"""
online/session_store.py — XTI-SOC Phase 1

Track active network sessions, accumulate per-session statistics,
and emit closed sessions to closed_queue for Phase 2 to consume.

DESIGN RULES (do not violate):
  1. pkt["tcp_flags"] is always a set[str]. Check: if "FIN" in pkt["tcp_flags"].
     Never convert to string — that reintroduces the "F in FIN-ACK" substring bug.

  2. IAT INVARIANT:
       len(fwd_iat_list) == len(fwd_pkt_sizes) - 1
       len(bwd_iat_list) == len(bwd_pkt_sizes) - 1
     The FIRST packet in each direction sets last_fwd_time / last_bwd_time
     but does NOT append to the IAT list (there is no previous packet to diff).
     Only the 2nd+ packet in each direction appends an IAT entry.

  3. The timeout daemon thread starts at MODULE IMPORT TIME (see bottom of file).
     It must NOT be started from capture.py or PacketCaptureEngine.start().
     Importing session_store is sufficient to activate session expiry.

  4. closed_queue is the ONLY output of Phase 1.
     No I/O, no HTTP, no WebSocket. Phase 2 imports closed_queue and consumes it.

  5. process_packet() must be fast — no I/O, no blocking, no sleep.
     The lock is held only for dict mutation + arithmetic — never for I/O.
"""

import queue
import threading
import time

# ── Public output queue ────────────────────────────────────────────────────────
# Phase 2 does: from online.session_store import closed_queue
closed_queue: queue.Queue = queue.Queue()

# ── Internal state ─────────────────────────────────────────────────────────────
_sessions: dict = {}         # key → session_dict
_sessions_lock = threading.Lock()

# ── Recently-closed suppression window ────────────────────────────────────────
# After a session closes (FIN / RST), its key is stored here with an expiry
# timestamp. Any new packet on the same 5-tuple within that window is silently
# discarded — it is a TCP teardown artifact (ACK-to-FIN, retransmit, server RST)
# and would only produce a garbage single-packet zero-duration session.
_recently_closed: dict = {}   # key → expiry float (time.time() + TTL)
_RECENTLY_CLOSED_TTL = 5.0    # seconds to suppress after a session closes

# ── Emit quality filter ────────────────────────────────────────────────────────
# Sessions that fail either threshold are dropped at queue-emit time.
# These thresholds match the implicit filtering CICFlowMeter applies —
# single-packet or zero-duration flows are not useful ML feature vectors.
_MIN_TOTAL_PACKETS = 4        # fwd + bwd must be >= 4
_MIN_DURATION_S    = 0.01     # session must last >= 10 ms


# ── Session key ────────────────────────────────────────────────────────────────

def _make_key(pkt: dict) -> tuple:
    """
    Canonical 5-tuple so A→B and B→A map to the SAME session.

    endpoint_a = min of the two (ip, port) pairs
    endpoint_b = max of the two (ip, port) pairs
    key = (*endpoint_a, *endpoint_b, protocol)
    """
    a = (pkt["src_ip"], pkt["src_port"] or 0)
    b = (pkt["dst_ip"], pkt["dst_port"] or 0)
    ep_a = min(a, b)
    ep_b = max(a, b)
    return (*ep_a, *ep_b, pkt["protocol"])


# ── Session creation ───────────────────────────────────────────────────────────

def _new_session(pkt: dict) -> dict:
    """
    Build a fresh session dict from the first packet of a flow.

    The first packet is ALWAYS treated as forward.
    It sets last_fwd_time but does NOT append to fwd_iat_list
    (IAT needs a previous packet; this is the first one).
    """
    now = pkt["timestamp"]
    tcp_flags: set = pkt["tcp_flags"]  # set[str]

    return {
        # Identity
        "src_ip":       pkt["src_ip"],
        "dst_ip":       pkt["dst_ip"],
        "src_port":     pkt["src_port"],
        "dst_port":     pkt["dst_port"],
        "protocol":     pkt["protocol"],
        "fwd_ip":       pkt["src_ip"],   # src_ip of first packet defines forward

        # Timing
        "start_time":   now,
        "last_seen":    now,

        # Forward packet sizes (first packet is forward)
        "fwd_pkt_sizes": [pkt["pkt_size"]],
        # Backward packet sizes
        "bwd_pkt_sizes": [],

        # IAT lists — first packet has no predecessor, so lists start empty.
        # After N fwd packets: len(fwd_iat_list) == N - 1  (invariant)
        "fwd_iat_list":  [],            # populated from 2nd fwd packet onward
        "bwd_iat_list":  [],            # populated from 2nd bwd packet onward
        "last_fwd_time": now,           # set by first fwd packet
        "last_bwd_time": None,          # no bwd packet yet

        # TCP flag counts (both directions combined)
        "fin_cnt": 1 if "FIN" in tcp_flags else 0,
        "syn_cnt": 1 if "SYN" in tcp_flags else 0,
        "rst_cnt": 1 if "RST" in tcp_flags else 0,
        "psh_cnt": 1 if "PSH" in tcp_flags else 0,
        "ack_cnt": 1 if "ACK" in tcp_flags else 0,

        # Forward PSH specifically (its own ML feature)
        "fwd_psh_flags": 1 if "PSH" in tcp_flags else 0,

        # Close metadata
        "close_reason": None,
    }


# ── Packet processing ──────────────────────────────────────────────────────────

def _maybe_emit(key: tuple, session: dict, now: float) -> None:
    """
    Conditionally place a closed session into closed_queue.

    Two gates must both pass:
      1. Total packets (fwd + bwd) >= _MIN_TOTAL_PACKETS (default 4)
         Filters: single-packet RST terminations, server-side resets,
         TCP teardown ACKs that created a new micro-session.
      2. Duration >= _MIN_DURATION_S (default 10 ms)
         Filters: zero-duration packets where start_time == last_seen.

    Also stamps the key in _recently_closed so subsequent teardown
    packets on the same 5-tuple are suppressed for _RECENTLY_CLOSED_TTL seconds.

    Called OUTSIDE the sessions lock — never holds the lock.
    """
    # Register suppression window regardless of whether we emit
    # (we don't want teardown artifacts even for sessions we drop)
    _recently_closed[key] = now + _RECENTLY_CLOSED_TTL

    total_pkts = len(session["fwd_pkt_sizes"]) + len(session["bwd_pkt_sizes"])
    duration   = session["last_seen"] - session["start_time"]

    if total_pkts >= _MIN_TOTAL_PACKETS and duration >= _MIN_DURATION_S:
        closed_queue.put(session)
    # else: silently drop — teardown artifact, not a real flow


def process_packet(pkt: dict) -> None:
    """
    Main entry point called from the capture thread for every parsed packet.

    Must be fast: no I/O, no blocking, no sleep.
    The lock is held only for the dict mutation block.

    If a session closes (FIN / RST), it is removed from _sessions and
    handed to _maybe_emit() which decides whether to put it in closed_queue.
    """
    key = _make_key(pkt)
    now = pkt["timestamp"]
    tcp_flags: set = pkt["tcp_flags"]   # set[str] — never convert to string

    closed_session = None

    with _sessions_lock:
        # ── Suppression window check ───────────────────────────────────────
        # If this 5-tuple closed recently, this packet is a TCP teardown
        # artifact (ACK-to-FIN, server FIN-ACK, OS retransmit, stale RST).
        # Discard it — do NOT create a new session.
        expiry = _recently_closed.get(key)
        if expiry is not None:
            if now < expiry:
                return   # still in suppression window — silently drop
            else:
                # Window expired — allow new sessions on this 5-tuple again
                del _recently_closed[key]

        if key not in _sessions:
            # ── New session ────────────────────────────────────────────────
            _sessions[key] = _new_session(pkt)
            # Check if opening packet already carries FIN or RST
            # (pathological but possible — handle gracefully)
            session = _sessions[key]
            if "FIN" in tcp_flags or "RST" in tcp_flags:
                session["close_reason"] = "RST" if "RST" in tcp_flags else "FIN"
                closed_session = _sessions.pop(key)

        else:
            # ── Existing session ───────────────────────────────────────────
            session = _sessions[key]
            session["last_seen"] = now

            # Compare (ip, port) pair — not just IP — so that loopback traffic
            # (src_ip == dst_ip == 127.0.0.1) is still directionally correct.
            is_forward = (pkt["src_ip"], pkt["src_port"]) == (session["fwd_ip"], session["src_port"])

            if is_forward:
                # IAT: only if there was a previous forward packet
                # INVARIANT: len(fwd_iat_list) == len(fwd_pkt_sizes) - 1
                if session["last_fwd_time"] is not None:
                    session["fwd_iat_list"].append(now - session["last_fwd_time"])
                session["fwd_pkt_sizes"].append(pkt["pkt_size"])
                session["last_fwd_time"] = now
                # Forward PSH counter
                if "PSH" in tcp_flags:
                    session["fwd_psh_flags"] += 1
            else:
                # IAT: only if there was a previous backward packet
                # INVARIANT: len(bwd_iat_list) == len(bwd_pkt_sizes) - 1
                if session["last_bwd_time"] is not None:
                    session["bwd_iat_list"].append(now - session["last_bwd_time"])
                session["bwd_pkt_sizes"].append(pkt["pkt_size"])
                session["last_bwd_time"] = now

            # Update all TCP flag counters (both directions)
            if "FIN" in tcp_flags:
                session["fin_cnt"] += 1
            if "SYN" in tcp_flags:
                session["syn_cnt"] += 1
            if "RST" in tcp_flags:
                session["rst_cnt"] += 1
            if "PSH" in tcp_flags:
                session["psh_cnt"] += 1
            if "ACK" in tcp_flags:
                session["ack_cnt"] += 1

            # Check for session close condition
            # Set membership check — never substring: "FIN" in {"FIN", "ACK"}
            if "FIN" in tcp_flags or "RST" in tcp_flags:
                session["close_reason"] = "RST" if "RST" in tcp_flags else "FIN"
                closed_session = _sessions.pop(key)

    # Emit outside the lock — _maybe_emit handles quality filter + suppression
    if closed_session is not None:
        _maybe_emit(key, closed_session, now)


# ── Timeout eviction ───────────────────────────────────────────────────────────

_TIMEOUT_SCAN_INTERVAL = 60    # seconds between scans
_SESSION_IDLE_TIMEOUT  = 300   # seconds of inactivity before eviction


def _timeout_worker() -> None:
    """
    Background daemon that evicts idle sessions every 60 seconds.

    A session is evicted if: now - last_seen > 300 seconds.
    Evicted sessions get close_reason="timeout" and are placed in closed_queue.

    This thread starts at MODULE IMPORT TIME (see below).
    It does NOT need to be started by capture.py or any other caller.
    """
    while True:
        time.sleep(_TIMEOUT_SCAN_INTERVAL)
        now = time.time()
        evicted: list[tuple] = []   # list of (key, session) pairs

        with _sessions_lock:
            # Evict idle sessions
            for key, session in list(_sessions.items()):
                if now - session["last_seen"] > _SESSION_IDLE_TIMEOUT:
                    session["close_reason"] = "timeout"
                    evicted.append((key, session))
                    del _sessions[key]

            # Purge expired recently-closed entries to prevent memory growth
            expired_keys = [k for k, exp in _recently_closed.items() if now >= exp]
            for k in expired_keys:
                del _recently_closed[k]

        # Timeout-closed sessions go through the same quality filter
        for key, session in evicted:
            _maybe_emit(key, session, now)


# ── Thread starts at IMPORT TIME ───────────────────────────────────────────────
# This is intentional. Importing session_store activates session expiry
# regardless of whether capture.py has been started.
# Do NOT move this into capture.py or PacketCaptureEngine.start().
_timeout_thread = threading.Thread(
    target=_timeout_worker,
    name="session-timeout-worker",
    daemon=True,          # dies automatically with the main process
)
_timeout_thread.start()


# ── Diagnostic helpers (used by main.py stats printer) ────────────────────────

def active_session_count() -> int:
    """Return the number of currently tracked active sessions."""
    with _sessions_lock:
        return len(_sessions)
