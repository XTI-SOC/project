"""
online/main.py — XTI-SOC Phase 1

Test harness for Phase 1. This file will be REPLACED in Phase 5 by the
FastAPI + WebSocket server. Its only purpose right now is to verify that
parser.py, session_store.py, and capture.py work correctly together.

What it does:
  1. Lists available network interfaces and lets the user pick one
  2. Starts PacketCaptureEngine on the selected interface
  3. Runs a consumer thread that reads closed sessions from closed_queue
     and prints a formatted summary to the terminal
  4. Prints a one-liner stats line every 10 seconds
  5. Handles Ctrl+C cleanly: stops capture, drains remaining queue

Run with:
  python -m online.main          (from project root)
  OR
  python online/main.py          (from project root, if __name__ == "__main__")

Must be run as Administrator on Windows (Scapy requires raw socket access).
"""

import queue
import signal
import sys
import threading
import time

from online.capture import PacketCaptureEngine
from online.interfaces import get_default_interface, get_interfaces
from online.session_store import active_session_count, closed_queue

# ── Formatting helpers ─────────────────────────────────────────────────────────

_SEP = "═" * 55


def _fmt_session(s: dict) -> str:
    """Format a closed session dict as a human-readable multi-line string."""
    duration = s["last_seen"] - s["start_time"]

    fwd_sizes = s["fwd_pkt_sizes"]
    bwd_sizes = s["bwd_pkt_sizes"]
    fwd_iats  = s["fwd_iat_list"]
    bwd_iats  = s["bwd_iat_list"]

    mean_fwd_iat = (sum(fwd_iats) / len(fwd_iats)) if fwd_iats else 0.0
    mean_bwd_iat = (sum(bwd_iats) / len(bwd_iats)) if bwd_iats else 0.0

    src_port = s["src_port"] if s["src_port"] is not None else "*"
    dst_port = s["dst_port"] if s["dst_port"] is not None else "*"

    # IAT invariant check (debug assertion — remove in production)
    assert len(fwd_iats) == max(0, len(fwd_sizes) - 1), (
        f"IAT invariant violated: fwd_iat={len(fwd_iats)} fwd_pkts={len(fwd_sizes)}"
    )
    assert len(bwd_iats) == max(0, len(bwd_sizes) - 1), (
        f"IAT invariant violated: bwd_iat={len(bwd_iats)} bwd_pkts={len(bwd_sizes)}"
    )

    lines = [
        _SEP,
        f"SESSION CLOSED [{s['close_reason']}]",
        f"  {s['src_ip']}:{src_port}  →  {s['dst_ip']}:{dst_port}  ({s['protocol']})",
        f"  Duration:    {duration:.3f}s",
        f"  Fwd packets: {len(fwd_sizes):>5}  |  Bwd packets: {len(bwd_sizes):>5}",
        f"  Fwd bytes:   {sum(fwd_sizes):>7}  |  Bwd bytes:   {sum(bwd_sizes):>7}",
        f"  Fwd IATs:    {len(fwd_iats):>5} samples  |  mean={mean_fwd_iat:.4f}s",
        f"  Bwd IATs:    {len(bwd_iats):>5} samples  |  mean={mean_bwd_iat:.4f}s",
        f"  Flags → FIN:{s['fin_cnt']} SYN:{s['syn_cnt']} RST:{s['rst_cnt']} "
        f"PSH:{s['psh_cnt']} ACK:{s['ack_cnt']}",
        f"  FwdPSH: {s['fwd_psh_flags']}",
        _SEP,
    ]
    return "\n".join(lines)


# ── Consumer thread ────────────────────────────────────────────────────────────

_total_closed: int = 0
_total_closed_lock = threading.Lock()


def _consumer_loop() -> None:
    """
    Reads closed session dicts from closed_queue and prints them.
    Runs in its own daemon thread so it never blocks the main thread.
    """
    global _total_closed
    while True:
        try:
            session = closed_queue.get(timeout=1.0)
            print(_fmt_session(session))
            with _total_closed_lock:
                _total_closed += 1
        except queue.Empty:
            continue
        except Exception as exc:
            print(f"[CONSUMER ERROR] {exc}")


# ── Stats printer ──────────────────────────────────────────────────────────────

def _stats_loop(engine: PacketCaptureEngine) -> None:
    """Print a one-liner stats summary every 10 seconds."""
    from online import alert_queue  # Import here to avoid circular dependency
    
    while True:
        time.sleep(10)
        with _total_closed_lock:
            closed_so_far = _total_closed
        
        # Get Phase 2 stats
        ml_stats = alert_queue.get_stats()
        
        print(
            f"[STATS] Active sessions: {active_session_count():>4}  |  "
            f"Closed (queue+printed): {closed_so_far:>6}  |  "
            f"Packets processed: {engine.packet_count():>8}  |  "
            f"ML: {ml_stats['malicious_count']}/{ml_stats['total_processed']} malicious"
        )


# ── Interface selection ────────────────────────────────────────────────────────

def _pick_interface() -> str:
    """
    Print available interfaces and prompt the user to select one.
    Returns the Scapy interface name string.
    """
    ifaces = get_interfaces()

    if not ifaces:
        print("[ERROR] No network interfaces found. Run as Administrator?")
        sys.exit(1)

    default_name = get_default_interface()

    print("\nAvailable network interfaces:")
    print("-" * 60)
    for i, iface in enumerate(ifaces):
        marker = " ◄ default" if iface["name"] == default_name else ""
        print(f"  [{i}] {iface['display']}{marker}")
    print("-" * 60)

    raw = input(f"Select interface [0-{len(ifaces)-1}] (Enter = default): ").strip()

    if raw == "":
        # Use default
        chosen_name = default_name
        chosen_display = next(
            (i["display"] for i in ifaces if i["name"] == default_name),
            default_name,
        )
    else:
        try:
            idx = int(raw)
            chosen = ifaces[idx]
            chosen_name = chosen["name"]
            chosen_display = chosen["display"]
        except (ValueError, IndexError):
            print("[ERROR] Invalid selection.")
            sys.exit(1)

    print(f"\nCapturing on: {chosen_display}")
    return chosen_name


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> None:
    engine = PacketCaptureEngine()

    # Select interface
    iface_name = _pick_interface()

    # Start capture
    engine.start(interface=iface_name)
    print("\nCapture started. Waiting for sessions to close...\n")
    print("(Open a browser, browse a site, then watch sessions appear here.)")
    print("(Press Ctrl+C to stop.)\n")

    # Start consumer thread (reads closed_queue → prints sessions)
    consumer_thread = threading.Thread(
        target=_consumer_loop,
        name="session-consumer",
        daemon=True,
    )
    consumer_thread.start()

    # Start stats printer thread
    stats_thread = threading.Thread(
        target=_stats_loop,
        args=(engine,),
        name="stats-printer",
        daemon=True,
    )
    stats_thread.start()

    # Block main thread until Ctrl+C
    try:
        signal.pause() if hasattr(signal, "pause") else _wait_forever()
    except (KeyboardInterrupt, SystemExit):
        pass
    finally:
        _shutdown(engine)


def _wait_forever() -> None:
    """Portable alternative to signal.pause() on Windows."""
    while True:
        time.sleep(1)


def _shutdown(engine: PacketCaptureEngine) -> None:
    """Stop capture and drain any remaining sessions from the queue."""
    print("\n\n[STOPPING] Draining remaining closed sessions...\n")
    engine.stop()
    time.sleep(0.5)  # give threads a moment to flush

    drained = 0
    while True:
        try:
            session = closed_queue.get_nowait()
            print(_fmt_session(session))
            drained += 1
        except queue.Empty:
            break

    with _total_closed_lock:
        total = _total_closed + drained

    print(f"\n[DONE] Total sessions printed: {total}")
    print(f"       Final packet count:     {engine.packet_count()}")


if __name__ == "__main__":
    main()
