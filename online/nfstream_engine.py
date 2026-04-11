"""
online/nfstream_engine.py — XTI-SOC

Replaces:
  capture.py + parser.py + session_store.py + feature_extractor.py

nfstream handles ALL of:
  - Packet capture   (libpcap via Npcap on Windows — no GIL, kernel-level)
  - Session tracking (bidirectional 5-tuple flows)
  - Feature computation (statistical_analysis=True)

This file has exactly two jobs:
  1. flow_to_features(flow)  → np.ndarray (1, 25) float64 | None
  2. NFStreamEngine           → manages capture thread, emits alert dicts

──────────────────────────────────────────────────────────────────────
DESIGN DECISIONS (answers to the 8 questions in the prompt)
──────────────────────────────────────────────────────────────────────

Q1  nfstream version in use: 6.6.0
    All field names below are verified against the 6.6.0 API.

Q2  statistical_analysis=True is REQUIRED.
    Without it, piat (packet inter-arrival time) fields are 0-initialised
    and never computed:
      bidirectional_mean_piat_ms, src2dst_mean_piat_ms, dst2src_mean_piat_ms
    accounting_mode and other flags do NOT imply statistical_analysis.

Q3  accounting_mode=0 gives IP-payload bytes — matching CICFlowMeter.
    Mode 1 = raw bytes (L2 headers included).
    Mode 2 = tunnelled payload.
    Always use 0 for CICFlowMeter compatibility.

Q4  flow_to_features() — see implementation below.
    Edge cases handled:
      - zero-duration flow  → clamped to 1 µs (1e-6 s) to avoid ÷0
      - inf / nan anywhere  → return None (flow discarded)
      - src2dst_bytes == 0  → Down/Up Ratio set to 0.0

Q5  NFStreamEngine — see class below.
    Alert dict keys are exactly as specified.

Q6  Interface names on Windows:
    nfstream accepts the SAME NPF GUID names that Scapy uses:
      \\Device\\NPF_{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}
    The existing online/interfaces.py (which reads from Scapy's conf.ifaces)
    returns the correct names — no change needed.
    nfstream also accepts plain strings like "Ethernet" or "Wi-Fi"
    (Npcap resolves them) but the NPF GUID form is more reliable.

Q7  Npcap requirement on Windows:
    nfstream uses WinPcap/Npcap under the hood (via libpcap bindings).
    Since Npcap is already installed for Scapy, nfstream will use it
    automatically — NO conflict.  Both live-capture tools share the same
    Npcap driver.  Do NOT install WinPcap alongside Npcap.

Q8  Validation script: scripts/validate_nfstream.py (see that file).
"""

import threading
import time
import numpy as np
import nfstream

from online import ml_engine


# ── Feature names — must match artifacts/feature_list.pkl ─────────────────────
FEATURE_NAMES: list[str] = [
    'Flow Duration',       # µs  (bidirectional_duration_ms × 1000)
    'Tot Fwd Pkts',
    'Tot Bwd Pkts',
    'TotLen Fwd Pkts',
    'TotLen Bwd Pkts',
    'Fwd Pkt Len Max',
    'Fwd Pkt Len Min',
    'Fwd Pkt Len Mean',
    'Bwd Pkt Len Max',
    'Bwd Pkt Len Min',
    'Bwd Pkt Len Mean',
    'Flow Byts/s',
    'Flow Pkts/s',
    'Flow IAT Mean',       # µs  (bidirectional_mean_piat_ms × 1000)
    'Fwd IAT Mean',        # µs  (src2dst_mean_piat_ms × 1000)
    'Bwd IAT Mean',        # µs  (dst2src_mean_piat_ms × 1000)
    'Fwd PSH Flags',
    'FIN Flag Cnt',
    'SYN Flag Cnt',
    'RST Flag Cnt',
    'PSH Flag Cnt',
    'ACK Flag Cnt',
    'Down/Up Ratio',
    'Fwd Seg Size Avg',
    'Bwd Seg Size Avg',
]


# ── Feature extraction ─────────────────────────────────────────────────────────

def flow_to_features(flow) -> np.ndarray | None:
    """
    Convert an nfstream flow object → numpy array shape (1, 25) float64.

    Returns None for flows that should be discarded:
      - Any inf or nan in the feature vector
      - Any exception during field access (corrupt / partial flow)

    Parameters
    ----------
    flow : nfstream.NFlow
        A completed flow emitted by NFStreamer (statistical_analysis=True).

    Returns
    -------
    np.ndarray | None
        Shape (1, 25), dtype float64 — ready for ml_engine.predict().
    """
    try:
        # ── Duration ──────────────────────────────────────────────────────────
        duration_ms: float = float(flow.bidirectional_duration_ms)
        # Clamp to 1 µs minimum to avoid division-by-zero for single-packet flows
        duration_s: float = max(duration_ms / 1_000.0, 1e-6)

        # ── Byte counts ───────────────────────────────────────────────────────
        total_bytes:   float = float(flow.bidirectional_bytes)
        total_pkts:    float = float(flow.bidirectional_packets)
        src2dst_bytes: float = float(flow.src2dst_bytes)
        dst2src_bytes: float = float(flow.dst2src_bytes)

        # ── Down/Up Ratio (safe division) ─────────────────────────────────────
        # CICFlowMeter defines this as bwd_bytes / fwd_bytes
        down_up_ratio: float = (
            dst2src_bytes / src2dst_bytes if src2dst_bytes > 0 else 0.0
        )

        # ── Feature vector (exact order matches FEATURE_NAMES) ────────────────
        values: list[float] = [
            duration_ms * 1_000.0,                          # Flow Duration (µs)
            float(flow.src2dst_packets),                    # Tot Fwd Pkts
            float(flow.dst2src_packets),                    # Tot Bwd Pkts
            src2dst_bytes,                                  # TotLen Fwd Pkts
            dst2src_bytes,                                  # TotLen Bwd Pkts
            float(flow.src2dst_max_ps),                    # Fwd Pkt Len Max
            float(flow.src2dst_min_ps),                    # Fwd Pkt Len Min
            float(flow.src2dst_mean_ps),                   # Fwd Pkt Len Mean
            float(flow.dst2src_max_ps),                    # Bwd Pkt Len Max
            float(flow.dst2src_min_ps),                    # Bwd Pkt Len Min
            float(flow.dst2src_mean_ps),                   # Bwd Pkt Len Mean
            total_bytes / duration_s,                       # Flow Byts/s
            total_pkts  / duration_s,                       # Flow Pkts/s
            float(flow.bidirectional_mean_piat_ms) * 1_000.0,  # Flow IAT Mean (µs)
            float(flow.src2dst_mean_piat_ms)        * 1_000.0,  # Fwd IAT Mean  (µs)
            float(flow.dst2src_mean_piat_ms)        * 1_000.0,  # Bwd IAT Mean  (µs)
            float(flow.src2dst_psh_packets),               # Fwd PSH Flags
            float(flow.bidirectional_fin_packets),         # FIN Flag Cnt
            float(flow.bidirectional_syn_packets),         # SYN Flag Cnt
            float(flow.bidirectional_rst_packets),         # RST Flag Cnt
            float(flow.bidirectional_psh_packets),         # PSH Flag Cnt
            float(flow.bidirectional_ack_packets),         # ACK Flag Cnt
            down_up_ratio,                                  # Down/Up Ratio
            float(flow.src2dst_mean_ps),                   # Fwd Seg Size Avg
            float(flow.dst2src_mean_ps),                   # Bwd Seg Size Avg
        ]

        arr = np.array(values, dtype=np.float64)

        # ── Sanity check ──────────────────────────────────────────────────────
        if np.any(np.isinf(arr)):
            print(f"[DEBUG] Skipping flow due to inf in features: {np.where(np.isinf(arr))[0]}")
            return None
        if np.any(np.isnan(arr)):
            print(f"[DEBUG] Skipping flow due to nan in features: {np.where(np.isnan(arr))[0]}")
            return None

        return arr.reshape(1, 25)

    except Exception as e:
        print(f"[DEBUG] Skipping flow due to Exception: {repr(e)}")
        import traceback
        traceback.print_exc()
        return None


# ── Alert builder ──────────────────────────────────────────────────────────────

def _build_alert(flow, ml_class: str, ml_prob: float) -> dict:
    """
    Build an alert dict from a completed nfstream flow + ML prediction.

    Keys are identical to the Scapy-era alert_queue._build_alert() output
    so downstream consumers (Phase 3 SHAP, Phase 4 CTI, Phase 5 API) are
    unaffected by the capture-layer swap.
    """
    return {
        # 5-tuple identity
        "src_ip":           flow.src_ip,
        "dst_ip":           flow.dst_ip,
        "src_port":         flow.src_port,
        "dst_port":         flow.dst_port,
        "protocol":         str(flow.protocol),          # "6"=TCP, "17"=UDP …

        # Timing
        "timestamp":        flow.bidirectional_last_seen_ms / 1_000.0,  # Unix s
        "duration_s":       flow.bidirectional_duration_ms  / 1_000.0,

        # ML result
        "ml_class":         ml_class,        # "BENIGN" | "MALICIOUS"
        "ml_probability":   ml_prob,         # float [0.0, 1.0]

        # Flow metadata
        "close_reason":     "nfstream",      # fixed; nfstream manages expiry
        "fwd_packets":      flow.src2dst_packets,
        "bwd_packets":      flow.dst2src_packets,
        "total_bytes":      flow.bidirectional_bytes,

        # Phase 3-5 placeholders
        "shap_explanation": None,            # Phase 3
        "cti_data":         None,            # Phase 4
        "alert_id":         None,            # Phase 5
        "risk_score":       None,            # Phase 5
    }


# ── Statistics ─────────────────────────────────────────────────────────────────

_stats_lock = threading.Lock()
_stats: dict = {
    "total_flows":         0,
    "malicious_count":     0,
    "benign_count":        0,
    "skipped_errors":      0,   # flows discarded by flow_to_features due to inf/nan
    "filtered_microflows": 0,   # flows dropped by quality thresholds
}


def get_stats() -> dict:
    """Return a snapshot of capture statistics (thread-safe)."""
    with _stats_lock:
        return _stats.copy()


def reset_stats() -> None:
    """Reset all counters to zero."""
    with _stats_lock:
        for key in _stats:
            _stats[key] = 0


# ── Capture engine ─────────────────────────────────────────────────────────────

class NFStreamEngine:
    """
    Live-capture engine: wraps nfstream.NFStreamer in a daemon thread.

    Usage
    -----
    from online.nfstream_engine import NFStreamEngine
    from online.alert_queue    import alert_queue

    engine = NFStreamEngine(output_queue=alert_queue)
    engine.start(interface=r"\\Device\\NPF_{...}")   # same name Scapy uses
    # … generate traffic …
    engine.stop()

    Interface names (Windows)
    -------------------------
    nfstream accepts the NPF GUID strings returned by online/interfaces.py
    (e.g. \\Device\\NPF_{A1B2C3D4-...}).  Npcap — already installed for
    Scapy — is used automatically with NO conflict.

    nfstream parameters
    -------------------
    statistical_analysis=True   REQUIRED for piat (inter-arrival time) fields.
    accounting_mode=0           IP-payload bytes → matches CICFlowMeter.
    NFSTREAM QUALITY FILTERS
    ------------------------
    MIN_PACKETS = 4
        Blinds the IDS to SYN Floods (1 pkt/flow) and Port Scans (2 pkts/flow).
        But effectively removes noisy background micro-flows (DNS droppings, 
        spurious RSTs, and orphaned FINs).
    MIN_DURATION_S = 0.01 (10ms)
        Ensures temporal features (IAT, Byts/s) are not inf/nan.
    """

    MIN_PACKETS = 4
    MIN_DURATION_S = 0.01

    def __init__(self, output_queue) -> None:
        """
        Parameters
        ----------
        output_queue : queue.Queue
            Where completed alert dicts are placed (e.g. alert_queue.alert_queue).
        """
        self._output_queue = output_queue
        self._stop_flag    = threading.Event()
        self._thread: threading.Thread | None = None
        self._interface: str = ""

    def start(self, interface: str) -> None:
        """
        Start live capture on *interface* in a background daemon thread.

        Parameters
        ----------
        interface : str
            NPF GUID (Windows) or OS name (Linux).
            Get from online.interfaces.get_interfaces()["name"].

        Raises
        ------
        RuntimeError
            If capture is already running.
        """
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError(
                "NFStreamEngine is already running. Call stop() first."
            )

        self._stop_flag.clear()
        from online.interfaces import resolve_interface_name
        self._interface = resolve_interface_name(interface)

        self._thread = threading.Thread(
            target=self._capture_loop,
            name="nfstream-capture",
            daemon=True,
        )
        self._thread.start()
        print(f"[NFSTREAM] Capture started on: {self._interface}")


    def stop(self) -> None:
        """
        Signal the capture thread to stop after the current flow.

        nfstream iterates lazily — the thread will exit at the next
        flow boundary (when idle_timeout fires for the last active flow).
        For immediate shutdown, the process termination is the cleanest path.
        """
        self._stop_flag.set()
        print("[NFSTREAM] Stop requested. Waiting for current flow to expire…")

    @property
    def is_running(self) -> bool:
        """True if the capture thread is alive."""
        return self._thread is not None and self._thread.is_alive()

    def _capture_loop(self) -> None:
        """
        Main capture loop — runs in daemon thread.

        Creates an NFStreamer, iterates over completed flows, converts each
        flow to a feature vector, runs ML inference, and puts the alert dict
        on the output queue.
        """
        try:
            streamer = nfstream.NFStreamer(
                source=self._interface,
                statistical_analysis=True,   # REQUIRED for piat fields
                accounting_mode=0,           # IP-payload bytes (CICFlowMeter)
                idle_timeout=15,             # seconds; lowered to 15s so you don't wait forever
                active_timeout=60,           # seconds; hard cap for long flows
                promiscuous_mode=True,
                n_meters=1,                  # forces single process to avoid 8x model loading
            )
        except Exception as e:
            print(f"[NFSTREAM ERROR] Failed to open interface '{self._interface}': {e}")
            print("[NFSTREAM] Hint: Run as Administrator and verify Npcap is installed.")
            return

        print(f"[NFSTREAM] Streaming flows from '{self._interface}'…")

        for flow in streamer:
            if self._stop_flag.is_set():
                break

            with _stats_lock:
                _stats["total_flows"] += 1

            # ── 1. Quality Filters (BEFORE feature extraction) ────────────────
            duration_s = flow.bidirectional_duration_ms / 1000.0
            
            # Additional check: src2dst_packets == 0 means no forward direction at all
            if (flow.bidirectional_packets < self.MIN_PACKETS or 
                duration_s < self.MIN_DURATION_S or
                flow.src2dst_packets == 0):
                with _stats_lock:
                    _stats["filtered_microflows"] += 1
                # Stay completely silent for filtered micro-flows to avoid terminal spam
                continue

            # ── 2. Feature extraction ────────────────────────────────────────────
            vec = flow_to_features(flow)

            if vec is None:
                with _stats_lock:
                    _stats["skipped_errors"] += 1
                continue

            # ── 3. ML inference ──────────────────────────────────────────────────
            try:
                ml_class, ml_prob = ml_engine.predict(vec)
            except Exception as e:
                print(f"[NFSTREAM ML ERROR] {e}")
                with _stats_lock:
                    _stats["skipped_errors"] += 1
                continue

            # ── Build & emit alert ────────────────────────────────────────────
            alert = _build_alert(flow, ml_class, ml_prob)
            self._output_queue.put(alert)

            with _stats_lock:
                if ml_class == "MALICIOUS":
                    _stats["malicious_count"] += 1
                else:
                    _stats["benign_count"] += 1

            print(
                f"[NFSTREAM] {flow.src_ip}:{flow.src_port} → "
                f"{flow.dst_ip}:{flow.dst_port} | "
                f"{ml_class} (p={ml_prob:.3f})"
            )

        print("[NFSTREAM] Capture loop exited.")
