"""
online/nfstream_engine.py — XTI-SOC

Replaces:
  capture.py + parser.py + session_store.py + feature_extractor.py

nfstream handles ALL of:
  - Packet capture   (libpcap via Npcap on Windows — no GIL, kernel-level)
  - Session tracking (bidirectional 5-tuple flows)
  - Feature computation (statistical_analysis=True)

This file has exactly three jobs:
  1. should_whitelist(flow)   → bool (filters out false positives)
  2. flow_to_features(flow)   → np.ndarray (1, 25) float64 | None
  3. NFStreamEngine           → manages capture thread, emits alert dicts
"""

import threading
import time
import numpy as np
import nfstream

from online import ml_engine
from online.cti_cache import enrich_alert


# ── Feature names — must match artifacts/feature_list.pkl ─────────────────────
FEATURE_NAMES: list[str] = [
    'Flow Duration',
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
    'Flow IAT Mean',
    'Fwd IAT Mean',
    'Bwd IAT Mean',
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


# ── Whitelist logic ────────────────────────────────────────────────────────────

def should_whitelist(flow) -> bool:
    """
    Check if the flow should be whitelisted (ignored) before feature extraction.
    Returns True for known benign noisy broadcasts/multicasts (DHCP, mDNS, etc).
    """
    # DHCP (UDP 67/68, or from 0.0.0.0, or to broadcast 255.255.255.255)
    if flow.src_port in (67, 68) or flow.dst_port in (67, 68) or \
       flow.src_ip == "0.0.0.0" or flow.dst_ip == "255.255.255.255":
        return True
        
    # mDNS (Multicast DNS)
    if flow.dst_ip == "224.0.0.251" or flow.dst_port == 5353:
        return True
        
    # SSDP (Simple Service Discovery Protocol)
    if flow.dst_ip == "239.255.255.250" or flow.dst_port == 1900:
        return True
        
    # APIPA (Automatic Private IP Addressing)
    if flow.src_ip.startswith("169.254.") or flow.dst_ip.startswith("169.254."):
        return True
        
    return False


# ── Feature extraction ─────────────────────────────────────────────────────────

def flow_to_features(flow) -> np.ndarray | None:
    """
    Convert an nfstream flow object → numpy array shape (1, 25) float64.
    Returns None for flows that should be discarded (inf/nan errors).
    """
    try:
        duration_ms: float = float(flow.bidirectional_duration_ms)
        duration_s: float = max(duration_ms / 1_000.0, 1e-6)

        total_bytes:   float = float(flow.bidirectional_bytes)
        total_pkts:    float = float(flow.bidirectional_packets)
        src2dst_bytes: float = float(flow.src2dst_bytes)
        dst2src_bytes: float = float(flow.dst2src_bytes)

        down_up_ratio: float = (
            dst2src_bytes / src2dst_bytes if src2dst_bytes > 0 else 0.0
        )

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

def _build_alert(flow, ml_class: str, attack_type: str, ml_prob: float, shap_explanation: list[dict] | None) -> dict:
    """
    Build an alert dict from a completed nfstream flow + ML prediction.
    """
    return {
        "src_ip":           flow.src_ip,
        "dst_ip":           flow.dst_ip,
        "src_port":         flow.src_port,
        "dst_port":         flow.dst_port,
        "protocol":         str(flow.protocol),
        "timestamp":        flow.bidirectional_last_seen_ms / 1_000.0,
        "duration_s":       flow.bidirectional_duration_ms  / 1_000.0,
        "ml_class":         ml_class,
        "attack_type":      attack_type,
        "ml_probability":   ml_prob,
        "shap_explanation": shap_explanation,
        "close_reason":     "nfstream",
        "fwd_packets":      flow.src2dst_packets,
        "bwd_packets":      flow.dst2src_packets,
        "total_bytes":      flow.bidirectional_bytes,
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
    "skipped_errors":      0,
    "filtered_microflows": 0,
    "whitelisted":         0,
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
    """

    MIN_PACKETS = 4
    MIN_DURATION_S = 0.01

    def __init__(self, output_queue) -> None:
        self._output_queue = output_queue
        self._stop_flag    = threading.Event()
        self._thread: threading.Thread | None = None
        self._interface: str = ""

    def start(self, interface: str) -> None:
        if self._thread is not None and self._thread.is_alive():
            raise RuntimeError("NFStreamEngine is already running. Call stop() first.")

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
        self._stop_flag.set()
        print("[NFSTREAM] Stop requested. Waiting for current flow to expire…")

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _capture_loop(self) -> None:
        try:
            streamer = nfstream.NFStreamer(
                source=self._interface,
                statistical_analysis=True,
                accounting_mode=0,
                idle_timeout=15,
                active_timeout=60,
                promiscuous_mode=True,
                n_meters=1,
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

            # ── 1. Quality Filters ───────────────────────────────────────────────
            duration_s = flow.bidirectional_duration_ms / 1000.0
            
            if (flow.bidirectional_packets < self.MIN_PACKETS or 
                duration_s < self.MIN_DURATION_S or
                flow.src2dst_packets == 0):
                with _stats_lock:
                    _stats["filtered_microflows"] += 1
                continue
                
            if should_whitelist(flow):
                with _stats_lock:
                    _stats["whitelisted"] += 1
                continue

            # ── 2. Feature extraction ────────────────────────────────────────────
            vec = flow_to_features(flow)
            if vec is None:
                with _stats_lock:
                    _stats["skipped_errors"] += 1
                continue

            # ── 3. ML inference ──────────────────────────────────────────────────
            try:
                binary_class, attack_type, ml_prob = ml_engine.predict(vec)
                
                if binary_class == "MALICIOUS":
                    shap_exp = ml_engine.get_shap_explanation(vec)
                else:
                    shap_exp = None
            except Exception as e:
                print(f"[NFSTREAM ML ERROR] {e}")
                with _stats_lock:
                    _stats["skipped_errors"] += 1
                continue

            # ── Build & emit alert ───────────────────────────────────────────────
            alert = _build_alert(flow, binary_class, attack_type, ml_prob, shap_exp)
            
            alert = enrich_alert(alert)

            # Only queue alerts that are not NO_ALERT
            if (alert.get("cti_data") or {}).get("alert_type") == "NO_ALERT":
                continue
                
            self._output_queue.put(alert)

            with _stats_lock:
                if binary_class == "MALICIOUS":
                    _stats["malicious_count"] += 1
                else:
                    _stats["benign_count"] += 1

            print(
                f"[NFSTREAM] {flow.src_ip}:{flow.src_port} → "
                f"{flow.dst_ip}:{flow.dst_port} | "
                f"{binary_class} ({attack_type}) [p={ml_prob:.3f}]"
            )

        print("[NFSTREAM] Capture loop exited.")
