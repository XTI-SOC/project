"""
online/alert_queue.py — XTI-SOC

Provides the shared alert queue that NFStreamEngine writes to
and downstream consumers (Phase 3 SHAP, Phase 4 CTI, Phase 5 API) read from.

With nfstream:
  - Packet capture, session tracking, feature extraction, and ML inference
    are all performed inside online/nfstream_engine.py::NFStreamEngine.
  - This module's ONLY job is to own the queue.Queue object and track stats.
  - The old Scapy-era processing loop (session_store → feature_extractor →
    ml_engine) has been removed; that is now handled by NFStreamEngine.

Design rules:
  - alert_queue is the SINGLE queue.Queue instance shared across the process
  - get_stats() / reset_stats() are thread-safe
  - This module does NOT start any threads at import time
"""

import queue
import threading


# ── Output queue (NFStreamEngine → downstream phases) ────────────────────────
# NFStreamEngine puts alert dicts here.
# Phase 3 (SHAP), Phase 4 (CTI), Phase 5 (API/WebSocket) read from here.
alert_queue: queue.Queue = queue.Queue()


# ── Statistics ─────────────────────────────────────────────────────────────────
_stats_lock = threading.Lock()
_stats: dict = {
    "total_processed":  0,    # flows successfully classified
    "benign_count":     0,
    "malicious_count":  0,
    "errors":           0,    # flows that raised an exception in ML
}


def get_stats() -> dict:
    """Return a thread-safe snapshot of processing statistics."""
    with _stats_lock:
        return _stats.copy()


def reset_stats() -> None:
    """Reset all counters to zero."""
    with _stats_lock:
        _stats["total_processed"]  = 0
        _stats["benign_count"]     = 0
        _stats["malicious_count"]  = 0
        _stats["errors"]           = 0


def record_alert(ml_class: str) -> None:
    """
    Increment counters after an alert is emitted.
    Called by NFStreamEngine._capture_loop().

    Parameters
    ----------
    ml_class : str
        "BENIGN" or "MALICIOUS"
    """
    with _stats_lock:
        _stats["total_processed"] += 1
        if ml_class == "MALICIOUS":
            _stats["malicious_count"] += 1
        else:
            _stats["benign_count"] += 1


def record_error() -> None:
    """Increment the error counter."""
    with _stats_lock:
        _stats["errors"] += 1