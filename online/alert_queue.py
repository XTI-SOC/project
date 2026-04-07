"""
online/alert_queue.py — XTI-SOC Phase 2

Processing thread that reads closed sessions, extracts features,
runs ML inference, and produces alerts.

Design rules:
  - Runs in its own daemon thread (started at module import)
  - Reads from session_store.closed_queue (Phase 1 output)
  - Writes to alert_queue (Phase 2 output — consumed by Phase 3/4/5)
  - Never blocks — uses queue.get(timeout=1.0) with exception handling
  - Logs all processing steps for debugging
"""

import queue
import threading
import time
from typing import Optional

from . import session_store, feature_extractor, ml_engine


# ── Output queue (Phase 2 → Phase 3) ──────────────────────────────────────────
# Phase 3 (SHAP) will read from this queue
alert_queue: queue.Queue = queue.Queue()


# ── Statistics ─────────────────────────────────────────────────────────────────
_stats_lock = threading.Lock()
_stats = {
    "total_processed": 0,
    "benign_count": 0,
    "malicious_count": 0,
    "errors": 0,
}


def get_stats() -> dict:
    """Return a copy of processing statistics."""
    with _stats_lock:
        return _stats.copy()


def reset_stats() -> None:
    """Reset all statistics counters."""
    with _stats_lock:
        _stats["total_processed"] = 0
        _stats["benign_count"] = 0
        _stats["malicious_count"] = 0
        _stats["errors"] = 0


# ── Alert builder ──────────────────────────────────────────────────────────────

def _build_alert(session: dict, ml_class: str, ml_prob: float) -> dict:
    """
    Build an alert dict from session + ML prediction.
    
    This is a minimal Phase 2 alert. Phase 3 will add SHAP data.
    Phase 4 will add CTI data. Phase 5 will add alerting metadata.
    
    Returns
    -------
    dict
        Alert dict with Phase 2 fields only
    """
    return {
        # Session identity
        "src_ip": session["src_ip"],
        "dst_ip": session["dst_ip"],
        "src_port": session["src_port"],
        "dst_port": session["dst_port"],
        "protocol": session["protocol"],
        
        # Timing
        "timestamp": session["last_seen"],  # Unix timestamp of session close
        "duration_s": session["last_seen"] - session["start_time"],
        
        # ML prediction (Phase 2)
        "ml_class": ml_class,           # "BENIGN" or "MALICIOUS"
        "ml_probability": ml_prob,      # float [0.0, 1.0]
        
        # Session metadata
        "close_reason": session["close_reason"],  # "FIN", "RST", or "timeout"
        "fwd_packets": len(session["fwd_pkt_sizes"]),
        "bwd_packets": len(session["bwd_pkt_sizes"]),
        "total_bytes": sum(session["fwd_pkt_sizes"]) + sum(session["bwd_pkt_sizes"]),
        
        # Phase 3-5 fields (placeholder — will be populated later)
        "shap_explanation": None,       # Phase 3
        "cti_data": None,               # Phase 4
        "alert_id": None,               # Phase 5
        "risk_score": None,             # Phase 5
    }


# ── Processing loop ────────────────────────────────────────────────────────────

def _processing_worker() -> None:
    """
    Main processing loop. Runs in daemon thread.
    
    Workflow per session:
      1. Read closed session from session_store.closed_queue
      2. Extract 25 features
      3. Run ML inference
      4. Build alert dict
      5. Put alert on alert_queue
      6. Update statistics
    """
    print("[ALERT_QUEUE] Processing thread started\n")
    
    while True:
        try:
            # Block for up to 1 second waiting for a closed session
            session = session_store.closed_queue.get(timeout=1.0)
            
            # Extract features
            feature_vector = feature_extractor.extract_features(session)
            
            # Run ML inference
            ml_class, ml_prob = ml_engine.predict(feature_vector)
            
            # Build alert
            alert = _build_alert(session, ml_class, ml_prob)
            
            # Emit to alert_queue
            alert_queue.put(alert)
            
            # Update statistics
            with _stats_lock:
                _stats["total_processed"] += 1
                if ml_class == "BENIGN":
                    _stats["benign_count"] += 1
                else:
                    _stats["malicious_count"] += 1
            
            # Log for debugging (remove in production)
            print(
                f"[ALERT] {session['src_ip']}:{session['src_port']} → "
                f"{session['dst_ip']}:{session['dst_port']} | "
                f"{ml_class} (p={ml_prob:.3f})"
            )
            
        except queue.Empty:
            # No sessions available — loop continues
            continue
            
        except Exception as e:
            # Log error but don't crash the thread
            print(f"[ALERT_QUEUE ERROR] {e}")
            with _stats_lock:
                _stats["errors"] += 1


# ── Start processing thread at import time ────────────────────────────────────
# This is intentional — importing alert_queue activates Phase 2 processing
_processing_thread = threading.Thread(
    target=_processing_worker,
    name="ml-processing-worker",
    daemon=True,
)
_processing_thread.start()