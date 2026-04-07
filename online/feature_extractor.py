"""
online/feature_extractor.py — XTI-SOC Phase 2

Extract 25 ML features from a closed session dict.
Feature order MUST match artifacts/feature_list.pkl exactly.

Design rules:
  - Returns numpy array shape (1, 25) — ready for scaler.transform()
  - Handles edge cases: empty lists, zero duration, division by zero
  - Never crashes — returns zero-filled vector on invalid input
  - All computations use float64 to match sklearn expectations
"""

import numpy as np


# Ground truth feature order from artifacts/feature_list.pkl
FEATURE_NAMES = [
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


def extract_features(session: dict) -> np.ndarray:
    """
    Extract 25 ML features from a closed session.
    
    Parameters
    ----------
    session : dict
        Closed session from session_store.closed_queue
        
    Returns
    -------
    np.ndarray
        Shape (1, 25) float64 array ready for scaler.transform()
        Returns zeros if session is invalid
    """
    try:
        # Unpack session data
        start_time = session["start_time"]
        last_seen = session["last_seen"]
        fwd_sizes = session["fwd_pkt_sizes"]
        bwd_sizes = session["bwd_pkt_sizes"]
        fwd_iats = session["fwd_iat_list"]
        bwd_iats = session["bwd_iat_list"]
        
        # Basic counts
        fwd_count = len(fwd_sizes)
        bwd_count = len(bwd_sizes)
        total_fwd_bytes = sum(fwd_sizes)
        total_bwd_bytes = sum(bwd_sizes)
        
        # Duration (in seconds)
        duration = last_seen - start_time
        duration = max(duration, 1e-6)  # prevent division by zero
        
        # Feature 1: Flow Duration (convert to microseconds like CICFlowMeter)
        flow_duration = duration * 1_000_000
        
        # Feature 2-3: Packet counts
        tot_fwd_pkts = float(fwd_count)
        tot_bwd_pkts = float(bwd_count)
        
        # Feature 4-5: Total lengths
        totlen_fwd_pkts = float(total_fwd_bytes)
        totlen_bwd_pkts = float(total_bwd_bytes)
        
        # Feature 6-8: Forward packet size statistics
        if fwd_sizes:
            fwd_pkt_len_max = float(max(fwd_sizes))
            fwd_pkt_len_min = float(min(fwd_sizes))
            fwd_pkt_len_mean = float(np.mean(fwd_sizes))
        else:
            fwd_pkt_len_max = 0.0
            fwd_pkt_len_min = 0.0
            fwd_pkt_len_mean = 0.0
        
        # Feature 9-11: Backward packet size statistics
        if bwd_sizes:
            bwd_pkt_len_max = float(max(bwd_sizes))
            bwd_pkt_len_min = float(min(bwd_sizes))
            bwd_pkt_len_mean = float(np.mean(bwd_sizes))
        else:
            bwd_pkt_len_max = 0.0
            bwd_pkt_len_min = 0.0
            bwd_pkt_len_mean = 0.0
        
        # Feature 12: Flow Bytes/s
        total_bytes = total_fwd_bytes + total_bwd_bytes
        flow_byts_s = total_bytes / duration
        
        # Feature 13: Flow Packets/s
        total_pkts = fwd_count + bwd_count
        flow_pkts_s = total_pkts / duration
        
        # Feature 14: Flow IAT Mean
        # Combine both directions' IATs
        all_iats = fwd_iats + bwd_iats
        flow_iat_mean = float(np.mean(all_iats)) if all_iats else 0.0
        
        # Feature 15: Fwd IAT Mean
        fwd_iat_mean = float(np.mean(fwd_iats)) if fwd_iats else 0.0
        
        # Feature 16: Bwd IAT Mean
        bwd_iat_mean = float(np.mean(bwd_iats)) if bwd_iats else 0.0
        
        # Feature 17: Fwd PSH Flags (count from session)
        fwd_psh_flags = float(session["fwd_psh_flags"])
        
        # Feature 18-22: TCP Flag counts (both directions combined)
        fin_flag_cnt = float(session["fin_cnt"])
        syn_flag_cnt = float(session["syn_cnt"])
        rst_flag_cnt = float(session["rst_cnt"])
        psh_flag_cnt = float(session["psh_cnt"])
        ack_flag_cnt = float(session["ack_cnt"])
        
        # Feature 23: Down/Up Ratio
        # CICFlowMeter: download = backward, upload = forward
        if total_fwd_bytes > 0:
            down_up_ratio = total_bwd_bytes / total_fwd_bytes
        else:
            down_up_ratio = 0.0
        
        # Feature 24: Fwd Seg Size Avg (same as Fwd Pkt Len Mean)
        fwd_seg_size_avg = fwd_pkt_len_mean
        
        # Feature 25: Bwd Seg Size Avg (same as Bwd Pkt Len Mean)
        bwd_seg_size_avg = bwd_pkt_len_mean
        
        # Build feature vector in EXACT order
        features = [
            flow_duration,        # 1
            tot_fwd_pkts,         # 2
            tot_bwd_pkts,         # 3
            totlen_fwd_pkts,      # 4
            totlen_bwd_pkts,      # 5
            fwd_pkt_len_max,      # 6
            fwd_pkt_len_min,      # 7
            fwd_pkt_len_mean,     # 8
            bwd_pkt_len_max,      # 9
            bwd_pkt_len_min,      # 10
            bwd_pkt_len_mean,     # 11
            flow_byts_s,          # 12
            flow_pkts_s,          # 13
            flow_iat_mean,        # 14
            fwd_iat_mean,         # 15
            bwd_iat_mean,         # 16
            fwd_psh_flags,        # 17
            fin_flag_cnt,         # 18
            syn_flag_cnt,         # 19
            rst_flag_cnt,         # 20
            psh_flag_cnt,         # 21
            ack_flag_cnt,         # 22
            down_up_ratio,        # 23
            fwd_seg_size_avg,     # 24
            bwd_seg_size_avg,     # 25
        ]
        
        # Convert to numpy array — shape (1, 25)
        return np.array(features, dtype=np.float64).reshape(1, -1)
        
    except Exception as e:
        # Log error and return zero vector (will be classified as benign)
        print(f"[FEATURE_EXTRACTOR ERROR] {e}")
        return np.zeros((1, 25), dtype=np.float64)


def validate_features() -> bool:
    """
    Verify that extract_features() produces exactly 25 features.
    Call this once at startup.
    
    Returns
    -------
    bool
        True if feature count matches, False otherwise
    """
    # Create a minimal valid session
    dummy_session = {
        "start_time": 0.0,
        "last_seen": 1.0,
        "fwd_pkt_sizes": [100, 200],
        "bwd_pkt_sizes": [50],
        "fwd_iat_list": [0.5],
        "bwd_iat_list": [],
        "fwd_psh_flags": 1,
        "fin_cnt": 1,
        "syn_cnt": 1,
        "rst_cnt": 0,
        "psh_cnt": 1,
        "ack_cnt": 2,
    }
    
    vector = extract_features(dummy_session)
    
    if vector.shape != (1, 25):
        print(f"❌ Feature extractor produces {vector.shape[1]} features, expected 25")
        return False
    
    print(f"✅ Feature extractor validated: {vector.shape}")
    return True