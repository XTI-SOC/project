# diagnostic.py
from online import alert_queue
import time

# Wait for some alerts
time.sleep(5)

# Check if any alerts were classified
stats = alert_queue.get_stats()
print(f"\nStats: {stats}")

# Manually trigger feature extraction on a dummy attack session
from online.feature_extractor import extract_features
import numpy as np

# Simulate a SYN flood session
attack_session = {
    "start_time": 0.0,
    "last_seen": 0.1,  # 100ms duration
    "fwd_pkt_sizes": [60] * 100,  # 100 small packets (SYN only)
    "bwd_pkt_sizes": [],  # No response
    "fwd_iat_list": [0.001] * 99,  # 1ms between packets
    "bwd_iat_list": [],
    "fwd_psh_flags": 0,
    "fin_cnt": 0,
    "syn_cnt": 100,  # 100 SYN flags
    "rst_cnt": 0,
    "psh_cnt": 0,
    "ack_cnt": 0,
}

features = extract_features(attack_session)
print(f"\nExtracted features shape: {features.shape}")
print(f"Feature values: {features[0]}")

# Run prediction
from online.ml_engine import predict
ml_class, ml_prob = predict(features)
print(f"\nPrediction: {ml_class} (p={ml_prob:.3f})")