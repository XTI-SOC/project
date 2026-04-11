"""Isolated unit test for flow_to_features() — no ml_engine required."""
import sys, os
sys.stdout.reconfigure(encoding='utf-8')
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import numpy as np

# Patch ml_engine out before importing nfstream_engine
import types, unittest.mock as mock

# Create a fake ml_engine module so nfstream_engine can import without loading PKLs
fake_ml = types.ModuleType("online.ml_engine")
fake_ml.predict = lambda vec: ("BENIGN", 0.1)
sys.modules["online.ml_engine"] = fake_ml

# Now import our code
from online.nfstream_engine import flow_to_features, FEATURE_NAMES


class MockFlow:
    bidirectional_duration_ms   = 500.0
    bidirectional_bytes         = 2000
    bidirectional_packets       = 10
    src2dst_bytes               = 1200
    dst2src_bytes               = 800
    src2dst_packets             = 6
    dst2src_packets             = 4
    src2dst_max_pkt_len         = 200.0
    src2dst_min_pkt_len         = 40.0
    src2dst_mean_pkt_len        = 200.0
    dst2src_max_pkt_len         = 200.0
    dst2src_min_pkt_len         = 40.0
    dst2src_mean_pkt_len        = 200.0
    bidirectional_mean_piat_ms  = 55.5
    src2dst_mean_piat_ms        = 100.0
    dst2src_mean_piat_ms        = 125.0
    src2dst_psh_packets         = 2
    bidirectional_fin_packets   = 2
    bidirectional_syn_packets   = 1
    bidirectional_rst_packets   = 0
    bidirectional_psh_packets   = 3
    bidirectional_ack_packets   = 8


# ── Test 1: Normal flow ────────────────────────────────────────────────────────
vec = flow_to_features(MockFlow())
assert vec is not None,             "Normal flow should not return None"
assert vec.shape == (1, 25),        f"Shape mismatch: {vec.shape}"
assert vec.dtype == np.float64,     f"dtype mismatch: {vec.dtype}"
assert not np.any(np.isinf(vec)),   "inf in feature vector"
assert not np.any(np.isnan(vec)),   "nan in feature vector"

print("Feature vector (normal flow):")
for name, val in zip(FEATURE_NAMES, vec.flatten()):
    print(f"  {name:<22} = {val:.4f}")

# ── Test 2: Zero-duration flow ────────────────────────────────────────────────
class ZeroDuration(MockFlow):
    bidirectional_duration_ms = 0.0

v2 = flow_to_features(ZeroDuration())
assert v2 is not None,              "Zero-duration flow should not discard"
assert not np.any(np.isinf(v2)),    "Zero-duration caused inf!"
assert not np.any(np.isnan(v2)),    "Zero-duration caused nan!"
print("\nZero-duration flow: OK (no inf/nan)")

# ── Test 3: Zero src2dst_bytes (Down/Up Ratio = 0) ───────────────────────────
class ZeroFwd(MockFlow):
    src2dst_bytes = 0

v3 = flow_to_features(ZeroFwd())
assert v3 is not None,              "Zero fwd bytes should not discard"
du_idx = FEATURE_NAMES.index("Down/Up Ratio")
assert v3[0, du_idx] == 0.0,       f"Down/Up Ratio should be 0, got {v3[0, du_idx]}"
print("Zero src2dst_bytes → Down/Up Ratio = 0.0: OK")

# ── Test 4: Exception in flow access ─────────────────────────────────────────
class BrokenFlow:
    @property
    def bidirectional_duration_ms(self):
        raise AttributeError("simulated broken flow")

v4 = flow_to_features(BrokenFlow())
assert v4 is None, "Broken flow should return None"
print("Broken flow returns None: OK")

# ── Summary ───────────────────────────────────────────────────────────────────
print()
print("=" * 50)
print("ALL UNIT TESTS PASSED")
print(f"  FEATURE_NAMES count : {len(FEATURE_NAMES)}  (must be 25)")
print(f"  Output shape        : {vec.shape}")
print(f"  Output dtype        : {vec.dtype}")
print("=" * 50)
