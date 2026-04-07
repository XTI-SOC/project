"""
online/ml_engine.py — XTI-SOC Phase 2

ML inference engine: loads artifacts and classifies feature vectors.

Design rules:
  - Loads all 4 artifacts at module import time (fail-fast if missing)
  - predict() is the ONLY public function
  - Works with RobustScaler (uses .center_ and .scale_, not .mean_)
  - Returns (ml_class, ml_probability) tuple
  - Thread-safe (sklearn models are read-only after loading)
"""

import pickle
import os
import numpy as np
from pathlib import Path


# ── Artifact paths ─────────────────────────────────────────────────────────────
# Assumes this file is at: online/ml_engine.py
# Artifacts are at: artifacts/*.pkl
_ONLINE_DIR = Path(__file__).parent
_ARTIFACTS_DIR = _ONLINE_DIR.parent / "artifacts"

_MODEL_PATH = _ARTIFACTS_DIR / "model.pkl"
_SCALER_PATH = _ARTIFACTS_DIR / "scaler.pkl"
_EXPLAINER_PATH = _ARTIFACTS_DIR / "explainer.pkl"
_FEATURES_PATH = _ARTIFACTS_DIR / "feature_list.pkl"


# ── Global artifacts (loaded once at import) ───────────────────────────────────
MODEL = None
SCALER = None
EXPLAINER = None
FEATURE_LIST = None


def _load_artifacts() -> None:
    """
    Load all 4 artifacts. Called once at module import time.
    Crashes the program if any artifact is missing or corrupt.
    """
    global MODEL, SCALER, EXPLAINER, FEATURE_LIST
    
    print("[ML_ENGINE] Loading artifacts...")
    
    # Check all files exist
    for path in [_MODEL_PATH, _SCALER_PATH, _EXPLAINER_PATH, _FEATURES_PATH]:
        if not path.exists():
            raise FileNotFoundError(f"Missing artifact: {path}")
    
    # Load model
    with open(_MODEL_PATH, 'rb') as f:
        MODEL = pickle.load(f)
    print(f"  ✅ Model: {type(MODEL).__name__} ({MODEL.n_features_in_} features)")
    
    # Load scaler
    with open(_SCALER_PATH, 'rb') as f:
        SCALER = pickle.load(f)
    scaler_type = type(SCALER).__name__
    
    # Verify scaler has correct attributes (works for both Standard and Robust)
    if hasattr(SCALER, 'center_'):
        n_features = len(SCALER.center_)
        print(f"  ✅ Scaler: {scaler_type} ({n_features} features, using .center_)")
    elif hasattr(SCALER, 'mean_'):
        n_features = len(SCALER.mean_)
        print(f"  ✅ Scaler: {scaler_type} ({n_features} features, using .mean_)")
    else:
        raise AttributeError(f"Scaler {scaler_type} has unknown attributes")
    
    # Load explainer (not used in Phase 2, but verify it exists)
    with open(_EXPLAINER_PATH, 'rb') as f:
        EXPLAINER = pickle.load(f)
    print(f"  ✅ Explainer: {type(EXPLAINER).__name__}")
    
    # Load feature list
    with open(_FEATURES_PATH, 'rb') as f:
        FEATURE_LIST = pickle.load(f)
    print(f"  ✅ Feature list: {len(FEATURE_LIST)} features")
    
    # Verify feature count consistency
    if MODEL.n_features_in_ != n_features != len(FEATURE_LIST):
        raise ValueError(
            f"Feature count mismatch: "
            f"model={MODEL.n_features_in_}, "
            f"scaler={n_features}, "
            f"list={len(FEATURE_LIST)}"
        )
    
    print(f"[ML_ENGINE] All artifacts loaded successfully\n")


# Load artifacts immediately when this module is imported
_load_artifacts()


# ── Public API ─────────────────────────────────────────────────────────────────

def predict(feature_vector: np.ndarray) -> tuple[str, float]:
    """
    Classify a feature vector using the loaded model.
    
    Parameters
    ----------
    feature_vector : np.ndarray
        Shape (1, 25) feature array from feature_extractor.extract_features()
        
    Returns
    -------
    tuple[str, float]
        (ml_class, ml_probability)
        - ml_class: "BENIGN" or "MALICIOUS"
        - ml_probability: probability of MALICIOUS class [0.0, 1.0]
        
    Raises
    ------
    ValueError
        If feature_vector has wrong shape
    """
    if feature_vector.shape != (1, 25):
        raise ValueError(
            f"Expected feature vector shape (1, 25), got {feature_vector.shape}"
        )
    
    # Scale features
    # Works with both StandardScaler and RobustScaler — they both implement .transform()
    scaled = SCALER.transform(feature_vector)
    
    # Get prediction probabilities
    # XGBClassifier.predict_proba returns [[P(class_0), P(class_1)]]
    proba = MODEL.predict_proba(scaled)
    
    # Extract malicious probability (class 1)
    ml_prob = float(proba[0][1])
    
    # Classify using 0.5 threshold
    ml_class = "MALICIOUS" if ml_prob > 0.5 else "BENIGN"
    
    return ml_class, ml_prob


def get_feature_names() -> list[str]:
    """
    Return the list of 25 feature names.
    Useful for debugging and logging.
    """
    return FEATURE_LIST.copy()


def get_model_info() -> dict:
    """
    Return metadata about the loaded model.
    Useful for diagnostics.
    """
    return {
        "model_type": type(MODEL).__name__,
        "scaler_type": type(SCALER).__name__,
        "n_features": MODEL.n_features_in_,
        "classes": MODEL.classes_.tolist(),
    }