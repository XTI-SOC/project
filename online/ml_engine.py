"""
online/ml_engine.py — XTI-SOC Phase 2

ML inference engine: loads artifacts and classifies feature vectors.

Design rules:
  - Loads binary artifacts at module import time (fail-fast if missing)
  - Loads multiclass artifacts optionally (graceful degradation to UNKNOWN)
  - predict() returns (binary_class, attack_type, ml_probability)
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

_MODEL_MULTICLASS_PATH = _ARTIFACTS_DIR / "model_multiclass.pkl"
_SCALER_MULTICLASS_PATH = _ARTIFACTS_DIR / "scaler_multiclass.pkl"
_LABEL_MAP_PATH = _ARTIFACTS_DIR / "label_map.pkl"


# ── Global artifacts (loaded once at import) ───────────────────────────────────
MODEL = None
SCALER = None
EXPLAINER = None
FEATURE_LIST = None

MODEL_MULTICLASS = None
SCALER_MULTICLASS = None
LABEL_MAP = None


def _load_artifacts() -> None:
    """
    Load all artifacts. Called once at module import time.
    Binary artifacts are required. Multiclass artifacts are optional.
    """
    global MODEL, SCALER, EXPLAINER, FEATURE_LIST
    global MODEL_MULTICLASS, SCALER_MULTICLASS, LABEL_MAP
    
    print("[ML_ENGINE] Loading binary artifacts...")
    
    # Check all binary files exist
    for path in [_MODEL_PATH, _SCALER_PATH, _EXPLAINER_PATH, _FEATURES_PATH]:
        if not path.exists():
            raise FileNotFoundError(f"Missing artifact: {path}")
            
    # Load binary model
    with open(_MODEL_PATH, 'rb') as f:
        MODEL = pickle.load(f)
    print(f"  [OK] Binary Model: {type(MODEL).__name__} ({MODEL.n_features_in_} features)")

    # Load binary scaler
    with open(_SCALER_PATH, 'rb') as f:
        SCALER = pickle.load(f)
    scaler_type = type(SCALER).__name__
    
    # Verify scaler has correct attributes
    if hasattr(SCALER, 'center_'):
        n_features = len(SCALER.center_)
        print(f"  [OK] Binary Scaler: {scaler_type} ({n_features} features, using .center_)")
    elif hasattr(SCALER, 'mean_'):
        n_features = len(SCALER.mean_)
        print(f"  [OK] Binary Scaler: {scaler_type} ({n_features} features, using .mean_)")
    else:
        raise AttributeError(f"Scaler {scaler_type} has unknown attributes")
        
    # Load binary explainer (graceful: SHAP may fail on Python 3.13)
    try:
        with open(_EXPLAINER_PATH, 'rb') as f:
            EXPLAINER = pickle.load(f)
        print(f"  [OK] Binary Explainer: {type(EXPLAINER).__name__}")
    except Exception as e:
        EXPLAINER = None
        print(f"  [WARNING] SHAP Explainer failed to load (Python version mismatch): {e}")
        print(f"  [WARNING] SHAP explanations will be disabled. Re-serialize explainer.pkl to fix.")
    
    # Load feature list
    with open(_FEATURES_PATH, 'rb') as f:
        FEATURE_LIST = pickle.load(f)
    print(f"  [OK] Feature list: {len(FEATURE_LIST)} features")
    
    # Verify feature count consistency
    if MODEL.n_features_in_ != n_features != len(FEATURE_LIST):
        raise ValueError(
            f"Feature count mismatch: "
            f"model={MODEL.n_features_in_}, "
            f"scaler={n_features}, "
            f"list={len(FEATURE_LIST)}"
        )
        
    print("[ML_ENGINE] Loading multiclass artifacts...")
    if _MODEL_MULTICLASS_PATH.exists() and _SCALER_MULTICLASS_PATH.exists() and _LABEL_MAP_PATH.exists():
        with open(_MODEL_MULTICLASS_PATH, 'rb') as f:
            MODEL_MULTICLASS = pickle.load(f)
        with open(_SCALER_MULTICLASS_PATH, 'rb') as f:
            SCALER_MULTICLASS = pickle.load(f)
        with open(_LABEL_MAP_PATH, 'rb') as f:
            LABEL_MAP = pickle.load(f)
        print("  [OK] Multiclass artifacts loaded successfully.")
    else:
        print("  [WARNING] Multiclass artifacts missing. Fallback to UNKNOWN will be used.")
        
    print(f"[ML_ENGINE] Initialization complete\n")


# Load artifacts immediately when this module is imported
_load_artifacts()


# ── Public API ─────────────────────────────────────────────────────────────────

def predict(feature_vector: np.ndarray) -> tuple[str, str, float]:
    """
    Classify a feature vector using the loaded models.
    
    Parameters
    ----------
    feature_vector : np.ndarray
        Shape (1, 25) feature array from feature_extractor.extract_features()
        
    Returns
    -------
    tuple[str, str, float]
        (binary_class, attack_type, ml_probability)
        - binary_class: "BENIGN" or "MALICIOUS"
        - attack_type: "BENIGN"/"DoS"/"DDoS"/"BruteForce"/"WebAttack"/"Infiltration"/"Botnet"/"UNKNOWN"
        - ml_probability: probability of MALICIOUS class [0.0, 1.0] from binary model
    """
    if feature_vector.shape != (1, 25):
        raise ValueError(
            f"Expected feature vector shape (1, 25), got {feature_vector.shape}"
        )
        
    # Step 1: Scale with binary scaler and predict binary class
    scaled_bin = SCALER.transform(feature_vector)
    proba = MODEL.predict_proba(scaled_bin)
    ml_prob = float(proba[0][1])
    binary_class = "MALICIOUS" if ml_prob > 0.5 else "BENIGN"
    
    # Step 2: Multiclass classification
    if binary_class == "MALICIOUS":
        if MODEL_MULTICLASS is not None and SCALER_MULTICLASS is not None and LABEL_MAP is not None:
            scaled_multi = SCALER_MULTICLASS.transform(feature_vector)
            pred_int = int(MODEL_MULTICLASS.predict(scaled_multi)[0])
            attack_type = LABEL_MAP.get(pred_int, "UNKNOWN")
            if attack_type == "BENIGN":
                attack_type = "UNKNOWN"
        else:
            attack_type = "UNKNOWN"
    else:
        attack_type = "BENIGN"
        
    return binary_class, attack_type, ml_prob


def get_shap_explanation(feature_vector: np.ndarray) -> list[dict]:
    """
    Get SHAP explanation for a MALICIOUS flow based on the binary explainer.
    
    Returns
    -------
    list[dict]
        Top 5 features sorted by absolute shap_value descending.
        [{"feature": str, "shap_value": float}, ...]
    """
    if EXPLAINER is None:
        return []
    try:
        scaled = SCALER.transform(feature_vector)
        shap_values = EXPLAINER.shap_values(scaled)
        vals = shap_values[0]
        indices = np.argsort(np.abs(vals))[::-1][:5]
        result = []
        for idx in indices:
            result.append({
                "feature": FEATURE_LIST[idx],
                "shap_value": float(vals[idx])
            })
        return result
    except Exception:
        return []


def get_feature_names() -> list[str]:
    """
    Return the list of 25 feature names.
    """
    return FEATURE_LIST.copy()


def get_model_info() -> dict:
    """
    Return metadata about the loaded models.
    """
    return {
        "model_type": type(MODEL).__name__,
        "scaler_type": type(SCALER).__name__,
        "n_features": MODEL.n_features_in_,
        "classes": MODEL.classes_.tolist(),
        "multiclass_loaded": MODEL_MULTICLASS is not None
    }