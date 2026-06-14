"""
Model Inference Module
======================
Loads the serialized XGBoost model and provides a prediction function
that runs on the saved model — no retraining per request.
"""

import os
import logging
import joblib
import pandas as pd
from .features import extract_features, get_additional_indicators

logger = logging.getLogger(__name__)

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(CURRENT_DIR, "..", "models")

# Load model artifacts at module import time
try:
    model = joblib.load(os.path.join(MODEL_DIR, "phishing_xgboost.joblib"))
    label_encoder = joblib.load(os.path.join(MODEL_DIR, "label_encoder.joblib"))
    feature_columns = joblib.load(os.path.join(MODEL_DIR, "feature_columns.joblib"))
    logger.info("ML model artifacts loaded successfully from %s", MODEL_DIR)
except Exception as e:
    logger.error("Failed to load model artifacts: %s", e)
    model, label_encoder, feature_columns = None, None, None


def predict_domain(domain: str) -> dict:
    """
    Predict whether a domain is phishing or legitimate.

    Returns a dict with keys: domain, label, confidence, features,
    additional_indicators.
    """
    if model is None or label_encoder is None or feature_columns is None:
        raise RuntimeError(
            "ML model is not loaded. Ensure phishing_xgboost.joblib, "
            "label_encoder.joblib, and feature_columns.joblib exist in "
            f"{MODEL_DIR}"
        )

    # 1. Extract features (shared with training pipeline)
    base_features = extract_features(domain)

    # 2. Additional UI indicators (not used by the ML model)
    extra_indicators = get_additional_indicators(domain)

    # 3. Align feature dict to the trained column order
    aligned = {col: base_features.get(col, 0) for col in feature_columns}
    X_input = pd.DataFrame([aligned])[feature_columns]

    # 4. Predict
    prob = model.predict_proba(X_input)[0]
    pred_idx = model.predict(X_input)[0]
    pred_label = label_encoder.inverse_transform([pred_idx])[0]
    confidence = float(prob[pred_idx])

    # Heuristic override: if the domain is a verified root/subdomain of an official brand
    if base_features.get("known_brand_root", 0) == 1:
        logger.info("Heuristic override: %s is an official brand root domain. Overriding to legitimate.", domain)
        pred_label = "legitimate"
        confidence = 1.0

    return {
        "domain": domain,
        "label": pred_label,
        "confidence": confidence,
        "features": base_features,
        "additional_indicators": extra_indicators,
    }
