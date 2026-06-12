import os
import joblib
import pandas as pd
from .features import extract_features, get_additional_indicators

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.path.join(CURRENT_DIR, "..", "models")

# Load model, label encoder, and feature column list
try:
    model = joblib.load(os.path.join(MODEL_DIR, "phishing_xgboost.joblib"))
    label_encoder = joblib.load(os.path.join(MODEL_DIR, "label_encoder.joblib"))
    feature_columns = joblib.load(os.path.join(MODEL_DIR, "feature_columns.joblib"))
except Exception as e:
    print(f"Error loading model artifacts: {e}")
    model, label_encoder, feature_columns = None, None, None

def predict_domain(domain: str) -> dict:
    """
    Predicts if a domain is phishing or legitimate.
    Returns:
        dict: {
            "domain": str,
            "label": str, (Phishing / Legitimate)
            "confidence": float,
            "features": dict,
            "additional_indicators": dict
        }
    """
    if model is None or label_encoder is None or feature_columns is None:
        raise RuntimeError("Machine Learning Model is not loaded successfully.")

    # 1. Extract base features
    base_features = extract_features(domain)
    
    # 2. Extract additional features (not used by ML but shown on UI)
    extra_indicators = get_additional_indicators(domain)

    # 3. Create Aligned Dictionary for Feature columns
    tld_val = base_features.get("tld", "")
    
    aligned_dict = {}
    for col in feature_columns:
        if col.startswith("tld_"):
            tld_name = col.split("tld_")[1]
            aligned_dict[col] = int(tld_val == tld_name)
        else:
            # Copy base numerical/boolean feature value
            aligned_dict[col] = base_features.get(col, 0)

    # Construct DataFrame in one go
    X_input = pd.DataFrame([aligned_dict])[feature_columns]

    # 4. Predict probability and label
    prob = model.predict_proba(X_input)[0]  # [p_legit, p_phish]
    pred_idx = model.predict(X_input)[0]

    # Label index to human readable string
    pred_label = label_encoder.inverse_transform([pred_idx])[0]
    
    # Confidence is the probability of the predicted label
    confidence = float(prob[pred_idx])

    return {
        "domain": domain,
        "label": pred_label,
        "confidence": confidence,
        "features": base_features,
        "additional_indicators": extra_indicators
    }
