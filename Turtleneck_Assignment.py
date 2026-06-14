"""
Turtleneck Assignment — Standalone Training Script
===================================================
This script can be run directly from the project root to reproduce
model training end-to-end:

    python Turtleneck_Assignment.py

It re-uses the shared feature engineering module (backend/app/features.py)
and shared data utilities (backend/app/utils.py) to ensure consistency
between training and inference.
"""

import os
import sys
import pandas as pd
import numpy as np
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix,
)
from xgboost import XGBClassifier

# ── Ensure backend package is importable ─────────────────────────────
WORKSPACE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(WORKSPACE_DIR, "backend"))

from app.features import extract_features          # single source of truth
from app.utils import prepare_combined_dataset, find_file  # shared helpers

MODEL_OUT_DIR = os.path.join(WORKSPACE_DIR, "backend", "models")
os.makedirs(MODEL_OUT_DIR, exist_ok=True)


# =====================================================================
# MAIN TRAINING PIPELINE
# =====================================================================

def main():
    # Enforce custom feature schema order
    FEATURE_ORDER = [
        "is_suspicious_tld",
        "brand_match",
        "length",
        "subdomain_count",
        "special_char_count",
        "min_brand_distance",
        "hyphen_count",
        "digit_count",
        "entropy",
        "has_login",
        "has_secure",
        "has_verify",
        "has_account",
        "has_update",
        "has_signin",
        "has_support",
        "has_payment",
        "known_brand_root",
        "has_punycode",
        "contains_unicode",
        "unicode_ratio",
        "is_country_code_tld",
        "is_common_tld",
    ]

    # ── 1. Ingest data ───────────────────────────────────────────────
    df = prepare_combined_dataset(WORKSPACE_DIR)

    # ── 2. Handle class imbalance (downsample majority class) ────────
    phishing = df[df["label"] == "phishing"]
    legitimate = df[df["label"] == "legitimate"]
    if len(legitimate) > len(phishing):
        print(f"Balancing: downsampling legitimate from {len(legitimate)} -> {len(phishing)}")
        legitimate = legitimate.sample(n=len(phishing), random_state=42)
    elif len(phishing) > len(legitimate):
        print(f"Balancing: downsampling phishing from {len(phishing)} -> {len(legitimate)}")
        phishing = phishing.sample(n=len(legitimate), random_state=42)
    df = pd.concat([phishing, legitimate], ignore_index=True)
    print(f"\nBalanced dataset:\n{df['label'].value_counts()}")

    # ── 3. Feature Extraction (shared module) ────────────────────────
    features_csv = find_file("domain_features.csv", WORKSPACE_DIR)
    final_df = None
    if features_csv:
        print(f"Loading pre-computed features: {features_csv}")
        temp_df = pd.read_csv(features_csv)
        # Check if all required features are present in the CSV
        if all(col in temp_df.columns for col in FEATURE_ORDER):
            final_df = temp_df
        else:
            print("Pre-computed features are missing required columns. Re-extracting from scratch...")

    if final_df is None:
        print("Extracting features (this may take a few minutes)...")
        features = df["domain"].apply(extract_features)
        feature_df = pd.DataFrame(features.tolist())
        final_df = pd.concat(
            [df.reset_index(drop=True), feature_df.reset_index(drop=True)], axis=1
        )
        data_dir = os.path.join(WORKSPACE_DIR, "data")
        out_path = (
            os.path.join(data_dir, "domain_features_v3.csv")
            if os.path.isdir(data_dir)
            else os.path.join(WORKSPACE_DIR, "domain_features_v3.csv")
        )
        final_df.to_csv(out_path, index=False)
        print(f"Features saved to {out_path}")

    # ── 4. Prepare X / y ─────────────────────────────────────────────
    print("Preparing feature matrix...")
    X = final_df[FEATURE_ORDER]
    y = final_df["label"]

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)

    # ── 5. Train / Validation / Test Split (70 / 15 / 15) ────────────
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y_encoded, test_size=0.30, stratify=y_encoded, random_state=42
    )
    X_valid, X_test, y_valid, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=42
    )

    print(f"\nTraining set:   {X_train.shape}")
    print(f"Validation set: {X_valid.shape}")
    print(f"Test set:       {X_test.shape}")

    # ── 6. Train XGBoost ─────────────────────────────────────────────
    print("\nTraining XGBoost Classifier...")
    model = XGBClassifier(
        objective="binary:logistic",
        n_estimators=300,
        max_depth=6,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.5,
        colsample_bylevel=0.5,
        random_state=42,
    )
    model.fit(X_train, y_train)
    print("Training Complete.")

    # ── 7. Evaluation ────────────────────────────────────────────────
    for split_name, X_eval, y_eval in [
        ("VALIDATION", X_valid, y_valid),
        ("TEST", X_test, y_test),
    ]:
        preds = model.predict(X_eval)
        print(f"\n{'=' * 40}")
        print(f"{split_name} EVALUATION METRICS")
        print(f"{'=' * 40}")
        print(f"Accuracy:  {accuracy_score(y_eval, preds):.4f}")
        print(f"Precision: {precision_score(y_eval, preds, average='weighted'):.4f}")
        print(f"Recall:    {recall_score(y_eval, preds, average='weighted'):.4f}")
        print(f"F1 Score:  {f1_score(y_eval, preds, average='weighted'):.4f}")
        print(f"\nClassification Report:")
        print(classification_report(y_eval, preds, target_names=label_encoder.classes_))
        print(f"Confusion Matrix:")
        print(confusion_matrix(y_eval, preds))

    # ── 8. Feature Importance ────────────────────────────────────────
    importance_df = pd.DataFrame(
        {"feature": X.columns, "importance": model.feature_importances_}
    ).sort_values(by="importance", ascending=False)
    print(f"\nTop 10 Feature Importances:")
    print(importance_df.head(10).to_string(index=False))

    # ── 9. Serialize Model Assets ────────────────────────────────────
    joblib.dump(model, os.path.join(MODEL_OUT_DIR, "phishing_xgboost.joblib"))
    joblib.dump(label_encoder, os.path.join(MODEL_OUT_DIR, "label_encoder.joblib"))
    joblib.dump(list(X.columns), os.path.join(MODEL_OUT_DIR, "feature_columns.joblib"))
    print(f"\nModel artifacts saved to: {MODEL_OUT_DIR}")


if __name__ == "__main__":
    main()
