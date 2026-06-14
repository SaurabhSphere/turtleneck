"""
Model Training Pipeline
========================
Trains the XGBoost phishing classifier using features from the shared
feature engineering module.  Can be run standalone:
    python -m app.train
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

# Allow standalone execution
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.features import extract_features
from app.utils import find_file, prepare_combined_dataset

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(CURRENT_DIR)
WORKSPACE_DIR = os.path.dirname(BACKEND_DIR)
MODEL_OUT_DIR = os.path.join(BACKEND_DIR, "models")
os.makedirs(MODEL_OUT_DIR, exist_ok=True)


def run_training():
    """Full training pipeline: ingest -> features -> split -> train -> evaluate -> save."""
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

    # ── 1. Ingest ────────────────────────────────────────────────────────
    df = prepare_combined_dataset(WORKSPACE_DIR)

    # ── 2. Handle class imbalance (downsample majority class) ────────────
    phishing = df[df["label"] == "phishing"]
    legitimate = df[df["label"] == "legitimate"]
    if len(legitimate) > len(phishing):
        print(f"Balancing: downsampling legitimate from {len(legitimate)} -> {len(phishing)}")
        legitimate = legitimate.sample(n=len(phishing), random_state=42)
    elif len(phishing) > len(legitimate):
        print(f"Balancing: downsampling phishing from {len(phishing)} -> {len(legitimate)}")
        phishing = phishing.sample(n=len(legitimate), random_state=42)
    df = pd.concat([phishing, legitimate], ignore_index=True)
    print(f"\nBalanced dataset: {df['label'].value_counts().to_dict()}")

    # ── 3. Feature Extraction ────────────────────────────────────────────
    features_csv = find_file("domain_features_v3.csv", WORKSPACE_DIR)
    if not features_csv:
        features_csv = find_file("domain_features_v2.csv", WORKSPACE_DIR)
    if not features_csv:
        features_csv = find_file("domain_features.csv", WORKSPACE_DIR)

    cached_features_df = None
    if features_csv:
        print(f"Loading pre-computed features: {features_csv}")
        temp_df = pd.read_csv(features_csv)
        if all(col in temp_df.columns for col in FEATURE_ORDER):
            cached_features_df = temp_df.drop_duplicates(subset=["domain"])
        else:
            print("Pre-computed features missing columns. Will re-extract.")

    unique_domains_df = df.drop_duplicates(subset=["domain"])[["domain", "label"]]
    
    if cached_features_df is not None:
        missing_domains = set(unique_domains_df["domain"]) - set(cached_features_df["domain"])
        if missing_domains:
            print(f"Extracting features for {len(missing_domains)} new domains...")
            missing_df = pd.DataFrame({"domain": list(missing_domains)})
            missing_features = missing_df["domain"].apply(extract_features)
            missing_feature_df = pd.DataFrame(missing_features.tolist())
            new_features_df = pd.concat([missing_df, missing_feature_df], axis=1)
            cached_features_df = pd.concat([cached_features_df, new_features_df], ignore_index=True)
    else:
        print("Extracting features from scratch...")
        features = unique_domains_df["domain"].apply(extract_features)
        feature_df = pd.DataFrame(features.tolist())
        cached_features_df = pd.concat(
            [unique_domains_df.reset_index(drop=True), feature_df.reset_index(drop=True)], axis=1
        )

    # Save unique features back to cache to prevent bloat
    data_dir = os.path.join(WORKSPACE_DIR, "data")
    out_path = os.path.join(data_dir, "domain_features_v3.csv") if os.path.isdir(data_dir) else os.path.join(WORKSPACE_DIR, "domain_features_v3.csv")
    cached_features_df.drop(columns=["label"], errors="ignore").to_csv(out_path, index=False)
    
    # Merge features back onto the full (duplicated/augmented) dataset
    final_df = df.merge(cached_features_df.drop(columns=["label"], errors="ignore"), on="domain", how="left")

    # ── 4. Prepare X / y ─────────────────────────────────────────────────
    X = final_df[FEATURE_ORDER]
    y = final_df["label"]

    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    print("\nLabel classes:", dict(enumerate(label_encoder.classes_)))

    # ── 5. Train / Validation / Test Split (70 / 15 / 15) ────────────────
    X_train, X_temp, y_train, y_temp = train_test_split(
        X, y_encoded, test_size=0.30, stratify=y_encoded, random_state=42
    )
    X_valid, X_test, y_valid, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, stratify=y_temp, random_state=42
    )
    print(f"\nSplit sizes — Train: {X_train.shape}  Valid: {X_valid.shape}  Test: {X_test.shape}")

    # ── 6. Train XGBoost ─────────────────────────────────────────────────
    print("\nTraining XGBoost classifier...")
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
    print("Training complete.")

    # ── 7. Evaluation ────────────────────────────────────────────────────
    for split_name, X_eval, y_eval in [
        ("VALIDATION", X_valid, y_valid),
        ("TEST", X_test, y_test),
    ]:
        preds = model.predict(X_eval)
        print(f"\n{'=' * 40}")
        print(f"{split_name} RESULTS")
        print(f"{'=' * 40}")
        print(f"Accuracy:  {accuracy_score(y_eval, preds):.4f}")
        print(f"Precision: {precision_score(y_eval, preds, average='weighted'):.4f}")
        print(f"Recall:    {recall_score(y_eval, preds, average='weighted'):.4f}")
        print(f"F1 Score:  {f1_score(y_eval, preds, average='weighted'):.4f}")
        print(f"\nClassification Report:\n{classification_report(y_eval, preds, target_names=label_encoder.classes_)}")
        print(f"Confusion Matrix:\n{confusion_matrix(y_eval, preds)}")

    # ── 8. Feature Importance ────────────────────────────────────────────
    importance_df = pd.DataFrame(
        {"feature": X.columns, "importance": model.feature_importances_}
    ).sort_values(by="importance", ascending=False)
    print(f"\nTop 10 Feature Importances:\n{importance_df.head(10).to_string(index=False)}")

    # ── 9. Serialize ─────────────────────────────────────────────────────
    joblib.dump(model, os.path.join(MODEL_OUT_DIR, "phishing_xgboost.joblib"))
    joblib.dump(label_encoder, os.path.join(MODEL_OUT_DIR, "label_encoder.joblib"))
    joblib.dump(list(X.columns), os.path.join(MODEL_OUT_DIR, "feature_columns.joblib"))
    print(f"\nModel artifacts saved to {MODEL_OUT_DIR}")


if __name__ == "__main__":
    run_training()
