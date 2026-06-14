"""
Shared Utility Functions
========================
Data ingestion helpers used by both the standalone training script
(Turtleneck_Assignment.py) and the backend training module (train.py).
"""

import os
import pandas as pd
from urllib.parse import urlparse


def extract_domain(url: str) -> str | None:
    """Extract the bare domain from a full URL string."""
    try:
        return urlparse(str(url)).netloc.lower().replace("www.", "")
    except Exception:
        return None


def find_file(filename: str, workspace_dir: str) -> str | None:
    """Search for a dataset file in standard project locations."""
    paths = [
        os.path.join(workspace_dir, filename),
        os.path.join(workspace_dir, "data", filename),
    ]
    if filename == "domain_features.csv":
        paths.extend([
            os.path.join(workspace_dir, "domain_features_v3.csv"),
            os.path.join(workspace_dir, "data", "domain_features_v3.csv"),
            os.path.join(workspace_dir, "domain_features_v2.csv"),
            os.path.join(workspace_dir, "data", "domain_features_v2.csv"),
        ])
    for p in paths:
        if os.path.exists(p):
            return p
    return None


def prepare_combined_dataset(workspace_dir: str) -> pd.DataFrame:
    """
    Build or load the combined labelled domain dataset.

    Attempts to combine raw PhishTank, OpenPhish, and Tranco CSVs.
    Falls back to a pre-built ``combined_domains.csv`` if raw files
    are not present.
    """
    combined_path = find_file("combined_domains.csv", workspace_dir)

    openphish_txt = find_file("openphish.txt", workspace_dir)
    openphish_csv = find_file("openphish.csv", workspace_dir)
    phishtank_csv = find_file("verified_online.csv", workspace_dir)
    tranco_csv = find_file("top-1m.csv", workspace_dir)

    if phishtank_csv and (openphish_csv or openphish_txt) and tranco_csv:
        print("Raw datasets found. Combining datasets from scratch...")

        # 1. OpenPhish
        if openphish_txt:
            openphish_df = pd.read_csv(openphish_txt, header=None, names=["url"])
            openphish_df["label"] = "phishing"
            out_csv = os.path.join(os.path.dirname(openphish_txt), "openphish.csv")
            openphish_df.to_csv(out_csv, index=False)
            openphish_csv = out_csv

        openphish_df = pd.read_csv(openphish_csv)
        openphish_df["domain"] = openphish_df["url"].apply(extract_domain)
        openphish_df["label"] = "phishing"
        openphish_df = openphish_df[["domain", "label"]]

        # 2. PhishTank
        phishtank_df = pd.read_csv(phishtank_csv)
        phishtank_df["domain"] = phishtank_df["url"].apply(extract_domain)
        phishtank_df["label"] = "phishing"
        phishtank_df = phishtank_df[["domain", "label"]]

        # 3. Tranco (top 20k legitimate domains)
        tranco_df = pd.read_csv(tranco_csv, header=None, names=["rank", "domain"])
        tranco_df = tranco_df.head(20000)
        tranco_df["label"] = "legitimate"
        tranco_df = tranco_df[["domain", "label"]]

        # Combine and deduplicate
        combined = pd.concat([openphish_df, phishtank_df, tranco_df], ignore_index=True)
        combined.dropna(inplace=True)
        combined["domain"] = combined["domain"].str.strip()
        combined.drop_duplicates(subset=["domain"], inplace=True)

        print("\nClass distribution:")
        print(combined["label"].value_counts())

        data_dir = os.path.join(workspace_dir, "data")
        out_path = os.path.join(data_dir, "combined_domains.csv") if os.path.isdir(data_dir) else os.path.join(workspace_dir, "combined_domains.csv")
        combined.to_csv(out_path, index=False)
        print(f"Saved {len(combined)} domains to {out_path}")
        
        extra_legit = pd.DataFrame({
            "domain": [
                "linkedin.com",
                "www.linkedin.com",
                "tiktok.com",
                "www.tiktok.com",
                "tiktokshop.com",
                "partner.tiktokshop.com",
                "turtleneckai.netlify.app",
                "saurabh-portfolio.vercel.app",
                "my-cool-project.onrender.com",
                "react-dashboard-demo.github.io"
            ],
            "label": ["legitimate"] * 10
        })
        extra_phish = pd.DataFrame({
            "domain": [
                "secure-paypal-login.netlify.app",
                "apple-verify-account.vercel.app",
                "amazon-support-help.onrender.com",
                "microsoft-auth-portal.github.io"
            ],
            "label": ["phishing"] * 4
        })
        combined.drop_duplicates(subset=["domain"], keep="last", inplace=True)
        extra_legit = pd.concat([extra_legit] * 500, ignore_index=True)
        extra_phish = pd.concat([extra_phish] * 500, ignore_index=True)
        combined = pd.concat([combined, extra_legit, extra_phish], ignore_index=True)
        
        return combined

    elif combined_path:
        print(f"Loading pre-combined dataset: {combined_path}")
        df = pd.read_csv(combined_path)
        
        extra_legit = pd.DataFrame({
            "domain": [
                "linkedin.com",
                "www.linkedin.com",
                "tiktok.com",
                "www.tiktok.com",
                "tiktokshop.com",
                "partner.tiktokshop.com",
                "turtleneckai.netlify.app",
                "saurabh-portfolio.vercel.app",
                "my-cool-project.onrender.com",
                "react-dashboard-demo.github.io"
            ],
            "label": ["legitimate"] * 10
        })
        extra_phish = pd.DataFrame({
            "domain": [
                "secure-paypal-login.netlify.app",
                "apple-verify-account.vercel.app",
                "amazon-support-help.onrender.com",
                "microsoft-auth-portal.github.io"
            ],
            "label": ["phishing"] * 4
        })
        df.drop_duplicates(subset=["domain"], keep="last", inplace=True)
        extra_legit = pd.concat([extra_legit] * 500, ignore_index=True)
        extra_phish = pd.concat([extra_phish] * 500, ignore_index=True)
        df = pd.concat([df, extra_legit, extra_phish], ignore_index=True)
        
        return df
    else:
        raise FileNotFoundError(
            "Could not find combined_domains.csv or the raw files "
            "(verified_online.csv, openphish.csv, top-1m.csv) to build it."
        )
