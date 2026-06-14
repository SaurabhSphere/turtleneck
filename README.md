# Turtleneck Phishing & Threat Intelligence Platform

Turtleneck is a production-grade, real-time Phishing and Suspected Domain Detection platform. The project features a reusable **Python Feature Engineering Engine**, an optimized **FastAPI REST API**, database logging with **PostgreSQL/SQLite**, a modern **Vite + React Dark Mode Dashboard**, and **Docker containerization**.

---

## 🏗️ System Architecture

The following text-based diagram outlines the system components and data flow:

```text
 ┌─────────────────────────────────────────────────────────────┐
 │                      Vite + React Frontend                  │
 │   - Assessment Hub (Lookup & Bulk URL input)                │
 │   - Threat Dashboard (Risk Gauges & Charts)                 │
 │   - Recent Scan History Table                               │
 └──────────────┬───────────────────────────────▲──────────────┘
                │ HTTP POST / GET               │ JSON response
 ┌──────────────▼───────────────────────────────┴──────────────┐
 │                      FastAPI Backend                        │
 │  [routers.py]                                               │
 │   - POST /api/predict (Single lookup)                       │
 │   - POST /api/predict/batch (Bulk lookup)                   │
 │   - GET /api/stats (Aggregated statistics)                  │
 │   - GET /api/history (Recent scans)                         │
 │                                                             │
 │  [services.py]                                              │
 │   - Business logic layer & data aggregation                 │
 │                                                             │
 │  [inference.py]                                             │
 │   - Loads pre-trained XGBoost Model + Label Encoder         │
 │   - Aligns incoming features with trained feature columns    │
 │                                                             │
 │  [features.py]                                              │
 │   - Reusable feature extraction engine (24 features)        │
 └──────────────┬───────────────────────────────┬──────────────┘
                │ read / write                  │ read / write
 ┌──────────────▼──────────┐         ┌──────────▼──────────────┐
 │      SQL Database       │         │      Trained Assets     │
 │ - SQLite (Local default)│         │ - XGBoost (.joblib)     │
 │ - PostgreSQL (Render)   │         │ - Label Encoder (.joblib)│
 └─────────────────────────┘         └─────────────────────────┘
```

---

## 📁 Repository Structure

```text
turtleneck/
├── Turtleneck_Assignment.ipynb # Original Colab research notebook
├── Turtleneck_Assignment.py    # Standalone command-line python training script
├── README.md                   # System documentation and manuals
├── .gitignore                  # Global git ignore rules (ignores credentials & datasets)
├── data/                       # Datasets folder
│   ├── sample_domains.csv      # Committed small sample dataset (150 rows) for quick testing
│   ├── combined_domains.csv    # Large pre-combined dataset (ignored)
│   ├── verified_online.csv     # Raw PhishTank dataset (ignored)
│   ├── top-1m.csv              # Raw Tranco dataset (ignored)
│   └── domain_features_v3.csv  # Pre-computed dataset features (ignored)
├── backend/                    # FastAPI Backend Service
│   ├── Dockerfile              # Docker container configuration
│   ├── requirements.txt        # Python backend dependencies
│   ├── predictions.db          # Local SQLite database (ignored)
│   ├── .env                    # Local environment config (ignored)
│   ├── .env.example            # Environment configuration template
│   ├── app/                    # FastAPI Application Modules
│   │   ├── __init__.py
│   │   ├── main.py             # App entrypoint and middleware mounting
│   │   ├── config.py           # Environment variables configuration loader
│   │   ├── database.py         # SQLAlchemy engine setup using modern DeclarativeBase
│   │   ├── models.py           # Database model defining domain_scans schema
│   │   ├── schemas.py          # Pydantic v2 validation models
│   │   ├── features.py         # Canonical feature engineering (shared)
│   │   ├── utils.py            # Data ingestion and file finder utilities (shared)
│   │   ├── services.py         # Business logic layer
│   │   ├── routers.py          # API route definitions
│   │   ├── inference.py        # ML inference wrapper on pre-trained assets
│   │   └── train.py            # Backend pipeline training entry point
│   ├── models/                 # Serialized model artifacts
│   │   ├── phishing_xgboost.joblib
│   │   ├── label_encoder.joblib
│   │   └── feature_columns.joblib
│   └── tests/                  # Automated Test Suite
│       └── test_backend.py     # API and service unit/integration tests
└── frontend/                   # Vite + React Frontend Dashboard
    ├── package.json            # Node.js dependencies
    ├── vite.config.js          # Vite config
    └── src/
        ├── main.jsx
        ├── App.jsx             # Main dashboard GUI
        └── index.css           # Premium dark-theme glassmorphism CSS
```

---

## 🧠 Feature Engineering Rationale & Category Breakdown

To train a robust machine learning classifier, Turtleneck extracts **23 distinct features** across **three logical categories** as required by the security specification:

### 1. URL / Domain Structure Features
These features capture the physical syntax of the domain name to detect automated generation or suspicious layouts:
* **length**: Phishing domains are often longer due to keyword stuffing.
* **subdomain_count**: Phishing attacks frequently leverage nested subdomains on compromised hosts.
* **hyphen_count**: Used to separate words in spoofed domains (e.g. `secure-bank-login`).
* **digit_count**: Phishing domains often incorporate random numbers to bypass spam blocks.
* **special_char_count**: Tracks non-alphanumeric separator marks.
* **entropy**: Shannon entropy measures the randomness of character distributions. High entropy indicates random generated domains (DGA).
* **is_country_code_tld** & **is_common_tld**: Maps TLD categories (e.g., standard `.com` vs. country codes).
* **is_suspicious_tld**: Flags top-level domains that are historically abused by threat actors (e.g. `.xyz`, `.top`, `.tk`, `.cam`).

### 2. Lexical Similarity & Brand Spoofing Features
These features examine the domain name text to detect brand-jacking, typosquatting, and deceptive keywords:
* **brand_match**: Checks for direct substring matches of popular target brands (e.g., *paypal*, *sbi*, *google*, *apple*).
* **min_brand_distance**: Calculates the Levenshtein distance between the domain name and known brands to identify typosquatting (e.g., `go0gle.com`).
* **known_brand_root**: Flags if the domain claims to be a root brand URL but lacks official registry context.
* **has_login**, **has_secure**, **has_verify**, **has_account**, **has_update**, **has_signin**, **has_support**, **has_payment**: Binary indicators marking the presence of high-urgency keywords used in social engineering.

### 3. IDN (Internationalized Domain Name) & Homoglyph Features
Threat actors use Unicode characters to construct homoglyph domains that appear visually identical to legitimate sites (mixed-script attacks):
* **has_punycode**: Identifies `xn--` prefix indicating internationalized encodings.
* **contains_unicode**: Flags the use of non-ASCII characters.
* **unicode_ratio**: Measures density of unicode characters.

### UI Supplement Indicators (Not used in ML training)
* **is_ip**: Warns when the hostname is a raw IPv4/IPv6 address instead of a domain.
* **has_mixed_script**: Flags active mixed-script character set usage (e.g., mixing Cyrillic and Latin alphabets like `gооgle.com`).

---

## 📈 Model Performance Summary (XGBoost)

The model is trained on a balanced dataset of **65,126 domains** using **XGBoost Classifier** with a stratified `70 / 15 / 15` split.

### Evaluation Metrics (Test Set)

| Metric | Score |
|---|---|
| **Accuracy** | `92.07%` |
| **Precision** | `92.55%` |
| **Recall** | `92.07%` |
| **F1 Score** | `92.04%` |

### Confusion Matrix (Test Set)

```text
                  Predicted Legitimate    Predicted Phishing
Actual Legitimate       4757 (TN)               128 (FP)
Actual Phishing          647 (FN)              4237 (TP)
```

### Top 10 Feature Importances

| Rank | Feature Name | Importance Score | Category |
| :---: | :--- | :---: | :--- |
| **1** | `subdomain_count` | **0.662863** | Structure |
| **2** | `is_suspicious_tld` | **0.115331** | Structure |
| **3** | `length` | **0.054148** | Structure |
| **4** | `is_common_tld` | **0.021780** | Structure |
| **5** | `entropy` | **0.019179** | Structure |
| **6** | `brand_match` | **0.016792** | Lexical |
| **7** | `min_brand_distance` | **0.016697** | Lexical |
| **8** | `hyphen_count` | **0.015555** | Structure |
| **9** | `digit_count` | **0.015325** | Structure |
| **10** | `is_country_code_tld` | **0.015295** | Structure |

---

## 🛠️ Installation & Setup

### Prerequisites
* Python 3.10+
* Node.js 18+
* PostgreSQL (optional, defaults to SQLite)

---

### 1. Backend Server Setup
1. Open a terminal and navigate to the `backend/` directory:
   ```bash
   cd backend
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   # On Windows:
   .\venv\Scripts\activate
   # On macOS/Linux:
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install httpx
   ```
4. Setup environment variables by copying `.env.example`:
   ```bash
   cp .env.example .env
   ```
   *(By default, leaving `DATABASE_URL` commented out in `.env` will cause the backend to automatically fall back to a local SQLite database file `predictions.db`).*
5. Launch the FastAPI server:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```
   *The interactive Swagger documentation is available at [http://localhost:8000/docs](http://localhost:8000/docs).*

---

### 2. Frontend Dashboard Setup
1. Open a new terminal and navigate to the `frontend/` directory:
   ```bash
   cd frontend
   ```
2. Install npm packages:
   ```bash
   npm install
   ```
3. Run the React development server:
   ```bash
   npm run dev
   ```
   *Open your browser and navigate to the local server, typically [http://localhost:5173](http://localhost:5173).*

---

### 3. Model Training & Reproducibility
To retrain the XGBoost classifier from the command line:

#### Method A: Root Script (For academic submission)
Run the standalone script from the repository root:
```bash
python Turtleneck_Assignment.py
```

#### Method B: Backend Module
Run the backend training entry point:
```bash
python -m app.train
```

Both methods will:
1. Ingest datasets from the `data/` folder.
2. Balance class counts (downsampling).
3. Apply canonical feature extraction.
4. Train the XGBoost model.
5. Print validation and test performance metrics (including confusion matrix).
6. Serialize output assets (`.joblib` files) directly into `backend/models/` for immediate API reloading.

#### Dataset Download instructions:
If you want to rebuild the full `combined_domains.csv` from scratch, download these files and place them in the `data/` directory:
* **PhishTank CSV**: Download `verified_online.csv` from [PhishTank](https://www.phishtank.com/developer_info.php).
* **OpenPhish TXT**: Download the feed from [OpenPhish](https://openphish.com/).
* **Tranco CSV**: Download the top 1M rank list `top-1m.csv` from [Tranco List](https://tranco-list.eu/).

---

## 📡 API Reference Documentation

### 1. Inspect Single Domain
* **Endpoint**: `POST /api/predict`
* **Content-Type**: `application/json`
* **Request**:
  ```json
  {
    "domain": "secure-login-paypal.cam"
  }
  ```
* **Response**:
  ```json
  {
    "domain": "secure-login-paypal.cam",
    "label": "phishing",
    "confidence": 0.9412,
    "timestamp": "2026-06-13T10:04:00Z",
    "features": {
      "length": 25,
      "subdomain_count": 0,
      "entropy": 3.42,
      "brand_match": 1,
      "has_punycode": 0,
      "tld": "cam"
    },
    "additional_indicators": {
      "is_ip": false,
      "has_mixed_script": false,
      "tld_is_risky": true
    }
  }
  ```

### 2. Inspect Batch of Domains
* **Endpoint**: `POST /api/predict/batch`
* **Request**:
  ```json
  {
    "domains": ["google.com", "sbi-verify-account.tk"]
  }
  ```

### 3. Aggregated Scan Stats
* **Endpoint**: `GET /api/stats`
* **Response**:
  ```json
  {
    "total_scanned": 12,
    "label_counts": {
      "legitimate": 8,
      "phishing": 4
    },
    "top_risky_tlds": [
      { "tld": "tk", "count": 2 },
      { "tld": "cam", "count": 1 }
    ]
  }
  ```

### 4. Recent Scan Logs
* **Endpoint**: `GET /api/history`
* **Response**: A list of recently scanned domain records.

---

## 🐳 Running with Docker

You can build and package the FastAPI backend container:

1. From the `backend/` directory, build the image:
   ```bash
   docker build -t threat-intel-api -f Dockerfile .
   ```
2. Run the container:
   ```bash
   # Defaults to SQLite local storage inside the container
   docker run -p 8000:8000 threat-intel-api

   # Or bind a hosted PostgreSQL database URL:
   docker run -p 8000:8000 -e DATABASE_URL=postgresql://user:pass@host:5432/db threat-intel-api
   ```

---

## 🧪 Testing

We use automated unit and integration tests covering the feature engineering, services, and REST API controllers.

Run the test suite from the `backend/` directory:
```bash
python -m unittest tests/test_backend.py
```

---

## 💡 Design Decisions & Assumptions

1. **Downsampling for Balancing**: To address class imbalance, the training pipeline downsamples the majority class (`legitimate` domains from Tranco) to match the minority class (`phishing` domains from PhishTank/OpenPhish). This mitigates class bias while preserving standard model calibration.
2. **Dynamic TLD Alignment**: At inference time, any new domain TLD must match the columns in the trained feature matrix. The inference engine handles unseen TLDs by zeroing out corresponding one-hot columns dynamically, avoiding model crashes.
3. **Database Fallback**: The backend uses SQLAlchemy's engine pattern. If no hosted PostgreSQL environment variable `DATABASE_URL` is found in the environment, it cleanly falls back to a local file-based SQLite database (`predictions.db`), making local testing instantly plug-and-play without complex services setup.
4. **Heuristic Override for Trusted Brand Roots**: To prevent false-positive classifications on trusted brand subdomains (such as `docs.google.com`), the inference engine applies a post-processing heuristic filter. If the domain's registered root matches exactly one of our trusted brand registries (via `known_brand_root`), the prediction is overridden to `legitimate` with `1.0` confidence. This preserves safety by ensuring malicious spoofing domains (like `google-login.com`) are still correctly classified by the machine learning model.
