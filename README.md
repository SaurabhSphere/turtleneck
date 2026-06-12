# Turtleneck Phishing & Threat Intelligence Platform

This repository contains the complete implementation for the Turtleneck Phishing and Suspected Domain Detection platform. The project features a reusable **Python Feature Extraction Engine**, a **FastAPI REST API**, database integration with **PostgreSQL (Render compatible)**, a modern **Vite + React Dark Mode Dashboard**, and **Docker containerization**.

---

## 📁 Repository Structure

```
turtleneck/
├── Turtleneck_Assignment.ipynb # Original training Jupyter notebook
├── combined_domains.csv        # Preprocessed domain dataset (52k rows)
├── domain_features.csv         # Engineered features dataset
├── backend/                    # FastAPI Backend Service
│   ├── app/
│   │   ├── main.py             # FastAPI routing and CORS
│   │   ├── config.py           # Environment variables configuration
│   │   ├── database.py         # SQLAlchemy & PostgreSQL session engine
│   │   ├── models.py           # SQLAlchemy scan log schema
│   │   ├── schemas.py          # Pydantic request & response schemas
│   │   ├── features.py         # Reusable feature engineering logic
│   │   └── inference.py        # XGBoost inference and dynamic TLD alignment
│   ├── models/                 # Serialized model files (ignored in Git, copied here)
│   │   ├── phishing_xgboost.joblib
│   │   ├── label_encoder.joblib
│   │   └── feature_columns.joblib
│   ├── tests/
│   │   └── test_backend.py     # Backend unit tests
│   ├── requirements.txt        # Backend python dependencies
│   └── Dockerfile              # Containerization for FastAPI API
└── frontend/                   # Vite + React Frontend Dashboard
    ├── src/
    │   ├── App.jsx             # Main dashboard tabs, state, and API integrations
    │   ├── index.css           # Custom dark-theme glassmorphism styling
    │   └── main.jsx
    ├── package.json
    └── vite.config.js
```

---

## ⚡ Feature Engineering & Model Details

The system classifies domain threats based on features engineered across **three categories**:
1. **URL / Structure Features**:
   - `length`: Raw domain length.
   - `subdomain_count`: Count of subdomains (excluding TLD & domain body).
   - `hyphen_count`: Number of hyphens.
   - `digit_count`: Count of digit characters.
   - `entropy`: Character entropy calculation showing randomness.
   - `tld`: The top-level domain (one-hot encoded dynamically at query time).
2. **Lexical Similarity Features**:
   - `brand_match`: Presence of 12 known brand strings (e.g. google, paypal, apple).
   - `has_login`, `has_secure`, `has_verify`, `has_account`, `has_update`: Flags indicating misleading keyword presence.
3. **IDN (Internationalized Domain Names) Features**:
   - `has_punycode`: Detection of `xn--` prefix indicating encoded unicode domains.

### 🌟 Bonus Threat Indicators (UI Metadata)
- **Homoglyph Detection**: Identifies mixed-script characters (Cyrillic characters combined with Latin alphabets) used to trick users.
- **IP Address Hostname**: Flags when raw IP addresses (v4/v6) are used instead of readable hostnames.
- **TLD Risk Radar**: Warns when high-risk TLDs like `.tk`, `.xyz`, `.cam`, `.shop` are used.

### 📈 Model Metrics (XGBoost)
The model was evaluated using a held-out test split (30% total TEMPORAL/random validation & test):
- **Accuracy**: `92.6%`
- **Precision**: `93.0%`
- **Recall**: `92.6%`
- **F1 Score**: `92.7%`

---

## 🛠️ Installation & Setup

### 1. Prerequisites
- Python 3.10+
- Node.js 18+
- PostgreSQL (Local or Render hosted)

---

### 2. Backend Setup
1. Navigate to the `backend/` directory:
   ```bash
   cd backend
   ```
2. Create and activate a Python virtual environment:
   ```bash
   python -m venv venv
   # Windows:
   .\venv\Scripts\activate
   # macOS/Linux:
   source venv/bin/activate
   ```
3. Install required libraries:
   ```bash
   pip install -r requirements.txt
   ```
4. Create a `.env` file in the `backend/` directory:
   ```env
   DATABASE_URL=postgresql://<user>:<password>@<host>:<port>/<dbname>
   ```
5. Run the server locally:
   ```bash
   uvicorn app.main:app --reload --port 8000
   ```
   *The API will run at `http://localhost:8000`.*

---

### 3. Frontend Setup
1. Navigate to the `frontend/` directory:
   ```bash
   cd frontend
   ```
2. Install npm modules:
   ```bash
   npm install
   ```
3. Create a `.env` file in the `frontend/` directory:
   ```env
   VITE_API_URL=http://localhost:8000
   ```
4. Start the Vite React development server:
   ```bash
   npm run dev
   ```
   *The React interface will run at `http://localhost:5173`.*

---

## 🐳 Running with Docker

You can run the FastAPI backend container locally using the Dockerfile provided in `backend/`:

1. Build the image from the `backend/` folder:
   ```bash
   docker build -t threat-intel-api -f Dockerfile .
   ```
2. Run the container:
   ```bash
   docker run -p 8000:8000 -e DATABASE_URL=postgresql://<user>:<password>@<host>/<db> threat-intel-api
   ```

---

## 🧪 Testing
We have included a comprehensive unit test suite in `backend/tests/`. To run tests, execute:
```bash
# From the backend/ directory with active venv:
python -m unittest tests/test_backend.py
```

---

## 📡 API Reference Documentation

### 1. Inspect Single Domain
* **Endpoint**: `POST /api/predict`
* **Request Body**:
  ```json
  {
    "domain": "secure-login-paypal.cam"
  }
  ```
* **Response Body**:
  ```json
  {
    "domain": "secure-login-paypal.cam",
    "label": "phishing",
    "confidence": 0.9412,
    "timestamp": "2026-06-11T16:40:00Z",
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
* **Request Body**:
  ```json
  {
    "domains": ["google.com", "sbi-verify-account.tk"]
  }
  ```

### 3. Aggregated Scan Stats
* **Endpoint**: `GET /api/stats`
* **Response Body**:
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
