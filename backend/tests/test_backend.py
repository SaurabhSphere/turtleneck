import os
import sys
import unittest
from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Add backend directory to path so we can import app
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from app.main import app
from app.database import Base, get_db
from app.features import entropy, is_ip_address, has_homoglyphs, extract_features, get_additional_indicators
from app.inference import predict_domain
from app.models import DomainScan
from app.services import run_single_prediction, run_batch_prediction, get_aggregate_stats, get_scan_history

# Setup in-memory SQLite database for testing with StaticPool to persist schema across multiple connection opens
TEST_DATABASE_URL = "sqlite:///:memory:"
test_engine = create_engine(
    TEST_DATABASE_URL, 
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db


class TestThreatIntelPipeline(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Create tables
        Base.metadata.create_all(bind=test_engine)
        cls.client = TestClient(app)

    @classmethod
    def tearDownClass(cls):
        Base.metadata.drop_all(bind=test_engine)

    def setUp(self):
        # Clean up database records before each test
        self.db = TestingSessionLocal()
        self.db.query(DomainScan).delete()
        self.db.commit()

    def tearDown(self):
        self.db.close()

    # ── 1. Feature Engineering Unit Tests ─────────────────────────────

    def test_entropy(self):
        # Entropy of single repeating character should be 0
        self.assertEqual(entropy("aaaa"), 0.0)
        # Entropy of string with multiple characters should be > 0
        self.assertGreater(entropy("abc"), 0.0)

    def test_ip_address_detection(self):
        self.assertTrue(is_ip_address("192.168.1.1"))
        self.assertTrue(is_ip_address("8.8.8.8"))
        self.assertFalse(is_ip_address("google.com"))
        self.assertFalse(is_ip_address("192.168.1.300"))  # Invalid IP

    def test_homoglyph_detection(self):
        # Cyrillic 'о' in place of Latin 'o'
        suspicious_domain = "gооgle.com"
        self.assertTrue(has_homoglyphs(suspicious_domain))
        
        # Standard latin domain
        clean_domain = "google.com"
        self.assertFalse(has_homoglyphs(clean_domain))

    def test_feature_extraction(self):
        feats = extract_features("https://verify-login-paypal.com/signin")
        
        # Checking features
        self.assertEqual(feats["length"], 23)  # "verify-login-paypal.com"
        self.assertEqual(feats["subdomain_count"], 0)
        self.assertEqual(feats["has_login"], 1)
        self.assertEqual(feats["has_verify"], 1)
        self.assertEqual(feats["tld"], "com")

    # ── 2. Inference Unit Tests ───────────────────────────────────────

    def test_inference_alignment(self):
        # Verify prediction runs without crashes for a standard domain
        try:
            result = predict_domain("google.com")
            self.assertIn("label", result)
            self.assertIn("confidence", result)
            self.assertEqual(result["domain"], "google.com")
        except Exception as e:
            self.fail(f"predict_domain failed with exception: {e}")

    def test_trusted_brand_heuristic_override(self):
        # docs.google.com has known_brand_root=1 -> should be overridden to legitimate
        result_docs = predict_domain("docs.google.com")
        self.assertEqual(result_docs["label"], "legitimate")
        self.assertEqual(result_docs["confidence"], 1.0)

        # paypal-secure-update.com has known_brand_root=0 -> should NOT be overridden to legitimate
        result_phish = predict_domain("paypal-secure-update.com")
        self.assertEqual(result_phish["label"], "phishing")

    # ── 3. Service Layer Unit Tests ───────────────────────────────────

    def test_services_single_and_batch_predictions(self):
        # Test running single prediction via service layer
        resp = run_single_prediction("paypal-secure-update.com", self.db)
        self.assertEqual(resp.domain, "paypal-secure-update.com")
        
        # Check that it was saved to DB
        db_record = self.db.query(DomainScan).filter(DomainScan.domain == "paypal-secure-update.com").first()
        self.assertIsNotNone(db_record)
        self.assertEqual(db_record.label, resp.label)

        # Test batch prediction via service layer
        batch_resp = run_batch_prediction(["google.com", "apple-login.tk"], self.db)
        self.assertEqual(len(batch_resp), 2)
        
        # Verify all saved
        self.assertEqual(self.db.query(DomainScan).count(), 3)

    def test_services_stats_and_history(self):
        # Seed test data
        scan1 = DomainScan(domain="legit1.com", label="legitimate", confidence=0.95, features_json={})
        scan2 = DomainScan(domain="phish1.tk", label="phishing", confidence=0.88, features_json={})
        scan3 = DomainScan(domain="phish2.tk", label="phishing", confidence=0.92, features_json={})
        self.db.add_all([scan1, scan2, scan3])
        self.db.commit()

        # Test aggregate stats service
        stats = get_aggregate_stats(self.db)
        self.assertEqual(stats["total_scanned"], 3)
        self.assertEqual(stats["label_counts"]["legitimate"], 1)
        self.assertEqual(stats["label_counts"]["phishing"], 2)
        self.assertEqual(len(stats["top_risky_tlds"]), 1)
        self.assertEqual(stats["top_risky_tlds"][0]["tld"], "tk")
        self.assertEqual(stats["top_risky_tlds"][0]["count"], 2)

        # Test history service
        history = get_scan_history(self.db, limit=10)
        self.assertEqual(len(history), 3)

    # ── 4. API Endpoint Integration Tests ─────────────────────────────

    def test_api_predict_endpoint(self):
        # POST /api/predict
        response = self.client.post("/api/predict", json={"domain": "sbi-banking-verify.in"})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["domain"], "sbi-banking-verify.in")
        self.assertIn("label", data)
        self.assertIn("confidence", data)
        self.assertIn("features", data)

    def test_api_predict_batch_endpoint(self):
        # POST /api/predict/batch
        response = self.client.post(
            "/api/predict/batch", 
            json={"domains": ["microsoft.com", "secure-netflix-login.cam"]}
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("predictions", data)
        self.assertEqual(len(data["predictions"]), 2)
        self.assertEqual(data["predictions"][0]["domain"], "microsoft.com")

    def test_api_stats_endpoint(self):
        # Seed scanning history first
        self.client.post("/api/predict", json={"domain": "google.com"})
        self.client.post("/api/predict", json={"domain": "bad-site.tk"})

        # GET /api/stats
        response = self.client.get("/api/stats")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total_scanned"], 2)
        self.assertIn("legitimate", data["label_counts"])
        self.assertIn("phishing", data["label_counts"])

    def test_api_history_endpoint(self):
        # Seed scanning history
        self.client.post("/api/predict", json={"domain": "google.com"})

        # GET /api/history
        response = self.client.get("/api/history?limit=10")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreaterEqual(len(data), 1)
        self.assertEqual(data[0]["domain"], "google.com")

    # ── 5. Edge Case Input Verification ───────────────────────────────

    def test_api_predict_empty_domain(self):
        response = self.client.post("/api/predict", json={"domain": "   "})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "Domain name cannot be empty")

    def test_api_predict_batch_empty_list(self):
        response = self.client.post("/api/predict/batch", json={"domains": []})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()["detail"], "Domain list cannot be empty")


if __name__ == "__main__":
    unittest.main()
