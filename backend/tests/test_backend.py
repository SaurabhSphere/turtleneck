import os
import sys
import unittest

# Add backend directory to path so we can import app
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from app.features import entropy, is_ip_address, has_homoglyphs, extract_features, get_additional_indicators
from app.inference import predict_domain

class TestThreatIntelPipeline(unittest.TestCase):
    
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

    def test_inference_alignment(self):
        # Verify prediction runs without crashes for a standard domain
        try:
            result = predict_domain("google.com")
            self.assertIn("label", result)
            self.assertIn("confidence", result)
            self.assertEqual(result["domain"], "google.com")
        except Exception as e:
            self.fail(f"predict_domain failed with exception: {e}")

if __name__ == '__main__':
    unittest.main()
