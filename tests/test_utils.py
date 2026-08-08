"""Regression tests for dependency-light toolkit utility functions."""
import unittest

from app.utils import analyze_email_header, analyze_password, analyze_url, file_hashes, generate_password


class UtilityFunctionTests(unittest.TestCase):
    """Validate core toolkit helpers without requiring Flask to be installed."""

    def test_password_analysis_flags_weak_password(self):
        result = analyze_password("password123")
        self.assertEqual(result["label"], "Weak")
        self.assertTrue(any("common" in suggestion for suggestion in result["suggestions"]))

    def test_password_generator_respects_length(self):
        generated = generate_password(20, uppercase=True, lowercase=True, numbers=True, symbols=True)
        self.assertEqual(len(generated), 20)

    def test_file_hashes_for_known_bytes(self):
        hashes = file_hashes(b"cyber")
        self.assertEqual(hashes["MD5"], "7e60bc642fefc11b43792e8745df6c1d")
        self.assertEqual(hashes["SHA1"], "9017347a610d1436c1aaf52764e6578e8fc1a083")
        self.assertEqual(hashes["SHA256"], "b4bf5d7e5fcf89ef8adb64ec9c624db850d10f2afef020ed9ef23892df0833af")

    def test_url_analysis_scores_suspicious_url(self):
        result = analyze_url("http://192.168.1.10/login/verify")
        self.assertEqual(result["level"], "High")
        self.assertGreaterEqual(result["score"], 60)

    def test_email_header_extracts_security_fields(self):
        header = """Received: from mail.example.com ([203.0.113.10])
Received-SPF: pass
DKIM-Signature: v=1; a=rsa-sha256;
Authentication-Results: example.com; dmarc=pass
"""
        result = analyze_email_header(header)
        self.assertEqual(result["sender_ip"], "203.0.113.10")
        self.assertEqual(result["dkim"], "Present")
        self.assertIn("dmarc=pass", result["dmarc"])


if __name__ == "__main__":
    unittest.main()
