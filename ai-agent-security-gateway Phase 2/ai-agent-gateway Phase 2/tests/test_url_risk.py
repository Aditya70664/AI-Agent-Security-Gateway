import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gateway import db
from gateway.core import Gateway
from gateway.policy_engine import DECISION_ALLOW, DECISION_DENY, DECISION_PENDING_APPROVAL
from gateway.url_risk_engine import compute_url_risk


class UrlRiskEngineTests(unittest.TestCase):
    """Tests the risk-scoring logic in isolation, no gateway/DB involved."""

    def test_safe_https_url_scores_low(self):
        score, reasons = compute_url_risk("https://www.wikipedia.org/wiki/Python")
        self.assertLess(score, 20)

    def test_raw_ip_address_is_flagged(self):
        score, reasons = compute_url_risk("http://192.168.1.5/login")
        joined = " ".join(reasons)
        self.assertIn("raw IP address", joined)

    def test_at_symbol_redirect_trick_is_flagged(self):
        score, reasons = compute_url_risk("http://real-bank.com@attacker.com/phish")
        joined = " ".join(reasons)
        self.assertIn("@", joined)

    def test_suspicious_tld_is_flagged(self):
        score, reasons = compute_url_risk("http://free-prize.tk/claim")
        joined = " ".join(reasons)
        self.assertIn("TLD", joined)

    def test_executable_download_is_flagged(self):
        score, reasons = compute_url_risk("https://example.com/tools/update.exe")
        joined = " ".join(reasons)
        self.assertIn("executable", joined)

    def test_stacked_red_flags_score_higher_than_single_flag(self):
        safe_score, _ = compute_url_risk("https://example.com")
        single_flag_score, _ = compute_url_risk("http://example.com")  # just HTTP
        stacked_score, _ = compute_url_risk(
            "http://192.168.1.1-secure-login-verify.tk/account/signin.exe"
        )
        self.assertLess(safe_score, single_flag_score)
        self.assertLess(single_flag_score, stacked_score)

    def test_malformed_url_does_not_crash(self):
        score, reasons = compute_url_risk("not a url at all !!!")
        self.assertIsInstance(score, int)
        self.assertTrue(reasons)

    def test_empty_url_does_not_crash(self):
        score, reasons = compute_url_risk("")
        self.assertIsInstance(score, int)


class GatewayUrlIntegrationTests(unittest.TestCase):
    """Tests the URL risk module as used through the full gateway flow."""

    def setUp(self):
        db.DB_PATH = ":memory:"
        if hasattr(db._local, "conn"):
            del db._local.conn
        db.init_db()
        self.gw = Gateway()
        self.agent = self.gw.create_agent(name="WebBot", trust_level="MEDIUM")

    def test_visit_without_web_permission_is_denied(self):
        result = self.gw.evaluate_request(self.agent["id"], "VISIT", "https://example.com")
        self.assertEqual(result["decision"], DECISION_DENY)

    def test_visit_safe_url_with_permission_is_allowed(self):
        self.gw.set_permission(self.agent["id"], "VISIT", "web")
        result = self.gw.evaluate_request(self.agent["id"], "VISIT", "https://www.wikipedia.org")
        self.assertEqual(result["decision"], DECISION_ALLOW)

    def test_visit_phishing_like_url_requires_approval(self):
        self.gw.set_permission(self.agent["id"], "VISIT", "web")
        phishing_url = "http://192.168.1.1-secure-login-verify-account.tk/signin"
        result = self.gw.evaluate_request(self.agent["id"], "VISIT", phishing_url)
        self.assertEqual(result["decision"], DECISION_PENDING_APPROVAL)

    def test_web_permission_does_not_grant_unrelated_actions(self):
        # Granting VISIT on 'web' should not accidentally allow DELETE elsewhere.
        self.gw.set_permission(self.agent["id"], "VISIT", "web")
        result = self.gw.evaluate_request(self.agent["id"], "DELETE", "production_database")
        self.assertEqual(result["decision"], DECISION_DENY)

    def test_download_permission_is_separate_from_visit_permission(self):
        self.gw.set_permission(self.agent["id"], "VISIT", "web")
        result = self.gw.evaluate_request(self.agent["id"], "DOWNLOAD", "https://example.com/file.exe")
        self.assertEqual(result["decision"], DECISION_DENY)  # VISIT permission doesn't cover DOWNLOAD


if __name__ == "__main__":
    unittest.main()
