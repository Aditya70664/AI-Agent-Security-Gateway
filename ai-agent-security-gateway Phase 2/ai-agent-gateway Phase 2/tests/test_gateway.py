import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gateway import db
from gateway.core import Gateway, GatewayError
from gateway.policy_engine import (
    DECISION_ALLOW,
    DECISION_DENY,
    DECISION_PENDING_APPROVAL,
    DECISION_BLOCKED,
)


class GatewayTests(unittest.TestCase):
    def setUp(self):
        # Fresh in-memory-equivalent DB for every test.
        db.DB_PATH = ":memory:"
        # sqlite3 :memory: is per-connection; force a new thread-local connection.
        if hasattr(db._local, "conn"):
            del db._local.conn
        db.init_db()
        self.gw = Gateway()
        self.agent = self.gw.create_agent(name="TestBot", trust_level="MEDIUM")

    def test_low_risk_permitted_action_is_allowed(self):
        self.gw.set_permission(self.agent["id"], "READ", "invoices")
        result = self.gw.evaluate_request(self.agent["id"], "READ", "invoices")
        self.assertEqual(result["decision"], DECISION_ALLOW)

    def test_missing_permission_is_denied(self):
        result = self.gw.evaluate_request(self.agent["id"], "READ", "customer_database")
        self.assertEqual(result["decision"], DECISION_DENY)

    def test_high_risk_action_requires_approval(self):
        self.gw.set_permission(self.agent["id"], "DELETE", "production_database")
        result = self.gw.evaluate_request(
            self.agent["id"], "DELETE", "production_database", scope="ALL"
        )
        self.assertEqual(result["decision"], DECISION_PENDING_APPROVAL)
        self.assertIsNotNone(result["approval_id"])

    def test_kill_switch_blocks_everything(self):
        self.gw.set_permission(self.agent["id"], "READ", "invoices")
        self.gw.disable_agent(self.agent["id"])
        result = self.gw.evaluate_request(self.agent["id"], "READ", "invoices")
        self.assertEqual(result["decision"], DECISION_BLOCKED)

    def test_low_trust_agent_gets_stepped_up_at_medium_risk(self):
        low_trust = self.gw.create_agent(name="LowTrustBot", trust_level="LOW")
        self.gw.set_permission(low_trust["id"], "SEND", "email")
        result = self.gw.evaluate_request(low_trust["id"], "SEND", "email")
        self.assertEqual(result["decision"], DECISION_PENDING_APPROVAL)

    def test_approval_workflow_resolves_correctly(self):
        self.gw.set_permission(self.agent["id"], "DELETE", "production_database")
        result = self.gw.evaluate_request(
            self.agent["id"], "DELETE", "production_database", scope="ALL"
        )
        approval = self.gw.resolve_approval(result["approval_id"], approve=True)
        self.assertEqual(approval["status"], "APPROVED")
        with self.assertRaises(GatewayError):
            self.gw.resolve_approval(result["approval_id"], approve=True)  # already resolved

    def test_duplicate_agent_name_rejected(self):
        with self.assertRaises(GatewayError):
            self.gw.create_agent(name="TestBot")

    def test_dashboard_summary_counts_are_consistent(self):
        self.gw.set_permission(self.agent["id"], "READ", "invoices")
        self.gw.evaluate_request(self.agent["id"], "READ", "invoices")
        summary = self.gw.dashboard_summary()
        self.assertEqual(summary["total_agents"], 1)
        self.assertGreaterEqual(summary["actions_today"], 1)


if __name__ == "__main__":
    unittest.main()
