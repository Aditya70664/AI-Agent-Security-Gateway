"""
Gateway — the single entry point that every AI agent action must pass
through. This is the class both the HTTP API and the demo script call into.

Flow for every request:
    Agent Identity -> Permission Check -> Risk Scoring -> Policy Decision
        -> Audit Log -> (Approval record if needed)
"""

import json
from datetime import datetime, timezone

from . import db
from . import risk_engine
from . import policy_engine

# For VISIT/DOWNLOAD, the "resource" is an arbitrary URL that can't be
# pre-registered one-by-one in the permissions table. Instead, permission
# for these actions is granted against a fixed placeholder resource ("web")
# meaning "this agent may browse/download at all" — the URL itself is still
# passed through to the risk engine for per-request scoring.
WEB_PERMISSION_RESOURCE = "web"


class GatewayError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.message = message
        self.status = status


class Gateway:
    def __init__(self):
        db.init_db()

    # ---------------------------------------------------------------
    # Agent identity
    # ---------------------------------------------------------------
    def create_agent(self, name, owner=None, trust_level="MEDIUM"):
        trust_level = trust_level.upper()
        if trust_level not in ("LOW", "MEDIUM", "HIGH"):
            raise GatewayError("trust_level must be LOW, MEDIUM, or HIGH")
        conn = db.get_connection()
        try:
            cur = conn.execute(
                "INSERT INTO agents (name, owner, trust_level) VALUES (?, ?, ?)",
                (name, owner, trust_level),
            )
            conn.commit()
        except Exception as e:
            if "UNIQUE" in str(e):
                raise GatewayError(f"Agent '{name}' already exists", status=409)
            raise
        return self.get_agent(cur.lastrowid)

    def get_agent(self, agent_id):
        conn = db.get_connection()
        row = conn.execute("SELECT * FROM agents WHERE id = ?", (agent_id,)).fetchone()
        if not row:
            raise GatewayError(f"Agent {agent_id} not found", status=404)
        return dict(row)

    def list_agents(self):
        conn = db.get_connection()
        rows = conn.execute("SELECT * FROM agents ORDER BY id").fetchall()
        return [dict(r) for r in rows]

    def set_agent_status(self, agent_id, status):
        self.get_agent(agent_id)  # 404 if missing
        conn = db.get_connection()
        conn.execute("UPDATE agents SET status = ? WHERE id = ?", (status, agent_id))
        conn.commit()
        return self.get_agent(agent_id)

    def disable_agent(self, agent_id):
        """The 'kill switch' — instantly denies every future action."""
        return self.set_agent_status(agent_id, "DISABLED")

    def enable_agent(self, agent_id):
        return self.set_agent_status(agent_id, "ACTIVE")

    # ---------------------------------------------------------------
    # Permissions
    # ---------------------------------------------------------------
    def set_permission(self, agent_id, action, resource, allowed=True):
        self.get_agent(agent_id)
        conn = db.get_connection()
        conn.execute(
            """
            INSERT INTO permissions (agent_id, action, resource, allowed)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(agent_id, action, resource)
            DO UPDATE SET allowed = excluded.allowed
            """,
            (agent_id, action.upper(), resource.lower(), 1 if allowed else 0),
        )
        conn.commit()

    def get_permissions(self, agent_id):
        self.get_agent(agent_id)
        conn = db.get_connection()
        rows = conn.execute(
            "SELECT action, resource, allowed FROM permissions WHERE agent_id = ?", (agent_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def _has_permission(self, agent_id, action, resource):
        conn = db.get_connection()
        lookup_resource = (
            WEB_PERMISSION_RESOURCE if action.upper() in risk_engine.WEB_ACTIONS else resource.lower()
        )
        row = conn.execute(
            "SELECT allowed FROM permissions WHERE agent_id = ? AND action = ? AND resource = ?",
            (agent_id, action.upper(), lookup_resource),
        ).fetchone()
        # Least privilege: no record at all == no permission.
        return bool(row) and bool(row["allowed"])

    # ---------------------------------------------------------------
    # The main gateway decision
    # ---------------------------------------------------------------
    def evaluate_request(self, agent_id, action, resource, scope="SINGLE"):
        agent = self.get_agent(agent_id)

        has_permission = self._has_permission(agent_id, action, resource)
        risk_score, risk_reasons = risk_engine.compute_risk(
            action, resource, scope, agent["trust_level"]
        )
        decision, policy_reasons = policy_engine.decide(
            agent["status"], has_permission, risk_score, agent["trust_level"]
        )
        all_reasons = policy_reasons + risk_reasons

        audit_id = self._log_audit(agent_id, action, resource, scope, risk_score, decision, all_reasons)

        approval_id = None
        if decision == policy_engine.DECISION_PENDING_APPROVAL:
            approval_id = self._create_approval(audit_id)

        return {
            "agent_id": agent_id,
            "agent_name": agent["name"],
            "action": action.upper(),
            "resource": resource.lower(),
            "scope": scope.upper(),
            "risk_score": risk_score,
            "decision": decision,
            "reasons": all_reasons,
            "audit_log_id": audit_id,
            "approval_id": approval_id,
        }

    # ---------------------------------------------------------------
    # Audit log
    # ---------------------------------------------------------------
    def _log_audit(self, agent_id, action, resource, scope, risk_score, decision, reasons):
        conn = db.get_connection()
        cur = conn.execute(
            """
            INSERT INTO audit_logs (agent_id, action, resource, scope, risk_score, decision, reasons)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (agent_id, action.upper(), resource.lower(), scope.upper(), risk_score, decision, json.dumps(reasons)),
        )
        conn.commit()
        return cur.lastrowid

    def get_audit_log(self, agent_id=None, limit=50):
        conn = db.get_connection()
        if agent_id:
            rows = conn.execute(
                "SELECT * FROM audit_logs WHERE agent_id = ? ORDER BY id DESC LIMIT ?",
                (agent_id, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        results = []
        for r in rows:
            d = dict(r)
            d["reasons"] = json.loads(d["reasons"]) if d["reasons"] else []
            results.append(d)
        return results

    # ---------------------------------------------------------------
    # Human approval workflow
    # ---------------------------------------------------------------
    def _create_approval(self, audit_log_id):
        conn = db.get_connection()
        cur = conn.execute(
            "INSERT INTO approvals (audit_log_id, status) VALUES (?, 'PENDING')",
            (audit_log_id,),
        )
        conn.commit()
        return cur.lastrowid

    def list_approvals(self, status=None):
        conn = db.get_connection()
        query = """
            SELECT approvals.*, audit_logs.agent_id, audit_logs.action,
                   audit_logs.resource, audit_logs.risk_score
            FROM approvals JOIN audit_logs ON approvals.audit_log_id = audit_logs.id
        """
        params = ()
        if status:
            query += " WHERE approvals.status = ?"
            params = (status.upper(),)
        query += " ORDER BY approvals.id DESC"
        rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def resolve_approval(self, approval_id, approve: bool, resolved_by="admin"):
        conn = db.get_connection()
        row = conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone()
        if not row:
            raise GatewayError(f"Approval {approval_id} not found", status=404)
        if row["status"] != "PENDING":
            raise GatewayError(f"Approval {approval_id} already resolved", status=409)

        new_status = "APPROVED" if approve else "DENIED"
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE approvals SET status = ?, resolved_by = ?, resolved_at = ? WHERE id = ?",
            (new_status, resolved_by, now, approval_id),
        )
        conn.commit()
        return dict(conn.execute("SELECT * FROM approvals WHERE id = ?", (approval_id,)).fetchone())

    # ---------------------------------------------------------------
    # Dashboard summary
    # ---------------------------------------------------------------
    def dashboard_summary(self):
        conn = db.get_connection()
        total_agents = conn.execute("SELECT COUNT(*) c FROM agents").fetchone()["c"]
        active_agents = conn.execute(
            "SELECT COUNT(*) c FROM agents WHERE status = 'ACTIVE'"
        ).fetchone()["c"]
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        actions_today = conn.execute(
            "SELECT COUNT(*) c FROM audit_logs WHERE created_at LIKE ?", (f"{today}%",)
        ).fetchone()["c"]
        blocked_today = conn.execute(
            "SELECT COUNT(*) c FROM audit_logs WHERE created_at LIKE ? AND decision IN ('DENY','BLOCKED')",
            (f"{today}%",),
        ).fetchone()["c"]
        high_risk_today = conn.execute(
            "SELECT COUNT(*) c FROM audit_logs WHERE created_at LIKE ? AND risk_score >= 75",
            (f"{today}%",),
        ).fetchone()["c"]
        pending_approvals = conn.execute(
            "SELECT COUNT(*) c FROM approvals WHERE status = 'PENDING'"
        ).fetchone()["c"]
        return {
            "total_agents": total_agents,
            "active_agents": active_agents,
            "actions_today": actions_today,
            "blocked_today": blocked_today,
            "high_risk_today": high_risk_today,
            "pending_approvals": pending_approvals,
        }
