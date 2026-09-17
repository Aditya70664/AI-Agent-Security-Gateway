"""
Policy Engine — the actual authorization decision-maker.

Deliberately kept separate from the risk engine: risk scoring says "how
dangerous is this", the policy engine says "what do we do about it". This
mirrors the brief's note that the risk score should not itself be the
security mechanism — the backend policy engine is.
"""

LOW_RISK_THRESHOLD = 30
HIGH_RISK_THRESHOLD = 75

DECISION_ALLOW = "ALLOW"
DECISION_DENY = "DENY"
DECISION_PENDING_APPROVAL = "PENDING_APPROVAL"
DECISION_BLOCKED = "BLOCKED"


def decide(agent_status: str, has_permission: bool, risk_score: int, trust_level: str):
    """
    Returns (decision: str, reasons: list[str]).

    Order of checks (each one short-circuits the rest — least privilege
    and the kill switch always win, regardless of risk score):
      1. Kill switch — disabled agents are denied everything.
      2. Least privilege — no permission record means no access.
      3. Risk-based thresholds — decide ALLOW / step-up / block.
    """
    reasons = []

    if agent_status == "DISABLED":
        return DECISION_BLOCKED, ["Agent is disabled (kill switch active) — all actions blocked"]

    if not has_permission:
        return DECISION_DENY, ["Agent does not have permission for this action/resource"]

    if risk_score >= HIGH_RISK_THRESHOLD:
        reasons.append(f"Risk score {risk_score} >= {HIGH_RISK_THRESHOLD} — human approval required")
        return DECISION_PENDING_APPROVAL, reasons

    if risk_score >= LOW_RISK_THRESHOLD:
        if trust_level == "LOW":
            reasons.append(
                f"Risk score {risk_score} is medium and agent trust level is LOW — "
                "step-up to human approval"
            )
            return DECISION_PENDING_APPROVAL, reasons
        reasons.append(f"Risk score {risk_score} is medium — allowed, logged for review")
        return DECISION_ALLOW, reasons

    reasons.append(f"Risk score {risk_score} is low — allowed automatically")
    return DECISION_ALLOW, reasons
