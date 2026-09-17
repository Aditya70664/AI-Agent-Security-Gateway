"""
Risk Engine — turns an (agent, action, resource, scope) request into a
0-100 risk score plus a human-readable list of contributing factors.

This is deliberately rule-based and transparent (not a black box) so every
score can be explained — matching the "explainable" design goal from the
project brief. Swap in a learned model later by keeping the same interface:
    score, reasons = compute_risk(action, resource, scope, trust_level)

Actions VISIT and DOWNLOAD are treated specially: their "resource" is a
URL rather than a named data resource, so instead of the generic
RESOURCE_SENSITIVITY lookup below, their risk is computed by
url_risk_engine.compute_url_risk() — the AI-WSS phishing/malicious-URL
module, plugged in here as a second risk signal source alongside the
tool-action risk.

PROCESS_CONTENT is treated specially too: its "resource" is a block of
text (an email body, a scraped webpage, a document) that the agent is
about to read/act on. Its risk is computed by
prompt_injection_engine.detect_prompt_injection() — a third risk signal
source, scanning for instruction-hijacking patterns (OWASP's "prompt
injection" risk) before the agent is allowed to process that content.
"""

from . import url_risk_engine
from . import prompt_injection_engine

# Actions whose "resource" is a URL, not a named data resource.
WEB_ACTIONS = {"VISIT", "DOWNLOAD"}

# Actions whose "resource" is a block of text to be scanned for prompt injection.
CONTENT_ACTIONS = {"PROCESS_CONTENT"}

# Base risk purely from the type of action requested.
ACTION_BASE_RISK = {
    "READ": 10,
    "LIST": 10,
    "VISIT": 5,       # browsing itself is low-risk; the URL's own risk is added separately
    "DOWNLOAD": 20,    # downloading is inherently riskier than just visiting
    "PROCESS_CONTENT": 5,  # reading content is low-risk by itself; injected instructions add risk
    "WRITE": 45,
    "UPDATE": 45,
    "SEND": 40,
    "MODIFY_CONFIG": 80,
    "DELETE": 90,
    "ADMIN": 100,
}
DEFAULT_ACTION_RISK = 60  # unknown actions are treated as risky by default

# Additive risk from how sensitive the target resource is.
RESOURCE_SENSITIVITY = {
    "public_data": 0,
    "invoices": 5,
    "reports": 5,
    "documents": 10,
    "email": 10,
    "customer_database": 20,
    "financial_data": 25,
    "user_database": 25,
    "cloud_config": 30,
    "production_database": 35,
    "production_system": 35,
}
DEFAULT_RESOURCE_SENSITIVITY = 15  # unknown resources are treated cautiously

# Additive risk from the declared scope of the action.
SCOPE_RISK = {
    "SINGLE": 0,
    "SUBSET": 8,
    "BULK": 15,
    "ALL": 20,
}
DEFAULT_SCOPE_RISK = 0

# Trust-level adjustment: a more trusted agent gets a discount, a less
# trusted one gets a penalty. This is what makes an unfamiliar/new agent
# riskier by default even for the same action.
TRUST_ADJUSTMENT = {
    "HIGH": -10,
    "MEDIUM": 0,
    "LOW": 15,
}


def compute_risk(action: str, resource: str, scope: str, trust_level: str):
    """
    Returns (risk_score: int in [0, 100], reasons: list[str]).
    """
    action = (action or "").upper()
    resource = (resource or "").lower()
    scope = (scope or "SINGLE").upper()
    trust_level = (trust_level or "MEDIUM").upper()

    reasons = []
    score = 0

    action_risk = ACTION_BASE_RISK.get(action, DEFAULT_ACTION_RISK)
    score += action_risk
    if action in ACTION_BASE_RISK:
        reasons.append(f"Action '{action}' carries base risk {action_risk}")
    else:
        reasons.append(f"Unrecognized action '{action}' — treated cautiously (+{action_risk})")

    if action in WEB_ACTIONS:
        url_score, url_reasons = url_risk_engine.compute_url_risk(resource)
        score += url_score
        reasons.extend(url_reasons)
    elif action in CONTENT_ACTIONS:
        injection_score, injection_reasons, match_count = prompt_injection_engine.detect_prompt_injection(resource)
        score += injection_score
        reasons.extend(injection_reasons)
    else:
        resource_risk = RESOURCE_SENSITIVITY.get(resource, DEFAULT_RESOURCE_SENSITIVITY)
        score += resource_risk
        if resource in RESOURCE_SENSITIVITY:
            reasons.append(f"Resource '{resource}' sensitivity adds {resource_risk}")
        else:
            reasons.append(f"Unrecognized resource '{resource}' — treated cautiously (+{resource_risk})")

    scope_risk = SCOPE_RISK.get(scope, DEFAULT_SCOPE_RISK)
    if scope_risk:
        score += scope_risk
        reasons.append(f"Scope '{scope}' adds {scope_risk}")

    trust_adj = TRUST_ADJUSTMENT.get(trust_level, 0)
    if trust_adj:
        score += trust_adj
        sign = "reduces" if trust_adj < 0 else "increases"
        reasons.append(f"Agent trust level '{trust_level}' {sign} risk by {abs(trust_adj)}")

    score = max(0, min(100, score))
    return score, reasons
