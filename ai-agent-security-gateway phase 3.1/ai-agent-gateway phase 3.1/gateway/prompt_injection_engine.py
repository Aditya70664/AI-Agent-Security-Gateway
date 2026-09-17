"""
Prompt-Injection Detection Engine.

Scans arbitrary text content (an email body, a document, a scraped
webpage — anything an agent is about to read/process) for patterns
commonly used to hijack an LLM-based agent: instruction overrides, fake
system/role markers, requests to exfiltrate data, requests for secrecy,
and so on.

Same design philosophy as risk_engine.py and url_risk_engine.py: a
transparent, rule-based scanner that explains every point it adds,
rather than an opaque classifier. This is the OWASP "prompt injection"
risk from the project brief, made concrete.

    score, reasons, matches = detect_prompt_injection(content)
"""

import re

# Each entry: (compiled regex, weight, human-readable description)
INJECTION_PATTERNS = [
    (re.compile(r"ignore (all |any )?(previous|prior|above|earlier) instructions", re.I),
     40, "Attempts to override prior instructions"),
    (re.compile(r"disregard (your|the|all) (instructions|rules|guidelines|prompt)", re.I),
     40, "Attempts to override prior instructions"),
    (re.compile(r"forget (everything|all|your instructions|what you were told)", re.I),
     35, "Attempts to reset the agent's context/instructions"),
    (re.compile(r"reveal (your|the) (system prompt|instructions|prompt)", re.I),
     35, "Attempts to exfiltrate the agent's own instructions"),
    (re.compile(r"(print|show|output) (your|the) (system prompt|instructions)", re.I),
     35, "Attempts to exfiltrate the agent's own instructions"),
    (re.compile(r"you are now (a|an|the)?", re.I),
     20, "Attempts to reassign the agent's role/identity"),
    (re.compile(r"new instructions?\s*:", re.I),
     30, "Injects a fake new instruction block"),
    (re.compile(r"system\s*:", re.I),
     20, "Fake system-role marker embedded in content"),
    (re.compile(r"\[/?INST\]|<\|.*?\|>|<<SYS>>", re.I),
     20, "Fake special-token/role-formatting marker"),
    (re.compile(r"do not (tell|inform|notify|alert) (the user|anyone|your owner)", re.I),
     25, "Attempts to instruct secrecy from the user/owner"),
    (re.compile(
        r"(send|upload|forward|email) (it|this|the data|the database|the records|"
        r"customer (data|records)|everything|all (of )?(it|this))\s*to\b", re.I),
     30, "Attempts to redirect data to an external destination"),
    (re.compile(r"(api[ _-]?key|password|secret key|credentials?)\b", re.I),
     15, "References sensitive credentials"),
    (re.compile(r"external (website|server|url|domain|address)", re.I),
     20, "References an external destination for data"),
    (re.compile(r"(wire|bank) transfer|routing number|account number", re.I),
     30, "Attempts to trigger a financial transaction"),
    (re.compile(r"delete (all|every|the entire)\b", re.I),
     20, "Attempts to trigger a destructive bulk action"),
    (re.compile(r"this is (a|an) (urgent|emergency)", re.I),
     10, "Uses urgency as a manipulation tactic"),
]

# A single hit on any of these is a much stronger signal on its own.
HIGH_CONFIDENCE_PATTERNS = {
    "Attempts to override prior instructions",
    "Attempts to exfiltrate the agent's own instructions",
}


def detect_prompt_injection(content: str):
    """
    Returns (risk_score: int in [0, 100], reasons: list[str], match_count: int).
    Never raises on malformed/empty input.
    """
    if not content or not isinstance(content, str):
        return 0, ["No content provided"], 0

    score = 0
    reasons = []
    match_count = 0
    seen_descriptions = set()

    for pattern, weight, description in INJECTION_PATTERNS:
        if pattern.search(content):
            match_count += 1
            score += weight
            if description not in seen_descriptions:
                reasons.append(f"{description} (+{weight})")
                seen_descriptions.add(description)

    # Stacking bonus: multiple independent injection techniques found together
    # is a much stronger signal than any single one alone.
    if match_count >= 3:
        score += 15
        reasons.append(f"{match_count} distinct injection techniques found together (+15)")

    score = max(0, min(100, score))
    if not reasons:
        reasons.append("No prompt-injection patterns detected")

    return score, reasons, match_count
