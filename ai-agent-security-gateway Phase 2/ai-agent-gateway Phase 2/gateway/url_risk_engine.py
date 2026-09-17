"""
URL Risk Engine — analyzes a URL for phishing/malicious-download signals.

This is the AI-WSS idea (from the original browser-security-extension
concept) repurposed as a second risk-signal source inside the same
gateway used for tool-actions. When an agent's requested action is
VISIT or DOWNLOAD and the resource is a URL, this module's score is
combined with the general risk_engine score.

Deliberately rule-based and transparent (same philosophy as
risk_engine.py) rather than a black-box classifier, so every point can
be explained in a demo or report. The AI-WSS brief's ML model (Logistic
Regression / Random Forest on these same kinds of features) can later
replace `compute_url_risk`'s internals without changing its interface:
    score, reasons = compute_url_risk(url)
"""

import re
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "signin", "webscr", "password", "banking", "wallet", "billing",
    "suspended", "unlock", "invoice",
]

SUSPICIOUS_TLDS = [".zip", ".mov", ".xyz", ".top", ".click", ".gq", ".tk", ".ml", ".cf", ".work"]

URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly"]

SUSPICIOUS_DOWNLOAD_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".jar", ".apk", ".msi", ".ps1",
]

IPV4_PATTERN = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def _hostname_of(url: str) -> str:
    parsed = urlparse(url if "://" in url else f"http://{url}")
    return (parsed.hostname or "").lower()


def compute_url_risk(url: str):
    """
    Returns (risk_score: int in [0, 100], reasons: list[str]).
    Never raises on malformed input — an unparseable URL is itself
    treated as suspicious rather than crashing the gateway.
    """
    reasons = []
    score = 0

    if not url or not isinstance(url, str):
        return 40, ["Empty or invalid URL — treated cautiously"]

    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
        hostname = (parsed.hostname or "").lower()
        path = (parsed.path or "").lower()
        scheme = (parsed.scheme or "").lower()
    except Exception:
        return 50, ["URL could not be parsed — treated cautiously"]

    if not hostname:
        return 45, ["No hostname could be extracted from the URL — treated cautiously"]

    # 1. Plain HTTP instead of HTTPS
    if scheme == "http":
        score += 10
        reasons.append("Uses plain HTTP instead of HTTPS (+10)")

    # 2. Hostname is a raw IP address rather than a domain name
    if IPV4_PATTERN.match(hostname):
        score += 25
        reasons.append(f"Destination is a raw IP address ({hostname}) rather than a domain (+25)")

    # 3. "@" in the URL — classic redirect-trick (browser ignores everything before it)
    if "@" in url:
        score += 20
        reasons.append("URL contains '@', a common redirect-obfuscation trick (+20)")

    # 4. Excessive hyphens in the hostname (typosquatting pattern, e.g. paypal-secure-login.com)
    hyphen_count = hostname.count("-")
    if hyphen_count > 2:
        score += 10
        reasons.append(f"Hostname has {hyphen_count} hyphens — typosquatting pattern (+10)")

    # 5. Excessive subdomain depth (e.g. secure.login.paypal.attacker.com)
    subdomain_depth = hostname.count(".")
    if subdomain_depth > 3:
        score += 10
        reasons.append(f"Hostname has unusually deep subdomain nesting (+10)")

    # 6. Suspicious/free TLD often used for throwaway phishing domains
    if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
        score += 20
        reasons.append(f"Hostname uses a TLD commonly associated with abuse (+20)")

    # 7. Known URL-shortener — destination is hidden from the user
    if any(short in hostname for short in URL_SHORTENERS):
        score += 15
        reasons.append("URL uses a link-shortening service, hiding the real destination (+15)")

    # 8. Punycode / internationalized domain — possible homograph attack
    if hostname.startswith("xn--") or ".xn--" in hostname:
        score += 20
        reasons.append("Hostname uses punycode encoding — possible homograph/lookalike attack (+20)")

    # 9. Suspicious keywords anywhere in the URL (phishing pretext)
    full_url_lower = url.lower()
    found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url_lower]
    if found_keywords:
        keyword_risk = min(30, 10 * len(found_keywords))
        score += keyword_risk
        reasons.append(
            f"URL contains phishing-pretext keyword(s) {found_keywords[:3]} (+{keyword_risk})"
        )

    # 10. Overly long URL (often used to obscure the real destination)
    if len(url) > 75:
        score += 10
        reasons.append(f"URL is unusually long ({len(url)} chars) (+10)")

    # 11. Suspicious downloadable file extension
    matched_ext = next((ext for ext in SUSPICIOUS_DOWNLOAD_EXTENSIONS if path.endswith(ext)), None)
    if matched_ext:
        score += 25
        reasons.append(f"Links directly to an executable/script file ({matched_ext}) (+25)")

    score = max(0, min(100, score))
    if not reasons:
        reasons.append("No suspicious URL features detected")
    return score, reasons
