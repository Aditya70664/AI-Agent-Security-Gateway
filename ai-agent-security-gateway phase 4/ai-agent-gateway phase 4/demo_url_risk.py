"""
Demo: the URL/phishing risk module (Phase 2) plugged into the same
gateway used for tool-actions in Phase 1.

Run with:  python demo_url_risk.py
"""
import json
from gateway import db
from gateway.core import Gateway

SEPARATOR = "-" * 70


def show(title, result):
    print(f"\n{title}")
    print(SEPARATOR)
    print(json.dumps(result, indent=2, default=str))


def main():
    db.reset_db()
    gw = Gateway()

    web_bot = gw.create_agent(name="WebBot", owner="Research Team", trust_level="MEDIUM")
    print(f"Created agent: {web_bot['name']} (id={web_bot['id']})")

    # Grant blanket "may browse the web" permission — VISIT/DOWNLOAD permissions
    # are checked against a fixed 'web' resource, not the literal URL (see core.py).
    gw.set_permission(web_bot["id"], "VISIT", "web", allowed=True)

    # 1. A perfectly ordinary, safe URL
    show(
        "1) Visit https://www.wikipedia.org (expected: ALLOW, low risk)",
        gw.evaluate_request(web_bot["id"], action="VISIT", resource="https://www.wikipedia.org", scope="SINGLE"),
    )

    # 2. A URL with several classic phishing red flags stacked together
    phishing_url = "http://192.168.4.201-secure-login-verify-account.tk/paypal/signin.php"
    show(
        "2) Visit a suspicious phishing-style URL (expected: high risk, PENDING_APPROVAL)",
        gw.evaluate_request(web_bot["id"], action="VISIT", resource=phishing_url, scope="SINGLE"),
    )

    # 3. Agent has no DOWNLOAD permission at all yet -> denied regardless of risk
    show(
        "3) WebBot tries to download a file with NO download permission (expected: DENY)",
        gw.evaluate_request(web_bot["id"], action="DOWNLOAD", resource="https://example.com/setup.exe", scope="SINGLE"),
    )

    # 4. Grant download permission, then try downloading an executable from a
    #    link-shortener — should stack enough risk to need human approval.
    gw.set_permission(web_bot["id"], "DOWNLOAD", "web", allowed=True)
    result = gw.evaluate_request(
        web_bot["id"], action="DOWNLOAD", resource="http://bit.ly/free-update.exe", scope="SINGLE"
    )
    show("4) WebBot downloads a shortened-link .exe (expected: PENDING_APPROVAL)", result)

    if result["approval_id"]:
        resolved = gw.resolve_approval(result["approval_id"], approve=False, resolved_by="admin_aditya")
        show("5) Admin reviews and DENIES the download", resolved)

    # 6. Dashboard + audit trail
    show("6) Dashboard summary", gw.dashboard_summary())
    show("7) Full audit trail for WebBot", gw.get_audit_log(agent_id=web_bot["id"]))


if __name__ == "__main__":
    main()
