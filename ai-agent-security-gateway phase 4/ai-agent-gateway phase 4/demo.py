"""
End-to-end demo of the AI Agent Security Gateway — calls the Gateway class
directly (no HTTP server needed) so you can see the whole decision flow
in one script. This is the scenario from the project brief: FinanceBot
with limited permissions, a dangerous action, a kill switch, and a
human-approval workflow.

Run with:  python demo.py
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
    db.reset_db()  # start every demo run from a clean slate
    gw = Gateway()

    # 1. Create an agent and give it a narrow set of permissions
    finance_bot = gw.create_agent(name="FinanceBot", owner="Finance Dept", trust_level="MEDIUM")
    print(f"Created agent: {finance_bot['name']} (id={finance_bot['id']}, trust={finance_bot['trust_level']})")

    gw.set_permission(finance_bot["id"], "READ", "invoices", allowed=True)
    gw.set_permission(finance_bot["id"], "SEND", "email", allowed=True)
    gw.set_permission(finance_bot["id"], "DELETE", "production_database", allowed=True)
    # Note: no permission granted for customer_database at all -> denied by default (least privilege)

    # 2. A low-risk, permitted action -> should auto-ALLOW
    show(
        "1) FinanceBot reads an invoice (expected: ALLOW)",
        gw.evaluate_request(finance_bot["id"], action="READ", resource="invoices", scope="SINGLE"),
    )

    # 3. Action with no permission record at all -> should DENY (least privilege)
    show(
        "2) FinanceBot tries to read the customer database (expected: DENY - no permission)",
        gw.evaluate_request(finance_bot["id"], action="READ", resource="customer_database", scope="SINGLE"),
    )

    # 4. A high-risk but permitted action -> should require human approval
    result = gw.evaluate_request(
        finance_bot["id"], action="DELETE", resource="production_database", scope="ALL"
    )
    show("3) FinanceBot tries to delete the ENTIRE production database (expected: PENDING_APPROVAL)", result)

    # 5. An admin reviews and denies the pending request
    if result["approval_id"]:
        resolved = gw.resolve_approval(result["approval_id"], approve=False, resolved_by="admin_aditya")
        show("4) Admin reviews the pending request and DENIES it", resolved)

    # 6. Simulate a compromised agent -> hit the kill switch
    gw.disable_agent(finance_bot["id"])
    show(
        "5) FinanceBot is compromised -> admin hits the kill switch, then agent tries ANY action",
        gw.evaluate_request(finance_bot["id"], action="READ", resource="invoices", scope="SINGLE"),
    )

    # 7. Dashboard summary
    show("6) Dashboard summary", gw.dashboard_summary())

    # 8. Full audit trail
    show("7) Full audit trail for FinanceBot", gw.get_audit_log(agent_id=finance_bot["id"]))


if __name__ == "__main__":
    main()
