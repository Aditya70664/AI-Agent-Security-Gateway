# AI Agent Security Gateway (Phase 1 — Core)

A zero-trust authorization layer that sits between an AI agent and the
tools/systems it wants to access. Every action an agent tries to take is
checked for **identity → permission → risk → policy** before it's allowed
to happen — and every decision is logged and explainable.

This is the **core gateway** milestone: agent identity, least-privilege
permissions, an explainable risk engine, a policy engine (Allow / Deny /
Pending Approval / Blocked), a human-approval workflow, a kill switch, and
a full audit trail. The URL/phishing risk module (from the AI-WSS idea)
and a dashboard UI are meant to plug in later as additional risk-engine
modules and a frontend on top of this same API — nothing here needs to
change to add them.

**Zero third-party dependencies.** Everything is Python 3 standard library
(`sqlite3`, `wsgiref`, `json`) — no `pip install` required, so it runs
immediately in any environment, including ones without internet access.

## Project layout

```
gateway/
  db.py             # SQLite schema + connection handling
  risk_engine.py     # Rule-based, explainable 0-100 risk scoring
  policy_engine.py    # Turns permission + risk into ALLOW/DENY/etc.
  core.py             # Gateway class — orchestrates everything above
  api.py              # WSGI HTTP API (routes map 1:1 to core.py methods)
run_server.py         # Starts the HTTP API
demo.py               # End-to-end scripted walkthrough (no server needed)
tests/test_gateway.py # Unit tests for the decision logic
```

## Quick start

```bash
# 1. See the full story end-to-end (no server needed)
python demo.py

# 2. Run the test suite
python -m unittest tests.test_gateway -v

# 3. Or run it as a real HTTP API
python run_server.py 8000
```

## API reference

| Method | Path                          | Purpose                                   |
|--------|-------------------------------|--------------------------------------------|
| POST   | /agents                       | Register a new agent                       |
| GET    | /agents                       | List all agents                            |
| GET    | /agents/{id}                  | Get one agent                              |
| POST   | /agents/{id}/disable          | Kill switch — instantly block everything   |
| POST   | /agents/{id}/enable           | Re-enable a disabled agent                 |
| POST   | /agents/{id}/permissions      | Grant/deny a specific action+resource      |
| GET    | /agents/{id}/permissions      | List an agent's permissions                |
| POST   | /gateway/request               | **The main endpoint** — ask "can I do X?" |
| GET    | /approvals?status=PENDING     | List approval requests                     |
| POST   | /approvals/{id}/approve       | Approve a pending high-risk action         |
| POST   | /approvals/{id}/deny          | Deny a pending high-risk action            |
| GET    | /audit?agent_id=&limit=       | Full audit trail                           |
| GET    | /dashboard/summary            | Counts for a dashboard UI                  |

### Example: the full flow over HTTP

```bash
curl -X POST localhost:8000/agents \
  -d '{"name":"FinanceBot","owner":"Finance","trust_level":"MEDIUM"}'

curl -X POST localhost:8000/agents/1/permissions \
  -d '{"action":"READ","resource":"invoices","allowed":true}'

curl -X POST localhost:8000/gateway/request \
  -d '{"agent_id":1,"action":"READ","resource":"invoices"}'
# -> {"decision": "ALLOW", "risk_score": 15, "reasons": [...]}

curl -X POST localhost:8000/gateway/request \
  -d '{"agent_id":1,"action":"DELETE","resource":"production_database","scope":"ALL"}'
# -> {"decision": "PENDING_APPROVAL", "risk_score": 100, "approval_id": 1, ...}

curl -X POST localhost:8000/approvals/1/deny -d '{"resolved_by":"admin"}'
```

## How the decision is made

1. **Kill switch** — a disabled agent is blocked from everything, no
   matter what.
2. **Least privilege** — if there's no permission record for this exact
   `(action, resource)` pair, the request is denied by default. Nothing
   is implicitly allowed.
3. **Risk scoring** (`risk_engine.py`) — combines the action type (READ vs
   DELETE), the sensitivity of the resource, the scope of the action
   (one record vs "ALL"), and the agent's trust level into a 0-100 score,
   with a plain-English reason for every point added or removed.
4. **Policy decision** (`policy_engine.py`) — turns that score into
   ALLOW / DENY / PENDING_APPROVAL, with a "step-up" rule: a low-trust
   agent gets escalated to human approval at a lower risk threshold than
   a high-trust one.
5. **Audit log** — every single decision (not just denials) is recorded
   with its full reasoning, so nothing happens invisibly.

## Where this fits in the bigger project

This is Phase 1 of the roadmap discussed earlier:

- ✅ Phase 1 — Agent identity + permission engine (this repo)
- ✅ Phase 1 — Risk scoring + policy engine + human approval + audit (this repo)
- ⬜ Phase 2 — Plug in the URL/phishing risk analyzer (reuse the AI-WSS ML
  model as a second "risk signal source" alongside the tool-action risk
  already here)
- ⬜ Phase 3 — Prompt-injection detection module
- ⬜ Phase 4 — Dashboard frontend consuming `/dashboard/summary` and `/audit`
- ⬜ Phase 5 — JIT (time-limited) permissions, anomaly detection

## Notes for your report/demo

- The backend policy engine makes the actual authorization decision —
  an LLM is never trusted to grant itself permission, only to describe
  *intent*, which would flow in as the `action`/`resource`/`scope` fields.
- Every risk score comes with human-readable reasons — there's no black
  box to defend in front of your professor.
- The kill switch and human-approval queue are the two things that make
  this feel like real security infrastructure rather than a toy RBAC demo.
