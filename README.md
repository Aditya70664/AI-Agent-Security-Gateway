# AI Agent Security Gateway

### Zero-Trust Authorization and Risk-Control Framework for Autonomous AI Agents

A Python-based security gateway that sits between autonomous AI agents and the tools, systems, URLs, and content they attempt to access. Every action is evaluated through **identity verification, permission checks, risk analysis, policy enforcement, human approval, and audit logging**.

The project follows a **zero-trust and least-privilege security model**, ensuring that no agent action is implicitly trusted.

---

## 🚀 Overview

Autonomous AI agents can interact with databases, APIs, files, emails, cloud services, and the web. Giving these agents unrestricted access introduces risks such as:

* Excessive permissions
* Prompt-injection attacks
* Phishing and malicious URLs
* High-impact or destructive actions
* Lack of human oversight
* Insufficient auditability

This project addresses these risks through a centralized authorization gateway.

Every request follows a structured security pipeline:

```text
AI Agent
   │
   ▼
Identity Resolution
   │
   ▼
Kill-Switch Check
   │
   ▼
Permission Check
   │
   ▼
Risk Analysis
   │
   ├── General Action Risk
   ├── URL / Phishing Risk
   └── Prompt-Injection Risk
   │
   ▼
Policy Engine
   │
   ├── ALLOW
   ├── DENY
   ├── PENDING_APPROVAL
   └── BLOCKED
   │
   ▼
Audit Logging
```

The architecture is modular, allowing additional risk analyzers to be added without modifying the core permission, policy, or audit components.

---

## ✨ Key Features

### 🔐 Zero-Trust Authorization

Every request is evaluated independently.

An agent cannot perform an action unless an explicit permission exists for the requested action and resource.

```text
No Permission → DENY
```

This implements a default-deny, least-privilege authorization model.

### 👤 Agent Identity & Trust Levels

Each AI agent has:

* Unique identity
* Owner information
* Trust level

  * LOW
  * MEDIUM
  * HIGH
* ACTIVE / DISABLED status

Trust level contributes to risk evaluation and determines how certain medium-risk actions are handled.

### ⚠️ Risk Scoring

The gateway generates an explainable **0–100 risk score**.

The general risk engine considers:

* Action type
* Resource sensitivity
* Scope
* Agent trust level

Every contributing factor produces a human-readable explanation.

Example:

```text
Risk Score: 82

Reasons:
- DELETE operation has high base risk
- Target is a production database
- Scope is BULK
- Agent trust level is LOW
```

The score is clamped to the 0–100 range.

---

## 🛡️ Security Modules

### 1. General Tool-Action Risk Engine

Evaluates actions such as:

```text
READ
VISIT
DOWNLOAD
PROCESS_CONTENT
SEND
WRITE
UPDATE
MODIFY_CONFIG
DELETE
ADMIN
```

Higher-impact operations receive higher base-risk values.

---

### 2. URL & Phishing Risk Analyzer

The URL analyzer evaluates multiple signals, including:

* HTTP instead of HTTPS
* Raw IP addresses
* URL `@` obfuscation
* Excessive hostname hyphens
* Deep subdomain nesting
* Suspicious top-level domains
* URL shorteners
* Punycode domains
* Phishing-related keywords
* Excessively long URLs
* Executable/script file extensions

Signals are accumulated into an explainable risk score rather than producing an opaque classification.

Example:

```text
http://192.168.1.1-secure-login-verify.tk/signin
```

During testing, this URL produced a high risk score and was routed to human approval.

---

### 3. Prompt-Injection Detector

The prompt-injection analyzer scans content that an AI agent may process, such as:

* Emails
* Web content
* Documents
* External text

It detects patterns associated with techniques such as:

* Instruction override
* Context reset
* System-prompt extraction
* Role reassignment
* Fake system instructions
* Secrecy requests
* Data exfiltration
* Credential references
* External destinations
* Financial transaction triggers
* Destructive bulk actions
* Urgency manipulation

The current implementation uses **regular-expression pattern matching and weighted heuristics**, not machine-learning classifiers.

---

## 👨‍💻 Human-in-the-Loop Approval

High-risk requests are not automatically executed.

Depending on permission status, risk score, and agent trust level, an action can be placed into:

```text
PENDING_APPROVAL
```

A reviewer can then:

```text
APPROVE
   or
DENY
```

The approval decision is permanently recorded with the resolver and timestamp.

---

## 🔴 Kill Switch

Administrators can immediately disable an AI agent.

Once disabled:

```text
Agent Request
     ↓
Kill-Switch Check
     ↓
BLOCKED
```

The request is blocked before permission or risk evaluation occurs.

---

## 📋 Audit Logging

Every authorization decision is recorded:

* Agent
* Action
* Resource
* Scope
* Risk score
* Decision
* Risk reasons
* Timestamp

The system records:

```text
ALLOW
DENY
PENDING_APPROVAL
BLOCKED
```

This creates a centralized audit trail for security review and debugging.

---

## 🖥️ Browser Dashboard

The project includes a browser-based dashboard built without frontend frameworks.

### Dashboard capabilities

* Agent monitoring
* Agent creation
* Enable / Disable agents
* Permission management
* Request testing
* Risk-score visualization
* Human approval management
* Audit-log monitoring
* System statistics

The dashboard communicates with the same JSON REST API used by direct clients. It polls the API every four seconds to update displayed data.

### Frontend Stack

```text
HTML5
CSS3
Vanilla JavaScript
Fetch API
Async/Await
```

No React, Vue, jQuery, CSS framework, or CDN dependency is required.

---

## 🗄️ Database Design

The system uses **SQLite 3** with four relational tables:

```text
agents
   │
   ├── permissions
   │
   └── audit_logs
          │
          └── approvals
```

### `agents`

Stores registered AI agent identities.

### `permissions`

Stores explicit action/resource permissions.

### `audit_logs`

Stores every authorization decision and its risk information.

### `approvals`

Stores high-risk actions awaiting or completing human review.

The database schema is designed around explicit permissions and permanent auditability.

---

## 🔌 REST API

| Method | Endpoint                    | Purpose                  |
| ------ | --------------------------- | ------------------------ |
| GET    | `/`                         | Serve dashboard          |
| GET    | `/health`                   | Health check             |
| POST   | `/agents`                   | Register agent           |
| GET    | `/agents`                   | List agents              |
| GET    | `/agents/{id}`              | Get agent details        |
| POST   | `/agents/{id}/disable`      | Disable agent            |
| POST   | `/agents/{id}/enable`       | Enable agent             |
| POST   | `/agents/{id}/permissions`  | Grant/deny permission    |
| GET    | `/agents/{id}/permissions`  | List permissions         |
| POST   | `/gateway/request`          | Evaluate an agent action |
| GET    | `/approvals?status=PENDING` | List approvals           |
| POST   | `/approvals/{id}/approve`   | Approve request          |
| POST   | `/approvals/{id}/deny`      | Deny request             |
| GET    | `/audit`                    | Retrieve audit logs      |
| GET    | `/dashboard/summary`        | Dashboard statistics     |

The main gateway endpoint is:

```text
POST /gateway/request
```

It evaluates whether an agent is authorized to perform a specific action against a resource.

---

## 🧪 Testing & Quality Assurance

The project includes **34 automated unit tests** across three test modules.

```text
tests/test_gateway.py
    8 tests

tests/test_url_risk.py
    13 tests

tests/test_prompt_injection.py
    13 tests

Total
    34 tests
```

All 34 tests pass.

Testing covers:

* Identity handling
* Permission enforcement
* Risk scoring
* Policy decisions
* Kill switch
* Approval workflow
* URL-risk detection
* Prompt-injection detection
* Regression cases
* API integration
* Malformed input handling
* Permission-bucket isolation

---

## 🔬 Live Integration Testing

The system was also tested against a live HTTP server using:

* `curl`
* Windows PowerShell
* `Invoke-RestMethod`

Major workflows were tested end-to-end, including:

```text
Agent creation
      ↓
Permission assignment
      ↓
Gateway request
      ↓
Risk evaluation
      ↓
Policy decision
      ↓
Approval resolution
      ↓
Audit logging
```

Live testing uncovered two genuine implementation issues:

1. An HTTP `Expect: 100-continue` interoperability issue.
2. A prompt-injection data-exfiltration phrasing false negative.

Both were root-caused, fixed, and covered by regression testing.

---

## 🛠️ Technology Stack

### Backend

* Python 3.12+
* Python Standard Library
* `wsgiref.simple_server`
* `http.server`
* `sqlite3`
* `json`
* `re`
* `urllib.parse`
* `unittest`

### Frontend

* HTML5
* CSS3
* Vanilla JavaScript
* Fetch API

### Database

* SQLite 3

### Development

* Visual Studio Code
* Git
* GitHub
* Windows 10/11
* PowerShell

The backend deliberately uses **zero third-party Python dependencies**. No Flask, FastAPI, Django, React, Vue, or other framework installation is required.

---

## 📁 Project Structure

```text
AI-Agent-Security-Gateway/
│
├── gateway/
│   ├── api.py
│   ├── core.py
│   ├── policy_engine.py
│   ├── risk_engine.py
│   ├── url_risk_engine.py
│   ├── prompt_injection_engine.py
│   └── static/
│       └── dashboard.html
│
├── tests/
│   ├── test_gateway.py
│   ├── test_url_risk.py
│   └── test_prompt_injection.py
│
├── demo.py
├── demo_url_risk.py
├── demo_prompt_injection.py
├── run_server.py
├── gateway.db
└── README.md
```

> The exact file structure should match the files committed to the repository. Remove or modify entries above if your GitHub repository uses different filenames.

---

## ⚙️ Installation

### Prerequisites

* Python 3.12 or later
* Git

No external Python packages are required.

### Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/AI-Agent-Security-Gateway.git
cd AI-Agent-Security-Gateway
```

---

## ▶️ Running the Project

### 1. Run the demonstration scripts

```bash
python demo.py
```

Run the URL risk demonstration:

```bash
python demo_url_risk.py
```

Run the prompt-injection demonstration:

```bash
python demo_prompt_injection.py
```

These demonstrations can be executed without starting the HTTP server.

---

### 2. Run the test suite

```bash
python -m unittest discover -s tests -v
```

Expected result:

```text
Ran 34 tests

OK
```

---

### 3. Start the REST API server

```bash
python run_server.py 8000
```

The server will run at:

```text
http://127.0.0.1:8000
```

Open that address in your browser to access the dashboard.

---

## 🧪 Example API Usage

### Create an AI agent

```bash
curl -X POST http://localhost:8000/agents \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"FinanceBot\",\"trust_level\":\"MEDIUM\"}"
```

### Grant permission

```bash
curl -X POST http://localhost:8000/agents/1/permissions \
  -H "Content-Type: application/json" \
  -d "{\"action\":\"READ\",\"resource\":\"invoices\",\"allowed\":true}"
```

### Submit an action for authorization

```bash
curl -X POST http://localhost:8000/gateway/request \
  -H "Content-Type: application/json" \
  -d "{\"agent_id\":1,\"action\":\"READ\",\"resource\":\"invoices\"}"
```

The gateway evaluates the request and returns the risk score, decision, and reasons.

---

## 🧠 Engineering Principles

The implementation follows several core engineering principles:

### Zero Trust

Every request is evaluated independently.

### Least Privilege

No explicit permission means no access.

### Explainability

Risk decisions include human-readable reasons.

### Defense in Depth

Multiple independent security signals contribute to the decision.

### Fail Safe

Disabled agents and unauthorized actions resolve to blocking/denial rather than implicit access.

### Separation of Concerns

Identity, permissions, risk analysis, policy decisions, and audit logging are separated into independent modules.

These principles also make the system easier to extend and test.

---

## ⚠️ Current Limitations

This project is a **working prototype**, not a production security gateway.

Current limitations include:

* Risk detection is rule-based rather than machine-learned.
* The gateway does not fetch live web pages.
* The gateway API itself does not currently have API-key/token authentication.
* SQLite is used instead of a production server-based database.
* File-upload scanning is not implemented.
* Time-limited `expires_at` permissions are reserved but not currently enforced.
* Cryptographic agent identity is not implemented.
* Agent-to-agent authorization is not implemented.
* Behavioral anomaly detection is not implemented.

---

## 🔮 Future Improvements

Planned extensions include:

* Just-In-Time (JIT) permissions
* Machine-learned risk scoring
* Behavioral anomaly detection
* Cryptographically signed agent identities
* Agent-to-agent authorization
* Gateway API authentication
* PostgreSQL/server-based database deployment
* Docker containerization
* File-upload scanning

The modular risk-analyzer interface is designed so future ML-based analyzers can replace or augment the current rule-based modules without changing the core policy and authorization architecture.

---

## 📊 Project Highlights

| Area              | Implementation                     |
| ----------------- | ---------------------------------- |
| Authorization     | Zero-trust, least privilege        |
| API               | Python REST API                    |
| Database          | SQLite                             |
| Risk Analysis     | 3 independent modules              |
| URL Security      | Rule-based phishing risk analysis  |
| AI Security       | Prompt-injection pattern detection |
| Policy            | Allow / Deny / Approval / Block    |
| Human Review      | Approval workflow                  |
| Emergency Control | Agent kill switch                  |
| Logging           | Centralized audit trail            |
| Frontend          | HTML5 + CSS3 + Vanilla JavaScript  |
| Testing           | 34 automated unit tests            |
| Dependencies      | Python standard library only       |

---

## 📌 Project Status

**Status: Functional Prototype**

The four project phases have been implemented and integrated:

```text
Phase 1 → Core Authorization Gateway
Phase 2 → URL & Phishing Risk Analysis
Phase 3 → Prompt-Injection Detection
Phase 4 → Browser Dashboard
```

All 34 automated tests pass, and the major workflows were additionally validated against a live HTTP server.

---

## 👨‍💻 Author

**Aditya Sharma**

B.Tech Computer Science & Engineering
Siliguri Institute of Technology (MAKAUT)
Siliguri, West Bengal, India

---

## 📄 License

This project was developed as an academic/final-year project and prototype. Add a specific open-source license here if you intend to distribute the code under one.
