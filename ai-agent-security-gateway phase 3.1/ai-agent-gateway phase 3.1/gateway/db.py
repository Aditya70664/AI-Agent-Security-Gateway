"""
Database layer for the AI Agent Security Gateway.

Uses sqlite3 (Python standard library) — no external dependencies.
"""

import sqlite3
import os
import threading

DB_PATH = os.environ.get("GATEWAY_DB_PATH", os.path.join(os.path.dirname(__file__), "..", "gateway.db"))

_local = threading.local()

SCHEMA = """
CREATE TABLE IF NOT EXISTS agents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    owner TEXT,
    trust_level TEXT NOT NULL DEFAULT 'MEDIUM',  -- LOW / MEDIUM / HIGH
    status TEXT NOT NULL DEFAULT 'ACTIVE',       -- ACTIVE / DISABLED
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    allowed INTEGER NOT NULL DEFAULT 1,   -- 1 = allowed, 0 = explicitly denied
    expires_at TEXT,                      -- optional, for JIT/temporary permissions
    FOREIGN KEY (agent_id) REFERENCES agents(id),
    UNIQUE(agent_id, action, resource)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id INTEGER NOT NULL,
    action TEXT NOT NULL,
    resource TEXT NOT NULL,
    scope TEXT,
    risk_score INTEGER NOT NULL,
    decision TEXT NOT NULL,   -- ALLOW / DENY / PENDING_APPROVAL / BLOCKED
    reasons TEXT,             -- JSON-encoded list of strings
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (agent_id) REFERENCES agents(id)
);

CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_log_id INTEGER NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',  -- PENDING / APPROVED / DENIED
    resolved_by TEXT,
    resolved_at TEXT,
    FOREIGN KEY (audit_log_id) REFERENCES audit_logs(id)
);
"""


def get_connection():
    """Thread-local sqlite3 connection with row factory for dict-like access."""
    if not hasattr(_local, "conn"):
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        _local.conn = conn
    return _local.conn


def init_db():
    conn = get_connection()
    conn.executescript(SCHEMA)
    conn.commit()


def reset_db():
    """Wipe all tables — useful for tests/demo runs."""
    conn = get_connection()
    conn.executescript(
        "DROP TABLE IF EXISTS approvals;"
        "DROP TABLE IF EXISTS audit_logs;"
        "DROP TABLE IF EXISTS permissions;"
        "DROP TABLE IF EXISTS agents;"
    )
    conn.commit()
    init_db()
