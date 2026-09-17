"""
Minimal WSGI HTTP API for the Gateway — built entirely on the Python
standard library (wsgiref) so the project has zero third-party
dependencies and runs anywhere Python 3 runs.

If you later want a fuller framework (FastAPI, Flask, Spring Boot), this
module's routes map 1:1 onto what you'd write there — swapping frameworks
should not require touching gateway/core.py at all.
"""

import json
import re
import os
from urllib.parse import parse_qs

from .core import Gateway, GatewayError

gateway = Gateway()

STATIC_DIR = os.path.join(os.path.dirname(__file__), "static")

# Each route: (method, compiled_regex, handler)
ROUTES = []


def route(method, pattern):
    regex = re.compile("^" + pattern + "$")

    def decorator(fn):
        ROUTES.append((method, regex, fn))
        return fn

    return decorator


def _json_response(start_response, status, payload):
    body = json.dumps(payload, default=str).encode("utf-8")
    start_response(
        status,
        [("Content-Type", "application/json"), ("Content-Length", str(len(body)))],
    )
    return [body]


def _html_response(start_response, status, html_text):
    body = html_text.encode("utf-8")
    start_response(
        status,
        [("Content-Type", "text/html; charset=utf-8"), ("Content-Length", str(len(body)))],
    )
    return [body]


# ---------------------------------------------------------------------
# Agents
# ---------------------------------------------------------------------
@route("POST", r"/agents")
def create_agent(match, data, query):
    agent = gateway.create_agent(
        name=data["name"], owner=data.get("owner"), trust_level=data.get("trust_level", "MEDIUM")
    )
    return 201, agent


@route("GET", r"/agents")
def list_agents(match, data, query):
    return 200, gateway.list_agents()


@route("GET", r"/agents/(\d+)")
def get_agent(match, data, query):
    return 200, gateway.get_agent(int(match.group(1)))


@route("POST", r"/agents/(\d+)/disable")
def disable_agent(match, data, query):
    return 200, gateway.disable_agent(int(match.group(1)))


@route("POST", r"/agents/(\d+)/enable")
def enable_agent(match, data, query):
    return 200, gateway.enable_agent(int(match.group(1)))


@route("POST", r"/agents/(\d+)/permissions")
def set_permission(match, data, query):
    agent_id = int(match.group(1))
    gateway.set_permission(
        agent_id, data["action"], data["resource"], data.get("allowed", True)
    )
    return 201, {"status": "ok", "permissions": gateway.get_permissions(agent_id)}


@route("GET", r"/agents/(\d+)/permissions")
def get_permissions(match, data, query):
    return 200, gateway.get_permissions(int(match.group(1)))


# ---------------------------------------------------------------------
# The gateway decision endpoint — this is the one every "AI agent" calls
# ---------------------------------------------------------------------
@route("POST", r"/gateway/request")
def gateway_request(match, data, query):
    result = gateway.evaluate_request(
        agent_id=int(data["agent_id"]),
        action=data["action"],
        resource=data["resource"],
        scope=data.get("scope", "SINGLE"),
    )
    return 200, result


# ---------------------------------------------------------------------
# Human approval workflow
# ---------------------------------------------------------------------
@route("GET", r"/approvals")
def list_approvals(match, data, query):
    status = query.get("status", [None])[0]
    return 200, gateway.list_approvals(status)


@route("POST", r"/approvals/(\d+)/approve")
def approve(match, data, query):
    return 200, gateway.resolve_approval(int(match.group(1)), approve=True, resolved_by=data.get("resolved_by", "admin"))


@route("POST", r"/approvals/(\d+)/deny")
def deny(match, data, query):
    return 200, gateway.resolve_approval(int(match.group(1)), approve=False, resolved_by=data.get("resolved_by", "admin"))


# ---------------------------------------------------------------------
# Audit log + dashboard
# ---------------------------------------------------------------------
@route("GET", r"/audit")
def audit_log(match, data, query):
    agent_id = query.get("agent_id", [None])[0]
    limit = int(query.get("limit", [50])[0])
    return 200, gateway.get_audit_log(int(agent_id) if agent_id else None, limit)


@route("GET", r"/dashboard/summary")
def dashboard_summary(match, data, query):
    return 200, gateway.dashboard_summary()


@route("GET", r"/health")
def health(match, data, query):
    return 200, {"status": "ok"}


# ---------------------------------------------------------------------
# WSGI application
# ---------------------------------------------------------------------
def app(environ, start_response):
    method = environ["REQUEST_METHOD"]
    path = environ["PATH_INFO"].rstrip("/") or "/"
    query = parse_qs(environ.get("QUERY_STRING", ""))

    # Serve the dashboard UI at the root — everything else below is the JSON API.
    if method == "GET" and path == "/":
        try:
            with open(os.path.join(STATIC_DIR, "dashboard.html"), "r", encoding="utf-8") as f:
                return _html_response(start_response, "200 OK", f.read())
        except FileNotFoundError:
            return _json_response(start_response, "404 Not Found", {"error": "dashboard.html not found"})

    if method == "GET" and path == "/favicon.ico":
        start_response("204 No Content", [])
        return [b""]

    data = {}
    if method in ("POST", "PUT", "PATCH"):
        try:
            length = int(environ.get("CONTENT_LENGTH") or 0)
        except ValueError:
            length = 0
        raw = environ["wsgi.input"].read(length) if length else b""
        if raw:
            try:
                data = json.loads(raw)
            except json.JSONDecodeError:
                return _json_response(start_response, "400 Bad Request", {"error": "invalid JSON body"})

    for route_method, regex, handler in ROUTES:
        if route_method != method:
            continue
        m = regex.match(path)
        if not m:
            continue
        try:
            status_code, payload = handler(m, data, query)
            status_line = {200: "200 OK", 201: "201 Created"}.get(status_code, f"{status_code} OK")
            return _json_response(start_response, status_line, payload)
        except GatewayError as e:
            status_line = {400: "400 Bad Request", 404: "404 Not Found", 409: "409 Conflict"}.get(
                e.status, "400 Bad Request"
            )
            return _json_response(start_response, status_line, {"error": e.message})
        except KeyError as e:
            return _json_response(start_response, "400 Bad Request", {"error": f"missing field: {e}"})

    return _json_response(start_response, "404 Not Found", {"error": f"no route for {method} {path}"})
