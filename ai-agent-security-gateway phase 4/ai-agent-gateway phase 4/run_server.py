"""
Run the AI Agent Security Gateway HTTP API.

Usage:
    python run_server.py [port]

No dependencies to install — uses only the Python standard library.
"""
import sys
from wsgiref.simple_server import make_server, WSGIRequestHandler
from gateway.api import app


class Http11RequestHandler(WSGIRequestHandler):
    """
    Speak HTTP/1.1 and correctly acknowledge 'Expect: 100-continue'.

    Some HTTP clients (notably PowerShell's Invoke-RestMethod / .NET's
    HttpClient) send an 'Expect: 100-continue' header before a POST body
    and then WAIT for the server to explicitly reply '100 Continue'
    before sending that body. The base wsgiref handler defaults to
    HTTP/1.0 and never sends that acknowledgment, which makes such
    clients hang forever. Setting protocol_version to HTTP/1.1 here
    switches on Python's built-in handling of that handshake.
    """

    protocol_version = "HTTP/1.1"


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
    print(f"AI Agent Security Gateway listening on http://127.0.0.1:{port}")
    print("Try:  curl http://127.0.0.1:%d/health" % port)
    with make_server("127.0.0.1", port, app, handler_class=Http11RequestHandler) as httpd:
        httpd.serve_forever()
