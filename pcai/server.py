"""pcai HTTP service: issue and verify proof-carrying compliance certificates over HTTP, so an agent runtime
(or a gateway in front of one) integrates without linking the library. Zero dependencies beyond the stdlib.

    pcai serve --port 8787
    curl -sX POST localhost:8787/certify -d '{"action":{"amount":750,"counterparty":"alice"},
                                              "policy":{"spend_cap":1000,"allowlist":["alice","bob"]}}'
    curl -sX POST localhost:8787/verify  -d '{"certificate":{...},"policy":{...}}'
    curl -s     localhost:8787/health

/certify returns 200 with the signed ZK certificate, or 422 if the action is non-compliant (cannot be
certified). /verify returns {"valid": bool, "reason": str}. The service holds the signing key; verifiers only
need the public key (GET /health).
"""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .audit import AuditLog
from .certificate import Certificate, issue


def _make_handler(key, audit: AuditLog | None = None):
    pub = key.public_key().public_bytes_raw().hex()
    audit = audit if audit is not None else AuditLog()

    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, obj):
            body = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _read(self) -> dict:
            n = int(self.headers.get("Content-Length", 0))
            return json.loads(self.rfile.read(n) or b"{}")

        def log_message(self, *a):  # quiet
            pass

        def do_GET(self):
            if self.path == "/health":
                self._send(200, {"status": "ok", "pubkey": pub, "service": "pcai"})
            elif self.path == "/audit":
                self._send(200, {"count": len(audit.entries), "head": audit.head,
                                 "chain_verifies": audit.verify_chain()})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            try:
                req = self._read()
            except (ValueError, json.JSONDecodeError):
                return self._send(400, {"error": "invalid JSON"})
            try:
                if self.path == "/certify":
                    if not isinstance(req, dict) or not isinstance(req.get("action"), dict) or not isinstance(req.get("policy"), dict):
                        return self._send(400, {"error": "expected {action: {...}, policy: {...}}"})
                    try:
                        cert = issue(req["action"], req["policy"], key)
                    except ValueError as e:
                        return self._send(422, {"error": str(e), "certifiable": False})
                    audit.record(cert)
                    return self._send(200, json.loads(cert.to_json()))
                if self.path == "/verify":
                    if not isinstance(req, dict) or not isinstance(req.get("certificate"), dict) or not isinstance(req.get("policy"), dict):
                        return self._send(400, {"error": "expected {certificate: {...}, policy: {...}}"})
                    cert = Certificate.from_json(json.dumps(req["certificate"]))
                    ok, reason = cert.verify(req["policy"], req.get("pubkey", pub))
                    return self._send(200, {"valid": ok, "reason": reason})
                return self._send(404, {"error": "not found"})
            except Exception as e:  # any unexpected input -> fail closed with 400, never 500
                return self._send(400, {"error": f"bad request: {type(e).__name__}"})

    return Handler


def serve(key, host: str = "127.0.0.1", port: int = 8787):
    httpd = ThreadingHTTPServer((host, port), _make_handler(key))
    pub = key.public_key().public_bytes_raw().hex()
    print(f"pcai serving on http://{host}:{port}  (pubkey {pub[:16]}...)")
    print("  POST /certify  POST /verify  GET /health")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
