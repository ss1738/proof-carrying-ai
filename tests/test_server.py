"""Smoke test for the pcai HTTP service: start it on an ephemeral port, exercise /health, /certify, /verify.
Run: python3 tests/test_server.py
"""
import json
import os
import sys
import threading
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pcai.server import _make_handler

POLICY = {"spend_cap": 1000, "allowlist": ["alice", "bob"]}


def _post(url, obj):
    req = urllib.request.Request(url, data=json.dumps(obj).encode(), method="POST")
    try:
        with urllib.request.urlopen(req) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def main() -> int:
    key = Ed25519PrivateKey.generate()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(key))
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"
    checks = []

    with urllib.request.urlopen(base + "/health") as r:
        health = json.loads(r.read())
    checks.append(("health ok + pubkey", health["status"] == "ok" and len(health["pubkey"]) == 64))

    code, cert = _post(base + "/certify", {"action": {"amount": 750, "counterparty": "alice"}, "policy": POLICY})
    checks.append(("certify compliant -> 200", code == 200 and cert["verdict"] == "ALLOW"))

    code, res = _post(base + "/verify", {"certificate": cert, "policy": POLICY})
    checks.append(("verify -> valid", code == 200 and res["valid"] is True))

    code, err = _post(base + "/certify", {"action": {"amount": 5000, "counterparty": "alice"}, "policy": POLICY})
    checks.append(("over-cap -> 422 not certifiable", code == 422 and err.get("certifiable") is False))

    code, res = _post(base + "/verify", {"certificate": cert, "policy": {"spend_cap": 1000, "allowlist": ["x"]}})
    checks.append(("mismatched policy -> invalid", res["valid"] is False))

    with urllib.request.urlopen(base + "/audit") as r:
        audit = json.loads(r.read())
    checks.append(("audit trail records certs + verifies", audit["count"] == 1 and audit["chain_verifies"]))

    srv.shutdown()
    allok = all(p for _, p in checks)
    for name, p in checks:
        print(f"  [{'PASS' if p else 'FAIL'}] {name}")
    print(f"\n{'PASS' if allok else 'FAIL'}: pcai HTTP service.")
    return 0 if allok else 1


if __name__ == "__main__":
    raise SystemExit(main())
