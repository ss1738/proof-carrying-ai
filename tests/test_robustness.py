"""Adversarial robustness: throw malformed / hostile input at the HTTP service and confirm it NEVER 500s or
drops the connection -- every bad request gets a clean 4xx. A production service must fail closed, not crash.
Run: python3 tests/test_robustness.py
"""
import json
import os
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pcai.server import _make_handler

POLICY = {"spend_cap": 1000, "allowlist": ["alice", "bob"]}


def _raw_post(url, data: bytes):
    req = urllib.request.Request(url, data=data, method="POST", headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return 599  # dropped connection / timeout / crash -> a robustness failure


def main() -> int:
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(Ed25519PrivateKey.generate()))
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{port}"

    hostile = [
        ("empty body", b""),
        ("not json", b"}{ not json"),
        ("null", b"null"),
        ("missing action", json.dumps({"policy": POLICY}).encode()),
        ("missing policy", json.dumps({"action": {"amount": 1, "counterparty": "x"}}).encode()),
        ("wrong types", json.dumps({"action": {"amount": "lots", "counterparty": 5}, "policy": POLICY}).encode()),
        ("negative amount", json.dumps({"action": {"amount": -5, "counterparty": "alice"}, "policy": POLICY}).encode()),
        ("huge amount", json.dumps({"action": {"amount": 10**60, "counterparty": "alice"}, "policy": POLICY}).encode()),
        ("policy not dict", json.dumps({"action": {}, "policy": "nope"}).encode()),
        ("deeply nested junk", json.dumps({"action": {"amount": {"x": [1, 2, 3]}, "counterparty": "a"}, "policy": POLICY}).encode()),
    ]
    ok = True
    for name, body in hostile:
        for path in ("/certify", "/verify"):
            code = _raw_post(base + path, body)
            good = 400 <= code < 500  # a clean client error, never 5xx/599
            ok = ok and good
            if not good:
                print(f"  [FAIL] {path} {name}: got {code} (expected 4xx)")
    srv.shutdown()
    print(f"\n{'PASS' if ok else 'FAIL'}: service fails closed on {len(hostile) * 2} hostile requests (all 4xx, no 5xx/crash).")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
