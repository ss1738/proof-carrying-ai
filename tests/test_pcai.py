"""End-to-end test of the pcai certificate library: issue -> verify, plus the failure modes.
Run: python3 tests/test_pcai.py   (no test framework needed)
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pcai import Certificate, issue

POLICY = {"spend_cap": 1000, "allowlist": ["alice", "bob"]}


def main() -> int:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw().hex()
    checks = []

    # 1. compliant action -> issue -> verify OK
    cert = issue({"amount": 750, "counterparty": "alice"}, POLICY, key)
    ok, why = cert.verify(POLICY, pub)
    checks.append(("compliant issues + verifies", ok, why))

    # 2. round-trips through JSON unchanged
    cert2 = Certificate.from_json(cert.to_json())
    ok2, _ = cert2.verify(POLICY, pub)
    checks.append(("survives JSON round-trip", ok2, ""))

    # 3. over-cap amount cannot be certified
    try:
        issue({"amount": 5000, "counterparty": "alice"}, POLICY, key)
        checks.append(("over-cap refused", False, "issued a false certificate"))
    except ValueError:
        checks.append(("over-cap refused", True, ""))

    # 4. non-allowlisted counterparty cannot be certified
    try:
        issue({"amount": 100, "counterparty": "mallory"}, POLICY, key)
        checks.append(("bad counterparty refused", False, "issued a false certificate"))
    except ValueError:
        checks.append(("bad counterparty refused", True, ""))

    # 5. tampering the commitment breaks verification
    tampered = Certificate.from_json(cert.to_json())
    a = tampered.commitments["amount"]
    tampered.commitments["amount"] = a[:-1] + ("0" if a[-1] != "0" else "1")  # flip last hex char
    okt, _ = tampered.verify(POLICY, pub)
    checks.append(("tampered commitment rejected", not okt, ""))

    # 6. wrong pinned key rejected
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    okw, _ = cert.verify(POLICY, other)
    checks.append(("wrong pinned key rejected", not okw, ""))

    # 7. verifying against a different policy is rejected
    okp, _ = cert.verify({"spend_cap": 1000, "allowlist": ["alice", "carol"]}, pub)
    checks.append(("mismatched policy rejected", not okp, ""))

    allok = True
    for name, passed, note in checks:
        allok = allok and passed
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}" + (f"  ({note})" if note and not passed else ""))
    print(f"\n{'PASS' if allok else 'FAIL'}: pcai certificate library end-to-end.")
    return 0 if allok else 1


if __name__ == "__main__":
    raise SystemExit(main())
