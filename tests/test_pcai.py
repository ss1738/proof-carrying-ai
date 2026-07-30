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
    fld = next(iter(tampered.commitments))
    a = tampered.commitments[fld]
    tampered.commitments[fld] = a[:-1] + ("0" if a[-1] != "0" else "1")  # flip last hex char
    okt, _ = tampered.verify(POLICY, pub)
    checks.append(("tampered commitment rejected", not okt, ""))

    # 6. wrong pinned key rejected
    other = Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex()
    okw, _ = cert.verify(POLICY, other)
    checks.append(("wrong pinned key rejected", not okw, ""))

    # 7. verifying against a different policy is rejected
    okp, _ = cert.verify({"spend_cap": 1000, "allowlist": ["alice", "carol"]}, pub)
    checks.append(("mismatched policy rejected", not okp, ""))

    # 8. residency: a policy with regions -> region proven in ZK too
    rpol = {"spend_cap": 1000, "allowlist": ["alice", "bob"], "residency": ["EU", "UK"]}
    rcert = issue({"amount": 750, "counterparty": "bob", "region": "UK"}, rpol, key)
    okr, whyr = rcert.verify(rpol, pub)
    checks.append(("residency issues + verifies (3 ZK proofs)", okr and "3 ZK" in whyr, whyr))

    # 9. wrong region cannot be certified
    try:
        issue({"amount": 750, "counterparty": "bob", "region": "CN"}, rpol, key)
        checks.append(("wrong region refused", False, "issued a false certificate"))
    except ValueError:
        checks.append(("wrong region refused", True, ""))

    # 10. GENERAL policy over non-payment fields: an LLM tool call with a token budget + tool allowlist + min
    gpol = {"rules": [
        {"type": "max", "field": "tokens", "limit": 100_000},
        {"type": "min", "field": "tokens", "floor": 1},
        {"type": "in", "field": "tool", "set": ["read", "search", "summarize"]},
    ]}
    gcert = issue({"tokens": 42_000, "tool": "search"}, gpol, key)
    okg, whyg = gcert.verify(gpol, pub)
    checks.append(("general non-payment policy verifies", okg and "3 ZK" in whyg, whyg))

    # 11. over-budget tokens refused
    try:
        issue({"tokens": 500_000, "tool": "search"}, gpol, key)
        checks.append(("over-budget refused", False, "issued a false certificate"))
    except ValueError:
        checks.append(("over-budget refused", True, ""))

    # 12. disallowed tool refused
    try:
        issue({"tokens": 100, "tool": "delete_all"}, gpol, key)
        checks.append(("disallowed tool refused", False, "issued a false certificate"))
    except ValueError:
        checks.append(("disallowed tool refused", True, ""))

    # 13. band (max+min on the SAME field) shares ONE commitment -> rules bound to the same hidden value
    band = {"rules": [{"type": "max", "field": "amount", "limit": 1000}, {"type": "min", "field": "amount", "floor": 100}]}
    bcert = issue({"amount": 500}, band, key)
    okb, _ = bcert.verify(band, pub)
    one_commitment = len(bcert.commitments) == 1 and "amount" in bcert.commitments
    checks.append(("band shares one commitment + verifies (soundness fix)", okb and one_commitment, ""))
    # below the floor -> refused
    try:
        issue({"amount": 50}, band, key)
        checks.append(("below band floor refused", False, "issued a false certificate"))
    except ValueError:
        checks.append(("below band floor refused", True, ""))

    allok = True
    for name, passed, note in checks:
        allok = allok and passed
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}" + (f"  ({note})" if note and not passed else ""))
    print(f"\n{'PASS' if allok else 'FAIL'}: pcai certificate library end-to-end.")
    return 0 if allok else 1


if __name__ == "__main__":
    raise SystemExit(main())
