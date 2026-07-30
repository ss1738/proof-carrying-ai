"""Tamper-evident audit log: chain verifies; any edit/insert/delete breaks it; survives save/load.
Run: python3 tests/test_audit.py
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pcai import issue
from pcai.audit import AuditLog

POLICY = {"spend_cap": 1000, "allowlist": ["alice", "bob"]}


def main() -> int:
    key = Ed25519PrivateKey.generate()
    log = AuditLog()
    for i, cp in enumerate(["alice", "bob", "alice"]):
        log.record(issue({"amount": 100 + i, "counterparty": cp}, POLICY, key), at=1000.0 + i)
    checks = [("chain verifies", log.verify_chain())]

    # tamper: edit a recorded commitment -> chain breaks
    log.entries[1]["commitments"]["amount"] = "deadbeef"
    checks.append(("edited entry breaks chain", not log.verify_chain()))
    log.entries[1]["commitments"]["amount"] = log.entries[1]["hash"]  # restore-ish (still broken hash)

    # rebuild clean, test delete + reorder
    log2 = AuditLog()
    for i, cp in enumerate(["alice", "bob", "alice"]):
        log2.record(issue({"amount": 100 + i, "counterparty": cp}, POLICY, key), at=2000.0 + i)
    checks.append(("clean chain verifies", log2.verify_chain()))
    removed = log2.entries.pop(1)  # delete middle entry
    checks.append(("deleted entry breaks chain", not log2.verify_chain()))
    log2.entries.insert(1, removed)
    checks.append(("restored chain verifies again", log2.verify_chain()))

    # save/load round trip
    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
        path = f.name
    log2.save(path)
    loaded = AuditLog.load(path)
    os.unlink(path)
    checks.append(("survives save/load + verifies", loaded.verify_chain() and loaded.head == log2.head))

    allok = all(p for _, p in checks)
    for name, p in checks:
        print(f"  [{'PASS' if p else 'FAIL'}] {name}")
    print(f"\n{'PASS' if allok else 'FAIL'}: pcai tamper-evident audit log.")
    return 0 if allok else 1


if __name__ == "__main__":
    raise SystemExit(main())
