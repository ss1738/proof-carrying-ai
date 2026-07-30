"""pcai.audit -- a tamper-evident, hash-chained record of every certificate issued. A compliance product needs
an auditable trail: this appends one entry per certificate (its policy id + commitments, never the hidden
values), each entry hashing the previous head, so any insertion, deletion, or edit breaks the chain.

    log = AuditLog()
    log.record(cert)          # after issue(...)
    log.verify_chain()        # True unless the trail was tampered with
    log.save("audit.jsonl")   # persist; AuditLog.load("audit.jsonl") to reopen and re-verify
"""
from __future__ import annotations

import hashlib
import json
import time

_GENESIS = hashlib.sha256(b"pcai/audit/genesis").hexdigest()


def _entry_hash(entry: dict) -> str:
    return hashlib.sha256(json.dumps(entry, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


class AuditLog:
    def __init__(self):
        self.head = _GENESIS
        self.entries: list[dict] = []

    def record(self, cert, at: float | None = None) -> str:
        """Append a certificate to the chain. Stores its policy + commitments + verdict, not the hidden action."""
        body = {
            "prev": self.head,
            "policy": cert.policy,
            "commitments": cert.commitments,
            "verdict": cert.verdict,
            "pubkey": cert.pubkey,
            "time": round(at if at is not None else time.time(), 3),
        }
        h = _entry_hash(body)
        self.entries.append({**body, "hash": h})
        self.head = h
        return h

    def verify_chain(self) -> bool:
        """Recompute the chain from genesis; True iff every link and the head are intact."""
        prev = _GENESIS
        for e in self.entries:
            body = {k: e[k] for k in ("prev", "policy", "commitments", "verdict", "pubkey", "time")}
            if e["prev"] != prev or _entry_hash(body) != e["hash"]:
                return False
            prev = e["hash"]
        return prev == self.head

    def save(self, path: str) -> None:
        with open(path, "w") as f:
            for e in self.entries:
                f.write(json.dumps(e) + "\n")

    @staticmethod
    def load(path: str) -> "AuditLog":
        log = AuditLog()
        with open(path) as f:
            log.entries = [json.loads(line) for line in f if line.strip()]
        log.head = log.entries[-1]["hash"] if log.entries else _GENESIS
        return log
