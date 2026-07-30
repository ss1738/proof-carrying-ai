"""pcai.certificate -- the proof-carrying compliance certificate as one usable object.

`issue(action, policy, key)` takes an agent action with SENSITIVE fields, checks it against a formal policy,
and returns a Certificate that proves compliance in ZERO KNOWLEDGE, revealing only the policy, per-rule
commitments, the proofs, and an Ed25519 signature -- never the field values.

A policy is a list of rules over the action's fields (any field, not just payments):
  - {"type": "max", "field": F, "limit": L}   amount/token-budget/etc <= L   -> ZK range proof
  - {"type": "min", "field": F, "floor": FL}  F >= FL                        -> ZK range proof
  - {"type": "in",  "field": F, "set": [...]} F is one of the allowed values -> ZK set-membership

The payment shorthand still works: {"spend_cap": 1000, "allowlist": [...], "residency": [...]} normalizes to
`max amount`, `in counterparty`, `in region`. The soundness bridge (allowed set == compliant set) is
machine-checked and axiom-free in coq/.
"""
from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field

from . import _bulletproof as _bp
from . import _range as _bitwise
from . import _zkcore as zk_core
from ._ec import EC
from ._zkcore import ZKProof

Q = EC.q
_G = EC


def _scalar(name: str) -> int:
    return int.from_bytes(hashlib.sha256(f"pcai/cp|{name}".encode()).digest(), "big") % Q or 1


def _normalize(policy: dict) -> list[dict]:
    """Translate the payment shorthand + any explicit rules into one canonical, sorted rule list."""
    rules: list[dict] = []
    if "spend_cap" in policy:
        rules.append({"type": "max", "field": "amount", "limit": int(policy["spend_cap"])})
    if "allowlist" in policy:
        rules.append({"type": "in", "field": "counterparty", "set": sorted(str(x) for x in policy["allowlist"])})
    if "residency" in policy:
        rules.append({"type": "in", "field": "region", "set": sorted(str(x) for x in policy["residency"])})
    for r in policy.get("rules", []):
        if r["type"] == "in":
            rules.append({"type": "in", "field": str(r["field"]), "set": sorted(str(x) for x in r["set"])})
        elif r["type"] == "max":
            rules.append({"type": "max", "field": str(r["field"]), "limit": int(r["limit"])})
        elif r["type"] == "min":
            rules.append({"type": "min", "field": str(r["field"]), "floor": int(r["floor"])})
        else:
            raise ValueError(f"unknown rule type: {r['type']}")
    return sorted(rules, key=lambda x: (x["field"], x["type"]))


def policy_id(policy: dict) -> str:
    return hashlib.sha256(json.dumps(_normalize(policy), sort_keys=True).encode()).hexdigest()[:16]


def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


@dataclass
class Certificate:
    verdict: str
    policy: list  # normalized rule list
    commitments: dict = field(default_factory=dict)  # field -> ONE commitment (shared across its rules)
    rules: list = field(default_factory=list)  # per-rule proof material (references its field's commitment)
    signature: str = ""
    pubkey: str = ""

    def body(self) -> dict:
        return {"verdict": self.verdict, "policy": self.policy, "commitments": self.commitments, "rules": self.rules}

    def to_json(self, indent=2) -> str:
        return json.dumps({**self.body(), "signature": self.signature, "pubkey": self.pubkey}, indent=indent)

    @staticmethod
    def from_json(s: str) -> "Certificate":
        d = json.loads(s)
        return Certificate(d["verdict"], d["policy"], d.get("commitments", {}), d.get("rules", []),
                           d.get("signature", ""), d.get("pubkey", ""))

    def verify(self, policy: dict, pin_pubkey: str) -> tuple[bool, str]:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if _normalize(policy) != self.policy:
            return False, "policy does not match the certificate's policy"
        if self.pubkey != pin_pubkey:
            return False, "public key does not match the pinned key"
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(pin_pubkey)).verify(
                bytes.fromhex(self.signature), _canonical(self.body()))
        except InvalidSignature:
            return False, "signature invalid (certificate tampered)"
        if self.verdict != "ALLOW":
            return False, f"not an ALLOW certificate (verdict '{self.verdict}')"
        # completeness: the certificate must carry a proof for EVERY rule in its policy (no dropped rules).
        proven = sorted(({k: v for k, v in e.items() if k not in ("proof", "kind")} for e in self.rules),
                        key=lambda x: (x["field"], x["type"]))
        if proven != self.policy:
            return False, "certificate does not prove every policy rule"
        try:
            for e in self.rules:
                # every rule on a field verifies against that field's ONE commitment -> same-field rules
                # (e.g. max & min on 'amount') are structurally bound to the same hidden value.
                if not _verify_rule(e, self.commitments[e["field"]]):
                    return False, f"ZK proof for rule {e['type']} {e['field']} does not verify"
        except (ValueError, TypeError, KeyError):
            return False, "malformed commitment or proof (fails closed)"
        return True, f"signature valid AND {len(self.rules)} ZK compliance proofs verify"


def _verify_rule(e: dict, commitment_hex: str) -> bool:
    C = _G.deser(commitment_hex)
    if e["type"] == "max":
        kind = e.get("kind", "bulletproofs")
        if kind == "bitwise":
            return _bitwise.verify_le(C, int(e["limit"]), e["proof"], group=_G)
        return _bp.verify_le(C, int(e["limit"]), e["proof"])
    if e["type"] == "min":
        return _bp.verify_ge(C, int(e["floor"]), e["proof"])
    if e["type"] == "in":
        allowed = tuple(_scalar(n) for n in e["set"])
        return zk_core.verify(_G, allowed, C, ZKProof.from_dict(e["proof"]), f"pcai/in/{e['field']}")
    return False


def issue(action: dict, policy: dict, signing_key, nbits: int = 32, range_proof: str = "bulletproofs") -> Certificate:
    """Build a signed, zero-knowledge compliance certificate for `action` under `policy`.
    `range_proof`: "bulletproofs" (default, ~6x smaller) or "bitwise" (~2x faster to issue), for max/min rules.
    Each field is committed ONCE and shared across its rules, so multiple rules on a field (e.g. a min/max
    band) are bound to the same hidden value. Raises ValueError if the action violates any rule."""
    rules = _normalize(policy)
    by_field: dict[str, list] = {}
    for r in rules:
        by_field.setdefault(r["field"], []).append(r)

    commitments: dict[str, str] = {}
    entries: list[dict] = []
    for f, frules in by_field.items():
        types = {r["type"] for r in frules}
        if types & {"max", "min"} and "in" in types:
            raise ValueError(f"field '{f}' mixes numeric (max/min) and membership (in) rules")
        r_blind = secrets.randbelow(Q)  # ONE blinding per field -> one shared commitment

        if "in" in types:
            v = str(action.get(f))
            C = None
            for r in frules:
                if v not in r["set"]:
                    raise ValueError(f"rule violated: {f}={v} not permitted")
                proof, C = zk_core.prove(_G, tuple(_scalar(n) for n in r["set"]), _scalar(v), r_blind, "allow", f"pcai/in/{f}")
                entries.append({**r, "proof": proof.to_dict()})
            commitments[f] = _G.ser(C)
        else:
            v = int(action[f])
            # a min rule needs the Bulletproofs generator; force the whole field onto it so max & min share hb
            use_bp = range_proof == "bulletproofs" or "min" in types
            if range_proof not in ("bulletproofs", "bitwise"):
                raise ValueError("range_proof must be 'bulletproofs' or 'bitwise'")
            C = None
            for r in frules:
                if r["type"] == "max":
                    limit = int(r["limit"])
                    if not (0 <= v <= limit < (1 << nbits)):
                        raise ValueError(f"rule violated: {f} not in [0, {limit}]")
                    if use_bp:
                        C, pf = _bp.prove_le(v, r_blind, limit, nbits)
                        entries.append({**r, "proof": pf, "kind": "bulletproofs"})
                    else:
                        C, pf = _bitwise.prove_le(v, r_blind, limit, nbits, group=_G)
                        entries.append({**r, "proof": pf, "kind": "bitwise"})
                else:  # min
                    floor = int(r["floor"])
                    if not (0 <= floor <= v < (1 << nbits)):
                        raise ValueError(f"rule violated: {f} < {floor}")
                    C, pf = _bp.prove_ge(v, r_blind, floor, nbits)
                    entries.append({**r, "proof": pf})
            commitments[f] = _G.ser(C)

    cert = Certificate(verdict="ALLOW", policy=rules, commitments=commitments, rules=entries)
    cert.signature = signing_key.sign(_canonical(cert.body())).hex()
    cert.pubkey = signing_key.public_key().public_bytes_raw().hex()
    return cert
