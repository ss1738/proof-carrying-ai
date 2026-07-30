"""pcai.certificate -- the proof-carrying compliance certificate as one usable object.

`issue(action, policy, key)` takes an agent action with SENSITIVE fields (amount, counterparty), checks it
against a formal policy, and returns a Certificate that proves compliance in ZERO KNOWLEDGE:
  - spend_cap (amount <= cap)      -> a ZK range proof (zk_range, secp256k1)
  - allowlist (counterparty in S)  -> a ZK set-membership proof (qedra zk_core, secp256k1)
plus an Ed25519 signature over the whole bundle. The certificate reveals only the public policy, the
commitments, the proofs, and the signature -- never the amount or the counterparty.

`Certificate.verify(policy, pubkey)` re-checks both proofs and the signature from public data alone.
Underlying soundness (allowed-set == compliant-set) is machine-checked in coq/. This is the library surface
over the pieces demonstrated in demo_structured_certificate.py / live_agent_bridge.py.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys
from dataclasses import dataclass, field

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
sys.path.insert(0, os.path.expanduser("~/agent-guardrail"))

from ec_group import EC
from qedra import zk_core
from qedra.zk_core import ZKProof

import zk_range

Q = EC.q
_G = EC


def _scalar(name: str) -> int:
    return int.from_bytes(hashlib.sha256(f"pcai/cp|{name}".encode()).digest(), "big") % Q or 1


def _canon_policy(p: dict) -> dict:
    return {"spend_cap": int(p["spend_cap"]), "allowlist": sorted(str(x) for x in p["allowlist"])}


def policy_id(policy: dict) -> str:
    return hashlib.sha256(json.dumps(_canon_policy(policy), sort_keys=True).encode()).hexdigest()[:16]


@dataclass
class Certificate:
    verdict: str
    policy: dict
    commitments: dict
    proofs: dict
    signature: str = ""
    pubkey: str = ""

    def body(self) -> dict:
        return {"verdict": self.verdict, "policy": self.policy,
                "commitments": self.commitments, "proofs": self.proofs}

    def to_json(self, indent=2) -> str:
        d = self.body()
        d["signature"] = self.signature
        d["pubkey"] = self.pubkey
        return json.dumps(d, indent=indent)

    @staticmethod
    def from_json(s: str) -> "Certificate":
        d = json.loads(s)
        return Certificate(d["verdict"], d["policy"], d["commitments"], d["proofs"],
                           d.get("signature", ""), d.get("pubkey", ""))

    def verify(self, policy: dict, pin_pubkey: str) -> tuple[bool, str]:
        """Re-check the signature and the ZK proofs from public data + the pinned key."""
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if policy_id(policy) != policy_id(self.policy):
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

        cap = int(policy["spend_cap"])
        try:
            Ca = _G.deser(self.commitments["amount"])
            if not zk_range.verify_le(Ca, cap, self.proofs["spend_cap"], group=_G):
                return False, "spend_cap ZK range proof does not verify"
            allowed = tuple(_scalar(n) for n in policy["allowlist"])
            Ccp = _G.deser(self.commitments["counterparty"])
            if not zk_core.verify(_G, allowed, Ccp, ZKProof.from_dict(self.proofs["allowlist"]), "pcai/allowlist"):
                return False, "allowlist ZK membership proof does not verify"
        except (ValueError, TypeError, KeyError):
            return False, "malformed commitment or proof (fails closed)"
        return True, "signature valid AND both ZK compliance proofs verify"


def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def issue(action: dict, policy: dict, signing_key, nbits: int = 32) -> Certificate:
    """Build a signed, zero-knowledge compliance certificate for `action` under `policy`.
    Raises ValueError if the action is not compliant (a false statement cannot be proven)."""
    cap = int(policy["spend_cap"])
    amount = int(action["amount"])
    counterparty = str(action["counterparty"])
    allowed_names = list(policy["allowlist"])

    if not (0 <= amount <= cap < (1 << nbits)):
        raise ValueError("spend_cap violated: amount not in [0, cap]")
    if counterparty not in allowed_names:
        raise ValueError("allowlist violated: counterparty not permitted")

    r_a = secrets.randbelow(Q)
    Ca, range_pf = zk_range.prove_le(amount, r_a, cap, nbits, group=_G)
    cp = _scalar(counterparty)
    allowed = tuple(_scalar(n) for n in allowed_names)
    r_c = secrets.randbelow(Q)
    memb, Ccp = zk_core.prove(_G, allowed, cp, r_c, "allow", "pcai/allowlist")

    cert = Certificate(
        verdict="ALLOW",
        policy=_canon_policy(policy),
        commitments={"amount": _G.ser(Ca), "counterparty": _G.ser(Ccp)},
        proofs={"spend_cap": range_pf, "allowlist": memb.to_dict()},
    )
    cert.signature = signing_key.sign(_canonical(cert.body())).hex()
    cert.pubkey = signing_key.public_key().public_bytes_raw().hex()
    return cert
