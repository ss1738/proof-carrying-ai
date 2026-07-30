"""pcai.certificate -- the proof-carrying compliance certificate as one usable object.

`issue(action, policy, key)` takes an agent action with SENSITIVE fields (amount, counterparty), checks it
against a formal policy, and returns a Certificate that proves compliance in ZERO KNOWLEDGE:
  - spend_cap (amount <= cap)      -> a ZK Bulletproofs range proof (logarithmic size, secp256k1)
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
import secrets
from dataclasses import dataclass

from . import _bulletproof as _bp
from . import _range as _bitwise
from . import _zkcore as zk_core
from ._ec import EC
from ._zkcore import ZKProof


def _range_verify(kind: str, C_amount, cap: int, proof: dict) -> bool:
    if kind == "bulletproofs":
        return _bp.verify_le(C_amount, cap, proof)
    return _bitwise.verify_le(C_amount, cap, proof, group=EC)

Q = EC.q
_G = EC


def _scalar(name: str) -> int:
    return int.from_bytes(hashlib.sha256(f"pcai/cp|{name}".encode()).digest(), "big") % Q or 1


def _canon_policy(p: dict) -> dict:
    return {"spend_cap": int(p["spend_cap"]),
            "allowlist": sorted(str(x) for x in p["allowlist"]),
            "residency": sorted(str(x) for x in p.get("residency", []))}


def _prove_membership(name: str, allowed_names, tag: str):
    """Commit `name` (as a scalar) and prove it is in `allowed_names`, in zero knowledge. Returns (C_hex, proof_dict)."""
    allowed = tuple(_scalar(n) for n in allowed_names)
    r = secrets.randbelow(Q)
    proof, C = zk_core.prove(_G, allowed, _scalar(name), r, "allow", tag)
    return _G.ser(C), proof.to_dict()


def _verify_membership(C_hex: str, allowed_names, proof_dict: dict, tag: str) -> bool:
    allowed = tuple(_scalar(n) for n in allowed_names)
    return zk_core.verify(_G, allowed, _G.deser(C_hex), ZKProof.from_dict(proof_dict), tag)


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
            kind = self.proofs.get("spend_cap_kind", "bulletproofs")
            if not _range_verify(kind, Ca, cap, self.proofs["spend_cap"]):
                return False, "spend_cap ZK range proof does not verify"
            if not _verify_membership(self.commitments["counterparty"], policy["allowlist"],
                                      self.proofs["allowlist"], "pcai/allowlist"):
                return False, "allowlist ZK membership proof does not verify"
            regions = policy.get("residency", [])
            if regions and not _verify_membership(self.commitments["region"], regions,
                                                  self.proofs["residency"], "pcai/residency"):
                return False, "residency ZK membership proof does not verify"
        except (ValueError, TypeError, KeyError):
            return False, "malformed commitment or proof (fails closed)"
        rules = "3 ZK compliance proofs" if policy.get("residency") else "2 ZK compliance proofs"
        return True, f"signature valid AND {rules} verify"


def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def issue(action: dict, policy: dict, signing_key, nbits: int = 32, range_proof: str = "bulletproofs") -> Certificate:
    """Build a signed, zero-knowledge compliance certificate for `action` under `policy`.
    `range_proof`: "bulletproofs" (default) = ~6x smaller cert; "bitwise" = ~2x faster to issue.
    Raises ValueError if the action is not compliant (a false statement cannot be proven)."""
    cap = int(policy["spend_cap"])
    amount = int(action["amount"])
    counterparty = str(action["counterparty"])
    allowed_names = list(policy["allowlist"])
    regions = list(policy.get("residency", []))

    if not (0 <= amount <= cap < (1 << nbits)):
        raise ValueError("spend_cap violated: amount not in [0, cap]")
    if counterparty not in allowed_names:
        raise ValueError("allowlist violated: counterparty not permitted")
    if regions and str(action.get("region")) not in regions:
        raise ValueError("residency violated: region not permitted")

    r_a = secrets.randbelow(Q)
    if range_proof == "bulletproofs":
        Ca, range_pf = _bp.prove_le(amount, r_a, cap, nbits)
    elif range_proof == "bitwise":
        Ca, range_pf = _bitwise.prove_le(amount, r_a, cap, nbits, group=_G)
    else:
        raise ValueError("range_proof must be 'bulletproofs' or 'bitwise'")
    Ccp_hex, memb = _prove_membership(counterparty, allowed_names, "pcai/allowlist")

    commitments = {"amount": _G.ser(Ca), "counterparty": Ccp_hex}
    proofs = {"spend_cap": range_pf, "spend_cap_kind": range_proof, "allowlist": memb}
    if regions:
        commitments["region"], proofs["residency"] = _prove_membership(str(action["region"]), regions, "pcai/residency")

    cert = Certificate(verdict="ALLOW", policy=_canon_policy(policy), commitments=commitments, proofs=proofs)
    cert.signature = signing_key.sign(_canonical(cert.body())).hex()
    cert.pubkey = signing_key.public_key().public_bytes_raw().hex()
    return cert
