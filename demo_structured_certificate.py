"""demo_structured_certificate.py -- the first proof-carrying certificate for a STRUCTURED agent action.

A payment: {amount (private), counterparty (private), cap (public), allowed counterparties (public)}.
The certificate proves, in ZERO KNOWLEDGE, that the payment obeyed the policy:
    spend_cap:  amount <= cap        -> ZK RANGE proof        (zk_range.py, bit-decomposition)
    allowlist:  counterparty in set  -> ZK SET-MEMBERSHIP     (qedra Sigma OR-proof)
without revealing the amount or the counterparty. Verifiable from public data alone; unforgeable.

This is the landmark seed: not git branches, but a real agentic payment, with BOTH policy rules proven in ZK
and the underlying math machine-checked (coq/RangeProof.v for the range bound, coq/PolicyDSL.v for the
conjunction). The two policy rules here are exactly the two ZK-native rule shapes of the general DSL.

    python3 demo_structured_certificate.py
"""
import os
import secrets
import sys

sys.path.insert(0, os.path.expanduser("~/agent-guardrail"))
from qedra import zk_core
from qedra.zk_core import ZKProof

import zk_range
from ec_group import EC

G = EC          # secp256k1: ~8x smaller/faster proofs than the 2048-bit MODP group
Q = G.q

# ---- public policy ----
CAP = 1000
NBITS = 16
COUNTERPARTIES = {"alice": 1, "bob": 2, "carol": 3, "mallory": 4}
ALLOWED_IDS = (1, 2, 3)   # alice, bob, carol allowed; mallory (4) is not


def make_certificate(amount: int, counterparty: str) -> dict:
    """Prover side: build a ZK certificate for a payment. Raises for a NON-compliant payment
    (a proof of a false statement cannot be produced)."""
    cid = COUNTERPARTIES[counterparty]
    r_a, r_c = secrets.randbelow(Q), secrets.randbelow(Q)
    C_amount, range_pf = zk_range.prove_le(amount, r_a, CAP, NBITS, group=G)    # spend_cap (range)
    memb_pf, C_cp = zk_core.prove(G, ALLOWED_IDS, cid, r_c, "allow", "cert/counterparty")  # allowlist (membership)
    return {"C_amount": C_amount, "range": range_pf,
            "C_cp": G.ser(C_cp), "membership": memb_pf.to_dict()}


def verify_certificate(cert: dict) -> bool:
    """Verifier side: public data only. True iff (amount <= CAP) AND (counterparty in ALLOWED_IDS), in ZK."""
    cap_ok = zk_range.verify_le(cert["C_amount"], CAP, cert["range"], group=G)
    cp_ok = zk_core.verify(G, ALLOWED_IDS, G.deser(cert["C_cp"]),
                           ZKProof.from_dict(cert["membership"]), "cert/counterparty")
    return cap_ok and cp_ok


if __name__ == "__main__":
    ok = True
    print("== Proof-carrying certificate for a structured agent action (payment) ==\n")
    print(f"policy:  amount <= {CAP} (ZK range)   AND   counterparty in allowlist (ZK set-membership)\n")

    # 1. compliant payment -> certificate builds and verifies
    cert = make_certificate(amount=750, counterparty="bob")
    v = verify_certificate(cert)
    ok = ok and v
    print(f"  compliant  (amount=750,  cp=bob)      -> certificate {'VERIFIED' if v else 'REJECTED'}")

    # 2. over-cap payment -> honest prover cannot build a certificate
    try:
        make_certificate(amount=5000, counterparty="bob")
        print("  over-cap   (amount=5000)             -> prover built a false cert  *** BUG ***"); ok = False
    except ValueError:
        print("  over-cap   (amount=5000)             -> prover CANNOT build a certificate (correct)")

    # 3. non-allowlisted counterparty -> honest prover cannot build
    try:
        make_certificate(amount=100, counterparty="mallory")
        print("  bad-cp     (cp=mallory)              -> prover built a false cert  *** BUG ***"); ok = False
    except ValueError:
        print("  bad-cp     (cp=mallory)              -> prover CANNOT build a certificate (correct)")

    # 4. tamper: splice an over-cap commitment under an otherwise-valid cert -> verifier rejects
    tampered = dict(cert)
    tampered["C_amount"] = zk_range.commit(9999, secrets.randbelow(Q), group=G)
    v = verify_certificate(tampered)
    ok = ok and (not v)
    print(f"  tampered   (swapped C_amount=9999)    -> certificate {'VERIFIED *** BUG ***' if v else 'REJECTED (correct)'}")

    print(f"\n{'PASS' if ok else 'FAIL'}: both policy rules proven in zero knowledge; "
          "range-proof math machine-checked in coq/RangeProof.v.")
    raise SystemExit(0 if ok else 1)
