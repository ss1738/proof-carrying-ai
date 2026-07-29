"""Zero-knowledge range proof: prove a committed amount is <= a public limit, without revealing it.

Method: bit-decomposition. To prove a committed value d = limit - amount lies in [0, 2^n):
  - commit each bit b_i of d,
  - prove each bit is 0 or 1  (REUSES qedra's tested Sigma OR-proof over the set {0,1}),
  - the Pedersen homomorphism does the rest: the verifier recomputes prod(C_i^{2^i}) and checks it equals
    C_d = g^limit * C_amount^{-1}, which is publicly computable. If it matches and every bit is a bit, then
    d in [0, 2^n), i.e. amount <= limit.

The math this relies on (v = sum b_i 2^i with b_i in {0,1}  =>  0 <= v < 2^n) is machine-checked, axiom-free,
in coq/RangeProof.v. This is the spend_cap circuit for the general policy DSL.
"""
from __future__ import annotations

import os
import secrets
import sys

sys.path.insert(0, os.path.expanduser("~/agent-guardrail"))
from qedra import zk_core
from qedra.zk import MODP, P
from qedra.zk_core import ZKProof

G = MODP
Q = G.q


def commit(m: int, r: int) -> int:
    return zk_core.pedersen(G, m, r)


def prove_le(amount: int, r_a: int, limit: int, nbits: int = 32):
    """Prove commit(amount, r_a) hides an amount with 0 <= amount <= limit < 2^nbits, in zero knowledge.
    Returns (C_amount, proof_dict)."""
    if not (0 <= amount <= limit < (1 << nbits)):
        raise ValueError("cannot prove a false statement: need 0 <= amount <= limit < 2^nbits")
    C_amount = commit(amount, r_a)
    d = limit - amount                                   # >= 0, in [0, 2^nbits)
    bits = [(d >> i) & 1 for i in range(nbits)]
    r = [secrets.randbelow(Q) for _ in range(nbits)]
    # constrain the last randomness so that sum(r_i * 2^i) == -r_a (mod Q); then prod C_i^{2^i} == C_d.
    target = (-r_a) % Q
    partial = sum(r[i] * (1 << i) for i in range(nbits - 1)) % Q
    inv_top = pow((1 << (nbits - 1)) % Q, -1, Q)
    r[nbits - 1] = ((target - partial) * inv_top) % Q
    C_bits, bit_proofs = [], []
    for i in range(nbits):
        proof_i, C_i = zk_core.prove(G, (0, 1), bits[i], r[i], "bit", f"range/bit/{i}")
        C_bits.append(G.ser(C_i))
        bit_proofs.append(proof_i.to_dict())
    return C_amount, {"nbits": nbits, "C_bits": C_bits, "bit_proofs": bit_proofs}


def verify_le(C_amount: int, limit: int, proof: dict) -> bool:
    """Verify, from public data only, that C_amount hides a value <= limit."""
    nbits = proof["nbits"]
    C_bits = [G.deser(s) for s in proof["C_bits"]]
    bit_proofs = [ZKProof.from_dict(d) for d in proof["bit_proofs"]]
    if len(C_bits) != nbits or len(bit_proofs) != nbits:
        return False
    # 1. every committed bit really opens to {0,1}
    for i in range(nbits):
        if not zk_core.verify(G, (0, 1), C_bits[i], bit_proofs[i], f"range/bit/{i}"):
            return False
    # 2. homomorphic bind: prod(C_i^{2^i}) must equal C_d = g^limit * C_amount^{-1}
    lhs = 1
    for i in range(nbits):
        lhs = G.op(lhs, G.mul(C_bits[i], (1 << i) % Q))
    C_d = (pow(G.g, limit % Q, P) * pow(C_amount, -1, P)) % P
    return G.eq(lhs, C_d)


if __name__ == "__main__":
    # self-test: honest amount verifies; a forged over-limit certificate is rejected.
    r_a = secrets.randbelow(Q)
    C, pf = prove_le(amount=500, r_a=r_a, limit=1000, nbits=16)
    print("honest (500 <= 1000)      ->", "VERIFIED" if verify_le(C, 1000, pf) else "REJECTED")
    # forge: commit an over-limit amount, reuse a (false) range proof built for a small fake d.
    r_b = secrets.randbelow(Q)
    C_over = commit(5000, r_b)                          # amount 5000 > limit 1000
    # attacker tries to pass the honest proof's shape onto the over-limit commitment:
    print("forged (5000 <= 1000)     ->", "VERIFIED" if verify_le(C_over, 1000, pf) else "REJECTED (correct)")
    # and the honest prover simply cannot build a proof for a false statement:
    try:
        prove_le(amount=5000, r_a=r_b, limit=1000, nbits=16)
        print("prover built a false proof -> BUG")
    except ValueError:
        print("honest prover refuses false statement -> correct")
