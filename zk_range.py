"""Zero-knowledge range proof: prove a committed amount is <= a public limit, without revealing it.

Method: bit-decomposition. To prove a committed value d = limit - amount lies in [0, 2^n):
  - commit each bit b_i of d,
  - prove each bit is 0 or 1  (REUSES qedra's tested Sigma OR-proof over the set {0,1}),
  - the Pedersen homomorphism does the rest: the verifier recomputes prod(C_i^{2^i}) and checks it equals
    C_d = g^limit * C_amount^{-1}, which is publicly computable. If it matches and every bit is a bit, then
    d in [0, 2^n), i.e. amount <= limit.

Group-generic: works over any group with qedra's interface (op, mul, g, h, q, ser, deser, eq, rand_scalar).
Pass the 2048-bit MODP group (qedra default) or the secp256k1 EC group (ec_group.EC, ~8x smaller/faster).

The math this relies on (v = sum b_i 2^i with b_i in {0,1}  =>  0 <= v < 2^n) is machine-checked, axiom-free,
in coq/RangeProof.v. This is the spend_cap circuit for the general policy DSL.
"""
from __future__ import annotations

import os
import secrets
import sys

sys.path.insert(0, os.path.expanduser("~/agent-guardrail"))
from qedra import zk_core
from qedra.zk import MODP
from qedra.zk_core import ZKProof


def commit(m: int, r: int, group=MODP):
    return zk_core.pedersen(group, m, r)


def _inv(group, C):
    """C^{-1} in a group of prime order q: C^{q-1}. Interface-only, so it works for MODP and EC alike."""
    return group.mul(C, group.q - 1)


def prove_le(amount: int, r_a: int, limit: int, nbits: int = 32, group=MODP):
    """Prove commit(amount, r_a) hides an amount with 0 <= amount <= limit < 2^nbits, in zero knowledge.
    Returns (C_amount, proof_dict)."""
    if not (0 <= amount <= limit < (1 << nbits)):
        raise ValueError("cannot prove a false statement: need 0 <= amount <= limit < 2^nbits")
    q = group.q
    C_amount = commit(amount, r_a, group)
    d = limit - amount                                   # >= 0, in [0, 2^nbits)
    bits = [(d >> i) & 1 for i in range(nbits)]
    r = [secrets.randbelow(q) for _ in range(nbits)]
    # constrain the last randomness so that sum(r_i * 2^i) == -r_a (mod q); then prod C_i^{2^i} == C_d.
    target = (-r_a) % q
    partial = sum(r[i] * (1 << i) for i in range(nbits - 1)) % q
    inv_top = pow((1 << (nbits - 1)) % q, -1, q)
    r[nbits - 1] = ((target - partial) * inv_top) % q
    C_bits, bit_proofs = [], []
    for i in range(nbits):
        proof_i, C_i = zk_core.prove(group, (0, 1), bits[i], r[i], "bit", f"range/bit/{i}")
        C_bits.append(group.ser(C_i))
        bit_proofs.append(proof_i.to_dict())
    return C_amount, {"nbits": nbits, "C_bits": C_bits, "bit_proofs": bit_proofs}


def verify_le(C_amount, limit: int, proof: dict, group=MODP) -> bool:
    """Verify, from public data only, that C_amount hides a value <= limit."""
    q = group.q
    nbits = proof["nbits"]
    C_bits = [group.deser(s) for s in proof["C_bits"]]
    bit_proofs = [ZKProof.from_dict(d) for d in proof["bit_proofs"]]
    if len(C_bits) != nbits or len(bit_proofs) != nbits:
        return False
    # 1. every committed bit really opens to {0,1}
    for i in range(nbits):
        if not zk_core.verify(group, (0, 1), C_bits[i], bit_proofs[i], f"range/bit/{i}"):
            return False
    # 2. homomorphic bind: prod(C_i^{2^i}) must equal C_d = g^limit * C_amount^{-1}
    acc = None
    for i in range(nbits):
        term = group.mul(C_bits[i], (1 << i) % q)
        acc = term if acc is None else group.op(acc, term)
    C_d = group.op(group.mul(group.g, limit % q), _inv(group, C_amount))
    return group.eq(acc, C_d)


if __name__ == "__main__":
    from ec_group import EC
    for name, grp in (("MODP-2048", MODP), ("secp256k1", EC)):
        r_a = grp.rand_scalar()
        C, pf = prove_le(amount=500, r_a=r_a, limit=1000, nbits=16, group=grp)
        honest = verify_le(C, 1000, pf, group=grp)
        C_over = commit(5000, grp.rand_scalar(), grp)
        forged = verify_le(C_over, 1000, pf, group=grp)
        try:
            prove_le(amount=5000, r_a=r_a, limit=1000, nbits=16, group=grp)
            refuses = False
        except ValueError:
            refuses = True
        ok = honest and (not forged) and refuses
        print(f"  [{name:10}] honest={'VERIFIED' if honest else 'REJECTED'}  "
              f"forged={'REJECTED' if not forged else 'VERIFIED!!'}  prover_refuses_false={refuses}  "
              f"-> {'PASS' if ok else 'FAIL'}")
    print("range proof sound over both the 2048-bit MODP group and the secp256k1 EC group.")
