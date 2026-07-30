"""Zero-knowledge range proof (spend_cap: amount <= limit) by bit-decomposition, reusing the Sigma OR-proof
per bit + the Pedersen homomorphism. Vendored/adapted from the repo-root zk_range.py so the `pcai` package is
self-contained (no external path dependency). Group is required (pcai uses secp256k1, pcai._ec.EC).
"""
from __future__ import annotations

import secrets

from . import _zkcore as zk_core
from ._zkcore import ZKProof


def commit(m: int, r: int, group):
    return zk_core.pedersen(group, m, r)


def _inv(group, C):
    return group.mul(C, group.q - 1)  # C^{-1} in a prime-order group == C^{q-1}


def prove_le(amount: int, r_a: int, limit: int, nbits: int, group):
    if not (0 <= amount <= limit < (1 << nbits)):
        raise ValueError("cannot prove a false statement: need 0 <= amount <= limit < 2^nbits")
    q = group.q
    C_amount = commit(amount, r_a, group)
    d = limit - amount
    bits = [(d >> i) & 1 for i in range(nbits)]
    r = [secrets.randbelow(q) for _ in range(nbits)]
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


def verify_le(C_amount, limit: int, proof: dict, group) -> bool:
    q = group.q
    nbits = proof["nbits"]
    if not isinstance(nbits, int) or not (1 <= nbits <= 64):
        return False  # a range near the group order is vacuous; a real bound is small
    C_bits = [group.deser(s) for s in proof["C_bits"]]
    bit_proofs = [ZKProof.from_dict(d) for d in proof["bit_proofs"]]
    if len(C_bits) != nbits or len(bit_proofs) != nbits:
        return False
    for i in range(nbits):
        if not zk_core.verify(group, (0, 1), C_bits[i], bit_proofs[i], f"range/bit/{i}"):
            return False
    acc = None
    for i in range(nbits):
        term = group.mul(C_bits[i], (1 << i) % q)
        acc = term if acc is None else group.op(acc, term)
    C_d = group.op(group.mul(group.g, limit % q), _inv(group, C_amount))
    return group.eq(acc, C_d)
