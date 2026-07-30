"""BN254 (alt_bn128) G1 group, matching Ethereum's ecAdd (0x06) / ecMul (0x07) precompiles, so a Sigma
OR-proof built over it can be verified ON-CHAIN with those precompiles. Same protocol as qedra's zk_core,
additive EC notation. Points serialize as uncompressed 64-byte X||Y (the precompile format).
"""
from __future__ import annotations

import hashlib

# BN254 G1: y^2 = x^3 + 3 over F_Q; prime subgroup order R (== the whole curve, cofactor 1).
Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583
R = 21888242871839275222246405745257275088548364400416034343698204186575808495617
B = 3
G1 = (1, 2)

Point = tuple  # (x, y) or None (identity)


def _inv(x: int) -> int:
    return pow(x % Q, Q - 2, Q)


def add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % Q == 0:
        return None
    if p == q:
        s = (3 * x1 * x1) * _inv(2 * y1) % Q
    else:
        s = (y2 - y1) * _inv(x2 - x1) % Q
    x3 = (s * s - x1 - x2) % Q
    return (x3, (s * (x1 - x3) - y1) % Q)


def mul(k: int, p):
    k %= R
    r = None
    while k:
        if k & 1:
            r = add(r, p)
        p = add(p, p)
        k >>= 1
    return r


def on_curve(p) -> bool:
    if p is None:
        return True
    x, y = p
    return (y * y - (x * x * x + B)) % Q == 0


def hash_to_point(label: bytes):
    ctr = 0
    while True:
        x = int.from_bytes(hashlib.sha256(label + ctr.to_bytes(4, "big")).digest(), "big") % Q
        rhs = (x * x * x + B) % Q
        y = pow(rhs, (Q + 1) // 4, Q)  # Q == 3 mod 4
        if (y * y) % Q == rhs:
            return (x, y if y % 2 == 0 else Q - y)
        ctr += 1


H = hash_to_point(b"pcai/bn254/pedersen-h")  # nothing-up-my-sleeve second generator


def ser(p) -> bytes:
    """Uncompressed 64-byte X||Y, exactly the ecAdd/ecMul precompile encoding (identity = 64 zero bytes)."""
    if p is None:
        return b"\x00" * 64
    x, y = p
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


def ser_hex(p) -> str:
    return "0x" + ser(p).hex()


if __name__ == "__main__":
    assert on_curve(G1) and on_curve(H)
    assert mul(R, G1) is None, "G1 has order R"
    a, b = 12345, 67890
    assert add(mul(a, G1), mul(b, G1)) == mul((a + b) % R, G1), "homomorphism"
    assert len(ser(G1)) == 64 and len(ser(None)) == 64
    print("bn254 G1 self-test -> OK (on curve, order R, homomorphism, 64-byte ser)")
