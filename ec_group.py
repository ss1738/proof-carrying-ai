"""An elliptic-curve group (secp256k1) exposing the exact interface qedra's zk_core expects
(op, mul, g, h, q, ser, deser, rand_scalar, eq). Drop-in replacement for the 2048-bit MODP group:
256-bit field instead of 2048-bit, so commitments/proofs are ~8x smaller and scalar mul is far cheaper.

Pure Python, no dependencies. h is a nothing-up-my-sleeve second generator (hash-to-curve of a fixed
label), so its discrete log w.r.t. g is unknown -> Pedersen commitments are binding.
"""
from __future__ import annotations

import hashlib
import secrets

# secp256k1 domain parameters
_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_A = 0
_B = 7
_GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
_GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141  # prime order

Point = tuple  # (x, y) affine, or None for the point at infinity


def _inv_mod_p(x: int) -> int:
    return pow(x % _P, _P - 2, _P)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % _P == 0:
        return None                       # P + (-P) = infinity
    if p == q:
        s = (3 * x1 * x1 + _A) * _inv_mod_p(2 * y1) % _P
    else:
        s = (y2 - y1) * _inv_mod_p(x2 - x1) % _P
    x3 = (s * s - x1 - x2) % _P
    y3 = (s * (x1 - x3) - y1) % _P
    return (x3, y3)


def _mul(k: int, p):
    k %= _N
    r = None
    while k:
        if k & 1:
            r = _add(r, p)
        p = _add(p, p)
        k >>= 1
    return r


def _on_curve(p) -> bool:
    if p is None:
        return True
    x, y = p
    return (y * y - (x * x * x + _A * x + _B)) % _P == 0


def _hash_to_point(label: bytes):
    """Nothing-up-my-sleeve generator: hash label(+counter) to an x, lift to a curve point. p == 3 mod 4
    so a square root is x^((p+1)/4)."""
    ctr = 0
    while True:
        x = int.from_bytes(hashlib.sha256(label + ctr.to_bytes(4, "big")).digest(), "big") % _P
        rhs = (x * x * x + _A * x + _B) % _P
        y = pow(rhs, (_P + 1) // 4, _P)
        if (y * y) % _P == rhs:           # rhs was a quadratic residue -> valid point
            if y % 2:                     # canonicalize to even y
                y = _P - y
            return (x, y)
        ctr += 1


class _ECGroup:
    """Interface-compatible with qedra.zk._MODPGroup: op, mul, g, h, q, ser, deser, eq, rand_scalar."""

    def __init__(self):
        self.g = (_GX, _GY)
        self.h = _hash_to_point(b"acp/zk/v1/pedersen-h/secp256k1")
        self.q = _N

    @staticmethod
    def op(a, b):
        return _add(a, b)

    @staticmethod
    def mul(base, k):
        return _mul(k, base)

    @staticmethod
    def eq(a, b):
        return a == b

    @staticmethod
    def ser(a) -> str:
        if a is None:
            return "00"
        x, y = a
        return ("03" if y & 1 else "02") + f"{x:064x}"   # SEC1 compressed: 33 bytes

    @staticmethod
    def deser(s: str):
        if s == "00":
            return None
        prefix, x = s[:2], int(s[2:], 16)
        rhs = (x * x * x + _A * x + _B) % _P
        y = pow(rhs, (_P + 1) // 4, _P)
        if (y * y) % _P != rhs:
            raise ValueError("point not on curve")
        if (y & 1) != (prefix == "03"):
            y = _P - y
        return (x, y)

    def rand_scalar(self) -> int:
        return secrets.randbelow(self.q - 1) + 1


EC = _ECGroup()


if __name__ == "__main__":
    assert _on_curve(EC.g) and _on_curve(EC.h), "generators must be on the curve"
    assert EC.mul(EC.g, _N) is None, "g has order n"
    k = EC.rand_scalar()
    assert EC.eq(EC.deser(EC.ser(EC.mul(EC.g, k))), EC.mul(EC.g, k)), "ser/deser roundtrip"
    # homomorphism sanity: a*G + b*G == (a+b)*G
    a, b = EC.rand_scalar(), EC.rand_scalar()
    assert EC.eq(EC.op(EC.mul(EC.g, a), EC.mul(EC.g, b)), EC.mul(EC.g, (a + b) % _N))
    print("ec_group secp256k1 self-test -> OK (generators on curve, order n, ser/deser, homomorphism)")
