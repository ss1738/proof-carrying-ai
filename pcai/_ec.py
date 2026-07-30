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


# --- Jacobian coordinates (X,Y,Z), affine (x,y)=(X/Z^2, Y/Z^3), Z=0 = identity; a=0 curve. One field
#     inversion per scalar-mul (at _to_affine) instead of one per point-add -- the measured bottleneck. ---
def _jac_double(P):
    X, Y, Z = P
    if Z == 0:
        return (1, 1, 0)
    A = (X * X) % _P
    B = (Y * Y) % _P
    C = (B * B) % _P
    D = (2 * ((X + B) * (X + B) - A - C)) % _P
    E = (3 * A) % _P
    F = (E * E) % _P
    X3 = (F - 2 * D) % _P
    Y3 = (E * (D - X3) - 8 * C) % _P
    Z3 = (2 * Y * Z) % _P
    return (X3, Y3, Z3)


def _jac_add(P, Q):
    if P[2] == 0:
        return Q
    if Q[2] == 0:
        return P
    X1, Y1, Z1 = P
    X2, Y2, Z2 = Q
    Z1Z1 = (Z1 * Z1) % _P
    Z2Z2 = (Z2 * Z2) % _P
    U1 = (X1 * Z2Z2) % _P
    U2 = (X2 * Z1Z1) % _P
    S1 = (Y1 * Z2 * Z2Z2) % _P
    S2 = (Y2 * Z1 * Z1Z1) % _P
    if U1 == U2:
        return _jac_double(P) if S1 == S2 else (1, 1, 0)
    H = (U2 - U1) % _P
    HH = (H * H) % _P
    HHH = (H * HH) % _P
    Rr = (S2 - S1) % _P
    V = (U1 * HH) % _P
    X3 = (Rr * Rr - HHH - 2 * V) % _P
    Y3 = (Rr * (V - X3) - S1 * HHH) % _P
    Z3 = (H * Z1 * Z2) % _P
    return (X3, Y3, Z3)


def _to_affine(P):
    if P[2] == 0:
        return None
    zi = _inv_mod_p(P[2])
    zi2 = (zi * zi) % _P
    return ((P[0] * zi2) % _P, (P[1] * zi2 * zi) % _P)


def _add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    return _to_affine(_jac_add((p[0], p[1], 1), (q[0], q[1], 1)))


def _mul(k: int, p):
    if p is None:
        return None
    k %= _N
    if k == 0:
        return None
    acc = (1, 1, 0)
    cur = (p[0], p[1], 1)
    while k:
        if k & 1:
            acc = _jac_add(acc, cur)
        cur = _jac_double(cur)
        k >>= 1
    return _to_affine(acc)


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
