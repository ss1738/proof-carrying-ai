"""Sigma OR-proof over BN254 G1 with a SHA256 byte-Fiat-Shamir, designed to be verified ON-CHAIN by
SigmaVerifier.sol (ecAdd/ecMul/sha256 precompiles). Same protocol as qedra's zk_core; the only change from the
Python zk_core is the group (BN254 instead of 2048-bit MODP) and a byte-oriented FS (32-byte big-endian words)
so the Solidity verifier can recompute the challenge cheaply.

Running it: self-test (prove+verify in Python) and write onchain/proof.json for the forge test.
"""
from __future__ import annotations

import hashlib
import json
import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import bn254 as bn

R = bn.R
G, H = bn.G1, bn.H


def _b32(x: int) -> bytes:
    return (x % (1 << 256)).to_bytes(32, "big")


def _pt_bytes(p) -> bytes:
    x, y = (0, 0) if p is None else p
    return _b32(x) + _b32(y)


def domain(tag: str, verdict: str) -> bytes:
    return hashlib.sha256(f"pcai/onchain/v1|{tag}|{verdict}".encode()).digest()


def pedersen(m: int, r: int):
    return bn.add(bn.mul(m, G), bn.mul(r, H))


def _Y(C, mi: int):
    return bn.add(C, bn.mul((R - mi % R) % R, G))  # C - mi*G


def challenge(dom: bytes, C, ms, ts) -> int:
    buf = dom + _pt_bytes(G) + _pt_bytes(H) + _pt_bytes(C)
    for mi in ms:
        buf += _b32(mi)
    for t in ts:
        buf += _pt_bytes(t)
    return int.from_bytes(hashlib.sha256(buf).digest(), "big") % R


def prove(ms, m: int, r: int, tag: str, verdict: str):
    ms = list(ms)
    j = ms.index(m)
    n = len(ms)
    C = pedersen(m, r)
    dom = domain(tag, verdict)
    t = [None] * n
    e = [0] * n
    z = [0] * n
    for i in range(n):
        if i == j:
            continue
        e[i], z[i] = secrets.randbelow(R), secrets.randbelow(R)
        Yi = _Y(C, ms[i])
        t[i] = bn.add(bn.mul(z[i], H), bn.mul((R - e[i]) % R, Yi))  # z_i*H - e_i*Y_i
    k = secrets.randbelow(R)
    t[j] = bn.mul(k, H)
    e_total = challenge(dom, C, ms, t)
    e[j] = (e_total - sum(e[i] for i in range(n) if i != j)) % R
    z[j] = (k + e[j] * r) % R
    return C, t, e, z, dom


def verify(ms, C, t, e, z, dom) -> bool:
    ms = list(ms)
    n = len(ms)
    if not (len(t) == len(e) == len(z) == n):
        return False
    if any(not (0 <= v < R) for v in e + z):
        return False
    if challenge(dom, C, ms, t) != sum(e) % R:
        return False
    for i in range(n):
        Yi = _Y(C, ms[i])
        lhs = bn.mul(z[i], H)
        rhs = bn.add(t[i], bn.mul(e[i], Yi))
        if lhs != rhs:
            return False
    return True


if __name__ == "__main__":
    MS, M, TAG, VERDICT = [1, 2, 3], 2, "cert/counterparty", "allow"
    C, t, e, z, dom = prove(MS, M, secrets.randbelow(R), TAG, VERDICT)
    ok = verify(MS, C, t, e, z, dom)
    bad = verify([4, 5, 6], C, t, e, z, dom)
    print(f"onchain OR-proof: honest={'OK' if ok else 'FAIL'} wrong_set={'REJECTED' if not bad else 'ACCEPTED!!'}")

    def hx(v):
        return "0x" + _b32(v).hex()

    out = {
        "domain": "0x" + dom.hex(),
        "ms": [hx(v) for v in MS],
        "Cx": hx(C[0]), "Cy": hx(C[1]),
        "tx": [hx((0 if p is None else p[0])) for p in t],
        "ty": [hx((0 if p is None else p[1])) for p in t],
        "e": [hx(v) for v in e],
        "z": [hx(v) for v in z],
        "Hx": hx(H[0]), "Hy": hx(H[1]),
    }
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "proof.json"), "w") as f:
        json.dump(out, f, indent=2)
    print("wrote onchain/proof.json for the forge test")
    raise SystemExit(0 if ok and not bad else 1)
