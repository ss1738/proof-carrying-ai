"""Bulletproofs range proof over BN254 G1 (the curve Ethereum has precompiles for), with a SHA256 byte
Fiat-Shamir (64-byte X||Y points, 32-byte scalars) so a Solidity verifier could recompute the transcript.
Same protocol as bulletproof.py (secp256k1); this is the on-chain-curve instantiation.

Purpose here: a working, self-verified BN254 Bulletproofs prover, and a MEASURED calldata comparison against
the on-chain bit-decomposition range proof (range_proof.json). On-chain, Bulletproofs' win is calldata size
(a log-size proof), since verification still touches all n generators (an O(n) multiexp).
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
G = bn.G1


def inv(x: int) -> int:
    return pow(x % R, R - 2, R)


def smul(P, k: int):
    return bn.mul(k % R, P)


def padd(*pts):
    acc = None
    for p in pts:
        acc = bn.add(acc, p)
    return acc


def multiexp(scalars, points):
    acc = None
    for s, P in zip(scalars, points):
        acc = bn.add(acc, bn.mul(s % R, P))
    return acc


def vec_ip(a, b) -> int:
    return sum(x * y for x, y in zip(a, b)) % R


def _fs(*parts) -> int:
    h = hashlib.sha256(b"pcai/bp-bn254/v1|")
    for p in parts:
        if isinstance(p, tuple) or p is None:
            h.update(bn.ser(p))                 # 64-byte X||Y
        elif isinstance(p, int):
            h.update(p.to_bytes(32, "big"))
        else:
            h.update(str(p).encode())
        h.update(b"|")
    return int.from_bytes(h.digest(), "big") % R or 1


def gens(n: int):
    g = [bn.hash_to_point(f"pcai/bp/g/{i}".encode()) for i in range(n)]
    h = [bn.hash_to_point(f"pcai/bp/h/{i}".encode()) for i in range(n)]
    return g, h, bn.hash_to_point(b"pcai/bp/u"), bn.hash_to_point(b"pcai/bp/hblind")


def ipa_prove(g, h, u, a, b, seed):
    g, h, a, b = g[:], h[:], a[:], b[:]
    Ls, Rs = [], []
    e = seed
    while len(a) > 1:
        m = len(a) // 2
        aL, aR, bL, bR = a[:m], a[m:], b[:m], b[m:]
        gL, gR, hL, hR = g[:m], g[m:], h[:m], h[m:]
        L = padd(multiexp(aL, gR), multiexp(bR, hL), smul(u, vec_ip(aL, bR)))
        Rp = padd(multiexp(aR, gL), multiexp(bL, hR), smul(u, vec_ip(aR, bL)))
        Ls.append(L)
        Rs.append(Rp)
        e = _fs(e, L, Rp)
        x, xi = e, inv(e)
        a = [(aL[i] * x + aR[i] * xi) % R for i in range(m)]
        b = [(bL[i] * xi + bR[i] * x) % R for i in range(m)]
        g = [padd(smul(gL[i], xi), smul(gR[i], x)) for i in range(m)]
        h = [padd(smul(hL[i], x), smul(hR[i], xi)) for i in range(m)]
    return Ls, Rs, a[0], b[0]


def ipa_verify(g, h, u, P, Ls, Rs, a, b, seed):
    g, h = g[:], h[:]
    e = seed
    for L, Rp in zip(Ls, Rs):
        e = _fs(e, L, Rp)
        x = e
        x2, xi2 = (x * x) % R, inv((x * x) % R)
        xi = inv(x)
        m = len(g) // 2
        gL, gR, hL, hR = g[:m], g[m:], h[:m], h[m:]
        g = [padd(smul(gL[i], xi), smul(gR[i], x)) for i in range(m)]
        h = [padd(smul(hL[i], x), smul(hR[i], xi)) for i in range(m)]
        P = padd(smul(L, x2), P, smul(Rp, xi2))
    return P == padd(smul(g[0], a), smul(h[0], b), smul(u, (a * b) % R))


def range_prove(v: int, gamma: int, n: int):
    g, h, u, hb = gens(n)
    if not (0 <= v < (1 << n)):
        raise ValueError("need 0 <= v < 2^n")
    V = padd(smul(G, v), smul(hb, gamma))
    aL = [(v >> i) & 1 for i in range(n)]
    aR = [(aL[i] - 1) % R for i in range(n)]
    alpha = secrets.randbelow(R)
    A = padd(smul(hb, alpha), multiexp(aL, g), multiexp(aR, h))
    sL, sR = [secrets.randbelow(R) for _ in range(n)], [secrets.randbelow(R) for _ in range(n)]
    rho = secrets.randbelow(R)
    S = padd(smul(hb, rho), multiexp(sL, g), multiexp(sR, h))
    y = _fs("y", A, S)
    z = _fs("z", A, S, y)
    yn = [pow(y, i, R) for i in range(n)]
    twos = [(1 << i) % R for i in range(n)]
    z2 = z * z % R
    l0 = [(aL[i] - z) % R for i in range(n)]
    l1 = sL[:]
    r0 = [(yn[i] * ((aR[i] + z) % R) + z2 * twos[i]) % R for i in range(n)]
    r1 = [(yn[i] * sR[i]) % R for i in range(n)]
    t1 = (vec_ip(l0, r1) + vec_ip(l1, r0)) % R
    t2 = vec_ip(l1, r1)
    tau1, tau2 = secrets.randbelow(R), secrets.randbelow(R)
    T1 = padd(smul(G, t1), smul(hb, tau1))
    T2 = padd(smul(G, t2), smul(hb, tau2))
    x = _fs("x", T1, T2)
    l = [(l0[i] + l1[i] * x) % R for i in range(n)]
    r = [(r0[i] + r1[i] * x) % R for i in range(n)]
    t_hat = vec_ip(l, r)
    tau_x = (tau2 * x % R * x + tau1 * x + z2 * gamma) % R
    mu = (alpha + rho * x) % R
    yinv = inv(y)
    hp = [smul(h[i], pow(yinv, i, R)) for i in range(n)]
    seed = _fs("bp-range-ipa", A, S, T1, T2, x, t_hat, mu, tau_x)
    Ls, Rs, af, bf = ipa_prove(g, hp, u, l, r, seed)
    return V, {"n": n, "A": bn.ser_hex(A), "S": bn.ser_hex(S), "T1": bn.ser_hex(T1), "T2": bn.ser_hex(T2),
               "tau_x": str(tau_x), "mu": str(mu), "t_hat": str(t_hat),
               "L": [bn.ser_hex(p) for p in Ls], "R": [bn.ser_hex(p) for p in Rs],
               "a": str(af), "b": str(bf)}


def _deser(hexs):
    b = bytes.fromhex(hexs[2:])
    x, y = int.from_bytes(b[:32], "big"), int.from_bytes(b[32:], "big")
    return None if (x == 0 and y == 0) else (x, y)


def range_verify(V, proof) -> bool:
    n = proof["n"]
    g, h, u, hb = gens(n)
    A, S = _deser(proof["A"]), _deser(proof["S"])
    T1, T2 = _deser(proof["T1"]), _deser(proof["T2"])
    tau_x, mu, t_hat = int(proof["tau_x"]), int(proof["mu"]), int(proof["t_hat"])
    y = _fs("y", A, S)
    z = _fs("z", A, S, y)
    x = _fs("x", T1, T2)
    yn = [pow(y, i, R) for i in range(n)]
    twos = [(1 << i) % R for i in range(n)]
    z2 = z * z % R
    delta = ((z - z2) * sum(yn) - z2 * z % R * sum(twos)) % R
    lhs = padd(smul(G, t_hat), smul(hb, tau_x))
    rhs = padd(smul(V, z2), smul(G, delta), smul(T1, x), smul(T2, x * x % R))
    if lhs != rhs:
        return False
    yinv = inv(y)
    hp = [smul(h[i], pow(yinv, i, R)) for i in range(n)]
    hexp = [(z * yn[i] + z2 * twos[i]) % R for i in range(n)]
    P_ipa = padd(A, smul(S, x), smul(padd(*g), (-z) % R), multiexp(hexp, hp), smul(hb, (-mu) % R))
    P_hat = padd(P_ipa, smul(u, t_hat))
    seed = _fs("bp-range-ipa", A, S, T1, T2, x, t_hat, mu, tau_x)
    Ls = [_deser(p) for p in proof["L"]]
    Rs = [_deser(p) for p in proof["R"]]
    return ipa_verify(g, hp, u, P_hat, Ls, Rs, int(proof["a"]), int(proof["b"]), seed)


if __name__ == "__main__":
    rok = True
    for n, v in ((16, 750), (32, 1_000_000)):
        V, pf = range_prove(v, secrets.randbelow(R), n)
        good = range_verify(V, pf)
        Vwrong = padd(smul(G, v + 1), smul(bn.hash_to_point(b"pcai/bp/hblind"), secrets.randbelow(R)))
        bad = range_verify(Vwrong, pf)
        rok = rok and good and not bad
        npts = 4 + 2 * len(pf["L"])
        print(f"  BN254 BP n={n:2d} v={v}: honest={'OK' if good else 'FAIL'} wrongV={'REJECTED' if not bad else 'ACCEPTED!!'} "
              f"| {npts} points + 3 scalars")

    # calldata comparison vs the on-chain bit-decomposition range proof (if it has been generated)
    here = os.path.dirname(os.path.abspath(__file__))
    bd_path = os.path.join(here, "range_proof.json")
    if os.path.exists(bd_path):
        _, pf16 = range_prove(750, secrets.randbelow(R), 16)
        bp_bytes = 64 * (4 + 2 * len(pf16["L"])) + 32 * 3  # points 64B + 3 scalars 32B (raw calldata)
        bd = json.load(open(bd_path))
        bd_bytes = 64 * (1 + 2 * len(bd["bitCx"])) + 32 * (5 * len(bd["bitCx"]) + 1)
        print(f"\ncalldata (raw, n=16): Bulletproofs ~{bp_bytes} B  vs  bit-decomposition ~{bd_bytes} B  "
              f"(~{bd_bytes / bp_bytes:.1f}x smaller)")
        print("on-chain, this is the WIN: proof calldata. Verify compute stays O(n) (multiexp over n gens).")
    raise SystemExit(0 if rok else 1)
