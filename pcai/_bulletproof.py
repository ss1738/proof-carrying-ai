"""A Bulletproofs range proof (Bunz et al. 2018) over secp256k1 (ec_group.EC), replacing the linear
bit-decomposition range proof (zk_range.py) with a LOGARITHMIC one: the proof is O(log2 n) group elements
instead of O(n). This is the spend_cap circuit made succinct.

Built bottom-up: first the inner-product argument (IPA), the log-size core; then the range proof on top.
Prototype crypto (Fiat-Shamir in ROM); the point here is the size/asymptotics, measured against zk_range.
"""
from __future__ import annotations

import hashlib
from ._ec import EC, _hash_to_point

Q = EC.q


def inv(x: int) -> int:
    return pow(x % Q, Q - 2, Q)


def padd(*pts):
    acc = None
    for p in pts:
        acc = EC.op(acc, p)
    return acc


def multiexp(scalars, points):
    acc = None
    for s, P in zip(scalars, points):
        acc = EC.op(acc, EC.mul(P, s % Q))
    return acc


def vec_ip(a, b) -> int:
    return sum(x * y for x, y in zip(a, b)) % Q


def _fs(*parts) -> int:
    h = hashlib.sha256(b"bp/fiat-shamir/v1|")
    for p in parts:
        h.update((EC.ser(p) if isinstance(p, tuple) or p is None else str(p)).encode())
        h.update(b"|")
    return int.from_bytes(h.digest(), "big") % Q or 1


# ---- generators (nothing-up-my-sleeve) ----
def gens(n: int):
    g = [_hash_to_point(f"bp/g/{i}".encode()) for i in range(n)]
    h = [_hash_to_point(f"bp/h/{i}".encode()) for i in range(n)]
    u = _hash_to_point(b"bp/u")
    hb = _hash_to_point(b"bp/hblind")
    return g, h, u, hb


# ---- inner-product argument: prove P = <a,g> + <b,h> + <a,b> u, in O(log n) ----
def ipa_prove(g, h, u, a, b, seed):
    g, h, a, b = g[:], h[:], a[:], b[:]
    Ls, Rs = [], []
    e = seed
    while len(a) > 1:
        m = len(a) // 2
        aL, aR, bL, bR = a[:m], a[m:], b[:m], b[m:]
        gL, gR, hL, hR = g[:m], g[m:], h[:m], h[m:]
        L = padd(multiexp(aL, gR), multiexp(bR, hL), EC.mul(u, vec_ip(aL, bR)))
        R = padd(multiexp(aR, gL), multiexp(bL, hR), EC.mul(u, vec_ip(aR, bL)))
        Ls.append(L)
        Rs.append(R)
        e = _fs(e, L, R)
        x, xi = e, inv(e)
        a = [(aL[i] * x + aR[i] * xi) % Q for i in range(m)]
        b = [(bL[i] * xi + bR[i] * x) % Q for i in range(m)]
        g = [padd(EC.mul(gL[i], xi), EC.mul(gR[i], x)) for i in range(m)]
        h = [padd(EC.mul(hL[i], x), EC.mul(hR[i], xi)) for i in range(m)]
    return Ls, Rs, a[0], b[0]


def ipa_verify(g, h, u, P, Ls, Rs, a, b, seed):
    g, h = g[:], h[:]
    e = seed
    for L, R in zip(Ls, Rs):
        e = _fs(e, L, R)
        x = e
        x2, xi2 = (x * x) % Q, inv((x * x) % Q)
        m = len(g) // 2
        gL, gR, hL, hR = g[:m], g[m:], h[:m], h[m:]
        xi = inv(x)
        g = [padd(EC.mul(gL[i], xi), EC.mul(gR[i], x)) for i in range(m)]
        h = [padd(EC.mul(hL[i], x), EC.mul(hR[i], xi)) for i in range(m)]
        P = padd(EC.mul(L, x2), P, EC.mul(R, xi2))
    rhs = padd(EC.mul(g[0], a), EC.mul(h[0], b), EC.mul(u, (a * b) % Q))
    return P == rhs


def _seed(P, u, n):
    return _fs("ipa-v1", P, u, n)


# ---- Bulletproofs range proof: prove a committed v lies in [0, 2^n), in O(log n) size ----
def range_prove(v: int, gamma: int, n: int):
    g, h, u, hb = gens(n)
    if not (0 <= v < (1 << n)):
        raise ValueError("cannot prove a false statement: need 0 <= v < 2^n")
    V = padd(EC.mul(EC.g, v), EC.mul(hb, gamma))                       # Pedersen commit to v
    aL = [(v >> i) & 1 for i in range(n)]
    aR = [(aL[i] - 1) % Q for i in range(n)]
    alpha = _rand()
    A = padd(EC.mul(hb, alpha), multiexp(aL, g), multiexp(aR, h))
    sL, sR = [_rand() for _ in range(n)], [_rand() for _ in range(n)]
    rho = _rand()
    S = padd(EC.mul(hb, rho), multiexp(sL, g), multiexp(sR, h))
    y = _fs("y", A, S)
    z = _fs("z", A, S, y)
    yn = [pow(y, i, Q) for i in range(n)]
    twos = [(1 << i) % Q for i in range(n)]
    # l(X) = (aL - z) + sL X ; r(X) = yn o (aR + z + sR X) + z^2 2^n
    l0 = [(aL[i] - z) % Q for i in range(n)]
    l1 = sL[:]
    r0 = [(yn[i] * ((aR[i] + z) % Q) + z * z % Q * twos[i]) % Q for i in range(n)]
    r1 = [(yn[i] * sR[i]) % Q for i in range(n)]
    t1 = (vec_ip(l0, r1) + vec_ip(l1, r0)) % Q
    t2 = vec_ip(l1, r1)
    tau1, tau2 = _rand(), _rand()
    T1 = padd(EC.mul(EC.g, t1), EC.mul(hb, tau1))
    T2 = padd(EC.mul(EC.g, t2), EC.mul(hb, tau2))
    x = _fs("x", T1, T2)
    l = [(l0[i] + l1[i] * x) % Q for i in range(n)]
    r = [(r0[i] + r1[i] * x) % Q for i in range(n)]
    t_hat = vec_ip(l, r)
    tau_x = (tau2 * x % Q * x + tau1 * x + z * z % Q * gamma) % Q
    mu = (alpha + rho * x) % Q
    # IPA over g and h' = y^{-i} o h, proving <l,r> = t_hat
    yinv = inv(y)
    hp = [EC.mul(h[i], pow(yinv, i, Q)) for i in range(n)]
    seed = _fs("bp-range-ipa", A, S, T1, T2, x, t_hat, mu, tau_x)
    Ls, Rs, af, bf = ipa_prove(g, hp, u, l, r, seed)
    return V, {"n": n, "A": EC.ser(A), "S": EC.ser(S), "T1": EC.ser(T1), "T2": EC.ser(T2),
               "tau_x": str(tau_x), "mu": str(mu), "t_hat": str(t_hat),
               "L": [EC.ser(p) for p in Ls], "R": [EC.ser(p) for p in Rs],
               "a": str(af), "b": str(bf)}


def range_verify(V, proof: dict) -> bool:
    n = proof["n"]
    if not isinstance(n, int) or not (1 <= n <= 64):
        return False  # a range near the group order (~2^256) is vacuous; a real bound is small
    g, h, u, hb = gens(n)
    A, S = EC.deser(proof["A"]), EC.deser(proof["S"])
    T1, T2 = EC.deser(proof["T1"]), EC.deser(proof["T2"])
    tau_x, mu, t_hat = int(proof["tau_x"]), int(proof["mu"]), int(proof["t_hat"])
    y = _fs("y", A, S)
    z = _fs("z", A, S, y)
    x = _fs("x", T1, T2)
    yn = [pow(y, i, Q) for i in range(n)]
    twos = [(1 << i) % Q for i in range(n)]
    sum_yn = sum(yn) % Q
    sum_2n = sum(twos) % Q
    z2 = z * z % Q
    delta = ((z - z2) * sum_yn - z2 * z % Q * sum_2n) % Q
    # (a) t_hat consistency: g^t_hat h^tau_x == V^{z^2} g^delta T1^x T2^{x^2}
    lhs = padd(EC.mul(EC.g, t_hat), EC.mul(hb, tau_x))
    rhs = padd(EC.mul(V, z2), EC.mul(EC.g, delta), EC.mul(T1, x), EC.mul(T2, x * x % Q))
    if lhs != rhs:
        return False
    # (b) reconstruct P for the IPA and verify
    yinv = inv(y)
    hp = [EC.mul(h[i], pow(yinv, i, Q)) for i in range(n)]
    sum_g = padd(*g)
    hexp = [(z * yn[i] + z2 * twos[i]) % Q for i in range(n)]
    P_ipa = padd(A, EC.mul(S, x), EC.mul(sum_g, (-z) % Q), multiexp(hexp, hp), EC.mul(hb, (-mu) % Q))
    P_hat = padd(P_ipa, EC.mul(u, t_hat))
    seed = _fs("bp-range-ipa", A, S, T1, T2, x, t_hat, mu, tau_x)
    Ls = [EC.deser(p) for p in proof["L"]]
    Rs = [EC.deser(p) for p in proof["R"]]
    return ipa_verify(g, hp, u, P_hat, Ls, Rs, int(proof["a"]), int(proof["b"]), seed)


def _rand() -> int:
    import secrets
    return secrets.randbelow(Q)




# ---- spend_cap wrappers: prove a committed amount <= cap with a Bulletproofs range proof on (cap - amount).
#      C_amount and the Bulletproofs commitment V share the blinding generator hb, so the verifier can
#      recompute V = cap*G - C_amount and range-verify it. Same API shape as _range.prove_le/verify_le. ----
_HB = _hash_to_point(b"bp/hblind")


def _commit_amount(amount: int, r_a: int):
    return padd(EC.mul(EC.g, amount % Q), EC.mul(_HB, r_a % Q))


def prove_le(amount: int, r_a: int, cap: int, nbits: int):
    if not (0 <= amount <= cap < (1 << nbits)):
        raise ValueError("cannot prove a false statement: need 0 <= amount <= cap < 2^nbits")
    _V, proof = range_prove(cap - amount, (-r_a) % Q, nbits)   # V = (cap-amount)*G - r_a*hb == cap*G - C_amount
    return _commit_amount(amount, r_a), proof


def verify_le(C_amount, cap: int, proof: dict) -> bool:
    V = padd(EC.mul(EC.g, cap % Q), EC.mul(C_amount, Q - 1))    # cap*G - C_amount
    try:
        return range_verify(V, proof)
    except (ValueError, KeyError, TypeError):
        return False


def prove_ge(value: int, r: int, floor: int, nbits: int):
    """Prove a committed value >= floor (0 <= floor <= value < 2^nbits). Returns (C_value, proof).
    C_value shares the blinding generator hb with the Bulletproofs commitment, so the verifier recomputes
    V = C_value - floor*G and range-checks (value - floor) in [0, 2^n)."""
    if not (0 <= floor <= value < (1 << nbits)):
        raise ValueError("cannot prove a false statement: need 0 <= floor <= value < 2^nbits")
    _V, proof = range_prove(value - floor, r % Q, nbits)   # V = (value-floor)*G + r*hb == C_value - floor*G
    return _commit_amount(value, r), proof


def verify_ge(C_value, floor: int, proof: dict) -> bool:
    V = padd(C_value, EC.mul(EC.g, (Q - floor % Q) % Q))    # C_value - floor*G
    try:
        return range_verify(V, proof)
    except (ValueError, KeyError, TypeError):
        return False
