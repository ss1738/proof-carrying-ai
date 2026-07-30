"""specforge invariant spec for the Bulletproofs range argument (pcai._bulletproof).

The log-size range proof (Bunz et al. 2018) over secp256k1: prove a committed value
is in range / <= a cap, without revealing it. Soundness properties that must hold
through any refactor of the IPA or the range gadget. Run:
  specforge run specforge/bulletproof_soundness.py 15
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
for q in (os.path.expanduser("~/agent-guardrail"),
          os.path.expanduser("~/proof-carrying-ai-run/agent-guardrail")):
    if os.path.isdir(q):
        sys.path.insert(0, q); break

from pcai import _bulletproof as B

NBITS = 8
Q = B.Q

def completeness_range(rng):
    v = rng.randrange(0, 1 << NBITS)
    V, pf = B.range_prove(v, rng.randrange(Q), NBITS)
    return None if B.range_verify(V, pf) else "range proof for v=%d verified False" % v

def completeness_le(rng):
    cap = rng.randrange(1, 1 << NBITS)
    a = rng.randrange(0, cap + 1)
    C, pf = B.prove_le(a, rng.randrange(Q), cap, NBITS)
    return None if B.verify_le(C, cap, pf) else "prove_le a=%d cap=%d verified False" % (a, cap)

def false_statement_le(rng):
    # amount > cap must be unprovable OR unverifiable, never both accepted
    cap = rng.randrange(0, (1 << NBITS) - 1)
    a = rng.randrange(cap + 1, 1 << NBITS)
    try:
        C, pf = B.prove_le(a, rng.randrange(Q), cap, NBITS)
    except Exception:
        return None
    return "PROVED+VERIFIED amount=%d > cap=%d" % (a, cap) if B.verify_le(C, cap, pf) else None

def tamper_commitment(rng):
    # a proof is bound to its commitment: verifying against a commitment to a
    # different amount must be rejected.
    cap = rng.randrange(1, 1 << NBITS)
    a = rng.randrange(0, cap + 1)
    C, pf = B.prove_le(a, rng.randrange(Q), cap, NBITS)
    a2 = a + 1 if a + 1 <= cap else (a - 1 if a >= 1 else a)
    if a2 == a:
        return None
    C2, _ = B.prove_le(a2, rng.randrange(Q), cap, NBITS)
    return "proof verified against a commitment to a different amount" if B.verify_le(C2, cap, pf) else None

def cap_is_binding(rng):
    # a prove_le proof for `cap` must not verify against a tighter cap' < amount
    cap = rng.randrange(2, 1 << NBITS)
    a = rng.randrange(1, cap + 1)
    C, pf = B.prove_le(a, rng.randrange(Q), cap, NBITS)
    tighter = a - 1
    return "proof for cap=%d verified against tighter=%d < amount=%d" % (cap, tighter, a) \
        if (tighter >= 0 and B.verify_le(C, tighter, pf)) else None

INVARIANTS = [
    {"name": "completeness-range", "desc": "an in-range value verifies",              "run": completeness_range},
    {"name": "completeness-le",    "desc": "a valid amount<=cap proof verifies",      "run": completeness_le},
    {"name": "false-stmt-guard",   "desc": "amount>cap can't be proved+verified",     "run": false_statement_le},
    {"name": "commitment-binding", "desc": "no verify against a different commitment", "run": tamper_commitment},
    {"name": "cap-binding",        "desc": "no verify against a tighter cap",          "run": cap_is_binding},
]
