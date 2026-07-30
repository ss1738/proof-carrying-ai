"""specforge invariant spec for the zk_range range proof (amount <= limit, in ZK).

Soundness properties that must hold no matter how the code is refactored. Run with:
  specforge run specforge/zk_range_soundness.py 300
Wired into .ordeal.toml so any change that breaks a property is caught on every task.
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
for q in (os.path.expanduser("~/agent-guardrail"),
          os.path.expanduser("~/proof-carrying-ai-run/agent-guardrail")):
    if os.path.isdir(q):
        sys.path.insert(0, q); break

import zk_range
from ec_group import EC   # secp256k1: ~8x faster than MODP; soundness is group-independent

G = EC
NBITS = 8    # soundness is nbits-independent; small keeps the oracle fast enough for every task

def _valid(rng):
    limit = rng.randrange(1, 1 << NBITS)
    amount = rng.randrange(0, limit + 1)      # 0 <= amount <= limit
    return amount, limit, rng.randrange(G.q)

def completeness(rng):
    a, lim, r = _valid(rng)
    C, pf = zk_range.prove_le(a, r, lim, NBITS, group=G)
    return None if zk_range.verify_le(C, lim, pf, group=G) else \
        "amount=%d limit=%d verified False (should accept)" % (a, lim)

def false_statement_guarded(rng):
    # amount > limit must be either unprovable OR unverifiable — never both accepted
    lim = rng.randrange(0, (1 << NBITS) - 1)
    a = rng.randrange(lim + 1, 1 << NBITS)    # a > lim
    r = rng.randrange(G.q)
    try:
        C, pf = zk_range.prove_le(a, r, lim, NBITS, group=G)
    except ValueError:
        return None                            # correctly refused a false statement
    return "PROVED+VERIFIED false amount=%d > limit=%d" % (a, lim) \
        if zk_range.verify_le(C, lim, pf, group=G) else None

def tamper_rejected(rng):
    # a proof is bound to its commitment: verifying it against a commitment to a
    # DIFFERENT amount (group-agnostic tamper) must be rejected.
    a, lim, r = _valid(rng)
    C, pf = zk_range.prove_le(a, r, lim, NBITS, group=G)
    other = (a + 1) if a + 1 <= lim else (a - 1 if a >= 1 else a)
    if other == a:
        return None  # degenerate (lim==0), skip
    C_other = zk_range.commit(other, r, G)
    return "proof verified against a commitment to a different amount (%d vs %d)" % (other, a) \
        if zk_range.verify_le(C_other, lim, pf, group=G) else None

def bound_is_binding(rng):
    # a proof for `limit` must not verify against a tighter limit' < amount
    lim = rng.randrange(2, 1 << NBITS)
    a = rng.randrange(1, lim + 1)
    r = rng.randrange(G.q)
    C, pf = zk_range.prove_le(a, r, lim, NBITS, group=G)
    tighter = a - 1                            # claim "amount <= a-1" is false
    return "proof for limit=%d verified against tighter=%d < amount=%d" % (lim, tighter, a) \
        if zk_range.verify_le(C, tighter, pf, group=G) else None

INVARIANTS = [
    {"name": "completeness",     "desc": "a valid range proof verifies",              "run": completeness},
    {"name": "false-stmt-guard", "desc": "amount>limit can't be proved+verified",     "run": false_statement_guarded},
    {"name": "tamper-rejected",  "desc": "a tampered commitment is rejected",          "run": tamper_rejected},
    {"name": "bound-binding",    "desc": "a proof doesn't verify a tighter limit",     "run": bound_is_binding},
]
