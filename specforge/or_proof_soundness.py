"""specforge invariant spec for the Sigma OR-proof (set-membership) in pcai._zkcore.

Proves a committed value is a commitment to ONE member of a public set, in zero
knowledge. Soundness properties that must survive any refactor. Run:
  specforge run specforge/or_proof_soundness.py 40
Wired into .ordeal.toml so a change that breaks membership soundness is caught.
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
for q in (os.path.expanduser("~/agent-guardrail"),
          os.path.expanduser("~/proof-carrying-ai-run/agent-guardrail")):
    if os.path.isdir(q):
        sys.path.insert(0, q); break

from pcai import _zkcore as z          # EC (secp256k1) OR-proof, fast
from pcai._ec import EC

G = EC
TAG = "cert/member"

def _set(rng):
    k = rng.randint(2, 5)
    return tuple(rng.sample(range(1, 4000), k))

def completeness(rng):
    ms = _set(rng); m = rng.choice(ms)
    pf, C = z.prove(G, ms, m, rng.randrange(G.q), "allow", TAG)
    return None if z.verify(G, ms, C, pf, TAG) else "member m=%d in %s verified False" % (m, ms)

def nonmember_set_binding(rng):
    # a proof for m under set MS must NOT verify under a set that excludes m
    ms = _set(rng); m = rng.choice(ms)
    pf, C = z.prove(G, ms, m, rng.randrange(G.q), "allow", TAG)
    ms2 = tuple(x for x in ms if x != m) + (max(ms) + 7,)   # m no longer in the set
    return "proof for m=%d verified under a set excluding it" % m \
        if z.verify(G, ms2, C, pf, TAG) else None

def wrong_tag(rng):
    ms = _set(rng); m = rng.choice(ms)
    pf, C = z.prove(G, ms, m, rng.randrange(G.q), "allow", TAG)
    return "proof verified under a different tag (Fiat-Shamir not binding)" \
        if z.verify(G, ms, C, pf, TAG + "X") else None

def tamper_commitment(rng):
    # a proof is bound to its commitment: verifying against a commitment to a
    # DIFFERENT member of the same set must be rejected.
    ms = _set(rng); m = rng.choice(ms)
    pf, C = z.prove(G, ms, m, rng.randrange(G.q), "allow", TAG)
    others = [x for x in ms if x != m]
    if not others:
        return None
    _, C2 = z.prove(G, ms, rng.choice(others), rng.randrange(G.q), "allow", TAG)
    return "proof verified against a commitment to a different member" \
        if z.verify(G, ms, C2, pf, TAG) else None

def tamper_verdict(rng):
    # the verdict string is bound into the Fiat-Shamir challenge
    ms = _set(rng); m = rng.choice(ms)
    pf, C = z.prove(G, ms, m, rng.randrange(G.q), "allow", TAG)
    bad = z.ZKProof.from_dict({"verdict": pf.verdict + "!", "t": list(pf.t),
                               "e": [str(x) for x in pf.e], "z": [str(x) for x in pf.z]})
    return "proof verified after the verdict string was changed" \
        if z.verify(G, ms, C, bad, TAG) else None

INVARIANTS = [
    {"name": "completeness",       "desc": "a member proof verifies",                    "run": completeness},
    {"name": "set-binding",        "desc": "no verify under a set excluding the member", "run": nonmember_set_binding},
    {"name": "tag-binding",        "desc": "no verify under a different tag",            "run": wrong_tag},
    {"name": "commitment-binding", "desc": "no verify against another member's commitment", "run": tamper_commitment},
    {"name": "verdict-binding",    "desc": "no verify after the verdict is tampered",    "run": tamper_verdict},
]
