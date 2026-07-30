"""specforge invariant spec for the policy DSL / rule engine (policy_dsl.evaluate).

These runtime invariants are exactly what coq/PolicyDSL.v proves axiom-free:
`evaluate = forallb over the rules` (ALLOW iff every rule passes). This is the
property that makes the ZK certificate MEAN something — membership in the allowed
set has to equal compliance. Guarding it at runtime keeps the code aligned with the
proof. Run:  specforge run specforge/policy_dsl_soundness.py 200
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
for q in (os.path.expanduser("~/agent-guardrail"),
          os.path.expanduser("~/proof-carrying-ai-run/agent-guardrail")):
    if os.path.isdir(q):
        sys.path.insert(0, q); break

import policy_dsl as P

TO = ["0xA", "0xB", "0xC", "0xD"]

def _action(rng):
    return {"amount": rng.randint(0, 200), "to": rng.choice(TO)}

def _rule(rng):
    k = rng.randint(0, 2)
    if k == 0: return P.spend_cap(rng.choice([50, 100, 150]))
    if k == 1: return P.allowlist("to", rng.sample(TO, rng.randint(1, 3)))
    return P.denylist("to", rng.sample(TO, rng.randint(1, 2)))

def _policy(rng):
    return [_rule(rng) for _ in range(rng.randint(0, 4))]

def _allow(pol, a):
    return P.evaluate(pol, a)[0] == "ALLOW"

def conjunction_soundness(rng):
    # ALLOW iff every rule's predicate passes (forallb) — the core Coq claim
    pol, a = _policy(rng), _action(rng)
    expected = all(pred(a) for _, pred in pol)
    got = _allow(pol, a)
    return None if got == expected else \
        "verdict ALLOW=%s but preds say %s for action %s" % (got, expected, a)

def any_violation_blocks(rng):
    # if any rule fails, the verdict MUST be BLOCK (no rule is ignored)
    pol, a = _policy(rng), _action(rng)
    if any(not pred(a) for _, pred in pol) and _allow(pol, a):
        return "a rule failed yet the action was ALLOWED: %s" % a
    return None

def monotone_restriction(rng):
    # adding a rule can only RESTRICT: it must never turn a BLOCK into an ALLOW
    pol, a = _policy(rng), _action(rng)
    stricter = pol + [_rule(rng)]
    if _allow(stricter, a) and not _allow(pol, a):
        return "adding a rule turned BLOCK into ALLOW for %s" % a
    return None

def order_independent(rng):
    # conjunction is commutative: the ALLOW/BLOCK verdict must not depend on rule order
    pol, a = _policy(rng), _action(rng)
    shuffled = list(pol); rng.shuffle(shuffled)
    if _allow(pol, a) != _allow(shuffled, a):
        return "verdict changed when the rules were reordered: %s" % a
    return None

def empty_allows(rng):
    # vacuous conjunction: the empty policy allows every action
    a = _action(rng)
    return None if _allow([], a) else "empty policy did not ALLOW %s" % a

INVARIANTS = [
    {"name": "conjunction",      "desc": "ALLOW iff every rule passes (forallb)",     "run": conjunction_soundness},
    {"name": "violation-blocks", "desc": "any failing rule forces BLOCK",             "run": any_violation_blocks},
    {"name": "monotone",         "desc": "adding a rule only restricts (never allows more)", "run": monotone_restriction},
    {"name": "order-independent", "desc": "verdict is independent of rule order",      "run": order_independent},
    {"name": "empty-allows",     "desc": "the empty policy allows everything",         "run": empty_allows},
]
