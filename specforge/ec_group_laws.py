"""specforge invariant spec for the secp256k1 group (pcai._ec.EC).

The group-law axioms every ZK proof above silently depends on. If op/mul ever drift
(a bad reduction, a wrong doubling case), these break loudly instead of surfacing as
a mysterious proof failure later. Run:  specforge run specforge/ec_group_laws.py 100
"""
import os, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, REPO)
for q in (os.path.expanduser("~/agent-guardrail"),
          os.path.expanduser("~/proof-carrying-ai-run/agent-guardrail")):
    if os.path.isdir(q):
        sys.path.insert(0, q); break

from pcai._ec import EC

Q = EC.q
P_FIELD = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F  # secp256k1 prime
B = 7
O = None  # point at infinity (identity)

def _pt(rng):
    return EC.mul(EC.g, rng.randrange(1, Q))   # nonzero scalar -> non-identity point

def commutativity(rng):
    P, R = _pt(rng), _pt(rng)
    return None if EC.eq(EC.op(P, R), EC.op(R, P)) else "P+Q != Q+P"

def associativity(rng):
    P, R, S = _pt(rng), _pt(rng), _pt(rng)
    return None if EC.eq(EC.op(EC.op(P, R), S), EC.op(P, EC.op(R, S))) else "(P+Q)+R != P+(Q+R)"

def identity(rng):
    P = _pt(rng)
    return None if EC.eq(EC.op(P, O), P) and EC.eq(EC.op(O, P), P) else "P+O != P"

def order_annihilates(rng):
    # secp256k1 has prime order q: q*P = O for every point P
    P = _pt(rng)
    return None if EC.eq(EC.mul(P, Q), O) else "q*P != O (wrong group order)"

def scalar_distributive(rng):
    # (a+b)*P == a*P + b*P
    P = _pt(rng); a = rng.randrange(Q); b = rng.randrange(Q)
    lhs = EC.mul(P, (a + b) % Q)
    rhs = EC.op(EC.mul(P, a), EC.mul(P, b))
    return None if EC.eq(lhs, rhs) else "(a+b)P != aP+bP for a=%d b=%d" % (a, b)

def on_curve(rng):
    # every point produced by op/mul must satisfy y^2 = x^3 + 7 (mod p)
    P = EC.op(_pt(rng), _pt(rng))
    if P is O:
        return None
    x, y = P
    return None if (y * y - (x * x * x + B)) % P_FIELD == 0 else "point off curve: %s" % (P,)

INVARIANTS = [
    {"name": "commutativity",      "desc": "P+Q == Q+P",                  "run": commutativity},
    {"name": "associativity",      "desc": "(P+Q)+R == P+(Q+R)",          "run": associativity},
    {"name": "identity",           "desc": "P+O == P",                    "run": identity},
    {"name": "order-annihilates",  "desc": "q*P == O (prime order)",      "run": order_annihilates},
    {"name": "scalar-distributive","desc": "(a+b)P == aP+bP",             "run": scalar_distributive},
    {"name": "on-curve",           "desc": "op/mul outputs stay on curve", "run": on_curve},
]
