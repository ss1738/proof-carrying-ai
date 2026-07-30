"""Property-based fuzzing of the certificate engine. Generate random policies (mixed max/min/in rules over
random fields) and random actions, compute compliance independently, and assert the invariants:

  - a compliant action issues a certificate that VERIFIES;
  - a non-compliant action is REFUSED (issue raises);
  - a compliant certificate is rejected under a MUTATED policy (policy binding);
  - tampering any commitment makes it FAIL.

Deterministic (seeded) so CI is stable. Uses nbits=16 + the faster bitwise-or-bulletproofs backends.
Run: python3 tests/test_fuzz.py
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pcai import Certificate, issue
from pcai.certificate import _canonical

random.seed(20260730)

NUM_FIELDS = ["amount", "tokens", "qty"]
CAT = {"tool": ["read", "search", "write", "delete"], "region": ["EU", "UK", "US", "CN"], "tier": ["free", "pro", "ent"]}
NBITS = 16
CAP = 1 << NBITS


def random_policy():
    rules = []
    for f in random.sample(NUM_FIELDS, random.randint(0, 2)):
        if random.random() < 0.7:
            rules.append({"type": "max", "field": f, "limit": random.randint(10, CAP - 1)})
        if random.random() < 0.4:
            rules.append({"type": "min", "field": f, "floor": random.randint(0, 8)})
    for f in random.sample(list(CAT), random.randint(0, 2)):
        vals = CAT[f]
        rules.append({"type": "in", "field": f, "set": random.sample(vals, random.randint(1, len(vals)))})
    if not rules:
        rules.append({"type": "max", "field": "amount", "limit": 1000})
    return {"rules": rules}


def random_action():
    a = {f: random.randint(0, CAP - 1) for f in NUM_FIELDS}
    a.update({f: random.choice(CAT[f]) for f in CAT})
    return a


def compliant(policy, action) -> bool:
    for r in policy["rules"]:
        f = r["field"]
        if r["type"] == "max" and not (0 <= int(action[f]) <= int(r["limit"]) < CAP):
            return False
        if r["type"] == "min" and not (0 <= int(r["floor"]) <= int(action[f]) < CAP):
            return False
        if r["type"] == "in" and str(action[f]) not in r["set"]:
            return False
    return True


def main() -> int:
    key = Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes_raw().hex()
    N = 40
    n_ok = n_refused = 0
    for i in range(N):
        pol, act = random_policy(), random_action()
        kind = random.choice(["bulletproofs", "bitwise"])
        if compliant(pol, act):
            cert = issue(act, pol, key, nbits=NBITS, range_proof=kind, context=f"ctx{i}")
            ok, why = cert.verify(pol, pub, context=f"ctx{i}")
            assert ok, f"[iter {i}] compliant cert failed to verify: {why}\n  policy={pol}\n  action={act}"
            # policy binding: verifying under a mutated policy (tighten a limit / shrink a set) must fail
            mut = {"rules": [dict(r) for r in pol["rules"]]}
            r0 = mut["rules"][0]
            if r0["type"] == "max":
                r0["limit"] = max(0, int(r0["limit"]) - 1)
            elif r0["type"] == "min":
                r0["floor"] = int(r0["floor"]) + 1
            else:
                r0["set"] = r0["set"][:-1] or ["__none__"]
            assert not cert.verify(mut, pub, context=f"ctx{i}")[0], f"[iter {i}] mutated policy verified!"
            # tamper a commitment -> must fail
            t = Certificate.from_json(cert.to_json())
            fld = random.choice(list(t.commitments))
            c = t.commitments[fld]
            t.commitments[fld] = c[:-1] + ("0" if c[-1] != "0" else "1")
            assert not t.verify(pol, pub, context=f"ctx{i}")[0], f"[iter {i}] tampered commitment verified!"
            n_ok += 1
        else:
            try:
                issue(act, pol, key, nbits=NBITS, range_proof=kind)
                assert False, f"[iter {i}] non-compliant action was certified!\n  policy={pol}\n  action={act}"
            except ValueError:
                n_refused += 1

    print(f"  fuzzed {N} random (policy, action) pairs: {n_ok} compliant verified, {n_refused} non-compliant refused")
    print("  invariants held: compliant->verifies, non-compliant->refused, mutated-policy->fails, tamper->fails")
    print("\nPASS: property-based fuzz of the certificate engine.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
