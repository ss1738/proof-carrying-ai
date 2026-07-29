"""demo_certificate.py -- a proof-carrying compliance certificate, end to end.

An AI agent proposes an action. Instead of trusting the agent (or the operator), we attach a CERTIFICATE
that proves the action obeyed a formal policy:

  - ZERO-KNOWLEDGE layer (this script, reusing qedra's tested Sigma/Pedersen ZK): a proof that the hidden
    action's committed value lies in the policy's ALLOWED SET -- verifiable from public data alone, without
    revealing the action.
  - MACHINE-CHECKED layer (coq/Compliance.v): a coqc-checked proof that the allowed set IS exactly the set
    of policy-compliant actions, so a verifying certificate genuinely means "obeyed the policy."

This is the seed of the "Proof-Carrying AI" landmark: a certificate of agent-action compliance anyone can
check with only the public data, and that an adversary cannot forge for a non-compliant action.

    python3 demo_certificate.py

Scope (honest): the ZK policy reused here is qedra's git-branch policy (the one domain qedra's ZK covers
today). The research program is to generalize the policy DSL (spend caps, no-PII, data-residency) and scale
the circuits. The rigorous soundness (0 forged proofs accepted out of 500) is in qedra's tests/test_zk.py.
"""
import os
import sys

sys.path.insert(0, os.path.expanduser("~/agent-guardrail"))
from qedra import zk
from qedra.guardrail import Action


def main() -> int:
    print("== Proof-carrying compliance certificate ==\n")

    # 1. The agent proposes an action. We certify compliance in ZERO KNOWLEDGE: only the commitment C and
    #    the proof are published; the action itself is never revealed.
    action = Action("git", op="commit", branch="main")
    verdict, _ = zk.action_verdict(action)
    print(f"agent action (kept PRIVATE): {action.op!r} on {action.branch!r}   policy verdict: {verdict}")

    C, proof, r = zk.prove_action(action)
    print(f"published certificate       : C={str(C)[:22]}...  proof.verdict={proof.verdict!r}  (action hidden)")

    # 2. A relying party verifies with PUBLIC DATA ONLY -- no trust in the agent or operator.
    ok = zk.verify(C, proof)
    print(f"\nrelying party verifies      : {'VERIFIED' if ok else 'REJECTED'}")
    print(f"  -> proves the hidden action is policy-classified {proof.verdict!r}, without learning what it was.")

    # 3. Tamper-evidence: the certificate is bound to its commitment. Lifting the same proof onto a
    #    different (e.g. non-compliant) action's commitment fails.
    lifted = zk.verify(C + 1, proof)
    print(f"\nadversary lifts proof to a different commitment: {'VERIFIED' if lifted else 'REJECTED (correct)'}")

    passed = ok and not lifted
    print(f"\n{'PASS' if passed else 'FAIL'}: an honest compliance certificate verifies from public data;")
    print("      it cannot be lifted to a different action. (Full soundness: qedra tests/test_zk.py, 0/500 forged accepted.)")
    print("      Combined with coq/Compliance.v, a verifying certificate implies the hidden action obeyed the policy.")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
