"""A runnable example: an AI agent with a payment tool, gated by pcai. The agent decides to make payments;
`gate` ensures each executed payment carries a zero-knowledge compliance certificate, and blocks any payment
that violates the policy before it runs. A separate verifier (who never sees the amount or counterparty)
checks each certificate with the public key alone.

    python3 examples/agent_payment.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pcai import Certificate
from pcai.gate import PolicyViolation, gate

# The operator's policy and signing key (the key stays with the agent; verifiers only need the public key).
POLICY = {"spend_cap": 1000, "allowlist": ["alice", "bob"], "residency": ["EU", "UK"]}
KEY = Ed25519PrivateKey.generate()
PUBKEY = KEY.public_key().public_bytes_raw().hex()


# ---- the agent's payment tool, wrapped so every executed payment is certified ----
@gate(POLICY, KEY)
def send_payment(action: dict) -> str:
    return f"sent {action['amount']} to {action['counterparty']}"


def verifier_side(cert: Certificate) -> str:
    """A third party (bank, insurer, auditor) checks the certificate with the PUBLIC KEY alone."""
    ok, reason = cert.verify(POLICY, PUBKEY)
    return f"{'ACCEPTED' if ok else 'REJECTED'}: {reason}"


if __name__ == "__main__":
    # what the agent tries to do this session (some compliant, some not)
    attempts = [
        {"amount": 750, "counterparty": "alice", "region": "UK"},   # compliant
        {"amount": 200, "counterparty": "bob", "region": "EU"},     # compliant
        {"amount": 5000, "counterparty": "alice", "region": "UK"},  # over cap
        {"amount": 100, "counterparty": "mallory", "region": "UK"}, # not allowlisted
        {"amount": 100, "counterparty": "bob", "region": "CN"},     # wrong region
    ]
    executed = 0
    for a in attempts:
        try:
            out = send_payment(a)
            executed += 1
            # the certificate travels with the result; the verifier never sees amount/counterparty
            print(f"  EXECUTED  {out.result:28} | verifier: {verifier_side(out.certificate)}")
        except PolicyViolation as e:
            print(f"  BLOCKED   {'(' + str(a['amount']) + ' -> ' + a['counterparty'] + ')':28} | {e}")

    print(f"\n{executed}/5 payments executed, each carrying a verifiable ZK certificate; "
          "the rest blocked before execution.")
    ok = executed == 2
    raise SystemExit(0 if ok else 1)
