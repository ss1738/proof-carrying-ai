"""A non-payment example: an LLM agent whose tool calls are gated by pcai. The policy is a token budget +
a tool allowlist -- no money involved -- showing the certificate works for ANY agent action, not just
payments. Each executed tool call carries a zero-knowledge certificate; a verifier confirms it obeyed the
policy without seeing the token count or which tool was used.

    python3 examples/agent_llm_tool.py
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pcai.gate import PolicyViolation, gate

POLICY = {"rules": [
    {"type": "max", "field": "tokens", "limit": 100_000},   # per-call token budget
    {"type": "min", "field": "tokens", "floor": 1},         # non-trivial call
    {"type": "in",  "field": "tool",   "set": ["read", "search", "summarize"]},  # tool allowlist
]}
KEY = Ed25519PrivateKey.generate()
PUBKEY = KEY.public_key().public_bytes_raw().hex()


@gate(POLICY, KEY)
def call_tool(action: dict) -> str:
    return f"ran {action['tool']} ({action['tokens']} tokens)"


if __name__ == "__main__":
    attempts = [
        {"tool": "search", "tokens": 42_000},       # ok
        {"tool": "summarize", "tokens": 8_000},      # ok
        {"tool": "search", "tokens": 500_000},       # over token budget
        {"tool": "delete_all", "tokens": 100},       # tool not on the allowlist
    ]
    executed = 0
    for a in attempts:
        try:
            out = call_tool(a)
            executed += 1
            ok, reason = out.certificate.verify(POLICY, PUBKEY)
            print(f"  EXECUTED  {out.result:34} | verifier: {'ACCEPTED' if ok else 'REJECTED'}")
        except PolicyViolation as e:
            print(f"  BLOCKED   {'(' + a['tool'] + ', ' + str(a['tokens']) + ' tok)':34} | {e}")

    print(f"\n{executed}/4 tool calls executed with verifiable ZK certificates (no payments involved); "
          "the rest blocked before execution.")
    raise SystemExit(0 if executed == 2 else 1)
