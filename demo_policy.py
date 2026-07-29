"""demo_policy.py -- the general policy DSL on a realistic agent action: an agentic PAYMENT.

Shows a composable policy (spend cap + counterparty allowlist + no-secret-in-memo + data-residency) applied
to structured agent actions, with the failing rule named on a block. This is the "what a real agent-action
policy looks like" step beyond the git-branch domain.

    python3 demo_policy.py
"""
from policy_dsl import allowlist, evaluate, no_secret, residency, spend_cap

# A realistic agentic-payment policy: four composable rules, conjunction.
policy = [
    spend_cap(1000),
    allowlist("counterparty", {"alice", "bob"}),
    no_secret("memo"),
    residency({"EU", "UK"}),
]

# Which rules can be proven in ZERO KNOWLEDGE today vs need new circuits (honest scope):
#   allowlist / denylist  -> set-membership: qedra's Sigma OR-proof already does this.
#   spend_cap             -> a RANGE proof (amount <= limit): standard ZK, next circuit to add.
#   residency             -> set-membership (region in allowed): same as allowlist.
#   no_secret             -> SEMANTIC; the ZK can prove a syntactic regex-check, honestly weaker (see README).

actions = [
    ({"amount": 500,  "counterparty": "alice",   "memo": "invoice #42",            "region": "UK"}, "expect ALLOW"),
    ({"amount": 5000, "counterparty": "alice",   "memo": "ok",                     "region": "UK"}, "over cap"),
    ({"amount": 100,  "counterparty": "mallory", "memo": "ok",                     "region": "UK"}, "bad counterparty"),
    ({"amount": 100,  "counterparty": "bob",     "memo": "key=sk-proj-Ab3xK9mQ2nL5vR8tW1cY7dE4", "region": "UK"}, "secret in memo"),
    ({"amount": 100,  "counterparty": "bob",     "memo": "ok",                     "region": "CN"}, "wrong region"),
]

print("== General policy DSL on an agentic payment ==\n")
print(f"policy: {[name for name, _ in policy]}\n")
ok = True
for action, note in actions:
    verdict, failing = evaluate(policy, action)
    tag = "ALLOW " if verdict == "ALLOW" else f"BLOCK ({failing})"
    print(f"  [{tag:28}] {note:18} {action}")
    # sanity: the one 'expect ALLOW' must ALLOW; the rest must BLOCK
    if note == "expect ALLOW":
        ok = ok and verdict == "ALLOW"
    else:
        ok = ok and verdict == "BLOCK"

print(f"\n{'PASS' if ok else 'FAIL'}: composable policy admits the compliant payment and names the violated "
      "rule on each block.")
print("Machine-checked compositional soundness of this DSL: coq/PolicyDSL.v (3 theorems, axiom-free).")
raise SystemExit(0 if ok else 1)
