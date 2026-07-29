# proof-carrying-ai

**A proof-carrying compliance certificate for AI agent actions:** an agent action ships with a certificate
that proves it obeyed a formal policy — a *machine-checked* soundness proof plus a *zero-knowledge* proof —
verifiable by anyone with public data alone, and unforgeable for a non-compliant action.

The bet (see the thesis behind it): as AI agents take real actions autonomously, *generation becomes free and
verification becomes the scarce asset.* Existing tools **detect** heuristically; this one **proves.** The
distinction — "here is a proof it complied" vs "we didn't find a problem" — is the whole point.

```
$ ./verify.sh
Machine-checked compliance proof (coqc):
  Coq  Compliance.v          PASS
Zero-knowledge certificate demo (python):
  ZK   demo_certificate.py   PASS
ALL CHECKS PASSED
```

## The two layers of a certificate

An agent proposes an action. Instead of trusting the agent or the operator, we attach a certificate with two
independently-checkable layers:

1. **Zero-knowledge (crypto) — `demo_certificate.py`.** A proof that the *hidden* action's committed value
   lies in the policy's **allowed set** — verifiable from public data, without revealing the action. (Reuses
   qedra's tested Sigma/Pedersen ZK; rigorous soundness — 0 forged proofs accepted out of 500 — is in qedra's
   `tests/test_zk.py`.)
2. **Machine-checked (logic) — `coq/Compliance.v`.** A `coqc`-checked, **axiom-free** proof that the allowed
   set *is exactly* the set of policy-compliant actions (`certificate_sound`, `certificate_complete`,
   `certificate_exact`). This closes the gap the ZK layer leaves open: membership in the allowed set must
   actually **mean** policy compliance, or the ZK proof proves nothing meaningful.

**Together:** a verifying certificate implies the hidden action obeyed the formal policy — no trust in the
agent, the operator, or the server.

## Why it's defensible

The moat is the intersection almost nobody holds: **formal verification (Coq) + zero-knowledge cryptography
(Sigma/Pedersen, and Nova/KZG as circuits scale) + AI-agent semantics.** A wrapper, a prompt layer, or an
"AI-safety" SaaS cannot fake a proof.

## Honest scope (this is a seed, not the finished landmark)

- The ZK policy reused here is qedra's **git-branch policy** — the one domain qedra's ZK covers today. It is a
  working proof-of-concept of the *shape*, not yet a general agent-action prover.
- **Roadmap:** generalize the policy DSL (spend caps, no-PII, data-residency, tool-call constraints) →
  compile it to circuits → scale proving (Nova folding / GPU) → ship the first verifiable **certificate of
  agent-action compliance** for a real agent action (e.g. an agentic payment) as the landmark artifact.
- Builds directly on [qedra](https://github.com/ss1738/qedra) (the enforcer + the ZK) and
  [epbs-formal](https://github.com/ss1738/epbs-formal) (the machine-checked-proof craft).

## Reproduce

```
./verify.sh          # coqc on the proof + the ZK certificate demo
```
Requires `coqc` (Rocq/Coq) and `python3`; the ZK layer imports the `qedra` package (expected at
`~/agent-guardrail`).

## License

MIT.
