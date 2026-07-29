# proof-carrying-ai

**A proof-carrying compliance certificate for AI agent actions:** an agent action ships with a certificate
that proves it obeyed a formal policy — a *machine-checked* soundness proof plus a *zero-knowledge* proof —
verifiable by anyone with public data alone, and unforgeable for a non-compliant action.

The bet (see the thesis behind it): as AI agents take real actions autonomously, *generation becomes free and
verification becomes the scarce asset.* Existing tools **detect** heuristically; this one **proves.** The
distinction — "here is a proof it complied" vs "we didn't find a problem" — is the whole point.

```
$ ./verify.sh
Machine-checked proofs (coqc):
  Coq  Compliance.v           PASS
  Coq  PolicyDSL.v            PASS
  Coq  RangeProof.v           PASS
Runnable demos (python):
  Run  ec_group.py            PASS
  Run  demo_certificate.py    PASS
  Run  demo_policy.py         PASS
  Run  zk_range.py            PASS
  Run  demo_structured_certificate.py PASS
  Run  live_agent_bridge.py   PASS
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

## A general policy DSL (beyond git)

`coq/PolicyDSL.v` + `policy_dsl.py` generalize the single-predicate case to a real **composable policy** over
*structured* agent actions (a payment, a tool call, a data access) — not just git ops. A policy is a
conjunction of rules: `spend_cap`, `allowlist`, `denylist`, `no_secret`, `residency`. `demo_policy.py` runs a
realistic agentic-payment policy and names the violated rule on each block.

Machine-checked, axiom-free, parametric in the action type (`coq/PolicyDSL.v`):
- `policy_conjunction_sound` — ALLOW iff **every** rule passes (no rule silently skipped).
- `policy_blocks_on_violation` — **any** violated rule forces BLOCK (no bypass).
- `adding_a_rule_only_restricts` — defence-in-depth is monotone-safe.
- `allowed_set_exact` — what the ZK layer proves membership in == the compliant actions.

The Python `Rule` (a decidable predicate) mirrors the Coq `Rule := Action -> bool` exactly, so the runnable
policy and the proven model are the same object.

**Which rules ZK-prove today vs need new circuits** (honest): `allowlist`/`denylist`/`residency` are
**set-membership** — qedra's Sigma OR-proof already does this. `spend_cap` is a **range proof** — now built
(`zk_range.py`, below). `no_secret` is **semantic** — the ZK can prove a syntactic regex-check, which is
honestly a *weaker* property than "contains no secret"; that gap is stated, not hidden.

## The spend_cap circuit: a ZK range proof (`zk_range.py` + `coq/RangeProof.v`)

`spend_cap` ("amount ≤ limit") needs a **range proof**, not set-membership. `zk_range.py` builds one by
**bit-decomposition**: to prove the hidden `d = limit − amount` lies in `[0, 2^n)`, commit each bit of `d`,
prove each bit is 0 or 1 (**reusing qedra's tested Sigma OR-proof over the set {0,1}**), and let the Pedersen
homomorphism bind them — the verifier recomputes `∏ Cᵢ^(2^i)` and checks it equals the publicly-derivable
`C_d = g^limit · C_amount⁻¹`. Self-test: honest `500 ≤ 1000` **verifies**; a forged `5000 ≤ 1000` is
**rejected**; the prover cannot construct a proof of a false statement.

The one arithmetic fact this rests on — *n genuine bits reconstruct a value strictly below 2ⁿ* — is
machine-checked and **axiom-free** in `coq/RangeProof.v` (`range_bound`, `spend_cap_sound`). If that were
false, a valid-looking bit proof would bound nothing.

## The landmark seed: a certificate for a real agent action (`demo_structured_certificate.py`)

Not git branches — an **agentic payment**. The certificate proves, in zero knowledge, that a payment obeyed a
two-rule policy — `amount ≤ cap` (**ZK range proof**) **and** `counterparty ∈ allowlist` (**ZK
set-membership**) — without revealing the amount or the counterparty, verifiable from public data alone:

```
policy:  amount <= 1000 (ZK range)   AND   counterparty in allowlist (ZK set-membership)
  compliant  (amount=750,  cp=bob)      -> certificate VERIFIED
  over-cap   (amount=5000)             -> prover CANNOT build a certificate
  bad-cp     (cp=mallory)              -> prover CANNOT build a certificate
  tampered   (swapped C_amount=9999)    -> certificate REJECTED
```

This is the first proof-carrying compliance certificate for a *structured* agent action with **both** rules
proven in ZK and the underlying math machine-checked. It is the seed of the landmark, not the finished
system (see scope below).

## Group-generic: 2048-bit MODP *or* secp256k1 (`ec_group.py`)

The whole stack is parametric in the group (qedra's interface: `op, mul, g, h, q, ser, deser, eq`).
`ec_group.py` is a pure-Python secp256k1 group (nothing-up-my-sleeve second generator) that drops in with no
changes to the proofs. `demo_structured_certificate.py` runs on it; `zk_range.py` is verified sound over both.

**Measured** (`bench.py`, this M-series Mac, CPU-only — the numbers corrected my own prediction):

| group | range-proof size (n=32) | prove (n=32) |
|---|---|---|
| MODP-2048 | 140 KB | ~2.4 s |
| secp256k1 | **18 KB (~8× smaller)** | ~5.2 s (~2× *slower*) |

The size win is real and is what matters for transmission/on-chain. The speed *regression* is honest: naive
**affine** EC does a modular inverse per point-add, whereas 2048-bit `pow()` is a tuned C builtin. Projective
coordinates (defer inversions) or a native curve library recover the speed while keeping the small proofs —
that's an implementation detail, not a soundness one.

**Throughput** (`throughput.py`, MEASURED on the M4 Mini cluster, full certificate prove+verify, MODP n=16):
~0.42 certs/s single-core; ~2.5 certs/s on one 10-core M4 (6× scaling, 60% efficiency across its
performance+efficiency cores); ~5 certs/s across two Minis. Certificates are independent, so throughput scales
with **cores**, not with a GPU — this confirms the cost is per-certificate pure-Python bigint, exactly what a
log-size argument + native crypto (not an accelerator) would cut. Deployable today for occasional high-value
actions (a payment, a git op); not yet for high-frequency streams.

## A real agent action, carrying its own proof (`live_agent_bridge.py`)

Not a demo dict — an actual agent tool call, end to end. The input is what an agent proposes through qedra (a
git tool call; a Claude Code `PreToolUse` Bash payload), parsed into a qedra `Action` exactly as qedra's
executor does, run through qedra's **real gate** (`Guardrail.check`). An ALLOWED action in the ZK-covered
domain gets a **proof-carrying receipt**: a zero-knowledge proof it lies in the allowed set **plus** an
Ed25519 signature (qedra's session key). Anyone re-checks both from public data + the pinned public key:

```
  ALLOW    [ZK-cert] git commit               -> verify OK  (signature valid AND ZK compliance proof verifies)
  BLOCK    [signed ] force-push to main       -> verify OK  (signed decision 'BLOCK', no compliance cert)
  ALLOW    [ZK-cert] push a feature branch    -> verify OK  (signature valid AND ZK compliance proof verifies)
  ALLOW    [signed ] run tests (shell)        -> verify OK  (signed decision, outside ZK domain)
  tampered force-push BLOCK->ALLOW            -> verify FAIL (signature invalid)
```

No trust in the agent, the operator, or this process: a blocked action yields **no** compliance proof (you
cannot certify compliance of a non-compliant action), and flipping a receipt's verdict breaks the signature.

## Why it's defensible

The moat is the intersection almost nobody holds: **formal verification (Coq) + zero-knowledge cryptography
(Sigma/Pedersen, and Nova/KZG as circuits scale) + AI-agent semantics.** A wrapper, a prompt layer, or an
"AI-safety" SaaS cannot fake a proof.

## Honest scope (this is a seed, not the finished landmark)

- The ZK now covers **two rule shapes**: set-membership (allowlist/residency, via qedra) and a range proof
  (spend_cap, `zk_range.py`). `demo_structured_certificate.py` proves both on a real payment. Still a seed,
  not a general prover: `no_secret` is only syntactically ZK-provable, and the range proof uses a classic
  bit-decomposition (sound, but larger proofs than a modern range argument like Bulletproofs).
- **Roadmap:** more rule circuits (no-PII, data-residency, tool-call constraints) → succinct range/aggregation
  (Bulletproofs / Nova folding, GPU as circuits scale — CPU is fine at today's sizes) → wire a live agent's
  action through the certificate end-to-end as the landmark artifact.
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
