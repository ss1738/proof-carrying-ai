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
  Run  bulletproof.py         PASS
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

## Logarithmic range proofs: Bulletproofs (`bulletproof.py`)

The bit-decomposition range proof is O(n) in size (one commitment + OR-proof per bit). `bulletproof.py`
implements a **Bulletproofs** range proof (Bunz et al. 2018) over secp256k1: a committed value in `[0, 2^n)`
with an **O(log n)** proof, built on an inner-product argument (also here, independently tested). The IPA folds
the length-n `l`,`r` vectors down to `2·log2(n)` points via recursive halving.

**Measured** (`bulletproof.py`; proof size vs the bit-decomposition on the same secp256k1 group):

| n bits | Bulletproofs | bit-decomposition | smaller |
|---|---|---|---|
| 16 | 1,324 B | 9,237 B | 7.0× |
| 32 | **1,465 B** | 18,446 B | **12.6×** |

The Bulletproofs proof grows **logarithmically** — 16→32 bits adds ~141 B (one IPA round) while the
bit-decomposition *doubles*. That is an asymptotic change, not a constant-factor one. Sound (honest verifies;
a proof replayed against a commitment to a different value is rejected; an out-of-range value cannot be
proven). Prototype crypto (Fiat-Shamir in ROM), pending external review like the rest.

**Native prover, wire-compatible** (`rust/bulletproof-rs`): a Rust Bulletproofs prover over the *same*
secp256k1 group — identical generators (verified: `g[0]`/`u` serialize byte-for-byte the same), serialization,
and SHA256 Fiat-Shamir — so a **Rust-generated Bulletproofs proof verifies in Python's `range_verify`**
(measured, n=16 and n=32, and still true after the optimization below). Speed (measured on ironman):

| n | Python | Rust (affine) | **Rust (Jacobian)** | total vs Python |
|---|---|---|---|---|
| 16 | 6,460 ms | 1,351 ms | **188 ms** | **~34×** |
| 32 | 12,858 ms | 2,924 ms | **389 ms** | **~33×** |

The measurement said the bottleneck was a field inversion per point-add, not the language — so the prover uses
**Jacobian coordinates** (one inversion per scalar-mul instead of ~256). That alone gave ~7× on top of the
~4.8× from Rust, for ~34× over the *affine* Python baseline, with the affine serialization preserved so proofs
still verify in Python. This is the lever the earlier benchmark pointed to, applied and measured.

The same fix went into the Python group (`ec_group.py`): Jacobian coordinates cut Python Bulletproofs prove
from 6,460→272 ms (n=16) and 12,858→540 ms (n=32) — **~24×** — since Python's per-op overhead amplified the
inversion cost even more. Every Python EC demo (the structured certificate, EC range proofs) got faster for
free, and `./verify.sh` still passes.

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

**Throughput** (`throughput.py`, MEASURED on two 10-core M4 Mac Minis — `apsarth` and `ironman` — full
certificate prove+verify, MODP n=16): ~0.42 certs/s single-core; ~2.5 certs/s per Mini (6× scaling, 60%
efficiency across its performance+efficiency cores); ~5 certs/s across the two Minis. Certificates are independent, so throughput scales
with **cores**, not with a GPU — this confirms the cost is per-certificate pure-Python bigint, exactly what a
log-size argument + native crypto (not an accelerator) would cut. Deployable today for occasional high-value
actions (a payment, a git op); not yet for high-frequency streams.

## A native (Rust) prover, wire-compatible with the Python core (`rust/zkcore`)

`rust/zkcore` reimplements qedra's Sigma OR-proof over the 2048-bit MODP group in Rust, with **byte-identical**
group constants, serialization, and Fiat-Shamir hashing. A proof produced in Rust verifies in Python and vice
versa, so it is provably the *same protocol*, not a drifting reimplementation.

**Measured on `ironman` (M4 Mini, same box, |allowed set|=3, 200 reps):**

| | prove | verify |
|---|---|---|
| Python `qedra.zk_core` | 126.9 ms | 142.7 ms |
| Rust `zkcore` | **17.7 ms** | **19.9 ms** |
| speedup | **~7.2×** | **~7.2×** |

The Rust core covers the **whole certificate**, not just the OR-proof: it includes the bit-decomposition
**range proof** (spend_cap), also wire-compatible — a Rust range proof verifies in Python's `zk_range.verify_le`.
There are two backends, both the same protocol: `rust/zkcore` (num-bigint, pure Rust) and `rust/zkcore-gmp`
(GMP via `rug`, assembly modmul). Full payment certificate (range n=16 + membership), same box:

| backend | prove | verify | vs Python |
|---|---|---|---|
| Python `qedra` | 1372.9 ms | ≈ prove | 1× |
| Rust `zkcore` (num-bigint) | 186.5 ms | 200.6 ms | ~7.4× |
| **Rust `zkcore-gmp` (GMP)** | **103.1 ms** | **111.5 ms** | **~13.3×** |

Cross-language, all verified: `rust -> python verify OK`, `python -> rust verify OK`, `rust range -> python
verify_le OK`, `gmp -> python verify OK`, tampered commitment rejected by both (`rust/interop_test.py`,
`rust/gmp_interop.py`). Honest on the GMP delta: it is **~1.8× over num-bigint**, not an order of magnitude —
num-bigint is already good and GMP's edge at 2048-bit is modest (it widens at larger moduli / with dedicated
routines). Overall ~13× over Python, and a full certificate now proves in ~0.1 s single-core. Builds and runs
on the Mini cluster (`cargo build --release`), per the repo's compute rules.

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

## On-chain verification (`onchain/` — Solidity + BN254)

The certificate is only useful on Ethereum if a contract can check it. `onchain/SigmaVerifier.sol` verifies a
Sigma OR-proof (the allowlist / policy-verdict membership proof) **on-chain**, over **BN254 (alt_bn128)** using
the `ecAdd` (0x06), `ecMul` (0x07), and `sha256` (0x02) precompiles — no trusted setup, no 2048-bit modexp. A
smart account or bundler can gate an action on `verify(...) == true` without learning the hidden value.

The proof is produced off-chain by `onchain/onchain_prove.py` (same Sigma protocol, BN254 group, SHA256
byte-Fiat-Shamir) and verified on-chain unchanged. Measured with Foundry (`forge test`):

```
[PASS] test_honest_proof_verifies_onchain
[PASS] test_tampered_commitment_rejected
[PASS] test_tampered_challenge_rejected
[PASS] test_wrong_allowed_set_rejected
verify gas (|ms|=3): 132,844
```

Both rules of the payment policy verify on-chain (`RangeVerifier.sol` reuses the same clause check per bit +
a homomorphic bind):

| on-chain check | contract | gas |
|---|---|---|
| allowlist / verdict (set membership) | `SigmaVerifier.verify` | ~132,844 (|ms|=3) |
| spend_cap (range, n=16) | `RangeVerifier.verifyRange` | ~1,228,456 |

Every tamper — the commitment, a challenge scalar, the allowed set, the amount, or the limit — is rejected
(an off-curve point fails closed via the precompile). The range verifier is O(n) gas (bit-decomposition); a
Bulletproofs on-chain verifier would cut it to O(log n) and is the natural next optimization. This is the
concrete "verifiable agent action for Ethereum smart accounts" deliverable. Run it:
`cd onchain && forge install foundry-rs/forge-std && python3 onchain_prove.py && forge test -vv`.

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
