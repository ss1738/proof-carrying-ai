# Security

This document states, plainly, what the certificates guarantee, what they assume, and what is *not* yet
established. It is written for reviewers, auditors, and integrators. The project's whole point is honest
verification, so the caveats are first-class, not footnotes.

## What a verifying certificate proves

A certificate that `Certificate.verify` (or the on-chain verifier) accepts implies **the hidden action was in
the policy's allowed set**, without revealing the action, under the assumptions below:

- **spend_cap** — the committed amount is in `[0, cap]` (a zero-knowledge range proof).
- **allowlist / residency** — the committed counterparty / region is one of the permitted values (a
  zero-knowledge set-membership proof).
- **integrity + authenticity** — the whole bundle is signed (Ed25519); tampering with any field, or signing
  with the wrong key, is detected.

The bridge from "in the allowed set" to "compliant with the policy" is **machine-checked and axiom-free** in
`coq/` (`certificate_exact`: the allowed set equals the set of compliant actions).

## Assumptions (trust model)

- **Random-oracle model.** Fiat-Shamir is instantiated with SHA-256; soundness is in the ROM, standard for
  non-interactive Sigma protocols and Bulletproofs but not a plain-model guarantee.
- **Discrete-log hardness** in the groups used (2048-bit MODP QR subgroup; secp256k1; BN254 G1).
- **Nothing-up-my-sleeve generators.** The Pedersen second generator `h` (and the Bulletproofs generator
  vectors) are hash-to-curve of fixed labels, so their discrete log w.r.t. `g` is unknown — required for the
  binding property. The derivation is in code and reproducible.
- **Honest generation of the signing key**, kept secret by the issuer. A verifier trusts only the pinned
  public key, not the issuer's process.

## Known limitations (do not deploy against these)

- **NOT audited.** This is prototype cryptography pending independent review. Do not rely on it for funds or
  safety-critical decisions until audited.
- **`no_secret` is weaker than it looks.** It proves a *syntactic* regex check, not the semantic absence of a
  secret. It is not part of the ZK certificate for that reason.
- **On-chain range verification is O(n) gas** (bit-decomposition). Correct, but a Bulletproofs on-chain
  verifier would be smaller in calldata; not yet built.
- **Data-availability of commitments.** The certificate proves compliance of a *committed* value; it does not
  prove the committed value is the one the agent actually acted on. Binding the commitment to the executed
  action (e.g. inside an ERC-4337 account's validation) is an integration responsibility.
- **Replay.** Certificates are not nonce-bound by default; an integrator that needs anti-replay must bind a
  nonce/context into the policy `domain`.

## Self-audit (pre-external-review)

A self-audit of the general rule engine found and fixed three soundness gaps (each confirmed exploitable, then
regression-tested). They are recorded here in the spirit of honest disclosure — and as a reminder that an
*external* audit is expected to find more:

- **Band binding** (0.3.1) — two rules on the same field (e.g. min/max) were committed separately, so nothing
  bound them to the same value. Fixed: each field is committed once, shared across its rules.
- **Completeness** (0.3.2) — `verify` didn't check the certificate proves *every* policy rule; a re-signed
  cert could drop a rule. Fixed: proven rules must equal the policy.
- **Vacuous range** (0.3.3) — a range proof with `nbits` near the group order makes the interval the whole
  field, so an over-cap amount passed. Fixed: `nbits` is capped at 64.

## Reporting a vulnerability

Please report security issues privately to the maintainer (see the GitHub profile) rather than opening a
public issue. Since this is pre-audit prototype software, findings that a formal audit would surface are
expected — they are welcome and will be credited.
