# Changelog

## 0.3.2

**Soundness fix (completeness).** `verify` now requires the certificate to carry a proof for **every** rule in
its policy. Previously a certificate could drop a rule (and be re-signed by the key holder) yet still verify,
letting a malicious operator claim a policy while proving only a subset. The verifier now checks the proven
rules exactly match the policy. Regression test added.

## 0.3.1

**Soundness fix.** A field is now committed **once** and shared across all its rules. Previously a policy with
two rules on the same field (e.g. a min/max band) committed the field separately per rule, so nothing bound
them to the same hidden value -- a crafted certificate could prove the bounds against *different* values. Now
the verifier checks every same-field rule against one commitment, so bands are enforced. Found by inspection,
live in the LLM example; added a regression test.

## 0.3.0

General policy engine + full CLI/service parity.

- **General policy engine** — a policy is a list of rules (`max`/`min` on any numeric field, `in` on any
  categorical field), so certificates cover *any* agent action (LLM token budgets, tool allowlists, data
  scopes), not just payments. `spend_cap`/`allowlist`/`residency` remain as shorthand. **Breaking:** the
  certificate format is now rule-based (`cert.rules`), not the fixed `spend_cap`/`allowlist` fields.
- **CLI `--policy`/`--action` JSON** — general policies from the command line. `examples/agent_llm_tool.py`.
- Service hardened to fail closed on any malformed input (never 500); `tests/test_robustness.py`.


## 0.2.0

Product-grade packaging and integration surfaces.


- **Smaller certificates** — the spend_cap proof now uses **Bulletproofs** (logarithmic size) instead of
  bit-decomposition: a certificate shrank from ~20 KB to ~3.1 KB (~6.4x). Vendored `pcai/_bulletproof.py`.

- **Tamper-evident audit log** — `pcai.audit.AuditLog`: a hash-chained record of every issued certificate
  (policy + commitments, not the hidden values); any edit/insert/delete breaks the chain. Wired into `gate`
  (optional `audit_log=`) and the HTTP service (`GET /audit`).

- **Self-contained package** — vendored the ZK core (`pcai/_zkcore.py`, `_ec.py`, `_range.py`); removed the
  external `~/agent-guardrail` path dependency. `pip install .` needs only `cryptography`.
- **HTTP service** — `pcai serve` (`POST /certify`, `POST /verify`, `GET /health`), zero-dependency stdlib.
- **Agent integration** — `pcai.gate(policy, key)` decorator wraps an action function; every executed call
  carries a certificate, non-compliant calls are blocked before execution. `examples/agent_payment.py`.
- **residency** rule added as a third zero-knowledge membership proof.
- `SECURITY.md` (threat model + honest scope), `tests/test_server.py`, CI badge.

## 0.1.0

Initial certificate library + CLI.

- `pcai.issue` / `Certificate.verify` — a signed, zero-knowledge compliance certificate for an agent action
  (spend_cap range proof + allowlist membership), verifiable from public data alone.
- `pcai keygen | certify | verify` CLI; `tests/test_pcai.py`.
- Built on the underlying research artifact: axiom-free Coq soundness (`coq/`), Bulletproofs and
  bit-decomposition range proofs, a native Rust core, and on-chain BN254 verifiers.
