# Changelog

## 0.2.0

Product-grade packaging and integration surfaces.

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
