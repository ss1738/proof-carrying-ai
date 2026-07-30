# Differential fuzzer — proof-carrying-ai ZK core

Adversarial regression for the soundness of the Sigma OR-proof, across the three
wire-compatible backends. Built because the catastrophic failure mode of ZK /
formal-verification work is a *silent* soundness regression — a change that makes
one backend accept a proof another rejects. This hunts for exactly that.

## The oracle
Three backends implement the same protocol:

| backend | proves | verifies |
|---|---|---|
| Python `qedra.zk_core` | ✓ | ✓ |
| Rust `zkcore` (num-bigint) | ✓ | ✓ (stdin) |
| Rust `zkcore-gmp` (GMP/rug) | ✓ | — (no CLI verify subcommand) |

**Two independent verifiers (Python + zkcore) must return the identical
accept/reject decision for every `(proof, C, ms, tag)`.** All three provers are
exercised, so a bad proof from any of them is caught by both verifiers. A
disagreement = a real soundness bug.

Each random iteration checks:
- honest proof from **each** of the 3 provers → both verifiers accept;
- tampered commitment (`C+1`), tampered `z` scalar, wrong tag, wrong member set
  (`m ∉ ms'`), tampered verdict string → both verifiers reject, identically.

## Run
On a Mini (where the binaries + qedra are synced):
```bash
python3 differential_fuzz.py 2000 [--seed S]      # exit 1 on any divergence, prints a --seed repro
```
Env overrides: `PCAI_RUN` (default `~/proof-carrying-ai-run`), `QEDRA_PATH`, `PCAI_RUST`.

Nightly, from your laptop (syncs the fuzzer, runs on a Mini, dated log, non-zero on divergence):
```bash
FUZZ_N=2000 ./nightly.sh          # ironman by default; FUZZ_HOST=…apsarth to switch
```
Logs land in `fuzz/logs/`.

## Unattended nightly (launchd)
`com.satyawan.pcai-fuzz-nightly.plist` runs `nightly.sh` daily at **03:17 local**
(FUZZ_N=1500, ~30 min on ironman; if the Mac is asleep, launchd runs it on wake).
Install:
```bash
cp fuzz/com.satyawan.pcai-fuzz-nightly.plist ~/Library/LaunchAgents/
launchctl bootstrap gui/$(id -u) ~/Library/LaunchAgents/com.satyawan.pcai-fuzz-nightly.plist
launchctl kickstart gui/$(id -u)/com.satyawan.pcai-fuzz-nightly   # run once now
launchctl print   gui/$(id -u)/com.satyawan.pcai-fuzz-nightly | grep state
launchctl bootout gui/$(id -u)/com.satyawan.pcai-fuzz-nightly     # uninstall
```
Per-run output → `fuzz/logs/<UTC>.log`; launchd stdio → `fuzz/logs/launchd.{out,err}`.
Validated 2026-07-30: launchd reaches the Mini under its own env (ssh/scp work),
streams progress, exits non-zero on divergence.

## Why it's not a `verify-gate` pre-push check
It needs the built Rust binaries + qedra on a Mini, so it is a **nightly regression
on the cluster**, not a local per-commit gate. Run it after your normal
sync + `cargo build --release` so it fuzzes the current binaries. Pair with a
launchd/cron entry for unattended nightly coverage.

## Status
v0.1 — validated on ironman: N=20 → 160 checks, 0 divergences; scaling to N≥2000.
The first run also caught two harness bugs (gmp has no CLI verify; `MODP` has no
`.p`) — fixed. Finding harness bugs before crypto bugs is the tool working.
