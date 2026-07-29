#!/usr/bin/env bash
# Reproduce both layers of a proof-carrying compliance certificate with one command.
# Requires coqc (Rocq/Coq) and python3 (+ the qedra package at ~/agent-guardrail for the ZK layer).
set -uo pipefail
cd "$(dirname "$0")"
fail=0
echo "Machine-checked compliance proof (coqc):"
if ( cd coq && coqc Compliance.v >/dev/null 2>&1 ); then echo "  Coq  Compliance.v          PASS"; else echo "  Coq  Compliance.v          FAIL"; fail=1; fi
echo "Zero-knowledge certificate demo (python):"
if python3 demo_certificate.py >/dev/null 2>&1; then echo "  ZK   demo_certificate.py   PASS"; else echo "  ZK   demo_certificate.py   FAIL"; fail=1; fi
echo
if [ "$fail" -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "SOME CHECKS FAILED"; fi
exit "$fail"
