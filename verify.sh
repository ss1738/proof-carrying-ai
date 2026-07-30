#!/usr/bin/env bash
# Reproduce every layer of the proof-carrying compliance work with one command.
# Requires coqc (Rocq/Coq) and python3 (+ the qedra package at ~/agent-guardrail for the ZK + secret rules).
set -uo pipefail
cd "$(dirname "$0")"
fail=0
coq() { printf "  Coq  %-22s " "$1"; if ( cd coq && coqc "$1" >/dev/null 2>&1 ); then echo PASS; else echo FAIL; fail=1; fi; }
py()  { printf "  Run  %-22s " "$1"; if python3 "$1" >/dev/null 2>&1; then echo PASS; else echo FAIL; fail=1; fi; }
echo "Machine-checked proofs (coqc):"
coq Compliance.v
coq PolicyDSL.v
coq RangeProof.v
echo "Runnable demos (python):"
py ec_group.py
py demo_certificate.py
py demo_policy.py
py zk_range.py
py bulletproof.py
py onchain/onchain_bulletproof.py
py demo_structured_certificate.py
py live_agent_bridge.py
py tests/test_pcai.py
py tests/test_server.py
if command -v forge >/dev/null 2>&1 && [ -d onchain/lib/forge-std ]; then
  echo "On-chain verifier (forge):"
  printf "  Sol  %-22s " "SigmaVerifier.sol"
  if ( cd onchain && python3 onchain_prove.py >/dev/null 2>&1 && forge test >/dev/null 2>&1 ); then echo PASS; else echo FAIL; fail=1; fi
fi
echo
if [ "$fail" -eq 0 ]; then echo "ALL CHECKS PASSED"; else echo "SOME CHECKS FAILED"; fi
exit "$fail"
