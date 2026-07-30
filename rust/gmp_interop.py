"""Confirm the GMP-backed prover is still wire-compatible: its proofs verify in the Python stack."""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.expanduser("~/proof-carrying-ai-run/agent-guardrail"))
sys.path.insert(0, os.path.expanduser("~/proof-carrying-ai-run/proof-carrying-ai"))
from qedra import zk_core
from qedra.zk import MODP
from qedra.zk_core import ZKProof

import zk_range

MS, TAG, M, LIMIT, NBITS = (1, 2, 3), "cert/counterparty", 2, 1000, 16
GMP = os.path.expanduser("~/proof-carrying-ai-run/proof-carrying-ai/rust/zkcore-gmp/target/release/zkcore-gmp")

d = json.loads(subprocess.run([GMP, "prove", "allow", str(M), "1,2,3", TAG], capture_output=True, text=True).stdout)
or_ok = zk_core.verify(MODP, MS, int(d["C"]), ZKProof.from_dict({"verdict": d["verdict"], "t": d["t"], "e": d["e"], "z": d["z"]}), TAG)
rd = json.loads(subprocess.run([GMP, "range-prove", str(LIMIT), "750", str(NBITS)], capture_output=True, text=True).stdout)
range_ok = zk_range.verify_le(int(rd["C_amount"]), LIMIT, rd["range"], group=MODP)
print(f"gmp OR-proof -> python verify   : {'OK' if or_ok else 'FAIL'}")
print(f"gmp range    -> python verify_le: {'OK' if range_ok else 'FAIL'}")
raise SystemExit(0 if or_ok and range_ok else 1)
