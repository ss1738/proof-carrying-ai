"""Cross-language interop + head-to-head bench for the native Rust ZK core vs the Python zk_core.
Run on a Mini (both the Rust binary and the qedra package are synced there).

Proves the Rust prover and the Python prover speak the SAME protocol: a proof made in one verifies in the
other. Then times both on the same box, so the speedup is measured, not asserted.
"""
import json
import os
import secrets
import subprocess
import sys
import time

sys.path.insert(0, os.path.expanduser("~/proof-carrying-ai-run/agent-guardrail"))
from qedra import zk_core
from qedra.zk import MODP
from qedra.zk_core import ZKProof

MS = (1, 2, 3)
TAG = "cert/counterparty"
M = 2
BIN = os.path.expanduser("~/proof-carrying-ai-run/proof-carrying-ai/rust/zkcore/target/release/zkcore")
REPS = 200


def py_proof_to_json(proof, C):
    return json.dumps({"C": str(C), "verdict": proof.verdict, "t": list(proof.t),
                       "e": [str(x) for x in proof.e], "z": [str(x) for x in proof.z]})


# ---- 1. head-to-head bench (same OR-proof, same box) ----
t0 = time.perf_counter()
for _ in range(REPS):
    proof, C = zk_core.prove(MODP, MS, M, secrets.randbelow(MODP.q), "allow", TAG)
py_prove = (time.perf_counter() - t0) / REPS * 1000
t0 = time.perf_counter()
for _ in range(REPS):
    zk_core.verify(MODP, MS, C, proof, TAG)
py_verify = (time.perf_counter() - t0) / REPS * 1000
print(f"python  MODP-2048 OR-proof(|ms|=3): prove {py_prove:.3f} ms | verify {py_verify:.3f} ms (reps={REPS})")
print(subprocess.run([BIN, "bench", str(REPS), "1,2,3", TAG], capture_output=True, text=True).stdout.strip())

# ---- 2. Rust proves -> Python verifies ----
out = subprocess.run([BIN, "prove", "allow", str(M), "1,2,3", TAG], capture_output=True, text=True).stdout.strip()
d = json.loads(out)
Cr = int(d["C"])
pr = ZKProof.from_dict({"verdict": d["verdict"], "t": d["t"], "e": d["e"], "z": d["z"]})
r2p = zk_core.verify(MODP, MS, Cr, pr, TAG)
print(f"\nrust  -> python verify : {'OK' if r2p else 'FAIL'}")

# ---- 3. Python proves -> Rust verifies ----
proof, C = zk_core.prove(MODP, MS, M, secrets.randbelow(MODP.q), "allow", TAG)
res = subprocess.run([BIN, "verify", "1,2,3", TAG], input=py_proof_to_json(proof, C), capture_output=True, text=True)
p2r = res.stdout.strip()
print(f"python-> rust  verify  : {p2r}")

# ---- 4. tamper C -> Rust must reject ----
proof, C = zk_core.prove(MODP, MS, M, secrets.randbelow(MODP.q), "allow", TAG)
bad = py_proof_to_json(proof, C).replace(f'"C": "{C}"', f'"C": "{C + 1}"')
res = subprocess.run([BIN, "verify", "1,2,3", TAG], input=bad, capture_output=True, text=True)
tamper = res.stdout.strip()
print(f"python-> rust  tampered: {tamper} (want FAIL)")

speedup_p = py_prove / (py_prove)  # placeholder; real ratio printed by caller comparing lines
ok = r2p and p2r == "OK" and tamper == "FAIL"
print(f"\n{'PASS' if ok else 'FAIL'}: Rust and Python prove/verify are wire-compatible (same protocol), "
      "tampering rejected cross-language.")
raise SystemExit(0 if ok else 1)
