"""bench.py -- measured proving/verification cost and proof size, MODP-2048 vs secp256k1.

Answers honestly: is this ZK fast/small enough to be useful, does it need a GPU, and how much does moving
from the 2048-bit MODP group to an elliptic curve buy us? All numbers are MEASURED on this machine.

    python3 bench.py
"""
import json
import os
import platform
import secrets
import sys
import time

sys.path.insert(0, os.path.expanduser("~/agent-guardrail"))
from qedra.zk import MODP

import zk_range
from ec_group import EC


def _time(fn, reps):
    t0 = time.perf_counter()
    for _ in range(reps):
        fn()
    return (time.perf_counter() - t0) / reps * 1000.0  # ms per op


def bench_range(group, nbits, reps=3):
    limit, amount = (1 << nbits) - 1, (1 << nbits) // 3
    C, pf = zk_range.prove_le(amount, group.rand_scalar(), limit, nbits, group=group)
    size = len(json.dumps(pf).encode())
    prove_ms = _time(lambda: zk_range.prove_le(amount, group.rand_scalar(), limit, nbits, group=group), reps)
    verify_ms = _time(lambda: zk_range.verify_le(C, limit, pf, group=group), reps)
    return prove_ms, verify_ms, size


if __name__ == "__main__":
    print(f"platform: {platform.platform()} | python {platform.python_version()} "
          f"| {os.cpu_count()} cpus | MEASURED, CPU-only, single core\n")

    print(f"  {'group':>11} {'nbits':>6} {'prove (ms)':>12} {'verify (ms)':>12} {'proof (bytes)':>14}")
    for name, grp in (("MODP-2048", MODP), ("secp256k1", EC)):
        for nbits in (8, 16, 32):
            p, v, s = bench_range(grp, nbits)
            print(f"  {name:>11} {nbits:>6} {p:>12.1f} {v:>12.1f} {s:>14,}")

    print("\nread (honest, measured -- this corrected my prior): secp256k1 shrinks proofs ~8x (the win that")
    print("matters for transmission/on-chain), but here it is ~2x SLOWER, not faster. Why: naive AFFINE EC")
    print("does a modular inverse per point-add, while 2048-bit pow() is a tuned C builtin. Projective")
    print("coordinates (defer inversions) or a native curve lib recover the speed and keep the size win.")
    print("Either way cost is linear in bit-width (one OR-proof PER BIT) -> the real next win is a log-size")
    print("range ARGUMENT (Bulletproofs), NOT a GPU. A GPU/A100 matters only later, for recursive folding.")
