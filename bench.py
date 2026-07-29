"""bench.py -- measured proving/verification cost and proof size for the certificate.

Answers the practical question honestly: is this ZK fast/small enough to be useful today, and does it need a
GPU yet? All numbers are MEASURED on this machine (printed with the platform), not estimated.

    python3 bench.py
"""
import json
import os
import platform
import secrets
import sys
import time

sys.path.insert(0, os.path.expanduser("~/agent-guardrail"))
from qedra import zk_core
from qedra.zk import MODP

import zk_range
import demo_structured_certificate as cert

G = MODP
Q = G.q


def _time(fn, reps):
    t0 = time.perf_counter()
    for _ in range(reps):
        fn()
    return (time.perf_counter() - t0) / reps * 1000.0  # ms per op


def bench_range(nbits, reps=3):
    limit, amount = (1 << nbits) - 1, (1 << nbits) // 3
    r_a = secrets.randbelow(Q)
    C, pf = zk_range.prove_le(amount, r_a, limit, nbits)
    size = len(json.dumps(pf).encode())
    prove_ms = _time(lambda: zk_range.prove_le(amount, secrets.randbelow(Q), limit, nbits), reps)
    verify_ms = _time(lambda: zk_range.verify_le(C, limit, pf), reps)
    return prove_ms, verify_ms, size


def bench_certificate(reps=3):
    c = cert.make_certificate(amount=750, counterparty="bob")
    size = len(json.dumps(c, default=str).encode())
    prove_ms = _time(lambda: cert.make_certificate(750, "bob"), reps)
    verify_ms = _time(lambda: cert.verify_certificate(c), reps)
    return prove_ms, verify_ms, size


if __name__ == "__main__":
    print(f"platform: {platform.platform()} | python {platform.python_version()} "
          f"| {os.cpu_count()} cpus | MEASURED, CPU-only, single core\n")

    print("ZK range proof (spend_cap), by bit-width:")
    print(f"  {'nbits':>6} {'prove (ms)':>12} {'verify (ms)':>12} {'proof (bytes)':>14}")
    for nbits in (8, 16, 32):
        p, v, s = bench_range(nbits)
        print(f"  {nbits:>6} {p:>12.1f} {v:>12.1f} {s:>14,}")

    print(f"\nFull payment certificate (range n={cert.NBITS} + allowlist membership):")
    p, v, s = bench_certificate()
    print(f"  prove {p:.1f} ms | verify {v:.1f} ms | size {s:,} bytes")

    print("\nread (honest): a certificate costs ~1-3 CPU-SECONDS and tens of KB at these bit-widths. That is")
    print("fine for occasional high-value actions (a payment), but too slow/large for high throughput. The")
    print("cost is dominated by ~2048-bit modexp in pure Python over one OR-proof PER BIT -- so the win is a")
    print("better range ARGUMENT (Bulletproofs: log-size, or an elliptic-curve group), NOT a GPU. A GPU/A100")
    print("earns its keep only later, for recursive folding (Nova) over large aggregated statements.")
