"""throughput.py -- how many compliance certificates can we prove+verify per second, and does it scale
across cores? Certificates are independent, so this is embarrassingly parallel. This is the number that
answers "is it deployable", which a GPU does NOT change for pure-Python bigint ZK (parallel CPU does).

Each unit = a full structured-payment certificate: a ZK range proof (spend_cap) + a ZK set-membership proof
(allowlist), both proved AND verified. Fixed-wall-clock: each worker runs for D seconds and counts completions.

    python3 throughput.py [D_seconds]
"""
import os
import platform
import secrets
import sys
import time
from multiprocessing import Pool

sys.path.insert(0, os.path.expanduser("~/agent-guardrail"))
from qedra import zk_core
from qedra.zk import MODP

import zk_range

G = MODP                      # faster group -> more samples in the window; scaling is group-independent
Q = G.q
CAP, NBITS, ALLOWED = 1000, 16, (1, 2, 3)


def one_cert() -> bool:
    r_a, r_c = secrets.randbelow(Q), secrets.randbelow(Q)
    C, rp = zk_range.prove_le(750, r_a, CAP, NBITS, group=G)              # spend_cap (range)
    mp, Ccp = zk_core.prove(G, ALLOWED, 2, r_c, "allow", "cert/cp")       # allowlist (membership)
    return zk_range.verify_le(C, CAP, rp, group=G) and zk_core.verify(G, ALLOWED, Ccp, mp, "cert/cp")


def worker(duration: float) -> int:
    end = time.perf_counter() + duration
    n = 0
    while time.perf_counter() < end:
        if not one_cert():
            raise SystemExit("a certificate failed to verify")
        n += 1
    return n


if __name__ == "__main__":
    D = float(sys.argv[1]) if len(sys.argv) > 1 else 12.0
    ncpu = os.cpu_count()
    print(f"{platform.node()} | {platform.platform()} | {ncpu} cpus | MODP n={NBITS} | {D:.0f}s window/run")

    n1 = worker(D)
    r1 = n1 / D
    with Pool(ncpu) as p:
        counts = p.map(worker, [D] * ncpu)
    rall = sum(counts) / D
    print(f"  1 core  : {n1:5d} certs -> {r1:7.2f} certs/s")
    print(f"  {ncpu} cores : {sum(counts):5d} certs -> {rall:7.2f} certs/s  "
          f"(scaling {rall / r1:.1f}x, {100 * rall / r1 / ncpu:.0f}% parallel efficiency)")
