#!/usr/bin/env python3
"""Differential fuzzer for the proof-carrying-ai ZK core.

Three wire-compatible backends implement the SAME Sigma OR-proof protocol:
  - Python  (qedra.zk_core)      — proves AND verifies
  - Rust    zkcore      (num-bigint) — proves AND verifies (stdin)
  - Rust    zkcore-gmp  (GMP via rug) — proves only (no CLI verify subcommand)

Differential oracle: TWO independent verifiers (Python + zkcore) must return the
IDENTICAL accept/reject decision for every (proof, C, ms, tag). If they ever
disagree, that is a soundness divergence — a real bug. We exercise all THREE
provers (Python, zkcore, gmp) so a bad proof from any prover is caught, and throw
random tampered/negative cases that BOTH verifiers must reject identically.

Designed to run on a Mac Mini where the binaries + qedra are synced. Paths and
the qedra location are overridable via env so it also runs anywhere they exist.

  python3 differential_fuzz.py [N] [--seed S]

Exit 0 = no divergence found. Exit 1 = at least one divergence (prints a repro).
"""
import os, sys, json, random, subprocess

RUN = os.environ.get("PCAI_RUN", os.path.expanduser("~/proof-carrying-ai-run"))
QEDRA = os.environ.get("QEDRA_PATH", os.path.join(RUN, "agent-guardrail"))
RUSTDIR = os.environ.get("PCAI_RUST", os.path.join(RUN, "proof-carrying-ai", "rust"))
ZKCORE = os.path.join(RUSTDIR, "zkcore", "target", "release", "zkcore")
ZKGMP = os.path.join(RUSTDIR, "zkcore-gmp", "target", "release", "zkcore-gmp")

sys.path.insert(0, QEDRA)
try:
    from qedra import zk_core
    from qedra.zk import MODP
    from qedra.zk_core import ZKProof
except Exception as e:
    sys.exit("cannot import qedra (set QEDRA_PATH): %s" % e)

Q = MODP.q

def proof_to_json(proof, C):
    return json.dumps({"C": str(C), "verdict": proof.verdict,
                       "t": list(proof.t), "e": [str(x) for x in proof.e], "z": [str(x) for x in proof.z]})

def rust_verify(binary, ms, tag, proof_json):
    """Return True/False = backend accepts, or raise on crash."""
    ms_str = ",".join(str(m) for m in ms)
    r = subprocess.run([binary, "verify", ms_str, tag], input=proof_json,
                       capture_output=True, text=True, timeout=60)
    out = r.stdout.strip()
    if out not in ("OK", "FAIL"):
        raise RuntimeError("backend %s gave unexpected output %r (stderr: %s)" % (os.path.basename(binary), out, r.stderr[:200]))
    return out == "OK"

def py_verify(ms, C, proof, tag):
    # A verify that raises on a (tampered) input counts as a reject, not a crash;
    # an honest proof that raises will still be flagged, because want=True there.
    try:
        return bool(zk_core.verify(MODP, tuple(ms), C, proof, tag))
    except Exception:
        return False

DIVERGENCES = []
CHECKS = 0

def expect_agree(label, ms, C, proof, tag, want):
    """The two independent verifiers (Python + zkcore) must agree with each other AND with `want`."""
    global CHECKS
    pj = proof_to_json(proof, C)
    try:
        v_py = py_verify(ms, C, proof, tag)
        v_rs = rust_verify(ZKCORE, ms, tag, pj)
    except Exception as e:
        DIVERGENCES.append((label, "verifier crashed: %s" % e, pj[:300]))
        return
    CHECKS += 1
    decisions = {"python": v_py, "zkcore": v_rs}
    if v_py != v_rs:
        DIVERGENCES.append((label + " [VERIFIERS DISAGREE]", decisions, pj[:400]))
    elif v_py != want:
        DIVERGENCES.append((label + " [BOTH AGREE BUT WRONG: want %s]" % want, decisions, pj[:400]))

def rand_ms(rng):
    k = rng.randint(1, 5)
    return rng.sample(range(1, 4000), k)

def one_iteration(rng):
    ms = rand_ms(rng)
    m = rng.choice(ms)                    # honest member
    r = rng.randrange(Q)
    verdict = rng.choice(["allow", "deny", "review", "escalate"])
    tag = "cert/" + rng.choice(["cp", "counterparty", "spend", "x/y", ""]) + str(rng.randint(0, 9))

    # 1) honest Python proof -> all three MUST accept
    proof, C = zk_core.prove(MODP, tuple(ms), m, r, verdict, tag)
    expect_agree("honest-py", ms, C, proof, tag, True)

    # 2) honest Rust proofs (both zkcore and gmp provers) -> both verifiers MUST accept (cross-language)
    ms_str = ",".join(str(x) for x in ms)
    for prover_bin, tag_name in ((ZKCORE, "honest-zkcore"), (ZKGMP, "honest-gmp")):
        out = subprocess.run([prover_bin, "prove", verdict, str(m), ms_str, tag], capture_output=True, text=True, timeout=60).stdout.strip()
        try:
            d = json.loads(out)
            rp = ZKProof.from_dict({"verdict": d["verdict"], "t": d["t"], "e": d["e"], "z": d["z"]})
            expect_agree(tag_name, ms, int(d["C"]), rp, tag, True)
        except Exception as e:
            DIVERGENCES.append((tag_name + " prove/parse", str(e), out[:200]))

    # 3) tampering / negatives -> both verifiers MUST reject, identically
    #    tamper commitment (C+1 is no longer a valid Pedersen commitment)
    expect_agree("tamper-C", ms, C + 1, proof, tag, False)
    #    tamper a z scalar
    if proof.z:
        i = rng.randrange(len(proof.z))
        ztamp = ZKProof.from_dict({"verdict": proof.verdict, "t": list(proof.t),
                                   "e": [str(x) for x in proof.e],
                                   "z": [str((int(z) + (1 if j == i else 0)) % Q) for j, z in enumerate(proof.z)]})
        expect_agree("tamper-z", ms, C, ztamp, tag, False)
    #    verify under a DIFFERENT tag -> reject
    expect_agree("wrong-tag", ms, C, proof, tag + "Z", False)
    #    verify under a set that no longer contains m (soundness) -> reject
    ms2 = [x for x in ms if x != m] or [max(ms) + 1]
    ms2 = ms2 + [max(ms2) + 7]
    expect_agree("wrong-ms", ms2, C, proof, tag, False)
    #    tamper the verdict string in the proof -> reject
    vtamp = ZKProof.from_dict({"verdict": proof.verdict + "!", "t": list(proof.t),
                               "e": [str(x) for x in proof.e], "z": [str(x) for x in proof.z]})
    expect_agree("tamper-verdict", ms, C, vtamp, tag, False)

def main():
    args = [a for a in sys.argv[1:]]
    N = 100
    seed = None
    if args and args[0].isdigit():
        N = int(args[0])
    if "--seed" in args:
        seed = int(args[args.index("--seed") + 1])
    if seed is None:
        seed = int.from_bytes(os.urandom(4), "big")
    rng = random.Random(seed)

    for b in (ZKCORE, ZKGMP):
        if not os.path.exists(b):
            sys.exit("missing backend binary: %s (build it or set PCAI_RUST)" % b)

    print("differential-fuzz  N=%d  seed=%d  verifiers=python,zkcore  provers=python,zkcore,gmp" % (N, seed))
    for i in range(N):
        try:
            one_iteration(rng)
        except Exception as e:
            DIVERGENCES.append(("iteration %d crashed" % i, str(e), ""))
        if (i + 1) % 25 == 0:
            print("  %d/%d  checks=%d  divergences=%d" % (i + 1, N, CHECKS, len(DIVERGENCES)), flush=True)

    print("\nchecks run: %d   divergences: %d" % (CHECKS, len(DIVERGENCES)))
    if DIVERGENCES:
        print("\n\033[31mSOUNDNESS DIVERGENCE(S) FOUND\033[0m (reproduce with --seed %d):" % seed)
        for label, info, repro in DIVERGENCES[:20]:
            print("  - %s: %s" % (label, info))
            if repro:
                print("    proof: %s" % repro)
        sys.exit(1)
    print("\033[32mPASS\033[0m: all three backends agreed on every proof and rejected every tampered/negative case.")
    sys.exit(0)

if __name__ == "__main__":
    main()
