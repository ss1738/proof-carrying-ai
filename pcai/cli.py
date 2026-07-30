"""pcai CLI: keygen, certify, verify. Turns the library into a usable tool.

    pcai keygen                                          -> writes ~/.pcai/signing_key, prints public key
    pcai certify --amount 750 --counterparty alice \\
                 --cap 1000 --allow alice,bob --out cert.json
    pcai verify cert.json --cap 1000 --allow alice,bob --pubkey <hex>
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from .certificate import Certificate, issue


def _json_arg(s: str):
    """Parse a JSON value from a string, or from a file if it starts with '@'."""
    if s.startswith("@"):
        with open(os.path.expanduser(s[1:])) as f:
            return json.load(f)
    return json.loads(s)


def _load_or_create_key(path: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path = os.path.expanduser(path)
    if os.path.exists(path):
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(open(path).read().strip()))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    key = Ed25519PrivateKey.generate()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(key.private_bytes_raw().hex())
    return key


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="pcai", description="proof-carrying compliance certificates")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ap.add_argument("--key", default="~/.pcai/signing_key", help="Ed25519 signing key (created on first use)")

    sub.add_parser("keygen", help="create/print the signing key's public key")

    s = sub.add_parser("serve", help="run the HTTP service (POST /certify, /verify; GET /health)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8787)

    b = sub.add_parser("bench", help="measure issue/verify time and certificate size for both backends")
    b.add_argument("-n", type=int, default=10, help="repetitions")

    c = sub.add_parser("certify", help="issue a certificate for an agent action")
    c.add_argument("--action", help="action as JSON (or @file) -- for general policies")
    c.add_argument("--policy", help="policy as JSON (or @file) -- e.g. '{\"rules\":[{\"type\":\"max\",...}]}'")
    c.add_argument("--amount", type=int, help="payment shorthand: amount")
    c.add_argument("--counterparty", help="payment shorthand: counterparty")
    c.add_argument("--cap", type=int, help="payment shorthand: spend cap")
    c.add_argument("--allow", help="payment shorthand: comma-separated allowlist")
    c.add_argument("--region", help="the action's region (only if --regions is given)")
    c.add_argument("--regions", help="comma-separated allowed regions (residency rule)")
    c.add_argument("--out", help="write certificate JSON here (default: stdout)")

    v = sub.add_parser("verify", help="verify a certificate")
    v.add_argument("cert")
    v.add_argument("--policy", help="policy as JSON (or @file); must match the one used to certify")
    v.add_argument("--cap", type=int, help="payment shorthand: spend cap")
    v.add_argument("--allow", help="payment shorthand: allowlist")
    v.add_argument("--regions", help="comma-separated allowed regions (must match certify)")
    v.add_argument("--pubkey", required=True)

    args = ap.parse_args(argv)

    if args.cmd == "keygen":
        key = _load_or_create_key(args.key)
        print(key.public_key().public_bytes_raw().hex())
        return 0

    if args.cmd == "serve":
        from .server import serve
        serve(_load_or_create_key(args.key), args.host, args.port)
        return 0

    if args.cmd == "bench":
        import time
        key = _load_or_create_key(args.key)
        pub = key.public_key().public_bytes_raw().hex()
        policy = {"spend_cap": 1000, "allowlist": ["alice", "bob"]}
        action = {"amount": 750, "counterparty": "alice"}
        print(f"{'backend':13} {'issue (ms)':>11} {'verify (ms)':>12} {'size (B)':>10}  (n={args.n}, MEASURED)")
        for kind in ("bulletproofs", "bitwise"):
            t0 = time.perf_counter()
            for _ in range(args.n):
                cert = issue(action, policy, key, range_proof=kind)
            it = (time.perf_counter() - t0) / args.n * 1000
            t0 = time.perf_counter()
            for _ in range(args.n):
                cert.verify(policy, pub)
            vt = (time.perf_counter() - t0) / args.n * 1000
            size = len(cert.to_json(indent=None).encode())
            print(f"{kind:13} {it:>11.0f} {vt:>12.0f} {size:>10,}")
        return 0

    if args.cmd == "certify":
        key = _load_or_create_key(args.key)
        if args.policy:
            policy = _json_arg(args.policy)
            action = _json_arg(args.action) if args.action else {}
        else:
            policy = {"spend_cap": args.cap, "allowlist": (args.allow or "").split(",")}
            action = {"amount": args.amount, "counterparty": args.counterparty}
            if args.regions:
                policy["residency"] = args.regions.split(",")
                action["region"] = args.region
        try:
            cert = issue(action, policy, key)
        except ValueError as e:
            print(f"REFUSED: {e} (a non-compliant action cannot be certified)", file=sys.stderr)
            return 1
        out = cert.to_json()
        if args.out:
            open(args.out, "w").write(out)
            print(f"wrote {args.out} (pubkey {cert.pubkey[:16]}...)")
        else:
            print(out)
        return 0

    if args.cmd == "verify":
        cert = Certificate.from_json(open(args.cert).read())
        if args.policy:
            policy = _json_arg(args.policy)
        else:
            policy = {"spend_cap": args.cap, "allowlist": (args.allow or "").split(",")}
            if args.regions:
                policy["residency"] = args.regions.split(",")
        ok, reason = cert.verify(policy, args.pubkey)
        print(f"{'VALID' if ok else 'INVALID'}: {reason}")
        return 0 if ok else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
