"""pcai CLI: keygen, certify, verify. Turns the library into a usable tool.

    pcai keygen                                          -> writes ~/.pcai/signing_key, prints public key
    pcai certify --amount 750 --counterparty alice \\
                 --cap 1000 --allow alice,bob --out cert.json
    pcai verify cert.json --cap 1000 --allow alice,bob --pubkey <hex>
"""
from __future__ import annotations

import argparse
import os
import sys

from .certificate import Certificate, issue


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

    c = sub.add_parser("certify", help="issue a certificate for an agent action")
    c.add_argument("--amount", type=int, required=True)
    c.add_argument("--counterparty", required=True)
    c.add_argument("--cap", type=int, required=True)
    c.add_argument("--allow", required=True, help="comma-separated allowlist")
    c.add_argument("--out", help="write certificate JSON here (default: stdout)")

    v = sub.add_parser("verify", help="verify a certificate")
    v.add_argument("cert")
    v.add_argument("--cap", type=int, required=True)
    v.add_argument("--allow", required=True)
    v.add_argument("--pubkey", required=True)

    args = ap.parse_args(argv)

    if args.cmd == "keygen":
        key = _load_or_create_key(args.key)
        print(key.public_key().public_bytes_raw().hex())
        return 0

    if args.cmd == "certify":
        key = _load_or_create_key(args.key)
        policy = {"spend_cap": args.cap, "allowlist": args.allow.split(",")}
        try:
            cert = issue({"amount": args.amount, "counterparty": args.counterparty}, policy, key)
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
        policy = {"spend_cap": args.cap, "allowlist": args.allow.split(",")}
        ok, reason = cert.verify(policy, args.pubkey)
        print(f"{'VALID' if ok else 'INVALID'}: {reason}")
        return 0 if ok else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
