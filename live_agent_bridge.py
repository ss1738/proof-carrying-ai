"""live_agent_bridge.py -- a REAL agent action, end to end, carrying its own proof.

Not a demo dict. The input is what an agent actually proposes through qedra: a git tool call (the `git` MCP
tool / git pre-hook), and a Claude Code `PreToolUse` Bash payload. We parse each into a qedra Action exactly
as qedra's executor does, run it through qedra's ACTUAL gate (Guardrail.check), and emit a proof-carrying
certificate when the action is ALLOWED and in the ZK-covered (git-branch) domain:

    - a ZERO-KNOWLEDGE proof that the action lies in the policy's allowed set  (qedra zk.prove_action),
    - an ED25519 SIGNATURE over the certificate, using qedra's session signing key (~/.qedra/signing_key).

`verify_receipt` re-checks BOTH independently, from public data + the pinned public key -- no trust in this
process, the agent, or the operator. A blocked action yields no compliance proof (you cannot certify
compliance of a non-compliant action); an ALLOWED action outside the ZK domain is a signed decision only,
honestly labelled. Tampering breaks the signature.

    python3 live_agent_bridge.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.expanduser("~/agent-guardrail"))
from qedra import zk
from qedra.attest_cli import _load_or_create_key
from qedra.claude_code_hook import action_from_tool_call
from qedra.guardrail import Action, Guardrail
from qedra.zk_core import ZKProof


def git_action(args: str) -> Action:
    """Parse a git tool call into a qedra Action, mirroring qedra.executor.git exactly."""
    toks = args.split()
    op = toks[0] if toks else ""
    force = "--force" in toks or "-f" in toks
    hard = "--hard" in toks
    branch = next((t for t in toks if t in ("main", "master", "release", "dev", "feature")), "")
    if op in ("push", "reset", "rebase") and not branch:
        branch = "main"
    return Action("git", op=op, branch=branch, force=force, hard=hard)


def _canonical(body: dict) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode()


def certify(action: Action, guard: Guardrail, key) -> dict:
    """Gate a real action through qedra and return a signed, proof-carrying receipt."""
    decision = guard.check(action)                          # qedra's REAL gate
    body = {"verdict": decision.verdict, "reason": decision.reason, "summary": decision.action_summary}
    if decision.verdict == "ALLOW" and zk.supports(action):
        C, proof, _r = zk.prove_action(action)             # ZK proof of compliance
        body["zk"] = {"C": str(C), "proof": proof.to_dict()}
    else:
        body["zk"] = None                                  # blocked, or outside the ZK domain
    sig = key.sign(_canonical(body)).hex()
    return {**body, "sig": sig, "pubkey": key.public_key().public_bytes_raw().hex()}


def verify_receipt(receipt: dict, pin_pubkey: str) -> tuple[bool, str]:
    """Independently verify a receipt from public data + a pinned key. A receipt is valid iff its signature
    checks out AND, when it carries a ZK compliance claim, that claim verifies."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    if receipt.get("pubkey") != pin_pubkey:
        return False, "public key does not match the pinned key"
    body = {k: receipt[k] for k in ("verdict", "reason", "summary", "zk")}
    try:
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(pin_pubkey)).verify(
            bytes.fromhex(receipt["sig"]), _canonical(body))
    except InvalidSignature:
        return False, "signature invalid (receipt tampered)"

    if body["zk"] is None:
        return True, f"signed decision '{body['verdict']}' (no ZK compliance cert)"
    C = int(body["zk"]["C"])
    if not zk.verify(C, ZKProof.from_dict(body["zk"]["proof"])):
        return False, "ZK compliance proof does not verify"
    return True, "signature valid AND ZK compliance proof verifies"


if __name__ == "__main__":
    guard = Guardrail()
    key = _load_or_create_key(os.path.expanduser("~/.qedra/signing_key"))
    pin = key.public_key().public_bytes_raw().hex()
    print("== Live agent action -> proof-carrying certificate ==")
    print(f"pinned verifier key: {pin[:16]}...\n")

    cases = [
        ("git",  "commit -m 'add tests'",       "git commit"),          # ALLOW, in ZK domain -> cert
        ("git",  "push --force main",            "force-push to main"),  # BLOCK -> no cert
        ("git",  "push feature",                 "push a feature branch"),  # ALLOW, in ZK domain -> cert
        ("bash", "pytest -q",                    "run tests (shell)"),   # ALLOW, outside ZK domain
    ]
    receipts = []
    for kind, arg, label in cases:
        action = git_action(arg) if kind == "git" else action_from_tool_call("Bash", {"command": arg})
        r = certify(action, guard, key)
        ok, why = verify_receipt(r, pin)
        cert = "ZK-cert" if r.get("zk") else "signed "
        print(f"  {r['verdict']:8} [{cert}] {label:24} -> verify {'OK' if ok else 'FAIL'}  ({why})")
        receipts.append(r)

    # tamper: flip the force-push BLOCK to ALLOW -> signature must fail
    tampered = dict(receipts[1]); tampered["verdict"] = "ALLOW"
    ok_t, why_t = verify_receipt(tampered, pin)
    print(f"\n  tampered force-push BLOCK->ALLOW           -> verify {'OK (BUG)' if ok_t else 'FAIL'}  ({why_t})")

    zk_certs = sum(1 for r in receipts if r.get("zk") and verify_receipt(r, pin)[0])
    good = all(verify_receipt(r, pin)[0] for r in receipts) and (not ok_t) and zk_certs >= 2
    print(f"\n{'PASS' if good else 'FAIL'}: real agent actions carry ZK + signed compliance certificates "
          f"({zk_certs} ZK certs), verifiable by anyone; tampering is caught.")
    raise SystemExit(0 if good else 1)
