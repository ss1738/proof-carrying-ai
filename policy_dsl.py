"""A general, composable policy DSL for agent actions.

Generalizes qedra's git-branch policy to arbitrary STRUCTURED agent actions (a payment, a tool call, a data
access). A policy is a conjunction of rules; the machine-checked compositional soundness is in
coq/PolicyDSL.v (ALLOW iff every rule passes; any violation forces BLOCK; adding a rule only restricts).

Each rule returns a decidable bool, mirroring the Coq `Rule := Action -> bool` exactly, so the runnable
policy and the proven model are the same object.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.expanduser("~/agent-guardrail"))
from qedra.guardrail import SECRET_RE  # reuse the tested secret detector

Rule = tuple  # (name: str, predicate: Callable[[dict], bool])


def spend_cap(limit: float) -> Rule:
    return (f"spend<= {limit}", lambda a: float(a.get("amount", 0)) <= limit)


def allowlist(field: str, allowed) -> Rule:
    allowed = set(allowed)
    return (f"{field} in allowlist", lambda a: a.get(field) in allowed)


def denylist(field: str, blocked) -> Rule:
    blocked = set(blocked)
    return (f"{field} not in denylist", lambda a: a.get(field) not in blocked)


def no_secret(field: str) -> Rule:
    return (f"no secret in {field}", lambda a: not SECRET_RE.search(str(a.get(field, ""))))


def residency(regions) -> Rule:
    regions = set(regions)
    return (f"region in {sorted(regions)}", lambda a: a.get("region") in regions)


def evaluate(policy, action: dict):
    """Return (verdict, failing_rule_or_None). Conjunction: ALLOW iff every rule passes.
    Matches coq/PolicyDSL.v `evaluate` = forallb over the rules."""
    for name, pred in policy:
        if not pred(action):
            return "BLOCK", name
    return "ALLOW", None
