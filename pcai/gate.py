"""pcai.gate -- the integration surface: wrap an agent's action function so every call is checked against a
policy and, when allowed, carries a proof-carrying certificate. Non-compliant calls raise PolicyViolation and
the underlying action never runs.

    send = gate(policy, key)(send_payment)          # or @gate(policy, key)
    out = send({"amount": 750, "counterparty": "alice"})
    out.result       # whatever send_payment returned
    out.certificate  # a Certificate proving the call obeyed the policy, verifiable by anyone

This is how a real agent integrates: decorate the tool that moves money / touches data, and its outputs come
with a verifiable compliance proof instead of a trust-me log line.
"""
from __future__ import annotations

from dataclasses import dataclass
from functools import wraps

from .certificate import Certificate, issue


class PolicyViolation(Exception):
    """Raised when an action fails policy; the wrapped function is NOT executed."""


@dataclass
class GatedResult:
    result: object
    certificate: Certificate


def gate(policy: dict, signing_key):
    """Decorator: gate an action function `fn(action: dict, ...)` on `policy`. Issues a certificate BEFORE
    running fn (a non-compliant action cannot be certified, so it is blocked before execution)."""
    def deco(fn):
        @wraps(fn)
        def wrapper(action: dict, *args, **kwargs) -> GatedResult:
            try:
                cert = issue(action, policy, signing_key)   # proves compliance, or raises
            except ValueError as e:
                raise PolicyViolation(str(e)) from None
            result = fn(action, *args, **kwargs)             # only runs if certified
            return GatedResult(result=result, certificate=cert)
        return wrapper
    return deco
