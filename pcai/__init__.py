"""pcai -- proof-carrying compliance certificates for AI agent actions.

A certificate proves, in zero knowledge, that an agent action obeyed a formal policy (spend_cap + allowlist),
verifiable from public data alone and unforgeable. See certificate.issue / Certificate.verify.
"""
from .certificate import Certificate, issue, policy_id

__all__ = ["Certificate", "issue", "policy_id"]
__version__ = "0.3.1"
