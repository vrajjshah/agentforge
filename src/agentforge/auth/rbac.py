"""RBAC — only an authorized security-operator may hold a dashboard session.

Authorization is deny-by-default and evaluated server-side against the verified id_token claims,
never a request-supplied value. A principal is authorized iff it is on the operator allow-list
(matched by subject, fhirUser, or email) **or** the id_token carries a role the policy allows.
When no allow-list and no allowed roles are configured, access is refused (fail closed) — an
unconfigured deployment does not silently admit every OpenEMR user.
"""

from __future__ import annotations

from agentforge.auth.config import SsoConfig
from agentforge.auth.session import OperatorSession


def is_authorized(session: OperatorSession, cfg: SsoConfig) -> bool:
    identifiers = {v for v in (session.subject, session.fhir_user, session.email) if v}
    on_allowlist = bool(cfg.operator_allowlist) and bool(identifiers & set(cfg.operator_allowlist))
    has_role = bool(cfg.operator_roles) and bool(set(session.roles) & set(cfg.operator_roles))
    # Fail closed: with neither an allow-list match nor an allowed role, deny.
    return on_allowlist or has_role
