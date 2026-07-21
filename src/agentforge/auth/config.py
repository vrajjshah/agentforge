"""SSO configuration — OpenEMR OIDC endpoints, client credentials, and the RBAC policy.

Endpoints are derived from the issuer (never a caller-supplied value), matching OpenEMR's OIDC
discovery. The dashboard requires SSO only when ``require_sso`` is set; the public demo instance
leaves it off so a reviewer can inspect the read view, while every *mutating* action stays
SSO+RBAC gated. Production sets ``AGENTFORGE_SSO_REQUIRE=1``.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class SsoConfig:
    client_id: str
    client_secret: str
    issuer: str
    redirect_uri: str
    scope: str
    operator_allowlist: tuple[str, ...]     # authorized principals (sub / fhirUser / email)
    operator_roles: tuple[str, ...]         # authorized role claims, if the id_token carries roles
    require_sso: bool
    cookie_secure: bool

    @property
    def enabled(self) -> bool:
        """SSO can run once a client is registered. The secret is optional — a public client
        (OpenEMR's default from dynamic registration) is secured by PKCE, not a secret."""
        return bool(self.client_id and self.redirect_uri)

    @property
    def authorize_url(self) -> str:
        return f"{self.issuer.rstrip('/')}/authorize"

    @property
    def token_url(self) -> str:
        return f"{self.issuer.rstrip('/')}/token"

    @property
    def jwks_uri(self) -> str:
        return f"{self.issuer.rstrip('/')}/jwk"

    @property
    def registration_url(self) -> str:
        return f"{self.issuer.rstrip('/')}/registration"

    @classmethod
    def from_env(cls) -> SsoConfig:
        def csv(name: str, default: str = "") -> tuple[str, ...]:
            raw = os.environ.get(name, default)
            return tuple(x.strip() for x in raw.split(",") if x.strip())

        return cls(
            client_id=os.environ.get("AGENTFORGE_SSO_CLIENT_ID", ""),
            client_secret=os.environ.get("AGENTFORGE_SSO_CLIENT_SECRET", ""),
            issuer=os.environ.get("AGENTFORGE_SSO_ISSUER",
                                  "https://45-55-53-165.sslip.io/oauth2/default"),
            redirect_uri=os.environ.get("AGENTFORGE_SSO_REDIRECT_URI", ""),
            scope=os.environ.get("AGENTFORGE_SSO_SCOPE", "openid profile email fhirUser"),
            operator_allowlist=csv("AGENTFORGE_SSO_OPERATOR_ALLOWLIST"),
            operator_roles=csv("AGENTFORGE_SSO_OPERATOR_ROLES",
                               "admin,security-operator,administrator"),
            require_sso=os.environ.get("AGENTFORGE_SSO_REQUIRE", "0") in ("1", "true", "yes"),
            cookie_secure=os.environ.get("AGENTFORGE_SSO_COOKIE_SECURE",
                                         "1" if os.environ.get("PORT") else "0")
            in ("1", "true", "yes"),
        )
