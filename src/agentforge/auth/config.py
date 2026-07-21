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
    operator_names: dict[str, str]          # subject -> display name, for a name-less issuer
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
    def userinfo_url(self) -> str:
        return f"{self.issuer.rstrip('/')}/userinfo"

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

        def name_map(name: str) -> dict[str, str]:
            """``sub=Display Name`` pairs, comma-separated.

            **The value must mirror the identity provider's own record for that subject.** This
            renders in the header as the answer to "who is signed in", so a name invented here is
            the console asserting an identity nobody verified — worse than showing the raw
            subject, because a uuid is obviously opaque while a plausible name is not. Take it
            from the IdP's account record, not from a git author, a ticket, or a guess.

            A local operator directory, needed because this issuer exposes no name by any route:
            its id_token carries aud/iss/iat/exp/sub/nonce, and the ``userinfo_endpoint`` its own
            discovery document advertises returns 404. The alternative — granting this dashboard
            ``user/Person.read`` so it can fetch its own operator's FHIR record — would hand a
            security console EMR read access to render a label, which is a bad trade. This is
            presentation only: authorization still matches on the verified ``sub``.
            """
            pairs = (p.split("=", 1) for p in os.environ.get(name, "").split(",") if "=" in p)
            return {k.strip(): v.strip() for k, v in pairs if k.strip() and v.strip()}

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
            operator_names=name_map("AGENTFORGE_SSO_OPERATOR_NAMES"),
            require_sso=os.environ.get("AGENTFORGE_SSO_REQUIRE", "0") in ("1", "true", "yes"),
            cookie_secure=os.environ.get("AGENTFORGE_SSO_COOKIE_SECURE",
                                         "1" if os.environ.get("PORT") else "0")
            in ("1", "true", "yes"),
        )
