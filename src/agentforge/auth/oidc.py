"""OpenEMR OIDC client — the authorization-code + PKCE flow, with real token verification.

Security properties enforced here (beyond a TLS-trust shortcut):
  * the id_token **signature is verified against the issuer's JWKS** (RS256);
  * ``iss`` and ``aud`` are checked, ``exp`` is enforced, and the ``nonce`` must match the one this
    server minted for the flow (binds the token to the request, defeats replay/injection);
  * endpoints are derived from the configured issuer, never a caller-supplied value.

I/O (token exchange, dynamic registration) uses httpx; verification is synchronous PyJWT so it can
be unit-tested with an injected signing key and no network.
"""

from __future__ import annotations

import urllib.parse
from typing import Any, Protocol

import httpx
import jwt

from agentforge.auth.config import SsoConfig
from agentforge.auth.session import OperatorSession


class SigningKeyProvider(Protocol):
    def get_signing_key_from_jwt(self, token: str) -> Any: ...


class OidcError(RuntimeError):
    """A recoverable OIDC failure (bad token, exchange failure) — surfaced as a 4xx, never 500."""


class OidcClient:
    def __init__(self, cfg: SsoConfig, *, jwks_client: SigningKeyProvider | None = None,
                 timeout: float = 20.0) -> None:
        self._cfg = cfg
        self._jwks = jwks_client
        self._timeout = timeout

    def authorize_redirect(self, state: str, challenge: str, nonce: str) -> str:
        params = {
            "response_type": "code",
            "client_id": self._cfg.client_id,
            "redirect_uri": self._cfg.redirect_uri,
            "scope": self._cfg.scope,
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        }
        return f"{self._cfg.authorize_url}?{urllib.parse.urlencode(params)}"

    async def exchange_code(self, code: str, verifier: str, redirect_uri: str) -> dict[str, Any]:
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": self._cfg.client_id,
            "client_secret": self._cfg.client_secret,
            "code_verifier": verifier,
        }
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(self._cfg.token_url, data=data)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise OidcError(f"token endpoint unreachable: {exc}") from exc
        if resp.status_code != 200:
            raise OidcError(f"token exchange failed (HTTP {resp.status_code})")
        payload = resp.json()
        if "id_token" not in payload:
            raise OidcError("token response has no id_token")
        return dict(payload)

    def _signing_key(self, id_token: str) -> Any:
        if self._jwks is None:
            self._jwks = jwt.PyJWKClient(self._cfg.jwks_uri)
        return self._jwks.get_signing_key_from_jwt(id_token)

    def verify_id_token(self, id_token: str, expected_nonce: str) -> dict[str, Any]:
        """Verify signature + claims and return the trusted claim set. Raises ``OidcError``."""
        try:
            key = self._signing_key(id_token)
            claims: dict[str, Any] = jwt.decode(
                id_token,
                key.key,
                algorithms=["RS256"],
                audience=self._cfg.client_id,
                issuer=self._cfg.issuer,
                leeway=30,
                options={"require": ["exp", "iss", "aud", "sub"]},
            )
        except jwt.PyJWTError as exc:
            raise OidcError(f"id_token verification failed: {exc}") from exc
        if expected_nonce and claims.get("nonce") != expected_nonce:
            raise OidcError("id_token nonce mismatch (possible replay)")
        return claims

    async def register_client(self, redirect_uri: str, client_name: str) -> dict[str, Any]:
        """RFC 7591 dynamic client registration. Returns the issued client_id/secret."""
        body = {
            "application_type": "web",
            "client_name": client_name,
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": "client_secret_post",  # nosec B105 - OAuth method name
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "scope": self._cfg.scope,
        }
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(self._cfg.registration_url, json=body)
        if resp.status_code not in (200, 201):
            raise OidcError(
                f"client registration failed (HTTP {resp.status_code}): {resp.text[:200]}")
        return dict(resp.json())


def claims_to_session(claims: dict[str, Any]) -> OperatorSession:
    """Map verified id_token claims to an OperatorSession (server-resolved identity)."""
    name = (claims.get("name")
            or " ".join(x for x in (claims.get("given_name"), claims.get("family_name")) if x)
            or claims.get("preferred_username")
            or claims.get("email")
            or claims.get("sub", "operator"))
    roles = claims.get("roles") or claims.get("role") or claims.get("groups") or []
    if isinstance(roles, str):
        roles = [roles]
    return OperatorSession(
        subject=str(claims["sub"]),
        name=str(name),
        email=claims.get("email"),
        fhir_user=claims.get("fhirUser"),
        roles=tuple(str(r) for r in roles),
    )
