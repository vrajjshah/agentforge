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
from jwt.exceptions import PyJWKClientError

from agentforge.auth.config import SsoConfig
from agentforge.auth.session import OperatorSession


class SigningKeyProvider(Protocol):
    def get_signing_key_from_jwt(self, token: str) -> Any: ...

    def get_jwk_set(self) -> Any:
        """The parsed key set, used to recover from a JWKS published without a ``kid``.

        Defaulted so a test double need only supply the lookup it exercises.
        """
        raise PyJWKClientError("no key set available")


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
            "code_verifier": verifier,
        }
        # A confidential client authenticates with its secret; a public client relies on PKCE alone
        # (no secret to leak) — OpenEMR's dynamic registration issues public clients by default.
        if self._cfg.client_secret:
            data["client_secret"] = self._cfg.client_secret
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.post(self._cfg.token_url, data=data)
        except (httpx.TimeoutException, httpx.TransportError) as exc:
            raise OidcError(f"token endpoint unreachable: {exc}") from exc
        if resp.status_code != 200:
            # Carry the provider's own error through. It is logged server-side and never rendered
            # to the browser, and it is the difference between "the client is not enabled / needs a
            # secret" (invalid_client) and "the code was already used" (invalid_grant) — a
            # distinction a bare status code cannot make, and the one that costs a debugging cycle.
            raise OidcError(
                f"token exchange failed (HTTP {resp.status_code}): "
                f"{resp.text[:300].replace(chr(10), ' ')}"
            )
        payload = resp.json()
        if "id_token" not in payload:
            raise OidcError("token response has no id_token")
        return dict(payload)

    async def fetch_userinfo(self, access_token: str) -> dict[str, Any]:
        """Profile claims from the OIDC userinfo endpoint. Never fatal, never authoritative.

        OpenEMR's id_token carries only the authentication assertion — aud/iss/iat/exp/sub/nonce
        (``IdTokenSMARTResponse::getBuilder``) — so a display name is simply not in there, which is
        exactly what userinfo is specified for. The id_token stays the sole source of the
        *authorization* identity: ``sub`` is verified against the issuer's signature, and nothing
        fetched here is allowed to change who the caller is. This supplies presentation detail
        only, and a failure returns ``{}`` — a cosmetic lookup must never fail a login.
        """
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(self._cfg.userinfo_url,
                                        headers={"Authorization": f"Bearer {access_token}"})
            if resp.status_code != 200:
                return {}
            payload = resp.json()
            return dict(payload) if isinstance(payload, dict) else {}
        except (httpx.HTTPError, ValueError):
            return {}

    def _signing_key(self, id_token: str) -> Any:
        """Resolve the issuer's signing key, tolerating a JWK Set published without a ``kid``.

        PyJWT selects signing keys with ``public_key_use in ("sig", None) and key_id`` — that
        trailing clause makes a key without a ``kid`` invisible to it, and the resulting error
        ("The JWKS endpoint did not contain any signing keys") describes an empty key set rather
        than the filter that emptied it. OpenEMR publishes exactly one RSA key with ``use: sig``
        and no ``kid``, which RFC 7517 explicitly permits — ``kid`` is OPTIONAL, and it is a
        *selector* for choosing among several keys, not a security control.

        So when the strict lookup finds nothing, fall back to the sole published signing key.
        This does not weaken verification: the signature is still checked against a key fetched
        from the issuer's own JWKS over TLS. It is refused when the set holds more than one
        candidate, because then the missing ``kid`` genuinely is ambiguous and picking one would
        be guessing which key signed the token.
        """
        if self._jwks is None:
            self._jwks = jwt.PyJWKClient(self._cfg.jwks_uri)
        try:
            return self._jwks.get_signing_key_from_jwt(id_token)
        except PyJWKClientError:
            # Reuses the client's cached, already-parsed key set — no second fetch.
            candidates = [k for k in self._jwks.get_jwk_set().keys
                          if k.public_key_use in ("sig", None)]
            if len(candidates) != 1:
                raise
            return candidates[0]

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
        """RFC 7591 dynamic client registration. Returns the issued client_id/secret.

        ``application_type`` must be ``private``, and it is the whole ballgame on OpenEMR. Its
        registration handler issues a ``client_secret`` **only** for that value
        (``AuthorizationController::clientRegistration``); anything else — including the
        RFC-conventional ``web`` we sent originally — produces a *public* client with an empty
        secret. That is unusable here, because this issuer's discovery advertises
        ``token_endpoint_auth_methods_supported: ["client_secret_post"]`` and nothing else, so the
        token exchange has no way to authenticate and fails with ``invalid_client`` *after* a
        successful authorize — which is exactly the symptom we chased.

        The same flag also sets ``client_role`` to ``user`` rather than ``patient``, which routes
        the operator to the provider login instead of the patient portal. Both properties are
        wanted; both come from this one field.
        """
        body = {
            "application_type": "private",
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


def claims_to_session(claims: dict[str, Any],
                      profile: dict[str, Any] | None = None) -> OperatorSession:
    """Map verified id_token claims to an OperatorSession (server-resolved identity).

    ``profile`` is optional, unverified presentation detail from the userinfo endpoint. It may
    only supply a display name and email; ``sub`` — the value RBAC authorizes against — is taken
    from the verified id_token and never from here.
    """
    if profile:
        # Presentation fields only, and only where the id_token left a gap.
        claims = {**{k: v for k, v in profile.items()
                     if k in ("name", "given_name", "family_name", "preferred_username", "email")
                     and not claims.get(k)},
                  **claims}
    # Whitespace-collapsed, because an IdP's idea of a full name is whatever its SQL produced:
    # OpenEMR builds this as CONCAT(fname, ' ', lname), so an account with no first name yields
    # " Administrator" — a leading space that renders straight into the page.
    def _clean(value: object) -> str:
        return " ".join(str(value).split()) if value else ""

    name = (_clean(claims.get("name"))
            or _clean(f"{claims.get('given_name') or ''} {claims.get('family_name') or ''}")
            or _clean(claims.get("preferred_username"))
            or _clean(claims.get("email"))
            or _clean(claims.get("sub")))
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
