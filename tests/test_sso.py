"""SSO security unit tests — PKCE, id_token verification, RBAC, session lifecycle.

Uses a real RSA keypair to sign test id_tokens (RS256) and an injected signing-key provider, so
the verification path is exercised end-to-end with no network. Each negative case asserts a
specific attack is refused: replay (nonce), expiry, wrong audience, wrong issuer, forged signature,
CSRF/state replay, and RBAC deny.
"""

from __future__ import annotations

import base64
import hashlib
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives.asymmetric import rsa

from agentforge.auth.config import SsoConfig
from agentforge.auth.oidc import OidcClient, OidcError, claims_to_session
from agentforge.auth.pkce import pkce_pair
from agentforge.auth.rbac import is_authorized
from agentforge.auth.session import AuthFlow, AuthFlowStore, OperatorSession, SessionStore

_ISSUER = "https://emr.test/oauth2/default"
_CLIENT = "af-client-123"


def _cfg(**kw: Any) -> SsoConfig:
    base = dict(client_id=_CLIENT, client_secret="secret", issuer=_ISSUER,
                redirect_uri="https://af.test/callback", scope="openid profile email fhirUser",
                operator_allowlist=(), operator_roles=("admin", "security-operator"),
                require_sso=True, cookie_secure=True)
    base.update(kw)
    return SsoConfig(**base)  # type: ignore[arg-type]


@dataclass
class _Key:
    key: Any


class _FakeJwks:
    def __init__(self, public_key: Any) -> None:
        self._pub = public_key

    def get_signing_key_from_jwt(self, token: str) -> _Key:
        return _Key(self._pub)


@pytest.fixture(scope="module")
def rsa_keys() -> tuple[Any, Any]:
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


def _id_token(priv: Any, *, sub: str = "user-1", nonce: str = "N", aud: str = _CLIENT,
              iss: str = _ISSUER, exp_delta: int = 300, extra: dict[str, Any] | None = None) -> str:
    claims = {"sub": sub, "aud": aud, "iss": iss, "nonce": nonce,
              "iat": int(time.time()), "exp": int(time.time()) + exp_delta,
              "name": "Dr Ada Lovelace", "email": "ada@emr.test"}
    if extra:
        claims.update(extra)
    return jwt.encode(claims, priv, algorithm="RS256")


# --- PKCE ------------------------------------------------------------------------------------
def test_pkce_pair_is_valid_s256() -> None:
    verifier, challenge = pkce_pair()
    assert 43 <= len(verifier) <= 128
    digest = hashlib.sha256(verifier.encode()).digest()
    assert challenge == base64.urlsafe_b64encode(digest).decode().rstrip("=")


# --- authorize URL ---------------------------------------------------------------------------
def test_authorize_redirect_carries_pkce_and_state() -> None:
    url = OidcClient(_cfg()).authorize_redirect("STATE", "CHAL", "NONCE")
    assert url.startswith(_ISSUER + "/authorize?")
    for frag in ("client_id=af-client-123", "code_challenge=CHAL", "code_challenge_method=S256",
                 "state=STATE", "nonce=NONCE", "response_type=code"):
        assert frag in url


# --- id_token verification -------------------------------------------------------------------
def test_verify_valid_id_token(rsa_keys: tuple[Any, Any]) -> None:
    priv, pub = rsa_keys
    client = OidcClient(_cfg(), jwks_client=_FakeJwks(pub))
    claims = client.verify_id_token(_id_token(priv, nonce="N1"), "N1")
    assert claims["sub"] == "user-1" and claims["email"] == "ada@emr.test"


def test_verify_rejects_nonce_mismatch(rsa_keys: tuple[Any, Any]) -> None:
    priv, pub = rsa_keys
    client = OidcClient(_cfg(), jwks_client=_FakeJwks(pub))
    with pytest.raises(OidcError, match="nonce"):
        client.verify_id_token(_id_token(priv, nonce="attacker"), "expected")


def test_verify_rejects_expired(rsa_keys: tuple[Any, Any]) -> None:
    priv, pub = rsa_keys
    client = OidcClient(_cfg(), jwks_client=_FakeJwks(pub))
    with pytest.raises(OidcError):
        client.verify_id_token(_id_token(priv, exp_delta=-60), "N")


def test_verify_rejects_wrong_audience(rsa_keys: tuple[Any, Any]) -> None:
    priv, pub = rsa_keys
    client = OidcClient(_cfg(), jwks_client=_FakeJwks(pub))
    with pytest.raises(OidcError):
        client.verify_id_token(_id_token(priv, aud="someone-else"), "N")


def test_verify_rejects_wrong_issuer(rsa_keys: tuple[Any, Any]) -> None:
    priv, pub = rsa_keys
    client = OidcClient(_cfg(), jwks_client=_FakeJwks(pub))
    with pytest.raises(OidcError):
        client.verify_id_token(_id_token(priv, iss="https://evil.test"), "N")


def test_verify_rejects_forged_signature(rsa_keys: tuple[Any, Any]) -> None:
    _priv, pub = rsa_keys
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    # Signed by the attacker's key, but verified against the real public key → fails.
    client = OidcClient(_cfg(), jwks_client=_FakeJwks(pub))
    with pytest.raises(OidcError):
        client.verify_id_token(_id_token(attacker, nonce="N"), "N")


# --- token exchange (respx) ------------------------------------------------------------------
def test_public_client_is_enabled_without_secret() -> None:
    assert _cfg(client_secret="").enabled is True  # public client + PKCE, no secret needed


@respx.mock
async def test_public_client_exchange_omits_secret() -> None:
    captured: dict[str, Any] = {}

    def _capture(request: httpx.Request) -> httpx.Response:
        captured["body"] = request.content.decode()
        return httpx.Response(200, json={"id_token": "x"})

    respx.post(_ISSUER + "/token").mock(side_effect=_capture)
    await OidcClient(_cfg(client_secret="")).exchange_code("c", "v", "https://af.test/callback")
    assert "client_secret" not in captured["body"]  # public client sends no secret
    assert "code_verifier=v" in captured["body"]     # PKCE secures it instead


@respx.mock
async def test_exchange_code_success(rsa_keys: tuple[Any, Any]) -> None:
    priv, _ = rsa_keys
    respx.post(_ISSUER + "/token").mock(return_value=httpx.Response(
        200, json={"access_token": "a", "id_token": _id_token(priv)}))
    out = await OidcClient(_cfg()).exchange_code("code", "verifier", "https://af.test/callback")
    assert "id_token" in out


@respx.mock
async def test_exchange_code_failure_is_oidc_error() -> None:
    respx.post(_ISSUER + "/token").mock(return_value=httpx.Response(400, json={"error": "bad"}))
    with pytest.raises(OidcError):
        await OidcClient(_cfg()).exchange_code("code", "verifier", "https://af.test/callback")


# --- claims → session + RBAC -----------------------------------------------------------------
def test_claims_to_session_and_rbac_role() -> None:
    sess = claims_to_session({"sub": "u1", "email": "ada@emr.test", "roles": "admin",
                              "fhirUser": "Practitioner/9"})
    assert sess.name == "Dr Ada Lovelace" or sess.email == "ada@emr.test"
    assert is_authorized(sess, _cfg()) is True  # role "admin" allowed


def test_rbac_allowlist_match() -> None:
    sess = OperatorSession(subject="u1", name="X", email="ops@emr.test", fhir_user=None)
    cfg = _cfg(operator_roles=(), operator_allowlist=("ops@emr.test",))
    assert is_authorized(sess, cfg) is True


def test_rbac_denies_unknown_principal() -> None:
    sess = OperatorSession(subject="stranger", name="X", email="x@emr.test", fhir_user=None)
    cfg = _cfg(operator_allowlist=("ops@emr.test",), operator_roles=())
    assert is_authorized(sess, cfg) is False


def test_rbac_fails_closed_when_unconfigured() -> None:
    sess = OperatorSession(subject="anyone", name="X", email="x@emr.test", fhir_user=None,
                           roles=("clinician",))
    assert is_authorized(sess, _cfg(operator_allowlist=(), operator_roles=())) is False


# --- session + auth-flow stores --------------------------------------------------------------
def test_session_store_lifecycle() -> None:
    store = SessionStore(ttl_seconds=100)
    s = OperatorSession(subject="u1", name="X", email=None, fhir_user=None)
    store.set("sid", s)
    assert store.get("sid") == s
    store.delete("sid")
    assert store.get("sid") is None


def test_session_store_expiry() -> None:
    store = SessionStore(ttl_seconds=-1)  # already expired
    store.set("sid", OperatorSession(subject="u1", name="X", email=None, fhir_user=None))
    assert store.get("sid") is None


def test_auth_flow_is_single_use() -> None:
    store = AuthFlowStore(ttl_seconds=100)
    store.set("state", AuthFlow(code_verifier="v", nonce="n", redirect_uri="r"))
    assert store.pop("state") is not None
    assert store.pop("state") is None  # replay refused


# --- End-to-end web flow (login → callback → session → RBAC → logout) ------------------------
@pytest.fixture
def sso_app(monkeypatch: pytest.MonkeyPatch, rsa_keys: tuple[Any, Any]) -> tuple[Any, Any]:
    from agentforge import web
    from agentforge.auth.oidc import OidcClient
    from agentforge.auth.session import AuthFlowStore, SessionStore

    priv, pub = rsa_keys
    cfg = _cfg(require_sso=True, operator_roles=("admin",), cookie_secure=False)
    monkeypatch.setattr(web, "_sso", cfg)
    monkeypatch.setattr(web, "_oidc", OidcClient(cfg, jwks_client=_FakeJwks(pub)))
    monkeypatch.setattr(web, "_sessions", SessionStore())
    monkeypatch.setattr(web, "_flows", AuthFlowStore())
    return web, priv


def _client(web: Any) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=web.app),
                             base_url="https://af.test")


async def test_login_redirects_to_authorize_with_state(sso_app: tuple[Any, Any]) -> None:
    web, _ = sso_app
    async with _client(web) as c:
        r = await c.get("/login", follow_redirects=False)
    assert r.status_code == 302
    assert r.headers["location"].startswith(_ISSUER + "/authorize?")
    assert "code_challenge_method=S256" in r.headers["location"]
    assert web._STATE_COOKIE in r.cookies  # double-submit state cookie set


async def test_require_sso_redirects_anonymous_to_login(sso_app: tuple[Any, Any]) -> None:
    web, _ = sso_app
    async with _client(web) as c:
        r = await c.get("/", follow_redirects=False)
    assert r.status_code == 302 and r.headers["location"] == "/login"


async def test_full_login_grants_authorized_operator(sso_app: tuple[Any, Any]) -> None:
    web, priv = sso_app
    async with _client(web) as c:
        r = await c.get("/login", follow_redirects=False)
        state = r.cookies[web._STATE_COOKIE]
        nonce = next(iter(web._flows._data.values()))[1].nonce  # peek the server-minted nonce
        token = _id_token(priv, nonce=nonce, extra={"roles": "admin"})
        with respx.mock(assert_all_called=False) as router:
            router.post(_ISSUER + "/token").mock(
                return_value=httpx.Response(200, json={"id_token": token}))
            cb = await c.get(f"/callback?code=abc&state={state}",
                             cookies={web._STATE_COOKIE: state}, follow_redirects=False)
        assert cb.status_code == 302 and cb.headers["location"] == "/"
        sid = cb.cookies[web._SESSION_COOKIE]
        # authenticated read view renders with a sign-out control
        home = await c.get("/", cookies={web._SESSION_COOKIE: sid})
        assert home.status_code == 200 and "Sign out" in home.text
        # the mutating run trigger now succeeds for the authorized operator
        run = await c.post("/api/run/data_exfiltration", cookies={web._SESSION_COOKIE: sid})
        assert run.status_code == 200
        # logout clears the session
        await c.get("/logout", cookies={web._SESSION_COOKIE: sid}, follow_redirects=False)
        assert web._sessions.get(sid) is None


async def test_callback_rejects_state_mismatch(sso_app: tuple[Any, Any]) -> None:
    web, _ = sso_app
    async with _client(web) as c:
        await c.get("/login", follow_redirects=False)
        r = await c.get("/callback?code=abc&state=forged",
                        cookies={web._STATE_COOKIE: "different"}, follow_redirects=False)
    assert r.status_code == 400


async def test_callback_denies_unauthorized_role(sso_app: tuple[Any, Any]) -> None:
    web, priv = sso_app
    async with _client(web) as c:
        r = await c.get("/login", follow_redirects=False)
        state = r.cookies[web._STATE_COOKIE]
        nonce = next(iter(web._flows._data.values()))[1].nonce
        token = _id_token(priv, nonce=nonce, extra={"roles": "clinician"})
        with respx.mock(assert_all_called=False) as router:
            router.post(_ISSUER + "/token").mock(
                return_value=httpx.Response(200, json={"id_token": token}))
            cb = await c.get(f"/callback?code=abc&state={state}",
                             cookies={web._STATE_COOKIE: state}, follow_redirects=False)
    assert cb.status_code == 403  # authenticated but not an authorized operator


async def test_run_trigger_requires_login_when_sso_enabled(sso_app: tuple[Any, Any]) -> None:
    web, _ = sso_app
    async with _client(web) as c:
        r = await c.post("/api/run/data_exfiltration")
    assert r.status_code == 401
