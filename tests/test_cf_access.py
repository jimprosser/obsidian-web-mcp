"""Tests for the opt-in Cloudflare Access auth mode."""

import pytest

from obsidian_vault_mcp import cf_access
from obsidian_vault_mcp import config


@pytest.fixture
def cf_on(monkeypatch):
    """Enable CF Access mode with a canonical team domain + AUD."""
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", "myteam.cloudflareaccess.com")
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", "test-aud-tag")


def test_disabled_by_default(monkeypatch):
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", "")
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", "")
    assert cf_access.cf_access_enabled() is False


def test_both_or_neither_team_only(monkeypatch):
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", "myteam.cloudflareaccess.com")
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", "")
    assert cf_access.cf_access_enabled() is False


def test_both_or_neither_aud_only(monkeypatch):
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", "")
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", "test-aud-tag")
    assert cf_access.cf_access_enabled() is False


def test_enabled_when_both_set(cf_on):
    assert cf_access.cf_access_enabled() is True


def test_normalizes_bare_team_name(monkeypatch):
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", "myteam")
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", "aud")
    assert cf_access.team_domain() == "myteam.cloudflareaccess.com"


def test_normalizes_full_url(monkeypatch):
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", "https://myteam.cloudflareaccess.com/")
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", "aud")
    assert cf_access.team_domain() == "myteam.cloudflareaccess.com"


def test_issuer_and_certs_url(cf_on):
    assert cf_access.issuer() == "https://myteam.cloudflareaccess.com"
    assert cf_access.certs_url() == "https://myteam.cloudflareaccess.com/cdn-cgi/access/certs"


import time

# --- verify_access_token -----------------------------------------------------------

_TEAM = "myteam.cloudflareaccess.com"
_ISSUER = f"https://{_TEAM}"
_AUD = "test-aud-tag"


@pytest.fixture(scope="module")
def rsa_keys():
    from cryptography.hazmat.primitives.asymmetric import rsa
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return priv, priv.public_key()


class _FakeKey:
    def __init__(self, key):
        self.key = key


class _FakeJwkClient:
    """Stand-in for PyJWKClient: returns a fixed public key for any token."""

    def __init__(self, public_key):
        self._public_key = public_key

    def get_signing_key_from_jwt(self, token):
        return _FakeKey(self._public_key)


def _mint(priv, claims, headers=None):
    import jwt
    return jwt.encode(claims, priv, algorithm="RS256", headers=headers or {"kid": "test-kid"})


def _base_claims(**overrides):
    claims = {
        "aud": _AUD,
        "iss": _ISSUER,
        "exp": int(time.time()) + 3600,
        "iat": int(time.time()) - 10,
        "email": "claude@toye.io",
        "sub": "cf-subject-123",
    }
    claims.update(overrides)
    return claims


@pytest.fixture
def verify_env(monkeypatch, rsa_keys):
    """CF mode on + JWKS client stubbed to the in-test public key."""
    priv, pub = rsa_keys
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", _TEAM)
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", _AUD)
    monkeypatch.setattr(cf_access, "_get_jwk_client", lambda: _FakeJwkClient(pub))
    return priv, pub


def test_valid_token_returns_claims(verify_env):
    priv, _ = verify_env
    token = _mint(priv, _base_claims())
    claims = cf_access.verify_access_token(token)
    assert claims["email"] == "claude@toye.io"
    assert claims["sub"] == "cf-subject-123"


def test_missing_header_rejected(verify_env):
    with pytest.raises(cf_access.CfAccessError):
        cf_access.verify_access_token("")


def test_malformed_token_rejected(verify_env):
    with pytest.raises(cf_access.CfAccessError):
        cf_access.verify_access_token("not-a-jwt")


def test_wrong_audience_rejected(verify_env):
    priv, _ = verify_env
    token = _mint(priv, _base_claims(aud="some-other-aud"))
    with pytest.raises(cf_access.CfAccessError):
        cf_access.verify_access_token(token)


def test_wrong_issuer_rejected(verify_env):
    priv, _ = verify_env
    token = _mint(priv, _base_claims(iss="https://evil.cloudflareaccess.com"))
    with pytest.raises(cf_access.CfAccessError):
        cf_access.verify_access_token(token)


def test_expired_token_rejected(verify_env):
    priv, _ = verify_env
    token = _mint(priv, _base_claims(exp=int(time.time()) - 3600))
    with pytest.raises(cf_access.CfAccessError):
        cf_access.verify_access_token(token)


def test_bad_signature_rejected(verify_env, rsa_keys):
    from cryptography.hazmat.primitives.asymmetric import rsa
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = _mint(attacker, _base_claims())  # signed by the wrong key
    with pytest.raises(cf_access.CfAccessError):
        cf_access.verify_access_token(token)


def test_missing_exp_rejected(verify_env):
    priv, _ = verify_env
    claims = _base_claims()
    del claims["exp"]
    token = _mint(priv, claims)
    with pytest.raises(cf_access.CfAccessError):
        cf_access.verify_access_token(token)


def test_unreachable_jwks_rejected(monkeypatch, rsa_keys):
    priv, _ = rsa_keys
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", _TEAM)
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", _AUD)

    class _Boom:
        def get_signing_key_from_jwt(self, token):
            raise RuntimeError("cannot reach Cloudflare")

    monkeypatch.setattr(cf_access, "_get_jwk_client", lambda: _Boom())
    token = _mint(priv, _base_claims())
    with pytest.raises(cf_access.CfAccessError):
        cf_access.verify_access_token(token)


def test_alg_none_token_rejected(verify_env):
    # A forged token with "alg": "none" (unsigned) must be rejected — RS256 is pinned.
    import jwt
    try:
        token = jwt.encode(_base_claims(), key=None, algorithm="none")
    except Exception:
        # PyJWT may refuse to mint an alg=none token; that itself means the attack
        # can't be mounted. Nothing to verify.
        return
    with pytest.raises(cf_access.CfAccessError):
        cf_access.verify_access_token(token)


def test_hs256_token_signed_with_public_key_rejected(verify_env, rsa_keys):
    # Algorithm-confusion: an attacker who knows the RS256 *public* key tries to pass it
    # as an HS256 shared secret. Must be rejected — only RS256 is accepted.
    import jwt
    from cryptography.hazmat.primitives import serialization
    _priv, pub = rsa_keys
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    try:
        forged = jwt.encode(_base_claims(), key=pub_pem, algorithm="HS256")
    except Exception:
        # PyJWT may refuse to sign HS256 with an asymmetric-looking key; that itself
        # means the confusion attack can't even be mounted. Nothing to verify.
        return
    with pytest.raises(cf_access.CfAccessError):
        cf_access.verify_access_token(forged)


def test_require_dependencies_ok_when_installed():
    cf_access.require_dependencies()  # installed in the dev env -> no raise


def test_require_dependencies_raises_when_missing(monkeypatch):
    import sys
    monkeypatch.setitem(sys.modules, "jwt", None)  # forces ImportError on `import jwt`
    with pytest.raises(cf_access.CfAccessError):
        cf_access.require_dependencies()


def test_warm_jwks_never_raises(monkeypatch):
    class _Boom:
        def get_signing_keys(self):
            raise RuntimeError("down")

    monkeypatch.setattr(cf_access, "_get_jwk_client", lambda: _Boom())
    cf_access.warm_jwks()  # must swallow and return


def test_jwk_client_constructed_once(monkeypatch):
    """_get_jwk_client() must build exactly one PyJWKClient and return the same instance."""
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", _TEAM)
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", _AUD)
    monkeypatch.setattr(cf_access, "_jwk_client", None)  # reset module cache

    call_count = 0

    class _CountingClient:
        pass

    def _fake_pyjwkclient(url):
        nonlocal call_count
        call_count += 1
        return _CountingClient()

    monkeypatch.setattr("jwt.PyJWKClient", _fake_pyjwkclient)

    first = cf_access._get_jwk_client()
    second = cf_access._get_jwk_client()

    assert first is second, "expected the same client instance on both calls"
    assert call_count == 1, f"PyJWKClient constructed {call_count} times, expected 1"


# --- CloudflareAccessMiddleware ----------------------------------------------------

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from obsidian_vault_mcp import context as context_module


@pytest.fixture
def mw_client(monkeypatch):
    """A tiny app guarded by the CF middleware, with verify_access_token stubbed.

    The sentinel header value "good-token" verifies to a fixed claim set; anything else
    raises CfAccessError. Captures the principal the middleware threaded into context.
    """
    captured = {}

    def fake_verify(header_value):
        if header_value == "good-token":
            return {"email": "claude@toye.io", "sub": "cf-subject-123"}
        if header_value == "service-token":
            return {"sub": "svc-abc"}  # service token: no email claim
        raise cf_access.CfAccessError("bad")

    monkeypatch.setattr(cf_access, "verify_access_token", fake_verify)

    async def echo(request):
        captured["principal"] = context_module.current_request_context().get("principal")
        captured["client"] = context_module.current_request_context().get("client")
        return PlainTextResponse("ok")

    async def health(request):
        return PlainTextResponse("health-ok")

    app = Starlette(routes=[Route("/", echo), Route("/health", health)])
    app.add_middleware(cf_access.CloudflareAccessMiddleware)
    return TestClient(app), captured


def test_valid_header_passes_and_sets_email_principal(mw_client):
    client, captured = mw_client
    r = client.get("/", headers={"Cf-Access-Jwt-Assertion": "good-token"})
    assert r.status_code == 200
    assert r.text == "ok"
    assert captured["principal"] == "claude@toye.io"
    assert captured["client"] == "claude@toye.io"


def test_service_token_falls_back_to_sub(mw_client):
    client, captured = mw_client
    r = client.get("/", headers={"Cf-Access-Jwt-Assertion": "service-token"})
    assert r.status_code == 200
    assert captured["principal"] == "svc-abc"


def test_missing_header_is_401(mw_client):
    client, _ = mw_client
    r = client.get("/")
    assert r.status_code == 401


def test_invalid_header_is_401(mw_client):
    client, _ = mw_client
    r = client.get("/", headers={"Cf-Access-Jwt-Assertion": "nope"})
    assert r.status_code == 401


def test_health_is_exempt(mw_client):
    client, _ = mw_client
    r = client.get("/health")
    assert r.status_code == 200
    assert r.text == "health-ok"


# --- validate_cf_access_config (startup format check) ------------------------------


def test_validate_cf_access_config_noop_when_off(monkeypatch):
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", "")
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", "")
    cf_access.validate_cf_access_config()  # must not raise


def test_validate_cf_access_config_noop_when_half_configured(monkeypatch):
    # Half-config = mode OFF; the startup check must not fire (serve() warns instead).
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", "not a domain!!")
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", "")
    cf_access.validate_cf_access_config()  # off -> no validation, no raise


def test_validate_cf_access_config_accepts_valid_domain(monkeypatch):
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", "myteam.cloudflareaccess.com")
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", "aud")
    cf_access.validate_cf_access_config()  # must not raise


def test_validate_cf_access_config_accepts_bare_team_name(monkeypatch):
    # A bare name normalizes to <name>.cloudflareaccess.com, which is a valid hostname.
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", "myteam")
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", "aud")
    cf_access.validate_cf_access_config()  # must not raise


@pytest.mark.parametrize("bad", ["not a domain!!", "team@evil", "has space.com", "under_score.com"])
def test_validate_cf_access_config_rejects_malformed_domain(monkeypatch, bad):
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", bad)
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", "aud")
    with pytest.raises(ValueError):
        cf_access.validate_cf_access_config()
