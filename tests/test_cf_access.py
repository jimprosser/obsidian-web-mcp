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


def _b64url(data: bytes) -> str:
    import base64
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _forge(header: dict, claims: dict, signature: bytes) -> str:
    """Assemble a JWT by hand. An attacker doesn't need PyJWT to mint one, so the
    forgery tests must not depend on what PyJWT is willing to encode."""
    import json
    return ".".join((
        _b64url(json.dumps(header, separators=(",", ":")).encode()),
        _b64url(json.dumps(claims, separators=(",", ":")).encode()),
        _b64url(signature),
    ))


def test_alg_none_token_rejected(verify_env):
    # A hand-built unsigned token with "alg": "none" must be rejected — RS256 is pinned.
    token = _forge({"alg": "none", "typ": "JWT"}, _base_claims(), b"")
    with pytest.raises(cf_access.CfAccessError):
        cf_access.verify_access_token(token)


def test_hs256_token_signed_with_public_key_rejected(verify_env, rsa_keys):
    # Algorithm-confusion, signed by hand with hmac: an attacker who knows the RS256
    # *public* key uses it as an HS256 shared secret. Must be rejected — RS256 only.
    import hashlib
    import hmac
    import json
    from cryptography.hazmat.primitives import serialization
    _priv, pub = rsa_keys
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "test-kid"}, separators=(",", ":")).encode())
    payload = _b64url(json.dumps(_base_claims(), separators=(",", ":")).encode())
    signature = hmac.new(pub_pem, f"{header}.{payload}".encode(), hashlib.sha256).digest()
    forged = f"{header}.{payload}.{_b64url(signature)}"
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
    """_get_jwk_client() must build exactly one client and return the same instance."""
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", _TEAM)
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", _AUD)
    monkeypatch.setattr(cf_access, "_jwk_client", None)  # reset module cache

    call_count = 0

    class _CountingClient:
        pass

    def _fake_build(url):
        nonlocal call_count
        call_count += 1
        return _CountingClient()

    monkeypatch.setattr(cf_access, "_build_jwk_client", _fake_build)

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
            # Cloudflare service tokens carry sub: "" with the identity in common_name.
            return {"sub": "", "common_name": "my-service-token"}
        if header_value == "bare-sub-token":
            return {"sub": "svc-abc"}  # no email, no common_name
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


def test_service_token_uses_common_name(mw_client):
    # Service-token JWTs carry sub: "" with the identity in common_name; the audit
    # principal must never be empty for a validly-authenticated request.
    client, captured = mw_client
    r = client.get("/", headers={"Cf-Access-Jwt-Assertion": "service-token"})
    assert r.status_code == 200
    assert captured["principal"] == "my-service-token"


def test_principal_falls_back_to_sub(mw_client):
    client, captured = mw_client
    r = client.get("/", headers={"Cf-Access-Jwt-Assertion": "bare-sub-token"})
    assert r.status_code == 200
    assert captured["principal"] == "svc-abc"


def test_verification_runs_off_the_event_loop(monkeypatch):
    """verify_access_token does blocking network I/O (the JWKS fetch, up to 30s);
    the middleware must run it in a worker thread so a slow fetch cannot stall
    every other request on the event loop."""
    import threading

    seen = {}

    def fake_verify(header_value):
        seen["verify_thread"] = threading.get_ident()
        return {"email": "claude@toye.io"}

    monkeypatch.setattr(cf_access, "verify_access_token", fake_verify)

    async def echo(request):
        seen["loop_thread"] = threading.get_ident()
        return PlainTextResponse("ok")

    app = Starlette(routes=[Route("/", echo)])
    app.add_middleware(cf_access.CloudflareAccessMiddleware)
    client = TestClient(app)
    assert client.get("/", headers={"Cf-Access-Jwt-Assertion": "x"}).status_code == 200
    assert seen["verify_thread"] != seen["loop_thread"]


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


@pytest.mark.parametrize(
    "team,aud", [("myteam.cloudflareaccess.com", ""), ("", "some-aud-tag")]
)
def test_validate_cf_access_config_rejects_half_config(monkeypatch, team, aud):
    # Exactly one of the two settings set is a broken configuration, not mode-off:
    # the operator meant to enable the mode, so booting bearer+OAuth instead would
    # be a silently different auth surface. Fail at startup like a malformed domain.
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", team)
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", aud)
    with pytest.raises(ValueError) as exc:
        cf_access.validate_cf_access_config()
    assert "BOTH" in str(exc.value)


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


def test_malformed_domain_error_never_echoes_the_value(monkeypatch):
    # A pasted URL can carry credentials (https://user:secret@team/); the startup
    # error goes to the log, so it must name the setting and the expected format,
    # never the value itself.
    monkeypatch.setattr(
        config, "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN", "https://user:hunter2@myteam.cloudflareaccess.com/"
    )
    monkeypatch.setattr(config, "VAULT_MCP_CF_ACCESS_AUD", "aud")
    with pytest.raises(ValueError) as exc:
        cf_access.validate_cf_access_config()
    assert "hunter2" not in str(exc.value)
    assert "VAULT_MCP_CF_ACCESS_TEAM_DOMAIN" in str(exc.value)


# --- bounded JWKS fetch -------------------------------------------------------------


@pytest.fixture
def jwks_http_server():
    """A local HTTP server: /keys serves a tiny JWKS, /huge an oversized body,
    /redirect a 302 to /keys."""
    import http.server
    import threading

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/keys":
                body = b'{"keys": []}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/huge":
                body = b'{"keys": [' + b" " * (2 * 1024 * 1024) + b"]}"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif self.path == "/redirect":
                self.send_response(302)
                self.send_header("Location", "/keys")
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def test_jwks_fetch_rejects_oversized_response(jwks_http_server):
    # PyJWKClient's own fetch json.load()s the response unbounded; the bounded
    # client must cut off a body larger than the cap instead of parsing it.
    client = cf_access._build_jwk_client(f"{jwks_http_server}/huge")
    with pytest.raises(Exception, match="(?i)exceed"):
        client.fetch_data()


def test_jwks_fetch_refuses_redirects(jwks_http_server):
    client = cf_access._build_jwk_client(f"{jwks_http_server}/redirect")
    with pytest.raises(Exception):
        client.fetch_data()


def test_jwks_fetch_returns_normal_payload(jwks_http_server):
    client = cf_access._build_jwk_client(f"{jwks_http_server}/keys")
    assert client.fetch_data() == {"keys": []}
