"""Signed uploads exist only when the operator asks for them.

Without VAULT_UPLOAD_URL_SECRET there must be no tool handing out URLs, no route, and no
bearer-exempt path: an upgrade must not add an unauthenticated write path. That cannot be
tested in this process, because the tool registers at import; each case starts a real
server in a child process with an environment built from scratch.

The startup validation is checked here too: a bad or non-positive value, and a staging
directory inside the vault, must stop the server the way the audit log's rule does.
"""

import urllib.error
import urllib.request
import uuid

import pytest

from obsidian_vault_mcp import auth, config

from ._live_server import call_tool_over_http, list_tools_over_http, live_server

SECRET = {"VAULT_UPLOAD_URL_SECRET": "opt-in-test-secret"}


@pytest.fixture
def vault(tmp_path):
    v = tmp_path / "vault"
    v.mkdir()
    (v / "note.md").write_text("# Note\n", encoding="utf-8")
    return v


def _post(url: str, body: bytes = b"x", content_type: str = "application/pdf"):
    request = urllib.request.Request(url, data=body, method="POST", headers={"Content-Type": content_type})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status
    except urllib.error.HTTPError as err:
        return err.code


# --- off by default -------------------------------------------------------------------

def test_without_the_secret_there_is_no_tool_and_no_tokenless_route(tmp_path, vault):
    with live_server(tmp_path, vault) as (base_url, _log):
        tools = list_tools_over_http(base_url)
        status = _post(f"{base_url}/upload/{uuid.uuid4()}?expires=1&signature=x")

    assert "vault_request_upload_url" not in tools, tools
    assert "vault_read" in tools, "negative control: no tools listed at all"
    assert status == 401, status


def test_with_the_secret_the_tool_and_the_route_are_there(tmp_path, vault):
    with live_server(tmp_path, vault, {**SECRET, "VAULT_UPLOAD_STAGING_DIR": str(tmp_path / "staging")}) as (
        base_url,
        _log,
    ):
        tools = list_tools_over_http(base_url)
        grant = call_tool_over_http(
            base_url,
            "vault_request_upload_url",
            {"path": "a.pdf", "media_type": "application/pdf", "max_size_bytes": 1024},
        )
        # A real id with a wrong signature: the route exists and refuses.
        status = _post(grant["upload_url"].replace("signature=", "signature=0"))

    assert "vault_request_upload_url" in tools
    assert "error" not in grant, grant
    assert status in (403, 404), status


def test_the_exemption_is_off_when_the_feature_is_off(monkeypatch):
    """auth.is_signed_upload_request is the exemption itself, not just the route."""
    upload_path = f"/upload/{uuid.uuid4()}"

    monkeypatch.setattr(config, "VAULT_UPLOAD_URL_SECRET", "")
    assert auth.is_signed_upload_request("POST", upload_path) is False

    monkeypatch.setattr(config, "VAULT_UPLOAD_URL_SECRET", "secret")
    assert auth.is_signed_upload_request("POST", upload_path) is True


def test_no_fallback_to_the_bearer_token(monkeypatch, vault_dir):
    """The URL-signing key must be its own secret."""
    from obsidian_vault_mcp.tools import upload as upload_mod

    monkeypatch.setattr(config, "VAULT_UPLOAD_URL_SECRET", "")
    monkeypatch.setattr(config, "VAULT_MCP_TOKEN", "the-bearer-token")

    with pytest.raises(ValueError, match="VAULT_UPLOAD_URL_SECRET"):
        upload_mod._upload_secret()


# --- startup validation ---------------------------------------------------------------

@pytest.fixture
def upload_config(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "VAULT_UPLOAD_URL_SECRET", "validate-secret")
    monkeypatch.setattr(config, "VAULT_PATH", tmp_path / "vault")
    monkeypatch.setattr(config, "UPLOAD_STAGING_DIR", tmp_path / "staging")
    (tmp_path / "vault").mkdir()
    (tmp_path / "staging").mkdir()


def test_good_settings_validate(upload_config):
    config.validate_config()  # must not raise


@pytest.mark.parametrize(
    "name,raw",
    [
        ("VAULT_UPLOAD_MAX_BYTES", "100MB"),
        ("VAULT_UPLOAD_MAX_BYTES", "0"),
        ("VAULT_UPLOAD_URL_TTL_SECONDS", "-5"),
        ("VAULT_UPLOAD_URL_TTL_SECONDS", "fifteen"),
        ("VAULT_UPLOAD_URL_MAX_TTL_SECONDS", "0"),
    ],
)
def test_a_bad_value_stops_startup_and_names_the_variable(upload_config, monkeypatch, name, raw):
    monkeypatch.setenv(name, raw)

    with pytest.raises(ValueError, match=name):
        config.validate_config()


def test_a_max_ttl_below_the_default_ttl_is_refused(upload_config, monkeypatch):
    monkeypatch.setattr(config, "VAULT_UPLOAD_URL_TTL_SECONDS", 900)
    monkeypatch.setattr(config, "VAULT_UPLOAD_URL_MAX_TTL_SECONDS", 60)

    with pytest.raises(ValueError, match="VAULT_UPLOAD_URL_MAX_TTL_SECONDS"):
        config.validate_config()


def test_a_staging_dir_inside_the_vault_is_refused(upload_config, monkeypatch, tmp_path):
    inside = tmp_path / "vault" / "uploads"
    monkeypatch.setattr(config, "UPLOAD_STAGING_DIR", inside)

    with pytest.raises(ValueError, match="VAULT_UPLOAD_STAGING_DIR"):
        config.validate_config()


def test_the_settings_are_not_validated_when_the_feature_is_off(upload_config, monkeypatch):
    """Nobody should be stopped at startup by a stale variable for a feature they do not use."""
    monkeypatch.setattr(config, "VAULT_UPLOAD_URL_SECRET", "")
    monkeypatch.setenv("VAULT_UPLOAD_MAX_BYTES", "100MB")

    config.validate_config()  # must not raise
