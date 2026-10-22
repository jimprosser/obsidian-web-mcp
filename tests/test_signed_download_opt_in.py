"""Signed downloads exist only when the operator asks for them, and work end to end when asked.

Without VAULT_DOWNLOAD_URL_SECRET there must be no tool handing out URLs, no route, and no
bearer-exempt path: an upgrade must not add an unauthenticated read path, and turning on
signed uploads must not turn on downloads. That cannot be tested in this process, because
the tool registers at import; each case starts a real server (serve(), the production
entry point) in a child process with an environment built from scratch. The same child
carries the whole chain once: MCP over HTTP with a bearer token, then a tokenless GET,
with uvicorn's real access log checked for the signature.

The startup validation is checked here too, by the same rules as the upload settings.
"""

import urllib.error
import urllib.request
import uuid

import pytest

from obsidian_vault_mcp import auth, config

from ._live_server import call_tool_over_http, list_tools_over_http, live_server

SECRET = {"VAULT_DOWNLOAD_URL_SECRET": "opt-in-download-secret"}
PDF = b"%PDF-1.4\n" + bytes(range(256)) * 400


@pytest.fixture
def vault(tmp_path):
    v = tmp_path / "vault"
    (v / "ablage").mkdir(parents=True)
    (v / "note.md").write_text("# Note\n", encoding="utf-8")
    (v / "ablage" / "vertrag.pdf").write_bytes(PDF)
    return v


def _get(url: str):
    try:
        with urllib.request.urlopen(url, timeout=30) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as err:
        return err.code, err.read()


# --- off by default -------------------------------------------------------------------

@pytest.mark.parametrize("extra", [{}, {"VAULT_UPLOAD_URL_SECRET": "uploads-only"}], ids=["nothing", "uploads-on"])
def test_without_the_secret_there_is_no_tool_and_no_tokenless_route(tmp_path, vault, extra):
    with live_server(tmp_path, vault, extra) as (base_url, _log):
        tools = list_tools_over_http(base_url)
        status, _ = _get(f"{base_url}/download/{uuid.uuid4()}?expires=1&signature=x")

    assert "vault_request_download_url" not in tools, tools
    assert "vault_read" in tools, "negative control: no tools listed at all"
    assert status == 401, status


def test_with_the_secret_a_client_downloads_over_http_without_a_token(tmp_path, vault):
    with live_server(tmp_path, vault, SECRET) as (base_url, log_path):
        tools = list_tools_over_http(base_url)
        grant = call_tool_over_http(base_url, "vault_request_download_url", {"path": "ablage/vertrag.pdf"})
        tampered = _get(grant["download_url"].replace("signature=", "signature=0"))
        served = _get(grant["download_url"])
        again = _get(grant["download_url"])
        signature = grant["download_url"].split("signature=", 1)[1]
        log = log_path.read_text(encoding="utf-8", errors="replace")

    assert "vault_request_download_url" in tools
    assert "error" not in grant, grant
    assert tampered[0] == 403, tampered
    assert served == (200, PDF)
    assert grant["size"] == len(PDF)
    assert again == (200, PDF), "stateless: the URL works until it expires"
    assert "GET /download/" in log, "negative control: the access log recorded nothing"
    assert signature not in log


def test_the_exemption_is_off_when_the_feature_is_off(monkeypatch):
    """auth.is_signed_download_request is the exemption itself, not just the route."""
    download_path = f"/download/{uuid.uuid4()}"

    monkeypatch.setattr(config, "VAULT_DOWNLOAD_URL_SECRET", "")
    assert auth.is_signed_download_request("GET", download_path) is False

    monkeypatch.setattr(config, "VAULT_DOWNLOAD_URL_SECRET", "secret")
    assert auth.is_signed_download_request("GET", download_path) is True
    assert auth.is_signed_download_request("HEAD", download_path) is False


def test_no_fallback_to_another_secret(monkeypatch, vault_dir):
    """The URL-signing key must be its own secret, not the bearer token or the upload key."""
    from obsidian_vault_mcp.tools import download as download_mod

    monkeypatch.setattr(config, "VAULT_DOWNLOAD_URL_SECRET", "")
    monkeypatch.setattr(config, "VAULT_MCP_TOKEN", "the-bearer-token")
    monkeypatch.setattr(config, "VAULT_UPLOAD_URL_SECRET", "the-upload-secret")

    with pytest.raises(ValueError, match="VAULT_DOWNLOAD_URL_SECRET"):
        download_mod._download_secret()


# --- startup validation ---------------------------------------------------------------

@pytest.fixture
def download_config(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "VAULT_DOWNLOAD_URL_SECRET", "validate-secret")
    monkeypatch.setattr(config, "VAULT_PATH", tmp_path / "vault")
    (tmp_path / "vault").mkdir()


def test_good_settings_validate(download_config):
    config.validate_config()  # must not raise


@pytest.mark.parametrize(
    "name,raw",
    [
        ("VAULT_DOWNLOAD_URL_TTL_SECONDS", "-5"),
        ("VAULT_DOWNLOAD_URL_TTL_SECONDS", "five"),
        ("VAULT_DOWNLOAD_URL_MAX_TTL_SECONDS", "0"),
    ],
)
def test_a_bad_value_stops_startup_and_names_the_variable(download_config, monkeypatch, name, raw):
    monkeypatch.setenv(name, raw)

    with pytest.raises(ValueError, match=name):
        config.validate_config()


def test_a_max_ttl_below_the_default_ttl_is_refused(download_config, monkeypatch):
    monkeypatch.setattr(config, "VAULT_DOWNLOAD_URL_TTL_SECONDS", 900)
    monkeypatch.setattr(config, "VAULT_DOWNLOAD_URL_MAX_TTL_SECONDS", 60)

    with pytest.raises(ValueError, match="VAULT_DOWNLOAD_URL_MAX_TTL_SECONDS"):
        config.validate_config()


def test_the_settings_are_not_validated_when_the_feature_is_off(download_config, monkeypatch):
    monkeypatch.setattr(config, "VAULT_DOWNLOAD_URL_SECRET", "")
    monkeypatch.setenv("VAULT_DOWNLOAD_URL_TTL_SECONDS", "five")

    config.validate_config()  # must not raise
