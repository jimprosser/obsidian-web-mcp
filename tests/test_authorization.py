"""Protocol-level tests for per-client MCP authorization."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import secrets
from collections.abc import Iterator
from urllib.parse import parse_qs, urlsplit

import pytest
from mcp.server.fastmcp.exceptions import ToolError
from mcp.types import (
    CallToolResult,
    ListPromptsResult,
    ListResourcesResult,
    ListToolsResult,
)
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from obsidian_vault_mcp import auth, config, context, oauth, server
from obsidian_vault_mcp.authorization import PolicyFastMCP, ToolRegistrar
from obsidian_vault_mcp.extensions import Extension
from obsidian_vault_mcp.oauth_state import (
    LEGACY_FULL,
    VAULT_READONLY_CAPABILITIES,
)

MASTER_TOKEN = "master-bearer-must-not-be-issued"
LOGIN_USERNAME = "policy-user"
LOGIN_PASSWORD = "policy-password"
RESOURCE = "http://localhost:8420"
READ_ONLY = set(VAULT_READONLY_CAPABILITIES)
_EXTENSION_TOOL = "stage3_extension_probe"
_EXTENSION_CALLS: list[str] = []


class _RouteExtension(Extension):
    def register_routes(self, app) -> None:
        async def private_probe(_request):
            return JSONResponse({"ok": True})

        app.routes.insert(0, Route("/__private", private_probe, methods=["GET"]))


def test_policy_registrar_is_narrow_and_fail_closed():
    policy_server = PolicyFastMCP("authorization-unit")
    registrar = ToolRegistrar(policy_server)
    calls: list[str] = []

    @registrar.tool(name="unit_extension_tool")
    def unit_extension_tool() -> str:
        calls.append("called")
        return "called"

    assert not hasattr(registrar, "resource")
    assert not hasattr(registrar, "prompt")
    assert (
        policy_server.required_capability("unit_extension_tool")
        == "unit_extension_tool"
    )
    assert asyncio.run(policy_server.list_tools()) == []
    with pytest.raises(ToolError, match="Forbidden"):
        asyncio.run(policy_server.call_tool("unit_extension_tool", {}))

    denied_token = context.set_request_context(
        principal=context.AuthenticatedPrincipal(
            principal_id="oauth:denied",
            credential_id="a" * 64,
            client_id="denied",
            policy="vault_readonly_v1",
            capabilities=frozenset({"vault_read"}),
            full_access=False,
        ),
        request_id="denied",
    )
    try:
        assert asyncio.run(policy_server.list_tools()) == []
        with pytest.raises(ToolError, match="Forbidden"):
            asyncio.run(policy_server.call_tool("unit_extension_tool", {}))
    finally:
        context.reset_request_context(denied_token)

    allowed_token = context.set_request_context(
        principal=context.AuthenticatedPrincipal(
            principal_id="oauth:allowed",
            credential_id="b" * 64,
            client_id="allowed",
            policy="test",
            capabilities=frozenset({"unit_extension_tool"}),
            full_access=False,
        ),
        request_id="allowed",
    )
    try:
        tools = asyncio.run(policy_server.list_tools())
        assert [tool.name for tool in tools] == ["unit_extension_tool"]
        asyncio.run(policy_server.call_tool("unit_extension_tool", {}))
        assert calls == ["called"]
    finally:
        context.reset_request_context(allowed_token)

    master_token = context.set_request_context(
        principal=context.AuthenticatedPrincipal(
            principal_id="master",
            credential_id="c" * 64,
            client_id=None,
            policy=LEGACY_FULL,
            capabilities=frozenset(),
            full_access=True,
        ),
        request_id="master",
    )
    try:
        assert [tool.name for tool in asyncio.run(policy_server.list_tools())] == [
            "unit_extension_tool"
        ]
    finally:
        context.reset_request_context(master_token)


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return verifier, challenge


def _rpc(
    client: TestClient,
    token: str,
    method: str,
    params: dict[str, object],
) -> dict[str, object]:
    request_id = secrets.randbelow(2**31)
    response = client.post(
        config.VAULT_MCP_PATH,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
        },
        json={
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == request_id
    assert "error" not in body
    return body["result"]


def _rpc_error(
    client: TestClient,
    token: str,
    method: str,
    params: dict[str, object],
) -> dict[str, object]:
    request_id = secrets.randbelow(2**31)
    response = client.post(
        config.VAULT_MCP_PATH,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
        },
        json={
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
            "params": params,
        },
    )
    assert response.status_code == 200
    body = response.json()
    assert body["id"] == request_id
    assert "error" in body
    return body["error"]


def _initialize(client: TestClient, token: str) -> None:
    _rpc(
        client,
        token,
        "initialize",
        {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "authorization-test", "version": "1"},
        },
    )


def _list_tools(client: TestClient, token: str) -> set[str]:
    _initialize(client, token)
    result = ListToolsResult.model_validate(_rpc(client, token, "tools/list", {}))
    return {tool.name for tool in result.tools}


def _call_tool(
    client: TestClient,
    token: str,
    name: str,
    arguments: dict[str, object],
) -> CallToolResult:
    _initialize(client, token)
    return CallToolResult.model_validate(
        _rpc(
            client,
            token,
            "tools/call",
            {"name": name, "arguments": arguments},
        )
    )


def _issue_dynamic_token(client: TestClient, name: str) -> tuple[str, str]:
    redirect_uri = f"https://client.example.test/callback/{name}"
    registration = client.post(
        "/oauth/register",
        json={"client_name": name, "redirect_uris": [redirect_uri]},
    )
    assert registration.status_code == 201
    registered = registration.json()
    verifier, challenge = _pkce()
    authorization = client.post(
        "/oauth/authorize",
        data={
            "response_type": "code",
            "client_id": registered["client_id"],
            "redirect_uri": redirect_uri,
            "state": f"state-{name}",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": RESOURCE,
            "username": LOGIN_USERNAME,
            "password": LOGIN_PASSWORD,
        },
        follow_redirects=False,
    )
    assert authorization.status_code == 302
    code = parse_qs(urlsplit(authorization.headers["location"]).query)["code"][0]
    token_response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": registered["client_id"],
            "client_secret": registered["client_secret"],
            "code_verifier": verifier,
            "resource": RESOURCE,
        },
    )
    assert token_response.status_code == 200
    return registered["client_id"], token_response.json()["access_token"]


def _register_extension_tool() -> None:
    if server.mcp._tool_manager.get_tool(_EXTENSION_TOOL) is not None:
        return

    registrar = getattr(server, "tool_registrar", server.mcp)

    @registrar.tool(name=_EXTENSION_TOOL)
    def extension_probe() -> str:
        _EXTENSION_CALLS.append("called")
        return "extension-called"


@pytest.fixture(scope="module")
def policy_client(tmp_path_factory) -> Iterator[TestClient]:
    patch = pytest.MonkeyPatch()
    root = tmp_path_factory.mktemp("authorization")
    vault_path = root / "vault"
    vault_path.mkdir(mode=0o700)
    oauth.close_oauth_state()
    patch.setattr(config, "VAULT_PATH", vault_path)
    patch.setattr(server, "VAULT_PATH", vault_path)
    patch.setattr(config, "VAULT_MCP_TOKEN", MASTER_TOKEN)
    patch.setattr(auth, "VAULT_MCP_TOKEN", MASTER_TOKEN)
    patch.setattr(config, "VAULT_OAUTH_USERNAME", LOGIN_USERNAME)
    patch.setattr(config, "VAULT_OAUTH_PASSWORD", LOGIN_PASSWORD)
    patch.setattr(config, "VAULT_MCP_PUBLIC_URL", RESOURCE)
    patch.setattr(
        config,
        "VAULT_OAUTH_STATE_PATH",
        root / "oauth-state" / "oauth.sqlite3",
    )
    patch.setattr(config, "OAUTH_CLIENTS_PATH", root / "legacy" / "clients.json")
    patch.setattr(config, "VAULT_OAUTH_APPROVED_LEGACY_CLIENT_IDS", frozenset())
    _register_extension_tool()
    _EXTENSION_CALLS.clear()
    app = server.build_app((_RouteExtension(),))
    app.state.authorization_vault_path = vault_path
    with TestClient(app, base_url=RESOURCE) as client:
        yield client
    oauth.close_oauth_state()
    patch.undo()


def test_dynamic_client_discovers_exact_read_only_catalog(policy_client):
    _client_id, token = _issue_dynamic_token(policy_client, "catalog")
    assert _list_tools(policy_client, token) == READ_ONLY


def test_read_only_capabilities_name_registered_tools():
    registered = {tool.name for tool in server.mcp._tool_manager.list_tools()}
    assert READ_ONLY <= registered
    assert {server.mcp.required_capability(name) for name in READ_ONLY} == READ_ONLY


def test_dynamic_client_cannot_reach_mutation(policy_client):
    _client_id, token = _issue_dynamic_token(policy_client, "mutation")
    result = _call_tool(
        policy_client,
        token,
        "vault_write",
        {"path": "forbidden.md", "content": "must not exist"},
    )
    assert result.isError is True
    assert "Forbidden" in result.content[0].text
    vault_path = policy_client.app.state.authorization_vault_path
    assert not vault_path.joinpath("forbidden.md").exists()


def test_oauth_audit_attribution_is_stable_and_secret_free(
    policy_client,
    monkeypatch,
):
    client_id, token = _issue_dynamic_token(policy_client, "audit")
    vault_path = policy_client.app.state.authorization_vault_path
    vault_path.joinpath("audited-read.md").write_text(
        "visible",
        encoding="utf-8",
    )
    audit_path = vault_path.parent / "audit-attribution.jsonl"
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_PATH", str(audit_path))
    monkeypatch.setattr(config, "VAULT_AUDIT_LOG_INCLUDE_READS", True)

    for _ in range(2):
        result = _call_tool(
            policy_client,
            token,
            "vault_read",
            {"path": "audited-read.md"},
        )
        assert result.isError is not True

    raw_audit = audit_path.read_text(encoding="utf-8")
    records = [json.loads(line) for line in raw_audit.splitlines() if line]
    assert len(records) == 2
    assert records[0]["request_id"] != records[1]["request_id"]
    assert token not in raw_audit
    for record in records:
        assert record["client_id"] == client_id
        assert (
            record["token_id_hash"] == hashlib.sha256(token.encode("utf-8")).hexdigest()
        )
        assert record["principal_id"] == f"oauth:{client_id}"
        assert record["auth_policy"] == "vault_readonly_v1"


def test_new_extension_tool_is_denied_by_default(policy_client):
    _client_id, token = _issue_dynamic_token(policy_client, "extension")
    assert _EXTENSION_TOOL not in _list_tools(policy_client, token)
    result = _call_tool(policy_client, token, _EXTENSION_TOOL, {})
    assert result.isError is True
    assert _EXTENSION_CALLS == []


def test_master_retains_full_tool_access(policy_client):
    names = _list_tools(policy_client, MASTER_TOKEN)
    assert "vault_write" in names
    assert _EXTENSION_TOOL in names
    result = _call_tool(policy_client, MASTER_TOKEN, _EXTENSION_TOOL, {})
    assert result.isError is not True
    assert _EXTENSION_CALLS == ["called"]


def test_legacy_full_oauth_token_retains_full_tool_access(policy_client):
    state = oauth.get_oauth_state()
    state.ensure_static_client(
        "approved-static",
        ("https://approved.example.test/callback",),
        policy=LEGACY_FULL,
        capabilities=(),
    )
    issued = state.issue_access_token(
        client_id="approved-static",
        resource="http://localhost:8420",
    )
    names = _list_tools(policy_client, issued.access_token)
    assert "vault_write" in names
    assert _EXTENSION_TOOL in names


def test_read_only_principal_has_no_resources_or_prompts(policy_client):
    _client_id, token = _issue_dynamic_token(policy_client, "surfaces")
    _initialize(policy_client, token)
    resources = ListResourcesResult.model_validate(
        _rpc(policy_client, token, "resources/list", {})
    )
    prompts = ListPromptsResult.model_validate(
        _rpc(policy_client, token, "prompts/list", {})
    )
    assert resources.resources == []
    assert prompts.prompts == []
    resource_error = _rpc_error(
        policy_client,
        token,
        "resources/read",
        {"uri": "vault://private"},
    )
    prompt_error = _rpc_error(
        policy_client,
        token,
        "prompts/get",
        {"name": "private"},
    )
    assert "Forbidden" in str(resource_error)
    assert "Forbidden" in str(prompt_error)


@pytest.mark.parametrize("token", ["wrong", "v1.unknown.invalid"])
def test_invalid_bearer_returns_401(policy_client, token):
    response = policy_client.post(
        config.VAULT_MCP_PATH,
        headers={"Authorization": f"Bearer {token}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert response.status_code == 401
    assert 'error="invalid_token"' in response.headers["WWW-Authenticate"]


def test_revoked_oauth_token_returns_401(policy_client):
    _client_id, token = _issue_dynamic_token(policy_client, "revoked")
    metadata = oauth.get_oauth_state().lookup_access_token(token)
    assert metadata is not None
    assert oauth.get_oauth_state().revoke_token(metadata.token_id)
    response = policy_client.post(
        config.VAULT_MCP_PATH,
        headers={"Authorization": f"Bearer {token}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert response.status_code == 401


def test_wrong_resource_oauth_token_returns_401(policy_client):
    client_id, _valid_token = _issue_dynamic_token(
        policy_client,
        "wrong-resource",
    )
    state = oauth.get_oauth_state()
    issued = state.issue_access_token(
        client_id=client_id,
        resource="https://different-resource.example.test",
    )
    response = policy_client.post(
        config.VAULT_MCP_PATH,
        headers={"Authorization": f"Bearer {issued.access_token}"},
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    )
    assert response.status_code == 401


def test_read_only_token_gets_403_on_protected_non_mcp_route(policy_client):
    _client_id, token = _issue_dynamic_token(policy_client, "route")
    response = policy_client.get(
        "/__private",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert response.status_code == 403
    assert response.json() == {"error": "Insufficient scope"}
    assert 'error="insufficient_scope"' in response.headers["WWW-Authenticate"]


def test_dynamic_bearer_authentication_does_not_mutate_static_client(
    policy_client,
    monkeypatch,
):
    monkeypatch.setattr(config, "VAULT_OAUTH_CLIENT_ID", "configured-static")
    monkeypatch.setattr(config, "VAULT_OAUTH_CLIENT_SECRET", "configured-secret")
    monkeypatch.setattr(
        config,
        "VAULT_OAUTH_REDIRECT_URIS",
        ["https://static.example.test/callback"],
    )
    _client_id, token = _issue_dynamic_token(policy_client, "read-only-auth")
    state = oauth.get_oauth_state()
    statements: list[str] = []
    state._connection.set_trace_callback(statements.append)
    try:
        response = policy_client.get(
            "/__private",
            headers={"Authorization": f"Bearer {token}"},
        )
    finally:
        state._connection.set_trace_callback(None)

    assert response.status_code == 403
    mutations = [
        statement
        for statement in statements
        if statement.lstrip().partition(" ")[0].upper() in {"DELETE", "INSERT", "UPDATE"}
    ]
    assert mutations == []


def test_master_can_reach_protected_non_mcp_route(policy_client):
    response = policy_client.get(
        "/__private",
        headers={"Authorization": f"Bearer {MASTER_TOKEN}"},
    )
    assert response.status_code == 200
    assert response.json() == {"ok": True}
