"""Run the real server in a child process and talk to it over HTTP, as a client does.

Nothing is stubbed: the child calls ``server.serve()``, the production entry point, so
validate_config, the lifespan and MCP session manager, build_app(), the bearer middleware
and uvicorn with its log config are all the real ones. Tests use this for the one chain
no in-process test covers: a client calls a tool over MCP/HTTP and acts on the result.
"""

import asyncio
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path

TOKEN = "live-server-test-token"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def live_server(tmp_path: Path, vault: Path, extra_env: dict | None = None, bootstrap: str = ""):
    """Start ``serve()`` in a child process; yield (base_url, log_path)."""
    port = _free_port()
    log_path = tmp_path / "server.log"
    env = {
        **os.environ,
        "VAULT_PATH": str(vault),
        "VAULT_MCP_TOKEN": TOKEN,
        "VAULT_MCP_PORT": str(port),
        "VAULT_MCP_PUBLIC_URL": f"http://127.0.0.1:{port}",
        "PYTHONUNBUFFERED": "1",
        **(extra_env or {}),
    }
    code = bootstrap + "\nfrom obsidian_vault_mcp import server\nserver.serve(EXTENSIONS)\n"
    if "EXTENSIONS" not in bootstrap:
        code = "EXTENSIONS = ()\n" + code
    with open(log_path, "wb") as log:
        proc = subprocess.Popen([sys.executable, "-c", code], env=env, stdout=log, stderr=subprocess.STDOUT)
    base_url = f"http://127.0.0.1:{port}"
    try:
        deadline = time.time() + 60
        while True:
            if proc.poll() is not None:
                raise RuntimeError(f"server exited: {log_path.read_text(errors='replace')[-2000:]}")
            try:
                with urllib.request.urlopen(f"{base_url}/health", timeout=2) as response:
                    if response.status == 200:
                        break
            except OSError:
                pass
            if time.time() > deadline:
                raise RuntimeError(f"server did not come up: {log_path.read_text(errors='replace')[-2000:]}")
            time.sleep(0.3)
        yield base_url, log_path
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()


def call_tool_over_http(base_url: str, name: str, arguments: dict) -> dict:
    """Initialize an MCP session over streamable HTTP with the bearer token and call a tool."""
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    async def run():
        headers = {"Authorization": f"Bearer {TOKEN}"}
        async with streamablehttp_client(f"{base_url}/", headers=headers) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                result = await session.call_tool(name, arguments)
                text = "".join(getattr(block, "text", "") for block in result.content)
                return json.loads(text) if text.strip().startswith("{") else {"error": text, "isError": result.isError}

    return asyncio.run(run())
