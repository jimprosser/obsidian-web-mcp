"""Generic post-write hook dispatcher.

After any vault mutation, tools call fire_post_write() with a human-readable
operation string and the list of affected vault-relative paths.

If ``VAULT_MCP_POST_WRITE_CMD`` is set, that shell command is executed
fire-and-forget in a daemon thread.  Two environment variables are injected:

    MCP_OPERATION   — e.g. "created", "updated", "deleted"
    MCP_PATHS       — colon-separated vault-relative paths

If the variable is not set, fire_post_write() is a no-op.
"""

import logging
import os
import subprocess
import threading
from collections.abc import Sequence

from .config import VAULT_MCP_POST_WRITE_CMD

logger = logging.getLogger(__name__)

_PATH_SEP = ":"


def _run_cmd(cmd: str, operation: str, paths: list[str]) -> None:
    """Execute the configured post-write shell command.

    Called inside a daemon thread — never raises, only logs.
    """
    env = os.environ.copy()
    env["MCP_OPERATION"] = operation
    env["MCP_PATHS"] = _PATH_SEP.join(paths)

    try:
        result = subprocess.run(
            cmd,
            shell=True,
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            logger.warning(
                "post-write hook exited %d: %s",
                result.returncode,
                result.stderr.strip(),
            )
        else:
            logger.debug("post-write hook ok: %s %s", operation, paths)
    except subprocess.TimeoutExpired:
        logger.warning("post-write hook timed out: %s %s", operation, paths)
    except Exception as exc:
        logger.warning("post-write hook error: %s", exc)


def fire_post_write(operation: str, paths: Sequence[str]) -> None:
    """Dispatch a post-write hook fire-and-forget.

    Does nothing if ``VAULT_MCP_POST_WRITE_CMD`` is not configured.

    Args:
        operation: Human-readable verb describing the mutation
                   (e.g. "created", "updated", "deleted", "moved").
        paths:     Vault-relative paths of the affected files.
    """
    if not VAULT_MCP_POST_WRITE_CMD:
        return

    path_list = list(paths)
    if not path_list:
        return

    t = threading.Thread(
        target=_run_cmd,
        args=(VAULT_MCP_POST_WRITE_CMD, operation, path_list),
        daemon=True,
        name="mcp-post-write",
    )
    t.start()
