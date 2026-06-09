"""Post-write hook: passes operation/paths via env, no-op when unset."""

from obsidian_vault_mcp import hooks


def test_run_cmd_injects_operation_and_paths(monkeypatch):
    captured = {}

    def fake_run(cmd, shell, env, capture_output, text, timeout):
        captured["cmd"] = cmd
        captured["shell"] = shell
        captured["env"] = env

        class R:
            returncode = 0
            stderr = ""

        return R()

    monkeypatch.setattr(hooks.subprocess, "run", fake_run)
    hooks._run_cmd("echo hi", "created", ["a.md", "b.md"])

    assert captured["cmd"] == "echo hi"
    assert captured["shell"] is True
    assert captured["env"]["MCP_OPERATION"] == "created"
    assert captured["env"]["MCP_PATHS"] == "a.md:b.md"


def test_fire_post_write_noop_when_unset(monkeypatch):
    monkeypatch.setattr(hooks, "VAULT_MCP_POST_WRITE_CMD", "")

    def fake_thread(*a, **k):
        raise AssertionError("should not spawn a thread when unset")

    monkeypatch.setattr(hooks.threading, "Thread", fake_thread)
    hooks.fire_post_write("created", ["a.md"])  # must not raise


def test_fire_post_write_noop_when_no_paths(monkeypatch):
    monkeypatch.setattr(hooks, "VAULT_MCP_POST_WRITE_CMD", "echo hi")

    def fake_thread(*a, **k):
        raise AssertionError("should not spawn a thread with no paths")

    monkeypatch.setattr(hooks.threading, "Thread", fake_thread)
    hooks.fire_post_write("updated", [])  # empty path list -> no-op


def test_fire_post_write_spawns_daemon_thread_when_configured(monkeypatch):
    spawned = {}

    class FakeThread:
        def __init__(self, target, args, daemon, name):
            spawned["args"] = args
            spawned["daemon"] = daemon

        def start(self):
            spawned["started"] = True

    monkeypatch.setattr(hooks, "VAULT_MCP_POST_WRITE_CMD", "echo hi")
    monkeypatch.setattr(hooks.threading, "Thread", FakeThread)
    hooks.fire_post_write("moved", ["a.md", "b.md"])

    assert spawned["started"] is True
    assert spawned["daemon"] is True
    assert spawned["args"] == ("echo hi", "moved", ["a.md", "b.md"])
