"""Heartbeat pings the configured URL and never raises on failure."""

from obsidian_vault_mcp import server


def test_ping_hits_url(monkeypatch):
    seen = {}

    class FakeResp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b""

    def fake_urlopen(url, timeout):
        seen["url"] = url
        seen["timeout"] = timeout
        return FakeResp()

    monkeypatch.setattr(server.urllib.request, "urlopen", fake_urlopen)
    server._heartbeat_ping("http://monitor.example/push")
    assert seen["url"] == "http://monitor.example/push"


def test_loop_swallows_errors(monkeypatch):
    """A failing ping is logged and the loop proceeds to sleep, never propagating."""
    def boom(url):
        raise OSError("down")

    def stop(_):
        raise KeyboardInterrupt  # break out of the otherwise-infinite loop

    monkeypatch.setattr(server, "_heartbeat_ping", boom)
    monkeypatch.setattr(server.time, "sleep", stop)

    try:
        server._heartbeat_forever("http://x", 1)
    except KeyboardInterrupt:
        pass  # reaching sleep proves the OSError from the ping was swallowed
