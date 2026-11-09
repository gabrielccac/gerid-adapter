from types import SimpleNamespace

from gerid_adapter import mcp_server, recaptcha_http


def test_enterprise_http_uses_fresh_anchor_and_portal_action(monkeypatch):
    calls = []

    class Session:
        def __init__(self, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            pass

        def request(self, method, url, **kwargs):
            calls.append((method, url, kwargs))
            body = {
                "enterprise.js": "https://www.gstatic.com/recaptcha/releases/test_release/recaptcha__pt_br.js",
                "anchor": '<input value="fresh-anchor" id="recaptcha-token">',
                "reload": ")]}'\n[\"rresp\",\"new-token\"]",
            }[url.rsplit("/", 1)[1]]
            return SimpleNamespace(status_code=200, text=body, url=url + "?test=1")

    monkeypatch.setattr(recaptcha_http, "site_key", lambda: "fixture-key")
    monkeypatch.setattr(recaptcha_http.requests, "Session", Session)

    assert recaptcha_http.mint_http() == "new-token"
    assert [method for method, _, _ in calls] == ["GET", "GET", "POST"]
    assert calls[1][2]["params"]["v"] == "test_release"
    assert calls[1][2]["params"]["co"] == "aHR0cHM6Ly9hdGVuZGltZW50by5pbnNzLmdvdi5icjo0NDM."
    assert calls[2][2]["data"] == (
        b"\x0a\x0ctest_release\x12\x0cfresh-anchor\x32\x01q"
        b"\x42\x12buscaRequerimentos\x72\x0bfixture-key"
    )


def test_http_experiment_has_no_browser_fallback(monkeypatch):
    monkeypatch.setenv("INSS_BROWSER", "http")
    assert mcp_server._attempts() == ["http"]
