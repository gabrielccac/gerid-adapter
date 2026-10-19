"""Rotas com captcha e o oráculo headless, com transporte/página falsos (sem rede)."""

import base64
import json

import pytest

from gerid_adapter.api import ApiError, PortalApi, _search_date
from gerid_adapter.http import Response, impersonated_post_json
from gerid_adapter.recaptcha import FINGERPRINT_SEED, SITE_KEY, mint


def token_with(**claims):
    def segment(payload):
        return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    return f"{segment({'alg': 'RS256'})}.{segment(claims)}."


class FakeTransport:
    def get(self, url, cookies=None, referer=None, headers=None):
        raise AssertionError("GET não esperado aqui")


def make_api(responses):
    calls = []

    def poster(url, payload, headers=None):
        calls.append({"url": url, "payload": payload, "headers": headers})
        return responses.pop(0)

    token = token_with(**{"cpf": "02806598222", "auth-user-agent": "gerid-adapter-poc"})
    return PortalApi(token, poster=poster), calls


def response(status, body=b""):
    return Response("", status, [], body)


def test_notifications_posts_token_with_same_origin():
    client, calls = make_api([response(200, b'{"notificacoes": []}')])
    assert client.notifications("RC-1", first=5) == {"notificacoes": []}
    sent = calls[0]
    assert sent["url"].endswith("/notificacao?first=5")
    assert sent["payload"] == {"tokenReCAPTCHA": "RC-1"}
    assert sent["headers"]["Origin"] == "https://atendimento.inss.gov.br"
    assert sent["headers"]["Sec-Fetch-Site"] == "same-origin"
    assert sent["headers"]["Authorization"].startswith("Bearer ")


def test_notifications_rejects_negative_first():
    client, _ = make_api([])
    with pytest.raises(ValueError):
        client.notifications("RC-1", first=-1)


def test_search_tasks_posts_expected_shape():
    client, calls = make_api([response(200, b'{"tarefas": []}')])
    result = client.search_tasks("RC-2", page=2, page_size=10, status="Pendente")
    assert result == {"tarefas": []}
    sent = calls[0]
    assert sent["url"].endswith("/tarefa/consulta?first=10&pageSize=10")
    assert sent["payload"]["tokenReCAPTCHA"] == "RC-2"
    assert sent["payload"]["status"] == "Pendente"
    assert sent["payload"]["dataAtualizacaoInicial"].endswith("T03:00:00.000Z")


def test_search_tasks_validates_pagination():
    client, _ = make_api([])
    with pytest.raises(ValueError):
        client.search_tasks("RC", page=0)
    with pytest.raises(ValueError):
        client.search_tasks("RC", page_size=101)


def test_post_error_raises_with_status():
    client, _ = make_api([response(400, b'{"message":"x"}')])
    with pytest.raises(ApiError, match="400"):
        client.notifications("RC-BAD")


def test_impersonated_post_json_round_trip(monkeypatch):
    import curl_cffi.requests

    seen = {}

    class FakeResponse:
        status_code = 200
        headers = {"Content-Type": "application/json"}
        content = b'{"ok": true}'

    class FakeSession:
        def __init__(self, **kwargs):
            seen["session_kwargs"] = kwargs

        def post(self, url, json=None, headers=None, timeout=None):
            seen.update(url=url, payload=json, headers=headers)
            return FakeResponse()

    monkeypatch.setattr(curl_cffi.requests, "Session", FakeSession)
    response = impersonated_post_json(
        "https://example.test/apis/x?first=0", {"a": 1}, {"Authorization": "Bearer T"}
    )
    assert response.status == 200 and response.body == b'{"ok": true}'
    assert seen["url"] == "https://example.test/apis/x?first=0"
    assert seen["payload"] == {"a": 1}
    assert seen["headers"]["Authorization"] == "Bearer T"
    assert seen["session_kwargs"]["impersonate"] == "chrome"


def test_search_date_accepts_iso_and_rejects_garbage():
    assert _search_date("2026-04-17", None) == "2026-04-17T03:00:00.000Z"
    with pytest.raises(ValueError):
        _search_date("17/04/2026", None)


class FakePage:
    def __init__(self, title="Portal de Atendimento | INSS"):
        self.evaluated = None
        self._title = title

    def title(self):
        return self._title

    def set_default_timeout(self, timeout):
        pass

    def goto(self, url, wait_until=None, timeout=None):
        pass

    def wait_for_function(self, expression, timeout=None):
        pass

    def evaluate(self, expression, arg):
        self.evaluated = arg
        return "RC-MINTED"


class FakeContext:
    def __init__(self):
        self.page = FakePage()
        self.init_script = None

    def add_init_script(self, script):
        self.init_script = script

    def new_page(self):
        return self.page


class FakeBrowser:
    def __init__(self):
        self.context = FakeContext()
        self.closed = False

    def new_context(self, **kwargs):
        return self.context

    def close(self):
        self.closed = True


def test_mint_injects_state_and_returns_token(monkeypatch):
    import cloakbrowser

    browser = FakeBrowser()
    monkeypatch.setattr(cloakbrowser, "launch", lambda **kwargs: browser)
    state = {"ifs_auth": "JWT", "base_url": "https://atendimento.inss.gov.br/apis/"}
    assert mint(state) == "RC-MINTED"
    assert browser.closed
    assert '"ifs_auth"' in browser.context.init_script
    assert browser.context.page.evaluated["key"] == SITE_KEY
    assert FINGERPRINT_SEED  # seed fixa documentada


def test_execute_refuses_login_page():
    import gerid_adapter.recaptcha as recaptcha_mod

    page = FakePage(title="Login - CAS")
    with pytest.raises(RuntimeError, match="sessão morta no servidor"):
        recaptcha_mod._execute_token(page, "KEY", None)
    assert page.evaluated is None  # nem tenta o execute fora do portal


def test_mint_dispatches_backends(monkeypatch):
    import gerid_adapter.recaptcha as recaptcha_mod

    calls = []
    monkeypatch.setattr(recaptcha_mod, "mint_cloak", lambda *a, **k: calls.append("cloak") or "RC-CLOAK")
    monkeypatch.setattr(recaptcha_mod, "mint_cdp", lambda *a, **k: calls.append("cdp") or "RC-CDP")
    assert mint({}, backend_name="cloak") == "RC-CLOAK"
    assert mint({}, backend_name="cdp") == "RC-CDP"
    assert calls == ["cloak", "cdp"]
    with pytest.raises(ValueError):
        mint({}, backend_name="navegador-qualquer")


def test_stage_profile_copies_without_locks(tmp_path):
    import gerid_adapter.recaptcha as recaptcha_mod

    src = tmp_path / "aquecido"
    (src / "Default").mkdir(parents=True)
    (src / "Default" / "Cookies").write_text("c")
    (src / "SingletonLock").write_text("travado")
    staged = recaptcha_mod._stage_profile(src)
    try:
        assert staged.is_dir() and staged != src.resolve()
        assert (staged / "Default" / "Cookies").exists()
        assert not (staged / "SingletonLock").exists()
    finally:
        import shutil

        shutil.rmtree(staged, ignore_errors=True)


def test_stage_profile_missing_raises(tmp_path):
    import gerid_adapter.recaptcha as recaptcha_mod

    with pytest.raises(RuntimeError, match="Perfil aquecido não encontrado"):
        recaptcha_mod._stage_profile(tmp_path / "inexistente")


def test_free_port_is_connectable():
    import socket

    import gerid_adapter.recaptcha as recaptcha_mod

    port = recaptcha_mod._free_port()
    assert isinstance(port, int) and port > 0
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", port))  # ninguém segurou: estava livre mesmo


def test_chrome_cmd_uses_own_profile_and_port(tmp_path):
    import gerid_adapter.recaptcha as recaptcha_mod

    binary = tmp_path / "chrome-falso"
    binary.write_bytes(b"x")
    profile = tmp_path / "meu-perfil"
    cmd = recaptcha_mod.chrome_cmd(str(binary), port=9999, profile_dir=profile)
    assert cmd[0] == str(binary)
    assert "--remote-debugging-port=9999" in cmd
    assert f"--user-data-dir={profile.resolve()}" in cmd
    assert profile.is_dir()


def test_chrome_executable_prefers_configured(tmp_path):
    import gerid_adapter.recaptcha as recaptcha_mod

    binary = tmp_path / "chrome-falso"
    binary.write_bytes(b"x")
    assert recaptcha_mod.chrome_executable(str(binary)) == str(binary)


def test_chrome_cmd_headless_flag(tmp_path):
    import gerid_adapter.recaptcha as recaptcha_mod

    cmd = recaptcha_mod.chrome_cmd(
        str(tmp_path / "x"), port=9999, profile_dir=tmp_path / "p", headless=True
    )
    assert "--headless=new" in cmd
    headed = recaptcha_mod.chrome_cmd(
        str(tmp_path / "x"), port=9999, profile_dir=tmp_path / "p", headless=False
    )
    assert "--headless=new" not in headed


def _captcha_args(tmp_path, **overrides):
    import argparse

    args = argparse.Namespace(
        session_state=str(tmp_path / "portal-session.json"),
        browser="cloak",
        headless=False,
        first=0,
        page=1,
        page_size=20,
    )
    for key, value in overrides.items():
        setattr(args, key, value)
    return args


class FakeClient:
    def __init__(self, effects):
        self.effects = list(effects)
        self.mints_seen = []

    def notifications(self, captcha, first=0):
        effect = self.effects.pop(0)
        if isinstance(effect, Exception):
            raise effect
        return effect


def _api_error(status):
    from gerid_adapter.api import ApiError

    error = ApiError(f"POST x falhou ({status})")
    error.status = status
    return error


def test_captcha_call_succeeds_first_try(monkeypatch, tmp_path):
    from gerid_adapter.poc import _captcha_call
    import gerid_adapter.recaptcha as recaptcha_mod

    (tmp_path / "portal-session.json").write_text('{"ifs_auth": "JWT"}')
    monkeypatch.setattr(recaptcha_mod, "mint", lambda *a, **k: "RC-1")
    client = FakeClient([{"notificacoes": []}])
    result, failure = _captcha_call(_captcha_args(tmp_path), client, "notifications")
    assert failure is None and result == {"notificacoes": []}


def test_captcha_call_retries_once_on_400(monkeypatch, tmp_path):
    from gerid_adapter.poc import _captcha_call
    import gerid_adapter.recaptcha as recaptcha_mod

    (tmp_path / "portal-session.json").write_text('{"ifs_auth": "JWT"}')
    mints = []
    monkeypatch.setattr(recaptcha_mod, "mint", lambda *a, **k: mints.append(1) or f"RC-{len(mints)}")
    client = FakeClient([_api_error(400), {"notificacoes": [1]}])
    result, failure = _captcha_call(_captcha_args(tmp_path), client, "notifications")
    assert failure is None and result == {"notificacoes": [1]}
    assert len(mints) == 2


def test_captcha_call_does_not_retry_other_errors(monkeypatch, tmp_path):
    from gerid_adapter.poc import _captcha_call
    import gerid_adapter.recaptcha as recaptcha_mod

    (tmp_path / "portal-session.json").write_text('{"ifs_auth": "JWT"}')
    monkeypatch.setattr(recaptcha_mod, "mint", lambda *a, **k: "RC-1")
    client = FakeClient([_api_error(500)])
    result, failure = _captcha_call(_captcha_args(tmp_path), client, "notifications")
    assert result is None and "500" in failure


def test_captcha_call_without_state_file(tmp_path):
    from gerid_adapter.poc import _captcha_call

    result, failure = _captcha_call(_captcha_args(tmp_path), FakeClient([]), "notifications")
    assert result is None and "gerid-poc session" in failure


class RecordingPage(FakePage):
    def __init__(self):
        super().__init__()
        self.expressions = []

    def wait_for_function(self, expression, timeout=None):
        self.expressions.append(expression)

    def evaluate(self, expression, arg):
        self.expressions.append(expression)
        return super().evaluate(expression, arg)


def test_wait_requires_enterprise_not_plain_grecaptcha():
    """O portal também carrega o api.js comum: aceitar `grecaptcha` comum fazia o
    execute com key enterprise nunca resolver (travamento intermitente)."""
    import gerid_adapter.recaptcha as recaptcha_mod

    page = RecordingPage()
    recaptcha_mod._wait_grecaptcha(page, 1000)
    predicate = page.expressions[0]
    assert "grecaptcha.enterprise.execute" in predicate
    assert "|| window.grecaptcha" not in predicate


def test_execute_uses_enterprise_and_has_time_limit():
    import gerid_adapter.recaptcha as recaptcha_mod

    page = RecordingPage()
    assert recaptcha_mod._execute_token(page, "KEY", None) == "RC-MINTED"
    script = page.expressions[-1]
    assert "window.grecaptcha.enterprise;" in script
    assert "setTimeout" in script and "Promise.race" in script  # nunca pendura para sempre
