"""Servidor MCP (lógica testável com falsos, sem rede/browser)."""

import asyncio
import base64
import json

import pytest

from gerid_adapter import mcp_server as mcp


def run(coro):
    return asyncio.run(coro)


def test_sanitize_strips_urls_and_secrets():
    assert mcp.sanitize("GET https://x.test/a falhou (500)") == "GET [url] falhou (500)"
    assert "tok" not in mcp.sanitize("Authorization: Bearer tok123")


def test_attachment_filename_is_safe():
    assert mcp.attachment_filename('attachment; filename="a b.pdf"', "f.bin") == "a b.pdf"
    assert mcp.attachment_filename("../../etc/passwd", "f.bin") == "passwd"
    assert mcp.attachment_filename(None, "f.bin") == "f.bin"


def test_save_download_writes_restricted_file(tmp_path):
    data = base64.b64encode(b"%PDF-1.4 oi").decode()
    meta = mcp.save_download(data, 'attachment; filename="doc.pdf"', "fb.bin", tmp_path)
    assert meta["filename"] == "doc.pdf" and meta["bytes"] == 11 and meta["is_pdf"]
    assert (tmp_path / "doc.pdf").stat().st_mode & 0o777 == 0o600
    again = mcp.save_download(data, 'attachment; filename="doc.pdf"', "fb.bin", tmp_path)
    assert again["filename"] == "doc-1.pdf"  # não sobrescreve


def test_save_download_rejects_garbage(tmp_path):
    with pytest.raises(ValueError):
        mcp.save_download("não-é-base64!!!", None, "fb.bin", tmp_path)
    with pytest.raises(ValueError):
        mcp.save_download("", None, "fb.bin", tmp_path)


class FakePortal:
    def __init__(self, **responses):
        self.responses = responses
        self.seen = []

    def notifications(self, captcha, first=0):
        self.seen.append(("notifications", captcha, first))
        return self.responses["notifications"]

    def search_tasks(self, captcha, **options):
        self.seen.append(("search", captcha, options))
        return self.responses["search"]

    def get_task(self, protocolo):
        return self.responses["get_task"]

    def attachment(self, protocolo, anexo_id):
        return self.responses["attachment"]

    def process(self, protocolo):
        return self.responses["process"]


def test_do_notifications_uses_fresh_captcha(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp, "do_ensure", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(mcp, "_state_dir", lambda: tmp_path)
    monkeypatch.setattr(mcp, "_mint", lambda state_dir, backend=None: "RC-1")
    portal = FakePortal(notifications={"notificacoes": [{"id": 1}]})
    assert mcp.do_notifications(5, calls=(portal, None))["notificacoes"] == [{"id": 1}]
    assert portal.seen == [("notifications", "RC-1", 5)]


def test_do_search_tasks_passes_filters(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp, "do_ensure", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(mcp, "_state_dir", lambda: tmp_path)
    monkeypatch.setattr(mcp, "_mint", lambda state_dir, backend=None: "RC-2")
    portal = FakePortal(search={"tarefas": []})
    assert mcp.do_search_tasks(calls=(portal, None), page=2, page_size=10, status="X") == {"tarefas": []}
    assert portal.seen[0][0] == "search" and portal.seen[0][1] == "RC-2"


def test_fresh_captcha_retries_once_on_400(monkeypatch, tmp_path):
    from gerid_adapter.api import ApiError

    def boom(payload):
        error = ApiError("POST x falhou (400)")
        error.status = 400
        raise error

    class Portal:
        def __init__(self):
            self.calls = 0

        def notifications(self, captcha, first=0):
            self.calls += 1
            if self.calls == 1:
                boom(None)
            return {"notificacoes": [captcha]}

    mints = []
    monkeypatch.setattr(mcp, "_mint", lambda state_dir, backend=None: mints.append(backend) or f"RC-{len(mints)}")
    portal = Portal()
    assert mcp._with_fresh_captcha(lambda c: portal.notifications(c), tmp_path) == {"notificacoes": ["RC-2"]}
    assert len(mints) == 2


def test_fresh_captcha_does_not_retry_other_errors(monkeypatch, tmp_path):
    from gerid_adapter.api import ApiError

    def fail(token):
        error = ApiError("POST x falhou (500)")
        error.status = 500
        raise error

    monkeypatch.setattr(mcp, "_mint", lambda state_dir, backend=None: "RC-1")
    with pytest.raises(ApiError):
        mcp._with_fresh_captcha(fail, tmp_path)


def test_do_get_attachment_saves_file(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp, "do_ensure", lambda *a, **k: {"ok": True})
    payload = {"base64": base64.b64encode(b"%PDF-dados").decode(), "filename": "a.pdf"}
    portal = FakePortal(attachment=payload)
    meta = mcp.do_get_attachment("123", "456", portal=portal, directory=tmp_path)
    assert meta["filename"] == "123-456-a.pdf" and meta["bytes"] == 10 and meta["markdown"] == ""
    again = mcp.do_get_attachment("123", "456", portal=portal, directory=tmp_path)
    assert again["filename"] == "123-456-a.pdf"  # mesmo anexo: substitui, sem cópia -1
    assert sorted(p.name for p in tmp_path.iterdir() if not p.name.endswith(".text.json")) == ["123-456-a.pdf"]


def test_attachment_with_explicit_filename_keeps_it(monkeypatch, tmp_path):
    monkeypatch.setattr(mcp, "do_ensure", lambda *a, **k: {"ok": True})
    payload = {"base64": base64.b64encode(b"%PDF-dados").decode(), "filename": "a.pdf"}
    meta = mcp.do_get_attachment("123", "456", "meu.pdf", portal=FakePortal(attachment=payload), directory=tmp_path)
    assert meta["filename"] == "meu.pdf"


def test_do_get_process_without_report_is_a_clear_error(monkeypatch):
    class Portal:
        def process(self, protocolo):
            return {"protocolo": 1, "relatorio": None}

    monkeypatch.setattr(mcp, "do_ensure", lambda *a, **k: {"ok": True})
    with pytest.raises(LookupError, match="processo 1"):
        mcp.do_get_process("1", portal=Portal())


def test_missing_task_is_a_clear_tool_error(monkeypatch):
    monkeypatch.setattr(mcp, "do_ensure", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(mcp, "_portal", lambda: FakePortal(get_task=None))
    with pytest.raises(mcp.ToolError, match="protocolo 999 não encontrado"):
        run(mcp.get_task_tool("999"))


TASK = {
    "protocolo": 111, "status": "CONCLUIDA", "nomeServico": "Benefício Assistencial à Pessoa com Deficiência",
    "dataEntradaRequerimento": "2026-09-02T13:25:37", "nomeUnidade": "CEAB",
    "interessados": [{"nome": "FULANO", "cpf": 1234567, "dataNascimento": "2018-05-13", "nomeMae": "MAE"}] * 2,
    "procuradores": [{"nomeOuRazaoSocial": "ADV"}],
    "comentarios": [
        {"dataCriacao": "2026-09-02T13:25:47", "conteudo": "<p>Biometria&nbsp;<strong>pendente</strong></p><ul><li>CIN</li></ul>"},
        {"dataCriacao": "2026-10-16T11:16:10", "conteudo": (
            "<p>Em atenção ao requerimento ... nº 700.000.000-1, a Previdência Social comunica que não foi "
            "reconhecido o direito ao benefício.<BR>...motivo(s):<BR><BR>Não comparecimento para realização "
            "de exame médico pericial<BR><BR>Comunicamos que os agendamentos...</p>")},
    ],
    "agendamentosPericia": [{"descricaoDataHoraAgendamento": "30/09/2026 às 14:30", "situacaoAgendamento": "CUMPRIDO",
                             "nomeUnidade": "APS EXEMPLO", "protocolo": 11111111}],
    "descricaoEtapaPericia": "Cancelado por não comparecimento",
    "anexos": [{"id": 1, "nomeArquivo": "a.pdf", "descricaoArquivo": "Doc", "categoria": "INICIAL"}] * 2,
    "anexosIniciais": [{"id": 1}], "camposAdicionais": [{"nome": "x"}] * 10,
}


def test_compact_task_keeps_essentials_without_noise():
    view = mcp.compact_task(TASK)
    assert view["decisao"] == {"resultado": "indeferido", "data": "2026-10-16T11:16:10", "nb": "700.000.000-1",
                               "motivo": "Não comparecimento para realização de exame médico pericial"}
    assert len(view["interessados"]) == 1 and view["interessados"][0]["cpf"] == "00001234567"
    assert view["interessados"][0]["menor"] is True
    assert len(view["anexos"]) == 1 and "anexosIniciais" not in view and "camposAdicionais" not in view
    assert view["comentarios"][0]["texto"] == "Biometria pendente\n- CIN"
    assert view["agendamentos"][0]["situacao"] == "CUMPRIDO" and view["etapas"]["pericia"].startswith("Cancelado")
    assert len(json.dumps(view)) < len(json.dumps(TASK))


def test_get_task_full_returns_raw(monkeypatch):
    monkeypatch.setattr(mcp, "do_ensure", lambda *a, **k: {"ok": True})
    assert mcp.do_get_task("111", portal=FakePortal(get_task=TASK), full=True) is TASK


def test_do_list_downloads(tmp_path):
    assert mcp.do_list_downloads(tmp_path) == {"files": []}
    (tmp_path / "b.pdf").write_bytes(b"22")
    (tmp_path / "a.pdf").write_bytes(b"1")
    files = mcp.do_list_downloads(tmp_path)["files"]
    assert [f["filename"] for f in files] == ["a.pdf", "b.pdf"]
    assert files[0]["bytes"] == 1 and files[0]["path"].endswith("a.pdf")


def test_call_wraps_errors_as_tool_error():
    from mcp.server.mcpserver.exceptions import ToolError

    async def boom():
        raise ValueError("GET https://x.test/a ruim")

    with pytest.raises(ToolError, match=r"rotulo: GET \[url\] ruim"):
        run(mcp._call(boom(), "rotulo"))


def test_call_never_leaks_traceback():
    from mcp.server.mcpserver.exceptions import ToolError

    async def boom():
        raise TypeError("detalhe interno xyz")

    with pytest.raises(ToolError, match=r"falha inesperada \(TypeError\)"):
        run(mcp._call(boom(), "rotulo"))


def test_pin_keyring_failure_is_actionable(monkeypatch):
    import keyring
    from gerid_adapter import pin as pin_store

    monkeypatch.setattr(keyring, "get_password", lambda *a: (_ for _ in ()).throw(RuntimeError("dbus fora")))
    with pytest.raises(LookupError, match="Cofre do sistema inacessível"):
        pin_store.get_pin("123")


def test_poster_network_failure_is_actionable(monkeypatch):
    import curl_cffi.requests
    from gerid_adapter.http import impersonated_post_json

    class BadSession:
        def __init__(self, **kwargs):
            pass

        def post(self, *a, **k):
            raise ConnectionError("dns falhou")

    monkeypatch.setattr(curl_cffi.requests, "Session", BadSession)
    with pytest.raises(RuntimeError, match="Falha de rede"):
        impersonated_post_json("https://example.test/x", {})


def test_mint_failure_is_actionable(monkeypatch):
    import cloakbrowser
    from gerid_adapter.recaptcha import mint

    def explode(**kwargs):
        raise RuntimeError("binário bloqueado")

    monkeypatch.setattr(cloakbrowser, "launch", explode)
    with pytest.raises(RuntimeError, match="Mint do captcha falhou"):
        mint({})


def test_do_diagnose_lists_only_problems(monkeypatch):
    from gerid_adapter import poc as poc_mod

    monkeypatch.setattr(
        poc_mod, "diagnose",
        lambda: {"token": "T (série 1)", "pin": "ok (no cofre)", "totp": "ausente no cofre (grave com: x)"},
    )
    monkeypatch.setattr(
        "gerid_adapter.net.gerid_status",
        lambda: {"tcp_443": "ok (0.05s)", "tcp_8443": "ok (0.05s)",
                 "egress_ip": "1.2.3.4", "veredito": "rede ok"},
    )
    result = mcp.do_diagnose()
    assert result["problemas"] == [{"item": "TOTP", "estado": result["totp"]}]
    assert result["token"] == "T (série 1)"


def test_do_diagnose_flags_dead_port(monkeypatch):
    from gerid_adapter import poc as poc_mod

    monkeypatch.setattr(
        poc_mod, "diagnose",
        lambda: {"token": "T (série 1)", "pin": "ok (no cofre)", "totp": "ok (no cofre)"},
    )
    monkeypatch.setattr(
        "gerid_adapter.net.gerid_status",
        lambda: {"tcp_443": "ok (0.05s)", "tcp_8443": "falhou (TimeoutError após 4.0s)",
                 "egress_ip": "9.9.9.9", "veredito": "porta 8443 filtrada"},
    )
    result = mcp.do_diagnose()
    assert result["problemas"] == [{"item": "rede", "estado": "porta 8443 filtrada"}]


def test_do_ensure_failure_names_the_cause(monkeypatch, tmp_path):
    from mcp.server.mcpserver.exceptions import ToolError

    async def fail_ensure(*a, **k):
        raise RuntimeError("renovação da sessão falhou (token A3: ausente (x)). Conecte o token A3")

    async def call():
        return await mcp._call(fail_ensure(), "gerid_ensure_session")

    with pytest.raises(ToolError, match="token A3"):
        run(call())


def test_call_runs_sync_operations_off_the_event_loop():
    """Playwright sync recusa rodar dentro do loop asyncio: _call usa uma thread."""
    import threading

    def operation():
        with pytest.raises(RuntimeError):
            asyncio.get_running_loop()  # sem loop nesta thread
        return {"thread": threading.current_thread() is not threading.main_thread()}

    assert run(mcp._call(operation, "x")) == {"thread": True}


def test_mint_stamps_session_time(monkeypatch, tmp_path):
    """A SPA manda para o login do CAS se ifs_ts + ifs_ei venceu: carimbar agora."""
    old = "Fri Oct 16 2026 04:10:25 GMT-0300 (Horário Padrão de Brasília)"
    (tmp_path / "portal-session.json").write_text(json.dumps({"ifs_auth": "JWT", "ifs_ts": old, "ifs_iat": old}))
    seen = {}
    monkeypatch.setattr(mcp.recaptcha_mod, "mint", lambda state, **kw: seen.update(state) or "RC")
    monkeypatch.setattr(mcp, "js_now", lambda: "AGORA")
    assert mcp._mint(tmp_path) == "RC"
    assert seen["ifs_ts"] == seen["ifs_iat"] == "AGORA" and seen["ifs_auth"] == "JWT"


def test_document_result_puts_text_in_structured_content():
    """Clientes que leem só o structured_content (Claude Code) também recebem o texto."""
    result = mcp.document_result({"filename": "a.pdf", "markdown": "TEXTO"})
    assert result.structured_content["text"] == "TEXTO"
    assert result.structured_content["textReturned"] is True
    assert any("TEXTO" in part.text for part in result.content)


def test_get_process_reuses_recent_copy_without_network(monkeypatch, tmp_path):
    (tmp_path / "123-processo.pdf").write_bytes(b"%PDF-1.4 velho")
    monkeypatch.setattr(mcp, "do_ensure", lambda *a, **k: pytest.fail("não deveria tocar na sessão"))
    monkeypatch.setattr(mcp.docs, "analyze_document", lambda content, name: {"markdown": "TXT"})
    result = mcp.do_get_process("123", portal=object(), directory=tmp_path)
    assert result["reutilizado"] is True and result["markdown"] == "TXT"


def test_get_process_refresh_overwrites_canonical(monkeypatch, tmp_path):
    (tmp_path / "123-processo.pdf").write_bytes(b"%PDF-1.4 velho")
    monkeypatch.setattr(mcp, "do_ensure", lambda *a, **k: {"ok": True})
    monkeypatch.setattr(mcp.docs, "analyze_document", lambda content, name: {"markdown": "NOVO"})
    portal = FakePortal(process={"protocolo": 123, "relatorio": base64.b64encode(b"%PDF-1.4 novo").decode()})
    result = mcp.do_get_process("123", portal=portal, directory=tmp_path, refresh=True)
    assert result["reutilizado"] is False and result["filename"] == "123-processo.pdf"
    assert (tmp_path / "123-processo.pdf").read_bytes() == b"%PDF-1.4 novo"
    assert result["markdown"] == "NOVO"  # cache antigo não vale para o arquivo novo


def test_list_downloads_hides_text_cache(tmp_path):
    (tmp_path / "a.pdf").write_bytes(b"x")
    (tmp_path / "a.pdf.text.json").write_text("{}")
    assert [f["filename"] for f in mcp.do_list_downloads(tmp_path)["files"]] == ["a.pdf"]


def test_stdio_prints_never_reach_the_protocol_pipe(tmp_path):
    """Ponta a ponta: um print dentro de ferramenta (como os da cascata) não pode
    aparecer no stdout do servidor stdio, nem no encerramento."""
    import subprocess
    import sys

    server = tmp_path / "srv.py"
    server.write_text(
        "import asyncio\n"
        "from gerid_adapter import mcp_server as m\n"
        "@m.server.tool(name='talk')\n"
        "async def talk() -> dict:\n"
        "    return await m._call(lambda: print('VAZOU') or {'ok': True}, 'talk')\n"
        "m.main([])\n"
    )
    requests = "\n".join([
        '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18",'
        '"capabilities":{},"clientInfo":{"name":"t","version":"1"}}}',
        '{"jsonrpc":"2.0","method":"notifications/initialized"}',
        '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"talk","arguments":{}}}',
    ]) + "\n"
    proc = subprocess.Popen([sys.executable, str(server)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    proc.stdin.write(requests)
    proc.stdin.flush()
    lines = []
    while not any('"id":2' in line for line in lines):  # segura o stdin até a resposta da ferramenta
        line = proc.stdout.readline()
        assert line, proc.stderr.read()
        lines.append(line)
    proc.stdin.close()  # encerra: é aqui que o buffer retido vazava para o pipe
    rest, stderr = proc.stdout.read(), proc.stderr.read()
    proc.wait(timeout=30)
    lines += rest.splitlines()
    assert all(json.loads(line)["jsonrpc"] == "2.0" for line in lines if line.strip())
    assert "VAZOU" in stderr


def test_html_to_text_indents_nested_lists():
    source = ("<p>Liberada:</p><ul><li>Maior de 80 anos</li><li>Migrantes com:<ul><li>Registro;</li>"
              "<li>Protocolo</li></ul></li><li>Outros</li></ul><p><strong>Atenção!</strong>&nbsp;Fim</p>")
    assert mcp.html_to_text(source) == (
        "Liberada:\n- Maior de 80 anos\n- Migrantes com:\n  - Registro;\n  - Protocolo\n- Outros\nAtenção! Fim"
    )


def test_compact_task_summarizes_open_requirement():
    task = {**TASK, "tipoExigencia": "FALTA_BIOMETRIA", "definicoesAnexoExigencia": [
        {"nome": "Comprovante do cadastro biométrico do titular", "obrigatorio": False, "ativo": True,
         "extensoes": ["pdf", "jpg"]},
        {"nome": "Inativo", "ativo": False},
    ]}
    assert mcp.compact_task(task)["exigencia"] == {
        "tipo": "FALTA_BIOMETRIA",
        "documentosExigidos": [{"nome": "Comprovante do cadastro biométrico do titular", "obrigatorio": False,
                                "extensoes": ["pdf", "jpg"]}],
        "camposExigidos": [],
    }
    assert mcp.compact_task(TASK)["exigencia"] is None


def test_fresh_captcha_switches_browser_when_recaptcha_is_rejected(monkeypatch, tmp_path):
    """Perfil cdp com nota baixa (400 "Erro de validação do reCAPTCHA"): o mesmo pedido passa com o outro navegador."""
    from gerid_adapter.api import ApiError

    monkeypatch.setenv("INSS_BROWSER", "cdp")
    used = []
    monkeypatch.setattr(mcp, "_mint", lambda state_dir, backend=None: used.append(backend) or f"RC-{backend}")

    def call(token):
        if token == "RC-cdp":
            error = ApiError("POST x falhou (400): Erro de validação do reCAPTCHA.")
            error.status = 400
            raise error
        return {"ok": token}

    assert mcp._with_fresh_captcha(call, tmp_path) == {"ok": "RC-cloak"}
    assert used == ["cdp", "cloak"]


def test_fresh_captcha_switches_browser_when_mint_fails(monkeypatch, tmp_path):
    monkeypatch.delenv("INSS_BROWSER", raising=False)

    def mint(state_dir, backend=None):
        if backend == "cloak":
            raise RuntimeError("Mint do captcha falhou")
        return "RC-cdp"

    monkeypatch.setattr(mcp, "_mint", mint)
    assert mcp._with_fresh_captcha(lambda token: {"ok": token}, tmp_path) == {"ok": "RC-cdp"}
