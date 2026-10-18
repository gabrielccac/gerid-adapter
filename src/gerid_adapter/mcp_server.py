"""Servidor MCP do GERID: notificações, tarefas, detalhes e documentos via Claude.

Ferramentas de leitura devolvem JSON; as de documento baixam o PDF e devolvem
o caminho local (`.local/downloads/`, fora do git, 0600) com os metadados.
Nenhum token ou segredo aparece nas respostas: só dados do portal.

Uso (Claude Desktop / Code), via `uv`::

    uv run --directory /caminho/gerid-adapter gerid-mcp

A sessão é renovada sozinha quando preciso (ver `gerid-poc ensure`); as rotas
com captcha mintam um token por chamada em browser headless (ver `recaptcha`).
"""

import argparse
import asyncio
import base64
import binascii
import html
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Annotated, Any
from urllib.parse import unquote

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import CallToolResult, TextContent, ToolAnnotations
from pydantic import Field

from gerid_adapter import docs
from gerid_adapter import recaptcha as recaptcha_mod
from gerid_adapter.api import ApiError, PortalApi, seconds_left
from gerid_adapter.poc import STATE_DIR, ensure_session
from gerid_adapter.session import js_now

READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, idempotentHint=True, openWorldHint=True)
# Não muda nada no INSS, mas pode usar o token A3/PIN e gravar a sessão em .local/.
SESSION = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=True, openWorldHint=True)
LOCAL_WRITE = ToolAnnotations(readOnlyHint=False, destructiveHint=False, idempotentHint=False, openWorldHint=True)
Digits = Annotated[str, Field(pattern=r"^\d+$")]
MaxChars = Annotated[int, Field(ge=1000, le=200_000, description="Tamanho da janela do texto extraído")]
DOWNLOAD_DIR = STATE_DIR / "downloads"
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024

server = MCPServer("gerid-adapter", version="1.0.0")


def sanitize(value):
    """Tira URLs e segredos do texto que chega ao modelo (sem comer prosa como "token A3")."""
    text = re.sub(r"https?://\S+", "[url]", str(value or ""), flags=re.I)
    text = re.sub(r"Bearer\s+[^\s,;]+", "[redacted]", text)
    text = re.sub(r"(?:access[_-]?token|secret|password|passwd|pwd)\s*=\s*[^\s,;]+", "[redacted]", text, flags=re.I)
    text = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[redacted-jwt]", text)
    return re.sub(r"\s+", " ", text).strip()[:2000]


def _state_dir():
    return Path(os.environ.get("GERID_STATE_DIR") or STATE_DIR)


def _load_token():
    from gerid_adapter.api import load_token

    return load_token()


def _portal():
    return PortalApi(_load_token())


def _session_state(state_dir):
    return json.loads((state_dir / "portal-session.json").read_text())


def _mint(state_dir):
    # MCP usa o perfil nativo (cdp) headless: já aquecido e validado; cloak fica
    # disponível via INSS_BROWSER=cloak. Nunca abrir janela no servidor.
    # A SPA confere ifs_ts + ifs_ei (access_token de 10 min) e manda para o login
    # do CAS se venceu; quem vale para a API é o ifs_auth, então carimbamos agora.
    state = _session_state(state_dir)
    state["ifs_ts"] = state["ifs_iat"] = js_now()
    return recaptcha_mod.mint(state,
                              backend_name=os.environ.get("INSS_BROWSER", "cdp"),
                              headless=True)


def do_ensure(state_dir=None):
    """Garante sessão válida (renova sozinho o que expirou)."""
    state_dir = Path(state_dir or _state_dir())
    before = None
    token_file = state_dir / "ifs_auth.jwt"
    if token_file.exists():
        before = token_file.stat().st_mtime
    if ensure_session(argparse.Namespace(dir=str(state_dir), module=None)):
        problems = do_diagnose()
        details = "; ".join(f"{item['item']}: {item['estado']}" for item in problems["problemas"])
        raise RuntimeError(
            f"renovação da sessão falhou ({details or 'sem causa aparente'}). "
            "Conecte o token A3 e confira os segredos no cofre"
        )
    token = (state_dir / "ifs_auth.jwt").read_text().strip()
    after = token_file.stat().st_mtime if token_file.exists() else None
    return {"ok": True, "refreshed": before is None or after != before,
            "valid_minutes": seconds_left(token) // 60}


def do_diagnose():
    """Pré-verificação para o agente: A3? PIN/TOTP? Rede? (sem segredos)."""
    from gerid_adapter import net as netprobe
    from gerid_adapter.poc import diagnose

    state = diagnose()
    net = netprobe.gerid_status()
    problems = [
        {"item": name, "estado": value}
        for name, value in (("token A3", state["token"]), ("PIN", state["pin"]), ("TOTP", state["totp"]))
        if value.startswith(("ausente", "inseguro", "cofre"))
    ]
    if net["tcp_8443"].startswith("falhou"):
        problems.append({"item": "rede", "estado": net["veredito"]})
    return {"problemas": problems, "token": state["token"], "pin": state["pin"],
            "totp": state["totp"], "rede_443": net["tcp_443"], "rede_8443": net["tcp_8443"],
            "egress_ip": net["egress_ip"], "veredito_rede": net["veredito"]}


def _with_fresh_captcha(factory, state_dir):
    """Minta e chama; diante de 400 (perfil esfriando), tenta 1x com token novo."""
    last = None
    for _ in range(2):
        try:
            return factory(_mint(state_dir))
        except ApiError as error:
            last = error
            if getattr(error, "status", None) != 400:
                raise
    raise last


def do_notifications(first=0, calls=None):
    """Notificações da conta PAT (minta captcha e chama a API)."""
    portal, captcha = calls or (None, None)
    state_dir = _state_dir()
    do_ensure(state_dir)
    portal = portal or _portal()
    if captcha is not None:
        return portal.notifications(captcha, first=first)
    return _with_fresh_captcha(lambda token: portal.notifications(token, first=first), state_dir)


def do_search_tasks(calls=None, **options):
    """Busca paginada de tarefas (minta captcha e chama a API)."""
    portal, captcha = calls or (None, None)
    state_dir = _state_dir()
    do_ensure(state_dir)
    portal = portal or _portal()
    page = options.pop("page", 1)
    page_size = options.pop("page_size", 20)
    if captcha is not None:
        return portal.search_tasks(captcha, page=page, page_size=page_size, **options)
    return _with_fresh_captcha(
        lambda token: portal.search_tasks(token, page=page, page_size=page_size, **options), state_dir
    )


def do_get_task(protocolo, portal=None, full=False):
    """Detalhes de uma tarefa: visão compacta (padrão) ou o JSON bruto do portal."""
    do_ensure()
    task = (portal or _portal()).get_task(protocolo)
    if task is None:
        raise LookupError(f"protocolo {protocolo} não encontrado")
    return task if full else compact_task(task)


_TAG = re.compile(r"<(/?)([a-zA-Z0-9]+)[^>]*>")


def html_to_text(value):
    """Comentários do portal vêm em HTML: texto com quebras e listas indentadas."""
    parts, depth, last = [], 0, 0
    source = str(value or "")
    for tag in _TAG.finditer(source):
        parts.append(source[last:tag.start()])
        last = tag.end()
        closing, name = tag[1] == "/", tag[2].lower()
        if name in ("ul", "ol"):
            depth = max(0, depth + (-1 if closing else 1))
            parts.append("\n")
        elif name == "li" and not closing:
            parts.append("\n" + "  " * max(0, depth - 1) + "- ")
        elif name in ("br", "p", "div", "li"):
            parts.append("\n")
    parts.append(source[last:])
    text = html.unescape("".join(parts)).replace("\xa0", " ")
    lines = (re.sub(r"(?<=\S)[ \t]+", " ", line).rstrip() for line in text.splitlines())
    return "\n".join(line for line in lines if line.strip())


_DECISION = re.compile(r"(não )?foi reconhecido o direito", re.I)
_NB = re.compile(r"\b\d{3}\.\d{3}\.\d{3}-\d\b")
_REASON = re.compile(r"motivo\(s\):\s*(.+?)\s*(?:Comunicamos|Caso discorde|$)", re.I | re.S)


def _decision(comments):
    """A comunicação de decisão mais recente: resultado, NB e motivo."""
    for comment in reversed(comments):
        found = _DECISION.search(comment["texto"])
        if not found:
            continue
        nb = _NB.search(comment["texto"])
        reason = _REASON.search(comment["texto"])
        return {"resultado": "indeferido" if found[1] else "deferido", "data": comment["data"],
                "nb": nb[0] if nb else None, "motivo": reason[1].strip() if reason else None}
    return None


def _age(birth, today=None):
    try:
        year, month, day = (int(part) for part in str(birth)[:10].split("-"))
    except ValueError:
        return None
    today = today or __import__("datetime").date.today()
    return today.year - year - ((today.month, today.day) < (month, day))


def _unique(items, key):
    seen, out = set(), []
    for item in items or []:
        if item.get(key) not in seen:
            seen.add(item.get(key))
            out.append(item)
    return out


def _requirement(task):
    """O que o INSS está pedindo numa exigência aberta (None quando não há)."""
    kind = task.get("tipoExigencia")
    docs_required = [
        {"nome": item.get("nome"), "obrigatorio": bool(item.get("obrigatorio")),
         "extensoes": item.get("extensoes") or []}
        for item in task.get("definicoesAnexoExigencia") or [] if item.get("ativo", True)
    ]
    fields = [item.get("nome") for item in task.get("camposAdicionaisExigencia") or [] if item.get("nome")]
    if not (kind or docs_required or fields):
        return None
    return {"tipo": kind, "documentosExigidos": docs_required, "camposExigidos": fields}


def compact_task(task):
    """Só o que importa para triagem e peças, sem duplicatas nem HTML (~3x menor).

    Traz o que a rotina GERID→Juridiq usa: nome, CPF, nascimento (menor?),
    protocolo, NB, serviço, status, decisão com motivo, agendamentos e prazos.
    """
    comments = [
        {"data": item.get("dataCriacao"), "servidor": bool(item.get("incluidoPorServidor")),
         "texto": html_to_text(item.get("conteudo")),
         "anexos": [anexo.get("id") for anexo in item.get("anexos") or []]}
        for item in task.get("comentarios") or [] if item.get("visivel", True)
    ]
    people = []
    for person in _unique(task.get("interessados"), "cpf"):
        age = _age(person.get("dataNascimento"))
        people.append({"nome": person.get("nome"), "cpf": str(person.get("cpf") or "").zfill(11),
                       "dataNascimento": person.get("dataNascimento"), "idade": age,
                       "menor": age is not None and age < 18, "nomeMae": person.get("nomeMae")})
    schedules = [
        {"tipo": kind, "data": item.get("descricaoDataHoraAgendamento"), "situacao": item.get("situacaoAgendamento"),
         "unidade": item.get("nomeUnidade"), "protocolo": item.get("protocolo")}
        for kind, field in (("perícia", "agendamentosPericia"), ("avaliação social", "agendamentosAvaliacaoSocial"))
        for item in task.get(field) or []
    ]
    return {
        "protocolo": task.get("protocolo"),
        "status": task.get("status"),
        "servico": task.get("nomeServico"),
        "especie": task.get("especieBeneficio"),
        "dataEntrada": task.get("dataEntradaRequerimento"),
        "unidade": task.get("nomeUnidade"),
        "unidadeCriacao": task.get("nomeUnidadeCriacao"),
        "canal": task.get("tipoCanalAtendimentoPublico"),
        "interessados": people,
        "procuradores": [item.get("nomeOuRazaoSocial") for item in task.get("procuradores") or []],
        "decisao": _decision(comments),
        "etapas": {"avaliacaoSocial": task.get("descricaoEtapaAvaliacao"), "pericia": task.get("descricaoEtapaPericia")},
        "agendamentos": schedules,
        "podeCumprirExigencia": task.get("podeCumprirExigencia"),
        "exigencia": _requirement(task),
        "comentarios": comments,
        "anexos": [
            {"id": item.get("id"), "nome": item.get("nomeArquivo"), "descricao": item.get("descricaoArquivo"),
             "categoria": item.get("categoria")}
            for item in _unique(task.get("anexos"), "id")
        ],
    }


def attachment_filename(disposition, fallback):
    """Nome seguro a partir do Content-Disposition, sem atravessar diretórios."""
    encoded = re.search(r"filename\*=UTF-8''([^;]+)", disposition or "", re.I)
    plain = re.search(r'filename="?([^";]+)"?', disposition or "", re.I)
    raw = disposition if disposition and ";" not in disposition else None
    try:
        name = unquote((encoded and encoded[1]) or (plain and plain[1]) or raw or fallback, errors="strict")
    except (UnicodeDecodeError, ValueError):
        name = fallback
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", os.path.basename(name)).strip()
    return name if name and name not in (".", "..") else fallback


def save_download(data, filename, fallback, directory=None):
    """Decodifica o Base64, salva em `.local/downloads/` e devolve os metadados."""
    content = docs.decode_download(data)
    meta = docs.save_bytes(content, attachment_filename(filename, fallback), fallback,
                           directory or DOWNLOAD_DIR)
    return {**meta, "is_pdf": content.startswith(b"%PDF-")}


def do_get_attachment(protocolo, anexo_id, filename=None, portal=None, directory=None, max_chars=40_000):
    """Baixa um anexo, salva localmente e devolve metadados + 1ª janela do texto."""
    do_ensure()
    payload = (portal or _portal()).attachment(protocolo, anexo_id)
    if payload is None:
        raise LookupError(f"anexo {anexo_id} não encontrado no protocolo {protocolo}")
    content = docs.decode_download(payload["base64"])
    fallback = f"{protocolo}-{anexo_id}.bin"
    # Nomes do portal se repetem entre processos ("Despacho de Análise.pdf"):
    # prefixar com protocolo e id identifica o anexo, e como o conteúdo de um id
    # não muda, baixar de novo substitui em vez de criar cópias -1, -2...
    original = attachment_filename(payload["filename"], "anexo.bin")
    name = filename or f"{protocolo}-{anexo_id}-{original}"
    meta = docs.save_bytes(content, name, fallback, directory or DOWNLOAD_DIR, overwrite=not filename)
    return {"protocolo": protocolo, "anexoId": anexo_id, **meta,
            **docs.slice_text(docs.cached_analysis(meta["path"], content), 0, max_chars)}


PROCESS_REUSE_SECONDS = 3600


def do_get_process(protocolo, filename=None, portal=None, directory=None, max_chars=40_000, refresh=False):
    """Baixa o relatório consolidado em PDF, salva e devolve metadados + 1ª janela.

    Sem `filename`, usa o nome canônico `<protocolo>-processo.pdf`: reaproveita a
    cópia de até 1 h (sem rede) e, ao baixar de novo, substitui a antiga.
    """
    folder = Path(directory or DOWNLOAD_DIR)
    canonical = folder / f"{protocolo}-processo.pdf"
    if not filename and not refresh and canonical.is_file():
        age = time.time() - canonical.stat().st_mtime
        if age < PROCESS_REUSE_SECONDS:
            content = canonical.read_bytes()
            return {"protocolo": int(protocolo), "reutilizado": True, "baixadoHaMinutos": int(age // 60),
                    "path": str(canonical), "filename": canonical.name, "bytes": len(content),
                    **docs.slice_text(docs.cached_analysis(canonical, content), 0, max_chars)}
    do_ensure()
    payload = (portal or _portal()).process(protocolo)
    if payload is None or not payload.get("relatorio"):
        raise LookupError(f"relatório do processo {protocolo} não disponível (protocolo inexistente ou sem acesso)")
    content = docs.decode_download(payload["relatorio"])
    meta = docs.save_bytes(content, filename or canonical.name, canonical.name, folder, overwrite=not filename)
    return {"protocolo": payload.get("protocolo", int(protocolo)),
            "permitidoEmissaoSemConfirmacao": payload.get("permitidoEmissaoSemConfirmacao"),
            "reutilizado": False, **meta, **docs.slice_text(docs.cached_analysis(meta["path"], content), 0, max_chars)}


def do_read_document(filename, offset=0, max_chars=40_000, directory=None):
    """Continua a leitura de um arquivo já baixado (janela seguinte do texto)."""
    return docs.read_saved_document(filename, offset, max_chars, directory or DOWNLOAD_DIR)


def document_result(file):
    """Metadados em JSON + janela do texto extraído para o agente analisar."""
    file = dict(file)
    markdown = file.pop("markdown", None)
    content = [TextContent(type="text", text=json.dumps(file, ensure_ascii=False, indent=2))]
    if markdown:
        content.append(TextContent(type="text", text=f"Texto extraído do documento:\n\n{markdown}"))
    # Clientes que preferem o structured_content (ex.: Claude Code) descartam o
    # content: o texto precisa ir nos dois para chegar ao agente.
    structured = {**file, "textReturned": bool(markdown)}
    if markdown:
        structured["text"] = markdown
    return CallToolResult(content=content, structured_content=structured)


def do_list_downloads(directory=None):
    """Arquivos já baixados pelo `gerid_get_attachment`/`gerid_get_process`."""
    folder = Path(directory or DOWNLOAD_DIR)
    if not folder.is_dir():
        return {"files": []}
    files = [
        {"filename": path.name, "bytes": path.stat().st_size, "path": str(path)}
        for path in folder.iterdir()
        if path.is_file() and not path.name.endswith(docs.SIDECAR_SUFFIX) and not path.name.startswith(".")
    ]
    return {"files": sorted(files, key=lambda item: item["filename"])}


async def _call(operation, label):
    # Sem redirect_stdout aqui (troca global, insegura entre threads): o stdio_server
    # do mcp>=2.3 desvia o fd 1 para o stderr enquanto serve, e o main() tira o
    # buffer do sys.stdout para nada sobrar para o pipe no encerramento.
    try:
        # Playwright sync (mint do captcha) não roda dentro do loop: vai para uma thread.
        value = await operation if hasattr(operation, "__await__") else await asyncio.to_thread(operation)
    except (ApiError, ValueError, RuntimeError, LookupError, FileNotFoundError, OSError) as error:
        raise ToolError(f"{label}: {sanitize(error) or 'falhou'}") from error
    except Exception as error:  # nunca vazar traceback: agente recebe mensagem útil
        raise ToolError(f"{label}: falha inesperada ({type(error).__name__}): {sanitize(error) or 'sem detalhes'}") from error
    return value if isinstance(value, dict) else {"result": value}


@server.tool(
    name="gerid_diagnose",
    title="Diagnose GERID prerequisites",
    description="Pré-verificação: token A3 plugado? PIN/TOTP no cofre? Devolve o que falta fazer, sem segredos. Read-only.",
    annotations=READ_ONLY,
)
async def diagnose_tool() -> dict[str, Any]:
    return await _call(lambda: do_diagnose(), "gerid_diagnose")


@server.tool(
    name="gerid_ensure_session",
    title="Ensure GERID session",
    description=(
        "Garante sessão GERID válida e diz por quantos minutos vale. Se expirou, renova sozinho: "
        "troca de token, TOTP ou, em último caso, login com o token A3 (PIN do cofre; exige a porta 8443 "
        "acessível). Grava a sessão em .local/. Não altera nada no INSS. As outras ferramentas já chamam isto."
    ),
    annotations=SESSION,
)
async def ensure_session_tool() -> dict[str, Any]:
    return await _call(lambda: do_ensure(), "gerid_ensure_session")


@server.tool(
    name="gerid_list_notifications",
    title="List GERID notifications",
    description=(
        "Notificações da conta PAT (mudanças de status dos protocolos), 10 por página, mais recentes primeiro. "
        "Devolve notificacoes[], total e naoVisualizadas. Pagine com first=0, 10, 20... "
        "Gera um token reCAPTCHA por chamada (~5 s). Read-only."
    ),
    annotations=READ_ONLY,
)
async def list_notifications_tool(first: Annotated[int, Field(ge=0)] = 0) -> dict[str, Any]:
    return await _call(lambda: do_notifications(first), "gerid_list_notifications")


@server.tool(
    name="gerid_search_tasks",
    title="Search GERID tasks",
    description=(
        "Busca paginada de tarefas PAT (filtros do portal). Datas em AAAA-MM-DD; sem datas, usa os últimos "
        "180 dias de atualização. situacaoTarefa é código numérico: 1=Cancelada, 2=Concluída, 3=Exigência. "
        "Evite o filtro status (valores desconhecidos; o portal pode exigir captcha de imagem, HTTP 428). "
        "Devolve tarefas[] e quantidadeTotalTarefa. Gera um token reCAPTCHA por chamada (~5 s). Read-only."
    ),
    annotations=READ_ONLY,
)
async def search_tasks_tool(
    page: Annotated[int, Field(ge=1)] = 1,
    pageSize: Annotated[int, Field(ge=1, le=100)] = 20,
    cpf: Annotated[str | None, Field(pattern=r"^\d{11}$", description="CPF do requerente, 11 dígitos")] = None,
    nome: str | None = None,
    protocolo: Annotated[str | None, Field(pattern=r"^\d+$")] = None,
    status: str | None = None,
    dataAtualizacaoInicial: Annotated[str | None, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")] = None,
    dataAtualizacaoFinal: Annotated[str | None, Field(pattern=r"^\d{4}-\d{2}-\d{2}$")] = None,
    situacaoTarefa: Annotated[str | None, Field(description="1=Cancelada, 2=Concluída, 3=Exigência")] = None,
) -> dict[str, Any]:
    return await _call(
        lambda: do_search_tasks(
            page=page, page_size=pageSize, cpf=cpf, nome=nome, protocolo=protocolo, status=status,
            dataAtualizacaoInicial=dataAtualizacaoInicial, dataAtualizacaoFinal=dataAtualizacaoFinal,
            situacaoTarefa=situacaoTarefa,
        ),
        "gerid_search_tasks",
    )


@server.tool(
    name="gerid_get_task",
    title="Get GERID task",
    description=(
        "Detalhes de uma tarefa pelo protocolo. Padrão: visão compacta (interessados com idade/menor, decisão "
        "com resultado/NB/motivo, etapas, agendamentos, comentários em texto, anexos únicos com id para "
        "gerid_get_attachment). full=true devolve o JSON bruto do portal (bem maior). Read-only."
    ),
    annotations=READ_ONLY,
)
async def get_task_tool(protocolo: Digits, full: bool = False) -> dict[str, Any]:
    return await _call(lambda: do_get_task(protocolo, full=full), "gerid_get_task")


@server.tool(
    name="gerid_get_process",
    title="Get consolidated GERID process",
    description=(
        "Baixa o relatório consolidado do processo (PDF com tarefa, anexos, despachos, CNIS e decisão) e devolve "
        "a 1ª janela do texto; continue com gerid_read_document(filename, nextOffset). Reaproveita a cópia de "
        "até 1 h sem tocar no portal; refresh=true força baixar de novo."
    ),
    annotations=LOCAL_WRITE,
)
async def get_process_tool(
    protocolo: Digits, filename: str | None = None, maxChars: MaxChars = 40000, refresh: bool = False
) -> CallToolResult:
    file = await _call(lambda: do_get_process(protocolo, filename, max_chars=maxChars, refresh=refresh),
                       "gerid_get_process")
    return document_result(file) if isinstance(file, dict) and "path" in file else file


@server.tool(
    name="gerid_get_attachment",
    title="Get GERID attachment",
    description="Baixa um anexo da tarefa e devolve a 1ª janela do texto extraído para análise; continue com gerid_read_document.",
    annotations=LOCAL_WRITE,
)
async def get_attachment_tool(
    protocolo: Digits, anexoId: Digits, filename: str | None = None, maxChars: MaxChars = 40000
) -> CallToolResult:
    file = await _call(
        lambda: do_get_attachment(protocolo, anexoId, filename, max_chars=maxChars), "gerid_get_attachment"
    )
    return document_result(file) if isinstance(file, dict) and "path" in file else file


@server.tool(
    name="gerid_read_document",
    title="Read a saved GERID document",
    description="Continua a leitura de um arquivo baixado (passe filename e nextOffset). Sem login novo. Read-only.",
    annotations=READ_ONLY,
)
async def read_document_tool(
    filename: Annotated[str, Field(min_length=1, max_length=255)],
    offset: Annotated[int, Field(ge=0)] = 0,
    maxChars: MaxChars = 40000,
) -> CallToolResult:
    return document_result(await _call(lambda: do_read_document(filename, offset, maxChars), "gerid_read_document"))


@server.tool(
    name="gerid_list_downloads",
    title="List downloaded GERID documents",
    description="Arquivos já baixados por gerid_get_process/gerid_get_attachment. Read-only.",
    annotations=READ_ONLY,
)
async def list_downloads_tool() -> dict[str, Any]:
    return await _call(lambda: do_list_downloads(), "gerid_list_downloads")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Servidor MCP do GERID (stdio, ou HTTP com --http).")
    parser.add_argument("--http", action="store_true", help="serve streamable HTTP em /mcp em vez de stdio")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    if not args.http:
        # Os prints da cascata (poc.py) vão para o fd 1, que o stdio_server desvia
        # para o stderr enquanto serve. Sem buffer, cada print sai na hora; com
        # buffer, o texto retido era despejado no pipe JSON-RPC quando o fd 1
        # volta ao protocolo no encerramento (o cliente recebia JSON inválido).
        sys.stdout.reconfigure(line_buffering=True, write_through=True)
        server.run("stdio")
        return
    server.run("streamable-http", host=args.host, port=args.port)


if __name__ == "__main__":
    main()
