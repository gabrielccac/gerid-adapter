"""Sessão do portal INSS sem browser: troca do access_token + seleção de papel.

Cadeia completa (tudo por HTTP, sem PIN e sem tocar no token A3):

1. ``exchange``: ``GET /apis/gestaoApi/gerid/oauth?accessToken=AT-...`` devolve
   o ``gerid_token`` (JWT com ``rawRoles``).
2. ``select_role``: repete a chamada com ``idPapelSelecionado`` e devolve o
   ``ifs_auth`` (JWT final, com ``geridRoles``).
3. ``build_state``: monta o dicionário que a SPA do portal guarda no
   ``localStorage``. Injetado num browser fresco, o ``/tarefas`` abre
   autenticado e o reCAPTCHA da página passa a ser aceito.
"""

import json
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from gerid_adapter.api import PORTAL, ApiError, jwt_claims
from gerid_adapter.http import TlsHttp

OAUTH_PATH = "/apis/gestaoApi/gerid/oauth"
BASE_URL = PORTAL + "/apis/"
USER_AGENT = "gerid-adapter-poc"
DEFAULT_DIR = Path(__file__).resolve().parents[2] / ".local"
SAO_PAULO = ZoneInfo("America/Sao_Paulo")
WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _jwt_body(text):
    """O portal devolve o JWT como string JSON entre aspas."""
    token = text.strip().strip('"')
    jwt_claims(token)  # valida que é um JWT legível
    return token


def exchange(transport, access_token):
    """Troca o ``access_token`` (AT-...) pelo ``gerid_token`` (JWT)."""
    url = PORTAL + OAUTH_PATH + "?" + urlencode({"accessToken": access_token})
    response = transport.get(url, headers={"Referer": PORTAL + "/"})
    if response.status != 200:
        body = response.body[:200].decode("utf-8", "replace")
        raise ApiError(f"Troca do access_token falhou ({response.status}): {body}")
    return _jwt_body(response.body.decode("ascii", "replace"))


def select_role(transport, access_token, gerid_token):
    """Escolhe o primeiro papel de ``rawRoles`` e devolve o ``ifs_auth`` (JWT)."""
    roles = jwt_claims(gerid_token).get("rawRoles") or []
    if not roles:
        raise ApiError("O gerid_token não contém papéis (rawRoles vazio).")
    role = roles[0]
    url = PORTAL + OAUTH_PATH + "?" + urlencode(
        {"accessToken": access_token, "idPapelSelecionado": role["id"]}
    )
    response = transport.get(url, headers={"Referer": PORTAL + "/"})
    if response.status != 200:
        body = response.body[:200].decode("utf-8", "replace")
        raise ApiError(f"Seleção do papel falhou ({response.status}): {body}")
    return role, _jwt_body(response.body.decode("ascii", "replace"))


def js_now(at=None):
    """Agora no formato de ``Date().toString()`` que a SPA grava (ifs_ts/ifs_iat)."""
    moment = datetime.now(SAO_PAULO) if at is None else at
    return (
        f"{WEEKDAYS[moment.weekday()]} {MONTHS[moment.month - 1]} "
        f"{moment.day:02d} {moment.year} {moment:%H:%M:%S} GMT-0300 "
        "(Horário Padrão de Brasília)"
    )


def build_state(access_token, expires_in, gerid_token, ifs_auth, at=None):
    """As chaves que a SPA guarda no ``localStorage`` (suficiente p/ transferir)."""
    stamp = js_now(at)
    return {
        "access_token": access_token,
        "ifs_at": access_token,
        "ifs_ei": str(expires_in),
        "gerid_token": gerid_token,
        "ifs_auth": ifs_auth,
        "base_url": BASE_URL,
        "ifs_ts": stamp,
        "ifs_iat": stamp,
    }


def read_state(path):
    """Lê o portal-session.json. Arquivos gravados antes do utf-8 explícito (Windows) vêm em
    cp1252 ("Horário Padrão de Brasília" nas datas): utf-8 falha e cai para latin-1."""
    raw = Path(path).read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("latin-1")
    return json.loads(text)


def read_fragment(path):
    text = Path(path).read_text(encoding="utf-8").strip()
    return dict(item.split("=", 1) for item in text.split("&") if "=" in item)


def save_session(directory, access_token, expires_in, gerid_token, ifs_auth):
    """Grava os JWTs e o estado do localStorage (tudo 0600, dir 0700)."""
    directory = Path(directory)
    directory.mkdir(mode=0o700, exist_ok=True)
    files = {
        "gerid_token.jwt": gerid_token,
        "ifs_auth.jwt": ifs_auth,
        "portal-session.json": json.dumps(
            build_state(access_token, expires_in, gerid_token, ifs_auth),
            ensure_ascii=False, indent=2,
        ),
    }
    for name, content in files.items():
        target = directory / name
        target.write_text(content if content.endswith("\n") else content + "\n", encoding="utf-8")
        target.chmod(0o600)
    return {name: str(directory / name) for name in files}


def seconds_left(token):
    return int(jwt_claims(token).get("exp", 0) - time.time())


def make_transport():
    return TlsHttp(user_agent=USER_AGENT)
