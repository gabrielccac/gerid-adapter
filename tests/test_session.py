"""Troca do access_token + papel, com transporte falso (sem rede)."""

import base64
import json
import os
from datetime import datetime
from zoneinfo import ZoneInfo

import pytest

from gerid_adapter.api import ApiError
from gerid_adapter.http import Response
from gerid_adapter.session import (
    build_state,
    exchange,
    js_now,
    read_fragment,
    read_state,
    save_session,
    select_role,
)


def token_with(**claims):
    def segment(payload):
        return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    return f"{segment({'alg': 'RS256'})}.{segment(claims)}."


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def get(self, url, cookies=None, referer=None, headers=None):
        self.requests.append(url)
        return self.responses.pop(0)


def response(status, body=b""):
    return Response("", status, [], body)


GERID = token_with(**{"rawRoles": [{"id": "r1", "name": "PAPEL_X"}], "cpf": "02806598222"})
IFS = token_with(**{"cpf": "02806598222", "geridRoles": ["PAPEL_X#CNPJ"]})


def test_exchange_returns_jwt_and_calls_oauth():
    transport = FakeTransport([response(200, f'"{GERID}"'.encode())])
    assert exchange(transport, "AT-1") == GERID
    assert transport.requests[0].startswith(
        "https://atendimento.inss.gov.br/apis/gestaoApi/gerid/oauth?accessToken=AT-1"
    )


def test_exchange_rejects_non_jwt():
    transport = FakeTransport([response(200, b'"nao-e-jwt"')])
    with pytest.raises(ValueError):
        exchange(transport, "AT-1")


def test_exchange_raises_on_error_status():
    transport = FakeTransport([response(500, b"boom")])
    with pytest.raises(ApiError, match="500"):
        exchange(transport, "AT-1")


def test_select_role_picks_first_and_returns_pair():
    transport = FakeTransport([response(200, f'"{IFS}"'.encode())])
    role, token = select_role(transport, "AT-1", GERID)
    assert role["id"] == "r1" and token == IFS
    assert "idPapelSelecionado=r1" in transport.requests[0]


def test_select_role_requires_raw_roles():
    transport = FakeTransport([])
    with pytest.raises(ApiError):
        select_role(transport, "AT-1", token_with(cpf="1"))


def test_build_state_has_portal_keys():
    state = build_state("AT-1", "600", GERID, IFS)
    assert state["ifs_at"] == "AT-1" == state["access_token"]
    assert state["gerid_token"] == GERID and state["ifs_auth"] == IFS
    assert state["base_url"] == "https://atendimento.inss.gov.br/apis/"
    assert state["ifs_ei"] == "600" and state["ifs_ts"] == state["ifs_iat"]


def test_js_now_matches_portal_format():
    at = datetime(2026, 10, 16, 4, 1, 0, tzinfo=ZoneInfo("America/Sao_Paulo"))
    assert js_now(at) == "Fri Oct 16 2026 04:01:00 GMT-0300 (Horário Padrão de Brasília)"


def test_save_session_writes_files_with_restricted_mode(tmp_path):
    saved = save_session(tmp_path, "AT-1", "600", GERID, IFS)
    assert set(saved) == {"gerid_token.jwt", "ifs_auth.jwt", "portal-session.json"}
    for name in saved:
        assert os.name == "nt" or (tmp_path / name).stat().st_mode & 0o777 == 0o600  # Windows não tem modo Unix
    state = json.loads((tmp_path / "portal-session.json").read_text())
    assert state["ifs_auth"] == IFS


def test_read_fragment(tmp_path):
    fragment = tmp_path / "oauth-fragment.txt"
    fragment.write_text("access_token=AT-1&token_type=bearer&expires_in=600")
    assert read_fragment(fragment)["access_token"] == "AT-1"


def test_read_state_accepts_legacy_cp1252(tmp_path):
    legacy = tmp_path / "legacy.json"
    legacy.write_bytes(json.dumps({"tz": "Horário Padrão de Brasília"}, ensure_ascii=False).encode("cp1252"))
    current = tmp_path / "current.json"
    current.write_text(json.dumps({"tz": "Horário Padrão de Brasília"}, ensure_ascii=False), encoding="utf-8")
    assert read_state(legacy) == read_state(current) == {"tz": "Horário Padrão de Brasília"}
