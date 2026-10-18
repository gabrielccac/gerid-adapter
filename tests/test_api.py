"""Construção das chamadas da API do portal com um transporte falso (sem rede)."""

import base64
import json

import pytest

from gerid_adapter.api import ApiError, PortalApi, jwt_claims, seconds_left
from gerid_adapter.http import Response


def token_with(**claims):
    def segment(payload):
        return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

    return f"{segment({'alg': 'none'})}.{segment(claims)}."


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.requests = []

    def get(self, url, cookies=None, referer=None, headers=None):
        self.requests.append({"url": url, "headers": headers, "cookies": cookies, "referer": referer})
        return self.responses.pop(0)


def response(status, body=b"", headers=None):
    return Response("", status, headers or [], body)


def test_alive_true_on_204_and_business_error():
    assert PortalApi(token_with(cpf="1"), transport=FakeTransport([response(204)])).alive() is True
    assert PortalApi(token_with(cpf="1"), transport=FakeTransport([response(500, b"erro")])).alive() is True


def test_alive_false_on_401_and_network_error():
    assert PortalApi(token_with(cpf="1"), transport=FakeTransport([response(401, b"")])).alive() is False

    class BrokenTransport:
        def get(self, *args, **kwargs):
            raise ConnectionError("rede caiu")

    assert PortalApi(token_with(cpf="1"), transport=BrokenTransport()).alive() is False


def test_get_task_uses_bearer_and_expected_path():
    transport = FakeTransport([response(200, b'{"protocolo": 123}')])
    api = PortalApi(token_with(**{"cpf": "02806598222", "auth-user-agent": "gerid-adapter-poc"}), transport=transport)
    assert api.get_task("123") == {"protocolo": 123}
    sent = transport.requests[0]
    assert sent["url"] == "https://atendimento.inss.gov.br/apis/requerimentosPortalApi/requerimento/ec/tarefa/123"
    assert sent["headers"]["Authorization"].startswith("Bearer ")


def test_not_found_returns_none():
    api = PortalApi(token_with(cpf="1"), transport=FakeTransport([response(204)]))
    assert api.get_task("999") is None


def test_process_embeds_cpf_and_nome_from_token():
    transport = FakeTransport([response(200, b'{"protocolo": 7, "relatorio": "JVBERi0="}')])
    api = PortalApi(token_with(cpf="028.065.982-22", nome="Jean Ferreira"), transport=transport)
    result = api.process("7")
    url = transport.requests[0]["url"]
    assert "cpf=02806598222" in url and "sistema=PAT" in url and "nome=Jean+Ferreira" in url
    assert result["relatorio"] == "JVBERi0="


def test_non_2xx_raises_with_body():
    api = PortalApi(token_with(cpf="1"), transport=FakeTransport([response(500, b"boom")]))
    with pytest.raises(ApiError, match="500"):
        api.get_task("1")


def test_process_requires_cpf_and_nome():
    api = PortalApi(token_with(nome="X"), transport=FakeTransport([response(200, b"{}")]))
    with pytest.raises(ApiError):
        api.process("1")


def test_rejects_non_digits():
    api = PortalApi(token_with(cpf="1"), transport=FakeTransport([]))
    with pytest.raises(ValueError):
        api.get_task("12a")


def test_transport_reuses_token_user_agent():
    api = PortalApi(token_with(cpf="1", **{"auth-user-agent": "gerid-adapter-poc"}))
    assert api.transport.user_agent == "gerid-adapter-poc"


def test_seconds_left_and_claims():
    assert jwt_claims(token_with(exp=100))["exp"] == 100
    assert seconds_left(token_with(exp=0)) < 0
