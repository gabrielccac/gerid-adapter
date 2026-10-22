"""Chamadas à API interna do portal INSS com o token do GERID (somente leitura).

Reaproveita o transporte HTTP do `http.py`. O token é o `ifs_auth`/`gerid_token`
emitido depois do login por certificado; ele fica amarrado (claims `auth-ip` e
`auth-user-agent`) ao IP e ao User-Agent do momento do login, então reusamos o
próprio `auth-user-agent` do token para não ser recusado.

As rotas com captcha (`/notificacao` e `/tarefa/consulta`) recebem o
`tokenReCAPTCHA` como argumento: ele é de uso único e precisa ser mintado na
página autenticada (ver `recaptcha.py`) imediatamente antes da chamada.
"""

import base64
import json
import re
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

from gerid_adapter.http import TlsHttp, impersonated_post_json

PORTAL = "https://atendimento.inss.gov.br"
REFERER = PORTAL + "/"
SAO_PAULO = ZoneInfo("America/Sao_Paulo")
SAME_ORIGIN = {
    "Origin": PORTAL,
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
}
DEFAULT_TOKEN_PATH = Path(__file__).resolve().parents[2] / ".local" / "ifs_auth.jwt"
DEFAULT_STATE_PATH = Path(__file__).resolve().parents[2] / ".local" / "portal-session.json"
DIGITS = re.compile(r"^\d+$")


class ApiError(RuntimeError):
    """Resposta não-2xx (ou corpo inválido) da API do portal."""


def _error(message, status=None):
    error = ApiError(message)
    error.status = status
    return error


def jwt_claims(token):
    """Claims do JWT. Não verifica a assinatura: só lê os valores públicos."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Token do GERID não é um JWT.")
    segment = parts[1]
    return json.loads(base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4)))


def load_token(path=None):
    path = Path(path or DEFAULT_TOKEN_PATH)
    if not path.is_file():
        raise FileNotFoundError(f"Token do GERID não encontrado em {path}. Rode antes: uv run gerid-poc authorize")
    return path.read_text(encoding="utf-8").strip()


def seconds_left(token):
    """Segundos até o `exp` do token (negativo se já expirou)."""
    return int(jwt_claims(token).get("exp", 0) - __import__("time").time())


def _search_date(value, fallback):
    """Data no formato que a busca espera (`YYYY-MM-DDT03:00:00.000Z`)."""
    if not value:
        return fallback.strftime("%Y-%m-%dT03:00:00.000Z")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        return f"{value}T03:00:00.000Z"
    raise ValueError(f"Data de busca inválida: {value!r} (use AAAA-MM-DD).")


def _digits(value, name):
    if not isinstance(value, str) or not DIGITS.fullmatch(value):
        raise ValueError(f"{name} deve conter apenas dígitos.")
    return value


class PortalApi:
    def __init__(self, token, transport=None, poster=None):
        self.token = token
        self.claims = jwt_claims(token)
        # O token é amarrado ao User-Agent do login; reusar o mesmo evita recusa.
        user_agent = self.claims.get("auth-user-agent") or "gerid-adapter"
        self.transport = transport or TlsHttp(user_agent=user_agent)
        # As rotas com captcha barram outros fingerprints TLS (403/EOF):
        # usam TLS impersonando o Chrome.
        self.poster = poster or impersonated_post_json

    def _headers(self):
        return {"Authorization": f"Bearer {self.token}", "Referer": REFERER}

    def _get(self, path, query=None):
        url = PORTAL + path + (f"?{urlencode(query)}" if query else "")
        response = self.transport.get(url, headers=self._headers())
        if response.status == 204:
            return None
        if not 200 <= response.status < 300:
            body = response.body[:400].decode("utf-8", "replace")
            raise _error(f"GET {path} falhou ({response.status}): {body}", response.status)
        return response

    def alive(self):
        """Prova de vida: o token vale NO SERVIDOR (exp local pode mentir).

        Rota 3 com protocolo inexistente: 204 ou erro de negócio = viva;
        401 = morta; falha de rede = morta (a cascata de refresh dirá o porquê).
        """
        try:
            response = self.transport.get(
                PORTAL + "/apis/requerimentosPortalApi/requerimento/ec/tarefa/00000000000",
                headers=self._headers(),
            )
        except Exception:
            return False
        return response.status != 401

    def get_task(self, protocolo):
        """Detalhes de uma tarefa, ou None se não existir (o portal responde 204)."""
        _digits(protocolo, "protocolo")
        response = self._get(f"/apis/requerimentosPortalApi/requerimento/ec/tarefa/{protocolo}")
        return None if response is None else json.loads(response.body)

    def attachment(self, protocolo, anexo_id):
        """Anexo bruto em Base64 e o nome sugerido pelo Content-Disposition (ou None)."""
        _digits(protocolo, "protocolo")
        _digits(anexo_id, "anexoId")
        response = self._get(f"/apis/arquivosPortalApi/tarefa/{protocolo}/anexo/{anexo_id}")
        if response is None:
            return None
        return {
            "filename": response.header("content-disposition"),
            "base64": response.body.decode("ascii", "replace").strip(),
        }

    def _post_json(self, path, payload):
        response = self.poster(PORTAL + path, payload, {**self._headers(), **SAME_ORIGIN})
        if not 200 <= response.status < 300:
            body = response.body[:200].decode("utf-8", "replace")
            raise _error(f"POST {path} falhou ({response.status}): {body}", response.status)
        return json.loads(response.body or b"null")

    def notifications(self, recaptcha_token, first=0):
        """Notificações da conta PAT. O token captcha é de uso único (ver `recaptcha`)."""
        if not isinstance(first, int) or isinstance(first, bool) or first < 0:
            raise ValueError("first deve ser um inteiro a partir de 0.")
        return self._post_json(
            f"/apis/requerimentosPortalApi/requerimento/ec/notificacao?first={first}",
            {"tokenReCAPTCHA": recaptcha_token},
        )

    def search_tasks(self, recaptcha_token, page=1, page_size=20, **filters):
        """Busca paginada de tarefas. O token captcha é de uso único (ver `recaptcha`)."""
        if isinstance(page, bool) or not isinstance(page, int) or page < 1:
            raise ValueError("page deve ser um inteiro a partir de 1.")
        if isinstance(page_size, bool) or not isinstance(page_size, int) or not 1 <= page_size <= 100:
            raise ValueError("page_size deve estar entre 1 e 100.")
        now = datetime.now(SAO_PAULO)
        return self._post_json(
            "/apis/requerimentosPortalApi/requerimento/ec/tarefa/consulta"
            f"?first={(page - 1) * page_size}&pageSize={page_size}",
            {
                "cpf": filters.get("cpf") or "",
                "nome": filters.get("nome") or "",
                "protocolo": filters.get("protocolo") or "",
                "status": filters.get("status") or "",
                "tokenReCAPTCHA": recaptcha_token,
                "dataAtualizacaoInicial": _search_date(filters.get("dataAtualizacaoInicial"), now - timedelta(days=180)),
                "dataAtualizacaoFinal": _search_date(filters.get("dataAtualizacaoFinal"), now),
                "situacaoTarefa": filters.get("situacaoTarefa") or "",
            },
        )

    def process(self, protocolo):
        """Relatório consolidado do processo. CPF e nome saem do próprio token."""
        _digits(protocolo, "protocolo")
        raw_cpf = re.sub(r"\D", "", str(self.claims.get("cpf") or self.claims.get("user_name") or ""))
        cpf = raw_cpf.zfill(11)
        nome = str(self.claims.get("nome") or "").strip()
        if not raw_cpf or not re.fullmatch(r"\d{11}", cpf) or not nome:
            raise ApiError("O token do GERID não contém CPF e nome utilizáveis.")
        response = self._get(
            "/apis/consolidadorECApi/pap/metadados",
            {"protocolo": protocolo, "sistema": "PAT", "cpf": cpf, "nome": nome, "async": "false"},
        )
        if response is None:
            return None
        payload = json.loads(response.body)
        return {
            "protocolo": payload.get("protocolo", int(protocolo)),
            "permitidoEmissaoSemConfirmacao": payload.get("permitidoEmissaoSemConfirmacao"),
            "relatorio": payload.get("relatorio"),
        }
