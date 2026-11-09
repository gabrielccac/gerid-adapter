"""Experimento #4: emissão Enterprise por HTTP, sem credenciais do portal."""

import base64
import re
import secrets
from html.parser import HTMLParser

import certifi
from curl_cffi import requests

from gerid_adapter._vendor.bypassv3 import encode_reload_body, parse_reload_response
from gerid_adapter.recaptcha import PORTAL, PORTAL_ACTION, site_key

PROVIDER = "https://www.recaptcha.net"
ENTERPRISE = PROVIDER + "/recaptcha/enterprise"


class AnchorPage(HTMLParser):
    token = None

    def handle_starttag(self, tag, attrs):
        fields = dict(attrs)
        if tag == "input" and fields.get("id") == "recaptcha-token":
            self.token = fields.get("value")


def _request(session, stage, method, url, timeout, **kwargs):
    try:
        response = session.request(method, url, timeout=timeout, allow_redirects=False, **kwargs)
    except Exception as error:
        raise RuntimeError(f"reCAPTCHA HTTP {stage}: {type(error).__name__}") from None
    if response.status_code != 200:
        raise RuntimeError(f"reCAPTCHA HTTP {stage}: HTTP {response.status_code}")
    return response


def mint_http(action=PORTAL_ACTION, timeout_ms=20000):
    """Retorna o token emitido pelo Google. O aceite é verificado pelo portal."""
    key = site_key()
    timeout = timeout_ms / 1000
    origin = base64.urlsafe_b64encode(f"{PORTAL}:443".encode()).decode().replace("=", ".")
    with requests.Session(impersonate="chrome", verify=certifi.where()) as session:
        script = _request(session, "enterprise.js", "GET", ENTERPRISE + ".js", timeout,
                          params={"render": key})
        version = re.search(r"recaptcha/releases/([A-Za-z0-9_-]+)", script.text)
        if not version:
            raise RuntimeError("reCAPTCHA HTTP enterprise.js: versão não encontrada")
        anchor = _request(session, "anchor", "GET", ENTERPRISE + "/anchor", timeout,
                          params={"ar": "1", "k": key, "co": origin, "hl": "pt-BR",
                                  "v": version[1], "size": "invisible", "cb": secrets.token_hex(6)},
                          headers={"Referer": PORTAL + "/"})
        page = AnchorPage()
        page.feed(anchor.text)
        if not page.token:
            raise RuntimeError("reCAPTCHA HTTP anchor: resposta sem token de inicialização")
        body = encode_reload_body(v=version[1], c=page.token, k=key, action=action, fingerprint=None)
        response = _request(session, "reload", "POST", ENTERPRISE + "/reload", timeout,
                            params={"k": key}, data=body,
                            headers={"Content-Type": "application/x-protobuffer", "Accept": "*/*",
                                     "Origin": PROVIDER, "Referer": anchor.url})
    token = parse_reload_response(response.text)
    if not token:
        raise RuntimeError("reCAPTCHA HTTP reload: resposta sem token")
    return token
