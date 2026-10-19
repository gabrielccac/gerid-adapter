"""HTTP/1.1 mínimo sobre tlslite-ng para o GERID, com ou sem certificado de cliente.

O GERID só negocia TLS 1.2 com troca de chave RSA, que o módulo ssl do Python recusa
por padrão; por isso o tlslite também é usado nas conexões sem certificado.
"""

import http.client
import json
import socket
import warnings

import certifi
from dataclasses import dataclass, field
from datetime import datetime
from functools import lru_cache
from urllib.parse import urlencode, urljoin, urlsplit

import certifi
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.verification import PolicyBuilder, Store
from tlslite import HandshakeSettings, TLSConnection, X509, X509CertChain

USER_AGENT = "gerid-adapter"
MAX_BODY = 50_000_000  # relatórios consolidados passam de 2 MB em Base64


@dataclass
class Response:
    url: str
    status: int
    headers: list = field(default_factory=list)  # [(nome, valor)]
    body: bytes = b""

    def header(self, name):
        return next((v for k, v in self.headers if k.lower() == name.lower()), None)

    def cookies(self):
        result = {}
        for name, value in self.headers:
            if name.lower() == "set-cookie" and "=" in value:
                key, _, rest = value.partition("=")
                result[key.strip()] = rest.split(";", 1)[0]
        return result

    @property
    def location(self):
        value = self.header("Location")
        return urljoin(self.url, value) if value else None

    @property
    def is_html(self):
        return b"<html" in self.body[:4000].lower()


def tls_settings():
    s = HandshakeSettings()
    s.minVersion = s.maxVersion = (3, 3)
    s.rsaSchemes = ["pkcs1"]  # assinatura que o token faz com CKM_RSA_PKCS
    s.rsaSigHashes = ["sha256", "sha384", "sha512"]
    return s


def tlslite_cert(cert):
    parsed = X509()
    parsed.parseBinary(cert.public_bytes(Encoding.DER))  # parseBinary não devolve o objeto
    return parsed


def to_tlslite_chain(certs):
    return X509CertChain([tlslite_cert(cert) for cert in certs])


@lru_cache(maxsize=1)
def _roots():
    with warnings.catch_warnings():  # o bundle do certifi tem raízes antigas com serial negativo
        warnings.simplefilter("ignore")
        return Store(x509.load_pem_x509_certificates(open(certifi.where(), "rb").read()))


def verify_server(connection, host):
    """Valida cadeia e nome do servidor antes de enviar qualquer dado."""
    chain = [x509.load_der_x509_certificate(bytes(c.bytes)) for c in connection.session.serverCertChain.x509List]
    PolicyBuilder().store(_roots()).time(datetime.now()).build_server_verifier(x509.DNSName(host)).verify(
        chain[0], chain[1:]
    )
    return chain[0]


def parse_response(url, data):
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    status = int(lines[0].split()[1])
    headers = []
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers.append((name.strip(), value.strip()))
    if any(k.lower() == "transfer-encoding" and "chunked" in v.lower() for k, v in headers):
        body = dechunk(body)
    return Response(url, status, headers, body)


def dechunk(body):
    out, rest = b"", body
    while rest:
        size_line, _, rest = rest.partition(b"\r\n")
        size = int(size_line.split(b";")[0] or b"0", 16)
        if size == 0:
            break
        out, rest = out + rest[:size], rest[size + 2 :]
    return out


class TlsHttp:
    """Uma conexão por requisição (Connection: close), como o CAS espera de um navegador simples."""

    def __init__(self, client_chain=None, client_key=None, user_agent=USER_AGENT):
        self.client_chain = client_chain
        self.client_key = client_key
        self.user_agent = user_agent

    def request(self, method, url, form=None, cookies=None, referer=None, headers=None, json_body=None):
        parts = urlsplit(url)
        port = parts.port or 443
        host_header = parts.hostname if port == 443 else f"{parts.hostname}:{port}"
        target = parts.path or "/"
        if parts.query:
            target += "?" + parts.query
        body = b""
        lines = [f"{method} {target} HTTP/1.1", f"Host: {host_header}", f"User-Agent: {self.user_agent}",
                 "Accept: text/html,application/json,*/*", "Connection: close"]
        if json_body is not None:
            body = json.dumps(json_body).encode()
            lines += ["Content-Type: application/json", f"Content-Length: {len(body)}",
                      f"Origin: https://{host_header}"]
        elif form is not None:
            body = urlencode(form).encode()
            lines += ["Content-Type: application/x-www-form-urlencoded", f"Content-Length: {len(body)}",
                      f"Origin: https://{host_header}"]
        if referer:
            lines.append(f"Referer: {referer}")
        if cookies:
            lines.append("Cookie: " + "; ".join(f"{k}={v}" for k, v in cookies.items()))
        for name, value in (headers or {}).items():
            lines.append(f"{name}: {value}")

        sock = socket.create_connection((parts.hostname, port), timeout=30)
        connection = TLSConnection(sock)
        try:
            use_cert = self.client_chain is not None and port == 8443
            connection.handshakeClientCert(
                self.client_chain if use_cert else None,
                self.client_key if use_cert else None,
                settings=tls_settings(),
                serverName=parts.hostname,
            )
            verify_server(connection, parts.hostname)
            connection.write(("\r\n".join(lines) + "\r\n\r\n").encode() + body)
            data = b""
            while len(data) < MAX_BODY:
                try:
                    chunk = connection.read()
                except Exception:
                    break
                if not chunk:
                    break
                data += bytes(chunk)
        finally:
            connection.close()
        return parse_response(url, data)

    def get(self, url, cookies=None, referer=None, headers=None):
        return self.request("GET", url, cookies=cookies, referer=referer, headers=headers)

    def post(self, url, form, cookies=None, referer=None, headers=None):
        return self.request("POST", url, form=form, cookies=cookies, referer=referer, headers=headers)

    def post_json(self, url, payload, cookies=None, referer=None, headers=None):
        return self.request("POST", url, cookies=cookies, referer=referer, headers=headers, json_body=payload)


def impersonated_post_json(url, payload, headers=None, timeout=30):
    """POST JSON com TLS impersonando o Chrome.

    O transporte tlslite tem fingerprint TLS próprio e o TLS padrão do Python
    tem a conexão derrubada: alguns endpoints protegidos por WAF só aceitam
    stacks comuns, então aqui o TLS imita o Chrome (via curl_cffi).
    """
    from curl_cffi import requests as curl_requests

    head = {"Content-Type": "application/json", "Accept": "application/json"}
    for name, value in (headers or {}).items():
        head[name] = value
    session = curl_requests.Session(impersonate="chrome", verify=certifi.where())
    try:
        result = session.post(url, json=payload, headers=head, timeout=timeout)
    except Exception as error:
        raise RuntimeError(f"Falha de rede ao chamar o portal ({type(error).__name__})") from None
    return Response(url, result.status_code, list(result.headers.items()), result.content)
