"""Pacote criptografado de credenciais de um cliente: um arquivo que viaja por qualquer canal e abre com senha.

O operador gera com ``gerid-poc export --customer <nome>`` (lê ``customers/<nome>/.env``); a máquina do cliente
instala com ``gerid-poc import <arquivo>``, que grava PIN e TOTP no cofre do sistema. A senha é digitada numa
página local (127.0.0.1, uso único), nunca no chat. Formato igual ao do Jurisync: chave scrypt, AES-256-GCM,
cabeçalho autenticado como dado associado.
"""

import base64
import json
import os
import secrets
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs

FORMAT = "gerid-credentials"
VERSION = 1
HEADER = b"gerid-credentials-v1"
MIN_PASSPHRASE = 12
CUSTOMERS_DIR = Path(__file__).resolve().parents[2] / "customers"
TOTP_VAR = "GERID_TOTP_SECRET"
PIN_VAR = "GERID_A3_PIN"


def _b64(raw):
    return base64.b64encode(raw).decode("ascii")


def _derive(passphrase, salt):
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

    return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(passphrase.encode("utf-8"))


def generate_passphrase():
    return secrets.token_urlsafe(15)


def read_env(path):
    """Variáveis de um .env simples (``NOME=valor``, aspas opcionais); ignora comentários e linhas vazias."""
    values = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        name, value = line.removeprefix("export ").split("=", 1)
        values[name.strip()] = value.strip().strip("\"'")
    return values


def seal(env, passphrase, *, customer=""):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(passphrase) < MIN_PASSPHRASE:
        raise ValueError(f"A senha do pacote precisa ter ao menos {MIN_PASSPHRASE} caracteres")
    salt, nonce = os.urandom(16), os.urandom(12)
    payload = json.dumps({"customer": customer, "env": env}, ensure_ascii=False).encode("utf-8")
    box = AESGCM(_derive(passphrase, salt)).encrypt(nonce, payload, HEADER)
    bundle = {
        "format": FORMAT,
        "version": VERSION,
        "kdf": "scrypt-n15-r8-p1",
        "salt": _b64(salt),
        "nonce": _b64(nonce),
        "data": _b64(box),
    }
    return json.dumps(bundle, indent=2)


def unseal(text, passphrase):
    """Devolve ``{"customer", "env"}`` ou ValueError sem revelar o motivo da falha."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        bundle = json.loads(text)
        if bundle.get("format") != FORMAT or bundle.get("version") != VERSION:
            raise ValueError
        salt, nonce, data = (base64.b64decode(bundle[key]) for key in ("salt", "nonce", "data"))
    except (ValueError, KeyError, TypeError):
        raise ValueError("O arquivo não é um pacote de credenciais do gerid-adapter") from None
    try:
        payload = AESGCM(_derive(passphrase, salt)).decrypt(nonce, data, HEADER)
    except InvalidTag:
        raise ValueError("Senha do pacote incorreta ou arquivo alterado") from None
    result = json.loads(payload.decode("utf-8"))
    return {"customer": result.get("customer", ""), "env": dict(result.get("env") or {})}


def write_private(path, text):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        output.write(text)


PAGE = """<!doctype html><html lang="pt-BR"><meta charset="utf-8"><title>GERID</title>
<body style="font-family:system-ui;max-width:28rem;margin:4rem auto;padding:0 1rem">
<h1>Credenciais do GERID</h1>
<p>Digite a senha do pacote que você recebeu. Ela é usada só neste computador e esta página fecha em seguida.</p>
<form method="post"><input type="password" name="passphrase" autofocus required autocomplete="off"
 style="width:100%;padding:.6rem;font-size:1rem"><p><button style="padding:.6rem 1.2rem;font-size:1rem">Continuar</button></p>
</form></body></html>"""

DONE = "<!doctype html><meta charset='utf-8'><title>GERID</title><p style='font-family:system-ui;margin:4rem auto;max-width:28rem'>Pronto. Pode fechar esta janela e voltar ao Claude.</p>"


def passphrase_from_page(say, *, timeout=900, open_browser=True):
    """Pede a senha numa página de uso único em 127.0.0.1 e devolve o que foi digitado."""
    token = secrets.token_urlsafe(18)
    state = {"passphrase": None}

    class Handler(BaseHTTPRequestHandler):
        def _allowed(self):
            host = self.headers.get("Host", "")
            return self.path == f"/{token}" and host == f"127.0.0.1:{self.server.server_address[1]}"

        def _send(self, status, body):
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # noqa: N802
            self._send(200, PAGE) if self._allowed() else self._send(404, "")

        def do_POST(self):  # noqa: N802
            if not self._allowed() or state["passphrase"] is not None:
                return self._send(404, "")
            length = min(int(self.headers.get("Content-Length", "0") or 0), 4096)
            form = parse_qs(self.rfile.read(length).decode("utf-8"))
            state["passphrase"] = (form.get("passphrase") or [""])[0]
            self._send(200, DONE)

        def log_message(self, *_args):
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    server.timeout = 0.5
    url = f"http://127.0.0.1:{server.server_address[1]}/{token}"
    say(f"Abra esta página para digitar a senha do pacote: {url}")
    if open_browser:
        threading.Thread(target=webbrowser.open, args=(url,), daemon=True).start()
    deadline = time.time() + timeout
    try:
        while state["passphrase"] is None and time.time() < deadline:
            server.handle_request()
    finally:
        server.server_close()
    if state["passphrase"] is None:
        raise TimeoutError("Tempo esgotado esperando a senha do pacote")
    return state["passphrase"]
