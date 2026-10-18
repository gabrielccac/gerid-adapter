"""Prova de conceito: handshake mTLS com o GERID usando a chave do token A3.

  uv run gerid-poc check     # sem PIN: token, cadeia e handshake sem certificado de cliente
  uv run gerid-poc pin-set   # grava o PIN no cofre do sistema (você digita no terminal)
  uv run gerid-poc login     # UM login no token + handshake com certificado + GET no GERID
  uv run gerid-poc authorize # OAuth + TOTP com o TGC salvo (sem PIN)
  uv run gerid-poc session   # troca do access_token + papel e estado p/ o browser (sem PIN)
  uv run gerid-poc api       # chamadas read-only à API do portal com o token salvo (sem PIN)
"""

import argparse
import json
import os
import re
from html.parser import HTMLParser
from pathlib import Path
import socket
import sys
import threading
import time
import warnings
from contextlib import contextmanager
from datetime import datetime

import certifi
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.x509.verification import PolicyBuilder, Store
from tlslite import HandshakeSettings, TLSConnection, X509, X509CertChain

from gerid_adapter import pin as pin_store
from gerid_adapter import totp
from gerid_adapter.tlskey import Pkcs11RSAKey
from gerid_adapter.token import PinError, Token

HOST = "geridinss.dataprev.gov.br"
PORT = 8443
CAS_PATH = "/cas/login"  # login X.509 do CAS (o botão "Entrar com Certificado Digital" leva aqui)


def settings():
    s = HandshakeSettings()
    s.minVersion = s.maxVersion = (3, 3)  # o GERID negocia TLS 1.2
    s.rsaSchemes = ["pkcs1"]  # assinatura que o token faz com CKM_RSA_PKCS
    s.rsaSigHashes = ["sha256", "sha384", "sha512"]
    return s


def tlslite_cert(cert):
    parsed = X509()
    parsed.parseBinary(cert.public_bytes(Encoding.DER))  # parseBinary não devolve o objeto
    return parsed


def to_tlslite_chain(certs):
    return X509CertChain([tlslite_cert(cert) for cert in certs])


def verify_server(connection):
    """Valida a cadeia e o nome do servidor com as ACs públicas (certifi) antes de mandar qualquer dado."""
    chain = [x509.load_der_x509_certificate(bytes(c.bytes)) for c in connection.session.serverCertChain.x509List]
    with warnings.catch_warnings():  # o bundle do certifi tem raízes antigas com serial negativo
        warnings.simplefilter("ignore")
        roots = x509.load_pem_x509_certificates(open(certifi.where(), "rb").read())
    verifier = PolicyBuilder().store(Store(roots)).time(datetime.now()).build_server_verifier(x509.DNSName(HOST))
    verifier.verify(chain[0], chain[1:])
    return chain[0]


def _tcp_target(port):
    """(host, porta) para o TCP: direto ao GERID ou ao túnel SSH (só muda o transporte).

    GERID_TUNNEL desvia a 8443 (mTLS); GERID_TUNNEL_443 desvia a 443. Quando o
    login passa pelo túnel, o authorize precisa sair pelo MESMO egresso, senão
    o CAS rejeita o TGC (foi mintado por outro IP). Ex.: "127.0.0.1:8444".
    """
    if port == 443:
        override = os.environ.get("GERID_TUNNEL_443", "")
    else:
        override = os.environ.get("GERID_TUNNEL", "")
    if override.strip():
        host, _, tunnel_port = override.partition(":")
        return host.strip() or "127.0.0.1", int(tunnel_port.strip() or port)
    return HOST, port


def connect(cert_chain=None, private_key=None, port=PORT):
    # GERID_TUNNEL="127.0.0.1:8444" desvia SÓ o TCP (ex.: ssh -L 8444:geridinss.dataprev.gov.br:8443);
    # SNI, Host e verificação do certificado continuam com o nome real: o mTLS
    # termina na Dataprev e o túnel só vê bytes cifrados.
    target_host, target_port = _tcp_target(port)
    # tlslite também na 443: o GERID só oferece troca RSA, que o ssl do Python recusa por padrão.
    sock = socket.create_connection((target_host, target_port), timeout=30)
    connection = TLSConnection(sock)
    started = time.monotonic()
    connection.handshakeClientCert(cert_chain, private_key, settings=settings(), serverName=HOST)
    elapsed = time.monotonic() - started
    server_cert = verify_server(connection)
    return connection, server_cert, elapsed


def http_post(connection, path, form, port=PORT, cookies=None, referer=None):
    from urllib.parse import urlencode

    data = urlencode(form).encode()
    host = HOST if port == 443 else f"{HOST}:{port}"
    lines = [
        f"POST {path} HTTP/1.1", f"Host: {host}", "User-Agent: gerid-adapter-poc", "Accept: text/html,*/*",
        "Content-Type: application/x-www-form-urlencoded", f"Content-Length: {len(data)}",
        f"Origin: https://{host}", "Connection: close",
    ]
    if referer:
        lines.append(f"Referer: {referer}")
    if cookies:
        lines.append(f"Cookie: {'; '.join(f'{k}={v}' for k, v in cookies.items())}")
    connection.write(("\r\n".join(lines) + "\r\n\r\n").encode() + data)
    return read_response(connection)


def read_response(connection):
    data = b""
    while True:
        try:
            chunk = connection.read()
        except Exception:
            break
        if not chunk:
            break
        data += bytes(chunk)
        if len(data) > 512_000:
            break
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("iso-8859-1").split("\r\n")
    return lines[0], lines[1:], body


def http_get(connection, path="/", port=PORT, cookies=None):
    host = HOST if port == 443 else f"{HOST}:{port}"
    cookie = f"Cookie: {'; '.join(f'{k}={v}' for k, v in cookies.items())}\r\n" if cookies else ""
    request = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: gerid-adapter-poc\r\nAccept: text/html,*/*\r\n{cookie}Connection: close\r\n\r\n"
    connection.write(request.encode())
    return read_response(connection)


def describe_response(status, headers, body):
    print(f"  resposta: {status}")
    for header in headers:
        name, _, value = header.partition(":")
        lower = name.lower()
        if lower == "location":
            print(f"  Location: {value.strip()}")
        elif lower == "set-cookie":
            print(f"  Set-Cookie: {value.split('=', 1)[0].strip()}=<oculto>")
        elif lower in ("content-type", "server"):
            print(f"  {name}: {value.strip()}")
    print(f"  corpo: {len(body)} bytes")


STATE_DIR = Path(__file__).resolve().parents[2] / ".local"  # fora do git; só o seu usuário lê
KEYWORDS = re.compile(r"(c[óo]digo|autenticador|totp|2fa|dois fatores|verifica[çc][ãa]o|segundo fator|token|otp)", re.I)


class PageSummary(HTMLParser):
    """Estrutura da página sem valores: título, cabeçalhos, formulários, campos e textos-chave."""

    def __init__(self):
        super().__init__()
        self.title, self.headings, self.forms, self.texts = "", [], [], []
        self._tag = None
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style"):
            self._skip += 1
        self._tag = tag
        if tag == "form":
            self.forms.append({"id": a.get("id"), "action": a.get("action"), "method": a.get("method"), "fields": []})
        elif tag in ("input", "select", "textarea", "button") and self.forms:
            self.forms[-1]["fields"].append(
                {k: a.get(k) for k in ("type", "name", "id", "autocomplete", "maxlength", "inputmode") if a.get(k)}
            )
            if a.get("name"):
                self.forms[-1].setdefault("values", {})[a["name"]] = a.get("value") or ""

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        self._tag = None

    def handle_data(self, data):
        text = " ".join(data.split())
        if not text or self._skip:
            return
        if self._tag == "title":
            self.title += text
        elif self._tag in ("h1", "h2", "h3", "h4", "label", "legend"):
            self.headings.append(text)
        elif KEYWORDS.search(text) and len(text) < 200:
            self.texts.append(text)


def cookie_pairs(headers):
    return {
        value.split("=", 1)[0].strip(): value.split("=", 1)[1].split(";", 1)[0]
        for name, _, value in (h.partition(":") for h in headers)
        if name.lower() == "set-cookie" and "=" in value
    }


def save_state(name, status, headers, body):
    """Guarda o HTML e os cookies em .local/ (permissão 700) para os próximos passos do fluxo."""
    STATE_DIR.mkdir(mode=0o700, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    (STATE_DIR / f"{name}.html").write_bytes(body)
    cookies_file = STATE_DIR / "cookies.json"
    cookies = json.loads(cookies_file.read_text()) if cookies_file.exists() else {}
    cookies.update(cookie_pairs(headers))
    cookies_file.write_text(json.dumps(cookies))
    os.chmod(cookies_file, 0o600)
    (STATE_DIR / f"{name}.headers.txt").write_text(status + "\n" + "\n".join(
        h if not h.lower().startswith("set-cookie") else h.split("=", 1)[0] + "=<oculto>" for h in headers
    ))


def parse_page(body):
    page = PageSummary()
    page.feed(body.decode("utf-8", "replace"))
    return page


def describe_page(body):
    page = PageSummary()
    page.feed(body.decode("utf-8", "replace"))
    print(f"  título: {page.title or '-'}")
    for heading in page.headings[:12]:
        print(f"  texto: {heading}")
    for text in page.texts[:12]:
        print(f"  aviso: {text}")
    for form in page.forms:
        print(f"  formulário id={form['id']} method={form['method']} action={form['action']}")
        for field in form["fields"]:
            print("    campo: " + ", ".join(f"{k}={v}" for k, v in field.items()))


def describe_session(connection, elapsed):
    s = connection.session
    print(f"  handshake: {elapsed:.1f}s | {connection.getVersionName()} | {connection.getCipherName()} ({connection.getCipherImplementation()})")
    return s


def cmd_check(args):
    token = Token(args.module)
    try:
        print(f"Token: {token.label} (série {token.serial})")
        problems = token.unsafe_pin_state()
        print("  estado do PIN: " + ("; ".join(problems) if problems else "OK, nenhuma tentativa errada"))
        _, chain = token.end_entity()
        print(f"  titular: {chain[0].subject.rfc4514_string()}")
        print(f"  cadeia enviada: {' <- '.join(c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value for c in chain)}")
        print(f"  validade: até {chain[0].not_valid_after_utc:%d/%m/%Y}")
        try:
            pin_store.get_pin(token.serial)
            print("  PIN no cofre: sim")
        except LookupError:
            print("  PIN no cofre: não (rode: uv run gerid-poc pin-set)")
    finally:
        token.close()

    print(f"\nHandshake SEM certificado de cliente com {HOST}:{PORT} (esperado: o servidor recusar ou pedir o certificado)")
    try:
        connection, server_cert, elapsed = connect()
        describe_session(connection, elapsed)
        print(f"  servidor: {server_cert.subject.rfc4514_string()} (cadeia válida)")
        describe_response(*http_get(connection, CAS_PATH))
        connection.close()
    except Exception as error:  # o resultado esperado aqui é informativo, não uma falha da PoC
        print(f"  {type(error).__name__}: {error}")


def cmd_pin_set(args):
    token = Token(args.module)
    try:
        pin_store.set_pin_interactive(token.serial)
    finally:
        token.close()


def cmd_totp_set(args):
    """Grava o segredo do autenticador do GERID no cofre (do .env do Jurisync ou digitado)."""
    import getpass

    if args.from_jurisync_env:
        env = Path.home() / ".config" / "jurisync" / ".env"
        raw = next(
            (line.split("=", 1)[1] for line in env.read_text(encoding="utf-8").splitlines()
             if re.match(r"\s*(export\s+)?INSS_GERID_TOTP_SECRET=", line)),
            "",
        )
        if not raw.strip():
            print(f"INSS_GERID_TOTP_SECRET não encontrado ou vazio em {env}.")
            return 1
    else:
        raw = getpass.getpass("Segredo do autenticador do GERID (Base32 ou otpauth://): ")
    try:
        secret = totp.normalize_secret(raw)
    except ValueError as error:
        print(f"Não gravei: {error}")
        return 1
    pin_store.set_totp_secret(secret)
    print(f"Segredo TOTP gravado no cofre ({pin_store.SERVICE} / {pin_store.TOTP_ACCOUNT}), {len(secret)} caracteres.")
    print(f"Confira no app autenticador: o código atual termina em ...{totp.code(secret)[-2:]}"
          f" (válido por mais {int(totp.seconds_left())}s).")
    return 0


def cmd_login(args):
    from gerid_adapter import net as netprobe

    target_host, target_port = _tcp_target(PORT)
    via_tunnel = (target_host, target_port) != (HOST, PORT)
    check_host = target_host if via_tunnel else netprobe.HOST
    ok, detail = netprobe.tcp_probe(check_host, target_port)
    if not ok:
        where = f"{check_host}:{target_port}" + (" (túnel SSH)" if via_tunnel else "")
        print(f"Sem rota TCP para {where} ({detail}).")
        if via_tunnel:
            print("Confira o túnel: ssh -N -L <porta>:geridinss.dataprev.gov.br:8443 usuario@servidor")
        else:
            print("Não toquei no token: troque de rede (ex.: hotspot do celular), "
                  "ou aguarde e rode: uv run gerid-poc watch")
        return 3
    if via_tunnel:
        print(f"Túnel ok ({check_host}:{target_port}); mTLS termina na Dataprev.")
    token = Token(args.module)
    try:
        ident, chain = token.end_entity()
        print(f"Token: {token.label} | titular: {chain[0].subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value}")
        token.login(pin_store.get_pin(token.serial))
        print("  login no token: OK (PIN lido do cofre)")
        key = Pkcs11RSAKey(token, token.private_key(ident), chain[0].public_key().public_numbers())
        print(f"\nHandshake COM certificado de cliente com {HOST}:{PORT}")
        connection, server_cert, elapsed = connect(to_tlslite_chain(chain), key)
        describe_session(connection, elapsed)
        print(f"  servidor: {server_cert.subject.rfc4514_string()} (cadeia válida)")
        print(f"  assinaturas feitas pelo token: {key.signatures}")
        status, headers, body = http_get(connection, args.path)
        describe_response(status, headers, body)
        describe_page(body)
        save_state("pos-login", status, headers, body)
        print(f"  página e cookies salvos em {STATE_DIR} (fora do git)")
        connection.close()
        print("\nOK: handshake mTLS com a chave do token concluído sem digitar o PIN.")
    except PinError as error:
        print(f"\nPARADO: {error}")
        return 2
    finally:
        token.close()
    return 0


AUTHORIZE_PATH = "/cas/oauth2.0/authorize"
SAG_CLIENT_ID = "SAG"  # client OAuth do portal atendimento.inss.gov.br (tirado do JS do site)
SAG_REDIRECT = "https://atendimento.inss.gov.br"


def hide_query(url):
    """Mostra a URL com os nomes dos parâmetros (query e fragmento) e os valores ocultos."""
    from urllib.parse import parse_qsl, urlsplit

    parts = urlsplit(url)
    public = {"service", "client_id", "redirect_uri", "response_type", "token_type", "expires_in", "scope"}

    def keys(text):
        return "&".join(
            f"{k}={hide_query(v) if k in ('service', 'redirect_uri') and '://' in v else v}" if k in public else f"{k}=<oculto>"
            for k, v in parse_qsl(text, keep_blank_values=True)
        )
    shown = f"{parts.scheme}://{parts.netloc}{parts.path}"
    if parts.query:
        shown += "?" + keys(parts.query)
    if parts.fragment:
        shown += "#" + keys(parts.fragment)
    return shown


def cmd_authorize(args):
    """Passo OAuth (implicit) do portal do INSS reaproveitando o TGC salvo: sem login no token."""
    from urllib.parse import urlencode

    cookies_file = STATE_DIR / "cookies.json"
    cookies = json.loads(cookies_file.read_text()) if cookies_file.exists() else {}
    if "TGC" not in cookies:
        print("Sem TGC salvo; rode antes: uv run gerid-poc login")
        return 1
    path = AUTHORIZE_PATH + "?" + urlencode(
        {"client_id": SAG_CLIENT_ID, "response_type": "token", "redirect_uri": SAG_REDIRECT}
    )
    from urllib.parse import urljoin, urlsplit

    url = f"https://{HOST}{path}"
    totp_sent = False
    for hop in range(1, 11):
        parts = urlsplit(url)
        if parts.hostname != HOST:
            print(f"\n[{hop}] saiu do GERID para {parts.hostname}: fim do fluxo no CAS")
            break
        port = parts.port or 443
        target = parts.path + (f"?{parts.query}" if parts.query else "")
        connection, _, _ = connect(port=port)
        status, headers, body = http_get(connection, target, port=port, cookies=cookies)
        connection.close()
        print(f"\n[{hop}] GET {hide_query(url)}")
        print(f"  resposta: {status} | corpo: {len(body)} bytes")
        cookies.update(cookie_pairs(headers))
        location = ""
        for header in headers:
            name, _, value = header.partition(":")
            if name.lower() == "location":
                location = urljoin(url, value.strip())
                print(f"  Location: {hide_query(location)}")
            elif name.lower() == "set-cookie":
                print(f"  Set-Cookie: {value.strip().split('=', 1)[0]}=<oculto>")
        if body and b"<html" in body[:2000].lower():
            describe_page(body)
        save_state(f"authorize-{hop}", status, headers, body)
        if not location:
            page = parse_page(body)
            totp_form = next((f for f in page.forms if "token" in f.get("values", {})), None)
            if totp_form is None or totp_sent:
                print("  (sem redirecionamento: o fluxo parou nesta página)")
                if totp_sent:
                    print("  O código TOTP não foi aceito. Não vou tentar de novo: confira o segredo e o relógio do Mac.")
                break
            try:
                secret = pin_store.get_totp_secret()
            except LookupError as error:
                print(f"  O CAS pede o código TOTP. {error}")
                break
            form = {k: v for k, v in totp_form["values"].items() if not k.startswith("_eventId")}
            form["token"] = totp.fresh_code(secret)
            form["_eventId_submit"] = totp_form["values"].get("_eventId_submit", "")
            # _eventId_requestDeviceReset NUNCA é enviado: ele pede o reset do autenticador.
            totp_sent = True
            action = urljoin(url, totp_form.get("action") or parts.path)
            connection, _, _ = connect(port=port)
            status, headers, body = http_post(connection, urlsplit(action).path, form, port=port, cookies=cookies, referer=url)
            connection.close()
            print(f"\n[{hop}b] POST {hide_query(action)} (código TOTP gerado do segredo no cofre, não exibido)")
            print(f"  resposta: {status} | corpo: {len(body)} bytes")
            cookies.update(cookie_pairs(headers))
            location = ""
            for header in headers:
                name, _, value = header.partition(":")
                if name.lower() == "location":
                    location = urljoin(url, value.strip())
                    print(f"  Location: {hide_query(location)}")
                elif name.lower() == "set-cookie":
                    print(f"  Set-Cookie: {value.strip().split('=', 1)[0]}=<oculto>")
            if body and b"<html" in body[:2000].lower():
                describe_page(body)
            save_state(f"authorize-{hop}b", status, headers, body)
            if not location:
                print("  (sem redirecionamento após o código: provavelmente recusado; não vou repetir)")
                break
        if "#" in location and "access_token" in location.split("#", 1)[1]:
            fragment = STATE_DIR / "oauth-fragment.txt"
            fragment.write_text(location.split("#", 1)[1])
            os.chmod(fragment, 0o600)
            print("  access_token recebido e salvo em .local/oauth-fragment.txt (não exibido)")
            break
        url = location
    cookies_file.write_text(json.dumps(cookies))
    os.chmod(cookies_file, 0o600)
    return 0


def cmd_session(args):
    """Troca do access_token + papel, sem browser: completa a sessão do portal."""
    from gerid_adapter import session as session_mod

    fragment = session_mod.read_fragment(args.fragment)
    access_token = fragment.get("access_token", "")
    if not access_token.startswith("AT-"):
        print(f"Sem access_token válido em {args.fragment}; rode antes: uv run gerid-poc authorize")
        return 1
    transport = session_mod.make_transport()
    try:
        gerid_token = session_mod.exchange(transport, access_token)
        role, ifs_auth = session_mod.select_role(transport, access_token, gerid_token)
    except Exception as error:
        print(f"Falhou: {error}")
        return 1
    session_mod.save_session(args.dir, access_token, fragment.get("expires_in", "600"), gerid_token, ifs_auth)
    claims = session_mod.jwt_claims(ifs_auth)
    print(f"Papel: {role.get('name')} | {role.get('fullName')}")
    print(f"Token: {claims.get('nome')} | CPF {claims.get('cpf')} | válido por mais {session_mod.seconds_left(ifs_auth) // 60} min")
    print(f"Sessão salva em {args.dir} (gerid_token.jwt, ifs_auth.jwt, portal-session.json).")
    return 0


def _captcha_call(args, client, operation):
    """Minta e chama; diante de 400 (ex.: perfil ainda aquecendo), tenta 1x com token novo."""
    from gerid_adapter import api as api_mod
    from gerid_adapter import recaptcha as recaptcha_mod

    try:
        state = json.loads(Path(args.session_state).read_text())
    except OSError:
        return None, f"Sem estado do portal em {args.session_state}; rode antes: uv run gerid-poc session"
    last = None
    for _ in range(2):
        try:
            captcha = recaptcha_mod.mint(state, backend_name=args.browser, headless=args.headless)
            if operation == "notifications":
                return client.notifications(captcha, first=args.first), None
            return client.search_tasks(captcha, page=args.page, page_size=args.page_size), None
        except (api_mod.ApiError, OSError, RuntimeError) as error:
            last = error
            if getattr(error, "status", None) != 400:
                break
    return None, f"Falhou: {last}"


def _artifact_fresh(path, ttl_seconds):
    """Arquivo existe e foi escrito há menos de `ttl_seconds`?"""
    try:
        return time.time() - Path(path).stat().st_mtime < ttl_seconds
    except OSError:
        return False


def _try_session(state_dir):
    """Troca + papel com o access_token salvo. Devolve True se renovou."""
    from gerid_adapter import session as session_mod

    fragment, ifs = Path(state_dir) / "oauth-fragment.txt", Path(state_dir) / "ifs_auth.jwt"
    before = ifs.stat().st_mtime if ifs.exists() else 0
    args = argparse.Namespace(fragment=str(fragment), dir=str(state_dir))
    if cmd_session(args) != 0:
        return False
    try:
        return ifs.stat().st_mtime > before and session_mod.seconds_left(ifs.read_text().strip()) > 0
    except (OSError, ValueError):
        return False


def _try_authorize(state_dir):
    """OAuth + TOTP com o TGC salvo; True se saiu access_token novo."""
    fragment = Path(state_dir) / "oauth-fragment.txt"
    before = fragment.stat().st_mtime if fragment.exists() else 0
    if cmd_authorize(argparse.Namespace()) != 0:
        return False
    try:
        fresh = fragment.stat().st_mtime > before and "access_token=AT-" in fragment.read_text()
    except OSError:
        fresh = False
    return fresh and _try_session(state_dir)


def _try_full_login(state_dir, module):
    """Login no token + authorize + session. True se a cadeia completa passou."""
    if cmd_login(argparse.Namespace(module=module, path=CAS_PATH)) != 0:
        return False
    return _try_authorize(state_dir)


_SESSION_THREAD_LOCK = threading.Lock()


@contextmanager
def session_lock(state_dir):
    """Uma renovação por vez: entre threads do MCP e entre processos (MCP x CLI).

    Duas cascatas simultâneas disputam o token A3 (CKR_USER_NOT_LOGGED_IN) e
    gravam ifs_auth/portal-session pela metade; quem chega depois espera e,
    ao entrar, reavalia a sessão que o primeiro acabou de renovar.
    """
    folder = Path(state_dir)
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    with _SESSION_THREAD_LOCK, open(folder / "session.lock", "a") as handle:
        try:
            import fcntl
        except ImportError:  # Windows: só a trava entre threads
            yield
            return
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def ensure_session(args, quiet=False):
    """Garante sessão válida, renovando sozinho só o que expirou (sem digitar nada).

    Cascata: ifs_auth válido → reusar; access_token fresco → só troca+papel;
    TGC válido → authorize; senão login completo. Precisa do token A3 plugado
    e dos segredos no cofre apenas nos níveis que chegarem até eles.
    """
    state_dir = Path(getattr(args, "dir", None) or STATE_DIR)
    with session_lock(state_dir):
        return _ensure_session_locked(state_dir, getattr(args, "module", None), quiet)


def _ensure_session_locked(state_dir, module, quiet):
    from gerid_adapter import api as api_mod

    try:
        left = api_mod.seconds_left((state_dir / "ifs_auth.jwt").read_text().strip())
    except (OSError, ValueError):
        left = -1
    if left > 120:
        from gerid_adapter import api as api_mod

        token_text = (state_dir / "ifs_auth.jwt").read_text().strip()
        try:
            live = api_mod.PortalApi(token_text).alive()
        except Exception:
            live = False
        if live:
            if not quiet:
                print(f"Sessão válida por mais {left // 60} min (nada a renovar).")
            return 0
        print("Token vencido no servidor apesar do prazo; renovando...")
    if _artifact_fresh(state_dir / "oauth-fragment.txt", 600) and _try_session(state_dir):
        print("Sessão renovada (troca + papel).")
        return 0
    from gerid_adapter import pin as pin_store

    try:
        pin_store.get_totp_secret()
    except Exception as error:
        _report([f"TOTP: {error}", "Sem o segredo do autenticador, nem authorize nem login avançam."])
        return 1
    print("Renovando a sessão automaticamente...")
    if _try_authorize(state_dir):
        print("Sessão renovada.")
        return 0
    state = diagnose()
    login_blockers = [
        f"{name}: {state[name]}"
        for name in ("token", "pin")
        if state[name].startswith(("ausente", "inseguro", "cofre"))
    ]
    if login_blockers:
        _report(login_blockers)
        return 1
    if _try_full_login(state_dir, module):
        print("Sessão renovada.")
        return 0
    print("Não renovei (veja o motivo acima; se for rede, troque de rede ou rode `gerid-poc watch`).")
    return 1


def cmd_ensure(args):
    return ensure_session(args)


def cmd_watch(args):
    """Espera a 8443 voltar e roda a cadeia completa sozinho (login→authorize→session)."""
    from gerid_adapter import net as netprobe

    print(f"Aguardando {netprobe.HOST}:8443 por até {args.timeout}s "
          f"(verifico a cada {args.interval}s; sem tocar no token)...")
    if not netprobe.wait_for_port(timeout_total=args.timeout, interval=args.interval):
        print("8443 continuou sem responder; nada foi tentado no token.")
        return 3
    print("8443 respondeu; rodando a cadeia completa.")
    with session_lock(STATE_DIR):
        if cmd_login(argparse.Namespace(module=args.module, path=CAS_PATH)) != 0:
            return 1
        return 0 if _try_authorize(STATE_DIR) else 1


def diagnose():
    """Pré-verificação local (sem rede, sem login): A3 plugado? PIN/TOTP no cofre?

    Devolve {"token": ..., "pin": ..., "totp": ...} só com estado, nunca segredos.
    """
    from gerid_adapter import pin as pin_store
    from gerid_adapter.token import Token

    result = {"token": "ausente", "pin": "desconhecido", "totp": "desconhecido"}
    try:
        token = Token(None)
    except Exception as error:
        result["token"] = f"ausente ({error})"
        result["totp"] = _totp_state(pin_store)
        return result
    try:
        result["token"] = f"{token.label} (série {token.serial})"
        unsafe = token.unsafe_pin_state()
        if unsafe:
            result["pin"] = "inseguro: " + "; ".join(unsafe)
        else:
            try:
                pin_store.get_pin(token.serial)
                result["pin"] = "ok (no cofre)"
            except LookupError:
                result["pin"] = "ausente no cofre (grave com: uv run gerid-poc pin-set)"
            except Exception as error:
                result["pin"] = f"cofre inacessível ({error})"
    finally:
        try:
            token.close()
        except Exception:
            pass
    result["totp"] = _totp_state(pin_store)
    return result


def _totp_state(pin_store):
    try:
        pin_store.get_totp_secret()
        return "ok (no cofre)"
    except LookupError:
        return "ausente no cofre (grave com: uv run gerid-poc totp-set)"
    except Exception as error:
        return f"cofre inacessível ({error})"


def _report(problems):
    print("Pré-verificação:")
    for problem in problems:
        print(f"  - {problem}")


def cmd_diagnose(args):
    from gerid_adapter import net as netprobe

    state = diagnose()
    print(f"Token A3: {state['token']}")
    print(f"PIN: {state['pin']}")
    print(f"TOTP: {state['totp']}")
    net = netprobe.gerid_status()
    print(f"Rede 443: {net['tcp_443']}")
    print(f"Rede 8443: {net['tcp_8443']} (login mTLS)")
    print(f"Saída: {net['egress_ip'] or 'desconhecida'} | {net['veredito']}")
    ok = (
        not state["token"].startswith("ausente")
        and state["pin"].startswith("ok")
        and state["totp"].startswith("ok")
        and net["tcp_8443"].startswith("ok")
    )
    return 0 if ok else 1


def cmd_api(args):
    """Chamadas read-only à API do portal com o token salvo: sem PIN, sem tocar no token A3."""
    from gerid_adapter import api as api_mod

    if not args.no_refresh and args.token is None:
        state = argparse.Namespace(dir=str(STATE_DIR), module=args.module)
        if ensure_session(state, quiet=True):
            return 1
    token = api_mod.load_token(args.token)
    remaining = api_mod.seconds_left(token)
    if remaining <= 0:
        print(f"Token expirado há {-remaining}s; rode antes: uv run gerid-poc authorize")
        return 1
    client = api_mod.PortalApi(token)
    print(f"Token: {client.claims.get('nome')} | CPF {client.claims.get('cpf')} | válido por mais {remaining // 60} min")
    try:
        if args.task:
            result = client.get_task(args.task)
        elif args.process:
            result = client.process(args.process)
        elif args.attachment:
            result = client.attachment(*args.attachment)
        elif args.notifications or args.search:
            result, failure = _captcha_call(args, client, "notifications" if args.notifications else "search")
            if failure:
                print(failure)
                return 1
        else:
            print("Escolha uma operação: --task, --process, --attachment, --notifications ou --search.")
            return 2
    except (api_mod.ApiError, ValueError, OSError, RuntimeError) as error:
        print(f"Falhou: {error}")
        return 1
    if args.attachment:
        print(json.dumps(result, ensure_ascii=False, indent=2)[:4000] if result is not None else "(204: nada encontrado)")
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2) if result is not None else "(204: nada encontrado)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(prog="gerid-poc", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--module", help="biblioteca PKCS#11 (padrão: SafeSign do sistema)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check").set_defaults(func=cmd_check)
    sub.add_parser("pin-set").set_defaults(func=cmd_pin_set)
    login = sub.add_parser("login")
    login.add_argument("--path", default=CAS_PATH, help="caminho do GET depois do handshake")
    login.set_defaults(func=cmd_login)
    totp_set = sub.add_parser("totp-set", help="grava o segredo TOTP do GERID no cofre")
    totp_set.add_argument("--from-jurisync-env", action="store_true", help="lê INSS_GERID_TOTP_SECRET do .env do Jurisync")
    totp_set.set_defaults(func=cmd_totp_set)
    authorize = sub.add_parser("authorize", help="OAuth do portal do INSS com o TGC salvo (sem PIN)")
    authorize.set_defaults(func=cmd_authorize)
    session = sub.add_parser("session", help="troca do access_token + papel e estado p/ o browser (sem PIN)")
    session.add_argument("--fragment", default=str(STATE_DIR / "oauth-fragment.txt"))
    session.add_argument("--dir", default=str(STATE_DIR))
    session.set_defaults(func=cmd_session)
    ensure = sub.add_parser("ensure", help="garante sessão válida, renovando sozinho só o que expirou")
    ensure.add_argument("--dir", default=str(STATE_DIR))
    ensure.set_defaults(func=cmd_ensure)
    watch = sub.add_parser("watch", help="espera a 8443 voltar e credencia sozinho")
    watch.add_argument("--timeout", type=int, default=3600, help="tempo máximo de espera em segundos")
    watch.add_argument("--interval", type=int, default=30, help="intervalo entre verificações em segundos")
    watch.set_defaults(func=cmd_watch)
    sub.add_parser("diagnose", help="pré-verificação: A3 plugado? PIN/TOTP no cofre?").set_defaults(func=cmd_diagnose)
    api = sub.add_parser("api", help="chamadas read-only à API do portal com o token salvo (sem PIN)")
    api.add_argument("--token", help="arquivo do token (padrão .local/ifs_auth.jwt)")
    api.add_argument("--module", help="biblioteca PKCS#11 (só usada se a sessão precisar de login)")
    api.add_argument("--no-refresh", action="store_true", help="não renovar a sessão sozinho")
    api.add_argument("--task", metavar="PROTOCOLO", help="detalhes de uma tarefa")
    api.add_argument("--process", metavar="PROTOCOLO", help="relatório consolidado do processo")
    api.add_argument("--attachment", nargs=2, metavar=("PROTOCOLO", "ANEXO"), help="anexo em Base64")
    api.add_argument("--notifications", action="store_true", help="notificações (exige captcha: minta em headless)")
    api.add_argument("--first", type=int, default=0, help="deslocamento das notificações")
    api.add_argument("--search", action="store_true", help="busca de tarefas (exige captcha: minta em headless)")
    api.add_argument("--page", type=int, default=1, help="página da busca")
    api.add_argument("--page-size", type=int, default=20, help="itens por página (1-100)")
    api.add_argument("--session-state", default=str(STATE_DIR / "portal-session.json"))
    api.add_argument("--browser", default="cloak", choices=("cloak", "cdp"),
                     help="mint do captcha: cloak (headless stealth) ou cdp (seu Chrome, perfil persistente)")
    api.add_argument("--headless", action="store_true",
                     help="cdp em headless (sem janela; exige o perfil já aquecido)")
    api.set_defaults(func=cmd_api)
    args = parser.parse_args(argv)
    try:
        return_code = args.func(args) or 0
    except PinError as error:
        print(f"\nPARADO: {error}")
        return_code = 2
    except (OSError, RuntimeError) as error:
        print(f"\nFalhou antes de concluir: {error}")
        return_code = 1
    sys.exit(return_code)


if __name__ == "__main__":
    main()
