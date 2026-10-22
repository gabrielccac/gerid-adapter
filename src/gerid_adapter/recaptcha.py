"""Oráculo de `tokenReCAPTCHA`: minta o token dentro da página autenticada.

O token do reCAPTCHA Enterprise só é aceito quando nasce no contexto da
página autenticada do portal (mesma sessão/origem). Chrome headless comum
recebe score de bot e é recusado; por isso o mint roda num Chromium stealth
(CloakBrowser) headless, que pontua como humano.

Uso típico (um token por chamada, válido por ~2 min)::

    state = json.loads(Path(".local/portal-session.json").read_text(encoding="utf-8"))
    token = mint(state)
    api.notifications(token)

Backends: ``cloak`` (padrão, headless stealth) ou ``cdp`` (o Chrome do usuário
via CDP, com perfil persistente — abre janela, mas é binário first-party).
"""

import os
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

PORTAL = "https://atendimento.inss.gov.br"
TASKS_URL = PORTAL + "/tarefas"

# Key do anchor `recaptcha/enterprise` lida na página real do portal
# autenticado (não reutilizar chaves de terceiros: esta sai do nosso fluxo).
SITE_KEY = "6LfA-t8oAAAAAAMYMMHDthsSTek1eOYMwyjJcvoK"

# Seed fixa = identidade estável ("visitante recorrente") entre execuções.
FINGERPRINT_SEED = "424242"

DEFAULT_CDP_PORT = 9252

# O cloakbrowser baixa o próprio Chromium (centenas de MB) no primeiro launch e não
# tem trava: duas chamadas juntas baixariam em dobro. Um download por processo.
_CLOAK_BINARY_LOCK = threading.Lock()


def prepare_cloak():
    """Garante o Chromium do cloak no cache (~/.cloakbrowser), baixando se faltar. Devolve o caminho."""
    from cloakbrowser import ensure_binary

    with _CLOAK_BINARY_LOCK:
        return ensure_binary()
DEFAULT_CDP_PROFILE = Path(__file__).resolve().parents[2] / ".local" / "chrome-cdp-profile"


def site_key():
    return os.environ.get("INSS_RECAPTCHA_KEY") or SITE_KEY


def backend():
    """Backend de mint: flag --browser, env INSS_BROWSER ou o padrão cloak."""
    return os.environ.get("INSS_BROWSER", "cloak")


def chrome_executable(configured=None):
    """Chrome do usuário (para o backend cdp)."""
    candidates = [configured, os.environ.get("INSS_CHROME_PATH")]
    if sys.platform == "darwin":
        candidates.append("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome")
    elif sys.platform == "win32":
        candidates += [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        ]
    else:
        candidates += ["/usr/bin/google-chrome", "/usr/bin/chromium"]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    raise RuntimeError("Google Chrome não encontrado; defina INSS_CHROME_PATH.")


def chrome_cmd(chrome_path=None, port=DEFAULT_CDP_PORT, profile_dir=None, headless=False):
    """Linha de comando do Chrome CDP com perfil persistente (só o do usuário)."""
    profile = Path(profile_dir or DEFAULT_CDP_PROFILE)
    profile.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(profile, 0o700)  # o perfil guarda cookies/tokens: só o dono lê
    cmd = [
        chrome_executable(chrome_path),
        f"--remote-debugging-port={port}",
        f"--user-data-dir={profile.resolve()}",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-component-update",
        "--disable-background-networking",
        "--disable-sync",
        "--disable-translate",
        "--disable-default-apps",
    ]
    if headless:
        # Headless só passa no captcha com o perfil já aquecido (histórico/score);
        # perfil frio costuma levar 400 na primeira vez (o retry cobre isso).
        cmd[1:1] = ["--headless=new", "--disable-gpu"]
    return cmd + ["about:blank"]


def _init_script(state):
    return (
        "try{const S=%s;for(const k in S){localStorage.setItem(k,S[k]);}}catch(e){}"
        % __import__("json").dumps(state)
    )


def _execute_token(page, key, action):
    try:
        title = page.title() or ""
    except Exception:
        title = ""
    if "login" in title.lower():
        # A URL fica em /tarefas mas o conteúdo é o login do CAS: sessão morta
        # no servidor, e o execute com a nossa key nunca resolve nessa página.
        raise RuntimeError(
            "A página abriu na tela de login: sessão morta no servidor. "
            "Re-credencie (gerid-poc login && gerid-poc authorize && gerid-poc session)."
        )
    return page.evaluate(
        """async ({key, action}) => {
            const g = window.grecaptcha.enterprise;
            const run = new Promise((resolve, reject) => {
                g.ready(() => { g.execute(key, action ? {action} : {}).then(resolve).catch(reject); });
            });
            // Fora do portal (ex.: redirecionado ao login do CAS) o execute nunca resolve.
            const limit = new Promise((_, reject) => setTimeout(
                () => reject(new Error("grecaptcha.execute sem resposta em " + location.host)), 20000));
            return await Promise.race([run, limit]);
        }""",
        {"key": key, "action": action},
    )


def _wait_grecaptcha(page, timeout_ms):
    page.wait_for_function(
        # A página também carrega o api.js comum: esperar o enterprise, senão o
        # execute com a key enterprise cai no grecaptcha comum e nunca resolve.
        "() => !!(window.grecaptcha && window.grecaptcha.enterprise"
        " && window.grecaptcha.enterprise.execute)",
        timeout=timeout_ms,
    )


def mint_cloak(state, action=None, timeout_ms=60_000):
    """Mint headless com o Chromium stealth (padrão: sem janela)."""
    from cloakbrowser import launch

    with _CLOAK_BINARY_LOCK:  # o launch baixa o binário se faltar
        browser = launch(
            headless=True,
            locale="pt-BR",
            timezone="America/Sao_Paulo",
            args=[f"--fingerprint={FINGERPRINT_SEED}"],
        )
    try:
        context = browser.new_context(locale="pt-BR", timezone_id="America/Sao_Paulo")
        context.add_init_script(_init_script(state))
        page = context.new_page()
        page.set_default_timeout(timeout_ms)
        page.goto(TASKS_URL, wait_until="domcontentloaded", timeout=timeout_ms)
        _wait_grecaptcha(page, timeout_ms)
        return _execute_token(page, site_key(), action)
    finally:
        browser.close()


def _wait_cdp(port, timeout_s=60):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/json/version", timeout=2)
            return
        except Exception:
            time.sleep(0.5)
    raise RuntimeError(f"A porta CDP {port} não respondeu.")


def _free_port():
    """Uma porta TCP livre na hora (cada mint ganha a sua; sem colisão)."""
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _stage_profile(profile_dir):
    """Copia o perfil aquecido para um diretório temporário (sem locks).

    O original nunca é aberto diretamente: execuções concorrentes ou
    interrompidas não disputam trava nem porta, e nada órfão bloqueia o futuro.
    """
    import shutil
    import tempfile

    src = Path(profile_dir or DEFAULT_CDP_PROFILE)
    if not src.is_dir():
        raise RuntimeError(f"Perfil aquecido não encontrado em {src}. Rode uma vez headed para aquecer.")
    dest = Path(tempfile.mkdtemp(prefix="gerid-mint-"))
    shutil.rmtree(dest)
    # symlinks como links (RunningChromeVersion aponta p/ o .app; Singleton*
    # órfãos nem são copiados): nunca seguir link morto nem o binário inteiro.
    shutil.copytree(src, dest, symlinks=True, ignore=shutil.ignore_patterns("Singleton*"))
    os.chmod(dest, 0o700)
    return dest


def mint_cdp(state, action=None, timeout_ms=60_000, chrome=None, port=None,
           profile_dir=None, headless=False):
    """Mint no Chrome do usuário via CDP (cópia descartável do perfil aquecido)."""
    import shutil

    from playwright.sync_api import sync_playwright

    staged = _stage_profile(profile_dir or DEFAULT_CDP_PROFILE)
    port = port or _free_port()
    process = subprocess.Popen(
        chrome_cmd(chrome, port, staged, headless),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        _wait_cdp(port)
        playwright = sync_playwright().start()
        try:
            browser = playwright.chromium.connect_over_cdp(f"http://127.0.0.1:{port}", timeout=30000)
            context = browser.contexts[0]
            context.add_init_script(_init_script(state))
            page = context.new_page()
            page.set_default_timeout(timeout_ms)
            page.goto(TASKS_URL, wait_until="domcontentloaded", timeout=timeout_ms)
            _wait_grecaptcha(page, timeout_ms)
            return _execute_token(page, site_key(), action)
        finally:
            playwright.stop()
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except Exception:
            process.kill()
        shutil.rmtree(staged, ignore_errors=True)


def mint(state, action=None, timeout_ms=60_000, backend_name=None, headless=False):
    """Minta um `tokenReCAPTCHA` (uso único) com o estado de `portal-session.json`."""
    which = backend_name or backend()
    if which not in ("cdp", "cloak"):
        raise ValueError(f"Backend de mint desconhecido: {which!r} (use cloak ou cdp).")
    try:
        if which == "cdp":
            return mint_cdp(state, action, timeout_ms, headless=headless)
        return mint_cloak(state, action, timeout_ms)
    except Exception as error:
        raise RuntimeError(f"Mint do captcha falhou ({type(error).__name__}): {error}") from None
