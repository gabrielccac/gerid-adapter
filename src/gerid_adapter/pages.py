"""Leitura das páginas do CAS: estrutura e campos, sem expor valores ao imprimir."""

import re
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urlsplit

PUBLIC_PARAMS = {"service", "client_id", "redirect_uri", "response_type", "token_type", "expires_in", "scope"}


class Page(HTMLParser):
    def __init__(self, html):
        super().__init__()
        self.title, self.texts, self.forms = "", [], []
        self._tag, self._skip = None, 0
        self.feed(html if isinstance(html, str) else html.decode("utf-8", "replace"))

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("script", "style"):
            self._skip += 1
        self._tag = tag
        if tag == "form":
            self.forms.append({"id": a.get("id"), "action": a.get("action"), "method": (a.get("method") or "get").lower(),
                               "fields": {}})
        elif tag in ("input", "button", "select", "textarea") and self.forms and a.get("name"):
            self.forms[-1]["fields"][a["name"]] = a.get("value") or ""

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
        elif self._tag in ("h1", "h2", "h3", "h4", "label", "legend", "p", "span", "div", "li", "strong"):
            if len(text) < 240:
                self.texts.append(text)

    def form_with(self, field):
        return next((f for f in self.forms if field in f["fields"]), None)


def is_totp_page(page):
    return page.form_with("token") is not None and "_eventId_submit" in page.form_with("token")["fields"]


def is_certificate_login_page(page):
    """A tela inicial do CAS (usuário/senha ou botão de certificado): a sessão não vale mais."""
    return page.form_with("username") is not None or "Entrar com Certificado Digital" in " ".join(page.texts)


ERROR_HINTS = re.compile(r"(inv[áa]lid|incorret|expirad|bloquead|erro|n[ãa]o foi poss[íi]vel)", re.I)


def error_texts(page):
    return [t for t in page.texts if ERROR_HINTS.search(t)]


def hide_url(url):
    """A URL com os nomes dos parâmetros e só os valores públicos (sem tickets e tokens)."""
    parts = urlsplit(url)

    def show(text):
        items = []
        for key, value in parse_qsl(text, keep_blank_values=True):
            if key not in PUBLIC_PARAMS:
                value = "<oculto>"
            elif "://" in value:
                value = hide_url(value)
            items.append(f"{key}={value}")
        return "&".join(items)

    shown = f"{parts.scheme}://{parts.netloc}{parts.path}"
    if parts.query:
        shown += "?" + show(parts.query)
    if parts.fragment:
        shown += "#" + show(parts.fragment)
    return shown
