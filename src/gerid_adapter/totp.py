"""TOTP (RFC 6238) do 2FA do GERID: o mesmo código do Google Authenticator."""

import base64
import hashlib
import hmac
import re
import struct
import time
from urllib.parse import parse_qs, urlsplit

PERIOD = 30
DIGITS = 6


def normalize_secret(value):
    """Aceita a chave Base32 ou a URL otpauth://totp/...?secret=... e devolve o Base32 limpo."""
    value = value.strip().strip("\"'")
    if value.lower().startswith("otpauth://"):
        query = parse_qs(urlsplit(value).query)
        if "secret" not in query:
            raise ValueError("A URL otpauth não tem o parâmetro secret.")
        value = query["secret"][0]
    secret = re.sub(r"[\s-]", "", value).upper().rstrip("=")
    if not secret or not re.fullmatch(r"[A-Z2-7]+", secret):
        raise ValueError("O segredo TOTP não é Base32 válido.")
    base64.b32decode(secret + "=" * (-len(secret) % 8))
    return secret


def code(secret, at=None, digits=DIGITS, period=PERIOD, digest=hashlib.sha1):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    counter = int((time.time() if at is None else at) // period)
    mac = hmac.new(key, struct.pack(">Q", counter), digest).digest()
    offset = mac[-1] & 0x0F
    number = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(number % 10**digits).zfill(digits)


def seconds_left(period=PERIOD, at=None):
    now = time.time() if at is None else at
    return period - now % period


def fresh_code(secret, minimum_seconds=5):
    """Um código com pelo menos `minimum_seconds` de validade (espera a próxima janela se preciso)."""
    left = seconds_left()
    if left < minimum_seconds:
        time.sleep(left + 0.5)
    return code(secret)
