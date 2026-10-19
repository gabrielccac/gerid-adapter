"""PIN do token e segredo TOTP do GERID, lidos do `.env` do usuário.

O arquivo padrão é `.env` na raiz do projeto; `GERID_ENV_FILE` aponta para
outro. Variáveis já definidas no ambiente valem mais que o arquivo.
"""

import os
from pathlib import Path

from gerid_adapter import totp

PIN_VAR = "GERID_PIN"
TOTP_VAR = "GERID_TOTP_SECRET"
PROJECT_ROOT = Path(__file__).resolve().parents[2]


def env_file():
    return Path(os.environ.get("GERID_ENV_FILE") or PROJECT_ROOT / ".env")


def _parse(text):
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().removeprefix("export ").strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def _read(name):
    if os.environ.get(name):
        return os.environ[name]
    path = env_file()
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return None
    except OSError as error:
        raise RuntimeError(f"env ilegível ({path}: {error.strerror})") from None
    return _parse(text).get(name) or None


def get_pin(serial=None):
    """PIN do token A3. `serial` fica na assinatura por compatibilidade; um PIN por máquina."""
    pin = _read(PIN_VAR)
    if not pin:
        raise LookupError(f"{PIN_VAR} não está definido em {env_file()}.")
    return pin


def get_totp_secret():
    raw = _read(TOTP_VAR)
    if not raw:
        raise LookupError(f"{TOTP_VAR} não está definido em {env_file()}.")
    try:
        return totp.normalize_secret(raw)
    except ValueError as error:
        raise LookupError(f"{TOTP_VAR} inválido: {error}") from None


def secret_from_qr(image_path):
    """Lê o QR do autenticador do GERID numa imagem e devolve o segredo Base32."""
    import zxingcpp
    from PIL import Image

    with Image.open(image_path) as image:
        codes = zxingcpp.read_barcodes(image, formats=zxingcpp.BarcodeFormat.QRCode)
    if len(codes) != 1:
        raise ValueError(f"Esperava um QR na imagem, achei {len(codes)}.")
    text = codes[0].text
    if not text.startswith("otpauth://totp/"):
        raise ValueError("O QR não é um autenticador TOTP (otpauth://totp/...).")
    return totp.normalize_secret(text)


def save_totp_secret(secret):
    """Grava ou troca GERID_TOTP_SECRET no .env, mantendo o resto; arquivo com permissão 600."""
    path = env_file()
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    line = f"{TOTP_VAR}={secret}"
    for i, current in enumerate(lines):
        key = current.split("=", 1)[0].strip().removeprefix("export ").strip()
        if "=" in current and not current.lstrip().startswith("#") and key == TOTP_VAR:
            lines[i] = line
            break
    else:
        lines.append(line)
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    path.chmod(0o600)
    return path
