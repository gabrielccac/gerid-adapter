"""PIN do token no cofre do sistema (Chaveiro no macOS, Gerenciador de Credenciais
no Windows, Secret Service no Linux), nunca em arquivo."""

import getpass

import keyring

SERVICE = "gerid-adapter"


def account(serial):
    return f"pin:{serial}"


def get_pin(serial):
    pin = keyring.get_password(SERVICE, account(serial))
    if not pin:
        raise LookupError(
            f"PIN do token {serial} não está no cofre. Grave com: uv run gerid-poc pin-set"
        )
    return pin


def set_pin_interactive(serial):
    """Pede o PIN no terminal (sem eco) duas vezes e grava no cofre."""
    first = getpass.getpass(f"PIN do token {serial}: ")
    if first != getpass.getpass("Repita o PIN: "):
        raise SystemExit("Os PINs não conferem; nada foi gravado.")
    if not first.isdigit():
        print("Aviso: o PIN tem caracteres não numéricos; confira se está certo.")
    keyring.set_password(SERVICE, account(serial), first)
    print(f"PIN gravado no cofre do sistema ({SERVICE} / {account(serial)}).")


def delete_pin(serial):
    keyring.delete_password(SERVICE, account(serial))


TOTP_ACCOUNT = "totp:gerid"


def get_totp_secret():
    secret = keyring.get_password(SERVICE, TOTP_ACCOUNT)
    if not secret:
        raise LookupError("Segredo TOTP do GERID não está no cofre. Grave com: uv run gerid-poc totp-set")
    return secret


def set_totp_secret(secret):
    keyring.set_password(SERVICE, TOTP_ACCOUNT, secret)
