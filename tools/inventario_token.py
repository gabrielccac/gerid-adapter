"""Inventário só de leitura do token A3 via PKCS#11.

Não faz login (C_Login) e não pede PIN: lista slots, dados do token,
estado do contador de tentativas do PIN e os certificados públicos.

Uso: uv run --with pykcs11 --with cryptography python tools/inventario_token.py [caminho_do_modulo]
"""

import sys

import PyKCS11
from cryptography import x509

DEFAULT_MODULES = {
    "darwin": "/Applications/tokenadmin.app/Contents/Frameworks/libaetpkss.dylib",
    "win32": "aetpkss1.dll",
    "linux": "/usr/lib/libaetpkss.so",
}

PIN_FLAGS = {
    "CKF_USER_PIN_COUNT_LOW": "PIN: já houve tentativa errada",
    "CKF_USER_PIN_FINAL_TRY": "PIN: resta só UMA tentativa",
    "CKF_USER_PIN_LOCKED": "PIN: BLOQUEADO",
    "CKF_USER_PIN_TO_BE_CHANGED": "PIN: precisa ser trocado",
    "CKF_PROTECTED_AUTHENTICATION_PATH": "PIN digitado no próprio leitor/teclado",
    "CKF_LOGIN_REQUIRED": "login exigido para usar a chave privada",
}


def main():
    module = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_MODULES.get(sys.platform)
    lib = PyKCS11.PyKCS11Lib()
    lib.load(module)
    info = lib.getInfo()
    print(f"Módulo: {module}")
    print(f"  {info.manufacturerID.strip()} | {info.libraryDescription.strip()} | v{info.libraryVersion}")

    slots = lib.getSlotList(tokenPresent=True)
    print(f"Slots com token: {len(slots)}")
    for slot in slots:
        token = lib.getTokenInfo(slot)
        print(f"\n[slot {slot}] {token.label.strip()}")
        print(f"  fabricante: {token.manufacturerID.strip()} | modelo: {token.model.strip()} | série: {token.serialNumber.strip()}")
        print(f"  PIN: {token.ulMinPinLen}-{token.ulMaxPinLen} dígitos")
        flags = token.flags2text()
        for flag, text in PIN_FLAGS.items():
            if flag in flags:
                print(f"  • {text}")

        session = lib.openSession(slot, PyKCS11.CKF_SERIAL_SESSION)  # leitura, sem login
        try:
            certs = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)])
            print(f"  certificados públicos: {len(certs)}")
            for obj in certs:
                label, value, ident = session.getAttributeValue(
                    obj, [PyKCS11.CKA_LABEL, PyKCS11.CKA_VALUE, PyKCS11.CKA_ID]
                )
                cert = x509.load_der_x509_certificate(bytes(value))
                print(f"   - {label}")
                print(f"     titular: {cert.subject.rfc4514_string()}")
                print(f"     emissor: {cert.issuer.rfc4514_string()}")
                print(f"     validade: {cert.not_valid_before_utc:%d/%m/%Y} a {cert.not_valid_after_utc:%d/%m/%Y}")
                print(f"     CKA_ID: {bytes(ident).hex()}")
            mechs = lib.getMechanismList(slot)
            wanted = [m for m in mechs if m in ("CKM_RSA_PKCS", "CKM_RSA_PKCS_PSS", "CKM_SHA256_RSA_PKCS", "CKM_ECDSA")]
            print(f"  mecanismos de assinatura relevantes: {', '.join(wanted) or 'nenhum'}")
        finally:
            session.closeSession()


if __name__ == "__main__":
    main()
