"""Acesso ao token A3 via PKCS#11: certificados (sem login) e chave privada (com login)."""

import sys

import PyKCS11
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa

DEFAULT_MODULES = {
    "darwin": "/Applications/tokenadmin.app/Contents/Frameworks/libaetpkss.dylib",
    "win32": "aetpkss1.dll",
    "linux": "/usr/lib/libaetpkss.so",
}

# Qualquer um destes estados impede o login automático: errar de novo pode bloquear o token.
UNSAFE_PIN_FLAGS = {
    "CKF_USER_PIN_COUNT_LOW": "já houve tentativa de PIN errada",
    "CKF_USER_PIN_FINAL_TRY": "resta só uma tentativa de PIN",
    "CKF_USER_PIN_LOCKED": "PIN bloqueado",
    "CKF_USER_PIN_TO_BE_CHANGED": "o PIN precisa ser trocado",
}


class PinError(RuntimeError):
    """Erro de PIN: nunca deve ser repetido automaticamente."""


class Token:
    def __init__(self, module=None):
        self.module = module or DEFAULT_MODULES.get(sys.platform)
        self.lib = PyKCS11.PyKCS11Lib()
        self.lib.load(self.module)
        slots = self.lib.getSlotList(tokenPresent=True)
        if not slots:
            raise RuntimeError("Nenhum token conectado.")
        if len(slots) > 1:
            raise RuntimeError(f"Mais de um token conectado ({len(slots)}); deixe só um.")
        self.slot = slots[0]
        info = self.lib.getTokenInfo(self.slot)
        self.label = info.label.strip()
        self.serial = info.serialNumber.strip()
        self.session = self.lib.openSession(self.slot, PyKCS11.CKF_SERIAL_SESSION)
        self.logged_in = False

    def unsafe_pin_state(self):
        flags = self.lib.getTokenInfo(self.slot).flags2text()
        return [text for flag, text in UNSAFE_PIN_FLAGS.items() if flag in flags]

    def certificates(self):
        """Lista (CKA_ID, certificado) de todos os certificados do token, sem login."""
        result = []
        for obj in self.session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE)]):
            value, ident = self.session.getAttributeValue(obj, [PyKCS11.CKA_VALUE, PyKCS11.CKA_ID])
            result.append((bytes(ident), x509.load_der_x509_certificate(bytes(value))))
        return result

    def end_entity(self):
        """O certificado do titular (o único que não é de AC) e a cadeia até a raiz, sem a raiz."""
        certs = self.certificates()
        leaves = []
        for ident, cert in certs:
            try:
                ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
            except x509.ExtensionNotFound:
                ca = False
            if not ca:
                leaves.append((ident, cert))
        if len(leaves) != 1:
            raise RuntimeError(f"Esperava um certificado de titular no token, achei {len(leaves)}.")
        ident, leaf = leaves[0]
        by_subject = {cert.subject: cert for _, cert in certs}
        chain, current = [leaf], leaf
        while current.issuer != current.subject and current.issuer in by_subject:
            current = by_subject[current.issuer]
            if current.issuer != current.subject:  # a raiz não vai no handshake
                chain.append(current)
        if not isinstance(leaf.public_key(), rsa.RSAPublicKey):
            raise RuntimeError("A chave do certificado não é RSA.")
        return ident, chain

    def login(self, pin):
        """Um único C_Login. PIN errado vira PinError e não é repetido."""
        problems = self.unsafe_pin_state()
        if problems:
            raise PinError("Login automático cancelado: " + "; ".join(problems) + ".")
        try:
            self.session.login(pin, PyKCS11.CKU_USER)
        except PyKCS11.PyKCS11Error as error:
            if error.value == PyKCS11.CKR_USER_ALREADY_LOGGED_IN:
                self.logged_in = True
                return
            if error.value in (PyKCS11.CKR_PIN_INCORRECT, PyKCS11.CKR_PIN_LOCKED, PyKCS11.CKR_PIN_LEN_RANGE):
                raise PinError(
                    f"O token recusou o PIN ({PyKCS11.CKR[error.value]}). Não vou tentar de novo: "
                    "confira o PIN gravado no cofre antes da próxima execução."
                ) from None
            raise RuntimeError(
                f"O token A3 recusou a operação ({PyKCS11.CKR.get(error.value, error.value)}). "
                "Confira o token plugado e tente de novo; se persistir, desplugue e replugue."
            ) from None
        self.logged_in = True

    def private_key(self, ident):
        if not self.logged_in:
            raise RuntimeError("Faça login antes de usar a chave privada.")
        keys = self.session.findObjects(
            [(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_ID, list(ident))]
        )
        if len(keys) != 1:
            raise RuntimeError(f"Esperava uma chave privada com o CKA_ID do certificado, achei {len(keys)}.")
        return keys[0]

    def sign_pkcs1(self, key, data):
        """RSA PKCS#1 v1.5 sobre dados já no formato DigestInfo (CKM_RSA_PKCS)."""
        return bytes(self.session.sign(key, bytes(data), PyKCS11.Mechanism(PyKCS11.CKM_RSA_PKCS, None)))

    def close(self):
        try:
            if self.logged_in:
                self.session.logout()
        finally:
            self.session.closeSession()
