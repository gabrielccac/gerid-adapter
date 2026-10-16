"""Chave RSA do tlslite-ng cuja operação privada acontece dentro do token."""

from tlslite.utils.rsakey import RSAKey


class Pkcs11RSAKey(RSAKey):
    def __init__(self, token, key_handle, public_numbers):
        # RSAKey.__init__ é abstrato (levanta NotImplementedError); os atributos são definidos aqui.
        self.n = public_numbers.n
        self.e = public_numbers.e
        self.key_type = "rsa"
        self._key_hash = None
        self.token = token
        self.key_handle = key_handle
        self.signatures = 0

    def hasPrivateKey(self):
        return True

    def sign(self, bytes, padding="pkcs1", hashAlg=None, saltLen=None):
        # No TLS 1.2 o tlslite já entrega o DigestInfo pronto (hashAlg=None); o token aplica o padding.
        if padding.lower() != "pkcs1":
            raise ValueError(f"Esquema RSA não suportado por esta chave: {padding}")
        if hashAlg is not None:
            bytes = self.addPKCS1Prefix(bytes, hashAlg)
        self.signatures += 1
        return bytearray(self.token.sign_pkcs1(self.key_handle, bytes))

    def _rawPublicKeyOp(self, ciphertext):
        return pow(ciphertext, self.e, self.n)

    def _rawPrivateKeyOp(self, message):
        raise NotImplementedError("A chave privada fica no token; use sign().")

    def acceptsPassword(self):
        return False

    def write(self, password=None):
        raise NotImplementedError("A chave privada não sai do token.")
