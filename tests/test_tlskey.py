"""A chave do token assina como uma chave RSA comum (com um token falso em software)."""

from tlslite.utils.keyfactory import generateRSAKey
from tlslite.utils.rsakey import RSAKey

from gerid_adapter.tlskey import Pkcs11RSAKey


class FakeToken:
    """Faz o papel de CKM_RSA_PKCS: aplica o padding PKCS#1 e assina com a chave em software."""

    def __init__(self, soft_key):
        self.soft_key = soft_key

    def sign_pkcs1(self, key_handle, data):
        return bytes(self.soft_key._raw_pkcs1_sign(bytearray(data)))


class Numbers:
    def __init__(self, n, e):
        self.n, self.e = n, e


def make_key():
    soft = generateRSAKey(2048)
    return soft, Pkcs11RSAKey(FakeToken(soft), "handle", Numbers(soft.n, soft.e))


def test_tls12_digestinfo_signature_verifies():
    soft, key = make_key()
    digest_info = RSAKey.addPKCS1Prefix(bytearray(b"\x11" * 32), "sha256")
    signature = key.sign(digest_info)  # como o tlslite chama no CertificateVerify do TLS 1.2
    assert soft.verify(signature, digest_info)
    assert key.verify(signature, digest_info)
    assert key.signatures == 1


def test_hash_prefix_is_added_when_hash_name_given():
    soft, key = make_key()
    digest = bytearray(b"\x22" * 32)
    signature = key.sign(digest, "pkcs1", "sha256")
    assert soft.verify(signature, digest, "pkcs1", "sha256")


def test_pss_is_refused():
    _, key = make_key()
    try:
        key.sign(bytearray(32), "pss", "sha256", 32)
    except ValueError:
        return
    raise AssertionError("PSS deveria ser recusado")
