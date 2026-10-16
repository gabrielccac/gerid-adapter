"""Handshake mTLS completo (TLS 1.2, troca RSA como no GERID) com a chave "do token" em software."""

import datetime
import socket
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat
from cryptography.x509.oid import NameOID
from tlslite import HandshakeSettings, TLSConnection
from tlslite.utils.keyfactory import parsePEMKey

from gerid_adapter.poc import settings, tlslite_cert, to_tlslite_chain
from gerid_adapter.tlskey import Pkcs11RSAKey
from tests.test_tlskey import FakeToken


def self_signed(name):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    pem = key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()).decode()
    return cert, parsePEMKey(pem, private=True)


def test_mutual_tls_with_token_key():
    server_cert, server_key = self_signed("servidor")
    client_cert, client_soft_key = self_signed("titular")
    client_key = Pkcs11RSAKey(FakeToken(client_soft_key), "handle", client_cert.public_key().public_numbers())

    server_sock, client_sock = socket.socketpair()
    seen = {}

    def serve():
        conn = TLSConnection(server_sock)
        server_settings = HandshakeSettings()
        server_settings.minVersion = server_settings.maxVersion = (3, 3)
        server_settings.keyExchangeNames = ["rsa"]  # igual ao GERID: TLS_RSA_WITH_AES_256_GCM_SHA384
        conn.handshakeServer(
            certChain=to_tlslite_chain([server_cert]),
            privateKey=server_key,
            reqCert=True,
            settings=server_settings,
        )
        seen["client_chain"] = conn.session.clientCertChain
        conn.write(conn.read())
        conn.close()

    thread = threading.Thread(target=serve)
    thread.start()
    client = TLSConnection(client_sock)
    client.handshakeClientCert(to_tlslite_chain([client_cert]), client_key, settings=settings())
    client.write(b"ping")
    assert bytes(client.read()) == b"ping"
    client.close()
    thread.join(timeout=10)

    assert client_key.signatures == 1
    assert seen["client_chain"].getFingerprint() == tlslite_cert(client_cert).getFingerprint()
