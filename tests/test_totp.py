import base64

import pytest

from gerid_adapter.totp import code, normalize_secret

# Vetores do RFC 6238 (SHA-1, segredo ASCII "12345678901234567890").
RFC_SECRET = base64.b32encode(b"12345678901234567890").decode().rstrip("=")


@pytest.mark.parametrize(
    ("at", "expected"),
    [(59, "94287082"), (1111111109, "07081804"), (1234567890, "89005924"), (2000000000, "69279037")],
)
def test_rfc6238_vectors(at, expected):
    assert code(RFC_SECRET, at=at, digits=8) == expected


def test_normalize_accepts_otpauth_and_spaces():
    assert normalize_secret(f"otpauth://totp/GERID:x?secret={RFC_SECRET}&issuer=GERID") == RFC_SECRET
    spaced = " ".join(RFC_SECRET[i : i + 4] for i in range(0, len(RFC_SECRET), 4)).lower()
    assert normalize_secret(spaced) == RFC_SECRET


def test_normalize_rejects_garbage():
    with pytest.raises(ValueError):
        normalize_secret("isto-nao-e-base32-1890")
