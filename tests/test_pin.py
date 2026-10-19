import pytest

from gerid_adapter import pin as pin_store

SECRET = "JBSWY3DPEHPK3PXP"


@pytest.fixture
def env_file(tmp_path, monkeypatch):
    path = tmp_path / ".env"
    monkeypatch.setenv("GERID_ENV_FILE", str(path))
    monkeypatch.delenv("GERID_PIN", raising=False)
    monkeypatch.delenv("GERID_TOTP_SECRET", raising=False)
    return path


def test_reads_pin_and_secret_from_env_file(env_file):
    env_file.write_text(
        f'# comentário\nexport GERID_PIN="1234"\nGERID_TOTP_SECRET=otpauth://totp/GERID?secret={SECRET.lower()}&issuer=x\n'
    )
    assert pin_store.get_pin("serie") == "1234"
    assert pin_store.get_totp_secret() == SECRET


def test_environment_wins_over_file(env_file, monkeypatch):
    env_file.write_text("GERID_PIN=1111\n")
    monkeypatch.setenv("GERID_PIN", "2222")
    assert pin_store.get_pin() == "2222"


def test_missing_values_are_lookup_errors(env_file):
    with pytest.raises(LookupError, match="GERID_PIN"):
        pin_store.get_pin()
    env_file.write_text("GERID_PIN=\nGERID_TOTP_SECRET=não-é-base32\n")
    with pytest.raises(LookupError, match="GERID_PIN"):
        pin_store.get_pin()
    with pytest.raises(LookupError, match="inválido"):
        pin_store.get_totp_secret()


def test_save_totp_secret_replaces_only_that_line(env_file):
    env_file.write_text("GERID_PIN=1234\nGERID_TOTP_SECRET=OLD\n# GERID_TOTP_SECRET=comentario\n")
    pin_store.save_totp_secret(SECRET)
    text = env_file.read_text()
    assert text == f"GERID_PIN=1234\nGERID_TOTP_SECRET={SECRET}\n# GERID_TOTP_SECRET=comentario\n"
    assert env_file.stat().st_mode & 0o777 == 0o600
    assert pin_store.get_totp_secret() == SECRET


def test_secret_from_qr_image(tmp_path):
    zxingcpp = pytest.importorskip("zxingcpp")
    from PIL import Image

    uri = f"otpauth://totp/GERID:teste?secret={SECRET}&issuer=GERID"
    matrix = zxingcpp.create_barcode(uri, zxingcpp.BarcodeFormat.QRCode).to_image(scale=8)
    image = tmp_path / "qr.png"
    height, width = matrix.shape[:2]
    Image.frombytes("L", (width, height), bytes(memoryview(matrix))).save(image)
    assert pin_store.secret_from_qr(image) == SECRET
