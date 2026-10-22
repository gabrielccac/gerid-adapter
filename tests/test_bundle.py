"""Pacote de credenciais: ida e volta, senha errada, export a partir de customers/ e import no cofre."""

import io
import os

import pytest

from gerid_adapter import bundle, poc

SECRET = "JBSWY3DPEHPK3PXP"


def test_round_trip_and_wrong_passphrase():
    text = bundle.seal({"A": "1"}, "senha-bem-longa", customer="victor")
    assert "senha-bem-longa" not in text and '"1"' not in text
    assert bundle.unseal(text, "senha-bem-longa") == {"customer": "victor", "env": {"A": "1"}}
    with pytest.raises(ValueError, match="incorreta"):
        bundle.unseal(text, "outra-senha-longa")
    with pytest.raises(ValueError, match="não é um pacote"):
        bundle.unseal('{"format": "x"}', "senha-bem-longa")


def test_short_passphrase_refused():
    with pytest.raises(ValueError):
        bundle.seal({}, "curta")


def customer(monkeypatch, tmp_path, pin):
    (tmp_path / "victor").mkdir()
    (tmp_path / "victor" / ".env").write_text(
        f"# comentário\nGERID_TOTP_SECRET={SECRET}\nGERID_A3_PIN={pin}\n", encoding="utf-8"
    )
    monkeypatch.setattr(bundle, "CUSTOMERS_DIR", tmp_path)


def test_export_refuses_empty_pin(monkeypatch, tmp_path, capsys):
    customer(monkeypatch, tmp_path, "")
    args = poc.argparse.Namespace(customer="victor", out=str(tmp_path / "v.gerid"))
    assert poc.cmd_export(args) == 1
    assert "GERID_A3_PIN" in capsys.readouterr().out
    assert not (tmp_path / "v.gerid").exists()


class FakeToken:
    serial = "SERIE1"

    def __init__(self, module=None):
        pass

    def unsafe_pin_state(self):
        return []

    def close(self):
        pass


def test_export_then_import_writes_vault(monkeypatch, tmp_path, capsys):
    customer(monkeypatch, tmp_path, "1234")
    out = tmp_path / "v.gerid"
    assert poc.cmd_export(poc.argparse.Namespace(customer="victor", out=str(out))) == 0
    printed = capsys.readouterr().out
    passphrase = printed.rsplit(": ", 1)[1].strip()
    assert os.name == "nt" or (out.stat().st_mode & 0o777) == 0o600  # Windows não tem modo Unix
    assert "1234" not in out.read_text() and SECRET not in out.read_text()

    vault = {}
    monkeypatch.setattr(poc, "Token", FakeToken)
    monkeypatch.setattr(poc.pin_store, "set_pin", lambda serial, pin: vault.update({f"pin:{serial}": pin}))
    monkeypatch.setattr(poc.pin_store, "set_totp_secret", lambda secret: vault.update(totp=secret))
    monkeypatch.setattr("sys.stdin", io.StringIO(passphrase + "\n"))
    args = poc.argparse.Namespace(bundle=str(out), passphrase_stdin=True, terminal=False, module=None)
    assert poc.cmd_import(args) == 0
    assert vault == {"pin:SERIE1": "1234", "totp": SECRET}
    assert "1234" not in capsys.readouterr().out


def test_import_wrong_passphrase_writes_nothing(monkeypatch, tmp_path, capsys):
    out = tmp_path / "v.gerid"
    out.write_text(bundle.seal({"GERID_TOTP_SECRET": SECRET, "GERID_A3_PIN": "1"}, "senha-bem-longa"))
    monkeypatch.setattr(poc, "Token", lambda module=None: pytest.fail("não deve tocar no token"))
    monkeypatch.setattr("sys.stdin", io.StringIO("errada-errada-errada\n"))
    args = poc.argparse.Namespace(bundle=str(out), passphrase_stdin=True, terminal=False, module=None)
    assert poc.cmd_import(args) == 1
    assert "Não instalei nada" in capsys.readouterr().out
