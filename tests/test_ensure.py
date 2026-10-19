"""Renovação automática da sessão em cascata, com comandos falsos (sem rede)."""

import argparse
import base64
import json
import time

from gerid_adapter import poc


def jwt(exp_offset):
    exp = int(time.time()) + exp_offset
    seg = lambda o: base64.urlsafe_b64encode(json.dumps(o).encode()).decode().rstrip("=")
    return f"{seg({'alg': 'none'})}.{seg({'exp': exp})}."


def stub(monkeypatch, **effects):
    """Substitui cmd_login/cmd_authorize/cmd_session por falsos programáveis."""
    calls = []

    def make(name):
        outcomes = effects.get(name, [0])
        if not isinstance(outcomes, list):
            outcomes = [outcomes]

        def fake(args):
            calls.append(name)
            outcome = outcomes.pop(0) if outcomes else 0
            if callable(outcome):
                return outcome(args)
            return outcome

        return fake

    for name in ("cmd_login", "cmd_authorize", "cmd_session"):
        monkeypatch.setattr(poc, name, make(name))
    monkeypatch.setattr(
        poc, "diagnose",
        lambda: {"token": "T (série 1)", "pin": "ok (no cofre)", "totp": "ok (no cofre)"},
    )
    import gerid_adapter.api as api_mod

    class FakeApi:
        def __init__(self, token):
            pass

        def alive(self):
            return True

    monkeypatch.setattr(api_mod, "PortalApi", FakeApi)
    return calls


def test_expired_server_session_refreshes_despite_valid_exp(monkeypatch, tmp_path, capsys):
    (tmp_path / "ifs_auth.jwt").write_text(jwt(3600))
    (tmp_path / "oauth-fragment.txt").write_text("access_token=AT-1&expires_in=600")

    def session_ok(args):
        (tmp_path / "ifs_auth.jwt").write_text(jwt(7200))
        return 0

    import gerid_adapter.api as api_mod

    class DeadApi:
        def __init__(self, token):
            pass

        def alive(self):
            return False

    stub(monkeypatch, cmd_session=session_ok)
    monkeypatch.setattr(api_mod, "PortalApi", DeadApi)
    assert poc.ensure_session(argparse.Namespace(dir=str(tmp_path))) == 0
    assert "vencido no servidor" in capsys.readouterr().out


def test_valid_session_touches_nothing(monkeypatch, tmp_path):
    (tmp_path / "ifs_auth.jwt").write_text(jwt(3600))
    calls = stub(monkeypatch)
    assert poc.ensure_session(argparse.Namespace(dir=str(tmp_path))) == 0
    assert calls == []


def test_expired_token_renews_only_tokens(monkeypatch, tmp_path):
    (tmp_path / "ifs_auth.jwt").write_text(jwt(-10))
    (tmp_path / "oauth-fragment.txt").write_text("access_token=AT-1&expires_in=600")

    def session_ok(args):
        (tmp_path / "ifs_auth.jwt").write_text(jwt(3600))
        return 0

    calls = stub(monkeypatch, cmd_session=session_ok)
    assert poc.ensure_session(argparse.Namespace(dir=str(tmp_path))) == 0
    assert calls == ["cmd_session"]


def test_dead_access_token_falls_back_to_authorize(monkeypatch, tmp_path):
    (tmp_path / "ifs_auth.jwt").write_text(jwt(-10))
    (tmp_path / "oauth-fragment.txt").write_text("access_token=AT-velho&expires_in=600")

    def authorize_ok(args):
        (tmp_path / "oauth-fragment.txt").write_text("access_token=AT-novo&expires_in=600")
        return 0

    def session_ok(args):
        (tmp_path / "ifs_auth.jwt").write_text(jwt(3600))
        return 0

    calls = stub(monkeypatch, cmd_session=[1, session_ok], cmd_authorize=authorize_ok)
    assert poc.ensure_session(argparse.Namespace(dir=str(tmp_path))) == 0
    assert calls == ["cmd_session", "cmd_authorize", "cmd_session"]


def test_dead_tgc_falls_back_to_full_login(monkeypatch, tmp_path):
    (tmp_path / "ifs_auth.jwt").write_text(jwt(-10))
    (tmp_path / "oauth-fragment.txt").write_text("access_token=AT-velho&expires_in=600")

    def authorize_ok(args):
        (tmp_path / "oauth-fragment.txt").write_text("access_token=AT-novo&expires_in=600")
        return 0

    def session_ok(args):
        (tmp_path / "ifs_auth.jwt").write_text(jwt(3600))
        return 0

    calls = stub(
        monkeypatch, cmd_session=[1, session_ok], cmd_authorize=[0, authorize_ok], cmd_login=0
    )
    assert poc.ensure_session(argparse.Namespace(dir=str(tmp_path))) == 0
    assert calls == ["cmd_session", "cmd_authorize", "cmd_login", "cmd_authorize", "cmd_session"]


def test_login_failure_stops(monkeypatch, tmp_path):
    (tmp_path / "ifs_auth.jwt").write_text(jwt(-10))
    (tmp_path / "oauth-fragment.txt").write_text("access_token=AT-velho&expires_in=600")
    calls = stub(monkeypatch, cmd_session=1, cmd_authorize=0, cmd_login=2)
    assert poc.ensure_session(argparse.Namespace(dir=str(tmp_path))) == 1
    assert calls == ["cmd_session", "cmd_authorize", "cmd_login"]


def test_missing_everything_goes_to_full_login(monkeypatch, tmp_path):
    def authorize_ok(args):
        (tmp_path / "oauth-fragment.txt").write_text("access_token=AT-novo&expires_in=600")
        return 0

    def session_ok(args):
        (tmp_path / "ifs_auth.jwt").write_text(jwt(3600))
        return 0

    calls = stub(monkeypatch, cmd_session=session_ok, cmd_authorize=[1, authorize_ok], cmd_login=0)
    assert poc.ensure_session(argparse.Namespace(dir=str(tmp_path))) == 0
    assert "cmd_login" in calls


def test_login_preflight_blocks_dead_port(monkeypatch):
    import gerid_adapter.net as net_mod

    def explode(module=None):
        raise AssertionError("não deveria tocar no token sem rota")

    monkeypatch.setattr(net_mod, "tcp_probe", lambda *a, **k: (False, "TimeoutError após 4.0s"))
    monkeypatch.setattr(poc, "Token", explode)
    assert poc.cmd_login(argparse.Namespace(module=None, path="/cas/login")) == 3


def test_watch_runs_chain_when_port_returns(monkeypatch):
    import gerid_adapter.net as net_mod

    calls = []
    monkeypatch.setattr(net_mod, "wait_for_port", lambda **k: True)
    monkeypatch.setattr(poc, "cmd_login", lambda a: calls.append("login") or 0)
    monkeypatch.setattr(poc, "_try_authorize", lambda d: calls.append("authorize") or True)
    args = argparse.Namespace(module=None, timeout=60, interval=5)
    assert poc.cmd_watch(args) == 0
    assert calls == ["login", "authorize"]


def test_watch_gives_up_and_touches_nothing(monkeypatch):
    import gerid_adapter.net as net_mod

    calls = []
    monkeypatch.setattr(net_mod, "wait_for_port", lambda **k: False)
    monkeypatch.setattr(poc, "cmd_login", lambda a: calls.append("login") or 0)
    args = argparse.Namespace(module=None, timeout=60, interval=5)
    assert poc.cmd_watch(args) == 3
    assert calls == []


def test_artifact_freshness(tmp_path):
    target = tmp_path / "x.txt"
    assert poc._artifact_fresh(target, 600) is False
    target.write_text("x")
    assert poc._artifact_fresh(target, 600) is True
    assert poc._artifact_fresh(target, 0) is False


class FakeHardware:
    def __init__(self, label="TOKEN", serial="123", unsafe=None):
        self.label, self.serial, self._unsafe = label, serial, unsafe or []

    def unsafe_pin_state(self):
        return list(self._unsafe)

    def close(self):
        pass


def fake_hardware(monkeypatch, token=None, pin: str | Exception = "1234", totp: str | Exception = "SECRET"):
    import gerid_adapter.pin as pin_store
    import gerid_adapter.token as token_mod

    if isinstance(token, Exception):
        monkeypatch.setattr(token_mod, "Token", lambda module=None: (_ for _ in ()).throw(token))
    else:
        monkeypatch.setattr(token_mod, "Token", lambda module=None: token)
    if isinstance(pin, Exception):
        monkeypatch.setattr(pin_store, "get_pin", lambda serial: (_ for _ in ()).throw(pin))
    else:
        monkeypatch.setattr(pin_store, "get_pin", lambda serial: pin)
    if isinstance(totp, Exception):
        monkeypatch.setattr(pin_store, "get_totp_secret", lambda: (_ for _ in ()).throw(totp))
    else:
        monkeypatch.setattr(pin_store, "get_totp_secret", lambda: totp)


def test_diagnose_all_ok(monkeypatch):
    fake_hardware(monkeypatch, FakeHardware())
    monkeypatch.setattr(
        "gerid_adapter.net.gerid_status",
        lambda: {"tcp_443": "ok (0.05s)", "tcp_8443": "ok (0.05s)",
                 "egress_ip": "1.2.3.4", "veredito": "rede ok"},
    )
    state = poc.diagnose()
    assert state["token"] == "TOKEN (série 123)"
    assert state["pin"].startswith("ok") and state["totp"].startswith("ok")
    assert poc.cmd_diagnose(argparse.Namespace()) == 0


def test_diagnose_token_missing(monkeypatch):
    fake_hardware(monkeypatch, RuntimeError("Nenhum token conectado."))
    monkeypatch.setattr(
        "gerid_adapter.net.gerid_status",
        lambda: {"tcp_443": "ok (0.05s)", "tcp_8443": "ok (0.05s)",
                 "egress_ip": "1.2.3.4", "veredito": "rede ok"},
    )
    state = poc.diagnose()
    assert state["token"].startswith("ausente")
    assert poc.cmd_diagnose(argparse.Namespace()) == 1


def test_diagnose_unsafe_pin_and_missing_secrets(monkeypatch):
    fake_hardware(monkeypatch, FakeHardware(unsafe=["resta só uma tentativa de PIN"]),
                  pin=LookupError("sem pin"), totp=LookupError("sem totp"))
    monkeypatch.setattr(
        "gerid_adapter.net.gerid_status",
        lambda: {"tcp_443": "ok (0.05s)", "tcp_8443": "ok (0.05s)",
                 "egress_ip": "1.2.3.4", "veredito": "rede ok"},
    )
    state = poc.diagnose()
    assert state["pin"].startswith("inseguro")
    assert "pin-set" in state["pin"] or "inseguro" in state["pin"]
    assert "totp-set" in state["totp"]
    assert poc.cmd_diagnose(argparse.Namespace()) == 1


def test_diagnose_keyring_broken(monkeypatch):
    fake_hardware(monkeypatch, FakeHardware(), pin=RuntimeError("dbus quebrou"))
    assert poc.diagnose()["pin"].startswith("cofre")


def test_ensure_stops_when_totp_missing(monkeypatch, tmp_path, capsys):
    (tmp_path / "ifs_auth.jwt").write_text(jwt(-10))
    fake_hardware(monkeypatch, FakeHardware(), totp=LookupError("sem totp"))
    calls = stub(monkeypatch, cmd_session=1)
    assert poc.ensure_session(argparse.Namespace(dir=str(tmp_path))) == 1
    assert calls == []  # nem tenta authorize sem TOTP
    assert "TOTP" in capsys.readouterr().out


def test_ensure_reports_login_blockers(monkeypatch, tmp_path, capsys):
    (tmp_path / "ifs_auth.jwt").write_text(jwt(-10))
    (tmp_path / "oauth-fragment.txt").write_text("access_token=AT-velho&expires_in=600")
    calls = stub(monkeypatch, cmd_session=1, cmd_authorize=0)
    monkeypatch.setattr(
        poc, "diagnose",
        lambda: {"token": "T (série 1)", "pin": "inseguro: PIN bloqueado", "totp": "ok (no cofre)"},
    )
    assert poc.ensure_session(argparse.Namespace(dir=str(tmp_path))) == 1
    assert "cmd_login" not in calls  # não tenta login com PIN bloqueado
    assert "Pré-verificação" in capsys.readouterr().out


def test_concurrent_renewals_log_in_once(monkeypatch, tmp_path):
    """Duas chamadas simultâneas (ex.: ferramentas MCP em paralelo): um login só."""
    import threading

    def authorize_ok(args):
        (tmp_path / "oauth-fragment.txt").write_text("access_token=AT-novo&expires_in=600")
        return 0

    def slow_session(args):
        time.sleep(0.2)  # janela em que, sem trava, a outra thread também logaria
        (tmp_path / "ifs_auth.jwt").write_text(jwt(3600))
        return 0

    calls = stub(monkeypatch, cmd_session=slow_session, cmd_authorize=[1, authorize_ok], cmd_login=0)
    results = []
    threads = [
        threading.Thread(target=lambda: results.append(poc.ensure_session(argparse.Namespace(dir=str(tmp_path)))))
        for _ in range(2)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results == [0, 0]
    assert calls.count("cmd_login") == 1


def test_session_lock_serializes_across_processes(tmp_path):
    """A trava de arquivo também segura outro processo (MCP x CLI)."""
    import subprocess
    import sys

    child = (
        "import sys, time; from gerid_adapter import poc\n"
        "with poc.session_lock(sys.argv[1]):\n"
        "    print('in', flush=True); time.sleep(0.6)\n"
    )
    proc = subprocess.Popen([sys.executable, "-c", child, str(tmp_path)], stdout=subprocess.PIPE, text=True)
    assert proc.stdout is not None
    assert proc.stdout.readline().strip() == "in"
    start = time.monotonic()
    with poc.session_lock(tmp_path):
        waited = time.monotonic() - start
    proc.wait(timeout=5)
    assert waited >= 0.3
