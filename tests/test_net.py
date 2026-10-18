"""Probes TCP com sockets locais (sem internet) + vereditos com rede falsa."""

import socket

import gerid_adapter.net as net


def test_tcp_probe_open_and_refused():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    ok, detail = net.tcp_probe("127.0.0.1", port, timeout=5)
    assert ok and detail.endswith("s")
    server.close()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        closed = probe.getsockname()[1]
    ok, detail = net.tcp_probe("127.0.0.1", closed, timeout=5)
    assert not ok and detail.startswith("ConnectionRefusedError")


def test_wait_for_port_success_and_timeout(monkeypatch):
    monkeypatch.setattr(net, "tcp_probe", lambda *a, **k: (True, "0.01s"))
    assert net.wait_for_port(timeout_total=30, interval=5) is True
    monkeypatch.setattr(net, "tcp_probe", lambda *a, **k: (False, "TimeoutError após 4.0s"))
    assert net.wait_for_port(timeout_total=0.05, interval=0.01) is False


def test_verdicts(monkeypatch):
    monkeypatch.setattr(net, "egress_ip", lambda *a, **k: "1.2.3.4")
    monkeypatch.setattr(net, "tcp_probe", lambda *a, **k: (True, "0.05s"))
    status = net.gerid_status()
    assert status["veredito"].startswith("rede ok") and status["egress_ip"] == "1.2.3.4"

    def flaky(host=net.HOST, port=net.PORT_MTLS, timeout=4.0):
        return (True, "0.05s") if port == net.PORT_TLS else (False, "TimeoutError após 4.0s")

    monkeypatch.setattr(net, "tcp_probe", flaky)
    assert "8443 filtrada" in net.gerid_status()["veredito"]
    monkeypatch.setattr(net, "tcp_probe", lambda *a, **k: (False, "TimeoutError após 4.0s"))
    assert "sem rota" in net.gerid_status()["veredito"]


def test_tcp_target_defaults_to_gerid(monkeypatch):
    from gerid_adapter import poc as poc_mod

    monkeypatch.delenv("GERID_TUNNEL", raising=False)
    assert poc_mod._tcp_target(8443) == ("geridinss.dataprev.gov.br", 8443)


def test_tcp_target_supports_tunnel(monkeypatch):
    from gerid_adapter import poc as poc_mod

    monkeypatch.setenv("GERID_TUNNEL", "127.0.0.1:8444")
    assert poc_mod._tcp_target(8443) == ("127.0.0.1", 8444)
    assert poc_mod._tcp_target(443) == ("geridinss.dataprev.gov.br", 443)
    monkeypatch.setenv("GERID_TUNNEL", "127.0.0.1")
    assert poc_mod._tcp_target(8443) == ("127.0.0.1", 8443)
    monkeypatch.setenv("GERID_TUNNEL_443", "127.0.0.1:8445")
    assert poc_mod._tcp_target(443) == ("127.0.0.1", 8445)
