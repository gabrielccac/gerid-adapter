"""Prova de conectividade com o GERID (só rede, sem tocar no token A3).

O login mTLS exige TCP na porta 8443; quando ela está filtrada, a tentativa
só estoura timeout depois de mexer no token à toa. Estes probes falham rápido
(~segundos) e dizem onde: DNS, rota, porta ou borda da Dataprev.
"""

import socket
import time

HOST = "geridinss.dataprev.gov.br"
PORT_TLS = 443
PORT_MTLS = 8443
PROBE_TIMEOUT = 4.0


def tcp_probe(host=HOST, port=PORT_MTLS, timeout=PROBE_TIMEOUT):
    """(ok, detalhe): True com o RTT; senão o tipo do erro e o tempo.

    SYN descartado (filtragem silenciosa) aparece como timeout cheio;
    porta fechada normal responderia "refused" em milissegundos.
    """
    start = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except Exception as error:
        return False, f"{type(error).__name__} após {time.monotonic() - start:.1f}s"
    elapsed = time.monotonic() - start
    try:
        sock.close()
    except Exception:
        pass
    return True, f"{elapsed:.2f}s"


def egress_ip(timeout=5):
    """IP público de saída (ou None sem internet). Só informa, nunca autentica."""
    import urllib.request

    try:
        with urllib.request.urlopen("https://api.ipify.org", timeout=timeout) as response:
            text = response.read().decode().strip()
            return text or None
    except Exception:
        return None


def gerid_status(timeout=PROBE_TIMEOUT):
    """Estado da rota até o GERID + veredito legível."""
    ok_tls, detail_tls = tcp_probe(HOST, PORT_TLS, timeout)
    ok_mtls, detail_mtls = tcp_probe(HOST, PORT_MTLS, timeout)
    if ok_tls and ok_mtls:
        verdict = "rede ok: 443 e 8443 respondem"
    elif ok_tls and not ok_mtls:
        verdict = (
            f"porta 8443 filtrada ({detail_mtls}); a 443 funciona, então não é "
            "DNS nem código: filtragem no caminho ou instabilidade na borda da Dataprev"
        )
    elif not ok_tls and not ok_mtls:
        verdict = f"sem rota para o GERID (443: {detail_tls}; 8443: {detail_mtls})"
    else:
        verdict = f"estado incomum (443: {detail_tls}; 8443: {detail_mtls})"
    return {
        "tcp_443": f"ok ({detail_tls})" if ok_tls else f"falhou ({detail_tls})",
        "tcp_8443": f"ok ({detail_mtls})" if ok_mtls else f"falhou ({detail_mtls})",
        "egress_ip": egress_ip(),
        "veredito": verdict,
    }


def wait_for_port(port=PORT_MTLS, timeout_total=3600, interval=30):
    """Bloqueia até a porta responder ou estourar o tempo. Não toca no token."""
    deadline = time.monotonic() + timeout_total
    while True:
        ok, _ = tcp_probe(HOST, port, timeout=min(PROBE_TIMEOUT, max(1.0, deadline - time.monotonic())))
        if ok:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(interval, remaining))
