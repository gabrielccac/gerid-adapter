"""Teste de mint+POST fora da máquina local (VPS): valida as duas incógnitas do desacoplamento.

1. Score do IP do datacenter no reCAPTCHA Enterprise (mint headed via Chrome).
2. Binding `auth-ip` do ifs_auth: a SPA e o POST saindo de IP diferente do login.

Setup (Ubuntu/Debian):
    apt-get update && apt-get install -y xvfb chromium-browser git curl
    curl -LsSf https://astral.sh/uv/install.sh | sh
    git clone <repo> gerid-adapter && cd gerid-adapter && uv sync

Estado (nesta máquina, antes de copiar):
    scp -r .local usuario@vps:gerid-adapter/.local    # portal-session.json + ifs_auth.jwt

Rodar na VPS (headed precisa de display virtual no Linux):
    xvfb-run -a uv run python tools/vps_mint_test.py

Saída: JSON por etapa (egress_ip, mint, POST) — 200 = serviço de tokens viável ali.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from gerid_adapter import net as netprobe
from gerid_adapter import recaptcha as R
from gerid_adapter.api import PortalApi, jwt_claims, load_token, seconds_left
from gerid_adapter.session import js_now, read_state

STATE = Path(__file__).resolve().parents[1] / ".local" / "portal-session.json"


def main():
    out = {}
    net = netprobe.gerid_status()
    out["egress_ip"] = net.get("egress_ip")
    out["rede"] = {"tcp_443": net.get("tcp_443"), "tcp_8443": net.get("tcp_8443")}

    token = load_token()
    claims = jwt_claims(token)
    out["token"] = {
        "valid_min": seconds_left(token) // 60,
        "auth_ip_do_login": claims.get("auth-ip"),
        "egress_diferente_do_login": claims.get("auth-ip") not in (None, out["egress_ip"]),
    }

    state = read_state(STATE)
    state["ifs_ts"] = state["ifs_iat"] = js_now()
    try:
        captcha = R.mint(state, backend_name="cdp-headed")
        out["mint"] = {"ok": True, "len": len(captcha)}
    except Exception as error:
        out["mint"] = {"ok": False, "error": f"{type(error).__name__}: {str(error)[:200]}"}
        print(json.dumps(out, ensure_ascii=False, indent=2))
        return 1

    try:
        data = PortalApi(token).notifications(captcha, first=0)
        out["POST"] = {"status": 200, "total": data.get("total") if isinstance(data, dict) else None}
    except Exception as error:
        out["POST"] = {"status": getattr(error, "status", None), "error": str(error)[:200]}

    R._close_persistent()
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0 if out.get("POST", {}).get("status") == 200 else 1


if __name__ == "__main__":
    raise SystemExit(main())
