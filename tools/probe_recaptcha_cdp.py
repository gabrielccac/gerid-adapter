"""Compara dois POSTs de leitura na mesma sessão. Imprime somente etapas e status."""

import argparse
import json
import subprocess
from unittest.mock import patch

from gerid_adapter import mcp_server, recaptcha
from gerid_adapter.api import PortalApi, impersonated_post_json, seconds_left
from gerid_adapter.session import js_now


def compare(state, token, headless=False):
    original_execute = recaptcha._execute_token

    def compare_on_page(page, key, action):
        if page.url.split("?", 1)[0].split("#", 1)[0] != recaptcha.TASKS_URL:
            raise RuntimeError("unexpected_page")

        results = {}
        captured = {}

        def record_post(url, payload, headers):
            response = impersonated_post_json(url, payload, headers)
            captured["status"] = response.status
            return response

        for mode in ("curl_cffi", "browser_fetch"):
            stage = "token"
            try:
                captcha = original_execute(page, key, action)
                if not isinstance(captcha, str) or not captcha:
                    results[mode] = {"stage": stage, "error": "empty_token"}
                    continue
                stage = "post"
                if mode == "curl_cffi":
                    PortalApi(token, poster=record_post).notifications(captcha, first=0)
                    status = captured["status"]
                else:
                    status = page.evaluate(
                        """async ({captcha, origin}) => {
                            if (location.origin !== origin || location.pathname !== '/tarefas') {
                                throw new Error('unexpected_page');
                            }
                            const bearer = localStorage.getItem('ifs_auth');
                            if (!bearer) throw new Error('missing_session');
                            const response = await fetch(
                                '/apis/requerimentosPortalApi/requerimento/ec/notificacao?first=0', {
                                    method: 'POST', redirect: 'error', credentials: 'same-origin',
                                    signal: AbortSignal.timeout(20000),
                                    headers: {
                                        Authorization: 'Bearer ' + bearer,
                                        Accept: 'application/json',
                                        'Content-Type': 'application/json'
                                    },
                                    body: JSON.stringify({tokenReCAPTCHA: captcha})
                                }
                            );
                            return response.status;
                        }""",
                        {"captcha": captcha, "origin": recaptcha.PORTAL},
                    )
                results[mode] = {"http": status}
            except Exception as error:
                if mode == "curl_cffi" and "status" in captured:
                    results[mode] = {"http": captured["status"]}
                else:
                    results[mode] = {"stage": stage, "error": type(error).__name__}
        return results

    with patch.object(recaptcha, "_execute_token", compare_on_page):
        return recaptcha.mint(state, backend_name="cdp", headless=headless, timeout_ms=20000)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--open-profile", action="store_true", help="Abre o perfil dedicado para login manual.")
    parser.add_argument("--headless", action="store_true", help="Abre o Chrome via CDP sem janela.")
    args = parser.parse_args()
    if args.open_profile:
        try:
            return subprocess.call([
                recaptcha.chrome_executable(),
                f"--user-data-dir={recaptcha.DEFAULT_CDP_PROFILE}",
                "--no-first-run",
                recaptcha.TASKS_URL,
            ])
        except (OSError, RuntimeError) as error:
            print(json.dumps({"stage": "open_profile", "error": type(error).__name__}))
            return 2
    if not recaptcha.DEFAULT_CDP_PROFILE.is_dir():
        print(json.dumps({"error": "cdp_profile_missing", "profile": str(recaptcha.DEFAULT_CDP_PROFILE)}))
        return 2

    try:
        state = mcp_server._session_state(mcp_server._state_dir())
        token = mcp_server._load_token()
        if state.get("ifs_auth") != token:
            print(json.dumps({"error": "session_token_mismatch"}))
            return 2
        if seconds_left(token) < 120:
            print(json.dumps({"error": "session_needs_refresh"}))
            return 2
    except Exception as error:
        print(json.dumps({"stage": "session", "error": type(error).__name__}))
        return 2

    state["ifs_ts"] = state["ifs_iat"] = js_now()
    try:
        print(json.dumps(compare(state, token, args.headless)))
    except Exception as error:
        print(json.dumps({"stage": "browser", "error": type(error).__name__}))
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
