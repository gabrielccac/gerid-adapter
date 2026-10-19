# gerid-adapter

Prova de conceito **pausada** de autenticação no GERID (INSS/Dataprev) com
certificado ICP-Brasil A3, usando a chave do token via PKCS#11.

## Estado atual

O que foi validado manualmente, em etapas separadas:

1. Inventário do token (StarSign CUT S, driver SafeSign) via PKCS#11, sem PIN.
2. Handshake TLS 1.2 com `geridinss.dataprev.gov.br:8443`. A assinatura do
   `CertificateVerify` é feita dentro do token (`CKM_RSA_PKCS`); a chave privada
   não sai do token.
3. O CAS devolve o cookie de sessão (`TGC`) depois do login por certificado.
4. O passo OAuth do portal (`client_id=SAG`) exige o código do autenticador
   (TOTP) do GERID antes de emitir o `access_token`.

A troca do `access_token` pelo token do portal e a escolha do papel foram
observadas no JavaScript público do portal, mas **não estão implementadas
neste repositório**.

Não há comando único de login, e não há planos de wrapper da API interna do
portal. Para o uso do dia a dia, use o portal no navegador. Para pedir o PIN
menos vezes, configure o PinTimeout do SafeSign. Para acesso automatizado,
consulte o INSS e a OAB sobre canais oficiais para entidades conveniadas.

## Estrutura

| Caminho | Conteúdo |
|---|---|
| `tools/inventario_token.py` | Inventário do token, só leitura e sem login |
| `src/gerid_adapter/token.py` | Acesso PKCS#11: certificados, um único `C_Login`, assinatura. Para se o contador de PIN indicar tentativa errada |
| `src/gerid_adapter/tlskey.py` | Chave RSA do tlslite-ng com a assinatura delegada ao token |
| `src/gerid_adapter/pin.py` | Segredos no cofre do sistema (`keyring`), nunca em arquivo |
| `src/gerid_adapter/totp.py` | TOTP (RFC 6238) |
| `src/gerid_adapter/poc.py` | CLI `gerid-poc` (`check`, `pin-set`, `login`, `totp-set`, `authorize`, `session`, `ensure`, `diagnose`, `watch`, `api`) |
| `src/gerid_adapter/session.py` | Troca do `access_token` + papel e o estado do `localStorage` p/ transferir a sessão ao browser, tudo sem PIN |
| `src/gerid_adapter/recaptcha.py` | Oráculo de `tokenReCAPTCHA` (cloak headless ou seu Chrome via CDP com perfil persistente); um token por chamada |

Perfil aquecido padrão do backend `cdp`: `.local/chrome-cdp-profile/` (perfil
proprietário, fora do git via `.gitignore`, permissão 700). Primeira execução
aquece o perfil; com ele aquecido, `--browser cdp --headless` passa sem janela.

## Persistência da sessão

`gerid-poc ensure` garante sessão válida e só refaz o que expirou, sem digitar
nada (PIN e TOTP saem do cofre; o token A3 precisa estar plugado):

1. `ifs_auth` válido (> 2 min) **e vivo no servidor** (prova de vida; o `exp`
   local pode mentir — sessão derrubada no servidor renova mesmo no prazo) → reusar;
2. `access_token` fresco → só troca + papel (`session`);
3. TGC válido → `authorize` (TOTP) + troca + papel;
4. senão → `login` (PIN) + authorize + session.

Os comandos `api` renovam sozinhos antes de chamar (`--no-refresh` desliga).

## Servidor MCP (Claude)

`gerid-mcp` expõe 9 ferramentas (`gerid_diagnose`, `gerid_ensure_session`,
`gerid_list_notifications`, `gerid_search_tasks`, `gerid_get_task`,
`gerid_get_process`, `gerid_get_attachment`, `gerid_read_document`,
`gerid_list_downloads`). Documentos são salvos em `.local/downloads/` (0600)
e a ferramenta devolve a 1ª janela do **texto extraído do PDF** para o agente
analisar/resumir; `gerid_read_document` (com `nextOffset`) continua a leitura.
A sessão renova sozinha; rotas com captcha mintam um token por chamada em
browser headless.

- `gerid_get_task` devolve uma visão compacta (decisão com resultado/NB/motivo,
  interessados com idade, agendamentos, comentários em texto, anexos únicos);
  `full=true` traz o JSON bruto do portal.
- `gerid_get_process` reaproveita a cópia de até 1 h de `<protocolo>-processo.pdf`
  (`refresh=true` baixa de novo e substitui); o texto extraído fica em cache em
  `<arquivo>.text.json`, então `gerid_read_document` não reprocessa o PDF.
- Renovações são serializadas por uma trava (`.local/session.lock`) entre as
  ferramentas em paralelo e o CLI: um login A3 por vez.
- Protocolo/anexo inexistente vira erro claro ("protocolo X não encontrado").

Pré-verificação (`gerid-poc diagnose` ou `gerid_diagnose`): A3 plugado? PIN e
TOTP no cofre? O `ensure` consulta isso antes de tentar login e aborta com o
motivo (sem gastar tentativa de PIN); toda falha vira mensagem acionável em
vez de traceback, e nenhum segredo chega ao agente.

## Rede dinâmica

O login mTLS exige TCP na 8443. `gerid-poc login` sonda a porta antes de
encostar no token (sem rota → código 3, sem `C_Login` à toa); `gerid-poc
diagnose` mostra 443/8443, IP de saída e veredito; e `gerid-poc watch
[--timeout 3600] [--interval 30]` espera a porta voltar e credencia sozinho.
Códigos: 0 ok, 1 falha, 2 PIN, 3 rede.

Se a sua rede filtra a 8443, um túnel SSH resolve sem mudar o fluxo — o mTLS
termina na Dataprev e o túnel só vê bytes cifrados. O login usa a 8443 e o
`authorize` (TGC) precisa sair pelo MESMO egresso, então encaminhe as duas:

```bash
ssh -N -L 127.0.0.1:8444:geridinss.dataprev.gov.br:8443 \
       -L 127.0.0.1:8445:geridinss.dataprev.gov.br:443 usuario@servidor-fora-da-rede
GERID_TUNNEL=127.0.0.1:8444 GERID_TUNNEL_443=127.0.0.1:8445 uv run gerid-poc login
```

O usuário SSH do salto precisa de `PermitOpen` para os dois destinos (só
encaminhamento, sem shell). Sem isso, o CAS rejeita o TGC mintado por outro IP.

O arquivo `.mcp.json` na raiz já deixa o servidor pronto para o Claude Code.
Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "gerid": {
      "command": "uv",
      "args": ["run", "--directory", "/Users/jeanferreira/code/gerid-adapter", "gerid-mcp"]
    }
  }
}
```

Claude Code:

```bash
claude mcp add gerid -- uv run --directory /Users/jeanferreira/code/gerid-adapter gerid-mcp
```

Pré-requisitos na máquina do servidor: `uv sync` uma vez, token A3 plugado
e segredos no cofre (para a renovação automática). A primeira chamada com
captcha é mais lenta (sobe o browser headless).

## Variáveis de ambiente

| Variável | Efeito |
|---|---|
| `GERID_TUNNEL=127.0.0.1:8444` | Desvia a 8443 (mTLS/login) para um túnel SSH local |
| `GERID_TUNNEL_443=127.0.0.1:8445` | Desvia a 443 do GERID para o túnel (o TGC exige o mesmo egresso do login) |
| `GERID_STATE_DIR` | Troca o diretório de sessão (padrão `.local/`) |
| `INSS_BROWSER=cdp` \| `cloak` | Backend do mint de captcha (CLI padrão: `cloak` headless; MCP padrão: `cdp` headless com perfil aquecido) |
| `INSS_RECAPTCHA_KEY` | Sobrescreve a site key lida na página real (uso normal: não definir) |
| `src/gerid_adapter/api.py` | Chamadas read-only à API interna do portal com o token do GERID (tarefa, anexo, processo), por HTTP puro e sem PIN |
| `src/gerid_adapter/mcp_server.py` | Servidor MCP: 9 ferramentas sobre `session`+`api`+`docs`, com renovação e captcha automáticos |
| `src/gerid_adapter/docs.py` | Leitura local dos PDFs baixados (texto via pypdf) em janelas paginadas |
| `src/gerid_adapter/net.py` | Prova de conectividade (TCP 443/8443, IP de saída) e espera (`watch`) — sem tocar no token |
| `src/gerid_adapter/http.py` | Transporte HTTP/1.1 do tlslite-ng, usado pelo `api.py` |
| `src/gerid_adapter/pages.py` | **Incompleto**: parte da consolidação interrompida; ninguém usa |
| `tests/` | Chave do token com um token falso, handshake mTLS local, vetores do RFC 6238 e as chamadas do `api.py` |
| `.local/` | Páginas, cookies e tokens capturados durante os testes. Fora do git, permissão 700 |

## Desenvolvimento

```bash
uv sync
uv run pytest
uv run python tools/inventario_token.py
```

Módulos PKCS#11 padrão do SafeSign: `libaetpkss.dylib` (macOS),
`aetpkss1.dll` (Windows) e `libaetpkss.so` (Linux).
