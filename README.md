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
| `src/gerid_adapter/poc.py` | CLI `gerid-poc` com as etapas separadas (`check`, `pin-set`, `login`, `totp-set`, `authorize`) |
| `src/gerid_adapter/http.py`, `pages.py` | **Incompletos**: início de uma consolidação interrompida; nada os usa |
| `tests/` | Chave do token com um token falso, handshake mTLS local e vetores do RFC 6238 |
| `.local/` | Páginas, cookies e tokens capturados durante os testes. Fora do git, permissão 700 |

## Desenvolvimento

```bash
uv sync
uv run pytest
uv run python tools/inventario_token.py
```

Módulos PKCS#11 padrão do SafeSign: `libaetpkss.dylib` (macOS),
`aetpkss1.dll` (Windows) e `libaetpkss.so` (Linux).
