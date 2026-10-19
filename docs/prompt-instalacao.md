# Prompt de instalação do gerid-adapter no computador do cliente

Cole o bloco abaixo no Claude Code **no computador do cliente** (o mesmo onde o
token A3 fica plugado). Troque `<CLIENTE>` pelo nome do cliente. O prompt não
leva segredo nenhum: o PIN e o QR são colocados pelo próprio cliente (ou por
você, na máquina dele) no fim, direto no `.env`.

---

```text
Instale o gerid-adapter (MCP do GERID/INSS) neste computador para o cliente <CLIENTE>.
Ele usa o certificado A3 plugado aqui, então precisa rodar nesta máquina.

Regras de segurança:
- NUNCA me peça, leia, imprima ou repita o PIN do token nem o segredo TOTP do GERID.
  Eles ficam só no arquivo .env, que eu mesmo preencho. Não rode `cat .env`.
- Não faça commit do .env nem da imagem do QR.
- Não rode `gerid-poc login` nem `ensure` antes de `diagnose` mostrar PIN e TOTP ok:
  cada PIN errado gasta uma tentativa do token.

Passos:
1. Detecte o sistema (macOS, Windows ou Linux) e adapte os comandos.
2. Dependências: instale o que faltar e me diga o que instalou.
   - git e uv (https://docs.astral.sh/uv/);
   - Google Chrome (usado em segundo plano para o captcha do portal);
   - middleware do token A3 (SafeSign / tokenadmin). Confira se a biblioteca existe:
     macOS /Applications/tokenadmin.app/Contents/Frameworks/libaetpkss.dylib,
     Windows aetpkss1.dll, Linux /usr/lib/libaetpkss.so. Se o token for de outro
     fabricante, me avise: vai ser preciso passar --module com a biblioteca dele.
3. Clone https://github.com/gabrielccac/gerid-adapter numa pasta fixa
   (ex.: ~/code/gerid-adapter) e rode `uv sync` dentro dela.
4. Crie o arquivo de segredos sem preencher:
   `cp .env.example .env` e `chmod 600 .env` (no Windows, restrinja ao usuário atual).
5. PARE e me peça para:
   a) abrir o .env num editor e preencher GERID_PIN com o PIN do token;
   b) salvar a imagem do QR do autenticador do GERID nesta máquina.
   Espere eu confirmar.
6. Com o caminho da imagem que eu informar, rode
   `uv run gerid-poc totp-import <imagem>` (grava GERID_TOTP_SECRET no .env sem exibir)
   e me mostre o resultado do totp-check para eu comparar com o app autenticador.
   Depois que eu confirmar, apague a imagem do QR.
7. Com o token plugado, rode `uv run gerid-poc diagnose`. Tudo precisa sair ok:
   token, PIN, TOTP e rede (porta 8443). Se a 8443 estiver bloqueada, me mostre o
   veredito e a seção "Rede dinâmica" do README; não tente contornar sozinho.
8. Rode `uv run gerid-poc ensure` para o primeiro login e confirme "Sessão renovada"
   ou "Sessão válida".
9. Registre o MCP com o caminho absoluto da pasta:
   - Claude Code: `claude mcp add gerid -- uv run --directory <PASTA> gerid-mcp`
   - Claude Desktop: em claude_desktop_config.json, servidor "gerid" com
     command "uv" e args ["run", "--directory", "<PASTA>", "gerid-mcp"].
10. Reinicie o Claude e teste chamando `gerid_diagnose` e depois
    `gerid_list_notifications`. Me mostre um resumo do resultado.
```
