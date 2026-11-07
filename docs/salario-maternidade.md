# Salário-Maternidade Urbano no GERID

O comando local `gerid-sm` usa a sessão do `gerid-adapter` e o serviço TSMU, ID 1675. O piloto cobre parto com certidão de nascimento, entrada pelo GERID de entidade conveniada e inclusão de advogado pessoa física após o protocolo. Valide com um caso autorizado antes de adotar o fluxo.

## Como o agente prepara um caso

Crie uma pasta privada com um JSON e os documentos do caso. Gere um UUID para `caso_id` uma única vez e preserve-o nas revisões. Use os documentos para preencher dados factuais. Peça à pessoa responsável para confirmar as declarações de categoria e afastamento, os dados do advogado, as escolhas de unidade e pagador e a opção de acompanhamento.

Modelo com valores fictícios. Preencha as opções e os IDs com os valores oferecidos pelo GERID.

```json
{
  "caso_id": "2e0b6446-8191-4a52-9c27-162a75ba078a",
  "cpf": "01234567890",
  "nascimento": {
    "matricula": "00000000000000000000000000000000",
    "dataNascimento": "2025-01-01",
    "dataLavratura": "2025-01-02"
  },
  "respostas": {},
  "uf": "SP",
  "municipio": "São Paulo",
  "telefoneCelular": "11900000000",
  "acompanharAndamentoProcesso": true,
  "anexos": [
    {"arquivo": "representacao.pdf", "definicao": 1427},
    {"arquivo": "certidao.pdf", "definicao": 1432}
  ],
  "advogado": {"nome": "Advogada de Teste", "cpf": "12345678900"}
}
```

- Use a matrícula da certidão com 32 dígitos e datas no formato `AAAA-MM-DD`. Use os CPFs com 11 dígitos.
- Em `respostas`, confirme `CategReq` e `AfastApDIB` com as opções devolvidas pelo preparo. Informe `MtRescisao` quando a categoria for desempregada com último vínculo em carteira. O cenário de parto com certidão define `FatoGerad` e `TemCertid`.
- Pode informar `idMunicipio` do GERID em vez de `uf` e `municipio`. A primeira execução com as declarações completas devolve as unidades se faltar `idLocal`. Com a unidade selecionada, o preparo devolve os órgãos autorizados se faltar `idOrgaoPagador`.
- Informe pelo menos `email` ou `telefoneCelular`. Use caminhos relativos à pasta do JSON e associe cada documento à sua definição no GERID. Os IDs no exemplo vêm da captura e são conferidos a cada preparo.

```powershell
uv run gerid-sm --dir "C:\caminho\sessao-gerid" preparar "C:\caminho\caso\caso.json"
```

Sem `--dir`, o comando usa o mesmo diretório de sessão padrão do adaptador. `preparar` devolve JSON. Se faltarem informações, retorna `estado: revisar` com pendências e opções quando disponíveis. Se o GERID aceitar as validações, retorna `estado: preparado`, avisos, resumo, hashes dos anexos e a `confirmacao`. Revise os avisos e os documentos antes de aprovar. Guarde o JSON do caso e os documentos em uma pasta privada, fora do repositório.

## Protocolo após aprovação

Execute somente após a pessoa responsável aprovar o preparo e os documentos da versão apresentada.

```powershell
uv run gerid-sm --dir "C:\caminho\sessao-gerid" protocolar "C:\caminho\caso\caso.json" --confirmar CODIGO_DO_PREPARO
```

O comando confere a confirmação e revalida o preparo. Após gravar o protocolo, confere a tarefa no GERID, inclui o advogado pelo endpoint de procuradores e salva o comprovante. O JSON final traz `protocolo`, `advogado_incluido` e `comprovante`. O estado `protocolado` indica que há alguma etapa posterior pendente. Repetir o comando com a mesma versão retoma a conferência ou o comprovante a partir do protocolo registrado.

Se o envio ficar indeterminado, o comando consulta `requerimento/recuperar` e apresenta o protocolo candidato quando houver. Depois de conferir o pedido no portal, execute o comando de reconciliação.

```powershell
uv run gerid-sm --dir "C:\caminho\sessao-gerid" reconciliar "C:\caminho\caso\caso.json" --confirmar CODIGO_DO_PREPARO --protocolo PROTOCOLO_CONFERIDO
```

A reconciliação exige que o GERID retorne esse mesmo protocolo e que o detalhe confira com a requerente e o serviço. Uma tentativa de inclusão de advogado com resultado incerto é verificada pela lista de procuradores da tarefa. Se continuar incerta, confira no GERID. Preserve o diretório de sessão e o UUID do caso para manter o controle contra duplicidade.

## Evidência e validação

O HAR confirmou as rotas de catálogo, campos, localização, órgão pagador, protocolo, detalhe, procurador e comprovante. Os JSONs de validação adicional e envio foram reconstruídos a partir do JavaScript do portal. Os HARs omitem os dois corpos grandes e a autenticação. O comando usa o Bearer do adaptador e aceita `GERID_TOKEN_SERVIDOR` no ambiente quando a sessão também exigir esse cabeçalho. O comportamento dessas rotas com a sessão e o payload reais ainda precisa ser verificado.

Execute a suíte offline com `uv run --locked pytest -q`. Para validar no GERID, comece por `preparar` e confira o retorno. Use um caso autorizado para testar `protocolar`, que cria um requerimento real e inclui o advogado.
