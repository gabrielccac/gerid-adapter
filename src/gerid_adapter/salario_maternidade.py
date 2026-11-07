"""Preparação e protocolo do TSMU por parto com certidão no GERID."""

import base64
import hashlib
import json
import unicodedata
from datetime import date, datetime, timezone
from functools import partial
from pathlib import Path
from urllib.parse import urlencode
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from gerid_adapter.api import ApiError, PortalApi
from gerid_adapter.http import impersonated_post_json

BASE = "/apis/requerimentosPortalApi/requerimento"
CADASTRO = BASE + "/cadastro"
TSMU = 1675
MIB = 1024 * 1024
MARCAS = {
    "pdf": b"%PDF-", "jpg": b"\xff\xd8\xff", "jpeg": b"\xff\xd8\xff",
    "png": b"\x89PNG\r\n\x1a\n", "bmp": b"BM",
}
DESEMPREGADA = "desempregada (último vínculo com carteira assinada)"
DECLARACOES = ("CategReq", "AfastApDIB")
MAX_TOTAL = 50 * MIB


class Entrada(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class Nascimento(Entrada):
    matricula: str = Field(pattern=r"^[0-9]{32}$")
    dataNascimento: date
    dataLavratura: date


class Advogado(Entrada):
    cpf: str = Field(pattern=r"^[0-9]{11}$")
    nome: str = Field(min_length=3, max_length=150)


class Anexo(Entrada):
    arquivo: str = Field(min_length=1)
    definicao: int = Field(gt=0)


class Caso(Entrada):
    caso_id: UUID
    cpf: str | None = Field(default=None, pattern=r"^[0-9]{11}$")
    nascimento: Nascimento | None = None
    respostas: dict[str, str] = Field(default_factory=dict)
    idMunicipio: int | None = Field(default=None, gt=0)
    uf: str | None = Field(default=None, pattern=r"^[A-Z]{2}$")
    municipio: str | None = Field(default=None, min_length=2, max_length=100)
    idLocal: int | None = Field(default=None, gt=0)
    idOrgaoPagador: int | None = Field(default=None, gt=0)
    email: str | None = Field(default=None, pattern=r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
    telefoneCelular: str | None = Field(default=None, pattern=r"^[0-9]{10,11}$")
    acompanharAndamentoProcesso: bool | None = Field(default=None, strict=True)
    anexos: list[Anexo] = Field(default_factory=list, max_length=50)
    advogado: Advogado | None = None


class Pendencias(ValueError):
    def __init__(self, itens, **dados):
        super().__init__("Preparação incompleta.")
        self.resultado = {"estado": "revisar", "pendencias": itens, **dados}


class ErroPortal(RuntimeError):
    def __init__(self, etapa, status=None):
        super().__init__(etapa)
        self.etapa, self.status = etapa, status


class SalarioMaternidadeApi(PortalApi):
    def __init__(self, token, *, token_servidor=None, transport=None, poster=None):
        super().__init__(token, transport=transport, poster=poster or partial(
            impersonated_post_json, timeout=90, allow_redirects=False))
        self.token_servidor = token_servidor

    def _headers(self):
        headers = super()._headers()
        if self.token_servidor:
            headers["tokenServidor"] = self.token_servidor
        return headers

    def ler(self, etapa, caminho, query=None, *, pdf=False):
        try:
            resposta = self._get(caminho, query)
            if resposta is None:
                return None
            return resposta.body if pdf else json.loads(resposta.body)
        except (ApiError, RuntimeError, OSError, ValueError) as exc:
            raise ErroPortal(etapa, getattr(exc, "status", None)) from None

    def enviar(self, etapa, caminho, dados, query=None):
        rota = caminho + ("?" + urlencode(query) if query else "")
        try:
            return self._post_json(rota, dados)
        except (ApiError, RuntimeError, OSError, ValueError) as exc:
            raise ErroPortal(etapa, getattr(exc, "status", None)) from None

    def recuperar(self, dados):
        resposta = self.enviar("recuperar", CADASTRO + "/requerimento/recuperar",
                               dados, {"simples": "false"})
        return resposta or {}

    def tarefa(self, protocolo):
        return self.ler("tarefa", BASE + f"/ec/tarefa/{protocolo}")

    def comprovante(self, protocolo, cpf):
        return self.ler("comprovante", "/apis/consolidadorECApi/comprovante-interessado",
                        {"protocolo": protocolo, "cpf": int(cpf), "sistema": "PAT"}, pdf=True)


def digest(dados):
    raw = json.dumps(dados, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def arquivos_locais(caso, pasta):
    arquivos, erros, vistos, total = [], [], set(), 0
    for anexo in caso.anexos:
        origem = Path(anexo.arquivo)
        path = (pasta / origem).resolve()
        nome, ext = path.name, path.suffix.lstrip(".").lower()
        if (origem.is_absolute() or not path.is_relative_to(pasta) or not nome
                or any(ord(c) < 32 for c in nome) or len(nome) > 90 or nome.casefold() in vistos):
            erros.append("Use anexos com nomes únicos, dentro da pasta do caso.")
            continue
        if ext not in MARCAS:
            erros.append(f"Formato de anexo não suportado: {nome}.")
            continue
        try:
            if not path.is_file():
                raise OSError
            with path.open("rb") as file:
                raw = file.read(5 * MIB + 1)
        except OSError:
            erros.append(f"Anexo indisponível: {nome}.")
            continue
        if not raw.startswith(MARCAS[ext]) or len(raw) > 5 * MIB or total + len(raw) > MAX_TOTAL:
            erros.append(f"Anexo inválido ou acima do limite de tamanho: {nome}.")
            continue
        vistos.add(nome.casefold())
        total += len(raw)
        arquivos.append((anexo.definicao, nome, raw))
    return arquivos, erros


def entrada(caso, pasta):
    faltam = [f"Informe {chave}." for chave in (
        "cpf", "nascimento", "advogado", "acompanharAndamentoProcesso",
    ) if getattr(caso, chave) is None]
    if caso.idMunicipio is None and not (caso.uf and caso.municipio):
        faltam.append("Informe idMunicipio do GERID ou a UF e o nome do município.")
    if not (caso.email or caso.telefoneCelular):
        faltam.append("Informe um contato da requerente (email ou telefoneCelular).")
    if not caso.anexos:
        faltam.append("Adicione os documentos e informe a definição GERID de cada anexo.")
    if caso.nascimento and not (
        caso.nascimento.dataNascimento <= caso.nascimento.dataLavratura <= date.today()
    ):
        faltam.append("Confira as datas de nascimento e lavratura da certidão.")
    chaves = set(DECLARACOES) | {"MtRescisao"}
    if set(caso.respostas) - chaves:
        faltam.append("Use as respostas CategReq, AfastApDIB e MtRescisao quando aplicável.")
    arquivos, erros = arquivos_locais(caso, pasta)
    if faltam or erros:
        raise Pendencias(faltam + erros)
    manifest = [
        {"definicao": tipo, "nome": nome, "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)}
        for tipo, nome, raw in arquivos
    ]
    return arquivos, manifest, digest([caso.model_dump(mode="json"), manifest])


def aviso_ou_erro(resposta, etapa):
    if not isinstance(resposta, dict):
        raise ErroPortal(etapa)
    messages = resposta.get("messages", resposta)
    if not isinstance(messages, dict):
        raise ErroPortal(etapa)
    if messages.get("errors"):
        raise Pendencias([f"O GERID apontou erros em {etapa}."], erros_gerid=messages["errors"])
    return list(messages.get("warnings") or [])


def candidato(resposta):
    answer = resposta.get("answer")
    if not isinstance(answer, dict):
        return None
    protocolo = str(answer.get("protocoloRequerimento") or answer.get("protocolo") or "")
    return protocolo if protocolo.isascii() and protocolo.isdigit() else None


def dados_registro(caso):
    return {"idServico": TSMU, "cpf": int(caso.cpf),
            "salarioMaternidade": {"registroNascimento": caso.nascimento.model_dump(mode="json")}}


def dados_recuperacao(caso, nome):
    dados = dados_registro(caso)
    dados.pop("idServico")
    return {"idServico": TSMU, "origemSolicitacao": "INTRANET",
            "requerente": dados, "interessados": [{"cpf": int(caso.cpf), "nome": nome}]}


def selecionar_campos(definicoes, respostas):
    por_sigla = {campo.get("sigla"): campo for campo in definicoes if campo.get("sigla")}
    if any(sigla not in por_sigla for sigla in ("TemCertid", "FatoGerad", *DECLARACOES, "MtRescisao")):
        raise Pendencias(["O formulário TSMU mudou. Confira as definições do GERID."])
    valores = {"TemCertid": "SIM", "FatoGerad": "PARTO", **respostas}
    erros, opcoes = [], {}
    campos = []
    for campo in definicoes:
        if not campo.get("ativo", True):
            continue
        sigla = campo.get("sigla")
        valor = valores.get(sigla, campo.get("valor") or "")
        visivel = bool(campo.get("visivelUsuario"))
        if sigla == "MtRescisao" and respostas.get("CategReq") != DESEMPREGADA:
            if respostas.get(sigla):
                erros.append("Preencha MtRescisao somente para a categoria desempregada.")
            valor = ""
        elif ((sigla in DECLARACOES or sigla == "MtRescisao") and not respostas.get(sigla)
              or campo.get("tipoExigencia") == "OBRIGATORIO" and not valor):
            erros.append(f"Confirme o campo {sigla or campo.get('nome')}.")
        opcoes_campo = [v["valor"] for v in (campo.get("valores") or []) if "valor" in v]
        if sigla in {*DECLARACOES, "MtRescisao"}:
            opcoes[sigla] = opcoes_campo
        if valor and opcoes_campo and valor not in opcoes_campo:
            erros.append(f"Selecione uma opção vigente para {sigla or campo.get('nome')}.")
        campos.append({"id": campo["id"], "valor": valor, "visivelUsuario": visivel})
    if erros:
        raise Pendencias(erros, opcoes_gerid=opcoes)
    return campos


def anexos_gerid(arquivos, catalogo):
    config = catalogo["configuracao"]
    defs = {d["id"]: d for d in catalogo["definicoes"] if d.get("ativo", True)}
    presentes, anexos, faltam = set(), [], []
    for tipo, nome, raw in arquivos:
        definicao = defs.get(tipo)
        if (not definicao or Path(nome).suffix[1:].lower() not in
                {ext.lower().lstrip(".") for ext in definicao.get("extensoes") or []}
                or len(raw) > config["tamanhoMaximo"] * MIB):
            faltam.append(f"Confira a definição, formato e tamanho de {nome}.")
            continue
        presentes.add(tipo)
        anexos.append({"nomeArquivo": nome, "conteudoAnexo": base64.b64encode(raw).decode(),
                       "cpfCriador": 0, "tamanhoAnexo": len(raw), "idDefinicaoAnexo": tipo,
                       "descricao": definicao["nome"]})
    for tipo, definicao in defs.items():
        if definicao.get("obrigatorio") and tipo not in presentes:
            faltam.append(f"Anexo obrigatório {tipo}: {definicao['nome']}.")
    if sum(a["tamanhoAnexo"] for a in anexos) > config["tamanhoMaximoTotal"] * MIB:
        faltam.append("Os anexos superam o limite total do GERID.")
    if faltam:
        raise Pendencias(faltam, definicoes_anexo=[
            {"id": d["id"], "nome": d["nome"], "extensoes": d.get("extensoes")} for d in defs.values()
        ])
    return anexos


def codigo_municipio(api, caso):
    if caso.idMunicipio is not None:
        return caso.idMunicipio
    candidatos = api.ler("municipios", f"/apis/requerimentosPortalApi/uf/municipio/{caso.uf}/sigla")
    if not isinstance(candidatos, list):
        raise ErroPortal("municipios")

    def comparar(nome):
        return unicodedata.normalize("NFKD", nome).encode("ascii", "ignore").decode().casefold()

    matches = [m["codigo"] for m in candidatos if comparar(m["nome"]) == comparar(caso.municipio)]
    if len(matches) != 1 or not str(matches[0]).isdigit():
        raise Pendencias(["Confira o município informado para a UF ou forneça idMunicipio do GERID."])
    return int(matches[0])


def preparar(api, caso, arquivos, fingerprint):
    servico = api.ler("servico", f"{CADASTRO}/servico/{TSMU}/controle") or {}
    servico = servico.get("servico") or {}
    if servico.get("sigla") != "TSMU" or not servico.get("ativo") or servico.get("tipoServico") != "TAREFA":
        raise Pendencias(["Serviço TSMU indisponível ou diferente do mapeado."])
    anexos = anexos_gerid(arquivos, api.ler("anexos", f"{CADASTRO}/servico/{TSMU}/anexos"))
    registro = dados_registro(caso)
    definicoes = api.enviar("campos_adicionais", CADASTRO + "/servico/camposadicionais", registro)
    if not isinstance(definicoes, list):
        raise ErroPortal("campos_adicionais")
    campos = selecionar_campos(definicoes, caso.respostas)
    pessoa = api.ler("requerente", f"{CADASTRO}/requerente/{caso.cpf}/informacoes") or {}
    if not pessoa.get("nome") or str(pessoa.get("cpf", "")).zfill(11) != caso.cpf:
        raise Pendencias(["O cadastro devolvido pelo GERID precisa de conferência."])
    recuperar = dados_recuperacao(caso, pessoa["nome"])
    recuperado = api.recuperar(recuperar)
    avisos = aviso_ou_erro(recuperado, "recuperar")
    if recuperado.get("answer"):
        raise Pendencias(["O GERID retornou um requerimento existente para revisão."],
                         protocolo_candidato=candidato(recuperado))
    requerente = {"cpf": int(caso.cpf), "nome": pessoa["nome"],
                  "salarioMaternidade": registro["salarioMaternidade"]}
    if pessoa.get("dataNascimento"):
        requerente["dataNascimento"] = pessoa["dataNascimento"]
    contatos = {k: v for k in ("email", "telefoneCelular") if (v := getattr(caso, k))}
    requerente.update(contatos)
    interessado = {k: requerente[k] for k in ("cpf", "nome", "dataNascimento") if k in requerente}
    interessado["contatos"] = [
        {"tipo": {"email": "EMAIL", "telefoneCelular": "CELULAR"}[k], "valor": v}
        for k, v in contatos.items()
    ]
    validacao = api.enviar("validacao_requerente", CADASTRO + "/requerente/validacao", registro)
    avisos += aviso_ou_erro(validacao, "validacao_requerente")
    avisos += checar_validacao(validacao)
    previa = {"informacoesRequerimento": {
        "anexos": anexos, "camposAdicionaisInformados": campos, "interessados": [interessado],
        "acompanharAndamentoProcesso": caso.acompanharAndamentoProcesso,
        "requerentePossuiTempoExterior": False, "houveAtualizacaoDadosCadastrais": False,
        "numeroProcessoJudicial": None, "protocoloCumprimentoExigencia": None,
        "paisAcordoInternacional": None, "servidoresResponsaveis": [],
    }, "cpf": int(caso.cpf), "idServico": TSMU, "informacoesRequerente": contatos}
    validacao = api.enviar("validacao_adicional", CADASTRO + "/informacoesadicionais/validacao", previa)
    avisos += aviso_ou_erro(validacao, "validacao_adicional")
    avisos += checar_validacao(validacao)
    local_base = f"{CADASTRO}/servico/sigla/TSMU/cidadao/{int(caso.cpf)}/local"
    municipio = codigo_municipio(api, caso)
    locais = api.enviar("locais", local_base + f"/municipio/{municipio}", None,
                        {"void": "", "acaoINSS": "false", "encaminharParaPresencial": "false"})
    if not isinstance(locais, list):
        raise ErroPortal("locais")
    local = next((i for i in locais if i["local"]["id"] == caso.idLocal), None)
    if local is None:
        raise Pendencias(["Selecione uma unidade retornada pelo GERID."],
                         locais=[{k: i["local"].get(k) for k in ("id", "nome")} for i in locais],
                         avisos_gerid=avisos)
    ok = api.enviar("validacao_local", local_base + f"/{caso.idLocal}/validacao",
                    {"camposAdicionaisInformados": campos})
    avisos += aviso_ou_erro(ok, "validacao_local")
    if ok.get("answer") is not True:
        raise Pendencias(["A unidade selecionada não foi validada pelo GERID."])
    id_uo = str(local["local"].get("idUnidadeOrganica") or "")
    if not id_uo.isascii() or not id_uo.isdigit():
        raise ErroPortal("unidade_organica")
    pagadores = api.ler("orgaos_pagadores", f"/apis/requerimentosPortalApi/orgaospagadores/{id_uo}")
    if not isinstance(pagadores, list):
        raise ErroPortal("orgaos_pagadores")
    pagador = next((p for p in pagadores if p["idOrgaoPagador"] == caso.idOrgaoPagador
                    and p.get("pagamentoAutorizado") is True), None)
    if pagador is None:
        raise Pendencias(["Selecione um órgão pagador autorizado retornado pelo GERID."],
                         orgaos_pagadores=[{k: p.get(k) for k in ("idOrgaoPagador", "nomeOrgaoPagador")}
                                           for p in pagadores if p.get("pagamentoAutorizado") is True],
                         avisos_gerid=avisos)
    vaga = local.get("vaga") or {}
    dados_vaga = {"idLocal": caso.idLocal, "idServico": vaga.get("idServico", TSMU),
                  "idUO": id_uo}
    if vaga.get("data"):
        try:
            data = datetime.fromisoformat(vaga["data"].replace(" - ", " ").replace("Z", "+00:00"))
            if data.tzinfo is None:
                raise ValueError
            dados_vaga["dataDisponivel"] = data.astimezone(timezone.utc).isoformat(
                timespec="milliseconds").replace("+00:00", "Z")
        except ValueError:
            raise Pendencias(["Formato de disponibilidade do GERID precisa de validação."]) from None
    else:
        dados_vaga["dataDisponivel"] = ""
    if vaga.get("rastreio") is not None:
        dados_vaga["rastreio"] = vaga["rastreio"]
    payload = {"idServico": TSMU, "origemSolicitacao": "INTRANET", "requerente": requerente,
               "interessados": [interessado], "camposAdicionais": campos, "vaga": dados_vaga,
               "idOrgaoPagador": caso.idOrgaoPagador, "servidoresResponsaveis": [],
               "houveAtualizacaoDadosCadastrais": False,
               "acompanharAndamentoProcesso": caso.acompanharAndamentoProcesso,
               "anexos": [{**a, "descricaoArquivo": a["descricao"], "tamanho": a["tamanhoAnexo"]} for a in anexos]}
    revisao = {"servico": "TSMU", "caso_id": str(caso.caso_id), "campos": len(campos),
               "requerente_cpf_final": caso.cpf[-4:], "idMunicipio": municipio,
               "nascimento": caso.nascimento.dataNascimento.isoformat(),
               "lavratura": caso.nascimento.dataLavratura.isoformat(),
               "unidade": local["local"]["nome"], "orgao_pagador": pagador["nomeOrgaoPagador"],
               "respostas": caso.respostas, "avisos_gerid": list(dict.fromkeys(map(str, avisos))),
               "advogado": {"nome": caso.advogado.nome, "cpf_final": caso.advogado.cpf[-4:]}}
    return payload, recuperar, revisao, digest([fingerprint, payload, revisao])


def checar_validacao(resposta):
    answer = resposta.get("answer")
    if not isinstance(answer, dict):
        raise ErroPortal("validacao")
    biometria = answer.get("validacaoBiometria") or {}
    if (any(answer.get(k) for k in ("numeroProtocoloTarefaIncompativel", "numeroProtocoloAgendamentoIncompativel",
                                   "numeroProtocoloTarefaRecurso", "numeroProtocoloTarefaRdbi",
                                   "servicoParaRedirecionar", "deveCriarRecurso"))
            or biometria.get("validacaoRequerQuestionario") or biometria.get("validacaoDispensaEmAnalise")
            or biometria.get("validacaoAtiva") and not biometria.get("biometriaEncontrada")
            and not biometria.get("validacaoLiberadaAutomaticamente")):
        raise Pendencias(["A validação do GERID exige um tratamento fora deste fluxo."],
                         avisos_gerid=resposta.get("messages", {}).get("warnings") or [])
    avisos = list(answer.get("divergencias") or [])
    if answer.get("concessaoAutomaticaBloqueada"):
        avisos.append("O GERID informou bloqueio da concessão automática.")
    return avisos


def payload_envio(payload):
    agora = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    return {**payload, "dataDisponibilidade": payload["vaga"]["dataDisponivel"] or agora,
            "anexos": [{**a, "dataCriacao": agora} for a in payload["anexos"]]}
