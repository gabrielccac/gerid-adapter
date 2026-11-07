"""Comandos locais de preparação e protocolo explícito do salário-maternidade."""

import argparse
import json
import os
import re
import sqlite3
import sys
from contextlib import closing, redirect_stdout
from pathlib import Path
from tempfile import NamedTemporaryFile

from pydantic import ValidationError

from gerid_adapter.api import load_token
from gerid_adapter.poc import STATE_DIR, ensure_session
from gerid_adapter.salario_maternidade import (
    BASE, CADASTRO, TSMU, Caso, ErroPortal, Pendencias, SalarioMaternidadeApi,
    aviso_ou_erro, candidato, dados_recuperacao, entrada, payload_envio, preparar,
)


class Registro:
    """A tentativa fica gravada antes de qualquer POST que altere o processo."""

    def __init__(self, pasta):
        self.pasta = pasta
        pasta.mkdir(mode=0o700, parents=True, exist_ok=True)
        arquivo = pasta / "registro.sqlite3"
        fd = os.open(arquivo, os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        self.db = sqlite3.connect(arquivo)
        self.db.row_factory = sqlite3.Row
        self.db.execute("""CREATE TABLE IF NOT EXISTS casos (
            caso TEXT PRIMARY KEY, entrada TEXT NOT NULL, confirmacao TEXT NOT NULL,
            estado TEXT NOT NULL, protocolo TEXT)""")

    def close(self):
        self.db.close()

    def ler(self, caso):
        return self.db.execute("SELECT * FROM casos WHERE caso = ?", (caso,)).fetchone()

    def salvar_preparo(self, caso, fingerprint, confirmacao):
        with self.db:
            return self.db.execute("""INSERT INTO casos VALUES (?, ?, ?, 'preparado', NULL)
                ON CONFLICT(caso) DO UPDATE SET entrada=excluded.entrada,
                confirmacao=excluded.confirmacao WHERE casos.estado='preparado'""",
                (caso, fingerprint, confirmacao)).rowcount == 1

    def mover(self, caso, confirmacao, anterior, novo, protocolo=None):
        with self.db:
            return self.db.execute("""UPDATE casos SET estado=?, protocolo=COALESCE(?, protocolo)
                WHERE caso=? AND confirmacao=? AND estado=?""",
                (novo, protocolo, caso, confirmacao, anterior)).rowcount == 1


def tarefa_confere(tarefa, caso, protocolo):
    return (isinstance(tarefa, dict) and str(tarefa.get("protocolo")) == protocolo
            and str(tarefa.get("idServico")) == str(TSMU)
            and tarefa.get("status") not in ("CANCELADO", "CANCELADA")
            and str(tarefa.get("cpfRequerente", "")).zfill(11) == caso.cpf)


def advogado_presente(tarefa, caso):
    return any(str(p.get("cpf", "")).zfill(11) == caso.advogado.cpf
               for p in tarefa.get("procuradores") or [])


def salvar_comprovante(api, pasta, protocolo, cpf):
    destino = pasta / f"comprovante-{protocolo}.pdf"
    if destino.is_file():
        with destino.open("rb") as file:
            inicio = file.read(5)
            file.seek(max(0, destino.stat().st_size - 2048))
            if inicio == b"%PDF-" and b"%%EOF" in file.read(2048):
                return str(destino)
    pdf = api.comprovante(protocolo, cpf)
    if not pdf or not pdf.startswith(b"%PDF-") or b"%%EOF" not in pdf[-2048:]:
        raise ErroPortal("comprovante")
    with NamedTemporaryFile(dir=pasta, delete=False) as file:
        tmp = Path(file.name)
        file.write(pdf)
    try:
        tmp.replace(destino)
    finally:
        tmp.unlink(missing_ok=True)
    return str(destino)


def reconciliar_envio(api, caso):
    try:
        pessoa = api.ler("requerente", f"{CADASTRO}/requerente/{caso.cpf}/informacoes") or {}
        if not pessoa.get("nome") or str(pessoa.get("cpf", "")).zfill(11) != caso.cpf:
            raise ErroPortal("requerente")
        possivel = candidato(api.recuperar(dados_recuperacao(caso, pessoa["nome"])))
    except (ErroPortal, AttributeError):
        possivel = None
    return {"estado": "protocolo_indeterminado", "protocolo_candidato": possivel,
            "acao": "Confira o pedido no GERID antes de qualquer novo envio."}


def protocolar(api, registro, caso, arquivos, fingerprint, confirmacao, reconciliacao=None):
    chave = str(caso.caso_id)
    atual = registro.ler(chave)
    if atual is None or atual["entrada"] != fingerprint or atual["confirmacao"] != confirmacao:
        raise Pendencias(["Prepare e confirme esta versão dos dados e dos anexos."])
    estado, protocolo = atual["estado"], atual["protocolo"]
    if reconciliacao is not None and estado != "enviando":
        raise Pendencias(["A reconciliação se aplica somente a envios de resultado indeterminado."])
    if estado == "enviando" and reconciliacao is None:
        return reconciliar_envio(api, caso)
    if estado == "enviando":
        encontrado = reconciliar_envio(api, caso)["protocolo_candidato"]
        if encontrado != reconciliacao or not tarefa_confere(api.tarefa(encontrado), caso, encontrado):
            raise Pendencias(["O protocolo informado não foi confirmado pela recuperação do GERID."])
        if not registro.mover(chave, confirmacao, "enviando", "protocolado", encontrado):
            return {"estado": "execucao_concorrente"}
        estado, protocolo = "protocolado", encontrado
    if estado == "preparado":
        payload, _, _, nova = preparar(api, caso, arquivos, fingerprint)
        if nova != confirmacao:
            raise Pendencias(["Os dados, opções ou avisos do GERID mudaram. Revise um novo preparo."])
        if not registro.mover(chave, confirmacao, "preparado", "enviando"):
            return {"estado": "execucao_concorrente", "acao": "Consulte novamente com a mesma confirmação."}
        try:
            resposta = api.enviar("protocolar", CADASTRO + "/requerimento", payload_envio(payload))
            aviso_ou_erro(resposta, "protocolar")
            protocolo = candidato(resposta)
        except (ErroPortal, Pendencias):
            protocolo = None
        if not protocolo:
            return reconciliar_envio(api, caso)
        registro.mover(chave, confirmacao, "enviando", "protocolado", protocolo)
        estado = "protocolado"

    resultado = {"estado": "protocolado", "protocolo": protocolo,
                 "advogado_incluido": estado == "advogado_incluido", "comprovante": None}
    if estado in ("protocolado", "incluindo_advogado"):
        try:
            tarefa = api.tarefa(protocolo)
            if not tarefa_confere(tarefa, caso, protocolo):
                raise ErroPortal("conferir_tarefa")
            if advogado_presente(tarefa, caso):
                registro.mover(chave, confirmacao, estado, "advogado_incluido")
                resultado["advogado_incluido"] = True
            elif estado == "incluindo_advogado":
                resultado["pendencia_advogado"] = "Confira a inclusão no GERID antes de tentar novamente."
            elif registro.mover(chave, confirmacao, "protocolado", "incluindo_advogado"):
                resposta = api.enviar("incluir_advogado", BASE + f"/ec/tarefa/{protocolo}/procurador", {
                    "tipoPessoaRepresentante": "PESSOA_FISICA",
                    "cpfProcurador": caso.advogado.cpf, "nomeProcurador": caso.advogado.nome,
                })
                aviso_ou_erro(resposta, "incluir_advogado")
                if not resposta.get("successes"):
                    raise ErroPortal("incluir_advogado")
                registro.mover(chave, confirmacao, "incluindo_advogado", "advogado_incluido")
                resultado["advogado_incluido"] = True
            else:
                resultado["pendencia_advogado"] = "Outra execução está processando o advogado."
        except (ErroPortal, Pendencias) as exc:
            resultado["pendencia_advogado"] = getattr(exc, "etapa", "incluir_advogado")
    try:
        resultado["comprovante"] = salvar_comprovante(api, registro.pasta, protocolo, caso.cpf)
    except (ErroPortal, OSError):
        resultado["pendencia_comprovante"] = "O pedido existe. Repita com a mesma confirmação para obter o PDF."
    if resultado["advogado_incluido"] and resultado["comprovante"]:
        resultado["estado"] = "concluido"
    return resultado


def executar(args):
    caminho = Path(args.caso).resolve()
    caso = Caso.model_validate_json(caminho.read_text(encoding="utf-8-sig"))
    arquivos, manifest, fingerprint = entrada(caso, caminho.parent)
    sessao = Path(args.dir).resolve()
    with closing(Registro(sessao / "salario-maternidade")) as registro:
        chave = str(caso.caso_id)
        anterior = registro.ler(chave)
        if args.comando == "preparar" and anterior is not None and anterior["estado"] != "preparado":
            return {"estado": anterior["estado"], "protocolo": anterior["protocolo"],
                    "acao": "Retome com o mesmo arquivo e a confirmação original."}
        if args.comando != "preparar" and (
            anterior is None or anterior["entrada"] != fingerprint or anterior["confirmacao"] != args.confirmar
        ):
            raise Pendencias(["Prepare e confirme esta versão dos dados e dos anexos."])
        if ensure_session(argparse.Namespace(dir=str(sessao), module=None), quiet=True):
            return {"estado": "sessao_indisponivel", "acao": "Confira o certificado A3 e a sessão do GERID."}
        api = SalarioMaternidadeApi(load_token(sessao / "ifs_auth.jwt"),
                                    token_servidor=os.environ.get("GERID_TOKEN_SERVIDOR"))
        if args.comando != "preparar":
            return protocolar(api, registro, caso, arquivos, fingerprint, args.confirmar,
                              getattr(args, "protocolo", None))
        _, _, revisao, confirmacao = preparar(api, caso, arquivos, fingerprint)
        if not registro.salvar_preparo(chave, fingerprint, confirmacao):
            return {"estado": "execucao_concorrente"}
        return {"estado": "preparado", **revisao, "anexos": manifest, "confirmacao": confirmacao}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="gerid-sm", description=__doc__)
    parser.add_argument("--dir", default=str(STATE_DIR), help="Diretório privado da sessão GERID.")
    sub = parser.add_subparsers(dest="comando", required=True)
    sub.add_parser("preparar").add_argument("caso", help="Arquivo JSON do caso.")
    for comando in ("protocolar", "reconciliar"):
        send = sub.add_parser(comando)
        send.add_argument("caso", help="Mesmo arquivo JSON usado no preparo.")
        send.add_argument("--confirmar", required=True, help="Código exibido no preparo revisado.")
        if comando == "reconciliar":
            send.add_argument("--protocolo", required=True, help="Protocolo candidato conferido no portal.")
    args = parser.parse_args(argv)
    if args.comando != "preparar" and not re.fullmatch(r"[a-f0-9]{64}", args.confirmar):
        parser.error("--confirmar deve ser o código de 64 caracteres gerado no preparo.")
    if args.comando == "reconciliar" and not re.fullmatch(r"[0-9]{1,24}", args.protocolo):
        parser.error("--protocolo deve conter somente dígitos.")
    try:
        with redirect_stdout(sys.stderr):
            resultado = executar(args)
    except Pendencias as exc:
        resultado = exc.resultado
    except ValidationError as exc:
        resultado = {"estado": "revisar", "pendencias": [
            {"campo": ".".join(map(str, error["loc"])), "tipo": error["type"]}
            for error in exc.errors(include_input=False, include_url=False)
        ]}
    except ErroPortal as exc:
        resultado = {"estado": "falha_portal", "etapa": exc.etapa, "http_status": exc.status}
    except (OSError, ValueError, RuntimeError, sqlite3.Error, KeyError, TypeError):
        resultado = {"estado": "falha_local_ou_contrato", "acao": "Confira o arquivo e a versão do portal."}
    print(json.dumps(resultado, ensure_ascii=False, indent=2))
    return 0 if resultado["estado"] in ("preparado", "concluido") else 1


if __name__ == "__main__":
    raise SystemExit(main())
