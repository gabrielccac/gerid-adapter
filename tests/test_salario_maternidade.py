"""Contrato do piloto com respostas fictícias e transporte sem rede."""

from contextlib import closing

import pytest

from gerid_adapter import sm_cli
from gerid_adapter.salario_maternidade import Caso, ErroPortal, Pendencias, entrada, preparar

CPF = "01234567890"
PROTOCOLO = "1234567890"
AVISO = "Aviso fictício da validação."


class PortalFalso:
    def __init__(self):
        self.chamadas = []
        self.timeout_protocolo = False
        self.timeout_advogado = False
        self.protocolo_criado = False
        self.advogado_incluido = False
        self.aviso = AVISO

    def ler(self, etapa, caminho):
        self.chamadas.append((etapa, caminho, None))
        return {
            "servico": {"servico": {"sigla": "TSMU", "ativo": True, "tipoServico": "TAREFA"}},
            "anexos": {"configuracao": {"tamanhoMaximo": 5, "tamanhoMaximoTotal": 50},
                       "definicoes": [{"id": 1427, "nome": "Representação", "extensoes": ["pdf"],
                                      "obrigatorio": True}]},
            "requerente": {"cpf": int(CPF), "nome": "Requerente de Teste"},
            "municipios": [{"codigo": 710, "nome": "São José"}],
            "orgaos_pagadores": [{"idOrgaoPagador": 801, "nomeOrgaoPagador": "Banco de Teste",
                                  "pagamentoAutorizado": True}],
        }[etapa]

    def recuperar(self, dados):
        self.chamadas.append(("recuperar", None, dados))
        return {"answer": {"protocoloRequerimento": PROTOCOLO}} if self.protocolo_criado else {}

    def enviar(self, etapa, caminho, dados, query=None):
        self.chamadas.append((etapa, caminho, dados))
        if etapa == "campos_adicionais":
            campos = [
                ("TemCertid", ["SIM", "NÃO"]),
                ("FatoGerad", ["PARTO", "ADOÇÃO"]),
                ("CategReq", ["outras (todas as demais categorias)",
                             "desempregada (último vínculo com carteira assinada)"]),
                ("MtRescisao", ["por justa causa"]),
                ("AfastApDIB", ["C) Sim, ainda está afastada"]),
            ]
            return [{"id": i, "sigla": sigla, "visivelUsuario": True,
                     "tipoExigencia": "OBRIGATORIO", "valores": [{"valor": v} for v in opcoes]}
                    for i, (sigla, opcoes) in enumerate(campos)]
        if etapa in ("validacao_requerente", "validacao_adicional"):
            return {"answer": {}, "messages": {"warnings": [self.aviso]}}
        if etapa == "locais":
            assert dados is None and query == {"void": "", "acaoINSS": "false", "encaminharParaPresencial": "false"}
            return [{"local": {"id": 42, "nome": "APS de Teste", "idUnidadeOrganica": "00770"},
                     "vaga": {"data": "2026-09-01T10:30:00-03:00", "idServico": 1675}}]
        if etapa == "validacao_local":
            return {"answer": True}
        if etapa == "protocolar":
            self.protocolo_criado = True
            if self.timeout_protocolo:
                raise ErroPortal("protocolar")
            return {"answer": {"protocoloRequerimento": PROTOCOLO}}
        if etapa == "incluir_advogado":
            self.advogado_incluido = True
            if self.timeout_advogado:
                raise ErroPortal("incluir_advogado")
            return {"successes": ["Procurador incluído."]}
        raise AssertionError(etapa)

    def tarefa(self, protocolo):
        assert protocolo == PROTOCOLO
        return {"protocolo": int(protocolo), "idServico": 1675, "cpfRequerente": int(CPF),
                "procuradores": [{"cpf": 12345678900}] if self.advogado_incluido else []}

    def comprovante(self, protocolo, cpf):
        assert protocolo == PROTOCOLO and cpf == CPF
        return b"%PDF-1.4\nTeste\n%%EOF\n"


@pytest.fixture
def caso(tmp_path):
    (tmp_path / "representacao.pdf").write_bytes(b"%PDF-1.4\nFicticio")
    return Caso.model_validate({
        "caso_id": "2e0b6446-8191-4a52-9c27-162a75ba078a",
        "cpf": CPF, "nascimento": {"matricula": "0" * 32, "dataNascimento": "2025-01-01",
                                   "dataLavratura": "2025-01-02"},
        "respostas": {"CategReq": "outras (todas as demais categorias)",
                      "AfastApDIB": "C) Sim, ainda está afastada"},
        "uf": "SP", "municipio": "Sao Jose", "idLocal": 42, "idOrgaoPagador": 801,
        "telefoneCelular": "11900000000", "acompanharAndamentoProcesso": True,
        "anexos": [{"arquivo": "representacao.pdf", "definicao": 1427}],
        "advogado": {"nome": "Advogada de Teste", "cpf": "12345678900"},
    })


def aprovado(portal, registro, caso, pasta):
    arquivos, _, fingerprint = entrada(caso, pasta)
    _, _, _, confirmacao = preparar(portal, caso, arquivos, fingerprint)
    assert registro.salvar_preparo(str(caso.caso_id), fingerprint, confirmacao)
    return arquivos, fingerprint, confirmacao


def chamadas(portal, etapa):
    return [x for x in portal.chamadas if x[0] == etapa]


def test_preparo_e_protocolo_com_advogado_uma_vez(caso, tmp_path):
    portal = PortalFalso()
    with closing(sm_cli.Registro(tmp_path / "registro")) as registro:
        args = aprovado(portal, registro, caso, tmp_path)
        assert not chamadas(portal, "protocolar")
        assert not chamadas(portal, "incluir_advogado")
        for _ in range(2):
            resultado = sm_cli.protocolar(portal, registro, caso, *args)
            assert resultado["estado"] == "concluido"
            assert resultado["protocolo"] == PROTOCOLO
        assert len(chamadas(portal, "protocolar")) == len(chamadas(portal, "incluir_advogado")) == 1
        envio = chamadas(portal, "protocolar")[0][2]
        assert envio["requerente"]["salarioMaternidade"]["registroNascimento"]["matricula"] == "0" * 32
        assert envio["anexos"][0]["conteudoAnexo"].startswith("JVBER")
        assert envio["vaga"]["dataDisponivel"] == envio["dataDisponibilidade"] == "2026-09-01T13:30:00.000Z"
        assert chamadas(portal, "orgaos_pagadores")[0][1].endswith("/00770")
        assert "/cidadao/1234567890/" in chamadas(portal, "locais")[0][1]
        assert chamadas(portal, "incluir_advogado")[0][1].endswith(f"/{PROTOCOLO}/procurador")
        assert (tmp_path / "registro" / f"comprovante-{PROTOCOLO}.pdf").is_file()


def test_timeout_protocolo_exige_reconciliacao_explicita(caso, tmp_path):
    portal = PortalFalso()
    portal.timeout_protocolo = True
    with closing(sm_cli.Registro(tmp_path / "registro")) as registro:
        args = aprovado(portal, registro, caso, tmp_path)
        for _ in range(2):
            resultado = sm_cli.protocolar(portal, registro, caso, *args)
            assert resultado["estado"] == "protocolo_indeterminado"
            assert resultado["protocolo_candidato"] == PROTOCOLO
        assert len(chamadas(portal, "protocolar")) == 1
        assert not chamadas(portal, "incluir_advogado")
        with pytest.raises(Pendencias):
            sm_cli.protocolar(portal, registro, caso, *args, reconciliacao="999")
        assert sm_cli.protocolar(portal, registro, caso, *args, reconciliacao=PROTOCOLO)["estado"] == "concluido"
        assert len(chamadas(portal, "protocolar")) == 1


def test_timeout_advogado_reconcilia_pelo_cpf_sem_reenviar(caso, tmp_path):
    portal = PortalFalso()
    portal.timeout_advogado = True
    with closing(sm_cli.Registro(tmp_path / "registro")) as registro:
        args = aprovado(portal, registro, caso, tmp_path)
        primeiro = sm_cli.protocolar(portal, registro, caso, *args)
        assert primeiro["estado"] == "protocolado"
        assert primeiro["comprovante"]
        assert sm_cli.protocolar(portal, registro, caso, *args)["estado"] == "concluido"
        assert len(chamadas(portal, "protocolar")) == len(chamadas(portal, "incluir_advogado")) == 1


def test_confirmacao_invalida_apos_mudar_anexo_ou_aviso(caso, tmp_path):
    portal = PortalFalso()
    with closing(sm_cli.Registro(tmp_path / "registro")) as registro:
        arquivos, fingerprint, confirmacao = aprovado(portal, registro, caso, tmp_path)
        (tmp_path / "representacao.pdf").write_bytes(b"%PDF-1.4\nMudou")
        novos, _, nova_entrada = entrada(caso, tmp_path)
        with pytest.raises(Pendencias):
            sm_cli.protocolar(portal, registro, caso, novos, nova_entrada, confirmacao)
        portal.aviso = "Aviso mudou."
        with pytest.raises(Pendencias):
            sm_cli.protocolar(portal, registro, caso, arquivos, fingerprint, confirmacao)
        assert not chamadas(portal, "protocolar")


def test_motivo_rescisao_condicional(caso, tmp_path):
    caso.respostas["CategReq"] = "desempregada (último vínculo com carteira assinada)"
    arquivos, _, fingerprint = entrada(caso, tmp_path)
    with pytest.raises(Pendencias) as error:
        preparar(PortalFalso(), caso, arquivos, fingerprint)
    assert "MtRescisao" in str(error.value.resultado["pendencias"])


def test_preparo_incompleto_da_cli_nao_abre_sessao(tmp_path, monkeypatch, capsys):
    arquivo = tmp_path / "caso.json"
    arquivo.write_text('{"caso_id":"2e0b6446-8191-4a52-9c27-162a75ba078a"}', encoding="utf-8")
    monkeypatch.setattr(sm_cli, "ensure_session", lambda *_, **__: pytest.fail("abriu sessão"))
    assert sm_cli.main(["--dir", str(tmp_path), "preparar", str(arquivo)]) == 1
    assert '"estado": "revisar"' in capsys.readouterr().out


def test_registro_impede_envio_concorrente(tmp_path):
    with closing(sm_cli.Registro(tmp_path)) as primeiro, closing(sm_cli.Registro(tmp_path)) as segundo:
        primeiro.salvar_preparo("caso", "entrada", "conf")
        assert primeiro.mover("caso", "conf", "preparado", "enviando")
        assert not segundo.mover("caso", "conf", "preparado", "enviando")
        assert not segundo.salvar_preparo("caso", "mudou", "nova")
