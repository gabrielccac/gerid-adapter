"""Extração de texto e janelas, com PDF mínimo construído aqui (sem rede)."""

import base64
import os

import pytest

from gerid_adapter import docs


def mini_pdf(text):
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET\n".encode("latin-1")
    return b"%PDF-1.4\n" + (
        "1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n"
        "2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n"
        "3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]"
        "/Resources<</Font<</F1 4 0 R>>>>/Contents 5 0 R>>\nendobj\n"
        "4 0 obj\n<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>\nendobj\n"
        f"5 0 obj\n<</Length {len(stream)}>>\nstream\n"
    ).encode("latin-1") + stream + b"endstream\nendobj\ntrailer\n<</Root 1 0 R>>\nstartxref\n0\n%%EOF\n"


def test_mime_by_magic_and_extension():
    assert docs.attachment_mime_type(b"%PDF-1.4 x", "a.bin") == "application/pdf"
    assert docs.attachment_mime_type(b"\x89PNG\r\n\x1a\nxxxx", "a.bin") == "image/png"
    assert docs.attachment_mime_type(b"\xff\xd8\xffxxx", "a.bin") == "image/jpeg"
    assert docs.attachment_mime_type(b"a,b", "a.csv") == "text/csv"
    assert docs.attachment_mime_type(b"???", "a.bin") == "application/octet-stream"


def test_decode_download_validates():
    assert docs.decode_download(base64.b64encode(b"abc").decode()) == b"abc"
    with pytest.raises(ValueError):
        docs.decode_download("!!!")
    with pytest.raises(ValueError):
        docs.decode_download("  ")


def test_save_bytes_no_overwrite_and_perms(tmp_path):
    first = docs.save_bytes(b"1", "../x.pdf", "fb.bin", tmp_path)
    assert first["filename"] == "x.pdf"
    assert os.name == "nt" or (tmp_path / "x.pdf").stat().st_mode & 0o777 == 0o600  # Windows não tem modo Unix
    second = docs.save_bytes(b"22", "../x.pdf", "fb.bin", tmp_path)
    assert second["filename"] == "x-1.pdf" and second["bytes"] == 2


def test_analyze_extracts_text():
    parsed = docs.analyze_document(mini_pdf("Ola mundo GERID"), "doc.pdf")
    assert parsed["mimeType"] == "application/pdf"
    assert "Ola mundo GERID" in parsed["markdown"]
    assert parsed["pageCount"] == 1 and parsed["needsOcr"] is False


def test_analyze_non_pdf_and_garbage():
    assert docs.analyze_document(b"\x89PNG\r\n\x1a\nxx", "a.png") == {"mimeType": "image/png"}
    bad = docs.analyze_document(b"%PDF-1.4 [[[", "a.pdf")
    assert bad["mimeType"] == "application/pdf" and "pdfExtractionError" in bad


def test_slice_windows_chain():
    parsed = {"markdown": "abcdefghij", "mimeType": "application/pdf"}
    first = docs.slice_text(parsed, 0, 4)
    assert (first["markdown"], first["nextOffset"], first["offset"]) == ("abcd", 4, 0)
    last = docs.slice_text(parsed, first["nextOffset"], 99)
    assert (last["markdown"], last["nextOffset"]) == ("efghij", None)


def test_read_saved_document_and_traversal(tmp_path):
    (tmp_path / "doc.pdf").write_bytes(mini_pdf("Segunda pagina"))
    got = docs.read_saved_document("doc.pdf", directory=tmp_path)
    assert "Segunda pagina" in got["markdown"] and got["bytes"] > 0
    for evil in ("../doc.pdf", "/etc/passwd", "a\\b.pdf", "", ".", ".."):
        with pytest.raises((ValueError, FileNotFoundError)):
            docs.read_saved_document(evil, directory=tmp_path)
    with pytest.raises(FileNotFoundError):
        docs.read_saved_document("falta.pdf", directory=tmp_path)
    with pytest.raises(ValueError):
        docs.read_saved_document("doc.pdf", offset=-1, directory=tmp_path)


def test_cached_analysis_parses_once(monkeypatch, tmp_path):
    from gerid_adapter import docs

    pdf = tmp_path / "a.pdf"
    pdf.write_bytes(b"%PDF-1.4 x")
    calls = []
    monkeypatch.setattr(docs, "analyze_document", lambda content, name: calls.append(name) or {"markdown": "T"})
    assert docs.cached_analysis(pdf)["markdown"] == "T"
    assert docs.cached_analysis(pdf)["markdown"] == "T"
    assert calls == ["a.pdf"]  # segunda leitura veio do cache
    assert os.name == "nt" or (tmp_path / "a.pdf.text.json").stat().st_mode & 0o777 == 0o600  # Windows não tem modo Unix


def test_save_bytes_overwrite_replaces_canonical(tmp_path):
    from gerid_adapter import docs

    docs.save_bytes(b"v1", "p.pdf", "p.pdf", tmp_path, overwrite=True)
    meta = docs.save_bytes(b"v2", "p.pdf", "p.pdf", tmp_path, overwrite=True)
    assert meta["filename"] == "p.pdf" and (tmp_path / "p.pdf").read_bytes() == b"v2"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["p.pdf"]


def test_cached_analysis_writes_utf8_even_on_a_narrow_locale(tmp_path):
    """Windows grava em cp1252 por padrão e "□" (PDF digitalizado) não cabe: o cache tem de sair em UTF-8.

    Reproduz num processo com locale ASCII (LC_ALL=C, sem o modo UTF-8 do Python), que falha igual.
    """
    import os
    import subprocess
    import sys

    pdf = tmp_path / "p.pdf"
    pdf.write_bytes(b"%PDF-1.4 x")
    script = (
        "import sys; from gerid_adapter import docs\n"
        "docs.analyze_document = lambda content, name: {'markdown': 'campo \\u25a1 vazio'}\n"
        "print(docs.cached_analysis(sys.argv[1])['markdown'].encode('unicode_escape').decode())\n"
    )
    env = {**os.environ, "LC_ALL": "C", "LANG": "C", "PYTHONUTF8": "0", "PYTHONIOENCODING": "ascii"}
    done = subprocess.run([sys.executable, "-c", script, str(pdf)], env=env, capture_output=True, text=True)
    assert done.returncode == 0, done.stderr
    assert "\\u25a1" in done.stdout
    sidecar = tmp_path / "p.pdf.text.json"
    assert "□" in sidecar.read_bytes().decode("utf-8")
    assert docs.cached_analysis(pdf)["markdown"] == "campo □ vazio"  # e relê do cache


def test_cached_analysis_survives_cache_write_failure(monkeypatch, tmp_path):
    pdf = tmp_path / "a.pdf"
    pdf.write_bytes(b"%PDF-1.4 x")
    monkeypatch.setattr(docs, "analyze_document", lambda content, name: {"markdown": "T"})

    def broken(*args, **kwargs):
        raise UnicodeEncodeError("charmap", "□", 0, 1, "character maps to <undefined>")

    monkeypatch.setattr(docs.Path, "write_text", broken)
    assert docs.cached_analysis(pdf)["markdown"] == "T"  # a leitura não cai por causa do cache
    assert not (tmp_path / "a.pdf.text.json").exists()  # nada de cache vazio
    assert not list(tmp_path.glob(".*partial"))


def test_safe_name_is_portable():
    assert docs.safe_name("Despacho de Análise.pdf") == "Despacho_de_Analise.pdf"
    assert docs.safe_name("../../etc/passwd") == "passwd"
    assert docs.safe_name("..\\dir\\ç ã.pdf") == "c_a.pdf"
    assert docs.safe_name("___.pdf") == "pdf"
    assert docs.safe_name("") == ""
    long = docs.safe_name("a" * 300 + ".pdf")
    assert len(long) == 128 and long.endswith(".pdf")
    for raw in ("Relatório 74062872.pdf", "x y", "😀.pdf"):
        name = docs.safe_name(raw)
        assert not name or docs.SAFE_NAME.fullmatch(name)


def test_save_bytes_reports_saved_as_with_a_portable_name(tmp_path):
    meta = docs.save_bytes(b"1", "Despacho de Análise.pdf", "fb.bin", tmp_path)
    assert meta["savedAs"] == meta["filename"] == "Despacho_de_Analise.pdf"
    assert (tmp_path / "Despacho_de_Analise.pdf").is_file()
    fallback = docs.save_bytes(b"2", "😀", "123-9.bin", tmp_path)
    assert fallback["savedAs"] == "123-9.bin"
