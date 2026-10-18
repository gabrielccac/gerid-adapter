"""Extração de texto e janelas, com PDF mínimo construído aqui (sem rede)."""

import base64

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
    assert (tmp_path / "x.pdf").stat().st_mode & 0o777 == 0o600
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
    assert (tmp_path / "a.pdf.text.json").stat().st_mode & 0o777 == 0o600


def test_save_bytes_overwrite_replaces_canonical(tmp_path):
    from gerid_adapter import docs

    docs.save_bytes(b"v1", "p.pdf", "p.pdf", tmp_path, overwrite=True)
    meta = docs.save_bytes(b"v2", "p.pdf", "p.pdf", tmp_path, overwrite=True)
    assert meta["filename"] == "p.pdf" and (tmp_path / "p.pdf").read_bytes() == b"v2"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["p.pdf"]
