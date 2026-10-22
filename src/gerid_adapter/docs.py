"""Leitura local dos documentos baixados: texto do PDF em janelas paginadas.

Espelha o padrão do conector (janela inicial + `gerid_read_document` para
continuar): o agente recebe o texto extraído em vez do binário, e analisa,
resume ou destaca o importante a partir dele.
"""

import base64
import binascii
import json
import os
import re
import unicodedata
from io import BytesIO
from pathlib import Path

MAX_TEXT_CHARS = 500_000
MAX_DOWNLOAD_BYTES = 50 * 1024 * 1024


def attachment_mime_type(content, filename):
    if content[:5] == b"%PDF-":
        return "application/pdf"
    if content[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if content[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    return {".txt": "text/plain", ".csv": "text/csv", ".json": "application/json"}.get(
        Path(filename).suffix.lower(), "application/octet-stream"
    )


def decode_download(data):
    """Base64 da API em bytes (o portal devolve o arquivo assim)."""
    if not isinstance(data, str) or not data.strip():
        raise ValueError("resposta de download vazia ou inválida")
    try:
        content = base64.b64decode(re.sub(r"\s+", "", data))
    except binascii.Error:
        raise ValueError("resposta de download vazia ou inválida") from None
    if not content:
        raise ValueError("resposta de download vazia ou inválida")
    if len(content) > MAX_DOWNLOAD_BYTES:
        raise ValueError(f"download excede o limite de {MAX_DOWNLOAD_BYTES} bytes")
    return content


SIDECAR_SUFFIX = ".text.json"


SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")


def safe_name(filename):
    """Nome de arquivo portável: letras ASCII, dígitos, ponto, hífen e sublinhado, até 128 caracteres.

    Outros sistemas (ex.: o anexo de tarefas do Advbox) só aceitam arquivos por nomes assim.
    Acentos viram a letra base e o resto vira "_".
    """
    base = os.path.basename((filename or "").replace("\\", "/"))
    ascii_name = unicodedata.normalize("NFKD", base).encode("ascii", "ignore").decode("ascii")
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", ascii_name).lstrip("._-")
    stem, dot, ext = name.rpartition(".")
    if dot and len(name) > 128:
        name = stem[: 128 - len(ext) - 1] + "." + ext
    return name[:128]


def save_bytes(content, filename, fallback, directory, overwrite=False):
    """Salva e devolve os metadados. Sem `overwrite`, não sobrescreve (sufixos -1, -2...).

    `overwrite` serve aos nomes canônicos (ex.: `<protocolo>-processo.pdf`): a cópia
    nova substitui a antiga de forma atômica em vez de acumular duplicatas.
    """
    name = safe_name(filename)
    if not name or name.endswith(SIDECAR_SUFFIX):
        name = safe_name(fallback) or "documento.bin"
    folder = Path(directory)
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    output = folder / name
    if overwrite:
        partial = folder / f".{name}.partial"
        partial.write_bytes(content)
        os.chmod(partial, 0o600)
        os.replace(partial, output)
        return {"path": str(output), "filename": output.name, "savedAs": output.name, "bytes": len(content)}
    counter = 0
    while output.exists():
        counter += 1
        output = folder / f"{output.stem}-{counter}{output.suffix}"
    with open(output, "xb") as handle:
        handle.write(content)
    os.chmod(output, 0o600)
    return {"path": str(output), "filename": output.name, "savedAs": output.name, "bytes": len(content)}


def cached_analysis(path, content=None):
    """Texto extraído com cache ao lado do arquivo (`<nome>.text.json`, 0600).

    Ler um PDF longo em janelas reprocessava o arquivo inteiro a cada janela;
    o cache vale enquanto for mais novo que o arquivo.
    """
    path = Path(path)
    sidecar = path.with_name(path.name + SIDECAR_SUFFIX)
    try:
        if sidecar.stat().st_mtime >= path.stat().st_mtime:
            return json.loads(sidecar.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        pass
    parsed = analyze_document(content if content is not None else path.read_bytes(), path.name)
    # UTF-8 explícito: no Windows o padrão é cp1252 e caracteres de PDF digitalizado ("□")
    # não cabem. Grava num temporário e troca de uma vez: falha nunca deixa cache vazio,
    # e o cache é só atalho, então falhar nele não derruba a leitura.
    partial = sidecar.with_name(f".{sidecar.name}.partial")
    try:
        partial.write_text(json.dumps(parsed, ensure_ascii=False), encoding="utf-8")
        os.chmod(partial, 0o600)
        os.replace(partial, sidecar)
    except (OSError, ValueError):
        partial.unlink(missing_ok=True)
    return parsed


def _page_has_images(page):
    try:
        resources = page.get("/Resources") or {}
        xobjects = resources.get("/XObject") or {}
        for value in xobjects.values():
            if value.get_object().get("/Subtype") == "/Image":
                return True
    except Exception:
        pass
    return False


def analyze_document(content, filename, max_text_chars=MAX_TEXT_CHARS):
    """Texto extraído do PDF (pypdf). Escaneados sem texto voltam com `needsOcr`."""
    mime_type = attachment_mime_type(content, filename)
    if mime_type != "application/pdf":
        return {"mimeType": mime_type}
    try:
        from pypdf import PdfReader
    except ImportError:
        return {"mimeType": mime_type, "pdfExtractionError": "pypdf não instalado"}
    try:
        reader = PdfReader(BytesIO(content))
    except Exception as error:
        return {"mimeType": mime_type, "pdfExtractionError": str(error)[:200]}
    if reader.is_encrypted:
        try:
            opened = bool(reader.decrypt(""))
        except Exception:
            opened = False
        if not opened:
            return {"mimeType": mime_type, "pdfExtractionError": "PDF criptografado"}
    texts, size, limit = [], 0, max(1, int(max_text_chars))
    for page in reader.pages:
        try:
            text = page.extract_text() or ""
        except Exception:
            text = ""
        texts.append(text)
        size += len(text)
        if size >= limit:
            break
    markdown = "\n\n".join(" ".join(part.split()) for part in texts if part.strip())
    return {
        "mimeType": mime_type,
        "markdown": markdown[:limit],
        "textCharacters": len(markdown),
        "textTruncated": len(markdown) > limit,
        "pageCount": len(reader.pages),
        "needsOcr": not markdown and any(_page_has_images(page) for page in reader.pages),
    }


def slice_text(parsed, offset=0, max_chars=40_000):
    """Uma janela do texto e onde continua (`nextOffset`, None no fim)."""
    parsed = dict(parsed)
    markdown = parsed.pop("markdown", "") or ""
    window = markdown[offset : offset + max_chars]
    end = offset + len(window)
    return {
        **parsed,
        "markdown": window,
        "offset": offset,
        "textReturnedCharacters": len(window),
        "nextOffset": end if end < len(markdown) else None,
        "textTruncated": end < len(markdown) or bool(parsed.get("textTruncated")),
    }


def read_saved_document(filename, offset=0, max_chars=40_000, directory=None):
    """Lê um arquivo já baixado (só o nome-base dentro da pasta de downloads)."""
    if (
        not isinstance(filename, str)
        or filename in ("", ".", "..")
        or Path(filename).name != filename
        or "\\" in filename
    ):
        raise ValueError("filename deve ser só o nome do arquivo na pasta de downloads")
    if offset < 0 or max_chars < 1:
        raise ValueError("offset começa em 0 e max_chars é ao menos 1")
    folder = Path(directory).resolve() if directory else None
    if folder is None:
        raise ValueError("diretório de downloads não informado")
    path = (folder / filename).resolve()
    if path.parent != folder or not path.is_file():
        raise FileNotFoundError(f"{filename} não está na pasta de downloads")
    content = path.read_bytes()
    mime_type = attachment_mime_type(content, filename)
    parsed = cached_analysis(path, content) if mime_type == "application/pdf" else {}
    return {"filename": filename, "bytes": len(content), "mimeType": mime_type,
            **slice_text(parsed, offset, max_chars)}
