"""OCR do desafio de imagem do portal (428 da busca).

O captcha é um PNG 160x60 com 4 caracteres distorcidos e ruído. O ddddocr
(ONNX local, sem serviço externo) lê o texto; o portal compara em caixa alta,
por isso normalizamos. O envio da solução é feito pelo `api.search_tasks_challenge`
(query `tokenDesafio` + id no corpo).
"""

_ENGINE = None


def _engine():
    global _ENGINE
    if _ENGINE is None:
        try:
            import ddddocr
        except ImportError:
            raise RuntimeError(
                "Resolução do captcha de imagem indisponível: instale o OCR "
                "(`uv pip install ddddocr`) ou use o fallback headed."
            ) from None
        _ENGINE = ddddocr.DdddOcr(show_ad=False)
    return _ENGINE


def solve(png):
    """Texto do desafio a partir do PNG (bytes), em caixa alta."""
    if not png:
        raise ValueError("imagem do captcha vazia")
    text = _engine().classification(png)
    text = (text or "").strip().upper()
    if not text:
        raise RuntimeError("OCR não leu o captcha de imagem.")
    return text
