"""Selected functions from EvickaStudio/BypassV3 (Apache-2.0).

Source: https://github.com/EvickaStudio/BypassV3/blob/a571c3a516ae092e6978f45e26da19ad98efa271/bypass.py
Adaptation: only the protobuf encoder and response parser are included.
"""

import json
import re


# Minimal protobuf writer for /api2/reload.
def _encode_varint(value: int) -> bytes:
    if value < 0:
        value += 1 << 64
    out = bytearray()
    while value >= 0x80:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def _encode_field(field: int, wire: int, payload: bytes) -> bytes:
    tag = _encode_varint((field << 3) | wire)
    if wire == 2:
        return tag + _encode_varint(len(payload)) + payload
    if wire == 0:
        return tag + payload
    raise ValueError(f"unsupported wire type {wire}")


def _encode_string_field(field: int, text: str) -> bytes:
    return _encode_field(field, 2, text.encode("utf-8"))


def _encode_int_field(field: int, value: int) -> bytes:
    return _encode_field(field, 0, _encode_varint(value))


def encode_reload_body(
    *,
    v: str,
    c: str,
    k: str,
    action: str | None,
    fingerprint: dict | None,
    reason: str = "q",
) -> bytes:
    """Build the protobuf reload body, optionally with captured fingerprint fields."""
    body = bytearray()
    body += _encode_string_field(1, v)
    body += _encode_string_field(2, c)
    body += _encode_string_field(6, reason)
    if action:
        body += _encode_string_field(8, action)
    body += _encode_string_field(14, k)
    if fingerprint:
        for f in (5, 7, 16, 20, 22, 25):
            if val := fingerprint.get(str(f)) or fingerprint.get(f):
                body += _encode_string_field(f, val)
        for f in (28, 29):
            val = fingerprint.get(str(f)) or fingerprint.get(f)
            if val is not None:
                body += _encode_int_field(f, int(val))
    return bytes(body)


def parse_reload_response(text: str) -> str | None:
    """Extract the rresp token from JSON, with Google's XSSI guard stripped."""
    text = text.lstrip().removeprefix(")]}'").lstrip()
    try:
        arr = json.loads(text)
    except json.JSONDecodeError:
        m = re.search(r'\["rresp","(.*?)"', text)
        return m[1] if m else None
    if isinstance(arr, list) and len(arr) >= 2 and arr[0] == "rresp":
        token = arr[1]
        return token if isinstance(token, str) else None
    return None
