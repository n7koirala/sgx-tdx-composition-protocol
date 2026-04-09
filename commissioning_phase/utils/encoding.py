"""
Encoding and serialization helpers for the CVM commissioning phase.
"""

import base64


def bytes_to_base64_str(data: bytes) -> str:
    """Encode bytes to a base64-encoded UTF-8 string."""
    return base64.b64encode(data).decode("utf-8")


def decode_base64(input_str: str) -> bytes:
    """Decode a base64-encoded string to bytes.

    If the input is not valid base64, returns the original string as bytes.
    """
    v = input_str.encode("utf-8")
    if len(v) % 4 != 0:
        return v
    try:
        return base64.b64decode(v)
    except Exception:
        return v


def stringify(data) -> str:
    """Convert bytes or other objects to a string representation.

    For bytes, returns the UTF-8 decoded string (with replacement for
    invalid sequences). For other types, returns str().
    """
    if isinstance(data, bytes):
        return data.decode("utf-8", errors="replace")
    return str(data)
