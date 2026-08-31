from __future__ import annotations

import hashlib
import json
import struct
from typing import Any


def canonical_json_bytes(value: Any) -> bytes:
    """Match AccordLock's recursively key-sorted, compact UTF-8 JSON profile."""
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_digest(value: bytes) -> str:
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def json_digest(value: Any) -> str:
    return sha256_digest(canonical_json_bytes(value))


def length_prefixed_domain_digest(domain: bytes, value: Any) -> str:
    encoded = canonical_json_bytes(value)
    payload = domain + b"\x00" + struct.pack(">Q", len(encoded)) + encoded
    return sha256_digest(payload)
