"""Artifact envelope schema and checks.

A consumer calls `read_artifact` on a download directory. It rejects a missing
file, an extra file or a file over the size cap, checks the SHA-256 digest
before it parses anything, then validates the envelope against the schema.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SCHEMA_DIR = Path(__file__).resolve().parents[2] / "schema"

# One artifact holds exactly one file.
MAX_FILES = 1
# Byte cap on the envelope file, applied before the digest and before parsing.
MAX_ENVELOPE_BYTES = 16 * 1024 * 1024

_DIGEST_RE = re.compile(r"^(?:sha256:)?([0-9a-fA-F]{64})$")


class EnvelopeError(Exception):
    """The artifact or envelope is not acceptable. The gate fails closed."""


@lru_cache(maxsize=None)
def _validator(name: str) -> Draft202012Validator:
    schema = json.loads((SCHEMA_DIR / f"{name}.schema.json").read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def _first_error(name: str, doc: Any) -> str | None:
    errors = sorted(_validator(name).iter_errors(doc), key=lambda e: list(e.absolute_path))
    if not errors:
        return None
    e = errors[0]
    where = "/".join(str(p) for p in e.absolute_path) or "<root>"
    return f"{where}: {e.message[:200]}"


def validate_findings(doc: Any) -> None:
    err = _first_error("findings", doc)
    if err:
        raise EnvelopeError(f"findings schema: {err}")


def validate_envelope(doc: Any) -> None:
    """Check the envelope against the schema. A `pass` record with status `ok`
    also carries a payload that must match the findings schema."""
    err = _first_error("envelope", doc)
    if err:
        raise EnvelopeError(f"envelope schema: {err}")
    if doc["kind"] == "pass" and doc["status"] == "ok":
        validate_findings(doc["payload"])


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def check_digest(data: bytes, expected: str) -> None:
    """Compare the SHA-256 of `data` with `expected` (`sha256:<hex>` or bare hex)."""
    m = _DIGEST_RE.match(expected or "")
    if not m:
        raise EnvelopeError("digest: malformed expected digest")
    if not hmac.compare_digest(sha256_hex(data), m.group(1).lower()):
        raise EnvelopeError("digest mismatch")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise ValueError(f"duplicate key {k!r}")
        out[k] = v
    return out


def _reject_constant(name: str) -> Any:
    raise ValueError(f"non-finite number {name}")


def parse_json(data: bytes) -> Any:
    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise EnvelopeError(f"invalid JSON: {exc}") from exc


def read_artifact(
    directory: Path | str,
    *,
    expected_name: str,
    expected_digest: str,
    max_bytes: int = MAX_ENVELOPE_BYTES,
    max_files: int = MAX_FILES,
) -> dict[str, Any]:
    """Read and validate the envelope in one download directory.

    Order: file count, name, type, size, digest, parse, schema.
    """
    d = Path(directory)
    if not d.is_dir():
        raise EnvelopeError("artifact directory missing")
    entries = list(d.iterdir())
    if len(entries) > max_files:
        raise EnvelopeError(f"extra file: {len(entries)} entries, cap {max_files}")
    path = d / expected_name
    if not any(e.name == expected_name for e in entries):
        raise EnvelopeError(f"missing file {expected_name}")
    if path.is_symlink() or not path.is_file():
        raise EnvelopeError(f"{expected_name} is not a regular file")
    if path.stat().st_size > max_bytes:
        raise EnvelopeError(f"{expected_name} over size cap {max_bytes}")
    with path.open("rb") as fh:
        data = fh.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise EnvelopeError(f"{expected_name} over size cap {max_bytes}")
    check_digest(data, expected_digest)
    doc = parse_json(data)
    validate_envelope(doc)
    return doc
