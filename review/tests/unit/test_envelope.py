import json

import pytest

from oc_review import envelope
from oc_review.envelope import (
    MAX_ENVELOPE_BYTES,
    EnvelopeError,
    check_digest,
    read_artifact,
    sha256_hex,
)

NAME = "bundle.json"


def write(tmp_path, doc, name=NAME):
    data = doc if isinstance(doc, bytes) else json.dumps(doc).encode()
    (tmp_path / name).write_bytes(data)
    return data


def read(tmp_path, data, **kw):
    return read_artifact(tmp_path, expected_name=NAME, expected_digest=sha256_hex(data), **kw)


def padded(good_envelope, size):
    """Valid envelope JSON of exactly `size` bytes."""
    base = json.dumps({**good_envelope, "payload": {"p": ""}}).encode()
    pad = size - len(base)
    assert pad >= 0
    data = json.dumps({**good_envelope, "payload": {"p": "x" * pad}}).encode()
    assert len(data) == size
    return data


def test_reads_valid_artifact(tmp_path, good_envelope):
    data = write(tmp_path, good_envelope)
    assert read(tmp_path, data) == good_envelope


def test_digest_accepts_prefix_and_case(tmp_path):
    d = b"abc"
    check_digest(d, sha256_hex(d))
    check_digest(d, "sha256:" + sha256_hex(d).upper())


def test_digest_mismatch(tmp_path, good_envelope):
    data = write(tmp_path, good_envelope)
    with pytest.raises(EnvelopeError, match="digest mismatch"):
        read_artifact(tmp_path, expected_name=NAME, expected_digest=sha256_hex(data + b" "))


@pytest.mark.parametrize("bad", ["", "sha256:abc", "md5:" + "0" * 32, "z" * 64])
def test_digest_malformed(bad):
    with pytest.raises(EnvelopeError, match="malformed"):
        check_digest(b"x", bad)


def test_digest_checked_before_parse(tmp_path):
    data = write(tmp_path, b"not json")
    with pytest.raises(EnvelopeError, match="digest mismatch"):
        read_artifact(tmp_path, expected_name=NAME, expected_digest="0" * 64)
    with pytest.raises(EnvelopeError, match="invalid JSON"):
        read(tmp_path, data)


def test_file_count_at_limit_passes_and_over_fails(tmp_path, good_envelope):
    data = write(tmp_path, good_envelope)
    assert envelope.MAX_FILES == 1
    read(tmp_path, data)  # at limit
    (tmp_path / "extra.json").write_text("{}")  # limit + 1
    with pytest.raises(EnvelopeError, match="extra file"):
        read(tmp_path, data)


def test_extra_directory_counts(tmp_path, good_envelope):
    data = write(tmp_path, good_envelope)
    (tmp_path / "sub").mkdir()
    with pytest.raises(EnvelopeError, match="extra file"):
        read(tmp_path, data)


def test_missing_file(tmp_path):
    with pytest.raises(EnvelopeError, match="missing file"):
        read_artifact(tmp_path, expected_name=NAME, expected_digest="0" * 64)


def test_wrong_name_single_file(tmp_path, good_envelope):
    data = write(tmp_path, good_envelope, name="other.json")
    with pytest.raises(EnvelopeError, match="missing file"):
        read(tmp_path, data)


def test_missing_directory(tmp_path):
    with pytest.raises(EnvelopeError, match="directory missing"):
        read_artifact(tmp_path / "nope", expected_name=NAME, expected_digest="0" * 64)


def test_symlink_rejected(tmp_path, good_envelope):
    target = tmp_path / "elsewhere"
    target.mkdir()
    data = write(target, good_envelope, name="real.json")
    d = tmp_path / "dl"
    d.mkdir()
    (d / NAME).symlink_to(target / "real.json")
    with pytest.raises(EnvelopeError, match="not a regular file"):
        read(d, data)


def test_size_cap_at_limit_passes_and_over_fails(tmp_path, good_envelope):
    cap = 2048
    data = padded(good_envelope, cap)  # at limit
    write(tmp_path, data)
    assert read(tmp_path, data, max_bytes=cap)["kind"] == "bundle"
    data = padded(good_envelope, cap + 1)  # limit + 1
    write(tmp_path, data)
    with pytest.raises(EnvelopeError, match="over size cap"):
        read(tmp_path, data, max_bytes=cap)


def test_default_size_cap_value():
    assert MAX_ENVELOPE_BYTES == 16 * 1024 * 1024


def test_size_cap_checked_before_digest(tmp_path):
    write(tmp_path, b"x" * 11)
    with pytest.raises(EnvelopeError, match="over size cap"):
        read_artifact(tmp_path, expected_name=NAME, expected_digest="0" * 64, max_bytes=10)


@pytest.mark.parametrize(
    "raw",
    [b"\xff\xfe", b'{"a": 1, "a": 2}', b'{"a": NaN}', b"[1, 2", b""],
)
def test_invalid_json_rejected(tmp_path, raw):
    write(tmp_path, raw)
    with pytest.raises(EnvelopeError, match="invalid JSON"):
        read(tmp_path, raw)


def test_schema_failure_after_digest(tmp_path, good_envelope):
    bad = {**good_envelope, "extra": 1}
    data = write(tmp_path, bad)
    with pytest.raises(EnvelopeError, match="envelope schema"):
        read(tmp_path, data)


def test_pass_ok_payload_must_match_findings(tmp_path, good_envelope):
    bad = {**good_envelope, "kind": "pass", "pass": "review", "payload": {"summary": "x"}}
    data = write(tmp_path, bad)
    with pytest.raises(EnvelopeError, match="findings schema"):
        read(tmp_path, data)
