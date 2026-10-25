"""Deterministic prefilter checks and coverage (spec "Prefilter checks (no LLM)"
and "Coverage limits").

No LLM reads anything here, and nothing here fetches, runs or writes PR
content. Inputs are in memory: the tree diff from `snapshot.diff_trees`, the
blobs by SHA, and the dependency facts that collect builds with `deps.py`.

Rules this module keeps:

- Every changed text blob is scanned in full, up to `MAX_BLOB_BYTES`, whatever
  its line count. A blob that cannot be read, decoded as UTF-8 text, or is over
  the cap has coverage `unavailable`, which is the hard block "incomplete
  coverage".
- Hard blocks are decided here, by code. Claude output cannot clear them.
- Evidence never carries a credential value. Fields that hold PR text
  (`file`, `subject`) are untrusted; the publisher escapes them.
"""

from __future__ import annotations

import bisect
import codecs
import hashlib
import json
import re
import tomllib
import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta
from typing import Any, Literal

from oc_review import deps
from oc_review.snapshot import MODE_SUBMODULE, MODE_SYMLINK, ChangedFile, TreeDiff

# Hard cap on the bytes of one blob that the prefilter scans. Matches the cap
# on one dependency file in deps.py, so a lockfile deps.py can parse is never
# over this cap.
MAX_BLOB_BYTES = 16 * 1024 * 1024
# A blob is binary when its first bytes hold a NUL and it is not valid UTF-8
# (the same window git uses to call a file binary).
BINARY_SNIFF_BYTES = 8000
# Line numbers kept per check and file; `count` keeps the full total.
MAX_LINES_PER_CHECK = 20
# A package version published less than this long ago is a hard block.
FRESH_PUBLISH_WINDOW = timedelta(hours=72)
LONG_LINE_CHARS = 500
BLOB_RUN_CHARS = 200

Level = Literal["hard_block", "signal"]
CoverageKind = Literal["full", "binary", "unavailable"]

HARD_BLOCK: Level = "hard_block"
SIGNAL: Level = "signal"

# Check IDs. The gate only reads the level; the IDs are for the summary.
BIDI_CONTROL = "bidi-control"
BIDI_PATH = "bidi-control-in-path"
FOREIGN_SOURCE = "foreign-source"
FRESH_PUBLISH = "fresh-publish"
INCOMPLETE_COVERAGE = "incomplete-coverage"
INCOMPLETE_DEP_DATA = "incomplete-dependency-data"
ZERO_WIDTH = "zero-width"
INVISIBLE_CHAR = "invisible-character"
AI_DIRECTED_TEXT = "ai-directed-text"
CREDENTIAL = "credential-like-string"
INSTALL_SCRIPT_DEP = "dependency-install-script"
INSTALL_SCRIPT_CHANGE = "package-json-install-script"
SDIST_ONLY = "pypi-sdist-only"
MANIFEST_WITHOUT_LOCKFILE = "manifest-without-lockfile"
UNSUPPORTED_DEP_FILE = "unsupported-dependency-file"
SENSITIVE_PATH = "sensitive-path"
BUILD_SYSTEM_CHANGE = "pyproject-build-system"
BINARY_ADDED = "binary-file"
SUBMODULE = "submodule-change"
EXECUTABLE = "became-executable"
MINIFIED_JS = "minified-js"
LONG_LINE = "long-line"
ENCODED_BLOB = "encoded-blob"
FIRST_TIME_AUTHOR = "first-time-contributor"

# --- character classes ------------------------------------------------------

# Spec: U+202A to U+202E and U+2066 to U+2069 (Trojan Source).
_BIDI_RE = re.compile("[‪-‮⁦-⁩]")
# Spec: U+200B to U+200D, U+2060, U+FEFF (FEFF allowed at file start only).
_ZERO_WIDTH_RE = re.compile("[​-‍⁠﻿]")
# Coordinator-approved addition (see report "Spec follow-up"): invisible
# characters the zero-width row misses. FE00-FE0F are left out: emoji use them.
_INVISIBLE_RE = re.compile(
    "[­͏؜ᅟᅠ᠎‎‏⁡-⁤ㅤﾠ"
    "\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)

_BOMS_UNSUPPORTED = (
    b"\xff\xfe\x00\x00",  # UTF-32 LE
    b"\x00\x00\xfe\xff",  # UTF-32 BE
    b"\xff\xfe",  # UTF-16 LE
    b"\xfe\xff",  # UTF-16 BE
)
# PEP 263 coding cookie, first two lines only.
_CODING_RE = re.compile(rb"^[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)", re.ASCII)
_UTF8_CODECS = frozenset({"utf-8", "utf-8-sig", "ascii"})

# --- credentials --------------------------------------------------------------

# (kind, pattern). Matches are reported by kind and location only.
CREDENTIAL_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (kind, re.compile(pattern, re.ASCII))
    for kind, pattern in (
        ("private-key", r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"),
        ("github-token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})"),
        ("aws-access-key-id", r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
        ("anthropic-key", r"\bsk-ant-[A-Za-z0-9_-]{20,}"),
        ("openai-key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}"),
        ("slack-token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}"),
        ("slack-webhook", r"https://hooks\.slack\.com/services/[A-Za-z0-9/_-]{20,}"),
        ("google-api-key", r"\bAIza[0-9A-Za-z_-]{35}"),
        ("stripe-key", r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}"),
        ("npm-token", r"\bnpm_[A-Za-z0-9]{36}\b"),
        ("pypi-token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}"),
        ("gitlab-token", r"\bglpat-[A-Za-z0-9_-]{20,}"),
        ("sendgrid-key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b"),
        ("jwt", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    )
)

# --- text that addresses an AI or reviewer ------------------------------------

# Patterns run on normalized text (see `normalize_for_match`): NFKD, no marks or
# format characters, casefolded, common homoglyphs folded to Latin, and runs of
# whitespace and light punctuation collapsed to one space.
_AI_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = tuple(
    (name, re.compile(pattern))
    for name, pattern in (
        (
            "ignore-instructions",
            r"\b(?:ignore|disregard|forget|override) (?:(?:all|any|the|previous|prior|above|earlier"
            r"|your|of|these|those|system) ){1,4}(?:instructions?|rules|guidelines|prompts?)\b",
        ),
        ("as-an-ai", r"\bas an ai\b"),
        ("system-prompt", r"\bsystem prompt\b"),
        ("you-are-now", r"\byou are (?:now )?an? \w"),
        ("reviewer-address", r"\breviewer ?:"),
        ("ai-reviewer", r"\b(?:ai|llm|claude|gpt|chatgpt|model) (?:reviewer|assistant|agent)\b"),
        ("system-tag", r"< ?/? ?system ?>"),
        ("instructions-tag", r"< ?/ ?instructions ?>"),
        ("delimiter-tag", r"< ?/? ?untrusted pr"),
        ("chat-template", r"<\|(?:im start|im end|system|endoftext)\|>|\[/?inst\]"),
    )
)

# Lowercase Cyrillic and Greek letters that look like Latin ones.
_HOMOGLYPHS = str.maketrans(
    {
        "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "һ": "h", "і": "i", "ј": "j",
        "к": "k", "ӏ": "l", "м": "m", "н": "h", "о": "o", "р": "p", "ԛ": "q", "ѕ": "s",
        "т": "t", "у": "y", "ԝ": "w", "х": "x", "ү": "y",
        "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t",
        "υ": "u", "χ": "x", "ѵ": "v",
    }
)
_SEPARATORS_RE = re.compile(r"[\s_\-*~.,'\"`+]+")
_COMMENT_LEADER_RE = re.compile(r"^\s*(?:#+|//+|/\*+|\*+/?|--+|<!--|;+|%+|>+)\s*")
_DROP_CATEGORIES = frozenset({"Mn", "Me", "Cf"})

# --- encoded blobs ----------------------------------------------------------

_B64_CLASS = r"A-Za-z0-9+/=_\-"
_B64_RUN_RE = re.compile(rf"(?<![{_B64_CLASS}])[{_B64_CLASS}]{{{BLOB_RUN_CHARS + 1},}}")
_HEX_ONLY_RE = re.compile(r"[0-9A-Fa-f]+")
_ESCAPED_RUN_RE = re.compile(
    r"(?:\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|%[0-9A-Fa-f]{2}|0x[0-9A-Fa-f]{2}, ?)+"
)
# One line of a base64 blob that was wrapped over several lines.
_WRAPPED_B64_LINE_RE = re.compile(r"^\s*[\"'`]?([A-Za-z0-9+/]{40,}={0,2})[\"'`]?\s*[,;+]?\s*$")

# --- paths ------------------------------------------------------------------

# Install lifecycle scripts that run on `npm install` in the package root. The
# spec names the first four; the others also run on install.
_INSTALL_SCRIPTS = ("preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish")
# Dependency files deps.py does not parse yet, on top of deps.UNSUPPORTED_DEP_FILES.
_EXTRA_UNSUPPORTED_DEP_FILES = frozenset({"npm-shrinkwrap.json", ".pnpmfile.cjs", "deno.json", "deno.lock"})
_JS_SUFFIXES = (".js", ".mjs", ".cjs")
_BUNDLE_MARKERS = ("__webpack_require__", "__webpack_modules__", "/******/", "parcelRequire", "//# sourceMappingURL=")


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Check:
    """One prefilter result. One record per check, file and subject.

    `file` and `subject` hold PR text (paths, package names, versions) and are
    untrusted. `detail` is built by this module only. No field ever holds a
    credential value or the matched text of a content check.
    """

    id: str
    level: Level
    detail: str
    file: str | None = None
    subject: str | None = None
    lines: tuple[int, ...] = ()
    count: int = 1


@dataclass(frozen=True)
class FileCoverage:
    path: str
    coverage: CoverageKind
    reason: str | None = None  # why `unavailable`


@dataclass(frozen=True)
class Coverage:
    trees_complete: bool
    files_in_comparison: int
    files_collected: int
    files: tuple[FileCoverage, ...]

    @property
    def complete(self) -> bool:
        return self.trees_complete and all(f.coverage != "unavailable" for f in self.files)


@dataclass(frozen=True)
class PrefilterResult:
    signals: tuple[Check, ...]
    hard_blocks: tuple[Check, ...]
    coverage: Coverage

    def to_dict(self) -> dict[str, Any]:
        """JSON-ready form for the bundle."""
        return {
            "signals": [asdict(c) for c in self.signals],
            "hard_blocks": [asdict(c) for c in self.hard_blocks],
            "coverage": {**asdict(self.coverage), "complete": self.coverage.complete},
        }


@dataclass(frozen=True)
class DepFailure:
    """A supported dependency file that did not parse, has an unknown format
    version, or a registry lookup that still failed after retries."""

    path: str
    reason: str


@dataclass(frozen=True)
class DependencyFacts:
    """What collect hands the prefilter, built with deps.py.

    - `parsed_paths`: changed supported files (deps.family_for_path) that
      parsed at the head. A changed supported file that is in neither this set
      nor `failures` is incomplete dependency data.
    - `changes`: deps.compute_delta for every parsed changed file.
    - `new_global_sources`: file-wide sources (pip index URLs) at the head that
      are not at the merge base.
    - `registry`: lookup results by (ecosystem, name, version) for every change
      where `needs_registry_lookup` is true.
    - `has_wheel`: PyPI (name, version) -> whether the version has a wheel.
      deps.lookup_pypi does not report it yet; a missing key gives no signal.
    """

    parsed_paths: frozenset[str] = frozenset()
    changes: Sequence[deps.PackageChange] = ()
    new_global_sources: Sequence[deps.SourceIssue] = ()
    registry: Mapping[tuple[str, str, str], deps.RegistryInfo] = field(default_factory=dict)
    has_wheel: Mapping[tuple[str, str], bool] = field(default_factory=dict)
    failures: Sequence[DepFailure] = ()


@dataclass(frozen=True)
class BlobScan:
    """How the prefilter sees one blob."""

    kind: CoverageKind
    text: str | None = None  # set for `full` only
    reason: str | None = None  # set for `unavailable` only


# ---------------------------------------------------------------------------
# Blobs and coverage
# ---------------------------------------------------------------------------


def git_blob_sha(data: bytes, sha_len: int = 40) -> str:
    """Git object ID of a blob: SHA-1 (40 hex) or SHA-256 (64 hex)."""
    algo = hashlib.sha1 if sha_len == 40 else hashlib.sha256
    h = algo(f"blob {len(data)}\0".encode())
    h.update(data)
    return h.hexdigest()


def _declared_codec(data: bytes) -> str | None:
    """The codec a PEP 263 cookie in the first two lines names, if it is real."""
    for line in data.split(b"\n", 2)[:2]:
        m = _CODING_RE.match(line)
        if m:
            try:
                return codecs.lookup(m.group(1).decode("ascii")).name
            except LookupError:
                return None  # Python refuses such a file; nothing hides behind it
    return None


def scan_blob(data: bytes | None, *, sha: str | None = None, cap: int = MAX_BLOB_BYTES) -> BlobScan:
    """Classify one blob as `full` text, `binary` or `unavailable`.

    Text is strict UTF-8 (a leading UTF-8 BOM is kept as U+FEFF). NUL bytes are
    allowed in text, so a NUL cannot hide a valid UTF-8 file from the scan.
    """
    if data is None:
        return BlobScan("unavailable", reason="unreadable")
    if sha is not None and git_blob_sha(data, len(sha)) != sha.lower():
        return BlobScan("unavailable", reason="sha-mismatch")
    if data.startswith(_BOMS_UNSUPPORTED):
        return BlobScan("unavailable", reason="utf16-or-utf32")
    has_nul = b"\0" in data[:BINARY_SNIFF_BYTES]
    if len(data) > cap:
        return BlobScan("binary") if has_nul else BlobScan("unavailable", reason="over-cap")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return BlobScan("binary") if has_nul else BlobScan("unavailable", reason="undecodable")
    if data.count(0) * 4 > len(data):
        # Valid UTF-8 but mostly NUL: UTF-16 or UTF-32 text without a BOM.
        return BlobScan("unavailable", reason="nul-heavy")
    codec = _declared_codec(data)
    if codec is not None and codec not in _UTF8_CODECS:
        return BlobScan("unavailable", reason="declared-encoding")
    return BlobScan("full", text=text)


def _file_coverage(change: ChangedFile, base: BlobScan | None, head: BlobScan | None) -> FileCoverage:
    sides = [s for s in (head, base) if s is not None]
    for s in sides:
        if s.kind == "unavailable":
            return FileCoverage(change.path, "unavailable", s.reason)
    primary = head if head is not None else base
    if primary is None or primary.kind == "binary":
        return FileCoverage(change.path, "binary")
    return FileCoverage(change.path, "full")


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------


class _Lines:
    """Line view of a text: lines split on LF only (git and GitHub line numbers)."""

    def __init__(self, text: str):
        self.text = text
        self.starts = [0]
        self.starts.extend(m.end() for m in re.finditer("\n", text))
        if self.starts[-1] == len(text) and len(self.starts) > 1:
            self.starts.pop()  # trailing newline: no empty last line
        self.lines = text.split("\n")
        if text.endswith("\n"):
            self.lines.pop()

    def line_of(self, offset: int) -> int:
        """1-based line number of a character offset."""
        return bisect.bisect_right(self.starts, offset)


def _added_lines(head: _Lines, base: _Lines | None) -> list[int]:
    """1-based head line numbers whose text is not a line of the base.

    Linear and safe on hostile input. It never misses new text; it can miss a
    second copy of a line the base already has, which adds no new content.
    """
    if base is None:
        return list(range(1, len(head.lines) + 1))
    seen = set(base.lines)
    return [i for i, line in enumerate(head.lines, 1) if line not in seen]


def normalize_for_match(text: str) -> str:
    """Fold Unicode tricks so a pattern sees what a human reads."""
    if not text.isascii():
        text = unicodedata.normalize("NFKD", text)
        text = "".join(c for c in text if unicodedata.category(c) not in _DROP_CATEGORIES)
    text = text.casefold().translate(_HOMOGLYPHS)
    return _SEPARATORS_RE.sub(" ", text)


def _ai_hits(lines: Sequence[tuple[int, str]]) -> dict[str, list[int]]:
    """Run the AI-directed patterns over runs of consecutive lines.

    Lines are joined, so a phrase split over lines or comment markers still
    matches. Returns pattern name -> line numbers of each match start.
    """
    hits: dict[str, list[int]] = {}
    run: list[tuple[int, str]] = []

    def flush() -> None:
        if not run:
            return
        starts: list[int] = []
        parts: list[str] = []
        pos = 0
        for _, raw in run:
            norm = normalize_for_match(_COMMENT_LEADER_RE.sub("", raw)).strip()
            starts.append(pos)
            parts.append(norm)
            pos += len(norm) + 1
        joined = " ".join(parts)
        for name, pattern in _AI_PATTERNS:
            for m in pattern.finditer(joined):
                idx = bisect.bisect_right(starts, m.start()) - 1
                hits.setdefault(name, []).append(run[idx][0])
        run.clear()

    prev = None
    for number, raw in lines:
        if prev is not None and number != prev + 1:
            flush()
        run.append((number, raw))
        prev = number
    flush()
    return hits


def find_credentials(text: str) -> list[tuple[str, int, int]]:
    """(kind, start, end) of every credential-like string. For redaction too."""
    out = []
    for kind, pattern in CREDENTIAL_PATTERNS:
        out.extend((kind, m.start(), m.end()) for m in pattern.finditer(text))
    return out


# ---------------------------------------------------------------------------
# Collector
# ---------------------------------------------------------------------------


class _Results:
    def __init__(self) -> None:
        self.items: list[Check] = []

    def add(
        self,
        check_id: str,
        level: Level,
        detail: str,
        *,
        file: str | None = None,
        subject: str | None = None,
        lines: Iterable[int] = (),
        count: int | None = None,
    ) -> None:
        line_list = sorted(set(lines))
        self.items.append(
            Check(
                id=check_id,
                level=level,
                detail=detail,
                file=file,
                subject=subject,
                lines=tuple(line_list[:MAX_LINES_PER_CHECK]),
                count=count if count is not None else max(1, len(line_list)),
            )
        )

    def lines_check(self, check_id: str, level: Level, detail: str, file: str, lines: list[int]) -> None:
        if lines:
            self.add(check_id, level, detail, file=file, lines=lines, count=len(lines))


def _codepoints(chars: Iterable[str]) -> str:
    return ", ".join(f"U+{ord(c):04X}" for c in sorted(set(chars)))


# ---------------------------------------------------------------------------
# Per-file checks
# ---------------------------------------------------------------------------


def _check_text(out: _Results, path: str, head: _Lines, added: list[int]) -> None:
    text = head.text
    added_set = set(added)

    # Bidi controls anywhere in the file: hard block.
    bidi = list(_BIDI_RE.finditer(text))
    if bidi:
        out.lines_check(
            BIDI_CONTROL, HARD_BLOCK,
            f"bidi control characters {_codepoints(m.group() for m in bidi)}",
            path, [head.line_of(m.start()) for m in bidi],
        )

    # Zero-width characters in changed lines (U+FEFF at file start is a BOM).
    zw = [m for m in _ZERO_WIDTH_RE.finditer(text) if not (m.start() == 0 and m.group() == "﻿")]
    zw_lines = [n for m in zw if (n := head.line_of(m.start())) in added_set]
    if zw_lines:
        chars = [m.group() for m in zw if head.line_of(m.start()) in added_set]
        out.lines_check(ZERO_WIDTH, SIGNAL, f"zero-width characters {_codepoints(chars)}", path, zw_lines)

    inv = [m for m in _INVISIBLE_RE.finditer(text) if head.line_of(m.start()) in added_set]
    if inv:
        out.lines_check(
            INVISIBLE_CHAR, SIGNAL,
            f"invisible characters {_codepoints(m.group() for m in inv)}",
            path, [head.line_of(m.start()) for m in inv],
        )

    # Credential-like strings in changed lines, by kind and location only.
    by_kind: dict[str, list[int]] = {}
    for kind, start, _ in find_credentials(text):
        n = head.line_of(start)
        if n in added_set:
            by_kind.setdefault(kind, []).append(n)
    for kind, lines in sorted(by_kind.items()):
        out.lines_check(CREDENTIAL, SIGNAL, f"{kind} (value redacted)", path, lines)

    # Text that addresses an AI or reviewer, in changed lines.
    for name, lines in sorted(_ai_hits([(n, head.lines[n - 1]) for n in added]).items()):
        out.lines_check(AI_DIRECTED_TEXT, SIGNAL, f"pattern {name}", path, lines)

    # Long lines and encoded blobs in changed lines.
    long_lines: list[int] = []
    blobs: dict[str, list[int]] = {}
    wrapped_run: list[int] = []
    wrapped_chars = 0

    def end_wrapped() -> None:
        nonlocal wrapped_chars
        if wrapped_chars > BLOB_RUN_CHARS and len(wrapped_run) > 1:
            blobs.setdefault("base64 (wrapped)", []).append(wrapped_run[0])
        wrapped_run.clear()
        wrapped_chars = 0

    prev = None
    for n in added:
        line = head.lines[n - 1].rstrip("\r")
        if len(line) > LONG_LINE_CHARS:
            long_lines.append(n)
        if len(line) > BLOB_RUN_CHARS:
            for m in _B64_RUN_RE.finditer(line):
                kind = "hex" if _HEX_ONLY_RE.fullmatch(m.group()) else "base64"
                blobs.setdefault(kind, []).append(n)
            for m in _ESCAPED_RUN_RE.finditer(line):
                if len(m.group()) > BLOB_RUN_CHARS:
                    blobs.setdefault("escaped hex", []).append(n)
        w = _WRAPPED_B64_LINE_RE.match(line) if len(line) >= 40 else None
        if w and prev is not None and n == prev + 1 and wrapped_run:
            wrapped_run.append(n)
            wrapped_chars += len(w.group(1))
        else:
            end_wrapped()
            if w:
                wrapped_run.append(n)
                wrapped_chars = len(w.group(1))
        prev = n
    end_wrapped()
    out.lines_check(LONG_LINE, SIGNAL, f"lines longer than {LONG_LINE_CHARS} characters", path, long_lines)
    for kind, lines in sorted(blobs.items()):
        out.lines_check(ENCODED_BLOB, SIGNAL, f"{kind} run longer than {BLOB_RUN_CHARS} characters", path, lines)


def _under_dist_or_build(path: str) -> bool:
    return any(part in ("dist", "build") for part in path.split("/")[:-1])


def _is_minified_js(path: str, head: _Lines) -> bool:
    name = path.rsplit("/", 1)[-1].lower()
    if name.endswith(tuple(".min" + s for s in _JS_SUFFIXES)):
        return True
    text = head.text
    if any(marker in text for marker in _BUNDLE_MARKERS):
        return True
    lines = [line for line in head.lines if line.strip()]
    if not lines:
        return False
    longest = max(len(line) for line in lines)
    return longest > 5000 or (len(text) >= 1024 and len(text) / len(lines) > 250)


def _sensitive_path(path: str) -> str | None:
    low = path.lower()
    name = low.rsplit("/", 1)[-1]
    if low.startswith(".github/workflows/") or "/.github/workflows/" in low:
        return "workflow"
    if low.startswith(".github/actions/") or "/.github/actions/" in low:
        return "action"
    if name.startswith("dockerfile") or name.endswith(".dockerfile") or name.startswith("containerfile"):
        return "Dockerfile"
    if name in ("makefile", "gnumakefile"):
        return "Makefile"
    if name == ".npmrc":
        return ".npmrc"
    if name.startswith(".yarnrc"):
        return ".yarnrc"
    if name == "setup.py":
        return "setup.py"
    if name == "codeowners":
        return "CODEOWNERS"
    return None


def _strict_json(text: str) -> Any:
    def no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(pairs)

    return json.loads(text, object_pairs_hook=no_dupes)


def _install_scripts(text: str | None) -> dict[str, Any] | None:
    """Install lifecycle scripts of a package.json; None if it does not parse."""
    if text is None:
        return {}
    try:
        doc = _strict_json(text)
    except (ValueError, RecursionError):
        return None
    scripts = doc.get("scripts", {}) if isinstance(doc, dict) else None
    if not isinstance(scripts, dict):
        return None
    return {k: scripts[k] for k in _INSTALL_SCRIPTS if k in scripts}


def _build_system(text: str | None) -> Any:
    """The `[build-system]` table, or a sentinel string if it does not parse."""
    if text is None:
        return None
    try:
        return tomllib.loads(text).get("build-system")
    except (tomllib.TOMLDecodeError, RecursionError):
        return "<unparseable>"


def _check_file(out: _Results, change: ChangedFile, base: BlobScan | None, head: BlobScan | None) -> None:
    path = change.path
    paths = [p for p in (change.path, change.old_path) if p]

    for p in paths:
        bidi = _BIDI_RE.findall(p)
        if bidi:
            out.add(BIDI_PATH, HARD_BLOCK, f"bidi control characters {_codepoints(bidi)} in path", file=p)
    path_hits = _ai_hits([(1, p) for p in paths])
    for name in sorted(path_hits):
        out.add(AI_DIRECTED_TEXT, SIGNAL, f"pattern {name} in path", file=path)

    kinds = sorted({k for p in paths if (k := _sensitive_path(p))})
    if kinds:
        out.add(SENSITIVE_PATH, SIGNAL, f"change to {', '.join(kinds)}", file=path)
    if any(deps.is_unsupported_dep_file(p) or p.rsplit("/", 1)[-1].lower() in _EXTRA_UNSUPPORTED_DEP_FILES for p in paths):
        out.add(UNSUPPORTED_DEP_FILE, SIGNAL, "dependency file of an unsupported ecosystem changed", file=path)

    if change.is_submodule:
        out.add(
            SUBMODULE, SIGNAL, "submodule commit changed", file=path,
            subject=f"{change.base_sha or '(none)'} -> {change.head_sha or '(none)'}",
        )
        return
    if change.became_executable:
        out.add(EXECUTABLE, SIGNAL, f"mode {change.base_mode or '(new)'} -> {change.head_mode}", file=path)
    if head is not None and head.kind == "binary" and (base is None or base.kind != "binary"):
        out.add(BINARY_ADDED, SIGNAL, "binary file added" if base is None else "file became binary", file=path)

    head_text = head.text if head is not None and head.kind == "full" else None
    base_text = base.text if base is not None and base.kind == "full" else None
    name = path.rsplit("/", 1)[-1]

    if head_text is not None or base_text is not None:
        if name == "package.json" and change.head_mode != MODE_SYMLINK:
            old, new = _install_scripts(base_text), _install_scripts(head_text)
            if new is None:
                out.add(INSTALL_SCRIPT_CHANGE, SIGNAL, "package.json does not parse; install scripts unknown", file=path)
            elif old != new:
                keys = sorted(k for k in set(old or {}) | set(new) if (old or {}).get(k) != new.get(k))
                out.add(INSTALL_SCRIPT_CHANGE, SIGNAL, f"install scripts changed: {', '.join(keys)}", file=path)
        if name == "pyproject.toml" and change.head_mode != MODE_SYMLINK:
            if _build_system(base_text) != _build_system(head_text):
                out.add(BUILD_SYSTEM_CHANGE, SIGNAL, "[build-system] changed", file=path)

    if head_text is None:
        return
    head_lines = _Lines(head_text)
    base_lines = _Lines(base_text) if base_text is not None else None
    added = _added_lines(head_lines, base_lines)
    _check_text(out, path, head_lines, added)
    if (
        path.lower().endswith(_JS_SUFFIXES)
        and not _under_dist_or_build(path)
        and change.head_mode != MODE_SYMLINK
        and _is_minified_js(path, head_lines)
    ):
        out.add(MINIFIED_JS, SIGNAL, "minified or bundled JavaScript outside dist/ and build/", file=path)


# ---------------------------------------------------------------------------
# Dependency checks
# ---------------------------------------------------------------------------

_OFFICIAL_HOSTS = {"npm": deps.NPM_OFFICIAL_HOSTS, "pypi": deps.PYPI_OFFICIAL_HOSTS}
_NPM_FAMILIES = frozenset({"package.json", *deps.MANIFEST_LOCKFILES["package.json"]})
_EXACT_VERSION_RE = re.compile(r"[A-Za-z0-9.+_-]+", re.ASCII)


def _is_foreign(ecosystem: str, source: deps.Source) -> bool:
    """deps.Source.foreign, re-checked: an official source must name an
    official host of its own ecosystem."""
    if source.foreign:
        return True
    if source.kind == "registry":
        return source.host not in _OFFICIAL_HOSTS.get(ecosystem, frozenset())
    return False


def needs_registry_lookup(change: deps.PackageChange) -> bool:
    """True when the 72-hour rule applies, so collect must look the version up.

    That is a new or changed exact version from the official registry: every
    lockfile entry, and requirements entries pinned with `==`.
    """
    if change.source.kind != "registry" or _is_foreign(change.ecosystem, change.source):
        return False
    family = deps.family_for_path(change.path)
    if family in deps.LOCKFILE_FAMILIES:
        return True
    return family == "requirements" and bool(_EXACT_VERSION_RE.fullmatch(change.new_version))


def _check_deps(
    out: _Results,
    facts: DependencyFacts | None,
    changed: Sequence[ChangedFile],
    head_paths: frozenset[str],
    now: datetime,
) -> None:
    facts = facts or DependencyFacts()
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")

    for f in sorted(facts.failures, key=lambda f: (f.path, f.reason)):
        out.add(INCOMPLETE_DEP_DATA, HARD_BLOCK, f"dependency data incomplete: {f.reason}", file=f.path)
    failed = {f.path for f in facts.failures}
    for c in changed:
        if c.head_sha is None or c.is_submodule or deps.family_for_path(c.path) is None:
            continue
        if c.path not in facts.parsed_paths and c.path not in failed:
            out.add(INCOMPLETE_DEP_DATA, HARD_BLOCK, "supported dependency file was not parsed", file=c.path)

    for issue in facts.new_global_sources:
        eco = "npm" if deps.family_for_path(issue.path) in _NPM_FAMILIES else "pypi"
        if _is_foreign(eco, issue.source):
            out.add(
                FOREIGN_SOURCE, HARD_BLOCK, f"file-wide {issue.source.kind} source is not the official registry",
                file=issue.path, subject=issue.source.normalized,
            )

    for c in facts.changes:
        subject = f"{c.name}@{c.new_version}"
        if _is_foreign(c.ecosystem, c.source):
            out.add(
                FOREIGN_SOURCE, HARD_BLOCK, f"{c.source.kind} source is not the official registry",
                file=c.path, subject=f"{subject} from {c.source.normalized}",
            )
            continue
        info = facts.registry.get((c.ecosystem, c.name, c.new_version))
        if needs_registry_lookup(c):
            if info is None:
                out.add(INCOMPLETE_DEP_DATA, HARD_BLOCK, "no registry data for a new version", file=c.path, subject=subject)
            elif info.published.tzinfo is None:
                out.add(INCOMPLETE_DEP_DATA, HARD_BLOCK, "registry publish time has no time zone", file=c.path, subject=subject)
            elif now - info.published < FRESH_PUBLISH_WINDOW:
                hours = (now - info.published).total_seconds() / 3600
                out.add(
                    FRESH_PUBLISH, HARD_BLOCK, f"published {hours:.1f} hours ago (under 72)",
                    file=c.path, subject=subject,
                )
        if c.ecosystem == "npm":
            if c.has_install_script:
                out.add(INSTALL_SCRIPT_DEP, SIGNAL, "lockfile entry has an install script", file=c.path, subject=subject)
            scripts = info.install_scripts if info is not None else {}
            if scripts and c.direct is not False:
                out.add(
                    INSTALL_SCRIPT_DEP, SIGNAL,
                    f"registry manifest has install scripts: {', '.join(sorted(scripts))}",
                    file=c.path, subject=subject,
                )
        if c.ecosystem == "pypi" and facts.has_wheel.get((c.name, c.new_version)) is False:
            out.add(SDIST_ONLY, SIGNAL, "no wheel; setup.py runs at install", file=c.path, subject=subject)

    changed_paths = [c.path for c in changed]
    for p in deps.manifest_without_lockfile(changed_paths, head_paths):
        out.add(MANIFEST_WITHOUT_LOCKFILE, SIGNAL, "manifest changed but its lockfile did not", file=p)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

_FIRST_TIME = frozenset({"FIRST_TIME_CONTRIBUTOR", "FIRST_TIMER", "NONE"})


def run_prefilter(
    diff: TreeDiff,
    blobs: Mapping[str, bytes | None],
    *,
    head_paths: Iterable[str],
    now: datetime,
    dependencies: DependencyFacts | None = None,
    author_association: str | None = None,
    pr_title: str = "",
    pr_body: str = "",
    max_blob_bytes: int = MAX_BLOB_BYTES,
) -> PrefilterResult:
    """Run every prefilter check on one comparison.

    `blobs` maps a blob SHA to its bytes, or None when the read failed. A blob
    SHA missing from the map counts as unreadable. Each blob is checked against
    its SHA before it is scanned. `head_paths` is every path in the head tree.
    """
    out = _Results()
    file_cov: list[FileCoverage] = []
    collected = 0
    seen: set[str] = set()

    for change in diff.files:
        if change.path in seen:
            raise ValueError(f"duplicate path in diff: {change.path[:200]!r}")
        seen.add(change.path)
        if change.is_submodule:
            # A gitlink has no blob; the old and new commit SHAs are its content.
            file_cov.append(FileCoverage(change.path, "binary"))
            collected += 1
            _check_file(out, change, None, None)
            continue
        base = head = None
        if change.base_sha is not None:
            base = scan_blob(blobs.get(change.base_sha), sha=change.base_sha, cap=max_blob_bytes)
        if change.head_sha is not None:
            head = scan_blob(blobs.get(change.head_sha), sha=change.head_sha, cap=max_blob_bytes)
        if all(s.reason not in ("unreadable", "sha-mismatch") for s in (base, head) if s is not None):
            collected += 1
        file_cov.append(_file_coverage(change, base, head))
        _check_file(out, change, base, head)

    coverage = Coverage(
        trees_complete=diff.complete,
        files_in_comparison=len(diff.files),
        files_collected=collected,
        files=tuple(file_cov),
    )
    if not diff.complete:
        out.add(INCOMPLETE_COVERAGE, HARD_BLOCK, "a git tree was truncated; the comparison is incomplete")
    for fc in file_cov:
        if fc.coverage == "unavailable":
            out.add(INCOMPLETE_COVERAGE, HARD_BLOCK, f"file content not scanned: {fc.reason}", file=fc.path)

    _check_deps(out, dependencies, diff.files, frozenset(head_paths), now)

    for where, text in (("PR title", pr_title), ("PR body", pr_body)):
        hits = _ai_hits(list(enumerate(text.split("\n"), 1)))
        for name, lines in sorted(hits.items()):
            out.add(AI_DIRECTED_TEXT, SIGNAL, f"pattern {name} in {where}", lines=lines, count=len(lines))

    if author_association in _FIRST_TIME:
        out.add(FIRST_TIME_AUTHOR, SIGNAL, f"author_association {author_association} (context only)")

    return PrefilterResult(
        signals=tuple(c for c in out.items if c.level == SIGNAL),
        hard_blocks=tuple(c for c in out.items if c.level == HARD_BLOCK),
        coverage=coverage,
    )
