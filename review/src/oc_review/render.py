"""Bundle envelope -> prompt text with nonce delimiters and redaction.

Spec "Request shape": the bundle goes to Claude as one user message,

    <untrusted_pr_{nonce}>
    ...bundle rendered as text...
    </untrusted_pr_{nonce}>

`{nonce}` is 16 random hex characters per run. Every untrusted string goes
through the same steps before it is placed in the text:

1. `redact_text`: credential-like strings become `[REDACTED:<kind>]`.
2. `neutralize_delimiters`: any text that reads as the delimiter name
   (`untrusted_pr`, also in other case, with Unicode lookalikes or with
   invisible characters inside) becomes `[NEUTRALIZED:delimiter]`.
3. Control, format and line-break characters become visible `<U+XXXX>` text,
   so content cannot start a new line of the rendered text by itself.

Every line of a multi-line value starts with a `| ` prefix (with line numbers
for content and patches), so PR text cannot forge a section header. As a last
step, `check_no_delimiter` makes sure that the rendered bundle does not
contain `untrusted_pr_{nonce}`.

Steps 1-3 keep the line count (ruling R-LINES). `model_text` gives the text
exactly as Claude sees it, for the citation check in verdict.py.

Bundle payload shape (written by collect.py). Keys are optional; render shows
any other key with the same generic rules, so it drops nothing:

    pr:                {repository, repository_id, number, title, body,
                        author_login, author_association, labels}
    files:             [{path, old_path, status, additions, deletions,
                         head_blob_sha, base_blob_sha, binary, size, coverage,
                         patch, head_content}]
    dependency_delta, prefilter: {signals, hard_blocks}, coverage, size

- `pr.title` and `pr.body` are shown like files, with line numbers, at the
  reserved paths `/.pr/title` and `/.pr/body` (ruling R-META).
- `patch` is a plain unified diff of the two blobs (`@@` hunks; an optional
  `diff`/`---`/`+++` preamble). Render adds the base and head line numbers and
  fails closed when the hunk counts do not match the lines.
- `head_content` goes to Claude only for files under 2,000 lines (spec
  "Coverage limits"). Patches are not cut; the size gate bounds them.

Prompts: `load_prompt` reads `review/prompts/<name>.md` and fills `{nonce}`.
"""

from __future__ import annotations

import json
import re
import secrets
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

# Spec "Bundle": full head content only for text files under 2,000 lines.
MAX_HEAD_CONTENT_LINES = 2000
# Generic renderer depth cap. Collect writes a shallow structure.
MAX_DEPTH = 32

DELIMITER_NAME = "untrusted_pr"
# PR title and body are shown and cited as pseudo-files (ruling R-META). Same
# values as verdict.META_TITLE_PATH and verdict.META_BODY_PATH.
PR_TITLE_PATH = "/.pr/title"
PR_BODY_PATH = "/.pr/body"
NEUTRALIZED = "[NEUTRALIZED:delimiter]"

_NONCE_RE = re.compile(r"^[0-9a-f]{16}$")

# Sections in this order first, then any other payload key in its own order.
_SECTION_ORDER = ("pr", "files", "dependency_delta", "prefilter", "coverage", "size")
_SNAPSHOT_FIELDS = (
    "repository_id",
    "pr_number",
    "head_sha",
    "base_repository_id",
    "base_ref",
    "base_tip_sha",
    "merge_base_sha",
)


class RenderError(Exception):
    """The bundle cannot be rendered safely. The pass fails, so the gate fails."""


@dataclass(frozen=True)
class RenderedBundle:
    nonce: str
    text: str  # the full user message: open tag, bundle, close tag

    @property
    def open_tag(self) -> str:
        return f"<{DELIMITER_NAME}_{self.nonce}>"

    @property
    def close_tag(self) -> str:
        return f"</{DELIMITER_NAME}_{self.nonce}>"


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

REDACTED = "[REDACTED:{kind}]"

# Credential-like strings: token prefixes with their fixed formats. Order
# matters where one prefix contains another (sk-ant- before sk-).
_TOKEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("github-token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b")),
    ("github-token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    ("gitlab-token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}")),
    ("aws-access-key-id", re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b")),
    ("anthropic-api-key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}")),
    ("openai-api-key", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}")),
    ("stripe-key", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{10,}\b")),
    ("stripe-webhook-secret", re.compile(r"\bwhsec_[A-Za-z0-9]{20,}\b")),
    ("slack-token", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("slack-webhook", re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]+")),
    ("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}")),
    ("npm-token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b")),
    ("pypi-token", re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}")),
    ("sendgrid-key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
)
# user:password@ in a URL. Only the userinfo is replaced. The password part
# runs to the last @ before the path, so a raw @ in a password does not leak.
_URL_CREDENTIALS = re.compile(r"\b([A-Za-z][A-Za-z0-9+.\-]{0,31}://)[^\s/?#@:]{1,256}:[^\s/?#]{1,256}@")

_PK_BEGIN = re.compile(r"-----BEGIN[A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----")
_PK_END = re.compile(r"-----END[A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----")
# A key body run: base64 of 16+ characters with at least one digit, + or /.
_PK_BODY_RUN = re.compile(r"[A-Za-z0-9+/=]{16,}")
# A line that can still be part of an armored key: base64, armor headers,
# blank lines, string quotes and escapes around a key in code.
_PK_KEYISH_LINE = re.compile(r"^[A-Za-z0-9+/=\s:,.\-'\"\\|]*$")
# An unterminated key header redacts at most this many following lines.
_PK_MAX_LINES = 200


def _pk_body_sub(segment: str) -> str:
    def repl(m: re.Match[str]) -> str:
        run = m.group()
        if any(c.isdigit() or c in "+/" for c in run):
            return REDACTED.format(kind="private-key")
        return run

    return _PK_BODY_RUN.sub(repl, segment)


def _pk_line(line: str, in_key: bool) -> tuple[str, bool]:
    out: list[str] = []
    pos = 0
    while True:
        if in_key:
            end = _PK_END.search(line, pos)
            stop = end.start() if end else len(line)
            out.append(_pk_body_sub(line[pos:stop]))
            if end is None:
                return "".join(out), True
            out.append(end.group())
            pos, in_key = end.end(), False
        else:
            begin = _PK_BEGIN.search(line, pos)
            if begin is None:
                out.append(line[pos:])
                return "".join(out), False
            out.append(line[pos : begin.end()])
            pos, in_key = begin.end(), True


def _redact_private_keys(text: str) -> str:
    if "PRIVATE KEY" not in text:
        return text
    lines = text.split("\n")
    in_key, budget = False, 0
    for i, line in enumerate(lines):
        if in_key:
            budget -= 1
            keyish = _PK_KEYISH_LINE.match(line) or _pk_body_sub(line) != line
            if budget < 0 or not (keyish or _PK_END.search(line)):
                in_key = False
        lines[i], in_key = _pk_line(line, in_key)
        if in_key and _PK_BEGIN.search(line):
            budget = _PK_MAX_LINES
    return "\n".join(lines)


def find_credentials(text: str) -> list[tuple[str, int, int]]:
    """Locations of credential-like strings: (kind, start, end), by start.

    Private keys are reported by their header only. For the prefilter signal,
    which shows the location and never the value.
    """
    found: list[tuple[str, int, int]] = []
    for kind, pattern in _TOKEN_PATTERNS:
        found.extend((kind, m.start(), m.end()) for m in pattern.finditer(text))
    found.extend(("url-credentials", m.start(), m.end()) for m in _URL_CREDENTIALS.finditer(text))
    found.extend(("private-key", m.start(), m.end()) for m in _PK_BEGIN.finditer(text))
    return sorted(found, key=lambda f: (f[1], f[2]))


def redact_text(text: str) -> str:
    """Replace credential-like strings with `[REDACTED:<kind>]`.

    Keeps the line structure, so line numbers do not move. Used by render
    (before Claude sees the bundle) and by publish (before anything is posted).
    """
    if not isinstance(text, str):
        raise TypeError("redact_text takes a str")
    text = _redact_private_keys(text)
    for kind, pattern in _TOKEN_PATTERNS:
        text = pattern.sub(REDACTED.format(kind=kind), text)
    return _URL_CREDENTIALS.sub(lambda m: m.group(1) + REDACTED.format(kind="url-credentials") + "@", text)


# ---------------------------------------------------------------------------
# Delimiter neutralization
# ---------------------------------------------------------------------------

# Lookalikes for the letters of the delimiter name that NFKD and casefold do
# not map to ASCII (Cyrillic, Greek, Armenian, Latin small capitals).
_CONFUSABLES = {
    "\u03c5": "u", "\u057d": "u", "\u1d1c": "u", "\u028b": "u",
    "\u0578": "n", "\u043f": "n", "\u03b7": "n", "\u0274": "n",
    "\u0442": "t", "\u03c4": "t", "\u1d1b": "t",
    "\u0433": "r", "\u0280": "r", "\u027e": "r",
    "\u0455": "s", "\ua731": "s",
    "\u0435": "e", "\u04bd": "e", "\u03b5": "e", "\u1d07": "e",
    "\u0501": "d", "\u1d05": "d",
    "\u0440": "p", "\u03c1": "p", "\u1d18": "p",
}
_DELIM_SKELETON = re.compile(r"untrusted[^a-z0-9\n]{0,3}pr")
_DELIM_ASCII = re.compile(r"untrusted[^A-Za-z0-9\n]{0,3}pr", re.IGNORECASE)
# ASCII control characters (other than tab and newline) are skipped like any
# invisible character, so such text takes the slow path.
_ASCII_IGNORABLE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _ignorable(ch: str) -> bool:
    cp = ord(ch)
    return (
        unicodedata.category(ch) in ("Cf", "Mn", "Me", "Cc")
        and ch != "\n"
        or 0xFE00 <= cp <= 0xFE0F
        or 0xE0100 <= cp <= 0xE01EF
        or cp in (0x115F, 0x1160, 0x3164, 0xFFA0)
    )


def _skeleton(ch: str) -> str:
    if ch.isascii():
        return "" if ch != "\n" and _ignorable(ch) else ch.lower()
    if _ignorable(ch):
        return ""
    s = unicodedata.normalize("NFKD", ch)
    s = "".join(c for c in s if not _ignorable(c)).casefold()
    s = unicodedata.normalize("NFKC", s)
    return "".join(_CONFUSABLES.get(c, c) for c in s)


def neutralize_delimiters(text: str) -> str:
    """Replace text that reads as the delimiter name with a fixed marker.

    Matches `untrusted` + up to 3 separators + `pr` after case folding, NFKD,
    a lookalike table, and removal of invisible characters. A match never
    spans a newline, so line numbers do not move.
    """
    if text.isascii() and not _ASCII_IGNORABLE.search(text):
        return _DELIM_ASCII.sub(NEUTRALIZED, text)
    skel: list[str] = []
    owner: list[int] = []
    for i, ch in enumerate(text):
        for c in _skeleton(ch):
            skel.append(c)
            owner.append(i)
    out: list[str] = []
    pos = 0
    for m in _DELIM_SKELETON.finditer("".join(skel)):
        start, end = owner[m.start()], owner[m.end() - 1] + 1
        out.append(text[pos:start])
        out.append(NEUTRALIZED)
        pos = end
    out.append(text[pos:])
    return "".join(out)


def check_no_delimiter(rendered_bundle: str, nonce: str) -> None:
    """Spec: the rendered bundle must not contain `untrusted_pr_{nonce}`."""
    if f"{DELIMITER_NAME}_{nonce}".casefold() in rendered_bundle.casefold():
        raise RenderError("rendered bundle contains the delimiter for this run")


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_ASCII_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


def _u(ch: str) -> str:
    return f"<U+{ord(ch):04X}>"


def _visible(s: str) -> str:
    """Show control, format, line-break and invisible characters as `<U+XXXX>`.

    Tab is kept. Newline is shown too: callers split blocks on newline first.
    """
    if s.isascii():
        return _ASCII_CONTROL.sub(lambda m: _u(m.group()), s)
    out = []
    for ch in s:
        cp = ord(ch)
        if ch == "\t":
            out.append(ch)
        elif (
            unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Zl", "Zp")
            or 0xFE00 <= cp <= 0xFE0F
            or 0xE0100 <= cp <= 0xE01EF
            or cp in (0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0)
        ):
            out.append(_u(ch))
        else:
            out.append(ch)
    return "".join(out)


def _clean(s: str) -> str:
    return neutralize_delimiters(redact_text(s))


def _scalar(s: str) -> str:
    return _visible(_clean(s))


def model_lines(text: str) -> list[str]:
    """The lines of `text` exactly as Claude sees them in the bundle.

    Redacted, delimiter names neutralized, invisible characters made visible,
    one trailing CR per line dropped. Split on newline only, so line numbers
    match git; redaction keeps the line count (ruling R-LINES).
    """
    lines = _clean(text).split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return [_visible(line[:-1] if line.endswith("\r") else line) for line in lines]


def model_text(text: str) -> str:
    """`model_lines` joined, each line ending in a newline.

    The citation check (verdict.py `FileSides`) takes this text, so a quote is
    compared with what Claude saw, on the same line numbers.
    """
    return "".join(line + "\n" for line in model_lines(text))


def _key(k: Any) -> str:
    return _scalar(k if isinstance(k, str) else str(k))


def _emit(out: list[str], indent: int, key: str, value: Any, depth: int) -> None:
    if depth > MAX_DEPTH:
        raise RenderError("bundle nesting too deep")
    pad = "  " * indent
    if isinstance(value, Mapping):
        out.append(f"{pad}{key}:" + ("" if value else " {}"))
        for k, v in value.items():
            _emit(out, indent + 1, _key(k), v, depth + 1)
    elif isinstance(value, list):
        out.append(f"{pad}{key}: ({len(value)} items)")
        for i, v in enumerate(value, 1):
            _emit(out, indent + 1, f"[{i}]", v, depth + 1)
    elif isinstance(value, str):
        if "\n" in value or "\r" in value:
            lines = model_lines(value.replace("\r\n", "\n").replace("\r", "\n"))
            out.append(f"{pad}{key}: ({len(lines)} lines)")
            out.extend(f"{pad}  | {line}" for line in lines)
        else:
            out.append(f"{pad}{key}: {_scalar(value)}")
    elif value is None or isinstance(value, (bool, int, float)):
        out.append(f"{pad}{key}: {json.dumps(value)}")
    else:
        raise RenderError(f"unsupported value type {type(value).__name__}")


def _emit_numbered(out: list[str], label: str, text: str) -> None:
    lines = model_lines(text)
    out.append(f"{label}: ({len(lines)} lines)")
    out.extend(f"  | {n:>5} | {line}" for n, line in enumerate(lines, 1))


def _emit_head_content(out: list[str], content: Any) -> None:
    if not isinstance(content, str):
        _emit(out, 0, "head_content", content, 1)
        return
    n = content.count("\n") + (0 if content.endswith("\n") or not content else 1)
    if n >= MAX_HEAD_CONTENT_LINES:
        out.append(f"head_content: omitted, {n} lines (limit: under {MAX_HEAD_CONTENT_LINES} lines)")
        return
    _emit_numbered(out, "head_content", content)


_HUNK_RE = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(.*)", re.DOTALL)
_PATCH_PREAMBLE = ("diff ", "index ", "--- ", "+++ ", "new file mode ", "deleted file mode ",
                   "old mode ", "new mode ", "similarity index ", "rename from ", "rename to ")


def _annotate_patch(patch: str) -> list[str]:
    """Unified diff -> lines with base and head line numbers (spec "Bundle").

    Strict: hunk counts must match the lines, else RenderError (fail closed).
    Content lines always start with a diff marker, so PR text cannot forge a
    hunk header.
    """
    raw = patch.split("\n")
    if raw and raw[-1] == "":
        raw.pop()
    # (base number, head number, marker) per row; marker "@" is a hunk header.
    rows: list[tuple[int | None, int | None, str]] = []
    texts: list[str] = []
    base = head = rem_base = rem_head = 0
    seen_hunk = False
    for line in raw:
        if rem_base == 0 and rem_head == 0:
            m = _HUNK_RE.fullmatch(line)
            if m:
                base, rem_base = int(m.group(1)), int(m.group(2) or 1)
                head, rem_head = int(m.group(3)), int(m.group(4) or 1)
                seen_hunk = True
                rows.append((None, None, "@" + m.group(0)[: m.start(5)]))
                texts.append(m.group(5))
                continue
            if line.startswith("\\") and seen_hunk:
                rows.append((None, None, "\\"))
                texts.append(line[1:])
                continue
            if not seen_hunk and line.startswith(_PATCH_PREAMBLE):
                continue
            raise RenderError("malformed patch: line outside a hunk")
        marker, body = (line[:1], line[1:]) if line else (" ", "")
        if marker == " " and rem_base > 0 and rem_head > 0:
            rows.append((base, head, " "))
            base, head, rem_base, rem_head = base + 1, head + 1, rem_base - 1, rem_head - 1
        elif marker == "-" and rem_base > 0:
            rows.append((base, None, "-"))
            base, rem_base = base + 1, rem_base - 1
        elif marker == "+" and rem_head > 0:
            rows.append((None, head, "+"))
            head, rem_head = head + 1, rem_head - 1
        elif marker == "\\":
            rows.append((None, None, "\\"))
        else:
            raise RenderError("malformed patch: hunk counts do not match")
        texts.append(body)
    if rem_base or rem_head:
        raise RenderError("malformed patch: hunk ends early")
    # Clean all texts as one block, so a key that spans lines is redacted with
    # its context. Line count is kept, so rows and texts stay aligned.
    shown = model_lines("".join(t + "\n" for t in texts))
    if len(shown) != len(rows):
        raise RenderError("patch line count changed")
    out = []
    for (b, h, marker), text in zip(rows, shown):
        nums = f"{'' if b is None else b:>5} {'' if h is None else h:>5}"
        if marker.startswith("@"):
            out.append(f"{nums} | {marker[1:]}{text}")
        else:
            out.append(f"{nums} | {marker}{text}")
    return out


def _emit_patch(out: list[str], patch: Any) -> None:
    if not isinstance(patch, str):
        _emit(out, 0, "patch", patch, 1)
        return
    lines = _annotate_patch(patch)
    out.append(f"patch: ({len(lines)} lines; columns: base line, head line)")
    out.extend(f"  | {line}" for line in lines)


def _emit_file(out: list[str], index: int, total: int, f: Any) -> None:
    out.append(f"--- file {index} of {total} ---")
    if not isinstance(f, Mapping):
        _emit(out, 0, "file", f, 1)
        return
    binary = f.get("binary") is True
    for k, v in f.items():
        if k not in ("patch", "head_content"):
            _emit(out, 0, _key(k), v, 1)
    if binary:
        return
    if "patch" in f:
        _emit_patch(out, f["patch"])
    if "head_content" in f:
        _emit_head_content(out, f["head_content"])


def _emit_pr(out: list[str], pr: Mapping[str, Any]) -> None:
    for k, v in pr.items():
        if k not in ("title", "body"):
            _emit(out, 0, _key(k), v, 1)
    # Title and body are shown like files, at reserved paths (ruling R-META).
    for path, key in ((PR_TITLE_PATH, "title"), (PR_BODY_PATH, "body")):
        value = pr.get(key)
        out.append(f"--- {path} ---")
        out.append(f"path: {path}")
        if value is None or isinstance(value, str):
            _emit_numbered(out, "content", value or "")
        else:
            _emit(out, 0, "content", value, 1)


def _render_inner(envelope: Mapping[str, Any]) -> str:
    payload = envelope["payload"]
    out: list[str] = ["=== snapshot ==="]
    for field in _SNAPSHOT_FIELDS:
        _emit(out, 0, field, envelope.get(field), 1)

    keys = [k for k in _SECTION_ORDER if k in payload]
    keys += [k for k in payload if k not in _SECTION_ORDER]
    for key in keys:
        value = payload[key]
        if key == "files" and isinstance(value, list):
            out.append(f"=== files ({len(value)}) ===")
            for i, f in enumerate(value, 1):
                _emit_file(out, i, len(value), f)
            continue
        out.append(f"=== {_key(key)} ===")
        if key == "pr" and isinstance(value, Mapping):
            _emit_pr(out, value)
        elif isinstance(value, Mapping):
            for k, v in value.items():
                _emit(out, 0, _key(k), v, 1)
        else:
            _emit(out, 0, _key(key), value, 1)
    return "\n".join(out)


def new_nonce() -> str:
    """16 random hex characters, new for each run."""
    return secrets.token_hex(8)


def _check_nonce(nonce: Any) -> str:
    if not isinstance(nonce, str) or not _NONCE_RE.match(nonce):
        raise RenderError("nonce must be 16 lowercase hex characters")
    return nonce


def render_bundle(envelope: Mapping[str, Any], *, nonce: str | None = None) -> RenderedBundle:
    """Render a checked bundle envelope (status `ok`) as the untrusted user message.

    All three passes use the same nonce and text, so they share one cache entry.
    """
    nonce = _check_nonce(new_nonce() if nonce is None else nonce)
    if not isinstance(envelope, Mapping) or envelope.get("kind") != "bundle":
        raise RenderError("not a bundle envelope")
    if envelope.get("status") != "ok" or not isinstance(envelope.get("payload"), Mapping):
        raise RenderError("bundle status is not ok")
    try:
        inner = _render_inner(envelope)
    except RecursionError as e:
        raise RenderError("bundle nesting too deep") from e
    # Second pass over the whole text: a name can also form across the
    # scaffold, for example a key that ends in `untrusted` and a value that
    # starts with `pr`. The scaffold itself never holds the name.
    inner = neutralize_delimiters(inner)
    check_no_delimiter(inner, nonce)
    text = f"<{DELIMITER_NAME}_{nonce}>\n{inner}\n</{DELIMITER_NAME}_{nonce}>"
    return RenderedBundle(nonce=nonce, text=text)


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

PROMPTS_DIR = Path(__file__).resolve().parents[2] / "prompts"
PROMPT_NAMES = ("system", "review", "security", "supply-chain")
_PLACEHOLDER = "{nonce}"


def fill_prompt(template: str, nonce: str) -> str:
    """Put the run nonce into a prompt. Plain replace, never str.format."""
    nonce = _check_nonce(nonce)
    if _PLACEHOLDER not in template:
        raise RenderError("prompt has no {nonce} placeholder")
    return template.replace(_PLACEHOLDER, nonce)


def load_prompt(name: str, nonce: str) -> str:
    """Read `review/prompts/<name>.md` (system or a pass) and fill the nonce."""
    if name not in PROMPT_NAMES:
        raise RenderError(f"unknown prompt {name!r}")
    return fill_prompt((PROMPTS_DIR / f"{name}.md").read_text(encoding="utf-8"), nonce)
