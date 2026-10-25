"""Publisher: escaping of untrusted text.

Phase 1a holds only the escaping. The GitHub writes, the final check and the
exit code come in phase 1b.

Spec "Publishing (code)": every untrusted string (from Claude, and from the PR:
title, paths, package names, URLs, prefilter evidence) is escaped before it is
posted. `escape_text` does these steps, in this order:

1. Remove control, format and invisible characters (bidi controls, zero-width
   characters, Unicode tags, variation selectors). Line breaks become `\\n`.
   Long runs of combining marks are cut.
2. Redact credential-like strings (`render.redact_text`), before any cut, so
   no part of a secret survives truncation.
3. Single-line text: every line break becomes a space. Multi-line text: lines
   are stripped and blank lines dropped, so the result is one paragraph.
4. Truncate to the fixed limit (counted in characters after steps 1-3).
5. Break pings and autolinks with a zero-width space (U+200B): after every
   `@`, between `:` and `//`, after `www`, after `#` and `GH-` before a digit,
   and after every 6 characters of a run of 7+ hex characters (commit SHAs).
   This comes after the cut, so a cut cannot make a new reference.
6. Backslash-escape every ASCII punctuation character, so no Markdown link,
   image, HTML, autolink, emphasis, heading, list, table or entity can form.
   Multi-line text joins lines with a Markdown hard break (`\\` + newline).

The result is for Markdown prose only, not for code spans or code blocks
(backslashes show there).
"""

from __future__ import annotations

import re
import string
import unicodedata

from oc_review.render import redact_text

ZWSP = "​"
TRUNCATED = "… \\[truncated\\]"

# Fixed limits in characters, per field. Claude fields match the findings
# schema maxLength. PR fields use GitHub's own limits where they exist.
LIMITS: dict[str, int] = {
    # From Claude
    "summary": 1500,
    "title": 120,
    "explanation": 1200,
    "quote": 300,
    "file": 400,
    # From the PR and from code that read it
    "pr_title": 256,
    "path": 400,
    "package_name": 214,
    "version": 128,
    "url": 300,
    "evidence": 300,
    "login": 39,
    "label": 100,
    "reason": 300,
}
# Fields shown as several lines. All others are one line.
MULTILINE = frozenset({"summary", "explanation", "quote"})

# Combining marks kept after one base character ("Zalgo" text is cut).
MAX_COMBINING = 4

_PUNCT = frozenset(string.punctuation)
_LINE_BREAKS = re.compile(r"\r\n|[\r\n\x0b\x0c\x1c-\x1e\x85  ]")
_AT_SIGNS = ("@", "＠", "﹫")  # @, fullwidth @, small @
_DEFANG = re.compile(r"(?<=:)(?=//)|(?<=\bwww)(?=\.)|(?<=#)(?=\d)|(?<=\bgh-)(?=\d)", re.IGNORECASE)
# GitHub links a bare commit SHA, full or short (7+ hex characters), also in
# `user@sha` and `owner/repo@sha` forms. Every run of 7 or more hex characters
# gets a ZWSP after each 6, so no part is long enough. No word-boundary test:
# GitHub's exact rule is not known, so any such run is broken.
_HEX_RUN = re.compile(r"[0-9A-Fa-f]{7,}")
_HEX_CHUNK = 6


def _break_hex(m: re.Match[str]) -> str:
    run = m.group()
    return ZWSP.join(run[i : i + _HEX_CHUNK] for i in range(0, len(run), _HEX_CHUNK))


def _invisible(ch: str) -> bool:
    cp = ord(ch)
    return (
        unicodedata.category(ch) in ("Cc", "Cf", "Cs", "Co", "Cn")
        or 0xFE00 <= cp <= 0xFE0F
        or 0xE0100 <= cp <= 0xE01EF
        or cp in (0x034F, 0x115F, 0x1160, 0x3164, 0xFFA0)
    )


def _strip_controls(text: str) -> str:
    text = _LINE_BREAKS.sub("\n", text).replace("\t", " ")
    out: list[str] = []
    marks = 0
    for ch in text:
        if ch == "\n":
            out.append(ch)
            marks = 0
        elif _invisible(ch):
            continue
        elif unicodedata.category(ch) in ("Mn", "Me"):
            marks += 1
            if marks <= MAX_COMBINING:
                out.append(ch)
        else:
            out.append(ch)
            marks = 0
    return "".join(out)


def _escape_line(line: str) -> str:
    line = _HEX_RUN.sub(_break_hex, _DEFANG.sub(ZWSP, line))
    out: list[str] = []
    for ch in line:
        if ch in _PUNCT:
            out.append("\\" + ch)
        else:
            out.append(ch)
        if ch in _AT_SIGNS:
            out.append(ZWSP)
    return "".join(out)


def escape_text(text: str, limit: int, *, multiline: bool = False) -> str:
    """Escape one untrusted string for Markdown prose in a GitHub comment.

    `limit` counts characters of the cleaned text. The result is at most
    `3 * limit + len(TRUNCATED)` characters long.
    """
    if not isinstance(text, str):
        raise TypeError("escape_text takes a str")
    if not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive int")
    text = redact_text(_strip_controls(text))
    lines = [" ".join(line.split()) for line in text.split("\n")]
    lines = [line for line in lines if line]
    joined = "\n".join(lines) if multiline else " ".join(lines)
    cut = len(joined) > limit
    if cut:
        joined = joined[:limit].rstrip()
    escaped = "\\\n".join(_escape_line(line) for line in joined.split("\n"))
    return escaped + TRUNCATED if cut else escaped


def escape_field(kind: str, text: str) -> str:
    """`escape_text` with the fixed limit and line mode for a field kind."""
    if kind not in LIMITS:
        raise KeyError(f"no limit for field kind {kind!r}")
    return escape_text(text, LIMITS[kind], multiline=kind in MULTILINE)
