"""Publisher: the gate job. Escaping, GitHub comments, final check, exit code.

The gate job runs no LLM and holds no Anthropic credential. It reads the
artifacts by fixed directory and producer digest, re-validates the snapshot,
reads the override inputs, computes the gate (`verdict.compute_gate`), then
writes, in this order, each after a fresh snapshot check:

    inline review (event COMMENT) -> sticky summary -> final check -> exit code

A stale run writes nothing more and exits 1. The write targets (repository,
PR number) come from the trusted event payload only. The only writes are a
`COMMENT` review, a new issue comment and a PATCH of the bot's own sticky
comment (`GitHubApi.write` refuses every other route). The bot never
approves, requests changes, merges, closes, labels or edits the PR (K-1).

Escaping. Spec "Publishing (code)": every untrusted string (from Claude, and from the PR:
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

import argparse
import hashlib
import json
import os
import re
import secrets
import string
import sys
import unicodedata
import urllib.parse
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from oc_review import collect, envelope, linediff, snapshot, verdict
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
    "ref": 255,
    "model": 100,
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


def strip_controls(text: str) -> str:
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


def _defang(line: str) -> str:
    """Steps 5 of `escape_text`: break references, autolinks and commit SHAs."""
    line = _HEX_RUN.sub(_break_hex, _DEFANG.sub(ZWSP, line))
    return "".join(ch + ZWSP if ch in _AT_SIGNS else ch for ch in line)


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
    joined, cut = _clean_text(text, limit, multiline)
    escaped = "\\\n".join(_escape_line(line) for line in joined.split("\n"))
    return escaped + TRUNCATED if cut else escaped


def _clean_text(text: str, limit: int, multiline: bool) -> tuple[str, bool]:
    """The redacted, cut text that `escape_text` escapes, and whether it was cut."""
    text = redact_text(strip_controls(text))
    lines = [" ".join(line.split()) for line in text.split("\n")]
    lines = [line for line in lines if line]
    joined = "\n".join(lines) if multiline else " ".join(lines)
    cut = len(joined) > limit
    if cut:
        joined = joined[:limit].rstrip()
    return joined, cut


def shown_field(kind: str, text: str) -> str:
    """The text of a field as the reader sees it, before Markdown escaping:
    redacted and cut to the field limit, with a mark when cut."""
    joined, cut = _clean_text(text, LIMITS[kind], kind in MULTILINE)
    return joined + "… [truncated]" if cut else joined


def escape_field(kind: str, text: str) -> str:
    """`escape_text` with the fixed limit and line mode for a field kind."""
    if kind not in LIMITS:
        raise KeyError(f"no limit for field kind {kind!r}")
    return escape_text(text, LIMITS[kind], multiline=kind in MULTILINE)


def _esc(kind: str, value: Any) -> str:
    """`escape_field` for any value; a non-string becomes its JSON text."""
    if value is None:
        return ""
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=True, default=str)
    return escape_field(kind, value)


# ---------------------------------------------------------------------------
# GitHub client: reads, and the three allowed writes
# ---------------------------------------------------------------------------

REVIEW_EVENT = "COMMENT"
WRITE_MAX_BYTES = 1024 * 1024
PERMISSION_MAX_BYTES = 64 * 1024

# The only writes the gate job makes (spec "Publishing (code)", K-1).
_WRITE_ROUTES = (
    ("POST", re.compile(r"/repos/[^/]+/[^/]+/pulls/[1-9][0-9]*/reviews")),
    ("POST", re.compile(r"/repos/[^/]+/[^/]+/issues/[1-9][0-9]*/comments")),
    ("PATCH", re.compile(r"/repos/[^/]+/[^/]+/issues/comments/[1-9][0-9]*")),
)
_REVIEW_KEYS = frozenset({"commit_id", "event", "body", "comments"})


class WriteError(collect.HttpError):
    """A write was refused by this module or failed at GitHub."""


class GitHubApi(collect.GitHubClient):
    """`collect.GitHubClient` plus paging of object-wrapped lists and the
    publisher's writes. Writes are never retried: a retried POST could post
    twice."""

    def get_wrapped_pages(
        self,
        path: str,
        key: str,
        *,
        params: Mapping[str, Any] | None = None,
        max_bytes: int = collect.PAGE_MAX_BYTES,
        max_pages: int = collect.MAX_PAGES,
    ) -> tuple[list[Any], int]:
        """Every item of a list endpoint whose pages are `{total_count, <key>: [...]}`
        (for example `workflow_runs`), and the largest `total_count` seen.

        Fails like `get_pages` on a bad page, a bad Link header, a next link to
        another host or more than `max_pages` pages.
        """
        url = self._url(path, {"per_page": 100, **(params or {})})
        items: list[Any] = []
        total = 0
        for _ in range(max_pages):
            resp = self._get(url, accept=collect.ACCEPT_JSON, max_bytes=max_bytes)
            try:
                page = envelope.parse_json(resp.body)
            except envelope.EnvelopeError as exc:
                raise collect.HttpError(f"{path}: {exc}") from exc
            if not isinstance(page, Mapping) or not isinstance(page.get(key), list):
                raise collect.HttpError(f"{path}: page has no {key} list")
            count = page.get("total_count")
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise collect.HttpError(f"{path}: page has no total_count")
            total = max(total, count)
            items.extend(page[key])
            nxt = _next_page(resp, path)
            if nxt is None:
                return items, total
            url = nxt
        raise collect.HttpError(f"{path}: more than {max_pages} pages")

    def write(self, method: str, path: str, body: Mapping[str, Any]) -> Mapping[str, Any]:
        """POST or PATCH one of `_WRITE_ROUTES`. Returns the response object."""
        if not any(method == m and rx.fullmatch(path) for m, rx in _WRITE_ROUTES):
            raise WriteError(f"write not allowed: {method} {path[:200]}")
        if path.endswith("/reviews") and (
            body.get("event") != REVIEW_EVENT or not set(body) <= _REVIEW_KEYS
        ):
            raise WriteError("a review must have event COMMENT and no other fields")
        headers = {
            "Accept": collect.ACCEPT_JSON,
            "Authorization": f"Bearer {self._token}",
            "Content-Type": "application/json",
            "User-Agent": "oc-claude-review",
            "X-GitHub-Api-Version": collect.API_VERSION,
        }
        data = json.dumps(body, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        url = self._url(path, None)
        request = collect.HttpRequest(method, url, headers, WRITE_MAX_BYTES, self._timeout, data)
        try:
            resp = self._transport(request)
        except OSError as exc:
            raise WriteError(f"{method} {path}: {type(exc).__name__}") from exc
        served = urllib.parse.urlsplit(resp.url)
        if served.scheme != "https" or served.hostname != collect.API_HOST or served.port is not None:
            raise WriteError(f"{method} {path}: response came from another host")
        if resp.status not in (200, 201):
            raise WriteError(f"{method} {path}: HTTP {resp.status}", resp.status)
        if len(resp.body) > WRITE_MAX_BYTES:
            raise WriteError(f"{method} {path}: response is over the byte cap", resp.status)
        try:
            doc = envelope.parse_json(resp.body)
        except envelope.EnvelopeError as exc:
            raise WriteError(f"{method} {path}: {exc}", resp.status) from exc
        if not isinstance(doc, Mapping):
            raise WriteError(f"{method} {path}: response is not an object", resp.status)
        return doc


def _next_page(resp: collect.HttpResponse, path: str) -> str | None:
    link = resp.headers.get("link")
    if link is None:
        return None
    try:
        nexts = [uri for uri, rels in collect.parse_link_header(link) if "next" in rels]
    except ValueError as exc:
        raise collect.HttpError(f"{path}: {exc}") from exc
    if not nexts:
        return None
    if len(nexts) > 1:
        raise collect.HttpError(f"{path}: more than one next page link")
    nxt = urllib.parse.urlsplit(nexts[0])
    if nxt.scheme != "https" or nxt.hostname != collect.API_HOST or nxt.port is not None:
        raise collect.HttpError(f"{path}: next page link points to another host")
    return nexts[0]


# ---------------------------------------------------------------------------
# Trusted inputs
# ---------------------------------------------------------------------------

DEFAULT_SERVER_URL = "https://github.com"
_SERVER_URL_RE = re.compile(r"https://[A-Za-z0-9.-]+")
_LOGIN_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")
# Name of the dependency-review job output that holds the step outcome (1c).
DEPENDENCY_REVIEW_OUTPUT = "outcome"
DIGEST_ENV = {
    "bundle": "BUNDLE_DIGEST",
    "review": "REVIEW_DIGEST",
    "security": "SECURITY_DIGEST",
    "supply-chain": "SUPPLY_CHAIN_DIGEST",
}


@dataclass(frozen=True)
class PublishContext:
    """Write targets and run identity, from the trusted event and the runner only."""

    repository: str  # owner/name
    repository_id: int
    pr_number: int
    head_sha: str  # from the event; used only when there is no valid bundle
    pr_author: str
    run_id: int
    run_attempt: int
    server_url: str = DEFAULT_SERVER_URL

    @classmethod
    def from_event(
        cls, event: Mapping[str, Any], *, run_id: int, run_attempt: int, server_url: str | None = None
    ) -> PublishContext:
        ec = collect.EventContext.from_event(event)
        try:
            author = event["pull_request"]["user"]["login"]
        except (KeyError, TypeError) as exc:
            raise collect.CollectError(f"event payload is missing {exc}") from exc
        if not isinstance(author, str) or not author:
            raise collect.CollectError("event PR author login is not a string")
        for value, what in ((run_id, "run id"), (run_attempt, "run attempt")):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise collect.CollectError(f"{what} is not a positive integer")
        server = server_url if server_url and _SERVER_URL_RE.fullmatch(server_url) else DEFAULT_SERVER_URL
        return cls(ec.repository, ec.repository_id, ec.pr_number, ec.head_sha, author, run_id, run_attempt, server)

    @property
    def run_context(self) -> verdict.RunContext:
        return verdict.RunContext(self.repository_id, self.pr_number, self.run_id, self.run_attempt)

    @property
    def repo_path(self) -> str:
        owner, name = self.repository.split("/")
        return f"/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(name, safe='')}"

    @property
    def run_url(self) -> str:
        return f"{self.server_url}/{self.repository}/actions/runs/{self.run_id}/attempts/{self.run_attempt}"

    def comment_url(self, comment_id: int) -> str:
        return f"{self.server_url}/{self.repository}/pull/{self.pr_number}#issuecomment-{comment_id}"


def job_results(needs: Any) -> dict[str, str]:
    """`needs.<job>.result` from `toJSON(needs)`; a job that is not there is missing."""
    out: dict[str, str] = {}
    if isinstance(needs, Mapping):
        for job, value in needs.items():
            if isinstance(value, Mapping) and isinstance(value.get("result"), str):
                out[str(job)] = value["result"]
    return out


def dependency_review_outcome(needs: Any, env_value: str | None) -> str | None:
    """The exported dependency-review step outcome (spec "Reasons").

    Read from the job output in `needs` and from `DEPENDENCY_REVIEW_OUTCOME`.
    None (missing) when neither has it; when both have it and they differ,
    the result is not `success`.
    """
    values: list[str] = []
    job = needs.get(verdict.DEPENDENCY_REVIEW_JOB) if isinstance(needs, Mapping) else None
    outputs = job.get("outputs") if isinstance(job, Mapping) else None
    from_needs = outputs.get(DEPENDENCY_REVIEW_OUTPUT) if isinstance(outputs, Mapping) else None
    for v in (from_needs, env_value):
        if isinstance(v, str) and v:
            values.append(v)
    if not values:
        return None
    if len(set(values)) > 1:
        return "conflicting outcomes"
    return values[0]


def load_artifacts(
    data_dir: Path | str, digests: Mapping[str, str]
) -> tuple[verdict.ArtifactRead, tuple[verdict.ArtifactRead, ...]]:
    """The bundle and the three pass records from their fixed directories.

    A missing directory or an empty digest is an `ArtifactRead` error (the
    `artifact` reason, not waivable), never an exception (D10).
    """
    root = Path(data_dir)
    bundle = verdict.load_artifact(
        root / "bundle",
        kind="bundle",
        expected_name=collect.BUNDLE_FILE_NAME,
        expected_digest=digests.get("bundle", ""),
    )
    passes = tuple(
        verdict.load_artifact(
            root / envelope.pass_dir_name(name),
            kind="pass",
            expected_name=envelope.PASS_FILE_NAMES[name],
            expected_digest=digests.get(name, ""),
        )
        for name in verdict.PASS_NAMES
    )
    return bundle, passes


def bundle_snapshot(read: verdict.ArtifactRead) -> snapshot.Snapshot | None:
    doc = read.envelope
    if read.error is not None or doc is None:
        return None
    return snapshot.Snapshot(
        head_sha=doc["head_sha"],
        base_repository_id=doc["base_repository_id"],
        base_ref=doc["base_ref"],
        base_tip_sha=doc["base_tip_sha"],
        merge_base_sha=doc["merge_base_sha"],
    )


def _payload(read: verdict.ArtifactRead) -> Mapping[str, Any] | None:
    doc = read.envelope
    if read.error is not None or doc is None or doc["status"] not in verdict.BUNDLE_PAYLOAD_STATUSES:
        return None
    return doc["payload"]


def _opt_str(value: Any) -> str | None:
    return value if isinstance(value, str) else None


def bundle_files(read: verdict.ArtifactRead) -> tuple[verdict.FileSides, ...]:
    """Changed files and the PR title and body pseudo-files, for the citation check.

    The bundle is data: an entry with a bad shape is left out, which can only
    make a finding unverified (blocking never depends on verification).
    """
    payload = _payload(read)
    if payload is None:
        return ()
    out: list[verdict.FileSides] = []
    work = linediff.WorkBudget()  # one diff work budget for every file of the run
    files = payload.get("files")
    for entry in files if isinstance(files, list) else ():
        if not isinstance(entry, Mapping) or not isinstance(entry.get("path"), str):
            continue
        f = verdict.changed_file(
            entry["path"],
            old_path=_opt_str(entry.get("old_path")),
            base_raw=_opt_str(entry.get("base_content")),
            head_raw=_opt_str(entry.get("head_content")),
            work=work,
        )
        if f.no_hunks_reason is not None:
            # The job log says why (repr: a path is one log line).
            print(f"publish: {f.path!r}: {f.no_hunks_reason}; its findings go to the summary", file=sys.stderr)
        out.append(f)
    pr = payload.get("pr")
    if isinstance(pr, Mapping):
        out.extend(verdict.metadata_files_from_raw(_opt_str(pr.get("title")), _opt_str(pr.get("body"))))
    return tuple(out)


# ---------------------------------------------------------------------------
# Reads: snapshot, override inputs, run list
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SnapshotRead:
    """One fresh snapshot check before a write.

    `revalidation` is `snapshot.revalidate` against the bundle snapshot, or
    None when there is no bundle snapshot. With no bundle, only the PR head is
    checked against the event head (`head_moved`), so the summary can still
    explain the failure (D10). `error` means the check could not run.
    """

    revalidation: snapshot.Revalidation | None
    error: str | None = None
    head_moved: bool = False

    @property
    def blocks_writes(self) -> bool:
        if self.error is not None or self.head_moved:
            return True
        return self.revalidation is not None and self.revalidation.stale

    def describe(self) -> str:
        if self.error is not None:
            return f"snapshot check failed: {self.error}"
        if self.head_moved:
            return f"stale: {snapshot.STALE_HEAD_SHA}"
        if self.revalidation is not None and self.revalidation.stale:
            return "stale: " + ", ".join(self.revalidation.stale_reasons)
        return "current"


def _read_pr(api: GitHubApi, ctx: PublishContext) -> Mapping[str, Any]:
    pr = api.get_json(f"{ctx.repo_path}/pulls/{ctx.pr_number}", max_bytes=collect.PR_MAX_BYTES)
    if not isinstance(pr, Mapping) or pr.get("number") != ctx.pr_number:
        raise collect.CollectError("PR response is not for the event's PR")
    base = pr.get("base")
    base_repo = base.get("repo") if isinstance(base, Mapping) else None
    if not isinstance(base_repo, Mapping) or base_repo.get("id") != ctx.repository_id:
        raise collect.CollectError("PR base repository is not the event repository")
    return pr


def check_snapshot(api: GitHubApi, ctx: PublishContext, snap: snapshot.Snapshot | None) -> SnapshotRead:
    """Read the PR, the current tip of its base ref and `tip...head`, then
    `snapshot.revalidate` (spec "Consistent snapshot", Re-validate)."""
    try:
        pr = _read_pr(api, ctx)
        if snap is None:
            head = pr.get("head")
            return SnapshotRead(None, head_moved=not isinstance(head, Mapping) or head.get("sha") != ctx.head_sha)
        base_ref = pr["base"].get("ref")
        if not isinstance(base_ref, str) or not base_ref:
            raise collect.CollectError("PR base ref is not a non-empty string")
        tip = collect._read_base_tip(api, ctx.repo_path, base_ref)
        compare = api.get_json(
            f"{ctx.repo_path}/compare/{tip}...{snap.head_sha}",
            params={"per_page": 1},
            max_bytes=collect.COMPARE_MAX_BYTES,
        )
        return SnapshotRead(snapshot.revalidate(snap, pr, tip, compare))
    except (collect.CollectError, snapshot.SnapshotError) as exc:
        return SnapshotRead(None, error=str(exc)[:300])


def _parse_comments(items: Sequence[Any]) -> tuple[verdict.Comment, ...]:
    """A comment with a bad shape is skipped: it can be neither an override
    nor the sticky summary."""
    out = []
    for item in items:
        if not isinstance(item, Mapping):
            continue
        try:
            out.append(verdict.Comment.from_api(item))
        except ValueError:
            continue
    return tuple(out)


def read_timeline(api: GitHubApi, ctx: PublishContext) -> verdict.Timeline:
    """Every page of the PR timeline. A page or parse error: `complete=False`."""
    try:
        items = api.get_pages(f"{ctx.repo_path}/issues/{ctx.pr_number}/timeline")
        events = []
        for item in items:
            if not isinstance(item, Mapping):
                raise ValueError("timeline item is not an object")
            events.append(verdict.TimelineEvent.from_api(item))
    except (collect.CollectError, ValueError):
        return verdict.Timeline((), False)
    return verdict.Timeline(tuple(events), True)


def read_permission(api: GitHubApi, ctx: PublishContext, login: str) -> str | None:
    """The legacy `permission` field now; None when it cannot be read."""
    if not _LOGIN_RE.fullmatch(login):
        return None
    try:
        doc = api.get_json(
            f"{ctx.repo_path}/collaborators/{urllib.parse.quote(login, safe='')}/permission",
            max_bytes=PERMISSION_MAX_BYTES,
        )
    except collect.CollectError:
        return None
    perm = doc.get("permission") if isinstance(doc, Mapping) else None
    return perm if isinstance(perm, str) else None


def read_override_inputs(
    api: GitHubApi, ctx: PublishContext, pair: verdict.SnapshotPair | None
) -> tuple[verdict.OverrideInputs, tuple[verdict.Comment, ...]]:
    """All issue comments and the full timeline, every page; then the
    permission of each author whose comment passes every check but the
    permission one (spec "Override", V16).

    Returns the inputs and the comments (for the sticky lookup). Comments that
    cannot be read give no override.
    """
    try:
        comments = _parse_comments(api.get_pages(f"{ctx.repo_path}/issues/{ctx.pr_number}/comments"))
    except collect.CollectError:
        comments = ()
    timeline = read_timeline(api, ctx)
    pure = verdict.OverrideInputs(comments, timeline, {}, ctx.pr_author)
    candidates = sorted(
        {
            c.author_login.lower(): c.author_login
            for c in verdict.evaluate_overrides(pure, pair)
            if c.rejection == verdict.OV_NO_PERMISSION
        }.values()
    )
    permissions = {login: read_permission(api, ctx, login) for login in candidates}
    return verdict.OverrideInputs(comments, timeline, permissions, ctx.pr_author), comments


def read_runs(api: GitHubApi, ctx: PublishContext, head_sha: str) -> verdict.RunList:
    """Runs of any workflow on the head SHA, every page (spec "Final check").
    A list read only in part, or a run with a bad id, makes `complete=False`."""
    try:
        items, total = api.get_wrapped_pages(
            f"{ctx.repo_path}/actions/runs", "workflow_runs", params={"head_sha": head_sha}
        )
    except collect.CollectError:
        return verdict.RunList((), False)
    complete = len(items) >= total
    runs = []
    for item in items:
        rid = item.get("id") if isinstance(item, Mapping) else None
        if isinstance(rid, bool) or not isinstance(rid, int):
            complete = False
            continue
        runs.append(verdict.RunRecord(rid, _opt_str(item.get("path"))))
    return verdict.RunList(tuple(runs), complete)


# ---------------------------------------------------------------------------
# Inline review
# ---------------------------------------------------------------------------

_FINDING_KEY_RE = re.compile(r"<!-- oc-finding:([0-9a-f]{64}) ([0-9a-f]{64}) -->")
UNTRUSTED_NOTE = "Model output from untrusted input. Check it before you act on it."
VERIFIED_NOTE = "Verified means only that the quoted text is at that place. It does not mean the claim is true."


@dataclass(frozen=True)
class FindingKeys:
    """The two keys of a finding, both from the shown (redacted, cut) text.

    `d14` is the SHA-256 of `file\\0side\\0title\\0quote`. It does not change
    when the line moves or the explanation is worded again, so it is the
    across-run key. `full` is the SHA-256 of the JSON list of every shown
    field. Two findings share it only when they show the same text, so it is
    the in-run key (P3-2)."""

    d14: str
    full: str


def finding_keys(f: verdict.CitedFinding) -> FindingKeys:
    file, title, quote = (shown_field(k, getattr(f, k)) for k in ("file", "title", "quote"))
    explanation = shown_field("explanation", f.explanation)
    d14 = "\0".join((file, f.side, title, quote))
    # `json.dumps` with its defaults gives the same ASCII text for the same values.
    full = json.dumps([f.pass_name, f.category, f.severity, f.confidence, file, f.side, f.line,
                       title, quote, explanation])
    return FindingKeys(hashlib.sha256(d14.encode("utf-8")).hexdigest(),
                       hashlib.sha256(full.encode("ascii")).hexdigest())


def finding_key(f: verdict.CitedFinding) -> str:
    """The full key, which names a finding in `InlineOutcome`."""
    return finding_keys(f).full


@dataclass(frozen=True)
class PostedComment:
    """A review comment of `github-actions[bot]` whose body starts with the
    one marker it holds. `lines` holds its `line` and `original_line`."""

    d14: str
    full: str
    body: str
    path: str
    side: str
    lines: frozenset[int]


def _int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def read_posted_comments(api: GitHubApi, ctx: PublishContext) -> dict[str, tuple[PostedComment, ...]]:
    """The review comments of `github-actions[bot]` on the PR that start with
    their only marker, by D14 key. The login proves only that some Actions
    workflow in the repo wrote a comment, so `build_review` also checks its
    text. A read error gives no comments, so findings are posted again, never
    hidden."""
    try:
        items = api.get_pages(f"{ctx.repo_path}/pulls/{ctx.pr_number}/comments")
    except collect.CollectError:
        return {}
    out: dict[str, list[PostedComment]] = {}
    for item in items:
        if not isinstance(item, Mapping):
            continue
        user, body, path, side = (item.get(k) for k in ("user", "body", "path", "side"))
        if not (isinstance(user, Mapping) and user.get("login") == verdict.BOT_LOGIN):
            continue
        if not (isinstance(body, str) and isinstance(path, str) and isinstance(side, str)):
            continue
        m = _FINDING_KEY_RE.match(body)
        if m is None or len(_FINDING_KEY_RE.findall(body)) != 1:
            continue
        lines = frozenset(n for n in (_int(item.get("line")), _int(item.get("original_line"))) if n is not None)
        out.setdefault(m.group(1), []).append(PostedComment(m.group(1), m.group(2), body, path, side, lines))
    return {d14: tuple(cs) for d14, cs in out.items()}


def _diff_path(f: verdict.CitedFinding, files: Sequence[verdict.FileSides]) -> str | None:
    """The path GitHub shows for the cited file (the new path of a rename)."""
    if f.side == "base":
        for fs in files:
            if fs.old_path == f.file:
                return fs.path
    for fs in files:
        if fs.path == f.file:
            return fs.path
    return None


def _finding_line(f: verdict.CitedFinding) -> str:
    """Severity, category and confidence are schema enums; the pass name is ours."""
    return f"**{f.severity} {f.category}**, confidence {f.confidence}, pass {f.pass_name}"


def inline_comment_body(f: verdict.CitedFinding, keys: FindingKeys) -> str:
    return "\n\n".join(
        (
            f"<!-- oc-finding:{keys.d14} {keys.full} -->",
            _finding_line(f),
            _esc("title", f.title),
            _esc("explanation", f.explanation),
            f"_{UNTRUSTED_NOTE}_",
        )
    )


# The finding line of an inline comment, from the schema enums and our pass names.
_FINDING_LINE_RE = re.compile(
    r"\*\*(?:low|medium|high|critical) (?:bug|security|supply-chain|malicious|prompt-injection)\*\*, "
    r"confidence (?:low|medium|high), pass (?:" + "|".join(map(re.escape, verdict.PASS_NAMES)) + ")"
)


def _shows_same_place(c: PostedComment, f: verdict.CitedFinding, path: str, side: str) -> bool:
    """`c` has the layout of `inline_comment_body` (marker, finding line,
    title, explanation, note), at `path` and `side`, with the title of `f`.
    Its explanation and line can differ: the D14 key covers neither."""
    parts = c.body.split("\n\n")
    return (
        c.path == path
        and c.side == side
        and len(parts) == 5
        and _FINDING_LINE_RE.fullmatch(parts[1]) is not None
        and parts[2] == _esc("title", f.title)
        and parts[3] != ""
        and parts[4] == f"_{UNTRUSTED_NOTE}_"
    )


@dataclass(frozen=True)
class InlineOutcome:
    """Full keys posted by this run, full keys already on the PR, full keys
    whose D14 key is on the PR under other full keys (they show in full in
    the summary), and full keys that this run could not post (they show in
    full in the summary, D7)."""

    posted: frozenset[str] = frozenset()
    earlier: frozenset[str] = frozenset()
    changed: frozenset[str] = frozenset()
    not_posted: frozenset[str] = frozenset()
    note: str | None = None


def build_review(
    result: verdict.GateResult,
    files: Sequence[verdict.FileSides],
    posted: Mapping[str, Sequence[PostedComment]],
    head_sha: str,
) -> tuple[dict[str, Any] | None, InlineOutcome]:
    """The review request for verified, inline-eligible findings that no
    earlier comment shows, deduped by full key. Returns (request or None, the
    outcome if the request is posted).

    An earlier comment with the D14 key of a finding counts only when it has
    the inline layout, the same path, side and title (`_shows_same_place`);
    then the finding is not posted again. It is `earlier` only when that
    comment is, in full, the body this run would write, at the same line;
    else it is `changed` and the summary shows it in full. So a forged marker
    can at most move a finding from inline to its full summary block."""
    comments = []
    new: set[str] = set()
    earlier: set[str] = set()
    changed: set[str] = set()
    for f in result.findings:
        if not (f.verified and f.inline):
            continue
        keys = finding_keys(f)
        path = _diff_path(f, files)
        side = "RIGHT" if f.side == "head" else "LEFT"
        body = inline_comment_body(f, keys)
        same = [c for c in posted.get(keys.d14, ()) if path is not None and _shows_same_place(c, f, path, side)]
        if same:
            exact = any(c.full == keys.full and c.body == body and f.line in c.lines for c in same)
            (earlier if exact else changed).add(keys.full)
            continue
        if keys.full in new or path is None:
            continue
        new.add(keys.full)
        comments.append({"path": path, "line": f.line, "side": side, "body": body})
    outcome = InlineOutcome(posted=frozenset(new), earlier=frozenset(earlier), changed=frozenset(changed))
    if not comments:
        return None, outcome
    body = (
        f"OC Claude review, run {result.run_id}: {len(comments)} inline finding(s). "
        f"{UNTRUSTED_NOTE} The gate result is in the summary comment."
    )
    request = {"commit_id": head_sha, "event": REVIEW_EVENT, "body": body, "comments": comments}
    return request, outcome


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

# GitHub rejects a comment body over 65,536 characters (D8). The margin
# leaves room for the truncation notes.
SUMMARY_MAX_CHARS = 65_536
SUMMARY_LIMIT = 64_000
# The cut data is in the gate job log (`log_full_record`) and, under its cap,
# in the step summary.
TRUNCATED_NOTE = "truncated, see the run log"
OVERFLOW_NOTE = (
    "The summary does not fit in one comment, even after every permitted cut. "
    "Reasons, SHAs and override data are never cut, so this run fails closed."
)

# Cut order (D8): unverified low and medium findings, low and medium findings,
# dependency delta, signals. Every other block has no rank and is never cut:
# reasons, result, SHAs, override data, and also the blocks D8 does not list
# (high and critical findings, verified or not, model summaries, hard block
# and coverage details).
CUT_UNVERIFIED = 0
CUT_LOW_MEDIUM = 1
CUT_DEPENDENCY = 2
CUT_SIGNALS = 3
CUT_ORDER = (CUT_UNVERIFIED, CUT_LOW_MEDIUM, CUT_DEPENDENCY, CUT_SIGNALS)


def _usage_numbers(meta: Mapping[str, Any]) -> dict[str, int]:
    usage = meta.get("usage")
    out: dict[str, int] = {}
    if isinstance(usage, Mapping):
        for k, v in usage.items():
            if isinstance(k, str) and isinstance(v, int) and not isinstance(v, bool) and v >= 0:
                out[k] = v
    return out


USAGE_FIELDS = (
    ("input_tokens", "input"),
    ("output_tokens", "output"),
    ("cache_creation_input_tokens", "cache write"),
    ("cache_read_input_tokens", "cache read"),
    ("iterations", "attempts"),
)


@dataclass
class _Block:
    text: str
    rank: int | None = None  # None: never cut
    group: str = ""
    cols: int = 0  # table columns of a table row; 0 for any other block


def _cut_note(n: int, cols: int = 0) -> str:
    if cols:
        return f"| {n} item(s) {TRUNCATED_NOTE}. |" + " |" * (cols - 1)
    return f"- {n} item(s) {TRUNCATED_NOTE}."


def _fit(blocks: Sequence[_Block], limit: int) -> tuple[str | None, bool]:
    """Join blocks; cut by rank in `CUT_ORDER`, from the end of each rank,
    until it fits. Each group that lost blocks gets one note where its first
    cut block was (a table row for a table group, so the table stays whole).
    The space left after the never-cut blocks is the budget of the cut ranks.
    Returns (None, True) when the never-cut blocks alone do not fit: the
    caller fails closed (D8)."""
    keep = [True] * len(blocks)
    cut: dict[str, int] = {}
    cols_of: dict[str, int] = {}
    size = sum(len(b.text) + 1 for b in blocks) - 1  # joined with "\n"
    for rank in CUT_ORDER:
        for i in reversed(range(len(blocks))):
            if size <= limit:
                break
            b = blocks[i]
            if b.rank != rank:
                continue
            keep[i] = False
            n = cut.get(b.group, 0)
            cols_of.setdefault(b.group, b.cols)
            size -= len(b.text) + 1
            size += len(_cut_note(n + 1, b.cols)) + 1 - (len(_cut_note(n, b.cols)) + 1 if n else 0)
            cut[b.group] = n + 1
    if size > limit:
        return None, True
    out: list[str] = []
    for b, k in zip(blocks, keep):
        if k:
            out.append(b.text)
        elif b.group in cut:
            out.append(_cut_note(cut.pop(b.group), b.cols))
    return "\n".join(out), not all(keep)


# ---------------------------------------------------------------------------
# Labels. Reason codes and check IDs never show: each maps to a fixed label.
# ---------------------------------------------------------------------------

REASON_LABELS: Mapping[str, str] = {
    verdict.R_JOB_RESULT: "A required job did not succeed",
    verdict.R_ARTIFACT: "Review data could not be read",
    verdict.R_PASS_RECORDS: "A review pass failed",
    verdict.R_STALE: "Stale review",
    verdict.R_SUPERSEDED: "A newer required run exists",
    verdict.R_BASE_NOT_DEFAULT: "Wrong base branch",
    verdict.R_HARD_BLOCK: "Hard block from the file checks",
    verdict.R_DEPENDENCY_REVIEW: "Dependency review did not succeed",
    verdict.R_SIZE_GATE: "Change too large for the model review",
    verdict.R_BLOCKING_FINDING: "Blocking finding",
}
REASON_FALLBACK = "A required check failed"

CHECK_LABELS: Mapping[str, str] = {
    "bidi-control": "Hidden text-direction control",
    "bidi-control-in-path": "Hidden text-direction control in a file name",
    "foreign-source": "Dependency from a new source",
    "fresh-publish": "Recently published dependency",
    "incomplete-coverage": "Incomplete file coverage",
    "incomplete-dependency-data": "Incomplete dependency data",
    "base-dependency-file-unparsed": "Dependency file could not be read",
    "zero-width": "Hidden zero-width character",
    "invisible-character": "Hidden invisible character",
    "ai-directed-text": "Text aimed at an AI reviewer",
    "credential-like-string": "Credential-like string",
    "dependency-install-script": "Dependency with an install script",
    "package-json-install-script": "Install script added to package.json",
    "pypi-sdist-only": "Python package with source distribution only",
    "manifest-without-lockfile": "Dependency manifest without a lock file",
    "unsupported-dependency-file": "Dependency file type not checked",
    "sensitive-path": "Sensitive path changed",
    "pyproject-build-system": "Build system changed",
    "binary-file": "Binary file added",
    "submodule-change": "Submodule changed",
    "became-executable": "File became executable",
    "minified-js": "Minified script",
    "long-line": "Very long line",
    "encoded-blob": "Encoded blob",
    "first-time-contributor": "First-time contributor",
}
# Signals that point at a sensitive place get the warning mark. All other
# signals are context only.
_WARN_SIGNALS = frozenset({"sensitive-path"})

PASS_LABELS: Mapping[str, str] = {"review": "Review", "security": "Security", "supply-chain": "Supply chain"}
CODE_ROW = "Workflow (code, no model)"
FILE_CHECKS_ROW = "File checks (code, no model)"

SEVERITY_CELLS: Mapping[str, str] = {
    "critical": "⛔ **Critical**",
    "high": "🔴 **High**",
    "medium": "🟠 **Medium**",
    "low": "🟡 **Low**",
}
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}
_PASS_ORDER = {name: i for i, name in enumerate(verdict.PASS_NAMES)}

EFFECT_WAIVABLE = "Blocks, waivable"
EFFECT_NO_WAIVER = "Blocks, no waiver"
EFFECT_WAIVED = "Blocks, waived"
# Gate truth: a medium finding in a blocking category does not block, so it
# reads "Does not block" (coordinator ruling 6).
EFFECT_NONE = "Does not block"

HARD_BLOCK_CELL = "🚫 **Hard block**"
NOT_RUN_CELL = "⚠️ **Not run**"
BLOCKED_CELL = "🚫 **Blocked**"

# Reasons that mean part of the review did not complete.
_INCOMPLETE_CODES = frozenset(
    {verdict.R_PASS_RECORDS, verdict.R_ARTIFACT, verdict.R_JOB_RESULT, verdict.R_DEPENDENCY_REVIEW}
)

_WAIVER_NEXT = 'fix and push, or ask a maintainer to post the waiver line (under "Waiver" below).'


def _reason_label(code: str) -> str:
    return REASON_LABELS.get(code, REASON_FALLBACK)


def _check_label(check_id: Any) -> str:
    label = CHECK_LABELS.get(check_id) if isinstance(check_id, str) else None
    return label or _esc("label", check_id)


def _n(count: int, word: str) -> str:
    return f"{count} {word}" + ("" if count == 1 else "s")


def _code_span(kind: str, text: str, suffix: str = "") -> str:
    """A code span that is safe in a table cell. `escape_field` backslash-escapes
    punctuation, which would show inside a code span, so a span is cleaned
    and cut here instead: redacted, cut to the field limit, no backticks."""
    return _span_of(*_clean_text(text, LIMITS[kind], False), suffix)


def _span_of(joined: str, cut: bool, suffix: str = "") -> str:
    """The code span of text that `_clean_text` already cut: one marker only."""
    joined = _defang(joined).replace("`", "'").replace("<", "‹").replace("|", "\\|") + ("…" if cut else "")
    return f"`{joined or 'unknown'}{suffix}`"


def _cell(text: str) -> str:
    return text.replace("\n", " ")


def _row(*cells: str) -> str:
    return "| " + " | ".join(_cell(c) for c in cells) + " |"


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

_POSTING_TEXT: Mapping[str, str] = {
    "inline": "inline",
    "earlier": "inline, earlier run",
    "changed": "differs from the inline comment of an earlier run",
    "not-posted": "inline comment not posted",
    "meta": "PR title or body",
    "outside": "outside the diff",
    "unverified": "not posted",
}
_INLINE_STATES = frozenset({"inline", "earlier"})


def _posting_state(f: verdict.CitedFinding, inline: InlineOutcome) -> str:
    if not f.verified:
        return "unverified"
    key = finding_key(f)
    if key in inline.posted:
        return "inline"
    if key in inline.earlier:
        return "earlier"
    if key in inline.changed:
        return "changed"
    if key in inline.not_posted:
        return "not-posted"
    return "meta" if f.file in verdict.META_PATHS else "outside"


def _finding_effect(f: verdict.CitedFinding, result: verdict.GateResult) -> str:
    if not f.blocking:
        return EFFECT_NONE
    if result.override_applied:
        return EFFECT_WAIVED
    return EFFECT_WAIVABLE if verdict.WAIVABLE[verdict.R_BLOCKING_FINDING] else EFFECT_NO_WAIVER


def _cuttable(f: verdict.CitedFinding) -> bool:
    # A high or critical finding is never cut, also when it is unverified
    # (a cut file path makes it so).
    return f.severity not in verdict.BLOCKING_SEVERITIES


def _by_pass_then_severity(members: Sequence[verdict.CitedFinding]) -> list[verdict.CitedFinding]:
    return sorted(
        members,
        key=lambda f: (_PASS_ORDER.get(f.pass_name, len(_PASS_ORDER)), _SEVERITY_ORDER.get(f.severity, 9)),
    )


@dataclass
class _Row:
    """One visible row of the findings table: a hard block, a pass or job that
    did not run, or the model findings of one place that share one gate effect."""

    sort: tuple
    severity: str
    effect: str
    where: str
    claim: str
    found_by: str
    rank: int | None = None
    members: tuple[verdict.CitedFinding, ...] = ()
    is_model: bool = False
    label: str = ""  # a hard block row: its fixed label


def _found_by(pass_name: str, members: Sequence[verdict.CitedFinding]) -> str:
    """One pass of a merged row: its name, its highest severity and, when it
    reported more than one finding there, how many."""
    best = min(members, key=lambda f: _SEVERITY_ORDER.get(f.severity, 9)).severity
    more = f", {len(members)} findings" if len(members) > 1 else ""
    return f"{PASS_LABELS.get(pass_name, pass_name)} ({best}{more})"


def _merge_findings(result: verdict.GateResult, inline: InlineOutcome) -> list[_Row]:
    """Model findings, merged into one row per (shown file, side, line, gate
    effect), worst first. Different effects stay on separate rows (ruling 3).
    A merged row can be cut only when every member can be cut."""
    groups: dict[tuple[str, bool, str, int, str], list[verdict.CitedFinding]] = {}
    for f in result.findings:
        file, cut = _clean_text(f.file, LIMITS["file"], False)
        groups.setdefault((file, cut, f.side, f.line, _finding_effect(f, result)), []).append(f)
    rows: list[_Row] = []
    for (file, cut, side, line, effect), members in groups.items():
        members = _by_pass_then_severity(members)
        top = min(members, key=lambda f: _SEVERITY_ORDER.get(f.severity, 9))  # first of the best: pass order breaks ties
        unverified = [f for f in members if not f.verified]
        severity = SEVERITY_CELLS.get(top.severity, _esc("label", top.severity))
        if unverified:
            severity += " ❌ not checked"
        where = _span_of(file, cut, f":{line}") + (" (base side)" if side == "base" else "")
        states = [_posting_state(f, inline) for f in members]
        if all(s in _INLINE_STATES for s in states):
            pointer = (
                "See the inline comment from an earlier run."
                if all(s == "earlier" for s in states)
                else "See the inline comment."
            )
        elif any(s in _INLINE_STATES for s in states):
            pointer = "See the inline comment. Other findings here are in the record only."
        else:
            names = [PASS_LABELS.get(f.pass_name, f.pass_name) for f in members]
            pointer = "Summary only for " + ", ".join(dict.fromkeys(names)) + ". Details are in the record."
        claim = f"{_esc('title', top.title)} <sub>{pointer}</sub>"
        found_by = ", ".join(_found_by(name, [f for f in members if f.pass_name == name]) for name in dict.fromkeys(f.pass_name for f in members))
        if all(_cuttable(f) for f in members):
            rank = CUT_UNVERIFIED if len(unverified) == len(members) else CUT_LOW_MEDIUM
        else:
            rank = None
        rows.append(
            _Row(
                (2, _SEVERITY_ORDER.get(top.severity, 9), bool(len(unverified) == len(members)), file, line, effect),
                severity,
                effect,
                where,
                claim,
                found_by,
                rank,
                tuple(members),
                True,
            )
        )
    return rows


def _hard_block_items(payload: Mapping[str, Any] | None) -> list[Mapping[str, Any]]:
    pre = payload.get("prefilter") if isinstance(payload, Mapping) else None
    items = pre.get("hard_blocks") if isinstance(pre, Mapping) else None
    return [i for i in items or () if isinstance(i, Mapping)]


def _check_evidence(item: Mapping[str, Any]) -> str:
    """The label, detail, file, subject and lines of a prefilter item, as one line."""
    text = f"{_check_label(item.get('id'))}: {_esc('evidence', item.get('detail'))}"
    if item.get("file"):
        text += f", in {_esc('path', item.get('file'))}"
    if item.get("subject"):
        text += f", {_esc('evidence', item.get('subject'))}"
    lines = item.get("lines")
    if isinstance(lines, list) and lines:
        nums = [str(n) for n in lines[:10] if isinstance(n, int) and not isinstance(n, bool)]
        if nums:
            text += ", lines " + " ".join(nums) + (" and more" if len(lines) > 10 else "")
    return text


def _hard_block_label_of(item: Mapping[str, Any]) -> str:
    """The same text as `verdict._hard_block_label`, to match a reason to its item."""
    label = str(item.get("id"))
    file = item.get("file")
    return f"{label} in {file}" if isinstance(file, str) and file else label


def _hard_rows(result: verdict.GateResult, payload: Mapping[str, Any] | None) -> list[_Row]:
    """A row for each hard block. Items come from the bundle; a hard block
    reason with no item (missing evidence, unbound result) gets a row from the
    reason, so no hard block is ever left out of the table."""
    items = _hard_block_items(payload)
    out: list[_Row] = []
    for n, item in enumerate(items):
        file = item.get("file")
        lines = item.get("lines")
        first = next((x for x in lines if isinstance(x, int) and not isinstance(x, bool)), None) if isinstance(lines, list) else None
        if isinstance(file, str) and file:
            where = _code_span("path", file, f":{first}" if first is not None else "")
        else:
            where = "Whole PR"
        out.append(
            _Row((0, n), HARD_BLOCK_CELL, EFFECT_NO_WAIVER, where, _check_evidence(item), FILE_CHECKS_ROW,
                 label=_check_label(item.get("id")))
        )
    known = {_hard_block_label_of(i) for i in items}
    has_incomplete_item = any(i.get("id") == "incomplete-coverage" for i in items)
    for n, r in enumerate(x for x in result.reasons if x.code == verdict.R_HARD_BLOCK):
        if r.detail in known:
            continue
        if r.detail.startswith("incomplete-coverage") and has_incomplete_item:
            continue
        label = "Incomplete file coverage" if r.detail.startswith("incomplete-coverage") else "File check result"
        out.append(
            _Row((0, len(items) + n), HARD_BLOCK_CELL, EFFECT_NO_WAIVER, "Whole PR",
                 f"{label}: {_esc('reason', r.detail)}", FILE_CHECKS_ROW, label=label)
        )
    return out


def _not_run_rows(result: verdict.GateResult) -> list[_Row]:
    """Rows for every pass or job that did not complete, and for every other
    reason that is not a finding or a hard block."""
    out: list[_Row] = []
    by_pass = {p.name: p for p in result.passes}
    size_gate = any(r.code == verdict.R_SIZE_GATE for r in result.reasons)
    pass_rows = 0
    for name in verdict.PASS_NAMES:
        info = by_pass.get(name)
        label = PASS_LABELS[name]
        if info is None:
            claim = f"No valid record of the {label} pass. The pass returned no result."
        elif info.status == "ok" or (info.status == "skipped-size" and size_gate):
            continue
        else:
            reason = info.meta.get("reason")
            why = reason.strip().rstrip(".") if isinstance(reason, str) and reason.strip() else info.status
            claim = f"{_esc('reason', why)}. The pass returned no result."
        pass_rows += 1
        out.append(_Row((1, pass_rows), NOT_RUN_CELL, EFFECT_NO_WAIVER, f"{label} pass", claim, CODE_ROW))
    n = 0
    for r in result.reasons:
        if r.code in (verdict.R_HARD_BLOCK, verdict.R_BLOCKING_FINDING):
            continue
        if r.code == verdict.R_PASS_RECORDS and pass_rows:
            continue
        n += 1
        if r.code == verdict.R_SIZE_GATE:
            effect = EFFECT_WAIVED if result.override_applied else EFFECT_WAIVABLE
            out.append(
                _Row((1, 100 + n), NOT_RUN_CELL, effect, "Model passes",
                     "Too large for automatic review. File checks ran, model checks did not.", CODE_ROW)
            )
            continue
        cell = BLOCKED_CELL if r.code in (verdict.R_STALE, verdict.R_SUPERSEDED, verdict.R_BASE_NOT_DEFAULT) else NOT_RUN_CELL
        out.append(
            _Row((1, 100 + n), cell, EFFECT_NO_WAIVER, "Gate", f"{_reason_label(r.code)}: {_esc('reason', r.detail)}", CODE_ROW)
        )
    return out


def _findings_table(rows: list[_Row]) -> list[_Block]:
    if not rows:
        return []
    out = [
        _Block("\n| Severity | Effect | Where | Finding | Found by |"),
        _Block("|---|---|---|---|---|"),
    ]
    for r in rows:
        out.append(_Block(_row(r.severity, r.effect, r.where, r.claim, r.found_by), r.rank, "findings-table", 5))
    return out


# ---------------------------------------------------------------------------
# Result heading, callout, checks strip, provenance
# ---------------------------------------------------------------------------


def _payload_of(bundle: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
    if bundle is not None and bundle.get("status") in verdict.BUNDLE_PAYLOAD_STATUSES:
        payload = bundle.get("payload")
        if isinstance(payload, Mapping):
            return payload
    return None


def _model_rows(rows: list[_Row]) -> list[_Row]:
    return [r for r in rows if r.is_model]


def _status_heading(result: verdict.GateResult, model_rows: list[_Row]) -> str:
    if result.status != verdict.FAIL:
        if model_rows and not result.override_applied:
            return f"## 🟡 PASS: OC Claude review, {_n(len(model_rows), 'finding')} to consider"
        return "## 🟢 PASS: OC Claude review"
    if result.codes & _INCOMPLETE_CODES:
        return "## 🔴 FAIL: OC Claude review did not complete"
    return "## 🔴 FAIL: OC Claude review"


def _blocking_phrase(model_rows: list[_Row]) -> str:
    blocking = [r for r in model_rows if r.effect != EFFECT_NONE]
    if len(blocking) == 1:
        top = min(blocking[0].members, key=lambda f: _SEVERITY_ORDER.get(f.severity, 9))
        return f"One {top.severity}-severity {top.category.replace('-', ' ')} finding"
    return f"{len(blocking)} findings"


def _callout(result: verdict.GateResult, rows: list[_Row], hard: list[_Row], has_payload: bool) -> str:
    """The colored callout. Kind: TIP for a pass with no findings, NOTE for a
    pass with findings, CAUTION for every fail, waivable or not (ruling 1).
    The text says whether a waiver can clear it."""
    model = _model_rows(rows)
    codes = result.codes
    if result.status != verdict.FAIL:
        if result.override_applied:
            login = _esc("login", result.valid_overrides[0].author_login) if result.valid_overrides else "a maintainer"
            lines = [f"**A maintainer waiver was applied by {login}. Findings stay listed.** Nothing to do for this review."]
        elif model:
            one = len(model) == 1
            lines = [
                f"**{_n(len(model), 'finding')} to consider. {'It does' if one else 'They do'} not block this PR.**",
                f"**Next step for the author:** read the finding{'' if one else 's'} and fix what you agree with.",
            ]
            return "\n".join(f"> {x}" for x in ("[!NOTE]", *lines))
        else:
            lines = ["**No findings. This review found no reason to block.** Nothing to do for this review."]
        lines.append("The merge box shows whether the other required checks pass.")
        return "\n".join(f"> {x}" for x in ("[!TIP]", *lines))

    blocking = [r for r in model if r.effect != EFFECT_NONE]
    also = f" {_blocking_phrase(model)} also blocks." if blocking else ""
    failed = [
        PASS_LABELS[name]
        for name in verdict.PASS_NAMES
        if not any(p.name == name and p.status == "ok" for p in result.passes)
        and not (any(p.name == name and p.status == "skipped-size" for p in result.passes) and verdict.R_SIZE_GATE in codes)
    ]
    if hard and has_payload:  # with no bundle the hard rows are synthetic: the author cannot fix a missing artifact
        label = hard[0].label
        if len(hard) == 1:
            first = f"**{label} blocks this PR. No waiver can clear it.**{also}"
        else:
            first = f"**{label} and {len(hard) - 1} other hard block(s) block this PR. No waiver can clear them.**{also}"
        nxt = "**Next step for the author:** fix the cause named in the row, then push. The review runs again on the new commit."
    elif codes & _INCOMPLETE_CODES:
        if failed and verdict.R_PASS_RECORDS in codes:
            who = " and ".join(failed) if len(failed) <= 2 else "Review, Security and Supply chain"
            first = f"**The {who} {'review' if len(failed) == 1 else 'reviews'} did not run, so this PR could not be judged. No waiver can clear this.**{also}"
        else:
            first = f"**A required check did not complete, so this PR could not be judged. No waiver can clear this.**{also}"
        nxt = "**Next step:** a maintainer re-runs the newest run of the required workflow once the cause is fixed. "
        nxt += (
            f"The author also fixes or waives the finding{'' if len(blocking) == 1 else 's'}."
            if blocking
            else "The author does not need to change anything."
        )
    elif verdict.R_BASE_NOT_DEFAULT in codes:
        ref = _esc("ref", result.snapshot.base_ref) if result.snapshot else "another branch"
        first = f"**This PR targets {ref}, not the default branch. No waiver can clear this.**{also}"
        nxt = "**Next step for the author:** retarget the PR to the default branch."
    elif verdict.R_SUPERSEDED in codes:
        first = f"**A newer required run exists for this commit. No waiver can clear this.**{also}"
        nxt = "**Next step:** read the newest run in the merge box."
    elif verdict.R_STALE in codes:
        first = f"**This review is out of date. No waiver can clear this.**{also}"
        nxt = "**Next step:** read the newest run in the merge box."
    elif verdict.R_SIZE_GATE in codes:
        first = "**The change is too large for the model review. A maintainer can waive this.** File checks ran, model checks did not."
        nxt = '**Next step for the author:** split the change, or ask a maintainer for a waiver (under "Waiver" below).'
    else:
        phrase = _blocking_phrase(model)
        verb = "blocks" if phrase.startswith("One") else "block"
        who = "it" if phrase.startswith("One") else "them"
        first = f"**{phrase} {verb} this PR.** A maintainer can waive {who}."
        nxt = f"**Next step for the author:** {_WAIVER_NEXT}"
    return "\n".join(f"> {x}" for x in ("[!CAUTION]", first, nxt))


def _checks_strip(result: verdict.GateResult, payload: Mapping[str, Any] | None, hard_count: int) -> _Block:
    """One-row table: what ran. Never cut."""
    if payload is None:
        file_cell, coverage_cell = "❌ no result", "❌ unknown"
    else:
        pre = payload.get("prefilter") if isinstance(payload.get("prefilter"), Mapping) else {}
        signals = len([s for s in pre.get("signals") or () if isinstance(s, Mapping)])
        file_cell = f"🚫 {_n(hard_count, 'hard block')}" if hard_count else "✅ ok"
        if signals:
            file_cell += f", {_n(signals, 'signal')}"
        cov = payload.get("coverage")
        coverage_cell = "✅ complete" if isinstance(cov, Mapping) and cov.get("complete") is True else "🚫 incomplete"
    by_pass = {p.name: p for p in result.passes}
    unvalidated = payload is None and bool(result.codes & {verdict.R_ARTIFACT, verdict.R_PASS_RECORDS})
    cells = []
    for name in verdict.PASS_NAMES:
        info = by_pass.get(name)
        count = len([f for f in result.findings if f.pass_name == name])
        if info is None:
            cells.append("❌ missing")
        elif info.status == "ok" and unvalidated:
            cells.append("⚠️ not validated")
        elif info.status == "ok":
            cells.append(f"✅ ran, {_n(count, 'finding')}")
        elif info.status == "skipped-size":
            cells.append("⚠️ skipped, too large")
        else:
            cells.append(f"❌ {_esc('label', info.status)}")
    dep_failed = any(
        r.code == verdict.R_DEPENDENCY_REVIEW or (r.code == verdict.R_JOB_RESULT and verdict.DEPENDENCY_REVIEW_JOB in r.detail)
        for r in result.reasons
    )
    dep_cell = "❌ failed" if dep_failed else "✅ ok"
    return _Block(
        "\n".join(
            (
                "\n| File checks | Review | Security | Supply chain | Dependency review | Coverage |",
                "|:---:|:---:|:---:|:---:|:---:|:---:|",
                _row(file_cell, *cells, dep_cell, coverage_cell),
            )
        )
    )


def _provenance(ctx: PublishContext, result: verdict.GateResult, truncated: bool) -> _Block:
    snap = result.snapshot
    run = f"Run [{ctx.run_id}, attempt {ctx.run_attempt}]({ctx.run_url})"
    if snap is not None:
        where = f"for head `{snap.head_sha[:7]}` into {_esc('ref', snap.base_ref)}."
    else:
        where = f"for event head `{ctx.head_sha[:7]}`, merge base unknown."
    text = f"{run} {where} The required workflow in the merge box is the result that counts. This bot never approves a PR."
    if truncated:
        text += " Some details were truncated, see the run log."
    return _Block(f"\n<sub>{text}</sub>")


# ---------------------------------------------------------------------------
# Collapsed sections
# ---------------------------------------------------------------------------


def _details(summary: str, inner: Sequence[_Block]) -> list[_Block]:
    """`<details>` with never-cut open and close blocks, so a cut can never
    unbalance the tags."""
    return [_Block(f"\n<details>\n<summary>{summary}</summary>"), *inner, _Block("\n</details>")]


def _waiver_blocks(result: verdict.GateResult) -> list[_Block]:
    if result.override_command is None:
        return []
    text = (
        "\nThis PR fails for waivable reasons only. A person with write or admin access, who is not the PR "
        "author, posts this exact line as a new comment and replaces `<reason>` with the reason. Then they "
        "re-run the newest run of the required workflow through the GitHub REST API "
        "(`POST .../actions/runs/{run_id}/rerun`). Do not edit the comment afterwards. Do not close and "
        "reopen the PR to apply the waiver.\n\n```\n" + result.override_command + "\n```\n\n"
        "A waiver covers the code at this exact head and merge base. Any new push needs a new waiver."
    )
    return _details("🔑 Waiver: how a maintainer clears this", [_Block(text)])


def _title(text: str) -> _Block:
    return _Block(f"\n**{text}**\n")


def _snapshot_blocks(ctx: PublishContext, result: verdict.GateResult) -> list[_Block]:
    snap = result.snapshot
    run = f"{ctx.run_id}, attempt {ctx.run_attempt}"
    if snap is None:
        return [_title("Reviewed snapshot"),
                _Block(f"No valid bundle. Event head SHA `{ctx.head_sha}`, merge base unknown. Run {run}.")]
    return [
        _title("Reviewed snapshot"),
        _Block("| Head SHA | Merge base SHA | Base branch | Run |"),
        _Block("|---|---|---|---|"),
        _Block(_row(f"`{snap.head_sha}`", f"`{snap.merge_base_sha}`", _esc("ref", snap.base_ref), run)),
    ]


def _reason_blocks(result: verdict.GateResult) -> list[_Block]:
    out = [_title("Reasons the gate failed")]
    if not result.reasons:
        return out + [_Block("None. No reason applies.")]
    out += [_Block("| Reason | Waivable? | Detail |"), _Block("|---|---|---|")]
    for r in result.reasons:
        flag = ("✅ yes, waived" if result.override_applied else "✅ yes") if r.waivable else "🚫 no"
        out.append(_Block(_row(_reason_label(r.code), flag, _esc("reason", r.detail))))
    if result.status == verdict.FAIL and result.override_command is None:
        out.append(
            _Block(
                "\nNo waiver line is shown. At least one reason cannot be waived, so a waiver would not "
                "change the result."
            )
        )
    return out


def _override_blocks(ctx: PublishContext, result: verdict.GateResult) -> list[_Block]:
    valid = result.valid_overrides
    if not valid:
        return []
    waived = ", ".join(_reason_label(r.code) for r in result.waived) or "none"
    out = [
        _title("Maintainer waivers"),
        _Block("| Author | Time | Reason | Comment | Applied | Waived reasons |"),
        _Block("|---|---|---|---|---|---|"),
    ]
    for c in valid:
        out.append(
            _Block(
                _row(
                    _esc("login", c.author_login),
                    c.created_at.isoformat(),
                    _esc("reason", c.reason),
                    f"[comment]({ctx.comment_url(c.comment_id)})",
                    "yes" if result.override_applied else "no",
                    waived,
                )
            )
        )
    return out


def _check_block(item: Any, rank: int | None, group: str, mark: str = "") -> _Block | None:
    if not isinstance(item, Mapping):
        return None
    return _Block(f"- {mark}{_check_evidence(item)}", rank, group)


def _delta_blocks(delta: Any) -> list[_Block]:
    if not isinstance(delta, Mapping):
        return []
    out: list[_Block] = []
    for ch in delta.get("changes") or ():
        if not isinstance(ch, Mapping):
            continue
        old = ch.get("old_versions")
        olds = " ".join(_esc("version", v) for v in old) if isinstance(old, list) and old else "none"
        source = ch.get("source") if isinstance(ch.get("source"), Mapping) else {}
        text = (
            f"- {_esc('label', ch.get('ecosystem'))} {_esc('package_name', ch.get('name'))}: "
            f"{olds} to {_esc('version', ch.get('new_version'))}, "
            f"source {_esc('label', source.get('kind'))} {_esc('url', source.get('normalized'))}, "
            f"in {_esc('path', ch.get('path'))}"
        )
        reg = ch.get("registry")
        if isinstance(reg, Mapping):
            text += f", published {_esc('label', reg.get('published'))}"
            scripts = reg.get("install_scripts")
            if isinstance(scripts, Mapping) and scripts:
                text += ", install scripts " + " ".join(_esc("label", k) for k in sorted(map(str, scripts)))
        if ch.get("has_install_script") is True:
            text += ", has install script"
        out.append(_Block(text, CUT_DEPENDENCY, "dependency"))
    for s in delta.get("new_global_sources") or ():
        if isinstance(s, Mapping):
            src = s.get("source") if isinstance(s.get("source"), Mapping) else {}
            out.append(
                _Block(
                    f"- new file-wide source in {_esc('path', s.get('path'))}: {_esc('url', src.get('normalized'))}",
                    CUT_DEPENDENCY,
                    "dependency",
                )
            )
    for fl in delta.get("failures") or ():
        if isinstance(fl, Mapping):
            out.append(
                _Block(
                    f"- failed: {_esc('path', fl.get('path'))}: {_esc('reason', fl.get('reason'))}",
                    CUT_DEPENDENCY,
                    "dependency",
                )
            )
    return out


def _check_table_blocks(result: verdict.GateResult, payload: Mapping[str, Any] | None) -> list[_Block]:
    """The "Checks (code, no model)" table: hard blocks, coverage, dependency changes
    and the dependency-review job. Hard block evidence and unavailable files are never cut."""
    out = [_title("Checks (code, no model)"), _Block("| Check | Result | Detail |"), _Block("|---|---|---|")]
    if payload is None:
        return out + [_Block(_row("File checks", "❌ no result", "No bundle payload was available."))]
    items = _hard_block_items(payload)
    if items:
        out += [_Block(_row("Hard block", "🚫 blocks", _check_evidence(i))) for i in items]
    else:
        out.append(_Block(_row("Hard blocks", "✅ none", "")))
    cov = payload.get("coverage")
    if not isinstance(cov, Mapping):
        out.append(_Block(_row("Coverage", "❌ no record", "")))
    else:
        nums = []
        for k, label in (("files_in_comparison", "files in comparison"), ("files_collected", "files collected")):
            v = cov.get(k)
            if isinstance(v, int) and not isinstance(v, bool):
                nums.append(f"{label} {v}")
        trees = cov.get("trees_complete")
        if isinstance(trees, bool):
            nums.append("trees complete" if trees else "trees NOT complete")
        out.append(
            _Block(_row("Coverage", "✅ complete" if cov.get("complete") is True else "🚫 NOT complete", ", ".join(nums)))
        )
        files = cov.get("files")
        for f in files if isinstance(files, list) else ():
            if isinstance(f, Mapping) and f.get("coverage") == "unavailable":
                out.append(
                    _Block(_row("Unavailable file", "⚠️ unavailable", f"{_esc('path', f.get('path'))}: {_esc('reason', f.get('reason'))}"))
                )
    has_delta = bool(_delta_blocks(payload.get("dependency_delta")))
    out.append(_Block(_row("Dependency changes", "ℹ️ listed below" if has_delta else "✅ none", "")))
    dep_failed = any(
        r.code == verdict.R_DEPENDENCY_REVIEW or (r.code == verdict.R_JOB_RESULT and verdict.DEPENDENCY_REVIEW_JOB in r.detail)
        for r in result.reasons
    )
    out.append(_Block(_row("Dependency review job", "❌ failed" if dep_failed else "✅ success", "")))
    return out


def _signal_blocks(payload: Mapping[str, Any] | None) -> list[_Block]:
    out = [_title("Signals (context only, never block)")]
    pre = payload.get("prefilter") if isinstance(payload, Mapping) and isinstance(payload.get("prefilter"), Mapping) else {}
    items = []
    for i in pre.get("signals") or ():
        mark = "⚠️ " if isinstance(i, Mapping) and i.get("id") in _WARN_SIGNALS else "ℹ️ "
        blk = _check_block(i, CUT_SIGNALS, "signals", mark)
        if blk:
            items.append(blk)
    return out + (items or [_Block("None.")])


def _finding_block(f: verdict.CitedFinding, inline: InlineOutcome) -> _Block | None:
    """The record bullet of a finding that has no inline comment, with its
    explanation and quote. None for a finding that has one (its row says so)."""
    state = _posting_state(f, inline)
    if state in _INLINE_STATES:
        return None
    where = f"{_esc('file', f.file)} line {f.line} ({f.side})"
    head = f"- {_finding_line(f)}, at {where}: {_esc('title', f.title)}"
    # A high or critical finding is never cut, also when it is unverified.
    protected = not _cuttable(f)
    if state == "unverified":
        return _Block(
            "\\\n  ".join(
                (
                    head,
                    f"Not verified: {_esc('reason', f.unverified_reason or 'unknown')}",
                    _esc("explanation", f.explanation),
                    f"Quote: {_esc('quote', f.quote)}",
                )
            ),
            None if protected else CUT_UNVERIFIED,
            "unverified",
        )
    note = {
        "changed": "Differs from the inline comment of an earlier run, shown here.",
        "not-posted": "Inline comment not posted, shown here.",
        "meta": "PR title or body, summary only.",
        "outside": "Outside the diff, summary only.",
    }[state]
    return _Block(
        "\\\n  ".join((head, note, _esc("explanation", f.explanation), f"Quote: {_esc('quote', f.quote)}")),
        None if protected else CUT_LOW_MEDIUM,
        f"findings-{f.pass_name}",
    )


def _finding_detail_blocks(result: verdict.GateResult, inline: InlineOutcome) -> list[_Block]:
    out = [_title("Finding details"), _Block(f"> **{UNTRUSTED_NOTE}** {VERIFIED_NOTE}\n")]
    out.append(
        _Block(
            "Blocking is decided by code from category and severity, never by the model. "
            "A finding in a blocking category blocks only at high or critical severity."
        )
    )
    if inline.note:
        out.append(_Block("\n" + _esc("reason", inline.note)))
    by_pass = {p.name: p for p in result.passes}
    ran = [n for n in verdict.PASS_NAMES if by_pass.get(n) is not None and by_pass[n].status == "ok"]
    not_ran = [PASS_LABELS[n] for n in verdict.PASS_NAMES if n not in ran]
    findings = _by_pass_then_severity(result.findings)
    if findings:
        if any(len(r.members) > 1 for r in _merge_findings(result, inline)):
            out.append(
                _Block("\nEach row above merges findings of several passes at the same file, line and gate effect.")
            )
        out += [
            _Block("\n| Pass | Severity | Category | Confidence | Citation | Posted | Model title |"),
            _Block("|---|---|---|---|---|---|---|"),
        ]
        for f in findings:
            rank = None if not _cuttable(f) else (CUT_UNVERIFIED if not f.verified else CUT_LOW_MEDIUM)
            out.append(
                _Block(
                    _row(
                        PASS_LABELS.get(f.pass_name, f.pass_name),
                        f.severity,
                        f.category.replace("-", " "),
                        f.confidence,
                        "✅ checked" if f.verified else "❌ not checked",
                        _POSTING_TEXT[_posting_state(f, inline)],
                        _esc("title", f.title),
                    ),
                    rank,
                    "detail-rows",
                    7,
                )
            )
        bullets = [x for x in (_finding_block(f, inline) for f in findings) if x is not None]
        if bullets:
            out.append(_Block("\nFindings with no inline comment, in full:\n"))
            out += bullets
        quiet = [PASS_LABELS[n] for n in ran if not any(f.pass_name == n for f in findings)]
        for label in quiet:
            out.append(_Block(f"\nThe {label} pass completed and reported no findings."))
    elif not not_ran:
        out.append(_Block("\nNo findings. All three passes completed."))
    else:
        out.append(
            _Block(
                f"\nNo findings from the passes that ran. The {', '.join(not_ran)} pass did not run, "
                "so this is not a clean result."
            )
        )
    if findings and not_ran:
        out.append(_Block(f"\nThe {', '.join(not_ran)} pass did not run, so this is not a clean result."))
    return out


def _summary_table_blocks(result: verdict.GateResult) -> list[_Block]:
    out = [
        _title("Model summaries"),
        _Block(f"> **{UNTRUSTED_NOTE}** {VERIFIED_NOTE}\n"),
        _Block("| Pass | Status | Model | Summary |"),
        _Block("|---|---|---|---|"),
    ]
    by_pass = {p.name: p for p in result.passes}
    for name in verdict.PASS_NAMES:
        info = by_pass.get(name)
        label = PASS_LABELS[name]
        if info is None:
            out.append(_Block(_row(label, "❌ missing", "", "No valid pass record.")))
            continue
        model = info.meta.get("model")
        status = "✅ ok" if info.status == "ok" else f"❌ {_esc('label', info.status)}"
        if info.summary:
            # One line: a multi-line summary would end the table row.
            text = escape_text(info.summary, LIMITS["summary"])
        else:
            reason = info.meta.get("reason")
            text = "No summary." + (f" Reason: {_esc('reason', reason)}" if isinstance(reason, str) and reason else "")
        out.append(_Block(_row(label, status, _esc("model", model) if isinstance(model, str) else "", text)))
    return out


def _token_blocks(result: verdict.GateResult) -> list[_Block]:
    out = [
        _title("Token usage"),
        _Block("| Pass | Input | Output | Cache write | Cache read | Attempts |"),
        _Block("|---|---:|---:|---:|---:|---:|"),
    ]
    by_pass = {p.name: p for p in result.passes}
    totals: dict[str, int] = {}
    missing = False
    for name in verdict.PASS_NAMES:
        info = by_pass.get(name)
        nums = _usage_numbers(info.meta) if info is not None else {}
        cells = []
        for k, _label in USAGE_FIELDS:
            if k in nums:
                totals[k] = totals.get(k, 0) + nums[k]
                cells.append(str(nums[k]))
            else:
                missing = True
                cells.append("not recorded")
        out.append(_Block(_row(PASS_LABELS[name], *cells)))
    out.append(
        _Block(
            _row(
                "**Recorded total**" if missing else "**Total**",
                *(str(totals[k]) if k in totals else "not recorded" for k, _label in USAGE_FIELDS),
            )
        )
    )
    return out


def _record_blocks(ctx: PublishContext, result: verdict.GateResult, payload: Mapping[str, Any] | None,
                   inline: InlineOutcome) -> list[_Block]:
    inner: list[_Block] = []
    inner += _snapshot_blocks(ctx, result)
    inner += _reason_blocks(result)
    inner += _override_blocks(ctx, result)
    inner += _check_table_blocks(result, payload)
    inner += _signal_blocks(payload)
    inner.append(_title("Dependency changes"))
    delta = _delta_blocks(payload.get("dependency_delta")) if payload is not None else []
    inner += delta or [_Block("None.")]
    inner += _finding_detail_blocks(result, inline)
    inner += _summary_table_blocks(result)
    inner += _token_blocks(result)
    return _details(
        "📋 Full review record: reasons, checks, signals, finding details, model summaries, token usage", inner
    )


@dataclass(frozen=True)
class RenderedSummary:
    """The sticky summary body. `cut`: D8 cuts were made (the full record goes
    to the run log). `overflow`: the never-cut data did not fit, so the body is
    the short fail-closed notice and the run must fail."""

    body: str
    cut: bool
    overflow: bool = False


def _overflow_body(ctx: PublishContext, result: verdict.GateResult) -> str:
    """The fail-closed notice when the never-cut data does not fit (D8). It
    has a fixed size: the result, the SHAs, a count per reason code and the
    override count. The full record is in the run log."""
    counts: dict[str, int] = {}
    for r in result.reasons:
        counts[r.code] = counts.get(r.code, 0) + 1
    lines = [
        verdict.STICKY_MARKER,
        "## 🔴 FAIL: OC Claude review could not publish",
        "",
        "> [!CAUTION]",
        f"> **The full review does not fit in one comment.** {OVERFLOW_NOTE}",
        "> **Next step:** see the run log.",
        "",
        f"The computed gate result was {result.status}. The full record (every reason, override, "
        "finding and prefilter result) is in the run log.",
    ]
    lines += [b.text for b in _snapshot_blocks(ctx, result)]
    lines += ["", "**Reasons**", ""]
    if not counts:
        lines.append("No reason applies.")
    else:
        lines += ["| Reason | Waivable? | Count |", "|---|---|---|"]
        for code in sorted(counts):
            flag = "✅ yes" if verdict.WAIVABLE[code] else "🚫 no"
            lines.append(_row(_reason_label(code), flag, f"{counts[code]} reason(s)"))
    lines.append(f"\n{len(result.valid_overrides)} valid override(s).")
    lines.append(f"\n<sub>Run [{ctx.run_id}, attempt {ctx.run_attempt}]({ctx.run_url}). "
                 "The required workflow in the merge box is the result that counts. This bot never approves a PR.</sub>")
    return "\n".join(lines)


def _summary_blocks(
    ctx: PublishContext,
    result: verdict.GateResult,
    payload: Mapping[str, Any] | None,
    inline: InlineOutcome,
    truncated: bool,
) -> list[_Block]:
    hard = _hard_rows(result, payload)
    rows = sorted(
        [*hard, *_not_run_rows(result), *_merge_findings(result, inline)],
        key=lambda r: r.sort,
    )
    model = _model_rows(rows)
    b = [
        _Block(verdict.STICKY_MARKER),
        _Block(_status_heading(result, model)),
        _Block("\n" + _callout(result, rows, hard, payload is not None)),
    ]
    b += _findings_table(rows)
    b.append(_checks_strip(result, payload, len(hard)))
    b.append(_provenance(ctx, result, truncated))
    b += _waiver_blocks(result)
    b += _record_blocks(ctx, result, payload, inline)
    return b


def render_summary(
    ctx: PublishContext,
    result: verdict.GateResult,
    *,
    bundle: Mapping[str, Any] | None,
    inline: InlineOutcome,
    limit: int = SUMMARY_LIMIT,
) -> RenderedSummary:
    """The sticky summary body (D8). Every untrusted string goes through
    `escape_field` (or `_code_span`). Layout: result heading, callout, findings
    table, checks strip, provenance, then the collapsed waiver and record."""
    payload = _payload_of(bundle)
    body, cut = _fit(_summary_blocks(ctx, result, payload, inline, False), limit)
    if body is not None and cut:
        # The provenance line says so when a cut was made. Its longer text is
        # in the fit, so the body still fits.
        body, cut = _fit(_summary_blocks(ctx, result, payload, inline, True), limit)
    if body is None:
        return RenderedSummary(_overflow_body(ctx, result), True, overflow=True)
    return RenderedSummary(body, cut)


def _step_summary_record(
    ctx: PublishContext, result: verdict.GateResult | None, codes: Sequence[str], publish_error: str | None = None
) -> str:
    """One JSON line: run, result, reason codes and token counts per pass (D6).
    Only integers and fixed names, so no fence escape is needed. A failed
    publication makes the result `fail` and adds `publish_error`. A stale
    run (`stale` in the codes) is `fail` too: stale is never waivable, and an
    early stale exit can hold a gate result computed before the run went stale."""
    passes: dict[str, Any] = {}
    for info in result.passes if result is not None else ():
        model = info.meta.get("model")
        passes[info.name] = {
            "status": info.status,
            "model": re.sub(r"[^A-Za-z0-9._:-]", "", model)[:100] if isinstance(model, str) else None,
            "usage": _usage_numbers(info.meta),
        }
    record: dict[str, Any] = {
        "run_id": ctx.run_id,
        "run_attempt": ctx.run_attempt,
        "result": verdict.FAIL if result is None or publish_error is not None or verdict.R_STALE in codes else result.status,
        "reasons": sorted(set(codes)),
        "passes": passes,
    }
    if publish_error is not None:
        record["publish_error"] = publish_error
    return json.dumps(record, ensure_ascii=True, separators=(",", ":"))


def _fence(text: str) -> str:
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}\n{text}\n{fence}"


# GitHub caps the step summary of one step at 1 MiB.
STEP_SUMMARY_FULL_MAX = 512 * 1024


def _redact_strings(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, Mapping):
        return {k: _redact_strings(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_redact_strings(v) for v in value]
    return value


def full_record(ctx: PublishContext, result: verdict.GateResult, bundle: Mapping[str, Any] | None) -> str:
    """Everything the summary shows, as JSON with credentials redacted: the
    reasons, the overrides, every finding, and the bundle's prefilter results,
    coverage and dependency delta. For the run log when the comment was cut (D8)."""
    payload = None
    if bundle is not None and bundle.get("status") in verdict.BUNDLE_PAYLOAD_STATUSES:
        payload = bundle.get("payload")
    payload = payload if isinstance(payload, Mapping) else {}
    snap = result.snapshot
    doc = {
        "run_id": ctx.run_id,
        "run_attempt": ctx.run_attempt,
        "result": result.status,
        "head_sha": snap.head_sha if snap is not None else ctx.head_sha,
        "merge_base_sha": snap.merge_base_sha if snap is not None else None,
        "base_ref": snap.base_ref if snap is not None else None,
        "reasons": [{"code": r.code, "waivable": r.waivable, "detail": r.detail} for r in result.reasons],
        "override_applied": result.override_applied,
        "waived": [r.code for r in result.waived],
        "overrides": [
            {
                "author": c.author_login,
                "created_at": c.created_at.isoformat(),
                "reason": c.reason,
                "comment_url": ctx.comment_url(c.comment_id),
            }
            for c in result.valid_overrides
        ],
        "findings": [
            {
                "pass": f.pass_name,
                "category": f.category,
                "severity": f.severity,
                "confidence": f.confidence,
                "file": f.file,
                "side": f.side,
                "line": f.line,
                "title": f.title,
                "explanation": f.explanation,
                "quote": f.quote,
                "verified": f.verified,
                "inline": f.inline,
                "unverified_reason": f.unverified_reason,
            }
            for f in result.findings
        ],
        "prefilter": payload.get("prefilter"),
        "coverage": payload.get("coverage"),
        "dependency_delta": payload.get("dependency_delta"),
    }
    return json.dumps(_redact_strings(doc), ensure_ascii=True, indent=1)


def log_full_record(text: str) -> None:
    """Print the full record to the gate job log: the "run log" that each cut
    note names. The record holds untrusted text, so workflow commands are
    stopped while it prints (`::stop-commands::` with a random token)."""
    token = secrets.token_hex(16)
    print(f"::stop-commands::{token}")
    print("oc-claude-review full record (the summary comment was cut):")
    print(text)
    print(f"::{token}::", flush=True)


def append_step_summary(
    path: Path | str | None,
    ctx: PublishContext,
    result: verdict.GateResult | None,
    *,
    codes: Sequence[str] = (),
    full: str | None = None,
    publish_error: str | None = None,
) -> None:
    """Append the JSON line (spec "Cost reporting": token counts, no currency),
    and the full record when the summary was cut and it fits under the cap."""
    if not path:
        return
    codes = list(codes) or ([r.code for r in result.reasons] if result is not None else [])
    parts = ["oc-claude-review record:", _fence(_step_summary_record(ctx, result, codes, publish_error))]
    if full is not None and len(full) <= STEP_SUMMARY_FULL_MAX:
        parts += ["Full record (the summary comment was cut):", _fence(full)]
    elif full is not None:
        parts.append("The summary comment was cut. The full record is over the step summary cap; it is in the gate job log.")
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n\n".join(parts) + "\n")
    except OSError as exc:
        print(f"publish: cannot write the step summary: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Writes and the run
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SummaryWrite:
    """The result of one summary write. `comment_id` can be None after a
    successful POST whose response has no usable id."""

    ok: bool
    comment_id: int | None = None


def write_summary(
    api: GitHubApi,
    ctx: PublishContext,
    comments: Sequence[verdict.Comment],
    body: str,
    sticky_id: int | None = None,
) -> SummaryWrite:
    """PATCH the bot's sticky comment, or POST a new one. Never raises; a
    refused write gives `ok=False`."""
    if sticky_id is None:
        sticky = verdict.find_sticky_comment(comments)
        sticky_id = sticky.id if sticky is not None else None
    try:
        if sticky_id is not None:
            api.write("PATCH", f"{ctx.repo_path}/issues/comments/{sticky_id}", {"body": body})
            return SummaryWrite(True, sticky_id)
        doc = api.write("POST", f"{ctx.repo_path}/issues/{ctx.pr_number}/comments", {"body": body})
    except WriteError as exc:
        print(f"publish: summary write failed: {exc}", file=sys.stderr)
        return SummaryWrite(False)
    cid = doc.get("id")
    return SummaryWrite(True, cid if isinstance(cid, int) and not isinstance(cid, bool) else None)


def post_inline_review(
    api: GitHubApi,
    ctx: PublishContext,
    result: verdict.GateResult,
    files: Sequence[verdict.FileSides],
    head_sha: str,
    snap: snapshot.Snapshot | None,
) -> InlineOutcome | None:
    """Post one `COMMENT` review for the new inline findings. Returns None
    when the fresh snapshot check before the write shows the run stale."""
    if not any(f.verified and f.inline for f in result.findings):
        return InlineOutcome()
    request, outcome = build_review(result, files, read_posted_comments(api, ctx), head_sha)
    if request is None:
        return outcome
    check = check_snapshot(api, ctx, snap)
    if check.blocks_writes:
        print(f"publish: {check.describe()} before the inline review; no more writes", file=sys.stderr)
        return None
    try:
        api.write("POST", f"{ctx.repo_path}/pulls/{ctx.pr_number}/reviews", request)
    except WriteError as exc:
        # D7: one review per run. On 422 (a position GitHub's PR view does
        # not have) or any other failure, every finding of the request goes
        # to the summary. The gate does not change.
        if exc.status == 422:
            why = "GitHub rejected the inline review (HTTP 422)"
        else:
            why = "the inline review could not be posted"
        print(f"publish: {why}: {exc}", file=sys.stderr)
        return replace(
            outcome, posted=frozenset(), not_posted=outcome.posted, note=f"{why}; its findings are shown in full here."
        )
    return outcome


def _artifact_stale(result: verdict.GateResult) -> bool:
    """A stale status in the bundle or a pass record (not the publisher's own
    missing re-check, which `SnapshotRead` covers)."""
    return any(r.code == verdict.R_STALE and r.detail != verdict.NOT_REVALIDATED for r in result.reasons)


def publish(
    api: GitHubApi,
    ctx: PublishContext,
    *,
    data_dir: Path | str,
    needs: Any,
    dependency_outcome_env: str | None,
    digests: Mapping[str, str],
    step_summary: Path | str | None = None,
) -> int:
    """The gate job. Returns the exit code: 0 only for `pass`."""
    bundle_read, pass_reads = load_artifacts(data_dir, digests)
    snap = bundle_snapshot(bundle_read)
    pair = verdict.SnapshotPair(snap.head_sha, snap.merge_base_sha, snap.base_ref) if snap else None
    head_sha = snap.head_sha if snap else ctx.head_sha

    check = check_snapshot(api, ctx, snap)
    if check.blocks_writes:
        print(f"publish: {check.describe()}; nothing written", file=sys.stderr)
        append_step_summary(step_summary, ctx, None, codes=[verdict.R_STALE])
        return 1
    overrides, comments = read_override_inputs(api, ctx, pair)
    files = bundle_files(bundle_read)
    result = verdict.compute_gate(
        verdict.GateInputs(
            context=ctx.run_context,
            job_results=job_results(needs),
            dependency_review_outcome=dependency_review_outcome(needs, dependency_outcome_env),
            bundle=bundle_read,
            passes=pass_reads,
            revalidation=check.revalidation,
            prefilter=verdict.prefilter_evidence_from_bundle(bundle_read),
            files=files,
            overrides=overrides,
        )
    )
    if _artifact_stale(result):
        print("publish: the run is stale; nothing written", file=sys.stderr)
        append_step_summary(step_summary, ctx, result)
        return 1

    # a) inline review
    inline = post_inline_review(api, ctx, result, files, head_sha, snap)
    if inline is None:
        append_step_summary(step_summary, ctx, result, codes=[*result.codes, verdict.R_STALE])
        return 1

    # b) sticky summary
    check = check_snapshot(api, ctx, snap)
    if check.blocks_writes:
        print(f"publish: {check.describe()} before the summary; no more writes", file=sys.stderr)
        append_step_summary(step_summary, ctx, result, codes=[*result.codes, verdict.R_STALE])
        return 1
    bundle_doc = bundle_read.envelope if bundle_read.error is None else None
    summary = render_summary(ctx, result, bundle=bundle_doc, inline=inline)
    full = full_record(ctx, result, bundle_doc) if summary.cut else None
    if full is not None:
        log_full_record(full)
    written = write_summary(api, ctx, comments, summary.body)
    # The summary must be published in full (spec acceptance: a refused
    # summary write leaves the run failed; D8: never-cut data that does not
    # fit fails closed). This is not a gate reason, so no override applies.
    publish_error = None
    if not written.ok:
        publish_error = "the summary write failed"
    elif summary.overflow:
        publish_error = "the summary is over the comment limit"

    # c) final check: snapshot, override authority and run list read again
    check = check_snapshot(api, ctx, snap)
    overrides, comments = read_override_inputs(api, ctx, pair)
    runs = read_runs(api, ctx, head_sha)
    final = verdict.final_check(result, revalidation=check.revalidation, overrides=overrides, runs=runs)
    if check.blocks_writes:
        print(f"publish: {check.describe()} at the final check; no sticky update", file=sys.stderr)
        append_step_summary(
            step_summary, ctx, final, codes=[*final.codes, verdict.R_STALE], full=full, publish_error=publish_error
        )
        return 1
    if result.passed and not final.passed:
        # Best effort: the exit code is non-zero whatever this write does. The
        # reads above can take many pages, so check the snapshot once more.
        summary = render_summary(ctx, final, bundle=bundle_doc, inline=inline)
        check = check_snapshot(api, ctx, snap)
        if check.blocks_writes:
            print(f"publish: {check.describe()} before the summary update; no more writes", file=sys.stderr)
            append_step_summary(
                step_summary, ctx, final, codes=[*final.codes, verdict.R_STALE], full=full, publish_error=publish_error
            )
            return 1
        if summary.cut:
            full = full_record(ctx, final, bundle_doc)
            log_full_record(full)
        updated = write_summary(api, ctx, comments, summary.body, written.comment_id)
        # The step summary carries the full record of the comment as it stands:
        # none when the final summary was not cut, the initial one when the
        # update failed.
        if not summary.cut and updated.ok:
            full = None

    # d) exit code
    append_step_summary(step_summary, ctx, final, full=full, publish_error=publish_error)
    print(f"publish: result {final.status}, reasons {', '.join(sorted(final.codes)) or 'none'}")
    if publish_error is not None:
        print(f"publish: {publish_error}; the run fails", file=sys.stderr)
        return 1
    return verdict.exit_code(final)


def main(argv: Sequence[str] | None = None, *, transport: collect.Transport | None = None) -> int:
    """Workflow entry (plan 2.3.3). Any unexpected error exits 1: the gate fails closed."""
    parser = argparse.ArgumentParser(description="Gate job: compute the gate and write the PR comments.")
    parser.add_argument("--data-dir", required=True)
    parser.add_argument("--needs-json", required=True)
    args = parser.parse_args(argv)
    env = os.environ
    try:
        event = envelope.parse_json(Path(env["GITHUB_EVENT_PATH"]).read_bytes())
        ctx = PublishContext.from_event(
            event,
            run_id=int(env["GITHUB_RUN_ID"]),
            run_attempt=int(env["GITHUB_RUN_ATTEMPT"]),
            server_url=env.get("GITHUB_SERVER_URL"),
        )
        try:
            needs = envelope.parse_json(Path(args.needs_json).read_bytes())
        except (OSError, envelope.EnvelopeError) as exc:
            print(f"publish: needs JSON unreadable ({exc}); every job counts as missing", file=sys.stderr)
            needs = {}
        api = GitHubApi(env["GITHUB_TOKEN"], transport or collect.default_transport)
        return publish(
            api,
            ctx,
            data_dir=args.data_dir,
            needs=needs,
            dependency_outcome_env=env.get("DEPENDENCY_REVIEW_OUTCOME"),
            digests={k: env.get(v, "") for k, v in DIGEST_ENV.items()},
            step_summary=env.get("GITHUB_STEP_SUMMARY"),
        )
    except Exception as exc:  # noqa: BLE001 - fail closed on any error
        print(f"publish failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
