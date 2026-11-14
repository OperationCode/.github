"""Fixture builder for the live evals: source files -> `bundle.json`.

    python -m tests.eval_fixtures --check   # rebuild in memory, diff, exit 1 on a difference
    python -m tests.eval_fixtures --write   # rewrite every bundle.json

A case is a directory of `tests/fixtures` (the standard set) or
`tests/fixtures-long-context` (the long-context set, run on request) with a
`source/` directory:

- `source/pr.json`: `{"number", "title", "body", "author_association"}`, and
  optionally `"comments"`: PR comments, each `{"id", "login", "permission",
  "body"}`, where `permission` is the commenter's collaborator permission (so a
  `/oc-review size-limit Nx` raise goes through collect's real checks);
- `source/base/<path>.fixture` and `source/head/<path>.fixture`: the files of
  the merge base and the head. The `.fixture` suffix keeps GitHub (dependency
  graph, workflow and language detection) from reading them as real files;
  the builder strips it;
- `source/registry.json` (optional): registry responses by URL, in the
  `tests/unit/fixtures/collect` route-map shape (`{"status", "json"}`).

A case named in `GENERATED` also gets the files of its generator in this
module (trusted code), so a large case does not commit its bulk source.

The builder synthesizes the GitHub responses that `collect.collect()` reads
(PR, base ref, compare, two recursive trees, blobs with real git blob SHAs,
the PR comments and their commenters' permissions)
and runs the real `collect()` with a fixed clock, run ID and attempt. So the
hard blocks, signals and redaction in each committed bundle come from the real
prefilter, and a unit test checks that each committed bundle equals a fresh
build. It runs trusted code on fixture data, offline; it executes nothing
from a case.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:  # `python -m tests.eval_fixtures` from review/
    sys.path.insert(0, str(_SRC))

from oc_review import collect, deps, evals, prefilter  # noqa: E402

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
LONG_CONTEXT_DIR = Path(__file__).resolve().parent / "fixtures-long-context"
FIXTURE_ROOTS = (FIXTURES_DIR, LONG_CONTEXT_DIR)
SOURCE_DIR = "source"
SOURCE_SUFFIX = ".fixture"
BUNDLE_NAME = collect.BUNDLE_FILE_NAME

NOW = datetime(2026, 10, 26, 12, 0, 0, tzinfo=UTC)
RUN_ID = 123456
RUN_ATTEMPT = 1
REPOSITORY = evals.EVAL_REPOSITORY
REPOSITORY_ID = 42
HEAD_REPOSITORY_ID = 4242
BASE_REF = "main"
PR_KEYS = frozenset({"number", "title", "body", "author_association"})
COMMENT_KEYS = frozenset({"id", "login", "permission", "body"})
COMMENT_TIME = "2026-10-26T11:00:00Z"  # before NOW; created_at == updated_at (not edited)


class FixtureError(Exception):
    """A case source that the builder cannot turn into GitHub responses."""


@dataclass(frozen=True)
class CaseSource:
    name: str
    pr: Mapping[str, Any]
    base: Mapping[str, bytes]  # path -> blob bytes
    head: Mapping[str, bytes]
    registry: Mapping[str, Any]  # URL -> {"status", "json"}


def _commit_sha(case: str, role: str) -> str:
    """A fixed commit SHA per case and role. No real commit has to exist: the
    API responses are synthesized."""
    return hashlib.sha1(f"oc-eval-fixture {case} {role}".encode()).hexdigest()


def _read_tree(root: Path) -> dict[str, bytes]:
    if not root.is_dir():
        return {}
    out: dict[str, bytes] = {}
    for p in sorted(root.rglob("*")):
        if p.is_symlink():
            raise FixtureError(f"{p}: symbolic links are not allowed")
        if not p.is_file():
            continue
        rel = p.relative_to(root).as_posix()
        if not rel.endswith(SOURCE_SUFFIX):
            raise FixtureError(f"{p}: source files must end in {SOURCE_SUFFIX}")
        out[rel[: -len(SOURCE_SUFFIX)]] = p.read_bytes()
    return out


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise FixtureError(f"{path}: {type(exc).__name__}: {exc}") from exc


def _check_comments(path: Path, comments: Any) -> None:
    if not isinstance(comments, list):
        raise FixtureError(f"{path}: comments must be a list")
    for c in comments:
        if not isinstance(c, dict) or set(c) != COMMENT_KEYS:
            raise FixtureError(f"{path}: each comment's keys must be exactly {sorted(COMMENT_KEYS)}")
        if type(c["id"]) is not int or not all(isinstance(c[k], str) for k in ("login", "permission", "body")):
            raise FixtureError(f"{path}: comment id must be an integer, the other keys strings")


def load_source(case_dir: Path) -> CaseSource:
    src = case_dir / SOURCE_DIR
    pr = _load_json(src / "pr.json")
    if not isinstance(pr, dict) or not PR_KEYS <= set(pr) <= PR_KEYS | {"comments"}:
        raise FixtureError(f"{src / 'pr.json'}: keys must be exactly {sorted(PR_KEYS)}, plus an optional comments")
    _check_comments(src / "pr.json", pr.get("comments", []))
    registry_path = src / "registry.json"
    registry = _load_json(registry_path) if registry_path.exists() else {}
    if not isinstance(registry, dict):
        raise FixtureError(f"{registry_path}: must be a JSON object")
    base, head = _read_tree(src / "base"), _read_tree(src / "head")
    if case_dir.name in GENERATED:
        gen_base, gen_head = GENERATED[case_dir.name]()
        if (base.keys() & gen_base.keys()) or (head.keys() & gen_head.keys()):
            raise FixtureError(f"{case_dir.name}: a generated path is also in source/")
        base, head = {**base, **gen_base}, {**head, **gen_head}
    if base == head:
        raise FixtureError(f"{case_dir.name}: base and head are the same")
    return CaseSource(case_dir.name, pr, base, head, registry)


def case_dirs(root: Path | str = FIXTURES_DIR) -> list[Path]:
    """Every case directory with a source (sorted)."""
    root = Path(root)
    if not root.is_dir():
        return []
    return sorted(p for p in root.iterdir() if p.is_dir() and (p / SOURCE_DIR).is_dir())


# ---------------------------------------------------------------- generated sources


# long-context-4x: a logger migration across many service modules, about
# 800,000 estimated tokens in full mode. Its planted defect is in the
# hand-written source/ files; this bulk only has to be realistic, valid and
# free of prefilter signals. Index arithmetic, not `random`: the output must
# be the same on every Python version.
_LC_DOMAINS = ("billing", "chapters", "donations", "events", "jobs", "members",
               "mentors", "newsletters", "scholarships", "surveys", "volunteers", "workshops")
_LC_FUNCTIONS_PER_MODULE = 21  # the size knob: one more is about 30,000 estimated tokens (48 modules)
_LC_ENTITIES = ("Record", "Request", "Profile", "Invite", "Slot")
_LC_VERBS = ("create", "update", "archive", "restore", "approve", "reject", "assign", "schedule", "close", "reopen")
_LC_FIELDS = ("title", "status", "ownerId", "region", "startsAt", "endsAt", "summary", "priority", "channel", "tags")
_LC_MODULE_NAMES = ("store", "workflow", "reports", "notifications")


def _lc_module(domain: str, name: str, structured: bool) -> str:
    """One service module. `structured` is the head side: the new logger
    import, and every 7th function logs with pino's `(obj, msg)` order."""
    table = f"{domain}{name.capitalize()}"
    if structured:
        header = f'const log = require("../../lib/logger").child({{ module: "{domain}/{name}" }});'
    else:
        header = 'const log = require("../../lib/legacyLog");'
    out = [
        '"use strict";',
        "",
        f"// {domain} {name}: data access and state changes for the {domain} service.",
        "",
        'const { ValidationError } = require("../../lib/errors");',
        header,
        "",
    ]
    names = []
    pairs = [(verb, entity) for verb in _LC_VERBS for entity in _LC_ENTITIES][:_LC_FUNCTIONS_PER_MODULE]
    for k, (verb, entity) in enumerate(pairs):
        fn = f"{verb}{entity}"
        names.append(fn)
        # 3k+1 and k differ by an odd number, so the two fields always differ (10 fields).
        f1, f2 = _LC_FIELDS[k % len(_LC_FIELDS)], _LC_FIELDS[(k * 3 + 1) % len(_LC_FIELDS)]
        what = f"{verb} {domain} {entity.lower()}"
        done = f'log.info({{ id }}, "{what}");' if structured and k % 7 == 3 else f'log.info("{what}", id);'
        out += [
            "/**",
            f" * {verb.capitalize()} a {entity.lower()} in the {domain} {name}.",
            " * Returns the updated record, or null when no record has this id.",
            " */",
            f"async function {fn}(db, id, input = {{}}) {{",
            f"  const record = await db.{table}.findById(id);",
            "  if (!record) {",
            f'    log.warn("{what}: not found", id);',
            "    return null;",
            "  }",
            "  const next = {",
            "    ...record,",
            f"    {f1}: input.{f1} ?? record.{f1},",
            f"    {f2}: input.{f2} ?? record.{f2},",
            f'    lastAction: "{verb}",',
            "    updatedAt: new Date().toISOString(),",
            "  };",
            f"  if (next.{f1} === undefined || next.{f1} === null) {{",
            f'    throw new ValidationError("{entity.lower()} {f1} is required");',
            "  }",
            f"  await db.{table}.update(id, next);",
            f"  {done}",
            "  return next;",
            "}",
            "",
        ]
    out.append("module.exports = {")
    out += [f"  {n}," for n in names]
    out += ["};", ""]
    return "\n".join(out)


def _lc_test(domain: str, structured: bool) -> str:
    mock = ('jest.mock("../../src/lib/logger", () => ({ child: () => ({ info: jest.fn(), warn: jest.fn() }) }));'
            if structured else 'jest.mock("../../src/lib/legacyLog", () => ({ info: jest.fn(), warn: jest.fn() }));')
    out = ['"use strict";', "", mock, ""]
    for name in _LC_MODULE_NAMES:
        table = f"{domain}{name.capitalize()}"
        out += [f'const {name} = require("../../src/modules/{domain}/{name}");', ""]
        out += [f'describe("{domain} {name}", () => {{']
        for entity in _LC_ENTITIES:
            fn = f"update{entity}"
            out += [
                f'  it("{fn} returns null for a missing id", async () => {{',
                f"    const db = {{ {table}: {{ findById: async () => null, update: jest.fn() }} }};",
                f"    expect(await {name}.{fn}(db, 7, {{}})).toBeNull();",
                f"    expect(db.{table}.update).not.toHaveBeenCalled();",
                "  });",
                "",
            ]
        out += ["});", ""]
    return "\n".join(out)


def _lc_doc(domain: str, structured: bool) -> str:
    logging = ("Each module logs through `src/lib/logger.js` with a `module` field."
               if structured else "Each module logs through `src/lib/legacyLog.js`.")
    return "\n".join([
        f"# {domain.capitalize()} service",
        "",
        f"The {domain} service has four modules: " + ", ".join(f"`{n}`" for n in _LC_MODULE_NAMES) + ".",
        "",
        logging,
        "",
        "Every state change sets `lastAction` and `updatedAt`, and returns null when the id does not exist.",
        "",
    ])


_LC_LOGGER = """"use strict";

// Structured logger: JSON lines with a level, a time and a module field.

const pino = require("pino");

module.exports = pino({ level: process.env.LOG_LEVEL || "info" });
"""

_LC_LEGACY_LOG = """"use strict";

// Plain text logger (replaced by logger.js).

module.exports = {
  info: (msg, id) => console.log(`[info] ${msg} ${id}`),
  warn: (msg, id) => console.warn(`[warn] ${msg} ${id}`),
};
"""


def _long_context_files() -> tuple[dict[str, bytes], dict[str, bytes]]:
    base: dict[str, bytes] = {"src/lib/legacyLog.js": _LC_LEGACY_LOG.encode()}
    head: dict[str, bytes] = {"src/lib/legacyLog.js": _LC_LEGACY_LOG.encode(), "src/lib/logger.js": _LC_LOGGER.encode()}
    for domain in _LC_DOMAINS:
        for name in _LC_MODULE_NAMES:
            path = f"src/modules/{domain}/{name}.js"
            base[path], head[path] = (_lc_module(domain, name, s).encode() for s in (False, True))
        path = f"test/{domain}/{domain}.test.js"
        base[path], head[path] = (_lc_test(domain, s).encode() for s in (False, True))
        path = f"docs/services/{domain}.md"
        base[path], head[path] = (_lc_doc(domain, s).encode() for s in (False, True))
    return base, head


GENERATED: dict[str, Callable[[], tuple[dict[str, bytes], dict[str, bytes]]]] = {
    "long-context-4x": _long_context_files,
}


# ---------------------------------------------------------------- synthesized responses


def _tree(files: Mapping[str, bytes]) -> dict[str, Any]:
    items = [
        {"path": path, "mode": "100644", "type": "blob", "sha": prefilter.git_blob_sha(data), "size": len(data)}
        for path, data in sorted(files.items())
    ]
    sha = hashlib.sha1(json.dumps(items, sort_keys=True).encode()).hexdigest()
    return {"sha": sha, "tree": items, "truncated": False}


def _changed_files(source: CaseSource) -> int:
    return sum(1 for p in source.base.keys() | source.head.keys() if source.base.get(p) != source.head.get(p))


def github_routes(source: CaseSource) -> tuple[dict[str, Any], dict[str, bytes]]:
    """The trusted event and the GitHub responses by request path (with query)."""
    head_sha = _commit_sha(source.name, "head")
    merge_base = _commit_sha(source.name, "merge-base")
    owner, name = REPOSITORY.split("/")
    repo = f"/repos/{urllib.parse.quote(owner, safe='')}/{urllib.parse.quote(name, safe='')}"
    number = source.pr["number"]
    pr = {
        "number": number,
        "state": "open",
        "title": source.pr["title"],
        "body": source.pr["body"],
        "user": {"login": evals.EVAL_PR_AUTHOR},
        "author_association": source.pr["author_association"],
        "labels": [],
        "draft": False,
        "changed_files": _changed_files(source),
        "head": {"sha": head_sha, "ref": f"eval/{source.name}",
                 "repo": {"id": HEAD_REPOSITORY_ID, "full_name": f"{evals.EVAL_PR_AUTHOR}/{name}", "fork": True}},
        "base": {"sha": merge_base, "ref": BASE_REF,
                 "repo": {"id": REPOSITORY_ID, "full_name": REPOSITORY, "default_branch": BASE_REF, "fork": False}},
    }
    # The base tip is the merge base: the PR branch is ahead of main.
    compare = {
        "status": "ahead",
        "base_commit": {"sha": merge_base},
        "merge_base_commit": {"sha": merge_base},
        "commits": [{"sha": head_sha}],
    }
    routes: dict[str, bytes] = {
        f"{repo}/pulls/{number}": json.dumps(pr).encode(),
        f"{repo}/git/ref/heads/{BASE_REF}": json.dumps(
            {"ref": f"refs/heads/{BASE_REF}", "object": {"sha": merge_base, "type": "commit"}}
        ).encode(),
        f"{repo}/compare/{merge_base}...{head_sha}?per_page=1": json.dumps(compare).encode(),
        f"{repo}/git/trees/{merge_base}?recursive=1": json.dumps(_tree(source.base)).encode(),
        f"{repo}/git/trees/{head_sha}?recursive=1": json.dumps(_tree(source.head)).encode(),
    }
    comments = source.pr.get("comments", [])
    routes[f"{repo}/issues/{number}/comments?per_page=100"] = json.dumps([
        {"id": c["id"], "user": {"login": c["login"], "type": "User"}, "body": c["body"],
         "created_at": COMMENT_TIME, "updated_at": COMMENT_TIME,
         "html_url": f"https://github.com/{REPOSITORY}/pull/{number}#issuecomment-{c['id']}"}
        for c in comments
    ]).encode()
    permissions: dict[str, str] = {}
    for c in comments:
        if permissions.setdefault(c["login"].lower(), c["permission"]) != c["permission"]:
            raise FixtureError(f"{source.name}: {c['login']} has two permissions")
        routes[f"{repo}/collaborators/{urllib.parse.quote(c['login'], safe='')}/permission"] = json.dumps(
            {"permission": c["permission"]}).encode()
    for data in (*source.base.values(), *source.head.values()):
        routes[f"{repo}/git/blobs/{prefilter.git_blob_sha(data)}"] = data
    event = {
        "repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
        "pull_request": {"number": number, "head": {"sha": head_sha}},
    }
    return event, routes


class _Transport:
    """Serves the synthesized responses; any other request fails the build."""

    def __init__(self, routes: Mapping[str, bytes]) -> None:
        self.routes = routes

    def __call__(self, request: collect.HttpRequest) -> collect.HttpResponse:
        parts = urllib.parse.urlsplit(request.url)
        if request.method != "GET" or parts.scheme != "https" or parts.hostname != collect.API_HOST:
            raise FixtureError(f"unexpected request {request.method} {request.url}")
        key = parts.path + (f"?{parts.query}" if parts.query else "")
        if key not in self.routes:
            raise FixtureError(f"unsynthesized request {key}")
        return collect.HttpResponse(200, self.routes[key][: request.max_bytes + 1], request.url)


def _registry_fetch(registry: Mapping[str, Any]) -> deps.Fetcher:
    def fetch(url: str, max_bytes: int, timeout: float) -> deps.FetchResult:
        rec = registry.get(url)
        if rec is None:
            return deps.FetchResult(404, b"", url)
        return deps.FetchResult(rec["status"], json.dumps(rec["json"]).encode(), url)

    return fetch


def build(case_dir: Path) -> collect.Collected:
    """Run the real collect() over one case's synthesized responses."""
    return build_source(load_source(case_dir))


def build_source(source: CaseSource) -> collect.Collected:
    event, routes = github_routes(source)
    client = collect.GitHubClient("eval-fixture-token", _Transport(routes), retries=0, sleep=lambda s: None)
    collected = collect.collect(
        client,
        collect.EventContext.from_event(event),
        run_id=RUN_ID,
        run_attempt=RUN_ATTEMPT,
        now=NOW,
        registry_fetch=_registry_fetch(source.registry),
        registry_sleep=lambda s: None,
    )
    if collected.envelope["status"] != "ok":
        raise FixtureError(f"{source.name}: bundle status is {collected.envelope['status']}, not ok")
    return collected


def bundle_text(collected: collect.Collected) -> bytes:
    """The committed file: indented, ASCII-escaped JSON, so invisible and bidi
    characters show as escapes in a diff."""
    return (json.dumps(collected.envelope, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def _all_case_dirs(root: Path | str | None) -> list[Path]:
    """The cases of `root`, or of every fixture root when it is None."""
    return case_dirs(root) if root is not None else [d for r in FIXTURE_ROOTS for d in case_dirs(r)]


def check(root: Path | str | None = None) -> list[str]:
    """Problems: a case whose committed bundle differs from a fresh build."""
    problems = []
    for case_dir in _all_case_dirs(root):
        try:
            fresh = bundle_text(build(case_dir))
        except (FixtureError, collect.CollectError) as exc:
            problems.append(f"{case_dir.name}: build failed: {exc}")
            continue
        path = case_dir / BUNDLE_NAME
        if not path.exists():
            problems.append(f"{case_dir.name}: {BUNDLE_NAME} is missing")
        elif path.read_bytes() != fresh:
            problems.append(f"{case_dir.name}: {BUNDLE_NAME} differs from a fresh build (run --write)")
    return problems


def write(root: Path | str | None = None) -> list[Path]:
    written = []
    for case_dir in _all_case_dirs(root):
        path = case_dir / BUNDLE_NAME
        path.write_bytes(bundle_text(build(case_dir)))
        written.append(path)
    return written


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the eval fixture bundles from their sources.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="rebuild in memory and compare with the committed bundles")
    mode.add_argument("--write", action="store_true", help="rewrite every bundle.json")
    parser.add_argument("--fixtures-dir", default=None, help="one fixture root (default: every fixture root)")
    args = parser.parse_args(argv)
    cases = _all_case_dirs(args.fixtures_dir)
    if not cases:
        print(f"eval_fixtures: no cases in {args.fixtures_dir!r}", file=sys.stderr)
        return 1
    if args.write:
        for path in write(args.fixtures_dir):
            print(f"wrote {path}")
        return 0
    problems = check(args.fixtures_dir)
    for p in problems:
        print(p, file=sys.stderr)
    if not problems:
        print(f"eval_fixtures: {len(cases)} bundles match a fresh build")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
