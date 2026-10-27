"""Fixture builder for the live evals: source files -> `bundle.json`.

    python -m tests.eval_fixtures --check   # rebuild in memory, diff, exit 1 on a difference
    python -m tests.eval_fixtures --write   # rewrite every bundle.json

A case is a directory of `tests/fixtures` with a `source/` directory:

- `source/pr.json`: `{"number", "title", "body", "author_association"}`;
- `source/base/<path>.fixture` and `source/head/<path>.fixture`: the files of
  the merge base and the head. The `.fixture` suffix keeps GitHub (dependency
  graph, workflow and language detection) from reading them as real files;
  the builder strips it;
- `source/registry.json` (optional): registry responses by URL, in the
  `tests/unit/fixtures/collect` route-map shape (`{"status", "json"}`).

The builder synthesizes the GitHub responses that `collect.collect()` reads
(PR, base ref, compare, two recursive trees, blobs with real git blob SHAs)
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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:  # `python -m tests.eval_fixtures` from review/
    sys.path.insert(0, str(_SRC))

from oc_review import collect, deps, evals, prefilter  # noqa: E402

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
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


def load_source(case_dir: Path) -> CaseSource:
    src = case_dir / SOURCE_DIR
    pr = _load_json(src / "pr.json")
    if not isinstance(pr, dict) or set(pr) != PR_KEYS:
        raise FixtureError(f"{src / 'pr.json'}: keys must be exactly {sorted(PR_KEYS)}")
    registry_path = src / "registry.json"
    registry = _load_json(registry_path) if registry_path.exists() else {}
    if not isinstance(registry, dict):
        raise FixtureError(f"{registry_path}: must be a JSON object")
    base, head = _read_tree(src / "base"), _read_tree(src / "head")
    if base == head:
        raise FixtureError(f"{case_dir.name}: base and head are the same")
    return CaseSource(case_dir.name, pr, base, head, registry)


def case_dirs(root: Path | str = FIXTURES_DIR) -> list[Path]:
    """Every case directory with a source (sorted)."""
    return sorted(p for p in Path(root).iterdir() if p.is_dir() and (p / SOURCE_DIR).is_dir())


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
    source = load_source(case_dir)
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
        raise FixtureError(f"{case_dir.name}: bundle status is {collected.envelope['status']}, not ok")
    return collected


def bundle_text(collected: collect.Collected) -> bytes:
    """The committed file: indented, ASCII-escaped JSON, so invisible and bidi
    characters show as escapes in a diff."""
    return (json.dumps(collected.envelope, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")


def check(root: Path | str = FIXTURES_DIR) -> list[str]:
    """Problems: a case whose committed bundle differs from a fresh build."""
    problems = []
    for case_dir in case_dirs(root):
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


def write(root: Path | str = FIXTURES_DIR) -> list[Path]:
    written = []
    for case_dir in case_dirs(root):
        path = case_dir / BUNDLE_NAME
        path.write_bytes(bundle_text(build(case_dir)))
        written.append(path)
    return written


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the eval fixture bundles from their sources.")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true", help="rebuild in memory and compare with the committed bundles")
    mode.add_argument("--write", action="store_true", help="rewrite every bundle.json")
    parser.add_argument("--fixtures-dir", default=str(FIXTURES_DIR))
    args = parser.parse_args(argv)
    if not case_dirs(args.fixtures_dir):
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
        print(f"eval_fixtures: {len(case_dirs(args.fixtures_dir))} bundles match a fresh build")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
