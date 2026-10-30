"""Local reproduction harness for collect's dependency stage (developer tool).

    cd review
    uv run python tools/dep_repro.py --repo OWNER/NAME --head HEAD_SHA --base MERGE_BASE_SHA

It reads the two trees and the changed blobs through the GitHub REST API (the
token comes from `gh auth token`, or GITHUB_TOKEN), as data only: it never
checks out, installs, builds or runs anything from the repo. Then it runs the
same code as a collect run on those blobs: `collect.dependency_facts` (same
parser, delta, lookup code, limits and worker count) against the live
registries, and `prefilter.run_prefilter` on the result. It prints the keys,
unique names, decoded and wire bytes of the registry responses, the wall
time, each failed lookup log line, and every hard block and signal with a
count.

Pass the merge base as `--base`, as collect does. The PR title, body and
author association are not read, so the checks that use them see empty text.
Not imported by production code and not run in CI: it makes live calls.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import os
import re
import subprocess
import sys
import threading
import time
import urllib.request
from collections import Counter
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from oc_review import collect, deps, prefilter  # noqa: E402
from oc_review.snapshot import diff_trees  # noqa: E402

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
_MB = 1_000_000


class _Meter:
    """Registry traffic of one run: fetches, decoded and wire bytes."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.fetches = 0
        self.decoded = 0
        self.wire = 0
        self.errors: Counter[str] = Counter()


class _CountingResponse:
    """Wraps a urllib response and counts the bytes read from the socket."""

    def __init__(self, resp: Any, meter: _Meter) -> None:
        self._resp = resp
        self._meter = meter

    def read(self, n: int = -1) -> bytes:
        data = self._resp.read(n)
        with self._meter.lock:
            self._meter.wire += len(data)
        return data

    def __enter__(self) -> _CountingResponse:
        self._resp.__enter__()
        return self

    def __exit__(self, *exc: Any) -> None:
        self._resp.__exit__(*exc)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._resp, name)


class _CountingOpener:
    def __init__(self, meter: _Meter) -> None:
        self._opener = urllib.request.build_opener(deps._NoRedirect)
        self._meter = meter

    def open(self, request: Any, timeout: float) -> _CountingResponse:
        return _CountingResponse(self._opener.open(request, timeout=timeout), self._meter)


def _metered_fetch(meter: _Meter) -> deps.Fetcher:
    opener = _CountingOpener(meter)

    def fetch(url: str, max_bytes: int, timeout: float) -> deps.FetchResult:
        with meter.lock:
            meter.fetches += 1
        try:
            result = deps.default_fetch(url, max_bytes, timeout, opener=opener)
        except Exception as exc:
            with meter.lock:
                meter.errors[type(exc).__name__] += 1
            raise
        with meter.lock:
            meter.decoded += len(result.body)
        return result

    return fetch


def _token() -> str:
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        return token
    return subprocess.run(["gh", "auth", "token"], check=True, capture_output=True, text=True).stdout.strip()


def _sha(value: str) -> str:
    if not _SHA_RE.match(value):
        raise argparse.ArgumentTypeError("not a 40-character lowercase hex SHA")
    return value


def run(repo: str, head: str, base: str) -> int:
    owner, name = repo.split("/")
    repo_path = f"/repos/{owner}/{name}"
    client = collect.GitHubClient(_token())
    base_tree = collect._read_tree(client, repo_path, base)
    head_tree = collect._read_tree(client, repo_path, head)
    diff = diff_trees(base_tree.response, head_tree.response)
    if not diff.complete:
        print("tree diff is incomplete (truncated tree); collect would hard block")
        return 1
    sizes = {**base_tree.sizes, **head_tree.sizes}
    blobs, unread = collect._read_blobs(
        client, repo_path, collect._blob_shas(diff), sizes,
        max_blob_bytes=prefilter.MAX_BLOB_BYTES, max_reads=collect.MAX_BLOB_READS,
    )

    meter = _Meter()
    log = io.StringIO()
    started = time.monotonic()
    with contextlib.redirect_stderr(log):
        facts = collect.dependency_facts(diff, blobs, fetch=_metered_fetch(meter))
    wall = time.monotonic() - started
    result = prefilter.run_prefilter(
        diff, blobs, head_paths=head_tree.paths, now=datetime.now(UTC),
        dependencies=facts, unread_reasons=unread,
    )

    keys = sorted({k for ch in facts.changes if (k := prefilter.registry_key(ch)) is not None})
    missing = [k for k in keys if k not in facts.registry]
    files = [c.path for c in diff.files if deps.family_for_path(c.path) is not None]
    print(f"repo {repo} head {head} base {base}")
    print(f"code: collect.MAX_REGISTRY_BYTES={collect.MAX_REGISTRY_BYTES} "
          f"concurrency={collect.REGISTRY_LOOKUP_CONCURRENCY} "
          f"time budget={collect.REGISTRY_LOOKUP_BUDGET_SECONDS}s "
          f"npm cap={deps.NPM_MAX_RESPONSE_BYTES}")
    print(f"changed files {len(diff.files)}, dependency files {len(files)}: {', '.join(files) or '-'}")
    print(f"package changes {len(facts.changes)}, registry keys {len(keys)}, "
          f"unique names {len({k[:2] for k in keys})}")
    print(f"registry fetches {meter.fetches}, decoded {meter.decoded / _MB:.1f} MB, "
          f"wire {meter.wire / _MB:.1f} MB, lookup wall time {wall:.1f} s")
    if meter.errors:
        print("fetch exceptions: " + ", ".join(f"{k} {v}" for k, v in sorted(meter.errors.items())))
    print(f"keys with registry data {len(keys) - len(missing)}, keys without {len(missing)}")

    lines = [line for line in log.getvalue().splitlines() if line]
    by_class = Counter(m.group(1) for line in lines if (m := re.search(r"': (\w+): ", line)))
    print(f"\nfailed lookup log lines: {len(lines)}" + (
        " (" + ", ".join(f"{k} {v}" for k, v in sorted(by_class.items())) + ")" if by_class else ""))
    for line in lines:
        print(f"  {line}")

    for kind, checks in (("hard blocks", result.hard_blocks), ("signals", result.signals)):
        counts = Counter((c.id, c.detail) for c in checks)
        print(f"\n{kind}: {len(checks)}")
        for (cid, detail), n in sorted(counts.items()):
            print(f"  {n:4d}  {cid}: {detail}")
            subjects = sorted({f"{c.file}: {c.subject}" if c.subject else str(c.file)
                               for c in checks if (c.id, c.detail) == (cid, detail)})
            for s in subjects[:20]:
                print(f"          {s!r}")
            if len(subjects) > 20:
                print(f"          ... {len(subjects) - 20} more")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--repo", required=True, help="OWNER/NAME")
    parser.add_argument("--head", required=True, type=_sha, help="head commit SHA")
    parser.add_argument("--base", required=True, type=_sha, help="merge base commit SHA")
    args = parser.parse_args(argv)
    if not collect._REPO_RE.match(args.repo):
        parser.error("--repo must be OWNER/NAME")
    return run(args.repo, args.head, args.base)


if __name__ == "__main__":
    sys.exit(main())
