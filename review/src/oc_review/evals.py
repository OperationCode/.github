"""Eval runner: the live review passes over fixture bundles, checked against
expected results.

    python -m oc_review.evals --fixtures-dir D --out-dir O

Each case is a directory of `D` with:

- `bundle.json`: an `ok` bundle envelope (the collect output);
- `expected.json` (format v2, every key optional):
  - `gate`: `pass` or `fail`;
  - `findings`: the findings that must be present, each
    `{"category", "severity", "file"?, "side"?, "verified"?}`. `category` is a
    category or a list of categories (any of them matches). `severity` means
    that severity or higher. `file`, `side` and `verified` match exactly when
    given. Extra findings never fail a case;
  - `max_severity`: the highest severity allowed for any finding, verified or
    not;
  - `hard_blocks`: exactly the prefilter hard block check IDs of the bundle;
  - `summary_excludes`: strings that must not appear in the rendered summary.
  Another key, or a wrong type or value, fails the case before any call.

For each case the runner calls `analyze.analyze` with the eval federation IDs
and a GitHub client on an in-memory transport (no GitHub read), writes the
three pass records, and computes the gate with the same code the publisher
uses and synthetic trusted inputs: every job `success`, dependency review
`success`, a current snapshot, no overrides. It renders the sticky summary
with the publisher's code (no inline comment is posted, so every finding shows
in full) and writes it to `O/<case>/summary.md`. It writes one JSON line per
case to stdout and to `O/results.jsonl`. It exits 0 only when at least one case
ran and every case matched. A case matches only when all three passes are
`ok`: a failed call is an infrastructure failure, never a match.

Only token counts are reported, never a price. The runner runs trusted code on
fixture data; it never executes a bundle's content.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from oc_review import analyze, collect, envelope, publish, snapshot, verdict

# The eval federation rule, bound to the test workspace `claude-review-p0-test`
# (never the review workspace; spec "Fixture eval credential"). They are
# separate from the production IDs in `analyze`.
EVAL_FEDERATION_RULE_ID = "fdrl_01BL4n1gQzkrroCmDZoXUePm"
EVAL_ORGANIZATION_ID = "2bc920f9-977b-43b2-870a-f840e4ce809c"
EVAL_SERVICE_ACCOUNT_ID = "svac_017eR3ohB6rP5MEAsda6U7X6"

EVAL_REPOSITORY = "OperationCode/eval-fixtures"
EVAL_PR_AUTHOR = "eval-author"
USAGE_FIELDS = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
# The enums of schema/findings.schema.json; SEVERITIES is in rising order.
CATEGORIES = ("bug", "security", "supply-chain", "malicious", "prompt-injection")
SEVERITIES = ("low", "medium", "high", "critical")
SIDES = ("head", "base")
SUMMARY_FILE_NAME = "summary.md"


class EvalError(Exception):
    """A case that cannot run (bad fixture). The case fails; the run goes on."""


def eval_federation() -> analyze.FederationIds:
    return analyze.FederationIds(EVAL_FEDERATION_RULE_ID, EVAL_ORGANIZATION_ID, EVAL_SERVICE_ACCOUNT_ID)


def pr_transport(bundle: Mapping[str, Any], repository: str = EVAL_REPOSITORY) -> collect.Transport:
    """In-memory GitHub transport: the one PR the bundle snapshot describes.

    It asserts the host and path of every request, so a stray read cannot
    reach the network or return something else."""
    path = f"/repos/{repository}/pulls/{bundle['pr_number']}"
    pr = {
        "number": bundle["pr_number"],
        "head": {"sha": bundle["head_sha"]},
        "base": {"ref": bundle["base_ref"], "repo": {"id": bundle["base_repository_id"],
                                                     "default_branch": bundle["base_ref"]}},
    }

    def transport(request: collect.HttpRequest) -> collect.HttpResponse:
        parts = urllib.parse.urlsplit(request.url)
        if request.method != "GET" or parts.scheme != "https" or parts.hostname != collect.API_HOST or parts.path != path:
            raise AssertionError(f"eval transport: unexpected request {request.method} {request.url}")
        return collect.HttpResponse(200, json.dumps(pr).encode(), request.url)

    return transport


def _load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_bytes())
    except (OSError, ValueError) as exc:
        raise EvalError(f"{path.name}: {type(exc).__name__}: {exc}") from exc


def discover_cases(fixtures_dir: Path | str) -> list[Path]:
    root = Path(fixtures_dir)
    if not root.is_dir():
        return []
    return sorted(p for p in root.iterdir() if p.is_dir() and (p / "bundle.json").exists())


def _usage_total(results: Mapping[str, analyze.PassResult]) -> dict[str, int]:
    total = dict.fromkeys(USAGE_FIELDS, 0)
    for r in results.values():
        for name in USAGE_FIELDS:
            total[name] += (r.usage or {}).get(name, 0)
    return total


def _bundle_hard_block_ids(bundle: Mapping[str, Any]) -> list[str]:
    payload = bundle.get("payload")
    if not isinstance(payload, Mapping):
        return []
    return sorted({str(b["id"]) for b in payload["prefilter"]["hard_blocks"]})


def _rank(severity: str) -> int:
    return SEVERITIES.index(severity)


def _finding_matches(want: Mapping[str, Any], f: verdict.CitedFinding) -> bool:
    categories = [want["category"]] if isinstance(want["category"], str) else want["category"]
    return (
        f.category in categories
        and f.severity in SEVERITIES
        and _rank(f.severity) >= _rank(want["severity"])
        and all(getattr(f, key) == want[key] for key in ("file", "side", "verified") if key in want)
    )


def _describe(want: Mapping[str, Any]) -> str:
    category = want["category"] if isinstance(want["category"], str) else "|".join(want["category"])
    text = f"{category}/{want['severity']}+"
    for key in ("file", "side", "verified"):
        if key in want:
            text += f" {key}={json.dumps(want[key])}"
    return text


def _unescape(summary: str) -> str:
    """The summary as a reader sees it: without the publisher's backslash
    escapes and zero-width spaces, so an escaped copy of a string still counts."""
    return re.sub(r"\\(.)", r"\1", summary.replace(publish.ZWSP, ""), flags=re.DOTALL)


def compare(
    expected: Mapping[str, Any], gate: verdict.GateResult, bundle: Mapping[str, Any], summary: str
) -> list[str]:
    """What differs between a checked `expected` (see `_check_expected`) and
    the result; empty when they match."""
    out: list[str] = []
    if "gate" in expected and expected["gate"] != gate.status:
        out.append(f"gate: expected {expected['gate']}, got {gate.status}")
    for want in expected.get("findings", []):
        if not any(_finding_matches(want, f) for f in gate.findings):
            out.append(f"missing finding {_describe(want)}")
    if "max_severity" in expected:
        limit = _rank(expected["max_severity"])
        over = [f for f in gate.findings if f.severity not in SEVERITIES or _rank(f.severity) > limit]
        for f in over:
            out.append(f"finding above max_severity {expected['max_severity']}: {f.category}/{f.severity} "
                       f"({f.pass_name}, {'verified' if f.verified else 'unverified'})")
    if "hard_blocks" in expected:
        actual = _bundle_hard_block_ids(bundle)
        if sorted(expected["hard_blocks"]) != actual:
            out.append(f"hard blocks: expected {sorted(expected['hard_blocks'])}, got {actual}")
    plain = _unescape(summary)
    for i, text in enumerate(expected.get("summary_excludes", [])):
        if text in summary or text in plain:
            # never echo the string: it may be the credential the case checks
            out.append(f"summary contains summary_excludes[{i}]")
    return out


EXPECTED_KEYS = ("gate", "findings", "max_severity", "hard_blocks", "summary_excludes")
FINDING_KEYS = ("category", "severity", "file", "side", "verified")


def _check_expected_finding(i: int, want: Any) -> None:
    where = f"expected.json: findings[{i}]"
    if not isinstance(want, dict):
        raise EvalError(f"{where} must be an object")
    unknown = sorted(map(repr, set(want) - set(FINDING_KEYS)))
    if unknown:
        raise EvalError(f"{where}: unknown keys {', '.join(unknown)}; allowed: {', '.join(FINDING_KEYS)}")
    category = want.get("category")
    categories = [category] if isinstance(category, str) else category
    if not isinstance(categories, list) or not categories or not all(c in CATEGORIES for c in categories):
        raise EvalError(f"{where}: category must be one of {', '.join(CATEGORIES)}, or a non-empty list of them")
    if want.get("severity") not in SEVERITIES:
        raise EvalError(f"{where}: severity must be one of {', '.join(SEVERITIES)}")
    if "file" in want and (not isinstance(want["file"], str) or not want["file"]):
        raise EvalError(f"{where}: file must be a non-empty string")
    if "side" in want and want["side"] not in SIDES:
        raise EvalError(f"{where}: side must be head or base")
    if "verified" in want and not isinstance(want["verified"], bool):
        raise EvalError(f"{where}: verified must be true or false")


def _check_expected(expected: Any) -> None:
    """Reject an expectation that would silently skip a check: an unknown key,
    a wrong type or an unknown value."""
    if not isinstance(expected, dict):
        raise EvalError("expected.json: must be a JSON object")
    unknown = sorted(map(repr, set(expected) - set(EXPECTED_KEYS)))
    if unknown:
        raise EvalError(f"expected.json: unknown keys {', '.join(unknown)}; allowed: {', '.join(EXPECTED_KEYS)}")
    if expected.get("gate") not in (None, verdict.PASS, verdict.FAIL):
        raise EvalError("expected.json: gate must be pass or fail")
    findings = expected.get("findings", [])
    if not isinstance(findings, list):
        raise EvalError("expected.json: findings must be a list")
    for i, want in enumerate(findings):
        _check_expected_finding(i, want)
    if "max_severity" in expected and expected["max_severity"] not in SEVERITIES:
        raise EvalError(f"expected.json: max_severity must be one of {', '.join(SEVERITIES)}")
    hb = expected.get("hard_blocks", [])
    if not isinstance(hb, list) or not all(isinstance(x, str) for x in hb):
        raise EvalError("expected.json: hard_blocks must be a list of check IDs")
    excludes = expected.get("summary_excludes", [])
    if not isinstance(excludes, list) or not all(isinstance(x, str) and x for x in excludes):
        raise EvalError("expected.json: summary_excludes must be a list of non-empty strings")


def render_summary(gate: verdict.GateResult, bundle: Mapping[str, Any]) -> str:
    """The sticky summary body the publisher would write. Nothing is posted
    inline, so every inline finding counts as not posted and shows in full."""
    ctx = publish.PublishContext(EVAL_REPOSITORY, bundle["repository_id"], bundle["pr_number"], bundle["head_sha"],
                                 EVAL_PR_AUTHOR, bundle["run_id"], bundle["run_attempt"])
    inline = publish.InlineOutcome(not_posted=frozenset(publish.finding_key(f) for f in gate.findings if f.inline))
    return publish.render_summary(ctx, gate, bundle=bundle, inline=inline).body


def run_case(
    case_dir: Path,
    out_dir: Path,
    *,
    mint_oidc: analyze.OidcMinter,
    job_workflow_sha: str | None,
    runner_temp: Path | str | None,
    client_factory: analyze.ClientFactory,
    federation: analyze.FederationIds,
    clock: Callable[[], float],
    deadline_seconds: float,
) -> dict[str, Any]:
    name = case_dir.name
    bundle_bytes = (case_dir / "bundle.json").read_bytes()
    bundle = _load_json(case_dir / "bundle.json")
    expected = _load_json(case_dir / "expected.json")
    try:
        envelope.validate_envelope(bundle)
    except envelope.EnvelopeError as exc:
        raise EvalError(f"bundle.json: {exc}") from exc
    if bundle["kind"] != "bundle" or bundle["status"] != "ok":
        raise EvalError("bundle.json must be a bundle envelope with status ok")
    _check_expected(expected)

    event = collect.EventContext(EVAL_REPOSITORY, bundle["repository_id"], bundle["pr_number"], bundle["head_sha"])
    github = collect.GitHubClient("eval-token", pr_transport(bundle), retries=0, sleep=lambda s: None)
    results = analyze.analyze(
        bundle, event, github=github, mint_oidc=mint_oidc, job_workflow_sha=job_workflow_sha,
        runner_temp=runner_temp, client_factory=client_factory, clock=clock,
        deadline_seconds=deadline_seconds, federation=federation,
    )

    data = out_dir / name / "data"
    (data / "bundle").mkdir(parents=True, exist_ok=True)
    (data / "bundle" / collect.BUNDLE_FILE_NAME).write_bytes(bundle_bytes)
    written = analyze.write_records(bundle, results, data, run_id=bundle["run_id"], run_attempt=bundle["run_attempt"],
                                    schema_sha256=analyze.schema_digest(analyze.request_schema()))
    digests = {"bundle": envelope.sha256_hex(bundle_bytes), **{n: w.digest for n, w in written.items()}}
    bundle_read, pass_reads = publish.load_artifacts(data, digests)
    gate = verdict.compute_gate(verdict.GateInputs(
        context=verdict.RunContext(bundle["repository_id"], bundle["pr_number"], bundle["run_id"], bundle["run_attempt"]),
        job_results=dict.fromkeys((*verdict.REQUIRED_JOBS, verdict.DEPENDENCY_REVIEW_JOB), "success"),
        dependency_review_outcome="success",
        bundle=bundle_read,
        passes=pass_reads,
        revalidation=snapshot.Revalidation((), False),
        prefilter=verdict.prefilter_evidence_from_bundle(bundle_read),
        files=publish.bundle_files(bundle_read),
        overrides=verdict.OverrideInputs((), verdict.Timeline((), True), {}, EVAL_PR_AUTHOR),
    ))

    summary = render_summary(gate, bundle_read.envelope or bundle)
    (out_dir / name / SUMMARY_FILE_NAME).write_text(summary, encoding="utf-8")

    mismatches = compare(expected, gate, bundle, summary)
    for pass_name in analyze.PASS_NAMES:
        r = results[pass_name]
        if r.status != "ok":
            mismatches.append(f"pass {pass_name} {r.status}: {r.reason}")
    return {
        "case": name,
        "matched": not mismatches,
        "gate": gate.status,
        "expected_gate": expected.get("gate"),
        "mismatches": mismatches,
        "passes": {n: {"status": results[n].status, "reason": results[n].reason} for n in analyze.PASS_NAMES},
        "findings": [{"pass": f.pass_name, "category": f.category, "severity": f.severity, "file": f.file,
                      "side": f.side, "verified": f.verified} for f in gate.findings],
        "usage": _usage_total(results),
    }


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    oidc_transport: analyze.OidcTransport = analyze.default_oidc_transport,
    client_factory: analyze.ClientFactory = analyze.default_client_factory,
    federation: analyze.FederationIds | None = None,
    clock: Callable[[], float] = time.monotonic,
    deadline_seconds: float = analyze.DEADLINE_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    parser = argparse.ArgumentParser(description="Run the review passes over fixture bundles and check the results.")
    parser.add_argument("--fixtures-dir", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    federation = federation or eval_federation()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    cases = discover_cases(args.fixtures_dir)
    if not cases:
        print(f"evals: no cases in {args.fixtures_dir!r}", file=sys.stderr)
        return 1
    mint = analyze.oidc_minter(env.get("ACTIONS_ID_TOKEN_REQUEST_URL"), env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
                               oidc_transport, sleep=sleep)
    results_path = out_dir / "results.jsonl"
    results_path.write_text("", encoding="utf-8")
    ok = True
    for case_dir in cases:
        try:
            result = run_case(
                case_dir, out_dir, mint_oidc=mint, job_workflow_sha=env.get("JOB_WORKFLOW_SHA"),
                runner_temp=env.get("RUNNER_TEMP") or None, client_factory=client_factory, federation=federation,
                clock=clock, deadline_seconds=deadline_seconds,
            )
        except Exception as exc:  # noqa: BLE001 - one bad case must not stop the others
            result = {"case": case_dir.name, "matched": False, "mismatches": [f"{type(exc).__name__}: {exc}"]}
        ok = ok and result["matched"]
        line = json.dumps(result, sort_keys=True)
        with results_path.open("a", encoding="utf-8") as fh:  # per case: a kill keeps the finished cases
            fh.write(line + "\n")
        print(line)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
