"""Summary comment format, phase 6 (spec "Summary comment"): one row per root
cause, owner setting problems labeled apart from the author's change, paths
as plain text, no empty token table, and the informational unsigned-commit
row. No network: the gate job runs against the fake GitHub of test_publish.
"""

from __future__ import annotations

import http.client
import io
import json
import re
import urllib.error
from dataclasses import replace

import pytest

from oc_review import collect, publish, verdict
from oc_review.collect import HttpRequest, HttpResponse

from .test_publish import (
    BLOCKING,
    ZWSP,
    FakeGitHub,
    bundle_doc,
    clean_passes,
    finding,
    needs_ok,
    pass_doc,
    plain,
    reason_rows,
    run,
    signed_commit,
)
from .test_summary_comment import callout_kind, table_rows


def dr_failed_needs():
    needs = needs_ok(outcome="failure")
    needs["dependency-review"]["result"] = "failure"
    return needs


def findings_rows(s: str) -> list[list[str]]:
    return table_rows(s, "| Severity |") if "| Severity |" in s else []


def gate(r) -> tuple:
    """What the gate decided: exit code, step summary result and reason codes."""
    rec = r.record
    return r.code, rec["result"], tuple(sorted(rec.get("reasons") or rec.get("codes") or ()))


# ---------------------------------------------------------------- 1. one row per cause


def test_dependency_review_failure_is_one_row_and_one_reason_row(tmp_path):
    r = run(tmp_path, needs=dr_failed_needs())
    s = r.summary
    assert r.code == 1
    rows = findings_rows(s)
    assert len(rows) == 1  # job, job result and step outcome: one cause
    assert rows[0][:3] == ["⚠️ **Not run**", "Blocks, no waiver", "Dependency review"]
    for detail in ("dependency-review: failure", "job result failure", "step outcome failure"):
        assert detail in plain(rows[0][3])
    deps = [x for x in reason_rows(s) if x[0] == verdict.R_DEPENDENCY_REVIEW]
    assert len(deps) == 1 and not deps[0][1]
    assert "dependency-review: failure" in deps[0][2] and "step outcome failure" in deps[0][2]
    assert not any(c == verdict.R_JOB_RESULT for c, _, _ in reason_rows(s))
    # One fail row: the heading counts it once.
    assert "## 🔴 Comms down: the Claude of Duty review did not complete" in s


def test_dedupe_is_display_only(tmp_path):
    """The gate still holds every reason: the step summary lists both codes."""
    r = run(tmp_path, needs=dr_failed_needs())
    codes = set(r.record.get("reasons") or r.record.get("codes") or ())
    assert {verdict.R_JOB_RESULT, verdict.R_DEPENDENCY_REVIEW} <= codes


def failed_pass(name, reason):
    meta = {"reason": reason, "model": None, "stop_reason": None, "request_schema_sha256": "f" * 64, "usage": None}
    return pass_doc(name, "failed", meta=meta)


def test_passes_that_failed_for_one_reason_share_a_row(tmp_path):
    passes = {n: failed_pass(n, "authentication failed") for n in verdict.PASS_NAMES}
    s = run(tmp_path, passes=passes).summary
    rows = findings_rows(s)
    assert [x[2] for x in rows] == ["Review, Security and Supply chain passes"]
    assert "authentication failed" in plain(rows[0][3])
    [rec] = [x for x in reason_rows(s) if x[0] == verdict.R_PASS_RECORDS]  # one record row, every detail
    assert all(f"pass {n} failed: authentication failed" in rec[2] for n in verdict.PASS_NAMES)


def test_passes_that_failed_for_different_reasons_keep_their_rows(tmp_path):
    passes = clean_passes()
    passes["review"] = failed_pass("review", "authentication failed")
    passes["security"] = failed_pass("security", "API unavailable after 3 attempts")
    passes["supply-chain"] = failed_pass("supply-chain", "authentication failed")
    s = run(tmp_path, passes=passes).summary
    assert sorted(x[2] for x in findings_rows(s)) == ["Review and Supply chain passes", "Security pass"]
    assert len([x for x in reason_rows(s) if x[0] == verdict.R_PASS_RECORDS]) == 2


# ---------------------------------------------------------------- 2. owner setting problems


def graph_off_github(**kw) -> FakeGitHub:
    """GitHub answers the dependency comparison with 403 and an error message
    that says the Dependency graph is disabled: positive evidence."""
    return FakeGitHub(dependency_graph_status=403, dependency_graph_body=error_body(GRAPH_OFF_MESSAGE), **kw)


GRAPH_OFF_MESSAGE = "Dependency graph is disabled for this repository. Enable it in the repository settings."


def error_body(message: str) -> bytes:
    return json.dumps({"message": message, "documentation_url": "https://docs.github.com/rest"}).encode()


def test_dependency_graph_off_is_a_repo_setting_not_the_authors_fault(tmp_path):
    r = run(tmp_path, graph_off_github(), needs=dr_failed_needs())
    s = r.summary
    [row] = findings_rows(s)
    assert row[:3] == [publish.SETTING_CELL, "Blocks, no waiver", "Repo settings"]
    assert row[3] == publish.DEPENDENCY_GRAPH_CLAIM
    assert "Only a repo admin can fix this" in row[3] and "The author does not need to change anything." in row[3]
    assert callout_kind(s) == "CAUTION"
    assert "**A repo setting stops the dependency review" in s
    assert "**Next step for a repo admin:** turn on the Dependency graph" in s
    assert "Next step for the author" not in s
    assert "| ⚙️ repo setting |" in s  # checks strip
    assert publish.DEPENDENCY_GRAPH_DETAIL in s  # reasons and checks record


def test_setting_label_never_changes_the_gate(tmp_path):
    plain_run = run(tmp_path / "a", needs=dr_failed_needs())
    setting_run = run(tmp_path / "b", graph_off_github(), needs=dr_failed_needs())
    assert publish.SETTING_CELL in setting_run.summary
    assert gate(setting_run) == gate(plain_run)
    assert setting_run.code == 1
    assert "/oc-review override" not in setting_run.summary  # still not waivable


# A 403 alone is not evidence. Each case keeps the neutral dependency row.
NOT_EVIDENCE = {
    "200": (200, {}, b""),
    "404": (404, {}, b""),
    "500": (500, {}, b""),
    "403-empty-body": (403, {}, b""),
    "403-fork-forbidden": (403, {}, error_body("Forbidden")),
    "403-advanced-security-off": (403, {}, error_body(
        "Dependency review is not supported on this repository: GitHub Advanced Security is not enabled.")),
    "403-advanced-security-and-graph": (403, {}, error_body(
        "Dependency graph is not enabled, or Advanced Security is disabled for this repository.")),
    "403-permission": (403, {}, error_body("Resource not accessible by integration")),
    "403-secondary-rate-limit-no-headers": (403, {}, error_body(
        "You have exceeded a secondary rate limit. Please wait a few minutes before you try again.")),
    "403-rate-limit-headers": (403, {"x-ratelimit-remaining": "0"}, error_body(GRAPH_OFF_MESSAGE)),
    "403-retry-after": (403, {"retry-after": "60"}, error_body(GRAPH_OFF_MESSAGE)),
    "403-not-json": (403, {}, b"Dependency graph is disabled"),
    "403-message-not-a-string": (403, {}, json.dumps({"message": ["Dependency graph is disabled"]}).encode()),
    "200-with-the-message": (200, {}, error_body(GRAPH_OFF_MESSAGE)),
}


@pytest.mark.parametrize("case", NOT_EVIDENCE)
def test_without_positive_evidence_the_row_stays_neutral(tmp_path, case):
    status, headers, body = NOT_EVIDENCE[case]
    gh = FakeGitHub(dependency_graph_status=status, dependency_graph_headers=headers, dependency_graph_body=body)
    r = run(tmp_path, gh, needs=dr_failed_needs())
    s = r.summary
    [row] = findings_rows(s)
    assert row[2] == "Dependency review" and publish.SETTING_CELL not in s
    assert "repo setting" not in s.lower() and "Next step for a repo admin" not in s
    assert "| ❌ failed |" in s
    assert r.code == 1


@pytest.mark.parametrize("message", [
    GRAPH_OFF_MESSAGE,
    "The dependency graph is not enabled for this repository.",
    "Dependency-graph is turned off for this repository",
    "Review failed. Dependency graph is disabled for this repository",
    "The dependency graph for this repository is disabled.",
    "Dependency graph has been turned off for this repository.",
    "Dependency graph is currently disabled.",
])
def test_evidence_messages(message):
    resp = HttpResponse(403, error_body(message), "https://api.github.com/x", {})
    assert publish.dependency_graph_off_evidence(resp)


@pytest.mark.parametrize("message", [
    "Dependency graph is not disabled for this repository.",
    "Dependency graph isn't disabled.",
    "Dependency graph isn\u2019t turned off.",
    "Dependency graph is no longer disabled.",
    "Dependency graph is never turned off here.",
    "The dependency graph is not not enabled.",
    "Dependency graph is enabled, but the submission is disabled.",
    "Dependency graph is enabled but the submission is disabled.",
    "Dependency graph is on; the snapshot upload is disabled.",
    "Dependency graph is on and the snapshot API is turned off.",
    # Review AC I2: the state words before "nor" are still negated.
    "Dependency graph is neither disabled nor turned off.",
    "Dependency graph is either disabled or enabled.",
    "Dependency graph was not disabled.",
    "Dependency graph is reportedly disabled.",
    "Dependency graph is hardly ever turned off.",
])
def test_negated_or_joined_messages_are_not_evidence(message):
    """Display only: a negated state, or a state from another clause, keeps
    the neutral dependency review row."""
    resp = HttpResponse(403, error_body(message), "https://api.github.com/x", {})
    assert not publish.dependency_graph_off_evidence(resp)


def test_probe_runs_only_when_dependency_review_failed(tmp_path):
    r = run(tmp_path)
    assert not [p for p in r.gh.paths() if "/dependency-graph/" in p]
    r = run(tmp_path / "f", needs=dr_failed_needs())
    assert [p for p in r.gh.paths() if "/dependency-graph/" in p]


def test_probe_error_keeps_the_neutral_row(tmp_path):
    gh = FakeGitHub()

    def boom(gh_, req):
        if "/dependency-graph/" in req.url:
            raise RuntimeError("unexpected")

    gh.after = boom
    r = run(tmp_path, gh, needs=dr_failed_needs())
    assert r.code == 1 and publish.SETTING_CELL not in r.summary
    assert findings_rows(r.summary)[0][2] == "Dependency review"


def test_hard_block_and_setting_tell_the_author_only_their_part(tmp_path):
    item = {"id": "bidi-control", "level": "hard_block", "detail": "bidi control characters U+202E, line 1",
            "file": "bidi.txt", "subject": None, "lines": [1], "count": 1}
    s = run(tmp_path, graph_off_github(), bundle=bundle_doc(hard_blocks=[item]), needs=dr_failed_needs()).summary
    assert "**Next step for the author:** fix the cause named in the row" in s
    assert "only a repo admin can fix it" in s
    assert [x[0] for x in findings_rows(s)] == ["🚫 **Hard block**", publish.SETTING_CELL]


def test_default_transport_keeps_a_bounded_error_body():
    class Opener:
        def open(self, req, timeout):
            raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {"X-Test": "1"},
                                         io.BytesIO(error_body(GRAPH_OFF_MESSAGE) + b" " * 500))

    req = HttpRequest("GET", "https://api.github.com/x", {}, 100, 5.0)
    resp = collect.default_transport(req, opener=Opener())
    assert resp.status == 403 and resp.headers == {"x-test": "1"}
    assert len(resp.body) == 101  # cut at the byte cap + 1, like a 200 body


class _BadBody(io.BytesIO):
    def __init__(self, error: Exception) -> None:
        super().__init__(b"")
        self.error = error

    def read(self, *args, **kwargs):
        raise self.error


@pytest.mark.parametrize("error", [
    http.client.IncompleteRead(b"Dependency graph is dis", 40),
    http.client.HTTPException("bad chunk"),
    OSError("reset"),
    ValueError("closed"),
])
def test_default_transport_error_body_read_failure_keeps_the_status(error):
    """A cut-off error body is empty: the status stays, so every caller still
    fails on it (fail closed), and the display probe finds no evidence."""
    class Opener:
        def open(self, req, timeout):
            raise urllib.error.HTTPError(req.full_url, 403, "Forbidden", {}, _BadBody(error))

    req = HttpRequest("GET", "https://api.github.com/x", {}, 100, 5.0)
    resp = collect.default_transport(req, opener=Opener())
    assert resp.status == 403 and resp.body == b""
    assert not publish.dependency_graph_off_evidence(resp)


# ---------------------------------------------------------------- 3. plain paths


PATH = "review/tests/unit/test_publish-v2.py"


def test_paths_show_as_plain_text_not_backslash_escaped(tmp_path):
    item = {"id": "bidi-control", "level": "hard_block", "detail": "bidi control characters U+202E, line 4",
            "file": PATH, "subject": None, "lines": [4], "count": 1}
    unsafe = finding("bug", "low", file="docs/a_b.md", line=3, quote="nope")
    s = run(tmp_path, bundle=bundle_doc(hard_blocks=[item]), passes=clean_passes(review=[unsafe])).summary
    assert f"`{PATH}`" in s and f"`{PATH}:4`" in s
    assert "review\\/tests" not in s and "test\\_publish" not in s
    # Reasons table detail: a code span, not escaped prose.
    assert f"`bidi-control in {PATH}`" in s
    # Finding bullet in the record.
    assert "`docs/a_b.md` line 3 (head)" in s


def test_path_spans_stay_safe(tmp_path):
    bad = "a`b<img src=x>@user/#12/" + "deadbeefcafe1234.py"
    item = {"id": "binary-file", "level": "hard_block", "detail": "binary", "file": bad,
            "subject": None, "lines": [], "count": 1}
    s = run(tmp_path, bundle=bundle_doc(hard_blocks=[item])).summary
    span = publish._path_span(bad)
    assert span in s
    assert span.count("`") == 2 and "<img" not in span and "‹img" in span
    assert "@" + ZWSP in span and "#" + ZWSP + "12" in span
    assert "deadbeefcafe1234" not in s  # a hex run is still broken
    assert "<img" not in s


# ---------------------------------------------------------------- 4. no empty token table


def test_token_table_collapses_when_nothing_was_recorded(tmp_path):
    passes = {n: failed_pass(n, "authentication failed") for n in verdict.PASS_NAMES}
    s = run(tmp_path, passes=passes).summary
    assert "**Token usage**" in s and publish.TOKENS_NONE in s
    assert "| Pass | Input |" not in s and "not recorded" not in s


def test_token_table_stays_when_any_pass_recorded(tmp_path):
    passes = clean_passes()
    passes["security"] = failed_pass("security", "API unavailable")
    s = run(tmp_path, passes=passes).summary
    assert "| Pass | Input |" in s and publish.TOKENS_NONE not in s
    assert "**Recorded total**" in s


# ---------------------------------------------------------------- 5. unsigned commits (informational)


def test_no_unsigned_commits_no_row(tmp_path):
    gh = FakeGitHub(commits=[signed_commit(True, i) for i in range(3)])
    r = run(tmp_path, gh)
    assert r.code == 0
    assert "Unsigned commits" not in r.summary and "| Severity |" not in r.summary


def test_unsigned_commits_row_has_count_and_link_and_leaves_the_pass(tmp_path):
    commits = [signed_commit(True, 0), signed_commit(False, 1), signed_commit(False, 2)]
    clean = run(tmp_path / "a")
    r = run(tmp_path / "b", FakeGitHub(commits=commits))
    s = r.summary
    assert gate(r) == gate(clean) and r.code == 0
    assert s.startswith(verdict.STICKY_MARKER + "\n## 🟢 All clear: Claude of Duty review passed\n")
    assert callout_kind(s) == "TIP"
    [row] = findings_rows(s)
    assert row[:3] == [publish.INFO_CELL, publish.EFFECT_INFO, "Commits"]
    assert "**Unsigned commits:** 2 of 3 commits in this PR are not verified-signed." in row[3]
    assert f"[How to sign commits]({publish.SIGNING_GUIDE_URL})" in row[3]
    assert row[4] == publish.COMMIT_CHECK_ROW
    # The TIP must not say "nothing to do" next to a row that says the merge box blocks.
    assert publish.NOTHING_TO_DO not in s and f"** {publish.SIGNING_STEP}" in callout(s)


@pytest.mark.parametrize(("total", "unsigned", "text"), [
    (1, 1, "1 of 1 commit in this PR is not verified-signed."),
    (2, 1, "1 of 2 commits in this PR is not verified-signed."),
    (2, 2, "2 of 2 commits in this PR are not verified-signed."),
    (3, 2, "2 of 3 commits in this PR are not verified-signed."),
    (publish.COMMITS_MAX, 1, f"1 of the first {publish.COMMITS_MAX} commits in this PR is not verified-signed."),
    (publish.COMMITS_MAX, 7, f"7 of the first {publish.COMMITS_MAX} commits in this PR are not verified-signed."),
])
def test_signing_row_grammar(total, unsigned, text):
    [row] = publish._signing_row(publish.SummaryFacts(commits=publish.CommitSigning(total, unsigned)))
    assert row.claim.startswith(f"**Unsigned commits:** {text} ")


def callout(s: str) -> str:
    """The callout lines (each starts with "> ")."""
    return "\n".join(line for line in s.split("\n") if line.startswith("> "))


def test_tip_says_nothing_to_do_only_without_unsigned_commits(tmp_path):
    clean = run(tmp_path / "a", FakeGitHub(commits=[signed_commit(True)])).summary
    assert callout_kind(clean) == "TIP" and f"** {publish.NOTHING_TO_DO}" in callout(clean)
    assert publish.SIGNING_STEP not in clean


def test_waiver_tip_names_the_signing_step():
    from .test_publish import CTX

    r = replace(run_result_for_render(), override_applied=True)
    facts = publish.SummaryFacts(commits=publish.CommitSigning(2, 1))
    body = publish.render_summary(CTX, r, bundle=None, inline=publish.InlineOutcome(), facts=facts).body
    assert "Unsigned commits" in body and callout_kind(body) == "TIP"
    assert "A maintainer waiver was applied by a maintainer" in callout(body)
    assert publish.NOTHING_TO_DO not in body and f"** {publish.SIGNING_STEP}" in callout(body)
    plain_body = publish.render_summary(CTX, r, bundle=None, inline=publish.InlineOutcome()).body
    assert f"** {publish.NOTHING_TO_DO}" in callout(plain_body) and publish.SIGNING_STEP not in plain_body


def test_note_callout_is_unchanged_by_unsigned_commits(tmp_path):
    passes = clean_passes(review=[finding("bug", "low", file="a.py", line=1, quote="x")])
    signed = run(tmp_path / "a", FakeGitHub(commits=[signed_commit(True)]), passes=passes).summary
    unsigned = run(tmp_path / "b", FakeGitHub(commits=[signed_commit(False)]), passes=passes).summary
    assert callout_kind(unsigned) == "NOTE" and callout(unsigned) == callout(signed)
    assert publish.NOTHING_TO_DO not in unsigned and publish.SIGNING_STEP not in unsigned


def test_unsigned_commits_never_change_a_fail(tmp_path):
    passes = clean_passes(security=[BLOCKING])
    signed = run(tmp_path / "a", passes=passes)
    unsigned = run(tmp_path / "b", FakeGitHub(commits=[signed_commit(False)]), passes=passes)
    assert gate(unsigned) == gate(signed) and unsigned.code == 1
    # The heading counts only gate rows; the info row sorts last.
    head = signed.summary.split("\n")[1]
    assert unsigned.summary.split("\n")[1] == head
    rows = findings_rows(unsigned.summary)
    assert rows[-1][0] == publish.INFO_CELL and "1 of 1 commit in this PR is not" in rows[-1][3]
    assert "/oc-review override" in unsigned.summary  # the waiver line is unchanged


def test_commit_list_that_cannot_be_read_gives_no_row(tmp_path):
    gh = FakeGitHub(commits=[signed_commit(False)])
    gh.fail = {("GET", "/repos/OperationCode/back-end/pulls/7/commits", "1")}
    r = run(tmp_path, gh)
    assert r.code == 0 and "Unsigned commits" not in r.summary


def test_commit_list_cap_is_named(tmp_path):
    commits = [signed_commit(i % 2 == 0, i) for i in range(publish.COMMITS_MAX)]
    s = run(tmp_path, FakeGitHub(commits=commits)).summary
    assert "125 of the first 250 commits" in s


def test_commit_data_never_reaches_the_gate_inputs():
    """The gate reads no commit or setting fact: `GateInputs` has no field for them."""
    fields = set(verdict.GateInputs.__dataclass_fields__)
    assert not {f for f in fields if "commit" in f or "sign" in f or "setting" in f}


# ---------------------------------------------------------------- fix 1: the signing row never fails a review


def near_limit_passes():
    """Review AB Important 1: 35 advisory high findings with long fields. High
    severity is never cut, so the summary is close to the comment limit."""
    def many(n):
        return [finding("bug", "high", file="z" * 390 + str(i), title="T" * 120, quote="Q" * 300,
                        explanation="x" * 304) for i in range(n)]
    return clean_passes(review=many(10), security=many(10), supply_chain=many(15))


def test_signing_row_never_overflows_a_passing_review(tmp_path):
    passes = near_limit_passes()
    signed = run(tmp_path / "a", FakeGitHub(commits=[signed_commit(True)]), passes=passes)
    unsigned = run(tmp_path / "b", FakeGitHub(commits=[signed_commit(False)]), passes=passes)
    assert signed.code == 0 and len(signed.summary) > 60_000  # the boundary case
    assert gate(unsigned) == gate(signed) and unsigned.code == 0
    assert "publish_error" not in unsigned.record
    # Exactly the same comment: the row did not fit, so it is left out.
    assert unsigned.summary == signed.summary and "Unsigned commits" not in unsigned.summary


def test_signing_row_is_left_out_when_it_would_cause_a_cut():
    from .test_publish import CTX

    r = run_result_for_render()
    base = publish.render_summary(CTX, r, bundle=None, inline=publish.InlineOutcome())
    facts = publish.SummaryFacts(commits=publish.CommitSigning(3, 2))
    # Room for the body, not for the body plus the row: same body, no cut.
    tight = publish.render_summary(CTX, r, bundle=None, inline=publish.InlineOutcome(),
                                   limit=len(base.body) + 5, facts=facts)
    assert tight == base
    # With the row left out, the TIP keeps "nothing to do": it never names a row that is not there.
    assert f"** {publish.NOTHING_TO_DO}" in callout(tight.body) and publish.SIGNING_STEP not in tight.body
    roomy = publish.render_summary(CTX, r, bundle=None, inline=publish.InlineOutcome(), facts=facts)
    assert "Unsigned commits" in roomy.body and not roomy.cut and not roomy.overflow
    assert f"** {publish.SIGNING_STEP}" in callout(roomy.body)


def run_result_for_render() -> verdict.GateResult:
    return verdict.GateResult(status=verdict.PASS, run_id=1000, reasons=(), findings=(), snapshot=None,
                              overrides=(), override_applied=False)


@pytest.mark.parametrize("error", [RuntimeError("boom"), TimeoutError("slow"), ValueError("bad")])
def test_commit_read_errors_give_no_row_and_keep_the_pass(tmp_path, error):
    gh = FakeGitHub(commits=[signed_commit(False)])

    def fail(gh_, req):
        if req.url.split("?")[0].endswith("/pulls/7/commits"):
            raise error

    gh.after = fail
    r = run(tmp_path, gh)
    assert r.code == 0 and r.record["result"] == verdict.PASS
    assert "Unsigned commits" not in r.summary


@pytest.mark.parametrize("items", [
    [{"sha": "x"}],  # no commit object
    [{"commit": {"verification": None}}],
    ["not an object"],
])
def test_commits_with_missing_data_never_change_the_pass(tmp_path, items):
    r = run(tmp_path, FakeGitHub(commits=items))
    assert r.code == 0 and r.record["result"] == verdict.PASS


# ---------------------------------------------------------------- fix 3: hostile file names stay in one cell


def cells_cmark_gfm(line: str) -> list[str]:
    """cmark-gfm: a cell ends at a `|` that has no backslash right before it."""
    return re.split(r"(?<!\\)\|", line)[1:-1]


def cells_even_backslashes(line: str) -> list[str]:
    """Parsers such as marked: a `|` is escaped only after an odd number of
    backslashes, so `\\\\|` ends the cell."""
    out, cur, i = [], "", 0
    while i < len(line):
        ch = line[i]
        if ch == "|":
            n = len(cur) - len(cur.rstrip("\\"))
            if n % 2 == 0:
                out.append(cur)
                cur = ""
                i += 1
                continue
        cur += ch
        i += 1
    out.append(cur)
    return out[1:-1]


HOSTILE = {
    "pipe": "a|b.py",
    "backslash-pipe": "a\\|b.py",
    "two-backslashes-pipe": "a\\\\|b.py",
    "three-backslashes-pipe": "a\\\\\\|b.py",
    "trailing-backslash": "dir\\",
    "backtick": "a`b`|c.py",
    "newline": "a\nb|c.py",
    "bidi": "a\u202eb|c.py",
    "mix": "\\|`\\\\|\n\u2066|<x>|@u/#1\\",
}


@pytest.mark.parametrize("case", HOSTILE)
def test_hostile_path_stays_in_its_cell(tmp_path, case):
    path = HOSTILE[case]
    item = {"id": "binary-file", "level": "hard_block", "detail": "binary", "file": path,
            "subject": None, "lines": [], "count": 1}
    s = run(tmp_path, bundle=bundle_doc(hard_blocks=[item])).summary
    rows = [line for line in s.split("\n") if line.startswith("| 🚫 **Hard block** |")]
    assert len(rows) == 1
    for split in (cells_cmark_gfm, cells_even_backslashes):
        cells = split(rows[0])
        assert len(cells) == 5, (case, split.__name__, cells)
        assert cells[1].strip() == "Blocks, no waiver" and cells[4].strip() == "File checks (code, no model)"
        assert cells[2].strip().startswith("`") and cells[2].strip().endswith("`")
    span = publish._path_span(path)
    assert span.count("`") == 2 and "\n" not in span and "\u202e" not in span and "\u2066" not in span
    assert "<" not in span
    # Every pipe has exactly one backslash before it.
    assert not re.search(r"(?<!\\)\|", span.replace("\\|", "")) and "\\\\|" not in span


def test_findings_header_constant_matches_the_table(tmp_path):
    s = run(tmp_path, passes=clean_passes(review=[finding()])).summary
    assert publish._FINDINGS_HEADER + "\n|" in s
