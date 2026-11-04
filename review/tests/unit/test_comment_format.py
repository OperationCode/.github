"""Summary comment format, phase 6 (spec "Summary comment"): one row per root
cause, owner setting problems labeled apart from the author's change, paths
as plain text, no empty token table, and the informational unsigned-commit
row. No network: the gate job runs against the fake GitHub of test_publish.
"""

from __future__ import annotations

import pytest

from oc_review import publish, verdict

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


def test_dependency_graph_off_is_a_repo_setting_not_the_authors_fault(tmp_path):
    gh = FakeGitHub(dependency_graph_status=403)
    r = run(tmp_path, gh, needs=dr_failed_needs())
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
    setting_run = run(tmp_path / "b", FakeGitHub(dependency_graph_status=403), needs=dr_failed_needs())
    assert gate(setting_run) == gate(plain_run)
    assert setting_run.code == 1
    assert "/oc-review override" not in setting_run.summary  # still not waivable


@pytest.mark.parametrize(
    "status,headers",
    [(200, {}), (404, {}), (403, {"x-ratelimit-remaining": "0"}), (403, {"retry-after": "60"}), (500, {})],
)
def test_other_probe_answers_keep_the_generic_row(tmp_path, status, headers):
    gh = FakeGitHub(dependency_graph_status=status, dependency_graph_headers=headers)
    s = run(tmp_path, gh, needs=dr_failed_needs()).summary
    [row] = findings_rows(s)
    assert row[2] == "Dependency review" and publish.SETTING_CELL not in s
    assert "| ❌ failed |" in s


def test_probe_runs_only_when_dependency_review_failed(tmp_path):
    r = run(tmp_path)
    assert not [p for p in r.gh.paths() if "/dependency-graph/" in p]
    r = run(tmp_path / "f", needs=dr_failed_needs())
    assert [p for p in r.gh.paths() if "/dependency-graph/" in p]


def test_hard_block_and_setting_tell_the_author_only_their_part(tmp_path):
    item = {"id": "bidi-control", "level": "hard_block", "detail": "bidi control characters U+202E, line 1",
            "file": "bidi.txt", "subject": None, "lines": [1], "count": 1}
    gh = FakeGitHub(dependency_graph_status=403)
    s = run(tmp_path, gh, bundle=bundle_doc(hard_blocks=[item]), needs=dr_failed_needs()).summary
    assert "**Next step for the author:** fix the cause named in the row" in s
    assert "only a repo admin can fix it" in s
    assert [x[0] for x in findings_rows(s)] == ["🚫 **Hard block**", publish.SETTING_CELL]


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


def test_unsigned_commits_never_change_a_fail(tmp_path):
    passes = clean_passes(security=[BLOCKING])
    signed = run(tmp_path / "a", passes=passes)
    unsigned = run(tmp_path / "b", FakeGitHub(commits=[signed_commit(False)]), passes=passes)
    assert gate(unsigned) == gate(signed) and unsigned.code == 1
    # The heading counts only gate rows; the info row sorts last.
    head = signed.summary.split("\n")[1]
    assert unsigned.summary.split("\n")[1] == head
    rows = findings_rows(unsigned.summary)
    assert rows[-1][0] == publish.INFO_CELL and "1 of 1 commits in this PR is not" in rows[-1][3]
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
