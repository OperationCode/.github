"""The sticky PR summary comment: result heading, callout, findings table,
checks strip, collapsed waiver and record (spec "Publishing (code)"). No
network: the gate job runs against the fake GitHub of test_publish.

Set OC_RENDER_OUT to a directory to also write the rendered Markdown of each
case there (`<case>.md`).
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from types import SimpleNamespace

import pytest

from oc_review import publish, verdict

from .test_publish import (
    BLOCKING,
    HEAD,
    MB,
    FakeGitHub,
    needs_ok,
    bundle_doc,
    clean_passes,
    finding,
    pass_doc,
    plain,
    reason_rows,
    run,
)

SPOOF = "Workflow spoofs the review status check with a fake pass."
TLS = "TLS certificate verification is disabled for the download."
BIDI_ITEM = {
    "id": "bidi-control", "level": "hard_block", "detail": "bidi control characters U+202E, line 1",
    "file": "bidi.txt", "subject": None, "lines": [1], "count": 1,
}
SIGNALS = [
    {"id": "sensitive-path", "level": "signal", "detail": "workflow file", "file": ".github/workflows/x.yml",
     "subject": None, "lines": [], "count": 1},
    {"id": "first-time-contributor", "level": "signal", "detail": "author association NONE", "file": None,
     "subject": None, "lines": [], "count": 1},
]


def case_a(tmp_path):
    return run(tmp_path)


def case_b(tmp_path):
    low = finding("bug", "low", title="Setup command uses the old package name.", quote="shell=True")
    return run(tmp_path, passes=clean_passes(review=[low]))


def case_c(tmp_path):
    tls = finding("security", "high", title=TLS, quote="shell=True")
    retry = finding("bug", "low", line=11, quote="line 11", title="Retry loop never sleeps between attempts.")
    return run(tmp_path, passes=clean_passes(security=[tls], review=[retry]))


def case_d(tmp_path):
    spoof_sec = finding("security", "high", title=SPOOF, quote="shell=True")
    spoof_sc = finding("malicious", "high", title="Workflow spoofs the claude-review check with a fake pass.",
                       quote="shell=True")
    bidi_sec = finding("security", "medium", line=11, quote="line 11", title="Bidirectional override committed.")
    bidi_sc = finding("malicious", "medium", line=11, quote="line 11", title="Right-to-left override hidden.")
    passes = clean_passes(security=[spoof_sec, bidi_sec], supply_chain=[spoof_sc, bidi_sc])
    return run(tmp_path, passes=passes, bundle=bundle_doc(hard_blocks=[BIDI_ITEM], signals=SIGNALS))


def case_e(tmp_path):
    passes = clean_passes()
    meta = {"reason": "API unavailable after 3 attempts", "model": "claude-sonnet-5-5", "stop_reason": None,
            "request_schema_sha256": "f" * 64, "usage": None}
    passes["security"] = pass_doc("security", "failed", meta=meta)
    return run(tmp_path, passes=passes)


def case_f(tmp_path):
    title = "Job impersonates the review gate check name with a fake pass."
    passes = clean_passes(
        review=[finding("malicious", "high", title=title, quote="shell=True")],
        security=[finding("security", "medium", title="Workflow spoofs the required review check name.",
                          quote="shell=True")],
        supply_chain=[finding("supply-chain", "medium", title="Workflow job spoofs the review gate check name.",
                              quote="shell=True")],
    )
    return run(tmp_path, passes=passes, bundle=bundle_doc(signals=SIGNALS))


CASES = {
    "a-pass-clean": case_a,
    "b-pass-minor": case_b,
    "c-fail-waivable": case_c,
    "d-pr40-hard-block": case_d,
    "e-could-not-run": case_e,
    "f-pr39": case_f,
}


@pytest.fixture(params=CASES)
def rendered(request, tmp_path):
    r = CASES[request.param](tmp_path)
    out = os.environ.get("OC_RENDER_OUT")
    if out:
        Path(out).mkdir(parents=True, exist_ok=True)
        (Path(out) / f"{request.param}.md").write_text(r.summary, encoding="utf-8")
    return request.param, r


def callout_kind(s: str) -> str:
    return re.search(r"^> \[!(\w+)\]$", s, re.M).group(1)


def table_rows(s: str, header_start: str) -> list[list[str]]:
    """The body rows of the table whose header line starts with `header_start`, split into cells."""
    lines = s.split("\n")
    i = next(n for n, line in enumerate(lines) if line.startswith(header_start))
    rows = []
    for line in lines[i + 2 :]:
        if not line.startswith("|"):
            break
        rows.append([c.strip() for c in re.split(r"(?<!\\)\|", line)[1:-1]])
    return rows


# ---------------------------------------------------------------- the six cases


def test_a_pass_clean(tmp_path):
    s = case_a(tmp_path).summary
    assert s.startswith(verdict.STICKY_MARKER + "\n## 🟢 All clear: Claude of Duty review passed\n")
    assert callout_kind(s) == "TIP"
    assert "No findings. This review found no reason to block." in s
    assert "| Severity |" not in s  # no findings table
    assert "| ✅ ok | ✅ ran, 0 findings | ✅ ran, 0 findings | ✅ ran, 0 findings | ✅ ok | ✅ complete |" in s
    assert "<details>\n<summary>🔑" not in s  # no waiver block on a pass


def test_b_pass_with_a_minor_finding(tmp_path):
    s = case_b(tmp_path).summary
    assert "## 🟡 Clear to proceed: Claude of Duty logged 1 item to consider\n" in s
    assert callout_kind(s) == "NOTE"
    assert "It does not block this PR." in s
    [row] = table_rows(s, "| Severity |")
    assert row[:2] == ["🟡 **Low**", "Does not block"]
    assert row[2] == "`src/app.py:10`" and row[4] == "Review (low)"
    assert "Setup command uses the old package name\\. <sub>See the inline comment.</sub>" in row[3]


def test_c_waivable_fail_is_red_caution(tmp_path):
    r = case_c(tmp_path)
    s = r.summary
    assert r.code == 1
    assert "\n## 🔴 Hold deployment: Claude of Duty identified " in s
    assert callout_kind(s) == "CAUTION" and "[!WARNING]" not in s  # ruling 1
    assert "**One high-severity security finding blocks this PR.** A maintainer can waive it." in s
    assert "ask a maintainer to post the waiver line" in s
    rows = table_rows(s, "| Severity |")
    assert [(x[0], x[1]) for x in rows] == [("🔴 **High**", "Blocks, waivable"), ("🟡 **Low**", "Does not block")]
    assert "<summary>🔑 Waiver: how a maintainer clears this</summary>" in s
    assert f"/oc-review override {HEAD} {MB} <reason>" in s


def test_d_hard_block_comes_first_and_has_no_waiver(tmp_path):
    r = case_d(tmp_path)
    s = r.summary
    assert "\n## 🔴 Hold deployment: Claude of Duty identified " in s and callout_kind(s) == "CAUTION"
    assert "**Hidden text-direction control blocks this PR. No waiver can clear it.**" in s
    assert "One high-severity" in s and "also blocks." in s
    rows = table_rows(s, "| Severity |")
    assert [x[0] for x in rows] == ["🚫 **Hard block**", "🔴 **High**", "🟠 **Medium**"]
    assert rows[0][1:3] == ["Blocks, no waiver", "`bidi.txt:1`"] and rows[0][4] == "File checks (code, no model)"
    assert rows[1][1] == "Blocks, waivable" and rows[1][4] == "Security (high), Supply chain (high)"
    # Gate truth: a medium finding in a blocking category does not block (ruling 6).
    assert rows[2][1] == "Does not block" and rows[2][4] == "Security (medium), Supply chain (medium)"
    assert "/oc-review override" not in s and "🔑" not in s  # a hard block cannot be waived
    assert "| 🚫 1 hard block, 2 signals |" in s
    assert "⚠️ Sensitive path changed" in s and "ℹ️ First-time contributor" in s


def test_e_pass_that_did_not_run(tmp_path):
    r = case_e(tmp_path)
    s = r.summary
    assert "## 🔴 Comms down: the Claude of Duty review did not complete\n" in s and callout_kind(s) == "CAUTION"
    assert "The Security review did not run, so this PR could not be judged. No waiver can clear this." in s
    [row] = table_rows(s, "| Severity |")
    assert row[:3] == ["⚠️ **Not run**", "Blocks, no waiver", "Security pass"]
    assert "API unavailable after 3 attempts" in row[3]
    assert "| ✅ ok | ✅ ran, 0 findings | ❌ failed | ✅ ran, 0 findings | ✅ ok | ✅ complete |" in s
    assert "not recorded" in s and "**Recorded total**" in s  # missing usage is never zero
    assert "No summary. Reason: API unavailable after 3 attempts" in s
    assert "this is not a clean result" in s
    assert "/oc-review override" not in s


def test_f_pr39_waivable_fail_is_red_caution_with_two_rows(tmp_path):
    s = case_f(tmp_path).summary
    assert "\n## 🔴 Hold deployment: Claude of Duty identified " in s
    assert callout_kind(s) == "CAUTION" and "[!WARNING]" not in s  # ruling 1: not the yellow signal
    assert "A maintainer can waive it." in s
    # Ruling 3: the high finding blocks, the two medium findings do not. Different effects, different rows.
    rows = table_rows(s, "| Severity |")
    assert [(x[0], x[1], x[4]) for x in rows] == [
        ("🔴 **High**", "Blocks, waivable", "Review (high)"),
        ("🟠 **Medium**", "Does not block", "Security (medium), Supply chain (medium)"),
    ]
    assert "| ✅ ok, 2 signals | ✅ ran, 1 finding | ✅ ran, 1 finding | ✅ ran, 1 finding | ✅ ok | ✅ complete |" in s
    assert f"/oc-review override {HEAD} {MB} <reason>" in s


# ---------------------------------------------------------------- rules that hold in every case


def test_a_fail_never_uses_the_warning_callout(rendered):
    name, r = rendered
    s = r.summary
    assert "[!WARNING]" not in s
    if r.code == 1:
        assert callout_kind(s) == "CAUTION" and "🔴 " in s
    else:
        assert callout_kind(s) in ("TIP", "NOTE") and ("All clear" in s or "Clear to proceed" in s)


def test_the_comment_never_implies_approval(rendered):
    _, r = rendered
    s = r.summary.lower()
    assert "approved" not in s and "claude of duty never approves a pr" in s
    assert s.count("never approves") == 1


def test_marker_first_and_details_balanced(rendered):
    _, r = rendered
    s = r.summary
    assert s.startswith(verdict.STICKY_MARKER + "\n")
    assert s.count("<details>") == s.count("</details>") >= 1
    assert s.count("<summary>") == s.count("</summary>") == s.count("<details>")


def test_short_sha_is_visible_and_full_shas_are_in_the_record(rendered):
    _, r = rendered
    s = r.summary
    visible = s.split("<details>", 1)[0]
    assert f"head `{HEAD[:7]}` into main" in visible and HEAD not in visible
    record = s.rsplit("<details>", 1)[1]
    assert f"| `{HEAD}` | `{MB}` | main |" in record


def test_every_table_row_has_the_columns_of_its_header(rendered):
    _, r = rendered
    lines = r.summary.split("\n")
    header = None
    for line in lines:
        if not line.startswith("|"):
            header = None
            continue
        cols = len(re.split(r"(?<!\\)\|", line)) - 2
        if header is None:
            header = cols
        assert cols == header, line


def test_every_emoji_has_its_word_next_to_it(rendered):
    _, r = rendered
    for line in r.summary.split("\n"):
        for m in re.finditer(r"(🟢|🟡|🔴|🟠|⛔|🚫|⚠️|❌|✅|ℹ️|🔑|📋)(?! \*{0,2}[A-Za-z0-9])", line):
            pytest.fail(f"emoji with no word after it: {line!r}")


def test_the_record_holds_every_required_element(rendered):
    _, r = rendered
    s = r.summary
    for text in ("**Reviewed snapshot**", "**Reasons the gate failed**", "**Checks (code, no model)**",
                 "**Signals (context only, never block)**", "**Dependency changes**", "**Finding details**",
                 "**Model summaries**", "**Token usage**", publish.UNTRUSTED_NOTE):
        assert text in s, text
    assert f"[{r.record['run_id']}, attempt 1](" in s  # one run link


def test_reason_codes_never_show(rendered):
    _, r = rendered
    for code in verdict.WAIVABLE:
        assert f"| {code} |" not in r.summary


# ---------------------------------------------------------------- the merge rule


def at_one_place(*specs):
    """Findings of the three passes at src/app.py line 10 (head). `specs`: (pass, category, severity, title)."""
    by_pass: dict[str, list] = {}
    for name, category, severity, title in specs:
        by_pass.setdefault(name.replace("-", "_"), []).append(
            finding(category, severity, title=title, quote="shell=True"))
    return clean_passes(**by_pass)


def test_same_place_and_same_effect_merge_into_one_row(tmp_path):
    passes = at_one_place(
        ("review", "bug", "low", "Review title"),
        ("security", "security", "medium", "Security title"),
        ("supply-chain", "supply-chain", "medium", "Supply title"),
    )
    s = run(tmp_path, passes=passes).summary
    [row] = table_rows(s, "| Severity |")
    assert row[0] == "🟠 **Medium**" and row[1] == "Does not block"
    assert row[4] == "Review (low), Security (medium), Supply chain (medium)"  # every pass, in pass order
    assert row[3].startswith("Security title")  # the highest severity member names the row
    # The record keeps every title.
    record = s.rsplit("<details>", 1)[1]
    for title in ("Review title", "Security title", "Supply title"):
        assert f"| {title} |" in record


def test_same_place_with_different_effects_stay_on_separate_rows(tmp_path):
    passes = at_one_place(
        ("review", "malicious", "high", "Blocks"),
        ("security", "security", "medium", "Does not block"),
    )
    s = run(tmp_path, passes=passes).summary
    rows = table_rows(s, "| Severity |")
    assert [(x[1], x[4]) for x in rows] == [("Blocks, waivable", "Review (high)"),
                                           ("Does not block", "Security (medium)")]


def test_a_high_bug_does_not_block_and_does_not_merge_with_a_blocking_finding(tmp_path):
    passes = at_one_place(
        ("review", "bug", "high", "High bug"),
        ("security", "security", "high", "High security"),
    )
    s = run(tmp_path, passes=passes).summary
    rows = table_rows(s, "| Severity |")
    assert [x[1] for x in rows] == ["Blocks, waivable", "Does not block"]


def test_one_pass_with_two_findings_in_one_place_counts_them(tmp_path):
    passes = at_one_place(
        ("review", "bug", "low", "First"),
        ("review", "bug", "low", "Second"),
    )
    [row] = table_rows(run(tmp_path, passes=passes).summary, "| Severity |")
    assert row[4] == "Review (low, 2 findings)"


def test_different_lines_and_sides_never_merge(tmp_path):
    f = [finding(title="A", quote="line 11", line=11), finding(title="B", quote="line 12", line=12),
         finding(title="C", side="base", quote="line 10", line=10)]
    rows = table_rows(run(tmp_path, passes=clean_passes(review=f)).summary, "| Severity |")
    assert len(rows) == 3 and any("(base side)" in x[2] for x in rows)


def test_a_waiver_applied_is_a_green_pass_and_the_findings_stay_listed(tmp_path):
    from .test_publish import override
    r = run(tmp_path, FakeGitHub(issue_comments=[override(1)]), passes=clean_passes(supply_chain=[BLOCKING]))
    s = r.summary
    assert r.code == 0 and "## 🟢 All clear: Claude of Duty review passed\n" in s and callout_kind(s) == "TIP"
    assert "A maintainer waiver was applied by maintainer. Findings stay listed." in s
    assert s.lower().count("never approves") == 1
    [row] = table_rows(s, "| Severity |")
    assert row[1] == "Blocks, waived"
    assert ("blocking-finding", True) in [(c, w) for c, w, _ in reason_rows(s)]


# ---------------------------------------------------------------- size and cuts


def test_a_cut_keeps_tables_and_tags_whole(tmp_path, monkeypatch):
    real = publish.render_summary

    def small(ctx, result, **kw):
        return real(ctx, result, **{**kw, "limit": 9000})

    monkeypatch.setattr(publish, "render_summary", small)
    # Distinct lines, so the rows do not merge.
    review = [finding(title=f"Low {i}", file="src/app.py", line=1 + i, quote=f"line {1 + i}",
                      explanation="word " * 200) for i in range(9)]
    r = run(tmp_path, passes=clean_passes(review=review))
    s = r.summary
    assert len(s) <= 9000
    assert publish.TRUNCATED_NOTE in s
    assert "Some details were truncated, see the run log." in s
    assert s.count("<details>") == s.count("</details>")
    # A note row inside a table keeps the column count of its table.
    for line in s.split("\n"):
        if publish.TRUNCATED_NOTE in line and line.startswith("|"):
            assert len(re.split(r"(?<!\\)\|", line)) - 2 in (5, 7)
    # Cuts start at the end: the record loses whole bullets before the visible table loses a row.
    assert len(table_rows(s, "| Severity |")) == 9 and 0 < s.count("Quote: ") < 9


# ---------------------------------------------------------------- fix round 1


def case_g(tmp_path):
    return run(tmp_path, bundle=None)


def test_g_no_bundle_is_not_an_author_fix(tmp_path):
    r = case_g(tmp_path)
    s = r.summary
    out = os.environ.get("OC_RENDER_OUT")
    if out:
        Path(out).mkdir(parents=True, exist_ok=True)
        (Path(out) / "g-no-bundle.md").write_text(s, encoding="utf-8")
    assert r.code == 1
    assert "## 🔴 Comms down: the Claude of Duty review did not complete\n" in s and callout_kind(s) == "CAUTION"
    callout = "\n".join(line for line in s.split("\n") if line.startswith("> "))
    assert "A required check did not complete" in callout
    assert "a maintainer re-runs the newest run" in callout
    assert "fix the cause named in the row" not in callout and "then push" not in callout
    assert "blocks this PR" not in callout


def test_g_no_bundle_strip_does_not_say_ran(tmp_path):
    s = case_g(tmp_path).summary
    strip = next(line for line in s.split("\n") if line.startswith("| ❌ no result"))
    assert "ran" not in strip
    assert strip.count("⚠️ not validated") == 3


def test_hard_block_with_a_bundle_still_tells_the_author_to_fix(tmp_path):
    s = case_d(tmp_path).summary
    assert "fix the cause named in the row, then push" in s


def test_dependency_failure_with_blocking_finding_names_the_finding(tmp_path):
    tls = finding("security", "high", title=TLS, quote="shell=True")
    r = run(tmp_path, passes=clean_passes(security=[tls]), needs=needs_ok("failure"))
    callout = "\n".join(line for line in r.summary.split("\n") if line.startswith("> "))
    assert "also blocks" in callout
    assert "The author also fixes or waives the finding." in callout
    assert "does not need to change anything" not in callout


def test_dependency_failure_alone_needs_no_author_change(tmp_path):
    r = run(tmp_path, needs=needs_ok("failure"))
    assert "The author does not need to change anything." in r.summary


def test_long_path_is_cut_once(monkeypatch):
    """The schema caps `file` at 400, so a longer path reaches the renderer only
    from a future schema change; the merge key and the span must still cut once."""
    f = verdict.CitedFinding("review", "bug", "high", "high", "src/" + "d" * 600 + "/app.py", "head", 10,
                             "q", "Long path finding.", "e", True, True, True, None)
    result = SimpleNamespace(findings=[f])
    monkeypatch.setattr(publish, "_finding_effect", lambda *_: publish.EFFECT_NONE)
    [row] = publish._merge_findings(result, publish.InlineOutcome())
    assert row.where.count("…") == 1 and "[truncated]" not in row.where


def test_mission_line_sits_directly_under_the_heading(rendered):
    _, r = rendered
    lines = r.summary.split("\n")
    i = next(n for n, line in enumerate(lines) if line.startswith("## "))
    assert lines[i + 1] == publish.MISSION_LINE and r.summary.count(publish.MISSION_LINE) == 1
    assert publish.APPROVAL_NOTE in r.summary and "This bot never approves" not in r.summary


def test_fail_count_equals_findings_table_rows(rendered):
    _, r = rendered
    if r.code != 1 or "Comms down" in r.summary:
        return
    head = next(line for line in r.summary.split("\n") if line.startswith("## "))
    rows = []
    in_table = False
    for ln in r.summary.split("\n"):
        if ln.startswith("| Severity |"):
            in_table = True
        elif in_table and ln.startswith("|---"):
            continue
        elif in_table and ln.startswith("| "):
            rows.append(ln)
        elif in_table:
            break
    m = re.search(r"identified (\d+) items?", head)
    assert (int(m.group(1)) if m else 0) == len(rows)


def test_fail_heading_without_rows_has_no_number():
    result = SimpleNamespace(status=verdict.FAIL, codes=set(), override_applied=False)
    assert publish._status_heading(result, [], []) == (
        "## 🔴 Hold deployment: Claude of Duty identified items requiring attention")
