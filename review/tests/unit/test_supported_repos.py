"""docs/supported-repos.md: the inventory the review ruleset targets (spec
"Supported repos"). Parses the file only; no network."""

import re
from pathlib import Path

import pytest

DOC = Path(__file__).resolve().parents[3] / "docs" / "supported-repos.md"
GITHUB_REPO_ID = 1432342572  # OperationCode/.github: never a target (deadlock)
TEST_REPO_ID = 1432457406  # claude-review-test: only the scratch test ruleset
STATUSES = {"target", "candidate"}


def table(heading: str) -> list[list[str]]:
    """The body rows of the first Markdown table under `## heading`."""
    text = DOC.read_text(encoding="utf-8")
    section = text.split(f"\n## {heading}\n", 1)[1] if heading else text
    section = section.split("\n## ", 1)[0]
    rows = [line for line in section.splitlines() if line.startswith("|")]
    assert len(rows) >= 3, f"no table under {heading!r}"
    assert set(rows[1].replace("|", "").strip()) <= {"-", " "}, "second row must be the separator"
    return [[cell.strip() for cell in row.strip().strip("|").split("|")] for row in rows[2:]]


def supported() -> list[dict]:
    out = []
    for cells in table(""):
        assert len(cells) == 5, cells
        name, rid, branch, status, joined = cells
        out.append({"name": name.strip("`"), "id": int(rid), "branch": branch.strip("`"),
                    "status": status, "joined": joined})
    return out


def test_ids_are_unique_integers():
    ids = [r["id"] for r in supported()]
    assert ids and len(ids) == len(set(ids))


@pytest.mark.parametrize("never", [GITHUB_REPO_ID, TEST_REPO_ID])
def test_never_lists_github_or_the_test_repo(never):
    assert never not in {r["id"] for r in supported()}


def test_status_and_date():
    for r in supported():
        assert r["status"] in STATUSES, r
        assert r["branch"], r
        if r["status"] == "target":
            assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", r["joined"]), r
        else:
            assert r["joined"] == "", r


def test_excluded_list_names_github_and_the_test_repo_and_overlaps_nothing():
    excluded = {int(cells[1]) for cells in table("Excluded active repos")}
    assert {GITHUB_REPO_ID, TEST_REPO_ID} <= excluded
    assert not excluded & {r["id"] for r in supported()}


def test_ids_match_the_plan_at_phase_5():
    # Plan v2 section 2.1 (read-only GETs, 2026-11-01). Update with the list.
    assert {r["id"]: r["status"] for r in supported()} == {
        135777271: "target", 182584277: "target", 107068150: "target", 146210805: "target",
        82613670: "candidate"}
