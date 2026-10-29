"""Bounded line diff: the size budget and the counted work budgets."""

from __future__ import annotations

import difflib
import random
import time

import pytest

from oc_review import linediff

N = 2_000  # lines per side: minutes of difflib work on these inputs, unbounded


def _alt(n: int, x: str = "a", y: str = "b") -> list[str]:
    return [x if i % 2 == 0 else y for i in range(n)]


def _ends(lines: list[str], first: str, last: str) -> list[str]:
    return [first, *lines[1:-1], last]


LOW_ENTROPY = {
    # "a" only vs alternating "a"/"b" with changed ends.
    "a-only-vs-alternating": (["a"] * N, _ends(_alt(N), "c", "d")),
    # alternating vs pairs ("a a b b ..."), changed ends.
    "alternating-vs-pairs": (
        _ends(_alt(N), "c", "d"),
        _ends(["a" if (i // 2) % 2 == 0 else "b" for i in range(N)], "e", "f"),
    ),
    # "x0" block then "x1" block vs alternating "x0"/"x1", changed ends.
    "x0-x1-blocks-vs-alternating": (
        ["s", *["x0"] * (N // 2), *["x1"] * (N // 2), "e"],
        ["t", *_alt(N, "x0", "x1"), "f"],
    ),
}


def _coarse(a, b) -> list[linediff.Opcode]:
    return [("replace", 0, len(a), 0, len(b))]


@pytest.mark.parametrize("name", LOW_ENTROPY)
def test_low_entropy_input_falls_back_within_the_file_budget(name):
    a, b = LOW_ENTROPY[name]
    assert len(a) * len(b) <= linediff.DIFF_BUDGET  # the size budget lets it through
    work = linediff.WorkBudget()
    start = time.perf_counter()
    d = linediff.diff(a, b, work=work)
    elapsed = time.perf_counter() - start
    assert d.reason == linediff.PAST_FILE_WORK_BUDGET and not d.exact
    assert d.codes == _coarse(a, b)
    # The whole allowance is charged to the run.
    assert work.left == linediff.RUN_WORK_BUDGET - linediff.FILE_WORK_BUDGET
    # Loose guard only (the bound itself is the step count): about 0.3 s on
    # an M-series core; unbounded, these inputs take minutes.
    assert elapsed < 5, elapsed


def test_the_count_is_deterministic():
    a, b = LOW_ENTROPY["alternating-vs-pairs"]
    a, b = a[:300], b[:300]  # within the file budget
    lefts = set()
    for _ in range(3):
        work = linediff.WorkBudget()
        assert linediff.diff(a, b, work=work).exact
        lefts.add(work.left)
    (left,) = lefts
    assert 0 < linediff.RUN_WORK_BUDGET - left < linediff.FILE_WORK_BUDGET


def _reference(a, b) -> list[linediff.Opcode]:
    """The diff before the work budget: trimmed ends, plain difflib middle."""
    pre = 0
    while pre < min(len(a), len(b)) and a[pre] == b[pre]:
        pre += 1
    suf = 0
    while suf < min(len(a), len(b)) - pre and a[-1 - suf] == b[-1 - suf]:
        suf += 1
    codes = [("equal", 0, pre, 0, pre)] if pre else []
    am, bm = a[pre : len(a) - suf], b[pre : len(b) - suf]
    if am or bm:
        middle = difflib.SequenceMatcher(None, am, bm, autojunk=False).get_opcodes()
        codes += [(t, i1 + pre, i2 + pre, j1 + pre, j2 + pre) for t, i1, i2, j1, j2 in middle]
    if suf:
        codes.append(("equal", len(a) - suf, len(a), len(b) - suf, len(b)))
    return codes


def test_within_budget_the_opcodes_are_difflibs():
    rng = random.Random(99)
    for _ in range(300):
        a = [rng.choice("abcde") for _ in range(rng.randint(0, 60))]
        b = [rng.choice("abcde") for _ in range(rng.randint(0, 60))]
        d = linediff.diff(a, b)
        assert d.exact and d.codes == _reference(a, b)


class _Recording(linediff._CountingMatcher):
    def __init__(self, a, b, allowance):
        self.calls = []
        super().__init__(a, b, allowance)

    def find_longest_match(self, alo=0, ahi=None, blo=0, bhi=None):
        self.calls.append((alo, ahi, blo, bhi))
        return super().find_longest_match(alo, ahi, blo, bhi)


def test_counted_steps_cover_difflibs_inner_loop():
    rng = random.Random(5)
    for _ in range(100):
        a = [rng.choice("abc") for _ in range(rng.randint(1, 80))]
        b = [rng.choice("abc") for _ in range(rng.randint(1, 80))]
        m = _Recording(a, b, 10**9)
        m.get_opcodes()
        inner = 0
        for alo, ahi, blo, bhi in m.calls:
            for i in range(alo, ahi):
                for j in m.b2j.get(a[i], ()):
                    inner += 1
                    if j >= bhi:
                        break
        assert 10**9 - m.left >= inner + len(a) + len(b)


def test_one_side_empty_is_exact_and_free():
    work = linediff.WorkBudget(total=0)
    assert linediff.diff([], ["x"] * 10, work=work) == linediff.Diff([("insert", 0, 0, 0, 10)])
    assert linediff.diff(["x"] * 10, [], work=work) == linediff.Diff([("delete", 0, 10, 0, 0)])
    assert linediff.diff(["p", "x"], ["p", "x", "y"], work=work).exact
    assert work.left == 0


def test_size_budget_is_checked_first_and_costs_nothing():
    work = linediff.WorkBudget()
    d = linediff.diff(["a", "x", "b"], ["c", "x", "d"], budget=8, work=work)
    assert d.reason == linediff.PAST_SIZE_BUDGET
    assert d.codes == _coarse(["a", "x", "b"], ["c", "x", "d"])
    assert work.left == linediff.RUN_WORK_BUDGET


def test_the_run_budget_is_shared_by_every_file():
    a, b = LOW_ENTROPY["alternating-vs-pairs"]
    a, b = a[:300], b[:300]
    probe = linediff.WorkBudget()
    linediff.diff(a, b, work=probe)
    steps = linediff.RUN_WORK_BUDGET - probe.left

    work = linediff.WorkBudget(total=2 * steps + steps // 2, per_file=10 * steps)
    results = [linediff.diff(a, b, work=work) for _ in range(5)]
    assert [r.reason for r in results] == [None, None] + [linediff.PAST_RUN_WORK_BUDGET] * 3
    assert work.left == 0
    coarse = linediff.diff(a, b, work=linediff.WorkBudget(total=0)).codes
    assert all(r.codes == coarse for r in results[2:])
    assert [tag for tag, *_ in coarse if tag != "equal"] == ["replace"]
    # A small file after the run budget is spent still falls back.
    small = linediff.diff(["a", "b", "x"], ["b", "a", "y"], work=work)
    assert small.reason == linediff.PAST_RUN_WORK_BUDGET


def test_per_file_and_run_reasons():
    a, b = LOW_ENTROPY["a-only-vs-alternating"]
    # The file budget is the smaller limit: the file's reason.
    assert linediff.diff(a, b, work=linediff.WorkBudget(total=10**9, per_file=1_000)).reason == (
        linediff.PAST_FILE_WORK_BUDGET
    )
    # The run has less left than a file may take: the run's reason.
    assert linediff.diff(a, b, work=linediff.WorkBudget(total=1_000, per_file=10**9)).reason == (
        linediff.PAST_RUN_WORK_BUDGET
    )


# ---------------------------------------------------------------- anchored (collect, K-17)


def _check_script(a, b, codes) -> int:
    """`codes` is a correct edit script of `a` to `b`; returns the changed line count."""
    i = j = changed = 0
    for tag, i1, i2, j1, j2 in codes:
        assert (i1, j1) == (i, j)
        if tag == "equal":
            assert a[i1:i2] == b[j1:j2]
        else:
            changed += (i2 - i1) + (j2 - j1)
        i, j = i2, j2
    assert (i, j) == (len(a), len(b))
    return changed


def _lockfile(n: int, bumped: set[int]) -> list[str]:
    """pnpm-like lines: unique name and integrity lines, repeated filler lines."""
    out = []
    for k in range(n):
        v = f"1.0.{k + (k in bumped)}"
        out += [f"  pkg-{k}@{v}:", f"    resolution: {{integrity: sha512-{k}-{v}}}", "    engines: {node: '>=18'}", ""]
    return out


def test_anchored_lockfile_churn_is_a_small_diff_within_the_file_budget():
    n = 4_000  # 16,000 lines per side, changed near both ends
    bumped = {0, n - 1, *range(1, n, 97)}
    a, b = _lockfile(n, set()), _lockfile(n, bumped)
    assert len(a) * len(b) > linediff.DIFF_BUDGET
    work = linediff.WorkBudget()
    d = linediff.diff(a, b, work=work, anchored=True)
    assert d.reason == linediff.ANCHORED and not d.exact
    assert _check_script(a, b, d.codes) == 4 * len(bumped)  # name and integrity line, each side
    assert 0 < linediff.RUN_WORK_BUDGET - work.left < linediff.FILE_WORK_BUDGET
    # Without `anchored` (the publisher) the middle is one replace, as before.
    plain = linediff.diff(a, b, work=linediff.WorkBudget())
    assert plain.reason == linediff.PAST_SIZE_BUDGET
    assert _check_script(a, b, plain.codes) > len(a) + len(b) - 10


def test_anchored_diff_is_a_correct_edit_script():
    rng = random.Random(17)
    for _ in range(300):
        pool = [f"u{k}" for k in range(40)] + ["x", "y", ""] * 10
        a = [rng.choice(pool) for _ in range(rng.randint(0, 50))]
        b = [rng.choice(pool) for _ in range(rng.randint(0, 50))]
        work = linediff.WorkBudget()
        d = linediff.diff(a, b, budget=rng.choice([0, 1, 20, 400]), work=work, anchored=True)
        _check_script(a, b, d.codes)
        assert all(x[0] != "equal" or y[0] != "equal" for x, y in zip(d.codes, d.codes[1:]))
        assert work.left <= linediff.RUN_WORK_BUDGET


def test_anchored_with_no_unique_line_is_one_replace():
    a, b = ["s", *_alt(10)], ["t", *_alt(10, "b", "a")]
    d = linediff.diff(a, b, budget=1, anchored=True)
    assert d.codes == _coarse(a, b)
    assert d.reason == linediff.ANCHORED + "; part past the size budget"


def test_anchoring_is_charged_and_skipped_when_the_file_cannot_pay():
    a, b = ["a", "x", "b"], ["c", "x", "d"]
    cost = len(a) + len(b) + 3
    work = linediff.WorkBudget(total=cost - 1)
    d = linediff.diff(a, b, budget=0, work=work, anchored=True)
    assert (d.reason, d.codes, work.left) == (linediff.PAST_SIZE_BUDGET, _coarse(a, b), cost - 1)
    work = linediff.WorkBudget(total=cost)
    d = linediff.diff(a, b, budget=0, work=work, anchored=True)
    assert d.codes == [("replace", 0, 1, 0, 1), ("equal", 1, 2, 1, 2), ("replace", 2, 3, 2, 3)]
    assert d.reason == linediff.ANCHORED + "; part past the size budget"
    assert work.left == 0


def test_anchored_gap_past_the_work_budget_charges_the_whole_allowance():
    low_a, low_b = LOW_ENTROPY["a-only-vs-alternating"]
    a, b = ["head", *low_a, "tail"], ["head2", "head", *low_b, "tail"]
    # Only the gap after the anchor "head" fits the size budget.
    budget = len(low_a) * len(low_b)
    work = linediff.WorkBudget()
    d = linediff.diff(a, b, budget=budget, work=work, anchored=True)
    assert d.reason == linediff.ANCHORED + "; part past the per-file work budget"
    assert work.left == linediff.RUN_WORK_BUDGET - linediff.FILE_WORK_BUDGET
    _check_script(a, b, d.codes)
    run = linediff.WorkBudget(total=1_000_000)
    assert linediff.diff(a, b, budget=budget, work=run, anchored=True).reason == (
        linediff.ANCHORED + "; part past the run work budget"
    )
    assert run.left == 0
