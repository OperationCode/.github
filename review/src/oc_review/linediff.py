"""Bounded line diff, shared by collect (patches) and publish (inline hunks).

The common prefix and suffix are trimmed first, so a small change to a large
file is cheap. The middle is diffed line by line (difflib) only within two
limits:

- a size budget: the product of the middle lengths;
- a work budget: counted steps of difflib's inner loop. On low-entropy input
  (few distinct lines, each repeated many times) that work grows about with
  the cube of the line count, so the size budget alone does not bound it.
  Each file gets at most `FILE_WORK_BUDGET` steps, and every file of one run
  shares one `WorkBudget` of `RUN_WORK_BUDGET` steps.

The count is deterministic (it depends on the input only, never on the
clock). Past a limit the middle is one `replace`: every base line there is
removed and every head line added. The result then is not exact, and its
`reason` names the limit.

With `anchored=True` (collect's patches only, K-17), a middle past the size
budget is first split at anchors: lines that occur exactly once in the base
middle and once in the head middle, in the longest run that keeps their
order on both sides. Each gap between anchors gets the bounded diff above,
and a gap past a limit is one `replace`. Anchoring takes its steps from the
same work budget. The result is a correct edit script, never git's, so it is
not exact either.
"""

from __future__ import annotations

import difflib
from bisect import bisect_left
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from typing import Any

Opcode = tuple[str, int, int, int, int]

# Past this product of middle lengths, the middle is not diffed line by line.
DIFF_BUDGET = 25_000_000
# Counted steps (see `_CountingMatcher`) for one file, and for all files of one
# run. Measured on an Apple M-series core: 15 to 40 million steps per second,
# so at most about 0.35 s per file and 7 s per run (spec "Coverage limits").
FILE_WORK_BUDGET = 5_000_000
RUN_WORK_BUDGET = 100_000_000

PAST_SIZE_BUDGET = "line diff past the size budget"
PAST_FILE_WORK_BUDGET = "line diff past the per-file work budget"
PAST_RUN_WORK_BUDGET = "line diff past the run work budget"
ANCHORED = "line diff past the size budget, anchored on lines that occur once on each side"


class WorkBudget:
    """Diff work left for one run. Every file of the run takes from it."""

    def __init__(self, total: int | None = None, per_file: int | None = None) -> None:
        self.left = RUN_WORK_BUDGET if total is None else total
        self.per_file = FILE_WORK_BUDGET if per_file is None else per_file


@dataclass(frozen=True)
class Diff:
    """Opcodes of `a` to `b`. `reason` is None when they are exact."""

    codes: list[Opcode]
    reason: str | None = None

    @property
    def exact(self) -> bool:
        return self.reason is None


class _Spent(Exception):
    pass


class _CountingMatcher(difflib.SequenceMatcher):
    """SequenceMatcher (no junk) that stops when its step allowance is spent.

    Steps: one per line of both sequences (building the index), and for each
    `find_longest_match` call one per line of both ranges plus one per inner
    loop pass (each `j` that `a[i]` matches below `bhi`, and the pass that
    ends the `j` loop). This is at least the work difflib does, so time is
    about proportional to the count. A call is counted before it runs.
    """

    def __init__(self, a: Sequence[Any], b: Sequence[Any], allowance: int) -> None:
        self.left = allowance - len(a) - len(b)
        if self.left < 0:
            raise _Spent
        super().__init__(None, a, b, autojunk=False)

    def find_longest_match(self, alo: int = 0, ahi: int | None = None, blo: int = 0, bhi: int | None = None):
        ahi = len(self.a) if ahi is None else ahi
        bhi = len(self.b) if bhi is None else bhi
        left = self.left - (ahi - alo) - (bhi - blo)
        b2j, a = self.b2j, self.a
        for i in range(alo, ahi):
            js = b2j.get(a[i])
            if js:
                left -= bisect_left(js, bhi) + 1
                if left < 0:
                    raise _Spent
        if left < 0:
            raise _Spent
        self.left = left
        return super().find_longest_match(alo, ahi, blo, bhi)


def diff(
    a: Sequence[Any],
    b: Sequence[Any],
    budget: int = DIFF_BUDGET,
    work: WorkBudget | None = None,
    *,
    anchored: bool = False,
) -> Diff:
    """difflib-style opcodes of `a` to `b`, bounded by the size budget and by
    `work` (a fresh `WorkBudget` when None). `anchored` splits a middle past
    the size budget at unique lines first (`_anchored`)."""
    if work is None:
        work = WorkBudget()
    pre = 0
    while pre < len(a) and pre < len(b) and a[pre] == b[pre]:
        pre += 1
    suf = 0
    while suf < len(a) - pre and suf < len(b) - pre and a[-1 - suf] == b[-1 - suf]:
        suf += 1
    am, bm = a[pre : len(a) - suf], b[pre : len(b) - suf]
    codes: list[Opcode] = []
    reason: str | None = None
    if pre:
        codes.append(("equal", 0, pre, 0, pre))
    if am or bm:
        middle: list[Opcode] | None = None
        if not am:
            middle = [("insert", 0, 0, 0, len(bm))]
        elif not bm:
            middle = [("delete", 0, len(am), 0, 0)]
        elif len(am) * len(bm) > budget:
            reason = PAST_SIZE_BUDGET
            if anchored:
                middle, reason = _anchored(am, bm, budget, work)
        else:
            allowance = max(0, min(work.per_file, work.left))
            try:
                matcher = _CountingMatcher(am, bm, allowance)
                middle = matcher.get_opcodes()
            except _Spent:
                # Charge the whole allowance: the count that was cut off ran in part.
                work.left -= allowance
                reason = PAST_FILE_WORK_BUDGET if allowance == work.per_file else PAST_RUN_WORK_BUDGET
            else:
                work.left -= allowance - matcher.left
        if middle is None:
            middle = [("replace", 0, len(am), 0, len(bm))]
        codes.extend((tag, i1 + pre, i2 + pre, j1 + pre, j2 + pre) for tag, i1, i2, j1, j2 in middle)
    if suf:
        codes.append(("equal", len(a) - suf, len(a), len(b) - suf, len(b)))
    return Diff(codes, reason)


def _unique_pairs(a: Sequence[Any], b: Sequence[Any]) -> list[tuple[int, int]]:
    """(i, j) of each line that occurs once in `a` and once in `b`, by i."""
    seen_a: dict[Any, int] = {}
    for i, line in enumerate(a):
        seen_a[line] = -1 if line in seen_a else i
    seen_b: dict[Any, int] = {}
    for j, line in enumerate(b):
        seen_b[line] = -1 if line in seen_b else j
    return [
        (i, j) for i, line in enumerate(a) if seen_a[line] == i and (j := seen_b.get(line, -1)) >= 0
    ]


def _longest_ordered(pairs: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """The longest subsequence of `pairs` (sorted by i) whose j also rises."""
    tails: list[int] = []  # smallest last j of a run of each length
    tail_at: list[int] = []  # index in `pairs` of that last element
    prev = [-1] * len(pairs)
    for k, (_, j) in enumerate(pairs):
        n = bisect_left(tails, j)
        if n == len(tails):
            tails.append(j)
            tail_at.append(k)
        else:
            tails[n] = j
            tail_at[n] = k
        prev[k] = tail_at[n - 1] if n else -1
    out: list[tuple[int, int]] = []
    k = tail_at[-1] if tail_at else -1
    while k >= 0:
        out.append(pairs[k])
        k = prev[k]
    out.reverse()
    return out


def _anchored(
    a: Sequence[Any], b: Sequence[Any], budget: int, work: WorkBudget
) -> tuple[list[Opcode] | None, str]:
    """Opcodes of a middle past the size budget, split at anchors, and the
    reason. None (one `replace`) when the file's allowance cannot pay for
    the anchoring, which is then not run and costs nothing.

    Anchoring costs one step per line of both sides plus one per line of the
    shorter side (the pair list and its longest ordered run). Every gap
    takes its steps from what is left of the file's allowance, so the file
    and the run limits hold. A file past a limit in a gap is charged its
    whole allowance, and the reason names that limit.
    """
    allowance = max(0, min(work.per_file, work.left))
    cost = len(a) + len(b) + min(len(a), len(b))
    if cost > allowance:
        return None, PAST_SIZE_BUDGET
    gaps = WorkBudget(total=allowance - cost, per_file=allowance - cost)
    anchors = _longest_ordered(_unique_pairs(a, b))
    codes: list[Opcode] = []
    past: set[str] = set()
    i0 = j0 = 0
    for i, j in [*anchors, (len(a), len(b))]:
        part = diff(a[i0:i], b[j0:j], budget, gaps)
        if part.reason is not None:
            past.add(part.reason)
        codes.extend((tag, i1 + i0, i2 + i0, j1 + j0, j2 + j0) for tag, i1, i2, j1, j2 in part.codes)
        if i < len(a):
            codes.append(("equal", i, i + 1, j, j + 1))
        i0, j0 = i + 1, j + 1
    work.left -= allowance - gaps.left
    # A gap's own work reason is relative to `gaps`; name the file's limit.
    worst = None
    if past - {PAST_SIZE_BUDGET}:
        worst = PAST_FILE_WORK_BUDGET if allowance == work.per_file else PAST_RUN_WORK_BUDGET
    elif past:
        worst = PAST_SIZE_BUDGET
    reason = ANCHORED if worst is None else f"{ANCHORED}; part {worst.removeprefix('line diff ')}"
    return _merge_equal(codes), reason


def _merge_equal(codes: list[Opcode]) -> list[Opcode]:
    """Join adjacent `equal` opcodes, so `hunks` sees each equal run whole."""
    out: list[Opcode] = []
    for code in codes:
        if out and code[0] == "equal" and out[-1][0] == "equal":
            tag, i1, _, j1, _ = out[-1]
            out[-1] = (tag, i1, code[2], j1, code[4])
        else:
            out.append(code)
    return out


def hunks(codes: list[Opcode], n: int) -> Iterator[list[Opcode]]:
    """Group opcodes into hunks with `n` lines of context (difflib's rule)."""
    if not any(tag != "equal" for tag, *_ in codes):
        return
    codes = list(codes)
    tag, i1, i2, j1, j2 = codes[0]
    if tag == "equal":
        codes[0] = (tag, max(i1, i2 - n), i2, max(j1, j2 - n), j2)
    tag, i1, i2, j1, j2 = codes[-1]
    if tag == "equal":
        codes[-1] = (tag, i1, min(i2, i1 + n), j1, min(j2, j1 + n))
    group: list[Opcode] = []
    for tag, i1, i2, j1, j2 in codes:
        if tag == "equal" and i2 - i1 > 2 * n:
            group.append((tag, i1, min(i2, i1 + n), j1, min(j2, j1 + n)))
            yield group
            group = []
            i1, j1 = max(i1, i2 - n), max(j1, j2 - n)
        group.append((tag, i1, i2, j1, j2))
    if group and not (len(group) == 1 and group[0][0] == "equal"):
        yield group
