"""Bounded line diff, shared by collect (patches) and publish (inline hunks).

The common prefix and suffix are trimmed first, so a small change to a large
file is cheap. A line diff of the middle runs only when the product of the
middle lengths is within a fixed work budget, so a large repetitive blob
cannot hold a job until its timeout.
"""

from __future__ import annotations

import difflib
from collections.abc import Iterator, Sequence
from typing import Any

Opcode = tuple[str, int, int, int, int]

# Past this product of middle lengths, the middle is not diffed line by line.
DIFF_BUDGET = 25_000_000


def opcodes(a: Sequence[Any], b: Sequence[Any], budget: int = DIFF_BUDGET) -> tuple[list[Opcode], bool]:
    """difflib-style opcodes of `a` to `b`, and whether they are exact.

    Past `budget`, the middle between the common prefix and suffix is one
    `replace` (not exact): every base line there is removed and every head
    line added.
    """
    pre = 0
    while pre < len(a) and pre < len(b) and a[pre] == b[pre]:
        pre += 1
    suf = 0
    while suf < len(a) - pre and suf < len(b) - pre and a[-1 - suf] == b[-1 - suf]:
        suf += 1
    am, bm = a[pre : len(a) - suf], b[pre : len(b) - suf]
    codes: list[Opcode] = []
    exact = True
    if pre:
        codes.append(("equal", 0, pre, 0, pre))
    if am or bm:
        if len(am) * len(bm) <= budget:
            middle = difflib.SequenceMatcher(None, am, bm, autojunk=False).get_opcodes()
        else:
            middle = [("replace", 0, len(am), 0, len(bm))]
            exact = False
        codes.extend((tag, i1 + pre, i2 + pre, j1 + pre, j2 + pre) for tag, i1, i2, j1, j2 in middle)
    if suf:
        codes.append(("equal", len(a) - suf, len(a), len(b) - suf, len(b)))
    return codes, exact


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
