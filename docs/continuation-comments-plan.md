# Continuation comments for summary-only findings: plan

Status: **Planned, not built.** This plan is not part of the spec yet. The spec ([docs/claude-review-design.md](claude-review-design.md)) stays the source of truth until the build PR moves the parts below into it (see "Rollout"). Build plan item: [docs/build-plan.md](build-plan.md), phase 4.
Owner: Irving Popovetsky
Last updated: 2026-10-28

## Goal

When the sticky summary cannot hold every summary-only finding in full, the publisher posts the findings that do not fit in a bounded set of continuation comments. Then:

- no explanation of a finding is cut from the PR comments, and
- summary capacity no longer fails a run whose computed gate result is `pass`, when the overflow comes from findings.

The fail-closed check stays for every other case (see "Past the bound").

A "summary-only finding" is a finding with no inline comment that this run can point to: unverified, outside the diff, on `/.pr/title` or `/.pr/body`, changed from an earlier inline comment, or not posted because GitHub rejected the review. These are the posting states `unverified`, `outside`, `meta`, `changed` and `not-posted` in [publish.py:1085-1097](../review/src/oc_review/publish.py).

## Current behavior

All line numbers are at main `03e1b8d`.

**Where the findings are shown.** The sticky summary shows one table row per place for every finding ([publish.py:1146-1194](../review/src/oc_review/publish.py)). The collapsed record has a detail row per finding ([publish.py:1723-1744](../review/src/oc_review/publish.py)) and, for each summary-only finding, a bullet with the explanation and the quote under "Findings with no inline comment, in full" ([publish.py:1668-1701](../review/src/oc_review/publish.py), [publish.py:1745-1748](../review/src/oc_review/publish.py)).

**The size limit.** GitHub rejects a comment body over 65,536 characters. The code aims at 64,000 ([publish.py:864-865](../review/src/oc_review/publish.py)).

**The cut.** `_fit` joins the blocks and cuts by rank, each rank from its end: unverified low and medium findings, low and medium findings, dependency changes, signals ([publish.py:879-883](../review/src/oc_review/publish.py), [publish.py:919-951](../review/src/oc_review/publish.py)). A high or critical finding has no rank, so it is never cut, verified or not ([publish.py:1108-1111](../review/src/oc_review/publish.py), [publish.py:1676-1677](../review/src/oc_review/publish.py)). A cut group gets the note "N item(s) truncated, see the run log" ([publish.py:913-916](../review/src/oc_review/publish.py)), and the full redacted record goes to the gate job log ([publish.py:2208-2210](../review/src/oc_review/publish.py), [publish.py:2036-2044](../review/src/oc_review/publish.py)).

**The fail-closed check.** When the never-cut blocks alone are over the limit, `_fit` returns `(None, True)` ([publish.py:943-944](../review/src/oc_review/publish.py)). `render_summary` then returns the fixed-size notice with `overflow=True` ([publish.py:1930-1931](../review/src/oc_review/publish.py)). `publish` sets `publish_error = "the summary is over the comment limit"` ([publish.py:2218-2219](../review/src/oc_review/publish.py)) and returns 1 ([publish.py:2256-2258](../review/src/oc_review/publish.py)). The spec states this rule and its residual in "Publishing (code)", "Size limit and cut order" ([claude-review-design.md:594](claude-review-design.md)).

**What triggers it.** The never-cut data is over 64,000 characters: the heading, callout, checks strip, provenance, snapshot, reasons, waiver, override data, hard block evidence, coverage rows, model summaries, token usage, and the table rows, detail rows and bullets of high and critical findings. Under the schema caps (10, 10 and 15 findings per pass, [verdict.py:63-64](../review/src/oc_review/verdict.py)), the bullets are the large part. A measurement at `03e1b8d` with 35 unverified critical findings, every field at its schema limit and every character one that escapes to 3 characters, gave 300,164 characters of blocks: 267,730 in the 35 bullets (about 7,650 each) and 32,434 in everything else.

**What the user sees.** The sticky comment becomes the notice `## 🔴 FAIL: OC Claude review could not publish` with a `[!CAUTION]` callout, the computed gate result, the snapshot, a count per reason and the number of valid overrides ([publish.py:1854-1884](../review/src/oc_review/publish.py)). The required run fails, so the merge box blocks, also when the computed result was `pass`. A low or medium bullet that was cut shows only the truncation note; its explanation is in the run log only.

**Writes today.** The gate job may write only a `COMMENT` review, a new issue comment, and a PATCH of an issue comment ([publish.py:216-220](../review/src/oc_review/publish.py), [publish.py:270-277](../review/src/oc_review/publish.py)). The order is inline review, summary, final check, exit code, with a snapshot check before each write ([publish.py:2194-2259](../review/src/oc_review/publish.py)). The gate job has `contents: read`, `pull-requests: write`, `issues: write` and `actions: read`, and no Anthropic credential ([claude-review.yml:228-237](../.github/workflows/claude-review.yml)).

## Design

### When continuation is used

The publisher renders the sticky as today. If the result fits with no cut of a finding bullet (no block of rank `CUT_UNVERIFIED` or `CUT_LOW_MEDIUM` is cut, and `_fit` does not return `None`), it posts no continuation comment. This is the normal case, and the sticky does not change.

Otherwise it moves **every** summary-only bullet out of the sticky into continuation comments. It does not move only the bullets that do not fit. All-or-nothing keeps the order of findings in one place, keeps one pointer in the sticky, and gives the same layout on each re-run.

What stays in the sticky: every findings table row, every detail row, the model summaries and all other never-cut data. The detail rows of low and medium findings keep their cut rank, because the finding is still shown in full in a continuation comment. Dependency changes and signals keep their cut ranks and their run log note.

### Publish flow

```
 compute_gate (unchanged)
   |
   v
 inline review (unchanged)
   |
   v
 render sticky as today ------------------- fits, no finding bullet cut -----+
   |                                                                         |
   | a finding bullet would be cut, or _fit returns None                     |
   v                                                                         |
 move every summary-only bullet out; sort worst first; pack into parts       |
   |                                                                         |
   +-- parts > MAX_CONTINUATION, or the sticky still does not fit ---------+ |
   |                                                                       | |
   v                                                                       | |
 read own slots (bot author + slot marker), once                           | |
   |                                                                       | |
   v                                                                       | |
 for slot 1..K: snapshot check -> PATCH own slot, or POST a new one        | |
   |   stale -> write nothing more, exit 1                                 | |
   |   write refused -> stop, publish_error ---------------------------+   | |
   v                                                                   |   | |
 retire own slots > K (snapshot check, PATCH to the retired body)      |   | |
   |                                                                   |   | |
   v                                                                   v   v v
 snapshot check -> sticky write (normal layout with links to the parts, or the
                   fail-closed notice; any unused own slots are retired first,
                   best effort)
   |
   v
 final check (unchanged; a pass -> fail update re-renders only the sticky)
   |
   v
 exit code: 1 if publish_error, else verdict.exit_code(final)
```

The continuation comments are written before the sticky, so the sticky can link each part by a trusted comment ID and states only what was written. On the first run of a PR that needs continuation, the parts appear above the sticky in the timeline. This is accepted (see "Open questions", Q2).

### Limits

| Value | Proposed | Why |
|---|---|---|
| Body limit per continuation comment | 64,000 characters, the same `SUMMARY_LIMIT` as the sticky | GitHub rejects bodies over 65,536 characters. The same margin as the sticky. |
| Header and footer reserve | 1,000 characters | The header line, the run and sticky links and the untrusted-text note are fixed text plus integers. |
| Bullets per part | No count limit. Greedy packing by size, a bullet is never split | Worst case, a bullet is about 7,650 characters, so 8 fit in 63,000. |
| `MAX_CONTINUATION` | 6 | Worst case under today's caps: 35 bullets at about 7,650 characters at 8 per part is 5 parts. One spare part covers a small growth of the header or of one field limit. A unit test holds this (see "Test plan"). |
| Writes per run, continuation | At most 6 part writes plus at most 12 retire writes | Bounds the extra calls and the job time. A PATCH is skipped when the body is already the body to write. |

**Order.** Parts hold the bullets in the order of the findings table: severity first (critical, high, medium, low), verified before unverified within a severity, then pass order, file and line. That is the sort key of the table rows (`_Row.sort`). Part 1 always holds the worst findings.

### Past the bound

The publisher never drops a finding silently. It fails closed, as today, in each of these cases:

1. The bullets need more than `MAX_CONTINUATION` parts.
2. The sticky is still over the limit after every bullet moved out (for example, a very long list of coverage rows or hard block evidence, which this plan does not move).
3. A continuation write is refused, or its response has no usable comment ID.

In each case the sticky is the fixed-size notice of [publish.py:1854-1884](../review/src/oc_review/publish.py), with a note that names the case, the full record goes to the gate job log, and the job exits 1. Case 3 adds `publish_error = "a continuation comment write failed"`. Before the notice is written, any own continuation slots are retired, best effort, so no part from an older run reads as current. In case 1 no part is written.

So the existing `overflow` path in `render_summary` and `publish` stays. What changes is only that findings overflow goes to continuation first.

### Comment layout

```
 <!-- oc-claude-review-continuation:<slot> -->                   slot marker, first line
 ### OC Claude review: findings in full, part <i> of <K>
 <sub>Run [<run id>, attempt <n>](run URL). The result is in the [summary comment](link).
      The required workflow in the merge box is the result that counts. This bot never approves a PR.</sub>
 > **Model output from untrusted input. Check it before you act on it.** Verified means ...
 <!-- oc-continued:<d14 key> <full key> -->                       one per bullet
 - <the bullet, exactly as _finding_block renders it today>
 ...
```

- The slot marker uses a fixed prefix and a slot number from 1 to `MAX_CONTINUATION`. The regex accepts only that form. It never contains the sticky marker `<!-- oc-claude-review -->` as a substring, because `find_sticky_comment` matches by substring ([verdict.py:756-763](../review/src/oc_review/verdict.py)). A unit test holds this.
- Each bullet has the two keys of `finding_keys` ([publish.py:685-693](../review/src/oc_review/publish.py)) in the inline-marker shape, under the prefix `oc-continued:` and not `oc-finding:`. So `_FINDING_KEY_RE` ([publish.py:666](../review/src/oc_review/publish.py)) never matches it. That regex reads only review comments ([publish.py:718-742](../review/src/oc_review/publish.py)), and continuation comments are issue comments, so there are two separate guards.
- The bullet text has no gate-dependent words: no Effect column, no waiver text, no result. So a final check that turns `pass` into `fail` ([publish.py:2232-2246](../review/src/oc_review/publish.py)) needs no continuation update.
- The run link and the sticky link are built from trusted values only (server URL, repository, PR number, run ID, comment ID), as for the override links today.

In the sticky:

- The findings table pointer for a summary-only row reads "Details are in part i of K" with a link to that part, in place of "Details are in the record."
- In the record, "Findings with no inline comment, in full:" becomes one fixed line: "N findings with no inline comment are shown in full in K continuation comments:" and the K links.

### Idempotency on re-runs

The publisher finds its own continuation comments the way it finds the sticky: issue comments by `github-actions[bot]` whose body starts with a slot marker. For each slot it takes the oldest such comment (the same rule as `find_sticky_comment`). It reads the comments once, in the read that already gets the sticky and the override inputs.

- **Update.** Slots 1 to K that exist are PATCHed in place. A PATCH does not notify subscribers. Missing slots are POSTed. So a re-run makes no duplicate.
- **Stale parts.** Own slots above K, and any second comment for one slot (from two runs that wrote at the same time), are retired: PATCHed to a fixed short body with the slot marker, "This part is no longer used. Run R replaced it. The summary comment holds the current review." A retired comment is skipped when it already has that body.
- **No delete.** The plan adds no DELETE route. The write allowlist stays at three routes ([publish.py:216-220](../review/src/oc_review/publish.py)). See "Open questions", Q1.
- **No content trust.** The publisher reads a continuation comment only to find its slot and ID. It never reads findings, keys or text from it for a decision. Any Actions workflow in the repo can write as `github-actions[bot]`, so a forged part is at most overwritten or retired. This is the same rule as for the sticky.
- **Concurrent runs.** Runs on one PR are not serialized. Two runs can write parts of different runs. Each part names its run, and the sticky names its run, so a mix is visible. It never changes the gate (see "Summary writes" in the spec, [claude-review-design.md:540](claude-review-design.md)).

### Security

- **Same escaping and redaction.** A part holds only bullets from `_finding_block`, which uses `_esc` and `escape_text` for every untrusted string ([publish.py:157-205](../review/src/oc_review/publish.py)): control characters removed, credentials redacted before any cut, pings, links and commit references broken, Markdown punctuation escaped. The fixed header text has no untrusted string. No new escaping code.
- **Only the write job posts.** The parts are written by the gate job `oc-claude-review`, which has no Anthropic credential and no `id-token` ([claude-review.yml:228-237](../.github/workflows/claude-review.yml)). Analyze does not change.
- **Permissions unchanged.** `POST .../issues/{n}/comments` and `PATCH .../issues/comments/{id}` are already allowed. No new route, no new scope, no workflow change.
- **PATCH only own comments.** The PATCH route accepts any comment ID. A token with `issues: write` may be able to edit comments by other people, for example an override comment. So the build adds a code guard: a PATCH target must be an ID that this run read as a bot comment with the sticky marker or a slot marker. Any other ID is refused before the call. A unit test holds this.
- **Override parsing is not affected.** Override comments from bots are ignored, and a part holds only escaped text, so it cannot hold a valid override line.
- **Never a review verdict.** The parts are issue comments. The bot still never approves, requests changes, merges, closes, labels or edits the PR.

### Gate interaction

- Continuation runs after `compute_gate` and reads the frozen `GateResult` only. It never changes a reason, a finding, an override or the gate status.
- The exit code stays `1` when `publish_error` is set, else `verdict.exit_code(final)` ([publish.py:2253-2259](../review/src/oc_review/publish.py)). The only change: findings overflow no longer sets `publish_error` when every summary-only finding is published in full in the sticky or a part. That is not a gate reason and no override applies to it, so no gate verdict changes. A failed run caused by a gate reason stays failed.
- A missing or refused part can only make the run fail. Nothing in a part is read back.
- The rule "only code lowers risk" holds: the decision to post continuation comments is code, and Claude output cannot clear anything through it.

## Test plan

Unit tests, no network, with the fake GitHub of `test_publish.py`:

- **Normal case unchanged.** Every existing summary test renders the same body. No part is written when nothing would be cut.
- **Worst case fits the bound.** 35 findings at every schema limit, with characters that escape to 3 characters, need at most `MAX_CONTINUATION - 1` parts, and each part is at most 64,000 characters. The test reads the caps from `PASS_MAX_FINDINGS` and `LIMITS`, so a cap change that breaks the bound fails it.
- **Completeness.** For many sizes and mixes, the set of full keys of summary-only findings equals the set of `oc-continued:` keys across the parts, each once. The order across parts is the table order.
- **Never split.** No bullet spans two parts.
- **Past the bound.** More bullets than `MAX_CONTINUATION` parts can hold (test-only lower limit): no part is written, the sticky is the notice, the exit is 1. The same for a sticky that does not fit after the move.
- **Refused part write.** A 4xx or 5xx on part 2: no more part writes, the sticky is the notice, `publish_error` is set, exit 1.
- **Stale.** A snapshot change before part 2: nothing more is written, exit 1, step summary has `stale`.
- **Idempotency.** A re-run with the same parts makes 0 writes for unchanged bodies. A re-run with fewer parts PATCHes the parts it uses and retires the rest. Two comments with one slot marker: the oldest is used, the other retired. A slot marker from another author is ignored.
- **PATCH guard.** A PATCH to an ID that was not read as an own sticky or slot comment is refused before the call.
- **Markers.** No slot marker or part body contains the sticky marker. `_FINDING_KEY_RE` never matches a part. `find_sticky_comment` never picks a part.
- **Escaping.** The existing escaping tests run on a part body: a finding that quotes a credential, an `@` mention, a link, a commit SHA, HTML and an override line.
- **Gate truth.** For every case of the gate matrix, the gate status and reasons are the same with continuation used and not used. The exit code differs only in the findings-overflow case, from 1 to `verdict.exit_code(final)`.
- **Final check.** A pass turned to fail at the final check re-renders the sticky with the same part links and writes no part.
- **Write count.** No run makes more than `MAX_CONTINUATION` part writes plus 12 retire writes.

**Eval impact.** Continuation is code only. No model behavior changes, so no new live fixture case is needed. Two changes to the eval runner:

- It renders the parts too, to `<out-dir>/<case>/continuation-<i>.md`, when a case needs them.
- `summary_excludes` checks the sticky and every part, so a credential cannot leave through a part without a failed case.

Add one offline case under `review/tests/unit/fixtures/` (like `eval-smoke`) with fake pass records that force continuation. It runs in the unit tests, not in the live set. The release eval of the candidate still runs as in "Each release", because the candidate changes code.

**Live check.** No fixture makes the model return enough long findings on demand. So the unit tests are the proof. On claude-review-test, after the release, one run on a PR that needs no continuation must show the same sticky as before (no regression). The first real continuation in the pilot is recorded in the weekly pilot notes.

## Rollout

Two PRs, then one release.

1. **PR 1, pure functions.** Pack, sort, render a part body, slot marker parse, the worst-case and completeness tests. Not wired into `publish`. The fail-closed path is unchanged and is the only path.
2. **PR 2, wire it.** Slot read, part writes with a snapshot check before each, retire, the PATCH guard, the sticky pointers, the eval runner changes and the offline case. Update the spec in the same PR (list below). In this PR, findings overflow stops failing the run. The fail-closed check is not removed: it stays for the three cases in "Past the bound".
3. **Release.** The first release after M4. It ships as in "Each release" in the build plan: new federation rule, unit tests, the owner-approved release eval, the scratch test ruleset run, pin moves and read-backs.

The findings-overflow use of the fail-closed check goes away only in PR 2, after PR 1 and PR 2 tests pass, and in production only when the pin moves to that release. The check itself stays.

Spec sections to change in PR 2:

- "Architecture" diagram: "post inline comments (event: COMMENT), then the sticky summary" adds the continuation comments between them.
- "Threat model", the exfiltration row: the publisher escapes text in the summary and in continuation comments.
- "Publishing (code)": "Summary comment" (the part pointers in the table and the record), "Size limit and cut order" (continuation first, `MAX_CONTINUATION`, the three fail-closed cases; remove the residual that a low or medium explanation can be cut and that capacity fails a `pass`), "Full record" (also printed when parts are used), "Order of writes" (inline, parts, summary, final check; PATCH only own comments), "Refused summary write" (also a refused part write).
- "Which run counts", "Summary writes": parts are best effort and never a trust source, like the sticky.
- "Testing": the new unit tests and the eval runner changes.
- "Decision log": a new line for this change.
- [docs/build-plan.md](build-plan.md) phase 4: mark the item done.
- The `publish.py` module docstring: the write order.

## Open questions

Each has a recommended answer. The owner decides.

- **Q1. Delete stale parts, or PATCH them to a retired notice?** Recommend PATCH. A DELETE route on `issues/comments/{id}` could delete an override comment if a bug picks the wrong ID. A PATCH keeps the allowlist at three routes. Cost: up to `MAX_CONTINUATION` short retired comments can stay on a PR.
- **Q2. Write the parts before or after the sticky?** Recommend before. The sticky then links to parts that exist and states what was written. Cost: on the first run that needs parts, they show above the sticky in the timeline. On later runs the slots are reused in place.
- **Q3. Move only the bullets that do not fit, or all of them?** Recommend all of them. One layout and one pointer, and the order is in one place. Cost: when parts are used, the high and critical explanations are also one click away, not in the sticky. Their table rows stay in the sticky.
- **Q4. Also move other never-cut data (coverage rows, hard block evidence) to parts?** Recommend no, not in this release. The build plan item is about findings. Those lists are code output, and a fail-closed run on a very large PR is the safer outcome. Revisit if the pilot shows it.
- **Q5. One snapshot check per part write, or one before all parts?** Recommend one per write. The spec says every write is preceded by the snapshot check ([claude-review-design.md:597](claude-review-design.md)). Cost: two reads per part, at most 36 extra reads.
- **Q6. `MAX_CONTINUATION` value.** Recommend 6: worst case is 5 under today's caps, plus one spare. A unit test ties it to the caps.
- **Q7. Should a refused part write fail the run?** Recommend yes. It matches the refused summary write rule, and a missing part would hide findings. Cost: a GitHub write error can fail a run whose computed result is `pass`, as it can today.
