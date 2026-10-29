# Continuation comments for summary-only findings: plan

Status: **Planned, not built.** This plan is not part of the spec yet. The spec ([docs/claude-review-design.md](claude-review-design.md)) stays the source of truth until the build PR moves the parts below into it (see "Rollout"). Build plan item: [docs/build-plan.md](build-plan.md), phase 4.
Owner: Irving Popovetsky
Last updated: 2026-10-28 (revised after plan review B: 3 Important, 4 Minor; owner decisions on Q1 to Q7)

## Goal

When the sticky summary cannot hold every summary-only finding in full, the publisher posts the findings in a bounded set of continuation comments ("parts"). Then:

- no explanation of a finding is cut from the PR comments that the current sticky links, also when two runs publish at the same time, and
- summary capacity no longer fails a run whose computed gate result is `pass`, when the overflow comes from findings.

The fail-closed check stays for every other case (see "Past the bound").

A "summary-only finding" is a finding with no inline comment that this run can point to: unverified, outside the diff, on `/.pr/title` or `/.pr/body`, changed from an earlier inline comment, or not posted because GitHub rejected the review. These are the posting states `unverified`, `outside`, `meta`, `changed` and `not-posted` in [publish.py:1085-1097](../review/src/oc_review/publish.py).

## Current behavior

All line numbers are at main `03e1b8d`.

**Where the findings are shown.** The sticky summary shows one table row per place for every finding ([publish.py:1146-1194](../review/src/oc_review/publish.py)). The collapsed record has a detail row per finding ([publish.py:1723-1744](../review/src/oc_review/publish.py)) and, for each summary-only finding, a bullet with the explanation and the quote under "Findings with no inline comment, in full" ([publish.py:1668-1701](../review/src/oc_review/publish.py), [publish.py:1745-1748](../review/src/oc_review/publish.py)). Table rows and detail rows of low and medium findings have a cut rank, so at the largest sizes they can be cut too ([publish.py:1177-1180](../review/src/oc_review/publish.py), [publish.py:1306-1307](../review/src/oc_review/publish.py), [publish.py:1727-1743](../review/src/oc_review/publish.py)).

**The size limit.** GitHub rejects a comment body over 65,536 characters. The code aims at 64,000 ([publish.py:864-865](../review/src/oc_review/publish.py)).

**The cut.** `_fit` joins the blocks and cuts by rank, each rank from its end: unverified low and medium findings, low and medium findings, dependency changes, signals ([publish.py:879-883](../review/src/oc_review/publish.py), [publish.py:919-951](../review/src/oc_review/publish.py)). A high or critical finding has no rank, so it is never cut, verified or not ([publish.py:1108-1111](../review/src/oc_review/publish.py), [publish.py:1676-1677](../review/src/oc_review/publish.py)). A cut group gets the note "N item(s) truncated, see the run log" ([publish.py:913-916](../review/src/oc_review/publish.py)), and the full redacted record goes to the gate job log ([publish.py:2208-2210](../review/src/oc_review/publish.py), [publish.py:2036-2044](../review/src/oc_review/publish.py)).

**The fail-closed check.** When the never-cut blocks alone are over the limit, `_fit` returns `(None, True)` ([publish.py:943-944](../review/src/oc_review/publish.py)). `render_summary` then returns the fixed-size notice with `overflow=True` ([publish.py:1930-1931](../review/src/oc_review/publish.py)). `publish` sets `publish_error = "the summary is over the comment limit"` ([publish.py:2218-2219](../review/src/oc_review/publish.py)) and returns 1 ([publish.py:2256-2258](../review/src/oc_review/publish.py)). The spec states this rule and its residual in "Publishing (code)", "Size limit and cut order" ([claude-review-design.md:594](claude-review-design.md)).

**What triggers it.** The never-cut data is over 64,000 characters: the heading, callout, checks strip, provenance, snapshot, reasons, waiver, override data, hard block evidence, coverage rows, model summaries, token usage, and the table rows, detail rows and bullets of high and critical findings. Within the per-pass caps (10, 10 and 15 findings, [verdict.py:63-64](../review/src/oc_review/verdict.py)), the bullets are the large part. A measurement at `03e1b8d` with 35 unverified critical findings, every field at its schema limit and every character one that escapes to 3 characters, gave 300,164 characters of blocks: 267,730 in the 35 bullets (about 7,650 each) and 32,434 in everything else.

**The caps do not bound the input.** A pass over its cap adds a not-waivable `pass-records` reason and still keeps every finding ([verdict.py:950-957](../review/src/oc_review/verdict.py), [verdict.py:50](../review/src/oc_review/verdict.py)). So 35 is the maximum for passes within their caps, not the maximum input of the publisher. Such a run fails at the gate in any case.

**What the user sees.** The sticky comment becomes the notice `## 🔴 FAIL: OC Claude review could not publish` with a `[!CAUTION]` callout, the computed gate result, the snapshot, a count per reason and the number of valid overrides ([publish.py:1854-1884](../review/src/oc_review/publish.py)). The required run fails, so the merge box blocks, also when the computed result was `pass`. A low or medium bullet that was cut shows only the truncation note; its explanation is in the run log only.

**Writes today.** The gate job may write only a `COMMENT` review, a new issue comment, and a PATCH of an issue comment ([publish.py:216-220](../review/src/oc_review/publish.py), [publish.py:270-277](../review/src/oc_review/publish.py)). Writes are never retried ([publish.py:229-230](../review/src/oc_review/publish.py)), and a write sends no precondition header, so a PATCH cannot be made conditional on the current body ([publish.py:278-284](../review/src/oc_review/publish.py)). A write can raise after GitHub accepted it, for example a timeout while the response is read ([publish.py:288-304](../review/src/oc_review/publish.py)). The order is inline review, summary, final check, exit code, with a snapshot check before each write ([publish.py:2194-2259](../review/src/oc_review/publish.py)). A snapshot check is three reads with a valid bundle (PR, base tip, compare) and one read without ([publish.py:550-567](../review/src/oc_review/publish.py)). Each read has a 30 second timeout and at most 2 retries on a 429, a 5xx or a network error ([collect.py:76-77](../review/src/oc_review/collect.py), [collect.py:240-268](../review/src/oc_review/collect.py)). The gate job has `contents: read`, `pull-requests: write`, `issues: write` and `actions: read`, no Anthropic credential and a 10-minute timeout ([claude-review.yml:228-237](../.github/workflows/claude-review.yml)). Runs on one PR are not serialized: the workflow has no `concurrency` ([claude-review.yml:8](../.github/workflows/claude-review.yml)).

**The comment read.** `read_override_inputs` reads every issue comment once and returns an empty tuple when the read fails ([publish.py:625-629](../review/src/oc_review/publish.py)). The caller cannot tell a failed read from a PR with no comments. Then `write_summary` finds no sticky and POSTs a new one ([publish.py:2096-2103](../review/src/oc_review/publish.py)).

## Design

### When continuation is used

The publisher renders the sticky as today. If the result fits with no cut of a finding bullet (no block of rank `CUT_UNVERIFIED` or `CUT_LOW_MEDIUM` is cut, and `_fit` does not return `None`), it posts no part. This is the normal case, and the sticky does not change.

Otherwise it moves **every** summary-only bullet out of the sticky into parts (decision Q3). All-or-nothing keeps the order of findings in one place and gives the same layout on each re-run.

What stays in the sticky: the findings table rows, the detail rows, the model summaries and all other never-cut data, each with its cut rank of today. At the largest sizes a low or medium table row or detail row can still be cut, with its truncation note. Its finding is still in full in a part. Dependency changes and signals keep their cut ranks and their run log note.

### Ownership: each part belongs to one run attempt

This is the rule that keeps a published set whole when runs overlap (review B, Important 1).

- A run writes its parts only with POST. Each part carries the marker of its owner: run ID, run attempt and part number. A run never PATCHes a part of another run that can still be linked.
- A part is **linked** when a sticky comment by the bot lists its ID in a hidden links marker. Each sticky lists the IDs of the parts of its own run.
- A part is **retired** (PATCHed to a fixed short body) only when both of these are true:
  1. A run status read shows its owner run attempt is done: the run is `completed`, or its `run_attempt` is higher than the part's attempt.
  2. A comment read made **after** that status read shows no bot sticky that links the part.
- Both conditions stay true once they are true. A done run attempt never writes again, and only that run attempt writes a sticky that links its parts. So a part that a current or future sticky links is never retired.
- There is no reuse of a comment of another run, also not of a retired one. A PATCH cannot be made conditional on the body that the run read ([publish.py:278-284](../review/src/oc_review/publish.py)), so two runs could PATCH one retired comment at the same time and one would lose its part. Snapshot checks do not prevent this: they guard the PR head and base, not comment contents.

With this rule, the race of review B Important 1 cannot happen:

```
 run A (attempt 1)                         run B (attempt 1)
 POST A.1, A.2                             POST B.1
                                           sticky := B, links B.1
                                           cleanup: A is in progress -> A.1, A.2 kept
 sticky := A, links A.1, A.2   (last writer wins)
 final check: A.1, A.2 read back intact
                                    later run C:
                                    A done, B done; the sticky links A.1, A.2
                                    -> retire B.1 only
```

On an empty PR, two runs each POST their own set. There is no shared slot, so there is no duplicate of a slot. The set that the last sticky does not link is complete text of a run that does not count, and its header says so. A later run retires it.

### Publish flow

```
 first comment read (existing, now with a complete flag)
   -> override inputs, sticky ID for the backlink, retire candidates (other runs' parts)
   |
   v
 compute_gate (unchanged)
   |
   v
 run status reads for the owners of the candidates (new, capped)
   |
   v
 inline review (unchanged)
   |
   v
 render sticky as today ------------------- fits, no finding bullet cut -----+
   |                                                                         |
   | a finding bullet would be cut, or _fit returns None                     |
   v                                                                         |
 move every summary-only bullet out; sort; pack into parts                   |
   |                                                                         |
   +-- parts > MAX_CONTINUATION, or the sticky still does not fit ---------+ |
   |                                                                       | |
   v                                                                       | |
 for part 1..K: deadline? -> snapshot check -> POST own part               | |
   |   stale -> write nothing more, exit 1                                 | |
   |   refused, no usable ID, or deadline passed -> stop, publish_error -+ | |
   v                                                                     | | |
 snapshot check -> sticky write (normal layout that links the K parts,   v v v
                   or the fail-closed notice; publication result recorded)
   |
   v
 final check (existing reads); the comment read also verifies every linked part
   |   a linked part missing or changed -> publish_error
   v
 sticky update, at most one (snapshot check first):
   pass -> fail at the final check, or verification failed
   publish_error set -> the notice with the final result; else the normal layout
   |
   v
 cleanup: retire candidates that are done and not linked
   (snapshot check before each PATCH; capped; errors never fail the run)
   |
   v
 exit code: 1 if publish_error, else verdict.exit_code(final)
```

Parts are written before the sticky (decision Q2), so the sticky links only parts that exist and states only what was written. On the first run of a PR that needs continuation, the parts appear above the sticky in the timeline.

### Publication result

The publisher records one value for the whole publication, so no later step can lose a failure (review B, Important 3):

```
 Publication
   part_ids:   IDs of the parts this run wrote, in order
   complete:   every part was written with a usable ID and verified
   error:      None, or one fixed case label (see "Past the bound")
```

- `publish_error` is set from `Publication.error` and is never cleared.
- Every sticky render after the first gets the `Publication`. When `error` is set, the render is the fail-closed notice with the current gate result (initial or final) and the case label. It is never the normal layout with part links. So a waiver revoked at the final check after a refused part write updates the notice, not a summary that links missing parts.
- The step summary line gets `publish_error` and the counts `parts_written`, `parts_verified` and `stale_parts_left`.

### Limits

| Value | Proposed | Why |
|---|---|---|
| Body limit per part | 64,000 characters, the same `SUMMARY_LIMIT` as the sticky | GitHub rejects bodies over 65,536 characters. The same margin as the sticky. The test measures each final rendered part, with markers, header and footer. |
| Header and footer reserve | 1,000 characters | The header line, the run and sticky links and the untrusted-text note are fixed text plus integers. |
| Bullets per part | No count limit. Greedy packing by size, a bullet is never split | At the per-pass caps, a bullet with its `oc-continued:` marker is about 7,800 characters, so 8 fit in 63,000. |
| `MAX_CONTINUATION` (active parts per run) | 6, provisional (decision Q6) | Within the per-pass caps: 35 bullets at 8 per part is 5 parts, plus one spare. Past the caps the run already fails at the gate, and too many parts fail closed (case 1). |
| Part writes per run | At most `MAX_CONTINUATION` POSTs | One write per part. No retry. |
| Retire writes per run | At most 12 PATCHes, for parts of at most 6 owner run attempts | Bounds the cleanup. The rest waits for a later run (see "Read and write outcomes"). |
| Run status reads per run | At most 6, one per owner run attempt | `GET .../actions/runs/{id}`, oldest owner first. |
| Sticky writes | Unchanged: one write and at most one update | The verification failure uses the same single update as a pass to fail change. |
| Continuation time budget | 180 seconds for the part writes, then what is left of 60 seconds for cleanup | No request or retry starts after the deadline, and each request's timeout is the smaller of 30 seconds and the time left, as in the registry lookup budget ([collect.py:88-90](../review/src/oc_review/collect.py), [collect.py:656-671](../review/src/oc_review/collect.py)). Together 4 minutes, well under the 10-minute job timeout. |

**Request count.** With a valid bundle, each snapshot check is 3 reads. The new writes are at most 6 part POSTs and 12 retire PATCHes, so at most 18 writes and 54 snapshot reads, plus at most 6 run status reads: 78 new requests per run before transport retries. At 30 seconds per request and up to 3 attempts per read, that worst case is far over the job timeout. The time budget is what bounds it: past the deadline a missing part fails the run (case 4) and the cleanup stops. A failed snapshot read stays fail-closed: the run writes nothing more and exits 1.

**Historical comments.** Six is a bound on the active parts of one run, not on all part comments of a PR. Each run attempt that uses continuation POSTs up to 6 new comments. Retired comments stay on the PR with a short body (no DELETE, decision Q1). In sequential runs, at most two sets have full text at one time: the set that the sticky links and the set of the run before it, which the next cleanup retires. Overlapping runs, cleanup exhaustion and failed reads can leave more full sets for a time, each labeled with its run.

**Order.** Parts hold one bullet per summary-only finding, in this order (review B, Minor 1):

1. severity: critical, high, medium, low;
2. verified before unverified (the finding's own flag);
3. shown file, then line, then side (head before base);
4. pass order: review, security, supply-chain;
5. full key, so the order is total.

Severity has priority over the table's row order. The table sorts merged rows by their highest severity and whether every member is unverified ([publish.py:1182-1193](../review/src/oc_review/publish.py)), and orders members by pass before severity ([publish.py:1114-1118](../review/src/oc_review/publish.py)). So the members of one merged row can be in different parts: a critical member in part 1 and a low member in part 3. Part 1 always holds the worst findings.

### Past the bound

The publisher never drops a finding silently. It fails closed, as today, in each of these cases. Each case has a fixed label in the notice and in the step summary.

1. **Too many parts.** The bullets need more than `MAX_CONTINUATION` parts. No part is written.
2. **Sticky still too long.** The sticky is over the limit after every bullet moved out (for example, a very long list of coverage rows or hard block evidence, which this plan does not move, decision Q4). No part is written.
3. **Part write refused.** A part write raised `WriteError`, or its response had no usable comment ID. This includes a POST that GitHub accepted but whose response was lost ([publish.py:288-304](../review/src/oc_review/publish.py)). That comment is owned by this run attempt and no sticky links it, so a later run retires it. No more part writes.
4. **Time budget.** The deadline passed before every part was written. No more part writes.
5. **Part changed during the run.** The final-check comment read shows a linked part missing, not by the bot, or with a body other than the body written (line endings compared as `\n`).

In cases 1 to 4 the sticky write is the notice of [publish.py:1854-1884](../review/src/oc_review/publish.py), with the case label. In case 5 the sticky is already written, so the one sticky update writes the notice (best effort; the exit code is 1 whatever that write does). In every case the full redacted record goes to the gate job log, `publish_error` is set and the job exits 1. A gate reason is never cleared by any of this.

So the existing `overflow` path in `render_summary` and `publish` stays. What changes is only that findings overflow goes to continuation first.

### Read and write outcomes

Each outcome is defined, so no failure reads as an empty PR (review B, Important 2). The first comment read gets a `complete` flag, as `Timeline` and `RunList` have today ([verdict.py:291-292](../review/src/oc_review/verdict.py), [publish.py:642-659](../review/src/oc_review/publish.py)); the override inputs keep using the same comments.

| Event | What the publisher does | Fails publication? |
|---|---|---|
| First comment read complete, no bot part or sticky | POST every part. Backlink to the PR page. No retire candidate. | No |
| First comment read failed or incomplete (page error, bad Link header, 429 after retries) | POST every part (a POST only creates own comments). Retire nothing in this run. Backlink to the PR page. The sticky write POSTs a new sticky, as today ([publish.py:2096-2103](../review/src/oc_review/publish.py)); a part linked by any bot sticky is kept, so a second sticky protects its parts too. | No |
| Run status read failed (any error after retries) | That owner run counts as not done. None of its parts is retired. | No |
| Final-check comment read failed or incomplete | Verification cannot run. The parts were written with confirmed IDs, so publication stays complete; the step summary records `parts_verified: unknown`. Retire nothing. | No |
| A linked part missing or changed at the final check | Case 5. | Yes |
| Part write refused, 429 or 5xx (writes are not retried), no usable ID, or response lost | Case 3. | Yes |
| More retire candidates than 12 writes or 6 owner runs (cleanup exhaustion) | Retire oldest first up to the caps. Leave the rest for a later run. | No |
| Retire write refused, or its response lost | Stop the cleanup for this run. A lost response leaves the comment retired or not; a later run sees which. | No |
| Deadline passes during the cleanup | Stop the cleanup. | No |

**Stale parts that stay.** The sticky does not list parts that the cleanup left: the sticky is written before the cleanup, and a sticky update only for cleanup would be one more write per run. Each part is self-describing instead. Its header names its run and attempt and says that the summary comment holds the current review and that a part of another run is out of date. The step summary line has `stale_parts_left`. A stale part never affects the gate.

### Comment layout

```
 <!-- oc-claude-review-continuation:<run id>:<attempt>:<i> -->   owner marker, first line
 ### OC Claude review: findings in full, part <i> of <K>, run <run id> attempt <n>
 <sub>Run [<run id>, attempt <n>](run URL). The current result is in the [summary comment](link).
      A part of another run than the one the summary names is out of date.
      The required workflow in the merge box is the result that counts. This bot never approves a PR.</sub>
 > **Model output from untrusted input. Check it before you act on it.** Verified means ...
 <!-- oc-continued:<d14 key> <full key> -->                       one per bullet
 - <the bullet, exactly as _finding_block renders it today>
 ...
```

Retired body:

```
 <!-- oc-claude-review-continuation:retired -->
 This part is no longer used. The summary comment holds the current review.
```

In the sticky, one new hidden line after the sticky marker:

```
 <!-- oc-claude-review-parts:<run id>:<attempt>:<id>,<id>,... -->    the parts this sticky links
```

- The owner and parts markers use fixed prefixes and integers only. The regex accepts only that form. Neither contains the sticky marker `<!-- oc-claude-review -->` as a substring, because `find_sticky_comment` matches by substring ([verdict.py:756-763](../review/src/oc_review/verdict.py)). A unit test holds this.
- Each bullet has the two keys of `finding_keys` ([publish.py:685-693](../review/src/oc_review/publish.py)) in the inline-marker shape, under the prefix `oc-continued:` and not `oc-finding:`. So `_FINDING_KEY_RE` ([publish.py:666](../review/src/oc_review/publish.py)) never matches it. That regex reads only review comments ([publish.py:718-742](../review/src/oc_review/publish.py)), and parts are issue comments, so there are two separate guards.
- The bullet text has no gate-dependent words: no Effect column, no waiver text, no result. So a final check that turns `pass` into `fail` ([publish.py:2232-2246](../review/src/oc_review/publish.py)) needs no part update.
- **Backlink (review B, Minor 4).** The part body is fixed before the sticky write and is never PATCHed later. When the first comment read found a sticky (`find_sticky_comment`), the link is that comment's `#issuecomment-<id>` anchor. When it found none (the first run, or a failed read), the link is the PR conversation page. The sticky is PATCHed in place on later runs, so from the second run on the anchor is stable. This costs no write.
- The run link, the backlink and the part links in the sticky are built from trusted values only (server URL, repository, PR number, run ID, comment ID), as for the override links today.

In the sticky:

- The findings table pointer of a row with summary-only members reads "Details are in part i." with a link, in place of "Details are in the record." A merged row whose summary-only members are in more than one part lists each part once, in part order: "Details are in parts 1 and 3." (decision Q3).
- In the record, "Findings with no inline comment, in full:" becomes one fixed line: "N findings with no inline comment are shown in full in K continuation comments:" and the K links.

### Re-runs and duplicates

- **Re-run.** A new run or a new attempt POSTs a new set and its sticky links only that set. The older set is retired by the cleanup of this run or a later one, when it is done and not linked. A re-run makes no second **linked** set: one sticky links one set.
- **No delete.** The plan adds no DELETE route. The write allowlist stays at three routes ([publish.py:216-220](../review/src/oc_review/publish.py)). See decision Q1.
- **No content trust.** The publisher reads a part only for its owner marker, its ID, its author and (for own parts at the final check) its body. It never reads findings, keys or text from a part for a decision. Any Actions workflow in the repo can write as `github-actions[bot]`, so a forged part is at most retired. A forged sticky that links a part only keeps that part from retirement. This is the same rule as for the sticky.
- **Limits.** A person who can edit other people's comments, or another Actions workflow, can edit or delete a part. During the run, the final-check verification catches this (case 5). After the gate job ends, nothing reconciles it: the sticky can link a part with other text or no part. The gate does not change, the full redacted record of the run is in the gate job log, and a re-run publishes a new set. The spec states this residual next to "Summary writes" ([claude-review-design.md:540](claude-review-design.md)).

### Security

- **Same escaping and redaction.** A part holds only bullets from `_finding_block`, which uses `_esc` and `escape_text` for every untrusted string ([publish.py:157-205](../review/src/oc_review/publish.py)): control characters removed, credentials redacted before any cut, pings, links and commit references broken, Markdown punctuation escaped. The fixed header text and the markers hold integers and fixed text only. No new escaping code.
- **Only the write job posts.** The parts are written by the gate job `oc-claude-review`, which has no Anthropic credential and no `id-token` ([claude-review.yml:228-237](../.github/workflows/claude-review.yml)). Analyze does not change.
- **Permissions unchanged.** `POST .../issues/{n}/comments` and `PATCH .../issues/comments/{id}` are already allowed. The run status read is a GET under the existing `actions: read`. No new write route, no new scope, no workflow change.
- **PATCH only own comments.** The PATCH route accepts any comment ID. A token with `issues: write` may be able to edit comments by other people, for example an override comment. So the build adds a code guard: a PATCH target must be the sticky that this run read as a bot comment with the sticky marker or wrote itself, or a part that passed the retire rule in this run. Any other ID is refused before the call. A unit test holds this.
- **Override parsing is not affected.** Override comments from bots are ignored, and a part holds only escaped text, so it cannot hold a valid override line.
- **Never a review verdict.** Parts are issue comments. The bot still never approves, requests changes, merges, closes, labels or edits the PR.

### Gate interaction

- Continuation runs after `compute_gate` and reads the frozen `GateResult` only. It never changes a reason, a finding, an override or the gate status.
- The exit code stays `1` when `publish_error` is set, else `verdict.exit_code(final)` ([publish.py:2253-2259](../review/src/oc_review/publish.py)). The only change: findings overflow no longer sets `publish_error` when every summary-only finding is published in full in the sticky or in verified parts. That is not a gate reason and no override applies to it, so no gate verdict changes. A failed run caused by a gate reason stays failed.
- A missing, refused or changed part can only make the run fail. Nothing in a part is read back for a decision. Cleanup outcomes never change the exit code.
- The rule "only code lowers risk" holds: the decision to post parts is code, and Claude output cannot clear anything through it.

## Test plan

Unit tests, no network, with the fake GitHub of `test_publish.py`. The fake gains run status, comment IDs in creation order and a fake clock.

- **Normal case unchanged.** Every existing summary test renders the same body. No part is written when nothing would be cut.
- **Bound within the caps.** 35 findings at every schema limit, with characters that escape to 3 characters, need at most `MAX_CONTINUATION - 1` parts. Each **final rendered** part, with its owner marker, header, `oc-continued:` markers and footer, is at most 64,000 characters. The sticky with the parts marker and K links fits too. The test reads the caps from `PASS_MAX_FINDINGS` and `LIMITS`, so a cap change that breaks the bound fails it.
- **Over-limit pass.** A schema-valid review pass with 11 findings at every limit: the gate fails for `pass-records` (not waivable), the run exits 1, and the full redacted record is in the job log, whether the parts fit or case 1 applies.
- **Completeness.** For many sizes and mixes, the set of full keys of summary-only findings equals the set of `oc-continued:` keys across the parts, each once.
- **Order.** The order across parts follows the five keys in "Order". A merged row with a critical and a low summary-only member: the critical bullet is in part 1, the low one in a later part, and the row pointer names both parts.
- **Never split.** No bullet spans two parts.
- **Past the bound.** Cases 1 and 2 with a test-only lower limit: no part is written, the sticky is the notice with the case label, the exit is 1.
- **Refused part write.** A 4xx, a 5xx and a 429 on part 2: no more part writes, the sticky is the notice, `publish_error` is set, exit 1.
- **Lost response.** The fake stores part 2, then the transport raises: case 3, exit 1. A later run (owner done, not linked) retires that part.
- **Time budget.** The fake clock passes the deadline before part 3: case 4. In the cleanup: the cleanup stops, the exit code is the gate's. No request starts after a deadline.
- **Stale.** A snapshot change before part 2: nothing more is written, exit 1, step summary has `stale`.
- **Two publishers interleaved.** Two runs A and B with K = 2 each (test-only limit) on one fake. The test runs every interleaving of their steps (reads, POSTs, sticky writes, cleanup), on an empty PR and on a PR with an older done set. Invariant at the end of every interleaving: every part that a bot sticky links has the body its run wrote, and no part of a run that is not done was retired. A third run C then retires every set that no sticky links.
- **Changed part.** A human edit and a delete of a linked part before the final check: case 5, the sticky update is the notice, exit 1.
- **Combined final update.** A refused part write plus a waiver revoked at the final check: the sticky update is the notice with the final result, not a body with part links. Case 1 plus a newer run at the final check: the notice with the final result. Case 5 plus a pass to fail change: one sticky update, the notice.
- **Read outcomes.** A failed first comment read and a pagination failure: every part is POSTed, nothing is retired, the backlink is the PR page. A failed run status read: that owner's parts are kept. A failed final-check comment read: no case 5, nothing retired, `parts_verified: unknown`.
- **Cleanup bounds.** 13 retire candidates: 12 retired oldest first, `stale_parts_left: 1`, no failure. Candidates of 7 owner runs: 6 status reads. A refused retire write: the cleanup stops, no failure.
- **Retire rule.** A part of an in-progress run is never retired. A part that any bot sticky links is never retired. A part of attempt 1 is retired when attempt 2 is running and no sticky links it.
- **First-run backlink.** No bot comment at the start: each part links the PR page, and no part is PATCHed later.
- **PATCH guard.** A PATCH to an ID that is not the own sticky or a part that passed the retire rule is refused before the call.
- **Markers.** No owner, retired or parts marker contains the sticky marker. `_FINDING_KEY_RE` never matches a part. `find_sticky_comment` never picks a part. An untrusted field that holds a marker string (in every field) is escaped, so it cannot make a marker. A part marker by another author is ignored. A bot-authored forged part is at most retired.
- **Escaping.** The existing escaping tests run on a part body: a finding that quotes a credential, an `@` mention, a link, a commit SHA, HTML and an override line.
- **Gate truth.** For every case of the gate matrix, the gate status and reasons are the same with continuation used and not used. The exit code differs only in the findings-overflow case, from 1 to `verdict.exit_code(final)`.
- **Request count.** No run makes more than 6 part writes, 12 retire writes, 2 sticky writes and 6 run status reads, and each write follows a snapshot check.

**Eval impact.** Continuation is code only. No model behavior changes, so no new live fixture case is needed. Two changes to the eval runner:

- It renders the parts too, to `<out-dir>/<case>/continuation-<i>.md`, when a case needs them.
- `summary_excludes` checks the sticky and every part, so a credential cannot leave through a part without a failed case.

Add one offline case under `review/tests/unit/fixtures/` (like `eval-smoke`) with fake pass records that force continuation. It runs in the unit tests, not in the live set. The release eval of the candidate still runs as in "Each release", because the candidate changes code.

**Live check before release.** The model does not return enough long findings on demand, and the pilot may not show a natural continuation before the release. So the release adds one scripted publisher check on claude-review-test, run by the owner as part of the owner-approved release steps: the candidate gate job publishes the offline case's pass records with a test-only `MAX_CONTINUATION` of 2, (a) twice in a row, (b) twice at the same time, (c) once with case 1. The records show the parts, the links, the retirement of the older set and the notice. One normal run must also show the same sticky as before (no regression).

## Rollout

Two PRs, then one release.

1. **PR 1, pure functions.** Pack, sort, render a part body, the markers and their parsers, the retire rule as a pure function of (parts, run states, stickies), the `Publication` value, and their tests (bound, over-limit, order, completeness, retire rule). Not wired into `publish`. The fail-closed path is unchanged and is the only path.
2. **PR 2, wire it.** The `complete` flag on the comment read, run status reads, part writes with a snapshot check before each, the time budget, verification, the single sticky update with `Publication`, the cleanup, the PATCH guard, the sticky pointers, the eval runner changes and the offline case. Update the spec in the same PR (list below). In this PR, findings overflow stops failing the run, and only after the interleaving, combined final update and read outcome tests pass. The fail-closed check is not removed: it stays for the five cases in "Past the bound".
3. **Release.** The first release after M4. It ships as in "Each release" in the build plan: new federation rule, unit tests, the owner-approved release eval, the live publisher check above, the scratch test ruleset run, pin moves and read-backs.

The findings-overflow use of the fail-closed check goes away only in PR 2, after PR 1 and PR 2 tests pass, and in production only when the pin moves to that release. The check itself stays.

Spec sections to change in PR 2:

- "Architecture" diagram: "post inline comments (event: COMMENT), then the sticky summary" adds the parts between them and the cleanup after the final check.
- "Threat model", the exfiltration row: the publisher escapes text in the summary and in parts.
- "Publishing (code)": "Summary comment" (the parts marker, the part pointers in the table and the record), "Size limit and cut order" (continuation first, `MAX_CONTINUATION`, the five fail-closed cases; remove the residual that a low or medium explanation can be cut and that capacity fails a `pass`), "Full record" (also printed when parts are used), "Order of writes" (inline, parts, summary, final check with verification, at most one summary update, cleanup; PATCH only own comments; the time budget), "Refused summary write" (also a refused, lost, late or changed part).
- "Which run counts", "Summary writes": parts belong to one run attempt, are never a trust source, and are retired only when done and not linked; the residual of edits after the run.
- "Testing": the new unit tests, the eval runner changes and the live publisher check.
- "Decision log": a new line for this change and decisions Q1 to Q7.
- [docs/build-plan.md](build-plan.md) phase 4: mark the item done.
- The `publish.py` module docstring: the write order.

## Decisions

The owner accepted the recommended answer to each open question (2026-10-28). Review B's corrections are folded in.

- **Q1. PATCH stale parts to a retired body, no DELETE.** A DELETE route could delete an override comment if a bug picks the wrong ID; the allowlist stays at three routes, and the PATCH guard is required. Correction: retired comments are not bounded by six (see "Historical comments"), and cleanup exhaustion is defined. In-place reuse of another run's comment is dropped, because a PATCH cannot check the body it replaces (Important 1); retiring stays.
- **Q2. Parts before the sticky.** The sticky can then link parts that exist, by IDs from the POST responses. The first-run backlink is the PR page, and the complete-publication rule is the ownership rule plus verification.
- **Q3. Move every summary-only bullet.** Completeness and a stable order are easier to check. A merged row whose members are in more than one part names each part.
- **Q4. Other never-cut data stays in the sticky.** The build plan item is about findings. Overflow of that data stays fail-closed (case 2), and the full redacted record stays in the job log.
- **Q5. A snapshot check before each write.** The spec requires it ([claude-review-design.md:597](claude-review-design.md)). Correction: it is three reads per check with a valid bundle, and it does not protect comment contents from another writer; the ownership rule does that.
- **Q6. `MAX_CONTINUATION` = 6, provisional.** Within the per-pass caps the worst case is 5 parts. The test measures final rendered parts; an over-limit pass falls to case 1 and fails at the gate anyway. Six bounds active parts per run, not historical comments.
- **Q7. A refused required part fails the run.** Missing full findings must never count as a complete publication. `Publication` keeps the failure through the final update. Retirement errors never fail the run (see "Read and write outcomes").
