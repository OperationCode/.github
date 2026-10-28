# Claude PR Review: Build Plan

This plan turns the [design spec](claude-review-design.md) into work items. The spec is the source of truth. If the plan and the spec differ, the spec wins, and the plan gets fixed in the same PR.

Items marked "Owner:" need an org owner or the owner of the Anthropic account. "V" numbers are items in the spec's [Verify before building](claude-review-design.md#verify-before-building) list. "T" numbers are test rounds in [claude-review-test](https://github.com/OperationCode/claude-review-test).

## Goal

Every PR to a supported OperationCode repo gets the three-pass Claude review, and an org ruleset requires the central workflow at a pinned SHA before a merge.

Done when:

- [ ] The central workflow runs on every supported repo, from `OperationCode/.github` at a pinned SHA.
- [ ] A failed run blocks the merge. Only org admins can bypass, through a pull request.
- [ ] Every rule in the [CLAUDE.md](../CLAUDE.md) holds, and the unit tests check the ones that code can check.
- [ ] The owner has accepted the residuals in writing (spec "Which run counts").

## Phases

```
 0 platform tests ──> 1 build ──> 2 fixture evals ──> 3 smoke test ──> 4 pilot
   (build V items)    (this repo)   (live API, owner)   (claude-review-   (pilot ruleset,
                                                         test, fork PR)    bypass on)
                                                                              │
                         6 org-wide enforcement <── 5 before org-wide <───────┘
                           (org ruleset on,           (ruleset fixes,
                            bypass: org admins)        risk acceptance, re-tests)

 Gate on each arrow: the exit criteria of the phase before it.
 Exception: 1a may start in parallel with phase 0 (see phase 1a).
 V6 fails (an older run decides)  -> stop, change the gate design.
 V2 or V3 fails (no federation)   -> stop, change the auth design.
```

There is one build of the central workflow. Its gate job fails for real when the result is `fail`. The pilot and org-wide enforcement differ only in who can merge past a failed run (spec "Pilot and enforcement"). The pilot does not protect merges: a maintainer or repo admin can merge past any failed run, also on their own PR. Each pilot repo needs its own approval protection.

## Phase 0: platform tests that block the build

Use [claude-review-test](https://github.com/OperationCode/claude-review-test) as the target and a scratch source repo for the workflow. Only one ruleset requires the workflow on claude-review-test at a time. Record each result in the spec, in the same PR as any design change it causes.

Tasks:

- [ ] V6, first: which run counts when one head SHA has several runs. Cases (a) to (g). Use a scratch-only gate job that can pause after its final check.
  - Note for the open V6 rounds, such as (f) run deletion: the V6 kit `0ec8b86` in the scratch source repo always does the token exchange, and the test federation rule now names the V10 kit `df8ff51`. So a V6 run at `0ec8b86` fails in analyze, and the gate fails on it (not waivable). Use a kit variant without the exchange (`0ec8b86` with `P0_FEDERATION_RULE_ID` empty, and the ruleset pinned to it), or set the test rule back to `0ec8b86` in the Console.
- [x] V2: a fork PR run prints its decoded OIDC claims (never the token).
- [x] V3: check the intended federation rule against the WIF reference, record the final rule text in the spec, then test it on a test workspace.
- [x] V5: one Messages API request with a mid-conversation system message, structured output and server-side fallback.
- [x] V9: spend limit behavior on a test workspace with a very small limit.
- [x] V13: dependency review on a fork PR with no checkout and SHA refs.
- [x] V16: push epoch events on a fork PR.
- [x] V18: fork head trees and blobs through the base repo's git API.
- [x] V24: run list by head SHA from the gate job's token, and its delay.
- [x] V4: a Dependabot PR mints an OIDC token in a ruleset-required run. A stub analyze job is enough.

Owner:

- [x] Owner: create a scratch source repo in the org for the V tests, separate from claude-review-test ([claude-review-p0-source](https://github.com/OperationCode/claude-review-p0-source)).
- [ ] Owner: Anthropic Console: a dedicated workspace with a hard monthly spend limit and a service account. Create the production federation rule as in spec "Auth and cost": pattern mode, subject prefix `repo:OperationCode@10479364/*`, scope `workspace:developer`, the review workspace only, and the placeholder SHA `0000000000000000000000000000000000000000` in `job_workflow_ref`. Read it back; if the Console rejects the placeholder, stop and resolve the order of rule ID and SHA first (spec V26 a). Its ID goes into the central code; phase 3 sets the candidate SHA. No API key. Done 2026-10-27: workspace `claude-review`, service account `claude-review`, rule R1 `claude-review-prod-r1` created; the Console accepted the placeholder SHA (V26 a partial). The owner read R1 back at M1 and R2 at M2 on 2026-10-27 (spec P3-6). Still open: the service account and the workspace were not read back.
- [ ] Owner: the test workspace (reused for evals, spec P2-1), and a federation rule for `workflow_dispatch` runs in `OperationCode/.github` whose job uses the environment `eval`: pattern mode, the same subject prefix, exact claims `repository_owner_id`, `repository_id`, `event_name` and `environment`, scope `workspace:developer`, that workspace only (spec "Auth and cost"). Its IDs are in `evals.py`. The rule cannot name `eval.yml`: any `.github` workflow that uses `eval` can match, so the owner's approval and the workflow unit test (1c) hold it to `eval.yml`. Test it as in spec V27 before phase 2.
- [ ] Owner: on `.github`, create the GitHub environment `eval`: the owner is a required reviewer for every run, and any branch may deploy to it. "Prevent self-review" is off temporarily (owner, 2026-10-26), so that the coordinator, which runs with the owner's token, can approve eval runs it started from reviewed branches; the owner turns it on again in phase 5. Admin bypass stays on. During phase 2 the coordinator's approval stands in for the owner's under the owner's delegation. Before approving a run, check the run that waits for approval: the workflow file and commit it runs, every job in it that uses `eval`, and their effective permissions (no GitHub write). Also check that the PR does not change `eval.yml`, any other workflow file, the eval code, the prompts, the fixtures or the federation setup in a harmful way, and that `test.yml` passed. The approval is the control; the residual risk is an approver who approves without reading. Exception to the no-execute rule (K-4): evals of PRs to this repo may run that PR's code, only after an owner approves the `eval` environment run. Needed before phase 2.
- [x] Owner: a test workspace with a very small spend limit for V9.
- [ ] Owner: the test org ruleset for V6 that targets only claude-review-test.
- [ ] Owner: a Dependabot PR in claude-review-test for V4.

Exit criteria:

- [x] V6 shows that the newest run on the head SHA (among runs at the pinned SHA, see spec P3-3) decides. If not, building stops. (The queued cell is still open.)
- [x] V2 and V3 pass. If not, building stops.
- [x] V4, V5, V9, V13, V16, V18 and V24 have results in the spec. A fallback in the spec covers each one that failed.

## Phase 1: build in this repo

Python lives in `review/`, managed with `uv`. Unit tests make no network or API calls: `cd review && uv run pytest tests/unit`. Never check out, install, build or execute PR content.

### 1a. Code that does not depend on the gate

1a may start in parallel with phase 0. It merges to main only after phase 0 exits. Any V result that changes 1a code is fixed before 1b starts. Each task comes with its unit tests.

- [ ] `review/` project: `pyproject.toml`, `uv.lock` with hashes, `tests/unit/`.
- [ ] `schema/findings.schema.json` and `schema/envelope.schema.json`, with good and bad fixtures.
- [ ] `envelope.py`: envelope schema, digest check, file count and size caps.
- [ ] `snapshot.py`: comparison pair, tree diff by path, blob SHA and mode, stale checks.
- [ ] `prefilter.py`: every row of the spec's prefilter table, and the coverage rules.
- [ ] `deps.py`: one parser per supported file family, with fixtures for each supported version. Registry lookups on fixed routes only, with byte caps and timeouts.
- [ ] `collect.py`: GitHub REST reads into the bundle envelope. Tests use recorded responses, no network. Depends on V18 (fork objects through the base repo).
- [ ] `render.py`: bundle to prompt text with nonce delimiters and redaction. Test that the rendered text cannot contain `untrusted_pr_{nonce}`.
- [ ] Prompts: `system.md`, `review.md`, `security.md`, `supply-chain.md`. A unit test fails if any prompt file loses its `<grounding_rules>` block.
- [ ] `verdict.py`: citation check, inline eligibility, gate reasons, override checks. The full gate matrix from the spec's "Testing" section. The push epoch includes `reopened` (V16, spec K-12).
- [ ] Sanitizer and escaping for every untrusted string that the publisher posts.

Depends on: none for most tasks; V18 for `collect.py`, V16 for the push epoch in `verdict.py`.

### 1b. Analyze and publish

- [x] `analyze.py`: one Messages API call per pass, no tools, the model set per pass in code (`claude-sonnet-5-5` on every pass, see spec P3-4), explicit `effort` and `max_tokens`, structured output with the stripped schema and a full schema check in code (V5), fallback, at most 2 retries, a request deadline, stale check before the calls. The spend limit error (HTTP 400 `invalid_request_error`, "workspace API usage limits") is an outage with its own clear reason, not a request bug (V9). Always writes exactly three pass records, and exits 0 when it wrote them. The pass record has the optional `meta` field (reason, model, stop reason, schema digest, token usage). Federation goes through the SDK's `WorkloadIdentityCredentials`; placeholder IDs make it refuse to call, and the `release`-marked test (`pytest -m release`) fails on them; phase 3 set the production IDs. Tests use a fake client.
- [x] `publish.py`: escaping, inline `COMMENT` review, sticky summary, final check, exit code (0 only for `pass`). It never approves, requests changes, merges, closes, labels or edits the PR (spec decision K-1). A summary over the comment limit is cut in the spec's order, or fails closed with the full record in the gate job log. The summary shows token counts, no currency.

Depends on: V3, V5, V9 (analyze); V6, V16, V24 (publish).

### 1c. Central workflow

- [ ] `.github/workflows/claude-review.yml`: `pull_request_target` only, `permissions: {}` at the top, per-job scopes as in the spec, no job `if:` except `always()` on the gate job (the gate job's download steps carry the non-empty id guard, below), no concurrency group, no `continue-on-error`, every action pinned by full commit SHA, checkout of `OperationCode/.github` at `job.workflow_sha`.
- [ ] The analyze job is the only job with `id-token: write`. The gate job has no Anthropic credential. The analyze job sets `JOB_WORKFLOW_SHA: ${{ job.workflow_sha }}`, passes `GITHUB_TOKEN` and `RUNNER_TEMP`, and runs `python -m oc_review.analyze --bundle-dir ... --bundle-digest ... --out-dir ...`. The gate job has `contents: read` (spec D9), `pull-requests: write`, `issues: write` and `actions: read`.
- [ ] The dependency-review job exports the step outcome as the job output named `outcome` (`publish.py` reads `needs.dependency-review.outputs.outcome`, and `DEPENDENCY_REVIEW_OUTCOME` if the workflow sets it; the two must agree).
- [ ] Guard every artifact download in the gate job with an explicit non-empty id check (D10). An empty `artifact-ids` makes `actions/download-artifact` fetch every artifact of the run. When analyze failed, its ids are empty, and `publish.py` must find a missing directory and fail with the `artifact` reason while it still posts the summary.
- [ ] A unit test parses the workflow: no `continue-on-error`, the dependency-review job exports the step `outcome`, every `uses:` is a full SHA.
- [ ] `.github/workflows/test.yml`: unit tests on PRs to this repo (`pull_request`, no path filter) and on pushes to `main`. The job is `unit-tests`, with `contents: read`, no `id-token`, no environment and no secrets, so it runs a PR's code with a read-only token (the no-execute rule covers the review workflow). From phase 3 the job has a second step, `pytest tests/unit -m release`, so the check name does not change.
- [ ] Every workflow job starts with harden-runner and has `timeout-minutes`. Actions are pinned to the newest release at least 7 days old, except `setup-uv` v10.3.2 (spec K-15). Python is the runner image's 3.12, and `setup-uv` has an exact version and checksum, with its cache and the Astral mirror off. Artifact names carry the run attempt.
- [ ] `.github/workflows/eval.yml`: manual fixture evals. The job uses `environment: eval` and has `contents: read` and `id-token: write` only. A workflow unit test reads every workflow file and fails if a workflow other than `eval.yml` uses `environment: eval`, or if a job that uses `eval` sets no explicit job-level `permissions` or has any `write` permission other than `id-token: write`. Job-level `permissions` is required even if the workflow level sets it. `write-all` at either level fails the test, and so do `read-all` and a missing job-level block, because the job must state `contents: read` and `id-token: write` itself.
- [ ] `review/src/oc_review/evals.py`: the runner that `eval.yml` calls (`python -m oc_review.evals --fixtures-dir ... --out-dir ...`), with placeholder eval federation IDs and one smoke fixture. The phase 2 fixtures and IDs come later. `analyze` takes an optional federation IDs parameter for it.
- [ ] Prefilter run budget: the prefilter line diff has a budget of 40,000,000 steps per run next to its 2,000,000 per file (spec "Coverage limits").
- [x] V10: harden-runner in audit mode for a full run, then block mode (`disable-telemetry: true`) with the measured allowlist. Done 2026-10-27 (spec V10): block mode passed, but 2 of 24 block-mode jobs hung in "Complete job" (the symptoms match open harden-runner issue 708). Ruling K-14: every job runs in audit mode with its measured list and no `disable-sudo-and-containers`; the `release`-marked test holds the central lists to the V10 lists. The `test.yml` and `eval.yml` lists are not measured (phase 5).

Depends on: V2, V4, V13, V18 (workflow); V10 needs a full run, so it runs here.

Owner:

- [ ] Owner: confirm the protection of `.github` main: CODEOWNERS review, 1 approval, no force push, no deletion, org admin bypass through a pull request only.
- [ ] Owner: on `.github` main, turn on dismiss stale approvals on push, and require the `test.yml` check (the job `unit-tests`, only after it has reported once).
- [ ] Owner: org Actions setting, default `GITHUB_TOKEN` permissions read-only.

Exit criteria:

- [ ] Unit tests pass in CI on `.github`.
- [x] A full run in claude-review-test succeeds with egress in block mode (V10). Done 2026-10-27 with the test federation rule: a clean PR passed and a vulnerable one failed in block mode; 2 of 24 jobs hung; the K3 failed run passed on a re-run. The workflows ship in audit mode (spec K-14).
- [ ] Each change was reviewed through a PR with code owner approval.

## Phase 2: fixture evals

The fixture eval calls the live API and costs money. The owner runs it on request only. It is the one exception to the no-execute rule: it may run a PR's code, only after an owner approves the `eval` environment run (K-4).

- [x] V27, before the first eval (passed 2026-10-27, throwaway branch `v27-probe`, never merged; Console deny reasons read by the owner on 2026-10-27: `match_claim_absent` for N1 and the no-environment job of the rejected-approval run, `match_claim_value_mismatch` for the no-environment job of the push run, N3 and N4; claim name and P1 scope not shown in the list view, so P1 scope not confirmed): test the eval federation rule (an approved `eval.yml` run gets a token; the deny cases in the spec get none, including the other-repo case, spec P2-2; it ran as the substitute N4, `push` in claude-review-test with no environment, 401, so repository isolation is not tested separately).
- [x] Real eval federation IDs in `evals.py`, checked by a unit test against the production placeholders (spec P2-1).
- [x] Eval runner: expectation format v2 and the rendered summary per case (spec "Testing", P2-5).
- [x] Fixture builder `review/tests/eval_fixtures.py` and the 13 cases of the spec's minimum set in `review/tests/fixtures`, with expected outcomes. Unit tests: each bundle equals a rebuild, and each hard-block case fails the gate whatever Claude returns.
- [x] Move the smoke case to `review/tests/unit/fixtures/eval-smoke`, out of the live run (spec P2-3).
- [x] Owner: run `eval.yml` on the PR branch and approve the `eval` environment, with the eval federation rule and the test workspace (reused for evals) from phase 0. Check the PR first (see phase 0). Record the results in the PR that changed the prompts or code. Done 2026-10-27: [run 40445885087](https://github.com/OperationCode/.github/actions/runs/40445885087), commit 3a03ae8, run by the coordinator under the owner's delegation and approved in the `eval` environment; 13 of 13 cases matched with every pass ok, 207890 input and 20729 output tokens. Passing evals gate the merge of a prompt or model change, and a release pin moves only to a SHA whose tree has passed the evals (a merge SHA with the same tree as the tested candidate counts). No required check enforces the merge gate, so the owner holds the merge until the evals pass.
- [x] Fix prompts or code for each miss, then run the full set again on request. An expectation changes only with a written reason in the PR (spec P2-4). No misses in run 1, so no fix and no second run.
- [ ] Later phase (not required by the spec): keep the per-case `summary.md` that the runner writes to `--out-dir`. Run 1 uploaded no artifact, so nobody can read the rendered summaries. Add an `actions/upload-artifact` step to `eval.yml` (same pinned SHA as `claude-review.yml`, attempt in the name, short retention, `if: always()`), extend the workflow unit test, and check the harden-runner allowlist. Needs a spec change first (spec "Testing", eval runner).

Depends on: phase 1; V27.

Exit criteria:

- [x] V27 passes, with caveats: the "another environment" case was not run, and the repository check was not tested separately (N4 ran as `push` with no environment); P1 scope `workspace:developer` not confirmed (the Console list view does not show it).
- [x] Every fixture in the minimum set gives its expected outcome: one full run with all 13 cases matched (spec P2-4; run 40445885087).
- [x] The hard-block fixtures (bidi, git URL lockfile) block whatever Claude returns. The unit tests prove that both fail the gate whatever Claude returns, and run 1 confirms it.

## Phase 3: smoke test on claude-review-test

Run the spec's workflow acceptance tests under a test org ruleset that requires the central workflow from `OperationCode/.github` at the candidate release SHA and targets only claude-review-test. Only one ruleset requires the workflow there at a time.

- [x] Production IDs in `analyze.py` and the release tests in CI (the candidate S1). R1 `claude-review-prod-r1` (`fdrl_01N2ZktTiVKqUvvXwywBFfys`) and the production service account are set; `test.yml` runs `pytest tests/unit -m release`.
- [x] V26 a: the owner created R1 at the placeholder SHA and the Console accepted it (2026-10-27); R2 `claude-review-p3-r2` was created the same way. The owner read back R1 at M1 `590a387` and R2 at M2 `1cefe42` before the M3 edit (spec P3-6). The service account and the workspace were not read back.
- [x] P3-2: an over-long string no longer fails a pass. Release eval run 40517202830 at S1 matched 12 of 13: one supply-chain quote went over 300 characters, which the API cannot enforce. Analyze now cuts every string over its schema `maxLength` (summary, file, quote, title, explanation) to that limit and keeps the finding (spec P3-2). Fix round 1: a cut file path ends in "/", so it names no changed file; when the file, title or quote is at its limit, the inline comment key covers every shown field, so a cut never hides a distinct explanation. Fix round 2: a redaction can make two titles equal far below the limit, so the key of every finding covers every shown field, at any length. Fix round 3: each inline comment carries the D14 key and the full key, both of the redacted shown text; one run dedupes by full key, a later run skips a D14 key already on the PR and shows the finding in full in the summary when its full key is new. Fix round 4: an earlier comment counts only when its text checks out (the D14 skip needs the inline layout, path, side and title; "see the earlier comment" needs the exact body at the same line), and an unverified high or critical finding is never cut from the summary. A candidate with this change needs its own eval.
- [x] V26 b, before the acceptance tests: after the owner sets the production rule to the candidate SHA, a run at that SHA gets a token and a run at another SHA is denied. Run 40560632129 at S1 got a token (2026-10-27, 18:31Z); run 40561015054 at the probe SHA was denied, and the Console shows 6 rows `Failure` `match_claim_value_mismatch` on R1 at 18:33:49Z (owner).
- [ ] V26 c, before V22 b: release steps 1 to 6 with a scratch rule R2 on the test workspace, R1 unchanged. Include the second exchange at the release SHA, and check that the workflows rule accepts a scratch ruleset pinned to a SHA that is only on a non-default branch of `.github`. S2 `9752ba7` (PR 10 into `p3-sim-base`) and M2 `1cefe42` both got a token (runs 40585724589 and 40587964524); the rule accepted SHAs that are only on non-default branches. Partial: accepted at S2 and M2 (token inferred through R2); R2 Console rows were not read, no R2 read-back output is recorded, and step 5a was not run for R2/M2. Remaining: R2 read-backs at the placeholder, S2 and M2, and a denied exchange at M2 before the R2 edit.
- [x] Release eval at S1 (`3aa7ae9`): run 40528717338, 13 of 13 matched.
- [x] M1 tree check: M1 `590a387` and S1 have the same tree, and the R1 exchange works at M1 (run 40585413003) after the denied run at M1 (run 40583290922).
- [ ] Release simulation (R2, S2, M2): steps 1 to 6 of "Each release", never merged to main. Partial: steps ran and S2 and M2 got tokens; the R2 read-back at M2 is done. NOT RUN, stays open: the step 5a deny at M2 before the R2 edit.
- [x] A fork PR from an account outside the org, including a draft that later becomes ready. The review starts with no approval click (V8 b). Pass 2026-10-28: PR 38, run 40621436811 (spec P3-6).
- [x] V8 a: a fork PR whose own workflow has a job named `oc-claude-review`. Pass 2026-10-28 (PR 39): from a first-time fork GitHub holds the fake run (`action_required`), so it cannot start first; after approval it passed and the box followed the central run. The fake-first case stays covered by the same-repo evidence (PR 36, run 40572853203 started first; the box stayed blocked).
- [x] V11: retarget from a non-default branch. The retarget starts no run and the box stays blocked until a reopen run passes (PR 29, run 40561903948); an old pass on the same head counts (PR 30).
- [x] V12: repo-level Actions settings. With Actions disabled, and with a restrictive allowed-actions list, the required run still ran (runs 40562372022 and 40562688524). Settings restored.
- [x] V22 a and b: pin behind main, then a pin move with PRs open. `job.workflow_sha` equaled the pin in 33 of 33 attempts. After a forward pin move the old passes do not count; after a move back they count again (spec "Pinned SHA only"; PRs 28 and 37, 21:32 to 21:40Z).
- [x] V23: a same-path workflow file in the target repo. Pass 2026-10-28 (PR 40): the central run failed on the bidi hard block and was not replaced; the fork run stayed `action_required` and never ran (the running case is covered by PR 35). Same-repo evidence: PR 35, run 40572849014.
- [x] V25: the pilot bypass. Pass 2026-10-28 for Maintain (PR 42) and Admin (PR 43): each merged a failed PR with the bypass. Write bypass NOT RUN (a plain merge was refused, which does not test the bypass; Write is not on the bypass list). GitHub records `bypass` with the user ID as actor (no role ID), and a direct push to main by Maintain is refused (GH013). RepositoryRole 2 is Maintain and 5 is Admin (built-in role IDs). Residual: the Write `--admin` attempt. The TR bypass list is test-only and goes back to empty after phase 3 (owner's choice pending).
- [x] The rest of the acceptance list in the spec's "Testing" section that needs no account X, except the four unit-test-only cases listed in the next item (approver removed, edited override, artifact removed, gate cancel after inline comments), including the outage process (spec "Phase 3 results"). Design change (spec P3-1): the invalid federation rule case ran live with two denied exchanges (runs 40561015054 and 40583290922); the exhausted budget case is covered by V9 (phase 0) and the unit tests, with no Console limit edit (ruling Q7).
- [ ] Acceptance cases that needed account X: V6 f as a Write user is done (residual CONFIRMED, PR 41). The web UI "Re-run all jobs" button on a ruleset-started run passed (run 40628870689, PR 43: new attempt on the same run ID, live state re-read, summary comment updated; merge box not observed because the PR was merged); the override cases ran with the REST re-run. Also not run, covered by unit tests: gate cancelled after inline comments with a refused summary write, approver role removed, edited override, artifact upload removed.
- [x] Sonnet 5.5 on every pass (spec P3-4). Release evals 13 of 13 at M3 (run 40592861233); live run 40593729924 passed with `claude-sonnet-5-5` (spec P3-6). Eval at 302882f: runs 40589761270 and 40590079545 each matched 13 of 13 with no failed pass; the Opus reference run 40528717338 also matched 13 of 13. Total tokens 0.97x and 0.98x of Opus, output tokens 0.71x and 0.76x, eval wall time 84 s and 82 s against 138 s. The switch takes effect at the next release: the production rule pins a SHA, so merging does not change production.

Owner:

- [x] Owner: set `job_workflow_ref` of the production federation rule to the candidate release SHA. Done 2026-10-27 (S1, then M1 `590a387`; the run at M1 got a token; no read-back recorded). The candidate's code must name that rule ID (spec "Auth and cost", "Each release").
- [ ] Owner: an account outside the org opens the fork PRs.
- [x] Owner: test users with Write, Maintain and Admin on claude-review-test for V25. Done with account X `irvingpop2` (2026-10-28). Remove its access and empty the TR bypass list after phase 3 (owner's choice pending).

Depends on: phases 1 and 2; V8, V11, V12, V22, V23, V25, V26.

Exit criteria:

- [ ] Every "blocking" V item passes, or the spec records a design change for it.
- [ ] No acceptance case leaves the merge box clear on a failed or missing run.

## Phase 4: pilot

- [ ] Owner: before a repo joins the pilot, give it its own approval protection on the default branch: a repo ruleset or branch protection with at least 1 approval, code owner review and dismiss stale approvals on push. `back-end` has none today.
- [ ] Owner: before a repo joins the pilot, check it for people or bots that push to the default branch directly (V25).
- [ ] Owner: accept that during the pilot a maintainer or repo admin can merge past any failed run, also on their own PR (spec "Pilot and enforcement").
- [ ] Owner: confirm that the federation rule named in the release code has `job_workflow_ref` at the release SHA.
- [ ] Owner: create the pilot ruleset. Only the rule "Require workflows to pass before merging" with the central workflow `repository_id`, path and release SHA. Targets: the pilot repos by name (first `back-end`), default branch. Bypass in `pull_request` mode: the Maintain and Admin repository roles, and org admins.
- [ ] Owner: read the pilot ruleset back through the [org rules API](https://docs.github.com/en/rest/orgs/rules#get-an-organization-repository-ruleset). Check `repository_id`, path, `sha`, no `ref`, and the role `actor_id` values from V25. Then enable it.
- [ ] Owner: require 2FA for all org members.
- [ ] Owner: CODEOWNERS in each pilot repo for `.github/`, manifests, lockfiles, `pyproject.toml`, `Dockerfile`.
- [ ] Start a run on each open PR in the pilot repos (push, or close and reopen).
- [ ] Each week, record false positives, overrides, bypasses, failed runs by reason, egress blocks and cost per run. Keep cost numbers (any currency amount) in the owner's private notes and the Anthropic Console, never in this public repo. Public text may give ratios and timing only.
- [ ] Fix false positives in prompts or code. Each fix goes through phase 2 again, then ships as in "Each release" below.
- [ ] Keep the fixture eval results as an artifact: `eval.yml` uploads none today, so a release eval's per-case results exist only in the job log (phase 2 run 40445885087 and phase 3 run 40528717338 were read from logs). Ships as in "Each release".
- [ ] Plan publication before writing: bounded continuation comments, pointed to from the sticky summary, hold every summary-only finding (changed keys, unverified, outside the diff) when one comment cannot. Then no explanation is cut from the PR comments and summary capacity no longer fails a run whose computed result is `pass` (spec "Publishing (code)", size limit residual; review r-p3-cut-final Important 1). Keep the fail-closed check until this path is complete. Ships as in "Each release".

Depends on: phase 3.

Exit criteria:

- [ ] Owner: the owner judges that the false positive rate and the run failures are acceptable on real PRs, after a period the owner picks.

## Phase 5: before org-wide enforcement

- [ ] Owner: accept in writing the residuals in the spec's "Which run counts": an earlier pass on the same SHA, and run deletion (V6 f confirmed it as a Write user).
- [ ] Owner: fix the existing disabled org ruleset "All checks must pass" before it is enabled:
  - [ ] dismiss stale approvals on push: on
  - [ ] `OrganizationAdmin` bypass mode: `pull_request`, not `always`
  - [ ] remove the empty required status checks rule
  - [ ] fill the workflows rule with the `repository_id` of `OperationCode/.github`, the path `.github/workflows/claude-review.yml` and the pinned release SHA
  - [ ] targets: never `.github`, and none of the repos still in the pilot ruleset
- [ ] Owner: read the org ruleset back and check the workflow entry (`repository_id`, path, `sha`, no `ref`).
- [ ] Build the supported repo inventory (spec "Supported repos") as a list in this repo.
- [ ] Owner: CODEOWNERS in each supported repo.
- [ ] Owner: turn "prevent self-review" back on for the `eval` environment (it is off during phase 2), and decide whether admin bypass stays on.
- [ ] Owner: Dependabot alerts with npm malware detection on active repos.
- [ ] Re-run the key acceptance tests on the current release: V6 a, V8 a, V22 b, V23 and the outage process (the invalid federation rule case).
- [ ] Revisit harden-runner block mode (spec K-14): switch to block when harden-runner [issue 708](https://github.com/step-security/harden-runner/issues/708) is fixed in a harden-runner release. Pin that release, measure the `test.yml` and `eval.yml` lists in audit mode, and re-test block mode. If no job hangs, set `egress-policy: block` and `disable-telemetry: true` in every job, and update the unit tests and the spec.

Depends on: phase 4; V6, V8, V22, V23.

Exit criteria:

- [ ] The written acceptance exists.
- [ ] The org ruleset read-back matches this checklist.
- [ ] The re-run tests pass.

## Phase 6: org-wide enforcement

- [ ] Owner: enable the org ruleset with the supported repos that are not in the pilot. Add them in small groups.
- [ ] Owner: move each pilot repo: remove it from the pilot ruleset targets, then add it to the org ruleset targets at once. Never let both rulesets require the workflow on one repo.
- [ ] After each group or move, start a run on each open PR, and check that each shows the required workflow passing or failing on its own result.
- [ ] Owner: delete the pilot ruleset when no repo is left in it.
- [ ] Keep the supported repo inventory current. A repo joins or leaves through a PR to this repo.

Exit criteria:

- [ ] Every supported repo is a target of the org ruleset, and only org admins can bypass, through a pull request.

## Each release (from phase 4 on)

One federation rule allows one SHA, and every release is validated at its final SHA before a pin moves (spec "Auth and cost", "Each release"):

- [ ] Owner: create a new federation rule R2 as a copy of the current rule R1, with the placeholder SHA `0000000000000000000000000000000000000000` in `job_workflow_ref`. Read it back (V26).
- [ ] Put the R2 ID in the central code. That commit is the release candidate S2.
- [ ] Owner: set `job_workflow_ref` of R2 to S2 and read it back.
- [ ] Validate S2, for every release: unit tests pass, the owner-approved fixture eval passes, and a run under the scratch test ruleset pinned to S2 gets a token through R2.
- [ ] Merge. If the merge makes a new SHA, check that its tree equals S2 (`git diff` is empty, so the content and rule ID are the same). If the trees differ, treat the merge SHA as a new candidate and go back to the step that sets R2. That SHA is the release SHA. Phase 3 learned: every squash merge makes a new SHA, so one release takes two Console edits per rule, the candidate SHA and then the merge SHA.
- [ ] Before the second Console edit, pin the scratch test ruleset to the merge SHA and run once: the exchange must be denied, because the rule still names the candidate SHA (phase 3: run 40583290922). Then the owner sets R2 to the merge SHA and reads it back.
- [ ] Pin the scratch test ruleset to the release SHA and do one token exchange through R2. Any new candidate, for example a fix commit after a failed validation, repeats from the step that sets R2 to the candidate SHA.
- [ ] Owner: move the pin of every ruleset that requires the workflow (the pilot ruleset, the org ruleset, or both) to the release SHA, then read each back: `repository_id`, path, `sha`, no `ref`.
- [ ] Start a new run on each open PR (push, or close and reopen). Do not re-run old runs: after R1 is deleted, a re-run at the old SHA fails auth. Do this after every pin move, also a move back: the box counts only runs at the pinned SHA, so a move back revives older passes at that SHA (spec "Pinned SHA only").
- [ ] Owner: delete R1 only when each new run has completed at the release SHA (`job.workflow_sha`); a queued run does not count (V22).
