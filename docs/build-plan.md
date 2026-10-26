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
- [ ] Owner: Anthropic Console: a dedicated workspace with a hard monthly spend limit and a service account. Create the production federation rule as in spec "Auth and cost": pattern mode, subject prefix `repo:OperationCode@10479364/*`, scope `workspace:developer`, the review workspace only, and the placeholder SHA `0000000000000000000000000000000000000000` in `job_workflow_ref`. Read it back; if the Console rejects the placeholder, stop and resolve the order of rule ID and SHA first (spec V26 a). Its ID goes into the central code; phase 3 sets the candidate SHA. No API key.
- [ ] Owner: a separate eval workspace with its own small spend limit, and a federation rule for `workflow_dispatch` runs in `OperationCode/.github` whose job uses the environment `eval`: pattern mode, the same subject prefix, exact claims `repository_owner_id`, `repository_id`, `event_name` and `environment`, scope `workspace:developer`, the eval workspace only (spec "Auth and cost"). The rule cannot name `eval.yml`: any `.github` workflow that uses `eval` can match, so the owner's approval and the workflow unit test (1c) hold it to `eval.yml`. Test it as in spec V27 before phase 2.
- [ ] Owner: on `.github`, create the GitHub environment `eval`: the owner is a required reviewer for every run, and any branch may deploy to it. Turn on "prevent self-review" so the PR author cannot approve their own eval run. Before approving a run, check the run that waits for approval: the workflow file and commit it runs, every job in it that uses `eval`, and their effective permissions (no GitHub write). Also check that the PR does not change `eval.yml`, any other workflow file, the eval code, the prompts, the fixtures or the federation setup in a harmful way, and that `test.yml` passed. The approval is the control; the residual risk is an approver who approves without reading. Exception to the no-execute rule (K-4): evals of PRs to this repo may run that PR's code, only after an owner approves the `eval` environment run. Needed before phase 2.
- [x] Owner: a test workspace with a very small spend limit for V9.
- [ ] Owner: the test org ruleset for V6 that targets only claude-review-test.
- [ ] Owner: a Dependabot PR in claude-review-test for V4.

Exit criteria:

- [x] V6 shows that the newest run on the head SHA decides. If not, building stops. (The queued cell is still open.)
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

- [ ] `analyze.py`: one Messages API call per pass, no tools, `claude-opus-5-5`, explicit `effort` and `max_tokens`, structured output with the stripped schema and a full schema check in code (V5), fallback, at most 2 retries, a request deadline, stale check before the calls. The spend limit error (HTTP 400 `invalid_request_error`, "workspace API usage limits") is an outage with its own clear reason, not a request bug (V9). Always writes exactly three pass records. Tests use a fake client.
- [ ] `publish.py`: escaping, inline `COMMENT` review, sticky summary, final check, exit code (0 only for `pass`). It never approves, requests changes, merges, closes, labels or edits the PR (spec decision K-1).

Depends on: V3, V5, V9 (analyze); V6, V16, V24 (publish).

### 1c. Central workflow

- [ ] `.github/workflows/claude-review.yml`: `pull_request_target` only, `permissions: {}` at the top, per-job scopes as in the spec, no `if:` except `always()` on the gate job, no concurrency group, no `continue-on-error`, every action pinned by full commit SHA, checkout of `OperationCode/.github` at `job.workflow_sha`.
- [ ] The analyze job is the only job with `id-token: write`. The gate job has no Anthropic credential.
- [ ] A unit test parses the workflow: no `continue-on-error`, the dependency-review job exports the step `outcome`, every `uses:` is a full SHA.
- [ ] `.github/workflows/test.yml`: unit tests on PRs to this repo.
- [ ] `.github/workflows/eval.yml`: manual fixture evals. The job uses `environment: eval` and has `contents: read` and `id-token: write` only. A workflow unit test reads every workflow file and fails if a workflow other than `eval.yml` uses `environment: eval`, or if a job that uses `eval` sets no explicit job-level `permissions` or has any `write` permission other than `id-token: write`. Job-level `permissions` is required even if the workflow level sets it. `write-all` at either level fails the test, and so do `read-all` and a missing job-level block, because the job must state `contents: read` and `id-token: write` itself.
- [ ] V10: harden-runner in audit mode for a full run, then block mode with the measured allowlist.

Depends on: V2, V4, V13, V18 (workflow); V10 needs a full run, so it runs here.

Owner:

- [ ] Owner: confirm the protection of `.github` main: CODEOWNERS review, 1 approval, no force push, no deletion, org admin bypass through a pull request only.
- [ ] Owner: on `.github` main, turn on dismiss stale approvals on push, and require the `test.yml` check.
- [ ] Owner: org Actions setting, default `GITHUB_TOKEN` permissions read-only.

Exit criteria:

- [ ] Unit tests pass in CI on `.github`.
- [ ] A full run in claude-review-test succeeds with egress in block mode (V10).
- [ ] Each change was reviewed through a PR with code owner approval.

## Phase 2: fixture evals

The fixture eval calls the live API and costs money. The owner runs it on request only. It is the one exception to the no-execute rule: it may run a PR's code, only after an owner approves the `eval` environment run (K-4).

- [ ] V27, before the first eval: test the eval federation rule (an approved `eval.yml` run gets a token; the deny cases in the spec get none).
- [ ] Add the fixture bundles from the spec's minimum set, with expected outcomes.
- [ ] Owner: run `eval.yml` on the PR branch and approve the `eval` environment, with the eval federation rule and eval workspace from phase 0. Check the PR first (see phase 0). Record the results in the PR that changed the prompts or code. Passing evals gate the merge of a prompt or model change, and a release pin moves only to a SHA whose tree has passed the evals (a merge SHA with the same tree as the tested candidate counts). No required check enforces the merge gate, so the owner holds the merge until the evals pass.
- [ ] Fix prompts or code for each miss, then run again on request.

Depends on: phase 1; V27.

Exit criteria:

- [ ] V27 passes.
- [ ] Every fixture in the minimum set gives its expected outcome.
- [ ] The hard-block fixtures (bidi, git URL lockfile) block whatever Claude returns.

## Phase 3: smoke test on claude-review-test

Run the spec's workflow acceptance tests under a test org ruleset that requires the central workflow from `OperationCode/.github` at the candidate release SHA and targets only claude-review-test. Only one ruleset requires the workflow there at a time.

- [ ] V26 b, before the acceptance tests: after the owner sets the production rule to the candidate SHA, a run at that SHA gets a token and a run at another SHA is denied.
- [ ] V26 c, before V22 b: release steps 1 to 6 with a scratch rule R2 on the test workspace, R1 unchanged. Include the second exchange at the release SHA, and check that the workflows rule accepts a scratch ruleset pinned to a SHA that is only on a non-default branch of `.github`.
- [ ] A fork PR from an account outside the org, including a draft that later becomes ready. The review starts with no approval click (V8 b).
- [ ] V8 a: a fork PR whose own workflow has a job named `oc-claude-review` that starts before the required run.
- [ ] V11: retarget from a non-default branch.
- [ ] V12: repo-level Actions settings.
- [ ] V22 a and b: pin behind main, then a pin move with PRs open.
- [ ] V23: a same-path workflow file in the target repo.
- [ ] V25: the pilot bypass. Maintain and Admin can merge past a failed run, Write cannot, and GitHub records each bypass. Record the role `actor_id` values, and whether a direct push to the default branch is blocked.
- [ ] The rest of the acceptance list in the spec's "Testing" section, including the outage process (V9).

Owner:

- [ ] Owner: set `job_workflow_ref` of the production federation rule to the candidate release SHA. The candidate's code must name that rule ID (spec "Auth and cost", "Each release").
- [ ] Owner: an account outside the org opens the fork PRs.
- [ ] Owner: test users with Write, Maintain and Admin on claude-review-test for V25.

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

Depends on: phase 3.

Exit criteria:

- [ ] Owner: the owner judges that the false positive rate and the run failures are acceptable on real PRs, after a period the owner picks.

## Phase 5: before org-wide enforcement

- [ ] Owner: accept in writing the residuals in the spec's "Which run counts": an earlier pass on the same SHA, and run deletion if V6 f did not pass.
- [ ] Owner: fix the existing disabled org ruleset "All checks must pass" before it is enabled:
  - [ ] dismiss stale approvals on push: on
  - [ ] `OrganizationAdmin` bypass mode: `pull_request`, not `always`
  - [ ] remove the empty required status checks rule
  - [ ] fill the workflows rule with the `repository_id` of `OperationCode/.github`, the path `.github/workflows/claude-review.yml` and the pinned release SHA
  - [ ] targets: never `.github`, and none of the repos still in the pilot ruleset
- [ ] Owner: read the org ruleset back and check the workflow entry (`repository_id`, path, `sha`, no `ref`).
- [ ] Build the supported repo inventory (spec "Supported repos") as a list in this repo.
- [ ] Owner: CODEOWNERS in each supported repo.
- [ ] Owner: Dependabot alerts with npm malware detection on active repos.
- [ ] Re-run the key acceptance tests on the current release: V6 a, V8 a, V22 b, V23 and the outage process.

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
- [ ] Merge. If the merge makes a new SHA, check that its tree equals S2 (`git diff` is empty, so the content and rule ID are the same), then the owner sets R2 to that SHA and reads it back. If the trees differ, treat the merge SHA as a new candidate and go back to the step that sets R2. That SHA is the release SHA.
- [ ] Pin the scratch test ruleset to the release SHA and do one token exchange through R2. Any new candidate, for example a fix commit after a failed validation, repeats from the step that sets R2 to the candidate SHA.
- [ ] Owner: move the pin of every ruleset that requires the workflow (the pilot ruleset, the org ruleset, or both) to the release SHA, then read each back: `repository_id`, path, `sha`, no `ref`.
- [ ] Start a new run on each open PR (push, or close and reopen). Do not re-run old runs: after R1 is deleted, a re-run at the old SHA fails auth.
- [ ] Owner: delete R1 only when each new run has completed at the release SHA (`job.workflow_sha`); a queued run does not count (V22).
