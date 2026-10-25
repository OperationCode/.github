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
- [ ] V2: a fork PR run prints its decoded OIDC claims (never the token).
- [ ] V3: check the intended federation rule against the WIF reference, record the final rule text in the spec, then test it on a test workspace.
- [ ] V5: one Messages API request with a mid-conversation system message, structured output and server-side fallback.
- [ ] V9: spend limit behavior on a test workspace with a very small limit.
- [ ] V13: dependency review on a fork PR with no checkout and SHA refs.
- [ ] V16: push epoch events on a fork PR.
- [ ] V18: fork head trees and blobs through the base repo's git API.
- [ ] V24: run list by head SHA from the gate job's token, and its delay.
- [ ] V4: a Dependabot PR mints an OIDC token in a ruleset-required run. A stub analyze job is enough.

Owner:

- [ ] Owner: create a scratch source repo in the org for the V tests, separate from claude-review-test.
- [ ] Owner: Anthropic Console: a dedicated workspace with a hard monthly spend limit and a service account. Create the production federation rule from V3 with the condition shape only; it gets its first SHA in phase 3. No API key.
- [ ] Owner: a separate eval workspace with its own small spend limit, and a federation rule for `eval.yml` on `workflow_dispatch` in `OperationCode/.github` that also requires the claim `environment: "eval"` (spec "Auth and cost"). Needed before phase 2.
- [ ] Owner: on `.github`, create the GitHub environment `eval`: the owner is a required reviewer, and only the `main` branch may deploy to it. Needed before phase 2.
- [ ] Owner: a test workspace with a very small spend limit for V9.
- [ ] Owner: the test org ruleset for V6 that targets only claude-review-test.
- [ ] Owner: a Dependabot PR in claude-review-test for V4.

Exit criteria:

- [ ] V6 shows that the newest run on the head SHA decides. If not, building stops.
- [ ] V2 and V3 pass. If not, building stops.
- [ ] V4, V5, V9, V13, V16, V18 and V24 have results in the spec. A fallback in the spec covers each one that failed.

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
- [ ] `verdict.py`: citation check, inline eligibility, gate reasons, override checks. The full gate matrix from the spec's "Testing" section. The push epoch part depends on V16 (it may add `reopened`).
- [ ] Sanitizer and escaping for every untrusted string that the publisher posts.

Depends on: none for most tasks; V18 for `collect.py`, V16 for the push epoch in `verdict.py`.

### 1b. Analyze and publish

- [ ] `analyze.py`: one Messages API call per pass, no tools, `claude-opus-5-5`, explicit `effort` and `max_tokens`, structured output, fallback, at most 2 retries, a request deadline, stale check before the calls. Always writes exactly three pass records. Tests use a fake client.
- [ ] `publish.py`: escaping, inline `COMMENT` review, sticky summary, final check, exit code (0 only for `pass`). It never approves, requests changes, merges, closes, labels or edits the PR (spec decision K-1).

Depends on: V3, V5 (analyze); V6, V16, V24 (publish).

### 1c. Central workflow

- [ ] `.github/workflows/claude-review.yml`: `pull_request_target` only, `permissions: {}` at the top, per-job scopes as in the spec, no `if:` except `always()` on the gate job, no concurrency group, no `continue-on-error`, every action pinned by full commit SHA, checkout of `OperationCode/.github` at `job.workflow_sha`.
- [ ] The analyze job is the only job with `id-token: write`. The gate job has no Anthropic credential.
- [ ] A unit test parses the workflow: no `continue-on-error`, the dependency-review job exports the step `outcome`, every `uses:` is a full SHA.
- [ ] `.github/workflows/test.yml`: unit tests on PRs to this repo.
- [ ] `.github/workflows/eval.yml`: manual fixture evals. The job uses `environment: eval` and has `contents: read` and `id-token: write` only. The workflow unit test checks this.
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

The fixture eval calls the live API and costs money. The owner runs it on request only.

- [ ] Add the fixture bundles from the spec's minimum set, with expected outcomes.
- [ ] Owner: run `eval.yml` from `main` and approve the `eval` environment, with the eval federation rule and eval workspace from phase 0. Record the results in the PR that changed the prompts or code. A release pin never moves to a SHA whose evals have not passed.
- [ ] Fix prompts or code for each miss, then run again on request.

Depends on: phase 1.

Exit criteria:

- [ ] Every fixture in the minimum set gives its expected outcome.
- [ ] The hard-block fixtures (bidi, git URL lockfile) block whatever Claude returns.

## Phase 3: smoke test on claude-review-test

Run the spec's workflow acceptance tests under a test org ruleset that requires the central workflow from `OperationCode/.github` at the candidate release SHA and targets only claude-review-test. Only one ruleset requires the workflow there at a time.

- [ ] A fork PR from an account outside the org, including a draft that later becomes ready. The review starts with no approval click (V8 b).
- [ ] V8 a: a fork PR whose own workflow has a job named `oc-claude-review` that starts before the required run.
- [ ] V11: retarget from a non-default branch.
- [ ] V12: repo-level Actions settings.
- [ ] V22 a and b: pin behind main, then a pin move with PRs open.
- [ ] V23: a same-path workflow file in the target repo.
- [ ] V25: the pilot bypass. Maintain and Admin can merge past a failed run, Write cannot, and GitHub records each bypass. Record the role `actor_id` values, and whether a direct push to the default branch is blocked.
- [ ] The rest of the acceptance list in the spec's "Testing" section, including the outage process (V9).

Owner:

- [ ] Owner: add the candidate release SHA to the production federation rule.
- [ ] Owner: an account outside the org opens the fork PRs.
- [ ] Owner: test users with Write, Maintain and Admin on claude-review-test for V25.

Depends on: phases 1 and 2; V8, V11, V12, V22, V23, V25.

Exit criteria:

- [ ] Every "blocking" V item passes, or the spec records a design change for it.
- [ ] No acceptance case leaves the merge box clear on a failed or missing run.

## Phase 4: pilot

- [ ] Owner: before a repo joins the pilot, give it its own approval protection on the default branch: a repo ruleset or branch protection with at least 1 approval, code owner review and dismiss stale approvals on push. `back-end` has none today.
- [ ] Owner: before a repo joins the pilot, check it for people or bots that push to the default branch directly (V25).
- [ ] Owner: accept that during the pilot a maintainer or repo admin can merge past any failed run, also on their own PR (spec "Pilot and enforcement").
- [ ] Owner: confirm the release SHA is in the federation rule.
- [ ] Owner: create the pilot ruleset. Only the rule "Require workflows to pass before merging" with the central workflow `repository_id`, path and release SHA. Targets: the pilot repos by name (first `back-end`), default branch. Bypass in `pull_request` mode: the Maintain and Admin repository roles, and org admins.
- [ ] Owner: read the pilot ruleset back through the [org rules API](https://docs.github.com/en/rest/orgs/rules#get-an-organization-repository-ruleset). Check `repository_id`, path, `sha`, no `ref`, and the role `actor_id` values from V25. Then enable it.
- [ ] Owner: require 2FA for all org members.
- [ ] Owner: CODEOWNERS in each pilot repo for `.github/`, manifests, lockfiles, `pyproject.toml`, `Dockerfile`.
- [ ] Start a run on each open PR in the pilot repos (push, or close and reopen).
- [ ] Each week, record false positives, overrides, bypasses, failed runs by reason, egress blocks and cost per run. Keep cost numbers in the owner's private notes and the Anthropic Console, never in this public repo.
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

- [ ] Run unit tests, and the fixture eval on request when prompts or the model change.
- [ ] Owner: add the new SHA to the production federation rule.
- [ ] Owner: move the pin of every ruleset that requires the workflow (the pilot ruleset, the org ruleset, or both), then read each back: `repository_id`, path, `sha`, no `ref`.
- [ ] Owner: remove the previous SHA from the federation rule once open PRs have new runs (V22).
