# Supported repos

The review ruleset 26132750 targets the repos with status `target` below, by `repository_id`, on their default branch. The rules for a supported repo are in the [design spec](claude-review-design.md#supported-repos). A repo joins or leaves this list through a PR to this repo. A `candidate` meets the rules but is not a target yet; a one-line PR changes it to `target` after it joins the ruleset and its test PR passes.

Every active repo also gets the baseline ruleset 25787833 (`~ALL`), whether it is listed here or not.

| Repo | `repository_id` | Default branch | Status | Date joined |
|---|---|---|---|---|
| `front-end` | 135777271 | `main` | target | 2026-10-29 |
| `back-end` | 182584277 | `main` | target | 2026-10-29 |
| `operationcode_infra` | 107068150 | `main` | target | 2026-10-29 |
| `operationcode-pybot` | 146210805 | `master` | target | 2026-10-29 |
| `START_HERE` | 82613670 | `master` | candidate | |

## Excluded active repos

| Repo | `repository_id` | Reason |
|---|---|---|
| `.github` | 1432342572 | Never a target: it holds the central workflow, and a ruleset that requires a workflow from `.github` and also targets `.github` can deadlock. |
| `claude-review-test` | 1432457406 | Test repo. Only the scratch test ruleset 25835887 requires the workflow there. |
| `claude-review-p0-source` | 1433591286 | Test source repo for the acceptance tests. No review ruleset. |

Private repos are excluded (not supported): v1 supports public repos only.

Every other repo in the org is archived (decision P5-3).
