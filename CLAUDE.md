# CLAUDE.md

This repo holds OperationCode's org-wide GitHub config, mainly the Claude PR reviewer.

Read [docs/claude-review-design.md](docs/claude-review-design.md) before you change anything. It is the source of truth. If the code needs to differ from the spec, update the spec in the same PR.

## Rules that must not break

- Never check out, install, build or execute the content of a PR under review. Read it through the GitHub REST API only. One exception: evals of PRs to this repo may run that PR's code, only after an owner approves the eval environment run.
- The Claude call has no tools. Claude returns findings JSON only, never a verdict.
- Only code lowers risk. Claude output can add findings, but it can never clear a prefilter hard block, a failed pass or a dependency-review failure.
- The job that holds the Anthropic credential has no GitHub write permission. The job that writes to GitHub has no Anthropic credential.
- Pin every action by full commit SHA. Lock Python deps with hashes.
- Every prompt file keeps its `<grounding_rules>` block. A unit test enforces this.
- The bot never approves, requests changes, merges or edits a PR.

## Working here

- Python lives in `review/`, managed with `uv`.
- Unit tests make no network or API calls: `cd review && uv run pytest tests/unit`.
- The fixture eval calls the live API and costs money. Run it only on request.
