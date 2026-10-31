# OperationCode/.github

Org-wide GitHub configuration for [OperationCode](https://github.com/OperationCode).

## Claude PR review

Every PR in every OperationCode repo gets an automatic review from Claude: a code review, a security review, and a malicious-contribution review. An org ruleset enforces it. Claude reads the PR as data only. It never runs PR code and has no tools or GitHub token. A human approval is still required to merge.

Design: [docs/claude-review-design.md](docs/claude-review-design.md)

Build plan: [docs/build-plan.md](docs/build-plan.md)

## Releases (owner only)

A release points the production federation rule and every ruleset pin at one merge SHA on main. The owner runs it from a clone of this repo. No workflow runs it. See "Each release" in the [design](docs/claude-review-design.md) and the [build plan](docs/build-plan.md).

One-time setup: install the [`ant` CLI](https://platform.claude.com/docs/en/cli-sdks-libraries/cli/authentication) with `brew install anthropics/tap/ant`, and log in to `gh` as an org owner. You do not log in to `ant` yourself and you keep no `ant` profile. The tool runs `ant auth login --profile admin --scope "org:admin"` in a private temp dir (your browser opens), and runs `ant auth logout --all` and deletes the dir when it exits. The federation rule endpoints refuse Admin API keys, and an `org:admin` login stored on disk is readable by any process that runs as you, so no key or token is kept.

```sh
make release-plan SHA=<sha>                 # read-only; NO_CONSOLE=1 skips the Console reads
make release SHA=<sha>                      # plan, then apply at once (no prompt), read back; `make release-plan` is the read-only dry run
make release SHA=<previous sha>             # rollback
make release-rule-test RULE=<id> SHA=<sha>  # Console-only edit of a scratch rule (refuses the production rule)
```

Before and after JSON goes to `release-records/` (git-ignored, no secrets).
