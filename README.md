# OperationCode/.github

Org-wide GitHub configuration for [OperationCode](https://github.com/OperationCode).

## Claude PR review

Every PR in every OperationCode repo gets an automatic review from Claude: a code review, a security review, and a malicious-contribution review. An org ruleset enforces it. Claude reads the PR as data only. It never runs PR code and has no tools or GitHub token. A human approval is still required to merge.

Design: [docs/claude-review-design.md](docs/claude-review-design.md)
