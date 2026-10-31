# Owner-run release targets. Not used by any workflow or CI job: the release
# tool holds an Anthropic org:admin login and GitHub write at once, which no
# job may hold. See review/tools/release.py and docs/claude-review-design.md,
# "Each release" in "Auth and cost".
#
#   make release-plan SHA=<sha> [NO_CONSOLE=1]   read-only plan
#   make release SHA=<sha>                       plan, typed confirmation, apply, read back
#   make release-rule-test RULE=<id> SHA=<sha>   Console-only edit of a scratch rule
#   rollback: make release SHA=<previous release sha>

TOOL = cd review && uv run --frozen python tools/release.py

.PHONY: release-plan release release-rule-test

release-plan:
	$(TOOL) plan --sha "$(SHA)" $(if $(NO_CONSOLE),--no-console)

release:
	$(TOOL) release --sha "$(SHA)"

release-rule-test:
	$(TOOL) rule-test --rule "$(RULE)" --sha "$(SHA)"
