"""Owner-run setup of the self-review federation rule R-self.

    make self-review-plan     read-only: shows what the setup would create
    make self-review-setup    create what is missing, read it back, write the
                              rule ID into analyze.py (working tree, no commit)

Spec: docs/claude-review-design.md, "Self-review rule" in "Auth and cost".
Each step finds first and creates only what is missing; it never edits or
archives an object, so running it again is safe:

    1. read R1: R-self uses its issuer; its service account must be the one
       analyze.py names (R-self uses the same service account)
    2. workspace WORKSPACE_NAME: find by name, else create
    3. that service account is a member of the workspace, else add it
       (role WORKSPACE_ROLE)
    4. rule RULE_NAME: find by name, else create. A rule with that name and
       any other field is refused, never edited
    5. read the workspace, the membership and the rule back and check them
    6. write the rule ID into SELF_REVIEW_FEDERATION_RULE_ID in analyze.py

The workspace spend limit has no `ant` command, so the tool prints the
Console steps for it. Login, logout, cleanup and exit codes are release.py's
(an ephemeral org:admin `ant` session, cleared on every exit path).

Not run in CI or any workflow (it holds an Anthropic org:admin login).
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

import release  # sibling module: tools/ is on sys.path when this file runs as a script
from release import ReleaseError

WORKSPACE_NAME = "claude-review-self-review"
RULE_NAME = "claude-review-self-review"
WORKSPACE_ROLE = "workspace_developer"
OAUTH_SCOPE = "workspace:developer"
TOKEN_LIFETIME_S = 600
# Pattern mode: the org subject prefix plus exact claims (spec "Self-review rule").
EXPECTED_MATCH = {
    "subject_prefix": "repo:OperationCode@10479364/*",
    "claims": {
        "repository_id": str(release.WORKFLOW_REPO_ID),
        "event_name": "pull_request_target",
        "job_workflow_ref": f"{release.JOB_WORKFLOW_REF_PREFIX}refs/heads/main",
    },
}
ANALYZE_FILE = Path(__file__).resolve().parents[1] / "src" / "oc_review" / "analyze.py"
CONSTANT = "SELF_REVIEW_FEDERATION_RULE_ID"
PLACEHOLDER = "fdrl_" + "0" * 24
WORKSPACES = "organization:workspaces"
MEMBERS = "organization:workspaces:service-accounts"
ANT_COMMANDS = ((release.Console.RULES, ("retrieve", "list", "create")),
                (WORKSPACES, ("retrieve", "list", "create")),
                (MEMBERS, ("list", "add")))


# ---------------------------------------------------------------- pure logic


def parse_items(text: str, what: str) -> list[dict]:
    """Items of a `--format jsonl` list: one object per line. A line that is a
    page (`{"data": [...]}`) gives its items."""
    items: list[dict] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        obj = release._json(line, what)
        page = obj.get("data") if isinstance(obj, dict) else None
        for item in (page if isinstance(page, list) else [obj]):
            if not isinstance(item, dict):
                raise ReleaseError(f"{what}: an item is not an object")
            items.append(item)
    return items


def one_named(items: list[dict], name: str, what: str) -> dict | None:
    """The one live item called `name`, None when there is none. Several refuse."""
    hits = [i for i in items if i.get("name") == name and not i.get("archived_at")]
    if len(hits) > 1:
        raise ReleaseError(f"{len(hits)} {what}s are named {name!r}; archive the extra ones in the Console, then run again")
    return hits[0] if hits else None


def is_member(items: list[dict], service_account_id: str) -> bool:
    return any(service_account_id in (i.get("service_account_id"), i.get("id")) for i in items)


def rule_problems(rule: dict, *, workspace_id: str, issuer_id: str, service_account_id: str) -> list[str]:
    """Every field of R-self that is not as the spec says."""
    problems = [f"match.{p}" for p in release.diff_paths(EXPECTED_MATCH, release._strip_nulls(rule.get("match")))]
    target = rule.get("target") or {}
    workspaces = rule.get("workspace_ids") or [rule.get("workspace_id")]
    expected = {
        "issuer_id": (rule.get("issuer_id"), issuer_id),
        "oauth_scope": (rule.get("oauth_scope"), OAUTH_SCOPE),
        "target.type": (target.get("type"), "service_account"),
        "target.service_account_id": (target.get("service_account_id"), service_account_id),
        "applies_to_all_workspaces": (bool(rule.get("applies_to_all_workspaces")), False),
        "workspace_ids": (workspaces, [workspace_id]),
        "token_lifetime_seconds": (rule.get("token_lifetime_seconds"), TOKEN_LIFETIME_S),
        "archived_at": (rule.get("archived_at"), None),
    }
    problems += [f"{k} is {got!r}, expected {want!r}" for k, (got, want) in expected.items() if got != want]
    return problems


def analyze_constant(text: str, name: str) -> str:
    hits = re.findall(rf'^{name}\s*=\s*"([^"]*)"', text, re.M)
    if len(hits) != 1:
        raise ReleaseError(f"analyze.py has {len(hits)} lines that set {name}, expected 1")
    return hits[0]


def set_rule_id(text: str, rule_id: str) -> str:
    """analyze.py text with R-self set to `rule_id`. Refuses to replace another
    real rule ID: only the placeholder or the same ID is accepted."""
    current = analyze_constant(text, CONSTANT)
    if current not in (PLACEHOLDER, rule_id):
        raise ReleaseError(f"analyze.py already names R-self {current}, not {rule_id}; check the Console, "
                           "then edit analyze.py by hand")
    return re.sub(rf'^({CONSTANT}\s*=\s*)"[^"]*"', rf'\g<1>"{rule_id}"', text, count=1, flags=re.M)


def spend_limit_steps() -> str:
    return (f"MANUAL STEP (no `ant` command sets a workspace spend limit): in the Console, open the workspace\n"
            f"  {WORKSPACE_NAME!r}, Limits, and set a low monthly spend limit. Do it before you merge the PR\n"
            "  that sets the rule ID. Keep the amount out of this public repo.")


# ---------------------------------------------------------------- Console steps


class Setup:
    def __init__(self, console: release.Console, rec: release.Records, *, apply: bool):
        self.console, self.rec, self.apply = console, rec, apply

    def obj(self, args: Sequence[str], what: str) -> dict:
        got = release._json(self.console.call([*args, "--format", "json"], what), what)
        if not isinstance(got, dict) or not got.get("id"):
            raise ReleaseError(f"{what}: the response is not an object with an id")
        return got

    def items(self, args: Sequence[str], what: str) -> list[dict]:
        return parse_items(self.console.call([*args, "--format", "jsonl", "--max-items", "-1"], what), what)

    def r1(self, service_account_id: str) -> str:
        r1 = self.console.retrieve(release.PROD_RULE_ID)
        self.rec.save("r1", r1)
        target = (r1.get("target") or {}).get("service_account_id")
        if target != service_account_id:
            raise ReleaseError(f"R1 targets service account {target!r}, but analyze.py names {service_account_id}")
        issuer = r1.get("issuer_id")
        if not isinstance(issuer, str) or not issuer:
            raise ReleaseError("R1 has no issuer_id")
        print(f"  [ok] R1 {release.PROD_RULE_ID}: issuer {issuer}, service account {target}")
        return issuer

    def workspace(self) -> str | None:
        found = one_named(self.items([WORKSPACES, "list"], "workspace list"), WORKSPACE_NAME, "workspace")
        if found is None and not self.apply:
            print(f"  workspace {WORKSPACE_NAME!r}: missing, setup creates it")
            return None
        if found is None:
            print(f"  workspace {WORKSPACE_NAME!r}: missing, creating it")
            self.rec.save("workspace-created", self.obj([WORKSPACES, "create", "--name", WORKSPACE_NAME],
                                                        "workspace create"))
            found = one_named(self.items([WORKSPACES, "list"], "workspace list"), WORKSPACE_NAME, "workspace")
            if found is None:
                raise ReleaseError(f"workspace {WORKSPACE_NAME!r} was created but the list does not show it")
        wid = found["id"]
        back = self.obj([WORKSPACES, "retrieve", "--workspace-id", wid], f"workspace {wid}")
        self.rec.save("workspace", back)
        if back.get("name") != WORKSPACE_NAME or back.get("archived_at"):
            raise ReleaseError(f"workspace {wid} read back as {back.get('name')!r}, archived_at {back.get('archived_at')!r}")
        print(f"  [ok] workspace {WORKSPACE_NAME!r}: {wid}")
        return wid

    def membership(self, wid: str | None, service_account_id: str) -> None:
        if wid is None:
            print(f"  service account {service_account_id}: setup adds it to the new workspace as {WORKSPACE_ROLE}")
            return

        def members() -> list[dict]:
            return self.items([MEMBERS, "list", "--workspace-id", wid], f"members of {wid}")

        if not is_member(members(), service_account_id):
            if not self.apply:
                print(f"  service account {service_account_id}: not in {wid}, setup adds it as {WORKSPACE_ROLE}")
                return
            print(f"  service account {service_account_id}: not in {wid}, adding it as {WORKSPACE_ROLE}")
            self.console.call([MEMBERS, "add", "--workspace-id", wid, "--service-account-id", service_account_id,
                               "--workspace-role", WORKSPACE_ROLE, "--format", "json"], "service account add")
            if not is_member(members(), service_account_id):
                raise ReleaseError(f"service account {service_account_id} was added but {wid} does not list it")
        print(f"  [ok] service account {service_account_id} is a member of {wid}")

    def rule(self, wid: str | None, issuer_id: str, service_account_id: str) -> str | None:
        found = one_named(self.items([release.Console.RULES, "list"], "rule list"), RULE_NAME, "rule")
        create = ["--name", RULE_NAME, "--issuer-id", issuer_id,
                  "--match", json.dumps(EXPECTED_MATCH, separators=(",", ":")), "--oauth-scope", OAUTH_SCOPE,
                  "--target", json.dumps({"type": "service_account", "service_account_id": service_account_id},
                                         separators=(",", ":")),
                  "--workspace-id", wid or "<new workspace id>", "--token-lifetime-seconds", str(TOKEN_LIFETIME_S),
                  "--description", "Self-review of PRs to OperationCode/.github (spec: Self-review rule)"]
        if found is None and not self.apply:
            print(f"  rule {RULE_NAME!r}: missing, setup creates it with:\n    ant {release.Console.RULES} create "
                  + " ".join(create))
            return None
        if found is None:
            print(f"  rule {RULE_NAME!r}: missing, creating it")
            self.rec.save("rule-created", self.obj([release.Console.RULES, "create", *create], "rule create"))
            found = one_named(self.items([release.Console.RULES, "list"], "rule list"), RULE_NAME, "rule")
            if found is None:
                raise ReleaseError(f"rule {RULE_NAME!r} was created but the list does not show it")
        rid = release.validate_rule_id(found.get("id"))
        back = self.console.retrieve(rid)
        self.rec.save("rule", back)
        problems = rule_problems(back, workspace_id=wid or "<new workspace id>", issuer_id=issuer_id,
                                 service_account_id=service_account_id)
        if problems:
            raise ReleaseError(f"rule {rid} {RULE_NAME!r} is not as the spec says ({'; '.join(problems)}); this "
                               "tool never edits a rule: fix or archive it in the Console, then run again")
        print(f"  [ok] rule {RULE_NAME!r}: {rid}, every field as the spec says")
        return rid


def cmd(run: release.Runner, *, apply: bool) -> int:
    text = ANALYZE_FILE.read_text(encoding="utf-8")
    service_account_id = analyze_constant(text, "ANTHROPIC_SERVICE_ACCOUNT_ID")
    if analyze_constant(text, "ANTHROPIC_FEDERATION_RULE_ID") != release.PROD_RULE_ID:
        raise ReleaseError("analyze.py does not name R1; this tool runs on a checkout of main")
    analyze_constant(text, CONSTANT)  # fail before any login when the line is missing
    rec = release.Records(f"self-review-{'setup' if apply else 'plan'}")
    print(f"{'Self-review setup (creates what is missing, no prompt)' if apply else 'Self-review plan (read-only)'}"
          "\n\nConsole:")
    for resource, commands in ANT_COMMANDS:
        release.check_ant(run, resource, commands)
    with release.ephemeral_console(run) as console:
        s = Setup(console, rec, apply=apply)
        issuer = s.r1(service_account_id)
        wid = s.workspace()
        s.membership(wid, service_account_id)
        rule_id = s.rule(wid, issuer, service_account_id)
    print(f"\n{spend_limit_steps()}\nRecords: {rec.dir}")
    if rule_id is None:
        print("Plan OK. Nothing was changed.")
        return 0
    new = set_rule_id(text, rule_id)
    if not apply:
        print(f"Plan OK. Nothing was changed. analyze.py: {CONSTANT} "
              + ("already names it." if new == text else f"would be set to {rule_id}."))
        return 0
    if new != text:
        ANALYZE_FILE.write_text(new, encoding="utf-8")
    print(f"\nR-self is {rule_id}. analyze.py {CONSTANT} {'set' if new != text else 'already named it'} "
          "(working tree, not committed). Review `git diff`, then open a PR.")
    return 0


def main(argv: Sequence[str] | None = None, run: release.Runner | None = None) -> int:
    run = run or subprocess.run
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("cmd", choices=("plan", "setup"))
    args = p.parse_args(argv)
    return release.run_guarded(
        lambda: cmd(run, apply=args.cmd == "setup"),
        lambda: "Interrupted. The setup only creates what is missing: run `make self-review-plan` "
                "to see the state, then `make self-review-setup` again.")


if __name__ == "__main__":
    sys.exit(main())
