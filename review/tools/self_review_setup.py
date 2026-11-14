"""Owner-run setup of the self-review federation rule R-self.

    make self-review-plan     read-only: shows what the setup would create
    make self-review-setup    create what is missing, read it back, write the
                              rule ID into analyze.py (working tree, no commit)

Spec: docs/claude-review-design.md, "Self-review rule" in "Auth and cost".
All reads and checks run before any write. The tool creates only what is
missing; it never edits or archives an object, so running it again is safe:

    1. read R1: R-self uses its issuer; its service account must be the one
       analyze.py names (R-self uses the same service account)
    2. read: workspace WORKSPACE_NAME by name, the service account's role in
       it (must be WORKSPACE_ROLE), rule RULE_NAME by name (every field must
       be as the spec says). An unknown list shape, a wrong role or a wrong
       rule refuses here, before any write
    3. setup only: create the workspace, add the service account as
       WORKSPACE_ROLE, create the rule, each only when missing, and read each
       back and check it
    4. write the rule ID into SELF_REVIEW_FEDERATION_RULE_ID in analyze.py,
       atomically, only when the file did not change during the run

The workspace spend limit has no `ant` command, so the tool prints the
Console steps for it. Login, logout, cleanup and exit codes are release.py's
(an ephemeral org:admin `ant` session, cleared on every exit path).

Not run in CI or any workflow (it holds an Anthropic org:admin login).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
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

# The fields each list item must have, as non-empty strings. Any other shape
# (another envelope, an item without them) refuses before a create or add.
ITEM_FIELDS = {"workspace": ("id", "name"), "rule": ("id", "name"),
               "member": ("service_account_id", "workspace_role")}
PAGE_KEYS = frozenset({"data", "has_more", "first_id", "last_id", "next_page"})


def parse_items(text: str, kind: str, what: str) -> list[dict]:
    """Items of a `--format jsonl` list: one item per line, or a whole page
    (`{"data": [...]}` with no more pages). Every item must have ITEM_FIELDS."""
    items: list[dict] = []
    for line in text.splitlines():
        if not line.strip():
            continue
        obj = release._json(line, what)
        batch = [obj]
        if isinstance(obj, dict) and "data" in obj:
            if set(obj) - PAGE_KEYS or not isinstance(obj["data"], list):
                raise ReleaseError(f"{what}: unknown page shape (keys {sorted(obj)}); fix the tool before a write")
            if obj.get("has_more") or obj.get("next_page"):
                raise ReleaseError(f"{what}: the list has more pages than were read")
            batch = obj["data"]
        for item in batch:
            if not isinstance(item, dict) or not all(isinstance(item.get(f), str) and item[f]
                                                     for f in ITEM_FIELDS[kind]):
                raise ReleaseError(f"{what}: an item is not a {kind} with {', '.join(ITEM_FIELDS[kind])}; "
                                   "unknown response shape, fix the tool before a write")
            items.append(item)
    return items


def one_named(items: list[dict], name: str, what: str) -> dict | None:
    """The one live item called `name`, None when there is none. Several refuse."""
    hits = [i for i in items if i["name"] == name and not i.get("archived_at")]
    if len(hits) > 1:
        raise ReleaseError(f"{len(hits)} {what}s are named {name!r}; archive the extra ones in the Console, then run again")
    return hits[0] if hits else None


def member_role(items: list[dict], service_account_id: str) -> str | None:
    """The workspace role of the service account, None when it is no member."""
    roles = [i["workspace_role"] for i in items if i["service_account_id"] == service_account_id]
    if len(roles) > 1:
        raise ReleaseError(f"service account {service_account_id} is listed {len(roles)} times")
    return roles[0] if roles else None


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
    """`cmd` runs every read and check (`r1`, `find_workspace`, `role`,
    `find_rule`) before `write`, so an unknown response shape or a wrong
    object refuses before any create or add."""

    def __init__(self, console: release.Console, rec: release.Records):
        self.console, self.rec = console, rec

    def obj(self, args: Sequence[str], what: str) -> dict:
        got = release._json(self.console.call([*args, "--format", "json"], what), what)
        if not isinstance(got, dict) or not got.get("id"):
            raise ReleaseError(f"{what}: the response is not an object with an id")
        return got

    def items(self, args: Sequence[str], kind: str, what: str) -> list[dict]:
        out = self.console.call([*args, "--format", "jsonl", "--max-items", "-1"], what)
        self.rec.save(what.replace(" ", "-"), out)
        return parse_items(out, kind, what)

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

    def find_workspace(self) -> str | None:
        found = one_named(self.items([WORKSPACES, "list"], "workspace", "workspace list"), WORKSPACE_NAME, "workspace")
        if found is None:
            return None
        wid = found["id"]
        back = self.obj([WORKSPACES, "retrieve", "--workspace-id", wid], f"workspace {wid}")
        self.rec.save("workspace", back)
        if back.get("id") != wid or back.get("name") != WORKSPACE_NAME or back.get("archived_at"):
            raise ReleaseError(f"workspace {wid} read back as {back.get('name')!r}, archived_at {back.get('archived_at')!r}")
        print(f"  [ok] workspace {WORKSPACE_NAME!r}: {wid}")
        return wid

    def role(self, wid: str, service_account_id: str) -> str | None:
        """The service account's role in `wid`; refuses any role but WORKSPACE_ROLE."""
        role = member_role(self.items([MEMBERS, "list", "--workspace-id", wid], "member", f"members of {wid}"),
                           service_account_id)
        if role not in (None, WORKSPACE_ROLE):
            raise ReleaseError(f"service account {service_account_id} has role {role!r} in {wid}, not "
                               f"{WORKSPACE_ROLE}; this tool never edits a membership: fix it in the Console")
        if role:
            print(f"  [ok] service account {service_account_id} is a member of {wid} as {role}")
        return role

    def find_rule(self, wid: str | None, issuer_id: str, service_account_id: str) -> str | None:
        found = one_named(self.items([release.Console.RULES, "list"], "rule", "rule list"), RULE_NAME, "rule")
        if found is None:
            return None
        rid = release.validate_rule_id(found["id"])
        back = self.console.retrieve(rid)
        self.rec.save("rule", back)
        problems = rule_problems(back, workspace_id=wid or "<missing workspace>", issuer_id=issuer_id,
                                 service_account_id=service_account_id)
        if problems:
            raise ReleaseError(f"rule {rid} {RULE_NAME!r} is not as the spec says ({'; '.join(problems)}); this "
                               "tool never edits a rule: fix or archive it in the Console, then run again")
        print(f"  [ok] rule {RULE_NAME!r}: {rid}, every field as the spec says")
        return rid

    def create_args(self, wid: str, issuer_id: str, service_account_id: str) -> list[str]:
        return ["--name", RULE_NAME, "--issuer-id", issuer_id,
                "--match", json.dumps(EXPECTED_MATCH, separators=(",", ":")), "--oauth-scope", OAUTH_SCOPE,
                "--target", json.dumps({"type": "service_account", "service_account_id": service_account_id},
                                       separators=(",", ":")),
                "--workspace-id", wid, "--token-lifetime-seconds", str(TOKEN_LIFETIME_S),
                "--description", "Self-review of PRs to OperationCode/.github (spec: Self-review rule)"]

    def write(self, wid: str | None, role: str | None, rule_id: str | None, issuer_id: str,
              service_account_id: str) -> str:
        """Create what is missing, in order, and read each back. Returns the rule ID."""
        if wid is None:
            print(f"  workspace {WORKSPACE_NAME!r}: missing, creating it")
            self.rec.save("workspace-created", self.obj([WORKSPACES, "create", "--name", WORKSPACE_NAME],
                                                        "workspace create"))
            wid = self.find_workspace()
            if wid is None:
                raise ReleaseError(f"workspace {WORKSPACE_NAME!r} was created but the list does not show it")
        if role is None:
            print(f"  service account {service_account_id}: not in {wid}, adding it as {WORKSPACE_ROLE}")
            self.console.call([MEMBERS, "add", "--workspace-id", wid, "--service-account-id", service_account_id,
                               "--workspace-role", WORKSPACE_ROLE, "--format", "json"], "service account add")
            if self.role(wid, service_account_id) != WORKSPACE_ROLE:
                raise ReleaseError(f"service account {service_account_id} was added but {wid} does not list it "
                                   f"as {WORKSPACE_ROLE}")
        if rule_id is None:
            print(f"  rule {RULE_NAME!r}: missing, creating it")
            self.rec.save("rule-created", self.obj([release.Console.RULES, "create",
                                                    *self.create_args(wid, issuer_id, service_account_id)],
                                                   "rule create"))
            rule_id = self.find_rule(wid, issuer_id, service_account_id)
            if rule_id is None:
                raise ReleaseError(f"rule {RULE_NAME!r} was created but the list does not show it")
        return rule_id


def write_analyze(path: Path, original: str, new: str) -> None:
    """Replace analyze.py atomically, only when it still holds `original`
    (the text read at the start): an edit made during the login is kept."""
    if path.read_text(encoding="utf-8") != original:
        raise ReleaseError(f"{path} changed during the run, so it was not written. Run `make self-review-setup` "
                           "again: it finds the rule and only writes the ID")
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(new)
        os.chmod(tmp, stat.S_IMODE(path.stat().st_mode))
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def cmd(run: release.Runner, *, apply: bool) -> int:
    text = ANALYZE_FILE.read_text(encoding="utf-8")
    service_account_id = analyze_constant(text, "ANTHROPIC_SERVICE_ACCOUNT_ID")
    if analyze_constant(text, "ANTHROPIC_FEDERATION_RULE_ID") != release.PROD_RULE_ID:
        raise ReleaseError("analyze.py does not name R1; this tool runs on a checkout of main")
    analyze_constant(text, CONSTANT)  # fail before any login when the line is missing
    rec = release.Records(f"self-review-{'setup' if apply else 'plan'}")
    print(f"{'Self-review setup (creates what is missing, no prompt)' if apply else 'Self-review plan (read-only)'}"
          "\n\nConsole (reads and checks):")
    for resource, commands in ANT_COMMANDS:
        release.check_ant(run, resource, commands)
    with release.ephemeral_console(run) as console:
        s = Setup(console, rec)
        issuer = s.r1(service_account_id)
        wid = s.find_workspace()
        role = s.role(wid, service_account_id) if wid else None
        rule_id = s.find_rule(wid, issuer, service_account_id)
        if rule_id and wid is None:
            raise ReleaseError(f"rule {RULE_NAME!r} exists but workspace {WORKSPACE_NAME!r} does not")
        if not apply:
            if wid is None:
                print(f"  workspace {WORKSPACE_NAME!r}: missing, setup creates it")
            if role is None:
                print(f"  service account {service_account_id}: setup adds it to the workspace as {WORKSPACE_ROLE}")
            if rule_id is None:
                print(f"  rule {RULE_NAME!r}: missing, setup creates it with:\n    ant {release.Console.RULES} "
                      "create " + " ".join(s.create_args(wid or "<new workspace id>", issuer, service_account_id)))
        else:
            print("\nConsole (creates what is missing):")
            rule_id = s.write(wid, role, rule_id, issuer, service_account_id)
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
        write_analyze(ANALYZE_FILE, text, new)
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
