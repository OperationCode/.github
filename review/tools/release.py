"""Owner-run release tool: move the production federation rule and the ruleset pins.

    make release-plan SHA=<sha>              read-only; NO_CONSOLE=1 skips the Console reads
    make release SHA=<sha>                   plan, typed confirmation, then apply and read back
    make release-rule-test RULE=<id> SHA=<sha>   Console-only edit of a scratch rule

Spec: docs/claude-review-design.md, "Each release" in "Auth and cost". The steps
of a release, in this order:

    1. preconditions (fail closed): SHA is 40-hex and on main; test.yml and the
       release eval.yml run at SHA concluded success; analyze.py at SHA names
       rule R1; the caller is an org owner; each ruleset has exactly one
       workflows entry for claude-review.yml, with a sha and no ref
    2. Console: GET R1, change only the SHA suffix of
       match.claims.job_workflow_ref, POST the whole match, GET back, compare
    3. GitHub: for each ruleset, GET, change only that entry's sha, PUT the
       rules, GET back, compare

Between step 2 and the end of step 3 the rulesets still pin the old SHA and
R1 already names the new one, so a required run in that window fails closed
(authentication failed). Start a new run on each open PR after the release.
Rollback is the same command with the previous release SHA.

Credential (owner decision, no persistent admin token): the Console endpoints
take only an OAuth token with the org:admin scope; Admin API keys are refused.
This tool makes a private temp dir (0700), points ANTHROPIC_CONFIG_DIR at it
for its own `ant` subprocesses only, removes every other ANTHROPIC_* variable
from their environment, runs `ant auth login --profile admin --scope org:admin`
itself (the owner completes it in the browser), and on every exit path runs
`ant auth logout --all` and deletes the dir. The tool never reads, prints,
stores or exports a token. GitHub calls use `gh api` with the owner's gh login.

Before and after JSON goes to release-records/ at the repo root (git-ignored).
It holds rule and ruleset objects only, no credential.

Not imported by production code and not run in CI or any workflow: it holds
both an Anthropic admin login and GitHub write, which no job may hold.
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

REPO = "OperationCode/.github"
ORG = "OperationCode"
WORKFLOW_PATH = ".github/workflows/claude-review.yml"
WORKFLOW_REPO_ID = 1432342572
JOB_WORKFLOW_REF_PREFIX = f"{REPO}/{WORKFLOW_PATH}@"
PROD_RULE_ID = "fdrl_01N2ZktTiVKqUvvXwywBFfys"
ANALYZE_PATH = "review/src/oc_review/analyze.py"
# Every ruleset that requires the workflow: the pilot ruleset and the scratch
# test ruleset. Add the org ruleset here when it gets the pin (phase 6).
RULESETS: tuple[tuple[int, str], ...] = ((26132750, "claude-review-pilot"), (25835887, "p0-required-workflow"))
RELEASE_WORKFLOWS = ("test.yml", "eval.yml")
RULE_ID_RE = re.compile(r"^fdrl_[A-Za-z0-9]{24}$")
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
RECORDS = Path(__file__).resolve().parents[2] / "release-records"
# Server-set fields that may change on any write.
VOLATILE_KEYS = frozenset({"updated_at", "updated_by_actor_id"})
_REDACT_RE = re.compile(r"(?i)(bearer\s+|sk-ant-)[^\s\"']+")

Runner = Callable[..., subprocess.CompletedProcess]


class ReleaseError(Exception):
    """A refusal: the tool stops and changes nothing more."""


# ---------------------------------------------------------------- pure logic


def validate_sha(sha: str | None) -> str:
    if not sha or not SHA_RE.match(sha):
        raise ReleaseError(f"SHA must be 40 lowercase hex characters, got {sha!r}")
    return sha


def validate_rule_id(rule_id: str | None) -> str:
    if not rule_id or not RULE_ID_RE.match(rule_id):
        raise ReleaseError(f"RULE must look like fdrl_ plus 24 characters, got {rule_id!r}")
    return rule_id


def _strip_nulls(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _strip_nulls(v) for k, v in value.items() if v is not None}
    if isinstance(value, list):
        return [_strip_nulls(v) for v in value]
    return value


def patch_match(match: Any, sha: str, *, prefix: str | None = None) -> dict:
    """The whole match object to POST: a copy of `match` with only the SHA
    suffix of claims.job_workflow_ref changed. Null keys are dropped, because
    the POST replaces match as a whole and an unset matcher is the same as an
    absent one. With `prefix`, the ref before the SHA must equal it."""
    if not isinstance(match, dict):
        raise ReleaseError("rule has no match object")
    claims = match.get("claims")
    if not isinstance(claims, dict):
        raise ReleaseError("rule match has no claims object")
    ref = claims.get("job_workflow_ref")
    if not isinstance(ref, str) or "@" not in ref:
        raise ReleaseError(f"rule has no job_workflow_ref claim of the form <path>@<sha>: {ref!r}")
    head, _, old = ref.rpartition("@")
    if not SHA_RE.match(old):
        raise ReleaseError(f"job_workflow_ref does not end in a 40-hex SHA: {ref!r}")
    if prefix is not None and head + "@" != prefix:
        raise ReleaseError(f"job_workflow_ref is {ref!r}, expected {prefix}<sha>")
    new = _strip_nulls(copy.deepcopy(match))
    new["claims"]["job_workflow_ref"] = f"{head}@{sha}"
    return new


def diff_paths(a: Any, b: Any, path: str = "") -> list[str]:
    """Every path where a and b differ. A null and a missing key are equal."""
    if isinstance(a, dict) and isinstance(b, dict):
        out: list[str] = []
        for key in sorted(set(a) | set(b), key=str):
            out += diff_paths(a.get(key), b.get(key), f"{path}.{key}" if path else str(key))
        return out
    if isinstance(a, list) and isinstance(b, list):
        if len(a) != len(b):
            return [f"{path} (length {len(a)} -> {len(b)})"]
        out = []
        for i, (x, y) in enumerate(zip(a, b, strict=True)):
            out += diff_paths(x, y, f"{path}[{i}]")
        return out
    return [] if a == b else [path or "(root)"]


def _without_volatile(obj: dict) -> dict:
    return {k: v for k, v in obj.items() if k not in VOLATILE_KEYS}


def compare_rule(before: dict, after: dict, expected_match: dict) -> list[str]:
    """Mismatches after a rule update: match must equal what was sent, and
    every other field must equal the before state."""
    problems = [f"match.{p}" for p in diff_paths(expected_match, after.get("match"))]
    rest_before = {k: v for k, v in _without_volatile(before).items() if k != "match"}
    rest_after = {k: v for k, v in _without_volatile(after).items() if k != "match"}
    problems += diff_paths(rest_before, rest_after)
    return problems


def workflow_entry_index(ruleset: dict) -> tuple[int, int]:
    """(rule index, workflow index) of the one entry for the central workflow.
    Refuses zero or several entries, and an entry with a ref."""
    hits = []
    for ri, rule in enumerate(ruleset.get("rules") or []):
        if not isinstance(rule, dict) or rule.get("type") != "workflows":
            continue
        for wi, wf in enumerate((rule.get("parameters") or {}).get("workflows") or []):
            if wf.get("repository_id") == WORKFLOW_REPO_ID and wf.get("path") == WORKFLOW_PATH:
                hits.append((ri, wi))
    rid = ruleset.get("id")
    if len(hits) != 1:
        raise ReleaseError(f"ruleset {rid}: expected 1 workflows entry for {WORKFLOW_PATH}, found {len(hits)}")
    ri, wi = hits[0]
    wf = ruleset["rules"][ri]["parameters"]["workflows"][wi]
    if wf.get("ref") is not None:
        raise ReleaseError(f"ruleset {rid}: the workflow entry has a ref ({wf['ref']!r}); the pin must be a sha only")
    if not isinstance(wf.get("sha"), str) or not SHA_RE.match(wf["sha"]):
        raise ReleaseError(f"ruleset {rid}: the workflow entry has no 40-hex sha")
    return ri, wi


def ruleset_pin(ruleset: dict) -> str:
    ri, wi = workflow_entry_index(ruleset)
    return ruleset["rules"][ri]["parameters"]["workflows"][wi]["sha"]


def patch_ruleset(ruleset: dict, sha: str) -> dict:
    """The PUT body: every rule as read, with only the pinned sha changed."""
    ri, wi = workflow_entry_index(ruleset)
    rules = copy.deepcopy(ruleset["rules"])
    rules[ri]["parameters"]["workflows"][wi]["sha"] = sha
    return {"rules": rules}


def compare_ruleset(before: dict, after: dict, sha: str) -> list[str]:
    """Mismatches after a pin move: the pin must be `sha` with no ref, and
    every other field must equal the before state."""
    try:
        ri, wi = workflow_entry_index(after)
    except ReleaseError as e:
        return [str(e)]
    problems = []
    if after["rules"][ri]["parameters"]["workflows"][wi]["sha"] != sha:
        problems.append(f"rules[{ri}].parameters.workflows[{wi}].sha is not {sha}")
    expected = copy.deepcopy(before)
    expected["rules"] = patch_ruleset(before, sha)["rules"]
    problems += diff_paths(_without_volatile(expected), _without_volatile(after))
    return problems


def redact(text: str) -> str:
    return _REDACT_RE.sub(lambda m: m.group(1) + "[redacted]", text)


# ---------------------------------------------------------------- subprocess wrappers


def _check(cp: subprocess.CompletedProcess, what: str) -> str:
    if cp.returncode != 0:
        err = redact((cp.stderr or "").strip())[:2000]
        raise ReleaseError(f"{what} failed (exit {cp.returncode}): {err}")
    return cp.stdout or ""


def _json(text: str, what: str) -> Any:
    try:
        return json.loads(text)
    except ValueError as e:
        raise ReleaseError(f"{what}: output is not JSON ({e})") from None


class GitHub:
    def __init__(self, run: Runner):
        self.run = run

    def get(self, path: str) -> Any:
        cp = self.run(["gh", "api", "-H", "Accept: application/vnd.github+json", path],
                      capture_output=True, text=True)
        return _json(_check(cp, f"gh api GET {path}"), f"GET {path}")

    def put(self, path: str, body: dict) -> Any:
        cp = self.run(["gh", "api", "-X", "PUT", "-H", "Accept: application/vnd.github+json", path, "--input", "-"],
                      input=json.dumps(body), capture_output=True, text=True)
        return _json(_check(cp, f"gh api PUT {path}"), f"PUT {path}")


def ant_env(config_dir: str) -> dict[str, str]:
    """Environment for `ant`: no ANTHROPIC_* from the caller (an API key or
    auth token overrides every profile), and the private config dir."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("ANTHROPIC_")}
    env["ANTHROPIC_CONFIG_DIR"] = config_dir
    return env


class Console:
    """`ant` calls, all inside one private config dir."""

    RULES = "organization:federation:rules"

    def __init__(self, run: Runner, config_dir: str):
        self.run = run
        self.env = ant_env(config_dir)

    def _ant(self, args: Sequence[str], what: str) -> str:
        cp = self.run(["ant", *args], env=self.env, capture_output=True, text=True)
        return _check(cp, what)

    def login(self) -> None:
        print("Console: opening the browser for `ant auth login --profile admin --scope org:admin`.")
        print("         Log in as an org admin or owner. The token stays in a temp dir and is removed at exit.")
        cp = self.run(["ant", "auth", "login", "--profile", "admin", "--scope", "org:admin"], env=self.env)
        if cp.returncode != 0:
            raise ReleaseError(f"ant auth login failed (exit {cp.returncode}); not logged in to the Console")

    def logout(self) -> bool:
        try:
            cp = self.run(["ant", "auth", "logout", "--all"], env=self.env, capture_output=True, text=True)
        except OSError:
            return False
        return cp.returncode == 0

    def retrieve(self, rule_id: str) -> dict:
        out = self._ant([self.RULES, "retrieve", "--federation-rule-id", rule_id, "--format", "json"],
                        f"ant {self.RULES} retrieve {rule_id}")
        rule = _json(out, f"rule {rule_id}")
        if not isinstance(rule, dict) or rule.get("id", rule_id) != rule_id:
            raise ReleaseError(f"rule {rule_id}: the read returned a different object")
        return rule

    def update(self, rule_id: str, match: dict) -> dict:
        out = self._ant([self.RULES, "update", "--federation-rule-id", rule_id,
                         "--match", json.dumps(match, separators=(",", ":")), "--format", "json"],
                        f"ant {self.RULES} update {rule_id}")
        return _json(out, f"update of rule {rule_id}")


def check_ant(run: Runner) -> None:
    """`ant` is installed and has the rule commands this tool calls. The
    getter name `retrieve` is not confirmed by the docs, so check it here."""
    empty = tempfile.mkdtemp(prefix="oc-release-ant-help-")  # no profile in it
    try:
        cp = run(["ant", Console.RULES, "--help"], env=ant_env(empty), capture_output=True, text=True)
    except FileNotFoundError:
        raise ReleaseError("ant is not installed, so the Console cannot be read. Install it with "
                           "`brew install anthropics/tap/ant`, or run the plan with NO_CONSOLE=1 "
                           "to skip the Console part") from None
    finally:
        shutil.rmtree(empty, ignore_errors=True)
    text = (cp.stdout or "") + (cp.stderr or "")
    missing = [c for c in ("retrieve", "update") if not re.search(rf"\b{c}\b", text)]
    if cp.returncode != 0 or missing:
        raise ReleaseError(f"`ant {Console.RULES} --help` does not list {missing or 'its commands'}; "
                           "this ant build does not match the tool; read the help and fix the Console class")


@contextmanager
def ephemeral_console(run: Runner) -> Iterator[Console]:
    """Log in to the Console in a fresh 0700 dir; log out and delete it on
    every exit path."""
    config_dir = tempfile.mkdtemp(prefix="oc-release-ant-")
    os.chmod(config_dir, 0o700)
    console = Console(run, config_dir)
    try:
        console.login()
        yield console
    finally:
        ok = console.logout()
        shutil.rmtree(config_dir, ignore_errors=True)
        if not ok:
            print("WARNING: `ant auth logout --all` failed. The local token files are deleted, "
                  "but the session may stay valid until it expires.", file=sys.stderr)
        print("Console: logged out, temp config dir removed.")


# ---------------------------------------------------------------- records


class Records:
    def __init__(self, label: str, root: Path | None = None):
        stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        self.dir = (root or RECORDS) / f"{stamp}-{label}"

    def save(self, name: str, obj: Any) -> None:
        self.dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        (self.dir / f"{name}.json").write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")


# ---------------------------------------------------------------- preconditions


def github_preconditions(gh: GitHub, sha: str, rule_id: str) -> list[str]:
    """Read-only checks. Returns the failures (empty when all pass)."""
    fails: list[str] = []

    def check(ok: bool, good: str, bad: str) -> None:
        print(f"  [{'ok' if ok else 'FAIL'}] {good if ok else bad}")
        if not ok:
            fails.append(bad)

    try:
        cmp = gh.get(f"repos/{REPO}/compare/{sha}...main")
        status = cmp.get("status")
        check(status in ("ahead", "identical"), f"{sha} is on main ({status})",
              f"{sha} is not on main (compare status {status!r})")
        if status == "ahead":
            print(f"         note: main is {cmp.get('ahead_by')} commit(s) past {sha[:12]} (a rollback, or an old SHA)")
    except ReleaseError as e:
        check(False, "", f"cannot compare {sha} with main: {e}")

    for wf in RELEASE_WORKFLOWS:
        try:
            runs = gh.get(f"repos/{REPO}/actions/workflows/{wf}/runs?head_sha={sha}&per_page=100").get("workflow_runs") or []
        except ReleaseError as e:
            check(False, "", f"cannot read {wf} runs: {e}")
            continue
        runs = [r for r in runs if r.get("path") == f".github/workflows/{wf}"]
        good = [r for r in runs if r.get("status") == "completed" and r.get("conclusion") == "success"]
        check(bool(good), f"{wf} succeeded at {sha[:12]} (run {good[0]['id'] if good else ''})",
              f"no successful {wf} run at {sha} ({len(runs)} run(s) found)")

    try:
        meta = gh.get(f"repos/{REPO}/contents/{ANALYZE_PATH}?ref={sha}")
        text = base64.b64decode(meta.get("content") or "").decode("utf-8", "replace")
        named = re.search(r'^ANTHROPIC_FEDERATION_RULE_ID\s*=\s*"([^"]+)"', text, re.M)
        got = named.group(1) if named else None
        check(got == rule_id, f"analyze.py at {sha[:12]} names rule {rule_id}",
              f"analyze.py at {sha} names rule {got!r}, not {rule_id}")
    except ReleaseError as e:
        check(False, "", f"cannot read {ANALYZE_PATH} at {sha}: {e}")

    try:
        login = gh.get("user").get("login")
        role = gh.get(f"orgs/{ORG}/memberships/{login}").get("role")
        check(role == "admin", f"gh user {login} is an {ORG} owner",
              f"gh user {login} has org role {role!r}; moving a ruleset pin needs an org owner")
    except ReleaseError as e:
        check(False, "", f"cannot read the gh user or org role: {e}")
    return fails


# ---------------------------------------------------------------- flows


def plan_rulesets(gh: GitHub, sha: str, rec: Records) -> tuple[list[tuple[int, str, dict]], list[str]]:
    """GET each ruleset and print its pin change. Returns (ruleset id, name,
    before) for each, and the failures."""
    out, fails = [], []
    for rid, name in RULESETS:
        try:
            before = gh.get(f"orgs/{ORG}/rulesets/{rid}")
            pin = ruleset_pin(before)
        except ReleaseError as e:
            print(f"  [FAIL] ruleset {rid} {name}: {e}")
            fails.append(str(e))
            continue
        rec.save(f"ruleset-{rid}-before", before)
        state = "no change" if pin == sha else f"{pin} -> {sha}"
        print(f"  ruleset {rid} {before.get('name')!r} ({before.get('enforcement')}): pin {state}")
        out.append((rid, name, before))
    return out, fails


def plan_rule(console: Console, rule_id: str, sha: str, rec: Records, prefix: str | None) -> tuple[dict, dict]:
    before = console.retrieve(rule_id)
    rec.save(f"rule-{rule_id}-before", before)
    match = patch_match(before.get("match"), sha, prefix=prefix)
    old = before["match"]["claims"]["job_workflow_ref"]
    state = "no change" if old == match["claims"]["job_workflow_ref"] else f"{old}\n      -> {match['claims']['job_workflow_ref']}"
    print(f"  rule {rule_id} {before.get('name')!r}: job_workflow_ref {state}")
    print(f"  POST body: {json.dumps({'match': match}, sort_keys=True)}")
    return before, match


def apply_rule(console: Console, rule_id: str, before: dict, match: dict, rec: Records) -> None:
    now = console.retrieve(rule_id)
    changed = diff_paths(_without_volatile(before), _without_volatile(now))
    if changed:
        raise ReleaseError(f"rule {rule_id} changed since the plan read ({', '.join(changed)}); run again")
    if before["match"] == match or _strip_nulls(before["match"]) == match:
        print(f"  rule {rule_id}: already at the SHA, no POST")
    else:
        rec.save(f"rule-{rule_id}-response", console.update(rule_id, match))
    after = console.retrieve(rule_id)
    rec.save(f"rule-{rule_id}-after", after)
    problems = compare_rule(before, after, match)
    if problems:
        raise ReleaseError(f"rule {rule_id} read-back mismatch: {', '.join(problems)}")
    print(f"  [ok] rule {rule_id} read back: only job_workflow_ref changed")


def apply_ruleset(gh: GitHub, rid: int, before: dict, sha: str, rec: Records) -> None:
    now = gh.get(f"orgs/{ORG}/rulesets/{rid}")
    changed = diff_paths(_without_volatile(before), _without_volatile(now))
    if changed:
        raise ReleaseError(f"ruleset {rid} changed since the plan read ({', '.join(changed)}); run again")
    if ruleset_pin(before) == sha:
        print(f"  ruleset {rid}: already at the SHA, no PUT")
    else:
        body = patch_ruleset(before, sha)
        rec.save(f"ruleset-{rid}-body", body)
        gh.put(f"orgs/{ORG}/rulesets/{rid}", body)
    after = gh.get(f"orgs/{ORG}/rulesets/{rid}")
    rec.save(f"ruleset-{rid}-after", after)
    problems = compare_ruleset(before, after, sha)
    if problems:
        raise ReleaseError(f"ruleset {rid} read-back mismatch: {', '.join(problems)}")
    print(f"  [ok] ruleset {rid} read back: only the pin changed (repository_id, path, sha, no ref)")


def confirm(sha: str, ask: Callable[[str], str], what: str) -> None:
    token = f"release {sha[:12]}"
    print(f"\nThis will {what}.")
    answer = ask(f"Type '{token}' to apply, anything else to stop: ").strip()
    if answer != token:
        raise ReleaseError("not confirmed; nothing changed")


def cmd_plan(args, run: Runner, ask, *, apply: bool) -> int:
    sha = validate_sha(args.sha)
    gh = GitHub(run)
    rec = Records(f"{'release' if apply else 'plan'}-{sha[:12]}")
    print(f"Release {'' if apply else 'plan '}for {sha}\n\nPreconditions (GitHub, read-only):")
    fails = github_preconditions(gh, sha, PROD_RULE_ID)
    print("\nRulesets (GitHub, read-only):")
    rulesets, rs_fails = plan_rulesets(gh, sha, rec)
    fails += rs_fails
    if apply and fails:
        raise ReleaseError(f"{len(fails)} precondition(s) failed; nothing changed")

    if args.no_console:
        if apply:
            raise ReleaseError("NO_CONSOLE is for the plan only")
        print("\nConsole: skipped (NO_CONSOLE=1). Rule R1 was not read.")
    else:
        print("\nConsole (rule R1):")
        check_ant(run)
        with ephemeral_console(run) as console:
            before, match = plan_rule(console, PROD_RULE_ID, sha, rec, JOB_WORKFLOW_REF_PREFIX)
            if apply:
                confirm(sha, ask, f"set rule {PROD_RULE_ID} to {sha[:12]}, then move {len(rulesets)} ruleset pin(s). "
                        "From the rule change until the last pin moves, required runs fail closed (auth denied)")
                print("\nApply: Console rule first, then the ruleset pins.")
                apply_rule(console, PROD_RULE_ID, before, match, rec)
        if apply:
            for rid, _, before_rs in rulesets:
                apply_ruleset(gh, rid, before_rs, sha, rec)
            print(f"\nReleased {sha}. Records: {rec.dir}")
            print("Next: start a new run on each open PR (push, or close and reopen). Do not re-run old runs.")
            return 0
    print(f"\nRecords: {rec.dir}")
    if fails:
        print(f"PLAN FAILED: {len(fails)} precondition(s) failed:", file=sys.stderr)
        for f in fails:
            print(f"  - {f}", file=sys.stderr)
        return 1
    print("Plan OK. Nothing was changed.")
    return 0


def cmd_rule_test(args, run: Runner, ask) -> int:
    sha = validate_sha(args.sha)
    rule_id = validate_rule_id(args.rule)
    if rule_id == PROD_RULE_ID:
        raise ReleaseError("release-rule-test refuses the production rule R1; use `make release`")
    rec = Records(f"rule-test-{rule_id}-{sha[:12]}")
    print(f"Rule test: {rule_id} -> {sha}\n\nConsole:")
    check_ant(run)
    with ephemeral_console(run) as console:
        before, match = plan_rule(console, rule_id, sha, rec, None)
        confirm(sha, ask, f"set scratch rule {rule_id} to {sha[:12]}")
        apply_rule(console, rule_id, before, match, rec)
    print(f"\nRule test passed. Records: {rec.dir}")
    return 0


def _raise_on_signal(signum, _frame):
    raise KeyboardInterrupt(f"signal {signum}")


def main(argv: Sequence[str] | None = None, run: Runner | None = None, ask: Callable[[str], str] | None = None) -> int:
    run = run or subprocess.run
    ask = ask or input
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("plan", "release"):
        s = sub.add_parser(name)
        s.add_argument("--sha", required=True)
        s.add_argument("--no-console", action="store_true")
    s = sub.add_parser("rule-test")
    s.add_argument("--rule", required=True)
    s.add_argument("--sha", required=True)
    args = p.parse_args(argv)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)  # keep our lines in order with ant's output
    for sig in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, _raise_on_signal)
    try:
        if args.cmd == "rule-test":
            return cmd_rule_test(args, run, ask)
        return cmd_plan(args, run, ask, apply=args.cmd == "release")
    except ReleaseError as e:
        print(f"\nREFUSED: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted. Check the read-backs: a step may be half done.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())
