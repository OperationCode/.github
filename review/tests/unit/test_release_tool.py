"""Owner-run release tool (review/tools/release.py). No network: every gh and
ant call goes to a fake runner."""

import base64
import copy
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
_spec = importlib.util.spec_from_file_location("release_tool", ROOT / "review" / "tools" / "release.py")
release = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(release)

SHA_OLD = "96f496603d968121609abcda0e10666871de2ddf"
SHA_NEW = "3855f75" + "0" * 33
R1 = release.PROD_RULE_ID
R2 = "fdrl_01AfACzupW3U4Bx361ZUbsyR"
REF = release.JOB_WORKFLOW_REF_PREFIX


def rule(rule_id=R1, sha=SHA_OLD, prefix=REF):
    return {
        "applies_to_all_workspaces": False, "archived_at": None, "description": None,
        "id": rule_id, "issuer_id": "fdis_x", "name": "claude-review-prod-r1",
        "match": {
            "audience": None, "condition": None, "subject_prefix": "repo:OperationCode@10479364/*",
            "claims": {"event_name": "pull_request_target", "job_workflow_ref": f"{prefix}{sha}",
                       "repository_owner_id": "10479364"},
        },
        "oauth_scope": "workspace:developer",
        "target": {"service_account_id": "svac_x", "type": "service_account"},
        "token_lifetime_seconds": 600, "updated_at": "t0", "updated_by_actor_id": "user_a",
        "workspace_id": "wrkspc_x", "workspace_ids": ["wrkspc_x"],
    }


def ruleset(rid=26132750, sha=SHA_OLD):
    return {
        "id": rid, "name": "claude-review-pilot", "target": "branch", "enforcement": "active",
        "conditions": {"ref_name": {"exclude": [], "include": ["~DEFAULT_BRANCH"]},
                       "repository_id": {"repository_ids": [107068150, 135777271]}},
        "rules": [{"type": "workflows", "parameters": {"do_not_enforce_on_create": False, "workflows": [
            {"repository_id": release.WORKFLOW_REPO_ID, "path": release.WORKFLOW_PATH, "sha": sha}]}}],
        "bypass_actors": [{"actor_id": None, "actor_type": "OrganizationAdmin", "bypass_mode": "pull_request"}],
        "updated_at": "t0",
    }


# ---------------------------------------------------------------- SHA and IDs


@pytest.mark.parametrize("sha", [SHA_OLD, "0" * 40])
def test_validate_sha_accepts_40_hex(sha):
    assert release.validate_sha(sha) == sha


@pytest.mark.parametrize("sha", [None, "", SHA_OLD[:39], SHA_OLD + "0", SHA_OLD.upper(), " " + SHA_OLD,
                                 "g" * 40, "main", "refs/heads/main"])
def test_validate_sha_refuses_anything_else(sha):
    with pytest.raises(release.ReleaseError):
        release.validate_sha(sha)


@pytest.mark.parametrize("rid", [None, "", "fdrl_short", "abc_01AfACzupW3U4Bx361ZUbsyR", R2 + "x"])
def test_validate_rule_id_refuses(rid):
    with pytest.raises(release.ReleaseError):
        release.validate_rule_id(rid)


# ---------------------------------------------------------------- match patch


def test_patch_match_changes_only_the_sha_and_keeps_every_other_field():
    before = rule()
    new = release.patch_match(before["match"], SHA_NEW, prefix=REF)
    assert new["claims"]["job_workflow_ref"] == f"{REF}{SHA_NEW}"
    assert release.diff_paths(before["match"], new) == ["claims.job_workflow_ref"]
    assert new["subject_prefix"] == before["match"]["subject_prefix"]
    assert {k: v for k, v in new["claims"].items() if k != "job_workflow_ref"} == {
        "event_name": "pull_request_target", "repository_owner_id": "10479364"}
    assert before["match"]["claims"]["job_workflow_ref"] == f"{REF}{SHA_OLD}"  # input not mutated


def test_patch_match_drops_null_matchers_and_keeps_set_ones():
    m = rule()["match"]
    assert "audience" not in release.patch_match(m, SHA_NEW) and "condition" not in release.patch_match(m, SHA_NEW)
    m["audience"] = "https://api.anthropic.com"
    m["claims"]["extra"] = "x"
    new = release.patch_match(m, SHA_NEW)
    assert new["audience"] == "https://api.anthropic.com" and new["claims"]["extra"] == "x"


def test_patch_match_without_prefix_keeps_a_scratch_path():
    m = rule(prefix="OperationCode/claude-review-test/.github/workflows/v.yml@")["match"]
    new = release.patch_match(m, SHA_NEW)
    assert new["claims"]["job_workflow_ref"] == f"OperationCode/claude-review-test/.github/workflows/v.yml@{SHA_NEW}"


@pytest.mark.parametrize("mutate", [
    lambda m: m["claims"].update(job_workflow_ref="OperationCode/other/.github/workflows/x.yml@" + SHA_OLD),
    lambda m: m["claims"].update(job_workflow_ref=REF + "refs/heads/main"),
    lambda m: m["claims"].update(job_workflow_ref="no-at-sign"),
    lambda m: m["claims"].pop("job_workflow_ref"),
    lambda m: m.pop("claims"),
])
def test_patch_match_refuses_an_unexpected_rule(mutate):
    m = rule()["match"]
    mutate(m)
    with pytest.raises(release.ReleaseError):
        release.patch_match(m, SHA_NEW, prefix=REF)


def test_patch_match_refuses_no_match():
    with pytest.raises(release.ReleaseError):
        release.patch_match(None, SHA_NEW)


# ---------------------------------------------------------------- rule read-back


def _after_rule(sha=SHA_NEW):
    after = rule(sha=sha)
    after["updated_at"] = "t1"
    after["updated_by_actor_id"] = "user_b"
    del after["match"]["audience"]  # missing equals null
    return after


def test_compare_rule_passes_when_only_the_ref_changed():
    before = rule()
    expected = release.patch_match(before["match"], SHA_NEW, prefix=REF)
    assert release.compare_rule(before, _after_rule(), expected) == []


@pytest.mark.parametrize("mutate,where", [
    (lambda r: r["match"]["claims"].update(event_name="push"), "match.claims.event_name"),
    (lambda r: r["match"]["claims"].pop("repository_owner_id"), "match.claims.repository_owner_id"),
    (lambda r: r["match"]["claims"].update(repository="x"), "match.claims.repository"),
    (lambda r: r["match"].update(subject_prefix="repo:*"), "match.subject_prefix"),
    (lambda r: r["match"].update(condition="true"), "match.condition"),
    (lambda r: r["match"]["claims"].update(job_workflow_ref=REF + SHA_OLD), "match.claims.job_workflow_ref"),
    (lambda r: r.update(name="other"), "name"),
    (lambda r: r.update(oauth_scope="org:admin"), "oauth_scope"),
    (lambda r: r.update(token_lifetime_seconds=3600), "token_lifetime_seconds"),
    (lambda r: r.update(workspace_ids=["wrkspc_x", "wrkspc_y"]), "workspace_ids"),
    (lambda r: r.update(applies_to_all_workspaces=True), "applies_to_all_workspaces"),
    (lambda r: r["target"].update(service_account_id="svac_y"), "target.service_account_id"),
    (lambda r: r.update(archived_at="t2"), "archived_at"),
])
def test_compare_rule_detects_any_other_change(mutate, where):
    before = rule()
    expected = release.patch_match(before["match"], SHA_NEW, prefix=REF)
    after = _after_rule()
    mutate(after)
    assert where in " ".join(release.compare_rule(before, after, expected))


# ---------------------------------------------------------------- ruleset patch and read-back


def test_patch_ruleset_changes_only_the_pin():
    before = ruleset()
    body = release.patch_ruleset(before, SHA_NEW)
    assert set(body) == {"rules"}
    assert release.diff_paths(before["rules"], body["rules"]) == ["[0].parameters.workflows[0].sha"]
    assert before["rules"][0]["parameters"]["workflows"][0]["sha"] == SHA_OLD  # input not mutated


def test_patch_ruleset_keeps_other_rules_and_entries():
    before = ruleset()
    before["rules"].insert(0, {"type": "deletion"})
    before["rules"][1]["parameters"]["workflows"].append(
        {"repository_id": 1, "path": ".github/workflows/other.yml", "sha": SHA_OLD})
    body = release.patch_ruleset(before, SHA_NEW)
    assert release.diff_paths(before["rules"], body["rules"]) == ["[1].parameters.workflows[0].sha"]


@pytest.mark.parametrize("mutate", [
    lambda rs: rs["rules"][0]["parameters"]["workflows"][0].update(ref="refs/heads/main"),
    lambda rs: rs["rules"][0]["parameters"]["workflows"].append(copy.deepcopy(rs["rules"][0]["parameters"]["workflows"][0])),
    lambda rs: rs["rules"][0]["parameters"]["workflows"].clear(),
    lambda rs: rs["rules"].clear(),
    lambda rs: rs["rules"][0]["parameters"]["workflows"][0].pop("sha"),
    lambda rs: rs["rules"][0]["parameters"]["workflows"][0].update(repository_id=1432457406),
])
def test_patch_ruleset_refuses_unexpected_shape(mutate):
    rs = ruleset()
    mutate(rs)
    with pytest.raises(release.ReleaseError):
        release.patch_ruleset(rs, SHA_NEW)


def test_compare_ruleset_passes_when_only_the_pin_moved():
    after = ruleset(sha=SHA_NEW)
    after["updated_at"] = "t1"
    assert release.compare_ruleset(ruleset(), after, SHA_NEW) == []


@pytest.mark.parametrize("mutate", [
    lambda rs: rs.update(enforcement="disabled"),
    lambda rs: rs["bypass_actors"].append({"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}),
    lambda rs: rs["conditions"]["repository_id"]["repository_ids"].append(1),
    lambda rs: rs["conditions"]["ref_name"]["include"].append("refs/heads/x"),
    lambda rs: rs["rules"].append({"type": "deletion"}),
    lambda rs: rs["rules"][0]["parameters"].update(do_not_enforce_on_create=True),
    lambda rs: rs["rules"][0]["parameters"]["workflows"][0].update(sha=SHA_OLD),
    lambda rs: rs["rules"][0]["parameters"]["workflows"][0].update(ref="refs/heads/main"),
    lambda rs: rs["rules"][0]["parameters"]["workflows"][0].update(path=".github/workflows/x.yml"),
    lambda rs: rs.update(name="renamed"),
])
def test_compare_ruleset_detects_any_other_change(mutate):
    after = ruleset(sha=SHA_NEW)
    mutate(after)
    assert release.compare_ruleset(ruleset(), after, SHA_NEW)


def test_redact_hides_bearer_and_keys():
    out = release.redact('authorization: Bearer abc.def-123 and sk-ant-oat01-xyz"')
    assert "abc.def" not in out and "oat01-xyz" not in out and out.count("[redacted]") == 2


# ---------------------------------------------------------------- end to end with a fake runner


ANALYZE = f'ANTHROPIC_FEDERATION_RULE_ID = "{R1}"\n'


class Fake:
    """gh and ant stand-in. Records each call; keeps rule and ruleset state."""

    def __init__(self, *, sha=SHA_NEW, ant_installed=True, help_text="retrieve  update  list",
                 analyze=ANALYZE, test_ok=True, compare_status="identical", role="admin",
                 rule_after=None, login_raises=None):
        self.calls: list[tuple[list[str], dict]] = []
        self.rules = {R1: rule(R1), R2: rule(R2, prefix="OperationCode/claude-review-test/.github/workflows/v.yml@")}
        self.rulesets = {rid: ruleset(rid) for rid, _ in release.RULESETS}
        self.ant_installed, self.help_text, self.analyze = ant_installed, help_text, analyze
        self.test_ok, self.compare_status, self.role = test_ok, compare_status, role
        self.rule_after, self.login_raises = rule_after, login_raises
        self.config_dirs: set[str] = set()

    def __call__(self, cmd, **kw):
        self.calls.append((list(cmd), kw))
        if cmd[0] == "ant":
            return self.ant(cmd[1:], kw)
        assert cmd[:2] == ["gh", "api"]
        return self.gh(cmd, kw)

    @staticmethod
    def ok(obj=None, rc=0, stderr=""):
        return subprocess.CompletedProcess([], rc, json.dumps(obj) if obj is not None else "", stderr)

    def ant(self, args, kw):
        if not self.ant_installed:
            raise FileNotFoundError("ant")
        env = kw["env"]
        assert not any(k.startswith("ANTHROPIC_") and k != "ANTHROPIC_CONFIG_DIR" for k in env)
        self.config_dirs.add(env["ANTHROPIC_CONFIG_DIR"])
        if args[-1] == "--help":
            return subprocess.CompletedProcess([], 0, self.help_text, "")
        if args[:2] == ["auth", "login"]:
            assert "capture_output" not in kw  # interactive: owner sees the URL
            if self.login_raises:
                raise self.login_raises
            return self.ok()
        if args[:2] == ["auth", "logout"]:
            return self.ok()
        rid = args[args.index("--federation-rule-id") + 1]
        if args[1] == "retrieve":
            return self.ok(self.rules[rid])
        if args[1] == "update":
            new = copy.deepcopy(self.rules[rid])
            new["match"] = json.loads(args[args.index("--match") + 1])
            new["updated_at"] = "t1"
            if self.rule_after:
                self.rule_after(new)
            self.rules[rid] = new
            return self.ok(new)
        raise AssertionError(args)

    def gh(self, cmd, kw):
        path = cmd[-1] if "-X" not in cmd else cmd[cmd.index("--input") - 1]
        if "-X" in cmd:
            assert cmd[cmd.index("-X") + 1] == "PUT"
            rid = int(path.rsplit("/", 1)[1])
            new = copy.deepcopy(self.rulesets[rid])
            new.update(json.loads(kw["input"]))
            new["updated_at"] = "t1"
            self.rulesets[rid] = new
            return self.ok(new)
        if "/compare/" in path:
            return self.ok({"status": self.compare_status, "ahead_by": 0})
        if "/actions/workflows/" in path:
            wf = path.split("/actions/workflows/")[1].split("/")[0]
            concl = "success" if self.test_ok or wf != "test.yml" else "failure"
            return self.ok({"workflow_runs": [{"id": 1, "path": f".github/workflows/{wf}",
                                               "status": "completed", "conclusion": concl}]})
        if "/contents/" in path:
            return self.ok({"content": base64.b64encode(self.analyze.encode()).decode()})
        if path == "user":
            return self.ok({"login": "owner"})
        if "/memberships/" in path:
            return self.ok({"role": self.role})
        if "/rulesets/" in path:
            return self.ok(self.rulesets[int(path.rsplit("/", 1)[1])])
        raise AssertionError(path)

    def writes(self):
        return [c for c, _ in self.calls if ("-X" in c) or (len(c) > 2 and c[2] == "update")]


@pytest.fixture(autouse=True)
def _no_real_subprocess(monkeypatch):
    """No test may start a real gh or ant (no browser login, no API call)."""
    def refuse(*a, **kw):
        raise AssertionError(f"real subprocess call in a unit test: {a!r}")
    monkeypatch.setattr(release.subprocess, "run", refuse)
    monkeypatch.setattr(release.subprocess, "Popen", refuse)


@pytest.fixture(autouse=True)
def _records(tmp_path, monkeypatch):
    monkeypatch.setattr(release, "RECORDS", tmp_path / "records")
    for k in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.setenv(k, "must-not-reach-ant")


def confirm_with(text):
    return lambda _prompt: text


def test_release_applies_console_first_then_pins_and_cleans_up(capsys):
    fake = Fake()
    rc = release.main(["release", "--sha", SHA_NEW], run=fake, ask=confirm_with(f"release {SHA_NEW[:12]}"))
    assert rc == 0, capsys.readouterr()
    writes = fake.writes()
    assert writes[0][0] == "ant" and writes[0][2] == "update"
    assert [w[w.index("--input") - 1] for w in writes[1:]] == [f"orgs/OperationCode/rulesets/{rid}" for rid, _ in release.RULESETS]
    assert fake.rules[R1]["match"]["claims"]["job_workflow_ref"] == REF + SHA_NEW
    assert all(release.ruleset_pin(rs) == SHA_NEW for rs in fake.rulesets.values())
    logout = [c for c, _ in fake.calls if c[:3] == ["ant", "auth", "logout"]]
    assert logout == [["ant", "auth", "logout", "--all"]]
    assert fake.calls[-1][0][:3] != ["ant", "auth", "login"]
    assert all(not os.path.exists(d) for d in fake.config_dirs)
    recs = list((release.RECORDS).rglob("*.json"))
    names = {p.name for p in recs}
    assert f"rule-{R1}-before.json" in names and f"rule-{R1}-after.json" in names
    assert all(f"ruleset-{rid}-after.json" in names for rid, _ in release.RULESETS)
    assert not any("must-not-reach-ant" in p.read_text() for p in recs)


def test_release_rerun_at_the_same_sha_writes_nothing():
    fake = Fake()
    fake.rules[R1] = rule(sha=SHA_NEW)
    fake.rulesets = {rid: ruleset(rid, SHA_NEW) for rid, _ in release.RULESETS}
    assert release.main(["release", "--sha", SHA_NEW], run=fake, ask=confirm_with(f"release {SHA_NEW[:12]}")) == 0
    assert fake.writes() == []


def test_release_without_confirmation_changes_nothing_and_logs_out(capsys):
    fake = Fake()
    rc = release.main(["release", "--sha", SHA_NEW], run=fake, ask=confirm_with("yes"))
    assert rc == 2 and fake.writes() == []
    assert "not confirmed" in capsys.readouterr().err
    assert any(c[:3] == ["ant", "auth", "logout"] for c, _ in fake.calls)
    assert all(not os.path.exists(d) for d in fake.config_dirs)


@pytest.mark.parametrize("kw,msg", [
    (dict(test_ok=False), "no successful test.yml run"),
    (dict(compare_status="diverged"), "is not on main"),
    (dict(analyze='ANTHROPIC_FEDERATION_RULE_ID = "fdrl_000000000000000000000000"\n'), "names rule"),
    (dict(role="member"), "needs an org owner"),
])
def test_release_refuses_on_a_failed_precondition_before_any_console_call(kw, msg, capsys):
    fake = Fake(**kw)
    rc = release.main(["release", "--sha", SHA_NEW], run=fake, ask=confirm_with(f"release {SHA_NEW[:12]}"))
    assert rc == 2 and fake.writes() == []
    assert not any(c[0] == "ant" for c, _ in fake.calls)
    out = capsys.readouterr()
    assert msg in out.out and "precondition(s) failed" in out.err


def test_release_refuses_a_ruleset_with_a_ref():
    fake = Fake()
    fake.rulesets[25835887]["rules"][0]["parameters"]["workflows"][0]["ref"] = "refs/heads/main"
    assert release.main(["release", "--sha", SHA_NEW], run=fake, ask=confirm_with(f"release {SHA_NEW[:12]}")) == 2
    assert fake.writes() == []


def test_release_stops_before_the_pins_when_the_rule_reads_back_wrong(capsys):
    fake = Fake(rule_after=lambda r: r.update(token_lifetime_seconds=3600))
    rc = release.main(["release", "--sha", SHA_NEW], run=fake, ask=confirm_with(f"release {SHA_NEW[:12]}"))
    assert rc == 2
    assert "token_lifetime_seconds" in capsys.readouterr().err
    assert not any("-X" in c for c in fake.writes())


def test_release_refuses_a_rule_changed_since_the_plan_read():
    fake = Fake()

    def ask(_prompt):
        fake.rules[R1]["name"] = "changed meanwhile"
        return f"release {SHA_NEW[:12]}"

    assert release.main(["release", "--sha", SHA_NEW], run=fake, ask=ask) == 2
    assert fake.writes() == []


def test_release_refuses_no_console():
    fake = Fake()
    assert release.main(["release", "--sha", SHA_NEW, "--no-console"], run=fake, ask=confirm_with("x")) == 2
    assert fake.writes() == []


def test_plan_is_read_only_and_logs_out(capsys):
    fake = Fake()
    assert release.main(["plan", "--sha", SHA_NEW], run=fake, ask=confirm_with("never asked")) == 0
    assert fake.writes() == []
    out = capsys.readouterr().out
    assert f"{SHA_OLD} -> {SHA_NEW}" in out and "Plan OK" in out
    assert any(c[:3] == ["ant", "auth", "logout"] for c, _ in fake.calls)


def test_plan_no_console_makes_no_ant_call():
    fake = Fake()
    assert release.main(["plan", "--sha", SHA_NEW, "--no-console"], run=fake) == 0
    assert not any(c[0] == "ant" for c, _ in fake.calls)


def test_plan_without_ant_fails_closed_with_a_clear_message(capsys):
    fake = Fake(ant_installed=False)
    assert release.main(["plan", "--sha", SHA_NEW], run=fake) == 2
    assert "ant is not installed" in capsys.readouterr().err
    assert fake.writes() == []


def test_plan_refuses_an_ant_without_the_rule_getter(capsys):
    fake = Fake(help_text="list  create  archive  update")
    assert release.main(["plan", "--sha", SHA_NEW], run=fake) == 2
    assert "retrieve" in capsys.readouterr().err
    assert not any(c[:3] == ["ant", "auth", "login"] for c, _ in fake.calls)


def test_bad_sha_makes_no_call():
    fake = Fake()
    assert release.main(["release", "--sha", "main"], run=fake) == 2
    assert fake.calls == []


def test_interrupt_during_login_still_logs_out_and_removes_the_dir():
    fake = Fake(login_raises=KeyboardInterrupt())
    assert release.main(["plan", "--sha", SHA_NEW], run=fake) == 130
    assert any(c[:3] == ["ant", "auth", "logout"] for c, _ in fake.calls)
    assert fake.config_dirs and all(not os.path.exists(d) for d in fake.config_dirs)


def test_config_dir_is_private_during_the_run():
    modes = []
    fake = Fake()
    orig = fake.ant

    def ant(args, kw):
        if args[:2] == ["auth", "login"]:
            modes.append(os.stat(kw["env"]["ANTHROPIC_CONFIG_DIR"]).st_mode & 0o777)
        return orig(args, kw)

    fake.ant = ant
    release.main(["plan", "--sha", SHA_NEW], run=fake)
    assert modes == [0o700]


def test_rule_test_edits_only_the_given_rule():
    fake = Fake()
    rc = release.main(["rule-test", "--rule", R2, "--sha", SHA_NEW], run=fake, ask=confirm_with(f"release {SHA_NEW[:12]}"))
    assert rc == 0
    assert fake.rules[R2]["match"]["claims"]["job_workflow_ref"].endswith("@" + SHA_NEW)
    assert fake.rules[R1] == rule(R1)
    assert not any(c[0] == "gh" for c, _ in fake.calls)


def test_rule_test_refuses_the_production_rule():
    fake = Fake()
    assert release.main(["rule-test", "--rule", R1, "--sha", SHA_NEW], run=fake) == 2
    assert fake.calls == []


# ---------------------------------------------------------------- never in CI


def test_no_workflow_runs_the_release_tool():
    for path in (ROOT / ".github" / "workflows").glob("*.y*ml"):
        text = path.read_text(encoding="utf-8")
        assert "release.py" not in text and "make release" not in text and "ant " not in text, path.name


def test_default_runner_is_guarded_in_tests():
    with pytest.raises(AssertionError, match="real subprocess"):
        release.main(["plan", "--sha", SHA_NEW, "--no-console"])
