"""Owner-run release tool (review/tools/release.py). No network: every gh and
ant call goes to a fake runner."""

import base64
import copy
import importlib.util
import json
import os
import signal
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

# Recorded org ruleset bodies (GET /orgs/OperationCode/rulesets/{id} and the
# list, 2026-11-01): the review ruleset, the baseline and the scratch test ruleset.
FIXTURES = Path(__file__).parent / "fixtures" / "release"
BASELINE_ID = 25787833


def recorded(rid: int) -> dict:
    return json.loads((FIXTURES / f"ruleset-{rid}.json").read_text(encoding="utf-8"))


def good_run(wf, sha, **over):
    event = "push" if wf == "test.yml" else "workflow_dispatch"
    run = {"id": 1, "path": f".github/workflows/{wf}", "event": event, "head_branch": "main",
           "head_sha": sha, "status": "completed", "conclusion": "success"}
    run.update(over)
    return run


class Fake:
    """gh and ant stand-in. Records each call; keeps rule and ruleset state."""

    def __init__(self, *, sha=SHA_NEW, ant_installed=True, help_text="retrieve  update  list",
                 analyze=ANALYZE, test_ok=True, compare_status="identical", role="admin",
                 rule_after=None, login_raises=None, runs=None, logout=None, put=None, on_retrieve=None):
        self.calls: list[tuple[list[str], dict]] = []
        self.rules = {R1: rule(R1), R2: rule(R2, prefix="OperationCode/claude-review-test/.github/workflows/v.yml@")}
        self.rulesets = {rid: ruleset(rid) for rid, _ in release.RULESETS}
        self.ant_installed, self.help_text, self.analyze = ant_installed, help_text, analyze
        self.test_ok, self.compare_status, self.role = test_ok, compare_status, role
        self.rule_after, self.login_raises = rule_after, login_raises
        self.sha, self.runs, self.logout, self.put = sha, runs, logout, put
        self.config_dirs: set[str] = set()
        self.on_retrieve, self.retrieves = on_retrieve, {}
        # Org rulesets that are not in RULESETS (the live baseline by default),
        # and an optional override of the list pages: {page: [items]}.
        self.other_rulesets = {BASELINE_ID: recorded(BASELINE_ID)}
        self.list_pages: dict[int, object] | None = None

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
            cred = Path(env["ANTHROPIC_CONFIG_DIR"]) / "credentials" / "admin.json"
            cred.parent.mkdir(parents=True, exist_ok=True)
            cred.write_text('{"access_token": "synthetic", "refresh_token": "synthetic"}')
            if self.login_raises:
                raise self.login_raises
            return self.ok()
        if args[:2] == ["auth", "logout"]:
            if self.logout:
                return self.logout(env)
            return self.ok()
        rid = args[args.index("--federation-rule-id") + 1]
        if args[1] == "retrieve":
            self.retrieves[rid] = self.retrieves.get(rid, 0) + 1
            if self.on_retrieve:
                self.on_retrieve(self, rid, self.retrieves[rid])
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
            if self.put:
                return self.put(rid, new, self)
            self.rulesets[rid] = new
            return self.ok(new)
        if "/compare/" in path:
            return self.ok({"status": self.compare_status, "ahead_by": 0})
        if "/actions/workflows/" in path:
            wf = path.split("/actions/workflows/")[1].split("/")[0]
            if self.runs is not None:
                return self.ok({"workflow_runs": self.runs.get(wf, [])})
            concl = "success" if self.test_ok or wf != "test.yml" else "failure"
            return self.ok({"workflow_runs": [good_run(wf, self.sha, conclusion=concl)]})
        if "/contents/" in path:
            return self.ok({"content": base64.b64encode(self.analyze.encode()).decode()})
        if path == "user":
            return self.ok({"login": "owner"})
        if "/memberships/" in path:
            return self.ok({"role": self.role})
        if path.startswith("orgs/OperationCode/rulesets?"):
            page = int(path.rsplit("page=", 1)[1])
            if self.list_pages is not None:
                return self.ok(self.list_pages.get(page, []))
            items = [{"id": rid} for rid in [*self.rulesets, *self.other_rulesets]]
            return self.ok(items if page == 1 else [])
        if "/rulesets/" in path:
            rid = int(path.rsplit("/", 1)[1])
            return self.ok(self.rulesets[rid] if rid in self.rulesets else self.other_rulesets[rid])
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


PLANTED_ENV = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL", "ANTHROPIC_PROFILE")


def _repo_records():
    real = ROOT / "release-records"
    return sorted(str(p) for p in real.rglob("*")) if real.exists() else []


@pytest.fixture(autouse=True)
def _records(tmp_path, monkeypatch):
    """Hermetic: records and every temp dir go under this test's tmp_path,
    and the repo's release-records/ must not change."""
    before = _repo_records()
    monkeypatch.setattr(release, "RECORDS", tmp_path / "records")
    monkeypatch.setattr(release.tempfile, "tempdir", str(tmp_path / "tmp"))
    (tmp_path / "tmp").mkdir()
    # Planted before the test runs: ant must never see them (Fake.ant checks).
    for k in PLANTED_ENV:
        monkeypatch.setenv(k, "must-not-reach-ant")
    yield
    assert _repo_records() == before, "a test wrote to the repo's release-records/"


def change_r1_on_second_read(fake, rid, n):
    if rid == R1 and n == 2:  # the read just before the apply
        fake.rules[R1]["name"] = "changed meanwhile"


def test_apply_runs_without_reading_stdin(monkeypatch, capsys):
    class NoStdin:
        def read(self, *a):
            raise AssertionError("stdin was read")

        readline = readlines = read

        def isatty(self):
            return False

    monkeypatch.setattr(release.sys, "stdin", NoStdin())
    monkeypatch.setattr("builtins.input", lambda *a: (_ for _ in ()).throw(AssertionError("input() called")))
    fake = Fake()
    assert release.main(["release", "--sha", SHA_NEW], run=fake) == 0
    out = capsys.readouterr().out
    assert fake.writes() != [] and "no prompt" in out and "Apply?" not in out


def test_rule_test_applies_without_reading_stdin(monkeypatch):
    monkeypatch.setattr("builtins.input", lambda *a: (_ for _ in ()).throw(AssertionError("input() called")))
    fake = Fake()
    assert release.main(["rule-test", "--rule", R2, "--sha", SHA_NEW], run=fake) == 0
    assert fake.writes() != []


def test_plan_header_says_read_only_dry_run(capsys):
    assert release.main(["plan", "--sha", SHA_NEW], run=Fake()) == 0
    assert "read-only dry run" in capsys.readouterr().out


def test_release_applies_console_first_then_pins_and_cleans_up(capsys):
    fake = Fake()
    rc = release.main(["release", "--sha", SHA_NEW], run=fake)
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
    assert release.main(["release", "--sha", SHA_NEW], run=fake) == 0
    assert fake.writes() == []


@pytest.mark.parametrize("kw,msg", [
    (dict(test_ok=False), "no successful test.yml push run on main"),
    (dict(compare_status="diverged"), "is not on main"),
    (dict(analyze='ANTHROPIC_FEDERATION_RULE_ID = "fdrl_000000000000000000000000"\n'), "names rule"),
    (dict(role="member"), "needs an org owner"),
])
def test_release_refuses_on_a_failed_precondition_before_any_console_call(kw, msg, capsys):
    fake = Fake(**kw)
    rc = release.main(["release", "--sha", SHA_NEW], run=fake)
    assert rc == 2 and fake.writes() == []
    assert not any(c[0] == "ant" for c, _ in fake.calls)
    out = capsys.readouterr()
    assert msg in out.out and "precondition(s) failed" in out.err


def test_release_refuses_a_ruleset_with_a_ref():
    fake = Fake()
    fake.rulesets[25835887]["rules"][0]["parameters"]["workflows"][0]["ref"] = "refs/heads/main"
    assert release.main(["release", "--sha", SHA_NEW], run=fake) == 2
    assert fake.writes() == []


def test_release_stops_before_the_pins_when_the_rule_reads_back_wrong(capsys):
    fake = Fake(rule_after=lambda r: r.update(token_lifetime_seconds=3600))
    rc = release.main(["release", "--sha", SHA_NEW], run=fake)
    assert rc == 2
    assert "token_lifetime_seconds" in capsys.readouterr().err
    assert not any("-X" in c for c in fake.writes())


def test_release_refuses_a_rule_changed_since_the_plan_read():
    fake = Fake(on_retrieve=change_r1_on_second_read)

    assert release.main(["release", "--sha", SHA_NEW], run=fake) == 2
    assert fake.writes() == []


def test_release_refuses_no_console():
    fake = Fake()
    assert release.main(["release", "--sha", SHA_NEW, "--no-console"], run=fake) == 2
    assert fake.writes() == []


def test_plan_is_read_only_and_logs_out(capsys):
    fake = Fake()
    assert release.main(["plan", "--sha", SHA_NEW], run=fake) == 0
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
    rc = release.main(["rule-test", "--rule", R2, "--sha", SHA_NEW], run=fake)
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


# ---------------------------------------------------------------- fix round 1: release run checks


def _gh_only(fake):
    return release.github_preconditions(release.GitHub(fake), SHA_NEW, R1)


def test_preconditions_accept_push_and_dispatch_runs_on_main():
    assert _gh_only(Fake(runs={"test.yml": [good_run("test.yml", SHA_NEW)],
                               "eval.yml": [good_run("eval.yml", SHA_NEW)]})) == []


@pytest.mark.parametrize("wf,over", [
    ("test.yml", {"event": "pull_request", "head_branch": "candidate"}),
    ("test.yml", {"event": "pull_request"}),
    ("test.yml", {"event": "pull_request_target"}),
    ("test.yml", {"head_branch": "candidate"}),
    ("test.yml", {"head_sha": SHA_OLD}),
    ("test.yml", {"path": ".github/workflows/other.yml"}),
    ("test.yml", {"status": "in_progress", "conclusion": None}),
    ("eval.yml", {"event": "pull_request", "head_branch": "candidate"}),
    ("eval.yml", {"event": "push"}),
    ("eval.yml", {"head_branch": "candidate"}),
    ("eval.yml", {"head_sha": SHA_OLD}),
])
def test_preconditions_refuse_a_run_of_the_wrong_kind(wf, over, capsys):
    runs = {w: [good_run(w, SHA_NEW)] for w in ("test.yml", "eval.yml")}
    runs[wf] = [good_run(wf, SHA_NEW, **over)]
    fails = _gh_only(Fake(runs=runs))
    assert len(fails) == 1 and wf in fails[0]


def test_release_refuses_when_only_pull_request_runs_passed_at_the_sha(capsys):
    pr = {w: [good_run(w, SHA_NEW, event="pull_request", head_branch="candidate")] for w in ("test.yml", "eval.yml")}
    fake = Fake(runs=pr)
    assert release.main(["release", "--sha", SHA_NEW], run=fake) == 2
    assert fake.writes() == [] and not any(c[0] == "ant" for c, _ in fake.calls)


# ---------------------------------------------------------------- fix round 1: credential cleanup


def _cred_files(fake):
    return [p for d in fake.config_dirs for p in Path(d).rglob("*") if p.is_file()]


def test_logout_raising_keyboardinterrupt_leaves_no_credential_file():
    def logout(env):
        assert (Path(env["ANTHROPIC_CONFIG_DIR"]) / "credentials" / "admin.json").exists()
        raise KeyboardInterrupt()

    fake = Fake(logout=logout)
    assert release.main(["plan", "--sha", SHA_NEW], run=fake) == 130
    assert fake.config_dirs and _cred_files(fake) == []
    assert all(not os.path.exists(d) for d in fake.config_dirs)


def test_logout_raising_any_exception_leaves_no_credential_file():
    def logout(env):
        raise RuntimeError("synthetic")

    fake = Fake(logout=logout)
    with pytest.raises(RuntimeError):
        release.main(["plan", "--sha", SHA_NEW], run=fake)
    assert all(not os.path.exists(d) for d in fake.config_dirs)


def test_a_signal_during_cleanup_is_held_until_cleanup_ends():
    seen = []

    def logout(env):
        signal.raise_signal(signal.SIGINT)
        seen.append("logout finished")  # the signal must not cut logout short
        return Fake.ok()

    fake = Fake(logout=logout)
    assert release.main(["plan", "--sha", SHA_NEW], run=fake) == 130
    assert seen == ["logout finished"]
    assert all(not os.path.exists(d) for d in fake.config_dirs)
    assert signal.getsignal(signal.SIGINT) is signal.default_int_handler


def test_a_failed_delete_is_loud_and_makes_the_run_fail(monkeypatch, capsys):
    real_rmtree = release.shutil.rmtree
    dirs = []

    def no_delete(path, onexc=None):
        dirs.append(path)
        onexc(os.rmdir, path, PermissionError("synthetic"))

    monkeypatch.setattr(release.shutil, "rmtree", no_delete)
    fake = Fake()
    rc = release.main(["plan", "--sha", SHA_NEW], run=fake)
    err = capsys.readouterr().err
    monkeypatch.setattr(release.shutil, "rmtree", real_rmtree)
    for d in dirs:
        real_rmtree(d, ignore_errors=True)
    assert rc == 3
    assert "could not delete" in err and "rm -rf" in err and "CLEANUP FAILED" in err


# ---------------------------------------------------------------- fix round 1: partial failure report


# ---------------------------------------------------------------- fix round 2: signal at logout, logout timeout


def _interrupt_at_logout(how):
    def logout(env):
        if how == "signal":
            signal.raise_signal(signal.SIGINT)  # held during cleanup, raised at the context exit
            return Fake.ok()
        raise KeyboardInterrupt()
    return logout


@pytest.mark.parametrize("how", ["signal", "raise"])
def test_interrupt_during_logout_after_r1_moved_prints_the_state_report(how, capsys):
    fake = Fake(logout=_interrupt_at_logout(how))
    assert _release(fake) == 130
    err = capsys.readouterr().err
    assert "RELEASE INCOMPLETE" in err
    lines = _state_lines(err)
    assert "done" in lines[R1] and SHA_NEW in lines[R1]
    assert all("pending" in lines[str(r)] and f"now {SHA_OLD}" in lines[str(r)] for r in (FIRST, SECOND))
    assert f"make release SHA={SHA_OLD}" in err and f"make release SHA={SHA_NEW}" in err
    assert "Interrupted after a write was sent" in err and "Nothing was changed" not in err
    assert not any("-X" in c for c in fake.writes())  # no pin moved after the interrupt
    assert all(not os.path.exists(d) for d in fake.config_dirs)
    assert err.count("RELEASE INCOMPLETE:") == 1  # the report prints once


def test_rule_test_interrupt_during_logout_prints_the_state_report(capsys):
    fake = Fake(logout=_interrupt_at_logout("signal"))
    rc = release.main(["rule-test", "--rule", R2, "--sha", SHA_NEW], run=fake)
    assert rc == 130
    err = capsys.readouterr().err
    assert "RELEASE INCOMPLETE" in err and f"make release-rule-test RULE={R2} SHA={SHA_OLD}" in err
    assert "Interrupted after a write was sent" in err


def test_interrupt_before_any_write_says_nothing_changed(capsys):
    def interrupt(_fake, rid, n):
        if rid == R1 and n == 2:
            raise KeyboardInterrupt()

    fake = Fake(on_retrieve=interrupt)
    assert release.main(["release", "--sha", SHA_NEW], run=fake) == 130
    err = capsys.readouterr().err
    assert "RELEASE INCOMPLETE" not in err and "Interrupted before any write was sent. Nothing was changed." in err
    assert fake.writes() == []


def test_interrupt_during_logout_of_a_plan_says_nothing_changed(capsys):
    fake = Fake(logout=_interrupt_at_logout("signal"))
    assert release.main(["plan", "--sha", SHA_NEW], run=fake) == 130
    err = capsys.readouterr().err
    assert "RELEASE INCOMPLETE" not in err and "Nothing was changed" in err


def test_logout_has_a_timeout_and_the_dir_is_still_deleted(capsys):
    seen = {}

    def logout(env):
        raise subprocess.TimeoutExpired(["ant", "auth", "logout", "--all"], release.LOGOUT_TIMEOUT_S)

    fake = Fake(logout=logout)
    real = fake.ant

    def ant(args, kw):
        if args[:2] == ["auth", "logout"]:
            seen["timeout"] = kw.get("timeout")
        return real(args, kw)

    fake.ant = ant
    assert release.main(["plan", "--sha", SHA_NEW], run=fake) == 0
    err = capsys.readouterr().err
    assert seen["timeout"] == release.LOGOUT_TIMEOUT_S and 0 < release.LOGOUT_TIMEOUT_S <= 60
    assert "did not end within" in err and "local token files are deleted" in err
    assert fake.config_dirs and all(not os.path.exists(d) for d in fake.config_dirs)


def test_temp_dirs_stay_under_the_test_tmp_path(tmp_path):
    fake = Fake()
    release.main(["plan", "--sha", SHA_NEW], run=fake)
    assert fake.config_dirs and all(Path(d).is_relative_to(tmp_path) for d in fake.config_dirs)


def _fail_put_on(target, *, apply_first=False):
    def put(rid, new, fake):
        if rid == target:
            if apply_first:
                fake.rulesets[rid] = new  # the write reached GitHub, the reply was lost
            return Fake.ok(rc=1, stderr="synthetic ruleset failure")
        fake.rulesets[rid] = new
        return Fake.ok(new)
    return put


FIRST, SECOND = (rid for rid, _ in release.RULESETS)


def _release(fake):
    return release.main(["release", "--sha", SHA_NEW], run=fake)


def _state_lines(err):
    return {ln.split()[1]: ln for ln in err.splitlines() if ln.startswith("  rule ") or ln.startswith("  ruleset ")}


def test_first_ruleset_failure_reports_state_and_rollback(capsys):
    fake = Fake(put=_fail_put_on(FIRST))
    assert _release(fake) == 2
    err = capsys.readouterr().err
    assert "RELEASE INCOMPLETE" in err
    lines = _state_lines(err)
    assert "done" in lines[R1] and SHA_NEW in lines[R1]
    assert "failed" not in lines[str(FIRST)] and "sent" in lines[str(FIRST)] and f"now {SHA_OLD}" in lines[str(FIRST)]
    assert "pending" in lines[str(SECOND)] and f"now {SHA_OLD}" in lines[str(SECOND)]
    assert f"make release SHA={SHA_OLD}" in err and f"make release SHA={SHA_NEW}" in err
    assert "Records: " in err


def test_second_ruleset_failure_reports_state_and_rollback(capsys):
    fake = Fake(put=_fail_put_on(SECOND))
    assert _release(fake) == 2
    err = capsys.readouterr().err
    lines = _state_lines(err)
    assert "done" in lines[str(FIRST)] and f"now {SHA_NEW}" in lines[str(FIRST)]
    assert "sent" in lines[str(SECOND)] and f"now {SHA_OLD}" in lines[str(SECOND)]
    assert f"make release SHA={SHA_OLD}" in err


def test_ambiguous_write_is_reported_as_sent_with_the_real_state(capsys):
    fake = Fake(put=_fail_put_on(FIRST, apply_first=True))
    assert _release(fake) == 2
    err = capsys.readouterr().err
    lines = _state_lines(err)
    assert "sent" in lines[str(FIRST)] and f"now {SHA_NEW}" in lines[str(FIRST)]  # re-read shows it landed
    assert "may have reached the server" in err
    assert f"make release SHA={SHA_OLD}" in err


def test_ambiguous_rule_write_rereads_the_rule_before_logout(capsys):
    fake = Fake()
    real = fake.ant

    def ant(args, kw):
        if len(args) > 1 and args[1] == "update":
            real(args, kw)  # lands on the server
            return Fake.ok(rc=1, stderr="synthetic timeout")
        return real(args, kw)

    fake.ant = ant
    assert _release(fake) == 2
    err = capsys.readouterr().err
    lines = _state_lines(err)
    assert "sent" in lines[R1] and f"now {SHA_NEW}" in lines[R1]
    assert all("pending" in lines[str(r)] for r in (FIRST, SECOND))
    assert not any("-X" in c for c in fake.writes())
    assert f"make release SHA={SHA_OLD}" in err


def test_differing_previous_pins_give_per_object_recovery_not_one_sha(capsys):
    fake = Fake(put=_fail_put_on(SECOND))
    other = "1" * 40
    fake.rulesets[SECOND] = ruleset(SECOND, other)
    assert _release(fake) == 2
    err = capsys.readouterr().err
    assert "no single rollback SHA" in err
    assert f"make release SHA={SHA_OLD}" not in err and f"make release SHA={other}" not in err
    assert f"rulesets/{SECOND} --input" in err and f"ruleset-{SECOND}-rollback-body.json" in err
    body = json.loads(next(release.RECORDS.rglob(f"ruleset-{SECOND}-rollback-body.json")).read_text())
    assert release.ruleset_pin({"id": SECOND, "rules": body["rules"]}) == other


def test_failure_before_any_write_prints_no_state_report(capsys):
    fake = Fake(on_retrieve=change_r1_on_second_read)

    assert release.main(["release", "--sha", SHA_NEW], run=fake) == 2
    assert "RELEASE INCOMPLETE" not in capsys.readouterr().err


# ---------------------------------------------------------------- fix round 3


def test_the_planted_credentials_are_in_the_environment_during_each_test():
    assert all(os.environ.get(k) == "must-not-reach-ant" for k in PLANTED_ENV)


def test_ant_env_drops_every_anthropic_variable_and_sets_only_the_config_dir():
    env = release.ant_env("/private/dir")
    assert env["ANTHROPIC_CONFIG_DIR"] == "/private/dir"
    assert [k for k in env if k.startswith("ANTHROPIC_")] == ["ANTHROPIC_CONFIG_DIR"]
    assert "must-not-reach-ant" not in env.values()


def test_every_ant_call_of_a_release_gets_no_planted_credential():
    fake = Fake()
    assert release.main(["release", "--sha", SHA_NEW], run=fake) == 0
    ant_calls = [kw for c, kw in fake.calls if c[0] == "ant"]
    assert len(ant_calls) >= 5
    assert all("must-not-reach-ant" not in kw["env"].values() for kw in ant_calls)


def test_a_sent_write_counts_even_when_its_previous_sha_is_the_target(capsys):
    progress = release.Progress(SHA_NEW, release.Records("t"), lambda s: f"make release SHA={s}")
    progress.add("rule-x", "rule x", SHA_NEW)
    progress.set("rule-x", "sent")
    assert progress.wrote()
    progress.report()
    assert "RELEASE INCOMPLETE:" in capsys.readouterr().err


def test_a_sent_write_still_counts_after_its_step_is_done():
    progress = release.Progress(SHA_NEW, release.Records("t"), lambda s: f"make release SHA={s}")
    progress.add("rule-x", "rule x", SHA_NEW)
    for state in ("failed", "sent", "written", "done"):
        progress.set("rule-x", state)
    assert progress.wrote()


def test_interrupt_after_a_sent_write_at_the_same_sha_does_not_say_nothing_changed(capsys, monkeypatch):
    """R1's ref is already at the SHA but another match field differs, so a
    POST is sent; an interrupt during it must print the report."""
    fake = Fake()
    fake.rules[R1] = rule(sha=SHA_NEW)
    fake.rules[R1]["match"]["claims"]["job_workflow_ref"] = REF + SHA_NEW
    fake.rules[R1]["match"]["audience"] = None
    real = fake.ant

    def ant(args, kw):
        if len(args) > 1 and args[1] == "update":
            raise KeyboardInterrupt()
        return real(args, kw)

    fake.ant = ant
    real_patch = release.patch_match

    def patched(match, sha, *, prefix=None):
        out = real_patch(match, sha, prefix=prefix)
        out["claims"]["extra"] = "forces a POST"
        return out

    monkeypatch.setattr(release, "patch_match", patched)
    assert _release(fake) == 130
    err = capsys.readouterr().err
    assert "RELEASE INCOMPLETE:" in err and "Nothing was changed" not in err
    assert "Interrupted after a write was sent" in err


def test_an_unchanged_object_read_back_is_not_a_write():
    progress = release.Progress(SHA_NEW, release.Records("t"), lambda s: f"make release SHA={s}")
    progress.add("rule-x", "rule x", SHA_NEW)
    progress.set("rule-x", "unchanged")
    progress.set("rule-x", "done")
    assert not progress.wrote()


# ---------------------------------------------------------------- drift check (spec P5-7)

LIVE_IDS = [26132750, BASELINE_ID, 25835887]  # the recorded list order


def live_bodies() -> dict[int, dict]:
    return {rid: recorded(rid) for rid in LIVE_IDS}


def extra_review_ruleset(rid=99, **wf_over) -> dict:
    """A recorded review ruleset under a new id, as a new org ruleset would be."""
    body = recorded(26132750)
    body.update(id=rid, name="another-review")
    body["rules"][0]["parameters"]["workflows"][0].update(wf_over)
    return body


def test_recorded_list_and_bodies_match_the_live_org():
    listed = [i["id"] for i in json.loads((FIXTURES / "org-rulesets-list.json").read_text(encoding="utf-8"))]
    assert listed == LIVE_IDS
    assert {rid for rid, _ in release.RULESETS} == {26132750, 25835887}
    for rid, _ in release.RULESETS:
        assert release.ruleset_pin(recorded(rid))  # one entry, a sha, no ref


def test_drift_passes_on_the_recorded_org_baseline_without_workflows():
    bodies = live_bodies()
    assert not any(r["type"] == "workflows" for r in bodies[BASELINE_ID]["rules"])
    assert release.drift_problems(LIVE_IDS, bodies) == []


@pytest.mark.parametrize("wf_over", [
    {},  # same repository id and path
    {"repository_id": 1, "path": release.WORKFLOW_PATH},  # path only
    {"path": ".github/workflows/renamed.yml"},  # repository id only
    {"repository_id": 1, "path": "./.GitHub/Workflows/Claude-Review.yml"},  # path spelled differently
])
def test_drift_fails_on_an_extra_review_ruleset(wf_over):
    bodies = live_bodies() | {99: extra_review_ruleset(**wf_over)}
    problems = release.drift_problems([*LIVE_IDS, 99], bodies)
    assert len(problems) == 1 and problems[0].startswith("ruleset 99 'another-review'")
    assert "not in RULESETS" in problems[0]


def test_drift_fails_on_a_disabled_extra_review_ruleset():
    body = extra_review_ruleset()
    body["enforcement"] = "disabled"
    problems = release.drift_problems([*LIVE_IDS, 99], live_bodies() | {99: body})
    assert len(problems) == 1 and "ruleset 99" in problems[0] and "(disabled)" in problems[0]


def test_drift_ignores_a_workflows_rule_for_another_workflow():
    body = extra_review_ruleset(repository_id=1, path=".github/workflows/other.yml")
    assert release.drift_problems([*LIVE_IDS, 99], live_bodies() | {99: body}) == []


@pytest.mark.parametrize("missing", [26132750, 25835887])
def test_drift_fails_when_a_listed_id_is_missing(missing):
    ids = [i for i in LIVE_IDS if i != missing]
    problems = release.drift_problems(ids, {i: recorded(i) for i in ids})
    assert problems == [f"ruleset {missing} is in RULESETS but not in the org ruleset list"]


@pytest.mark.parametrize("context", ["oc-claude-review", "Claude of Duty / Mission report (pull_request_target)"])
def test_drift_fails_on_a_required_check_named_like_the_review(context):
    bodies = live_bodies()
    bodies[BASELINE_ID]["rules"].append({"type": "required_status_checks", "parameters": {
        "strict_required_status_checks_policy": False,
        "required_status_checks": [{"context": "unit-tests"}, {"context": context}]}})
    problems = release.drift_problems(LIVE_IDS, bodies)
    assert len(problems) == 1 and problems[0].startswith(f"ruleset {BASELINE_ID} 'org-baseline'")
    assert context in problems[0] and "unit-tests" not in problems[0]


@pytest.mark.parametrize("body", [None, [], {"id": BASELINE_ID}, {"id": 1, "rules": []}])
def test_drift_fails_closed_on_a_body_it_cannot_read(body):
    bodies = live_bodies()
    bodies[BASELINE_ID] = body
    assert release.drift_problems(LIVE_IDS, bodies) == [
        f"ruleset {BASELINE_ID}: the read did not return this ruleset with a rules list"]


def test_list_reads_every_page_until_a_short_one():
    fake = Fake()
    full = [{"id": 1000 + i} for i in range(release.RULESET_PAGE_SIZE)]
    fake.list_pages = {1: full, 2: [{"id": 26132750}, {"id": 1000}]}
    ids = release.list_org_rulesets(release.GitHub(fake))
    assert ids == [i["id"] for i in full] + [26132750]  # a repeat across pages counts once
    paths = [c[-1] for c, _ in fake.calls]
    assert paths == [f"orgs/OperationCode/rulesets?per_page={release.RULESET_PAGE_SIZE}&page={p}" for p in (1, 2)]


def test_list_with_an_exactly_full_last_page_reads_one_empty_page():
    fake = Fake()
    fake.list_pages = {1: [{"id": 1000 + i} for i in range(release.RULESET_PAGE_SIZE)], 2: []}
    assert len(release.list_org_rulesets(release.GitHub(fake))) == release.RULESET_PAGE_SIZE
    assert len(fake.calls) == 2


@pytest.mark.parametrize("pages,msg", [
    ({1: {"message": "Not Found"}}, "page 1 is not a list"),
    ({1: [{"name": "x"}]}, "no integer id"),
    ({1: [{"id": "26132750"}]}, "no integer id"),
])
def test_list_fails_closed_on_a_bad_page(pages, msg):
    fake = Fake()
    fake.list_pages = pages
    with pytest.raises(release.ReleaseError, match=msg):
        release.list_org_rulesets(release.GitHub(fake))


def test_list_fails_closed_past_the_page_limit():
    fake = Fake()
    fake.list_pages = {p: [{"id": p * 1000 + i} for i in range(release.RULESET_PAGE_SIZE)]
                       for p in range(1, release.RULESET_MAX_PAGES + 2)}
    with pytest.raises(release.ReleaseError, match="more than"):
        release.list_org_rulesets(release.GitHub(fake))
    assert len(fake.calls) == release.RULESET_MAX_PAGES


def test_plan_runs_the_drift_check_on_the_recorded_bodies(capsys):
    fake = Fake()
    fake.other_rulesets = {BASELINE_ID: recorded(BASELINE_ID)}
    assert release.main(["plan", "--sha", SHA_NEW], run=fake) == 0
    out = capsys.readouterr().out
    assert "[ok] drift check: 3 org ruleset(s)" in out and str(BASELINE_ID) in out
    assert any(p.name == "org-rulesets.json" for p in release.RECORDS.rglob("*.json"))


def test_release_refuses_an_extra_review_ruleset_before_any_console_call(capsys):
    fake = Fake()
    fake.other_rulesets[99] = extra_review_ruleset()
    rc = release.main(["release", "--sha", SHA_NEW], run=fake)
    assert rc == 2 and fake.writes() == []
    assert not any(c[0] == "ant" for c, _ in fake.calls)
    out = capsys.readouterr()
    assert "[FAIL] drift check: ruleset 99" in out.out and "precondition(s) failed" in out.err


def test_plan_fails_on_a_missing_listed_ruleset(capsys):
    fake = Fake()
    fake.list_pages = {1: [{"id": 26132750}, {"id": BASELINE_ID}]}
    assert release.main(["plan", "--sha", SHA_NEW, "--no-console"], run=fake) == 1
    err = capsys.readouterr().err
    assert "PLAN FAILED" in err and "ruleset 25835887 is in RULESETS but not in the org ruleset list" in err


def test_release_refuses_when_the_ruleset_list_cannot_be_read(capsys):
    fake = Fake()
    fake.list_pages = {1: {"message": "Resource not accessible"}}
    assert release.main(["release", "--sha", SHA_NEW], run=fake) == 2
    assert fake.writes() == [] and not any(c[0] == "ant" for c, _ in fake.calls)
    assert "drift check: cannot read the org rulesets" in capsys.readouterr().out
