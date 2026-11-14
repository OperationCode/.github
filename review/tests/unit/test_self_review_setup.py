"""Owner-run R-self setup (review/tools/self_review_setup.py). No network:
every ant call goes to a fake runner."""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "review" / "tools"))
import self_review_setup as setup  # noqa: E402

release = setup.release
R1 = release.PROD_RULE_ID
SA = "svac_01PiMgfb6qJgNpLZUV8hprCC"
ISSUER = "fdis_x"
WID = "wrkspc_self"
NEW_RULE = "fdrl_01SelfReviewRuleIdAbcdef"
ANALYZE_TEXT = (f'ANTHROPIC_FEDERATION_RULE_ID = "{R1}"\n'
                f'ANTHROPIC_SERVICE_ACCOUNT_ID = "{SA}"\n'
                f'SELF_REVIEW_FEDERATION_RULE_ID = "{setup.PLACEHOLDER}"\n')
HELP = "retrieve  update  list  create  add"


def r_self(rule_id=NEW_RULE, **over):
    rule = {"id": rule_id, "name": setup.RULE_NAME, "issuer_id": ISSUER, "archived_at": None,
            "match": {"audience": None, "condition": None, **copy.deepcopy(setup.EXPECTED_MATCH)},
            "oauth_scope": "workspace:developer", "applies_to_all_workspaces": False,
            "target": {"service_account_id": SA, "type": "service_account"},
            "token_lifetime_seconds": 600, "workspace_id": WID, "workspace_ids": [WID]}
    rule.update(over)
    return rule


class FakeAnt:
    """ant stand-in. Records each call; keeps workspace, member and rule state."""

    def __init__(self, *, workspaces=None, members=None, rules=None, help_text=HELP):
        self.calls: list[list[str]] = []
        self.workspaces = workspaces if workspaces is not None else []
        self.members = members if members is not None else {}
        self.rules = {R1: {"id": R1, "name": "claude-review-prod-r1", "issuer_id": ISSUER,
                           "target": {"service_account_id": SA, "type": "service_account"}}}
        self.rules.update(rules or {})
        self.help_text = help_text

    @staticmethod
    def out(obj=None, text=None):
        return subprocess.CompletedProcess([], 0, text if text is not None else json.dumps(obj), "")

    def __call__(self, cmd, **kw):
        assert cmd[0] == "ant"
        assert not any(k.startswith("ANTHROPIC_") and k != "ANTHROPIC_CONFIG_DIR" for k in kw["env"])
        args = cmd[1:]
        self.calls.append(args)
        if args[-1] == "--help":
            return self.out(text=self.help_text)
        if args[0] == "auth":
            return self.out(text="")
        res, verb = args[0], args[1]

        def opt(name):
            return args[args.index(name) + 1]

        def jsonl(items):
            return self.out(text="".join(json.dumps(i) + "\n" for i in items))

        if res == setup.WORKSPACES:
            if verb == "list":
                return jsonl(self.workspaces)
            if verb == "create":
                ws = {"id": WID, "name": opt("--name"), "archived_at": None}
                self.workspaces.append(ws)
                return self.out(ws)
            if verb == "retrieve":
                return self.out(next(w for w in self.workspaces if w["id"] == opt("--workspace-id")))
        if res == setup.MEMBERS:
            wid = opt("--workspace-id")
            if verb == "list":
                return jsonl(self.members.get(wid, []))
            if verb == "add":
                self.members.setdefault(wid, []).append({"service_account_id": opt("--service-account-id"),
                                                         "workspace_role": opt("--workspace-role")})
                return self.out({})
        if res == release.Console.RULES:
            if verb == "list":
                return jsonl(list(self.rules.values()))
            if verb == "retrieve":
                return self.out(self.rules[opt("--federation-rule-id")])
            if verb == "create":
                rule = r_self(match=json.loads(opt("--match")), issuer_id=opt("--issuer-id"),
                              target=json.loads(opt("--target")), oauth_scope=opt("--oauth-scope"),
                              workspace_id=opt("--workspace-id"), workspace_ids=[opt("--workspace-id")],
                              token_lifetime_seconds=int(opt("--token-lifetime-seconds")), name=opt("--name"))
                self.rules[NEW_RULE] = rule
                return self.out(rule)
        raise AssertionError(args)

    def writes(self):
        return [c for c in self.calls if len(c) > 1 and c[1] in ("create", "add", "update", "archive")]


@pytest.fixture(autouse=True)
def _hermetic(tmp_path, monkeypatch):
    """No real subprocess; records, temp dirs and analyze.py go under tmp_path."""
    def refuse(*a, **kw):
        raise AssertionError(f"real subprocess call in a unit test: {a!r}")
    monkeypatch.setattr(release.subprocess, "run", refuse)
    monkeypatch.setattr(release.subprocess, "Popen", refuse)
    monkeypatch.setattr(release, "RECORDS", tmp_path / "records")
    monkeypatch.setattr(release.tempfile, "tempdir", str(tmp_path / "tmp"))
    (tmp_path / "tmp").mkdir()
    analyze = tmp_path / "analyze.py"
    analyze.write_text(ANALYZE_TEXT)
    monkeypatch.setattr(setup, "ANALYZE_FILE", analyze)
    monkeypatch.setenv("ANTHROPIC_API_KEY", "must-not-reach-ant")


def analyze_text():
    return setup.ANALYZE_FILE.read_text()


def logged_out(fake):
    return fake.calls[-1] == ["auth", "logout", "--all"]


def test_setup_from_nothing_creates_workspace_member_and_rule_and_writes_the_id(capsys):
    fake = FakeAnt()
    assert setup.main(["setup"], run=fake) == 0
    assert [c[:2] for c in fake.writes()] == [[setup.WORKSPACES, "create"], [setup.MEMBERS, "add"],
                                              [release.Console.RULES, "create"]]
    assert fake.members[WID] == [{"service_account_id": SA, "workspace_role": "workspace_developer"}]
    assert setup.rule_problems(fake.rules[NEW_RULE], workspace_id=WID, issuer_id=ISSUER, service_account_id=SA) == []
    assert f'SELF_REVIEW_FEDERATION_RULE_ID = "{NEW_RULE}"' in analyze_text()
    assert analyze_text().count(R1) == 1  # R1 untouched
    out = capsys.readouterr().out
    assert "MANUAL STEP" in out and "spend limit" in out
    assert logged_out(fake) and not list((Path(release.tempfile.tempdir)).iterdir())


def test_setup_creates_the_rule_with_the_exact_claims():
    fake = FakeAnt()
    setup.main(["setup"], run=fake)
    create = next(c for c in fake.writes() if c[0] == release.Console.RULES)
    assert json.loads(create[create.index("--match") + 1]) == {
        "subject_prefix": "repo:OperationCode@10479364/*",
        "claims": {"repository_id": "1432342572", "event_name": "pull_request_target",
                   "job_workflow_ref": "OperationCode/.github/.github/workflows/claude-review.yml@refs/heads/main"}}
    assert create[create.index("--oauth-scope") + 1] == "workspace:developer"
    assert create[create.index("--workspace-id") + 1] == WID
    assert "--applies-to-all-workspaces" not in create


def test_setup_again_is_idempotent_and_writes_nothing():
    fake = FakeAnt(workspaces=[{"id": WID, "name": setup.WORKSPACE_NAME}],
                   members={WID: [{"service_account_id": SA}]}, rules={NEW_RULE: r_self()})
    assert setup.main(["setup"], run=fake) == 0
    assert fake.writes() == []
    assert f'"{NEW_RULE}"' in analyze_text()
    before = analyze_text()
    assert setup.main(["setup"], run=fake) == 0 and analyze_text() == before


def test_plan_is_read_only(capsys):
    fake = FakeAnt()
    assert setup.main(["plan"], run=fake) == 0
    assert fake.writes() == [] and analyze_text() == ANALYZE_TEXT and logged_out(fake)
    out = capsys.readouterr().out
    assert "missing, setup creates it" in out and "Nothing was changed" in out


def test_plan_with_everything_in_place_says_what_analyze_would_get(capsys):
    fake = FakeAnt(workspaces=[{"id": WID, "name": setup.WORKSPACE_NAME}],
                   members={WID: [{"id": SA}]}, rules={NEW_RULE: r_self()})
    assert setup.main(["plan"], run=fake) == 0
    assert fake.writes() == [] and analyze_text() == ANALYZE_TEXT
    assert f"would be set to {NEW_RULE}" in capsys.readouterr().out


@pytest.mark.parametrize("over", [
    {"match": {"subject_prefix": "repo:OperationCode@10479364/*",
               "claims": {"event_name": "pull_request_target", "repository_id": "1432342572"}}},
    {"oauth_scope": "org:admin"},
    {"applies_to_all_workspaces": True},
    {"workspace_ids": [WID, "wrkspc_other"]},
    {"target": {"service_account_id": "svac_other", "type": "service_account"}},
    {"token_lifetime_seconds": 3600},
])
def test_an_existing_rule_that_differs_is_refused_never_edited(over, capsys):
    fake = FakeAnt(workspaces=[{"id": WID, "name": setup.WORKSPACE_NAME}],
                   members={WID: [{"service_account_id": SA}]}, rules={NEW_RULE: r_self(**over)})
    assert setup.main(["setup"], run=fake) == 2
    assert fake.writes() == [] and analyze_text() == ANALYZE_TEXT and logged_out(fake)
    assert "never edits a rule" in capsys.readouterr().err


def test_two_workspaces_with_the_name_are_refused():
    ws = [{"id": "wrkspc_a", "name": setup.WORKSPACE_NAME}, {"id": "wrkspc_b", "name": setup.WORKSPACE_NAME}]
    fake = FakeAnt(workspaces=ws)
    assert setup.main(["setup"], run=fake) == 2
    assert fake.writes() == [] and logged_out(fake)


def test_an_archived_workspace_with_the_name_does_not_count():
    fake = FakeAnt(workspaces=[{"id": "wrkspc_old", "name": setup.WORKSPACE_NAME, "archived_at": "t"}])
    assert setup.main(["setup"], run=fake) == 0
    assert [c[:2] for c in fake.writes()][0] == [setup.WORKSPACES, "create"]


def test_r1_with_another_service_account_is_refused_before_any_write():
    fake = FakeAnt()
    fake.rules[R1]["target"]["service_account_id"] = "svac_other"
    assert setup.main(["setup"], run=fake) == 2
    assert fake.writes() == [] and logged_out(fake)


def test_analyze_with_another_real_r_self_is_not_overwritten(capsys):
    setup.ANALYZE_FILE.write_text(ANALYZE_TEXT.replace(setup.PLACEHOLDER, "fdrl_01OtherRuleAbcdefghijklm"))
    before = analyze_text()
    fake = FakeAnt(workspaces=[{"id": WID, "name": setup.WORKSPACE_NAME}],
                   members={WID: [{"service_account_id": SA}]}, rules={NEW_RULE: r_self()})
    assert setup.main(["setup"], run=fake) == 2
    assert analyze_text() == before
    assert "edit analyze.py by hand" in capsys.readouterr().err


def test_analyze_without_the_constant_refuses_before_login():
    setup.ANALYZE_FILE.write_text(ANALYZE_TEXT.replace("SELF_REVIEW_FEDERATION_RULE_ID", "OTHER"))
    fake = FakeAnt()
    assert setup.main(["setup"], run=fake) == 2
    assert fake.calls == []


def test_an_ant_without_a_needed_command_refuses_before_login():
    fake = FakeAnt(help_text="retrieve  update  list")
    assert setup.main(["setup"], run=fake) == 2
    assert all(c[-1] == "--help" for c in fake.calls)


def test_interrupt_logs_out_and_says_how_to_recover(monkeypatch, capsys):
    fake = FakeAnt()

    def interrupt(*a, **k):
        raise KeyboardInterrupt
    monkeypatch.setattr(setup.Setup, "membership", interrupt)
    assert setup.main(["setup"], run=fake) == 130
    assert logged_out(fake)
    assert "make self-review-plan" in capsys.readouterr().err


def test_parse_items_reads_jsonl_items_and_pages():
    text = '{"id": "a"}\n\n{"data": [{"id": "b"}, {"id": "c"}]}\n'
    assert [i["id"] for i in setup.parse_items(text, "x")] == ["a", "b", "c"]
    with pytest.raises(release.ReleaseError):
        setup.parse_items("not json\n", "x")
