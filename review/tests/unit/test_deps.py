"""Unit tests for oc_review.deps. No network: registry tests use a fake fetcher."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from oc_review import deps
from oc_review.deps import DepsError, RegistryError, UnsupportedVersionError

FIXTURES = Path(__file__).parent / "fixtures" / "deps"


def load(fixture: str, as_path: str) -> deps.ParsedDeps:
    return deps.parse_file(as_path, (FIXTURES / fixture).read_bytes())


def by_name(parsed: deps.ParsedDeps) -> dict[str, list[deps.Package]]:
    out: dict[str, list[deps.Package]] = {}
    for pkg in parsed.packages:
        out.setdefault(pkg.name, []).append(pkg)
    return out


def one(parsed: deps.ParsedDeps, name: str) -> deps.Package:
    found = by_name(parsed)[name]
    assert len(found) == 1, found
    return found[0]


# --- family detection ---------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "family"),
    [
        ("package.json", "package.json"),
        ("web/package-lock.json", "package-lock.json"),
        ("yarn.lock", "yarn.lock"),
        ("pnpm-lock.yaml", "pnpm-lock.yaml"),
        ("pyproject.toml", "pyproject.toml"),
        ("a/b/poetry.lock", "poetry.lock"),
        ("uv.lock", "uv.lock"),
        ("requirements.txt", "requirements"),
        ("requirements-dev.txt", "requirements"),
        ("sub/requirements_test.txt", "requirements"),
        ("constraints.txt", None),
        ("requirements.in", None),
        ("package.json.bak", None),
        ("Gemfile.lock", None),
    ],
)
def test_family_for_path(path, family):
    assert deps.family_for_path(path) == family


def test_unsupported_dep_files():
    assert deps.is_unsupported_dep_file("Gemfile.lock")
    assert deps.is_unsupported_dep_file("svc/go.sum")
    assert not deps.is_unsupported_dep_file("package-lock.json")


def test_parse_unsupported_path_raises():
    with pytest.raises(DepsError):
        deps.parse_file("go.sum", b"")


# --- byte cap and decode ------------------------------------------------------


def test_byte_cap_applies_before_parsing(monkeypatch):
    monkeypatch.setattr(deps, "MAX_DEP_FILE_BYTES", 10)
    called = []
    monkeypatch.setitem(deps._PARSERS, "package.json", lambda text: called.append(text))
    with pytest.raises(DepsError, match="byte cap"):
        deps.parse_file("package.json", b"{" + b" " * 20 + b"}")
    assert called == []


def test_non_utf8_raises():
    with pytest.raises(DepsError, match="UTF-8"):
        deps.parse_file("package.json", b"\xff\xfe{}")


@pytest.mark.parametrize(
    ("path", "data"),
    [
        ("package.json", b"{not json"),
        ("package.json", b"[]"),
        ("package.json", b'{"dependencies": ["a"]}'),
        ("package.json", b'{"dependencies": {"a": 1}}'),
        ("package-lock.json", b'{"lockfileVersion": 3, "packages": []}'),
        ("package-lock.json", b'{"lockfileVersion": 3, "packages": {"node_modules/a": 5}}'),
        ("package-lock.json", b'{"lockfileVersion": 3, "packages": {"node_modules/a": {"resolved": "https://registry.npmjs.org/a.tgz"}}}'),
        ("yarn.lock", b"# yarn lockfile v1\n\nfoo@^1:\n  resolved \"x\"\n"),
        ("yarn.lock", b"nothing here"),
        ("pnpm-lock.yaml", b"lockfileVersion: '9.0'\npackages: [1]\n"),
        ("pnpm-lock.yaml", b"lockfileVersion: '9.0'\n: : :\n  - ["),
        ("pyproject.toml", b"[project\n"),
        ("pyproject.toml", b'[project]\ndependencies = ["???"]\n'),
        ("poetry.lock", b"[metadata]\nlock-version = \"2.0\"\n[[package]]\nname = 1\n"),
        ("uv.lock", b"version = 1\n[[package]]\nname = \"a\"\n"),
        ("uv.lock", b"version = 1\n[[package]]\nname = \"a\"\nversion = \"1\"\nsource = { registry = \"x\", git = \"y\" }\n"),
    ],
)
def test_malformed_files_raise(path, data):
    with pytest.raises(DepsError):
        deps.parse_file(path, data)


def test_yaml_is_loaded_safely():
    with pytest.raises(DepsError):
        deps.parse_file("pnpm-lock.yaml", b"lockfileVersion: !!python/object/apply:os.getcwd []\n")


# --- package.json --------------------------------------------------------------


def test_package_json():
    parsed = load("package.json", "package.json")
    assert parsed.format_version is None
    assert one(parsed, "left-pad").source.official
    assert one(parsed, "left-pad").direct is True
    assert one(parsed, "forked").source.kind == "git"
    assert one(parsed, "short").source.kind == "git"
    assert one(parsed, "tarball").source.kind == "url"
    assert one(parsed, "local").source.kind == "file"
    assert one(parsed, "aliased").source.official
    assert one(parsed, "ws").source.kind == "workspace"
    assert one(parsed, "jest").version == "^29.0.0"
    assert "fsevents" in by_name(parsed)


# --- package-lock.json ---------------------------------------------------------


def test_package_lock_v2():
    parsed = load("package-lock.v2.json", "package-lock.json")
    assert parsed.format_version == "2"
    assert one(parsed, "left-pad").version == "1.3.0"
    assert one(parsed, "left-pad").direct is True
    assert one(parsed, "esbuild").has_install_script is True
    assert one(parsed, "left-pad").has_install_script is False
    nested = one(parsed, "nested")
    assert nested.direct is False
    assert all(p.source.official for p in parsed.packages)
    assert deps.non_registry_sources(parsed) == []


def test_package_lock_v3_sources():
    parsed = load("package-lock.v3.json", "package-lock.json")
    assert parsed.format_version == "3"
    gitdep = one(parsed, "gitdep")
    assert gitdep.source.kind == "git"
    assert gitdep.source.normalized == "git+ssh://github.com/o/r.git#0123456789abcdef"
    assert "git@" not in gitdep.source.normalized
    evil = one(parsed, "evil")
    assert evil.source.kind == "url" and evil.source.host == "evil.example.com"
    assert one(parsed, "real-name").version == "2.0.0"  # alias uses the real name
    assert one(parsed, "linked").source.kind == "workspace"
    assert one(parsed, "bundled").source.kind == "bundled"
    assert "linked" in by_name(parsed) and len(by_name(parsed)["linked"]) == 1
    foreign = {i.name for i in deps.non_registry_sources(parsed) if i.source.foreign}
    assert foreign == {"gitdep", "evil"}
    assert not one(parsed, "bundled").source.foreign


def test_package_lock_v1_is_unknown_version():
    with pytest.raises(UnsupportedVersionError):
        load("package-lock.v1.json", "package-lock.json")


def test_package_lock_missing_resolved_is_unknown_source():
    data = json.dumps(
        {"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"version": "1.0.0"}}}
    ).encode()
    parsed = deps.parse_file("package-lock.json", data)
    assert parsed.packages[0].source.kind == "unknown"
    assert parsed.packages[0].source.foreign


@pytest.mark.parametrize(
    "resolved",
    [
        "http://registry.npmjs.org/a/-/a-1.0.0.tgz",
        "https://registry.npmjs.org.evil.example/a/-/a-1.0.0.tgz",
        "https://user:pw@registry.npmjs.org/a/-/a-1.0.0.tgz",
        "https://registry.npmjs.org:8443/a/-/a-1.0.0.tgz",
        "https://evil.example/registry.npmjs.org/a.tgz",
    ],
)
def test_lookalike_registry_hosts_are_foreign(resolved):
    source = deps.classify_source(resolved, deps.NPM_OFFICIAL_HOSTS)
    assert source.foreign


def test_url_credentials_are_redacted():
    source = deps.classify_source("https://tok:secret@example.com/a.tgz", frozenset())
    assert "secret" not in source.normalized and "tok" not in source.normalized


# --- yarn.lock -----------------------------------------------------------------


def test_yarn_v1():
    parsed = load("yarn.v1.lock", "yarn.lock")
    assert parsed.format_version == "1"
    core = one(parsed, "@babel/core")
    assert core.version == "7.1.0" and core.source.official
    assert one(parsed, "left-pad").source.official
    assert one(parsed, "forked").source.kind == "git"
    assert one(parsed, "tarball").source.kind == "url"
    alias = one(parsed, "real-name")  # `alias@npm:real-name@...`
    assert alias.version == "2.0.1"


@pytest.mark.parametrize("fixture", ["yarn.berry4.lock", "yarn.berry6.lock", "yarn.berry8.lock"])
def test_yarn_berry_versions_parse(fixture):
    parsed = load(fixture, "yarn.lock")
    assert parsed.format_version in {"4", "6", "8"}
    assert parsed.packages


def test_yarn_berry6_sources():
    parsed = load("yarn.berry6.lock", "yarn.lock")
    assert one(parsed, "left-pad").source.official
    assert one(parsed, "forked").source.kind == "git"
    assert one(parsed, "demo").source.kind == "workspace"
    assert one(parsed, "typescript").source.official  # builtin patch
    mirror = one(parsed, "mirror")
    assert mirror.source.kind == "url" and mirror.source.host == "evil.example.com"
    assert {i.name for i in deps.non_registry_sources(parsed) if i.source.foreign} == {"forked", "mirror"}


def test_yarn_berry8_scoped_name():
    parsed = load("yarn.berry8.lock", "yarn.lock")
    assert one(parsed, "@scope/pkg").version == "2.1.0"


def test_yarn_berry_unknown_version():
    with pytest.raises(UnsupportedVersionError):
        load("yarn.berry99.lock", "yarn.lock")


# --- pnpm-lock.yaml ------------------------------------------------------------


def test_pnpm_v6():
    parsed = load("pnpm-lock.v6.yaml", "pnpm-lock.yaml")
    assert parsed.format_version == "6.0"
    assert one(parsed, "left-pad").direct is True
    assert one(parsed, "@babel/core").version == "7.1.0"  # peer suffix stripped
    assert one(parsed, "esbuild").has_install_script is True
    forked = one(parsed, "forked")
    assert forked.source.kind == "git"
    assert forked.source.normalized.endswith("#abcdef")
    assert one(parsed, "tar").source.kind == "url"


def test_pnpm_v9():
    parsed = load("pnpm-lock.v9.yaml", "pnpm-lock.yaml")
    assert parsed.format_version == "9.0"
    assert one(parsed, "left-pad").direct is True
    assert one(parsed, "@babel/core").version == "7.1.0"
    assert one(parsed, "esbuild").has_install_script is True
    evil = one(parsed, "evil")
    assert evil.source.kind == "url" and evil.source.foreign
    assert one(parsed, "left-pad").source.official


def test_pnpm_v5_is_unknown_version():
    with pytest.raises(UnsupportedVersionError):
        load("pnpm-lock.v5.yaml", "pnpm-lock.yaml")


# --- pyproject.toml ------------------------------------------------------------


def test_pyproject_pep621():
    parsed = load("pyproject.toml", "pyproject.toml")
    assert one(parsed, "requests").version == ">=2.31"
    assert one(parsed, "flask").version == "3.0.0"
    assert one(parsed, "hatchling").direct is True  # build-system.requires
    assert one(parsed, "pytest").version == ">=8"
    assert one(parsed, "ruff").version == ""
    private = one(parsed, "private-lib")
    assert private.source.kind == "git"
    assert one(parsed, "tarpkg").source.kind == "url"
    internal = one(parsed, "internal-pkg")
    assert internal.source.kind == "registry" and not internal.source.official
    assert internal.source.host == "pypi.corp.example"
    assert one(parsed, "rich").source.kind == "file"
    # The corp index is also a file-wide source.
    assert [s.host for s in parsed.global_sources] == ["pypi.corp.example"]
    assert "include-group" not in str(by_name(parsed).keys())


def test_pyproject_poetry():
    parsed = load("pyproject-poetry.toml", "pyproject.toml")
    assert "python" not in by_name(parsed)
    assert one(parsed, "requests").source.official
    assert one(parsed, "forked").source.kind == "git"
    assert one(parsed, "local").source.kind == "file"
    assert one(parsed, "multi").version == "^1.0 || ^2.0"
    assert one(parsed, "pytest").version == "^8"


# --- poetry.lock ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("fixture", "version"),
    [("poetry.v1_1.lock", "1.1"), ("poetry.v2_0.lock", "2.0"), ("poetry.v2_1.lock", "2.1")],
)
def test_poetry_lock_versions(fixture, version):
    parsed = load(fixture, "poetry.lock")
    assert parsed.format_version == version
    assert one(parsed, "requests").source.official


def test_poetry_lock_sources():
    parsed = load("poetry.v2_0.lock", "poetry.lock")
    forked = one(parsed, "forked-pkg")  # name is PEP 503 normalized
    assert forked.source.kind == "git"
    assert forked.source.normalized == "https://github.com/o/forked.git#0123456789abcdef"
    corp = one(parsed, "corp")
    assert corp.source.kind == "registry" and corp.source.foreign
    assert one(parsed, "viapypi").source.official


def test_poetry_lock_unknown_version():
    with pytest.raises(UnsupportedVersionError):
        load("poetry.v3_0.lock", "poetry.lock")


# --- uv.lock -------------------------------------------------------------------


@pytest.mark.parametrize("fixture", ["uv.v1.lock", "uv.v1-rev3.lock"])
def test_uv_lock_version_1(fixture):
    parsed = load(fixture, "uv.lock")
    assert parsed.format_version == "1"
    assert one(parsed, "requests").source.official


def test_uv_lock_sources():
    parsed = load("uv.v1.lock", "uv.lock")
    assert one(parsed, "demo").source.kind == "workspace"
    assert one(parsed, "forked-pkg").source.kind == "git"
    assert one(parsed, "tarpkg").source.kind == "url"
    assert one(parsed, "corp").source.foreign
    assert one(parsed, "localpkg").source.kind == "file"
    foreign = {i.name for i in deps.non_registry_sources(parsed) if i.source.foreign}
    assert foreign == {"forked-pkg", "tarpkg", "corp"}


def test_uv_lock_unknown_version():
    with pytest.raises(UnsupportedVersionError):
        load("uv.v2.lock", "uv.lock")


# --- requirements*.txt ---------------------------------------------------------


def test_requirements():
    parsed = load("requirements.txt", "requirements.txt")
    assert one(parsed, "requests").version == "2.31.0"  # continuation and hashes
    assert one(parsed, "flask").version == ">=3.0"
    assert one(parsed, "django").version == ">=4.2,<5"
    assert one(parsed, "private-lib").source.kind == "git"
    assert one(parsed, "other-pkg").source.kind == "git"
    edit = one(parsed, "edit")
    assert edit.source.kind == "git" and "secret" not in edit.source.normalized
    assert one(parsed, "(url)").source.kind == "url"
    paths = [p for p in parsed.packages if p.name == "(path)"]
    assert {p.version for p in paths} == {"./local/pkg", "../editable"}
    # index-url on another host counts as a file-wide foreign source; pypi.org does not.
    issues = deps.non_registry_sources(parsed)
    assert issues[0].name is None and issues[0].source.host == "pypi.corp.example"
    assert [i.source.host for i in issues if i.name is None] == ["pypi.corp.example"]


# --- delta and agreement -------------------------------------------------------


def test_compute_delta():
    old = deps.parse_file(
        "package-lock.json",
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {},
                    "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
                    "node_modules/b": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/b/-/b-1.0.0.tgz"},
                    "node_modules/gone": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/gone/-/gone-1.0.0.tgz"},
                },
            }
        ).encode(),
    )
    new = deps.parse_file(
        "package-lock.json",
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {},
                    "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
                    "node_modules/b": {"version": "1.1.0", "resolved": "https://registry.npmjs.org/b/-/b-1.1.0.tgz", "hasInstallScript": True},
                    "node_modules/c": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/c/-/c-2.0.0.tgz"},
                },
            }
        ).encode(),
    )
    changes = {c.name: c for c in deps.compute_delta(old, new)}
    assert set(changes) == {"b", "c"}
    assert changes["b"].old_versions == ("1.0.0",)
    assert changes["b"].new_version == "1.1.0"
    assert changes["b"].has_install_script is True
    assert changes["c"].old_versions == ()
    assert len(deps.compute_delta(None, new)) == 3


def test_delta_catches_source_change_at_same_version():
    def lock(resolved):
        return deps.parse_file(
            "package-lock.json",
            json.dumps(
                {"lockfileVersion": 3, "packages": {"": {}, "node_modules/a": {"version": "1.0.0", "resolved": resolved}}}
            ).encode(),
        )

    old = lock("https://registry.npmjs.org/a/-/a-1.0.0.tgz")
    new = lock("https://evil.example.com/a-1.0.0.tgz")
    assert [c.name for c in deps.compute_delta(old, new)] == ["a"]


def test_manifest_without_lockfile():
    repo = ["package.json", "package-lock.json", "svc/pyproject.toml", "svc/uv.lock", "tools/pyproject.toml"]
    assert deps.manifest_without_lockfile(["package.json"], repo) == ["package.json"]
    assert deps.manifest_without_lockfile(["package.json", "package-lock.json"], repo) == []
    assert deps.manifest_without_lockfile(["svc/pyproject.toml"], repo) == ["svc/pyproject.toml"]
    assert deps.manifest_without_lockfile(["svc/pyproject.toml", "svc/uv.lock"], repo) == []
    # No lockfile for this manifest in the repo: no signal.
    assert deps.manifest_without_lockfile(["tools/pyproject.toml"], repo) == []
    # A root lockfile covers a workspace manifest below it.
    assert deps.manifest_without_lockfile(["web/package.json"], repo) == ["web/package.json"]
    assert deps.manifest_without_lockfile(["web/package.json", "package-lock.json"], repo) == []


# --- registry: URL builders ----------------------------------------------------


def test_npm_url():
    assert deps.npm_url("left-pad") == "https://registry.npmjs.org/left-pad"
    assert deps.npm_url("@babel/core") == "https://registry.npmjs.org/@babel%2Fcore"


def test_pypi_url_uses_normalized_name():
    assert deps.pypi_url("Flask_SQLAlchemy") == "https://pypi.org/pypi/flask-sqlalchemy/json"


@pytest.mark.parametrize(
    "name",
    [
        "",
        "../etc/passwd",
        "a/b",
        "@scope/",
        "@/name",
        "a b",
        "a?x=1",
        "a#frag",
        "a%2Fb",
        "https://evil.example/x",
        "evil.example:8080@x",
        ".hidden",
        "_private",
        "a" * 215,
        "a\nb",
        "a\\b",
    ],
)
def test_npm_url_rejects_bad_names(name):
    with pytest.raises(RegistryError):
        deps.npm_url(name)


@pytest.mark.parametrize(
    "name", ["", "a/b", "../x", "a b", "-x", "x-", "a?b", "a#b", "a%2Fb", "a" * 215, "a\nb", "@scope/x"]
)
def test_pypi_url_rejects_bad_names(name):
    with pytest.raises(RegistryError):
        deps.pypi_url(name)


# --- registry: lookups with a fake fetcher ------------------------------------

NPM_DOC = {
    "name": "esbuild",
    "time": {"created": "2020-01-01T00:00:00.000Z", "0.19.0": "2023-06-01T12:30:00.000Z"},
    "versions": {
        "0.19.0": {
            "scripts": {"postinstall": "node install.js", "test": "jest", "prepare": "husky"},
        }
    },
}
PYPI_DOC = {
    "info": {"name": "Flask"},
    "releases": {
        "3.0.0": [
            {"upload_time_iso_8601": "2023-09-30T10:00:00.500000Z"},
            {"upload_time_iso_8601": "2023-09-30T09:59:00.000000Z"},
        ],
        "3.0.1": [],
    },
}


class FakeFetch:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.calls: list[tuple[str, int, float]] = []

    def __call__(self, url, max_bytes, timeout):
        self.calls.append((url, max_bytes, timeout))
        item = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(item, Exception):
            raise item
        return item


def ok(doc, url, status=200):
    return deps.FetchResult(status=status, body=json.dumps(doc).encode(), url=url)


def test_lookup_npm():
    fetch = FakeFetch(ok(NPM_DOC, "https://registry.npmjs.org/esbuild"))
    info = deps.lookup_npm("esbuild", "0.19.0", fetch)
    assert info.published == datetime(2023, 6, 1, 12, 30, tzinfo=UTC)
    assert info.install_scripts == {"postinstall": "node install.js", "prepare": "husky"}
    url, max_bytes, timeout = fetch.calls[0]
    assert url == "https://registry.npmjs.org/esbuild"
    assert max_bytes == deps.NPM_MAX_RESPONSE_BYTES
    assert timeout == deps.REGISTRY_TIMEOUT_SECONDS


def test_lookup_npm_scoped_url():
    doc = {"name": "@a/b", "time": {"1.0.0": "2024-01-01T00:00:00Z"}, "versions": {"1.0.0": {}}}
    fetch = FakeFetch(ok(doc, "https://registry.npmjs.org/@a%2Fb"))
    info = deps.lookup_npm("@a/b", "1.0.0", fetch)
    assert fetch.calls[0][0] == "https://registry.npmjs.org/@a%2Fb"
    assert info.install_scripts == {}


def test_lookup_pypi_takes_earliest_upload():
    fetch = FakeFetch(ok(PYPI_DOC, "https://pypi.org/pypi/flask/json"))
    info = deps.lookup_pypi("Flask", "3.0.0", fetch)
    assert info.published == datetime(2023, 9, 30, 9, 59, tzinfo=UTC)
    assert fetch.calls[0][0] == "https://pypi.org/pypi/flask/json"
    assert fetch.calls[0][1] == deps.PYPI_MAX_RESPONSE_BYTES


def test_lookup_never_fetches_for_a_bad_name():
    fetch = FakeFetch(ok({}, "x"))
    with pytest.raises(RegistryError):
        deps.lookup_npm("../x", "1.0.0", fetch)
    with pytest.raises(RegistryError):
        deps.lookup_pypi("a/b", "1.0.0", fetch)
    assert fetch.calls == []


def test_version_is_never_part_of_the_url():
    fetch = FakeFetch(ok(NPM_DOC, "https://registry.npmjs.org/esbuild"))
    with pytest.raises(RegistryError):
        deps.lookup_npm("esbuild", "../../evil", fetch)
    assert fetch.calls[0][0] == "https://registry.npmjs.org/esbuild"


@pytest.mark.parametrize(
    "final_url",
    [
        "https://evil.example.com/esbuild",
        "http://registry.npmjs.org/esbuild",
        "https://registry.npmjs.org.evil.example/esbuild",
        "https://registry.npmjs.org:8443/esbuild",
        "https://user@registry.npmjs.org@evil.example/esbuild",
    ],
)
def test_redirect_to_another_host_is_rejected(final_url):
    fetch = FakeFetch(ok(NPM_DOC, final_url))
    with pytest.raises(RegistryError, match="another host"):
        deps.lookup_npm("esbuild", "0.19.0", fetch)


def test_redirect_status_is_rejected():
    resp = deps.FetchResult(status=302, body=b"", url="https://registry.npmjs.org/esbuild")
    with pytest.raises(RegistryError, match="HTTP 302"):
        deps.lookup_npm("esbuild", "0.19.0", FakeFetch(resp))


def test_oversized_response_is_rejected_before_parsing():
    body = b"x" * (deps.NPM_MAX_RESPONSE_BYTES + 1)
    resp = deps.FetchResult(status=200, body=body, url="https://registry.npmjs.org/esbuild")
    with pytest.raises(RegistryError, match="byte cap"):
        deps.lookup_npm("esbuild", "0.19.0", FakeFetch(resp))


@pytest.mark.parametrize(
    "doc",
    [
        [],
        {"name": "other", "time": {}, "versions": {}},
        {"name": "esbuild"},
        {"name": "esbuild", "time": {"0.19.0": "x"}, "versions": {"0.19.0": {}}},
        {"name": "esbuild", "time": {}, "versions": {"0.19.0": {}}},
        {"name": "esbuild", "time": {"0.19.0": "2023-01-01T00:00:00Z"}, "versions": {"0.19.0": {"scripts": []}}},
        {"name": "esbuild", "time": {"0.19.0": "2023-01-01T00:00:00Z"}, "versions": {"0.19.0": {"scripts": {"install": 1}}}},
    ],
)
def test_invalid_npm_documents_raise(doc):
    fetch = FakeFetch(ok(doc, "https://registry.npmjs.org/esbuild"))
    with pytest.raises(RegistryError):
        deps.lookup_npm("esbuild", "0.19.0", fetch)


def test_not_json_raises():
    resp = deps.FetchResult(status=200, body=b"<html>", url="https://registry.npmjs.org/esbuild")
    with pytest.raises(RegistryError, match="not JSON"):
        deps.lookup_npm("esbuild", "0.19.0", FakeFetch(resp))


@pytest.mark.parametrize("version", ["9.9.9", "3.0.1"])
def test_pypi_missing_or_empty_version_raises(version):
    fetch = FakeFetch(ok(PYPI_DOC, "https://pypi.org/pypi/flask/json"))
    with pytest.raises(RegistryError, match="not found"):
        deps.lookup_pypi("flask", version, fetch)


def test_pypi_response_for_another_package_raises():
    doc = {**PYPI_DOC, "info": {"name": "other"}}
    with pytest.raises(RegistryError, match="another package"):
        deps.lookup_pypi("flask", "3.0.0", FakeFetch(ok(doc, "https://pypi.org/pypi/flask/json")))


def test_retries_then_succeeds():
    sleeps = []
    fetch = FakeFetch(
        TimeoutError("slow"),
        deps.FetchResult(status=503, body=b"", url="https://registry.npmjs.org/esbuild"),
        ok(NPM_DOC, "https://registry.npmjs.org/esbuild"),
    )
    info = deps.lookup_npm("esbuild", "0.19.0", fetch, sleep=sleeps.append)
    assert info.version == "0.19.0"
    assert len(fetch.calls) == 3
    assert len(sleeps) == 2


def test_retries_exhausted_raises():
    fetch = FakeFetch(OSError("down"))
    with pytest.raises(RegistryError, match="failed after 3 attempts"):
        deps.lookup_npm("esbuild", "0.19.0", fetch, sleep=lambda _s: None)
    assert len(fetch.calls) == 3


def test_client_error_is_not_retried():
    resp = deps.FetchResult(status=404, body=b"", url="https://registry.npmjs.org/esbuild")
    fetch = FakeFetch(resp)
    with pytest.raises(RegistryError, match="HTTP 404"):
        deps.lookup_npm("esbuild", "0.19.0", fetch, sleep=lambda _s: None)
    assert len(fetch.calls) == 1


def test_default_fetch_refuses_other_hosts():
    with pytest.raises(RegistryError):
        deps.default_fetch("https://evil.example.com/x", 10, 1.0)
    with pytest.raises(RegistryError):
        deps.default_fetch("http://registry.npmjs.org/x", 10, 1.0)
