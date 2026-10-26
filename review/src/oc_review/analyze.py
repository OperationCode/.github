"""The Claude call: one Messages API call per pass, no tools.

Analyze reads the bundle envelope from collect, checks it against the trusted
run context, and always writes exactly three pass records, one per pass
(review, security, supply-chain). Claude returns findings JSON only. Code
checks the response against the full findings schema; a pass that fails any
check is `failed`, with a clear reason in the record's `meta`. Analyze never
decides the gate.

Exit code: 0 when the three records were written, whatever their status (a
failed pass still fails the gate, not waivable). Non-zero only when the bundle
is not trusted (no record can name a snapshot it cannot trust) or the records
cannot be written.

Federation: the IDs below are not secret. They live in the pinned code, so a
repo cannot change them, and each release names its own rule. Until the owner
creates the production rule they are placeholders, and analyze refuses to call.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import json
import os
import re
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence

from . import collect, envelope, render, snapshot

PASS_NAMES = ("review", "security", "supply-chain")
# Started first; the other passes start when its response begins to stream,
# so they can read the cache entry it writes (spec "Cache order").
FIRST_PASS = "supply-chain"

MODEL = "claude-opus-5-5"
EFFORT = {"review": "medium", "security": "medium", "supply-chain": "high"}
# Thinking tokens count toward `max_tokens`, so this bounds thinking plus output.
MAX_TOKENS = {"review": 16_000, "security": 16_000, "supply-chain": 32_000}
FALLBACK_BETA = "server-side-fallback-2026-07-01"
MAX_RETRIES = 2
# Absolute deadline per pass, from the start of analyze. Each SDK attempt gets
# at most the time left, so the passes end inside the 10-minute job timeout.
DEADLINE_SECONDS = 420.0

# Production federation rule (spec "Auth and cost", "Each release").
# Placeholders until the owner creates the rule: analyze refuses to call.
ANTHROPIC_FEDERATION_RULE_ID = "fdrl_000000000000000000000000"
ANTHROPIC_ORGANIZATION_ID = "00000000-0000-0000-0000-000000000000"
ANTHROPIC_SERVICE_ACCOUNT_ID = "svac_000000000000000000000000"

FEDERATION_RULE_ID_RE = re.compile(r"^fdrl_[A-Za-z0-9]{24}$")
ORGANIZATION_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SERVICE_ACCOUNT_ID_RE = re.compile(r"^svac_[A-Za-z0-9]{24}$")

OIDC_AUDIENCE = "https://api.anthropic.com"
OIDC_MAX_BYTES = 64 * 1024
OIDC_TIMEOUT_SECONDS = 30.0
OIDC_RETRIES = 2
TOKEN_FILE_PREFIX = "oc-review-oidc-"

# Structured outputs reject these keywords (spec "Request shape", P0-12). The
# request carries a copy without them; the full schema stays the contract.
UNSUPPORTED_SCHEMA_KEYWORDS = frozenset({
    "minLength", "maxLength", "minimum", "maximum", "exclusiveMinimum",
    "exclusiveMaximum", "multipleOf", "minItems", "maxItems", "uniqueItems",
})
# Keywords whose value is a map of names to subschemas: the names are data.
_SCHEMA_MAPS = frozenset({"properties", "patternProperties", "$defs", "definitions", "dependentSchemas"})
# Keywords whose value is one subschema (or, for `items`, a list in old drafts).
_SCHEMA_ONE = frozenset({
    "items", "additionalItems", "additionalProperties", "unevaluatedItems",
    "unevaluatedProperties", "contains", "propertyNames", "not", "if", "then", "else",
})
_SCHEMA_LISTS = frozenset({"allOf", "anyOf", "oneOf", "prefixItems"})

SPEND_LIMIT_TEXT = "workspace API usage limits"

# Reasons in `meta.reason`. Code text only: never model or PR text.
R_SPEND_LIMIT = "workspace spend limit reached"
R_REQUEST_REJECTED = "request rejected"
R_AUTH = "authentication failed"
R_UNAVAILABLE = "API unavailable"
R_DEADLINE = "deadline exceeded"
R_RENDER = "render failed"
R_FEDERATION_NOT_CONFIGURED = "federation not configured"
R_OIDC_MISMATCH = "OIDC claim mismatch"
R_OIDC_UNAVAILABLE = "OIDC token unavailable"
R_PR_READ = "PR read failed"
R_NO_TEXT = "response has no text block"
R_BAD_JSON = "response is not valid JSON"
R_SCHEMA = "response does not match the findings schema"
R_RECORD = "pass record is not valid"
R_INTERNAL = "internal error"

META_REASON_MAX = 200
META_MODEL_MAX = 100
META_STOP_REASON_MAX = 40
_USAGE_FIELDS = ("input_tokens", "output_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
_SCHEMA_ERROR_RE = re.compile(r"^findings schema: (.*?: \[\w+\])")


class AnalyzeError(Exception):
    """The bundle or the run context is not trusted. No record is written."""


class PassFailure(Exception):
    """One pass failed. `reason` goes into the record's `meta`."""

    def __init__(self, reason: str, *, model: str | None = None, stop_reason: str | None = None,
                 usage: dict[str, int] | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.model = model
        self.stop_reason = stop_reason
        self.usage = usage


@dataclass(frozen=True)
class PassResult:
    status: str  # ok | failed | skipped-size | stale
    payload: dict[str, Any] | None
    reason: str | None = None
    model: str | None = None
    stop_reason: str | None = None
    usage: dict[str, int] | None = None


@dataclass(frozen=True)
class WrittenRecord:
    path: Path
    digest: str
    status: str


# ---------------------------------------------------------------------------
# Request schema
# ---------------------------------------------------------------------------


def strip_schema(schema: Any) -> Any:
    """Copy of a JSON Schema without the keywords structured outputs reject.

    The walk knows the schema structure: it removes a keyword only where it is
    a keyword, never a property *named* like one, and it copies data values
    (`enum`, `const`, `default`, `examples`, `required`) unchanged."""
    if isinstance(schema, bool) or not isinstance(schema, Mapping):
        return copy.deepcopy(schema)
    out: dict[str, Any] = {}
    for key, value in schema.items():
        if key in UNSUPPORTED_SCHEMA_KEYWORDS:
            continue
        if key in _SCHEMA_MAPS and isinstance(value, Mapping):
            out[key] = {name: strip_schema(sub) for name, sub in value.items()}
        elif key in _SCHEMA_ONE:
            out[key] = [strip_schema(s) for s in value] if isinstance(value, list) else strip_schema(value)
        elif key in _SCHEMA_LISTS and isinstance(value, list):
            out[key] = [strip_schema(s) for s in value]
        else:
            out[key] = copy.deepcopy(value)
    return out


def canonical_json(doc: Any) -> bytes:
    return json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")


def schema_digest(schema: Any) -> str:
    return hashlib.sha256(canonical_json(schema)).hexdigest()


def request_schema() -> dict[str, Any]:
    full = envelope.parse_json((envelope.SCHEMA_DIR / "findings.schema.json").read_bytes())
    return strip_schema(full)


def build_request(pass_name: str, *, system_text: str, user_text: str, pass_text: str,
                  schema: Mapping[str, Any]) -> dict[str, Any]:
    """Keyword arguments of `client.beta.messages.stream` for one pass, without
    the timeout. No `tools` and no `tool_choice`: Claude can only return JSON.

    The system prompt and the user message are the same for all three passes,
    so they share one cache entry. The pass message is a mid-conversation
    system message, after the untrusted data, as the last entry."""
    return {
        "model": MODEL,
        "max_tokens": MAX_TOKENS[pass_name],
        "system": system_text,
        "messages": [
            {
                "role": "user",
                "content": [{"type": "text", "text": user_text, "cache_control": {"type": "ephemeral"}}],
            },
            {"role": "system", "content": pass_text},
        ],
        "output_config": {
            "effort": EFFORT[pass_name],
            "format": {"type": "json_schema", "schema": copy.deepcopy(dict(schema))},
        },
        "fallbacks": "default",
        "betas": [FALLBACK_BETA],
    }


# ---------------------------------------------------------------------------
# Response handling
# ---------------------------------------------------------------------------


def _clip(value: Any, limit: int) -> str | None:
    return value[:limit] if isinstance(value, str) else None


def usage_of(message: Any) -> dict[str, int] | None:
    """Token counts from the top-level `usage`. `iterations` is the number of
    sampling attempts, fallback attempts included, when the API reports them."""
    usage = getattr(message, "usage", None)
    if usage is None:
        return None
    out: dict[str, int] = {}
    for name in _USAGE_FIELDS:
        v = getattr(usage, name, None)
        if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
            out[name] = v
    iterations = getattr(usage, "iterations", None)
    if isinstance(iterations, list):
        out["iterations"] = len(iterations)
    return out


def parse_response(message: Any) -> PassResult:
    """Check `stop_reason` first, then parse the final text block and check it
    against the full findings schema. Never truncates."""
    model = _clip(getattr(message, "model", None), META_MODEL_MAX)
    stop_reason = _clip(getattr(message, "stop_reason", None), META_STOP_REASON_MAX)
    usage = usage_of(message)
    info = {"model": model, "stop_reason": stop_reason, "usage": usage}
    if stop_reason != "end_turn":
        raise PassFailure(f"stop reason {stop_reason or 'missing'}", **info)
    # The final text block: a fallback block (and any text of a model that
    # declined) comes before it.
    texts = [b for b in (getattr(message, "content", None) or []) if getattr(b, "type", None) == "text"]
    if not texts or not isinstance(getattr(texts[-1], "text", None), str):
        raise PassFailure(R_NO_TEXT, **info)
    try:
        doc = envelope.parse_json(texts[-1].text.encode("utf-8"))
    except (envelope.EnvelopeError, UnicodeEncodeError) as exc:
        raise PassFailure(R_BAD_JSON, **info) from exc
    try:
        envelope.validate_findings(doc)
    except envelope.EnvelopeError as exc:
        # Name the place and the keyword only; the value is model text.
        m = _SCHEMA_ERROR_RE.match(str(exc))
        raise PassFailure(f"{R_SCHEMA}: {m.group(1)}" if m else R_SCHEMA, **info) from exc
    return PassResult("ok", doc, None, model, stop_reason, usage)


def _error_body(exc: Exception) -> tuple[str | None, str]:
    body = getattr(exc, "body", None)
    err = body.get("error") if isinstance(body, Mapping) else None
    if isinstance(err, Mapping):
        etype = err.get("type") if isinstance(err.get("type"), str) else None
        msg = err.get("message") if isinstance(err.get("message"), str) else ""
        return etype, msg
    return None, str(getattr(exc, "message", "") or exc)


def classify_error(exc: BaseException) -> str:
    """Map an SDK error (after the SDK's own retries) to a pass failure reason.

    The spend limit is an outage, not a request bug: HTTP 400
    `invalid_request_error` with "workspace API usage limits" (V9). The SDK does
    not retry a 400."""
    import anthropic

    if isinstance(exc, anthropic.APIStatusError):
        status = exc.status_code
        etype, msg = _error_body(exc)
        if status == 400:
            if etype == "invalid_request_error" and SPEND_LIMIT_TEXT in msg:
                return R_SPEND_LIMIT
            return R_REQUEST_REJECTED
        if status in (401, 403):
            return R_AUTH
        if 400 <= status < 500 and status not in (408, 409, 429):
            return R_REQUEST_REJECTED
        return R_UNAVAILABLE
    if isinstance(exc, anthropic.APIConnectionError):  # includes APITimeoutError
        return R_UNAVAILABLE
    if isinstance(exc, anthropic.WorkloadIdentityError):
        code = exc.status_code
        return R_UNAVAILABLE if code is None or code == 429 or code >= 500 else R_AUTH
    if isinstance(exc, anthropic.CredentialsError):
        return R_AUTH
    if isinstance(exc, anthropic.APIError):
        return R_UNAVAILABLE
    return R_INTERNAL


class _DeadlinePassed(Exception):
    pass


def call_pass(
    client: Any,
    request: Mapping[str, Any],
    *,
    deadline: float,
    clock: Callable[[], float],
    on_first_event: Callable[[], None] = lambda: None,
) -> PassResult:
    """One streamed Messages API call. Raises PassFailure."""
    remaining = deadline - clock()
    if remaining <= 0:
        raise PassFailure(R_DEADLINE)
    try:
        with client.beta.messages.stream(**request, timeout=remaining) as stream:
            first = True
            for _event in stream:
                if first:
                    first = False
                    on_first_event()
                if clock() > deadline:
                    raise _DeadlinePassed()
            message = stream.get_final_message()
    except _DeadlinePassed:
        raise PassFailure(R_DEADLINE) from None
    except Exception as exc:  # the SDK raises many types; classify them all
        if clock() >= deadline:
            raise PassFailure(R_DEADLINE) from None
        raise PassFailure(classify_error(exc)) from None
    return parse_response(message)


# ---------------------------------------------------------------------------
# Federation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FederationIds:
    rule_id: str
    organization_id: str
    service_account_id: str


def federation_ids() -> FederationIds:
    return FederationIds(ANTHROPIC_FEDERATION_RULE_ID, ANTHROPIC_ORGANIZATION_ID, ANTHROPIC_SERVICE_ACCOUNT_ID)


def _all_zero(s: str) -> bool:
    return set(s) <= {"0", "-"}


def ids_valid(ids: FederationIds) -> bool:
    return bool(
        FEDERATION_RULE_ID_RE.match(ids.rule_id)
        and ORGANIZATION_ID_RE.match(ids.organization_id)
        and SERVICE_ACCOUNT_ID_RE.match(ids.service_account_id)
    )


def ids_are_placeholders(ids: FederationIds) -> bool:
    """True when any ID is still a placeholder (all zeros after its prefix)."""
    return (
        _all_zero(ids.rule_id.removeprefix("fdrl_"))
        or _all_zero(ids.organization_id)
        or _all_zero(ids.service_account_id.removeprefix("svac_"))
    )


# mint() -> the GitHub OIDC token (a JWT). Raises OidcError.
OidcMinter = Callable[[], str]
# oidc transport(url, request_token) -> (status, body bytes). Never follows a
# redirect and reads at most OIDC_MAX_BYTES + 1 bytes.
OidcTransport = Callable[[str, str], tuple[int, bytes]]


class OidcError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def default_oidc_transport(url: str, request_token: str) -> tuple[int, bytes]:
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        raise OidcError("OIDC request URL is not https")
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"Authorization": f"bearer {request_token}", "Accept": "application/json"})
    try:
        with opener.open(req, timeout=OIDC_TIMEOUT_SECONDS) as resp:
            return resp.status, resp.read(OIDC_MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, b""


def oidc_minter(
    request_url: str | None,
    request_token: str | None,
    transport: OidcTransport = default_oidc_transport,
    *,
    sleep: Callable[[float], None] = time.sleep,
) -> OidcMinter:
    """Mint a GitHub OIDC token with audience `https://api.anthropic.com`."""

    def mint() -> str:
        if not request_url or not request_token:
            raise OidcError("OIDC request variables are not set")
        sep = "&" if urllib.parse.urlsplit(request_url).query else "?"
        url = f"{request_url}{sep}audience={urllib.parse.quote(OIDC_AUDIENCE, safe='')}"
        last = ""
        for attempt in range(OIDC_RETRIES + 1):
            if attempt:
                sleep(0.5 * 2 ** (attempt - 1))
            try:
                status, body = transport(url, request_token)
            except (OSError, ValueError) as exc:
                last = type(exc).__name__
                continue
            if status == 429 or status >= 500:
                last = f"HTTP {status}"
                continue
            if status != 200:
                raise OidcError(f"OIDC token request: HTTP {status}")
            if len(body) > OIDC_MAX_BYTES:
                raise OidcError("OIDC token response over the byte cap")
            try:
                value = envelope.parse_json(body).get("value")
            except (envelope.EnvelopeError, AttributeError) as exc:
                raise OidcError("OIDC token response is not a JSON object") from exc
            if not isinstance(value, str) or value.count(".") != 2:
                raise OidcError("OIDC token response has no JWT")
            return value
        raise OidcError(f"OIDC token request failed ({last})")

    return mint


def jwt_claims(token: str) -> dict[str, Any]:
    """Decode the JWT payload without verifying it. Only the claim check below
    reads it; Anthropic verifies the token at the exchange."""
    parts = token.split(".")
    if len(parts) != 3:
        raise OidcError("token is not a JWT")
    seg = parts[1]
    try:
        raw = base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))
        claims = envelope.parse_json(raw)
    except (binascii.Error, ValueError, envelope.EnvelopeError) as exc:
        raise OidcError("JWT payload does not decode") from exc
    if not isinstance(claims, dict):
        raise OidcError("JWT payload is not an object")
    return claims


def claims_match(claims: Mapping[str, Any], job_workflow_sha: str | None) -> bool:
    """The token is for this job's pinned workflow file (`job.workflow_sha`)."""
    if not isinstance(job_workflow_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", job_workflow_sha):
        return False
    aud = claims.get("aud")
    auds = aud if isinstance(aud, list) else [aud]
    return claims.get("job_workflow_sha") == job_workflow_sha and OIDC_AUDIENCE in auds


def write_token_file(token: str, runner_temp: Path | str) -> Path:
    """Write the token to a new file, mode 0600, under `RUNNER_TEMP`."""
    fd, name = tempfile.mkstemp(prefix=TOKEN_FILE_PREFIX, dir=runner_temp)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, token.encode("ascii"))
    finally:
        os.close(fd)
    return Path(name)


# client_factory(token_file) -> an object with `.beta.messages.stream(...)`.
ClientFactory = Callable[[Path], Any]


def default_client_factory(token_file: Path) -> Any:
    """SDK client with workload identity federation.

    The credentials are passed to the constructor, so the SDK reads no
    credential from the environment or from a profile on disk: no
    `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN` or profile can stand in for
    federation. The SDK exchanges the token at `/v1/oauth/token`."""
    import anthropic

    ids = federation_ids()
    credentials = anthropic.WorkloadIdentityCredentials(
        identity_token_provider=anthropic.IdentityTokenFile(token_file),
        federation_rule_id=ids.rule_id,
        organization_id=ids.organization_id,
        service_account_id=ids.service_account_id,
    )
    return anthropic.Anthropic(credentials=credentials, max_retries=MAX_RETRIES, timeout=DEADLINE_SECONDS)


# ---------------------------------------------------------------------------
# Passes
# ---------------------------------------------------------------------------


def _all(status: str, reason: str | None) -> dict[str, PassResult]:
    return {name: PassResult(status, None, reason) for name in PASS_NAMES}


def run_passes(
    client: Any,
    requests: Mapping[str, Mapping[str, Any]],
    *,
    deadline: float,
    clock: Callable[[], float],
) -> dict[str, PassResult]:
    """Run the three calls in threads. Supply-chain starts first; the other two
    start when its response begins to stream (or when it ends without a
    stream). A failure in one pass never changes another pass's result. A pass
    with no result at the deadline is `failed` with "deadline exceeded"."""
    results: dict[str, PassResult] = {}
    lock = threading.Lock()
    first_started = threading.Event()

    def worker(name: str) -> None:
        try:
            result = call_pass(
                client, requests[name], deadline=deadline, clock=clock,
                on_first_event=first_started.set if name == FIRST_PASS else (lambda: None),
            )
        except PassFailure as f:
            result = PassResult("failed", None, f.reason, f.model, f.stop_reason, f.usage)
        except BaseException:  # noqa: BLE001 - a thread must always leave a result
            result = PassResult("failed", None, R_INTERNAL)
        finally:
            if name == FIRST_PASS:
                first_started.set()
        with lock:
            results.setdefault(name, result)

    threads = {name: threading.Thread(target=worker, args=(name,), name=f"pass-{name}", daemon=True) for name in PASS_NAMES}
    threads[FIRST_PASS].start()
    first_started.wait(max(0.0, deadline - clock()))
    for name in PASS_NAMES:
        if name != FIRST_PASS:
            threads[name].start()
    for name in PASS_NAMES:
        threads[name].join(max(0.0, deadline - clock()))
    with lock:
        for name in PASS_NAMES:
            results.setdefault(name, PassResult("failed", None, R_DEADLINE))
        return dict(results)


def bundle_snapshot(bundle: Mapping[str, Any]) -> snapshot.Snapshot:
    return snapshot.Snapshot(**{f: bundle[f] for f in envelope.SNAPSHOT_FIELDS})


def analyze(
    bundle: Mapping[str, Any],
    event: collect.EventContext,
    *,
    github: collect.GitHubClient,
    mint_oidc: OidcMinter,
    job_workflow_sha: str | None,
    runner_temp: Path | str,
    client_factory: ClientFactory = default_client_factory,
    clock: Callable[[], float] = time.monotonic,
    deadline_seconds: float = DEADLINE_SECONDS,
    nonce: str | None = None,
) -> dict[str, PassResult]:
    """Results for the three passes of a trusted bundle. Never raises for a
    pass problem; every path gives three results."""
    deadline = clock() + deadline_seconds
    status = bundle["status"]
    if status in ("skipped-size", "stale", "failed"):
        return _all(status, f"bundle status {status}")
    if status != "ok":
        return _all("failed", R_INTERNAL)

    # Stale check before the calls (spec L244): head SHA and base ref only.
    # A base that is not the default branch does not stop the calls; the
    # publisher fails the gate for it.
    try:
        pr = github.get_json(f"/repos/{event.repository}/pulls/{event.pr_number}", max_bytes=collect.PR_MAX_BYTES)
        if not isinstance(pr, Mapping):
            raise snapshot.SnapshotError("PR response is not an object")
        check = snapshot.check_head_and_base_ref(bundle_snapshot(bundle), pr)
    except (collect.CollectError, snapshot.SnapshotError):
        return _all("failed", R_PR_READ)
    if check.stale:
        return _all("stale", "stale before the calls: " + ", ".join(check.stale_reasons))

    nonce = nonce or render.new_nonce()
    try:
        rendered = render.render_bundle(bundle, nonce=nonce)
        system_text = render.load_prompt("system", nonce)
        pass_texts = {name: render.load_prompt(name, nonce) for name in PASS_NAMES}
    except render.RenderError:
        return _all("failed", R_RENDER)
    schema = request_schema()
    requests = {
        name: build_request(name, system_text=system_text, user_text=rendered.text,
                            pass_text=pass_texts[name], schema=schema)
        for name in PASS_NAMES
    }

    ids = federation_ids()
    if not ids_valid(ids) or ids_are_placeholders(ids):
        return _all("failed", R_FEDERATION_NOT_CONFIGURED)
    try:
        token = mint_oidc()
        claims = jwt_claims(token)
    except OidcError:
        return _all("failed", R_OIDC_UNAVAILABLE)
    if not claims_match(claims, job_workflow_sha):
        return _all("failed", R_OIDC_MISMATCH)
    token_file = write_token_file(token, runner_temp)
    del token
    try:
        client = client_factory(token_file)
        return run_passes(client, requests, deadline=deadline, clock=clock)
    finally:
        token_file.unlink(missing_ok=True)


# ---------------------------------------------------------------------------
# Records
# ---------------------------------------------------------------------------


def build_record(
    bundle: Mapping[str, Any],
    pass_name: str,
    result: PassResult,
    *,
    run_id: int,
    run_attempt: int,
    schema_sha256: str | None,
) -> dict[str, Any]:
    meta: dict[str, Any] = {
        "reason": _clip(result.reason, META_REASON_MAX),
        "model": _clip(result.model, META_MODEL_MAX),
        "stop_reason": _clip(result.stop_reason, META_STOP_REASON_MAX),
        "usage": result.usage,
    }
    if schema_sha256:
        meta["request_schema_sha256"] = schema_sha256
    doc = {
        "schema_version": collect.SCHEMA_VERSION,
        "kind": "pass",
        "run_id": run_id,
        "run_attempt": run_attempt,
        "repository_id": bundle["repository_id"],
        "pr_number": bundle["pr_number"],
        **{f: bundle[f] for f in envelope.SNAPSHOT_FIELDS},
        "pass": pass_name,
        "status": result.status,
        "payload": result.payload if result.status == "ok" else None,
        "meta": meta,
    }
    return doc


def encode_record(doc: dict[str, Any]) -> bytes:
    """Validated record bytes. A record that does not validate or is over the
    size cap becomes `failed` (fail closed), never a missing record."""
    try:
        envelope.validate_envelope(doc)
        data = collect.encode_envelope(doc)
        if len(data) > envelope.MAX_BYTES_BY_KIND["pass"]:
            raise envelope.EnvelopeError("pass record over the size cap")
        return data
    except (envelope.EnvelopeError, ValueError):
        failed = {**doc, "status": "failed", "payload": None,
                  "meta": {**doc["meta"], "reason": R_RECORD}}
        envelope.validate_envelope(failed)
        return collect.encode_envelope(failed)


def write_records(
    bundle: Mapping[str, Any],
    results: Mapping[str, PassResult],
    out_dir: Path | str,
    *,
    run_id: int,
    run_attempt: int,
    schema_sha256: str | None,
) -> dict[str, WrittenRecord]:
    written: dict[str, WrittenRecord] = {}
    for name in PASS_NAMES:
        doc = build_record(bundle, name, results[name], run_id=run_id, run_attempt=run_attempt,
                           schema_sha256=schema_sha256)
        data = encode_record(doc)
        d = Path(out_dir) / envelope.pass_dir_name(name)
        d.mkdir(parents=True, exist_ok=True)
        path = d / envelope.PASS_FILE_NAMES[name]
        path.write_bytes(data)
        written[name] = WrittenRecord(path, envelope.sha256_hex(data), envelope.parse_json(data)["status"])
    return written


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def read_trusted_bundle(
    bundle_dir: Path | str, bundle_digest: str, event: collect.EventContext, *, run_id: int, run_attempt: int
) -> dict[str, Any]:
    """The bundle, checked against its digest and the trusted run context."""
    try:
        bundle = envelope.read_artifact(
            bundle_dir, kind="bundle", expected_name=collect.BUNDLE_FILE_NAME, expected_digest=bundle_digest
        )
        envelope.check_context(
            bundle,
            repository_id=event.repository_id,
            pr_number=event.pr_number,
            run_id=run_id,
            run_attempt=run_attempt,
            snapshot={f: bundle[f] for f in envelope.SNAPSHOT_FIELDS},
        )
    except envelope.EnvelopeError as exc:
        raise AnalyzeError(f"bundle not trusted: {exc}") from exc
    return bundle


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    github_transport: collect.Transport = collect.default_transport,
    oidc_transport: OidcTransport = default_oidc_transport,
    client_factory: ClientFactory = default_client_factory,
    clock: Callable[[], float] = time.monotonic,
    deadline_seconds: float = DEADLINE_SECONDS,
    sleep: Callable[[float], None] = time.sleep,
) -> int:
    """Workflow entry. Outputs per pass: `<name>-digest` and `<name>-status`."""
    parser = argparse.ArgumentParser(description="Run the three Claude passes on the bundle.")
    parser.add_argument("--bundle-dir", required=True)
    parser.add_argument("--bundle-digest", required=True)
    parser.add_argument("--out-dir", required=True)
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    try:
        event = collect.EventContext.from_event(envelope.parse_json(Path(env["GITHUB_EVENT_PATH"]).read_bytes()))
        run_id = int(env["GITHUB_RUN_ID"])
        run_attempt = int(env["GITHUB_RUN_ATTEMPT"])
        bundle = read_trusted_bundle(args.bundle_dir, args.bundle_digest, event, run_id=run_id, run_attempt=run_attempt)
        github_token = env["GITHUB_TOKEN"]
        output_path = env["GITHUB_OUTPUT"]
        runner_temp = env["RUNNER_TEMP"]
    except (AnalyzeError, collect.CollectError, envelope.EnvelopeError, KeyError, ValueError, OSError) as exc:
        print(f"analyze failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1

    schema_sha256: str | None = None
    try:
        schema_sha256 = schema_digest(request_schema())
        results = analyze(
            bundle,
            event,
            github=collect.GitHubClient(github_token, github_transport, sleep=sleep),
            mint_oidc=oidc_minter(env.get("ACTIONS_ID_TOKEN_REQUEST_URL"), env.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
                                  oidc_transport, sleep=sleep),
            job_workflow_sha=env.get("JOB_WORKFLOW_SHA"),
            runner_temp=runner_temp,
            client_factory=client_factory,
            clock=clock,
            deadline_seconds=deadline_seconds,
        )
    except Exception as exc:  # noqa: BLE001 - fail closed with three records
        print(f"analyze: internal error: {type(exc).__name__}", file=sys.stderr)
        results = _all("failed", R_INTERNAL)

    try:
        written = write_records(bundle, results, args.out_dir, run_id=run_id, run_attempt=run_attempt,
                                schema_sha256=schema_sha256)
        with open(output_path, "a", encoding="utf-8") as fh:
            for name, rec in written.items():
                fh.write(f"{name}-digest={rec.digest}\n{name}-status={rec.status}\n")
    except (OSError, envelope.EnvelopeError, ValueError) as exc:
        print(f"analyze failed: cannot write pass records: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 1
    for name in PASS_NAMES:
        reason = results[name].reason
        print(f"analyze: {name} {written[name].status}" + (f" ({reason})" if reason else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
