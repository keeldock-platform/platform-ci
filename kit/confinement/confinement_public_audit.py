"""Independent source-free audit for Linux and Windows source-admission runs.

The auditor runs as its own job after the producer jobs, with read-only API access and no source
or credential. It never trusts a producer summary. From the live run, job, step, check, log,
annotation, artifact and cache records it checks that:

    the run, attempt, control commit, workflow path, CI ref and title are exactly the expected ones
    every expected job exists once, completed with success, and ran exactly the expected steps
    the verdict job log holds exactly one verdict line, valid under the closed verdict schema,
    bound to the expected operating system, control commit, run and attempt, and accepted
    no log or annotation contains the committed canary in any pinned encoding
    the run artifact inventory equals the expected set, empty unless the caller lists names
    the repository cache inventory equals the digest taken before the producer jobs ran

Anything missing, incomplete, paginated short, cancelled, skipped or mismatched refuses. The
public result is one fixed line and a refusal names only a closed phase, never a value.

API client interface, injected so tests use fakes:

    json(path) returns a pair of a decoded body and a headers mapping, for a GET of the path
    log_text(job_id) returns the complete log of one job as bytes

Accepted line:

    KD-CONFINEMENT-AUDIT schema=1 status=accepted os=<os> mode=<mode> control-sha=<sha>
    run-id=<n> run-attempt=<n> verdict=accepted log-canary=absent artifacts=expected caches=unchanged

Refusal line:

    KD-CONFINEMENT-AUDIT schema=1 status=refused phase=<phase> reason=confinement_audit_invalid
"""

import hashlib
import json
import os
import re
import sys
import urllib.parse

try:
    from . import confinement_verdict
    from . import log_canary
except ImportError:
    import confinement_verdict
    import log_canary


SCHEMA_VERSION = 1
AUDIT_PREFIX = "KD-CONFINEMENT-AUDIT"
REFUSAL_REASON = "confinement_audit_invalid"
EXPECTED_ENV = "CONFINEMENT_AUDIT_EXPECTED"
MAX_EXPECTED_BYTES = 65536
MAX_LINE_BYTES = 512
PAGE_SIZE = 100
MAX_PAGES = 100
MAX_JOBS = 20
MAX_ARTIFACTS = 1000
MAX_CACHES = 10000
MAX_ANNOTATIONS = 1000
MAX_LOG_BYTES = 32 * 1024 * 1024
MAX_CHECK_TEXT = 262144
MAX_ANNOTATION_TEXT = 4 * 1024 * 1024
MAX_RUN_ID = 9007199254740991
MODES = ("candidate", "synthetic")
CI_REFS = ("main", "untrusted")
PHASES = frozenset((
    "request", "run", "jobs", "job_steps", "job_logs", "verdict", "log_canary",
    "annotations", "artifact_inventory", "cache_inventory", "pagination", "unavailable",
))
EXPECTED_FIELDS = frozenset((
    "repository", "os", "mode", "control_sha", "run_id", "run_attempt", "workflow_path",
    "ci_ref", "display_title", "jobs", "verdict_job", "auditor_job", "artifact_names",
    "cache_digest",
))
JOB_FIELDS = frozenset(("steps", "optional_steps"))
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}")
WORKFLOW_RE = re.compile(r"\.github/workflows/[A-Za-z0-9_.-]{1,100}\.yml")
SHA_RE = re.compile(r"[a-f0-9]{40}")
DIGEST_RE = re.compile(r"[a-f0-9]{64}")
LABEL_RE = re.compile(r"[\x20-\x7e]{1,200}")
ARTIFACT_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}")
VERDICT_PREFIX = confinement_verdict.LINE_PREFIX.encode("ascii")
ACCEPTED_RE = re.compile(
    re.escape(AUDIT_PREFIX) + r" schema=1 status=accepted os=(linux|windows)"
    r" mode=(candidate|synthetic) control-sha=([a-f0-9]{40}) run-id=([1-9][0-9]{0,15})"
    r" run-attempt=([1-9][0-9]?) verdict=accepted log-canary=absent artifacts=expected"
    r" caches=unchanged"
)
REFUSED_RE = re.compile(
    re.escape(AUDIT_PREFIX) + r" schema=1 status=refused phase=([a-z_]{1,24})"
    r" reason=" + REFUSAL_REASON
)


class AuditRefusal(Exception):
    def __init__(self, phase="unavailable"):
        self.phase = phase if type(phase) is str and phase in PHASES else "unavailable"
        self.reason = REFUSAL_REASON
        super().__init__(self.reason)


def _fail(phase):
    raise AuditRefusal(phase)


def _guard(phase, function, *arguments):
    try:
        return function(*arguments)
    except AuditRefusal:
        raise
    except Exception:
        raise AuditRefusal(phase) from None


def _is(value, expected):
    return type(value) is type(expected) and value == expected


def _exact_int(value, minimum, maximum=MAX_RUN_ID):
    return type(value) is int and minimum <= value <= maximum


def _text_tuple(value, minimum, maximum, pattern):
    return (type(value) is tuple and minimum <= len(value) <= maximum
            and all(type(item) is str and pattern.fullmatch(item) is not None for item in value))


def validate_expected(expected):
    """Refuse any expected-run description that is not exactly the closed shape."""
    if type(expected) is not dict or set(expected) != EXPECTED_FIELDS:
        _fail("request")
    jobs = expected["jobs"]
    if (type(expected["repository"]) is not str or REPOSITORY_RE.fullmatch(expected["repository"]) is None
            or expected["os"] not in confinement_verdict.OPERATING_SYSTEMS
            or type(expected["os"]) is not str
            or type(expected["mode"]) is not str or expected["mode"] not in MODES
            or type(expected["control_sha"]) is not str or SHA_RE.fullmatch(expected["control_sha"]) is None
            or not _exact_int(expected["run_id"], 1)
            or not _exact_int(expected["run_attempt"], 1, 99)
            or (expected["mode"] == "candidate" and expected["run_attempt"] != 1)
            or type(expected["workflow_path"]) is not str
            or WORKFLOW_RE.fullmatch(expected["workflow_path"]) is None
            or type(expected["ci_ref"]) is not str or expected["ci_ref"] not in CI_REFS
            or type(expected["display_title"]) is not str
            or LABEL_RE.fullmatch(expected["display_title"]) is None
            or type(jobs) is not dict or not 1 <= len(jobs) < MAX_JOBS
            or type(expected["verdict_job"]) is not str or expected["verdict_job"] not in jobs
            or type(expected["auditor_job"]) is not str
            or LABEL_RE.fullmatch(expected["auditor_job"]) is None
            or expected["auditor_job"] in jobs
            or not _text_tuple(expected["artifact_names"], 0, 20, ARTIFACT_RE)
            or len(set(expected["artifact_names"])) != len(expected["artifact_names"])
            or type(expected["cache_digest"]) is not str
            or DIGEST_RE.fullmatch(expected["cache_digest"]) is None):
        _fail("request")
    for name, spec in jobs.items():
        if (type(name) is not str or LABEL_RE.fullmatch(name) is None or type(spec) is not dict
                or set(spec) != JOB_FIELDS
                or not _text_tuple(spec["steps"], 1, 100, LABEL_RE)
                or not _text_tuple(spec["optional_steps"], 0, 100, LABEL_RE)
                or not set(spec["optional_steps"]).issubset(spec["steps"])):
            _fail("request")


def _resolve_config(config):
    resolved = log_canary.pinned_config() if config is None else config
    log_canary.Scanner(resolved)
    return resolved


def _page_path(path, page):
    return path + "?per_page=" + str(PAGE_SIZE) + "&page=" + str(page)


def _collect_counted(api, path, key, maximum):
    total = None
    pages = 1
    items = []
    page = 1
    while True:
        body, unused_headers = api.json(_page_path(path, page))
        if (type(body) is not dict or type(body.get("total_count")) is not int
                or body["total_count"] < 0 or type(body.get(key)) is not list):
            _fail("pagination")
        if total is None:
            total = body["total_count"]
            if total > maximum:
                _fail("pagination")
            pages = max(1, -(-total // PAGE_SIZE))
        elif body["total_count"] != total:
            _fail("pagination")
        if len(body[key]) != min(PAGE_SIZE, total - (page - 1) * PAGE_SIZE):
            _fail("pagination")
        items.extend(body[key])
        if page >= pages:
            break
        page += 1
    if len(items) != total:
        _fail("pagination")
    return items


def _collect_annotations(api, path, count):
    items = []
    for page in range(1, MAX_PAGES + 1):
        body, unused_headers = api.json(_page_path(path, page))
        if type(body) is not list or len(body) > PAGE_SIZE:
            _fail("pagination")
        items.extend(body)
        if len(items) > count:
            _fail("pagination")
        if len(body) < PAGE_SIZE:
            if len(items) != count:
                _fail("pagination")
            return items
    _fail("pagination")


def _check_run(api, expected):
    run, unused_headers = api.json(
        "/repos/" + expected["repository"] + "/actions/runs/" + str(expected["run_id"])
    )
    repository = run.get("repository") if type(run) is dict else None
    if (type(run) is not dict
            or not _is(run.get("id"), expected["run_id"])
            or not _is(run.get("run_attempt"), expected["run_attempt"])
            or not _is(run.get("head_sha"), expected["control_sha"])
            or not _is(run.get("path"), expected["workflow_path"])
            or not _is(run.get("head_branch"), expected["ci_ref"])
            or not _is(run.get("event"), "workflow_dispatch")
            or not _is(run.get("display_title"), expected["display_title"])
            or not _is(run.get("status"), "in_progress")
            or run.get("conclusion") is not None
            or type(repository) is not dict
            or not _is(repository.get("full_name"), expected["repository"])):
        _fail("run")


def _check_steps(job, spec):
    steps = job["steps"]
    if len(steps) != len(spec["steps"]):
        _fail("job_steps")
    for index, step in enumerate(steps, start=1):
        name = spec["steps"][index - 1]
        if (type(step) is not dict or not _is(step.get("number"), index)
                or not _is(step.get("name"), name) or not _is(step.get("status"), "completed")):
            _fail("job_steps")
        conclusion = step.get("conclusion")
        if conclusion == "success":
            continue
        if conclusion == "skipped" and name in spec["optional_steps"]:
            continue
        _fail("job_steps")


def _check_jobs(api, expected):
    path = ("/repos/" + expected["repository"] + "/actions/runs/" + str(expected["run_id"])
            + "/attempts/" + str(expected["run_attempt"]) + "/jobs")
    jobs = _collect_counted(api, path, "jobs", MAX_JOBS)
    names = set(expected["jobs"]) | {expected["auditor_job"]}
    if len(jobs) != len(names):
        _fail("jobs")
    by_name = {}
    identifiers = set()
    for job in jobs:
        if type(job) is not dict or not _exact_int(job.get("id"), 1) or job["id"] in identifiers:
            _fail("jobs")
        identifiers.add(job["id"])
        name = job.get("name")
        if (type(name) is not str or name not in names or name in by_name
                or not _is(job.get("run_id"), expected["run_id"])
                or not _is(job.get("run_attempt"), expected["run_attempt"])
                or not _is(job.get("head_sha"), expected["control_sha"])
                or type(job.get("check_run_url")) is not str
                or type(job.get("steps")) is not list):
            _fail("jobs")
        by_name[name] = job
    if set(by_name) != names:
        _fail("jobs")
    auditor = by_name[expected["auditor_job"]]
    if auditor.get("status") != "in_progress" or auditor.get("conclusion") is not None:
        _fail("jobs")
    for name, spec in expected["jobs"].items():
        job = by_name[name]
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            _fail("jobs")
        _guard("job_steps", _check_steps, job, spec)
    return by_name


def _check_id(job, repository):
    parts = urllib.parse.urlsplit(job["check_run_url"])
    matched = re.fullmatch(
        "/repos/" + re.escape(repository) + "/check-runs/([1-9][0-9]{0,18})", parts.path,
    )
    if (parts.scheme != "https" or parts.netloc != "api.github.com" or parts.query
            or parts.fragment or matched is None):
        _fail("annotations")
    return int(matched.group(1))


def _check_surfaces(api, by_name, expected):
    texts = []
    total = 0
    for name in sorted(expected["jobs"]):
        check_id = _check_id(by_name[name], expected["repository"])
        check_path = "/repos/" + expected["repository"] + "/check-runs/" + str(check_id)
        check, unused_headers = api.json(check_path)
        output = check.get("output") if type(check) is dict else None
        if (type(check) is not dict or not _is(check.get("id"), check_id)
                or not _is(check.get("head_sha"), expected["control_sha"])
                or not _is(check.get("status"), "completed")
                or not _is(check.get("conclusion"), "success")
                or type(output) is not dict
                or not _exact_int(output.get("annotations_count"), 0, MAX_ANNOTATIONS)):
            _fail("annotations")
        for field in ("title", "summary", "text"):
            value = output.get(field)
            if value is None:
                continue
            if type(value) is not str or len(value) > MAX_CHECK_TEXT:
                _fail("annotations")
            texts.append(value)
        annotations = _collect_annotations(
            api, check_path + "/annotations", output["annotations_count"],
        )
        for annotation in annotations:
            if type(annotation) is not dict:
                _fail("annotations")
            for value in annotation.values():
                if type(value) is str:
                    texts.append(value)
                elif value is not None and type(value) not in (int, bool):
                    _fail("annotations")
        total = sum(len(text) for text in texts)
        if total > MAX_ANNOTATION_TEXT:
            _fail("annotations")
    return texts


def _check_logs(api, by_name, expected, config):
    verdict_lines = None
    for name in sorted(expected["jobs"]):
        log = api.log_text(by_name[name]["id"])
        if type(log) is not bytes or not log or len(log) > MAX_LOG_BYTES:
            _fail("job_logs")
        if _guard("log_canary", log_canary.scan_bytes, log, config) != log_canary.ABSENT:
            _fail("log_canary")
        lines = _guard("verdict", confinement_verdict.find_lines, log)
        if log.count(VERDICT_PREFIX) != len(lines):
            _fail("verdict")
        if name == expected["verdict_job"]:
            verdict_lines = lines
        elif lines:
            _fail("verdict")
    if verdict_lines is None or len(verdict_lines) != 1:
        _fail("verdict")
    return verdict_lines[0]


def _check_verdict(line, expected):
    record = confinement_verdict.decode_line(line)
    if (record["os"] != expected["os"] or record["control_sha"] != expected["control_sha"]
            or record["run_id"] != expected["run_id"]
            or record["run_attempt"] != expected["run_attempt"]
            or not confinement_verdict.confinement_accepted(record)):
        _fail("verdict")
    if expected["mode"] == "candidate" and not confinement_verdict.run_accepted(record):
        _fail("verdict")


def _check_artifacts(api, expected):
    path = ("/repos/" + expected["repository"] + "/actions/runs/" + str(expected["run_id"])
            + "/artifacts")
    items = _collect_counted(api, path, "artifacts", MAX_ARTIFACTS)
    names = []
    identifiers = set()
    for item in items:
        run = item.get("workflow_run") if type(item) is dict else None
        if (type(item) is not dict or not _exact_int(item.get("id"), 1) or item["id"] in identifiers
                or type(item.get("name")) is not str
                or not _exact_int(item.get("size_in_bytes"), 0)
                or type(item.get("expired")) is not bool
                or type(run) is not dict
                or not _is(run.get("id"), expected["run_id"])
                or not _is(run.get("head_sha"), expected["control_sha"])):
            _fail("artifact_inventory")
        identifiers.add(item["id"])
        names.append(item["name"])
    if len(set(names)) != len(names) or sorted(names) != sorted(expected["artifact_names"]):
        _fail("artifact_inventory")


def cache_inventory_digest(entries):
    """Digest the stable fields of the repository cache inventory, ignoring access times."""
    rows = []
    identifiers = set()
    for item in entries:
        if (type(item) is not dict or not _exact_int(item.get("id"), 1) or item["id"] in identifiers
                or type(item.get("key")) is not str or type(item.get("ref")) is not str
                or type(item.get("version")) is not str
                or not _exact_int(item.get("size_in_bytes"), 0)
                or type(item.get("created_at")) is not str):
            _fail("cache_inventory")
        identifiers.add(item["id"])
        rows.append([
            item["id"], item["key"], item["ref"], item["version"],
            item["size_in_bytes"], item["created_at"],
        ])
    rows.sort()
    encoded = json.dumps(rows, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("ascii")).hexdigest()


def snapshot_cache_digest(api, repository):
    """Take the cache digest before producer jobs run, for later comparison by the auditor."""
    if type(repository) is not str or REPOSITORY_RE.fullmatch(repository) is None:
        _fail("request")
    items = _collect_counted(
        api, "/repos/" + repository + "/actions/caches", "actions_caches", MAX_CACHES,
    )
    return cache_inventory_digest(items)


def accepted_line(expected):
    return (
        AUDIT_PREFIX + " schema=" + str(SCHEMA_VERSION) + " status=accepted os=" + expected["os"]
        + " mode=" + expected["mode"] + " control-sha=" + expected["control_sha"]
        + " run-id=" + str(expected["run_id"]) + " run-attempt=" + str(expected["run_attempt"])
        + " verdict=accepted log-canary=absent artifacts=expected caches=unchanged"
    )


def refusal_line(phase):
    safe = phase if type(phase) is str and phase in PHASES else "unavailable"
    return (AUDIT_PREFIX + " schema=" + str(SCHEMA_VERSION) + " status=refused phase=" + safe
            + " reason=" + REFUSAL_REASON)


def decode_audit_line(raw):
    """Parse one audit line strictly; refuse anything that is not one of the two fixed forms."""
    if type(raw) is bytes:
        if len(raw) > MAX_LINE_BYTES + 1:
            _fail("unavailable")
        try:
            text = raw.decode("ascii", "strict")
        except UnicodeError:
            _fail("unavailable")
    elif type(raw) is str and len(raw) <= MAX_LINE_BYTES + 1:
        text = raw
    else:
        _fail("unavailable")
    if text.endswith("\n"):
        text = text[:-1]
    matched = ACCEPTED_RE.fullmatch(text)
    if matched is not None:
        return {
            "status": "accepted", "os": matched.group(1), "mode": matched.group(2),
            "control_sha": matched.group(3), "run_id": int(matched.group(4)),
            "run_attempt": int(matched.group(5)),
        }
    matched = REFUSED_RE.fullmatch(text)
    if matched is not None and matched.group(1) in PHASES:
        return {"status": "refused", "phase": matched.group(1)}
    _fail("unavailable")


def audit(api, expected, config=None):
    """Return the accepted public line, or raise AuditRefusal naming only a closed phase."""
    _guard("request", validate_expected, expected)
    resolved = _guard("log_canary", _resolve_config, config)
    _guard("run", _check_run, api, expected)
    by_name = _guard("jobs", _check_jobs, api, expected)
    line = _guard("job_logs", _check_logs, api, by_name, expected, resolved)
    _guard("verdict", _check_verdict, line, expected)
    texts = _guard("annotations", _check_surfaces, api, by_name, expected)
    if _guard("log_canary", log_canary.scan_texts, texts, resolved) != log_canary.ABSENT:
        _fail("log_canary")
    if any(VERDICT_PREFIX in text.encode("utf-8", "replace") for text in texts):
        _fail("annotations")
    _guard("artifact_inventory", _check_artifacts, api, expected)
    items = _guard("cache_inventory", _collect_counted, api,
                   "/repos/" + expected["repository"] + "/actions/caches", "actions_caches", MAX_CACHES)
    if _guard("cache_inventory", cache_inventory_digest, items) != expected["cache_digest"]:
        _fail("cache_inventory")
    return accepted_line(expected)


def audit_line(api, expected, config=None):
    """Return a pair of the accepted flag and the one public line; never raises on a refusal."""
    try:
        return True, audit(api, expected, config)
    except AuditRefusal as error:
        return False, refusal_line(error.phase)
    except Exception:
        return False, refusal_line("unavailable")


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate")
        value[key] = item
    return value


def parse_expected(raw):
    """Build the expected-run description from its JSON form, converting lists to tuples."""
    if type(raw) is not str or not raw or len(raw) > MAX_EXPECTED_BYTES:
        _fail("request")
    try:
        value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_reject_constant)
    except Exception:
        _fail("request")
    if type(value) is not dict:
        _fail("request")
    if type(value.get("artifact_names")) is list:
        value["artifact_names"] = tuple(value["artifact_names"])
    if type(value.get("jobs")) is dict:
        for spec in value["jobs"].values():
            if type(spec) is dict:
                for field in JOB_FIELDS:
                    if type(spec.get(field)) is list:
                        spec[field] = tuple(spec[field])
    validate_expected(value)
    return value


def _reject_constant(unused):
    raise ValueError("constant")


def _default_api_factory(token):
    try:
        from . import macos_public_audit
    except ImportError:
        import macos_public_audit
    return macos_public_audit.GitHubAPI(token)


def main(arguments=None, environ=None, api_factory=None, stdout=None):
    """Workflow entry point: print one public line and exit zero only for an accepted audit."""
    actual = sys.argv[1:] if arguments is None else arguments
    env = os.environ if environ is None else environ
    sink = sys.stdout if stdout is None else stdout
    factory = _default_api_factory if api_factory is None else api_factory
    if actual:
        return 2
    try:
        expected = parse_expected(env.get(EXPECTED_ENV, ""))
        if (env.get("GITHUB_REPOSITORY") != expected["repository"]
                or env.get("GITHUB_RUN_ID") != str(expected["run_id"])
                or env.get("GITHUB_RUN_ATTEMPT") != str(expected["run_attempt"])
                or env.get("GITHUB_SHA") != expected["control_sha"]):
            _fail("request")
        accepted, line = audit_line(factory(env.get("GITHUB_TOKEN", "")), expected)
    except AuditRefusal as error:
        accepted, line = False, refusal_line(error.phase)
    except Exception:
        accepted, line = False, refusal_line("unavailable")
    sink.write(line + "\n")
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
