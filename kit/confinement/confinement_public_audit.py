"""Independent source-free audit for Linux and Windows source-admission runs.

The auditor runs as its own job after the producer jobs, with read-only API access and no source
or credential. It never trusts a producer summary. From the live run, job, step, check, log,
annotation, artifact and cache records it checks that:

    the run, attempt one, control commit, workflow path, CI ref and title are the expected ones
    no log, check output or annotation of any completed job, whatever its conclusion, contains
    the committed canary in any pinned encoding; this scan runs first, before any other verdict
    every expected job exists once, completed with success, and ran exactly the expected steps
    the verdict job log holds exactly one verdict line, valid under the closed verdict schema,
    bound to the expected operating system, control commit, run and attempt, accepted, and
    inside the log section of the one required verdict step
    the run artifact inventory is empty: artifact contents are not scanned, so no artifact is
    admitted until a content scan exists
    the repository cache inventory equals the digest taken before the producer jobs ran

Because the canary scan precedes every other check, a failed or cancelled producer that leaked
the canary still refuses with the canary phase. Anything missing, incomplete, paginated short,
cancelled, skipped or mismatched refuses. The public result is one fixed line and a refusal
names only a closed phase, never a value.

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
import urllib.request

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
    "ci_ref", "display_title", "jobs", "verdict_job", "verdict_step", "auditor_job",
    "artifact_names", "cache_digest",
))
UNSECTIONED_STEPS = ("Set up job", "Complete job")
GROUP_MARK = bytes((35, 35)) + b"[group]"
RUN_HEADER = GROUP_MARK + b"Run "
SECTION_HEADERS = (GROUP_MARK + b"Post Run ", GROUP_MARK + b"Complete job")
BOM = b"\xef\xbb\xbf"
CACHE_QUERY = "sort=created_at&direction=asc"
JOB_FIELDS = frozenset(("steps", "optional_steps"))
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}")
WORKFLOW_RE = re.compile(r"\.github/workflows/[A-Za-z0-9_.-]{1,100}\.yml")
SHA_RE = re.compile(r"[a-f0-9]{40}")
DIGEST_RE = re.compile(r"[a-f0-9]{64}")
LABEL_RE = re.compile(r"[\x20-\x7e]{1,200}")
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
            or not _is(expected["run_attempt"], 1)
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
            or type(expected["artifact_names"]) is not tuple or expected["artifact_names"] != ()
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
    verdict_spec = jobs[expected["verdict_job"]]
    step = expected["verdict_step"]
    if (type(step) is not str or verdict_spec["steps"].count(step) != 1
            or step in verdict_spec["optional_steps"] or step in UNSECTIONED_STEPS
            or step.startswith("Post ")):
        _fail("request")


def _resolve_config(config):
    resolved = log_canary.pinned_config() if config is None else config
    log_canary.Scanner(resolved)
    return resolved


def _page_path(path, page, query=""):
    prefix = query + "&" if query else ""
    return path + "?" + prefix + "per_page=" + str(PAGE_SIZE) + "&page=" + str(page)


def _collect_counted(api, path, key, maximum, query=""):
    total = None
    pages = 1
    items = []
    page = 1
    while True:
        body, unused_headers = api.json(_page_path(path, page, query))
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


def _list_jobs(api, expected):
    path = ("/repos/" + expected["repository"] + "/actions/runs/" + str(expected["run_id"])
            + "/attempts/" + str(expected["run_attempt"]) + "/jobs")
    return _collect_counted(api, path, "jobs", MAX_JOBS)


def _check_jobs(jobs, expected):
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
    url = job.get("check_run_url")
    if type(url) is not str:
        _fail("annotations")
    parts = urllib.parse.urlsplit(url)
    matched = re.fullmatch(
        "/repos/" + re.escape(repository) + "/check-runs/([1-9][0-9]{0,18})", parts.path,
    )
    if (parts.scheme != "https" or parts.netloc != "api.github.com" or parts.query
            or parts.fragment or matched is None):
        _fail("annotations")
    return int(matched.group(1))


def _surface_texts(api, job, expected):
    check_id = _check_id(job, expected["repository"])
    check_path = "/repos/" + expected["repository"] + "/check-runs/" + str(check_id)
    check, unused_headers = api.json(check_path)
    output = check.get("output") if type(check) is dict else None
    if (type(check) is not dict or not _is(check.get("id"), check_id)
            or not _is(check.get("head_sha"), expected["control_sha"])
            or not _is(check.get("status"), "completed")
            or not _is(check.get("conclusion"), job.get("conclusion"))
            or type(output) is not dict
            or not _exact_int(output.get("annotations_count"), 0, MAX_ANNOTATIONS)):
        _fail("annotations")
    texts = []
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
    return texts


def _candidates(jobs, expected):
    chosen = [
        job for job in jobs
        if type(job) is dict and _exact_int(job.get("id"), 1)
        and job.get("status") == "completed" and job.get("name") != expected["auditor_job"]
    ]
    return sorted(chosen, key=lambda item: item["id"])


def _gather(api, jobs, expected):
    """Collect the log, check output and annotations of every completed job.

    Fetch problems are recorded and returned, not raised, so the canary scan covers everything
    that could be read before any other refusal is reported.
    """
    logs = {}
    texts = []
    pending = []
    total = 0
    for job in _candidates(jobs, expected):
        try:
            log = api.log_text(job["id"])
            if type(log) is not bytes or not log or len(log) > MAX_LOG_BYTES:
                _fail("job_logs")
            logs[job["id"]] = log
        except AuditRefusal as error:
            pending.append(error.phase)
        except Exception:
            pending.append("job_logs")
        try:
            found = _surface_texts(api, job, expected)
            total += sum(len(text) for text in found)
            if total > MAX_ANNOTATION_TEXT:
                _fail("annotations")
            texts.extend(found)
        except AuditRefusal as error:
            pending.append(error.phase)
        except Exception:
            pending.append("annotations")
    return logs, texts, pending


def _scan(logs, texts, config):
    for log in logs.values():
        if _guard("log_canary", log_canary.scan_bytes, log, config) != log_canary.ABSENT:
            _fail("log_canary")
    if _guard("log_canary", log_canary.scan_texts, texts, config) != log_canary.ABSENT:
        _fail("log_canary")


def _stripped_lines(log):
    if log.startswith(BOM):
        log = log[3:]
    result = []
    for line in log.splitlines():
        stamp = confinement_verdict.TIMESTAMP_PREFIX_RE.match(line)
        result.append(line[stamp.end():] if stamp is not None else line)
    return result


def _check_section(log, job, expected):
    ordinal = None
    eligible = 0
    for step in job["steps"]:
        name = step.get("name")
        if (step.get("conclusion") != "success" or name in UNSECTIONED_STEPS
                or name.startswith("Post ")):
            continue
        if name == expected["verdict_step"]:
            ordinal = eligible
        eligible += 1
    lines = _stripped_lines(log)
    runs = [index for index, line in enumerate(lines) if line.startswith(RUN_HEADER)]
    if ordinal is None or len(runs) != eligible:
        _fail("verdict")
    start = runs[ordinal]
    following = [
        index for index, line in enumerate(lines)
        if index > start and (line.startswith(RUN_HEADER) or line.startswith(SECTION_HEADERS))
    ]
    end = following[0] if following else len(lines)
    positions = [index for index, line in enumerate(lines) if line.startswith(VERDICT_PREFIX)]
    if len(positions) != 1 or not start < positions[0] < end:
        _fail("verdict")


def _verdict_line(logs, by_name, expected):
    line = None
    for name in sorted(expected["jobs"]):
        job = by_name[name]
        log = logs.get(job["id"])
        if log is None:
            _fail("job_logs")
        lines = confinement_verdict.find_lines(log)
        if log.count(VERDICT_PREFIX) != len(lines):
            _fail("verdict")
        if name == expected["verdict_job"]:
            if len(lines) != 1:
                _fail("verdict")
            _check_section(log, job, expected)
            line = lines[0]
        elif lines:
            _fail("verdict")
    return line


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
    if items:
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
    return cache_inventory_digest(_collect_caches(api, repository))


def _collect_caches(api, repository):
    return _collect_counted(
        api, "/repos/" + repository + "/actions/caches", "actions_caches", MAX_CACHES, CACHE_QUERY,
    )


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
    jobs = _guard("jobs", _list_jobs, api, expected)
    logs, texts, pending = _gather(api, jobs, expected)
    _scan(logs, texts, resolved)
    by_name = _guard("jobs", _check_jobs, jobs, expected)
    if pending:
        _fail(pending[0])
    line = _guard("verdict", _verdict_line, logs, by_name, expected)
    _guard("verdict", _check_verdict, line, expected)
    if any(VERDICT_PREFIX in text.encode("utf-8", "replace") for text in texts):
        _fail("annotations")
    _guard("artifact_inventory", _check_artifacts, api, expected)
    items = _guard("cache_inventory", _collect_caches, api, expected["repository"])
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


def _default_api_factory(token, repository):
    """Build the read-only client for one repository.

    It reuses the bounded transport of the existing public auditor, but fetches logs for the
    given repository and returns them as bytes without requiring valid UTF-8, so an undecodable
    log is still canary-scanned instead of being refused before the scan.
    """
    try:
        from . import macos_public_audit as base
    except ImportError:
        import macos_public_audit as base
    if type(repository) is not str or REPOSITORY_RE.fullmatch(repository) is None:
        _fail("request")

    class Client(base.GitHubAPI):
        def log_text(self, job_id):
            if type(job_id) is not int or job_id < 1:
                raise ValueError("job")
            path = "/repos/" + repository + "/actions/jobs/" + str(job_id) + "/logs"
            request = urllib.request.Request(
                base.API_ORIGIN + path,
                headers={
                    "Accept": "application/vnd.github+json",
                    "Authorization": "Bearer " + self._token,
                    "X-GitHub-Api-Version": base.API_VERSION,
                    "User-Agent": "confinement-public-audit",
                    "Accept-Encoding": "identity",
                },
                method="GET",
            )
            unused, response_headers = self._open(request, 1, allow_redirect=True)
            location = response_headers.get("Location")
            if (type(location) is not str or not location or len(location) > 8192
                    or any(ord(char) < 33 or ord(char) > 126 for char in location)):
                raise ValueError("location")
            base._validate_log_location(location)
            blob = urllib.request.Request(
                location,
                headers={
                    "Accept": "text/plain",
                    "Accept-Encoding": "identity",
                    "User-Agent": "confinement-public-audit",
                },
                method="GET",
            )
            data, blob_headers = self._open(blob, MAX_LOG_BYTES)
            if blob_headers.get("Content-Encoding", "identity").lower() != "identity":
                raise ValueError("encoding")
            return data

    return Client(token)


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
        accepted, line = audit_line(
            factory(env.get("GITHUB_TOKEN", ""), expected["repository"]), expected,
        )
    except AuditRefusal as error:
        accepted, line = False, refusal_line(error.phase)
    except Exception:
        accepted, line = False, refusal_line("unavailable")
    sink.write(line + "\n")
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
