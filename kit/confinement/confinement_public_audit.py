"""Independent source-free audit for Linux and Windows source-admission runs.

The auditor runs as its own job after the producer jobs, with read-only API access and no source
or credential. It never trusts a producer summary. From the live run, job, step, check, log,
annotation, artifact and cache records it checks that:

    the run, attempt one, control commit, workflow path, CI ref and title are the expected ones
    no log, check output or annotation of any completed job, whatever its conclusion, contains
    the committed canary in any pinned encoding; a surface that could not be read or scanned in
    full counts as a possible leak and is reported with the canary phase
    every expected job exists once, completed with success, and ran exactly the expected steps
    the verdict job log holds exactly one verdict line, valid under the closed verdict schema,
    bound to the expected operating system, control commit, run and attempt, accepted, and
    inside the log section of the one required verdict step; the section of a step runs from
    its run header to the next run header or the job tail line, composite action layouts are
    refused because their nested headers and markers cannot be mapped to job steps
    the run artifact inventory is empty: artifact contents are not scanned, so no artifact is
    admitted until a content scan exists
    the full repository cache inventory is fingerprinted, cache-service evictions are tolerated,
    row mutations and unknown additions are refused, and only validated main-ref managed keys may
    be added; untrusted workflows cannot add cache entries

The Windows source profile is a separate closed shape selected by the windows argument. It has six
audited jobs, four of them called workflows whose step lists are matched as required steps in order
with every other step succeeding, a verdict that must be an accepted full run in both modes, and an
artifact inventory that is exactly two capsules, four role statements and one evidence bundle, each
unexpired with one day retention. The windows-expected argument builds the expected description and
the pre-run cache digest for the later audit job.

The request, configuration, run identity and job listing are checked first, because they decide
what is scanned. After that the canary scan precedes every other check, so a failed or
cancelled producer that leaked the canary still refuses with the canary phase. Anything missing, incomplete, paginated short,
cancelled, skipped or mismatched refuses. The public result is one fixed line and a refusal
names only a closed phase, never a value.

API client interface, injected so tests use fakes:

    json(path) returns a pair of a decoded body and a headers mapping, for a GET of the path
    log_text(job_id) returns the complete log of one job as bytes

Accepted line:

    KD-CONFINEMENT-AUDIT schema=1 status=accepted os=<os> mode=<mode> control-sha=<sha>
    run-id=<n> run-attempt=<n> verdict=accepted log-canary=absent artifacts=expected caches=verified

Refusal line:

    KD-CONFINEMENT-AUDIT schema=1 status=refused phase=<phase> reason=confinement_audit_invalid
"""

import base64
import datetime
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
AUDIT_CACHE_KEYS_ENV = "CONFINEMENT_AUDIT_CACHE_KEYS"
MAX_EXPECTED_BYTES = 600000
MAX_LINE_BYTES = 512
PAGE_SIZE = 100
MAX_PAGES = 100
MAX_JOBS = 20
MAX_ARTIFACTS = 1000
MAX_CACHES = 10000
MAX_CACHE_BASELINE_BYTES = 32 + MAX_CACHES * 40
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
    "artifact_names", "cache_digest", "cache_baseline",
))
UNSECTIONED_STEPS = ("Set up job", "Complete job")
GROUP_MARK = bytes((35, 35)) + b"[group]"
RUN_HEADER = GROUP_MARK + b"Run "
SECTION_HEADERS = (GROUP_MARK + b"Post ",)
TAIL_LINES = (b"Post job cleanup.", b"Cleaning up orphan processes")
START_ACTION = bytes((35, 35)) + b"[start-action "
END_ACTION = bytes((35, 35)) + b"[end-action "
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
    r" caches=(verified|unchanged)"
)
REFUSED_RE = re.compile(
    re.escape(AUDIT_PREFIX) + r" schema=1 status=refused phase=([a-z_]{1,24})"
    r" reason=" + REFUSAL_REASON
)


QUICK_MODE = "quick"
QUICK_WORKFLOW_PATH = ".github/workflows/core-linux-quick-return.yml"
LINUX_SOURCE_WORKFLOW_PATH = ".github/workflows/linux-source-admission.yml"
LINUX_SOURCE_TITLE_PREFIX = "Linux admission source "
QUICK_GATES_STEP = "Run all offline project gates"
QUICK_LINE_STEP = "Record quick return counts"
QUICK_ARTIFACT_PREFIX = "linux-quick-"
QUICK_FRAME_BYTES = 4 * 1024 * 1024 - 64 * 1024 + 470 + 16
QUICK_ARTIFACT_SLACK_BYTES = 8192
QUICK_RETENTION_SECONDS = 24 * 60 * 60
QUICK_RETENTION_SLACK_SECONDS = 600
QUICK_MIN_GATES = 15
QUICK_MAX_GATES = 19
QUICK_SCREENS_MAX_PARTS = 17
QUICK_FULL_MEMBERS = 1 + QUICK_SCREENS_MAX_PARTS
QUICK_EXPECTED_FIELDS = (
    (EXPECTED_FIELDS - frozenset(("verdict_job", "verdict_step"))) | frozenset(("quick_job", "request_id"))
)
QUICK_LINE_PREFIX = b"KD-LINUX-QUICK"
QUICK_COUNT_PREFIX = QUICK_LINE_PREFIX + b" "
QUICK_COUNT_RE = re.compile(
    rb"KD-LINUX-QUICK schema=1 request-id=([a-f0-9]{64}) tier=quick admission=never"
    rb" gates-selected=(0|[1-9][0-9]?) gates-passed=(0|[1-9][0-9]?) failed=(0|[1-9][0-9]?)"
    rb" status=encrypted"
)
QUICK_PREFLIGHT_RE = re.compile(
    rb"KD-LINUX-QUICK-PREFLIGHT schema=1 request-id=([a-f0-9]{64}) tier=quick admission=never"
    rb" status=verified"
)
QUICK_TIME_RE = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.[0-9]{1,9})?Z")
QUICK_ARTIFACT_FIELDS = frozenset(("id", "name", "size_in_bytes", "created_at", "expires_at", "expired", "workflow_run"))


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
            or DIGEST_RE.fullmatch(expected["cache_digest"]) is None
            or not _cache_baseline_ok(expected["cache_baseline"])
            or (expected["cache_baseline"] != ""
                and _cache_baseline_digest(expected["cache_baseline"]) != expected["cache_digest"])):
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


def _is_tail_step(name):
    return name == "Complete job" or name.startswith("Post ")


def _step_numbers_ok(names, numbers):
    """Require strictly increasing numbers, main steps contiguous from one, and any gap only before a tail step.

    GitHub numbers post-job steps and the final completion step after a gap that follows the
    main steps, so only a step named Post or the completion step may take a larger number.
    """
    if len(names) != len(numbers):
        return False
    previous = 0
    main_steps = 0
    for name, number in zip(names, numbers):
        if type(name) is not str or not _exact_int(number, 1) or number <= previous:
            return False
        if not _is_tail_step(name):
            main_steps += 1
            if number != main_steps:
                return False
        previous = number
    return True


def _check_steps(job, spec):
    steps = job["steps"]
    if len(steps) != len(spec["steps"]):
        _fail("job_steps")
    if (any(type(step) is not dict for step in steps)
            or not _step_numbers_ok(spec["steps"], [step.get("number") for step in steps])):
        _fail("job_steps")
    for index, step in enumerate(steps, start=1):
        name = spec["steps"][index - 1]
        if not _is(step.get("name"), name) or not _is(step.get("status"), "completed"):
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


def _index_jobs(jobs, expected):
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
    return by_name


def _check_jobs(jobs, expected):
    by_name = _index_jobs(jobs, expected)
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


def _surface_texts(api, job, expected, texts):
    """Append every readable text of the job check; return None or the phase to report.

    Anything that cannot be read or understood in full, or that exceeds a bound, is reported as
    the canary phase because absence of the canary is then not proven. Texts are appended before
    any bound or identity check is applied, so they are always scanned.
    """
    check_id = _check_id(job, expected["repository"])
    check_path = "/repos/" + expected["repository"] + "/check-runs/" + str(check_id)
    try:
        check, unused_headers = api.json(check_path)
    except Exception:
        return "log_canary"
    output = check.get("output") if type(check) is dict else None
    if type(output) is not dict:
        return "log_canary"
    unscanned = False
    for field in ("title", "summary", "text"):
        value = output.get(field)
        if value is None:
            continue
        if type(value) is not str:
            unscanned = True
            continue
        texts.append(value)
        if len(value) > MAX_CHECK_TEXT:
            unscanned = True
    count = output.get("annotations_count")
    if not _exact_int(count, 0, MAX_ANNOTATIONS):
        return "log_canary"
    try:
        annotations = _collect_annotations(api, check_path + "/annotations", count)
    except Exception:
        return "log_canary"
    for annotation in annotations:
        if type(annotation) is not dict:
            unscanned = True
            continue
        for value in annotation.values():
            if type(value) is str:
                texts.append(value)
            elif value is not None and type(value) not in (int, bool):
                unscanned = True
    if unscanned:
        return "log_canary"
    if (not _is(check.get("id"), check_id)
            or not _is(check.get("head_sha"), expected["control_sha"])
            or not _is(check.get("status"), "completed")
            or not _is(check.get("conclusion"), job.get("conclusion"))):
        return "annotations"
    return None


def _candidates(jobs, expected):
    chosen = [
        job for job in jobs
        if type(job) is dict and _exact_int(job.get("id"), 1)
        and job.get("status") == "completed" and job.get("name") != expected["auditor_job"]
    ]
    return sorted(chosen, key=lambda item: item["id"])


def _gather(api, jobs, expected):
    """Collect the log, check output and annotations of every completed job.

    Problems are recorded and returned, not raised, so the canary scan covers everything that
    could be read before any other refusal is reported. The last value is true when some
    surface could not be read or scanned in full, so absence of the canary is not proven.
    """
    logs = {}
    texts = []
    pending = []
    unscanned = False
    for job in _candidates(jobs, expected):
        try:
            log = api.log_text(job["id"])
        except Exception:
            log = None
        if type(log) is bytes and log:
            logs[job["id"]] = log
            if len(log) > MAX_LOG_BYTES:
                unscanned = True
        else:
            unscanned = True
        try:
            phase = _surface_texts(api, job, expected, texts)
        except AuditRefusal as error:
            phase = error.phase
        except Exception:
            phase = "log_canary"
        if phase == "log_canary":
            unscanned = True
        elif phase is not None:
            pending.append(phase)
        if sum(len(text) for text in texts) > MAX_ANNOTATION_TEXT:
            unscanned = True
    return logs, texts, pending, unscanned


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
    """Require the single verdict line inside the log section of the verdict step.

    Raw job logs have no per-step header or footer for plain steps: each step starts with a
    run header line and its section ends at the next run header, a post header, or the job tail
    line. Composite actions add nested run headers and start and end markers that do not map to
    job steps, so any such marker refuses.
    """
    _check_prefix_section(log, job, expected["verdict_step"], VERDICT_PREFIX, ("success",))


def _check_prefix_section(log, job, step_name, prefix, conclusions):
    ordinal = None
    eligible = 0
    for step in job["steps"]:
        name = step.get("name")
        if (step.get("conclusion") not in conclusions or name in UNSECTIONED_STEPS
                or name.startswith("Post ")):
            continue
        if name == step_name:
            ordinal = eligible
        eligible += 1
    lines = _stripped_lines(log)
    if any(line.startswith(START_ACTION) or line.startswith(END_ACTION) for line in lines):
        _fail("verdict")
    runs = [index for index, line in enumerate(lines) if line.startswith(RUN_HEADER)]
    if ordinal is None or len(runs) != eligible:
        _fail("verdict")
    start = runs[ordinal]
    following = [
        index for index, line in enumerate(lines)
        if index > start and (
            line.startswith(RUN_HEADER) or line.startswith(SECTION_HEADERS)
            or line.rstrip() in TAIL_LINES
        )
    ]
    end = following[0] if following else len(lines)
    positions = [index for index, line in enumerate(lines) if line.startswith(prefix)]
    if len(positions) != 1 or not start < positions[0] < end:
        _fail("verdict")
    return lines[positions[0]]


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


SOURCE_CACHE_NAMESPACE = "-linux-source-"


def _cache_entry_digest(item):
    row = [
        item["id"], item["key"], item["ref"], item["version"],
        item["size_in_bytes"], item["created_at"],
    ]
    encoded = json.dumps(row, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
    return hashlib.sha256(encoded.encode("ascii")).digest()


def _decode_cache_baseline(cache_baseline):
    maximum = ((MAX_CACHE_BASELINE_BYTES + 2) // 3) * 4
    if cache_baseline == "":
        return {}
    if type(cache_baseline) is not str or len(cache_baseline) > maximum:
        raise ValueError("cache baseline")
    try:
        encoded = base64.b64decode(cache_baseline, validate=True)
    except (ValueError, TypeError):
        raise ValueError("cache baseline") from None
    if (base64.b64encode(encoded).decode("ascii") != cache_baseline
            or len(encoded) < 32 or (len(encoded) - 32) % 40 != 0
            or (len(encoded) - 32) // 40 > MAX_CACHES
            or hashlib.sha256(encoded[32:]).digest() != encoded[:32]):
        raise ValueError("cache baseline")
    result = {}
    previous = 0
    for offset in range(32, len(encoded), 40):
        identifier = int.from_bytes(encoded[offset:offset + 8], "big")
        if identifier <= previous:
            raise ValueError("cache baseline")
        result[identifier] = encoded[offset + 8:offset + 40]
        previous = identifier
    return result


def _cache_baseline_ok(cache_baseline):
    try:
        _decode_cache_baseline(cache_baseline)
    except (ValueError, TypeError, OverflowError):
        return False
    return True


def _cache_baseline_digest(cache_baseline):
    if cache_baseline == "":
        return None
    try:
        encoded = base64.b64decode(cache_baseline, validate=True)
    except (ValueError, TypeError):
        raise ValueError("cache baseline") from None
    return encoded[:32].hex()


def cache_inventory_baseline(entries):
    """Encode per-cache fingerprints compactly so evictions can be distinguished from mutations."""
    cache_inventory_digest(entries)
    fingerprints = bytearray()
    for item in sorted(entries, key=lambda entry: entry["id"]):
        try:
            fingerprints.extend(item["id"].to_bytes(8, "big"))
        except OverflowError:
            _fail("cache_inventory")
        fingerprints.extend(_cache_entry_digest(item))
    encoded = hashlib.sha256(fingerprints).digest() + fingerprints
    return base64.b64encode(encoded).decode("ascii")


def snapshot_cache_inventory(api, repository):
    """Capture the baseline digest and per-entry fingerprints for the later audit."""
    if type(repository) is not str or REPOSITORY_RE.fullmatch(repository) is None:
        _fail("request")
    entries = _collect_caches(api, repository)
    baseline = cache_inventory_baseline(entries)
    return _cache_baseline_digest(baseline), baseline


def snapshot_cache_digest(api, repository):
    """Take the cache digest before producer jobs run, for later comparison by the auditor."""
    if type(repository) is not str or REPOSITORY_RE.fullmatch(repository) is None:
        _fail("request")
    entries = _collect_caches(api, repository)
    baseline = cache_inventory_baseline(entries)
    return _cache_baseline_digest(baseline), baseline


def _collect_caches(api, repository):
    return _collect_counted(
        api, "/repos/" + repository + "/actions/caches", "actions_caches", MAX_CACHES, CACHE_QUERY,
    )


def accepted_line(expected):
    return (
        AUDIT_PREFIX + " schema=" + str(SCHEMA_VERSION) + " status=accepted os=" + expected["os"]
        + " mode=" + expected["mode"] + " control-sha=" + expected["control_sha"]
        + " run-id=" + str(expected["run_id"]) + " run-attempt=" + str(expected["run_attempt"])
        + " verdict=accepted log-canary=absent artifacts=expected caches=verified"
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


RUST_CACHE_KEY_RE = re.compile(
    r"kd-rust-v5-(?:Linux|macOS|Windows)-(?:x64|arm64)-"
    r"(?:rust|runtime-workspace|linux-source-admission|linux-source-verifier)-"
    r"(?:primary|independent-verifier)-[a-f0-9]{40}-[a-f0-9]{40}-"
    r"[a-f0-9]{64}-[a-f0-9]{64}-[a-f0-9]{64}\Z"
)
SOURCE_CACHE_KEY_RE = re.compile(
    r"kd-rust-v5-Linux-x64-linux-source-(?:admission-primary|verifier-independent-verifier)-"
    r"([a-f0-9]{40})-([a-f0-9]{40})-[a-f0-9]{64}-[a-f0-9]{64}-[a-f0-9]{64}\Z"
)


def _cache_inventory_matches(api, expected, allowed_cache_keys=()):
    items = _collect_caches(api, expected["repository"])
    cache_inventory_digest(items)
    baseline = _decode_cache_baseline(expected["cache_baseline"])
    baseline_rows = [item for item in items if item["id"] in baseline]
    additions = [item for item in items if item["id"] not in baseline]
    baseline_by_id = {item["id"]: item for item in baseline_rows}
    if (_cache_baseline_digest(expected["cache_baseline"]) != expected["cache_digest"]
            or any(_cache_entry_digest(item) != baseline[item["id"]] for item in baseline_rows)
            or (len(baseline_by_id) == len(baseline)
                and cache_inventory_baseline(baseline_rows) != expected["cache_baseline"])
            or any(not _authorized_cache_addition(item, expected, allowed_cache_keys)
                   for item in additions)
            or len({item["key"] for item in additions}) != len(additions)):
        _fail("cache_inventory")


def _authorized_cache_addition(item, expected, allowed_cache_keys=()):
    """Accept current-run keys or schema-valid managed writes from protected main."""
    if item["ref"] != "refs/heads/main" or item["size_in_bytes"] <= 0:
        return False
    if item["key"] in allowed_cache_keys:
        return expected["ci_ref"] == "main"
    if SOURCE_CACHE_NAMESPACE in item["key"]:
        matched = SOURCE_CACHE_KEY_RE.fullmatch(item["key"])
        if matched is None:
            return False
        title_prefix = LINUX_SOURCE_TITLE_PREFIX
        if (expected["workflow_path"] == LINUX_SOURCE_WORKFLOW_PATH
                and expected["mode"] == "candidate" and expected["ci_ref"] == "main"
                and expected["display_title"].startswith(title_prefix)
                and SHA_RE.fullmatch(expected["display_title"][len(title_prefix):]) is not None
                and matched.group(1) == expected["display_title"][len(title_prefix):]
                and matched.group(2) == expected["control_sha"]):
            return False
        return True
    if RUST_CACHE_KEY_RE.fullmatch(item["key"]) is not None:
        return True
    return re.fullmatch(
        r"macos-public-cache-seed-v1-[1-9][0-9]{0,18}-[1-9][0-9]{0,18}", item["key"]
    ) is not None


def parse_allowed_cache_keys(raw, expected):
    """Accept only the exact cache-key forms emitted by the main-ref source-read job."""
    if type(raw) is not str or len(raw) > 2048:
        _fail("request")
    if raw == "":
        return ()
    keys = tuple(raw.split(","))
    if any(not item for item in keys):
        _fail("request")
    if not keys:
        return ()
    if (expected["mode"] != "candidate" or expected["ci_ref"] != "main"
            or len(keys) > 2 or len(set(keys)) != len(keys)):
        _fail("request")
    title_prefix = LINUX_SOURCE_TITLE_PREFIX
    source_sha = expected["display_title"][len(title_prefix):]
    if (not expected["display_title"].startswith(title_prefix)
            or SHA_RE.fullmatch(source_sha) is None):
        _fail("request")
    allowed_prefixes = (
        ("kd-rust-v5-Linux-x64-linux-source-admission-primary-", "primary"),
        ("kd-rust-v5-Linux-x64-linux-source-verifier-independent-verifier-", "independent-verifier"),
    )
    seen_scopes = set()
    for key in keys:
        matched_prefix = next(((prefix, scope) for prefix, scope in allowed_prefixes
                               if key.startswith(prefix)), None)
        if RUST_CACHE_KEY_RE.fullmatch(key) is None or matched_prefix is None:
            _fail("request")
        suffix = key[len(matched_prefix[0]):].split("-")
        if (len(suffix) != 5 or suffix[0] != source_sha or suffix[1] != expected["control_sha"]
                or any(SHA_RE.fullmatch(value) is None for value in suffix[:2])
                or any(DIGEST_RE.fullmatch(value) is None for value in suffix[2:])):
            _fail("request")
        scope = matched_prefix[1]
        if scope in seen_scopes:
            _fail("request")
        seen_scopes.add(scope)
    return keys


def audit(api, expected, config=None, allowed_cache_keys=()):
    """Return the accepted public line, or raise AuditRefusal naming only a closed phase."""
    _guard("request", validate_expected, expected)
    if type(allowed_cache_keys) is not tuple or len(allowed_cache_keys) > 2:
        _fail("request")
    if allowed_cache_keys:
        _guard("request", parse_allowed_cache_keys, ",".join(allowed_cache_keys), expected)
    resolved = _guard("log_canary", _resolve_config, config)
    _guard("run", _check_run, api, expected)
    jobs = _guard("jobs", _list_jobs, api, expected)
    logs, texts, pending, unscanned = _gather(api, jobs, expected)
    _scan(logs, texts, resolved)
    if unscanned:
        _fail("log_canary")
    by_name = _guard("jobs", _check_jobs, jobs, expected)
    if pending:
        _fail(pending[0])
    line = _guard("verdict", _verdict_line, logs, by_name, expected)
    _guard("verdict", _check_verdict, line, expected)
    if any(VERDICT_PREFIX in text.encode("utf-8", "replace") for text in texts):
        _fail("annotations")
    _guard("artifact_inventory", _check_artifacts, api, expected)
    _guard("cache_inventory", _cache_inventory_matches, api, expected, allowed_cache_keys)
    return accepted_line(expected)


def audit_line(api, expected, config=None, allowed_cache_keys=()):
    """Return a pair of the accepted flag and the one public line; never raises on a refusal."""
    try:
        return True, audit(api, expected, config, allowed_cache_keys)
    except AuditRefusal as error:
        return False, refusal_line(error.phase)
    except Exception:
        return False, refusal_line("unavailable")


def validate_expected_quick(expected):
    """Refuse any expected quick-run description that is not exactly the closed shape."""
    if type(expected) is not dict or set(expected) != QUICK_EXPECTED_FIELDS:
        _fail("request")
    jobs = expected["jobs"]
    request_id = expected["request_id"]
    if (type(expected["repository"]) is not str or REPOSITORY_RE.fullmatch(expected["repository"]) is None
            or not _is(expected["os"], "linux")
            or not _is(expected["mode"], QUICK_MODE)
            or type(expected["control_sha"]) is not str or SHA_RE.fullmatch(expected["control_sha"]) is None
            or not _exact_int(expected["run_id"], 1)
            or not _is(expected["run_attempt"], 1)
            or not _is(expected["workflow_path"], QUICK_WORKFLOW_PATH)
            or not _is(expected["ci_ref"], "untrusted")
            or type(expected["display_title"]) is not str
            or LABEL_RE.fullmatch(expected["display_title"]) is None
            or type(jobs) is not dict or not 1 <= len(jobs) < MAX_JOBS
            or type(expected["quick_job"]) is not str or expected["quick_job"] not in jobs
            or type(expected["auditor_job"]) is not str
            or LABEL_RE.fullmatch(expected["auditor_job"]) is None
            or expected["auditor_job"] in jobs
            or type(request_id) is not str or DIGEST_RE.fullmatch(request_id) is None
            or type(expected["artifact_names"]) is not tuple
            or expected["artifact_names"] != (QUICK_ARTIFACT_PREFIX + request_id,)
            or type(expected["cache_digest"]) is not str
            or DIGEST_RE.fullmatch(expected["cache_digest"]) is None
            or not _cache_baseline_ok(expected["cache_baseline"])
            or (expected["cache_baseline"] != ""
                and _cache_baseline_digest(expected["cache_baseline"]) != expected["cache_digest"])):
        _fail("request")
    for name, spec in jobs.items():
        if (type(name) is not str or LABEL_RE.fullmatch(name) is None or type(spec) is not dict
                or set(spec) != JOB_FIELDS
                or not _text_tuple(spec["steps"], 1, 100, LABEL_RE)
                or not _text_tuple(spec["optional_steps"], 0, 100, LABEL_RE)
                or not set(spec["optional_steps"]).issubset(spec["steps"])
                or any("verdict" in step.lower() for step in spec["steps"])):
            _fail("request")
    quick_spec = jobs[expected["quick_job"]]
    for step in (QUICK_GATES_STEP, QUICK_LINE_STEP):
        if quick_spec["steps"].count(step) != 1 or step in quick_spec["optional_steps"]:
            _fail("request")


def _check_quick_steps(job, spec):
    steps = job["steps"]
    if len(steps) != len(spec["steps"]):
        _fail("job_steps")
    gates = None
    if (any(type(step) is not dict for step in steps)
            or not _step_numbers_ok(spec["steps"], [step.get("number") for step in steps])):
        _fail("job_steps")
    for index, step in enumerate(steps, start=1):
        name = spec["steps"][index - 1]
        if not _is(step.get("name"), name) or not _is(step.get("status"), "completed"):
            _fail("job_steps")
        conclusion = step.get("conclusion")
        if name == QUICK_GATES_STEP:
            if conclusion not in ("success", "failure"):
                _fail("job_steps")
            gates = conclusion
        elif conclusion != "success" and not (conclusion == "skipped" and name in spec["optional_steps"]):
            _fail("job_steps")
    return gates


def _check_quick_jobs(jobs, expected):
    by_name = _index_jobs(jobs, expected)
    outcome = None
    for name, spec in expected["jobs"].items():
        job = by_name[name]
        if job.get("status") != "completed":
            _fail("jobs")
        if name == expected["quick_job"]:
            if job.get("conclusion") not in ("success", "failure"):
                _fail("jobs")
            outcome = _guard("job_steps", _check_quick_steps, job, spec)
            if (job["conclusion"] == "success") != (outcome == "success"):
                _fail("jobs")
        else:
            if job.get("conclusion") != "success":
                _fail("jobs")
            _guard("job_steps", _check_steps, job, spec)
    return by_name, outcome


def _check_quick_logs(logs, by_name, expected, outcome):
    for name in sorted(expected["jobs"]):
        job = by_name[name]
        log = logs.get(job["id"])
        if log is None:
            _fail("job_logs")
        if VERDICT_PREFIX in log or confinement_verdict.find_lines(log):
            _fail("verdict")
        quick_job = name == expected["quick_job"]
        for line in _stripped_lines(log):
            if not line.startswith(QUICK_LINE_PREFIX):
                continue
            matched = QUICK_PREFLIGHT_RE.fullmatch(line)
            if matched is not None:
                if matched.group(1).decode("ascii") != expected["request_id"]:
                    _fail("verdict")
            elif not quick_job or QUICK_COUNT_RE.fullmatch(line) is None:
                _fail("verdict")
        if not quick_job:
            continue
        line = _check_prefix_section(log, job, QUICK_LINE_STEP, QUICK_COUNT_PREFIX, ("success", "failure"))
        matched = QUICK_COUNT_RE.fullmatch(line)
        if matched is None or matched.group(1).decode("ascii") != expected["request_id"]:
            _fail("verdict")
        selected, passed, failed = (int(matched.group(index)) for index in (2, 3, 4))
        if (not QUICK_MIN_GATES <= selected <= QUICK_MAX_GATES or passed + failed > selected
                or failed > 1 or (failed == 0) != (outcome == "success")
                or (outcome == "success" and passed != selected)):
            _fail("verdict")


def _quick_time(value):
    matched = QUICK_TIME_RE.fullmatch(value) if type(value) is str else None
    if matched is None:
        _fail("artifact_inventory")
    return datetime.datetime.strptime(matched.group(1), "%Y-%m-%dT%H:%M:%S")


def _check_quick_artifacts(api, expected):
    path = ("/repos/" + expected["repository"] + "/actions/runs/" + str(expected["run_id"])
            + "/artifacts")
    items = _collect_counted(api, path, "artifacts", MAX_ARTIFACTS)
    if len(items) != 1:
        _fail("artifact_inventory")
    item = items[0]
    if type(item) is not dict or not QUICK_ARTIFACT_FIELDS.issubset(item):
        _fail("artifact_inventory")
    run = item["workflow_run"]
    size = item["size_in_bytes"]
    if (not _exact_int(item["id"], 1)
            or not _is(item["name"], expected["artifact_names"][0])
            or not _is(item["expired"], False)
            or not (
                _exact_int(size, QUICK_FRAME_BYTES, QUICK_FRAME_BYTES + QUICK_ARTIFACT_SLACK_BYTES)
                or _exact_int(
                    size, QUICK_FULL_MEMBERS * QUICK_FRAME_BYTES,
                    QUICK_FULL_MEMBERS * (QUICK_FRAME_BYTES + QUICK_ARTIFACT_SLACK_BYTES),
                )
            )
            or type(run) is not dict
            or not _is(run.get("id"), expected["run_id"])
            or not _is(run.get("head_sha"), expected["control_sha"])
            or not _is(run.get("head_branch"), expected["ci_ref"])):
        _fail("artifact_inventory")
    lifetime = (_quick_time(item["expires_at"]) - _quick_time(item["created_at"])).total_seconds()
    if not 0 < lifetime <= QUICK_RETENTION_SECONDS + QUICK_RETENTION_SLACK_SECONDS:
        _fail("artifact_inventory")


def quick_accepted_line(expected):
    return (
        AUDIT_PREFIX + " schema=" + str(SCHEMA_VERSION) + " status=accepted os=linux mode=quick"
        + " tier=quick admission=never control-sha=" + expected["control_sha"]
        + " run-id=" + str(expected["run_id"]) + " run-attempt=" + str(expected["run_attempt"])
        + " verdict=none log-canary=absent artifacts=expected caches=verified"
    )


def audit_quick(api, expected, config=None):
    """Return the accepted quick line, or raise AuditRefusal naming only a closed phase."""
    _guard("request", validate_expected_quick, expected)
    resolved = _guard("log_canary", _resolve_config, config)
    _guard("run", _check_run, api, expected)
    jobs = _guard("jobs", _list_jobs, api, expected)
    logs, texts, pending, unscanned = _gather(api, jobs, expected)
    _scan(logs, texts, resolved)
    if unscanned:
        _fail("log_canary")
    by_name, outcome = _guard("jobs", _check_quick_jobs, jobs, expected)
    if pending:
        _fail(pending[0])
    _guard("verdict", _check_quick_logs, logs, by_name, expected, outcome)
    if any(VERDICT_PREFIX in text.encode("utf-8", "replace") for text in texts):
        _fail("annotations")
    _guard("artifact_inventory", _check_quick_artifacts, api, expected)
    _guard("cache_inventory", _cache_inventory_matches, api, expected)
    return quick_accepted_line(expected)


def quick_audit_line(api, expected, config=None):
    """Return a pair of the accepted flag and the one public line; never raises on a refusal."""
    try:
        return True, audit_quick(api, expected, config)
    except AuditRefusal as error:
        return False, refusal_line(error.phase)
    except Exception:
        return False, refusal_line("unavailable")


WINDOWS_MODE = "windows"
WINDOWS_EXPECTED_ARG = "windows-expected"
WINDOWS_WORKFLOW_PATH = ".github/workflows/windows-source-admission.yml"
WINDOWS_TITLE_PREFIX = "Windows admission source "
WINDOWS_SYNTHETIC_TITLE = "Windows admission synthetic synthetic"
WINDOWS_SETTINGS_JOB = "settings"
WINDOWS_PRODUCER_JOB = "role-call-windows-producer-v1 / role-windows-producer-v1"
WINDOWS_VERIFIER_JOB = "role-call-windows-verifier-v1 / role-windows-verifier-v1"
WINDOWS_LINUX_JOB = "role-call-linux-fetch-encrypt-v1 / role-linux-fetch-encrypt-v1"
WINDOWS_ATTESTER_JOB = "role-call-capsule-attester-v1 / role-capsule-attester-v1"
WINDOWS_EVIDENCE_JOB = "verify-role-evidence-windows-source"
WINDOWS_AUDITOR_JOB = "audit"
WINDOWS_OPEN_JOBS = (
    WINDOWS_PRODUCER_JOB, WINDOWS_VERIFIER_JOB, WINDOWS_LINUX_JOB, WINDOWS_ATTESTER_JOB,
)
WINDOWS_VERDICT_STEP = "Publish confinement verdict"
WINDOWS_SETTINGS_STEPS = (
    "Set up job",
    "Fetch exact public control",
    "Snapshot cache inventory and validate preflight",
    "Build audit identity",
    "Complete job",
)
WINDOWS_EVIDENCE_STEPS = (
    "Set up job",
    "Checkout reviewed control files",
    "Collect complete attempt-specific job and artifact evidence",
    "Retain source-free role evidence",
    "Apply the exact candidate profile and uniqueness policy",
    "Post Checkout reviewed control files",
    "Complete job",
)
WINDOWS_PRODUCER_STEPS = ("Set up job", "Complete job")
WINDOWS_VERIFIER_STEPS = ("Set up job", WINDOWS_VERDICT_STEP, "Complete job")
WINDOWS_LINUX_STEPS = (
    "Set up job",
    "Wait for both exact current-attempt receiver artifacts",
    "handoff-revoke-source-token-v1",
    "handoff-verify-token-rejection-v1",
    "Upload the producer source capsule",
    "Upload the verifier source capsule",
    "Complete job",
)
WINDOWS_LINUX_SYNTHETIC_SKIPS = (
    "Repeat preflight in source-read",
    "Record image and fetch pinned toolchains",
    "Mint scoped source-reader token",
    "Verify selected installation identity",
    "Fetch exact source and verify binding, tree, signatures and committed locks",
    "Post Mint scoped source-reader token",
)
WINDOWS_ATTESTER_STEPS = (
    "Set up job",
    "Sign only the capsule-attester role statement",
    "Upload exact attester subject, predicate, and bundle",
    "Complete job",
)
WINDOWS_EXPECTED_FIELDS = EXPECTED_FIELDS | frozenset(("open_jobs",))
WINDOWS_CAPSULE_PREFIX = "source-capsule-"
WINDOWS_CAPSULE_ROLES = ("producer", "verifier")
WINDOWS_EVIDENCE_PREFIX = "role-signer-candidate-evidence-"
WINDOWS_CAPSULE_BYTES = 286261248
WINDOWS_CAPSULE_SLACK_BYTES = 8192
WINDOWS_SMALL_ARTIFACT_BYTES = 16 * 1024 * 1024
WINDOWS_RETENTION_SECONDS = 24 * 60 * 60
WINDOWS_RETENTION_SLACK_SECONDS = 600
WINDOWS_ARTIFACT_COUNT = 7
WINDOWS_ROLE_ARTIFACT_RE = re.compile(
    r"role-statement-(windows-receiver|windows-producer|windows-verifier|linux-fetch-encrypt"
    r"|capsule-attester)-([1-9][0-9]{0,15})-([1-9][0-9]?)-([a-f0-9]{32})"
)
WINDOWS_ROLE_COUNTS = (("windows", 2), ("linux-fetch-encrypt", 1), ("capsule-attester", 1))
WINDOWS_SYNTHETIC_CANARY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
WINDOWS_CANARY_ENV = "KD_WINDOWS_LOG_CANARY"


def windows_capsule_names(run_id, run_attempt):
    return tuple(
        WINDOWS_CAPSULE_PREFIX + role + "-" + str(run_id) + "-" + str(run_attempt)
        for role in WINDOWS_CAPSULE_ROLES
    )


def windows_evidence_name(run_id, run_attempt):
    return WINDOWS_EVIDENCE_PREFIX + str(run_id) + "-" + str(run_attempt)


def _windows_open_spec_ok(name, spec):
    if (type(spec) is not dict or set(spec) != JOB_FIELDS
            or not _text_tuple(spec["steps"], 2, 100, LABEL_RE)
            or not _text_tuple(spec["optional_steps"], 0, 100, LABEL_RE)):
        return False
    steps = spec["steps"]
    return (steps[0] == "Set up job" and steps[-1] == "Complete job"
            and len(set(steps)) == len(steps)
            and not set(spec["optional_steps"]) & set(steps))


def validate_expected_windows(expected):
    """Refuse any expected Windows source-run description that is not exactly the closed shape."""
    if type(expected) is not dict or set(expected) != WINDOWS_EXPECTED_FIELDS:
        _fail("request")
    jobs = expected["jobs"]
    run_id = expected["run_id"]
    if (type(expected["repository"]) is not str or REPOSITORY_RE.fullmatch(expected["repository"]) is None
            or not _is(expected["os"], "windows")
            or type(expected["mode"]) is not str or expected["mode"] not in MODES
            or type(expected["control_sha"]) is not str or SHA_RE.fullmatch(expected["control_sha"]) is None
            or not _exact_int(run_id, 1)
            or not _is(expected["run_attempt"], 1)
            or not _is(expected["workflow_path"], WINDOWS_WORKFLOW_PATH)
            or type(expected["ci_ref"]) is not str or expected["ci_ref"] not in CI_REFS
            or (expected["mode"] == "synthetic" and expected["ci_ref"] != "main")
            or (expected["mode"] == "synthetic"
                and not _is(expected["display_title"], WINDOWS_SYNTHETIC_TITLE))
            or type(expected["display_title"]) is not str
            or LABEL_RE.fullmatch(expected["display_title"]) is None
            or (expected["mode"] == "candidate"
                and (not expected["display_title"].startswith(WINDOWS_TITLE_PREFIX)
                     or SHA_RE.fullmatch(expected["display_title"][len(WINDOWS_TITLE_PREFIX):]) is None))
            or not _is(expected["verdict_job"], WINDOWS_VERIFIER_JOB)
            or not _is(expected["verdict_step"], WINDOWS_VERDICT_STEP)
            or not _is(expected["auditor_job"], WINDOWS_AUDITOR_JOB)
            or not _is(expected["artifact_names"], windows_capsule_names(run_id, expected["run_attempt"]))
            or not _is(expected["open_jobs"], WINDOWS_OPEN_JOBS)
            or type(expected["cache_digest"]) is not str
            or DIGEST_RE.fullmatch(expected["cache_digest"]) is None
            or not _cache_baseline_ok(expected["cache_baseline"])
            or (expected["cache_baseline"] != ""
                and _cache_baseline_digest(expected["cache_baseline"]) != expected["cache_digest"])
            or type(jobs) is not dict
            or set(jobs) != set(WINDOWS_OPEN_JOBS) | {WINDOWS_SETTINGS_JOB, WINDOWS_EVIDENCE_JOB}):
        _fail("request")
    for name, spec in jobs.items():
        if name in WINDOWS_OPEN_JOBS:
            if not _windows_open_spec_ok(name, spec):
                _fail("request")
            continue
        if (type(spec) is not dict or set(spec) != JOB_FIELDS
                or not _text_tuple(spec["steps"], 1, 100, LABEL_RE)
                or not _text_tuple(spec["optional_steps"], 0, 100, LABEL_RE)
                or not set(spec["optional_steps"]).issubset(spec["steps"])):
            _fail("request")
    verdict_steps = jobs[WINDOWS_VERIFIER_JOB]["steps"]
    if (verdict_steps.count(WINDOWS_VERDICT_STEP) != 1
            or WINDOWS_VERDICT_STEP in jobs[WINDOWS_VERIFIER_JOB]["optional_steps"]):
        _fail("request")
    for name in (WINDOWS_PRODUCER_JOB, WINDOWS_LINUX_JOB, WINDOWS_ATTESTER_JOB):
        if any("verdict" in step.lower() for step in jobs[name]["steps"]):
            _fail("request")


def _check_open_steps(job, spec):
    steps = job["steps"]
    if (len(steps) < len(spec["steps"]) or len(steps) > 100
            or steps[0].get("name") != "Set up job" or steps[-1].get("name") != "Complete job"):
        _fail("job_steps")
    required = list(spec["steps"])
    if any(type(step) is not dict or type(step.get("name")) is not str for step in steps):
        _fail("job_steps")
    if not _step_numbers_ok([step["name"] for step in steps], [step.get("number") for step in steps]):
        _fail("job_steps")
    for step in steps:
        if (LABEL_RE.fullmatch(step["name"]) is None
                or not _is(step.get("status"), "completed")):
            _fail("job_steps")
        conclusion = step.get("conclusion")
        if conclusion != "success" and not (
                conclusion == "skipped" and step["name"] in spec["optional_steps"]):
            _fail("job_steps")
        if required and step["name"] == required[0]:
            required.pop(0)
    if required:
        _fail("job_steps")
    names = [step["name"] for step in steps]
    for name in spec["steps"]:
        if names.count(name) != 1:
            _fail("job_steps")


def _check_windows_jobs(jobs, expected):
    by_name = _index_jobs(jobs, expected)
    for name, spec in expected["jobs"].items():
        job = by_name[name]
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            _fail("jobs")
        if name in expected["open_jobs"]:
            _guard("job_steps", _check_open_steps, job, spec)
        else:
            _guard("job_steps", _check_steps, job, spec)
    return by_name


def _windows_artifact_time_ok(item):
    lifetime = (_quick_time(item["expires_at"]) - _quick_time(item["created_at"])).total_seconds()
    return 0 < lifetime <= WINDOWS_RETENTION_SECONDS + WINDOWS_RETENTION_SLACK_SECONDS


def _check_windows_artifacts(api, expected):
    path = ("/repos/" + expected["repository"] + "/actions/runs/" + str(expected["run_id"])
            + "/artifacts")
    items = _collect_counted(api, path, "artifacts", MAX_ARTIFACTS)
    if len(items) != WINDOWS_ARTIFACT_COUNT:
        _fail("artifact_inventory")
    run_id = expected["run_id"]
    attempt = expected["run_attempt"]
    capsules = set(expected["artifact_names"])
    evidence = windows_evidence_name(run_id, attempt)
    seen = set()
    counts = {"windows": 0, "linux-fetch-encrypt": 0, "capsule-attester": 0}
    for item in items:
        if type(item) is not dict or not QUICK_ARTIFACT_FIELDS.issubset(item):
            _fail("artifact_inventory")
        name = item["name"]
        run = item["workflow_run"]
        size = item["size_in_bytes"]
        if (type(name) is not str or name in seen or not _exact_int(item["id"], 1)
                or not _is(item["expired"], False)
                or type(run) is not dict
                or not _is(run.get("id"), run_id)
                or not _is(run.get("head_sha"), expected["control_sha"])
                or not _is(run.get("head_branch"), expected["ci_ref"])
                or not _windows_artifact_time_ok(item)):
            _fail("artifact_inventory")
        seen.add(name)
        if name in capsules:
            if not _exact_int(size, WINDOWS_CAPSULE_BYTES, WINDOWS_CAPSULE_BYTES + WINDOWS_CAPSULE_SLACK_BYTES):
                _fail("artifact_inventory")
            continue
        if not _exact_int(size, 1, WINDOWS_SMALL_ARTIFACT_BYTES):
            _fail("artifact_inventory")
        if name == evidence:
            continue
        matched = WINDOWS_ROLE_ARTIFACT_RE.fullmatch(name)
        if (matched is None or matched.group(2) != str(run_id) or matched.group(3) != str(attempt)):
            _fail("artifact_inventory")
        role = matched.group(1)
        counts["windows" if role.startswith("windows-") else role] += 1
    if (not capsules.issubset(seen) or evidence not in seen
            or any(counts[kind] != number for kind, number in WINDOWS_ROLE_COUNTS)):
        _fail("artifact_inventory")


def _check_windows_verdict(line, expected):
    record = confinement_verdict.decode_line(line)
    if (record["os"] != "windows" or record["control_sha"] != expected["control_sha"]
            or record["run_id"] != expected["run_id"]
            or record["run_attempt"] != expected["run_attempt"]
            or not confinement_verdict.run_accepted(record)):
        _fail("verdict")


def audit_windows(api, expected, config=None):
    """Return the accepted Windows line, or raise AuditRefusal naming only a closed phase."""
    _guard("request", validate_expected_windows, expected)
    resolved = _guard("log_canary", _resolve_config, config)
    _guard("run", _check_run, api, expected)
    jobs = _guard("jobs", _list_jobs, api, expected)
    logs, texts, pending, unscanned = _gather(api, jobs, expected)
    _scan(logs, texts, resolved)
    if unscanned:
        _fail("log_canary")
    by_name = _guard("jobs", _check_windows_jobs, jobs, expected)
    if pending:
        _fail(pending[0])
    line = _guard("verdict", _verdict_line, logs, by_name, expected)
    _guard("verdict", _check_windows_verdict, line, expected)
    if any(VERDICT_PREFIX in text.encode("utf-8", "replace") for text in texts):
        _fail("annotations")
    _guard("artifact_inventory", _check_windows_artifacts, api, expected)
    _guard("cache_inventory", _cache_inventory_matches, api, expected)
    return accepted_line(expected)


def windows_audit_line(api, expected, config=None):
    """Return a pair of the accepted flag and the one public line; never raises on a refusal."""
    try:
        return True, audit_windows(api, expected, config)
    except AuditRefusal as error:
        return False, refusal_line(error.phase)
    except Exception:
        return False, refusal_line("unavailable")


def windows_expected(environ, cache_digest, cache_baseline=""):
    """Build the expected Windows run description from the dispatch environment."""
    mode = environ.get("CI_MODE", "")
    run_id = environ.get("GITHUB_RUN_ID", "")
    attempt = environ.get("GITHUB_RUN_ATTEMPT", "")
    source_sha = environ.get("REQUESTED_SOURCE_SHA", "")
    ci_ref = environ.get("CI_REF", "")
    if (mode not in ("source", "synthetic") or re.fullmatch(r"[1-9][0-9]{0,15}", run_id) is None
            or attempt != "1" or ci_ref not in ("refs/heads/main", "refs/heads/untrusted")
            or SHA_RE.fullmatch(environ.get("CI_SHA", "")) is None
            or (mode == "source" and SHA_RE.fullmatch(source_sha) is None)):
        _fail("request")
    run_number = int(run_id)
    if mode == "source":
        title = WINDOWS_TITLE_PREFIX + source_sha
        optional = ()
    else:
        title = WINDOWS_SYNTHETIC_TITLE
        optional = WINDOWS_LINUX_SYNTHETIC_SKIPS
    expected = {
        "repository": environ.get("CI_REPOSITORY", ""),
        "os": "windows",
        "mode": "candidate" if mode == "source" else "synthetic",
        "control_sha": environ["CI_SHA"],
        "run_id": run_number,
        "run_attempt": 1,
        "workflow_path": WINDOWS_WORKFLOW_PATH,
        "ci_ref": ci_ref.removeprefix("refs/heads/"),
        "display_title": title,
        "jobs": {
            WINDOWS_SETTINGS_JOB: {"steps": WINDOWS_SETTINGS_STEPS, "optional_steps": ()},
            WINDOWS_PRODUCER_JOB: {
                "steps": WINDOWS_PRODUCER_STEPS,
                "optional_steps": (WINDOWS_VERDICT_STEP,),
            },
            WINDOWS_VERIFIER_JOB: {"steps": WINDOWS_VERIFIER_STEPS, "optional_steps": ()},
            WINDOWS_LINUX_JOB: {"steps": WINDOWS_LINUX_STEPS, "optional_steps": optional},
            WINDOWS_ATTESTER_JOB: {"steps": WINDOWS_ATTESTER_STEPS, "optional_steps": ()},
            WINDOWS_EVIDENCE_JOB: {"steps": WINDOWS_EVIDENCE_STEPS, "optional_steps": ()},
        },
        "verdict_job": WINDOWS_VERIFIER_JOB,
        "verdict_step": WINDOWS_VERDICT_STEP,
        "auditor_job": WINDOWS_AUDITOR_JOB,
        "artifact_names": windows_capsule_names(run_number, 1),
        "open_jobs": WINDOWS_OPEN_JOBS,
        "cache_digest": cache_digest if DIGEST_RE.fullmatch(cache_digest or "") else "0" * 64,
        "cache_baseline": cache_baseline,
    }
    validate_expected_windows(expected)
    return expected


def _write_windows_expected(env, sink, factory):
    """Write the expected description and the pre-run cache digest to the step output."""
    token = env.get("GITHUB_TOKEN", "")
    repository = env.get("CI_REPOSITORY", "")
    api = factory(token, repository)
    digest, baseline = snapshot_cache_digest(api, repository)
    expected = windows_expected(env, digest, baseline)
    encoded = json.dumps(expected, sort_keys=True, separators=(",", ":"))
    path = env.get("GITHUB_OUTPUT", "")
    if not path:
        _fail("request")
    with open(path, "at", encoding="ascii") as output:
        output.write("expected=" + encoded + "\n")
        output.write("cache_digest=" + digest + "\n")
    sink.write("windows-source-audit-identity=prepared\n")


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate")
        value[key] = item
    return value


def parse_expected(raw, quick=False, windows=False):
    """Build the expected-run description from its JSON form, converting lists to tuples."""
    if quick and windows:
        _fail("request")
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
    if type(value.get("open_jobs")) is list:
        value["open_jobs"] = tuple(value["open_jobs"])
    if quick:
        validate_expected_quick(value)
    elif windows:
        validate_expected_windows(value)
    else:
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
            length = blob_headers.get("Content-Length")
            if (blob_headers.get_content_type() not in ("text/plain", "application/octet-stream")
                    or blob_headers.get("Content-Encoding", "identity").lower() != "identity"
                    or type(length) is not str or not length.isascii() or not length.isdecimal()
                    or int(length) != len(data)):
                raise ValueError("log")
            return data

    return Client(token)


def _windows_config(environ):
    value = WINDOWS_SYNTHETIC_CANARY if environ.get("CI_MODE") == "synthetic" else environ.get(WINDOWS_CANARY_ENV, "")
    try:
        return log_canary.compute_config(value)
    except Exception:
        _fail("log_canary")


def main(arguments=None, environ=None, api_factory=None, stdout=None):
    """Workflow entry point: print one public line and exit zero only for an accepted audit."""
    actual = sys.argv[1:] if arguments is None else arguments
    env = os.environ if environ is None else environ
    sink = sys.stdout if stdout is None else stdout
    factory = _default_api_factory if api_factory is None else api_factory
    quick = list(actual) == [QUICK_MODE]
    windows = list(actual) == [WINDOWS_MODE]
    identity = list(actual) == [WINDOWS_EXPECTED_ARG]
    if actual and not (quick or windows or identity):
        return 2
    if identity:
        try:
            _write_windows_expected(env, sink, factory)
            return 0
        except BaseException:
            sink.write("windows-source-audit-identity=unavailable\n")
            return 1
    try:
        expected = parse_expected(env.get(EXPECTED_ENV, ""), quick, windows)
        if (env.get("GITHUB_REPOSITORY") != expected["repository"]
                or env.get("GITHUB_RUN_ID") != str(expected["run_id"])
                or env.get("GITHUB_RUN_ATTEMPT") != str(expected["run_attempt"])
                or env.get("GITHUB_SHA") != expected["control_sha"]):
            _fail("request")
        if windows:
            accepted, line = windows_audit_line(
                factory(env.get("GITHUB_TOKEN", ""), expected["repository"]), expected,
                _windows_config(env),
            )
        else:
            api = factory(env.get("GITHUB_TOKEN", ""), expected["repository"])
            if quick:
                accepted, line = quick_audit_line(api, expected)
            else:
                allowed_cache_keys = parse_allowed_cache_keys(
                    env.get(AUDIT_CACHE_KEYS_ENV, ""), expected,
                )
                accepted, line = audit_line(
                    api, expected, allowed_cache_keys=allowed_cache_keys,
                )
    except AuditRefusal as error:
        accepted, line = False, refusal_line(error.phase)
    except Exception:
        accepted, line = False, refusal_line("unavailable")
    sink.write(line + "\n")
    return 0 if accepted else 1


if __name__ == "__main__":
    raise SystemExit(main())
