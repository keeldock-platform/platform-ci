"""Authenticated post-run collection for the three encrypted feedback profiles."""

import datetime
import hashlib
import json
import re
import urllib.parse
import urllib.request

try:
    from . import feedback_request
    from . import macos_public_audit as public_audit
    from . import node_lock_receipt
except ImportError:
    import feedback_request
    import macos_public_audit as public_audit
    import node_lock_receipt


RUN_TITLE_PREFIX = "feedback-request-"
ARTIFACT_PREFIX = "feedback-"
REQUEST_ENV = "KD_FEEDBACK_REQUEST_B64"
RECIPIENT_ENV = "KD_FEEDBACK_RECIPIENT_SPKI_B64"
SETTINGS_SUFFIX = "-settings"
PREPARE_SUFFIX = "-prepare"
MAX_HISTORY_RUNS = 1000
MAX_JOBS = 16
MAX_ARTIFACT_AGE_SECONDS = 24 * 60 * 60
MAX_CAPACITY_NOTICES = 64
MAX_MARKER_BYTES = 16 * 1024
HISTORY_API_REASONS = ("status", "schema", "pagination", "unavailable")
HISTORY_FAILURE_PHASES = frozenset(
    "history_all_api_" + reason for reason in HISTORY_API_REASONS
) | frozenset((
    "history_duplicate_ids", "history_match_zero", "history_match_multiple",
    "history_identity_mismatch", "history_status_mismatch",
))
PRODUCER_TOKEN_FALLBACK_STEP = "Revoke token when producer did not confirm"
HEX64_RE = re.compile(r"[a-f0-9]{64}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
ACTOR_RE = re.compile(r"[A-Za-z0-9-]{1,39}\Z")
MARKER_TIME = rb"(?:[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z )?"
PRODUCER_MARKER = re.compile(rb"(?m)^" + MARKER_TIME + rb"KD-FEEDBACK-PRODUCER (\{[^\r\n]{1,16384}\})(?=\r?(?:\n|$))")
UPLOAD_MARKER = re.compile(
    rb"(?m)^" + MARKER_TIME
    + rb"KD-FEEDBACK-UPLOAD schema=1 request-id=([a-f0-9]{64}) "
    rb"artifact-id=([1-9][0-9]{0,18}) archive-digest=(?:sha256:)?([a-f0-9]{64})"
    rb"(?=\r?(?:\n|$))"
)
AUDIT_MARKER = re.compile(rb"(?m)^" + MARKER_TIME + rb"KD-FEEDBACK-AUDIT (\{[^\r\n]{1,16384}\})(?=\r?(?:\n|$))")
CACHE_SNAPSHOT_MARKER = re.compile(
    rb"(?m)^" + MARKER_TIME
    + rb"KD-FEEDBACK-CACHE-SNAPSHOT schema=1 control-sha=([a-f0-9]{40}) "
    rb"run-id=([1-9][0-9]{0,18}) run-attempt=1 digest=([a-f0-9]{64})"
    rb"(?=\r?(?:\n|$))"
)
CAPACITY_NOTICE = "Due to capacity constraints, jobs targeting macOS arm64 runners may experience longer queue times."
CAPACITY_NOTICE_PATH = ".github"
API_REPOSITORY = public_audit.REPOSITORY
RUN_FIELDS = frozenset((
    "id", "repository_id", "head_sha", "workflow_path", "workflow_ref", "event",
    "status", "conclusion", "actor_login", "run_attempt",
))
JOB_FIELDS = frozenset(("id", "name", "run_id", "run_attempt", "head_sha", "status", "conclusion"))
ARTIFACT_FIELDS = frozenset((
    "id", "name", "repository_id", "run_id", "head_sha", "digest", "size",
    "retention", "expires_at", "expired",
))
RAW_ARTIFACT_FIELDS = frozenset((
    "id", "node_id", "name", "size_in_bytes", "url", "archive_download_url",
    "expired", "created_at", "updated_at", "expires_at", "digest", "workflow_run",
))


class FeedbackAPIRefusal(Exception):
    """A bounded refusal with no provider payload or secret attached."""

    def __init__(self):
        self.reason = "feedback_api_invalid"
        super().__init__(self.reason)


class HistoryRefusal(FeedbackAPIRefusal):
    def __init__(self, diagnostic):
        super().__init__()
        self.diagnostic = (
            diagnostic if type(diagnostic) is str and diagnostic in HISTORY_FAILURE_PHASES
            else "history"
        )


def _refuse():
    raise FeedbackAPIRefusal()


def _exact_dict(value, fields):
    return type(value) is dict and set(value) == set(fields)


def _safe_int(value, minimum=0):
    return type(value) is int and minimum <= value <= node_lock_receipt.MAX_SAFE_INTEGER


def _iso_utc_epoch(value):
    if type(value) is not str or len(value) > 64 or not value.endswith("Z"):
        _refuse()
    try:
        parsed = datetime.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        _refuse()
    if parsed.tzinfo is None or parsed.utcoffset() != datetime.timedelta(0):
        _refuse()
    return int(parsed.timestamp())


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse()
        result[key] = value
    return result


def _one_json_marker(raw, pattern):
    if type(raw) is not bytes or len(raw) > public_audit.MAX_LOG_BYTES:
        _refuse()
    matches = list(pattern.finditer(raw))
    if len(matches) != 1:
        _refuse()
    encoded = matches[0].group(1)
    if len(encoded) > MAX_MARKER_BYTES:
        _refuse()
    try:
        value = json.loads(encoded.decode("ascii", "strict"), object_pairs_hook=_json_object)
        canonical = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    except (UnicodeError, ValueError, TypeError):
        _refuse()
    if type(value) is not dict or canonical != encoded:
        _refuse()
    return value


def _producer_success_summary_present(log, request, profile):
    if type(log) is not bytes or len(log) > public_audit.MAX_LOG_BYTES:
        return False
    expected = (
        "KD-FEEDBACK-PRODUCER-SUMMARY schema=1 request-id="
        + request["request_id"] + " profile=" + profile["kind"] + " status=encrypted"
    ).encode("ascii")
    prefix = b"KD-FEEDBACK-PRODUCER-SUMMARY "
    records = []
    for line in log.splitlines():
        if line.startswith(prefix):
            records.append(line)
        elif len(line) > 30 and line[4:5] == b"-" and b"Z " in line[:32]:
            marker = line.split(b"Z ", 1)
            if len(marker) == 2 and marker[1].startswith(prefix):
                records.append(marker[1])
    return len(records) == 1 and records[0] == expected


def _feedback_job_steps_success(detail, job_name, profile, request, log):
    """Accept successful job steps, including the producer's confirmed-token fallback skip."""
    producer_job = job_name == profile["producer_job"]
    summary_confirmed = producer_job and _producer_success_summary_present(log, request, profile)
    if producer_job and not summary_confirmed:
        return False
    if public_audit._validate_job_steps(detail):
        return True
    if not summary_confirmed:
        return False
    steps = detail.get("steps") if type(detail) is dict else None
    if type(steps) is not list:
        return False
    fallback_name_count = sum(
        step.get("name") == PRODUCER_TOKEN_FALLBACK_STEP
        for step in steps if type(step) is dict
    )
    skipped_fallback = 0
    for step in steps:
        if type(step) is not dict or step.get("status") != "completed":
            return False
        if step.get("conclusion") == "success":
            continue
        if (step.get("conclusion") == "skipped"
                and step.get("name") == PRODUCER_TOKEN_FALLBACK_STEP):
            skipped_fallback += 1
            continue
        return False
    return skipped_fallback == 1 and fallback_name_count == 1


def _check_run(api, request, profile, expected_actor_login, run_id, run_attempt):
    if (type(run_id) is not str or DECIMAL_RE.fullmatch(run_id) is None
            or type(run_attempt) is not int or run_attempt != 1
            or type(expected_actor_login) is not str or ACTOR_RE.fullmatch(expected_actor_login) is None):
        _refuse()
    run_path = "/repos/" + API_REPOSITORY + "/actions/runs/" + run_id
    run, unused_headers = api.json(run_path)
    actor = run.get("actor") if type(run) is dict else None
    repository = run.get("repository") if type(run) is dict else None
    if (type(actor) is not dict or type(repository) is not dict
            or not _safe_int(run.get("id"), 1) or str(run["id"]) != run_id
            or not _safe_int(run.get("run_attempt"), 1) or run["run_attempt"] != run_attempt
            or run.get("head_sha") != request["control_sha"]
            or run.get("path") != profile["workflow_path"]
            or run.get("head_branch") != "main"
            or run.get("event") != "workflow_dispatch"
            or run.get("status") != "completed" or run.get("conclusion") != "success"
            or run.get("display_title") != RUN_TITLE_PREFIX + request["request_id"]
            or actor.get("login") != expected_actor_login
            or not _safe_int(repository.get("id"), 1)
            or str(repository["id"]) != request["ci_repository_id"]
            or repository.get("full_name") != API_REPOSITORY
            or not _safe_int(run.get("workflow_id"), 1)):
        _refuse()
    workflow, unused_headers = api.json(
        "/repos/" + API_REPOSITORY + "/actions/workflows/" + str(run["workflow_id"]),
    )
    if (type(workflow) is not dict or workflow.get("id") != run["workflow_id"]
            or workflow.get("path") != profile["workflow_path"] or workflow.get("state") != "active"):
        _refuse()
    return run


def _validate_history_run(item, failure_phase):
    if (type(item) is not dict or not _safe_int(item.get("id"), 1)
            or not _safe_int(item.get("run_attempt"), 1)
            or type(item.get("display_title")) is not str or len(item["display_title"]) > 256
            or type(item.get("head_sha")) is not str
            or type(item.get("path")) is not str or type(item.get("event")) is not str
            or type(item.get("head_branch")) is not str or type(item.get("status")) is not str
            or type(item.get("conclusion")) not in (str, type(None))):
        raise HistoryRefusal(failure_phase)


class _HistoryCollectionAPI:
    def __init__(self, api):
        self.api = api
        self.seen_ids = set()

    def json(self, path):
        body, headers = self.api.json(path)
        items = body.get("workflow_runs") if type(body) is dict else None
        if type(items) is list and len(items) <= public_audit.PAGE_SIZE:
            for item in items:
                run_id = item.get("id") if type(item) is dict else None
                if type(run_id) is int and run_id > 0:
                    if run_id in self.seen_ids:
                        raise HistoryRefusal("history_duplicate_ids")
                    self.seen_ids.add(run_id)
        return body, headers


def _history(api, request, profile, run, expected_actor_login, now, *, live=False):
    lower = request["expiry"] - feedback_request.MAX_REQUEST_TTL_SECONDS
    lower_date = datetime.datetime.fromtimestamp(lower, datetime.timezone.utc).date().isoformat()
    upper_date = datetime.datetime.fromtimestamp(now, datetime.timezone.utc).date().isoformat()
    path = (
        "/repos/" + API_REPOSITORY + "/actions/workflows/"
        + str(run["workflow_id"]) + "/runs"
    )
    query = {
        "branch": "main",
        "created": lower_date + ".." + upper_date,
        "event": "workflow_dispatch",
        "head_sha": request["control_sha"],
    }

    def validate_history_item(item):
        _validate_history_run(item, "history_all_api_schema")

    try:
        items = public_audit._read_counted_collection(
            _HistoryCollectionAPI(api), path, "workflow_runs", MAX_HISTORY_RUNS, validate_history_item,
            fixed_query=query,
        )
    except HistoryRefusal:
        raise
    except public_audit.AuditRefusal as error:
        diagnostic = {
            "api_status": "status",
            "api_schema": "schema",
            "pagination_incomplete": "pagination",
            "api_unavailable": "unavailable",
        }.get(getattr(error, "reason", None), "unavailable")
        raise HistoryRefusal("history_all_api_" + diagnostic) from None
    except Exception:
        raise HistoryRefusal("history_all_api_unavailable") from None
    if len(items) >= MAX_HISTORY_RUNS:
        raise HistoryRefusal("history_all_api_pagination")
    matches = [
        item for item in items
        if item.get("display_title") == RUN_TITLE_PREFIX + request["request_id"]
    ]
    if not matches:
        raise HistoryRefusal("history_match_zero")
    if len(matches) != 1:
        raise HistoryRefusal("history_match_multiple")
    match = matches[0]
    if (match.get("id") != run["id"]
            or match.get("run_attempt") != 1
            or match.get("path") != profile["workflow_path"]
            or match.get("head_sha") != request["control_sha"]):
        raise HistoryRefusal("history_identity_mismatch")
    if (match.get("status") != ("in_progress" if live else "completed")
            or match.get("conclusion") != (None if live else "success")):
        raise HistoryRefusal("history_status_mismatch")
    return {"complete": True, "matches": [{
        "request_id": request["request_id"],
        "run_id": str(run["id"]),
        "run_attempt": 1,
    }]}


def _validate_capacity_notice(item, control_sha):
    expected = {
        "annotation_level": "notice",
        "blob_href": "https://github.com/" + API_REPOSITORY + "/blob/" + control_sha + "/.github",
        "end_column": None,
        "end_line": 1,
        "message": CAPACITY_NOTICE,
        "path": CAPACITY_NOTICE_PATH,
        "raw_details": "",
        "start_column": None,
        "start_line": 1,
        "title": "",
    }
    if item != expected:
        _refuse()


def _scan_check(api, detail, check_id, job_name, control_sha, *, allow_capacity_notice):
    check, unused_headers = api.json(
        "/repos/" + API_REPOSITORY + "/check-runs/" + str(check_id),
    )
    if (type(check) is not dict or check.get("id") != check_id
            or check.get("head_sha") != control_sha or check.get("status") != "completed"
            or check.get("conclusion") != detail.get("conclusion")):
        _refuse()
    output = check.get("output")
    if type(output) is not dict or not _safe_int(output.get("annotations_count"), 0):
        _refuse()
    if output["annotations_count"] > public_audit.MAX_ANNOTATIONS:
        _refuse()
    for name in ("title", "summary", "text"):
        value = output.get(name)
        if value is not None and (type(value) is not str or len(value) > 65536):
            _refuse()
    try:
        raw_output = json.dumps(output, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    except (TypeError, ValueError, UnicodeError):
        _refuse()
    if len(raw_output) > 262144:
        _refuse()
    public_audit.inspect_public_bytes(raw_output, control_sha)
    annotations = public_audit._read_annotations(
        api, "/repos/" + API_REPOSITORY + "/check-runs/" + str(check_id) + "/annotations",
    )
    if len(annotations) != output["annotations_count"]:
        _refuse()
    for annotation in annotations:
        _validate_capacity_notice(annotation, control_sha)
        raw = json.dumps(annotation, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
        if len(raw) > 65536:
            _refuse()
        public_audit.inspect_public_bytes(raw, control_sha)
    if annotations and (not allow_capacity_notice or len(annotations) > MAX_CAPACITY_NOTICES):
        _refuse()


def _normalize_jobs(api, run, profile, request):
    run_id = str(run["id"])
    attempt = str(run["run_attempt"])
    path = (
        "/repos/" + API_REPOSITORY + "/actions/runs/" + run_id
        + "/attempts/" + attempt + "/jobs"
    )
    jobs = public_audit._read_counted_collection(
        api, path, "jobs", MAX_JOBS, public_audit._validate_job_record,
    )
    expected = {
        profile["producer_job"] + SETTINGS_SUFFIX,
        profile["producer_job"] + PREPARE_SUFFIX,
        profile["producer_job"],
        profile["auditor_job"],
    }
    if len(jobs) != len(expected) or {job.get("name") for job in jobs} != expected:
        _refuse()
    normalized = []
    details_by_name = {}
    for job in jobs:
        detail, check_id, unused_steps_success = public_audit._job_detail(
            api, job, run_id, attempt, run["head_sha"], job["name"],
        )
        if detail.get("status") != "completed" or detail.get("conclusion") != "success":
            _refuse()
        _scan_check(
            api, detail, check_id, job["name"], run["head_sha"],
            allow_capacity_notice=(job["name"] == profile["producer_job"]
                                   or job["name"] == profile["producer_job"] + PREPARE_SUFFIX),
        )
        log = api.log_text(job["id"])
        public_audit.inspect_public_bytes(log, run["head_sha"])
        if not _feedback_job_steps_success(detail, job["name"], profile, request, log):
            _refuse()
        normalized.append({
            "id": job["id"], "name": job["name"], "run_id": job["run_id"],
            "run_attempt": job["run_attempt"], "head_sha": job["head_sha"],
            "status": job["status"], "conclusion": job.get("conclusion"),
        })
        details_by_name[job["name"]] = {"detail": detail, "check_id": check_id, "log": log}
    normalized.sort(key=lambda value: value["name"])
    return normalized, details_by_name


def _read_upload_marker(log, request):
    matches = list(UPLOAD_MARKER.finditer(log))
    if len(matches) != 1:
        _refuse()
    match = matches[0]
    if match.group(1).decode("ascii") != request["request_id"]:
        _refuse()
    return {
        "artifact_id": int(match.group(2)),
        "archive_digest": match.group(3).decode("ascii"),
    }


def _read_producer_marker(log, request, profile, run):
    record = _one_json_marker(log, PRODUCER_MARKER)
    context_fields = (
        node_lock_receipt.CONTEXT_FIELDS
        if profile["profile_id"] == 1 else node_lock_receipt.FEEDBACK_CONTEXT_FIELDS
    )
    expected_fields = set(context_fields) | {
        "schema_version", "status", "job_name", "member_name", "ciphertext_digest", "member_size",
    }
    if not _exact_dict(record, expected_fields):
        _refuse()
    expected_context = {name: request[name] for name in request if name in context_fields}
    expected_context.update({
        "run_id": str(run["id"]),
        "producer_job": profile["producer_job"],
        "run_attempt": 1,
    })
    if any(record.get(name) != value for name, value in expected_context.items()):
        _refuse()
    if (type(record.get("schema_version")) is not int or record["schema_version"] != 1
            or record.get("status") != "encrypted"
            or record.get("job_name") != profile["producer_job"]
            or record.get("member_name") != profile["member_name"]
            or type(record.get("member_size")) is not int
            or not 0 < record["member_size"] <= node_lock_receipt.MAX_MEMBER_BYTES
            or type(record.get("ciphertext_digest")) is not str
            or HEX64_RE.fullmatch(record["ciphertext_digest"]) is None):
        _refuse()
    return record


def _artifact_digest(value):
    if type(value) is not str:
        _refuse()
    digest = value.removeprefix("sha256:")
    if HEX64_RE.fullmatch(digest) is None:
        _refuse()
    return digest


def _download_archive(api, artifact_id):
    path = "/repos/" + API_REPOSITORY + "/actions/artifacts/" + str(artifact_id) + "/zip"
    request = urllib.request.Request(
        public_audit.API_ORIGIN + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + api._token,
            "X-GitHub-Api-Version": public_audit.API_VERSION,
            "User-Agent": "feedback-api-collector",
            "Accept-Encoding": "identity",
        },
        method="GET",
    )
    unused_data, headers = api._open(request, 1, allow_redirect=True)
    if unused_data is not None:
        _refuse()
    location = headers.get("Location")
    if type(location) is not str or len(location) > 8192:
        _refuse()
    public_audit._validate_log_location(location)
    blob_request = urllib.request.Request(
        location,
        headers={"Accept": "application/zip", "Accept-Encoding": "identity", "User-Agent": "feedback-api-collector"},
        method="GET",
    )
    archive, blob_headers = api._open(blob_request, node_lock_receipt.MAX_ARCHIVE_BYTES)
    if (blob_headers.get_content_type() not in ("application/zip", "application/octet-stream")
            or blob_headers.get("Content-Encoding", "identity").lower() != "identity"):
        _refuse()
    length = blob_headers.get("Content-Length")
    if (length is None or not length.isascii() or not length.isdecimal()
            or int(length) != len(archive)):
        _refuse()
    return archive


def _artifact_evidence(api, request, profile, run, producer_output, producer_record, now):
    path = "/repos/" + API_REPOSITORY + "/actions/runs/" + str(run["id"]) + "/artifacts"
    artifacts = public_audit._read_counted_collection(
        api, path, "artifacts", public_audit.MAX_ARTIFACT_ITEMS, public_audit._validate_artifact,
    )
    expected_name = ARTIFACT_PREFIX + profile["kind"] + "-" + request["request_id"]
    if len(artifacts) != 1:
        _refuse()
    artifact = artifacts[0]
    workflow_run = artifact.get("workflow_run")
    repository = run.get("repository") if type(run) is dict else None
    if type(repository) is not dict or not _safe_int(repository.get("id"), 1):
        _refuse()
    repository_id = repository["id"]
    if (not _exact_dict(artifact, RAW_ARTIFACT_FIELDS)
            or type(artifact.get("node_id")) is not str or len(artifact["node_id"]) > 128
            or type(artifact.get("url")) is not str or len(artifact["url"]) > 2048
            or type(artifact.get("archive_download_url")) is not str
            or len(artifact["archive_download_url"]) > 2048
            or type(artifact.get("updated_at")) is not str
            or not _exact_dict(workflow_run, {
                "id", "repository_id", "head_repository_id", "head_branch", "head_sha",
            })
            or workflow_run.get("id") != run["id"]
            or workflow_run.get("repository_id") != repository_id
            or workflow_run.get("head_repository_id") != repository_id
            or workflow_run.get("head_sha") != run["head_sha"]
            or workflow_run.get("head_branch") != "main"
            or artifact.get("name") != expected_name or artifact.get("expired") is not False
            or not _safe_int(artifact.get("id"), 1)
            or not _safe_int(artifact.get("size_in_bytes"), 1)
            or artifact["size_in_bytes"] > node_lock_receipt.MAX_ARCHIVE_BYTES):
        _refuse()
    public_audit._validate_api_url(
        artifact["url"],
        "/repos/" + API_REPOSITORY + "/actions/artifacts/" + str(artifact["id"]),
    )
    public_audit._validate_api_url(
        artifact["archive_download_url"],
        "/repos/" + API_REPOSITORY + "/actions/artifacts/" + str(artifact["id"]) + "/zip",
    )
    _iso_utc_epoch(artifact["updated_at"])
    created = _iso_utc_epoch(artifact.get("created_at"))
    expires = _iso_utc_epoch(artifact.get("expires_at"))
    duration = expires - created
    if (created > now or expires <= now or duration <= 0
            or duration > MAX_ARTIFACT_AGE_SECONDS
            or expires - now > MAX_ARTIFACT_AGE_SECONDS):
        _refuse()
    digest = _artifact_digest(artifact.get("digest"))
    if (producer_output["artifact_id"] != artifact["id"]
            or producer_output["archive_digest"] != digest):
        _refuse()
    archive = _download_archive(api, artifact["id"])
    if len(archive) != artifact["size_in_bytes"] or hashlib.sha256(archive).hexdigest() != digest:
        _refuse()
    member = node_lock_receipt.validate_ciphertext_archive(
        archive, member_name=profile["member_name"],
    )
    if (len(member) != producer_record["member_size"]
            or hashlib.sha256(member).hexdigest() != producer_record["ciphertext_digest"]):
        _refuse()
    normalized = {
        "id": artifact["id"],
        "name": artifact["name"],
        "repository_id": repository_id,
        "run_id": run["id"],
        "head_sha": run["head_sha"],
        "digest": digest,
        "size": artifact["size_in_bytes"],
        "retention": 1,
        "expires_at": expires,
        "expired": False,
    }
    return normalized, archive, member, expected_name, created


def _receipt_from_marker(log, expected, run, producer, artifact, producer_record):
    receipt = _one_json_marker(log, AUDIT_MARKER)
    if type(receipt) is not dict:
        _refuse()
    profile_id = expected.get("profile_id")
    fields = (
        node_lock_receipt.CONTEXT_FIELDS
        if profile_id == 1 else node_lock_receipt.FEEDBACK_CONTEXT_FIELDS
    )
    required = (
        node_lock_receipt.RECEIPT_COMMON_FIELDS
        | frozenset(fields)
        | node_lock_receipt.RECEIPT_EVIDENCE_FIELDS
    )
    if not _exact_dict(receipt, required):
        _refuse()
    expected_receipt = {name: expected[name] for name in fields}
    expected_receipt.update({
        "schema_version": 1,
        "status": "passed",
        "job_name": expected["producer_job"],
        "artifact_id": artifact["id"],
        "ciphertext_digest": producer_record["ciphertext_digest"],
        "archive_digest": artifact["digest"],
        "job_id": producer["id"],
        "size": artifact["size"],
        "retention": 1,
        "member_size": producer_record["member_size"],
        "archive_size": artifact["size"],
    })
    if any(receipt.get(key) != value for key, value in expected_receipt.items()):
        _refuse()
    return receipt


def collect_feedback_evidence(api, request, *, expected_actor_login, run_id, run_attempt, now):
    """Collect complete authenticated evidence for an already-completed feedback run."""
    try:
        profile = feedback_request.validate_request(request, now=now)
        if (not _safe_int(now, 1) or not isinstance(api, public_audit.GitHubAPI)
                or request["workflow_ref"] != feedback_request.WORKFLOW_REF):
            _refuse()
        run_record = _check_run(api, request, profile, expected_actor_login, run_id, run_attempt)
        history = _history(api, request, profile, run_record, expected_actor_login, now)
        normalized_jobs, job_details = _normalize_jobs(api, run_record, profile, request)
        producer_name = profile["producer_job"]
        audit_name = profile["auditor_job"]
        producer_job = next(job for job in normalized_jobs if job["name"] == producer_name)
        producer_log = job_details[producer_name]["log"]
        producer_record = _read_producer_marker(producer_log, request, profile, run_record)
        producer_output = _read_upload_marker(producer_log, request)
        audit_log = job_details[audit_name]["log"]
        normalized_artifact, archive, member, artifact_name, created = _artifact_evidence(
            api, request, profile, run_record, producer_output, producer_record, now,
        )
        run = {
            "id": run_record["id"],
            "repository_id": run_record["repository"]["id"],
            "head_sha": run_record["head_sha"],
            "workflow_path": run_record["path"],
            "workflow_ref": request["workflow_ref"],
            "event": run_record["event"],
            "status": run_record["status"],
            "conclusion": run_record["conclusion"],
            "actor_login": run_record["actor"]["login"],
            "run_attempt": run_record["run_attempt"],
        }
        receipt_expected = dict(request)
        receipt_expected.update({
            "profile_id": profile["profile_id"],
            "run_id": str(run_record["id"]),
            "producer_job": producer_name,
            "run_attempt": 1,
        })
        receipt = _receipt_from_marker(
            audit_log, receipt_expected, run, producer_job, normalized_artifact, producer_record,
        )
        api_evidence = {
            "run": run,
            "jobs": normalized_jobs,
            "artifacts": [normalized_artifact],
            "request_history": history,
        }
        node_lock_receipt.validate_receipt(
            request, receipt, api_evidence, producer_output, archive,
            ci_repository_id=int(request["ci_repository_id"]),
            actor_login=expected_actor_login,
            artifact_name=artifact_name,
            now=now,
        )
        return {
            "receipt": receipt,
            "api_evidence": api_evidence,
            "producer_output": producer_output,
            "archive_bytes": archive,
            "ci_repository_id": int(request["ci_repository_id"]),
            "actor_login": run_record["actor"]["login"],
            "artifact_name": artifact_name,
            "now": now,
        }
    except FeedbackAPIRefusal:
        raise
    except Exception:
        raise FeedbackAPIRefusal() from None
