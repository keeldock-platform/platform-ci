"""Protected feedback workflow preflight and live public-surface audit."""

import base64
import hashlib
import json
import os
import re
import sys
import stat
import time
import urllib.parse

try:
    from . import feedback_api
    from . import feedback_request
    from . import macos_public_audit as public_audit
    from . import node_lock_receipt
except ImportError:
    import feedback_api
    import feedback_request
    import macos_public_audit as public_audit
    import node_lock_receipt


MAX_REQUEST_ENCODED = 4096
MAX_RECORD_BYTES = 16384
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
HEX40_RE = re.compile(r"[a-f0-9]{40}\Z")
HEX64_RE = re.compile(r"[a-f0-9]{64}\Z")
ACTOR_RE = re.compile(r"[A-Za-z0-9-]{1,39}\Z")
CHECK_PATH_RE = re.compile(r"/repos/" + re.escape(public_audit.REPOSITORY)
                           + r"/check-runs/([1-9][0-9]{0,18})\Z")
CACHE_MARKER = feedback_api.CACHE_SNAPSHOT_MARKER
SETTINGS_PREFIX = b"KD-FEEDBACK-SETTINGS "
PREPARE_PREFIX = b"KD-FEEDBACK-PREPARE "
PRODUCER_SUMMARY_PREFIX = b"KD-FEEDBACK-PRODUCER-SUMMARY "
AUDIT_SUMMARY_PREFIX = b"KD-FEEDBACK-AUDIT-SUMMARY "


class FeedbackAuditRefusal(Exception):
    def __init__(self):
        self.reason = "feedback_audit_invalid"
        super().__init__(self.reason)


def _refuse():
    raise FeedbackAuditRefusal()


def _safe_int(value, minimum=0):
    return type(value) is int and minimum <= value <= feedback_request.MAX_SAFE_INTEGER


def _request_from_environment(environ, *, now):
    encoded = environ.get(feedback_api.REQUEST_ENV)
    if type(encoded) is not str or not encoded or len(encoded) > MAX_REQUEST_ENCODED:
        _refuse()
    try:
        raw = base64.b64decode(encoded.encode("ascii", "strict"), validate=True)
    except (UnicodeError, ValueError):
        _refuse()
    if (not raw or len(raw) > feedback_request.MAX_REQUEST_BYTES
            or base64.b64encode(raw).decode("ascii") != encoded):
        _refuse()
    try:
        request = feedback_request.parse_request(raw, now=now)
    except Exception:
        _refuse()
    return request, feedback_request.validate_request(request, now=now)


def _validate_identity(environ, request, profile, *, job_name):
    control = environ.get("CI_SHA", "")
    run_id = environ.get("GITHUB_RUN_ID", "")
    attempt = environ.get("GITHUB_RUN_ATTEMPT", "")
    actor = environ.get("GITHUB_ACTOR", "")
    if (environ.get("CI_REPOSITORY") != public_audit.REPOSITORY
            or environ.get("CI_SERVER_URL") != "https://github.com"
            or environ.get("CI_REF") != "refs/heads/main"
            or environ.get("CI_EVENT_NAME") != "workflow_dispatch"
            or environ.get("GITHUB_REPOSITORY") != public_audit.REPOSITORY
            or environ.get("GITHUB_REF") != "refs/heads/main"
            or environ.get("GITHUB_SHA") != control
            or environ.get("GITHUB_WORKFLOW_REF") != public_audit.REPOSITORY + "/"
                + profile["workflow_path"] + "@refs/heads/main"
            or environ.get("KD_FEEDBACK_REQUEST_ID") != request["request_id"]
            or environ.get("GITHUB_JOB") != job_name
            or not HEX40_RE.fullmatch(control)
            or request["control_sha"] != control
            or not DECIMAL_RE.fullmatch(run_id)
            or not _safe_int(int(run_id), 1)
            or attempt != "1"
            or not ACTOR_RE.fullmatch(actor)
            or environ.get("GITHUB_REPOSITORY_ID") != request["ci_repository_id"]):
        _refuse()
    return control, run_id, actor


def _validate_protected_binding(environ, request, *, require_candidate=True):
    source = environ.get("CORE_CONTRACT_REVIEWED_SOURCE_SHA", "")
    base = environ.get("CORE_CONTRACT_REVIEWED_BASE_SHA", "")
    branch = environ.get("CORE_CONTRACT_REVIEWED_BASE_BRANCH", "")
    diff = environ.get("CORE_CONTRACT_REVIEWED_DIFF_SHA256", "")
    candidate = environ.get("CORE_CONTRACT_REVIEWED_CANDIDATE_REF", "")
    if (environ.get("CORE_CONTRACT_ALLOWED_SHA") != request["source_sha"]
            or environ.get("CORE_CONTRACT_ALLOWED_CONTROL_SHA") != request["control_sha"]
            or source != request["source_sha"] or base != request["base_sha"]
            or branch != request["base_branch"] or diff != request["reviewed_diff_sha256"]
            or not HEX40_RE.fullmatch(source) or not HEX40_RE.fullmatch(base)
            or not HEX64_RE.fullmatch(diff)):
        _refuse()
    if require_candidate:
        if (type(candidate) is not str or len(candidate) > 160
                or not candidate.startswith("refs/heads/")):
            _refuse()
        if source == base:
            if candidate != "refs/heads/" + branch:
                _refuse()
        elif re.fullmatch(r"refs/heads/(?:feat|fix|chore|plan)/[A-Za-z0-9][A-Za-z0-9._/-]{0,126}", candidate) is None:
            _refuse()
    if environ.get("SOURCE_REPOSITORY_ID") != request["repository_id"]:
        _refuse()


def _decode_recipient(environ, request):
    encoded = environ.get(feedback_api.RECIPIENT_ENV)
    if type(encoded) is not str or not encoded or len(encoded) > 8192:
        _refuse()
    try:
        decoded = base64.b64decode(encoded.encode("ascii", "strict"), validate=True)
    except (UnicodeError, ValueError):
        _refuse()
    if (not decoded or len(decoded) > 4096
            or base64.b64encode(decoded).decode("ascii") != encoded
            or hashlib.sha256(decoded).hexdigest() != request["recipient_fingerprint"]):
        _refuse()


def _write_outputs(environ, values):
    path = environ.get("GITHUB_OUTPUT", "")
    if type(path) is not str or not path.startswith(os.sep) or len(path) > 4096:
        _refuse()
    allowed = {"cache_snapshot", "request_id", "source_sha", "base_sha", "base_branch", "kind"}
    if type(values) is not dict or not set(values).issubset(allowed):
        _refuse()
    payload = "".join(name + "=" + str(value) + "\n" for name, value in values.items()).encode("ascii")
    if len(payload) > 4096:
        _refuse()
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        _refuse()
    descriptor = None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | nofollow)
        info = os.fstat(descriptor)
        named = os.lstat(path)
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(named.st_mode)
                or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)
                or info.st_uid != os.geteuid() or info.st_size >= 1024 * 1024):
            _refuse()
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                _refuse()
            written += count
    except FeedbackAuditRefusal:
        raise
    except BaseException:
        _refuse()
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _snapshot_cache(api, control_sha):
    entries = public_audit._fetch_cache_entries(api, control_sha, reviewed=True)
    return public_audit.cache_inventory_digest(entries)


def settings(environ=None, api_factory=None, *, now=None):
    env = os.environ if environ is None else environ
    current = int(time.time()) if now is None else now
    request, profile = _request_from_environment(env, now=current)
    _validate_identity(env, request, profile, job_name=profile["producer_job"] + "-settings")
    _decode_recipient(env, request)
    token = env.get("GITHUB_TOKEN", "")
    factory = public_audit.GitHubAPI if api_factory is None else api_factory
    api = factory(token)
    digest = _snapshot_cache(api, request["control_sha"])
    _write_outputs(env, {
        "cache_snapshot": digest,
        "request_id": request["request_id"],
        "source_sha": request["source_sha"],
        "base_sha": request["base_sha"],
        "base_branch": request["base_branch"],
        "kind": profile["kind"],
    })
    return ("KD-FEEDBACK-CACHE-SNAPSHOT schema=1 control-sha=" + request["control_sha"]
            + " run-id=" + env["GITHUB_RUN_ID"] + " run-attempt=1 digest=" + digest)


def producer_preflight(environ=None, *, now=None):
    """Bind the public request to protected review values before token minting."""
    env = os.environ if environ is None else environ
    current = int(time.time()) if now is None else now
    request, profile = _request_from_environment(env, now=current)
    _validate_identity(env, request, profile, job_name=profile["producer_job"])
    _validate_protected_binding(env, request, require_candidate=True)
    _decode_recipient(env, request)
    if (env.get("REQUESTED_SOURCE_SHA") != request["source_sha"]
            or env.get("REQUESTED_BASE_SHA") != request["base_sha"]
            or env.get("REQUESTED_BASE_BRANCH") != request["base_branch"]):
        _refuse()
    return ("KD-FEEDBACK-BINDING schema=1 request-id=" + request["request_id"]
            + " profile=" + profile["kind"] + " status=verified")


def prepare(environ=None, *, now=None):
    env = os.environ if environ is None else environ
    current = int(time.time()) if now is None else now
    request, profile = _request_from_environment(env, now=current)
    _validate_identity(env, request, profile, job_name=profile["producer_job"] + "-prepare")
    _decode_recipient(env, request)
    if (env.get("RUNNER_OS") != "macOS" or not env.get("ImageOS")
            or not env.get("ImageVersion")):
        _refuse()
    return ("KD-FEEDBACK-PREPARE schema=1 request-id=" + request["request_id"]
            + " profile=" + profile["kind"] + " status=passed")


def _history_for_live_run(api, request, profile, run, actor, now):
    try:
        history = feedback_api._history(api, request, profile, run, actor, now, live=True)
    except Exception:
        _refuse()
    return history


def _check_surface(api, job, run, *, live_auditor=False, allow_capacity=False):
    valid = True
    check_url = job.get("check_run_url")
    try:
        path = urllib.parse.urlsplit(check_url).path
    except Exception:
        path = ""
        valid = False
    match = CHECK_PATH_RE.fullmatch(path)
    if match is None:
        return False, None
    check_id = int(match.group(1))
    try:
        public_audit._validate_api_url(check_url, path)
        check, unused_headers = api.json(path)
    except Exception:
        return False, check_id
    expected_status = "in_progress" if live_auditor else "completed"
    expected_conclusion = None if live_auditor else job.get("conclusion")
    if (type(check) is not dict or check.get("id") != check_id
            or check.get("head_sha") != run["head_sha"]
            or check.get("status") != expected_status
            or check.get("conclusion") != expected_conclusion):
        valid = False
    output = check.get("output") if type(check) is dict else None
    if type(output) is not dict or type(output.get("annotations_count")) is not int:
        return False, check_id
    count = output["annotations_count"]
    if count < 0 or count > feedback_api.MAX_CAPACITY_NOTICES:
        valid = False
    try:
        encoded = json.dumps(output, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        if len(encoded) > 262144:
            valid = False
        public_audit.inspect_public_bytes(encoded, run["head_sha"])
        annotations = public_audit._read_annotations(
            api, "/repos/" + public_audit.REPOSITORY + "/check-runs/" + str(check_id) + "/annotations",
        )
    except Exception:
        return False, check_id
    if len(annotations) != count:
        valid = False
    for annotation in annotations:
        try:
            feedback_api._validate_capacity_notice(annotation, run["head_sha"])
            raw = json.dumps(annotation, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            if len(raw) > 65536:
                valid = False
            public_audit.inspect_public_bytes(raw, run["head_sha"])
        except Exception:
            valid = False
    if annotations and (not allow_capacity or len(annotations) > feedback_api.MAX_CAPACITY_NOTICES):
        valid = False
    if live_auditor and annotations:
        valid = False
    return valid, check_id


def _summary_line(log, expected):
    prefix = expected.split(b" ", 1)[0] + b" "
    matches = []
    for line in log.splitlines():
        if line.startswith(prefix):
            matches.append(line)
        elif len(line) > 30 and line[4:5] == b"-" and b"Z " in line[:32]:
            marker = line.split(b"Z ", 1)
            if len(marker) == 2 and marker[1].startswith(prefix):
                matches.append(marker[1])
    return len(matches) == 1 and matches[0] == expected


def _read_cache_snapshot(log, control_sha, run_id):
    matches = list(CACHE_MARKER.finditer(log))
    if (len(matches) != 1 or log.count(b"KD-FEEDBACK-CACHE-SNAPSHOT ") != 1
            or matches[0].group(1).decode("ascii") != control_sha
            or matches[0].group(2).decode("ascii") != run_id):
        _refuse()
    return matches[0].group(3).decode("ascii")


def audit_live(environ=None, api_factory=None, *, now=None):
    env = os.environ if environ is None else environ
    current = int(time.time()) if now is None else now
    request, profile = _request_from_environment(env, now=current)
    control_sha, run_id, actor = _validate_identity(
        env, request, profile, job_name=profile["auditor_job"],
    )
    run_path = "/repos/" + public_audit.REPOSITORY + "/actions/runs/" + run_id
    factory = public_audit.GitHubAPI if api_factory is None else api_factory
    api = factory(env.get("GITHUB_TOKEN", ""))
    try:
        run, unused_headers = api.json(run_path)
        if (type(run) is not dict or run.get("id") != int(run_id)
                or run.get("run_attempt") != 1 or run.get("head_sha") != control_sha
                or run.get("path") != profile["workflow_path"]
                or run.get("head_branch") != "main" or run.get("event") != "workflow_dispatch"
                or run.get("status") != "in_progress" or run.get("conclusion") is not None
                or run.get("display_title") != feedback_api.RUN_TITLE_PREFIX + request["request_id"]
                or type(run.get("actor")) is not dict or run["actor"].get("login") != actor
                or type(run.get("repository")) is not dict
                or str(run["repository"].get("id")) != request["ci_repository_id"]
                or run["repository"].get("full_name") != public_audit.REPOSITORY
                or not _safe_int(run.get("workflow_id"), 1)):
            _refuse()
        workflow, unused_headers = api.json(
            "/repos/" + public_audit.REPOSITORY + "/actions/workflows/" + str(run["workflow_id"]),
        )
        if (type(workflow) is not dict or workflow.get("id") != run["workflow_id"]
                or workflow.get("path") != profile["workflow_path"] or workflow.get("state") != "active"):
            _refuse()
        _history_for_live_run(api, request, profile, run, actor, current)
        jobs_path = ("/repos/" + public_audit.REPOSITORY + "/actions/runs/" + run_id
                     + "/attempts/1/jobs")
        jobs = public_audit._read_counted_collection(
            api, jobs_path, "jobs", feedback_api.MAX_JOBS, public_audit._validate_job_record,
        )
    except FeedbackAuditRefusal:
        raise
    except BaseException:
        _refuse()

    expected_names = {
        profile["producer_job"] + feedback_api.SETTINGS_SUFFIX,
        profile["producer_job"] + feedback_api.PREPARE_SUFFIX,
        profile["producer_job"],
        profile["auditor_job"],
    }
    by_name = {}
    surfaces_ok = len(jobs) == len(expected_names)
    for job in jobs:
        name = job.get("name") if type(job) is dict else None
        if type(name) is not str or name in by_name:
            surfaces_ok = False
            continue
        by_name[name] = job
        if (job.get("run_id") != int(run_id) or job.get("run_attempt") != 1
                or job.get("head_sha") != control_sha):
            surfaces_ok = False
    if set(by_name) != expected_names:
        surfaces_ok = False

    logs = {}
    details = {}
    for name, job in by_name.items():
        own_auditor = name == profile["auditor_job"]
        if own_auditor:
            if job.get("status") != "in_progress" or job.get("conclusion") is not None:
                surfaces_ok = False
            check_ok, unused_id = _check_surface(api, job, run, live_auditor=True)
            surfaces_ok = surfaces_ok and check_ok
            continue
        if job.get("status") != "completed":
            surfaces_ok = False
        detail = None
        check_id = None
        steps_success = False
        try:
            detail, check_id, steps_success = public_audit._job_detail(
                api, job, run_id, "1", control_sha, name,
            )
        except Exception:
            surfaces_ok = False
        check_ok, checked_id = _check_surface(
            api, job, run,
            allow_capacity=(name == profile["producer_job"]
                            or name == profile["producer_job"] + feedback_api.PREPARE_SUFFIX),
        )
        check_id = checked_id if checked_id is not None else check_id
        if not check_ok:
            surfaces_ok = False
        if detail is not None:
            if detail.get("conclusion") != "success" or not steps_success:
                surfaces_ok = False
            details[name] = detail
        try:
            log = api.log_text(job["id"])
            public_audit.inspect_public_bytes(log, control_sha)
            logs[name] = log
        except Exception:
            surfaces_ok = False
            logs[name] = b""

    expected_artifact_name = "feedback-" + profile["kind"] + "-" + request["request_id"]
    artifact_records = []
    scanned_archive = None
    scanned_member = None
    try:
        artifact_records = public_audit._read_counted_collection(
            api,
            "/repos/" + public_audit.REPOSITORY + "/actions/runs/" + run_id + "/artifacts",
            "artifacts", public_audit.MAX_ARTIFACT_ITEMS, public_audit._validate_artifact,
        )
        for item in artifact_records:
            raw = json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            if len(raw) > 65536:
                surfaces_ok = False
            public_audit.inspect_public_bytes(raw, control_sha)
        if len(artifact_records) == 1:
            artifact_record = artifact_records[0]
            if (type(artifact_record.get("id")) is int
                    and artifact_record.get("name") == expected_artifact_name
                    and artifact_record.get("expired") is False
                    and 0 < artifact_record.get("size_in_bytes", 0) <= node_lock_receipt.MAX_ARCHIVE_BYTES):
                scanned_archive = feedback_api._download_archive(api, artifact_record["id"])
                digest = feedback_api._artifact_digest(artifact_record.get("digest"))
                if (len(scanned_archive) != artifact_record["size_in_bytes"]
                        or hashlib.sha256(scanned_archive).hexdigest() != digest):
                    surfaces_ok = False
                scanned_member = node_lock_receipt.validate_ciphertext_archive(
                    scanned_archive, member_name=profile["member_name"],
                )
            else:
                surfaces_ok = False
        else:
            surfaces_ok = False
    except Exception:
        surfaces_ok = False

    cache_digest = None
    try:
        cache_digest = _snapshot_cache(api, control_sha)
    except Exception:
        surfaces_ok = False
    settings_name = profile["producer_job"] + feedback_api.SETTINGS_SUFFIX
    prepare_name = profile["producer_job"] + feedback_api.PREPARE_SUFFIX
    producer_name = profile["producer_job"]
    try:
        baseline = _read_cache_snapshot(logs[settings_name], control_sha, run_id)
        if cache_digest != baseline:
            surfaces_ok = False
        expected_settings = (SETTINGS_PREFIX + b"schema=1 request-id="
                             + request["request_id"].encode("ascii") + b" profile="
                             + profile["kind"].encode("ascii") + b" status=verified")
        expected_prepare = (PREPARE_PREFIX + b"schema=1 request-id="
                            + request["request_id"].encode("ascii") + b" profile="
                            + profile["kind"].encode("ascii") + b" status=passed")
        expected_producer = (PRODUCER_SUMMARY_PREFIX + b"schema=1 request-id="
                             + request["request_id"].encode("ascii") + b" profile="
                             + profile["kind"].encode("ascii") + b" status=encrypted")
        if not _summary_line(logs[settings_name], expected_settings):
            surfaces_ok = False
        if not _summary_line(logs[prepare_name], expected_prepare):
            surfaces_ok = False
        if not _summary_line(logs[producer_name], expected_producer):
            surfaces_ok = False
    except (KeyError, Exception):
        surfaces_ok = False

    producer_record = None
    producer_output = None
    producer_job = next((job for job in jobs if job.get("name") == producer_name), None)
    artifact = None
    archive = None
    artifact_name = expected_artifact_name
    try:
        if producer_job is None or len(artifact_records) != 1:
            raise FeedbackAPIRefusal()
        producer_record = feedback_api._read_producer_marker(
            logs[producer_name], request, profile, run,
        )
        producer_output = feedback_api._read_upload_marker(logs[producer_name], request)
        artifact, archive, unused_member, artifact_name, unused_created = feedback_api._artifact_evidence(
            api, request, profile, run, producer_output, producer_record, current,
        )
    except Exception:
        surfaces_ok = False

    if scanned_archive is None or scanned_member is None:
        surfaces_ok = False
    if not surfaces_ok:
        _refuse()
    context_fields = (
        node_lock_receipt.CONTEXT_FIELDS
        if profile["profile_id"] == 1 else node_lock_receipt.FEEDBACK_CONTEXT_FIELDS
    )
    receipt = {name: request[name] for name in context_fields if name in request}
    receipt.update({
        "run_id": run_id,
        "producer_job": profile["producer_job"],
        "run_attempt": 1,
        "schema_version": 1,
        "status": "passed",
        "job_name": profile["producer_job"],
        "artifact_id": artifact["id"],
        "ciphertext_digest": producer_record["ciphertext_digest"],
        "archive_digest": artifact["digest"],
        "job_id": producer_job["id"],
        "size": artifact["size"],
        "retention": 1,
        "member_size": producer_record["member_size"],
        "archive_size": artifact["size"],
    })
    encoded = json.dumps(receipt, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    if len(encoded) > MAX_RECORD_BYTES:
        _refuse()
    return "KD-FEEDBACK-AUDIT " + encoded.decode("ascii")


def main(arguments=None, environ=None):
    args = sys.argv[1:] if arguments is None else arguments
    env = os.environ if environ is None else environ
    if type(args) not in (tuple, list) or len(args) != 1 or args[0] not in {"settings", "preflight", "prepare", "audit"}:
        print("KD-FEEDBACK-AUDIT-REFUSAL {\"reason\":\"invalid_input\",\"schema_version\":1}")
        return 2
    try:
        if args[0] == "settings":
            line = settings(env)
        elif args[0] == "preflight":
            line = producer_preflight(env)
        elif args[0] == "prepare":
            line = prepare(env)
        else:
            line = audit_live(env)
        if not line.startswith("KD-FEEDBACK-") or len(line.encode("ascii")) > MAX_RECORD_BYTES:
            _refuse()
        print(line)
        return 0
    except FeedbackAuditRefusal:
        print("KD-FEEDBACK-AUDIT-REFUSAL {\"reason\":\"feedback_audit_invalid\",\"schema_version\":1}")
        return 2
    except BaseException:
        print("KD-FEEDBACK-AUDIT-REFUSAL {\"reason\":\"feedback_audit_invalid\",\"schema_version\":1}")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
