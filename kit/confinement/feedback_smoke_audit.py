"""Bounded, read-only audit of the public encrypted-feedback smoke artifact."""

import hashlib
import os
import re
import sys
import time
from datetime import datetime, timedelta, timezone
import urllib.parse
import urllib.request

from macos_public_audit import (
    API_ORIGIN,
    AuditRefusal,
    GitHubAPI,
    _read_annotations,
    _validate_log_location,
)
from node_lock_receipt import MAX_ARCHIVE_BYTES, ZIP_MEMBER, validate_ciphertext_archive


REPOSITORY = "keeldock-platform/platform-ci"
WORKFLOW_PATH = ".github/workflows/development-feedback-smoke.yml"
PRODUCER_PREFIX = "feedback-smoke-producer "
RUNNERS = ("ubuntu-24.04", "macos-15", "windows-2025")
AUDITOR_JOB = "feedback-smoke-audit"
ARTIFACT_PREFIX = "development-feedback-smoke-"
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_SUMMARY_BYTES = 16 * 1024
MAX_LOG_BYTES = 32 * 1024 * 1024
MAX_MACOS_CAPACITY_NOTICES = 64
CANARY = b"feedback-smoke-canary-7c49b2"
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
SHA40_RE = re.compile(r"[a-f0-9]{40}\Z")
REF_RE = re.compile(r"refs/heads/[A-Za-z0-9._/-]{1,200}\Z")
TIMESTAMP = rb"(?:[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z )?"
CIPHERTEXT_MARKER = re.compile(
    rb"(?m)^" + TIMESTAMP
    + rb"KD-FEEDBACK-CIPHERTEXT schema=1 control-sha=([a-f0-9]{40}) "
    rb"run-id=([1-9][0-9]{0,18}) run-attempt=1 member=lock-return-v1\.enc "
    rb"ciphertext-sha256=([a-f0-9]{64}) ciphertext-size=([1-9][0-9]{0,6}) "
    rb"roundtrip=passed source=synthetic(?=\r?(?:\n|$))"
)
UPLOAD_MARKER = re.compile(
    rb"(?m)^" + TIMESTAMP
    + rb"KD-FEEDBACK-UPLOAD schema=1 control-sha=([a-f0-9]{40}) "
    rb"run-id=([1-9][0-9]{0,18}) run-attempt=1 artifact-id=([1-9][0-9]{0,18}) "
    rb"artifact-digest=([a-f0-9]{64}) artifact-name=(development-feedback-smoke-[1-9][0-9]{0,18}-1) "
    rb"ciphertext-sha256=([a-f0-9]{64}) ciphertext-size=([1-9][0-9]{0,6})(?=\r?(?:\n|$))"
)
MARKER_LINE_PREFIX = re.compile(
    rb"(?m)^(?:[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?Z )?"
    rb"(KD-FEEDBACK-(?:CIPHERTEXT|UPLOAD) )"
)
API_TIME = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z")
def _macos_capacity_notice(control_sha):
    return {
        "annotation_level": "notice",
        "blob_href": f"https://github.com/{REPOSITORY}/blob/{control_sha}/.github",
        "end_column": None,
        "end_line": 1,
        "message": "Due to capacity constraints, jobs targeting macOS arm64 runners may experience longer queue times.",
        "path": ".github",
        "raw_details": "",
        "start_column": None,
        "start_line": 1,
        "title": "",
    }


READINESS_ATTEMPTS = 6
READINESS_INTERVAL_SECONDS = 10
READINESS_MAX_SECONDS = 60
DETAIL_STAGES = frozenset(
    ("run", "jobs", "upload_marker", "artifact")
    + tuple(
        stage + ":" + runner
        for stage in ("check_run", "annotations", "log_fetch", "log_markers")
        for runner in RUNNERS
    )
)


class SmokeAuditRefusal(Exception):
    def __init__(self, reason, detail=None):
        self.reason = reason if reason in {
            "invalid_input", "api_unavailable", "api_status", "api_schema",
            "producer_failed", "summary_invalid", "artifact_invalid", "archive_invalid",
        } else "internal_error"
        self.detail = detail if detail in DETAIL_STAGES else None
        super().__init__(self.reason)


def _fail(reason):
    raise SmokeAuditRefusal(reason)


def _exact_int(value, minimum=0):
    return type(value) is int and minimum <= value <= MAX_SAFE_INTEGER


def _positive_decimal(value):
    return (
        type(value) is str and DECIMAL_RE.fullmatch(value) is not None
        and int(value) <= MAX_SAFE_INTEGER
    )


def _parse_marker(raw, pattern, prefix, reason):
    if type(raw) is not bytes or len(raw) > MAX_LOG_BYTES or CANARY in raw:
        _fail(reason)
    matches = list(pattern.finditer(raw))
    prefixes = [match for match in MARKER_LINE_PREFIX.finditer(raw) if match.group(1) == prefix]
    if len(matches) != 1 or len(prefixes) != 1:
        _fail(reason)
    return matches[0]


def parse_ciphertext_marker(raw):
    match = _parse_marker(raw, CIPHERTEXT_MARKER, b"KD-FEEDBACK-CIPHERTEXT ", "summary_invalid")
    sha, run_id, digest, size = match.groups()
    if int(run_id) > MAX_SAFE_INTEGER or int(size) > MAX_ARCHIVE_BYTES:
        _fail("summary_invalid")
    return {
        "control_sha": sha.decode("ascii"),
        "run_id": run_id.decode("ascii"),
        "ciphertext_sha256": digest.decode("ascii"),
        "ciphertext_size": int(size),
        "member": ZIP_MEMBER,
    }


def parse_upload_marker(raw):
    match = _parse_marker(raw, UPLOAD_MARKER, b"KD-FEEDBACK-UPLOAD ", "summary_invalid")
    control_sha, run_id, artifact_id, digest, name, ciphertext_sha, ciphertext_size = match.groups()
    if (int(run_id) > MAX_SAFE_INTEGER or int(artifact_id) > MAX_SAFE_INTEGER
            or int(ciphertext_size) > MAX_ARCHIVE_BYTES):
        _fail("summary_invalid")
    return {
        "control_sha": control_sha.decode("ascii"),
        "run_id": run_id.decode("ascii"),
        "artifact_id": int(artifact_id),
        "archive_sha256": digest.decode("ascii"),
        "artifact_name": name.decode("ascii"),
        "ciphertext_sha256": ciphertext_sha.decode("ascii"),
        "ciphertext_size": int(ciphertext_size),
    }


def _clean_ref(value):
    if (type(value) is not str or REF_RE.fullmatch(value) is None
            or ".." in value or "//" in value or value.endswith(("/", "."))):
        _fail("invalid_input")
    return value


def _validate_environment(env):
    if type(env) is not dict and not hasattr(env, "get"):
        _fail("invalid_input")
    repo = env.get("CI_REPOSITORY")
    ref = _clean_ref(env.get("CI_REF"))
    sha = env.get("CI_SHA")
    event = env.get("CI_EVENT_NAME")
    run_id = env.get("GITHUB_RUN_ID")
    attempt = env.get("GITHUB_RUN_ATTEMPT")
    repo_id = env.get("GITHUB_REPOSITORY_ID")
    if (repo != REPOSITORY or env.get("CI_SERVER_URL") != "https://github.com"
            or event not in ("push", "workflow_dispatch")
            or type(sha) is not str or SHA40_RE.fullmatch(sha) is None
            or not _positive_decimal(run_id) or not _positive_decimal(repo_id)
            or attempt != "1"):
        _fail("invalid_input")
    if env.get("GITHUB_WORKFLOW") not in (None, "development-feedback-smoke"):
        _fail("invalid_input")
    return {
        "repository": repo,
        "ref": ref,
        "sha": sha,
        "event": event,
        "run_id": run_id,
        "repository_id": int(repo_id),
    }


def _validate_run(api, identity):
    path = f"/repos/{REPOSITORY}/actions/runs/{identity['run_id']}"
    try:
        value, _ = api.json(path)
    except Exception:
        return False
    repo = value.get("repository") if type(value) is dict else None
    head_repo = value.get("head_repository") if type(value) is dict else None
    if (type(value) is not dict or not _exact_int(value.get("id"), 1)
            or str(value["id"]) != identity["run_id"]
            or value.get("path") != WORKFLOW_PATH
            or value.get("head_branch") != identity["ref"].removeprefix("refs/heads/")
            or value.get("head_sha") != identity["sha"]
            or value.get("event") != identity["event"]
            or type(value.get("run_attempt")) is not int or value.get("run_attempt") != 1
            or value.get("status") != "in_progress" or value.get("conclusion") is not None
            or type(repo) is not dict or type(repo.get("id")) is not int
            or repo.get("full_name") != REPOSITORY
            or repo.get("id") != identity["repository_id"]
            or type(head_repo) is not dict or type(head_repo.get("id")) is not int
            or head_repo.get("full_name") != REPOSITORY
            or head_repo.get("id") != identity["repository_id"]):
        return False
    return True


def _validate_jobs(api, identity):
    path = f"/repos/{REPOSITORY}/actions/runs/{identity['run_id']}/jobs?filter=all&per_page=100&page=1"
    try:
        value, headers = api.json(path)
    except Exception:
        return {runner: [] for runner in RUNNERS}, False
    if type(value) is not dict or type(value.get("jobs")) is not list:
        return {runner: [] for runner in RUNNERS}, False
    valid = (value.get("total_count") == 4 and len(value["jobs"]) == 4
             and not headers.get("Link") and len(value["jobs"]) <= 100)
    by_name = {runner: [] for runner in RUNNERS}
    audit_jobs = []
    seen_ids = set()
    for job in value["jobs"][:100]:
        if type(job) is not dict or type(job.get("name")) is not str:
            valid = False
            continue
        if job["name"] == AUDITOR_JOB:
            audit_jobs.append(job)
            audit_id = job.get("id")
            if not _exact_int(audit_id, 1) or audit_id in seen_ids:
                valid = False
            else:
                seen_ids.add(audit_id)
            if (type(job.get("run_id")) is not int
                    or job.get("run_id") != int(identity["run_id"])
                    or type(job.get("run_attempt")) is not int or job.get("run_attempt") != 1
                    or job.get("head_sha") != identity["sha"]
                    or type(job.get("status")) is not str):
                valid = False
            continue
        if not job["name"].startswith(PRODUCER_PREFIX):
            valid = False
            continue
        runner = job["name"][len(PRODUCER_PREFIX):]
        if runner not in RUNNERS:
            valid = False
            continue
        if (not _exact_int(job.get("id"), 1) or job["id"] in seen_ids):
            valid = False
            continue
        seen_ids.add(job["id"])
        by_name[runner].append(job)
        if (type(job.get("run_id")) is not int or job.get("run_id") != int(identity["run_id"])
                or type(job.get("run_attempt")) is not int or job.get("run_attempt") != 1
                or job.get("head_sha") != identity["sha"]
                or type(job.get("status")) is not str):
            valid = False
        if job.get("status") != "completed" or job.get("conclusion") != "success":
            valid = False
    for runner in RUNNERS:
        if len(by_name[runner]) != 1:
            valid = False
    if (len(audit_jobs) != 1 or audit_jobs[0].get("status") != "in_progress"
            or audit_jobs[0].get("conclusion") is not None):
        valid = False
    return by_name, valid


def _check_id(url):
    if type(url) is not str or len(url) > 512:
        _fail("api_schema")
    try:
        parsed = urllib.parse.urlsplit(url)
        check_id = re.fullmatch(
            r"/repos/keeldock-platform/platform-ci/check-runs/([1-9][0-9]{0,18})",
            parsed.path,
        )
    except Exception:
        _fail("api_schema")
    if (parsed.scheme != "https" or parsed.netloc != "api.github.com"
            or parsed.query or parsed.fragment or check_id is None
            or int(check_id.group(1)) > MAX_SAFE_INTEGER):
        _fail("api_schema")
    return int(check_id.group(1))


def _note(stages, token):
    if stages is not None:
        stages.append(token)


def _audit_check(api, job, identity, runner, stages=None):
    valid = True
    try:
        check_id = _check_id(job.get("check_run_url"))
    except Exception:
        check_id = None
        valid = False
        _note(stages, "check_run:" + runner)
    output = None
    if check_id is not None:
        try:
            value, _ = api.json(f"/repos/{REPOSITORY}/check-runs/{check_id}")
        except Exception:
            value = None
            valid = False
            _note(stages, "check_run:" + runner)
        else:
            if (type(value) is not dict or value.get("id") != check_id
                    or value.get("head_sha") != identity["sha"]
                    or value.get("status") != "completed" or value.get("conclusion") != "success"):
                valid = False
                _note(stages, "check_run:" + runner)
        if type(value) is dict:
            output = value.get("output")

    annotations = None
    annotations_failed = False
    if check_id is not None:
        try:
            annotations = _read_annotations(
                api, f"/repos/{REPOSITORY}/check-runs/{check_id}/annotations"
            )
        except Exception:
            valid = False
            annotations_failed = True
    if type(output) is not dict or type(output.get("annotations_count")) is not int:
        valid = False
        _note(stages, "check_run:" + runner)
        annotations_count = None
    else:
        annotations_count = output["annotations_count"]
        if annotations_count < 0:
            valid = False
            _note(stages, "check_run:" + runner)
    if type(output) is dict:
        for key in ("title", "summary", "text"):
            field = output.get(key)
            if field is not None:
                if type(field) is not str:
                    valid = False
                    _note(stages, "check_run:" + runner)
                    continue
                try:
                    encoded = field.encode("utf-8", "strict")
                except UnicodeError:
                    valid = False
                    _note(stages, "check_run:" + runner)
                    continue
                if len(encoded) > MAX_SUMMARY_BYTES or CANARY in encoded:
                    valid = False
                    _note(stages, "check_run:" + runner)
    expected_notice = _macos_capacity_notice(identity["sha"])
    annotations_valid = annotations is not None and annotations_count is not None
    if annotations_valid and len(annotations) != annotations_count:
        annotations_valid = False
    if annotations_valid:
        if runner == "macos-15":
            annotations_valid = (
                len(annotations) <= MAX_MACOS_CAPACITY_NOTICES
                and all(item == expected_notice for item in annotations)
            )
        else:
            annotations_valid = len(annotations) == 0
    if not annotations_valid:
        valid = False
        if annotations_failed or annotations is not None:
            _note(stages, "annotations:" + runner)

    try:
        log = api.log_text(job["id"])
    except Exception:
        _note(stages, "log_fetch:" + runner)
        return None, None, False
    if type(log) is not bytes or len(log) > MAX_LOG_BYTES:
        _note(stages, "log_fetch:" + runner)
        return None, None, False
    if CANARY in log or b"KD-FEEDBACK-REFUSAL " in log:
        valid = False
        _note(stages, "log_markers:" + runner)
    try:
        cipher = parse_ciphertext_marker(log)
    except Exception:
        cipher = None
        valid = False
        _note(stages, "log_markers:" + runner)
    if (cipher is None or cipher["control_sha"] != identity["sha"]
            or cipher["run_id"] != identity["run_id"]):
        valid = False
        _note(stages, "log_markers:" + runner)
    upload = None
    if runner == "macos-15":
        try:
            upload = parse_upload_marker(log)
        except Exception:
            valid = False
            _note(stages, "upload_marker")
        if upload is not None and (cipher is None
                or upload["control_sha"] != identity["sha"]
                or upload["run_id"] != identity["run_id"]
                or upload["artifact_name"] != ARTIFACT_PREFIX + identity["run_id"] + "-1"
                or upload["ciphertext_sha256"] != cipher["ciphertext_sha256"]
                or upload["ciphertext_size"] != cipher["ciphertext_size"]):
            valid = False
            _note(stages, "upload_marker")
    elif b"KD-FEEDBACK-UPLOAD " in log:
        valid = False
        _note(stages, "upload_marker")
    return cipher, upload, valid


def _validate_artifact_record(record, identity, upload, *, now=None):
    if (type(record) is not dict or not _exact_int(record.get("id"), 1)
            or record.get("name") != ARTIFACT_PREFIX + identity["run_id"] + "-1"
            or not _exact_int(record.get("size_in_bytes"), 1)
            or record.get("expired") is not False
            or type(record.get("digest")) is not str
            or re.fullmatch(r"sha256:[a-f0-9]{64}", record["digest"]) is None):
        _fail("artifact_invalid")
    if upload is not None and (record["id"] != upload["artifact_id"]
            or record.get("name") != upload["artifact_name"]
            or record.get("digest") != "sha256:" + upload["archive_sha256"]):
        _fail("artifact_invalid")
    workflow_run = record.get("workflow_run")
    if (type(workflow_run) is not dict or type(workflow_run.get("id")) is not int
            or workflow_run.get("id") != int(identity["run_id"])
            or type(workflow_run.get("repository_id")) is not int
            or workflow_run.get("repository_id") != identity["repository_id"]
            or workflow_run.get("head_sha") != identity["sha"]):
        _fail("artifact_invalid")
    created = _parse_api_time(record.get("created_at"))
    expires = _parse_api_time(record.get("expires_at"))
    retention = expires - created
    current = datetime.now(timezone.utc) if now is None else now
    if (not isinstance(current, datetime) or current.tzinfo is None
            or current.utcoffset() != timedelta(0)
            or created > current or expires <= current
            or retention <= timedelta(0) or retention > timedelta(days=1)
            or expires - current > timedelta(days=1)):
        _fail("artifact_invalid")
    return record["size_in_bytes"]


def _parse_api_time(value):
    if type(value) is not str or API_TIME.fullmatch(value) is None:
        _fail("artifact_invalid")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except ValueError:
        _fail("artifact_invalid")


def _download_archive(api, artifact_id):
    path = f"/repos/{REPOSITORY}/actions/artifacts/{artifact_id}/zip"
    request = urllib.request.Request(
        API_ORIGIN + path,
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + api._token,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "development-feedback-smoke-audit",
            "Accept-Encoding": "identity",
        },
        method="GET",
    )
    _, headers = api._open(request, 1, allow_redirect=True)
    location = headers.get("Location")
    if (type(location) is not str or not location or len(location) > 8192
            or any(ord(char) < 33 or ord(char) > 126 for char in location)):
        _fail("artifact_invalid")
    _validate_log_location(location)
    blob_request = urllib.request.Request(
        location,
        headers={"Accept": "application/zip", "Accept-Encoding": "identity",
                 "User-Agent": "development-feedback-smoke-audit"},
        method="GET",
    )
    archive, blob_headers = api._open(blob_request, MAX_ARCHIVE_BYTES)
    if (blob_headers.get_content_type() not in ("application/zip", "application/octet-stream")
            or blob_headers.get("Content-Encoding", "identity").lower() != "identity"):
        _fail("artifact_invalid")
    content_length = blob_headers.get("Content-Length")
    if (content_length is None or not content_length.isascii() or not content_length.isdecimal()
            or int(content_length) != len(archive)):
        _fail("artifact_invalid")
    return archive


def _validate_artifact(api, identity, upload):
    path = f"/repos/{REPOSITORY}/actions/runs/{identity['run_id']}/artifacts?per_page=100&page=1"
    try:
        value, headers = api.json(path)
    except Exception:
        return False
    if type(value) is not dict or type(value.get("artifacts")) is not list:
        return False
    artifacts = value["artifacts"]
    valid = (value.get("total_count") == 1 and len(artifacts) == 1
             and not headers.get("Link"))
    if len(artifacts) != 1:
        return False
    record = artifacts[0]
    try:
        expected_archive_size = _validate_artifact_record(record, identity, upload)
    except Exception:
        expected_archive_size = None
        valid = False
    if type(record) is not dict or not _exact_int(record.get("id"), 1):
        return False
    try:
        archive = _download_archive(api, record["id"])
    except Exception:
        return False
    if (type(archive) is not bytes or len(archive) > MAX_ARCHIVE_BYTES
            or (expected_archive_size is not None and len(archive) != expected_archive_size)):
        valid = False
    try:
        member = validate_ciphertext_archive(archive, member_name=ZIP_MEMBER)
    except Exception:
        return False
    archive_digest = hashlib.sha256(archive).hexdigest()
    ciphertext_digest = hashlib.sha256(member).hexdigest()
    if (CANARY in member or type(record.get("digest")) is not str
            or record["digest"] != "sha256:" + archive_digest):
        valid = False
    if upload is not None and (len(member) != upload["ciphertext_size"]
            or ciphertext_digest != upload["ciphertext_sha256"]
            or archive_digest != upload["archive_sha256"]):
        valid = False
    return valid


def _check_ready(api, job, runner):
    try:
        check_id = _check_id(job.get("check_run_url"))
        value, _ = api.json(f"/repos/{REPOSITORY}/check-runs/{check_id}")
        if type(value) is not dict or value.get("status") != "completed":
            return False
        output = value.get("output")
        if type(output) is not dict or type(output.get("annotations_count")) is not int:
            return False
        annotations = _read_annotations(
            api, f"/repos/{REPOSITORY}/check-runs/{check_id}/annotations"
        )
        if len(annotations) != output["annotations_count"]:
            return False
        log = api.log_text(job["id"])
        if type(log) is not bytes:
            return False
        if (job.get("conclusion") not in (None, "success")
                or value.get("conclusion") not in (None, "success")):
            return True
        parse_ciphertext_marker(log)
        if runner == "macos-15":
            parse_upload_marker(log)
        return True
    except Exception:
        return False


def _producers_ready(api, identity, deadline, monotonic):
    if monotonic() > deadline:
        return False
    try:
        by_name, _ = _validate_jobs(api, identity)
    except Exception:
        return False
    ready = True
    for runner in RUNNERS:
        if not by_name[runner]:
            ready = False
        for job in by_name[runner]:
            if monotonic() > deadline:
                return False
            if not _check_ready(api, job, runner):
                ready = False
    return ready


def _wait_for_producers(api, identity, sleep, monotonic):
    started = monotonic()
    deadline = started + READINESS_MAX_SECONDS
    for attempt in range(READINESS_ATTEMPTS):
        if _producers_ready(api, identity, deadline, monotonic):
            return True
        if attempt + 1 == READINESS_ATTEMPTS:
            break
        if monotonic() - started + READINESS_INTERVAL_SECONDS > READINESS_MAX_SECONDS:
            break
        sleep(READINESS_INTERVAL_SECONDS)
    return False


def audit_feedback_smoke(env=None, api_factory=GitHubAPI, sleep=time.sleep,
                         monotonic=time.monotonic):
    env = os.environ if env is None else env
    identity = _validate_environment(env)
    token = env.get("GITHUB_TOKEN")
    if type(token) is not str or len(token) < 20 or len(token) > 512:
        _fail("invalid_input")
    api = api_factory(token)
    _wait_for_producers(api, identity, sleep, monotonic)
    stages = []
    run_valid = _validate_run(api, identity)
    if not run_valid:
        stages.append("run")
    jobs, jobs_valid = _validate_jobs(api, identity)
    if not jobs_valid:
        stages.append("jobs")
    upload = None
    checks_valid = True
    for runner in RUNNERS:
        if not jobs[runner]:
            checks_valid = False
        for job in jobs[runner]:
            _, runner_upload, check_valid = _audit_check(api, job, identity, runner, stages)
            checks_valid = check_valid and checks_valid
            if runner_upload is not None:
                if upload is None:
                    upload = runner_upload
                else:
                    checks_valid = False
                    stages.append("upload_marker")
    artifact_valid = _validate_artifact(api, identity, upload)
    if not run_valid or not jobs_valid or not checks_valid:
        raise SmokeAuditRefusal("producer_failed", stages[0] if stages else None)
    if not artifact_valid:
        raise SmokeAuditRefusal("artifact_invalid", "artifact")
    return (
        f"KD-FEEDBACK-AUDIT schema=1 status=passed control-sha={identity['sha']} "
        f"run-id={identity['run_id']} run-attempt=1 producers=3 ciphertexts=3 "
        f"artifact=verified archive=verified source=synthetic"
    )


def _write_summary(env, marker):
    path = env.get("GITHUB_STEP_SUMMARY")
    if type(path) is not str or not os.path.isabs(path):
        _fail("invalid_input")
    with open(path, "ab") as target:
        target.write(marker.encode("ascii") + b"\n")


def main():
    try:
        marker = audit_feedback_smoke()
        _write_summary(os.environ, marker)
        sys.stdout.write(marker + "\n")
    except SmokeAuditRefusal as error:
        sys.stderr.write(f"KD-FEEDBACK-AUDIT-REFUSAL reason={error.reason}\n")
        if error.detail in DETAIL_STAGES:
            sys.stderr.write(f"KD-FEEDBACK-AUDIT-DETAIL stage={error.detail}\n")
        return 1
    except AuditRefusal as error:
        reason = error.reason if error.reason in {
            "api_unavailable", "api_status", "api_schema", "producer_failed",
            "summary_invalid", "artifact_invalid", "archive_invalid",
        } else "internal_error"
        sys.stderr.write(f"KD-FEEDBACK-AUDIT-REFUSAL reason={reason}\n")
        return 1
    except Exception:
        sys.stderr.write("KD-FEEDBACK-AUDIT-REFUSAL reason=internal_error\n")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
