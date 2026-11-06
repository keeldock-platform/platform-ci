"""Source-inert inventory probes and explicitly non-passing future-stage checks."""

import argparse
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path


SCHEMA_VERSION = 1
MAX_INVENTORY_BYTES = 1024 * 1024
MAX_JOBS = 256
MAX_PATHS_PER_JOB = 4096
MAX_RESULT_BYTES = 8192
SHA40_RE = re.compile(r"[a-f0-9]{40}\Z")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]{1,39}/[A-Za-z0-9_.-]{1,100}\Z")
JOB_ID_RE = re.compile(r"[a-z][a-z0-9-]{0,95}\Z")
CHECKPOINTS = frozenset(("CP1", "CP2", "CP3", "ci27", "ci28", "ci29", "ci30", "ci31", "appium"))
FUTURE_STAGE_JOB_EXIT_CODE = 78
FUTURE_STAGE_STATUS = "blocked"
FUTURE_STAGE_GATE_EVIDENCE = "forbidden"
INVENTORY_FIELDS = frozenset(("schema_version", "jobs"))
JOB_FIELDS = frozenset(("job_id", "checkpoint", "required_paths"))
RESULT_FIELDS = frozenset((
    "schema_version", "check_name", "job_id", "checkpoint", "source_sha", "status",
    "reason", "gate_evidence", "inventory_digest", "required_count", "present_count",
    "missing_count",
))
API_ROOT = "https://api.github.com"


class FutureStageError(ValueError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _fail(code):
    raise FutureStageError(code)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("inventory-invalid")
        result[key] = value
    return result


def _safe_path(value):
    if type(value) is not str or not value or "\\" in value or value.startswith("/"):
        return False
    parts = value.split("/")
    return all(part not in ("", ".", "..") for part in parts)


def _read_inventory(path):
    target = Path(path)
    try:
        raw = target.read_bytes()
    except OSError:
        _fail("inventory-unavailable")
    if not 0 < len(raw) <= MAX_INVENTORY_BYTES:
        _fail("inventory-invalid")
    try:
        text = raw.decode("ascii", "strict")
        inventory = json.loads(text, object_pairs_hook=_unique_object)
    except Exception:
        _fail("inventory-invalid")
    if type(inventory) is not dict or set(inventory) != INVENTORY_FIELDS:
        _fail("inventory-invalid")
    if type(inventory["schema_version"]) is not int or inventory["schema_version"] != SCHEMA_VERSION:
        _fail("inventory-invalid")
    jobs = inventory["jobs"]
    if type(jobs) is not list or not 1 <= len(jobs) <= MAX_JOBS:
        _fail("inventory-invalid")
    seen = set()
    for job in jobs:
        if type(job) is not dict or set(job) != JOB_FIELDS:
            _fail("inventory-invalid")
        identifier = job["job_id"]
        checkpoint = job["checkpoint"]
        if (type(identifier) is not str or JOB_ID_RE.fullmatch(identifier) is None
                or identifier in seen):
            _fail("inventory-invalid")
        if type(checkpoint) is not str or checkpoint not in CHECKPOINTS:
            _fail("inventory-invalid")
        paths = job["required_paths"]
        if (type(paths) is not list or not 1 <= len(paths) <= MAX_PATHS_PER_JOB
                or any(not _safe_path(item) for item in paths) or len(set(paths)) != len(paths)):
            _fail("inventory-invalid")
        seen.add(identifier)
    return inventory, raw


def _regular_file(root, relative):
    current = root
    parts = relative.split("/")
    for index, part in enumerate(parts):
        current = current / part
        try:
            info = current.lstat()
        except OSError:
            return False
        if current.is_symlink():
            return False
        if index < len(parts) - 1:
            if not current.is_dir():
                return False
        elif not current.is_file():
            return False
    return True


def probe_job(inventory_path, job_id, root, source_sha):
    if type(job_id) is not str or JOB_ID_RE.fullmatch(job_id) is None:
        _fail("job-invalid")
    if type(source_sha) is not str or SHA40_RE.fullmatch(source_sha) is None:
        _fail("source-invalid")
    inventory, raw = _read_inventory(inventory_path)
    rows = [row for row in inventory["jobs"] if row["job_id"] == job_id]
    if len(rows) != 1:
        _fail("job-unknown")
    job = rows[0]
    try:
        root_path = Path(root).resolve(strict=True)
    except OSError:
        _fail("source-root-unavailable")
    if not root_path.is_dir():
        _fail("source-root-unavailable")
    present = sum(_regular_file(root_path, path) for path in job["required_paths"])
    required = len(job["required_paths"])
    return {
        "schema_version": SCHEMA_VERSION,
        "check_name": "future-stage:" + job_id,
        "job_id": job_id,
        "checkpoint": job["checkpoint"],
        "source_sha": source_sha,
        "status": FUTURE_STAGE_STATUS,
        "reason": "future-stage",
        "gate_evidence": FUTURE_STAGE_GATE_EVIDENCE,
        "inventory_digest": hashlib.sha256(raw).hexdigest(),
        "required_count": required,
        "present_count": present,
        "missing_count": required - present,
    }


def encode_result(result):
    if type(result) is not dict or set(result) != RESULT_FIELDS:
        _fail("result-invalid")
    if (type(result.get("job_id")) is not str or JOB_ID_RE.fullmatch(result["job_id"]) is None
            or result.get("check_name") != "future-stage:" + result["job_id"]
            or type(result.get("checkpoint")) is not str or result["checkpoint"] not in CHECKPOINTS
            or type(result.get("source_sha")) is not str or SHA40_RE.fullmatch(result["source_sha"]) is None
            or type(result.get("inventory_digest")) is not str
            or re.fullmatch(r"[a-f0-9]{64}", result["inventory_digest"]) is None
            or result.get("status") != FUTURE_STAGE_STATUS or result.get("reason") != "future-stage"
            or result.get("gate_evidence") != FUTURE_STAGE_GATE_EVIDENCE
            or type(result.get("required_count")) is not int
            or type(result.get("present_count")) is not int
            or type(result.get("missing_count")) is not int
            or result["required_count"] < 1 or result["present_count"] < 0 or result["missing_count"] < 0
            or result["required_count"] != result["present_count"] + result["missing_count"]):
        _fail("result-invalid")
    return json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"


def matrix(inventory_path, checkpoints=None):
    inventory, unused = _read_inventory(inventory_path)
    try:
        selected = None if checkpoints is None else frozenset(checkpoints)
    except TypeError:
        _fail("checkpoint-invalid")
    if selected is not None and (not selected or not selected <= CHECKPOINTS):
        _fail("checkpoint-invalid")
    jobs = [job for job in inventory["jobs"]
            if selected is None or job["checkpoint"] in selected]
    if not jobs:
        _fail("job-unknown")
    return {"include": [
        {"job_id": job["job_id"], "checkpoint": job["checkpoint"]}
        for job in jobs
    ]}


def publish_nonpassing_check(result, *, repository, token, opener=None, timeout=10):
    """Create and verify a failing check row for one unimplemented stage job."""
    if (type(repository) is not str or REPOSITORY_RE.fullmatch(repository) is None
            or type(token) is not str or not 1 <= len(token) <= 8192
            or not all(0x21 <= ord(character) <= 0x7e for character in token)):
        _fail("check-input-invalid")
    text = encode_result(result)
    if len(text.encode("ascii")) > MAX_RESULT_BYTES:
        _fail("result-invalid")
    body = json.dumps({
        "name": result["check_name"],
        "head_sha": result["source_sha"],
        "status": "completed",
        "conclusion": "failure",
        "output": {
            "title": "Future stage inventory probe",
            "summary": "result=blocked gate-evidence=forbidden reason=future-stage checkpoint="
            + result["checkpoint"]
            + " inventory-present=" + str(result["present_count"])
            + " inventory-required=" + str(result["required_count"]),
        },
    }, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    url = API_ROOT + "/repos/" + repository + "/check-runs"
    request = urllib.request.Request(url, data=body, method="POST", headers={
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
        "User-Agent": "platform-ci-future-stage",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    client = opener if opener is not None else urllib.request.build_opener(_NoRedirect())
    try:
        with client.open(request, timeout=timeout) as response:
            if response.status != 201 or response.geturl() != url:
                _fail("check-api-refused")
            raw = response.read(65537)
    except FutureStageError:
        raise
    except Exception:
        _fail("check-api-refused")
    if type(raw) is not bytes or not 0 < len(raw) <= 65536:
        _fail("check-api-refused")
    try:
        check = json.loads(raw.decode("ascii", "strict"), object_pairs_hook=_unique_object)
    except Exception:
        _fail("check-api-refused")
    if (type(check) is not dict or check.get("name") != result["check_name"]
            or check.get("head_sha") != result["source_sha"]
            or check.get("status") != "completed" or check.get("conclusion") != "failure"):
        _fail("check-api-refused")
    return check


def _parser():
    parser = argparse.ArgumentParser(add_help=True)
    commands = parser.add_subparsers(dest="command", required=True)
    matrix_parser = commands.add_parser("matrix")
    matrix_parser.add_argument("--inventory", required=True)
    matrix_parser.add_argument("--checkpoint", action="append")
    probe_parser = commands.add_parser("probe")
    probe_parser.add_argument("--inventory", required=True)
    probe_parser.add_argument("--job", required=True)
    probe_parser.add_argument("--root", required=True)
    probe_parser.add_argument("--source-sha", required=True)
    probe_parser.add_argument("--output", required=True)
    probe_parser.add_argument("--publish", action="store_true")
    return parser


def main(argv=None, environ=None):
    environment = os.environ if environ is None else environ
    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "matrix":
            result = matrix(arguments.inventory, arguments.checkpoint)
            sys.stdout.write(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n")
            return 0
        result = probe_job(arguments.inventory, arguments.job, arguments.root, arguments.source_sha)
        encoded = encode_result(result)
        if arguments.publish:
            publish_nonpassing_check(
                result,
                repository=environment.get("GITHUB_REPOSITORY", ""),
                token=environment.get("GITHUB_TOKEN", ""),
            )
        Path(arguments.output).write_text(encoded, encoding="ascii")
        sys.stdout.write(encoded)
        return FUTURE_STAGE_JOB_EXIT_CODE
    except Exception:
        sys.stdout.write('{"status":"refused","reason":"future-stage-probe-invalid"}\n')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
