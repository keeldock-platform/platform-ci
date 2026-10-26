import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


REPOSITORY = "keeldock-platform/platform-ci"
WORKFLOW_PATH = ".github/workflows/macos-capability.yml"
NATIVE_JOB_NAME = "macos-capability"
REVIEWED_WORKFLOW_PATH = ".github/workflows/macos-reviewed-build.yml"
REVIEWED_SNAPSHOT_JOB_NAME = "macos-public-snapshot"
REVIEWED_SMOKE_JOB_NAME = "macos-reviewed-smoke"
REVIEWED_AUDIT_JOB_NAME = "macos-public-surface-audit"
API_ORIGIN = "https://api.github.com"
API_HOST = "api.github.com"
API_VERSION = "2022-11-28"
PAGE_SIZE = 100
MAX_API_BYTES = 2 * 1024 * 1024
MAX_TOTAL_API_BYTES = 16 * 1024 * 1024
MAX_LOG_BYTES = 32 * 1024 * 1024
MAX_CACHE_ITEMS = 10000
MAX_ARTIFACT_ITEMS = 1000
MAX_ANNOTATIONS = 10000
MAX_PAGES = 100
MAX_RECEIPT_BYTES = 16 * 1024
CONTROL_SHA_RE = re.compile(r"[a-f0-9]{40}\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9_./-]{20,512}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
HEX_DIGEST_RE = re.compile(r"[a-f0-9]{64}\Z")
REVIEWED_SMOKE_MARKER_RE = re.compile(
    rb"macos-build=synthetic-smoke-passed schema=1 source=none "
    rb"control-sha=([a-f0-9]{40}) run-id=([1-9][0-9]{0,18}) "
    rb"run-attempt=([1-9][0-9]{0,18}) "
    rb"image-os=(macos-?[0-9]{1,2}(?:-(?:arm64|x64|intel))?) "
    rb"image-version=[0-9]+(?:\.[0-9]+){1,3} "
    rb"macos-version=[0-9]+\.[0-9]+(?:\.[0-9]+)? "
    rb"architecture=(?:arm64|x86_64) "
    rb"xcode=[0-9]+(?:\.[0-9]+){0,3} xcode-build=[A-Za-z0-9.]+ "
    rb"compiler-origin=(?:command-line-tools|xcode) "
    rb"clang=[0-9]+(?:\.[0-9]+){0,3} sdk=[0-9]+(?:\.[0-9]+){0,3} "
    rb"developer-mode=disabled privilege=separate-nonadmin sudo=denied "
    rb"compile=passed link=passed load-test=passed capture=passed "
    rb"summary-standin=write-denied cleanup=complete seatbelt=not-run pf=not-run"
    rb"(?=\r?(?:\n|$))"
)
CANARY_DOMAIN = b"keeldock" + b"-macos-ci-canary-v1\0"
CANARY_PREFIX = b"KD-MACOS-CI-CANARY-v1:"
REVIEWED_CANARY_PREFIX = b"KD-RB-CANARY-"
CANARY_COMMANDS = (
    b"::error file=canary.txt,line=1::",
    b"::warning::",
    b"::add-mask::",
    b"::set-output name=leak::",
    b"::group::",
    b"::endgroup::",
)
EXPECTED_CHANNELS = {
    "https": "blocked",
    "dns": "blocked",
    "redirect": "blocked",
    "proxy": "blocked",
    "runner_ipc": "blocked",
    "raw_logs": "captured_private",
    "artifact_upload": "pending_audit",
    "cache_upload": "pending_audit",
    "runner_files": "blocked",
    "process_memory": "blocked",
    "boundary_disablement": "blocked",
}
REASONS = frozenset(
    (
        "invalid_input",
        "api_unavailable",
        "api_status",
        "api_schema",
        "run_identity_mismatch",
        "pagination_incomplete",
        "inventory_changed",
        "artifact_found",
        "log_unavailable",
        "log_too_large",
        "log_format_unknown",
        "canary_exposed",
        "workflow_command_exposed",
        "receipt_invalid",
        "native_job_failed",
        "output_unavailable",
        "internal_error",
    )
)


class AuditRefusal(Exception):
    def __init__(self, reason):
        super().__init__()
        self.reason = reason if reason in REASONS else "internal_error"


def _fail(reason):
    raise AuditRefusal(reason)


def _exact_int(value, minimum=0):
    return type(value) is int and value >= minimum


def _no_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("api_schema")
        result[key] = value
    return result


def _json_loads(raw, reason="api_schema"):
    if type(raw) is not bytes or len(raw) > MAX_API_BYTES:
        _fail(reason)
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_no_duplicate_pairs)
    except AuditRefusal:
        raise
    except Exception:
        _fail(reason)


def _valid_sha(value):
    return type(value) is str and CONTROL_SHA_RE.fullmatch(value) is not None


def _positive_decimal(value):
    return type(value) is str and DECIMAL_RE.fullmatch(value) is not None


def derive_canary(control_sha):
    if not _valid_sha(control_sha):
        _fail("invalid_input")
    digest = hashlib.sha256(CANARY_DOMAIN + control_sha.encode("ascii")).hexdigest()[:32]
    return CANARY_PREFIX + digest.encode("ascii")


def _canary_variants(control_sha):
    value = derive_canary(control_sha)
    return {
        value,
        value.upper(),
        value.hex().encode("ascii"),
        base64.b64encode(value),
        base64.urlsafe_b64encode(value).rstrip(b"="),
        urllib.parse.quote_from_bytes(value, safe="").encode("ascii"),
    }


def derive_reviewed_canary(control_sha):
    if not _valid_sha(control_sha):
        _fail("invalid_input")
    return REVIEWED_CANARY_PREFIX + control_sha[:16].encode("ascii")


def _reviewed_canary_variants(control_sha):
    value = derive_reviewed_canary(control_sha)
    return {
        value,
        value.upper(),
        value.hex().encode("ascii"),
        base64.b64encode(value),
        base64.urlsafe_b64encode(value).rstrip(b"="),
        urllib.parse.quote_from_bytes(value, safe="").encode("ascii"),
    }


def canary_needles(control_sha):
    variants = _canary_variants(control_sha)
    values = set(variants)
    for command in CANARY_COMMANDS:
        for variant in variants:
            values.add(command + variant)
    return tuple(sorted(values, key=len, reverse=True))


def inspect_public_bytes(raw, control_sha):
    if type(raw) is not bytes:
        _fail("log_format_unknown")
    for command in CANARY_COMMANDS:
        if command in raw:
            _fail("workflow_command_exposed")
        for variant in _canary_variants(control_sha):
            if command + variant in raw:
                _fail("workflow_command_exposed")
    for needle in _canary_variants(control_sha):
        if needle and needle in raw:
            _fail("canary_exposed")


def inspect_reviewed_public_bytes(raw, control_sha):
    inspect_public_bytes(raw, control_sha)
    for needle in _reviewed_canary_variants(control_sha):
        if needle and needle in raw:
            _fail("canary_exposed")


def cache_inventory_digest(entries):
    if type(entries) is not list or len(entries) > MAX_CACHE_ITEMS:
        _fail("api_schema")
    normalized = []
    seen = set()
    required = {
        "id", "ref", "key", "version", "last_accessed_at", "created_at", "size_in_bytes"
    }
    for item in entries:
        if type(item) is not dict or set(item) != required:
            _fail("api_schema")
        if not _exact_int(item["id"], 1) or item["id"] in seen:
            _fail("api_schema")
        seen.add(item["id"])
        if (type(item["ref"]) is not str or type(item["key"]) is not str
                or type(item["version"]) is not str or type(item["created_at"]) is not str
                or (item["last_accessed_at"] is not None
                    and type(item["last_accessed_at"]) is not str)
                or not _exact_int(item["size_in_bytes"], 0)):
            _fail("api_schema")
        normalized.append({key: item[key] for key in sorted(required)})
    normalized.sort(key=lambda item: item["id"])
    canonical = json.dumps(normalized, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def validate_receipt(encoded, control_sha, run_id, run_attempt):
    if (not _valid_sha(control_sha) or not _positive_decimal(run_id)
            or not _positive_decimal(run_attempt)):
        _fail("receipt_invalid")
    if type(encoded) is not str or not encoded or len(encoded) > (MAX_RECEIPT_BYTES * 4 // 3 + 8):
        _fail("receipt_invalid")
    if re.fullmatch(r"[A-Za-z0-9_-]+", encoded) is None:
        _fail("receipt_invalid")
    padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)
    try:
        raw = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except Exception:
        _fail("receipt_invalid")
    if len(raw) > MAX_RECEIPT_BYTES or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != encoded:
        _fail("receipt_invalid")
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_no_duplicate_pairs)
    except AuditRefusal:
        _fail("receipt_invalid")
    except Exception:
        _fail("receipt_invalid")
    if type(value) is not dict or set(value) != {
        "schema_version", "run_id", "run_attempt", "control_sha", "boundary",
        "macos_product_version", "runner_image_os", "runner_image_version",
        "developer_mode", "pf", "sandbox_selftest", "positive_build", "channels",
        "private_source_executed",
    }:
        _fail("receipt_invalid")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 2
            or not _exact_int(value["run_id"], 1) or value["run_id"] != int(run_id)
            or not _exact_int(value["run_attempt"], 1) or value["run_attempt"] != int(run_attempt)
            or value["control_sha"] != control_sha):
        _fail("receipt_invalid")
    fixed_values = {
        "boundary": "seatbelt-deny-default",
        "macos_product_version": "15.7.9",
        "runner_image_os": "macos-15-arm64",
        "runner_image_version": "20260907.0337.1",
        "developer_mode": "disabled",
        "pf": "enforced",
        "sandbox_selftest": "enforced",
        "positive_build": "passed",
        "private_source_executed": False,
    }
    for key, expected in fixed_values.items():
        if type(value[key]) is not type(expected) or value[key] != expected:
            _fail("receipt_invalid")
    channels = value["channels"]
    if type(channels) is not dict or channels != EXPECTED_CHANNELS:
        _fail("receipt_invalid")
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


class GitHubAPI:
    def __init__(self, token):
        if type(token) is not str or TOKEN_RE.fullmatch(token) is None:
            _fail("invalid_input")
        self._token = token
        self._total_json_bytes = 0
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect()
        )

    def _open(self, request, limit, allow_redirect=False):
        try:
            response = self._opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            if allow_redirect and error.code == 302:
                headers = error.headers
                error.close()
                return None, headers
            _fail("api_status")
        except Exception:
            _fail("api_unavailable")
        try:
            status = response.status
            if status != 200:
                _fail("api_status")
            length = response.headers.get("Content-Length")
            if length is not None:
                if not length.isascii() or not length.isdecimal() or int(length) > limit:
                    _fail("log_too_large" if limit == MAX_LOG_BYTES else "api_schema")
            data = response.read(limit + 1)
            if len(data) > limit:
                _fail("log_too_large" if limit == MAX_LOG_BYTES else "api_schema")
            if length is not None and len(data) != int(length):
                _fail("api_schema")
            return data, response.headers
        except AuditRefusal:
            raise
        except Exception:
            _fail("api_unavailable")
        finally:
            try:
                response.close()
            except Exception:
                pass

    def json(self, path):
        url = API_ORIGIN + path
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + self._token,
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "macos-public-audit",
            "Accept-Encoding": "identity",
        }
        request = urllib.request.Request(url, headers=headers, method="GET")
        raw, response_headers = self._open(request, MAX_API_BYTES)
        self._total_json_bytes += len(raw)
        if self._total_json_bytes > MAX_TOTAL_API_BYTES:
            _fail("api_schema")
        content_type = response_headers.get_content_type()
        if (content_type != "application/json"
                or response_headers.get("Content-Encoding", "identity").lower() != "identity"):
            _fail("api_schema")
        return _json_loads(raw), response_headers

    def log_text(self, job_id):
        path = "/repos/keeldock-platform/platform-ci/actions/jobs/" + str(job_id) + "/logs"
        request = urllib.request.Request(
            API_ORIGIN + path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self._token,
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "macos-public-audit",
                "Accept-Encoding": "identity",
            },
            method="GET",
        )
        _, response_headers = self._open(request, 1, allow_redirect=True)
        location = response_headers.get("Location")
        if (type(location) is not str or not location or len(location) > 8192
                or any(ord(char) < 33 or ord(char) > 126 for char in location)):
            _fail("log_unavailable")
        _validate_log_location(location)
        blob_request = urllib.request.Request(
            location,
            headers={"Accept": "text/plain", "Accept-Encoding": "identity", "User-Agent": "macos-public-audit"},
            method="GET",
        )
        data, blob_headers = self._open(blob_request, MAX_LOG_BYTES)
        content_type = blob_headers.get_content_type()
        if content_type not in ("text/plain", "application/octet-stream"):
            _fail("log_format_unknown")
        content_length = blob_headers.get("Content-Length")
        if (content_length is None or not content_length.isascii()
                or not content_length.isdecimal() or int(content_length) != len(data)):
            _fail("log_format_unknown")
        if blob_headers.get("Content-Encoding", "identity").lower() != "identity":
            _fail("log_format_unknown")
        try:
            data.decode("utf-8", "strict")
        except Exception:
            _fail("log_format_unknown")
        return data


def _validate_api_url(value, expected_path):
    if type(value) is not str or any(ord(char) < 32 or ord(char) == 127 for char in value):
        _fail("api_schema")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except Exception:
        _fail("api_schema")
    if (parsed.scheme != "https" or parsed.hostname != API_HOST or parsed.netloc != API_HOST
            or port is not None
            or parsed.username is not None or parsed.password is not None
            or parsed.path != expected_path or parsed.query or parsed.fragment):
        _fail("api_schema")


def _validate_log_location(value):
    try:
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except Exception:
        _fail("log_unavailable")
    if (parsed.scheme != "https" or host is None or parsed.netloc != host
            or re.fullmatch(r"productionresultssa[0-9]+\.blob\.core\.windows\.net", host) is None
            or parsed.username is not None or parsed.password is not None
            or port is not None or parsed.fragment or not parsed.query):
        _fail("log_unavailable")


def _page_link_map(header_value, path, page, expected_last_page=None):
    if header_value is None or header_value == "":
        if expected_last_page is not None and expected_last_page > page:
            _fail("pagination_incomplete")
        if expected_last_page is None and page > 1:
            _fail("pagination_incomplete")
        return {"_last_page": expected_last_page if expected_last_page is not None else page}
    if type(header_value) is not str or len(header_value) > 65536:
        _fail("pagination_incomplete")
    result = {}
    segments = header_value.split(",")
    for segment in segments:
        match = re.fullmatch(r"\s*<([^<>]+)>\s*;\s*rel=\"([a-z]+)\"\s*", segment)
        if match is None:
            _fail("pagination_incomplete")
        url, relation = match.groups()
        if relation in result or relation not in {"first", "prev", "next", "last"}:
            _fail("pagination_incomplete")
        try:
            parsed = urllib.parse.urlsplit(url)
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
            port = parsed.port
        except Exception:
            _fail("pagination_incomplete")
        if (parsed.scheme != "https" or parsed.hostname != API_HOST or parsed.netloc != API_HOST
                or port is not None
                or parsed.username is not None or parsed.password is not None or parsed.path != path
                or parsed.fragment or set(query) != {"page", "per_page"}
                or len(query["page"]) != 1 or len(query["per_page"]) != 1
                or query["per_page"][0] != str(PAGE_SIZE)
                or not query["page"][0].isdecimal()
                or parsed.query not in (
                    "per_page=" + str(PAGE_SIZE) + "&page=" + query["page"][0],
                    "page=" + query["page"][0] + "&per_page=" + str(PAGE_SIZE),
                )):
            _fail("pagination_incomplete")
        target_page = int(query["page"][0])
        if relation == "first" and target_page != 1:
            _fail("pagination_incomplete")
        result[relation] = target_page
    if "prev" in result and result["prev"] != page - 1:
        _fail("pagination_incomplete")
    if "next" in result and result["next"] != page + 1:
        _fail("pagination_incomplete")
    if expected_last_page is not None:
        last_page = expected_last_page
        if "last" in result and result["last"] != last_page:
            _fail("pagination_incomplete")
    else:
        if "next" in result and "last" not in result:
            _fail("pagination_incomplete")
        last_page = result.get("last", page)
    if last_page < page:
        _fail("pagination_incomplete")
    if last_page > page and result.get("next") != page + 1:
        _fail("pagination_incomplete")
    if last_page <= page and "next" in result:
        _fail("pagination_incomplete")
    if last_page > 1 and "last" in result and result.get("last") != last_page:
        _fail("pagination_incomplete")
    result["_last_page"] = last_page
    return result


def _query_path(path, page):
    return path + "?per_page=" + str(PAGE_SIZE) + "&page=" + str(page)


def _read_counted_collection(api, path, key, maximum, item_validator):
    first, headers = api.json(_query_path(path, 1))
    if type(first) is not dict or type(first.get("total_count")) is not int or first["total_count"] < 0:
        _fail("api_schema")
    total = first["total_count"]
    items = first.get(key)
    if type(items) is not list or total > maximum:
        _fail("api_schema")
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    if pages > MAX_PAGES:
        _fail("pagination_incomplete")
    if len(items) != min(PAGE_SIZE, total):
        _fail("pagination_incomplete")
    _page_link_map(headers.get("Link"), path, 1, pages)
    collected = list(items)
    for page in range(2, pages + 1):
        body, page_headers = api.json(_query_path(path, page))
        if (type(body) is not dict or type(body.get("total_count")) is not int
                or body["total_count"] != total or type(body.get(key)) is not list):
            _fail("pagination_incomplete")
        expected_count = min(PAGE_SIZE, total - (page - 1) * PAGE_SIZE)
        if len(body[key]) != expected_count:
            _fail("pagination_incomplete")
        _page_link_map(page_headers.get("Link"), path, page, pages)
        collected.extend(body[key])
    if len(collected) != total:
        _fail("pagination_incomplete")
    seen_ids = set()
    for item in collected:
        if type(item) is not dict or not _exact_int(item.get("id"), 1) or item["id"] in seen_ids:
            _fail("api_schema")
        seen_ids.add(item["id"])
        item_validator(item)
    return collected


def _read_annotations(api, path):
    all_items = []
    page = 1
    expected_last_page = None
    while True:
        query_path = _query_path(path, page)
        body, headers = api.json(query_path)
        if type(body) is not list or len(body) > PAGE_SIZE:
            _fail("api_schema")
        if len(all_items) + len(body) > MAX_ANNOTATIONS:
            _fail("pagination_incomplete")
        links = _page_link_map(headers.get("Link"), path, page, expected_last_page)
        if expected_last_page is None:
            expected_last_page = links["_last_page"]
            if expected_last_page > MAX_PAGES:
                _fail("pagination_incomplete")
        elif links["_last_page"] != expected_last_page:
            _fail("pagination_incomplete")
        for item in body:
            if type(item) is not dict:
                _fail("api_schema")
            all_items.append(item)
        if "next" not in links:
            if len(body) == PAGE_SIZE and "last" not in links:
                _fail("pagination_incomplete")
            return all_items
        if len(body) != PAGE_SIZE:
            _fail("pagination_incomplete")
        page += 1
        if page > MAX_PAGES:
            _fail("pagination_incomplete")


def _validate_cache(item):
    if type(item) is not dict:
        _fail("api_schema")


def _validate_artifact(item):
    if (type(item) is not dict or not _exact_int(item.get("id"), 1)
            or type(item.get("name")) is not str or not _exact_int(item.get("size_in_bytes"), 0)
            or type(item.get("expired")) is not bool):
        _fail("api_schema")


def _validate_job_record(item):
    if (type(item) is not dict or not _exact_int(item.get("id"), 1)
            or not _exact_int(item.get("run_id"), 1)
            or not _exact_int(item.get("run_attempt"), 1)
            or type(item.get("name")) is not str or not _valid_sha(item.get("head_sha"))
            or type(item.get("status")) is not str
            or item.get("status") not in {"queued", "in_progress", "completed"}
            or type(item.get("check_run_url")) is not str):
        _fail("api_schema")


def _validate_job_steps(job):
    steps = job.get("steps")
    if type(steps) is not list or len(steps) > 100:
        _fail("api_schema")
    seen = set()
    all_success = bool(steps)
    for step in steps:
        if (type(step) is not dict or not _exact_int(step.get("number"), 1)
                or step["number"] in seen or type(step.get("name")) is not str
                or type(step.get("status")) is not str
                or step.get("status") not in {"queued", "in_progress", "completed"}
                or type(step.get("conclusion")) is not str
                or step.get("conclusion") not in {
                    "success", "failure", "cancelled", "skipped", "timed_out",
                    "action_required", "neutral", "stale", "startup_failure",
                }):
            _fail("api_schema")
        if step.get("status") != "completed" or step.get("conclusion") != "success":
            all_success = False
        seen.add(step["number"])
    return all_success


def _validate_run(api, run_id, run_attempt, control_sha, workflow_path=WORKFLOW_PATH):
    run_path = "/repos/keeldock-platform/platform-ci/actions/runs/" + run_id
    run, _ = api.json(run_path)
    repository = run.get("repository") if type(run) is dict else None
    if (type(run) is not dict or not _exact_int(run.get("id"), 1)
            or run["id"] != int(run_id) or type(run.get("run_attempt")) is not int
            or run["run_attempt"] != int(run_attempt) or run.get("head_sha") != control_sha
            or run.get("event") != "workflow_dispatch" or run.get("head_branch") != "main"
            or run.get("path") != workflow_path or type(repository) is not dict
            or repository.get("full_name") != REPOSITORY):
        _fail("run_identity_mismatch")
    return run


def _job_detail(api, job, run_id, run_attempt, control_sha, job_name):
    if (job.get("run_id") != int(run_id) or job.get("run_attempt") != int(run_attempt)
            or job.get("head_sha") != control_sha
            or job.get("status") != "completed"):
        _fail("run_identity_mismatch")
    detail_path = "/repos/keeldock-platform/platform-ci/actions/jobs/" + str(job["id"])
    detail, _ = api.json(detail_path)
    _validate_job_record(detail)
    if (detail.get("id") != job["id"] or detail.get("run_id") != int(run_id)
            or detail.get("run_attempt") != int(run_attempt) or detail.get("head_sha") != control_sha
            or detail.get("name") != job_name or detail.get("status") != "completed"
            or detail.get("conclusion") != job.get("conclusion")):
        _fail("run_identity_mismatch")
    steps_success = _validate_job_steps(detail)
    try:
        check_path = urllib.parse.urlsplit(detail["check_run_url"]).path
    except Exception:
        _fail("api_schema")
    check_id = re.fullmatch(
        r"/repos/keeldock-platform/platform-ci/check-runs/([1-9][0-9]{0,18})",
        check_path,
    )
    expected_check_path = check_id.group(0) if check_id is not None else None
    _validate_api_url(detail["check_run_url"], expected_check_path)
    if job.get("check_run_url") != detail.get("check_run_url"):
        _fail("run_identity_mismatch")
    return detail, int(check_id.group(1)), steps_success


def _native_job(api, run_id, run_attempt, control_sha):
    path = (
        "/repos/keeldock-platform/platform-ci/actions/runs/" + run_id
        + "/attempts/" + run_attempt + "/jobs"
    )
    jobs = _read_counted_collection(api, path, "jobs", 10000, _validate_job_record)
    matches = [job for job in jobs if type(job) is dict and job.get("name") == NATIVE_JOB_NAME]
    if len(matches) != 1:
        _fail("api_schema")
    return _job_detail(api, matches[0], run_id, run_attempt, control_sha, NATIVE_JOB_NAME)


def _reviewed_jobs(api, run_id, run_attempt, control_sha):
    path = (
        "/repos/keeldock-platform/platform-ci/actions/runs/" + run_id
        + "/attempts/" + run_attempt + "/jobs"
    )
    jobs = _read_counted_collection(api, path, "jobs", 10000, _validate_job_record)
    expected_names = {
        REVIEWED_SNAPSHOT_JOB_NAME,
        REVIEWED_SMOKE_JOB_NAME,
        REVIEWED_AUDIT_JOB_NAME,
    }
    if len(jobs) != len(expected_names) or {job.get("name") for job in jobs} != expected_names:
        _fail("api_schema")
    audit_job = next(job for job in jobs if job.get("name") == REVIEWED_AUDIT_JOB_NAME)
    if (audit_job.get("run_id") != int(run_id) or audit_job.get("run_attempt") != int(run_attempt)
            or audit_job.get("head_sha") != control_sha or audit_job.get("status") != "in_progress"):
        _fail("run_identity_mismatch")
    snapshot = next(job for job in jobs if job.get("name") == REVIEWED_SNAPSHOT_JOB_NAME)
    smoke = next(job for job in jobs if job.get("name") == REVIEWED_SMOKE_JOB_NAME)
    return (
        _job_detail(api, snapshot, run_id, run_attempt, control_sha, REVIEWED_SNAPSHOT_JOB_NAME),
        _job_detail(api, smoke, run_id, run_attempt, control_sha, REVIEWED_SMOKE_JOB_NAME),
    )


def _inspect_reviewed_smoke_marker(raw, control_sha, run_id, run_attempt):
    matches = list(REVIEWED_SMOKE_MARKER_RE.finditer(raw))
    if len(matches) != 1 or raw.count(b"macos-build=") != 1:
        _fail("receipt_invalid")
    match = matches[0]
    if match.group(1) != control_sha.encode("ascii") or match.group(2) != run_id.encode("ascii") or match.group(3) != run_attempt.encode("ascii"):
        _fail("receipt_invalid")


def _scan_annotations(api, job, check_id, control_sha, reviewed=False):
    check_path = "/repos/keeldock-platform/platform-ci/check-runs/" + str(check_id)
    check_run, _ = api.json(check_path)
    if (type(check_run) is not dict or not _exact_int(check_run.get("id"), 1)
            or check_run["id"] != check_id or check_run.get("head_sha") != control_sha
            or check_run.get("status") != "completed"
            or type(check_run.get("conclusion")) is not str
            or check_run.get("conclusion") != job.get("conclusion")):
        _fail("run_identity_mismatch")
    output = check_run.get("output")
    if (type(output) is not dict or not _exact_int(output.get("annotations_count"), 0)
            or output["annotations_count"] > MAX_ANNOTATIONS):
        _fail("api_schema")
    try:
        output_bytes = json.dumps(output, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    except Exception:
        _fail("api_schema")
    inspect = inspect_reviewed_public_bytes if reviewed else inspect_public_bytes
    inspect(output_bytes, control_sha)
    path = "/repos/keeldock-platform/platform-ci/check-runs/" + str(check_id) + "/annotations"
    items = _read_annotations(api, path)
    if len(items) != output["annotations_count"]:
        _fail("pagination_incomplete")
    for item in items:
        try:
            raw = json.dumps(item, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
        except Exception:
            _fail("api_schema")
        inspect(raw, control_sha)


def _fetch_artifacts(api, run_id):
    path = "/repos/keeldock-platform/platform-ci/actions/runs/" + run_id + "/artifacts"
    artifacts = _read_counted_collection(api, path, "artifacts", MAX_ARTIFACT_ITEMS, _validate_artifact)
    if artifacts:
        _fail("artifact_found")


def _fetch_caches(api, control_sha, reviewed=False):
    path = "/repos/keeldock-platform/platform-ci/actions/caches"
    caches = _read_counted_collection(api, path, "actions_caches", MAX_CACHE_ITEMS, _validate_cache)
    for item in caches:
        try:
            raw = json.dumps(item, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
        except Exception:
            _fail("api_schema")
        inspect = inspect_reviewed_public_bytes if reviewed else inspect_public_bytes
        inspect(raw, control_sha)
    return cache_inventory_digest(caches)


def _snapshot(phase, api, control_sha, run_id, run_attempt, env):
    workflow_path = REVIEWED_WORKFLOW_PATH if phase == "reviewed-snapshot" else WORKFLOW_PATH
    _validate_run(api, run_id, run_attempt, control_sha, workflow_path)
    digest = _fetch_caches(api, control_sha, reviewed=phase == "reviewed-snapshot")
    if phase in {"snapshot", "reviewed-snapshot"}:
        _write_output("cache_snapshot", digest, env)
        print("macos-public-surface-audit=snapshot-ready")
        return 0
    baseline = env.get("MACOS_CACHE_SNAPSHOT", "")
    if HEX_DIGEST_RE.fullmatch(baseline) is None or digest != baseline:
        _fail("inventory_changed")
    return 0


def _write_output(key, value, env):
    if key != "cache_snapshot" or HEX_DIGEST_RE.fullmatch(value) is None:
        _fail("output_unavailable")
    output_path = env.get("GITHUB_OUTPUT", "")
    if not output_path or not os.path.isabs(output_path):
        _fail("output_unavailable")
    try:
        descriptor = os.open(output_path, os.O_WRONLY | os.O_APPEND)
        try:
            remaining = memoryview((key + "=" + value + "\n").encode("ascii"))
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    _fail("output_unavailable")
                remaining = remaining[written:]
        finally:
            os.close(descriptor)
    except Exception:
        _fail("output_unavailable")


def run(phase, environ=None, api=None):
    env = os.environ if environ is None else environ
    if phase not in {"snapshot", "audit", "reviewed-snapshot", "reviewed-audit"}:
        _fail("invalid_input")
    repository = env.get("GITHUB_REPOSITORY", "")
    run_id = env.get("GITHUB_RUN_ID", "")
    run_attempt = env.get("GITHUB_RUN_ATTEMPT", "")
    control_sha = env.get("CI_SHA", "")
    token = env.get("GITHUB_TOKEN", "")
    if (repository != REPOSITORY or not _positive_decimal(run_id)
            or not _positive_decimal(run_attempt) or not _valid_sha(control_sha)):
        _fail("invalid_input")
    if api is None:
        api = GitHubAPI(token)
    elif type(token) is not str or TOKEN_RE.fullmatch(token) is None:
        _fail("invalid_input")
    if phase in {"snapshot", "reviewed-snapshot"}:
        return _snapshot(phase, api, control_sha, run_id, run_attempt, env)

    if phase == "reviewed-audit":
        _validate_run(api, run_id, run_attempt, control_sha, REVIEWED_WORKFLOW_PATH)
        snapshot, smoke = _reviewed_jobs(api, run_id, run_attempt, control_sha)
        snapshot_log = api.log_text(snapshot[0]["id"])
        inspect_reviewed_public_bytes(snapshot_log, control_sha)
        smoke_log = api.log_text(smoke[0]["id"])
        inspect_reviewed_public_bytes(smoke_log, control_sha)
        _scan_annotations(api, snapshot[0], snapshot[1], control_sha, reviewed=True)
        _scan_annotations(api, smoke[0], smoke[1], control_sha, reviewed=True)
        _fetch_artifacts(api, run_id)
        cache_digest = _fetch_caches(api, control_sha, reviewed=True)
        baseline = env.get("MACOS_CACHE_SNAPSHOT", "")
        if HEX_DIGEST_RE.fullmatch(baseline) is None or cache_digest != baseline:
            _fail("inventory_changed")
        if (snapshot[0].get("conclusion") != "success" or not snapshot[2]
                or smoke[0].get("conclusion") != "success" or not smoke[2]):
            _fail("native_job_failed")
        _inspect_reviewed_smoke_marker(smoke_log, control_sha, run_id, run_attempt)
        print("macos-public-surface-audit=synthetic-smoke-audited")
        return 0

    _validate_run(api, run_id, run_attempt, control_sha)
    job, check_id, steps_success = _native_job(api, run_id, run_attempt, control_sha)
    log_bytes = api.log_text(job["id"])
    inspect_public_bytes(log_bytes, control_sha)
    _scan_annotations(api, job, check_id, control_sha)
    _fetch_artifacts(api, run_id)
    cache_digest = _fetch_caches(api, control_sha)
    baseline = env.get("MACOS_CACHE_SNAPSHOT", "")
    if HEX_DIGEST_RE.fullmatch(baseline) is None or cache_digest != baseline:
        _fail("inventory_changed")
    if job.get("conclusion") != "success" or not steps_success:
        _fail("native_job_failed")
    validate_receipt(env.get("MACOS_NATIVE_RECEIPT_B64URL", ""), control_sha, run_id, run_attempt)
    print("macos-public-surface-audit=passed")
    return 0


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1 or args[0] not in {"snapshot", "audit", "reviewed-snapshot", "reviewed-audit"}:
        print("macos-public-surface-audit=refused reason=invalid_input")
        return 2
    try:
        return run(args[0])
    except AuditRefusal as error:
        print("macos-public-surface-audit=refused reason=" + error.reason)
        return 2
    except BaseException:
        print("macos-public-surface-audit=refused reason=internal_error")
        return 2


if __name__ == "__main__":
    sys.exit(main())
