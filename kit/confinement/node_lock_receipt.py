"""Pure, inactive post-run validation for the registered encrypted feedback profiles.

This path requires the independent auditor job to have completed successfully. A live auditor must
not call it to establish its own success; it exists for the post-run consumer only.
"""

import hashlib
import io
import re
import stat
import struct
import zipfile
import zlib

try:
    from .feedback_request import (
        EXCEPTION_END,
        PROFILES as FEEDBACK_PROFILES,
        RequestRefusal,
        validate_request as _validate_feedback_request,
    )
except ImportError:
    from feedback_request import (
        EXCEPTION_END,
        PROFILES as FEEDBACK_PROFILES,
        RequestRefusal,
        validate_request as _validate_feedback_request,
    )

LOCK_PROFILE = FEEDBACK_PROFILES["core-node-lock-return"]
CONCERN = LOCK_PROFILE["concern"]
WORKFLOW_PATH = LOCK_PROFILE["workflow_path"]
WORKFLOW_REF = "refs/heads/main"
PRODUCER_JOB = LOCK_PROFILE["producer_job"]
AUDITOR_JOB = LOCK_PROFILE["auditor_job"]
ZIP_MEMBER = LOCK_PROFILE["member_name"]
ZIP_MEMBERS = frozenset(profile["member_name"] for profile in FEEDBACK_PROFILES.values())
SCHEMA_VERSION = 1
MAX_ARCHIVE_BYTES = 4 * 1024 * 1024
MAX_MEMBER_BYTES = 4 * 1024 * 1024
MAX_REQUEST_TTL_SECONDS = 24 * 60 * 60
MAX_SAFE_INTEGER = 9_007_199_254_740_991
MAX_JOBS = 64
HEX40_RE = re.compile(r"[a-f0-9]{40}\Z")
HEX64_RE = re.compile(r"[a-f0-9]{64}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
ACTOR_RE = re.compile(r"[A-Za-z0-9-]{1,39}\Z")
LABEL_RE = re.compile(r"[A-Za-z0-9._-]{1,128}\Z")
CONTEXT_FIELDS = (
    "request_id", "nonce", "recipient_fingerprint", "concern", "repository_id",
    "source_sha", "base_sha", "control_sha", "base_branch", "reviewed_diff_sha256",
    "workflow_ref", "run_id", "producer_job", "run_attempt", "expiry",
)
FEEDBACK_CONTEXT_FIELDS = (
    "request_id", "nonce", "recipient_fingerprint", "concern", "kind", "repository_id",
    "source_sha", "base_sha", "control_sha", "base_branch", "reviewed_diff_sha256",
    "workflow_ref", "run_id", "producer_job", "run_attempt", "expiry",
)
RECEIPT_COMMON_FIELDS = frozenset(("schema_version", "status", "job_name"))
RECEIPT_EVIDENCE_FIELDS = frozenset((
    "artifact_id", "ciphertext_digest", "archive_digest", "job_id", "size", "retention",
    "member_size", "archive_size",
))
RECEIPT_FIELDS = RECEIPT_COMMON_FIELDS | frozenset(CONTEXT_FIELDS) | RECEIPT_EVIDENCE_FIELDS
RUN_FIELDS = frozenset((
    "id", "repository_id", "head_sha", "workflow_path", "workflow_ref", "event",
    "status", "conclusion", "actor_login", "run_attempt",
))
JOB_FIELDS = frozenset(("id", "name", "run_id", "run_attempt", "head_sha", "status", "conclusion"))
ARTIFACT_FIELDS = frozenset((
    "id", "name", "repository_id", "run_id", "head_sha", "digest", "size",
    "retention", "expires_at", "expired",
))
API_EVIDENCE_FIELDS = frozenset(("run", "jobs", "artifacts", "request_history"))
PRODUCER_OUTPUT_FIELDS = frozenset(("artifact_id", "archive_digest"))
HISTORY_FIELDS = frozenset(("complete", "matches"))
HISTORY_MATCH_FIELDS = frozenset(("request_id", "run_id", "run_attempt"))


class Refusal(Exception):
    def __init__(self):
        self.reason = "receipt_invalid"
        super().__init__(self.reason)


def _refuse():
    raise Refusal()


def _exact_dict(value, fields):
    return type(value) is dict and set(value) == set(fields)


def _safe_int(value, minimum=0, maximum=MAX_SAFE_INTEGER):
    return type(value) is int and minimum <= value <= maximum


def _positive_decimal(value):
    return (
        type(value) is str and len(value) <= 19
        and DECIMAL_RE.fullmatch(value) is not None and int(value) <= MAX_SAFE_INTEGER
    )


def _valid_ascii_label(value, pattern=LABEL_RE, maximum=128):
    return type(value) is str and len(value) <= maximum and pattern.fullmatch(value) is not None


def _valid_hex(value, size):
    if type(value) is not str or len(value) != size:
        return False
    pattern = HEX40_RE if size == 40 else HEX64_RE
    return pattern.fullmatch(value) is not None


def _bounded_equal(value, expected):
    return type(value) is str and len(value) <= len(expected) and value == expected


def _request_profile(request, now):
    try:
        profile = _validate_feedback_request(request, now=now)
    except RequestRefusal:
        _refuse()
    return profile


def _profile_for_context(context):
    if type(context) is not dict or type(context.get("concern")) is not str:
        _refuse()
    profile = FEEDBACK_PROFILES.get(context["concern"])
    if profile is None:
        _refuse()
    if profile["profile_id"] == 1:
        if "kind" in context:
            _refuse()
    elif context.get("kind") != profile["kind"]:
        _refuse()
    return profile


def _context_fields(profile):
    return CONTEXT_FIELDS if profile["profile_id"] == 1 else FEEDBACK_CONTEXT_FIELDS


def _validate_context(context, profile=None):
    profile = profile or _profile_for_context(context)
    fields = _context_fields(profile)
    if not _exact_dict(context, fields):
        _refuse()
    if (not _valid_hex(context["request_id"], 64)
            or not _valid_hex(context["nonce"], 64)
            or not _valid_hex(context["recipient_fingerprint"], 64)
            or context["concern"] != profile["concern"]
            or not _positive_decimal(context["repository_id"])
            or not _valid_hex(context["source_sha"], 40)
            or not _valid_hex(context["base_sha"], 40)
            or not _valid_hex(context["control_sha"], 40)
            or context["base_branch"] not in ("main", "develop", "uat")
            or type(context["base_branch"]) is not str
            or not _valid_hex(context["reviewed_diff_sha256"], 64)
            or context["workflow_ref"] != WORKFLOW_REF
            or type(context["workflow_ref"]) is not str
            or not _safe_int(context["expiry"], minimum=1, maximum=EXCEPTION_END)
            or not _positive_decimal(context["run_id"])
            or context["producer_job"] != profile["producer_job"]
            or type(context["producer_job"]) is not str
            or type(context["run_attempt"]) is not int or context["run_attempt"] != 1):
        _refuse()
    if profile["profile_id"] != 1:
        if context["kind"] != profile["kind"]:
            _refuse()


def canonical_context(context):
    """Return the exact fixed-order context bytes for one registered profile."""
    profile = _profile_for_context(context)
    _validate_context(context, profile)
    domain = (
        "node-lock-return-context-v1"
        if profile["profile_id"] == 1 else "node-feedback-return-context-v1"
    )
    lines = [domain + "\n"]
    for name in _context_fields(profile):
        value = context[name]
        if type(value) is int:
            value = str(value)
        if type(value) is not str:
            _refuse()
        lines.append(name + "=" + value + "\n")
    try:
        return "".join(lines).encode("ascii", "strict")
    except (UnicodeEncodeError, UnicodeError):
        _refuse()


def _valid_api_evidence(
    api_evidence, ci_repository_id, actor_login, artifact_name, request, profile, now,
):
    if not _exact_dict(api_evidence, API_EVIDENCE_FIELDS):
        _refuse()
    run = api_evidence["run"]
    if not _exact_dict(run, RUN_FIELDS):
        _refuse()
    if (not _safe_int(run["id"], minimum=1)
            or not _safe_int(run["repository_id"], minimum=1)
            or run["repository_id"] != ci_repository_id
            or run["head_sha"] != request["control_sha"]
            or not _bounded_equal(run["workflow_path"], profile["workflow_path"])
            or run["workflow_ref"] != WORKFLOW_REF
            or run["event"] != "workflow_dispatch"
            or run["status"] != "completed"
            or run["conclusion"] != "success"
            or run["actor_login"] != actor_login
            or type(run["run_attempt"]) is not int or run["run_attempt"] != 1):
        _refuse()
    if (not _valid_hex(run["head_sha"], 40)
            or not _valid_ascii_label(run["actor_login"], ACTOR_RE, 39)
            or type(run["workflow_ref"]) is not str or len(run["workflow_ref"]) > 128
            or type(run["event"]) is not str or len(run["event"]) > 32
            or type(run["status"]) is not str or len(run["status"]) > 32
            or type(run["conclusion"]) is not str or len(run["conclusion"]) > 32):
        _refuse()

    run_id = str(run["id"])
    jobs = api_evidence["jobs"]
    if type(jobs) is not list or not 1 <= len(jobs) <= MAX_JOBS:
        _refuse()
    producer = []
    auditor = []
    seen_ids = set()
    for job in jobs:
        if not _exact_dict(job, JOB_FIELDS):
            _refuse()
        if (not _safe_int(job["id"], minimum=1) or job["id"] in seen_ids
                or not _safe_int(job["run_id"], minimum=1) or str(job["run_id"]) != run_id
                or type(job["run_attempt"]) is not int or job["run_attempt"] != 1
                or job["head_sha"] != request["control_sha"]
                or not _valid_ascii_label(job["name"])
                or not _valid_hex(job["head_sha"], 40)
                or type(job["status"]) is not str or len(job["status"]) > 32
                or type(job["conclusion"]) is not str or len(job["conclusion"]) > 32):
            _refuse()
        seen_ids.add(job["id"])
        if job["name"] == profile["producer_job"]:
            producer.append(job)
        elif job["name"] == profile["auditor_job"]:
            auditor.append(job)
    if (len(producer) != 1 or len(auditor) != 1
            or producer[0]["status"] != "completed" or producer[0]["conclusion"] != "success"
            or auditor[0]["status"] != "completed" or auditor[0]["conclusion"] != "success"):
        _refuse()

    artifacts = api_evidence["artifacts"]
    if type(artifacts) is not list or len(artifacts) != 1:
        _refuse()
    artifact = artifacts[0]
    if not _exact_dict(artifact, ARTIFACT_FIELDS):
        _refuse()
    if (not _safe_int(artifact["id"], minimum=1)
            or artifact["name"] != artifact_name
            or artifact["repository_id"] != ci_repository_id
            or artifact["run_id"] != run["id"]
            or artifact["head_sha"] != request["control_sha"]
            or not _valid_hex(artifact["digest"], 64)
            or not _safe_int(artifact["size"], minimum=1, maximum=MAX_ARCHIVE_BYTES)
            or type(artifact["retention"]) is not int or artifact["retention"] != 1
            or not _safe_int(artifact["expires_at"], minimum=1)
            or artifact["expires_at"] <= now
            or artifact["expires_at"] - now > MAX_REQUEST_TTL_SECONDS
            or artifact["expired"] is not False):
        _refuse()
    if (not _valid_ascii_label(artifact["name"])
            or not _safe_int(artifact["repository_id"], minimum=1)
            or not _safe_int(artifact["run_id"], minimum=1)
            or not _valid_hex(artifact["head_sha"], 40)):
        _refuse()

    history = api_evidence["request_history"]
    if not _exact_dict(history, HISTORY_FIELDS) or history["complete"] is not True:
        _refuse()
    matches = history["matches"]
    if type(matches) is not list or len(matches) != 1:
        _refuse()
    match = matches[0]
    if (not _exact_dict(match, HISTORY_MATCH_FIELDS)
            or match["request_id"] != request["request_id"]
            or match["run_id"] != run_id
            or type(match["run_attempt"]) is not int or match["run_attempt"] != 1):
        _refuse()
    if (not _valid_hex(match["request_id"], 64)
            or not _positive_decimal(match["run_id"])):
        _refuse()
    return run, producer[0], auditor[0], artifact


def _zip_member(archive_bytes, member_name=ZIP_MEMBER):
    if type(archive_bytes) is not bytes or not 0 < len(archive_bytes) <= MAX_ARCHIVE_BYTES:
        _refuse()
    if type(member_name) is not str or member_name not in ZIP_MEMBERS:
        _refuse()
    expected_name = member_name.encode("ascii")
    if len(archive_bytes) < 22 + 30 + 46:
        _refuse()
    end = len(archive_bytes) - 22
    if archive_bytes[end:end + 4] != b"PK\x05\x06":
        _refuse()
    try:
        (disk, central_disk, disk_count, entry_count, central_size, central_offset, comment_size) = (
            struct.unpack_from("<HHHHIIH", archive_bytes, end + 4)
        )
    except struct.error:
        _refuse()
    if (disk != 0 or central_disk != 0 or disk_count != 1 or entry_count != 1
            or comment_size != 0
            or central_offset + central_size != end):
        _refuse()
    try:
        central = struct.unpack_from("<4s6H3I5H2I", archive_bytes, central_offset)
    except struct.error:
        _refuse()
    (central_signature, made_by, central_version, central_flags, method, modified_time,
     modified_date, central_crc, compressed_size, member_size, central_name_size,
     central_extra_size, central_comment_size, central_disk_start, internal_attributes,
     external_attributes, local_offset) = central
    del made_by, internal_attributes
    central_end = central_offset + 46 + central_name_size + central_extra_size + central_comment_size
    if (central_signature != b"PK\x01\x02" or central_end != end or central_extra_size != 0
            or central_comment_size != 0 or central_disk_start != 0 or local_offset != 0
            or central_name_size != len(expected_name)
            or member_size <= 0 or member_size > MAX_MEMBER_BYTES
            or compressed_size > MAX_MEMBER_BYTES
            or method not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)
            or central_flags not in (0, 0x0008, 0x0800, 0x0808)):
        _refuse()
    central_name_start = central_offset + 46
    central_name = archive_bytes[central_name_start:central_end]
    if central_name != expected_name or b"\x00" in central_name:
        _refuse()
    try:
        local = struct.unpack_from("<4s5H3I2H", archive_bytes, 0)
    except struct.error:
        _refuse()
    (local_signature, local_version, local_flags, local_method, local_time, local_date,
     local_crc, local_compressed_size, local_member_size, local_name_size, local_extra_size) = local
    local_name_start = 30
    local_name_end = local_name_start + local_name_size
    if (local_signature != b"PK\x03\x04" or local_offset != 0
            or local_version != central_version or local_flags != central_flags
            or local_method != method or local_time != modified_time or local_date != modified_date
            or local_name_size != central_name_size or local_extra_size != 0
            or local_name_end > len(archive_bytes)
            or archive_bytes[local_name_start:local_name_end] != expected_name
            or b"\x00" in archive_bytes[local_name_start:local_name_end]):
        _refuse()
    data_start = local_name_end
    data_end = data_start + compressed_size
    if data_end > central_offset:
        _refuse()
    if central_flags & 0x0008:
        if (local_crc, local_compressed_size, local_member_size) not in (
            (0, 0, 0), (central_crc, compressed_size, member_size),
        ):
            _refuse()
        if archive_bytes[data_end:data_end + 4] == b"PK\x07\x08":
            try:
                descriptor_signature, descriptor_crc, descriptor_compressed, descriptor_member = (
                    struct.unpack_from("<4sIII", archive_bytes, data_end)
                )
            except struct.error:
                _refuse()
            descriptor_end = data_end + 16
            if descriptor_signature != b"PK\x07\x08":
                _refuse()
        else:
            try:
                descriptor_crc, descriptor_compressed, descriptor_member = (
                    struct.unpack_from("<III", archive_bytes, data_end)
                )
            except struct.error:
                _refuse()
            descriptor_end = data_end + 12
        if (descriptor_end != central_offset or descriptor_crc != central_crc
                or descriptor_compressed != compressed_size or descriptor_member != member_size):
            _refuse()
    elif ((local_crc, local_compressed_size, local_member_size)
          != (central_crc, compressed_size, member_size) or data_end != central_offset):
        _refuse()

    mode = (external_attributes >> 16) & 0xFFFF
    file_type = stat.S_IFMT(mode)
    permissions = stat.S_IMODE(mode)
    if (file_type not in (0, stat.S_IFREG)
            or permissions & (0o111 | 0o7000 | 0o022)
            or external_attributes & 0x10):
        _refuse()
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes), "r") as archive:
            entries = archive.infolist()
            if len(entries) != 1:
                _refuse()
            info = entries[0]
            if (info.filename != member_name or info.orig_filename != member_name
                    or info.is_dir() or info.header_offset != 0
                    or info.flag_bits != central_flags or info.compress_type != method
                    or info.file_size != member_size or info.compress_size != compressed_size
                    or info.file_size <= 0 or info.file_size > MAX_MEMBER_BYTES
                    or info.compress_size > MAX_MEMBER_BYTES):
                _refuse()
    except Refusal:
        raise
    except Exception:
        raise Refusal() from None

    compressed_member = archive_bytes[data_start:data_end]
    if method == zipfile.ZIP_STORED:
        if compressed_size != member_size:
            _refuse()
        member = compressed_member
    else:
        try:
            decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
            member = decompressor.decompress(compressed_member, MAX_MEMBER_BYTES + 1)
        except zlib.error:
            _refuse()
        if (len(member) > MAX_MEMBER_BYTES or not decompressor.eof
                or decompressor.unused_data or decompressor.unconsumed_tail):
            _refuse()
    if (len(member) != member_size or (zlib.crc32(member) & 0xFFFFFFFF) != central_crc):
        _refuse()
    return member


def validate_ciphertext_archive(archive_bytes, *, member_name):
    """Validate the fixed single-member encrypted ZIP and return its bounded member."""
    return _zip_member(archive_bytes, member_name=member_name)


def validate_receipt(
    request, receipt, api_evidence, producer_output, archive_bytes, *,
    ci_repository_id, actor_login, artifact_name, now,
):
    """Validate trusted bindings and return the trusted context and ciphertext bytes."""
    try:
        profile = _request_profile(request, now)
        if (not _safe_int(now, minimum=1)
                or request["expiry"] <= now
                or request["expiry"] - now > MAX_REQUEST_TTL_SECONDS
                or not _safe_int(ci_repository_id, minimum=1)
                or request["ci_repository_id"] != str(ci_repository_id)
                or request["workflow_path"] != profile["workflow_path"]
                or request["repository_id"] == str(ci_repository_id)
                or not _valid_ascii_label(actor_login, ACTOR_RE, 39)
                or not _valid_ascii_label(artifact_name)):
            _refuse()
        context_fields = _context_fields(profile)
        receipt_fields = RECEIPT_COMMON_FIELDS | frozenset(context_fields) | RECEIPT_EVIDENCE_FIELDS
        if not _exact_dict(receipt, receipt_fields):
            _refuse()
        if (type(receipt["schema_version"]) is not int or receipt["schema_version"] != SCHEMA_VERSION
                or receipt["job_name"] != profile["producer_job"]
                or type(receipt["job_name"]) is not str
                or receipt["status"] != "passed"
                or type(receipt["status"]) is not str):
            _refuse()
        if not _exact_dict(producer_output, PRODUCER_OUTPUT_FIELDS):
            _refuse()
        if (not _safe_int(producer_output["artifact_id"], minimum=1)
                or not _valid_hex(producer_output["archive_digest"], 64)):
            _refuse()

        run, producer, unused_auditor, artifact = _valid_api_evidence(
            api_evidence, ci_repository_id, actor_login, artifact_name, request, profile, now,
        )
        context = {name: request[name] for name in context_fields if name in request}
        context.update({
            "run_id": str(run["id"]),
            "producer_job": profile["producer_job"],
            "run_attempt": 1,
        })
        _validate_context(context, profile)
        canonical_context(context)
        receipt_context = {name: receipt[name] for name in context_fields}
        _validate_context(receipt_context, profile)
        if any(receipt[name] != context[name] for name in context_fields):
            _refuse()
        if (not _safe_int(receipt["artifact_id"], minimum=1)
                or not _safe_int(receipt["job_id"], minimum=1)
                or not _safe_int(receipt["size"], minimum=1, maximum=MAX_ARCHIVE_BYTES)
                or type(receipt["retention"]) is not int or receipt["retention"] != 1
                or not _safe_int(receipt["member_size"], minimum=1, maximum=MAX_MEMBER_BYTES)
                or not _safe_int(receipt["archive_size"], minimum=1, maximum=MAX_ARCHIVE_BYTES)
                or not _valid_hex(receipt["ciphertext_digest"], 64)
                or not _valid_hex(receipt["archive_digest"], 64)):
            _refuse()

        member = _zip_member(archive_bytes, profile["member_name"])
        archive_digest = hashlib.sha256(archive_bytes).hexdigest()
        member_digest = hashlib.sha256(member).hexdigest()
        if (receipt["artifact_id"] != artifact["id"]
                or receipt["artifact_id"] != producer_output["artifact_id"]
                or receipt["job_id"] != producer["id"]
                or receipt["size"] != artifact["size"]
                or receipt["size"] != len(archive_bytes)
                or receipt["archive_size"] != len(archive_bytes)
                or receipt["member_size"] != len(member)
                or receipt["archive_digest"] != artifact["digest"]
                or receipt["archive_digest"] != producer_output["archive_digest"]
                or receipt["archive_digest"] != archive_digest
                or receipt["ciphertext_digest"] != member_digest
                or receipt["retention"] != artifact["retention"]):
            _refuse()
        return {"context": context, "ciphertext": member}
    except Refusal:
        raise
    except Exception:
        raise Refusal() from None
