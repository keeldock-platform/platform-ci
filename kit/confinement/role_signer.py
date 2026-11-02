import argparse
import base64
import datetime
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit


MAX_JSON_BYTES = 8388608
MAX_CERTIFICATE_FIELDS = 64
MAX_FILE_BYTES = 262144
MAX_U64 = (1 << 64) - 1
MAX_U32 = (1 << 32) - 1
MAX_PROVIDER_PAGES = 256
CONTROL_REPOSITORY = "keeldock-platform/platform-ci"
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
PREDICATE_TYPE = "https://example.invalid/role-statement/v1"
ROLE_ORDER = ("windows-receiver", "linux-fetch-encrypt", "capsule-attester")
CANDIDATE_ROLES = ("windows-producer", "windows-verifier", "linux-fetch-encrypt", "capsule-attester")
ALL_ROLES = (
    "windows-receiver", "windows-producer", "windows-verifier", "linux-fetch-encrypt", "capsule-attester",
)
WINDOWS_ROLES = ("windows-receiver", "windows-producer", "windows-verifier")
RECEIVER_WORKFLOW_PATH = ".github/workflows/lane-h-windows-receiver.yml"
ROLE_PATHS = {
    "windows-receiver": RECEIVER_WORKFLOW_PATH,
    "linux-fetch-encrypt": ".github/workflows/lane-h-linux-fetch-encrypt.yml",
    "capsule-attester": ".github/workflows/lane-h-capsule-attester.yml",
    "windows-producer": RECEIVER_WORKFLOW_PATH,
    "windows-verifier": RECEIVER_WORKFLOW_PATH,
}
ROLE_RUNNERS = {
    "windows-receiver": "windows-2025",
    "linux-fetch-encrypt": "ubuntu-24.04",
    "capsule-attester": "ubuntu-24.04",
    "windows-producer": "windows-2025",
    "windows-verifier": "windows-2025",
}
CALLER_PROFILES = {
    "probe": {
        "path": ".github/workflows/attestation-role-signer-probe.yml",
        "name": "attestation-role-signer-probe",
        "ref": "refs/heads/main",
        "refs": ("refs/heads/main",),
    },
    "production-synthetic": {
        "path": ".github/workflows/windows-source-admission.yml",
        "name": "windows-source-admission",
        "ref": "refs/heads/main",
        "refs": ("refs/heads/main",),
    },
    "candidate": {
        "path": ".github/workflows/windows-source-admission.yml",
        "name": "windows-source-admission",
        "refs": ("refs/heads/main", "refs/heads/untrusted"),
    },
}
PROFILE_ROLES = {
    "probe": ROLE_ORDER,
    "production-synthetic": ROLE_ORDER,
    "candidate": CANDIDATE_ROLES,
}
PINNED_WORKFLOW_SHA256 = {
    ".github/workflows/windows-source-admission.yml": "d8109fc807a8a4e2fdd4d753c9a2b8d00b35c190b4c8e70e37048bde6b1c8b25",
    ".github/workflows/lane-h-windows-receiver.yml": "a7b5598823bbfb5e5fab051314a578567da06c17d86e888fbbef04c280174198",
    ".github/workflows/lane-h-linux-fetch-encrypt.yml": "315cef77a9df73249f23ff54db23dbbc30fe00288922c3fad9543afd0412a033",
    ".github/workflows/lane-h-capsule-attester.yml": "192d78328f8bf093a68bef0f1dd323a88772e2929d79c92b24a8864d17c1b48c",
}
API_JOB_NAME_PINS = {
    profile: {role: "role-call-%s-v1 / role-%s-v1" % (role, role) for role in PROFILE_ROLES[profile]}
    for profile in CALLER_PROFILES
}
API_LINUX_STEP_NAME_PINS = {
    profile: {
        "revoke-source-token": "handoff-revoke-source-token-v1",
        "verify-token-rejection": "handoff-verify-token-rejection-v1",
    }
    for profile in CALLER_PROFILES
}
API_LINUX_STEP_ORDINAL_PINS = {
    profile: {"revoke-source-token": 9, "verify-token-rejection": 10}
    for profile in CALLER_PROFILES
}
API_LINUX_STEP_ORDINAL_PINS["candidate"] = {"revoke-source-token": 12, "verify-token-rejection": 13}
UNLABELED_LOG_STEP = "UNKNOWN STEP"
BYTE_ORDER_MARK = chr(65279)
LOG_GROUP_PREFIX = chr(35) * 2 + "[group]Run "
LOG_GROUP_END = chr(35) * 2 + "[endgroup]"
LINUX_STEP_LOG_MARKERS = {
    "revoke-source-token": "printf '%s\\n' 'probe=source-free-revocation-simulation status=passed'",
    "verify-token-rejection": "printf '%s\\n' 'probe=source-free-revocation-simulation result=synthetic'",
}
CANDIDATE_LINUX_STEP_LOG_MARKERS = {
    "revoke-source-token": "python3 -B kit/confinement/linux_source_build.py revoke",
    "verify-token-rejection": "printf '%s\\n' 'handoff-revocation=confirmed'",
}
LINUX_STEP_LOG_MARKERS_BY_PROFILE = {
    "probe": LINUX_STEP_LOG_MARKERS,
    "production-synthetic": LINUX_STEP_LOG_MARKERS,
    "candidate": CANDIDATE_LINUX_STEP_LOG_MARKERS,
}
ANSI_ESCAPE = re.compile(r"(?:\x1b|\^\[)\[[0-9;]*m")
CONTROL_BYTES = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
GUARD_LABELS = (
    "api-fetch-failed",
    "run-view-failed",
    "attestation-verify-failed",
    "artifact-download-failed",
    "provider-fetch-failed",
    "job-log-fetch-failed",
)
GUARD_RETRY_CLASSES = ("in-progress", "http-404", "http-5xx", "network", "timeout")
GUARD_STDERR_CLASSES = (
    ("still in progress", "in-progress"),
    ("rate limit", "rate-limit"),
    ("no attestations", "no-attestations"),
    ("failed to verify", "verification-failed"),
    ("verification failed", "verification-failed"),
    ("timed out", "timeout"),
    ("could not resolve", "network"),
    ("connection", "network"),
    ("no such host", "network"),
    ("escape sequences", "escape-sequences"),
    ("unknown flag", "gh-usage"),
    ("redirect", "redirect"),
)
GUARD_HTTP_CLASSES = {
    "301": "http-redirect",
    "302": "http-redirect",
    "307": "http-redirect",
    "308": "http-redirect",
    "400": "http-400",
    "401": "http-401",
    "403": "http-403",
    "404": "http-404",
    "406": "http-406",
    "409": "http-409",
    "410": "http-410",
    "422": "http-422",
    "429": "rate-limit",
}
GUARD_TIMEOUT_SECONDS = 300
GUARD_FALLBACK_ROUTE = re.compile(r"repos/([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)/actions/jobs/([0-9]+)/logs")
GUARD_STDERR_BYTES = 65536
CERTIFICATE_ISSUER_PIN = "CN=sigstore-intermediate,O=sigstore.dev"
CERTIFICATE_DIGEST_FIELDS = ("sourceRepositoryDigest", "buildSignerDigest", "buildConfigDigest")
HEX_20 = re.compile(r"[a-f0-9]{40}\Z")
HEX_32 = re.compile(r"[a-f0-9]{64}\Z")
HEX_16 = re.compile(r"[a-f0-9]{32}\Z")
DECIMAL = re.compile(r"[1-9][0-9]*\Z")
ARTIFACT_NAME = re.compile(
    r"role-statement-(windows-receiver|windows-producer|windows-verifier|linux-fetch-encrypt|capsule-attester)-"
    r"([1-9][0-9]{0,19})-([1-9][0-9]{0,9})-([a-f0-9]{32})\Z"
)
P256_PRIME = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
BINDING_KEYS = frozenset((
    "capsule_producer_sha256", "capsule_verifier_sha256", "key_record_producer_sha256",
    "key_record_verifier_sha256", "lock_sha256", "manifest_sha256", "revocation", "schema",
    "source_sha", "tree_id",
))
ATTESTED_KEYS = BINDING_KEYS | frozenset(("kind", "linux_subject_sha256"))
BINDING_MAX_BYTES = 4096
HASH_BLOCK_BYTES = 1048576
CAPSULE_SLACK_BYTES = 8192
RECEIVE_POLL_SECONDS = 5
PREPARE_FLAGS = (
    "receiver_record", "verifier_record", "capsule_producer", "capsule_verifier", "public_point_file",
    "revocation_receipt", "source_sha", "tree_id", "lock_sha256", "manifest_sha256", "linux_subject",
)
PREPARE_CANDIDATE_ONLY_FLAGS = frozenset(PREPARE_FLAGS) - {"receiver_record"}
PREPARE_ROLE_FLAGS = {
    "windows-producer": frozenset(("public_point_file",)),
    "windows-verifier": frozenset(("public_point_file",)),
    "linux-fetch-encrypt": frozenset((
        "receiver_record", "verifier_record", "capsule_producer", "capsule_verifier", "source_sha",
        "tree_id", "lock_sha256", "manifest_sha256",
    )),
    "capsule-attester": frozenset((
        "receiver_record", "verifier_record", "capsule_producer", "capsule_verifier", "linux_subject",
    )),
}
KEY_RECORD_SIZE = 320
CAPSULE_SIZE = 4096
DESIGN_CAPSULE_SIZE = 286261248
P256_GENERATOR = bytes.fromhex(
    "04"
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
ZERO_35 = bytes(35)


class Refusal(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def profile_roles(profile):
    if type(profile) is not str or profile not in PROFILE_ROLES:
        raise Refusal("profile-invalid")
    return PROFILE_ROLES[profile]


def profile_refs(profile):
    if type(profile) is not str or profile not in CALLER_PROFILES:
        raise Refusal("profile-invalid")
    return CALLER_PROFILES[profile]["refs"]


def gate_roles(profile, gate):
    roles = profile_roles(profile)
    if profile == "candidate":
        return roles[:2] if gate == "A" else roles[:3]
    return roles[:1] if gate == "A" else roles[:2]


def validate_public_point(point):
    if type(point) is not bytes or len(point) != 65 or point[0] != 4:
        raise Refusal("public-point-shape")
    x = int.from_bytes(point[1:33], "big")
    y = int.from_bytes(point[33:65], "big")
    if x >= P256_PRIME or y >= P256_PRIME:
        raise Refusal("public-point-range")
    if (y * y - (x * x * x - 3 * x + P256_B)) % P256_PRIME != 0:
        raise Refusal("public-point-curve")
    return point


def _pairs_without_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refusal("duplicate-json-field")
        result[key] = value
    return result


def load_json_bytes(payload, maximum=MAX_JSON_BYTES):
    if type(payload) is not bytes:
        raise Refusal("json-input-type")
    if len(payload) > maximum:
        raise Refusal("json-input-too-large")
    try:
        return json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_pairs_without_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(Refusal("json-number")),
        )
    except Refusal:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        raise Refusal("json-invalid")


def load_json_file(path, maximum=MAX_JSON_BYTES):
    try:
        payload = Path(path).read_bytes()
    except OSError:
        raise Refusal("file-unavailable")
    return load_json_bytes(payload, maximum)


def _is_u64(value, positive=True):
    if type(value) is int:
        number = value
    elif type(value) is str and DECIMAL.fullmatch(value):
        if len(value) > 20:
            raise Refusal("u64-range")
        number = int(value)
    else:
        raise Refusal("u64-encoding")
    if number < (1 if positive else 0) or number > MAX_U64:
        raise Refusal("u64-range")
    if type(value) is str and str(number) != value:
        raise Refusal("u64-canonical")
    return number


def _is_u32(value, positive=True):
    if type(value) is int:
        number = value
    elif type(value) is str and DECIMAL.fullmatch(value):
        if len(value) > 10:
            raise Refusal("u32-range")
        number = int(value)
    else:
        raise Refusal("u32-encoding")
    if number < (1 if positive else 0) or number > MAX_U32:
        raise Refusal("u32-range")
    if type(value) is str and str(number) != value:
        raise Refusal("u32-canonical")
    return number


def _canonical_cert_integer(value, maximum):
    if type(value) is not str or DECIMAL.fullmatch(value) is None:
        raise Refusal("certificate-id-encoding")
    if len(value) > 20:
        raise Refusal("certificate-id-range")
    number = int(value)
    if number < 1 or number > maximum or str(number) != value:
        raise Refusal("certificate-id-range")
    return number


def validate_commit_sha(value):
    if type(value) is not str or HEX_20.fullmatch(value) is None:
        raise Refusal("control-sha-invalid")
    return value


def _repo_parts(repository):
    if type(repository) is not str or repository.count("/") != 1:
        raise Refusal("repository-invalid")
    owner, name = repository.split("/", 1)
    component = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
    if component.fullmatch(owner) is None or component.fullmatch(name) is None:
        raise Refusal("repository-invalid")
    return owner, name


def github_root(repository):
    _repo_parts(repository)
    return "https:" + chr(47) * 2 + "github.com" + chr(47) + repository


def canonical_run_invocation(repository, run_id, run_attempt):
    run_number = _is_u64(run_id)
    attempt_number = _is_u32(run_attempt)
    return (
        github_root(repository)
        + "/actions/runs/"
        + str(run_number)
        + "/attempts/"
        + str(attempt_number)
    )


def validate_run_invocation(raw, repository, run_id, run_attempt):
    expected = canonical_run_invocation(repository, run_id, run_attempt)
    if type(raw) is not str or raw != expected:
        raise Refusal("run-invocation-raw-mismatch")
    try:
        parsed = urlsplit(raw)
    except ValueError:
        raise Refusal("run-invocation-url")
    expected_path = "/" + repository + "/actions/runs/" + str(_is_u64(run_id))
    expected_path += "/attempts/" + str(_is_u32(run_attempt))
    if (
        parsed.scheme != "https"
        or parsed.netloc != "github.com"
        or parsed.username is not None
        or parsed.password is not None
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != expected_path
        or "%" in raw
        or not raw.isascii()
    ):
        raise Refusal("run-invocation-structure")
    return raw


def role_nonce(key_record, role, subject):
    if type(key_record) is not bytes or type(subject) is not bytes:
        raise Refusal("nonce-input-type")
    if role not in ALL_ROLES:
        raise Refusal("nonce-role")
    key_digest = hashlib.sha256(key_record).digest()
    subject_digest = hashlib.sha256(subject).digest()
    message = (
        b"KDWH-v1/role-statement-nonce\x00"
        + key_digest
        + role.encode("ascii")
        + b"\x00"
        + subject_digest
    )
    return hashlib.sha256(message).digest()[:16].hex()


def _runtime_hex(value, length, code):
    pattern = re.compile(r"[a-f0-9]{%d}\Z" % (length * 2))
    if type(value) is not str or pattern.fullmatch(value) is None:
        raise Refusal(code)
    return bytes.fromhex(value)


def make_key_record(repository_id, control_sha, run_id, run_attempt, workflow_ref, now=None, public_point=None):
    repository_number = _is_u64(repository_id)
    run_number = _is_u64(run_id)
    attempt_number = _is_u32(run_attempt)
    sha = validate_commit_sha(control_sha)
    if type(workflow_ref) is not str or not workflow_ref.isascii():
        raise Refusal("workflow-ref-invalid")
    created = int(time.time()) if now is None else _is_u64(now)
    transfer = secrets.token_bytes(16)
    point = P256_GENERATOR if public_point is None else validate_public_point(public_point)
    key_id = hashlib.sha256(point).digest()
    result = bytearray(KEY_RECORD_SIZE)
    result[0:8] = b"KDWHKEY1"
    result[8:10] = (1).to_bytes(2, "big")
    result[10:12] = (1).to_bytes(2, "big")
    result[12:20] = repository_number.to_bytes(8, "big")
    result[20:40] = bytes.fromhex(sha)
    result[40:48] = run_number.to_bytes(8, "big")
    result[48:52] = attempt_number.to_bytes(4, "big")
    result[52:68] = transfer
    result[68:100] = key_id
    result[100:165] = point
    result[165:197] = hashlib.sha256(workflow_ref.encode("ascii")).digest()
    result[197:229] = hashlib.sha256(b"windows-receiver").digest()
    result[229:237] = created.to_bytes(8, "big")
    result[237:245] = (created + 86400).to_bytes(8, "big")
    result[245:253] = DESIGN_CAPSULE_SIZE.to_bytes(8, "big")
    result[253:285] = hashlib.sha256(b"windows-2025").digest()
    result[285:320] = ZERO_35
    return bytes(result)


def validate_key_record(
    record,
    repository_id,
    control_sha,
    run_id,
    run_attempt,
    workflow_ref,
    now=None,
    allow_any_point=False,
):
    if type(record) is not bytes or len(record) != KEY_RECORD_SIZE:
        raise Refusal("key-record-size")
    if record[0:8] != b"KDWHKEY1" or record[8:10] != b"\x00\x01" or record[10:12] != b"\x00\x01":
        raise Refusal("key-record-header")
    repository_number = _is_u64(repository_id)
    run_number = _is_u64(run_id)
    attempt_number = _is_u32(run_attempt)
    sha = validate_commit_sha(control_sha)
    if int.from_bytes(record[12:20], "big") != repository_number:
        raise Refusal("key-record-repository-id")
    if record[20:40] != bytes.fromhex(sha):
        raise Refusal("key-record-control-sha")
    if int.from_bytes(record[40:48], "big") != run_number:
        raise Refusal("key-record-run-id")
    if int.from_bytes(record[48:52], "big") != attempt_number:
        raise Refusal("key-record-attempt")
    if record[52:68] == bytes(16):
        raise Refusal("key-record-transfer")
    if record[68:100] != hashlib.sha256(record[100:165]).digest():
        raise Refusal("key-record-key-id")
    if allow_any_point:
        validate_public_point(record[100:165])
    elif record[100:165] != P256_GENERATOR:
        raise Refusal("key-record-public-point")
    if type(workflow_ref) is not str or not workflow_ref.isascii():
        raise Refusal("workflow-ref-invalid")
    if record[165:197] != hashlib.sha256(workflow_ref.encode("ascii")).digest():
        raise Refusal("key-record-workflow-ref")
    if record[197:229] != hashlib.sha256(b"windows-receiver").digest():
        raise Refusal("key-record-role")
    created = int.from_bytes(record[229:237], "big")
    expires = int.from_bytes(record[237:245], "big")
    current = int(time.time()) if now is None else _is_u64(now)
    if created < 1 or created > current + 300 or expires <= current or expires <= created:
        raise Refusal("key-record-time")
    if expires - created > 86400:
        raise Refusal("key-record-lifetime")
    if int.from_bytes(record[245:253], "big") != DESIGN_CAPSULE_SIZE:
        raise Refusal("key-record-capsule-size")
    if record[253:285] != hashlib.sha256(b"windows-2025").digest():
        raise Refusal("key-record-runner")
    if record[285:320] != ZERO_35:
        raise Refusal("key-record-reserved")
    return {
        "repository_id": repository_number,
        "control_sha": sha,
        "run_id": run_number,
        "run_attempt": attempt_number,
        "transfer_id": record[52:68].hex(),
        "key_record_sha256": hashlib.sha256(record).hexdigest(),
        "created": created,
        "expires": expires,
    }


def make_synthetic_capsule(key_record):
    if type(key_record) is not bytes or len(key_record) != KEY_RECORD_SIZE:
        raise Refusal("key-record-size")
    binding = hashlib.sha256(key_record).digest()
    seed = b"KDWHCAP-PROBE1\x00" + binding + key_record[40:68]
    result = bytearray(CAPSULE_SIZE)
    prefix = b"KDWHCAP-PROBE1\x00" + binding + key_record[40:68]
    result[: len(prefix)] = prefix
    offset = len(prefix)
    counter = 0
    while offset < CAPSULE_SIZE:
        block = hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        count = min(len(block), CAPSULE_SIZE - offset)
        result[offset : offset + count] = block[:count]
        offset += count
        counter += 1
    return bytes(result)


def make_predicate(profile, role, repository, control_sha, ref, run_id, run_attempt, key_record, subject):
    if profile not in CALLER_PROFILES:
        raise Refusal("profile-invalid")
    if role not in profile_roles(profile):
        raise Refusal("role-invalid")
    profile_data = CALLER_PROFILES[profile]
    if ref not in profile_refs(profile):
        raise Refusal("profile-ref")
    validate_commit_sha(control_sha)
    run_number = _is_u64(run_id)
    attempt_number = _is_u32(run_attempt)
    _repo_parts(repository)
    if repository != CONTROL_REPOSITORY:
        raise Refusal("control-repository")
    record_info = validate_key_record(
        key_record,
        int.from_bytes(key_record[12:20], "big"),
        control_sha,
        run_number,
        attempt_number,
        repository + "/" + profile_data["path"] + "@" + ref,
        allow_any_point=profile == "candidate",
    )
    subject_hash = hashlib.sha256(subject).hexdigest()
    return {
        "schemaVersion": 1,
        "profile": profile,
        "role": role,
        "controlRepository": repository,
        "controlSha": control_sha,
        "controlRef": ref,
        "runId": str(run_number),
        "runAttempt": str(attempt_number),
        "transferId": record_info["transfer_id"],
        "keyRecordSha256": record_info["key_record_sha256"],
        "subjectSha256": subject_hash,
        "nonce": role_nonce(key_record, role, subject),
    }


def verified_result(document):
    if type(document) is list:
        if len(document) != 1:
            raise Refusal("verified-result-cardinality")
        document = document[0]
    if type(document) is not dict:
        raise Refusal("verified-result-shape")
    result = document.get("verificationResult")
    if type(result) is not dict:
        raise Refusal("verified-result-missing")
    if "certificate" in result:
        raise Refusal("verified-sibling-certificate")
    signature = result.get("signature")
    if type(signature) is not dict or type(signature.get("certificate")) is not dict:
        raise Refusal("verified-certificate-missing")
    statement = result.get("statement")
    if type(statement) is not dict:
        raise Refusal("verified-statement-missing")
    predicate = statement.get("predicate")
    if type(predicate) is dict and "certificate" in predicate:
        raise Refusal("predicate-certificate-forbidden")
    return result, signature["certificate"], statement


def verified_leaf_summary(document):
    try:
        return verified_result(document)[1]
    except Refusal:
        return None


def _profile_uri(repository, caller_path, ref):
    return github_root(repository) + "/" + caller_path + "@" + ref


def _role_uri(repository, role, ref):
    return github_root(repository) + "/" + ROLE_PATHS[role] + "@" + ref


def certificate_expectations(
    profile,
    repository,
    ref,
    control_sha,
    run_id,
    run_attempt,
    control_repository_id,
    owner_id,
    role,
    runner,
    digest_pins,
):
    if profile not in CALLER_PROFILES or role not in PROFILE_ROLES[profile]:
        raise Refusal("profile-role-invalid")
    profile_data = CALLER_PROFILES[profile]
    if repository != CONTROL_REPOSITORY or ref not in profile_data["refs"]:
        raise Refusal("profile-repository-ref")
    validate_commit_sha(control_sha)
    expected_invocation = canonical_run_invocation(repository, run_id, run_attempt)
    if type(digest_pins) is not dict or set(digest_pins) != {
        "sourceRepositoryDigest",
        "buildSignerDigest",
        "buildConfigDigest",
        "certificateIssuer",
    }:
        raise Refusal("digest-profile-unresolved")
    if any(type(value) is not str or not value for value in digest_pins.values()):
        raise Refusal("digest-profile-unresolved")
    owner, unused_name = _repo_parts(repository)
    root = github_root(repository)
    return {
        "buildSignerURI": _role_uri(repository, role, ref),
        "subjectAlternativeName": _role_uri(repository, role, ref),
        "buildConfigURI": _profile_uri(repository, profile_data["path"], ref),
        "githubWorkflowRef": ref,
        "githubWorkflowName": profile_data["name"],
        "githubWorkflowRepository": repository,
        "githubWorkflowSHA": control_sha,
        "githubWorkflowTrigger": "workflow_dispatch",
        "sourceRepositoryIdentifier": _is_u64(control_repository_id),
        "sourceRepositoryURI": root,
        "sourceRepositoryRef": ref,
        "sourceRepositoryOwnerIdentifier": _is_u64(owner_id),
        "sourceRepositoryOwnerURI": "https:" + chr(47) * 2 + "github.com/" + owner,
        "sourceRepositoryVisibilityAtSigning": "public",
        "sourceRepositoryDigest": digest_pins["sourceRepositoryDigest"],
        "buildSignerDigest": digest_pins["buildSignerDigest"],
        "buildConfigDigest": digest_pins["buildConfigDigest"],
        "buildTrigger": "workflow_dispatch",
        "runInvocationURI": expected_invocation,
        "runnerEnvironment": "github-hosted",
        "issuer": OIDC_ISSUER,
        "certificateIssuer": digest_pins["certificateIssuer"],
        "runner": runner,
        "control_repository_id": _is_u64(control_repository_id),
        "owner_id": _is_u64(owner_id),
        "run_id": _is_u64(run_id),
        "run_attempt": _is_u32(run_attempt),
        "profile": profile,
        "role": role,
    }


def resolve_certificate_pins(profile, control_sha):
    if profile not in CALLER_PROFILES:
        raise Refusal("certificate-profile-unresolved")
    if type(control_sha) is not str or HEX_20.fullmatch(control_sha) is None:
        raise Refusal("certificate-control-sha-missing")
    pins = {field: control_sha for field in CERTIFICATE_DIGEST_FIELDS}
    pins["certificateIssuer"] = CERTIFICATE_ISSUER_PIN
    return {role: dict(pins) for role in PROFILE_ROLES[profile]}


def validate_certificate(certificate, expected):
    if type(certificate) is not dict or len(certificate) > MAX_CERTIFICATE_FIELDS:
        raise Refusal("certificate-shape")
    if any(type(key) is not str for key in certificate):
        raise Refusal("certificate-field-name")
    if any(type(value) in (dict, list) for value in certificate.values()):
        raise Refusal("certificate-field-structure")
    required = (
        "buildSignerURI",
        "subjectAlternativeName",
        "buildConfigURI",
        "githubWorkflowRef",
        "githubWorkflowName",
        "githubWorkflowRepository",
        "githubWorkflowSHA",
        "githubWorkflowTrigger",
        "sourceRepositoryIdentifier",
        "sourceRepositoryURI",
        "sourceRepositoryRef",
        "sourceRepositoryOwnerIdentifier",
        "sourceRepositoryOwnerURI",
        "sourceRepositoryVisibilityAtSigning",
        "sourceRepositoryDigest",
        "buildSignerDigest",
        "buildConfigDigest",
        "buildTrigger",
        "runInvocationURI",
        "runnerEnvironment",
        "issuer",
        "certificateIssuer",
    )
    if any(name not in certificate for name in required):
        raise Refusal("certificate-field-missing")
    for name in required:
        if type(certificate[name]) is not str:
            raise Refusal("certificate-field-type")
    if type(expected) is not dict:
        raise Refusal("certificate-expectations")
    for field in (
        "sourceRepositoryIdentifier",
        "sourceRepositoryOwnerIdentifier",
    ):
        value = _canonical_cert_integer(certificate[field], MAX_U64)
        if value != expected["control_repository_id" if field == "sourceRepositoryIdentifier" else "owner_id"]:
            raise Refusal("certificate-numeric-id-mismatch")
    exact_fields = (
        "buildSignerURI",
        "subjectAlternativeName",
        "buildConfigURI",
        "githubWorkflowRef",
        "githubWorkflowName",
        "githubWorkflowRepository",
        "githubWorkflowSHA",
        "githubWorkflowTrigger",
        "sourceRepositoryURI",
        "sourceRepositoryRef",
        "sourceRepositoryOwnerURI",
        "sourceRepositoryVisibilityAtSigning",
        "sourceRepositoryDigest",
        "buildSignerDigest",
        "buildConfigDigest",
        "buildTrigger",
        "runnerEnvironment",
        "issuer",
        "certificateIssuer",
    )
    for field in exact_fields:
        if certificate[field] != expected[field]:
            if field in CERTIFICATE_DIGEST_FIELDS:
                raise Refusal("certificate-digest-mismatch")
            raise Refusal("certificate-claim-mismatch")
    validate_run_invocation(
        certificate["runInvocationURI"],
        expected["githubWorkflowRepository"],
        expected["run_id"],
        expected["run_attempt"],
    )
    return True


def validate_statement_predicate(predicate, expected, key_record, subject):
    if type(predicate) is not dict:
        raise Refusal("predicate-shape")
    required = {
        "schemaVersion",
        "profile",
        "role",
        "controlRepository",
        "controlSha",
        "controlRef",
        "runId",
        "runAttempt",
        "transferId",
        "keyRecordSha256",
        "subjectSha256",
        "nonce",
    }
    if set(predicate) != required or "certificate" in predicate:
        raise Refusal("predicate-fields")
    role = predicate["role"]
    if role not in ALL_ROLES:
        raise Refusal("predicate-role")
    actual = {
        "schemaVersion": 1,
        "profile": expected["profile"],
        "role": expected["role"],
        "controlRepository": expected["repository"],
        "controlSha": expected["control_sha"],
        "controlRef": expected["ref"],
        "runId": str(_is_u64(expected["run_id"])),
        "runAttempt": str(_is_u32(expected["run_attempt"])),
        "transferId": expected["transfer_id"],
        "keyRecordSha256": hashlib.sha256(key_record).hexdigest(),
        "subjectSha256": hashlib.sha256(subject).hexdigest(),
        "nonce": role_nonce(key_record, role, subject),
    }
    if predicate != actual:
        raise Refusal("predicate-binding-mismatch")
    _runtime_hex(predicate["transferId"], 16, "predicate-transfer-id")
    _runtime_hex(predicate["keyRecordSha256"], 32, "predicate-key-digest")
    _runtime_hex(predicate["subjectSha256"], 32, "predicate-subject-digest")
    _runtime_hex(predicate["nonce"], 16, "predicate-nonce")
    return True


def validate_verified_statement(document, subject, predicate, expected_certificate, expected_binding):
    result, certificate, statement = verified_result(document)
    if validate_certificate(certificate, expected_certificate) is not True:
        raise Refusal("certificate-invalid")
    if statement.get("predicateType") != PREDICATE_TYPE:
        raise Refusal("predicate-type")
    signed_predicate = statement.get("predicate")
    if signed_predicate != predicate:
        raise Refusal("predicate-not-authenticated")
    subjects = statement.get("subject")
    if type(subjects) is not list or len(subjects) != 1 or type(subjects[0]) is not dict:
        raise Refusal("statement-subject-cardinality")
    digest = subjects[0].get("digest")
    expected_digest = hashlib.sha256(subject).hexdigest()
    if type(digest) is not dict or digest.get("sha256") != expected_digest:
        raise Refusal("statement-subject-digest")
    if set(digest) != {"sha256"}:
        raise Refusal("statement-subject-digest-fields")
    validate_statement_predicate(predicate, expected_binding, expected_binding["key_record"], subject)
    return result


def verify_workflow_bytes(root, profile, pinned=None):
    if profile not in CALLER_PROFILES:
        raise Refusal("profile-invalid")
    expected_pins = PINNED_WORKFLOW_SHA256 if pinned is None else pinned
    required_paths = profile_workflow_paths(profile)
    digests = {}
    for relative in required_paths:
        expected = expected_pins.get(relative)
        if type(expected) is not str or HEX_32.fullmatch(expected) is None:
            raise Refusal("workflow-pin-unresolved")
        path = Path(root) / relative
        try:
            stat = path.stat()
            if stat.st_size > MAX_FILE_BYTES or not path.is_file() or path.is_symlink():
                raise Refusal("workflow-file-size")
            content = path.read_bytes()
        except OSError:
            raise Refusal("workflow-file-unavailable")
        actual = hashlib.sha256(content).hexdigest()
        if actual != expected:
            raise Refusal("workflow-byte-mismatch")
        if not content.isascii():
            raise Refusal("workflow-non-ascii")
        digests[relative] = actual
    validate_workflow_graph(root, profile)
    return digests


CANDIDATE_CALLER_JOBS = (
    "settings", "windows-producer", "windows-verifier", "linux-fetch-encrypt", "capsule-attester",
    "verify-role-evidence", "audit",
)
CANDIDATE_ROLE_FILES = (
    (RECEIVER_WORKFLOW_PATH, "windows-candidate", "windows-2025", ("profile", "role", "mode", "source_sha")),
    (
        ROLE_PATHS["linux-fetch-encrypt"], "linux-fetch-encrypt", "ubuntu-24.04",
        ("profile", "mode", "source_sha", "base_sha", "base_branch", "fingerprint", "environment_name"),
    ),
    (ROLE_PATHS["capsule-attester"], "capsule-attester", "ubuntu-24.04", ("profile", "mode")),
)
FETCH_ENVIRONMENT_LINE = "    environment: ${{ inputs.mode == 'source' && 'linux-source-read' || '' }}"
ACTION_USE_PATTERN = re.compile(
    r"\s*uses:\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[a-f0-9]{40}\s+"
    + chr(35)
    + r"\s+v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?"
)


def _read_workflow_text(path, code):
    try:
        return Path(path).read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError):
        raise Refusal(code)


def _jobs_section(text):
    marker = "\njobs:\n"
    if marker not in text:
        raise Refusal("workflow-jobs-missing")
    return text.split(marker, 1)[1]


def _job_ids(text):
    return re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\n", _jobs_section(text))


def _job_block(text, job_id):
    found = re.search(
        r"(?ms)^  " + re.escape(job_id) + r":\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)", _jobs_section(text),
    )
    return None if found is None else found.group(1)


def _check_action_uses(text):
    for line in [item for item in text.splitlines() if re.match(r"\s*uses:\s+", item)]:
        if line.strip().startswith("uses: ./"):
            continue
        if ACTION_USE_PATTERN.fullmatch(line) is None:
            raise Refusal("action-pin-invalid")


def _check_candidate_inputs(workflow, names):
    opening = "    inputs:\n"
    start = workflow.find(opening)
    end = workflow.find("\npermissions: {}\n")
    if start < 0 or end < start:
        raise Refusal("role-input-schema")
    block = workflow[start + len(opening):end + 1]
    entries = re.findall(r"(?ms)^      ([A-Za-z0-9_]+):\n((?:        [^\n]*\n)+)", block)
    if tuple(name for name, unused in entries) != names:
        raise Refusal("role-input-schema")
    if sum(8 + len(name) + len(body) for name, body in entries) != len(block):
        raise Refusal("role-input-schema")
    for name, body in entries:
        required = "true" if name == "profile" else "false"
        if (body.count("        required: ") != 1 or "        required: " + required + "\n" not in body
                or body.count("        type: string\n") != 1):
            raise Refusal("role-input-schema")


def validate_candidate_caller(root):
    caller = _read_workflow_text(Path(root) / CALLER_PROFILES["candidate"]["path"], "caller-workflow-unavailable")
    if caller.count("workflow_dispatch:") != 1 or "workflow_call:" in caller:
        raise Refusal("caller-trigger-shape")
    permissions = "\npermissions: {}\n"
    if ("\non:\n  workflow_dispatch:\n" not in caller or caller.count(permissions) != 1
            or "\njobs:\n" not in caller or caller.index(permissions) > caller.index("\njobs:\n")):
        raise Refusal("caller-extra-trigger")
    if any(ref not in caller for ref in profile_refs("candidate")) or "matrix:" in caller or "strategy:" in caller:
        raise Refusal("caller-guard-shape")
    if "source-read" in caller or "secrets: inherit" in caller:
        raise Refusal("caller-source-path")
    if re.search(r"(?m)^\s*continue-on-error\s*:", caller):
        raise Refusal("caller-masked-failure")
    _check_action_uses(caller)
    if tuple(_job_ids(caller)) != CANDIDATE_CALLER_JOBS:
        raise Refusal("role-job-cardinality")
    for role in CANDIDATE_ROLES:
        block = _job_block(caller, role)
        if block is None or block.count("uses: ./" + ROLE_PATHS[role] + "\n") != 1:
            raise Refusal("role-call-cardinality")
        if "      profile: candidate\n" not in block:
            raise Refusal("role-fixed-input")
        if role in ("windows-producer", "windows-verifier") and (
                "      role: " + role[len("windows-"):] + "\n" not in block):
            raise Refusal("role-fixed-input")
        needs = re.search(r"(?m)^    needs:\n((?:      - [A-Za-z0-9_-]+\n)+)", block)
        items = [] if needs is None else re.findall(r"- ([A-Za-z0-9_-]+)", needs.group(1))
        if block.count("needs:") != 1:
            items = []
        if role == "capsule-attester":
            if items != ["settings", "linux-fetch-encrypt"]:
                raise Refusal("attester-order")
        elif items != ["settings"]:
            raise Refusal("handoff-start-order")
    for path in sorted(set(ROLE_PATHS[role] for role in CANDIDATE_ROLES)):
        expected = 2 if path == RECEIVER_WORKFLOW_PATH else 1
        if caller.count("uses: ./" + path + "\n") != expected:
            raise Refusal("role-call-cardinality")


def validate_candidate_role_files(root):
    for relative, job_id, runner, names in CANDIDATE_ROLE_FILES:
        workflow = _read_workflow_text(Path(root) / relative, "role-workflow-unavailable")
        if workflow.count("workflow_call:") != 1:
            raise Refusal("role-trigger-shape")
        _check_candidate_inputs(workflow, names)
        if workflow.count("uses: actions/attest@") != 1:
            raise Refusal("role-sign-step-cardinality")
        if _job_ids(workflow) != [job_id]:
            raise Refusal("role-job-cardinality")
        if "    runs-on: " + runner + "\n" not in workflow:
            raise Refusal("role-runner")
        if "matrix:" in workflow or "strategy:" in workflow:
            raise Refusal("role-matrix")
        if "uses: ./.github/workflows/" in workflow or "workflow_dispatch:" in workflow:
            raise Refusal("role-nested-call")
        environments = re.findall(r"(?m)^ *environment:.*$", workflow)
        if relative == ROLE_PATHS["linux-fetch-encrypt"]:
            if environments != [FETCH_ENVIRONMENT_LINE]:
                raise Refusal("role-source-path")
        elif "source-read" in workflow:
            raise Refusal("role-source-path")
        if "secrets: inherit" in workflow:
            raise Refusal("role-source-path")
        if re.search(r"(?m)^\s*continue-on-error\s*:", workflow):
            raise Refusal("role-masked-failure")
        if set(re.findall(r"(?m)^\s+([a-z-]+): write$", workflow)) - {"id-token", "attestations"}:
            raise Refusal("role-permissions")
        _check_action_uses(workflow)
        condition = re.search(r"(?m)^    if: (.*)$", _job_block(workflow, job_id) or "")
        if condition is None or "inputs.profile == 'candidate'" not in condition.group(1):
            raise Refusal("role-fixed-input")
    return True


def validate_candidate_graph(root):
    validate_candidate_caller(root)
    validate_candidate_role_files(root)
    return True


def profile_workflow_paths(profile):
    paths = [CALLER_PROFILES[profile]["path"]]
    for role in profile_roles(profile):
        if ROLE_PATHS[role] not in paths:
            paths.append(ROLE_PATHS[role])
    return tuple(paths)


def validate_workflow_graph(root, profile):
    if profile == "candidate":
        return validate_candidate_graph(root)
    caller_path = Path(root) / CALLER_PROFILES[profile]["path"]
    try:
        caller = caller_path.read_text(encoding="ascii")
    except (OSError, UnicodeDecodeError):
        raise Refusal("caller-workflow-unavailable")
    if caller.count("workflow_dispatch:") != 1 or "workflow_call:" in caller:
        raise Refusal("caller-trigger-shape")
    if "on:\n  workflow_dispatch:\npermissions: {}\n" not in caller:
        raise Refusal("caller-extra-trigger")
    if ("refs/heads/main" not in caller or CALLER_PROFILES[profile]["ref"] not in caller
            or "matrix:" in caller or "strategy:" in caller):
        raise Refusal("caller-guard-shape")
    if "source-read" in caller or "secrets: inherit" in caller:
        raise Refusal("caller-source-path")
    if re.search(r"(?m)^\s*continue-on-error\s*:", caller):
        raise Refusal("caller-masked-failure")
    for line in [item for item in caller.splitlines() if re.match(r"\s*uses:\s+", item)]:
        if line.strip().startswith("uses: ./"):
            continue
        if re.fullmatch(
            r"\s*uses:\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[a-f0-9]{40}\s+"
            + chr(35)
            + r"\s+v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?",
            line,
        ) is None:
            raise Refusal("action-pin-invalid")
    for role in ROLE_ORDER:
        path = ROLE_PATHS[role]
        local_call = "uses: ./%s" % path
        if caller.count(local_call) != 1:
            raise Refusal("role-call-cardinality")
        caller_job = re.search(
            r"(?ms)^  " + re.escape(role) + r":\n(.*?)(?=^  [A-Za-z0-9_-]+:\n|\Z)",
            caller,
        )
        if caller_job is None or "profile: " + profile not in caller_job.group(1):
            raise Refusal("role-fixed-input")
        if role in ("windows-receiver", "linux-fetch-encrypt") and re.search(
            r"(?m)^    needs:", caller_job.group(1)
        ):
            raise Refusal("handoff-start-order")
        if role == "capsule-attester" and "needs:\n      - linux-fetch-encrypt\n" not in caller_job.group(1):
            raise Refusal("attester-order")
    for role in ROLE_ORDER:
        relative = ROLE_PATHS[role]
        path = Path(root) / relative
        try:
            workflow = path.read_text(encoding="ascii")
        except (OSError, UnicodeDecodeError):
            raise Refusal("role-workflow-unavailable")
        if workflow.count("workflow_call:") != 1:
            raise Refusal("role-trigger-shape")
        if workflow.count("      profile:") != 1 or workflow.count("        required: true") != 1 or workflow.count("        type: string") != 1:
            raise Refusal("role-input-schema")
        if workflow.count("uses: actions/attest@") != 1:
            raise Refusal("role-sign-step-cardinality")
        if workflow.count("jobs:\n  ") != 1 or "\njobs:\n  %s:\n" % role not in workflow:
            raise Refusal("role-job-cardinality")
        if "    runs-on: " + ROLE_RUNNERS[role] + "\n" not in workflow:
            raise Refusal("role-runner")
        if "matrix:" in workflow or "strategy:" in workflow:
            raise Refusal("role-matrix")
        if "uses: ./.github/workflows/" in workflow or "workflow_dispatch:" in workflow:
            raise Refusal("role-nested-call")
        if "source-read" in workflow or "secrets: inherit" in workflow:
            raise Refusal("role-source-path")
        if re.search(r"(?m)^\s*continue-on-error\s*:", workflow):
            raise Refusal("role-masked-failure")
        if "contents: write" in workflow or "actions: write" in workflow or "checks: write" in workflow:
            raise Refusal("role-permissions")
        action_lines = [line for line in workflow.splitlines() if re.match(r"\s*uses:\s+", line)]
        for line in action_lines:
            if line.strip().startswith("uses: ./"):
                continue
            if re.fullmatch(
                r"\s*uses:\s+[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[a-f0-9]{40}\s+"
                + chr(35)
                + r"\s+v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?",
                line,
            ) is None:
                raise Refusal("action-pin-invalid")
    return True


def validate_call_graph(graph, profile):
    if profile not in CALLER_PROFILES or type(graph) is not dict:
        raise Refusal("call-graph-shape")
    if set(graph) != {"caller", "roles"}:
        raise Refusal("call-graph-fields")
    caller = graph["caller"]
    if type(caller) is not dict or set(caller) != {"path", "ref", "call_sites", "source_access"}:
        raise Refusal("call-graph-caller")
    profile_data = CALLER_PROFILES[profile]
    profile_set = PROFILE_ROLES[profile]
    if caller["path"] != profile_data["path"] or caller["ref"] not in profile_data["refs"]:
        raise Refusal("call-graph-profile")
    if caller["source_access"] is not False:
        raise Refusal("call-graph-source-access")
    calls = caller["call_sites"]
    if type(calls) is not list or len(calls) != len(profile_set):
        raise Refusal("call-site-cardinality")
    conditions = (None, "mode-bound") if profile == "candidate" else (None, "main-only")
    observed = []
    for call in calls:
        expected_keys = {"role", "uses", "profile", "matrix", "dynamic", "condition"}
        if type(call) is not dict or set(call) != expected_keys:
            raise Refusal("call-site-shape")
        role = call["role"]
        if role not in profile_set or call["uses"] != ROLE_PATHS[role]:
            raise Refusal("call-site-role")
        if call["profile"] != profile or call["matrix"] is not False or call["dynamic"] is not False:
            raise Refusal("call-site-dynamic")
        if call["condition"] not in conditions:
            raise Refusal("call-site-condition")
        observed.append(role)
    if tuple(sorted(observed)) != tuple(sorted(profile_set)) or len(set(observed)) != len(profile_set):
        raise Refusal("call-site-duplicate")
    roles = graph["roles"]
    if type(roles) is not list or len(roles) != len(profile_set):
        raise Refusal("callee-cardinality")
    role_names = []
    for callee in roles:
        expected_keys = {"role", "path", "jobs", "sign_steps", "nested_calls", "matrix", "dynamic"}
        if type(callee) is not dict or set(callee) != expected_keys:
            raise Refusal("callee-shape")
        role = callee["role"]
        if role not in profile_set or callee["path"] != ROLE_PATHS[role]:
            raise Refusal("callee-role")
        expected_job = "windows-candidate" if profile == "candidate" and role in WINDOWS_ROLES else role
        if callee["jobs"] != [expected_job] or callee["sign_steps"] != ["attest-role-statement"]:
            raise Refusal("callee-job-or-sign-step")
        if callee["nested_calls"] != [] or callee["matrix"] is not False or callee["dynamic"] is not False:
            raise Refusal("callee-dynamic")
        role_names.append(role)
    if len(set(role_names)) != len(profile_set) or set(role_names) != set(profile_set):
        raise Refusal("callee-duplicate")
    return True


def wrap_api_pages(kind, pages, run_id, run_attempt, head_sha):
    if kind not in ("jobs", "artifacts") or type(pages) is not list or not pages:
        raise Refusal("api-pages-shape")
    if type(head_sha) is not str or HEX_20.fullmatch(head_sha) is None:
        raise Refusal("api-head-sha")
    key = kind
    wrapped = []
    total = None
    seen = 0
    for index, page in enumerate(pages, 1):
        if type(page) is not dict or type(page.get(key)) is not list:
            raise Refusal("api-page-shape")
        if len(page[key]) > 100:
            raise Refusal("api-page-count")
        reported = _is_u64(page.get("total_count"), positive=False)
        if total is None:
            total = reported
        if reported != total:
            raise Refusal("api-page-count")
        if index < len(pages) and len(page[key]) != 100:
            raise Refusal("api-pagination-incomplete")
        seen += len(page[key])
        wrapped.append({
            "page": index,
            "next_page": index + 1 if index < len(pages) else None,
            "total_count": reported,
            key: page[key],
        })
    expected_pages = max(1, (total + 99) // 100)
    if seen != total or len(pages) != expected_pages:
        raise Refusal("api-pagination-incomplete")
    return {
        "kind": kind,
        "complete": True,
        "total_count": total,
        "run_id": str(_is_u64(run_id)),
        "run_attempt": str(_is_u32(run_attempt)),
        "head_sha": head_sha,
        "pages": wrapped,
    }


def provider_start_uri(subject_digest):
    if type(subject_digest) is not str or HEX_32.fullmatch(subject_digest) is None:
        raise Refusal("provider-subject")
    return ("https:" + chr(47) * 2 + "api.github.com/repos/" + CONTROL_REPOSITORY
            + "/attestations/sha256:" + subject_digest + "?per_page=100")


def validate_provider_uri(uri, subject_digest, initial=False):
    if (type(uri) is not str or len(uri) > 2048 or
            any(ord(character) < 33 or ord(character) > 126 for character in uri)):
        raise Refusal("provider-cursor-uri")
    try:
        parts = urlsplit(uri)
    except ValueError:
        raise Refusal("provider-cursor-uri")
    expected_path = "/repos/" + CONTROL_REPOSITORY + "/attestations/sha256:" + subject_digest
    if (parts.scheme != "https" or parts.netloc != "api.github.com" or
            parts.path != expected_path or parts.fragment):
        raise Refusal("provider-cursor-uri")
    if re.search(r"%(?![a-fA-F0-9]{2})", parts.query) is not None:
        raise Refusal("provider-cursor-query")
    try:
        pairs = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        raise Refusal("provider-cursor-query")
    query = dict(pairs)
    if len(query) != len(pairs) or set(query) - {"per_page", "after", "before"}:
        raise Refusal("provider-cursor-query")
    if query.get("per_page") not in (None, "100"):
        raise Refusal("provider-page-size")
    cursors = set(query) & {"after", "before"}
    if initial:
        if uri != provider_start_uri(subject_digest):
            raise Refusal("provider-start-uri")
    elif len(cursors) != 1 or not query[next(iter(cursors))] or len(query[next(iter(cursors))]) > 512:
        raise Refusal("provider-cursor-query")
    return uri


def _split_provider_link_parts(value, separator, angle_brackets=False):
    parts = []
    start = 0
    quoted = False
    escaped = False
    in_angle = False
    for index, character in enumerate(value):
        if escaped:
            escaped = False
            continue
        if quoted:
            if character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
            continue
        if character == '"':
            quoted = True
            continue
        if angle_brackets:
            if character == "<":
                if in_angle:
                    raise Refusal("provider-link-shape")
                in_angle = True
            elif character == ">":
                if not in_angle:
                    raise Refusal("provider-link-shape")
                in_angle = False
        if character == separator and not in_angle:
            parts.append(value[start:index])
            start = index + 1
    if quoted or escaped or in_angle:
        raise Refusal("provider-link-shape")
    parts.append(value[start:])
    return parts


def _provider_link_parameter(raw):
    match = re.fullmatch(
        r'([A-Za-z0-9!$%&\'*+.^_`|~-]+)[ \t]*=[ \t]*(?:"((?:[^"\\]|\\.)*)"|([A-Za-z0-9!$%&\'*+.^_`|~:/?@-]+))',
        raw,
    )
    if match is None:
        raise Refusal("provider-link-shape")
    name = match.group(1).lower()
    value = match.group(2) if match.group(2) is not None else match.group(3)
    if match.group(2) is not None:
        unescaped = []
        position = 0
        while position < len(value):
            character = value[position]
            if character == "\\":
                position += 1
                if position == len(value) or value[position] not in ('"', "\\"):
                    raise Refusal("provider-link-shape")
                character = value[position]
            unescaped.append(character)
            position += 1
        value = "".join(unescaped)
    if name == "" or value is None:
        raise Refusal("provider-link-shape")
    return name, value


def _provider_link_entry(raw, subject_digest, relations):
    entry = raw.strip(" \t")
    if not entry.startswith("<"):
        raise Refusal("provider-link-shape")
    closing = entry.find(">")
    if closing <= 1 or "<" in entry[1:closing]:
        raise Refusal("provider-link-shape")
    uri = entry[1:closing]
    if (not uri.isascii() or any(ord(character) < 33 or ord(character) > 126 for character in uri)
            or any(character in uri for character in '<>"\\{}|^`')
            or re.search(r"%(?![a-fA-F0-9]{2})", uri) is not None):
        raise Refusal("provider-link-shape")
    try:
        urlsplit(uri)
    except ValueError:
        raise Refusal("provider-link-shape")
    suffix = entry[closing + 1:]
    parameters = _split_provider_link_parts(suffix, ";")
    if parameters[0].strip(" \t"):
        raise Refusal("provider-link-shape")
    values = {}
    for raw_parameter in parameters[1:]:
        parameter = raw_parameter.strip(" \t")
        if not parameter:
            raise Refusal("provider-link-shape")
        name, value = _provider_link_parameter(parameter)
        if name in values:
            raise Refusal("provider-link-shape")
        values[name] = value
    relation_value = values.get("rel")
    if relation_value is None:
        raise Refusal("provider-link-shape")
    entry_relations = re.split(r"[ \t]+", relation_value.strip(" \t"))
    if not entry_relations or any(re.fullmatch(r"[a-z]+", relation) is None for relation in entry_relations):
        raise Refusal("provider-link-shape")
    next_uri = None
    for relation in entry_relations:
        if relation not in ("next", "last", "prev", "first", "deprecation") or relation in relations:
            raise Refusal("provider-link-shape")
        relations.add(relation)
        if relation != "deprecation":
            checked_uri = validate_provider_uri(uri, subject_digest)
            if relation == "next":
                next_uri = checked_uri
    return next_uri


def provider_next_link(headers, subject_digest):
    links = [value for name, value in headers if name.lower() == "link"]
    if not links:
        return None
    entries = []
    for value in links:
        entries.extend(_split_provider_link_parts(value, ",", angle_brackets=True))
    relations = set()
    next_uri = None
    for entry in entries:
        entry_next_uri = _provider_link_entry(entry, subject_digest, relations)
        if entry_next_uri is not None:
            next_uri = entry_next_uri
    return next_uri


def parse_provider_http(payload, subject_digest, run_id, run_attempt, head_sha):
    if type(payload) is not bytes or len(payload) > MAX_JSON_BYTES:
        raise Refusal("provider-http-size")
    try:
        source = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise Refusal("provider-http-encoding")
    decoder = json.JSONDecoder(object_pairs_hook=_pairs_without_duplicates)
    pages = []
    position = 0
    request_uri = provider_start_uri(subject_digest)
    visited = set()
    while position < len(source):
        if len(pages) >= MAX_PROVIDER_PAGES or request_uri in visited:
            raise Refusal("provider-pagination-limit")
        visited.add(request_uri)
        boundary = re.search(r"\r?\n\r?\n", source[position:])
        if boundary is None:
            raise Refusal("provider-http-headers")
        header_end = position + boundary.start()
        header_lines = source[position:header_end].splitlines()
        if not header_lines or re.fullmatch(r"HTTP/(?:1\.[01]|2(?:\.0)?) 200(?: .*)?", header_lines[0]) is None:
            raise Refusal("provider-http-status")
        headers = []
        for line in header_lines[1:]:
            if ":" not in line:
                raise Refusal("provider-http-header")
            name, value = line.split(":", 1)
            if re.fullmatch(r"[A-Za-z0-9-]+", name) is None:
                raise Refusal("provider-http-header")
            headers.append((name, value.strip()))
        next_uri = provider_next_link(headers, subject_digest)
        body_start = header_end + len(boundary.group(0))
        while body_start < len(source) and source[body_start] in "\r\n\t ":
            body_start += 1
        try:
            document, body_end = decoder.raw_decode(source, body_start)
        except (json.JSONDecodeError, Refusal):
            raise Refusal("provider-http-body")
        if type(document) is not dict or set(document) != {"attestations"} or type(document["attestations"]) is not list:
            raise Refusal("provider-page-shape")
        if len(document["attestations"]) > 100:
            raise Refusal("provider-page-size")
        pages.append({"page": len(pages) + 1, "request_uri": request_uri,
                      "next_uri": next_uri, "attestations": document["attestations"]})
        position = body_end
        while position < len(source) and source[position] in "\r\n\t ":
            position += 1
        if next_uri is None:
            if position != len(source):
                raise Refusal("provider-after-terminal")
            break
        if position == len(source):
            raise Refusal("provider-pagination-incomplete")
        request_uri = next_uri
    if not pages or pages[-1]["next_uri"] is not None:
        raise Refusal("provider-pagination-incomplete")
    return {"kind": "attestations", "complete": True,
            "observed_count": sum(len(page["attestations"]) for page in pages),
            "run_id": str(_is_u64(run_id)), "run_attempt": str(_is_u32(run_attempt)),
            "head_sha": validate_commit_sha(head_sha), "subject_digest": subject_digest,
            "http_sha256": hashlib.sha256(payload).hexdigest(), "pages": pages}


def _validate_snapshot(snapshot, kind, run_id, run_attempt, head_sha):
    if type(snapshot) is not dict:
        raise Refusal("api-snapshot-shape")
    required_top = {"kind", "complete", "run_id", "run_attempt", "head_sha", "pages"}
    if kind == "attestations":
        required_top.update(("subject_digest", "observed_count", "http_sha256"))
    else:
        required_top.add("total_count")
    if set(snapshot) != required_top or snapshot["kind"] != kind or snapshot["complete"] is not True:
        raise Refusal("api-snapshot-incomplete")
    if kind == "attestations" and (type(snapshot["http_sha256"]) is not str or
                                    HEX_32.fullmatch(snapshot["http_sha256"]) is None):
        raise Refusal("provider-http-digest")
    if _is_u64(snapshot["run_id"]) != _is_u64(run_id):
        raise Refusal("api-run-mismatch")
    if _is_u32(snapshot["run_attempt"]) != _is_u32(run_attempt):
        raise Refusal("api-attempt-mismatch")
    if snapshot["head_sha"] != validate_commit_sha(head_sha):
        raise Refusal("api-head-mismatch")
    pages = snapshot["pages"]
    if type(pages) is not list or not pages:
        raise Refusal("api-pages-missing")
    row_key = "jobs" if kind == "jobs" else "artifacts" if kind == "artifacts" else "attestations"
    total = _is_u64(snapshot["observed_count" if kind == "attestations" else "total_count"], positive=False)
    rows = []
    subject_digest = snapshot.get("subject_digest") if kind == "attestations" else None
    next_uri = provider_start_uri(subject_digest) if kind == "attestations" else None
    visited = set()
    for index, page in enumerate(pages, 1):
        expected_fields = {"page", row_key}
        if kind == "attestations":
            expected_fields.update(("request_uri", "next_uri"))
        else:
            expected_fields.add("next_page")
            expected_fields.add("total_count")
        if type(page) is not dict or set(page) != expected_fields:
            raise Refusal("api-page-fields")
        if type(page["page"]) is not int or page["page"] != index:
            raise Refusal("api-page-order")
        if type(page[row_key]) is not list:
            raise Refusal("api-pagination-incomplete")
        if len(page[row_key]) > 100:
            raise Refusal("api-page-count")
        if kind == "attestations":
            if (next_uri is None or page["request_uri"] != next_uri or
                    next_uri in visited):
                raise Refusal("provider-cursor-chain")
            visited.add(next_uri)
            next_uri = page["next_uri"]
            if next_uri is not None:
                validate_provider_uri(next_uri, subject_digest)
            if (index < len(pages)) != (next_uri is not None):
                raise Refusal("provider-pagination-incomplete")
        else:
            expected_next = index + 1 if index < len(pages) else None
            if page["next_page"] != expected_next:
                raise Refusal("api-pagination-incomplete")
            if _is_u64(page["total_count"], positive=False) != total:
                raise Refusal("api-page-count")
            if index < len(pages) and len(page[row_key]) != 100:
                raise Refusal("api-pagination-incomplete")
        rows.extend(page[row_key])
    expected_pages = max(1, (total + 99) // 100)
    if len(rows) != total or (kind != "attestations" and len(pages) != expected_pages):
        raise Refusal("api-pagination-incomplete")
    if kind == "attestations" and len(pages) > MAX_PROVIDER_PAGES:
        raise Refusal("provider-pagination-limit")
    return rows


def _api_numeric_id(value, code):
    try:
        return _is_u64(value)
    except Refusal:
        raise Refusal(code)


def validate_api_runner(job, role):
    name = job.get("runner_name")
    labels = job.get("labels")
    if type(name) is not str or not name or len(name) > 256:
        raise Refusal("api-runner-name")
    if (type(labels) is not list or not labels or
            any(type(label) is not str or not label or len(label) > 128 for label in labels) or
            len(set(labels)) != len(labels) or ROLE_RUNNERS[role] not in labels):
        raise Refusal("api-runner-label")
    return name, labels


def validate_jobs_snapshot(snapshot, run_id, run_attempt, head_sha, api_name_pins, roles=None):
    jobs = _validate_snapshot(snapshot, "jobs", run_id, run_attempt, head_sha)
    roles = ROLE_ORDER if roles is None else tuple(roles)
    if type(api_name_pins) is not dict or set(api_name_pins) != set(roles):
        raise Refusal("api-job-map-unresolved")
    if any(type(name) is not str or not name for name in api_name_pins.values()):
        raise Refusal("api-job-map-unresolved")
    if len(set(api_name_pins.values())) != len(roles):
        raise Refusal("api-job-map-duplicate")
    role_markers = tuple(roles)
    relevant = [
        job for job in jobs
        if type(job) is dict
        and type(job.get("name")) is str
        and any(marker in job["name"] for marker in role_markers)
    ]
    if len(relevant) != len(roles):
        raise Refusal("api-role-job-cardinality")
    result = {}
    identifiers = set()
    check_run_ids = set()
    names = set()
    for role in roles:
        matches = [job for job in jobs if type(job) is dict and job.get("name") == api_name_pins[role]]
        if len(matches) != 1:
            raise Refusal("api-role-job-not-unique")
        job = matches[0]
        if any(type(job.get(field)) is not str for field in ("name", "head_sha", "status")):
            raise Refusal("api-job-fields")
        if job["head_sha"] != head_sha or _api_numeric_id(job.get("run_id"), "api-job-run-id") != _is_u64(run_id):
            raise Refusal("api-job-run-binding")
        if "run_attempt" in job and _is_u32(job["run_attempt"]) != _is_u32(run_attempt):
            raise Refusal("api-job-attempt-binding")
        job_id = _api_numeric_id(job.get("id"), "api-job-id")
        check_url = job.get("check_run_url")
        if type(check_url) is not str:
            raise Refusal("api-check-run-url")
        check_match = re.search(r"/check-runs/([1-9][0-9]*)\Z", check_url)
        if check_match is None:
            raise Refusal("api-check-run-id")
        check_id = _api_numeric_id(check_match.group(1), "api-check-run-id")
        expected_check_url = (
            "https:" + chr(47) * 2 + "api.github.com/repos/" + CONTROL_REPOSITORY
            + "/check-runs/" + str(check_id)
        )
        if check_url != expected_check_url:
            raise Refusal("api-check-run-url")
        if job_id in identifiers or check_id in check_run_ids or job["name"] in names:
            raise Refusal("api-job-duplicate")
        identifiers.add(job_id)
        check_run_ids.add(check_id)
        names.add(job["name"])
        if job["status"] not in ("queued", "in_progress", "completed"):
            raise Refusal("api-job-status")
        conclusion = job.get("conclusion")
        if job["status"] == "completed" and conclusion not in (
            "success", "failure", "cancelled", "skipped", "timed_out", "action_required", "neutral", "stale"
        ):
            raise Refusal("api-job-conclusion")
        if job["status"] != "completed" and conclusion is not None:
            raise Refusal("api-job-conclusion")
        runner_name, labels = validate_api_runner(job, role)
        steps = job.get("steps")
        if type(steps) is not list:
            raise Refusal("api-job-steps")
        numbers = set()
        step_names = set()
        for step in steps:
            if type(step) is not dict or type(step.get("name")) is not str:
                raise Refusal("api-step-fields")
            number = _is_u32(step.get("number"))
            if number in numbers or step["name"] in step_names:
                raise Refusal("api-step-duplicate")
            numbers.add(number)
            step_names.add(step["name"])
            if step.get("status") not in ("queued", "in_progress", "completed"):
                raise Refusal("api-step-status")
            if step.get("status") == "completed" and step.get("conclusion") not in (
                "success", "failure", "cancelled", "skipped", "timed_out", "action_required", "neutral", "stale"
            ):
                raise Refusal("api-step-conclusion")
        result[role] = {
            "job_id": job_id,
            "check_run_id": check_id,
            "name": job["name"],
            "runner_name": runner_name,
            "labels": labels,
            "status": job["status"],
            "conclusion": conclusion,
            "steps": steps,
        }
    if names != set(api_name_pins.values()):
        raise Refusal("api-extra-role-job")
    return result


def validate_role_job(snapshot, run_id, run_attempt, head_sha, role, api_name, allowed_statuses):
    jobs = _validate_snapshot(snapshot, "jobs", run_id, run_attempt, head_sha)
    if role not in ALL_ROLES or type(api_name) is not str or not api_name:
        raise Refusal("api-job-map-unresolved")
    matches = [job for job in jobs if type(job) is dict and job.get("name") == api_name]
    role_marked = [
        job for job in jobs
        if type(job) is dict and type(job.get("name")) is str and role in job["name"]
    ]
    if len(matches) != 1 or len(role_marked) != 1 or role_marked[0] is not matches[0]:
        raise Refusal("api-role-job-not-unique")
    job = matches[0]
    if _api_numeric_id(job.get("run_id"), "api-job-run-id") != _is_u64(run_id):
        raise Refusal("api-job-run-binding")
    if "run_attempt" in job and _is_u32(job["run_attempt"]) != _is_u32(run_attempt):
        raise Refusal("api-job-attempt-binding")
    if job.get("head_sha") != head_sha:
        raise Refusal("api-job-identity")
    validate_api_runner(job, role)
    if job.get("status") not in allowed_statuses:
        raise Refusal("api-job-status")
    _api_numeric_id(job.get("id"), "api-job-id")
    check_url = job.get("check_run_url")
    check_match = re.search(r"/check-runs/([1-9][0-9]*)\Z", check_url) if type(check_url) is str else None
    if check_match is None:
        raise Refusal("api-check-run-id")
    check_id = _api_numeric_id(check_match.group(1), "api-check-run-id")
    expected_check_url = (
        "https:" + chr(47) * 2 + "api.github.com/repos/" + CONTROL_REPOSITORY
        + "/check-runs/" + str(check_id)
    )
    if check_url != expected_check_url:
        raise Refusal("api-check-run-url")
    if job.get("status") == "completed" and job.get("conclusion") not in (
        "success", "failure", "cancelled", "skipped", "timed_out", "action_required", "neutral", "stale"
    ):
        raise Refusal("api-job-conclusion")
    if job.get("status") != "completed" and job.get("conclusion") is not None:
        raise Refusal("api-job-conclusion")
    if type(job.get("steps")) is not list:
        raise Refusal("api-job-steps")
    step_numbers = set()
    step_names = set()
    for step in job["steps"]:
        if type(step) is not dict or type(step.get("name")) is not str:
            raise Refusal("api-step-fields")
        number = _is_u32(step.get("number"))
        if number in step_numbers or step["name"] in step_names:
            raise Refusal("api-step-duplicate")
        step_numbers.add(number)
        step_names.add(step["name"])
        if step.get("status") not in ("queued", "in_progress", "completed"):
            raise Refusal("api-step-status")
        if step.get("status") == "completed" and step.get("conclusion") not in (
            "success", "failure", "cancelled", "skipped", "timed_out", "action_required", "neutral", "stale"
        ):
            raise Refusal("api-step-conclusion")
        if step.get("status") != "completed" and step.get("conclusion") is not None:
            raise Refusal("api-step-conclusion")
    return job


def validate_linux_revocation_evidence(
    snapshot,
    run_id,
    run_attempt,
    head_sha,
    linux_api_name,
    step_name_pins,
    step_ordinal_pins,
    log_sections,
    other_log_sections,
):
    job = validate_role_job(
        snapshot,
        run_id,
        run_attempt,
        head_sha,
        "linux-fetch-encrypt",
        linux_api_name,
        ("completed",),
    )
    if job.get("conclusion") != "success":
        raise Refusal("linux-job-not-successful")
    expected_ids = {"revoke-source-token", "verify-token-rejection"}
    if type(step_name_pins) is not dict or set(step_name_pins) != expected_ids:
        raise Refusal("linux-step-map-unresolved")
    if type(step_ordinal_pins) is not dict or set(step_ordinal_pins) != expected_ids:
        raise Refusal("linux-step-ordinal-unresolved")
    if any(type(value) is not str or not value for value in step_name_pins.values()):
        raise Refusal("linux-step-map-unresolved")
    if any(type(value) is not int or value < 1 or value > MAX_U32 for value in step_ordinal_pins.values()):
        raise Refusal("linux-step-ordinal-unresolved")
    if len(set(step_name_pins.values())) != 2 or len(set(step_ordinal_pins.values())) != 2:
        raise Refusal("linux-step-map-duplicate")
    if type(log_sections) is not dict or set(log_sections) != expected_ids:
        raise Refusal("linux-log-sections-unresolved")
    if type(other_log_sections) is not list or any(type(value) is not str for value in other_log_sections):
        raise Refusal("other-log-sections-unresolved")
    by_name = {}
    for step in job["steps"]:
        if type(step) is not dict or type(step.get("name")) is not str:
            raise Refusal("linux-step-fields")
        if step["name"] in step_name_pins.values():
            by_name.setdefault(step["name"], []).append(step)
    for step_id in expected_ids:
        api_name = step_name_pins[step_id]
        matches = by_name.get(api_name, [])
        if len(matches) != 1:
            raise Refusal("linux-step-not-unique")
        step = matches[0]
        if _is_u32(step.get("number")) != step_ordinal_pins[step_id]:
            raise Refusal("linux-step-ordinal")
        if step.get("status") != "completed" or step.get("conclusion") != "success":
            raise Refusal("linux-step-not-successful")
        if type(log_sections[step_id]) is not str:
            raise Refusal("linux-log-section-type")
    line = "handoff-revocation=confirmed"
    verification_log = log_sections["verify-token-rejection"]
    count = sum(1 for item in verification_log.splitlines() if item == line)
    other_count = sum(
        1
        for step_id in expected_ids - {"verify-token-rejection"}
        for item in log_sections[step_id].splitlines()
        if item == line
    )
    outside_count = sum(
        1
        for section in other_log_sections
        for item in section.splitlines()
        if item == line
    )
    if count != 1 or other_count != 0 or outside_count != 0:
        raise Refusal("linux-revocation-line")
    return job


def validate_repository_metadata(document, repository):
    if type(document) is not dict:
        raise Refusal("repository-metadata-shape")
    if document.get("full_name") != repository or document.get("visibility") != "public":
        raise Refusal("repository-metadata-name-or-visibility")
    repository_id = _is_u64(document.get("id"))
    owner = document.get("owner")
    owner_id = document.get("owner_id")
    if type(owner) is dict:
        owner_id = owner.get("id")
    return repository_id, _is_u64(owner_id)


def validate_run_metadata(document, profile, repository, run_id, run_attempt, head_sha, repository_id):
    if profile not in CALLER_PROFILES or type(document) is not dict:
        raise Refusal("run-metadata-shape")
    profile_data = CALLER_PROFILES[profile]
    if _api_numeric_id(document.get("id"), "run-id") != _is_u64(run_id):
        raise Refusal("run-id-mismatch")
    if _is_u32(document.get("run_attempt")) != _is_u32(run_attempt):
        raise Refusal("run-attempt-mismatch")
    if document.get("head_sha") != validate_commit_sha(head_sha):
        raise Refusal("run-head-sha-mismatch")
    if document.get("path") != profile_data["path"] or document.get("event") != "workflow_dispatch":
        raise Refusal("run-workflow-identity")
    if document.get("head_branch") not in [ref[len("refs/heads/"):] for ref in profile_data["refs"]]:
        raise Refusal("run-ref-mismatch")
    api_repository = document.get("repository")
    if type(api_repository) is not dict or api_repository.get("full_name") != repository:
        raise Refusal("run-repository-name")
    if _api_numeric_id(api_repository.get("id"), "run-repository-id") != _is_u64(repository_id):
        raise Refusal("run-repository-id")
    if document.get("status") not in ("queued", "in_progress", "completed"):
        raise Refusal("run-status")
    if document.get("status") == "completed" and document.get("conclusion") not in (
        "success", "failure", "cancelled", "skipped", "timed_out", "action_required", "neutral", "stale"
    ):
        raise Refusal("run-conclusion")
    return True


def select_artifact(pages, repository_run_id, run_id, run_attempt, role):
    snapshot = pages
    if type(snapshot) is list:
        wrapped = wrap_api_pages("artifacts", snapshot, run_id, run_attempt, "0" * 40)
        rows = _validate_snapshot(wrapped, "artifacts", run_id, run_attempt, "0" * 40)
    else:
        rows = _validate_snapshot(snapshot, "artifacts", run_id, run_attempt, snapshot.get("head_sha"))
    matches = []
    prefix = "role-statement-" + role + "-" + str(_is_u64(run_id)) + "-" + str(_is_u32(run_attempt)) + "-"
    for artifact in rows:
        if type(artifact) is not dict or type(artifact.get("name")) is not str:
            raise Refusal("artifact-fields")
        if not artifact["name"].startswith(prefix):
            continue
        match = ARTIFACT_NAME.fullmatch(artifact["name"])
        if match is None or match.group(1) != role:
            raise Refusal("artifact-name")
        workflow_run = artifact.get("workflow_run")
        if type(workflow_run) is not dict or _api_numeric_id(workflow_run.get("id"), "artifact-run-id") != _is_u64(repository_run_id):
            raise Refusal("artifact-run-binding")
        _validate_artifact_metadata(artifact)
        matches.append(artifact)
    if len(matches) != 1:
        raise Refusal("artifact-not-unique")
    selected = matches[0]
    selected_match = ARTIFACT_NAME.fullmatch(selected["name"])
    return dict(_validate_artifact_metadata(selected),
                id=_api_numeric_id(selected.get("id"), "artifact-id"),
                name=selected["name"], transfer_id=selected_match.group(4))


def select_artifact_name(pages, repository_run_id, run_id, run_attempt, role):
    return select_artifact(pages, repository_run_id, run_id, run_attempt, role)["name"]


def _validate_artifact_metadata(artifact, now=None):
    if artifact.get("expired") is not False:
        raise Refusal("artifact-expired")
    size = _is_u64(artifact.get("size_in_bytes"), positive=False)
    if size <= 0 or size > MAX_JSON_BYTES * 4:
        raise Refusal("artifact-size")
    digest = artifact.get("digest")
    if type(digest) is not str or re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None:
        raise Refusal("artifact-digest")
    created = artifact.get("created_at")
    expires = artifact.get("expires_at")
    if type(created) is not str or type(expires) is not str:
        raise Refusal("artifact-retention")
    try:
        created_at = datetime.datetime.fromisoformat(created.replace("Z", "+00:00"))
        expires_at = datetime.datetime.fromisoformat(expires.replace("Z", "+00:00"))
    except ValueError:
        raise Refusal("artifact-retention")
    if created_at.tzinfo is None or expires_at.tzinfo is None:
        raise Refusal("artifact-retention")
    duration = (expires_at - created_at).total_seconds()
    current = datetime.datetime.now(datetime.timezone.utc) if now is None else now
    if duration <= 0 or duration > 86400 or expires_at <= current:
        raise Refusal("artifact-retention")
    return {"expired": False, "digest": digest, "size_in_bytes": size,
            "created_at": created, "expires_at": expires}


def validated_archive_members(artifact, archive_bytes):
    if type(artifact) is not dict or type(archive_bytes) is not bytes:
        raise Refusal("artifact-archive-shape")
    metadata = _validate_artifact_metadata(artifact)
    if len(archive_bytes) != metadata["size_in_bytes"]:
        raise Refusal("artifact-archive-size")
    if "sha256:" + hashlib.sha256(archive_bytes).hexdigest() != metadata["digest"]:
        raise Refusal("artifact-archive-digest")
    expected = {"subject.bin", "predicate.json", "bundle.json"}
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            members = archive.infolist()
            if len(members) != len(expected) or {item.filename for item in members} != expected:
                raise Refusal("artifact-archive-members")
            if any(item.is_dir() or item.file_size > MAX_JSON_BYTES or
                   (item.external_attr >> 16) & 0o170000 == 0o120000 for item in members):
                raise Refusal("artifact-archive-member-shape")
            if sum(item.file_size for item in members) > MAX_JSON_BYTES * 2:
                raise Refusal("artifact-archive-uncompressed-size")
            content = {item.filename: archive.read(item) for item in members}
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError):
        raise Refusal("artifact-archive-invalid")
    if not content["subject.bin"] or not content["predicate.json"] or not content["bundle.json"]:
        raise Refusal("artifact-archive-empty")
    return content


def read_bounded_archive(path, expected_size):
    size = _is_u64(expected_size, positive=False)
    if size <= 0 or size > MAX_JSON_BYTES * 4:
        raise Refusal("artifact-size")
    try:
        archive_path = Path(path)
        if not archive_path.is_file() or archive_path.is_symlink() or archive_path.stat().st_size != size:
            raise Refusal("artifact-archive-size")
        with archive_path.open("rb") as source:
            payload = source.read(size + 1)
    except OSError:
        raise Refusal("artifact-archive-unavailable")
    if len(payload) != size:
        raise Refusal("artifact-archive-size")
    return payload


def extract_artifact_archive(artifact, archive_bytes, directory):
    content = validated_archive_members(artifact, archive_bytes)
    destination = Path(directory)
    destination.mkdir(parents=True, exist_ok=False)
    for name, payload in content.items():
        (destination / name).write_bytes(payload)
    return content


def validate_artifact_inventory(snapshot, run_id, run_attempt, head_sha, expected_roles=ROLE_ORDER, profile=None):
    artifacts = _validate_snapshot(snapshot, "artifacts", run_id, run_attempt, head_sha)
    names = set()
    identifiers = set()
    by_role = {}
    for artifact in artifacts:
        if type(artifact) is not dict:
            raise Refusal("artifact-fields")
        name = artifact.get("name")
        identifier = _api_numeric_id(artifact.get("id"), "artifact-id")
        if type(name) is not str or name in names or identifier in identifiers:
            raise Refusal("artifact-duplicate")
        names.add(name)
        identifiers.add(identifier)
        match = ARTIFACT_NAME.fullmatch(name)
        if match is None:
            if name.startswith("role-statement-"):
                raise Refusal("artifact-unexpected-role")
            continue
        role, artifact_run, artifact_attempt, transfer = match.groups()
        if artifact_run != str(_is_u64(run_id)) or artifact_attempt != str(_is_u32(run_attempt)):
            raise Refusal("artifact-attempt-binding")
        workflow_run = artifact.get("workflow_run")
        if type(workflow_run) is not dict or _api_numeric_id(workflow_run.get("id"), "artifact-run-id") != _is_u64(run_id):
            raise Refusal("artifact-run-binding")
        metadata = _validate_artifact_metadata(artifact)
        by_role.setdefault(role, []).append(dict(metadata, id=identifier, name=name, transfer_id=transfer))
    if set(by_role) != set(expected_roles) or any(len(by_role[role]) != 1 for role in expected_roles):
        raise Refusal("artifact-role-cardinality")
    if profile == "candidate":
        anchor = by_role["windows-producer"][0]["transfer_id"] if "windows-producer" in by_role else None
        for role in expected_roles:
            if role in ("linux-fetch-encrypt", "capsule-attester") and by_role[role][0]["transfer_id"] != anchor:
                raise Refusal("artifact-transfer-mismatch")
        if "windows-verifier" in by_role and by_role["windows-verifier"][0]["transfer_id"] == anchor:
            raise Refusal("artifact-transfer-reused")
        return by_role
    transfers = {by_role[role][0]["transfer_id"] for role in expected_roles}
    if len(transfers) != 1:
        raise Refusal("artifact-transfer-mismatch")
    return by_role


def validate_attestation_inventory(rows, subject_digests, expected_roles=ROLE_ORDER):
    if type(rows) is not list:
        raise Refusal("attestation-rows")
    if type(subject_digests) is not dict or set(subject_digests) != set(expected_roles):
        raise Refusal("attestation-subject-map")
    seen = set()
    by_role = {}
    for row in rows:
        if type(row) is not dict:
            raise Refusal("attestation-fields")
        role = row.get("role")
        digest = row.get("subject_digest")
        statement_digest = row.get("statement_digest")
        if role not in expected_roles or digest != subject_digests[role]:
            raise Refusal("attestation-unexpected")
        if type(statement_digest) is not str or HEX_32.fullmatch(statement_digest) is None:
            raise Refusal("attestation-statement-digest")
        key = (role, statement_digest)
        if key in seen:
            continue
        seen.add(key)
        by_role.setdefault(role, set()).add(statement_digest)
    if set(by_role) != set(expected_roles) or any(len(by_role[role]) != 1 for role in expected_roles):
        raise Refusal("attestation-cardinality")
    return {role: next(iter(by_role[role])) for role in expected_roles}


def signed_statement_payload(bundle_document):
    if type(bundle_document) is not dict:
        raise Refusal("bundle-shape")
    envelope = bundle_document.get("dsseEnvelope")
    if type(envelope) is not dict or type(envelope.get("payload")) is not str:
        raise Refusal("bundle-envelope")
    if envelope.get("payloadType") != "application/vnd.in-toto+json":
        raise Refusal("bundle-payload-type")
    try:
        payload = base64.b64decode(envelope["payload"].encode("ascii"), validate=True)
    except (ValueError, UnicodeEncodeError):
        raise Refusal("bundle-payload-encoding")
    if base64.b64encode(payload).decode("ascii") != envelope["payload"]:
        raise Refusal("bundle-payload-canonical")
    statement = load_json_bytes(payload)
    if type(statement) is not dict or type(statement.get("subject")) is not list or len(statement["subject"]) != 1:
        raise Refusal("bundle-statement-shape")
    predicate = statement.get("predicate")
    if type(predicate) is not dict or "certificate" in predicate:
        raise Refusal("bundle-predicate")
    return payload, statement


def normalize_provider_attestations(snapshot, subject_digest, role_expectations,
                                    verified_documents, run_id, run_attempt, head_sha):
    if type(subject_digest) is not str or HEX_32.fullmatch(subject_digest) is None:
        raise Refusal("provider-subject")
    if type(snapshot) is not dict or snapshot.get("subject_digest") != subject_digest:
        raise Refusal("provider-subject-mismatch")
    rows = _validate_snapshot(
        snapshot,
        "attestations",
        run_id,
        run_attempt,
        head_sha,
    )
    if type(role_expectations) is not dict or type(verified_documents) is not list or len(verified_documents) != len(rows):
        raise Refusal("provider-verification-missing")
    normalized = []
    for row, verified in zip(rows, verified_documents):
        if type(row) is not dict or type(row.get("bundle")) is not dict:
            raise Refusal("provider-attestation-shape")
        payload, statement = signed_statement_payload(row["bundle"])
        subjects = statement["subject"]
        digest = subjects[0].get("digest") if type(subjects[0]) is dict else None
        if type(digest) is not dict or digest.get("sha256") != subject_digest or set(digest) != {"sha256"}:
            raise Refusal("provider-subject-mismatch")
        unused_result, certificate, verified_statement = verified_result(verified)
        matches = [
            candidate for candidate, expected in role_expectations.items()
            if certificate.get("buildSignerURI") == expected["certificate"]["buildSignerURI"]
            and certificate.get("subjectAlternativeName") == expected["certificate"]["subjectAlternativeName"]
        ]
        if len(matches) > 1:
            matches = [
                candidate for candidate in matches
                if hashlib.sha256(role_expectations[candidate]["subject"]).hexdigest() == subject_digest
            ]
        if len(matches) != 1:
            raise Refusal("provider-verified-role-identity")
        role = matches[0]
        predicate = statement.get("predicate")
        if type(predicate) is not dict or predicate.get("role") != role:
            raise Refusal("provider-role-predicate")
        expected = role_expectations[role]
        statement_digest = hashlib.sha256(payload).hexdigest()
        if (predicate != expected["predicate"] or
                statement_digest != expected["statement_digest"] or
                hashlib.sha256(expected["subject"]).hexdigest() != subject_digest):
            raise Refusal("provider-role-predicate")
        if verified_statement != statement:
            raise Refusal("provider-verified-statement-mismatch")
        validate_verified_statement(verified, expected["subject"], expected["predicate"],
                                    expected["certificate"], expected["binding"])
        normalized.append({"role": role, "subject_digest": subject_digest,
                           "statement_digest": statement_digest})
    return normalized


def _hex_text(value, length, code):
    if type(value) is not str or re.fullmatch(r"[a-f0-9]{%d}" % length, value) is None:
        raise Refusal(code)
    return value


def canonical_json_subject(document):
    try:
        encoded = (json.dumps(
            document, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ) + "\n").encode("ascii")
    except (TypeError, ValueError):
        raise Refusal("binding-encoding")
    if len(encoded) > BINDING_MAX_BYTES:
        raise Refusal("binding-size")
    return encoded


def _binding_fields(document, keys):
    if type(document) is not dict or set(document) != keys:
        raise Refusal("binding-fields")
    if type(document["schema"]) is not int or document["schema"] != 1:
        raise Refusal("binding-schema")
    for name in ("source_sha", "tree_id"):
        _hex_text(document[name], 40, "binding-hex")
    for name in (
        "capsule_producer_sha256", "capsule_verifier_sha256", "key_record_producer_sha256",
        "key_record_verifier_sha256", "lock_sha256", "manifest_sha256",
    ):
        _hex_text(document[name], 64, "binding-hex")
    if document["revocation"] != "confirmed":
        raise Refusal("binding-revocation")
    return document


def parse_binding_subject(subject, attested=False):
    if type(subject) is not bytes or len(subject) > BINDING_MAX_BYTES:
        raise Refusal("binding-size")
    document = load_json_bytes(subject, BINDING_MAX_BYTES)
    _binding_fields(document, ATTESTED_KEYS if attested else BINDING_KEYS)
    if attested:
        if document["kind"] != "attested":
            raise Refusal("binding-kind")
        _hex_text(document["linux_subject_sha256"], 64, "binding-hex")
    if canonical_json_subject(document) != subject:
        raise Refusal("binding-not-canonical")
    return document


def build_binding_subject(producer_record, verifier_record, producer_capsule, verifier_capsule,
                          source_sha, tree_id, lock_sha256, manifest_sha256):
    document = {
        "capsule_producer_sha256": producer_capsule,
        "capsule_verifier_sha256": verifier_capsule,
        "key_record_producer_sha256": hashlib.sha256(producer_record).hexdigest(),
        "key_record_verifier_sha256": hashlib.sha256(verifier_record).hexdigest(),
        "lock_sha256": lock_sha256,
        "manifest_sha256": manifest_sha256,
        "revocation": "confirmed",
        "schema": 1,
        "source_sha": source_sha,
        "tree_id": tree_id,
    }
    _binding_fields(document, BINDING_KEYS)
    return canonical_json_subject(document)


def build_attested_subject(linux_subject):
    document = dict(parse_binding_subject(linux_subject))
    document["kind"] = "attested"
    document["linux_subject_sha256"] = hashlib.sha256(linux_subject).hexdigest()
    return canonical_json_subject(document)


def _check_candidate_subject(role, signed_subject, records, linux_subject):
    if role == "linux-fetch-encrypt":
        document = parse_binding_subject(signed_subject)
        for short in ("producer", "verifier"):
            held = records.get("windows-" + short)
            if held is None or document["key_record_%s_sha256" % short] != hashlib.sha256(held).hexdigest():
                raise Refusal("binding-key-record-mismatch")
        return
    if linux_subject is None:
        raise Refusal("linux-statement-missing")
    if signed_subject != build_attested_subject(linux_subject):
        raise Refusal("attested-subject-mismatch")


def _read_regular(path, limit, code):
    try:
        item = Path(path)
        if item.is_symlink() or not item.is_file() or item.stat().st_size > limit:
            raise Refusal(code)
        return item.read_bytes()
    except (OSError, TypeError):
        raise Refusal(code)


def _file_digest(path, code):
    digest = hashlib.sha256()
    try:
        item = Path(path)
        if item.is_symlink() or not item.is_file():
            raise Refusal(code)
        with item.open("rb") as source:
            while True:
                block = source.read(HASH_BLOCK_BYTES)
                if not block:
                    break
                digest.update(block)
    except (OSError, TypeError):
        raise Refusal(code)
    return digest.hexdigest()


def validate_revocation_receipt(path, ref, control_sha, run_id, run_attempt):
    if ref == "refs/heads/main":
        if path is not None:
            raise Refusal("revocation-receipt-forbidden")
        return "confirmed"
    if ref != "refs/heads/untrusted":
        raise Refusal("prepare-ref")
    if path is None:
        raise Refusal("revocation-receipt-required")
    document = load_json_bytes(_read_regular(path, 4096, "revocation-receipt-unavailable"), 4096)
    if (type(document) is not dict
            or type(document.get("schema_version")) is not int or document["schema_version"] != 1
            or document.get("status") != "confirmed"
            or document.get("rejected_after_revoke") is not True
            or document.get("control_sha") != control_sha
            or document.get("run_id") != str(_is_u64(run_id))
            or document.get("run_attempt") != str(_is_u32(run_attempt))):
        raise Refusal("revocation-receipt-invalid")
    return "confirmed"


def validate_role_artifact_set(
    profile,
    repository,
    ref,
    control_sha,
    run_id,
    run_attempt,
    repository_id,
    owner_id,
    artifact_map,
    evidence_root,
    digest_pins,
    required_roles=None,
):
    profile_set = PROFILE_ROLES.get(profile, ROLE_ORDER)
    required_roles = profile_set if required_roles is None else required_roles
    if type(artifact_map) is not dict or set(artifact_map) != set(required_roles):
        raise Refusal("role-artifact-map")
    if type(digest_pins) is not dict or set(digest_pins) != set(profile_set):
        raise Refusal("certificate-digest-profile-unresolved")
    record = None
    records = {}
    linux_subject = None
    role_subjects = {}
    role_predicates = {}
    artifact_records = []
    provider_expectations = {}
    for role in required_roles:
        role_digest_pins = digest_pins[role]
        if type(role_digest_pins) is not dict:
            raise Refusal("certificate-digest-profile-unresolved")
        artifact = artifact_map[role]
        if type(artifact) is not dict or set(artifact) != {
            "id", "name", "transfer_id", "expired", "digest", "size_in_bytes", "created_at", "expires_at"
        }:
            raise Refusal("role-artifact-fields")
        directory = Path(evidence_root) / artifact["name"]
        archive_bytes = read_bounded_archive(
            Path(evidence_root) / (artifact["name"] + ".zip"),
            artifact["size_in_bytes"],
        )
        archived = validated_archive_members(artifact, archive_bytes)
        expected_names = {"subject.bin", "predicate.json", "bundle.json", "verified.json"}
        try:
            actual_names = {item.name for item in directory.iterdir() if item.is_file()}
        except OSError:
            raise Refusal("role-artifact-unavailable")
        if not expected_names.issubset(actual_names):
            raise Refusal("role-artifact-files")
        subject_path = directory / "subject.bin"
        bundle_path = directory / "bundle.json"
        predicate_path = directory / "predicate.json"
        verified_path = directory / "verified.json"
        try:
            signed_subject = subject_path.read_bytes()
            bundle_bytes = bundle_path.read_bytes()
        except OSError:
            raise Refusal("role-artifact-unavailable")
        for name, payload in archived.items():
            try:
                if (directory / name).read_bytes() != payload:
                    raise Refusal("role-artifact-archive-mismatch")
            except OSError:
                raise Refusal("role-artifact-unavailable")
        if len(signed_subject) > 4096 or len(bundle_bytes) <= 0 or len(bundle_bytes) > MAX_JSON_BYTES:
            raise Refusal("role-artifact-size")
        predicate = load_json_file(predicate_path)
        verified = load_json_file(verified_path)
        if profile == "candidate":
            if role in ("windows-producer", "windows-verifier"):
                validate_key_record(signed_subject, repository_id, control_sha, run_id, run_attempt,
                                    repository + "/" + CALLER_PROFILES[profile]["path"] + "@" + ref,
                                    allow_any_point=True)
                if signed_subject in records.values():
                    raise Refusal("receiver-records-identical")
                records[role] = signed_subject
                if role == "windows-producer":
                    record = signed_subject
                predicate_record = signed_subject
            else:
                if record is None:
                    raise Refusal("receiver-statement-missing")
                _check_candidate_subject(role, signed_subject, records, linux_subject)
                if role == "linux-fetch-encrypt":
                    linux_subject = signed_subject
                predicate_record = record
        else:
            if role == "windows-receiver":
                record = signed_subject
                validate_key_record(record, repository_id, control_sha, run_id, run_attempt,
                                    repository + "/" + CALLER_PROFILES[profile]["path"] + "@" + ref)
            elif record is None:
                raise Refusal("receiver-statement-missing")
            if record is None:
                raise Refusal("receiver-statement-missing")
            if role != "windows-receiver" and signed_subject != make_synthetic_capsule(record):
                raise Refusal("capsule-subject-mismatch")
            predicate_record = record
        expected_predicate = make_predicate(
            profile,
            role,
            repository,
            control_sha,
            ref,
            run_id,
            run_attempt,
            predicate_record,
            signed_subject,
        )
        if predicate != expected_predicate or artifact["transfer_id"] != expected_predicate["transferId"]:
            raise Refusal("role-predicate-mismatch")
        certificate_expected = certificate_expectations(
            profile,
            repository,
            ref,
            control_sha,
            run_id,
            run_attempt,
            repository_id,
            owner_id,
            role,
            ROLE_RUNNERS[role],
            role_digest_pins,
        )
        expected_binding = {
            "profile": profile,
            "role": role,
            "repository": repository,
            "control_sha": control_sha,
            "ref": ref,
            "run_id": run_id,
            "run_attempt": run_attempt,
            "transfer_id": expected_predicate["transferId"],
            "key_record": predicate_record,
        }
        result, unused_certificate, verified_statement = verified_result(verified)
        if type(result.get("statement")) is not dict:
            raise Refusal("verified-statement-missing")
        bundle_document = load_json_bytes(bundle_bytes)
        payload, bundle_statement = signed_statement_payload(bundle_document)
        if bundle_statement != verified_statement:
            raise Refusal("bundle-verified-statement-mismatch")
        validate_verified_statement(verified, signed_subject, predicate, certificate_expected, expected_binding)
        statement_digest = hashlib.sha256(payload).hexdigest()
        role_subjects[role] = hashlib.sha256(signed_subject).hexdigest()
        role_predicates[role] = predicate
        artifact_records.append({
            "role": role,
            "artifact_id": artifact["id"],
            "artifact_name": artifact["name"],
            "statement_digest": statement_digest,
        })
        provider_expectations[role] = {
            "subject": signed_subject,
            "predicate": predicate,
            "certificate": certificate_expected,
            "binding": expected_binding,
            "statement_digest": statement_digest,
        }
    if record is None:
        raise Refusal("receiver-statement-missing")
    return {
        "record": record,
        "predicates": role_predicates,
        "subject_digests": role_subjects,
        "artifact_records": artifact_records,
        "provider_expectations": provider_expectations,
    }


def verify_source_free_evidence(
    profile,
    repository,
    ref,
    control_sha,
    run_id,
    run_attempt,
    repository_metadata,
    run_metadata,
    jobs_snapshot,
    artifacts_snapshot,
    provider_snapshots,
    control_root,
    evidence_root,
    api_name_pins,
    digest_pins,
):
    repository_id, owner_id = validate_repository_metadata(repository_metadata, repository)
    validate_run_metadata(run_metadata, profile, repository, run_id, run_attempt, control_sha, repository_id)
    verify_workflow_bytes(control_root, profile)
    profile_set = profile_roles(profile)
    jobs = validate_jobs_snapshot(jobs_snapshot, run_id, run_attempt, control_sha, api_name_pins, profile_set)
    if any(job["status"] != "completed" or job["conclusion"] != "success" for job in jobs.values()):
        raise Refusal("role-job-not-successful")
    artifact_map = validate_artifact_inventory(
        artifacts_snapshot, run_id, run_attempt, control_sha, profile_set, profile)
    roles = validate_role_artifact_set(
        profile,
        repository,
        ref,
        control_sha,
        run_id,
        run_attempt,
        repository_id,
        owner_id,
        {role: artifact_map[role][0] for role in profile_set},
        Path(evidence_root) / "artifacts",
        digest_pins,
        profile_set,
    )
    reconcile_provider_evidence(roles, provider_snapshots, run_id, run_attempt,
                                control_sha, profile_set)
    return roles


def reconcile_provider_evidence(roles, provider_snapshots, run_id, run_attempt,
                                control_sha, expected_roles):
    distinct_subjects = set(roles["subject_digests"].values())
    if type(provider_snapshots) is not dict or set(provider_snapshots) != distinct_subjects:
        raise Refusal("provider-listing-unavailable")
    provider_records = []
    for subject_digest in sorted(distinct_subjects):
        provider = provider_snapshots[subject_digest]
        if type(provider) is not dict or set(provider) != {"snapshot", "verified"}:
            raise Refusal("provider-verification-missing")
        normalized = normalize_provider_attestations(
            provider["snapshot"],
            subject_digest,
            roles["provider_expectations"],
            provider["verified"],
            run_id,
            run_attempt,
            control_sha,
        )
        provider_records.extend(normalized)
    validate_attestation_inventory(provider_records, roles["subject_digests"], expected_roles)
    verify_statement_cardinality(roles["artifact_records"], provider_records, expected_roles)
    return provider_records


def verify_statement_cardinality(artifact_records, provider_records, expected_roles=ROLE_ORDER):
    if type(artifact_records) is not list or type(provider_records) is not list:
        raise Refusal("statement-inventory-shape")
    artifacts_seen = set()
    names_seen = set()
    statements = {role: set() for role in expected_roles}
    artifact_roles = {role: 0 for role in expected_roles}
    for record in artifact_records:
        if type(record) is not dict or set(record) != {"role", "artifact_id", "artifact_name", "statement_digest"}:
            raise Refusal("statement-artifact-fields")
        role = record["role"]
        if role not in expected_roles:
            raise Refusal("statement-artifact-role")
        artifact_id = _api_numeric_id(record["artifact_id"], "statement-artifact-id")
        name = record["artifact_name"]
        digest = record["statement_digest"]
        if type(name) is not str or not name or type(digest) is not str or HEX_32.fullmatch(digest) is None:
            raise Refusal("statement-artifact-binding")
        if artifact_id in artifacts_seen or name in names_seen:
            raise Refusal("statement-artifact-duplicate")
        artifacts_seen.add(artifact_id)
        names_seen.add(name)
        artifact_roles[role] += 1
        statements[role].add(digest)
    for record in provider_records:
        if type(record) is not dict or set(record) != {"role", "subject_digest", "statement_digest"}:
            raise Refusal("statement-provider-fields")
        role = record["role"]
        subject_digest = record["subject_digest"]
        digest = record["statement_digest"]
        if (role not in expected_roles or type(digest) is not str or HEX_32.fullmatch(digest) is None
                or type(subject_digest) is not str or HEX_32.fullmatch(subject_digest) is None):
            raise Refusal("statement-provider-binding")
        statements[role].add(digest)
    if any(artifact_roles[role] != 1 for role in expected_roles):
        raise Refusal("statement-artifact-cardinality")
    if any(len(statements[role]) != 1 for role in expected_roles):
        raise Refusal("statement-cardinality")
    return {role: next(iter(statements[role])) for role in expected_roles}


def verify_transition_evidence(
    gate, profile, repository, ref, control_sha, run_id, run_attempt,
    repository_metadata, run_metadata, jobs_snapshot, artifacts_snapshot,
    provider_snapshots, control_root, evidence_root, api_name_pins, digest_pins,
    step_name_pins=None, step_ordinal_pins=None, log_sections=None,
    other_log_sections=None,
):
    if gate not in ("A", "B") or profile not in CALLER_PROFILES:
        raise Refusal("transition-gate-invalid")
    repository_id, owner_id = validate_repository_metadata(repository_metadata, repository)
    validate_run_metadata(run_metadata, profile, repository, run_id, run_attempt,
                          control_sha, repository_id)
    verify_workflow_bytes(control_root, profile)
    if type(api_name_pins) is not dict or set(api_name_pins) != set(PROFILE_ROLES[profile]):
        raise Refusal("api-job-map-unresolved")
    required_roles = gate_roles(profile, gate)
    job_ids = set()
    check_urls = set()
    for role in required_roles:
        allowed_statuses = ("in_progress", "completed") if role in WINDOWS_ROLES else ("completed",)
        job = validate_role_job(jobs_snapshot, run_id, run_attempt, control_sha,
                                role, api_name_pins[role], allowed_statuses)
        if job["status"] == "completed" and job["conclusion"] != "success":
            raise Refusal("transition-role-job-not-successful")
        identifier = _api_numeric_id(job["id"], "api-job-id")
        if identifier in job_ids or job["check_run_url"] in check_urls:
            raise Refusal("transition-role-job-duplicate")
        job_ids.add(identifier)
        check_urls.add(job["check_run_url"])
    artifact_map = validate_artifact_inventory(
        artifacts_snapshot, run_id, run_attempt, control_sha, required_roles, profile)
    roles = {role: artifact_map[role][0] for role in required_roles}
    result = validate_role_artifact_set(
        profile, repository, ref, control_sha, run_id, run_attempt,
        repository_id, owner_id, roles, evidence_root, digest_pins,
        required_roles=required_roles,
    )
    if gate == "B":
        validate_linux_revocation_evidence(
            jobs_snapshot, run_id, run_attempt, control_sha,
            api_name_pins["linux-fetch-encrypt"], step_name_pins,
            step_ordinal_pins, log_sections, other_log_sections,
        )
    reconcile_provider_evidence(result, provider_snapshots, run_id, run_attempt,
                                control_sha, required_roles)
    return result


GATE_REQUIREMENTS = {
    "A": (
        "receiver_key_record_valid",
        "receiver_statement_valid",
        "receiver_subject_exact",
        "receiver_nonce_valid",
        "workflow_bytes_pinned",
        "receiver_job_unique",
    ),
    "B": (
        "gate_a_passed",
        "receiver_binding_valid",
        "capsule_subject_exact",
        "linux_statement_valid",
        "linux_job_completed_successfully",
        "revoke_step_completed_successfully",
        "verify_rejection_step_completed_successfully",
        "revocation_line_count",
    ),
    "C": (
        "gate_b_passed",
        "receiver_statement_valid",
        "linux_statement_valid",
        "attester_statement_valid",
        "capsule_subject_exact",
        "all_nonces_valid",
        "attester_job_completed_successfully",
        "signed_receipt_valid",
        "manifest_authenticated",
        "git_objects_validated",
    ),
    "D": (
        "gate_c_passed",
        "jobs_listing_complete",
        "artifacts_listing_complete",
        "attestations_listing_complete",
        "one_unique_job_per_role",
        "one_statement_per_role",
        "all_expected_jobs_successful",
        "fresh_transfer_binding",
        "all_remaining_evidence_valid",
        "post_run_revocation_confirmed",
    ),
}


def evaluate_gate(gate, evidence):
    if gate not in GATE_REQUIREMENTS or type(evidence) is not dict:
        raise Refusal("gate-invalid")
    if gate in ("C", "D"):
        raise Refusal("gate-evidence-not-implemented")
    raise Refusal("gate-boolean-evidence-untrusted")


def _write_json(path, value):
    Path(path).write_text(
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )


def _prepare_flags(arguments, profile, role, ref):
    provided = {name for name in PREPARE_FLAGS if getattr(arguments, name, None) is not None}
    if profile != "candidate":
        if provided & PREPARE_CANDIDATE_ONLY_FLAGS:
            raise Refusal("prepare-flag-profile")
        return provided
    required = set(PREPARE_ROLE_FLAGS[role])
    if role == "linux-fetch-encrypt" and ref == "refs/heads/untrusted":
        required.add("revocation_receipt")
    if required - provided:
        raise Refusal("prepare-flag-missing")
    if provided - required:
        raise Refusal("prepare-flag-foreign")
    return provided


def _candidate_records(arguments, repository_id, control_sha, run_id, run_attempt, workflow_ref):
    producer = _read_regular(arguments.receiver_record, KEY_RECORD_SIZE, "receiver-record-unavailable")
    verifier = _read_regular(arguments.verifier_record, KEY_RECORD_SIZE, "verifier-record-unavailable")
    for held in (producer, verifier):
        validate_key_record(held, repository_id, control_sha, run_id, run_attempt, workflow_ref,
                            allow_any_point=True)
    if producer == verifier:
        raise Refusal("receiver-records-identical")
    return producer, verifier


def prepare_subject(arguments):
    profile = arguments.profile
    role = arguments.role
    if profile not in CALLER_PROFILES or role not in profile_roles(profile):
        raise Refusal("prepare-profile-role")
    profile_data = CALLER_PROFILES[profile]
    if arguments.ref not in profile_data["refs"]:
        raise Refusal("prepare-ref")
    repository = arguments.repository
    if repository != CONTROL_REPOSITORY:
        raise Refusal("prepare-repository")
    owner, unused_name = _repo_parts(repository)
    repository_id = _is_u64(arguments.repository_id)
    control_sha = validate_commit_sha(arguments.control_sha)
    run_id = _is_u64(arguments.run_id)
    run_attempt = _is_u32(arguments.run_attempt)
    if arguments.runner != ROLE_RUNNERS[role]:
        raise Refusal("prepare-runner")
    workflow_ref = repository + "/" + profile_data["path"] + "@" + arguments.ref
    if arguments.workflow_ref != workflow_ref:
        raise Refusal("prepare-workflow-ref")
    _prepare_flags(arguments, profile, role, arguments.ref)
    allow_any = profile == "candidate"
    if profile == "candidate" and role in ("windows-producer", "windows-verifier"):
        point = _read_regular(arguments.public_point_file, 65, "public-point-unavailable")
        subject = make_key_record(
            repository_id, control_sha, run_id, run_attempt, workflow_ref, public_point=point,
        )
        key_record = subject
    elif profile == "candidate":
        key_record, verifier_record = _candidate_records(
            arguments, repository_id, control_sha, run_id, run_attempt, workflow_ref)
        producer_capsule = _file_digest(arguments.capsule_producer, "capsule-producer-unavailable")
        verifier_capsule = _file_digest(arguments.capsule_verifier, "capsule-verifier-unavailable")
        if role == "linux-fetch-encrypt":
            revocation = validate_revocation_receipt(
                arguments.revocation_receipt, arguments.ref, control_sha, run_id, run_attempt)
            if revocation != "confirmed":
                raise Refusal("binding-revocation")
            subject = build_binding_subject(
                key_record, verifier_record, producer_capsule, verifier_capsule,
                arguments.source_sha, arguments.tree_id, arguments.lock_sha256, arguments.manifest_sha256,
            )
        else:
            linux_bytes = _read_regular(arguments.linux_subject, BINDING_MAX_BYTES, "linux-subject-unavailable")
            document = parse_binding_subject(linux_bytes)
            if (document["key_record_producer_sha256"] != hashlib.sha256(key_record).hexdigest()
                    or document["key_record_verifier_sha256"] != hashlib.sha256(verifier_record).hexdigest()
                    or document["capsule_producer_sha256"] != producer_capsule
                    or document["capsule_verifier_sha256"] != verifier_capsule):
                raise Refusal("binding-mismatch")
            subject = build_attested_subject(linux_bytes)
    elif role == "windows-receiver":
        subject = make_key_record(
            repository_id,
            control_sha,
            run_id,
            run_attempt,
            workflow_ref,
        )
        key_record = subject
    else:
        if not arguments.receiver_record:
            raise Refusal("receiver-record-required")
        try:
            key_record = Path(arguments.receiver_record).read_bytes()
        except OSError:
            raise Refusal("receiver-record-unavailable")
        validate_key_record(
            key_record,
            repository_id,
            control_sha,
            run_id,
            run_attempt,
            workflow_ref,
        )
        subject = make_synthetic_capsule(key_record)
    predicate = make_predicate(
        profile,
        role,
        repository,
        control_sha,
        arguments.ref,
        run_id,
        run_attempt,
        key_record,
        subject,
    )
    record_info = validate_key_record(
        key_record,
        repository_id,
        control_sha,
        run_id,
        run_attempt,
        workflow_ref,
        allow_any_point=allow_any,
    )
    target = Path(arguments.output_directory)
    target.mkdir(parents=True, exist_ok=True)
    (target / "subject.bin").write_bytes(subject)
    _write_json(target / "predicate.json", predicate)
    output_path = os.environ.get("GITHUB_OUTPUT")
    if output_path:
        with open(output_path, "a", encoding="ascii", newline="\n") as output:
            output.write("transfer_id=" + record_info["transfer_id"] + "\n")
    print("subject=created role=%s bytes=%d sha256=%s" % (
        role,
        len(subject),
        hashlib.sha256(subject).hexdigest(),
    ))


def _read_pages_argument(path):
    raw = load_json_file(path)
    if type(raw) is dict and raw.get("complete") is True:
        return raw
    if type(raw) is not list or not raw:
        raise Refusal("api-pages-unavailable")
    return raw


def _cmd_wrap_pages(arguments):
    pages = load_json_file(arguments.input)
    if type(pages) is not list:
        raise Refusal("api-pages-shape")
    wrapped = wrap_api_pages(
        arguments.kind,
        pages,
        arguments.run_id,
        arguments.run_attempt,
        arguments.head_sha,
    )
    _write_json(arguments.output, wrapped)
    print("pages=wrapped kind=%s count=%d" % (arguments.kind, len(pages)))


def _cmd_wrap_provider_http(arguments):
    try:
        source = Path(arguments.input)
        if not source.is_file() or source.is_symlink() or source.stat().st_size > MAX_JSON_BYTES:
            raise Refusal("provider-http-size")
        payload = source.read_bytes()
    except OSError:
        raise Refusal("provider-http-unavailable")
    wrapped = parse_provider_http(payload, arguments.subject_digest, arguments.run_id,
                                  arguments.run_attempt, arguments.head_sha)
    _write_json(arguments.output, wrapped)
    print("provider=wrapped pages=%d" % len(wrapped["pages"]))


def _cmd_find_artifact(arguments):
    pages = _read_pages_argument(arguments.artifacts_file)
    if type(pages) is list:
        pages = wrap_api_pages("artifacts", pages, arguments.run_id, arguments.run_attempt, "0" * 40)
    artifact = select_artifact(
        pages,
        arguments.run_id,
        arguments.run_id,
        arguments.run_attempt,
        arguments.role,
    )
    print(artifact[arguments.field])


def _cmd_extract_artifact(arguments):
    pages = _read_pages_argument(arguments.artifacts_file)
    if type(pages) is list:
        pages = wrap_api_pages("artifacts", pages, arguments.run_id,
                               arguments.run_attempt, arguments.head_sha)
    artifact = select_artifact(pages, arguments.run_id, arguments.run_id,
                               arguments.run_attempt, arguments.role)
    archive = read_bounded_archive(arguments.archive_file, artifact["size_in_bytes"])
    extract_artifact_archive(artifact, archive, arguments.output_directory)
    print("artifact=extracted id=%d role=%s" % (artifact["id"], arguments.role))


def _cmd_export_provider(arguments):
    snapshot = load_json_file(arguments.snapshot)
    rows = _validate_snapshot(snapshot, "attestations", arguments.run_id,
                              arguments.run_attempt, arguments.head_sha)
    directory = Path(arguments.output_directory)
    directory.mkdir(parents=True, exist_ok=False)
    manifest = []
    for index, row in enumerate(rows, 1):
        if type(row) is not dict or type(row.get("bundle")) is not dict:
            raise Refusal("provider-attestation-shape")
        unused_payload, statement = signed_statement_payload(row["bundle"])
        predicate = statement.get("predicate")
        role = predicate.get("role") if type(predicate) is dict else None
        if role not in ALL_ROLES:
            raise Refusal("provider-role-predicate")
        _write_json(directory / ("bundle-%d.json" % index), row["bundle"])
        manifest.append("%d %s" % (index, role))
    (directory / "manifest.txt").write_text("\n".join(manifest) + "\n", encoding="ascii")


def _cmd_find_job(arguments):
    snapshot = load_json_file(arguments.jobs_file)
    role = arguments.role
    pins = API_JOB_NAME_PINS[arguments.profile]
    if role not in pins:
        raise Refusal("find-job-role")
    api_name = pins[role]
    if arguments.observe:
        jobs = _validate_snapshot(snapshot, "jobs", arguments.run_id,
                                  arguments.run_attempt, arguments.head_sha)
        matches = [job for job in jobs if type(job) is dict and
                   type(job.get("name")) is str and role in job["name"]]
        if len(matches) != 1:
            raise Refusal("observation-job-cardinality")
        api_name = matches[0]["name"]
    job = validate_role_job(snapshot, arguments.run_id, arguments.run_attempt,
                            arguments.head_sha, role, api_name, ("completed",))
    print(job["id"])


def _caret_form(match):
    return "^" + chr((ord(match.group(0)) + 64) % 128)


def _without_mark(text):
    return text[1:] if text.startswith(BYTE_ORDER_MARK) else text


def parse_linux_log_sections(log_text, job_name, step_names, markers=None):
    if type(log_text) is not str or type(job_name) is not str:
        raise Refusal("linux-log-shape")
    sections = {step_id: [] for step_id in step_names}
    other = []
    labels = []
    messages = []
    lines = log_text.splitlines()
    bare = bool(lines) and re.match(r"\d{4}-\d{2}-\d{2}T", _without_mark(lines[0])) is not None
    for line in lines:
        fields = [job_name, UNLABELED_LOG_STEP, line] if bare else line.split("\t", 2)
        if len(fields) != 3 or fields[0] != job_name:
            raise Refusal("linux-log-format")
        stamped = _without_mark(fields[2])
        match = re.fullmatch(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z)[ \t]+(.*)", stamped)
        if match is None:
            raise Refusal("linux-log-timestamp")
        try:
            datetime.datetime.strptime(match.group(1)[:19], "%Y-%m-%dT%H:%M:%S")
        except ValueError:
            raise Refusal("linux-log-timestamp")
        labels.append(fields[1])
        messages.append(CONTROL_BYTES.sub(_caret_form, match.group(2)))
    if messages and all(label == UNLABELED_LOG_STEP for label in labels):
        return _marker_log_sections(messages, step_names, markers)
    for label, message in zip(labels, messages):
        matches = [step_id for step_id, name in step_names.items() if label == name]
        if len(matches) == 1:
            sections[matches[0]].append(message)
        else:
            other.append(message)
    if any(not lines for lines in sections.values()):
        raise Refusal("linux-log-section-missing")
    return {"sections": {key: "\n".join(value) for key, value in sections.items()},
            "other": ["\n".join(other)]}


def _marker_log_sections(messages, step_names, markers=None):
    markers = LINUX_STEP_LOG_MARKERS if markers is None else markers
    blocks = []
    header = False
    for index, message in enumerate(messages):
        clean = ANSI_ESCAPE.sub("", message)
        if clean.startswith(LOG_GROUP_PREFIX):
            if header:
                blocks[-1]["nested"] = True
            blocks.append({"script": [], "output": [], "nested": False})
            header = True
        elif not blocks:
            continue
        elif header:
            if clean == LOG_GROUP_END:
                header = False
            else:
                blocks[-1]["script"].append(clean)
        else:
            blocks[-1]["output"].append(index)
    claimed = {}
    for step_id in step_names:
        marker = markers.get(step_id)
        found = [number for number, block in enumerate(blocks) if marker in block["script"]]
        if marker is None or not found:
            raise Refusal("linux-log-section-missing")
        if len(found) != 1:
            raise Refusal("linux-log-section-ambiguous")
        if blocks[found[0]]["nested"]:
            raise Refusal("linux-log-section-nested")
        claimed[step_id] = found[0]
    if len(set(claimed.values())) != len(claimed):
        raise Refusal("linux-log-section-ambiguous")
    owned = set()
    sections = {}
    for step_id, number in claimed.items():
        indexes = blocks[number]["output"]
        if not indexes:
            raise Refusal("linux-log-section-missing")
        owned.update(indexes)
        sections[step_id] = "\n".join(messages[index] for index in indexes)
    other = [message for index, message in enumerate(messages) if index not in owned]
    return {"sections": sections, "other": ["\n".join(other)]}


def _guard_error_class(stderr):
    text = stderr[:GUARD_STDERR_BYTES].decode("utf-8", "replace").lower()
    match = re.search(r"http ([0-9]{3})", text)
    if match is not None:
        status = match.group(1)
        if status[0] == "5":
            return "http-5xx"
        if status in GUARD_HTTP_CLASSES:
            return GUARD_HTTP_CLASSES[status]
    for needle, name in GUARD_STDERR_CLASSES:
        if needle in text:
            return name
    return "unclassified"


def _guard_run_once(command, output):
    try:
        with open(output, "wb") as handle:
            result = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=handle,
                                    stderr=subprocess.PIPE, timeout=GUARD_TIMEOUT_SECONDS,
                                    check=False)
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except OSError:
        return 127, "spawn-failed"
    if result.returncode == 0:
        return 0, ""
    return min(abs(result.returncode), 255), _guard_error_class(result.stderr or b"")


def _guard_attempts(command, output, label, attempts, pause):
    for attempt in range(1, attempts + 1):
        code, error_class = _guard_run_once(command, output)
        if code == 0:
            return 0, ""
        if attempt < attempts and error_class in GUARD_RETRY_CLASSES:
            print("probe=role-signer retry=%s attempt=%d class=%s" % (
                label, attempt, error_class))
            time.sleep(pause)
            continue
        break
    return code, error_class


def _guard_option(command, name):
    values = [command[index + 1] for index, item in enumerate(command[:-1]) if item == name]
    return values[0] if len(values) == 1 else None


def _guard_route_matches(route, command):
    match = GUARD_FALLBACK_ROUTE.fullmatch(route)
    if match is None:
        return False
    owner, repository, job = match.groups()
    if owner in (".", "..") or repository in (".", ".."):
        return False
    return (_guard_option(command, "--repo") == owner + "/" + repository
            and _guard_option(command, "--job") == job)


def _cmd_guard(arguments):
    command = list(arguments.guard_command)
    if command and command[0] == "--":
        command = command[1:]
    if not command or command[0] != "gh":
        raise Refusal("guard-command")
    if not 1 <= arguments.attempts <= 10 or not 0 <= arguments.pause <= 30:
        raise Refusal("guard-bounds")
    route = arguments.fallback_route
    if route is not None and not _guard_route_matches(route, command):
        raise Refusal("guard-command")
    label = arguments.label
    code, error_class = _guard_attempts(
        command, arguments.output, label, arguments.attempts, arguments.pause)
    if code != 0 and route is not None and error_class == "in-progress":
        print("probe=role-signer fallback=job-log-api")
        label = "job-log-fetch-failed"
        code, error_class = _guard_attempts(
            ["gh", "api", "--allow-escape-sequences", route], arguments.output, label, arguments.attempts,
            arguments.pause)
    if code == 0:
        return 0
    print("probe=role-signer result=unavailable reason=%s exit=%d class=%s" % (
        label, code, error_class))
    return 1


def _cmd_parse_linux_logs(arguments):
    jobs = load_json_file(arguments.jobs_file)
    api_name = API_JOB_NAME_PINS[arguments.profile]["linux-fetch-encrypt"]
    if arguments.observe:
        rows = _validate_snapshot(jobs, "jobs", arguments.run_id,
                                  arguments.run_attempt, arguments.head_sha)
        matches = [row for row in rows if type(row) is dict and
                   type(row.get("name")) is str and "linux-fetch-encrypt" in row["name"]]
        if len(matches) != 1:
            raise Refusal("observation-job-cardinality")
        api_name = matches[0]["name"]
    job = validate_role_job(jobs, arguments.run_id, arguments.run_attempt,
                            arguments.head_sha, "linux-fetch-encrypt",
                            api_name,
                            ("completed",))
    try:
        log_text = Path(arguments.input).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        raise Refusal("linux-log-unavailable")
    _write_json(arguments.output, parse_linux_log_sections(
        log_text, job["name"], API_LINUX_STEP_NAME_PINS[arguments.profile],
        LINUX_STEP_LOG_MARKERS_BY_PROFILE[arguments.profile]))


def _cmd_gate_transition(arguments):
    profile = arguments.profile
    if profile not in CALLER_PROFILES or arguments.repository != CONTROL_REPOSITORY:
        raise Refusal("transition-profile")
    if arguments.observe and not arguments.observation_output:
        raise Refusal("observation-output-missing")
    jobs = load_json_file(arguments.jobs_file)
    artifacts = load_json_file(arguments.artifacts_file)
    required_roles = gate_roles(profile, arguments.gate)
    artifact_map = validate_artifact_inventory(artifacts, arguments.run_id,
                                               arguments.run_attempt, arguments.control_sha,
                                               required_roles, profile)
    providers = load_provider_snapshots(artifact_map, required_roles,
                                        arguments.artifact_directory,
                                        arguments.provider_directory,
                                        arguments.run_id, arguments.run_attempt,
                                        arguments.control_sha)
    logs = load_json_file(arguments.linux_logs) if arguments.gate == "B" else None
    api_pins = API_JOB_NAME_PINS[profile]
    digest_pins = resolve_certificate_pins(profile, arguments.control_sha)
    ordinal_pins = API_LINUX_STEP_ORDINAL_PINS[profile]
    job_observations = {}
    if arguments.observe:
        api_pins, digest_pins, ordinal_pins, job_observations = observed_pins(
            jobs, artifact_map, arguments.artifact_directory, required_roles,
            arguments.run_id, arguments.run_attempt, arguments.control_sha, profile)
    verify_transition_evidence(
        arguments.gate, profile, arguments.repository, arguments.ref,
        arguments.control_sha, arguments.run_id, arguments.run_attempt,
        load_json_file(arguments.repository_metadata), load_json_file(arguments.run_metadata),
        jobs, artifacts, providers, arguments.root, arguments.artifact_directory,
        api_pins, digest_pins,
        API_LINUX_STEP_NAME_PINS[profile], ordinal_pins,
        logs.get("sections") if type(logs) is dict else None,
        logs.get("other") if type(logs) is dict else None,
    )
    if arguments.observe:
        _write_json(arguments.observation_output, {
            "profile": profile, "gate": arguments.gate, "acceptance": "blocked",
            "api_job_names": api_pins, "certificate_digests": digest_pins,
            "linux_step_ordinals": ordinal_pins,
            "api_job_identity": job_observations,
        })
        print("probe=role-signer observation=collected acceptance=blocked gate=%s" % arguments.gate)
    else:
        print("gate=%s result=verified profile=%s" % (arguments.gate, profile))


def observed_pins(jobs_snapshot, artifact_map, artifact_directory, roles,
                  run_id, run_attempt, control_sha, profile):
    if profile not in CALLER_PROFILES or not roles or set(roles) - set(PROFILE_ROLES[profile]):
        raise Refusal("observation-profile")
    jobs = _validate_snapshot(jobs_snapshot, "jobs", run_id, run_attempt, control_sha)
    api_pins = {role: None for role in PROFILE_ROLES[profile]}
    digest_pins = {role: None for role in PROFILE_ROLES[profile]}
    ordinal_pins = {step: None for step in API_LINUX_STEP_NAME_PINS[profile]}
    job_observations = {}
    for role in roles:
        matches = [job for job in jobs if type(job) is dict and
                   type(job.get("name")) is str and role in job["name"]]
        if len(matches) != 1:
            raise Refusal("observation-job-cardinality")
        name = matches[0]["name"]
        allowed = ("in_progress", "completed") if role in WINDOWS_ROLES else ("completed",)
        job = validate_role_job(jobs_snapshot, run_id, run_attempt, control_sha,
                                role, name, allowed)
        if job["status"] == "completed" and job["conclusion"] != "success":
            raise Refusal("observation-job-not-successful")
        api_pins[role] = name
        job_observations[role] = {
            "policy_caller_job_id": role,
            "policy_callee_job_id": "windows-candidate" if profile == "candidate" and role in WINDOWS_ROLES else role,
            "job_id": _api_numeric_id(job["id"], "api-job-id"),
            "check_run_id": _api_numeric_id(job["check_run_url"].rsplit("/", 1)[1],
                                            "api-check-run-id"),
            "check_run_url": job["check_run_url"],
            "runner_name": job["runner_name"], "labels": job["labels"]}
        if role == "linux-fetch-encrypt":
            for step_id, step_name in API_LINUX_STEP_NAME_PINS[profile].items():
                steps = [step for step in job["steps"] if step["name"] == step_name]
                if len(steps) != 1:
                    raise Refusal("observation-step-cardinality")
                ordinal_pins[step_id] = _is_u32(steps[0]["number"])
        artifact = artifact_map[role][0]
        verified = load_json_file(Path(artifact_directory) / artifact["name"] / "verified.json")
        certificate = verified_result(verified)[1]
        measured = {}
        for field in ("sourceRepositoryDigest", "buildSignerDigest", "buildConfigDigest"):
            value = certificate.get(field)
            if type(value) is not str or not value or len(value) > 512 or not value.isprintable():
                raise Refusal("observation-certificate-digest")
            measured[field] = value
        issuer = certificate.get("certificateIssuer")
        if type(issuer) is not str or not issuer or len(issuer) > 512:
            raise Refusal("observation-certificate-issuer")
        measured["certificateIssuer"] = issuer
        digest_pins[role] = measured
    return api_pins, digest_pins, ordinal_pins, job_observations


def load_provider_snapshots(artifact_map, roles, artifact_directory,
                            provider_directory, run_id, run_attempt, control_sha):
    provider_snapshots = {}
    for role in roles:
        artifact = artifact_map[role][0]
        subject_path = Path(artifact_directory) / artifact["name"] / "subject.bin"
        try:
            subject_digest = hashlib.sha256(subject_path.read_bytes()).hexdigest()
        except OSError:
            raise Refusal("provider-subject-unavailable")
        if subject_digest in provider_snapshots:
            continue
        snapshot = load_json_file(Path(provider_directory) /
                                  ("provider-" + subject_digest + ".json"))
        if type(snapshot) is not dict or snapshot.get("subject_digest") != subject_digest:
            raise Refusal("provider-subject-mismatch")
        try:
            source = Path(provider_directory) / ("provider-" + subject_digest + "-http.txt")
            if not source.is_file() or source.is_symlink() or source.stat().st_size > MAX_JSON_BYTES:
                raise Refusal("provider-http-size")
            raw_http = source.read_bytes()
        except OSError:
            raise Refusal("provider-http-unavailable")
        if parse_provider_http(raw_http, subject_digest, run_id,
                               run_attempt, control_sha) != snapshot:
            raise Refusal("provider-http-snapshot-mismatch")
        rows = _validate_snapshot(snapshot, "attestations", run_id,
                                  run_attempt, control_sha)
        directory = Path(provider_directory) / ("provider-" + subject_digest)
        verified = [load_json_file(directory / ("verified-%d.json" % index))
                    for index in range(1, len(rows) + 1)]
        if len(list(directory.glob("verified-*.json"))) != len(rows):
            raise Refusal("provider-verification-cardinality")
        provider_snapshots[subject_digest] = {"snapshot": snapshot, "verified": verified}
    return provider_snapshots


def check_fixed_linux_evidence(profile, jobs, run_id, run_attempt, control_sha, linux_logs_path):
    if profile != "candidate":
        raise Refusal("profile-invalid")
    if not linux_logs_path:
        raise Refusal("linux-logs-missing")
    logs = load_json_file(linux_logs_path)
    if type(logs) is not dict or set(logs) != {"sections", "other"}:
        raise Refusal("linux-logs-shape")
    return validate_linux_revocation_evidence(
        jobs, run_id, run_attempt, control_sha,
        API_JOB_NAME_PINS[profile]["linux-fetch-encrypt"], API_LINUX_STEP_NAME_PINS[profile],
        API_LINUX_STEP_ORDINAL_PINS[profile], logs["sections"], logs["other"])


def _cmd_verify_snapshot(arguments):
    profile = arguments.profile
    if profile not in CALLER_PROFILES:
        raise Refusal("profile-invalid")
    if arguments.observe and not arguments.observation_output:
        raise Refusal("observation-output-missing")
    repository = arguments.repository
    if repository != CONTROL_REPOSITORY:
        raise Refusal("control-repository")
    validate_commit_sha(arguments.control_sha)
    if arguments.ref not in profile_refs(profile):
        raise Refusal("profile-ref")
    jobs = _read_pages_argument(arguments.jobs_file)
    artifacts = _read_pages_argument(arguments.artifacts_file)
    if type(jobs) is list:
        jobs = wrap_api_pages("jobs", jobs, arguments.run_id, arguments.run_attempt, arguments.control_sha)
    if type(artifacts) is list:
        artifacts = wrap_api_pages("artifacts", artifacts, arguments.run_id, arguments.run_attempt, arguments.control_sha)
    repository_metadata = load_json_file(arguments.repository_metadata)
    run_metadata = load_json_file(arguments.run_metadata)
    artifact_map = validate_artifact_inventory(artifacts, arguments.run_id,
                                               arguments.run_attempt, arguments.control_sha,
                                               profile_roles(profile), profile)
    provider_snapshots = load_provider_snapshots(
        artifact_map, profile_roles(profile), Path(arguments.evidence_directory) / "artifacts",
        arguments.evidence_directory, arguments.run_id, arguments.run_attempt,
        arguments.control_sha)
    api_pins = API_JOB_NAME_PINS[profile]
    digest_pins = resolve_certificate_pins(profile, arguments.control_sha)
    ordinal_pins = API_LINUX_STEP_ORDINAL_PINS[profile]
    job_observations = {}
    if arguments.observe:
        api_pins, digest_pins, ordinal_pins, job_observations = observed_pins(
            jobs, artifact_map, Path(arguments.evidence_directory) / "artifacts",
            profile_roles(profile), arguments.run_id, arguments.run_attempt,
            arguments.control_sha, profile)
        if not arguments.linux_logs:
            raise Refusal("observation-linux-logs-missing")
        log_document = load_json_file(arguments.linux_logs)
        if type(log_document) is not dict or set(log_document) != {"sections", "other"}:
            raise Refusal("observation-linux-logs-shape")
        validate_linux_revocation_evidence(
            jobs, arguments.run_id, arguments.run_attempt, arguments.control_sha,
            api_pins["linux-fetch-encrypt"], API_LINUX_STEP_NAME_PINS[profile],
            ordinal_pins, log_document["sections"], log_document["other"])
    verify_source_free_evidence(
        profile,
        repository,
        arguments.ref,
        arguments.control_sha,
        arguments.run_id,
        arguments.run_attempt,
        repository_metadata,
        run_metadata,
        jobs,
        artifacts,
        provider_snapshots,
        arguments.root,
        arguments.evidence_directory,
        api_pins,
        digest_pins,
    )
    if arguments.observe:
        _write_json(arguments.observation_output, {
            "profile": profile, "acceptance": "blocked",
            "api_job_names": api_pins, "certificate_digests": digest_pins,
            "linux_step_ordinals": ordinal_pins,
            "api_job_identity": job_observations,
        })
        print("probe=role-signer observation=collected acceptance=blocked")
        return
    if profile == "candidate":
        check_fixed_linux_evidence(
            profile, jobs, arguments.run_id, arguments.run_attempt, arguments.control_sha, arguments.linux_logs)
    if profile == "production-synthetic":
        raise Refusal("gate-c-and-d-evidence-not-implemented")
    print("probe=role-signer result=source-free-evidence-verified profile=%s gate-c=blocked gate-d=blocked" % profile)


def run_gh(arguments, output_path):
    try:
        with open(output_path, "wb") as handle:
            result = subprocess.run(
                ["gh"] + list(arguments), stdin=subprocess.DEVNULL, stdout=handle,
                stderr=subprocess.DEVNULL, timeout=GUARD_TIMEOUT_SECONDS, check=False,
            )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def _capsule_artifact(row, run_id, control_sha):
    run = row.get("workflow_run")
    if (type(run) is not dict or _api_numeric_id(run.get("id"), "receive-capsule-artifact") != run_id
            or run.get("head_sha") != control_sha or row.get("expired") is not False):
        raise Refusal("receive-capsule-artifact")
    size = _is_u64(row.get("size_in_bytes"), positive=False)
    if not DESIGN_CAPSULE_SIZE <= size <= DESIGN_CAPSULE_SIZE + CAPSULE_SLACK_BYTES:
        raise Refusal("receive-capsule-size")
    digest = row.get("digest")
    if type(digest) is not str or re.fullmatch(r"sha256:[a-f0-9]{64}", digest) is None:
        raise Refusal("receive-capsule-artifact")
    return {"id": _api_numeric_id(row.get("id"), "receive-capsule-artifact"), "size": size, "digest": digest}


def _receive_wait(gh, sleep, clock, work, repository, run_id, attempt, control_sha, short, seconds):
    deadline = clock() + seconds
    pages_path = work / "artifact-pages.json"
    api_path = "repos/%s/actions/runs/%d/artifacts?per_page=100" % (repository, run_id)
    capsule_name = "source-capsule-%s-%d-%d" % (short, run_id, attempt)
    prefixes = ["role-statement-%s-%d-%d-" % (role, run_id, attempt) for role in CANDIDATE_ROLES]
    while True:
        if gh(["api", "--paginate", "--slurp", api_path], str(pages_path)):
            try:
                pages = load_json_file(pages_path)
                if type(pages) is not list:
                    raise Refusal("api-pages-shape")
                snapshot = wrap_api_pages("artifacts", pages, run_id, attempt, control_sha)
                rows = _validate_snapshot(snapshot, "artifacts", run_id, attempt, control_sha)
            except Refusal:
                snapshot = None
            if snapshot is not None:
                names = [row.get("name") for row in rows if type(row) is dict]
                if capsule_name in names and all(
                        any(type(name) is str and name.startswith(prefix) for name in names)
                        for prefix in prefixes):
                    return snapshot, rows, capsule_name
        if clock() >= deadline:
            raise Refusal("receive-deadline")
        sleep(RECEIVE_POLL_SECONDS)


def _receive_statements(gh, work, repository, run_id, attempt, snapshot):
    evidence = work / "artifacts"
    evidence.mkdir()
    artifacts = {}
    for role in CANDIDATE_ROLES:
        artifact = select_artifact(snapshot, run_id, run_id, attempt, role)
        archive_path = evidence / (artifact["name"] + ".zip")
        if not gh(["api", "repos/%s/actions/artifacts/%d/zip" % (repository, artifact["id"])], str(archive_path)):
            raise Refusal("receive-download-failed")
        archive = read_bounded_archive(archive_path, artifact["size_in_bytes"])
        directory = evidence / artifact["name"]
        extract_artifact_archive(artifact, archive, directory)
        verified = gh([
            "attestation", "verify", str(directory / "subject.bin"), "--bundle", str(directory / "bundle.json"),
            "--repo", repository, "--signer-workflow", repository + "/" + ROLE_PATHS[role],
            "--predicate-type", PREDICATE_TYPE, "--cert-oidc-issuer", OIDC_ISSUER,
            "--deny-self-hosted-runners", "--format", "json",
        ], str(directory / "verified.json"))
        if not verified:
            raise Refusal("receive-attestation-verify")
        artifacts[role] = artifact
    return evidence, artifacts


def _receive_extract(archive_path, output):
    try:
        with zipfile.ZipFile(archive_path) as archive:
            members = archive.infolist()
            if len(members) != 1 or members[0].filename != "capsule.bin":
                raise Refusal("receive-capsule-members")
            member = members[0]
            if member.is_dir() or (member.external_attr >> 16) & 0o170000 == 0o120000:
                raise Refusal("receive-capsule-members")
            if member.file_size != DESIGN_CAPSULE_SIZE:
                raise Refusal("receive-capsule-length")
            digest = hashlib.sha256()
            count = 0
            with archive.open(member) as source, open(output / "capsule.bin", "xb") as sink:
                while True:
                    block = source.read(HASH_BLOCK_BYTES)
                    if not block:
                        break
                    count += len(block)
                    if count > DESIGN_CAPSULE_SIZE:
                        raise Refusal("receive-capsule-length")
                    digest.update(block)
                    sink.write(block)
    except Refusal:
        raise
    except (OSError, zipfile.BadZipFile, RuntimeError, ValueError, EOFError):
        raise Refusal("receive-capsule-archive")
    if count != DESIGN_CAPSULE_SIZE:
        raise Refusal("receive-capsule-length")
    return digest.hexdigest()


def _receive_into(gh, sleep, clock, work, output, arguments, repository_id, run_id, attempt, control_sha, short):
    repository = arguments.repository
    snapshot, rows, capsule_name = _receive_wait(
        gh, sleep, clock, work, repository, run_id, attempt, control_sha, short, arguments.deadline_seconds)
    capsule_rows = [row for row in rows if type(row) is dict and row.get("name") == capsule_name]
    if len(capsule_rows) != 1:
        raise Refusal("receive-capsule-artifact")
    capsule = _capsule_artifact(capsule_rows[0], run_id, control_sha)
    metadata_path = work / "repository.json"
    if not gh(["api", "repos/" + repository, "--jq",
               "{id:.id,full_name:.full_name,owner_id:.owner.id,visibility:.visibility}"], str(metadata_path)):
        raise Refusal("receive-api-failed")
    metadata_id, owner_id = validate_repository_metadata(load_json_file(metadata_path), repository)
    if metadata_id != repository_id:
        raise Refusal("receive-repository-id")
    evidence, artifacts = _receive_statements(gh, work, repository, run_id, attempt, snapshot)
    validate_role_artifact_set(
        "candidate", repository, arguments.ref, control_sha, run_id, attempt, repository_id, owner_id,
        artifacts, evidence, resolve_certificate_pins("candidate", control_sha), CANDIDATE_ROLES,
    )
    own = (evidence / artifacts[arguments.role]["name"] / "subject.bin").read_bytes()
    binding = parse_binding_subject(
        (evidence / artifacts["linux-fetch-encrypt"]["name"] / "subject.bin").read_bytes())
    if binding["key_record_%s_sha256" % short] != hashlib.sha256(own).hexdigest():
        raise Refusal("receive-key-record-mismatch")
    capsule_zip = work / "capsule.zip"
    if not gh(["api", "repos/%s/actions/artifacts/%d/zip" % (repository, capsule["id"])], str(capsule_zip)):
        raise Refusal("receive-download-failed")
    if capsule_zip.is_symlink() or not capsule_zip.is_file() or capsule_zip.stat().st_size != capsule["size"]:
        raise Refusal("receive-capsule-size")
    if "sha256:" + _file_digest(capsule_zip, "receive-capsule-archive") != capsule["digest"]:
        raise Refusal("receive-capsule-digest")
    digest = _receive_extract(capsule_zip, output)
    if digest != binding["capsule_%s_sha256" % short]:
        raise Refusal("receive-capsule-digest")
    if binding["revocation"] != "confirmed":
        raise Refusal("binding-revocation")
    _write_json(output / "bound.json", {
        "capsule_sha256": digest, "source_sha": binding["source_sha"], "tree_id": binding["tree_id"],
        "lock_sha256": binding["lock_sha256"], "manifest_sha256": binding["manifest_sha256"],
        "revocation": binding["revocation"],
    })
    return digest


def _clear_directory(directory, remove):
    try:
        for item in Path(directory).iterdir():
            if item.is_dir() and not item.is_symlink():
                shutil.rmtree(item, ignore_errors=True)
            else:
                item.unlink()
        if remove:
            Path(directory).rmdir()
    except OSError:
        pass


def receive_capsule(arguments, gh=None, sleep=None, clock=None):
    gh = run_gh if gh is None else gh
    sleep = time.sleep if sleep is None else sleep
    clock = time.monotonic if clock is None else clock
    if arguments.profile != "candidate" or arguments.role not in ("windows-producer", "windows-verifier"):
        raise Refusal("receive-profile-role")
    if arguments.ref not in profile_refs("candidate"):
        raise Refusal("receive-ref")
    if arguments.repository != CONTROL_REPOSITORY:
        raise Refusal("control-repository")
    repository_id = _is_u64(arguments.repository_id)
    control_sha = validate_commit_sha(arguments.control_sha)
    run_id = _is_u64(arguments.run_id)
    attempt = _is_u32(arguments.run_attempt)
    seconds = arguments.deadline_seconds
    if type(seconds) is not int or not 1 <= seconds <= 3600:
        raise Refusal("receive-deadline-range")
    output = Path(arguments.output_directory)
    created = not output.exists()
    if not created and (output.is_symlink() or not output.is_dir() or any(output.iterdir())):
        raise Refusal("receive-output")
    output.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(output, 0o700)
    except OSError:
        pass
    work = Path(tempfile.mkdtemp(prefix="kd-receive-", dir=str(output.parent)))
    try:
        digest = _receive_into(
            gh, sleep, clock, work, output, arguments, repository_id, run_id, attempt, control_sha,
            arguments.role[len("windows-"):])
    except BaseException:
        _clear_directory(output, created)
        raise
    finally:
        shutil.rmtree(work, ignore_errors=True)
    print("capsule=received role=%s sha256=%s" % (arguments.role, digest))


def build_parser():
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--profile", required=True)
    prepare.add_argument("--role", required=True)
    prepare.add_argument("--repository", required=True)
    prepare.add_argument("--repository-id", required=True)
    prepare.add_argument("--control-sha", required=True)
    prepare.add_argument("--ref", required=True)
    prepare.add_argument("--run-id", required=True)
    prepare.add_argument("--run-attempt", required=True)
    prepare.add_argument("--workflow-ref", required=True)
    prepare.add_argument("--runner", required=True)
    prepare.add_argument("--output-directory", required=True)
    prepare.add_argument("--receiver-record")
    prepare.add_argument("--verifier-record")
    prepare.add_argument("--capsule-producer")
    prepare.add_argument("--capsule-verifier")
    prepare.add_argument("--public-point-file")
    prepare.add_argument("--revocation-receipt")
    prepare.add_argument("--source-sha")
    prepare.add_argument("--tree-id")
    prepare.add_argument("--lock-sha256")
    prepare.add_argument("--manifest-sha256")
    prepare.add_argument("--linux-subject")
    receive = commands.add_parser("receive-capsule")
    receive.add_argument("--profile", required=True)
    receive.add_argument("--role", choices=("windows-producer", "windows-verifier"), required=True)
    receive.add_argument("--repository", required=True)
    receive.add_argument("--repository-id", required=True)
    receive.add_argument("--control-sha", required=True)
    receive.add_argument("--ref", required=True)
    receive.add_argument("--run-id", required=True)
    receive.add_argument("--run-attempt", required=True)
    receive.add_argument("--deadline-seconds", type=int, required=True)
    receive.add_argument("--output-directory", required=True)
    wrap = commands.add_parser("wrap-pages")
    wrap.add_argument("--kind", choices=("jobs", "artifacts"), required=True)
    wrap.add_argument("--input", required=True)
    wrap.add_argument("--output", required=True)
    wrap.add_argument("--run-id", required=True)
    wrap.add_argument("--run-attempt", required=True)
    wrap.add_argument("--head-sha", required=True)
    provider = commands.add_parser("wrap-provider-http")
    provider.add_argument("--input", required=True)
    provider.add_argument("--subject-digest", required=True)
    provider.add_argument("--output", required=True)
    provider.add_argument("--run-id", required=True)
    provider.add_argument("--run-attempt", required=True)
    provider.add_argument("--head-sha", required=True)
    find = commands.add_parser("find-artifact")
    find.add_argument("--artifacts-file", required=True)
    find.add_argument("--role", choices=ALL_ROLES, required=True)
    find.add_argument("--run-id", required=True)
    find.add_argument("--run-attempt", required=True)
    find.add_argument("--field", choices=("id", "name"), default="name")
    extract = commands.add_parser("extract-artifact")
    extract.add_argument("--artifacts-file", required=True)
    extract.add_argument("--role", choices=ALL_ROLES, required=True)
    extract.add_argument("--run-id", required=True)
    extract.add_argument("--run-attempt", required=True)
    extract.add_argument("--head-sha", required=True)
    extract.add_argument("--archive-file", required=True)
    extract.add_argument("--output-directory", required=True)
    export = commands.add_parser("export-provider")
    export.add_argument("--snapshot", required=True)
    export.add_argument("--run-id", required=True)
    export.add_argument("--run-attempt", required=True)
    export.add_argument("--head-sha", required=True)
    export.add_argument("--output-directory", required=True)
    guard = commands.add_parser("guard")
    guard.add_argument("--label", choices=GUARD_LABELS, required=True)
    guard.add_argument("--output", required=True)
    guard.add_argument("--attempts", type=int, default=1)
    guard.add_argument("--pause", type=int, default=5)
    guard.add_argument("--fallback-route")
    guard.add_argument("guard_command", nargs=argparse.REMAINDER)
    find_job = commands.add_parser("find-job")
    find_job.add_argument("--profile", choices=tuple(CALLER_PROFILES), required=True)
    find_job.add_argument("--role", choices=ALL_ROLES, required=True)
    find_job.add_argument("--jobs-file", required=True)
    find_job.add_argument("--run-id", required=True)
    find_job.add_argument("--run-attempt", required=True)
    find_job.add_argument("--head-sha", required=True)
    find_job.add_argument("--observe", action="store_true")
    parse_logs = commands.add_parser("parse-linux-logs")
    parse_logs.add_argument("--profile", choices=tuple(CALLER_PROFILES), required=True)
    parse_logs.add_argument("--jobs-file", required=True)
    parse_logs.add_argument("--input", required=True)
    parse_logs.add_argument("--output", required=True)
    parse_logs.add_argument("--run-id", required=True)
    parse_logs.add_argument("--run-attempt", required=True)
    parse_logs.add_argument("--head-sha", required=True)
    parse_logs.add_argument("--observe", action="store_true")
    gate = commands.add_parser("gate-transition")
    gate.add_argument("--gate", choices=("A", "B"), required=True)
    gate.add_argument("--profile", choices=tuple(CALLER_PROFILES), required=True)
    gate.add_argument("--repository", required=True)
    gate.add_argument("--ref", required=True)
    gate.add_argument("--control-sha", required=True)
    gate.add_argument("--run-id", required=True)
    gate.add_argument("--run-attempt", required=True)
    gate.add_argument("--root", default=".")
    gate.add_argument("--jobs-file", required=True)
    gate.add_argument("--artifacts-file", required=True)
    gate.add_argument("--repository-metadata", required=True)
    gate.add_argument("--run-metadata", required=True)
    gate.add_argument("--artifact-directory", required=True)
    gate.add_argument("--provider-directory", required=True)
    gate.add_argument("--linux-logs")
    gate.add_argument("--observe", action="store_true")
    gate.add_argument("--observation-output")
    verify = commands.add_parser("verify-snapshot")
    verify.add_argument("--profile", required=True)
    verify.add_argument("--repository", required=True)
    verify.add_argument("--ref", required=True)
    verify.add_argument("--control-sha", required=True)
    verify.add_argument("--run-id", required=True)
    verify.add_argument("--run-attempt", required=True)
    verify.add_argument("--root", default=".")
    verify.add_argument("--jobs-file", required=True)
    verify.add_argument("--artifacts-file", required=True)
    verify.add_argument("--repository-metadata", required=True)
    verify.add_argument("--run-metadata", required=True)
    verify.add_argument("--evidence-directory", required=True)
    verify.add_argument("--linux-logs")
    verify.add_argument("--observe", action="store_true")
    verify.add_argument("--observation-output")
    return parser


def main(argv=None):
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "prepare":
            prepare_subject(arguments)
        elif arguments.command == "wrap-pages":
            _cmd_wrap_pages(arguments)
        elif arguments.command == "wrap-provider-http":
            _cmd_wrap_provider_http(arguments)
        elif arguments.command == "find-artifact":
            _cmd_find_artifact(arguments)
        elif arguments.command == "extract-artifact":
            _cmd_extract_artifact(arguments)
        elif arguments.command == "export-provider":
            _cmd_export_provider(arguments)
        elif arguments.command == "find-job":
            _cmd_find_job(arguments)
        elif arguments.command == "parse-linux-logs":
            _cmd_parse_linux_logs(arguments)
        elif arguments.command == "gate-transition":
            _cmd_gate_transition(arguments)
        elif arguments.command == "receive-capsule":
            receive_capsule(arguments)
        elif arguments.command == "guard":
            return _cmd_guard(arguments)
        else:
            _cmd_verify_snapshot(arguments)
        return 0
    except (Refusal, OSError, OverflowError, ValueError):
        code = sys.exc_info()[1]
        reason = code.code if isinstance(code, Refusal) else "input-invalid"
        print("probe=role-signer result=unavailable reason=" + reason)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
