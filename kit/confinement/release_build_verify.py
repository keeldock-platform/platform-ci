import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


SCHEMA_VERSION = 1
MAX_MANIFEST_BYTES = 131072
MAX_JSON_DEPTH = 16
MAX_JSON_STRUCTURAL_TOKENS = 4096
MAX_LOCK_RECEIPTS = 64
MAX_TOOLCHAINS = 128
MAX_IMAGES = 128
MAX_ENVIRONMENT_ITEMS = 128
MAX_ARTIFACTS = 512
MAX_OBSERVATIONS = 64
MAX_ARTIFACT_SIZE = 1099511627776
MAX_TOTAL_ARTIFACT_SIZE = 4398046511104
MAX_BUILD_AGE_SECONDS = 86400
MAX_CLOCK_SKEW_SECONDS = 300
MAX_POLICY_ENTRIES = 64
MAX_POLICY_VERSION = 65535
MAX_SAFE_INTEGER = 9007199254740991
MODE = "shadow"

NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
ENVIRONMENT_NAME_RE = re.compile(r"[A-Z_][A-Z0-9_]{0,127}\Z")
OBSERVATION_NAME_RE = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
SOURCE_SHA_RE = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
BUILD_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
ARTIFACT_PATH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/_-]{0,511}\Z")
ALLOWLIST_FIELD_RE = re.compile(r"observations\.([a-z][a-z0-9_-]{0,63})\Z")

MANIFEST_FIELDS = frozenset(
    ("schema_version", "build_id", "created_at", "inputs", "artifacts", "observations")
)
INPUT_FIELDS = frozenset(
    (
        "source_sha",
        "lock_receipts",
        "toolchain_identities",
        "image_identities",
        "environment_allowlist",
    )
)
REFUSAL_CODES = frozenset(
    (
        "allowlist_invalid",
        "artifact_digest_mismatch",
        "artifact_extra",
        "artifact_missing",
        "artifact_size_mismatch",
        "build_identity_reused",
        "build_identity_stale",
        "input_mismatch",
        "manifest_malformed",
        "manifest_oversize",
        "unallowlisted_difference",
    )
)


class BuildVerificationRefusal(ValueError):
    """Expose one stable code without echoing untrusted manifest values."""

    def __init__(self, code):
        if type(code) is not str or code not in REFUSAL_CODES:
            code = "manifest_malformed"
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class LockReceipt:
    """Bind lock bytes to the receipt that admitted them."""

    name: str
    lock_sha256: str
    receipt_sha256: str


@dataclass(frozen=True)
class ToolchainIdentity:
    """Identify one versioned toolchain by its executable digest."""

    name: str
    version: str
    sha256: str


@dataclass(frozen=True)
class ImageIdentity:
    """Identify one build image by its immutable digest."""

    name: str
    sha256: str


@dataclass(frozen=True)
class EnvironmentValue:
    """Record one permitted environment name and its exact value."""

    name: str
    value: str


@dataclass(frozen=True)
class BuildInputs:
    """Hold the reproducible identities shared by both builds."""

    source_sha: str
    lock_receipts: tuple
    toolchain_identities: tuple
    image_identities: tuple
    environment_allowlist: tuple


@dataclass(frozen=True)
class BuildArtifact:
    """Describe one output by relative path, byte size and digest."""

    path: str
    size: int
    sha256: str


@dataclass(frozen=True)
class BuildEvidenceManifest:
    """Hold one canonical build record and its complete output set."""

    schema_version: int
    build_id: str
    created_at: str
    inputs: BuildInputs
    artifacts: tuple
    observations: tuple


@dataclass(frozen=True)
class DifferenceAllowance:
    """Justify one permitted observation-only difference."""

    field: str
    justification: str


@dataclass(frozen=True)
class DifferenceAllowlist:
    """Version the explicit set of permitted observation differences."""

    version: int
    entries: tuple


@dataclass(frozen=True)
class BuildComparisonResult:
    """Expose the digests that bind an accepted shadow comparison."""

    accepted: bool
    mode: str
    input_identity_sha256: str
    build_a_id: str
    build_b_id: str
    build_a_output_set_sha256: str
    build_b_output_set_sha256: str
    allowlist_version: int
    allowlist_sha256: str
    allowed_differences: tuple
    comparison_sha256: str


EMPTY_ALLOWLIST = DifferenceAllowlist(1, ())


def _refuse(code):
    raise BuildVerificationRefusal(code)


def _require_ascii(value):
    if type(value) is not str or not value.isascii():
        _refuse("manifest_malformed")
    return value


def _bounded_string(value, pattern, maximum):
    value = _require_ascii(value)
    if len(value) > maximum or pattern.fullmatch(value) is None:
        _refuse("manifest_malformed")
    return value


def _digest(value):
    return _bounded_string(value, SHA256_RE, 64)


def _timestamp(value):
    timestamp_pattern = re.compile(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z\Z"
    )
    value = _bounded_string(value, timestamp_pattern, 20)
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _refuse("manifest_malformed")
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        _refuse("manifest_malformed")
    return value


def _artifact_path(value):
    value = _bounded_string(value, ARTIFACT_PATH_RE, 512)
    if value.endswith("/") or "//" in value or "\\" in value:
        _refuse("manifest_malformed")
    if any(part in ("", ".", "..") for part in value.split("/")):
        _refuse("manifest_malformed")
    return value


def _object_fields(value, fields):
    if type(value) is not dict or any(type(key) is not str for key in value):
        _refuse("manifest_malformed")
    if set(value) != fields:
        _refuse("manifest_malformed")


def _record_list(value, maximum, minimum=0):
    if type(value) is not list or len(value) < minimum or len(value) > maximum:
        _refuse("manifest_malformed")
    return value


def manifest_from_mapping(value):
    """Build a closed manifest model from already decoded JSON data."""

    _object_fields(value, MANIFEST_FIELDS)
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        _refuse("manifest_malformed")
    build_id = _bounded_string(value["build_id"], BUILD_ID_RE, 128)
    created_at = _timestamp(value["created_at"])

    raw_inputs = value["inputs"]
    _object_fields(raw_inputs, INPUT_FIELDS)
    source_sha = _bounded_string(raw_inputs["source_sha"], SOURCE_SHA_RE, 64)

    lock_receipts = []
    previous_name = None
    for item in _record_list(raw_inputs["lock_receipts"], MAX_LOCK_RECEIPTS, 1):
        _object_fields(item, frozenset(("name", "lock_sha256", "receipt_sha256")))
        name = _bounded_string(item["name"], NAME_RE, 128)
        if previous_name is not None and name <= previous_name:
            _refuse("manifest_malformed")
        previous_name = name
        lock_receipts.append(
            LockReceipt(name, _digest(item["lock_sha256"]), _digest(item["receipt_sha256"]))
        )

    toolchain_identities = []
    previous_name = None
    for item in _record_list(raw_inputs["toolchain_identities"], MAX_TOOLCHAINS, 1):
        _object_fields(item, frozenset(("name", "version", "sha256")))
        name = _bounded_string(item["name"], NAME_RE, 128)
        if previous_name is not None and name <= previous_name:
            _refuse("manifest_malformed")
        previous_name = name
        version = _bounded_string(item["version"], VERSION_RE, 64)
        toolchain_identities.append(ToolchainIdentity(name, version, _digest(item["sha256"])))

    image_identities = []
    previous_name = None
    for item in _record_list(raw_inputs["image_identities"], MAX_IMAGES, 1):
        _object_fields(item, frozenset(("name", "sha256")))
        name = _bounded_string(item["name"], NAME_RE, 128)
        if previous_name is not None and name <= previous_name:
            _refuse("manifest_malformed")
        previous_name = name
        image_identities.append(ImageIdentity(name, _digest(item["sha256"])))

    environment_allowlist = []
    previous_name = None
    for item in _record_list(raw_inputs["environment_allowlist"], MAX_ENVIRONMENT_ITEMS):
        _object_fields(item, frozenset(("name", "value")))
        name = _bounded_string(item["name"], ENVIRONMENT_NAME_RE, 128)
        if previous_name is not None and name <= previous_name:
            _refuse("manifest_malformed")
        previous_name = name
        environment_value = _require_ascii(item["value"])
        if len(environment_value) > 1024 or not environment_value.isprintable():
            _refuse("manifest_malformed")
        environment_allowlist.append(EnvironmentValue(name, environment_value))

    inputs = BuildInputs(
        source_sha,
        tuple(lock_receipts),
        tuple(toolchain_identities),
        tuple(image_identities),
        tuple(environment_allowlist),
    )

    artifacts = []
    previous_path = None
    total_size = 0
    for item in _record_list(value["artifacts"], MAX_ARTIFACTS, 1):
        _object_fields(item, frozenset(("path", "size", "sha256")))
        path = _artifact_path(item["path"])
        if previous_path is not None and path <= previous_path:
            _refuse("manifest_malformed")
        previous_path = path
        size = item["size"]
        if type(size) is not int or size < 0 or size > MAX_ARTIFACT_SIZE:
            _refuse("manifest_malformed")
        total_size += size
        if total_size > MAX_TOTAL_ARTIFACT_SIZE:
            _refuse("manifest_malformed")
        artifacts.append(BuildArtifact(path, size, _digest(item["sha256"])))

    raw_observations = value["observations"]
    if type(raw_observations) is not dict or len(raw_observations) > MAX_OBSERVATIONS:
        _refuse("manifest_malformed")
    observations = []
    if any(type(name) is not str for name in raw_observations):
        _refuse("manifest_malformed")
    for name in sorted(raw_observations):
        _bounded_string(name, OBSERVATION_NAME_RE, 64)
        observation_value = _require_ascii(raw_observations[name])
        if len(observation_value) > 1024 or not observation_value.isprintable():
            _refuse("manifest_malformed")
        observations.append((name, observation_value))

    return BuildEvidenceManifest(
        SCHEMA_VERSION,
        build_id,
        created_at,
        inputs,
        tuple(artifacts),
        tuple(observations),
    )


def _no_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse("manifest_malformed")
        result[key] = value
    return result


def _parse_integer(value):
    digits = value[1:] if value.startswith("-") else value
    if len(digits) > 16:
        _refuse("manifest_malformed")
    parsed = int(value)
    if parsed < -MAX_SAFE_INTEGER or parsed > MAX_SAFE_INTEGER:
        _refuse("manifest_malformed")
    return parsed


def _reject_number(value):
    _refuse("manifest_malformed")


def _check_json_bounds(raw):
    depth = 0
    structural_tokens = 0
    inside_string = False
    escaped = False
    for value in raw:
        if inside_string:
            if escaped:
                escaped = False
            elif value == 92:
                escaped = True
            elif value == 34:
                inside_string = False
            continue
        if value == 34:
            inside_string = True
        elif value in (123, 91):
            depth += 1
            structural_tokens += 1
            if depth > MAX_JSON_DEPTH:
                _refuse("manifest_malformed")
        elif value in (125, 93):
            depth -= 1
            structural_tokens += 1
        elif value in (44, 58):
            structural_tokens += 1
        if structural_tokens > MAX_JSON_STRUCTURAL_TOKENS:
            _refuse("manifest_malformed")


def encode_canonical_json(value):
    """Encode a compact, sorted, ASCII JSON representation."""

    try:
        raw = json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError, RecursionError):
        _refuse("manifest_malformed")
    if len(raw) > MAX_MANIFEST_BYTES:
        _refuse("manifest_oversize")
    return raw


def parse_manifest(raw):
    """Parse a bounded canonical manifest and reject duplicate keys."""

    if type(raw) is not bytes:
        _refuse("manifest_malformed")
    if len(raw) > MAX_MANIFEST_BYTES:
        _refuse("manifest_oversize")
    if not raw.isascii():
        _refuse("manifest_malformed")
    _check_json_bounds(raw)
    try:
        value = json.loads(
            raw.decode("ascii"),
            object_pairs_hook=_no_duplicate_pairs,
            parse_int=_parse_integer,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except BuildVerificationRefusal:
        raise
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError):
        _refuse("manifest_malformed")
    if encode_canonical_json(value) != raw:
        _refuse("manifest_malformed")
    return manifest_from_mapping(value)


def allowlist_from_mapping(value):
    """Build a versioned allowlist whose every entry has a justification."""

    if (
        type(value) is not dict
        or any(type(key) is not str for key in value)
        or set(value) != set(("version", "entries"))
    ):
        _refuse("allowlist_invalid")
    version = value["version"]
    if type(version) is not int or version < 1 or version > MAX_POLICY_VERSION:
        _refuse("allowlist_invalid")
    raw_entries = value["entries"]
    if type(raw_entries) is not list or len(raw_entries) > MAX_POLICY_ENTRIES:
        _refuse("allowlist_invalid")
    entries = []
    previous_field = None
    for item in raw_entries:
        if type(item) is not dict or set(item) != set(("field", "justification")):
            _refuse("allowlist_invalid")
        field = item["field"]
        justification = item["justification"]
        if type(field) is not str or ALLOWLIST_FIELD_RE.fullmatch(field) is None:
            _refuse("allowlist_invalid")
        if previous_field is not None and field <= previous_field:
            _refuse("allowlist_invalid")
        previous_field = field
        if (
            type(justification) is not str
            or not justification.isascii()
            or not justification.isprintable()
            or len(justification) < 8
            or len(justification) > 512
            or justification != justification.strip()
        ):
            _refuse("allowlist_invalid")
        entries.append(DifferenceAllowance(field, justification))
    return DifferenceAllowlist(version, tuple(entries))


def _allowlist_mapping(allowlist):
    if type(allowlist) is not DifferenceAllowlist:
        _refuse("allowlist_invalid")
    if type(allowlist.entries) is not tuple or len(allowlist.entries) > MAX_POLICY_ENTRIES:
        _refuse("allowlist_invalid")
    entries = []
    for entry in allowlist.entries:
        if type(entry) is not DifferenceAllowance:
            _refuse("allowlist_invalid")
        entries.append({"field": entry.field, "justification": entry.justification})
    mapping = {
        "version": allowlist.version,
        "entries": entries,
    }
    validated = allowlist_from_mapping(mapping)
    if validated != allowlist:
        _refuse("allowlist_invalid")
    return mapping


def _inputs_mapping(inputs):
    return {
        "source_sha": inputs.source_sha,
        "lock_receipts": [
            {
                "name": item.name,
                "lock_sha256": item.lock_sha256,
                "receipt_sha256": item.receipt_sha256,
            }
            for item in inputs.lock_receipts
        ],
        "toolchain_identities": [
            {"name": item.name, "version": item.version, "sha256": item.sha256}
            for item in inputs.toolchain_identities
        ],
        "image_identities": [
            {"name": item.name, "sha256": item.sha256}
            for item in inputs.image_identities
        ],
        "environment_allowlist": [
            {"name": item.name, "value": item.value}
            for item in inputs.environment_allowlist
        ],
    }


def _manifest_mapping(manifest):
    return {
        "schema_version": manifest.schema_version,
        "build_id": manifest.build_id,
        "created_at": manifest.created_at,
        "inputs": _inputs_mapping(manifest.inputs),
        "artifacts": [
            {"path": item.path, "size": item.size, "sha256": item.sha256}
            for item in manifest.artifacts
        ],
        "observations": dict(manifest.observations),
    }


def _validated_manifest(value):
    if type(value) is bytes:
        return parse_manifest(value)
    if type(value) is BuildEvidenceManifest:
        try:
            if type(value.observations) is not tuple:
                _refuse("manifest_malformed")
            if len(dict(value.observations)) != len(value.observations):
                _refuse("manifest_malformed")
            return manifest_from_mapping(_manifest_mapping(value))
        except BuildVerificationRefusal:
            raise
        except (AttributeError, TypeError, ValueError):
            _refuse("manifest_malformed")
    _refuse("manifest_malformed")


def _manifest_digest(value):
    return hashlib.sha256(encode_canonical_json(value)).hexdigest()


def _validate_now(value):
    if type(value) is not datetime or value.tzinfo is None or value.utcoffset() is None:
        _refuse("manifest_malformed")
    return value.astimezone(timezone.utc)


def _check_freshness(manifest, now):
    parsed = datetime.strptime(manifest.created_at, "%Y-%m-%dT%H:%M:%SZ").replace(
        tzinfo=timezone.utc
    )
    if parsed < now - timedelta(seconds=MAX_BUILD_AGE_SECONDS):
        _refuse("build_identity_stale")
    if parsed > now + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        _refuse("build_identity_stale")


def _observation_differences(left, right):
    left_values = dict(left.observations)
    right_values = dict(right.observations)
    sentinel = object()
    differences = []
    for name in sorted(set(left_values) | set(right_values)):
        if left_values.get(name, sentinel) != right_values.get(name, sentinel):
            differences.append("observations." + name)
    return tuple(differences)


def _artifact_mapping(manifest):
    return [
        {"path": item.path, "size": item.size, "sha256": item.sha256}
        for item in manifest.artifacts
    ]


def compare_builds(build_a, build_b, now, allowlist=EMPTY_ALLOWLIST, seen_build_ids=()):
    """Compare two fresh manifests without reading files or changing state."""

    left = _validated_manifest(build_a)
    right = _validated_manifest(build_b)
    policy = _allowlist_mapping(allowlist)
    current_time = _validate_now(now)

    _check_freshness(left, current_time)
    _check_freshness(right, current_time)

    if type(seen_build_ids) not in (tuple, list, set, frozenset):
        _refuse("manifest_malformed")
    if len(seen_build_ids) > 4096:
        _refuse("manifest_malformed")
    validated_seen = set()
    for build_id in seen_build_ids:
        if type(build_id) is not str or BUILD_ID_RE.fullmatch(build_id) is None:
            _refuse("manifest_malformed")
        validated_seen.add(build_id)
    if (
        left.build_id == right.build_id
        or left.build_id in validated_seen
        or right.build_id in validated_seen
    ):
        _refuse("build_identity_reused")

    if left.inputs != right.inputs:
        _refuse("input_mismatch")

    left_paths = set(item.path for item in left.artifacts)
    right_paths = set(item.path for item in right.artifacts)
    if left_paths - right_paths:
        _refuse("artifact_missing")
    if right_paths - left_paths:
        _refuse("artifact_extra")
    left_artifacts = dict((item.path, item) for item in left.artifacts)
    right_artifacts = dict((item.path, item) for item in right.artifacts)
    for path in sorted(left_paths):
        if left_artifacts[path].sha256 != right_artifacts[path].sha256:
            _refuse("artifact_digest_mismatch")
        if left_artifacts[path].size != right_artifacts[path].size:
            _refuse("artifact_size_mismatch")

    differences = _observation_differences(left, right)
    allowed_fields = set(item["field"] for item in policy["entries"])
    if set(differences) - allowed_fields:
        _refuse("unallowlisted_difference")

    input_identity_sha256 = _manifest_digest(_inputs_mapping(left.inputs))
    output_a_sha256 = _manifest_digest(_artifact_mapping(left))
    output_b_sha256 = _manifest_digest(_artifact_mapping(right))
    allowlist_sha256 = _manifest_digest(policy)
    comparison_identity = {
        "schema_version": SCHEMA_VERSION,
        "input_identity_sha256": input_identity_sha256,
        "build_a": {
            "build_id": left.build_id,
            "created_at": left.created_at,
            "output_set_sha256": output_a_sha256,
        },
        "build_b": {
            "build_id": right.build_id,
            "created_at": right.created_at,
            "output_set_sha256": output_b_sha256,
        },
        "allowlist_version": allowlist.version,
        "allowlist_sha256": allowlist_sha256,
        "allowed_differences": list(differences),
    }
    comparison_sha256 = _manifest_digest(comparison_identity)
    return BuildComparisonResult(
        True,
        MODE,
        input_identity_sha256,
        left.build_id,
        right.build_id,
        output_a_sha256,
        output_b_sha256,
        allowlist.version,
        allowlist_sha256,
        differences,
        comparison_sha256,
    )
