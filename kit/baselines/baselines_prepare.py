import argparse
import hashlib
import json
import os
import re
import shutil
import sys


SCHEMA = "baseline-evidence-v1"
MAX_BLOCK_BYTES = 262144
MAX_VECTOR_LENGTH = 1000
MAX_PRIMARY_BATCHES = 7
MAX_CONFIRMATION_BATCHES = 2
MAX_BATCHES = MAX_PRIMARY_BATCHES + MAX_CONFIRMATION_BATCHES
MAX_ROWS = 256
MAX_SAFE_INTEGER = 9007199254740991
MAX_FILE_BYTES = 262144
MAX_SUMMARY_BYTES = 1048576
MAX_TOOLCHAIN_ITEMS = 16

BEGIN_MARKER = "baseline-evidence-v1-begin"
END_MARKER = "baseline-evidence-v1-end"
VERDICT_PREFIX = "baselines-prepare="
REQUIRED_EVENT = "workflow_dispatch"
REQUIRED_REF = "refs/heads/main"
REQUIRED_RUNNER_ENVIRONMENT = "github-hosted"
WORKFLOW_PATH = ".github/workflows/baselines-prepare.yml"
WORKFLOWS_DIRECTORY = ".github/workflows"

SHA1_RE = re.compile(r"[0-9a-f]{40}\Z")
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,15}\Z")
LABEL_RE = re.compile(r"[a-z0-9]{1,16}\Z")
IMAGE_VERSION_RE = re.compile(r"[0-9]{1,8}(?:\.[0-9]{1,8}){0,3}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,63}\Z")
USES_RE = re.compile(r"^\s*(?:-\s+)?uses:\s+(\S+)")
REMOTE_REF_RE = re.compile(
    r"([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_-]+)*)@([0-9a-f]{40})\Z"
)
LOCAL_REF_RE = re.compile(r"\./[A-Za-z0-9_.-][A-Za-z0-9_./-]*\Z")
TOP_KEY_RE = re.compile(r"^([A-Za-z0-9_-]+):")
JOB_KEY_RE = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
ACCESS_LEVEL_RE = re.compile(r"^\s*[A-Za-z-]+:\s*(?:read|write)(?:-all)?\s*$")
TOP_PERMISSIONS_RE = re.compile(r"(?m)^permissions:")

REFUSAL_CODES = frozenset(
    (
        "audit_mismatch",
        "cache_mode_invalid",
        "control_sha_invalid",
        "file_oversize",
        "file_unreadable",
        "identity_invalid",
        "native_tool_missing",
        "permissions_invalid",
        "pin_malformed",
        "pin_unreviewed",
        "platform_unknown",
        "record_fields",
        "record_identity",
        "record_malformed",
        "record_oversize",
        "record_row",
        "record_statistic",
        "run_context_invalid",
        "runner_architecture",
        "runner_environment",
        "runner_image",
        "runner_os",
        "runner_unavailable",
        "summary_markers",
        "summary_oversize",
        "summary_shape",
        "summary_unavailable",
        "workflow_unavailable",
    )
)

PLATFORMS = {
    "linux": {
        "runner_os": "linux",
        "architecture": "x64",
        "image_os": "ubuntu24",
        "label": "ubuntu-24.04",
    },
    "windows": {
        "runner_os": "windows",
        "architecture": "x64",
        "image_os": "win25",
        "label": "windows-2025",
    },
    "macos": {
        "runner_os": "macos",
        "architecture": "arm64",
        "image_os": "macos15",
        "label": "macos-15",
    },
}

REVIEWED_PINS = frozenset(
    (
        ("actions/attest", "1e69f48acb82d1966a394da916b4c1698aa569d6"),
        ("actions/cache/restore", "3edfce9056124e459a23f683a21433670d47daca"),
        ("actions/cache/save", "3edfce9056124e459a23f683a21433670d47daca"),
        ("actions/checkout", "11bd71901bbe5b1630ceea73d27597364c9af683"),
        ("actions/create-github-app-token", "64ab729a6294000f5aa4a4bc0b73d1f32bc45510"),
        ("actions/setup-node", "949feb2413d6458794dcd2491c4babbbce0c15c1"),
        ("actions/upload-artifact", "cf430e030ddbb5b0abf93d22962f4752f3646cd9"),
    )
)

EXTRA_TOOL_DIRECTORIES = {
    "linux": ("/usr/sbin", "/sbin", "/usr/bin", "/bin"),
    "windows": (),
    "macos": ("/usr/sbin", "/sbin", "/usr/bin", "/bin"),
}
NATIVE_TOOLS = {
    "linux": (
        ("Xvfb", False),
        ("xvfb-run", False),
        ("dbus-daemon", False),
        ("useradd", True),
        ("userdel", True),
        ("losetup", True),
        ("mkfs.ext4", True),
    ),
    "windows": (
        ("msiexec", True),
        ("diskpart", True),
        ("powershell", True),
        ("pwsh", False),
    ),
    "macos": (
        ("hdiutil", True),
        ("ditto", True),
        ("dscl", True),
        ("sysadminctl", True),
        ("screencapture", False),
        ("xcodebuild", False),
    ),
}

UNITS = frozenset(("us", "bytes", "count"))
STATUSES = frozenset(("ok", "failed", "invalid"))
BATCH_KINDS = frozenset(("primary", "confirmation"))
VARIANTS = frozenset(("default", "cold", "warm", "numeric", "mixed"))
EVIDENCE_CLASSES = frozenset(("synthetic", "measured"))
PROFILE_MODES = frozenset(("empty-cold", "prepared-cold", "empty-warm", "prepared-warm"))
TOOLCHAIN_NAMES = frozenset(
    ("rust", "node", "npm", "tauri", "webkit", "webview2", "xcode", "python", "git")
)
PERCENTILES = {"p95": 95, "p05": 5, "median": 50}
STATISTICS = frozenset(("p95", "p05", "median", "min", "max"))

METRICS = {
    "native.startup.splash": ("startup", "us", 20, True),
    "native.startup.interactive": ("startup", "us", 20, True),
    "native.startup.first-tool": ("startup", "us", 20, True),
    "native.startup.second-launch": ("startup", "us", 20, True),
    "native.memory.idle-shell": ("memory", "bytes", 60, True),
    "native.memory.per-tool": ("memory", "bytes", 180, True),
    "native.memory.large-result": ("memory", "bytes", 1000, True),
    "grid.virtual-1m-200": ("grid", "us", 120, False),
    "grid.virtual-1m-40": ("grid", "us", 120, False),
    "ipc.echo-64": ("ipc", "us", 1000, False),
    "ipc.transfer-10mb": ("ipc", "us", 40, False),
    "ipc.throughput": ("ipc", "bytes", 30, False),
    "package.installer-bytes": ("package", "bytes", 1, False),
    "package.installed-bytes": ("package", "bytes", 1, False),
    "bundle.desktop-bytes": ("bundle", "bytes", 1, False),
    "bundle.desktop-files": ("bundle", "count", 1, False),
    "cargo.build-cold": ("cargo", "us", 1, False),
    "cargo.build-warm": ("cargo", "us", 1, False),
}

BLOCK_FIELDS = frozenset(("schema", "identity", "rows"))
IDENTITY_FIELDS = frozenset(
    (
        "evidence_class",
        "source_sha",
        "control_sha",
        "source_repository_id",
        "oracle_tree",
        "run_id",
        "run_attempt",
        "admission_receipt_digest",
        "platform",
        "architecture",
        "image_os",
        "image_version",
        "toolchain",
        "lockfile_digest",
        "fixture_digest",
        "method_digest",
        "calibration_digest",
        "method_version",
    )
)
COMMON_ROW_FIELDS = frozenset(
    (
        "suite_id",
        "metric_id",
        "variant_id",
        "batch_index",
        "batch_kind",
        "observation_count",
        "unit",
        "status",
        "values",
        "statistic_name",
        "statistic_value",
    )
)
NATIVE_ROW_FIELDS = frozenset(
    (
        "profile_mode",
        "seed_digest",
        "setup_count",
        "primer_count",
        "isolation_code",
        "termination_code",
        "cleanup_code",
    )
)
SUMMARY_HEADER_FIELDS = frozenset(
    (
        "rows",
        "bytes",
        "digest",
        "control-sha",
        "run-id",
        "run-attempt",
        "platform",
        "evidence-class",
    )
)


class BaselinesRefusal(ValueError):
    def __init__(self, code):
        if type(code) is not str or code not in REFUSAL_CODES:
            code = "record_malformed"
        self.code = code
        super().__init__(code)


def _is_int(value, low, high):
    return type(value) is int and low <= value <= high


def _is_member(value, allowed):
    return type(value) is str and value in allowed


def _is_match(value, pattern):
    return type(value) is str and pattern.match(value) is not None


def read_text_file(path, code="file_unreadable"):
    try:
        with open(path, "rb") as source:
            payload = source.read(MAX_FILE_BYTES + 1)
    except OSError:
        raise BaselinesRefusal(code)
    if len(payload) > MAX_FILE_BYTES:
        raise BaselinesRefusal("file_oversize")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        raise BaselinesRefusal(code)


def validate_run_context(environ, control_sha):
    if not _is_match(control_sha, SHA1_RE):
        raise BaselinesRefusal("control_sha_invalid")
    if environ.get("GITHUB_SHA") != control_sha:
        raise BaselinesRefusal("run_context_invalid")
    if environ.get("GITHUB_EVENT_NAME") != REQUIRED_EVENT:
        raise BaselinesRefusal("run_context_invalid")
    if environ.get("GITHUB_REF") != REQUIRED_REF:
        raise BaselinesRefusal("run_context_invalid")
    numbers = []
    for name in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        value = environ.get(name)
        if not _is_match(value, DECIMAL_RE):
            raise BaselinesRefusal("run_context_invalid")
        number = int(value)
        if number > MAX_SAFE_INTEGER:
            raise BaselinesRefusal("run_context_invalid")
        numbers.append(number)
    return numbers[0], numbers[1]


def check_runner_identity(platform, environ):
    if type(platform) is not str or platform not in PLATFORMS:
        raise BaselinesRefusal("platform_unknown")
    spec = PLATFORMS[platform]
    if environ.get("RUNNER_ENVIRONMENT") != REQUIRED_RUNNER_ENVIRONMENT:
        raise BaselinesRefusal("runner_environment")
    runner_os = environ.get("RUNNER_OS")
    if type(runner_os) is not str or runner_os.lower() != spec["runner_os"]:
        raise BaselinesRefusal("runner_os")
    architecture = environ.get("RUNNER_ARCH")
    if type(architecture) is not str or architecture.lower() != spec["architecture"]:
        raise BaselinesRefusal("runner_architecture")
    image_os = environ.get("ImageOS")
    if type(image_os) is not str or image_os.lower() != spec["image_os"]:
        raise BaselinesRefusal("runner_image")
    image_version = environ.get("ImageVersion")
    if not _is_match(image_version, IMAGE_VERSION_RE):
        raise BaselinesRefusal("runner_image")
    return {
        "platform": platform,
        "architecture": spec["architecture"],
        "image_os": spec["image_os"],
        "image_version": image_version,
    }


def inspect_workflow_uses(text):
    references = []
    for line in text.split("\n"):
        match = USES_RE.match(line)
        if match is not None:
            references.append(match.group(1))
    return references


def validate_action_pins(root):
    directory = os.path.join(str(root), *WORKFLOWS_DIRECTORY.split("/"))
    try:
        names = sorted(name for name in os.listdir(directory) if name.endswith(".yml"))
    except OSError:
        raise BaselinesRefusal("workflow_unavailable")
    if not names:
        raise BaselinesRefusal("workflow_unavailable")
    remote_count = 0
    local_count = 0
    for name in names:
        text = read_text_file(os.path.join(directory, name), "workflow_unavailable")
        for reference in inspect_workflow_uses(text):
            if LOCAL_REF_RE.match(reference) is not None:
                if ".." in reference.split("/"):
                    raise BaselinesRefusal("pin_malformed")
                local_count += 1
                continue
            match = REMOTE_REF_RE.match(reference)
            if match is None:
                raise BaselinesRefusal("pin_malformed")
            if (match.group(1), match.group(2)) not in REVIEWED_PINS:
                raise BaselinesRefusal("pin_unreviewed")
            remote_count += 1
    return {"workflows": len(names), "remote_pins": remote_count, "local_references": local_count}


def validate_top_level_permissions(text):
    if len(TOP_PERMISSIONS_RE.findall(text)) != 1:
        raise BaselinesRefusal("permissions_invalid")
    return True


def validate_lane_controls(text):
    if type(text) is not str:
        raise BaselinesRefusal("permissions_invalid")
    in_jobs = False
    jobs = 0
    job_permissions = 0
    job_cache = 0
    top_permissions = 0
    top_cache = 0
    for line in text.split("\n"):
        stripped = line.strip()
        if "secrets" in line or "inherit" in line:
            raise BaselinesRefusal("permissions_invalid")
        if stripped.startswith("cache-mode:") and line not in (
            "cache-mode: none",
            "    cache-mode: none",
        ):
            raise BaselinesRefusal("cache_mode_invalid")
        if ACCESS_LEVEL_RE.match(line) is not None:
            raise BaselinesRefusal("permissions_invalid")
        if stripped.startswith("permissions:") and line not in (
            "permissions: {}",
            "    permissions: {}",
        ):
            raise BaselinesRefusal("permissions_invalid")
        top = TOP_KEY_RE.match(line)
        if top is not None:
            in_jobs = top.group(1) == "jobs"
            if line == "permissions: {}":
                top_permissions += 1
            elif line == "cache-mode: none":
                top_cache += 1
            continue
        if not in_jobs:
            continue
        if JOB_KEY_RE.match(line) is not None:
            jobs += 1
        elif line == "    permissions: {}":
            job_permissions += 1
        elif line == "    cache-mode: none":
            job_cache += 1
    if top_permissions != 1 or jobs < 1 or job_permissions != jobs:
        raise BaselinesRefusal("permissions_invalid")
    if top_cache != 1 or job_cache != jobs:
        raise BaselinesRefusal("cache_mode_invalid")
    return jobs


def validate_job_permissions(root):
    directory = os.path.join(str(root), *WORKFLOWS_DIRECTORY.split("/"))
    try:
        names = sorted(name for name in os.listdir(directory) if name.endswith(".yml"))
    except OSError:
        raise BaselinesRefusal("workflow_unavailable")
    for name in names:
        validate_top_level_permissions(
            read_text_file(os.path.join(directory, name), "workflow_unavailable")
        )
    lane_text = read_text_file(
        os.path.join(str(root), *WORKFLOW_PATH.split("/")), "workflow_unavailable"
    )
    return validate_lane_controls(lane_text)


def probe_native_tools(platform, environ):
    if type(platform) is not str or platform not in PLATFORMS:
        raise BaselinesRefusal("platform_unknown")
    search = [item for item in str(environ.get("PATH", "")).split(os.pathsep) if item]
    search.extend(EXTRA_TOOL_DIRECTORIES[platform])
    search_path = os.pathsep.join(search)
    results = []
    for name, required in NATIVE_TOOLS[platform]:
        present = shutil.which(name, path=search_path) is not None
        results.append((name, required, present))
    return results


def compute_statistic(name, values):
    if type(name) is not str or name not in STATISTICS:
        raise BaselinesRefusal("record_statistic")
    if type(values) is not list or not values:
        raise BaselinesRefusal("record_statistic")
    ordered = sorted(values)
    if name == "min":
        return ordered[0]
    if name == "max":
        return ordered[-1]
    rank = (PERCENTILES[name] * len(ordered) + 99) // 100
    if rank < 1:
        rank = 1
    return ordered[rank - 1]


def validate_identity(identity):
    if type(identity) is not dict or set(identity) != IDENTITY_FIELDS:
        raise BaselinesRefusal("record_identity")
    checks = (
        _is_member(identity["evidence_class"], EVIDENCE_CLASSES),
        _is_match(identity["source_sha"], SHA1_RE),
        _is_match(identity["control_sha"], SHA1_RE),
        _is_int(identity["source_repository_id"], 1, MAX_SAFE_INTEGER),
        _is_match(identity["oracle_tree"], SHA1_RE),
        _is_int(identity["run_id"], 1, MAX_SAFE_INTEGER),
        _is_int(identity["run_attempt"], 1, MAX_SAFE_INTEGER),
        _is_match(identity["admission_receipt_digest"], SHA256_RE),
        _is_member(identity["platform"], PLATFORMS),
        _is_match(identity["architecture"], LABEL_RE),
        _is_match(identity["image_os"], LABEL_RE),
        _is_match(identity["image_version"], IMAGE_VERSION_RE),
        _is_match(identity["lockfile_digest"], SHA256_RE),
        _is_match(identity["fixture_digest"], SHA256_RE),
        _is_match(identity["method_digest"], SHA256_RE),
        _is_match(identity["calibration_digest"], SHA256_RE),
        _is_int(identity["method_version"], 1, 65535),
    )
    if not all(checks):
        raise BaselinesRefusal("record_identity")
    toolchain = identity["toolchain"]
    if type(toolchain) is not list or len(toolchain) > MAX_TOOLCHAIN_ITEMS:
        raise BaselinesRefusal("record_identity")
    seen = set()
    for item in toolchain:
        if type(item) is not dict or set(item) != {"name", "version"}:
            raise BaselinesRefusal("record_identity")
        if not _is_member(item["name"], TOOLCHAIN_NAMES) or item["name"] in seen:
            raise BaselinesRefusal("record_identity")
        if not _is_match(item["version"], VERSION_RE):
            raise BaselinesRefusal("record_identity")
        seen.add(item["name"])
    return True


def validate_row(row):
    if type(row) is not dict:
        raise BaselinesRefusal("record_row")
    metric_id = row.get("metric_id")
    if type(metric_id) is not str or metric_id not in METRICS:
        raise BaselinesRefusal("record_row")
    suite_id, unit, max_length, native = METRICS[metric_id]
    expected = COMMON_ROW_FIELDS | NATIVE_ROW_FIELDS if native else COMMON_ROW_FIELDS
    if set(row) != expected:
        raise BaselinesRefusal("record_fields")
    if row["suite_id"] != suite_id or row["unit"] != unit:
        raise BaselinesRefusal("record_row")
    if not _is_member(row["variant_id"], VARIANTS):
        raise BaselinesRefusal("record_row")
    if not _is_member(row["status"], STATUSES):
        raise BaselinesRefusal("record_row")
    if not _is_member(row["batch_kind"], BATCH_KINDS):
        raise BaselinesRefusal("record_row")
    if not _is_int(row["batch_index"], 0, MAX_BATCHES - 1):
        raise BaselinesRefusal("record_row")
    primary = row["batch_kind"] == "primary"
    if primary != (row["batch_index"] < MAX_PRIMARY_BATCHES):
        raise BaselinesRefusal("record_row")
    values = row["values"]
    if type(values) is not list or len(values) > min(max_length, MAX_VECTOR_LENGTH):
        raise BaselinesRefusal("record_row")
    for value in values:
        if not _is_int(value, 0, MAX_SAFE_INTEGER):
            raise BaselinesRefusal("record_row")
    if row["observation_count"] != len(values) or type(row["observation_count"]) is not int:
        raise BaselinesRefusal("record_row")
    if not _is_member(row["statistic_name"], STATISTICS):
        raise BaselinesRefusal("record_statistic")
    if row["status"] == "ok":
        if not values:
            raise BaselinesRefusal("record_row")
        statistic = row["statistic_value"]
        if type(statistic) is not int or statistic != compute_statistic(
            row["statistic_name"], values
        ):
            raise BaselinesRefusal("record_statistic")
    elif row["statistic_value"] is not None:
        raise BaselinesRefusal("record_statistic")
    if native:
        native_checks = (
            _is_member(row["profile_mode"], PROFILE_MODES),
            _is_match(row["seed_digest"], SHA256_RE),
            _is_int(row["setup_count"], 0, 1000),
            _is_int(row["primer_count"], 0, 1000),
            _is_int(row["isolation_code"], 0, 255),
            _is_int(row["termination_code"], 0, 255),
            _is_int(row["cleanup_code"], 0, 255),
        )
        if not all(native_checks):
            raise BaselinesRefusal("record_row")
    return True


def canonical_bytes(block):
    try:
        text = json.dumps(
            block,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError):
        raise BaselinesRefusal("record_malformed")
    return text.encode("ascii")


def validate_block(block):
    if type(block) is not dict or set(block) != BLOCK_FIELDS:
        raise BaselinesRefusal("record_fields")
    if block["schema"] != SCHEMA:
        raise BaselinesRefusal("record_fields")
    validate_identity(block["identity"])
    rows = block["rows"]
    if type(rows) is not list or not rows or len(rows) > MAX_ROWS:
        raise BaselinesRefusal("record_row")
    seen = set()
    for row in rows:
        validate_row(row)
        key = (row["metric_id"], row["variant_id"], row["batch_index"])
        if key in seen:
            raise BaselinesRefusal("record_row")
        seen.add(key)
    if len(canonical_bytes(block)) > MAX_BLOCK_BYTES:
        raise BaselinesRefusal("record_oversize")
    return True


def _reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise BaselinesRefusal("record_malformed")
        result[key] = value
    return result


def _reject_constant(name):
    raise BaselinesRefusal("record_malformed")


def load_block(payload):
    if type(payload) is not bytes:
        raise BaselinesRefusal("record_malformed")
    if len(payload) > MAX_BLOCK_BYTES:
        raise BaselinesRefusal("record_oversize")
    try:
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except BaselinesRefusal:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise BaselinesRefusal("record_malformed")
    validate_block(value)
    return value


def build_synthetic_block(runner, control_sha, run_id, run_attempt):
    zero_digest = "0" * 64
    python_version = "%d.%d.%d" % (
        sys.version_info[0],
        sys.version_info[1],
        sys.version_info[2],
    )
    identity = {
        "evidence_class": "synthetic",
        "source_sha": "0" * 40,
        "control_sha": control_sha,
        "source_repository_id": 1,
        "oracle_tree": "0" * 40,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "admission_receipt_digest": zero_digest,
        "platform": runner["platform"],
        "architecture": runner["architecture"],
        "image_os": runner["image_os"],
        "image_version": runner["image_version"],
        "toolchain": [{"name": "python", "version": python_version}],
        "lockfile_digest": zero_digest,
        "fixture_digest": zero_digest,
        "method_digest": zero_digest,
        "calibration_digest": zero_digest,
        "method_version": 1,
    }
    values = [MAX_SAFE_INTEGER - offset for offset in range(MAX_VECTOR_LENGTH)]
    rows = []
    for index in range(MAX_BATCHES):
        rows.append(
            {
                "suite_id": "ipc",
                "metric_id": "ipc.echo-64",
                "variant_id": "default",
                "batch_index": index,
                "batch_kind": "primary" if index < MAX_PRIMARY_BATCHES else "confirmation",
                "observation_count": len(values),
                "unit": "us",
                "status": "ok",
                "values": list(values),
                "statistic_name": "p95",
                "statistic_value": compute_statistic("p95", values),
            }
        )
    block = {"schema": SCHEMA, "identity": identity, "rows": rows}
    validate_block(block)
    return block


def render_summary(block):
    validate_block(block)
    payload = canonical_bytes(block)
    identity = block["identity"]
    fence = chr(96) * 3
    header = " ".join(
        (
            BEGIN_MARKER,
            "rows=" + str(len(block["rows"])),
            "bytes=" + str(len(payload)),
            "digest=" + hashlib.sha256(payload).hexdigest(),
            "control-sha=" + identity["control_sha"],
            "run-id=" + str(identity["run_id"]),
            "run-attempt=" + str(identity["run_attempt"]),
            "platform=" + identity["platform"],
            "evidence-class=" + identity["evidence_class"],
        )
    )
    footer = END_MARKER + " digest=" + hashlib.sha256(payload).hexdigest()
    return "\n".join((header, fence + "text", payload.decode("ascii"), fence, footer)) + "\n"


def _parse_fields(line, marker):
    parts = line.split(" ")
    if parts[0] != marker:
        raise BaselinesRefusal("summary_shape")
    fields = {}
    for part in parts[1:]:
        key, separator, value = part.partition("=")
        if not separator or not key or key in fields:
            raise BaselinesRefusal("summary_shape")
        fields[key] = value
    return fields


def audit_summary(text, control_sha, run_id, run_attempt, platform):
    if type(text) is not str:
        raise BaselinesRefusal("summary_shape")
    lines = text.split("\n")
    begins = [index for index, line in enumerate(lines) if line.startswith(BEGIN_MARKER + " ")]
    ends = [index for index, line in enumerate(lines) if line.startswith(END_MARKER + " ")]
    if len(begins) != 1 or len(ends) != 1:
        raise BaselinesRefusal("summary_markers")
    begin = begins[0]
    if ends[0] != begin + 4:
        raise BaselinesRefusal("summary_shape")
    fence = chr(96) * 3
    if lines[begin + 1] != fence + "text" or lines[begin + 3] != fence:
        raise BaselinesRefusal("summary_shape")
    header = _parse_fields(lines[begin], BEGIN_MARKER)
    footer = _parse_fields(lines[ends[0]], END_MARKER)
    if set(header) != SUMMARY_HEADER_FIELDS or set(footer) != {"digest"}:
        raise BaselinesRefusal("summary_shape")
    try:
        payload = lines[begin + 2].encode("ascii")
    except UnicodeEncodeError:
        raise BaselinesRefusal("summary_shape")
    block = load_block(payload)
    identity = block["identity"]
    digest = hashlib.sha256(payload).hexdigest()
    expected = {
        "rows": str(len(block["rows"])),
        "bytes": str(len(payload)),
        "digest": digest,
        "control-sha": control_sha,
        "run-id": str(run_id),
        "run-attempt": str(run_attempt),
        "platform": platform,
        "evidence-class": identity["evidence_class"],
    }
    if header != expected or footer["digest"] != digest:
        raise BaselinesRefusal("audit_mismatch")
    if (
        identity["control_sha"] != control_sha
        or identity["run_id"] != run_id
        or identity["run_attempt"] != run_attempt
        or identity["platform"] != platform
    ):
        raise BaselinesRefusal("audit_mismatch")
    return block


def append_summary(path, text):
    if type(path) is not str or not path or not os.path.isabs(path):
        raise BaselinesRefusal("summary_unavailable")
    try:
        with open(path, "a", encoding="utf-8", newline="\n") as target:
            target.write(text)
    except OSError:
        raise BaselinesRefusal("summary_unavailable")


def read_summary(path):
    if type(path) is not str or not path or not os.path.isabs(path):
        raise BaselinesRefusal("summary_unavailable")
    try:
        with open(path, "rb") as source:
            payload = source.read(MAX_SUMMARY_BYTES + 1)
    except OSError:
        raise BaselinesRefusal("summary_unavailable")
    if len(payload) > MAX_SUMMARY_BYTES:
        raise BaselinesRefusal("summary_oversize")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        raise BaselinesRefusal("summary_unavailable")


def run_preparation(root, platform, control_sha, environ, emit=print):
    run_id, run_attempt = validate_run_context(environ, control_sha)
    runner = check_runner_identity(platform, environ)
    pins = validate_action_pins(root)
    jobs = validate_job_permissions(root)
    tools = probe_native_tools(platform, environ)
    missing_required = False
    for name, required, present in tools:
        emit(
            "native-tool name=%s required=%s present=%s"
            % (name, "yes" if required else "no", "yes" if present else "no")
        )
        if required and not present:
            missing_required = True
    if missing_required:
        raise BaselinesRefusal("native_tool_missing")
    block = build_synthetic_block(runner, control_sha, run_id, run_attempt)
    summary_path = environ.get("GITHUB_STEP_SUMMARY")
    append_summary(summary_path, "\n" + render_summary(block))
    audited = audit_summary(read_summary(summary_path), control_sha, run_id, run_attempt, platform)
    payload = canonical_bytes(audited)
    return {
        "platform": platform,
        "control_sha": control_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "pins": pins["remote_pins"],
        "workflows": pins["workflows"],
        "jobs": jobs,
        "tools_present": sum(1 for item in tools if item[2]),
        "tools_total": len(tools),
        "rows": len(audited["rows"]),
        "bytes": len(payload),
        "digest": hashlib.sha256(payload).hexdigest(),
    }


def main(argv=None, environ=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--platform", required=True, choices=sorted(PLATFORMS))
    parser.add_argument("--control-sha", required=True)
    arguments = parser.parse_args(argv)
    environment = os.environ if environ is None else environ
    try:
        result = run_preparation(
            arguments.root, arguments.platform, arguments.control_sha, environment
        )
    except BaselinesRefusal as refusal:
        print(VERDICT_PREFIX + "refused code=" + refusal.code)
        return 1
    except OSError:
        print(VERDICT_PREFIX + "refused code=runner_unavailable")
        return 1
    print(
        VERDICT_PREFIX
        + "ok platform=%s control-sha=%s run-id=%d run-attempt=%d workflows=%d pins=%d jobs=%d "
        "native-tools=%d/%d rows=%d bytes=%d digest=%s"
        % (
            result["platform"],
            result["control_sha"],
            result["run_id"],
            result["run_attempt"],
            result["workflows"],
            result["pins"],
            result["jobs"],
            result["tools_present"],
            result["tools_total"],
            result["rows"],
            result["bytes"],
            result["digest"],
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
