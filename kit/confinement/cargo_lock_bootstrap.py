"""Bounded Cargo lock bootstrap: forced settings, proposed receipt, evidence and return bundle.

Every check that needs no network runs before the first registry request. The
bundle limits here are the Cargo lock profile's own limits and never reuse the
Node lock channel size.

Manifests are checked before any Cargo command. A version metadata response may be up
to 512 KiB, which leaves room for crates with very large feature maps such as windows-sys
and web-sys; anything larger is refused. The User-Agent names the project only and carries
no contact address, because a contact URL or email is forbidden in the public tree.
"""

import base64
import calendar
import datetime
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
import posixpath
from pathlib import Path
import re
import stat
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

try:
    import cargo_lock_receipt as cargo
except ImportError:
    _receipt_path = Path(__file__).resolve(strict=True).parent / "cargo_lock_receipt.py"
    _receipt_spec = importlib.util.spec_from_file_location("cargo_lock_receipt", str(_receipt_path))
    if _receipt_spec is None or _receipt_spec.loader is None:
        raise ImportError("cargo lock receipt unavailable")
    cargo = importlib.util.module_from_spec(_receipt_spec)
    sys.modules["cargo_lock_receipt"] = cargo
    try:
        _receipt_spec.loader.exec_module(cargo)
    except BaseException:
        sys.modules.pop("cargo_lock_receipt", None)
        raise ImportError("cargo lock receipt unavailable") from None


SCHEMA_VERSION = 1
MAX_BUNDLE_BYTES = 1024 * 1024
MAX_LOCK_BYTES = 256 * 1024
MAX_RECEIPT_BYTES = 128 * 1024
MAX_EVIDENCE_BYTES = 192 * 1024
MAX_PACKAGES = 512
MAX_INDEX_ENTRY_BYTES = 4 * 1024 * 1024
MAX_API_BYTES = 512 * 1024
MAX_TREE_ENTRIES = 20_000
MAX_SOURCE_INVENTORY_BYTES = 1024 * 1024
MAX_SOURCE_INVENTORY_ROWS = 20_000
MAX_INVENTORY_FILE_BYTES = 64 * 1024 * 1024
MIN_PACKAGE_AGE_SECONDS = 7 * 24 * 60 * 60
CLOCK_SKEW_SECONDS = 300
MAX_REQUEST_TTL_SECONDS = 24 * 60 * 60
PENDING_AUDIT_ID = "pending-review"
DEPENDENCY_POLICY_REVISION = "contract-policy-2026-10-29.1"
BUILD_INPUT_ALLOWLIST = ()
INDEX_HOST = "index.crates.io"
API_HOST = "crates.io"
USER_AGENT = "platform-ci-cargo-lock-bootstrap"
FETCH_TIMEOUT_SECONDS = 30
HEX64_RE = re.compile(r"[a-f0-9]{64}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
SOURCE_LINE_RE = re.compile(r"\s*source\s*=\s*\"([^\"]*)\"\s*\Z")
SOURCE_SHA_RE = re.compile(r"[a-f0-9]{40}\Z")
DEPENDENCY_SOURCE_RE = re.compile(r"\(([A-Za-z][A-Za-z0-9+.-]*\+[^()\"]*)\)")
CREATED_AT_RE = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.[0-9]{1,9})?(?:Z|\+00:00)\Z"
)
CRATE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
MAX_MANIFEST_BYTES = 256 * 1024
MAX_MANIFEST_LINES = 8192
MAX_MANIFEST_VALUE_DEPTH = 8
MAX_MANIFESTS = 32
MAX_WORKSPACE_EXCLUDE = 64
CONTRACT_WORKSPACE = "contract"
RUNTIME_WORKSPACE = "runtime"
RUNTIME_WORKSPACE_DIRECTORY = "runtime"
WORKSPACE_DIRECTORIES = {CONTRACT_WORKSPACE: ".", RUNTIME_WORKSPACE: RUNTIME_WORKSPACE_DIRECTORY}
CONTRACT_BASE_MEMBERS = frozenset((
    "crates/host/api", "crates/host/mock", "crates/host/conformance", "crates/kernel/i18n",
))
CONTRACT_XTASK_MEMBER = "tools/xtask"
CONTRACT_DEMO_MEMBER = "crates/host/conformance/fixtures/demo-tool"
CONTRACT_WAVE_70A_MEMBERS = CONTRACT_BASE_MEMBERS | frozenset((CONTRACT_XTASK_MEMBER,))
CONTRACT_WAVE_70B_MEMBERS = CONTRACT_WAVE_70A_MEMBERS | frozenset((CONTRACT_DEMO_MEMBER,))
CONTRACT_MEMBERS = CONTRACT_BASE_MEMBERS
CONTRACT_PACKAGE_NAMES = {
    "crates/host/api": "keeldock" + "-host-api",
    "crates/host/mock": "keeldock" + "-host-mock",
    "crates/host/conformance": "keeldock" + "-host-conformance",
    "crates/kernel/i18n": "keeldock" + "-kernel-i18n",
}
CONTRACT_ROOT_DEPENDENCIES = {
    "keeldock" + "-host-api": {"path": "crates/host/api"},
    "keeldock" + "-host-mock": {"path": "crates/host/mock"},
}
CONTRACT_FIRST_BATCH_DEPENDENCIES = {
    "serde": {
        "version": "=1.0.229", "default-features": False, "features": ["derive", "std"],
    },
    "serde_json": {
        "version": "=1.0.154", "default-features": False, "features": ["std"],
    },
    "schemars": {
        "version": "=1.2.3", "default-features": False, "features": ["derive", "std"],
    },
}
CONTRACT_MEMBER_DEPENDENCIES = {
    "crates/host/api": {"dependencies": CONTRACT_FIRST_BATCH_DEPENDENCIES},
    "crates/host/mock": {
        "dependencies": {"keeldock" + "-host-api": {"workspace": True}},
    },
    "crates/host/conformance": {
        "dependencies": {"keeldock" + "-host-api": {"workspace": True}},
        "dev-dependencies": {"keeldock" + "-host-mock": {"workspace": True}},
    },
    "crates/kernel/i18n": {"dependencies": {}},
}
CONTRACT_API_MANIFEST_PATH = "crates/host/api/Cargo.toml"
HOST_API_POLICY_API_PACKAGE = "keeldock" + "-host-api"
HOST_API_POLICY_API_PATH = "../crates/host/api"
HOST_API_POLICY_API_VERSION = "=0.2.0"
HOST_API_POLICY_API_WORKSPACE_SPEC = {
    "path": HOST_API_POLICY_API_PATH, "version": HOST_API_POLICY_API_VERSION,
}
HOST_API_POLICY_API_MANIFEST_PATH = CONTRACT_API_MANIFEST_PATH
HOST_API_POLICY_API_SOURCE_PREFIX = "crates/host/api/src/"
HOST_API_POLICY_RUNTIME_CONSUMER_ROOTS = (
    "runtime/crates/host/registry", "runtime/crates/host/core",
    "runtime/crates/host/settings-schema", "runtime/crates/services/palette",
    "runtime/crates/services/notifications", "runtime/crates/host/entitlements",
    "runtime/crates/services/log", "runtime/crates/services/fs",
    "runtime/crates/services/store", "runtime/crates/services/vault",
    "runtime/apps/test-shell-desktop/src-tauri",
    "runtime/apps/test-shell-mobile/src-tauri",
)
HOST_API_POLICY_RUNTIME_BASE_CONSUMER_ROOTS = HOST_API_POLICY_RUNTIME_CONSUMER_ROOTS[:5]
RUNTIME_WAVE_70_NEW_CONSUMER_ROOTS = (
    "runtime/crates/host/entitlements", "runtime/crates/services/log",
    "runtime/crates/services/fs", "runtime/crates/services/store",
    "runtime/crates/services/vault", "runtime/apps/test-shell-desktop/src-tauri",
    "runtime/apps/test-shell-mobile/src-tauri",
)
RUNTIME_WAVE_70A_NEW_CONSUMER_ROOTS = (
    "runtime/apps/test-shell-desktop/src-tauri",
    "runtime/apps/test-shell-mobile/src-tauri",
)
RUNTIME_WAVE_70_SOURCE_ROOTS = RUNTIME_WAVE_70_NEW_CONSUMER_ROOTS[:5]
HOST_API_POLICY_RUNTIME_BASE_MEMBER_ROOTS = (
    "runtime/crates/services/sync-publication",
    "runtime/crates/test-fixtures/host-router",
    "runtime/crates/test-fixtures/fixture-data",
    "runtime/crates/test-fixtures/tool-a",
    "runtime/crates/test-fixtures/tool-b",
    "runtime/crates/test-fixtures/tool-bad-no-handler",
    "runtime/crates/test-fixtures/tool-bad-no-manifest",
)
HOST_API_POLICY_RUNTIME_BASE_WORKSPACE_DEPENDENCIES = {
    "host-router": {"path": "crates/test-fixtures/host-router"},
    "fixture-data": {"path": "crates/test-fixtures/fixture-data"},
    "tool-a": {"path": "crates/test-fixtures/tool-a"},
    "tool-b": {"path": "crates/test-fixtures/tool-b"},
    "tool-bad-no-handler": {"path": "crates/test-fixtures/tool-bad-no-handler"},
    "tool-bad-no-manifest": {"path": "crates/test-fixtures/tool-bad-no-manifest"},
}
RUNTIME_BATCH_SEVEN_CRATE_ROOTS = HOST_API_POLICY_RUNTIME_CONSUMER_ROOTS[:5]
RUNTIME_WAVE_70_CRATE_ROOTS = RUNTIME_WAVE_70_SOURCE_ROOTS
RUNTIME_BATCH_SEVEN_DOC_FILES = frozenset(("README.md", "CONTRACT.md", "CHANGELOG.md"))
RUNTIME_CONFIG_FILES = ("rust-toolchain.toml", "rustfmt.toml", "clippy.toml")
RUNTIME_EXISTING_SERVICE_DOC_ROOT = "runtime/crates/services/sync-publication"
RUNTIME_EXISTING_SERVICE_DOC_FILES = frozenset(("README.md", "CONTRACT.md", "CHANGELOG.md"))
HOST_API_POLICY_OPTIONAL_SYNC_FORMAT_ROOT = "runtime/crates/services/sync-format"
HOST_API_POLICY_RUNTIME_REQUIRED_MEMBER_ROOTS = (
    "runtime/crates/services/sync-publication",
    "runtime/crates/test-fixtures/host-router",
    "runtime/crates/test-fixtures/fixture-data",
    "runtime/crates/test-fixtures/tool-a",
    "runtime/crates/test-fixtures/tool-b",
    "runtime/crates/test-fixtures/tool-bad-no-handler",
    "runtime/crates/test-fixtures/tool-bad-no-manifest",
    *HOST_API_POLICY_RUNTIME_BASE_CONSUMER_ROOTS,
)
HOST_API_POLICY_RUNTIME_BASE_REQUIRED_MEMBER_ROOTS = (
    *HOST_API_POLICY_RUNTIME_BASE_MEMBER_ROOTS,
    *HOST_API_POLICY_RUNTIME_BASE_CONSUMER_ROOTS,
)
HOST_API_POLICY_RUNTIME_WAVE_70A_REQUIRED_MEMBER_ROOTS = (
    *HOST_API_POLICY_RUNTIME_BASE_REQUIRED_MEMBER_ROOTS,
    *RUNTIME_WAVE_70A_NEW_CONSUMER_ROOTS,
)
HOST_API_POLICY_RUNTIME_WAVE_70B_REQUIRED_MEMBER_ROOTS = (
    *HOST_API_POLICY_RUNTIME_BASE_REQUIRED_MEMBER_ROOTS,
    *RUNTIME_WAVE_70_NEW_CONSUMER_ROOTS,
)
HOST_API_POLICY_RUNTIME_OPTIONAL_MEMBER_ROOTS = (HOST_API_POLICY_OPTIONAL_SYNC_FORMAT_ROOT,)
RUNTIME_APP_TAURI_ROOTS = (
    "runtime/apps/test-shell-desktop/src-tauri",
    "runtime/apps/test-shell-mobile/src-tauri",
)
RUNTIME_FRONTEND_SOURCE_ROOTS = (
    "runtime/apps/test-shell-desktop/web/src",
    "runtime/apps/test-shell-mobile/web/src",
    "runtime/packages/host-ui/src",
)
RUNTIME_FRONTEND_SOURCE_SUFFIXES = frozenset((".css", ".js", ".jsx", ".json", ".ts", ".tsx"))
RUNTIME_MEMBER_PATH_RE = re.compile(
    RUNTIME_WORKSPACE_DIRECTORY
    + r"/crates/[a-z][a-z0-9]*(?:-[a-z0-9]+)*/[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z"
)
EXCLUDE_PATH_RE = re.compile(r"[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*\Z")
BARE_KEY_RE = re.compile(r"[A-Za-z0-9_-]+")
NUMBER_RE = re.compile(r"[+-]?[0-9][0-9_]*(?:\.[0-9_]+)?(?:[eE][+-]?[0-9]+)?")
MANIFEST_PIN_RE = re.compile(
    r"=(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z"
)
DEPENDENCY_TABLE_NAMES = ("dependencies", "dev-dependencies", "build-dependencies")
REQUIRED_EDITION = "2024"
ALLOWED_TOP_TABLES = frozenset((
    "package", "lib", "bin", "example", "test", "bench", "dependencies", "dev-dependencies",
    "build-dependencies", "target", "features", "workspace", "profile", "lints",
))
ALLOWED_TARGET_KEYS = frozenset(("dependencies", "dev-dependencies", "build-dependencies"))
ALLOWED_WORKSPACE_KEYS = frozenset((
    "members", "exclude", "default-members", "resolver", "package", "dependencies", "metadata",
    "lints",
))
ARRAY_TABLE_NAMES = frozenset(("bin", "example", "test", "bench"))
DEPENDENCY_SPEC_KEYS = frozenset((
    "version", "path", "features", "default-features", "default_features", "optional",
    "package", "workspace",
))
FORBIDDEN_ENVIRONMENT_PREFIXES = (
    "CARGO_", "RUSTC", "RUSTUP", "RUSTFLAGS", "RUSTDOC", "GIT_", "SSL_", "CURL_",
)
PROXY_ENVIRONMENT_NAMES = frozenset((
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY", "PROXY",
))
TARGET_RUNNER_TRIPLES = (
    "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc",
    "x86_64-apple-darwin", "aarch64-apple-darwin",
)
CONTEXT_FIELDS = frozenset(cargo.CONTEXT_FIELDS)
EVIDENCE_FIELDS = frozenset((
    "schema_version", "receipt_sha256", "lock_sha256", "run_id", "run_attempt",
    "generated_at", "expiry", "minimum_age_seconds", "index_origin", "api_origin", "toolchain_target",
    "build_inputs", "packages",
))
EVIDENCE_PACKAGE_FIELDS = frozenset((
    "name", "version", "checksum", "index_entry_sha256", "created_at",
))
BUNDLE_FIELDS = frozenset(("schema_version", "lock_b64", "receipt_b64", "evidence_b64"))
REASONS = frozenset((
    "bootstrap_input_invalid", "bootstrap_config_refused", "bootstrap_environment_refused",
    "bootstrap_lock_refused", "bootstrap_mismatch", "bootstrap_source_refused",
    "bootstrap_package_too_young", "bootstrap_package_yanked", "bootstrap_evidence_invalid",
    "bootstrap_network_refused", "bootstrap_payload_too_large", "bootstrap_build_input_refused",
    "bootstrap_stale", "bootstrap_manifest_refused",
))
CARGO_REASON_MAP = {
    "cargo_lock_invalid": "bootstrap_lock_refused",
    "cargo_receipt_invalid": "bootstrap_mismatch",
    "cargo_lock_mismatch": "bootstrap_mismatch",
}


class BootstrapRefusal(Exception):
    """A refusal with a fixed reason that never contains caller-provided data."""

    def __init__(self, reason="bootstrap_input_invalid"):
        if reason not in REASONS:
            reason = "bootstrap_input_invalid"
        self.reason = reason
        super().__init__(reason)


def _refuse(reason="bootstrap_input_invalid"):
    raise BootstrapRefusal(reason)


def _call_cargo(function, *arguments):
    try:
        return function(*arguments)
    except cargo.Refusal as error:
        raise BootstrapRefusal(CARGO_REASON_MAP.get(error.reason, "bootstrap_mismatch")) from None


def _valid_hex(value):
    return type(value) is str and HEX64_RE.fullmatch(value) is not None


def _canonical(record, reason):
    try:
        return json.dumps(
            record, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("ascii", "strict")
    except (TypeError, ValueError, UnicodeError):
        _refuse(reason)


def _strict_json(data, maximum, reason, encoding="ascii"):
    if type(data) is not bytes or not 0 < len(data) <= maximum:
        _refuse(reason)
    try:
        return json.loads(
            data.decode(encoding, "strict"), object_pairs_hook=cargo._unique_json_pairs,
            parse_constant=cargo._reject_json_constant,
        )
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _refuse(reason)


def forced_config_items():
    """Return the Cargo settings the bootstrap forces, as ordered key and value pairs."""
    items = [
        ("registry.global-credential-providers", "[]"),
        ("registry.credential-provider", json.dumps("cargo:token")),
        ("patch.crates-io", "{}"),
        ("net.offline", "false"),
        ("net.git-fetch-with-cli", "false"),
        ("net.retry", "2"),
        ("http.proxy", json.dumps("")),
        ("http.multiplexing", "false"),
        ("http.timeout", "30"),
        ("http.check-revoke", "true"),
    ]
    for triple in TARGET_RUNNER_TRIPLES:
        items.append(("target." + triple + ".runner", "[]"))
    return tuple(items)


def bootstrap_config_arguments():
    """Return the forced Cargo command line settings for lock generation."""
    arguments = []
    for key, value in forced_config_items():
        arguments.extend(("--config", key + "=" + value))
    return tuple(arguments)


def _absolute(value):
    return os.path.isabs(value) or posixpath.isabs(value)


def generate_lockfile_command(cargo_executable, manifest_path):
    """Return the one Cargo command that resolves a lock without building or running code."""
    for value in (cargo_executable, manifest_path):
        if (type(value) is not str or not _absolute(value) or len(value) > 4096
                or "\x00" in value or "\n" in value or "\r" in value):
            _refuse("bootstrap_input_invalid")
    if os.path.basename(manifest_path) != "Cargo.toml":
        _refuse("bootstrap_input_invalid")
    return (cargo_executable,) + bootstrap_config_arguments() + (
        "generate-lockfile", "--manifest-path", manifest_path,
    )


def injected_environment_names(parent):
    """Name every inherited variable that would reach Cargo configuration or networking."""
    if type(parent) is not dict:
        _refuse("bootstrap_environment_refused")
    names = []
    for name in parent:
        if type(name) is not str:
            _refuse("bootstrap_environment_refused")
        upper = name.upper()
        if (upper.startswith(FORBIDDEN_ENVIRONMENT_PREFIXES)
                or upper in PROXY_ENVIRONMENT_NAMES or upper.endswith("_PROXY")):
            names.append(name)
    return tuple(sorted(names))


def _environment_text(value, absolute):
    if (type(value) is not str or not value or len(value) > 4096 or "\x00" in value
            or "\n" in value or "\r" in value or (absolute and not _absolute(value))):
        _refuse("bootstrap_environment_refused")
    return value


def build_cargo_environment(parent, *, cargo_home, home, tmpdir, path):
    """Build the whole Cargo environment from fixed values; nothing is inherited from parent."""
    injected_environment_names(parent)
    return {
        "PATH": _environment_text(path, False),
        "HOME": _environment_text(home, True),
        "CARGO_HOME": _environment_text(cargo_home, True),
        "TMPDIR": _environment_text(tmpdir, True),
        "LANG": "C",
        "LC_ALL": "C",
    }


def require_fresh_directory(path):
    """Require an existing empty directory that is not a link."""
    try:
        directory = Path(path)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError
        if os.listdir(directory):
            raise ValueError
    except (OSError, ValueError, TypeError):
        _refuse("bootstrap_environment_refused")
    return True


def refuse_cargo_config(source_root):
    """Refuse any Cargo configuration in the tree or in any parent directory."""
    try:
        root = Path(source_root)
        if not root.is_absolute() or not root.is_dir() or root.is_symlink():
            raise ValueError
    except (OSError, ValueError, TypeError):
        _refuse("bootstrap_config_refused")
    count = 0
    failed = []

    def on_error(error):
        failed.append(error)

    for current, directories, files in os.walk(root, followlinks=False, onerror=on_error):
        for name in directories + files:
            count += 1
            if count > MAX_TREE_ENTRIES:
                _refuse("bootstrap_config_refused")
            entry = Path(current) / name
            if name.lower().startswith(".cargo") or entry.is_symlink():
                _refuse("bootstrap_config_refused")
    if failed:
        _refuse("bootstrap_config_refused")
    for parent in root.parents:
        if os.path.lexists(parent / ".cargo"):
            _refuse("bootstrap_config_refused")
    return True


def validate_build_inputs(inputs, allowed=BUILD_INPUT_ALLOWLIST):
    """Accept only allowlisted build inputs; the allowlist is empty until one is admitted."""
    if type(inputs) is not dict or type(allowed) is not tuple or len(inputs) > len(allowed):
        _refuse("bootstrap_build_input_refused")
    for name, value in inputs.items():
        if (type(name) is not str or name not in allowed or type(value) is not str
                or not 0 < len(value) <= 256 or not value.isascii() or not value.isprintable()):
            _refuse("bootstrap_build_input_refused")
    return dict(inputs)


def _manifest_refuse():
    _refuse("bootstrap_manifest_refused")


def _skip_space(text, index):
    while index < len(text) and text[index] in " \t":
        index += 1
    return index


def _strip_comment(line):
    quote = None
    for index, character in enumerate(line):
        if quote is not None:
            if character == quote:
                quote = None
        elif character in "\"'":
            quote = character
        elif character == "\x23":
            return line[:index]
    if quote is not None:
        _manifest_refuse()
    return line


def _bracket_depth(text):
    depth = 0
    quote = None
    for character in text:
        if quote is not None:
            if character == quote:
                quote = None
        elif character in "\"'":
            quote = character
        elif character in "[{":
            depth += 1
        elif character in "]}":
            depth -= 1
    if quote is not None or depth < 0:
        _manifest_refuse()
    return depth


def _parse_key(text, index):
    parts = []
    while True:
        index = _skip_space(text, index)
        if index >= len(text):
            _manifest_refuse()
        if text[index] in "\"'":
            end = text.find(text[index], index + 1)
            if end < 0:
                _manifest_refuse()
            part = text[index + 1:end]
            index = end + 1
        else:
            match = BARE_KEY_RE.match(text, index)
            if match is None:
                _manifest_refuse()
            part = match.group(0)
            index = match.end()
        if not part:
            _manifest_refuse()
        parts.append(part)
        index = _skip_space(text, index)
        if index < len(text) and text[index] == ".":
            index += 1
            continue
        return parts, index


def _set_path(table, parts, value):
    current = table
    for part in parts[:-1]:
        current = current.setdefault(part, {})
        if type(current) is not dict:
            _manifest_refuse()
    if parts[-1] in current:
        _manifest_refuse()
    current[parts[-1]] = value


def _parse_value(text, index, depth):
    if depth > MAX_MANIFEST_VALUE_DEPTH:
        _manifest_refuse()
    index = _skip_space(text, index)
    if index >= len(text):
        _manifest_refuse()
    character = text[index]
    if character in "\"'":
        end = text.find(character, index + 1)
        if end < 0:
            _manifest_refuse()
        return text[index + 1:end], end + 1
    if character == "[":
        values = []
        index += 1
        while True:
            index = _skip_space(text, index)
            if index < len(text) and text[index] == "]":
                return values, index + 1
            value, index = _parse_value(text, index, depth + 1)
            values.append(value)
            index = _skip_space(text, index)
            if index < len(text) and text[index] == ",":
                index += 1
            elif index >= len(text) or text[index] != "]":
                _manifest_refuse()
    if character == "{":
        table = {}
        index += 1
        while True:
            index = _skip_space(text, index)
            if index < len(text) and text[index] == "}":
                return table, index + 1
            parts, index = _parse_key(text, index)
            index = _skip_space(text, index)
            if index >= len(text) or text[index] != "=":
                _manifest_refuse()
            value, index = _parse_value(text, index + 1, depth + 1)
            _set_path(table, parts, value)
            index = _skip_space(text, index)
            if index < len(text) and text[index] == ",":
                index += 1
            elif index >= len(text) or text[index] != "}":
                _manifest_refuse()
    for word, value in (("true", True), ("false", False)):
        if text.startswith(word, index):
            return value, index + len(word)
    match = NUMBER_RE.match(text, index)
    if match is None:
        _manifest_refuse()
    return ("number", match.group(0)), match.end()


def _parse_manifest(data):
    if (type(data) is not bytes or not 0 < len(data) <= MAX_MANIFEST_BYTES
            or b"\\" in data or b"\x00" in data):
        _manifest_refuse()
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeError:
        _manifest_refuse()
    if '"""' in text or "'''" in text:
        _manifest_refuse()
    lines = text.split("\n")
    if len(lines) > MAX_MANIFEST_LINES:
        _manifest_refuse()
    document = {}
    current = document
    defined = set()
    position = 0
    while position < len(lines):
        line = _strip_comment(lines[position].rstrip("\r")).strip()
        position += 1
        if not line:
            continue
        if line.startswith("["):
            array = line.startswith("[[")
            closer = "]]" if array else "]"
            if not line.endswith(closer):
                _manifest_refuse()
            inner = line[2:-2] if array else line[1:-1]
            parts, index = _parse_key(inner, 0)
            if _skip_space(inner, index) != len(inner):
                _manifest_refuse()
            if array:
                if len(parts) != 1 or parts[0] not in ARRAY_TABLE_NAMES:
                    _manifest_refuse()
                entries = document.setdefault(parts[0], [])
                if type(entries) is not list:
                    _manifest_refuse()
                current = {}
                entries.append(current)
                continue
            if tuple(parts) in defined:
                _manifest_refuse()
            defined.add(tuple(parts))
            current = document
            for part in parts:
                current = current.setdefault(part, {})
                if type(current) is not dict:
                    _manifest_refuse()
            continue
        parts, index = _parse_key(line, 0)
        index = _skip_space(line, index)
        if index >= len(line) or line[index] != "=":
            _manifest_refuse()
        statement = line[index + 1:]
        while _bracket_depth(statement) > 0:
            if position >= len(lines):
                _manifest_refuse()
            statement += " " + _strip_comment(lines[position].rstrip("\r")).strip()
            position += 1
        value, end = _parse_value(statement, 0, 0)
        if _skip_space(statement, end) != len(statement):
            _manifest_refuse()
        _set_path(current, parts, value)
    return document


def _check_pin(value):
    if type(value) is not str or MANIFEST_PIN_RE.fullmatch(value) is None:
        _manifest_refuse()


def _check_dependency(
        name, spec, directory, members, allow_runtime_profile_runtime_edge=False,
        allow_runtime_profile_versioned_edge=False):
    if type(name) is not str or CRATE_NAME_RE.fullmatch(name) is None:
        _manifest_refuse()
    if type(spec) is str:
        _check_pin(spec)
        return
    if type(spec) is not dict or set(spec) - DEPENDENCY_SPEC_KEYS:
        _manifest_refuse()
    for key in ("default-features", "default_features", "optional"):
        if key in spec and type(spec[key]) is not bool:
            _manifest_refuse()
    features = spec.get("features", [])
    if type(features) is not list or any(type(item) is not str for item in features):
        _manifest_refuse()
    if "package" in spec and (type(spec["package"]) is not str
                              or CRATE_NAME_RE.fullmatch(spec["package"]) is None):
        _manifest_refuse()
    if allow_runtime_profile_runtime_edge and name == HOST_API_POLICY_API_PACKAGE:
        expected = (
            HOST_API_POLICY_API_WORKSPACE_SPEC if allow_runtime_profile_versioned_edge
            else {"path": HOST_API_POLICY_API_PATH}
        )
        if spec != expected:
            _manifest_refuse()
        return
    if "workspace" in spec:
        if spec["workspace"] is not True or "version" in spec or "path" in spec:
            _manifest_refuse()
        return
    if "path" in spec:
        path = spec["path"]
        if type(path) is not str or not path or path.startswith("/") or "\\" in path:
            _manifest_refuse()
        resolved = posixpath.normpath(posixpath.join(directory, path))
        if resolved.startswith("..") or resolved not in members:
            _manifest_refuse()
        if "version" in spec:
            _check_pin(spec["version"])
        return
    if "version" not in spec:
        _manifest_refuse()
    _check_pin(spec["version"])


def _check_workspace_exclude(excluded, members):
    if (type(excluded) is not list or len(excluded) > MAX_WORKSPACE_EXCLUDE
            or any(type(item) is not str for item in excluded)
            or len(set(excluded)) != len(excluded)):
        _manifest_refuse()
    for item in excluded:
        if (EXCLUDE_PATH_RE.fullmatch(item) is None
                or any(part in (".", "..") for part in item.split("/"))):
            _manifest_refuse()
        for member in members:
            if member == item or member.startswith(item + "/"):
                _manifest_refuse()


def workspace_directory(workspace):
    """Map a workspace selector to its fixed root directory; any other value is refused."""
    if type(workspace) is not str or workspace not in WORKSPACE_DIRECTORIES:
        _refuse("bootstrap_input_invalid")
    return WORKSPACE_DIRECTORIES[workspace]


def workspace_root_manifest(workspace):
    """Return the fixed root manifest path of a workspace relative to the source root."""
    directory = workspace_directory(workspace)
    return "Cargo.toml" if directory == "." else directory + "/Cargo.toml"


def _resolved_listing(listed, root_directory):
    if root_directory == ".":
        return listed
    return [posixpath.normpath(posixpath.join(root_directory, item)) for item in listed]


def _check_workspace_members(workspace, members, root_directory="."):
    listed = workspace.get("members")
    if type(listed) is not list or any(type(item) is not str for item in listed):
        _manifest_refuse()
    resolved = _resolved_listing(listed, root_directory)
    if len(set(listed)) != len(listed) or set(resolved) != set(members) or len(set(resolved)) != len(resolved):
        _manifest_refuse()
    if root_directory != "." and (
        "exclude" in workspace or "default-members" in workspace
        or any(".." in item or item.startswith("/") for item in listed)
    ):
        _manifest_refuse()
    if "exclude" in workspace:
        _check_workspace_exclude(workspace["exclude"], members)
    if "default-members" in workspace:
        default = workspace["default-members"]
        if (type(default) is not list or any(type(item) is not str for item in default)
                or len(set(default)) != len(default) or set(default) != set(members)):
            _manifest_refuse()


def _check_document(document, directory, members, is_root, root_directory="."):
    if set(document) - ALLOWED_TOP_TABLES:
        _manifest_refuse()
    workspace = document.get("workspace")
    if workspace is not None:
        if not is_root or type(workspace) is not dict or set(workspace) - ALLOWED_WORKSPACE_KEYS:
            _manifest_refuse()
        _check_workspace_members(workspace, members, root_directory)
    elif is_root:
        _manifest_refuse()
    tables = [(document[name], False) for name in DEPENDENCY_TABLE_NAMES if name in document]
    target = document.get("target")
    if target is not None:
        if type(target) is not dict:
            _manifest_refuse()
        for entry in target.values():
            if type(entry) is not dict or set(entry) - ALLOWED_TARGET_KEYS:
                _manifest_refuse()
            tables.extend((entry[name], False) for name in DEPENDENCY_TABLE_NAMES if name in entry)
    wave70_profile = set(RUNTIME_APP_TAURI_ROOTS).issubset(members)
    if workspace is not None and "dependencies" in workspace:
        tables.append((
            workspace["dependencies"],
            is_root and root_directory == RUNTIME_WORKSPACE_DIRECTORY,
            wave70_profile,
        ))
    for table in tables:
        if len(table) == 2:
            table, allow_runtime_profile_runtime_edge = table
            allow_runtime_profile_versioned_edge = False
        else:
            table, allow_runtime_profile_runtime_edge, allow_runtime_profile_versioned_edge = table
        if type(table) is not dict:
            _manifest_refuse()
        for name, spec in table.items():
            _check_dependency(
                name, spec, directory, members, allow_runtime_profile_runtime_edge,
                allow_runtime_profile_versioned_edge,
            )
    package = document.get("package")
    if package is None:
        return None, None
    if root_directory != "." and is_root:
        _manifest_refuse()
    if (type(package) is not dict or type(package.get("name")) is not str
            or "workspace" in package or "edition" not in package):
        _manifest_refuse()
    return package["name"], package["edition"]


def _check_contract_dependency_policy(documents, *, require_first_batch=True):
    root = documents.get("Cargo.toml")
    workspace = root.get("workspace") if type(root) is dict else None
    members = frozenset(
        posixpath.normpath(item) for item in workspace.get("members", ())
    ) if type(workspace) is dict and type(workspace.get("members")) is list else frozenset()
    if (type(workspace) is not dict
            or workspace.get("dependencies") != CONTRACT_ROOT_DEPENDENCIES
            or members not in (CONTRACT_BASE_MEMBERS, CONTRACT_WAVE_70A_MEMBERS,
                               CONTRACT_WAVE_70B_MEMBERS)):
        _manifest_refuse()
    expected_names = dict(CONTRACT_PACKAGE_NAMES)
    if members >= CONTRACT_WAVE_70A_MEMBERS:
        expected_names[CONTRACT_XTASK_MEMBER] = "keeldock" + "-" + "xtask"
    if members == CONTRACT_WAVE_70B_MEMBERS:
        expected_names[CONTRACT_DEMO_MEMBER] = "keeldock" + "-" + "demo-tool"
    if set(documents) != {"Cargo.toml"} | {member + "/Cargo.toml" for member in members}:
        _manifest_refuse()
    for member, expected_name in expected_names.items():
        document = documents.get(member + "/Cargo.toml")
        package = document.get("package") if type(document) is dict else None
        if type(package) is not dict or package.get("name") != expected_name:
            _manifest_refuse()
        if "target" in document:
            _manifest_refuse()
        if member == CONTRACT_XTASK_MEMBER:
            expected_tables = {"dependencies": {
                HOST_API_POLICY_API_PACKAGE: {"path": "../../crates/host/api"},
            }}
        elif member == CONTRACT_DEMO_MEMBER:
            expected_tables = {"dependencies": {
                HOST_API_POLICY_API_PACKAGE: {"path": "../../../api", "version": "=0.2.0"},
            }}
        else:
            expected_tables = CONTRACT_MEMBER_DEPENDENCIES[member]
        for table_name in DEPENDENCY_TABLE_NAMES:
            if (member == "crates/host/api" and not require_first_batch
                    and table_name == "dependencies"):
                continue
            if document.get(table_name, {}) != expected_tables.get(table_name, {}):
                _manifest_refuse()


def _check_runtime_profile(documents, member_set):
    base_required = frozenset(HOST_API_POLICY_RUNTIME_BASE_MEMBER_ROOTS)
    required = frozenset(HOST_API_POLICY_RUNTIME_REQUIRED_MEMBER_ROOTS)
    wave70a_required = frozenset(HOST_API_POLICY_RUNTIME_WAVE_70A_REQUIRED_MEMBER_ROOTS)
    wave70b_required = frozenset(HOST_API_POLICY_RUNTIME_WAVE_70B_REQUIRED_MEMBER_ROOTS)
    legacy_required = frozenset(HOST_API_POLICY_RUNTIME_BASE_REQUIRED_MEMBER_ROOTS)
    optional = frozenset(HOST_API_POLICY_RUNTIME_OPTIONAL_MEMBER_ROOTS)
    root = documents.get(workspace_root_manifest(RUNTIME_WORKSPACE))
    workspace = root.get("workspace") if type(root) is dict else None
    workspace_dependencies = workspace.get("dependencies") if type(workspace) is dict else None
    if member_set == base_required:
        if workspace_dependencies != HOST_API_POLICY_RUNTIME_BASE_WORKSPACE_DEPENDENCIES:
            _manifest_refuse()
        for document in documents.values():
            for table_name in DEPENDENCY_TABLE_NAMES:
                table = document.get(table_name, {})
                if (type(table) is not dict or HOST_API_POLICY_API_PACKAGE in table
                        or any(type(spec) is dict and spec.get("package") == HOST_API_POLICY_API_PACKAGE
                               for spec in table.values())):
                    _manifest_refuse()
            target = document.get("target", {})
            if type(target) is not dict:
                _manifest_refuse()
            for target_entry in target.values():
                if type(target_entry) is not dict:
                    _manifest_refuse()
                for table_name in DEPENDENCY_TABLE_NAMES:
                    table = target_entry.get(table_name, {})
                    if (type(table) is not dict or HOST_API_POLICY_API_PACKAGE in table
                            or any(type(spec) is dict and spec.get("package") == HOST_API_POLICY_API_PACKAGE
                                   for spec in table.values())):
                        _manifest_refuse()
        return
    if member_set not in (legacy_required, legacy_required | optional,
                          wave70a_required, wave70a_required | optional,
                          wave70b_required, wave70b_required | optional):
        _manifest_refuse()
    if member_set in (wave70b_required, wave70b_required | optional):
        profile_consumers = HOST_API_POLICY_RUNTIME_CONSUMER_ROOTS
    elif member_set in (wave70a_required, wave70a_required | optional):
        profile_consumers = (
            *HOST_API_POLICY_RUNTIME_BASE_CONSUMER_ROOTS,
            *RUNTIME_WAVE_70A_NEW_CONSUMER_ROOTS,
        )
    else:
        profile_consumers = HOST_API_POLICY_RUNTIME_BASE_CONSUMER_ROOTS
    expected_api_spec = (
        HOST_API_POLICY_API_WORKSPACE_SPEC
        if member_set in (wave70a_required, wave70a_required | optional,
                          wave70b_required, wave70b_required | optional)
        else {"path": HOST_API_POLICY_API_PATH}
    )
    if (type(workspace_dependencies) is not dict
            or workspace_dependencies.get(HOST_API_POLICY_API_PACKAGE) != expected_api_spec):
        _manifest_refuse()
    for dependency, spec in workspace_dependencies.items():
        if dependency != HOST_API_POLICY_API_PACKAGE and (
            type(spec) is dict and spec.get("package") == HOST_API_POLICY_API_PACKAGE
        ):
            _manifest_refuse()
    for table_name in DEPENDENCY_TABLE_NAMES:
        table = root.get(table_name, {})
        if type(table) is not dict:
            _manifest_refuse()
        if HOST_API_POLICY_API_PACKAGE in table or any(
            type(spec) is dict and spec.get("package") == HOST_API_POLICY_API_PACKAGE
            for spec in table.values()
        ):
            _manifest_refuse()
    target = root.get("target", {})
    if type(target) is not dict:
        _manifest_refuse()
    for target_entry in target.values():
        if type(target_entry) is not dict:
            _manifest_refuse()
        for table_name in DEPENDENCY_TABLE_NAMES:
            table = target_entry.get(table_name, {})
            if type(table) is not dict or HOST_API_POLICY_API_PACKAGE in table or any(
                type(spec) is dict and spec.get("package") == HOST_API_POLICY_API_PACKAGE
                for spec in table.values()
            ):
                _manifest_refuse()
    for member in member_set:
        document = documents.get(member + "/Cargo.toml")
        if type(document) is not dict:
            _manifest_refuse()
        required_consumer = member in profile_consumers
        optional_consumer = member == HOST_API_POLICY_OPTIONAL_SYNC_FORMAT_ROOT
        tables = [(name, document.get(name, {})) for name in DEPENDENCY_TABLE_NAMES]
        target = document.get("target", {})
        if type(target) is not dict:
            _manifest_refuse()
        for target_entry in target.values():
            if type(target_entry) is not dict:
                _manifest_refuse()
            tables.extend(("target:" + name, target_entry.get(name, {}))
                          for name in DEPENDENCY_TABLE_NAMES)
        for table_name, table in tables:
            if type(table) is not dict:
                _manifest_refuse()
            for dependency, spec in table.items():
                permitted_consumer = (
                    table_name == "dependencies" and (required_consumer or optional_consumer)
                    and dependency == HOST_API_POLICY_API_PACKAGE and spec == {"workspace": True}
                )
                if not permitted_consumer and (dependency == HOST_API_POLICY_API_PACKAGE or (
                    type(spec) is dict and spec.get("package") == HOST_API_POLICY_API_PACKAGE
                )):
                    _manifest_refuse()
        ordinary = document.get("dependencies", {})
        if required_consumer:
            if ordinary.get(HOST_API_POLICY_API_PACKAGE) != {"workspace": True}:
                _manifest_refuse()
        elif optional_consumer and HOST_API_POLICY_API_PACKAGE in ordinary:
            if ordinary.get(HOST_API_POLICY_API_PACKAGE) != {"workspace": True}:
                _manifest_refuse()
        elif HOST_API_POLICY_API_PACKAGE in ordinary:
            _manifest_refuse()


def _check_edition(edition, root_document):
    if edition == REQUIRED_EDITION and type(edition) is str:
        return
    if type(edition) is dict and edition == {"workspace": True}:
        workspace = root_document.get("workspace")
        shared = workspace.get("package") if type(workspace) is dict else None
        if type(shared) is dict and type(shared.get("edition")) is str \
                and shared["edition"] == REQUIRED_EDITION:
            return
    _manifest_refuse()


def check_manifests(manifests, members, workspace=CONTRACT_WORKSPACE, *, require_first_batch=True):
    """Check the root and member manifests before any Cargo command runs.

    Only exact version pins from the default registry and path dependencies that name a
    fixed workspace member are accepted. Git, registry, registry-index, any other path and
    every table outside the allowlist are refused, so are the underscore spellings of the
    dependency tables, a project table, a package workspace key, a workspace member list
    that differs from the fixed members, and any package without edition 2024. Anything
    that cannot be parsed is refused. Returns the package names the manifests declare.

    The workspace selector names one fixed root manifest. The contract root is the
    repository root manifest. The runtime root is a virtual manifest in its own directory
    whose members sit inside that directory as plain relative paths, never use a parent
    segment and never declare a package workspace key; any parent segment anywhere in a
    runtime manifest is refused. A manifest of one workspace never satisfies the other,
    because the root path differs.
    """
    root_directory = workspace_directory(workspace)
    root_path = workspace_root_manifest(workspace)
    if (type(manifests) is not dict or type(members) not in (set, frozenset, tuple)
            or not 1 <= len(manifests) <= MAX_MANIFESTS or root_path not in manifests):
        _manifest_refuse()
    member_set = frozenset(members)
    if root_directory != "." and (
        any(type(member) is not str or (
            RUNTIME_MEMBER_PATH_RE.fullmatch(member) is None
            and member not in RUNTIME_APP_TAURI_ROOTS
        ) for member in member_set)
        or any(type(data) is not bytes for data in manifests.values())
    ):
        _manifest_refuse()
    allowed = {root_path} | {member + "/Cargo.toml" for member in member_set}
    for path in manifests:
        if type(path) is not str or path not in allowed:
            _manifest_refuse()
    if root_directory == "." and member_set in (
            CONTRACT_BASE_MEMBERS, CONTRACT_WAVE_70A_MEMBERS, CONTRACT_WAVE_70B_MEMBERS):
        if set(manifests) != {root_path} | {
            member + "/Cargo.toml" for member in member_set
        }:
            _manifest_refuse()
    documents = {path: _parse_manifest(manifests[path]) for path in sorted(manifests)}
    if root_directory != ".":
        for path, data in manifests.items():
            if b".." in data:
                if (path != root_path or data.count(HOST_API_POLICY_API_PATH.encode("ascii")) != 1
                        or b".." in data.replace(HOST_API_POLICY_API_PATH.encode("ascii"), b"", 1)):
                    _manifest_refuse()
    names = set()
    for path, document in documents.items():
        directory = posixpath.dirname(path) or "."
        name, edition = _check_document(
            document, directory, member_set, path == root_path, root_directory,
        )
        if name is not None:
            _check_edition(edition, documents[root_path])
            if name in names:
                _manifest_refuse()
            names.add(name)
    if root_directory == "." and member_set in (
            CONTRACT_BASE_MEMBERS, CONTRACT_WAVE_70A_MEMBERS, CONTRACT_WAVE_70B_MEMBERS):
        if type(require_first_batch) is not bool:
            _manifest_refuse()
        _check_contract_dependency_policy(documents, require_first_batch=require_first_batch)
    if root_directory == RUNTIME_WORKSPACE_DIRECTORY:
        _check_runtime_profile(documents, member_set)
        if any(frozenset(profile) <= member_set for profile in (
                HOST_API_POLICY_RUNTIME_BASE_REQUIRED_MEMBER_ROOTS,
                HOST_API_POLICY_RUNTIME_WAVE_70A_REQUIRED_MEMBER_ROOTS,
                HOST_API_POLICY_RUNTIME_REQUIRED_MEMBER_ROOTS,
                HOST_API_POLICY_RUNTIME_WAVE_70B_REQUIRED_MEMBER_ROOTS)):
            names.add(HOST_API_POLICY_API_PACKAGE)
    return frozenset(names)


def manifest_dependency_rules(manifests, workspace=CONTRACT_WORKSPACE):
    """Return each local package's direct dependency identities from checked TOML bytes."""
    root_path = workspace_root_manifest(workspace)
    if type(manifests) is not dict or root_path not in manifests:
        _manifest_refuse()
    documents = {path: _parse_manifest(data) for path, data in manifests.items()}
    root = documents[root_path]
    workspace_table = root.get("workspace")
    workspace_dependencies = (
        workspace_table.get("dependencies", {}) if type(workspace_table) is dict else {}
    )
    if type(workspace_dependencies) is not dict:
        _manifest_refuse()
    result = {}
    for document in documents.values():
        package = document.get("package") if type(document) is dict else None
        if package is None:
            continue
        if type(package) is not dict or type(package.get("name")) is not str:
            _manifest_refuse()
        package_name = package["name"]
        rules = {}
        tables = [document.get(name, {}) for name in DEPENDENCY_TABLE_NAMES]
        target = document.get("target", {})
        if type(target) is not dict:
            _manifest_refuse()
        for entry in target.values():
            if type(entry) is not dict:
                _manifest_refuse()
            tables.extend(entry.get(name, {}) for name in DEPENDENCY_TABLE_NAMES)
        for table in tables:
            if type(table) is not dict:
                _manifest_refuse()
            for alias, spec in table.items():
                if type(spec) is dict and spec.get("workspace") is True:
                    spec = workspace_dependencies.get(alias)
                    if type(spec) is not dict:
                        _manifest_refuse()
                actual_name = spec.get("package", alias) if type(spec) is dict else alias
                if type(actual_name) is not str:
                    _manifest_refuse()
                if type(spec) is str:
                    version = spec[1:] if spec.startswith("=") else spec
                    source = "registry"
                elif type(spec) is dict:
                    version = spec.get("version")
                    if type(version) is str and version.startswith("="):
                        version = version[1:]
                    source = None if "path" in spec else "registry"
                else:
                    _manifest_refuse()
                rules.setdefault(actual_name, set()).add((version, source))
        result[package_name] = rules
    return result


def check_lock_members(lock_bytes, package_names, package_identities=None,
                       dependency_rules=None):
    """Require exact local identities and a lock graph containing no unreferenced packages."""
    lock = parse_lock(lock_bytes)
    packages = lock["packages"]
    local = [package for package in packages if package.get("source") is None]
    local_names = [package["name"] for package in local]
    sourceless = set(local_names)
    if (type(package_names) not in (set, frozenset)
            or sourceless != set(package_names) or len(local_names) != len(sourceless)):
        _refuse("bootstrap_lock_refused")
    if package_identities is not None:
        if type(package_identities) not in (set, frozenset, tuple):
            _refuse("bootstrap_lock_refused")
        expected = set(package_identities)
        actual = {(package["name"], package["version"]) for package in local}
        if expected != actual or len(expected) != len(package_names):
            _refuse("bootstrap_lock_refused")
    if dependency_rules is not None and type(dependency_rules) is not dict:
        _refuse("bootstrap_lock_refused")
    by_name = {}
    by_identity = {}
    for package in packages:
        identity = (package["name"], package["version"], package.get("source"))
        if identity in by_identity:
            _refuse("bootstrap_lock_refused")
        by_identity[identity] = package
        by_name.setdefault(package["name"], []).append(package)
    reachable = set()
    pending = [(package["name"], package["version"], package.get("source")) for package in local]
    while pending:
        identity = pending.pop()
        if identity in reachable:
            continue
        package = by_identity.get(identity)
        if package is None:
            _refuse("bootstrap_lock_refused")
        reachable.add(identity)
        for name, version, source in package.get("dependencies", []):
            if version is None:
                candidates = by_name.get(name, [])
                candidate = candidates[0] if len(candidates) == 1 else None
            else:
                candidate = by_identity.get((name, version, source))
                if candidate is None and source is None:
                    matches = [
                        item for item in by_name.get(name, []) if item["version"] == version
                    ]
                    candidate = matches[0] if len(matches) == 1 else None
            if candidate is None:
                _refuse("bootstrap_lock_refused")
            if dependency_rules is not None and identity[2] is None:
                allowed = dependency_rules.get(identity[0], {}).get(name, set())
                source_kind = "registry" if candidate.get("source") == cargo.REGISTRY_SOURCE else None
                if not any(
                    (expected_version is None or expected_version == candidate["version"])
                    and expected_source == source_kind
                    for expected_version, expected_source in allowed
                ):
                    _refuse("bootstrap_lock_refused")
            pending.append((candidate["name"], candidate["version"], candidate.get("source")))
    if reachable != set(by_identity):
        _refuse("bootstrap_lock_refused")
    return True


def manifest_package_identities(manifests, workspace=CONTRACT_WORKSPACE):
    """Return exact local package name/version pairs from an already checked manifest set."""
    root_path = workspace_root_manifest(workspace)
    if type(manifests) is not dict or root_path not in manifests:
        _manifest_refuse()
    documents = {path: _parse_manifest(data) for path, data in manifests.items()}
    root = documents[root_path]
    workspace_table = root.get("workspace")
    shared_package = (workspace_table.get("package")
                      if type(workspace_table) is dict else None)
    identities = set()
    for document in documents.values():
        package = document.get("package") if type(document) is dict else None
        if package is None:
            continue
        if type(package) is not dict or type(package.get("name")) is not str:
            _manifest_refuse()
        version = package.get("version")
        if version == {"workspace": True}:
            version = shared_package.get("version") if type(shared_package) is dict else None
        if (type(version) is not str
                or not cargo._valid_package_identity(package["name"], version)):
            _manifest_refuse()
        identity = (package["name"], version)
        if identity in identities:
            _manifest_refuse()
        identities.add(identity)
    if not identities:
        _manifest_refuse()
    return frozenset(identities)


def _runtime_profile_file(root, relative, maximum):
    parts = relative.split("/")
    if (not parts or any(part in ("", ".", "..") for part in parts)
            or Path(relative).is_absolute() or "\\" in relative):
        _manifest_refuse()
    current = root
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    for part in parts[:-1]:
        current = current / part
        try:
            info = current.lstat()
        except OSError:
            _manifest_refuse()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & reparse):
            _manifest_refuse()
    target = current / parts[-1]
    try:
        info = target.lstat()
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & reparse
                or info.st_nlink != 1 or info.st_size <= 0 or info.st_size > maximum):
            _manifest_refuse()
        payload = target.read_bytes()
    except OSError:
        _manifest_refuse()
    if len(payload) != info.st_size or len(payload) > maximum:
        _manifest_refuse()
    return payload


def _runtime_profile_source_directory(root, relative):
    parts = relative.split("/")
    if not parts or any(part in ("", ".", "..") for part in parts):
        _manifest_refuse()
    target = root
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    for part in parts:
        target = target / part
        try:
            info = target.lstat()
        except OSError:
            _manifest_refuse()
        if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or getattr(info, "st_file_attributes", 0) & reparse):
            _manifest_refuse()
    return target


def _runtime_batch_seven_file_allowed(relative):
    if relative in ("Cargo.toml", "README.md", "CONTRACT.md", "CHANGELOG.md"):
        return True
    parts = relative.split("/")
    if (len(parts) >= 2 and parts[0] == "src" and relative.endswith(".rs")
            and not _is_build_script_name(parts[-1])):
        return True
    return (
        len(parts) == 2 and parts[0] == "tests" and relative.endswith(".rs")
        and not _is_build_script_name(parts[-1])
    )


def _runtime_batch_seven_directory_allowed(relative):
    return relative == "src" or relative.startswith("src/") or relative == "tests"


def _validate_runtime_batch_seven_crate_trees(root):
    crates_root = _runtime_profile_source_directory(root, "runtime/crates")
    batch_prefixes = tuple(RUNTIME_BATCH_SEVEN_CRATE_ROOTS)
    required_files = {prefix: {"Cargo.toml", "README.md", "CONTRACT.md", "CHANGELOG.md", "src/lib.rs"}
                      for prefix in batch_prefixes}
    found_files = {prefix: set() for prefix in batch_prefixes}
    stack = [(crates_root, "runtime/crates")]
    count = 0
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    doc_names = {"README.md", "CONTRACT.md", "CHANGELOG.md"}
    while stack:
        directory, parent_relative = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError:
            _manifest_refuse()
        for entry in entries:
            count += 1
            if count > MAX_TREE_ENTRIES:
                _manifest_refuse()
            relative = parent_relative + "/" + entry.name
            try:
                info = Path(entry.path).lstat()
            except OSError:
                _manifest_refuse()
            batch_root = next((prefix for prefix in batch_prefixes
                               if relative == prefix or relative.startswith(prefix + "/")), None)
            if (stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & reparse):
                if batch_root is not None or entry.name in doc_names:
                    _manifest_refuse()
                continue
            if entry.name in doc_names:
                previous_service_path = (
                    relative in {
                        RUNTIME_EXISTING_SERVICE_DOC_ROOT + "/" + name
                        for name in RUNTIME_EXISTING_SERVICE_DOC_FILES
                    }
                )
                batch_document_path = (
                    batch_root is not None
                    and relative[len(batch_root) + 1:] in RUNTIME_BATCH_SEVEN_DOC_FILES
                )
                if (not previous_service_path and not batch_document_path
                        or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                    _manifest_refuse()
            if stat.S_ISDIR(info.st_mode):
                if batch_root is not None and relative != batch_root:
                    within = relative[len(batch_root) + 1:]
                    if not _runtime_batch_seven_directory_allowed(within):
                        _manifest_refuse()
                stack.append((Path(entry.path), relative))
                continue
            if batch_root is not None:
                within = relative[len(batch_root) + 1:]
                if (not _runtime_batch_seven_file_allowed(within)
                        or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                    _manifest_refuse()
                found_files[batch_root].add(within)
            elif not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode):
                continue
    for prefix, required in required_files.items():
        if not required.issubset(found_files[prefix]):
            _manifest_refuse()


def _runtime_profile_file_allowed(
        relative, absolute, inventory_paths, *, allow_docs, approved_build_paths=frozenset()):
    if _is_build_script_path(absolute):
        return (
            _canonical_build_script_path(absolute)
            and _unique_canonical_path_member(absolute, inventory_paths)
            and _unique_canonical_path_member(absolute, approved_build_paths)
        )
    if relative == "Cargo.toml":
        return True
    if allow_docs and relative in RUNTIME_BATCH_SEVEN_DOC_FILES:
        return True
    parts = relative.split("/")
    if (len(parts) >= 2 and parts[0] == "src" and relative.endswith(".rs")
            and not _is_build_script_name(parts[-1])):
        return True
    if (len(parts) == 2 and parts[0] == "tests" and relative.endswith(".rs")
            and not _is_build_script_name(parts[-1])):
        return True
    for frontend_root in RUNTIME_FRONTEND_SOURCE_ROOTS:
        if absolute.startswith(frontend_root + "/"):
            frontend_relative = absolute[len(frontend_root) + 1:]
            return (
                ".." not in frontend_relative.split("/")
                and Path(absolute).suffix in RUNTIME_FRONTEND_SOURCE_SUFFIXES
            )
    return absolute in inventory_paths


def _runtime_profile_directory_allowed(relative, absolute_root, inventory_paths):
    if relative == "src" or relative.startswith("src/") or relative == "tests":
        return True
    absolute = absolute_root + "/" + relative
    return (
        any(path.startswith(absolute + "/") for path in inventory_paths)
        or any(root == absolute or root.startswith(absolute + "/") for root in RUNTIME_FRONTEND_SOURCE_ROOTS)
    )


def _runtime_frontend_source_allowed(path):
    if type(path) is not str:
        return False
    for root in RUNTIME_FRONTEND_SOURCE_ROOTS:
        if path.startswith(root + "/"):
            relative = path[len(root) + 1:]
            return (
                relative and ".." not in relative.split("/")
                and Path(relative).suffix in RUNTIME_FRONTEND_SOURCE_SUFFIXES
            )
    return False


def _validate_runtime_wave70_crate_trees(root, inventory_paths=frozenset()):
    """Check the five new service roots against Rust and inventoried file profiles."""
    prefixes = tuple(RUNTIME_WAVE_70_SOURCE_ROOTS)
    required_files = {
        prefix: {"Cargo.toml", "README.md", "CONTRACT.md", "CHANGELOG.md", "src/lib.rs"}
        for prefix in prefixes
    }
    found_files = {prefix: set() for prefix in prefixes}
    count = 0
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    for root_name in prefixes:
        directory = _runtime_profile_source_directory(root, root_name)
        stack = [(directory, root_name)]
        while stack:
            current, parent = stack.pop()
            try:
                with os.scandir(current) as iterator:
                    entries = sorted(iterator, key=lambda item: item.name)
            except OSError:
                _manifest_refuse()
            for entry in entries:
                count += 1
                if count > MAX_TREE_ENTRIES:
                    _manifest_refuse()
                relative = parent + "/" + entry.name
                within = relative[len(root_name) + 1:]
                try:
                    info = Path(entry.path).lstat()
                except OSError:
                    _manifest_refuse()
                if (stat.S_ISLNK(info.st_mode)
                        or getattr(info, "st_file_attributes", 0) & reparse):
                    _manifest_refuse()
                if stat.S_ISDIR(info.st_mode):
                    if not _runtime_profile_directory_allowed(within, root_name, inventory_paths):
                        _manifest_refuse()
                    stack.append((Path(entry.path), relative))
                    continue
                if (not _runtime_profile_file_allowed(
                        within, relative, inventory_paths, allow_docs=True,
                ) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                    _manifest_refuse()
                found_files[root_name].add(within)
    for prefix, required in required_files.items():
        if not required.issubset(found_files[prefix]):
            _manifest_refuse()


def _validate_runtime_wave70_app_trees(root, inventory_paths=frozenset()):
    """Validate shell Rust source while inventory-backing native and generated inputs."""
    count = 0
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    for root_name in RUNTIME_APP_TAURI_ROOTS:
        directory = _runtime_profile_source_directory(root, root_name)
        stack = [(directory, root_name)]
        found = set()
        while stack:
            current, parent = stack.pop()
            try:
                with os.scandir(current) as iterator:
                    entries = sorted(iterator, key=lambda item: item.name)
            except OSError:
                _manifest_refuse()
            for entry in entries:
                count += 1
                if count > MAX_TREE_ENTRIES:
                    _manifest_refuse()
                relative = parent + "/" + entry.name
                within = relative[len(root_name) + 1:]
                try:
                    info = Path(entry.path).lstat()
                except OSError:
                    _manifest_refuse()
                if (stat.S_ISLNK(info.st_mode)
                        or getattr(info, "st_file_attributes", 0) & reparse):
                    _manifest_refuse()
                if stat.S_ISDIR(info.st_mode):
                    if not _runtime_profile_directory_allowed(within, root_name, inventory_paths):
                        _manifest_refuse()
                    stack.append((Path(entry.path), relative))
                    continue
                if (not _runtime_profile_file_allowed(
                        within, relative, inventory_paths, allow_docs=True,
                ) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                    _manifest_refuse()
                found.add(within)
        if (not {"Cargo.toml", "README.md", "CONTRACT.md", "CHANGELOG.md"} <= found
                or not ({"src/lib.rs", "src/main.rs"} & found)):
            _manifest_refuse()


def _validate_runtime_profile_tree_files(
        root, crate_roots, inventory_paths, approved_build_paths=frozenset()):
    """Reject runtime files outside the exact Rust and authenticated inventory profiles."""
    runtime = _runtime_profile_source_directory(root, "runtime")
    member_roots = {}
    for member in crate_roots:
        if isinstance(member, Path):
            normalized = member.as_posix()
        elif type(member) is str:
            normalized = member.replace("\\", "/")
        elif isinstance(member, (tuple, list)) and all(type(part) is str for part in member):
            normalized = "/".join(member)
        else:
            _manifest_refuse()
        normalized = posixpath.normpath(normalized)
        if (normalized in (".", "..") or normalized.startswith("../")
                or normalized.startswith("/") or normalized in member_roots):
            _manifest_refuse()
        member_roots[normalized] = normalized
    root_files = frozenset(("runtime/Cargo.toml", "runtime/Cargo.lock")) | frozenset(
        "runtime/" + name for name in RUNTIME_CONFIG_FILES
    )
    stack = [(runtime, "runtime")]
    count = 0
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    while stack:
        directory, parent = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError:
            _manifest_refuse()
        for entry in entries:
            if entry.name in ("target", "vendor", "node_modules", ".git", ".cargo"):
                continue
            count += 1
            if count > MAX_TREE_ENTRIES * 4:
                _manifest_refuse()
            relative = parent + "/" + entry.name
            try:
                info = Path(entry.path).lstat()
            except OSError:
                _manifest_refuse()
            if (stat.S_ISLNK(info.st_mode)
                    or getattr(info, "st_file_attributes", 0) & reparse):
                _manifest_refuse()
            if stat.S_ISDIR(info.st_mode):
                stack.append((Path(entry.path), relative))
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                _manifest_refuse()
            if relative == SOURCE_INVENTORY_PATH:
                continue
            if _is_build_script_path(relative):
                if relative not in inventory_paths or relative not in approved_build_paths:
                    _manifest_refuse()
                continue
            if relative in inventory_paths:
                continue
            if _runtime_frontend_source_allowed(relative):
                continue
            if relative in root_files:
                continue
            member_root = next((prefix for prefix in member_roots
                                if relative.startswith(prefix + "/")), None)
            if member_root is None:
                _manifest_refuse()
            within = relative[len(member_root) + 1:]
            root_parts = member_roots[member_root]
            allow_docs = (
                root_parts in RUNTIME_BATCH_SEVEN_CRATE_ROOTS
                or root_parts in RUNTIME_WAVE_70_SOURCE_ROOTS
                or root_parts == RUNTIME_EXISTING_SERVICE_DOC_ROOT
                or root_parts in RUNTIME_APP_TAURI_ROOTS
            )
            if not _runtime_profile_file_allowed(
                    within, relative, inventory_paths, allow_docs=allow_docs):
                _manifest_refuse()


def _contract_members_from_root_bytes(root_bytes):
    document = _parse_manifest(root_bytes)
    workspace = document.get("workspace")
    listed = workspace.get("members") if type(workspace) is dict else None
    if type(listed) is not list or any(type(item) is not str for item in listed):
        _manifest_refuse()
    members = frozenset(posixpath.normpath(item) for item in listed)
    if members not in (CONTRACT_BASE_MEMBERS, CONTRACT_WAVE_70A_MEMBERS,
                       CONTRACT_WAVE_70B_MEMBERS):
        _manifest_refuse()
    return members


def _validate_contract_wave70_trees(root, members):
    for member in (CONTRACT_XTASK_MEMBER, CONTRACT_DEMO_MEMBER):
        if member not in members:
            continue
        directory = _runtime_profile_source_directory(root, member)
        required = {"Cargo.toml", "README.md", "CONTRACT.md", "CHANGELOG.md", "src/lib.rs"}
        found = set()
        stack = [(directory, member)]
        count = 0
        while stack:
            current, prefix = stack.pop()
            try:
                with os.scandir(current) as iterator:
                    entries = sorted(iterator, key=lambda item: item.name)
            except OSError:
                _manifest_refuse()
            for entry in entries:
                count += 1
                if count > MAX_TREE_ENTRIES:
                    _manifest_refuse()
                relative = prefix + "/" + entry.name
                target = Path(entry.path)
                try:
                    info = target.lstat()
                except OSError:
                    _manifest_refuse()
                if stat.S_ISLNK(info.st_mode) or getattr(
                        info, "st_file_attributes", 0) & getattr(
                            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                    _manifest_refuse()
                within = relative[len(member) + 1:]
                if stat.S_ISDIR(info.st_mode):
                    if not (within == "src" or within.startswith("src/")
                            or within == "tests"):
                        _manifest_refuse()
                    stack.append((target, relative))
                    continue
                if (not _runtime_batch_seven_file_allowed(within)
                        or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                    _manifest_refuse()
                found.add(within)
        if not required.issubset(found):
            _manifest_refuse()


SOURCE_INVENTORY_PATH = "runtime/admission/inventory.toml"
TRUSTED_BUILD_SCRIPT_REVIEWS = ()
SOURCE_INVENTORY_FIELDS = frozenset((
    "path", "sha256", "owner", "package", "target", "generator",
    "generator_version", "provenance",
))
SOURCE_INVENTORY_ASSIGNMENT_RE = re.compile(r'([a-z0-9_]+) = "([^"\r\n]*)"\Z')
SOURCE_INVENTORY_PATH_RE = re.compile(r"[A-Za-z0-9._/-]{1,512}\Z")
SOURCE_INVENTORY_OWNER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
SOURCE_INVENTORY_LABEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._ /:-]{0,255}\Z")


def _source_inventory_path_required(relative):
    """Return true for candidate inputs that need a concrete non-crate inventory row."""
    if not _safe_relative_inventory_path(relative):
        return False
    parts = relative.split("/")
    name = parts[-1]
    if _runtime_frontend_source_allowed(relative):
        return False
    if _is_build_script_name(name):
        return True
    if relative.startswith("runtime/crates/"):
        crate_relative = relative[len("runtime/crates/"):]
        crate_parts = crate_relative.split("/")
        within = "/".join(crate_parts[2:]) if len(crate_parts) >= 3 else ""
        if (name in ("Cargo.toml", "Cargo.lock")
                or name in RUNTIME_BATCH_SEVEN_DOC_FILES
                or (within.startswith("src/") and within.endswith(".rs")
                    and not _is_build_script_name(name))
                or (within.startswith("tests/") and len(within.split("/")) == 2
                    and within.endswith(".rs") and not _is_build_script_name(name))):
            return False
        return True
    shell_roots = (
        "runtime/apps/test-shell-desktop", "runtime/apps/test-shell-mobile",
    )
    shell_root = next((root for root in shell_roots if relative.startswith(root + "/")), None)
    if shell_root is not None:
        within_shell = relative[len(shell_root) + 1:]
        if within_shell.startswith("src-tauri/"):
            within_crate = within_shell[len("src-tauri/"):]
            if (within_crate == "Cargo.toml" or within_crate in RUNTIME_BATCH_SEVEN_DOC_FILES
                    or (within_crate.startswith("src/") and within_crate.endswith(".rs"))
                    or (within_crate.startswith("tests/") and len(within_crate.split("/")) == 2
                        and within_crate.endswith(".rs"))):
                return False
        elif name in RUNTIME_BATCH_SEVEN_DOC_FILES:
            return False
        return (
            "/src-tauri/" in relative or "/icons/" in relative
            or name in ("package.json", "package-lock.json", ".node-version", ".npmrc",
                        "index.html", "vite.config.ts", "tsconfig.json")
            or name.lower().endswith((".png", ".ico", ".icns", ".svg", ".webp"))
            or "/ios/" in relative or "/android/" in relative
        )
    if (relative in ("package.json", "package-lock.json", ".node-version", ".npmrc",
                     "runtime/package.json", "runtime/package-lock.json",
                     "runtime/.node-version", "runtime/.npmrc")):
        return True
    if relative.startswith("runtime/packages/") and name in ("package.json", "package-lock.json"):
        return True
    if relative.startswith(("runtime/capabilities/", "runtime/config/tauri/")):
        return True
    if (relative.startswith("packages/") and name in ("package.json", "package-lock.json")):
        return True
    if relative.startswith("packages/kernel-icons/") and name.lower().endswith(
            (".png", ".ico", ".icns", ".svg", ".webp")):
        return True
    if (name in ("command_metadata.rs", "command-metadata.json", "generated-metadata.json")
            or "/metadata/" in relative):
        return True
    return False


def _safe_relative_inventory_path(relative):
    return (
        type(relative) is str and SOURCE_INVENTORY_PATH_RE.fullmatch(relative) is not None
        and not relative.startswith("/") and "\\" not in relative
        and all(part not in ("", ".", "..") for part in relative.split("/"))
    )


def _normalized_relative_path_key(path):
    """Return a conservative casefolded key for filesystem path comparisons."""
    if type(path) is not str:
        return None
    normalized = unicodedata.normalize("NFKC", path)
    return unicodedata.normalize("NFKC", normalized.casefold())


def _is_build_script_name(name):
    return _normalized_relative_path_key(name) == "build.rs"


def _is_build_script_path(path):
    key = _normalized_relative_path_key(path)
    return key is not None and key.rsplit("/", 1)[-1] == "build.rs"


def _canonical_build_script_path(path):
    key = _normalized_relative_path_key(path)
    return key is not None and _is_build_script_path(path) and path == key


def _unique_canonical_path_member(path, candidates):
    key = _normalized_relative_path_key(path)
    if key is None or path != key:
        return False
    matches = [candidate for candidate in candidates
               if _normalized_relative_path_key(candidate) == key]
    return len(matches) == 1 and matches[0] == path


def _source_inventory_required_paths(root):
    required = set()
    skip = frozenset((".git", "node_modules", "target", "vendor", ".cargo"))
    stack = [Path(root)]
    count = 0
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError:
            _manifest_refuse()
        for entry in entries:
            if entry.name in skip:
                continue
            count += 1
            if count > MAX_TREE_ENTRIES * 4:
                _manifest_refuse()
            target = Path(entry.path)
            try:
                info = target.lstat()
            except OSError:
                _manifest_refuse()
            relative = target.relative_to(root).as_posix()
            if stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode):
                stack.append(target)
            elif _source_inventory_path_required(relative):
                if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                        or getattr(info, "st_file_attributes", 0)
                        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
                        or getattr(info, "st_nlink", 1) != 1):
                    _manifest_refuse()
                required.add(relative)
    return required


def _build_script_reviews_valid(rows, source_sha, reviews):
    """Bind each executable inventory row to an explicit trusted review record."""
    if type(reviews) is not tuple:
        _manifest_refuse()
    by_path = {}
    for review in reviews:
        if (type(review) is not tuple or len(review) != 3
                or any(type(value) is not str for value in review)):
            _manifest_refuse()
        path, digest, reviewed_source_sha = review
        if (not _safe_relative_inventory_path(path) or not _is_build_script_path(path)
                or not _canonical_build_script_path(path)
                or not _valid_hex(digest) or reviewed_source_sha != source_sha
                or _normalized_relative_path_key(path) in by_path):
            _manifest_refuse()
        by_path[_normalized_relative_path_key(path)] = digest
    build_rows = {}
    for row in rows:
        path = row["path"]
        if not _is_build_script_path(path):
            continue
        if not _canonical_build_script_path(path):
            _manifest_refuse()
        key = _normalized_relative_path_key(path)
        if key in build_rows:
            _manifest_refuse()
        build_rows[key] = row["sha256"]
    if build_rows != by_path:
        _manifest_refuse()


def parse_runtime_source_inventory(payload, source_sha, *, build_script_reviews=None):
    """Parse and authenticate the canonical inventory grammar for a candidate SHA."""
    if type(source_sha) is not str or SOURCE_SHA_RE.fullmatch(source_sha) is None:
        _manifest_refuse()
    if type(payload) is not bytes or not 0 < len(payload) <= MAX_SOURCE_INVENTORY_BYTES:
        _manifest_refuse()
    try:
        text = payload.decode("ascii", "strict")
    except UnicodeDecodeError:
        _manifest_refuse()
    if not text.endswith("\n") or "\r" in text or "\x00" in text:
        _manifest_refuse()
    lines = text.splitlines()
    if len(lines) < 1 or lines[0] != "schema_version = 1":
        _manifest_refuse()
    rows = []
    current = None
    for line in lines[1:]:
        if not line:
            continue
        if line == "[[files]]":
            if current is not None:
                if set(current) != SOURCE_INVENTORY_FIELDS:
                    _manifest_refuse()
                rows.append(current)
            current = {}
            if len(rows) >= MAX_SOURCE_INVENTORY_ROWS:
                _manifest_refuse()
            continue
        match = SOURCE_INVENTORY_ASSIGNMENT_RE.fullmatch(line)
        if match is None or current is None:
            _manifest_refuse()
        key, value = match.groups()
        if key not in SOURCE_INVENTORY_FIELDS or key in current:
            _manifest_refuse()
        current[key] = value
    if current is not None:
        if set(current) != SOURCE_INVENTORY_FIELDS:
            _manifest_refuse()
        rows.append(current)
    if len(rows) > MAX_SOURCE_INVENTORY_ROWS:
        _manifest_refuse()
    paths = [row["path"] for row in rows]
    path_keys = [_normalized_relative_path_key(path) for path in paths]
    if (paths != sorted(paths) or len(set(paths)) != len(paths)
            or len(set(path_keys)) != len(path_keys)
            or any(not _safe_relative_inventory_path(path) for path in paths)):
        _manifest_refuse()
    shell_roots = (
        "runtime/apps/test-shell-desktop",
        "runtime/apps/test-shell-mobile",
    )
    for shell_root in shell_roots:
        if not any(path.startswith(shell_root + "/") for path in paths):
            _manifest_refuse()
        if not any(
                path.startswith(shell_root + "/")
                and "tauri.conf" in path.rsplit("/", 1)[-1]
                for path in paths):
            _manifest_refuse()
    for row in rows:
        path = row["path"]
        if (not _source_inventory_path_required(path)
                or not _valid_hex(row["sha256"])
                or SOURCE_INVENTORY_OWNER_RE.fullmatch(row["owner"]) is None
                or SOURCE_INVENTORY_LABEL_RE.fullmatch(row["package"]) is None
                or SOURCE_INVENTORY_LABEL_RE.fullmatch(row["target"]) is None
                or any(not value.isascii() or len(value) > 512 for value in (
                    row["generator"], row["generator_version"], row["provenance"],
                ))):
            _manifest_refuse()
        generated = any(row[key] for key in ("generator", "generator_version", "provenance"))
        if generated and not all(row[key] for key in ("generator", "generator_version", "provenance")):
            _manifest_refuse()
    reviews = TRUSTED_BUILD_SCRIPT_REVIEWS if build_script_reviews is None else build_script_reviews
    _build_script_reviews_valid(rows, source_sha, reviews)
    return tuple(rows), hashlib.sha256(payload).hexdigest()


def validate_runtime_source_inventory(source, source_sha, *, build_script_reviews=None):
    """Authenticate the exact non-crate inputs listed by the 10.I candidate inventory."""
    try:
        root = Path(source).resolve(strict=True)
    except OSError:
        _manifest_refuse()
    payload = _runtime_profile_file(root, SOURCE_INVENTORY_PATH, MAX_SOURCE_INVENTORY_BYTES)
    rows, inventory_sha256 = parse_runtime_source_inventory(
        payload, source_sha, build_script_reviews=build_script_reviews,
    )
    paths = [row["path"] for row in rows]
    for row in rows:
        data = _runtime_profile_file(root, row["path"], MAX_INVENTORY_FILE_BYTES)
        if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), row["sha256"]):
            _manifest_refuse()
    if set(paths) != _source_inventory_required_paths(root):
        _manifest_refuse()
    return inventory_sha256


STAGED_INVENTORY_RECEIPT_FIELDS = frozenset((
    "schema_version", "source_sha", "original_inventory_sha256",
    "sanitized_inventory_sha256", "deleted_paths", "modified_paths",
))


def validate_runtime_source_inventory_staged(source, source_sha, receipt_bytes):
    """Validate a privileged staging receipt after its authenticated sanitization."""
    receipt = _strict_json(receipt_bytes, 65536, "bootstrap_manifest_refused")
    if (type(receipt) is not dict or set(receipt) != set(STAGED_INVENTORY_RECEIPT_FIELDS)
            or _canonical(receipt, "bootstrap_manifest_refused") + b"\n" != receipt_bytes
            or receipt["schema_version"] != 1 or receipt["source_sha"] != source_sha
            or SOURCE_SHA_RE.fullmatch(source_sha or "") is None
            or not _valid_hex(receipt["original_inventory_sha256"])
            or not _valid_hex(receipt["sanitized_inventory_sha256"])):
        _manifest_refuse()
    deleted = receipt["deleted_paths"]
    modified = receipt["modified_paths"]
    if (type(deleted) is not list or deleted != sorted(set(deleted))
            or any(type(path) is not str or not (
                path == ".npmrc" or path.endswith("/.npmrc")
            ) for path in deleted)
            or type(modified) is not list or modified != sorted(set(modified))
            or any(path not in ("package-lock.json", "runtime/package-lock.json")
                   for path in modified)):
        _manifest_refuse()
    try:
        root = Path(source).resolve(strict=True)
    except OSError:
        _manifest_refuse()
    inventory_payload = _runtime_profile_file(
        root, SOURCE_INVENTORY_PATH, MAX_SOURCE_INVENTORY_BYTES,
    )
    inventory_sha256 = hashlib.sha256(inventory_payload).hexdigest()
    if not hmac.compare_digest(inventory_sha256, receipt["sanitized_inventory_sha256"]):
        _manifest_refuse()
    inventory_sha256 = validate_runtime_source_inventory(root, source_sha)
    for relative in deleted:
        if (root / Path(*relative.split("/"))).exists():
            _manifest_refuse()
    for relative in modified:
        if not (root / Path(*relative.split("/"))).is_file():
            _manifest_refuse()
    return inventory_sha256


def validate_runtime_profile_source_tree(
        source, source_sha=None, *, build_script_reviews=None, staged_inventory_receipt=None):
    """Validate the paired contract and runtime locks before Windows selects Rust gates."""
    try:
        root = Path(source).resolve(strict=True)
    except OSError:
        _manifest_refuse()
    runtime_manifest_path = root / workspace_root_manifest(RUNTIME_WORKSPACE)
    runtime_lock_path = root / workspace_directory(RUNTIME_WORKSPACE) / "Cargo.lock"
    try:
        runtime_manifest_path.lstat()
        runtime_manifest_present = True
    except FileNotFoundError:
        runtime_manifest_present = False
    except OSError:
        _manifest_refuse()
    try:
        runtime_lock_path.lstat()
        runtime_lock_present = True
    except FileNotFoundError:
        runtime_lock_present = False
    except OSError:
        _manifest_refuse()
    if not runtime_manifest_present and not runtime_lock_present:
        runtime_directory = root / workspace_directory(RUNTIME_WORKSPACE)
        try:
            directory_info = runtime_directory.lstat()
        except FileNotFoundError:
            return False
        except OSError:
            _manifest_refuse()
        reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if (not stat.S_ISDIR(directory_info.st_mode) or stat.S_ISLNK(directory_info.st_mode)
                or getattr(directory_info, "st_file_attributes", 0) & reparse):
            _manifest_refuse()
        stack = [runtime_directory]
        while stack:
            directory = stack.pop()
            try:
                with os.scandir(directory) as iterator:
                    entries = sorted(iterator, key=lambda item: item.name)
            except OSError:
                _manifest_refuse()
            for entry in entries:
                target = Path(entry.path)
                try:
                    info = target.lstat()
                except OSError:
                    _manifest_refuse()
                if (stat.S_ISLNK(info.st_mode)
                        or getattr(info, "st_file_attributes", 0) & reparse):
                    _manifest_refuse()
                if entry.name in ("Cargo.toml", "Cargo.lock"):
                    _manifest_refuse()
                if stat.S_ISDIR(info.st_mode):
                    stack.append(target)
                elif not stat.S_ISREG(info.st_mode):
                    _manifest_refuse()
                if len(stack) > MAX_TREE_ENTRIES:
                    _manifest_refuse()
        return False
    if not runtime_manifest_present or not runtime_lock_present:
        _manifest_refuse()
    runtime_manifest = _runtime_profile_file(
        root, workspace_root_manifest(RUNTIME_WORKSPACE), MAX_MANIFEST_BYTES,
    )
    runtime_document = _parse_manifest(runtime_manifest)
    workspace = runtime_document.get("workspace")
    listed = workspace.get("members") if type(workspace) is dict else None
    if type(listed) is not list or any(type(item) is not str for item in listed):
        _manifest_refuse()
    runtime_members = frozenset(posixpath.normpath(posixpath.join("runtime", item)) for item in listed)
    runtime_manifest_paths = {workspace_root_manifest(RUNTIME_WORKSPACE)}
    runtime_manifest_paths.update(member + "/Cargo.toml" for member in runtime_members)
    runtime_manifests = {
        path: runtime_manifest if path == workspace_root_manifest(RUNTIME_WORKSPACE)
        else _runtime_profile_file(root, path, MAX_MANIFEST_BYTES)
        for path in runtime_manifest_paths
    }
    runtime_names = check_manifests(runtime_manifests, runtime_members, RUNTIME_WORKSPACE)
    runtime_identities = set(manifest_package_identities(runtime_manifests, RUNTIME_WORKSPACE))
    runtime_api_profile = any(
        frozenset(profile) <= runtime_members for profile in (
            HOST_API_POLICY_RUNTIME_BASE_REQUIRED_MEMBER_ROOTS,
            HOST_API_POLICY_RUNTIME_WAVE_70A_REQUIRED_MEMBER_ROOTS,
            HOST_API_POLICY_RUNTIME_REQUIRED_MEMBER_ROOTS,
            HOST_API_POLICY_RUNTIME_WAVE_70B_REQUIRED_MEMBER_ROOTS,
        )
    )
    wave70a_profile = (
        frozenset(HOST_API_POLICY_RUNTIME_WAVE_70A_REQUIRED_MEMBER_ROOTS) <= runtime_members
    )
    wave70_profile = (
        frozenset(HOST_API_POLICY_RUNTIME_WAVE_70B_REQUIRED_MEMBER_ROOTS) <= runtime_members
    )
    if runtime_api_profile:
        _validate_runtime_batch_seven_crate_trees(root)
    inventory_paths = frozenset()
    approved_build_paths = frozenset()
    if wave70a_profile or wave70_profile:
        if staged_inventory_receipt is None:
            inventory_sha = validate_runtime_source_inventory(
                root, source_sha=source_sha, build_script_reviews=build_script_reviews,
            )
        else:
            inventory_sha = validate_runtime_source_inventory_staged(
                root, source_sha, staged_inventory_receipt,
            )
        inventory_rows, parsed_inventory_sha = parse_runtime_source_inventory(
            _runtime_profile_file(root, SOURCE_INVENTORY_PATH, MAX_SOURCE_INVENTORY_BYTES),
            source_sha, build_script_reviews=build_script_reviews,
        )
        if not hmac.compare_digest(inventory_sha, parsed_inventory_sha):
            _manifest_refuse()
        inventory_paths = frozenset(_source_inventory_required_paths(root))
        approved_build_paths = frozenset(
            row["path"] for row in inventory_rows if _is_build_script_path(row["path"])
        )
    if wave70_profile:
        _validate_runtime_wave70_crate_trees(root, inventory_paths)
    if wave70a_profile or wave70_profile:
        _validate_runtime_wave70_app_trees(root, inventory_paths)
        _validate_runtime_profile_tree_files(
            root, tuple(runtime_members), inventory_paths, approved_build_paths,
        )
    runtime_lock = _runtime_profile_file(root, "runtime/Cargo.lock", MAX_LOCK_BYTES)
    contract_root = _runtime_profile_file(root, "Cargo.toml", MAX_MANIFEST_BYTES)
    contract_members = _contract_members_from_root_bytes(contract_root)
    _validate_contract_wave70_trees(root, contract_members)
    contract_manifest_paths = {"Cargo.toml"}
    contract_manifest_paths.update(member + "/Cargo.toml" for member in contract_members)
    contract_manifests = {
        path: contract_root if path == "Cargo.toml"
        else _runtime_profile_file(root, path, MAX_MANIFEST_BYTES)
        for path in contract_manifest_paths
    }
    contract_names = check_manifests(
        contract_manifests, contract_members, CONTRACT_WORKSPACE, require_first_batch=False,
    )
    contract_identities = manifest_package_identities(contract_manifests, CONTRACT_WORKSPACE)
    api_identity = next((identity for identity in contract_identities
                         if identity[0] == HOST_API_POLICY_API_PACKAGE), None)
    if runtime_api_profile:
        if api_identity is None or HOST_API_POLICY_API_PACKAGE not in runtime_names:
            _manifest_refuse()
        runtime_identities.add(api_identity)
    runtime_dependency_rules = manifest_dependency_rules(runtime_manifests, RUNTIME_WORKSPACE)
    if runtime_api_profile:
        api_dependency_rules = manifest_dependency_rules(
            {"Cargo.toml": contract_manifests["Cargo.toml"],
             HOST_API_POLICY_API_MANIFEST_PATH: contract_manifests[HOST_API_POLICY_API_MANIFEST_PATH]},
            CONTRACT_WORKSPACE,
        )
        runtime_dependency_rules.update(api_dependency_rules)
    check_lock_members(runtime_lock, runtime_names, runtime_identities, runtime_dependency_rules)
    contract_lock = _runtime_profile_file(root, "Cargo.lock", MAX_LOCK_BYTES)
    check_lock_members(
        contract_lock, contract_names,
        manifest_package_identities(contract_manifests, CONTRACT_WORKSPACE),
        manifest_dependency_rules(contract_manifests, CONTRACT_WORKSPACE),
    )
    source_directory = _runtime_profile_source_directory(root, "crates/host/api/src")
    stack = [source_directory]
    source_files = []
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    while stack:
        directory = stack.pop()
        try:
            with os.scandir(directory) as iterator:
                entries = sorted(iterator, key=lambda item: item.name)
        except OSError:
            _manifest_refuse()
        for entry in entries:
            target = Path(entry.path)
            try:
                info = target.lstat()
            except OSError:
                _manifest_refuse()
            if (stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & reparse):
                _manifest_refuse()
            if stat.S_ISDIR(info.st_mode):
                stack.append(target)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                source_files.append(target.relative_to(root).as_posix())
            else:
                _manifest_refuse()
            if len(source_files) + len(stack) > MAX_TREE_ENTRIES:
                _manifest_refuse()
    if "crates/host/api/src/lib.rs" not in source_files:
        _manifest_refuse()
    return True


def _main(arguments):
    if len(arguments) != 3 or arguments[0] != "check-runtime_profile-source":
        _refuse("bootstrap_input_invalid")
    result = validate_runtime_profile_source_tree(arguments[1], arguments[2])
    sys.stdout.write("runtime_profile=runtime\n" if result else "runtime_profile=base\n")
    return 0


def refuse_foreign_sources(lock_bytes):
    """Refuse any lock source other than the fixed crates.io registry before parsing."""
    if type(lock_bytes) is not bytes or not lock_bytes:
        _refuse("bootstrap_lock_refused")
    if len(lock_bytes) > MAX_LOCK_BYTES:
        _refuse("bootstrap_payload_too_large")
    try:
        text = lock_bytes.decode("ascii", "strict")
    except UnicodeError:
        _refuse("bootstrap_lock_refused")
    allowed = (cargo.REGISTRY_SOURCE, cargo.SPARSE_REGISTRY_SOURCE)
    for line in text.splitlines():
        match = SOURCE_LINE_RE.match(line)
        if match is not None and match.group(1) not in allowed:
            _refuse("bootstrap_source_refused")
    for match in DEPENDENCY_SOURCE_RE.finditer(text):
        if match.group(1) not in allowed:
            _refuse("bootstrap_source_refused")
    return True


def parse_lock(lock_bytes):
    refuse_foreign_sources(lock_bytes)
    return _call_cargo(cargo.parse_cargo_lock, lock_bytes)


def _registry_packages(lock):
    packages = sorted(
        (package["name"], package["version"], package["checksum"])
        for package in lock["packages"] if package.get("source") == cargo.REGISTRY_SOURCE
    )
    if not packages or len(packages) > MAX_PACKAGES:
        _refuse("bootstrap_lock_refused")
    return packages


def _check_context(trusted_context):
    if type(trusted_context) is not dict or set(trusted_context) != set(CONTEXT_FIELDS):
        _refuse("bootstrap_input_invalid")
    return trusted_context


def build_receipt(lock_bytes, trusted_context):
    """Build the canonical proposed receipt; every audit record stays pending review."""
    _check_context(trusted_context)
    packages = _registry_packages(parse_lock(lock_bytes))
    record = {"schema_version": SCHEMA_VERSION}
    record.update({field: trusted_context[field] for field in sorted(CONTEXT_FIELDS)})
    record["lock_sha256"] = hashlib.sha256(lock_bytes).hexdigest()
    record["packages"] = [
        {"name": name, "version": version, "checksum": checksum, "audit_record_id": PENDING_AUDIT_ID}
        for name, version, checksum in packages
    ]
    encoded = _call_cargo(cargo.encode_receipt, record)
    if len(encoded) > MAX_RECEIPT_BYTES:
        _refuse("bootstrap_payload_too_large")
    return encoded


def self_check(lock_bytes, receipt_bytes, trusted_context):
    """Verify lock and receipt against trusted context before any network request."""
    _check_context(trusted_context)
    if type(receipt_bytes) is not bytes or not receipt_bytes:
        _refuse("bootstrap_mismatch")
    if len(receipt_bytes) > MAX_RECEIPT_BYTES:
        _refuse("bootstrap_payload_too_large")
    refuse_foreign_sources(lock_bytes)
    receipt = _call_cargo(cargo.decode_receipt, receipt_bytes)
    expected = dict(trusted_context)
    expected["receipt_sha256"] = hashlib.sha256(receipt_bytes).hexdigest()
    audits = {}
    for package in receipt["packages"]:
        if package["audit_record_id"] != PENDING_AUDIT_ID:
            _refuse("bootstrap_mismatch")
        audits[(package["name"], package["version"], package["checksum"])] = PENDING_AUDIT_ID
    _call_cargo(cargo.verify_lock_against_receipt, lock_bytes, receipt_bytes, expected, audits)
    return receipt


def index_path(name):
    """Return the sparse index path of a crate."""
    if type(name) is not str or CRATE_NAME_RE.fullmatch(name) is None:
        _refuse("bootstrap_input_invalid")
    lowered = name.lower()
    if len(lowered) == 1:
        return "/1/" + lowered
    if len(lowered) == 2:
        return "/2/" + lowered
    if len(lowered) == 3:
        return "/3/" + lowered[0] + "/" + lowered
    return "/" + lowered[:2] + "/" + lowered[2:4] + "/" + lowered


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class RegistryFetcher:
    """Fetch index entries and version metadata from the two fixed crates.io origins only."""

    def __init__(self, opener=None):
        self._proxy_handler = urllib.request.ProxyHandler({})
        self._opener = opener if opener is not None else urllib.request.build_opener(
            self._proxy_handler, _NoRedirect(),
        )

    def _get(self, host, path, limit, accept):
        url = "https:" + chr(47) * 2 + host + path
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or parsed.hostname != host or parsed.port is not None
                or parsed.query or parsed.fragment or parsed.username or parsed.password):
            _refuse("bootstrap_network_refused")
        request = urllib.request.Request(
            url, headers={"Accept": accept, "User-Agent": USER_AGENT}, method="GET",
        )
        try:
            with self._opener.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
                if response.status != 200 or response.geturl() != url:
                    raise ValueError
                data = response.read(limit + 1)
        except (OSError, ValueError, http.client.HTTPException, urllib.error.URLError):
            _refuse("bootstrap_network_refused")
        if type(data) is not bytes or not 0 < len(data) <= limit:
            _refuse("bootstrap_network_refused")
        return data

    def index_entry(self, name):
        return self._get(INDEX_HOST, index_path(name), MAX_INDEX_ENTRY_BYTES, "text/plain")

    def version_metadata(self, name, version):
        if not cargo._valid_package_identity(name, version):
            _refuse("bootstrap_input_invalid")
        return self._get(
            API_HOST, "/api/v1/crates/" + name + "/" + version, MAX_API_BYTES, "application/json",
        )


def _parse_created_at(value):
    match = CREATED_AT_RE.fullmatch(value) if type(value) is str else None
    if match is None:
        _refuse("bootstrap_evidence_invalid")
    fields = tuple(int(part) for part in match.groups())
    try:
        moment = datetime.datetime(*fields)
    except ValueError:
        _refuse("bootstrap_evidence_invalid")
    epoch = calendar.timegm(moment.utctimetuple())
    normalized = "%04d-%02d-%02dT%02d:%02d:%02dZ" % fields
    return epoch, normalized


def _check_index_entry(index_bytes, name, version, checksum):
    if type(index_bytes) is not bytes or not 0 < len(index_bytes) <= MAX_INDEX_ENTRY_BYTES:
        _refuse("bootstrap_evidence_invalid")
    try:
        text = index_bytes.decode("utf-8", "strict")
    except UnicodeError:
        _refuse("bootstrap_evidence_invalid")
    found = None
    for line in text.split("\n"):
        if not line:
            continue
        try:
            record = json.loads(
                line, object_pairs_hook=cargo._unique_json_pairs,
                parse_constant=cargo._reject_json_constant,
            )
        except (ValueError, TypeError, RecursionError):
            _refuse("bootstrap_evidence_invalid")
        if type(record) is not dict or type(record.get("name")) is not str:
            _refuse("bootstrap_evidence_invalid")
        if record["name"].lower() != name.lower():
            _refuse("bootstrap_evidence_invalid")
        if record.get("vers") == version:
            if found is not None:
                _refuse("bootstrap_evidence_invalid")
            found = record
    if found is None or type(found.get("yanked")) is not bool or found.get("cksum") != checksum:
        _refuse("bootstrap_evidence_invalid")
    if found["yanked"]:
        _refuse("bootstrap_package_yanked")


def _check_version_metadata(api_bytes, name, version, checksum, now):
    record = _strict_json(api_bytes, MAX_API_BYTES, "bootstrap_evidence_invalid", "utf-8")
    entry = record.get("version") if type(record) is dict else None
    if (type(entry) is not dict or entry.get("crate") != name or entry.get("num") != version
            or entry.get("checksum") != checksum or type(entry.get("yanked")) is not bool):
        _refuse("bootstrap_evidence_invalid")
    if entry["yanked"]:
        _refuse("bootstrap_package_yanked")
    epoch, normalized = _parse_created_at(entry.get("created_at"))
    if epoch > now + CLOCK_SKEW_SECONDS:
        _refuse("bootstrap_evidence_invalid")
    if now - epoch < MIN_PACKAGE_AGE_SECONDS:
        _refuse("bootstrap_package_too_young")
    return normalized


def _check_times(now, expiry):
    if (type(now) is not int or type(expiry) is not int or now < 1 or expiry <= now
            or expiry - now > MAX_REQUEST_TTL_SECONDS):
        _refuse("bootstrap_stale")


def _check_target(target):
    if type(target) is not str or cargo.TARGET_TRIPLE_RE.fullmatch(target) is None:
        _refuse("bootstrap_input_invalid")


def _check_run(run_id, run_attempt):
    if (type(run_id) is not str or DECIMAL_RE.fullmatch(run_id) is None
            or type(run_attempt) is not int or run_attempt != 1):
        _refuse("bootstrap_input_invalid")


def build_evidence(lock_bytes, receipt_bytes, trusted_context, *, run_id, run_attempt, now,
                   expiry, build_inputs, fetcher, toolchain_target):
    """Record index entry hashes and registry creation times for every receipt package."""
    receipt = self_check(lock_bytes, receipt_bytes, trusted_context)
    inputs = validate_build_inputs(build_inputs)
    _check_run(run_id, run_attempt)
    _check_target(toolchain_target)
    _check_times(now, expiry)
    if fetcher is None or not callable(getattr(fetcher, "index_entry", None)) \
            or not callable(getattr(fetcher, "version_metadata", None)):
        _refuse("bootstrap_input_invalid")
    index_entries = {}
    packages = []
    for package in receipt["packages"]:
        name, version, checksum = package["name"], package["version"], package["checksum"]
        if name not in index_entries:
            index_bytes = fetcher.index_entry(name)
            if type(index_bytes) is not bytes:
                _refuse("bootstrap_evidence_invalid")
            index_entries[name] = (hashlib.sha256(index_bytes).hexdigest(), index_bytes)
        index_digest, index_bytes = index_entries[name]
        _check_index_entry(index_bytes, name, version, checksum)
        created_at = _check_version_metadata(
            fetcher.version_metadata(name, version), name, version, checksum, now,
        )
        packages.append({
            "name": name, "version": version, "checksum": checksum,
            "index_entry_sha256": index_digest, "created_at": created_at,
        })
    record = {
        "schema_version": SCHEMA_VERSION,
        "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "run_id": run_id,
        "run_attempt": run_attempt,
        "generated_at": now,
        "expiry": expiry,
        "minimum_age_seconds": MIN_PACKAGE_AGE_SECONDS,
        "index_origin": INDEX_HOST,
        "api_origin": API_HOST,
        "toolchain_target": toolchain_target,
        "build_inputs": inputs,
        "packages": packages,
    }
    encoded = _canonical(record, "bootstrap_evidence_invalid")
    if len(encoded) > MAX_EVIDENCE_BYTES:
        _refuse("bootstrap_payload_too_large")
    return encoded


def validate_evidence(evidence_bytes, receipt_bytes, lock_bytes, *, now):
    """Check the evidence against its receipt and lock, its age rule, and its expiry."""
    if type(evidence_bytes) is not bytes or len(evidence_bytes) > MAX_EVIDENCE_BYTES:
        _refuse("bootstrap_payload_too_large" if type(evidence_bytes) is bytes
                else "bootstrap_evidence_invalid")
    record = _strict_json(evidence_bytes, MAX_EVIDENCE_BYTES, "bootstrap_evidence_invalid")
    if _canonical(record, "bootstrap_evidence_invalid") != evidence_bytes:
        _refuse("bootstrap_evidence_invalid")
    if type(record) is not dict or set(record) != set(EVIDENCE_FIELDS):
        _refuse("bootstrap_evidence_invalid")
    if (type(record["schema_version"]) is not int or record["schema_version"] != SCHEMA_VERSION
            or not _valid_hex(record["receipt_sha256"]) or not _valid_hex(record["lock_sha256"])
            or not hmac.compare_digest(record["receipt_sha256"], hashlib.sha256(receipt_bytes).hexdigest())
            or not hmac.compare_digest(record["lock_sha256"], hashlib.sha256(lock_bytes).hexdigest())
            or record["index_origin"] != INDEX_HOST or record["api_origin"] != API_HOST
            or type(record["minimum_age_seconds"]) is not int
            or record["minimum_age_seconds"] != MIN_PACKAGE_AGE_SECONDS):
        _refuse("bootstrap_evidence_invalid")
    _check_run(record["run_id"], record["run_attempt"])
    _check_target(record["toolchain_target"])
    generated_at = record["generated_at"]
    expiry = record["expiry"]
    _check_times(generated_at, expiry)
    if type(now) is not int or now >= expiry or now < generated_at - CLOCK_SKEW_SECONDS:
        _refuse("bootstrap_stale")
    validate_build_inputs(record["build_inputs"])
    receipt = _call_cargo(cargo.decode_receipt, receipt_bytes)
    packages = record["packages"]
    if type(packages) is not list or len(packages) != len(receipt["packages"]):
        _refuse("bootstrap_evidence_invalid")
    for item, expected in zip(packages, receipt["packages"]):
        if (type(item) is not dict or set(item) != set(EVIDENCE_PACKAGE_FIELDS)
                or item["name"] != expected["name"] or item["version"] != expected["version"]
                or item["checksum"] != expected["checksum"]
                or not _valid_hex(item["index_entry_sha256"])):
            _refuse("bootstrap_evidence_invalid")
        epoch, normalized = _parse_created_at(item["created_at"])
        if normalized != item["created_at"]:
            _refuse("bootstrap_evidence_invalid")
        if generated_at - epoch < MIN_PACKAGE_AGE_SECONDS:
            _refuse("bootstrap_package_too_young")
    return record


def encode_bundle(lock_bytes, receipt_bytes, evidence_bytes):
    """Encode the single return payload under the Cargo lock profile's own limits."""
    for data, maximum in (
        (lock_bytes, MAX_LOCK_BYTES), (receipt_bytes, MAX_RECEIPT_BYTES),
        (evidence_bytes, MAX_EVIDENCE_BYTES),
    ):
        if type(data) is not bytes or not data:
            _refuse("bootstrap_input_invalid")
        if len(data) > maximum:
            _refuse("bootstrap_payload_too_large")
    encoded = _canonical({
        "schema_version": SCHEMA_VERSION,
        "lock_b64": base64.b64encode(lock_bytes).decode("ascii"),
        "receipt_b64": base64.b64encode(receipt_bytes).decode("ascii"),
        "evidence_b64": base64.b64encode(evidence_bytes).decode("ascii"),
    }, "bootstrap_input_invalid")
    if len(encoded) > MAX_BUNDLE_BYTES:
        _refuse("bootstrap_payload_too_large")
    return encoded


def decode_bundle(bundle_bytes):
    """Decode only canonical bounded bundle bytes into lock, receipt and evidence bytes."""
    if type(bundle_bytes) is not bytes or not bundle_bytes:
        _refuse("bootstrap_input_invalid")
    if len(bundle_bytes) > MAX_BUNDLE_BYTES:
        _refuse("bootstrap_payload_too_large")
    record = _strict_json(bundle_bytes, MAX_BUNDLE_BYTES, "bootstrap_input_invalid")
    if (type(record) is not dict or set(record) != set(BUNDLE_FIELDS)
            or type(record["schema_version"]) is not int or record["schema_version"] != SCHEMA_VERSION):
        _refuse("bootstrap_input_invalid")
    members = []
    for name, maximum in (
        ("lock_b64", MAX_LOCK_BYTES), ("receipt_b64", MAX_RECEIPT_BYTES),
        ("evidence_b64", MAX_EVIDENCE_BYTES),
    ):
        text = record[name]
        if type(text) is not str or not text:
            _refuse("bootstrap_input_invalid")
        try:
            data = base64.b64decode(text.encode("ascii"), validate=True)
        except (ValueError, UnicodeError):
            _refuse("bootstrap_input_invalid")
        if base64.b64encode(data).decode("ascii") != text or not data:
            _refuse("bootstrap_input_invalid")
        if len(data) > maximum:
            _refuse("bootstrap_payload_too_large")
        members.append(data)
    if encode_bundle(*members) != bundle_bytes:
        _refuse("bootstrap_input_invalid")
    return tuple(members)


def verify_bundle(bundle_bytes, trusted_context, *, now):
    """Fully re-verify a bundle: lock, receipt, evidence ages and expiry."""
    lock_bytes, receipt_bytes, evidence_bytes = decode_bundle(bundle_bytes)
    self_check(lock_bytes, receipt_bytes, trusted_context)
    validate_evidence(evidence_bytes, receipt_bytes, lock_bytes, now=now)
    return lock_bytes, receipt_bytes, evidence_bytes


def produce_bundle(lock_bytes, trusted_context, *, run_id, run_attempt, now, expiry,
                   build_inputs, fetcher, toolchain_target):
    """Build, self-check and encode the return payload for one generated lock."""
    receipt_bytes = build_receipt(lock_bytes, trusted_context)
    self_check(lock_bytes, receipt_bytes, trusted_context)
    evidence_bytes = build_evidence(
        lock_bytes, receipt_bytes, trusted_context, run_id=run_id, run_attempt=run_attempt,
        now=now, expiry=expiry, build_inputs=build_inputs, fetcher=fetcher,
        toolchain_target=toolchain_target,
    )
    bundle = encode_bundle(lock_bytes, receipt_bytes, evidence_bytes)
    verify_bundle(bundle, trusted_context, now=now)
    return bundle


if __name__ == "__main__":
    try:
        sys.exit(_main(sys.argv[1:]))
    except BootstrapRefusal as error:
        sys.stderr.write(error.reason + "\n")
        sys.exit(2)
