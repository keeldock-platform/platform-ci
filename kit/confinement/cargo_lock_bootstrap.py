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
MIN_PACKAGE_AGE_SECONDS = 7 * 24 * 60 * 60
CLOCK_SKEW_SECONDS = 300
MAX_REQUEST_TTL_SECONDS = 24 * 60 * 60
PENDING_AUDIT_ID = "pending-review"
DEPENDENCY_POLICY_REVISION = "bootstrap-pending"
BUILD_INPUT_ALLOWLIST = ()
INDEX_HOST = "index.crates.io"
API_HOST = "crates.io"
USER_AGENT = "platform-ci-cargo-lock-bootstrap"
FETCH_TIMEOUT_SECONDS = 30
HEX64_RE = re.compile(r"[a-f0-9]{64}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
SOURCE_LINE_RE = re.compile(r"\s*source\s*=\s*\"([^\"]*)\"\s*\Z")
DEPENDENCY_SOURCE_RE = re.compile(r"\(([A-Za-z][A-Za-z0-9+.-]*\+[^()\"]*)\)")
CREATED_AT_RE = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.[0-9]{1,9})?(?:Z|\+00:00)\Z"
)
CRATE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
MAX_MANIFEST_BYTES = 256 * 1024
MAX_MANIFEST_LINES = 8192
MAX_MANIFEST_VALUE_DEPTH = 8
MAX_MANIFESTS = 16
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
        elif character == chr(35):
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


def _check_dependency(name, spec, directory, members):
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


def _check_workspace_members(workspace, members):
    listed = workspace.get("members")
    if (type(listed) is not list or any(type(item) is not str for item in listed)
            or len(set(listed)) != len(listed) or set(listed) != set(members)):
        _manifest_refuse()
    if "exclude" in workspace and workspace["exclude"] != []:
        _manifest_refuse()
    if "default-members" in workspace:
        default = workspace["default-members"]
        if (type(default) is not list or any(type(item) is not str for item in default)
                or len(set(default)) != len(default) or set(default) != set(members)):
            _manifest_refuse()


def _check_document(document, directory, members, is_root):
    if set(document) - ALLOWED_TOP_TABLES:
        _manifest_refuse()
    workspace = document.get("workspace")
    if workspace is not None:
        if not is_root or type(workspace) is not dict or set(workspace) - ALLOWED_WORKSPACE_KEYS:
            _manifest_refuse()
        _check_workspace_members(workspace, members)
    elif is_root:
        _manifest_refuse()
    tables = [document[name] for name in DEPENDENCY_TABLE_NAMES if name in document]
    target = document.get("target")
    if target is not None:
        if type(target) is not dict:
            _manifest_refuse()
        for entry in target.values():
            if type(entry) is not dict or set(entry) - ALLOWED_TARGET_KEYS:
                _manifest_refuse()
            tables.extend(entry[name] for name in DEPENDENCY_TABLE_NAMES if name in entry)
    if workspace is not None and "dependencies" in workspace:
        tables.append(workspace["dependencies"])
    for table in tables:
        if type(table) is not dict:
            _manifest_refuse()
        for name, spec in table.items():
            _check_dependency(name, spec, directory, members)
    package = document.get("package")
    if package is None:
        return None, None
    if (type(package) is not dict or type(package.get("name")) is not str
            or "workspace" in package or "edition" not in package):
        _manifest_refuse()
    return package["name"], package["edition"]


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


def check_manifests(manifests, members):
    """Check the root and member manifests before any Cargo command runs.

    Only exact version pins from the default registry and path dependencies that name a
    fixed workspace member are accepted. Git, registry, registry-index, any other path and
    every table outside the allowlist are refused, so are the underscore spellings of the
    dependency tables, a project table, a package workspace key, a workspace member list
    that differs from the fixed members, and any package without edition 2024. Anything
    that cannot be parsed is refused. Returns the package names the manifests declare.
    """
    if (type(manifests) is not dict or type(members) not in (set, frozenset, tuple)
            or not 1 <= len(manifests) <= MAX_MANIFESTS or "Cargo.toml" not in manifests):
        _manifest_refuse()
    member_set = frozenset(members)
    allowed = {"Cargo.toml"} | {member + "/Cargo.toml" for member in member_set}
    for path in manifests:
        if type(path) is not str or path not in allowed:
            _manifest_refuse()
    documents = {path: _parse_manifest(manifests[path]) for path in sorted(manifests)}
    names = set()
    for path, document in documents.items():
        directory = posixpath.dirname(path) or "."
        name, edition = _check_document(document, directory, member_set, path == "Cargo.toml")
        if name is not None:
            _check_edition(edition, documents["Cargo.toml"])
            if name in names:
                _manifest_refuse()
            names.add(name)
    return frozenset(names)


def check_lock_members(lock_bytes, package_names):
    """Require the lock's sourceless packages to be exactly the workspace packages."""
    lock = parse_lock(lock_bytes)
    sourceless = {package["name"] for package in lock["packages"] if package.get("source") is None}
    if type(package_names) not in (set, frozenset) or sourceless != set(package_names):
        _refuse("bootstrap_lock_refused")
    return True


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
