import base64
import binascii
import gzip
import hashlib
import hmac
import io
import json
import os
import re
import stat
import tarfile
from urllib.parse import quote
import zlib


SCHEMA_VERSION = 1
MATERIAL_SCHEMA_VERSION = 1
MAX_LOCK_BYTES = (4 * 1024 * 1024) - (64 * 1024)
MAX_JSON_DEPTH = 64
MAX_JSON_NODES = 250_000
MAX_JSON_STRING_BYTES = 8 * 1024
MAX_LOCK_ENTRIES = 1024
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
MAX_TARBALL_BYTES = 32 * 1024 * 1024
MAX_TAR_BYTES = 192 * 1024 * 1024
MAX_PACKAGE_UNPACKED_BYTES = 128 * 1024 * 1024
MAX_TOTAL_COMPRESSED_BYTES = 192 * 1024 * 1024
MAX_TOTAL_UNPACKED_BYTES = 768 * 1024 * 1024
MAX_ARCHIVE_FILES = 100_000
MAX_ARCHIVE_PATH_BYTES = 512
MAX_PACKAGE_JSON_BYTES = 256 * 1024
MAX_RECEIPT_TTL_SECONDS = 24 * 60 * 60
MAX_SAFE_INTEGER = 9_007_199_254_740_991
WINDOWS_RESERVED_BASENAMES = frozenset((
    "con", "prn", "aux", "nul", "conin$", "conout$", "clock$",
))
HEX40_RE = re.compile(r"[a-f0-9]{40}\Z")
HEX64_RE = re.compile(r"[a-f0-9]{64}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
PACKAGE_NAME_RE = re.compile(
    r"(?:@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*\Z"
)
DEPENDENCY_SPEC_RE = re.compile(r"[0-9A-Za-z.*^~<>=|+ -]{1,128}\Z")
IDENTIFIER_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
JOB_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
BRANCHES = frozenset(("main", "develop", "uat"))
PLATFORMS = frozenset(("linux", "windows", "macos"))
PROOF_PHASES = frozenset(("native-proof", "source-build", "release-replay"))
LOCK_ROOT_FIELDS = frozenset(("name", "version", "lockfileVersion", "requires", "packages"))
LOCK_ENTRY_FIELDS = frozenset((
    "name", "version", "workspaces", "resolved", "integrity", "link", "inBundle",
    "hasInstallScript", "hasShrinkwrap", "dev", "devOptional", "optional", "peer",
    "dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
    "peerDependenciesMeta", "bin", "license", "engines", "os", "cpu", "libc",
    "deprecated", "funding", "bundledDependencies", "bundleDependencies",
))
DEPENDENCY_FIELDS = frozenset((
    "dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
))
BOOLEAN_ENTRY_FIELDS = frozenset((
    "link", "inBundle", "hasInstallScript", "hasShrinkwrap", "dev", "devOptional",
    "optional", "peer",
))
WORKSPACE_LINKS = {
    "node_modules/" + "@" + "keeldock" + "/host-api": "packages/host-api",
}
MATERIAL_PATHS = (
    ".node-version",
    ".npmrc",
    "package.json",
    "package-lock.json",
    "packages/host-api/package.json",
    "dependency-policy.json",
)
_DOMAIN_PREFIX = b"keeldock" + b"-"
MATERIAL_DOMAIN = _DOMAIN_PREFIX + b"npm-material-v1\x00"
ARCHIVE_SET_DOMAIN = _DOMAIN_PREFIX + b"npm-archive-set-v1\x00"
PACKAGE_SET_DOMAIN = _DOMAIN_PREFIX + b"npm-package-set-v1\x00"
RUN_RECEIPT_FIELDS = frozenset((
    "schema_version", "record_type", "receipt_id", "context", "authorization",
))
LEDGER_RECORD_FIELDS = frozenset((
    "schema_version", "record_type", "admission_id", "context", "material_sha256",
    "lock_sha256", "archive_set_sha256", "package_set_sha256", "archive_identities",
    "archive_audit_store_sha256", "native_specification_sha256", "proof_results_sha256",
    "browser_set_id", "browser_inventory_sha256", "security_review_sha256",
    "frontend_review_sha256", "owner_approval_sha256", "created_at",
))
LEDGER_CONTEXT_FIELDS = frozenset((
    "repository_id", "source_sha", "base_sha", "base_branch", "reviewed_diff_sha256",
    "control_sha",
))
RUN_CONTEXT_FIELDS = LEDGER_CONTEXT_FIELDS | frozenset((
    "proof_phase", "platform", "job", "run_id", "run_attempt",
    "recipient_key_fingerprint", "issued_at", "expires_at",
))
ARCHIVE_IDENTITY_FIELDS = frozenset(("path", "name", "version", "integrity", "sha256"))
AUTHORIZATION_FIELDS = frozenset((
    "authorization_type", "authorization_id", "repository_id", "control_sha",
    "material_sha256", "lock_sha256", "archive_set_sha256", "package_set_sha256",
    "archive_identities", "native_specification_sha256", "browser_set_id",
    "browser_inventory_sha256",
))
REFUSAL_CODES = frozenset((
    "npm_lock_invalid", "npm_receipt_invalid", "npm_archive_invalid",
    "npm_material_invalid", "npm_context_mismatch", "npm_config_invalid",
))


class Refusal(Exception):
    def __init__(self, reason="npm_lock_invalid"):
        if reason not in REFUSAL_CODES:
            reason = "npm_lock_invalid"
        self.reason = reason
        super().__init__(reason)


def _refuse(reason="npm_lock_invalid"):
    raise Refusal(reason)


def _exact_dict(value, fields):
    return type(value) is dict and set(value) == set(fields)


def _valid_hex(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def _safe_int(value, minimum=0, maximum=MAX_SAFE_INTEGER):
    return type(value) is int and minimum <= value <= maximum


def _positive_decimal(value):
    return (
        type(value) is str and len(value) <= 19
        and DECIMAL_RE.fullmatch(value) is not None and int(value) <= MAX_SAFE_INTEGER
    )


def _valid_version(value):
    if type(value) is not str or len(value) > 128 or VERSION_RE.fullmatch(value) is None:
        return False
    core = value.split("+", 1)[0]
    if "-" in core:
        prerelease = core.split("-", 1)[1]
        for identifier in prerelease.split("."):
            if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
                return False
    return True


def _valid_package_name(value):
    if (type(value) is not str or len(value) > 214
            or PACKAGE_NAME_RE.fullmatch(value) is None or ".." in value):
        return False
    return value not in ("__proto__", "constructor", "prototype")


def _internal_name(name, extra_names=()):
    folded = name.lower().replace("_", "-")
    private_scope = "@" + "keeldock" + "/"
    private_prefix = "keeldock" + "-"
    return (
        folded.startswith(private_scope)
        or folded.startswith(private_prefix)
        or name in extra_names
    )


def _unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _parse_json_int(value):
    if len(value) > 16:
        raise ValueError("integer")
    parsed = int(value)
    if abs(parsed) > MAX_SAFE_INTEGER:
        raise ValueError("integer")
    return parsed


def _reject_json_number(value):
    raise ValueError("number")


def _reject_json_constant(value):
    raise ValueError("constant")


def _check_json_bounds(value, reason, depth=0, counter=None):
    if counter is None:
        counter = [0]
    counter[0] += 1
    if counter[0] > MAX_JSON_NODES or depth > MAX_JSON_DEPTH:
        _refuse(reason)
    if type(value) is str:
        try:
            encoded = value.encode("utf-8", "strict")
        except UnicodeError:
            _refuse(reason)
        if len(encoded) > MAX_JSON_STRING_BYTES:
            _refuse(reason)
    elif type(value) is dict:
        for key, item in value.items():
            if type(key) is not str or key in ("__proto__", "constructor", "prototype"):
                _refuse(reason)
            _check_json_bounds(key, reason, depth + 1, counter)
            _check_json_bounds(item, reason, depth + 1, counter)
    elif type(value) is list:
        for item in value:
            _check_json_bounds(item, reason, depth + 1, counter)
    elif value is None or type(value) in (bool, int):
        if type(value) is int and not _safe_int(value, -MAX_SAFE_INTEGER, MAX_SAFE_INTEGER):
            _refuse(reason)
    else:
        _refuse(reason)


def _load_json(data, maximum, reason, ascii_only=False):
    if type(data) is not bytes or not data or len(data) > maximum:
        _refuse(reason)
    encoding = "ascii" if ascii_only else "utf-8"
    try:
        text = data.decode(encoding, "strict")
        if text.startswith("\ufeff"):
            _refuse(reason)
        parsed = json.loads(
            text,
            object_pairs_hook=_unique_json_pairs,
            parse_int=_parse_json_int,
            parse_float=_reject_json_number,
            parse_constant=_reject_json_constant,
        )
    except Refusal:
        raise
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError, RecursionError):
        _refuse(reason)
    _check_json_bounds(parsed, reason)
    return parsed


def _valid_integrity(value):
    if type(value) is not str or not value.startswith("sha512-") or len(value) > 100:
        return False
    encoded = value[len("sha512-"):]
    try:
        decoded = base64.b64decode(encoded.encode("ascii", "strict"), validate=True)
    except (ValueError, UnicodeError, binascii.Error):
        return False
    return len(decoded) == 64 and base64.b64encode(decoded).decode("ascii") == encoded


def _integrity_bytes(value):
    if not _valid_integrity(value):
        _refuse("npm_lock_invalid")
    return base64.b64decode(value[len("sha512-"):].encode("ascii"), validate=True)


def _canonical_tarball_url(name, version):
    basename = name.rsplit("/", 1)[-1]
    package_path = quote(name, safe="@/")
    filename = quote(basename + "-" + version + ".tgz", safe="-._~")
    return "https:" + chr(47) * 2 + "registry.npmjs.org/" + package_path + "/-/" + filename


def _valid_workspace_path(value):
    if type(value) is not str or not value.startswith("packages/") or "\\" in value:
        return False
    if len(value.encode("utf-8", "strict")) > MAX_ARCHIVE_PATH_BYTES:
        return False
    parts = value.split("/")
    return all(part and part not in (".", "..") for part in parts)


def _package_name_from_lock_path(path):
    if type(path) is not str or len(path) > MAX_ARCHIVE_PATH_BYTES or "\\" in path:
        return None
    parts = path.split("/")
    if not parts or parts[0] != "node_modules":
        return None
    index = 1
    last_name = None
    while index < len(parts):
        if parts[index].startswith("@"):
            if index + 1 >= len(parts):
                return None
            last_name = parts[index] + "/" + parts[index + 1]
            index += 2
        else:
            last_name = parts[index]
            index += 1
        if not _valid_package_name(last_name):
            return None
        if index == len(parts):
            return last_name
        if parts[index] != "node_modules":
            return None
        index += 1
    return None


def _valid_dependency_spec(value, workspace_allowed):
    if type(value) is not str or len(value) > 128:
        return False
    if value.startswith("workspace:"):
        return workspace_allowed and re.fullmatch(
            r"workspace:(?:\*|\^|~|[0-9][0-9A-Za-z.+-]*)", value,
        ) is not None
    folded = value.lower()
    if any(folded.startswith(prefix) for prefix in (
            "file:", "link:", "git:", "git+", "http:", "https:", "ssh:",
            "github:", "npm:", "gitlab:", "bitbucket:")):
        return False
    if "://" in value or value.startswith(("/", "\\", "@")):
        return False
    return DEPENDENCY_SPEC_RE.fullmatch(value) is not None


def _validate_dependency_map(value, workspace_names, extra_internal_names):
    if type(value) is not dict or len(value) > 512:
        _refuse("npm_lock_invalid")
    for name, spec in value.items():
        if not _valid_package_name(name):
            _refuse("npm_lock_invalid")
        workspace_allowed = name in workspace_names
        if _internal_name(name, extra_internal_names) and not workspace_allowed:
            _refuse("npm_lock_invalid")
        if not _valid_dependency_spec(spec, workspace_allowed):
            _refuse("npm_lock_invalid")


def _validate_entry_shape(entry, workspace_names, extra_internal_names):
    if type(entry) is not dict or any(key not in LOCK_ENTRY_FIELDS for key in entry):
        _refuse("npm_lock_invalid")
    for key in BOOLEAN_ENTRY_FIELDS:
        if key in entry and type(entry[key]) is not bool:
            _refuse("npm_lock_invalid")
    if entry.get("inBundle") is True:
        _refuse("npm_lock_invalid")
    for key in DEPENDENCY_FIELDS:
        if key in entry:
            _validate_dependency_map(entry[key], workspace_names, extra_internal_names)
    if "peerDependenciesMeta" in entry:
        metadata = entry["peerDependenciesMeta"]
        if type(metadata) is not dict or len(metadata) > 512:
            _refuse("npm_lock_invalid")
        for name, options in metadata.items():
            if (not _valid_package_name(name) or type(options) is not dict
                    or (_internal_name(name, extra_internal_names) and name not in workspace_names)
                    or set(options) - {"optional"}
                    or ("optional" in options and type(options["optional"]) is not bool)):
                _refuse("npm_lock_invalid")
    if "workspaces" in entry:
        workspaces = entry["workspaces"]
        if (type(workspaces) is not list or len(workspaces) > 16
                or any(type(path) is not str for path in workspaces)
                or len(set(workspaces)) != len(workspaces)):
            _refuse("npm_lock_invalid")
        if any(type(path) is not str or not (
                path == "packages/*" or _valid_workspace_path(path)) for path in workspaces):
            _refuse("npm_lock_invalid")
    for key in ("os", "cpu", "libc", "bundledDependencies", "bundleDependencies"):
        if key in entry:
            values = entry[key]
            if (type(values) is not list or len(values) > 128
                    or any(type(item) is not str or len(item) > 128 for item in values)):
                _refuse("npm_lock_invalid")
            if key in ("bundledDependencies", "bundleDependencies"):
                if values:
                    _refuse("npm_lock_invalid")
    if "engines" in entry:
        engines = entry["engines"]
        if (type(engines) is not dict or len(engines) > 16
                or any(type(key) is not str or type(value) is not str
                       or len(key) > 64 or len(value) > 128
                       for key, value in engines.items())):
            _refuse("npm_lock_invalid")
    if "bin" in entry:
        bins = entry["bin"]
        if type(bins) is str:
            values = (bins,)
        elif type(bins) is dict and len(bins) <= 64:
            values = tuple(bins.values())
            if any(type(key) is not str or len(key) > 128 for key in bins):
                _refuse("npm_lock_invalid")
        else:
            _refuse("npm_lock_invalid")
        if any(type(value) is not str or len(value) > 512 or "\\" in value
               or value.startswith("/") or ".." in value.split("/") for value in values):
            _refuse("npm_lock_invalid")
    for key in ("license", "deprecated"):
        if key in entry and (type(entry[key]) is not str or len(entry[key]) > 4096):
            _refuse("npm_lock_invalid")
    if "funding" in entry:
        funding = entry["funding"]
        if type(funding) not in (str, dict, list):
            _refuse("npm_lock_invalid")
        if type(funding) is str and len(funding) > 2048:
            _refuse("npm_lock_invalid")


def parse_lock(lock_bytes, internal_names=()):
    if type(lock_bytes) is not bytes or len(lock_bytes) > MAX_LOCK_BYTES:
        _refuse("npm_lock_invalid")
    lock = _load_json(lock_bytes, MAX_LOCK_BYTES, "npm_lock_invalid")
    if type(lock) is not dict or set(lock) != LOCK_ROOT_FIELDS:
        _refuse("npm_lock_invalid")
    if (not _valid_package_name(lock["name"]) or not _valid_version(lock["version"])
            or type(lock["lockfileVersion"]) is not int or lock["lockfileVersion"] != 3
            or type(lock["requires"]) is not bool or lock["requires"] is not True):
        _refuse("npm_lock_invalid")
    if type(internal_names) not in (tuple, list, set, frozenset):
        _refuse("npm_lock_invalid")
    links = WORKSPACE_LINKS
    if not links or len(links) > 16:
        _refuse("npm_lock_invalid")
    expected_links = {}
    expected_workspace_names_by_path = {}
    expected_workspace_names = set()
    for link_path, workspace_path in links.items():
        package_name = _package_name_from_lock_path(link_path)
        if (package_name is None or not _valid_workspace_path(workspace_path)
                or workspace_path in expected_links.values()):
            _refuse("npm_lock_invalid")
        expected_links[link_path] = workspace_path
        expected_workspace_names_by_path[workspace_path] = package_name
        expected_workspace_names.add(package_name)
    extra_internal_names = tuple(internal_names)
    if any(not _valid_package_name(name) for name in extra_internal_names):
        _refuse("npm_lock_invalid")
    packages = lock["packages"]
    if (type(packages) is not dict or len(packages) < 1
            or len(packages) > MAX_LOCK_ENTRIES or "" not in packages):
        _refuse("npm_lock_invalid")
    if set(packages) - {"", *expected_links.keys(), *expected_links.values()}:
        for path in packages:
            if path == "" or path in expected_links or path in expected_links.values():
                continue
            if _package_name_from_lock_path(path) is None:
                _refuse("npm_lock_invalid")
    root_entry = packages[""]
    _validate_entry_shape(root_entry, expected_workspace_names, extra_internal_names)
    if (root_entry.get("name") != lock["name"] or root_entry.get("version") != lock["version"]
            or any(key in root_entry for key in ("resolved", "integrity", "link"))):
        _refuse("npm_lock_invalid")
    for workspace_path in expected_links.values():
        entry = packages.get(workspace_path)
        if entry is None:
            _refuse("npm_lock_invalid")
        _validate_entry_shape(entry, expected_workspace_names, extra_internal_names)
        if (not _valid_package_name(entry.get("name")) or not _valid_version(entry.get("version"))
                or entry["name"] != expected_workspace_names_by_path[workspace_path]
                or any(key in entry for key in ("resolved", "integrity", "link"))):
            _refuse("npm_lock_invalid")
    for link_path, workspace_path in expected_links.items():
        entry = packages.get(link_path)
        if (type(entry) is not dict or set(entry) != {"resolved", "link"}
                or entry["resolved"] != workspace_path or entry["link"] is not True):
            _refuse("npm_lock_invalid")
    registry_paths = set()
    for path, entry in packages.items():
        if path == "" or path in expected_links or path in expected_links.values():
            continue
        name = _package_name_from_lock_path(path)
        if name is None or path in registry_paths:
            _refuse("npm_lock_invalid")
        _validate_entry_shape(entry, expected_workspace_names, extra_internal_names)
        if ("link" in entry or not _valid_version(entry.get("version"))
                or not _valid_integrity(entry.get("integrity"))):
            _refuse("npm_lock_invalid")
        entry_name = entry.get("name", name)
        if (entry_name != name or _internal_name(name, extra_internal_names)
                or type(entry.get("resolved")) is not str
                or entry["resolved"] != _canonical_tarball_url(name, entry["version"])):
            _refuse("npm_lock_invalid")
        registry_paths.add(path)
    if set(expected_links) - set(packages) or set(expected_links.values()) - set(packages):
        _refuse("npm_lock_invalid")
    if any(not _valid_workspace_path(path) for path in packages if path not in ("",)
           and path not in expected_links and path not in expected_links.values()
           and not path.startswith("node_modules/")):
        _refuse("npm_lock_invalid")
    return lock


def registry_entries(lock, internal_names=()):
    if type(lock) is not bytes:
        _refuse("npm_lock_invalid")
    lock = parse_lock(lock, internal_names=internal_names)
    entries = []
    for path, entry in lock["packages"].items():
        if path == "" or path in WORKSPACE_LINKS or path in WORKSPACE_LINKS.values():
            continue
        normalized = dict(entry)
        normalized.setdefault("name", _package_name_from_lock_path(path))
        entries.append((path, normalized))
    entries.sort(key=lambda item: item[0].encode("ascii", "strict"))
    return entries


def compute_material_digest(material_files):
    if type(material_files) is not dict or set(material_files) != set(MATERIAL_PATHS):
        _refuse("npm_material_invalid")
    total = 0
    digest = hashlib.sha256()
    digest.update(MATERIAL_DOMAIN)
    digest.update(MATERIAL_SCHEMA_VERSION.to_bytes(4, "big"))
    ordered = sorted(material_files.items(), key=lambda item: item[0].encode("ascii", "strict"))
    digest.update(len(ordered).to_bytes(4, "big"))
    for path, content in ordered:
        if type(content) is not bytes:
            _refuse("npm_material_invalid")
        total += len(content)
        if total > MAX_LOCK_BYTES + (len(MATERIAL_PATHS) * 1024 * 1024):
            _refuse("npm_material_invalid")
        path_bytes = path.encode("ascii", "strict")
        digest.update(len(path_bytes).to_bytes(4, "big"))
        digest.update(path_bytes)
        digest.update(len(content).to_bytes(8, "big"))
        digest.update(hashlib.sha256(content).digest())
    return digest.hexdigest()


def _safe_relative_archive_path(value):
    if type(value) is not str or not value or "\\" in value or value.startswith("/"):
        return False
    try:
        encoded = value.encode("utf-8", "strict")
    except UnicodeError:
        return False
    if len(encoded) > MAX_ARCHIVE_PATH_BYTES or any(ord(char) < 32 or ord(char) > 126 for char in value):
        return False
    parts = value.split("/")
    if not parts or any(part in ("", ".", "..") for part in parts):
        return False
    for part in parts:
        if (part[-1] in (".", " ")
                or any(char in '<>:"|?*~' for char in part)):
            return False
        basename = part.split(".", 1)[0].strip(" ").lower()
        if (basename in WINDOWS_RESERVED_BASENAMES
                or (len(basename) == 4 and basename[:3] in ("com", "lpt")
                    and basename[3] in "123456789\u00b9\u00b2\u00b3")):
            return False
    return True


def _read_bounded_gzip(data):
    if type(data) is not bytes or len(data) < 2 or data[:2] != b"\x1f\x8b":
        _refuse("npm_archive_invalid")
    output = io.BytesIO()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as stream:
            total = 0
            while True:
                chunk = stream.read(min(1024 * 1024, MAX_TAR_BYTES + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_TAR_BYTES:
                    _refuse("npm_archive_invalid")
                output.write(chunk)
    except Refusal:
        raise
    except (OSError, EOFError, gzip.BadGzipFile, zlib.error):
        _refuse("npm_archive_invalid")
    return output.getvalue()


def _tar_octal(raw):
    value = raw.strip(b"\x00 ")
    if not value or any(byte not in b"01234567" for byte in value):
        _refuse("npm_archive_invalid")
    return int(value, 8)


def _preflight_tar_headers(data):
    if type(data) is not bytes or len(data) < 1024 or len(data) % 512:
        _refuse("npm_archive_invalid")
    offset = 0
    count = 0
    total = 0
    found_end = False
    while offset + 512 <= len(data):
        header = data[offset:offset + 512]
        if header == bytes(512):
            found_end = True
            if any(data[offset:]):
                _refuse("npm_archive_invalid")
            break
        count += 1
        if count > MAX_ARCHIVE_FILES:
            _refuse("npm_archive_invalid")
        stored_checksum = _tar_octal(header[148:156])
        actual_checksum = sum(header[:148]) + (32 * 8) + sum(header[156:])
        if stored_checksum != actual_checksum:
            _refuse("npm_archive_invalid")
        member_type = header[156:157]
        if member_type not in (b"0", b"5", b"\x00"):
            _refuse("npm_archive_invalid")
        raw_name = header[:100].split(b"\x00", 1)[0]
        if member_type == b"5":
            if not raw_name.endswith(b"/") or raw_name.endswith(b"//"):
                _refuse("npm_archive_invalid")
        elif raw_name.endswith(b"/"):
            _refuse("npm_archive_invalid")
        size = _tar_octal(header[124:136])
        if size > MAX_PACKAGE_UNPACKED_BYTES or (member_type == b"5" and size != 0):
            _refuse("npm_archive_invalid")
        total += size
        if total > MAX_PACKAGE_UNPACKED_BYTES:
            _refuse("npm_archive_invalid")
        offset += 512 + (((size + 511) // 512) * 512)
        if offset > len(data):
            _refuse("npm_archive_invalid")
    if not found_end:
        _refuse("npm_archive_invalid")


def _native_path(path):
    folded = path.lower()
    return folded.endswith((".node", ".dll", ".so", ".dylib", ".exe", ".pyd"))


def _native_magic(data):
    return (
        data.startswith(b"\x7fELF") or data.startswith(b"MZ")
        or data.startswith((b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe"))
        or data.startswith((b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe"))
        or data.startswith((b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"))
        or data.startswith((b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca"))
    )


def _manifest_scripts(data, name, version):
    manifest = _load_json(data, MAX_PACKAGE_JSON_BYTES, "npm_archive_invalid")
    if type(manifest) is not dict or manifest.get("name") != name or manifest.get("version") != version:
        _refuse("npm_archive_invalid")
    scripts = manifest.get("scripts", {})
    if type(scripts) is not dict or len(scripts) > 256:
        _refuse("npm_archive_invalid")
    for key, value in scripts.items():
        if type(key) is not str or type(value) is not str or len(key) > 128:
            _refuse("npm_archive_invalid")
    return scripts, manifest.get("gypfile", True)


def _inspect_tarball(name, version, integrity, data, internal_names=()):
    if (not _valid_package_name(name) or not _valid_version(version)
            or _internal_name(name, internal_names) or not _valid_integrity(integrity)
            or type(data) is not bytes
            or len(data) == 0 or len(data) > MAX_TARBALL_BYTES):
        _refuse("npm_archive_invalid")
    expected_digest = _integrity_bytes(integrity)
    actual_digest = hashlib.sha512(data).digest()
    if not hmac.compare_digest(actual_digest, expected_digest):
        _refuse("npm_archive_invalid")
    archive_sha256 = hashlib.sha256(data).hexdigest()
    tar_bytes = _read_bounded_gzip(data)
    _preflight_tar_headers(tar_bytes)
    entries = {}
    folded = set()
    spellings = {}
    total = 0
    package_json_member = None
    manifest_bytes = None
    native_paths = []
    root_binding_gyp = False
    try:
        archive = tarfile.open(
            fileobj=io.BytesIO(tar_bytes), mode="r:", encoding="utf-8", errors="strict",
        )
        with archive:
            count = 0
            for member in archive:
                count += 1
                if count > MAX_ARCHIVE_FILES:
                    _refuse("npm_archive_invalid")
                raw_name = member.name
                if (member.pax_headers or getattr(member, "sparse", None)
                        or not _safe_relative_archive_path(raw_name.rstrip("/"))):
                    _refuse("npm_archive_invalid")
                is_directory = member.type == tarfile.DIRTYPE
                is_regular = member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                if not is_directory and not is_regular:
                    _refuse("npm_archive_invalid")
                if member.linkname:
                    _refuse("npm_archive_invalid")
                relative = raw_name.rstrip("/")
                if relative.split("/", 1)[0] != "package":
                    _refuse("npm_archive_invalid")
                if not is_directory and raw_name.endswith("/"):
                    _refuse("npm_archive_invalid")
                folded_relative = relative.lower()
                if relative in entries or folded_relative in folded:
                    _refuse("npm_archive_invalid")
                folded.add(folded_relative)
                parts = relative.split("/")
                if any(part.lower() == "node_modules" for part in parts[1:]):
                    _refuse("npm_archive_invalid")
                for index in range(1, len(parts) + 1):
                    spelling = "/".join(parts[:index])
                    key = spelling.lower()
                    previous = spellings.get(key)
                    if previous is not None and previous != spelling:
                        _refuse("npm_archive_invalid")
                    spellings[key] = spelling
                if len(parts) == 1 and not is_directory:
                    _refuse("npm_archive_invalid")
                if member.size < 0 or member.size > MAX_PACKAGE_UNPACKED_BYTES:
                    _refuse("npm_archive_invalid")
                if is_directory and member.size != 0:
                    _refuse("npm_archive_invalid")
                if not is_directory:
                    total += member.size
                    if total > MAX_PACKAGE_UNPACKED_BYTES:
                        _refuse("npm_archive_invalid")
                entries[relative] = (is_directory, member)
                if relative == "package/package.json" and not is_directory:
                    package_json_member = member
                if folded_relative == "package/binding.gyp" and not is_directory:
                    root_binding_gyp = True
                if not is_directory and _native_path(relative):
                    native_paths.append(relative)
            for path, (is_directory, member) in entries.items():
                parts = path.split("/")
                for index in range(1, len(parts)):
                    parent = "/".join(parts[:index])
                    parent_entry = entries.get(parent)
                    if parent_entry is not None and not parent_entry[0]:
                        _refuse("npm_archive_invalid")
                if is_directory:
                    continue
                stream = archive.extractfile(member)
                if stream is None:
                    _refuse("npm_archive_invalid")
                with stream:
                    if path == "package/package.json":
                        content = stream.read(MAX_PACKAGE_JSON_BYTES + 1)
                        if len(content) != member.size or len(content) > MAX_PACKAGE_JSON_BYTES:
                            _refuse("npm_archive_invalid")
                        manifest_bytes = content
                    else:
                        content = stream.read(8)
                if not is_directory and _native_magic(content) and path not in native_paths:
                    native_paths.append(path)
    except Refusal:
        raise
    except (tarfile.TarError, OSError, UnicodeError, ValueError, EOFError, RecursionError):
        _refuse("npm_archive_invalid")
    if package_json_member is None:
        _refuse("npm_archive_invalid")
    if manifest_bytes is None:
        _refuse("npm_archive_invalid")
    scripts, gypfile = _manifest_scripts(manifest_bytes, name, version)
    implicit_install = (
        root_binding_gyp and gypfile is not False
        and not scripts.get("preinstall") and not scripts.get("install")
    )
    lifecycle = ("preinstall", "install", "postinstall", "prepare")
    install_scripts = tuple(
        script for script in lifecycle
        if scripts.get(script) or (implicit_install and script == "install")
    )
    return {
        "name": name,
        "version": version,
        "sha256": archive_sha256,
        "compressed_bytes": len(data),
        "unpacked_bytes": total,
        "file_count": sum(1 for is_directory, unused in entries.values() if not is_directory),
        "install_scripts": install_scripts,
        "implicit_install_scripts": ("install",) if implicit_install else (),
        "native_binaries": tuple(sorted(native_paths)),
    }


def verify_tarball(entry, data, internal_names=()):
    if type(entry) is not dict or not {"name", "version", "integrity"}.issubset(entry):
        _refuse("npm_archive_invalid")
    name = entry["name"]
    version = entry["version"]
    if (not _valid_package_name(name) or not _valid_version(version)
            or _internal_name(name, internal_names)):
        _refuse("npm_archive_invalid")
    if "resolved" in entry and entry["resolved"] != _canonical_tarball_url(name, version):
        _refuse("npm_archive_invalid")
    return _inspect_tarball(name, version, entry["integrity"], data, internal_names)


def read_bounded_file(path, maximum=MAX_TARBALL_BYTES):
    if type(maximum) is not int or maximum < 1 or maximum > MAX_TARBALL_BYTES:
        _refuse("npm_archive_invalid")
    try:
        path_text = os.fspath(path)
    except TypeError:
        _refuse("npm_archive_invalid")
    if (type(path_text) is not str or len(path_text) > 4096 or "\x00" in path_text
            or "\n" in path_text or "\r" in path_text or not os.path.isabs(path_text)):
        _refuse("npm_archive_invalid")
    descriptor = None
    try:
        before_path = os.lstat(path_text)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if (stat.S_ISLNK(before_path.st_mode)
                or getattr(before_path, "st_file_attributes", 0) & reparse_flag):
            _refuse("npm_archive_invalid")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path_text, flags)
        before = os.fstat(descriptor)
        if (not stat.S_ISREG(before.st_mode) or getattr(before, "st_nlink", 1) != 1
                or before.st_size < 1 or before.st_size > maximum
                or (before.st_dev, before.st_ino) != (before_path.st_dev, before_path.st_ino)):
            _refuse("npm_archive_invalid")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                _refuse("npm_archive_invalid")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
                after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            _refuse("npm_archive_invalid")
        return b"".join(chunks)
    except Refusal:
        raise
    except OSError:
        _refuse("npm_archive_invalid")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def verify_tarball_file(path, entry):
    return verify_tarball(entry, read_bounded_file(path))


def verify_archive_set(lock_bytes, archive_bytes_by_path, internal_names=()):
    entries = registry_entries(lock_bytes, internal_names=internal_names)
    expected_paths = {path for path, unused_entry in entries}
    if type(archive_bytes_by_path) is not dict or set(archive_bytes_by_path) != expected_paths:
        _refuse("npm_archive_invalid")
    identities = []
    total_compressed = 0
    total_unpacked = 0
    total_files = 0
    for path, entry in entries:
        report = verify_tarball(entry, archive_bytes_by_path[path], internal_names=internal_names)
        total_compressed += report["compressed_bytes"]
        total_unpacked += report["unpacked_bytes"]
        total_files += report["file_count"]
        if (total_compressed > MAX_TOTAL_COMPRESSED_BYTES
                or total_unpacked > MAX_TOTAL_UNPACKED_BYTES
                or total_files > MAX_ARCHIVE_FILES):
            _refuse("npm_archive_invalid")
        identities.append({
            "path": path,
            "name": entry.get("name", _package_name_from_lock_path(path)),
            "version": entry["version"],
            "integrity": entry["integrity"],
            "sha256": report["sha256"],
        })
    return identities


def _validate_archive_identities(identities):
    if type(identities) is not list or len(identities) > MAX_LOCK_ENTRIES:
        _refuse("npm_receipt_invalid")
    previous = None
    for item in identities:
        if not _exact_dict(item, ARCHIVE_IDENTITY_FIELDS):
            _refuse("npm_receipt_invalid")
        path = item["path"]
        name = item["name"]
        if (type(path) is not str or len(path) > MAX_ARCHIVE_PATH_BYTES
                or _package_name_from_lock_path(path) != name
                or not _valid_package_name(name) or _internal_name(name)
                or not _valid_version(item["version"]) or not _valid_integrity(item["integrity"])
                or not _valid_hex(item["sha256"], HEX64_RE)):
            _refuse("npm_receipt_invalid")
        if previous is not None and path <= previous:
            _refuse("npm_receipt_invalid")
        previous = path


def archive_set_digest(identities):
    _validate_archive_identities(identities)
    encoded = _canonical_json(identities, "npm_receipt_invalid")
    digest = hashlib.sha256()
    digest.update(ARCHIVE_SET_DOMAIN)
    digest.update(len(identities).to_bytes(4, "big"))
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)
    return digest.hexdigest()


def package_set_digest(lock_sha256, identities):
    if not _valid_hex(lock_sha256, HEX64_RE):
        _refuse("npm_receipt_invalid")
    archive_digest = bytes.fromhex(archive_set_digest(identities))
    digest = hashlib.sha256()
    digest.update(PACKAGE_SET_DOMAIN)
    digest.update(bytes.fromhex(lock_sha256))
    digest.update(archive_digest)
    return digest.hexdigest()


def _canonical_json(value, reason):
    try:
        return json.dumps(
            value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("ascii", "strict")
    except (TypeError, ValueError, UnicodeError):
        _refuse(reason)


def _validate_ledger_context(context, fields):
    if not _exact_dict(context, fields):
        _refuse("npm_receipt_invalid")
    if (not _positive_decimal(context["repository_id"])
            or not _valid_hex(context["source_sha"], HEX40_RE)
            or not _valid_hex(context["base_sha"], HEX40_RE)
            or type(context["base_branch"]) is not str
            or context["base_branch"] not in BRANCHES
            or not _valid_hex(context["reviewed_diff_sha256"], HEX64_RE)
            or not _valid_hex(context["control_sha"], HEX40_RE)):
        _refuse("npm_receipt_invalid")


def _validate_run_context(context):
    _validate_ledger_context(context, RUN_CONTEXT_FIELDS)
    if (type(context["proof_phase"]) is not str or context["proof_phase"] not in PROOF_PHASES
            or type(context["platform"]) is not str or context["platform"] not in PLATFORMS
            or type(context["job"]) is not str or JOB_RE.fullmatch(context["job"]) is None
            or not _positive_decimal(context["run_id"])
            or not _safe_int(context["run_attempt"], 1, 100)
            or not _valid_hex(context["recipient_key_fingerprint"], HEX64_RE)
            or not _safe_int(context["issued_at"], 1)
            or not _safe_int(context["expires_at"], 1)
            or context["expires_at"] <= context["issued_at"]
            or context["expires_at"] - context["issued_at"] > MAX_RECEIPT_TTL_SECONDS):
        _refuse("npm_receipt_invalid")


def _validate_admission_id(value):
    return type(value) is str and IDENTIFIER_RE.fullmatch(value) is not None


def _validate_archive_bindings(record):
    _validate_archive_identities(record["archive_identities"])
    if (not _valid_hex(record["material_sha256"], HEX64_RE)
            or not _valid_hex(record["lock_sha256"], HEX64_RE)
            or not _valid_hex(record["archive_set_sha256"], HEX64_RE)
            or not _valid_hex(record["package_set_sha256"], HEX64_RE)):
        _refuse("npm_receipt_invalid")
    if archive_set_digest(record["archive_identities"]) != record["archive_set_sha256"]:
        _refuse("npm_receipt_invalid")
    if package_set_digest(record["lock_sha256"], record["archive_identities"]) != record["package_set_sha256"]:
        _refuse("npm_receipt_invalid")


def _validate_run_receipt(record):
    if not _exact_dict(record, RUN_RECEIPT_FIELDS):
        _refuse("npm_receipt_invalid")
    if (type(record["schema_version"]) is not int or record["schema_version"] != SCHEMA_VERSION
            or record["record_type"] != "npm-run-receipt"
            or type(record["record_type"]) is not str
            or not _valid_hex(record["receipt_id"], HEX64_RE)):
        _refuse("npm_receipt_invalid")
    _validate_run_context(record["context"])
    _validate_authorization(record["authorization"])


def _validate_authorization(binding):
    if not _exact_dict(binding, AUTHORIZATION_FIELDS):
        _refuse("npm_receipt_invalid")
    if (binding["authorization_type"] not in ("admission", "permit")
            or type(binding["authorization_type"]) is not str
            or not _validate_admission_id(binding["authorization_id"])
            or not _positive_decimal(binding["repository_id"])
            or not _valid_hex(binding["control_sha"], HEX40_RE)):
        _refuse("npm_receipt_invalid")
    _validate_archive_bindings(binding)
    if not _valid_hex(binding["native_specification_sha256"], HEX64_RE):
        _refuse("npm_receipt_invalid")
    browser_set_id = binding["browser_set_id"]
    browser_inventory = binding["browser_inventory_sha256"]
    if browser_set_id == "":
        if browser_inventory != "0" * 64:
            _refuse("npm_receipt_invalid")
    elif (not _validate_admission_id(browser_set_id)
            or not _valid_hex(browser_inventory, HEX64_RE)):
        _refuse("npm_receipt_invalid")


def _validate_ledger_record(record):
    if not _exact_dict(record, LEDGER_RECORD_FIELDS):
        _refuse("npm_receipt_invalid")
    if (type(record["schema_version"]) is not int or record["schema_version"] != SCHEMA_VERSION
            or record["record_type"] != "npm-admission-ledger-record"
            or type(record["record_type"]) is not str
            or not _validate_admission_id(record["admission_id"])):
        _refuse("npm_receipt_invalid")
    _validate_ledger_context(record["context"], LEDGER_CONTEXT_FIELDS)
    _validate_archive_bindings(record)
    for field in (
            "archive_audit_store_sha256", "native_specification_sha256", "proof_results_sha256",
            "security_review_sha256", "frontend_review_sha256", "owner_approval_sha256"):
        if not _valid_hex(record[field], HEX64_RE):
            _refuse("npm_receipt_invalid")
    browser_set_id = record["browser_set_id"]
    browser_inventory = record["browser_inventory_sha256"]
    if browser_set_id == "":
        if browser_inventory != "0" * 64:
            _refuse("npm_receipt_invalid")
    elif (not _validate_admission_id(browser_set_id)
            or not _valid_hex(browser_inventory, HEX64_RE)):
        _refuse("npm_receipt_invalid")
    if not _safe_int(record["created_at"], 1):
        _refuse("npm_receipt_invalid")


def encode_run_receipt(record):
    _validate_run_receipt(record)
    encoded = _canonical_json(record, "npm_receipt_invalid")
    if len(encoded) > MAX_RECEIPT_BYTES:
        _refuse("npm_receipt_invalid")
    return encoded


def encode_admission_record(record):
    _validate_ledger_record(record)
    encoded = _canonical_json(record, "npm_receipt_invalid")
    if len(encoded) > MAX_RECEIPT_BYTES:
        _refuse("npm_receipt_invalid")
    return encoded


def _decode_canonical_record(data, validator):
    record = _load_json(data, MAX_RECEIPT_BYTES, "npm_receipt_invalid", ascii_only=True)
    validator(record)
    if _canonical_json(record, "npm_receipt_invalid") != data:
        _refuse("npm_receipt_invalid")
    return record


def decode_run_receipt(data):
    return _decode_canonical_record(data, _validate_run_receipt)


def decode_admission_record(data):
    return _decode_canonical_record(data, _validate_ledger_record)


def _compare_context(actual, expected, fields):
    if not _exact_dict(expected, fields):
        _refuse("npm_context_mismatch")
    for field in fields:
        if actual.get(field) != expected[field]:
            _refuse("npm_context_mismatch")


def verify_admission_record(
    record, lock_bytes, material_files, archive_bytes_by_path, expected_context,
    internal_names=(),
):
    if type(record) is bytes:
        record = decode_admission_record(record)
    else:
        _validate_ledger_record(record)
    _compare_context(record["context"], expected_context, LEDGER_CONTEXT_FIELDS)
    try:
        lock = parse_lock(lock_bytes)
        material_digest = compute_material_digest(material_files)
    except Refusal:
        _refuse("npm_context_mismatch")
    lock_digest = hashlib.sha256(lock_bytes).hexdigest()
    identities = verify_archive_set(
        lock_bytes, archive_bytes_by_path, internal_names=internal_names,
    )
    if (material_files["package-lock.json"] != lock_bytes
            or material_digest != record["material_sha256"]
            or lock_digest != record["lock_sha256"]
            or identities != record["archive_identities"]
            or package_set_digest(lock_digest, identities) != record["package_set_sha256"]):
        _refuse("npm_context_mismatch")
    if record["archive_set_sha256"] != archive_set_digest(identities):
        _refuse("npm_context_mismatch")
    return True


def verify_run_receipt(
    receipt, lock_bytes, material_files, archive_bytes_by_path, expected_context,
    expected_authorization, now, internal_names=(),
):
    if type(receipt) is bytes:
        receipt = decode_run_receipt(receipt)
    else:
        _validate_run_receipt(receipt)
    _compare_context(receipt["context"], expected_context, RUN_CONTEXT_FIELDS)
    _validate_authorization(expected_authorization)
    if (receipt["authorization"] != expected_authorization
            or receipt["context"]["repository_id"] != expected_authorization["repository_id"]
            or receipt["context"]["control_sha"] != expected_authorization["control_sha"]):
        _refuse("npm_context_mismatch")
    if not _safe_int(now, 1) or now < receipt["context"]["issued_at"] or now >= receipt["context"]["expires_at"]:
        _refuse("npm_context_mismatch")
    if (material_files.get("package-lock.json") != lock_bytes
            or compute_material_digest(material_files) != expected_authorization["material_sha256"]
            or hashlib.sha256(lock_bytes).hexdigest() != expected_authorization["lock_sha256"]):
        _refuse("npm_context_mismatch")
    identities = verify_archive_set(
        lock_bytes, archive_bytes_by_path, internal_names=internal_names,
    )
    lock_digest = hashlib.sha256(lock_bytes).hexdigest()
    if (identities != expected_authorization["archive_identities"]
            or archive_set_digest(identities) != expected_authorization["archive_set_sha256"]
            or package_set_digest(lock_digest, identities) != expected_authorization["package_set_sha256"]):
        _refuse("npm_context_mismatch")
    return True


def admission_authorization(record):
    if type(record) is bytes:
        record = decode_admission_record(record)
    else:
        _validate_ledger_record(record)
    return {
        "authorization_type": "admission",
        "authorization_id": record["admission_id"],
        "repository_id": record["context"]["repository_id"],
        "control_sha": record["context"]["control_sha"],
        "material_sha256": record["material_sha256"],
        "lock_sha256": record["lock_sha256"],
        "archive_set_sha256": record["archive_set_sha256"],
        "package_set_sha256": record["package_set_sha256"],
        "archive_identities": record["archive_identities"],
        "native_specification_sha256": record["native_specification_sha256"],
        "browser_set_id": record["browser_set_id"],
        "browser_inventory_sha256": record["browser_inventory_sha256"],
    }


def build_offline_install_arguments():
    return ("ci", "--offline", "--ignore-scripts", "--no-audit", "--no-fund")


def _safe_environment_path(value):
    return (
        type(value) is str and 1 <= len(value) <= 4096 and os.path.isabs(value)
        and "\x00" not in value and "\n" not in value and "\r" not in value
    )


def build_offline_install_environment(runtime_bin, scratch_root, inherited_environment=None):
    if not _safe_environment_path(runtime_bin) or not _safe_environment_path(scratch_root):
        _refuse("npm_config_invalid")
    inherited = dict(os.environ) if inherited_environment is None else inherited_environment
    if type(inherited) is not dict:
        _refuse("npm_config_invalid")
    environment = {}
    for key in ("LANG", "LC_ALL", "TZ"):
        value = inherited.get(key)
        if value is not None:
            if (type(value) is not str or len(value) > 128 or "\x00" in value
                    or "\n" in value or "\r" in value):
                _refuse("npm_config_invalid")
            environment[key] = value
    if os.name == "nt":
        system_root = inherited.get("SystemRoot", inherited.get("SYSTEMROOT"))
        if not _safe_environment_path(system_root):
            _refuse("npm_config_invalid")
        environment["SystemRoot"] = system_root
        environment["PATH"] = os.pathsep.join((runtime_bin, os.path.join(system_root, "System32")))
    else:
        environment["PATH"] = os.pathsep.join((runtime_bin, "/usr/bin", "/bin"))
    temp_root = os.path.join(scratch_root, "tmp")
    isolated_home = os.path.join(scratch_root, "home")
    environment.update({
        "HOME": isolated_home,
        "TMPDIR": temp_root,
        "TEMP": temp_root,
        "TMP": temp_root,
        "npm_config_cache": os.path.join(scratch_root, "cache"),
        "npm_config_userconfig": os.path.join(scratch_root, "empty-user.npmrc"),
        "npm_config_globalconfig": os.path.join(scratch_root, "empty-global.npmrc"),
        "npm_config_offline": "true",
        "npm_config_ignore_scripts": "true",
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_update_notifier": "false",
        "npm_config_logs_max": "0",
    })
    if os.name == "nt":
        environment["USERPROFILE"] = isolated_home
    return environment
