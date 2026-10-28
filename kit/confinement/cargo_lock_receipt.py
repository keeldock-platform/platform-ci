"""Bounded Cargo lock receipts and verified, source-free crate materialization."""

import ctypes
import errno
import gzip
import hashlib
import hmac
import io
import json
import os
import secrets
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import tarfile
import tempfile


REGISTRY_SOURCE = (
    "registry+https:" + chr(47) * 2 + "github.com" + chr(47)
    + "rust-lang" + chr(47) + "crates.io-index"
)
SPARSE_REGISTRY_SOURCE = "sparse+https:" + chr(47) * 2 + "index.crates.io/"
SCHEMA_VERSION = 1
MAX_LOCK_BYTES = 4 * 1024 * 1024
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_TAR_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
MAX_COMPRESSION_RATIO = 200
MAX_LOCK_PACKAGES = 20_000
MAX_LOCK_DEPENDENCIES = 20_000
MAX_DEPENDENCY_ARRAY_BYTES = 1024 * 1024
MAX_DEPENDENCY_ARRAY_LINES = 20_000
HEX40_RE = re.compile(r"[a-f0-9]{40}\Z")
HEX64_RE = re.compile(r"[a-f0-9]{64}\Z")
PACKAGE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
VERSION_RE = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z"
)
DEPENDENCY_RE = re.compile(
    r"(?P<name>[A-Za-z0-9][A-Za-z0-9_-]{0,63})"
    r"(?: (?P<version>[^ ()]{1,128}))?"
    r"(?: \((?P<source>[^()]*)\))?\Z"
)
LOCK_FIELDS = frozenset(("name", "version", "source", "checksum", "dependencies"))
RECEIPT_FIELDS = frozenset((
    "schema_version", "repository", "workspace_path", "source_sha", "base_sha",
    "base_branch", "reviewed_diff_fingerprint", "dependency_policy_revision",
    "control_sha", "toolchain_hash", "lock_sha256", "packages",
))
PACKAGE_RECEIPT_FIELDS = frozenset(("name", "version", "checksum", "audit_record_id"))
CONTEXT_FIELDS = RECEIPT_FIELDS - frozenset(("schema_version", "lock_sha256", "packages"))
TRUSTED_CONTEXT_FIELDS = CONTEXT_FIELDS | frozenset(("receipt_sha256",))
PATH_PART_RE = re.compile(r"[A-Za-z0-9._+@ -]{1,255}\Z")
AUDIT_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
WINDOWS_RESERVED_NAMES = frozenset(("CON", "PRN", "AUX", "NUL")) | frozenset(
    "COM" + str(number) for number in range(1, 10)
) | frozenset("LPT" + str(number) for number in range(1, 10))


class Refusal(Exception):
    """A refusal with a fixed message that never contains caller-provided data."""

    def __init__(self, reason="cargo_lock_receipt_invalid"):
        if reason not in (
            "cargo_lock_receipt_invalid", "cargo_lock_invalid", "cargo_receipt_invalid",
            "cargo_lock_mismatch", "cargo_archive_invalid", "cargo_config_invalid",
            "cargo_vendor_invalid",
        ):
            reason = "cargo_lock_receipt_invalid"
        self.reason = reason
        super().__init__(reason)


def _refuse(reason="cargo_lock_receipt_invalid"):
    raise Refusal(reason)


def _exact_dict(value, fields):
    return type(value) is dict and set(value) == set(fields)


def _valid_hex(value, pattern):
    return type(value) is str and pattern.fullmatch(value) is not None


def _valid_package_identity(name, version):
    return (
        type(name) is str and PACKAGE_NAME_RE.fullmatch(name) is not None
        and _valid_version(version)
    )


def _valid_version(version):
    if type(version) is not str or len(version) > 128 or VERSION_RE.fullmatch(version) is None:
        return False
    core = version.split("+", 1)[0]
    if "-" in core:
        prerelease = core.split("-", 1)[1]
        for identifier in prerelease.split("."):
            if identifier.isdigit() and len(identifier) > 1 and identifier.startswith("0"):
                return False
    return True


def _internal_registry_name(name):
    return name.lower().replace("_", "-").startswith("keeldock" + "-")


def _registry_source(source):
    if source in (REGISTRY_SOURCE, SPARSE_REGISTRY_SOURCE):
        return REGISTRY_SOURCE
    return None


def _is_link_or_reparse(path):
    try:
        metadata = Path(path).lstat()
    except OSError:
        return False
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & reparse_flag
    )


def _decode_ascii(data, maximum, reason):
    if type(data) is not bytes or len(data) > maximum:
        _refuse(reason)
    try:
        return data.decode("ascii", "strict")
    except UnicodeError:
        _refuse(reason)


def _strip_toml_comment(line):
    quoted = False
    escaped = False
    for index, character in enumerate(line):
        if escaped:
            escaped = False
        elif quoted and character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif character == chr(35) and not quoted:
            return line[:index]
    if quoted or escaped:
        _refuse("cargo_lock_invalid")
    return line


def _parse_toml_string(value):
    if len(value) < 2 or value[0] != '"' or value[-1] != '"':
        _refuse("cargo_lock_invalid")
    result = []
    index = 1
    while index < len(value) - 1:
        character = value[index]
        if character == "\\":
            index += 1
            if index >= len(value) - 1 or value[index] not in ('"', "\\"):
                _refuse("cargo_lock_invalid")
            character = value[index]
        elif character == '"' or ord(character) < 32:
            _refuse("cargo_lock_invalid")
        result.append(character)
        index += 1
    return "".join(result)


def _parse_string_array(value):
    if not value.startswith("[") or not value.endswith("]"):
        _refuse("cargo_lock_invalid")
    body = value[1:-1]
    result = []
    index = 0
    while index < len(body):
        while index < len(body) and body[index] in " \t":
            index += 1
        if index == len(body):
            break
        if body[index] != '"':
            _refuse("cargo_lock_invalid")
        start = index
        index += 1
        escaped = False
        while index < len(body):
            character = body[index]
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                index += 1
                break
            index += 1
        else:
            _refuse("cargo_lock_invalid")
        result.append(_parse_toml_string(body[start:index]))
        if len(result) > MAX_LOCK_DEPENDENCIES or len(result[-1]) > 512:
            _refuse("cargo_lock_invalid")
        while index < len(body) and body[index] in " \t":
            index += 1
        if index == len(body):
            break
        if body[index] != ",":
            _refuse("cargo_lock_invalid")
        index += 1
        while index < len(body) and body[index] in " \t":
            index += 1
        if index < len(body) and body[index] == ",":
            _refuse("cargo_lock_invalid")
    return result


def _scan_array_fragment(value, quoted=False, escaped=False, depth=0):
    complete = False
    for character in value:
        if complete:
            if character not in " \t":
                _refuse("cargo_lock_invalid")
            continue
        if escaped:
            escaped = False
        elif quoted and character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif not quoted and character == "[":
            depth += 1
            if depth != 1:
                _refuse("cargo_lock_invalid")
        elif not quoted and character == "]":
            depth -= 1
            if depth == 0:
                complete = True
            if depth < 0:
                _refuse("cargo_lock_invalid")
    return complete, quoted, escaped, depth


def _parse_lock_value(key, value):
    value = value.strip()
    if key == "dependencies":
        return _parse_string_array(value)
    if value.startswith('"'):
        return _parse_toml_string(value)
    if key == "version" and value in ("3", "4"):
        return int(value)
    _refuse("cargo_lock_invalid")


def _dependency_record(value):
    if type(value) is not str or len(value) > 512:
        _refuse("cargo_lock_invalid")
    match = DEPENDENCY_RE.fullmatch(value)
    if match is None:
        _refuse("cargo_lock_invalid")
    name = match.group("name")
    version = match.group("version")
    source = match.group("source")
    if source is not None and _registry_source(source) and _internal_registry_name(name):
        _refuse("cargo_lock_invalid")
    if version is not None and not _valid_package_identity(name, version):
        _refuse("cargo_lock_invalid")
    if source is not None and _registry_source(source) is None:
        _refuse("cargo_lock_invalid")
    if source is not None and version is None:
        _refuse("cargo_lock_invalid")
    return name, version, _registry_source(source) if source is not None else None


def parse_cargo_lock(lock_bytes):
    """Parse the supported v3/v4 Cargo.lock subset without a general TOML parser."""
    text = _decode_ascii(lock_bytes, MAX_LOCK_BYTES, "cargo_lock_invalid")
    if text.startswith("\ufeff"):
        _refuse("cargo_lock_invalid")
    packages = []
    current = None
    lock_version = None
    lines = iter(text.splitlines(keepends=True))
    for raw_line in lines:
        line = _strip_toml_comment(raw_line).strip()
        if not line:
            continue
        if line == "[[package]]":
            if current is not None:
                packages.append(current)
                if len(packages) >= MAX_LOCK_PACKAGES:
                    _refuse("cargo_lock_invalid")
            current = {}
            continue
        if "=" not in line:
            _refuse("cargo_lock_invalid")
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", key) is None:
            _refuse("cargo_lock_invalid")
        raw_value = raw_value.strip()
        if key == "dependencies" and raw_value.startswith("["):
            fragments = [raw_value]
            complete, quoted, escaped, depth = _scan_array_fragment(raw_value)
            total_array_bytes = len(raw_line)
            line_count = 1
            if total_array_bytes > MAX_DEPENDENCY_ARRAY_BYTES:
                _refuse("cargo_lock_invalid")
            while not complete:
                try:
                    continuation_line = next(lines)
                except StopIteration:
                    _refuse("cargo_lock_invalid")
                line_count += 1
                total_array_bytes += len(continuation_line)
                if (line_count > MAX_DEPENDENCY_ARRAY_LINES
                        or total_array_bytes > MAX_DEPENDENCY_ARRAY_BYTES):
                    _refuse("cargo_lock_invalid")
                continuation = _strip_toml_comment(continuation_line).strip()
                if continuation:
                    fragments.append(continuation)
                    complete, quoted, escaped, depth = _scan_array_fragment(
                        continuation, quoted, escaped, depth,
                    )
            raw_value = " ".join(fragments)
        value = _parse_lock_value(key, raw_value)
        if current is None:
            if key != "version" or lock_version is not None:
                _refuse("cargo_lock_invalid")
            lock_version = value
        else:
            if key not in LOCK_FIELDS or key in current:
                _refuse("cargo_lock_invalid")
            current[key] = value
    if current is not None:
        packages.append(current)
    if lock_version not in (3, 4) or not packages:
        _refuse("cargo_lock_invalid")

    seen = set()
    for package in packages:
        if not _valid_package_identity(package.get("name"), package.get("version")):
            _refuse("cargo_lock_invalid")
        name = package["name"]
        version = package["version"]
        source = package.get("source")
        checksum = package.get("checksum")
        if source is None:
            if checksum is not None:
                _refuse("cargo_lock_invalid")
        elif _registry_source(source) is not None:
            if _internal_registry_name(name) or not _valid_hex(checksum, HEX64_RE):
                _refuse("cargo_lock_invalid")
            package["source"] = REGISTRY_SOURCE
        else:
            _refuse("cargo_lock_invalid")
        identity = (name, version)
        if identity in seen:
            _refuse("cargo_lock_invalid")
        seen.add(identity)
        dependencies = package.get("dependencies", [])
        if type(dependencies) is not list:
            _refuse("cargo_lock_invalid")
        parsed_dependencies = [_dependency_record(item) for item in dependencies]
        if len(set(parsed_dependencies)) != len(parsed_dependencies):
            _refuse("cargo_lock_invalid")
        package["dependencies"] = parsed_dependencies

    by_name = {}
    by_identity = {}
    for package in packages:
        by_name.setdefault(package["name"], []).append(package)
        by_identity[(package["name"], package["version"])] = package
    for package in packages:
        for dependency_name, dependency_version, dependency_source in package["dependencies"]:
            if dependency_version is None:
                candidates = by_name.get(dependency_name, [])
                candidate = candidates[0] if len(candidates) == 1 else None
            else:
                candidate = by_identity.get((dependency_name, dependency_version))
            if candidate is None or (dependency_source is not None
                                     and candidate.get("source") != dependency_source):
                _refuse("cargo_lock_invalid")
    return {"version": lock_version, "packages": packages}


def _valid_repository(value):
    if type(value) is not str or len(value) > 128 or value.count("/") != 1:
        return False
    owner, repository = value.split("/", 1)
    pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")
    return pattern.fullmatch(owner) is not None and pattern.fullmatch(repository) is not None


def _valid_workspace_path(value):
    if type(value) is not str or len(value) > 512 or "\\" in value or value.startswith("/"):
        return False
    if value == ".":
        return True
    parts = value.split("/")
    return bool(parts) and all(
        _safe_path_part(part)
        for part in parts
    )


def _valid_branch(value):
    return (
        type(value) is str and len(value) <= 128
        and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", value) is not None
        and ".." not in value and "//" not in value and not value.endswith("/")
        and not value.endswith(".lock") and "@{" not in value
    )


def _validate_receipt(record):
    if not _exact_dict(record, RECEIPT_FIELDS):
        _refuse("cargo_receipt_invalid")
    if (type(record["schema_version"]) is not int or record["schema_version"] != SCHEMA_VERSION
            or not _valid_repository(record["repository"])
            or not _valid_workspace_path(record["workspace_path"])
            or not _valid_hex(record["source_sha"], HEX40_RE)
            or not _valid_hex(record["base_sha"], HEX40_RE)
            or not _valid_branch(record["base_branch"])
            or not _valid_hex(record["reviewed_diff_fingerprint"], HEX64_RE)
            or type(record["dependency_policy_revision"]) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}", record["dependency_policy_revision"]) is None
            or not _valid_hex(record["control_sha"], HEX40_RE)
            or not _valid_hex(record["toolchain_hash"], HEX64_RE)
            or not _valid_hex(record["lock_sha256"], HEX64_RE)):
        _refuse("cargo_receipt_invalid")
    packages = record["packages"]
    if type(packages) is not list or len(packages) > 20_000:
        _refuse("cargo_receipt_invalid")
    previous = None
    seen = set()
    for item in packages:
        if not _exact_dict(item, PACKAGE_RECEIPT_FIELDS):
            _refuse("cargo_receipt_invalid")
        if (not _valid_package_identity(item["name"], item["version"])
                or _internal_registry_name(item["name"])
                or not _valid_hex(item["checksum"], HEX64_RE)
                or type(item["audit_record_id"]) is not str
                or AUDIT_ID_RE.fullmatch(item["audit_record_id"]) is None):
            _refuse("cargo_receipt_invalid")
        identity = (item["name"], item["version"])
        if identity in seen or (previous is not None and identity < previous):
            _refuse("cargo_receipt_invalid")
        previous = identity
        seen.add(identity)


def _canonical_json(record):
    try:
        return json.dumps(
            record, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
            allow_nan=False,
        ).encode("ascii", "strict")
    except (TypeError, ValueError, UnicodeError):
        _refuse("cargo_receipt_invalid")


def encode_receipt(record):
    """Encode a strictly validated receipt as canonical UTF-8 JSON bytes."""
    _validate_receipt(record)
    encoded = _canonical_json(record)
    if len(encoded) > MAX_RECEIPT_BYTES:
        _refuse("cargo_receipt_invalid")
    return encoded


def _unique_json_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate")
        result[key] = value
    return result


def _reject_json_constant(value):
    raise ValueError("constant")


def decode_receipt(receipt_bytes):
    """Decode only canonical, exact-schema receipt bytes; errors never echo input."""
    text = _decode_ascii(receipt_bytes, MAX_RECEIPT_BYTES, "cargo_receipt_invalid")
    try:
        record = json.loads(
            text, object_pairs_hook=_unique_json_pairs, parse_constant=_reject_json_constant,
        )
    except (ValueError, TypeError, json.JSONDecodeError, RecursionError):
        _refuse("cargo_receipt_invalid")
    _validate_receipt(record)
    if _canonical_json(record) != receipt_bytes:
        _refuse("cargo_receipt_invalid")
    return record


def verify_lock_against_receipt(lock_bytes, receipt, expected_context, authorized_audits):
    """Require trusted context, receipt provenance and audit mapping before network use.

    The caller obtains expected_context and authorized_audits from independently
    authenticated policy and review records, not from the receipt or checkout.
    """
    if type(receipt) is bytes:
        receipt = decode_receipt(receipt)
    else:
        _validate_receipt(receipt)
    if not _exact_dict(expected_context, TRUSTED_CONTEXT_FIELDS):
        _refuse("cargo_lock_mismatch")
    for field in CONTEXT_FIELDS:
        if expected_context[field] != receipt[field]:
            _refuse("cargo_lock_mismatch")
    if not _valid_hex(expected_context["receipt_sha256"], HEX64_RE):
        _refuse("cargo_lock_mismatch")
    canonical_receipt = encode_receipt(receipt)
    if not hmac.compare_digest(
            hashlib.sha256(canonical_receipt).hexdigest(), expected_context["receipt_sha256"]):
        _refuse("cargo_lock_mismatch")
    if type(authorized_audits) is not dict or len(authorized_audits) != len(receipt["packages"]):
        _refuse("cargo_lock_mismatch")
    for package in receipt["packages"]:
        identity = (package["name"], package["version"], package["checksum"])
        if authorized_audits.get(identity) != package["audit_record_id"]:
            _refuse("cargo_lock_mismatch")
    if type(lock_bytes) is not bytes or len(lock_bytes) > MAX_LOCK_BYTES:
        _refuse("cargo_lock_mismatch")
    lock_digest = hashlib.sha256(lock_bytes).hexdigest()
    if not hmac.compare_digest(lock_digest, receipt["lock_sha256"]):
        _refuse("cargo_lock_mismatch")
    lock = parse_cargo_lock(lock_bytes)
    expected = [
        (package["name"], package["version"], package["checksum"])
        for package in receipt["packages"]
    ]
    actual = sorted(
        (package["name"], package["version"], package["checksum"])
        for package in lock["packages"] if package.get("source") == REGISTRY_SOURCE
    )
    if actual != expected:
        _refuse("cargo_lock_mismatch")
    return True


def crate_archive_url(name, version):
    """Build the only permitted crate archive URL after validating path components."""
    if not _valid_package_identity(name, version) or _internal_registry_name(name):
        _refuse("cargo_archive_invalid")
    return "https:" + chr(47) * 2 + "static.crates.io/crates/" + name + "/" + name + "-" + version + ".crate"


def _safe_relative_path(value):
    if type(value) is not str or not value or len(value) > 1024 or "\\" in value:
        return False
    if value.startswith("/") or "\x00" in value:
        return False
    parts = value.split("/")
    return all(_safe_path_part(part) for part in parts)


def _safe_path_part(part):
    if (type(part) is not str or part in ("", ".", "..")
            or PATH_PART_RE.fullmatch(part) is None or part.endswith((".", " "))):
        return False
    stem = part.split(".", 1)[0].upper()
    return stem not in WINDOWS_RESERVED_NAMES


def _bounded_gzip(data):
    if type(data) is not bytes or not data:
        _refuse("cargo_archive_invalid")
    if len(data) < 2 or data[:2] != b"\x1f\x8b":
        _refuse("cargo_archive_invalid")
    output = io.BytesIO()
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(data), mode="rb") as stream:
            total = 0
            while True:
                chunk = stream.read(min(1024 * 1024, MAX_TAR_BYTES + 1 - total))
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_TAR_BYTES or total > len(data) * MAX_COMPRESSION_RATIO:
                    _refuse("cargo_archive_invalid")
                output.write(chunk)
    except Refusal:
        raise
    except (OSError, EOFError, gzip.BadGzipFile):
        _refuse("cargo_archive_invalid")
    return output.getvalue()


def _preflight_tar_headers(data):
    if len(data) % 512:
        _refuse("cargo_archive_invalid")
    offset = 0
    count = 0
    while offset + 512 <= len(data):
        header = data[offset:offset + 512]
        if header == bytes(512):
            for start in range(offset, len(data), 1024 * 1024):
                chunk = data[start:start + 1024 * 1024]
                if chunk != bytes(len(chunk)):
                    _refuse("cargo_archive_invalid")
            return
        count += 1
        if count > MAX_ARCHIVE_MEMBERS:
            _refuse("cargo_archive_invalid")
        member_type = header[156:157]
        if member_type not in (b"0", b"5", b"\x00"):
            _refuse("cargo_archive_invalid")
        raw_size = header[124:136].strip(b"\x00 ")
        if not raw_size or any(byte not in b"01234567" for byte in raw_size):
            _refuse("cargo_archive_invalid")
        size = int(raw_size, 8)
        if size > MAX_FILE_BYTES or (member_type == b"5" and size != 0):
            _refuse("cargo_archive_invalid")
        offset += 512 + ((size + 511) // 512) * 512
        if offset > len(data):
            _refuse("cargo_archive_invalid")
    _refuse("cargo_archive_invalid")


def _parse_checksum_manifest(data, expected_checksum, file_hashes):
    if type(data) is not bytes or len(data) > 2 * 1024 * 1024:
        _refuse("cargo_archive_invalid")
    try:
        manifest = json.loads(
            data.decode("ascii", "strict"), object_pairs_hook=_unique_json_pairs,
            parse_constant=_reject_json_constant,
        )
    except (ValueError, TypeError, UnicodeError, json.JSONDecodeError, RecursionError):
        _refuse("cargo_archive_invalid")
    if not _exact_dict(manifest, ("files", "package")) or type(manifest["files"]) is not dict:
        _refuse("cargo_archive_invalid")
    if manifest["package"] != expected_checksum:
        _refuse("cargo_archive_invalid")
    provided = manifest["files"]
    if set(provided) != set(file_hashes):
        _refuse("cargo_archive_invalid")
    for name, digest in provided.items():
        if (not _safe_relative_path(name) or type(digest) is not str
                or not _valid_hex(digest, HEX64_RE) or digest != file_hashes[name]):
            _refuse("cargo_archive_invalid")


def _inspect_archive(name, version, data, expected_sha256):
    if not _valid_package_identity(name, version) or not _valid_hex(expected_sha256, HEX64_RE):
        _refuse("cargo_archive_invalid")
    if type(data) is not bytes or len(data) > MAX_ARCHIVE_BYTES:
        _refuse("cargo_archive_invalid")
    actual_digest = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(actual_digest, expected_sha256):
        _refuse("cargo_archive_invalid")
    tar_bytes = _bounded_gzip(data)
    _preflight_tar_headers(tar_bytes)
    entries = {}
    folded = set()
    case_spellings = {}
    total_bytes = 0
    try:
        archive = tarfile.open(
            fileobj=io.BytesIO(tar_bytes), mode="r:", encoding="utf-8", errors="strict",
        )
        with archive:
            member_count = 0
            for member in archive:
                member_count += 1
                if member_count > MAX_ARCHIVE_MEMBERS:
                    _refuse("cargo_archive_invalid")
                raw_name = member.name
                if (not _safe_relative_path(raw_name.rstrip("/"))
                        or member.pax_headers or getattr(member, "sparse", None)):
                    _refuse("cargo_archive_invalid")
                is_directory = member.type == tarfile.DIRTYPE
                is_regular = member.type in (tarfile.REGTYPE, tarfile.AREGTYPE)
                if not is_directory and not is_regular:
                    _refuse("cargo_archive_invalid")
                if ((not is_directory and raw_name.endswith("/"))
                        or raw_name.endswith("//")):
                    _refuse("cargo_archive_invalid")
                relative = raw_name.rstrip("/")
                parts = relative.split("/")
                expected_root = name + "-" + version
                if not parts or parts[0] != expected_root:
                    _refuse("cargo_archive_invalid")
                if len(parts) == 1 and not is_directory:
                    _refuse("cargo_archive_invalid")
                folded_path = relative.casefold()
                if folded_path in folded:
                    _refuse("cargo_archive_invalid")
                folded.add(folded_path)
                for index in range(1, len(parts) + 1):
                    spelling = "/".join(parts[:index])
                    folded_prefix = spelling.casefold()
                    previous_spelling = case_spellings.get(folded_prefix)
                    if previous_spelling is not None and previous_spelling != spelling:
                        _refuse("cargo_archive_invalid")
                    case_spellings[folded_prefix] = spelling
                key = "/".join(parts)
                if key in entries:
                    _refuse("cargo_archive_invalid")
                if is_directory:
                    if member.size != 0:
                        _refuse("cargo_archive_invalid")
                    entries[key] = (True, b"")
                else:
                    if member.size < 0 or member.size > MAX_FILE_BYTES:
                        _refuse("cargo_archive_invalid")
                    total_bytes += member.size
                    if total_bytes > MAX_TOTAL_BYTES:
                        _refuse("cargo_archive_invalid")
                    stream = archive.extractfile(member)
                    if stream is None:
                        _refuse("cargo_archive_invalid")
                    with stream:
                        content = stream.read(member.size + 1)
                    if len(content) != member.size:
                        _refuse("cargo_archive_invalid")
                    entries[key] = (False, content)
    except Refusal:
        raise
    except (tarfile.TarError, OSError, UnicodeError, ValueError, EOFError, RecursionError):
        _refuse("cargo_archive_invalid")

    root = name + "-" + version
    for path, (is_directory, unused_content) in entries.items():
        parts = path.split("/")
        if path != root:
            for index in range(1, len(parts)):
                parent = "/".join(parts[:index])
                if parent in entries and not entries[parent][0]:
                    _refuse("cargo_archive_invalid")
        if parts[-1] == ".cargo-checksum.json" and path != root + "/.cargo-checksum.json":
            _refuse("cargo_archive_invalid")
    if root in entries and entries[root][0] is not True:
        _refuse("cargo_archive_invalid")
    if root not in entries and not any(path.startswith(root + "/") for path in entries):
        _refuse("cargo_archive_invalid")
    cargo_toml = root + "/Cargo.toml"
    if cargo_toml not in entries or entries[cargo_toml][0]:
        _refuse("cargo_archive_invalid")
    checksum_path = root + "/.cargo-checksum.json"
    file_hashes = {}
    for path, (is_directory, content) in entries.items():
        if is_directory or path == checksum_path:
            continue
        file_hashes[path[len(root) + 1:]] = hashlib.sha256(content).hexdigest()
    if root + "/Cargo.toml.orig" in entries and "Cargo.toml.orig" not in file_hashes:
        _refuse("cargo_archive_invalid")
    if checksum_path in entries:
        if entries[checksum_path][0]:
            _refuse("cargo_archive_invalid")
        _parse_checksum_manifest(entries[checksum_path][1], expected_sha256, file_hashes)
    return root, entries, file_hashes, expected_sha256


def verify_archive(name, version, data, expected_sha256):
    """Verify archive digest, bounded gzip/tar structure and any embedded vendor checksums."""
    _inspect_archive(name, version, data, expected_sha256)
    return True


def _require_no_extended_acl(descriptor):
    """Require a macOS directory descriptor with no extended ACL entries."""
    if sys.platform != "darwin":
        return
    try:
        library = ctypes.CDLL(None, use_errno=True)
        get_acl = library.acl_get_fd_np
        get_acl.argtypes = (ctypes.c_int, ctypes.c_int)
        get_acl.restype = ctypes.c_void_p
        get_entry = library.acl_get_entry
        get_entry.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.POINTER(ctypes.c_void_p))
        get_entry.restype = ctypes.c_int
        release = library.acl_free
        release.argtypes = (ctypes.c_void_p,)
        release.restype = ctypes.c_int
        ctypes.set_errno(0)
        acl = get_acl(descriptor, 0x100)
        if not acl:
            if ctypes.get_errno() == errno.ENOENT:
                return
            _refuse("cargo_archive_invalid")
        try:
            entry = ctypes.c_void_p()
            ctypes.set_errno(0)
            result = get_entry(acl, 0, ctypes.byref(entry))
            if result != -1 or ctypes.get_errno() != errno.EINVAL:
                _refuse("cargo_archive_invalid")
        finally:
            if release(acl) != 0:
                _refuse("cargo_archive_invalid")
    except (AttributeError, OSError, TypeError, ValueError):
        _refuse("cargo_archive_invalid")


def _require_trusted_ancestor(metadata, descriptor):
    mode = stat.S_IMODE(metadata.st_mode)
    if (not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid not in (0, os.geteuid())
            or ((mode & 0o022) and not (metadata.st_uid == 0 and mode & stat.S_ISVTX))):
        _refuse("cargo_archive_invalid")
    _require_no_extended_acl(descriptor)


def _open_target_directory(path):
    if not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW"):
        _refuse("cargo_archive_invalid")
    target = Path(path)
    if not target.is_absolute() or any(part in (".", "..") for part in target.parts):
        _refuse("cargo_archive_invalid")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open("/", flags)
    pending = list(target.parts[1:])
    physical_parts = []
    private_boundary = False
    link_count = 0
    try:
        while pending:
            if len(pending) > 128 or len(physical_parts) > 128:
                _refuse("cargo_archive_invalid")
            component = pending.pop(0)
            _require_trusted_ancestor(os.fstat(descriptor), descriptor)
            entry = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(entry.st_mode):
                if private_boundary or entry.st_uid not in (0, os.geteuid()) or link_count >= 4:
                    _refuse("cargo_archive_invalid")
                link = os.readlink(component, dir_fd=descriptor)
                link_parts = link.split("/")
                if not all(_safe_path_part(part) for part in link_parts):
                    _refuse("cargo_archive_invalid")
                pending = link_parts + pending
                link_count += 1
                continue
            next_descriptor = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            physical_parts.append(component)
            child = os.fstat(descriptor)
            child_mode = stat.S_IMODE(child.st_mode)
            if child.st_uid == os.geteuid() and (child_mode & 0o077) == 0:
                private_boundary = True
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or (mode & 0o077) or (mode & 0o700) != 0o700):
            _refuse("cargo_archive_invalid")
        _require_no_extended_acl(descriptor)
        return descriptor, Path("/", *physical_parts)
    except BaseException:
        os.close(descriptor)
        raise


def _open_relative_directory(root_fd, parts):
    descriptor = os.dup(root_fd)
    try:
        for component in parts:
            next_descriptor = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _write_stage_file(root_fd, relative, content):
    parts = relative.split("/")
    parent_fd = _open_relative_directory(root_fd, parts[:-1])
    try:
        descriptor = os.open(
            parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600, dir_fd=parent_fd,
        )
        try:
            view = memoryview(content)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    _refuse("cargo_archive_invalid")
                view = view[written:]
            os.fchmod(descriptor, 0o444)
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_fd)


def _file_identity(metadata):
    return metadata.st_dev, metadata.st_ino


def _entry_identity(parent_fd, name):
    metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if not stat.S_ISDIR(metadata.st_mode):
        _refuse("cargo_archive_invalid")
    return _file_identity(metadata)


def _remove_stage(parent_fd, name, expected_identity=None):
    descriptor = os.open(
        name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd,
    )
    try:
        if expected_identity is not None and _file_identity(os.fstat(descriptor)) != expected_identity:
            _refuse("cargo_archive_invalid")
        os.fchmod(descriptor, 0o700)
        for child in os.listdir(descriptor):
            mode = os.stat(child, dir_fd=descriptor, follow_symlinks=False).st_mode
            if stat.S_ISDIR(mode):
                _remove_stage(descriptor, child)
            else:
                os.unlink(child, dir_fd=descriptor)
    finally:
        os.close(descriptor)
    os.rmdir(name, dir_fd=parent_fd)


def _publish_stage(parent_fd, stage_name, final_name, expected_identity):
    if _entry_identity(parent_fd, stage_name) != expected_identity:
        _refuse("cargo_archive_invalid")
    symbol = "renameatx_np" if sys.platform == "darwin" else "renameat2"
    rename = getattr(ctypes.CDLL(None, use_errno=True), symbol, None)
    if rename is None:
        _refuse("cargo_archive_invalid")
    rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    rename.restype = ctypes.c_int
    flag = 4 if sys.platform == "darwin" else 1
    if rename(parent_fd, stage_name.encode("ascii"), parent_fd,
              final_name.encode("ascii"), flag) != 0:
        raise OSError(ctypes.get_errno(), "atomic package publication failed")
    if _entry_identity(parent_fd, final_name) != expected_identity:
        _refuse("cargo_archive_invalid")


def _windows_stage_identity(path):
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or _is_link_or_reparse(path):
        _refuse("cargo_archive_invalid")
    return _file_identity(metadata)


def _validate_windows_target(path):
    target = Path(path)
    if not target.is_absolute() or any(part in (".", "..") for part in target.parts):
        _refuse("cargo_archive_invalid")
    for directory in (target,) + tuple(target.parents):
        if _is_link_or_reparse(directory) or not directory.is_dir():
            _refuse("cargo_archive_invalid")
    return target


def _trusted_windows_temp_root():
    buffer = ctypes.create_unicode_buffer(32768)
    try:
        result = ctypes.windll.shell32.SHGetFolderPathW(None, 0x001c, None, 0, buffer)
    except (AttributeError, OSError, ValueError):
        _refuse("cargo_config_invalid")
    if result != 0 or not buffer.value:
        _refuse("cargo_config_invalid")
    root = Path(buffer.value) / "Temp"
    if not root.is_dir():
        _refuse("cargo_config_invalid")
    try:
        _validate_windows_target(root)
    except (Refusal, OSError, ValueError):
        _refuse("cargo_config_invalid")
    return str(root)


def _write_windows_file(stage, relative, content):
    output = stage.joinpath(*relative.split("/"))
    for parent in output.parents:
        if parent == stage.parent:
            break
        if _is_link_or_reparse(parent) or not parent.is_dir():
            _refuse("cargo_archive_invalid")
    descriptor = os.open(
        str(output), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600,
    )
    try:
        view = memoryview(content)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                _refuse("cargo_archive_invalid")
            view = view[written:]
    finally:
        os.close(descriptor)
    os.chmod(output, 0o444)


def _remove_windows_stage(stage, expected_identity):
    if _windows_stage_identity(stage) != expected_identity:
        _refuse("cargo_archive_invalid")

    def remove(directory):
        os.chmod(directory, 0o700)
        for child in directory.iterdir():
            if _is_link_or_reparse(child):
                child.unlink()
            elif child.is_dir():
                remove(child)
            else:
                os.chmod(child, 0o600)
                child.unlink()
        directory.rmdir()

    remove(stage)


def _publish_windows_stage(stage, destination, expected_identity):
    if _windows_stage_identity(stage) != expected_identity:
        _refuse("cargo_archive_invalid")
    if destination.exists() or _is_link_or_reparse(destination):
        _refuse("cargo_archive_invalid")
    os.rename(stage, destination)
    if _windows_stage_identity(destination) != expected_identity:
        _refuse("cargo_archive_invalid")


def _extract_archive_windows(root, entries, file_hashes, package_hash, target_dir):
    target = _validate_windows_target(target_dir)
    stage = None
    stage_identity = None
    try:
        stage = Path(tempfile.mkdtemp(prefix=".cargo-stage-", dir=str(target)))
        stage_identity = _windows_stage_identity(stage)
        directories = set()
        for path, (is_directory, unused_content) in entries.items():
            if path == root:
                continue
            relative = path[len(root) + 1:]
            parts = relative.split("/")
            for count in range(1, len(parts)):
                directories.add("/".join(parts[:count]))
            if is_directory:
                directories.add(relative)
        for directory in sorted(directories, key=lambda value: (value.count("/"), value)):
            output = stage.joinpath(*directory.split("/"))
            if _is_link_or_reparse(output.parent) or not output.parent.is_dir():
                _refuse("cargo_archive_invalid")
            output.mkdir(mode=0o700)
        for path, (is_directory, content) in entries.items():
            if not is_directory and path != root + "/.cargo-checksum.json":
                _write_windows_file(stage, path[len(root) + 1:], content)
        checksum = {"files": dict(sorted(file_hashes.items())), "package": package_hash}
        checksum_bytes = json.dumps(
            checksum, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("ascii")
        _write_windows_file(stage, ".cargo-checksum.json", checksum_bytes)
        for directory in sorted(directories, key=lambda value: (value.count("/"), value), reverse=True):
            os.chmod(stage.joinpath(*directory.split("/")), 0o555)
        os.chmod(stage, 0o555)
        _publish_windows_stage(stage, target / root, stage_identity)
        stage = None
        return target / root
    except Refusal:
        raise
    except (OSError, ValueError, TypeError):
        _refuse("cargo_archive_invalid")
    finally:
        if stage is not None and stage_identity is not None:
            try:
                _remove_windows_stage(stage, stage_identity)
            except (OSError, Refusal):
                pass


def extract_archive(name, version, data, expected_sha256, target_dir):
    """Materialize one verified crate read-only, preserving and hashing Cargo.toml.orig.

    The archived Cargo.toml.orig is never substituted for Cargo.toml. The generated
    vendor checksum manifest covers both files when the original is present. Call
    make_vendor_read_only after adding the last package to freeze the vendor root.
    The target itself is the staging parent and must be a preexisting private
    directory in a trusted preparation job. POSIX ownership and permissions are
    checked along the whole ancestor chain, including root-owned sticky parents.
    macOS ancestors and the private target must also have no extended ACL entries.
    A bounded, trusted symlink above the first private user directory is resolved
    to a physical path; symlinks below that directory are refused. Windows callers
    must isolate the target and its ancestors with runner ACLs. On every platform,
    the job must exclude untrusted processes running as the same user. A same-user
    writer can replace the staging entry between its identity check and rename;
    the post-check refuses, but the replacement can remain published.
    The package root is frozen through its original descriptor after publication.
    """
    root, entries, file_hashes, package_hash = _inspect_archive(name, version, data, expected_sha256)
    if os.name == "nt":
        return _extract_archive_windows(root, entries, file_hashes, package_hash, target_dir)
    parent_fd = None
    stage_name = None
    published_name = None
    stage_created = False
    stage_identity = None
    try:
        parent_fd, target = _open_target_directory(target_dir)
        stage_name = ".cargo-stage-" + secrets.token_hex(16)
        os.mkdir(stage_name, 0o700, dir_fd=parent_fd)
        stage_created = True
        stage_fd = os.open(
            stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=parent_fd,
        )
        stage_identity = _file_identity(os.fstat(stage_fd))
        os.fchmod(stage_fd, 0o700)
        directories = set()
        for path, (is_directory, unused_content) in entries.items():
            if path == root:
                continue
            relative = path[len(root) + 1:]
            parts = relative.split("/")
            for count in range(1, len(parts)):
                directories.add("/".join(parts[:count]))
            if is_directory:
                directories.add(relative)
        for directory in sorted(directories, key=lambda value: (value.count("/"), value)):
            parts = directory.split("/")
            directory_parent = _open_relative_directory(stage_fd, parts[:-1])
            try:
                os.mkdir(parts[-1], 0o700, dir_fd=directory_parent)
            finally:
                os.close(directory_parent)
        for path, (is_directory, content) in entries.items():
            if is_directory or path == root + "/.cargo-checksum.json":
                continue
            _write_stage_file(stage_fd, path[len(root) + 1:], content)
        checksum = {
            "files": dict(sorted(file_hashes.items())),
            "package": package_hash,
        }
        checksum_bytes = json.dumps(
            checksum, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("ascii")
        _write_stage_file(stage_fd, ".cargo-checksum.json", checksum_bytes)
        for directory in sorted(directories, key=lambda value: (value.count("/"), value), reverse=True):
            directory_fd = _open_relative_directory(stage_fd, directory.split("/"))
            try:
                os.fchmod(directory_fd, 0o555)
            finally:
                os.close(directory_fd)
        _publish_stage(parent_fd, stage_name, root, stage_identity)
        stage_name = None
        published_name = root
        os.fchmod(stage_fd, 0o555)
        if _entry_identity(parent_fd, root) != stage_identity:
            _refuse("cargo_archive_invalid")
        os.close(stage_fd)
        stage_fd = None
        published_name = None
        return target / root
    except Refusal:
        raise
    except (OSError, ValueError, TypeError):
        _refuse("cargo_archive_invalid")
    finally:
        if "stage_fd" in locals() and stage_fd is not None:
            os.close(stage_fd)
        if stage_created and stage_name is not None and parent_fd is not None:
            try:
                _remove_stage(parent_fd, stage_name, stage_identity)
            except (OSError, Refusal):
                pass
        if published_name is not None and parent_fd is not None:
            try:
                _remove_stage(parent_fd, published_name, stage_identity)
            except (OSError, Refusal):
                pass
        if parent_fd is not None:
            os.close(parent_fd)


def _vendor_digest_header(digest, relative, is_directory, mode, size):
    name_bytes = relative.encode("ascii")
    digest.update(b"D" if is_directory else b"F")
    digest.update(len(name_bytes).to_bytes(4, "big"))
    digest.update(name_bytes)
    digest.update(stat.S_IMODE(mode).to_bytes(4, "big"))
    digest.update(size.to_bytes(8, "big"))


def vendor_tree_inventory_fd(root_fd, require_read_only=None):
    """Inspect an anchored vendor tree using no-follow descriptor-relative opens."""
    if os.name == "nt" or not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
        _refuse("cargo_archive_invalid")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    items = {}
    folded = set()
    case_spellings = {}
    total = 0
    try:
        if not stat.S_ISDIR(os.fstat(root_fd).st_mode):
            _refuse("cargo_archive_invalid")
        if require_read_only is not None:
            require_read_only(root_fd)

        def collect(directory_fd, prefix):
            nonlocal total
            for name in sorted(os.listdir(directory_fd)):
                relative = prefix + name
                if not _safe_relative_path(relative):
                    _refuse("cargo_archive_invalid")
                folded_path = relative.casefold()
                if folded_path in folded:
                    _refuse("cargo_archive_invalid")
                folded.add(folded_path)
                parts = relative.split("/")
                for count in range(1, len(parts) + 1):
                    spelling = "/".join(parts[:count])
                    folded_prefix = spelling.casefold()
                    previous = case_spellings.get(folded_prefix)
                    if previous is not None and previous != spelling:
                        _refuse("cargo_archive_invalid")
                    case_spellings[folded_prefix] = spelling
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                mode = metadata.st_mode
                if (stat.S_ISLNK(mode) or getattr(metadata, "st_file_attributes", 0)
                        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)):
                    _refuse("cargo_archive_invalid")
                is_directory = stat.S_ISDIR(mode)
                if is_directory:
                    items[relative] = (True, metadata)
                    child_fd = os.open(name, flags, dir_fd=directory_fd)
                    try:
                        child = os.fstat(child_fd)
                        if _file_identity(child) != _file_identity(metadata):
                            _refuse("cargo_archive_invalid")
                        if require_read_only is not None:
                            require_read_only(child_fd)
                        collect(child_fd, relative + "/")
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(mode):
                    if getattr(metadata, "st_nlink", 1) != 1:
                        _refuse("cargo_archive_invalid")
                    total += metadata.st_size
                    if metadata.st_size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                        _refuse("cargo_archive_invalid")
                    items[relative] = (False, metadata)
                else:
                    _refuse("cargo_archive_invalid")
                if len(items) > MAX_ARCHIVE_MEMBERS:
                    _refuse("cargo_archive_invalid")

        collect(root_fd, "")
        digest = hashlib.sha256()
        digest.update(b"cargo-vendor-tree-v1\n")
        file_hashes = {}
        for relative, (is_directory, metadata) in sorted(
                items.items(), key=lambda item: item[0].encode("ascii")):
            _vendor_digest_header(
                digest, relative, is_directory, metadata.st_mode,
                0 if is_directory else metadata.st_size,
            )
            if is_directory:
                continue
            parts = relative.split("/")
            parent_fd = _open_relative_directory(root_fd, parts[:-1])
            try:
                file_fd = os.open(
                    parts[-1], os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0),
                    dir_fd=parent_fd,
                )
                try:
                    opened = os.fstat(file_fd)
                    if (not stat.S_ISREG(opened.st_mode) or opened.st_dev != metadata.st_dev
                            or opened.st_ino != metadata.st_ino
                            or opened.st_size != metadata.st_size
                            or opened.st_mode != metadata.st_mode
                            or getattr(opened, "st_nlink", 1) != 1):
                        _refuse("cargo_archive_invalid")
                    if require_read_only is not None:
                        require_read_only(file_fd)
                    file_digest = hashlib.sha256()
                    size = 0
                    while True:
                        chunk = os.read(file_fd, 1024 * 1024)
                        if not chunk:
                            break
                        size += len(chunk)
                        if size > MAX_FILE_BYTES:
                            _refuse("cargo_archive_invalid")
                        digest.update(chunk)
                        file_digest.update(chunk)
                    after = os.fstat(file_fd)
                    if (size != metadata.st_size or after.st_dev != metadata.st_dev
                            or after.st_ino != metadata.st_ino
                            or after.st_size != metadata.st_size
                            or after.st_mode != metadata.st_mode
                            or after.st_mtime_ns != opened.st_mtime_ns):
                        _refuse("cargo_archive_invalid")
                    file_hashes[relative] = file_digest.hexdigest()
                finally:
                    os.close(file_fd)
            finally:
                os.close(parent_fd)
        return digest.hexdigest(), items, file_hashes
    except Refusal:
        raise
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        _refuse("cargo_archive_invalid")


def vendor_tree_digest(directory):
    """Hash sorted vendor paths, permission modes and file bytes with explicit framing."""
    root = Path(directory)
    if not root.is_dir() or _is_link_or_reparse(root):
        _refuse("cargo_archive_invalid")
    if os.name != "nt":
        if not hasattr(os, "O_NOFOLLOW") or not hasattr(os, "O_DIRECTORY"):
            _refuse("cargo_archive_invalid")
        try:
            descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        except OSError:
            _refuse("cargo_archive_invalid")
        try:
            return vendor_tree_inventory_fd(descriptor)[0]
        finally:
            os.close(descriptor)
    items = []
    seen_folded = set()
    case_spellings = {}
    total = 0
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories.sort()
        files.sort()
        for name in list(directories) + files:
            item = current_path / name
            relative = item.relative_to(root).as_posix()
            if not _safe_relative_path(relative):
                _refuse("cargo_archive_invalid")
            folded = relative.casefold()
            if folded in seen_folded:
                _refuse("cargo_archive_invalid")
            seen_folded.add(folded)
            parts = relative.split("/")
            for index in range(1, len(parts) + 1):
                spelling = "/".join(parts[:index])
                folded_prefix = spelling.casefold()
                previous_spelling = case_spellings.get(folded_prefix)
                if previous_spelling is not None and previous_spelling != spelling:
                    _refuse("cargo_archive_invalid")
                case_spellings[folded_prefix] = spelling
            mode = item.lstat().st_mode
            if stat.S_ISLNK(mode) or getattr(item.lstat(), "st_file_attributes", 0) & getattr(
                    stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
                _refuse("cargo_archive_invalid")
            if stat.S_ISDIR(mode):
                items.append((relative, True, mode))
            elif stat.S_ISREG(mode):
                metadata = item.stat()
                if getattr(metadata, "st_nlink", 1) != 1:
                    _refuse("cargo_archive_invalid")
                size = metadata.st_size
                total += size
                if size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                    _refuse("cargo_archive_invalid")
                items.append((relative, False, mode))
            else:
                _refuse("cargo_archive_invalid")
            if len(items) > MAX_ARCHIVE_MEMBERS:
                _refuse("cargo_archive_invalid")
        directories[:] = [name for name in directories if not _is_link_or_reparse(current_path / name)]
    digest = hashlib.sha256()
    digest.update(b"cargo-vendor-tree-v1\n")
    for relative, is_directory, mode in sorted(items, key=lambda item: item[0].encode("ascii")):
        size = 0 if is_directory else Path(directory, relative).stat().st_size
        _vendor_digest_header(digest, relative, is_directory, mode, size)
        if not is_directory:
            with Path(directory, relative).open("rb") as stream:
                while True:
                    chunk = stream.read(1024 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
    return digest.hexdigest()


def make_vendor_read_only(directory):
    """Normalize a completed vendor tree to read-only modes and return its digest."""
    root = Path(directory)
    vendor_tree_digest(root)
    try:
        files = []
        directories = []
        for current, child_directories, child_files in os.walk(root, followlinks=False):
            current_path = Path(current)
            directories.append(current_path)
            files.extend(current_path / name for name in child_files)
            directories.extend(current_path / name for name in child_directories)
        for item in files:
            os.chmod(item, 0o644)
        for item in directories:
            os.chmod(item, 0o755)
        os.chmod(root, 0o755)
        for item in files:
            os.chmod(item, 0o444)
        for item in sorted(set(directories), key=lambda value: len(value.parts), reverse=True):
            os.chmod(item, 0o555)
        os.chmod(root, 0o555)
    except OSError:
        _refuse("cargo_archive_invalid")
    return vendor_tree_digest(root)


def cargo_config_for_vendor(vendor_dir):
    """Return forced Cargo settings and an isolated toolchain environment.

    Cargo config cannot erase arbitrary keys from an already loaded config tree, cannot
    override manifest-level patch tables, and has no wildcard target-runner setting.
    The source validator must refuse checkout and parent .cargo/config* files and must
    reject manifest patch overrides. The caller must run from a controlled directory
    and launch the directly pinned Cargo binary, never a rustup proxy.
    """
    vendor = Path(vendor_dir)
    if _is_link_or_reparse(vendor):
        _refuse("cargo_config_invalid")
    try:
        vendor_text = str(vendor.resolve(strict=True))
    except (OSError, RuntimeError):
        _refuse("cargo_config_invalid")
    if (not Path(vendor_text).is_dir() or "\x00" in vendor_text
            or "\n" in vendor_text or "\r" in vendor_text):
        _refuse("cargo_config_invalid")
    config_items = (
        ("source.crates-io.replace-with", "\"verified-vendor\""),
        ("source.verified-vendor.directory", json.dumps(vendor_text, ensure_ascii=True)),
        ("net.offline", "true"),
        ("registry.global-credential-providers", "[]"),
        ("patch.crates-io", "{}"),
        ("http.proxy", "\"\""),
        ("http.multiplexing", "false"),
        ("http.timeout", "30"),
        ("target.x86_64-unknown-linux-gnu.runner", "[]"),
        ("target.aarch64-unknown-linux-gnu.runner", "[]"),
        ("target.x86_64-pc-windows-msvc.runner", "[]"),
        ("target.aarch64-pc-windows-msvc.runner", "[]"),
        ("target.x86_64-apple-darwin.runner", "[]"),
        ("target.aarch64-apple-darwin.runner", "[]"),
    )
    arguments = []
    for key, value in config_items:
        arguments.extend(("--config", key + "=" + value))
    environment = {
        key: os.environ[key]
        for key in ("LANG", "LC_ALL", "TZ")
        if key in os.environ
    }
    if os.name == "nt":
        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
        if not length or length >= len(buffer):
            _refuse("cargo_config_invalid")
        environment["PATH"] = buffer.value
        temp_root = _trusted_windows_temp_root()
        environment["TEMP"] = temp_root
        environment["TMP"] = temp_root
    else:
        environment["PATH"] = "/usr/bin:/bin"
        temp_root = "/tmp"
    environment["TMPDIR"] = temp_root
    created = []
    try:
        for key, prefix in (("HOME", "cargo-user-"), ("CARGO_HOME", "cargo-home-"),
                            ("RUSTUP_HOME", "rustup-home-")):
            directory = tempfile.mkdtemp(prefix=prefix, dir=temp_root)
            created.append(directory)
            os.chmod(directory, 0o700)
            environment[key] = directory
    except OSError:
        for directory in created:
            try:
                os.rmdir(directory)
            except OSError:
                pass
        _refuse("cargo_config_invalid")
    return arguments, environment
