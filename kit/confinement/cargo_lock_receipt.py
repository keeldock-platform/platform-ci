"""Bounded Cargo lock receipts and verified, source-free crate materialization."""

import gzip
import hashlib
import hmac
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
import tempfile


REGISTRY_SOURCE = (
    "registry+https:" + chr(47) * 2 + "github.com" + chr(47)
    + "rust-lang" + chr(47) + "crates.io-index"
)
SCHEMA_VERSION = 1
MAX_LOCK_BYTES = 4 * 1024 * 1024
MAX_RECEIPT_BYTES = 2 * 1024 * 1024
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_TAR_BYTES = 256 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 20_000
MAX_COMPRESSION_RATIO = 200
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
    r"(?: (?P<version>(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?))?"
    r"(?: \((?P<source>[^()]*)\))?\Z"
)
LOCK_FIELDS = frozenset(("name", "version", "source", "checksum", "dependencies"))
RECEIPT_FIELDS = frozenset((
    "schema_version", "repository", "workspace_path", "source_sha", "base_sha",
    "base_branch", "reviewed_diff_fingerprint", "dependency_policy_revision",
    "control_sha", "toolchain_hash", "lock_sha256", "packages",
))
PACKAGE_RECEIPT_FIELDS = frozenset(("name", "version", "checksum", "audit_record_id"))
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
        and type(version) is str and len(version) <= 128
        and VERSION_RE.fullmatch(version) is not None
    )


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


def _array_complete(value):
    quoted = False
    escaped = False
    depth = 0
    for character in value:
        if escaped:
            escaped = False
        elif quoted and character == "\\":
            escaped = True
        elif character == '"':
            quoted = not quoted
        elif not quoted and character == "[":
            depth += 1
        elif not quoted and character == "]":
            depth -= 1
            if depth == 0:
                return True
            if depth < 0:
                _refuse("cargo_lock_invalid")
    return False


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
    if source == REGISTRY_SOURCE and name.lower().startswith("keeldock" + "-"):
        _refuse("cargo_lock_invalid")
    if version is not None and not _valid_package_identity(name, version):
        _refuse("cargo_lock_invalid")
    if source is not None and source != REGISTRY_SOURCE:
        _refuse("cargo_lock_invalid")
    if source is not None and version is None:
        _refuse("cargo_lock_invalid")
    return name, version, source


def parse_cargo_lock(lock_bytes):
    """Parse the supported v3/v4 Cargo.lock subset without a general TOML parser."""
    text = _decode_ascii(lock_bytes, MAX_LOCK_BYTES, "cargo_lock_invalid")
    if text.startswith("\ufeff"):
        _refuse("cargo_lock_invalid")
    packages = []
    current = None
    lock_version = None
    lines = iter(text.splitlines())
    for raw_line in lines:
        line = _strip_toml_comment(raw_line).strip()
        if not line:
            continue
        if line == "[[package]]":
            if current is not None:
                packages.append(current)
            current = {"dependencies": []}
            continue
        if "=" not in line:
            _refuse("cargo_lock_invalid")
        key, raw_value = line.split("=", 1)
        key = key.strip()
        if re.fullmatch(r"[a-z][a-z0-9_-]{0,63}", key) is None:
            _refuse("cargo_lock_invalid")
        raw_value = raw_value.strip()
        if key == "dependencies" and raw_value.startswith("[") and not _array_complete(raw_value):
            fragments = [raw_value]
            while not _array_complete(" ".join(fragments)):
                try:
                    continuation = _strip_toml_comment(next(lines)).strip()
                except StopIteration:
                    _refuse("cargo_lock_invalid")
                if continuation:
                    fragments.append(continuation)
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
        elif source == REGISTRY_SOURCE:
            if name.lower().startswith("keeldock" + "-") or not _valid_hex(checksum, HEX64_RE):
                _refuse("cargo_lock_invalid")
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
    for package in packages:
        by_name.setdefault(package["name"], []).append(package)
    for package in packages:
        for dependency_name, dependency_version, dependency_source in package["dependencies"]:
            candidates = by_name.get(dependency_name, [])
            if dependency_version is not None:
                candidates = [item for item in candidates if item["version"] == dependency_version]
            if dependency_source is not None:
                candidates = [item for item in candidates if item.get("source") == dependency_source]
            if len(candidates) != 1:
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
                or item["name"].lower().startswith("keeldock" + "-")
                or not _valid_hex(item["checksum"], HEX64_RE)
                or type(item["audit_record_id"]) is not str
                or AUDIT_ID_RE.fullmatch(item["audit_record_id"]) is None):
            _refuse("cargo_receipt_invalid")
        identity = (item["name"], item["version"])
        if identity in seen or (previous is not None and identity <= previous):
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


def verify_lock_against_receipt(lock_bytes, receipt):
    """Verify exact lock bytes and audit mappings before any caller performs network use."""
    if type(receipt) is bytes:
        receipt = decode_receipt(receipt)
    else:
        _validate_receipt(receipt)
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
    if not _valid_package_identity(name, version) or name.lower().startswith("keeldock" + "-"):
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
    if type(data) is not bytes or not 1 <= len(data) <= MAX_ARCHIVE_BYTES:
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
                if ((is_directory and not raw_name.endswith("/"))
                        or (not is_directory and raw_name.endswith("/"))
                        or (is_directory and raw_name.endswith("//"))):
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
    except (tarfile.TarError, OSError, UnicodeError, ValueError, EOFError):
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


def extract_archive(name, version, data, expected_sha256, target_dir):
    """Materialize one verified crate read-only, preserving and hashing Cargo.toml.orig.

    The archived Cargo.toml.orig is never substituted for Cargo.toml. The generated
    vendor checksum manifest covers both files when the original is present. Call
    make_vendor_read_only after adding the last package to freeze the vendor root.
    """
    root, entries, file_hashes, package_hash = _inspect_archive(
        name, version, data, expected_sha256,
    )
    try:
        target = Path(target_dir)
        if target.exists() and (_is_link_or_reparse(target) or not target.is_dir()):
            _refuse("cargo_archive_invalid")
        target.mkdir(parents=True, exist_ok=True, mode=0o755)
        if _is_link_or_reparse(target):
            _refuse("cargo_archive_invalid")
        package_root = target / root
        if package_root.exists() or _is_link_or_reparse(package_root):
            _refuse("cargo_archive_invalid")
        package_root.mkdir(mode=0o755)
        os.chmod(package_root, 0o755)
        directories = {root}
        for path, (is_directory, unused_content) in entries.items():
            parts = path.split("/")
            for count in range(1, len(parts)):
                directories.add("/".join(parts[:count]))
            if is_directory:
                directories.add(path)
        for directory in sorted(directories, key=lambda value: (value.count("/"), value)):
            output = target.joinpath(*directory.split("/"))
            if output == package_root:
                continue
            output.mkdir(mode=0o755, exist_ok=True)
            if _is_link_or_reparse(output) or not output.is_dir():
                _refuse("cargo_archive_invalid")
            os.chmod(output, 0o755)
        for path, (is_directory, content) in entries.items():
            if is_directory or path == root + "/.cargo-checksum.json":
                continue
            output = target.joinpath(*path.split("/"))
            with output.open("xb") as stream:
                stream.write(content)
            os.chmod(output, 0o644)
        checksum = {
            "files": dict(sorted(file_hashes.items())),
            "package": package_hash,
        }
        checksum_bytes = json.dumps(
            checksum, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("ascii")
        checksum_output = package_root / ".cargo-checksum.json"
        with checksum_output.open("xb") as stream:
            stream.write(checksum_bytes)
        os.chmod(checksum_output, 0o644)
        for path, (is_directory, unused_content) in entries.items():
            if is_directory:
                os.chmod(target.joinpath(*path.split("/")), 0o755)
        for path, (is_directory, unused_content) in entries.items():
            if not is_directory and path != root + "/.cargo-checksum.json":
                os.chmod(target.joinpath(*path.split("/")), 0o444)
        os.chmod(checksum_output, 0o444)
        for directory in sorted(directories, key=lambda value: (value.count("/"), value), reverse=True):
            os.chmod(target.joinpath(*directory.split("/")), 0o555)
    except Refusal:
        raise
    except (OSError, ValueError, TypeError):
        _refuse("cargo_archive_invalid")
    return package_root


def vendor_tree_digest(directory):
    """Hash sorted vendor paths, permission modes and file bytes with explicit framing."""
    root = Path(directory)
    if not root.is_dir() or _is_link_or_reparse(root):
        _refuse("cargo_archive_invalid")
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
        name_bytes = relative.encode("ascii")
        digest.update(b"D" if is_directory else b"F")
        digest.update(len(name_bytes).to_bytes(4, "big"))
        digest.update(name_bytes)
        digest.update(stat.S_IMODE(mode).to_bytes(4, "big"))
        if is_directory:
            digest.update((0).to_bytes(8, "big"))
        else:
            size = Path(directory, relative).stat().st_size
            digest.update(size.to_bytes(8, "big"))
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
    """Return forced Cargo CLI settings and a sanitized environment with fresh CARGO_HOME.

    Cargo config cannot erase arbitrary keys from an already loaded config tree, cannot
    override manifest-level patch tables, and has no wildcard target-runner setting.
    The source validator must refuse checkout and parent .cargo/config* files and must
    reject manifest patch overrides. The caller must run from a controlled directory.
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
        key: value for key, value in os.environ.items()
        if (not key.startswith("CARGO_") and not key.startswith("RUSTC")
            and "proxy" not in key.lower())
    }
    try:
        fresh_cargo_home = tempfile.mkdtemp(prefix="cargo-home-")
        os.chmod(fresh_cargo_home, 0o700)
    except OSError:
        _refuse("cargo_config_invalid")
    environment["CARGO_HOME"] = fresh_cargo_home
    return arguments, environment
