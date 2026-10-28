"""Fail-closed canary scanning for retained release evidence."""

import hashlib
import os
import re
import stat
from dataclasses import dataclass, field

try:
    from . import confinement_public_audit, log_canary
except ImportError:
    import confinement_public_audit
    import log_canary


SCHEMA_VERSION = 1
MAX_EVIDENCE_ITEMS = confinement_public_audit.MAX_ARTIFACTS
MAX_LOG_BYTES = confinement_public_audit.MAX_LOG_BYTES
MAX_ARTIFACT_BYTES = log_canary.MAX_TOTAL_BYTES
MAX_EVIDENCE_TOTAL_BYTES = log_canary.MAX_TOTAL_BYTES
MAX_TREE_NODES = MAX_EVIDENCE_ITEMS * 4
MAX_PATH_DEPTH = 16
READ_CHUNK_BYTES = log_canary.SLICE_BYTES
ROLES = frozenset(("log", "artifact"))
MANIFEST_FIELDS = frozenset(("schema_version", "items"))
ITEM_FIELDS = frozenset(("path", "role", "size", "sha256"))
PATH_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/_-]{0,511}\Z")
SHA256_RE = re.compile(r"[a-f0-9]{64}\Z")
REFUSAL_REASONS = frozenset((
    "manifest_invalid", "tree_invalid", "tree_unreadable", "file_unlisted",
    "file_missing", "file_unreadable", "file_not_regular", "file_over_limit",
    "file_size_mismatch", "file_digest_mismatch", "file_changed", "canary_present",
    "canary_unscanned", "canary_config_invalid", "compressed_unsupported",
    "log_profile_unpinned", "log_profile_invalid", "tree_changed", "internal_error",
))
COMPRESSED_SUFFIXES = (
    ".gz", ".gzip", ".zip", ".tgz", ".tar", ".bz2", ".xz", ".zst", ".lz4",
    ".br", ".7z", ".rar",
)
COMPRESSED_SIGNATURES = (
    b"\x1f\x8b", b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"BZh",
    b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd", b"\x04\x22\x4d\x18",
    b"\x1f\x9d", b"\x1f\xa0", b"7z\xbc\xaf\x27\x1c",
    b"Rar!\x1a\x07\x00", b"Rar!\x1a\x07\x01\x00", b"MSCF", b"!<arch>\n",
    b"xar!", b"\x02\x21\x4c\x18",
)
CONTAINER_HEADER_BYTES = 512
TAR_SIGNATURE_OFFSET = 257
TAR_SIGNATURES = (b"ustar\x00", b"ustar  ")
MAX_LOG_LINE_BYTES = 512
MAX_LOG_PROFILE_LINES = 1000
PINNED_PLAIN_LOG_LINES = None
OPEN_QUESTIONS = (
    "No plain-log producer profile or bounded artifact extraction profile is admitted by default. "
    "Each requires a separately reviewed and pinned admission before its verdict can pass.",
)


class EvidenceRefusal(Exception):
    def __init__(self, reason):
        self.reason = (
            reason if type(reason) is str and reason in REFUSAL_REASONS else "internal_error"
        )
        super().__init__(self.reason)


@dataclass(frozen=True)
class EvidenceItem:
    path: str
    role: str
    size: int
    sha256: str


@dataclass(frozen=True)
class EvidenceManifest:
    schema_version: int
    items: tuple


@dataclass(frozen=True)
class EvidenceSnapshot:
    path: str
    size: int
    sha256: str
    chunks: tuple = field(repr=False)


@dataclass(frozen=True)
class EvidenceVerdict:
    accepted: bool
    reason: str
    files_scanned: int
    bytes_scanned: int
    snapshots: tuple = field(default=(), repr=False)


def manifest_from_mapping(value):
    """Build the closed evidence manifest model from decoded JSON data."""
    if type(value) is not dict or set(value) != MANIFEST_FIELDS:
        raise EvidenceRefusal("manifest_invalid")
    if type(value["schema_version"]) is not int or value["schema_version"] != SCHEMA_VERSION:
        raise EvidenceRefusal("manifest_invalid")
    raw_items = value["items"]
    if type(raw_items) is not list or not raw_items:
        raise EvidenceRefusal("manifest_invalid")
    items = []
    for raw_item in raw_items:
        if type(raw_item) is not dict or set(raw_item) != ITEM_FIELDS:
            raise EvidenceRefusal("manifest_invalid")
        items.append(EvidenceItem(
            raw_item["path"], raw_item["role"], raw_item["size"], raw_item["sha256"]
        ))
    manifest = EvidenceManifest(value["schema_version"], tuple(items))
    _validate_manifest(manifest)
    return manifest


def _valid_path(value):
    if type(value) is not str or PATH_RE.fullmatch(value) is None:
        return False
    if "\\" in value or value.endswith("/") or "//" in value:
        return False
    parts = value.split("/")
    return all(part not in ("", ".", "..") for part in parts)


def _validate_manifest(manifest):
    if (type(manifest) is not EvidenceManifest
            or type(manifest.schema_version) is not int
            or manifest.schema_version != SCHEMA_VERSION):
        raise EvidenceRefusal("manifest_invalid")
    if type(manifest.items) is not tuple or not manifest.items:
        raise EvidenceRefusal("manifest_invalid")
    if len(manifest.items) > MAX_EVIDENCE_ITEMS:
        raise EvidenceRefusal("manifest_invalid")
    seen = set()
    total_size = 0
    for item in manifest.items:
        if type(item) is not EvidenceItem:
            raise EvidenceRefusal("manifest_invalid")
        if (not _valid_path(item.path) or type(item.role) is not str or item.role not in ROLES
                or type(item.size) is not int or item.size <= 0
                or type(item.sha256) is not str or SHA256_RE.fullmatch(item.sha256) is None):
            raise EvidenceRefusal("manifest_invalid")
        if item.path in seen:
            raise EvidenceRefusal("manifest_invalid")
        seen.add(item.path)
        item_limit = MAX_LOG_BYTES if item.role == "log" else MAX_ARTIFACT_BYTES
        if item.size > item_limit:
            raise EvidenceRefusal("file_over_limit")
        total_size += item.size
        if total_size > MAX_EVIDENCE_TOTAL_BYTES:
            raise EvidenceRefusal("file_over_limit")
        if item.path.lower().endswith(COMPRESSED_SUFFIXES):
            raise EvidenceRefusal("compressed_unsupported")
    return total_size


def _expected_directories(items):
    directories = set()
    for item in items:
        parts = item.path.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            directories.add("/".join(parts[:index]))
    return directories


def _is_link(metadata):
    attributes = getattr(metadata, "st_file_attributes", 0)
    reparse = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(metadata.st_mode) or bool(reparse and attributes & reparse)


def _anchor_root(root):
    raw_path = os.fspath(root)
    if type(raw_path) is not str or not raw_path:
        raise EvidenceRefusal("tree_invalid")
    components = raw_path.replace(os.altsep, os.sep) if os.altsep else raw_path
    if any(part in (".", "..") for part in components.split(os.sep)):
        raise EvidenceRefusal("tree_invalid")
    path = os.path.normpath(raw_path)
    try:
        metadata = os.lstat(path)
        if _is_link(metadata) or not stat.S_ISDIR(metadata.st_mode):
            raise EvidenceRefusal("tree_invalid")
        if os.name != "posix":
            return path, None, metadata
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if _file_identity(opened) != _file_identity(metadata):
                raise EvidenceRefusal("tree_changed")
        except Exception:
            os.close(descriptor)
            raise
        return path, descriptor, metadata
    except EvidenceRefusal:
        raise
    except OSError:
        raise EvidenceRefusal("tree_unreadable") from None


def _inventory(root, root_descriptor):
    files = {}
    directories = {}
    nodes = [0]

    def visit(directory, prefix, depth):
        if depth > MAX_PATH_DEPTH:
            raise EvidenceRefusal("tree_invalid")
        try:
            entries = os.scandir(directory)
        except OSError:
            raise EvidenceRefusal("tree_unreadable") from None
        try:
            with entries:
                for entry in entries:
                    relative = entry.name if not prefix else prefix + "/" + entry.name
                    if not _valid_path(relative):
                        raise EvidenceRefusal("tree_invalid")
                    nodes[0] += 1
                    if nodes[0] > MAX_TREE_NODES:
                        raise EvidenceRefusal("tree_invalid")
                    try:
                        metadata = entry.stat(follow_symlinks=False)
                        if _is_link(metadata):
                            raise EvidenceRefusal("tree_invalid")
                    except EvidenceRefusal:
                        raise
                    except OSError:
                        raise EvidenceRefusal("tree_unreadable") from None
                    if stat.S_ISDIR(metadata.st_mode):
                        directories[relative] = metadata
                        if root_descriptor is None:
                            visit(entry.path, relative, depth + 1)
                        else:
                            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                            try:
                                child = os.open(entry.name, flags, dir_fd=directory)
                                try:
                                    changed = (_file_identity(os.fstat(child))
                                               != _file_identity(metadata))
                                except Exception:
                                    os.close(child)
                                    raise
                                if changed:
                                    os.close(child)
                                    raise EvidenceRefusal("tree_changed")
                            except EvidenceRefusal:
                                raise
                            except OSError:
                                raise EvidenceRefusal("tree_unreadable") from None
                            try:
                                visit(child, relative, depth + 1)
                            finally:
                                os.close(child)
                    elif stat.S_ISREG(metadata.st_mode):
                        files[relative] = metadata
                    else:
                        raise EvidenceRefusal("file_not_regular")
        except OSError:
            raise EvidenceRefusal("tree_unreadable") from None
    visit(root_descriptor if root_descriptor is not None else root, "", 0)
    return files, directories


def _preflight(root, root_descriptor, manifest):
    total_size = _validate_manifest(manifest)
    files, directories = _inventory(root, root_descriptor)
    expected = {item.path for item in manifest.items}
    if set(files) - expected:
        raise EvidenceRefusal("file_unlisted")
    if expected - set(files):
        raise EvidenceRefusal("file_missing")
    if set(directories) != _expected_directories(manifest.items):
        raise EvidenceRefusal("file_unlisted")
    for item in manifest.items:
        if files[item.path].st_size != item.size:
            raise EvidenceRefusal("file_size_mismatch")
        item_limit = MAX_LOG_BYTES if item.role == "log" else MAX_ARTIFACT_BYTES
        if files[item.path].st_size > item_limit:
            raise EvidenceRefusal("file_over_limit")
    if total_size > MAX_EVIDENCE_TOTAL_BYTES:
        raise EvidenceRefusal("file_over_limit")
    return files, directories, total_size


def _compressed_prefix(data):
    """No bounded extractor is admitted, so recognized containers are refused."""
    return (
        any(data.startswith(signature) for signature in COMPRESSED_SIGNATURES)
        or (len(data) >= 4 and data[1:4] == b"\x2a\x4d\x18"
            and 0x50 <= data[0] <= 0x5f)
        or any(
            data[TAR_SIGNATURE_OFFSET:].startswith(signature)
            for signature in TAR_SIGNATURES
        )
    )


def _resolve_plain_log_profile():
    lines = PINNED_PLAIN_LOG_LINES
    if lines is None:
        raise EvidenceRefusal("log_profile_unpinned")
    if type(lines) is not tuple or not 0 < len(lines) <= MAX_LOG_PROFILE_LINES:
        raise EvidenceRefusal("log_profile_invalid")
    for line in lines:
        if (type(line) is not bytes or not 0 < len(line) <= MAX_LOG_LINE_BYTES
                or any(byte < 32 or byte > 126 for byte in line)):
            raise EvidenceRefusal("log_profile_invalid")
    if len(set(lines)) != len(lines):
        raise EvidenceRefusal("log_profile_invalid")
    return frozenset(lines)


def _check_plain_log(chunks, profile):
    carry = b""
    for chunk in chunks:
        if any(byte != 10 and (byte < 32 or byte > 126) for byte in chunk):
            raise EvidenceRefusal("log_profile_invalid")
        parts = (carry + chunk).split(b"\n")
        if any(line not in profile for line in parts[:-1]):
            raise EvidenceRefusal("log_profile_invalid")
        carry = parts[-1]
        if len(carry) > MAX_LOG_LINE_BYTES:
            raise EvidenceRefusal("log_profile_invalid")
    if carry:
        raise EvidenceRefusal("log_profile_invalid")


def _file_identity(metadata):
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_size,
        metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _open_evidence_file(root, root_descriptor, item):
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    if os.name == "posix":
        flags |= os.O_NONBLOCK
    if root_descriptor is None:
        path = os.path.join(root, *item.path.split("/"))
        metadata = os.lstat(path)
        if _is_link(metadata) or not stat.S_ISREG(metadata.st_mode):
            raise EvidenceRefusal("file_not_regular")
        return os.open(path, flags)
    parent = root_descriptor
    opened_directories = []
    try:
        parts = item.path.split("/")
        for part in parts[:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent)
            opened_directories.append(child)
            parent = child
        return os.open(parts[-1], flags, dir_fd=parent)
    finally:
        for directory in reversed(opened_directories):
            os.close(directory)


def _scan_file(root, root_descriptor, item, expected_metadata, config):
    try:
        descriptor = _open_evidence_file(root, root_descriptor, item)
    except EvidenceRefusal:
        raise
    except OSError:
        raise EvidenceRefusal("file_unreadable") from None
    try:
        try:
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode):
                raise EvidenceRefusal("file_not_regular")
            if _file_identity(before) != _file_identity(expected_metadata):
                raise EvidenceRefusal("file_changed")
            digest = hashlib.sha256()
            total = 0
            prefix = b""
            chunks = []
            stream = os.fdopen(descriptor, "rb", closefd=False)
            try:
                while True:
                    remaining = item.size - total
                    chunk = stream.read(min(READ_CHUNK_BYTES, remaining + 1))
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > item.size:
                        raise EvidenceRefusal("file_size_mismatch")
                    if len(prefix) < CONTAINER_HEADER_BYTES:
                        prefix += chunk[:CONTAINER_HEADER_BYTES - len(prefix)]
                    if _compressed_prefix(prefix):
                        raise EvidenceRefusal("compressed_unsupported")
                    chunks.append(chunk)
                    digest.update(chunk)
            finally:
                stream.close()
            after = os.fstat(descriptor)
            if total != item.size or after.st_size != item.size:
                raise EvidenceRefusal("file_size_mismatch")
            if _file_identity(before) != _file_identity(after):
                raise EvidenceRefusal("file_changed")
            if digest.hexdigest() != item.sha256:
                raise EvidenceRefusal("file_digest_mismatch")
            scanner = log_canary.Scanner(config)
            for chunk in chunks:
                scanner.feed(chunk)
            scanner.finish()
            if scanner.result() != log_canary.ABSENT:
                raise EvidenceRefusal("canary_present")
            return total, tuple(chunks)
        except EvidenceRefusal:
            raise
        except log_canary.ScanRefusal as error:
            if error.reason == "config_unpinned" or error.reason == "config_invalid":
                raise EvidenceRefusal("canary_config_invalid") from None
            raise EvidenceRefusal("canary_unscanned") from None
        except OSError:
            raise EvidenceRefusal("file_unreadable") from None
    finally:
        os.close(descriptor)


def _verify_snapshot_source(root, root_descriptor, item, expected_metadata, digest):
    try:
        descriptor = _open_evidence_file(root, root_descriptor, item)
    except EvidenceRefusal:
        raise
    except OSError:
        raise EvidenceRefusal("file_unreadable") from None
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise EvidenceRefusal("file_not_regular")
        if _file_identity(before) != _file_identity(expected_metadata):
            raise EvidenceRefusal("tree_changed")
        check = hashlib.sha256()
        total = 0
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            while True:
                chunk = stream.read(READ_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > item.size:
                    raise EvidenceRefusal("tree_changed")
                check.update(chunk)
        after = os.fstat(descriptor)
        if (total != item.size or _file_identity(after) != _file_identity(before)
                or check.digest() != digest):
            raise EvidenceRefusal("tree_changed")
    except EvidenceRefusal:
        raise
    except OSError:
        raise EvidenceRefusal("file_unreadable") from None
    finally:
        os.close(descriptor)


def _resolve_config():
    try:
        resolved = log_canary.pinned_config()
        log_canary.Scanner(resolved)
        return resolved
    except log_canary.ScanRefusal as error:
        if error.reason == "config_unpinned" or error.reason == "config_invalid":
            raise EvidenceRefusal("canary_config_invalid") from None
        raise EvidenceRefusal("canary_unscanned") from None


def scan_evidence(root, manifest):
    """Scan bounded immutable byte snapshots and reject a changed source tree."""
    scanned = 0
    bytes_scanned = 0
    root_descriptor = None
    try:
        _validate_manifest(manifest)
        root_path, root_descriptor, root_metadata = _anchor_root(root)
        files, directories, expected_total = _preflight(root_path, root_descriptor, manifest)
        config = _resolve_config()
        snapshots = []
        ordered_items = sorted(manifest.items, key=lambda value: value.path)
        plain_log_profile = (
            _resolve_plain_log_profile()
            if any(item.role == "log" for item in ordered_items) else None
        )
        for item in ordered_items:
            count, snapshot = _scan_file(
                root_path, root_descriptor, item, files[item.path], config
            )
            snapshots.append(EvidenceSnapshot(item.path, count, item.sha256, snapshot))
            bytes_scanned += count
            scanned += 1
            if item.role == "log":
                _check_plain_log(snapshot, plain_log_profile)
        for item, snapshot in zip(ordered_items, snapshots):
            _verify_snapshot_source(
                root_path, root_descriptor, item, files[item.path],
                bytes.fromhex(snapshot.sha256)
            )
        final_files, final_directories = _inventory(root_path, root_descriptor)
        final_root = os.lstat(root_path)
        if (_is_link(final_root)
                or _file_identity(final_root) != _file_identity(root_metadata)
                or set(final_files) != set(files)
                or set(final_directories) != _expected_directories(manifest.items)
                or any(
                    _file_identity(final_directories[path]) != _file_identity(directories[path])
                    for path in directories if path in final_directories
                )
                or any(
                    _file_identity(final_files[path]) != _file_identity(files[path])
                    for path in files
                )):
            raise EvidenceRefusal("tree_changed")
        if bytes_scanned != expected_total:
            raise EvidenceRefusal("file_size_mismatch")
        if any(item.role == "artifact" for item in ordered_items):
            raise EvidenceRefusal("compressed_unsupported")
        return EvidenceVerdict(True, "none", scanned, bytes_scanned, tuple(snapshots))
    except EvidenceRefusal as error:
        return EvidenceVerdict(False, error.reason, scanned, bytes_scanned)
    except Exception:
        return EvidenceVerdict(False, "internal_error", scanned, bytes_scanned)
    finally:
        if root_descriptor is not None:
            os.close(root_descriptor)
