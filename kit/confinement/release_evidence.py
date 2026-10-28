"""Fail-closed canary scanning for retained release evidence."""

import hashlib
import os
import re
import stat
from dataclasses import dataclass

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
    "tree_changed", "internal_error",
))
COMPRESSED_SUFFIXES = (
    ".gz", ".gzip", ".zip", ".tgz", ".tar", ".bz2", ".xz", ".zst", ".lz4",
    ".br", ".7z", ".rar",
)
COMPRESSED_SIGNATURES = (
    b"\x1f\x8b", b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08", b"BZh",
    b"\xfd7zXZ\x00", b"\x28\xb5\x2f\xfd", b"\x04\x22\x4d\x18",
    b"\x1f\x9d", b"\x1f\xa0",
)
OPEN_QUESTIONS = (
    "Container formats and internally compressed binary sections need an admitted extraction "
    "profile before a scan can claim coverage of their uncompressed contents.",
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
class EvidenceVerdict:
    accepted: bool
    reason: str
    files_scanned: int
    bytes_scanned: int


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


def _inventory(root):
    files = {}
    directories = set()
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
                        if entry.is_symlink():
                            raise EvidenceRefusal("tree_invalid")
                    except EvidenceRefusal:
                        raise
                    except OSError:
                        raise EvidenceRefusal("tree_unreadable") from None
                    if stat.S_ISDIR(metadata.st_mode):
                        directories.add(relative)
                        visit(entry.path, relative, depth + 1)
                    elif stat.S_ISREG(metadata.st_mode):
                        files[relative] = metadata
                    else:
                        raise EvidenceRefusal("file_not_regular")
        except OSError:
            raise EvidenceRefusal("tree_unreadable") from None
    try:
        root_metadata = os.lstat(root)
    except OSError:
        raise EvidenceRefusal("tree_unreadable") from None
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise EvidenceRefusal("tree_invalid")
    visit(root, "", 0)
    return files, directories


def _preflight(root, manifest):
    total_size = _validate_manifest(manifest)
    files, directories = _inventory(root)
    expected = {item.path for item in manifest.items}
    if set(files) - expected:
        raise EvidenceRefusal("file_unlisted")
    if expected - set(files):
        raise EvidenceRefusal("file_missing")
    if directories != _expected_directories(manifest.items):
        raise EvidenceRefusal("file_unlisted")
    for item in manifest.items:
        if files[item.path].st_size != item.size:
            raise EvidenceRefusal("file_size_mismatch")
        item_limit = MAX_LOG_BYTES if item.role == "log" else MAX_ARTIFACT_BYTES
        if files[item.path].st_size > item_limit:
            raise EvidenceRefusal("file_over_limit")
    if total_size > MAX_EVIDENCE_TOTAL_BYTES:
        raise EvidenceRefusal("file_over_limit")
    return files, total_size


def _compressed_prefix(data):
    return any(data.startswith(signature) for signature in COMPRESSED_SIGNATURES)


def _file_identity(metadata):
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_size,
        getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1000000000)),
    )


def _scan_file(root, item, expected_metadata, config):
    path = os.path.join(root, *item.path.split("/"))
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        path_metadata = os.lstat(path)
        if not stat.S_ISREG(path_metadata.st_mode):
            raise EvidenceRefusal("file_not_regular")
        if _file_identity(path_metadata) != _file_identity(expected_metadata):
            raise EvidenceRefusal("file_changed")
        descriptor = os.open(path, flags)
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
            scanner = log_canary.Scanner(config)
            total = 0
            prefix = b""
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
                    if len(prefix) < 8:
                        prefix += chunk[:8 - len(prefix)]
                    if _compressed_prefix(prefix):
                        raise EvidenceRefusal("compressed_unsupported")
                    digest.update(chunk)
                    scanner.feed(chunk)
                scanner.finish()
            finally:
                stream.close()
            after = os.fstat(descriptor)
            if total != item.size or after.st_size != item.size:
                raise EvidenceRefusal("file_size_mismatch")
            if _file_identity(before) != _file_identity(after):
                raise EvidenceRefusal("file_changed")
            if digest.hexdigest() != item.sha256:
                raise EvidenceRefusal("file_digest_mismatch")
            if scanner.result() != log_canary.ABSENT:
                raise EvidenceRefusal("canary_present")
            return total
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
    """Return accepted only after every listed regular file is fully read and checked."""
    scanned = 0
    bytes_scanned = 0
    try:
        files, expected_total = _preflight(os.fspath(root), manifest)
        config = _resolve_config()
        for item in sorted(manifest.items, key=lambda value: value.path):
            bytes_scanned += _scan_file(root, item, files[item.path], config)
            scanned += 1
        final_files, final_directories = _inventory(os.fspath(root))
        if (set(final_files) != set(files)
                or final_directories != _expected_directories(manifest.items)
                or any(
                    _file_identity(final_files[path]) != _file_identity(files[path])
                    for path in files
                )):
            raise EvidenceRefusal("tree_changed")
        if bytes_scanned != expected_total:
            raise EvidenceRefusal("file_size_mismatch")
        return EvidenceVerdict(True, "none", scanned, bytes_scanned)
    except EvidenceRefusal as error:
        return EvidenceVerdict(False, error.reason, scanned, bytes_scanned)
    except Exception:
        return EvidenceVerdict(False, "internal_error", scanned, bytes_scanned)
