"""Bounded offline registry cache contract for the baseline and candidate constraints.

The contract stays inside the encrypted run. Its public code contains no source-derived
dependency inventory. A caller must pass bindings from the authenticated decrypted
manifest and independently verified control/source context; this module never trusts the
cache document to establish its own identity.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import tomllib
from pathlib import Path, PurePosixPath
from typing import Any

import bounded_registry_io
import constraint_resolver
import registry_prefetch


SCHEMA = "keeldock.semver-offline-cache.v4"
REQUIRED_SCOPES = (
    "baseline-runtime",
    "candidate-root",
    "candidate-runtime",
    "candidate-fuzz",
)
TEMPORARY_PROJECT_OPERATIONS = {
    "local": ["before-update", "after-update", "after-metadata", "after-doc"],
    "registry": ["before-metadata", "after-metadata", "after-doc"],
}
MAX_CONTRACT_BYTES = 4 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_REGISTRY_FILE_BYTES = 256 * 1024 * 1024
MAX_FILES = 250_000
MAX_TREE_BYTES = 8 * 1024 * 1024 * 1024
MAX_SOURCE_FILE_BYTES = 32 * 1024 * 1024
MAX_SOURCE_TREE_BYTES = 512 * 1024 * 1024
MAX_SOURCE_TREE_ENTRIES = 250_000
CHUNK = 1024 * 1024
SMALL_READ_SECONDS = 5.0
TOOL_VERSION_COMMANDS = {
    "cargo": ("--version", "--verbose", b"cargo 1.99.1 ",
              b"host: x86_64-unknown-linux-gnu"),
    "rustc": ("-vV", b"rustc 1.99.1 ",
              b"host: x86_64-unknown-linux-gnu"),
}
INPUT_KEYS = frozenset((
    "source_commit", "control_sha", "manifest_projection_sha256",
    "baseline_source_map_sha256", "candidate_source_map_sha256",
    "candidate_full_source_map_sha256", "candidate_root_manifest_sha256",
    "candidate_fuzz_manifest_sha256",
    "baseline_runtime_manifest_sha256", "candidate_runtime_manifest_sha256",
    "baseline_runtime_version", "candidate_runtime_version",
    "semver_tool_binary_sha256",
))
SHA256_FIELDS = frozenset(INPUT_KEYS - {
    "source_commit", "control_sha", "baseline_runtime_version", "candidate_runtime_version",
})
HEX = frozenset("0123456789abcdef")
BASELINE_ROOT = "semver-baseline/runtime"
REGISTRY_ROOT = "cargo-local-registry"
CONTRACT_NAME = "semver-offline-contract.json"
CARGO_CONFIG = (
    b'[source.crates-io]\nreplace-with = "prepared-registry"\n'
    b'[source.prepared-registry]\nlocal-registry = "/prepared/cargo-local-registry"\n'
    b'[net]\noffline = true\nretry = 0\n'
)
RUST_V2_BASELINE_ROOT = "workspace/semver-baseline/runtime"
RUST_V2_REGISTRY_ROOT = "cargo-local-registry"
RUST_V2_LOCKS = {
    "Cargo.toml": "Cargo.lock",
    "runtime/Cargo.toml": "runtime/Cargo.lock",
    "fuzz/Cargo.toml": "fuzz/Cargo.lock",
}
RUST_V2_GENERATED_LOCK_STATUS = "ephemeral-offline-generated-not-committed"


class Refusal(ValueError):
    """Stable code only; never renders a source path or package coordinate."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _refuse(code: str) -> None:
    raise Refusal(code)


def _sha(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _valid_hex(value: object) -> bool:
    return (type(value) is str and len(value) == 64
            and all(char in HEX for char in value))


def _valid_commit(value: object) -> bool:
    return (type(value) is str and len(value) == 40
            and all(char in HEX for char in value))


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":")).encode("ascii")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _refuse("semver-cache-json-duplicate-key")
        result[key] = value
    return result


def _validate_input_identity(value: object) -> dict[str, str]:
    if type(value) is not dict or set(value) != INPUT_KEYS:
        _refuse("semver-cache-input-binding")
    if not _valid_commit(value.get("source_commit")) or not _valid_commit(value.get("control_sha")):
        _refuse("semver-cache-input-binding")
    if any(not _valid_hex(value.get(field)) for field in SHA256_FIELDS):
        _refuse("semver-cache-input-binding")
    if any(type(value.get(field)) is not str or not value[field] or len(value[field]) > 128
           for field in ("baseline_runtime_version", "candidate_runtime_version")):
        _refuse("semver-cache-input-binding")
    return dict(value)


def _scope_rows(scope_locks: object, scope_manifests: object) -> tuple[dict, dict, list[dict[str, str]]]:
    if (type(scope_locks) is not dict or set(scope_locks) != set(REQUIRED_SCOPES)
            or type(scope_manifests) is not dict or set(scope_manifests) != set(REQUIRED_SCOPES)):
        _refuse("semver-cache-scope-set")
    records: dict[str, dict[str, Any]] = {}
    lock_hashes: dict[str, str] = {}
    union: dict[tuple[str, str], dict[str, str]] = {}
    for scope in REQUIRED_SCOPES:
        lock_bytes = scope_locks[scope]
        manifest_bytes = scope_manifests[scope]
        if (type(lock_bytes) is not bytes or not lock_bytes or len(lock_bytes) > MAX_FILE_BYTES
                or type(manifest_bytes) is not bytes or not manifest_bytes
                or len(manifest_bytes) > MAX_FILE_BYTES):
            _refuse("semver-cache-scope-size")
        try:
            packages = constraint_resolver.lock_package_rows(lock_bytes)
        except constraint_resolver.Refusal:
            _refuse("semver-cache-lock-invalid")
        if not packages and scope != "baseline-runtime":
            _refuse("semver-cache-scope-empty")
        for row in packages:
            coordinate = (row["name"], row["version"])
            previous = union.get(coordinate)
            if previous is not None and previous["checksum"] != row["checksum"]:
                _refuse("semver-cache-coordinate-collision")
            union[coordinate] = row
        lock_digest = _sha(lock_bytes)
        manifest_digest = _sha(manifest_bytes)
        lock_hashes[scope] = lock_digest
        records[scope] = {
            "manifest_sha256": manifest_digest,
            "lock_sha256": lock_digest,
            "packages": packages,
        }
    return records, lock_hashes, sorted(union.values(), key=lambda row: (row["name"], row["version"]))


def _candidate_lock_output_digest(lock_hashes: dict[str, str]) -> str:
    required = {"Cargo.lock", "runtime/Cargo.lock", "fuzz/Cargo.lock"}
    if (type(lock_hashes) is not dict or set(lock_hashes) != required
            or any(not _valid_hex(value) for value in lock_hashes.values())):
        _refuse("semver-cache-lock-output-binding")
    return _sha(_canonical(lock_hashes))


def _require_canonical_directory(path: str | Path, code: str) -> Path:
    value = Path(path)
    if not value.is_absolute():
        _refuse(code)
    cursor = Path(value.anchor)
    for part in value.parts[1:]:
        cursor = cursor / part
        if cursor.is_symlink():
            _refuse(code)
    if not value.is_dir():
        _refuse(code)
    try:
        if value.resolve(strict=True) != value:
            _refuse(code)
    except OSError:
        _refuse(code)
    return value


def _require_safe_member(root: Path, member: Path) -> None:
    try:
        relative = member.relative_to(root)
    except ValueError:
        _refuse("semver-cache-input-path")
    cursor = root
    for part in relative.parts[:-1]:
        cursor = cursor / part
        if cursor.is_symlink() or not cursor.is_dir():
            _refuse("semver-cache-input-path")
    if member.is_symlink():
        _refuse("semver-cache-input-path")


def contract_for_prepared_registry(baseline_lock: bytes,
                                   candidate_resolver_lock: bytes,
                                   scope_manifests: dict[str, bytes],
                                   input_identity: dict[str, str],
                                   registry_root: str | Path,
                                   budget: bounded_registry_io.PhaseBudget) -> dict[str, Any]:
    """Bind prefetch inputs without requiring final candidate Cargo.lock files.

    Only pre-cut baseline and candidate resolver locks contribute to the registry closure.
    The SemVer tool creates its placeholder projects after the cut; their actual Cargo files and
    generated locks are bound by the trusted post-cut checkpoint callback.
    """
    identity = _validate_input_identity(input_identity)
    if type(scope_manifests) is not dict or set(scope_manifests) != set(REQUIRED_SCOPES):
        _refuse("semver-cache-scope-set")
    manifest_hashes = {}
    for scope in REQUIRED_SCOPES:
        payload = scope_manifests[scope]
        if type(payload) is not bytes or not payload or len(payload) > MAX_FILE_BYTES:
            _refuse("semver-cache-scope-size")
        manifest_hashes[scope] = _sha(payload)
    expected_manifest_hashes = {
        "baseline-runtime": identity["baseline_runtime_manifest_sha256"],
        "candidate-root": identity["candidate_root_manifest_sha256"],
        "candidate-runtime": identity["candidate_runtime_manifest_sha256"],
        "candidate-fuzz": identity["candidate_fuzz_manifest_sha256"],
    }
    if manifest_hashes != expected_manifest_hashes:
        _refuse("semver-cache-manifest-binding")
    lock_inputs = {
        "baseline-runtime": baseline_lock,
        "candidate-resolver-closure": candidate_resolver_lock,
    }
    input_rows = {}
    union: dict[tuple[str, str], dict[str, str]] = {}
    for scope, lock_bytes in lock_inputs.items():
        if type(lock_bytes) is not bytes or not lock_bytes or len(lock_bytes) > MAX_FILE_BYTES:
            _refuse("semver-cache-scope-size")
        try:
            rows = constraint_resolver.lock_package_rows(lock_bytes)
        except constraint_resolver.Refusal:
            _refuse("semver-cache-lock-invalid")
        if not rows and scope != "baseline-runtime":
            _refuse("semver-cache-scope-empty")
        for row in rows:
            coordinate = (row["name"], row["version"])
            previous = union.get(coordinate)
            if previous is not None and previous["checksum"] != row["checksum"]:
                _refuse("semver-cache-coordinate-collision")
            union[coordinate] = row
        input_rows[scope] = {"lock_sha256": _sha(lock_bytes), "packages": rows}
    packages = sorted(union.values(), key=lambda row: (row["name"], row["version"]))
    registry = Path(registry_root)
    try:
        inventory = bounded_registry_io.verify_bounded_registry_tree(registry, packages, budget)
        registry_digest, registry_files, registry_bytes = tree_digest(registry, budget)
    except (bounded_registry_io.Refusal, OSError):
        _refuse("semver-cache-registry-invalid")
    return {
        "schema": SCHEMA,
        "input_identity": identity,
        "scope_manifest_sha256": manifest_hashes,
        "prefetch_lock_inputs": input_rows,
        "temporary_project_operations": TEMPORARY_PROJECT_OPERATIONS,
        "registry": {
            "tree_sha256": registry_digest,
            "package_count": len(packages),
            "file_count": registry_files,
            "tree_bytes": registry_bytes,
            "index_bytes": inventory["index_bytes"],
            "archive_bytes": inventory["archive_bytes"],
            "expanded_bytes": inventory["expanded_bytes"],
            "members": inventory["members"],
        },
    }


def write_prepared_contract(prepared_root: str | Path, contract: dict[str, Any]) -> None:
    """Sync a temporary sibling, then publish once without replacing an existing contract."""
    root = Path(prepared_root)
    if root.is_symlink() or not root.is_dir():
        _refuse("semver-cache-prepared-root")
    target = root / CONTRACT_NAME
    if target.exists() or target.is_symlink():
        _refuse("semver-cache-contract-exists")
    payload = _canonical(contract) + b"\n"
    if len(payload) > MAX_CONTRACT_BYTES:
        _refuse("semver-cache-contract-size")
    descriptor = None
    temporary = None
    published = False
    identity = None
    try:
        descriptor, temporary = tempfile.mkstemp(prefix=".semver-contract-", dir=root)
        os.fchmod(descriptor, 0o400)
        metadata = os.fstat(descriptor)
        identity = (metadata.st_dev, metadata.st_ino)
        remaining = memoryview(payload)
        while remaining:
            count = os.write(descriptor, remaining)
            if count <= 0:
                raise OSError("contract write made no progress")
            remaining = remaining[count:]
        os.fsync(descriptor)
        closing = descriptor
        descriptor = None
        os.close(closing)
        os.link(temporary, target, follow_symlinks=False)
        published = True
        os.unlink(temporary)
        temporary = None
        directory = os.open(root, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                            | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except FileExistsError:
        _refuse("semver-cache-contract-exists")
    except OSError:
        if published:
            try:
                current = target.stat(follow_symlinks=False)
                if (current.st_dev, current.st_ino) == identity:
                    target.unlink()
            except OSError:
                pass
        _refuse("semver-cache-contract-write")
    finally:
        if descriptor is not None:
            closing = descriptor
            descriptor = None
            try:
                os.close(closing)
            except OSError:
                pass
        if temporary is not None:
            try:
                os.unlink(temporary)
            except OSError:
                pass


def _input_package_union(baseline_lock: bytes, candidate_resolver_lock: bytes) -> list[dict[str, str]]:
    rows_by_scope = {}
    union: dict[tuple[str, str], dict[str, str]] = {}
    for scope, lock_bytes in (
            ("baseline-runtime", baseline_lock),
            ("candidate-resolver-closure", candidate_resolver_lock)):
        if type(lock_bytes) is not bytes or not lock_bytes or len(lock_bytes) > MAX_FILE_BYTES:
            _refuse("semver-cache-scope-size")
        try:
            rows = constraint_resolver.lock_package_rows(lock_bytes)
        except constraint_resolver.Refusal:
            _refuse("semver-cache-lock-invalid")
        if not rows and scope != "baseline-runtime":
            _refuse("semver-cache-scope-empty")
        rows_by_scope[scope] = rows
        for row in rows:
            coordinate = (row["name"], row["version"])
            previous = union.get(coordinate)
            if previous is not None and previous["checksum"] != row["checksum"]:
                _refuse("semver-cache-coordinate-collision")
            union[coordinate] = row
    return sorted(union.values(), key=lambda row: (row["name"], row["version"]))


def build_prepared_cache(prepared_root: str | Path,
                         candidate_manifests: dict[str, bytes],
                         candidate_resolver_lock: bytes,
                         input_identity: dict[str, str],
                         budget: bounded_registry_io.PhaseBudget) -> dict[str, Any]:
    """Prefetch baseline and candidate-resolver closures before decrypt.

    Candidate Cargo.lock outputs are intentionally absent here: the encrypted offline worker
    generates them after cut and binds their output digest separately. This removes the old-lock
    hash prerequisite while keeping the pre-decrypt registry closure complete and bounded.
    """
    identity = _validate_input_identity(input_identity)
    prepared = _require_canonical_directory(prepared_root, "semver-cache-prepared-root")
    baseline = prepared / BASELINE_ROOT
    if baseline.is_symlink() or not baseline.is_dir():
        _refuse("semver-cache-prepared-input-missing")
    baseline = _require_canonical_directory(baseline, "semver-cache-prepared-input-missing")
    baseline_map, _baseline_count, _baseline_bytes = source_map_digest(baseline, budget)
    if baseline_map != identity["baseline_source_map_sha256"]:
        _refuse("semver-cache-baseline-source-binding")
    if workspace_version(baseline / "Cargo.toml") != identity["baseline_runtime_version"]:
        _refuse("semver-cache-workspace-version")
    if (type(candidate_manifests) is not dict
            or set(candidate_manifests) != {"candidate-root", "candidate-runtime", "candidate-fuzz"}):
        _refuse("semver-cache-scope-set")
    scope_manifests = {
        "baseline-runtime": _read_file(baseline / "Cargo.toml", MAX_FILE_BYTES),
        "candidate-root": candidate_manifests["candidate-root"],
        "candidate-runtime": candidate_manifests["candidate-runtime"],
        "candidate-fuzz": candidate_manifests["candidate-fuzz"],
    }
    expected_manifests = {
        "baseline-runtime": identity["baseline_runtime_manifest_sha256"],
        "candidate-root": identity["candidate_root_manifest_sha256"],
        "candidate-runtime": identity["candidate_runtime_manifest_sha256"],
        "candidate-fuzz": identity["candidate_fuzz_manifest_sha256"],
    }
    if {scope: _sha(value) for scope, value in scope_manifests.items()} != expected_manifests:
        _refuse("semver-cache-manifest-binding")
    if (workspace_version(baseline / "Cargo.toml") != identity["baseline_runtime_version"]):
        _refuse("semver-cache-workspace-version")
    baseline_lock = _read_file(baseline / "Cargo.lock", MAX_FILE_BYTES)
    resolver_path = prepared / "cargo-resolver.lock"
    _require_safe_member(prepared, resolver_path)
    if _read_file(resolver_path, MAX_FILE_BYTES) != candidate_resolver_lock:
        _refuse("semver-cache-resolver-lock-binding")
    packages = _input_package_union(baseline_lock, candidate_resolver_lock)
    registry = prepared / REGISTRY_ROOT
    if registry.exists() or registry.is_symlink():
        _refuse("semver-cache-registry-exists")
    created = False
    try:
        bounded_registry_io.build_bounded_registry(packages, registry, budget)
        created = True
        contract = contract_for_prepared_registry(
            baseline_lock, candidate_resolver_lock,
            scope_manifests, identity, registry, budget,
        )
        write_prepared_contract(prepared_root, contract)
        return contract
    except (Refusal, bounded_registry_io.Refusal, OSError):
        if created and (registry.exists() or registry.is_symlink()):
            try:
                bounded_registry_io.remove_tree_bounded(registry, budget)
            except bounded_registry_io.Refusal:
                _refuse("semver-cache-cleanup")
        raise


def tree_digest(root: str | Path, budget: bounded_registry_io.PhaseBudget) -> tuple[str, int, int]:
    """Stream a bounded path/size/content inventory without following links."""
    base = Path(root)
    if base.is_symlink() or not base.is_dir():
        _refuse("semver-cache-tree-invalid")
    rows: list[list[Any]] = []
    file_count = total = 0
    for current, directories, files in os.walk(base, topdown=True, followlinks=False):
        budget.remaining()
        parent = Path(current)
        for name in directories:
            path = parent / name
            if path.is_symlink() or not path.is_dir():
                _refuse("semver-cache-tree-link")
        for name in files:
            budget.remaining()
            path = parent / name
            try:
                metadata = path.lstat()
            except OSError:
                _refuse("semver-cache-tree-invalid")
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_size > MAX_REGISTRY_FILE_BYTES):
                _refuse("semver-cache-tree-member")
            file_count += 1
            if file_count > MAX_FILES:
                _refuse("semver-cache-tree-count")
            descriptor = None
            digest = hashlib.sha256()
            size = 0
            try:
                nofollow = getattr(os, "O_NOFOLLOW", 0)
                nonblock = getattr(os, "O_NONBLOCK", 0)
                if not nofollow or not nonblock:
                    _refuse("semver-cache-tree-read")
                descriptor = os.open(path, os.O_RDONLY | nofollow | nonblock
                                     | getattr(os, "O_CLOEXEC", 0))
                opened = os.fstat(descriptor)
                if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                        or opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino
                        or opened.st_size != metadata.st_size
                        or opened.st_size > MAX_REGISTRY_FILE_BYTES):
                    _refuse("semver-cache-tree-race")
                local_deadline = time.monotonic() + 10.0
                while True:
                    if time.monotonic() >= local_deadline:
                        _refuse("semver-cache-tree-deadline")
                    budget.remaining()
                    chunk = os.read(descriptor, min(CHUNK, MAX_REGISTRY_FILE_BYTES + 1 - size))
                    if not chunk:
                        break
                    size += len(chunk)
                    total += len(chunk)
                    if size > MAX_REGISTRY_FILE_BYTES or total > MAX_TREE_BYTES:
                        _refuse("semver-cache-tree-size")
                    digest.update(chunk)
                after = os.fstat(descriptor)
                try:
                    after_path = path.lstat()
                except OSError:
                    _refuse("semver-cache-tree-race")
                if (size != opened.st_size or not stat.S_ISREG(after_path.st_mode)
                        or after_path.st_nlink != 1 or after.st_dev != opened.st_dev
                        or after.st_ino != opened.st_ino or after.st_size != opened.st_size
                        or after.st_nlink != 1 or after.st_mtime_ns != opened.st_mtime_ns
                        or after.st_ctime_ns != opened.st_ctime_ns
                        or after_path.st_dev != opened.st_dev
                        or after_path.st_ino != opened.st_ino):
                    _refuse("semver-cache-tree-race")
            except Refusal:
                raise
            except OSError:
                _refuse("semver-cache-tree-read")
            finally:
                if descriptor is not None:
                    os.close(descriptor)
            rows.append([path.relative_to(base).as_posix(), size, digest.hexdigest()])
    rows.sort(key=lambda item: item[0])
    return _sha(_canonical(rows)), file_count, total


def source_map_digest(root: str | Path, budget: bounded_registry_io.PhaseBudget,
                      *, omit_root_cargo_lock: bool = False,
                      allow_missing_root_cargo_lock: bool = False,
                      root_relative_keys: bool = False,
                      omit_paths: tuple[str, ...] = (),
                      required_omitted_paths: tuple[str, ...] = ()) -> tuple[str, int, int]:
    """Recompute the sorted path-to-file-hash map under fixed tree limits.

    The candidate runtime map may omit exactly its Cargo.lock because that lock is a
    separately generated output. The complete candidate map and immutable baseline map
    include every regular file. The returned digest uses canonical JSON encoding.
    Runtime maps use the product-relative ``runtime/`` prefix; a SemVer-created temporary
    project uses root-relative keys while omitting its generated root lock.
    """
    if (root_relative_keys and not omit_root_cargo_lock
            or type(omit_paths) is not tuple or type(required_omitted_paths) is not tuple):
        _refuse("semver-cache-source-map-mode")
    omitted_paths = set(omit_paths)
    required_paths = set(required_omitted_paths)
    if (len(omitted_paths) != len(omit_paths)
            or len(required_paths) != len(required_omitted_paths)
            or not required_paths.issubset(omitted_paths)
            or any(type(item) is not str or not item or "\\" in item or "\x00" in item
                   or item.startswith("/") or any(part in ("", ".", "..")
                                                  for part in item.split("/"))
                   for item in (*omit_paths, *required_omitted_paths))):
        _refuse("semver-cache-source-map-mode")
    if omit_root_cargo_lock:
        if "Cargo.lock" in omitted_paths:
            _refuse("semver-cache-source-map-mode")
        omitted_paths.add("Cargo.lock")
        if not allow_missing_root_cargo_lock:
            required_paths.add("Cargo.lock")
    base = _require_canonical_directory(root, "semver-cache-source-root")
    rows: dict[str, str] = {}
    entries = total = 0
    omitted_seen: set[str] = set()
    try:
        for current, directories, files in os.walk(base, topdown=True, followlinks=False):
            budget.remaining()
            directory = Path(current)
            directories.sort()
            files.sort()
            for name in directories:
                entries += 1
                child = directory / name
                if (entries > MAX_SOURCE_TREE_ENTRIES or child.is_symlink()
                        or not child.is_dir()):
                    _refuse("semver-cache-source-tree-entry")
            for name in files:
                budget.remaining()
                entries += 1
                if entries > MAX_SOURCE_TREE_ENTRIES:
                    _refuse("semver-cache-source-tree-count")
                path = directory / name
                relative = path.relative_to(base).as_posix()
                try:
                    before = path.lstat()
                except OSError:
                    _refuse("semver-cache-source-tree-read")
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                        or before.st_size > MAX_SOURCE_FILE_BYTES):
                    _refuse("semver-cache-source-tree-member")
                if relative in omitted_paths:
                    omitted_seen.add(relative)
                    continue
                descriptor = None
                digest = hashlib.sha256()
                size = 0
                try:
                    required_flags = (getattr(os, "O_NOFOLLOW", 0)
                                      | getattr(os, "O_NONBLOCK", 0)
                                      | getattr(os, "O_CLOEXEC", 0))
                    if not required_flags & getattr(os, "O_NOFOLLOW", 0) or not (
                            required_flags & getattr(os, "O_NONBLOCK", 0)):
                        _refuse("semver-cache-source-tree-read")
                    descriptor = os.open(path, os.O_RDONLY | required_flags)
                    opened = os.fstat(descriptor)
                    if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                            or opened.st_dev != before.st_dev or opened.st_ino != before.st_ino
                            or opened.st_size != before.st_size):
                        _refuse("semver-cache-source-tree-race")
                    while True:
                        budget.remaining()
                        chunk = os.read(descriptor, min(CHUNK, MAX_SOURCE_FILE_BYTES + 1 - size))
                        if not chunk:
                            break
                        size += len(chunk)
                        total += len(chunk)
                        if size > MAX_SOURCE_FILE_BYTES or total > MAX_SOURCE_TREE_BYTES:
                            _refuse("semver-cache-source-tree-size")
                        digest.update(chunk)
                    after = os.fstat(descriptor)
                    try:
                        after_path = path.lstat()
                    except OSError:
                        _refuse("semver-cache-source-tree-race")
                    if (size != opened.st_size or not stat.S_ISREG(after_path.st_mode)
                            or after_path.st_nlink != 1 or after.st_dev != opened.st_dev
                            or after.st_ino != opened.st_ino or after.st_size != opened.st_size
                            or after.st_nlink != 1 or after.st_mtime_ns != opened.st_mtime_ns
                            or after.st_ctime_ns != opened.st_ctime_ns
                            or after_path.st_dev != opened.st_dev
                            or after_path.st_ino != opened.st_ino):
                        _refuse("semver-cache-source-tree-race")
                except Refusal:
                    raise
                except OSError:
                    _refuse("semver-cache-source-tree-read")
                finally:
                    if descriptor is not None:
                        os.close(descriptor)
                key = ("runtime/" + relative
                       if omit_root_cargo_lock and not root_relative_keys else relative)
                rows[key] = digest.hexdigest()
    except Refusal:
        raise
    except OSError:
        _refuse("semver-cache-source-tree-read")
    if not required_paths.issubset(omitted_seen):
        _refuse("semver-cache-source-lock-missing")
    if not rows:
        _refuse("semver-cache-source-tree-empty")
    ordered = dict(sorted(rows.items()))
    encoded = (json.dumps(ordered, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    return _sha(encoded), len(ordered), total


def workspace_version(manifest_path: Path) -> str:
    """Read the workspace package version without exposing parser details."""
    payload = _read_file(manifest_path, MAX_FILE_BYTES)
    try:
        value = tomllib.loads(payload.decode("utf-8", "strict"))
        version = value["workspace"]["package"]["version"]
    except (UnicodeError, ValueError, KeyError, TypeError, RecursionError):
        _refuse("semver-cache-workspace-version")
    if type(version) is not str or not version or len(version) > 128:
        _refuse("semver-cache-workspace-version")
    return version


def _decode_mount_field(value: str) -> str:
    return value.replace("\\134", "\\").replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n")


def require_readonly_bind_mount(path: str | Path, mountinfo: str) -> None:
    canonical = _require_canonical_directory(path, "semver-cache-mount-path")
    target = str(canonical)
    if type(mountinfo) is not str or len(mountinfo) > 4 * 1024 * 1024:
        _refuse("semver-cache-mountinfo-invalid")
    records: list[tuple[str, frozenset[str]]] = []
    for line in mountinfo.splitlines():
        fields = line.split()
        if len(fields) < 10 or "-" not in fields:
            continue
        separator = fields.index("-")
        if separator < 6:
            continue
        mountpoint = _decode_mount_field(fields[4])
        options = frozenset(fields[5].split(","))
        records.append((mountpoint.rstrip("/") or "/", options))
    covering = [(mountpoint, options) for mountpoint, options in records
                if target == mountpoint or target.startswith(mountpoint.rstrip("/") + "/")]
    if not covering:
        _refuse("semver-cache-readonly-mount-required")
    nearest = max(covering, key=lambda item: len(item[0]))
    if "ro" not in nearest[1] or "rw" in nearest[1]:
        _refuse("semver-cache-readonly-mount-required")
    prefix = target.rstrip("/") + "/"
    for mountpoint, options in records:
        if mountpoint.startswith(prefix) and ("rw" in options or "ro" not in options):
            _refuse("semver-cache-readonly-mount-required")


def _read_file(path: Path, maximum: int, budget=None) -> bytes:
    descriptor = None
    try:
        metadata = path.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or metadata.st_size > maximum):
            _refuse("semver-cache-input-file")
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        nonblock = getattr(os, "O_NONBLOCK", 0)
        if not nofollow or not nonblock:
            _refuse("semver-cache-input-file")
        descriptor = os.open(path, os.O_RDONLY | nofollow | nonblock
                             | getattr(os, "O_CLOEXEC", 0))
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino
                or opened.st_size != metadata.st_size):
            _refuse("semver-cache-input-race")
        chunks = bytearray()
        local_deadline = time.monotonic() + SMALL_READ_SECONDS
        while len(chunks) <= maximum:
            if time.monotonic() >= local_deadline:
                _refuse("semver-cache-input-deadline")
            if budget is not None:
                budget.remaining()
            chunk = os.read(descriptor, min(CHUNK, maximum + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
        try:
            after_path = path.lstat()
        except OSError:
            _refuse("semver-cache-input-race")
        if (len(chunks) != opened.st_size or len(chunks) > maximum
                or not stat.S_ISREG(after_path.st_mode) or after_path.st_nlink != 1
                or after.st_dev != opened.st_dev or after.st_ino != opened.st_ino
                or after.st_size != opened.st_size or after.st_nlink != 1
                or after.st_mtime_ns != opened.st_mtime_ns or after.st_ctime_ns != opened.st_ctime_ns
                or after_path.st_dev != opened.st_dev or after_path.st_ino != opened.st_ino):
            _refuse("semver-cache-input-size")
        return bytes(chunks)
    except Refusal:
        raise
    except OSError:
        _refuse("semver-cache-input-file")
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _verify_rust_tool_receipts(rust_tools: Path, tool_hashes: dict[str, str], budget,
                               *, run_process=None) -> None:
    runner = subprocess.run if run_process is None else run_process
    tool_root = _require_canonical_directory(rust_tools, "semver-cache-tool-binding")
    for name, (argument0, *version_policy) in TOOL_VERSION_COMMANDS.items():
        executable = tool_root / "bin" / name
        expected_binary = tool_hashes.get(name + "_sha256")
        expected_output = tool_hashes.get(name + "_version_output_sha256")
        if (not _valid_hex(expected_binary) or not _valid_hex(expected_output)
                or _sha(_read_file(executable, MAX_REGISTRY_FILE_BYTES, budget)) != expected_binary):
            _refuse("semver-cache-tool-binding")
        budget.remaining()
        executable_text = str(executable)
        output_prefix = version_policy[-2]
        required_line = version_policy[-1]
        environment = {
            "PATH": str(executable.parent) + ":/usr/bin:/bin",
            "LC_ALL": "C",
            "LD_LIBRARY_PATH": str(executable.parent.parent / "lib"),
        }
        try:
            result = runner(
                [executable_text, argument0, *version_policy[:-2]],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                check=False, close_fds=True,
                timeout=min(10, budget.remaining()), env=environment,
            )
        except (OSError, subprocess.SubprocessError, bounded_registry_io.Refusal):
            _refuse("semver-cache-tool-binding")
        if (type(result.stdout) is not bytes or type(result.stderr) is not bytes
                or len(result.stdout) > 4096 or len(result.stderr) > 4096):
            _refuse("semver-cache-tool-binding")
        try:
            constraint_resolver.validate_tool_version_output(
                name, result.stdout, result.stderr, result.returncode,
                output_prefix, required_line,
            )
        except (constraint_resolver.Refusal, AttributeError):
            _refuse("semver-cache-tool-binding")
        if _sha(result.stdout) != expected_output:
            _refuse("semver-cache-tool-binding")


def _load_contract(path: Path) -> dict[str, Any]:
    raw = _read_file(path, MAX_CONTRACT_BYTES)
    try:
        value = json.loads(raw.decode("ascii", "strict"), object_pairs_hook=_unique_pairs)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        _refuse("semver-cache-contract-invalid")
    required = {"schema", "input_identity", "scope_manifest_sha256", "prefetch_lock_inputs",
                "temporary_project_operations", "registry"}
    if type(value) is not dict or set(value) != required or value.get("schema") != SCHEMA:
        _refuse("semver-cache-contract-invalid")
    if (type(value.get("scope_manifest_sha256")) is not dict
            or set(value["scope_manifest_sha256"]) != set(REQUIRED_SCOPES)
            or any(not _valid_hex(digest) for digest in value["scope_manifest_sha256"].values())
            or value.get("temporary_project_operations") != TEMPORARY_PROJECT_OPERATIONS):
        _refuse("semver-cache-contract-scope-set")
    identity = _validate_input_identity(value.get("input_identity"))
    expected_manifests = {
        "baseline-runtime": identity["baseline_runtime_manifest_sha256"],
        "candidate-root": identity["candidate_root_manifest_sha256"],
        "candidate-runtime": identity["candidate_runtime_manifest_sha256"],
        "candidate-fuzz": identity["candidate_fuzz_manifest_sha256"],
    }
    if value["scope_manifest_sha256"] != expected_manifests:
        _refuse("semver-cache-manifest-binding")
    registry = value.get("registry")
    if (type(registry) is not dict
            or set(registry) != {"tree_sha256", "package_count", "file_count", "tree_bytes",
                                "index_bytes", "archive_bytes", "expanded_bytes", "members"}
            or not _valid_hex(registry.get("tree_sha256"))
            or type(registry.get("package_count")) is not int
            or registry["package_count"] <= 0
            or any(type(registry.get(key)) is not int or registry[key] < 0
                   for key in ("file_count", "tree_bytes", "index_bytes", "archive_bytes",
                               "expanded_bytes", "members"))
            or registry["file_count"] <= 0 or registry["tree_bytes"] <= 0
            or registry["archive_bytes"] <= 0 or registry["members"] <= 0):
        _refuse("semver-cache-contract-registry")
    lock_inputs = value.get("prefetch_lock_inputs")
    required_lock_inputs = {"baseline-runtime", "candidate-resolver-closure"}
    if type(lock_inputs) is not dict or set(lock_inputs) != required_lock_inputs:
        _refuse("semver-cache-contract-lock-set")
    for scope in required_lock_inputs:
        record = lock_inputs.get(scope)
        if (type(record) is not dict or set(record) != {"lock_sha256", "packages"}
                or not _valid_hex(record.get("lock_sha256"))):
            _refuse("semver-cache-contract-lock-set")
        _normal_package_rows(record.get("packages"))
    return value


def _normal_package_rows(rows: object) -> list[dict[str, str]]:
    try:
        return registry_prefetch._validate_packages(rows)
    except (registry_prefetch.Refusal, TypeError):
        _refuse("semver-cache-contract-packages")


def validate_prepared_cache(prepared_root: str | Path,
                            candidate_root: str | Path,
                            cargo_home: str | Path,
                            authenticated_binding: object,
                            budget: bounded_registry_io.PhaseBudget,
                            *, expected_source_sha: str | None,
                            expected_control_sha: str | None,
                            expected_projection_sha256: str | None,
                            expected_source_maps: object,
                            mountinfo: str) -> dict[str, Any]:
    """Refuse before SemVer launch unless all locked scopes and fresh offline config match.

    ``authenticated_binding`` must come from the decrypted, authenticated bundle manifest.
    The source/control/projection arguments are supplied independently by the trusted caller.
    The existing public release-asset route does not provide them for Rust and remains closed.
    """
    identity = _validate_input_identity(authenticated_binding)
    if not isinstance(budget, bounded_registry_io.PhaseBudget):
        _refuse("semver-cache-budget-invalid")
    try:
        budget.remaining()
    except bounded_registry_io.Refusal:
        _refuse("semver-cache-budget-closed")
    if (expected_source_sha != identity["source_commit"]
            or expected_control_sha != identity["control_sha"]
            or expected_projection_sha256 != identity["manifest_projection_sha256"]):
        _refuse("semver-cache-trusted-binding-mismatch")
    required_source_maps = {
        "baseline_source_map_sha256", "candidate_source_map_sha256",
        "candidate_full_source_map_sha256",
    }
    if (type(expected_source_maps) is not dict or set(expected_source_maps) != required_source_maps
            or any(not _valid_hex(expected_source_maps.get(key)) for key in required_source_maps)
            or any(identity[key] != expected_source_maps[key] for key in required_source_maps)):
        _refuse("semver-cache-source-map-binding")
    prepared = Path(prepared_root)
    candidate = Path(candidate_root)
    home = Path(cargo_home)
    _require_canonical_directory(prepared, "semver-cache-root-invalid")
    _require_canonical_directory(candidate, "semver-cache-root-invalid")
    _require_canonical_directory(home, "semver-cache-root-invalid")
    require_readonly_bind_mount(prepared, mountinfo)
    baseline = _require_canonical_directory(
        prepared / BASELINE_ROOT, "semver-cache-prepared-input-missing",
    )
    registry = prepared / REGISTRY_ROOT
    contract_path = prepared / CONTRACT_NAME
    if registry.is_symlink() or not registry.is_dir():
        _refuse("semver-cache-prepared-input-missing")
    registry = _require_canonical_directory(registry, "semver-cache-prepared-input-missing")
    contract = _load_contract(contract_path)
    if contract.get("input_identity") != identity:
        _refuse("semver-cache-trusted-binding-mismatch")

    manifest_paths = {
        "baseline-runtime": prepared / BASELINE_ROOT / "Cargo.toml",
        "candidate-root": candidate / "Cargo.toml",
        "candidate-runtime": candidate / "runtime/Cargo.toml",
        "candidate-fuzz": candidate / "fuzz/Cargo.toml",
    }
    for scope, path in manifest_paths.items():
        scope_root = prepared / BASELINE_ROOT if scope == "baseline-runtime" else candidate
        _require_safe_member(scope_root, path)
        if _sha(_read_file(path, MAX_FILE_BYTES)) != contract["scope_manifest_sha256"][scope]:
            _refuse("semver-cache-manifest-binding")

    baseline_digest, baseline_count, _baseline_bytes = source_map_digest(baseline, budget)
    candidate_runtime_digest, candidate_runtime_count, _candidate_runtime_bytes = source_map_digest(
        candidate / "runtime", budget, omit_root_cargo_lock=True,
    )
    candidate_full_digest, candidate_full_count, _candidate_full_bytes = source_map_digest(
        candidate, budget,
    )
    if (baseline_digest != identity["baseline_source_map_sha256"]
            or candidate_runtime_digest != identity["candidate_source_map_sha256"]
            or candidate_full_digest != identity["candidate_full_source_map_sha256"]):
        _refuse("semver-cache-source-map-binding")
    if (workspace_version(baseline / "Cargo.toml") != identity["baseline_runtime_version"]
            or workspace_version(candidate / "runtime/Cargo.toml")
            != identity["candidate_runtime_version"]):
        _refuse("semver-cache-workspace-version")

    lock_paths = {
        "baseline-runtime": prepared / BASELINE_ROOT / "Cargo.lock",
        "candidate-resolver-closure": prepared / "cargo-resolver.lock",
    }
    input_rows: dict[str, list[dict[str, str]]] = {}
    for scope, path in lock_paths.items():
        _require_safe_member(prepared, path)
        lock_bytes = _read_file(path, MAX_FILE_BYTES)
        record = contract["prefetch_lock_inputs"][scope]
        if _sha(lock_bytes) != record["lock_sha256"]:
            _refuse("semver-cache-prefetch-lock-binding")
        try:
            rows = constraint_resolver.lock_package_rows(lock_bytes)
        except constraint_resolver.Refusal:
            _refuse("semver-cache-lock-invalid")
        if ((not rows and scope != "baseline-runtime")
                or rows != _normal_package_rows(record["packages"])):
            _refuse("semver-cache-prefetch-lock-closure")
        input_rows[scope] = rows
    union: dict[tuple[str, str], dict[str, str]] = {}
    for rows in input_rows.values():
        for row in rows:
            coordinate = (row["name"], row["version"])
            previous = union.get(coordinate)
            if previous is not None and previous["checksum"] != row["checksum"]:
                _refuse("semver-cache-coordinate-collision")
            union[coordinate] = row
    packages = sorted(union.values(), key=lambda row: (row["name"], row["version"]))
    try:
        inventory = bounded_registry_io.verify_bounded_registry_tree(registry, packages, budget)
        digest, package_files, _total = tree_digest(registry, budget)
    except (bounded_registry_io.Refusal, OSError):
        _refuse("semver-cache-registry-invalid")
    expected_registry = {
        "tree_sha256": digest,
        "package_count": len(packages),
        "file_count": package_files,
        "tree_bytes": _total,
        "index_bytes": inventory.get("index_bytes"),
        "archive_bytes": inventory.get("archive_bytes"),
        "expanded_bytes": inventory.get("expanded_bytes"),
        "members": inventory.get("members"),
    }
    if contract["registry"] != expected_registry:
        _refuse("semver-cache-registry-binding")

    config_path = home / "config.toml"
    try:
        home_entries = {entry.name for entry in home.iterdir()}
    except OSError:
        _refuse("semver-cache-cargo-home-invalid")
    if home_entries != {"config.toml"} or config_path.is_symlink():
        _refuse("semver-cache-cargo-home-not-fresh")
    config = _read_file(config_path, 4096)
    if (config != CARGO_CONFIG or _sha(config) != _sha(CARGO_CONFIG)
            or stat.S_IMODE(config_path.stat().st_mode) & 0o222):
        _refuse("semver-cache-cargo-config-invalid")
    return {
        "schema": SCHEMA,
        "source_commit": identity["source_commit"],
        "control_sha": identity["control_sha"],
        "manifest_projection_sha256": identity["manifest_projection_sha256"],
        "registry_tree_sha256": digest,
        "_registry_package_rows": packages,
        "registry_package_count": len(packages),
        "source_map_file_counts": {
            "baseline_runtime": baseline_count,
            "candidate_runtime_excluding_cargo_lock": candidate_runtime_count,
            "candidate_full": candidate_full_count,
        },
        "prefetch_lock_sha256": {
            scope: contract["prefetch_lock_inputs"][scope]["lock_sha256"]
            for scope in sorted(contract["prefetch_lock_inputs"])
        },
        "cargo_net_offline": True,
        "temporary_project_operations": TEMPORARY_PROJECT_OPERATIONS,
    }


def _r4_source_map_sha256(path_hashes: dict[str, str]) -> str:
    if type(path_hashes) is not dict or not path_hashes:
        _refuse("semver-cache-source-map-binding")
    if any(type(path) is not str or not path or type(digest) is not str
           or not _valid_hex(digest) for path, digest in path_hashes.items()):
        _refuse("semver-cache-source-map-binding")
    ordered = dict(sorted(path_hashes.items()))
    payload = (json.dumps(ordered, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("ascii")
    return _sha(payload)


def _authenticated_source_maps(manifest: object, expected_source_sets: object):
    """Recover candidate/baseline file maps from the authenticated inner manifest."""
    if (type(manifest) is not dict or manifest.get("schema") != 2
            or manifest.get("profile") != "core-rust"
            or type(expected_source_sets) is not dict
            or manifest.get("source_sets") != expected_source_sets
            or type(manifest.get("files")) is not list
            or len(manifest["files"]) > MAX_FILES):
        _refuse("semver-cache-source-set-binding")
    candidate_policy = expected_source_sets.get("candidate")
    baseline_policy = expected_source_sets.get("baseline_runtime")
    if (type(candidate_policy) is not dict or type(baseline_policy) is not dict
            or type(expected_source_sets.get("exclusions")) is not list
            or expected_source_sets["exclusions"] != [
                {"path": ".npmrc", "status": "untransferred-unscanned"},
            ]):
        _refuse("semver-cache-source-set-binding")
    baseline_prefix = baseline_policy.get("namespace")
    if (type(baseline_prefix) is not str or not baseline_prefix
            or baseline_prefix.startswith("/") or "\\" in baseline_prefix):
        _refuse("semver-cache-source-set-binding")
    baseline_prefix += "/"
    candidate: dict[str, str] = {}
    baseline: dict[str, str] = {}
    candidate_sizes: dict[str, int] = {}
    baseline_sizes: dict[str, int] = {}
    all_rows: dict[str, tuple[int, str]] = {}
    for row in manifest["files"]:
        if (type(row) is not dict or set(row) != {"path", "size", "sha256"}
                or type(row.get("path")) is not str
                or type(row.get("size")) is not int or not 0 <= row["size"] <= MAX_SOURCE_FILE_BYTES
                or not _valid_hex(row.get("sha256"))):
            _refuse("semver-cache-source-set-binding")
        name = row["path"]
        path = PurePosixPath(name)
        if (not name or "\\" in name or "\x00" in name or path.is_absolute()
                or path.as_posix() != name or any(part in ("", ".", "..") for part in path.parts)
                or name in all_rows):
            _refuse("semver-cache-source-set-binding")
        all_rows[name] = (row["size"], row["sha256"])
        if name.startswith(baseline_prefix):
            relative = name[len(baseline_prefix):]
            if not relative or relative.startswith(baseline_prefix):
                _refuse("semver-cache-source-set-binding")
            baseline[relative] = row["sha256"]
            baseline_sizes[relative] = row["size"]
        else:
            if (name == ".npmrc" or name.startswith(".devlane/") or name == ".devlane"
                    or ".cargo" in path.parts):
                _refuse("semver-cache-source-set-binding")
            candidate[name] = row["sha256"]
            candidate_sizes[name] = row["size"]
    candidate_locks = set(RUST_V2_LOCKS.values())
    if (set(manifest.get("original_lockfiles", {})) != candidate_locks
            or type(manifest.get("original_lockfiles")) is not dict
            or any(all_rows.get(path, (None, None))[1] != digest
                   for path, digest in manifest["original_lockfiles"].items())):
        _refuse("semver-cache-source-set-locks")
    if (len(candidate) != candidate_policy.get("selected_file_count")
            or sum(candidate_sizes.values()) != candidate_policy.get("selected_bytes")
            or _r4_source_map_sha256(candidate) != candidate_policy.get("selected_map_sha256")
            or len(baseline) != baseline_policy.get("file_count")
            or sum(baseline_sizes.values()) != baseline_policy.get("bytes")
            or _r4_source_map_sha256(baseline) != baseline_policy.get("map_sha256")):
        _refuse("semver-cache-source-set-map")
    selected_manifests = candidate_policy.get("selected_manifest_sha256")
    if (type(selected_manifests) is not dict
            or set(selected_manifests) != set(RUST_V2_LOCKS)
            or any(candidate.get(path) != digest for path, digest in selected_manifests.items())
            or baseline.get("Cargo.toml") != baseline_policy.get("runtime_manifest_sha256")
            or baseline.get("Cargo.lock") != baseline_policy.get("runtime_lock_sha256")):
        _refuse("semver-cache-source-set-manifest")
    return candidate, candidate_sizes, baseline, baseline_sizes


def validate_rust_v2_semver_inputs(
        prepared_root: str | Path, candidate_root: str | Path,
        staged_baseline_root: str | Path, semver_cargo_home: str | Path,
        matrix_cargo_home: str | Path, rust_tools_root: str | Path,
        manifest: object, projection: object,
        preparation: object, generated_lock_record: object,
        authenticated_binding: object, expected_source_sets: object,
        expected_source_maps: object, budget: bounded_registry_io.PhaseBudget,
        *, expected_source_sha: str, expected_control_sha: str,
        expected_projection_sha256: str, mountinfo: str) -> dict[str, Any]:
    """Validate the post-cut Rust v2 preparation before the SemVer worker starts.

    The baseline is read only at its authenticated workspace mount. Candidate files are
    compared with the encrypted manifest after excluding exactly the three locks that the
    trusted offline generator replaced. The receipt remains explicitly ephemeral.
    """
    identity = _validate_input_identity(authenticated_binding)
    if not isinstance(budget, bounded_registry_io.PhaseBudget):
        _refuse("semver-cache-budget-invalid")
    try:
        budget.remaining()
    except bounded_registry_io.Refusal:
        _refuse("semver-cache-budget-closed")
    if (identity["source_commit"] != expected_source_sha
            or identity["control_sha"] != expected_control_sha
            or identity["manifest_projection_sha256"] != expected_projection_sha256):
        _refuse("semver-cache-trusted-binding-mismatch")
    maps = {
        "baseline_source_map_sha256": identity["baseline_source_map_sha256"],
        "candidate_source_map_sha256": identity["candidate_source_map_sha256"],
        "candidate_full_source_map_sha256": identity["candidate_full_source_map_sha256"],
    }
    if (type(expected_source_maps) is not dict or expected_source_maps != maps
            or type(expected_source_sets) is not dict):
        _refuse("semver-cache-source-map-binding")
    candidate_policy = expected_source_sets.get("candidate")
    baseline_policy = expected_source_sets.get("baseline_runtime")
    if (type(candidate_policy) is not dict or type(baseline_policy) is not dict
            or candidate_policy.get("source_revision") != identity["source_commit"]
            or candidate_policy.get("full_map_sha256") is None
            or candidate_policy.get("selected_map_sha256") != identity["candidate_full_source_map_sha256"]
            or baseline_policy.get("map_sha256") != identity["baseline_source_map_sha256"]
            or candidate_policy.get("selected_manifest_sha256") != {
                "Cargo.toml": identity["candidate_root_manifest_sha256"],
                "runtime/Cargo.toml": identity["candidate_runtime_manifest_sha256"],
                "fuzz/Cargo.toml": identity["candidate_fuzz_manifest_sha256"],
            }
            or baseline_policy.get("runtime_manifest_sha256")
            != identity["baseline_runtime_manifest_sha256"]):
        _refuse("semver-cache-source-set-binding")

    prepared = _require_canonical_directory(prepared_root, "semver-cache-root-invalid")
    candidate_root = _require_canonical_directory(candidate_root, "semver-cache-root-invalid")
    baseline = _require_canonical_directory(
        staged_baseline_root, "semver-cache-baseline-missing",
    )
    cargo_home = _require_canonical_directory(semver_cargo_home, "semver-cache-cargo-home-invalid")
    matrix_home = _require_canonical_directory(matrix_cargo_home, "semver-cache-cargo-home-invalid")
    require_readonly_bind_mount(prepared, mountinfo)
    require_readonly_bind_mount(baseline, mountinfo)

    if (type(projection) is not dict or projection.get("schema") != 2
            or projection.get("profile") != "core-rust"
            or projection.get("source_sets") != expected_source_sets
            or projection.get("manifest_projection_sha256") != expected_projection_sha256
            or type(projection.get("manifest_constraints")) is not dict):
        _refuse("semver-cache-projection-binding")
    projection_path = prepared / "projection.json"
    if _read_file(projection_path, MAX_CONTRACT_BYTES) != _canonical(projection) + b"\n":
        _refuse("semver-cache-projection-binding")
    constraints = projection["manifest_constraints"]
    if (set(constraints) != {"candidate", "baseline_runtime"}
            or type(constraints["candidate"]) is not dict
            or not constraints["candidate"].get("constraints")
            or type(constraints["baseline_runtime"]) is not dict
            or constraints["baseline_runtime"].get("constraints") != []):
        _refuse("semver-cache-projection-binding")

    candidate_files, candidate_sizes, baseline_files, baseline_sizes = _authenticated_source_maps(
        manifest, expected_source_sets,
    )
    source_sets = manifest["source_sets"]
    if (manifest.get("source_revision") != identity["source_commit"]
            or manifest.get("fetch_sha256") != identity["manifest_projection_sha256"]
            or _sha(_canonical(manifest["files"])) != manifest.get("tree_sha256")):
        _refuse("semver-cache-source-set-binding")
    original_map = dict(candidate_files)
    lock_paths = set(RUST_V2_LOCKS.values())
    original_nonlock = {path: digest for path, digest in original_map.items() if path not in lock_paths}
    original_nonlock_bytes = sum(size for path, size in candidate_sizes.items() if path not in lock_paths)
    try:
        actual_map, actual_count, actual_bytes = source_map_digest(
            candidate_root, budget, omit_paths=tuple(sorted(lock_paths)),
            required_omitted_paths=tuple(sorted(lock_paths)),
        )
        baseline_map, baseline_count, baseline_bytes = source_map_digest(baseline, budget)
        candidate_runtime_map, _runtime_count, _runtime_bytes = source_map_digest(
            candidate_root / "runtime", budget, omit_root_cargo_lock=True,
        )
    except (OSError, bounded_registry_io.Refusal, Refusal):
        _refuse("semver-cache-source-map-binding")
    if (actual_map != _r4_source_map_sha256(original_nonlock)
            or actual_count != len(original_nonlock)
            or actual_bytes != original_nonlock_bytes
            or baseline_map != identity["baseline_source_map_sha256"]
            or baseline_map != source_sets["baseline_runtime"]["map_sha256"]
            or baseline_count != source_sets["baseline_runtime"]["file_count"]
            or baseline_bytes != source_sets["baseline_runtime"]["bytes"]
            or candidate_runtime_map != identity["candidate_source_map_sha256"]):
        _refuse("semver-cache-source-map-binding")
    if (workspace_version(baseline / "Cargo.toml") != identity["baseline_runtime_version"]
            or workspace_version(candidate_root / "runtime/Cargo.toml")
            != identity["candidate_runtime_version"]
            or _sha(_read_file(baseline / "Cargo.toml", MAX_FILE_BYTES))
            != identity["baseline_runtime_manifest_sha256"]):
        _refuse("semver-cache-workspace-version")
    baseline_lock = _read_file(baseline / "Cargo.lock", MAX_FILE_BYTES)
    try:
        if constraint_resolver.lock_package_rows(baseline_lock):
            _refuse("semver-cache-baseline-external-closure")
    except constraint_resolver.Refusal:
        _refuse("semver-cache-baseline-external-closure")

    prep_fields = {
        "schema", "source_commit", "control_sha", "manifest_projection_sha256",
        "resolver_lock_sha256", "tool_hashes", "tool_provenance_status",
        "packages", "inventory", "baseline_external_packages",
    }
    if (type(preparation) is not dict or set(preparation) != prep_fields
            or preparation.get("schema") != 2
            or preparation.get("source_commit") != identity["source_commit"]
            or preparation.get("control_sha") != identity["control_sha"]
            or preparation.get("manifest_projection_sha256") != identity["manifest_projection_sha256"]
            or not _valid_hex(preparation.get("resolver_lock_sha256"))
            or preparation.get("tool_provenance_status")
            != "binary-hash-bound-origin-unverified"
            or preparation.get("baseline_external_packages") != []):
        _refuse("semver-cache-preparation-binding")
    tool_hashes = preparation.get("tool_hashes")
    expected_tool_hashes = {
        "cargo_sha256", "rustc_sha256", "cargo_version_output_sha256",
        "rustc_version_output_sha256",
    }
    if (type(tool_hashes) is not dict or set(tool_hashes) != expected_tool_hashes
            or any(not _valid_hex(value) for value in tool_hashes.values())):
        _refuse("semver-cache-preparation-binding")
    try:
        packages = registry_prefetch._validate_packages(preparation.get("packages"))
    except (TypeError, ValueError):
        _refuse("semver-cache-preparation-binding")
    if not packages:
        _refuse("semver-cache-candidate-closure-empty")
    registry = _require_canonical_directory(
        prepared / RUST_V2_REGISTRY_ROOT, "semver-cache-prepared-input-missing",
    )
    try:
        inventory = bounded_registry_io.verify_bounded_registry_tree(registry, packages, budget)
        registry_tree_sha256, _registry_files, _registry_bytes = tree_digest(registry, budget)
    except (bounded_registry_io.Refusal, OSError):
        _refuse("semver-cache-registry-invalid")
    recorded_inventory = preparation.get("inventory")
    if (type(recorded_inventory) is not dict
            or set(recorded_inventory) != {"index_bytes", "archive_bytes", "expanded_bytes", "members"}
            or recorded_inventory != inventory):
        _refuse("semver-cache-registry-binding")

    rust_tools = _require_canonical_directory(rust_tools_root, "semver-cache-tool-binding")
    _verify_rust_tool_receipts(rust_tools, tool_hashes, budget)

    config = CARGO_CONFIG
    for home, exact_entries in ((cargo_home, True), (matrix_home, False)):
        try:
            config_path = home / "config.toml"
            if exact_entries and {entry.name for entry in home.iterdir()} != {"config.toml"}:
                _refuse("semver-cache-cargo-home-not-fresh")
            if (config_path.is_symlink()
                    or stat.S_IMODE(config_path.stat().st_mode) & 0o222
                    or _read_file(config_path, 4096) != config):
                _refuse("semver-cache-cargo-config-invalid")
        except OSError:
            _refuse("semver-cache-cargo-config-invalid")
    if _read_file(prepared / "cargo-config.toml", 4096) != config:
        _refuse("semver-cache-cargo-config-invalid")

    lock_fields = {
        "schema", "source_commit", "control_sha", "status",
        "input_projection_sha256", "tool_hashes", "tool_provenance_status",
        "generated_lock_sha256",
    }
    expected_locks = set(RUST_V2_LOCKS.values())
    lock_hashes = (generated_lock_record.get("generated_lock_sha256")
                   if type(generated_lock_record) is dict else None)
    if (type(generated_lock_record) is not dict or set(generated_lock_record) != lock_fields
            or generated_lock_record.get("schema") != 1
            or generated_lock_record.get("source_commit") != identity["source_commit"]
            or generated_lock_record.get("control_sha") != identity["control_sha"]
            or generated_lock_record.get("status") != RUST_V2_GENERATED_LOCK_STATUS
            or generated_lock_record.get("input_projection_sha256")
            != identity["manifest_projection_sha256"]
            or generated_lock_record.get("tool_hashes") != tool_hashes
            or generated_lock_record.get("tool_provenance_status")
            != preparation["tool_provenance_status"]
            or type(lock_hashes) is not dict or set(lock_hashes) != expected_locks
            or any(not _valid_hex(value) for value in lock_hashes.values())):
        _refuse("semver-cache-generated-output-binding")
    available = {(row["name"], row["version"]): row["checksum"] for row in packages}
    for relative in expected_locks:
        lock_bytes = _read_file(candidate_root / relative, MAX_FILE_BYTES)
        if _sha(lock_bytes) != lock_hashes[relative]:
            _refuse("semver-cache-generated-lock-binding")
        try:
            rows = constraint_resolver.lock_package_rows(lock_bytes)
        except constraint_resolver.Refusal:
            _refuse("semver-cache-generated-lock-invalid")
        if any(available.get((row["name"], row["version"])) != row["checksum"]
               for row in rows):
            _refuse("semver-cache-candidate-outside-closure")

    return {
        "schema": "keeldock.rust-v2-semver-execution-inputs.v1",
        "authenticated_binding": identity,
        "expected_source_maps": maps,
        "_registry_package_rows": packages,
        "registry_tree_sha256": registry_tree_sha256,
        "generated_lock_sha256": dict(lock_hashes),
        "generated_lock_status": RUST_V2_GENERATED_LOCK_STATUS,
        "rust_tool_hashes": dict(tool_hashes),
        "rust_tool_provenance_status": preparation["tool_provenance_status"],
        "cargo_net_offline": True,
    }


def fresh_cargo_environment(cargo_home: str | Path) -> dict[str, str]:
    """Return only the offline Cargo settings consumed by the fixed runner."""
    return {"CARGO_HOME": str(cargo_home), "CARGO_NET_OFFLINE": "true"}
