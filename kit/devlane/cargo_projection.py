"""Sanitised pre-decrypt Cargo package projection policy for the public lane.

This module parses lockfiles and emits only official registry coordinates. It never
invokes Cargo or serialises private manifest text, workspace names, or dependency edges.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tomllib
from pathlib import Path, PurePosixPath


SCHEMA = 1
PROFILE = "core-rust"
TOOLCHAIN = "1.99.1"
TARGETS = ("x86_64-unknown-linux-gnu",)
FEATURE_SETS = ("default", "all")
LOCKS = ("Cargo.lock", "runtime/Cargo.lock", "fuzz/Cargo.lock")
REGISTRIES = frozenset((
    "registry+https://github.com/rust-lang/crates.io-index",
    "registry+https://index.crates.io/",
))
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
GIT_SHA = re.compile(r"[a-f0-9]{40}\Z")
CRATE = re.compile(r"[A-Za-z][A-Za-z0-9_-]{0,63}\Z")
STABLE_COMPONENT = r"(?:0|[1-9][0-9]{0,19})"
STABLE_VERSION = re.compile(STABLE_COMPONENT + r"\." + STABLE_COMPONENT + r"\." + STABLE_COMPONENT + r"\Z")
MAX_LOCK_BYTES = 8 * 1024 * 1024
MAX_PACKAGES = 5000
MAX_PROJECTION_BYTES = 16 * 1024 * 1024


class Refusal(ValueError):
    """A bounded policy refusal; messages are safe codes only."""


def _refuse(code: str) -> None:
    raise Refusal(code)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _valid_identity(value: object) -> bool:
    return type(value) is str and GIT_SHA.fullmatch(value) is not None


def _valid_package(item: object) -> tuple[str, str, str]:
    if type(item) is not dict or set(item) != {"name", "version", "checksum"}:
        _refuse("package-shape")
    name, version, checksum = item["name"], item["version"], item["checksum"]
    if (type(name) is not str or CRATE.fullmatch(name) is None or name != name.lower()
            or name.lower().startswith("private-")
            or type(version) is not str or STABLE_VERSION.fullmatch(version) is None
            or type(checksum) is not str or SHA256.fullmatch(checksum) is None):
        _refuse("package-coordinate")
    return name, version, checksum


def _parse_lock(payload: bytes) -> tuple[list[dict[str, str]], dict[str, object]]:
    if type(payload) is not bytes or not payload or len(payload) > MAX_LOCK_BYTES:
        _refuse("lock-size")
    try:
        value = tomllib.loads(payload.decode("utf-8", "strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError):
        _refuse("lock-parse")
    if (type(value) is not dict or type(value.get("version")) is not int
            or value["version"] not in (3, 4) or type(value.get("package")) is not list):
        _refuse("lock-shape")
    packages: dict[tuple[str, str], str] = {}
    for item in value["package"]:
        if type(item) is not dict:
            _refuse("lock-package")
        name, version, source = item.get("name"), item.get("version"), item.get("source")
        if (type(name) is not str or CRATE.fullmatch(name) is None
                or type(version) is not str or STABLE_VERSION.fullmatch(version) is None):
            _refuse("lock-package-version")
        if source is None:

            continue
        if type(source) is not str or source not in REGISTRIES:
            _refuse("lock-source")
        checksum = item.get("checksum")
        if type(checksum) is not str or SHA256.fullmatch(checksum) is None:
            _refuse("lock-checksum")
        if name.lower().startswith("private-"):
            _refuse("private-registry-name")
        identity = (name, version)
        previous = packages.get(identity)
        if previous is not None and previous != checksum:
            _refuse("lock-coordinate-conflict")
        if previous is not None:
            _refuse("lock-coordinate-duplicate")
        packages[identity] = checksum
    if len(packages) > MAX_PACKAGES:
        _refuse("lock-package-count")
    rows = [{"name": name, "version": version, "checksum": checksum}
            for (name, version), checksum in sorted(packages.items())]
    return rows, value


def _lockset_digest(bindings: dict[str, str]) -> str:
    if set(bindings) != set(LOCKS):
        _refuse("lockset-paths")
    for path, digest in bindings.items():
        parts = PurePosixPath(path).parts
        if (path not in LOCKS or not parts or any(part in ("", ".", "..") for part in parts)
                or type(digest) is not str or SHA256.fullmatch(digest) is None):
            _refuse("lockset-binding")
    return _sha(canonical_json({path: bindings[path] for path in LOCKS}))


def build_projection(lock_bytes: dict[str, bytes], source_sha: str, control_sha: str) -> dict[str, object]:
    """Build a package-only envelope from three already-generated lockfiles."""
    if set(lock_bytes) != set(LOCKS):
        _refuse("lockset-paths")
    if not _valid_identity(source_sha) or not _valid_identity(control_sha):
        _refuse("sha-binding")
    union: dict[tuple[str, str], str] = {}
    bindings: dict[str, str] = {}
    for path in LOCKS:
        rows, _ = _parse_lock(lock_bytes[path])
        bindings[path] = _sha(lock_bytes[path])
        for row in rows:
            key = (row["name"], row["version"])
            prior = union.get(key)
            if prior is not None and prior != row["checksum"]:
                _refuse("lock-coordinate-conflict")
            union[key] = row["checksum"]
    packages = [{"name": name, "version": version, "checksum": checksum}
                for (name, version), checksum in sorted(union.items())]
    projection = {
        "schema": SCHEMA,
        "profile": PROFILE,
        "source_sha": source_sha,
        "control_sha": control_sha,
        "toolchain": TOOLCHAIN,
        "targets": list(TARGETS),
        "feature_sets": list(FEATURE_SETS),
        "lockset_sha256": _lockset_digest(bindings),
        "packages": packages,
    }
    validate_projection(projection, source_sha, control_sha)
    return projection


def validate_projection(value: object, expected_source_sha: str, expected_control_sha: str) -> dict[str, object]:
    fields = {"schema", "profile", "source_sha", "control_sha", "toolchain", "targets",
              "feature_sets", "lockset_sha256", "packages"}
    if type(value) is not dict or set(value) != fields:
        _refuse("projection-shape")
    if (type(value["schema"]) is not int or value["schema"] != SCHEMA or value["profile"] != PROFILE
            or value["source_sha"] != expected_source_sha or value["control_sha"] != expected_control_sha
            or not _valid_identity(value["source_sha"]) or not _valid_identity(value["control_sha"])):
        _refuse("projection-binding")
    if value["toolchain"] != TOOLCHAIN or value["targets"] != list(TARGETS) or value["feature_sets"] != list(FEATURE_SETS):
        _refuse("projection-matrix")
    if type(value["lockset_sha256"]) is not str or SHA256.fullmatch(value["lockset_sha256"]) is None:
        _refuse("projection-lockset")
    packages = value["packages"]
    if type(packages) is not list or len(packages) > MAX_PACKAGES:
        _refuse("projection-packages")
    seen: set[tuple[str, str]] = set()
    last: tuple[str, str] | None = None
    for row in packages:
        item = _valid_package(row)
        if item[:2] in seen or (last is not None and item[:2] <= last):
            _refuse("projection-package-order")
        seen.add(item[:2])
        last = item[:2]
    return value


def parse_projection(payload: bytes, expected_digest: str, expected_source_sha: str,
                     expected_control_sha: str) -> dict[str, object]:
    if (type(payload) is not bytes or not payload or len(payload) > MAX_PROJECTION_BYTES
            or type(expected_digest) is not str or SHA256.fullmatch(expected_digest) is None
            or _sha(payload) != expected_digest):
        _refuse("projection-digest")
    def unique_pairs(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                _refuse("projection-duplicate-key")
            result[key] = value
        return result
    try:
        value = json.loads(payload.decode("ascii", "strict"), object_pairs_hook=unique_pairs)
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        _refuse("projection-parse")
    return validate_projection(value, expected_source_sha, expected_control_sha)


def inspect_source_inputs(root: str | Path) -> None:
    """Refuse Cargo input that could redirect resolution away from crates.io."""
    root = Path(root)
    if root.is_symlink() or not root.is_dir():
        _refuse("source-root")
    source_root = root.resolve(strict=True)
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
        base = Path(current)
        kept = []
        for name in dirs:
            entry = base / name
            if name == ".cargo":
                if entry.is_symlink():
                    _refuse("cargo-config")
                _refuse("cargo-config-directory")
            if entry.is_symlink():
                continue
            kept.append(name)
        dirs[:] = kept
        for name in files:
            entry = base / name
            if entry.is_symlink() and name in ("Cargo.toml", "Cargo.lock"):
                _refuse("source-symlink")
            if name == "Cargo.toml":
                if entry.is_symlink():
                    _refuse("source-symlink")
                _validate_manifest(entry, source_root)


def _validate_local_path(source_root: Path, manifest_dir: Path, value: object) -> None:
    if type(value) is not str or not value:
        _refuse("manifest-path")
    try:
        candidate = manifest_dir / value
        relative = candidate.relative_to(source_root)
        if Path(value).is_absolute():
            _refuse("manifest-path")
    except (OSError, RuntimeError, ValueError):
        _refuse("manifest-path-escape")
    current = source_root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            _refuse("source-symlink")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        _refuse("manifest-path-missing")
    if (not resolved.is_relative_to(source_root) or not resolved.is_dir()
            or not (resolved / "Cargo.toml").is_file()):
        _refuse("manifest-path-escape")


def _validate_manifest(path: Path, source_root: Path | None = None) -> None:
    source_root = source_root or path.parent.resolve(strict=True)
    try:
        value = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError):
        _refuse("manifest-parse")
    if type(value) is not dict or any(key in value for key in ("patch", "replace")):
        _refuse("manifest-source-override")
    targets = value.get("target", {})
    sections = [value.get("dependencies", {}), value.get("dev-dependencies", {}),
                value.get("build-dependencies", {})]
    workspace = value.get("workspace", {})
    if type(workspace) is dict:
        sections.append(workspace.get("dependencies", {}))
        for key in ("members", "default-members"):
            members = workspace.get(key, [])
            if type(members) is not list:
                _refuse("manifest-workspace-members")
            for member in members:
                if type(member) is not str or any(char in member for char in "*?[]"):
                    _refuse("manifest-workspace-glob")
                _validate_local_path(source_root, path.parent, member)
    else:
        workspace = {}
    if type(targets) is not dict:
        _refuse("manifest-targets")
    for target in targets.values():
        if type(target) is not dict:
            _refuse("manifest-targets")
        sections.extend(target.get(section, {}) for section in ("dependencies", "dev-dependencies", "build-dependencies"))
    for section in sections:
        if type(section) is not dict:
            _refuse("manifest-dependencies")
        for spec in section.values():
            if type(spec) is str:
                continue
            if type(spec) is not dict:
                _refuse("manifest-dependency")
            if "git" in spec or "registry" in spec:
                _refuse("manifest-nonregistry-source")
            if "path" in spec:
                _validate_local_path(source_root, path.parent, spec["path"])


def package_rows_from_locks(lock_bytes: dict[str, bytes]) -> list[dict[str, str]]:
    if set(lock_bytes) != set(LOCKS):
        _refuse("lockset-paths")
    union: dict[tuple[str, str], str] = {}
    for path in LOCKS:
        rows, _ = _parse_lock(lock_bytes[path])
        for row in rows:
            key = (row["name"], row["version"])
            previous = union.get(key)
            if previous is not None and previous != row["checksum"]:
                _refuse("lock-coordinate-conflict")
            union[key] = row["checksum"]
    return [{"name": name, "version": version, "checksum": checksum}
            for (name, version), checksum in sorted(union.items())]


def package_rows_from_lock(payload: bytes) -> list[dict[str, str]]:
    rows, _ = _parse_lock(payload)
    return rows


def verify_decrypted_binding(projection: dict[str, object], expected_source_sha: str,
                             expected_control_sha: str, source_revision: str,
                             original_lockfiles: dict[str, str], lock_bytes: dict[str, bytes]) -> None:
    validate_projection(projection, expected_source_sha, expected_control_sha)
    if source_revision != expected_source_sha:
        _refuse("decrypted-source-binding")
    if set(original_lockfiles) != set(LOCKS) or set(lock_bytes) != set(LOCKS):
        _refuse("decrypted-lockset")
    actual_bindings = {path: _sha(lock_bytes[path]) for path in LOCKS}
    if actual_bindings != original_lockfiles or _lockset_digest(actual_bindings) != projection["lockset_sha256"]:
        _refuse("decrypted-lockset-binding")
    if package_rows_from_locks(lock_bytes) != projection["packages"]:
        _refuse("decrypted-package-drift")


def verify_generated_locks(projection: dict[str, object], generated_locks: dict[str, bytes]) -> None:
    """Check offline-generated lock bytes before any source test/build command."""
    if set(generated_locks) != set(LOCKS):
        _refuse("generated-lockset")
    if package_rows_from_locks(generated_locks) != projection["packages"]:
        _refuse("offline-resolution-drift")


def assert_phase_order(events: list[str]) -> None:
    """Strict phase-order contract exercised by source-free policy fixtures."""
    expected = ["projection_fetch", "projection_validate", "glib_seed", "glib_resolve_source_free",
                "projection_fixture_union", "official_index_prefetch", "crate_archive_prefetch",
                "registry_inventory_verify", "network_cut", "network_probe", "decrypt",
                "source_binding_verify", "offline_generate_lock", "locked_metadata_verify",
                "source_execute"]
    if events != expected or events.index("source_execute") < events.index("network_cut"):
        _refuse("phase-order")



