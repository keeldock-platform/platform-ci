"""Source-free external Cargo constraint sanitisation and synthetic-root generation.

This candidate helper accepts already sanitised constraint rows. It never reads Cargo.toml,
source trees, workspace identifiers, package prose, or private dependency edges. The trusted
manifest reader that emits the rows is a separate integration seam and must be reviewed with
its actual source-reader context before composition.
"""
from __future__ import annotations

import hashlib
import fnmatch
import http.server
import json
import os
import posixpath
import re
import secrets
import stat
import tempfile
import threading
import tomllib
import urllib.parse
from functools import lru_cache
from typing import Any
from pathlib import Path, PurePosixPath

SCHEMA = 2
TOOLCHAIN = "1.99.1"
MAX_INPUT_BYTES = 4 * 1024 * 1024
MAX_CONSTRAINTS = 20_000
MAX_NAME = 64
MAX_VERSION_REQ = 128
MAX_FEATURES_PER_PACKAGE = 256
MAX_TOTAL_FEATURES = 100_000
MAX_MANIFEST_PATH_DEPTH = 64
MAX_SYNTHETIC_MANIFEST_BYTES = 8 * 1024 * 1024
MAX_RESOLUTION_ROUNDS = 16
MAX_RESOLVED_PACKAGES = 5_000
MAX_SYNTHETIC_ROOTS = MAX_CONSTRAINTS + MAX_RESOLVED_PACKAGES
MAX_INDEX_PACKAGE_NAMES = MAX_CONSTRAINTS + MAX_RESOLVED_PACKAGES
MAX_LOCAL_INDEX_REQUESTS = MAX_RESOLUTION_ROUNDS * MAX_INDEX_PACKAGE_NAMES
PRODUCTION_MANIFESTS = ("Cargo.toml", "runtime/Cargo.toml", "fuzz/Cargo.toml")
NAME = re.compile(r"[a-z][a-z0-9_-]{0,63}\Z")
OPAQUE_ID = re.compile(r"d[0-9]{6}\Z")
SEMVER_REQ = re.compile(r"[=<>~^*0-9A-Za-z._,+| -]{1,128}\Z")
FEATURE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
COMMIT = re.compile(r"[a-f0-9]{40}\Z")
STABLE_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\Z")
INDEX_VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\Z"
)


class Refusal(ValueError):
    """A safe, bounded refusal code."""


class _LocalSparseIndex:
    """Serve verified official index rows to Cargo over loopback only."""

    def __init__(self, budget: Any, config: bytes):
        self.budget = budget
        self.config = config
        self.index_files: dict[str, Path] = {}
        self.missing: set[str] = set()
        self.bad_request = False
        self.requests = 0
        self.lock = threading.Lock()
        self.active_handlers = 0
        self.stopping = False
        self.handlers_changed = threading.Condition(self.lock)
        owner = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, _format: str, *_args: object) -> None:
                return

            def do_GET(self) -> None:
                owner._handle(self)

            def do_HEAD(self) -> None:
                owner._handle(self, head_only=True)

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.server.timeout = 0.25
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.url = "sparse+http://127.0.0.1:%d/" % self.server.server_address[1]

    def _handle(self, handler: http.server.BaseHTTPRequestHandler, *, head_only: bool = False) -> None:
        with self.handlers_changed:
            if self.stopping:
                handler.close_connection = True
                return
            self.active_handlers += 1
        try:
            handler.connection.settimeout(min(2.0, self.budget.remaining()))
            self._serve(handler, head_only=head_only)
        except Exception:
            self.bad_request = True
            handler.close_connection = True
        finally:
            with self.handlers_changed:
                self.active_handlers -= 1
                self.handlers_changed.notify_all()

    def _serve(self, handler: http.server.BaseHTTPRequestHandler, *, head_only: bool = False) -> None:
        path = ""
        try:
            self.budget.remaining()
        except Exception:
            self.bad_request = True
            payload, status = b"", 503
        else:
            parsed = urllib.parse.urlsplit(handler.path)
            path = urllib.parse.unquote(parsed.path)
            with self.lock:
                self.requests += 1
                if self.requests > MAX_LOCAL_INDEX_REQUESTS:
                    self.bad_request = True
                over_limit = self.requests > MAX_LOCAL_INDEX_REQUESTS
            if (over_limit or parsed.query or parsed.fragment or len(path) > 256
                    or not path.startswith("/") or "\\" in path or "\x00" in path):
                self.bad_request = True
                payload, status = b"", 400
            elif path == "/config.json":
                payload, status = self.config, 200
            else:
                name = self._name_for_index_path(path.lstrip("/"))
                if name is None:
                    self.bad_request = True
                    payload, status = b"", 404
                elif name in self.index_files:
                    self._serve_index_file(handler, self.index_files[name], head_only=head_only)
                    return
                else:
                    with self.lock:
                        self.missing.add(name)
                    payload, status = b"", 404
        try:
            handler.send_response(status)
            handler.send_header("Content-Length", str(len(payload)))
            handler.send_header("Content-Type", "application/json" if path == "/config.json"
                                else "application/octet-stream")
            handler.send_header("Cache-Control", "no-store")
            handler.send_header("Connection", "close")
            handler.end_headers()
            if not head_only and payload:
                self.budget.add_transfer(len(payload))
                handler.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError, OSError):
            self.bad_request = True

    def _serve_index_file(self, handler: http.server.BaseHTTPRequestHandler,
                          path: Path, *, head_only: bool) -> None:
        descriptor = None
        try:
            descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_size < 1
                    or metadata.st_size > 16 * 1024 * 1024):
                raise OSError("index-file")
            handler.send_response(200)
            handler.send_header("Content-Length", str(metadata.st_size))
            handler.send_header("Content-Type", "application/octet-stream")
            handler.send_header("Cache-Control", "no-store")
            handler.send_header("Connection", "close")
            handler.end_headers()
            if head_only:
                return
            with os.fdopen(descriptor, "rb", closefd=True) as source:
                descriptor = None
                remaining = metadata.st_size
                while remaining:
                    self.budget.remaining()
                    chunk = source.read(min(64 * 1024, remaining))
                    if not chunk:
                        raise OSError("index-truncated")
                    self.budget.add_transfer(len(chunk))
                    handler.wfile.write(chunk)
                    remaining -= len(chunk)
                if source.read(1):
                    raise OSError("index-grew")
        except Exception:
            self.bad_request = True
            try:
                handler.close_connection = True
            except Exception:
                pass
        finally:
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    self.bad_request = True

    @staticmethod
    def _name_for_index_path(path: str) -> str | None:
        parts = path.split("/")
        if len(parts) == 2 and parts[0] in ("1", "2"):
            name = parts[1]
        elif len(parts) == 3 and parts[0] == "3":
            name = parts[2]
        elif len(parts) == 3 and len(parts[0]) == 2 and len(parts[1]) == 2:
            name = parts[2]
        else:
            return None
        if (NAME.fullmatch(name) is None or name != name.lower()
                or posixpath.normpath(path) != path):
            return None
        try:
            import registry_prefetch
            if registry_prefetch.crate_index_path(name) != path:
                return None
        except Exception:
            return None
        return name

    def clear_missing(self) -> None:
        with self.lock:
            self.missing.clear()
            self.bad_request = False

    def missing_names(self) -> set[str]:
        with self.lock:
            return set(self.missing)

    def close(self, budget: Any) -> None:
        with self.handlers_changed:
            self.stopping = True
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=min(2.0, budget.remaining(cleanup=True)))
        if self.thread.is_alive():
            _fail("resolver-index-server-cleanup")
        with self.handlers_changed:
            while self.active_handlers:
                wait = min(0.05, budget.remaining(cleanup=True))
                self.handlers_changed.wait(timeout=wait)


def _fail(code: str) -> None:
    raise Refusal(code)


def canonical_json(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def manifest_projection_digest(value: dict[str, Any]) -> str:
    """Hash immutable resolution inputs, excluding commit identity and random row ids.

    A lock-only owner commit changes ``source_commit`` while preserving this projection.
    Generated lock digests are separate output identities.
    """
    body = {key: value[key] for key in (
        "schema", "profile", "toolchain", "target_set", "resolution_mode", "resolver_version",
    )}
    body["constraints"] = [
        {"package": row["package"], "version_req": row["version_req"]}
        for row in value["constraints"]
    ]
    return sha256(canonical_json(body))


def _valid_identity(value: object) -> bool:
    return type(value) is str and HEX.fullmatch(value) is not None


def _valid_commit(value: object) -> bool:
    return type(value) is str and COMMIT.fullmatch(value) is not None


def validate_constraints(value: object, *, expected_source_sha: str,
                          expected_control_sha: str, allow_empty: bool = False) -> dict[str, Any]:
    """Validate privacy-minimised external constraints and all identity bindings."""
    fields = {"schema", "profile", "source_commit", "control_sha", "manifest_projection_sha256",
              "toolchain", "target_set", "resolution_mode", "resolver_version", "constraints"}
    if type(value) is not dict or set(value) != fields:
        _fail("constraint-envelope-shape")
    if (type(value["schema"]) is not int or value["schema"] != SCHEMA
            or value["profile"] != "core-rust"
            or value["source_commit"] != expected_source_sha
            or value["control_sha"] != expected_control_sha
            or not _valid_commit(value["source_commit"])
            or not _valid_commit(value["control_sha"])
            or not _valid_identity(value["manifest_projection_sha256"])):
        _fail("constraint-envelope-binding")
    if (value["toolchain"] != TOOLCHAIN
            or value["target_set"] != ["x86_64-unknown-linux-gnu"]
            or value["resolution_mode"] != "external-all-features-all-targets-v2"
            or value["resolver_version"] not in ("1", "2", "3")):
        _fail("constraint-envelope-matrix")
    rows = value["constraints"]
    if type(rows) is not list or (not rows and not allow_empty) or len(rows) > MAX_CONSTRAINTS:
        _fail("constraint-count")
    seen_ids: set[str] = set()
    keys: set[tuple[str, str, tuple[str, ...], bool]] = set()
    previous: tuple[str, str, tuple[str, ...], bool] | None = None
    for row in rows:
        if type(row) is not dict or set(row) != {"id", "package", "version_req"}:
            _fail("constraint-row-shape")
        ident, package, requirement = row["id"], row["package"], row["version_req"]
        if type(ident) is not str or OPAQUE_ID.fullmatch(ident) is None or ident in seen_ids:
            _fail("constraint-id")
        if (type(package) is not str or NAME.fullmatch(package) is None
                or package.startswith(("keeldock" + "-"))
                or type(requirement) is not str or len(requirement) > MAX_VERSION_REQ
                or SEMVER_REQ.fullmatch(requirement) is None):
            _fail("constraint-value")


        key = (package, requirement, (), True)
        if previous is not None and key < previous:
            _fail("constraint-order")
        if key in keys:
            _fail("constraint-duplicate")
        previous = key
        keys.add(key)
        seen_ids.add(ident)
    if manifest_projection_digest(value) != value["manifest_projection_sha256"]:
        _fail("manifest-projection-digest")
    if len(canonical_json(value)) > MAX_INPUT_BYTES:
        _fail("constraint-bytes")
    return value


def build_constraint_envelope(*, source_commit: str, control_sha: str,
                              constraints: list[dict[str, Any]],
                              resolver_version: str = "2",
                              allow_empty: bool = False) -> dict[str, Any]:
    """Create the exact pre-decrypt envelope after a trusted private manifest scan."""
    if type(source_commit) is not str or not re.fullmatch(r"[a-f0-9]{40}", source_commit):
        _fail("constraint-source-commit")
    if type(control_sha) is not str or not re.fullmatch(r"[a-f0-9]{40}", control_sha):
        _fail("constraint-control-sha")
    body = {
        "schema": SCHEMA,
        "profile": "core-rust",
        "source_commit": source_commit,
        "control_sha": control_sha,
        "toolchain": TOOLCHAIN,
        "target_set": ["x86_64-unknown-linux-gnu"],
        "resolution_mode": "external-all-features-all-targets-v2",
        "resolver_version": resolver_version,
        "constraints": constraints,
    }
    envelope = dict(body)
    envelope["manifest_projection_sha256"] = manifest_projection_digest(envelope)
    return validate_constraints(envelope, expected_source_sha=source_commit,
                                expected_control_sha=control_sha, allow_empty=allow_empty)


def build_manifest_constraint_envelope(*, manifests: dict[str, bytes], source_commit: str,
                                       control_sha: str,
                                       selected_manifests: list[str] | None = None,
                                       allow_empty: bool = False) -> dict[str, Any]:
    """Project exact source manifests to external-only constraints in memory.

    The caller is the trusted source-side reader. The returned envelope contains only crates.io
    names, version requirements, opaque per-row membership ids, public control/source identities,
    and a digest of the sanitized manifest projection. It does not contain manifest paths,
    workspace package names, dependency aliases, local edges, features, or prose.
    """


    manifest_inventory_digest(manifests)
    constraints, resolver_version = _extract_external_constraints(
        manifests, selected_manifests=selected_manifests, allow_empty=allow_empty,
    )
    return build_constraint_envelope(source_commit=source_commit, control_sha=control_sha,
                                     constraints=constraints,
                                     resolver_version=resolver_version, allow_empty=allow_empty)


def manifest_inventory_digest(manifests: dict[str, bytes]) -> str:
    """Validate a complete bounded manifest inventory; callers must keep its digest private."""
    if type(manifests) is not dict or not manifests or len(manifests) > 20_000:
        _fail("manifest-input-count")
    rows = []
    total = 0
    for path, payload in manifests.items():
        pure = PurePosixPath(path) if type(path) is str else None
        if (pure is None or pure.is_absolute() or pure.as_posix() != path
                or any(part in ("", ".", "..") for part in pure.parts)
                or len(pure.parts) > MAX_MANIFEST_PATH_DEPTH
                or pure.name != "Cargo.toml" or type(payload) is not bytes or not payload
                or len(payload) > 4 * 1024 * 1024):
            _fail("manifest-inventory-entry")
        total += len(payload)
        if total > 32 * 1024 * 1024:
            _fail("manifest-input-budget")
        rows.append({"path": path, "size": len(payload), "sha256": sha256(payload)})
    rows.sort(key=lambda row: row["path"])
    return sha256(canonical_json(rows))


def verify_decrypted_manifest_projection(envelope: dict[str, Any], *,
                                         actual_manifests: dict[str, bytes],
                                         actual_source_commit: str,
                                         expected_control_sha: str,
                                         selected_manifests: list[str] | None = None) -> dict[str, str]:
    """Bind the private decrypted manifests to immutable pre-decrypt projection inputs.

    Source commit and manifest projection digest are inputs. Cargo-generated production lock
    hashes are outputs and are deliberately handled by ``lock_output_envelope`` instead.
    """
    submitted = validate_constraints(
        envelope, expected_source_sha=actual_source_commit,
        expected_control_sha=expected_control_sha,
    )
    actual = build_manifest_constraint_envelope(
        manifests=actual_manifests, source_commit=actual_source_commit,
        control_sha=expected_control_sha, selected_manifests=selected_manifests,
    )
    if actual["manifest_projection_sha256"] != submitted["manifest_projection_sha256"]:
        _fail("decrypted-manifest-projection-mismatch")
    return {
        "source_commit": actual_source_commit,
        "control_sha": expected_control_sha,
        "manifest_projection_sha256": actual["manifest_projection_sha256"],
    }


def _extract_external_constraints(manifests: dict[str, bytes], *,
                                  selected_manifests: list[str] | None = None,
                                  allow_empty: bool = False
                                  ) -> tuple[list[dict[str, str]], str]:
    """Flatten declared external dependencies from an in-memory manifest snapshot.

    ``manifests`` is populated by the trusted coordinator from the exact source commit. Paths
    and workspace/package names are used only to resolve local workspace inheritance and path
    dependencies; they are discarded before return. All dependency kinds and target sections
    are scanned. Optional declarations are treated as mandatory synthetic roots downstream.
    """
    if type(manifests) is not dict or not manifests or len(manifests) > 20_000:
        _fail("manifest-input-count")
    parsed: dict[str, dict[str, Any]] = {}
    total_bytes = 0
    for path, payload in manifests.items():
        if (type(path) is not str or not path.endswith("Cargo.toml")
                or PurePosixPath(path).as_posix() != path
                or len(PurePosixPath(path).parts) > MAX_MANIFEST_PATH_DEPTH):
            _fail("manifest-input-path")
        pure = PurePosixPath(path)
        if (pure.is_absolute() or any(part in ("", ".", "..") for part in pure.parts)
                or len(pure.parts) > MAX_MANIFEST_PATH_DEPTH):
            _fail("manifest-input-path")
        if type(payload) is not bytes or not payload:
            _fail("manifest-input-bytes")
        total_bytes += len(payload)
        if total_bytes > 32 * 1024 * 1024:
            _fail("manifest-input-budget")
        try:
            value = tomllib.loads(payload.decode("utf-8", "strict"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError):
            _fail("manifest-parse")
        if type(value) is not dict:
            _fail("manifest-shape")
        if "patch" in value or "replace" in value:
            _fail("manifest-source-override")
        if type(value.get("registries", {})) is not dict or value.get("registries", {}):
            _fail("manifest-registry-override")
        parsed[path] = value

    def dependency_tables(manifest: dict[str, Any]) -> list[dict[str, Any]]:
        tables: list[dict[str, Any]] = []
        for key in ("dependencies", "dev-dependencies", "build-dependencies"):
            value = manifest.get(key, {})
            if type(value) is not dict:
                _fail("manifest-dependency-table")
            tables.append(value)
        targets = manifest.get("target", {})
        if type(targets) is not dict:
            _fail("manifest-target-table")
        for target in targets.values():
            if type(target) is not dict:
                _fail("manifest-target-table")
            for key in ("dependencies", "dev-dependencies", "build-dependencies"):
                value = target.get(key, {})
                if type(value) is not dict:
                    _fail("manifest-target-dependency-table")
                tables.append(value)
        return tables

    package_paths = {path for path, manifest in parsed.items()
                     if type(manifest.get("package")) is dict}
    workspace_glob_states = 0

    def workspace_patterns(root_manifest: dict[str, Any], field: str) -> list[str]:
        workspace = root_manifest.get("workspace")
        values = workspace.get(field, []) if type(workspace) is dict else []
        if type(values) is not list or len(values) > MAX_CONSTRAINTS:
            _fail("workspace-member-shape")
        for pattern in values:
            if (type(pattern) is not str or not pattern or len(pattern.encode("utf-8")) > 4096
                    or "\\" in pattern or "\x00" in pattern
                    or PurePosixPath(pattern).is_absolute()
                    or len(PurePosixPath(pattern).parts) > MAX_MANIFEST_PATH_DEPTH
                    or any(part in ("", ".", "..") for part in pattern.split("/"))):
                _fail("workspace-member-pattern")
        return values

    def member_pattern_matches(relative: str, pattern: str) -> bool:
        nonlocal workspace_glob_states
        if any(token in pattern for token in ("{", "}", "\\")):
            _fail("workspace-member-pattern-unsupported")
        path_parts = PurePosixPath(relative).parts
        pattern_parts = PurePosixPath(pattern).parts
        workspace_glob_states += max(1, len(path_parts) * len(pattern_parts))
        if workspace_glob_states > 2_000_000:
            _fail("workspace-member-selection-budget")

        @lru_cache(maxsize=None)
        def match(path_index: int, pattern_index: int) -> bool:
            if pattern_index == len(pattern_parts):
                return path_index == len(path_parts)
            component = pattern_parts[pattern_index]
            if component == "**":
                if match(path_index, pattern_index + 1):
                    return True
                return path_index < len(path_parts) and match(path_index + 1, pattern_index)
            return (path_index < len(path_parts)
                    and fnmatch.fnmatchcase(path_parts[path_index], component)
                    and match(path_index + 1, pattern_index + 1))

        return match(0, 0)

    roots: dict[str, dict[str, Any]] = {
        path: manifest for path, manifest in parsed.items()
        if type(manifest.get("workspace")) is dict
    }
    if not roots and not package_paths:
        _fail("manifest-root-missing")

    workspace_member_owner: dict[str, str] = {}
    for root_path, root_manifest in roots.items():
        root_dir = PurePosixPath(root_path).parent
        members = workspace_patterns(root_manifest, "members")
        excludes = workspace_patterns(root_manifest, "exclude")
        matched_by_pattern = {pattern: 0 for pattern in members}
        if root_path in package_paths:
            workspace_member_owner[root_path] = root_path
        for package_path in package_paths:
            package_dir = PurePosixPath(package_path).parent
            try:
                relative = package_dir.relative_to(root_dir).as_posix()
            except ValueError:
                continue
            if relative == "." or any(member_pattern_matches(relative, pattern)
                                       for pattern in excludes):
                continue
            matched_patterns = [pattern for pattern in members
                                if member_pattern_matches(relative, pattern)]
            for pattern in matched_patterns:
                matched_by_pattern[pattern] += 1
            if matched_patterns:
                previous = workspace_member_owner.get(package_path)
                if previous is None or len(root_dir.parts) > len(PurePosixPath(previous).parent.parts):
                    workspace_member_owner[package_path] = root_path
                elif previous != root_path and len(root_dir.parts) == len(
                        PurePosixPath(previous).parent.parts):
                    _fail("workspace-member-ambiguous")
        if any(count == 0 and not any(char in pattern for char in "*?[")
               for pattern, count in matched_by_pattern.items()):
            _fail("workspace-member-manifest-missing")



    for package_path in package_paths:
        if package_path not in workspace_member_owner:
            roots[package_path] = parsed[package_path]

    if selected_manifests is None:
        selected_workspace_roots = set(roots)
    else:
        if (type(selected_manifests) is not list or not selected_manifests
                or len(selected_manifests) > MAX_CONSTRAINTS
                or any(type(path) is not str for path in selected_manifests)
                or len(set(selected_manifests)) != len(selected_manifests)):
            _fail("manifest-selected-roots")
        selected_workspace_roots: set[str] = set()
        for selected_path in selected_manifests:
            pure = PurePosixPath(selected_path)
            if (pure.is_absolute() or pure.as_posix() != selected_path
                    or any(part in ("", ".", "..") for part in pure.parts)
                    or selected_path not in parsed):
                _fail("manifest-selected-root-missing")
            if selected_path in roots:
                selected_workspace_roots.add(selected_path)
                continue
            owner_root = workspace_member_owner.get(selected_path)
            if owner_root is None:
                _fail("manifest-selected-root-unresolved")
            selected_workspace_roots.add(owner_root)

    resolver_versions = set()
    for root_path in selected_workspace_roots:
        root_manifest = roots[root_path]
        workspace = root_manifest.get("workspace")
        declared = workspace.get("resolver") if type(workspace) is dict else None
        if declared is not None:
            if type(declared) is not str or declared not in ("1", "2", "3"):
                _fail("manifest-resolver-version")
            resolver_versions.add(declared)
            continue
        package = root_manifest.get("package")
        if type(package) is dict:
            edition = package.get("edition")
            if type(edition) is dict and edition.get("workspace") is True:
                edition = workspace.get("package", {}).get("edition") \
                    if type(workspace.get("package", {})) is dict else None
            if edition is None and type(workspace) is dict:
                package_defaults = workspace.get("package", {})
                if type(package_defaults) is dict:
                    edition = package_defaults.get("edition")
            if edition is None:
                edition = "2015"
            defaults = {"2015": "1", "2018": "2", "2021": "2", "2024": "3"}
            if type(edition) is not str or edition not in defaults:
                _fail("manifest-edition")
            resolver_versions.add(defaults[edition])
        else:

            resolver_versions.add("1")
    if len(resolver_versions) != 1:
        _fail("manifest-resolver-mismatch")
    resolver_version = next(iter(resolver_versions))

    def root_for(manifest_path: str) -> tuple[str, dict[str, Any]]:
        owner = workspace_member_owner.get(manifest_path, manifest_path if manifest_path in roots else None)
        if owner is None or owner not in roots:
            _fail("manifest-workspace-unresolved")
        return owner, roots[owner]

    active_paths: set[str] = set()
    for root_path, root_manifest in roots.items():
        if root_path not in selected_workspace_roots:
            continue
        if root_path in package_paths:
            active_paths.add(root_path)
        active_paths.update(package_path for package_path, owner in workspace_member_owner.items()
                            if owner == root_path)
    if not active_paths:
        _fail("workspace-package-set-empty")

    external: set[tuple[str, str]] = set()
    pending_paths = list(sorted(active_paths))
    visited_paths: set[str] = set()
    while pending_paths:
        path = pending_paths.pop()
        if path in visited_paths:
            continue
        visited_paths.add(path)
        manifest = parsed[path]
        parent = PurePosixPath(path).parent
        root_path, root_manifest = root_for(path)
        workspace = root_manifest.get("workspace")
        workspace_deps = workspace.get("dependencies", {}) if type(workspace) is dict else {}
        if type(workspace_deps) is not dict:
            _fail("workspace-dependencies")

        for table in dependency_tables(manifest):
            for alias, raw in table.items():
                if type(alias) is not str or not alias or len(alias) > MAX_NAME:
                    _fail("dependency-alias")
                if type(raw) is str:
                    spec: dict[str, Any] = {"version": raw}
                elif type(raw) is dict:
                    spec = dict(raw)
                else:
                    _fail("dependency-spec")
                allowed_spec_fields = {
                    "version", "path", "git", "branch", "tag", "rev", "registry", "package",
                    "default-features", "features", "optional", "workspace", "public",
                }
                if set(spec) - allowed_spec_fields:
                    _fail("dependency-spec-field")
                declared_features = spec.get("features", [])
                if (type(declared_features) is not list or len(declared_features) > MAX_FEATURES_PER_PACKAGE
                        or any(type(item) is not str or FEATURE.fullmatch(item) is None
                               for item in declared_features)):
                    _fail("dependency-feature-syntax")
                if ("default-features" in spec and type(spec["default-features"]) is not bool
                        or "optional" in spec and type(spec["optional"]) is not bool
                        or "public" in spec and type(spec["public"]) is not bool):
                    _fail("dependency-boolean-field")
                dependency_base = parent
                if spec.get("workspace") is True:
                    inherited = workspace_deps.get(alias)
                    if type(inherited) is str:
                        inherited_spec: dict[str, Any] = {"version": inherited}
                    elif type(inherited) is dict:
                        inherited_spec = dict(inherited)
                    else:
                        _fail("workspace-dependency-missing")

                    inherited_features = inherited_spec.get("features", [])
                    local_features = spec.get("features", [])
                    if (type(inherited_features) is not list or type(local_features) is not list
                            or len(inherited_features) + len(local_features) > MAX_FEATURES_PER_PACKAGE
                            or any(type(item) is not str or FEATURE.fullmatch(item) is None
                                   for item in inherited_features)):
                        _fail("workspace-feature-shape")
                    inherited_spec.update({key: value for key, value in spec.items() if key != "features"})
                    inherited_spec["features"] = sorted(set(inherited_features) | set(local_features))
                    spec = inherited_spec
                    dependency_base = PurePosixPath(root_path).parent
                if "workspace" in spec and spec.get("workspace") is not True:
                    _fail("workspace-dependency-flag")
                if "git" in spec:
                    _fail("dependency-git-source")
                if "registry" in spec:
                    _fail("dependency-registry-source")
                local_path = spec.get("path")
                if local_path is not None:
                    if type(local_path) is not str or not local_path or PurePosixPath(local_path).is_absolute():
                        _fail("dependency-path")
                    resolved = posixpath.normpath(posixpath.join(dependency_base.as_posix(), local_path))
                    if resolved == ".." or resolved.startswith("../"):
                        _fail("dependency-path-escape")
                    member_manifest = (PurePosixPath(resolved) / "Cargo.toml").as_posix()
                    if (member_manifest not in parsed
                            or type(parsed[member_manifest].get("package")) is not dict):
                        _fail("dependency-path-manifest-missing")
                    pending_paths.append(member_manifest)
                    continue
                package = spec.get("package", alias)
                version_req = spec.get("version")
                if (type(package) is not str or NAME.fullmatch(package) is None
                        or package.startswith(("keeldock" + "-")) or type(version_req) is not str
                        or len(version_req) > MAX_VERSION_REQ or SEMVER_REQ.fullmatch(version_req) is None):
                    _fail("dependency-external-constraint")
                external.add((package, version_req))
                if len(external) > MAX_CONSTRAINTS:
                    _fail("constraint-count")

    ordered = sorted(external)


    identifiers = set()
    rows = []
    for package, requirement in ordered:
        while True:
            ident = "d%06d" % secrets.randbelow(1_000_000)
            if ident not in identifiers:
                identifiers.add(ident)
                break
        rows.append({"id": ident, "package": package, "version_req": requirement})
    if not rows and not allow_empty:
        _fail("external-constraints-empty")
    return rows, resolver_version


def extract_external_constraints(manifests: dict[str, bytes]) -> list[dict[str, str]]:
    """Compatibility view returning only the privacy-minimised rows."""
    rows, _resolver_version = _extract_external_constraints(manifests)
    return rows


def validate_official_index_names(constraints: dict[str, Any], official_index_rows: dict[str, str]) -> None:
    """Bind submitted names to crates.io index names; no inferred/alias names are accepted."""
    if type(official_index_rows) is not dict:
        _fail("official-name-catalogue")
    for row in constraints["constraints"]:
        name = row["package"]
        canonical = official_index_rows.get(name)
        if canonical != name or type(canonical) is not str or NAME.fullmatch(canonical) is None:
            _fail("official-name-mismatch")


def synthetic_manifest(constraints: dict[str, Any],
                       exact_feature_roots: list[dict[str, Any]] | None = None) -> bytes:
    """Build public-only roots; all-feature expansion is exact-version and iterative.

    Range constraints start with default features. After each real Cargo resolution, the trusted
    control reads the official index feature table for every exact selected coordinate and adds
    opaque exact-version roots requesting that version's complete feature set. Re-running Cargo
    discovers optional/build/target transitive dependencies; repeat to a bounded fixed point.
    """
    if exact_feature_roots is None:
        exact_feature_roots = []
    if (type(constraints) is not dict or type(constraints.get("constraints")) is not list
            or not constraints["constraints"] or len(constraints["constraints"]) > MAX_CONSTRAINTS):
        _fail("synthetic-manifest-shape")
    if (type(exact_feature_roots) is not list
            or len(exact_feature_roots) > MAX_RESOLVED_PACKAGES
            or len(constraints["constraints"]) + len(exact_feature_roots) > MAX_SYNTHETIC_ROOTS):
        _fail("exact-feature-root-count")
    original_aliases: set[str] = set()
    for row in constraints["constraints"]:
        if (type(row) is not dict or set(row) != {"id", "package", "version_req"}
                or type(row.get("id")) is not str or OPAQUE_ID.fullmatch(row["id"]) is None):
            _fail("synthetic-manifest-alias")
        alias = row["id"]
        if alias in original_aliases:
            _fail("synthetic-manifest-alias-collision")
        original_aliases.add(alias)
    aliases = set(original_aliases)
    parts = [
        "[package]", 'name = "devlane-constraint-root"', 'version = "0.0.0"',
        'edition = "2024"', 'publish = false', "", "[workspace]",
        'resolver = ' + json.dumps(constraints["resolver_version"]), "",
        "[dependencies]",
    ]
    for row in constraints["constraints"]:
        alias = row["id"]
        package = row["package"]
        requirement = json.dumps(row["version_req"])
        package_literal = json.dumps(package)
        parts.append(
            f'{alias} = {{ package = {package_literal}, version = {requirement}, '
            'default-features = true }'
        )
    seen_exact: set[tuple[str, str]] = set()
    for index, row in enumerate(exact_feature_roots, 1):
        if type(row) is not dict or set(row) != {"package", "version", "features"}:
            _fail("exact-feature-root-shape")
        package, version, features = row["package"], row["version"], row["features"]
        if (type(package) is not str or NAME.fullmatch(package) is None
                or package.startswith(("keeldock" + "-")) or type(version) is not str
                or STABLE_VERSION.fullmatch(version) is None
                or type(features) is not list or len(features) > MAX_FEATURES_PER_PACKAGE
                or any(type(item) is not str or FEATURE.fullmatch(item) is None for item in features)):
            _fail("exact-feature-root-value")
        identity = (package, version)
        if identity in seen_exact:
            _fail("exact-feature-root-duplicate")
        seen_exact.add(identity)
        alias = _exact_feature_alias(index)
        if alias in aliases:
            _fail("synthetic-manifest-alias-collision")
        aliases.add(alias)
        feature_literal = ", ".join(json.dumps(item) for item in sorted(set(features)))
        parts.append(
            f'{alias} = {{ package = {json.dumps(package)}, version = "={version}", '
            f'default-features = true, features = [{feature_literal}] }}'
        )
    payload = ("\n".join(parts) + "\n").encode("ascii")
    if len(payload) > MAX_SYNTHETIC_MANIFEST_BYTES:
        _fail("synthetic-manifest-bytes")
    try:
        parsed = tomllib.loads(payload.decode("ascii"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError):
        _fail("synthetic-manifest-invalid")
    deps = parsed.get("dependencies") if type(parsed) is dict else None
    if type(deps) is not dict or set(deps) != aliases:
        _fail("synthetic-manifest-shape")
    return payload


def _exact_feature_alias(index: int) -> str:
    if type(index) is not int or index < 1 or index > MAX_CONSTRAINTS:
        _fail("exact-feature-root-count")
    return "r%06d" % index


def exact_feature_roots(lock_bytes: bytes,
                        official_features: dict[str, dict[str, list[str]]]) -> list[dict[str, Any]]:
    """Return all-feature roots for exact Cargo-selected crates.io coordinates.

    ``official_features`` must be built from verified official index records keyed by public
    package and exact version. No version-agnostic feature union is safe: a feature supported
    by one release can make Cargo reject a different release selected by a range constraint.
    """
    if type(official_features) is not dict:
        _fail("official-features-catalogue")
    roots = []
    total_features = 0
    for row in lock_package_rows(lock_bytes):
        versions = official_features.get(row["name"])
        if type(versions) is not dict or row["version"] not in versions:
            _fail("official-features-missing")
        features = versions[row["version"]]
        if (type(features) is not list or len(features) > MAX_FEATURES_PER_PACKAGE
                or any(type(item) is not str or FEATURE.fullmatch(item) is None for item in features)):
            _fail("official-features-invalid")
        total_features += len(features)
        if total_features > MAX_TOTAL_FEATURES:
            _fail("resolver-total-feature-count")
        roots.append({"package": row["name"], "version": row["version"],
                      "features": sorted(set(features))})
    return roots


def all_index_feature_names(index_record: dict[str, Any]) -> list[str]:
    """Return explicit plus Cargo implicit optional-dependency feature names."""
    if type(index_record) is not dict:
        _fail("official-features-invalid")
    features = index_record.get("features", {})
    features2 = index_record.get("features2", {})
    dependencies = index_record.get("deps", [])
    if (type(features) is not dict or type(features2) is not dict
            or type(dependencies) is not list):
        _fail("official-features-invalid")
    names = set(features) | set(features2)
    hidden_implicit: set[str] = set()
    for table in (features, features2):
        for values in table.values():
            if type(values) is not list:
                _fail("official-features-invalid")
            for value in values:
                if type(value) is not str:
                    _fail("official-features-invalid")
                if value.startswith("dep:"):
                    hidden_implicit.add(value[4:])
    for dependency in dependencies:
        if type(dependency) is not dict:
            _fail("official-features-invalid")
        if dependency.get("kind") == "dev" or dependency.get("optional") is not True:
            continue
        if dependency.get("optional") is True:


            name = dependency.get("name")
            if type(name) is not str or NAME.fullmatch(name) is None:
                _fail("official-features-invalid")
            if name not in hidden_implicit:
                names.add(name)
    if len(names) > MAX_FEATURES_PER_PACKAGE:
        _fail("resolver-feature-count")
    if any(type(name) is not str or FEATURE.fullmatch(name) is None for name in names):
        _fail("official-features-invalid")
    return sorted(names)


def resolve_feature_fixed_point(envelope: dict[str, Any], resolver,
                                official_records, *, budget_remaining) -> tuple[bytes, list[dict[str, str]], int, bytes]:
    """Drive exact-version feature closure through injected resolver/index boundaries.

    Production supplies Cargo against the verified loopback index and parsed records from the
    official index reader. Contract tests use deterministic fake boundaries and never start Cargo.
    """
    if not callable(resolver) or not callable(official_records) or not callable(budget_remaining):
        _fail("resolver-boundary-invalid")
    exact_roots: list[dict[str, Any]] = []
    previous_coordinates = None
    previous_features = None
    final_lock = b""
    final_rows: list[dict[str, str]] = []
    final_manifest = b""
    for round_index in range(MAX_RESOLUTION_ROUNDS):
        budget_remaining()
        manifest = synthetic_manifest(envelope, exact_roots)
        lock_bytes = resolver(manifest)
        if type(lock_bytes) is not bytes:
            _fail("resolver-lock-output")
        rows = lock_package_rows(lock_bytes)
        if not rows or len(rows) > MAX_RESOLVED_PACKAGES:
            _fail("resolver-package-count")
        wanted_versions: dict[str, set[str]] = {}
        for row in rows:
            wanted_versions.setdefault(row["name"], set()).add(row["version"])
        selected_records = {
            package_name: official_records(package_name, versions)
            for package_name, versions in sorted(wanted_versions.items())
        }
        official_features: dict[str, dict[str, list[str]]] = {}
        for row in rows:
            records = selected_records.get(row["name"])
            indexed = records.get(row["version"]) if type(records) is dict else None
            if (indexed is None or indexed.get("cksum") != row["checksum"]
                    or indexed.get("yanked") is not False):
                _fail("resolver-selected-index-binding")
            official_features.setdefault(row["name"], {})[row["version"]] = all_index_feature_names(indexed)
        next_roots = exact_feature_roots(lock_bytes, official_features)
        coordinates = tuple((row["name"], row["version"], row["checksum"]) for row in rows)
        features = tuple((row["package"], row["version"], tuple(row["features"])) for row in next_roots)
        final_lock, final_rows, final_manifest = lock_bytes, rows, manifest
        if coordinates == previous_coordinates and features == previous_features:
            return final_lock, final_rows, round_index + 1, final_manifest
        previous_coordinates, previous_features = coordinates, features
        exact_roots = next_roots
    _fail("resolver-fixed-point-exhausted")


def validate_tool_version_output(tool: str, output: bytes, error: bytes, returncode: int,
                                 prefix: bytes, required_line: bytes | None) -> None:
    if tool not in ("cargo", "rustc"):
        _fail("resolver-toolchain-name")
    if returncode != 0:
        reason = ("shared-library" if b"error while loading shared libraries" in error
                  else "execution")
    elif len(output) > 4096:
        reason = "size"
    elif not output.startswith(prefix):
        reason = "release"
    elif required_line is not None and required_line not in output.splitlines():
        reason = "host"
    else:
        return
    _fail("resolver-" + tool + "-version-" + reason)


def validate_tool_execution_access(executable: str) -> None:
    path = Path(executable)
    role = path.name if path.name in {"cargo", "rustc"} else "tool"
    prefix = "resolver-" + role + "-execute-"
    try:
        metadata = path.stat(follow_symlinks=False)
        if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & 0o111:
            _fail(prefix + "file-mode")
        if os.statvfs(path).f_flag & os.ST_NOEXEC:
            _fail(prefix + "mount-noexec")
        for parent in path.parents:
            if not os.access(parent, os.X_OK, effective_ids=True):
                _fail(prefix + "ancestor-access")
        if not os.access(path, os.X_OK, effective_ids=True):
            _fail(prefix + "file-access")
    except OSError:
        _fail(prefix + "inspection")


def run_cargo_fixed_point(envelope: dict[str, Any], *, expected_source_sha: str,
                          expected_control_sha: str, cargo: str, rustc: str,
                          scratch_parent: str | Path, deadline_file: str | Path,
                          phase_budget: Any = None) -> dict[str, Any]:
    """Resolve source-free public constraints with real pinned Cargo before the cut.

    Network reads use the existing official-host/TLS/redirect implementation. Cargo has no
    registry egress: a fresh CARGO_HOME replaces crates.io with a loopback sparse index that
    serves only rows already fetched and validated by the bounded official-host reader. The
    generated resolver lock remains private control data, never a production lock or public artifact.
    """
    import bounded_registry_io
    import deadline as deadline_budget
    import registry_prefetch

    value = validate_constraints(envelope, expected_source_sha=expected_source_sha,
                                 expected_control_sha=expected_control_sha)
    parent = Path(scratch_parent)
    if not parent.is_absolute() or parent.is_symlink() or not parent.is_dir():
        _fail("resolver-scratch-parent")
    ancestor = parent
    while True:
        cargo_config = ancestor / ".cargo"
        if cargo_config.exists() or cargo_config.is_symlink():
            _fail("resolver-ancestor-cargo-config")
        if ancestor.parent == ancestor:
            break
        ancestor = ancestor.parent
    for executable in (cargo, rustc):
        path = Path(executable)
        if not path.is_absolute() or path.is_symlink() or not path.is_file():
            _fail("resolver-tool-path")
        validate_tool_execution_access(executable)
    try:
        outer = deadline_budget._read(deadline_file)
        if phase_budget is None:
            budget = bounded_registry_io.PhaseBudget.from_outer_deadlines(
                outer["work_deadline"], outer["work_deadline"] + outer["cleanup_reserve"])
        else:
            if (not isinstance(phase_budget, bounded_registry_io.PhaseBudget)
                    or phase_budget.deadline != float(outer["work_deadline"])
                    or phase_budget.cleanup_deadline != float(
                        outer["work_deadline"] + outer["cleanup_reserve"]
                    )):
                _fail("resolver-shared-budget-binding")
            phase_budget.remaining()
            budget = phase_budget
    except Refusal:
        raise
    except (deadline_budget.DeadlineRefusal, bounded_registry_io.Refusal, OSError, ValueError):
        _fail("resolver-deadline")

    scratch = Path(tempfile.mkdtemp(prefix="cargo-constraints-", dir=str(parent)))
    try:
        root = scratch / "resolver"
        root.mkdir(mode=0o700)
        (root / "src").mkdir(mode=0o700)
        (root / "src" / "lib.rs").write_bytes(b"pub fn source_free_root() {}\n")
    except OSError:
        try:
            bounded_registry_io.remove_tree_bounded(scratch, budget)
        except bounded_registry_io.Refusal:
            _fail("resolver-scratch-cleanup")
        _fail("resolver-scratch-setup")
    manifest_path = root / "Cargo.toml"
    lock_path = root / "Cargo.lock"
    index_cache: set[str] = set()
    index_paths: dict[str, Path] = {}
    total_index_bytes = 0
    index_server: _LocalSparseIndex | None = None

    def parse_index_line(line: bytes, package_name: str) -> dict[str, Any]:
        try:
            item = json.loads(line.decode("utf-8", "strict"),
                              object_pairs_hook=registry_prefetch._unique_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            _fail("resolver-index-parse")
        if type(item) is not dict or item.get("name") != package_name:
            _fail("resolver-index-name")
        version = item.get("vers")
        checksum = item.get("cksum")
        if (type(version) is not str or len(version) > 128
                or INDEX_VERSION.fullmatch(version) is None
                or type(checksum) is not str or HEX.fullmatch(checksum) is None
                or type(item.get("yanked")) is not bool
                or not registry_prefetch._valid_index_fields(item)):
            _fail("resolver-index-record")
        return item

    def official_rows(package_name: str) -> Path:
        nonlocal total_index_bytes
        if package_name in index_cache:
            return index_paths[package_name]
        if len(index_cache) >= MAX_INDEX_PACKAGE_NAMES:
            _fail("resolver-index-package-count")
        budget.remaining()
        url = "https://" + registry_prefetch.INDEX_HOST + "/" + registry_prefetch.crate_index_path(package_name)
        index_path = scratch / ("index-" + hashlib.sha256(package_name.encode("ascii")).hexdigest())
        retained = False
        try:
            size, _digest = bounded_registry_io.fetch_official_to_new_file(
                url, index_path, registry_prefetch.MAX_INDEX_BYTES, budget)
            total_index_bytes += size
            if total_index_bytes > registry_prefetch.MAX_TOTAL_INDEX_BYTES:
                _fail("resolver-index-aggregate-budget")
            versions: set[str] = set()
            with index_path.open("rb") as index_stream:
                for line in bounded_registry_io.read_index_lines(index_stream, budget, count_transfer=False):
                    if not line.endswith(b"\n") or line == b"\n":
                        _fail("resolver-index-line")
                    item = parse_index_line(line, package_name)
                    version = item["vers"]
                    if version in versions:
                        _fail("resolver-index-duplicate")
                    versions.add(version)
            if not versions:
                _fail("official-name-mismatch")
            index_cache.add(package_name)
            index_paths[package_name] = index_path
            retained = True
            if index_server is not None:
                index_server.index_files[package_name] = index_path
            return index_path
        except (registry_prefetch.Refusal, bounded_registry_io.Refusal, OSError):
            _fail("resolver-official-index-refused")
        finally:
            if not retained:
                try:
                    index_path.unlink(missing_ok=True)
                except OSError:
                    _fail("resolver-index-cleanup")
        _fail("resolver-official-index-refused")

    def official_records(package_name: str, wanted_versions: set[str]) -> dict[str, dict[str, Any]]:
        index_path = official_rows(package_name)
        records: dict[str, dict[str, Any]] = {}
        try:
            with index_path.open("rb") as index_stream:
                for line in bounded_registry_io.read_index_lines(
                        index_stream, budget, count_transfer=False, count_index=False):
                    item = parse_index_line(line, package_name)
                    version = item["vers"]
                    if version not in wanted_versions:
                        continue
                    if version in records:
                        _fail("resolver-index-duplicate")
                    records[version] = item
        except (bounded_registry_io.Refusal, OSError):
            _fail("resolver-official-index-refused")
        if set(records) != wanted_versions:
            _fail("resolver-selected-index-version-missing")
        return records

    def tool_version(executable: str, args: list[str], prefix: bytes,
                     required_line: bytes | None = None) -> None:
        output_path = scratch / ("version-" + Path(executable).name)
        error_path = output_path.with_name(output_path.name + "-error")
        try:
            with output_path.open("xb") as output, error_path.open("xb") as error:
                code = bounded_registry_io.run_bounded_process(
                    [executable, *args], budget, cwd=root,
                    env={"PATH": str(Path(executable).parent) + ":/usr/bin:/bin", "LC_ALL": "C",
                         "LD_LIBRARY_PATH": str(Path(executable).parent.parent / "lib")},
                    stdout=output, stderr=error, max_output_bytes=8192,
                )
            version_output = output_path.read_bytes()
            validate_tool_version_output(Path(executable).name, version_output, error_path.read_bytes(),
                                         code, prefix, required_line)
            tool_version_hashes[Path(executable).name] = sha256(version_output)
        except bounded_registry_io.Refusal as error:
            reason = error.args[0] if error.args and error.args[0] in {
                "phase-deadline", "cleanup-deadline", "process-output-limit", "process-start", "cancelled",
                "process-start-permission", "process-start-missing-file", "process-start-process-limit",
                "process-start-memory", "process-start-policy", "process-start-format",
                "process-start-busy", "process-start-os",
            } else "process"
            _fail("resolver-" + Path(executable).name + "-version-" + reason)
        except OSError:
            _fail("resolver-" + Path(executable).name + "-version-io")
        finally:
            try:
                output_path.unlink(missing_ok=True)
                error_path.unlink(missing_ok=True)
            except OSError:
                _fail("resolver-version-cleanup")

    def tool_file_sha256(executable: str) -> str:
        digest = hashlib.sha256()
        try:
            with open(executable, "rb") as source:
                while True:
                    budget.remaining()
                    chunk = source.read(64 * 1024)
                    if not chunk:
                        break
                    digest.update(chunk)
        except OSError:
            _fail("resolver-toolchain-file")
        return digest.hexdigest()

    try:
        tool_version_hashes: dict[str, str] = {}
        tool_version(cargo, ["--version", "--verbose"], b"cargo 1.99.1 ",
                     b"host: x86_64-unknown-linux-gnu")
        tool_version(rustc, ["-vV"], b"rustc 1.99.1 ",
                     b"host: x86_64-unknown-linux-gnu")
        official_names = {}
        for package_name in sorted({row["package"] for row in value["constraints"]}):
            official_rows(package_name)
            official_names[package_name] = package_name
        validate_official_index_names(value, official_names)

        index_server = _LocalSparseIndex(budget, registry_prefetch.LOCAL_INDEX_CONFIG)
        index_server.index_files.update(index_paths)

        def cargo_resolve(manifest_payload: bytes) -> bytes:
            """Run Cargo only against verified rows served from loopback."""
            manifest_path.write_bytes(manifest_payload)
            for attempt in range(MAX_INDEX_PACKAGE_NAMES + 1):
                budget.remaining()
                index_server.clear_missing()
                try:
                    lock_path.unlink(missing_ok=True)
                except OSError:
                    _fail("resolver-stale-lock-cleanup")
                cargo_home = scratch / ("cargo-home-%05d" % attempt)
                try:
                    cargo_home.mkdir(mode=0o700)
                    config = (
                        "[source.crates-io]\n"
                        'replace-with = "devlane-official-snapshot"\n\n'
                        "[source.devlane-official-snapshot]\n"
                        "registry = " + json.dumps(index_server.url) + "\n\n"
                        "[net]\nretry = 0\n"
                    ).encode("ascii")
                    (cargo_home / "config.toml").write_bytes(config)
                    env = {
                        "PATH": str(Path(cargo).parent) + ":/usr/bin:/bin",
                        "LD_LIBRARY_PATH": str(Path(rustc).parent.parent / "lib"),
                        "HOME": str(scratch),
                        "CARGO_HOME": str(cargo_home),
                        "CARGO_TERM_COLOR": "never",
                        "CARGO_NET_RETRY": "0",
                        "CARGO_HTTP_MULTIPLEXING": "false",
                        "LC_ALL": "C",
                        "RUSTC": rustc,
                    }
                    try:
                        bounded_registry_io.run_bounded_process(
                            [cargo, "generate-lockfile", "--manifest-path", str(manifest_path)],
                            budget, cwd=root, env=env,
                        )
                    except bounded_registry_io.Refusal:
                        if index_server.bad_request:
                            _fail("resolver-local-index-protocol")
                        missing = index_server.missing_names()
                        if not missing:
                            _fail("resolver-cargo-refused")
                        for package_name in sorted(missing):
                            if package_name in index_cache:
                                _fail("resolver-local-index-known-row-missing")
                            official_rows(package_name)
                        continue
                    if index_server.bad_request:
                        _fail("resolver-local-index-protocol")
                    missing = index_server.missing_names()
                    if missing:
                        for package_name in sorted(missing):
                            if package_name in index_cache:
                                _fail("resolver-local-index-known-row-missing")
                            official_rows(package_name)
                        continue
                    if (lock_path.is_symlink() or not lock_path.is_file()
                            or lock_path.stat().st_size > 8 * 1024 * 1024):
                        _fail("resolver-lock-output")
                    return lock_path.read_bytes()
                except OSError:
                    _fail("resolver-cargo-home")
                finally:
                    if cargo_home.exists() or cargo_home.is_symlink():
                        try:
                            bounded_registry_io.remove_tree_bounded(cargo_home, budget)
                        except bounded_registry_io.Refusal:
                            _fail("resolver-cargo-home-cleanup")
            _fail("resolver-index-discovery-exhausted")

        final_lock, final_rows, rounds, final_manifest = resolve_feature_fixed_point(
            value, cargo_resolve, official_records, budget_remaining=budget.remaining,
        )
        if lock_path.is_symlink() or not lock_path.is_file():
            _fail("resolver-lock-output")
        return {
            "source_commit": value["source_commit"],
            "control_sha": value["control_sha"],
            "manifest_projection_sha256": value["manifest_projection_sha256"],
            "cargo_version": TOOLCHAIN,
            "resolver_manifest": final_manifest,
            "resolver_lock_sha256": sha256(final_lock),
            "resolver_lock": final_lock,
            "packages": final_rows,
            "rounds": rounds,
            "index_bytes": total_index_bytes,
            "tool_provenance_status": "binary-hash-bound-origin-unverified",
            "tool_hashes": {
                "cargo_sha256": tool_file_sha256(cargo),
                "rustc_sha256": tool_file_sha256(rustc),
                "cargo_version_output_sha256": tool_version_hashes["cargo"],
                "rustc_version_output_sha256": tool_version_hashes["rustc"],
            },
        }
    finally:
        cleanup_failed = False
        if index_server is not None:
            try:
                index_server.close(budget)
            except (bounded_registry_io.Refusal, OSError):
                cleanup_failed = True
        try:
            bounded_registry_io.remove_tree_bounded(scratch, budget)
        except bounded_registry_io.Refusal:
            cleanup_failed = True
        if cleanup_failed:
            _fail("resolver-scratch-cleanup")


def lock_package_rows(lock_bytes: bytes) -> list[dict[str, str]]:
    """Extract only stable crates.io package coordinates from Cargo's generated lock."""
    if type(lock_bytes) is not bytes or not lock_bytes or len(lock_bytes) > 8 * 1024 * 1024:
        _fail("generated-lock-size")
    try:
        value = tomllib.loads(lock_bytes.decode("utf-8", "strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, RecursionError):
        _fail("generated-lock-parse")
    if (type(value) is not dict or type(value.get("version")) is not int
            or value["version"] not in (3, 4) or type(value.get("package")) is not list):
        _fail("generated-lock-shape")
    rows = []
    seen: set[tuple[str, str]] = set()
    for package in value["package"]:
        if type(package) is not dict:
            _fail("generated-lock-package")
        name, version, source, checksum = (package.get("name"), package.get("version"),
                                           package.get("source"), package.get("checksum"))
        if source is None:
            continue
        if (type(name) is not str or NAME.fullmatch(name) is None or name.startswith(("keeldock" + "-"))
                or type(version) is not str or STABLE_VERSION.fullmatch(version) is None
                or source not in ("registry+https://index.crates.io/",
                                 "registry+https://github.com/rust-lang/crates.io-index")
                or type(checksum) is not str or HEX.fullmatch(checksum) is None):
            _fail("generated-lock-coordinate")
        identity = (name, version)
        if identity in seen:
            _fail("generated-lock-duplicate")
        seen.add(identity)
        rows.append({"name": name, "version": version, "checksum": checksum})
        if len(rows) > 20_000:
            _fail("generated-lock-count")
    return sorted(rows, key=lambda item: (item["name"], item["version"]))


def lock_output_envelope(*, input_envelope: dict[str, Any],
                         verified_manifest_binding: dict[str, str],
                         generated_locks: dict[str, bytes],
                         resolver_lock: bytes, cargo_version: str) -> dict[str, Any]:
    """Describe generated private lock outputs without serialising lock bytes publicly.

    ``input_envelope`` and ``verified_manifest_binding`` are immutable generation inputs.
    Cargo-generated lock digests are output identities; they are never compared to historical
    source lock hashes here.
    """
    expected = {"Cargo.lock", "runtime/Cargo.lock", "fuzz/Cargo.lock"}
    if set(generated_locks) != expected:
        _fail("generated-lockset-paths")
    if (type(input_envelope) is not dict
            or type(input_envelope.get("source_commit")) is not str
            or type(input_envelope.get("control_sha")) is not str):
        _fail("generated-lockset-binding")
    value = validate_constraints(
        input_envelope, expected_source_sha=input_envelope["source_commit"],
        expected_control_sha=input_envelope["control_sha"],
    )
    expected_binding = {
        "source_commit": value["source_commit"],
        "control_sha": value["control_sha"],
        "manifest_projection_sha256": value["manifest_projection_sha256"],
    }
    if (type(verified_manifest_binding) is not dict
            or verified_manifest_binding != expected_binding or cargo_version != TOOLCHAIN):
        _fail("generated-lockset-binding")
    lock_hashes = {name: sha256(generated_locks[name]) for name in sorted(expected)}
    for payload in generated_locks.values():
        lock_package_rows(payload)
    resolver_rows = lock_package_rows(resolver_lock)
    resolver_coordinates = {(row["name"], row["version"], row["checksum"]) for row in resolver_rows}
    lock_coordinates: set[tuple[str, str, str]] = set()
    for payload in generated_locks.values():
        lock_coordinates.update((row["name"], row["version"], row["checksum"])
                                for row in lock_package_rows(payload))
    if not lock_coordinates.issubset(resolver_coordinates):
        _fail("resolver-closure-incomplete")
    return {
        "schema": 1,
        "source_commit": value["source_commit"],
        "control_sha": value["control_sha"],
        "manifest_projection_sha256": value["manifest_projection_sha256"],
        "cargo_version": cargo_version,
        "resolver_lock_sha256": sha256(resolver_lock),
        "generated_lock_sha256": lock_hashes,
        "generated_lockset_sha256": sha256(canonical_json(lock_hashes)),
        "generated_lock_output_digest": sha256(canonical_json(lock_hashes)),
        "package_count": len(lock_coordinates),
        "private_lock_payload": True,
        "public_output_allowed": False,
    }
