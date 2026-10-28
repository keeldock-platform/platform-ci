import base64
import difflib
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time

try:
    from . import feedback_request
except ImportError:
    _request_path = Path(__file__).resolve(strict=True).parent / "feedback_request.py"
    _request_spec = importlib.util.spec_from_file_location("feedback_request", str(_request_path))
    if _request_spec is None or _request_spec.loader is None:
        raise ImportError("feedback request unavailable")
    feedback_request = importlib.util.module_from_spec(_request_spec)
    sys.modules["feedback_request"] = feedback_request
    try:
        _request_spec.loader.exec_module(feedback_request)
    except BaseException:
        raise ImportError("feedback request unavailable") from None


SCHEMA_VERSION = 1
REQUEST_ENV = "KD_FEEDBACK_REQUEST_B64"
RECIPIENT_ENV = "KD_FEEDBACK_RECIPIENT_SPKI_B64"
NODE_ENV = "KD_NODE_EXECUTABLE"
NODE_VERSION = "24.22.1"
OUTPUT_DIRECTORY = "core-feedback"
FEEDBACK_TEMP_DIRECTORY = "feedback-tmp"
MAX_REQUEST_BYTES = 2048
MAX_KEY_BYTES = 4096
MAX_JSON_BYTES = 128 * 1024
MAX_PACKAGE_JSON_BYTES = 256 * 1024
MAX_LOCK_BYTES = 4 * 1024 * 1024 - 64 * 1024
MAX_RUST_FILE_BYTES = 1024 * 1024
MAX_RUST_PATHS = 256
MAX_PATCH_BYTES = 1024 * 1024
MAX_NODE_INPUT_BYTES = 6 * 1024 * 1024
MAX_CIPHERTEXT_BYTES = 4 * 1024 * 1024
SHA1_RE = re.compile(r"[a-f0-9]{40}\Z")
SHA256_RE = re.compile(r"[a-f0-9]{64}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
PACKAGE_NAME_RE = re.compile(r"^(?:@[a-z0-9][a-z0-9._~-]*\/)?[a-z0-9][a-z0-9._~-]*$")
VERSION_SPEC_RE = re.compile(r"^[0-9A-Za-z.*^~<>=|+ -]{1,128}$")
PACKAGE_ROOTS = (
    Path("crates/host/api"), Path("crates/host/mock"), Path("crates/host/conformance"),
)
FOUNDATION_FUZZ_TARGETS = frozenset(("identifiers", "tool_error_codes", "versions"))
FOUNDATION_FUZZ_TARGET_RE = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\.rs\Z")
MAX_FOUNDATION_FUZZ_TARGETS = 16
FOUNDATION_FUZZ_MANIFESTS = ("fuzz/Cargo.toml", "fuzz/Cargo.lock")
RUST_ROOT_FILES = ("Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rustfmt.toml", "clippy.toml")
DIAGNOSTIC_BASE_GATES = (
    "format", "clippy", "workspace_tests", "api_tests", "mock_tests", "conformance_tests",
)
DIAGNOSTIC_PARSER_GATES = ("parser_format", "parser_clippy", "parser_replay")
DIAGNOSTIC_NODE_GATES = (
    "node_dependency_prepare", "node_dependency_audit", "typescript_typecheck", "typescript_tests",
)
DIAGNOSTIC_GATE_SELECTIONS = (
    DIAGNOSTIC_BASE_GATES, DIAGNOSTIC_BASE_GATES + DIAGNOSTIC_PARSER_GATES,
    DIAGNOSTIC_BASE_GATES + DIAGNOSTIC_PARSER_GATES + DIAGNOSTIC_NODE_GATES,
)
WORKSPACE_PACKAGE_PATHS = ("packages/host-api",)
DEPENDENCY_GROUPS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")
PROFILE_BY_KIND = feedback_request.PROFILE_BY_KIND
PROFILE_BY_CONCERN = feedback_request.PROFILES


class FeedbackRefusal(Exception):
    def __init__(self, reason="feedback_invalid"):
        self.reason = reason if reason in {
            "feedback_invalid", "request_invalid", "recipient_invalid", "manifest_invalid",
            "tool_unavailable", "command_failed", "capture_invalid", "payload_invalid",
            "output_unavailable", "cleanup_incomplete",
        } else "feedback_invalid"
        super().__init__(self.reason)


def _refuse(reason="feedback_invalid"):
    raise FeedbackRefusal(reason)


def _valid_decimal(value):
    return type(value) is str and DECIMAL_RE.fullmatch(value) is not None


def _decode_b64(value, maximum):
    if type(value) is not str or not value or len(value) > ((maximum + 2) // 3) * 4:
        _refuse("request_invalid")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except BaseException:
        _refuse("request_invalid")
    if not decoded or len(decoded) > maximum or base64.b64encode(decoded).decode("ascii") != value:
        _refuse("request_invalid")
    return decoded


def _strict_json(raw, maximum):
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        _refuse("manifest_invalid")

    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=pairs,
                          parse_constant=lambda unused: (_ for _ in ()).throw(ValueError()))
    except BaseException:
        _refuse("manifest_invalid")


def _read_file(path, *, maximum, owner=0):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        _refuse("manifest_invalid")
    descriptor = None
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner or before.st_nlink != 1
                or before.st_size <= 0 or before.st_size > maximum
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | nofollow)
        opened = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_uid != owner
                or opened.st_nlink != 1 or opened.st_size > maximum):
            raise ValueError
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(8192, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ValueError
            chunks.append(chunk)
        after = os.fstat(descriptor)
        named = path.lstat()
        if (total != opened.st_size or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or after.st_uid != owner or after.st_nlink != 1
                or after.st_size > maximum or after.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise ValueError
        return b"".join(chunks)
    except BaseException:
        _refuse("manifest_invalid")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _expected_manifest(source):
    root = _strict_json(_read_file(source / "package.json", maximum=MAX_PACKAGE_JSON_BYTES),
                        MAX_PACKAGE_JSON_BYTES)
    if type(root) is not dict or type(root.get("name")) is not str or type(root.get("version")) is not str:
        _refuse("manifest_invalid")
    if any(key in root for key in ("overrides", "resolutions", "bundleDependencies", "bundledDependencies")):
        _refuse("manifest_invalid")
    workspaces = root.get("workspaces")
    if type(workspaces) is dict:
        if set(workspaces) != {"packages"}:
            _refuse("manifest_invalid")
        workspaces = workspaces.get("packages")
    if (type(workspaces) is not list or len(workspaces) != 1
            or workspaces[0] not in ("packages/*", "packages/host-api")):
        _refuse("manifest_invalid")
    expected_paths = []
    for path in WORKSPACE_PACKAGE_PATHS:
        if any(pattern == path or pattern == "packages/*" and path.startswith("packages/")
               for pattern in workspaces):
            expected_paths.append(path)
    if len(expected_paths) != len(WORKSPACE_PACKAGE_PATHS):
        _refuse("manifest_invalid")
    root_expected = {
        "name": root["name"], "version": root["version"],
        "workspaces": workspaces,
    }
    for group in DEPENDENCY_GROUPS:
        if group in root:
            root_expected[group] = root[group]
    workspace_expected = []
    for workspace_path in expected_paths:
        package = _strict_json(
            _read_file(source / workspace_path / "package.json", maximum=MAX_PACKAGE_JSON_BYTES),
            MAX_PACKAGE_JSON_BYTES,
        )
        if type(package) is not dict or type(package.get("name")) is not str or type(package.get("version")) is not str:
            _refuse("manifest_invalid")
        if any(key in package for key in ("overrides", "resolutions", "bundleDependencies", "bundledDependencies")):
            _refuse("manifest_invalid")
        expected = {"path": workspace_path, "name": package["name"], "version": package["version"]}
        for group in DEPENDENCY_GROUPS:
            if group in package:
                expected[group] = package[group]
        workspace_expected.append(expected)
    _validate_dependency_sources(root_expected, workspace_expected)
    return {"root": root_expected, "workspaces": workspace_expected}


def _validate_dependency_sources(root, workspaces):
    workspace_names = {item["name"] for item in workspaces}
    for manifest in (root, *workspaces):
        for group in DEPENDENCY_GROUPS:
            dependencies = manifest.get(group, {})
            if type(dependencies) is not dict or len(dependencies) > 512:
                _refuse("manifest_invalid")
            for name, spec in dependencies.items():
                if (type(name) is not str or len(name) > 214 or not PACKAGE_NAME_RE.fullmatch(name)
                        or ".." in name or type(spec) is not str or len(spec) > 128):
                    _refuse("manifest_invalid")
                if name in workspace_names and spec.startswith("workspace:"):
                    if re.fullmatch(r"workspace:(?:\*|\^|~|[0-9][0-9A-Za-z.+-]*)", spec) is None:
                        _refuse("manifest_invalid")
                elif not VERSION_SPEC_RE.fullmatch(spec):
                    _refuse("manifest_invalid")
        if any(key in manifest for key in ("overrides", "resolutions", "bundleDependencies", "bundledDependencies")):
            _refuse("manifest_invalid")


def _validated_fuzz_rust_paths(source):
    directory = source / "fuzz/fuzz_targets"
    try:
        directory_info = directory.lstat()
        if (not stat.S_ISDIR(directory_info.st_mode) or stat.S_ISLNK(directory_info.st_mode)
                or directory_info.st_uid != 0
                or directory_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            _refuse("manifest_invalid")
        with os.scandir(directory) as iterator:
            names = sorted(entry.name for entry in iterator)
    except OSError:
        _refuse("manifest_invalid")
    if (not 1 <= len(names) <= MAX_FOUNDATION_FUZZ_TARGETS
            or not FOUNDATION_FUZZ_TARGETS.issubset({name[:-3] for name in names})
            or any(len(name[:-3]) > 64 or FOUNDATION_FUZZ_TARGET_RE.fullmatch(name) is None
                   for name in names)):
        _refuse("manifest_invalid")
    paths = []
    for relative in ("fuzz/src/main.rs",) + tuple("fuzz/fuzz_targets/" + name for name in names):
        target = source / relative
        try:
            info = target.lstat()
        except OSError:
            _refuse("manifest_invalid")
        if (not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode)
                or info.st_uid != 0 or info.st_nlink != 1
                or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
            _refuse("manifest_invalid")
        paths.append(relative)
    return tuple(paths)


def _reviewed_rust_paths(source, *, include_fuzz=False):
    if type(include_fuzz) is not bool:
        _refuse("manifest_invalid")
    paths = []
    for package_root in PACKAGE_ROOTS:
        source_directory = source / package_root / "src"
        try:
            source_info = source_directory.lstat()
        except OSError:
            _refuse("manifest_invalid")
        if (not stat.S_ISDIR(source_info.st_mode) or stat.S_ISLNK(source_info.st_mode)
                or source_info.st_uid != 0 or source_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            _refuse("manifest_invalid")
        for folder in ("src", "tests"):
            directory = source / package_root / folder
            try:
                with os.scandir(directory) as iterator:
                    entries = sorted(iterator, key=lambda item: item.name)
            except FileNotFoundError:
                continue
            except OSError:
                _refuse("manifest_invalid")
            stack = [(directory, entries)]
            while stack:
                current, values = stack.pop()
                for entry in values:
                    target = Path(entry.path)
                    try:
                        info = target.lstat()
                    except OSError:
                        _refuse("manifest_invalid")
                    if (stat.S_ISLNK(info.st_mode) or info.st_uid != 0
                            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
                        _refuse("manifest_invalid")
                    if stat.S_ISDIR(info.st_mode):
                        try:
                            with os.scandir(target) as iterator:
                                child_entries = sorted(iterator, key=lambda item: item.name)
                        except OSError:
                            _refuse("manifest_invalid")
                        stack.append((target, child_entries))
                    elif target.suffix == ".rs" and target.name != "build.rs":
                        relative = target.relative_to(source).as_posix()
                        if (not stat.S_ISREG(info.st_mode) or len(relative) > 256
                                or relative in paths or info.st_nlink != 1):
                            _refuse("manifest_invalid")
                        paths.append(relative)
                        if len(paths) > MAX_RUST_PATHS:
                            _refuse("manifest_invalid")
                    elif not stat.S_ISREG(info.st_mode) and not stat.S_ISDIR(info.st_mode):
                        _refuse("manifest_invalid")
    if include_fuzz:
        fuzz_paths = _validated_fuzz_rust_paths(source)
        if set(paths) & set(fuzz_paths):
            _refuse("manifest_invalid")
        paths.extend(fuzz_paths)
    if not paths or len(paths) > MAX_RUST_PATHS:
        _refuse("manifest_invalid")
    return tuple(sorted(paths))


def validate_dispatch(kind, environ, *, now=None):
    if type(kind) is not str or kind not in PROFILE_BY_KIND:
        _refuse("request_invalid")
    current = int(time.time()) if now is None else now
    try:
        request_bytes = _decode_b64(environ.get(REQUEST_ENV), MAX_REQUEST_BYTES)
        spki_der = _decode_b64(environ.get(RECIPIENT_ENV), MAX_KEY_BYTES)
        request = feedback_request.parse_request(request_bytes, now=current)
    except FeedbackRefusal:
        raise
    except BaseException:
        _refuse("request_invalid")
    profile = PROFILE_BY_KIND[kind]
    workflow_ref = environ.get("GITHUB_WORKFLOW_REF", "")
    repository_slug = environ.get("GITHUB_REPOSITORY", "")
    run_id = environ.get("GITHUB_RUN_ID", "")
    if (request.get("kind") != profile["kind"] or request.get("concern") != profile["concern"]
            or request.get("workflow_path") != profile["workflow_path"]
            or request.get("workflow_ref") != feedback_request.WORKFLOW_REF
            or request.get("ci_repository_id") != environ.get("GITHUB_REPOSITORY_ID")
            or request.get("repository_id") != environ.get("SOURCE_REPOSITORY_ID")
            or request.get("source_sha") != environ.get("CORE_CONTRACT_REVIEWED_SOURCE_SHA")
            or request.get("base_sha") != environ.get("CORE_CONTRACT_REVIEWED_BASE_SHA")
            or request.get("base_branch") != environ.get("CORE_CONTRACT_REVIEWED_BASE_BRANCH")
            or request.get("reviewed_diff_sha256") != environ.get("CORE_CONTRACT_REVIEWED_DIFF_SHA256")
            or request.get("control_sha") != environ.get("CI_SHA")
            or environ.get("GITHUB_SHA") != environ.get("CI_SHA")
            or environ.get("GITHUB_REF") != "refs/heads/main"
            or environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
            or workflow_ref != repository_slug + "/" + profile["workflow_path"] + "@refs/heads/main"
            or environ.get("GITHUB_JOB") != profile["producer_job"]
            or not _valid_decimal(run_id)
            or environ.get("GITHUB_RUN_ATTEMPT") != "1"
            or len(spki_der) > MAX_KEY_BYTES
            or hashlib.sha256(spki_der).hexdigest() != request.get("recipient_fingerprint")):
        _refuse("request_invalid")
    context = {
        "request_id": request["request_id"],
        "nonce": request["nonce"],
        "recipient_fingerprint": request["recipient_fingerprint"],
        "concern": profile["concern"],
        "repository_id": request["repository_id"],
        "source_sha": request["source_sha"],
        "base_sha": request["base_sha"],
        "control_sha": request["control_sha"],
        "base_branch": request["base_branch"],
        "reviewed_diff_sha256": request["reviewed_diff_sha256"],
        "workflow_ref": request["workflow_ref"],
        "run_id": run_id,
        "producer_job": profile["producer_job"],
        "run_attempt": 1,
        "expiry": request["expiry"],
    }
    if profile["profile_id"] != 1:
        context["kind"] = profile["kind"]
        context = {
            "request_id": context["request_id"], "nonce": context["nonce"],
            "recipient_fingerprint": context["recipient_fingerprint"],
            "concern": context["concern"], "kind": context["kind"],
            **{name: value for name, value in context.items()
               if name not in ("request_id", "nonce", "recipient_fingerprint", "concern", "kind")},
        }
    return {"profile": dict(profile), "request": request, "context": context, "spki_der": spki_der}


def resolve_node(environ, *, require_npm=False):
    candidate = environ.get(NODE_ENV, "")
    cache = environ.get("RUNNER_TOOL_CACHE", "")
    try:
        node = Path(candidate)
        root = Path(cache).resolve(strict=True) / "node" / NODE_VERSION
        resolved = node.resolve(strict=True)
        info = resolved.lstat()
    except BaseException:
        _refuse("tool_unavailable")
    if (not node.is_absolute() or node != resolved or root not in resolved.parents
            or not stat.S_ISREG(info.st_mode) or not info.st_mode & stat.S_IXUSR
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        _refuse("tool_unavailable")
    environment = {"PATH": str(resolved.parent), "HOME": "/var/empty", "LANG": "C", "LC_ALL": "C"}
    try:
        result = subprocess.run((str(resolved), "--version"), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=environment,
                                timeout=10, close_fds=True, check=False)
    except BaseException:
        _refuse("tool_unavailable")
    if result.returncode != 0 or result.stdout != b"v" + NODE_VERSION.encode("ascii") + b"\n" or result.stderr:
        _refuse("tool_unavailable")
    if not require_npm:
        return resolved, None
    npm_cli = resolved.parent.parent / "lib/node_modules/npm/bin/npm-cli.js"
    try:
        npm_info = npm_cli.lstat()
        resolved_npm = npm_cli.resolve(strict=True)
    except OSError:
        _refuse("tool_unavailable")
    if (not stat.S_ISREG(npm_info.st_mode) or npm_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or root not in resolved_npm.parents):
        _refuse("tool_unavailable")
    return resolved, resolved_npm


def _encrypt_payload(encryptor, input_record, node):
    raw = json.dumps(input_record, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    if len(raw) > MAX_NODE_INPUT_BYTES:
        _refuse("payload_invalid")
    try:
        result = subprocess.run((str(node), str(encryptor)), input=raw, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                env={"PATH": str(node.parent), "HOME": "/var/empty", "LANG": "C", "LC_ALL": "C"},
                                timeout=60, close_fds=True, check=False)
    except BaseException:
        _refuse("payload_invalid")
    if (result.returncode != 0 or result.stderr or not result.stdout
            or len(result.stdout) > MAX_CIPHERTEXT_BYTES or result.stdout[:4] != b"KDLE"):
        _refuse("payload_invalid")
    return bytes(result.stdout)


def _write_ciphertext(runner_temp, member_name, payload):
    if (member_name not in {profile["member_name"] for profile in PROFILE_BY_KIND.values()}
            or type(payload) is not bytes or not 1 <= len(payload) <= MAX_CIPHERTEXT_BYTES):
        _refuse("output_unavailable")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        _refuse("output_unavailable")
    parent_fd = directory_fd = file_fd = None
    directory_created = False
    file_created = False
    try:
        parent_fd = os.open(runner_temp, os.O_RDONLY | directory_flag | nofollow)
        parent = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid == 0:
            raise ValueError
        os.mkdir(OUTPUT_DIRECTORY, 0o700, dir_fd=parent_fd)
        directory_created = True
        directory_fd = os.open(OUTPUT_DIRECTORY, os.O_RDONLY | directory_flag | nofollow, dir_fd=parent_fd)
        os.fchown(directory_fd, 0, 0)
        os.fchmod(directory_fd, 0o700)
        directory = os.fstat(directory_fd)
        if not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0 or stat.S_IMODE(directory.st_mode) != 0o700:
            raise ValueError
        file_fd = os.open(member_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                          0o600, dir_fd=directory_fd)
        file_created = True
        os.fchown(file_fd, 0, 0)
        os.fchmod(file_fd, 0o400)
        offset = 0
        while offset < len(payload):
            count = os.write(file_fd, payload[offset:])
            if count <= 0:
                raise OSError
            offset += count
        os.fsync(file_fd)
        opened = os.fstat(file_fd)
        named = os.stat(member_name, dir_fd=directory_fd, follow_symlinks=False)
        if ((opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0 or opened.st_nlink != 1
                or opened.st_size != len(payload) or stat.S_IMODE(opened.st_mode) != 0o400):
            raise ValueError
        os.fsync(directory_fd)
        return {
            "member_name": member_name,
            "ciphertext_digest": hashlib.sha256(payload).hexdigest(),
            "member_size": len(payload),
        }
    except BaseException:
        if file_created and directory_fd is not None:
            try:
                os.unlink(member_name, dir_fd=directory_fd)
            except OSError:
                pass
        if directory_created and parent_fd is not None:
            try:
                os.rmdir(OUTPUT_DIRECTORY, dir_fd=parent_fd)
            except OSError:
                pass
        _refuse("output_unavailable")
    finally:
        for descriptor in (file_fd, directory_fd, parent_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def producer_receipt(dispatch, ciphertext_info):
    profile = dispatch["profile"]
    context_fields = (
        ("request_id", "nonce", "recipient_fingerprint", "concern", "repository_id", "source_sha",
         "base_sha", "control_sha", "base_branch", "reviewed_diff_sha256", "workflow_ref", "run_id",
         "producer_job", "run_attempt", "expiry")
        if profile["profile_id"] == 1 else
        ("request_id", "nonce", "recipient_fingerprint", "concern", "kind", "repository_id", "source_sha",
         "base_sha", "control_sha", "base_branch", "reviewed_diff_sha256", "workflow_ref", "run_id",
         "producer_job", "run_attempt", "expiry")
    )
    record = {name: dispatch["context"][name] for name in context_fields}
    record.update({
        "schema_version": SCHEMA_VERSION,
        "status": "encrypted",
        "job_name": profile["producer_job"],
        **ciphertext_info,
    })
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _make_worker_directory(path, worker_uid, primary_gid):
    try:
        os.mkdir(path, 0o700)
        os.chown(path, worker_uid, primary_gid)
        os.chmod(path, 0o700)
        info = path.lstat()
    except BaseException:
        _refuse("output_unavailable")
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != worker_uid or info.st_gid != primary_gid
            or stat.S_IMODE(info.st_mode) != 0o700):
        _refuse("output_unavailable")


def _write_worker_file(path, payload, worker_uid, primary_gid):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        _refuse("output_unavailable")
    descriptor = None
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
        os.fchown(descriptor, worker_uid, primary_gid)
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            count = os.write(descriptor, payload[offset:])
            if count <= 0:
                raise OSError
            offset += count
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        named = path.lstat()
        if ((opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_uid != worker_uid
                or opened.st_gid != primary_gid or opened.st_nlink != 1
                or opened.st_size != len(payload) or stat.S_IMODE(opened.st_mode) != 0o600):
            raise ValueError
    except BaseException:
        _refuse("output_unavailable")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _copy_reviewed_files(source, destination, relative_paths, worker_uid, primary_gid):
    _make_worker_directory(destination, worker_uid, primary_gid)
    for relative in relative_paths:
        rel = Path(relative)
        if rel.is_absolute() or any(part in ("", ".", "..") for part in rel.parts):
            _refuse("manifest_invalid")
        current = destination
        for part in rel.parts[:-1]:
            current = current / part
            try:
                current.lstat()
            except FileNotFoundError:
                _make_worker_directory(current, worker_uid, primary_gid)
            except OSError:
                _refuse("output_unavailable")
        payload = _read_file(source / rel, maximum=MAX_RUST_FILE_BYTES if rel.suffix in (".rs", ".ts")
                             else MAX_PACKAGE_JSON_BYTES)
        _write_worker_file(current / rel.name, payload, worker_uid, primary_gid)


def _read_worker_file(path, worker_uid, maximum):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        _refuse("capture_invalid")
    descriptor = None
    try:
        before = path.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != worker_uid or before.st_nlink != 1
                or before.st_size <= 0 or before.st_size > maximum
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | nofollow)
        opened = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_uid != worker_uid
                or opened.st_nlink != 1 or opened.st_size > maximum):
            raise ValueError
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(8192, maximum + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise ValueError
            chunks.append(chunk)
        after = os.fstat(descriptor)
        named = path.lstat()
        if (total != opened.st_size or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or after.st_uid != worker_uid or after.st_nlink != 1):
            raise ValueError
        return b"".join(chunks)
    except BaseException:
        _refuse("capture_invalid")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _node_environment(environment, node, worker_storage):
    home = environment.get("HOME", "")
    if type(home) is not str or not Path(home).is_absolute():
        _refuse("tool_unavailable")
    return {
        "PATH": str(node.parent) + ":/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": home,
        "TMPDIR": str(worker_storage / FEEDBACK_TEMP_DIRECTORY),
        "LANG": "C",
        "LC_ALL": "C",
        "npm_config_cache": str(worker_storage / "npm-cache"),
        "npm_config_registry": "https://registry.npmjs.org/",
        "npm_config_userconfig": "/dev/null",
        "npm_config_globalconfig": "/dev/null",
        "npm_config_ignore_scripts": "true",
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_fetch_retries": "0",
        "npm_config_fetch_timeout": "30000",
        "npm_config_update_notifier": "false",
    }


def _run_worker(rust, argv, worker_uid, environment, python_executable, capability, stage, deadline,
                *, allow_nonzero_capture=False):
    command = tuple(str(part) for part in argv)
    if any(not part or "\x00" in part for part in command):
        _refuse("capture_invalid")
    try:
        result = rust._run_worker_command(
            command, worker_uid, environment, python_executable, capability,
            stage=stage, deadline=deadline, timeout=120,
            allow_nonzero_capture=allow_nonzero_capture,
        )
    except BaseException as error:
        if getattr(error, "reason", None) == "cleanup_incomplete":
            _refuse("cleanup_incomplete")
        if getattr(error, "reason", None) == "capture_invalid":
            _refuse("capture_invalid")
        _refuse("command_failed")
    stdout_limit = rust.MAX_CAPTURE_BYTES if allow_nonzero_capture else 32_768
    if (type(result.returncode) is not int or type(result.stdout) is not bytes
            or type(result.stderr) is not bytes or len(result.stdout) > stdout_limit
            or len(result.stderr) > 32_768):
        _refuse("capture_invalid")
    return result


def _source_root_files(*, include_fuzz=False):
    if type(include_fuzz) is not bool:
        _refuse("manifest_invalid")
    paths = list(RUST_ROOT_FILES)
    for package_root in PACKAGE_ROOTS:
        paths.append((package_root / "Cargo.toml").as_posix())
    if include_fuzz:
        paths.extend(FOUNDATION_FUZZ_MANIFESTS)
    return tuple(paths)


def _rust_format_patch(source, formatted, reviewed_paths, worker_uid):
    chunks = []
    total = 0
    for relative in reviewed_paths:
        before = _read_file(source / relative, maximum=MAX_RUST_FILE_BYTES)
        after = _read_worker_file(formatted / relative, worker_uid, MAX_RUST_FILE_BYTES)
        if before == after:
            continue
        try:
            before_text = before.decode("utf-8", "strict").splitlines(keepends=True)
            after_text = after.decode("utf-8", "strict").splitlines(keepends=True)
        except UnicodeError:
            _refuse("payload_invalid")
        body = "".join(difflib.unified_diff(
            before_text, after_text, fromfile="a/" + relative, tofile="b/" + relative,
            lineterm="\n",
        ))
        if not body.endswith("\n"):
            body += "\n"
        chunk = ("diff --git a/" + relative + " b/" + relative + "\n" + body).encode("utf-8")
        total += len(chunk)
        if total > MAX_PATCH_BYTES:
            _refuse("payload_invalid")
        chunks.append(chunk)
    payload = b"".join(chunks)
    if not payload:
        _refuse("payload_invalid")
    return payload


def run_source_profile(dispatch, source, worker_storage, worker_uid, environment, tools,
                       host_toolchain, capability, rust, reviewed, deadline, node, npm_cli,
                       *, validated_fuzz_workspace=False):
    kind = dispatch["profile"]["kind"]
    if (type(validated_fuzz_workspace) is not bool
            or validated_fuzz_workspace and kind not in ("rust_patch", "build_diagnostics")):
        _refuse("manifest_invalid")
    if kind == "lock":
        _refuse("request_invalid")

    if kind == "rust_patch":
        reviewed_paths = _reviewed_rust_paths(source, include_fuzz=validated_fuzz_workspace)
        copy_paths = _source_root_files(include_fuzz=validated_fuzz_workspace) + reviewed_paths
        formatted = worker_storage / "feedback-rust-format"
        _copy_reviewed_files(source, formatted, copy_paths, worker_uid, capability.PROBE_PRIMARY_GID)
        commands = [("feedback_format", (
            tools["cargo"], "fmt", "--manifest-path", str(formatted / "Cargo.toml"), "--all",
        ))]
        if validated_fuzz_workspace:
            commands.append(("feedback_parser_format", (
                tools["cargo"], "--locked", "--offline", "fmt", "--manifest-path",
                str(formatted / "fuzz/Cargo.toml"), "--all",
            )))
        try:
            os.chdir(formatted)
            for stage, argv in commands:
                result = _run_worker(
                    rust, argv, worker_uid, environment, host_toolchain["python"], capability,
                    stage, deadline, allow_nonzero_capture=True,
                )
                if result.returncode != 0:
                    _refuse("command_failed")
        finally:
            try:
                os.chdir(source)
            except OSError:
                _refuse("cleanup_incomplete")
        patch = _rust_format_patch(source, formatted, reviewed_paths, worker_uid)
        return {"payload_bytes": patch, "expected_manifest": None,
                "reviewed_rust_paths": list(reviewed_paths), "source_result": "command_completed"}

    _refuse("request_invalid")


def build_diagnostic_payload(outcome):
    if type(outcome) is not dict:
        _refuse("capture_invalid")
    failed = outcome.get("failed_stage")
    selected = outcome.get("selected_gates")
    completed = outcome.get("completed")
    if (type(selected) is not tuple or selected not in DIAGNOSTIC_GATE_SELECTIONS
            or type(completed) is not tuple or any(type(stage) is not str for stage in completed)):
        _refuse("capture_invalid")
    if failed is None:
        if (completed != selected or type(outcome.get("returncode")) is not int
                or outcome.get("returncode") != 0 or outcome.get("stdout") != b""
                or outcome.get("stderr") != b""
                or outcome.get("stdout_truncated") is not False
                or outcome.get("stderr_truncated") is not False):
            _refuse("capture_invalid")
        reviewed_count = outcome.get("node_reviewed_file_count")
        reviewed_digest = outcome.get("node_reviewed_paths_sha256")
        if selected == DIAGNOSTIC_GATE_SELECTIONS[-1]:
            if (type(reviewed_count) is not int or not 5 <= reviewed_count <= 133
                    or type(reviewed_digest) is not str
                    or SHA256_RE.fullmatch(reviewed_digest) is None):
                _refuse("capture_invalid")
            reviewed_evidence = (" node_reviewed_file_count=" + str(reviewed_count)
                                 + " node_reviewed_paths_sha256=" + reviewed_digest)
        elif reviewed_count is not None or reviewed_digest is not None:
            _refuse("capture_invalid")
        else:
            reviewed_evidence = ""
        return (
            "KD-BUILD-DIAGNOSTICS schema=1 selected_gates=" + ",".join(selected)
            + " completed_gates=" + ",".join(completed)
            + " result=all-gates-completed" + reviewed_evidence + "\n"
        ).encode("ascii")
    if (type(failed) is not str or failed not in selected
            or completed != selected[:selected.index(failed)]):
        _refuse("capture_invalid")
    if (type(outcome.get("returncode")) is not int
            or not 1 <= outcome["returncode"] <= 255
            or type(outcome.get("stdout")) is not bytes or type(outcome.get("stderr")) is not bytes):
        _refuse("capture_invalid")
    if (len(outcome["stdout"]) > 32_768 or len(outcome["stderr"]) > 32_768):
        _refuse("capture_invalid")
    if (type(outcome.get("stdout_truncated")) is not bool
            or type(outcome.get("stderr_truncated")) is not bool):
        _refuse("capture_invalid")
    prefix = ("KD-BUILD-DIAGNOSTICS schema=1 stage=" + failed
              + " stdout_truncated=" + ("true" if outcome["stdout_truncated"] else "false")
              + " stderr_truncated=" + ("true" if outcome["stderr_truncated"] else "false")
              + " exit=" + str(outcome["returncode"])
              + " selected_gates=" + ",".join(selected)
              + " completed_gates=" + (",".join(completed) if completed else "none")
              + "\nstdout:\n").encode("ascii")
    payload = prefix + outcome["stdout"] + b"\nstderr:\n" + outcome["stderr"]
    if len(payload) > 512 * 1024:
        _refuse("payload_invalid")
    try:
        payload.decode("utf-8", "strict")
    except UnicodeError:
        _refuse("payload_invalid")
    return payload


def encrypt_after_cleanup(dispatch, result, node):
    profile = dispatch["profile"]
    payload = result.get("payload_bytes")
    if type(payload) is not bytes or not payload:
        _refuse("payload_invalid")
    record = {
        "schema_version": 1,
        "kind": profile["kind"],
        "payload_b64": base64.b64encode(payload).decode("ascii"),
        "context": dispatch["context"],
        "recipient_spki_b64": base64.b64encode(dispatch["spki_der"]).decode("ascii"),
        "now": int(time.time()),
    }
    if profile["kind"] == "lock":
        expected = result.get("expected_manifest")
        if type(expected) is not dict:
            _refuse("manifest_invalid")
        record["expected_manifest"] = expected
    elif profile["kind"] == "rust_patch":
        paths = result.get("reviewed_rust_paths")
        if type(paths) is not list or not paths:
            _refuse("manifest_invalid")
        record["reviewed_rust_paths"] = paths
    encryptor = Path(__file__).resolve(strict=True).parent / "feedback_producer_crypto.mjs"
    try:
        info = encryptor.lstat()
        resolved_encryptor = encryptor.resolve(strict=True)
    except OSError:
        _refuse("tool_unavailable")
    control_directory = Path(__file__).resolve(strict=True).parent
    if (resolved_encryptor.parent != control_directory or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1 or stat.S_ISLNK(info.st_mode)
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        _refuse("tool_unavailable")
    return _encrypt_payload(encryptor, record, node)


def write_output(runner_temp, dispatch, ciphertext):
    info = _write_ciphertext(runner_temp, dispatch["profile"]["member_name"], ciphertext)
    return producer_receipt(dispatch, info)


def _parse_producer_line(raw, kind, environ):
    if (type(raw) is not bytes or len(raw) > 8192 or not raw.endswith(b"\n")
            or raw.count(b"\n") != 1 or not raw.startswith(b"KD-FEEDBACK-PRODUCER ")):
        _refuse("request_invalid")
    try:
        payload = raw[len(b"KD-FEEDBACK-PRODUCER "):-1].decode("ascii", "strict")
        record = _strict_json(payload.encode("ascii"), 8192)
        canonical = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        if canonical != payload:
            raise ValueError
        dispatch = validate_dispatch(kind, environ)
        profile = dispatch["profile"]
        expected = producer_receipt(dispatch, {
            "member_name": profile["member_name"],
            "ciphertext_digest": record.get("ciphertext_digest"),
            "member_size": record.get("member_size"),
        })
        if payload != expected:
            raise ValueError
        if (type(record.get("ciphertext_digest")) is not str
                or SHA256_RE.fullmatch(record["ciphertext_digest"]) is None
                or type(record.get("member_size")) is not int
                or not 1 <= record["member_size"] <= MAX_CIPHERTEXT_BYTES):
            raise ValueError
    except FeedbackRefusal:
        raise
    except BaseException:
        _refuse("request_invalid")
    return dispatch, record, payload


def _read_root_spool(runner_temp, member_name, expected_size, expected_digest):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        _refuse("output_unavailable")
    parent_fd = directory_fd = file_fd = None
    try:
        parent_path = Path(runner_temp)
        if parent_path.resolve(strict=True) != parent_path:
            raise ValueError
        parent_fd = os.open(parent_path, os.O_RDONLY | directory_flag | nofollow)
        parent = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid == 0:
            raise ValueError
        directory_fd = os.open(OUTPUT_DIRECTORY, os.O_RDONLY | directory_flag | nofollow, dir_fd=parent_fd)
        directory = os.fstat(directory_fd)
        named_directory = os.stat(OUTPUT_DIRECTORY, dir_fd=parent_fd, follow_symlinks=False)
        if ((directory.st_dev, directory.st_ino) != (named_directory.st_dev, named_directory.st_ino)
                or not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0
                or stat.S_IMODE(directory.st_mode) != 0o700):
            raise ValueError
        file_fd = os.open(member_name, os.O_RDONLY | nofollow, dir_fd=directory_fd)
        opened = os.fstat(file_fd)
        named = os.stat(member_name, dir_fd=directory_fd, follow_symlinks=False)
        if ((opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_uid != 0
                or opened.st_nlink != 1 or opened.st_size != expected_size
                or stat.S_IMODE(opened.st_mode) != 0o400):
            raise ValueError
        chunks = []
        total = 0
        while True:
            chunk = os.read(file_fd, min(65_536, expected_size + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > expected_size:
                raise ValueError
            chunks.append(chunk)
        after = os.fstat(file_fd)
        named_after = os.stat(member_name, dir_fd=directory_fd, follow_symlinks=False)
        if ((after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                or (named_after.st_dev, named_after.st_ino) != (opened.st_dev, opened.st_ino)
                or after.st_uid != 0 or after.st_nlink != 1 or after.st_size != expected_size):
            raise ValueError
        payload = b"".join(chunks)
        if hashlib.sha256(payload).hexdigest() != expected_digest:
            raise ValueError
        return payload
    except BaseException:
        _refuse("output_unavailable")
    finally:
        for descriptor in (file_fd, directory_fd, parent_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _stage_ciphertext(runner_temp, member_name, payload):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None:
        _refuse("output_unavailable")
    parent_fd = directory_fd = file_fd = None
    created_directory = False
    temporary_name = "." + member_name + ".tmp"
    file_installed = False
    try:
        parent_fd = os.open(runner_temp, os.O_RDONLY | directory_flag | nofollow)
        parent = os.fstat(parent_fd)
        if not stat.S_ISDIR(parent.st_mode) or parent.st_uid == 0:
            raise ValueError
        os.mkdir("core-feedback-upload", 0o700, dir_fd=parent_fd)
        created_directory = True
        directory_fd = os.open("core-feedback-upload", os.O_RDONLY | directory_flag | nofollow,
                               dir_fd=parent_fd)
        directory = os.fstat(directory_fd)
        os.fchown(directory_fd, 0, 0)
        os.fchmod(directory_fd, 0o700)
        directory = os.fstat(directory_fd)
        if (not stat.S_ISDIR(directory.st_mode) or directory.st_uid != 0
                or stat.S_IMODE(directory.st_mode) != 0o700):
            raise ValueError
        file_fd = os.open(temporary_name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow,
                          0o600, dir_fd=directory_fd)
        os.fchown(file_fd, 0, 0)
        os.fchmod(file_fd, 0o600)
        offset = 0
        while offset < len(payload):
            count = os.write(file_fd, payload[offset:])
            if count <= 0:
                raise OSError
            offset += count
        os.fsync(file_fd)
        created = os.fstat(file_fd)
        os.rename(temporary_name, member_name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        file_installed = True
        named = os.stat(member_name, dir_fd=directory_fd, follow_symlinks=False)
        if ((created.st_dev, created.st_ino) != (named.st_dev, named.st_ino)
                or not stat.S_ISREG(named.st_mode) or named.st_uid != 0
                or named.st_nlink != 1 or named.st_size != len(payload)):
            raise ValueError
        os.fchown(file_fd, parent.st_uid, parent.st_gid)
        os.fchmod(file_fd, 0o600)
        os.fsync(file_fd)
        copied = os.fstat(file_fd)
        named = os.stat(member_name, dir_fd=directory_fd, follow_symlinks=False)
        if ((copied.st_dev, copied.st_ino) != (named.st_dev, named.st_ino)
                or copied.st_uid != parent.st_uid or copied.st_gid != parent.st_gid
                or stat.S_IMODE(copied.st_mode) != 0o600 or copied.st_size != len(payload)):
            raise ValueError
        os.fchown(directory_fd, parent.st_uid, parent.st_gid)
        os.fchmod(directory_fd, 0o700)
        os.fsync(directory_fd)
        named_directory = os.stat("core-feedback-upload", dir_fd=parent_fd, follow_symlinks=False)
        if ((named_directory.st_dev, named_directory.st_ino) != (directory.st_dev, directory.st_ino)
                or named_directory.st_uid != parent.st_uid
                or stat.S_IMODE(named_directory.st_mode) != 0o700):
            raise ValueError
    except BaseException:
        if directory_fd is not None:
            try:
                if file_installed:
                    os.unlink(member_name, dir_fd=directory_fd)
                else:
                    os.unlink(temporary_name, dir_fd=directory_fd)
            except OSError:
                pass
        if created_directory and parent_fd is not None:
            try:
                os.rmdir("core-feedback-upload", dir_fd=parent_fd)
            except OSError:
                pass
        _refuse("output_unavailable")
    finally:
        for descriptor in (file_fd, directory_fd, parent_fd):
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError:
                    pass


def _append_github_output(path, runner_uid, runner_gid, values):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        _refuse("output_unavailable")
    descriptor = None
    try:
        target = Path(path)
        before = target.lstat()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != runner_uid
                or before.st_gid != runner_gid or before.st_nlink != 1 or before.st_size > 1024 * 1024
                or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise ValueError
        descriptor = os.open(target, os.O_WRONLY | os.O_APPEND | nofollow)
        opened = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or opened.st_uid != runner_uid or opened.st_gid != runner_gid or opened.st_nlink != 1):
            raise ValueError
        payload = "".join(name + "=" + value + "\n" for name, value in values.items()).encode("ascii")
        if len(payload) > 16 * 1024:
            raise ValueError
        offset = 0
        while offset < len(payload):
            count = os.write(descriptor, payload[offset:])
            if count <= 0:
                raise OSError
            offset += count
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        named = target.lstat()
        if ((after.st_dev, after.st_ino) != (opened.st_dev, opened.st_ino)
                or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
                or after.st_uid != runner_uid or after.st_gid != runner_gid):
            raise ValueError
    except BaseException:
        _refuse("output_unavailable")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def publish_output(raw_receipt, kind, environ):
    dispatch, record, receipt_json = _parse_producer_line(raw_receipt, kind, environ)
    runner_temp = environ.get("RUNNER_TEMP", "")
    try:
        runner_path = Path(runner_temp)
        runner_info = runner_path.lstat()
    except OSError:
        _refuse("output_unavailable")
    if not stat.S_ISDIR(runner_info.st_mode) or runner_info.st_uid == 0:
        _refuse("output_unavailable")
    output_path = environ.get("GITHUB_OUTPUT", "")
    if not output_path:
        _refuse("output_unavailable")
    payload = _read_root_spool(
        runner_path, record["member_name"], record["member_size"], record["ciphertext_digest"],
    )
    _stage_ciphertext(runner_path, record["member_name"], payload)
    _append_github_output(output_path, runner_info.st_uid, runner_info.st_gid, {
        "member_name": record["member_name"],
        "ciphertext_digest": record["ciphertext_digest"],
        "member_size": str(record["member_size"]),
        "producer_receipt": receipt_json,
    })
    return {
        "member_name": record["member_name"],
        "ciphertext_digest": record["ciphertext_digest"],
        "member_size": record["member_size"],
    }


def _parse_cli(arguments):
    if (type(arguments) not in (tuple, list) or len(arguments) != 10
            or arguments[0] != "run" or arguments[1] != "--profile"
            or arguments[3] != "--token-stdin" or arguments[4] != "--source-sha"
            or arguments[6] != "--base-sha" or arguments[8] != "--base-branch"):
        return "invalid", []
    kind = arguments[2]
    if kind not in PROFILE_BY_KIND:
        return "invalid", []
    return kind, [
        "run", "--token-stdin", "--source-sha", arguments[5],
        "--base-sha", arguments[7], "--base-branch", arguments[9],
    ]


def main(arguments=None, environ=None, stdin=None, stdout=None):
    actual = sys.argv[1:] if arguments is None else arguments
    environment = dict(os.environ) if environ is None else dict(environ)
    input_stream = sys.stdin.buffer if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout
    if (type(actual) in (tuple, list) and len(actual) == 3
            and actual[0] == "publish" and actual[1] == "--profile"):
        kind = actual[2]
        try:
            raw = input_stream.read(8193)
        except BaseException:
            raw = None
        try:
            if type(raw) is not bytes or len(raw) > 8192 or kind not in PROFILE_BY_KIND:
                _refuse("request_invalid")
            result = publish_output(raw, kind, environment)
            payload = json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            output_stream.write("KD-FEEDBACK-PUBLISHER " + payload + "\n")
            return 0
        except FeedbackRefusal:
            output_stream.write(
                'KD-FEEDBACK-PUBLISHER-REFUSAL '
                '{"reason":"output_unavailable","schema_version":1,"status":"refused"}\n'
            )
            return 1
    kind, core_arguments = _parse_cli(actual)
    control_path = Path(__file__).resolve(strict=True).parent / "macos_core_contract.py"
    try:
        spec = importlib.util.spec_from_file_location("macos_core_contract", str(control_path))
        if spec is None or spec.loader is None:
            raise ValueError
        core = importlib.util.module_from_spec(spec)
        sys.modules["macos_core_contract"] = core
        spec.loader.exec_module(core)
    except BaseException:
        _refuse("tool_unavailable")
    return core.main(
        arguments=core_arguments,
        environ=environ,
        stdin=stdin,
        stdout=stdout,
        feedback_kind=kind,
    )


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FeedbackRefusal:
        sys.stdout.write(
            'KD-FEEDBACK-PRODUCER-REFUSAL '
            '{"diagnostic":"unavailable","reason":"runner_unavailable",'
            '"schema_version":1,"stage":"context","status":"refused"}\n'
        )
        raise SystemExit(1)
