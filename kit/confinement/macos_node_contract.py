"""Bounded orchestration for the reviewed TypeScript dependency contract."""

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time


NODE_VERSION = "24.22.1"
NPM_VERSION = "11.19.1"
RELEASE_AGE_DAYS = 7
REGISTRY_URL = "https://registry.npmjs.org/"
AUDIT_ENDPOINT = "npm-bulk-advisory-v1"
USER_CONFIG_NAME = "npm-user-empty.npmrc"
GLOBAL_CONFIG_NAME = "npm-global-empty.npmrc"
NODE_TITLE_MODULE_SOURCE = 'let kdTitle = String(process.title);Object.defineProperty(process,"title",{get(){return kdTitle;},set(value){kdTitle = String(value);},configurable:true,enumerable:true});'
NODE_OPTIONS_VALUE = "--import=data:text/javascript;base64,bGV0IGtkVGl0bGUgPSBTdHJpbmcocHJvY2Vzcy50aXRsZSk7T2JqZWN0LmRlZmluZVByb3BlcnR5KHByb2Nlc3MsInRpdGxlIix7Z2V0KCl7cmV0dXJuIGtkVGl0bGU7fSxzZXQodmFsdWUpe2tkVGl0bGUgPSBTdHJpbmcodmFsdWUpO30sY29uZmlndXJhYmxlOnRydWUsZW51bWVyYWJsZTp0cnVlfSk7"
EMPTY_CONFIG_BYTES = b"\n"
MAX_LOCK_BYTES = 4 * 1024 * 1024 - 64 * 1024
MAX_REQUEST_BYTES = 6 * 1024 * 1024
MAX_CAPTURE_BYTES = 32 * 1024
MAX_EXPECTATION_BYTES = 256 * 1024
MAX_NPM_CONFIG_BYTES = 16
MAX_STAGE_SECONDS = 120
MAX_AUDIT_SECONDS = 90
DAY_MS = 24 * 60 * 60 * 1000
MAX_EXPECTATION_NODES = 200_000
SHA40 = re.compile(r"[a-f0-9]{40}\Z")
SHA64 = re.compile(r"[a-f0-9]{64}\Z")
IDENTITY_KEYS = ("source_sha", "base_sha", "control_sha", "reviewed_diff_sha256")
PROVENANCE_KEYS = (
    "schema_version", "status", "generation_identity", "accepted_source_identity", "lock_sha256",
    "manifest_sha256", "node_version", "npm_version", "release_age_days", "policy_epoch_ms",
    "cutoff_epoch_ms", "age_status", "generation_attempts", "audit_endpoint", "audit_status",
    "accepted_at_ms",
)
NODE_ERROR_CODES = frozenset({
    "invalid_input", "limit_exceeded", "manifest_invalid", "lock_missing", "toolchain_mismatch",
    "accepted_provenance_invalid", "audit_unavailable", "audit_response_invalid",
    "vulnerable_dependency", "deadline_exceeded",
})
STAGES = frozenset({
    "node_dependency_prepare", "node_dependency_audit", "typescript_typecheck", "typescript_tests",
})


class NodeContractRefusal(Exception):
    def __init__(self, reason="contract_refused", *, stage="node_dependency_prepare", substage=None,
                 returncode=None, stdout=b"", stderr=b"", stdout_truncated=False,
                 stderr_truncated=False):
        self.reason = reason if reason in {
            "invalid_input", "tool_unavailable", "toolchain_mismatch", "accepted_provenance_invalid",
            "lock_missing", "lock_already_present", "manifest_invalid", "limit_exceeded",
            "command_failed", "audit_unavailable", "audit_response_invalid", "vulnerable_dependency",
            "deadline_exceeded", "capture_invalid", "cleanup_incomplete",
        } else "contract_refused"
        self.stage = stage if stage in STAGES else "node_dependency_prepare"
        self.substage = substage if type(substage) is str and substage in {
            "runtime_version", "npm_version", "lock_generation", "lock_validation", "bulk_audit",
            "npm_ci", "typecheck", "tests",
        } else None
        self.returncode = returncode if type(returncode) is int and 0 <= returncode <= 255 else None
        self.stdout = stdout if type(stdout) is bytes and len(stdout) <= MAX_CAPTURE_BYTES else b""
        self.stderr = stderr if type(stderr) is bytes and len(stderr) <= MAX_CAPTURE_BYTES else b""
        self.stdout_truncated = bool(stdout_truncated)
        self.stderr_truncated = bool(stderr_truncated)
        self.completed_stages = ()
        super().__init__("Node contract refused")

    def diagnostic(self):
        return {
            "stage": self.stage,
            "substage": self.substage,
            "returncode": self.returncode,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "stdout_truncated": self.stdout_truncated,
            "stderr_truncated": self.stderr_truncated,
            "completed_stages": self.completed_stages,
        }


def _refuse(reason="contract_refused", **details):
    raise NodeContractRefusal(reason, **details)


def _safe_object(value, keys, *, code="invalid_input"):
    if type(value) is not dict or set(value) != set(keys):
        _refuse(code)
    return value


def _valid_identity(value):
    identity = _safe_object(value, IDENTITY_KEYS, code="accepted_provenance_invalid")
    if (type(identity["source_sha"]) is not str or SHA40.fullmatch(identity["source_sha"]) is None
            or type(identity["base_sha"]) is not str or SHA40.fullmatch(identity["base_sha"]) is None
            or type(identity["control_sha"]) is not str or SHA40.fullmatch(identity["control_sha"]) is None
            or type(identity["reviewed_diff_sha256"]) is not str
            or SHA64.fullmatch(identity["reviewed_diff_sha256"]) is None):
        _refuse("accepted_provenance_invalid")
    return dict(identity)


def _validate_accepted_provenance(value, identity, lock_bytes, manifest_sha256, now_ms):
    record = _safe_object(value, PROVENANCE_KEYS, code="accepted_provenance_invalid")
    _valid_identity(record["generation_identity"])
    accepted_identity = _valid_identity(record["accepted_source_identity"])
    lock_digest = hashlib.sha256(lock_bytes).hexdigest()
    if (type(record["schema_version"]) is not int or record["schema_version"] != 1
            or record["status"] != "accepted"
            or accepted_identity != identity or record["lock_sha256"] != lock_digest
            or record["manifest_sha256"] != manifest_sha256
            or record["node_version"] != NODE_VERSION or record["npm_version"] != NPM_VERSION
            or record["release_age_days"] != RELEASE_AGE_DAYS or record["age_status"] != "passed"
            or record["generation_attempts"] != 1 or record["audit_endpoint"] != AUDIT_ENDPOINT
            or record["audit_status"] != "passed"
            or type(record["policy_epoch_ms"]) is not int or not 0 < record["policy_epoch_ms"]
            or type(record["cutoff_epoch_ms"]) is not int
            or record["cutoff_epoch_ms"] != record["policy_epoch_ms"] - RELEASE_AGE_DAYS * DAY_MS
            or type(record["accepted_at_ms"]) is not int
            or not record["policy_epoch_ms"] <= record["accepted_at_ms"] <= now_ms):
        _refuse("accepted_provenance_invalid")
    return dict(record)


def _validate_expectation(value):
    if type(value) is not dict or set(value) != {"root", "workspaces"}:
        _refuse("manifest_invalid")
    budget = [0, 0]

    def bound(item, depth=0):
        budget[0] += 1
        if budget[0] > MAX_EXPECTATION_NODES or depth > 16:
            _refuse("limit_exceeded")
        if type(item) is str:
            budget[1] += len(item) * 12 + 2
        elif type(item) is list:
            if len(item) > 512:
                _refuse("limit_exceeded")
            budget[1] += 2
            for child in item:
                bound(child, depth + 1)
        elif type(item) is dict:
            if len(item) > 512:
                _refuse("limit_exceeded")
            budget[1] += 2
            for key, child in item.items():
                if type(key) is not str:
                    _refuse("manifest_invalid")
                budget[0] += 1
                budget[1] += len(key) * 12 + 4
                if budget[0] > MAX_EXPECTATION_NODES:
                    _refuse("limit_exceeded")
                bound(child, depth + 1)
        else:
            _refuse("manifest_invalid")
        if budget[1] > MAX_EXPECTATION_BYTES:
            _refuse("limit_exceeded")

    bound(value)
    try:
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                         allow_nan=False).encode("ascii")
    except BaseException:
        _refuse("manifest_invalid")
    if len(raw) > MAX_EXPECTATION_BYTES:
        _refuse("limit_exceeded")
    return raw


def _validate_toolchain_paths(node_executable, npm_cli, tool_cache_root):
    try:
        cache = Path(tool_cache_root)
        node = Path(node_executable)
        npm = Path(npm_cli)
        if not cache.is_absolute() or not node.is_absolute() or not npm.is_absolute():
            raise ValueError
        cache_real = cache.resolve(strict=True)
        node_root = (cache_real / "node" / NODE_VERSION).resolve(strict=True)
        node_real = node.resolve(strict=True)
        node_info = node.lstat()
        expected_npm = node_real.parent.parent / "lib/node_modules/npm/bin/npm-cli.js"
        npm_real = npm.resolve(strict=True)
        npm_info = npm.lstat()
    except BaseException:
        _refuse("tool_unavailable")
    if (node != node_real or npm != npm_real or node_root not in node_real.parents
            or npm_real != expected_npm or not stat.S_ISREG(node_info.st_mode)
            or stat.S_ISLNK(node_info.st_mode) or not node_info.st_mode & stat.S_IXUSR
            or node_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            or not stat.S_ISREG(npm_info.st_mode) or stat.S_ISLNK(npm_info.st_mode)
            or npm_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        _refuse("tool_unavailable")
    helper = Path(__file__).resolve(strict=True).with_name("node_contract_validation.mjs")
    try:
        helper_info = helper.lstat()
    except OSError:
        _refuse("tool_unavailable")
    if (not stat.S_ISREG(helper_info.st_mode) or stat.S_ISLNK(helper_info.st_mode)
            or helper_info.st_nlink != 1 or helper_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
        _refuse("tool_unavailable")
    return node_real, npm_real, helper


def _owned_directory(path, uid, gid, *, create=False):
    target = Path(path)
    try:
        if create:
            os.mkdir(target, 0o700)
            os.chown(target, uid, gid)
            os.chmod(target, 0o700)
        info = target.lstat()
    except BaseException:
        _refuse("tool_unavailable")
    if (not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode)
            or info.st_uid != uid or info.st_gid != gid or stat.S_IMODE(info.st_mode) != 0o700):
        _refuse("tool_unavailable")
    return target


def _write_worker_file(path, payload, uid, gid):
    target = Path(path)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None or type(payload) is not bytes or not payload:
        _refuse("tool_unavailable")
    descriptor = None
    try:
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            count = os.write(descriptor, payload[offset:])
            if count <= 0:
                raise OSError
            offset += count
        os.fsync(descriptor)
        opened = os.fstat(descriptor)
        named = target.lstat()
        if ((opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_uid != uid or opened.st_gid != gid
                or opened.st_nlink != 1 or opened.st_size != len(payload)
                or stat.S_IMODE(opened.st_mode) != 0o600):
            raise ValueError
    except BaseException:
        _refuse("tool_unavailable")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _read_worker_file(path, uid, maximum):
    target = Path(path)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        _refuse("lock_missing")
    descriptor = None
    try:
        before = target.lstat()
        if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
                or before.st_uid != uid or before.st_nlink != 1 or before.st_size <= 0
                or before.st_size > maximum or before.st_mode & (stat.S_IWGRP | stat.S_IWOTH)):
            raise ValueError
        descriptor = os.open(target, os.O_RDONLY | nofollow)
        opened = os.fstat(descriptor)
        if ((before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
                or not stat.S_ISREG(opened.st_mode) or opened.st_uid != uid
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
        named = target.lstat()
        if (total != opened.st_size or (opened.st_dev, opened.st_ino) != (after.st_dev, after.st_ino)
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
                or after.st_uid != uid or after.st_nlink != 1):
            raise ValueError
        return b"".join(chunks)
    except FileNotFoundError:
        _refuse("lock_missing")
    except NodeContractRefusal:
        raise
    except BaseException:
        _refuse("manifest_invalid")
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _strict_json(raw, maximum):
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        _refuse("capture_invalid")

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
        _refuse("capture_invalid")


def _worker_result(run_worker, argv, *, stage, substage, project, environment, deadline, timeout):
    if stage not in STAGES or type(argv) not in (tuple, list) or not argv:
        _refuse("capture_invalid", stage=stage, substage=substage)
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        _refuse("deadline_exceeded", stage=stage, substage=substage)
    bounded_timeout = max(1, min(timeout, int(remaining)))
    try:
        result = run_worker(tuple(str(item) for item in argv), stage=stage, substage=substage,
                            cwd=project, env=environment, deadline=deadline,
                            timeout=bounded_timeout, allow_nonzero_capture=True)
    except BaseException as error:
        if getattr(error, "reason", None) == "cleanup_incomplete":
            _refuse("cleanup_incomplete", stage=stage, substage=substage)
        if getattr(error, "reason", None) == "deadline_exceeded":
            _refuse("deadline_exceeded", stage=stage, substage=substage)
        _refuse("command_failed", stage=stage, substage=substage)
    stdout = getattr(result, "stdout", None)
    stderr = getattr(result, "stderr", None)
    returncode = getattr(result, "returncode", None)
    stdout_truncated = getattr(result, "stdout_truncated", False)
    stderr_truncated = getattr(result, "stderr_truncated", False)
    if (type(stdout) is not bytes or type(stderr) is not bytes or type(returncode) is not int
            or not 0 <= returncode <= 255 or len(stdout) > MAX_CAPTURE_BYTES
            or len(stderr) > MAX_CAPTURE_BYTES or type(stdout_truncated) is not bool
            or type(stderr_truncated) is not bool):
        _refuse("capture_invalid", stage=stage, substage=substage)
    return result


def _capture_failure(result, reason, *, stage, substage):
    _refuse(reason, stage=stage, substage=substage, returncode=result.returncode,
            stdout=result.stdout, stderr=result.stderr,
            stdout_truncated=getattr(result, "stdout_truncated", False),
            stderr_truncated=getattr(result, "stderr_truncated", False))


def _tool_versions(run_worker, node, npm_cli, project, environment, deadline):
    for command, expected, substage in (
        ((str(node), "--version"), f"v{NODE_VERSION}\n".encode("ascii"), "runtime_version"),
        ((str(node), str(npm_cli), "--version"), f"{NPM_VERSION}\n".encode("ascii"), "npm_version"),
    ):
        result = _worker_result(run_worker, command, stage="node_dependency_prepare", substage=substage,
                                project=project, environment=environment, deadline=deadline, timeout=10)
        if result.returncode != 0 or result.stdout != expected or result.stderr:
            _capture_failure(result, "toolchain_mismatch", stage="node_dependency_prepare", substage=substage)


def _node_environment(node, worker_storage, worker_uid, worker_gid):
    root = Path(worker_storage)
    home = _owned_directory(root / "node-home", worker_uid, worker_gid, create=True)
    temporary = _owned_directory(root / "node-tmp", worker_uid, worker_gid, create=True)
    cache = _owned_directory(root / "node-cache", worker_uid, worker_gid, create=True)
    user_config = root / USER_CONFIG_NAME
    global_config = root / GLOBAL_CONFIG_NAME
    _write_worker_file(user_config, EMPTY_CONFIG_BYTES, worker_uid, worker_gid)
    _write_worker_file(global_config, EMPTY_CONFIG_BYTES, worker_uid, worker_gid)
    return {
        "PATH": str(Path(node).parent) + ":/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(home),
        "TMPDIR": str(temporary),
        "LANG": "C",
        "LC_ALL": "C",
        "NODE_OPTIONS": NODE_OPTIONS_VALUE,
        "npm_config_cache": str(cache),
        "npm_config_registry": REGISTRY_URL,
        "npm_config_userconfig": str(user_config),
        "npm_config_globalconfig": str(global_config),
        "npm_config_ignore_scripts": "true",
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_fetch_retries": "0",
        "npm_config_fetch_timeout": "30000",
        "npm_config_update_notifier": "false",
    }


def _validate_npm_config_files(environment, worker_storage, worker_uid, worker_gid, *, stage, substage):
    if type(environment) is not dict:
        _refuse("tool_unavailable", stage=stage, substage=substage)
    root = Path(worker_storage)
    for key, name in (("npm_config_userconfig", USER_CONFIG_NAME),
                      ("npm_config_globalconfig", GLOBAL_CONFIG_NAME)):
        target = root / name
        if environment.get(key) != str(target):
            _refuse("tool_unavailable", stage=stage, substage=substage)
        try:
            before = target.lstat()
            if (not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode)
                    or before.st_uid != worker_uid or before.st_gid != worker_gid
                    or before.st_nlink != 1 or before.st_size != len(EMPTY_CONFIG_BYTES)
                    or stat.S_IMODE(before.st_mode) != 0o600):
                raise ValueError
            payload = _read_worker_file(target, worker_uid, MAX_NPM_CONFIG_BYTES)
            after = target.lstat()
            if ((before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
                    or not stat.S_ISREG(after.st_mode) or stat.S_ISLNK(after.st_mode)
                    or after.st_uid != worker_uid or after.st_gid != worker_gid
                    or after.st_nlink != 1 or after.st_size != len(EMPTY_CONFIG_BYTES)
                    or stat.S_IMODE(after.st_mode) != 0o600 or payload != EMPTY_CONFIG_BYTES):
                raise ValueError
        except BaseException:
            _refuse("tool_unavailable", stage=stage, substage=substage)


def _cutoff_iso(cutoff_ms):
    try:
        seconds, milliseconds = divmod(cutoff_ms, 1000)
        value = datetime.fromtimestamp(seconds, tz=timezone.utc).replace(microsecond=milliseconds * 1000)
        return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except BaseException:
        _refuse("invalid_input")


def _command_prefix(node, npm_cli, cutoff_ms, environment):
    if type(environment) is not dict:
        _refuse("invalid_input")
    user_config = environment.get("npm_config_userconfig")
    global_config = environment.get("npm_config_globalconfig")
    if (type(user_config) is not str or type(global_config) is not str
            or not Path(user_config).is_absolute() or not Path(global_config).is_absolute()
            or user_config == global_config or any("\x00" in value or "\n" in value for value in (
                user_config, global_config))):
        _refuse("invalid_input")
    return (
        str(node), str(npm_cli), "--registry=" + REGISTRY_URL,
        "--userconfig=" + user_config, "--globalconfig=" + global_config, "--ignore-scripts",
        "--audit=false", "--fund=false", "--fetch-retries=0", "--fetch-timeout=30000",
        "--no-update-notifier", "--min-release-age=7", "--before=" + _cutoff_iso(cutoff_ms),
    )


def _lock_path(project):
    return Path(project) / "package-lock.json"


def _ensure_absent(path, *, reason):
    try:
        Path(path).lstat()
    except FileNotFoundError:
        return
    except OSError:
        _refuse("tool_unavailable")
    _refuse(reason)


def _request_bytes(mode, lock_bytes, expected_manifest, identity, npm_cli, proof, provenance,
                   now_ms, deadline_ms, policy_epoch_ms):
    record = {
        "schema_version": 1,
        "mode": mode,
        "lock_base64": base64.b64encode(lock_bytes).decode("ascii"),
        "expected_manifest": expected_manifest,
        "source_identity": identity,
        "npm_cli_path": str(npm_cli),
        "generation_proof": proof,
        "accepted_provenance": provenance,
        "policy_epoch_ms": policy_epoch_ms,
        "now_ms": now_ms,
        "deadline_ms": deadline_ms,
    }
    try:
        raw = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                         allow_nan=False).encode("ascii")
    except BaseException:
        _refuse("manifest_invalid")
    if len(raw) > MAX_REQUEST_BYTES:
        _refuse("limit_exceeded")
    return raw


def _validate_gate_result(raw, lock_bytes, manifest_sha256, mode, policy_epoch_ms, *, stage):
    output = _strict_json(raw, 8192)
    if type(output) is not dict or type(output.get("schema_version")) is not int or output["schema_version"] != 1:
        _refuse("capture_invalid", stage=stage, substage="bulk_audit")
    if output.get("status") == "refused":
        if (set(output) != {"schema_version", "status", "reason"}
                or output["reason"] not in NODE_ERROR_CODES):
            _refuse("capture_invalid", stage=stage, substage="bulk_audit")
        reason = output["reason"]
        mapped = reason if reason in {"limit_exceeded", "manifest_invalid", "lock_missing",
                                      "accepted_provenance_invalid", "audit_unavailable",
                                      "audit_response_invalid", "vulnerable_dependency", "deadline_exceeded"} else "audit_response_invalid"
        _refuse(mapped, stage=stage, substage="bulk_audit")
    if set(output) != {"schema_version", "status", "result"} or output["status"] != "passed":
        _refuse("capture_invalid", stage=stage, substage="bulk_audit")
    result = output["result"]
    expected_keys = {
        "schema_version", "status", "mode", "lock_sha256", "manifest_sha256", "node_version", "npm_version",
        "release_age_days", "policy_epoch_ms", "cutoff_epoch_ms", "age_status", "generation_attempts",
        "audit_endpoint", "audit_status", "package_count", "remote_package_count", "remote_version_count",
        "advisory_count",
    }
    if (type(result) is not dict or set(result) != expected_keys
            or type(result["schema_version"]) is not int or result["schema_version"] != 1
            or result["status"] != "passed" or result["mode"] != mode
            or result["lock_sha256"] != hashlib.sha256(lock_bytes).hexdigest()
            or result["manifest_sha256"] != manifest_sha256
            or result["policy_epoch_ms"] != policy_epoch_ms
            or result["node_version"] != NODE_VERSION or result["npm_version"] != NPM_VERSION
            or type(result["release_age_days"]) is not int
            or result["release_age_days"] != RELEASE_AGE_DAYS or result["age_status"] != "passed"
            or type(result["generation_attempts"]) is not int or result["generation_attempts"] != 1
            or result["audit_endpoint"] != AUDIT_ENDPOINT
            or result["audit_status"] != "passed"
            or any(type(result[key]) is not int or result[key] < 0 for key in (
                "policy_epoch_ms", "cutoff_epoch_ms", "package_count", "remote_package_count",
                "remote_version_count", "advisory_count"))
            or result["cutoff_epoch_ms"] != result["policy_epoch_ms"] - RELEASE_AGE_DAYS * DAY_MS):
        _refuse("capture_invalid", stage=stage, substage="bulk_audit")
    return dict(result)


def _validate_stage_result(result, stage, substage):
    if result.returncode != 0:
        _capture_failure(result, "command_failed", stage=stage, substage=substage)


def _run_node_contract(
    mode,
    *,
    project,
    worker_storage,
    worker_uid,
    worker_gid,
    node_executable,
    npm_cli,
    tool_cache_root,
    expected_manifest,
    source_identity,
    run_worker,
    deadline,
    policy_epoch_ms=None,
    accepted_lock=None,
    accepted_provenance=None,
    _completed=None,
):
    """Generate and audit one bootstrap lock, or validate an already accepted lock and run TS checks."""
    if mode not in ("bootstrap", "verify") or type(worker_uid) is not int or type(worker_gid) is not int:
        _refuse("invalid_input")
    if not callable(run_worker) or not isinstance(deadline, (int, float)) or deadline <= time.monotonic():
        _refuse("deadline_exceeded")
    identity = _valid_identity(source_identity)
    expectation_bytes = _validate_expectation(expected_manifest)
    manifest_sha256 = hashlib.sha256(expectation_bytes).hexdigest()
    try:
        node, npm, helper = _validate_toolchain_paths(node_executable, npm_cli, tool_cache_root)
    except NodeContractRefusal:
        raise
    current_ms = int(time.time() * 1000)
    if mode == "bootstrap":
        if (accepted_lock is not None or accepted_provenance is not None
                or type(policy_epoch_ms) is not int or policy_epoch_ms <= 0
                or policy_epoch_ms > current_ms or current_ms - policy_epoch_ms > DAY_MS):
            _refuse("invalid_input")
        lock_bytes = None
        cutoff_ms = policy_epoch_ms - RELEASE_AGE_DAYS * DAY_MS
    else:
        if (policy_epoch_ms is not None or type(accepted_lock) is not bytes
                or not 0 < len(accepted_lock) <= MAX_LOCK_BYTES):
            _refuse("lock_missing")
        provenance = _validate_accepted_provenance(
            accepted_provenance, identity, accepted_lock, manifest_sha256, current_ms,
        )
        lock_bytes = accepted_lock
        policy_epoch_ms = provenance["policy_epoch_ms"]
        cutoff_ms = provenance["cutoff_epoch_ms"]

    project_path = _owned_directory(project, worker_uid, worker_gid)
    storage_path = _owned_directory(worker_storage, worker_uid, worker_gid)
    if mode == "verify":
        project_lock = _read_worker_file(_lock_path(project_path), worker_uid, MAX_LOCK_BYTES)
        if project_lock != lock_bytes:
            _refuse("accepted_provenance_invalid", stage="node_dependency_prepare",
                    substage="lock_validation")
    environment = _node_environment(node, storage_path, worker_uid, worker_gid)

    def checked_worker(argv, *, stage, substage, cwd, env, deadline, timeout,
                       allow_nonzero_capture=True):
        _validate_npm_config_files(environment, storage_path, worker_uid, worker_gid,
                                   stage=stage, substage=substage)
        return run_worker(argv, stage=stage, substage=substage, cwd=cwd, env=env,
                          deadline=deadline, timeout=timeout,
                          allow_nonzero_capture=allow_nonzero_capture)

    _tool_versions(checked_worker, node, npm, project_path, environment, deadline)

    if mode == "bootstrap":
        _ensure_absent(_lock_path(project_path), reason="lock_already_present")
        command = _command_prefix(node, npm, cutoff_ms, environment) + (
            "install", "--package-lock-only", "--workspaces=true", "--include-workspace-root",
        )
        prepared = _worker_result(checked_worker, command, stage="node_dependency_prepare",
                                  substage="lock_generation", project=project_path,
                                  environment=environment, deadline=deadline, timeout=MAX_STAGE_SECONDS)
        _validate_stage_result(prepared, "node_dependency_prepare", "lock_generation")
        lock_bytes = _read_worker_file(_lock_path(project_path), worker_uid, MAX_LOCK_BYTES)
        generation_proof = {
            "schema_version": 1,
            "status": "generated",
            "generation_identity": identity,
            "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
            "manifest_sha256": manifest_sha256,
            "node_version": NODE_VERSION,
            "npm_version": NPM_VERSION,
            "release_age_days": RELEASE_AGE_DAYS,
            "policy_epoch_ms": policy_epoch_ms,
            "cutoff_epoch_ms": cutoff_ms,
            "age_status": "passed",
            "generation_attempts": 1,
        }
        _completed.append("node_dependency_prepare")
        accepted = None
    else:
        generation_proof = None
        accepted = provenance
        _completed.append("node_dependency_prepare")

    now_for_audit = int(time.time() * 1000)
    remaining_ms = max(1, min(MAX_AUDIT_SECONDS * 1000,
                              int((deadline - time.monotonic()) * 1000)))
    audit_deadline_ms = now_for_audit + remaining_ms
    request = _request_bytes(
        mode, lock_bytes, expected_manifest, identity, npm, generation_proof, accepted,
        now_for_audit, audit_deadline_ms, policy_epoch_ms if mode == "bootstrap" else None,
    )
    request_path = storage_path / "node-contract-request.json"
    _ensure_absent(request_path, reason="lock_already_present")
    _write_worker_file(request_path, request, worker_uid, worker_gid)
    try:
        audited = _worker_result(
            checked_worker, (str(node), str(helper), "--request", str(request_path)),
            stage="node_dependency_audit", substage="bulk_audit", project=project_path,
            environment=environment, deadline=deadline, timeout=MAX_AUDIT_SECONDS,
        )
        audit_result = _validate_gate_result(audited.stdout, lock_bytes, manifest_sha256, mode,
                                             policy_epoch_ms,
                                             stage="node_dependency_audit")
        if audited.returncode != 0:
            _capture_failure(audited, "audit_response_invalid", stage="node_dependency_audit",
                             substage="bulk_audit")
        if mode == "bootstrap":
            _completed.append("node_dependency_audit")
    finally:
        try:
            info = request_path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != worker_uid:
                raise ValueError
            os.unlink(request_path)
            descriptor = os.open(storage_path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except BaseException:
            _refuse("cleanup_incomplete", stage="node_dependency_audit", substage="bulk_audit")

    if mode == "bootstrap":
        candidate = {
            "schema_version": 1,
            "status": "validated_candidate",
            "generation_identity": identity,
            "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
            "manifest_sha256": manifest_sha256,
            "node_version": NODE_VERSION,
            "npm_version": NPM_VERSION,
            "release_age_days": RELEASE_AGE_DAYS,
            "policy_epoch_ms": policy_epoch_ms,
            "cutoff_epoch_ms": cutoff_ms,
            "age_status": "passed",
            "generation_attempts": 1,
            "audit_endpoint": AUDIT_ENDPOINT,
            "audit_status": "passed",
        }
        return {
            "schema_version": 1,
            "mode": "bootstrap",
            "status": "passed",
            "lock_bytes": lock_bytes,
            "lock_sha256": candidate["lock_sha256"],
            "provenance_candidate": candidate,
            "stages": ("node_dependency_prepare", "node_dependency_audit"),
            "audit_summary": {
                "package_count": audit_result["package_count"],
                "remote_package_count": audit_result["remote_package_count"],
                "remote_version_count": audit_result["remote_version_count"],
                "advisory_count": audit_result["advisory_count"],
            },
        }

    ci = _worker_result(
        checked_worker,
        _command_prefix(node, npm, cutoff_ms, environment)
        + ("ci", "--workspaces=true", "--include-workspace-root"),
        stage="node_dependency_audit", substage="npm_ci", project=project_path,
        environment=environment, deadline=deadline, timeout=MAX_STAGE_SECONDS,
    )
    _validate_stage_result(ci, "node_dependency_audit", "npm_ci")
    _completed.append("node_dependency_audit")

    typecheck = _worker_result(
        checked_worker, (str(node), str(npm), "run", "typecheck", "--workspaces", "--ignore-scripts"),
        stage="typescript_typecheck", substage="typecheck", project=project_path,
        environment=environment, deadline=deadline, timeout=MAX_STAGE_SECONDS,
    )
    _validate_stage_result(typecheck, "typescript_typecheck", "typecheck")
    _completed.append("typescript_typecheck")
    tests = _worker_result(
        checked_worker, (str(node), str(npm), "run", "test", "--workspaces", "--ignore-scripts"),
        stage="typescript_tests", substage="tests", project=project_path,
        environment=environment, deadline=deadline, timeout=MAX_STAGE_SECONDS,
    )
    _validate_stage_result(tests, "typescript_tests", "tests")
    _completed.append("typescript_tests")
    return {
        "schema_version": 1,
        "mode": "verify",
        "status": "passed",
        "lock_bytes": lock_bytes,
        "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "accepted_provenance": dict(provenance),
        "audit_summary": {
            "package_count": audit_result["package_count"],
            "remote_package_count": audit_result["remote_package_count"],
            "remote_version_count": audit_result["remote_version_count"],
            "advisory_count": audit_result["advisory_count"],
        },
        "stages": (
            "node_dependency_prepare", "node_dependency_audit", "typescript_typecheck", "typescript_tests",
        ),
    }


def run_node_contract(
    mode,
    *,
    project,
    worker_storage,
    worker_uid,
    worker_gid,
    node_executable,
    npm_cli,
    tool_cache_root,
    expected_manifest,
    source_identity,
    run_worker,
    deadline,
    policy_epoch_ms=None,
    accepted_lock=None,
    accepted_provenance=None,
):
    """Run the fixed Node stages and attach the completed ordered prefix to failures."""
    completed = []
    try:
        result = _run_node_contract(
            mode,
            project=project,
            worker_storage=worker_storage,
            worker_uid=worker_uid,
            worker_gid=worker_gid,
            node_executable=node_executable,
            npm_cli=npm_cli,
            tool_cache_root=tool_cache_root,
            expected_manifest=expected_manifest,
            source_identity=source_identity,
            run_worker=run_worker,
            deadline=deadline,
            policy_epoch_ms=policy_epoch_ms,
            accepted_lock=accepted_lock,
            accepted_provenance=accepted_provenance,
            _completed=completed,
        )
    except NodeContractRefusal as error:
        error.completed_stages = tuple(completed)
        raise
    return result
