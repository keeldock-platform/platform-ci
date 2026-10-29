"""Fixed, offline macOS validation for the reviewed KeelDock core contract."""

import hashlib
import importlib.util
import json
import os
from contextlib import contextmanager
from pathlib import Path
import platform
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time


SCHEMA_VERSION = 1
CONCERN = "core-contract"
TEMP_ROOT = Path(chr(47) + "private" + chr(47) + "tmp")
RUN_PREFIX = "macos-core-contract-"
WORKER_PREFIX = "macos-core-contract-worker-"
MAX_TOTAL_SECONDS = 15 * 60
MAX_COMMAND_SECONDS = 120
MAX_DIFF_BYTES = 2 * 1024 * 1024
MAX_CAPTURE_BYTES = 65_536
MAX_RECEIPT_BYTES = 8192
MAX_REFUSAL_BYTES = 512
SHA1_RE = re.compile(r"[a-f0-9]{40}\Z")
SHA256_RE = re.compile(r"[a-f0-9]{64}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
TOKEN_RE = re.compile(r"[!-~]{1,4096}\Z")
BASE_BRANCHES = frozenset(("main", "develop", "uat"))
ALLOWED_CONTROL_SIBLINGS = frozenset((
    "macos_capability", "macos_reviewed_build", "macos_boundary_guard",
    "macos_private_validation", "macos_source_reader", "macos_network_observer",
    "macos_rust_toolchain", "macos_rules_bootstrap", "macos_feedback_producer",
    "macos_node_contract", "foundation_node_feedback", "cargo_lock_bootstrap",
))
FEEDBACK_TREE_LABELS = {
    "core-contract": "core_contract",
    "core-node-lock-return": "core_node_lock_return",
    "core-rust-format-return": "core_rust_format_return",
    "core-build-diagnostic-return": "core_build_diagnostic_return",
    "core-rust-lock-return": "core_rust_lock_return",
}
LOCKED_FOUNDATION_TREE = "core_build_diagnostic_return_with_package_lock"
GATE_NAMES = (
    "format", "clippy", "workspace_tests", "api_tests", "mock_tests", "conformance_tests",
)
PARSER_GATE_NAMES = ("parser_format", "parser_clippy", "parser_replay")
SOURCE_GATE_STAGES = GATE_NAMES + PARSER_GATE_NAMES
SUITE_NAMES = (
    "core.static", "core.host-api", "core.mock-host", "core.conformance",
)
PRIVATE_VALIDATION_REASONS = frozenset((
    "invalid_input", "context_unavailable", "configuration_unavailable",
    "source_reader_unavailable", "repository_scope_invalid", "source_fetch_unavailable",
    "revocation_unconfirmed", "base_invalid", "signature_invalid", "revocation_policy_invalid",
    "bootstrap_snapshot_invalid", "bootstrap_not_approved", "cleanup_incomplete", "internal_error",
))
PRIVATE_VALIDATION_STAGES = frozenset((
    "input", "context", "configuration", "source_scope", "fetch", "revoke",
    "history", "signature", "revocation", "bootstrap", "cleanup",
))
PRIVATE_FETCH_OPERATIONS = frozenset((
    "git_init", "remote_add", "base_fetch", "base_ref", "candidate_fetch",
    "source_ref", "shallow_check", "remote_remove", "source_snapshot",
))
PRIVATE_FETCH_CLASSES = frozenset((
    "exit_nonzero", "stderr_present", "process_failure", "unexpected_exception",
))
CORE_BOOTSTRAP_CHECKS = frozenset((
    "tree_entries", "required_files", "path_mode", "base_policy", "rules_manifest",
    "rules_inventory", "rules_hash", "workspace_decode", "workspace_members",
    "cargo_lock_decode", "cargo_lock_shape", "toolchain", "package_decode",
    "package_build", "checkout", "lease_paths", "lease_acl", "lease_access", "lease_census",
))
SOURCE_LEASE_OPEN_ERROR_DIAGNOSTICS = {
    TypeError: "source_lease_open_type_error",
    AttributeError: "source_lease_open_attribute_error",
    ValueError: "source_lease_open_value_error",
    PermissionError: "source_lease_open_permission_error",
    FileNotFoundError: "source_lease_open_not_found",
    TimeoutError: "source_lease_open_timeout",
    OSError: "source_lease_open_os_error",
}
REASONS = frozenset((
    "invalid_input", "unsupported_host", "runner_unavailable", "source_validation_failed",
    "token_revocation_unconfirmed", "source_binding_mismatch", "source_diff_mismatch",
    "toolchain_install_failed", "toolchain_version_mismatch", "gate_failed",
    "network_observation_failed", "summary_guard_failed", "capture_invalid",
    "cleanup_incomplete", "internal_error",
))
STAGES = frozenset((
    "arguments", "context", "host", "source_validation", "source_lease", "source_tree",
    "source_diff", "toolchain_install", "worker_setup", "summary_guard", "observer",
    "format", "clippy", "workspace_tests", "api_tests", "mock_tests",
    "conformance_tests", "parser_format", "parser_clippy", "parser_replay",
    "cleanup", "receipt", "internal",
))
OPERATION_DIAGNOSTICS = frozenset((
    "load_controls", "review_binding", "host_preflight", "temp_root_check", "smoke_receipt",
    "token_input", "token_revocation", "disable_developer_mode", "resolve_host_toolchain",
    "resolve_worker_tools", "create_worker_identity", "create_run_directory", "create_source_storage",
    "prepare_worker_storage", "worker_identity_check", "worker_privilege_probe",
    "worker_privilege_probe_group_cleanup", "worker_privilege_probe_capture_cleanup",
    "worker_privilege_probe_census", "worker_privilege_probe_survivor",
    "worker_privilege_probe_timeout",
    "worker_privilege_census", "summary_guard_setup", "source_lease_request", "source_lease_open",
    "source_revocation_check", "source_lease_record", "source_path_validation", "source_tree_probe",
    "resolve_git", "git_diff_verification", "network_observer_start", "toolchain_install",
    "toolchain_tree_check", "worker_environment", "toolchain_version_probe", "toolchain_version_match",
    "source_gates", "worker_storage_verify", "cwd_restore", "network_observer_finish",
    "summary_guard_probe", "source_lease_cleanup", "worker_cleanup", "fallback_tree_cleanup",
    "summary_guard_finish", "success_receipt", "output_write",
))
SOURCE_RUNTIME_DIAGNOSTICS = frozenset(
    "source_runtime_" + stage + "_" + reason
    for stage in PRIVATE_VALIDATION_STAGES
    for reason in PRIVATE_VALIDATION_REASONS
)
SOURCE_FETCH_DIAGNOSTICS = frozenset(
    "source_fetch_" + operation + "_" + failure_class
    for operation in PRIVATE_FETCH_OPERATIONS
    for failure_class in PRIVATE_FETCH_CLASSES
)
SOURCE_BOOTSTRAP_DIAGNOSTICS = frozenset(
    "source_bootstrap_" + check for check in CORE_BOOTSTRAP_CHECKS
)
SOURCE_LEASE_OPEN_CLASS_DIAGNOSTICS = (
    frozenset(SOURCE_LEASE_OPEN_ERROR_DIAGNOSTICS.values())
    | frozenset(("source_lease_open_other",))
)
SOURCE_GATE_COMMAND_DIAGNOSTICS = {
    "spawn_failure": "source_gate_spawn_failure",
    "nonzero_exit": "source_gate_nonzero_exit",
    "helper_failure": "source_gate_helper_failure",
    "capture_invalid": "source_gate_capture_invalid",
    "capture_overflow": "source_gate_capture_overflow",
}
SOURCE_GATE_DIAGNOSTICS = frozenset(SOURCE_GATE_COMMAND_DIAGNOSTICS.values())
SOURCE_GATES_NODE_REASONS_BY_SUBSTAGE = (
    ("none", (
        "invalid_input", "tool_unavailable", "accepted_provenance_invalid", "lock_missing",
        "lock_already_present", "manifest_invalid", "limit_exceeded", "deadline_exceeded",
        "capture_invalid", "contract_refused",
    )),
    ("runtime_version", (
        "toolchain_mismatch", "command_failed", "capture_invalid", "tool_unavailable",
        "deadline_exceeded",
    )),
    ("npm_version", (
        "toolchain_mismatch", "command_failed", "capture_invalid", "tool_unavailable",
        "deadline_exceeded",
    )),
    ("lock_generation", (
        "command_failed", "capture_invalid", "tool_unavailable", "deadline_exceeded",
    )),
    ("lock_validation", ("accepted_provenance_invalid",)),
    ("bulk_audit", (
        "limit_exceeded", "manifest_invalid", "lock_missing", "accepted_provenance_invalid",
        "audit_unavailable", "audit_response_invalid", "vulnerable_dependency",
        "deadline_exceeded", "capture_invalid", "command_failed", "tool_unavailable",
    )),
    ("npm_ci", ("command_failed", "capture_invalid", "tool_unavailable", "deadline_exceeded")),
    ("typecheck", ("command_failed", "capture_invalid", "tool_unavailable", "deadline_exceeded")),
    ("tests", ("command_failed", "capture_invalid", "tool_unavailable", "deadline_exceeded")),
)
SOURCE_GATES_NODE_COMMAND_SUBSTAGES = (
    "runtime_version", "npm_version", "lock_generation", "bulk_audit", "npm_ci", "typecheck",
    "tests",
)
SOURCE_GATES_NODE_COMMAND_CHECKS = (
    "spawn_failure", "nonzero_exit", "timeout", "capture_invalid", "capture_overflow",
    "helper_failure",
)
SOURCE_GATES_NODE_DIAGNOSTIC_REASONS = {
    **{
        "source_gates_node_" + substage + "_" + reason:
            "capture_invalid" if reason == "capture_invalid" else "runner_unavailable"
        for substage, reasons in SOURCE_GATES_NODE_REASONS_BY_SUBSTAGE
        for reason in reasons
    },
    **{
        "source_gates_node_" + substage + "_command_" + check: "runner_unavailable"
        for substage in SOURCE_GATES_NODE_COMMAND_SUBSTAGES
        for check in SOURCE_GATES_NODE_COMMAND_CHECKS
    },
}
SOURCE_GATES_NODE_DIAGNOSTICS = frozenset(SOURCE_GATES_NODE_DIAGNOSTIC_REASONS)
SUMMARY_GUARD_CHECKS = frozenset((
    "input", "protect_controls", "runner_identity", "prepare_summary", "real_probe",
    "verify_controls", "make_scratch", "write_denial_probe", "standin_check", "remove_scratch",
    "protect_controls_workspace_owner", "protect_controls_directory_type_owner",
    "protect_controls_directory_permissions", "protect_controls_file_reference",
    "protect_controls_file_type_owner", "protect_controls_file_permissions",
))
SUMMARY_GUARD_DIAGNOSTIC_MAP = {
    check: "summary_guard_" + check for check in SUMMARY_GUARD_CHECKS
}
SUMMARY_GUARD_DIAGNOSTICS = frozenset(SUMMARY_GUARD_DIAGNOSTIC_MAP.values())
PRESERVED_SOURCE_DIAGNOSTICS = (
    SOURCE_RUNTIME_DIAGNOSTICS | SOURCE_FETCH_DIAGNOSTICS
    | SOURCE_BOOTSTRAP_DIAGNOSTICS | SOURCE_LEASE_OPEN_CLASS_DIAGNOSTICS
    | SOURCE_GATE_DIAGNOSTICS | SOURCE_GATES_NODE_DIAGNOSTICS
)
PRESERVED_SUMMARY_GUARD_DIAGNOSTICS = SUMMARY_GUARD_DIAGNOSTICS
PRIVILEGE_PROBE_CHECK_DIAGNOSTICS = {
    "probe_process_group_cleanup": "worker_privilege_probe_group_cleanup",
    "probe_process_capture_cleanup": "worker_privilege_probe_capture_cleanup",
    "probe_process_census": "worker_privilege_probe_census",
    "probe_process_survivor": "worker_privilege_probe_survivor",
    "probe_process_timeout": "worker_privilege_probe_timeout",
}
SOURCE_GATES_SURVIVOR_CLASSES = (
    "python", "ps", "developer_shim", "helper_preferences", "helper_notifications",
    "helper_launch_services", "helper_security", "helper_trust", "helper_containers",
    "apple_system_path", "other", "unknown", "additional",
)
SOURCE_GATES_CLEANUP_DIAGNOSTICS = frozenset(
    "source_gates_survivor_" + category for category in SOURCE_GATES_SURVIVOR_CLASSES
) | frozenset((
    "source_gates_survivor_multiple", "source_gates_timeout", "source_gates_census",
    "source_gates_group_cleanup", "source_gates_capture_cleanup", "source_gates_restore",
    "source_gates_cleanup_unclassified", "source_gates_wait_uncertain",
    "source_gates_audit_request",
))
CLEANUP_DIAGNOSTICS = frozenset((
    "cleanup_lease", "cleanup_storage", "cleanup_worker", "cleanup_summary",
    "cleanup_summary_census", "cleanup_summary_present", "cleanup_summary_present_python",
    "cleanup_summary_present_ps",
    "cleanup_summary_present_developer_shim", "cleanup_summary_present_helper_preferences",
    "cleanup_summary_present_helper_notifications", "cleanup_summary_present_helper_launch_services",
    "cleanup_summary_present_helper_security", "cleanup_summary_present_helper_trust",
    "cleanup_summary_present_helper_containers", "cleanup_summary_present_apple_system_path",
    "cleanup_summary_probe", "cleanup_summary_restore", "cleanup_summary_close", "cleanup_dash",
    "cleanup_unknown",
)) | SOURCE_GATES_CLEANUP_DIAGNOSTICS
DIAGNOSTICS = (
    OPERATION_DIAGNOSTICS | CLEANUP_DIAGNOSTICS | SOURCE_RUNTIME_DIAGNOSTICS
    | SOURCE_FETCH_DIAGNOSTICS | SOURCE_BOOTSTRAP_DIAGNOSTICS | SOURCE_LEASE_OPEN_CLASS_DIAGNOSTICS
    | SOURCE_GATE_DIAGNOSTICS | SOURCE_GATES_NODE_DIAGNOSTICS | SUMMARY_GUARD_DIAGNOSTICS
    | frozenset(("none", "unavailable"))
)
DETAILED_DIAGNOSTICS = DIAGNOSTICS - frozenset(("none", "unavailable"))
NO_OPERATION_STAGES = frozenset(("arguments", "context", "host"))

PRIVILEGE_IDENTITY_CHECK = """\
if os.getuid() != uid or os.geteuid() != uid or os.getgid() != 20:
    raise SystemExit(51)
"""
PRIVILEGE_SCRIPT = '''\
import os, subprocess, sys
uid = int(sys.argv[1])
''' + PRIVILEGE_IDENTITY_CHECK + '''\
base_env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": os.environ["HOME"], "LANG": "C", "LC_ALL": "C"}
try:
    sudo = subprocess.run(("/usr/bin/sudo", "-n", "/usr/bin/true"), stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=base_env,
                          timeout=3, close_fds=True, check=False)
except BaseException:
    raise SystemExit(53)
expected = (b"password is required", b"not in the sudoers", b"not allowed to execute", b"not allowed to run sudo")
if (sudo.returncode != 1 or sudo.stdout or len(sudo.stderr) > 1024
        or not any(value in sudo.stderr.lower() for value in expected)):
    raise SystemExit(54)
os.write(1, b"KD-CORE-CONTRACT:privilege=verified\\n")
'''
PRIVILEGE_MARKER = b"KD-CORE-CONTRACT:privilege=verified\n"


class Refusal(Exception):
    def __init__(self, reason, stage, diagnostic=None):
        self.reason = reason if type(reason) is str and reason in REASONS else "internal_error"
        self.stage = stage if type(stage) is str and stage in STAGES else "internal"
        if type(diagnostic) is str and diagnostic in DIAGNOSTICS:
            self.diagnostic = diagnostic
        elif self.stage in NO_OPERATION_STAGES:
            self.diagnostic = "none"
        else:
            self.diagnostic = "unavailable"
        super().__init__(self.reason)


class _FailureDiagnostics:
    def __init__(self):
        self.first_cleanup = None

    def remember_cleanup(self, error, operation, cleanup_stage=None):
        if self.first_cleanup is not None:
            return
        if type(cleanup_stage) is str and cleanup_stage in CLEANUP_DIAGNOSTICS:
            self.first_cleanup = cleanup_stage
        elif (operation == "source_gates" and type(getattr(error, "cleanup_diagnostic", None)) is str
                and error.cleanup_diagnostic in SOURCE_GATES_CLEANUP_DIAGNOSTICS):
            self.first_cleanup = error.cleanup_diagnostic
        elif type(getattr(error, "diagnostic", None)) is str and error.diagnostic in DETAILED_DIAGNOSTICS:
            self.first_cleanup = error.diagnostic
        elif type(operation) is str and operation in OPERATION_DIAGNOSTICS:
            self.first_cleanup = operation
        else:
            self.first_cleanup = "unavailable"

    def attach(self, error, operation, cleanup_stage=None):
        reason = getattr(error, "reason", None)
        stage = getattr(error, "stage", "internal")
        if type(error) is not Refusal:
            reason, stage = "internal_error", "internal"
        if reason == "cleanup_incomplete":
            self.remember_cleanup(error, operation, cleanup_stage)
            return Refusal(reason, stage, diagnostic=self.first_cleanup)
        diagnostic = getattr(error, "diagnostic", None)
        if (type(diagnostic) is str
                and diagnostic in (OPERATION_DIAGNOSTICS | PRESERVED_SOURCE_DIAGNOSTICS)):
            return Refusal(reason, stage, diagnostic=diagnostic)
        if (type(error) is Refusal and reason == "summary_guard_failed" and stage == "summary_guard"
                and type(diagnostic) is str
                and diagnostic in PRESERVED_SUMMARY_GUARD_DIAGNOSTICS):
            return Refusal(reason, stage, diagnostic=diagnostic)
        if stage in NO_OPERATION_STAGES and operation not in OPERATION_DIAGNOSTICS:
            return Refusal(reason, stage, diagnostic="none")
        if type(operation) is str and operation in OPERATION_DIAGNOSTICS:
            return Refusal(reason, stage, diagnostic=operation)
        return Refusal(reason, stage, diagnostic="unavailable")


@contextmanager
def _lease_with_diagnostic_capture(lease_context, diagnostics, operation_getter, cleanup_state):
    with lease_context as lease:
        try:
            yield lease
        except BaseException as error:
            if getattr(error, "reason", None) == "cleanup_incomplete":
                diagnostics.remember_cleanup(error, operation_getter(), cleanup_state.get("first"))
            raise


def _load_control_sibling(name):
    if type(name) is not str or name not in ALLOWED_CONTROL_SIBLINGS:
        raise ImportError("control module unavailable")
    directory = Path(__file__).resolve(strict=True).parent
    path = (directory / (name + ".py")).resolve(strict=True)
    if path.parent != directory or not path.is_file():
        raise ImportError("control module unavailable")
    loaded = sys.modules.get(name)
    if loaded is not None and getattr(loaded, "__file__", None):
        try:
            if Path(loaded.__file__).resolve(strict=True) == path:
                return loaded
        except OSError:
            pass
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError("control module unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def _valid_sha(value):
    return type(value) is str and SHA1_RE.fullmatch(value) is not None


def _valid_sha256(value):
    return type(value) is str and SHA256_RE.fullmatch(value) is not None


def _safe_id(value):
    return type(value) is str and DECIMAL_RE.fullmatch(value) is not None


def _summary_guard_diagnostic(error, rules):
    rules_refusal = getattr(rules, "Refusal", None)
    if not isinstance(rules_refusal, type) or type(error) is not rules_refusal:
        return None
    reason = getattr(error, "reason", None)
    stage = getattr(error, "stage", None)
    if (type(reason) is not str or type(stage) is not str
            or (reason, stage) not in (
                ("summary_guard_failed", "summary_guard"),
                ("cleanup_incomplete", "cleanup_summary"),
            )):
        return None
    check = getattr(error, "diagnostic", None)
    if type(check) is str and check in SUMMARY_GUARD_DIAGNOSTIC_MAP:
        return SUMMARY_GUARD_DIAGNOSTIC_MAP[check]
    return None


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _canonical_json(record):
    try:
        payload = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    except BaseException:
        raise Refusal("capture_invalid", "receipt") from None
    return payload


def _parse_arguments(arguments):
    if type(arguments) not in (tuple, list) or len(arguments) != 8:
        raise Refusal("invalid_input", "arguments")
    if (arguments[0] != "run" or arguments[1] != "--token-stdin"
            or tuple(arguments[2::2]) != ("--source-sha", "--base-sha", "--base-branch")):
        raise Refusal("invalid_input", "arguments")
    source_sha, base_sha, branch = arguments[3], arguments[5], arguments[7]
    if (not _valid_sha(source_sha) or not _valid_sha(base_sha)
            or type(branch) is not str or branch not in BASE_BRANCHES):
        raise Refusal("invalid_input", "arguments")
    return {"source_sha": source_sha, "base_sha": base_sha, "base_branch": branch, "concern": CONCERN}


def _read_token_stdin(stream):
    try:
        raw = stream.read(4097)
    except BaseException:
        raise Refusal("invalid_input", "arguments") from None
    if type(raw) is not bytes or len(raw) > 4096:
        raise Refusal("invalid_input", "arguments")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    if b"\n" in raw or b"\r" in raw:
        raise Refusal("invalid_input", "arguments")
    try:
        token = raw.decode("ascii", "strict")
    except UnicodeDecodeError:
        raise Refusal("invalid_input", "arguments") from None
    if TOKEN_RE.fullmatch(token) is None:
        raise Refusal("invalid_input", "arguments")
    return token


def _load_controls():
    try:
        reviewed = _load_control_sibling("macos_reviewed_build")
        capability = _load_control_sibling("macos_capability")
        boundary = _load_control_sibling("macos_boundary_guard")
        runtime = _load_control_sibling("macos_private_validation")
        rust = _load_control_sibling("macos_rust_toolchain")
        rules = _load_control_sibling("macos_rules_bootstrap")
    except BaseException:
        raise Refusal("runner_unavailable", "context") from None
    if getattr(reviewed, "capability", None) is None:
        raise Refusal("runner_unavailable", "context")
    return reviewed, capability, boundary, runtime, rust, rules


def _validate_context(environ, reviewed, capability, boundary, rust):
    control_sha = environ.get("CI_SHA", "")
    if not _valid_sha(control_sha):
        raise Refusal("source_binding_mismatch", "context")
    try:
        binding, root = _load_control_sibling("macos_rules_bootstrap")._public_context(
            environ, reviewed, capability, boundary,
        )
        run_id, run_attempt, runner_temp = rust._strict_context(environ, control_sha)
    except Refusal:
        raise
    except BaseException:
        raise Refusal("runner_unavailable", "context") from None
    if (binding.get("control_sha") != control_sha or binding.get("run_id") != run_id
            or binding.get("run_attempt") != run_attempt or not _safe_id(run_id)
            or not _safe_id(run_attempt) or not isinstance(root, Path)):
        raise Refusal("source_binding_mismatch", "context")
    return binding, root, runner_temp


def _validate_review_gate(request, binding, environ, runtime):
    source = environ.get("CORE_CONTRACT_REVIEWED_SOURCE_SHA", "")
    base = environ.get("CORE_CONTRACT_REVIEWED_BASE_SHA", "")
    branch = environ.get("CORE_CONTRACT_REVIEWED_BASE_BRANCH", "")
    candidate_ref = environ.get("CORE_CONTRACT_REVIEWED_CANDIDATE_REF", "")
    diff_sha256 = environ.get("CORE_CONTRACT_REVIEWED_DIFF_SHA256", "")
    if (environ.get("CORE_CONTRACT_ALLOWED_SHA") != request["source_sha"]
            or environ.get("CORE_CONTRACT_ALLOWED_CONTROL_SHA") != binding["control_sha"]
            or source != request["source_sha"] or base != request["base_sha"]
            or branch != request["base_branch"] or not _valid_sha256(diff_sha256)
            or type(candidate_ref) is not str or not candidate_ref or len(candidate_ref) > 160
            or any(character in candidate_ref for character in ("\n", "\r", "\x00"))):
        raise Refusal("source_binding_mismatch", "source_lease")
    if (type(environ.get(runtime.SOURCE_CANDIDATE_REF_ENV, candidate_ref)) is not str
            or environ.get(runtime.SOURCE_CANDIDATE_REF_ENV, candidate_ref) != candidate_ref):
        raise Refusal("source_binding_mismatch", "source_lease")
    return diff_sha256, candidate_ref


def _check_temp_root():
    try:
        info = TEMP_ROOT.lstat()
    except BaseException:
        raise Refusal("runner_unavailable", "context") from None
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o1777:
        raise Refusal("runner_unavailable", "context")


def _read_regular_file(path, *, max_bytes, expected_mode=None):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise Refusal("capture_invalid", "receipt")
    descriptor = None
    try:
        named = path.lstat()
        if (not stat.S_ISREG(named.st_mode) or named.st_uid != 0 or named.st_nlink != 1
                or named.st_size <= 0 or named.st_size > max_bytes
                or (expected_mode is not None and stat.S_IMODE(named.st_mode) != expected_mode)):
            raise ValueError
        descriptor = os.open(path, os.O_RDONLY | nofollow)
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)
                or opened.st_uid != 0 or opened.st_nlink != 1 or opened.st_size > max_bytes):
            raise ValueError
        chunks = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(4096, max_bytes + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise ValueError
            chunks.append(chunk)
        if total != opened.st_size:
            raise ValueError
        return b"".join(chunks)
    except BaseException:
        raise Refusal("capture_invalid", "receipt") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _validate_smoke_receipt(runner_temp, binding, rust):
    path = runner_temp / rust.REPORT_NAME
    payload = _read_regular_file(path, max_bytes=MAX_RECEIPT_BYTES, expected_mode=0o444)
    if not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        raise Refusal("source_binding_mismatch", "receipt")
    try:
        record = json.loads(payload[:-1].decode("ascii", "strict"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, ValueError, TypeError):
        raise Refusal("source_binding_mismatch", "receipt") from None
    expected_components = {component.name: component.sha256 for component in rust.COMPONENTS}
    required = {
        "schema_version", "concern", "status", "control_sha", "run_id", "run_attempt", "host",
        "toolchain", "components", "versions", "target", "smoke", "source", "offline", "cleanup",
    }
    if (type(record) is not dict or set(record) != required or _canonical_json(record) != payload
            or type(record["schema_version"]) is not int or record["schema_version"] != 1
            or record["concern"] != "rust-toolchain-smoke" or record["status"] != "passed"
            or record["control_sha"] != binding["control_sha"] or record["run_id"] != binding["run_id"]
            or record["run_attempt"] != binding["run_attempt"] or record["host"] != rust.TARGET
            or record["toolchain"] != rust.TOOLCHAIN_VERSION or record["components"] != expected_components
            or record["target"] != rust.TARGET or record["source"] != "none"
            or type(record["offline"]) is not bool or record["offline"] is not True
            or record["cleanup"] != "complete" or type(record["versions"]) is not dict
            or set(record["versions"]) != {"rustc", "cargo", "rustfmt", "clippy"}
            or record["versions"].get("rustc") != rust.EXPECTED_VERSIONS["rustc"]
            or record["versions"].get("cargo") not in ("0.100.0", "1.99.0", "1.99.1")
            or record["versions"].get("rustfmt") != rust.EXPECTED_VERSIONS["rustfmt"]
            or record["versions"].get("clippy") != rust.EXPECTED_VERSIONS["clippy"]
            or type(record["smoke"]) is not dict or set(record["smoke"]) != {"fmt", "clippy", "test"}
            or any(type(value) is not str or value != "passed" for value in record["smoke"].values())):
        raise Refusal("source_binding_mismatch", "receipt")
    return dict(record["versions"])


def _validate_source_lease(record, request, binding, worker_uid, runtime):
    required = {
        "repository_id", "source_sha", "base_sha", "base_branch", "concern", "candidate_class",
        "signature", "rules_lock", "tree", "source_execution", "app_build", "cleanup",
        "repository_scope", "metadata", "control_sha", "run_id", "run_attempt", "image_os",
        "image_version", "token_revocation", "signer_authority", "signatures", "ancestry",
        "revocation_policy", "worker_access",
    }
    if type(record) is not dict and not hasattr(record, "keys"):
        raise Refusal("source_validation_failed", "source_lease")
    if set(record.keys()) != required:
        raise Refusal("source_validation_failed", "source_lease")
    expected_tree = FEEDBACK_TREE_LABELS.get(request["concern"])
    if (request["concern"] == "core-build-diagnostic-return"
            and record.get("tree") == LOCKED_FOUNDATION_TREE
            and getattr(runtime, "CORE_CONTRACT_PACKAGE_LOCK_TREE", None) == LOCKED_FOUNDATION_TREE):
        expected_tree = LOCKED_FOUNDATION_TREE
    expected = {
        "source_sha": request["source_sha"], "base_sha": request["base_sha"],
        "base_branch": request["base_branch"], "concern": request["concern"],
        "signature": "verified", "rules_lock": "present",
        "tree": expected_tree,
        "source_execution": "not_run_at_yield", "app_build": "not_run", "cleanup": "lease_open",
        "repository_scope": "verified", "metadata": "verified", "control_sha": binding["control_sha"],
        "run_id": binding["run_id"], "run_attempt": binding["run_attempt"],
        "image_os": binding["image_os"], "image_version": binding["image_version"],
        "token_revocation": "confirmed_before_yield", "signer_authority": "bound_base",
        "signatures": "all_new_commits_verified", "ancestry": "base_ancestor",
        "revocation_policy": "current_control_fingerprints", "worker_access": "uid_read_only",
    }
    if (any(record[key] != value for key, value in expected.items())
            or not _safe_id(record["repository_id"])
            or record["candidate_class"] not in ("permanent-tip", "signed-descendant")
            or (record["candidate_class"] == "permanent-tip") != (request["source_sha"] == request["base_sha"])
            or type(worker_uid) is not int or worker_uid <= 0 or worker_uid >= 60000):
        raise Refusal("source_validation_failed", "source_lease")
    return dict(record)


def _validate_source_path(source_path, storage_root):
    try:
        source = Path(source_path)
        if source.resolve(strict=True) != source or source.is_symlink() or not source.is_dir():
            raise ValueError
        source.relative_to(storage_root)
        info = source.lstat()
        if info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o077:
            raise ValueError
        for relative in (
            "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rustfmt.toml", "clippy.toml",
            "crates/host/api/Cargo.toml", "crates/host/mock/Cargo.toml",
            "crates/host/conformance/Cargo.toml",
        ):
            target = source / relative
            target_info = target.lstat()
            if (not stat.S_ISREG(target_info.st_mode) or target_info.st_uid != 0
                    or target_info.st_nlink != 1
                    or target_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
                raise ValueError
        git_metadata = source / ".git"
        git_info = git_metadata.lstat()
        if not (stat.S_ISDIR(git_info.st_mode) or stat.S_ISREG(git_info.st_mode)) or git_info.st_uid != 0:
            raise ValueError
        return source
    except BaseException:
        raise Refusal("source_validation_failed", "source_tree") from None


def _stream_git_diff_hash(source, base_sha, source_sha, expected_sha256, git_executable, deadline):
    environment = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/var/empty", "LANG": "C", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0", "GIT_PAGER": "cat", "PAGER": "cat", "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "color.ui", "GIT_CONFIG_VALUE_0": "false",
    }
    argv = (git_executable, "diff", "--binary", "--full-index", "--no-ext-diff", base_sha, source_sha)
    process = None
    selector = None
    digest = hashlib.sha256()
    stdout_size = 0
    stderr_size = 0
    try:
        process = subprocess.Popen(
            argv, cwd=str(source), env=environment, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, start_new_session=True,
        )
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError
            for key, unused_mask in selector.select(min(remaining, 0.25)):
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                if key.data == "stdout":
                    stdout_size += len(chunk)
                    if stdout_size > MAX_DIFF_BYTES:
                        raise OverflowError
                    digest.update(chunk)
                else:
                    stderr_size += len(chunk)
                    if stderr_size > MAX_CAPTURE_BYTES:
                        raise OverflowError
            if process.poll() is not None and not selector.get_map():
                break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        returncode = process.wait(timeout=min(remaining, MAX_COMMAND_SECONDS))
        if returncode != 0 or stderr_size != 0:
            raise ValueError
    except BaseException:
        if process is not None and process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            except BaseException:
                raise Refusal("cleanup_incomplete", "cleanup") from None
        raise Refusal("source_diff_mismatch", "source_diff") from None
    finally:
        if selector is not None:
            selector.close()
        if process is not None:
            for stream in (process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()
    actual = digest.hexdigest()
    if actual != expected_sha256:
        raise Refusal("source_diff_mismatch", "source_diff")
    return actual


def _source_commands(source, tool_paths, *, include_parser=False):
    if type(include_parser) is not bool:
        raise Refusal("capture_invalid", "source_gates")
    cargo = str(tool_paths["cargo"])
    workspace_manifest = str(source / "Cargo.toml")
    commands = (
        ("format", (cargo, "fmt", "--manifest-path", workspace_manifest, "--all", "--", "--check")),
        ("clippy", (cargo, "clippy", "--offline", "--manifest-path", workspace_manifest,
                     "--workspace", "--all-targets", "--locked", "--", "-D", "warnings")),
        ("workspace_tests", (cargo, "test", "--offline", "--manifest-path", workspace_manifest,
                              "--workspace", "--all-targets", "--locked")),
        ("api_tests", (cargo, "test", "--offline", "--manifest-path",
                        str(source / "crates/host/api/Cargo.toml"), "--all-targets", "--locked")),
        ("mock_tests", (cargo, "test", "--offline", "--manifest-path",
                         str(source / "crates/host/mock/Cargo.toml"), "--all-targets", "--locked")),
        ("conformance_tests", (cargo, "test", "--offline", "--manifest-path",
                                str(source / "crates/host/conformance/Cargo.toml"), "--all-targets", "--locked")),
    )
    if not include_parser:
        return commands
    fuzz_manifest = str(source / "fuzz/Cargo.toml")
    return commands + (
        ("parser_format", (cargo, "--locked", "--offline", "fmt", "--manifest-path", fuzz_manifest,
                            "--all", "--", "--check")),
        ("parser_clippy", (cargo, "clippy", "--offline", "--manifest-path", fuzz_manifest,
                            "--all-targets", "--locked", "--", "-D", "warnings")),
        ("parser_replay", (cargo, "run", "--locked", "--offline", "--manifest-path", fuzz_manifest)),
    )


def _validated_fuzz_workspace(source, lease_record, runtime):
    concern = lease_record.get("concern") if type(lease_record) is dict else None
    if concern == CONCERN:
        return False
    if concern not in FEEDBACK_TREE_LABELS:
        raise Refusal("source_validation_failed", "source_validation")
    foundation_files = getattr(runtime, "CORE_CONTRACT_FOUNDATION_FILES", None)
    required = frozenset((
        "fuzz/Cargo.toml", "fuzz/Cargo.lock", "fuzz/src/main.rs",
        "fuzz/fuzz_targets/identifiers.rs", "fuzz/fuzz_targets/tool_error_codes.rs",
        "fuzz/fuzz_targets/versions.rs",
    ))
    if type(foundation_files) is not frozenset or not required.issubset(foundation_files):
        raise Refusal("source_validation_failed", "source_validation")
    marker = source / "fuzz/Cargo.toml"
    try:
        marker_info = marker.lstat()
    except FileNotFoundError:
        if concern == "core-node-lock-return":
            raise Refusal("source_validation_failed", "source_validation") from None
        return False
    except OSError:
        raise Refusal("source_validation_failed", "source_validation") from None
    if (not stat.S_ISREG(marker_info.st_mode) or stat.S_ISLNK(marker_info.st_mode)
            or marker_info.st_uid != 0 or marker_info.st_nlink != 1
            or marker_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)):
        raise Refusal("source_validation_failed", "source_validation")
    return True


def _prepare_worker_storage(root, uid, capability):
    storage = None
    try:
        storage = Path(tempfile.mkdtemp(prefix=WORKER_PREFIX, dir=str(TEMP_ROOT)))
        identity = capability._prepare_storage_directory(storage, uid)
        for name in ("cargo-home", "target", "tmp", "rustup-home"):
            path = storage / name
            os.mkdir(path, 0o700)
            os.chown(path, uid, capability.PROBE_PRIMARY_GID)
            os.chmod(path, 0o700)
            info = path.lstat()
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != uid
                    or info.st_gid != capability.PROBE_PRIMARY_GID or stat.S_IMODE(info.st_mode) != 0o700):
                raise OSError
        return storage, identity
    except BaseException:
        if storage is not None:
            try:
                capability._remove_probe_tree(storage)
            except BaseException:
                raise Refusal("cleanup_incomplete", "cleanup") from None
        raise Refusal("runner_unavailable", "worker_setup") from None


def _worker_environment(home, storage, prefix, tools, host_toolchain, worker_tools, reviewed, source):
    environment = _load_control_sibling("macos_rust_toolchain")._worker_environment(
        home, storage, prefix, tools, host_toolchain, worker_tools, _load_control_sibling("macos_capability"), reviewed,
    )
    environment.update({
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_COUNT": "1",
        "GIT_CONFIG_KEY_0": "safe.directory", "GIT_CONFIG_VALUE_0": str(source),
        "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
    })
    if environment.get("CARGO_NET_OFFLINE") != "true":
        raise Refusal("runner_unavailable", "worker_setup")
    return environment


def _run_privilege_probe(worker_uid, home, host_toolchain, reviewed):
    try:
        environment = reviewed._child_environment(home, Path("/tmp"), host_toolchain)
        reviewed._run_probe_step(
            reviewed._probe_argv(host_toolchain["python"], PRIVILEGE_SCRIPT, str(worker_uid)),
            worker_uid, env=environment, python_executable=host_toolchain["python"],
            stage="privilege", expected_stdout=PRIVILEGE_MARKER,
        )
    except BaseException as error:
        if getattr(error, "reason", None) == "cleanup_incomplete":
            probe_check = getattr(error, "probe_check", None)
            diagnostic = (
                PRIVILEGE_PROBE_CHECK_DIAGNOSTICS.get(probe_check, "worker_privilege_probe")
                if type(probe_check) is str else "worker_privilege_probe"
            )
            raise Refusal("cleanup_incomplete", "cleanup", diagnostic=diagnostic) from None
        raise Refusal("runner_unavailable", "worker_setup", diagnostic="worker_privilege_probe") from None
    try:
        reviewed._worker_census(worker_uid, host_toolchain["python"], "privilege")
    except BaseException as error:
        if getattr(error, "reason", None) == "cleanup_incomplete":
            raise Refusal("cleanup_incomplete", "cleanup", diagnostic="worker_privilege_census") from None
        raise Refusal("runner_unavailable", "worker_setup", diagnostic="worker_privilege_census") from None


def _run_inside_source(source, original_cwd, command):
    try:
        os.chdir(source)
        return command()
    finally:
        try:
            os.chdir(original_cwd)
        except BaseException:
            raise Refusal("cleanup_incomplete", "cleanup", diagnostic="cwd_restore") from None


def _run_gates(source, environment, uid, host_toolchain, capability, rust, tools, deadline,
               capture_failure=False, include_parser=False):
    if type(capture_failure) is not bool or type(include_parser) is not bool:
        raise Refusal("capture_invalid", "source_gates")
    if include_parser and not capture_failure:
        raise Refusal("gate_failed", "receipt")
    commands = _source_commands(source, tools, include_parser=include_parser)
    selected_gates = tuple(stage for stage, unused_argv in commands)
    completed = []
    for stage, argv in commands:
        if time.monotonic() >= deadline:
            raise Refusal("gate_failed", stage)
        try:
            result = rust._run_worker_command(
                argv, uid, environment, host_toolchain["python"], capability,
                stage=stage, deadline=deadline, timeout=MAX_COMMAND_SECONDS,
                allow_nonzero_capture=capture_failure,
            )
        except BaseException as error:
            if getattr(error, "reason", None) == "cleanup_incomplete":
                raise Refusal("cleanup_incomplete", "cleanup") from None
            command_check = getattr(error, "command_check", None)
            diagnostic = (
                SOURCE_GATE_COMMAND_DIAGNOSTICS.get(command_check)
                if type(command_check) is str else None
            )
            if diagnostic is not None and stage in SOURCE_GATE_STAGES:
                reason = "capture_invalid" if getattr(error, "reason", None) == "capture_invalid" else "gate_failed"
                raise Refusal(reason, stage, diagnostic=diagnostic) from None
            if getattr(error, "reason", None) == "capture_invalid":
                raise Refusal("capture_invalid", stage) from None
            raise Refusal("gate_failed", stage) from None
        if (type(result.returncode) is not int
                or type(result.stdout) is not bytes or type(result.stderr) is not bytes
                or len(result.stdout) > MAX_CAPTURE_BYTES or len(result.stderr) > MAX_CAPTURE_BYTES):
            raise Refusal("capture_invalid", stage)
        try:
            _load_control_sibling("macos_reviewed_build")._worker_census(uid, host_toolchain["python"], stage)
        except BaseException:
            raise Refusal("cleanup_incomplete", "cleanup") from None
        if result.returncode != 0:
            if capture_failure:
                return {
                    "completed": tuple(completed), "failed_stage": stage,
                    "selected_gates": selected_gates,
                    "returncode": result.returncode, "stdout": result.stdout, "stderr": result.stderr,
                    "stdout_truncated": getattr(result, "stdout_truncated", False),
                    "stderr_truncated": getattr(result, "stderr_truncated", False),
                }
            raise Refusal("capture_invalid", stage)
        completed.append(stage)
    if capture_failure:
        return {"completed": tuple(completed), "selected_gates": selected_gates,
                "failed_stage": None, "returncode": 0,
                "stdout": b"", "stderr": b"", "stdout_truncated": False,
                "stderr_truncated": False}
    if tuple(completed) != GATE_NAMES:
        raise Refusal("gate_failed", "receipt")
    return {name: "passed" for name in GATE_NAMES}


def _validate_success_record(record, binding, request, lease_record, diff_sha256, versions, gates,
                             network_captured, summary_guard_passed):
    keys = {
        "schema_version", "concern", "status", "control_sha", "run_id", "run_attempt", "repository_id",
        "source_sha", "base_sha", "base_branch", "candidate_class", "signer_authority", "signatures",
        "ancestry", "token_revocation", "offline", "image_os", "image_version", "toolchain_versions",
        "gates", "gate_count", "gates_passed", "gates_failed", "suites", "suite_count",
        "suites_passed", "suites_failed", "reviewed_diff_sha256", "source_tree", "lease_cleanup",
        "process_cleanup", "identity_cleanup", "summary_guard", "summary_guard_bypass_test",
        "positive_sentinel", "network_observation",
    }
    if type(record) is not dict or set(record) != keys:
        raise Refusal("capture_invalid", "receipt")
    if (type(record["schema_version"]) is not int or record["schema_version"] != SCHEMA_VERSION
            or record["concern"] != CONCERN or record["status"] != "passed"
            or record["control_sha"] != binding["control_sha"] or record["run_id"] != binding["run_id"]
            or record["run_attempt"] != binding["run_attempt"]
            or record["repository_id"] != lease_record["repository_id"]
            or record["source_sha"] != request["source_sha"] or record["base_sha"] != request["base_sha"]
            or record["base_branch"] != request["base_branch"]
            or record["candidate_class"] != lease_record["candidate_class"]
            or record["signer_authority"] != "bound_base"
            or record["signatures"] != "all_new_commits_verified" or record["ancestry"] != "base_ancestor"
            or record["token_revocation"] != "confirmed_before_execution"
            or type(record["offline"]) is not bool or record["offline"] is not True
            or record["image_os"] != binding["image_os"] or record["image_version"] != binding["image_version"]
            or record["toolchain_versions"] != versions or record["gates"] != gates
            or type(record["gate_count"]) is not int or record["gate_count"] != 6
            or type(record["gates_passed"]) is not int or record["gates_passed"] != 6
            or type(record["gates_failed"]) is not int or record["gates_failed"] != 0
            or record["suites"] != list(SUITE_NAMES)
            or type(record["suite_count"]) is not int or record["suite_count"] != 4
            or type(record["suites_passed"]) is not int or record["suites_passed"] != 4
            or type(record["suites_failed"]) is not int or record["suites_failed"] != 0
            or record["reviewed_diff_sha256"] != diff_sha256
            or record["source_tree"] != "uid_read_only" or record["lease_cleanup"] != "complete"
            or record["process_cleanup"] != "complete" or record["identity_cleanup"] != "complete"
            or record["summary_guard"] != "append_sibling_create_readback_restore"
            or record["summary_guard_bypass_test"] != "passed"
            or record["positive_sentinel"] != "passed"
            or record["network_observation"] != "captured"
            or not network_captured or not summary_guard_passed):
        raise Refusal("capture_invalid", "receipt")
    for key in ("control_sha", "source_sha", "base_sha"):
        if not _valid_sha(record[key]):
            raise Refusal("capture_invalid", "receipt")
    if not _valid_sha256(record["reviewed_diff_sha256"]):
        raise Refusal("capture_invalid", "receipt")
    if (not _safe_id(record["run_id"]) or not _safe_id(record["run_attempt"])
            or not _safe_id(record["repository_id"]) or record["base_branch"] not in BASE_BRANCHES
            or record["candidate_class"] not in ("permanent-tip", "signed-descendant")
            or type(record["toolchain_versions"]) is not dict
            or set(record["toolchain_versions"]) != {"rustc", "cargo", "rustfmt", "clippy"}
            or any(type(value) is not str or not value.isascii() or len(value) > 128
                   for value in record["toolchain_versions"].values())
            or type(record["gates"]) is not dict or set(record["gates"]) != set(GATE_NAMES)
            or any(type(value) is not str or value != "passed" for value in record["gates"].values())
            or type(record["suites"]) is not list or any(type(value) is not str for value in record["suites"])):
        raise Refusal("capture_invalid", "receipt")
    return record


def _build_success_record(binding, request, lease_record, diff_sha256, versions, gates):
    return {
        "schema_version": SCHEMA_VERSION,
        "concern": CONCERN,
        "status": "passed",
        "control_sha": binding["control_sha"],
        "run_id": binding["run_id"],
        "run_attempt": binding["run_attempt"],
        "repository_id": lease_record["repository_id"],
        "source_sha": request["source_sha"],
        "base_sha": request["base_sha"],
        "base_branch": request["base_branch"],
        "candidate_class": lease_record["candidate_class"],
        "signer_authority": "bound_base",
        "signatures": "all_new_commits_verified",
        "ancestry": "base_ancestor",
        "token_revocation": "confirmed_before_execution",
        "offline": True,
        "image_os": binding["image_os"],
        "image_version": binding["image_version"],
        "toolchain_versions": dict(versions),
        "gates": dict(gates),
        "gate_count": 6,
        "gates_passed": 6,
        "gates_failed": 0,
        "suites": list(SUITE_NAMES),
        "suite_count": 4,
        "suites_passed": 4,
        "suites_failed": 0,
        "reviewed_diff_sha256": diff_sha256,
        "source_tree": "uid_read_only",
        "lease_cleanup": "complete",
        "process_cleanup": "complete",
        "identity_cleanup": "complete",
        "summary_guard": "append_sibling_create_readback_restore",
        "summary_guard_bypass_test": "passed",
        "positive_sentinel": "passed",
        "network_observation": "captured",
    }


def _runtime_refusal(runtime, error):
    if getattr(error, "reason", None) == "cleanup_incomplete":
        return Refusal("cleanup_incomplete", "cleanup")
    if getattr(error, "reason", None) == "revocation_unconfirmed":
        return Refusal("token_revocation_unconfirmed", "source_validation")
    if getattr(error, "reason", None) in ("signature_invalid", "base_invalid", "bootstrap_not_approved"):
        return Refusal("source_binding_mismatch", "source_validation")
    if getattr(error, "reason", None) == "invalid_input":
        return Refusal("invalid_input", "source_validation")
    return Refusal("source_validation_failed", "source_validation")


def _source_runtime_diagnostic(runtime, error):
    try:
        if (getattr(runtime, "REASONS", None) != PRIVATE_VALIDATION_REASONS
                or getattr(runtime, "STAGES", None) != PRIVATE_VALIDATION_STAGES):
            return None
        reason = getattr(error, "reason", None)
        stage = getattr(error, "stage", None)
        if (type(reason) is not str or reason not in PRIVATE_VALIDATION_REASONS
                or type(stage) is not str or stage not in PRIVATE_VALIDATION_STAGES):
            return None
        if (reason == "bootstrap_snapshot_invalid" and stage == "bootstrap"):
            if getattr(runtime, "CORE_BOOTSTRAP_CHECKS", None) == CORE_BOOTSTRAP_CHECKS:
                check = getattr(error, "core_check", None)
                if type(check) is str and check in CORE_BOOTSTRAP_CHECKS:
                    return "source_bootstrap_" + check
        if reason == "source_fetch_unavailable" and stage == "fetch":
            if (getattr(runtime, "FETCH_DIAGNOSTIC_OPERATIONS", None) == PRIVATE_FETCH_OPERATIONS
                    and getattr(runtime, "FETCH_DIAGNOSTIC_CLASSES", None) == PRIVATE_FETCH_CLASSES):
                source_diagnostic = getattr(error, "source_diagnostic", None)
                if (type(source_diagnostic) is tuple and len(source_diagnostic) == 2
                        and type(source_diagnostic[0]) is str
                        and source_diagnostic[0] in PRIVATE_FETCH_OPERATIONS
                        and type(source_diagnostic[1]) is str
                        and source_diagnostic[1] in PRIVATE_FETCH_CLASSES):
                    return "source_fetch_" + source_diagnostic[0] + "_" + source_diagnostic[1]
        return "source_runtime_" + stage + "_" + reason
    except BaseException:
        return None


def _source_lease_open_exception_diagnostic(error):
    return SOURCE_LEASE_OPEN_ERROR_DIAGNOSTICS.get(type(error), "source_lease_open_other")


def _make_directory(prefix, mode):
    path = None
    try:
        path = Path(tempfile.mkdtemp(prefix=prefix, dir=str(TEMP_ROOT)))
        os.chown(path, 0, 0)
        os.chmod(path, mode)
        info = path.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != mode):
            raise OSError
        return path
    except BaseException:
        if path is not None:
            try:
                shutil.rmtree(path)
            except BaseException:
                raise Refusal("cleanup_incomplete", "cleanup") from None
        raise Refusal("runner_unavailable", "worker_setup") from None


def _node_refusal_diagnostic(error):
    try:
        if type(error).__name__ != "NodeContractRefusal":
            return None
        reason = getattr(error, "reason", None)
        substage = getattr(error, "substage", None)
        command_check = getattr(error, "command_check", None)
        if type(reason) is not str or (substage is not None and type(substage) is not str):
            return None
        label = "none" if substage is None else substage
        if reason == "command_failed" and type(command_check) is str:
            candidate = "source_gates_node_" + label + "_command_" + command_check
        else:
            candidate = "source_gates_node_" + label + "_" + reason
        if candidate in SOURCE_GATES_NODE_DIAGNOSTICS:
            return candidate
    except BaseException:
        pass
    return None


def _toolchain_refusal(error, stage):
    reason = getattr(error, "reason", None)
    if reason == "cleanup_incomplete":
        diagnostic = getattr(error, "cleanup_diagnostic", None)
        if type(diagnostic) is str and diagnostic in SOURCE_GATES_CLEANUP_DIAGNOSTICS:
            return Refusal("cleanup_incomplete", "cleanup", diagnostic=diagnostic)
        return Refusal("cleanup_incomplete", "cleanup")
    node_diagnostic = _node_refusal_diagnostic(error) if stage == "worker_setup" else None
    expected_reason = (
        SOURCE_GATES_NODE_DIAGNOSTIC_REASONS.get(node_diagnostic) if node_diagnostic is not None else None
    )
    if reason == "capture_invalid":
        return Refusal(
            "capture_invalid", stage,
            diagnostic=node_diagnostic if expected_reason == "capture_invalid" else None,
        )
    if reason == "version_mismatch":
        return Refusal("toolchain_version_mismatch", "toolchain_install")
    if stage == "observer":
        return Refusal("network_observation_failed", "observer")
    if stage in ("source_validation", "source_tree"):
        return Refusal("source_validation_failed", stage)
    if stage == "source_diff":
        return Refusal("source_diff_mismatch", "source_diff")
    if stage == "toolchain_install":
        return Refusal("toolchain_install_failed", "toolchain_install")
    return Refusal(
        "runner_unavailable", "worker_setup",
        diagnostic=node_diagnostic if expected_reason == "runner_unavailable" else None,
    )


def _run_source(request, binding, root, runner_temp, environ, controls, diff_sha256, deadline, lifecycle,
                feedback=None):
    reviewed, capability, runtime, rust, rules = controls
    host_toolchain = None
    worker_tools = None
    worker_uid = None
    home_parent = None
    home = None
    run_root = None
    lease_storage = None
    worker_storage = None
    storage_identity = None
    prefix = None
    tools = None
    summary_guard_state = {"guard": None}
    cleanup_state = {"first": None}
    control_inventory_state = None
    revocation_state = None
    retained_token = lifecycle.get("token_reference")
    lease_record = None
    versions = None
    gates = None
    feedback_result = None
    network_observer = None
    network_session = None
    network_captured = False
    summary_guard_passed = False
    worker_cleanup_confirmed = False
    failure = None
    diagnostics = _FailureDiagnostics()
    try:
        original_cwd = Path.cwd()
    except BaseException:
        raise Refusal("internal_error", "internal", diagnostic="cwd_restore") from None
    operation = "host_preflight"
    phase = "source_validation"
    try:
        operation = "host_preflight"
        if os.geteuid() != 0:
            raise Refusal("unsupported_host", "host")
        operation = "context"
        if time.monotonic() >= deadline:
            raise Refusal("runner_unavailable", "context")
        operation = "temp_root_check"
        _check_temp_root()
        try:
            operation = "disable_developer_mode"
            capability._disable_developer_mode()
            operation = "resolve_host_toolchain"
            host_toolchain = capability._resolve_trusted_toolchain()
            operation = "resolve_worker_tools"
            worker_tools = capability._resolve_worker_tools(host_toolchain)
            operation = "source_lease_request"
            control_inventory_state = runtime._prepare_control_inventory(
                root, binding["control_sha"], runner_temp,
            )
            operation = "create_worker_identity"
            worker_uid, home_parent, home = capability._create_probe_identity(root)
        except Refusal as error:
            raise diagnostics.attach(error, operation) from None
        except BaseException as error:
            runtime_refusal = getattr(runtime, "Refusal", None)
            if isinstance(runtime_refusal, type) and isinstance(error, runtime_refusal):
                mapped_refusal = _runtime_refusal(runtime, error)
                runtime_diagnostic = _source_runtime_diagnostic(runtime, error)
                if runtime_diagnostic is not None:
                    mapped_refusal = Refusal(
                        mapped_refusal.reason, mapped_refusal.stage, diagnostic=runtime_diagnostic,
                    )
                raise diagnostics.attach(mapped_refusal, operation) from None
            raise Refusal("runner_unavailable", "worker_setup", diagnostic=operation) from None
        operation = "create_run_directory"
        run_root = _make_directory(RUN_PREFIX, 0o711)
        operation = "create_source_storage"
        lease_storage = _make_directory("macos-core-contract-source-", 0o700)
        operation = "prepare_worker_storage"
        worker_storage, storage_identity = _prepare_worker_storage(run_root, worker_uid, capability)
        operation = "worker_identity_check"
        if worker_uid == os.stat(runner_temp).st_uid:
            raise Refusal("runner_unavailable", "worker_setup")
        operation = "worker_privilege_probe"
        _run_privilege_probe(worker_uid, home, host_toolchain, reviewed)
        try:
            operation = "summary_guard_setup"
            rules._summary_guard(
                worker_uid, home, host_toolchain, reviewed, capability, root, binding, environ,
                summary_guard_state, cleanup_state,
            )
            summary_guard_passed = True
        except BaseException as error:
            diagnostic = _summary_guard_diagnostic(error, rules)
            raise diagnostics.attach(
                Refusal("summary_guard_failed", "summary_guard", diagnostic=diagnostic), operation,
                cleanup_state.get("first"),
            ) from None

        operation = "source_lease_request"
        revocation_state = runtime.RevocationState()
        runtime_request = runtime.parse_request((
            "--source-sha", request["source_sha"], "--base-sha", request["base_sha"],
            "--base-branch", request["base_branch"], "--concern", request["concern"],
        ))
        if runtime_request != request:
            raise Refusal("source_binding_mismatch", "source_lease", diagnostic=operation)
        operation = "source_lease_open"
        lease_context = runtime.validated_source(
            request, binding, root, environ, worker_uid=worker_uid,
            storage_root=lease_storage, revocation_state=revocation_state,
        )
        command_failure = None
        observer_failure = None
        summary_failure = None
        cwd_failure = None
        try:
            with _lease_with_diagnostic_capture(
                lease_context, diagnostics, lambda: operation, cleanup_state,
            ) as lease:
                operation = "source_revocation_check"
                if not runtime.revocation_confirmed(
                    revocation_state, retained_token, environ.get(runtime.SOURCE_REPOSITORY_ID_ENV), request, binding,
                ):
                    raise Refusal("token_revocation_unconfirmed", "source_lease", diagnostic=operation)
                lifecycle["token_revocation"] = "confirmed_before_execution"
                operation = "source_lease_record"
                lease_record = _validate_source_lease(lease.record, request, binding, worker_uid, runtime)
                phase = "source_tree"
                operation = "source_path_validation"
                source = _validate_source_path(lease.source_path, lease_storage)
                operation = "source_tree_probe"
                rules._run_tree_probe(source, worker_uid, home, host_toolchain, capability)
                operation = "resolve_git"
                git_executable = runtime._resolve_trusted_executable("/usr/bin/git")
                phase = "source_diff"
                operation = "git_diff_verification"
                _stream_git_diff_hash(
                    source, request["base_sha"], request["source_sha"], diff_sha256,
                    str(git_executable), deadline,
                )
                if time.monotonic() >= deadline:
                    raise Refusal("runner_unavailable", "toolchain_install", diagnostic="toolchain_install")

                phase = "observer"
                operation = "network_observer_start"
                network_observer, network_session = rules._start_network_observation(
                    binding, request["source_sha"], cleanup_state,
                )
                phase = "toolchain_install"
                operation = "toolchain_install"
                prefix, tools = rust._install_pinned_toolchain(run_root, capability, deadline)
                operation = "toolchain_tree_check"
                rust._check_installed_tree(prefix, deadline)
                operation = "worker_environment"
                environment = _worker_environment(
                    home, worker_storage, prefix, tools, host_toolchain, worker_tools,
                    reviewed, source,
                )
                operation = "toolchain_version_probe"
                versions = rust._read_toolchain_versions(
                    prefix, tools, worker_uid, environment, host_toolchain["python"], capability, deadline,
                )
                operation = "smoke_receipt"
                if versions != _validate_smoke_receipt(runner_temp, binding, rust):
                    raise Refusal("toolchain_version_mismatch", "toolchain_install", diagnostic="toolchain_version_match")
                operation = "toolchain_version_match"
                toolchain_paths = rust.ToolchainPaths(
                    root=run_root, prefix=prefix,
                    rustc=tools["rustc"], cargo=tools["cargo"], rustfmt=tools["rustfmt"],
                    cargo_fmt=tools["cargo_fmt"], cargo_clippy=tools["cargo_clippy"],
                    clippy_driver=tools["clippy_driver"], host=rust.TARGET,
                    rustc_version=versions["rustc"], cargo_version=versions["cargo"],
                    rustfmt_version=versions["rustfmt"], clippy_version=versions["clippy"],
                    component_hashes=tuple((component.name, component.sha256) for component in rust.COMPONENTS),
                )
                operation = "worker_environment"
                environment = _worker_environment(
                    home, worker_storage, prefix, toolchain_paths.command_paths(), host_toolchain,
                    worker_tools, reviewed, source,
                )
                phase = "worker_setup"
                operation = "source_gates"
                if feedback is None:
                    gates = _run_inside_source(
                        source,
                        original_cwd,
                        lambda: _run_gates(
                            source, environment, worker_uid, host_toolchain, capability, rust,
                            toolchain_paths.command_paths(), deadline,
                        ),
                    )
                else:
                    producer = _load_control_sibling("macos_feedback_producer")
                    validated_fuzz_workspace = False
                    if feedback["profile"]["kind"] in ("rust_patch", "build_diagnostics"):
                        validated_fuzz_workspace = _validated_fuzz_workspace(
                            source, lease_record, runtime,
                        )
                    if feedback["profile"]["kind"] == "build_diagnostics":
                        outcome = _run_inside_source(
                            source,
                            original_cwd,
                            lambda: _run_gates(
                                source, environment, worker_uid, host_toolchain, capability, rust,
                                toolchain_paths.command_paths(), deadline, capture_failure=True,
                                include_parser=validated_fuzz_workspace,
                            ),
                        )
                        if lease_record["tree"] == LOCKED_FOUNDATION_TREE:
                            adapter = _load_control_sibling("foundation_node_feedback")
                            contract = _load_control_sibling("macos_node_contract")
                            outcome = adapter.extend_diagnostic_outcome(
                                outcome,
                                lambda: adapter.run_node_profile(
                                    "verify", dispatch=feedback["dispatch"], source=source,
                                    worker_storage=worker_storage, worker_uid=worker_uid,
                                    environment=environment, host_toolchain=host_toolchain,
                                    capability=capability, rust=rust, deadline=deadline,
                                    node=feedback["node"], npm_cli=feedback["npm_cli"],
                                    contract=contract, producer=producer, source_runtime=runtime,
                                    tool_cache_root=feedback["tool_cache_root"],
                                    accepted_provenance=feedback.get("accepted_node_provenance"),
                                    validated_tree=lease_record["tree"],
                                ),
                                contract,
                            )
                        feedback_result = {
                            "payload_bytes": producer.build_diagnostic_payload(outcome),
                            "expected_manifest": None, "reviewed_rust_paths": None,
                            "source_result": "gate_failure" if outcome["failed_stage"] else "all_gates_completed",
                        }
                    elif feedback["profile"]["kind"] == "lock":
                        adapter = _load_control_sibling("foundation_node_feedback")
                        node_result = adapter.run_node_profile(
                            "bootstrap", dispatch=feedback["dispatch"], source=source,
                            worker_storage=worker_storage, worker_uid=worker_uid,
                            environment=environment, host_toolchain=host_toolchain,
                            capability=capability, rust=rust, deadline=deadline,
                            node=feedback["node"], npm_cli=feedback["npm_cli"],
                            contract=_load_control_sibling("macos_node_contract"),
                            producer=producer, source_runtime=runtime,
                            tool_cache_root=feedback["tool_cache_root"],
                            validated_tree=lease_record["tree"],
                        )
                        feedback_result = {
                            "payload_bytes": node_result["lock_bytes"],
                            "expected_manifest": producer._expected_manifest(source),
                            "reviewed_rust_paths": None, "source_result": "command_completed",
                        }
                    elif feedback["profile"]["kind"] == "cargo_lock":
                        feedback_result = _run_inside_source(
                            source,
                            original_cwd,
                            lambda: producer.run_cargo_lock_profile(
                                feedback["dispatch"], source, worker_storage, worker_uid, environment,
                                toolchain_paths.command_paths(), host_toolchain, capability, rust,
                                deadline, _load_control_sibling("cargo_lock_bootstrap"), environ,
                            ),
                        )
                    else:
                        feedback_result = _run_inside_source(
                            source,
                            original_cwd,
                            lambda: producer.run_source_profile(
                                feedback["dispatch"], source, worker_storage, worker_uid, environment,
                                toolchain_paths.command_paths(), host_toolchain, capability, rust,
                                reviewed, deadline, feedback["node"], feedback.get("npm_cli"),
                                validated_fuzz_workspace=validated_fuzz_workspace,
                            ),
                        )
                operation = "worker_storage_verify"
                capability._verify_storage_directory(worker_storage, storage_identity, worker_uid)
        except Refusal as error:
            command_failure = diagnostics.attach(error, operation, cleanup_state.get("first"))
        except BaseException as error:
            runtime_refusal = getattr(runtime, "Refusal", None)
            if isinstance(runtime_refusal, type) and isinstance(error, runtime_refusal):
                if getattr(error, "reason", None) == "cleanup_incomplete":
                    operation = "source_lease_cleanup"
                mapped_refusal = _runtime_refusal(runtime, error)
                runtime_diagnostic = _source_runtime_diagnostic(runtime, error)
                if runtime_diagnostic is not None:
                    mapped_refusal = Refusal(
                        mapped_refusal.reason, mapped_refusal.stage, diagnostic=runtime_diagnostic,
                    )
                command_failure = diagnostics.attach(
                    mapped_refusal, operation, cleanup_state.get("first"),
                )
            elif phase in ("source_validation", "source_tree"):
                diagnostic = (
                    _source_lease_open_exception_diagnostic(error)
                    if phase == "source_validation" and operation == "source_lease_open"
                    else operation
                )
                command_failure = Refusal("source_validation_failed", phase, diagnostic=diagnostic)
            else:
                command_failure = diagnostics.attach(_toolchain_refusal(error, phase), operation,
                                                    cleanup_state.get("first"))
        finally:
            operation = "cwd_restore"
            try:
                current_cwd = Path.cwd()
            except BaseException:
                current_cwd = None
            if current_cwd != original_cwd:
                try:
                    os.chdir(original_cwd)
                except BaseException:
                    cwd_failure = diagnostics.attach(
                        Refusal("cleanup_incomplete", "cleanup"), operation, cleanup_state.get("first"),
                    )
            if network_session is not None and not network_captured:
                operation = "network_observer_finish"
                try:
                    record = rules._finish_network_observation(
                        network_observer, network_session, binding, request["source_sha"], cleanup_state,
                    )
                    if record.get("status") != "observed":
                        raise ValueError
                    network_captured = True
                except BaseException as error:
                    refusal = (Refusal("cleanup_incomplete", "cleanup")
                               if getattr(error, "reason", None) == "cleanup_incomplete"
                               else Refusal("network_observation_failed", "observer"))
                    observer_failure = diagnostics.attach(refusal, operation, cleanup_state.get("first"))
            if summary_guard_state["guard"] is not None:
                operation = "summary_guard_probe"
                try:
                    rules._probe_summary_after_commands(
                        summary_guard_state["guard"], worker_uid, home, host_toolchain,
                        reviewed, capability, binding, cleanup_state,
                    )
                except BaseException as error:
                    refusal = (Refusal("cleanup_incomplete", "cleanup")
                               if getattr(error, "reason", None) == "cleanup_incomplete"
                               else Refusal("summary_guard_failed", "summary_guard"))
                    summary_failure = diagnostics.attach(refusal, operation, cleanup_state.get("first"))
        if cleanup_state.get("first") is not None:
            raise diagnostics.attach(
                Refusal("cleanup_incomplete", "cleanup"), "source_lease_cleanup", cleanup_state.get("first"),
            )
        if any(
            getattr(error, "reason", None) == "cleanup_incomplete"
            for error in (cwd_failure, summary_failure, observer_failure, command_failure)
            if error is not None
        ):
            cleanup_error = next(
                error for error in (cwd_failure, summary_failure, observer_failure, command_failure)
                if error is not None and getattr(error, "reason", None) == "cleanup_incomplete"
            )
            raise diagnostics.attach(
                cleanup_error, getattr(cleanup_error, "diagnostic", "unavailable"), cleanup_state.get("first"),
            )
        if summary_failure is not None:
            raise summary_failure
        if observer_failure is not None:
            raise observer_failure
        if command_failure is not None:
            raise command_failure
    except Refusal as error:
        failure = diagnostics.attach(error, operation, cleanup_state.get("first"))
    except BaseException:
        failure = diagnostics.attach(Refusal("internal_error", "internal"), operation,
                                    cleanup_state.get("first"))
    finally:
        operation = "source_revocation_check"
        if revocation_state is not None and retained_token is not None:
            try:
                if runtime.revocation_confirmed(
                    revocation_state, retained_token, environ.get(runtime.SOURCE_REPOSITORY_ID_ENV), request, binding,
                ):
                    lifecycle["token_revocation"] = "confirmed_before_execution"
            except BaseException:
                pass
        if cleanup_state.get("first") is not None:
            failure = diagnostics.attach(
                Refusal("cleanup_incomplete", "cleanup"), operation, cleanup_state.get("first"),
            )
        operation = "cwd_restore"
        try:
            current_cwd = Path.cwd()
        except BaseException:
            current_cwd = None
        if current_cwd != original_cwd:
            try:
                os.chdir(original_cwd)
            except BaseException:
                failure = diagnostics.attach(
                    Refusal("cleanup_incomplete", "cleanup"), operation, cleanup_state.get("first"),
                )
        cleanup_paths = tuple(path for path in (worker_storage, home_parent, run_root, lease_storage) if path is not None)
        if host_toolchain is not None and (worker_uid is not None or cleanup_paths):
            operation = "worker_cleanup"
            try:
                reviewed._cleanup(cleanup_paths, worker_uid, host_toolchain)
                worker_cleanup_confirmed = True
            except BaseException:
                failure = diagnostics.attach(
                    Refusal("cleanup_incomplete", "cleanup"), operation, cleanup_state.get("first"),
                )
        else:
            cleanup_failed = False
            for path in cleanup_paths:
                operation = "fallback_tree_cleanup"
                try:
                    capability._remove_probe_tree(path)
                except BaseException:
                    cleanup_failed = True
            if worker_uid is not None or home_parent is not None:
                cleanup_failed = True
            if cleanup_failed:
                failure = diagnostics.attach(
                    Refusal("cleanup_incomplete", "cleanup"), operation, cleanup_state.get("first"),
                )
            else:
                worker_cleanup_confirmed = True
        operation = "summary_guard_finish"
        try:
            rules._finish_summary_guard(
                summary_guard_state["guard"], reviewed,
                worker_cleanup_confirmed=worker_cleanup_confirmed,
                cleanup_state=cleanup_state,
            )
        except BaseException:
            failure = diagnostics.attach(
                Refusal("cleanup_incomplete", "cleanup"), operation, cleanup_state.get("first"),
            )
        if control_inventory_state is not None:
            operation = "worker_cleanup"
            if worker_cleanup_confirmed:
                try:
                    runtime._restore_control_inventory(control_inventory_state)
                except BaseException:
                    failure = diagnostics.attach(
                        Refusal("cleanup_incomplete", "cleanup"), operation, cleanup_state.get("first"),
                    )
            else:
                try:
                    runtime._close_control_inventory(control_inventory_state)
                except BaseException:
                    pass
                failure = diagnostics.attach(
                    Refusal("cleanup_incomplete", "cleanup"), operation, cleanup_state.get("first"),
                )
            control_inventory_state = None

    if failure is not None:
        if getattr(failure, "reason", None) == "cleanup_incomplete":
            raise diagnostics.attach(failure, operation, cleanup_state.get("first"))
        if getattr(failure, "reason", None) in REASONS and getattr(failure, "stage", None) in STAGES:
            raise failure
        raise Refusal("internal_error", "internal", diagnostic="unavailable")
    if lifecycle.get("token_revocation") != "confirmed_before_execution":
        raise diagnostics.attach(
            Refusal("cleanup_incomplete", "cleanup"), "source_revocation_check", cleanup_state.get("first"),
        )
    if feedback is None:
        complete_source_run = (
            lease_record is not None and versions is not None and gates is not None
            and tuple(gates) == GATE_NAMES
        )
    else:
        complete_source_run = (
            lease_record is not None and versions is not None and type(feedback_result) is dict
            and type(feedback_result.get("payload_bytes")) is bytes
            and bool(feedback_result["payload_bytes"])
        )
    if (not complete_source_run or not network_captured or not summary_guard_passed
            or not worker_cleanup_confirmed):
        raise diagnostics.attach(
            Refusal("cleanup_incomplete", "cleanup"), "source_lease_cleanup", cleanup_state.get("first"),
        )
    return lease_record, versions, gates if feedback is None else feedback_result, network_captured, summary_guard_passed


def _execute(arguments, environ, token_reference, lifecycle, feedback_kind=None):
    operation = "load_controls"
    try:
        started = time.monotonic()
        deadline = started + MAX_TOTAL_SECONDS
        controls = _load_controls()
        reviewed, capability, boundary, runtime, rust, rules = controls
        operation = "arguments"
        request = _parse_arguments(arguments)
        feedback = None
        feedback_producer = None
        if feedback_kind is not None:
            feedback_producer = _load_control_sibling("macos_feedback_producer")
            try:
                dispatch = feedback_producer.validate_dispatch(feedback_kind, environ)
                full_request = dispatch["request"]
                if any(request[name] != full_request[name]
                       for name in ("source_sha", "base_sha", "base_branch")):
                    raise ValueError
                request["concern"] = dispatch["profile"]["concern"]
                feedback = {"profile": dispatch["profile"], "dispatch": dispatch}
            except feedback_producer.FeedbackRefusal:
                raise Refusal("invalid_input", "arguments") from None
            except Refusal:
                raise
            except BaseException:
                raise Refusal("runner_unavailable", "context") from None
        operation = "context"
        binding, root, runner_temp = _validate_context(environ, reviewed, capability, boundary, rust)
        operation = "review_binding"
        diff_sha256, candidate_ref = _validate_review_gate(request, binding, environ, runtime)
        environ[runtime.SOURCE_CANDIDATE_REF_ENV] = candidate_ref
        operation = "host_preflight"
        if (os.geteuid() != 0 or sys.platform != "darwin"
                or platform.machine() not in ("arm64", "aarch64")):
            raise Refusal("unsupported_host", "host")
        operation = "temp_root_check"
        _check_temp_root()
        operation = "smoke_receipt"
        smoke_versions = _validate_smoke_receipt(runner_temp, binding, rust)
        if feedback is not None:
            operation = "toolchain_node"
            try:
                node, npm_cli = feedback_producer.resolve_node(
                    environ, require_npm=feedback["profile"]["kind"] in ("lock", "build_diagnostics"),
                )
                feedback["node"] = node
                feedback["npm_cli"] = npm_cli
                feedback["tool_cache_root"] = environ.get("RUNNER_TOOL_CACHE", "")
                provenance = environ.get("CORE_CONTRACT_ACCEPTED_NODE_LOCK_JSON", "")
                if provenance:
                    if feedback["profile"]["kind"] != "build_diagnostics":
                        raise ValueError
                    parsed = feedback_producer._strict_json(provenance.encode("utf-8"), 16384)
                    if type(parsed) is not dict:
                        raise ValueError
                    feedback["accepted_node_provenance"] = parsed
            except feedback_producer.FeedbackRefusal:
                raise Refusal("runner_unavailable", "worker_setup") from None
            except BaseException:
                raise Refusal("runner_unavailable", "worker_setup") from None
        operation = "token_input"
        if type(token_reference) is not str or TOKEN_RE.fullmatch(token_reference) is None:
            raise Refusal("token_revocation_unconfirmed", "source_lease")
        environ["SOURCE_READER_TOKEN"] = token_reference
        lifecycle["token_reference"] = token_reference
        try:
            operation = "source_gates"
            lease_record, versions, gates, network_captured, summary_guard_passed = _run_source(
                request, binding, root, runner_temp, environ,
                (reviewed, capability, runtime, rust, rules), diff_sha256, deadline, lifecycle,
                feedback=feedback,
            )
        finally:
            lifecycle.pop("token_reference", None)
        operation = "success_receipt"
        if (time.monotonic() >= deadline or versions != smoke_versions
                or lifecycle.get("token_revocation") != "confirmed_before_execution"):
            raise Refusal("runner_unavailable", "receipt")
        if feedback is not None:
            producer = _load_control_sibling("macos_feedback_producer")
            ciphertext = producer.encrypt_after_cleanup(feedback["dispatch"], gates, feedback["node"])
            receipt = producer.write_output(runner_temp, feedback["dispatch"], ciphertext)
            payload = receipt.encode("ascii", "strict")
            if len(payload) > MAX_RECEIPT_BYTES:
                raise Refusal("capture_invalid", "receipt")
            return payload
        record = _build_success_record(binding, request, lease_record, diff_sha256, versions, gates)
        _validate_success_record(
            record, binding, request, lease_record, diff_sha256, versions, gates,
            network_captured, summary_guard_passed,
        )
        payload = _canonical_json(record)
        if len(payload) > MAX_RECEIPT_BYTES - len("KD-CORE-CONTRACT ".encode("ascii")):
            raise Refusal("capture_invalid", "receipt")
        return payload[:-1]
    except Refusal as error:
        raise _FailureDiagnostics().attach(error, operation) from None
    except BaseException:
        diagnostic = operation if operation in OPERATION_DIAGNOSTICS else "unavailable"
        raise Refusal("internal_error", "internal", diagnostic=diagnostic) from None


def _format_refusal(error):
    reason = error.reason if type(error) is Refusal else "internal_error"
    stage = error.stage if type(error) is Refusal else "internal"
    diagnostic = error.diagnostic if type(error) is Refusal else "unavailable"
    if type(diagnostic) is not str or diagnostic not in DIAGNOSTICS:
        diagnostic = "unavailable"
    record = {
        "diagnostic": diagnostic, "reason": reason, "schema_version": SCHEMA_VERSION,
        "stage": stage, "status": "refused",
    }
    payload = _canonical_json(record)
    prefix_bytes = len("KD-CORE-CONTRACT-REFUSAL ".encode("ascii"))
    if len(payload) + prefix_bytes > MAX_REFUSAL_BYTES:
        return b'{"diagnostic":"unavailable","reason":"internal_error","schema_version":1,"stage":"internal","status":"refused"}'
    return payload[:-1]


def main(arguments=None, environ=None, stdin=None, stdout=None, feedback_kind=None):
    actual_arguments = sys.argv[1:] if arguments is None else arguments
    environment = dict(os.environ) if environ is None else dict(environ)
    input_stream = sys.stdin.buffer if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout
    token_reference = None
    lifecycle = {"token_revocation": "unconfirmed"}
    failure_diagnostics = _FailureDiagnostics()
    failure = None
    pending_tokens = []
    try:
        os.environ.pop("SOURCE_READER_TOKEN", None)
    except BaseException:
        pass
    environment_token = environment.pop("SOURCE_READER_TOKEN", None)
    if type(environment_token) is str and TOKEN_RE.fullmatch(environment_token) is not None:
        pending_tokens.append(environment_token)
    elif environment_token is not None:
        failure = Refusal("invalid_input", "arguments")
    token_requested = (
        type(actual_arguments) in (tuple, list) and len(actual_arguments) >= 2
        and actual_arguments[0] == "run" and actual_arguments[1] == "--token-stdin"
    )
    if token_requested:
        try:
            pending_tokens.append(_read_token_stdin(input_stream))
        except Refusal as error:
            if failure is None:
                failure = error
    pending_tokens = list(dict.fromkeys(pending_tokens))
    if len(pending_tokens) > 1 and failure is None:
        failure = Refusal("invalid_input", "arguments")
    token_reference = pending_tokens[0] if pending_tokens else None
    try:
        if failure is not None:
            raise failure
        result = _execute(actual_arguments, environment, token_reference, lifecycle,
                          feedback_kind=feedback_kind)
    except Refusal as error:
        failure = error
    except BaseException:
        failure = Refusal("internal_error", "internal", diagnostic="unavailable")
    if failure is not None:
        failure = failure_diagnostics.attach(failure, getattr(failure, "diagnostic", "unavailable"))
        for pending_token in pending_tokens:
            if (pending_token == token_reference
                    and lifecycle.get("token_revocation") == "confirmed_before_execution"):
                continue
            try:
                rules = _load_control_sibling("macos_rules_bootstrap")
                if rules._revoke_pending_token(environment, pending_token):
                    lifecycle["token_revocation"] = "confirmed_before_execution"
                else:
                    failure = failure_diagnostics.attach(
                        Refusal("cleanup_incomplete", "cleanup"), "token_revocation",
                    )
            except BaseException:
                failure = failure_diagnostics.attach(
                    Refusal("cleanup_incomplete", "cleanup"), "token_revocation",
                )
                break
    if failure is not None:
        prefix = "KD-FEEDBACK-PRODUCER-REFUSAL " if feedback_kind is not None else "KD-CORE-CONTRACT-REFUSAL "
        output_stream.write(prefix + _format_refusal(failure).decode("ascii") + "\n")
        return 1
    prefix = "KD-FEEDBACK-PRODUCER " if feedback_kind is not None else "KD-CORE-CONTRACT "
    output_stream.write(prefix + result.decode("ascii") + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
