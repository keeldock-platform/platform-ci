import hashlib
import os
from pathlib import Path
import re
import time


RUST_GATE_NAMES = (
    "format", "clippy", "workspace_tests", "api_tests", "mock_tests", "conformance_tests",
)
PARSER_GATE_NAMES = ("parser_format", "parser_clippy", "parser_replay")
RUST_FOUNDATION_GATES = RUST_GATE_NAMES + PARSER_GATE_NAMES
NODE_GATE_NAMES = (
    "node_dependency_prepare", "node_dependency_audit", "typescript_typecheck", "typescript_tests",
)
NODE_BOOTSTRAP_GATES = ("node_dependency_prepare", "node_dependency_audit")
FULL_FOUNDATION_GATES = RUST_FOUNDATION_GATES + NODE_GATE_NAMES
BOOTSTRAP_MANIFESTS = ("package.json", "packages/host-api/package.json")
NODE_REVIEWED_FILES = frozenset((
    ".node-version", "package.json", "tsconfig.base.json",
    "packages/host-api/package.json", "packages/host-api/tsconfig.json",
    "packages/host-api/src/budget.ts", "packages/host-api/src/effects.ts",
    "packages/host-api/src/entitlements.ts", "packages/host-api/src/errors.ts",
    "packages/host-api/src/ids.ts", "packages/host-api/src/index.ts",
    "packages/host-api/src/manifest.ts", "packages/host-api/src/metadata.ts",
    "packages/host-api/src/module.ts", "packages/host-api/src/plugin.ts",
    "packages/host-api/src/result.ts", "packages/host-api/src/streams.ts",
    "packages/host-api/src/version.ts", "packages/host-api/tests/budget-streams.test.ts",
    "packages/host-api/tests/entitlements-errors.test.ts",
    "packages/host-api/tests/ids-version.test.ts",
    "packages/host-api/tests/manifest-metadata.test.ts",
))
PACKAGE_LOCK_PATH = "package-lock.json"
PACKAGE_LOCK_TREE = "core_build_diagnostic_return_with_package_lock"
SOURCE_IDENTITY_KEYS = ("source_sha", "base_sha", "control_sha", "reviewed_diff_sha256")
NODE_SUBSTAGES = frozenset((
    "runtime_version", "npm_version", "lock_generation", "lock_validation", "bulk_audit",
    "npm_ci", "typecheck", "tests",
))
NODE_REASONS = frozenset((
    "invalid_input", "tool_unavailable", "toolchain_mismatch", "accepted_provenance_invalid",
    "lock_missing", "lock_already_present", "manifest_invalid", "limit_exceeded",
    "command_failed", "audit_unavailable", "audit_response_invalid", "vulnerable_dependency",
    "deadline_exceeded", "capture_invalid", "cleanup_incomplete", "contract_refused",
))
SHA40_RE = re.compile(r"[a-f0-9]{40}\Z")
SHA64_RE = re.compile(r"[a-f0-9]{64}\Z")


SURVIVOR_CLASSES = frozenset((
    "python", "ps", "developer_shim", "helper_preferences", "helper_notifications",
    "helper_launch_services", "helper_security", "helper_trust", "helper_containers",
    "apple_system_path", "other", "unknown", "additional",
))
CLEANUP_UNCLASSIFIED_DIAGNOSTIC = "source_gates_cleanup_unclassified"
SURVIVOR_UNKNOWN_DIAGNOSTIC = "source_gates_survivor_unknown"
COMMAND_CLEANUP_CHECK_DIAGNOSTICS = {
    "probe_process_census": "source_gates_census",
    "probe_process_group_cleanup": "source_gates_group_cleanup",
    "probe_process_capture_cleanup": "source_gates_capture_cleanup",
}


def _refuse(producer, reason):
    producer._refuse(reason)


def _survivor_diagnostic(classes):
    """The survivor_unknown value is used only when the census itself reported the unknown class
    (or reported survivors it could not classify). With no usable class information the fixed
    cleanup_unclassified fallback is used instead."""
    if (type(classes) is tuple and classes
            and all(type(item) is str and item in SURVIVOR_CLASSES for item in classes)):
        if len(classes) == 1:
            return "source_gates_survivor_" + classes[0]
        return "source_gates_survivor_multiple"
    return CLEANUP_UNCLASSIFIED_DIAGNOSTIC


def _command_cleanup_diagnostic(error):
    check = getattr(error, "probe_check", None)
    command_check = getattr(error, "command_check", None)
    if type(check) is str:
        if check == "probe_process_timeout":
            if type(command_check) is str and command_check == "timeout":
                return "source_gates_timeout"
            if type(command_check) is str and command_check == "helper_failure":
                return "source_gates_wait_uncertain"
            return CLEANUP_UNCLASSIFIED_DIAGNOSTIC
        if check in COMMAND_CLEANUP_CHECK_DIAGNOSTICS:
            return COMMAND_CLEANUP_CHECK_DIAGNOSTICS[check]
        if check == "probe_process_survivor":
            return _survivor_diagnostic(getattr(error, "survivor_classes", None))
    if type(command_check) is str and command_check == "timeout":
        return "source_gates_timeout"
    return CLEANUP_UNCLASSIFIED_DIAGNOSTIC


def _census_diagnostic(error):
    classes = getattr(error, "survivor_classes", None)
    if type(classes) is tuple:
        return _survivor_diagnostic(classes)
    if type(classes) is str and classes == "unclassified":
        return SURVIVOR_UNKNOWN_DIAGNOSTIC
    return "source_gates_census"


def _diagnostic_or_fallback(classify, error):
    try:
        diagnostic = classify(error)
    except BaseException:
        return CLEANUP_UNCLASSIFIED_DIAGNOSTIC
    if type(diagnostic) is not str:
        return CLEANUP_UNCLASSIFIED_DIAGNOSTIC
    return diagnostic


def _attach_cleanup_diagnostic(error, record):
    diagnostic = record.get("diagnostic")
    if (type(diagnostic) is str and getattr(error, "reason", None) == "cleanup_incomplete"):
        try:
            error.cleanup_diagnostic = diagnostic
        except BaseException:
            pass


def _profile_context(mode, dispatch, producer, source_runtime, validated_tree, accepted_provenance):
    if type(mode) is not str or mode not in ("bootstrap", "verify") or type(dispatch) is not dict:
        raise ValueError
    profile = dispatch.get("profile")
    request = dispatch.get("request")
    context = dispatch.get("context")
    if type(profile) is not dict or type(request) is not dict or type(context) is not dict:
        raise ValueError
    kind = profile.get("kind")
    if kind not in producer.PROFILE_BY_KIND or profile != producer.PROFILE_BY_KIND[kind]:
        raise ValueError
    if (mode == "bootstrap" and kind != "lock"
            or mode == "verify" and kind != "build_diagnostics"):
        raise ValueError
    if request.get("kind") != kind or request.get("concern") != profile.get("concern"):
        raise ValueError
    if any(request.get(name) != context.get(name) for name in SOURCE_IDENTITY_KEYS):
        raise ValueError
    identity = {name: request.get(name) for name in SOURCE_IDENTITY_KEYS}
    if (any(type(identity[name]) is not str for name in SOURCE_IDENTITY_KEYS)
            or SHA40_RE.fullmatch(identity["source_sha"]) is None
            or SHA40_RE.fullmatch(identity["base_sha"]) is None
            or SHA40_RE.fullmatch(identity["control_sha"]) is None
            or SHA64_RE.fullmatch(identity["reviewed_diff_sha256"]) is None):
        raise ValueError
    if mode == "bootstrap":
        tree_map = getattr(source_runtime, "CORE_CONTRACT_TREE_BY_CONCERN", None)
        expected_tree = tree_map.get(profile["concern"]) if type(tree_map) is dict else None
        if (expected_tree != "core_node_lock_return" or validated_tree != expected_tree
                or accepted_provenance is not None):
            raise ValueError
        expiry = request.get("expiry")
        if type(expiry) is not int:
            raise ValueError
        policy_epoch_ms = (expiry - producer.feedback_request.MAX_REQUEST_TTL_SECONDS) * 1000
        if policy_epoch_ms <= 0:
            raise ValueError
    else:
        expected_tree = getattr(source_runtime, "CORE_CONTRACT_PACKAGE_LOCK_TREE", None)
        if (expected_tree != PACKAGE_LOCK_TREE or validated_tree != PACKAGE_LOCK_TREE
                or accepted_provenance is None or type(accepted_provenance) is not dict):
            raise ValueError
        policy_epoch_ms = None
    return profile, request, identity, policy_epoch_ms


def _reviewed_files(source_runtime, mode, producer):
    source_files = getattr(source_runtime, "CORE_CONTRACT_FEEDBACK_FILES", None)
    if type(source_files) is not frozenset:
        _refuse(producer, "manifest_invalid")
    required = set(BOOTSTRAP_MANIFESTS)
    if mode == "verify":
        required.update(NODE_REVIEWED_FILES)
    if not required.issubset(source_files):
        _refuse(producer, "manifest_invalid")
    if mode == "bootstrap":
        return BOOTSTRAP_MANIFESTS
    return tuple(sorted(NODE_REVIEWED_FILES))


def _node_environment(storage, node, contract):
    return {
        "PATH": str(node.parent) + ":/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(storage / "node-home"),
        "TMPDIR": str(storage / "node-tmp"),
        "LANG": "C",
        "LC_ALL": "C",
        "npm_config_cache": str(storage / "node-cache"),
        "npm_config_registry": contract.REGISTRY_URL,
        "npm_config_userconfig": str(storage / contract.USER_CONFIG_NAME),
        "npm_config_globalconfig": str(storage / contract.GLOBAL_CONFIG_NAME),
        "npm_config_ignore_scripts": "true",
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_fetch_retries": "0",
        "npm_config_fetch_timeout": "30000",
        "npm_config_update_notifier": "false",
    }


def _expected_command(mode, argv, stage, substage, contract, node, npm_cli, storage,
                      policy_epoch_ms, accepted_provenance):
    if (type(argv) is not tuple or not argv or any(type(item) is not str or not item
            or "\x00" in item or len(item) > 4096 for item in argv)
            or len(argv) > 32 or sum(len(item) for item in argv) > 16384):
        return False
    if stage == "node_dependency_prepare" and substage == "runtime_version":
        return argv == (str(node), "--version")
    if stage == "node_dependency_prepare" and substage == "npm_version":
        return argv == (str(node), str(npm_cli), "--version")
    if stage == "node_dependency_prepare" and substage == "lock_generation" and mode == "bootstrap":
        if type(request_epoch := policy_epoch_ms) is not int:
            return False
        cutoff_ms = request_epoch - contract.RELEASE_AGE_DAYS * contract.DAY_MS
        environment = _node_environment(storage, node, contract)
        suffix = ("install", "--package-lock-only", "--workspaces=true", "--include-workspace-root")
        return argv == tuple(contract._command_prefix(node, npm_cli, cutoff_ms, environment)) + suffix
    if stage == "node_dependency_audit" and substage == "bulk_audit":
        helper = Path(contract.__file__).resolve().with_name("node_contract_validation.mjs")
        return argv == (str(node), str(helper), "--request", str(storage / "node-contract-request.json"))
    if stage == "node_dependency_audit" and substage == "npm_ci" and mode == "verify":
        if type(accepted_provenance) is not dict:
            return False
        cutoff_ms = accepted_provenance.get("cutoff_epoch_ms")
        if type(cutoff_ms) is not int:
            return False
        environment = _node_environment(storage, node, contract)
        suffix = ("ci", "--workspaces=true", "--include-workspace-root")
        return argv == tuple(contract._command_prefix(node, npm_cli, cutoff_ms, environment)) + suffix
    if stage == "typescript_typecheck" and substage == "typecheck" and mode == "verify":
        return argv == (str(node), str(npm_cli), "run", "typecheck", "--workspaces", "--ignore-scripts")
    if stage == "typescript_tests" and substage == "tests" and mode == "verify":
        return argv == (str(node), str(npm_cli), "run", "test", "--workspaces", "--ignore-scripts")
    return False


def run_node_profile(mode, *, dispatch, source, worker_storage, worker_uid, environment,
                     host_toolchain, capability, rust, deadline, node, npm_cli, contract,
                     producer, source_runtime, tool_cache_root, accepted_provenance=None,
                     validated_tree=None):
    cleanup_record = {"diagnostic": None}
    try:
        profile, request, identity, policy_epoch_ms = _profile_context(
            mode, dispatch, producer, source_runtime, validated_tree, accepted_provenance,
        )
        if (type(worker_uid) is not int or worker_uid <= 0
                or type(environment) is not dict or type(host_toolchain) is not dict
                or type(deadline) not in (int, float) or deadline <= time.monotonic()):
            raise ValueError
        worker_gid = getattr(capability, "PROBE_PRIMARY_GID", None)
        python_executable = host_toolchain.get("python")
        node_path = Path(node)
        npm_path = Path(npm_cli)
        cache_path = Path(tool_cache_root)
        source_path = Path(source)
        root_storage = Path(worker_storage)
        if (type(worker_gid) is not int or worker_gid <= 0
                or type(python_executable) is not str or not Path(python_executable).is_absolute()
                or not node_path.is_absolute() or not npm_path.is_absolute()
                or not cache_path.is_absolute() or not source_path.is_absolute()
                or not root_storage.is_absolute()):
            raise ValueError
        expected_manifest = producer._expected_manifest(source_path)
        if mode == "verify":
            lock_bytes = producer._read_file(
                source_path / PACKAGE_LOCK_PATH, maximum=contract.MAX_LOCK_BYTES,
            )
        else:
            lock_bytes = None
        files = _reviewed_files(source_runtime, mode, producer)
        storage = root_storage / "foundation-node-contract"
        producer._make_worker_directory(storage, worker_uid, worker_gid)
        project = storage / "project"
        producer._copy_reviewed_files(source_path, project, files, worker_uid, worker_gid)
        if lock_bytes is not None:
            producer._write_worker_file(project / PACKAGE_LOCK_PATH, lock_bytes, worker_uid, worker_gid)
            if producer._read_worker_file(project / PACKAGE_LOCK_PATH, worker_uid,
                                          contract.MAX_LOCK_BYTES) != lock_bytes:
                _refuse(producer, "manifest_invalid")
        if (not callable(getattr(rust, "_run_worker_command", None))
                or not callable(getattr(rust, "_load_control_sibling", None))):
            raise ValueError
        reviewed = rust._load_control_sibling("macos_reviewed_build")
        worker_census = getattr(reviewed, "_worker_census", None)
        if not callable(worker_census):
            raise ValueError
        expected_environment = _node_environment(storage, node_path, contract)
        expected_deadline = deadline

        def run_worker(argv, *, stage, substage, cwd, env, deadline, timeout, allow_nonzero_capture):
            if (Path(cwd) != project or env != expected_environment or deadline != expected_deadline
                    or allow_nonzero_capture is not True
                    or type(timeout) is not int or timeout < 1
                    or timeout > (10 if substage in ("runtime_version", "npm_version") else
                                  90 if substage == "bulk_audit" else 120)
                    or substage not in NODE_SUBSTAGES
                    or not _expected_command(mode, argv, stage, substage, contract, node_path, npm_path,
                                             storage, policy_epoch_ms, accepted_provenance)):
                _refuse(producer, "capture_invalid")
            original_cwd = Path.cwd()
            result = None
            worker_error = None
            cleanup_failed = False
            try:
                os.chdir(project)
                result = rust._run_worker_command(
                    argv, worker_uid, expected_environment, python_executable, capability,
                    stage=stage, deadline=deadline, timeout=timeout,
                    allow_nonzero_capture=True,
                )
            except BaseException as error:
                worker_error = error
                if getattr(error, "reason", None) == "cleanup_incomplete":
                    cleanup_record["diagnostic"] = _diagnostic_or_fallback(
                        _command_cleanup_diagnostic, error,
                    )
            finally:
                try:
                    worker_census(worker_uid, python_executable, "feedback-node")
                except BaseException as census_error:
                    cleanup_failed = True
                    if cleanup_record["diagnostic"] in (None, CLEANUP_UNCLASSIFIED_DIAGNOSTIC):
                        cleanup_record["diagnostic"] = _diagnostic_or_fallback(
                            _census_diagnostic, census_error,
                        )
                try:
                    os.chdir(original_cwd)
                except BaseException:
                    cleanup_failed = True
                    if cleanup_record["diagnostic"] in (None, CLEANUP_UNCLASSIFIED_DIAGNOSTIC):
                        cleanup_record["diagnostic"] = "source_gates_restore"
            if cleanup_failed:
                _refuse(producer, "cleanup_incomplete")
            if worker_error is not None:
                raise worker_error
            return result

        result = contract.run_node_contract(
            mode,
            project=project,
            worker_storage=storage,
            worker_uid=worker_uid,
            worker_gid=worker_gid,
            node_executable=node_path,
            npm_cli=npm_path,
            tool_cache_root=cache_path,
            expected_manifest=expected_manifest,
            source_identity=identity,
            run_worker=run_worker,
            deadline=deadline,
            policy_epoch_ms=policy_epoch_ms,
            accepted_lock=lock_bytes,
            accepted_provenance=accepted_provenance,
        )
        _validate_result(mode, result, contract, identity, expected_manifest, lock_bytes,
                         policy_epoch_ms, accepted_provenance, producer)
        return result
    except Exception as error:
        _attach_cleanup_diagnostic(error, cleanup_record)
        node_refusal = getattr(contract, "NodeContractRefusal", None)
        if isinstance(node_refusal, type) and isinstance(error, node_refusal):
            raise
        if getattr(error, "reason", None) in ("cleanup_incomplete", "command_failed", "capture_invalid",
                                               "manifest_invalid", "output_unavailable"):
            raise
        _refuse(producer, "manifest_invalid")


def _validate_result(mode, result, contract, identity, expected_manifest, lock_bytes,
                     policy_epoch_ms, accepted_provenance, producer):
    if (type(result) is not dict or type(result.get("schema_version")) is not int
            or result.get("schema_version") != 1 or result.get("mode") != mode):
        _refuse(producer, "capture_invalid")
    expected_stages = NODE_BOOTSTRAP_GATES if mode == "bootstrap" else NODE_GATE_NAMES
    if result.get("status") != "passed" or result.get("stages") != expected_stages:
        _refuse(producer, "capture_invalid")
    audit = result.get("audit_summary")
    if (type(audit) is not dict or set(audit) != {
            "package_count", "remote_package_count", "remote_version_count", "advisory_count",
        } or any(type(value) is not int or value < 0 for value in audit.values())):
        _refuse(producer, "capture_invalid")
    returned_lock = result.get("lock_bytes")
    digest = result.get("lock_sha256")
    if (type(returned_lock) is not bytes or not 0 < len(returned_lock) <= contract.MAX_LOCK_BYTES
            or type(digest) is not str or SHA64_RE.fullmatch(digest) is None
            or hashlib.sha256(returned_lock).hexdigest() != digest):
        _refuse(producer, "capture_invalid")
    if mode == "bootstrap":
        candidate = result.get("provenance_candidate")
        required = {
            "schema_version", "status", "generation_identity", "lock_sha256", "manifest_sha256",
            "node_version", "npm_version", "release_age_days", "policy_epoch_ms", "cutoff_epoch_ms",
            "age_status", "generation_attempts", "audit_endpoint", "audit_status",
        }
        if (set(result) != {
                "schema_version", "mode", "status", "lock_bytes", "lock_sha256",
                "provenance_candidate", "stages", "audit_summary",
            } or type(candidate) is not dict or set(candidate) != required
                or type(candidate.get("schema_version")) is not int or candidate.get("schema_version") != 1
                or candidate.get("status") != "validated_candidate"
                or candidate.get("generation_identity") != identity or candidate.get("lock_sha256") != digest
                or type(candidate.get("policy_epoch_ms")) is not int
                or candidate.get("policy_epoch_ms") != policy_epoch_ms
                or candidate.get("node_version") != contract.NODE_VERSION
                or candidate.get("npm_version") != contract.NPM_VERSION
                or type(candidate.get("release_age_days")) is not int
                or candidate.get("release_age_days") != contract.RELEASE_AGE_DAYS
                or type(candidate.get("cutoff_epoch_ms")) is not int
                or candidate.get("cutoff_epoch_ms") != policy_epoch_ms - contract.RELEASE_AGE_DAYS * contract.DAY_MS
                or candidate.get("age_status") != "passed"
                or type(candidate.get("generation_attempts")) is not int
                or candidate.get("generation_attempts") != 1
                or candidate.get("audit_endpoint") != contract.AUDIT_ENDPOINT
                or candidate.get("audit_status") != "passed"
                or type(candidate.get("manifest_sha256")) is not str
                or SHA64_RE.fullmatch(candidate["manifest_sha256"]) is None):
            _refuse(producer, "capture_invalid")
        manifest_digest = hashlib.sha256(contract._validate_expectation(expected_manifest)).hexdigest()
        if candidate["manifest_sha256"] != manifest_digest:
            _refuse(producer, "capture_invalid")
    else:
        if (returned_lock != lock_bytes or result.get("accepted_provenance") != accepted_provenance
                or set(result) != {
                    "schema_version", "mode", "status", "lock_bytes", "lock_sha256",
                    "accepted_provenance", "audit_summary", "stages",
                }):
            _refuse(producer, "capture_invalid")


def _valid_rust_outcome(outcome):
    required = {
        "completed", "selected_gates", "failed_stage", "returncode", "stdout", "stderr",
        "stdout_truncated", "stderr_truncated",
    }
    if type(outcome) is not dict or set(outcome) != required:
        return False
    if (outcome["selected_gates"] != RUST_FOUNDATION_GATES
            or type(outcome["completed"]) is not tuple
            or outcome["completed"] != RUST_FOUNDATION_GATES[:len(outcome["completed"])]
            or type(outcome["stdout"]) is not bytes or type(outcome["stderr"]) is not bytes
            or len(outcome["stdout"]) > 32_768 or len(outcome["stderr"]) > 32_768
            or type(outcome["stdout_truncated"]) is not bool
            or type(outcome["stderr_truncated"]) is not bool):
        return False
    stage = outcome["failed_stage"]
    if stage is None:
        return (outcome["completed"] == RUST_FOUNDATION_GATES
                and type(outcome["returncode"]) is int and outcome["returncode"] == 0
                and outcome["stdout"] == b"" and outcome["stderr"] == b""
                and outcome["stdout_truncated"] is False and outcome["stderr_truncated"] is False)
    return (type(stage) is str and stage in RUST_FOUNDATION_GATES
            and outcome["completed"] == RUST_FOUNDATION_GATES[:RUST_FOUNDATION_GATES.index(stage)]
            and type(outcome["returncode"]) is int and 1 <= outcome["returncode"] <= 255)


def extend_diagnostic_outcome(rust_outcome, node_callback, contract):
    if not _valid_rust_outcome(rust_outcome) or not callable(node_callback):
        raise ValueError("diagnostic outcome invalid")
    selected = FULL_FOUNDATION_GATES
    failed = rust_outcome["failed_stage"]
    if failed is not None:
        return {
            "selected_gates": selected,
            "completed": rust_outcome["completed"],
            "failed_stage": failed,
            "returncode": rust_outcome["returncode"],
            "stdout": rust_outcome["stdout"],
            "stderr": rust_outcome["stderr"],
            "stdout_truncated": rust_outcome["stdout_truncated"],
            "stderr_truncated": rust_outcome["stderr_truncated"],
        }
    try:
        result = node_callback()
    except contract.NodeContractRefusal as error:
        if error.reason == "cleanup_incomplete":
            raise
        node_stage = error.stage
        completed_node = getattr(error, "completed_stages", None)
        if (type(node_stage) is not str or node_stage not in NODE_GATE_NAMES
                or type(completed_node) is not tuple
                or completed_node != NODE_GATE_NAMES[:NODE_GATE_NAMES.index(node_stage)]):
            raise ValueError("node diagnostic invalid") from None
        raw_stdout = getattr(error, "stdout", b"")
        raw_stderr = getattr(error, "stderr", b"")
        if (type(raw_stdout) is not bytes or type(raw_stderr) is not bytes
                or len(raw_stdout) > 32_768 or len(raw_stderr) > 32_768):
            raise ValueError("node capture invalid") from None
        reason = getattr(error, "reason", "contract_refused")
        if type(reason) is not str or reason not in NODE_REASONS:
            reason = "contract_refused"
        substage = getattr(error, "substage", None)
        if substage is None:
            substage = "none"
        elif type(substage) is not str or substage not in NODE_SUBSTAGES:
            raise ValueError("node substage invalid") from None
        metadata = ("node_reason=" + reason + " node_substage=" + substage + "\n").encode("ascii")
        stderr = metadata + raw_stderr[:max(0, 32_768 - len(metadata))]
        returncode = getattr(error, "returncode", None)
        if type(returncode) is not int or not 1 <= returncode <= 255:
            returncode = 1
        return {
            "selected_gates": selected,
            "completed": RUST_FOUNDATION_GATES + completed_node,
            "failed_stage": node_stage,
            "returncode": returncode,
            "stdout": raw_stdout,
            "stderr": stderr,
            "stdout_truncated": bool(getattr(error, "stdout_truncated", False)),
            "stderr_truncated": bool(getattr(error, "stderr_truncated", False)
                                      or len(metadata) + len(raw_stderr) > 32_768),
        }
    if (type(result) is not dict or result.get("mode") != "verify"
            or result.get("status") != "passed" or result.get("stages") != NODE_GATE_NAMES):
        raise ValueError("node verification incomplete")
    return {
        "selected_gates": selected,
        "completed": selected,
        "failed_stage": None,
        "returncode": 0,
        "stdout": b"",
        "stderr": b"",
        "stdout_truncated": False,
        "stderr_truncated": False,
    }
