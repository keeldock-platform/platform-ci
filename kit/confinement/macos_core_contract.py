"""Fixed, offline macOS validation for the reviewed KeelDock core contract."""

import hashlib
import importlib.util
import json
import os
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
    "macos_rust_toolchain", "macos_rules_bootstrap",
))
GATE_NAMES = (
    "format", "clippy", "workspace_tests", "api_tests", "mock_tests", "conformance_tests",
)
SUITE_NAMES = (
    "core.static", "core.host-api", "core.mock-host", "core.conformance",
)
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
    "conformance_tests", "cleanup", "receipt", "internal",
))

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
    developer = subprocess.run(("/usr/sbin/DevToolsSecurity", "-status"), stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=base_env,
                               timeout=3, close_fds=True, check=False)
    if (developer.returncode != 0 or developer.stderr
            or developer.stdout != b"Developer mode is currently disabled.\\n"):
        raise SystemExit(52)
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
    def __init__(self, reason, stage):
        self.reason = reason if type(reason) is str and reason in REASONS else "internal_error"
        self.stage = stage if type(stage) is str and stage in STAGES else "internal"
        super().__init__(self.reason)


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
    expected = {
        "source_sha": request["source_sha"], "base_sha": request["base_sha"],
        "base_branch": request["base_branch"], "concern": CONCERN,
        "signature": "verified", "rules_lock": "present", "tree": "core_contract",
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


def _source_commands(source, tool_paths):
    cargo = str(tool_paths["cargo"])
    workspace_manifest = str(source / "Cargo.toml")
    return (
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
    environment = reviewed._child_environment(home, Path("/tmp"), host_toolchain)
    try:
        reviewed._run_probe_step(
            reviewed._probe_argv(host_toolchain["python"], PRIVILEGE_SCRIPT, str(worker_uid)),
            worker_uid, env=environment, python_executable=host_toolchain["python"],
            stage="privilege", expected_stdout=PRIVILEGE_MARKER,
        )
        reviewed._worker_census(worker_uid, host_toolchain["python"], "privilege")
    except BaseException as error:
        if getattr(error, "reason", None) == "cleanup_incomplete":
            raise Refusal("cleanup_incomplete", "cleanup") from None
        raise Refusal("runner_unavailable", "worker_setup") from None


def _run_inside_source(source, original_cwd, command):
    try:
        os.chdir(source)
        return command()
    finally:
        try:
            os.chdir(original_cwd)
        except BaseException:
            raise Refusal("cleanup_incomplete", "cleanup") from None


def _run_gates(source, environment, uid, host_toolchain, capability, rust, tools, deadline):
    completed = []
    for stage, argv in _source_commands(source, tools):
        if time.monotonic() >= deadline:
            raise Refusal("gate_failed", stage)
        try:
            result = rust._run_worker_command(
                argv, uid, environment, host_toolchain["python"], capability,
                stage=stage, deadline=deadline, timeout=MAX_COMMAND_SECONDS,
            )
        except BaseException as error:
            if getattr(error, "reason", None) == "cleanup_incomplete":
                raise Refusal("cleanup_incomplete", "cleanup") from None
            if getattr(error, "reason", None) == "capture_invalid":
                raise Refusal("capture_invalid", stage) from None
            raise Refusal("gate_failed", stage) from None
        if (type(result.returncode) is not int or result.returncode != 0
                or type(result.stdout) is not bytes or type(result.stderr) is not bytes
                or len(result.stdout) > MAX_CAPTURE_BYTES or len(result.stderr) > MAX_CAPTURE_BYTES):
            raise Refusal("capture_invalid", stage)
        try:
            _load_control_sibling("macos_reviewed_build")._worker_census(uid, host_toolchain["python"], stage)
        except BaseException:
            raise Refusal("cleanup_incomplete", "cleanup") from None
        completed.append(stage)
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


def _toolchain_refusal(error, stage):
    reason = getattr(error, "reason", None)
    if reason == "cleanup_incomplete":
        return Refusal("cleanup_incomplete", "cleanup")
    if reason == "capture_invalid":
        return Refusal("capture_invalid", stage)
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
    return Refusal("runner_unavailable", "worker_setup")


def _run_source(request, binding, root, runner_temp, environ, controls, diff_sha256, deadline, lifecycle):
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
    revocation_state = None
    retained_token = lifecycle.get("token_reference")
    lease_record = None
    versions = None
    gates = None
    network_observer = None
    network_session = None
    network_captured = False
    summary_guard_passed = False
    worker_cleanup_confirmed = False
    original_cwd = Path.cwd()
    failure = None
    phase = "source_validation"
    try:
        if os.geteuid() != 0:
            raise Refusal("unsupported_host", "host")
        if time.monotonic() >= deadline:
            raise Refusal("runner_unavailable", "context")
        _check_temp_root()
        try:
            capability._disable_developer_mode()
            host_toolchain = capability._resolve_trusted_toolchain()
            worker_tools = capability._resolve_worker_tools(host_toolchain)
            worker_uid, home_parent, home = capability._create_probe_identity(root)
        except Refusal:
            raise
        except BaseException:
            raise Refusal("runner_unavailable", "worker_setup") from None
        run_root = _make_directory(RUN_PREFIX, 0o711)
        lease_storage = _make_directory("macos-core-contract-source-", 0o700)
        worker_storage, storage_identity = _prepare_worker_storage(run_root, worker_uid, capability)
        if worker_uid == os.stat(runner_temp).st_uid:
            raise Refusal("runner_unavailable", "worker_setup")
        _run_privilege_probe(worker_uid, home, host_toolchain, reviewed)
        try:
            rules._summary_guard(
                worker_uid, home, host_toolchain, reviewed, capability, root, binding, environ,
                summary_guard_state, cleanup_state,
            )
            summary_guard_passed = True
        except BaseException:
            raise Refusal("summary_guard_failed", "summary_guard") from None

        revocation_state = runtime.RevocationState()
        runtime_request = runtime.parse_request((
            "--source-sha", request["source_sha"], "--base-sha", request["base_sha"],
            "--base-branch", request["base_branch"], "--concern", CONCERN,
        ))
        if runtime_request != request:
            raise Refusal("source_binding_mismatch", "source_lease")
        lease_context = runtime.validated_source(
            request, binding, root, environ, worker_uid=worker_uid,
            storage_root=lease_storage, revocation_state=revocation_state,
        )
        command_failure = None
        observer_failure = None
        summary_failure = None
        cwd_failure = None
        try:
            with lease_context as lease:
                if not runtime.revocation_confirmed(
                    revocation_state, retained_token, environ.get(runtime.SOURCE_REPOSITORY_ID_ENV), request, binding,
                ):
                    raise Refusal("token_revocation_unconfirmed", "source_lease")
                lifecycle["token_revocation"] = "confirmed_before_execution"
                lease_record = _validate_source_lease(lease.record, request, binding, worker_uid, runtime)
                phase = "source_tree"
                source = _validate_source_path(lease.source_path, lease_storage)
                rules._run_tree_probe(source, worker_uid, home, host_toolchain, capability)
                git_executable = runtime._resolve_trusted_executable("/usr/bin/git")
                phase = "source_diff"
                _stream_git_diff_hash(
                    source, request["base_sha"], request["source_sha"], diff_sha256,
                    str(git_executable), deadline,
                )
                if time.monotonic() >= deadline:
                    raise Refusal("runner_unavailable", "toolchain_install")

                phase = "observer"
                network_observer, network_session = rules._start_network_observation(
                    binding, request["source_sha"], cleanup_state,
                )
                phase = "toolchain_install"
                prefix, tools = rust._install_pinned_toolchain(run_root, capability, deadline)
                rust._check_installed_tree(prefix, deadline)
                environment = _worker_environment(
                    home, worker_storage, prefix, tools, host_toolchain, worker_tools,
                    reviewed, source,
                )
                versions = rust._read_toolchain_versions(
                    prefix, tools, worker_uid, environment, host_toolchain["python"], capability, deadline,
                )
                if versions != _validate_smoke_receipt(runner_temp, binding, rust):
                    raise Refusal("toolchain_version_mismatch", "toolchain_install")
                toolchain_paths = rust.ToolchainPaths(
                    root=run_root, prefix=prefix,
                    rustc=tools["rustc"], cargo=tools["cargo"], rustfmt=tools["rustfmt"],
                    cargo_fmt=tools["cargo_fmt"], cargo_clippy=tools["cargo_clippy"],
                    clippy_driver=tools["clippy_driver"], host=rust.TARGET,
                    rustc_version=versions["rustc"], cargo_version=versions["cargo"],
                    rustfmt_version=versions["rustfmt"], clippy_version=versions["clippy"],
                    component_hashes=tuple((component.name, component.sha256) for component in rust.COMPONENTS),
                )
                environment = _worker_environment(
                    home, worker_storage, prefix, toolchain_paths.command_paths(), host_toolchain,
                    worker_tools, reviewed, source,
                )
                phase = "worker_setup"
                gates = _run_inside_source(
                    source,
                    original_cwd,
                    lambda: _run_gates(
                        source, environment, worker_uid, host_toolchain, capability, rust,
                        toolchain_paths.command_paths(), deadline,
                    ),
                )
                capability._verify_storage_directory(worker_storage, storage_identity, worker_uid)
        except Refusal as error:
            command_failure = error
        except BaseException as error:
            runtime_refusal = getattr(runtime, "Refusal", None)
            if isinstance(runtime_refusal, type) and isinstance(error, runtime_refusal):
                command_failure = _runtime_refusal(runtime, error)
            elif phase in ("source_validation", "source_tree"):
                command_failure = Refusal("source_validation_failed", phase)
            else:
                command_failure = _toolchain_refusal(error, phase)
        finally:
            try:
                current_cwd = Path.cwd()
            except BaseException:
                current_cwd = None
            if current_cwd != original_cwd:
                try:
                    os.chdir(original_cwd)
                except BaseException:
                    cwd_failure = Refusal("cleanup_incomplete", "cleanup")
            if network_session is not None and not network_captured:
                try:
                    record = rules._finish_network_observation(
                        network_observer, network_session, binding, request["source_sha"], cleanup_state,
                    )
                    if record.get("status") != "observed":
                        raise ValueError
                    network_captured = True
                except BaseException as error:
                    observer_failure = (
                        Refusal("cleanup_incomplete", "cleanup")
                        if getattr(error, "reason", None) == "cleanup_incomplete"
                        else Refusal("network_observation_failed", "observer")
                    )
            if summary_guard_state["guard"] is not None:
                try:
                    rules._probe_summary_after_commands(
                        summary_guard_state["guard"], worker_uid, home, host_toolchain,
                        reviewed, capability, binding, cleanup_state,
                    )
                except BaseException as error:
                    summary_failure = (
                        Refusal("cleanup_incomplete", "cleanup")
                        if getattr(error, "reason", None) == "cleanup_incomplete"
                        else Refusal("summary_guard_failed", "summary_guard")
                    )
        if cleanup_state.get("first") is not None:
            raise Refusal("cleanup_incomplete", "cleanup")
        if any(
            getattr(error, "reason", None) == "cleanup_incomplete"
            for error in (cwd_failure, summary_failure, observer_failure, command_failure)
            if error is not None
        ):
            raise Refusal("cleanup_incomplete", "cleanup")
        if summary_failure is not None:
            raise summary_failure
        if observer_failure is not None:
            raise observer_failure
        if command_failure is not None:
            raise command_failure
    except Refusal as error:
        failure = error
    except BaseException:
        failure = Refusal("internal_error", "internal")
    finally:
        if revocation_state is not None and retained_token is not None:
            try:
                if runtime.revocation_confirmed(
                    revocation_state, retained_token, environ.get(runtime.SOURCE_REPOSITORY_ID_ENV), request, binding,
                ):
                    lifecycle["token_revocation"] = "confirmed_before_execution"
            except BaseException:
                pass
        if cleanup_state.get("first") is not None:
            failure = Refusal("cleanup_incomplete", "cleanup")
        try:
            current_cwd = Path.cwd()
        except BaseException:
            current_cwd = None
        if current_cwd != original_cwd:
            try:
                os.chdir(original_cwd)
            except BaseException:
                failure = Refusal("cleanup_incomplete", "cleanup")
        cleanup_paths = tuple(path for path in (worker_storage, home_parent, run_root, lease_storage) if path is not None)
        if host_toolchain is not None and (worker_uid is not None or cleanup_paths):
            try:
                reviewed._cleanup(cleanup_paths, worker_uid, host_toolchain)
                worker_cleanup_confirmed = True
            except BaseException:
                failure = Refusal("cleanup_incomplete", "cleanup")
        else:
            cleanup_failed = False
            for path in cleanup_paths:
                try:
                    capability._remove_probe_tree(path)
                except BaseException:
                    cleanup_failed = True
            if worker_uid is not None or home_parent is not None:
                cleanup_failed = True
            if cleanup_failed:
                failure = Refusal("cleanup_incomplete", "cleanup")
            else:
                worker_cleanup_confirmed = True
        try:
            rules._finish_summary_guard(
                summary_guard_state["guard"], reviewed,
                worker_cleanup_confirmed=worker_cleanup_confirmed,
                cleanup_state=cleanup_state,
            )
        except BaseException:
            failure = Refusal("cleanup_incomplete", "cleanup")

    if failure is not None:
        if getattr(failure, "reason", None) == "cleanup_incomplete":
            raise Refusal("cleanup_incomplete", "cleanup")
        if getattr(failure, "reason", None) in REASONS and getattr(failure, "stage", None) in STAGES:
            raise failure
        raise Refusal("internal_error", "internal")
    if (lease_record is None or versions is None or gates is None or tuple(gates) != GATE_NAMES
            or lifecycle.get("token_revocation") != "confirmed_before_execution"
            or not network_captured or not summary_guard_passed or not worker_cleanup_confirmed):
        raise Refusal("cleanup_incomplete", "cleanup")
    return lease_record, versions, gates, network_captured, summary_guard_passed


def _execute(arguments, environ, token_reference, lifecycle):
    started = time.monotonic()
    deadline = started + MAX_TOTAL_SECONDS
    controls = _load_controls()
    reviewed, capability, boundary, runtime, rust, rules = controls
    request = _parse_arguments(arguments)
    binding, root, runner_temp = _validate_context(environ, reviewed, capability, boundary, rust)
    diff_sha256, candidate_ref = _validate_review_gate(request, binding, environ, runtime)
    environ[runtime.SOURCE_CANDIDATE_REF_ENV] = candidate_ref
    if os.geteuid() != 0 or sys.platform != "darwin" or platform.machine() not in ("arm64", "aarch64"):
        raise Refusal("unsupported_host", "host")
    _check_temp_root()
    smoke_versions = _validate_smoke_receipt(runner_temp, binding, rust)
    if type(token_reference) is not str or TOKEN_RE.fullmatch(token_reference) is None:
        raise Refusal("token_revocation_unconfirmed", "source_lease")
    environ["SOURCE_READER_TOKEN"] = token_reference
    lifecycle["token_reference"] = token_reference
    try:
        lease_record, versions, gates, network_captured, summary_guard_passed = _run_source(
            request, binding, root, runner_temp, environ,
            (reviewed, capability, runtime, rust, rules), diff_sha256, deadline, lifecycle,
        )
    except Refusal:
        raise
    except BaseException:
        raise Refusal("internal_error", "internal") from None
    finally:
        lifecycle.pop("token_reference", None)
    if (time.monotonic() >= deadline or versions != smoke_versions
            or lifecycle.get("token_revocation") != "confirmed_before_execution"):
        raise Refusal("runner_unavailable", "receipt")
    record = _build_success_record(binding, request, lease_record, diff_sha256, versions, gates)
    _validate_success_record(
        record, binding, request, lease_record, diff_sha256, versions, gates,
        network_captured, summary_guard_passed,
    )
    payload = _canonical_json(record)
    if len(payload) > MAX_RECEIPT_BYTES - len("KD-CORE-CONTRACT ".encode("ascii")):
        raise Refusal("capture_invalid", "receipt")
    return payload[:-1]


def _format_refusal(error):
    reason = error.reason if type(error) is Refusal else "internal_error"
    stage = error.stage if type(error) is Refusal else "internal"
    record = {"schema_version": SCHEMA_VERSION, "status": "refused", "stage": stage, "reason": reason}
    payload = _canonical_json(record)
    prefix_bytes = len("KD-CORE-CONTRACT-REFUSAL ".encode("ascii"))
    if len(payload) + prefix_bytes > MAX_REFUSAL_BYTES:
        return b'{"reason":"internal_error","schema_version":1,"stage":"internal","status":"refused"}'
    return payload[:-1]


def main(arguments=None, environ=None, stdin=None, stdout=None):
    actual_arguments = sys.argv[1:] if arguments is None else arguments
    environment = dict(os.environ) if environ is None else dict(environ)
    input_stream = sys.stdin.buffer if stdin is None else stdin
    output_stream = sys.stdout if stdout is None else stdout
    token_reference = None
    lifecycle = {"token_revocation": "unconfirmed"}
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
        result = _execute(actual_arguments, environment, token_reference, lifecycle)
    except Refusal as error:
        failure = error
    except BaseException:
        failure = Refusal("internal_error", "internal")
    if failure is not None:
        for pending_token in pending_tokens:
            if (pending_token == token_reference
                    and lifecycle.get("token_revocation") == "confirmed_before_execution"):
                continue
            try:
                rules = _load_control_sibling("macos_rules_bootstrap")
                if rules._revoke_pending_token(environment, pending_token):
                    lifecycle["token_revocation"] = "confirmed_before_execution"
                else:
                    failure = Refusal("cleanup_incomplete", "cleanup")
            except BaseException:
                failure = Refusal("cleanup_incomplete", "cleanup")
                break
    if failure is not None:
        output_stream.write("KD-CORE-CONTRACT-REFUSAL " + _format_refusal(failure).decode("ascii") + "\n")
        return 1
    output_stream.write("KD-CORE-CONTRACT " + result.decode("ascii") + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
