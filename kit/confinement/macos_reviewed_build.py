import errno
import importlib.util
import os
import platform
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


_CONTROL_DIRECTORY = Path(__file__).resolve(strict=True).parent


def _load_control_sibling(module_name):
    if type(module_name) is not str or module_name != "macos_capability":
        raise ImportError("control module unavailable")
    path = (_CONTROL_DIRECTORY / (module_name + ".py")).resolve(strict=True)
    if path.parent != _CONTROL_DIRECTORY or not path.is_file():
        raise ImportError("control module unavailable")
    loaded = sys.modules.get(module_name)
    if loaded is not None:
        loaded_path = getattr(loaded, "__file__", None)
        if type(loaded_path) is str:
            try:
                if Path(loaded_path).resolve(strict=True) == path:
                    return loaded
            except OSError:
                pass
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError("control module unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


try:
    capability = _load_control_sibling("macos_capability")
except BaseException:
    capability = None


SCHEMA_VERSION = 1
CONTROL_SHA = re.compile(r"[a-f0-9]{40}\Z")
RUN_ID = re.compile(r"[1-9][0-9]{0,18}\Z")
RUN_ATTEMPT = re.compile(r"[1-9][0-9]{0,18}\Z")
IMAGE_OS = re.compile(r"macos-?[0-9]{1,2}(?:-(?:arm64|x64|intel))?\Z")
IMAGE_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){1,3}\Z")
PRODUCT_VERSION = re.compile(r"[0-9]+\.[0-9]+(?:\.[0-9]+)?\Z")
TOOL_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+){0,3}\Z")
ARCHITECTURES = frozenset(("arm64", "x86_64"))
REASONS = frozenset((
    "invalid_control_identity",
    "context_unavailable",
    "runner_identity_unavailable",
    "toolchain_unavailable",
    "developer_mode_unavailable",
    "probe_identity_unavailable",
    "privilege_check_failed",
    "synthetic_build_failed",
    "capture_invalid",
    "summary_standin_write_allowed",
    "cleanup_incomplete",
    "internal_error",
))
STAGES = frozenset((
    "context", "toolchain", "developer_mode", "identity", "privilege", "storage",
    "compile", "link", "load_test", "capture", "cleanup", "preflight",
    "toolchain_module", "toolchain_resolve", "xcode_version", "clang_version", "sdk_version",
))
SUMMARY_STANDIN = b"synthetic-summary-standin-v1\n"
SUMMARY_MARKER = b"KD-RB:summary-standin=write-denied\n"
PRIVILEGE_MARKER = b"KD-RB:privilege=sudo-denied\n"
COMPILE_MARKER = b"KD-RB:compile=passed\n"
LINK_MARKER = b"KD-RB:link=passed\n"
LOAD_MARKER = b"KD-RB:load-test=passed\n"
MAX_TOOL_OUTPUT = 8192
MAX_VERSION_OUTPUT = 4096
MAX_NATIVE_STEP_SECONDS = 90

SOURCE = "int kd_synthetic_value(void) { return 42; }\n"

PRIVILEGE_SCRIPT = '''\
import os
import subprocess
import sys

try:
    result = subprocess.run(
        ("/usr/bin/sudo", "-n", "/usr/bin/true"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": os.environ["HOME"], "LANG": "C", "LC_ALL": "C"},
        timeout=3,
        close_fds=True,
        check=False,
    )
except BaseException:
    raise SystemExit(51)

expected = (
    b"password is required",
    b"not in the sudoers",
    b"not allowed to execute",
    b"not allowed to run sudo",
)
if (result.returncode != 1 or result.stdout or len(result.stderr) > 1024
        or not any(value in result.stderr.lower() for value in expected)):
    raise SystemExit(52)
os.write(1, b"KD-RB:privilege=sudo-denied\\n")
'''

COMPILE_SCRIPT = '''\
import os
import subprocess
import sys

clang, sdk, source, output = sys.argv[1:]
try:
    result = subprocess.run(
        (clang, "-isysroot", sdk, "-O", "-c", source, "-o", output),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=45,
        close_fds=True,
        check=False,
    )
except BaseException:
    raise SystemExit(61)
if result.returncode != 0:
    raise SystemExit(62)
os.write(1, b"KD-RB:compile=passed\\n")
'''

LINK_SCRIPT = '''\
import os
import subprocess
import sys

clang, linker, sdk, obj, output = sys.argv[1:]
try:
    result = subprocess.run(
        (clang, "-dynamiclib", "-isysroot", sdk, "-O", "-fuse-ld=" + linker, "-o", output, obj),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=45,
        close_fds=True,
        check=False,
    )
except BaseException:
    raise SystemExit(71)
if result.returncode != 0:
    raise SystemExit(72)
os.write(1, b"KD-RB:link=passed\\n")
'''

LOAD_TEST_SCRIPT = '''\
import ctypes
import errno
import os
import sys

library_path, summary_standin, canary = sys.argv[1:]
try:
    canary_bytes = canary.encode("ascii")
except UnicodeEncodeError:
    raise SystemExit(84)
if (not canary_bytes.startswith(b"KD-RB-CANARY-") or len(canary_bytes) != 29
        or any(value not in b"0123456789abcdef" for value in canary_bytes[13:])):
    raise SystemExit(84)

try:
    library = ctypes.CDLL(library_path)
    function = library.kd_synthetic_value
    function.restype = ctypes.c_int
    if function() != 42:
        raise ValueError
except BaseException:
    raise SystemExit(81)

try:
    descriptor = os.open(summary_standin, os.O_WRONLY | os.O_NOFOLLOW)
except OSError as error:
    if error.errno not in (errno.EACCES, errno.EPERM):
        raise SystemExit(82)
else:
    os.close(descriptor)
    raise SystemExit(83)

os.write(1, b"KD-RB:load-test=passed\\n")
os.write(1, b"KD-RB:summary-standin=write-denied\\n")
os.write(1, b"::error file=synthetic.c,line=1::" + canary_bytes + b"\\n")
os.write(2, b"KD-RB:stderr-canary=" + canary_bytes + b"\\n")
'''


class Refusal(Exception):
    def __init__(self, reason, stage):
        self.reason = reason if type(reason) is str and reason in REASONS else "internal_error"
        self.stage = stage if type(stage) is str and stage in STAGES else "preflight"
        super().__init__(self.reason)


def valid_sha(value):
    return type(value) is str and CONTROL_SHA.fullmatch(value) is not None


def _valid_run_value(pattern, value):
    return type(value) is str and pattern.fullmatch(value) is not None


def _binding(control_sha, environ):
    if not valid_sha(control_sha) or environ.get("CI_SHA") != control_sha:
        raise Refusal("invalid_control_identity", "context")
    run_id = environ.get("GITHUB_RUN_ID", "")
    run_attempt = environ.get("GITHUB_RUN_ATTEMPT", "")
    if not _valid_run_value(RUN_ID, run_id) or not _valid_run_value(RUN_ATTEMPT, run_attempt):
        raise Refusal("invalid_control_identity", "context")
    image_os = environ.get("ImageOS", "")
    image_version = environ.get("ImageVersion", "")
    if not _valid_run_value(IMAGE_OS, image_os) or not _valid_run_value(IMAGE_VERSION, image_version):
        raise Refusal("runner_identity_unavailable", "context")
    return {
        "control_sha": control_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "image_os": image_os,
        "image_version": image_version,
    }


def _run_command(argv, *, env, timeout, max_output=MAX_TOOL_OUTPUT, failure_stage="toolchain"):
    stage = failure_stage if type(failure_stage) is str and failure_stage in STAGES else "toolchain"
    try:
        result = subprocess.run(
            [str(part) for part in argv],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=timeout,
            close_fds=True,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        raise Refusal("toolchain_unavailable", stage) from None
    if len(result.stdout) > max_output or len(result.stderr) > max_output:
        raise Refusal("toolchain_unavailable", stage)
    return result


def _single_ascii_line(payload, pattern):
    if type(payload) is not bytes or not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        return None
    try:
        value = payload[:-1].decode("ascii")
    except UnicodeDecodeError:
        return None
    return value if pattern.fullmatch(value) is not None else None


def _is_xcode_developer_directory(path):
    return (
        isinstance(path, Path)
        and path.name == "Developer"
        and path.parent.name == "Contents"
        and path.parent.parent.name.startswith("Xcode")
        and path.parent.parent.name.endswith(".app")
        and path.parent.parent.parent == Path("/Applications")
    )


def _compiler_origin(toolchain):
    developer_directory = Path(toolchain.get("developer_directory", ""))
    if developer_directory.as_posix() == "/Library/Developer/CommandLineTools":
        return "command-line-tools"
    if _is_xcode_developer_directory(developer_directory):
        return "xcode"
    raise Refusal("toolchain_unavailable", "toolchain_resolve")


def _host_identity(binding, toolchain):
    if platform.system() != "Darwin" or platform.machine() not in ARCHITECTURES:
        raise Refusal("runner_identity_unavailable", "toolchain")
    compiler_origin = _compiler_origin(toolchain)
    base_env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": "/var/empty",
        "LANG": "C",
        "LC_ALL": "C",
    }
    compiler_env = {**base_env, "DEVELOPER_DIR": toolchain["developer_directory"]}
    product_result = _run_command(("/usr/bin/sw_vers", "-productVersion"), env=base_env, timeout=5)
    if product_result.returncode != 0 or product_result.stderr:
        raise Refusal("runner_identity_unavailable", "toolchain")
    product_version = _single_ascii_line(product_result.stdout, PRODUCT_VERSION)
    if compiler_origin == "xcode":
        xcode_result = _run_command(
            ("/usr/bin/xcodebuild", "-version"), env=compiler_env, timeout=10,
            max_output=MAX_VERSION_OUTPUT, failure_stage="xcode_version",
        )
        if xcode_result.returncode != 0 or xcode_result.stderr:
            raise Refusal("toolchain_unavailable", "xcode_version")
        try:
            xcode_lines = xcode_result.stdout.decode("ascii", "strict").splitlines()
        except UnicodeDecodeError:
            raise Refusal("toolchain_unavailable", "xcode_version") from None
        if len(xcode_lines) != 2 or not xcode_lines[0].startswith("Xcode ") or not xcode_lines[1].startswith("Build version "):
            raise Refusal("toolchain_unavailable", "xcode_version")
        xcode_version = xcode_lines[0][len("Xcode "):]
        xcode_build = xcode_lines[1][len("Build version "):]
        if not _valid_run_value(TOOL_VERSION, xcode_version) or re.fullmatch(r"[A-Za-z0-9.]+", xcode_build) is None:
            raise Refusal("toolchain_unavailable", "xcode_version")
    else:
        xcode_version = "not-used"
        xcode_build = "not-used"
    clang_result = _run_command(
        (toolchain["clang"], "--version"), env=compiler_env, timeout=10,
        max_output=MAX_VERSION_OUTPUT, failure_stage="clang_version",
    )
    if clang_result.returncode != 0 or clang_result.stderr:
        raise Refusal("toolchain_unavailable", "clang_version")
    try:
        clang_first = clang_result.stdout.decode("ascii", "strict").splitlines()[0]
    except (UnicodeDecodeError, IndexError):
        raise Refusal("toolchain_unavailable", "clang_version") from None
    clang_match = re.match(r"^Apple clang version ([0-9]+(?:\.[0-9]+){0,3})(?:\s|$)", clang_first)
    clang_version = clang_match.group(1) if clang_match is not None else None
    sdk_result = _run_command(
        ("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-version"), env=compiler_env, timeout=10,
        failure_stage="sdk_version",
    )
    if sdk_result.returncode != 0 or sdk_result.stderr:
        raise Refusal("toolchain_unavailable", "sdk_version")
    sdk_version = _single_ascii_line(sdk_result.stdout, TOOL_VERSION)
    if (
        product_version is None or clang_version is None
        or not _valid_run_value(TOOL_VERSION, clang_version) or sdk_version is None
    ):
        if product_version is None:
            raise Refusal("runner_identity_unavailable", "toolchain")
        if clang_version is None or not _valid_run_value(TOOL_VERSION, clang_version):
            raise Refusal("toolchain_unavailable", "clang_version")
        raise Refusal("toolchain_unavailable", "sdk_version")
    return {
        **binding,
        "macos_version": product_version,
        "architecture": platform.machine(),
        "xcode_version": xcode_version,
        "xcode_build": xcode_build,
        "compiler_origin": compiler_origin,
        "clang_version": clang_version,
        "sdk_version": sdk_version,
    }


def _child_environment(home, storage, toolchain):
    return {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(home),
        "TMPDIR": str(storage),
        "DEVELOPER_DIR": toolchain["developer_directory"],
        "LANG": "C",
        "LC_ALL": "C",
    }


def _make_control_scratch():
    path = Path(tempfile.mkdtemp(prefix="macos-reviewed-control-", dir="/tmp"))
    try:
        os.chmod(path, 0o755)
        standin = path / "summary-standin"
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise OSError("no-follow unavailable")
        descriptor = os.open(standin, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
            os.fchown(descriptor, 0, 0)
            if os.write(descriptor, SUMMARY_STANDIN) != len(SUMMARY_STANDIN):
                raise OSError("short write")
        finally:
            os.close(descriptor)
        info = standin.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or standin.read_bytes() != SUMMARY_STANDIN
        ):
            raise OSError("invalid stand-in")
        return path, standin
    except BaseException:
        try:
            capability._remove_probe_tree(path)
        except BaseException:
            raise Refusal("cleanup_incomplete", "cleanup") from None
        raise Refusal("synthetic_build_failed", "storage") from None


def _create_synthetic_source(storage, uid):
    source = storage / "smoke.c"
    descriptor = os.open(source, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, uid, capability.PROBE_PRIMARY_GID)
        if os.write(descriptor, SOURCE.encode("ascii")) != len(SOURCE):
            raise OSError("short write")
    finally:
        os.close(descriptor)
    info = source.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o600:
        raise Refusal("synthetic_build_failed", "storage")
    return source


def _canary(control_sha):
    if not valid_sha(control_sha):
        raise Refusal("invalid_control_identity", "context")
    return ("KD-RB-CANARY-" + control_sha[:16]).encode("ascii")


def _expected_capture(control_sha):
    marker = _canary(control_sha)
    return (
        LOAD_MARKER + SUMMARY_MARKER + b"::error file=synthetic.c,line=1::" + marker + b"\n",
        b"KD-RB:stderr-canary=" + marker + b"\n",
    )


def _check_capture(result, expected_stdout, expected_stderr):
    return (
        type(result) is subprocess.CompletedProcess
        and type(result.returncode) is int
        and result.returncode == 0
        and type(result.stdout) is bytes
        and type(result.stderr) is bytes
        and len(result.stdout) <= capability.MAX_CAPTURE_BYTES
        and len(result.stderr) <= capability.MAX_CAPTURE_BYTES
        and result.stdout == expected_stdout
        and result.stderr == expected_stderr
    )


def _run_probe_step(argv, uid, *, env, python_executable, stage, expected_stdout, expected_stderr=b""):
    try:
        result = capability._run_as_probe_user(
            argv,
            uid,
            env=env,
            timeout=MAX_NATIVE_STEP_SECONDS,
            failure_reason="native_preflight_unavailable",
            python_executable=python_executable,
        )
    except capability.ProbeFailure as error:
        if not error.cleanup_complete:
            raise Refusal("cleanup_incomplete", "cleanup") from None
        reason = "privilege_check_failed" if stage == "privilege" else "synthetic_build_failed"
        raise Refusal(reason, stage) from None
    if not _check_capture(result, expected_stdout, expected_stderr):
        raise Refusal("capture_invalid", "capture")


def _probe_argv(python_executable, script, *arguments):
    return (python_executable, "-I", "-S", "-B", "-c", script, *[str(value) for value in arguments])


def _assert_standin_unchanged(path):
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or path.read_bytes() != SUMMARY_STANDIN
        ):
            raise Refusal("summary_standin_write_allowed", "capture")
    except Refusal:
        raise
    except BaseException:
        raise Refusal("capture_invalid", "capture") from None


def _remove_identity(uid, *, toolchain):
    try:
        presence = capability._probe_uid_processes_present(
            uid,
            include_survivor_classes=True,
            python_executable=toolchain["python"],
        )
        present, _ = capability._presence_result(presence)
        if present:
            raise Refusal("cleanup_incomplete", "cleanup")
        result = capability._run(
            ("/usr/bin/dscl", ".", "-delete", "/Users/" + capability.USERNAME),
            timeout=10,
            timeout_check="probe_identity_cleanup",
        )
        if result.returncode != 0 or result.stderr:
            raise Refusal("cleanup_incomplete", "cleanup")
    except Refusal:
        raise
    except BaseException:
        raise Refusal("cleanup_incomplete", "cleanup") from None


def _cleanup(paths, uid, toolchain):
    if uid is not None:
        try:
            presence = capability._probe_uid_processes_present(
                uid,
                include_survivor_classes=True,
                python_executable=toolchain["python"],
            )
            present, _ = capability._presence_result(presence)
        except BaseException:
            raise Refusal("cleanup_incomplete", "cleanup") from None
        if present:
            raise Refusal("cleanup_incomplete", "cleanup")
    for path in paths:
        if path is not None:
            try:
                capability._remove_probe_tree(path)
            except BaseException:
                raise Refusal("cleanup_incomplete", "cleanup") from None
    if uid is not None:
        _remove_identity(uid, toolchain=toolchain)


def _safe_context(control_sha):
    try:
        environ = os.environ
        binding = _binding(control_sha, environ)
        workspace = environ.get("CI_WORKSPACE", "")
        root = capability._check_context(control_sha, workspace)
    except Refusal:
        raise
    except capability.ProbeFailure as error:
        if error.reason == "control_identity_invalid":
            raise Refusal("invalid_control_identity", "context") from None
        raise Refusal("context_unavailable", "context") from None
    except BaseException:
        raise Refusal("context_unavailable", "context") from None
    return binding, root


def _run_synthetic_smoke(control_sha):
    if capability is None:
        raise Refusal("toolchain_unavailable", "toolchain_module")
    binding, root = _safe_context(control_sha)
    toolchain = None
    identity_uid = None
    home_parent = None
    home = None
    control_scratch = None
    build_storage = None
    failure = None
    record = None
    stage = "toolchain"
    try:
        stage = "toolchain_resolve"
        toolchain = capability._resolve_trusted_toolchain()
        identity = _host_identity(binding, toolchain)
        stage = "developer_mode"
        capability._disable_developer_mode()
        stage = "identity"
        identity_uid, home_parent, home = capability._create_probe_identity(root)
        stage = "storage"
        control_scratch, standin = _make_control_scratch()
        build_storage = Path(tempfile.mkdtemp(prefix="macos-reviewed-build-", dir="/tmp"))
        storage_identity = capability._prepare_storage_directory(build_storage, identity_uid)
        build_storage = Path(storage_identity[0])
        child_env = _child_environment(home, build_storage, toolchain)
        stage = "privilege"
        _run_probe_step(
            _probe_argv(toolchain["python"], PRIVILEGE_SCRIPT),
            identity_uid,
            env=child_env,
            python_executable=toolchain["python"],
            stage=stage,
            expected_stdout=PRIVILEGE_MARKER,
        )
        stage = "storage"
        source = _create_synthetic_source(build_storage, identity_uid)
        object_path = build_storage / "smoke.o"
        library_path = build_storage / "smoke.dylib"
        stage = "compile"
        _run_probe_step(
            _probe_argv(toolchain["python"], COMPILE_SCRIPT, toolchain["clang"], toolchain["sdk"], source, object_path),
            identity_uid,
            env=child_env,
            python_executable=toolchain["python"],
            stage=stage,
            expected_stdout=COMPILE_MARKER,
        )
        stage = "link"
        _run_probe_step(
            _probe_argv(
                toolchain["python"], LINK_SCRIPT, toolchain["clang"], toolchain["linker"],
                toolchain["sdk"], object_path, library_path,
            ),
            identity_uid,
            env=child_env,
            python_executable=toolchain["python"],
            stage=stage,
            expected_stdout=LINK_MARKER,
        )
        stage = "load_test"
        expected_stdout, expected_stderr = _expected_capture(control_sha)
        _run_probe_step(
            _probe_argv(
                toolchain["python"], LOAD_TEST_SCRIPT, library_path, standin,
                _canary(control_sha).decode("ascii"),
            ),
            identity_uid,
            env=child_env,
            python_executable=toolchain["python"],
            stage=stage,
            expected_stdout=expected_stdout,
            expected_stderr=expected_stderr,
        )
        _assert_standin_unchanged(standin)
        capability._verify_storage_directory(build_storage, storage_identity, identity_uid)
        record = {
            **identity,
            "developer_mode": "disabled",
            "privilege": "separate_nonadmin",
            "sudo": "denied",
            "compile": "passed",
            "link": "passed",
            "load_test": "passed",
            "capture": "passed",
            "summary_standin": "write_denied",
            "cleanup": "complete",
            "seatbelt": "not_run",
            "pf": "not_run",
            "source": "none",
        }
    except Refusal as error:
        failure = error
    except capability.ProbeFailure as error:
        if not error.cleanup_complete:
            failure = Refusal("cleanup_incomplete", "cleanup")
        elif stage == "developer_mode" or error.reason == "developer_mode_unavailable":
            failure = Refusal("developer_mode_unavailable", stage)
        elif stage == "identity" or error.reason == "probe_identity_unavailable":
            failure = Refusal("probe_identity_unavailable", stage)
        elif stage == "privilege":
            failure = Refusal("privilege_check_failed", stage)
        else:
            failure = Refusal("toolchain_unavailable", stage)
    except BaseException:
        failure = Refusal("internal_error", stage)
    finally:
        if toolchain is not None:
            try:
                _cleanup((build_storage, control_scratch, home_parent), identity_uid, toolchain)
            except Refusal as error:
                failure = error
            except BaseException:
                failure = Refusal("cleanup_incomplete", "cleanup")
        elif any(path is not None for path in (build_storage, control_scratch, home_parent)):
            failure = Refusal("cleanup_incomplete", "cleanup")
    if failure is not None:
        raise failure
    if record is None:
        raise Refusal("internal_error", "preflight")
    return record


def _format_success(record):
    required = (
        "schema_version", "control_sha", "run_id", "run_attempt", "image_os", "image_version",
        "macos_version", "architecture", "xcode_version", "xcode_build", "compiler_origin",
        "clang_version", "sdk_version",
        "developer_mode", "privilege", "sudo", "compile", "link", "load_test", "capture",
        "summary_standin", "cleanup", "seatbelt", "pf", "source",
    )
    if type(record) is not dict or set(record) != set(required):
        raise Refusal("internal_error", "preflight")
    if type(record["schema_version"]) is not int or record["schema_version"] != SCHEMA_VERSION or not valid_sha(record["control_sha"]):
        raise Refusal("internal_error", "preflight")
    if not _valid_run_value(RUN_ID, record["run_id"]) or not _valid_run_value(RUN_ATTEMPT, record["run_attempt"]):
        raise Refusal("internal_error", "preflight")
    if type(record["compiler_origin"]) is not str or record["compiler_origin"] not in {"command-line-tools", "xcode"}:
        raise Refusal("internal_error", "preflight")
    for key, pattern in (("image_os", IMAGE_OS), ("image_version", IMAGE_VERSION), ("macos_version", PRODUCT_VERSION),
                         ("architecture", re.compile(r"(?:arm64|x86_64)\Z")),
                         ("clang_version", TOOL_VERSION), ("sdk_version", TOOL_VERSION)):
        if not _valid_run_value(pattern, record[key]):
            raise Refusal("internal_error", "preflight")
    if record["compiler_origin"] == "command-line-tools":
        if record["xcode_version"] != "not-used" or record["xcode_build"] != "not-used":
            raise Refusal("internal_error", "preflight")
    elif (
        not _valid_run_value(TOOL_VERSION, record["xcode_version"])
        or not _valid_run_value(re.compile(r"[A-Za-z0-9.]+\Z"), record["xcode_build"])
    ):
        raise Refusal("internal_error", "preflight")
    fixed_values = {
        "developer_mode": "disabled", "privilege": "separate_nonadmin", "sudo": "denied",
        "compile": "passed", "link": "passed", "load_test": "passed", "capture": "passed",
        "summary_standin": "write_denied", "cleanup": "complete", "seatbelt": "not_run", "pf": "not_run",
        "source": "none",
    }
    if any(record[key] != value for key, value in fixed_values.items()):
        raise Refusal("internal_error", "preflight")
    fields = (
        "macos-build=synthetic-smoke-passed",
        "schema=" + str(SCHEMA_VERSION),
        "source=none",
        "control-sha=" + record["control_sha"],
        "run-id=" + record["run_id"],
        "run-attempt=" + record["run_attempt"],
        "image-os=" + record["image_os"],
        "image-version=" + record["image_version"],
        "macos-version=" + record["macos_version"],
        "architecture=" + record["architecture"],
        "xcode=" + record["xcode_version"],
        "xcode-build=" + record["xcode_build"],
        "compiler-origin=" + record["compiler_origin"],
        "clang=" + record["clang_version"],
        "sdk=" + record["sdk_version"],
        "developer-mode=disabled",
        "privilege=separate-nonadmin",
        "sudo=denied",
        "compile=passed",
        "link=passed",
        "load-test=passed",
        "capture=passed",
        "summary-standin=write-denied",
        "cleanup=complete",
        "seatbelt=not-run",
        "pf=not-run",
    )
    return " ".join(fields)


def _safe_binding_fields(control_sha, environ):
    sha = control_sha if valid_sha(control_sha) else "unknown"
    run_id = environ.get("GITHUB_RUN_ID", "")
    run_attempt = environ.get("GITHUB_RUN_ATTEMPT", "")
    if not _valid_run_value(RUN_ID, run_id):
        run_id = "unknown"
    if not _valid_run_value(RUN_ATTEMPT, run_attempt):
        run_attempt = "unknown"
    return sha, run_id, run_attempt


def _format_refusal(error, control_sha, environ):
    if type(error) is not Refusal:
        error = Refusal("internal_error", "preflight")
    reason = error.reason if type(error.reason) is str and error.reason in REASONS else "internal_error"
    stage = error.stage if type(error.stage) is str and error.stage in STAGES else "preflight"
    sha, run_id, run_attempt = _safe_binding_fields(control_sha, environ)
    return (
        "macos-build=refused schema=1 reason=" + reason + " stage=" + stage
        + " control-sha=" + sha + " run-id=" + run_id + " run-attempt=" + run_attempt
    )


def _parse_cli(argv):
    if type(argv) not in (tuple, list) or len(argv) != 2 or argv[0] != "--control-sha" or not valid_sha(argv[1]):
        raise Refusal("invalid_control_identity", "context")
    return argv[1]


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    control_sha = args[1] if type(args) in (tuple, list) and len(args) == 2 else ""
    try:
        control_sha = _parse_cli(args)
        record = _run_synthetic_smoke(control_sha)
        line = _format_success({"schema_version": SCHEMA_VERSION, **record})
    except Refusal as error:
        line = _format_refusal(error, control_sha, os.environ)
        sys.stdout.write(line + "\n")
        return 1
    except BaseException:
        line = _format_refusal(Refusal("internal_error", "preflight"), control_sha, os.environ)
        sys.stdout.write(line + "\n")
        return 1
    sys.stdout.write(line + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
