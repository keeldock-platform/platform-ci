import argparse
import ctypes
from contextlib import contextmanager
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time


CONTROL_SHA = re.compile(r"[a-f0-9]{40}\Z")
USERNAME = "ci-sandbox-probe"
PROBE_PRIMARY_GID = 20
APP_IDENTIFIER = "org.example.sandboxcapability"
CHILD_IDENTIFIER = APP_IDENTIFIER + ".CapabilityChild"
MAX_CAPTURE_BYTES = 65536
MAX_PROBE_SECONDS = 45
MAX_RUNNER_ANCESTORS = 16
MAX_PROCESS_PATH_BYTES = 4096
MAX_TOOL_PATH_BYTES = 4096
SANDBOX_EXEC_PATH = "/usr/bin/sandbox-exec"
SEATBELT_PROFILE_NAME = "capability.sb"
SEATBELT_WRITABLE_DEVICES = ("/dev/null", "/dev/dtracehelper")
SEATBELT_MACH_LOOKUP_NAMES = ()
SEATBELT_MACH_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._@-]{0,127}\Z")
MAX_SEATBELT_PATHS = 64
MAX_SURVIVOR_PATH_READBACKS = 16
DARWIN_UID_MODULUS = 1 << 32
DARWIN_UID_MAX = DARWIN_UID_MODULUS - 1
DARWIN_SIGNED_UID_MIN = -(1 << 31)
LSOF_NON_DESCRIPTOR_ENTRIES = frozenset(("cwd", "rtd", "txt", "mem", "ltx"))
PROC_PIDLISTFDS = 1
PROC_PIDFDVNODEPATHINFO = 2
PROC_PIDFDPIPEINFO = 6
PROX_FDTYPE_VNODE = 1
PROX_FDTYPE_PIPE = 6
FREAD = 1
FWRITE = 2
PROBE_IDENTITY_VERIFIED = b"probe-identity=verified\n"
PROBE_IDENTITY_REFUSED = b"probe-identity=refused\n"
SANDBOX_STAGES = (
    "marker_access",
    "positive_read_spawn", "positive_read_overflow", "positive_read_exit",
    "positive_write_spawn", "positive_write_overflow", "positive_write_exit",
    "probe_spawn",
    "probe_stdout_overflow_before_wait", "probe_stderr_overflow_before_wait",
    "probe_stdout_overflow_after_wait", "probe_stderr_overflow_after_wait",
    "probe_stdout_overflow_final", "probe_stderr_overflow_final",
    "probe_exit",
)
SANDBOX_FAILURES = (
    "invalid_input", "identity_invalid", "sandbox_missing", "child_sandbox_missing", "child_failed",
    "storage_unavailable", "outside_write_allowed", "network_allowed", "child_network_allowed",
    "ipc_allowed", "child_ipc_allowed", "profile_rejected",
    "python_error", "exec_failed",
    "signal_kill", "signal_trap", "signal_abort", "signal_segv", "signal_bus", "signal_ill", "signal_term",
    "signal_other", "other_exit",
)
SANDBOX_EXIT_STAGES = ("positive_read_exit", "positive_write_exit", "probe_exit")
SANDBOX_STAGE_SET = frozenset(SANDBOX_STAGES)
SANDBOX_FAILURE_SET = frozenset(SANDBOX_FAILURES)
SANDBOX_EXIT_STAGE_SET = frozenset(SANDBOX_EXIT_STAGES)
PROBE_ROLE_ORDER = (
    "capabilityprobe",
    "capabilitychild",
    "sh",
    "sleep",
    "capability-child",
    "forked-grandchild",
    "python3",
    "clang",
)
PROBE_ROLE_SET = frozenset(PROBE_ROLE_ORDER)
SNAPSHOT_REJECTION_BUCKETS = ("none", "some", "many")
SNAPSHOT_REJECTION_SET = frozenset(SNAPSHOT_REJECTION_BUCKETS)
SNAPSHOT_REJECTIONS_MANY = 10
PROBE_STDIN_DEVICE = "/dev/null"
CLANG_ROLE_EVIDENCE = "spawn-time descriptors of the suspended hold process"


def _closed_missing_roles(roles):
    if not isinstance(roles, (tuple, list, set, frozenset)):
        return ()
    present = {role for role in roles if type(role) is str and role in PROBE_ROLE_SET}
    return tuple(role for role in PROBE_ROLE_ORDER if role in present)


def _closed_rejection_bucket(bucket):
    if type(bucket) is str and bucket in SNAPSHOT_REJECTION_SET:
        return bucket
    return None
SIGNAL_EXIT_FAILURES = {
    9: "signal_kill",
    5: "signal_trap",
    6: "signal_abort",
    11: "signal_segv",
    10: "signal_bus",
    4: "signal_ill",
    15: "signal_term",
}
PROBE_EXIT_FAILURES = {
    20: "invalid_input",
    21: "identity_invalid",
    22: "sandbox_missing",
    23: "child_failed",
    24: "storage_unavailable",
    25: "outside_write_allowed",
    26: "child_sandbox_missing",
    27: "network_allowed",
    28: "child_network_allowed",
    29: "ipc_allowed",
    30: "child_ipc_allowed",
    65: "profile_rejected",
    125: "exec_failed",
}
CONTROL_EXIT_FAILURES = {
    1: "python_error",
    125: "exec_failed",
}
SURVIVOR_CLASS_ORDER = (
    "python",
    "ps",
    "developer_shim",
    "helper_preferences",
    "helper_notifications",
    "helper_launch_services",
    "helper_security",
    "helper_trust",
    "helper_containers",
    "apple_system_path",
    "other",
    "unknown",
    "additional",
)
SURVIVOR_CLASSES = frozenset(SURVIVOR_CLASS_ORDER)
PYTHON_XCODE_LAYOUT = re.compile(
    r"/Applications/[^/]+\.app/Contents/Developer/Library/Frameworks/"
    r"Python3\.framework/Versions/[0-9]+(?:\.[0-9]+)*/bin/python3\.[0-9]+\Z"
)
PYTHON_CLT_LAYOUT = re.compile(
    r"/Library/Developer/CommandLineTools/Library/Frameworks/"
    r"Python3\.framework/Versions/[0-9]+(?:\.[0-9]+)*/bin/python3\.[0-9]+\Z"
)
DEVELOPER_SHIM_PATHS = frozenset(
    (
        "/usr/bin/python3",
        "/usr/bin/clang",
        "/usr/bin/swiftc",
        "/usr/bin/xcrun",
        "/usr/bin/xcodebuild",
    )
)
APPLE_SYSTEM_PATH_ROOTS = tuple(
    PurePosixPath(path)
    for path in ("/System/Library", "/usr/libexec", "/usr/sbin", "/sbin", "/bin", "/usr/bin")
)
PROCESS_TABLE_PATHS = frozenset(("/bin/ps", "/usr/bin/ps"))
KNOWN_APPLE_HELPER_PATHS = {
    "/usr/sbin/cfprefsd": "helper_preferences",
    "/usr/libexec/cfprefsd": "helper_preferences",
    "/usr/sbin/distnoted": "helper_notifications",
    "/usr/libexec/distnoted": "helper_notifications",
    "/usr/libexec/lsd": "helper_launch_services",
    "/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsd": "helper_launch_services",
    "/usr/libexec/secd": "helper_security",
    "/usr/libexec/trustd": "helper_trust",
    "/usr/libexec/containermanagerd": "helper_containers",
    "/System/Library/PrivateFrameworks/ContainerManager.framework/Support/containermanagerd": "helper_containers",
}
PROBE_IDENTITY_BOOTSTRAP = '''\
import ctypes
import os
import subprocess
import sys

try:
    uid = int(sys.argv[1])
    gid = int(sys.argv[2])
    target = sys.argv[3:]
    if (uid <= 0 or not target or not target[0].startswith("/")
            or os.getuid() != uid or os.geteuid() != uid
            or os.getgid() != gid or os.getegid() != gid):
        raise ValueError

    libc = ctypes.CDLL(None, use_errno=True)
    getgroups = libc.getgroups
    getgroups.argtypes = (ctypes.c_int, ctypes.POINTER(ctypes.c_uint32))
    getgroups.restype = ctypes.c_int
    group_count = getgroups(0, None)
    if group_count < 0 or group_count > 16:
        raise ValueError
    group_buffer = (ctypes.c_uint32 * max(1, group_count))()
    readback_count = getgroups(group_count, group_buffer) if group_count else getgroups(0, None)
    if readback_count != group_count or tuple(group_buffer[:readback_count]) != (gid,):
        raise ValueError

    identities = subprocess.run(
        ["/bin/ps", "-p", str(os.getpid()), "-o", "ruid=,uid=,svuid=,rgid=,gid=,svgid="],
        env={"LANG": "C", "LC_ALL": "C"},
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3,
        check=False,
        close_fds=True,
    )
    if (identities.returncode != 0 or identities.stderr
            or len(identities.stdout) > 128 or len(identities.stderr) > 128):
        raise ValueError
    identity_fields = identities.stdout.decode("ascii").split()
    if (len(identity_fields) != 6 or not all(field.isdecimal() for field in identity_fields)
            or tuple(int(field) for field in identity_fields) != (uid, uid, uid, gid, gid, gid)):
        raise ValueError
except BaseException:
    try:
        os.write(2, b"probe-identity=refused\\n")
    finally:
        os._exit(125)

try:
    if os.write(2, b"probe-identity=verified\\n") != len(b"probe-identity=verified\\n"):
        os._exit(125)
    os.execv(target[0], target)
except BaseException:
    os._exit(125)
'''
REASONS = frozenset(
    (
        "control_identity_invalid",
        "native_preflight_unavailable",
        "runner_control_unavailable",
        "developer_mode_unavailable",
        "probe_identity_unavailable",
        "sandbox_signing_unavailable",
        "sandbox_behavior_unavailable",
        "descriptor_readback_unavailable",
        "descriptor_channel_unexpected",
        "probe_timeout",
    )
)
RUNNER_CONTROL_CHECKS = frozenset(
    (
        "temp_reference",
        "workspace_layout",
        "diagnostics_access",
        "diagnostics_layout",
        "diagnostics_worker_uid",
        "diagnostics_worker_bin",
        "diagnostics_root_family",
        "diagnostics_root_outside_home",
        "diagnostics_root_parent_component",
        "diagnostics_root_actions_runner",
        "diagnostics_root_cached_versioned",
        "diagnostics_root_extracted_versioned",
        "diagnostics_root_other",
        "diagnostics_home_owner",
        "diagnostics_component_owner",
        "diagnostics_process_changed",
        "workspace_owner",
        "directory_type_owner",
        "directory_permissions",
        "file_reference",
        "file_type_owner",
        "file_permissions",
        "probe_access",
    )
)
NATIVE_PREFLIGHT_CHECKS = frozenset(
    (
        "context", "developer_mode", "runner_controls", "probe_identity", "capability_probe",
        "probe_identity_inventory", "probe_identity_home",
        "probe_identity_create", "probe_identity_attributes", "probe_identity_permissions",
        "probe_identity_readback", "probe_identity_cleanup", "probe_process_timeout", "probe_process_cleanup",
        "probe_process_group_cleanup", "probe_process_capture_cleanup", "probe_process_census",
        "probe_process_launch", "probe_process_identity",
        "probe_process_toolchain", "probe_process_seatbelt", "probe_process_profile",
        "probe_process_storage",
        "probe_process_survivor", "probe_process_observation",
        "probe_process_survivor_controls", "probe_process_survivor_positive_read",
        "probe_process_survivor_positive_write", "probe_process_survivor_probe_tree",
        "probe_process_survivor_final_census",
        "probe_process_survivor_controls_same_group",
        "probe_process_survivor_controls_other_group",
        "probe_process_survivor_controls_zombie",
        "probe_process_survivor_controls_multiple",
        "probe_process_survivor_controls_unattributed",
    )
)
SURVIVOR_CHECKS = frozenset(
    (
        "probe_process_survivor", "probe_process_survivor_controls",
        "probe_process_survivor_controls_same_group", "probe_process_survivor_controls_other_group",
        "probe_process_survivor_controls_zombie", "probe_process_survivor_controls_multiple",
        "probe_process_survivor_controls_unattributed", "probe_process_survivor_positive_read",
        "probe_process_survivor_positive_write", "probe_process_survivor_probe_tree",
        "probe_process_survivor_final_census",
    )
)
PROBE_IDENTITY_CHECKS = frozenset(
    (
        "probe_identity", "probe_identity_inventory", "probe_identity_home", "probe_identity_create",
        "probe_identity_attributes", "probe_identity_permissions", "probe_identity_readback",
        "probe_identity_census", "probe_identity_cleanup", "probe_process_identity",
    )
)


class ProbeFailure(Exception):
    def __init__(
        self, reason, cleanup_complete=True, check=None, survivor_classes=None,
        sandbox_stage=None, sandbox_failure=None, missing_roles=None, snapshot_rejections=None,
    ):
        super().__init__(reason if reason in REASONS else "native_preflight_unavailable")
        self.reason = reason if reason in REASONS else "native_preflight_unavailable"
        self.cleanup_complete = cleanup_complete
        if self.reason == "runner_control_unavailable" and check in RUNNER_CONTROL_CHECKS:
            self.check = check
        elif self.reason == "native_preflight_unavailable" and check in NATIVE_PREFLIGHT_CHECKS:
            self.check = check
        elif self.reason == "probe_identity_unavailable" and check in PROBE_IDENTITY_CHECKS:
            self.check = check
        else:
            self.check = None
        if isinstance(survivor_classes, (tuple, list, set, frozenset)):
            self.survivor_classes = tuple(
                category for category in SURVIVOR_CLASS_ORDER if category in survivor_classes
            )
        else:
            self.survivor_classes = ()
        if (
            self.reason == "sandbox_behavior_unavailable"
            and type(sandbox_stage) is str
            and sandbox_stage in SANDBOX_STAGE_SET
        ):
            self.sandbox_stage = sandbox_stage
            if (
                sandbox_stage in SANDBOX_EXIT_STAGE_SET
                and type(sandbox_failure) is str
                and sandbox_failure in SANDBOX_FAILURE_SET
            ):
                self.sandbox_failure = sandbox_failure
            else:
                self.sandbox_failure = None
        else:
            self.sandbox_stage = None
            self.sandbox_failure = None
        if self.reason == "descriptor_readback_unavailable":
            self.missing_roles = _closed_missing_roles(missing_roles)
            self.snapshot_rejections = _closed_rejection_bucket(snapshot_rejections)
        else:
            self.missing_roles = ()
            self.snapshot_rejections = None


class _ProcFdInfo(ctypes.Structure):
    _fields_ = (("fd", ctypes.c_int32), ("type", ctypes.c_uint32))


class _ProcFileInfo(ctypes.Structure):
    _fields_ = (
        ("openflags", ctypes.c_uint32),
        ("status", ctypes.c_uint32),
        ("offset", ctypes.c_int64),
        ("type", ctypes.c_int32),
        ("guardflags", ctypes.c_uint32),
    )


class _VInfoStat(ctypes.Structure):
    _fields_ = (
        ("dev", ctypes.c_uint32),
        ("mode", ctypes.c_uint16),
        ("nlink", ctypes.c_uint16),
        ("ino", ctypes.c_uint64),
        ("uid", ctypes.c_uint32),
        ("gid", ctypes.c_uint32),
        ("atime", ctypes.c_int64),
        ("atimensec", ctypes.c_int64),
        ("mtime", ctypes.c_int64),
        ("mtimensec", ctypes.c_int64),
        ("ctime", ctypes.c_int64),
        ("ctimensec", ctypes.c_int64),
        ("birthtime", ctypes.c_int64),
        ("birthtimensec", ctypes.c_int64),
        ("size", ctypes.c_int64),
        ("blocks", ctypes.c_int64),
        ("blksize", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
        ("gen", ctypes.c_uint32),
        ("rdev", ctypes.c_uint32),
        ("qspare", ctypes.c_int64 * 2),
    )


class _PipeInfo(ctypes.Structure):
    _fields_ = (
        ("stat", _VInfoStat),
        ("handle", ctypes.c_uint64),
        ("peerhandle", ctypes.c_uint64),
        ("status", ctypes.c_int32),
        ("reserved", ctypes.c_int32),
    )


class _PipeFdInfo(ctypes.Structure):
    _fields_ = (("pfi", _ProcFileInfo), ("pipeinfo", _PipeInfo))


class _VnodeInfo(ctypes.Structure):
    _fields_ = (
        ("stat", _VInfoStat),
        ("type", ctypes.c_int32),
        ("pad", ctypes.c_int32),
        ("fsid", ctypes.c_int32 * 2),
    )


class _VnodePathInfo(ctypes.Structure):
    _fields_ = (("vnode", _VnodeInfo), ("path", ctypes.c_char * 1024))


class _VnodeFdInfoWithPath(ctypes.Structure):
    _fields_ = (("pfi", _ProcFileInfo), ("pvip", _VnodePathInfo))


def valid_sha(value):
    return type(value) is str and CONTROL_SHA.fullmatch(value) is not None


def safe_output(
    observed, reason="native_preflight_unavailable", check=None, survivor_classes=None,
    sandbox_stage=None, sandbox_failure=None, missing_roles=None, snapshot_rejections=None,
):
    capability = "macos-capability=observed" if observed else "macos-capability=refused"
    if not observed:
        if reason not in REASONS:
            reason = "native_preflight_unavailable"
        capability += " reason=" + reason
        if (reason == "runner_control_unavailable" and check in RUNNER_CONTROL_CHECKS) or (
            reason == "native_preflight_unavailable" and check in NATIVE_PREFLIGHT_CHECKS
        ) or (reason == "probe_identity_unavailable" and check in PROBE_IDENTITY_CHECKS):
            capability += " check=" + check
        if (
            reason == "native_preflight_unavailable"
            and check in SURVIVOR_CHECKS
            and isinstance(survivor_classes, (tuple, list, set, frozenset))
        ):
            categories = tuple(
                category for category in SURVIVOR_CLASS_ORDER if category in survivor_classes
            )
            if categories:
                capability += " survivor_classes=" + ",".join(categories)
        if (
            reason == "sandbox_behavior_unavailable"
            and type(sandbox_stage) is str
            and sandbox_stage in SANDBOX_STAGE_SET
        ):
            capability += " sandbox_stage=" + sandbox_stage
            if (
                sandbox_stage in SANDBOX_EXIT_STAGE_SET
                and type(sandbox_failure) is str
                and sandbox_failure in SANDBOX_FAILURE_SET
            ):
                capability += " sandbox_failure=" + sandbox_failure
        if reason == "descriptor_readback_unavailable":
            roles = _closed_missing_roles(missing_roles)
            if roles:
                capability += " missing_roles=" + ",".join(roles)
            bucket = _closed_rejection_bucket(snapshot_rejections)
            if bucket is not None:
                capability += " snapshot_rejections=" + bucket
    return capability + "\nmacos-confinement=refused reason=incomplete_channel_evidence\n"


@contextmanager
def _preflight_phase(check):
    try:
        yield
    except ProbeFailure as error:
        if error.reason == "native_preflight_unavailable":
            raise ProbeFailure(
                error.reason,
                cleanup_complete=error.cleanup_complete,
                check=error.check or check,
                survivor_classes=error.survivor_classes,
            ) from None
        if error.reason == "probe_identity_unavailable":
            identity_check = error.check if error.check in PROBE_IDENTITY_CHECKS else check
            raise ProbeFailure(
                error.reason,
                cleanup_complete=error.cleanup_complete,
                check=identity_check,
            ) from None
        raise
    except BaseException:
        raise ProbeFailure("native_preflight_unavailable", check=check) from None


def _run(argv, *, cwd=None, env=None, timeout=30, timeout_check=None):
    try:
        return subprocess.run(
            [str(part) for part in argv],
            cwd=str(cwd) if cwd is not None else None,
            env=env,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            close_fds=True,
        )
    except subprocess.TimeoutExpired:
        raise ProbeFailure("native_preflight_unavailable", cleanup_complete=False, check=timeout_check) from None
    except (OSError, subprocess.SubprocessError):
        raise ProbeFailure("native_preflight_unavailable")


def _require_success(result, reason):
    if result.returncode != 0:
        raise ProbeFailure(reason)
    return result


def _check_context(control_sha, workspace):
    if sys.platform != "darwin" or os.geteuid() != 0:
        raise ProbeFailure("native_preflight_unavailable")
    values = {
        "CI_EVENT_NAME": "workflow_dispatch",
        "CI_REF": "refs/heads/main",
        "CI_REPOSITORY": "keeldock-platform/platform-ci",
        "CI_SERVER_URL": "https://github.com",
    }
    if not valid_sha(control_sha) or os.environ.get("CI_SHA") != control_sha:
        raise ProbeFailure("control_identity_invalid")
    if any(os.environ.get(key) != expected for key, expected in values.items()):
        raise ProbeFailure("control_identity_invalid")
    root = Path(__file__).resolve().parents[2]
    if root != Path(workspace).resolve() or Path.cwd().resolve() != root:
        raise ProbeFailure("control_identity_invalid")
    result = _run(["/usr/bin/git", "rev-parse", "--verify", "HEAD"], cwd=root, timeout=5)
    _require_success(result, "control_identity_invalid")
    if result.stdout.decode("ascii", "ignore").strip() != control_sha:
        raise ProbeFailure("control_identity_invalid")
    return root


def _runner_paths(workspace):
    runner_temp = os.environ.get("RUNNER_TEMP")
    if not runner_temp:
        raise ProbeFailure("runner_control_unavailable", check="temp_reference")
    workspace = Path(workspace).resolve()
    if len(workspace.parents) < 3:
        raise ProbeFailure("runner_control_unavailable", check="workspace_layout")
    diagnostics = _runner_diagnostics(workspace)
    work_temp = workspace.parents[1] / "_temp"
    return (Path(runner_temp), work_temp, diagnostics)


def _parent_pid_and_uid(pid):
    try:
        result = _run(["/bin/ps", "-p", str(pid), "-o", "ppid=,uid="], timeout=5)
    except ProbeFailure:
        raise ProbeFailure("runner_control_unavailable", check="diagnostics_access")
    fields = result.stdout.decode("ascii", "ignore").split()
    if result.returncode != 0 or len(result.stdout) > 128 or len(fields) != 2 or not all(field.isdecimal() for field in fields):
        raise ProbeFailure("runner_control_unavailable", check="diagnostics_access")
    return int(fields[0]), int(fields[1])


def _process_executable(pid):
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        library.proc_pidpath.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
        library.proc_pidpath.restype = ctypes.c_int
        buffer = ctypes.create_string_buffer(MAX_PROCESS_PATH_BYTES)
        size = library.proc_pidpath(pid, buffer, len(buffer))
        if size <= 0 or size >= len(buffer):
            raise ProbeFailure("runner_control_unavailable", check="diagnostics_access")
        raw = buffer.raw[:size].split(b"\0", 1)[0].decode("utf-8")
        if not raw or not Path(raw).is_absolute():
            raise ProbeFailure("runner_control_unavailable", check="diagnostics_access")
        return Path(raw)
    except (OSError, AttributeError, UnicodeDecodeError, ValueError):
        raise ProbeFailure("runner_control_unavailable", check="diagnostics_access")


def _runner_diagnostics(workspace):
    try:
        runner_uid = workspace.stat().st_uid
    except OSError:
        raise ProbeFailure("runner_control_unavailable", check="diagnostics_access")
    runner_home = workspace.parents[2]
    pid = os.getppid()
    seen = set()
    for _ in range(MAX_RUNNER_ANCESTORS):
        if pid <= 1 or pid in seen:
            break
        seen.add(pid)
        parent, uid = _parent_pid_and_uid(pid)
        executable = _process_executable(pid)
        if executable.name == "Runner.Worker":
            if uid != runner_uid:
                raise ProbeFailure("runner_control_unavailable", check="diagnostics_worker_uid")
            if executable.parent.name != "bin":
                raise ProbeFailure("runner_control_unavailable", check="diagnostics_worker_bin")
            root = executable.parent.parent
            try:
                relative = root.relative_to(runner_home)
            except ValueError:
                raise ProbeFailure("runner_control_unavailable", check="diagnostics_root_outside_home")
            allowed_root = relative.parts in (("actions-runner", "cached"), ("actions-runner", "extracted")) or (
                len(relative.parts) == 3
                and relative.parts[:2] == ("actions-runner", "cached")
                and re.fullmatch(r"2\.[0-9]+\.[0-9]+", relative.parts[2]) is not None
            ) or (
                len(relative.parts) == 2
                and relative.parts[0] == "runners"
                and re.fullmatch(r"2\.[0-9]+\.[0-9]+", relative.parts[1]) is not None
            )
            if not allowed_root or ".." in executable.parts:
                if ".." in executable.parts:
                    check = "diagnostics_root_parent_component"
                elif relative.parts == ("actions-runner",):
                    check = "diagnostics_root_actions_runner"
                elif (
                    len(relative.parts) == 3
                    and relative.parts[:2] in (("actions-runner", "cached"), ("actions-runner", "extracted"))
                    and re.fullmatch(r"2\.[0-9]+\.[0-9]+", relative.parts[2]) is not None
                ):
                    check = (
                        "diagnostics_root_cached_versioned"
                        if relative.parts[1] == "cached"
                        else "diagnostics_root_extracted_versioned"
                    )
                else:
                    check = "diagnostics_root_other"
                raise ProbeFailure("runner_control_unavailable", check=check)
            path = runner_home
            try:
                home_info = path.lstat()
            except OSError:
                raise ProbeFailure("runner_control_unavailable", check="diagnostics_home_owner")
            if not stat.S_ISDIR(home_info.st_mode) or home_info.st_uid != runner_uid:
                raise ProbeFailure("runner_control_unavailable", check="diagnostics_home_owner")
            for component in relative.parts + ("bin", "Runner.Worker"):
                path = path / component
                try:
                    info = path.lstat()
                except OSError:
                    raise ProbeFailure("runner_control_unavailable", check="diagnostics_component_owner")
                required = stat.S_ISREG if path == executable else stat.S_ISDIR
                if not required(info.st_mode) or info.st_uid != runner_uid:
                    raise ProbeFailure("runner_control_unavailable", check="diagnostics_component_owner")
            if _parent_pid_and_uid(pid) != (parent, uid) or _process_executable(pid) != executable:
                raise ProbeFailure("runner_control_unavailable", check="diagnostics_process_changed")
            return root / "_diag"
        pid = parent
    raise ProbeFailure("runner_control_unavailable", check="diagnostics_access")


def _open_control_nofollow(path, directory):
    path = Path(path)
    if not path.is_absolute() or len(path.parts) < 2:
        raise OSError("control path is not absolute")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    directory_flag = getattr(os, "O_DIRECTORY", None)
    if nofollow is None or directory_flag is None or not hasattr(os, "fchmod"):
        raise OSError("no-follow file controls unavailable")
    flags = os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0)
    current = os.open(path.anchor, flags | directory_flag)
    try:
        for index, component in enumerate(path.parts[1:]):
            last = index == len(path.parts) - 2
            following = os.open(component, flags | (directory_flag if directory or not last else 0), dir_fd=current)
            os.close(current)
            current = following
        return current
    except Exception:
        os.close(current)
        raise


def _protect_runner_controls(workspace):
    try:
        runner_uid = os.stat(workspace).st_uid
    except OSError:
        raise ProbeFailure("runner_control_unavailable", check="workspace_owner")
    if runner_uid == 0:
        raise ProbeFailure("runner_control_unavailable", check="workspace_owner")
    directories = set(_runner_paths(workspace))
    for path in directories:
        try:
            named = path.lstat()
            if not stat.S_ISDIR(named.st_mode) or named.st_uid != runner_uid:
                raise ProbeFailure("runner_control_unavailable", check="directory_type_owner")
        except OSError:
            raise ProbeFailure("runner_control_unavailable", check="directory_permissions")
        try:
            descriptor = _open_control_nofollow(path, True)
        except OSError:
            raise ProbeFailure("runner_control_unavailable", check="directory_permissions")
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISDIR(info.st_mode) or info.st_uid != runner_uid
                    or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
                raise ProbeFailure("runner_control_unavailable", check="directory_type_owner")
            os.fchmod(descriptor, stat.S_IMODE(info.st_mode) & 0o700)
            checked = os.fstat(descriptor)
            named = path.lstat()
            if (checked.st_dev, checked.st_ino) != (named.st_dev, named.st_ino) or stat.S_IMODE(checked.st_mode) & 0o077:
                raise ProbeFailure("runner_control_unavailable", check="directory_permissions")
        except OSError:
            raise ProbeFailure("runner_control_unavailable", check="directory_permissions")
        finally:
            os.close(descriptor)
    control_files = ("GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH", "GITHUB_STEP_SUMMARY")
    for key in control_files:
        value = os.environ.get(key)
        if not value:
            raise ProbeFailure("runner_control_unavailable", check="file_reference")
        path = Path(value)
        try:
            named = path.lstat()
            if not stat.S_ISREG(named.st_mode) or named.st_uid != runner_uid:
                raise ProbeFailure("runner_control_unavailable", check="file_type_owner")
        except OSError:
            raise ProbeFailure("runner_control_unavailable", check="file_permissions")
        try:
            descriptor = _open_control_nofollow(path, False)
        except OSError:
            raise ProbeFailure("runner_control_unavailable", check="file_permissions")
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != runner_uid
                    or (info.st_dev, info.st_ino) != (named.st_dev, named.st_ino)):
                raise ProbeFailure("runner_control_unavailable", check="file_type_owner")
            os.fchmod(descriptor, stat.S_IMODE(info.st_mode) & 0o600)
            checked = os.fstat(descriptor)
            named = path.lstat()
            if (checked.st_dev, checked.st_ino) != (named.st_dev, named.st_ino) or stat.S_IMODE(checked.st_mode) & 0o077:
                raise ProbeFailure("runner_control_unavailable", check="file_permissions")
        except OSError:
            raise ProbeFailure("runner_control_unavailable", check="file_permissions")
        finally:
            os.close(descriptor)
    return runner_uid, tuple(sorted(directories)), tuple(Path(os.environ[key]) for key in control_files)


def _parse_darwin_uid(value):
    if re.fullmatch(r"-?[0-9]+", value) is None:
        return None
    try:
        parsed = int(value, 10)
    except ValueError:
        return None
    if parsed < DARWIN_SIGNED_UID_MIN or parsed > DARWIN_UID_MAX:
        return None
    return parsed, parsed % DARWIN_UID_MODULUS


def _create_probe_identity(workspace):
    if os.geteuid() != 0:
        raise ProbeFailure("probe_identity_unavailable")
    account = "/Users/" + USERNAME
    created = False
    with _preflight_phase("probe_identity_inventory"):
        listed = _require_success(_run(["/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"], timeout=10), "probe_identity_unavailable")
        ids = set()
        raw_ids = []
        records = set()
        try:
            lines = listed.stdout.decode("ascii").splitlines()
        except UnicodeDecodeError:
            raise ProbeFailure("probe_identity_unavailable") from None
        if listed.stderr:
            raise ProbeFailure("probe_identity_unavailable")
        for line in lines:
            fields = line.split()
            if len(fields) != 2 or re.fullmatch(r"[A-Za-z0-9._-]+", fields[0]) is None:
                raise ProbeFailure("probe_identity_unavailable")
            uid_record = _parse_darwin_uid(fields[1])
            if uid_record is None:
                raise ProbeFailure("probe_identity_unavailable")
            raw_uid, normalized_uid = uid_record
            if fields[0] in records:
                raise ProbeFailure("probe_identity_unavailable")
            records.add(fields[0])
            raw_ids.append(raw_uid)
            ids.add(normalized_uid)
        if USERNAME in records:
            raise ProbeFailure("probe_identity_unavailable")
        uid = max(raw_ids or [500]) + 1
        if uid <= 0 or uid >= 60000 or uid in ids:
            raise ProbeFailure("probe_identity_unavailable")
    with _preflight_phase("probe_identity_census"):
        if _probe_uid_processes_present(uid):
            raise ProbeFailure("probe_identity_unavailable", check="probe_identity_census")
    with _preflight_phase("probe_identity_home"):
        home_parent = Path(tempfile.mkdtemp(prefix="sandbox-capability-home-", dir="/tmp"))
    home = home_parent / "home"
    try:
        with _preflight_phase("probe_identity_home"):
            home.mkdir(mode=0o700)
        with _preflight_phase("probe_identity_create"):
            create_result = _run(["/usr/bin/dscl", ".", "-create", account], timeout=10)
            if create_result.returncode != 0 or create_result.stderr:
                raise ProbeFailure(
                    "native_preflight_unavailable", cleanup_complete=False, check="probe_identity_create"
                )
            created = True
        with _preflight_phase("probe_identity_attributes"):
            for key, value in (
                ("UniqueID", str(uid)),
                ("PrimaryGroupID", str(PROBE_PRIMARY_GID)),
                ("NFSHomeDirectory", str(home)),
                ("UserShell", "/usr/bin/false"),
                ("RealName", "Capability Probe"),
                ("IsHidden", "1"),
            ):
                _require_success(_run(["/usr/bin/dscl", ".", "-create", account, key, value], timeout=10), "probe_identity_unavailable")
        with _preflight_phase("probe_identity_permissions"):
            os.chown(home_parent, uid, 20)
            os.chown(home, uid, 20)
            os.chmod(home_parent, 0o700)
            os.chmod(home, 0o700)
        with _preflight_phase("probe_identity_readback"):
            group_result = _require_success(_run(["/usr/bin/id", "-Gn", USERNAME], timeout=5), "probe_identity_unavailable")
            uid_result = _require_success(_run(["/usr/bin/id", "-u", USERNAME], timeout=5), "probe_identity_unavailable")
            try:
                group_text = group_result.stdout.decode("ascii")
                uid_text = uid_result.stdout.decode("ascii")
            except UnicodeDecodeError:
                raise ProbeFailure("probe_identity_unavailable") from None
            if group_result.stderr or uid_result.stderr:
                raise ProbeFailure("probe_identity_unavailable")
            if re.fullmatch(r"[A-Za-z0-9._-]+(?:[ \t]+[A-Za-z0-9._-]+)*\n", group_text) is None:
                raise ProbeFailure("probe_identity_unavailable")
            groups = group_text[:-1].split()
            if ("admin" in groups or "_developer" in groups or uid <= 0
                    or uid_text != str(uid) + "\n" or uid == runner_uid_for_workspace(workspace)):
                raise ProbeFailure("probe_identity_unavailable")
    except BaseException as error:
        if isinstance(error, ProbeFailure) and not error.cleanup_complete:
            raise
        cleanup_failed = False
        if created:
            try:
                if _probe_uid_processes_present(uid):
                    raise ProbeFailure(
                        "native_preflight_unavailable",
                        cleanup_complete=False,
                        check="probe_identity_cleanup",
                    )
            except BaseException:
                raise ProbeFailure(
                    "native_preflight_unavailable", cleanup_complete=False, check="probe_identity_cleanup"
                ) from None
        try:
            _remove_probe_tree(home_parent)
        except ProbeFailure:
            cleanup_failed = True
        if not cleanup_failed and created:
            try:
                delete_result = _run(["/usr/bin/dscl", ".", "-delete", account], timeout=10)
                cleanup_failed = delete_result.returncode != 0 or bool(delete_result.stderr)
            except Exception:
                cleanup_failed = True
        if cleanup_failed:
            raise ProbeFailure(
                "native_preflight_unavailable", cleanup_complete=False, check="probe_identity_cleanup"
            ) from None
        raise
    return uid, home_parent, home


def runner_uid_for_workspace(workspace):
    try:
        return os.stat(workspace).st_uid
    except OSError:
        raise ProbeFailure("runner_control_unavailable")


def _survivor_path_class(path, python_executable):
    if path is None:
        return "unknown"
    try:
        raw_path = path.as_posix() if hasattr(path, "as_posix") else str(path)
        candidate = PurePosixPath(raw_path)
        if not candidate.is_absolute():
            return "unknown"
        value = candidate.as_posix()
    except BaseException:
        return "unknown"
    if value == PurePosixPath(python_executable).as_posix():
        return "python"
    if value in PROCESS_TABLE_PATHS:
        return "ps"
    if value in DEVELOPER_SHIM_PATHS:
        return "developer_shim"
    if value in KNOWN_APPLE_HELPER_PATHS:
        return KNOWN_APPLE_HELPER_PATHS[value]
    if any(candidate == root or root in candidate.parents for root in APPLE_SYSTEM_PATH_ROOTS):
        return "apple_system_path"
    return "other"


def _survivor_process_classes(pids, uid, python_executable, additional):
    categories = set()
    for pid in pids[:MAX_SURVIVOR_PATH_READBACKS]:
        try:
            path = _process_executable(pid)
        except BaseException:
            path = None
        categories.add(_survivor_path_class(path, python_executable))
    if additional:
        categories.add("additional")
    try:
        selected = ",".join(str(pid) for pid in pids[:MAX_SURVIVOR_PATH_READBACKS])
        result = _run(
            ["/bin/ps", "-p", selected, "-o", "pid=,ruid=,uid=,svuid="],
            env={"LANG": "C", "LC_ALL": "C"},
            timeout=5,
            timeout_check="probe_process_census",
        )
        if result.returncode != 0 or result.stderr or len(result.stdout) > MAX_CAPTURE_BYTES:
            raise ValueError
        output = result.stdout.decode("ascii")
        if output and not output.endswith("\n"):
            raise ValueError
        current = {}
        for line in output.splitlines():
            fields = line.split()
            if len(fields) != 4 or not all(field.isdecimal() for field in fields):
                raise ValueError
            pid, *identities = (int(field) for field in fields)
            if pid in current or uid not in identities:
                raise ValueError
            current[pid] = True
        if set(current) != set(pids[:MAX_SURVIVOR_PATH_READBACKS]):
            raise ValueError
    except BaseException:
        categories = {"unknown"}
        if additional:
            categories.add("additional")
    return tuple(category for category in SURVIVOR_CLASS_ORDER if category in categories)


def _probe_uid_process_snapshot(uid, launched_pgid=None, *, include_survivor_classes=False, python_executable=None):
    if uid <= 0 or (launched_pgid is not None and launched_pgid <= 0):
        raise ProbeFailure("native_preflight_unavailable", cleanup_complete=False, check="probe_process_census")
    control_diagnostics = launched_pgid is not None
    fields = "pid=,pgid=,state=,ruid=,uid=,svuid=" if control_diagnostics else "pid=,ruid=,uid=,svuid="
    try:
        result = _run(
            ["/bin/ps", "-A", "-o", fields],
            env={"LANG": "C", "LC_ALL": "C"},
            timeout=5,
            timeout_check="probe_process_census",
        )
    except BaseException:
        raise ProbeFailure(
            "native_preflight_unavailable", cleanup_complete=False, check="probe_process_census"
        ) from None
    if result.returncode != 0 or result.stderr or len(result.stdout) > MAX_CAPTURE_BYTES:
        raise ProbeFailure("native_preflight_unavailable", cleanup_complete=False, check="probe_process_census")
    try:
        output = result.stdout.decode("ascii")
    except UnicodeDecodeError:
        raise ProbeFailure("native_preflight_unavailable", cleanup_complete=False, check="probe_process_census") from None
    if not output.endswith("\n"):
        raise ProbeFailure("native_preflight_unavailable", cleanup_complete=False, check="probe_process_census")
    lines = output.splitlines()
    if not lines:
        raise ProbeFailure("native_preflight_unavailable", cleanup_complete=False, check="probe_process_census")
    seen_pids = set()
    matches = 0
    matched_pgid = None
    matched_state = None
    matched_pids = []
    for line in lines:
        row = line.split()
        if control_diagnostics:
            if len(row) != 6 or not all(field.isdecimal() for field in row[:2] + row[3:]):
                raise ProbeFailure("native_preflight_unavailable", cleanup_complete=False, check="probe_process_census")
            if any(len(field) > 10 for field in row[:2] + row[3:]):
                raise ProbeFailure("native_preflight_unavailable", cleanup_complete=False, check="probe_process_census")
            pid, pgid = (int(field) for field in row[:2])
            state = row[2]
            if (
                not state
                or state[0] not in "IRSTUZ"
                or any(character not in "+<>AELNsSVWX" for character in state[1:])
            ):
                raise ProbeFailure("native_preflight_unavailable", cleanup_complete=False, check="probe_process_census")
            real_uid, effective_uid, saved_uid = (int(field) for field in row[3:])
        else:
            if len(row) != 4 or not all(field.isdecimal() for field in row):
                raise ProbeFailure("native_preflight_unavailable", cleanup_complete=False, check="probe_process_census")
            if any(len(field) > 10 for field in row):
                raise ProbeFailure("native_preflight_unavailable", cleanup_complete=False, check="probe_process_census")
            pid, real_uid, effective_uid, saved_uid = (int(field) for field in row)
            pgid = None
            state = None
        if pid in seen_pids:
            raise ProbeFailure("native_preflight_unavailable", cleanup_complete=False, check="probe_process_census")
        seen_pids.add(pid)
        if uid in (real_uid, effective_uid, saved_uid):
            matches += 1
            if len(matched_pids) < MAX_SURVIVOR_PATH_READBACKS + 1:
                matched_pids.append(pid)
            if matches == 1:
                matched_pgid = pgid
                matched_state = state
    survivor_classes = ()
    if include_survivor_classes and matches > 0:
        survivor_classes = _survivor_process_classes(
            matched_pids,
            uid,
            python_executable,
            additional=matches > MAX_SURVIVOR_PATH_READBACKS,
        )
    if not control_diagnostics:
        result = (matches > 0, None)
        return result + (survivor_classes,) if include_survivor_classes else result
    if matches == 0:
        result = (False, None)
        return result + (survivor_classes,) if include_survivor_classes else result
    if matches > 1:
        result = (True, "probe_process_survivor_controls_multiple")
        return result + (survivor_classes,) if include_survivor_classes else result
    if matched_state[0] == "Z":
        result = (True, "probe_process_survivor_controls_zombie")
        return result + (survivor_classes,) if include_survivor_classes else result
    if matched_pgid <= 0:
        result = (True, "probe_process_survivor_controls_unattributed")
        return result + (survivor_classes,) if include_survivor_classes else result
    if matched_pgid == launched_pgid:
        result = (True, "probe_process_survivor_controls_same_group")
    else:
        result = (True, "probe_process_survivor_controls_other_group")
    return result + (survivor_classes,) if include_survivor_classes else result


def _probe_uid_processes_present(uid, *, include_survivor_classes=False, python_executable=None):
    snapshot = _probe_uid_process_snapshot(
        uid,
        include_survivor_classes=include_survivor_classes,
        python_executable=python_executable,
    )
    if include_survivor_classes:
        return snapshot[0], snapshot[2]
    return snapshot[0]


def _presence_result(value):
    valid = (
        type(value) is tuple
        and len(value) == 2
        and type(value[0]) is bool
        and type(value[1]) is tuple
        and len(value[1]) <= len(SURVIVOR_CLASS_ORDER)
        and all(type(category) is str and category in SURVIVOR_CLASSES for category in value[1])
        and len(set(value[1])) == len(value[1])
        and tuple(category for category in SURVIVOR_CLASS_ORDER if category in value[1]) == value[1]
        and (value[0] or not value[1])
    )
    if not valid:
        raise ProbeFailure(
            "native_preflight_unavailable", cleanup_complete=False, check="probe_process_census"
        )
    return value


def _snapshot_presence_result(value):
    if type(value) is not tuple or len(value) != 3:
        raise ProbeFailure(
            "native_preflight_unavailable", cleanup_complete=False, check="probe_process_census"
        )
    present, check, classes = value
    present, classes = _presence_result((present, classes))
    if (present and (type(check) is not str or check not in SURVIVOR_CHECKS)) or (
        not present and check is not None
    ):
        raise ProbeFailure(
            "native_preflight_unavailable", cleanup_complete=False, check="probe_process_census"
        )
    return present, check, classes


def _remove_probe_tree(path):
    if path is None:
        return
    try:
        shutil.rmtree(path)
    except FileNotFoundError:
        pass
    except BaseException:
        raise ProbeFailure(
            "native_preflight_unavailable", cleanup_complete=False, check="probe_identity_cleanup"
        ) from None
    try:
        os.lstat(path)
    except FileNotFoundError:
        return
    except BaseException:
        raise ProbeFailure(
            "native_preflight_unavailable", cleanup_complete=False, check="probe_identity_cleanup"
        ) from None
    raise ProbeFailure("native_preflight_unavailable", cleanup_complete=False, check="probe_identity_cleanup")


def _trusted_path_metadata(path, *, directory=False):
    try:
        components = list(reversed(path.parents)) + [path]
        metadata = None
        for component in components:
            metadata = component.stat()
            mode = metadata.st_mode
            if (
                metadata.st_uid != 0
                or mode & stat.S_IWOTH
                or (mode & stat.S_IWGRP and metadata.st_gid == PROBE_PRIMARY_GID)
            ):
                raise ValueError
        if directory:
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError
        elif (
            not stat.S_ISREG(metadata.st_mode)
            or not metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)
        ):
            raise ValueError
    except BaseException:
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_toolchain") from None
    return path


def _resolve_trusted_path(raw, *, directory=False, reject_python_shim=False):
    if not isinstance(raw, str) or not raw or "\0" in raw:
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_toolchain")
    try:
        if len(os.fsencode(raw)) > MAX_TOOL_PATH_BYTES:
            raise ValueError
        semantic_path = PurePosixPath(raw)
        supplied = Path(raw)
        if not semantic_path.is_absolute() or (
            reject_python_shim and semantic_path.as_posix() == "/usr/bin/python3"
        ):
            raise ValueError
        link_metadata = supplied.lstat()
        if link_metadata.st_uid != 0:
            raise ValueError
        resolved = supplied.resolve(strict=True)
    except BaseException:
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_toolchain") from None
    return _trusted_path_metadata(resolved, directory=directory)


def _python_developer_directory(path):
    text = path.as_posix()
    semantic_path = PurePosixPath(text)
    if PYTHON_XCODE_LAYOUT.fullmatch(text):
        return Path(PurePosixPath(*semantic_path.parts[:5]).as_posix())
    if PYTHON_CLT_LAYOUT.fullmatch(text):
        return Path("/Library/Developer/CommandLineTools")
    raise ProbeFailure("native_preflight_unavailable", check="probe_process_toolchain")


def _read_tool_path(result):
    if (
        result.returncode != 0
        or result.stderr
        or not result.stdout.endswith(b"\n")
        or result.stdout.count(b"\n") != 1
        or len(result.stdout) > MAX_TOOL_PATH_BYTES
    ):
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_toolchain")
    try:
        value = result.stdout[:-1].decode("ascii")
    except UnicodeDecodeError:
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_toolchain") from None
    if not value or value != value.strip():
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_toolchain")
    return value


def _resolve_toolchain_file(raw, developer_directory, *, kind):
    path = _resolve_trusted_path(raw, directory=kind == "sdk")
    try:
        relative = PurePosixPath(path.as_posix()).relative_to(
            PurePosixPath(developer_directory.as_posix())
        ).parts
    except ValueError:
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_toolchain") from None
    is_xcode = PurePosixPath(developer_directory.as_posix()).name == "Developer"
    if kind == "clang":
        expected = (
            ("Toolchains", "XcodeDefault.xctoolchain", "usr", "bin", "clang")
            if is_xcode
            else ("usr", "bin", "clang")
        )
        valid = relative == expected
    elif kind == "linker":
        expected = (
            ("Toolchains", "XcodeDefault.xctoolchain", "usr", "bin", "ld")
            if is_xcode
            else ("usr", "bin", "ld")
        )
        valid = relative == expected
    elif kind == "sdk":
        sdk_name = relative[-1] if relative else ""
        if is_xcode:
            valid = (
                len(relative) == 5
                and relative[:4] == ("Platforms", "MacOSX.platform", "Developer", "SDKs")
                and re.fullmatch(r"MacOSX[0-9]*(?:\.[0-9]+)*\.sdk", sdk_name) is not None
            )
        else:
            valid = (
                len(relative) == 2
                and relative[0] == "SDKs"
                and re.fullmatch(r"MacOSX[0-9]*(?:\.[0-9]+)*\.sdk", sdk_name) is not None
            )
    else:
        valid = False
    if not valid:
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_toolchain")
    return path


def _resolve_trusted_toolchain():
    if sys.platform != "darwin" or os.geteuid() != 0:
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_toolchain")
    if sys.version_info < (3, 9):
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_toolchain")
    python = _resolve_trusted_path(sys.executable, reject_python_shim=True)
    if not (PYTHON_XCODE_LAYOUT.fullmatch(python.as_posix()) or PYTHON_CLT_LAYOUT.fullmatch(python.as_posix())):
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_toolchain")
    developer_directory = _python_developer_directory(python)
    _trusted_path_metadata(developer_directory, directory=True)
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": "/var/empty",
        "DEVELOPER_DIR": developer_directory.as_posix(),
        "LANG": "C",
        "LC_ALL": "C",
    }
    xcrun = _resolve_trusted_path("/usr/bin/xcrun")
    clang_query = _run(
        [str(xcrun), "--sdk", "macosx", "--find", "clang"],
        env=env,
        timeout=10,
        timeout_check="probe_process_toolchain",
    )
    sdk_query = _run(
        [str(xcrun), "--sdk", "macosx", "--show-sdk-path"],
        env=env,
        timeout=10,
        timeout_check="probe_process_toolchain",
    )
    clang = _resolve_toolchain_file(_read_tool_path(clang_query), developer_directory, kind="clang")
    sdk = _resolve_toolchain_file(_read_tool_path(sdk_query), developer_directory, kind="sdk")
    linker_query = _run(
        [str(clang), "-isysroot", str(sdk), "-print-prog-name=ld"],
        env=env,
        timeout=10,
        timeout_check="probe_process_toolchain",
    )
    linker = _resolve_toolchain_file(_read_tool_path(linker_query), developer_directory, kind="linker")
    return {
        "python": python.as_posix(),
        "clang": clang.as_posix(),
        "sdk": sdk.as_posix(),
        "linker": linker.as_posix(),
        "developer_directory": developer_directory.as_posix(),
    }


def _probe_user_command(argv, uid, python_executable):
    if (
        uid <= 0
        or not argv
        or not str(argv[0]).startswith("/")
        or not isinstance(python_executable, str)
        or not python_executable.startswith("/")
        or len(os.fsencode(python_executable)) > MAX_TOOL_PATH_BYTES
    ):
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_launch")
    if sys.version_info < (3, 9):
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_launch")
    return [
        str(python_executable),
        "-I",
        "-S",
        "-B",
        "-c",
        PROBE_IDENTITY_BOOTSTRAP,
        str(uid),
        str(PROBE_PRIMARY_GID),
        *[str(part) for part in argv],
    ]


def _spawn_probe_user(
    argv, uid, *, env, python_executable, cwd=None, failure_reason, failure_check=None, failure_stage=None,
):
    command = _probe_user_command(argv, uid, python_executable)
    launch_env = env if env is not None else {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": "/tmp",
        "LANG": "C",
    }
    try:
        return subprocess.Popen(
            command,
            cwd=str(cwd) if cwd is not None else None,
            env=launch_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
            user=uid,
            group=PROBE_PRIMARY_GID,
            extra_groups=(),
        )
    except TypeError:
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_launch") from None
    except (OSError, subprocess.SubprocessError):
        raise ProbeFailure(failure_reason, check=failure_check, sandbox_stage=failure_stage) from None


def _classify_exit(returncode, codes):
    if type(returncode) is not int:
        return "other_exit"
    if returncode < 0:
        return SIGNAL_EXIT_FAILURES.get(-returncode, "signal_other")
    if returncode in codes:
        return codes[returncode]
    return "other_exit"


def _strip_probe_identity_record(stderr):
    if stderr.startswith(PROBE_IDENTITY_VERIFIED):
        return stderr[len(PROBE_IDENTITY_VERIFIED):]
    if stderr.startswith(PROBE_IDENTITY_REFUSED):
        raise ProbeFailure("probe_identity_unavailable", check="probe_process_identity")
    raise ProbeFailure("probe_identity_unavailable", check="probe_process_identity")


def _run_as_probe_user(
    argv,
    uid,
    *,
    env=None,
    timeout=10,
    failure_reason="probe_identity_unavailable",
    failure_check=None,
    failure_stage_spawn=None,
    failure_stage_overflow=None,
    failure_stage_exit=None,
    survivor_check="probe_process_survivor",
    control_survivor_diagnostics=False,
    python_executable,
):
    if uid <= 0:
        raise ProbeFailure("probe_identity_unavailable")
    command = [str(part) for part in argv]
    process = _spawn_probe_user(
        command,
        uid,
        env=env,
        python_executable=python_executable,
        failure_reason=failure_reason,
        failure_check=failure_check,
        failure_stage=failure_stage_spawn,
    )
    stdout_capture = _Capture(process.stdout)
    stderr_capture = _Capture(process.stderr)
    captures = (stdout_capture, stderr_capture)
    timed_out = False
    wait_uncertain = False
    try:
        for capture in captures:
            capture.start()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
        except BaseException:
            wait_uncertain = True
    except BaseException:
        wait_uncertain = True
    finally:
        try:
            tree_stopped = _terminate_probe_tree(process)
        except BaseException:
            tree_stopped = False
        captures_joined = True
        for capture in captures:
            try:
                joined = capture.join()
            except BaseException:
                joined = False
            if not joined:
                captures_joined = False
        census_known = False
        escaped_process = True
        control_survivor_check = None
        control_survivor_classes = ()
        try:
            if control_survivor_diagnostics:
                snapshot = _probe_uid_process_snapshot(
                    uid,
                    launched_pgid=process.pid,
                    include_survivor_classes=True,
                    python_executable=python_executable,
                )
                (
                    escaped_process,
                    control_survivor_check,
                    control_survivor_classes,
                ) = _snapshot_presence_result(snapshot)
            else:
                presence = _probe_uid_processes_present(
                    uid,
                    include_survivor_classes=True,
                    python_executable=python_executable,
                )
                escaped_process, control_survivor_classes = _presence_result(presence)
            census_known = True
        except BaseException:
            pass
        if not tree_stopped:
            cleanup_check = "probe_process_group_cleanup"
        elif not captures_joined:
            cleanup_check = "probe_process_capture_cleanup"
        elif not census_known:
            cleanup_check = "probe_process_census"
        elif escaped_process:
            if control_survivor_diagnostics:
                cleanup_check = (
                    control_survivor_check
                    if isinstance(control_survivor_check, str)
                    and control_survivor_check in NATIVE_PREFLIGHT_CHECKS
                    else "probe_process_survivor_controls_unattributed"
                )
            else:
                cleanup_check = (
                    survivor_check
                    if isinstance(survivor_check, str) and survivor_check in NATIVE_PREFLIGHT_CHECKS
                    else "probe_process_survivor"
                )
        else:
            cleanup_check = None
        if cleanup_check is not None:
            raise ProbeFailure(
                "native_preflight_unavailable",
                cleanup_complete=False,
                check=cleanup_check,
                survivor_classes=control_survivor_classes,
            )
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
    if timed_out or wait_uncertain:
        raise ProbeFailure("native_preflight_unavailable", cleanup_complete=False, check="probe_process_timeout")
    if stdout_capture.overflow or stderr_capture.overflow:
        raise ProbeFailure(failure_reason, check=failure_check, sandbox_stage=failure_stage_overflow)
    stderr = _strip_probe_identity_record(bytes(stderr_capture.data))
    if process.returncode != 0:
        raise ProbeFailure(
            failure_reason,
            check=failure_check,
            sandbox_stage=failure_stage_exit,
            sandbox_failure=_classify_exit(process.returncode, CONTROL_EXIT_FAILURES),
        )
    return subprocess.CompletedProcess(command, process.returncode, bytes(stdout_capture.data), stderr)


def _verify_runner_controls_are_private(paths, uid, python_executable):
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": "/tmp"}
    script = "import os,sys; raise SystemExit(1 if os.access(sys.argv[1], os.R_OK) else 0)"
    for path in paths:
        _run_as_probe_user(
            [python_executable, "-c", script, str(path)], uid, env=env, timeout=5,
            failure_reason="runner_control_unavailable", failure_check="probe_access",
            survivor_check="probe_process_survivor_controls",
            control_survivor_diagnostics=True,
            python_executable=python_executable,
        )
    if uid == 0:
        raise ProbeFailure("probe_identity_unavailable")


def _disable_developer_mode():
    env = {"LANG": "C", "LC_ALL": "C"}
    _require_success(_run(["/usr/sbin/DevToolsSecurity", "-disable"], env=env, timeout=10), "developer_mode_unavailable")
    result = _require_success(_run(["/usr/sbin/DevToolsSecurity", "-status"], env=env, timeout=10), "developer_mode_unavailable")
    if result.stdout != b"Developer mode is currently disabled.\n" or result.stderr:
        raise ProbeFailure("developer_mode_unavailable")


def _codesign_info(path, identifier):
    result = _require_success(
        _run(["/usr/bin/codesign", "-d", "--verbose=4", "--entitlements", ":-", str(path)], timeout=10),
        "sandbox_signing_unavailable",
    )
    details = (result.stdout + b"\n" + result.stderr).decode("utf-8", "ignore")
    if "Identifier=" + identifier not in details or "Signature=adhoc" not in details:
        raise ProbeFailure("sandbox_signing_unavailable")
    if "<?xml" in details or "com.apple.security" in details:
        raise ProbeFailure("sandbox_signing_unavailable")


def _build_signed_probe(root, scratch):
    source = root / "kit/confinement/macos_capability.swift"
    executable = scratch / "CapabilityProbe"
    child = scratch / "CapabilityChild"
    _require_success(
        _run(["/usr/bin/swiftc", "-O", "-o", executable, source], cwd=root, timeout=120),
        "sandbox_signing_unavailable",
    )
    shutil.copy2(executable, child)
    os.chmod(executable, 0o755)
    os.chmod(child, 0o755)
    signed = ((executable, APP_IDENTIFIER), (child, CHILD_IDENTIFIER))
    for path, identifier in signed:
        _require_success(
            _run(["/usr/bin/codesign", "--force", "--sign", "-", "--identifier", identifier, path], timeout=20),
            "sandbox_signing_unavailable",
        )
    for path, identifier in signed:
        _require_success(
            _run(["/usr/bin/codesign", "--verify", "--strict", "--verbose=0", path], timeout=15),
            "sandbox_signing_unavailable",
        )
        _codesign_info(path, identifier)
    return executable


def _resolve_sandbox_exec():
    try:
        path = _resolve_trusted_path(SANDBOX_EXEC_PATH)
        if path.as_posix() != SANDBOX_EXEC_PATH:
            raise ValueError
    except BaseException:
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_seatbelt") from None
    return SANDBOX_EXEC_PATH


def _prepare_storage_directory(path, uid):
    try:
        os.chown(path, uid, PROBE_PRIMARY_GID)
        os.chmod(path, 0o700)
        info = os.lstat(path)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != uid
            or info.st_gid != PROBE_PRIMARY_GID
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ValueError
        return _canonical_path(path), _storage_identity(info)
    except BaseException:
        raise ProbeFailure("probe_identity_unavailable", check="probe_identity_permissions") from None


def _storage_identity(info):
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode)


def _verify_storage_directory(path, expected, uid):
    try:
        canonical, identity = expected
        if _canonical_path(path) != canonical:
            raise ValueError
        info = os.lstat(canonical)
        if (
            not stat.S_ISDIR(info.st_mode)
            or _storage_identity(info) != identity
            or info.st_uid != uid
            or info.st_gid != PROBE_PRIMARY_GID
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise ValueError
    except BaseException:
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_storage") from None


def _canonical_path(path):
    return os.path.realpath(str(path))


def _seatbelt_literal(path):
    if type(path) is not str or not path:
        raise ValueError
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in path):
        raise ValueError
    if len(path.encode("utf-8")) > MAX_TOOL_PATH_BYTES:
        raise ValueError
    semantic_path = PurePosixPath(path)
    if (
        not semantic_path.is_absolute()
        or len(semantic_path.parts) < 2
        or semantic_path.as_posix() != path
        or ".." in semantic_path.parts
    ):
        raise ValueError
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _seatbelt_profile_text(marker, storage_directory, protected_directories, protected_files):
    try:
        if (
            not isinstance(protected_directories, (tuple, list))
            or not isinstance(protected_files, (tuple, list))
            or len(protected_directories) + len(protected_files) > MAX_SEATBELT_PATHS
        ):
            raise ValueError
        marker_literal = _seatbelt_literal(marker)
        storage_literal = _seatbelt_literal(storage_directory)
        directory_literals = sorted({_seatbelt_literal(path) for path in protected_directories})
        file_literals = sorted({_seatbelt_literal(path) for path in protected_files})
        mach_names = tuple(SEATBELT_MACH_LOOKUP_NAMES)
        if not all(type(name) is str and SEATBELT_MACH_NAME.fullmatch(name) for name in mach_names):
            raise ValueError
    except BaseException:
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_profile") from None
    lines = [
        "(version 1)",
        "(allow default)",
        "(deny network*)",
        "(deny lsopen)",
        "(deny mach-lookup)",
    ]
    if mach_names:
        lines.append(
            "(allow mach-lookup" + "".join(' (global-name "' + name + '")' for name in mach_names) + ")"
        )
    lines.append("(deny file-read* (literal " + marker_literal + "))")
    lines.extend("(deny file-read* (subpath " + literal + "))" for literal in directory_literals)
    lines.extend("(deny file-read* (literal " + literal + "))" for literal in file_literals)
    lines.append('(deny file-write* (subpath "/"))')
    lines.append(
        "(allow file-write* (subpath "
        + storage_literal
        + ")"
        + "".join(' (literal "' + device + '")' for device in SEATBELT_WRITABLE_DEVICES)
        + ")"
    )
    return "\n".join(lines) + "\n"


def _write_seatbelt_profile(scratch, marker, storage_directory, protected_directories, protected_files):
    try:
        text = _seatbelt_profile_text(
            _canonical_path(marker),
            _canonical_path(storage_directory),
            tuple(_canonical_path(path) for path in protected_directories),
            tuple(_canonical_path(path) for path in protected_files),
        )
        payload = text.encode("utf-8")
        path = Path(scratch) / SEATBELT_PROFILE_NAME
        flags = (
            os.O_WRONLY | os.O_CREAT | os.O_EXCL
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
        )
        descriptor = os.open(path, flags, 0o644)
        try:
            if os.write(descriptor, payload) != len(payload):
                raise OSError("short profile write")
        finally:
            os.close(descriptor)
        os.chmod(path, 0o644)
    except ProbeFailure:
        raise
    except BaseException:
        raise ProbeFailure("native_preflight_unavailable", check="probe_process_profile") from None
    return path


def _process_table():
    result = _require_success(_run(["/bin/ps", "-axo", "pid=,ppid=,uid=,comm="], timeout=5), "descriptor_readback_unavailable")
    rows = {}
    for line in result.stdout.decode("utf-8", "ignore").splitlines():
        fields = line.strip().split(maxsplit=3)
        if len(fields) != 4 or not fields[0].isdigit() or not fields[1].isdigit() or not fields[2].isdigit():
            continue
        rows[int(fields[0])] = (int(fields[1]), int(fields[2]), fields[3])
    return rows


def _descendants(root_pid, rows):
    children = {}
    for pid, (parent, uid, command) in rows.items():
        children.setdefault(parent, []).append(pid)
    result = []
    pending = list(children.get(root_pid, ()))
    while pending:
        pid = pending.pop()
        result.append(pid)
        pending.extend(children.get(pid, ()))
    return result


def _load_libproc():
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        library.proc_pidinfo.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_uint64, ctypes.c_void_p, ctypes.c_int)
        library.proc_pidinfo.restype = ctypes.c_int
        library.proc_pidfdinfo.argtypes = (ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int)
        library.proc_pidfdinfo.restype = ctypes.c_int
        library.proc_pidpath.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
        library.proc_pidpath.restype = ctypes.c_int
        return library
    except (OSError, AttributeError):
        raise ProbeFailure("descriptor_readback_unavailable")


def _unexpected_channel():
    return ProbeFailure("descriptor_channel_unexpected")


class _ToolchainPolicy:
    def __init__(self, images, storage, read_roots):
        self.images = frozenset(images)
        self.storage = storage
        self.read_roots = tuple(read_roots)


def _within(path, root):
    return path == root or path.startswith(root.rstrip("/") + "/")


def _toolchain_policy(compiler, linker, sdk_root, storage_directory):
    roots = [_canonical_path(sdk_root), _canonical_path(storage_directory)]
    for tool in (compiler, linker):
        parents = Path(_canonical_path(tool)).parents
        if len(parents) > 3:
            roots.append(parents[2].as_posix())
    return _ToolchainPolicy(
        (_canonical_path(compiler), _canonical_path(linker)),
        _canonical_path(storage_directory),
        sorted(set(roots)),
    )


def _pid_image(library, pid):
    buffer = ctypes.create_string_buffer(4096)
    returned = library.proc_pidpath(pid, buffer, len(buffer))
    if returned <= 0 or returned >= len(buffer):
        return None
    try:
        return buffer.raw[:returned].decode("utf-8")
    except UnicodeDecodeError:
        return None


def _image_is_trusted(pid, policy):
    if policy is None:
        return False
    image = _pid_image(_load_libproc(), pid)
    return image is not None and image in policy.images


_NULL_DEVICE_RDEV = []


def _null_device_rdev():
    if not _NULL_DEVICE_RDEV:
        try:
            info = os.stat(PROBE_STDIN_DEVICE)
        except OSError:
            raise ProbeFailure("descriptor_readback_unavailable") from None
        if not stat.S_ISCHR(info.st_mode):
            raise ProbeFailure("descriptor_readback_unavailable")
        _NULL_DEVICE_RDEV.append(info.st_rdev)
    return _NULL_DEVICE_RDEV[0]


def _native_vnode(library, pid, fd):
    buffer = ctypes.create_string_buffer(ctypes.sizeof(_VnodeFdInfoWithPath))
    returned = library.proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, buffer, len(buffer))
    if returned != ctypes.sizeof(_VnodeFdInfoWithPath):
        return None
    info = _VnodeFdInfoWithPath.from_buffer_copy(buffer.raw)
    if info.pfi.type != PROX_FDTYPE_VNODE:
        return None
    return info.pvip.vnode.stat.mode, info.pvip.vnode.stat.rdev, info.pvip.path, info.pfi.openflags


def _extra_descriptor_allowed(node, policy):
    mode, _rdev, raw_path, flags = node
    try:
        path = raw_path.decode("utf-8")
    except UnicodeDecodeError:
        return False
    if not (stat.S_ISREG(mode) or stat.S_ISDIR(mode)):
        return False
    if not path.startswith("/") or ".." in path.split("/"):
        return False
    if _within(path, policy.storage):
        return True
    if flags & FWRITE:
        return False
    return any(_within(path, root) for root in policy.read_roots)


def _native_descriptor_snapshot(pid, policy=None):
    """Return (descriptors, granted) for pid, None when the process is gone or unreadable,
    and raise descriptor_channel_unexpected for any readable but non-conforming process.
    The toolchain allowance is granted by the executable image path alone, never by name."""
    library = _load_libproc()
    buffer = ctypes.create_string_buffer(8192)
    returned = library.proc_pidinfo(pid, PROC_PIDLISTFDS, 0, buffer, len(buffer))
    if returned <= 0:
        return None
    if returned >= len(buffer):
        raise _unexpected_channel()
    if returned % ctypes.sizeof(_ProcFdInfo):
        raise ProbeFailure("descriptor_readback_unavailable")
    descriptors = {}
    for offset in range(0, returned, ctypes.sizeof(_ProcFdInfo)):
        item = _ProcFdInfo.from_buffer_copy(buffer.raw[offset : offset + ctypes.sizeof(_ProcFdInfo)])
        if item.fd < 0 or item.fd in descriptors:
            raise _unexpected_channel()
        descriptors[item.fd] = item.type
    if not descriptors:
        return None
    extras = sorted(set(descriptors) - {0, 1, 2})
    for fd, kind in descriptors.items():
        if kind != (PROX_FDTYPE_PIPE if fd in (1, 2) else PROX_FDTYPE_VNODE):
            raise _unexpected_channel()
    if not {1, 2}.issubset(descriptors):
        raise _unexpected_channel()
    granted = False
    if extras:
        if policy is None:
            raise _unexpected_channel()
        image = _pid_image(library, pid)
        if image is None:
            return None
        if image not in policy.images:
            raise _unexpected_channel()
        granted = True

    unreadable = False
    observations = {}
    if 0 in descriptors:
        node = _native_vnode(library, pid, 0)
        if node is None:
            unreadable = True
        else:
            mode, rdev, path, _flags = node
            if (
                path != PROBE_STDIN_DEVICE.encode("ascii")
                or not stat.S_ISCHR(mode)
                or rdev != _null_device_rdev()
            ):
                raise _unexpected_channel()
            observations[0] = {"mode": "?", "type": "VNODE", "name": PROBE_STDIN_DEVICE}
    pipe_handles = set()
    for fd in (1, 2):
        pipe_buffer = ctypes.create_string_buffer(ctypes.sizeof(_PipeFdInfo))
        returned = library.proc_pidfdinfo(pid, fd, PROC_PIDFDPIPEINFO, pipe_buffer, len(pipe_buffer))
        if returned != ctypes.sizeof(_PipeFdInfo):
            unreadable = True
            continue
        pipe = _PipeFdInfo.from_buffer_copy(pipe_buffer.raw)
        if pipe.pfi.type != PROX_FDTYPE_PIPE or pipe.pfi.openflags & (FREAD | FWRITE) != FWRITE:
            raise _unexpected_channel()
        handles = (pipe.pipeinfo.handle, pipe.pipeinfo.peerhandle)
        if not all(handles) or handles[0] == handles[1] or pipe_handles.intersection(handles):
            raise _unexpected_channel()
        pipe_handles.update(handles)
        observations[fd] = {
            "mode": "w",
            "type": "PIPE",
            "name": "->0x" + format(handles[0], "x"),
        }
    for fd in extras:
        node = _native_vnode(library, pid, fd)
        if node is None:
            unreadable = True
        elif not _extra_descriptor_allowed(node, policy):
            raise _unexpected_channel()
    if unreadable:
        return None
    return observations, granted


def _check_lsof_descriptors(entries, granted):
    for fd, entry in entries.items():
        if fd == 0:
            allowed = entry["type"] == "CHR" and entry["name"] == PROBE_STDIN_DEVICE
        elif fd in (1, 2):
            allowed = entry["type"] == "PIPE" and entry["name"].startswith("->")
        else:
            allowed = granted and entry["type"] in ("REG", "DIR")
        if not allowed:
            raise _unexpected_channel()
    if not {1, 2}.issubset(entries) or entries[1]["name"] == entries[2]["name"]:
        raise _unexpected_channel()


def _descriptor_snapshot(pids, policy=None, agreed=None):
    if not pids or len(set(pids)) != len(pids):
        raise ProbeFailure("descriptor_readback_unavailable")
    if agreed is None:
        agreed = set()
    agreed.intersection_update(pids)
    unconfirmed = [pid for pid in pids if pid not in agreed]
    lsof = {}
    if unconfirmed:
        joined = ",".join(str(pid) for pid in unconfirmed)
        result = _run(["/usr/sbin/lsof", "-nP", "-Fpfnt", "-p", joined], timeout=10)
        if result.returncode not in (0, 1):
            raise ProbeFailure("descriptor_readback_unavailable")
    else:
        result = subprocess.CompletedProcess([], 0, b"", b"")
    current_pid = None
    current_fd = None
    current_special_entry = False
    for line in result.stdout.decode("utf-8", "ignore").splitlines():
        if line.startswith("p") and line[1:].isdigit():
            current_pid = int(line[1:])
            if current_pid in lsof:
                raise ProbeFailure("descriptor_readback_unavailable")
            lsof[current_pid] = {}
            current_fd = None
            current_special_entry = False
        elif current_pid is not None and line.startswith("f"):
            descriptor = line[1:]
            match = re.fullmatch(r"(\d+)", descriptor)
            if match is None and descriptor not in LSOF_NON_DESCRIPTOR_ENTRIES:
                raise ProbeFailure("descriptor_readback_unavailable")
            if match is None:
                current_fd = None
                current_special_entry = True
            else:
                current_fd = int(match.group(1))
                current_special_entry = False
                if current_fd in lsof[current_pid]:
                    raise ProbeFailure("descriptor_readback_unavailable")
                lsof[current_pid][current_fd] = {"type": "", "name": ""}
        elif current_pid is not None and current_special_entry and line.startswith(("t", "n")):
            if not line[1:]:
                raise ProbeFailure("descriptor_readback_unavailable")
        elif current_pid is not None and current_fd is not None and line.startswith("t"):
            entry = lsof[current_pid][current_fd]
            if entry["type"] or not line[1:]:
                raise ProbeFailure("descriptor_readback_unavailable")
            entry["type"] = line[1:]
        elif current_pid is not None and current_fd is not None and line.startswith("n"):
            entry = lsof[current_pid][current_fd]
            if entry["name"] or not line[1:]:
                raise ProbeFailure("descriptor_readback_unavailable")
            entry["name"] = line[1:]
        else:
            raise ProbeFailure("descriptor_readback_unavailable")
    observations = {}
    for pid in pids:
        result_pair = _native_descriptor_snapshot(pid, policy)
        if result_pair is None:
            agreed.discard(pid)
            continue
        native, granted = result_pair
        if pid in agreed:
            observations[pid] = native
            continue
        entries = lsof.get(pid)
        if not entries:
            continue
        _check_lsof_descriptors(entries, granted)
        if {fd for fd in entries if fd < 3} != set(native):
            continue
        if native[1]["name"] == native[2]["name"]:
            raise _unexpected_channel()
        if any(native[fd]["type"] != entries[fd]["type"] or native[fd]["mode"] != "w" for fd in (1, 2)):
            continue
        agreed.add(pid)
        observations[pid] = native
    return observations


def _role_names(rows, pids):
    return {Path(rows[pid][2]).name.lower() for pid in pids if pid in rows}


def _observe_roles(names, counts):
    roles = set()
    roles.update(name for name in names if name in {"capabilityprobe", "capabilitychild", "sh", "sleep", "capability-child"})
    if any(name.startswith("python3") or name == "python" for name in names):
        roles.add("python3")
    if any(name.startswith("clang") for name in names):
        roles.add("clang")
    if counts.get("capability-child", 0) >= 2:
        roles.add("forked-grandchild")
    return roles


def _roles_complete(roles):
    return PROBE_ROLE_SET.issubset(roles)


def _missing_roles(roles):
    return tuple(role for role in PROBE_ROLE_ORDER if role not in roles)


def _rejection_bucket(count):
    if count <= 0:
        return "none"
    return "many" if count >= SNAPSHOT_REJECTIONS_MANY else "some"


class _Capture:
    def __init__(self, stream):
        self.stream = stream
        self.data = bytearray()
        self.overflow = False
        self.thread = threading.Thread(target=self._drain, daemon=True)

    def start(self):
        self.thread.start()

    def _drain(self):
        while True:
            try:
                chunk = self.stream.read(4096)
            except (OSError, ValueError):
                return
            if not chunk:
                return
            if len(self.data) + len(chunk) <= MAX_CAPTURE_BYTES:
                self.data.extend(chunk)
            else:
                self.overflow = True

    def join(self):
        if self.thread.ident is None:
            return True
        self.thread.join(timeout=5)
        return not self.thread.is_alive()


def _probe_group_exists(pgid):
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


def _signal_probe_group(process, signum):
    try:
        os.killpg(process.pid, signum)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.send_signal(signum)
        except OSError:
            pass


def _wait_probe_group_gone(process, timeout):
    deadline = time.monotonic() + timeout
    while _probe_group_exists(process.pid) and time.monotonic() < deadline:
        if process.poll() is None:
            try:
                process.wait(timeout=min(0.05, max(0.001, deadline - time.monotonic())))
            except subprocess.TimeoutExpired:
                pass
        else:
            time.sleep(min(0.05, max(0.001, deadline - time.monotonic())))
    return not _probe_group_exists(process.pid)


def _terminate_probe_tree(process):
    _signal_probe_group(process, signal.SIGTERM)
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        pass
    except OSError:
        return False
    if not _wait_probe_group_gone(process, 2):
        _signal_probe_group(process, signal.SIGKILL)
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass
        except OSError:
            return False
        if not _wait_probe_group_gone(process, 2):
            return False
    return process.poll() is not None


def _observe_probe(
    executable,
    marker,
    writable_directory,
    uid,
    home,
    *,
    sandbox_exec,
    profile,
    storage_directory,
    python_executable,
    compiler_executable,
    linker_executable,
    sdk_root,
    storage_identity,
):
    env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home), "LANG": "C"}
    argv = [
        str(sandbox_exec),
        "-f",
        str(profile),
        str(executable),
        "--marker",
        str(marker),
        "--writable-directory",
        str(writable_directory),
        "--storage-directory",
        str(storage_directory),
        "--python-executable",
        str(python_executable),
        "--compiler-executable",
        str(compiler_executable),
        "--linker-executable",
        str(linker_executable),
        "--sdk-root",
        str(sdk_root),
    ]
    _verify_storage_directory(storage_directory, storage_identity, uid)
    process = _spawn_probe_user(
        argv,
        uid,
        env=env,
        python_executable=python_executable,
        cwd="/tmp",
        failure_reason="sandbox_behavior_unavailable",
        failure_stage="probe_spawn",
    )
    captures = []
    try:
        out_capture = _Capture(process.stdout)
        err_capture = _Capture(process.stderr)
        captures.extend((out_capture, err_capture))
        out_capture.start()
        err_capture.start()
        deadline = time.monotonic() + MAX_PROBE_SECONDS
        observed_roles = set()
        rejected_polls = 0
        agreed = set()
        policy = _toolchain_policy(compiler_executable, linker_executable, sdk_root, storage_directory)
        expected_executable = Path(executable).name
        while time.monotonic() < deadline and process.poll() is None:
            rows = _process_table()
            root = rows.get(process.pid)
            root_is_probe = (
                root is not None
                and root[1] == uid
                and Path(root[2]).name == expected_executable
            )
            pids = (
                [pid for pid in _descendants(process.pid, rows) if rows[pid][1] == uid]
                if root_is_probe
                else []
            )
            if root_is_probe:
                pids.insert(0, process.pid)
            if pids:
                try:
                    verified = _descriptor_snapshot(pids, policy, agreed)
                except ProbeFailure as error:
                    if error.reason == "descriptor_channel_unexpected":
                        raise
                    verified = {}
                if len(verified) != len(pids):
                    rejected_polls += 1
                counts = {}
                for pid in pids:
                    if pid in verified:
                        name = Path(rows[pid][2]).name.lower()
                        if name.startswith("clang") and not _image_is_trusted(pid, policy):
                            continue
                        counts[name] = counts.get(name, 0) + 1
                observed_roles.update(_observe_roles(set(counts), counts))
            if out_capture.overflow or err_capture.overflow:
                break
            time.sleep(0.08)
        if out_capture.overflow or err_capture.overflow:
            raise ProbeFailure(
                "sandbox_behavior_unavailable",
                sandbox_stage=(
                    "probe_stdout_overflow_before_wait" if out_capture.overflow
                    else "probe_stderr_overflow_before_wait"
                ),
            )
        try:
            process.wait(timeout=max(1, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            raise ProbeFailure("probe_timeout", cleanup_complete=False)
        if out_capture.overflow or err_capture.overflow:
            raise ProbeFailure(
                "sandbox_behavior_unavailable",
                sandbox_stage=(
                    "probe_stdout_overflow_after_wait" if out_capture.overflow
                    else "probe_stderr_overflow_after_wait"
                ),
            )
    except ProbeFailure:
        raise
    except BaseException:
        raise ProbeFailure("native_preflight_unavailable", cleanup_complete=False, check="probe_process_observation") from None
    finally:
        try:
            tree_stopped = _terminate_probe_tree(process)
        except BaseException:
            tree_stopped = False
        captures_joined = True
        for capture in captures:
            try:
                joined = capture.join()
            except BaseException:
                joined = False
            if not joined:
                captures_joined = False
        census_known = False
        escaped_process = True
        survivor_classes = ()
        try:
            presence = _probe_uid_processes_present(
                uid,
                include_survivor_classes=True,
                python_executable=python_executable,
            )
            escaped_process, survivor_classes = _presence_result(presence)
            census_known = True
        except BaseException:
            pass
        if not tree_stopped:
            cleanup_check = "probe_process_group_cleanup"
        elif not captures_joined:
            cleanup_check = "probe_process_capture_cleanup"
        elif not census_known:
            cleanup_check = "probe_process_census"
        elif escaped_process:
            cleanup_check = "probe_process_survivor_probe_tree"
        else:
            cleanup_check = None
        if cleanup_check is not None:
            raise ProbeFailure(
                "native_preflight_unavailable", cleanup_complete=False, check=cleanup_check,
                survivor_classes=survivor_classes,
            )
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
    if out_capture.overflow or err_capture.overflow:
        raise ProbeFailure(
            "sandbox_behavior_unavailable",
            sandbox_stage=(
                "probe_stdout_overflow_final" if out_capture.overflow
                else "probe_stderr_overflow_final"
            ),
        )
    _strip_probe_identity_record(bytes(err_capture.data))
    if process.returncode != 0:
        raise ProbeFailure(
            "sandbox_behavior_unavailable",
            sandbox_stage="probe_exit",
            sandbox_failure=_classify_exit(process.returncode, PROBE_EXIT_FAILURES),
        )
    if not _roles_complete(observed_roles):
        raise ProbeFailure(
            "descriptor_readback_unavailable",
            missing_roles=_missing_roles(observed_roles),
            snapshot_rejections=_rejection_bucket(rejected_polls),
        )


def run_native_probe(control_sha):
    workspace = os.environ.get("CI_WORKSPACE")
    if not workspace:
        raise ProbeFailure("runner_control_unavailable")
    with _preflight_phase("context"):
        root = _check_context(control_sha, workspace)
    with _preflight_phase("probe_process_toolchain"):
        toolchain = _resolve_trusted_toolchain()
    with _preflight_phase("probe_process_seatbelt"):
        sandbox_exec = _resolve_sandbox_exec()
    with _preflight_phase("developer_mode"):
        _disable_developer_mode()
    with _preflight_phase("runner_controls"):
        runner_uid, protected_directories, protected_files = _protect_runner_controls(root)
    with _preflight_phase("probe_identity"):
        probe_uid, home_parent, home = _create_probe_identity(root)
    scratch = None
    outside = None
    storage = None
    cleanup_safe = True
    with _preflight_phase("capability_probe"):
        try:
            scratch = Path(tempfile.mkdtemp(prefix="sandbox-capability-", dir="/tmp"))
            outside = Path(tempfile.mkdtemp(prefix="sandbox-capability-write-", dir="/tmp"))
            storage = Path(tempfile.mkdtemp(prefix="sandbox-capability-storage-", dir="/tmp"))
            os.chmod(scratch, 0o755)
            os.chmod(outside, 0o1777)
            storage_identity = _prepare_storage_directory(storage, probe_uid)
            _verify_runner_controls_are_private(
                protected_directories + protected_files, probe_uid, python_executable=toolchain["python"]
            )
            marker = root / "kit/confinement/macos_capability.swift"
            if not marker.is_file() or not (marker.stat().st_mode & stat.S_IROTH):
                raise ProbeFailure("sandbox_behavior_unavailable", sandbox_stage="marker_access")
            user_env = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "HOME": str(home), "LANG": "C"}
            positive_read = "import sys; open(sys.argv[1], 'rb').close()"
            _run_as_probe_user(
                [toolchain["python"], "-c", positive_read, str(marker)], probe_uid, env=user_env, timeout=10,
                failure_reason="sandbox_behavior_unavailable",
                failure_stage_spawn="positive_read_spawn",
                failure_stage_overflow="positive_read_overflow",
                failure_stage_exit="positive_read_exit",
                survivor_check="probe_process_survivor_positive_read",
                python_executable=toolchain["python"],
            )
            positive_write = "import sys; open(sys.argv[1], 'wb').close()"
            positive_file = outside / "positive-control"
            _run_as_probe_user(
                [toolchain["python"], "-c", positive_write, str(positive_file)], probe_uid, env=user_env, timeout=10,
                failure_reason="sandbox_behavior_unavailable",
                failure_stage_spawn="positive_write_spawn",
                failure_stage_overflow="positive_write_overflow",
                failure_stage_exit="positive_write_exit",
                survivor_check="probe_process_survivor_positive_write",
                python_executable=toolchain["python"],
            )
            profile = _write_seatbelt_profile(
                scratch, marker, storage, protected_directories, protected_files
            )
            executable = _build_signed_probe(root, scratch)
            _observe_probe(
                executable,
                marker,
                outside,
                probe_uid,
                home,
                sandbox_exec=sandbox_exec,
                profile=profile,
                storage_directory=storage,
                python_executable=toolchain["python"],
                compiler_executable=toolchain["clang"],
                linker_executable=toolchain["linker"],
                sdk_root=toolchain["sdk"],
                storage_identity=storage_identity,
            )
        except ProbeFailure as error:
            if not error.cleanup_complete:
                cleanup_safe = False
            raise
        finally:
            if cleanup_safe:
                presence = _probe_uid_processes_present(
                    probe_uid,
                    include_survivor_classes=True,
                    python_executable=toolchain["python"],
                )
                has_survivors, survivor_classes = _presence_result(presence)
                if has_survivors:
                    raise ProbeFailure(
                        "native_preflight_unavailable", cleanup_complete=False,
                        check="probe_process_survivor_final_census", survivor_classes=survivor_classes,
                    )
                cleanup_failed = False
                for path in (home_parent, scratch, outside, storage):
                    try:
                        _remove_probe_tree(path)
                    except ProbeFailure:
                        cleanup_failed = True
                if cleanup_failed:
                    raise ProbeFailure(
                        "native_preflight_unavailable", cleanup_complete=False, check="probe_identity_cleanup"
                    )
                try:
                    delete_user = _run(["/usr/bin/dscl", ".", "-delete", "/Users/" + USERNAME], timeout=10)
                except ProbeFailure as error:
                    if error.reason == "native_preflight_unavailable":
                        raise ProbeFailure(
                            error.reason,
                            cleanup_complete=False,
                            check=error.check or "probe_identity_cleanup",
                        ) from None
                    raise
                except BaseException:
                    raise ProbeFailure(
                        "native_preflight_unavailable", cleanup_complete=False, check="probe_identity_cleanup"
                    ) from None
                if delete_user.returncode != 0 or delete_user.stderr:
                    raise ProbeFailure(
                        "native_preflight_unavailable", cleanup_complete=False, check="probe_identity_cleanup"
                    )


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-sha", required=True)
    arguments = parser.parse_args(argv)
    try:
        run_native_probe(arguments.control_sha)
    except ProbeFailure as error:
        print(
            safe_output(
                False, error.reason, error.check, survivor_classes=error.survivor_classes,
                sandbox_stage=error.sandbox_stage, sandbox_failure=error.sandbox_failure,
                missing_roles=error.missing_roles, snapshot_rejections=error.snapshot_rejections,
            ),
            end="",
        )
        return 1
    except BaseException:
        print("macos-capability=refused reason=native_preflight_unavailable")
        print("macos-confinement=refused reason=incomplete_channel_evidence")
        return 1
    print(safe_output(True), end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
