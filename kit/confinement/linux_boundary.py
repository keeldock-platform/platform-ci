import argparse
import ctypes
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

import linux_canaries as canaries
import linux_channels as channels
import linux_fixtures as fixtures
import linux_harness as harness
import linux_probes as probes
import linux_session as session
from linux_channels import BoundaryRefusal


BASE_ENV = {
    "PATH": "/usr/local/bin:/usr/bin",
    "LANG": "C",
    "LC_ALL": "C",
    "PYTHONDONTWRITEBYTECODE": "1",
    "PYTHONNOUSERSITE": "1",
}
LAUNCH = ["/usr/bin/python3", "-B", "/launch.py"]
PATH_PATTERN = re.compile(r"/[A-Za-z0-9._/@+=-]{1,300}")
SHA_PATTERN = re.compile(r"[a-f0-9]{40}")
CHANNEL_ORDER = tuple(name for name in channels.CHANNELS if name != "raw_logs") + ("raw_logs",)
FAULTS = {
    "network-open": "channel_leak",
    "control-dead": "control_not_fired",
    "usr-writable": "readback_failed",
    "uid-root": "readback_failed",
    "canary-readable": "canary_present",
    "canary-env": "canary_present",
    "scope-lowered": "readback_failed",
    "fixture-allowed": "fixture_allowed",
    "fixture-truncated": "fixture_incomplete",
    "recheck-dead": "control_not_fired",
}
PROCESS_VM_READV = 310
WORKER_NAMES = ("Runner.Worker", "Runner.Listener")


class Emitter:
    def __init__(self, stream=None):
        self.stream = sys.stdout if stream is None else stream
        self.lines = []

    def emit(self, text):
        self.lines.append(text)
        self.stream.write(text + chr(10))
        self.stream.flush()


class Outcome:
    def __init__(self, status, control, refusal=None):
        if status == "not-run":
            control = False
        self.status = status
        self.control = bool(control)
        self.refusal = refusal


class Iovec(ctypes.Structure):
    _fields_ = (("base", ctypes.c_void_p), ("length", ctypes.c_size_t))


def vm_readv_self_control(nonce):
    marker = ("vm-" + nonce).encode("ascii")
    source = ctypes.create_string_buffer(marker)
    target = ctypes.create_string_buffer(len(marker))
    local = Iovec(ctypes.cast(target, ctypes.c_void_p), len(marker))
    remote = Iovec(ctypes.cast(source, ctypes.c_void_p), len(marker))
    libc = ctypes.CDLL(None, use_errno=True)
    done = libc.syscall(
        ctypes.c_long(PROCESS_VM_READV),
        ctypes.c_long(os.getpid()),
        ctypes.byref(local),
        ctypes.c_long(1),
        ctypes.byref(remote),
        ctypes.c_long(1),
        ctypes.c_long(0),
    )
    return done == len(marker) and target.raw == marker


BPF_SYSCTL = "/proc/sys/kernel/unprivileged_bpf_disabled"
PERF_SYSCTL = "/proc/sys/kernel/perf_event_paranoid"


def restrict_kernel():
    if harness._read_sysctl(BPF_SYSCTL) == "0":
        harness._set_sysctl(BPF_SYSCTL, "1")
    paranoid = harness._read_sysctl(PERF_SYSCTL)
    if re.fullmatch(r"-?[0-9]{1,2}", paranoid) is None or int(paranoid) < 3:
        harness._set_sysctl(PERF_SYSCTL, "3")


def transcript_hits(lines, nonce, needles):
    marker = "kd-log-" + nonce
    count = 0
    for line in lines:
        encoded = line.encode("utf-8", "replace")
        if marker in line or line.startswith("::") or any(needle in encoded for needle in needles):
            count += 1
    return count


def verify_control_sha(expected):
    if type(expected) is not str or SHA_PATTERN.fullmatch(expected) is None:
        raise BoundaryRefusal("environment")
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=True,
            close_fds=True,
        )
    except (OSError, subprocess.SubprocessError):
        raise BoundaryRefusal("environment")
    if completed.stdout.decode("ascii", "replace").strip() != expected:
        raise BoundaryRefusal("environment")


def find_pids(names):
    found = []
    for item in os.listdir("/proc"):
        if not item.isdecimal():
            continue
        try:
            with open("/proc/" + item + "/comm", "rt", encoding="ascii", errors="replace") as source:
                if source.read(64).strip() in names:
                    found.append(int(item))
        except OSError:
            continue
    return sorted(found)


class Boundary:
    def __init__(self, arguments, emitter):
        self.arguments = arguments
        self.emitter = emitter
        self.fault = None
        self.nonce = os.urandom(12).hex()
        self.workdir = None
        self.tripwires = None
        self.usr_ro = []
        self.memory_canary = "not-run"
        self.readable_canary = "not-run"
        self.scope = "unread"
        self.fixture_controlled = 0
        self.fixture_uncontrolled = 0

    def close(self):
        if self.tripwires is not None:
            self.tripwires.close()
        if self.workdir is not None:
            shutil.rmtree(self.workdir, ignore_errors=True)

    def readback_before_drop(self, reader=None):
        read = harness._read_sysctl if reader is None else reader
        self.scope = read("/proc/sys/kernel/yama/ptrace_scope")
        if self.scope != "3":
            raise BoundaryRefusal("readback_failed", None, 61)
        if harness._read_sysctl("/proc/sys/user/max_user_namespaces") != "0":
            raise BoundaryRefusal("readback_failed", None, 62)
        if harness._read_sysctl("/proc/sys/kernel/unprivileged_bpf_disabled") not in ("1", "2"):
            raise BoundaryRefusal("readback_failed", None, 64)
        paranoid = harness._read_sysctl("/proc/sys/kernel/perf_event_paranoid")
        if re.fullmatch(r"-?[0-9]{1,2}", paranoid) is None or int(paranoid) < 2:
            raise BoundaryRefusal("readback_failed", None, 65)
        if self.arguments.runner_uid == harness.CHILD_UID:
            raise BoundaryRefusal("readback_failed", None, 23)

    def prepare(self, set_kernel):
        if os.geteuid() != 0:
            raise BoundaryRefusal("environment")
        verify_control_sha(self.arguments.control_sha)
        if set_kernel:
            try:
                harness._prepare_kernel()
                restrict_kernel()
            except harness.ProofFailure as failure:
                raise BoundaryRefusal("readback_failed", None, failure.reason)
        self.readback_before_drop()
        self.canary = canaries.load_canary(os.environ)
        if self.arguments.synthetic_standin and self.canary != canaries.STANDIN_VALUE:
            raise BoundaryRefusal("environment")
        self.workdir = tempfile.mkdtemp(prefix="kd-linux-")
        os.chmod(self.workdir, 0o755)
        self.public_dir = os.path.join(self.workdir, "public")
        self.ipc_dir = os.path.join(self.workdir, "ipc")
        self.canary_dir = os.path.join(self.workdir, "canary")
        self.control_dir = os.path.join(self.workdir, "control")
        for path in (self.public_dir, self.ipc_dir, self.canary_dir, self.control_dir):
            os.mkdir(path, 0o755)
        self.tripwires = session.TripwireSet(self.nonce, self.ipc_dir)
        self.nonce_canary = canaries.new_nonce_canary()
        self.derived_canary = canaries.derive_canary(self.canary, "kd-linux-file-placement")
        self.placed = [self.canary if self.arguments.synthetic_standin else self.derived_canary, self.nonce_canary]
        variants = set(canaries.needles_for(self.canary))
        variants.update(canaries.needles_for(self.derived_canary))
        variants.update(canaries.needles_for(self.nonce_canary))
        self.secret_needles = tuple(sorted(variants))
        canaries.place_canaries(self.canary_dir, self.placed)
        canaries.plant_control_files(self.control_dir, self.nonce)
        self.runner_root = canaries.runner_root()
        self.targets = canaries.runner_targets(self.arguments.runner_home, self.arguments.runner_temp, self.runner_root)
        self.required = canaries.required_unreadable(self.arguments.runner_temp, self.runner_root)

    def probe_files(self):
        return {
            "/probe.py": (probes.PROBE_SOURCE, 0o444),
            "/launch.py": (probes.LAUNCHER_SOURCE, 0o444),
        }

    def ipc_binds(self):
        return [{"source": self.ipc_dir, "target": "/ipc", "ro": True}]

    def chroot(self, argv, env, mode="confined", files=None, binds=None, **options):
        merged = self.probe_files()
        merged.update(files or {})
        result = session.run_chroot(
            self.workdir,
            self.nonce,
            argv,
            env,
            mode,
            merged,
            binds=self.ipc_binds() if binds is None else binds,
            **options
        )
        if mode == "confined" and not options.get("keep_root") and "usr_ro" in result.readback:
            self.usr_ro.append(bool(result.readback["usr_ro"]))
        return result

    def config(self, broken=False):
        config = self.tripwires.config()
        if broken:
            config["ports"] = {name: 9 for name in config["ports"]}
            config["unix_path"] = "/ipc/absent.sock"
            config["abstract_name"] = "kd-absent"
        return config

    def probe_argv(self, channel, config):
        return LAUNCH + ["/usr/bin/python3", "-B", "/probe.py", channel, json.dumps(config, sort_keys=True)]

    def decide(self, result, verdict, leaks, control):
        if result.timed_out:
            return Outcome("not-run", False, BoundaryRefusal("attempt_incomplete"))
        if leaks or verdict == "leak":
            return Outcome("observed-leak", control, BoundaryRefusal("channel_leak"))
        if verdict == "unexpected":
            return Outcome("not-run", False, BoundaryRefusal("attempt_unexpected"))
        if verdict == "incomplete":
            return Outcome("not-run", False, BoundaryRefusal("attempt_incomplete"))
        if not control:
            return Outcome("blocked", False, BoundaryRefusal("control_not_fired"))
        return Outcome("blocked", True)

    def network_control(self, channel, broken):
        self.tripwires.store.clear()
        environment = dict(BASE_ENV)
        if channel in ("artifact_upload", "cache_upload") and not broken:
            environment["ACTIONS_RUNTIME_TOKEN"] = "control-" + self.nonce
        result = self.chroot(
            self.probe_argv(channel, self.config(broken)),
            environment,
            mode="open",
            extra_fd=channel == "runner_ipc" and not broken,
        )
        markers = channels.control_markers(channel, self.nonce, self.tripwires.ipv6)
        seen = all(self.tripwires.store.seen(name, marker) for name, marker in markers)
        extra = channels.extra_control_attempt(channel)
        if extra is not None:
            seen = seen and dict(channels.parse_attempts(result.stdout)).get(extra) == "allowed"
        self.tripwires.store.clear()
        return seen

    def network_channel(self, channel, broken=False):
        mode = "confined"
        fault = None
        if self.fault == "network-open" and channel == "https":
            mode = "open"
        if self.fault == "uid-root" and channel == "runner_ipc":
            fault = "uid-root"
        if (self.fault == "control-dead" and channel == "dns") or (self.fault == "recheck-dead" and channel == "https"):
            broken = True
        before = self.network_control(channel, broken)
        self.tripwires.store.clear()
        result = self.chroot(self.probe_argv(channel, self.config()), BASE_ENV, mode=mode, fault=fault)
        leaks = self.tripwires.store.snapshot()
        verdict = channels.judge_attempts(channels.ATTEMPT_RULES[channel], result.stdout)
        self.tripwires.store.clear()
        after = self.network_control(channel, broken)
        return self.decide(result, verdict, leaks, before and after)

    def channel_raw_logs(self):
        result = self.chroot(self.probe_argv("raw_logs", self.config()), BASE_ENV)
        verdict = channels.judge_attempts(channels.ATTEMPT_RULES["raw_logs"], result.stdout)
        marker = ("kd-log-" + self.nonce).encode("ascii")
        captured = marker in result.stdout and marker in result.stderr
        scanner = transcript_hits(["x kd-log-" + self.nonce], self.nonce, self.secret_needles) == 1
        leaks = transcript_hits(self.emitter.lines, self.nonce, self.secret_needles)
        return self.decide(result, verdict, [1] * leaks, captured and scanner)

    def channel_boundary_disablement(self):
        fault = "usr-writable" if self.fault == "usr-writable" else None
        control = self.chroot(
            self.probe_argv("boundary_disablement", self.config()),
            BASE_ENV,
            mode="confined",
            keep_root=True,
        )
        confined = self.chroot(
            self.probe_argv("boundary_disablement", self.config()),
            BASE_ENV,
            mode="confined",
            fault=fault,
        )
        readback = confined.readback
        if readback.get("ptrace_scope") != "3" or readback.get("usr_ro") is not True or readback.get("netns") is not True:
            raise BoundaryRefusal("readback_failed", "boundary_disablement", 61)
        verdict = channels.judge_attempts(
            channels.ATTEMPT_RULES["boundary_disablement"],
            confined.stdout,
            channels.OPTIONAL_ATTEMPTS["boundary_disablement"],
        )
        allowed = channels.control_attempts_allowed(control.stdout, channels.BOUNDARY_CONTROL_ATTEMPTS)
        return self.decide(confined, verdict, [], allowed)

    def channel_runner_files(self):
        if self.fault == "canary-readable":
            canaries.place_canaries(self.canary_dir, self.placed, world_readable=True)
        try:
            return self.runner_files_outcome()
        finally:
            leak = os.path.join(self.canary_dir, "leak-file")
            if os.path.exists(leak):
                os.unlink(leak)

    def runner_files_outcome(self):
        control_dir, control_file = canaries.plant_writable_control(os.path.join(self.workdir, "writable"))
        real = list(self.targets)
        entries = real + [control_dir, control_file]
        paths = canaries.run_walker({"mode": "paths", "targets": entries, "nonce": self.nonce}, 60)
        existing = sum(1 for path in real if os.path.lexists(path))
        leaks = paths.get("leaks")
        required_ok = len(self.required) == 2 and all(path in real for path in self.required)
        if type(leaks) is not list or paths.get("tested") != existing + 2 or not required_ok:
            raise BoundaryRefusal("scan_incomplete", "runner_files")
        controls_leak = (len(real) in leaks) and (len(real) + 1 in leaks)
        real_leaks = [index for index in leaks if type(index) is int and index < len(real)]
        readable = canaries.control_token("readable", self.nonce).encode("ascii")
        private = canaries.control_token("private", self.nonce).encode("ascii")
        groups = [
            (canaries.GROUP_SECRET, self.secret_needles),
            (canaries.GROUP_READABLE_CONTROL, (readable,)),
            (canaries.GROUP_PRIVATE_CONTROL, (private,)),
        ]
        request = {
            "mode": "walk",
            "needles": canaries.encode_needles(groups),
            "cutoff_ns": canaries.current_cutoff_ns(),
            "seconds": canaries.WALK_SECONDS,
        }
        walk = canaries.evaluate_walk(canaries.run_walker(request, canaries.WALK_SECONDS + 60))
        self.readable_canary = "present" if walk["secret"] else "absent"
        control = controls_leak and walk["readable_control"] and not walk["private_control"]
        if walk["secret"]:
            return Outcome("observed-leak", control, BoundaryRefusal("canary_present", "runner_files"))
        if real_leaks:
            return Outcome("observed-leak", control, BoundaryRefusal("channel_leak", "runner_files"))
        if not control:
            return Outcome("blocked", False, BoundaryRefusal("control_not_fired", "runner_files"))
        return Outcome("blocked", True)

    def channel_process_memory(self):
        token = canaries.control_token("environ", self.nonce)
        extra = {canaries.CANARY_ENV_NAME: self.derived_canary} if self.fault == "canary-env" else None
        peer = session.start_peer(token, extra)
        try:
            targets = [os.getpid(), 1] + find_pids(WORKER_NAMES)
            config = {"nonce": self.nonce, "targets": targets, "helper": peer.pid}
            base = self.public_dir
            files = {
                base + "/launch.py": (probes.LAUNCHER_SOURCE, 0o444),
                base + "/probe.py": (probes.PROBE_SOURCE, 0o444),
            }
            argv = [
                "/usr/bin/python3", "-B", base + "/launch.py",
                "/usr/bin/python3", "-B", base + "/probe.py", "process_memory", json.dumps(config, sort_keys=True),
            ]
            result = session.run_host(self.workdir, self.nonce, argv, BASE_ENV, files)
            groups = [
                (canaries.GROUP_SECRET, self.secret_needles),
                (canaries.GROUP_READABLE_CONTROL, (token.encode("ascii"),)),
            ]
            scan = canaries.evaluate_environ(
                canaries.run_walker({"mode": "environ", "needles": canaries.encode_needles(groups)}, 120)
            )
        finally:
            session.stop_peer(peer)
        if result.readback.get("ptrace_scope") != "3":
            raise BoundaryRefusal("readback_failed", "process_memory", 61)
        verdict = channels.judge_attempts(channels.ATTEMPT_RULES["process_memory"], result.stdout)
        controls = channels.control_attempts_allowed(result.stdout, channels.control_names("process_memory"))
        control = controls and scan["readable_control"] and vm_readv_self_control(self.nonce)
        self.memory_canary = "absent" if (verdict == "ok" and not scan["secret"]) else "present"
        if scan["secret"]:
            return Outcome("observed-leak", control, BoundaryRefusal("canary_present", "process_memory"))
        return self.decide(result, verdict, [], control)

    def run_channel(self, channel):
        table = {name: (lambda name=name: self.network_channel(name)) for name in channels.NETWORK_CHANNELS}
        table["raw_logs"] = self.channel_raw_logs
        table["runner_files"] = self.channel_runner_files
        table["process_memory"] = self.channel_process_memory
        table["boundary_disablement"] = self.channel_boundary_disablement
        try:
            outcome = table[channel]()
        except BoundaryRefusal as refusal:
            outcome = Outcome("not-run", False, BoundaryRefusal(refusal.reason, channel, refusal.detail))
        except harness.ProofFailure as failure:
            outcome = Outcome("not-run", False, BoundaryRefusal("readback_failed", channel, failure.reason))
        if outcome.refusal is not None and outcome.refusal.channel is None:
            outcome.refusal = BoundaryRefusal(outcome.refusal.reason, channel, outcome.refusal.detail)
        return outcome

    def fixture_outcome(self, form):
        needs_rust = form in fixtures.NEEDS_RUSTC
        sysroot = self.arguments.rust_sysroot
        if needs_rust and not sysroot:
            raise BoundaryRefusal("fixture_incomplete")
        files = {path: entry for path, entry in fixtures.fixture_files(form).items()}
        files["/launch.py"] = (probes.LAUNCHER_SOURCE, 0o444)
        binds = self.ipc_binds()
        rustc = None
        if needs_rust:
            binds.append({"source": sysroot, "target": sysroot, "ro": True})
            rustc = sysroot + "/bin/rustc"
        environment = fixtures.fixture_env(form, self.nonce, self.tripwires.ports, "/ipc/docker.sock", rustc)
        argv = LAUNCH + fixtures.fixture_argv(form, self.nonce)
        options = {"work": True, "limits": "fixture", "timeout": fixtures.RUN_TIMEOUT[form], "cwd": "/work"}
        self.tripwires.store.clear()
        self.chroot(argv, environment, mode="open", files=files, binds=binds, **options)
        control = all(self.tripwires.store.seen(name, marker) for name, marker in fixtures.control_markers(form, self.nonce))
        self.tripwires.store.clear()
        mode = "open" if self.fault == "fixture-allowed" and form == "python" else "confined"
        confined_argv = argv
        if self.fault == "fixture-truncated" and form == "shell":
            confined_argv = LAUNCH + ["/usr/bin/bash", "-c", "exit 0"]
        result = self.chroot(confined_argv, environment, mode=mode, files=files, binds=binds, **options)
        events = self.tripwires.store.snapshot()
        self.tripwires.store.clear()
        verdict = channels.judge_attempts(fixtures.fixture_rules(form), result.stdout, fixtures.fixture_optional(form))
        if result.timed_out or verdict in ("incomplete",):
            raise BoundaryRefusal("fixture_incomplete")
        if events or verdict == "leak":
            raise BoundaryRefusal("fixture_allowed")
        if verdict == "unexpected":
            raise BoundaryRefusal("attempt_unexpected")
        if not control:
            raise BoundaryRefusal("control_not_fired")
        total = len(fixtures.fixture_rules(form))
        uncontrolled = len(fixtures.uncontrolled_attempts(form))
        self.fixture_controlled += total - uncontrolled
        self.fixture_uncontrolled += uncontrolled

    def run_fixtures(self):
        first = None
        completed = 0
        for form in fixtures.FORMS:
            try:
                self.fixture_outcome(form)
                completed += 1
            except BoundaryRefusal as refusal:
                if first is None:
                    first = refusal
            except harness.ProofFailure as failure:
                if first is None:
                    first = BoundaryRefusal("readback_failed", None, failure.reason)
        return completed, first


def run_phase(boundary, phase, with_fixtures):
    emitter = boundary.emitter
    record = channels.empty_record(phase)
    refusal = None
    outcomes = {}
    fixtures_state = "not-run"
    for channel in CHANNEL_ORDER:
        if channel == "raw_logs" and with_fixtures:
            completed, failure = boundary.run_fixtures()
            fixtures_state = "complete" if failure is None else "failed"
            emitter.emit(
                channels.LINE_PREFIX + "-FIXTURES schema=" + str(channels.SCHEMA_VERSION) + " phase=" + phase
                + " forms=" + str(completed) + "/" + str(len(fixtures.FORMS)) + " result=" + fixtures_state
                + " controlled=" + str(boundary.fixture_controlled) + " uncontrolled=" + str(boundary.fixture_uncontrolled)
            )
            if failure is not None and refusal is None:
                refusal = failure
        outcome = boundary.run_channel(channel)
        outcomes[channel] = outcome
        record["channels"][channel] = {"status": outcome.status, "control": outcome.control}
        emitter.emit(channels.channel_line(phase, channel, outcome.status, outcome.control))
        if outcome.refusal is not None and refusal is None:
            refusal = outcome.refusal
    record["fixtures"] = fixtures_state
    record["fixture_attempts"] = {
        "controlled": boundary.fixture_controlled,
        "uncontrolled": boundary.fixture_uncontrolled,
    }
    record["memory_canary"] = boundary.memory_canary
    record["readable_file_canary"] = boundary.readable_canary
    emitter.emit(channels.canary_line(phase, record["memory_canary"], record["readable_file_canary"]))
    usr = "unread" if not boundary.usr_ro else ("ro" if all(boundary.usr_ro) else "rw")
    emitter.emit(channels.readback_line(phase, (
        ("ptrace-scope", boundary.scope if re.fullmatch(r"[0-3]", boundary.scope or "") else "unread"),
        ("project-uid", str(harness.CHILD_UID)),
        ("usr-submounts", usr),
        ("runner-uid-distinct", "1" if boundary.arguments.runner_uid != harness.CHILD_UID else "0"),
    )))
    if refusal is None and with_fixtures and fixtures_state != "complete":
        refusal = BoundaryRefusal("fixture_incomplete")
    if refusal is None and (record["memory_canary"] != "absent" or record["readable_file_canary"] != "absent"):
        refusal = BoundaryRefusal("canary_present")
    if refusal is None and not all(item.status == "blocked" and item.control for item in outcomes.values()):
        refusal = BoundaryRefusal("control_not_fired")
    record["result"] = "accepted" if refusal is None else "refused"
    record["reason"] = "none" if refusal is None else refusal.reason
    blocked = sum(1 for item in outcomes.values() if item.status == "blocked")
    emitter.emit(channels.verdict_line(phase, refusal, blocked))
    return record, refusal


def write_record(path, record):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(descriptor, channels.dump_record(record).encode("ascii"))
    finally:
        os.close(descriptor)


def refused_record(phase, refusal):
    record = channels.empty_record(phase)
    record["reason"] = refusal.reason
    return record


def run_named_phase(arguments, phase):
    emitter = Emitter()
    boundary = Boundary(arguments, emitter)
    try:
        try:
            boundary.prepare(phase == "selftest")
        except BoundaryRefusal as refusal:
            emitter.emit(channels.verdict_line(phase, refusal, 0))
            write_record(arguments.record, refused_record(phase, refusal))
            return 1
        record, refusal = run_phase(boundary, phase, phase == "selftest")
        write_record(arguments.record, record)
        return 0 if refusal is None else 1
    finally:
        boundary.close()


def run_fault(boundary, name):
    expected = FAULTS[name]
    boundary.fault = name
    refusal = None
    try:
        if name == "scope-lowered":
            boundary.readback_before_drop(lambda path: "1")
        elif name in ("fixture-allowed", "fixture-truncated"):
            boundary.fixture_outcome("python" if name == "fixture-allowed" else "shell")
        elif name == "recheck-dead":
            outcome = boundary.run_channel("https")
            refusal = outcome.refusal
        else:
            channel = {
                "network-open": "https",
                "control-dead": "dns",
                "usr-writable": "boundary_disablement",
                "uid-root": "runner_ipc",
                "canary-readable": "runner_files",
                "canary-env": "process_memory",
            }[name]
            refusal = boundary.run_channel(channel).refusal
    except BoundaryRefusal as caught:
        refusal = caught
    except harness.ProofFailure as failure:
        refusal = BoundaryRefusal("readback_failed", None, failure.reason)
    finally:
        boundary.fault = None
    if name == "recheck-dead":
        boundary.emitter.emit(channels.verdict_line("recheck", refusal, 0) if refusal is not None else "linux-forced-fault-gap")
    matched = refusal is not None and refusal.reason == expected
    boundary.emitter.emit(
        "linux-forced-fault name=" + name + " result=" + ("refused" if matched else "unexpected")
        + " reason=" + (refusal.reason if refusal is not None else "none") + " expected=" + expected
    )
    return matched


def run_faults(arguments):
    emitter = Emitter()
    boundary = Boundary(arguments, emitter)
    try:
        try:
            boundary.prepare(True)
        except BoundaryRefusal as refusal:
            emitter.emit(channels.verdict_line("selftest", refusal, 0))
            return 1
        results = [run_fault(boundary, name) for name in FAULTS]
        status = "ok" if all(results) else "failed"
        emitter.emit("linux-forced-faults=" + status + " count=" + str(len(results)))
        return 0 if status == "ok" else 1
    finally:
        boundary.close()


def run_harden(arguments):
    emitter = Emitter()
    try:
        if os.geteuid() != 0:
            raise BoundaryRefusal("environment")
        root = canaries.runner_root()
        targets = canaries.runner_targets(arguments.runner_home, arguments.runner_temp, root)
        required = canaries.required_unreadable(arguments.runner_temp, root)
        if len(required) != 2 or not all(path in targets for path in required):
            raise BoundaryRefusal("scan_incomplete", "runner_files")
        changed = canaries.harden_runner_paths(targets)
        paths = canaries.run_walker({"mode": "paths", "targets": targets, "nonce": os.urandom(12).hex()}, 60)
        if paths.get("leaks") != [] or paths.get("tested") != len(targets):
            raise BoundaryRefusal("readback_failed", "runner_files")
    except BoundaryRefusal as refusal:
        line = (
            channels.LINE_PREFIX + "-HARDEN schema=" + str(channels.SCHEMA_VERSION)
            + " result=refused reason=" + refusal.reason
        )
        if refusal.channel is not None:
            line += " channel=" + refusal.channel
        emitter.emit(line + " project-execution=not_started")
        return 1
    emitter.emit(
        channels.LINE_PREFIX + "-HARDEN schema=" + str(channels.SCHEMA_VERSION)
        + " result=accepted targets=" + str(len(targets)) + " changed=" + str(changed) + " readable=0"
    )
    return 0


def run_merge(arguments):
    emitter = Emitter()
    try:
        with open(arguments.selftest, "rt", encoding="ascii") as source:
            first = channels.load_record(source.read(8193))
        with open(arguments.recheck, "rt", encoding="ascii") as source:
            second = channels.load_record(source.read(8193))
        merged = channels.merge_records(first, second)
    except (OSError, ValueError):
        emitter.emit("linux-source-boundary=refused phase=recheck reason=environment project-execution=not_started")
        return 1
    blocked = sum(1 for entry in merged["channels"].values() if entry["status"] == "blocked")
    emitter.emit(
        "linux-source-boundary-merged accepted=" + str(int(merged["accepted"]))
        + " channels=" + str(blocked) + "/" + str(len(channels.CHANNELS))
        + " memory-canary=" + merged["memory_canary"]
        + " readable-file-canary=" + merged["readable_file_canary"]
        + " fixtures=" + merged["fixtures"]
    )
    if arguments.out:
        handoff = arguments.reader_uid is not None or arguments.reader_gid is not None
        if handoff and (arguments.reader_uid is None or arguments.reader_gid is None
                        or arguments.reader_uid <= 0 or arguments.reader_gid <= 0):
            raise BoundaryRefusal("environment")
        if not os.path.isabs(arguments.out):
            raise BoundaryRefusal("environment")
        parent = os.open(os.path.dirname(arguments.out), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            descriptor = os.open(
                os.path.basename(arguments.out),
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600, dir_fd=parent,
            )
            try:
                body = (json.dumps(merged, sort_keys=True, separators=(",", ":")) + chr(10)).encode("ascii")
                if os.write(descriptor, body) != len(body):
                    raise BoundaryRefusal("environment")
                if handoff:
                    os.fchown(descriptor, arguments.reader_uid, arguments.reader_gid)
                    os.fchmod(descriptor, 0o600)
            finally:
                os.close(descriptor)
        finally:
            os.close(parent)
    return 0 if merged["accepted"] else 1


def optional_path(value):
    if value is None or value == "":
        return None
    if PATH_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("path")
    return value


def build_parser():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("command", choices=("selftest", "recheck", "faults", "merge", "harden"))
    parser.add_argument("--control-sha")
    parser.add_argument("--record")
    parser.add_argument("--rust-sysroot", type=optional_path, default=None)
    parser.add_argument("--runner-uid", type=int, default=-1)
    parser.add_argument("--runner-home", type=optional_path, default=None)
    parser.add_argument("--runner-temp", type=optional_path, default=None)
    parser.add_argument("--synthetic-standin", action="store_true")
    parser.add_argument("--selftest")
    parser.add_argument("--recheck")
    parser.add_argument("--out")
    parser.add_argument("--reader-uid", type=int)
    parser.add_argument("--reader-gid", type=int)
    return parser


def main(argv=None):
    arguments = build_parser().parse_args(argv)
    try:
        if arguments.command == "merge":
            return run_merge(arguments)
        if arguments.command in ("selftest", "recheck") and optional_path(arguments.record) is None:
            return 2
        if arguments.runner_uid < 0:
            return 2
        if arguments.command == "harden":
            return run_harden(arguments)
        if arguments.command == "faults":
            return run_faults(arguments)
        return run_named_phase(arguments, arguments.command)
    except Exception:
        sys.stdout.write("linux-source-boundary=refused phase=selftest reason=environment project-execution=not_started" + chr(10))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
