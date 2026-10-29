import base64
import functools
import json
import os
import re
import resource
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time

import linux_harness as harness
from linux_channels import BoundaryRefusal, valid_nonce


RESULT_PREFIX = b"KD-SESSION "
MAX_CAPTURE_BYTES = 65536
MAX_RESULT_BYTES = 400000
OUTER_SLACK_SECONDS = 40
PROBE_LIMITS = (
    (resource.RLIMIT_CPU, (20, 20)),
    (resource.RLIMIT_FSIZE, (4194304, 4194304)),
    (resource.RLIMIT_AS, (1073741824, 1073741824)),
    (resource.RLIMIT_NPROC, (64, 64)),
    (resource.RLIMIT_NOFILE, (64, 64)),
    (resource.RLIMIT_CORE, (0, 0)),
)
FIXTURE_LIMITS = (
    (resource.RLIMIT_CPU, (120, 120)),
    (resource.RLIMIT_FSIZE, (67108864, 67108864)),
    (resource.RLIMIT_AS, (resource.RLIM_INFINITY, resource.RLIM_INFINITY)),
    (resource.RLIMIT_NPROC, (256, 256)),
    (resource.RLIMIT_NOFILE, (256, 256)),
    (resource.RLIMIT_CORE, (0, 0)),
)
LIMIT_PROFILES = {"probe": PROBE_LIMITS, "fixture": FIXTURE_LIMITS}
CONFINED_UNSHARE = tuple(harness.UNSHARE_ARGUMENTS)
OPEN_UNSHARE = ("--mount", "--pid", "--fork", "--ipc", "--propagation", "private", "--kill-child=KILL")
HOST_UNSHARE = ("--mount", "--pid", "--fork", "--ipc", "--net", "--propagation", "private", "--kill-child=KILL")
MODES = ("confined", "open")
VIEWS = ("chroot", "host")
FAULTS = ("usr-writable", "uid-root")
MOUNT_FLAG_NAMES = {
    "nosuid": harness.MS_NOSUID,
    "nodev": harness.MS_NODEV,
    "noexec": harness.MS_NOEXEC,
    "noatime": 1024,
    "nodiratime": 2048,
    "relatime": 2097152,
}
HOSTS_TEXT = "127.0.0.1 localhost tripwire.invalid\n::1 localhost\n"
PASSWD_TEXT = "root:x:0:0:root:/root:/usr/sbin/nologin\nkdproject:x:62000:62000:project:/work:/usr/sbin/nologin\n"
GROUP_TEXT = "root:x:0:\nkdproject:x:62000:\n"
CRLF = bytes((13, 10))
SAFE_PATH = re.compile(r"/[A-Za-z0-9._/@+=-]{0,400}")
PROJECT_ENV_NAMES = frozenset((
    "PATH", "LANG", "LC_ALL", "HOME", "TMP", "TMPDIR", "CI",
    "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "CARGO_HOME", "RUSTUP_HOME",
    "CARGO_TARGET_DIR", "CARGO_NET_OFFLINE", "CARGO_INCREMENTAL", "RUSTC", "RUSTDOC",
    "RUSTFMT", "NODE", "NPM_CONFIG_OFFLINE", "NPM_CONFIG_CACHE", "NPM_CONFIG_USERCONFIG",
    "NPM_CONFIG_GLOBALCONFIG", "npm_config_offline", "npm_config_cache", "npm_config_userconfig",
    "npm_config_globalconfig",
))
PROJECT_ENV_SECRET_PARTS = ("TOKEN", "SECRET", "PASSWORD", "PRIVATE_KEY", "CREDENTIAL")


class EventStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.events = []

    def record(self, name, data):
        with self.lock:
            self.events.append((name, bytes(data)))

    def clear(self):
        with self.lock:
            self.events = []

    def snapshot(self):
        with self.lock:
            return list(self.events)

    def seen(self, name, marker):
        needle = marker.encode("ascii") if type(marker) is str else marker
        with self.lock:
            return any(entry == name and needle in data for entry, data in self.events)


def ok_reply(data):
    return b"HTTP/1.1 200 OK" + CRLF + b"Content-Length: 4" + CRLF + b"Connection: close" + CRLF + CRLF + b"live"


def proxy_reply(data):
    if data.startswith(b"CONNECT "):
        return b"HTTP/1.1 200 Connection established" + CRLF + CRLF
    return ok_reply(data)


def dns_reply(query):
    if len(query) < 17:
        return b""
    answer = bytes((0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1))
    return query[:2] + bytes((0x81, 0x80)) + query[4:6] + bytes((0, 1, 0, 0, 0, 0)) + query[12:] + answer


def redirect_reply(target_port):
    def reply(data):
        matched = re.match(rb"GET /redirect/([A-Za-z0-9-]{1,64}) ", data)
        if matched is None:
            return ok_reply(data)
        location = b"http://127.0.0.1:" + str(target_port).encode("ascii") + b"/sink/" + matched.group(1)
        return b"HTTP/1.1 302 Found" + CRLF + b"Location: " + location + CRLF + b"Content-Length: 0" + CRLF + b"Connection: close" + CRLF + CRLF
    return reply


def udp_reply(data):
    return b"live"


class Listener:
    def __init__(self, name, family, kind, address, reply, store):
        self.name = name
        self.kind = kind
        self.reply = reply
        self.store = store
        self.sock = socket.socket(family, kind)
        try:
            if family in (socket.AF_INET, socket.AF_INET6):
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if family == socket.AF_INET6:
                self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            self.sock.bind(address)
            if kind == socket.SOCK_STREAM:
                self.sock.listen(16)
        except OSError:
            self.sock.close()
            raise
        self.address = self.sock.getsockname()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while True:
            try:
                if self.kind == socket.SOCK_STREAM:
                    client, unused = self.sock.accept()
                    with client:
                        client.settimeout(1)
                        try:
                            data = client.recv(2048)
                        except OSError:
                            data = b""
                        self.store.record(self.name, data)
                        answer = self.reply(data) if self.reply is not None else b""
                        if answer:
                            try:
                                client.sendall(answer)
                            except OSError:
                                pass
                else:
                    data, sender = self.sock.recvfrom(2048)
                    self.store.record(self.name, data)
                    answer = self.reply(data) if self.reply is not None else b""
                    if answer:
                        try:
                            self.sock.sendto(answer, sender)
                        except OSError:
                            pass
            except OSError:
                return

    def close(self):
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


class TripwireSet:
    def __init__(self, nonce, ipc_directory):
        if not valid_nonce(nonce):
            raise BoundaryRefusal("environment")
        self.nonce = nonce
        self.store = EventStore()
        self.listeners = {}
        self.ports = {}
        self.ipv6 = False
        loopback = "127.0.0.1"
        stream = socket.SOCK_STREAM
        datagram = socket.SOCK_DGRAM
        try:
            self._add("https4", socket.AF_INET, stream, (loopback, 0), None)
            self._add("dns_udp", socket.AF_INET, datagram, (loopback, 53), dns_reply)
            self._add("dns_tcp", socket.AF_INET, stream, (loopback, 53), None)
            self._add("udp", socket.AF_INET, datagram, (loopback, 0), udp_reply)
            self._add("redirect_b", socket.AF_INET, stream, (loopback, 0), ok_reply)
            self._add("redirect_a", socket.AF_INET, stream, (loopback, 0), redirect_reply(self.ports["redirect_b"]))
            self._add("proxy", socket.AF_INET, stream, (loopback, 0), proxy_reply)
            self._add("artifact", socket.AF_INET, stream, (loopback, 0), ok_reply)
            self._add("cache", socket.AF_INET, stream, (loopback, 0), ok_reply)
        except OSError:
            self.close()
            raise BoundaryRefusal("environment")
        try:
            self._add("https6", socket.AF_INET6, stream, ("::1", 0), None)
            self.ipv6 = True
        except OSError:
            self.ipv6 = False
        self.unix_path = os.path.join(ipc_directory, "docker.sock")
        self.abstract_name = "kd-" + nonce
        try:
            self._add_unix("unix", self.unix_path)
            os.chmod(self.unix_path, 0o666)
            self._add_unix("abstract", chr(0) + self.abstract_name)
        except OSError:
            self.close()
            raise BoundaryRefusal("environment")

    def _add(self, name, family, kind, address, reply):
        listener = Listener(name, family, kind, address, reply, self.store)
        self.listeners[name] = listener
        self.ports[name] = listener.address[1]

    def _add_unix(self, name, address):
        listener = Listener(name, socket.AF_UNIX, socket.SOCK_STREAM, address, None, self.store)
        self.listeners[name] = listener

    def config(self):
        ports = {name: port for name, port in self.ports.items()}
        return {
            "nonce": self.nonce,
            "ports": ports,
            "unix_path": "/ipc/docker.sock",
            "abstract_name": self.abstract_name,
        }

    def close(self):
        for listener in list(self.listeners.values()):
            listener.close()


def parse_mountinfo(text):
    entries = []
    for line in text.splitlines():
        left, separator, unused = line.partition(" - ")
        fields = left.split(" ")
        if not separator or len(fields) < 6:
            continue
        mount_point = re.sub(r"\\([0-7]{3})", lambda matched: chr(int(matched.group(1), 8)), fields[4])
        entries.append({"mount_point": mount_point, "options": fields[5].split(",")})
    return entries


def mounts_under(entries, prefix):
    return [
        entry for entry in entries
        if entry["mount_point"] == prefix or entry["mount_point"].startswith(prefix.rstrip("/") + "/")
    ]


def writable_mounts(entries, prefix):
    return [entry["mount_point"] for entry in mounts_under(entries, prefix) if "ro" not in entry["options"]]


def remount_flags(options):
    flags = harness.MS_BIND | harness.MS_REMOUNT | harness.MS_RDONLY | harness.MS_NOSUID | harness.MS_NODEV
    for name in options:
        flags |= MOUNT_FLAG_NAMES.get(name, 0)
    return flags


def read_mountinfo():
    with open("/proc/self/mountinfo", "rt", encoding="utf-8", errors="replace") as source:
        return parse_mountinfo(source.read(1048576))


def harden_usr_submounts(rootfs):
    prefix = os.path.join(rootfs, "usr")
    for entry in sorted(mounts_under(read_mountinfo(), prefix), key=lambda item: len(item["mount_point"])):
        if "ro" not in entry["options"]:
            harness._mount(None, entry["mount_point"], None, remount_flags(entry["options"]))
    if writable_mounts(read_mountinfo(), prefix):
        raise harness.ProofFailure(95)


def harden_host_usr():
    harness._mount("/usr", "/usr", None, harness.MS_BIND | harness.MS_REC)
    for entry in sorted(mounts_under(read_mountinfo(), "/usr"), key=lambda item: len(item["mount_point"])):
        if "ro" not in entry["options"]:
            harness._mount(None, entry["mount_point"], None, remount_flags(entry["options"]))
    require_usr_readonly("/usr")


def require_usr_readonly(prefix):
    entries = mounts_under(read_mountinfo(), prefix)
    if not entries or writable_mounts(entries, prefix):
        raise harness.ProofFailure(95)


def netns_inode():
    return os.stat("/proc/self/ns/net").st_ino


def validate_spec(spec):
    if type(spec) is not dict:
        raise harness.ProofFailure(96)
    if spec.get("mode") not in MODES or spec.get("view") not in VIEWS or not valid_nonce(spec.get("nonce")):
        raise harness.ProofFailure(96)
    if spec["view"] == "host" and spec["mode"] != "confined":
        raise harness.ProofFailure(96)
    if type(spec.get("argv")) is not list or not spec["argv"] or not all(type(item) is str for item in spec["argv"]):
        raise harness.ProofFailure(96)
    env = spec.get("env")
    if type(env) is not dict or not all(type(key) is str and type(value) is str for key, value in env.items()):
        raise harness.ProofFailure(96)
    if any(
        key.startswith(("GITHUB_", "ACTIONS_", "RUNNER_", "SOURCE_READER_"))
        or any(part in key.upper() for part in PROJECT_ENV_SECRET_PARTS)
        or (key not in PROJECT_ENV_NAMES and not key.startswith("KD_"))
        for key in env
    ):
        raise harness.ProofFailure(96)
    files = spec.get("files")
    if type(files) is not dict:
        raise harness.ProofFailure(96)
    for path, entry in files.items():
        if type(path) is not str or SAFE_PATH.fullmatch(path) is None or type(entry) is not list or len(entry) != 2:
            raise harness.ProofFailure(96)
        if type(entry[0]) is not str or type(entry[1]) is not int:
            raise harness.ProofFailure(96)
    for bind in spec.get("binds", []):
        if type(bind) is not dict or set(bind) != {"source", "target", "ro"}:
            raise harness.ProofFailure(96)
        if SAFE_PATH.fullmatch(str(bind["source"])) is None or SAFE_PATH.fullmatch(str(bind["target"])) is None:
            raise harness.ProofFailure(96)
    if spec.get("limits") not in LIMIT_PROFILES:
        raise harness.ProofFailure(96)
    if type(spec.get("timeout")) is not int or not 1 <= spec["timeout"] <= 600:
        raise harness.ProofFailure(96)
    if spec.get("fault") is not None and spec["fault"] not in FAULTS:
        raise harness.ProofFailure(96)
    if type(spec.get("rootfs")) is not str or SAFE_PATH.fullmatch(spec["rootfs"]) is None:
        raise harness.ProofFailure(96)
    return spec


def write_files(base, files):
    for path, (text, mode) in files.items():
        target = base + path
        os.makedirs(os.path.dirname(target), mode=0o755, exist_ok=True)
        with open(target, "wt", encoding="utf-8") as sink:
            sink.write(text)
        os.chmod(target, mode)


def extend_rootfs(rootfs, spec):
    if spec.get("fault") == "usr-writable":
        harness._mount(None, os.path.join(rootfs, "usr"), None, harness.MS_BIND | harness.MS_REMOUNT | harness.MS_NOSUID | harness.MS_NODEV)
    else:
        harden_usr_submounts(rootfs)
    for name, text in (("hosts", HOSTS_TEXT), ("passwd", PASSWD_TEXT), ("group", GROUP_TEXT)):
        path = os.path.join(rootfs, "etc", name)
        with open(path, "wt", encoding="ascii") as sink:
            sink.write(text)
        os.chmod(path, 0o444)
    if spec.get("work"):
        work = os.path.join(rootfs, "work")
        os.makedirs(work, mode=0o700, exist_ok=True)
        harness._mount(
            "tmpfs", work, "tmpfs", harness.MS_NOSUID | harness.MS_NODEV,
            "size=96m,mode=0700,uid=" + str(harness.CHILD_UID) + ",gid=" + str(harness.CHILD_GID),
        )
    for bind in spec.get("binds", []):
        target = rootfs + bind["target"]
        os.makedirs(target, mode=0o755, exist_ok=True)
        harness._mount(bind["source"], target, None, harness.MS_BIND | harness.MS_REC)
        if bind["ro"]:
            harness._mount(None, target, None, harness.MS_BIND | harness.MS_REMOUNT | harness.MS_RDONLY | harness.MS_NOSUID | harness.MS_NODEV)
    write_files(rootfs, spec["files"])


def verify_dropped(pid):
    status = harness._read_status(pid)
    if status["Uid"] != [str(harness.CHILD_UID)] * 4 or status["Gid"] != [str(harness.CHILD_GID)] * 4:
        raise harness.ProofFailure(23)
    zero = ["0000000000000000"]
    if any(status[key] != zero for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")):
        raise harness.ProofFailure(24)
    if status["Groups"]:
        raise harness.ProofFailure(77)
    if status["NoNewPrivs"] != ["1"] or status["Seccomp"] != ["2"]:
        raise harness.ProofFailure(25)


def read_capture(reader):
    os.lseek(reader, 0, os.SEEK_SET)
    data = os.read(reader, MAX_CAPTURE_BYTES)
    os.close(reader)
    return data


def launch_and_collect(spec, argv, cwd, out, err, chrooted):
    confined = spec["mode"] == "confined"
    keep_root = bool(spec.get("keep_root"))
    drop = not keep_root and spec.get("fault") != "uid-root"
    limits = LIMIT_PROFILES[spec["limits"]]
    filter_on = confined and not keep_root and spec.get("fault") != "uid-root"
    preexec = functools.partial(harness._drop_child, limits, filter_on, drop)
    extra = None
    pass_fds = ()
    if spec.get("extra_fd"):
        extra = os.pipe()
        pass_fds = (extra[1],)
    process = subprocess.Popen(
        argv,
        stdout=out[1],
        stderr=err[1],
        close_fds=True,
        cwd=cwd,
        env=spec["env"],
        preexec_fn=preexec,
        start_new_session=True,
        pass_fds=pass_fds,
    )
    os.close(out[1])
    os.close(err[1])
    code = None
    timed_out = False
    try:
        harness._wait_for_stopped_process(process.pid)
        if confined and not keep_root:
            if chrooted:
                harness._verify_child(process.pid, spec["nonce"])
            else:
                verify_dropped(process.pid)
        os.kill(process.pid, signal.SIGCONT)
        try:
            code = process.wait(timeout=spec["timeout"])
        except subprocess.TimeoutExpired:
            timed_out = True
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        if chrooted and os.getpid() == 1:
            try:
                os.kill(-1, signal.SIGKILL)
            except OSError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.SubprocessError:
            pass
        if extra is not None:
            os.close(extra[0])
            os.close(extra[1])
    return code, timed_out


def inside_chroot(spec):
    confined = spec["mode"] == "confined"
    rootfs = harness._make_rootfs(spec["rootfs"])
    extend_rootfs(rootfs, spec)
    nonce = spec["nonce"]
    out_path, out_writer, out_reader = harness._write_capture(rootfs, "out-" + nonce)
    err_path, err_writer, err_reader = harness._write_capture(rootfs, "err-" + nonce)
    os.chroot(rootfs)
    os.chdir("/tmp")
    code = None
    timed_out = False
    try:
        code, timed_out = launch_and_collect(spec, spec["argv"], spec.get("cwd", "/tmp"), (out_path, out_writer), (err_path, err_writer), True)
    finally:
        stdout = read_capture(out_reader)
        stderr = read_capture(err_reader)
    readback = {"netns": False, "usr_ro": False, "ptrace_scope": "unread"}
    if confined and not spec.get("keep_root"):
        harness._verify_netns()
        readback["netns"] = True
        require_usr_readonly("/usr")
        readback["usr_ro"] = True
        readback["ptrace_scope"] = harness._read_sysctl("/proc/sys/kernel/yama/ptrace_scope")
    return code, timed_out, stdout, stderr, readback


def inside_host(spec):
    base = spec["rootfs"]
    write_files("", spec["files"])
    os.makedirs(os.path.join(base, "capture"), mode=0o700, exist_ok=True)
    harness._mount("proc", "/proc", "proc", harness.MS_NOSUID | harness.MS_NODEV | harness.MS_NOEXEC)
    minimal_dev("/dev")
    harden_host_usr()
    nonce = spec["nonce"]
    out_path, out_writer, out_reader = harness._write_capture(base, "out-" + nonce)
    err_path, err_writer, err_reader = harness._write_capture(base, "err-" + nonce)
    code = None
    timed_out = False
    try:
        code, timed_out = launch_and_collect(spec, spec["argv"], spec.get("cwd", "/"), (out_path, out_writer), (err_path, err_writer), False)
    finally:
        stdout = read_capture(out_reader)
        stderr = read_capture(err_reader)
    harness._verify_netns()
    require_usr_readonly("/usr")
    readback = {
        "netns": True,
        "usr_ro": True,
        "ptrace_scope": harness._read_sysctl("/proc/sys/kernel/yama/ptrace_scope"),
    }
    return code, timed_out, stdout, stderr, readback


def minimal_dev(path):
    os.makedirs(path, mode=0o755, exist_ok=True)
    harness._mount("tmpfs", path, "tmpfs", harness.MS_NOSUID | harness.MS_NOEXEC, "mode=0755,size=1m")
    for name, major, minor in (("null", 1, 3), ("zero", 1, 5), ("random", 1, 8), ("urandom", 1, 9)):
        target = os.path.join(path, name)
        os.mknod(target, stat.S_IFCHR | 0o666, os.makedev(major, minor))


def inside(spec):
    validate_spec(spec)
    if os.geteuid() != 0:
        raise harness.ProofFailure(46)
    if spec["mode"] == "confined":
        if netns_inode() == int(spec["netns"]):
            raise harness.ProofFailure(47)
        harness._verify_netns()
    if spec["view"] == "host":
        code, timed_out, stdout, stderr, readback = inside_host(spec)
    else:
        code, timed_out, stdout, stderr, readback = inside_chroot(spec)
    return {
        "exit": code,
        "timeout": timed_out,
        "stdout": base64.b64encode(stdout).decode("ascii"),
        "stderr": base64.b64encode(stderr).decode("ascii"),
        "readback": readback,
    }


def inside_main(spec_path):
    try:
        with open(spec_path, "rt", encoding="utf-8") as source:
            spec = json.load(source)
        reply = inside(spec)
    except harness.ProofFailure as failure:
        reply = {"refused": {"reason": "readback_failed", "detail": failure.reason}}
    except BoundaryRefusal as refusal:
        reply = {"refused": {"reason": refusal.reason, "detail": refusal.detail}}
    except Exception:
        reply = {"refused": {"reason": "session_failed", "detail": 98}}
    sys.stdout.write(RESULT_PREFIX.decode("ascii") + json.dumps(reply, sort_keys=True, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 0


class SessionResult:
    def __init__(self, exit_code, timed_out, stdout, stderr, readback):
        self.exit_code = exit_code
        self.timed_out = timed_out
        self.stdout = stdout
        self.stderr = stderr
        self.readback = readback


def parse_session_output(output):
    if type(output) is not bytes or len(output) > MAX_RESULT_BYTES:
        raise BoundaryRefusal("session_failed")
    lines = [line for line in output.split(b"\n") if line.startswith(RESULT_PREFIX)]
    if len(lines) != 1:
        raise BoundaryRefusal("session_failed")
    try:
        reply = json.loads(lines[0][len(RESULT_PREFIX):].decode("ascii"))
    except (UnicodeError, ValueError):
        raise BoundaryRefusal("session_failed")
    if type(reply) is not dict:
        raise BoundaryRefusal("session_failed")
    if "refused" in reply:
        refusal = reply["refused"]
        if type(refusal) is not dict:
            raise BoundaryRefusal("session_failed")
        detail = refusal.get("detail")
        raise BoundaryRefusal(refusal.get("reason", "session_failed"), None, detail if type(detail) is int else None)
    if set(reply) != {"exit", "timeout", "stdout", "stderr", "readback"}:
        raise BoundaryRefusal("session_failed")
    try:
        stdout = base64.b64decode(reply["stdout"], validate=True)
        stderr = base64.b64decode(reply["stderr"], validate=True)
    except (ValueError, TypeError):
        raise BoundaryRefusal("session_failed")
    if type(reply["readback"]) is not dict or type(reply["timeout"]) is not bool:
        raise BoundaryRefusal("session_failed")
    return SessionResult(reply["exit"], reply["timeout"], stdout, stderr, reply["readback"])


def _spawn(workdir, spec, unshare_arguments):
    session_dir = tempfile.mkdtemp(prefix="session-", dir=workdir)
    try:
        spec = dict(spec)
        spec["rootfs"] = os.path.join(session_dir, "root")
        spec["netns"] = str(netns_inode())
        spec.setdefault("binds", [])
        spec.setdefault("fault", None)
        try:
            validate_spec(spec)
        except harness.ProofFailure:
            raise BoundaryRefusal("environment")
        spec_path = os.path.join(session_dir, "spec.json")
        descriptor = os.open(spec_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wt", encoding="utf-8") as sink:
            json.dump(spec, sink)
        os.mkdir(spec["rootfs"], 0o700)
        command = [
            shutil.which("unshare") or "/usr/bin/unshare",
            *unshare_arguments,
            "--",
            sys.executable,
            "-B",
            os.path.abspath(__file__),
            "--inside",
            spec_path,
        ]
        environment = {
            "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        try:
            completed = subprocess.run(
                command,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=spec["timeout"] + OUTER_SLACK_SECONDS,
                check=False,
                close_fds=True,
            )
        except (OSError, subprocess.SubprocessError):
            raise BoundaryRefusal("session_failed")
        return parse_session_output(completed.stdout)
    finally:
        shutil.rmtree(session_dir, ignore_errors=True)


def run_chroot(workdir, nonce, argv, env, mode, files, binds=(), work=False, limits="probe", timeout=30,
               extra_fd=False, keep_root=False, fault=None, cwd="/tmp"):
    spec = {
        "mode": mode,
        "view": "chroot",
        "nonce": nonce,
        "argv": list(argv),
        "env": dict(env),
        "files": {path: [text, mode_bits] for path, (text, mode_bits) in files.items()},
        "binds": [dict(item) for item in binds],
        "work": bool(work),
        "limits": limits,
        "timeout": timeout,
        "extra_fd": bool(extra_fd),
        "keep_root": bool(keep_root),
        "fault": fault,
        "cwd": cwd,
    }
    arguments = CONFINED_UNSHARE if mode == "confined" else OPEN_UNSHARE
    return _spawn(workdir, spec, arguments)


def run_host(workdir, nonce, argv, env, files, limits="probe", timeout=30, cwd="/"):
    spec = {
        "mode": "confined",
        "view": "host",
        "nonce": nonce,
        "argv": list(argv),
        "env": dict(env),
        "files": {path: [text, mode_bits] for path, (text, mode_bits) in files.items()},
        "binds": [],
        "work": False,
        "limits": limits,
        "timeout": timeout,
        "extra_fd": False,
        "keep_root": False,
        "fault": None,
        "cwd": cwd,
    }
    return _spawn(workdir, spec, HOST_UNSHARE)


def start_peer(token, extra=None):
    environment = {"KD_CONTROL": token}
    environment.update(extra or {})
    return subprocess.Popen(
        ["/usr/bin/python3", "-c", "import time; time.sleep(120)"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        env=environment,
        user=harness.CHILD_UID,
        group=harness.CHILD_GID,
        extra_groups=[],
        start_new_session=True,
    )


def stop_peer(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        pass
    try:
        process.wait(timeout=5)
    except subprocess.SubprocessError:
        pass


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--inside":
        raise SystemExit(inside_main(sys.argv[2]))
    raise SystemExit(2)
