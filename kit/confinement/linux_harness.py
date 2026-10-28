import argparse
import ctypes
import errno
import fcntl
import http.server
import os
import pathlib
import re
import resource
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request


SHA_PATTERN = re.compile(r"[a-f0-9]{40}\Z")
PROBES = ("tcp", "udp", "dns", "http", "proxy", "redirect", "ipc", "socket-policy", "file", "environment", "process", "boundary")
SUPERVISION_TRANSITIONS = {
    ("start", "parent-stopped"): "parent-held",
    ("parent-held", "descendant-stopped"): "descendant-held",
    ("descendant-held", "descendant-killed"): "descendant-dead",
    ("descendant-dead", "parent-stopped-again"): "parent-held-again",
    ("parent-held-again", "parent-resumed"): "parent-running",
    ("parent-running", "parent-exited"): "parent-dead",
    ("parent-dead", "descendant-reaped"): "complete",
}
CHILD_UID = 65534
CHILD_GID = 65534
MAX_CAPTURE = 8192
MAX_PROBE_SECONDS = 10
INNER_REFUSAL_REASONS = (
    20, 21, 22, 23, 24, 25, 26, 27, 45, 46, 47, 48, 51, 52, 53,
    57, 58, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78,
    79, 80, 81, 85, 86, 87, 88, 89, 90, 98,
)
INNER_REFUSAL_LINES = {
    ("inner=refused reason=" + str(reason) + "\n").encode("ascii"): reason
    for reason in INNER_REFUSAL_REASONS
}
MAX_INNER_REFUSAL_BYTES = len(b"inner=refused reason=98\n")
UNSHARE_ARGUMENTS = ("--mount", "--pid", "--fork", "--ipc", "--net", "--propagation", "private", "--kill-child=KILL")
PR_SET_NO_NEW_PRIVS = 38
PR_CAPBSET_DROP = 24
SIOCGIFFLAGS = 0x8913
IFF_UP = 0x1
NETLINK_ROUTE = 0
SOL_NETLINK = 270
NETLINK_GET_STRICT_CHK = 12
RTM_GETROUTE = 26
NLM_F_REQUEST = 1
NLM_F_MULTI = 2
NLM_F_DUMP = 0x300
NLMSG_DONE = 3
ROUTE_CHANGE_GROUPS = sum(1 << (group - 1) for group in (1, 5, 7, 8, 9, 11, 19))
MAX_ROUTE_DUMP_BYTES = 65536
MAX_ROUTE_DUMP_SECONDS = 2
MS_RDONLY = 1
MS_NOSUID = 2
MS_NODEV = 4
MS_NOEXEC = 8
MS_BIND = 4096
MS_REC = 16384
MS_REMOUNT = 32
PR_SET_CHILD_SUBREAPER = 36
PR_SET_SECCOMP = 22
AUDIT_ARCH_NATIVE = 0xC000003E
COMPAT_SYSCALL_BIT = 0x40000000
SECCOMP_DENY = 0x00050000 | errno.EPERM
SECCOMP_ALLOW = 0x7FFF0000
SOCKET_SYSCALLS = (41, 53, 425, 426, 427)
SOCKET_FILTER = (
    (0x20, 0, 0, 4),
    (0x15, 1, 0, AUDIT_ARCH_NATIVE),
    (0x06, 0, 0, SECCOMP_DENY),
    (0x20, 0, 0, 0),
    (0x45, 0, 1, COMPAT_SYSCALL_BIT),
    (0x06, 0, 0, SECCOMP_DENY),
) + tuple(instruction for number in SOCKET_SYSCALLS for instruction in (
    (0x15, 0, 1, number),
    (0x06, 0, 0, SECCOMP_DENY),
)) + ((0x06, 0, 0, SECCOMP_ALLOW),)


class SockFilter(ctypes.Structure):
    _fields_ = (("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint32))


class SockFprog(ctypes.Structure):
    _fields_ = (("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter)))


class ProofFailure(Exception):
    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def valid_sha(value):
    return type(value) is str and SHA_PATTERN.fullmatch(value) is not None


def outcome(accepted, reason, control_sha=None):
    if type(reason) is not int or reason < 0 or reason > 99:
        raise ValueError("reason")
    if accepted:
        if not valid_sha(control_sha):
            raise ValueError("sha")
        return "linux-confinement=accepted control-sha=" + control_sha + " reason=" + str(reason)
    return "linux-confinement=refused reason=" + str(reason)


def advance_supervision(stage, event):
    next_stage = SUPERVISION_TRANSITIONS.get((stage, event))
    if next_stage is None:
        raise ProofFailure(69)
    return next_stage


def _raise_errno(reason):
    raise ProofFailure(reason)


def _mount(source, target, filesystem, flags, data=None):
    libc = ctypes.CDLL(None, use_errno=True)
    src = None if source is None else os.fsencode(source)
    dst = os.fsencode(target)
    fs = None if filesystem is None else os.fsencode(filesystem)
    opts = None if data is None else os.fsencode(data)
    if libc.mount(src, dst, fs, flags, opts) != 0:
        _raise_errno(20)


def _prctl(option, argument):
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(option, argument, 0, 0, 0) != 0:
        _raise_errno(21)


def _read_status(pid):
    result = {}
    with open("/proc/" + str(pid) + "/status", "rt", encoding="ascii") as source:
        for line in source:
            if ":" in line:
                key, value = line.split(":", 1)
                if key in ("Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp", "Seccomp_filters"):
                    result[key] = value.strip().split()
    if set(result) != {"Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs", "Seccomp", "Seccomp_filters"}:
        raise ProofFailure(22)
    return result


def _filter_count(status):
    values = status["Seccomp_filters"]
    if len(values) != 1 or re.fullmatch(r"[0-9]{1,2}", values[0]) is None:
        raise ProofFailure(89)
    return int(values[0])


def _install_socket_filter():
    if sys.platform != "linux" or os.uname().machine != "x86_64" or ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ProofFailure(88)
    before = _read_status(os.getpid())
    if before["NoNewPrivs"] != ["1"] or before["Seccomp"] not in (["0"], ["2"]):
        raise ProofFailure(88)
    expected_count = _filter_count(before) + 1
    instructions = (SockFilter * len(SOCKET_FILTER))(*(SockFilter(*item) for item in SOCKET_FILTER))
    program = SockFprog(len(instructions), instructions)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_SECCOMP, 2, ctypes.byref(program), 0, 0) != 0:
        raise ProofFailure(88)
    after = _read_status(os.getpid())
    if after["NoNewPrivs"] != ["1"] or after["Seccomp"] != ["2"] or _filter_count(after) != expected_count:
        raise ProofFailure(89)


def _descriptor_targets(pid):
    directory = pathlib.Path("/proc") / str(pid) / "fd"
    names = sorted(directory.iterdir(), key=lambda item: int(item.name))
    return {item.name: os.readlink(item) for item in names}


def _verify_child(pid, nonce):
    status = _read_status(pid)
    if status["Uid"] != [str(CHILD_UID)] * 4 or status["Gid"] != [str(CHILD_GID)] * 4:
        raise ProofFailure(23)
    zero = ["0000000000000000"]
    if any(status[key] != zero for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")):
        raise ProofFailure(24)
    if status["Groups"]:
        raise ProofFailure(77)
    if status["NoNewPrivs"] != ["1"]:
        raise ProofFailure(25)
    if status["Seccomp"] != ["2"] or _filter_count(status) != _filter_count(_read_status(1)) + 1:
        raise ProofFailure(89)
    tasks = os.listdir("/proc/" + str(pid) + "/task")
    if tasks != [str(pid)]:
        raise ProofFailure(80)
    descriptors = _descriptor_targets(pid)
    if set(descriptors) != {"1", "2"}:
        raise ProofFailure(26)
    for descriptor, name in (("1", "out"), ("2", "err")):
        expected_path = "/capture/" + name + "-" + nonce
        if descriptors[descriptor] != expected_path:
            raise ProofFailure(27)
        expected = os.stat(expected_path, follow_symlinks=False)
        actual = os.stat("/proc/" + str(pid) + "/fd/" + descriptor)
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise ProofFailure(90)
        if not stat.S_ISREG(actual.st_mode) or stat.S_IMODE(actual.st_mode) != 0o200 or actual.st_uid != 0:
            raise ProofFailure(90)
        with open("/proc/" + str(pid) + "/fdinfo/" + descriptor, "rt", encoding="ascii") as source:
            info = source.read(1025)
        flags = re.findall(r"^flags:\s+([0-7]+)$", info, re.MULTILINE)
        if len(info) > 1024 or len(flags) != 1 or int(flags[0], 8) & os.O_ACCMODE != os.O_WRONLY:
            raise ProofFailure(90)
    return descriptors


def _verify_process_set(expected):
    actual = set()
    for item in os.listdir("/proc"):
        if item.isdecimal():
            actual.add(int(item))
    if actual != set(expected):
        raise ProofFailure(68)


def _read_process_state(pid):
    with open("/proc/" + str(pid) + "/status", "rt", encoding="ascii") as source:
        for line in source:
            if line.startswith("State:"):
                return line.split()[1]
    raise ProofFailure(70)


def _children(pid):
    path = "/proc/" + str(pid) + "/task/" + str(pid) + "/children"
    with open(path, "rt", encoding="ascii") as source:
        value = source.read(256).strip()
    if len(value) > 256:
        raise ProofFailure(71)
    return tuple(int(item) for item in value.split())


def _wait_for_stopped_descendant(parent):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        children = _children(parent)
        if len(children) == 1:
            child = children[0]
            if _read_process_state(child) in ("T", "t"):
                return child
        elif len(children) > 1:
            raise ProofFailure(72)
        time.sleep(0.01)
    raise ProofFailure(73)


def _wait_for_stopped_process(pid):
    _wait_for_process_state(pid, "T")
    waited, status = os.waitpid(pid, os.WUNTRACED | os.WNOHANG)
    if waited != pid or not os.WIFSTOPPED(status):
        raise ProofFailure(78)
    return status


def _wait_for_process_state(pid, expected):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            if _read_process_state(pid) == expected:
                return
        except OSError:
            pass
        time.sleep(0.01)
    raise ProofFailure(74)


CHILD_LIMITS = (
    (resource.RLIMIT_CPU, (3, 3)),
    (resource.RLIMIT_FSIZE, (MAX_CAPTURE // 2, MAX_CAPTURE // 2)),
    (resource.RLIMIT_AS, (268435456, 268435456)),
    (resource.RLIMIT_NPROC, (16, 16)),
    (resource.RLIMIT_NOFILE, (16, 16)),
    (resource.RLIMIT_CORE, (0, 0)),
)


def _drop_child(limits=None, socket_filter=True, drop_privileges=True):
    libc = ctypes.CDLL(None, use_errno=True)
    if drop_privileges:
        for capability in range(64):
            if libc.prctl(PR_CAPBSET_DROP, capability, 0, 0, 0) != 0:
                error = ctypes.get_errno()
                if error not in (errno.EINVAL, errno.EPERM):
                    os._exit(91)
        if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
            os._exit(92)
        os.setgroups([])
        os.setresgid(CHILD_GID, CHILD_GID, CHILD_GID)
        os.setresuid(CHILD_UID, CHILD_UID, CHILD_UID)
    if socket_filter:
        _install_socket_filter()
    for key, limit in (CHILD_LIMITS if limits is None else limits):
        resource.setrlimit(key, limit)
    os.close(0)


CHILD_SOURCE = """
import ctypes
import errno
import os
import signal
import socket
import sys
import urllib.error
import urllib.request

kind = sys.argv[1]
nonce = sys.argv[2]
tcp_port = int(sys.argv[3])
udp_port = int(sys.argv[4])
http_port = int(sys.argv[6])
ipc_path = sys.argv[7]
file_path = sys.argv[8]
names = tuple(os.environ)

def _require_socket_policy():
    libc = ctypes.CDLL(None, use_errno=True)
    pair = (ctypes.c_int * 2)()
    calls = [(41, (family, kind, 0)) for family in (1, 2, 10, 16, 17, 40, 0x7fffffff) for kind in (1, 2, 3, 5)]
    calls += [(41, (40 | (1 << 32), 1, 0)), (41, (40, 1 | 0x80000 | 0x800, 0))]
    calls += [(53, (1, 1, 0, ctypes.addressof(pair)))]
    calls += [(number, (0, 0, 0, 0, 0, 0)) for number in (425, 426, 427)]
    calls += [(0x40000000 | number, (0, 0, 0, 0, 0, 0)) for number in (41, 53, 425, 426, 427)]
    for number, arguments in calls:
        ctypes.set_errno(0)
        result = libc.syscall(ctypes.c_long(number), *(ctypes.c_long(value) for value in arguments))
        if result != -1 or ctypes.get_errno() != errno.EPERM:
            raise RuntimeError("socket-policy")

def _require_process_denials():
    for path in ("/proc/1/environ", "/proc/1/fd"):
        try:
            if path.endswith("/fd"):
                os.listdir(path)
            else:
                with open(path, "rb") as source:
                    source.read(4096)
        except PermissionError as error:
            if error.errno not in (errno.EACCES, errno.EPERM):
                raise
        else:
            raise RuntimeError("process")

os.kill(os.getpid(), signal.SIGSTOP)
pid = os.fork()
if pid == 0:
    _require_socket_policy()
    os.kill(os.getpid(), signal.SIGSTOP)
    os._exit(0)
blocked = False

def _expected_denial(kind, error):
    if kind == "file":
        return isinstance(error, OSError) and error.errno == errno.ENOENT
    if kind in ("tcp", "udp", "dns", "http", "proxy", "redirect", "ipc"):
        if type(error) is urllib.error.URLError:
            error = error.reason
        return isinstance(error, OSError) and error.errno == errno.EPERM
    return False

try:
    if kind == "tcp":
        with socket.create_connection(("127.0.0.1", tcp_port), timeout=1) as client:
            client.sendall(("child-" + nonce).encode())
    elif kind == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(1)
            client.sendto(("child-" + nonce).encode(), ("127.0.0.1", udp_port))
            client.recvfrom(256)
    elif kind == "dns":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.sendto(b"synthetic-dns", ("127.0.0.1", 53))
    elif kind == "http":
        urllib.request.urlopen("http://127.0.0.1:" + str(http_port) + "/api/child-" + nonce, timeout=1).read(64)
    elif kind == "proxy":
        proxy = "http://127.0.0.1:" + str(http_port)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy}))
        opener.open("http://probe.invalid/proxy/child-" + nonce, timeout=1).read(64)
    elif kind == "redirect":
        urllib.request.urlopen("http://127.0.0.1:" + str(http_port) + "/redirect/child-" + nonce, timeout=1).read(64)
    elif kind == "ipc":
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(1)
            client.connect(ipc_path)
            client.sendall(("child-" + nonce).encode())
    elif kind == "socket-policy":
        _require_socket_policy()
        blocked = True
    elif kind == "file":
        with open(file_path, "rb") as source:
            source.read(64)
    elif kind == "environment":
        if "CONTROL_ENV_CANARY" in names or any(name.startswith(("GITHUB_", "ACTIONS_", "RUNNER_")) for name in names):
            raise RuntimeError("environment")
        allowed = ("PATH", "LANG", "LC_ALL", "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "PROBE_KIND", "PROBE_NONCE", "PROBE_TCP", "PROBE_UDP", "PROBE_DNS", "PROBE_HTTP", "PROBE_IPC", "PROBE_FILE")
        if any(name not in allowed for name in names):
            raise RuntimeError("environment")
        blocked = True
    elif kind == "process":
        if "CONTROL_ENV_CANARY" in names:
            raise RuntimeError("environment")
        _require_process_denials()
        blocked = True
    elif kind == "boundary":
        libc = ctypes.CDLL(None, use_errno=True)
        for flags in (0x10000000, 0x00020000 | 0x40000000 | 0x20000000 | 0x08000000):
            ctypes.set_errno(0)
            if libc.unshare(flags) == 0 or ctypes.get_errno() != errno.EPERM:
                raise RuntimeError("namespace")
        try:
            os.setuid(0)
            raise RuntimeError("setuid")
        except PermissionError:
            pass
        target = "/tmp/mount-target"
        os.mkdir(target)
        ctypes.set_errno(0)
        if libc.mount(b"tmpfs", target.encode(), b"tmpfs", 0, None) == 0 or ctypes.get_errno() != errno.EPERM:
            raise RuntimeError("mount")
        blocked = True
    else:
        raise RuntimeError("probe")
except (OSError, urllib.error.URLError) as error:
    blocked = _expected_denial(kind, error)
    if not blocked:
        raise RuntimeError("unexpected-denial")
if not blocked:
    raise RuntimeError("unexpected-access")
sys.stderr.write("::warning::synthetic-log-canary-" + nonce + "\\n")
sys.stdout.write("child-result=" + kind + ":denied\\n")
sys.stdout.flush()
sys.stderr.flush()
os.kill(os.getpid(), signal.SIGSTOP)
"""


def _expected_denial(kind, error):
    if kind == "file":
        return isinstance(error, OSError) and error.errno == errno.ENOENT
    if kind in ("tcp", "udp", "dns", "http", "proxy", "redirect", "ipc"):
        if type(error) is urllib.error.URLError:
            error = error.reason
        return isinstance(error, OSError) and error.errno == errno.EPERM
    return False


class Tripwires:
    def __init__(self, nonce, directory):
        self.nonce = nonce
        self.directory = directory
        self.events = []
        self.condition = threading.Condition()
        self.tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.tcp.bind(("127.0.0.1", 0))
        self.tcp.listen(16)
        self.tcp_port = self.tcp.getsockname()[1]
        self.udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.udp.bind(("127.0.0.1", 0))
        self.udp_port = self.udp.getsockname()[1]
        self.dns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.dns.bind(("127.0.0.1", 53))
        self.http = http.server.ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.http_port = self.http.server_address[1]
        self.ipc_path = os.path.join(directory, "socket-" + nonce)
        self.ipc = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.ipc.bind(self.ipc_path)
        self.ipc.listen(8)
        self.file_path = os.path.join(directory, "file-" + nonce)
        with open(self.file_path, "wb") as target:
            target.write(("outer-file-" + nonce).encode())
        self.threads = []
        self._start(self._tcp_loop)
        self._start(self._udp_loop)
        self._start(self._dns_loop)
        self._start(self.http.serve_forever)
        self._start(self._ipc_loop)

    def _record(self, value):
        with self.condition:
            self.events.append(value)
            self.condition.notify_all()

    def require(self, expected):
        deadline = time.monotonic() + 2
        with self.condition:
            while expected not in self.events:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProofFailure(42)
                self.condition.wait(remaining)

    def _start(self, target):
        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        self.threads.append(thread)

    def _tcp_loop(self):
        while True:
            try:
                client, _ = self.tcp.accept()
                with client:
                    self._record(client.recv(4096).decode("utf-8", "replace"))
            except OSError:
                return

    def _udp_loop(self):
        while True:
            try:
                data, address = self.udp.recvfrom(4096)
                self._record(data.decode("utf-8", "replace"))
                self.udp.sendto(b"live", address)
            except OSError:
                return

    def _dns_loop(self):
        while True:
            try:
                query, address = self.dns.recvfrom(512)
                self._record("dns:" + query.hex())
                if len(query) >= 17:
                    response = query[:2] + b"\x81\x80" + query[4:6] + b"\x00\x01\x00\x00\x00\x00" + query[12:] + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"
                    self.dns.sendto(response, address)
            except OSError:
                return

    def _ipc_loop(self):
        while True:
            try:
                client, _ = self.ipc.accept()
                with client:
                    self._record("ipc:" + client.recv(4096).decode("utf-8", "replace"))
            except OSError:
                return

    def _handler(self):
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, pattern, *args):
                return

            def do_GET(self):
                path = urllib.parse.urlsplit(self.path).path
                outer._record("http:" + path)
                if path.startswith("/redirect/"):
                    self.send_response(302)
                    self.send_header("Location", "http://127.0.0.1:" + str(outer.http_port) + "/sink/" + path.rsplit("/", 1)[-1])
                    self.end_headers()
                    return
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"live")

        return Handler

    def close(self):
        for item in (self.tcp, self.udp, self.dns, self.ipc):
            item.close()
        self.http.shutdown()
        self.http.server_close()


def _dns_query(name):
    labels = name.encode().split(b".")
    question = b"".join(bytes((len(label),)) + label for label in labels) + b"\x00\x00\x01\x00\x01"
    return b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question


def _positive_control(kind, services, canary):
    if kind == "tcp":
        with socket.create_connection(("127.0.0.1", services.tcp_port), timeout=1) as client:
            client.sendall(canary.encode())
        expected = canary
    elif kind == "udp":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(1)
            client.sendto(canary.encode(), ("127.0.0.1", services.udp_port))
            if client.recvfrom(256)[0] != b"live":
                raise ProofFailure(31)
        expected = canary
    elif kind == "dns":
        query = _dns_query("q-" + services.nonce + ".invalid")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(1)
            client.sendto(query, ("127.0.0.1", 53))
            response = client.recvfrom(512)[0]
        if response[:2] != query[:2] or response[2:4] != b"\x81\x80":
            raise ProofFailure(32)
        expected = "dns:" + query.hex()
    elif kind == "http":
        with urllib.request.urlopen("http://127.0.0.1:" + str(services.http_port) + "/api/" + canary, timeout=1) as response:
            if response.read(16) != b"live":
                raise ProofFailure(33)
        expected = "http:/api/" + canary
    elif kind == "proxy":
        proxy = "http://127.0.0.1:" + str(services.http_port)
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy}))
        with opener.open("http://probe.invalid/proxy/" + canary, timeout=1) as response:
            if response.read(16) != b"live":
                raise ProofFailure(34)
        expected = "http:/proxy/" + canary
    elif kind == "redirect":
        with urllib.request.urlopen("http://127.0.0.1:" + str(services.http_port) + "/redirect/" + canary, timeout=1) as response:
            if response.read(16) != b"live":
                raise ProofFailure(35)
        services.require("http:/redirect/" + canary)
        expected = "http:/sink/" + canary
    elif kind == "ipc":
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.connect(services.ipc_path)
            client.sendall(canary.encode())
        expected = "ipc:" + canary
    elif kind == "socket-policy":
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM):
            pass
        first, second = socket.socketpair()
        first.close()
        second.close()
        return
    elif kind == "file":
        with open(services.file_path, "rb") as source:
            if source.read() != ("outer-file-" + services.nonce).encode():
                raise ProofFailure(36)
        return
    elif kind == "environment":
        os.environ["CONTROL_ENV_CANARY"] = "outer-" + services.nonce
        if os.environ.get("CONTROL_ENV_CANARY") != "outer-" + services.nonce:
            raise ProofFailure(37)
        return
    elif kind == "process":
        os.environ["CONTROL_ENV_CANARY"] = "outer-" + services.nonce
        try:
            descriptors = os.listdir("/proc/self/fd")
        except OSError:
            raise ProofFailure(37)
        if os.environ.get("CONTROL_ENV_CANARY") != "outer-" + services.nonce or not descriptors:
            raise ProofFailure(37)
        return
    elif kind == "boundary":
        if os.geteuid() != 0:
            raise ProofFailure(38)
        if _read_sysctl("/proc/sys/kernel/yama/ptrace_scope") != "3":
            raise ProofFailure(39)
        if _read_sysctl("/proc/sys/user/max_user_namespaces") != "0":
            raise ProofFailure(40)
        return
    else:
        raise ProofFailure(41)
    services.require(expected)


def _read_sysctl(path):
    with open(path, "rt", encoding="ascii") as source:
        return source.read().strip()


def _set_sysctl(path, value):
    try:
        with open(path, "wt", encoding="ascii") as target:
            target.write(value)
        if _read_sysctl(path) != value:
            raise ProofFailure(43)
    except OSError:
        raise ProofFailure(44)


def _make_rootfs(rootfs):
    os.makedirs(rootfs, mode=0o700, exist_ok=True)
    _mount("tmpfs", rootfs, "tmpfs", MS_NOSUID | MS_NODEV, "size=128m")
    for relative in ("usr", "etc", "proc", "tmp", "capture"):
        os.makedirs(os.path.join(rootfs, relative), mode=0o755, exist_ok=True)
    os.chmod(rootfs, 0o555)
    _mount("/usr", os.path.join(rootfs, "usr"), None, MS_BIND | MS_REC)
    _mount(None, os.path.join(rootfs, "usr"), None, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_NOSUID | MS_NODEV)
    _mount("proc", os.path.join(rootfs, "proc"), "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC)
    _mount("tmpfs", os.path.join(rootfs, "tmp"), "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=8m")
    os.chmod(os.path.join(rootfs, "tmp"), 0o1777)
    os.chmod(os.path.join(rootfs, "capture"), 0o700)
    for name, value in (
        ("hosts", "127.0.0.1 localhost\n::1 localhost\n"),
        ("resolv.conf", "nameserver 127.0.0.1\noptions timeout:1 attempts:1\n"),
        ("nsswitch.conf", "hosts: files dns\n"),
    ):
        with open(os.path.join(rootfs, "etc", name), "wt", encoding="ascii") as target:
            target.write(value)
        os.chmod(os.path.join(rootfs, "etc", name), 0o444)
    for name, target in (("bin", "usr/bin"), ("lib", "usr/lib"), ("lib64", "usr/lib64")):
        link = os.path.join(rootfs, name)
        if not os.path.exists(link):
            os.symlink(target, link)
    if not os.path.exists(os.path.join(rootfs, "usr/bin/python3")):
        raise ProofFailure(45)
    return rootfs


def _verify_interfaces_down():
    interfaces = tuple(socket.if_nameindex())
    if tuple(name for _, name in interfaces) != ("lo",):
        raise ProofFailure(57)
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        request = struct.pack("16sH22x", b"lo", 0)
        flags = struct.unpack_from("16sH", fcntl.ioctl(probe.fileno(), SIOCGIFFLAGS, request))[1]
    finally:
        probe.close()
    if flags & IFF_UP:
        raise ProofFailure(58)
    return interfaces, flags


def _verify_proc_routes():
    with open("/proc/net/route", "rt", encoding="ascii") as source:
        route_data = source.read(65537)
    with open("/proc/net/ipv6_route", "rt", encoding="ascii") as source:
        route_data6 = source.read(65537)
    if len(route_data) > 65536 or len(route_data6) > 65536:
        raise ProofFailure(81)
    routes = tuple(line for line in route_data.splitlines()[1:] if line.strip())
    routes6 = tuple(line for line in route_data6.splitlines() if line.strip())
    if routes:
        raise ProofFailure(85)
    if routes6 and not all(_is_kernel_unreachable_ipv6_route(line) for line in routes6):
        raise ProofFailure(87)


def _require_empty_route_dump(probe, family, sequence, port_id):
    payload = struct.pack("=BBBBBBBBI", family, 0, 0, 0, 0, 0, 0, 0, 0)
    request = struct.pack("=IHHII", 16 + len(payload), RTM_GETROUTE, NLM_F_REQUEST | NLM_F_DUMP, sequence, port_id) + payload
    if probe.sendto(request, (0, 0)) != len(request):
        raise ProofFailure(86)
    data, ancillary, flags, sender = probe.recvmsg(MAX_ROUTE_DUMP_BYTES, 0)
    if ancillary or flags or sender != (0, 0) or len(data) != 20:
        raise ProofFailure(86)
    length, kind, message_flags, reply_sequence, recipient = struct.unpack_from("=IHHII", data)
    if (length, kind, message_flags, reply_sequence, recipient) != (20, NLMSG_DONE, NLM_F_MULTI, sequence, port_id):
        raise ProofFailure(86)
    if struct.unpack_from("=i", data, 16)[0] != 0:
        raise ProofFailure(86)


def _verify_netns():
    try:
        with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE) as probe:
            probe.settimeout(MAX_ROUTE_DUMP_SECONDS)
            probe.setsockopt(SOL_NETLINK, NETLINK_GET_STRICT_CHK, 1)
            probe.bind((0, ROUTE_CHANGE_GROUPS))
            port_id, groups = probe.getsockname()
            if not 0 < port_id <= 0xffffffff or groups != ROUTE_CHANGE_GROUPS:
                raise ProofFailure(86)
            interfaces = _verify_interfaces_down()
            _verify_proc_routes()
            for sequence, family in enumerate((socket.AF_INET, socket.AF_INET6), start=1):
                _require_empty_route_dump(probe, family, sequence, port_id)
            if _verify_interfaces_down() != interfaces:
                raise ProofFailure(86)
            probe.setblocking(False)
            try:
                probe.recvmsg(MAX_ROUTE_DUMP_BYTES, 0)
            except BlockingIOError as error:
                if error.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                    raise ProofFailure(86) from None
            else:
                raise ProofFailure(86)
    except (OSError, ValueError, struct.error):
        raise ProofFailure(86) from None


def _is_kernel_unreachable_ipv6_route(line):
    fields = line.split()
    if len(fields) != 10:
        return False
    destination, destination_bits, source, source_bits, gateway, metric, references, uses, flags, device = fields
    zero = "0" * 32
    return (
        destination == source == gateway == zero
        and destination_bits == source_bits == "00"
        and metric == "ffffffff"
        and re.fullmatch(r"[0-9a-f]{8}", references) is not None
        and re.fullmatch(r"[0-9a-f]{8}", uses) is not None
        and flags == "00200200"
        and device == "lo"
    )


def _write_capture(rootfs, name):
    path = os.path.join(rootfs, "capture", name)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o200)
    os.fchmod(descriptor, 0o200)
    reader = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    return path, descriptor, reader


def _enter_rootfs_and_launch(arguments, environment, out_writer, err_writer):
    source_path = "/probe.py"
    with open(source_path, "wt", encoding="utf-8") as target:
        target.write(CHILD_SOURCE)
    os.chmod(source_path, 0o444)
    return subprocess.Popen(
        ["/usr/bin/python3", "-B", source_path, arguments.probe, arguments.nonce, str(arguments.tcp), str(arguments.udp), str(arguments.dns), str(arguments.http), arguments.ipc, arguments.file],
        stdout=out_writer,
        stderr=err_writer,
        close_fds=True,
        cwd="/tmp",
        env=environment,
        preexec_fn=_drop_child,
        start_new_session=True,
    )


def _supervise_child_process(process, nonce):
    stage = "start"
    _wait_for_stopped_process(process.pid)
    stage = advance_supervision(stage, "parent-stopped")
    _verify_child(process.pid, nonce)
    _verify_process_set((1, process.pid))
    os.kill(process.pid, signal.SIGCONT)
    descendant = _wait_for_stopped_descendant(process.pid)
    stage = advance_supervision(stage, "descendant-stopped")
    _verify_child(descendant, nonce)
    _verify_process_set((1, process.pid, descendant))
    os.kill(descendant, signal.SIGKILL)
    _wait_for_process_state(descendant, "Z")
    stage = advance_supervision(stage, "descendant-killed")
    _verify_process_set((1, process.pid, descendant))
    _wait_for_stopped_process(process.pid)
    stage = advance_supervision(stage, "parent-stopped-again")
    _verify_child(process.pid, nonce)
    _verify_process_set((1, process.pid, descendant))
    os.kill(process.pid, signal.SIGCONT)
    stage = advance_supervision(stage, "parent-resumed")
    if process.wait(timeout=MAX_PROBE_SECONDS) != 0:
        raise ProofFailure(51)
    stage = advance_supervision(stage, "parent-exited")
    _verify_process_set((1, descendant))
    if _children(1) != (descendant,):
        raise ProofFailure(79)
    reaped, status = os.waitpid(-1, os.WNOHANG)
    if reaped != descendant or not os.WIFSIGNALED(status):
        raise ProofFailure(75)
    stage = advance_supervision(stage, "descendant-reaped")
    if stage != "complete":
        raise ProofFailure(76)
    _verify_process_set((1,))
    return stage


def _inside(arguments):
    if os.geteuid() != 0:
        raise ProofFailure(46)
    _prctl(PR_SET_CHILD_SUBREAPER, 1)
    if os.stat("/proc/self/ns/net").st_ino == int(os.environ["CONTROL_NETNS"]):
        raise ProofFailure(47)
    _verify_netns()
    for name, port in (("tcp", arguments.tcp), ("udp", arguments.udp), ("http", arguments.http)):
        if port < 1 or port > 65535:
            raise ProofFailure(48)
    rootfs = _make_rootfs(arguments.rootfs)
    out_path, out_writer, out_reader = _write_capture(rootfs, "out-" + arguments.nonce)
    err_path, err_writer, err_reader = _write_capture(rootfs, "err-" + arguments.nonce)
    os.chroot(rootfs)
    os.chdir("/tmp")
    environment = {
        "PATH": "/usr/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PROBE_KIND": arguments.probe,
        "PROBE_NONCE": arguments.nonce,
        "PROBE_TCP": str(arguments.tcp),
        "PROBE_UDP": str(arguments.udp),
        "PROBE_DNS": str(arguments.dns),
        "PROBE_HTTP": str(arguments.http),
        "PROBE_IPC": arguments.ipc,
        "PROBE_FILE": arguments.file,
    }
    process = _enter_rootfs_and_launch(arguments, environment, out_writer, err_writer)
    os.close(out_writer)
    os.close(err_writer)
    try:
        _supervise_child_process(process, arguments.nonce)
    except Exception:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except OSError:
            pass
        raise
    finally:
        os.lseek(out_reader, 0, os.SEEK_SET)
        stdout = os.read(out_reader, MAX_CAPTURE + 1)
        os.lseek(err_reader, 0, os.SEEK_SET)
        stderr = os.read(err_reader, MAX_CAPTURE + 1)
        os.close(out_reader)
        os.close(err_reader)
    expected = ("child-result=" + arguments.probe + ":denied\n").encode()
    log_canary = ("::warning::synthetic-log-canary-" + arguments.nonce + "\n").encode()
    if len(stdout) > MAX_CAPTURE or len(stderr) > MAX_CAPTURE:
        raise ProofFailure(52)
    if expected not in stdout or log_canary not in stderr:
        raise ProofFailure(53)
    return "inner=accepted probe=" + arguments.probe + "\n"


def _run_probe(kind, services, nonce, rootfs, control_sha):
    canary = "outer-" + nonce + "-" + kind
    child_canary = "child-" + nonce
    _positive_control(kind, services, canary)
    environment = {
        "PATH": "/usr/bin:/bin",
        "LANG": "C",
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "CONTROL_NETNS": str(os.stat("/proc/self/ns/net").st_ino),
        "CONTROL_ENV_CANARY": "outer-" + nonce,
    }
    command = [
        shutil.which("unshare") or "/usr/bin/unshare",
        *UNSHARE_ARGUMENTS,
        "--",
        sys.executable,
        "-B",
        str(pathlib.Path(__file__).resolve()),
        "--inside",
        "--control-sha",
        control_sha,
        "--probe",
        kind,
        "--nonce",
        nonce,
        "--rootfs",
        rootfs,
        "--tcp",
        str(services.tcp_port),
        "--udp",
        str(services.udp_port),
        "--dns",
        "53",
        "--http",
        str(services.http_port),
        "--ipc",
        services.ipc_path,
        "--file",
        services.file_path,
    ]
    try:
        result = subprocess.run(command, env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=MAX_PROBE_SECONDS + 5, check=False, close_fds=True)
    except (OSError, subprocess.TimeoutExpired):
        raise ProofFailure(54)
    expected = ("inner=accepted probe=" + kind + "\n").encode()
    if result.returncode != 0:
        if result.returncode == 1 and result.stderr == b"" and len(result.stdout) <= MAX_INNER_REFUSAL_BYTES:
            inner_reason = INNER_REFUSAL_LINES.get(result.stdout)
            if inner_reason is not None:
                raise ProofFailure(inner_reason)
        raise ProofFailure(82)
    if result.stdout != expected:
        raise ProofFailure(83)
    if result.stderr:
        raise ProofFailure(84)
    _positive_control(kind, services, "check-" + nonce + "-" + kind)
    with services.condition:
        if any(child_canary in event or ("q-child-" + nonce).encode().hex() in event for event in services.events):
            raise ProofFailure(56)
    return True


def _prepare_kernel():
    if os.geteuid() != 0:
        raise ProofFailure(60)
    _set_sysctl("/proc/sys/kernel/yama/ptrace_scope", "3")
    _set_sysctl("/proc/sys/user/max_user_namespaces", "0")
    clone_toggle = "/proc/sys/kernel/unprivileged_userns_clone"
    if os.path.exists(clone_toggle):
        _set_sysctl(clone_toggle, "0")
    if _read_sysctl("/proc/sys/kernel/yama/ptrace_scope") != "3":
        raise ProofFailure(61)
    if _read_sysctl("/proc/sys/user/max_user_namespaces") != "0":
        raise ProofFailure(62)


def _outer(control_sha):
    if not valid_sha(control_sha):
        raise ProofFailure(63)
    try:
        git = subprocess.run(["git", "rev-parse", "--verify", "HEAD"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3, check=True, close_fds=True)
    except (OSError, subprocess.SubprocessError):
        raise ProofFailure(64)
    if git.stdout.decode("ascii", "strict").strip() != control_sha:
        raise ProofFailure(65)
    _prepare_kernel()
    nonce = os.urandom(12).hex()
    with tempfile.TemporaryDirectory(prefix="linux-probe-") as directory:
        services = Tripwires(nonce, directory)
        try:
            for kind in PROBES:
                rootfs = os.path.join(directory, "root-" + kind)
                os.mkdir(rootfs, 0o700)
                _run_probe(kind, services, nonce, rootfs, control_sha)
        except OSError:
            raise ProofFailure(66)
        finally:
            services.close()
    return outcome(True, 0, control_sha)


def main():
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--control-sha")
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--probe")
    parser.add_argument("--nonce")
    parser.add_argument("--rootfs")
    parser.add_argument("--tcp", type=int)
    parser.add_argument("--udp", type=int)
    parser.add_argument("--dns", type=int)
    parser.add_argument("--http", type=int)
    parser.add_argument("--ipc")
    parser.add_argument("--file")
    arguments = parser.parse_args()
    try:
        if arguments.inside:
            if arguments.probe not in PROBES or not re.fullmatch(r"[a-f0-9]{24}", arguments.nonce or ""):
                raise ProofFailure(67)
            result = _inside(arguments)
            sys.stdout.write(result)
            return 0
        sys.stdout.write(_outer(arguments.control_sha) + "\n")
        return 0
    except ProofFailure as failure:
        if arguments.inside:
            sys.stdout.write("inner=refused reason=" + str(failure.reason) + "\n")
        else:
            sys.stdout.write(outcome(False, failure.reason) + "\n")
        return 1
    except Exception:
        if arguments.inside:
            sys.stdout.write("inner=refused reason=98\n")
        else:
            sys.stdout.write(outcome(False, 99) + "\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
