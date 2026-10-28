LAUNCHER_SOURCE = """
import os
import signal
import sys

os.kill(os.getpid(), signal.SIGSTOP)
os.execv(sys.argv[1], sys.argv[1:])
"""

PREAMBLE = """
import ctypes
import errno
import json
import os
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request

NL = chr(10)
CRLF = chr(13) + chr(10)
channel = sys.argv[1]
cfg = json.loads(sys.argv[2])
nonce = cfg["nonce"]
ports = cfg.get("ports", {})
NET_DENIED = (errno.EPERM, errno.EACCES)
FS_DENIED = (errno.EPERM, errno.EACCES, errno.ENOENT, errno.ENXIO, errno.ENODEV, errno.ENOTDIR, errno.EROFS)
BOUNDARY_DENIED = (errno.EPERM, errno.EACCES, errno.EINVAL, errno.ENOSPC)
GAI_DENIED = (socket.EAI_AGAIN, socket.EAI_FAIL, socket.EAI_NONAME, socket.EAI_SYSTEM)
libc = ctypes.CDLL(None, use_errno=True)


def refused(error, accepted):
    if isinstance(error, urllib.error.URLError) and isinstance(error.reason, BaseException):
        error = error.reason
    if isinstance(error, ssl.SSLError):
        return False
    if isinstance(error, socket.gaierror):
        return error.errno in GAI_DENIED
    if isinstance(error, OSError):
        return error.errno in accepted
    return False


def attempt(name, action, accepted=NET_DENIED, contained=False, optional=False):
    try:
        action()
    except FileNotFoundError as error:
        if optional:
            result = "na"
        else:
            result = "denied" if refused(error, accepted) else "other"
    except BaseException as error:
        result = "denied" if refused(error, accepted) else "other"
    else:
        result = "contained" if contained else "allowed"
    sys.stdout.write("KDATT " + name + " " + result + NL)
    sys.stdout.flush()


def closed():
    raise OSError(errno.EPERM, "closed")


def raise_errno():
    code = ctypes.get_errno()
    raise OSError(code, os.strerror(code))


def tls(host, port, label):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection((host, port), timeout=1)
    try:
        context.wrap_socket(raw, server_hostname=label + "-" + nonce + ".example.invalid")
    finally:
        raw.close()


def dns_query(label):
    header = bytes((0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0))
    name = b"".join(bytes((len(part),)) + part for part in label.encode().split(b"."))
    return header + name + bytes((0, 0, 1, 0, 1))


def fetch(url):
    urllib.request.urlopen(url, timeout=1).read(64)


"""

PROBE_BODY = """

def run_https():
    attempt("tls-ipv4", lambda: tls("127.0.0.1", ports["https4"], "v4"))
    attempt("tls-ipv6", lambda: tls("::1", ports.get("https6", 9), "v6"))
    attempt("tls-hostname", lambda: tls("tripwire.invalid", ports["https4"], "host"))


def run_dns():
    def udp():
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1)
            sock.sendto(dns_query("r-" + nonce + ".example.invalid"), ("127.0.0.1", ports["dns_udp"]))

    def tcp():
        query = dns_query("t-" + nonce + ".example.invalid")
        with socket.create_connection(("127.0.0.1", ports["dns_tcp"]), timeout=1) as sock:
            sock.sendall(bytes((len(query) >> 8, len(query) & 255)) + query)

    attempt("getaddrinfo", lambda: socket.getaddrinfo("g-" + nonce + ".example.invalid", 80))
    attempt("udp-query", udp)
    attempt("tcp-query", tcp)


def run_redirect():
    attempt("http-redirect", lambda: fetch("http://127.0.0.1:%d/redirect/x-%s" % (ports["redirect_a"], nonce)))


def run_proxy():
    def through_environment():
        proxy = "http://127.0.0.1:%d" % ports["proxy"]
        for name in ("http_proxy", "HTTP_PROXY", "https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
            os.environ[name] = proxy
        fetch("http://proxy-target.example.invalid/p-" + nonce)

    def connect():
        with socket.create_connection(("127.0.0.1", ports["proxy"]), timeout=1) as sock:
            sock.sendall(("CONNECT c-" + nonce + ".example.invalid:443 HTTP/1.1" + CRLF + CRLF).encode())

    attempt("proxy-env-http", through_environment)
    attempt("proxy-connect", connect)


def run_runner_ipc():
    def unix_path():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect(cfg["unix_path"])
            sock.sendall(("u-" + nonce).encode())

    def unix_abstract():
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(1)
            sock.connect(chr(0) + cfg["abstract_name"])
            sock.sendall(("a-" + nonce).encode())

    def inventory():
        leaked = []
        for number in range(3, 256):
            try:
                os.fstat(number)
            except OSError:
                continue
            leaked.append(number)
        if not leaked:
            closed()

    attempt("unix-path", unix_path)
    attempt("unix-abstract", unix_abstract)
    attempt("fd-inventory", inventory)


def run_raw_logs():
    def markers():
        sys.stdout.write("::error::kd-log-" + nonce + NL)
        sys.stderr.write("::set-output name=kd::kd-log-" + nonce + NL)
        sys.stdout.flush()
        sys.stderr.flush()

    def terminal():
        for path in ("/dev/tty", "/dev/console"):
            with open(path, "w") as target:
                target.write("kd-log-" + nonce + NL)

    def datagram(path):
        def action():
            with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as sock:
                sock.connect(path)
                sock.send(("kd-log-" + nonce).encode())
        return action

    attempt("stdout-markers", markers, contained=True)
    attempt("tty-open", terminal, accepted=FS_DENIED)
    attempt("syslog-socket", datagram("/dev/log"))
    attempt("journal-socket", datagram("/run/systemd/journal/socket"))


def hunt():
    names = [name for name in os.environ if name.startswith(("ACTIONS_", "GITHUB_", "RUNNER_"))]
    if not names:
        closed()


def upload(port_name, variable, path, tag):
    def action():
        base = "http://127.0.0.1:%d/" % ports[port_name]
        os.environ[variable] = base
        os.environ["ACTIONS_RUNTIME_TOKEN"] = "tripwire-token-" + nonce
        request = urllib.request.Request(
            base + path + "?n=" + tag + "-" + nonce,
            data=("payload-" + tag + "-" + nonce).encode(),
            headers={"Authorization": "Bearer tripwire-token-" + nonce},
            method="POST",
        )
        urllib.request.urlopen(request, timeout=1).read(64)
    return action


def stage(directory, name):
    def action():
        os.makedirs(directory, exist_ok=True)
        with open(directory + "/" + name + "-" + nonce + ".bin", "wb") as target:
            target.write(bytes(1024))
    return action


def run_artifact_upload():
    attempt("env-hunt", hunt)
    attempt("endpoint-post", upload("artifact", "ACTIONS_RESULTS_URL", "twirp/github.actions.results.api.v1.ArtifactService/CreateArtifact", "art"))
    attempt("staging-write", stage("/tmp/staging", "artifact"), contained=True)


def run_cache_upload():
    attempt("env-hunt", hunt)
    attempt("endpoint-post", upload("cache", "ACTIONS_CACHE_URL", "_apis/artifactcache/caches", "cache"))
    attempt("cache-write", stage("/tmp/cache", "cache"), contained=True)


def check(result):
    if result != 0:
        raise_errno()


def run_boundary_disablement():
    def setuid_root():
        os.setuid(0)

    def unshare(flags):
        return lambda: check(libc.unshare(flags))

    def mount_tmpfs():
        os.mkdir("/tmp/mount-target")
        ctypes.set_errno(0)
        check(libc.mount(b"tmpfs", b"/tmp/mount-target", b"tmpfs", 0, None))

    def remount_usr():
        ctypes.set_errno(0)
        check(libc.mount(None, b"/usr", None, 32 | 4096, None))

    def sysctl():
        path = "/proc/sys/kernel/yama/ptrace_scope"
        with open(path) as source:
            value = source.read().strip()
        with open(path, "w") as target:
            target.write(value)

    def signal_init():
        os.kill(1, 0)

    def escape():
        os.chroot("/")

    def clear_no_new_privs():
        ctypes.set_errno(0)
        check(libc.prctl(38, 0, 0, 0, 0))

    def command(arguments):
        def action():
            done = subprocess.run(
                arguments,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
            if done.returncode != 0:
                closed()
        return action

    attempt("setuid-root", setuid_root, accepted=BOUNDARY_DENIED)
    attempt("unshare-user", unshare(0x10000000), accepted=BOUNDARY_DENIED)
    attempt("unshare-namespaces", unshare(0x00020000 | 0x40000000 | 0x20000000 | 0x08000000), accepted=BOUNDARY_DENIED)
    attempt("mount-tmpfs", mount_tmpfs, accepted=BOUNDARY_DENIED)
    attempt("usr-remount-rw", remount_usr, accepted=BOUNDARY_DENIED)
    attempt("sysctl-write", sysctl, accepted=BOUNDARY_DENIED)
    attempt("signal-init", signal_init, accepted=BOUNDARY_DENIED)
    attempt("chroot-escape", escape, accepted=BOUNDARY_DENIED)
    attempt("nnp-clear", clear_no_new_privs, accepted=BOUNDARY_DENIED)
    attempt("sudo", command(["/usr/bin/sudo", "-n", "true"]), accepted=BOUNDARY_DENIED, optional=True)
    attempt("docker", command(["/usr/bin/docker", "version"]), accepted=BOUNDARY_DENIED, optional=True)
    attempt("ip-link", command(["/usr/sbin/ip", "link", "set", "lo", "up"]), accepted=BOUNDARY_DENIED, optional=True)
    attempt("nsenter", command(["/usr/bin/nsenter", "-t", "1", "-n", "true"]), accepted=BOUNDARY_DENIED, optional=True)


class Iov(ctypes.Structure):
    _fields_ = (("base", ctypes.c_void_p), ("length", ctypes.c_size_t))


def each_target(action):
    reached = False
    last = None
    for pid in cfg["targets"]:
        try:
            action(pid)
            reached = True
        except OSError as error:
            last = error
    if not reached:
        raise last if last is not None else OSError(errno.EPERM, "closed")


def read_proc(name):
    def action(pid):
        with open("/proc/%d/%s" % (pid, name), "rb") as source:
            source.read(1)
    return action


def trace(pid):
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = (ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p)
    ctypes.set_errno(0)
    if libc.ptrace(16, pid, None, None) != 0:
        raise_errno()
    libc.ptrace(17, pid, None, None)


def vm_read(pid):
    buffer = ctypes.create_string_buffer(8)
    local = Iov(ctypes.cast(buffer, ctypes.c_void_p), 8)
    remote = Iov(0x400000, 8)
    ctypes.set_errno(0)
    done = libc.syscall(
        ctypes.c_long(310),
        ctypes.c_long(pid),
        ctypes.byref(local),
        ctypes.c_long(1),
        ctypes.byref(remote),
        ctypes.c_long(1),
        ctypes.c_long(0),
    )
    if done < 0:
        raise_errno()


def self_memory():
    marker = ("ctl-" + nonce).encode()
    buffer = ctypes.create_string_buffer(marker)
    with open("/proc/self/mem", "rb", buffering=0) as source:
        source.seek(ctypes.addressof(buffer))
        if source.read(len(marker)) != marker:
            closed()


def peer_environ():
    with open("/proc/%d/environ" % cfg["helper"], "rb") as source:
        if ("kd-control-environ-" + nonce).encode() not in source.read(65536):
            closed()


def run_process_memory():
    attempt("mem-read", lambda: each_target(read_proc("mem")))
    attempt("environ-read", lambda: each_target(read_proc("environ")))
    attempt("ptrace-attach", lambda: each_target(trace))
    attempt("process-vm-readv", lambda: each_target(vm_read))
    attempt("control-self-memory", self_memory)
    attempt("control-peer-environ", peer_environ)


HANDLERS = {
    "https": run_https,
    "dns": run_dns,
    "redirect": run_redirect,
    "proxy": run_proxy,
    "runner_ipc": run_runner_ipc,
    "raw_logs": run_raw_logs,
    "artifact_upload": run_artifact_upload,
    "cache_upload": run_cache_upload,
    "boundary_disablement": run_boundary_disablement,
    "process_memory": run_process_memory,
}
HANDLERS[channel]()
"""

PROBE_SOURCE = PREAMBLE + PROBE_BODY
