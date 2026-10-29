"""Hosted-only deny-default Seatbelt proof for the macOS control job."""

import base64
import argparse
import errno
import hashlib
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import re
import selectors
import shutil
import signal
import socket
import socketserver
import ssl
import stat
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import quote

def _load_control_sibling(module_name):
    if type(module_name) is not str or module_name not in {"macos_capability", "macos_boundary_guard"}:
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


_BOOTSTRAP_OK = True
try:
    _CONTROL_DIRECTORY = Path(__file__).resolve(strict=True).parent
    if not _CONTROL_DIRECTORY.is_dir():
        raise ImportError("control directory unavailable")
    capability = _load_control_sibling("macos_capability")
except BaseException:
    _CONTROL_DIRECTORY = Path("/")
    capability = None
    boundary_guard = None
    _BOOTSTRAP_OK = False
else:
    try:
        boundary_guard = _load_control_sibling("macos_boundary_guard")
    except BaseException:
        boundary_guard = None


CHANNELS = (
    "https",
    "dns",
    "redirect",
    "proxy",
    "runner_ipc",
    "raw_logs",
    "artifact_upload",
    "cache_upload",
    "runner_files",
    "process_memory",
    "boundary_disablement",
)
CONTROL_SHA = re.compile(r"[a-f0-9]{40}\Z")
APPROVED_MACOS_PRODUCT_VERSION = "15.7.9"
APPROVED_IMAGE_OS_VALUE = "macos15"
APPROVED_RUNNER_IMAGE_OS = "macos-15-arm64"
APPROVED_RUNNER_IMAGE_VERSION = "20260907.0337.1"
APPROVED_HOST_RELEASES = (
    (APPROVED_MACOS_PRODUCT_VERSION, APPROVED_RUNNER_IMAGE_VERSION),
    ("15.8.2", "20261028.0489.1"),
)
APPROVED_HOST_RELEASE_FIRST_RUNS = {("15.8.2", "20261028.0489.1"): "40941660825"}
APPROVED_ARCH = "arm64"
PF_ANCHOR = "com.apple/ci-probe"
CANARY_PREFIX = b"KD-MACOS-CI-CANARY-v1:"
CANARY_DOMAIN = b"keeldock" + b"-macos-ci-canary-v1\0"
WORKFLOW_MARKERS = (
    b"::error file=canary.txt,line=1::",
    b"::warning::",
    b"::add-mask::",
    b"::set-output name=leak::",
    b"::group::",
    b"::endgroup::",
)
MAX_CHILD_SECONDS = 300
MAX_RECEIPT_BYTES = 16384
DENIED_ERRNOS = frozenset((errno.EPERM, errno.EACCES))
STAGES = frozenset((
    "preflight", "platform", "context", "toolchain", "developer_mode", "runner_controls",
    "probe_identity", "profile", "positive_build", "profile_selftest", "network_positive",
    "memory_positive", "ipc_positive", "log_positive", "walk", "seatbelt_channels", "pf_only",
    "pf_channels", "receipt", "output", "cleanup",
))
REFUSAL_REASONS = frozenset((
    "invalid_control_identity", "native_preflight_unavailable", "macos_version_unapproved",
    "sandbox_selftest_failed", "pf_unavailable", "channel_not_blocked", "positive_control_failed",
    "probe_identity_unavailable", "boundary_disablement", "cleanup_incomplete",
))


class Refusal(Exception):
    def __init__(self, reason, *, stage="preflight", channel=None):
        self.reason = reason if type(reason) is str and reason in REFUSAL_REASONS else "native_preflight_unavailable"
        self.stage = stage if type(stage) is str and stage in STAGES else "preflight"
        self.channel = channel if type(channel) is str and channel in CHANNELS else None
        super().__init__(self.reason)


def refusal_line(error):
    if type(error) is not Refusal:
        error = Refusal("native_preflight_unavailable")
    values = [
        "macos-confinement=refused",
        "reason=" + error.reason,
        "stage=" + error.stage,
    ]
    if error.channel is not None:
        values.append("channel=" + error.channel)
    return " ".join(values)


def canary_bytes(control_sha):
    if type(control_sha) is not str or CONTROL_SHA.fullmatch(control_sha) is None:
        raise Refusal("invalid_control_identity")
    digest = hashlib.sha256(CANARY_DOMAIN + control_sha.encode("ascii")).hexdigest()[:32].encode("ascii")
    return CANARY_PREFIX + digest


def _safe_env(home=None):
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}
    if home is not None:
        environment["HOME"] = str(home)
    return environment


def _command(argv, *, env=None, timeout=15, input_bytes=None):
    try:
        result = subprocess.run(
            [str(part) for part in argv],
            env=_safe_env() if env is None else env,
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            close_fds=True,
        )
    except (OSError, subprocess.SubprocessError):
        raise Refusal("native_preflight_unavailable") from None
    if len(result.stdout) > 65536 or len(result.stderr) > 65536:
        raise Refusal("native_preflight_unavailable")
    return result


def _trusted_root_path(path, *, executable=False, directory=False):
    try:
        requested = Path(path)
        if not requested.is_absolute() or ".." in requested.parts:
            raise ValueError
        resolved = requested.resolve(strict=True)
        if resolved.as_posix() != requested.as_posix():
            raise ValueError
        parts = (Path(resolved.anchor),) + tuple(resolved.parents)[-2::-1]
        for component in parts:
            metadata = component.lstat()
            if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0:
                raise ValueError
            if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
                raise ValueError
        metadata = resolved.lstat()
        if metadata.st_uid != 0 or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ValueError
        if directory and not stat.S_ISDIR(metadata.st_mode):
            raise ValueError
        if executable and (
            not stat.S_ISREG(metadata.st_mode)
            or not metadata.st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
            or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID)
        ):
            raise ValueError
        return resolved
    except BaseException:
        raise Refusal("native_preflight_unavailable") from None


def _quote_profile_path(path):
    value = str(path)
    semantic = PurePosixPath(value)
    if (
        not semantic.is_absolute()
        or semantic.as_posix() != value
        or ".." in semantic.parts
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        or len(value.encode("utf-8")) > 4096
    ):
        raise Refusal("native_preflight_unavailable")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def profile_text(workspace, storage, toolchain):
    workspace = Path(workspace).resolve(strict=True)
    storage = Path(storage).resolve(strict=True)
    developer = Path(toolchain["developer_directory"]).resolve(strict=True)
    sdk = Path(toolchain["sdk"]).resolve(strict=True)
    read_directories = {
        "/System/Library",
        "/System/Volumes/Preboot/Cryptexes/OS",
        "/usr/lib",
        "/usr/share",
        "/usr/bin",
        "/bin",
        str(developer),
        str(sdk),
        str(workspace),
        str(storage),
    }
    if toolchain.get("control_kit"):
        read_directories.add(str(Path(toolchain["control_kit"]).resolve(strict=True)))
    exec_directories = {
        "/usr/bin",
        "/bin",
        str(developer),
        str(sdk),
    }
    read_rules = [
        "(allow file-read* (subpath " + _quote_profile_path(path) + "))"
        for path in sorted(read_directories)
    ]
    exec_rules = [
        "(allow process-exec (subpath " + _quote_profile_path(path) + "))"
        for path in sorted(exec_directories)
    ]
    sysctl_names = (
        "hw.machine",
        "hw.ncpu",
        "hw.pagesize",
        "kern.ostype",
        "kern.osrelease",
        "kern.osversion",
    )
    lines = [
        "(version 1)",
        "(deny default)",
        "(allow process-fork)",
        "(deny network*)",
        "(deny mach-lookup)",
        "(deny mach-register)",
        "(deny ipc-posix-shm)",
        "(deny ipc-posix-sem)",
        "(deny iokit-open)",
        "(allow signal (target same-sandbox))",
        *exec_rules,
        *read_rules,
        '(allow file-read* (literal "/dev/null") (literal "/dev/urandom"))',
        "(allow file-write* (subpath " + _quote_profile_path(storage) + ") "
        + '(literal "/dev/null") (literal "/dev/dtracehelper"))',
        "(allow file-map-executable (literal "
        + _quote_profile_path(storage / "positive-build.dylib") + "))",
        "(allow sysctl-read"
        + "".join(' (sysctl-name "' + name + '")' for name in sysctl_names)
        + ")",
    ]
    return "\n".join(lines) + "\n"


def _write_profile(directory, workspace, storage, toolchain):
    target = Path(directory) / "deny-default.sb"
    payload = profile_text(workspace, storage, toolchain).encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(target, flags, 0o444)
        try:
            if os.write(descriptor, payload) != len(payload):
                raise OSError("short write")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        metadata = target.lstat()
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) != 0o444:
            raise OSError("profile ownership")
    except BaseException:
        try:
            target.unlink()
        except OSError:
            pass
        raise Refusal("native_preflight_unavailable") from None
    return target


def _run_profile_selftest(sandbox_exec, profile, python, storage, outside_write, outside_read, uid, home, policy):
    script = r'''import errno, json, os, signal, socket, sys, time
storage, outside_write, outside_read = sys.argv[1:]
results = {}
try:
    with open(os.path.join(storage, "selftest-positive"), "wb") as stream:
        stream.write(b"ok")
    results["write_storage"] = True
except OSError:
    results["write_storage"] = False
try:
    with open(outside_write, "wb") as stream:
        stream.write(b"no")
    results["write_outside"] = False
except OSError as error:
    results["write_outside"] = error.errno in (errno.EACCES, errno.EPERM)
try:
    with open(outside_read, "rb") as stream:
        stream.read(1)
    results["read_outside"] = False
except OSError as error:
    results["read_outside"] = error.errno in (errno.EACCES, errno.EPERM)
try:
    socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    results["network"] = False
except OSError as error:
    results["network"] = error.errno in (errno.EACCES, errno.EPERM)
try:
    child = os.fork()
    if child == 0:
        time.sleep(3)
        os._exit(0)
    os.kill(child, signal.SIGTERM)
    _, status = os.waitpid(child, 0)
    results["fork"] = os.WIFSIGNALED(status) and os.WTERMSIG(status) == signal.SIGTERM
except OSError:
    results["fork"] = False
print("KD-SELFTEST:" + json.dumps(results, sort_keys=True, separators=(",", ":")))
'''
    result = _run_confined(
        [sandbox_exec, "-f", profile, python, "-I", "-S", "-B", "-c", script,
         str(storage), str(outside_write), str(outside_read)],
        uid,
        env=_safe_env(home),
        python=python,
        storage=storage,
        policy=policy,
        timeout=20,
        refusal="sandbox_selftest_failed",
    )
    if result.returncode != 0 or result.stderr:
        raise Refusal("sandbox_selftest_failed")
    lines = result.stdout.splitlines()
    evidence = [line[len(b"KD-SELFTEST:"):] for line in lines if line.startswith(b"KD-SELFTEST:")]
    if len(evidence) != 1:
        raise Refusal("sandbox_selftest_failed")
    try:
        values = json.loads(evidence[0].decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        raise Refusal("sandbox_selftest_failed") from None
    if values != {
        "fork": True,
        "network": True,
        "read_outside": True,
        "write_outside": True,
        "write_storage": True,
    }:
        raise Refusal("sandbox_selftest_failed")
    return True


class _ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class _IPv6ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    address_family = socket.AF_INET6
    allow_reuse_address = True
    daemon_threads = True


class _IPv6UdpServer(socketserver.UDPServer):
    address_family = socket.AF_INET6


class _TripwireState:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []
        self.tls = []
        self.dns = []

    def record(self, category, payload):
        with self.lock:
            getattr(self, category).append(bytes(payload))

    def counts(self):
        with self.lock:
            return {"requests": len(self.requests), "tls": len(self.tls), "dns": len(self.dns)}

    def additions(self, before):
        with self.lock:
            return {
                "requests": tuple(self.requests[before["requests"]:]),
                "tls": tuple(self.tls[before["tls"]:]),
                "dns": tuple(self.dns[before["dns"]:]),
            }


def _tripwire_channel(state, before):
    additions = state.additions(before)
    if additions["dns"]:
        return "dns"
    if additions["tls"]:
        return "https"
    for request in additions["requests"]:
        line = request.split(b"\r\n", 1)[0].lower()
        if line.startswith(b"connect "):
            return "proxy"
        if b"/_apis/artifacts/" in line:
            return "artifact_upload"
        if b"/_apis/cache/" in line:
            return "cache_upload"
        if b"/redirect/" in line:
            return "redirect"
        return "https"
    return None


class _HttpHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            first = self.rfile.readline(8192)
            headers = bytearray(first)
            while len(headers) <= 16384:
                line = self.rfile.readline(4096)
                if not line or line in (b"\r\n", b"\n"):
                    break
                headers.extend(line)
            self.server.state.record("requests", bytes(headers))
            if first.startswith(b"CONNECT "):
                body = b"proxy tripwire\n"
                self.wfile.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: " + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            elif b"/redirect/" in first:
                self.wfile.write(
                    b"HTTP/1.1 302 Found\r\nLocation: "
                    + self.server.redirect_target.encode("ascii")
                    + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                )
            else:
                self.wfile.write(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
        except (OSError, ValueError):
            return


class _TlsHandler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(2)
        try:
            payload = self.request.recv(8192)
            if payload:
                self.server.state.record("tls", payload)
        except OSError:
            return


class _DnsHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            query, transport = self.request
            self.server.state.record("dns", query[:4096])
            question_end = query.find(b"\0", 12)
            if len(query) >= 17 and question_end >= 0 and len(query) >= question_end + 5:
                question = query[12:question_end + 5]
                qtype = int.from_bytes(query[question_end + 1:question_end + 3], "big")
                if qtype == 1:
                    answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"
                elif qtype == 28:
                    answer = b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x00\x3c\x00\x10" + b"\x00" * 15 + b"\x01"
                else:
                    answer = b""
                answer_count = b"\x00\x01" if answer else b"\x00\x00"
                response = (
                    query[:2] + b"\x81\x80\x00\x01" + answer_count + b"\x00\x00\x00\x00"
                    + question + answer
                )
                transport.sendto(response, self.client_address)
        except BaseException:
            return


class _Tripwires:
    def __init__(self, canary, certificate, private_key):
        self.state = _TripwireState()
        self.servers = []
        self.threads = []
        self.canary = canary.decode("ascii")
        self.redirect_target = None
        self.http_port = None
        self.tls4_port = None
        self.tls6_port = None
        self.dns4 = None
        self.dns6 = None

    def __enter__(self):
        handler = type("HttpHandler", (_HttpHandler,), {})
        self.http = _ThreadedServer(("127.0.0.1", 0), handler)
        self.http.state = self.state
        self.http_port = self.http.server_address[1]
        self.http.redirect_target = "http://127.0.0.1:%d/target/%s" % (self.http_port, quote(self.canary))
        self.redirect_target = self.http.redirect_target
        tls_handler = type("TlsHandler", (_TlsHandler,), {})
        self.tls4 = _ThreadedServer(("127.0.0.1", 0), tls_handler)
        self.tls4.state = self.state
        self.tls4_port = self.tls4.server_address[1]
        self.tls6 = _IPv6ThreadedServer(("::1", 0), tls_handler)
        self.tls6.state = self.state
        self.tls6_port = self.tls6.server_address[1]
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.load_cert_chain(str(certificate), str(private_key))
        self.tls4.socket = tls_context.wrap_socket(self.tls4.socket, server_side=True)
        self.tls6.socket = tls_context.wrap_socket(self.tls6.socket, server_side=True)
        dns_handler = type("DnsHandler", (_DnsHandler,), {})
        self.dns4 = socketserver.UDPServer(("127.0.0.1", 53), dns_handler)
        self.dns4.state = self.state
        self.dns6 = _IPv6UdpServer(("::1", 53), dns_handler)
        self.dns6.state = self.state
        self.servers = [self.http, self.tls4, self.tls6, self.dns4, self.dns6]
        try:
            for server in self.servers:
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                self.threads.append(thread)
            self._wait_ready()
        except BaseException:
            for server in reversed(self.servers):
                try:
                    server.server_close()
                except BaseException:
                    pass
            raise Refusal("positive_control_failed") from None
        return self

    def _wait_ready(self):
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline:
            if all(thread.is_alive() for thread in self.threads):
                return
            time.sleep(0.01)
        raise Refusal("positive_control_failed")

    def __exit__(self, exc_type, exc, traceback):
        failed = False
        for server in reversed(self.servers):
            try:
                server.shutdown()
                server.server_close()
            except BaseException:
                failed = True
        for thread in self.threads:
            thread.join(timeout=3)
            failed = failed or thread.is_alive()
        if failed and exc_type is None:
            raise Refusal("cleanup_incomplete")
        return False


def _http_path(port, path):
    return "http://127.0.0.1:%d%s" % (port, path)


def _create_local_tls_identity(directory):
    try:
        openssl = capability._resolve_trusted_path("/usr/bin/openssl")
    except capability.ProbeFailure:
        raise Refusal("positive_control_failed") from None
    certificate = Path(directory) / "tripwire-cert.pem"
    private_key = Path(directory) / "tripwire-key.pem"
    result = _command(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            private_key,
            "-out",
            certificate,
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=probe.invalid",
        ],
        env=_safe_env(directory),
        timeout=45,
    )
    try:
        key_info = private_key.lstat()
        cert_info = certificate.lstat()
        if (
            result.returncode != 0
            or not stat.S_ISREG(key_info.st_mode)
            or key_info.st_uid != 0
            or stat.S_IMODE(key_info.st_mode) & 0o077
            or not stat.S_ISREG(cert_info.st_mode)
            or cert_info.st_uid != 0
            or stat.S_IMODE(cert_info.st_mode) & 0o022
        ):
            raise ValueError
        return certificate, private_key
    except BaseException:
        raise Refusal("positive_control_failed") from None


def _copy_canary_scanner(directory):
    source = Path(__file__).with_name("macos_canary_scan.py")
    control_kit = Path(directory) / "control-kit"
    target = control_kit / "macos_canary_scan.py"
    try:
        source_info = source.lstat()
        payload = source.read_bytes()
        if not stat.S_ISREG(source_info.st_mode) or len(payload) > 65536:
            raise ValueError
        control_kit.mkdir(mode=0o755)
        if control_kit.lstat().st_uid != 0 or stat.S_IMODE(control_kit.lstat().st_mode) != 0o755:
            raise ValueError
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags, 0o444)
        try:
            offset = 0
            while offset < len(payload):
                offset += os.write(descriptor, payload[offset:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.chown(target, 0, 0)
        os.chmod(target, 0o444)
        os.chmod(control_kit, 0o555)
        metadata = target.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o444
            or target.read_bytes() != payload
        ):
            raise ValueError
        return control_kit
    except BaseException:
        raise Refusal("native_preflight_unavailable") from None


def _prepare_resolver_fixture(canary):
    parent = Path("/private") / "etc"
    resolver_directory = parent / "resolver"
    created_directory = False
    target = None
    identity = None
    payload = b"nameserver 127.0.0.1\nport 53\nsearch_order 1\n"
    try:
        _trusted_root_path(parent, directory=True)
        try:
            directory_info = resolver_directory.lstat()
        except FileNotFoundError:
            resolver_directory.mkdir(mode=0o755)
            created_directory = True
            directory_info = resolver_directory.lstat()
        if (
            not stat.S_ISDIR(directory_info.st_mode)
            or directory_info.st_uid != 0
            or directory_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise ValueError
        _trusted_root_path(resolver_directory, directory=True)
        suffix = hashlib.sha256(canary + b"-resolver-domain").hexdigest()[:20]
        domain = "kd-" + suffix + ".test"
        positive_host = "positive." + domain
        positive_after_host = "after." + domain
        first_host = "first." + domain
        second_host = "second." + domain
        target = resolver_directory / domain
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(target, flags, 0o444)
        try:
            identity = os.fstat(descriptor)
            if not stat.S_ISREG(identity.st_mode) or identity.st_uid != 0:
                raise ValueError
            os.fchmod(descriptor, 0o444)
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("short resolver write")
                remaining = remaining[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        named = target.lstat()
        if (
            (named.st_dev, named.st_ino) != (identity.st_dev, identity.st_ino)
            or stat.S_IMODE(named.st_mode) != 0o444
            or target.read_bytes() != payload
        ):
            raise ValueError
        return (target, resolver_directory, created_directory, identity.st_dev, identity.st_ino, payload), (
            positive_host, positive_after_host, first_host, second_host,
        )
    except BaseException:
        if target is not None and identity is not None:
            try:
                named = target.lstat()
                if (named.st_dev, named.st_ino) == (identity.st_dev, identity.st_ino):
                    target.unlink()
            except OSError:
                pass
        if created_directory:
            try:
                resolver_directory.rmdir()
            except OSError:
                pass
        raise Refusal("native_preflight_unavailable") from None


def _remove_resolver_fixture(fixture):
    if fixture is None:
        return
    target, resolver_directory, created_directory, device, inode, payload = fixture
    try:
        named = target.lstat()
        if (
            not stat.S_ISREG(named.st_mode)
            or named.st_uid != 0
            or stat.S_IMODE(named.st_mode) != 0o444
            or (named.st_dev, named.st_ino) != (device, inode)
            or target.read_bytes() != payload
        ):
            raise ValueError
        target.unlink()
        if created_directory:
            resolver_directory.rmdir()
    except BaseException:
        raise Refusal("cleanup_incomplete", stage="cleanup") from None


def _positive_control_script():
    return r'''import http.client, socket, ssl, sys, urllib.request
http_port, tls4, tls6, dns_hostname, token, runner_file = sys.argv[1:]
http_port, tls4, tls6 = int(http_port), int(tls4), int(tls6)
def request(url, method="GET", proxy=None):
    if proxy:
        connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=2)
        connection.set_tunnel("example.invalid", 443, headers={"X-Probe": token})
        try:
            connection.request("GET", "/")
            response = connection.getresponse()
            response.read()
            connection.close()
            return response.status == 502
        except OSError:
            connection.close()
            return True
    if method in ("POST", "PUT"):
        request = urllib.request.Request(url, data=token.encode(), method=method,
                                         headers={"Authorization": "Bearer " + token})
        with urllib.request.urlopen(request, timeout=3) as response:
            response.read(64)
            return response.status in (200, 204)
    with urllib.request.urlopen(url, timeout=3) as response:
        response.read(64)
        return response.status in (200, 204)
def tls(host, address, port):
    raw = socket.create_connection((address, port), timeout=2)
    context = ssl._create_unverified_context()
    wrapped = context.wrap_socket(raw, server_hostname=host)
    wrapped.sendall(b"KD-TLS-CONTROL")
    wrapped.close()
    return True
try:
    with open(runner_file, "rb") as stream:
        runner_file_result = stream.read() == token.encode() + b"\n"
    addresses = socket.getaddrinfo(dns_hostname, 443, socket.AF_INET, socket.SOCK_STREAM)
    resolver_result = any(item[4][0] == "127.0.0.1" for item in addresses)
    results = {
      "https4": tls("127.0.0.1", "127.0.0.1", tls4),
      "https6": tls("::1", "::1", tls6),
      "https_host": tls(dns_hostname, dns_hostname, tls4),
      "dns_resolver": resolver_result,
      "redirect": request("http://127.0.0.1:%d/redirect/%s" % (http_port, token)),
      "proxy": request("", proxy=True),
      "artifact": request("http://127.0.0.1:%d/_apis/artifacts/%s" % (http_port, token), "POST"),
      "cache": request("http://127.0.0.1:%d/_apis/cache/%s" % (http_port, token), "PUT"),
      "runner_file": runner_file_result,
    }
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(2)
    udp.sendto(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x06probe1\x07invalid\x00\x00\x01\x00\x01", ("127.0.0.1", 53))
    reply4, _ = udp.recvfrom(4096)
    results["dns4"] = reply4[:2] == b"\x12\x34" and (reply4[2] & 0x80) != 0
    udp6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    udp6.settimeout(2)
    udp6.sendto(b"\x12\x35\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + b"\x06probe1\x07invalid\x00\x00\x01\x00\x01", ("::1", 53))
    reply6, _ = udp6.recvfrom(4096)
    results["dns6"] = reply6[:2] == b"\x12\x35" and (reply6[2] & 0x80) != 0
    print("KD-POSITIVE:" + str(all(results.values())))
except BaseException:
    print("KD-POSITIVE:false")
'''


def _run_positive_controls(
    toolchain, uid, home, storage, policy, tripwires, canary, dns_hostname, runner_file, retained_pids=(),
):
    before = tripwires.state.counts()
    script = _positive_control_script()
    result = _run_confined(
        [toolchain["python"], "-I", "-S", "-B", "-c", script,
         str(tripwires.http_port), str(tripwires.tls4_port), str(tripwires.tls6_port),
         dns_hostname, canary.decode("ascii"), str(runner_file)],
        uid,
        env=_safe_env(home),
        python=toolchain["python"],
        storage=storage,
        policy=policy,
        timeout=20,
        refusal="positive_control_failed",
        retained_pids=retained_pids,
        trusted_control=True,
    )
    if result.stderr or b"KD-POSITIVE:True" not in result.stdout:
        raise Refusal("positive_control_failed")
    after = tripwires.state.counts()
    if (
        after["tls"] - before["tls"] < 3
        or after["dns"] - before["dns"] < 3
        or after["requests"] - before["requests"] < 5
    ):
        raise Refusal("positive_control_failed")


def _pf_probe_script():
    return r'''import errno, socket, sys
http_port, tls4, tls6 = map(int, sys.argv[1:])
denied = (errno.EPERM, errno.EACCES, errno.EHOSTUNREACH, errno.ECONNREFUSED, errno.ETIMEDOUT)
def tcp_blocked(family, address, port):
    try:
        sock = socket.socket(family, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((address, port))
        sock.close()
        return False
    except OSError as error:
        return error.errno in denied
def dns_blocked(family, address, txid):
    try:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.settimeout(1)
        query = txid + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06probe1\x07invalid\x00\x00\x01\x00\x01"
        sock.sendto(query, (address, 53))
        sock.recvfrom(4096)
        sock.close()
        return False
    except socket.timeout:
        return True
    except OSError as error:
        return error.errno in denied
results = (
    tcp_blocked(socket.AF_INET, "127.0.0.1", http_port),
    tcp_blocked(socket.AF_INET, "127.0.0.1", tls4),
    dns_blocked(socket.AF_INET, "127.0.0.1", b"\x12\x37"),
    tcp_blocked(socket.AF_INET6, "::1", tls6),
    dns_blocked(socket.AF_INET6, "::1", b"\x12\x38"),
)
print("KD-PF:" + str(all(results)))
'''


def _probe_pf_denial(toolchain, uid, home, storage, policy, tripwires, guard, retained_pids=()):
    before = tripwires.state.counts()
    guard.verify()
    result = _run_confined(
        [toolchain["python"], "-I", "-S", "-B", "-c", _pf_probe_script(),
         str(tripwires.http_port), str(tripwires.tls4_port), str(tripwires.tls6_port)],
        uid,
        env=_safe_env(home),
        python=toolchain["python"],
        storage=storage,
        policy=policy,
        timeout=10,
        refusal="pf_unavailable",
        retained_pids=retained_pids,
        trusted_control=True,
    )
    if result.stderr or result.stdout.strip() != b"KD-PF:True":
        raise Refusal("pf_unavailable", stage="pf_only")
    after = tripwires.state.counts()
    if after != before:
        raise Refusal("pf_unavailable", stage="pf_only")
    guard.verify(require_hits=True)


def _procargs_bytes(pid):
    import ctypes

    library = ctypes.CDLL(None, use_errno=True)
    mib = (ctypes.c_int * 3)(1, 49, int(pid))
    size = ctypes.c_size_t()
    function = library.sysctl
    function.argtypes = (ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
                         ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t)
    function.restype = ctypes.c_int
    if function(mib, 3, None, ctypes.byref(size), None, 0) != 0 or size.value < 4 or size.value > 1048576:
        raise Refusal("positive_control_failed")
    buffer = ctypes.create_string_buffer(size.value)
    if function(mib, 3, buffer, ctypes.byref(size), None, 0) != 0:
        raise Refusal("positive_control_failed")
    return buffer.raw[:size.value]


def _start_memory_target(toolchain, uid, home, canary, policy):
    helper = "import os,time; value=os.environ['KD_MEMORY_CANARY']; print('KD-MEMORY-READY',flush=True); time.sleep(180)"
    process = None
    try:
        process = capability._spawn_probe_user(
            [toolchain["python"], "-I", "-S", "-B", "-c", helper],
            uid,
            env={**_safe_env(home), "KD_MEMORY_CANARY": canary.decode("ascii")},
            python_executable=toolchain["python"],
            failure_reason="positive_control_failed",
            failure_check="probe_process_launch",
            failure_stage="probe_spawn",
        )
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        records = {}
        deadline = time.monotonic() + 5
        while len(records) < 2 and time.monotonic() < deadline:
            for key, _events in selector.select(max(0, deadline - time.monotonic())):
                records[key.data] = key.fileobj.readline()
        selector.close()
        if (
            records.get("stdout") != b"KD-MEMORY-READY\n"
            or records.get("stderr") != capability.PROBE_IDENTITY_VERIFIED
            or process.poll() is not None
        ):
            raise Refusal("positive_control_failed")
        if canary not in _procargs_bytes(process.pid):
            raise Refusal("positive_control_failed")
        rows = capability._process_table()
        snapshot = capability._descriptor_snapshot([process.pid], policy)
        if rows.get(process.pid, (None, None))[1] != uid or set(snapshot) != {process.pid}:
            raise Refusal("positive_control_failed")
        return process
    except Refusal as error:
        if process is not None:
            try:
                _stop_memory_target(process)
            except Refusal:
                raise Refusal("cleanup_incomplete", stage="cleanup") from None
        raise
    except BaseException:
        if process is not None:
            try:
                _stop_memory_target(process)
            except Refusal:
                raise Refusal("cleanup_incomplete", stage="cleanup") from None
        raise Refusal("positive_control_failed") from None


def _stop_memory_target(process):
    if process is None:
        return
    try:
        clean = capability._terminate_probe_tree(process)
        if not clean:
            raise Refusal("cleanup_incomplete")
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()
    except BaseException:
        raise Refusal("cleanup_incomplete") from None


def _memory_positive_script():
    return r'''import ctypes, os, signal, sys
pid, canary = int(sys.argv[1]), sys.argv[2].encode()
libc = ctypes.CDLL(None, use_errno=True)
task = ctypes.c_uint.in_dll(libc, "mach_task_self_").value
port = ctypes.c_uint()
task_for_pid = libc.task_for_pid
task_for_pid.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.POINTER(ctypes.c_uint))
task_for_pid.restype = ctypes.c_int
task_status = task_for_pid(task, pid, ctypes.byref(port))
if task_status != 0:
    raise SystemExit(1)
libc.mach_port_deallocate(task, port.value)
mib = (ctypes.c_int * 3)(1, 49, pid)
size = ctypes.c_size_t()
sysctl = libc.sysctl
sysctl.argtypes = (ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
                   ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t)
sysctl.restype = ctypes.c_int
if sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0 or size.value < 4 or size.value > 1048576:
    raise SystemExit(2)
buffer = ctypes.create_string_buffer(size.value)
if sysctl(mib, 3, buffer, ctypes.byref(size), None, 0) != 0 or canary not in buffer.raw[:size.value]:
    raise SystemExit(3)
os.kill(pid, signal.SIGCONT)
print("KD-MEMORY-POSITIVE:passed")
'''


def _run_memory_positive_control(toolchain, uid, home, storage, policy, target, canary):
    if target is None or target.poll() is not None or canary not in _procargs_bytes(target.pid):
        raise Refusal("positive_control_failed")
    result = _run_confined(
        [toolchain["python"], "-I", "-S", "-B", "-c", _memory_positive_script(),
         str(target.pid), canary.decode("ascii")],
        uid,
        env=_safe_env(home),
        python=toolchain["python"],
        storage=storage,
        policy=policy,
        timeout=10,
        refusal="positive_control_failed",
        retained_pids=(target.pid,),
        trusted_control=True,
    )
    if result.stderr or result.stdout.strip() != b"KD-MEMORY-POSITIVE:passed":
        raise Refusal("positive_control_failed")


def _unified_log_is_clear(canary):
    predicate = 'eventMessage CONTAINS[c] "' + canary.decode("ascii") + '"'
    deadline = time.monotonic() + 2
    while True:
        result = _command(
            ["/usr/bin/log", "show", "--last", "3m", "--style", "compact", "--predicate", predicate],
            timeout=30,
        )
        if result.returncode != 0:
            raise Refusal("channel_not_blocked", channel="raw_logs")
        if canary in result.stdout or canary in result.stderr:
            return False
        if time.monotonic() >= deadline:
            return True
        time.sleep(0.25)


def _unified_log_contains(marker):
    predicate = 'eventMessage CONTAINS[c] "' + marker.decode("ascii") + '"'
    result = _command(
        ["/usr/bin/log", "show", "--last", "5m", "--style", "compact", "--predicate", predicate],
        timeout=30,
    )
    if result.returncode != 0:
        raise Refusal("positive_control_failed")
    return marker in result.stdout


def _log_control_script():
    return r'''import ctypes, socket, subprocess, sys
logger_marker, syslog_marker, oslog_marker = sys.argv[1:]
try:
    logger = subprocess.run(("/usr/bin/logger", logger_marker), stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, close_fds=True)
    if logger.returncode != 0:
        raise RuntimeError
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    sock.connect("/var/run/syslog")
    sock.send(syslog_marker.encode())
    sock.close()
    trace = ctypes.CDLL("/usr/lib/system/libsystem_trace.dylib")
    create = trace.os_log_create
    create.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
    create.restype = ctypes.c_void_p
    log = create(b"org.example.keeldock", b"ci-control")
    if not log:
        raise RuntimeError
    emit = trace.os_log_with_type
    emit.argtypes = (ctypes.c_void_p, ctypes.c_uint, ctypes.c_char_p)
    emit.restype = None
    emit(log, 0, b"%{public}s", ctypes.c_char_p(oslog_marker.encode()))
    print("KD-LOG-CONTROL:True")
except BaseException:
    print("KD-LOG-CONTROL:False")
'''


def _run_log_positive_controls(toolchain, uid, home, storage, policy, canary, retained_pids=()):
    marker_prefix = hashlib.sha256(canary + b"-log-control").hexdigest()[:24]
    logger_marker = "KD-LOG-POSITIVE-" + marker_prefix + "-logger"
    syslog_marker = "KD-LOG-POSITIVE-" + marker_prefix + "-syslog"
    oslog_marker = "KD-LOG-POSITIVE-" + marker_prefix + "-oslog"
    result = _run_confined(
        [toolchain["python"], "-I", "-S", "-B", "-c", _log_control_script(),
         logger_marker, syslog_marker, oslog_marker],
        uid,
        env=_safe_env(home),
        python=toolchain["python"],
        storage=storage,
        policy=policy,
        timeout=15,
        refusal="positive_control_failed",
        retained_pids=retained_pids,
        trusted_control=True,
    )
    if result.stderr or result.stdout.strip() != b"KD-LOG-CONTROL:True":
        raise Refusal("positive_control_failed")
    if not all(_unified_log_contains(marker.encode("ascii")) for marker in (
        logger_marker,
        syslog_marker,
        oslog_marker,
    )):
        raise Refusal("positive_control_failed")


def _ipc_positive_script():
    return r'''import ctypes, json, os, socket, subprocess, sys
uid, nonce = int(sys.argv[1]), sys.argv[2]
result = {}
libc = ctypes.CDLL(None, use_errno=True)
task = ctypes.c_uint.in_dll(libc, "mach_task_self_").value
bootstrap = ctypes.c_uint()
task_get = libc.task_get_special_port
task_get.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.POINTER(ctypes.c_uint))
task_get.restype = ctypes.c_int
if task_get(task, 4, ctypes.byref(bootstrap)) != 0:
    raise SystemExit(1)
port = ctypes.c_uint()
lookup = libc.bootstrap_look_up
lookup.argtypes = (ctypes.c_uint, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint))
lookup.restype = ctypes.c_int
if lookup(bootstrap.value, b"com.apple.trustd", ctypes.byref(port)) != 0:
    raise SystemExit(2)
result["mach_lookup"] = True
receive = ctypes.c_uint()
allocate = libc.mach_port_allocate
allocate.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.POINTER(ctypes.c_uint))
allocate.restype = ctypes.c_int
register = libc.bootstrap_register
register.argtypes = (ctypes.c_uint, ctypes.c_char_p, ctypes.c_uint)
register.restype = ctypes.c_int
service = ("org.example.kd." + nonce).encode()
if allocate(task, 1, ctypes.byref(receive)) != 0:
    raise SystemExit(3)
if register(bootstrap.value, service, receive.value) != 0:
    raise SystemExit(4)
registered = ctypes.c_uint()
if lookup(bootstrap.value, service, ctypes.byref(registered)) != 0:
    raise SystemExit(5)
result["mach_register"] = True
libc.mach_port_deallocate(task, registered.value)
libc.mach_port_deallocate(task, receive.value)
shm_name = ("/kd-shm-" + nonce).encode()
shm_open = libc.shm_open
shm_open.argtypes = (ctypes.c_char_p, ctypes.c_int, ctypes.c_int)
shm_fd = shm_open(shm_name, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
if shm_fd < 0:
    raise SystemExit(6)
os.close(shm_fd)
libc.shm_unlink(shm_name)
sem_name = ("/kd-sem-" + nonce).encode()
sem_open = libc.sem_open
sem_open.restype = ctypes.c_void_p
sem = sem_open(sem_name, os.O_CREAT | os.O_EXCL, 0o600, 1)
if sem in (None, ctypes.c_void_p(-1).value):
    raise SystemExit(7)
libc.sem_close(ctypes.c_void_p(sem))
libc.sem_unlink(sem_name)
result["posix_ipc"] = True
route = socket.socket(getattr(socket, "AF_ROUTE", 17), socket.SOCK_RAW)
route.close()
system = socket.socket(32, socket.SOCK_DGRAM, 2)
system.close()
result["kernel_sockets"] = True
local = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
local.connect("/var/run/mDNSResponder")
local.send(b"\x00")
local.close()
result["mdns_socket"] = True
launchctl = subprocess.run(("/bin/launchctl", "print", "system/com.apple.trustd"),
                           stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=3, close_fds=True)
if launchctl.returncode != 0:
    raise SystemExit(8)
result["launchctl"] = True
print("KD-IPC-POSITIVE:" + json.dumps(result, sort_keys=True, separators=(",", ":")))
'''


def _run_ipc_positive_controls(toolchain, uid, home, storage, policy, canary, retained_pids=()):
    nonce = hashlib.sha256(canary + b"-ipc-control").hexdigest()[:16]
    result = _run_confined(
        [toolchain["python"], "-I", "-S", "-B", "-c", _ipc_positive_script(), str(uid), nonce],
        uid,
        env=_safe_env(home),
        python=toolchain["python"],
        storage=storage,
        policy=policy,
        timeout=15,
        refusal="positive_control_failed",
        retained_pids=retained_pids,
        trusted_control=True,
    )
    prefix = b"KD-IPC-POSITIVE:"
    lines = [line[len(prefix):] for line in result.stdout.splitlines() if line.startswith(prefix)]
    if result.stderr or len(lines) != 1:
        raise Refusal("positive_control_failed")
    try:
        values = json.loads(lines[0].decode("ascii"))
    except (ValueError, UnicodeDecodeError):
        raise Refusal("positive_control_failed") from None
    if type(values) is not dict or values != {
        "mach_lookup": True,
        "mach_register": True,
        "posix_ipc": True,
        "kernel_sockets": True,
        "mdns_socket": True,
        "launchctl": True,
    }:
        raise Refusal("positive_control_failed")


def _descriptor_policy(toolchain, sandbox_exec, workspace, storage):
    image_paths = (
        toolchain["python"],
        toolchain["clang"],
        toolchain["linker"],
        sandbox_exec,
        "/usr/bin/logger",
        "/usr/bin/sudo",
        "/usr/bin/sysctl",
        "/bin/launchctl",
        "/usr/bin/curl",
    )
    images = set()
    for image in image_paths:
        try:
            trusted = capability._resolve_trusted_path(image)
        except capability.ProbeFailure:
            if image in image_paths[:4]:
                raise Refusal("native_preflight_unavailable") from None
            continue
        images.add(str(image))
        images.add(trusted.as_posix())
    read_roots = (
        "/System/Library",
        "/System/Volumes/Preboot/Cryptexes/OS",
        "/usr/lib",
        "/usr/share",
        "/usr/bin",
        "/bin",
        toolchain["developer_directory"],
        toolchain["sdk"],
        str(Path(workspace).resolve()),
        str(Path(storage).resolve()),
    )
    if toolchain.get("control_kit"):
        read_roots = read_roots + (str(Path(toolchain["control_kit"]).resolve(strict=True)),)
    return capability._ToolchainPolicy(
        tuple(images),
        str(Path(storage).resolve()),
        tuple(sorted(set(str(Path(path).resolve()) for path in read_roots))),
    )


def _uid_processes_are_only(uid, allowed_pids):
    expected = set(allowed_pids)
    try:
        first = capability._process_table()
        first_uid_pids = {pid for pid, row in first.items() if row[1] == uid}
        time.sleep(0.05)
        second = capability._process_table()
        second_uid_pids = {pid for pid, row in second.items() if row[1] == uid}
    except capability.ProbeFailure:
        return False
    return (
        first_uid_pids == expected
        and second_uid_pids == expected
        and all(pid in second and second[pid][1] == uid for pid in expected)
    )


def _run_confined(
    argv, uid, *, env, python, storage, policy, timeout, refusal, retained_pids=(), trusted_control=False,
):
    try:
        process = capability._spawn_probe_user(
            argv,
            uid,
            env=env,
            python_executable=python,
            cwd=storage,
            failure_reason=refusal,
            failure_check="probe_process_launch",
            failure_stage="probe_spawn",
        )
    except capability.ProbeFailure:
        raise Refusal(refusal) from None
    stdout = stderr = None
    process_tree_stopped = False
    captures_joined = False
    census_clean = False
    confirmed = False
    try:
        stdout = capability._Capture(process.stdout)
        stderr = capability._Capture(process.stderr)
        stdout.start()
        stderr.start()
        deadline = time.monotonic() + timeout
        while process.poll() is None and time.monotonic() < deadline:
            rows = capability._process_table()
            root = rows.get(process.pid)
            if root is None or root[1] != uid:
                raise Refusal("native_preflight_unavailable")
            pids = [process.pid]
            pids.extend(
                pid for pid in capability._descendants(process.pid, rows)
                if pid != process.pid and rows[pid][1] == uid
            )
            if trusted_control:
                library = capability._load_libproc()
                images = tuple(capability._pid_image(library, pid) for pid in pids)
                safe_images = all(image is not None and image in policy.images for image in images)
            else:
                snapshot = capability._descriptor_snapshot(pids, policy)
                safe_images = set(snapshot) == set(pids)
            if safe_images:
                confirmed = True
            elif time.monotonic() + 0.1 >= deadline:
                raise Refusal("native_preflight_unavailable")
            if stdout.overflow or stderr.overflow:
                raise Refusal(refusal)
            try:
                process.wait(timeout=0.1)
            except subprocess.TimeoutExpired:
                pass
        if process.poll() is None:
            raise Refusal("native_preflight_unavailable")
        if not confirmed or stdout.overflow or stderr.overflow:
            raise Refusal(refusal)
    except capability.ProbeFailure:
        raise Refusal("native_preflight_unavailable") from None
    finally:
        try:
            process_tree_stopped = capability._terminate_probe_tree(process)
        except BaseException:
            process_tree_stopped = False
        for capture in (stdout, stderr):
            if capture is not None:
                try:
                    captures_joined = capture.join() and (captures_joined or capture is stdout)
                except BaseException:
                    captures_joined = False
        try:
            census_clean = _uid_processes_are_only(uid, retained_pids)
        except BaseException:
            census_clean = False
        for stream in (process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                try:
                    stream.close()
                except (OSError, ValueError):
                    pass
        if not process_tree_stopped or not captures_joined or not census_clean:
            raise Refusal("cleanup_incomplete", stage="cleanup")
    if process.returncode != 0:
        raise Refusal(refusal)
    try:
        captured_stderr = capability._strip_probe_identity_record(bytes(stderr.data))
    except capability.ProbeFailure:
        raise Refusal("probe_identity_unavailable", stage="probe_identity") from None
    return subprocess.CompletedProcess(
        [str(part) for part in argv], process.returncode,
        bytes(stdout.data), captured_stderr,
    )


def _canary_files(runner_home, runner_paths, control_files, canary, probe_uid, runner_uid, outside, created=None):
    created = [] if created is None else created
    readable_paths = []
    payload = canary + b"\n"
    directories = list(runner_paths) + [Path(runner_home)]
    suffix = hashlib.sha256(canary + b"-runner-files").hexdigest()[:20]
    for index, directory in enumerate(directories):
        root = Path(directory)
        target = root / (".kd-native-canary-%02d-%s" % (index, suffix))
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(target, flags, 0o444)
            created.append(target)
            try:
                if os.write(descriptor, payload) != len(payload):
                    raise OSError("short canary write")
            finally:
                os.close(descriptor)
            os.chown(target, 0, 0)
            os.chmod(target, 0o444)
            readable_paths.append(target)
        except BaseException:
            for path in reversed(created):
                try:
                    path.unlink()
                except OSError:
                    pass
            raise Refusal("native_preflight_unavailable") from None
    sensitive_paths = (
        Path(runner_home) / (".credentials-kd-" + suffix),
        Path(runner_home) / (".runner-kd-" + suffix),
        Path(runner_home) / ".ssh" / ("kd-" + suffix),
        Path(runner_home) / "Library" / "Keychains" / ("kd-" + suffix),
    )
    for target in sensitive_paths:
        current = Path(runner_home)
        for component in target.parent.relative_to(runner_home).parts:
            current = current / component
            try:
                metadata = current.lstat()
            except FileNotFoundError:
                try:
                    current.mkdir(mode=0o755)
                    created.append(current)
                    os.chown(current, runner_uid, capability.PROBE_PRIMARY_GID)
                    os.chmod(current, 0o755)
                    metadata = current.lstat()
                except OSError:
                    raise Refusal("native_preflight_unavailable") from None
            except OSError:
                raise Refusal("native_preflight_unavailable") from None
            if (
                stat.S_ISLNK(metadata.st_mode)
                or not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid not in (runner_uid, 0)
            ):
                raise Refusal("native_preflight_unavailable")
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(target, flags, 0o444)
            created.append(target)
            try:
                if os.write(descriptor, payload) != len(payload):
                    raise OSError("short canary write")
            finally:
                os.close(descriptor)
            os.chown(target, 0, 0)
            os.chmod(target, 0o444)
            readable_paths.append(target)
        except BaseException:
            raise Refusal("native_preflight_unavailable") from None
    fixture = Path(outside) / "runner-files"
    fixture.mkdir(mode=0o700)
    created.append(fixture)
    os.chown(fixture, probe_uid, capability.PROBE_PRIMARY_GID)
    os.chmod(fixture, 0o700)
    for relative in (".credentials", ".runner", ".ssh/id_ed25519", "Library/Keychains/login.keychain-db"):
        target = fixture / relative
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        for parent in (target.parent, *target.parent.parents):
            if parent == fixture.parent:
                break
            try:
                os.chown(parent, probe_uid, capability.PROBE_PRIMARY_GID)
                os.chmod(parent, 0o755)
            except OSError:
                raise Refusal("native_preflight_unavailable") from None
        created.append(target)
        target.write_bytes(payload)
        os.chown(target, 0, 0)
        os.chmod(target, 0o444)
        readable_paths.append(target)
    return tuple(created), tuple(readable_paths) + tuple(control_files)


def _hostile_script():
    return r'''import ctypes, errno, hashlib, http.client, json, os, pathlib, signal, socket, ssl, subprocess, sys, urllib.request
canary, dns_hostname, storage, outside, runner_paths, control_files, http_port, tls4, tls6, target_pid, anchor, active_profile, scanner_path = sys.argv[1:]
runner_paths = json.loads(runner_paths)
control_files = json.loads(control_files)
http_port, tls4, tls6, target_pid = int(http_port), int(tls4), int(tls6), int(target_pid)
sys.path.insert(0, scanner_path)
from macos_canary_scan import CanaryPresent, ScanIncomplete, scan_readable_roots
denied = (errno.EPERM, errno.EACCES)
KERN_FAILURE = 5
result = {}
def socket_denied(family, kind, address):
    try:
        sock = socket.socket(family, kind)
        sock.settimeout(1)
        if kind == socket.SOCK_DGRAM:
            sock.sendto(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06probe1\x07invalid\x00\x00\x01\x00\x01", address)
            sock.recvfrom(4096)
        else:
            sock.connect(address)
        sock.close()
        return False
    except OSError as error:
        return error.errno in denied
def socket_create_denied(family, kind, protocol=0):
    try:
        sock = socket.socket(family, kind, protocol)
        sock.close()
        return False
    except OSError as error:
        return error.errno in denied
def unix_socket_denied(path):
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.connect(path)
        sock.close()
        return False
    except OSError as error:
        return error.errno in denied
def tls_denied(host, address, port):
    try:
        raw = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(2)
        raw.connect((address, port))
        context = ssl._create_unverified_context()
        wrapped = context.wrap_socket(raw, server_hostname=host, do_handshake_on_connect=False)
        wrapped.do_handshake()
        wrapped.sendall(canary.encode())
        wrapped.close()
        return False
    except OSError as error:
        return error.errno in denied
    except ssl.SSLError:
        return False
def resolver_denied(host):
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        lookup = libc.getaddrinfo
        lookup.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p))
        lookup.restype = ctypes.c_int
        addresses = ctypes.c_void_p()
        ctypes.set_errno(0)
        status = lookup(host.encode("ascii"), b"443", None, ctypes.byref(addresses))
        if status == 0:
            libc.freeaddrinfo.argtypes = (ctypes.c_void_p,)
            libc.freeaddrinfo.restype = None
            libc.freeaddrinfo(addresses)
            return False
        return status == socket.EAI_SYSTEM and ctypes.get_errno() in denied
    except (AttributeError, OSError, ValueError):
        return False
def denied_http(url, method="GET", proxy=None):
    try:
        if proxy:
            os.environ["HTTPS_PROXY"] = proxy
            os.environ["https_proxy"] = proxy
            os.environ["HTTP_PROXY"] = proxy
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
            opener.open("https://example.invalid/" + canary, timeout=2).read(32)
        elif method == "PUT":
            request = urllib.request.Request(url, data=canary.encode(), method="PUT", headers={"Authorization": "Bearer " + canary})
            urllib.request.urlopen(request, timeout=2).read(32)
        elif method == "POST":
            request = urllib.request.Request(url, data=canary.encode(), method="POST", headers={"Authorization": "Bearer " + canary})
            urllib.request.urlopen(request, timeout=2).read(32)
        else:
            urllib.request.urlopen(url, timeout=2).read(32)
        return False
    except OSError as error:
        return error.errno in denied
    except Exception as error:
        return getattr(error, "errno", None) in denied
def file_denied(path, write=False):
    try:
        if write:
            with open(path, "wb") as stream:
                stream.write(canary.encode())
            try:
                os.unlink(path)
            except OSError:
                pass
            return False
        if os.path.isdir(path):
            with os.scandir(path) as entries:
                next(entries, None)
            return False
        with open(path, "rb"):
            return False
    except OSError as error:
        return error.errno in denied
def mach_denied():
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        bootstrap_lookup = libc.bootstrap_look_up
        bootstrap_lookup.argtypes = (ctypes.c_uint, ctypes.c_char_p, ctypes.POINTER(ctypes.c_uint))
        bootstrap_lookup.restype = ctypes.c_int
        bootstrap = ctypes.c_uint.in_dll(libc, "mach_task_self_").value
        task_get = libc.task_get_special_port
        task_get.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.POINTER(ctypes.c_uint))
        task_get.restype = ctypes.c_int
        bootstrap_port = ctypes.c_uint()
        if task_get(bootstrap, 4, ctypes.byref(bootstrap_port)) != 0:
            return False
        port = ctypes.c_uint()
        status = bootstrap_lookup(bootstrap_port.value, b"com.apple.trustd", ctypes.byref(port))
        return status == 1100
    except (AttributeError, OSError, ValueError):
        return False
def register_denied():
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        task = ctypes.c_uint.in_dll(libc, "mach_task_self_").value
        port = ctypes.c_uint()
        allocate = libc.mach_port_allocate
        allocate.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.POINTER(ctypes.c_uint))
        allocate.restype = ctypes.c_int
        if allocate(task, 1, ctypes.byref(port)) != 0:
            return False
        bootstrap = ctypes.c_uint()
        if libc.task_get_special_port(task, 4, ctypes.byref(bootstrap)) != 0:
            libc.mach_port_deallocate(task, port.value)
            return False
        register = libc.bootstrap_register
        register.argtypes = (ctypes.c_uint, ctypes.c_char_p, ctypes.c_uint)
        register.restype = ctypes.c_int
        name = ("org.example.kd." + canary[-16:]).encode()
        status = register(bootstrap.value, name, port.value)
        libc.mach_port_deallocate(task, port.value)
        return status == 1100
    except (AttributeError, OSError, ValueError):
        return False
def posix_ipc_denied(name):
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        nonce = hashlib.sha256(canary.encode("ascii") + b"-ipc-control").hexdigest()[:16]
        if name == "shm":
            function = libc.shm_open
            function.argtypes = (ctypes.c_char_p, ctypes.c_int, ctypes.c_int)
            shared_name = ("/kd-shm-" + nonce).encode("ascii")
            ctypes.set_errno(0)
            descriptor = function(shared_name, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            if descriptor >= 0:
                os.close(descriptor)
                unlink = libc.shm_unlink
                unlink.argtypes = (ctypes.c_char_p,)
                unlink(shared_name)
                return False
        else:
            function = libc.sem_open
            function.restype = ctypes.c_void_p
            shared_name = ("/kd-sem-" + nonce).encode("ascii")
            ctypes.set_errno(0)
            pointer = function(shared_name, os.O_CREAT | os.O_EXCL, 0o600, 1)
            if pointer not in (None, ctypes.c_void_p(-1).value):
                close = libc.sem_close
                close.argtypes = (ctypes.c_void_p,)
                close(pointer)
                unlink = libc.sem_unlink
                unlink.argtypes = (ctypes.c_char_p,)
                unlink(shared_name)
                return False
        return ctypes.get_errno() in denied
    except (AttributeError, OSError, ValueError):
        return False
def memory_denied():
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        task = ctypes.c_uint.in_dll(libc, "mach_task_self_").value
        own_type = ctypes.c_uint()
        MACH_PORT_TYPE_SEND = 1 << 16
        port_type = libc.mach_port_type
        port_type.argtypes = (ctypes.c_uint, ctypes.c_uint, ctypes.POINTER(ctypes.c_uint))
        port_type.restype = ctypes.c_int
        if port_type(task, task, ctypes.byref(own_type)) != 0 or not own_type.value & MACH_PORT_TYPE_SEND:
            return False
        port = ctypes.c_uint()
        task_for_pid = libc.task_for_pid
        task_for_pid.argtypes = (ctypes.c_uint, ctypes.c_int, ctypes.POINTER(ctypes.c_uint))
        task_for_pid.restype = ctypes.c_int
        task_status = task_for_pid(task, target_pid, ctypes.byref(port))
        if task_status != KERN_FAILURE:
            return False
        mib = (ctypes.c_int * 3)(1, 49, target_pid)
        size = ctypes.c_size_t()
        sysctl = libc.sysctl
        sysctl.argtypes = (ctypes.POINTER(ctypes.c_int), ctypes.c_uint, ctypes.c_void_p,
                           ctypes.POINTER(ctypes.c_size_t), ctypes.c_void_p, ctypes.c_size_t)
        sysctl.restype = ctypes.c_int
        if sysctl(mib, 3, None, ctypes.byref(size), None, 0) != 0:
            return ctypes.get_errno() in denied
        if size.value < 4 or size.value > 1048576:
            return False
        buffer = ctypes.create_string_buffer(size.value)
        if sysctl(mib, 3, buffer, ctypes.byref(size), None, 0) == 0:
            return False
        return ctypes.get_errno() in denied
    except (AttributeError, OSError, ValueError):
        return False
def boundary_attempts():
    outcomes = []
    commands = (
      (("/usr/bin/sudo", "-n", "/usr/bin/true"),
       (b"password is required", b"not in the sudoers", b"not allowed to execute")),
      (("/usr/sbin/DevToolsSecurity", "-enable"),
       (b"operation not permitted", b"not permitted", b"permission denied")),
      (("/sbin/pfctl", "-a", anchor, "-f", "/dev/null"),
       (b"operation not permitted", b"not permitted", b"permission denied")),
      (("/usr/sbin/sysctl", "-w", "kern.maxfiles=999999"),
       (b"operation not permitted", b"not permitted", b"permission denied")),
    )
    for command, expected_errors in commands:
        try:
            process = subprocess.run(command, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, timeout=3, close_fds=True)
            output = (process.stdout + process.stderr).lower()
            outcomes.append(process.returncode != 0 and any(text in output for text in expected_errors))
        except OSError as error:
            outcomes.append(error.errno in denied)
        except subprocess.SubprocessError:
            outcomes.append(False)
    profile = os.path.join(storage, "nested-permissive.sb")
    nested_script = (
        "import errno,socket,sys\n"
        "try:\n socket.socket(socket.AF_INET,socket.SOCK_STREAM)\n"
        "except OSError as error:\n"
        " print('KD-NESTED:blocked' if error.errno in (errno.EPERM,errno.EACCES) else 'KD-NESTED:other')\n"
        "else:\n print('KD-NESTED:allowed')\n"
    )
    try:
        with open(profile, "w", encoding="ascii") as stream:
            stream.write("(version 1)\n(allow default)\n")
        nested = subprocess.run(("/usr/bin/sandbox-exec", "-f", profile, sys.executable, "-I", "-S", "-B",
                                 "-c", nested_script),
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                timeout=3, close_fds=True)
        outcomes.append(nested.returncode == 0 and nested.stdout.strip() == b"KD-NESTED:blocked")
    except OSError as error:
        outcomes.append(error.errno in denied)
    except subprocess.SubprocessError:
        outcomes.append(False)
    outcomes.append(file_denied(active_profile, write=True))
    try:
        os.kill(target_pid, signal.SIGCONT)
        outcomes.append(False)
    except OSError as error:
        outcomes.append(error.errno in denied)
    return all(outcomes)
try:
    result["actions_environment"] = not any(name in os.environ for name in (
      "ACTIONS_RUNTIME_TOKEN", "ACTIONS_RUNTIME_URL", "ACTIONS_RESULTS_URL",
      "ACTIONS_CACHE_URL", "GITHUB_TOKEN",
    ))
    result["environment_canary"] = os.environ.get("KD_PRIVATE_CANARY") == canary
    with open(os.path.join(storage, "artifact-stage"), "wb") as stream:
        stream.write(b"synthetic artifact")
    with open(os.path.join(storage, "cache-stage"), "wb") as stream:
        stream.write(b"synthetic cache")
    result["staging_write"] = True
    with open(os.path.join(storage, "positive-read"), "rb") as stream:
        result["positive_read"] = stream.read(2) == b"ok"
    with open(os.path.join(storage, "positive-write"), "wb") as stream:
        stream.write(b"ok")
    result["positive_write"] = True
    outside_write = os.path.join(outside, "write-test")
    result["outside_write"] = file_denied(outside_write, write=True)
    result["dns_resolver"] = resolver_denied(dns_hostname)
    result["https"] = result["dns_resolver"] and all((
      tls_denied("127.0.0.1", "127.0.0.1", tls4),
      tls_denied("::1", "::1", tls6),
    ))
    result["dns"] = (
      result["dns_resolver"]
      and
      socket_denied(socket.AF_INET, socket.SOCK_DGRAM, ("127.0.0.1", 53))
      and socket_denied(socket.AF_INET6, socket.SOCK_DGRAM, ("::1", 53))
    )
    result["redirect"] = denied_http("http://127.0.0.1:%d/redirect/%s" % (http_port, canary))
    result["proxy"] = denied_http("", proxy="http://127.0.0.1:%d" % http_port)
    result["artifact_upload"] = result["actions_environment"] and result["staging_write"] and denied_http("http://127.0.0.1:%d/_apis/artifacts/%s" % (http_port, canary), method="POST")
    result["cache_upload"] = result["actions_environment"] and result["staging_write"] and denied_http("http://127.0.0.1:%d/_apis/cache/%s" % (http_port, canary), method="PUT")
    result["runner_files"] = (
      all(file_denied(path) for path in runner_paths + control_files)
      and all(file_denied(os.path.join(os.path.dirname(path), ".kd-probe-write"), write=True)
              for path in runner_paths + control_files)
    )
    try:
        launchctl = subprocess.run(("/bin/launchctl", "print", "system/com.apple.trustd"),
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, timeout=3, close_fds=True)
        output = (launchctl.stdout + launchctl.stderr).lower()
        result["launchctl"] = (
            launchctl.returncode != 0
            and any(text in output for text in (
                b"operation not permitted", b"not permitted", b"permission denied",
            ))
        )
    except OSError as error:
        result["launchctl"] = error.errno in denied
    except subprocess.SubprocessError:
        result["launchctl"] = False
    result["runner_ipc"] = (
      mach_denied() and register_denied()
      and posix_ipc_denied("shm") and posix_ipc_denied("sem")
      and socket_create_denied(getattr(socket, "AF_ROUTE", 17), socket.SOCK_RAW)
      and socket_create_denied(32, socket.SOCK_DGRAM, 2)
      and unix_socket_denied("/var/run/mDNSResponder")
      and result["launchctl"]
    )
    result["process_memory"] = memory_denied()
    result["boundary_disablement"] = boundary_attempts()
    for marker in (
        b"::error file=canary.txt,line=1::",
        b"::warning::",
        b"::add-mask::",
        b"::set-output name=leak::",
        b"::group::",
        b"::endgroup::",
    ):
        os.write(1, marker + canary.encode() + b"\n")
    os.write(2, canary.encode() + b"\n")
    try:
        descriptor = os.open("/dev/tty", os.O_WRONLY | os.O_NOFOLLOW)
        os.write(descriptor, canary.encode())
        os.close(descriptor)
        result["tty"] = "reached"
    except OSError as error:
        if error.errno in denied:
            result["tty"] = "blocked"
        elif error.errno in (errno.ENXIO, errno.ENODEV, errno.ENOENT):
            result["tty"] = "unavailable"
        else:
            result["tty"] = "unproved"
    try:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        sock.connect("/var/run/syslog")
        sock.send(canary.encode())
        sock.close()
        result["syslog"] = False
    except OSError as error:
        result["syslog"] = error.errno in denied
    try:
        logger = subprocess.run(("/usr/bin/logger", canary), stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=3, close_fds=True)
        output = (logger.stdout + logger.stderr).lower()
        result["logger_attempted"] = (
            logger.returncode == 0
            or any(text in output for text in (
                b"operation not permitted", b"not permitted", b"permission denied",
            ))
        )
    except OSError as error:
        result["logger_attempted"] = error.errno in denied
    except subprocess.SubprocessError:
        result["logger_attempted"] = False
    try:
        import ctypes.util
        trace = ctypes.CDLL("/usr/lib/system/libsystem_trace.dylib")
        create = trace.os_log_create
        create.argtypes = (ctypes.c_char_p, ctypes.c_char_p)
        create.restype = ctypes.c_void_p
        log = create(b"org.example.keeldock", b"ci-probe")
        if not log:
            raise RuntimeError
        emit = trace.os_log_with_type
        emit.argtypes = (ctypes.c_void_p, ctypes.c_uint, ctypes.c_char_p)
        emit.restype = None
        emit(log, 0, b"%{public}s", ctypes.c_char_p(canary.encode()))
        result["os_log_attempted"] = True
    except (OSError, AttributeError, TypeError):
        result["os_log_attempted"] = False
    result["raw_log_channels"] = (
        result.get("syslog") is True
        and result.get("logger_attempted") is True
        and result.get("os_log_attempted") is True
    )
    scan_roots = json.loads(os.environ.get("KD_READ_ROOTS", "[]"))
    try:
        scan_readable_roots(scan_roots, canary.encode("ascii"))
        result["readable_file_canary"] = "absent"
    except CanaryPresent:
        result["readable_file_canary"] = "present"
    except ScanIncomplete:
        result["readable_file_canary"] = "incomplete"
    expected = {"https", "dns", "dns_resolver", "redirect", "proxy", "runner_ipc", "artifact_upload",
                "cache_upload", "runner_files", "process_memory", "boundary_disablement",
                "actions_environment", "environment_canary", "staging_write", "raw_log_channels", "positive_read",
                "positive_write", "outside_write"}
    passed = (
        all(result.get(channel) is True for channel in expected)
        and result.get("readable_file_canary") == "absent"
    )
    result["memory_canary"] = "absent" if result.get("process_memory") else "present"
    result["native_pass"] = passed
    print("KD-PROOF:" + json.dumps(result, sort_keys=True, separators=(",", ":")))
except BaseException:
    print("KD-PROOF-REFUSED")
'''


def _run_hostile_fixture(
    *, sandbox_exec, profile, toolchain, uid, home, storage, outside, policy,
    runner_file_paths, control_files, workspace, canary, tripwires, memory_target_pid,
    active_profile, dns_hostname, failure_stage="seatbelt_channels", retained_pids=(),
):
    before = tripwires.state.counts()
    roots = {
        "/System/Library",
        "/System/Volumes/Preboot/Cryptexes/OS",
        "/usr/lib",
        "/usr/share",
        "/usr/bin",
        "/bin",
        toolchain["developer_directory"],
        toolchain["sdk"],
        str(Path(workspace).resolve()),
        str(Path(storage).resolve()),
    }
    if toolchain.get("control_kit"):
        roots.add(str(Path(toolchain["control_kit"]).resolve(strict=True)))
    child_env = _safe_env(home)
    child_env["KD_PRIVATE_CANARY"] = canary.decode("ascii")
    child_env["KD_READ_ROOTS"] = json.dumps(sorted(roots), separators=(",", ":"))
    files_arg = json.dumps([str(path) for path in runner_file_paths], separators=(",", ":"))
    controls_arg = json.dumps([str(path) for path in control_files], separators=(",", ":"))
    result = _run_confined(
        [sandbox_exec, "-f", str(profile), toolchain["python"], "-I", "-S", "-B", "-c",
         _hostile_script(), canary.decode("ascii"), dns_hostname, str(storage), str(outside), files_arg,
         controls_arg, str(tripwires.http_port), str(tripwires.tls4_port),
         str(tripwires.tls6_port), str(memory_target_pid), PF_ANCHOR, str(active_profile),
         toolchain["control_kit"]],
        uid,
        env=child_env,
        python=toolchain["python"],
        storage=storage,
        policy=policy,
        timeout=MAX_CHILD_SECONDS,
        refusal="channel_not_blocked",
        retained_pids=retained_pids,
    )
    try:
        proof = _validate_proof_payload(result.stdout, result.stderr, canary)
    except Refusal as error:
        if error.stage == "seatbelt_channels" and failure_stage != "seatbelt_channels":
            raise Refusal(error.reason, stage=failure_stage, channel=error.channel) from None
        raise
    if not _unified_log_is_clear(canary):
        raise Refusal("channel_not_blocked", stage=failure_stage, channel="raw_logs")
    if tripwires.state.counts() != before:
        raise Refusal(
            "channel_not_blocked",
            stage=failure_stage,
            channel=_tripwire_channel(tripwires.state, before),
        )
    return proof


def _validate_proof_payload(stdout, stderr, canary):
    if type(stdout) is not bytes or type(stderr) is not bytes or type(canary) is not bytes or not canary:
        raise Refusal("channel_not_blocked", stage="seatbelt_channels")
    prefix = b"KD-PROOF:"
    proof_lines = [line[len(prefix):] for line in stdout.splitlines() if line.startswith(prefix)]
    if (
        len(proof_lines) != 1
        or canary not in stdout
        or canary not in stderr
        or canary in proof_lines[0]
        or any(marker + canary not in stdout for marker in WORKFLOW_MARKERS)
    ):
        raise Refusal("channel_not_blocked", stage="seatbelt_channels")

    def reject_duplicate_keys(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result

    try:
        proof = json.loads(
            proof_lines[0].decode("ascii", "strict"),
            object_pairs_hook=reject_duplicate_keys,
        )
    except (ValueError, UnicodeDecodeError):
        raise Refusal("channel_not_blocked", stage="seatbelt_channels") from None
    expected_keys = {
        "actions_environment", "artifact_upload", "boundary_disablement", "cache_upload",
        "environment_canary",
        "dns", "dns_resolver", "https", "launchctl", "logger_attempted",
        "memory_canary", "native_pass", "os_log_attempted", "outside_write",
        "positive_read", "positive_write", "process_memory", "proxy", "raw_log_channels",
        "readable_file_canary", "redirect", "runner_files", "runner_ipc", "staging_write",
        "syslog", "tty",
    }
    required_true = {
        "actions_environment", "artifact_upload", "boundary_disablement", "cache_upload",
        "environment_canary",
        "dns", "dns_resolver", "https", "launchctl", "logger_attempted",
        "native_pass", "os_log_attempted", "outside_write", "positive_read", "positive_write",
        "process_memory", "proxy", "raw_log_channels", "redirect", "runner_files", "runner_ipc",
        "staging_write", "syslog",
    }
    if type(proof) is not dict or set(proof) != expected_keys:
        raise Refusal("channel_not_blocked", stage="seatbelt_channels")
    channel_fields = {
        "https": "https",
        "dns": "dns",
        "redirect": "redirect",
        "proxy": "proxy",
        "runner_ipc": "runner_ipc",
        "artifact_upload": "artifact_upload",
        "cache_upload": "cache_upload",
        "runner_files": "runner_files",
        "process_memory": "process_memory",
        "boundary_disablement": "boundary_disablement",
        "raw_log_channels": "raw_logs",
    }
    for field, channel in channel_fields.items():
        if proof.get(field) is not True:
            raise Refusal("channel_not_blocked", stage="seatbelt_channels", channel=channel)
    if proof.get("readable_file_canary") == "present":
        raise Refusal("channel_not_blocked", stage="walk", channel="runner_files")
    if proof.get("readable_file_canary") != "absent":
        raise Refusal("channel_not_blocked", stage="walk")
    if proof.get("memory_canary") != "absent":
        raise Refusal("channel_not_blocked", stage="memory_positive", channel="process_memory")
    if (
        any(proof.get(key) is not True for key in required_true)
        or proof.get("tty") not in {"blocked", "unavailable"}
    ):
        channel = "raw_logs" if proof.get("tty") == "reached" else None
        raise Refusal("channel_not_blocked", stage="seatbelt_channels", channel=channel)
    return proof


def _native_receipt(control_sha, run_id, run_attempt, macos_identity):
    if type(control_sha) is not str or CONTROL_SHA.fullmatch(control_sha) is None:
        raise Refusal("invalid_control_identity")
    decimal_identity = re.compile(r"[1-9][0-9]{0,18}\Z")
    if (
        type(run_id) is not str
        or decimal_identity.fullmatch(run_id) is None
        or type(run_attempt) is not str
        or decimal_identity.fullmatch(run_attempt) is None
    ):
        raise Refusal("native_preflight_unavailable") from None
    numeric_run_id = int(run_id)
    numeric_attempt = int(run_attempt)
    if numeric_run_id <= 0 or numeric_attempt <= 0:
        raise Refusal("native_preflight_unavailable")
    if type(macos_identity) is not dict or set(macos_identity) != {
        "product_version", "image_os", "runner_image_os", "image_version", "architecture",
    }:
        raise Refusal("native_preflight_unavailable")
    if macos_identity not in [
        {
            "product_version": release[0],
            "image_os": APPROVED_IMAGE_OS_VALUE,
            "runner_image_os": APPROVED_RUNNER_IMAGE_OS,
            "image_version": release[1],
            "architecture": APPROVED_ARCH,
        }
        for release in APPROVED_HOST_RELEASES
    ]:
        raise Refusal("macos_version_unapproved")
    return {
        "schema_version": 2,
        "run_id": numeric_run_id,
        "run_attempt": numeric_attempt,
        "control_sha": control_sha,
        "boundary": "seatbelt-deny-default",
        "macos_product_version": macos_identity["product_version"],
        "runner_image_os": macos_identity["runner_image_os"],
        "runner_image_version": macos_identity["image_version"],
        "developer_mode": "disabled",
        "pf": "enforced",
        "sandbox_selftest": "enforced",
        "positive_build": "passed",
        "channels": {
            "https": "blocked",
            "dns": "blocked",
            "redirect": "blocked",
            "proxy": "blocked",
            "runner_ipc": "blocked",
            "raw_logs": "captured_private",
            "artifact_upload": "pending_audit",
            "cache_upload": "pending_audit",
            "runner_files": "blocked",
            "process_memory": "blocked",
            "boundary_disablement": "blocked",
        },
        "private_source_executed": False,
    }


def _write_step_output(receipt, expected_uid):
    path = os.environ.get("GITHUB_OUTPUT", "")
    if not path:
        raise Refusal("native_preflight_unavailable", stage="output")
    payload = json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_RECEIPT_BYTES:
        raise Refusal("native_preflight_unavailable", stage="output")
    encoded = base64.urlsafe_b64encode(payload).rstrip(b"=")
    try:
        named = Path(path).lstat()
        if not stat.S_ISREG(named.st_mode) or named.st_uid != expected_uid:
            raise OSError("output identity")
        flags = os.O_WRONLY | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_uid != expected_uid
                or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
            ):
                raise OSError("output identity")
            remaining = memoryview(b"receipt=" + encoded + b"\n")
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("short output write")
                remaining = remaining[written:]
        finally:
            os.close(descriptor)
    except BaseException:
        raise Refusal("native_preflight_unavailable", stage="output") from None


def _plant_runner_env_canary(path, canary, expected_uid):
    descriptor = None
    original_size = None
    identity = None
    added_size = None
    try:
        named = Path(path).lstat()
        if not stat.S_ISREG(named.st_mode) or named.st_uid != expected_uid or named.st_size > 1048576:
            raise ValueError
        descriptor = os.open(path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != expected_uid
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise ValueError
        original_size = opened.st_size
        line = b"KD_CI_CANARY=" + canary + b"\n"
        added_size = len(line)
        identity = (opened.st_dev, opened.st_ino)
        if os.lseek(descriptor, 0, os.SEEK_END) != original_size:
            raise ValueError
        offset = 0
        while offset < len(line):
            written = os.write(descriptor, line[offset:])
            if written <= 0:
                raise OSError("short environment write")
            offset += written
        os.fsync(descriptor)
        if os.fstat(descriptor).st_size != original_size + len(line):
            raise ValueError
        return (descriptor, path, expected_uid, opened.st_dev, opened.st_ino, original_size, len(line), line)
    except BaseException:
        if descriptor is not None:
            try:
                opened = os.fstat(descriptor)
                if (
                    identity is not None
                    and (opened.st_dev, opened.st_ino) == identity
                    and opened.st_size <= original_size + added_size
                    and opened.st_size >= original_size
                ):
                    os.ftruncate(descriptor, original_size)
                    os.fsync(descriptor)
            except BaseException:
                try:
                    os.close(descriptor)
                except OSError:
                    pass
                raise Refusal("cleanup_incomplete", stage="cleanup") from None
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise Refusal("native_preflight_unavailable") from None


def _restore_runner_env_canary(state):
    if state is None:
        return
    descriptor, _path, expected_uid, device, inode, original_size, added_size, line = state
    failed = False
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_uid != expected_uid
            or (opened.st_dev, opened.st_ino) != (device, inode)
            or opened.st_size != original_size + added_size
            or os.pread(descriptor, added_size, original_size) != line
        ):
            raise ValueError
        os.ftruncate(descriptor, original_size)
        os.fsync(descriptor)
        if os.fstat(descriptor).st_size != original_size:
            raise ValueError
    except BaseException:
        failed = True
    try:
        os.close(descriptor)
    except OSError:
        failed = True
    if failed:
        raise Refusal("cleanup_incomplete", stage="cleanup") from None


def _verify_developer_mode_disabled():
    try:
        result = capability._run(
            ["/usr/sbin/DevToolsSecurity", "-status"],
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"},
            timeout=10,
        )
    except capability.ProbeFailure:
        raise Refusal("boundary_disablement") from None
    if result.returncode != 0 or result.stderr or result.stdout != b"Developer mode is currently disabled.\n":
        raise Refusal("boundary_disablement")


def _verify_profile_unchanged(profile, expected_digest):
    try:
        metadata = Path(profile).lstat()
        payload = Path(profile).read_bytes()
    except OSError:
        raise Refusal("boundary_disablement") from None
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o444
        or hashlib.sha256(payload).hexdigest() != expected_digest
    ):
        raise Refusal("boundary_disablement")


def _verify_memory_target(target, canary, uid, policy):
    if target is None or target.poll() is not None:
        raise Refusal("channel_not_blocked")
    if canary not in _procargs_bytes(target.pid):
        raise Refusal("channel_not_blocked")
    try:
        rows = capability._process_table()
        snapshot = capability._descriptor_snapshot([target.pid], policy)
    except capability.ProbeFailure:
        raise Refusal("channel_not_blocked") from None
    if rows.get(target.pid, (None, None))[1] != uid or set(snapshot) != {target.pid}:
        raise Refusal("channel_not_blocked")


def _run_proof(control_sha):
    stage = "platform"
    if not _BOOTSTRAP_OK or capability is None:
        raise Refusal("native_preflight_unavailable", stage="preflight")
    if boundary_guard is None:
        raise Refusal("native_preflight_unavailable", stage=stage)
    try:
        identity = boundary_guard.check_platform()
    except BaseException:
        raise Refusal("macos_version_unapproved", stage=stage) from None
    stage = "context"
    workspace = os.environ.get("CI_WORKSPACE", "")
    if not workspace:
        raise Refusal("native_preflight_unavailable", stage=stage)
    try:
        root = capability._check_context(control_sha, workspace)
        stage = "toolchain"
        toolchain = capability._resolve_trusted_toolchain()
        sandbox_exec = capability._resolve_sandbox_exec()
        stage = "developer_mode"
        capability._disable_developer_mode()
        stage = "runner_controls"
        runner_uid, runner_paths, control_files = capability._protect_runner_controls(root)
    except capability.ProbeFailure as error:
        raise Refusal(error.reason, stage=stage) from None
    probe_uid = None
    home_parent = home = None
    scratch = outside = storage = None
    memory_target = None
    pf_guard = None
    resolver_fixture = None
    dns_hostnames = None
    runner_env_state = None
    created_canaries = ()
    canary = canary_bytes(control_sha)
    receipt = None
    identity_created = False
    try:
        try:
            stage = "probe_identity"
            probe_uid, home_parent, home = capability._create_probe_identity(root)
            identity_created = True
        except capability.ProbeFailure as error:
            if not error.cleanup_complete:
                raise Refusal("cleanup_incomplete", stage="cleanup") from None
            raise Refusal(error.reason, stage=stage) from None

        stage = "profile"
        scratch = Path(tempfile.mkdtemp(prefix="kd-seatbelt-", dir="/tmp"))
        outside = Path(tempfile.mkdtemp(prefix="kd-seatbelt-outside-", dir="/tmp"))
        storage = Path(tempfile.mkdtemp(prefix="kd-seatbelt-storage-", dir="/tmp"))
        os.chmod(scratch, 0o755)
        os.chown(outside, probe_uid, capability.PROBE_PRIMARY_GID)
        os.chmod(outside, 0o700)
        storage_identity = capability._prepare_storage_directory(storage, probe_uid)
        _trusted_root_path(sandbox_exec, executable=True)
        toolchain["control_kit"] = str(_copy_canary_scanner(scratch))
        policy = _descriptor_policy(toolchain, sandbox_exec, root, storage)
        profile = _write_profile(scratch, root, storage, toolchain)
        profile_digest = hashlib.sha256(Path(profile).read_bytes()).hexdigest()

        stage = "positive_build"
        positive_source = storage / "positive.c"
        positive_source.write_text("int kd_positive_build(void) { return 1; }\n", encoding="ascii")
        os.chown(positive_source, probe_uid, capability.PROBE_PRIMARY_GID)
        os.chmod(positive_source, 0o600)
        positive_read = storage / "positive-read"
        positive_read.write_bytes(b"ok")
        os.chown(positive_read, 0, 0)
        os.chmod(positive_read, 0o444)
        build_script = (
            "import ctypes,subprocess,sys\n"
            "clang,sdk,source,binary=sys.argv[1:]\n"
            "build=subprocess.run((clang,'-dynamiclib','-isysroot',sdk,'-O','-o',binary,source),"
            "stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.PIPE,"
            "timeout=45,close_fds=True)\n"
            "if build.returncode != 0: raise SystemExit(1)\n"
            "library=ctypes.CDLL(binary)\n"
            "function=library.kd_positive_build\n"
            "function.restype=ctypes.c_int\n"
            "if function() != 1: raise SystemExit(2)\n"
            "print('KD-BUILD:passed')\n"
        )
        positive_binary = storage / "positive-build.dylib"
        build_result = _run_confined(
            [sandbox_exec, "-f", str(profile), toolchain["python"], "-I", "-S", "-B", "-c",
             build_script, toolchain["clang"], toolchain["sdk"], str(positive_source), str(positive_binary)],
            probe_uid,
            env=_safe_env(home),
            python=toolchain["python"],
            storage=storage,
            policy=policy,
            timeout=90,
            refusal="sandbox_selftest_failed",
        )
        if build_result.stdout.strip() != b"KD-BUILD:passed":
            raise Refusal("sandbox_selftest_failed", stage=stage)

        stage = "profile_selftest"
        outside_marker = outside / "read-canary"
        outside_marker.write_bytes(canary + b"\n")
        os.chown(outside_marker, 0, 0)
        os.chmod(outside_marker, 0o444)
        outside_write = outside / "write-test"
        selftest = _run_profile_selftest(
            sandbox_exec, profile, toolchain["python"], storage, outside_write,
            outside_marker, probe_uid, home, policy,
        )
        if not selftest:
            raise Refusal("sandbox_selftest_failed", stage=stage)

        stage = "runner_controls"
        runner_home = Path(os.environ.get("RUNNER_HOME", ""))
        try:
            runner_home_info = runner_home.lstat()
            if (
                not runner_home.is_absolute()
                or runner_home.resolve(strict=True) != runner_home
                or not stat.S_ISDIR(runner_home_info.st_mode)
                or runner_home_info.st_uid != runner_uid
            ):
                raise ValueError
        except BaseException:
            raise Refusal("native_preflight_unavailable") from None
        created_canaries = []
        created_paths, runner_file_paths = _canary_files(
            runner_home, runner_paths, control_files, canary, probe_uid, runner_uid, outside, created_canaries,
        )
        if tuple(created_canaries) != created_paths:
            raise Refusal("native_preflight_unavailable")
        if not control_files:
            raise Refusal("native_preflight_unavailable")
        runner_env_state = _plant_runner_env_canary(control_files[0], canary, runner_uid)

        _verify_profile_unchanged(profile, profile_digest)
        _verify_developer_mode_disabled()
        capability._verify_storage_directory(storage, storage_identity, probe_uid)
        stage = "network_positive"
        resolver_fixture, dns_hostnames = _prepare_resolver_fixture(canary)
        certificate, private_key = _create_local_tls_identity(scratch)
        stage = "memory_positive"
        memory_target = _start_memory_target(toolchain, probe_uid, home, canary, policy)
        _verify_memory_target(memory_target, canary, probe_uid, policy)

        with _Tripwires(canary, certificate, private_key) as tripwires:
            retained = (memory_target.pid,)
            _run_memory_positive_control(
                toolchain, probe_uid, home, storage, policy, memory_target, canary,
            )
            stage = "network_positive"
            _run_positive_controls(
                toolchain, probe_uid, home, storage, policy, tripwires, canary, dns_hostnames[0],
                Path(outside) / "runner-files" / ".credentials", retained,
            )
            stage = "log_positive"
            _run_log_positive_controls(
                toolchain, probe_uid, home, storage, policy, canary, retained,
            )
            stage = "ipc_positive"
            _run_ipc_positive_controls(
                toolchain, probe_uid, home, storage, policy, canary, retained,
            )
            _verify_memory_target(memory_target, canary, probe_uid, policy)

            stage = "seatbelt_channels"
            _run_hostile_fixture(
                sandbox_exec=sandbox_exec,
                profile=profile,
                toolchain=toolchain,
                uid=probe_uid,
                home=home,
                storage=storage,
                outside=outside,
                policy=policy,
                runner_file_paths=runner_file_paths,
                control_files=control_files,
                workspace=root,
                canary=canary,
                tripwires=tripwires,
                memory_target_pid=memory_target.pid,
                active_profile=profile,
                dns_hostname=dns_hostnames[2],
                retained_pids=retained,
            )
            _verify_profile_unchanged(profile, profile_digest)
            _verify_developer_mode_disabled()
            _verify_memory_target(memory_target, canary, probe_uid, policy)

            stage = "pf_only"
            pf_guard = boundary_guard.install_pf(probe_uid, scratch / "pf.rules")
            _probe_pf_denial(
                toolchain, probe_uid, home, storage, policy, tripwires, pf_guard, retained,
            )
            pf_guard.verify(require_hits=True)
            stage = "pf_channels"
            _run_hostile_fixture(
                sandbox_exec=sandbox_exec,
                profile=profile,
                toolchain=toolchain,
                uid=probe_uid,
                home=home,
                storage=storage,
                outside=outside,
                policy=policy,
                runner_file_paths=runner_file_paths,
                control_files=control_files,
                workspace=root,
                canary=canary,
                tripwires=tripwires,
                memory_target_pid=memory_target.pid,
                active_profile=profile,
                dns_hostname=dns_hostnames[3],
                failure_stage="pf_channels",
                retained_pids=retained,
            )
            pf_guard.verify(require_hits=True)
            _verify_profile_unchanged(profile, profile_digest)
            _verify_developer_mode_disabled()
            _verify_memory_target(memory_target, canary, probe_uid, policy)
            pf_guard.close()
            pf_guard = None

            stage = "network_positive"
            before_after = tripwires.state.counts()
            _run_positive_controls(
                toolchain, probe_uid, home, storage, policy, tripwires, canary, dns_hostnames[1],
                Path(outside) / "runner-files" / ".credentials", retained,
            )
            after_controls = tripwires.state.counts()
            if (
                after_controls["tls"] - before_after["tls"] < 3
                or after_controls["dns"] - before_after["dns"] < 3
                or after_controls["requests"] - before_after["requests"] < 5
            ):
                raise Refusal("positive_control_failed")

        receipt = _native_receipt(
            control_sha,
            os.environ.get("GITHUB_RUN_ID", ""),
            os.environ.get("GITHUB_RUN_ATTEMPT", ""),
            identity.as_dict(),
        )
        stage = "receipt"
    except capability.ProbeFailure as error:
        if not error.cleanup_complete:
            raise Refusal("cleanup_incomplete", stage="cleanup") from None
        raise Refusal(error.reason, stage=stage) from None
    except Refusal as error:
        if error.stage != "preflight":
            raise
        raise Refusal(error.reason, stage=stage, channel=error.channel) from None
    except boundary_guard.GuardError as error:
        reason = {
            "platform_unapproved": "macos_version_unapproved",
            "cleanup_incomplete": "cleanup_incomplete",
            "pf_unavailable": "pf_unavailable",
            "pf_rules_unexpected": "pf_unavailable",
        }.get(error.reason, "native_preflight_unavailable")
        raise Refusal(reason, stage="cleanup" if reason == "cleanup_incomplete" else stage) from None
    except Exception:
        raise Refusal("native_preflight_unavailable", stage=stage) from None
    finally:
        cleanup_failed = False
        if pf_guard is not None:
            try:
                pf_guard.close()
            except BaseException:
                cleanup_failed = True
        if resolver_fixture is not None:
            try:
                _remove_resolver_fixture(resolver_fixture)
            except BaseException:
                cleanup_failed = True
        if runner_env_state is not None:
            try:
                _restore_runner_env_canary(runner_env_state)
            except BaseException:
                cleanup_failed = True
        if memory_target is not None:
            try:
                _stop_memory_target(memory_target)
            except BaseException:
                cleanup_failed = True
        for path in reversed(created_canaries):
            try:
                if path.is_dir() and not path.is_symlink():
                    shutil.rmtree(path)
                else:
                    path.unlink(missing_ok=True)
            except BaseException:
                cleanup_failed = True
        if identity_created and probe_uid is not None:
            try:
                if capability._probe_uid_processes_present(probe_uid):
                    cleanup_failed = True
            except BaseException:
                cleanup_failed = True
        if not cleanup_failed:
            for path in (scratch, outside, storage, home_parent):
                if path is not None:
                    try:
                        capability._remove_probe_tree(path)
                    except BaseException:
                        cleanup_failed = True
            if identity_created and not cleanup_failed:
                try:
                    deleted = capability._run(
                        ["/usr/bin/dscl", ".", "-delete", "/Users/" + capability.USERNAME], timeout=10,
                    )
                    if deleted.returncode != 0 or deleted.stderr:
                        cleanup_failed = True
                except BaseException:
                    cleanup_failed = True
        if cleanup_failed:
            raise Refusal("cleanup_incomplete", stage="cleanup")
    if receipt is None:
        raise Refusal("native_preflight_unavailable", stage="receipt")
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--control-sha", required=True)
    arguments = parser.parse_args(argv)
    if type(arguments.control_sha) is not str or CONTROL_SHA.fullmatch(arguments.control_sha) is None:
        print(refusal_line(Refusal("invalid_control_identity", stage="context")))
        return 2
    try:
        receipt = _run_proof(arguments.control_sha)
        workspace = os.environ.get("CI_WORKSPACE", "")
        expected_uid = Path(workspace).stat().st_uid
        _write_step_output(receipt, expected_uid)
    except Refusal as error:
        print(refusal_line(error))
        return 1
    except BaseException:
        print(refusal_line(Refusal("native_preflight_unavailable", stage="preflight")))
        return 1
    print(
        "macos-confinement=observed boundary=seatbelt-deny-default native-proof=complete "
        "memory-canary=absent readable-file-canary=absent pf=enforced sandbox-selftest=enforced "
        "external-audit=pending control-sha=" + receipt["control_sha"]
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
