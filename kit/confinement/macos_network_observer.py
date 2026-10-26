import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import shutil
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import time


SCHEMA_VERSION = 1
SHA_RE = re.compile(r"[a-f0-9]{40}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
INTERFACE_RE = re.compile(r"en[0-9]{1,2}\Z")
CAPTURE_INTERFACE_RE = re.compile(r"(?:en[0-9]{1,2}|lo0)\Z")
HASH_RE = re.compile(r"[a-f0-9]{64}\Z")
TCPDUMP_PATH = "/usr/sbin/tcpdump"
NETWORKSETUP_PATH = "/usr/sbin/networksetup"
IFCONFIG_PATH = "/sbin/ifconfig"
TEMP_ROOT = "/tmp"
TEMP_PREFIX = "macos-ci-network-"
MAX_INTERFACES = 4
MAX_CAPTURE_PACKETS = 2048
MAX_CAPTURE_BYTES = 1200000
MAX_TOTAL_CAPTURE_BYTES = MAX_INTERFACES * MAX_CAPTURE_BYTES
MAX_SNAPSHOT_BYTES = 512
MAX_HASHES = 16
MAX_COUNT = 65535
MAX_OBSERVATION_SECONDS = 3600
COMMAND_TIMEOUT_SECONDS = 8
STARTUP_WAIT_SECONDS = 3
STARTUP_POLL_SECONDS = 0.05
SELFTEST_DRAIN_SECONDS = 3
STOP_WAIT_SECONDS = 5
MAX_TOOL_OUTPUT_BYTES = 32768
MAX_CAPTURE_DIRECTORY_ENTRIES = MAX_INTERFACES
DNS_DOMAIN = "network-observer.invalid"
DNS_QUERY_ID = 0x4B44
REASONS = frozenset((
    "arguments_invalid", "binding_invalid", "interface_unavailable", "observer_unavailable",
    "capture_invalid", "cleanup_incomplete", "internal_error",
))
STAGES = frozenset(("arguments", "binding", "interface", "start", "finish", "parse", "cleanup", "selftest"))
SELFTEST_DIAGNOSTIC_STAGES = frozenset((
    "unknown", "fixture_setup", "capture_started", "dns_exchange", "tcp_exchange",
    "capture_drain", "capture_finished", "receipt",
))
NETWORK_ENV = {
    "HOME": "/var/empty",
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "TMPDIR": TEMP_ROOT,
    "TZ": "UTC",
}


class ObserverRefusal(Exception):
    def __init__(self, reason, stage, diagnostics=None):
        self.reason = reason if type(reason) is str and reason in REASONS else "internal_error"
        self.stage = stage if type(stage) is str and stage in STAGES else "finish"
        self.diagnostics = diagnostics
        super().__init__(self.reason)


def _valid_sha(value):
    return type(value) is str and SHA_RE.fullmatch(value) is not None


def _valid_decimal(value):
    return type(value) is str and DECIMAL_RE.fullmatch(value) is not None


def _selftest_diagnostics(stage, record, expected_dns_hash=None, expected_tcp_hash=None):
    stage_value = stage if type(stage) is str and stage in SELFTEST_DIAGNOSTIC_STAGES else "unknown"

    def count_value(name):
        if type(record) is not dict:
            return None
        value = record.get(name)
        return value if type(value) is int and 0 <= value <= MAX_COUNT else None

    def expected_match(name, expected_hash):
        if type(record) is not dict or type(expected_hash) is not str or HASH_RE.fullmatch(expected_hash) is None:
            return None
        values = record.get(name)
        if type(values) not in (list, tuple) or any(type(value) is not str for value in values):
            return None
        return expected_hash in values

    capture_limited = None
    if type(record) is dict and type(record.get("capture_limited")) is bool:
        capture_limited = record["capture_limited"]
    return {
        "selftest_stage": stage_value,
        "dns_query_count": count_value("dns_query_count"),
        "tcp_syn_count": count_value("tcp_syn_count"),
        "dns_expected_match": expected_match("dns_name_hashes", expected_dns_hash),
        "tcp_expected_match": expected_match("tcp_destination_hashes", expected_tcp_hash),
        "capture_limited": capture_limited,
    }


def _format_refusal_line(error, control_sha, run_id, run_attempt):
    line = (
        "macos-network-observer=refused schema=1 reason=" + error.reason
        + " stage=" + error.stage + " control-sha=" + control_sha
        + " run-id=" + run_id + " run-attempt=" + run_attempt
    )
    diagnostics = error.diagnostics
    expected = {
        "selftest_stage", "dns_query_count", "tcp_syn_count", "dns_expected_match",
        "tcp_expected_match", "capture_limited",
    }
    if type(diagnostics) is not dict or set(diagnostics) != expected:
        return line
    stage = diagnostics["selftest_stage"]
    if type(stage) is not str or stage not in SELFTEST_DIAGNOSTIC_STAGES:
        return line

    def count_text(name):
        value = diagnostics[name]
        if type(value) is int and 0 <= value <= MAX_COUNT:
            return str(value)
        if value is None:
            return "unknown"
        return None

    def match_text(name):
        value = diagnostics[name]
        if type(value) is bool:
            return "yes" if value else "no"
        if value is None:
            return "unknown"
        return None

    dns_count = count_text("dns_query_count")
    tcp_count = count_text("tcp_syn_count")
    dns_match = match_text("dns_expected_match")
    tcp_match = match_text("tcp_expected_match")
    limited = diagnostics["capture_limited"]
    if type(limited) is bool:
        limited_text = "true" if limited else "false"
    elif limited is None:
        limited_text = "unknown"
    else:
        return line
    if None in (dns_count, tcp_count, dns_match, tcp_match):
        return line
    return (
        line + " selftest-stage=" + stage
        + " dns-query-count=" + dns_count
        + " tcp-syn-count=" + tcp_count
        + " dns-expected-match=" + dns_match
        + " tcp-expected-match=" + tcp_match
        + " capture-limited=" + limited_text
    )


def _validated_binding(control_sha, run_id, run_attempt, source_sha):
    if not (_valid_sha(control_sha) and _valid_decimal(run_id) and _valid_decimal(run_attempt)):
        raise ObserverRefusal("binding_invalid", "binding")
    if source_sha is not None and not _valid_sha(source_sha):
        raise ObserverRefusal("binding_invalid", "binding")
    return {
        "control_sha": control_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "source_sha": source_sha if source_sha is not None else "none",
    }


def _require_macos_root(stage):
    if sys.platform != "darwin" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise ObserverRefusal("observer_unavailable", stage)


def _run_fixed_command(arguments, stage):
    try:
        result = subprocess.run(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=NETWORK_ENV,
            timeout=COMMAND_TIMEOUT_SECONDS,
            close_fds=True,
            check=False,
        )
    except BaseException:
        raise ObserverRefusal("observer_unavailable", stage) from None
    if (type(result.returncode) is not int or result.returncode != 0
            or type(result.stdout) is not bytes or len(result.stdout) > MAX_TOOL_OUTPUT_BYTES
            or type(result.stderr) is not bytes or len(result.stderr) > MAX_TOOL_OUTPUT_BYTES
            or result.stderr):
        raise ObserverRefusal("observer_unavailable", stage) from None
    return result.stdout


def _parse_hardware_devices(output):
    if type(output) is not bytes or len(output) > MAX_TOOL_OUTPUT_BYTES:
        raise ObserverRefusal("interface_unavailable", "interface")
    try:
        lines = output.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise ObserverRefusal("interface_unavailable", "interface") from None
    devices = []
    for line in lines:
        match = re.fullmatch(r"\s*Device:\s*([A-Za-z0-9_.-]+)\s*", line)
        if match is None:
            continue
        name = match.group(1)
        if INTERFACE_RE.fullmatch(name) is not None:
            if name in devices:
                raise ObserverRefusal("interface_unavailable", "interface")
            devices.append(name)
    return tuple(devices)


def _parse_capture_devices(output):
    if type(output) is not bytes or len(output) > MAX_TOOL_OUTPUT_BYTES:
        raise ObserverRefusal("interface_unavailable", "interface")
    try:
        lines = output.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise ObserverRefusal("interface_unavailable", "interface") from None
    devices = {}
    for line in lines:
        match = re.fullmatch(r"\s*[1-9][0-9]*\.([A-Za-z0-9_.-]+)(?:\s+(.*))?\s*", line)
        if match is None:
            raise ObserverRefusal("interface_unavailable", "interface")
        name = match.group(1)
        details = match.group(2) or ""
        flags_match = re.search(r"\[([A-Za-z, ]+)\]", details)
        flags = set() if flags_match is None else {item.strip() for item in flags_match.group(1).split(",")}
        if name in devices:
            raise ObserverRefusal("interface_unavailable", "interface")
        devices[name] = {"up": "Up" in flags, "running": "Running" in flags}
    return devices


def _parse_local_addresses(output):
    if type(output) is not bytes or len(output) > MAX_TOOL_OUTPUT_BYTES:
        raise ObserverRefusal("interface_unavailable", "interface")
    try:
        lines = output.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise ObserverRefusal("interface_unavailable", "interface") from None
    addresses = set()
    for line in lines:
        match = re.match(r"\s*inet\s+([^\s]+)", line)
        if match is None:
            match = re.match(r"\s*inet6\s+([^\s]+)", line)
        if match is None:
            continue
        address_text = match.group(1).split("%", 1)[0]
        try:
            address = ipaddress.ip_address(address_text)
        except ValueError:
            continue
        if not address.is_unspecified:
            addresses.add(str(address))
    return frozenset(addresses)


def _interface_key(name):
    match = re.fullmatch(r"en([0-9]{1,2})", name)
    return int(match.group(1)) if match is not None else MAX_INTERFACES + 1


def _system_interfaces():
    hardware_output = _run_fixed_command(
        (NETWORKSETUP_PATH, "-listallhardwareports"), "interface"
    )
    capture_output = _run_fixed_command((TCPDUMP_PATH, "-D"), "interface")
    hardware = _parse_hardware_devices(hardware_output)
    capture_devices = _parse_capture_devices(capture_output)
    names = sorted(
        (
            name for name in hardware
            if capture_devices.get(name) == {"up": True, "running": True}
        ),
        key=_interface_key,
    )
    if not names or len(names) > MAX_INTERFACES:
        raise ObserverRefusal("interface_unavailable", "interface")
    result = []
    for name in names:
        output = _run_fixed_command((IFCONFIG_PATH, name), "interface")
        addresses = _parse_local_addresses(output)
        if not addresses:
            raise ObserverRefusal("interface_unavailable", "interface")
        result.append({"name": name, "addresses": addresses})
    return tuple(result)


def _create_private_directory():
    path = None
    temp_root = None
    try:
        temp_root = os.path.realpath(TEMP_ROOT)
        root_info = os.stat(temp_root, follow_symlinks=False)
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0
                or not root_info.st_mode & stat.S_ISVTX):
            raise ValueError
        path = tempfile.mkdtemp(prefix=TEMP_PREFIX, dir=temp_root)
        os.chown(path, 0, 0)
        os.chmod(path, 0o700)
        resolved = os.path.realpath(path)
        info = os.stat(resolved, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o700
                or os.path.dirname(resolved) != temp_root
                or not os.path.basename(resolved).startswith(TEMP_PREFIX)):
            raise ValueError
        return resolved
    except BaseException:
        if path is not None and temp_root is not None:
            _discard_created_directory(path, temp_root)
        raise ObserverRefusal("observer_unavailable", "start") from None


def _discard_created_directory(path, temp_root):
    try:
        info = os.lstat(path)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or os.path.dirname(path) != temp_root
            or not os.path.basename(path).startswith(TEMP_PREFIX)
        ):
            raise ValueError
        shutil.rmtree(path)
        if os.path.lexists(path):
            raise OSError
    except BaseException:
        raise ObserverRefusal("cleanup_incomplete", "cleanup") from None


def _create_capture_file(directory, index):
    path = os.path.join(directory, "capture-" + str(index) + ".pcap")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        try:
            os.fchown(descriptor, 0, 0)
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)
    except BaseException:
        raise ObserverRefusal("observer_unavailable", "start") from None
    return path


def _read_capture_snapshot(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_size < 0
                    or info.st_size > MAX_CAPTURE_BYTES):
                raise ValueError
            if info.st_size < 24:
                return None
            chunks = []
            remaining = info.st_size
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    return None
                chunks.append(chunk)
                remaining -= len(chunk)
            after = os.fstat(descriptor)
            path_info = os.lstat(path)
            if ((after.st_dev, after.st_ino) != (info.st_dev, info.st_ino)
                    or not stat.S_ISREG(after.st_mode) or after.st_uid != 0
                    or after.st_nlink != 1 or stat.S_IMODE(after.st_mode) != 0o600
                    or after.st_size < info.st_size
                    or not stat.S_ISREG(path_info.st_mode)
                    or path_info.st_uid != 0 or path_info.st_nlink != 1
                    or stat.S_IMODE(path_info.st_mode) != 0o600
                    or (path_info.st_dev, path_info.st_ino) != (info.st_dev, info.st_ino)):
                raise ValueError
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except BaseException:
        raise ObserverRefusal("capture_invalid", "start") from None


def _capture_header_ready(path):
    data = _read_capture_snapshot(path)
    if data is None:
        return False
    unused_endian, snaplen, unused_linktype = _pcap_header(data[:24])
    if snaplen != MAX_SNAPSHOT_BYTES:
        raise ObserverRefusal("capture_invalid", "start")
    return True


def _wait_capture_ready(process, path):
    deadline = time.monotonic() + STARTUP_WAIT_SECONDS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ObserverRefusal("observer_unavailable", "start")
        if _capture_header_ready(path):
            if process.poll() is None:
                return
            raise ObserverRefusal("observer_unavailable", "start")
        time.sleep(STARTUP_POLL_SECONDS)
    raise ObserverRefusal("observer_unavailable", "start")


def _capture_filter(dns_udp_ports, dns_tcp_ports, tcp_ports=None):
    if tcp_ports is None:
        return "udp port 53 or tcp port 53 or (tcp[tcpflags] & 2 != 0)"
    udp_terms = ["udp port " + str(port) for port in sorted(dns_udp_ports)]
    tcp_terms = ["tcp port " + str(port) for port in sorted(tcp_ports)]
    terms = udp_terms + tcp_terms
    if not terms:
        raise ObserverRefusal("binding_invalid", "binding")
    return " or ".join(terms)


def _start_capture(directory, index, interface, filter_expression):
    path = _create_capture_file(directory, index)
    arguments = (
        TCPDUMP_PATH,
        "-i", interface["name"],
        "-n",
        "-p",
        "--immediate-mode",
        "-s", str(MAX_SNAPSHOT_BYTES),
        "-c", str(MAX_CAPTURE_PACKETS),
        "-U",
        "-w", path,
        filter_expression,
    )
    process = None
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=NETWORK_ENV,
            close_fds=True,
            start_new_session=True,
        )
        _wait_capture_ready(process, path)
    except BaseException:
        if process is not None:
            _terminate_unregistered_process(process)
        raise ObserverRefusal("observer_unavailable", "start") from None
    return {"interface": interface["name"], "addresses": interface["addresses"], "path": path, "process": process}


def _terminate_unregistered_process(process):
    try:
        if process.poll() is None:
            try:
                process.send_signal(signal.SIGINT)
            except ProcessLookupError:
                pass
        try:
            process.wait(timeout=STOP_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=STOP_WAIT_SECONDS)
        if process.poll() is None:
            raise OSError
    except BaseException:
        raise ObserverRefusal("cleanup_incomplete", "cleanup") from None


def _stop_capture(capture):
    process = capture["process"]
    try:
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            status = process.wait(timeout=STOP_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            try:
                status = process.wait(timeout=STOP_WAIT_SECONDS)
            except BaseException:
                raise ObserverRefusal("cleanup_incomplete", "cleanup") from None
        if type(status) is not int or status != 0:
            raise ObserverRefusal("observer_unavailable", "finish")
    except ObserverRefusal:
        raise
    except BaseException:
        raise ObserverRefusal("cleanup_incomplete", "cleanup") from None


def _read_capture_file(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        try:
            info = os.fstat(descriptor)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600
                    or info.st_size < 24 or info.st_size > MAX_CAPTURE_BYTES):
                raise ValueError
            chunks = []
            remaining = info.st_size
            while remaining:
                chunk = os.read(descriptor, min(65536, remaining))
                if not chunk:
                    raise ValueError
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise ValueError
            after = os.fstat(descriptor)
            if (after.st_dev, after.st_ino, after.st_size) != (info.st_dev, info.st_ino, info.st_size):
                raise ValueError
            return b"".join(chunks)
        finally:
            os.close(descriptor)
    except BaseException:
        raise ObserverRefusal("capture_invalid", "parse") from None


def _read_dns_name(message, start):
    labels = []
    cursor = start
    resume = None
    seen = set()
    total = 0
    for unused_index in range(128):
        if cursor >= len(message):
            return None, None
        length = message[cursor]
        if length == 0:
            next_offset = cursor + 1 if resume is None else resume
            canonical = b"".join(bytes((len(label),)) + label for label in labels) + b"\x00"
            return canonical, next_offset
        if length & 0xC0 == 0xC0:
            if cursor + 1 >= len(message):
                return None, None
            pointer = ((length & 0x3F) << 8) | message[cursor + 1]
            if pointer >= len(message) or pointer in seen:
                return None, None
            seen.add(pointer)
            if resume is None:
                resume = cursor + 2
            cursor = pointer
            continue
        if length & 0xC0 or length > 63:
            return None, None
        cursor += 1
        if cursor + length > len(message):
            return None, None
        label = message[cursor:cursor + length].lower()
        total += length + 1
        if total > 255:
            return None, None
        labels.append(label)
        cursor += length
    return None, None


def _dns_questions(payload, tcp):
    if tcp:
        if len(payload) < 14:
            return (), False
        message_length = int.from_bytes(payload[:2], "big")
        if message_length < 12 or message_length > len(payload) - 2:
            return (), False
        message = payload[2:2 + message_length]
    else:
        message = payload
    if len(message) < 12:
        return (), False
    flags = int.from_bytes(message[2:4], "big")
    if flags & 0x8000:
        return (), False
    question_count = int.from_bytes(message[4:6], "big")
    if question_count == 0:
        return (), False
    truncated = question_count > MAX_HASHES
    names = []
    offset = 12
    for unused_index in range(min(question_count, MAX_HASHES)):
        name, next_offset = _read_dns_name(message, offset)
        if name is None or next_offset is None or next_offset + 4 > len(message):
            return (), truncated
        names.append(name)
        offset = next_offset + 4
    return tuple(names), truncated


def _ipv4_transport(packet, offset):
    if offset + 20 > len(packet) or packet[offset] >> 4 != 4:
        return None
    header_length = (packet[offset] & 0x0F) * 4
    if header_length < 20 or offset + header_length > len(packet):
        return None
    total_length = int.from_bytes(packet[offset + 2:offset + 4], "big")
    if total_length < header_length or offset + total_length > len(packet):
        return None
    fragment = int.from_bytes(packet[offset + 6:offset + 8], "big")
    if fragment & 0x1FFF:
        return None
    protocol = packet[offset + 9]
    source = ipaddress.ip_address(packet[offset + 12:offset + 16])
    destination = ipaddress.ip_address(packet[offset + 16:offset + 20])
    return source, destination, protocol, packet[offset + header_length:offset + total_length]


def _ipv6_transport(packet, offset):
    if offset + 40 > len(packet) or packet[offset] >> 4 != 6:
        return None
    payload_length = int.from_bytes(packet[offset + 4:offset + 6], "big")
    end = offset + 40 + payload_length
    if end > len(packet):
        return None
    source = ipaddress.ip_address(packet[offset + 8:offset + 24])
    destination = ipaddress.ip_address(packet[offset + 24:offset + 40])
    next_header = packet[offset + 6]
    cursor = offset + 40
    for unused_index in range(8):
        if next_header in (0, 43, 60, 135, 139, 140):
            if cursor + 2 > end:
                return None
            length = (packet[cursor + 1] + 1) * 8
            following = packet[cursor]
        elif next_header == 44:
            if cursor + 8 > end:
                return None
            fragment = int.from_bytes(packet[cursor + 2:cursor + 4], "big")
            if fragment & 0xFFF8:
                return None
            length = 8
            following = packet[cursor]
        elif next_header == 51:
            if cursor + 2 > end:
                return None
            length = (packet[cursor + 1] + 2) * 4
            following = packet[cursor]
        else:
            return source, destination, next_header, packet[cursor:end]
        if length <= 0 or cursor + length > end:
            return None
        cursor += length
        next_header = following
    return None


def _network_packet(frame, linktype):
    if linktype == 1:
        if len(frame) < 14:
            return None
        offset = 14
        protocol = int.from_bytes(frame[12:14], "big")
        for unused_index in range(2):
            if protocol not in (0x8100, 0x88A8, 0x9100):
                break
            if offset + 4 > len(frame):
                return None
            protocol = int.from_bytes(frame[offset + 2:offset + 4], "big")
            offset += 4
        if protocol == 0x0800:
            return _ipv4_transport(frame, offset)
        if protocol == 0x86DD:
            return _ipv6_transport(frame, offset)
        return None
    if linktype in (0, 108):
        if len(frame) < 5:
            return None
        families = (struct.unpack("<I", frame[:4])[0], struct.unpack(">I", frame[:4])[0])
        if linktype == 108:
            families = (families[1], families[0])
        for family in families:
            if family == 2:
                return _ipv4_transport(frame, 4)
            if family in (10, 24, 28, 30):
                return _ipv6_transport(frame, 4)
        return None
    if linktype == 12:
        if not frame:
            return None
        version = frame[0] >> 4
        if version == 4:
            return _ipv4_transport(frame, 0)
        if version == 6:
            return _ipv6_transport(frame, 0)
    raise ObserverRefusal("capture_invalid", "parse")


def _pcap_header(data):
    if len(data) < 24:
        raise ObserverRefusal("capture_invalid", "parse")
    formats = {
        b"\xd4\xc3\xb2\xa1": "<",
        b"\xa1\xb2\xc3\xd4": ">",
        b"\x4d\x3c\xb2\xa1": "<",
        b"\xa1\xb2\x3c\x4d": ">",
    }
    endian = formats.get(data[:4])
    if endian is None:
        raise ObserverRefusal("capture_invalid", "parse")
    major, minor, unused_zone, unused_sigfigs, snaplen, linktype = struct.unpack(
        endian + "HHIIII", data[4:24]
    )
    linktype &= 0xFFFF
    if major != 2 or minor != 4 or snaplen <= 0 or snaplen > MAX_SNAPSHOT_BYTES:
        raise ObserverRefusal("capture_invalid", "parse")
    if linktype not in (0, 1, 12, 108):
        raise ObserverRefusal("capture_invalid", "parse")
    return endian, snaplen, linktype


def _add_digest(target, value, key):
    digest = hmac.new(key, value, hashlib.sha256).hexdigest()
    target.add(digest)
    if len(target) > MAX_HASHES:
        return set(sorted(target)[:MAX_HASHES]), True
    return target, False


def _parse_pcap(data, local_addresses, key, dns_udp_ports, dns_tcp_ports):
    endian, snaplen, linktype = _pcap_header(data)
    offset = 24
    packet_count = 0
    dns_query_count = 0
    tcp_syn_count = 0
    dns_hashes = set()
    tcp_hashes = set()
    hashes_truncated = False
    capture_limited = False
    while offset < len(data):
        if offset + 16 > len(data):
            raise ObserverRefusal("capture_invalid", "parse")
        unused_seconds, unused_fraction, captured_length, original_length = struct.unpack(
            endian + "IIII", data[offset:offset + 16]
        )
        offset += 16
        if (captured_length > snaplen or captured_length > MAX_SNAPSHOT_BYTES
                or original_length < captured_length or offset + captured_length > len(data)):
            raise ObserverRefusal("capture_invalid", "parse")
        frame = data[offset:offset + captured_length]
        offset += captured_length
        packet_count += 1
        if packet_count > MAX_CAPTURE_PACKETS:
            raise ObserverRefusal("capture_invalid", "parse")
        if captured_length < original_length:
            capture_limited = True
        packet = _network_packet(frame, linktype)
        if packet is None:
            continue
        source, destination, protocol, segment = packet
        source_text = str(source)
        if protocol == 17:
            if len(segment) < 8:
                continue
            source_port, destination_port, udp_length, unused_checksum = struct.unpack(
                "!HHHH", segment[:8]
            )
            if udp_length < 8 or udp_length > len(segment):
                continue
            if source_text in local_addresses and destination_port in dns_udp_ports:
                names, truncated = _dns_questions(segment[8:udp_length], False)
                if names:
                    dns_query_count = min(MAX_COUNT, dns_query_count + 1)
                    hashes_truncated = hashes_truncated or truncated
                    for name in names:
                        dns_hashes, overflow = _add_digest(dns_hashes, b"dns\x00" + name, key)
                        hashes_truncated = hashes_truncated or overflow
        elif protocol == 6:
            if len(segment) < 20:
                continue
            source_port, destination_port = struct.unpack("!HH", segment[:4])
            header_length = (segment[12] >> 4) * 4
            flags = segment[13]
            if header_length < 20 or header_length > len(segment):
                continue
            payload = segment[header_length:]
            if source_text in local_addresses and flags & 0x02 and not flags & 0x10:
                tcp_syn_count = min(MAX_COUNT, tcp_syn_count + 1)
                endpoint = (b"tcp\x00" + str(destination).encode("ascii") + b":"
                            + str(destination_port).encode("ascii"))
                tcp_hashes, overflow = _add_digest(tcp_hashes, endpoint, key)
                hashes_truncated = hashes_truncated or overflow
            if source_text in local_addresses and destination_port in dns_tcp_ports:
                names, truncated = _dns_questions(payload, True)
                if names:
                    dns_query_count = min(MAX_COUNT, dns_query_count + 1)
                    hashes_truncated = hashes_truncated or truncated
                    for name in names:
                        dns_hashes, overflow = _add_digest(dns_hashes, b"dns\x00" + name, key)
                        hashes_truncated = hashes_truncated or overflow
    if offset != len(data):
        raise ObserverRefusal("capture_invalid", "parse")
    return {
        "dns_query_count": dns_query_count,
        "tcp_syn_count": tcp_syn_count,
        "dns_name_hashes": tuple(sorted(dns_hashes)),
        "tcp_destination_hashes": tuple(sorted(tcp_hashes)),
        "hashes_truncated": hashes_truncated,
        "capture_limited": capture_limited or packet_count == MAX_CAPTURE_PACKETS,
        "packet_count": packet_count,
    }


def _wait_for_expected_fixture(session, capture, expected_dns_hash, expected_tcp_hash):
    deadline = time.monotonic() + SELFTEST_DRAIN_SECONDS
    while True:
        data = _read_capture_snapshot(capture["path"])
        if data is not None:
            try:
                parsed = _parse_pcap(
                    data,
                    capture["addresses"],
                    session._hash_key,
                    session._dns_udp_ports,
                    session._dns_tcp_ports,
                )
            except ObserverRefusal as error:
                if error.reason != "capture_invalid":
                    raise
            else:
                if (parsed["dns_query_count"] >= 1 and parsed["tcp_syn_count"] >= 1
                        and expected_dns_hash in parsed["dns_name_hashes"]
                        and expected_tcp_hash in parsed["tcp_destination_hashes"]):
                    return
        if time.monotonic() >= deadline or capture["process"].poll() is not None:
            raise ObserverRefusal("capture_invalid", "selftest")
        time.sleep(STARTUP_POLL_SECONDS)


def _remove_private_directory(directory):
    try:
        resolved = os.path.realpath(directory)
        info = os.stat(resolved, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
                or stat.S_IMODE(info.st_mode) != 0o700
                or os.path.dirname(resolved) != os.path.realpath(TEMP_ROOT)
                or not os.path.basename(resolved).startswith(TEMP_PREFIX)):
            raise ValueError
        shutil.rmtree(resolved)
        if os.path.lexists(resolved):
            raise OSError
    except BaseException:
        raise ObserverRefusal("cleanup_incomplete", "cleanup") from None


class ObservationSession:
    def __init__(self, binding, directory, captures, dns_udp_ports, dns_tcp_ports, started, hash_key):
        self._binding = binding
        self._directory = directory
        self._captures = tuple(captures)
        self._dns_udp_ports = frozenset(dns_udp_ports)
        self._dns_tcp_ports = frozenset(dns_tcp_ports)
        self._started = started
        self._hash_key = hash_key
        self._finished = False
        self._record = None

    def finish(self):
        if self._record is not None:
            record = dict(self._record)
            record["dns_name_hashes"] = list(self._record["dns_name_hashes"])
            record["tcp_destination_hashes"] = list(self._record["tcp_destination_hashes"])
            return record
        if self._finished:
            raise ObserverRefusal("internal_error", "finish")
        self._finished = True
        failure = None
        termination_confirmed = True
        for capture in self._captures:
            try:
                _stop_capture(capture)
            except ObserverRefusal as error:
                if failure is None or error.reason == "cleanup_incomplete":
                    failure = error
                if error.reason == "cleanup_incomplete":
                    termination_confirmed = False
        if not termination_confirmed:
            self._hash_key = b""
            raise ObserverRefusal("cleanup_incomplete", "cleanup")
        parsed = []
        if failure is None:
            try:
                total_bytes = 0
                for capture in self._captures:
                    data = _read_capture_file(capture["path"])
                    total_bytes += len(data)
                    if total_bytes > MAX_TOTAL_CAPTURE_BYTES:
                        raise ObserverRefusal("capture_invalid", "parse")
                    parsed.append(_parse_pcap(
                        data,
                        capture["addresses"],
                        self._hash_key,
                        self._dns_udp_ports,
                        self._dns_tcp_ports,
                    ))
            except ObserverRefusal as error:
                failure = error
            except BaseException:
                failure = ObserverRefusal("capture_invalid", "parse")
        cleanup_failure = None
        try:
            _remove_private_directory(self._directory)
        except ObserverRefusal as error:
            cleanup_failure = error
        self._hash_key = b""
        if cleanup_failure is not None:
            raise cleanup_failure
        if failure is not None:
            raise failure
        elapsed = time.monotonic() - self._started
        dns_count = min(MAX_COUNT, sum(item["dns_query_count"] for item in parsed))
        tcp_count = min(MAX_COUNT, sum(item["tcp_syn_count"] for item in parsed))
        dns_hashes = set()
        tcp_hashes = set()
        hashes_truncated = elapsed > MAX_OBSERVATION_SECONDS
        capture_limited = elapsed > MAX_OBSERVATION_SECONDS
        for item in parsed:
            dns_hashes.update(item["dns_name_hashes"])
            tcp_hashes.update(item["tcp_destination_hashes"])
            hashes_truncated = hashes_truncated or item["hashes_truncated"]
            capture_limited = capture_limited or item["capture_limited"]
        if len(dns_hashes) > MAX_HASHES:
            dns_hashes = set(sorted(dns_hashes)[:MAX_HASHES])
            hashes_truncated = True
        if len(tcp_hashes) > MAX_HASHES:
            tcp_hashes = set(sorted(tcp_hashes)[:MAX_HASHES])
            hashes_truncated = True
        self._record = {
            "schema_version": SCHEMA_VERSION,
            "status": "observed",
            "mode": "host-level",
            "control_sha": self._binding["control_sha"],
            "run_id": self._binding["run_id"],
            "run_attempt": self._binding["run_attempt"],
            "source_sha": self._binding["source_sha"],
            "interface_count": len(self._captures),
            "dns_query_count": dns_count,
            "tcp_syn_count": tcp_count,
            "dns_name_hashes": sorted(dns_hashes),
            "tcp_destination_hashes": sorted(tcp_hashes),
            "hashes_truncated": hashes_truncated,
            "capture_limited": capture_limited,
            "capture": "private",
            "cleanup": "complete",
            "worker_attribution": "not-claimed",
            "completeness": "not-claimed",
            "network_blocking": "not-claimed",
        }
        record = dict(self._record)
        record["dns_name_hashes"] = list(self._record["dns_name_hashes"])
        record["tcp_destination_hashes"] = list(self._record["tcp_destination_hashes"])
        return record


def _start_session(binding, interfaces, dns_udp_ports, dns_tcp_ports, filters):
    if type(interfaces) is not tuple or not interfaces or len(interfaces) > MAX_INTERFACES:
        raise ObserverRefusal("interface_unavailable", "interface")
    directory = _create_private_directory()
    captures = []
    try:
        for index, interface in enumerate(interfaces):
            if (type(interface) is not dict or set(interface) != {"name", "addresses"}
                    or type(interface["name"]) is not str
                    or CAPTURE_INTERFACE_RE.fullmatch(interface["name"]) is None
                    or type(interface["addresses"]) not in (set, frozenset)
                    or not interface["addresses"]):
                raise ObserverRefusal("interface_unavailable", "interface")
            expression = filters.get(interface["name"])
            if type(expression) is not str or not expression or len(expression) > 128:
                raise ObserverRefusal("binding_invalid", "binding")
            captures.append(_start_capture(directory, index, interface, expression))
        return ObservationSession(
            binding, directory, captures, dns_udp_ports, dns_tcp_ports, time.monotonic(), secrets.token_bytes(32)
        )
    except BaseException as error:
        failure = error if type(error) is ObserverRefusal else ObserverRefusal("observer_unavailable", "start")
        cleanup_safe = failure.reason != "cleanup_incomplete"
        for capture in captures:
            try:
                _stop_capture(capture)
            except ObserverRefusal as cleanup_error:
                if cleanup_error.reason == "cleanup_incomplete":
                    failure = cleanup_error
                    cleanup_safe = False
        if cleanup_safe:
            try:
                _remove_private_directory(directory)
            except ObserverRefusal as cleanup_error:
                failure = cleanup_error
        raise failure


def start_observation(control_sha, run_id, run_attempt, source_sha):
    binding = _validated_binding(control_sha, run_id, run_attempt, source_sha)
    _require_macos_root("start")
    interfaces = _system_interfaces()
    expression = _capture_filter(frozenset((53,)), frozenset((53,)))
    filters = {interface["name"]: expression for interface in interfaces}
    return _start_session(binding, interfaces, frozenset((53,)), frozenset((53,)), filters)


def _tcpdump_interfaces():
    output = _run_fixed_command((TCPDUMP_PATH, "-D"), "interface")
    return _parse_capture_devices(output)


def _encode_dns_name(domain):
    try:
        labels = domain.encode("ascii").split(b".")
    except UnicodeEncodeError:
        raise ObserverRefusal("internal_error", "selftest") from None
    if (not labels or any(not label or len(label) > 63 for label in labels)
            or sum(len(label) + 1 for label in labels) > 255):
        raise ObserverRefusal("internal_error", "selftest")
    return b"".join(bytes((len(label),)) + label for label in labels) + b"\x00"


def _make_dns_query():
    question = _encode_dns_name(DNS_DOMAIN) + struct.pack("!HH", 1, 1)
    return struct.pack("!HHHHHH", DNS_QUERY_ID, 0x0100, 1, 0, 0, 0) + question


def _make_dns_response(query):
    if len(query) < 12:
        raise ObserverRefusal("internal_error", "selftest")
    return query[:2] + struct.pack("!HHHHH", 0x8180, 1, 0, 0, 0) + query[12:]


def _selftest_record(binding):
    _require_macos_root("selftest")
    devices = _tcpdump_interfaces()
    if devices.get("lo0") != {"up": True, "running": True}:
        raise ObserverRefusal("interface_unavailable", "interface")
    dns_server = None
    tcp_server = None
    dns_client = None
    tcp_client = None
    accepted = None
    session = None
    session_finish_attempted = False
    failure = None
    record = None
    diagnostic_stage = "fixture_setup"
    expected_dns_hash = None
    expected_tcp_hash = None
    try:
        dns_server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_server.bind(("127.0.0.1", 0))
        dns_server.settimeout(3)
        dns_port = dns_server.getsockname()[1]
        tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        tcp_server.bind(("127.0.0.1", 0))
        tcp_server.listen(1)
        tcp_server.settimeout(3)
        tcp_port = tcp_server.getsockname()[1]
        interface = {"name": "lo0", "addresses": frozenset(("127.0.0.1", "::1"))}
        expression = _capture_filter(frozenset((dns_port,)), frozenset(), frozenset((tcp_port,)))
        session = _start_session(
            binding,
            (interface,),
            frozenset((dns_port,)),
            frozenset(),
            {"lo0": expression},
        )
        diagnostic_stage = "capture_started"
        expected_dns_hash = hmac.new(
            session._hash_key,
            b"dns\x00" + _encode_dns_name(DNS_DOMAIN),
            hashlib.sha256,
        ).hexdigest()
        expected_tcp_hash = hmac.new(
            session._hash_key,
            b"tcp\x00" + b"127.0.0.1:" + str(tcp_port).encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
        query = _make_dns_query()
        dns_client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_client.settimeout(3)
        diagnostic_stage = "dns_exchange"
        dns_client.sendto(query, ("127.0.0.1", dns_port))
        received_query, peer = dns_server.recvfrom(512)
        if received_query != query:
            raise ObserverRefusal("observer_unavailable", "selftest")
        dns_server.sendto(_make_dns_response(received_query), peer)
        response, unused_address = dns_client.recvfrom(512)
        if len(response) < 12 or response[:2] != query[:2] or not int.from_bytes(response[2:4], "big") & 0x8000:
            raise ObserverRefusal("observer_unavailable", "selftest")
        tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_client.settimeout(3)
        diagnostic_stage = "tcp_exchange"
        tcp_client.connect(("127.0.0.1", tcp_port))
        accepted, unused_address = tcp_server.accept()
        tcp_client.close()
        tcp_client = None
        accepted.close()
        accepted = None
        diagnostic_stage = "capture_drain"
        _wait_for_expected_fixture(
            session,
            session._captures[0],
            expected_dns_hash,
            expected_tcp_hash,
        )
        session_finish_attempted = True
        record = session.finish()
        session = None
        diagnostic_stage = "capture_finished"
    except ObserverRefusal as error:
        failure = error
    except BaseException:
        failure = ObserverRefusal("observer_unavailable", "selftest")
    finally:
        for item in (dns_client, tcp_client, accepted, dns_server, tcp_server):
            if item is not None:
                try:
                    item.close()
                except BaseException:
                    if failure is None:
                        failure = ObserverRefusal("cleanup_incomplete", "cleanup")
        if session is not None and not session_finish_attempted:
            session_finish_attempted = True
            try:
                cleanup_record = session.finish()
                if record is None:
                    record = cleanup_record
            except ObserverRefusal as error:
                if failure is None or error.reason == "cleanup_incomplete":
                    failure = error
    if failure is not None:
        raise ObserverRefusal(
            failure.reason,
            failure.stage,
            _selftest_diagnostics(
                diagnostic_stage,
                record,
                expected_dns_hash,
                expected_tcp_hash,
            ),
        )
    diagnostic_stage = "receipt"
    if (type(record) is not dict or record.get("dns_query_count", 0) < 1
            or type(expected_dns_hash) is not str
            or expected_dns_hash not in record.get("dns_name_hashes", ())
            or record.get("tcp_syn_count", 0) < 1
            or type(expected_tcp_hash) is not str
            or expected_tcp_hash not in record.get("tcp_destination_hashes", ())
            or record.get("capture_limited") is not False):
        raise ObserverRefusal(
            "capture_invalid",
            "selftest",
            _selftest_diagnostics(
                diagnostic_stage,
                record,
                expected_dns_hash,
                expected_tcp_hash,
            ),
        )
    return record


def _hash_field(values):
    if type(values) not in (tuple, list) or len(values) < 1 or len(values) > MAX_HASHES:
        raise ObserverRefusal("capture_invalid", "selftest")
    if any(type(value) is not str or HASH_RE.fullmatch(value) is None for value in values):
        raise ObserverRefusal("capture_invalid", "selftest")
    if tuple(sorted(set(values))) != tuple(values):
        raise ObserverRefusal("capture_invalid", "selftest")
    return ",".join(values)


def _format_selftest_record(record):
    required = {
        "schema_version", "status", "mode", "control_sha", "run_id", "run_attempt", "source_sha",
        "interface_count", "dns_query_count", "tcp_syn_count", "dns_name_hashes",
        "tcp_destination_hashes", "hashes_truncated", "capture_limited", "capture", "cleanup",
        "worker_attribution", "completeness", "network_blocking",
    }
    if type(record) is not dict or set(record) != required:
        raise ObserverRefusal("capture_invalid", "selftest")
    if (type(record["schema_version"]) is not int or record["schema_version"] != SCHEMA_VERSION
            or record["status"] != "observed" or record["mode"] != "host-level"
            or not _valid_sha(record["control_sha"]) or not _valid_decimal(record["run_id"])
            or not _valid_decimal(record["run_attempt"]) or record["source_sha"] != "none"
            or record["interface_count"] != 1 or type(record["interface_count"]) is not int
            or type(record["dns_query_count"]) is not int or not 1 <= record["dns_query_count"] <= MAX_COUNT
            or type(record["tcp_syn_count"]) is not int or not 1 <= record["tcp_syn_count"] <= MAX_COUNT
            or type(record["hashes_truncated"]) is not bool or record["capture_limited"] is not False
            or record["capture"] != "private" or record["cleanup"] != "complete"
            or record["worker_attribution"] != "not-claimed"
            or record["completeness"] != "not-claimed"
            or record["network_blocking"] != "not-claimed"):
        raise ObserverRefusal("capture_invalid", "selftest")
    dns_hashes = _hash_field(record["dns_name_hashes"])
    tcp_hashes = _hash_field(record["tcp_destination_hashes"])
    return (
        "macos-network-observer=selftest-passed schema=1 mode=host-level "
        + "control-sha=" + record["control_sha"]
        + " run-id=" + record["run_id"]
        + " run-attempt=" + record["run_attempt"]
        + " source-sha=none interface-count=1"
        + " dns-query-count=" + str(record["dns_query_count"])
        + " tcp-syn-count=" + str(record["tcp_syn_count"])
        + " dns-name-hashes=" + dns_hashes
        + " tcp-destination-hashes=" + tcp_hashes
        + " hashes-truncated=" + ("true" if record["hashes_truncated"] else "false")
        + " capture=private capture-limited=false cleanup=complete"
        + " worker-attribution=not-claimed completeness=not-claimed network-blocking=not-claimed"
    )


def _safe_identity_fields(environment):
    control_sha = environment.get("CI_SHA", "")
    run_id = environment.get("GITHUB_RUN_ID", "")
    run_attempt = environment.get("GITHUB_RUN_ATTEMPT", "")
    return (
        control_sha if _valid_sha(control_sha) else "unknown",
        run_id if _valid_decimal(run_id) else "unknown",
        run_attempt if _valid_decimal(run_attempt) else "unknown",
    )


def main(arguments=None, environ=None):
    actual_arguments = sys.argv[1:] if arguments is None else arguments
    environment = os.environ if environ is None else environ
    control_sha, run_id, run_attempt = _safe_identity_fields(environment)
    if type(actual_arguments) is not list or actual_arguments != ["selftest"]:
        error = ObserverRefusal("arguments_invalid", "arguments")
        sys.stdout.write(_format_refusal_line(error, control_sha, run_id, run_attempt) + "\n")
        return 1
    if (control_sha == "unknown" or run_id == "unknown" or run_attempt == "unknown"):
        error = ObserverRefusal("binding_invalid", "binding")
        sys.stdout.write(_format_refusal_line(error, control_sha, run_id, run_attempt) + "\n")
        return 1
    try:
        binding = _validated_binding(control_sha, run_id, run_attempt, None)
        record = _selftest_record(binding)
        line = _format_selftest_record(record)
    except ObserverRefusal as error:
        line = _format_refusal_line(error, control_sha, run_id, run_attempt)
        sys.stdout.write(line + "\n")
        return 1
    except BaseException:
        sys.stdout.write(
            "macos-network-observer=refused schema=1 reason=internal_error stage=selftest"
            + " control-sha=" + control_sha + " run-id=" + run_id
            + " run-attempt=" + run_attempt + "\n"
        )
        return 1
    sys.stdout.write(line + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
