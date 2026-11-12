"""Executable source-free network topology and denial regressions."""

import errno
import ipaddress
import inspect
from pathlib import Path
import re
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import network_probe
import supervisor


HOST_NET = 100


FIB_TRIE = """\
Main:
  +-- 0.0.0.0/0 2 0 2
     +-- 0.0.0.0/0 2 0 2
        |-- 0.0.0.0
           /0 universe UNICAST
        +-- 127.0.0.0/8 2 0 2
           +-- 127.0.0.0/31 1 0 0
              |-- 127.0.0.0
                 /32 link BROADCAST
                 /8 host LOCAL
              |-- 127.0.0.1
                 /32 host LOCAL
              |-- 127.255.255.255
                 /32 link BROADCAST
Local:
  +-- 0.0.0.0/0 2 0 2
     +-- 0.0.0.0/0 2 0 2
        +-- 127.0.0.0/8 2 0 2
           +-- 127.0.0.0/31 1 0 0
              |-- 127.0.0.0
                 /32 link BROADCAST
                 /8 host LOCAL
              |-- 127.0.0.1
                 /32 host LOCAL
"""
IPV4_ROUTE = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT                                                       \n"
IPV6_ROUTE = """\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000002 00000000 80200001       lo
00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo
"""
IPV6_ADDRESS = "00000000000000000000000000000001 01 80 10 80       lo\n"
KERNEL_68_ROUTES = {
    network_probe.socket.AF_INET: (
        ("127.0.0.0", 8, network_probe.RTN_LOCAL, network_probe.RT_SCOPE_HOST),
        ("127.0.0.1", 32, network_probe.RTN_LOCAL, network_probe.RT_SCOPE_HOST),
        ("127.255.255.255", 32, network_probe.RTN_BROADCAST, network_probe.RT_SCOPE_LINK),
    ),
    network_probe.socket.AF_INET6: (
        ("::1", 128, network_probe.RTN_LOCAL, network_probe.RT_SCOPE_UNIVERSE),
    ),
}
NET_DEV = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
"""


def _proc_sys_fixture(testcase, *, fib_trie=FIB_TRIE, ipv4_route=IPV4_ROUTE,
                      ipv6_route=IPV6_ROUTE, ipv6_address=IPV6_ADDRESS, flags="0x9\n"):
    temporary = tempfile.TemporaryDirectory()
    testcase.addCleanup(temporary.cleanup)
    base = Path(temporary.name)
    proc = base / "proc"
    sysfs = base / "sys"
    net = proc / "self/net"
    net.mkdir(parents=True)
    (proc / "net").symlink_to("self/net")
    (net / "dev").write_text(NET_DEV, encoding="ascii")
    (net / "fib_trie").write_text(fib_trie, encoding="ascii")
    (net / "route").write_text(ipv4_route, encoding="ascii")
    (net / "ipv6_route").write_text(ipv6_route, encoding="ascii")
    (net / "if_inet6").write_text(ipv6_address, encoding="ascii")
    device = sysfs / "devices/virtual/net/lo"
    device.mkdir(parents=True)
    (device / "flags").write_text(flags, encoding="ascii")
    (device / "type").write_text("772\n", encoding="ascii")
    (device / "ifindex").write_text("1\n", encoding="ascii")
    net_class = sysfs / "class/net"
    net_class.mkdir(parents=True)
    (net_class / "lo").symlink_to("../../devices/virtual/net/lo")
    return proc, net_class, net


def _real_netns_dump_sections():
    fixture = Path(__file__).with_name("fixtures") / "real-netns-dump-ubuntu2404.txt"
    sections = {}
    section = None
    for line in fixture.read_text(encoding="utf-8").splitlines():
        columns = line.split("\t", 2)
        if (len(columns) != 3 or columns[0] != "dump"
                or columns[1] != "Dump loopback-only namespace routes"):
            continue
        timestamp_and_payload = columns[2]
        if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z .*", timestamp_and_payload) is None:
            continue
        payload = timestamp_and_payload.split("Z ", 1)[1]
        if payload.startswith("== "):
            section = payload[3:]
            sections[section] = []
        elif section is not None:
            sections[section].append(payload)
    return {name: "\n".join(lines) + ("\n" if lines else "")
            for name, lines in sections.items()}


def _fixture_snapshot(testcase, proc, net_class):
    with patch.object(network_probe, "PROC_ROOT", str(proc)), \
            patch.object(network_probe, "SYS_CLASS_NET", str(net_class)), \
            patch.object(network_probe.os, "stat", return_value=SimpleNamespace(st_ino=200)), \
            patch.object(network_probe, "_check_rtnetlink_routes"):
        return network_probe.structural_snapshot(HOST_NET)


def _route_attribute(kind, payload):
    value = struct.pack("=HH", 4 + len(payload), kind) + payload
    return value + b"\0" * ((-len(value)) & 3)


def _netlink_frame(message_type, payload, sequence):
    value = struct.pack("=IHHII", 16 + len(payload), message_type, 0, sequence, 0) + payload
    return value + b"\0" * ((-len(value)) & 3)


def _rtnetlink_route(family, destination, prefix, route_type, scope, *, table=255,
                     protocol=network_probe.RTPROT_KERNEL, oif=1, gateway=None):
    address = ipaddress.ip_address(destination)
    payload = struct.pack("=BBBBBBBBI", family, prefix, 0, 0, table, protocol,
                          scope, route_type, 0)
    if prefix:
        payload += _route_attribute(network_probe.RTA_DST, address.packed)
    if family == network_probe.socket.AF_INET6:
        payload += _route_attribute(network_probe.RTA_TABLE, struct.pack("=I", table))
        payload += _route_attribute(6, struct.pack("=I", 0))
        payload += _route_attribute(8, b"")
        payload += _route_attribute(12, b"\0" * 32)
        payload += _route_attribute(20, b"\0")
    if oif is not None:
        payload += _route_attribute(network_probe.RTA_OIF, struct.pack("=I", oif))
    if family == network_probe.socket.AF_INET:
        payload += _route_attribute(7, ipaddress.IPv4Address("127.0.0.1").packed)
    if gateway is not None:
        payload += _route_attribute(network_probe.RTA_GATEWAY, ipaddress.ip_address(gateway).packed)
    return payload


def _kernel_68_payloads(family):
    return [
        _rtnetlink_route(family, destination, prefix, route_type, scope)
        for destination, prefix, route_type, scope in KERNEL_68_ROUTES[family]
    ]


def _snapshot(*, links=None, routes4=None, probes=None):
    return {
        "namespace_inode": 200,
        "interfaces": ["lo"] if links is None else links,
        "routes": 0 if routes4 is None else routes4,
        "loopback": True,
        "probes": probes or {
            "ipv4_https": False, "ipv6_https": False, "dns_udp": False,
            "dns_tcp": False, "doh_direct_ip": False, "metadata": False,
        },
        "proxy_environment": {},
        "extra_fds": [],
        "identity": "65534:65534",
    }


class NetworkProbeTests(unittest.TestCase):
    def test_supervisor_mounts_proc_and_sys_for_worker_read_only(self):
        source = Path(network_probe.__file__).with_name("supervisor.py").read_text(encoding="utf-8")
        self.assertIn('"ro,hidepid=2,subset=pid"', source)
        self.assertIn('"ro,nosuid,nodev,noexec"', source)
        self.assertIn('str(root / "sys")', source)
        self.assertIn('_mount_fs(["mount", "-t", "proc"', source)
        self.assertIn('_mount_fs(["mount", "-t", "sysfs"', source)
        self.assertIn('MOUNT_TARGETS.append(Path(destination))', inspect.getsource(supervisor._mount_fs))
        cleanup_source = inspect.getsource(supervisor.Service._cleanup)
        self.assertIn('mount_reason = _unmount_tracked_mounts()', cleanup_source)
        self.assertLess(cleanup_source.index('_kill_workload_descendants()'),
                        cleanup_source.index('_unmount_tracked_mounts()'))
        self.assertIn('--make-rprivate', inspect.getsource(supervisor._mount_private))
        self.assertIn('--make-rprivate', Path(network_probe.__file__).with_name("prepare.py").read_text(
            encoding="utf-8"))

    def test_probe_proc_and_sys_mounts_are_unmounted_leaf_first(self):
        root = Path("/probe/root")
        proc, sysfs = root / "proc", root / "sys"
        mounted = {root, proc, sysfs}
        commands = []

        def run(argv, **_kwargs):
            commands.append(tuple(argv))
            mounted.remove(Path(argv[-1]))

        with patch.object(supervisor.os.path, "ismount", side_effect=lambda path: Path(path) in mounted), \
                patch.object(supervisor, "_run", side_effect=run):
            reason = supervisor._unmount_tracked_mounts((root, proc, sysfs))
        self.assertEqual(reason, "")
        self.assertEqual([command[-1] for command in commands], [str(sysfs), str(proc), str(root)])
        self.assertEqual(mounted, set())

    def test_refusal_result_parser_accepts_only_bounded_fixed_codes(self):
        code = "network-address-unexpected"
        result = network_probe.refusal_code_from_result(
            2, b"", ("network_probe_refusal=" + code + "\n").encode("ascii"),
        )
        self.assertEqual(result, code)
        for returncode, stdout, stderr in (
                (0, b"", b"network_probe_refusal=" + code.encode("ascii") + b"\n"),
                (2, b"unexpected", b"network_probe_refusal=" + code.encode("ascii") + b"\n"),
                (2, b"", b"network_probe_refusal=private-path\n"),
                (2, b"", b"network_probe_refusal=" + code.encode("ascii") + b"\nextra\n"),
                (2, b"", b"network_probe_refusal=" + code.encode("ascii")
                 + b"\n" + b"x" * network_probe.MAX_REFUSAL_OUTPUT_BYTES),
        ):
            with self.subTest(stderr=stderr[:96]):
                self.assertIsNone(network_probe.refusal_code_from_result(returncode, stdout, stderr))

        route_detail = (
            "route[table=main,type=unicast,family=4,dst=0.0.0.0/0,"
            "oif=lo,proto=boot,scope=universe]"
        )
        detailed = ("network_probe_refusal=network-route-unexpected " + route_detail + "\n").encode("ascii")
        self.assertEqual(network_probe.refusal_code_from_result(2, b"", detailed),
                         "network-route-unexpected")
        self.assertEqual(network_probe.refusal_message_from_result(2, b"", detailed),
                         "network-route-unexpected " + route_detail)
        for invalid in (
                detailed.replace(b"oif=lo", b"oif=private/path"),
                detailed.replace(b"network-route-unexpected", b"network-address-unexpected"),
                detailed.replace(b"proto=boot", b"proto=private-path")):
            self.assertIsNone(network_probe.refusal_code_from_result(2, b"", invalid))

    def test_reachable_external_control_is_required_before_the_cut(self):
        class Connected:
            def close(self):
                pass

        self.assertEqual(network_probe.positive_control(connector=lambda address, timeout: Connected()),
                         {"connected": True, "target": "public-tls-control"})
        for error in (TimeoutError(), OSError(errno.ECONNREFUSED, "refused"),
                      OSError(errno.ENETUNREACH, "unreachable"), OSError(errno.EACCES, "permission")):
            with self.subTest(error=type(error).__name__), self.assertRaisesRegex(
                    network_probe.ProbeRefusal, "positive-control-unavailable"):
                network_probe.positive_control(connector=lambda address, timeout, e=error: (_ for _ in ()).throw(e))
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "positive-control-error"):
            network_probe.positive_control(connector=lambda address, timeout: (_ for _ in ()).throw(RuntimeError()))

    def test_active_external_probe_classifies_block_errors_and_rejects_reachability(self):
        blocked = (
            TimeoutError(),
            OSError(errno.ETIMEDOUT, "timed out"),
            OSError(errno.ECONNREFUSED, "refused"),
            OSError(errno.ENETUNREACH, "unreachable"),
            OSError(errno.EHOSTUNREACH, "host unreachable"),
            OSError(errno.EPERM, "denied"),
            OSError(errno.EACCES, "permission"),
        )
        for error in blocked:
            with self.subTest(error=repr(error)):
                operation = lambda e=error: (_ for _ in ()).throw(e)
                self.assertFalse(network_probe.require_external_blocked(operation))
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "external-connectivity"):
            network_probe.require_external_blocked(lambda: True)
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "external-probe-error"):
            network_probe.require_external_blocked(lambda: (_ for _ in ()).throw(RuntimeError()))

    def test_actual_socket_wrappers_refuse_unexpected_oserrors(self):
        wrappers = (
            lambda: network_probe._attempt_tcp("203.0.113.10", 443),
            lambda: network_probe._attempt_https("203.0.113.10"),
            lambda: network_probe._attempt_tcp_dns("203.0.113.10"),
        )
        for wrapper in wrappers:
            with self.subTest(wrapper=wrapper), patch.object(
                    network_probe.socket, "create_connection",
                    side_effect=OSError(errno.EBADF, "bad descriptor")):
                with self.assertRaisesRegex(network_probe.ProbeRefusal, "external-probe-error"):
                    network_probe.require_external_blocked(wrapper)

        class BadDatagram:
            def settimeout(self, timeout):
                pass
            def connect(self, address):
                raise OSError(errno.EBADF, "bad descriptor")
            def __enter__(self):
                return self
            def __exit__(self, *_):
                return False
        with patch.object(network_probe.socket, "socket", return_value=BadDatagram()):
            with self.assertRaisesRegex(network_probe.ProbeRefusal, "external-probe-error"):
                network_probe.require_external_blocked(lambda: network_probe._attempt_udp_dns("203.0.113.10"))

        with patch.object(network_probe.socket, "create_connection",
                          side_effect=OSError(errno.ENETUNREACH, "blocked")):
            self.assertFalse(network_probe.require_external_blocked(
                lambda: network_probe._attempt_tcp("203.0.113.10", 443)))

    def test_transport_reachability_survives_tls_http_and_dns_protocol_failures(self):
        raw = SimpleNamespace(close=lambda: None)
        with patch.object(network_probe.socket, "create_connection", return_value=raw), \
                patch.object(network_probe.ssl, "create_default_context") as context:
            context.return_value.wrap_socket.side_effect = network_probe.ssl.SSLError("synthetic handshake failure")
            with self.assertRaisesRegex(network_probe.ProbeRefusal, "external-connectivity"):
                network_probe.require_external_blocked(lambda: network_probe._attempt_https("203.0.113.10"))
        connection = SimpleNamespace(
            sendall=lambda payload: (_ for _ in ()).throw(OSError(errno.EPROTO, "synthetic DNS response failure")),
            close=lambda: None,
        )
        with patch.object(network_probe.socket, "create_connection", return_value=connection):
            with self.assertRaisesRegex(network_probe.ProbeRefusal, "external-connectivity"):
                network_probe.require_external_blocked(lambda: network_probe._attempt_tcp_dns("203.0.113.10"))

    def test_structural_readback_uses_ubuntu_proc_sys_fixtures_without_tools(self):
        proc, net_class, _net = _proc_sys_fixture(self)
        with patch.object(network_probe.subprocess, "run", side_effect=AssertionError("worker tool called")):
            self.assertEqual(_fixture_snapshot(self, proc, net_class), {
                "netns_inode": 200, "interfaces": ["lo"], "routes": 0,
            })

    def test_structural_readback_refuses_extra_interface_or_route_from_proc_sys(self):
        proc, net_class, net = _proc_sys_fixture(self)
        device = net_class.parent.parent / "devices/virtual/net/eth0"
        device.mkdir(parents=True)
        (device / "flags").write_text("0x1003\n", encoding="ascii")
        (device / "type").write_text("1\n", encoding="ascii")
        (device / "ifindex").write_text("2\n", encoding="ascii")
        (net_class / "eth0").symlink_to("../../devices/virtual/net/eth0")
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-interface-unexpected"):
            _fixture_snapshot(self, proc, net_class)

        (net_class / "eth0").unlink()
        for name in ("flags", "type", "ifindex"):
            (device / name).unlink()
        device.rmdir()
        (net / "route").write_text(IPV4_ROUTE +
                                   "lo 00000000 0100000A 0003 0 0 0 00000000 0 0 0\n",
                                   encoding="ascii")
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-route-unexpected"):
            _fixture_snapshot(self, proc, net_class)
        (net / "route").write_text(IPV4_ROUTE, encoding="ascii")
        (net / "ipv6_route").write_text(IPV6_ROUTE +
                                       "20010db8000000000000000000000000 20 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 00000000 lo\n",
                                       encoding="ascii")
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-route-unexpected"):
            _fixture_snapshot(self, proc, net_class)

    def test_real_ubuntu2404_netns_dump_and_negative_route_fixtures(self):
        sections = _real_netns_dump_sections()
        self.assertEqual(sections["/proc/net/route"], IPV4_ROUTE)
        self.assertEqual(sections["/proc/net/ipv6_route"], IPV6_ROUTE)
        self.assertEqual(sections["/proc/net/if_inet6"], IPV6_ADDRESS)
        self.assertEqual(sections["/sys/class/net/lo/flags"], "0x9\n")
        self.assertEqual(
            network_probe._ipv4_local_addresses(sections["fib_trie"]),
            {("127.0.0.0", 8), ("127.0.0.1", 32)},
        )
        proc, net_class, net = _proc_sys_fixture(
            self,
            fib_trie=sections["fib_trie"],
            ipv4_route=sections["/proc/net/route"],
            ipv6_route=sections["/proc/net/ipv6_route"],
            ipv6_address=sections["/proc/net/if_inet6"],
            flags=sections["/sys/class/net/lo/flags"],
        )

        class RouteSocket:
            def __init__(self):
                self.responses = []

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def settimeout(self, _timeout):
                pass

            def bind(self, address):
                if address != (0, 0):
                    raise AssertionError("route socket binding changed")

            def sendto(self, request, _address):
                _length, kind, flags, sequence, _pid = struct.unpack_from("=IHHII", request)
                if kind != network_probe.RTM_GETROUTE or flags != (
                        network_probe.NLM_F_REQUEST | network_probe.NLM_F_DUMP):
                    raise AssertionError("route dump request changed")
                family = request[16]
                self.responses = [
                    *(_netlink_frame(network_probe.RTM_NEWROUTE, payload, sequence)
                      for payload in _kernel_68_payloads(family)),
                    _netlink_frame(network_probe.NLMSG_DONE, b"", sequence),
                ]

            def recvfrom(self, _maximum):
                return self.responses.pop(0), (0, 0)

        with patch.object(network_probe, "PROC_ROOT", str(proc)), \
                patch.object(network_probe, "SYS_CLASS_NET", str(net_class)), \
                patch.object(network_probe.os, "stat", return_value=SimpleNamespace(st_ino=200)), \
                patch.object(network_probe.socket, "socket", side_effect=lambda *_: RouteSocket()):
            self.assertEqual(network_probe.structural_snapshot(HOST_NET), {
                "netns_inode": 200, "interfaces": ["lo"], "routes": 0,
            })

        (net / "route").write_text(
            sections["/proc/net/route"]
            + "lo\t0000007F\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0\n",
            encoding="ascii",
        )
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-route-unexpected"):
            _fixture_snapshot(self, proc, net_class)
        (net / "route").write_text(sections["/proc/net/route"], encoding="ascii")

        null_route = sections["/proc/net/ipv6_route"].splitlines()[0] + "\n"
        (net / "ipv6_route").write_text(
            sections["/proc/net/ipv6_route"] + null_route, encoding="ascii",
        )
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-route-unexpected"):
            _fixture_snapshot(self, proc, net_class)
        (net / "ipv6_route").write_text(
            sections["/proc/net/ipv6_route"].replace(" ffffffff ", " 00000000 ", 1),
            encoding="ascii",
        )
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-route-unexpected"):
            _fixture_snapshot(self, proc, net_class)
        (net / "ipv6_route").write_text(sections["/proc/net/ipv6_route"], encoding="ascii")

        (net / "fib_trie").write_text(
            sections["fib_trie"] + "        |-- 10.0.0.2\n           /32 host LOCAL\n",
            encoding="ascii",
        )
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-address-unexpected"):
            _fixture_snapshot(self, proc, net_class)

    def test_structural_readback_requires_exact_loopback_flags(self):
        proc, net_class, _net = _proc_sys_fixture(self)
        link_flags = net_class / "lo/flags"
        for flags in (0x8, 0x9 | 0x80, 0x9 | 0x100, 0x1009):
            with self.subTest(flags=hex(flags)):
                link_flags.write_text(hex(flags) + "\n", encoding="ascii")
                with self.assertRaisesRegex(network_probe.ProbeRefusal, "loopback-unavailable"):
                    _fixture_snapshot(self, proc, net_class)

    def test_structural_readback_refuses_non_loopback_ipv4_and_ipv6_addresses(self):
        proc, net_class, net = _proc_sys_fixture(self)
        (net / "fib_trie").write_text(FIB_TRIE +
                                      "              |-- 10.0.0.2\n                 /32 host LOCAL\n",
                                      encoding="ascii")
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-address-unexpected"):
            _fixture_snapshot(self, proc, net_class)

        (net / "fib_trie").write_text(FIB_TRIE, encoding="ascii")
        (net / "if_inet6").write_text(IPV6_ADDRESS +
                                     "20010db8000000000000000000000001 01 40 00 80 lo\n",
                                     encoding="ascii")
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-address-unexpected"):
            _fixture_snapshot(self, proc, net_class)
        for address_flags in ("00", "81"):
            (net / "if_inet6").write_text(
                IPV6_ADDRESS.replace(" 80       lo", " " + address_flags + "       lo"),
                encoding="ascii",
            )
            with self.subTest(address_flags=address_flags), self.assertRaisesRegex(
                    network_probe.ProbeRefusal, "network-address-unexpected"):
                _fixture_snapshot(self, proc, net_class)
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-structure-unexpected"):
            network_probe.validate_probe(_snapshot(links=["lo", "eth0"], routes4=1), HOST_NET)

    def test_rtnetlink_route_parser_accepts_v6_8_loopback_and_reports_sanitized_mismatch(self):
        for family in (network_probe.socket.AF_INET, network_probe.socket.AF_INET6):
            for payload in _kernel_68_payloads(family):
                self.assertIsNotNone(network_probe._validate_route_payload(payload, family, 1))

        local_without_oif = _rtnetlink_route(
            network_probe.socket.AF_INET, "127.0.0.0", 8, network_probe.RTN_LOCAL,
            network_probe.RT_SCOPE_HOST, oif=None,
        )
        self.assertIsNone(network_probe._validate_route_payload(
            local_without_oif, network_probe.socket.AF_INET, 1,
        )["oif"])

        default = _rtnetlink_route(
            network_probe.socket.AF_INET, "0.0.0.0", 0, network_probe.RTN_UNICAST,
            network_probe.RT_SCOPE_UNIVERSE, table=network_probe.RT_TABLE_MAIN,
            protocol=network_probe.RTPROT_BOOT,
        )
        with self.assertRaisesRegex(
                network_probe.ProbeRefusal,
                r"network-route-unexpected route\[table=main,type=unicast,family=4,"
                r"dst=0\.0\.0\.0/0,oif=lo,proto=boot,scope=universe\]",
        ):
            network_probe._validate_route_payload(default, network_probe.socket.AF_INET, 1)

        gateway = _rtnetlink_route(
            network_probe.socket.AF_INET, "127.0.0.0", 8, network_probe.RTN_LOCAL,
            network_probe.RT_SCOPE_HOST, gateway="127.0.0.1",
        )
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-route-unexpected route\\["):
            network_probe._validate_route_payload(gateway, network_probe.socket.AF_INET, 1)

    def test_rtnetlink_dump_accepts_kernel_68_fixture_and_refuses_default_interface_and_gateway(self):
        class RouteSocket:
            def __init__(self, extra_route=None, omit_broadcast=False):
                self.extra_route = extra_route
                self.omit_broadcast = omit_broadcast
                self.responses = []

            def __enter__(self):
                return self

            def __exit__(self, *_):
                return False

            def settimeout(self, _timeout):
                pass

            def bind(self, address):
                if address != (0, 0):
                    raise AssertionError("route socket binding changed")

            def sendto(self, request, _address):
                _length, kind, flags, sequence, _pid = struct.unpack_from("=IHHII", request)
                if kind != network_probe.RTM_GETROUTE or flags != (
                        network_probe.NLM_F_REQUEST | network_probe.NLM_F_DUMP):
                    raise AssertionError("route dump request changed")
                family = request[16]
                payloads = _kernel_68_payloads(family)
                if self.omit_broadcast and family == network_probe.socket.AF_INET:
                    payloads = payloads[:2]
                if self.extra_route is not None and family == network_probe.socket.AF_INET:
                    payloads.append(self.extra_route)
                self.responses = [
                    *(_netlink_frame(network_probe.RTM_NEWROUTE, payload, sequence)
                      for payload in payloads),
                    _netlink_frame(network_probe.NLMSG_DONE, b"", sequence),
                ]

            def recvfrom(self, _maximum):
                return self.responses.pop(0), (0, 0)

        with patch.object(network_probe.socket, "socket", side_effect=lambda *_: RouteSocket()):
            network_probe._check_rtnetlink_routes(1)

        negative_routes = {
            "default": _rtnetlink_route(
                network_probe.socket.AF_INET, "0.0.0.0", 0, network_probe.RTN_UNICAST,
                network_probe.RT_SCOPE_UNIVERSE, table=network_probe.RT_TABLE_MAIN,
                protocol=network_probe.RTPROT_BOOT,
            ),
            "extra-interface": _rtnetlink_route(
                network_probe.socket.AF_INET, "10.0.0.0", 24, network_probe.RTN_UNICAST,
                network_probe.RT_SCOPE_LINK, table=network_probe.RT_TABLE_MAIN, oif=2,
            ),
            "gateway": _rtnetlink_route(
                network_probe.socket.AF_INET, "127.0.0.0", 8, network_probe.RTN_LOCAL,
                network_probe.RT_SCOPE_HOST, gateway="127.0.0.1",
            ),
        }
        for name, route in negative_routes.items():
            with self.subTest(name=name), \
                    patch.object(network_probe.socket, "socket",
                                 side_effect=lambda *_, route=route: RouteSocket(route)), \
                    patch.object(network_probe.socket, "if_indextoname", return_value="eth0"):
                with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-route-unexpected"):
                    network_probe._check_rtnetlink_routes(1)

        with patch.object(network_probe.socket, "socket",
                          side_effect=lambda *_: RouteSocket(omit_broadcast=True)):
            network_probe._check_rtnetlink_routes(1)

    def test_firewall_readback_rejects_external_accept_rules_and_relaxed_policy(self):
        chains = {
            name: {"family": "inet", "table": "devlane", "name": name, "type": "filter",
                   "hook": name, "prio": 0, "policy": "drop"}
            for name in ("input", "output", "forward")
        }

        def rule(chain, key, device):
            return {"rule": {
                "family": "inet", "table": "devlane", "chain": chain,
                "expr": [
                    {"match": {"op": "==", "left": {"meta": {"key": key}}, "right": device}},
                    {"accept": None},
                ],
            }}

        rows = [
            {"table": {"family": "inet", "name": "devlane"}},
            *({"chain": value} for value in chains.values()),
            rule("input", "iifname", "lo"),
            rule("output", "oifname", "lo"),
        ]
        network_probe._validate_firewall_rows({("inet", "devlane")}, chains, rows, 2)
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "firewall-rule-(?:shape|set)"):
            network_probe._validate_firewall_rows(
                {("inet", "devlane")}, chains,
                rows[:-1] + [rule("output", "oifname", "eth0")], 2,
            )
        relaxed = {name: dict(value) for name, value in chains.items()}
        relaxed["output"]["policy"] = "accept"
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "firewall-policy"):
            network_probe._validate_firewall_rows({("inet", "devlane")}, relaxed, rows, 2)

    def test_controlled_reachable_egress_fails_after_cut(self):
        positive = _snapshot(probes={
            "ipv4_https": True, "ipv6_https": False, "dns_udp": False,
            "dns_tcp": False, "doh_direct_ip": False, "metadata": False,
        })
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "external-connectivity"):
            network_probe.validate_probe(positive, HOST_NET)


if __name__ == "__main__":
    unittest.main()
