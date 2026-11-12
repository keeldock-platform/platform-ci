"""Executable source-free network topology and denial regressions."""

import errno
import ipaddress
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import network_probe


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
IPV4_ROUTE = """\
Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
lo\t0000007F\t00000000\t0001\t0\t0\t0\t000000FF\t0\t0\t0
"""
IPV6_ROUTE = """\
00000000000000000000000000000001 80 00000000000000000000000000000000 00 00000000000000000000000000000000 00000000 00000000 00000000 00000000 lo
"""
IPV6_ADDRESS = "00000000000000000000000000000001 01 80 10 80 lo\n"
NET_DEV = """\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo:       0       0    0    0    0     0          0         0        0       0    0    0    0     0       0          0
"""


def _proc_sys_fixture(testcase):
    temporary = tempfile.TemporaryDirectory()
    testcase.addCleanup(temporary.cleanup)
    base = Path(temporary.name)
    proc = base / "proc"
    sysfs = base / "sys"
    net = proc / "self/net"
    net.mkdir(parents=True)
    (proc / "net").symlink_to("self/net")
    (net / "dev").write_text(NET_DEV, encoding="ascii")
    (net / "fib_trie").write_text(FIB_TRIE, encoding="ascii")
    (net / "route").write_text(IPV4_ROUTE, encoding="ascii")
    (net / "ipv6_route").write_text(IPV6_ROUTE, encoding="ascii")
    (net / "if_inet6").write_text(IPV6_ADDRESS, encoding="ascii")
    device = sysfs / "devices/virtual/net/lo"
    device.mkdir(parents=True)
    (device / "flags").write_text("0x9\n", encoding="ascii")
    (device / "type").write_text("772\n", encoding="ascii")
    (device / "ifindex").write_text("1\n", encoding="ascii")
    net_class = sysfs / "class/net"
    net_class.mkdir(parents=True)
    (net_class / "lo").symlink_to("../../devices/virtual/net/lo")
    return proc, net_class, net


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
        self.assertIn('MOUNT_TARGETS.append(root / "sys")', source)

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

    def test_structural_readback_requires_loopback_link_up(self):
        proc, net_class, _net = _proc_sys_fixture(self)
        link_flags = net_class / "lo/flags"
        link_flags.write_text("0x8\n", encoding="ascii")
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
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-structure-unexpected"):
            network_probe.validate_probe(_snapshot(links=["lo", "eth0"], routes4=1), HOST_NET)

    def test_rtnetlink_route_parser_accepts_loopback_and_rejects_non_loopback_table_rows(self):
        destination = _route_attribute(network_probe.RTA_DST, ipaddress.IPv4Address("127.0.0.0").packed)
        output = _route_attribute(network_probe.RTA_OIF, struct.pack("=I", 1))
        loopback = struct.pack("=BBBBBBBBI", network_probe.socket.AF_INET, 8, 0, 0, 255,
                               2, 254, network_probe.RTN_LOCAL, 0) + destination + output
        network_probe._validate_route_payload(loopback, network_probe.socket.AF_INET, 1)

        external = struct.pack("=BBBBBBBBI", network_probe.socket.AF_INET, 8, 0, 0, 100,
                               3, 0, network_probe.RTN_UNICAST, 0)
        external += _route_attribute(network_probe.RTA_DST, ipaddress.IPv4Address("10.0.0.0").packed)
        external += output
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-route-unexpected"):
            network_probe._validate_route_payload(external, network_probe.socket.AF_INET, 1)

        v6_destination = _route_attribute(
            network_probe.RTA_DST, ipaddress.IPv6Address("::1").packed,
        )
        v6_loopback = struct.pack("=BBBBBBBBI", network_probe.socket.AF_INET6, 128, 0, 0, 255,
                                  2, 254, network_probe.RTN_LOCAL, 0) + v6_destination + output
        network_probe._validate_route_payload(v6_loopback, network_probe.socket.AF_INET6, 1)
        v6_external = struct.pack("=BBBBBBBBI", network_probe.socket.AF_INET6, 64, 0, 0, 100,
                                  3, 0, network_probe.RTN_UNICAST, 0)
        v6_external += _route_attribute(
            network_probe.RTA_DST, ipaddress.IPv6Address("2001:db8::").packed,
        ) + output
        with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-route-unexpected"):
            network_probe._validate_route_payload(v6_external, network_probe.socket.AF_INET6, 1)

    def test_rtnetlink_dump_reads_both_families_and_rejects_table_routes(self):
        class RouteSocket:
            def __init__(self, *, external=False):
                self.external = external
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
                if family == network_probe.socket.AF_INET:
                    destination = "10.0.0.0" if self.external else "127.0.0.0"
                    prefix = 8
                    route_type = network_probe.RTN_UNICAST if self.external else network_probe.RTN_LOCAL
                    address = ipaddress.IPv4Address(destination).packed
                else:
                    address = ipaddress.IPv6Address("::1").packed
                    prefix = 128
                    route_type = network_probe.RTN_LOCAL
                payload = struct.pack("=BBBBBBBBI", family, prefix, 0, 0, 100 if self.external else 255,
                                       3 if self.external else 2, 0 if self.external else 254,
                                       route_type, 0)
                payload += _route_attribute(network_probe.RTA_DST, address)
                payload += _route_attribute(network_probe.RTA_OIF, struct.pack("=I", 1))
                self.responses = [
                    _netlink_frame(network_probe.RTM_NEWROUTE, payload, sequence),
                    _netlink_frame(network_probe.NLMSG_DONE, b"", sequence),
                ]

            def recvfrom(self, _maximum):
                return self.responses.pop(0), (0, 0)

        with patch.object(network_probe.socket, "socket", side_effect=lambda *_: RouteSocket()):
            network_probe._check_rtnetlink_routes(1)
        with patch.object(network_probe.socket, "socket", side_effect=lambda *_: RouteSocket(external=True)):
            with self.assertRaisesRegex(network_probe.ProbeRefusal, "network-route-unexpected"):
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
