import ast
import ctypes
import errno
import io
import os
import signal
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
from types import SimpleNamespace
import urllib.error
from unittest.mock import MagicMock, Mock, call, patch

import linux_harness as harness
from linux_harness import DENIED_SYSCALLS, AUDIT_ARCH_NATIVE, CHILD_SOURCE, MAX_PROBE_SECONDS, PROBES, SECCOMP_ALLOW, SECCOMP_DENY, SOCKET_FILTER, UNSHARE_ARGUMENTS, COMPAT_SYSCALL_BIT, ProofFailure, SockFprog, _drop_child, _enter_rootfs_and_launch, _expected_denial, _inside, _install_socket_filter, _run_probe, _supervise_child_process, _verify_child, _verify_netns, _verify_proc_routes, _require_empty_address_dump, _require_empty_route_dump, ROUTE_CHANGE_GROUPS, advance_supervision, outcome, valid_sha


class HarnessPolicyTests(unittest.TestCase):
    def test_proc_routes_allow_only_empty_or_exact_sentinel_for_cross_check(self):
        zero = "0" * 32
        null_route = f"{zero} 00 {zero} 00 {zero} ffffffff 00000001 00000000 00200200 lo\n"
        other_route = f"{zero} 00 {zero} 00 {zero} 00000001 00000001 00000000 00000001 lo\n"
        header = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"

        cases = (
            ("empty", header, "", None),
            ("ipv4", header + "lo 00000000 00000000 0001\n", "", 85),
            ("ipv6-null", header, null_route, None),
            ("two-ipv6-nulls", header, null_route * 2, None),
            ("ipv6-other", header, other_route, 87),
            ("ipv6-mixed", header, null_route + other_route, 87),
            ("ipv4-precedes-ipv6", header + "lo 00000000 00000000 0001\n", null_route, 85),
            ("malformed-ipv6", header, "unexpected-row\n", 87),
            ("oversized", header, "x" * 65537, 81),
        )
        for label, ipv4, ipv6, reason in cases:
            def route_file(path, mode, encoding=None):
                return io.StringIO(ipv4 if path == "/proc/net/route" else ipv6)

            with self.subTest(case=label), \
                 patch("linux_harness.open", create=True, side_effect=route_file):
                if reason is None:
                    self.assertIsNone(_verify_proc_routes())
                else:
                    with self.assertRaises(ProofFailure) as raised:
                        _verify_proc_routes()
                    self.assertEqual(raised.exception.reason, reason)
                    self.assertEqual(outcome(False, reason), f"linux-confinement=refused reason={reason}")

    def test_route_dump_requests_every_table_and_requires_exact_completion(self):
        for family in (socket.AF_INET, socket.AF_INET6):
            probe = Mock()
            probe.sendto.return_value = 28
            probe.recvmsg.return_value = (struct.pack("=IHHIIi", 20, 3, 2, 1, 19, 0), [], 0, (0, 0))
            self.assertIsNone(_require_empty_route_dump(probe, family, 1, 19))
            request, target = probe.sendto.call_args.args
            self.assertEqual(target, (0, 0))
            self.assertEqual(struct.unpack_from("=IHHII", request), (28, 26, 0x301, 1, 19))
            self.assertEqual(struct.unpack_from("=BBBBBBBBI", request, 16), (family, 0, 0, 0, 0, 0, 0, 0, 0))
            probe.recvmsg.assert_called_once_with(65536, 0)

    def test_address_dump_requests_every_interface_and_requires_exact_completion(self):
        for family in (socket.AF_INET, socket.AF_INET6):
            probe = Mock()
            probe.sendto.return_value = 24
            probe.recvmsg.return_value = (struct.pack("=IHHIIi", 20, 3, 2, 3, 19, 0), [], 0, (0, 0))
            self.assertIsNone(_require_empty_address_dump(probe, family, 3, 19))
            request, target = probe.sendto.call_args.args
            self.assertEqual(target, (0, 0))
            self.assertEqual(len(request), 24)
            self.assertEqual(struct.unpack_from("=IHHII", request), (24, 22, 0x301, 3, 19))
            self.assertEqual(struct.unpack_from("=BBBBI", request, 16), (family, 0, 0, 0, 0))
            probe.recvmsg.assert_called_once_with(65536, 0)

    def test_route_dump_refuses_malformed_partial_interrupted_or_filtered_messages(self):
        done = struct.pack("=IHHIIi", 20, 3, 2, 1, 19, 0)
        packets = [(b"", 18), (done[:15], 18), (done[:19], 18), (done + b"x", 18), (done + done, 18)]
        for offset in range(len(done)):
            for bit in range(8):
                packet = bytearray(done)
                packet[offset] ^= 1 << bit
                packets.append((bytes(packet), 19 if offset >= 16 else 18))
        for kind in (1, 2, 4, 16, 17, 20, 21, 25, 32, 33):
            packets.append((struct.pack("=IHHIIi", 20, kind, 2, 1, 19, 0), 18))
        packets.append((struct.pack("=IHHIIi", 20, 24, 2, 1, 19, 0), 16))
        for flags in (0, 1, 0x12, 0x22, 0x102, 0x202):
            packets.append((struct.pack("=IHHIIi", 20, 3, flags, 1, 19, 0), 18))
        for packet, reason in packets:
            probe = Mock()
            probe.sendto.return_value = 28
            probe.recvmsg.return_value = (packet, [], 0, (0, 0))
            with self.assertRaises(ProofFailure) as raised:
                _require_empty_route_dump(probe, socket.AF_INET, 1, 19)
            self.assertEqual(raised.exception.reason, reason)

    def test_every_route_object_refuses_with_its_family_reason_including_alternate_tables(self):
        for family, reason in ((socket.AF_INET, 16), (socket.AF_INET6, 17)):
            for table in (1, 253, 254, 255, 1000):
                for kind in (1, 2, 6, 7, 8, 9):
                    payload = struct.pack("=BBBBBBBBI", family, 0, 0, 0, min(table, 255), 2, 0, kind, 0)
                    payload += struct.pack("=HHI", 8, 15, table)
                    route = struct.pack("=IHHII", 16 + len(payload), 24, 2, 1, 19) + payload
                    for packet in (route, route + struct.pack("=IHHIIi", 20, 3, 2, 1, 19, 0)):
                        probe = Mock()
                        probe.sendto.return_value = 28
                        probe.recvmsg.return_value = (packet, [], 0, (0, 0))
                        with self.assertRaises(ProofFailure) as raised:
                            _require_empty_route_dump(probe, family, 1, 19)
                        self.assertEqual(raised.exception.reason, reason)

    def test_every_address_object_refuses_with_its_family_reason(self):
        for family, reason in ((socket.AF_INET, 49), (socket.AF_INET6, 50)):
            payload = struct.pack("=BBBBI", family, 8, 0x80, 254, 1) + struct.pack("=HH", 8, 2) + bytes((127, 0, 0, 1))
            address = struct.pack("=IHHII", 16 + len(payload), 20, 2, 3, 19) + payload
            for packet in (address, address + struct.pack("=IHHIIi", 20, 3, 2, 3, 19, 0)):
                probe = Mock()
                probe.sendto.return_value = 24
                probe.recvmsg.return_value = (packet, [], 0, (0, 0))
                with self.assertRaises(ProofFailure) as raised:
                    _require_empty_address_dump(probe, family, 3, 19)
                self.assertEqual(raised.exception.reason, reason)
        probe = Mock()
        probe.sendto.return_value = 24
        probe.recvmsg.return_value = (struct.pack("=IHHIIi", 20, 24, 2, 3, 19, 0), [], 0, (0, 0))
        with self.assertRaises(ProofFailure) as raised:
            _require_empty_address_dump(probe, socket.AF_INET, 3, 19)
        self.assertEqual(raised.exception.reason, 18)

    def test_route_dump_refuses_wrong_sender_truncation_and_ancillary_data(self):
        done = struct.pack("=IHHIIi", 20, 3, 2, 1, 19, 0)
        for ancillary, flags, sender in (([], 0x20, (0, 0)), ([], 0x8, (0, 0)), ([(1, 2, b"x")], 0, (0, 0)), ([], 0, (1, 0)), ([], 0, (0, 1))):
            probe = Mock()
            probe.sendto.return_value = 28
            probe.recvmsg.return_value = (done, ancillary, flags, sender)
            with self.assertRaises(ProofFailure) as raised:
                _require_empty_route_dump(probe, socket.AF_INET, 1, 19)
            self.assertEqual(raised.exception.reason, 15)
        for dump in (_require_empty_route_dump, _require_empty_address_dump):
            probe = Mock()
            probe.sendto.return_value = 27
            with self.assertRaises(ProofFailure) as raised:
                dump(probe, socket.AF_INET, 1, 19)
            self.assertEqual(raised.exception.reason, 14)
            probe.recvmsg.assert_not_called()

    def test_sentinel_cross_check_requires_every_dump_and_quiet_mutation_subscription(self):
        zero = "0" * 32
        sentinel = f"{zero} 00 {zero} 00 {zero} ffffffff 00000001 00000000 00200200 lo\n"
        done4 = (struct.pack("=IHHIIi", 20, 3, 2, 1, 19, 0), [], 0, (0, 0))
        done6 = (struct.pack("=IHHIIi", 20, 3, 2, 2, 19, 0), [], 0, (0, 0))
        address4 = (struct.pack("=IHHIIi", 20, 3, 2, 3, 19, 0), [], 0, (0, 0))
        address6 = (struct.pack("=IHHIIi", 20, 3, 2, 4, 19, 0), [], 0, (0, 0))
        mutation = (struct.pack("=IHHIIi", 20, 16, 0, 0, 0, 0), [], 0, (0, 1))
        empty = BlockingIOError(errno.EAGAIN, "empty")
        dumps = [done4, done6, address4, address6]
        cases = (
            ("complete", dumps + [empty], None),
            ("timeout-first", [TimeoutError()], 86),
            ("timeout-second", [done4, TimeoutError()], 86),
            ("timeout-address", [done4, done6, TimeoutError()], 86),
            ("overflow", [done4, OSError(errno.ENOBUFS, "overflow")], 86),
            ("changed-before-dump", [mutation], 15),
            ("changed-between-dumps", [done4, mutation], 15),
            ("changed-before-address-dump", [done4, done6, mutation], 15),
            ("changed-between-address-dumps", [done4, done6, address4, mutation], 15),
            ("changed-after-dumps", dumps + [mutation], 28),
            ("late-overflow", dumps + [OSError(errno.ENOBUFS, "overflow")], 29),
            ("wrong-final-error", dumps + [BlockingIOError(errno.EPERM, "denied")], 29),
            ("duplicate-completion", dumps + [address6], 28),
            ("stale-completion", [done4, done6, done6], 18),
        )
        for label, packets, reason in cases:
            probe = MagicMock()
            probe.__enter__.return_value = probe
            probe.getsockname.return_value = (19, ROUTE_CHANGE_GROUPS)
            probe.sendto.side_effect = lambda request, target: len(request)
            probe.recvmsg.side_effect = packets
            def route_file(path, mode, encoding=None):
                return io.StringIO("Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n" if path == "/proc/net/route" else sentinel)
            with self.subTest(case=label), \
                 patch("linux_harness.socket.AF_NETLINK", 16, create=True), \
                 patch("linux_harness.socket.socket", return_value=probe), \
                 patch("linux_harness._verify_interfaces_down", return_value=(((1, "lo"),), 0)), \
                 patch("linux_harness.open", create=True, side_effect=route_file):
                if reason is None:
                    self.assertIsNone(_verify_netns())
                    requests = [item.args[0] for item in probe.sendto.call_args_list]
                    self.assertEqual([struct.unpack_from("=HxxI", request, 4) for request in requests], [(26, 1), (26, 2), (22, 3), (22, 4)])
                    self.assertEqual([request[16] for request in requests], [socket.AF_INET, socket.AF_INET6] * 2)
                    probe.settimeout.assert_called_once_with(2)
                    probe.setsockopt.assert_called_once_with(270, 12, 1)
                    probe.bind.assert_called_once_with((0, 0x405d1))
                    probe.setblocking.assert_called_once_with(False)
                else:
                    with self.assertRaises(ProofFailure) as raised:
                        _verify_netns()
                    self.assertEqual(raised.exception.reason, reason)
            probe.__exit__.assert_called_once()

    def test_route_cross_check_refuses_interface_mutations_and_setup_errors(self):
        for states, reason in (
            ((ProofFailure(11),), 11),
            ((ProofFailure(12),), 12),
            (((((1, "lo"),), 0), (((2, "lo"),), 0)), 13),
            (((((1, "lo"),), 0), (((1, "lo"),), 1)), 13),
            (((((1, "lo"),), 0), ProofFailure(12)), 12),
        ):
            probe = MagicMock()
            probe.__enter__.return_value = probe
            probe.getsockname.return_value = (19, ROUTE_CHANGE_GROUPS)
            with patch("linux_harness.socket.AF_NETLINK", 16, create=True), \
                 patch("linux_harness.socket.socket", return_value=probe), \
                 patch("linux_harness._verify_interfaces_down", side_effect=states), \
                 patch("linux_harness._verify_proc_routes"), \
                 patch("linux_harness._require_empty_route_dump"), \
                 patch("linux_harness._require_empty_address_dump"):
                with self.assertRaises(ProofFailure) as raised:
                    _verify_netns()
                self.assertEqual(raised.exception.reason, reason)
        for identity in ((19, 0), (0, ROUTE_CHANGE_GROUPS), (0x100000000, ROUTE_CHANGE_GROUPS), (19, ROUTE_CHANGE_GROUPS | 2)):
            probe = MagicMock()
            probe.__enter__.return_value = probe
            probe.getsockname.return_value = identity
            with patch("linux_harness.socket.AF_NETLINK", 16, create=True), \
                 patch("linux_harness.socket.socket", return_value=probe), \
                 patch("linux_harness._verify_interfaces_down", side_effect=AssertionError("interfaces-before-identity")):
                with self.assertRaises(ProofFailure) as raised:
                    _verify_netns()
                self.assertEqual(raised.exception.reason, 10)
        for operation in ("settimeout", "setsockopt", "bind", "getsockname"):
            probe = MagicMock()
            probe.__enter__.return_value = probe
            getattr(probe, operation).side_effect = OSError(errno.EPERM, "denied")
            with patch("linux_harness.socket.AF_NETLINK", 16, create=True), patch("linux_harness.socket.socket", return_value=probe):
                with self.assertRaises(ProofFailure) as raised:
                    _verify_netns()
                self.assertEqual(raised.exception.reason, 86)

    def test_interface_readback_names_extra_interfaces_and_a_raised_loopback_apart(self):
        probe = SimpleNamespace(fileno=lambda: 5, close=lambda: None)
        for names, flags, reason in (
            (((1, "lo"),), 0x8, None),
            (((1, "lo"), (2, "eth0")), 0x8, 11),
            ((), 0x8, 11),
            (((2, "dummy"),), 0x8, 11),
            (((1, "lo"),), 0x9, 12),
        ):
            with self.subTest(names=names, flags=flags), \
                 patch("linux_harness.socket.if_nameindex", return_value=list(names)), \
                 patch("linux_harness.socket.socket", return_value=probe), \
                 patch("linux_harness.fcntl.ioctl", return_value=struct.pack("16sH22x", b"lo", flags)):
                if reason is None:
                    self.assertEqual(harness._verify_interfaces_down(), (names, flags))
                else:
                    with self.assertRaises(ProofFailure) as raised:
                        harness._verify_interfaces_down()
                    self.assertEqual(raised.exception.reason, reason)

    def test_public_probe_set_is_fixed_and_linux_only(self):
        self.assertEqual(
            PROBES,
            ("tcp", "udp", "dns", "http", "proxy", "redirect", "ipc", "socket-policy", "file", "environment", "process", "boundary"),
        )

    def test_runtime_namespace_command_has_bounded_child_teardown(self):
        self.assertIn("--kill-child=KILL", UNSHARE_ARGUMENTS)
        self.assertIn("--fork", UNSHARE_ARGUMENTS)
        self.assertTrue(all(flag in UNSHARE_ARGUMENTS for flag in ("--mount", "--pid", "--ipc", "--net")))
        self.assertNotIn("--user", UNSHARE_ARGUMENTS)

    def test_runtime_launch_uses_teardown_option_and_timeout(self):
        services = SimpleNamespace(
            tcp_port=1,
            udp_port=2,
            http_port=3,
            ipc_path="/tmp/socket",
            file_path="/tmp/file",
            condition=threading.Condition(),
            events=[],
        )
        result = SimpleNamespace(returncode=0, stdout=b"inner=accepted probe=tcp\n", stderr=b"")
        with patch("linux_harness._positive_control"), patch("linux_harness.shutil.which", return_value="/usr/bin/unshare"), patch("linux_harness.os.stat", return_value=SimpleNamespace(st_ino=1)), patch("linux_harness.subprocess.run", return_value=result) as run:
            _run_probe("tcp", services, "a" * 24, "/tmp/root", "b" * 40)
        command = run.call_args.args[0]
        self.assertIn("--kill-child=KILL", command)
        self.assertIn("--mount", command)
        self.assertIn("--pid", command)
        self.assertIn("--ipc", command)
        self.assertIn("--net", command)
        self.assertEqual(run.call_args.kwargs["timeout"], MAX_PROBE_SECONDS + 5)
        self.assertTrue(run.call_args.kwargs["close_fds"])

    def test_inner_probe_failures_have_fixed_numeric_reasons(self):
        services = SimpleNamespace(
            tcp_port=1,
            udp_port=2,
            http_port=3,
            ipc_path="/tmp/socket",
            file_path="/tmp/file",
            condition=threading.Condition(),
            events=[],
        )
        expected = b"inner=accepted probe=tcp\n"
        cases = (
            ("child-nonzero", SimpleNamespace(returncode=1, stdout=expected, stderr=b""), 82),
            ("stdout-mismatch", SimpleNamespace(returncode=0, stdout=b"opaque output", stderr=b""), 83),
            ("stderr-present", SimpleNamespace(returncode=0, stdout=expected, stderr=b"opaque output"), 84),
            ("nonzero-precedes-output", SimpleNamespace(returncode=1, stdout=b"opaque output", stderr=b"opaque output"), 82),
        )
        for label, result, reason in cases:
            with self.subTest(case=label), \
                 patch("linux_harness._positive_control") as control, \
                 patch("linux_harness.shutil.which", return_value="/usr/bin/unshare"), \
                 patch("linux_harness.os.stat", return_value=SimpleNamespace(st_ino=1)), \
                 patch("linux_harness.subprocess.run", return_value=result):
                with self.assertRaises(ProofFailure) as raised:
                    _run_probe("tcp", services, "a" * 24, "/tmp/root", "b" * 40)
                self.assertEqual(raised.exception.reason, reason)
                self.assertEqual(outcome(False, raised.exception.reason), "linux-confinement=refused reason=" + str(reason))
                control.assert_called_once()

    def test_only_exact_known_inner_refusals_cross_the_capture_boundary(self):
        services = SimpleNamespace(
            tcp_port=1,
            udp_port=2,
            http_port=3,
            ipc_path="/tmp/socket",
            file_path="/tmp/file",
            condition=threading.Condition(),
            events=[],
        )
        cases = (
            ("known-boundary", 1, b"inner=refused reason=53\n", b"", 53),
            ("ipv4-route", 1, b"inner=refused reason=85\n", b"", 85),
            ("ipv4-local-route", 1, b"inner=refused reason=16\n", b"", 16),
            ("ipv4-loopback-address", 1, b"inner=refused reason=49\n", b"", 49),
            ("restore-reason-stays-outside", 1, b"inner=refused reason=93\n", b"", 82),
            ("ipv6-null-route", 1, b"inner=refused reason=86\n", b"", 86),
            ("ipv6-other-route", 1, b"inner=refused reason=87\n", b"", 87),
            ("known-generic", 1, b"inner=refused reason=98\n", b"", 98),
            ("retired-route-reason", 1, b"inner=refused reason=59\n", b"", 82),
            ("unknown-reason", 1, b"inner=refused reason=54\n", b"", 82),
            ("arbitrary-number", 1, b"inner=refused reason=99\n", b"", 82),
            ("leading-zero", 1, b"inner=refused reason=053\n", b"", 82),
            ("extra-line", 1, b"inner=refused reason=53\nextra\n", b"", 82),
            ("stderr", 1, b"inner=refused reason=53\n", b"opaque output", 82),
            ("wrong-exit", 2, b"inner=refused reason=53\n", b"", 82),
            ("oversized", 1, b"inner=refused reason=53\n" + b"x" * 8192, b"", 82),
        )
        for label, returncode, stdout, stderr, reason in cases:
            with self.subTest(case=label), \
                 patch("linux_harness._positive_control") as control, \
                 patch("linux_harness.shutil.which", return_value="/usr/bin/unshare"), \
                 patch("linux_harness.os.stat", return_value=SimpleNamespace(st_ino=1)), \
                 patch("linux_harness.subprocess.run", return_value=SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)):
                with self.assertRaises(ProofFailure) as raised:
                    _run_probe("tcp", services, "a" * 24, "/tmp/root", "b" * 40)
                self.assertEqual(raised.exception.reason, reason)
                self.assertEqual(outcome(False, raised.exception.reason), "linux-confinement=refused reason=" + str(reason))
                control.assert_called_once()

    def test_embedded_synthetic_program_is_standalone_valid_python(self):
        tree = ast.parse(CHILD_SOURCE)
        functions = {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}
        self.assertIn("_expected_denial", functions)

    def test_supervision_requires_every_observed_process_state_in_order(self):
        stage = "start"
        events = (
            "parent-stopped",
            "descendant-stopped",
            "descendant-killed",
            "parent-stopped-again",
            "parent-resumed",
            "parent-exited",
            "descendant-reaped",
        )
        for event in events:
            stage = advance_supervision(stage, event)
        self.assertEqual(stage, "complete")
        for stage, event in (("start", "descendant-stopped"), ("parent-held", "parent-exited"), ("parent-dead", "parent-resumed")):
            with self.subTest(stage=stage, event=event):
                with self.assertRaises(ProofFailure):
                    advance_supervision(stage, event)

    def test_chrooted_launch_never_opens_devnull_and_preexec_closes_stdin(self):
        events = []
        arguments = SimpleNamespace(
            rootfs="/synthetic-root",
            probe="tcp",
            nonce="a" * 24,
            tcp=101,
            udp=102,
            dns=103,
            http=104,
            ipc="/tmp/ipc",
            file="/tmp/file",
        )
        def record(name):
            def call(*args, **kwargs):
                events.append((name, args, kwargs))
            return call

        def fake_open(path, mode, encoding=None):
            events.append(("open", (path, mode, encoding), {}))
            return io.StringIO()

        with patch("linux_harness.open", create=True, side_effect=fake_open), \
             patch("linux_harness.os.chmod", side_effect=record("chmod")), \
             patch("linux_harness.subprocess.Popen", side_effect=record("popen")) as popen:
            _enter_rootfs_and_launch(arguments, {"PATH": "/usr/bin"}, 11, 12)
        names = [item[0] for item in events]
        self.assertEqual(names, ["open", "chmod", "popen"])
        kwargs = popen.call_args.kwargs
        self.assertNotIn("stdin", kwargs)
        self.assertIs(kwargs["preexec_fn"], _drop_child)
        self.assertTrue(kwargs["close_fds"])
        self.assertEqual(kwargs["stdout"], 11)
        self.assertEqual(kwargs["stderr"], 12)

        class FakeLibc:
            @staticmethod
            def prctl(*args):
                return 0

        ordered = []
        with patch("linux_harness.ctypes.CDLL", return_value=FakeLibc()), \
             patch("linux_harness._install_socket_filter", side_effect=lambda: ordered.append(("filter",))), \
             patch("linux_harness.os.setgroups", create=True, side_effect=lambda value: ordered.append(("groups", value))), \
             patch("linux_harness.os.setresgid", create=True, side_effect=lambda *value: ordered.append(("gid", value))), \
             patch("linux_harness.os.setresuid", create=True, side_effect=lambda *value: ordered.append(("uid", value))), \
             patch("linux_harness.resource.setrlimit", side_effect=lambda *value: ordered.append(("limit", value))), \
             patch("linux_harness.os.close", side_effect=lambda fd: ordered.append(("close", fd))):
            _drop_child()
        self.assertEqual(ordered[-1], ("close", 0))
        self.assertEqual(ordered[-2][0], "limit")
        self.assertLess(ordered.index(("filter",)), next(index for index, item in enumerate(ordered) if item[0] == "limit"))

    def test_inside_calls_real_launch_helper_after_exactly_one_chroot(self):
        rootfs = "/tmp/linux-probe/root-tcp"
        arguments = SimpleNamespace(rootfs=rootfs, probe="tcp", nonce="c" * 24, tcp=101, udp=102, dns=53, http=104, ipc="/tmp/ipc", file="/tmp/file")
        expected_stdout = b"child-result=tcp:denied\n"
        expected_stderr = ("::warning::synthetic-log-canary-" + arguments.nonce + "\n").encode()
        events = []
        chroot_paths = []

        def chroot(path):
            events.append(("chroot", path))
            if chroot_paths:
                raise AssertionError("duplicate-chroot")
            chroot_paths.append(path)

        def fake_open(path, mode, encoding=None):
            events.append(("open", path))
            return io.StringIO()

        def read_capture(fd, size):
            return expected_stdout if fd == 13 else expected_stderr

        with patch.dict("linux_harness.os.environ", {"CONTROL_NETNS": "123"}), \
             patch("linux_harness.os.geteuid", return_value=0), \
             patch("linux_harness._prctl"), \
             patch("linux_harness.os.stat", return_value=SimpleNamespace(st_ino=456)), \
             patch("linux_harness._verify_netns", side_effect=lambda: events.append(("verify-netns",))) as verify_netns, \
             patch("linux_harness._make_rootfs", side_effect=lambda path: events.append(("rootfs", path)) or rootfs), \
             patch("linux_harness._write_capture", side_effect=[("out", 11, 13), ("err", 12, 14)]), \
             patch("linux_harness.os.chroot", side_effect=chroot), \
             patch("linux_harness.os.chdir", side_effect=lambda path: events.append(("chdir", path))), \
             patch("linux_harness.open", create=True, side_effect=fake_open), \
             patch("linux_harness.os.chmod", side_effect=lambda *args: events.append(("chmod", args))), \
             patch("linux_harness.subprocess.Popen", side_effect=lambda *args, **kwargs: events.append(("launch",)) or SimpleNamespace(pid=777)) as popen, \
             patch("linux_harness.os.close"), \
             patch("linux_harness._supervise_child_process", side_effect=lambda *args: events.append(("supervise", args))), \
             patch("linux_harness.os.lseek"), \
             patch("linux_harness.os.read", side_effect=read_capture):
            result = _inside(arguments)
        self.assertEqual(result, "inner=accepted probe=tcp\n")
        verify_netns.assert_called_once_with()
        self.assertEqual(chroot_paths, [rootfs])
        self.assertEqual([event[0] for event in events], ["verify-netns", "rootfs", "chroot", "chdir", "open", "chmod", "launch", "supervise"])
        self.assertNotIn("stdin", popen.call_args.kwargs)
        self.assertIs(popen.call_args.kwargs["preexec_fn"], _drop_child)
        self.assertEqual(popen.call_args.kwargs["stdout"], 11)
        self.assertEqual(popen.call_args.kwargs["stderr"], 12)
        environment = popen.call_args.kwargs["env"]
        self.assertEqual(environment["LC_ALL"], "C")
        locale = subprocess.run(
            [sys.executable, "-B", "-c", "import os; print(repr((os.environ.get('LC_ALL'), os.environ.get('LC_CTYPE'))))"],
            env=environment, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=5, check=True,
        )
        self.assertEqual(locale.stdout, "('C', None)\n")

    def test_inside_network_refusal_prevents_rootfs_chroot_and_child_launch(self):
        arguments = SimpleNamespace(rootfs="/tmp/root", probe="tcp", nonce="c" * 24, tcp=101, udp=102, dns=53, http=104, ipc="/tmp/ipc", file="/tmp/file")
        with patch.dict("linux_harness.os.environ", {"CONTROL_NETNS": "123"}), \
             patch("linux_harness.os.geteuid", return_value=0), \
             patch("linux_harness._prctl"), \
             patch("linux_harness.os.stat", return_value=SimpleNamespace(st_ino=456)), \
             patch("linux_harness._verify_netns", side_effect=ProofFailure(86)) as verify_netns, \
             patch("linux_harness._make_rootfs") as make_rootfs, \
             patch("linux_harness._write_capture", side_effect=AssertionError("capture-before-verification")) as capture, \
             patch("linux_harness.os.chroot") as chroot, \
             patch("linux_harness.os.chdir"), \
             patch("linux_harness._enter_rootfs_and_launch", side_effect=AssertionError("launch-before-verification")) as launch:
            with self.assertRaises(ProofFailure) as raised:
                _inside(arguments)
        self.assertEqual(raised.exception.reason, 86)
        verify_netns.assert_called_once_with()
        make_rootfs.assert_not_called()
        capture.assert_not_called()
        chroot.assert_not_called()
        launch.assert_not_called()

    def test_synthetic_environment_accepts_fixed_locale_and_rejects_unexpected_names(self):
        node = next(node for node in ast.walk(ast.parse(CHILD_SOURCE)) if isinstance(node, ast.If)
                    and isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name)
                    and node.test.left.id == "kind" and len(node.test.comparators) == 1
                    and isinstance(node.test.comparators[0], ast.Constant) and node.test.comparators[0].value == "environment")
        check = compile(ast.Module(body=node.body, type_ignores=[]), "synthetic", "exec")
        names = ("PATH", "LANG", "LC_ALL", "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "PROBE_KIND", "PROBE_NONCE", "PROBE_TCP", "PROBE_UDP", "PROBE_DNS", "PROBE_HTTP", "PROBE_IPC", "PROBE_FILE")
        scope = {"names": names}
        exec(check, scope)
        self.assertIs(scope["blocked"], True)
        for name in ("LC_CTYPE", "CONTROL_ENV_CANARY", "GITHUB_TOKEN", "ACTIONS_RUNTIME_TOKEN", "RUNNER_TEMP", "PYTHONPATH", "UNEXPECTED"):
            with self.subTest(name=name), self.assertRaises(RuntimeError):
                exec(check, {"names": names + (name,)})

    def test_supervisor_keeps_zombie_in_process_set_until_parent_exit_and_reap(self):
        pid, descendant = 71, 72
        expected_sets = []
        events = []
        process = SimpleNamespace(pid=pid, wait=lambda timeout: events.append(("parent-wait", timeout)) or 0)
        with patch("linux_harness._wait_for_stopped_process", side_effect=lambda value: events.append(("stopped", value))), \
             patch("linux_harness._verify_child", side_effect=lambda value, nonce: events.append(("verify-child", value, nonce))), \
             patch("linux_harness._verify_process_set", side_effect=lambda value: expected_sets.append(value)), \
             patch("linux_harness.os.kill", side_effect=lambda value, sig: events.append(("kill", value, sig))), \
             patch("linux_harness._wait_for_stopped_descendant", return_value=descendant), \
             patch("linux_harness._wait_for_process_state", side_effect=lambda value, state: events.append(("state", value, state))), \
             patch("linux_harness._children", return_value=(descendant,)), \
             patch("linux_harness.os.waitpid", return_value=(descendant, signal.SIGKILL)):
            stage = _supervise_child_process(process, "b" * 24)
        self.assertEqual(stage, "complete")
        self.assertEqual(expected_sets, [
            (1, pid),
            (1, pid, descendant),
            (1, pid, descendant),
            (1, pid, descendant),
            (1, descendant),
            (1,),
        ])
        self.assertIn(("state", descendant, "Z"), events)
        self.assertLess(events.index(("state", descendant, "Z")), events.index(("stopped", pid), 1))
        self.assertEqual(events[-1], ("parent-wait", MAX_PROBE_SECONDS))

    def test_control_sha_requires_full_lowercase_hex(self):
        accepted = "a" * 40
        self.assertTrue(valid_sha(accepted))
        for value in ("a" * 12, "A" * 40, "g" * 40, "a" * 41, None):
            with self.subTest(value_type=type(value).__name__):
                self.assertFalse(valid_sha(value))

    def test_public_outcomes_contain_only_fixed_fields(self):
        accepted = outcome(True, 0, "b" * 40)
        self.assertEqual(accepted, "linux-confinement=accepted control-sha=" + "b" * 40 + " reason=0")
        self.assertEqual(outcome(False, 7), "linux-confinement=refused reason=7")
        for reason in (-1, 100, True, "7"):
            with self.subTest(reason_type=type(reason).__name__):
                with self.assertRaises(ValueError):
                    outcome(False, reason)
        with self.assertRaises(ValueError):
            outcome(True, 0, "short")

    def test_only_specific_os_denials_count_as_blocked_access(self):
        self.assertTrue(_expected_denial("tcp", OSError(errno.EPERM, "opaque")))
        self.assertTrue(_expected_denial("proxy", urllib.error.URLError(OSError(errno.EPERM, "opaque"))))
        self.assertTrue(_expected_denial("dns", OSError(errno.EPERM, "opaque")))
        self.assertTrue(_expected_denial("ipc", OSError(errno.EPERM, "opaque")))
        self.assertTrue(_expected_denial("file", OSError(errno.ENOENT, "opaque")))
        self.assertFalse(_expected_denial("tcp", OSError(errno.ETIMEDOUT, "opaque")))
        self.assertFalse(_expected_denial("dns", socket.gaierror(socket.EAI_NONAME, "opaque")))
        self.assertFalse(_expected_denial("ipc", OSError(errno.EACCES, "opaque")))
        self.assertFalse(_expected_denial("file", OSError(errno.EACCES, "opaque")))
        self.assertFalse(_expected_denial("http", urllib.error.URLError("opaque")))
        self.assertFalse(_expected_denial("unknown", ProofFailure(1)))
        for kind in ("tcp", "udp", "dns", "http", "proxy", "redirect", "ipc"):
            for value in (errno.ENETUNREACH, errno.ECONNREFUSED, errno.ENOENT, errno.EACCES):
                self.assertFalse(_expected_denial(kind, OSError(value, "opaque")))
        self.assertFalse(_expected_denial("dns", socket.gaierror(socket.EAI_AGAIN, "opaque")))

    @staticmethod
    def _evaluate_filter(architecture, number, domain=0, kind=0):
        data = struct.pack("<IIQ6Q", number, architecture, 0, domain, kind, *([0] * 4))
        accumulator = 0
        pc = 0
        for _ in range(128):
            code, yes, no, value = SOCKET_FILTER[pc]
            if code == 0x20:
                accumulator = struct.unpack_from("<I", data, value)[0]
                pc += 1
            elif code == 0x15:
                pc += 1 + (yes if accumulator == value else no)
            elif code == 0x45:
                pc += 1 + (yes if accumulator & value else no)
            elif code == 0x54:
                accumulator &= value
                pc += 1
            elif code == 0x06:
                return value
            else:
                raise AssertionError("unexpected-filter-instruction")
        raise AssertionError("filter-did-not-return")

    def test_filter_denies_socket_and_ring_syscalls_in_every_supported_entry(self):
        evaluate = self._evaluate_filter
        for number in range(512):
            expected = SECCOMP_DENY if number in DENIED_SYSCALLS or number == harness.SOCKETPAIR_SYSCALL else SECCOMP_ALLOW
            self.assertEqual(evaluate(AUDIT_ARCH_NATIVE, number), expected)
            self.assertEqual(evaluate(AUDIT_ARCH_NATIVE, COMPAT_SYSCALL_BIT | number), SECCOMP_DENY)
            for architecture in (0x40000003, 0xC00000B7, 0, 0xFFFFFFFF):
                self.assertEqual(evaluate(architecture, number), SECCOMP_DENY)

    def test_filter_allows_socketpair_only_for_unix_stream_and_seqpacket(self):
        evaluate = self._evaluate_filter
        number = harness.SOCKETPAIR_SYSCALL
        unix = harness.AF_UNIX
        self.assertEqual(number, 53)
        self.assertEqual(unix, socket.AF_UNIX)
        self.assertEqual((harness.SOCK_STREAM, harness.SOCK_DGRAM, harness.SOCK_RAW, harness.SOCK_SEQPACKET), (1, 2, 3, 5))
        self.assertEqual(harness.SOCK_NONBLOCK, 0x800)
        self.assertEqual(harness.SOCK_CLOEXEC, 0x80000)
        self.assertEqual(harness.SOCK_FLAGS_CLEAR_MASK, 0xFFF7F7FF)
        flags = harness.SOCK_NONBLOCK | harness.SOCK_CLOEXEC
        for kind in (1, 5):
            for extra in (0, harness.SOCK_NONBLOCK, harness.SOCK_CLOEXEC, flags):
                with self.subTest(kind=kind, extra=extra):
                    self.assertEqual(evaluate(AUDIT_ARCH_NATIVE, number, unix, kind | extra), SECCOMP_ALLOW)
                    self.assertEqual(evaluate(AUDIT_ARCH_NATIVE, number, unix | (1 << 32), kind | extra), SECCOMP_ALLOW)
        denied_kinds = (
            0, 2, 3, 4, 6, 7, 10, 2 | harness.SOCK_CLOEXEC, 2 | harness.SOCK_NONBLOCK, 2 | flags,
            3 | harness.SOCK_CLOEXEC, 1 | 0x100, 5 | 0x100, 1 | 0x40000, 5 | 0x1000, 0x7FFFFFFF, 0xFFFFFFFF,
            harness.SOCK_CLOEXEC, harness.SOCK_NONBLOCK, flags,
        )
        for kind in denied_kinds:
            with self.subTest(kind=kind):
                self.assertEqual(evaluate(AUDIT_ARCH_NATIVE, number, unix, kind), SECCOMP_DENY)
        for domain in (0, socket.AF_INET, socket.AF_INET6, 16, 17, 40, 3, 0x7FFFFFFF, 0xFFFFFFFF, 40 | (1 << 32)):
            for kind in (1, 5, 2, 0, 1 | harness.SOCK_CLOEXEC):
                with self.subTest(domain=domain, kind=kind):
                    self.assertEqual(evaluate(AUDIT_ARCH_NATIVE, number, domain, kind), SECCOMP_DENY)
        for kind in (1, 5):
            self.assertEqual(evaluate(AUDIT_ARCH_NATIVE, COMPAT_SYSCALL_BIT | number, unix, kind), SECCOMP_DENY)
            for architecture in (0x40000003, 0xC00000B7, 0, 0xFFFFFFFF):
                self.assertEqual(evaluate(architecture, number, unix, kind), SECCOMP_DENY)

    def test_filter_still_denies_socket_in_every_domain_and_type_including_unix_stream(self):
        evaluate = self._evaluate_filter
        for domain in (0, socket.AF_UNIX, socket.AF_INET, socket.AF_INET6, 16, 17, 40, 0x7FFFFFFF):
            for kind in (0, 1, 2, 5):
                with self.subTest(domain=domain, kind=kind):
                    self.assertEqual(evaluate(AUDIT_ARCH_NATIVE, 41, domain, kind), SECCOMP_DENY)
        for number in (425, 426, 427):
            self.assertEqual(evaluate(AUDIT_ARCH_NATIVE, number, socket.AF_UNIX, 1), SECCOMP_DENY)

    def test_filter_layout_and_jump_offsets_are_exact(self):
        rule = harness.SOCKETPAIR_RULE
        self.assertEqual(len(rule), 9)
        self.assertEqual(len(SOCKET_FILTER), 6 + 9 + 2 * len(DENIED_SYSCALLS) + 1)
        self.assertEqual(len(SOCKET_FILTER), 70)
        self.assertEqual(SOCKET_FILTER[6:15], rule)
        self.assertEqual(
            rule,
            (
                (0x15, 0, 8, 53),
                (0x20, 0, 0, 16),
                (0x15, 0, 4, 1),
                (0x20, 0, 0, 24),
                (0x54, 0, 0, 0xFFF7F7FF),
                (0x15, 2, 0, 1),
                (0x15, 1, 0, 5),
                (0x06, 0, 0, SECCOMP_DENY),
                (0x06, 0, 0, SECCOMP_ALLOW),
            ),
        )
        self.assertEqual(6 + 1 + rule[0][2], 15)
        self.assertEqual(8 + 1 + rule[2][2], 13)
        self.assertEqual(SOCKET_FILTER[13], (0x06, 0, 0, SECCOMP_DENY))
        self.assertEqual(11 + 1 + rule[5][1], 14)
        self.assertEqual(12 + 1 + rule[6][1], 14)
        self.assertEqual(SOCKET_FILTER[14], (0x06, 0, 0, SECCOMP_ALLOW))
        for index, (code, yes, no, value) in enumerate(SOCKET_FILTER):
            if code in (0x15, 0x45):
                self.assertLess(index + 1 + max(yes, no), len(SOCKET_FILTER))
        self.assertEqual(SOCKET_FILTER[-1], (0x06, 0, 0, SECCOMP_ALLOW))

    def test_filter_installation_requires_success_and_exact_readback(self):
        before = {"NoNewPrivs": ["1"], "Seccomp": ["0"], "Seccomp_filters": ["0"]}
        after = {"NoNewPrivs": ["1"], "Seccomp": ["2"], "Seccomp_filters": ["1"]}
        installed = []

        def install(option, mode, pointer, unused1, unused2):
            self.assertEqual((option, mode, unused1, unused2), (22, 2, 0, 0))
            program = ctypes.cast(pointer, ctypes.POINTER(SockFprog)).contents
            installed.append(tuple((item.code, item.jt, item.jf, item.k) for item in program.filter[:program.len]))
            return 0

        with patch("linux_harness.sys.platform", "linux"), \
             patch("linux_harness.os.uname", return_value=SimpleNamespace(machine="x86_64")), \
             patch("linux_harness._read_status", side_effect=[before, after]), \
             patch("linux_harness.ctypes.CDLL", return_value=SimpleNamespace(prctl=install)):
            _install_socket_filter()
        self.assertEqual(installed, [SOCKET_FILTER])
        cases = (
            (before, after, -1, 88),
            (dict(before, NoNewPrivs=["0"]), after, 0, 88),
            (before, dict(after, Seccomp=["0"]), 0, 89),
            (before, dict(after, Seccomp_filters=["0"]), 0, 89),
            (before, dict(after, Seccomp_filters=["2"]), 0, 89),
            (dict(before, Seccomp_filters=["unknown"]), after, 0, 89),
        )
        for initial, final, result, reason in cases:
            with self.subTest(reason=reason, initial=initial, final=final), \
                 patch("linux_harness.sys.platform", "linux"), \
                 patch("linux_harness.os.uname", return_value=SimpleNamespace(machine="x86_64")), \
                 patch("linux_harness._read_status", side_effect=[initial, final]), \
                 patch("linux_harness.ctypes.CDLL", return_value=SimpleNamespace(prctl=lambda *args: result)):
                with self.assertRaises(ProofFailure) as raised:
                    _install_socket_filter()
                self.assertEqual(raised.exception.reason, reason)
        with patch("linux_harness.sys.platform", "linux"), patch("linux_harness.os.uname", return_value=SimpleNamespace(machine="aarch64")):
            with self.assertRaises(ProofFailure) as raised:
                _install_socket_filter()
            self.assertEqual(raised.exception.reason, 88)

    def test_synthetic_process_probe_rejects_each_successful_proc_access(self):
        node = next(node for node in ast.parse(CHILD_SOURCE).body if isinstance(node, ast.FunctionDef) and node.name == "_require_process_denials")
        for denied_environ, denied_fds in ((True, True), (True, False), (False, True), (False, False)):
            def access_environ(*args):
                if denied_environ:
                    raise PermissionError(errno.EACCES, "opaque")
                return io.BytesIO(b"synthetic")

            def access_fds(*args):
                if denied_fds:
                    raise PermissionError(errno.EPERM, "opaque")
                return ["1"]

            scope = {"os": SimpleNamespace(listdir=access_fds), "open": access_environ, "errno": errno}
            exec(compile(ast.Module(body=[node], type_ignores=[]), "synthetic", "exec"), scope)
            with self.subTest(environ=denied_environ, fds=denied_fds):
                if denied_environ and denied_fds:
                    scope["_require_process_denials"]()
                else:
                    with self.assertRaises(RuntimeError):
                        scope["_require_process_denials"]()

    def test_descendant_checks_socket_policy_before_stopping_and_refuses_on_failure(self):
        program = ast.parse(CHILD_SOURCE)
        fork = next(node for node in program.body if isinstance(node, ast.Assign)
                    and isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Attribute)
                    and isinstance(node.value.func.value, ast.Name) and node.value.func.value.id == "os"
                    and node.value.func.attr == "fork")
        branch = program.body[program.body.index(fork) + 1]
        code = compile(ast.Module(body=[fork, branch], type_ignores=[]), "synthetic", "exec")
        for refused in (False, True):
            events = []

            def require_policy():
                events.append(("policy",))
                if refused:
                    raise RuntimeError("socket-policy")

            def exit_child(status):
                events.append(("exit", status))
                raise SystemExit(status)

            policy = Mock(side_effect=require_policy)
            process = SimpleNamespace(fork=lambda: 0, getpid=lambda: 71,
                                      kill=lambda pid, signum: events.append(("stop", pid, signum)), _exit=exit_child)
            scope = {"os": process, "signal": signal, "_require_socket_policy": policy}
            with self.subTest(refused=refused):
                if refused:
                    with self.assertRaisesRegex(RuntimeError, "socket-policy"):
                        exec(code, scope)
                    self.assertEqual(events, [("policy",)])
                else:
                    with self.assertRaises(SystemExit) as raised:
                        exec(code, scope)
                    self.assertEqual(raised.exception.code, 0)
                    self.assertEqual(events, [("policy",), ("stop", 71, signal.SIGSTOP), ("exit", 0)])
                policy.assert_called_once_with()

    def test_synthetic_policy_challenges_native_x32_families_pairs_and_rings(self):
        node = next(node for node in ast.parse(CHILD_SOURCE).body if isinstance(node, ast.FunctionDef) and node.name == "_require_socket_policy")
        calls = []

        def syscall(number, *arguments):
            calls.append((number.value, tuple(value.value for value in arguments)))
            ctypes.set_errno(errno.EPERM)
            return -1

        ends = ((Mock(), Mock()), (Mock(), Mock()))
        fake_socket = SimpleNamespace(
            AF_UNIX=1, SOCK_STREAM=1, SOCK_SEQPACKET=5, socketpair=Mock(side_effect=list(ends)),
        )
        scope = {"ctypes": ctypes, "errno": errno, "socket": fake_socket}
        exec(compile(ast.Module(body=[node], type_ignores=[]), "synthetic", "exec"), scope)
        with patch("ctypes.CDLL", return_value=SimpleNamespace(syscall=syscall)):
            scope["_require_socket_policy"]()
        self.assertEqual({arguments[0] for number, arguments in calls if number == 41}, {1, 2, 10, 16, 17, 40, 0x7fffffff, 40 | (1 << 32)})
        self.assertEqual({arguments[0] for number, arguments in calls if number == 53}, {0, 1, 2, 10, 16, 17, 40, 0x7fffffff, 40 | (1 << 32)})
        self.assertEqual(
            {arguments[1] for number, arguments in calls if number == 53 and arguments[0] == 1},
            {0, 2, 3, 4, 6, 2 | 0x80000, 2 | 0x800, 3 | 0x80000, 1 | 0x100, 5 | 0x100, 1 | 0x40000, 0xffffffff},
        )
        self.assertEqual(
            {arguments[1] for number, arguments in calls if number == 53 and arguments[0] != 1},
            {1, 5},
        )
        self.assertEqual(
            [arguments[:2] for number, arguments in calls if number == COMPAT_SYSCALL_BIT | 53],
            [(0, 0), (1, 1), (1, 5)],
        )
        self.assertEqual({number for number, _ in calls}, {41, 53, 425, 426, 427, *(COMPAT_SYSCALL_BIT | number for number in (41, 53, 425, 426, 427))})
        self.assertEqual(fake_socket.socketpair.call_args_list, [call(1, 1), call(1, 5)])
        for pair in ends:
            for end in pair:
                end.close.assert_called_once_with()
        for result, error in ((0, errno.EPERM), (-1, errno.EAFNOSUPPORT), (-1, errno.EINVAL)):
            def wrong_denial(*args):
                ctypes.set_errno(error)
                return result
            with patch("ctypes.CDLL", return_value=SimpleNamespace(syscall=wrong_denial)):
                with self.assertRaises(RuntimeError):
                    scope["_require_socket_policy"]()
        refused_pair = SimpleNamespace(
            AF_UNIX=1, SOCK_STREAM=1, SOCK_SEQPACKET=5,
            socketpair=Mock(side_effect=PermissionError(errno.EPERM, "opaque")),
        )
        scope["socket"] = refused_pair
        with patch("ctypes.CDLL", return_value=SimpleNamespace(syscall=syscall)):
            with self.assertRaisesRegex(RuntimeError, "socket-policy"):
                scope["_require_socket_policy"]()

    def test_capture_verification_requires_exact_identity_and_write_only_regular_files(self):
        nonce = "c" * 24
        child = {"Uid": [str(harness.CHILD_UID)] * 4, "Gid": [str(harness.CHILD_GID)] * 4, "Groups": [], "NoNewPrivs": ["1"], "Seccomp": ["2"], "Seccomp_filters": ["1"]}
        child.update({key: ["0000000000000000"] for key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")})
        root = {"Seccomp_filters": ["0"]}
        regular = SimpleNamespace(st_dev=1, st_ino=20, st_uid=0, st_mode=stat.S_IFREG | 0o200)
        cases = (
            (regular, "flags:\t0100001\n", None),
            (SimpleNamespace(st_dev=1, st_ino=21, st_uid=0, st_mode=stat.S_IFREG | 0o200), "flags:\t1\n", 90),
            (SimpleNamespace(st_dev=1, st_ino=20, st_uid=0, st_mode=stat.S_IFSOCK | 0o200), "flags:\t1\n", 90),
            (SimpleNamespace(st_dev=1, st_ino=20, st_uid=harness.CHILD_UID, st_mode=stat.S_IFREG | 0o200), "flags:\t1\n", 90),
            (regular, "flags:\t2\n", 90),
            (regular, "flags:\t1\nflags:\t1\n", 90),
        )
        for actual, info, reason in cases:
            def file_stat(path, **kwargs):
                return actual if path.startswith("/proc/") else regular
            with self.subTest(info=info, mode=actual.st_mode, inode=actual.st_ino), \
                 patch("linux_harness._read_status", side_effect=[child, root]), \
                 patch("linux_harness.os.listdir", return_value=["2"]), \
                 patch("linux_harness._descriptor_targets", return_value={"1": "/capture/out-" + nonce, "2": "/capture/err-" + nonce}), \
                 patch("linux_harness.os.stat", side_effect=file_stat), \
                 patch("linux_harness.open", create=True, side_effect=lambda *args, **kwargs: io.StringIO(info)):
                if reason is None:
                    _verify_child(2, nonce)
                else:
                    with self.assertRaises(ProofFailure) as raised:
                        _verify_child(2, nonce)
                    self.assertEqual(raised.exception.reason, reason)


from test_linux_boundary import *
from test_linux_canaries import *
from test_linux_channels import *
from test_linux_fixtures import *
from test_linux_session import *
from test_linux_settings import *


class LoopbackProfileTests(unittest.TestCase):
    ARCH = AUDIT_ARCH_NATIVE
    FLAGS = harness.SOCK_NONBLOCK | harness.SOCK_CLOEXEC

    @staticmethod
    def _evaluate(rules, architecture, number, domain=0, kind=0, protocol=0):
        data = struct.pack("<IIQ6Q", number, architecture, 0, domain, kind, protocol, 0, 0, 0)
        accumulator = 0
        pc = 0
        for _ in range(256):
            code, yes, no, value = rules[pc]
            if code == 0x20:
                accumulator = struct.unpack_from("<I", data, value)[0]
                pc += 1
            elif code == 0x15:
                pc += 1 + (yes if accumulator == value else no)
            elif code == 0x45:
                pc += 1 + (yes if accumulator & value else no)
            elif code == 0x54:
                accumulator &= value
                pc += 1
            elif code == 0x06:
                return value
            else:
                raise AssertionError("unexpected-filter-instruction")
        raise AssertionError("filter-did-not-return")

    def _loopback(self, *arguments, **keywords):
        return self._evaluate(harness.LOOPBACK_SOCKET_FILTER, *arguments, **keywords)

    def _base(self, *arguments, **keywords):
        return self._evaluate(SOCKET_FILTER, *arguments, **keywords)

    def test_the_base_filter_is_unchanged_and_the_loopback_filter_adds_exactly_one_rule(self):
        rule = harness.INET_SOCKET_RULE
        self.assertEqual(len(rule), 11)
        self.assertEqual(
            SOCKET_FILTER, harness.SOCKET_FILTER_HEAD + harness.SOCKETPAIR_RULE + harness.SOCKET_FILTER_TAIL,
        )
        self.assertEqual(len(SOCKET_FILTER), 70)
        self.assertEqual(len(harness.LOOPBACK_SOCKET_FILTER), 81)
        self.assertEqual(harness.LOOPBACK_SOCKET_FILTER[:15], SOCKET_FILTER[:15])
        self.assertEqual(harness.LOOPBACK_SOCKET_FILTER[15:26], rule)
        self.assertEqual(harness.LOOPBACK_SOCKET_FILTER[26:], SOCKET_FILTER[15:])
        self.assertEqual(harness.LOOPBACK_SOCKET_FILTER[-1], (0x06, 0, 0, SECCOMP_ALLOW))
        self.assertLess(len(harness.LOOPBACK_SOCKET_FILTER), 4096)

    def test_the_new_rule_jump_offsets_land_on_the_right_instructions(self):
        rule = harness.INET_SOCKET_RULE
        self.assertEqual(rule[0], (0x15, 0, 10, 41))
        self.assertEqual(0 + 1 + rule[0][2], len(rule))
        self.assertEqual(2 + 1 + rule[2][2], 9)
        self.assertEqual(5 + 1 + rule[5][2], 9)
        self.assertEqual(7 + 1 + rule[7][1], 10)
        self.assertEqual(8 + 1 + rule[8][1], 10)
        self.assertEqual(rule[9], (0x06, 0, 0, SECCOMP_DENY))
        self.assertEqual(rule[10], (0x06, 0, 0, SECCOMP_ALLOW))
        self.assertEqual(
            (rule[2][3], rule[5][3], rule[7][3], rule[8][3]), (socket.AF_INET, socket.SOCK_STREAM, 0, socket.IPPROTO_TCP),
        )
        self.assertEqual((rule[1][3], rule[3][3], rule[6][3]), (16, 24, 32))
        for index, (code, yes, no, value) in enumerate(harness.LOOPBACK_SOCKET_FILTER):
            if code in (0x15, 0x45):
                self.assertLess(index + 1 + max(yes, no), len(harness.LOOPBACK_SOCKET_FILTER))

    def test_the_loopback_filter_allows_only_inet_tcp_stream_sockets(self):
        for extra in (0, harness.SOCK_NONBLOCK, harness.SOCK_CLOEXEC, self.FLAGS):
            for protocol in (0, socket.IPPROTO_TCP):
                with self.subTest(extra=extra, protocol=protocol):
                    self.assertEqual(
                        self._loopback(self.ARCH, 41, socket.AF_INET, socket.SOCK_STREAM | extra, protocol),
                        SECCOMP_ALLOW,
                    )
        self.assertEqual(
            self._loopback(self.ARCH, 41, socket.AF_INET | (1 << 32), socket.SOCK_STREAM, 0), SECCOMP_ALLOW,
        )

    def test_the_loopback_filter_denies_every_other_socket_domain_type_and_protocol(self):
        for domain in (0, socket.AF_UNIX, socket.AF_INET6, 16, 17, 40, 3, 0x7FFFFFFF, 0xFFFFFFFF, 2 | (1 << 32) | 1):
            with self.subTest(domain=domain):
                self.assertEqual(self._loopback(self.ARCH, 41, domain, socket.SOCK_STREAM, 0), SECCOMP_DENY)
                self.assertEqual(self._loopback(self.ARCH, 41, domain, socket.SOCK_DGRAM, 0), SECCOMP_DENY)
        for kind in (0, 2, 3, 4, 5, 6, 10, 2 | self.FLAGS, 3 | harness.SOCK_CLOEXEC, 1 | 0x100, 1 | 0x40000,
                     0x7FFFFFFF, 0xFFFFFFFF, harness.SOCK_CLOEXEC, self.FLAGS):
            with self.subTest(kind=kind):
                self.assertEqual(self._loopback(self.ARCH, 41, socket.AF_INET, kind, 0), SECCOMP_DENY)
        for protocol in (1, 2, 17, 33, 47, 58, 132, 136, 255, 262, 0x100, 0x7FFFFFFF, 0xFFFFFFFF):
            with self.subTest(protocol=protocol):
                self.assertEqual(
                    self._loopback(self.ARCH, 41, socket.AF_INET, socket.SOCK_STREAM, protocol), SECCOMP_DENY,
                )
        for architecture in (0x40000003, 0xC00000B7, 0, 0xFFFFFFFF):
            self.assertEqual(self._loopback(architecture, 41, socket.AF_INET, socket.SOCK_STREAM, 0), SECCOMP_DENY)
        self.assertEqual(
            self._loopback(self.ARCH, COMPAT_SYSCALL_BIT | 41, socket.AF_INET, socket.SOCK_STREAM, 0), SECCOMP_DENY,
        )

    def test_the_base_filter_still_denies_inet_sockets_for_every_gate_but_the_browser_gate(self):
        for kind in (socket.SOCK_STREAM, socket.SOCK_STREAM | self.FLAGS, socket.SOCK_DGRAM):
            for protocol in (0, socket.IPPROTO_TCP):
                with self.subTest(kind=kind, protocol=protocol):
                    self.assertEqual(self._base(self.ARCH, 41, socket.AF_INET, kind, protocol), SECCOMP_DENY)
                    self.assertEqual(self._base(self.ARCH, 41, socket.AF_INET6, kind, protocol), SECCOMP_DENY)

    def test_the_loopback_filter_keeps_socketpair_ring_and_mount_denials_identical(self):
        for number in range(512):
            if number == 41:
                continue
            for domain, kind in ((0, 0), (socket.AF_UNIX, 1), (socket.AF_UNIX, 5), (socket.AF_UNIX, 2),
                                 (socket.AF_INET, 1), (socket.AF_INET6, 1)):
                with self.subTest(number=number, domain=domain, kind=kind):
                    self.assertEqual(
                        self._loopback(self.ARCH, number, domain, kind), self._base(self.ARCH, number, domain, kind),
                    )
        for number in (101, 155, 161, 165, 166, 248, 249, 250, 272, 298, 308, 310, 311, 321, 323, 425, 426, 427,
                       428, 429, 430, 431, 432, 433, 438, 442):
            self.assertEqual(self._loopback(self.ARCH, number, socket.AF_INET, 1, 0), SECCOMP_DENY)
        self.assertEqual(self._loopback(self.ARCH, 53, socket.AF_UNIX, 1), SECCOMP_ALLOW)
        self.assertEqual(self._loopback(self.ARCH, 53, socket.AF_UNIX, 5), SECCOMP_ALLOW)
        self.assertEqual(self._loopback(self.ARCH, 53, socket.AF_UNIX, 2), SECCOMP_DENY)
        self.assertEqual(self._loopback(self.ARCH, 53, socket.AF_INET, 1), SECCOMP_DENY)

    def test_the_child_installs_the_loopback_filter_only_when_asked(self):
        libc = SimpleNamespace(prctl=lambda *arguments: 0)
        with patch("linux_harness.ctypes.CDLL", return_value=libc), \
             patch("linux_harness._install_socket_filter") as install, patch("linux_harness.os.close"):
            _drop_child((), True, False, True)
            install.assert_called_once_with(harness.LOOPBACK_SOCKET_FILTER)
        with patch("linux_harness.ctypes.CDLL", return_value=libc), \
             patch("linux_harness._install_socket_filter") as install, patch("linux_harness.os.close"):
            _drop_child((), True, False)
            install.assert_called_once_with()
        with patch("linux_harness.ctypes.CDLL", return_value=libc), \
             patch("linux_harness._install_socket_filter") as install, patch("linux_harness.os.close"):
            _drop_child((), False, False, True)
            install.assert_not_called()

    def test_the_loopback_program_is_installed_with_exact_readback(self):
        before = {"NoNewPrivs": ["1"], "Seccomp": ["0"], "Seccomp_filters": ["0"]}
        after = {"NoNewPrivs": ["1"], "Seccomp": ["2"], "Seccomp_filters": ["1"]}
        installed = []

        def install(option, mode, pointer, unused1, unused2):
            program = ctypes.cast(pointer, ctypes.POINTER(SockFprog)).contents
            installed.append(tuple((item.code, item.jt, item.jf, item.k) for item in program.filter[:program.len]))
            return 0

        with patch("linux_harness.sys.platform", "linux"), \
             patch("linux_harness.os.uname", return_value=SimpleNamespace(machine="x86_64")), \
             patch("linux_harness._read_status", side_effect=[before, after]), \
             patch("linux_harness.ctypes.CDLL", return_value=SimpleNamespace(prctl=install)):
            _install_socket_filter(harness.LOOPBACK_SOCKET_FILTER)
        self.assertEqual(installed, [harness.LOOPBACK_SOCKET_FILTER])

    def _interface(self, flags):
        state = {"flags": flags, "calls": []}

        def ioctl(descriptor, request, argument):
            state["calls"].append(request)
            if request == harness.SIOCSIFFLAGS:
                name, value = struct.unpack_from("16sH", argument)
                self.assertEqual(name.rstrip(b"\0"), b"lo")
                state["flags"] = value
            return struct.pack("16sH22x", b"lo", state["flags"])

        return state, ioctl

    def test_loopback_is_raised_and_lowered_on_the_named_interface_only(self):
        probe = SimpleNamespace(fileno=lambda: 5, close=lambda: None)
        state, ioctl = self._interface(0x8)
        with patch("linux_harness.socket.socket", return_value=probe), patch("linux_harness.fcntl.ioctl", side_effect=ioctl):
            harness._set_loopback(True)
            self.assertEqual(state["flags"], 0x9)
            harness._set_loopback(False)
            self.assertEqual(state["flags"], 0x8)
        self.assertEqual(state["calls"].count(harness.SIOCSIFFLAGS), 2)
        self.assertEqual(harness.SIOCSIFFLAGS, 0x8914)

    def test_loopback_changes_that_do_not_take_effect_or_fail_refuse(self):
        probe = SimpleNamespace(fileno=lambda: 5, close=lambda: None)
        state, ioctl = self._interface(0x8)

        def ignore(descriptor, request, argument):
            if request == harness.SIOCSIFFLAGS:
                return argument
            return ioctl(descriptor, request, argument)

        with patch("linux_harness.socket.socket", return_value=probe), patch("linux_harness.fcntl.ioctl", side_effect=ignore):
            with self.assertRaises(ProofFailure) as raised:
                harness._set_loopback(True)
            self.assertEqual(raised.exception.reason, 58)
        with patch("linux_harness.socket.socket", return_value=probe), \
             patch("linux_harness.fcntl.ioctl", side_effect=OSError(errno.EPERM, "denied")):
            with self.assertRaises(ProofFailure) as raised:
                harness._set_loopback(True)
            self.assertEqual(raised.exception.reason, 57)

    def test_loopback_ipv6_is_disabled_or_absent_and_anything_else_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = os.path.join(temporary, "disable_ipv6")
            with patch.object(harness, "LOOPBACK_IPV6_SYSCTL", target):
                harness._disable_loopback_ipv6()
            with open(target, "rt", encoding="ascii") as source:
                self.assertEqual(source.read(), "1")
            with patch.object(harness, "LOOPBACK_IPV6_SYSCTL", os.path.join(temporary, "absent", "disable_ipv6")):
                harness._disable_loopback_ipv6()
            with patch.object(harness, "LOOPBACK_IPV6_SYSCTL", temporary):
                with self.assertRaises(ProofFailure) as raised:
                    harness._disable_loopback_ipv6()
                self.assertEqual(raised.exception.reason, 57)
            with patch.object(harness, "LOOPBACK_IPV6_SYSCTL", target), patch.object(harness, "_read_sysctl", return_value="0"):
                with self.assertRaises(ProofFailure) as raised:
                    harness._disable_loopback_ipv6()
                self.assertEqual(raised.exception.reason, 57)

    def test_the_loopback_failure_reasons_are_public_inner_refusal_reasons(self):
        for reason in (57, 58):
            self.assertIn(reason, harness.INNER_REFUSAL_REASONS)

    def test_every_namespace_readback_check_has_its_own_public_inner_refusal_reason(self):
        reasons = (10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 28, 29, 49, 50, 81, 85, 86, 87)
        self.assertEqual(len(set(reasons)), len(reasons))
        self.assertEqual(len(set(harness.INNER_REFUSAL_REASONS)), len(harness.INNER_REFUSAL_REASONS))
        for reason in reasons:
            line = ("inner=refused reason=" + str(reason) + "\n").encode("ascii")
            self.assertIn(reason, harness.INNER_REFUSAL_REASONS)
            self.assertLessEqual(len(line), harness.MAX_INNER_REFUSAL_BYTES)
            self.assertEqual(harness.INNER_REFUSAL_LINES[line], reason)
            self.assertEqual(outcome(False, reason), "linux-confinement=refused reason=" + str(reason))
        for reason in (55, 93):
            self.assertNotIn(reason, harness.INNER_REFUSAL_REASONS)

    def _restore_control(self, reply, identity=(19, 0)):
        control = MagicMock()
        control.__enter__.return_value = control
        control.getsockname.return_value = identity
        control.sendto.side_effect = lambda request, target: len(request)
        control.recvmsg.side_effect = lambda size, flags: reply(control.sendto.call_args.args[0])
        return control

    def _ack(self, request, error=0, flags=0x100, length=36, sequence=1, port=19, kind=2, echo=None):
        echoed = request[:16] if echo is None else echo
        return struct.pack("=IHHIIi", length, kind, flags, sequence, port, error) + echoed

    def _restore(self, control, index=1):
        with patch("linux_harness.socket.AF_NETLINK", 16, create=True), \
             patch("linux_harness.socket.if_nametoindex", return_value=index) as lookup, \
             patch("linux_harness.socket.socket", return_value=control) as opened:
            result = harness._restore_loopback()
        return result, lookup, opened

    def test_loopback_restore_deletes_exactly_the_kernel_loopback_address_and_requires_its_ack(self):
        address = bytes((127, 0, 0, 1))
        for flags in (0, 0x100):
            control = self._restore_control(lambda request: (self._ack(request, flags=flags), [], 0, (0, 0)))
            result, lookup, opened = self._restore(control, index=1)
            self.assertIsNone(result)
            lookup.assert_called_once_with("lo")
            opened.assert_called_once_with(16, socket.SOCK_RAW, 0)
            control.settimeout.assert_called_once_with(2)
            control.bind.assert_called_once_with((0, 0))
            request, target = control.sendto.call_args.args
            self.assertEqual(target, (0, 0))
            self.assertEqual(len(request), 40)
            self.assertEqual(struct.unpack_from("=IHHII", request), (40, 21, 5, 1, 19))
            self.assertEqual(struct.unpack_from("=BBBBI", request, 16), (socket.AF_INET, 8, 0, 0, 1))
            self.assertEqual(request[24:], struct.pack("=HH", 8, 2) + address + struct.pack("=HH", 8, 1) + address)
            control.recvmsg.assert_called_once_with(65536, 0)
            control.__exit__.assert_called_once()

    def test_loopback_restore_refuses_a_kernel_refusal_and_every_unexpected_reply(self):
        cases = (
            ("address-absent", lambda request: (self._ack(request, error=-errno.EADDRNOTAVAIL, flags=0, length=60, echo=request), [], 0, (0, 0)), 93),
            ("not-permitted", lambda request: (self._ack(request, error=-errno.EPERM, flags=0, length=60, echo=request), [], 0, (0, 0)), 93),
            ("positive-error", lambda request: (self._ack(request, error=1), [], 0, (0, 0)), 93),
            ("wrong-kind", lambda request: (self._ack(request, kind=3), [], 0, (0, 0)), 55),
            ("address-echo", lambda request: (self._ack(request, kind=20), [], 0, (0, 0)), 55),
            ("wrong-sequence", lambda request: (self._ack(request, sequence=2), [], 0, (0, 0)), 55),
            ("wrong-port", lambda request: (self._ack(request, port=20), [], 0, (0, 0)), 55),
            ("short", lambda request: (self._ack(request)[:19], [], 0, (0, 0)), 55),
            ("header-only", lambda request: (self._ack(request)[:20], [], 0, (0, 0)), 55),
            ("wrong-length-field", lambda request: (self._ack(request, length=40), [], 0, (0, 0)), 55),
            ("trailing", lambda request: (self._ack(request) + b"x", [], 0, (0, 0)), 55),
            ("second-message", lambda request: (self._ack(request) + self._ack(request), [], 0, (0, 0)), 55),
            ("unexpected-flags", lambda request: (self._ack(request, flags=0x200), [], 0, (0, 0)), 55),
            ("wrong-echo", lambda request: (self._ack(request, echo=bytes(16)), [], 0, (0, 0)), 55),
            ("ancillary", lambda request: (self._ack(request), [(1, 2, b"x")], 0, (0, 0)), 55),
            ("truncated", lambda request: (self._ack(request), [], 0x20, (0, 0)), 55),
            ("multicast", lambda request: (self._ack(request), [], 0, (0, 1)), 55),
            ("foreign-sender", lambda request: (self._ack(request), [], 0, (7, 0)), 55),
        )
        for label, reply, reason in cases:
            with self.subTest(case=label):
                control = self._restore_control(reply)
                with self.assertRaises(ProofFailure) as raised:
                    self._restore(control)
                self.assertEqual(raised.exception.reason, reason)

    def test_loopback_restore_refuses_socket_failures_and_a_foreign_identity(self):
        def timeout(request):
            raise TimeoutError()

        for identity in ((19, 1), (0, 0), (0x100000000, 0)):
            control = self._restore_control(lambda request: (self._ack(request), [], 0, (0, 0)), identity)
            with self.assertRaises(ProofFailure) as raised:
                self._restore(control)
            self.assertEqual(raised.exception.reason, 55)
            control.sendto.assert_not_called()
        control = self._restore_control(timeout)
        with self.assertRaises(ProofFailure) as raised:
            self._restore(control)
        self.assertEqual(raised.exception.reason, 55)
        for operation in ("settimeout", "bind", "getsockname"):
            control = self._restore_control(lambda request: (self._ack(request), [], 0, (0, 0)))
            getattr(control, operation).side_effect = OSError(errno.EPERM, "denied")
            with self.assertRaises(ProofFailure) as raised:
                self._restore(control)
            self.assertEqual(raised.exception.reason, 55)
            control.sendto.assert_not_called()
        control = self._restore_control(lambda request: (self._ack(request), [], 0, (0, 0)))
        control.sendto.side_effect = lambda request, target: len(request) - 1
        with self.assertRaises(ProofFailure) as raised:
            self._restore(control)
        self.assertEqual(raised.exception.reason, 55)
        control.recvmsg.assert_not_called()
        with patch("linux_harness.socket.AF_NETLINK", 16, create=True), \
             patch("linux_harness.socket.if_nametoindex", side_effect=OSError(errno.ENODEV, "absent")), \
             patch("linux_harness.socket.socket") as opened:
            with self.assertRaises(ProofFailure) as raised:
                harness._restore_loopback()
        self.assertEqual(raised.exception.reason, 55)
        opened.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=2)
