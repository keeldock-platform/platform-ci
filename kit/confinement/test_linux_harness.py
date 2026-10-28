import ast
import ctypes
import errno
import io
import signal
import socket
import stat
import struct
import subprocess
import sys
import threading
import unittest
from types import SimpleNamespace
import urllib.error
from unittest.mock import MagicMock, Mock, patch

import linux_harness as harness
from linux_harness import DENIED_SYSCALLS, AUDIT_ARCH_NATIVE, CHILD_SOURCE, MAX_PROBE_SECONDS, PROBES, SECCOMP_ALLOW, SECCOMP_DENY, SOCKET_FILTER, UNSHARE_ARGUMENTS, COMPAT_SYSCALL_BIT, ProofFailure, SockFprog, _drop_child, _enter_rootfs_and_launch, _expected_denial, _inside, _install_socket_filter, _run_probe, _supervise_child_process, _verify_child, _verify_netns, _verify_proc_routes, _require_empty_route_dump, ROUTE_CHANGE_GROUPS, advance_supervision, outcome, valid_sha


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

    def test_route_dump_refuses_malformed_partial_interrupted_or_filtered_messages(self):
        done = struct.pack("=IHHIIi", 20, 3, 2, 1, 19, 0)
        packets = [b"", done[:15], done[:19], done + b"x", done + done]
        for offset in range(len(done)):
            for bit in range(8):
                packet = bytearray(done)
                packet[offset] ^= 1 << bit
                packets.append(bytes(packet))
        for kind in (1, 2, 4, 16, 17, 20, 21, 24, 25, 32, 33):
            packets.append(struct.pack("=IHHIIi", 20, kind, 2, 1, 19, 0))
        for flags in (0, 1, 0x12, 0x22, 0x102, 0x202):
            packets.append(struct.pack("=IHHIIi", 20, 3, flags, 1, 19, 0))
        for packet in packets:
            probe = Mock()
            probe.sendto.return_value = 28
            probe.recvmsg.return_value = (packet, [], 0, (0, 0))
            with self.assertRaises(ProofFailure) as raised:
                _require_empty_route_dump(probe, socket.AF_INET, 1, 19)
            self.assertEqual(raised.exception.reason, 86)

    def test_every_route_object_refuses_including_alternate_tables_and_unreachable(self):
        for family in (socket.AF_INET, socket.AF_INET6):
            for table in (1, 253, 254, 255, 1000):
                for kind in (1, 2, 6, 7, 8, 9):
                    payload = struct.pack("=BBBBBBBBI", family, 0, 0, 0, min(table, 255), 2, 0, kind, 0)
                    payload += struct.pack("=HHI", 8, 15, table)
                    route = struct.pack("=IHHII", 16 + len(payload), 24, 2, 1, 19) + payload
                    probe = Mock()
                    probe.sendto.return_value = 28
                    probe.recvmsg.return_value = (route, [], 0, (0, 0))
                    with self.assertRaises(ProofFailure):
                        _require_empty_route_dump(probe, family, 1, 19)

    def test_route_dump_refuses_wrong_sender_truncation_and_ancillary_data(self):
        done = struct.pack("=IHHIIi", 20, 3, 2, 1, 19, 0)
        for ancillary, flags, sender in (([], 0x20, (0, 0)), ([], 0x8, (0, 0)), ([(1, 2, b"x")], 0, (0, 0)), ([], 0, (1, 0)), ([], 0, (0, 1))):
            probe = Mock()
            probe.sendto.return_value = 28
            probe.recvmsg.return_value = (done, ancillary, flags, sender)
            with self.assertRaises(ProofFailure):
                _require_empty_route_dump(probe, socket.AF_INET, 1, 19)
        probe = Mock()
        probe.sendto.return_value = 27
        with self.assertRaises(ProofFailure):
            _require_empty_route_dump(probe, socket.AF_INET, 1, 19)
        probe.recvmsg.assert_not_called()

    def test_sentinel_cross_check_requires_both_dumps_and_quiet_mutation_subscription(self):
        zero = "0" * 32
        sentinel = f"{zero} 00 {zero} 00 {zero} ffffffff 00000001 00000000 00200200 lo\n"
        done4 = (struct.pack("=IHHIIi", 20, 3, 2, 1, 19, 0), [], 0, (0, 0))
        done6 = (struct.pack("=IHHIIi", 20, 3, 2, 2, 19, 0), [], 0, (0, 0))
        mutation = (struct.pack("=IHHIIi", 20, 16, 0, 0, 0, 0), [], 0, (0, 1))
        empty = BlockingIOError(errno.EAGAIN, "empty")
        cases = (
            ("complete", [done4, done6, empty], None),
            ("timeout-first", [TimeoutError()], 86),
            ("timeout-second", [done4, TimeoutError()], 86),
            ("overflow", [done4, OSError(errno.ENOBUFS, "overflow")], 86),
            ("changed-before-dump", [mutation], 86),
            ("changed-between-dumps", [done4, mutation], 86),
            ("changed-after-dumps", [done4, done6, mutation], 86),
            ("late-overflow", [done4, done6, OSError(errno.ENOBUFS, "overflow")], 86),
            ("wrong-final-error", [done4, done6, BlockingIOError(errno.EPERM, "denied")], 86),
            ("duplicate-completion", [done4, done6, done6], 86),
        )
        for label, packets, reason in cases:
            probe = MagicMock()
            probe.__enter__.return_value = probe
            probe.getsockname.return_value = (19, ROUTE_CHANGE_GROUPS)
            probe.sendto.return_value = 28
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
                    self.assertEqual(probe.sendto.call_count, 2)
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
        for states in ((ProofFailure(57),), (ProofFailure(58),), ((((1, "lo"),), 0), (((2, "lo"),), 0)), ((((1, "lo"),), 0), ProofFailure(58))):
            probe = MagicMock()
            probe.__enter__.return_value = probe
            probe.getsockname.return_value = (19, ROUTE_CHANGE_GROUPS)
            with patch("linux_harness.socket.AF_NETLINK", 16, create=True), \
                 patch("linux_harness.socket.socket", return_value=probe), \
                 patch("linux_harness._verify_interfaces_down", side_effect=states), \
                 patch("linux_harness._verify_proc_routes"), \
                 patch("linux_harness._require_empty_route_dump"):
                with self.assertRaises(ProofFailure):
                    _verify_netns()
        for operation in ("settimeout", "setsockopt", "bind", "getsockname"):
            probe = MagicMock()
            probe.__enter__.return_value = probe
            getattr(probe, operation).side_effect = OSError(errno.EPERM, "denied")
            with patch("linux_harness.socket.AF_NETLINK", 16, create=True), patch("linux_harness.socket.socket", return_value=probe):
                with self.assertRaises(ProofFailure) as raised:
                    _verify_netns()
                self.assertEqual(raised.exception.reason, 86)

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

    def test_filter_denies_socket_and_ring_syscalls_in_every_supported_entry(self):
        def evaluate(architecture, number):
            data = struct.pack("<IIQ6Q", number, architecture, 0, *([0] * 6))
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
                elif code == 0x06:
                    return value
                else:
                    self.fail("unexpected-filter-instruction")
            self.fail("filter-did-not-return")

        for number in range(512):
            expected = SECCOMP_DENY if number in DENIED_SYSCALLS else SECCOMP_ALLOW
            self.assertEqual(evaluate(AUDIT_ARCH_NATIVE, number), expected)
            self.assertEqual(evaluate(AUDIT_ARCH_NATIVE, COMPAT_SYSCALL_BIT | number), SECCOMP_DENY)
            for architecture in (0x40000003, 0xC00000B7, 0, 0xFFFFFFFF):
                self.assertEqual(evaluate(architecture, number), SECCOMP_DENY)

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

        scope = {"ctypes": ctypes, "errno": errno}
        exec(compile(ast.Module(body=[node], type_ignores=[]), "synthetic", "exec"), scope)
        with patch("ctypes.CDLL", return_value=SimpleNamespace(syscall=syscall)):
            scope["_require_socket_policy"]()
        self.assertEqual({arguments[0] for number, arguments in calls if number == 41}, {1, 2, 10, 16, 17, 40, 0x7fffffff, 40 | (1 << 32)})
        self.assertEqual({number for number, _ in calls}, {41, 53, 425, 426, 427, *(COMPAT_SYSCALL_BIT | number for number in (41, 53, 425, 426, 427))})
        for result, error in ((0, errno.EPERM), (-1, errno.EAFNOSUPPORT), (-1, errno.EINVAL)):
            def wrong_denial(*args):
                ctypes.set_errno(error)
                return result
            with patch("ctypes.CDLL", return_value=SimpleNamespace(syscall=wrong_denial)):
                with self.assertRaises(RuntimeError):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
