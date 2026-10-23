import ast
import errno
import io
import signal
import socket
import struct
import threading
import unittest
from types import SimpleNamespace
import urllib.error
from unittest.mock import patch

from linux_harness import CHILD_SOURCE, MAX_PROBE_SECONDS, PROBES, UNSHARE_ARGUMENTS, ProofFailure, _drop_child, _enter_rootfs_and_launch, _expected_denial, _inside, _run_probe, _supervise_child_process, _verify_netns, advance_supervision, outcome, valid_sha


class HarnessPolicyTests(unittest.TestCase):
    def test_route_diagnostics_refuse_every_nonempty_table_without_printing_rows(self):
        zero = "0" * 32
        null_route = f"{zero} 00 {zero} 00 {zero} ffffffff 00000001 00000000 00200200 lo\n"
        other_route = f"{zero} 00 {zero} 00 {zero} 00000001 00000001 00000000 00000001 lo\n"
        header = "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"

        class DatagramSocket:
            def fileno(self):
                return 9

            def close(self):
                pass

        cases = (
            ("empty", header, "", None),
            ("ipv4", header + "lo 00000000 00000000 0001\n", "", 85),
            ("ipv6-null", header, null_route, 86),
            ("two-ipv6-nulls", header, null_route * 2, 86),
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
                 patch("linux_harness.socket.if_nameindex", return_value=((1, "lo"),)), \
                 patch("linux_harness.socket.socket", return_value=DatagramSocket()), \
                 patch("linux_harness.fcntl.ioctl", return_value=struct.pack("16sH22x", b"lo", 0)), \
                 patch("linux_harness.open", create=True, side_effect=route_file):
                if reason is None:
                    self.assertIsNone(_verify_netns())
                else:
                    with self.assertRaises(ProofFailure) as raised:
                        _verify_netns()
                    self.assertEqual(raised.exception.reason, reason)
                    self.assertEqual(outcome(False, reason), f"linux-confinement=refused reason={reason}")

    def test_public_probe_set_is_fixed_and_linux_only(self):
        self.assertEqual(
            PROBES,
            ("tcp", "udp", "dns", "http", "proxy", "redirect", "ipc", "file", "environment", "process", "boundary"),
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
             patch("linux_harness.os.setgroups", create=True, side_effect=lambda value: ordered.append(("groups", value))), \
             patch("linux_harness.os.setresgid", create=True, side_effect=lambda *value: ordered.append(("gid", value))), \
             patch("linux_harness.os.setresuid", create=True, side_effect=lambda *value: ordered.append(("uid", value))), \
             patch("linux_harness.resource.setrlimit", side_effect=lambda *value: ordered.append(("limit", value))), \
             patch("linux_harness.os.close", side_effect=lambda fd: ordered.append(("close", fd))):
            _drop_child()
        self.assertEqual(ordered[-1], ("close", 0))
        self.assertEqual(ordered[-2][0], "limit")

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
             patch("linux_harness._verify_netns"), \
             patch("linux_harness._make_rootfs", return_value=rootfs), \
             patch("linux_harness._write_capture", side_effect=[("out", 11, 13), ("err", 12, 14)]), \
             patch("linux_harness.os.chroot", side_effect=chroot), \
             patch("linux_harness.os.chdir", side_effect=lambda path: events.append(("chdir", path))), \
             patch("linux_harness.open", create=True, side_effect=fake_open), \
             patch("linux_harness.os.chmod", side_effect=lambda *args: events.append(("chmod", args))), \
             patch("linux_harness.subprocess.Popen", return_value=SimpleNamespace(pid=777)) as popen, \
             patch("linux_harness.os.close"), \
             patch("linux_harness._supervise_child_process", side_effect=lambda *args: events.append(("supervise", args))), \
             patch("linux_harness.os.lseek"), \
             patch("linux_harness.os.read", side_effect=read_capture):
            result = _inside(arguments)
        self.assertEqual(result, "inner=accepted probe=tcp\n")
        self.assertEqual(chroot_paths, [rootfs])
        self.assertEqual([event[0] for event in events], ["chroot", "chdir", "open", "chmod", "supervise"])
        self.assertNotIn("stdin", popen.call_args.kwargs)
        self.assertIs(popen.call_args.kwargs["preexec_fn"], _drop_child)
        self.assertEqual(popen.call_args.kwargs["stdout"], 11)
        self.assertEqual(popen.call_args.kwargs["stderr"], 12)

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
        self.assertTrue(_expected_denial("tcp", OSError(errno.ENETUNREACH, "opaque")))
        self.assertTrue(_expected_denial("proxy", urllib.error.URLError(OSError(errno.EPERM, "opaque"))))
        self.assertTrue(_expected_denial("dns", socket.gaierror(socket.EAI_AGAIN, "opaque")))
        self.assertTrue(_expected_denial("ipc", OSError(errno.ENOENT, "opaque")))
        self.assertTrue(_expected_denial("file", OSError(errno.ENOENT, "opaque")))
        self.assertFalse(_expected_denial("tcp", OSError(errno.ETIMEDOUT, "opaque")))
        self.assertFalse(_expected_denial("dns", socket.gaierror(socket.EAI_NONAME, "opaque")))
        self.assertFalse(_expected_denial("ipc", OSError(errno.EACCES, "opaque")))
        self.assertFalse(_expected_denial("file", OSError(errno.EACCES, "opaque")))
        self.assertFalse(_expected_denial("http", urllib.error.URLError("opaque")))
        self.assertFalse(_expected_denial("unknown", ProofFailure(1)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
