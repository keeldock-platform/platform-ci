import base64
import json
import socket
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import linux_harness as harness
import linux_session as session
from linux_channels import BoundaryRefusal


__all__ = ["LinuxSessionPureTests", "LinuxSessionSpecTests", "LinuxSessionLaunchTests", "LinuxSeccompNumberTests"]

NONCE = "0123456789abcdef01234567"
MOUNTINFO = (
    "36 35 98:0 / /tmp/root/usr ro,nosuid,nodev,relatime master:1 - ext4 /dev/root ro\n"
    "37 36 98:0 /share /tmp/root/usr/share rw,relatime - ext4 /dev/root rw\n"
    "38 36 0:40 / /tmp/root/usr/local/with\\040space rw,noatime - tmpfs tmpfs rw\n"
    "39 35 0:41 / /tmp/root/proc rw,nosuid - proc proc rw\n"
    "garbage line\n"
)


def good_spec(**changes):
    spec = {
        "mode": "confined",
        "view": "chroot",
        "nonce": NONCE,
        "argv": ["/usr/bin/python3"],
        "env": {"PATH": "/usr/bin"},
        "files": {"/probe.py": ["text", 0o444]},
        "binds": [],
        "work": False,
        "limits": "probe",
        "timeout": 5,
        "extra_fd": False,
        "keep_root": False,
        "fault": None,
        "rootfs": "/tmp/session/root",
        "netns": "1",
    }
    spec.update(changes)
    return spec


def encode(value):
    return session.RESULT_PREFIX + json.dumps(value).encode("ascii") + b"\n"


class LinuxSessionPureTests(unittest.TestCase):
    def test_mountinfo_parsing_finds_every_mount_under_usr_and_the_writable_ones(self):
        entries = session.parse_mountinfo(MOUNTINFO)
        self.assertEqual(len(entries), 4)
        under = session.mounts_under(entries, "/tmp/root/usr")
        self.assertEqual([entry["mount_point"] for entry in under], [
            "/tmp/root/usr", "/tmp/root/usr/share", "/tmp/root/usr/local/with space",
        ])
        self.assertEqual(
            session.writable_mounts(entries, "/tmp/root/usr"),
            ["/tmp/root/usr/share", "/tmp/root/usr/local/with space"],
        )
        self.assertEqual(session.mounts_under(entries, "/tmp/root/us"), [])
        self.assertEqual(session.writable_mounts(entries, "/tmp/root/proc"), ["/tmp/root/proc"])

    def test_remount_flags_always_read_only_and_keep_existing_restrictions(self):
        flags = session.remount_flags(["rw", "noexec", "noatime"])
        for required in (harness.MS_BIND, harness.MS_REMOUNT, harness.MS_RDONLY, harness.MS_NOSUID, harness.MS_NODEV, harness.MS_NOEXEC, 1024):
            self.assertTrue(flags & required)
        self.assertEqual(session.remount_flags([]) & harness.MS_NOEXEC, 0)

    def test_harden_remounts_each_writable_submount_and_verifies_the_readback(self):
        calls = []
        before = session.parse_mountinfo(MOUNTINFO)
        after = [{"mount_point": entry["mount_point"], "options": ["ro"]} for entry in before]
        with patch("linux_session.read_mountinfo", side_effect=[before, after]), \
             patch("linux_session.harness._mount", side_effect=lambda *args: calls.append(args)):
            session.harden_usr_submounts("/tmp/root")
        self.assertEqual([call[1] for call in calls], ["/tmp/root/usr/share", "/tmp/root/usr/local/with space"])
        for call in calls:
            self.assertIsNone(call[0])
            self.assertTrue(call[3] & harness.MS_RDONLY)
        with patch("linux_session.read_mountinfo", side_effect=[before, before]), \
             patch("linux_session.harness._mount"):
            with self.assertRaises(harness.ProofFailure) as raised:
                session.harden_usr_submounts("/tmp/root")
        self.assertEqual(raised.exception.reason, 95)

    def test_usr_readback_inside_the_chroot_requires_a_present_read_only_mount(self):
        ro = [{"mount_point": "/usr", "options": ["ro"]}]
        rw = [{"mount_point": "/usr", "options": ["rw"]}]
        with patch("linux_session.read_mountinfo", return_value=ro):
            session.require_usr_readonly("/usr")
        for entries in (rw, [], [{"mount_point": "/usr", "options": ["ro"]}, {"mount_point": "/usr/x", "options": ["rw"]}]):
            with patch("linux_session.read_mountinfo", return_value=entries):
                with self.assertRaises(harness.ProofFailure):
                    session.require_usr_readonly("/usr")

    def test_tripwire_replies_are_exact(self):
        self.assertTrue(session.ok_reply(b"").endswith(b"live"))
        self.assertTrue(session.proxy_reply(b"CONNECT a:443 HTTP/1.1").startswith(b"HTTP/1.1 200 Connection"))
        self.assertTrue(session.proxy_reply(b"GET / HTTP/1.1").endswith(b"live"))
        redirect = session.redirect_reply(4242)(b"GET /redirect/x-abc HTTP/1.1\r\n")
        self.assertIn(b"302 Found", redirect)
        self.assertIn(b"Location: http://127.0.0.1:4242/sink/x-abc", redirect)
        self.assertTrue(session.redirect_reply(1)(b"GET /other HTTP/1.1").endswith(b"live"))
        query = bytes((0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0)) + b"\x01a\x00\x00\x01\x00\x01"
        answer = session.dns_reply(query)
        self.assertEqual(answer[:2], query[:2])
        self.assertEqual(answer[2:4], bytes((0x81, 0x80)))
        self.assertTrue(answer.endswith(bytes((127, 0, 0, 1))))
        self.assertEqual(session.dns_reply(b"short"), b"")

    def test_event_store_records_matches_and_clears(self):
        store = session.EventStore()
        store.record("https4", b"hello v4-abc world")
        self.assertTrue(store.seen("https4", "v4-abc"))
        self.assertFalse(store.seen("https6", "v4-abc"))
        self.assertFalse(store.seen("https4", "other"))
        self.assertEqual(len(store.snapshot()), 1)
        store.clear()
        self.assertEqual(store.snapshot(), [])

    def test_listener_records_a_loopback_connection_and_replies(self):
        store = session.EventStore()
        listener = session.Listener("proxy", socket.AF_INET, socket.SOCK_STREAM, ("127.0.0.1", 0), session.proxy_reply, store)
        try:
            with socket.create_connection(("127.0.0.1", listener.address[1]), timeout=2) as client:
                client.sendall(b"CONNECT c-abc.example.invalid:443 HTTP/1.1\r\n\r\n")
                reply = client.recv(256)
            self.assertIn(b"200 Connection established", reply)
            for unused in range(50):
                if store.seen("proxy", "c-abc"):
                    break
                socket.create_connection(("127.0.0.1", listener.address[1]), timeout=2).close()
            self.assertTrue(store.seen("proxy", "c-abc"))
        finally:
            listener.close()

    def test_limit_profiles_and_unshare_argument_sets(self):
        self.assertEqual(set(session.LIMIT_PROFILES), {"probe", "fixture"})
        self.assertIn("--net", session.CONFINED_UNSHARE)
        self.assertIn("--pid", session.CONFINED_UNSHARE)
        self.assertNotIn("--net", session.OPEN_UNSHARE)
        self.assertIn("--pid", session.OPEN_UNSHARE)
        self.assertIn("--kill-child=KILL", session.OPEN_UNSHARE)
        self.assertIn("--net", session.HOST_UNSHARE)
        self.assertNotIn("--pid", session.HOST_UNSHARE)
        self.assertNotIn("--user", session.CONFINED_UNSHARE + session.OPEN_UNSHARE + session.HOST_UNSHARE)


class LinuxSessionSpecTests(unittest.TestCase):
    def test_a_well_formed_spec_validates(self):
        self.assertEqual(session.validate_spec(good_spec())["view"], "chroot")

    def test_malformed_specs_are_refused_with_a_fixed_reason(self):
        bad = (
            good_spec(mode="other"),
            good_spec(view="other"),
            good_spec(nonce="bad"),
            good_spec(view="host", mode="open"),
            good_spec(argv=[]),
            good_spec(argv=[1]),
            good_spec(env={"A": 1}),
            good_spec(files={"relative": ["t", 1]}),
            good_spec(files={"/a": ["t"]}),
            good_spec(files={"/a": [1, 1]}),
            good_spec(binds=[{"source": "/a", "target": "/b"}]),
            good_spec(binds=[{"source": "/a b", "target": "/b", "ro": True}]),
            good_spec(limits="huge"),
            good_spec(timeout=0),
            good_spec(timeout=601),
            good_spec(fault="other"),
            good_spec(rootfs="relative"),
        )
        for index, spec in enumerate(bad):
            with self.subTest(index=index):
                with self.assertRaises(harness.ProofFailure) as raised:
                    session.validate_spec(spec)
                self.assertEqual(raised.exception.reason, 96)
        with self.assertRaises(harness.ProofFailure):
            session.validate_spec([])

    def test_result_parsing_accepts_one_line_and_refuses_everything_else(self):
        reply = {
            "exit": 0, "timeout": False, "readback": {"netns": True},
            "stdout": base64.b64encode(b"out").decode(), "stderr": base64.b64encode(b"err").decode(),
        }
        parsed = session.parse_session_output(b"noise\n" + encode(reply))
        self.assertEqual((parsed.exit_code, parsed.stdout, parsed.stderr, parsed.timed_out), (0, b"out", b"err", False))
        for bad in (b"", encode(reply) * 2, b"KD-SESSION not-json\n", b"x" * 400001, encode([]), encode({"exit": 0})):
            with self.assertRaises(BoundaryRefusal):
                session.parse_session_output(bad)
        broken = dict(reply, stdout="!!!")
        with self.assertRaises(BoundaryRefusal):
            session.parse_session_output(encode(broken))
        with self.assertRaises(BoundaryRefusal):
            session.parse_session_output("text")

    def test_refused_results_map_to_closed_reasons_and_numeric_detail(self):
        with self.assertRaises(BoundaryRefusal) as raised:
            session.parse_session_output(encode({"refused": {"reason": "readback_failed", "detail": 95}}))
        self.assertEqual((raised.exception.reason, raised.exception.detail), ("readback_failed", 95))
        with self.assertRaises(BoundaryRefusal) as raised:
            session.parse_session_output(encode({"refused": {"reason": "bogus", "detail": "x"}}))
        self.assertEqual((raised.exception.reason, raised.exception.detail), ("environment", None))

    def test_inside_refuses_a_shared_network_namespace_before_building_anything(self):
        with patch("linux_session.os.geteuid", return_value=0), \
             patch("linux_session.netns_inode", return_value=1), \
             patch("linux_session.inside_chroot") as chroot:
            with self.assertRaises(harness.ProofFailure) as raised:
                session.inside(good_spec())
        self.assertEqual(raised.exception.reason, 47)
        chroot.assert_not_called()

    def test_inside_main_turns_every_failure_into_one_closed_refusal_line(self):
        import io
        import os
        import tempfile
        with tempfile.TemporaryDirectory() as base:
            path = os.path.join(base, "spec.json")
            with open(path, "w") as sink:
                json.dump(good_spec(), sink)
            for error, reason, detail in (
                (harness.ProofFailure(23), "readback_failed", 23),
                (BoundaryRefusal("control_not_fired"), "control_not_fired", None),
                (RuntimeError("secret detail"), "session_failed", 98),
            ):
                out = io.StringIO()
                with patch("linux_session.inside", side_effect=error), patch("linux_session.sys.stdout", out):
                    self.assertEqual(session.inside_main(path), 0)
                text = out.getvalue()
                self.assertNotIn("secret detail", text)
                line = json.loads(text[len("KD-SESSION "):])
                self.assertEqual(line, {"refused": {"reason": reason, "detail": detail}})


class LinuxSessionLaunchTests(unittest.TestCase):
    def run_spawn(self, spec_changes=None, view_runner=None):
        captured = {}

        def fake_run(command, **kwargs):
            captured["command"] = command
            captured["kwargs"] = kwargs
            spec_path = command[-1]
            with open(spec_path, "rt") as source:
                captured["spec"] = json.load(source)
            reply = {"exit": 0, "timeout": False, "readback": {}, "stdout": "", "stderr": ""}
            return SimpleNamespace(stdout=encode(reply), returncode=0)

        import tempfile
        with tempfile.TemporaryDirectory() as base, \
             patch("linux_session.subprocess.run", side_effect=fake_run), \
             patch("linux_session.netns_inode", return_value=77), \
             patch("linux_session.shutil.which", return_value="/usr/bin/unshare"):
            files = {"/probe.py": ("text", 0o444)}
            if view_runner == "host":
                result = session.run_host(base, NONCE, ["/usr/bin/python3"], {"PATH": "/usr/bin"}, files)
            else:
                result = session.run_chroot(base, NONCE, ["/usr/bin/python3"], {"PATH": "/usr/bin"}, "confined", files, **(spec_changes or {}))
            import os
            captured["cleaned"] = os.listdir(base) == []
        captured["result"] = result
        return captured

    def test_outer_launch_uses_fixed_namespaces_a_scrubbed_environment_and_cleans_up(self):
        captured = self.run_spawn()
        command = captured["command"]
        self.assertEqual(command[0], "/usr/bin/unshare")
        for flag in ("--mount", "--pid", "--ipc", "--net", "--kill-child=KILL", "--inside"):
            self.assertIn(flag, command)
        env = captured["kwargs"]["env"]
        self.assertEqual(set(env), {"PATH", "LANG", "LC_ALL", "PYTHONDONTWRITEBYTECODE"})
        self.assertEqual(captured["spec"]["netns"], "77")
        self.assertEqual(captured["spec"]["view"], "chroot")
        self.assertEqual(captured["spec"]["files"], {"/probe.py": ["text", 0o444]})
        self.assertGreater(captured["kwargs"]["timeout"], captured["spec"]["timeout"])
        self.assertTrue(captured["cleaned"])
        self.assertEqual(captured["result"].exit_code, 0)

    def test_host_view_has_no_pid_namespace_and_never_runs_open(self):
        captured = self.run_spawn(view_runner="host")
        command = captured["command"]
        self.assertNotIn("--pid", command)
        self.assertIn("--net", command)
        self.assertEqual(captured["spec"]["view"], "host")
        self.assertEqual(captured["spec"]["mode"], "confined")

    def test_open_mode_omits_the_network_namespace_and_fault_names_are_closed(self):
        captured = self.run_spawn()
        self.assertIn("--net", captured["command"])
        with patch("linux_session._spawn") as spawn:
            session.run_chroot("/tmp", NONCE, ["/x"], {}, "open", {})
        self.assertNotIn("--net", spawn.call_args.args[2])
        with self.assertRaises(BoundaryRefusal):
            with patch("linux_session.netns_inode", return_value=1):
                import tempfile
                with tempfile.TemporaryDirectory() as base:
                    session.run_chroot(base, NONCE, ["/x"], {}, "confined", {}, fault="made-up")
        self.assertEqual(session.FAULTS, ("usr-writable", "uid-root"))

    def test_launcher_drops_privileges_and_filters_by_mode_and_fault(self):
        cases = (
            ({"mode": "confined"}, True, True),
            ({"mode": "open"}, False, True),
            ({"mode": "confined", "keep_root": True}, False, False),
            ({"mode": "confined", "fault": "uid-root"}, False, False),
        )
        for changes, filter_on, drop in cases:
            spec = good_spec(**changes)
            process = MagicMock()
            process.pid = 4321
            process.wait.return_value = 0
            with self.subTest(changes=changes), \
                 patch("linux_session.subprocess.Popen", return_value=process) as popen, \
                 patch("linux_session.harness._wait_for_stopped_process"), \
                 patch("linux_session.harness._verify_child"), \
                 patch("linux_session.verify_dropped"), \
                 patch("linux_session.os.kill"), patch("linux_session.os.killpg"), \
                 patch("linux_session.os.close"), patch("linux_session.os.getpid", return_value=5):
                code, timed_out = session.launch_and_collect(spec, ["/x"], "/tmp", ("a", 11), ("b", 12), True)
            preexec = popen.call_args.kwargs["preexec_fn"]
            self.assertEqual(preexec.args, (session.PROBE_LIMITS, filter_on, drop))
            self.assertIs(preexec.func, harness._drop_child)
            self.assertEqual((code, timed_out), (0, False))
            self.assertTrue(popen.call_args.kwargs["start_new_session"])
            self.assertEqual(popen.call_args.kwargs["env"], spec["env"])

    def test_timeouts_kill_the_group_and_are_reported(self):
        process = MagicMock()
        process.pid = 4321
        process.wait.side_effect = [subprocess.TimeoutExpired("x", 1), 0]
        with patch("linux_session.subprocess.Popen", return_value=process), \
             patch("linux_session.harness._wait_for_stopped_process"), \
             patch("linux_session.harness._verify_child"), \
             patch("linux_session.os.kill"), patch("linux_session.os.killpg") as killpg, \
             patch("linux_session.os.close"), patch("linux_session.os.getpid", return_value=5):
            code, timed_out = session.launch_and_collect(good_spec(), ["/x"], "/tmp", ("a", 11), ("b", 12), True)
        self.assertEqual((code, timed_out), (None, True))
        killpg.assert_called()

    def test_kill_everything_is_only_ever_sent_by_the_pid_namespace_init(self):
        for pid, chrooted, expected in ((1, True, True), (5, True, False), (1, False, False)):
            process = MagicMock()
            process.pid = 4321
            process.wait.return_value = 0
            with self.subTest(pid=pid, chrooted=chrooted), \
                 patch("linux_session.subprocess.Popen", return_value=process), \
                 patch("linux_session.harness._wait_for_stopped_process"), \
                 patch("linux_session.harness._verify_child"), patch("linux_session.verify_dropped"), \
                 patch("linux_session.os.killpg"), patch("linux_session.os.close"), \
                 patch("linux_session.os.getpid", return_value=pid), \
                 patch("linux_session.os.kill") as kill:
                session.launch_and_collect(good_spec(), ["/x"], "/tmp", ("a", 11), ("b", 12), chrooted)
            self.assertEqual(any(call.args[0] == -1 for call in kill.call_args_list), expected)

    def test_peer_helper_runs_as_the_project_user_with_only_its_own_environment(self):
        with patch("linux_session.subprocess.Popen") as popen:
            session.start_peer("token", {"A": "b"})
        kwargs = popen.call_args.kwargs
        self.assertEqual((kwargs["user"], kwargs["group"], kwargs["extra_groups"]), (65534, 65534, []))
        self.assertEqual(kwargs["env"], {"KD_CONTROL": "token", "A": "b"})
        self.assertNotIn("preexec_fn", kwargs)



class LinuxSeccompNumberTests(unittest.TestCase):
    SYSCALL_NUMBERS = {
        "socket": 41, "socketpair": 53, "io_uring_setup": 425, "io_uring_enter": 426, "io_uring_register": 427,
        "ptrace": 101, "pivot_root": 155, "chroot": 161, "mount": 165, "umount2": 166,
        "add_key": 248, "request_key": 249, "keyctl": 250, "unshare": 272, "perf_event_open": 298,
        "setns": 308, "process_vm_readv": 310, "process_vm_writev": 311, "bpf": 321, "userfaultfd": 323,
        "open_tree": 428, "move_mount": 429, "fsopen": 430, "fsconfig": 431, "fsmount": 432, "fspick": 433,
        "pidfd_getfd": 438, "mount_setattr": 442,
    }

    def test_denied_syscalls_are_exactly_the_reviewed_x86_64_numbers(self):
        self.assertEqual(sorted(harness.DENIED_SYSCALLS), sorted(self.SYSCALL_NUMBERS.values()))
        self.assertEqual(len(set(harness.DENIED_SYSCALLS)), len(harness.DENIED_SYSCALLS))
        required = (
            "ptrace", "process_vm_readv", "process_vm_writev", "pidfd_getfd", "mount", "umount2", "pivot_root",
            "move_mount", "open_tree", "fsopen", "fsmount", "fsconfig", "mount_setattr", "chroot", "unshare",
            "setns", "keyctl", "add_key", "request_key", "bpf", "perf_event_open", "userfaultfd",
        )
        for name in required:
            self.assertIn(self.SYSCALL_NUMBERS[name], harness.DENIED_SYSCALLS, name)

    def test_filter_has_one_compare_and_deny_pair_per_denied_syscall(self):
        pairs = [
            (harness.SOCKET_FILTER[index][3], harness.SOCKET_FILTER[index + 1][3])
            for index in range(6, len(harness.SOCKET_FILTER) - 1, 2)
        ]
        self.assertEqual([number for number, unused in pairs], list(harness.DENIED_SYSCALLS))
        self.assertTrue(all(value == harness.SECCOMP_DENY for unused, value in pairs))
        self.assertEqual(harness.SOCKET_FILTER[-1][3], harness.SECCOMP_ALLOW)
        self.assertLess(len(harness.SOCKET_FILTER), 4096)


if __name__ == "__main__":
    unittest.main(verbosity=2)
