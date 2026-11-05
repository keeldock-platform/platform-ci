import base64
import inspect
import json
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import linux_harness as harness
import linux_session as session
from linux_channels import BoundaryRefusal


__all__ = ["LinuxSessionPureTests", "LinuxSessionBindTargetTests", "LinuxSessionSpecTests", "LinuxSessionLaunchTests", "LinuxSessionLoopbackTests", "LinuxSeccompNumberTests"]

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

    def test_host_view_remounts_usr_read_only_before_project_launch(self):
        before = [
            {"mount_point": "/usr", "options": ["rw", "relatime"]},
            {"mount_point": "/usr/local", "options": ["rw", "noexec"]},
        ]
        after = [{"mount_point": item["mount_point"], "options": ["ro"]} for item in before]
        with patch("linux_session.read_mountinfo", side_effect=[before, after]), patch(
            "linux_session.harness._mount"
        ) as mount:
            session.harden_host_usr()
        self.assertEqual(mount.call_count, 3)
        self.assertEqual(mount.call_args_list[0].args[:2], ("/usr", "/usr"))
        self.assertEqual([call.args[1] for call in mount.call_args_list[1:]], ["/usr", "/usr/local"])
        for call in mount.call_args_list[1:]:
            self.assertTrue(call.args[3] & harness.MS_RDONLY)
        with patch("linux_session.read_mountinfo", side_effect=[before, before]), patch(
            "linux_session.harness._mount"
        ):
            with self.assertRaises(harness.ProofFailure):
                session.harden_host_usr()

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

    def test_closing_a_listener_ends_its_thread_before_returning_for_every_socket_kind(self):
        store = session.EventStore()
        directory = tempfile.mkdtemp(prefix="kd-listener-")
        self.addCleanup(shutil.rmtree, directory, True)
        cases = (
            ("tcp", socket.AF_INET, socket.SOCK_STREAM, ("127.0.0.1", 0)),
            ("udp", socket.AF_INET, socket.SOCK_DGRAM, ("127.0.0.1", 0)),
            ("unix", socket.AF_UNIX, socket.SOCK_STREAM, os.path.join(directory, "kd.sock")),
            ("abstract", socket.AF_UNIX, socket.SOCK_STREAM, chr(0) + "kd-listener-" + NONCE),
        )
        for name, family, kind, address in cases:
            with self.subTest(name=name):
                listener = session.Listener(name, family, kind, address, None, store)
                self.assertTrue(listener.thread.is_alive())
                listener.close()
                self.assertFalse(listener.thread.is_alive())
                self.assertTrue(listener.stopping.is_set())
        self.assertEqual(store.snapshot(), [])

    def test_a_listener_that_is_stopping_swallows_late_errors_and_otherwise_still_raises(self):
        store = session.EventStore()
        listener = session.Listener("udp", socket.AF_INET, socket.SOCK_DGRAM, ("127.0.0.1", 0), None, store)
        listener.close()
        self.assertFalse(listener.thread.is_alive())
        text = inspect.getsource(session.Listener._loop)
        self.assertIn("while not self.stopping.is_set():", text)
        self.assertIn("except Exception:\n                if self.stopping.is_set():\n                    return\n                raise", text)
        self.assertIn("daemon=True", inspect.getsource(session.Listener.__init__))
        self.assertIn("self.thread.join(LISTENER_JOIN_SECONDS)", inspect.getsource(session.Listener.close))
        self.assertGreater(session.LISTENER_JOIN_SECONDS, 0)

    def test_the_project_profile_has_its_own_limits_and_the_other_profiles_are_unchanged(self):
        rl = session.resource
        inf = rl.RLIM_INFINITY
        self.assertEqual(session.PROJECT_LIMITS, (
            (rl.RLIMIT_CPU, (3600, 3600)), (rl.RLIMIT_FSIZE, (4294967296, 4294967296)),
            (rl.RLIMIT_AS, (inf, inf)), (rl.RLIMIT_NPROC, (1024, 1024)),
            (rl.RLIMIT_NOFILE, (4096, 4096)), (rl.RLIMIT_CORE, (0, 0)),
        ))
        self.assertEqual(session.FIXTURE_LIMITS, (
            (rl.RLIMIT_CPU, (120, 120)), (rl.RLIMIT_FSIZE, (67108864, 67108864)),
            (rl.RLIMIT_AS, (inf, inf)), (rl.RLIMIT_NPROC, (256, 256)),
            (rl.RLIMIT_NOFILE, (256, 256)), (rl.RLIMIT_CORE, (0, 0)),
        ))
        self.assertEqual(session.PROBE_LIMITS, (
            (rl.RLIMIT_CPU, (20, 20)), (rl.RLIMIT_FSIZE, (4194304, 4194304)),
            (rl.RLIMIT_AS, (1073741824, 1073741824)), (rl.RLIMIT_NPROC, (64, 64)),
            (rl.RLIMIT_NOFILE, (64, 64)), (rl.RLIMIT_CORE, (0, 0)),
        ))
        self.assertIs(session.LIMIT_PROFILES["project"], session.PROJECT_LIMITS)
        self.assertIs(session.LIMIT_PROFILES["fixture"], session.FIXTURE_LIMITS)
        self.assertIs(session.LIMIT_PROFILES["probe"], session.PROBE_LIMITS)
        self.assertEqual(session.MAX_TIMEOUT_SECONDS, {"probe": 600, "fixture": 600, "project": 1800})
        session.validate_spec(good_spec(limits="project", timeout=1800))
        session.validate_spec(good_spec(limits="fixture", timeout=600))

    def test_limit_profiles_and_unshare_argument_sets(self):
        self.assertEqual(set(session.LIMIT_PROFILES), {"probe", "fixture", "project"})
        self.assertIn("--net", session.CONFINED_UNSHARE)
        self.assertIn("--pid", session.CONFINED_UNSHARE)
        self.assertNotIn("--net", session.OPEN_UNSHARE)
        self.assertIn("--pid", session.OPEN_UNSHARE)
        self.assertIn("--kill-child=KILL", session.OPEN_UNSHARE)
        self.assertIn("--net", session.HOST_UNSHARE)
        self.assertIn("--pid", session.HOST_UNSHARE)
        self.assertIn("--fork", session.HOST_UNSHARE)
        self.assertIn("--kill-child=KILL", session.HOST_UNSHARE)
        self.assertNotIn("--user", session.CONFINED_UNSHARE + session.OPEN_UNSHARE + session.HOST_UNSHARE)


class LinuxSessionBindTargetTests(unittest.TestCase):
    def test_pinned_node_mount_identity_must_match_the_checked_file(self):
        with tempfile.TemporaryDirectory() as target:
            node = os.path.join(target, "node")
            with open(node, "wb") as sink:
                sink.write(b"node")
            checked = os.stat(node, follow_symlinks=False)
            bind = {"st_dev": checked.st_dev, "st_ino": checked.st_ino}
            session.verify_bind_identity(target, bind)
            for changed in (
                {"st_dev": checked.st_dev + 1, "st_ino": checked.st_ino},
                {"st_dev": checked.st_dev, "st_ino": checked.st_ino + 1},
            ):
                with self.subTest(identity=changed), self.assertRaises(BoundaryRefusal) as raised:
                    session.verify_bind_identity(target, changed)
                self.assertEqual((raised.exception.reason, raised.exception.detail), ("fixture_incomplete", 62))
        with tempfile.TemporaryDirectory() as target:
            with self.assertRaises(BoundaryRefusal) as raised:
                session.verify_bind_identity(target, {"st_dev": 1, "st_ino": 2})
            self.assertEqual((raised.exception.reason, raised.exception.detail), ("fixture_incomplete", 62))

    def test_every_missing_component_of_a_bind_target_is_created_searchable_whatever_the_umask(self):
        with tempfile.TemporaryDirectory() as base:
            previous = os.umask(0o077)
            try:
                leaf = session.make_tree(base, "/srv/runner/.kit/toolchains/stable")
            finally:
                os.umask(previous)
            self.assertEqual(leaf, os.path.join(base, "srv/runner/.kit/toolchains/stable"))
            walked = base
            for part in ("srv", "runner", ".kit", "toolchains", "stable"):
                walked = os.path.join(walked, part)
                self.assertTrue(os.path.isdir(walked))
                self.assertEqual(stat.S_IMODE(os.stat(walked).st_mode), 0o755, walked)

    def test_existing_components_are_reused_and_never_changed(self):
        with tempfile.TemporaryDirectory() as base:
            os.mkdir(os.path.join(base, "keep"), 0o700)
            os.chmod(os.path.join(base, "keep"), 0o700)
            leaf = session.make_tree(base, "/keep/inner")
            self.assertEqual(stat.S_IMODE(os.stat(os.path.join(base, "keep")).st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(os.stat(leaf).st_mode), 0o755)
            self.assertEqual(session.make_tree(base, "/keep/inner"), leaf)
            self.assertEqual(session.make_tree(base, "keep//inner/"), leaf)

    def test_dot_components_and_empty_targets_are_refused_and_a_file_in_the_way_is_an_error(self):
        with tempfile.TemporaryDirectory() as base:
            for bad in ("", "/", "/a/../b", "/..", "/./a", "/a/."):
                with self.subTest(bad=bad):
                    with self.assertRaises(harness.ProofFailure) as raised:
                        session.make_tree(base, bad)
                    self.assertEqual(raised.exception.reason, 96)
            self.assertEqual(os.listdir(base), [])
            with open(os.path.join(base, "file"), "wt", encoding="ascii") as sink:
                sink.write("x")
            with self.assertRaises(FileExistsError):
                session.make_tree(base, "/file/below")
            with self.assertRaises(FileExistsError):
                session.make_tree(base, "/file")

    def test_the_root_builder_uses_the_helper_for_every_bind_target(self):
        source = inspect.getsource(session.extend_rootfs)
        self.assertIn("make_tree(rootfs, bind[", source)
        self.assertIn("verify_bind_identity(target, bind)", source)
        self.assertLess(source.index("harness._mount(bind[\"source\"]"), source.index("verify_bind_identity(target, bind)"))
        self.assertNotIn("makedirs(target", source)


class LinuxSessionSpecTests(unittest.TestCase):
    def test_a_well_formed_spec_validates(self):
        self.assertEqual(session.validate_spec(good_spec())["view"], "chroot")

    def test_project_environment_is_scrubbed_and_the_uid_is_dedicated(self):
        self.assertEqual(session.validate_spec(good_spec())["env"], {"PATH": "/usr/bin"})
        self.assertNotEqual(harness.CHILD_UID, 65534)
        self.assertNotEqual(harness.CHILD_GID, 65534)
        for key in ("GITHUB_TOKEN", "SOURCE_READER_TOKEN", "PASSWORD", "UNLISTED_ENV"):
            spec = good_spec(env={key: "value"})
            with self.subTest(key=key), self.assertRaises(harness.ProofFailure):
                session.validate_spec(spec)

    def test_project_session_refuses_action_and_token_names_before_launch(self):
        for key in ("ACTIONS_RUNTIME_TOKEN", "ACTIONS_RESULTS_URL", "PROJECT_TOKEN"):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as base, \
                 patch("linux_session.netns_inode", return_value=77), \
                 patch("linux_session.subprocess.run") as launch:
                with self.assertRaises(BoundaryRefusal) as raised:
                    session.run_chroot(
                        base, NONCE, ["/usr/bin/python3"], {"PATH": "/usr/bin", key: "synthetic"},
                        "confined", {},
                    )
                self.assertEqual(raised.exception.reason, "environment")
                launch.assert_not_called()

    def test_host_view_uses_only_minimal_device_nodes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = temporary + "/dev"
            with patch("linux_session.harness._mount") as mount, patch("linux_session.os.mknod") as mknod:
                session.minimal_dev(path)
            mount.assert_called_once_with(
                "tmpfs", path, "tmpfs", harness.MS_NOSUID | harness.MS_NOEXEC, "mode=0755,size=1m",
            )
            self.assertEqual(mknod.call_count, 4)
            names = tuple(call.args[0].rsplit("/", 1)[1] for call in mknod.call_args_list)
            self.assertEqual(names, ("null", "zero", "random", "urandom"))
            self.assertTrue(all(stat.S_IFMT(call.args[1]) == stat.S_IFCHR for call in mknod.call_args_list))

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
            good_spec(binds=[{"source": "/a", "target": "/b", "ro": True, "rec": "no"}]),
            good_spec(binds=[{"source": "/a", "target": "/b", "ro": True, "other": False}]),
            good_spec(binds=[{"source": "/a", "target": "/b", "ro": True, "st_dev": 1}]),
            good_spec(binds=[{"source": "/a", "target": "/b", "ro": True, "st_dev": True, "st_ino": 2}]),
            good_spec(binds=[{"source": "/a", "target": "/b", "ro": True, "st_dev": 1, "st_ino": -1}]),
            good_spec(binds=[{"source": "/a", "target": "/b", "ro": True, "rec": False, "st_dev": 1, "st_ino": 2}]),
            good_spec(binds=[{"source": "/a", "target": "/kd-node", "ro": False, "rec": False, "st_dev": 1, "st_ino": 2}]),
            good_spec(limits="huge"),
            good_spec(timeout=0),
            good_spec(timeout=601),
            good_spec(limits="fixture", timeout=601),
            good_spec(limits="project", timeout=1801),
            good_spec(limits="project", timeout=0),
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

    def test_binds_may_opt_out_of_recursion_with_a_boolean_only(self):
        spec = good_spec(binds=[{"source": "/a", "target": "/b", "ro": True, "rec": False}])
        self.assertIs(session.validate_spec(spec), spec)

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

    def test_host_view_has_pid_namespace_and_never_runs_open(self):
        captured = self.run_spawn(view_runner="host")
        command = captured["command"]
        self.assertIn("--pid", command)
        self.assertIn("--fork", command)
        self.assertIn("--kill-child=KILL", command)
        self.assertIn("--net", command)
        self.assertEqual(captured["spec"]["view"], "host")
        self.assertEqual(captured["spec"]["mode"], "confined")

    def test_host_view_can_share_the_host_pid_namespace_only_when_asked(self):
        self.assertNotIn("--pid", session.HOST_SHARED_PID_UNSHARE)
        for flag in ("--mount", "--fork", "--ipc", "--net", "--kill-child=KILL"):
            self.assertIn(flag, session.HOST_SHARED_PID_UNSHARE)
        self.assertNotIn("--user", session.HOST_SHARED_PID_UNSHARE)
        with patch("linux_session._spawn") as spawn:
            session.run_host("/tmp", NONCE, ["/x"], {}, {})
            session.run_host("/tmp", NONCE, ["/x"], {}, {}, host_pids=True)
        self.assertIs(spawn.call_args_list[0].args[2], session.HOST_UNSHARE)
        self.assertIs(spawn.call_args_list[1].args[2], session.HOST_SHARED_PID_UNSHARE)

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
        self.assertEqual(
            (kwargs["user"], kwargs["group"], kwargs["extra_groups"]),
            (harness.CHILD_UID, harness.CHILD_GID, []),
        )
        self.assertEqual(kwargs["env"], {"KD_CONTROL": "token", "A": "b"})
        self.assertNotIn("preexec_fn", kwargs)



class LinuxSessionLoopbackTests(unittest.TestCase):
    def host_spec(self, **changes):
        return good_spec(view="host", limits="project", timeout=5, **changes)

    def test_loopback_is_accepted_only_for_a_confined_host_view_project_gate(self):
        self.assertIs(session.validate_spec(self.host_spec(loopback=True))["loopback"], True)
        session.validate_spec(self.host_spec())
        for value in (False, None, 1, 0, "yes", "true", [], {}):
            with self.subTest(value=value):
                with self.assertRaises(harness.ProofFailure) as raised:
                    session.validate_spec(self.host_spec(loopback=value))
                self.assertEqual(raised.exception.reason, 96)
        for changes in ({"view": "chroot"}, {"limits": "probe"}, {"limits": "fixture"}, {"mode": "open", "view": "chroot"}):
            with self.subTest(changes=changes):
                spec = self.host_spec(loopback=True)
                spec.update(changes)
                with self.assertRaises(harness.ProofFailure) as raised:
                    session.validate_spec(spec)
                self.assertEqual(raised.exception.reason, 96)

    def test_run_host_marks_the_spec_only_when_loopback_is_asked(self):
        with patch("linux_session._spawn") as spawn:
            session.run_host("/tmp", NONCE, ["/x"], {}, {}, limits="project")
            session.run_host("/tmp", NONCE, ["/x"], {}, {}, limits="project", loopback=True)
        self.assertNotIn("loopback", spawn.call_args_list[0].args[1])
        self.assertIs(spawn.call_args_list[1].args[1]["loopback"], True)
        self.assertIs(spawn.call_args_list[1].args[2], session.HOST_UNSHARE)
        self.assertIn("--net", session.HOST_UNSHARE)

    def test_the_launcher_selects_the_loopback_filter_only_for_a_marked_spec(self):
        for changes, expected in (({}, (session.PROJECT_LIMITS, True, True)),
                                  ({"loopback": True}, (session.PROJECT_LIMITS, True, True, True))):
            spec = self.host_spec(**changes)
            process = MagicMock()
            process.pid = 4321
            process.wait.return_value = 0
            with self.subTest(changes=changes), \
                 patch("linux_session.subprocess.Popen", return_value=process) as popen, \
                 patch("linux_session.harness._wait_for_stopped_process"), \
                 patch("linux_session.verify_dropped"), \
                 patch("linux_session.os.kill"), patch("linux_session.os.killpg"), \
                 patch("linux_session.os.close"), patch("linux_session.os.getpid", return_value=5):
                session.launch_and_collect(spec, ["/x"], "/tmp", ("a", 11), ("b", 12), False)
            preexec = popen.call_args.kwargs["preexec_fn"]
            self.assertEqual(preexec.args, expected)
            self.assertIs(preexec.func, harness._drop_child)

    def run_inside_host(self, spec, launch_effect=None, restore_effect=None):
        events = []

        def launch(*arguments):
            events.append("launch")
            if launch_effect is not None:
                raise launch_effect
            return 0, False

        def restore():
            events.append("restore")
            if restore_effect is not None:
                raise restore_effect

        patches = (
            patch("linux_session.write_files"), patch("linux_session.os.makedirs"),
            patch("linux_session.harness._mount"), patch("linux_session.minimal_dev"),
            patch("linux_session.harden_host_usr"),
            patch("linux_session.harness._write_capture", return_value=("path", 1, 2)),
            patch("linux_session.launch_and_collect", side_effect=launch),
            patch("linux_session.read_capture", side_effect=lambda reader: events.append("read") or b""),
            patch("linux_session.harness._verify_netns", side_effect=lambda: events.append("verify")),
            patch("linux_session.require_usr_readonly"),
            patch("linux_session.harness._read_sysctl", return_value="1"),
            patch("linux_session.harness._disable_loopback_ipv6", side_effect=lambda: events.append("ipv6")),
            patch("linux_session.harness._set_loopback", side_effect=lambda up: events.append(("loopback", up))),
            patch("linux_session.harness._restore_loopback", side_effect=restore),
        )
        for item in patches:
            item.start()
        try:
            error = None
            try:
                session.inside_host(spec)
            except (OSError, harness.ProofFailure) as caught:
                error = caught
        finally:
            for item in reversed(patches):
                item.stop()
        return events, error

    def test_loopback_is_raised_before_the_launch_and_lowered_before_the_namespace_verification(self):
        events, error = self.run_inside_host(self.host_spec(loopback=True))
        self.assertIsNone(error)
        self.assertEqual(events, ["ipv6", ("loopback", True), "launch", ("loopback", False), "restore", "read", "read", "verify"])

    def test_a_host_session_without_loopback_never_touches_the_interface(self):
        events, error = self.run_inside_host(self.host_spec())
        self.assertIsNone(error)
        self.assertEqual(events, ["launch", "read", "read", "verify"])

    def test_loopback_is_lowered_even_when_the_launch_fails(self):
        events, error = self.run_inside_host(self.host_spec(loopback=True), launch_effect=OSError("boom"))
        self.assertIsInstance(error, OSError)
        self.assertEqual(events, ["ipv6", ("loopback", True), "launch", ("loopback", False), "restore", "read", "read"])

    def test_a_loopback_restore_refusal_stops_the_session_before_the_namespace_verification(self):
        for reason in (55, 93):
            with self.subTest(reason=reason):
                events, error = self.run_inside_host(self.host_spec(loopback=True), restore_effect=harness.ProofFailure(reason))
                self.assertIsInstance(error, harness.ProofFailure)
                self.assertEqual(error.reason, reason)
                self.assertEqual(events, ["ipv6", ("loopback", True), "launch", ("loopback", False), "restore", "read", "read"])


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
        unconditional = {name: number for name, number in self.SYSCALL_NUMBERS.items() if name != "socketpair"}
        self.assertEqual(sorted(harness.DENIED_SYSCALLS), sorted(unconditional.values()))
        self.assertEqual(len(set(harness.DENIED_SYSCALLS)), len(harness.DENIED_SYSCALLS))
        self.assertNotIn(self.SYSCALL_NUMBERS["socketpair"], harness.DENIED_SYSCALLS)
        self.assertEqual(harness.SOCKETPAIR_SYSCALL, self.SYSCALL_NUMBERS["socketpair"])
        required = (
            "ptrace", "process_vm_readv", "process_vm_writev", "pidfd_getfd", "mount", "umount2", "pivot_root",
            "move_mount", "open_tree", "fsopen", "fsmount", "fsconfig", "mount_setattr", "chroot", "unshare",
            "setns", "keyctl", "add_key", "request_key", "bpf", "perf_event_open", "userfaultfd",
        )
        for name in required:
            self.assertIn(self.SYSCALL_NUMBERS[name], harness.DENIED_SYSCALLS, name)
        for name in ("socket", "io_uring_setup", "io_uring_enter", "io_uring_register"):
            self.assertIn(self.SYSCALL_NUMBERS[name], harness.DENIED_SYSCALLS, name)

    def test_filter_has_one_compare_and_deny_pair_per_denied_syscall(self):
        start = 6 + len(harness.SOCKETPAIR_RULE)
        self.assertEqual(start, 15)
        self.assertEqual(harness.SOCKET_FILTER[6:start], harness.SOCKETPAIR_RULE)
        pairs = [
            (harness.SOCKET_FILTER[index][3], harness.SOCKET_FILTER[index + 1][3])
            for index in range(start, len(harness.SOCKET_FILTER) - 1, 2)
        ]
        self.assertEqual([number for number, unused in pairs], list(harness.DENIED_SYSCALLS))
        self.assertTrue(all(value == harness.SECCOMP_DENY for unused, value in pairs))
        self.assertEqual(harness.SOCKET_FILTER[-1][3], harness.SECCOMP_ALLOW)
        self.assertLess(len(harness.SOCKET_FILTER), 4096)
        self.assertEqual(len(harness.SOCKET_FILTER), 70)

    def test_socketpair_rule_allows_only_unix_stream_and_seqpacket_with_the_two_flag_bits_cleared(self):
        rule = harness.SOCKETPAIR_RULE
        self.assertEqual(len(rule), 9)
        self.assertEqual(rule[0], (0x15, 0, 8, 53))
        self.assertEqual(rule[1], (0x20, 0, 0, harness.SECCOMP_ARGUMENT_ZERO_OFFSET))
        self.assertEqual(harness.SECCOMP_ARGUMENT_ZERO_OFFSET, 16)
        self.assertEqual(rule[2], (0x15, 0, 4, harness.AF_UNIX))
        self.assertEqual(harness.AF_UNIX, 1)
        self.assertEqual(rule[3], (0x20, 0, 0, harness.SECCOMP_ARGUMENT_ONE_OFFSET))
        self.assertEqual(harness.SECCOMP_ARGUMENT_ONE_OFFSET, 24)
        self.assertEqual(rule[4], (0x54, 0, 0, 0xFFF7F7FF))
        self.assertEqual(harness.SOCK_FLAGS_CLEAR_MASK, 0xFFFFFFFF & ~(0x800 | 0x80000))
        self.assertEqual(rule[5], (0x15, 2, 0, harness.SOCK_STREAM))
        self.assertEqual(rule[6], (0x15, 1, 0, harness.SOCK_SEQPACKET))
        self.assertEqual((harness.SOCK_STREAM, harness.SOCK_SEQPACKET), (1, 5))
        self.assertEqual(rule[7], (0x06, 0, 0, harness.SECCOMP_DENY))
        self.assertEqual(rule[8], (0x06, 0, 0, harness.SECCOMP_ALLOW))


if __name__ == "__main__":
    unittest.main(verbosity=2)
