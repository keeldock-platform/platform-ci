"""Failure cases for the pinned platform and dedicated PF guard."""

import os
from contextlib import ExitStack
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock

import macos_boundary_guard as boundary


APPROVED_IDENTITY = boundary.PlatformIdentity(
    product_version="15.7.9",
    image_os="macos15",
    runner_image_os="macos-15-arm64",
    image_version="20260907.0337.1",
    architecture="arm64",
)
ACTIVE_PARENT = b'anchor "com.apple/*" all\n'
PF_CONFIG = 'anchor "com.apple/*"\n'


class Result:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class PFctlHarness:
    def __init__(self):
        self.rules = b""
        self.enabled = True
        self.parent_active = True
        self.token_in_stderr = False
        self.token_missing = False
        self.fail_load = False
        self.fail_next_readback = False
        self.fail_release = False
        self.override_loaded_rules = None
        self.verbose_override = None
        self.rules_on_enable = None
        self.hit_count = 0
        self.commands = []
        self.released = []

    def __call__(self, argv, *, timeout=boundary.COMMAND_TIMEOUT_SECONDS):
        argv = tuple(str(part) for part in argv)
        self.commands.append(argv)
        if not argv or argv[0] != boundary.PFCTL_PATH:
            raise AssertionError("unexpected executable")
        args = argv[1:]
        if args == ("-E",):
            if self.rules_on_enable is not None:
                self.rules = self.rules_on_enable
            if self.token_missing:
                return Result(stdout=b"enabled\n")
            token_text = b"Token : 4821\n"
            if self.token_in_stderr:
                return Result(stderr=token_text)
            return Result(stdout=token_text)
        if args == ("-s", "info"):
            status = b"Status: Enabled\n" if self.enabled else b"Status: Disabled\n"
            return Result(stdout=status)
        if args == ("-sr",):
            return Result(stdout=ACTIVE_PARENT if self.parent_active else b"")
        if args == ("-a", boundary.PF_ANCHOR, "-sr"):
            if self.fail_next_readback:
                self.fail_next_readback = False
                return Result(returncode=1)
            return Result(stdout=self.rules)
        if args == ("-a", boundary.PF_ANCHOR, "-vvsr"):
            if self.verbose_override is not None:
                return Result(stdout=self.verbose_override)
            return Result(stdout=self._verbose_rules())
        if len(args) == 4 and args[:3] == ("-a", boundary.PF_ANCHOR, "-f"):
            if self.fail_load:
                return Result(returncode=1)
            self.rules = Path(args[3]).read_bytes()
            if self.override_loaded_rules is not None:
                self.rules = self.override_loaded_rules
            return Result()
        if args == ("-a", boundary.PF_ANCHOR, "-F", "rules"):
            self.rules = b""
            return Result()
        if len(args) == 2 and args[0] == "-X":
            if self.fail_release:
                return Result(returncode=1)
            self.released.append(args[1])
            return Result()
        raise AssertionError("unexpected pfctl request")

    def _verbose_rules(self):
        if not self.rules:
            return b""
        lines = []
        for index, rule in enumerate(self.rules.decode("ascii").splitlines()):
            lines.append("@" + str(index) + " " + rule)
            lines.append(
                " [ Evaluations: " + str(self.hit_count)
                + " Packets: " + str(self.hit_count)
                + " Bytes: " + str(self.hit_count * 64) + " ]"
            )
        return ("\n".join(lines) + "\n").encode("ascii")


class PlatformGuardTests(unittest.TestCase):
    def _approved_platform(self, *, product="15.7.9", image_os="macos15", image_version="20260907.0337.1", arch="arm64"):
        product_result = Result(stdout=(product + "\n").encode("ascii"))
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(boundary.platform, "system", return_value="Darwin"))
            stack.enter_context(mock.patch.object(boundary.platform, "machine", return_value=arch))
            stack.enter_context(mock.patch.object(boundary, "_check_trusted_system_file"))
            stack.enter_context(mock.patch.object(boundary, "_run_command", return_value=product_result))
            stack.enter_context(
                mock.patch.dict(
                    os.environ,
                    {"ImageOS": image_os, "ImageVersion": image_version},
                    clear=True,
                )
            )
            return boundary.check_platform()

    def test_approved_platform_returns_the_canonical_identity(self):
        self.assertEqual(self._approved_platform(), APPROVED_IDENTITY)

    def test_unapproved_product_image_or_architecture_refuses_before_probe(self):
        for values in (
            {"product": "15.7.8"},
            {"image_os": "macos-15-arm64"},
            {"image_version": "20260907.0337.2"},
            {"arch": "x86_64"},
        ):
            with self.subTest(values=values):
                with self.assertRaises(boundary.GuardError) as raised:
                    self._approved_platform(**values)
                self.assertEqual(raised.exception.reason, "platform_unapproved")

    def test_untrusted_or_writable_system_executable_refuses(self):
        valid = stat.S_IFREG | 0o755
        for metadata in (
            type("Meta", (), {"st_mode": valid, "st_uid": 501})(),
            type("Meta", (), {"st_mode": stat.S_IFREG | 0o775, "st_uid": 0})(),
            type("Meta", (), {"st_mode": stat.S_IFREG | 0o644, "st_uid": 0})(),
        ):
            with self.subTest(metadata=metadata.st_mode, uid=metadata.st_uid):
                with self.assertRaises(boundary.GuardError):
                    boundary._validate_file_metadata(metadata, executable=True)


class PFGuardTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.rules_path = Path(self.tempdir.name) / "pf.rules"
        self.pf = PFctlHarness()
        self.patches = (
            mock.patch.object(boundary, "check_platform", return_value=APPROVED_IDENTITY),
            mock.patch.object(boundary, "_read_pf_config", return_value=PF_CONFIG),
            mock.patch.object(boundary, "_validate_directory_metadata"),
            mock.patch.object(boundary, "_validate_file_metadata"),
            mock.patch.object(boundary.os, "geteuid", return_value=0),
            mock.patch.object(boundary, "_run_command", side_effect=self.pf),
            mock.patch.object(boundary, "_write_rules_file", side_effect=self._write_rules),
        )
        for patcher in self.patches:
            patcher.start()
            self.addCleanup(patcher.stop)

    def _write_rules(self, path, rules):
        target = Path(path)
        target.write_text("\n".join(rules) + "\n", encoding="ascii")
        return target

    def _install(self):
        return boundary.install_pf(501, self.rules_path)

    def test_pf_enable_token_from_stderr_is_retained_and_cleanup_is_scoped(self):
        self.pf.token_in_stderr = True
        guard = self._install()
        self.assertEqual(guard.token, "4821")
        self.assertEqual(guard.rules, boundary._rules_for_uid(501))
        self.assertEqual(guard.verify(), tuple((0, 0, 0) for _ in range(4)))
        guard.close()
        self.assertEqual(self.pf.released, ["4821"])
        self.assertEqual(self.pf.rules, b"")
        flushes = [command for command in self.pf.commands if "-F" in command]
        self.assertEqual(flushes, [(boundary.PFCTL_PATH, "-a", boundary.PF_ANCHOR, "-F", "rules")])
        self.assertFalse(any(command[1:2] == ("-f",) for command in self.pf.commands))

    def test_inactive_parent_anchor_refuses_without_enabling_pf(self):
        self.pf.parent_active = False
        with self.assertRaises(boundary.GuardError) as raised:
            self._install()
        self.assertEqual(raised.exception.reason, "pf_unavailable")
        self.assertFalse(any(command[1:] == ("-E",) for command in self.pf.commands))

    def test_preexisting_rules_in_the_dedicated_anchor_refuse(self):
        self.pf.rules = b"block drop out quick inet proto tcp all user = 501\n"
        with self.assertRaises(boundary.GuardError) as raised:
            self._install()
        self.assertEqual(raised.exception.reason, "pf_rules_unexpected")
        self.assertFalse(any(command[1:] == ("-E",) for command in self.pf.commands))

    def test_rules_appearing_after_enable_are_preserved(self):
        foreign = b"block drop out quick inet proto tcp all user = 502\n"
        self.pf.rules_on_enable = foreign
        with self.assertRaises(boundary.GuardError) as raised:
            self._install()
        self.assertEqual(raised.exception.reason, "cleanup_incomplete")
        self.assertEqual(self.pf.rules, foreign)
        self.assertEqual(self.pf.released, ["4821"])
        self.assertFalse(any("-F" in command for command in self.pf.commands))

    def test_rules_replaced_before_close_are_preserved(self):
        guard = self._install()
        foreign = b"block drop out quick inet proto tcp all user = 502\n"
        self.pf.rules = foreign
        with self.assertRaises(boundary.GuardError) as raised:
            guard.close()
        self.assertEqual(raised.exception.reason, "cleanup_incomplete")
        self.assertEqual(self.pf.rules, foreign)
        self.assertEqual(self.pf.released, ["4821"])
        self.assertFalse(any("-F" in command for command in self.pf.commands))

    def test_missing_enable_token_refuses_without_loading_rules(self):
        self.pf.token_missing = True
        with self.assertRaises(boundary.GuardError) as raised:
            self._install()
        self.assertEqual(raised.exception.reason, "cleanup_incomplete")
        self.assertFalse(any("-f" in command for command in self.pf.commands))

    def test_wrong_uid_protocol_or_family_rules_are_never_flushed(self):
        bad_rules = (
            b"block drop out quick inet proto tcp all user = 502\n",
            b"block drop out quick inet proto icmp all user = 501\n",
            b"block drop out quick inet6 proto tcp all user = 501\n",
        )
        for bad_rule in bad_rules:
            with self.subTest(rule=bad_rule):
                self.pf.rules = b""
                self.pf.released.clear()
                self.pf.override_loaded_rules = bad_rule
                with self.assertRaises(boundary.GuardError) as raised:
                    self._install()
                self.assertEqual(raised.exception.reason, "cleanup_incomplete")
                self.assertEqual(self.pf.rules, bad_rule)
                self.assertEqual(self.pf.released, ["4821"])
                self.assertFalse(any("-F" in command for command in self.pf.commands))
        self.pf.override_loaded_rules = None

    def test_load_failure_releases_token_and_leaves_no_anchor_rules(self):
        self.pf.fail_load = True
        with self.assertRaises(boundary.GuardError) as raised:
            self._install()
        self.assertEqual(raised.exception.reason, "pf_unavailable")
        self.assertEqual(self.pf.rules, b"")
        self.assertEqual(self.pf.released, ["4821"])

    def test_transient_readback_failure_is_reported_after_cleanup(self):
        guard = self._install()
        self.pf.fail_next_readback = True
        with self.assertRaises(boundary.GuardError) as raised:
            guard.verify()
        self.assertEqual(raised.exception.reason, "pf_unavailable")
        guard.close()
        self.assertEqual(self.pf.released, ["4821"])

    def test_exposed_rule_counters_can_be_required_to_show_hits(self):
        guard = self._install()
        with self.assertRaises(boundary.GuardError) as raised:
            guard.verify(require_hits=True)
        self.assertEqual(raised.exception.reason, "pf_unavailable")
        self.pf.verbose_override = b""
        with self.assertRaises(boundary.GuardError) as raised:
            guard.verify(require_hits=True)
        self.assertEqual(raised.exception.reason, "pf_unavailable")
        self.pf.verbose_override = b"".join(
            b"[ Evaluations: 1 Packets: 1 Bytes: 64 ]\n" for _ in range(4)
        )
        with self.assertRaises(boundary.GuardError) as raised:
            guard.verify(require_hits=True)
        self.assertEqual(raised.exception.reason, "pf_rules_unexpected")
        malformed = []
        for index, rule in enumerate(boundary._rules_for_uid(501)):
            malformed.append("@" + str(index) + " " + rule + "\n")
            malformed.append(" [ Evaluations: invalid Packets: 1 Bytes: 64 ]\n")
        self.pf.verbose_override = "".join(malformed).encode("ascii")
        with self.assertRaises(boundary.GuardError) as raised:
            guard.verify(require_hits=True)
        self.assertEqual(raised.exception.reason, "pf_rules_unexpected")
        self.pf.verbose_override = None
        self.pf.hit_count = 1
        counters = guard.verify(require_hits=True)
        self.assertEqual(counters, tuple((1, 1, 64) for _ in range(4)))
        guard.close()

    def test_cleanup_failure_is_not_swallowed(self):
        guard = self._install()
        self.pf.fail_release = True
        with self.assertRaises(boundary.GuardError) as raised:
            guard.close()
        self.assertEqual(raised.exception.reason, "cleanup_incomplete")

    def test_live_parent_must_be_unconstrained_and_not_bypassed(self):
        self.assertTrue(boundary._live_parent_is_reachable(ACTIVE_PARENT.decode("ascii")))
        self.assertFalse(
            boundary._live_parent_is_reachable(
                'anchor "com.apple/*" on en0 all\n'
            )
        )
        self.assertFalse(
            boundary._live_parent_is_reachable(
                'pass out quick all\nanchor "com.apple/*" all\n'
            )
        )
        self.assertFalse(
            boundary._live_parent_is_reachable(
                'anchor "com.apple/*" all\nanchor "com.apple/*" on en0 all\n'
            )
        )
        self.assertFalse(
            boundary._has_parent_anchor(
                'anchor "com.apple/*" all\nanchor "com.apple/*" on en0 all\n'
            )
        )
        self.assertFalse(
            boundary._has_parent_anchor('anchor "com.apple/*" on en0 all\n')
        )


if __name__ == "__main__":
    unittest.main()
