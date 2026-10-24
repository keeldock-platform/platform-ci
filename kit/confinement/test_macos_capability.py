import ctypes
import io
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import macos_capability


CONTROL_SHA = "a" * 40


def descriptor_output(pids=(101, 102)):
    lines = []
    for pid in pids:
        lines.extend(("p" + str(pid), "fcwd", "tDIR", "n/tmp", "ftxt", "tREG", "n/usr/bin/python3"))
        lines.extend(("f1", "tPIPE", "n->0xa41e4580bb63aaf3"))
        lines.extend(("f2", "tPIPE", "n->0x2c6caff2d92a6b2b"))
    return "\n".join(lines) + "\n"


def native_snapshot(pids=(101, 102)):
    result = {}
    for index, pid in enumerate(pids):
        base = 0x1000 + index * 0x100
        result[pid] = {
            1: {"mode": "w", "type": "PIPE", "name": "->0x%x" % base},
            2: {"mode": "w", "type": "PIPE", "name": "->0x%x" % (base + 1)},
        }
    return result


class FixedOutcomeTests(unittest.TestCase):
    def test_control_sha_is_full_lowercase_hex_only(self):
        self.assertTrue(macos_capability.valid_sha(CONTROL_SHA))
        for value in (CONTROL_SHA[:12], CONTROL_SHA.upper(), "g" * 40, CONTROL_SHA + "0", None):
            with self.subTest(value_type=type(value).__name__):
                self.assertFalse(macos_capability.valid_sha(value))

    def test_success_still_refuses_overall_confinement(self):
        self.assertEqual(
            macos_capability.safe_output(True),
            "macos-capability=observed\nmacos-confinement=refused reason=incomplete_channel_evidence\n",
        )

    def test_refusal_reason_is_limited_to_fixed_classes(self):
        self.assertEqual(
            macos_capability.safe_output(False, "descriptor_readback_unavailable"),
            "macos-capability=refused reason=descriptor_readback_unavailable\n"
            "macos-confinement=refused reason=incomplete_channel_evidence\n",
        )

    def test_native_preflight_checks_are_fixed_and_never_echo_error_data(self):
        for check in macos_capability.NATIVE_PREFLIGHT_CHECKS:
            with self.subTest(check=check):
                refusal = macos_capability.ProbeFailure("native_preflight_unavailable", check=check)
                self.assertEqual(
                    macos_capability.safe_output(False, refusal.reason, refusal.check),
                    "macos-capability=refused reason=native_preflight_unavailable check=" + check + "\n"
                    "macos-confinement=refused reason=incomplete_channel_evidence\n",
                )
        for unsafe in (chr(47) + "private/tmp/secret", "context\nsecret=raw", "probe_identity path=/tmp"):
            with self.subTest(unsafe=unsafe):
                refusal = macos_capability.ProbeFailure("native_preflight_unavailable", check=unsafe)
                self.assertIsNone(refusal.check)
                self.assertEqual(
                    macos_capability.safe_output(False, refusal.reason, refusal.check),
                    "macos-capability=refused reason=native_preflight_unavailable\n"
                    "macos-confinement=refused reason=incomplete_channel_evidence\n",
                )

    def test_each_native_preflight_phase_labels_only_generic_failures(self):
        phases = (
            ("context", "_check_context"),
            ("developer_mode", "_disable_developer_mode"),
            ("runner_controls", "_protect_runner_controls"),
            ("probe_identity", "_create_probe_identity"),
        )
        defaults = {
            "_check_context": Path("/tmp/synthetic-control"),
            "_disable_developer_mode": None,
            "_protect_runner_controls": (501, (), ()),
            "_create_probe_identity": (502, Path("/tmp/synthetic-home"), Path("/tmp/synthetic-home/home")),
        }
        for check, failing in phases:
            for failure in (macos_capability.ProbeFailure("native_preflight_unavailable"), RuntimeError("private path /tmp/secret")):
                with self.subTest(check=check, failure=type(failure).__name__):
                    output = io.StringIO()
                    with ExitStack() as stack:
                        stack.enter_context(patch.dict(os.environ, {"CI_WORKSPACE": "/tmp/synthetic-control"}))
                        for name, result in defaults.items():
                            stack.enter_context(patch.object(
                                macos_capability, name,
                                side_effect=failure if name == failing else None,
                                return_value=result,
                            ))
                        with redirect_stdout(output):
                            status = macos_capability.main(["--control-sha", CONTROL_SHA])
                    self.assertEqual(status, 1)
                    self.assertEqual(
                        output.getvalue(),
                        "macos-capability=refused reason=native_preflight_unavailable check=" + check + "\n"
                        "macos-confinement=refused reason=incomplete_channel_evidence\n",
                    )

    def test_subprocess_launch_failure_stays_in_its_fixed_preflight_phase(self):
        output = io.StringIO()
        with patch.dict(os.environ, {"CI_WORKSPACE": "/tmp/synthetic-control"}):
            with patch.object(macos_capability, "_check_context", return_value=Path("/tmp/synthetic-control")):
                with patch.object(macos_capability.subprocess, "run", side_effect=OSError("private path /tmp/secret")):
                    with redirect_stdout(output):
                        status = macos_capability.main(["--control-sha", CONTROL_SHA])
        self.assertEqual(status, 1)
        self.assertEqual(
            output.getvalue(),
            "macos-capability=refused reason=native_preflight_unavailable check=developer_mode\n"
            "macos-confinement=refused reason=incomplete_channel_evidence\n",
        )

    def test_post_identity_generic_failure_still_cleans_up_and_only_prints_phase(self):
        output = io.StringIO()
        with patch.dict(os.environ, {"CI_WORKSPACE": "/tmp/synthetic-control"}):
            with patch.object(macos_capability, "_check_context", return_value=Path("/tmp/synthetic-control")):
                with patch.object(macos_capability, "_disable_developer_mode"):
                    with patch.object(macos_capability, "_protect_runner_controls", return_value=(501, (), ())):
                        with patch.object(macos_capability, "_create_probe_identity", return_value=(502, Path("/tmp/synthetic-home"), Path("/tmp/synthetic-home/home"))):
                            with patch.object(macos_capability.tempfile, "mkdtemp", side_effect=RuntimeError("private path /tmp/secret")):
                                with patch.object(macos_capability, "_run", return_value=subprocess.CompletedProcess([], 0, b"", b"")) as command:
                                    with patch.object(macos_capability.shutil, "rmtree") as remove:
                                        with redirect_stdout(output):
                                            status = macos_capability.main(["--control-sha", CONTROL_SHA])
        self.assertEqual(status, 1)
        self.assertEqual(
            output.getvalue(),
            "macos-capability=refused reason=native_preflight_unavailable check=capability_probe\n"
            "macos-confinement=refused reason=incomplete_channel_evidence\n",
        )
        command.assert_called_once_with(["/usr/bin/dscl", ".", "-delete", chr(47) + "Users/" + macos_capability.USERNAME], timeout=10)
        remove.assert_called_once_with(Path("/tmp/synthetic-home"), ignore_errors=True)

    def test_preflight_phase_does_not_change_existing_specific_refusal(self):
        output = io.StringIO()
        with patch.dict(os.environ, {"CI_WORKSPACE": "/tmp/synthetic-control"}):
            with patch.object(macos_capability, "_check_context", return_value=Path("/tmp/synthetic-control")):
                with patch.object(macos_capability, "_disable_developer_mode"):
                    with patch.object(
                        macos_capability, "_protect_runner_controls",
                        side_effect=macos_capability.ProbeFailure("runner_control_unavailable", check="directory_type_owner"),
                    ):
                        with redirect_stdout(output):
                            status = macos_capability.main(["--control-sha", CONTROL_SHA])
        self.assertEqual(status, 1)
        self.assertEqual(
            output.getvalue(),
            "macos-capability=refused reason=runner_control_unavailable check=directory_type_owner\n"
            "macos-confinement=refused reason=incomplete_channel_evidence\n",
        )
        self.assertEqual(
            macos_capability.safe_output(False, "raw-private-error"),
            "macos-capability=refused reason=native_preflight_unavailable\n"
            "macos-confinement=refused reason=incomplete_channel_evidence\n",
        )

    def test_native_probe_uses_checkout_workspace_not_reserved_runner_parent(self):
        runner_parent = "/runner/work/platform-ci"
        checkout_root = runner_parent + "/platform-ci"
        with patch.dict(
            os.environ,
            {"CI_WORKSPACE": checkout_root, "RUNNER_WORKSPACE": runner_parent},
        ):
            with patch.object(
                macos_capability,
                "_check_context",
                side_effect=macos_capability.ProbeFailure("control_identity_invalid"),
            ) as check_context:
                with self.assertRaisesRegex(macos_capability.ProbeFailure, "control_identity_invalid"):
                    macos_capability.run_native_probe(CONTROL_SHA)

        check_context.assert_called_once_with(CONTROL_SHA, checkout_root)

    def test_runner_control_refusal_emits_only_allowlisted_check(self):
        refusal = macos_capability.ProbeFailure("runner_control_unavailable", check="diagnostics_layout")
        self.assertEqual(
            macos_capability.safe_output(False, refusal.reason, refusal.check),
            "macos-capability=refused reason=runner_control_unavailable check=diagnostics_layout\n"
            "macos-confinement=refused reason=incomplete_channel_evidence\n",
        )
        for unsafe in (
            chr(47) + "private" + chr(47) + "tmp" + chr(47) + "secret",
            "diagnostics_layout\nsecret=raw",
            "file_permissions path=/tmp",
        ):
            with self.subTest(unsafe=unsafe):
                refusal = macos_capability.ProbeFailure("runner_control_unavailable", check=unsafe)
                self.assertIsNone(refusal.check)
                self.assertEqual(
                    macos_capability.safe_output(False, refusal.reason, refusal.check),
                    "macos-capability=refused reason=runner_control_unavailable\n"
                    "macos-confinement=refused reason=incomplete_channel_evidence\n",
                )

    def test_main_preserves_refusal_and_emits_bounded_check(self):
        output = io.StringIO()
        with patch.object(
            macos_capability,
            "run_native_probe",
            side_effect=macos_capability.ProbeFailure("runner_control_unavailable", check="file_type_owner"),
        ):
            with redirect_stdout(output):
                status = macos_capability.main(["--control-sha", CONTROL_SHA])
        self.assertEqual(status, 1)
        self.assertEqual(
            output.getvalue(),
            "macos-capability=refused reason=runner_control_unavailable check=file_type_owner\n"
            "macos-confinement=refused reason=incomplete_channel_evidence\n",
        )


class ProbeIdentityDiagnosticTests(unittest.TestCase):
    def test_privilege_timeout_is_distinguished_from_launch_and_unknown_failures(self):
        failures = (
            (OSError("private launch detail"), "probe_identity_privilege"),
            (subprocess.SubprocessError("private subprocess detail"), "probe_identity_privilege"),
            (
                subprocess.TimeoutExpired(
                    "stub-timeout",
                    5,
                    output=b"private stdout",
                    stderr=b"private stderr",
                ),
                "probe_identity_privilege_timeout",
            ),
        )
        for failure, check in failures:
            with self.subTest(check=check, failure=type(failure).__name__):
                with patch.object(macos_capability.subprocess, "run", side_effect=failure):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        with macos_capability._preflight_phase("probe_identity_privilege"):
                            macos_capability._run_as_probe_user(
                                ["/usr/bin/python3", "-c", "pass"],
                                502,
                                env={"PATH": "/usr/bin:/bin"},
                                timeout=5,
                                timeout_check="probe_identity_privilege_timeout",
                            )
                self.assertEqual(raised.exception.reason, "native_preflight_unavailable")
                self.assertEqual(raised.exception.check, check)
                output = macos_capability.safe_output(False, raised.exception.reason, raised.exception.check)
                self.assertEqual(
                    output,
                    "macos-capability=refused reason=native_preflight_unavailable check=" + check + "\n"
                    "macos-confinement=refused reason=incomplete_channel_evidence\n",
                )
                self.assertNotIn("private", output)

    def test_probe_identity_privilege_call_selects_timeout_diagnostic(self):
        with tempfile.TemporaryDirectory(prefix="macos-identity-timeout-test-") as directory:
            parent = Path(directory) / "probe-home"
            parent.mkdir()
            calls = []

            def command(argv, **kwargs):
                calls.append((argv, kwargs))
                if argv[0] == "/usr/bin/sudo":
                    raise macos_capability.ProbeFailure(
                        "native_preflight_unavailable", check=kwargs.get("timeout_check")
                    )
                if argv[2:4] == ["-read", "/Users/" + macos_capability.USERNAME]:
                    return subprocess.CompletedProcess(argv, 1, b"", b"")
                output = b"account 501\n" if "-list" in argv else b""
                if "-Gn" in argv:
                    output = b"staff\n"
                if "-u" in argv and argv[0] == "/usr/bin/id":
                    output = b"502\n"
                return subprocess.CompletedProcess(argv, 0, output, b"")

            with ExitStack() as stack:
                stack.enter_context(patch.object(macos_capability.os, "geteuid", return_value=0, create=True))
                stack.enter_context(patch.object(macos_capability.tempfile, "mkdtemp", return_value=str(parent)))
                stack.enter_context(patch.object(macos_capability.os, "chown", create=True))
                stack.enter_context(patch.object(macos_capability.os, "chmod"))
                stack.enter_context(patch.object(macos_capability, "runner_uid_for_workspace", return_value=501))
                stack.enter_context(patch.object(macos_capability, "_run", side_effect=command))
                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                    with macos_capability._preflight_phase("probe_identity"):
                        macos_capability._create_probe_identity(Path(directory))

            self.assertEqual(raised.exception.check, "probe_identity_privilege_timeout")
            privilege_call = next(call for call in calls if call[0][0] == "/usr/bin/sudo")
            self.assertEqual(privilege_call[1]["timeout"], 5)
            self.assertEqual(privilege_call[1]["timeout_check"], "probe_identity_privilege_timeout")
            self.assertFalse(parent.exists())

    def test_identity_command_failures_report_fixed_subphase_and_keep_cleanup(self):
        checks = (
            "probe_identity_lookup", "probe_identity_inventory", "probe_identity_create",
            *("probe_identity_attributes",) * 6,
            "probe_identity_readback", "probe_identity_readback", "probe_identity_privilege",
        )
        for failure_index, check in enumerate(checks):
            with self.subTest(check=check, command=failure_index):
                with tempfile.TemporaryDirectory(prefix="macos-identity-test-") as directory:
                    parent = Path(directory) / "probe-home"
                    parent.mkdir()
                    calls = []
                    def command(argv, **kwargs):
                        index = len(calls)
                        calls.append(argv)
                        if index == failure_index:
                            raise macos_capability.ProbeFailure("native_preflight_unavailable")
                        if argv[2:4] == ["-read", "/Users/" + macos_capability.USERNAME]:
                            return subprocess.CompletedProcess(argv, 1, b"", b"")
                        output = b"account 501\n" if "-list" in argv else b""
                        if "-Gn" in argv:
                            output = b"staff\n"
                        if "-u" in argv and argv[0] == "/usr/bin/id":
                            output = b"502\n"
                        return subprocess.CompletedProcess(argv, 0, output, b"")
                    with ExitStack() as stack:
                        stack.enter_context(patch.object(macos_capability.os, "geteuid", return_value=0, create=True))
                        stack.enter_context(patch.object(macos_capability.tempfile, "mkdtemp", return_value=str(parent)))
                        stack.enter_context(patch.object(macos_capability.os, "chown", create=True))
                        stack.enter_context(patch.object(macos_capability.os, "chmod"))
                        stack.enter_context(patch.object(macos_capability, "runner_uid_for_workspace", return_value=501))
                        stack.enter_context(patch.object(macos_capability, "_run", side_effect=command))
                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                            with macos_capability._preflight_phase("probe_identity"):
                                macos_capability._create_probe_identity(Path(directory))
                    self.assertEqual(raised.exception.reason, "native_preflight_unavailable")
                    self.assertEqual(raised.exception.check, check)
                    self.assertEqual(
                        macos_capability.safe_output(False, raised.exception.reason, raised.exception.check),
                        "macos-capability=refused reason=native_preflight_unavailable check=" + check + "\n"
                        "macos-confinement=refused reason=incomplete_channel_evidence\n",
                    )
                    if failure_index >= 2:
                        self.assertEqual(calls[-1], ["/usr/bin/dscl", ".", "-delete", "/Users/" + macos_capability.USERNAME])
                        self.assertFalse(parent.exists())
                    else:
                        self.assertTrue(parent.exists())

    def test_identity_home_error_is_sanitised_before_account_creation(self):
        results = (subprocess.CompletedProcess([], 1, b"", b""), subprocess.CompletedProcess([], 0, b"account 501\n", b""))
        with patch.object(macos_capability.os, "geteuid", return_value=0, create=True):
            with patch.object(macos_capability, "_run", side_effect=results) as command:
                with patch.object(macos_capability.tempfile, "mkdtemp", side_effect=OSError("sensitive filesystem detail")):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        with macos_capability._preflight_phase("probe_identity"):
                            macos_capability._create_probe_identity(Path("/tmp/synthetic-workspace"))
        self.assertEqual(command.call_count, 2)
        self.assertEqual(raised.exception.check, "probe_identity_home")
        self.assertNotIn("sensitive", str(raised.exception))

    def test_nested_identity_phase_preserves_cleanup_flag(self):
        with self.assertRaises(macos_capability.ProbeFailure) as raised:
            with macos_capability._preflight_phase("probe_identity"):
                with macos_capability._preflight_phase("probe_identity_privilege"):
                    raise macos_capability.ProbeFailure("native_preflight_unavailable", cleanup_complete=False)
        self.assertEqual(raised.exception.check, "probe_identity_privilege")
        self.assertFalse(raised.exception.cleanup_complete)

    def test_identity_permission_error_keeps_account_and_home_cleanup(self):
        for operation in ("chown", "chmod"):
            with self.subTest(operation=operation):
                with tempfile.TemporaryDirectory(prefix="macos-identity-test-") as directory:
                    parent = Path(directory) / "probe-home"
                    parent.mkdir()
                    results = [subprocess.CompletedProcess([], 1, b"", b"")]
                    results.append(subprocess.CompletedProcess([], 0, b"account 501\n", b""))
                    results.extend([subprocess.CompletedProcess([], 0, b"", b"")] * 8)
                    with ExitStack() as stack:
                        stack.enter_context(patch.object(macos_capability.os, "geteuid", return_value=0, create=True))
                        stack.enter_context(patch.object(macos_capability.tempfile, "mkdtemp", return_value=str(parent)))
                        for name in ("chown", "chmod"):
                            stack.enter_context(patch.object(
                                macos_capability.os, name,
                                side_effect=OSError("sensitive filesystem detail") if name == operation else None,
                                create=(name == "chown"),
                            ))
                        command = stack.enter_context(patch.object(macos_capability, "_run", side_effect=results))
                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                            with macos_capability._preflight_phase("probe_identity"):
                                macos_capability._create_probe_identity(Path(directory))
                    self.assertEqual(raised.exception.check, "probe_identity_permissions")
                    self.assertNotIn("sensitive", str(raised.exception))
                    command.assert_called_with(["/usr/bin/dscl", ".", "-delete", "/Users/" + macos_capability.USERNAME], timeout=10)
                    self.assertFalse(parent.exists())


class RunnerControlDiagnosticTests(unittest.TestCase):
    def test_unknown_worker_roots_have_only_fixed_refusal_categories(self):
        with tempfile.TemporaryDirectory(prefix="macos-runner-control-") as directory:
            runner_home, workspace, _, _, _ = self.runner_layout(directory)
            uid = os.stat(workspace).st_uid
            roots = (
                ("diagnostics_root_outside_home", runner_home.parent / "elsewhere"),
                ("diagnostics_root_parent_component", runner_home / "actions-runner" / "cached" / ".." / "cached"),
                ("diagnostics_root_actions_runner", runner_home / "actions-runner"),
                ("diagnostics_root_extracted_versioned", runner_home / "actions-runner" / "extracted" / "2.338.0"),
                ("diagnostics_root_other", runner_home / "actions-runner" / "cached" / "2.338.0-extra"),
            )
            for expected, root in roots:
                with self.subTest(check=expected):
                    executable = root / "bin" / "Runner.Worker"
                    with patch.object(macos_capability.os, "getppid", return_value=100):
                        with patch.object(macos_capability, "_parent_pid_and_uid", return_value=(1, uid)):
                            with patch.object(macos_capability, "_process_executable", return_value=executable):
                                with patch.object(macos_capability.os, "fchmod", create=True) as chmod:
                                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                        macos_capability._runner_diagnostics(workspace)
                    chmod.assert_not_called()
                    self.assertEqual(raised.exception.reason, "runner_control_unavailable")
                    self.assertEqual(raised.exception.check, expected)
                    self.assertEqual(
                        macos_capability.safe_output(False, raised.exception.reason, raised.exception.check),
                        "macos-capability=refused reason=runner_control_unavailable check=" + expected + "\n"
                        "macos-confinement=refused reason=incomplete_channel_evidence\n",
                    )

    def test_runner_layout_subreasons_are_fixed_and_do_not_expose_evidence(self):
        with tempfile.TemporaryDirectory(prefix="macos-runner-control-") as directory:
            runner_home, workspace, _, executable, _ = self.runner_layout(directory)
            uid = os.stat(workspace).st_uid

            def refusal(candidate, *, process_uid=None, changed=False, untrusted=None):
                parent = (1, uid if process_uid is None else process_uid)
                if changed:
                    parents = [(1, uid), (2, uid)]
                else:
                    parents = None
                original_lstat = Path.lstat

                def checked_lstat(path):
                    info = original_lstat(path)
                    if path == untrusted:
                        return type("UntrustedInfo", (), {"st_mode": info.st_mode, "st_uid": uid + 1})()
                    return info

                with patch.object(macos_capability.os, "getppid", return_value=100):
                    with patch.object(macos_capability, "_parent_pid_and_uid", side_effect=parents, return_value=parent):
                        with patch.object(macos_capability, "_process_executable", return_value=candidate):
                            with patch.object(Path, "lstat", autospec=True, side_effect=checked_lstat):
                                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                    macos_capability._runner_diagnostics(workspace)
                return raised.exception

            cases = (
                ("diagnostics_worker_uid", executable, uid + 1, False, None),
                ("diagnostics_worker_bin", executable.parent.parent / "other" / "Runner.Worker", None, False, None),
                ("diagnostics_root_other", runner_home / "work" / "decoy" / "bin" / "Runner.Worker", None, False, None),
                ("diagnostics_home_owner", executable, None, False, runner_home),
                ("diagnostics_component_owner", executable, None, False, executable),
                ("diagnostics_process_changed", executable, None, True, None),
            )
            for expected, candidate, process_uid, changed, untrusted in cases:
                with self.subTest(check=expected):
                    failure = refusal(candidate, process_uid=process_uid, changed=changed, untrusted=untrusted)
                    self.assertEqual(failure.reason, "runner_control_unavailable")
                    self.assertEqual(failure.check, expected)
                    self.assertEqual(
                        macos_capability.safe_output(False, failure.reason, failure.check),
                        "macos-capability=refused reason=runner_control_unavailable check=" + expected + "\n"
                        "macos-confinement=refused reason=incomplete_channel_evidence\n",
                    )

            unsafe = macos_capability.ProbeFailure(
                "runner_control_unavailable", check="diagnostics_root_family path=" + str(executable)
            )
            self.assertIsNone(unsafe.check)

    def test_parent_link_requires_only_two_bounded_numeric_fields(self):
        accepted = subprocess.CompletedProcess([], 0, b"1 501\n", b"")
        with patch.object(macos_capability, "_run", return_value=accepted):
            self.assertEqual(macos_capability._parent_pid_and_uid(100), (1, 501))
        for payload in (b"1 501 forged-command\n", b"1 -1\n", b"1\n", b"1 " + b"9" * 130):
            with self.subTest(payload_length=len(payload)):
                result = subprocess.CompletedProcess([], 0, payload, b"")
                with patch.object(macos_capability, "_run", return_value=result):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._parent_pid_and_uid(100)
                self.assertEqual(raised.exception.check, "diagnostics_access")

    def test_executable_path_is_read_from_kernel_api_and_must_be_absolute(self):
        absolute = str(Path.cwd() / "synthetic" / "bin" / "Runner.Worker").encode("utf-8")

        class ProcPidPath:
            def __init__(self, payload):
                self.payload = payload

            def __call__(self, pid, buffer, length):
                self_pid = 100
                if pid != self_pid:
                    return 0
                ctypes.memmove(buffer, self.payload, len(self.payload))
                return len(self.payload)

        for payload, accepted in ((absolute, True), (b"relative/Runner.Worker", False)):
            with self.subTest(accepted=accepted):
                library = type("Libproc", (), {"proc_pidpath": ProcPidPath(payload)})()
                with patch.object(macos_capability.ctypes, "CDLL", return_value=library):
                    if accepted:
                        self.assertEqual(macos_capability._process_executable(100), Path(absolute.decode("utf-8")))
                    else:
                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                            macos_capability._process_executable(100)
                        self.assertEqual(raised.exception.check, "diagnostics_access")

    def test_missing_no_follow_support_refuses_instead_of_opening_path(self):
        with patch.object(macos_capability.os, "O_NOFOLLOW", None, create=True):
            with patch.object(macos_capability.os, "open") as opened:
                with self.assertRaises(OSError):
                    macos_capability._open_control_nofollow(Path.cwd(), True)
        opened.assert_not_called()

    def runner_layout(self, directory):
        runner_home = Path(directory).resolve() / "runner"
        workspace = runner_home / "work" / "platform-ci" / "platform-ci"
        workspace.mkdir(parents=True)
        runner_temp = runner_home / "work" / "_temp"
        runner_temp.mkdir()
        installation = runner_home / "actions-runner" / "cached"
        executable = installation / "bin" / "Runner.Worker"
        executable.parent.mkdir(parents=True)
        executable.write_text("synthetic runner executable")
        diagnostics = installation / "_diag"
        diagnostics.mkdir()
        return runner_home, workspace, runner_temp, executable, diagnostics

    def runner_ancestor(self, pid, runner_uid):
        if pid == 200:
            return 100, 0
        if pid == 100:
            return 1, runner_uid
        raise AssertionError("unexpected ancestor")

    def runner_executable(self, pid, executable):
        if pid == 200:
            return Path("/usr/bin/sudo")
        if pid == 100:
            return executable
        raise AssertionError("unexpected ancestor")

    def test_zero_workspace_owner_refuses_before_any_permission_change(self):
        owner = type("WorkspaceOwner", (), {"st_uid": 0})()
        with patch.object(macos_capability.os, "stat", return_value=owner):
            with patch.object(macos_capability.os, "fchmod", create=True) as chmod:
                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                    macos_capability._protect_runner_controls("synthetic-workspace")
        self.assertEqual(raised.exception.reason, "runner_control_unavailable")
        self.assertEqual(raised.exception.check, "workspace_owner")
        chmod.assert_not_called()

    def test_runner_diagnostics_comes_from_exact_worker_ancestor_not_decoy_directory(self):
        with tempfile.TemporaryDirectory(prefix="macos-runner-control-") as directory:
            runner_home, workspace, runner_temp, executable, diagnostics = self.runner_layout(directory)
            decoy = runner_home / "runners" / "2.338.0" / "_diag"
            decoy.mkdir(parents=True)
            decoy_before = decoy.stat()
            uid = os.stat(workspace).st_uid
            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                with patch.object(macos_capability.os, "getppid", return_value=200):
                    with patch.object(macos_capability, "_parent_pid_and_uid", side_effect=lambda pid: self.runner_ancestor(pid, uid)):
                        with patch.object(macos_capability, "_process_executable", side_effect=lambda pid: self.runner_executable(pid, executable)):
                            self.assertEqual(
                                macos_capability._runner_paths(workspace),
                                (runner_temp, runner_temp, diagnostics),
                            )
            decoy_after = decoy.stat()
            self.assertEqual((decoy_after.st_dev, decoy_after.st_ino), (decoy_before.st_dev, decoy_before.st_ino))
            self.assertEqual(decoy_after.st_mode & 0o777, decoy_before.st_mode & 0o777)

    def test_versioned_runner_family_requires_exact_worker_process(self):
        with tempfile.TemporaryDirectory(prefix="macos-runner-control-") as directory:
            runner_home, workspace, runner_temp, executable, diagnostics = self.runner_layout(directory)
            versioned = runner_home / "runners" / "2.338.0" / "bin" / "Runner.Worker"
            versioned.parent.mkdir(parents=True)
            versioned.write_text("synthetic versioned runner")
            versioned_diag = versioned.parent.parent / "_diag"
            versioned_diag.mkdir()
            uid = os.stat(workspace).st_uid
            with patch.object(macos_capability.os, "getppid", return_value=100):
                with patch.object(macos_capability, "_parent_pid_and_uid", return_value=(1, uid)):
                    with patch.object(macos_capability, "_process_executable", return_value=versioned):
                        self.assertEqual(macos_capability._runner_diagnostics(workspace), versioned_diag)
            self.assertNotEqual(versioned_diag, diagnostics)

    def test_extracted_runner_family_requires_exact_worker_and_trusted_components(self):
        with tempfile.TemporaryDirectory(prefix="macos-runner-control-") as directory:
            runner_home, workspace, runner_temp, cached_worker, cached_diag = self.runner_layout(directory)
            extracted = runner_home / "actions-runner" / "extracted"
            worker = extracted / "bin" / "Runner.Worker"
            worker.parent.mkdir(parents=True)
            worker.write_text("synthetic extracted worker")
            diagnostics = extracted / "_diag"
            diagnostics.mkdir()
            uid = os.stat(workspace).st_uid

            def discover(candidate, *, process_uid=None, executable_readback=None):
                owner = uid if process_uid is None else process_uid
                readback = candidate if executable_readback is None else executable_readback
                with patch.object(macos_capability.os, "getppid", return_value=100):
                    with patch.object(macos_capability, "_parent_pid_and_uid", return_value=(1, owner)):
                        with patch.object(macos_capability, "_process_executable", side_effect=[candidate, readback]):
                            with patch.object(macos_capability.os, "fchmod", create=True) as chmod:
                                try:
                                    return macos_capability._runner_paths(workspace)
                                finally:
                                    chmod.assert_not_called()

            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                self.assertEqual(discover(worker), (runner_temp, runner_temp, diagnostics))
                self.assertNotEqual(diagnostics, cached_diag)

                for candidate in (
                    runner_home / "actions-runner" / "extracted-evil" / "bin" / "Runner.Worker",
                    runner_home / "work" / "decoy" / "bin" / "Runner.Worker",
                ):
                    with self.subTest(candidate=candidate.parent.parent.name):
                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                            discover(candidate)
                        self.assertEqual(raised.exception.check, "diagnostics_root_other")

                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                    discover(worker, process_uid=uid + 1)
                self.assertEqual(raised.exception.check, "diagnostics_worker_uid")

                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                    discover(worker, executable_readback=cached_worker)
                self.assertEqual(raised.exception.check, "diagnostics_process_changed")

                original_lstat = Path.lstat

                def wrong_owner(path):
                    info = original_lstat(path)
                    if path == extracted:
                        return type("WrongOwner", (), {"st_mode": info.st_mode, "st_uid": uid + 1})()
                    return info

                with patch.object(Path, "lstat", autospec=True, side_effect=wrong_owner):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        discover(worker)
                self.assertEqual(raised.exception.check, "diagnostics_component_owner")

                if os.name == "nt":
                    def symlinked_bin(path):
                        info = original_lstat(path)
                        if path == worker.parent:
                            return type("SymlinkInfo", (), {"st_mode": stat.S_IFLNK | 0o777, "st_uid": uid})()
                        return info

                    with patch.object(Path, "lstat", autospec=True, side_effect=symlinked_bin):
                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                            discover(worker)
                else:
                    worker.unlink()
                    worker.parent.rmdir()
                    worker.parent.symlink_to(cached_worker.parent, target_is_directory=True)
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        discover(worker)
                self.assertEqual(raised.exception.check, "diagnostics_component_owner")

    def test_versioned_cached_runner_requires_exact_version_and_trusted_worker(self):
        with tempfile.TemporaryDirectory(prefix="macos-runner-control-") as directory:
            runner_home, workspace, runner_temp, old_worker, old_diag = self.runner_layout(directory)
            installation = runner_home / "actions-runner" / "cached" / "2.338.0"
            worker = installation / "bin" / "Runner.Worker"
            worker.parent.mkdir(parents=True)
            worker.write_text("synthetic versioned worker")
            diagnostics = installation / "_diag"
            diagnostics.mkdir()
            old_diag_before = old_diag.stat()
            uid = os.stat(workspace).st_uid

            def discover(candidate, *, process_uid=None, readback=None):
                owner = uid if process_uid is None else process_uid
                second = candidate if readback is None else readback
                with patch.object(macos_capability.os, "getppid", return_value=100):
                    with patch.object(macos_capability, "_parent_pid_and_uid", return_value=(1, owner)):
                        with patch.object(macos_capability, "_process_executable", side_effect=[candidate, second]):
                            with patch.object(macos_capability.os, "fchmod", create=True) as chmod:
                                try:
                                    return macos_capability._runner_paths(workspace)
                                finally:
                                    chmod.assert_not_called()

            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                self.assertEqual(discover(worker), (runner_temp, runner_temp, diagnostics))
                old_diag_after = old_diag.stat()
                self.assertEqual(
                    (old_diag_after.st_dev, old_diag_after.st_ino, old_diag_after.st_mode),
                    (old_diag_before.st_dev, old_diag_before.st_ino, old_diag_before.st_mode),
                )
                for candidate, expected in (
                    (runner_home / "actions-runner" / "cached" / "2.338.0-extra" / "bin" / "Runner.Worker", "diagnostics_root_other"),
                    (runner_home / "actions-runner" / "cached-evil" / "2.338.0" / "bin" / "Runner.Worker", "diagnostics_root_other"),
                    (installation / ".." / "other" / "bin" / "Runner.Worker", "diagnostics_root_parent_component"),
                ):
                    with self.subTest(check=expected):
                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                            discover(candidate)
                        self.assertEqual(raised.exception.check, expected)

                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                    discover(worker, process_uid=uid + 1)
                self.assertEqual(raised.exception.check, "diagnostics_worker_uid")
                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                    discover(worker, readback=old_worker)
                self.assertEqual(raised.exception.check, "diagnostics_process_changed")

                original_lstat = Path.lstat

                def wrong_owner(path):
                    info = original_lstat(path)
                    if path == installation:
                        return type("WrongOwner", (), {"st_mode": info.st_mode, "st_uid": uid + 1})()
                    return info

                with patch.object(Path, "lstat", autospec=True, side_effect=wrong_owner):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        discover(worker)
                self.assertEqual(raised.exception.check, "diagnostics_component_owner")

                if os.name == "nt":
                    def symlinked_bin(path):
                        info = original_lstat(path)
                        if path == worker.parent:
                            return type("SymlinkInfo", (), {"st_mode": stat.S_IFLNK | 0o777, "st_uid": uid})()
                        return info

                    with patch.object(Path, "lstat", autospec=True, side_effect=symlinked_bin):
                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                            discover(worker)
                else:
                    worker.unlink()
                    worker.parent.rmdir()
                    worker.parent.symlink_to(old_worker.parent, target_is_directory=True)
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        discover(worker)
                self.assertEqual(raised.exception.check, "diagnostics_component_owner")

    def test_versioned_cached_diagnostics_symlink_refuses_without_changing_target(self):
        with tempfile.TemporaryDirectory(prefix="macos-runner-control-") as directory:
            runner_home, workspace, runner_temp, _, old_diag = self.runner_layout(directory)
            installation = runner_home / "actions-runner" / "cached" / "2.338.0"
            worker = installation / "bin" / "Runner.Worker"
            worker.parent.mkdir(parents=True)
            worker.write_text("synthetic versioned worker")
            diagnostics = installation / "_diag"
            old_diag.chmod(0o755)
            target_before = old_diag.stat()
            uid = os.stat(workspace).st_uid

            if os.name != "nt":
                diagnostics.symlink_to(old_diag, target_is_directory=True)
            with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                with patch.object(macos_capability.os, "getppid", return_value=100):
                    with patch.object(macos_capability, "_parent_pid_and_uid", return_value=(1, uid)):
                        with patch.object(macos_capability, "_process_executable", return_value=worker):
                            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                macos_capability._protect_runner_controls(workspace)
            self.assertEqual(raised.exception.reason, "runner_control_unavailable")
            self.assertEqual(raised.exception.check, "workspace_owner" if os.name == "nt" else "directory_type_owner")
            target_after = old_diag.stat()
            self.assertEqual(
                (target_after.st_dev, target_after.st_ino, stat.S_IMODE(target_after.st_mode)),
                (target_before.st_dev, target_before.st_ino, stat.S_IMODE(target_before.st_mode)),
            )

    def test_replaced_directory_inode_refuses_before_chmod(self):
        with tempfile.TemporaryDirectory(prefix="macos-runner-control-") as directory:
            runner_home, workspace, runner_temp, executable, diagnostics = self.runner_layout(directory)
            if os.name == "nt":
                with patch.object(macos_capability.os, "fchmod", create=True) as chmod:
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._protect_runner_controls(workspace)
                self.assertEqual(raised.exception.check, "workspace_owner")
                chmod.assert_not_called()
            else:
                decoy = runner_home / "decoy"
                decoy.mkdir()
                decoy_fd = os.open(decoy, os.O_RDONLY)
                try:
                    with patch.object(macos_capability, "_runner_paths", return_value=(diagnostics,)):
                        with patch.object(macos_capability, "_open_control_nofollow", side_effect=lambda path, directory: os.dup(decoy_fd)):
                            with patch.object(macos_capability.os, "fchmod", create=True) as chmod:
                                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                    macos_capability._protect_runner_controls(workspace)
                    self.assertEqual(raised.exception.check, "directory_type_owner")
                    chmod.assert_not_called()
                finally:
                    os.close(decoy_fd)

    def test_untrusted_or_missing_worker_ancestor_refuses_before_chmod(self):
        with tempfile.TemporaryDirectory(prefix="macos-runner-control-") as directory:
            runner_home, workspace, runner_temp, executable, diagnostics = self.runner_layout(directory)
            uid = os.stat(workspace).st_uid
            unsafe = runner_home / "work" / "decoy" / "bin" / "Runner.Worker"
            unsafe.parent.mkdir(parents=True)
            unsafe.write_text("synthetic decoy")
            candidates = (unsafe, executable.parent.parent.parent / "missing" / "bin" / "Runner.Worker")
            for candidate in candidates:
                with self.subTest(candidate=candidate.name):
                    with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                        with patch.object(macos_capability.os, "getppid", return_value=100):
                            with patch.object(macos_capability, "_parent_pid_and_uid", return_value=(1, uid)):
                                with patch.object(macos_capability, "_process_executable", return_value=candidate):
                                    with patch.object(macos_capability.os, "fchmod", create=True) as chmod:
                                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                            if os.name == "nt":
                                                macos_capability._runner_diagnostics(workspace)
                                            else:
                                                macos_capability._protect_runner_controls(workspace)
                    self.assertEqual(raised.exception.reason, "runner_control_unavailable")
                    self.assertEqual(raised.exception.check, "diagnostics_root_other")
                    chmod.assert_not_called()

            if os.name == "nt":
                with patch.object(macos_capability.os, "getppid", return_value=100):
                    with patch.object(macos_capability, "_parent_pid_and_uid", return_value=(1, uid)):
                        with patch.object(macos_capability, "_process_executable", return_value=Path("synthetic-python")):
                            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                macos_capability._runner_diagnostics(workspace)
                self.assertEqual(raised.exception.check, "diagnostics_access")
            else:
                executable.unlink()
                executable.parent.rmdir()
                executable.parent.symlink_to(runner_home / "work" / "decoy" / "bin", target_is_directory=True)
                with patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                    with patch.object(macos_capability.os, "getppid", return_value=100):
                        with patch.object(macos_capability, "_parent_pid_and_uid", return_value=(1, uid)):
                            with patch.object(macos_capability, "_process_executable", return_value=executable):
                                with patch.object(macos_capability.os, "fchmod", create=True) as chmod:
                                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                        macos_capability._protect_runner_controls(workspace)
                self.assertEqual(raised.exception.check, "diagnostics_component_owner")
                chmod.assert_not_called()

    def test_runner_control_files_are_protected_and_missing_file_refuses(self):
        with tempfile.TemporaryDirectory(prefix="macos-runner-control-") as directory:
            runner_home, workspace, runner_temp, executable, diagnostics = self.runner_layout(directory)
            uid = os.stat(workspace).st_uid
            files = {key: runner_temp / key.lower() for key in (
                "GITHUB_ENV", "GITHUB_OUTPUT", "GITHUB_PATH", "GITHUB_STEP_SUMMARY"
            )}
            for path in files.values():
                path.write_text("")
                path.chmod(0o666)
            environment = {key: str(path) for key, path in files.items()}
            environment["RUNNER_TEMP"] = str(runner_temp)
            with patch.object(macos_capability.os, "getppid", return_value=100):
                with patch.object(macos_capability, "_parent_pid_and_uid", return_value=(1, uid)):
                    with patch.object(macos_capability, "_process_executable", return_value=executable):
                        if os.name == "nt":
                            self.assertEqual(uid, 0)
                            with patch.dict(os.environ, environment):
                                with patch.object(macos_capability.os, "fchmod", create=True) as chmod:
                                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                        macos_capability._protect_runner_controls(workspace)
                            self.assertEqual(raised.exception.reason, "runner_control_unavailable")
                            self.assertEqual(raised.exception.check, "workspace_owner")
                            chmod.assert_not_called()
                        else:
                            with patch.dict(os.environ, environment):
                                runner_uid, directories, protected_files = macos_capability._protect_runner_controls(workspace)
                            self.assertEqual(runner_uid, uid)
                            self.assertEqual(set(directories), {runner_temp, diagnostics})
                            self.assertEqual(set(protected_files), set(files.values()))
                            self.assertTrue(all(path.stat().st_mode & 0o077 == 0 for path in directories + protected_files))
                            files["GITHUB_STEP_SUMMARY"].unlink()
                            with patch.dict(os.environ, environment):
                                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                    macos_capability._protect_runner_controls(workspace)
                            self.assertEqual(raised.exception.reason, "runner_control_unavailable")
                            self.assertEqual(raised.exception.check, "file_permissions")
                            files["GITHUB_STEP_SUMMARY"].symlink_to(files["GITHUB_ENV"])
                            with patch.dict(os.environ, environment):
                                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                    macos_capability._protect_runner_controls(workspace)
                            self.assertEqual(raised.exception.check, "file_type_owner")
                            files["GITHUB_STEP_SUMMARY"].unlink()
                            files["GITHUB_STEP_SUMMARY"].write_text("")
                            alias = runner_temp / "alias"
                            alias.symlink_to(runner_temp, target_is_directory=True)
                            through_alias = dict(environment)
                            through_alias["GITHUB_STEP_SUMMARY"] = str(alias / files["GITHUB_STEP_SUMMARY"].name)
                            with patch.dict(os.environ, through_alias):
                                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                    macos_capability._protect_runner_controls(workspace)
                            self.assertEqual(raised.exception.check, "file_permissions")


class DescriptorReadbackTests(unittest.TestCase):
    def read_snapshot(self, payload, pids=(101, 102)):
        result = subprocess.CompletedProcess([], 0, payload.encode("utf-8"), b"")
        native = native_snapshot(pids)
        with patch.object(macos_capability, "_run", return_value=result):
            with patch.object(macos_capability, "_native_descriptor_snapshot", side_effect=lambda pid: native[pid]):
                return macos_capability._descriptor_snapshot(list(pids))

    def test_realistic_lsof_pipe_output_without_access_mode_uses_native_readback(self):
        result = self.read_snapshot(descriptor_output())
        self.assertEqual(set(result), {101, 102})
        self.assertEqual(set(result[101]), {1, 2})
        self.assertEqual(result[101][1]["mode"], "w")
        self.assertEqual(result[101][2]["mode"], "w")
        self.assertNotEqual(result[101][1]["name"], result[101][2]["name"])

    def test_lsof_is_requested_for_types_and_names_without_access_mode(self):
        payload = descriptor_output((101,))
        result = subprocess.CompletedProcess([], 0, payload.encode("utf-8"), b"")
        native = native_snapshot((101,))
        with patch.object(macos_capability, "_run", return_value=result) as run:
            with patch.object(macos_capability, "_native_descriptor_snapshot", side_effect=lambda pid: native[pid]):
                snapshot = macos_capability._descriptor_snapshot([101])
        run.assert_called_once_with(
            ["/usr/sbin/lsof", "-nP", "-Fpfnt", "-p", "101"],
            timeout=10,
        )
        self.assertEqual(snapshot[101][1]["mode"], "w")
        self.assertEqual(snapshot[101][2]["mode"], "w")

    def test_lsof_readback_refuses_missing_extra_non_pipe_or_shared_descriptors(self):
        base = descriptor_output((101,))
        mutations = (
            base.replace("f1\ntPIPE", "f0\ntPIPE"),
            base + "f3\ntPIPE\nn->0xfeed\n",
            base.replace("f1\ntPIPE", "f1\ntREG"),
            base.replace("n->0x2c6caff2d92a6b2b", "n->0xa41e4580bb63aaf3"),
            base.replace("f2\ntPIPE\nn->0x2c6caff2d92a6b2b\n", ""),
            base.replace("fcwd", "fother"),
            descriptor_output((101,)),
        )
        pids = ((101,), (101,), (101,), (101,), (101,), (101,), (101, 102))
        for index, (payload, expected_pids) in enumerate(zip(mutations, pids)):
            with self.subTest(mutation_index=index):
                with self.assertRaisesRegex(macos_capability.ProbeFailure, "descriptor_readback_unavailable"):
                    self.read_snapshot(payload, expected_pids)

    def test_native_readback_refuses_unallowed_descriptors_modes_types_and_shared_pipes(self):
        payload = descriptor_output((101,))
        mutations = (
            {1: {"mode": "w", "type": "PIPE", "name": "->1"}},
            {1: {"mode": "w", "type": "PIPE", "name": "->1"}, 2: {"mode": "w", "type": "PIPE", "name": "->2"}, 3: {"mode": "w", "type": "PIPE", "name": "->3"}},
            {0: {"mode": "rw", "type": "CHR", "name": "/dev/null"}, 1: {"mode": "w", "type": "PIPE", "name": "->1"}, 2: {"mode": "w", "type": "PIPE", "name": "->2"}},
            {1: {"mode": "r", "type": "PIPE", "name": "->1"}, 2: {"mode": "w", "type": "PIPE", "name": "->2"}},
            {1: {"mode": "w", "type": "PIPE", "name": "->1"}, 2: {"mode": "u", "type": "PIPE", "name": "->2"}},
            {1: {"mode": "w", "type": "PIPE", "name": "->1"}, 2: {"mode": "w", "type": "PIPE", "name": "->1"}},
        )
        for index, native in enumerate(mutations):
            result = subprocess.CompletedProcess([], 0, payload.encode("utf-8"), b"")
            with self.subTest(mutation_index=index):
                with patch.object(macos_capability, "_run", return_value=result):
                    with patch.object(macos_capability, "_native_descriptor_snapshot", return_value=native):
                        with self.assertRaisesRegex(macos_capability.ProbeFailure, "descriptor_readback_unavailable"):
                            macos_capability._descriptor_snapshot([101])

    def test_probe_requires_observed_forked_grandchild_and_all_process_roles(self):
        roles = {
            "capabilityprobe",
            "capabilitychild",
            "sh",
            "sleep",
            "capability-child",
            "forked-grandchild",
            "python3",
            "clang",
        }
        self.assertTrue(macos_capability._roles_complete(roles))
        roles.remove("forked-grandchild")
        self.assertFalse(macos_capability._roles_complete(roles))
        observed = macos_capability._observe_roles(
            {"capabilityprobe", "capabilitychild", "capability-child", "clang"},
            {"capabilityprobe": 1, "capabilitychild": 1, "capability-child": 2, "clang": 1},
        )
        self.assertIn("forked-grandchild", observed)


class ProbeTeardownTests(unittest.TestCase):
    def test_process_table_error_terminates_and_reaps_injected_probe_group(self):
        process = type(
            "StubProcess",
            (),
            {"pid": 12345, "stdout": io.BytesIO(), "stderr": io.BytesIO(), "returncode": None},
        )()
        process.poll = lambda: process.returncode
        group = {process.pid}

        def terminate_group(process_to_stop):
            self.assertIs(process_to_stop, process)
            group.discard(process_to_stop.pid)
            process_to_stop.returncode = -15
            return not group and process_to_stop.poll() is not None

        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(
                macos_capability,
                "_process_table",
                side_effect=macos_capability.ProbeFailure("descriptor_readback_unavailable"),
            ):
                with patch.object(macos_capability, "_terminate_probe_tree", side_effect=terminate_group) as teardown:
                    with self.assertRaisesRegex(
                        macos_capability.ProbeFailure,
                        "descriptor_readback_unavailable",
                    ):
                        macos_capability._observe_probe(
                            "unused",
                            "unused",
                            "unused",
                            501,
                            "unused",
                        )
        self.assertIsNotNone(process.poll(), "probe root process was not reaped")
        self.assertFalse(group, "probe process group was not terminated")
        teardown.assert_called_once_with(process)

    def test_terminate_probe_tree_escalates_with_injected_group_operations(self):
        class StubProcess:
            pid = 12345

            def __init__(self):
                self.returncode = None
                self.wait_calls = 0

            def poll(self):
                return self.returncode

            def wait(self, timeout):
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise subprocess.TimeoutExpired("stub-probe", timeout)
                self.returncode = -9
                return self.returncode

        process = StubProcess()
        with patch.object(macos_capability.os, "killpg", create=True) as killpg:
            with patch.object(macos_capability.signal, "SIGKILL", 9, create=True):
                with patch.object(
                    macos_capability,
                    "_wait_probe_group_gone",
                    side_effect=(False, True),
                ) as group_gone:
                    self.assertTrue(macos_capability._terminate_probe_tree(process))
        self.assertEqual(
            [(call.args[0], call.args[1]) for call in killpg.call_args_list],
            [(process.pid, macos_capability.signal.SIGTERM), (process.pid, 9)],
        )
        self.assertEqual(process.wait_calls, 2)
        self.assertEqual(group_gone.call_count, 2)

    def test_process_table_error_runs_teardown_contract_on_every_platform(self):
        process = type(
            "StubProcess",
            (),
            {"pid": 12345, "stdout": io.BytesIO(), "stderr": io.BytesIO(), "poll": lambda self: None},
        )()
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(
                macos_capability,
                "_process_table",
                side_effect=macos_capability.ProbeFailure("descriptor_readback_unavailable"),
            ):
                with patch.object(macos_capability, "_terminate_probe_tree", return_value=True) as teardown:
                    with self.assertRaisesRegex(
                        macos_capability.ProbeFailure,
                        "descriptor_readback_unavailable",
                    ):
                        macos_capability._observe_probe(
                            "unused",
                            "unused",
                            "unused",
                            501,
                            "unused",
                        )
        teardown.assert_called_once_with(process)

    def test_unproven_teardown_does_not_close_stream_under_live_capture(self):
        class LockedStream:
            def __init__(self):
                self.closed = False
                self.close_calls = 0

            def close(self):
                self.close_calls += 1
                raise RuntimeError("close blocked behind active capture read")

        stdout = LockedStream()
        stderr = LockedStream()
        process = type(
            "StubProcess",
            (),
            {"pid": 12345, "stdout": stdout, "stderr": stderr, "poll": lambda self: None},
        )()
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(
                macos_capability,
                "_process_table",
                side_effect=macos_capability.ProbeFailure("descriptor_readback_unavailable"),
            ):
                with patch.object(macos_capability, "_terminate_probe_tree", return_value=False):
                    with patch.object(macos_capability._Capture, "start"):
                        with patch.object(macos_capability._Capture, "join", return_value=False):
                            with self.assertRaisesRegex(
                                macos_capability.ProbeFailure,
                                "sandbox_behavior_unavailable",
                            ) as raised:
                                macos_capability._observe_probe(
                                    "unused",
                                    "unused",
                                    "unused",
                                    501,
                                    "unused",
                                )
        self.assertFalse(raised.exception.cleanup_complete)
        self.assertEqual(stdout.close_calls, 0)
        self.assertEqual(stderr.close_calls, 0)

    def test_unproven_teardown_keeps_account_and_scratch_state(self):
        with tempfile.TemporaryDirectory(prefix="macos-probe-cleanup-guard-") as directory:
            root = os.path.join(directory, "workspace")
            marker = os.path.join(root, "kit", "confinement", "macos_capability.swift")
            os.makedirs(os.path.dirname(marker))
            with open(marker, "w", encoding="utf-8") as handle:
                handle.write("// public synthetic probe\n")
            home_parent = os.path.join(directory, "home-parent")
            home = os.path.join(home_parent, "home")
            os.mkdir(home_parent)
            os.mkdir(home)
            scratch_paths = []

            def make_scratch(prefix, dir):
                path = os.path.join(directory, prefix + str(len(scratch_paths)))
                os.mkdir(path)
                scratch_paths.append(path)
                return path

            failure = macos_capability.ProbeFailure("sandbox_behavior_unavailable", cleanup_complete=False)
            with patch.dict(os.environ, {"CI_WORKSPACE": root}):
                with patch.object(macos_capability, "_check_context", return_value=Path(root)):
                    with patch.object(macos_capability, "_disable_developer_mode"):
                        with patch.object(macos_capability, "_protect_runner_controls", return_value=(501, (), ())):
                            with patch.object(macos_capability, "_create_probe_identity", return_value=(502, home_parent, home)):
                                with patch.object(macos_capability.tempfile, "mkdtemp", side_effect=make_scratch):
                                    with patch.object(macos_capability, "_verify_runner_controls_are_private"):
                                        with patch.object(macos_capability, "_run_as_probe_user"):
                                            with patch.object(macos_capability, "_build_signed_probe", return_value="unused"):
                                                with patch.object(macos_capability, "_observe_probe", side_effect=failure):
                                                    with patch.object(macos_capability, "_run") as run:
                                                        with self.assertRaisesRegex(
                                                            macos_capability.ProbeFailure,
                                                            "sandbox_behavior_unavailable",
                                                        ):
                                                            macos_capability.run_native_probe("a" * 40)
            self.assertTrue(os.path.isdir(home_parent))
            self.assertTrue(os.path.isdir(home))
            self.assertTrue(all(os.path.isdir(path) for path in scratch_paths))
            run.assert_not_called()
            shutil.rmtree(home_parent, ignore_errors=True)
            for path in scratch_paths:
                shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
