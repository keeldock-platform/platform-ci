import builtins
import ctypes
import io
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path, PurePosixPath
from unittest.mock import patch

import macos_capability


CONTROL_SHA = "a" * 40
TEST_TOOLCHAIN = {
    "python": "/Applications/ToolchainFixture.app/Contents/Developer/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9",
    "clang": "/Applications/ToolchainFixture.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
    "linker": "/Applications/ToolchainFixture.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/ld",
    "sdk": "/Applications/ToolchainFixture.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk",
    "developer_directory": "/Applications/ToolchainFixture.app/Contents/Developer",
}


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
    def test_malformed_presence_results_refuse_as_census_errors(self):
        malformed = (
            None,
            0,
            "",
            (),
            (None, ()),
            (True, []),
            (True, ("unknown-private",)),
            (True, ("python", "python")),
            (False, ("python",)),
            (True, ("ps", "python")),
        )
        for value in malformed:
            with self.subTest(value=repr(value)):
                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                    macos_capability._presence_result(value)
                self.assertEqual(raised.exception.reason, "native_preflight_unavailable")
                self.assertEqual(raised.exception.check, "probe_process_census")
                self.assertFalse(raised.exception.cleanup_complete)

        malformed_snapshots = (
            None,
            (None, None, ()),
            (True, None, ()),
            (False, "probe_process_survivor_controls_multiple", ()),
            (True, "unreviewed", ()),
        )
        for value in malformed_snapshots:
            with self.subTest(snapshot=repr(value)):
                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                    macos_capability._snapshot_presence_result(value)
                self.assertEqual(raised.exception.check, "probe_process_census")
                self.assertFalse(raised.exception.cleanup_complete)

    def test_malformed_final_census_prevents_any_account_or_path_cleanup(self):
        output = io.StringIO()
        with patch.dict(os.environ, {"CI_WORKSPACE": "/tmp/synthetic-control"}):
            with patch.object(macos_capability, "_check_context", return_value=Path("/tmp/synthetic-control")):
                with patch.object(macos_capability, "_resolve_trusted_toolchain", return_value=TEST_TOOLCHAIN):
                    with patch.object(macos_capability, "_disable_developer_mode"):
                        with patch.object(macos_capability, "_protect_runner_controls", return_value=(501, (), ())):
                            with patch.object(macos_capability, "_create_probe_identity", return_value=(502, Path("/tmp/synthetic-home"), Path("/tmp/synthetic-home/home"))):
                                with patch.object(macos_capability, "_probe_uid_processes_present", return_value=None):
                                    with patch.object(macos_capability.tempfile, "mkdtemp", side_effect=RuntimeError("private path")):
                                        with patch.object(macos_capability, "_run") as command:
                                            with patch.object(macos_capability.shutil, "rmtree") as remove:
                                                with redirect_stdout(output):
                                                    status = macos_capability.main(["--control-sha", CONTROL_SHA])
        self.assertEqual(status, 1)
        self.assertEqual(
            output.getvalue(),
            "macos-capability=refused reason=native_preflight_unavailable check=probe_process_census\n"
            "macos-confinement=refused reason=incomplete_channel_evidence\n",
        )
        command.assert_not_called()
        remove.assert_not_called()

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

    def test_survivor_classes_are_fixed_bounded_and_limited_to_survivor_refusals(self):
        classes = ("other", "python", "ps", "unknown", "python", "unreviewed /tmp/private")
        refusal = macos_capability.ProbeFailure(
            "native_preflight_unavailable",
            check="probe_process_survivor_controls_multiple",
            survivor_classes=classes,
        )
        self.assertEqual(
            macos_capability.safe_output(
                False, refusal.reason, refusal.check, survivor_classes=refusal.survivor_classes
            ),
            "macos-capability=refused reason=native_preflight_unavailable "
            "check=probe_process_survivor_controls_multiple survivor_classes=python,ps,other,unknown\n"
            "macos-confinement=refused reason=incomplete_channel_evidence\n",
        )
        self.assertNotIn("private", macos_capability.safe_output(
            False,
            refusal.reason,
            "probe_process_survivor_controls_same_group",
            survivor_classes=classes,
        ))
        later_refusal = macos_capability.ProbeFailure(
            "native_preflight_unavailable",
            check="probe_process_survivor_positive_read",
            survivor_classes=("helper_preferences", "unknown"),
        )
        self.assertIn(
            "check=probe_process_survivor_positive_read survivor_classes=helper_preferences,unknown",
            macos_capability.safe_output(
                False,
                later_refusal.reason,
                later_refusal.check,
                survivor_classes=later_refusal.survivor_classes,
            ),
        )

    def test_identity_subphase_checks_are_fixed_and_never_echo_error_data(self):
        for check in macos_capability.PROBE_IDENTITY_CHECKS:
            with self.subTest(check=check):
                refusal = macos_capability.ProbeFailure("probe_identity_unavailable", check=check)
                self.assertEqual(
                    macos_capability.safe_output(False, refusal.reason, refusal.check),
                    "macos-capability=refused reason=probe_identity_unavailable check=" + check + "\n"
                    "macos-confinement=refused reason=incomplete_channel_evidence\n",
                )
        for unsafe in ("private account name", "probe_identity_readback path=/tmp/secret", "probe_identity_inventory\nsecret"):
            with self.subTest(unsafe=unsafe):
                refusal = macos_capability.ProbeFailure("probe_identity_unavailable", check=unsafe)
                self.assertIsNone(refusal.check)
                self.assertEqual(
                    macos_capability.safe_output(False, refusal.reason, refusal.check),
                    "macos-capability=refused reason=probe_identity_unavailable\n"
                    "macos-confinement=refused reason=incomplete_channel_evidence\n",
                )

    def test_main_preserves_fixed_identity_subphase_diagnostic(self):
        output = io.StringIO()
        failure = macos_capability.ProbeFailure(
            "probe_identity_unavailable", check="probe_identity_readback"
        )
        with patch.dict(os.environ, {"CI_WORKSPACE": "/tmp/synthetic-control"}):
            with patch.object(macos_capability, "_check_context", return_value=Path("/tmp/synthetic-control")):
                with patch.object(macos_capability, "_resolve_trusted_toolchain", return_value=TEST_TOOLCHAIN):
                    with patch.object(macos_capability, "_disable_developer_mode"):
                        with patch.object(macos_capability, "_protect_runner_controls", return_value=(501, (), ())):
                            with patch.object(macos_capability, "_create_probe_identity", side_effect=failure):
                                with redirect_stdout(output):
                                    status = macos_capability.main(["--control-sha", CONTROL_SHA])
        self.assertEqual(status, 1)
        self.assertEqual(
            output.getvalue(),
            "macos-capability=refused reason=probe_identity_unavailable check=probe_identity_readback\n"
            "macos-confinement=refused reason=incomplete_channel_evidence\n",
        )

    def test_each_native_preflight_phase_labels_only_generic_failures(self):
        phases = (
            ("context", "_check_context"),
            ("probe_process_toolchain", "_resolve_trusted_toolchain"),
            ("developer_mode", "_disable_developer_mode"),
            ("runner_controls", "_protect_runner_controls"),
            ("probe_identity", "_create_probe_identity"),
        )
        defaults = {
            "_check_context": Path("/tmp/synthetic-control"),
            "_resolve_trusted_toolchain": TEST_TOOLCHAIN,
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
            "macos-capability=refused reason=native_preflight_unavailable check=probe_process_toolchain\n"
            "macos-confinement=refused reason=incomplete_channel_evidence\n",
        )

    def test_subprocess_timeout_marks_cleanup_unproven(self):
        with patch.object(
            macos_capability.subprocess,
            "run",
            side_effect=subprocess.TimeoutExpired("stub-command", 1),
        ):
            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                macos_capability._run(["/usr/bin/true"], timeout=1)
        self.assertEqual(raised.exception.reason, "native_preflight_unavailable")
        self.assertFalse(raised.exception.cleanup_complete)

    def test_post_identity_generic_failure_still_cleans_up_and_only_prints_phase(self):
        output = io.StringIO()
        with patch.dict(os.environ, {"CI_WORKSPACE": "/tmp/synthetic-control"}):
            with patch.object(macos_capability, "_check_context", return_value=Path("/tmp/synthetic-control")):
                with patch.object(macos_capability, "_resolve_trusted_toolchain", return_value=TEST_TOOLCHAIN):
                    with patch.object(macos_capability, "_disable_developer_mode"):
                        with patch.object(macos_capability, "_protect_runner_controls", return_value=(501, (), ())):
                            with patch.object(macos_capability, "_create_probe_identity", return_value=(502, Path("/tmp/synthetic-home"), Path("/tmp/synthetic-home/home"))):
                                with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
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
        remove.assert_called_once_with(Path("/tmp/synthetic-home"))

    def test_preflight_phase_does_not_change_existing_specific_refusal(self):
        output = io.StringIO()
        with patch.dict(os.environ, {"CI_WORKSPACE": "/tmp/synthetic-control"}):
            with patch.object(macos_capability, "_check_context", return_value=Path("/tmp/synthetic-control")):
                with patch.object(macos_capability, "_resolve_trusted_toolchain", return_value=TEST_TOOLCHAIN):
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


class CommandLineToolsInterpreterTests(unittest.TestCase):
    CLT_PYTHON = (
        "/Library/Developer/CommandLineTools/Library/Frameworks/"
        "Python3.framework/Versions/3.9/bin/python3.9"
    )

    def test_pinned_command_line_tools_interpreter_matches_layout_and_maps_to_developer_directory(self):
        self.assertIsNotNone(macos_capability.PYTHON_CLT_LAYOUT.fullmatch(self.CLT_PYTHON))
        self.assertEqual(
            macos_capability._python_developer_directory(Path(self.CLT_PYTHON)),
            Path("/Library/Developer/CommandLineTools"),
        )

    def test_current_alias_and_shim_do_not_match_command_line_tools_layout(self):
        alias = self.CLT_PYTHON.replace("Versions/3.9", "Versions/Current")
        self.assertIsNone(macos_capability.PYTHON_CLT_LAYOUT.fullmatch(alias))
        with self.assertRaises(macos_capability.ProbeFailure):
            macos_capability._python_developer_directory(Path(alias))
        with self.assertRaises(macos_capability.ProbeFailure):
            macos_capability._python_developer_directory(Path("/usr/bin/python3"))


class TrustedToolchainTests(unittest.TestCase):
    def test_toolchain_binds_current_python_and_resolves_clang_sdk_and_linker_from_its_install(self):
        values = {
            TEST_TOOLCHAIN["python"]: PurePosixPath(TEST_TOOLCHAIN["python"]),
            "/usr/bin/xcrun": PurePosixPath("/usr/bin/xcrun"),
            TEST_TOOLCHAIN["clang"]: PurePosixPath(TEST_TOOLCHAIN["clang"]),
            TEST_TOOLCHAIN["sdk"]: PurePosixPath(TEST_TOOLCHAIN["sdk"]),
            TEST_TOOLCHAIN["linker"]: PurePosixPath(TEST_TOOLCHAIN["linker"]),
        }
        output = (
            subprocess.CompletedProcess([], 0, (TEST_TOOLCHAIN["clang"] + "\n").encode(), b""),
            subprocess.CompletedProcess([], 0, (TEST_TOOLCHAIN["sdk"] + "\n").encode(), b""),
            subprocess.CompletedProcess([], 0, (TEST_TOOLCHAIN["linker"] + "\n").encode(), b""),
        )
        with ExitStack() as stack:
            stack.enter_context(patch.object(macos_capability.sys, "platform", "darwin"))
            stack.enter_context(patch.object(macos_capability.sys, "executable", TEST_TOOLCHAIN["python"]))
            stack.enter_context(patch.object(macos_capability.os, "geteuid", return_value=0, create=True))
            stack.enter_context(
                patch.object(
                    macos_capability,
                    "_resolve_trusted_path",
                    side_effect=lambda raw, **kwargs: values[raw],
                )
            )
            stack.enter_context(
                patch.object(macos_capability, "_trusted_path_metadata", side_effect=lambda path, **kwargs: path)
            )
            run = stack.enter_context(patch.object(macos_capability, "_run", side_effect=output))
            stack.enter_context(
                patch.dict(
                    os.environ,
                    {
                        "DEVELOPER_DIR": "/tmp/untrusted-developer-dir",
                        "TOOLCHAINS": "untrusted-toolchain",
                        "SDKROOT": "/tmp/untrusted-sdk",
                    },
                )
            )
            tools = macos_capability._resolve_trusted_toolchain()
        self.assertEqual(tools, TEST_TOOLCHAIN)
        self.assertEqual(run.call_count, 3)
        env = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": "/var/empty",
            "DEVELOPER_DIR": TEST_TOOLCHAIN["developer_directory"],
            "LANG": "C",
            "LC_ALL": "C",
        }
        self.assertEqual(
            run.call_args_list[0].args[0],
            ["/usr/bin/xcrun", "--sdk", "macosx", "--find", "clang"],
        )
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"],
        )
        self.assertEqual(
            run.call_args_list[2].args[0],
            [TEST_TOOLCHAIN["clang"], "-isysroot", TEST_TOOLCHAIN["sdk"], "-print-prog-name=ld"],
        )
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["env"], env)
            self.assertEqual(call.kwargs["timeout"], 10)

    def test_unreviewed_python_layout_fails_before_tool_queries(self):
        with patch.object(macos_capability.sys, "platform", "darwin"):
            with patch.object(macos_capability.sys, "executable", "/opt/unreviewed/python3"):
                with patch.object(macos_capability.os, "geteuid", return_value=0, create=True):
                    with patch.object(
                        macos_capability,
                        "_resolve_trusted_path",
                        return_value=PurePosixPath("/opt/unreviewed/python3"),
                    ):
                        with patch.object(macos_capability, "_run") as run:
                            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                macos_capability._resolve_trusted_toolchain()
        self.assertEqual(raised.exception.check, "probe_process_toolchain")
        run.assert_not_called()

    def test_trusted_path_checks_each_ancestor_and_allows_only_non_probe_group_writes(self):
        expected = Path(TEST_TOOLCHAIN["python"])
        host_path_type = type(expected)
        expected_text = expected.as_posix()

        def metadata(path, *, unsafe=None):
            path_text = path.as_posix()
            if unsafe == "probe_group" and path_text == "/Applications":
                return types.SimpleNamespace(st_uid=0, st_gid=20, st_mode=stat.S_IFDIR | 0o775)
            if unsafe == "world" and path_text == "/":
                return types.SimpleNamespace(st_uid=0, st_gid=80, st_mode=stat.S_IFDIR | 0o777)
            if unsafe == "owner" and path_text == "/Applications":
                return types.SimpleNamespace(st_uid=501, st_gid=80, st_mode=stat.S_IFDIR | 0o755)
            if unsafe == "setuid" and path_text == expected_text:
                return types.SimpleNamespace(st_uid=0, st_gid=80, st_mode=stat.S_IFREG | 0o755 | stat.S_ISUID)
            if path_text == expected_text:
                return types.SimpleNamespace(st_uid=0, st_gid=80, st_mode=stat.S_IFREG | 0o755)
            return types.SimpleNamespace(st_uid=0, st_gid=80, st_mode=stat.S_IFDIR | 0o775)

        with patch.object(host_path_type, "lstat", return_value=types.SimpleNamespace(st_uid=0)):
            with patch.object(host_path_type, "resolve", return_value=expected):
                with patch.object(host_path_type, "stat", autospec=True, side_effect=lambda self: metadata(self)):
                    self.assertEqual(
                        macos_capability._resolve_trusted_path(TEST_TOOLCHAIN["python"], reject_python_shim=True),
                        expected,
                    )
                for unsafe in ("probe_group", "world", "owner", "setuid"):
                    with self.subTest(unsafe=unsafe):
                        with patch.object(
                            host_path_type,
                            "stat",
                            autospec=True,
                            side_effect=lambda self, unsafe=unsafe: metadata(self, unsafe=unsafe),
                        ):
                            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                macos_capability._resolve_trusted_path(
                                    TEST_TOOLCHAIN["python"], reject_python_shim=True
                                )
                        self.assertEqual(raised.exception.check, "probe_process_toolchain")

    def test_operating_system_python_shim_is_refused_even_if_it_resolves(self):
        with patch.object(Path, "lstat", return_value=types.SimpleNamespace(st_uid=0)) as lstat:
            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                macos_capability._resolve_trusted_path("/usr/bin/python3", reject_python_shim=True)
        self.assertEqual(raised.exception.check, "probe_process_toolchain")
        lstat.assert_not_called()

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


class ProbeUidCensusTests(unittest.TestCase):
    def test_census_checks_real_effective_and_saved_uid_fields(self):
        rows = b"10 0 0 0\n11 502 0 0\n12 0 502 0\n13 0 0 502\n"
        with patch.object(
            macos_capability,
            "_run",
            return_value=subprocess.CompletedProcess([], 0, rows, b""),
        ) as command:
            self.assertTrue(macos_capability._probe_uid_processes_present(502))
        command.assert_called_once_with(
            ["/bin/ps", "-A", "-o", "pid=,ruid=,uid=,svuid="],
            env={"LANG": "C", "LC_ALL": "C"},
            timeout=5,
            timeout_check="probe_process_census",
        )

    def test_census_accepts_clean_snapshot_but_only_as_a_snapshot(self):
        with patch.object(
            macos_capability,
            "_run",
            return_value=subprocess.CompletedProcess([], 0, b"1 0 0 0\n2 501 501 501\n", b""),
        ):
            self.assertFalse(macos_capability._probe_uid_processes_present(502))

    def test_census_malformed_or_failed_readback_is_incomplete(self):
        invalid_outputs = (b"", b"1 0 0 0", b"1 0 0 unknown\n", b"1 0 0 0\n1 1 1 1\n1 1 1 1\n")
        results = [subprocess.CompletedProcess([], 0, output, b"") for output in invalid_outputs]
        results.extend((
            subprocess.CompletedProcess([], 1, b"1 0 0 0\n", b""),
            subprocess.CompletedProcess([], 0, b"1 0 0 0\n", b"warning\n"),
        ))
        for result in results:
            with self.subTest(result=result):
                with patch.object(macos_capability, "_run", return_value=result):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._probe_uid_processes_present(502)
                self.assertEqual(raised.exception.check, "probe_process_census")
                self.assertFalse(raised.exception.cleanup_complete)
        with patch.object(macos_capability, "_run", side_effect=macos_capability.ProbeFailure("native_preflight_unavailable", cleanup_complete=False)):
            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                macos_capability._probe_uid_processes_present(502)
        self.assertEqual(raised.exception.check, "probe_process_census")
        self.assertFalse(raised.exception.cleanup_complete)

    def test_control_uid_snapshot_classifies_count_and_group_from_one_process_table(self):
        cases = (
            (b"1 1 S 0 0 0\n", (False, None)),
            (b"1 1 S 0 0 0\n20 10 R 502 502 502\n", (True, "probe_process_survivor_controls_same_group")),
            (b"1 1 S 0 0 0\n20 11 R 502 0 0\n", (True, "probe_process_survivor_controls_other_group")),
            (b"1 1 S 0 0 0\n20 2 Z 0 502 0\n", (True, "probe_process_survivor_controls_zombie")),
            (b"1 1 S 0 0 0\n20 0 Z 0 502 0\n", (True, "probe_process_survivor_controls_zombie")),
            (b"1 1 S 0 0 0\n20 2 R 0 502 0\n21 3 R 502 0 0\n", (True, "probe_process_survivor_controls_multiple")),
            (b"1 1 S 0 0 0\n20 0 R 0 502 0\n21 3 R 502 0 0\n", (True, "probe_process_survivor_controls_multiple")),
            (b"1 1 S 0 0 0\n20 0 R 502 502 502\n", (True, "probe_process_survivor_controls_unattributed")),
        )
        for output, expected in cases:
            with self.subTest(expected=expected):
                with patch.object(
                    macos_capability,
                    "_run",
                    return_value=subprocess.CompletedProcess([], 0, output, b""),
                ) as command:
                    self.assertEqual(
                        macos_capability._probe_uid_process_snapshot(502, launched_pgid=10), expected
                    )
                command.assert_called_once_with(
                    ["/bin/ps", "-A", "-o", "pid=,pgid=,state=,ruid=,uid=,svuid="],
                    env={"LANG": "C", "LC_ALL": "C"},
                    timeout=5,
                    timeout_check="probe_process_census",
                )

    def test_control_uid_snapshot_refuses_malformed_or_ambiguous_rows(self):
        invalid_outputs = (
            b"",
            b"1 1 S 0 0 0",
            b"1 1 Q 0 0 0\n",
            b"1 1 S 0 0 0\n1 1 S 0 0 0\n",
            b"1 1 S 0 0 0\ninvalid\n",
            b"\xff\n",
        )
        for output in invalid_outputs:
            with self.subTest(output_size=len(output)):
                with patch.object(
                    macos_capability,
                    "_run",
                    return_value=subprocess.CompletedProcess([], 0, output, b""),
                ):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._probe_uid_process_snapshot(502, launched_pgid=10)
                self.assertEqual(raised.exception.check, "probe_process_census")
                self.assertFalse(raised.exception.cleanup_complete)

    def test_control_uid_snapshot_preserves_strict_command_failures(self):
        outputs = (
            subprocess.CompletedProcess([], 1, b"1 1 S 0 0 0\n", b""),
            subprocess.CompletedProcess([], 0, b"1 1 S 0 0 0\n", b"warning\n"),
            subprocess.CompletedProcess([], 0, b"1 1 S 0 0 0\n" + b"0" * (macos_capability.MAX_CAPTURE_BYTES + 1), b""),
        )
        for result in outputs:
            with self.subTest(returncode=result.returncode, stderr=bool(result.stderr)):
                with patch.object(macos_capability, "_run", return_value=result):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._probe_uid_process_snapshot(502, launched_pgid=10)
                self.assertEqual(raised.exception.check, "probe_process_census")
                self.assertFalse(raised.exception.cleanup_complete)

    def test_noncontrol_survivor_snapshot_can_attach_bounded_classes(self):
        initial = b"20 502 0 0\n"
        recheck = b"20 502 0 0\n"
        with patch.object(
            macos_capability,
            "_run",
            side_effect=(
                subprocess.CompletedProcess([], 0, initial, b""),
                subprocess.CompletedProcess([], 0, recheck, b""),
            ),
        ):
            with patch.object(
                macos_capability,
                "_process_executable",
                return_value=PurePosixPath(TEST_TOOLCHAIN["python"]),
            ):
                result = macos_capability._probe_uid_process_snapshot(
                    502,
                    include_survivor_classes=True,
                    python_executable=TEST_TOOLCHAIN["python"],
                )
        self.assertEqual(result, (True, None, ("python",)))

    def test_survivor_diagnostic_uses_kernel_paths_and_revalidates_the_uid_rows(self):
        initial = b"1 1 S 0 0 0\n20 2 R 0 502 0\n21 3 R 502 0 0\n"
        readback = b"20 0 502 0\n21 502 0 0\n"
        with patch.object(
            macos_capability,
            "_run",
            side_effect=(
                subprocess.CompletedProcess([], 0, initial, b""),
                subprocess.CompletedProcess([], 0, readback, b""),
            ),
        ) as command:
            with patch.object(
                macos_capability,
                "_process_executable",
                side_effect=(PurePosixPath(TEST_TOOLCHAIN["python"]), PurePosixPath("/bin/ps")),
            ) as process_path:
                result = macos_capability._probe_uid_process_snapshot(
                    502,
                    launched_pgid=10,
                    include_survivor_classes=True,
                    python_executable=TEST_TOOLCHAIN["python"],
                )
        self.assertEqual(
            result,
            (True, "probe_process_survivor_controls_multiple", ("python", "ps")),
        )
        self.assertEqual(process_path.call_args_list[0].args, (20,))
        self.assertEqual(process_path.call_args_list[1].args, (21,))
        self.assertEqual(command.call_args_list[1].args[0], ["/bin/ps", "-p", "20,21", "-o", "pid=,ruid=,uid=,svuid="])

    def test_ambiguous_survivor_readback_adds_unknown_without_clearing_refusal(self):
        initial = b"1 1 S 0 0 0\n20 2 R 0 502 0\n21 3 R 502 0 0\n"
        changed = b"20 0 502 0\n"
        with patch.object(
            macos_capability,
            "_run",
            side_effect=(
                subprocess.CompletedProcess([], 0, initial, b""),
                subprocess.CompletedProcess([], 0, changed, b""),
            ),
        ):
            with patch.object(
                macos_capability,
                "_process_executable",
                side_effect=(PurePosixPath(TEST_TOOLCHAIN["python"]), PurePosixPath("/bin/ps")),
            ):
                result = macos_capability._probe_uid_process_snapshot(
                    502,
                    launched_pgid=10,
                    include_survivor_classes=True,
                    python_executable=TEST_TOOLCHAIN["python"],
                )
        self.assertEqual(
            result,
            (True, "probe_process_survivor_controls_multiple", ("unknown",)),
        )

    def test_survivor_path_classes_use_exact_namespaces_and_never_process_text(self):
        cases = (
            (PurePosixPath(TEST_TOOLCHAIN["python"]), "python"),
            (PurePosixPath("/bin/ps"), "ps"),
            (PurePosixPath("/usr/bin/clang"), "developer_shim"),
            (PurePosixPath("/usr/libexec/cfprefsd"), "helper_preferences"),
            (PurePosixPath("/usr/libexec/distnoted"), "helper_notifications"),
            (PurePosixPath("/usr/libexec/lsd"), "helper_launch_services"),
            (
                PurePosixPath("/System/Library/Frameworks/CoreServices.framework/Versions/A/Frameworks/LaunchServices.framework/Versions/A/Support/lsd"),
                "helper_launch_services",
            ),
            (PurePosixPath("/usr/libexec/secd"), "helper_security"),
            (PurePosixPath("/usr/libexec/trustd"), "helper_trust"),
            (PurePosixPath("/usr/libexec/containermanagerd"), "helper_containers"),
            (
                PurePosixPath("/System/Library/PrivateFrameworks/ContainerManager.framework/Support/containermanagerd"),
                "helper_containers",
            ),
            (PurePosixPath("/usr/libexec/example-agent"), "apple_system_path"),
            (PurePosixPath("/opt/example-agent"), "other"),
            (PurePosixPath("/tmp/cfprefsd-copy"), "other"),
            (None, "unknown"),
        )
        for path, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(
                    macos_capability._survivor_path_class(path, TEST_TOOLCHAIN["python"]), expected
                )

    def test_macos_path_classification_uses_posix_semantics_on_every_host(self):
        path = PurePosixPath("/usr/libexec/distnoted")
        self.assertTrue(path.is_absolute())
        self.assertEqual(
            macos_capability._survivor_path_class(path, TEST_TOOLCHAIN["python"]),
            "helper_notifications",
        )
        self.assertTrue(all(isinstance(root, PurePosixPath) for root in macos_capability.APPLE_SYSTEM_PATH_ROOTS))

    def test_survivor_path_readback_is_bounded_and_marks_unread_rows_as_additional(self):
        pids = tuple(range(100, 117))
        readback = "".join(f"{pid} 502 0 0\n" for pid in pids[:macos_capability.MAX_SURVIVOR_PATH_READBACKS])
        with patch.object(
            macos_capability,
            "_process_executable",
            return_value=PurePosixPath("/bin/ps"),
        ) as process_path:
            with patch.object(
                macos_capability,
                "_run",
                return_value=subprocess.CompletedProcess([], 0, readback.encode("ascii"), b""),
            ) as command:
                categories = macos_capability._survivor_process_classes(
                    pids, 502, TEST_TOOLCHAIN["python"], additional=True
                )
        self.assertEqual(categories, ("ps", "additional"))
        self.assertEqual(process_path.call_count, macos_capability.MAX_SURVIVOR_PATH_READBACKS)
        selected = ",".join(str(pid) for pid in pids[:macos_capability.MAX_SURVIVOR_PATH_READBACKS])
        self.assertEqual(command.call_args.args[0][2], selected)


class ProbeIdentityDiagnosticTests(unittest.TestCase):
    def _identity_runner(
        self, directory, *, listing=b"runner 501\n", groups=b"staff\n", uid=b"502\n",
        delete_status=0, fail_attribute=False, events=None, census_results=(False, False),
    ):
        parent = Path(directory) / "probe-home"
        parent.mkdir()
        calls = []

        def command(argv, **kwargs):
            calls.append((argv, kwargs))
            if argv[0] == "/usr/bin/dscl" and "-list" in argv:
                return subprocess.CompletedProcess(argv, 0, listing, b"")
            if argv[0] == "/usr/bin/dscl" and "-delete" in argv:
                if events is not None:
                    events.append(("delete", parent.exists()))
                return subprocess.CompletedProcess(argv, delete_status, b"", b"")
            if fail_attribute and argv[0] == "/usr/bin/dscl" and argv[2:4] == ["-create", "/Users/" + macos_capability.USERNAME] and len(argv) > 4:
                raise macos_capability.ProbeFailure("native_preflight_unavailable")
            if argv[0] == "/usr/bin/id" and "-Gn" in argv:
                return subprocess.CompletedProcess(argv, 0, groups, b"")
            if argv[0] == "/usr/bin/id" and "-u" in argv:
                return subprocess.CompletedProcess(argv, 0, uid, b"")
            return subprocess.CompletedProcess(argv, 0, b"", b"")

        with ExitStack() as stack:
            stack.enter_context(patch.object(macos_capability.os, "geteuid", return_value=0, create=True))
            stack.enter_context(patch.object(macos_capability.tempfile, "mkdtemp", return_value=str(parent)))
            stack.enter_context(patch.object(macos_capability.os, "chown", create=True))
            stack.enter_context(patch.object(macos_capability.os, "chmod"))
            stack.enter_context(patch.object(macos_capability, "runner_uid_for_workspace", return_value=501))
            stack.enter_context(patch.object(macos_capability, "_run", side_effect=command))
            stack.enter_context(
                patch.object(macos_capability, "_probe_uid_processes_present", side_effect=census_results)
            )
            if events is not None:
                real_remove = macos_capability._remove_probe_tree

                def remove_and_record(path):
                    events.append(("remove", Path(path).exists()))
                    return real_remove(path)

                stack.enter_context(patch.object(macos_capability, "_remove_probe_tree", side_effect=remove_and_record))
            result = macos_capability._create_probe_identity(Path(directory))
        return result, calls, parent

    def test_identity_readback_proves_distinct_non_admin_account_without_claiming_sudo_absence(self):
        with tempfile.TemporaryDirectory(prefix="macos-identity-test-") as directory:
            (uid, parent, home), calls, _ = self._identity_runner(directory)
            self.assertEqual(uid, 502)
            self.assertEqual(home, parent / "home")
            self.assertIn(["/usr/bin/id", "-Gn", macos_capability.USERNAME], [call[0] for call in calls])
            self.assertIn(["/usr/bin/id", "-u", macos_capability.USERNAME], [call[0] for call in calls])
            self.assertFalse(any(call[0][0] == "/usr/bin/sudo" for call in calls))
            shutil.rmtree(parent, ignore_errors=True)

    def test_admin_and_developer_group_membership_refuse_and_clean_created_identity(self):
        for groups in (b"staff admin\n", b"staff _developer\n"):
            with self.subTest(groups=groups), tempfile.TemporaryDirectory(prefix="macos-identity-test-") as directory:
                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                    self._identity_runner(directory, groups=groups)
                self.assertEqual(raised.exception.reason, "probe_identity_unavailable")
                self.assertEqual(raised.exception.check, "probe_identity_readback")
                self.assertFalse((Path(directory) / "probe-home").exists())

    def test_malformed_group_and_uid_readback_refuse(self):
        cases = ((b"staff\nextra\n", b"502\n"), (b"staff\n", b"502\n502\n"), (b"staff\n", b"503\n"))
        for groups, uid in cases:
            with self.subTest(groups=groups, uid=uid), tempfile.TemporaryDirectory(prefix="macos-identity-test-") as directory:
                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                    self._identity_runner(directory, groups=groups, uid=uid)
                self.assertEqual(raised.exception.reason, "probe_identity_unavailable")
                self.assertEqual(raised.exception.check, "probe_identity_readback")
                self.assertFalse((Path(directory) / "probe-home").exists())

    def test_identity_inventory_refuses_existing_fixed_name_or_malformed_records(self):
        for listing in (
            b"ci-sandbox-probe 502\n",
            b"broken record\n",
            b"negative -\n",
            b"positive +2\n",
            b"double-sign --2\n",
            b"non-ascii \xc2\xb2\n",
        ):
            with self.subTest(listing=listing), tempfile.TemporaryDirectory(prefix="macos-identity-test-") as directory:
                def command(argv, **kwargs):
                    return subprocess.CompletedProcess(argv, 0, listing, b"")

                with patch.object(macos_capability.os, "geteuid", return_value=0, create=True):
                    with patch.object(macos_capability, "_run", side_effect=command):
                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                            with macos_capability._preflight_phase("probe_identity"):
                                macos_capability._create_probe_identity(Path(directory))
                self.assertEqual(raised.exception.reason, "probe_identity_unavailable")
                self.assertEqual(raised.exception.check, "probe_identity_inventory")

    def test_selected_uid_is_censused_before_home_or_account_creation(self):
        with tempfile.TemporaryDirectory(prefix="macos-identity-census-") as directory:
            with patch.object(macos_capability.os, "geteuid", return_value=0, create=True):
                with patch.object(
                    macos_capability,
                    "_run",
                    return_value=subprocess.CompletedProcess([], 0, b"runner 501\n", b""),
                ) as command:
                    with patch.object(macos_capability, "_probe_uid_processes_present", return_value=True) as census:
                        with patch.object(macos_capability.tempfile, "mkdtemp") as make_home:
                            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                with macos_capability._preflight_phase("probe_identity"):
                                    macos_capability._create_probe_identity(Path(directory))
            self.assertEqual(raised.exception.reason, "probe_identity_unavailable")
            self.assertEqual(raised.exception.check, "probe_identity_census")
            census.assert_called_once_with(502)
            command.assert_called_once_with(["/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"], timeout=10)
            make_home.assert_not_called()

    def test_identity_inventory_accepts_ascii_negative_uids_and_preserves_positive_collision_scan(self):
        with tempfile.TemporaryDirectory(prefix="macos-identity-test-") as directory:
            listing = b"legacy -2\nrunner 501\noccupied 502\n"
            (uid, parent, home), calls, _ = self._identity_runner(
                directory, listing=listing, uid=b"503\n"
            )
            self.assertEqual(uid, 503)
            self.assertEqual(home, parent / "home")
            self.assertIn(
                ["/usr/bin/dscl", ".", "-create", "/Users/" + macos_capability.USERNAME, "UniqueID", "503"],
                [call[0] for call in calls],
            )
            shutil.rmtree(parent, ignore_errors=True)

    def test_signed_uid_normalization_is_bounded_to_darwin_uid_width(self):
        self.assertEqual(
            macos_capability._parse_darwin_uid("-2"),
            (-2, 4294967294),
        )
        self.assertEqual(
            macos_capability._parse_darwin_uid("4294967295"),
            (4294967295, 4294967295),
        )
        self.assertEqual(
            macos_capability._parse_darwin_uid("-2147483648"),
            (-2147483648, 2147483648),
        )
        self.assertIsNone(macos_capability._parse_darwin_uid("-4294966794"))
        self.assertIsNone(macos_capability._parse_darwin_uid("4294967296"))

    def test_out_of_range_signed_alias_refuses_before_account_creation(self):
        listing = b"runner 501\noverflow -4294966794\n"
        calls = []
        with tempfile.TemporaryDirectory(prefix="macos-identity-test-") as directory:
            def command(argv, **kwargs):
                calls.append(argv)
                return subprocess.CompletedProcess(argv, 0, listing, b"")

            with patch.object(macos_capability.os, "geteuid", return_value=0, create=True):
                with patch.object(macos_capability, "_run", side_effect=command):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        with macos_capability._preflight_phase("probe_identity"):
                            macos_capability._create_probe_identity(Path(directory))
        self.assertEqual(raised.exception.reason, "probe_identity_unavailable")
        self.assertEqual(raised.exception.check, "probe_identity_inventory")
        self.assertEqual(calls, [["/usr/bin/dscl", ".", "-list", "/Users", "UniqueID"]])

    def test_ambiguous_create_timeout_preserves_home_and_never_deletes_account(self):
        with tempfile.TemporaryDirectory(prefix="macos-identity-timeout-") as directory:
            parent = Path(directory) / "probe-home"
            parent.mkdir()
            calls = []

            def command(argv, **kwargs):
                calls.append(argv)
                if "-list" in argv:
                    return subprocess.CompletedProcess(argv, 0, b"runner 501\n", b"")
                raise macos_capability.ProbeFailure("native_preflight_unavailable", cleanup_complete=False)

            with ExitStack() as stack:
                stack.enter_context(patch.object(macos_capability.os, "geteuid", return_value=0, create=True))
                stack.enter_context(patch.object(macos_capability.tempfile, "mkdtemp", return_value=str(parent)))
                stack.enter_context(patch.object(macos_capability.os, "chown", create=True))
                stack.enter_context(patch.object(macos_capability.os, "chmod"))
                stack.enter_context(patch.object(macos_capability, "runner_uid_for_workspace", return_value=501))
                stack.enter_context(patch.object(macos_capability, "_probe_uid_processes_present", return_value=False))
                stack.enter_context(patch.object(macos_capability, "_run", side_effect=command))
                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                    with macos_capability._preflight_phase("probe_identity"):
                        macos_capability._create_probe_identity(Path(directory))
            self.assertFalse(raised.exception.cleanup_complete)
            self.assertEqual(raised.exception.check, "probe_identity_create")
            self.assertEqual(calls[-1], ["/usr/bin/dscl", ".", "-create", "/Users/" + macos_capability.USERNAME])
            self.assertTrue(parent.exists())

    def test_identity_cleanup_removes_home_then_refuses_when_account_delete_fails(self):
        with tempfile.TemporaryDirectory(prefix="macos-identity-cleanup-") as directory:
            events = []
            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                self._identity_runner(directory, groups=b"staff admin\n", delete_status=1, events=events)
            self.assertFalse(raised.exception.cleanup_complete)
            self.assertEqual(raised.exception.check, "probe_identity_cleanup")
            self.assertFalse((Path(directory) / "probe-home").exists())
            self.assertEqual(events, [("remove", True), ("delete", False)])

    def test_setup_error_keeps_account_and_home_when_uid_census_is_uncertain(self):
        with tempfile.TemporaryDirectory(prefix="macos-identity-cleanup-census-") as directory:
            events = []
            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                self._identity_runner(
                    directory,
                    fail_attribute=True,
                    events=events,
                    census_results=(False, macos_capability.ProbeFailure("native_preflight_unavailable")),
                )
            self.assertEqual(raised.exception.reason, "native_preflight_unavailable")
            self.assertEqual(raised.exception.check, "probe_identity_cleanup")
            self.assertFalse(raised.exception.cleanup_complete)
            self.assertEqual(events, [])
            self.assertTrue((Path(directory) / "probe-home").exists())

    def test_identity_failure_refuses_when_home_removal_errors_or_leaves_path(self):
        for remove_behavior in (PermissionError("home-delete-error"), None):
            with self.subTest(remove_behavior=remove_behavior), tempfile.TemporaryDirectory(
                prefix="macos-identity-home-cleanup-"
            ) as directory:
                events = []
                parent = Path(directory) / "probe-home"
                if remove_behavior is None:
                    remove = lambda path: None
                else:
                    remove = unittest.mock.Mock(side_effect=remove_behavior)
                with patch.object(macos_capability.shutil, "rmtree", side_effect=remove):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        self._identity_runner(directory, groups=b"staff admin\n", events=events)
                self.assertEqual(raised.exception.reason, "native_preflight_unavailable")
                self.assertEqual(raised.exception.check, "probe_identity_cleanup")
                self.assertFalse(raised.exception.cleanup_complete)
                self.assertTrue(parent.is_dir())
                self.assertEqual(events, [("remove", True)])
                shutil.rmtree(parent)

    def test_failure_after_account_creation_removes_only_the_created_account(self):
        with tempfile.TemporaryDirectory(prefix="macos-identity-test-") as directory:
            events = []
            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                self._identity_runner(directory, fail_attribute=True, events=events)
            self.assertEqual(raised.exception.check, "probe_identity_attributes")
            self.assertFalse((Path(directory) / "probe-home").exists())
            self.assertEqual(events, [("remove", True), ("delete", False)])


class ProbeIdentityBootstrapTests(unittest.TestCase):
    def setUp(self):
        original = macos_capability._run_as_probe_user

        def launch_with_test_binding(*args, **kwargs):
            kwargs.setdefault("python_executable", TEST_TOOLCHAIN["python"])
            return original(*args, **kwargs)

        self.launch_patcher = patch.object(
            macos_capability, "_run_as_probe_user", side_effect=launch_with_test_binding
        )
        self.launch_patcher.start()
        self.addCleanup(self.launch_patcher.stop)

    def run_bootstrap(
        self,
        *,
        identifiers=None,
        groups=(20,),
        ps_values=(502, 502, 502, 20, 20, 20),
        ps_output=None,
        ps_status=0,
        ps_stderr=b"",
        short_marker_write=False,
        source=None,
    ):
        class StopBootstrap(BaseException):
            pass

        identity_values = {"getuid": 502, "geteuid": 502, "getgid": 20, "getegid": 20}
        identity_values.update(identifiers or {})
        if ps_output is None:
            ps_output = " ".join(str(value) for value in ps_values).encode("ascii") + b"\n"
        events = {"writes": [], "exec": [], "exit": [], "ps": []}

        class GroupReader:
            def __init__(self, values):
                self.values = tuple(values)
                self.argtypes = None
                self.restype = None

            def __call__(self, count, buffer):
                if count == 0:
                    return len(self.values)
                if count < len(self.values):
                    return -1
                for index, value in enumerate(self.values):
                    buffer[index] = value
                return len(self.values)

        group_reader = GroupReader(groups)
        fake_os = types.SimpleNamespace(
            **{name: (lambda value=value: value) for name, value in identity_values.items()}
        )
        fake_os.getpid = lambda: 999

        def write(fd, data):
            data = bytes(data)
            events["writes"].append((fd, data))
            if short_marker_write and data == macos_capability.PROBE_IDENTITY_VERIFIED:
                return len(data) - 1
            return len(data)

        def execv(path, argv):
            events["exec"].append((path, list(argv)))

        def exit_process(code):
            events["exit"].append(code)
            raise StopBootstrap()

        fake_os.write = write
        fake_os.execv = execv
        fake_os._exit = exit_process
        ps_run = types.SimpleNamespace(
            returncode=ps_status,
            stdout=ps_output,
            stderr=ps_stderr,
        )
        fake_subprocess = types.SimpleNamespace(
            DEVNULL=object(),
            PIPE=object(),
            run=lambda argv, **kwargs: (events["ps"].append((argv, kwargs)) or ps_run),
        )
        fake_ctypes = types.SimpleNamespace(
            CDLL=lambda name, use_errno: types.SimpleNamespace(getgroups=group_reader),
            c_int=ctypes.c_int,
            POINTER=ctypes.POINTER,
            c_uint32=ctypes.c_uint32,
        )
        fake_sys = types.SimpleNamespace(argv=["-c", "502", "20", "/usr/bin/true"])
        modules = {
            "ctypes": fake_ctypes,
            "os": fake_os,
            "subprocess": fake_subprocess,
            "sys": fake_sys,
        }
        python_builtins = vars(builtins).copy()
        python_builtins["__import__"] = lambda name, *args, **kwargs: modules[name]
        try:
            exec(source or macos_capability.PROBE_IDENTITY_BOOTSTRAP, {"__builtins__": python_builtins})
        except StopBootstrap:
            pass
        return events

    def assert_refused_without_exec(self, **kwargs):
        events = self.run_bootstrap(**kwargs)
        self.assertEqual(events["exec"], [])
        self.assertTrue(events["exit"])
        self.assertTrue(all(code == 125 for code in events["exit"]))
        return events

    def test_bootstrap_checks_kernel_credentials_then_execs_target(self):
        events = self.run_bootstrap()
        self.assertEqual(events["writes"], [(2, macos_capability.PROBE_IDENTITY_VERIFIED)])
        self.assertEqual(events["exec"], [("/usr/bin/true", ["/usr/bin/true"])])
        self.assertEqual(events["exit"], [])
        argv, kwargs = events["ps"][0]
        self.assertEqual(
            argv,
            ["/bin/ps", "-p", "999", "-o", "ruid=,uid=,svuid=,rgid=,gid=,svgid="],
        )
        self.assertEqual(kwargs["timeout"], 3)
        self.assertTrue(kwargs["close_fds"])

    def test_bootstrap_refuses_all_credential_group_and_process_readback_mismatches(self):
        identifier_cases = []
        for name in ("getuid", "geteuid", "getgid", "getegid"):
            identifier_cases.append(("identifier-" + name, {name: 0}))
        for index in range(6):
            ps_values = [502, 502, 502, 20, 20, 20]
            ps_values[index] = 0
            identifier_cases.append(("ps-field-" + str(index), {"ps_values": tuple(ps_values)}))
        group_cases = (
            ("empty-groups", ()),
            ("wrong-group", (0,)),
            ("extra-group", (20, 80)),
            ("duplicate-group", (20, 20)),
            ("too-many-groups", tuple(range(17))),
        )
        ps_cases = (
            ("empty-ps", {"ps_output": b""}),
            ("extra-ps-field", {"ps_output": b"502 502 502 20 20 20 1\n"}),
            ("oversized-ps", {"ps_output": b"x" * 129}),
            ("failed-ps", {"ps_status": 1}),
            ("ps-stderr", {"ps_stderr": b"error\n"}),
        )
        for name, changes in identifier_cases:
            with self.subTest(case=name):
                identifiers = {"getuid": 502, "geteuid": 502, "getgid": 20, "getegid": 20}
                if name.startswith("identifier-"):
                    identifiers.update(changes)
                    self.assert_refused_without_exec(identifiers=identifiers)
                else:
                    self.assert_refused_without_exec(**changes)
        for name, values in group_cases:
            with self.subTest(case=name):
                self.assert_refused_without_exec(groups=values)
        for name, changes in ps_cases:
            with self.subTest(case=name):
                self.assert_refused_without_exec(**changes)
        with self.subTest(case="short-marker-write"):
            self.assert_refused_without_exec(short_marker_write=True)

    def test_effective_uid_readback_is_a_required_security_check(self):
        mutated = macos_capability.PROBE_IDENTITY_BOOTSTRAP.replace(
            "or os.geteuid() != uid", "or False"
        )
        events = self.run_bootstrap(
            identifiers={"getuid": 502, "geteuid": 0, "getgid": 20, "getegid": 20},
            source=mutated,
        )
        self.assertEqual(events["exec"], [("/usr/bin/true", ["/usr/bin/true"])])

    def test_identity_marker_parser_rejects_missing_or_malformed_records(self):
        self.assertEqual(
            macos_capability._strip_probe_identity_record(
                macos_capability.PROBE_IDENTITY_VERIFIED + b"target stderr"
            ),
            b"target stderr",
        )
        for record in (
            b"",
            b"unexpected" + macos_capability.PROBE_IDENTITY_VERIFIED,
            macos_capability.PROBE_IDENTITY_VERIFIED.rstrip(b"\n"),
            macos_capability.PROBE_IDENTITY_REFUSED,
        ):
            with self.subTest(record=record):
                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                    macos_capability._strip_probe_identity_record(record)
                self.assertEqual(raised.exception.check, "probe_process_identity")

    def test_probe_user_timeout_is_bounded_and_group_cleanup_is_checked(self):
        class StubProcess:
            pid = 12345
            stdout = io.BytesIO(b"")
            stderr = io.BytesIO(b"")
            returncode = None

            def wait(self, timeout):
                raise subprocess.TimeoutExpired("stub-probe", timeout)

            def poll(self):
                return self.returncode

        process = StubProcess()
        with patch.object(macos_capability.subprocess, "Popen", return_value=process) as popen:
            with patch.object(macos_capability, "_terminate_probe_tree", return_value=True) as cleanup:
                with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._run_as_probe_user(["/usr/bin/true"], 502, timeout=3)
        self.assertEqual(raised.exception.check, "probe_process_timeout")
        self.assertFalse(raised.exception.cleanup_complete)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(popen.call_args.kwargs["close_fds"], True)
        self.assertEqual(popen.call_args.kwargs["user"], 502)
        self.assertEqual(popen.call_args.kwargs["group"], macos_capability.PROBE_PRIMARY_GID)
        self.assertEqual(popen.call_args.kwargs["extra_groups"], ())
        cleanup.assert_called_once_with(process)

    def test_probe_user_census_detects_detached_child_after_group_cleanup(self):
        class StubProcess:
            pid = 12346
            stdout = io.BytesIO(b"")
            stderr = io.BytesIO(b"")
            returncode = 0

            def wait(self, timeout):
                return 0

            def poll(self):
                return self.returncode

        process = StubProcess()
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(True, ())):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._run_as_probe_user(["/usr/bin/true"], 502, timeout=3)
        self.assertEqual(raised.exception.check, "probe_process_survivor")
        self.assertFalse(raised.exception.cleanup_complete)

    def test_descendant_pid_does_not_define_control_group_classification(self):
        output = b"10 10 S 0 0 0\n20 12352 R 502 502 502\n"
        with patch.object(
            macos_capability,
            "_run",
            return_value=subprocess.CompletedProcess([], 0, output, b""),
        ):
            self.assertEqual(
                macos_capability._probe_uid_process_snapshot(502, launched_pgid=12352),
                (True, "probe_process_survivor_controls_same_group"),
            )

    def test_control_access_probe_uses_one_authoritative_group_census(self):
        process = type(
            "CompletedProcess",
            (),
            {
                "pid": 12352,
                "stdout": io.BytesIO(b""),
                "stderr": io.BytesIO(macos_capability.PROBE_IDENTITY_VERIFIED),
                "returncode": 0,
            },
        )()
        process.wait = lambda timeout: process.returncode
        process.poll = lambda: process.returncode
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                with patch.object(
                    macos_capability,
                    "_probe_uid_process_snapshot",
                    return_value=(True, "probe_process_survivor_controls_multiple", ()),
                ) as census:
                    with patch.object(
                        macos_capability,
                        "_probe_uid_processes_present",
                    ) as ordinary_census:
                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                            macos_capability._run_as_probe_user(
                                ["/usr/bin/true"], 502, timeout=3, control_survivor_diagnostics=True
                            )
        self.assertEqual(raised.exception.check, "probe_process_survivor_controls_multiple")
        self.assertFalse(raised.exception.cleanup_complete)
        census.assert_called_once_with(
            502,
            launched_pgid=12352,
            include_survivor_classes=True,
            python_executable=TEST_TOOLCHAIN["python"],
        )
        ordinary_census.assert_not_called()

    def test_control_access_probe_accepts_only_a_clean_zero_match_snapshot(self):
        process = type(
            "CompletedProcess",
            (),
            {
                "pid": 12352,
                "stdout": io.BytesIO(b""),
                "stderr": io.BytesIO(macos_capability.PROBE_IDENTITY_VERIFIED),
                "returncode": 0,
            },
        )()
        process.wait = lambda timeout: process.returncode
        process.poll = lambda: process.returncode
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                with patch.object(
                    macos_capability,
                    "_probe_uid_process_snapshot",
                    return_value=(False, None, ()),
                ) as census:
                    with patch.object(macos_capability, "_probe_uid_processes_present") as ordinary_census:
                        result = macos_capability._run_as_probe_user(
                            ["/usr/bin/true"], 502, timeout=3, control_survivor_diagnostics=True
                        )
        self.assertEqual(result.stdout, b"")
        census.assert_called_once_with(
            502,
            launched_pgid=12352,
            include_survivor_classes=True,
            python_executable=TEST_TOOLCHAIN["python"],
        )
        ordinary_census.assert_not_called()

    def test_positive_control_snapshot_without_fixed_category_fails_closed(self):
        process = type(
            "CompletedProcess",
            (),
            {"pid": 12352, "stdout": io.BytesIO(b""), "stderr": io.BytesIO(b""), "returncode": 0},
        )()
        process.wait = lambda timeout: process.returncode
        process.poll = lambda: process.returncode
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                with patch.object(
                    macos_capability,
                    "_probe_uid_process_snapshot",
                    return_value=(True, "probe_process_survivor_controls_unattributed", ()),
                ):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._run_as_probe_user(
                            ["/usr/bin/true"], 502, timeout=3, control_survivor_diagnostics=True
                        )
        self.assertEqual(raised.exception.check, "probe_process_survivor_controls_unattributed")
        self.assertFalse(raised.exception.cleanup_complete)

    def test_malformed_control_snapshot_preserves_census_refusal(self):
        process = type(
            "CompletedProcess",
            (),
            {"pid": 12352, "stdout": io.BytesIO(b""), "stderr": io.BytesIO(b""), "returncode": 0},
        )()
        process.wait = lambda timeout: process.returncode
        process.poll = lambda: process.returncode
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                with patch.object(
                    macos_capability,
                    "_probe_uid_process_snapshot",
                    side_effect=macos_capability.ProbeFailure(
                        "native_preflight_unavailable", cleanup_complete=False, check="probe_process_census"
                    ),
                ):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._run_as_probe_user(
                            ["/usr/bin/true"], 502, timeout=3, control_survivor_diagnostics=True
                        )
        self.assertEqual(raised.exception.check, "probe_process_census")
        self.assertFalse(raised.exception.cleanup_complete)

    def test_control_snapshot_does_not_override_tree_or_capture_cleanup_failures(self):
        process = type(
            "CompletedProcess",
            (),
            {"pid": 12352, "stdout": io.BytesIO(b""), "stderr": io.BytesIO(b""), "returncode": 0},
        )()
        process.wait = lambda timeout: process.returncode
        process.poll = lambda: process.returncode
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(macos_capability, "_terminate_probe_tree", return_value=False):
                with patch.object(
                    macos_capability,
                    "_probe_uid_process_snapshot",
                    return_value=(True, "probe_process_survivor_controls_same_group", ()),
                ):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._run_as_probe_user(
                            ["/usr/bin/true"], 502, timeout=3, control_survivor_diagnostics=True
                        )
        self.assertEqual(raised.exception.check, "probe_process_group_cleanup")
        self.assertFalse(raised.exception.cleanup_complete)

        process = type(
            "CompletedProcess",
            (),
            {"pid": 12353, "stdout": io.BytesIO(b""), "stderr": io.BytesIO(b""), "returncode": 0},
        )()
        process.wait = lambda timeout: process.returncode
        process.poll = lambda: process.returncode
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                with patch.object(macos_capability._Capture, "join", return_value=False):
                    with patch.object(
                        macos_capability,
                        "_probe_uid_process_snapshot",
                        return_value=(True, "probe_process_survivor_controls_same_group", ()),
                    ):
                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                            macos_capability._run_as_probe_user(
                                ["/usr/bin/true"], 502, timeout=3, control_survivor_diagnostics=True
                            )
        self.assertEqual(raised.exception.check, "probe_process_capture_cleanup")
        self.assertFalse(raised.exception.cleanup_complete)

    def test_runner_control_access_requests_control_survivor_correlation(self):
        with patch.object(macos_capability, "_run_as_probe_user") as command:
            macos_capability._verify_runner_controls_are_private(
                ["/protected"], 502, TEST_TOOLCHAIN["python"]
            )
        self.assertTrue(command.call_args.kwargs["control_survivor_diagnostics"])
        self.assertEqual(command.call_args.args[0][0], TEST_TOOLCHAIN["python"])
        self.assertEqual(command.call_args.kwargs["python_executable"], TEST_TOOLCHAIN["python"])

    def test_probe_user_survivor_diagnostic_is_fixed_to_caller_phase(self):
        class StubProcess:
            pid = 12350
            stdout = io.BytesIO(b"")
            stderr = io.BytesIO(b"")
            returncode = 0

            def wait(self, timeout):
                return 0

            def poll(self):
                return self.returncode

        process = StubProcess()
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(True, ())):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._run_as_probe_user(
                            ["/usr/bin/true"], 502, timeout=3,
                            survivor_check="probe_process_survivor_positive_read",
                        )
        self.assertEqual(raised.exception.check, "probe_process_survivor_positive_read")
        self.assertFalse(raised.exception.cleanup_complete)

    def test_probe_user_invalid_survivor_diagnostic_still_refuses(self):
        class StubProcess:
            def __init__(self):
                self.pid = 12351
                self.stdout = io.BytesIO(b"")
                self.stderr = io.BytesIO(b"")
                self.returncode = 0

            def wait(self, timeout):
                return 0

            def poll(self):
                return self.returncode

        for survivor_check in (None, "private/path", []):
            with self.subTest(survivor_check_type=type(survivor_check).__name__):
                process = StubProcess()
                with patch.object(macos_capability.subprocess, "Popen", return_value=process):
                    with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                        with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(True, ())):
                            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                macos_capability._run_as_probe_user(
                                    ["/usr/bin/true"], 502, timeout=3,
                                    survivor_check=survivor_check,
                                )
                self.assertEqual(raised.exception.check, "probe_process_survivor")
                self.assertFalse(raised.exception.cleanup_complete)

    def test_probe_user_group_cleanup_failure_has_fixed_subphase(self):
        class StubProcess:
            pid = 12349
            stdout = io.BytesIO(b"")
            stderr = io.BytesIO(b"")
            returncode = 0

            def wait(self, timeout):
                return 0

            def poll(self):
                return self.returncode

        process = StubProcess()
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(macos_capability, "_terminate_probe_tree", return_value=False):
                with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._run_as_probe_user(["/usr/bin/true"], 502, timeout=3)
        self.assertEqual(raised.exception.check, "probe_process_group_cleanup")
        self.assertFalse(raised.exception.cleanup_complete)

    def test_probe_user_normal_completion_requires_clean_census(self):
        class StubProcess:
            pid = 12347
            stdout = io.BytesIO(b"safe output\n")
            stderr = io.BytesIO(macos_capability.PROBE_IDENTITY_VERIFIED)
            returncode = 0

            def wait(self, timeout):
                return 0

            def poll(self):
                return self.returncode

        process = StubProcess()
        with patch.object(macos_capability.subprocess, "Popen", return_value=process) as popen:
            with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())) as census:
                    result = macos_capability._run_as_probe_user(["/usr/bin/true"], 502, timeout=3)
        self.assertEqual(result.stdout, b"safe output\n")
        self.assertEqual(result.stderr, b"")
        command = popen.call_args.args[0]
        self.assertEqual(
            command[:5], [TEST_TOOLCHAIN["python"], "-I", "-S", "-B", "-c"]
        )
        self.assertEqual(command[5], macos_capability.PROBE_IDENTITY_BOOTSTRAP)
        self.assertEqual(command[6:], ["502", "20", "/usr/bin/true"])
        self.assertNotIn("/usr/bin/sudo", command)
        self.assertEqual(popen.call_args.kwargs["user"], 502)
        self.assertEqual(popen.call_args.kwargs["group"], macos_capability.PROBE_PRIMARY_GID)
        self.assertEqual(popen.call_args.kwargs["extra_groups"], ())
        census.assert_called_once_with(
            502, include_survivor_classes=True, python_executable=TEST_TOOLCHAIN["python"]
        )

    def test_probe_user_identity_mismatch_or_missing_marker_refuses(self):
        class StubProcess:
            pid = 12354
            stdout = io.BytesIO(b"")
            returncode = 125

            def __init__(self, marker):
                self.stderr = io.BytesIO(marker)

            def wait(self, timeout):
                return self.returncode

            def poll(self):
                return self.returncode

        for marker in (macos_capability.PROBE_IDENTITY_REFUSED, b""):
            with self.subTest(marker=marker):
                process = StubProcess(marker)
                with patch.object(macos_capability.subprocess, "Popen", return_value=process):
                    with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                        with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                macos_capability._run_as_probe_user(["/usr/bin/true"], 502, timeout=3)
                self.assertEqual(raised.exception.reason, "probe_identity_unavailable")
                self.assertEqual(raised.exception.check, "probe_process_identity")

    def test_probe_user_old_python_or_missing_keyword_support_fails_without_sudo_fallback(self):
        process = type("StubProcess", (), {"pid": 12355})()
        for version, launch_error in (((3, 8, 0), None), ((3, 14, 0), TypeError("unsupported keyword"))):
            with self.subTest(version=version):
                with patch.object(macos_capability, "sys") as runtime:
                    runtime.version_info = version
                    runtime.platform = "linux"
                    runtime.executable = str(Path(sys.executable).resolve(strict=True))
                    with patch.object(macos_capability.subprocess, "Popen", side_effect=launch_error) as popen:
                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                            macos_capability._run_as_probe_user(
                                ["/usr/bin/true"], 502, python_executable=TEST_TOOLCHAIN["python"]
                            )
                self.assertEqual(raised.exception.reason, "native_preflight_unavailable")
                self.assertEqual(raised.exception.check, "probe_process_launch")
                self.assertEqual(popen.call_count, int(version >= (3, 9, 0)))

    def test_probe_user_wait_error_is_incomplete_even_with_clean_snapshot(self):
        class StubProcess:
            pid = 12348
            stdout = io.BytesIO(b"")
            stderr = io.BytesIO(b"")
            returncode = None

            def wait(self, timeout):
                raise OSError("private wait detail")

            def poll(self):
                return self.returncode

        process = StubProcess()
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._run_as_probe_user(["/usr/bin/true"], 502, timeout=3)
        self.assertEqual(raised.exception.check, "probe_process_timeout")
        self.assertFalse(raised.exception.cleanup_complete)


class DeveloperModeReadbackTests(unittest.TestCase):
    def test_disable_uses_c_locale_and_requires_exact_disabled_status(self):
        success = subprocess.CompletedProcess([], 0, b"", b"")
        status = subprocess.CompletedProcess([], 0, b"Developer mode is currently disabled.\n", b"")
        with patch.object(macos_capability, "_run", side_effect=(success, status)) as command:
            macos_capability._disable_developer_mode()
        self.assertEqual(command.call_args_list[0].args[0], ["/usr/sbin/DevToolsSecurity", "-disable"])
        self.assertEqual(command.call_args_list[1].args[0], ["/usr/sbin/DevToolsSecurity", "-status"])
        for call in command.call_args_list:
            self.assertEqual(call.kwargs["env"], {"LANG": "C", "LC_ALL": "C"})
            self.assertEqual(call.kwargs["timeout"], 10)

    def test_enabled_extra_or_ambiguous_status_refuses(self):
        cases = (
            (b"Developer mode is currently enabled.\n", b""),
            (b"prefix Developer mode is currently disabled.\n", b""),
            (b"Developer mode is currently disabled.\nextra\n", b""),
            (b"Developer mode is currently disabled.\n", b"warning\n"),
            (b"Developer mode is currently disabled.", b""),
        )
        for stdout, stderr in cases:
            with self.subTest(stdout=stdout, stderr=stderr):
                status = subprocess.CompletedProcess([], 0, stdout, stderr)
                with patch.object(macos_capability, "_run", side_effect=(subprocess.CompletedProcess([], 0, b"", b""), status)):
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        macos_capability._disable_developer_mode()
                self.assertEqual(raised.exception.reason, "developer_mode_unavailable")

    def test_disable_or_status_command_failure_refuses(self):
        for results in (
            (subprocess.CompletedProcess([], 1, b"", b""),),
            (subprocess.CompletedProcess([], 0, b"", b""), subprocess.CompletedProcess([], 1, b"", b"")),
        ):
            with self.subTest(results=results):
                with patch.object(macos_capability, "_run", side_effect=results):
                    with self.assertRaises(macos_capability.ProbeFailure):
                        macos_capability._disable_developer_mode()


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
    def setUp(self):
        self.toolchain_patcher = patch.object(
            macos_capability, "_resolve_trusted_toolchain", return_value=TEST_TOOLCHAIN
        )
        self.toolchain_patcher.start()
        self.addCleanup(self.toolchain_patcher.stop)

    def observe_probe(self, *args):
        return macos_capability._observe_probe(
            *args,
            python_executable=TEST_TOOLCHAIN["python"],
            compiler_executable=TEST_TOOLCHAIN["clang"],
            linker_executable=TEST_TOOLCHAIN["linker"],
            sdk_root=TEST_TOOLCHAIN["sdk"],
        )

    def test_bootstrap_and_later_mismatched_root_rows_cannot_supply_probe_roles(self):
        class StubProcess:
            pid = 12340
            stdout = io.BytesIO(b"")
            stderr = io.BytesIO(macos_capability.PROBE_IDENTITY_VERIFIED)
            returncode = None

            def __init__(self):
                self.poll_calls = 0

            def poll(self):
                self.poll_calls += 1
                return None if self.poll_calls < 4 else 0

            def wait(self, timeout):
                self.returncode = 0
                return 0

        process = StubProcess()
        uid = 502
        bootstrap_rows = {
            process.pid: (1, uid, "/usr/bin/python3"),
            12341: (process.pid, uid, "/bin/ps"),
        }
        signed_probe_rows = {
            process.pid: (1, uid, chr(47) + "private/tmp/CapabilityProbe"),
            12342: (process.pid, uid, "CapabilityChild"),
            12343: (process.pid, uid, "/bin/sh"),
            12344: (process.pid, uid, "/bin/sleep"),
            12345: (process.pid, uid, "capability-child"),
            12346: (process.pid, uid, "capability-child"),
            12347: (process.pid, uid, "/usr/bin/clang"),
        }
        later_mismatch_rows = dict(signed_probe_rows)
        later_mismatch_rows[process.pid] = (1, uid, "/usr/bin/python3")
        later_mismatch_rows[12348] = (process.pid, uid, "/usr/bin/python3")

        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(
                macos_capability,
                "_process_table",
                side_effect=(bootstrap_rows, signed_probe_rows, later_mismatch_rows),
            ) as table:
                with patch.object(macos_capability, "_descriptor_snapshot", return_value={}) as descriptors:
                    with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                        with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                            with patch.object(macos_capability.time, "sleep"):
                                with self.assertRaisesRegex(
                                    macos_capability.ProbeFailure,
                                    "descriptor_readback_unavailable",
                                ):
                                    self.observe_probe(
                                        "/tmp/CapabilityProbe", "/tmp/marker", "/tmp/outside", uid, "/tmp/home"
                                    )

        self.assertEqual(table.call_count, 3)
        descriptors.assert_called_once()
        sampled_pids = descriptors.call_args.args[0]
        self.assertEqual(set(sampled_pids), set(signed_probe_rows))

    def test_observe_census_detects_detached_child_after_group_cleanup(self):
        process = type(
            "CompletedProcess",
            (),
            {"pid": 12344, "stdout": io.BytesIO(), "stderr": io.BytesIO(), "returncode": 0},
        )()
        process.poll = lambda: process.returncode
        process.wait = lambda timeout: process.returncode
        with patch.object(macos_capability.subprocess, "Popen", return_value=process) as popen:
            with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(True, ())) as census:
                    with self.assertRaises(macos_capability.ProbeFailure) as raised:
                        self.observe_probe("/tmp/unused", "unused", "unused", 502, "unused")
        self.assertEqual(raised.exception.check, "probe_process_survivor_probe_tree")
        self.assertFalse(raised.exception.cleanup_complete)
        census.assert_called_once_with(
            502, include_survivor_classes=True, python_executable=TEST_TOOLCHAIN["python"]
        )
        command = popen.call_args.args[0]
        self.assertEqual(command[:5], [TEST_TOOLCHAIN["python"], "-I", "-S", "-B", "-c"])
        self.assertNotIn("/usr/bin/sudo", command)
        self.assertEqual(popen.call_args.kwargs["user"], 502)
        self.assertEqual(popen.call_args.kwargs["group"], macos_capability.PROBE_PRIMARY_GID)
        self.assertEqual(popen.call_args.kwargs["extra_groups"], ())
        self.assertEqual(popen.call_args.kwargs["cwd"], "/tmp")

    def test_observe_timeout_is_never_cleanup_complete(self):
        process = type(
            "TimedOutProcess",
            (),
            {"pid": 12343, "stdout": io.BytesIO(), "stderr": io.BytesIO(), "returncode": None},
        )()
        process.poll = lambda: None

        def wait(timeout):
            raise subprocess.TimeoutExpired("stub-probe", timeout)

        process.wait = wait
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(macos_capability, "MAX_PROBE_SECONDS", 0):
                with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                    with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                            self.observe_probe("/tmp/unused", "unused", "unused", 502, "unused")
        self.assertEqual(raised.exception.reason, "probe_timeout")
        self.assertFalse(raised.exception.cleanup_complete)

    def test_observe_wait_error_is_never_cleanup_complete(self):
        process = type(
            "WaitErrorProcess",
            (),
            {"pid": 12342, "stdout": io.BytesIO(), "stderr": io.BytesIO(), "returncode": None},
        )()
        process.poll = lambda: None

        def wait(timeout):
            raise OSError("private wait detail")

        process.wait = wait
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(macos_capability, "MAX_PROBE_SECONDS", 0):
                with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                    with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                            self.observe_probe("/tmp/unused", "unused", "unused", 502, "unused")
        self.assertEqual(raised.exception.check, "probe_process_observation")
        self.assertFalse(raised.exception.cleanup_complete)

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
                        with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                            with self.assertRaisesRegex(
                                macos_capability.ProbeFailure,
                                "descriptor_readback_unavailable",
                            ):
                                self.observe_probe(
                                    "/tmp/unused",
                                    "/tmp/unused",
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
                        with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                            with self.assertRaisesRegex(
                                macos_capability.ProbeFailure,
                                "descriptor_readback_unavailable",
                            ):
                                self.observe_probe(
                                    "/tmp/unused",
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
                with patch.object(macos_capability, "_terminate_probe_tree", return_value=True):
                        with patch.object(macos_capability._Capture, "start"):
                            with patch.object(macos_capability._Capture, "join", return_value=False):
                                with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                                    with self.assertRaisesRegex(
                                        macos_capability.ProbeFailure,
                                        "native_preflight_unavailable",
                                    ) as raised:
                                        self.observe_probe(
                                            "/tmp/unused",
                                            "/tmp/unused",
                                            "unused",
                                            501,
                                            "unused",
                                        )
        self.assertFalse(raised.exception.cleanup_complete)
        self.assertEqual(raised.exception.check, "probe_process_capture_cleanup")
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

    def test_probe_process_cleanup_ambiguity_refuses_before_probe_build(self):
        with tempfile.TemporaryDirectory(prefix="macos-probe-command-cleanup-") as directory:
            root = Path(directory) / "workspace"
            marker = root / "kit" / "confinement" / "macos_capability.swift"
            marker.parent.mkdir(parents=True)
            marker.write_text("// public synthetic probe\n", encoding="utf-8")
            home_parent = Path(directory) / "home-parent"
            home = home_parent / "home"
            home_parent.mkdir()
            home.mkdir()
            scratch_paths = []

            def make_scratch(prefix, dir):
                path = Path(directory) / (prefix + str(len(scratch_paths)))
                path.mkdir()
                scratch_paths.append(path)
                return str(path)

            failure = macos_capability.ProbeFailure(
                "native_preflight_unavailable", cleanup_complete=False, check="probe_process_cleanup"
            )
            with patch.dict(os.environ, {"CI_WORKSPACE": str(root)}):
                with patch.object(macos_capability, "_check_context", return_value=root):
                    with patch.object(macos_capability, "_disable_developer_mode"):
                        with patch.object(macos_capability, "_protect_runner_controls", return_value=(501, (), ())):
                            with patch.object(macos_capability, "_create_probe_identity", return_value=(502, home_parent, home)):
                                with patch.object(macos_capability.tempfile, "mkdtemp", side_effect=make_scratch):
                                    with patch.object(macos_capability, "_verify_runner_controls_are_private"):
                                        with patch.object(macos_capability, "_run_as_probe_user", side_effect=failure):
                                            with patch.object(macos_capability, "_build_signed_probe") as build:
                                                with patch.object(macos_capability, "_observe_probe") as observe:
                                                    with patch.object(macos_capability, "_run") as command:
                                                        with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                                            macos_capability.run_native_probe("a" * 40)
            self.assertEqual(raised.exception.check, "probe_process_cleanup")
            self.assertFalse(raised.exception.cleanup_complete)
            build.assert_not_called()
            observe.assert_not_called()
            command.assert_not_called()
            self.assertTrue(home_parent.is_dir())
            self.assertTrue(all(path.is_dir() for path in scratch_paths))
            shutil.rmtree(home_parent, ignore_errors=True)
            for path in scratch_paths:
                shutil.rmtree(path, ignore_errors=True)

    def test_account_deletion_is_refused_when_uid_census_finds_escaped_child(self):
        with tempfile.TemporaryDirectory(prefix="macos-account-census-") as directory:
            root = Path(directory) / "workspace"
            marker = root / "kit" / "confinement" / "macos_capability.swift"
            marker.parent.mkdir(parents=True)
            marker.write_text("// public synthetic probe\n", encoding="utf-8")
            home_parent = Path(directory) / "home-parent"
            home = home_parent / "home"
            home_parent.mkdir()
            home.mkdir()
            scratch_paths = []

            def make_scratch(prefix, dir):
                path = Path(directory) / (prefix + str(len(scratch_paths)))
                path.mkdir()
                scratch_paths.append(path)
                return str(path)

            with patch.dict(os.environ, {"CI_WORKSPACE": str(root)}):
                with patch.object(macos_capability, "_check_context", return_value=root):
                    with patch.object(macos_capability, "_disable_developer_mode"):
                        with patch.object(macos_capability, "_protect_runner_controls", return_value=(501, (), ())):
                            with patch.object(macos_capability, "_create_probe_identity", return_value=(502, home_parent, home)):
                                with patch.object(macos_capability.tempfile, "mkdtemp", side_effect=make_scratch):
                                    with patch.object(macos_capability, "_verify_runner_controls_are_private"):
                                        with patch.object(macos_capability, "_run_as_probe_user", return_value=subprocess.CompletedProcess([], 0, b"", b"")):
                                            with patch.object(macos_capability, "_build_signed_probe", return_value="unused"):
                                                with patch.object(macos_capability, "_observe_probe"):
                                                    with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(True, ())) as census:
                                                        with patch.object(macos_capability, "_run") as command:
                                                            with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                                                macos_capability.run_native_probe("a" * 40)
            self.assertEqual(raised.exception.check, "probe_process_survivor_final_census")
            self.assertFalse(raised.exception.cleanup_complete)
            census.assert_called_once_with(
                502, include_survivor_classes=True, python_executable=TEST_TOOLCHAIN["python"]
            )
            command.assert_not_called()
            self.assertTrue(home_parent.is_dir())
            self.assertTrue(all(path.is_dir() for path in scratch_paths))
            shutil.rmtree(home_parent, ignore_errors=True)
            for path in scratch_paths:
                shutil.rmtree(path, ignore_errors=True)

    def test_final_cleanup_refuses_when_home_removal_errors_and_checks_remaining_paths(self):
        with tempfile.TemporaryDirectory(prefix="macos-final-home-cleanup-") as directory:
            root = Path(directory) / "workspace"
            marker = root / "kit" / "confinement" / "macos_capability.swift"
            marker.parent.mkdir(parents=True)
            marker.write_text("// public synthetic probe\n", encoding="utf-8")
            marker.chmod(0o644)
            home_parent = Path(directory) / "home-parent"
            home = home_parent / "home"
            home_parent.mkdir()
            home.mkdir()
            scratch_paths = []

            def make_scratch(prefix, dir):
                path = Path(directory) / (prefix + str(len(scratch_paths)))
                path.mkdir()
                scratch_paths.append(path)
                return str(path)

            real_rmtree = shutil.rmtree

            def fail_home_remove(path):
                if Path(path) == home_parent:
                    raise PermissionError("home-delete-error")
                real_rmtree(path)

            with patch.dict(os.environ, {"CI_WORKSPACE": str(root)}):
                with patch.object(macos_capability, "_check_context", return_value=root):
                    with patch.object(macos_capability, "_disable_developer_mode"):
                        with patch.object(macos_capability, "_protect_runner_controls", return_value=(501, (), ())):
                            with patch.object(macos_capability, "_create_probe_identity", return_value=(502, home_parent, home)):
                                with patch.object(macos_capability.tempfile, "mkdtemp", side_effect=make_scratch):
                                    with patch.object(macos_capability, "_verify_runner_controls_are_private"):
                                        with patch.object(
                                            macos_capability,
                                            "_run_as_probe_user",
                                            return_value=subprocess.CompletedProcess([], 0, b"", b""),
                                        ):
                                            with patch.object(macos_capability, "_build_signed_probe", return_value="unused"):
                                                with patch.object(macos_capability, "_observe_probe"):
                                                    with patch.object(macos_capability, "_probe_uid_processes_present", return_value=(False, ())):
                                                        with patch.object(
                                                            macos_capability,
                                                            "_run",
                                                            return_value=subprocess.CompletedProcess([], 0, b"", b""),
                                                        ) as command:
                                                            with patch.object(
                                                                macos_capability.shutil,
                                                                "rmtree",
                                                                side_effect=fail_home_remove,
                                                            ):
                                                                with self.assertRaises(macos_capability.ProbeFailure) as raised:
                                                                    macos_capability.run_native_probe("a" * 40)
            self.assertEqual(raised.exception.reason, "native_preflight_unavailable")
            self.assertEqual(raised.exception.check, "probe_identity_cleanup")
            self.assertFalse(raised.exception.cleanup_complete)
            self.assertTrue(home_parent.is_dir())
            self.assertTrue(home.is_dir())
            self.assertTrue(all(not path.exists() for path in scratch_paths))
            command.assert_not_called()
            real_rmtree(home_parent)

    def test_final_cleanup_removes_every_tree_before_deleting_identity(self):
        with tempfile.TemporaryDirectory(prefix="macos-final-cleanup-order-") as directory:
            root = Path(directory) / "workspace"
            marker = root / "kit" / "confinement" / "macos_capability.swift"
            marker.parent.mkdir(parents=True)
            marker.write_text("// public synthetic probe\n", encoding="utf-8")
            marker.chmod(0o644)
            home_parent = Path(directory) / "home-parent"
            home_parent.mkdir()
            (home_parent / "home").mkdir()
            scratch_paths = []
            events = []

            def make_scratch(prefix, dir):
                path = Path(directory) / prefix
                path.mkdir()
                scratch_paths.append(path)
                return str(path)

            def command(argv, **kwargs):
                events.append(("dscl-delete", all(not path.exists() for path in [home_parent, *scratch_paths])))
                return subprocess.CompletedProcess(argv, 0, b"", b"")

            with patch.dict(os.environ, {"CI_WORKSPACE": str(root)}):
                with patch.object(macos_capability, "_check_context", return_value=root):
                    with patch.object(macos_capability, "_disable_developer_mode"):
                        with patch.object(macos_capability, "_protect_runner_controls", return_value=(501, (), ())):
                            with patch.object(
                                macos_capability,
                                "_create_probe_identity",
                                return_value=(502, home_parent, home_parent / "home"),
                            ):
                                with patch.object(macos_capability.tempfile, "mkdtemp", side_effect=make_scratch):
                                    with patch.object(macos_capability, "_verify_runner_controls_are_private"):
                                        with patch.object(
                                            macos_capability,
                                            "_run_as_probe_user",
                                            return_value=subprocess.CompletedProcess([], 0, b"", b""),
                                        ):
                                            with patch.object(macos_capability, "_build_signed_probe", return_value="unused"):
                                                with patch.object(macos_capability, "_observe_probe"):
                                                    with patch.object(
                                                        macos_capability,
                                                        "_probe_uid_processes_present",
                                                        return_value=(False, ()),
                                                    ) as census:
                                                        with patch.object(macos_capability, "_run", side_effect=command) as run:
                                                            macos_capability.run_native_probe("a" * 40)

            self.assertEqual(events, [("dscl-delete", True)])
            self.assertEqual(run.call_args.args[0], ["/usr/bin/dscl", ".", "-delete", "/Users/" + macos_capability.USERNAME])
            census.assert_called_once_with(
                502, include_survivor_classes=True, python_executable=TEST_TOOLCHAIN["python"]
            )


class SandboxStageDiagnosticTests(unittest.TestCase):
    PREFIX = "macos-capability=refused reason=sandbox_behavior_unavailable"
    SUFFIX = "\nmacos-confinement=refused reason=incomplete_channel_evidence\n"

    def line(self, text):
        return self.PREFIX + text + self.SUFFIX

    def test_sandbox_enums_are_fixed(self):
        self.assertEqual(
            macos_capability.SANDBOX_STAGES,
            (
                "marker_access",
                "positive_read_spawn", "positive_read_overflow", "positive_read_exit",
                "positive_write_spawn", "positive_write_overflow", "positive_write_exit",
                "probe_spawn",
                "probe_stdout_overflow_before_wait", "probe_stderr_overflow_before_wait",
                "probe_stdout_overflow_after_wait", "probe_stderr_overflow_after_wait",
                "probe_stdout_overflow_final", "probe_stderr_overflow_final",
                "probe_exit",
            ),
        )
        self.assertEqual(
            macos_capability.SANDBOX_FAILURES,
            (
                "invalid_input", "identity_invalid", "sandbox_missing", "child_sandbox_missing", "child_failed",
                "storage_unavailable", "outside_write_allowed",
                "python_error", "exec_failed",
                "signal_exit", "other_exit",
            ),
        )
        self.assertEqual(
            macos_capability.SANDBOX_EXIT_STAGES, ("positive_read_exit", "positive_write_exit", "probe_exit")
        )
        self.assertEqual(
            macos_capability.PROBE_EXIT_FAILURES,
            {
                20: "invalid_input", 21: "identity_invalid", 22: "sandbox_missing",
                23: "child_failed", 24: "storage_unavailable", 25: "outside_write_allowed",
                26: "child_sandbox_missing", 125: "exec_failed",
            },
        )
        self.assertEqual(
            macos_capability.CONTROL_EXIT_FAILURES, {1: "python_error", 125: "exec_failed"}
        )
        for ordered, derived in (
            (macos_capability.SANDBOX_STAGES, macos_capability.SANDBOX_STAGE_SET),
            (macos_capability.SANDBOX_FAILURES, macos_capability.SANDBOX_FAILURE_SET),
            (macos_capability.SANDBOX_EXIT_STAGES, macos_capability.SANDBOX_EXIT_STAGE_SET),
        ):
            self.assertIs(type(ordered), tuple)
            self.assertIs(type(derived), frozenset)
            self.assertEqual(len(ordered), len(derived))
            self.assertEqual(derived, frozenset(ordered))
        self.assertEqual(
            macos_capability.SANDBOX_EXIT_STAGE_SET | frozenset(), frozenset(macos_capability.SANDBOX_EXIT_STAGES)
        )
        for value in (*macos_capability.SANDBOX_STAGES, *macos_capability.SANDBOX_FAILURES):
            self.assertRegex(value, r"^[a-z_]+$")

    def test_every_declared_value_is_emitted_and_no_undeclared_value_is(self):
        import ast

        tree = ast.parse(Path(macos_capability.__file__).read_text(encoding="utf-8"))
        stage_keywords = {
            "sandbox_stage", "failure_stage", "failure_stage_spawn",
            "failure_stage_overflow", "failure_stage_exit",
        }

        def literals(node):
            if isinstance(node, ast.Constant):
                return {node.value}
            if isinstance(node, ast.IfExp):
                return literals(node.body) | literals(node.orelse)
            if isinstance(node, ast.Name) and node.id in stage_keywords:
                return set()
            if isinstance(node, ast.Attribute) and node.attr == "sandbox_stage":
                return set()
            self.fail("unresolvable stage argument at line " + str(node.lineno))

        emitted_stages = set()
        sandbox_raises = 0
        sandbox_reason_calls = 0
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            keywords = {k.arg: k.value for k in node.keywords}
            is_probe_failure = isinstance(node.func, ast.Name) and node.func.id == "ProbeFailure"
            if is_probe_failure and node.args and isinstance(node.args[0], ast.Constant) and (
                node.args[0].value == "sandbox_behavior_unavailable"
            ):
                sandbox_raises += 1
                self.assertIn("sandbox_stage", keywords)
            if isinstance(keywords.get("failure_reason"), ast.Constant) and (
                keywords["failure_reason"].value == "sandbox_behavior_unavailable"
            ):
                sandbox_reason_calls += 1
                self.assertTrue(stage_keywords & set(keywords))
            for name, value in keywords.items():
                if name in stage_keywords:
                    emitted_stages |= literals(value)
        self.assertEqual(sandbox_raises, 5)
        self.assertEqual(sandbox_reason_calls, 3)
        emitted_stages.discard(None)
        self.assertEqual(emitted_stages, macos_capability.SANDBOX_STAGE_SET)

        emitted_failures = set()
        for node in tree.body:
            if (
                isinstance(node, ast.Assign)
                and len(node.targets) == 1
                and getattr(node.targets[0], "id", None) in ("PROBE_EXIT_FAILURES", "CONTROL_EXIT_FAILURES")
            ):
                emitted_failures |= {value.value for value in node.value.values}
        classify = next(
            f for f in ast.walk(tree) if isinstance(f, ast.FunctionDef) and f.name == "_classify_exit"
        )
        for node in ast.walk(classify):
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Constant):
                emitted_failures.add(node.value.value)
        self.assertEqual(emitted_failures, macos_capability.SANDBOX_FAILURE_SET)

    def test_classify_exit_maps_known_codes_signals_and_everything_else(self):
        classify = macos_capability._classify_exit
        for code, expected in macos_capability.PROBE_EXIT_FAILURES.items():
            self.assertEqual(classify(code, macos_capability.PROBE_EXIT_FAILURES), expected)
        for code, expected in macos_capability.CONTROL_EXIT_FAILURES.items():
            self.assertEqual(classify(code, macos_capability.CONTROL_EXIT_FAILURES), expected)
        for code in (1, 2, 19, 27, 31, 126, 255):
            self.assertEqual(classify(code, macos_capability.PROBE_EXIT_FAILURES), "other_exit")
        for code in (2, 20, 126):
            self.assertEqual(classify(code, macos_capability.CONTROL_EXIT_FAILURES), "other_exit")
        for code in (-1, -9, -15):
            self.assertEqual(classify(code, macos_capability.PROBE_EXIT_FAILURES), "signal_exit")
        for code in (None, "23", 23.0, True):
            self.assertEqual(classify(code, macos_capability.PROBE_EXIT_FAILURES), "other_exit")

    def test_safe_output_emits_only_declared_sandbox_values_for_the_sandbox_reason(self):
        reason = "sandbox_behavior_unavailable"
        for stage in macos_capability.SANDBOX_STAGES:
            self.assertEqual(
                macos_capability.safe_output(False, reason, sandbox_stage=stage),
                self.line(" sandbox_stage=" + stage),
            )
            self.assertEqual(
                macos_capability.safe_output(False, reason, sandbox_failure="other_exit"),
                self.line(""),
            )
            for failure in macos_capability.SANDBOX_FAILURES:
                expected = " sandbox_stage=" + stage
                if stage in macos_capability.SANDBOX_EXIT_STAGES:
                    expected += " sandbox_failure=" + failure
                self.assertEqual(
                    macos_capability.safe_output(False, reason, sandbox_stage=stage, sandbox_failure=failure),
                    self.line(expected),
                )
                refusal = macos_capability.ProbeFailure(
                    reason, sandbox_stage=stage, sandbox_failure=failure
                )
                self.assertEqual(refusal.sandbox_stage, stage)
                self.assertEqual(
                    refusal.sandbox_failure,
                    failure if stage in macos_capability.SANDBOX_EXIT_STAGES else None,
                )

    def test_hostile_sandbox_values_are_dropped_everywhere(self):
        class StrSubclass(str):
            pass

        reason = "sandbox_behavior_unavailable"
        hostile = (
            "other", "", "probe_exit\nmacos-confinement=observed", "probe_exit::x", "probe_exit extra=1",
            "probe_exit ", "PROBE_EXIT", "/tmp/secret", 23, None, b"probe_exit", ["probe_exit"],
            ("probe_exit",), StrSubclass("probe_exit"), True,
        )
        for value in hostile:
            with self.subTest(stage=value):
                self.assertEqual(
                    macos_capability.safe_output(False, reason, sandbox_stage=value), self.line("")
                )
                refusal = macos_capability.ProbeFailure(reason, sandbox_stage=value, sandbox_failure="other_exit")
                self.assertIsNone(refusal.sandbox_stage)
                self.assertIsNone(refusal.sandbox_failure)
            with self.subTest(failure=value):
                self.assertEqual(
                    macos_capability.safe_output(
                        False, reason, sandbox_stage="probe_exit", sandbox_failure=value
                    ),
                    self.line(" sandbox_stage=probe_exit"),
                )
                refusal = macos_capability.ProbeFailure(
                    reason, sandbox_stage="probe_exit", sandbox_failure=value
                )
                self.assertEqual(refusal.sandbox_stage, "probe_exit")
                self.assertIsNone(refusal.sandbox_failure)

    def test_sandbox_values_on_other_reasons_are_dropped_and_other_output_is_unchanged(self):
        for reason in sorted(macos_capability.REASONS - {"sandbox_behavior_unavailable"}) + ["unknown_reason"]:
            plain = macos_capability.safe_output(False, reason)
            self.assertEqual(
                macos_capability.safe_output(
                    False, reason, sandbox_stage="probe_exit", sandbox_failure="child_failed"
                ),
                plain,
            )
            refusal = macos_capability.ProbeFailure(
                reason, sandbox_stage="probe_exit", sandbox_failure="child_failed"
            )
            self.assertIsNone(refusal.sandbox_stage)
            self.assertIsNone(refusal.sandbox_failure)
            self.assertNotIn("sandbox_stage", plain)
        self.assertEqual(
            macos_capability.safe_output(False, "probe_timeout"),
            "macos-capability=refused reason=probe_timeout\n" + self.SUFFIX[1:],
        )
        self.assertEqual(
            macos_capability.safe_output(
                False, "native_preflight_unavailable", "probe_process_launch"
            ),
            "macos-capability=refused reason=native_preflight_unavailable check=probe_process_launch"
            + self.SUFFIX,
        )
        self.assertEqual(
            macos_capability.safe_output(False, "sandbox_behavior_unavailable"), self.line("")
        )
        self.assertEqual(
            macos_capability.safe_output(True, "sandbox_behavior_unavailable", sandbox_stage="probe_exit"),
            "macos-capability=observed" + self.SUFFIX,
        )

    def drive(self, *, marker="readable", popen_script=(), captures=None, terminate=None):
        stub_toolchain = TEST_TOOLCHAIN
        state = {"popen": 0, "captures": 0, "phase": "before"}

        class Process:
            pid = 12400
            returncode = None

            def __init__(self, returncode, stdout, stderr):
                self.stdout = io.BytesIO(stdout)
                self.stderr = io.BytesIO(stderr)
                self.final = returncode

            def poll(self):
                return self.final

            def wait(self, timeout=None):
                state["phase"] = "after"
                self.returncode = self.final
                return self.final

        def popen(*args, **kwargs):
            step = popen_script[state["popen"]] if state["popen"] < len(popen_script) else ("ok",)
            state["popen"] += 1
            state["phase"] = "before"
            if step[0] == "oserror":
                raise OSError("private detail /tmp/secret")
            if step[0] == "exit":
                return Process(step[1], b"", macos_capability.PROBE_IDENTITY_VERIFIED)
            if step[0] == "refused":
                return Process(step[1], b"", macos_capability.PROBE_IDENTITY_REFUSED)
            if step[0] == "overflow":
                return Process(0, b"x" * (macos_capability.MAX_CAPTURE_BYTES + 1), macos_capability.PROBE_IDENTITY_VERIFIED)
            return Process(0, b"", macos_capability.PROBE_IDENTITY_VERIFIED)

        real_capture = macos_capability._Capture

        class FakeCapture:
            def __init__(self, stream):
                self.index = state["captures"]
                state["captures"] += 1
                self.real = real_capture(stream) if self.index < 4 or captures is None else None
                if self.real is None:
                    self.data = bytearray(macos_capability.PROBE_IDENTITY_VERIFIED)

            def __getattr__(self, name):
                if self.real is not None:
                    return getattr(self.real, name)
                raise AttributeError(name)

            @property
            def overflow(self):
                if self.real is not None:
                    return self.real.overflow
                stream = "stdout" if self.index % 2 == 0 else "stderr"
                return state["phase"] in captures.get(stream, ())

            def start(self):
                if self.real is not None:
                    self.real.start()

            def join(self):
                return True if self.real is None else self.real.join()

        def fake_terminate(process):
            if state["phase"] == "after":
                state["phase"] = "final"
            return True

        with tempfile.TemporaryDirectory(prefix="macos-sandbox-stage-") as directory:
            root = Path(directory) / "workspace"
            marker_path = root / "kit" / "confinement" / "macos_capability.swift"
            marker_path.parent.mkdir(parents=True)
            if marker != "missing":
                marker_path.write_text("synthetic\n", encoding="utf-8")
            marker_mode = stat.S_IFREG | (0o600 if marker == "private" else 0o644)
            host_path_type = type(root)
            real_stat = host_path_type.stat

            def injected_stat(path, *args, **kwargs):
                if path == marker_path:
                    return types.SimpleNamespace(st_mode=marker_mode)
                return real_stat(path, *args, **kwargs)

            home_parent = Path(directory) / "home-parent"
            home = home_parent / "home"
            home.mkdir(parents=True)
            counter = []

            def make_scratch(prefix, dir):
                path = Path(directory) / (prefix + str(len(counter)))
                path.mkdir()
                counter.append(path)
                return str(path)

            dscl = subprocess.CompletedProcess([], 0, b"", b"")
            output = io.StringIO()
            with ExitStack() as stack:
                stack.enter_context(patch.dict(os.environ, {"CI_WORKSPACE": str(root)}))
                for name, value in (
                    ("_check_context", root),
                    ("_resolve_trusted_toolchain", stub_toolchain),
                    ("_disable_developer_mode", None),
                    ("_protect_runner_controls", (501, (), ())),
                    ("_create_probe_identity", (502, home_parent, home)),
                    ("_verify_runner_controls_are_private", None),
                    ("_build_signed_probe", "/tmp/CapabilityProbe"),
                    ("_process_table", {}),
                    ("_probe_uid_processes_present", (False, ())),
                    ("_remove_probe_tree", None),
                    ("_run", dscl),
                ):
                    stack.enter_context(patch.object(macos_capability, name, return_value=value))
                if marker != "missing":
                    stack.enter_context(patch.object(host_path_type, "stat", injected_stat))
                stack.enter_context(patch.object(macos_capability.tempfile, "mkdtemp", side_effect=make_scratch))
                stack.enter_context(patch.object(macos_capability.subprocess, "Popen", side_effect=popen))
                stack.enter_context(patch.object(macos_capability, "_Capture", FakeCapture))
                stack.enter_context(
                    patch.object(macos_capability, "_terminate_probe_tree", side_effect=terminate or fake_terminate)
                )
                stack.enter_context(patch.object(macos_capability.time, "sleep"))
                stack.enter_context(redirect_stdout(output))
                status = macos_capability.main(["--control-sha", CONTROL_SHA])
        return status, output.getvalue()

    def assert_refusal(self, result, suffix):
        status, text = result
        self.assertEqual(status, 1)
        self.assertEqual(text, self.line(suffix))

    def test_marker_site(self):
        self.assert_refusal(self.drive(marker="missing"), " sandbox_stage=marker_access")
        self.assert_refusal(self.drive(marker="private"), " sandbox_stage=marker_access")

    def test_positive_control_sites(self):
        self.assert_refusal(self.drive(popen_script=(("oserror",),)), " sandbox_stage=positive_read_spawn")
        self.assert_refusal(self.drive(popen_script=(("overflow",),)), " sandbox_stage=positive_read_overflow")
        self.assert_refusal(
            self.drive(popen_script=(("exit", 1),)),
            " sandbox_stage=positive_read_exit sandbox_failure=python_error",
        )
        self.assert_refusal(
            self.drive(popen_script=(("exit", 125),)),
            " sandbox_stage=positive_read_exit sandbox_failure=exec_failed",
        )
        self.assert_refusal(
            self.drive(popen_script=(("exit", -9),)),
            " sandbox_stage=positive_read_exit sandbox_failure=signal_exit",
        )
        self.assert_refusal(
            self.drive(popen_script=(("exit", 7),)),
            " sandbox_stage=positive_read_exit sandbox_failure=other_exit",
        )
        self.assert_refusal(
            self.drive(popen_script=(("ok",), ("oserror",))), " sandbox_stage=positive_write_spawn"
        )
        self.assert_refusal(
            self.drive(popen_script=(("ok",), ("overflow",))), " sandbox_stage=positive_write_overflow"
        )
        self.assert_refusal(
            self.drive(popen_script=(("ok",), ("exit", 1))),
            " sandbox_stage=positive_write_exit sandbox_failure=python_error",
        )

    def test_probe_spawn_site(self):
        self.assert_refusal(
            self.drive(popen_script=(("ok",), ("ok",), ("oserror",))), " sandbox_stage=probe_spawn"
        )

    def test_probe_overflow_sites_name_phase_and_stream(self):
        for phase, label in (("before", "before_wait"), ("after", "after_wait"), ("final", "final")):
            for stream in ("stdout", "stderr"):
                with self.subTest(phase=phase, stream=stream):
                    self.assert_refusal(
                        self.drive(captures={stream: (phase,)}),
                        " sandbox_stage=probe_" + stream + "_overflow_" + label,
                    )
        self.assert_refusal(
            self.drive(captures={"stdout": ("before",), "stderr": ("before",)}),
            " sandbox_stage=probe_stdout_overflow_before_wait",
        )

    def test_probe_identity_refusal_wins_over_exit_status(self):
        status, text = self.drive(popen_script=(("ok",), ("ok",), ("refused", 125)))
        self.assertEqual(status, 1)
        self.assertEqual(
            text,
            "macos-capability=refused reason=probe_identity_unavailable check=probe_process_identity"
            + self.SUFFIX,
        )
        self.assertNotIn("sandbox_stage", text)

    def test_probe_exit_site_maps_each_known_code_signal_and_other(self):
        expected = dict(macos_capability.PROBE_EXIT_FAILURES)
        expected.update({26: "child_sandbox_missing", 27: "other_exit", 1: "other_exit", 125: "exec_failed", -9: "signal_exit", -6: "signal_exit"})
        for code, failure in expected.items():
            with self.subTest(code=code):
                self.assert_refusal(
                    self.drive(popen_script=(("ok",), ("ok",), ("exit", code)), captures={}),
                    " sandbox_stage=probe_exit sandbox_failure=" + failure,
                )


if __name__ == "__main__":
    unittest.main(verbosity=2)
