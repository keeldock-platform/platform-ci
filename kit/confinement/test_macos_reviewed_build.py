import contextlib
import io
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import macos_reviewed_build as reviewed_build


CONTROL_SHA = "a" * 40


def binding_environment(**changes):
    environment = {
        "CI_SHA": CONTROL_SHA,
        "GITHUB_RUN_ID": "123456789",
        "GITHUB_RUN_ATTEMPT": "1",
        "ImageOS": "macos15",
        "ImageVersion": "20260907.0337.1",
    }
    environment.update(changes)
    return environment


def success_record(**changes):
    record = {
        "schema_version": 1,
        "control_sha": CONTROL_SHA,
        "run_id": "123456789",
        "run_attempt": "1",
        "image_os": "macos15",
        "image_version": "20260907.0337.1",
        "macos_version": "15.7.9",
        "architecture": "arm64",
        "xcode_version": "26.1",
        "xcode_build": "17B55",
        "compiler_origin": "command-line-tools",
        "clang_version": "17.0.0",
        "sdk_version": "15.5",
        "developer_mode": "disabled",
        "privilege": "separate_nonadmin",
        "sudo": "denied",
        "compile": "passed",
        "link": "passed",
        "load_test": "passed",
        "capture": "passed",
        "summary_standin": "write_denied",
        "cleanup": "complete",
        "seatbelt": "not_run",
        "pf": "not_run",
        "source": "none",
    }
    record.update(changes)
    return record


class RunBindingTests(unittest.TestCase):
    def test_binding_accepts_full_control_and_runner_identity(self):
        value = reviewed_build._binding(CONTROL_SHA, binding_environment())
        self.assertEqual(value["control_sha"], CONTROL_SHA)
        self.assertEqual(value["run_id"], "123456789")
        self.assertEqual(value["run_attempt"], "1")
        self.assertEqual(value["image_os"], "macos15")

    def test_binding_rejects_wrong_sha_and_malformed_runner_identity(self):
        cases = (
            ("b" * 40, binding_environment(), "invalid_control_identity"),
            (CONTROL_SHA, binding_environment(CI_SHA="short"), "invalid_control_identity"),
            (CONTROL_SHA, binding_environment(GITHUB_RUN_ID="0"), "invalid_control_identity"),
            (CONTROL_SHA, binding_environment(GITHUB_RUN_ATTEMPT="1\nother"), "invalid_control_identity"),
            (CONTROL_SHA, binding_environment(ImageOS="macos15::error"), "runner_identity_unavailable"),
            (CONTROL_SHA, binding_environment(ImageVersion="20260907.0337.1\nmarker"), "runner_identity_unavailable"),
        )
        for control_sha, environment, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(reviewed_build.Refusal, reason):
                    reviewed_build._binding(control_sha, environment)


class ToolchainProvenanceTests(unittest.TestCase):
    def test_selected_xcode_query_does_not_inherit_command_line_tools_override(self):
        selected_path = "/Applications/Xcode_26.1.app/Contents/Developer"
        selected_alias = "/Applications/Xcode.app/Contents/Developer"
        result = subprocess.CompletedProcess(("xcode-select",), 0, (selected_alias + "\n").encode(), b"")
        def resolve_trusted_path(path, directory=False):
            if path == selected_alias:
                return Path(selected_path)
            return Path(path)
        with patch.object(
            reviewed_build.capability,
            "_resolve_trusted_path",
            side_effect=resolve_trusted_path,
        ):
            with patch.object(reviewed_build, "_run_command", return_value=result) as run:
                resolved = reviewed_build._selected_xcode_directory()
        self.assertEqual(resolved, Path(selected_path))
        environment = run.call_args.kwargs["env"]
        self.assertNotIn("DEVELOPER_DIR", environment)
        self.assertEqual(run.call_args.args[0][-1], "--print-path")

    def test_selected_xcode_query_refuses_the_command_line_tools_directory(self):
        result = subprocess.CompletedProcess(
            ("xcode-select",), 0, b"/Library/Developer/CommandLineTools\n", b"",
        )
        with patch.object(
            reviewed_build.capability,
            "_resolve_trusted_path",
            side_effect=lambda path, directory=False: Path(path),
        ):
            with patch.object(reviewed_build, "_run_command", return_value=result):
                with self.assertRaises(reviewed_build.Refusal) as raised:
                    reviewed_build._selected_xcode_directory()
        self.assertEqual(raised.exception.reason, "toolchain_unavailable")
        self.assertEqual(raised.exception.stage, "xcode_select_path")

    def test_host_versions_bind_xcodebuild_to_selected_xcode_and_keep_compiler_origin(self):
        selected_xcode = Path("/Applications/Xcode_26.1.app/Contents/Developer")
        toolchain = {
            "developer_directory": "/Library/Developer/CommandLineTools",
            "clang": "/Library/Developer/CommandLineTools/usr/bin/clang",
        }
        results = (
            subprocess.CompletedProcess(("sw_vers",), 0, b"15.7.9\n", b""),
            subprocess.CompletedProcess(("xcodebuild",), 0, b"Xcode 26.1\nBuild version 17B55\n", b""),
            subprocess.CompletedProcess(("clang",), 0, b"Apple clang version 17.0.0 (clang-1700.0.13.3)\n", b""),
            subprocess.CompletedProcess(("xcrun",), 0, b"15.5\n", b""),
        )
        with patch.object(reviewed_build.platform, "system", return_value="Darwin"):
            with patch.object(reviewed_build.platform, "machine", return_value="arm64"):
                with patch.object(reviewed_build, "_selected_xcode_directory", return_value=selected_xcode):
                    with patch.object(reviewed_build, "_run_command", side_effect=results) as run:
                        identity = reviewed_build._host_identity(binding_environment(), toolchain)
        calls = run.call_args_list
        self.assertEqual(calls[1].kwargs["env"]["DEVELOPER_DIR"], selected_xcode.as_posix())
        self.assertEqual(calls[2].kwargs["env"]["DEVELOPER_DIR"], toolchain["developer_directory"])
        self.assertEqual(calls[3].kwargs["env"]["DEVELOPER_DIR"], toolchain["developer_directory"])
        self.assertEqual(identity["compiler_origin"], "command-line-tools")
        self.assertEqual(reviewed_build._compiler_origin({
            "developer_directory": selected_xcode.as_posix(),
        }), "xcode")
        with self.assertRaisesRegex(reviewed_build.Refusal, "toolchain_unavailable"):
            reviewed_build._compiler_origin({"developer_directory": "/tmp/other"})
        different_xcode = {
            "developer_directory": "/Applications/Xcode_26.0.app/Contents/Developer",
            "clang": "/Applications/Xcode_26.0.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        }
        with patch.object(reviewed_build.platform, "system", return_value="Darwin"):
            with patch.object(reviewed_build.platform, "machine", return_value="arm64"):
                with patch.object(reviewed_build, "_selected_xcode_directory", return_value=selected_xcode):
                    with self.assertRaisesRegex(reviewed_build.Refusal, "toolchain_unavailable"):
                        reviewed_build._host_identity(binding_environment(), different_xcode)

    def test_selector_resolution_and_query_failures_have_distinct_fixed_stages(self):
        with patch.object(
            reviewed_build.capability,
            "_resolve_trusted_path",
            side_effect=reviewed_build.capability.ProbeFailure("native_preflight_unavailable"),
        ):
            with self.assertRaises(reviewed_build.Refusal) as raised:
                reviewed_build._selected_xcode_directory()
        self.assertEqual(raised.exception.reason, "toolchain_unavailable")
        self.assertEqual(raised.exception.stage, "xcode_select_path")

        selector = Path("/usr/bin/xcode-select")
        malformed_query = subprocess.CompletedProcess(("xcode-select",), 0, b"bad\npath\n", b"")
        with patch.object(
            reviewed_build.capability,
            "_resolve_trusted_path",
            return_value=selector,
        ):
            with patch.object(reviewed_build, "_run_command", return_value=malformed_query):
                with self.assertRaises(reviewed_build.Refusal) as raised:
                    reviewed_build._selected_xcode_directory()
        self.assertEqual(raised.exception.reason, "toolchain_unavailable")
        self.assertEqual(raised.exception.stage, "xcode_select_query")

        failed_query = subprocess.CompletedProcess(("xcode-select",), 1, b"", b"private diagnostic")
        with patch.object(
            reviewed_build.capability,
            "_resolve_trusted_path",
            return_value=selector,
        ):
            with patch.object(reviewed_build, "_run_command", return_value=failed_query):
                with self.assertRaises(reviewed_build.Refusal) as raised:
                    reviewed_build._selected_xcode_directory()
        self.assertEqual(raised.exception.stage, "xcode_select_query")
        self.assertNotIn("private diagnostic", str(raised.exception))


class ToolchainStageTests(unittest.TestCase):
    def test_missing_capability_module_has_a_fixed_stage(self):
        with patch.object(reviewed_build, "capability", None):
            with self.assertRaises(reviewed_build.Refusal) as raised:
                reviewed_build._run_synthetic_smoke(CONTROL_SHA)
        self.assertEqual(raised.exception.reason, "toolchain_unavailable")
        self.assertEqual(raised.exception.stage, "toolchain_module")

    def test_trusted_toolchain_failure_has_a_fixed_stage(self):
        failure = reviewed_build.capability.ProbeFailure("native_preflight_unavailable")
        with patch.object(reviewed_build, "_safe_context", return_value=({}, Path("/tmp/root"))):
            with patch.object(
                reviewed_build.capability,
                "_resolve_trusted_toolchain",
                side_effect=failure,
            ):
                with self.assertRaises(reviewed_build.Refusal) as raised:
                    reviewed_build._run_synthetic_smoke(CONTROL_SHA)
        self.assertEqual(raised.exception.reason, "toolchain_unavailable")
        self.assertEqual(raised.exception.stage, "toolchain_resolve")

    def test_host_version_queries_report_only_their_fixed_stage(self):
        selected_xcode = Path("/Applications/Xcode_26.1.app/Contents/Developer")
        toolchain = {
            "developer_directory": "/Library/Developer/CommandLineTools",
            "clang": "/Library/Developer/CommandLineTools/usr/bin/clang",
        }
        valid_sw_vers = subprocess.CompletedProcess(("sw_vers",), 0, b"15.7.9\n", b"")
        valid_xcode = subprocess.CompletedProcess(
            ("xcodebuild",), 0, b"Xcode 26.1\nBuild version 17B55\n", b"",
        )
        valid_clang = subprocess.CompletedProcess(
            ("clang",), 0, b"Apple clang version 17.0.0 (clang-1700.0.13.3)\n", b"",
        )
        cases = (
            (
                (valid_sw_vers, subprocess.CompletedProcess(("xcodebuild",), 1, b"", b"private diagnostic")),
                "xcode_version",
            ),
            (
                (valid_sw_vers, valid_xcode,
                 subprocess.CompletedProcess(("clang",), 1, b"", b"private diagnostic")),
                "clang_version",
            ),
            (
                (valid_sw_vers, valid_xcode, valid_clang,
                 subprocess.CompletedProcess(("xcrun",), 1, b"", b"private diagnostic")),
                "sdk_version",
            ),
        )
        for results, expected_stage in cases:
            with self.subTest(stage=expected_stage):
                with patch.object(reviewed_build.platform, "system", return_value="Darwin"):
                    with patch.object(reviewed_build.platform, "machine", return_value="arm64"):
                        with patch.object(reviewed_build, "_selected_xcode_directory", return_value=selected_xcode):
                            with patch.object(reviewed_build, "_run_command", side_effect=results):
                                with self.assertRaises(reviewed_build.Refusal) as raised:
                                    reviewed_build._host_identity(binding_environment(), toolchain)
                self.assertEqual(raised.exception.reason, "toolchain_unavailable")
                self.assertEqual(raised.exception.stage, expected_stage)

    def test_command_failure_does_not_expose_process_diagnostics(self):
        with patch.object(subprocess, "run", side_effect=OSError("private diagnostic")):
            with self.assertRaises(reviewed_build.Refusal) as raised:
                reviewed_build._run_command(
                    ("/usr/bin/xcodebuild", "-version"),
                    env={},
                    timeout=1,
                    failure_stage="xcode_version",
                )
        self.assertEqual(raised.exception.reason, "toolchain_unavailable")
        self.assertEqual(raised.exception.stage, "xcode_version")
        self.assertNotIn("private diagnostic", str(raised.exception))


class ChildEnvironmentTests(unittest.TestCase):
    def test_native_child_receives_only_fixed_build_environment(self):
        environment = reviewed_build._child_environment(
            "/tmp/probe-home",
            "/tmp/probe-storage",
            {"developer_directory": "/Applications/Xcode.app/Contents/Developer"},
        )
        self.assertEqual(
            set(environment),
            {"PATH", "HOME", "TMPDIR", "DEVELOPER_DIR", "LANG", "LC_ALL"},
        )
        self.assertFalse(any(key.startswith(("GITHUB_", "ACTIONS_", "CI_")) for key in environment))
        self.assertNotIn("GITHUB_STEP_SUMMARY", environment)
        self.assertNotIn("GITHUB_OUTPUT", environment)

    def test_capture_probe_contains_a_synthetic_standin_not_a_runner_summary_path(self):
        self.assertIn("os.open(summary_standin", reviewed_build.LOAD_TEST_SCRIPT)
        self.assertIn("KD-RB:summary-standin=write-denied", reviewed_build.LOAD_TEST_SCRIPT)
        self.assertNotIn("GITHUB_STEP_SUMMARY", reviewed_build.LOAD_TEST_SCRIPT)
        self.assertNotIn("GITHUB_OUTPUT", reviewed_build.LOAD_TEST_SCRIPT)
        self.assertNotIn("ACTIONS_RUNTIME_TOKEN", reviewed_build.LOAD_TEST_SCRIPT)

    def test_canary_argument_is_ascii_text_and_child_encodes_before_output(self):
        expected = reviewed_build._canary(CONTROL_SHA).decode("ascii")
        argv = reviewed_build._probe_argv(
            "/usr/bin/python3",
            reviewed_build.LOAD_TEST_SCRIPT,
            "/tmp/synthetic-library",
            "/tmp/synthetic-summary-standin",
            expected,
        )
        self.assertEqual(argv[-1], expected)
        self.assertNotIn("b'", argv[-1])
        self.assertIn('canary_bytes = canary.encode("ascii")', reviewed_build.LOAD_TEST_SCRIPT)
        self.assertIn('b"::error file=synthetic.c,line=1::" + canary_bytes', reviewed_build.LOAD_TEST_SCRIPT)
        self.assertIn('b"KD-RB:stderr-canary=" + canary_bytes', reviewed_build.LOAD_TEST_SCRIPT)


class CapturedOutputTests(unittest.TestCase):
    def test_load_test_capture_accepts_only_the_expected_private_markers(self):
        expected_stdout, expected_stderr = reviewed_build._expected_capture(CONTROL_SHA)
        result = subprocess.CompletedProcess(("synthetic",), 0, expected_stdout, expected_stderr)
        self.assertTrue(reviewed_build._check_capture(result, expected_stdout, expected_stderr))
        self.assertIn(b"::error file=synthetic.c,line=1::", result.stdout)
        self.assertNotIn(reviewed_build._canary(CONTROL_SHA), reviewed_build._format_success(success_record()).encode())

    def test_capture_refuses_extra_output_and_missing_markers(self):
        expected_stdout, expected_stderr = reviewed_build._expected_capture(CONTROL_SHA)
        cases = (
            subprocess.CompletedProcess(("synthetic",), 0, expected_stdout + b"extra", expected_stderr),
            subprocess.CompletedProcess(("synthetic",), 0, expected_stdout, b""),
            subprocess.CompletedProcess(("synthetic",), 0, expected_stdout, expected_stderr + b"extra"),
            subprocess.CompletedProcess(("synthetic",), 1, expected_stdout, expected_stderr),
        )
        for result in cases:
            with self.subTest(returncode=result.returncode, stdout_len=len(result.stdout), stderr_len=len(result.stderr)):
                self.assertFalse(reviewed_build._check_capture(result, expected_stdout, expected_stderr))

    def test_capture_refuses_unbounded_output(self):
        expected_stdout, expected_stderr = reviewed_build._expected_capture(CONTROL_SHA)
        result = subprocess.CompletedProcess(
            ("synthetic",), 0, b"x" * (reviewed_build.capability.MAX_CAPTURE_BYTES + 1), expected_stderr,
        )
        self.assertFalse(reviewed_build._check_capture(result, expected_stdout, expected_stderr))


class PrivilegeProbeTests(unittest.TestCase):
    def test_sudo_check_is_noninteractive_and_bounded(self):
        self.assertIn('("/usr/bin/sudo", "-n", "/usr/bin/true")', reviewed_build.PRIVILEGE_SCRIPT)
        self.assertIn("timeout=3", reviewed_build.PRIVILEGE_SCRIPT)
        self.assertIn("password is required", reviewed_build.PRIVILEGE_SCRIPT)

    def test_uncertain_child_cleanup_never_becomes_success(self):
        failure = reviewed_build.capability.ProbeFailure(
            "native_preflight_unavailable", cleanup_complete=False,
        )
        with patch.object(reviewed_build.capability, "_run_as_probe_user", side_effect=failure):
            with self.assertRaisesRegex(reviewed_build.Refusal, "cleanup_incomplete"):
                reviewed_build._run_probe_step(
                    ("synthetic",),
                    501,
                    env={},
                    python_executable="/usr/bin/python3",
                    stage="privilege",
                    expected_stdout=reviewed_build.PRIVILEGE_MARKER,
                )

    def test_privilege_check_failure_has_a_closed_reason(self):
        failure = reviewed_build.capability.ProbeFailure("native_preflight_unavailable")
        with patch.object(reviewed_build.capability, "_run_as_probe_user", side_effect=failure):
            with self.assertRaisesRegex(reviewed_build.Refusal, "privilege_check_failed"):
                reviewed_build._run_probe_step(
                    ("synthetic",),
                    501,
                    env={},
                    python_executable="/usr/bin/python3",
                    stage="privilege",
                    expected_stdout=reviewed_build.PRIVILEGE_MARKER,
                )


class FixedRecordTests(unittest.TestCase):
    def test_success_line_has_fixed_schema_and_no_diagnostic_or_command_text(self):
        line = reviewed_build._format_success(success_record())
        expected = (
            "macos-build=synthetic-smoke-passed schema=1 source=none control-sha=" + CONTROL_SHA
            + " run-id=123456789 run-attempt=1 image-os=macos15 image-version=20260907.0337.1"
            + " macos-version=15.7.9 architecture=arm64 xcode=26.1 xcode-build=17B55"
            + " compiler-origin=command-line-tools clang=17.0.0 sdk=15.5"
            + " developer-mode=disabled privilege=separate-nonadmin"
            + " sudo=denied compile=passed link=passed load-test=passed capture=passed"
            + " summary-standin=write-denied cleanup=complete seatbelt=not-run pf=not-run"
        )
        self.assertEqual(line, expected)
        self.assertNotIn("::error", line)
        self.assertNotIn("summary-standin-v1", line)
        self.assertNotIn("/tmp/", line)

    def test_success_record_rejects_extra_or_inaccurate_claims(self):
        for record in (
            success_record(extra="value"),
            success_record(seatbelt="accepted"),
            success_record(pf="enforced"),
            success_record(source="private"),
            success_record(capture="unknown"),
        ):
            with self.subTest(fields=tuple(record)):
                with self.assertRaisesRegex(reviewed_build.Refusal, "internal_error"):
                    reviewed_build._format_success(record)

    def test_refusal_formatter_collapses_unrecognized_values(self):
        refusal = reviewed_build.Refusal("internal_error", "preflight")
        refusal.reason = "unexpected diagnostic"
        refusal.stage = "private location"
        line = reviewed_build._format_refusal(refusal, CONTROL_SHA, binding_environment())
        self.assertEqual(
            line,
            "macos-build=refused schema=1 reason=internal_error stage=preflight"
            + " control-sha=" + CONTROL_SHA + " run-id=123456789 run-attempt=1",
        )
        self.assertNotIn("unexpected diagnostic", line)
        self.assertNotIn("private location", line)


class CliTests(unittest.TestCase):
    def test_command_surface_rejects_extra_execution_arguments_without_echoing_them(self):
        output = io.StringIO()
        with patch.dict("os.environ", {}, clear=True):
            with contextlib.redirect_stdout(output):
                result = reviewed_build.main(("--control-sha", CONTROL_SHA, "--source-command", "synthetic"))
        self.assertEqual(result, 1)
        self.assertEqual(
            output.getvalue(),
            "macos-build=refused schema=1 reason=invalid_control_identity stage=context"
            + " control-sha=unknown run-id=unknown run-attempt=unknown\n",
        )
        self.assertNotIn("source-command", output.getvalue())

    def test_malformed_sha_is_refused_with_closed_output(self):
        output = io.StringIO()
        with patch.dict("os.environ", {}, clear=True):
            with contextlib.redirect_stdout(output):
                result = reviewed_build.main(("--control-sha", "invalid"))
        self.assertEqual(result, 1)
        self.assertEqual(
            output.getvalue(),
            "macos-build=refused schema=1 reason=invalid_control_identity stage=context"
            + " control-sha=unknown run-id=unknown run-attempt=unknown\n",
        )


if __name__ == "__main__":
    unittest.main()
