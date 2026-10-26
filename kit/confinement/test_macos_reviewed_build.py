import contextlib
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
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
        "xcode_version": "not-used",
        "xcode_build": "not-used",
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
        "real_summary": "write_denied",
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
    def test_command_line_tools_origin_records_versions_without_querying_xcode(self):
        toolchain = {
            "developer_directory": "/Library/Developer/CommandLineTools",
            "clang": "/Library/Developer/CommandLineTools/usr/bin/clang",
        }
        results = (
            subprocess.CompletedProcess(("sw_vers",), 0, b"15.7.9\n", b""),
            subprocess.CompletedProcess(("clang",), 0, b"Apple clang version 17.0.0 (clang-1700.0.13.3)\n", b""),
            subprocess.CompletedProcess(("xcrun",), 0, b"15.5\n", b""),
        )
        with patch.object(reviewed_build.platform, "system", return_value="Darwin"):
            with patch.object(reviewed_build.platform, "machine", return_value="arm64"):
                with patch.object(reviewed_build, "_run_command", side_effect=results) as run:
                    identity = reviewed_build._host_identity(binding_environment(), toolchain)
        calls = run.call_args_list
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[1].args[0][0], toolchain["clang"])
        self.assertEqual(calls[1].kwargs["env"]["DEVELOPER_DIR"], toolchain["developer_directory"])
        self.assertEqual(calls[2].kwargs["env"]["DEVELOPER_DIR"], toolchain["developer_directory"])
        self.assertEqual(identity["compiler_origin"], "command-line-tools")
        self.assertEqual(identity["xcode_version"], "not-used")
        self.assertEqual(identity["xcode_build"], "not-used")
        self.assertEqual(identity["clang_version"], "17.0.0")
        self.assertEqual(identity["sdk_version"], "15.5")

    def test_xcode_origin_queries_metadata_from_verified_toolchain_directory(self):
        developer_directory = "/Applications/Xcode_26.1.app/Contents/Developer"
        toolchain = {
            "developer_directory": developer_directory,
            "clang": developer_directory + "/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        }
        results = (
            subprocess.CompletedProcess(("sw_vers",), 0, b"15.7.9\n", b""),
            subprocess.CompletedProcess(("xcodebuild",), 0, b"Xcode 26.1\nBuild version 17B55\n", b""),
            subprocess.CompletedProcess(("clang",), 0, b"Apple clang version 17.0.0 (clang-1700.0.13.3)\n", b""),
            subprocess.CompletedProcess(("xcrun",), 0, b"15.5\n", b""),
        )
        with patch.object(reviewed_build.platform, "system", return_value="Darwin"):
            with patch.object(reviewed_build.platform, "machine", return_value="arm64"):
                with patch.object(reviewed_build, "_run_command", side_effect=results) as run:
                    identity = reviewed_build._host_identity(binding_environment(), toolchain)
        calls = run.call_args_list
        self.assertEqual(calls[1].args[0][0], "/usr/bin/xcodebuild")
        self.assertEqual(calls[1].kwargs["env"]["DEVELOPER_DIR"], developer_directory)
        self.assertEqual(calls[2].kwargs["env"]["DEVELOPER_DIR"], developer_directory)
        self.assertEqual(identity["compiler_origin"], "xcode")
        self.assertEqual(identity["xcode_version"], "26.1")
        self.assertEqual(identity["xcode_build"], "17B55")

    def test_compiler_origin_rejects_unverified_layout(self):
        self.assertEqual(reviewed_build._compiler_origin({
            "developer_directory": "/Library/Developer/CommandLineTools",
        }), "command-line-tools")
        with self.assertRaisesRegex(reviewed_build.Refusal, "toolchain_unavailable"):
            reviewed_build._compiler_origin({"developer_directory": "/tmp/other"})


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
        clt_toolchain = {
            "developer_directory": "/Library/Developer/CommandLineTools",
            "clang": "/Library/Developer/CommandLineTools/usr/bin/clang",
        }
        xcode_directory = "/Applications/Xcode_26.1.app/Contents/Developer"
        xcode_toolchain = {
            "developer_directory": xcode_directory,
            "clang": xcode_directory + "/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
        }
        valid_sw_vers = subprocess.CompletedProcess(("sw_vers",), 0, b"15.7.9\n", b"")
        valid_clang = subprocess.CompletedProcess(
            ("clang",), 0, b"Apple clang version 17.0.0 (clang-1700.0.13.3)\n", b"",
        )
        cases = (
            (
                xcode_toolchain,
                (valid_sw_vers, subprocess.CompletedProcess(("xcodebuild",), 1, b"", b"private diagnostic")),
                "xcode_version",
            ),
            (
                clt_toolchain,
                (valid_sw_vers, subprocess.CompletedProcess(("clang",), 1, b"", b"private diagnostic")),
                "clang_version",
            ),
            (
                clt_toolchain,
                (valid_sw_vers, valid_clang,
                 subprocess.CompletedProcess(("xcrun",), 1, b"", b"private diagnostic")),
                "sdk_version",
            ),
        )
        for toolchain, results, expected_stage in cases:
            with self.subTest(stage=expected_stage):
                with patch.object(reviewed_build.platform, "system", return_value="Darwin"):
                    with patch.object(reviewed_build.platform, "machine", return_value="arm64"):
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
        self.assertNotIn("CI_STEP_SUMMARY", environment)
        self.assertNotIn("GITHUB_OUTPUT", environment)

    def test_capture_probe_contains_a_synthetic_standin_not_a_runner_summary_path(self):
        self.assertIn("os.open(summary_standin", reviewed_build.LOAD_TEST_SCRIPT)
        self.assertIn("KD-RB:summary-standin=write-denied", reviewed_build.LOAD_TEST_SCRIPT)
        self.assertNotIn("GITHUB_STEP_SUMMARY", reviewed_build.LOAD_TEST_SCRIPT)
        self.assertNotIn("GITHUB_OUTPUT", reviewed_build.LOAD_TEST_SCRIPT)
        self.assertNotIn("ACTIONS_RUNTIME_TOKEN", reviewed_build.LOAD_TEST_SCRIPT)

    def test_real_summary_path_is_an_argument_and_never_a_child_environment_value(self):
        summary_path = "/runner/work/_temp/_runner_file_commands/step_summary_fixture"
        parent_probe = str(Path(summary_path).parent / (Path(summary_path).name + ".kd-rb-123-1"))
        argv = reviewed_build._probe_argv(
            "/usr/bin/python3",
            reviewed_build.SUMMARY_FILE_SCRIPT,
            summary_path,
            parent_probe,
        )
        self.assertEqual(argv[-2:], (summary_path, parent_probe))
        self.assertIn("os.open(summary_path, os.O_WRONLY | os.O_APPEND | nofollow)", reviewed_build.SUMMARY_FILE_SCRIPT)
        self.assertIn("parent_probe, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow", reviewed_build.SUMMARY_FILE_SCRIPT)
        self.assertNotIn("CI_STEP_SUMMARY", reviewed_build.SUMMARY_FILE_SCRIPT)
        self.assertNotIn("GITHUB_STEP_SUMMARY", reviewed_build.SUMMARY_FILE_SCRIPT)


@unittest.skipUnless(
    sys.platform == "darwin"
    and hasattr(os, "O_NOFOLLOW")
    and hasattr(os, "O_DIRECTORY")
    and os.open in getattr(os, "supports_dir_fd", ()),
    "requires macOS no-follow descriptor support",
)
class RealSummaryFileTests(unittest.TestCase):
    def _temporary_summary(self):
        home = Path.home()
        temporary = tempfile.TemporaryDirectory(dir=str(home))
        directory = Path(temporary.name)
        summary = directory / "step_summary_fixture"
        descriptor = os.open(summary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(descriptor)
        return temporary, home, directory, summary

    def test_runner_file_guard_binds_owner_inode_and_empty_contents(self):
        temporary, home, directory, summary = self._temporary_summary()
        guard = None
        try:
            runner_uid = home.stat().st_uid
            with patch.dict(
                "os.environ",
                {"RUNNER_HOME": str(home), "CI_STEP_SUMMARY": str(summary)},
                clear=False,
            ):
                guard = reviewed_build._prepare_runner_summary(runner_uid + 1)
            self.assertEqual(guard["original_contents"], b"")
            self.assertEqual(guard["original_info"].st_uid, runner_uid)
            self.assertEqual(stat.S_IMODE(guard["original_info"].st_mode), 0o600)
            self.assertEqual(guard["original_info"].st_nlink, 1)
        finally:
            if guard is not None:
                reviewed_build._close_runner_summary(guard)
            temporary.cleanup()

    def test_runner_file_guard_refuses_a_writable_parent(self):
        temporary, home, directory, summary = self._temporary_summary()
        try:
            os.chmod(directory, 0o777)
            with patch.dict(
                "os.environ",
                {"RUNNER_HOME": str(home), "CI_STEP_SUMMARY": str(summary)},
                clear=False,
            ):
                with self.assertRaises(reviewed_build.Refusal) as raised:
                    reviewed_build._prepare_runner_summary(home.stat().st_uid + 1)
            self.assertEqual(raised.exception.reason, "summary_file_unavailable")
            self.assertEqual(raised.exception.stage, "summary_file")
        finally:
            os.chmod(directory, 0o700)
            temporary.cleanup()

    def test_runner_file_restoration_clears_a_synthetic_direct_write(self):
        temporary, home, directory, summary = self._temporary_summary()
        guard = None
        try:
            runner_uid = home.stat().st_uid
            with patch.dict(
                "os.environ",
                {"RUNNER_HOME": str(home), "CI_STEP_SUMMARY": str(summary)},
                clear=False,
            ):
                guard = reviewed_build._prepare_runner_summary(runner_uid + 1)
            os.write(guard["descriptor"], reviewed_build.REAL_SUMMARY_CANARY)
            reviewed_build._restore_runner_summary(guard)
            self.assertEqual(reviewed_build._read_summary_descriptor(guard["descriptor"]), b"")
            info = summary.lstat()
            self.assertEqual(info.st_uid, runner_uid)
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
            self.assertEqual(info.st_nlink, 1)
        finally:
            if guard is not None:
                reviewed_build._close_runner_summary(guard)
            temporary.cleanup()

    def test_direct_write_and_parent_create_attempts_refuse_and_restore(self):
        temporary, home, directory, summary = self._temporary_summary()
        guard = None
        try:
            runner_uid = home.stat().st_uid
            with patch.dict(
                "os.environ",
                {"RUNNER_HOME": str(home), "CI_STEP_SUMMARY": str(summary)},
                clear=False,
            ):
                guard = reviewed_build._prepare_runner_summary(runner_uid + 1)

            def simulate_child(argv, uid, *, env, timeout, failure_reason, python_executable):
                Path(argv[-2]).write_bytes(reviewed_build.REAL_SUMMARY_CANARY)
                Path(argv[-1]).write_bytes(b"KD-RB-PARENT-WRITE-CANARY-v1\n")
                return subprocess.CompletedProcess(argv, 0, reviewed_build.REAL_SUMMARY_ALLOWED_MARKER, b"")

            with patch.object(reviewed_build.capability, "_run_as_probe_user", side_effect=simulate_child):
                with self.assertRaises(reviewed_build.Refusal) as raised:
                    reviewed_build._run_real_summary_probe(
                        guard,
                        runner_uid + 1,
                        env={},
                        python_executable="/usr/bin/python3",
                        binding={"run_id": "123", "run_attempt": "1"},
                    )
            self.assertEqual(raised.exception.reason, "summary_file_write_allowed")
            self.assertEqual(raised.exception.stage, "summary_file")
            self.assertEqual(summary.read_bytes(), b"")
            self.assertEqual(tuple(directory.glob("*.kd-rb-*")), ())
            info = summary.lstat()
            self.assertEqual(info.st_uid, runner_uid)
            self.assertEqual(stat.S_IMODE(info.st_mode), 0o600)
        finally:
            if guard is not None:
                reviewed_build._close_runner_summary(guard)
            temporary.cleanup()

    def test_denied_child_write_is_accepted_only_after_runner_file_readback(self):
        temporary, home, directory, summary = self._temporary_summary()
        guard = None
        try:
            runner_uid = home.stat().st_uid
            with patch.dict(
                "os.environ",
                {"RUNNER_HOME": str(home), "CI_STEP_SUMMARY": str(summary)},
                clear=False,
            ):
                guard = reviewed_build._prepare_runner_summary(runner_uid + 1)

            def simulate_child(argv, uid, *, env, timeout, failure_reason, python_executable):
                return subprocess.CompletedProcess(argv, 0, reviewed_build.REAL_SUMMARY_MARKER, b"")

            with patch.object(reviewed_build.capability, "_run_as_probe_user", side_effect=simulate_child):
                reviewed_build._run_real_summary_probe(
                    guard,
                    runner_uid + 1,
                    env={},
                    python_executable="/usr/bin/python3",
                    binding={"run_id": "123", "run_attempt": "1"},
                )
            self.assertEqual(summary.read_bytes(), b"")
            self.assertEqual(tuple(directory.glob("*.kd-rb-*")), ())
            self.assertTrue(guard["child_termination_confirmed"])
        finally:
            if guard is not None:
                reviewed_build._close_runner_summary(guard)
            temporary.cleanup()


class CanaryArgumentTests(unittest.TestCase):
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
            + " macos-version=15.7.9 architecture=arm64 xcode=not-used xcode-build=not-used"
            + " compiler-origin=command-line-tools clang=17.0.0 sdk=15.5"
            + " developer-mode=disabled privilege=separate-nonadmin"
            + " sudo=denied compile=passed link=passed load-test=passed capture=passed"
            + " summary-standin=write-denied real-summary=write-denied"
            + " cleanup=complete seatbelt=not-run pf=not-run"
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
            success_record(real_summary="unknown"),
            success_record(xcode_version="26.1", xcode_build="17B55"),
            success_record(compiler_origin="xcode"),
        ):
            with self.subTest(fields=tuple(record)):
                with self.assertRaisesRegex(reviewed_build.Refusal, "internal_error"):
                    reviewed_build._format_success(record)

    def test_xcode_origin_records_the_numeric_version_pair(self):
        record = success_record(
            compiler_origin="xcode",
            xcode_version="26.1",
            xcode_build="17B55",
        )
        line = reviewed_build._format_success(record)
        self.assertIn(
            "xcode=26.1 xcode-build=17B55 compiler-origin=xcode",
            line,
        )

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
