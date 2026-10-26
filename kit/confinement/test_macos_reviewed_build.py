import contextlib
import io
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
            + " clang=17.0.0 sdk=15.5 developer-mode=disabled privilege=separate-nonadmin"
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
