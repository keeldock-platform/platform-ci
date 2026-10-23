import contextlib
import io
import ast
from pathlib import Path
import unittest

import macos_harness


CONTROL_SHA = "a" * 40


def record(**changes):
    value = {
        "boundary": "unreviewed",
        "channel_results": {channel: "blocked" for channel in macos_harness.CHANNELS},
        "control_sha": CONTROL_SHA,
        "developer_mode": "disabled",
        "runner_isolation": "fresh_job_vm",
        "schema_version": 1,
    }
    value.update(changes)
    return value


class ControlIdentityTests(unittest.TestCase):
    def test_only_full_lowercase_control_shas_are_valid(self):
        self.assertTrue(macos_harness.valid_sha(CONTROL_SHA))
        for value in ("a" * 12, "A" * 40, "g" * 40, "a" * 41, None):
            with self.subTest(value_type=type(value).__name__):
                self.assertFalse(macos_harness.valid_sha(value))

    def test_mismatched_control_identity_refuses(self):
        with self.assertRaisesRegex(macos_harness.Refusal, "invalid_control_identity"):
            macos_harness.validate_candidate_record(record(control_sha="b" * 40), CONTROL_SHA)
        with self.assertRaisesRegex(macos_harness.Refusal, "invalid_control_identity"):
            macos_harness.validate_candidate_record(record(), "short")


class BoundaryRefusalTests(unittest.TestCase):
    def test_deprecated_arbitrary_process_sandbox_cannot_be_accepted(self):
        with self.assertRaisesRegex(macos_harness.Refusal, "deprecated_process_sandbox"):
            macos_harness.validate_candidate_record(record(boundary="sandbox-exec"), CONTROL_SHA)

    def test_app_sandbox_for_an_app_target_cannot_be_claimed_for_arbitrary_source(self):
        with self.assertRaisesRegex(macos_harness.Refusal, "app_sandbox_target_mismatch"):
            macos_harness.validate_candidate_record(record(boundary="app-sandbox"), CONTROL_SHA)

    def test_fresh_github_job_vm_is_not_a_process_boundary(self):
        with self.assertRaisesRegex(macos_harness.Refusal, "runner_vm_is_not_process_boundary"):
            macos_harness.validate_candidate_record(
                record(boundary="fresh-runner-vm", runner_isolation="job_vm_only"), CONTROL_SHA
            )

    def test_separate_user_and_disabled_developer_mode_are_insufficient(self):
        with self.assertRaisesRegex(macos_harness.Refusal, "no_supported_boundary"):
            macos_harness.validate_candidate_record(record(boundary="separate-user-only"), CONTROL_SHA)
        with self.assertRaisesRegex(macos_harness.Refusal, "incomplete_channel_evidence"):
            macos_harness.validate_candidate_record(
                record(boundary="separate-user-only", developer_mode="enabled"), CONTROL_SHA
            )

    def test_unknown_boundary_fails_closed(self):
        with self.assertRaisesRegex(macos_harness.Refusal, "no_supported_boundary"):
            macos_harness.validate_candidate_record(record(boundary="unreviewed"), CONTROL_SHA)


class ChannelEvidenceTests(unittest.TestCase):
    def test_every_required_channel_must_be_present_and_blocked(self):
        for channel in macos_harness.CHANNELS:
            missing = record()
            del missing["channel_results"][channel]
            with self.subTest(channel=channel, case="missing"):
                with self.assertRaisesRegex(macos_harness.Refusal, "incomplete_channel_evidence"):
                    macos_harness.validate_candidate_record(missing, CONTROL_SHA)

            reached = record()
            reached["channel_results"][channel] = "reached"
            with self.subTest(channel=channel, case="reached"):
                with self.assertRaisesRegex(macos_harness.Refusal, "incomplete_channel_evidence"):
                    macos_harness.validate_candidate_record(reached, CONTROL_SHA)

    def test_extra_channel_and_forged_field_are_rejected(self):
        extra_channel = record()
        extra_channel["channel_results"]["unknown"] = "blocked"
        with self.assertRaisesRegex(macos_harness.Refusal, "incomplete_channel_evidence"):
            macos_harness.validate_candidate_record(extra_channel, CONTROL_SHA)
        forged = record()
        forged["source_sha"] = CONTROL_SHA
        with self.assertRaisesRegex(macos_harness.Refusal, "incomplete_channel_evidence"):
            macos_harness.validate_candidate_record(forged, CONTROL_SHA)

    def test_malformed_or_overspecified_records_refuse(self):
        cases = (
            None,
            [],
            record(schema_version=True),
            record(schema_version=2),
            record(channel_results=[]),
        )
        for value in cases:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaises(macos_harness.Refusal):
                    macos_harness.validate_candidate_record(value, CONTROL_SHA)


class NativeExecutionRefusalTests(unittest.TestCase):
    def test_candidate_contains_no_native_command_or_host_control_imports(self):
        source = Path(macos_harness.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        forbidden = {"ctypes", "os", "pwd", "grp", "resource", "socket", "subprocess", "tempfile", "urllib"}
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        self.assertTrue(imported.isdisjoint(forbidden))
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in {"system", "popen", "run", "Popen"} for node in ast.walk(tree)))

    def test_native_probe_refuses_without_running(self):
        with self.assertRaisesRegex(macos_harness.Refusal, "native_probe_not_authorized"):
            macos_harness.run_native_probe(CONTROL_SHA)

    def test_cli_emits_only_a_fixed_refusal_and_never_an_acceptance(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = macos_harness.main(["--control-sha", CONTROL_SHA])
        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue(), "macos-confinement=refused reason=native_probe_not_authorized\n")
        self.assertNotIn("accepted", output.getvalue())

    def test_unknown_refusal_reason_collapses_to_fixed_safe_class(self):
        self.assertEqual(macos_harness.refuse("unknown-refusal-token"), "macos-confinement=refused reason=no_supported_boundary")


if __name__ == "__main__":
    unittest.main(verbosity=2)
