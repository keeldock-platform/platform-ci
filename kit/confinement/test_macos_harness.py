import ast
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import macos_harness
import macos_public_audit


CONTROL_SHA = "a" * 40


def receipt(**changes):
    value = {
        "schema_version": 2,
        "run_id": 123,
        "run_attempt": 1,
        "control_sha": CONTROL_SHA,
        "boundary": "seatbelt-deny-default",
        "macos_product_version": "15.7.9",
        "runner_image_os": "macos-15-arm64",
        "runner_image_version": "20260907.0337.1",
        "developer_mode": "disabled",
        "pf": "enforced",
        "sandbox_selftest": "enforced",
        "positive_build": "passed",
        "channels": dict(macos_public_audit.EXPECTED_CHANNELS),
        "private_source_executed": False,
    }
    value.update(changes)
    return value


def encode_receipt(value):
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode("ascii")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def validate_with_receipt(candidate, native_receipt):
    environment = {
        "CI_SHA": CONTROL_SHA,
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
        "MACOS_NATIVE_RECEIPT_B64URL": encode_receipt(native_receipt),
    }
    with patch.dict("os.environ", environment, clear=True):
        with patch.object(macos_public_audit, "run", return_value=0):
            return macos_harness.validate_candidate_record(candidate, CONTROL_SHA)


class ControlIdentityTests(unittest.TestCase):
    def test_only_full_lowercase_control_shas_are_valid(self):
        self.assertTrue(macos_harness.valid_sha(CONTROL_SHA))
        for value in ("a" * 12, "A" * 40, "g" * 40, "a" * 41, None):
            with self.subTest(value_type=type(value).__name__):
                self.assertFalse(macos_harness.valid_sha(value))

    def test_candidate_sha_must_match_control_identity(self):
        candidate = macos_harness._record_from_receipt(receipt())
        with self.assertRaisesRegex(macos_harness.Refusal, "invalid_control_identity"):
            macos_harness.validate_candidate_record(candidate, "short")
        with patch.dict("os.environ", {"CI_SHA": CONTROL_SHA}, clear=True):
            with self.assertRaisesRegex(macos_harness.Refusal, "invalid_control_identity"):
                macos_harness.validate_candidate_record(candidate, "b" * 40)


class CurrentRunAcceptanceTests(unittest.TestCase):
    def test_caller_fabricated_record_requires_current_api_audit(self):
        candidate = macos_harness._record_from_receipt(receipt())
        environment = {
            "CI_SHA": CONTROL_SHA,
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "MACOS_NATIVE_RECEIPT_B64URL": encode_receipt(receipt()),
        }
        with patch.dict("os.environ", environment, clear=True):
            with patch.object(macos_public_audit, "run", side_effect=RuntimeError("untrusted")):
                with self.assertRaisesRegex(macos_harness.Refusal, "public_audit_incomplete"):
                    macos_harness.validate_candidate_record(candidate, CONTROL_SHA)

    def test_valid_record_requires_current_audit_and_maps_all_channels(self):
        native_receipt = receipt()
        candidate = macos_harness._record_from_receipt(native_receipt)
        environment = {
            "CI_SHA": CONTROL_SHA,
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "MACOS_NATIVE_RECEIPT_B64URL": encode_receipt(native_receipt),
        }
        with patch.dict("os.environ", environment, clear=True):
            with patch.object(macos_public_audit, "run", return_value=0) as run:
                accepted = macos_harness.validate_candidate_record(candidate, CONTROL_SHA)
        run.assert_called_once_with("audit", environ=os.environ)
        self.assertEqual(accepted["boundary"], "seatbelt-deny-default")
        self.assertFalse(accepted["private_source_executed"])
        self.assertEqual(set(accepted["channel_results"].values()), {"blocked"})

    def test_partial_receipt_refuses_before_candidate_acceptance(self):
        partial = receipt()
        del partial["positive_build"]
        candidate = macos_harness._record_from_receipt(receipt())
        environment = {
            "CI_SHA": CONTROL_SHA,
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "MACOS_NATIVE_RECEIPT_B64URL": encode_receipt(partial),
        }
        with patch.dict("os.environ", environment, clear=True):
            with patch.object(macos_public_audit, "run", return_value=0):
                with self.assertRaisesRegex(macos_harness.Refusal, "public_audit_incomplete"):
                    macos_harness.validate_candidate_record(candidate, CONTROL_SHA)

    def test_mismatched_receipt_or_candidate_identity_refuses(self):
        candidate = macos_harness._record_from_receipt(receipt())
        mismatched_receipt = receipt(control_sha="b" * 40)
        environment = {
            "CI_SHA": CONTROL_SHA,
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "MACOS_NATIVE_RECEIPT_B64URL": encode_receipt(mismatched_receipt),
        }
        with patch.dict("os.environ", environment, clear=True):
            with patch.object(macos_public_audit, "run", return_value=0):
                with self.assertRaisesRegex(macos_harness.Refusal, "public_audit_incomplete"):
                    macos_harness.validate_candidate_record(candidate, CONTROL_SHA)

        changed = dict(candidate, control_sha="b" * 40)
        with self.assertRaisesRegex(macos_harness.Refusal, "incomplete_channel_evidence"):
            validate_with_receipt(changed, receipt())

    def test_candidate_cannot_supply_an_authorizing_evidence_object(self):
        candidate = macos_harness._record_from_receipt(receipt())
        with self.assertRaises(TypeError):
            macos_harness.validate_candidate_record(candidate, CONTROL_SHA, evidence=object())

    def test_each_channel_must_remain_blocked(self):
        native_receipt = receipt()
        candidate = macos_harness._record_from_receipt(native_receipt)
        for channel in macos_harness.CHANNELS:
            changed = dict(candidate)
            changed["channel_results"] = dict(candidate["channel_results"])
            changed["channel_results"][channel] = "reached"
            with self.subTest(channel=channel):
                with self.assertRaisesRegex(macos_harness.Refusal, "incomplete_channel_evidence"):
                    validate_with_receipt(changed, native_receipt)

    def test_malformed_or_overspecified_candidate_records_refuse(self):
        candidate = macos_harness._record_from_receipt(receipt())
        extra_field = dict(candidate, unexpected="value")
        missing_field = dict(candidate)
        del missing_field["control_sha"]
        extra_channel = dict(candidate)
        extra_channel["channel_results"] = dict(candidate["channel_results"])
        extra_channel["channel_results"]["unknown"] = "blocked"
        cases = (
            None,
            [],
            dict(candidate, schema_version=True),
            dict(candidate, schema_version=2.0),
            extra_field,
            missing_field,
            dict(candidate, channel_results=[]),
            extra_channel,
        )
        for value in cases:
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaisesRegex(macos_harness.Refusal, "incomplete_channel_evidence"):
                    validate_with_receipt(value, receipt())

    def test_boundary_and_runner_claims_fail_closed(self):
        native_receipt = receipt()
        candidate = macos_harness._record_from_receipt(native_receipt)
        cases = (
            (dict(candidate, boundary="sandbox-exec"), "deprecated_process_sandbox"),
            (dict(candidate, boundary="app-sandbox"), "app_sandbox_target_mismatch"),
            (dict(candidate, boundary="unreviewed"), "no_supported_boundary"),
            (
                dict(candidate, boundary="fresh-runner-vm", runner_isolation="job_vm_only"),
                "runner_vm_is_not_process_boundary",
            ),
            (dict(candidate, developer_mode="enabled"), "no_supported_boundary"),
        )
        for changed, reason in cases:
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(macos_harness.Refusal, reason):
                    validate_with_receipt(changed, native_receipt)

    def test_external_audit_fields_are_required_before_mapping(self):
        for channel, native_value in (
            ("raw_logs", "blocked"),
            ("artifact_upload", "blocked"),
            ("cache_upload", "blocked"),
        ):
            native = receipt()
            native["channels"] = dict(native["channels"])
            native["channels"][channel] = native_value
            with self.subTest(channel=channel):
                with self.assertRaisesRegex(macos_harness.Refusal, "incomplete_channel_evidence"):
                    macos_harness._record_from_receipt(native)


class PublicAuditBindingTests(unittest.TestCase):
    def test_current_run_binds_receipt_to_live_run_identity(self):
        native_receipt = receipt()
        env = {
            "CI_SHA": CONTROL_SHA,
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "MACOS_NATIVE_RECEIPT_B64URL": encode_receipt(native_receipt),
        }
        with patch.dict("os.environ", env, clear=True):
            with patch.object(macos_public_audit, "run", return_value=0) as run:
                result = macos_harness._verify_current_run(CONTROL_SHA)
        run.assert_called_once_with("audit", environ=os.environ)
        self.assertEqual(result, native_receipt)

    def test_audit_failure_collapses_to_safe_refusal(self):
        env = {
            "CI_SHA": CONTROL_SHA,
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "MACOS_NATIVE_RECEIPT_B64URL": encode_receipt(receipt()),
        }
        with patch.dict("os.environ", env, clear=True):
            with patch.object(macos_public_audit, "run", side_effect=RuntimeError("private diagnostic")):
                with self.assertRaisesRegex(macos_harness.Refusal, "public_audit_incomplete"):
                    macos_harness._verify_current_run(CONTROL_SHA)

    def test_nonzero_audit_status_cannot_authorize(self):
        env = {
            "CI_SHA": CONTROL_SHA,
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "MACOS_NATIVE_RECEIPT_B64URL": encode_receipt(receipt()),
        }
        with patch.dict("os.environ", env, clear=True):
            with patch.object(macos_public_audit, "run", return_value=2):
                with self.assertRaisesRegex(macos_harness.Refusal, "public_audit_incomplete"):
                    macos_harness._verify_current_run(CONTROL_SHA)

    def test_command_line_acceptance_uses_one_live_audit(self):
        env = {
            "CI_SHA": CONTROL_SHA,
            "GITHUB_RUN_ID": "123",
            "GITHUB_RUN_ATTEMPT": "1",
            "MACOS_NATIVE_RECEIPT_B64URL": encode_receipt(receipt()),
        }
        output = io.StringIO()
        with patch.dict("os.environ", env, clear=True):
            with patch.object(macos_public_audit, "run", return_value=0) as run:
                with contextlib.redirect_stdout(output):
                    result = macos_harness.main(["--control-sha", CONTROL_SHA])
        self.assertEqual(result, 0)
        run.assert_called_once_with("audit", environ=os.environ)
        self.assertEqual(
            output.getvalue(),
            "macos-confinement=accepted boundary=seatbelt-deny-default channels=11/11 "
            "evidence=github-native-and-public-audit\n",
        )
        self.assertNotIn("canary", output.getvalue())


class SourceSafetyTests(unittest.TestCase):
    def test_harness_has_no_native_process_or_host_control_imports(self):
        source = Path(macos_harness.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        forbidden = {"ctypes", "pwd", "grp", "resource", "socket", "subprocess", "tempfile", "urllib"}
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.update(alias.name.split(".", 1)[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module.split(".", 1)[0])
        self.assertTrue(imported.isdisjoint(forbidden))

        unsafe_calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if isinstance(function, ast.Attribute):
                trusted_audit_call = (
                    function.attr == "run"
                    and isinstance(function.value, ast.Name)
                    and function.value.id == "macos_public_audit"
                )
                if function.attr in {"system", "popen", "Popen"}:
                    unsafe_calls.append(node)
                elif function.attr == "run" and not trusted_audit_call:
                    unsafe_calls.append(node)
            elif isinstance(function, ast.Name) and function.id in {
                "eval", "exec", "compile", "__import__"
            }:
                unsafe_calls.append(node)
        self.assertEqual(unsafe_calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
