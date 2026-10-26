import base64
import datetime
import hashlib
import tempfile
import unittest
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

import macos_private_validation as subject


def _ssh_key_blob(start=0):
    algorithm = b"ssh-ed25519"
    public_key = bytes((start + offset) % 256 for offset in range(32))
    return len(algorithm).to_bytes(4, "big") + algorithm + len(public_key).to_bytes(4, "big") + public_key


class RequestTests(unittest.TestCase):
    def test_core_bootstrap_request_is_closed(self):
        request = subject.parse_request((
            "--source-sha", "a" * 40,
            "--base-sha", "b" * 40,
            "--base-branch", "main",
            "--concern", "core-bootstrap",
        ))
        self.assertEqual(request, {
            "source_sha": "a" * 40,
            "base_sha": "b" * 40,
            "base_branch": "main",
            "concern": "core-bootstrap",
        })

    def test_rules_bootstrap_request_is_closed(self):
        request = subject.parse_request((
            "--source-sha", "a" * 40,
            "--base-sha", "b" * 40,
            "--base-branch", "develop",
            "--concern", "rules-bootstrap",
        ))
        self.assertEqual(request["concern"], "rules-bootstrap")

    def test_extra_or_unrecognized_arguments_refuse(self):
        values = (
            "--source-sha", "a" * 40,
            "--base-sha", "b" * 40,
            "--base-branch", "main",
            "--concern", "core-bootstrap",
        )
        for arguments in (values + ("extra",), values[:2] + ("--command", "anything") + values[4:]):
            with self.subTest(arguments=arguments):
                with self.assertRaises(subject.Refusal) as result:
                    subject.parse_request(arguments)
                self.assertEqual((result.exception.reason, result.exception.stage), ("invalid_input", "input"))


class BootstrapGateTests(unittest.TestCase):
    def test_missing_control_sibling_imports_refuse_with_closed_context_stage(self):
        with patch.object(subject, "capability", None), patch.object(subject, "reviewed_build", None):
            with self.assertRaises(subject.Refusal) as result:
                subject._safe_context("c" * 40, {})
        self.assertEqual((result.exception.reason, result.exception.stage), ("context_unavailable", "context"))

    def test_rules_bootstrap_requires_both_exact_protected_shas(self):
        request = {
            "source_sha": "a" * 40,
            "base_sha": "b" * 40,
            "base_branch": "main",
            "concern": "rules-bootstrap",
        }
        environment = {
            "CI_SHA": "c" * 40,
            subject.RULES_BOOTSTRAP_SOURCE_GATE_ENV: "a" * 40,
            subject.RULES_BOOTSTRAP_CONTROL_GATE_ENV: "c" * 40,
        }
        subject._check_rules_bootstrap_gate(request, environment)
        environment[subject.RULES_BOOTSTRAP_SOURCE_GATE_ENV] = "d" * 40
        with self.assertRaises(subject.Refusal) as result:
            subject._check_rules_bootstrap_gate(request, environment)
        self.assertEqual((result.exception.reason, result.exception.stage), ("bootstrap_not_approved", "configuration"))

    def test_missing_rules_gate_refuses_before_context_or_helper_loading(self):
        request = {
            "source_sha": "a" * 40,
            "base_sha": "b" * 40,
            "base_branch": "main",
            "concern": "rules-bootstrap",
        }
        binding = {
            "control_sha": "c" * 40,
            "run_id": "1",
            "run_attempt": "1",
            "image_os": "macos-test",
            "image_version": "1",
        }
        with patch.object(subject, "_safe_context") as context, patch.object(subject, "_load_source_reader") as reader:
            with self.assertRaises(subject.Refusal) as result:
                with subject.validated_source(request, binding, Path("/missing"), {"CI_SHA": "c" * 40}):
                    self.fail("unapproved source lease opened")
        self.assertEqual((result.exception.reason, result.exception.stage), ("bootstrap_not_approved", "configuration"))
        context.assert_not_called()
        reader.assert_not_called()

    def test_missing_candidate_ref_refuses_before_context_or_helper_loading(self):
        request = {
            "source_sha": "a" * 40,
            "base_sha": "b" * 40,
            "base_branch": "main",
            "concern": "rules-bootstrap",
        }
        binding = {
            "control_sha": "c" * 40,
            "run_id": "1",
            "run_attempt": "1",
            "image_os": "macos-test",
            "image_version": "1",
        }
        environment = {
            "CI_SHA": "c" * 40,
            subject.RULES_BOOTSTRAP_SOURCE_GATE_ENV: "a" * 40,
            subject.RULES_BOOTSTRAP_CONTROL_GATE_ENV: "c" * 40,
        }
        with patch.object(subject, "_safe_context") as context, patch.object(subject, "_load_source_reader") as reader:
            with self.assertRaises(subject.Refusal) as result:
                with subject.validated_source(request, binding, Path("/missing"), environment):
                    self.fail("candidate without a protected branch ref was accepted")
        self.assertEqual((result.exception.reason, result.exception.stage), ("bootstrap_not_approved", "configuration"))
        context.assert_not_called()
        reader.assert_not_called()


class SourceRefTests(unittest.TestCase):
    def test_rules_descendant_requires_fixed_safe_candidate_ref(self):
        request = {
            "source_sha": "a" * 40,
            "base_sha": "b" * 40,
            "base_branch": "main",
            "concern": "rules-bootstrap",
        }
        environment = {subject.SOURCE_CANDIDATE_REF_ENV: "refs/heads/feat/reviewed-candidate"}
        self.assertEqual(
            subject._check_source_ref_binding(request, environment),
            "refs/heads/feat/reviewed-candidate",
        )

    def test_invalid_candidate_ref_and_core_descendant_refuse(self):
        request = {
            "source_sha": "a" * 40,
            "base_sha": "b" * 40,
            "base_branch": "main",
            "concern": "rules-bootstrap",
        }
        for value in (
            "refs/heads/users/candidate",
            "refs/heads/feat/../candidate",
            "refs/heads/feat/name.lock",
            "refs/heads/feat/name.",
            "refs/heads/feat/.hidden",
        ):
            with self.subTest(value=value), self.assertRaises(subject.Refusal):
                subject._check_source_ref_binding(request, {subject.SOURCE_CANDIDATE_REF_ENV: value})
        request["concern"] = "core-bootstrap"
        with self.assertRaises(subject.Refusal):
            subject._check_source_ref_binding(request, {subject.SOURCE_CANDIDATE_REF_ENV: "refs/heads/feat/candidate"})

    def test_permanent_tip_uses_the_already_bound_branch(self):
        request = {
            "source_sha": "a" * 40,
            "base_sha": "a" * 40,
            "base_branch": "develop",
            "concern": "rules-bootstrap",
        }
        self.assertIsNone(subject._check_source_ref_binding(request, {}))
        self.assertIsNone(
            subject._check_source_ref_binding(request, {subject.SOURCE_CANDIDATE_REF_ENV: "refs/heads/develop"})
        )


class RevocationResultTests(unittest.TestCase):
    class Reader:
        TOKEN_ENV = "SOURCE_READER_TOKEN"

        def __init__(self, result):
            self.result = result

        def run(self, environ=None):
            return self.result

    def test_exact_revocation_success_record_and_token_removal(self):
        environment = {"SOURCE_READER_TOKEN": "masked-token"}
        result = {
            "schema_version": 1,
            "status": "passed",
            "reason": "ok",
            "repository_scope": "verified",
            "metadata": "verified",
            "revocation": "confirmed",
        }
        self.assertEqual(subject._revoke_token(self.Reader(result), environment), result)
        self.assertNotIn("SOURCE_READER_TOKEN", environment)

    def test_noncanonical_revocation_record_refuses_and_removes_token(self):
        environment = {"SOURCE_READER_TOKEN": "masked-token"}
        result = {
            "schema_version": 1,
            "status": "passed",
            "reason": "ok",
            "repository_scope": "verified",
            "metadata": "verified",
            "revocation": "confirmed",
            "extra": "ignored",
        }
        with self.assertRaises(subject.Refusal) as refusal:
            subject._revoke_token(self.Reader(result), environment)
        self.assertEqual((refusal.exception.reason, refusal.exception.stage), ("revocation_unconfirmed", "revoke"))
        self.assertNotIn("SOURCE_READER_TOKEN", environment)

    def test_source_lease_is_immutable(self):
        lease = subject.SourceLease(Path("/tmp/lease"), MappingProxyType({"source_sha": "a" * 40}))
        with self.assertRaises(AttributeError):
            lease.source_path = Path("/other")
        with self.assertRaises(TypeError):
            lease.record["source_sha"] = "b" * 40


class EvidenceTests(unittest.TestCase):
    def _record(self, concern="core-bootstrap"):
        return {
            "repository_id": "123",
            "source_sha": "a" * 40,
            "base_sha": "a" * 40,
            "base_branch": "main",
            "concern": concern,
            "candidate_class": "permanent-tip",
            "signature": "verified",
            "rules_lock": "present" if concern == "core-bootstrap" else "not-applicable",
            "tree": "core_administrative" if concern == "core-bootstrap" else "rules_regular_files",
            "source_execution": "not_run_at_yield",
            "app_build": "not_run",
            "cleanup": "complete",
            "control_sha": "c" * 40,
            "run_id": "12",
            "run_attempt": "1",
            "image_os": "macos-test",
            "image_version": "1",
            "repository_scope": "verified",
            "metadata": "verified",
            "token_revocation": "confirmed_before_yield",
            "signer_authority": "bound_base",
            "signatures": "all_new_commits_verified",
            "ancestry": "base_ancestor",
            "revocation_policy": "current_control_fingerprints",
            "worker_access": "not_applicable" if concern == "core-bootstrap" else "uid_read_only",
        }

    def test_core_marker_binds_source_control_and_cleanup(self):
        binding = {
            "control_sha": "c" * 40,
            "run_id": "12",
            "run_attempt": "1",
            "image_os": "macos-test",
            "image_version": "1",
        }
        line = subject._format_success(self._record(), binding)
        for field in (
            "control-sha=" + "c" * 40,
            "source-repository-id=123",
            "source-sha=" + "a" * 40,
            "base-sha=" + "a" * 40,
            "rules-lock=present",
            "source-execution=not-run",
            "cleanup=complete",
        ):
            with self.subTest(field=field):
                self.assertIn(field, line.split())

    def test_rules_record_cannot_claim_core_lock_presence(self):
        binding = {
            "control_sha": "c" * 40,
            "run_id": "12",
            "run_attempt": "1",
            "image_os": "macos-test",
            "image_version": "1",
        }
        line = subject._format_success(self._record("rules-bootstrap"), binding)
        self.assertIn("rules-lock=not-applicable", line.split())

    def test_candidate_class_must_match_source_and_base_binding(self):
        binding = {
            "control_sha": "c" * 40,
            "run_id": "12",
            "run_attempt": "1",
            "image_os": "macos-test",
            "image_version": "1",
        }
        record = self._record()
        record["base_sha"] = "b" * 40
        with self.assertRaises(subject.Refusal) as result:
            subject._format_success(record, binding)
        self.assertEqual((result.exception.reason, result.exception.stage), ("internal_error", "input"))


class RevocationInventoryTests(unittest.TestCase):
    def test_empty_inventory_is_explicit_empty_state(self):
        self.assertEqual(subject._parse_fingerprint_inventory(b""), ())

    def test_canonical_fingerprint_lines_are_accepted(self):
        fingerprint = "SHA256:" + "A" * 43
        self.assertEqual(subject._parse_fingerprint_inventory((fingerprint + "\n").encode("ascii")), (fingerprint,))

    def test_malformed_duplicate_and_padded_fingerprints_refuse(self):
        fingerprint = "SHA256:" + "A" * 43
        invalid_payloads = (
            (fingerprint + "\r\n").encode("ascii"),
            (fingerprint + "\n" + fingerprint + "\n").encode("ascii"),
            (fingerprint + "=\n").encode("ascii"),
            (fingerprint).encode("ascii"),
        )
        for payload in invalid_payloads:
            with self.subTest(payload=payload):
                with self.assertRaises(subject.Refusal) as result:
                    subject._parse_fingerprint_inventory(payload)
                self.assertEqual(result.exception.reason, "revocation_policy_invalid")

    def test_revoked_fingerprint_must_match_base_signer(self):
        fingerprint = "SHA256:" + "A" * 43
        with self.assertRaises(subject.Refusal) as result:
            subject._revocation_payload((fingerprint,), {})
        self.assertEqual((result.exception.reason, result.exception.stage), ("revocation_policy_invalid", "revocation"))


class SignerInventoryTests(unittest.TestCase):
    def test_actual_compact_validity_interval_is_active_now(self):
        key_blob = _ssh_key_blob()
        encoded = base64.b64encode(key_blob).decode("ascii")
        payload = (
            "builder@example.invalid namespaces=\"git\",valid-after=\"20261021\",valid-before=\"20270119\" "
            "ssh-ed25519 " + encoded + "\n"
        ).encode("ascii")
        now = datetime.datetime(2026, 10, 26, 12, tzinfo=datetime.timezone.utc)
        signers = subject._signer_inventory(payload, current_time=now)
        expected = "SHA256:" + base64.b64encode(hashlib.sha256(key_blob).digest()).decode("ascii").rstrip("=")
        self.assertEqual(set(signers), {expected})
        self.assertEqual(signers[expected][0], ("ssh-ed25519 " + encoded + "\n").encode("ascii"))
        self.assertEqual(subject._active_signer_payload(signers), payload)

    def test_expired_signer_is_retained_for_revocation_but_not_current_authority(self):
        active_blob = _ssh_key_blob()
        retired_blob = _ssh_key_blob(1)
        active_encoded = base64.b64encode(active_blob).decode("ascii")
        retired_encoded = base64.b64encode(retired_blob).decode("ascii")
        payload = (
            "active@example.invalid namespaces=\"git\",valid-after=\"20261021\",valid-before=\"20270119\" "
            "ssh-ed25519 " + active_encoded + "\n"
            "retired@example.invalid namespaces=\"git\",valid-before=\"20261025\" "
            "ssh-ed25519 " + retired_encoded + "\n"
        ).encode("ascii")
        now = datetime.datetime(2026, 10, 26, 12, tzinfo=datetime.timezone.utc)
        signers = subject._signer_inventory(payload, current_time=now)
        active_fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(active_blob).digest()).decode("ascii").rstrip("=")
        retired_fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(retired_blob).digest()).decode("ascii").rstrip("=")
        self.assertEqual(set(signers), {active_fingerprint, retired_fingerprint})
        self.assertEqual(
            subject._active_signer_payload(signers),
            ("active@example.invalid namespaces=\"git\",valid-after=\"20261021\",valid-before=\"20270119\" ssh-ed25519 "
             + active_encoded + "\n").encode("ascii"),
        )
        self.assertEqual(
            subject._revocation_payload((retired_fingerprint,), signers),
            ("ssh-ed25519 " + retired_encoded + "\n").encode("ascii"),
        )

    def test_expired_or_not_yet_valid_signer_file_refuses_when_no_key_is_active(self):
        encoded = base64.b64encode(_ssh_key_blob()).decode("ascii")
        now = datetime.datetime(2026, 11, 1, 12, tzinfo=datetime.timezone.utc)
        for options in (
            "namespaces=\"git\",valid-before=\"20261031\"",
            "namespaces=\"git\",valid-after=\"20261102\"",
        ):
            payload = ("builder@example.invalid " + options + " ssh-ed25519 " + encoded + "\n").encode("ascii")
            with self.subTest(options=options), self.assertRaises(subject.Refusal) as result:
                subject._signer_inventory(payload, current_time=now)
            self.assertEqual((result.exception.reason, result.exception.stage), ("signature_invalid", "signature"))

    def test_expiry_date_is_a_utc_midnight_boundary(self):
        encoded = base64.b64encode(_ssh_key_blob()).decode("ascii")
        payload = (
            "builder@example.invalid namespaces=\"git\",valid-before=\"2026-11-01\" "
            "ssh-ed25519 " + encoded + "\n"
        ).encode("ascii")
        now = datetime.datetime(2026, 11, 1, 12, tzinfo=datetime.timezone.utc)
        with self.assertRaises(subject.Refusal) as result:
            subject._signer_inventory(payload, current_time=now)
        self.assertEqual((result.exception.reason, result.exception.stage), ("signature_invalid", "signature"))

    def test_exact_validity_timestamp_boundary_is_inclusive(self):
        encoded = base64.b64encode(_ssh_key_blob()).decode("ascii")
        payload = (
            "builder@example.invalid namespaces=\"git\",valid-after=\"202611011200\",valid-before=\"202611011200\" "
            "ssh-ed25519 " + encoded + "\n"
        ).encode("ascii")
        now = datetime.datetime(2026, 11, 1, 12, tzinfo=datetime.timezone.utc)
        signers = subject._signer_inventory(payload, current_time=now)
        self.assertTrue(subject._active_signer_payload(signers))

    def test_unknown_signer_option_refuses(self):
        encoded = base64.b64encode(_ssh_key_blob()).decode("ascii")
        payload = (
            "builder@example.invalid namespaces=\"git\",unknown=\"value\" "
            "ssh-ed25519 " + encoded + "\n"
        ).encode("ascii")
        with self.assertRaises(subject.Refusal) as result:
            subject._signer_inventory(payload)
        self.assertEqual((result.exception.reason, result.exception.stage), ("signature_invalid", "signature"))


class TreeEntryTests(unittest.TestCase):
    def test_single_nul_terminated_tree_entry_is_parsed(self):
        payload = b"100644 blob " + b"a" * 40 + b"\tci/revoked-signer-fingerprints\x00"
        self.assertEqual(
            subject._parse_single_tree_entry(payload, "ci/revoked-signer-fingerprints"),
            ("100644", "blob", "a" * 40),
        )

    def test_noncanonical_tree_entry_refuses(self):
        valid = b"100644 blob " + b"a" * 40 + b"\tci/revoked-signer-fingerprints\x00"
        invalid = (
            valid[:-1],
            valid + valid,
            valid.replace(b"ci/revoked-signer-fingerprints", b"other/path"),
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                self.assertIsNone(subject._parse_single_tree_entry(payload, "ci/revoked-signer-fingerprints"))


class ControlGitCommandTests(unittest.TestCase):
    def test_empty_graft_override_suppresses_only_its_deprecation_advice(self):
        environment = subject._base_git_environment(Path("/tmp"))
        settings = {
            environment["GIT_CONFIG_KEY_" + str(index)]: environment["GIT_CONFIG_VALUE_" + str(index)]
            for index in range(int(environment["GIT_CONFIG_COUNT"]))
        }
        self.assertEqual(environment["GIT_GRAFT_FILE"], "/dev/null")
        self.assertEqual(environment["GIT_NO_REPLACE_OBJECTS"], "1")
        self.assertEqual(settings["advice.graftFileDeprecated"], "false")
        self.assertEqual(settings["core.hooksPath"], "/dev/null")
        self.assertEqual(settings["credential.helper"], "")

    def test_git_error_and_other_stderr_still_refuse(self):
        for returncode, stderr in ((0, b"unexpected diagnostic"), (1, b"")):
            with self.subTest(returncode=returncode):
                result = subject.subprocess.CompletedProcess(("git",), returncode, b"", stderr)
                with self.assertRaises(subject.Refusal) as refusal:
                    subject._require_git_success(result, "configuration")
                self.assertEqual(refusal.exception.reason, "revocation_policy_invalid")

    def test_control_commands_bind_only_the_exact_resolved_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for operation in (
                ("ls-tree", "-z", "a" * 40, "--", subject.REVOCATION_INVENTORY),
                ("cat-file", "blob", "b" * 40),
            ):
                command = subject._control_git_command("/usr/bin/git", root, *operation)
                self.assertEqual(command[:3], (
                    "/usr/bin/git",
                    "-c",
                    "safe.directory=" + root.resolve().as_posix(),
                ))
                self.assertEqual(command[3:], operation)
                self.assertNotIn("safe.directory=*", command)

    def test_control_command_refuses_untrusted_or_missing_root(self):
        with self.assertRaises(subject.Refusal) as invalid_executable:
            subject._control_git_command("git", Path("/"), "ls-tree")
        self.assertEqual(
            (invalid_executable.exception.reason, invalid_executable.exception.stage),
            ("revocation_policy_invalid", "revocation"),
        )
        with tempfile.TemporaryDirectory() as temporary:
            missing = Path(temporary) / "missing"
            with self.assertRaises(subject.Refusal) as missing_root:
                subject._control_git_command("/usr/bin/git", missing, "ls-tree")
            self.assertEqual(
                (missing_root.exception.reason, missing_root.exception.stage),
                ("revocation_policy_invalid", "revocation"),
            )


if __name__ == "__main__":
    unittest.main()
