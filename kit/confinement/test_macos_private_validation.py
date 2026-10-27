import base64
import datetime
import hashlib
import stat
import tempfile
import unittest
from contextlib import nullcontext
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
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


@unittest.skipUnless(subject.os.name == "posix", "storage-root semantics use POSIX paths")
class StorageRootValidationTests(unittest.TestCase):
    def setUp(self):
        self.storage = Path("/tmp/storage-root-fixture")
        self.parent = Path("/tmp")
        self.directory = self._info(mode=stat.S_IFDIR | 0o700)
        self.parent_directory = self._info(mode=stat.S_IFDIR | 0o1777)

    @staticmethod
    def _info(*, device=1, inode=2, uid=0, mode, links=2):
        return SimpleNamespace(st_dev=device, st_ino=inode, st_uid=uid, st_mode=mode, st_nlink=links)

    def _validate(self, *, named=None, resolved=None, parent=None, resolved_path=None, nonempty=False):
        resolved_path = self.storage if resolved_path is None else resolved_path
        named = self.directory if named is None else named
        resolved = named if resolved is None else resolved
        parent = self.parent_directory if parent is None else parent

        def resolve(path, strict=False):
            if path == self.storage:
                return resolved_path
            if path == self.parent:
                return self.parent
            return path

        def lstat(path):
            if path == self.storage:
                return named
            if path == resolved_path:
                return resolved
            if path == self.parent:
                return parent
            raise AssertionError("unexpected path metadata request")

        entries = iter((object(),)) if nonempty else iter(())
        with patch.object(type(self.storage), "resolve", autospec=True, side_effect=resolve), \
                patch.object(type(self.storage), "lstat", autospec=True, side_effect=lstat), \
                patch.object(subject.os, "scandir", return_value=nullcontext(entries)):
            return subject._validate_storage_root(self.storage)

    def test_accepts_a_concrete_path_object_for_a_valid_root_owned_directory(self):
        self.assertIsInstance(self.storage, Path)
        self.assertEqual(self._validate(), self.storage)

    def test_refuses_nonabsolute_or_nonpath_values(self):
        for value in (Path("relative-storage-root"), object()):
            with self.subTest(value=type(value).__name__), self.assertRaises(subject.Refusal) as result:
                subject._validate_storage_root(value)
            self.assertEqual((result.exception.reason, result.exception.stage), ("bootstrap_not_approved", "configuration"))

    def test_refuses_nonroot_storage_directory(self):
        with self.assertRaises(subject.Refusal) as result:
            self._validate(named=self._info(uid=501, mode=stat.S_IFDIR | 0o700))
        self.assertEqual((result.exception.reason, result.exception.stage), ("bootstrap_not_approved", "configuration"))

    def test_refuses_storage_directory_with_unexpected_link_count(self):
        with self.assertRaises(subject.Refusal) as result:
            self._validate(named=self._info(mode=stat.S_IFDIR | 0o700, links=1))
        self.assertEqual((result.exception.reason, result.exception.stage), ("bootstrap_not_approved", "configuration"))

    def test_refuses_permissive_storage_mode(self):
        with self.assertRaises(subject.Refusal) as result:
            self._validate(named=self._info(mode=stat.S_IFDIR | 0o770))
        self.assertEqual((result.exception.reason, result.exception.stage), ("bootstrap_not_approved", "configuration"))

    def test_refuses_a_symlink_identity_change(self):
        target = Path("/tmp/storage-root-target")
        with self.assertRaises(subject.Refusal) as result:
            self._validate(
                named=self._info(mode=stat.S_IFLNK | 0o777),
                resolved=self._info(inode=3, mode=stat.S_IFDIR | 0o700),
                resolved_path=target,
            )
        self.assertEqual((result.exception.reason, result.exception.stage), ("bootstrap_not_approved", "configuration"))

    def test_refuses_untrusted_parent_and_nonempty_directory(self):
        for parent_info, nonempty in (
            (self._info(uid=501, mode=stat.S_IFDIR | 0o1777), False),
            (self._info(mode=stat.S_IFDIR | 0o0777), False),
            (self.parent_directory, True),
        ):
            with self.subTest(parent=parent_info, nonempty=nonempty), self.assertRaises(subject.Refusal) as result:
                self._validate(parent=parent_info, nonempty=nonempty)
            self.assertEqual((result.exception.reason, result.exception.stage), ("bootstrap_not_approved", "configuration"))

    def test_refuses_path_outside_the_fixed_temporary_parent(self):
        outside = Path("/tmp/nested/storage-root-fixture")
        with self.assertRaises(subject.Refusal) as result:
            self._validate(resolved_path=outside)
        self.assertEqual((result.exception.reason, result.exception.stage), ("bootstrap_not_approved", "configuration"))


class AclEntryTests(unittest.TestCase):
    def _read_entries(self, entry):
        output = b"drwx------  2 root  wheel  64 Oct 27 00:00 storage-root\n"
        output += entry.encode("ascii") + b"\n"
        result = SimpleNamespace(returncode=0, stderr=b"", stdout=output)
        with patch.object(subject, "_run_process", return_value=result):
            return subject._acl_entries(Path("/tmp/storage-root"), "/bin/ls")

    def test_accepts_the_single_space_emitted_by_apple_ls(self):
        entries = self._read_entries(" 0: user:runner allow search")
        self.assertEqual(entries, [" 0: user:runner allow search"])
        with patch.object(subject, "_acl_entries", return_value=entries):
            subject._verify_acl_rule(Path("/tmp/storage-root"), "/bin/ls", "runner", ("search",))

    def test_refuses_malformed_acl_spacing_and_nonmatching_rules(self):
        for entry in (
            "0: user:runner allow search",
            "  0: user:runner allow search",
            "\t0: user:runner allow search",
            " 1: user:runner allow search",
            " 0: user:other allow search",
            " 0: user:runner deny search",
            " 0: user:runner allow list,search",
            " 0: user:runner allow search,search",
            " 0: user:runner allow search inherited",
        ):
            with self.subTest(entry=entry), patch.object(subject, "_acl_entries", return_value=[entry]):
                with self.assertRaises(subject.Refusal) as result:
                    subject._verify_acl_rule(Path("/tmp/storage-root"), "/bin/ls", "runner", ("search",))
                self.assertEqual((result.exception.reason, result.exception.stage), ("bootstrap_snapshot_invalid", "bootstrap"))

    def test_refuses_multiple_acl_entries(self):
        entries = [" 0: user:runner allow search", " 1: user:runner allow search"]
        with patch.object(subject, "_acl_entries", return_value=entries):
            with self.assertRaises(subject.Refusal) as result:
                subject._verify_acl_rule(Path("/tmp/storage-root"), "/bin/ls", "runner", ("search",))
        self.assertEqual((result.exception.reason, result.exception.stage), ("bootstrap_snapshot_invalid", "bootstrap"))


class RevocationResultTests(unittest.TestCase):
    class Reader:
        TOKEN_ENV = "SOURCE_READER_TOKEN"

        def __init__(self, result):
            self.result = result

        def run(self, environ=None):
            return self.result

    def _run_snapshot_refusal_after_revocation(self, failure_stage):
        token = "opaque-token-for-proof"
        request = {
            "source_sha": "a" * 40,
            "base_sha": "a" * 40,
            "base_branch": "main",
            "concern": "core-bootstrap",
        }
        binding = {
            "control_sha": "b" * 40,
            "run_id": "12",
            "run_attempt": "2",
            "image_os": "macos-test",
            "image_version": "1",
        }
        environment = {
            "SOURCE_READER_TOKEN": token,
            "SOURCE_REPOSITORY_ID": "123",
        }
        result = {
            "schema_version": 1,
            "status": "passed",
            "reason": "ok",
            "repository_scope": "verified",
            "metadata": "verified",
            "revocation": "confirmed",
        }

        class Reader:
            TOKEN_ENV = "SOURCE_READER_TOKEN"

            @staticmethod
            def run(environ=None):
                return result

        def completed(returncode=0, stdout=b"", stderr=b""):
            return subject.subprocess.CompletedProcess(("git",), returncode, stdout, stderr)

        if failure_stage == "fetch":
            commands = (completed(), completed(), completed(1))
            expected = ("source_fetch_unavailable", "fetch")
        else:
            commands = (
                completed(), completed(), completed(), completed(stdout=b"a" * 40 + b"\n"),
                completed(stdout=b"a" * 40 + b"\n"), completed(stdout=b"false\n"), completed(),
            )
            expected = ("signature_invalid", "signature")
        state = subject.RevocationState()
        signer_inventory = (
            None if failure_stage == "fetch"
            else subject.Refusal("signature_invalid", "signature")
        )
        with patch.object(subject, "_resolve_trusted_executable", side_effect=lambda path: path), \
                patch.object(subject, "_safe_temp_root", return_value=Path("snapshot-fixture")), \
                patch.object(subject, "_control_inventory", return_value=()), \
                patch.object(subject, "_load_source_reader", return_value=Reader), \
                patch.object(subject, "_repository_configuration", return_value=(123, "owner", "repo", token)), \
                patch.object(subject, "_verify_repository_scope"), \
                patch.object(subject, "_base_git_environment", return_value={}), \
                patch.object(subject, "_run_process", side_effect=commands), \
                patch.object(subject, "_source_entry", return_value=("100644", "blob", "d" * 40)), \
                patch.object(subject, "_read_source_blob", return_value=b"signer fixture\n"), \
                patch.object(subject, "_signer_inventory", side_effect=signer_inventory), \
                patch.object(subject, "_remove_tree"):
            with self.assertRaises(subject.Refusal) as refusal:
                subject._source_snapshot(
                    request,
                    binding,
                    Path("control-root"),
                    environment,
                    revocation_state=state,
                )
        self.assertEqual((refusal.exception.reason, refusal.exception.stage), expected)
        self.assertTrue(subject.revocation_confirmed(state, token, "123", request, binding))
        self.assertNotIn("SOURCE_READER_TOKEN", environment)
        return state, token, request, binding

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

    def test_noncanonical_revocation_record_refuses_and_retains_token(self):
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
        self.assertEqual(environment["SOURCE_READER_TOKEN"], "masked-token")

    def test_revocation_proof_binds_token_repository_control_source_and_run(self):
        token = "opaque-token-for-proof"
        repository_id = "123"
        request = {
            "source_sha": "a" * 40,
            "base_sha": "a" * 40,
            "base_branch": "main",
            "concern": "core-bootstrap",
        }
        binding = {
            "control_sha": "b" * 40,
            "run_id": "12",
            "run_attempt": "2",
            "image_os": "macos-test",
            "image_version": "1",
        }
        result = {
            "schema_version": 1,
            "status": "passed",
            "reason": "ok",
            "repository_scope": "verified",
            "metadata": "verified",
            "revocation": "confirmed",
        }
        environment = {"SOURCE_READER_TOKEN": token}
        state = subject.RevocationState()
        subject._revoke_token(
            self.Reader(result),
            environment,
            revocation_state=state,
            retained_token=token,
            repository_id=repository_id,
            request=request,
            binding=binding,
        )
        self.assertTrue(subject.revocation_confirmed(state, token, repository_id, request, binding))
        self.assertFalse(subject.revocation_confirmed(state, "different-token", repository_id, request, binding))
        self.assertFalse(subject.revocation_confirmed(state, token, "124", request, binding))
        changed_binding = dict(binding, run_attempt="3")
        self.assertFalse(subject.revocation_confirmed(state, token, repository_id, request, changed_binding))
        changed_request = dict(request, source_sha="c" * 40)
        self.assertFalse(subject.revocation_confirmed(state, token, repository_id, changed_request, binding))

    def test_unconfirmed_reader_result_never_creates_a_revocation_proof(self):
        token = "opaque-token-for-proof"
        request = {
            "source_sha": "a" * 40,
            "base_sha": "a" * 40,
            "base_branch": "main",
            "concern": "core-bootstrap",
        }
        binding = {
            "control_sha": "b" * 40,
            "run_id": "12",
            "run_attempt": "2",
            "image_os": "macos-test",
            "image_version": "1",
        }
        refused = {
            "schema_version": 1,
            "status": "refused",
            "reason": "revocation_unconfirmed",
            "repository_scope": "verified",
            "metadata": "verified",
            "revocation": "unconfirmed",
        }
        environment = {"SOURCE_READER_TOKEN": token}
        state = subject.RevocationState()
        with self.assertRaises(subject.Refusal):
            subject._revoke_token(
                self.Reader(refused),
                environment,
                revocation_state=state,
                retained_token=token,
                repository_id="123",
                request=request,
                binding=binding,
            )
        self.assertEqual(environment["SOURCE_READER_TOKEN"], token)
        self.assertFalse(subject.revocation_confirmed(state, token, "123", request, binding))

    def test_confirmed_remote_receipt_survives_local_token_cleanup_failure(self):
        token = "opaque-token-for-proof"
        request = {
            "source_sha": "a" * 40,
            "base_sha": "a" * 40,
            "base_branch": "main",
            "concern": "core-bootstrap",
        }
        binding = {
            "control_sha": "b" * 40,
            "run_id": "12",
            "run_attempt": "2",
            "image_os": "macos-test",
            "image_version": "1",
        }
        result = {
            "schema_version": 1,
            "status": "passed",
            "reason": "ok",
            "repository_scope": "verified",
            "metadata": "verified",
            "revocation": "confirmed",
        }

        class NoPop(dict):
            def pop(self, key, default=None):
                raise OSError

        environment = NoPop({"SOURCE_READER_TOKEN": token})
        state = subject.RevocationState()
        with self.assertRaises(subject.Refusal) as refusal:
            subject._revoke_token(
                self.Reader(result), environment,
                revocation_state=state,
                retained_token=token,
                repository_id="123",
                request=request,
                binding=binding,
            )
        self.assertEqual((refusal.exception.reason, refusal.exception.stage), ("cleanup_incomplete", "cleanup"))
        self.assertTrue(subject.revocation_confirmed(state, token, "123", request, binding))
        self.assertEqual(environment["SOURCE_READER_TOKEN"], token)

    def test_proof_state_cannot_be_reused(self):
        token = "opaque-token-for-proof"
        request = {
            "source_sha": "a" * 40,
            "base_sha": "a" * 40,
            "base_branch": "main",
            "concern": "core-bootstrap",
        }
        binding = {
            "control_sha": "b" * 40,
            "run_id": "12",
            "run_attempt": "2",
            "image_os": "macos-test",
            "image_version": "1",
        }
        result = {
            "schema_version": 1,
            "status": "passed",
            "reason": "ok",
            "repository_scope": "verified",
            "metadata": "verified",
            "revocation": "confirmed",
        }
        state = subject.RevocationState()
        first_environment = {"SOURCE_READER_TOKEN": token}
        subject._revoke_token(
            self.Reader(result), first_environment,
            revocation_state=state,
            retained_token=token,
            repository_id="123",
            request=request,
            binding=binding,
        )
        second_environment = {"SOURCE_READER_TOKEN": token}
        with self.assertRaises(subject.Refusal):
            subject._revoke_token(
                self.Reader(result), second_environment,
                revocation_state=state,
                retained_token=token,
                repository_id="123",
                request=request,
                binding=binding,
            )
        self.assertEqual(second_environment["SOURCE_READER_TOKEN"], token)

    def test_pending_fetch_refusal_retains_exact_revocation_receipt(self):
        self._run_snapshot_refusal_after_revocation("fetch")

    def test_later_signature_refusal_retains_exact_revocation_receipt(self):
        self._run_snapshot_refusal_after_revocation("signature")

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

    def test_fetch_refusal_has_only_closed_operation_and_failure_labels(self):
        cases = (
            (1, b"private diagnostic", "exit_nonzero"),
            (0, b"private diagnostic", "stderr_present"),
        )
        for returncode, stderr, failure_class in cases:
            result = subject.subprocess.CompletedProcess(("git",), returncode, b"", stderr)
            with self.subTest(returncode=returncode), self.assertRaises(subject.Refusal) as refusal:
                subject._require_git_success(result, "fetch", operation="base_fetch")
            self.assertEqual(refusal.exception.reason, "source_fetch_unavailable")
            self.assertEqual(refusal.exception.stage, "fetch")
            self.assertEqual(refusal.exception.source_diagnostic, ("base_fetch", failure_class))
            self.assertEqual(str(refusal.exception), "source_fetch_unavailable")

    def test_source_git_labels_process_and_unexpected_failures_without_exception_text(self):
        with patch.object(
            subject, "_run_process", side_effect=subject.Refusal("source_fetch_unavailable", "fetch"),
        ):
            with self.assertRaises(subject.Refusal) as process_refusal:
                subject._run_source_git("candidate_fetch", ("git", "fetch"), cwd=Path("/tmp"), environ={})
        self.assertEqual(process_refusal.exception.source_diagnostic, ("candidate_fetch", "process_failure"))
        self.assertEqual(str(process_refusal.exception), "source_fetch_unavailable")

        with patch.object(subject, "_run_process", side_effect=RuntimeError("private exception text")):
            with self.assertRaises(subject.Refusal) as unexpected_refusal:
                subject._run_source_git("base_fetch", ("git", "fetch"), cwd=Path("/tmp"), environ={})
        self.assertEqual(unexpected_refusal.exception.source_diagnostic, ("base_fetch", "unexpected_exception"))
        self.assertEqual(str(unexpected_refusal.exception), "source_fetch_unavailable")

    def test_unknown_source_git_operation_has_no_diagnostic(self):
        with self.assertRaises(subject.Refusal) as refusal:
            subject._run_source_git("unlisted_operation", ("git", "fetch"), cwd=Path("/tmp"), environ={})
        self.assertEqual((refusal.exception.reason, refusal.exception.stage), ("source_fetch_unavailable", "fetch"))
        self.assertIsNone(refusal.exception.source_diagnostic)

    def test_worktree_add_suppresses_git_feedback_and_still_rejects_other_stderr(self):
        arguments = subject._worktree_add_arguments(
            "/usr/bin/git", Path("source-fixture"), "a" * 40,
        )
        self.assertEqual(arguments, (
            "/usr/bin/git", "worktree", "add", "--quiet", "--detach", "--no-checkout",
            "source-fixture", "a" * 40,
        ))
        self.assertEqual(subject._require_git_success(
            subject.subprocess.CompletedProcess(arguments, 0, b"", b""), "bootstrap",
        ), b"")
        with self.assertRaises(subject.Refusal) as refusal:
            subject._require_git_success(
                subject.subprocess.CompletedProcess(arguments, 0, b"", b"unexpected"), "bootstrap",
            )
        self.assertEqual((refusal.exception.reason, refusal.exception.stage), (
            "bootstrap_snapshot_invalid", "bootstrap",
        ))

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
