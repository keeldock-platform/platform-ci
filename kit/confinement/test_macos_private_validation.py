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

    def test_core_contract_request_is_closed(self):
        request = subject.parse_request((
            "--source-sha", "a" * 40,
            "--base-sha", "b" * 40,
            "--base-branch", "main",
            "--concern", "core-contract",
        ))
        self.assertEqual(request["concern"], "core-contract")

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


class CoreCheckTests(unittest.TestCase):
    def test_core_check_values_are_closed_and_preserve_the_original_refusal(self):
        expected = {
            "tree_entries", "required_files", "path_mode", "base_policy", "rules_manifest",
            "rules_inventory", "rules_hash", "workspace_decode", "workspace_members",
            "cargo_lock_decode", "cargo_lock_shape", "toolchain", "package_decode",
            "package_build", "checkout", "lease_paths", "lease_acl", "lease_access",
            "lease_census",
        }
        self.assertEqual(subject.CORE_BOOTSTRAP_CHECKS, expected)
        for check in expected:
            with self.subTest(check=check):
                refusal = subject.Refusal(
                    "bootstrap_snapshot_invalid", "bootstrap", core_check=check,
                )
                self.assertEqual(
                    (refusal.reason, refusal.stage, refusal.core_check),
                    ("bootstrap_snapshot_invalid", "bootstrap", check),
                )
                self.assertEqual(str(refusal), "bootstrap_snapshot_invalid")

    def test_core_check_discards_unknown_values_and_non_core_refusals(self):
        for check in ("private-value", 17, object()):
            with self.subTest(check=type(check).__name__):
                refusal = subject.Refusal(
                    "bootstrap_snapshot_invalid", "bootstrap", core_check=check,
                )
                self.assertIsNone(refusal.core_check)
        for reason, stage in (
            ("source_fetch_unavailable", "fetch"),
            ("cleanup_incomplete", "cleanup"),
            ("bootstrap_snapshot_invalid", "configuration"),
        ):
            with self.subTest(reason=reason, stage=stage):
                refusal = subject.Refusal(
                    reason, stage, core_check="tree_entries",
                )
                self.assertIsNone(refusal.core_check)
                self.assertEqual((refusal.reason, refusal.stage), (reason, stage))


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

    def test_core_contract_requires_its_own_exact_protected_shas(self):
        request = {
            "source_sha": "a" * 40,
            "base_sha": "b" * 40,
            "base_branch": "main",
            "concern": "core-contract",
        }
        environment = {
            "CI_SHA": "c" * 40,
            subject.CORE_CONTRACT_SOURCE_GATE_ENV: "a" * 40,
            subject.CORE_CONTRACT_CONTROL_GATE_ENV: "c" * 40,
        }
        subject._check_core_contract_gate(request, environment)
        for key, value in (
            (subject.CORE_CONTRACT_SOURCE_GATE_ENV, "d" * 40),
            (subject.CORE_CONTRACT_CONTROL_GATE_ENV, "d" * 40),
            ("CI_SHA", "invalid"),
        ):
            changed = dict(environment, **{key: value})
            with self.subTest(key=key), self.assertRaises(subject.Refusal) as result:
                subject._check_core_contract_gate(request, changed)
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

    def test_missing_core_contract_gate_refuses_before_context_or_helper_loading(self):
        request = {
            "source_sha": "a" * 40,
            "base_sha": "b" * 40,
            "base_branch": "main",
            "concern": "core-contract",
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
                    self.fail("unapproved contract source lease opened")
        self.assertEqual((result.exception.reason, result.exception.stage), ("bootstrap_not_approved", "configuration"))
        context.assert_not_called()
        reader.assert_not_called()

    def test_core_contract_snapshot_cannot_be_opened_with_rules_gate_values(self):
        request = {
            "source_sha": "a" * 40,
            "base_sha": "b" * 40,
            "base_branch": "main",
            "concern": "core-contract",
        }
        environment = {
            "CI_SHA": "c" * 40,
            subject.RULES_BOOTSTRAP_SOURCE_GATE_ENV: "a" * 40,
            subject.RULES_BOOTSTRAP_CONTROL_GATE_ENV: "c" * 40,
        }
        with patch.object(subject, "_resolve_trusted_executable") as resolve:
            with self.assertRaises(subject.Refusal) as result:
                subject._source_snapshot(request, {}, Path("/tmp"), environment)
        self.assertEqual((result.exception.reason, result.exception.stage), ("bootstrap_not_approved", "configuration"))
        resolve.assert_not_called()

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

    def test_core_contract_descendant_requires_fixed_safe_candidate_ref(self):
        request = {
            "source_sha": "a" * 40,
            "base_sha": "b" * 40,
            "base_branch": "main",
            "concern": "core-contract",
        }
        self.assertEqual(
            subject._check_source_ref_binding(
                request,
                {subject.SOURCE_CANDIDATE_REF_ENV: "refs/heads/feat/reviewed-contract"},
            ),
            "refs/heads/feat/reviewed-contract",
        )
        for value in ("refs/heads/users/candidate", "refs/heads/feat/../candidate"):
            with self.subTest(value=value), self.assertRaises(subject.Refusal):
                subject._check_source_ref_binding(request, {subject.SOURCE_CANDIDATE_REF_ENV: value})

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


class CoreContractTreeTests(unittest.TestCase):
    def test_core_contract_path_scope_is_limited_to_workspace_and_three_crates(self):
        for path in subject.CORE_CONTRACT_ROOT_FILES:
            self.assertEqual(subject._core_contract_expected_mode(path), "100644")
        for root in subject.CORE_CONTRACT_CRATE_ROOTS:
            prefix = "/".join(root)
            for path in (
                prefix + "/Cargo.toml",
                prefix + "/README.md",
                prefix + "/CONTRACT.md",
                prefix + "/CHANGELOG.md",
                prefix + "/src/lib.rs",
                prefix + "/tests/nested/contract.rs",
            ):
                with self.subTest(path=path):
                    self.assertEqual(subject._core_contract_expected_mode(path), "100644")
        for path in (
            "crates/host/core/src/lib.rs",
            "crates/host/api/build.rs",
            "crates/host/api/src/build.rs",
            "crates/host/api/tests/build.rs",
            ".cargo/config.toml",
            "ci/run-suite.sh",
        ):
            with self.subTest(path=path):
                self.assertIsNone(subject._core_contract_expected_mode(path))

    def test_rules_lock_requires_v2_and_only_manifested_installed_files(self):
        rules_file = subject.RULES_DIRECTORY + "/rules/shared/rust.md"
        hooks_file = subject.RULES_DIRECTORY + "/hooks/shared/check-shared-lock.sh"
        digest = hashlib.sha256(b"fixture").hexdigest()
        payload = (
            "format 3\n"
            "profile full\n"
            "tag v2.4.1\n"
            "signature verified\n"
            "file AGENTS.md " + digest + "\n"
            "file " + rules_file + " " + digest + "\n"
            "file " + hooks_file + " " + digest + "\n"
        ).encode("ascii")
        self.assertEqual(set(subject._rules_v2_file_manifest(payload)), {"AGENTS.md", rules_file, hooks_file})
        for invalid in (
            payload.replace(b"tag v2.4.1", b"tag v1.4.1"),
            payload.replace(rules_file.encode("ascii"), b"outside/rules.md"),
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(subject.Refusal) as refusal:
                    subject._rules_v2_file_manifest(invalid)
            self.assertEqual(
                (refusal.exception.reason, refusal.exception.stage, refusal.exception.core_check),
                ("bootstrap_snapshot_invalid", "bootstrap", "rules_manifest"),
            )

    def test_contract_tree_parser_refuses_a_link_entry(self):
        payload = b"120000 blob " + b"a" * 40 + b"\tcrates/host/api/src/lib.rs\x00"
        result = subject.subprocess.CompletedProcess(("git",), 0, payload, b"")
        with patch.object(subject, "_run_process", return_value=result):
            with self.assertRaises(subject.Refusal) as refusal:
                subject._contract_tree_entries("repository", "/usr/bin/git", {}, "a" * 40)
        self.assertEqual(
            (refusal.exception.reason, refusal.exception.stage, refusal.exception.core_check),
            ("bootstrap_snapshot_invalid", "bootstrap", "tree_entries"),
        )

    @staticmethod
    def _required_core_contract_entries():
        paths = {
            ".gitignore", "AGENTS.md", "CLAUDE.md", "README.md", subject.RULES_LOCK_PATH,
            subject.RULES_DIRECTORY + "/settings.json", "/".join(subject.SIGNER_PATH_PARTS),
        } | set(subject.CORE_CONTRACT_ROOT_FILES)
        for crate_root in subject.CORE_CONTRACT_CRATE_ROOTS:
            prefix = "/".join(crate_root)
            paths.update(prefix + "/" + item for item in subject.CORE_CONTRACT_PACKAGE_FILES)
            paths.add(prefix + "/src/lib.rs")
        return {path: ("100644", "a" * 40) for path in paths}

    def test_core_contract_required_file_and_path_mode_checks_are_tagged(self):
        for entries, check in (
            ({}, "required_files"),
            ({**self._required_core_contract_entries(), ".gitignore": ("100755", "a" * 40)}, "path_mode"),
        ):
            with self.subTest(check=check), patch.object(
                subject, "_contract_tree_entries", side_effect=(entries, entries),
            ), self.assertRaises(subject.Refusal) as refusal:
                subject._safe_core_contract_tree(
                    "repository", "/usr/bin/git", {}, "a" * 40, "b" * 40,
                )
            self.assertEqual(
                (refusal.exception.reason, refusal.exception.stage, refusal.exception.core_check),
                ("bootstrap_snapshot_invalid", "bootstrap", check),
            )

    def test_core_contract_base_policy_mismatch_is_tagged(self):
        entries = self._required_core_contract_entries()
        base_entries = dict(entries)
        signer = "/".join(subject.SIGNER_PATH_PARTS)
        base_entries[signer] = ("100644", "b" * 40)
        with patch.object(
            subject, "_contract_tree_entries", side_effect=(base_entries, entries),
        ), self.assertRaises(subject.Refusal) as refusal:
            subject._safe_core_contract_tree(
                "repository", "/usr/bin/git", {}, "a" * 40, "b" * 40,
            )
        self.assertEqual(
            (refusal.exception.reason, refusal.exception.stage, refusal.exception.core_check),
            ("bootstrap_snapshot_invalid", "bootstrap", "base_policy"),
        )

    def test_core_checkout_labels_only_core_contract_and_preserves_cleanup_refusal(self):
        failed = subject.subprocess.CompletedProcess(("git",), 1, b"", b"")
        with patch.object(subject, "_run_process", return_value=failed):
            with self.assertRaises(subject.Refusal) as core_refusal:
                subject._checkout_source(
                    Path("/tmp/repository"), "/usr/bin/git", {}, Path("/tmp/lease"),
                    "a" * 40, core_contract=True,
                )
        self.assertEqual(
            (core_refusal.exception.reason, core_refusal.exception.stage, core_refusal.exception.core_check),
            ("bootstrap_snapshot_invalid", "bootstrap", "checkout"),
        )
        with patch.object(subject, "_run_process", return_value=failed):
            with self.assertRaises(subject.Refusal) as other_refusal:
                subject._checkout_source(
                    Path("/tmp/repository"), "/usr/bin/git", {}, Path("/tmp/lease"),
                    "a" * 40,
                )
        self.assertEqual(
            (other_refusal.exception.reason, other_refusal.exception.stage, other_refusal.exception.core_check),
            ("bootstrap_snapshot_invalid", "bootstrap", None),
        )
        cleanup = subject.Refusal("cleanup_incomplete", "cleanup")
        with patch.object(subject, "_run_process", side_effect=cleanup):
            with self.assertRaises(subject.Refusal) as cleanup_refusal:
                subject._checkout_source(
                    Path("/tmp/repository"), "/usr/bin/git", {}, Path("/tmp/lease"),
                    "a" * 40, core_contract=True,
                )
        self.assertEqual(
            (cleanup_refusal.exception.reason, cleanup_refusal.exception.stage, cleanup_refusal.exception.core_check),
            ("cleanup_incomplete", "cleanup", None),
        )

    def test_core_lease_path_and_census_refusals_are_tagged(self):
        with patch.object(subject.os, "walk", side_effect=OSError):
            with self.assertRaises(subject.Refusal) as path_refusal:
                subject._lease_paths(Path("/tmp/lease"), core_contract=True)
        self.assertEqual(
            (path_refusal.exception.reason, path_refusal.exception.stage, path_refusal.exception.core_check),
            ("bootstrap_snapshot_invalid", "bootstrap", "lease_paths"),
        )

        path_type = type(Path("/tmp/lease"))
        file_info = SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)
        with patch.object(subject, "MAX_TEMP_PATHS", 1), \
                patch.object(subject.os, "walk", return_value=[("/tmp/lease", [], ["item"])]) as walk, \
                patch.object(path_type, "lstat", return_value=file_info):
            with self.assertRaises(subject.Refusal) as census_refusal:
                subject._lease_paths(Path("/tmp/lease"), core_contract=True)
        walk.assert_called_once()
        self.assertEqual(
            (census_refusal.exception.reason, census_refusal.exception.stage, census_refusal.exception.core_check),
            ("bootstrap_snapshot_invalid", "bootstrap", "lease_census"),
        )

    def test_core_worker_lease_labels_acl_and_access_checks(self):
        directory = Path("/tmp/lease-directory")
        with patch.object(subject, "capability", SimpleNamespace(USERNAME="worker")), \
                patch.object(subject, "_resolve_trusted_executable", return_value="/bin/chmod"), \
                patch.object(subject, "_lease_paths", return_value=([directory], [])), \
                patch.object(
                    subject, "_run_acl_command",
                    side_effect=subject.Refusal("bootstrap_snapshot_invalid", "bootstrap"),
                ):
            with self.assertRaises(subject.Refusal) as acl_refusal:
                subject._grant_worker_readonly(
                    Path("/tmp/lease"), Path("/tmp/source"), Path("/tmp/storage"), 501,
                    core_contract=True,
                )
        self.assertEqual(
            (acl_refusal.exception.reason, acl_refusal.exception.stage, acl_refusal.exception.core_check),
            ("bootstrap_snapshot_invalid", "bootstrap", "lease_acl"),
        )

        capability = SimpleNamespace(
            USERNAME="worker",
            _resolve_trusted_toolchain=lambda: {"python": "/usr/bin/python3"},
            _run_as_probe_user=lambda *args, **kwargs: SimpleNamespace(
                returncode=1, stdout=b"", stderr=b"",
            ),
        )
        with patch.object(subject, "capability", capability), \
                patch.object(subject, "_resolve_trusted_executable", return_value="/bin/chmod"), \
                patch.object(subject, "_lease_paths", return_value=([], [])), \
                patch.object(Path, "is_file", return_value=True), \
                patch.object(Path, "exists", return_value=False):
            with self.assertRaises(subject.Refusal) as access_refusal:
                subject._grant_worker_readonly(
                    Path("/tmp/lease"), Path("/tmp/source"), Path("/tmp/storage"), 501,
                    core_contract=True,
                )
        self.assertEqual(
            (access_refusal.exception.reason, access_refusal.exception.stage, access_refusal.exception.core_check),
            ("bootstrap_snapshot_invalid", "bootstrap", "lease_access"),
        )

    def test_core_contract_keeps_signer_authority_and_installed_rules_from_base(self):
        signer = "/".join(subject.SIGNER_PATH_PARTS)
        lock = subject.RULES_LOCK_PATH
        base = {
            signer: ("100644", "a" * 40),
            lock: ("100644", "b" * 40),
        }
        self.assertTrue(subject._core_contract_policy_matches_base(base, dict(base)))
        changed_signer = dict(base)
        changed_signer[signer] = ("100644", "c" * 40)
        changed_rules = dict(base)
        changed_rules[lock] = ("100644", "d" * 40)
        added_rules = dict(base)
        added_rules[subject.RULES_DIRECTORY + "/rules/shared/extra.md"] = ("100644", "e" * 40)
        self.assertFalse(subject._core_contract_policy_matches_base(base, changed_signer))
        self.assertFalse(subject._core_contract_policy_matches_base(base, changed_rules))
        self.assertFalse(subject._core_contract_policy_matches_base(base, added_rules))


class CoreContractLeaseTests(unittest.TestCase):
    def test_core_contract_uses_read_only_worker_lease_and_strict_cleanup(self):
        source_sha = "d" * 40
        base_sha = "b" * 40
        control_sha = "c" * 40
        branch = "refs/heads/feat/reviewed-contract"
        request = {
            "source_sha": source_sha,
            "base_sha": base_sha,
            "base_branch": "main",
            "concern": "core-contract",
        }
        binding = {
            "control_sha": control_sha,
            "run_id": "12",
            "run_attempt": "1",
            "image_os": "macos-test",
            "image_version": "1",
        }
        environment = {
            "CI_SHA": control_sha,
            subject.CORE_CONTRACT_SOURCE_GATE_ENV: source_sha,
            subject.CORE_CONTRACT_CONTROL_GATE_ENV: control_sha,
            subject.SOURCE_CANDIDATE_REF_ENV: branch,
        }
        record = {
            "source_sha": source_sha,
            "base_sha": base_sha,
            "base_branch": "main",
            "concern": "core-contract",
            "candidate_class": "signed-descendant",
            "signature": "verified",
            "rules_lock": "present",
            "tree": "core_contract",
            "source_execution": "not_run",
            "app_build": "not_run",
            "cleanup": "lease_open",
        }
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent).resolve()
            storage = Path("/tmp/core-contract-storage")
            temporary = Path("/tmp/core-contract-snapshot")
            source = temporary / "source"
            snapshot = patch.object(subject, "_source_snapshot", return_value=(record, temporary, source))
            worker_grant = patch.object(subject, "_grant_worker_readonly", return_value="/usr/bin/python3")
            worker_absent = patch.object(subject, "_assert_worker_absent")
            with patch.object(subject, "_safe_context", return_value=(binding, root)), \
                    patch.object(subject, "_check_worker_identity"), \
                    patch.object(subject, "_validate_storage_root", return_value=storage), \
                    patch.object(subject, "_add_storage_search_acl") as add_acl, \
                    snapshot as source_snapshot, worker_grant as grant, worker_absent as absent, \
                    patch.object(subject, "_remove_tree") as remove_tree, \
                    patch.object(subject, "_remove_storage_search_acl") as remove_acl:
                with subject.validated_source(
                    request, binding, root, environment, worker_uid=501, storage_root=storage,
                ) as lease:
                    self.assertEqual(lease.record["concern"], "core-contract")
                    self.assertEqual(lease.record["tree"], "core_contract")
                    self.assertEqual(lease.record["worker_access"], "uid_read_only")
                    self.assertEqual(lease.record["token_revocation"], "confirmed_before_yield")
                    self.assertEqual(lease.record["source_execution"], "not_run_at_yield")
                self.assertEqual(add_acl.call_count, 1)
                self.assertEqual(grant.call_count, 1)
                self.assertEqual(absent.call_count, 1)
                self.assertEqual(remove_tree.call_args.args, (temporary,))
                self.assertEqual(remove_acl.call_args.args, (storage,))
                self.assertEqual(source_snapshot.call_args.kwargs["candidate_ref"], branch)
                self.assertTrue(source_snapshot.call_args.kwargs["retain"])
                self.assertEqual(source_snapshot.call_args.kwargs["temp_parent"], storage)


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
            "rules_lock": "not-applicable" if concern == "rules-bootstrap" else "present",
            "tree": {
                "core-bootstrap": "core_administrative",
                "rules-bootstrap": "rules_regular_files",
                "core-contract": "core_contract",
            }[concern],
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

    def test_core_contract_receipt_requires_v2_tree_and_worker_lease(self):
        binding = {
            "control_sha": "c" * 40,
            "run_id": "12",
            "run_attempt": "1",
            "image_os": "macos-test",
            "image_version": "1",
        }
        record = self._record("core-contract")
        record["candidate_class"] = "signed-descendant"
        record["source_sha"] = "d" * 40
        line = subject._format_success(record, binding)
        self.assertIn("concern=core-contract", line.split())
        self.assertIn("rules-lock=present", line.split())
        self.assertIn("source-execution=not-run", line.split())

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
