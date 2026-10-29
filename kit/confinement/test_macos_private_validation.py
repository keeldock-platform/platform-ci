import base64
import datetime
import hashlib
import stat
import tempfile
import unittest
from contextlib import ExitStack, nullcontext
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from unittest.mock import patch

import macos_private_validation as subject
import feedback_request as feedback_requests


def _ssh_key_blob(start=0):
    algorithm = b"ssh-ed25519"
    public_key = bytes((start + offset) % 256 for offset in range(32))
    return len(algorithm).to_bytes(4, "big") + algorithm + len(public_key).to_bytes(4, "big") + public_key


class _FakeStat:
    def __init__(self, mode, uid, gid, device, inode, size=0, links=1):
        self.st_mode = mode
        self.st_uid = uid
        self.st_gid = gid
        self.st_dev = device
        self.st_ino = inode
        self.st_size = size
        self.st_nlink = links
        self.st_mtime_ns = 10
        self.st_ctime_ns = 11


class _InventoryHarness:
    def __init__(self, root, runner_temp, contents, blob=None):
        self.root = root
        self.runner_temp = runner_temp
        self.contents = contents
        self.blob = contents if blob is None else blob
        self.runner_uid = 501
        self.runner = _FakeStat(stat.S_IFDIR | 0o700, self.runner_uid, 20, 1, 4, links=2)
        self.root_info = _FakeStat(stat.S_IFDIR | 0o755, self.runner_uid, 20, 1, 1, links=2)
        self.ci_info = _FakeStat(stat.S_IFDIR | 0o755, self.runner_uid, 20, 1, 2, links=2)
        self.inventory_info = _FakeStat(
            stat.S_IFREG | 0o644, self.runner_uid, 20, 1, 3, len(contents),
        )
        self.swap_ci = False
        self.fchown_calls = []
        self.closed = []
        self.offset = 0
        self.fail_inventory_chown = False
        self.fail_inventory_restore = False
        self.original_stat = subject.os.stat
        self.original_path_lstat = Path.lstat

    def open(self, path, flags, mode=0o777, *, dir_fd=None):
        if dir_fd is None and Path(path) == self.root:
            return 10
        if dir_fd == 10 and path == "ci":
            return 11
        if dir_fd == 11 and path == "revoked-signer-fingerprints":
            return 12
        raise OSError

    def stat(self, path, *, dir_fd=None, follow_symlinks=True):
        if dir_fd == 10 and path == "ci":
            if self.swap_ci:
                return _FakeStat(stat.S_IFDIR | 0o755, 0, 0, 1, 20, links=2)
            return self.ci_info
        if dir_fd == 11 and path == "revoked-signer-fingerprints":
            return self.inventory_info
        if Path(path) == self.root:
            return self.root_info
        if Path(path) == self.runner_temp:
            return self.runner
        return self.original_stat(path, follow_symlinks=follow_symlinks)

    def path_lstat(self, path):
        if path == self.root:
            return self.root_info
        if path == self.runner_temp:
            return self.runner
        return self.original_path_lstat(path)

    def fstat(self, descriptor):
        return {10: self.root_info, 11: self.ci_info, 12: self.inventory_info}[descriptor]

    def read(self, descriptor, size):
        if descriptor != 12:
            raise OSError
        payload = self.contents[self.offset:self.offset + size]
        self.offset += len(payload)
        return payload

    def lseek(self, descriptor, offset, whence):
        if descriptor != 12 or offset != 0:
            raise OSError
        self.offset = 0
        return 0

    def fchown(self, descriptor, uid, gid):
        self.fchown_calls.append((descriptor, uid, gid))
        if descriptor == 12 and uid != self.runner_uid and self.fail_inventory_chown:
            self.fail_inventory_chown = False
            raise OSError
        if descriptor == 12 and uid == self.runner_uid and self.fail_inventory_restore:
            raise OSError
        info = self.fstat(descriptor)
        info.st_uid = uid
        info.st_gid = gid
        info.st_ctime_ns += 1

    def close(self, descriptor):
        self.closed.append(descriptor)

    def process(self, argv, **kwargs):
        if "ls-tree" in argv:
            digest = hashlib.sha1(self.blob).hexdigest().encode("ascii")
            output = b"100644 blob " + digest + b"\t" + subject.REVOCATION_INVENTORY.encode("ascii") + b"\x00"
        else:
            output = self.blob
        return subject.subprocess.CompletedProcess(argv, 0, output, b"")

    def patches(self):
        stack = ExitStack()
        for name, replacement in (
            ("open", self.open), ("stat", self.stat), ("fstat", self.fstat),
            ("read", self.read), ("lseek", self.lseek), ("fchown", self.fchown),
            ("close", self.close),
        ):
            stack.enter_context(patch.object(subject.os, name, replacement, create=True))
        stack.enter_context(patch.object(
            subject.os, "supports_dir_fd", {self.open, self.stat}, create=True,
        ))
        stack.enter_context(patch.object(
            subject.os, "supports_follow_symlinks", {self.stat}, create=True,
        ))
        stack.enter_context(patch.object(Path, "lstat", lambda path: self.path_lstat(path)))
        stack.enter_context(patch.object(subject.os, "O_NOFOLLOW", 0x100, create=True))
        stack.enter_context(patch.object(subject.os, "O_DIRECTORY", 0x10000, create=True))
        stack.enter_context(patch.object(subject, "_resolve_trusted_executable", return_value="/usr/bin/git"))
        stack.enter_context(patch.object(subject, "_base_git_environment", return_value={}))
        stack.enter_context(patch.object(subject, "_run_process", side_effect=self.process))
        return stack


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

    def test_feedback_return_requests_match_the_closed_profile_table(self):
        self.assertEqual(
            subject.FEEDBACK_PROFILE_CONCERNS,
            frozenset(profile["concern"] for profile in feedback_requests.PROFILES.values()),
        )
        for concern in sorted(subject.FEEDBACK_PROFILE_CONCERNS):
            with self.subTest(concern=concern):
                request = subject.parse_request((
                    "--source-sha", "a" * 40,
                    "--base-sha", "b" * 40,
                    "--base-branch", "main",
                    "--concern", concern,
                ))
                self.assertEqual(request["concern"], concern)
        with self.assertRaises(subject.Refusal):
            subject.parse_request((
                "--source-sha", "a" * 40,
                "--base-sha", "b" * 40,
                "--base-branch", "main",
                "--concern", "core-feedback-return",
            ))

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

    def test_every_core_feedback_profile_requires_its_own_exact_protected_shas(self):
        environment = {
            "CI_SHA": "c" * 40,
            subject.CORE_CONTRACT_SOURCE_GATE_ENV: "a" * 40,
            subject.CORE_CONTRACT_CONTROL_GATE_ENV: "c" * 40,
        }
        for concern in sorted(subject.CORE_CONTRACT_CONCERNS):
            request = {
                "source_sha": "a" * 40,
                "base_sha": "b" * 40,
                "base_branch": "main",
                "concern": concern,
            }
            with self.subTest(concern=concern):
                subject._check_core_contract_gate(request, environment)
                for key, value in (
                    (subject.CORE_CONTRACT_SOURCE_GATE_ENV, "d" * 40),
                    (subject.CORE_CONTRACT_CONTROL_GATE_ENV, "d" * 40),
                    ("CI_SHA", "invalid"),
                ):
                    changed = dict(environment, **{key: value})
                    with self.subTest(key=key), self.assertRaises(subject.Refusal) as result:
                        subject._check_core_contract_gate(request, changed)
                    self.assertEqual(
                        (result.exception.reason, result.exception.stage),
                        ("bootstrap_not_approved", "configuration"),
                    )

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
        for concern in sorted(subject.CORE_CONTRACT_CONCERNS):
            request = {
                "source_sha": "a" * 40,
                "base_sha": "b" * 40,
                "base_branch": "main",
                "concern": concern,
            }
            with self.subTest(concern=concern):
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


CRATE_MANIFEST = (
    chr(35) + " Synthetic crate manifest.\n"
    "[package]\n"
    "name = \"synthetic-crate\"\n"
    "description = \"Synthetic crate: used only by the tree tests.\"\n"
    "version.workspace = true\n"
    "edition.workspace = true\n"
    "rust-version.workspace = true\n"
    "publish.workspace = true\n"
    "\n"
    "[dependencies]\n"
    "keeldock" "-host-api = { workspace = true }\n"
    "\n"
    "[dev-dependencies]\n"
    "keeldock" "-host-mock = { workspace = true }\n"
    "\n"
    "[lints]\n"
    "workspace = true\n"
)


class CoreContractTreeTests(unittest.TestCase):
    @staticmethod
    def _module_lines(names):
        declarations = "".join(
            chr(35) + '[path = "../fuzz_targets/' + name + '.rs"]\nmod ' + name + ';\n'
            for name in sorted(names)
        )
        references = "fn replay() {\n" + "".join(
            "    let _ = " + name + "::fuzz;\n" for name in sorted(names)
        ) + "}\n"
        return (declarations + references).encode("ascii")

    @staticmethod
    def _validate_feedback_tree(
        entries, concern, main_payload=None, workspace_text=None, lock_text=None, manifest_text=None,
    ):
        digest = hashlib.sha256(b"x").hexdigest()

        def blob(unused_repository, unused_git, unused_environment, unused_entries, path, **unused):
            if path.startswith("crates/") and path.endswith("/Cargo.toml"):
                return (manifest_text or CRATE_MANIFEST).encode("utf-8")
            if path == "Cargo.toml":
                if workspace_text is not None:
                    return workspace_text.encode("utf-8")
                members = ", ".join('"' + "/".join(root) + '"'
                                     for root in subject.CORE_CONTRACT_CRATE_ROOTS)
                return ("[workspace]\nmembers = [" + members + "]\n").encode("utf-8")
            if path == "Cargo.lock":
                if lock_text is not None:
                    return lock_text.encode("ascii")
                return ("version = 4\n" + "[[package]]\n" * len(subject.CORE_CONTRACT_CRATE_ROOTS)).encode("ascii")
            if path == "rust-toolchain.toml":
                return subject.CORE_CONTRACT_TOOLCHAIN
            if path == "fuzz/src/main.rs":
                return main_payload if main_payload is not None else CoreContractTreeTests._module_lines(
                    subject.CORE_CONTRACT_FUZZ_CORPUS_TARGETS,
                )
            return b"x"

        with patch.object(
            subject, "_contract_tree_entries", side_effect=(dict(entries), entries),
        ), patch.object(subject, "_contract_blob", side_effect=blob) as blob, \
                patch.object(subject, "_contract_blob_size", return_value=1), \
                patch.object(subject, "_feedback_corpus_shape", return_value=True), \
                patch.object(subject, "_feedback_manifest_shape", return_value=True), \
                patch.object(subject, "_feedback_fuzz_manifest_shape", return_value=True), \
                patch.object(subject, "_core_contract_policy_matches_base", return_value=True), \
                patch.object(subject, "_rules_v2_file_manifest", return_value={"AGENTS.md": digest}):
            marker = subject._safe_core_contract_tree(
                "repository", "/usr/bin/git", {}, "a" * 40, "b" * 40,
                concern=concern,
            )
        return marker, blob

    def test_core_contract_path_scope_is_limited_to_workspace_and_four_crates(self):
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

    def test_feedback_tree_allows_reviewed_typescript_patterns_and_fixed_configs(self):
        for path in subject.CORE_CONTRACT_FEEDBACK_FILES:
            with self.subTest(path=path):
                self.assertIsNone(subject._core_contract_expected_mode(path))
                for concern in subject.FEEDBACK_PROFILE_CONCERNS:
                    self.assertEqual(
                        subject._core_contract_expected_mode(path, concern=concern), "100644",
                    )
        for path in (
            "packages/host-api/src/new-module.ts",
            "packages/host-api/tests/new-test.test.ts",
        ):
            with self.subTest(path=path):
                self.assertIsNone(subject._core_contract_expected_mode(path))
                for concern in subject.FEEDBACK_PROFILE_CONCERNS:
                    self.assertEqual(
                        subject._core_contract_expected_mode(path, concern=concern), "100644",
                    )
        for path in (
            "packages/host-api/src/New-module.ts",
            "packages/host-api/src/nested/new-module.ts",
            "packages/host-api/src/new-module.js",
            "packages/host-api/src/new-module.mjs",
            "packages/host-api/src/new-module.cjs",
            "packages/host-api/src/.hidden.ts",
            "packages/host-api/src/" + "a" * (subject.MAX_CORE_CONTRACT_NAME_LENGTH + 1) + ".ts",
            "packages/host-api/src/vite.config.ts",
            "packages/host-api/src/vitest.config.ts",
            "packages/host-api/src/tsconfig.json",
            "packages/host-api/src/eslint.config.js",
            "packages/host-api/src/package.json",
            "packages/host-api/tests/New-test.test.ts",
            "packages/host-api/tests/nested/new-test.test.ts",
            "packages/host-api/tests/" + "a" * (subject.MAX_CORE_CONTRACT_NAME_LENGTH + 1) + ".test.ts",
            "packages/host-api/tests/new-test.test.js",
            "packages/host-api/build.rs",
            "packages/other/package.json",
        ):
            with self.subTest(path=path):
                for concern in subject.FEEDBACK_PROFILE_CONCERNS:
                    self.assertIsNone(subject._core_contract_expected_mode(path, concern=concern))

    @staticmethod
    def _workspace_text(members, trailing_comma=True):
        lines = ",\n".join('    "' + member + '"' for member in members)
        return (
            '[workspace]\nresolver = "3"\nmembers = [\n' + lines
            + (",\n" if trailing_comma else "\n") + ']\nexclude = [\n    "apps",\n]\n'
        )

    def _refused_check(self, entries, concern, **overrides):
        with self.assertRaises(subject.Refusal) as refusal:
            self._validate_feedback_tree(entries, concern, **overrides)
        self.assertEqual(refusal.exception.reason, "bootstrap_snapshot_invalid")
        return refusal.exception.core_check

    def test_workspace_members_are_the_four_exact_paths(self):
        members = [
            "crates/host/api", "crates/host/mock", "crates/host/conformance", "crates/kernel/i18n",
        ]
        self.assertEqual(
            ["/".join(root) for root in subject.CORE_CONTRACT_CRATE_ROOTS], members,
        )
        for trailing_comma in (True, False):
            with self.subTest(trailing_comma=trailing_comma):
                self.assertEqual(
                    subject._core_contract_workspace_members(
                        self._workspace_text(members, trailing_comma=trailing_comma),
                    ),
                    members,
                )
        self.assertEqual(
            subject._core_contract_workspace_members(
                "[workspace]\nmembers = [" + ", ".join('"' + item + '"' for item in members) + "]\n",
            ),
            members,
        )
        for rejected in (
            "[workspace]\n",
            "[workspace]\nmembers = []\n",
            "[workspace]\nmembers = [\n    \"crates/host/api\" \"crates/host/mock\",\n]\n",
            "[workspace]\nmembers = [\n    \"crates/host/api\",,\n]\n",
            "[workspace]\nmembers = [\n    crates/host/api,\n]\n",
            "[workspace]\nmembers = [\n    \"crates/host/api\", " + chr(35) + " note\n]\n",
            self._workspace_text(members) + 'members = [\n    "crates/host/api",\n]\n',
        ):
            with self.subTest(rejected=rejected):
                self.assertNotEqual(subject._core_contract_workspace_members(rejected), members)

    def test_four_member_multiline_workspace_is_admitted(self):
        concern = "core-rust-format-return"
        entries = self._required_core_contract_entries(concern)
        members = ["/".join(root) for root in subject.CORE_CONTRACT_CRATE_ROOTS]
        marker, unused_blob = self._validate_feedback_tree(
            entries, concern, workspace_text=self._workspace_text(members),
        )
        self.assertEqual(marker, subject.CORE_CONTRACT_TREE_BY_CONCERN[concern])

    def test_workspace_with_a_fifth_missing_reordered_or_glob_member_is_refused(self):
        concern = "core-rust-format-return"
        entries = self._required_core_contract_entries(concern)
        members = ["/".join(root) for root in subject.CORE_CONTRACT_CRATE_ROOTS]
        for changed in (
            members + ["crates/kernel/extra"],
            members[:-1],
            list(reversed(members)),
            members + [members[0]],
            members[:-1] + ["crates/kernel/*"],
            members[:-1] + ["crates/kernel/i18n/../i18n"],
        ):
            with self.subTest(members=changed):
                self.assertEqual(
                    self._refused_check(
                        entries, concern, workspace_text=self._workspace_text(changed),
                    ),
                    "workspace_members",
                )

    def test_lock_with_a_fifth_package_or_a_registry_source_is_refused(self):
        concern = "core-rust-format-return"
        entries = self._required_core_contract_entries(concern)
        count = len(subject.CORE_CONTRACT_CRATE_ROOTS)
        registry = 'source = "registry+crates"\n'
        for lock_text in (
            "version = 4\n" + "[[package]]\n" * (count + 1),
            "version = 4\n" + "[[package]]\n" * (count - 1),
            "version = 4\n" + "[[package]]\n" * count + registry,
            "version = 4\n" + "[[package]]\n" * (count - 1) + "[[package]]\n" + registry,
            "version = 3\n" + "[[package]]\n" * count,
        ):
            with self.subTest(lock=lock_text):
                self.assertEqual(
                    self._refused_check(entries, concern, lock_text=lock_text),
                    "cargo_lock_shape",
                )
        marker, unused_blob = self._validate_feedback_tree(
            entries, concern, lock_text="version = 4\n" + "[[package]]\n" * count,
        )
        self.assertEqual(marker, subject.CORE_CONTRACT_TREE_BY_CONCERN[concern])

    def test_kernel_paths_are_admitted_only_for_feedback_concerns_by_exact_rule(self):
        for path in (
            "crates/kernel/i18n/Cargo.toml",
            "crates/kernel/i18n/src/lib.rs",
            "crates/kernel/i18n/src/pattern/parser.rs",
            "crates/kernel/i18n/tests/i18n_conformance/faults.rs",
        ):
            with self.subTest(path=path):
                self.assertEqual(subject._core_contract_expected_mode(path), "100644")
        for path in (
            "crates/kernel/i18n/src/cldr46_cardinal_rules.md",
            "crates/host/api/tests/fixtures/i18n-v1.jsonl",
            "crates/host/api/tests/fixtures/i18n-regression-v1.jsonl",
            "packages/kernel-i18n/CHANGELOG.md",
            "packages/kernel-i18n/CONTRACT.md",
            "packages/kernel-i18n/README.md",
            "packages/kernel-i18n/package.json",
            "packages/kernel-i18n/tsconfig.json",
            "packages/kernel-i18n/data/cldr46_cardinal_rules.md",
            "packages/kernel-i18n/tests/support.ts",
            "packages/kernel-i18n/src/catalogue.ts",
            "packages/kernel-i18n/tests/catalogue-vectors.test.ts",
        ):
            with self.subTest(path=path):
                self.assertTrue(subject._core_contract_foundation_path(path))
                self.assertIsNone(subject._core_contract_expected_mode(path))
                for concern in subject.FEEDBACK_PROFILE_CONCERNS:
                    self.assertEqual(
                        subject._core_contract_expected_mode(path, concern=concern), "100644",
                    )

    def test_paths_outside_the_kernel_allowlist_are_refused(self):
        for path in (
            "crates/kernel/Cargo.toml",
            "crates/kernel/core/src/lib.rs",
            "crates/kernel/i18n/build.rs",
            "crates/kernel/i18n/src/build.rs",
            "crates/kernel/i18n/src/other.md",
            "crates/kernel/i18n/src/nested/data.json",
            "crates/kernel/i18n/data/cldr46_cardinal_rules.md",
            "crates/host/api/tests/fixtures/other.jsonl",
            "crates/host/api/tests/fixtures/i18n-v1.json",
            "crates/host/api/tests/fixtures/nested/i18n-v1.jsonl",
            "crates/host/mock/tests/fixtures/i18n-v1.jsonl",
            "packages/kernel-i18n/package-lock.json",
            "packages/kernel-i18n/vite.config.ts",
            "packages/kernel-i18n/data/other.md",
            "packages/kernel-i18n/src/Key.ts",
            "packages/kernel-i18n/src/key.js",
            "packages/kernel-i18n/src/nested/key.ts",
            "packages/kernel-i18n/tests/other.ts",
            "packages/kernel-i18n/tests/nested/key.test.ts",
            "packages/kernel-other/package.json",
            "packages/kernel-i18n-extra/src/key.ts",
            "packages/.hidden/package.json",
            "packages/kernel-i18n/.hidden.ts",
            "packages/kernel-i18n/src/.hidden.ts",
            "packages/kernel-i18n/tests/.hidden.test.ts",
            "packages/Kernel-I18n/src/key.ts",
            "packages/KERNEL-I18N/package.json",
            "packages/Host-Api/src/ids.ts",
            "packages/kernel-i18n/src/Key.ts",
            "packages/kernel-i18n/Package.json",
        ):
            with self.subTest(path=path):
                self.assertFalse(subject._core_contract_foundation_path(path))
                for concern in subject.CORE_CONTRACT_CONCERNS:
                    self.assertIsNone(subject._core_contract_expected_mode(path, concern=concern))

    def test_kernel_package_lock_follows_the_existing_root_lock_rule(self):
        path = subject.CORE_CONTRACT_PACKAGE_LOCK_PATH
        for concern in subject.CORE_CONTRACT_CONCERNS:
            with self.subTest(concern=concern):
                expected = "100644" if concern in (
                    "core-build-diagnostic-return", "core-rust-format-return",
                ) else None
                self.assertEqual(
                    subject._core_contract_expected_mode(path, concern=concern), expected,
                )

    def test_root_package_lock_is_admitted_for_build_diagnostic_and_format_return_only(self):
        path = subject.CORE_CONTRACT_PACKAGE_LOCK_PATH
        self.assertIsNone(subject._core_contract_expected_mode(path))
        self.assertIsNone(subject._core_contract_expected_mode(
            path, concern="core-node-lock-return",
        ))
        for concern in ("core-rust-format-return", "core-build-diagnostic-return"):
            with self.subTest(concern=concern):
                self.assertEqual(
                    subject._core_contract_expected_mode(path, concern=concern), "100644",
                )
                self.assertIsNone(subject._core_contract_expected_mode(
                    "Package-lock.json", concern=concern,
                ))

    @staticmethod
    def _four_crate_entries(concern):
        entries = CoreContractTreeTests._required_core_contract_entries(concern)
        extra = set(subject.CORE_CONTRACT_KERNEL_FEEDBACK_FILES) | {
            "crates/kernel/i18n/src/pattern/parser.rs",
            "crates/kernel/i18n/tests/message_keys.rs",
            "packages/kernel-i18n/src/index.ts",
            "packages/kernel-i18n/src/key.ts",
            "packages/kernel-i18n/tests/key.test.ts",
            subject.CORE_CONTRACT_PACKAGE_LOCK_PATH,
        }
        entries.update({path: ("100644", "a" * 40) for path in extra})
        return entries

    def test_four_crate_two_package_tree_is_admitted_by_format_return_and_diagnostics(self):
        for concern, tree in (
            ("core-rust-format-return", "core_rust_format_return"),
            ("core-build-diagnostic-return", subject.CORE_CONTRACT_PACKAGE_LOCK_TREE),
        ):
            with self.subTest(concern=concern):
                entries = self._four_crate_entries(concern)
                members = ["/".join(root) for root in subject.CORE_CONTRACT_CRATE_ROOTS]
                marker, blob = self._validate_feedback_tree(
                    entries, concern, workspace_text=self._workspace_text(members),
                )
                self.assertEqual(marker, tree)
                lock_calls = [
                    call for call in blob.call_args_list
                    if call.args[4] == subject.CORE_CONTRACT_PACKAGE_LOCK_PATH
                ]
                self.assertEqual(len(lock_calls), 1)
                self.assertEqual(lock_calls[0].kwargs["max_bytes"], subject.MAX_FEEDBACK_LOCK_BYTES)

    def test_package_lock_is_refused_for_node_lock_return_and_non_regular_modes(self):
        entries = self._four_crate_entries("core-node-lock-return")
        self.assertEqual(self._refused_check(entries, "core-node-lock-return"), "path_mode")
        for concern in ("core-rust-format-return", "core-build-diagnostic-return"):
            changed = self._four_crate_entries(concern)
            changed[subject.CORE_CONTRACT_PACKAGE_LOCK_PATH] = ("100755", "a" * 40)
            with self.subTest(concern=concern):
                self.assertEqual(self._refused_check(changed, concern), "path_mode")

    def test_format_return_refuses_a_package_lock_without_the_foundation_files(self):
        concern = "core-rust-format-return"
        entries = {
            path: entry for path, entry in self._required_core_contract_entries(concern).items()
            if not subject._core_contract_foundation_path(path)
        }
        entries[subject.CORE_CONTRACT_PACKAGE_LOCK_PATH] = ("100644", "a" * 40)
        with patch.object(
            subject, "_contract_tree_entries", side_effect=(dict(entries), entries),
        ), self.assertRaises(subject.Refusal) as refusal:
            subject._safe_core_contract_tree(
                "repository", "/usr/bin/git", {}, "a" * 40, "b" * 40, concern=concern,
            )
        self.assertEqual(refusal.exception.core_check, "required_files")

    def test_crate_manifest_shape_admits_only_the_sections_and_keys_in_use(self):
        self.assertTrue(subject._core_contract_crate_manifest_shape(CRATE_MANIFEST))
        minimal = (
            '[package]\nname = "synthetic-crate"\n\n[dependencies]\n\n[lints]\nworkspace = true\n'
        )
        self.assertTrue(subject._core_contract_crate_manifest_shape(minimal))

    def test_crate_manifest_shape_refuses_every_build_bypass_form(self):
        header = '[package]\nname = "synthetic-crate"\n'
        for name, text in (
            ("plain", header + 'build = "build.rs"\n'),
            ("quoted key", header + '"build" = "build.rs"\n'),
            ("quoted dotted key", header + '"package"."build" = "build.rs"\n'),
            ("single quoted key", header + "'build' = 'build.rs'\n"),
            ("disabled", header + "build = false\n"),
            ("inline package table", 'package = { name = "synthetic-crate", build = "build.rs" }\n'),
            ("dotted package key", 'package.build = "build.rs"\n' + header),
            ("spaced key", header + 'build   =   "build.rs"\n'),
            ("build dependencies", header + '[build-dependencies]\nkeeldock' '-host-api = { workspace = true }\n'),
            ("trailing comment", header + 'build = "b.rs" ' + chr(35) + " note\n"),
        ):
            with self.subTest(form=name):
                self.assertFalse(subject._core_contract_crate_manifest_shape(text))

    def test_crate_manifest_shape_refuses_proc_macro_lib_paths_and_path_dependencies(self):
        header = '[package]\nname = "synthetic-crate"\n'
        for name, text in (
            ("proc macro", header + "[lib]\nproc-macro = true\n"),
            ("lib path outside", header + '[lib]\npath = "../outside/lib.rs"\n'),
            ("lib path inside", header + '[lib]\npath = "src/lib.rs"\n'),
            ("bin section", header + '[[bin]]\nname = "tool"\npath = "src/main.rs"\n'),
            ("test section", header + '[[test]]\nname = "contract"\npath = "tests/main.rs"\n'),
            ("path dependency", header + '[dependencies]\nevil = { path = "../evil" }\n'),
            ("member name with path", header + '[dependencies]\nkeeldock' '-host-api = { path = "../x" }\n'),
            ("workspace and path", header + '[dependencies]\nkeeldock' '-host-api = { workspace = true, path = "../x" }\n'),
            ("dev dependency path", header + '[dev-dependencies]\nkeeldock' '-host-mock = { path = "../x" }\n'),
            ("dotted dependency path", header + '[dependencies]\nkeeldock' '-host-api.path = "../x"\n'),
            ("version dependency", header + '[dependencies]\nkeeldock' '-host-api = "1.0.0"\n'),
            ("unknown dependency", header + '[dependencies]\nserde = { workspace = true }\n'),
            ("target table", header + "[target.'cfg(unix)'.dependencies]\n"),
            ("package metadata", header + "[package.metadata]\n"),
            ("workspace section", header + "[workspace]\n"),
            ("patch section", header + '[patch.crates-io]\nserde = { path = "../x" }\n'),
            ("features", header + "[features]\n"),
            ("links key", header + 'links = "native"\n'),
            ("autobins key", header + "autobins = true\n"),
            ("literal version", header + 'version = "1.0.0"\n'),
            ("inherited false", header + "version.workspace = false\n"),
            ("duplicate section", header + header),
            ("duplicate key", header + 'name = "other"\n'),
            ("key before section", 'name = "synthetic-crate"\n' + header),
            ("continuation line", header + 'description = "first\n  second"\n'),
            ("array value", header + 'name = ["synthetic-crate"]\n'),
            ("description escape", header + 'description = "a\\"b"\n'),
            ("carriage return", header.replace("\n", "\r\n")),
            ("missing package", "[dependencies]\n"),
            ("missing name", "[package]\nversion.workspace = true\n"),
            ("empty", ""),
        ):
            with self.subTest(form=name):
                self.assertFalse(subject._core_contract_crate_manifest_shape(text))

    def test_tree_refuses_each_crate_manifest_bypass_with_a_tagged_check(self):
        concern = "core-rust-format-return"
        entries = self._required_core_contract_entries(concern)
        header = '[package]\nname = "synthetic-crate"\n'
        for text, check in (
            (header + 'build = "build.rs"\n', "package_build"),
            (header + '"build" = "build.rs"\n', "package_build"),
            ('package = { name = "x", build = "build.rs" }\n', "package_build"),
            (header + "[lib]\nproc-macro = true\n", "package_decode"),
            (header + '[lib]\npath = "../outside/lib.rs"\n', "package_decode"),
            (header + '[dependencies]\nevil = { path = "../evil" }\n', "package_decode"),
            (header + '[[test]]\nname = "contract"\n', "package_decode"),
        ):
            with self.subTest(text=text):
                self.assertEqual(
                    self._refused_check(entries, concern, manifest_text=text), check,
                )

    def test_workspace_paths_shape_admits_only_the_two_member_path_dependencies(self):
        members = ["/".join(root) for root in subject.CORE_CONTRACT_CRATE_ROOTS]
        base = self._workspace_text(members)
        allowed = (
            "[workspace.package]\nversion = \"0.1.0\"\n\n[workspace.dependencies]\n"
            'keeldock' '-host-api = { path = "crates/host/api" }\n'
            'keeldock' '-host-mock = { path = "crates/host/mock" }\n\n'
            "[workspace.lints.rust]\nunsafe_code = \"forbid\"\n"
        )
        self.assertTrue(subject._core_contract_workspace_paths_shape(base))
        self.assertTrue(subject._core_contract_workspace_paths_shape(base + allowed))
        for name, extra in (
            ("outside path", '[workspace.dependencies]\nevil = { path = "../evil" }\n'),
            ("member name wrong path", '[workspace.dependencies]\nkeeldock' '-host-api = { path = "crates/host/mock" }\n'),
            ("member name outside path", '[workspace.dependencies]\nkeeldock' '-host-api = { path = "../api" }\n'),
            ("duplicate", '[workspace.dependencies]\nkeeldock' '-host-api = { path = "crates/host/api" }\nkeeldock' '-host-api = { path = "crates/host/api" }\n'),
            ("quoted key", '[workspace.dependencies]\n"evil" = { "path" = "../evil" }\n'),
            ("dotted key", '[workspace.dependencies]\nevil.path = "../evil"\n'),
            ("dependency table", '[workspace.dependencies.evil]\npath = "../evil"\n'),
            ("patch", '[patch.crates-io]\nevil = { path = "../evil" }\n'),
            ("replace", '[replace]\n"evil:1.0.0" = { path = "../evil" }\n'),
            ("dependencies", '[dependencies]\nevil = { path = "../evil" }\n'),
            ("array section", '[[bin]]\nname = "tool"\n'),
        ):
            with self.subTest(form=name):
                self.assertFalse(subject._core_contract_workspace_paths_shape(base + extra))
                self.assertEqual(
                    self._refused_check(
                        self._required_core_contract_entries("core-rust-format-return"),
                        "core-rust-format-return", workspace_text=base + extra,
                    ),
                    "workspace_members",
                )

    def test_build_diagnostic_tree_marker_distinguishes_optional_root_lock(self):
        concern = "core-build-diagnostic-return"
        entries = self._required_core_contract_entries(concern)
        marker, blob = self._validate_feedback_tree(entries, concern)
        self.assertEqual(marker, subject.CORE_CONTRACT_TREE_BY_CONCERN[concern])
        self.assertFalse(any(
            call.args[4] == subject.CORE_CONTRACT_PACKAGE_LOCK_PATH
            for call in blob.call_args_list
        ))

        with_lock = dict(entries)
        with_lock[subject.CORE_CONTRACT_PACKAGE_LOCK_PATH] = ("100644", "b" * 40)
        marker, blob = self._validate_feedback_tree(with_lock, concern)
        self.assertEqual(marker, subject.CORE_CONTRACT_PACKAGE_LOCK_TREE)
        lock_calls = [
            call for call in blob.call_args_list
            if call.args[4] == subject.CORE_CONTRACT_PACKAGE_LOCK_PATH
        ]
        self.assertEqual(len(lock_calls), 1)
        self.assertEqual(lock_calls[0].kwargs["max_bytes"], subject.MAX_FEEDBACK_LOCK_BYTES)

    def test_node_lock_bootstrap_tree_keeps_source_lock_optional(self):
        concern = "core-node-lock-return"
        entries = self._required_core_contract_entries(concern)
        marker, blob = self._validate_feedback_tree(entries, concern)
        self.assertEqual(marker, subject.CORE_CONTRACT_TREE_BY_CONCERN[concern])
        self.assertNotIn(subject.CORE_CONTRACT_PACKAGE_LOCK_PATH, entries)
        self.assertFalse(any(
            call.args[4] == subject.CORE_CONTRACT_PACKAGE_LOCK_PATH
            for call in blob.call_args_list
        ))

    def test_build_diagnostic_root_lock_requires_full_foundation_and_regular_mode(self):
        concern = "core-build-diagnostic-return"
        root_lock = subject.CORE_CONTRACT_PACKAGE_LOCK_PATH
        entries = self._required_core_contract_entries(concern)
        entries[root_lock] = ("100644", "b" * 40)
        self.assertEqual(
            self._validate_feedback_tree(entries, concern)[0],
            subject.CORE_CONTRACT_PACKAGE_LOCK_TREE,
        )

        no_foundation = {
            path: entry for path, entry in entries.items()
            if not subject._core_contract_foundation_path(path)
        }
        no_foundation[root_lock] = ("100644", "b" * 40)
        with patch.object(
            subject, "_contract_tree_entries", side_effect=(dict(no_foundation), no_foundation),
        ), patch.object(subject, "_contract_blob") as blob, self.assertRaises(subject.Refusal) as refusal:
            subject._safe_core_contract_tree(
                "repository", "/usr/bin/git", {}, "a" * 40, "b" * 40,
                concern=concern,
            )
        blob.assert_not_called()
        self.assertEqual(refusal.exception.core_check, "required_files")

        for invalid_mode in ("100755", "120000"):
            wrong_mode = dict(entries)
            wrong_mode[root_lock] = (invalid_mode, "b" * 40)
            digest = hashlib.sha256(b"x").hexdigest()

            def blob_payload(unused_repository, unused_git, unused_environment,
                             unused_entries, path, **unused):
                if path == "fuzz/src/main.rs":
                    return self._module_lines(subject.CORE_CONTRACT_FUZZ_CORPUS_TARGETS)
                return b"x"

            with self.subTest(mode=invalid_mode), patch.object(
                subject, "_contract_tree_entries", side_effect=(dict(wrong_mode), wrong_mode),
            ), patch.object(subject, "_contract_blob", side_effect=blob_payload) as blob, \
                    patch.object(subject, "_feedback_corpus_shape", return_value=True), \
                    patch.object(subject, "_feedback_manifest_shape", return_value=True), \
                    patch.object(subject, "_feedback_fuzz_manifest_shape", return_value=True), \
                    patch.object(subject, "_core_contract_policy_matches_base", return_value=True), \
                    patch.object(subject, "_rules_v2_file_manifest", return_value={"AGENTS.md": digest}), \
                    self.assertRaises(subject.Refusal) as refusal:
                subject._safe_core_contract_tree(
                    "repository", "/usr/bin/git", {}, "a" * 40, "b" * 40,
                    concern=concern,
                )
            self.assertEqual(refusal.exception.core_check, "path_mode")
            self.assertFalse(any(
                call.args[4] == root_lock for call in blob.call_args_list
            ))

    def test_feedback_foundation_allows_numbered_adrs_and_snake_fuzz_targets(self):
        fixed_paths = set(subject.CORE_CONTRACT_FOUNDATION_FILES)
        fixed_paths.update((
            "docs/adr/0004-reviewed-decisions.md",
            "fuzz/fuzz_targets/new_target.rs",
            "fuzz/corpus/identifiers/valid-seed",
            "fuzz/corpus/tool_error_codes/valid-seed",
            "fuzz/corpus/versions/valid-seed",
        ))
        for path in fixed_paths:
            with self.subTest(path=path):
                for concern in subject.FEEDBACK_PROFILE_CONCERNS:
                    self.assertEqual(
                        subject._core_contract_expected_mode(path, concern=concern), "100644",
                    )
        for path in (
            "docs/adr/004-reviewed-decisions.md",
            "docs/adr/00004-reviewed-decisions.md",
            "docs/adr/0004-Reviewed-decisions.md",
            "docs/adr/nested/0004-reviewed-decisions.md",
            "docs/adr/0004-reviewed-decisions.txt",
            "docs/adr/0004-" + "a" * (subject.MAX_CORE_CONTRACT_NAME_LENGTH + 1) + ".md",
            "fuzz/fuzz_targets/New_target.rs",
            "fuzz/fuzz_targets/nested/new_target.rs",
            "fuzz/fuzz_targets/new-target.rs",
            "fuzz/fuzz_targets/new_target.js",
            "fuzz/fuzz_targets/" + "a" * (subject.MAX_CORE_CONTRACT_NAME_LENGTH + 1) + ".rs",
            "fuzz/corpus/versions/nested/seed",
            "fuzz/corpus/versions/seed.txt",
        ):
            with self.subTest(path=path):
                for concern in subject.FEEDBACK_PROFILE_CONCERNS:
                    self.assertIsNone(subject._core_contract_expected_mode(path, concern=concern))

    def test_feedback_tree_accepts_new_files_in_each_reviewed_pattern(self):
        concern = "core-rust-format-return"
        entries = self._required_core_contract_entries(concern)
        for path in (
            "packages/host-api/src/new-module.ts",
            "packages/host-api/tests/new-test.test.ts",
            "docs/adr/0004-reviewed-decisions.md",
            "fuzz/fuzz_targets/new_target.rs",
            "fuzz/corpus/new_target/seed",
        ):
            entries[path] = ("100644", "b" * 40)
        main_payload = self._module_lines(subject.CORE_CONTRACT_FUZZ_CORPUS_TARGETS | {"new_target"})
        marker, unused_blob = self._validate_feedback_tree(entries, concern, main_payload)
        self.assertEqual(marker, subject.CORE_CONTRACT_TREE_BY_CONCERN[concern])

    def test_feedback_tree_refuses_new_fuzz_target_without_module_declaration(self):
        concern = "core-rust-format-return"
        entries = self._required_core_contract_entries(concern)
        entries["fuzz/fuzz_targets/new_target.rs"] = ("100644", "b" * 40)
        with self.assertRaises(subject.Refusal) as refusal:
            self._validate_feedback_tree(entries, concern)
        self.assertEqual(refusal.exception.core_check, "package_decode")

    def test_feedback_tree_refuses_a_corpus_for_an_undeclared_target(self):
        concern = "core-rust-format-return"
        entries = self._required_core_contract_entries(concern)
        entries["fuzz/corpus/unreviewed/seed"] = ("100644", "b" * 40)
        with patch.object(
            subject, "_contract_tree_entries", side_effect=(dict(entries), entries),
        ), patch.object(subject, "_contract_blob") as blob, \
                self.assertRaises(subject.Refusal) as refusal:
            subject._safe_core_contract_tree(
                "repository", "/usr/bin/git", {}, "a" * 40, "b" * 40,
                concern=concern,
            )
        blob.assert_not_called()
        self.assertEqual(
            (refusal.exception.reason, refusal.exception.stage, refusal.exception.core_check),
            ("bootstrap_snapshot_invalid", "bootstrap", "tree_entries"),
        )

    def test_feedback_pattern_count_limits_refuse_before_blob_reads(self):
        cases = (
            ("ts_sources", subject.MAX_CORE_CONTRACT_TS_SOURCES,
             lambda index: "packages/host-api/src/extra-" + str(index) + ".ts"),
            ("ts_tests", subject.MAX_CORE_CONTRACT_TS_TESTS,
             lambda index: "packages/host-api/tests/extra-" + str(index) + ".test.ts"),
            ("adrs", subject.MAX_CORE_CONTRACT_ADRS,
             lambda index: "docs/adr/" + str(1000 + index) + "-extra.md"),
            ("fuzz_targets", subject.MAX_CORE_CONTRACT_FUZZ_TARGETS,
             lambda index: "fuzz/fuzz_targets/extra_" + str(index) + ".rs"),
        )
        for name, maximum, path_for in cases:
            entries = self._required_core_contract_entries("core-rust-format-return")
            existing = len(subject._core_contract_pattern_paths(entries)[name])
            for index in range(maximum - existing + 1):
                entries[path_for(index)] = ("100644", "b" * 40)
            with self.subTest(name=name), patch.object(
                subject, "_contract_tree_entries", side_effect=(dict(entries), entries),
            ), patch.object(subject, "_contract_blob") as blob, \
                    patch.object(subject, "_contract_blob_size") as blob_size, \
                    self.assertRaises(subject.Refusal) as refusal:
                subject._safe_core_contract_tree(
                    "repository", "/usr/bin/git", {}, "a" * 40, "b" * 40,
                    concern="core-rust-format-return",
                )
            blob.assert_not_called()
            blob_size.assert_not_called()
            self.assertEqual(
                (refusal.exception.reason, refusal.exception.stage, refusal.exception.core_check),
                ("bootstrap_snapshot_invalid", "bootstrap", "tree_entries"),
            )

    def test_oversized_new_source_module_refuses_under_the_file_limit(self):
        concern = "core-rust-format-return"
        entries = self._required_core_contract_entries(concern)
        path = "packages/host-api/src/new-module.ts"
        entries[path] = ("100644", "b" * 40)
        with patch.object(
            subject, "_contract_tree_entries", side_effect=(dict(entries), entries),
        ), patch.object(
            subject, "_contract_blob_size",
            return_value=subject.MAX_CORE_CONTRACT_FILE_BYTES + 1,
        ) as blob_size, patch.object(subject, "_contract_blob") as blob, \
                self.assertRaises(subject.Refusal) as refusal:
            subject._safe_core_contract_tree(
                "repository", "/usr/bin/git", {}, "a" * 40, "b" * 40,
                concern=concern,
            )
        blob_size.assert_called_once()
        blob.assert_not_called()
        self.assertEqual(
            (refusal.exception.reason, refusal.exception.stage, refusal.exception.core_check),
            ("bootstrap_snapshot_invalid", "bootstrap", "tree_entries"),
        )

    def test_added_pattern_files_share_a_bounded_total_size(self):
        concern = "core-rust-format-return"
        entries = self._required_core_contract_entries(concern)
        entries["packages/host-api/src/new-module.ts"] = ("100644", "b" * 40)
        entries["packages/host-api/tests/new-test.test.ts"] = ("100644", "c" * 40)
        with patch.object(
            subject, "_contract_tree_entries", side_effect=(dict(entries), entries),
        ), patch.object(
            subject, "_contract_blob_size",
            return_value=subject.MAX_CORE_CONTRACT_PATTERN_TOTAL_BYTES // 2 + 1,
        ) as blob_size, patch.object(subject, "_contract_blob") as blob, \
                self.assertRaises(subject.Refusal) as refusal:
            subject._safe_core_contract_tree(
                "repository", "/usr/bin/git", {}, "a" * 40, "b" * 40,
                concern=concern,
            )
        self.assertEqual(blob_size.call_count, 2)
        blob.assert_not_called()
        self.assertEqual(
            (refusal.exception.reason, refusal.exception.stage, refusal.exception.core_check),
            ("bootstrap_snapshot_invalid", "bootstrap", "tree_entries"),
        )

    def test_feedback_corpus_accepts_empty_utf8_seeds_with_bounded_closed_paths(self):
        paths = [
            "fuzz/corpus/identifiers/empty",
            "fuzz/corpus/tool_error_codes/empty-cause",
            "fuzz/corpus/versions/empty",
        ]
        payloads = {paths[0]: b"", paths[1]: b"CODE: ", paths[2]: b""}
        self.assertTrue(subject._feedback_corpus_shape(paths, payloads))
        oversized = dict(payloads)
        oversized[paths[1]] = b"x" * (subject.MAX_FUZZ_CORPUS_FILE_BYTES + 1)
        self.assertFalse(subject._feedback_corpus_shape(paths, oversized))
        unknown = paths[:-1] + ["fuzz/corpus/unreviewed/empty"]
        unknown_payloads = {path: b"" for path in unknown}
        self.assertFalse(subject._feedback_corpus_shape(unknown, unknown_payloads))
        self.assertFalse(subject._feedback_corpus_paths_shape(
            paths + ["fuzz/corpus/other/seed"],
        ))
        new_target_path = "fuzz/corpus/new_target/seed"
        extended_paths = paths + [new_target_path]
        extended_payloads = dict(payloads)
        extended_payloads[new_target_path] = b""
        declared_targets = subject.CORE_CONTRACT_FUZZ_CORPUS_TARGETS | {"new_target"}
        self.assertTrue(subject._feedback_corpus_shape(
            extended_paths, extended_payloads, declared_targets,
        ))
        self.assertFalse(subject._feedback_corpus_shape(extended_paths, extended_payloads))
        bad_utf8 = dict(payloads)
        bad_utf8[paths[1]] = b"\xff"
        self.assertFalse(subject._feedback_corpus_shape(paths, bad_utf8))
        target_names = ("identifiers", "tool_error_codes", "versions")
        too_many = [
            "fuzz/corpus/" + target + "/seed-" + str(index)
            for target, count in zip(target_names, (86, 86, 85))
            for index in range(count)
        ]
        self.assertFalse(
            subject._feedback_corpus_shape(too_many, {path: b"" for path in too_many}),
        )
        over_total = [
            "fuzz/corpus/" + target + "/data-" + str(index)
            for target in target_names
            for index in range(11)
        ]
        self.assertFalse(subject._feedback_corpus_shape(
            over_total, {path: b"x" * subject.MAX_FUZZ_CORPUS_FILE_BYTES for path in over_total},
        ))

    def test_feedback_tree_checks_corpus_count_before_reading_any_seed_blob(self):
        entries = self._required_core_contract_entries("core-rust-format-return")
        for index in range(subject.MAX_FUZZ_CORPUS_FILES - 2):
            path = "fuzz/corpus/identifiers/seed-" + str(index)
            entries[path] = ("100644", "a" * 40)
        self.assertEqual(
            sum(subject.CORE_CONTRACT_FUZZ_CORPUS_PATH.fullmatch(path) is not None for path in entries),
            subject.MAX_FUZZ_CORPUS_FILES + 1,
        )
        with patch.object(
            subject, "_contract_tree_entries", side_effect=(dict(entries), entries),
        ), patch.object(subject, "_contract_blob") as blob, self.assertRaises(subject.Refusal) as refusal:
            subject._safe_core_contract_tree(
                "repository", "/usr/bin/git", {}, "a" * 40, "b" * 40,
                concern="core-rust-format-return",
            )
        blob.assert_not_called()
        self.assertEqual(
            (refusal.exception.reason, refusal.exception.stage, refusal.exception.core_check),
            ("bootstrap_snapshot_invalid", "bootstrap", "tree_entries"),
        )

    def test_feedback_corpus_blob_read_is_bounded_to_one_seed_limit(self):
        path = "fuzz/corpus/identifiers/large"
        result = subject.subprocess.CompletedProcess(
            ("git",), 0, b"x" * (subject.MAX_FUZZ_CORPUS_FILE_BYTES + 1), b"",
        )
        with patch.object(subject, "_run_process", return_value=result) as run_process:
            with self.assertRaises(subject.Refusal) as refusal:
                subject._contract_blob(
                    "repository", "/usr/bin/git", {}, {path: ("100644", "a" * 40)},
                    path, core_check="tree_entries", max_bytes=subject.MAX_FUZZ_CORPUS_FILE_BYTES,
                )
        self.assertEqual(run_process.call_args.kwargs["max_output"], subject.MAX_FUZZ_CORPUS_FILE_BYTES)
        self.assertEqual(
            (refusal.exception.reason, refusal.exception.stage, refusal.exception.core_check),
            ("bootstrap_snapshot_invalid", "bootstrap", "tree_entries"),
        )

    def test_feedback_pattern_blob_size_read_refuses_an_oversized_file(self):
        path = "packages/host-api/src/new-module.ts"
        result = subject.subprocess.CompletedProcess(
            ("git",), 0,
            str(subject.MAX_CORE_CONTRACT_FILE_BYTES + 1).encode("ascii") + b"\n",
            b"",
        )
        with patch.object(subject, "_run_process", return_value=result) as run_process:
            with self.assertRaises(subject.Refusal) as refusal:
                subject._contract_blob_size(
                    "repository", "/usr/bin/git", {}, {path: ("100644", "a" * 40)},
                    path, core_check="tree_entries",
                )
        self.assertEqual(run_process.call_args.kwargs["max_output"], 32)
        self.assertEqual(
            (refusal.exception.reason, refusal.exception.stage, refusal.exception.core_check),
            ("bootstrap_snapshot_invalid", "bootstrap", "tree_entries"),
        )

    def test_feedback_lock_blob_read_uses_node_manifest_limit(self):
        path = subject.CORE_CONTRACT_PACKAGE_LOCK_PATH
        entries = {path: ("100644", "a" * 40)}
        exact_payload = b"x" * subject.MAX_FEEDBACK_LOCK_BYTES
        result = subject.subprocess.CompletedProcess(("git",), 0, exact_payload, b"")
        with patch.object(subject, "_run_process", return_value=result) as run_process:
            self.assertEqual(subject._contract_blob(
                "repository", "/usr/bin/git", {}, entries, path,
                core_check="package_decode", max_bytes=subject.MAX_FEEDBACK_LOCK_BYTES,
            ), exact_payload)
        self.assertEqual(
            run_process.call_args.kwargs["max_output"], subject.MAX_FEEDBACK_LOCK_BYTES,
        )

        oversized = subject.subprocess.CompletedProcess(
            ("git",), 0, b"x" * (subject.MAX_FEEDBACK_LOCK_BYTES + 1), b"",
        )
        with patch.object(subject, "_run_process", return_value=oversized) as run_process:
            with self.assertRaises(subject.Refusal) as refusal:
                subject._contract_blob(
                    "repository", "/usr/bin/git", {}, entries, path,
                    core_check="package_decode", max_bytes=subject.MAX_FEEDBACK_LOCK_BYTES,
                )
        self.assertEqual(
            run_process.call_args.kwargs["max_output"], subject.MAX_FEEDBACK_LOCK_BYTES,
        )
        self.assertEqual(
            (refusal.exception.reason, refusal.exception.stage, refusal.exception.core_check),
            ("bootstrap_snapshot_invalid", "bootstrap", "package_decode"),
        )

    def test_feedback_manifest_bytes_are_unique_and_match_the_bounded_workspace_shape(self):
        root_manifest = (
            b'{"private":true,"workspaces":["packages/*"],'
            b'"packageManager":"npm@11.19.1",'
            b'"engines":{"node":"24.22.1","npm":"11.19.1"},'
            b'"scripts":{"typecheck":"fixed","test":"fixed"}}'
        )
        package_manifest = (
            b'{"name":"fixture","version":"1.0.0","type":"module",'
            b'"exports":{".":{}},"scripts":{"typecheck":"fixed","test":"fixed"}}'
        )
        self.assertTrue(subject._feedback_manifest_shape(root_manifest, package_manifest))
        self.assertFalse(subject._feedback_manifest_shape(
            root_manifest.replace(b'"private":true', b'"private":true,"private":false'),
            package_manifest,
        ))
        self.assertFalse(subject._feedback_manifest_shape(
            root_manifest,
            package_manifest.replace(b'"scripts":{', b'"scripts":{"postinstall":"fixed",'),
        ))

    def test_feedback_fuzz_replay_workspace_is_local_only_and_dependency_bounded(self):
        fuzz_manifest = (
            b'[package]\nname = "parser-fixture"\ndescription = "bounded fixture"\n'
            b'version = "0.1.0"\nedition = "2024"\nrust-version = "1.99.1"\n'
            b'publish = false\n\n[dependencies]\napi-fixture = { path = "../crates/host/api" }\n'
            b'\n[workspace]\nresolver = "3"\n\n[lints.rust]\n'
            b'unsafe_code = "forbid"\nwarnings = "deny"\n'
        )
        api_manifest = (
            b'[package]\nname = "api-fixture"\ndescription = "bounded API fixture"\n'
            b'version.workspace = true\n'
            b'edition.workspace = true\nrust-version.workspace = true\npublish.workspace = true\n'
            b'\n[dependencies]\n\n[lints]\nworkspace = true\n'
        )
        fuzz_lock = (
            bytes((35,)) + b' Generated fixture.\nversion = 4\n\n[[package]]\n'
            b'name = "parser-fixture"\nversion = "0.1.0"\ndependencies = [\n "api-fixture",\n]\n'
            b'\n[[package]]\nname = "api-fixture"\nversion = "0.1.0"\n'
        )
        self.assertTrue(subject._feedback_fuzz_manifest_shape(fuzz_manifest, api_manifest, fuzz_lock))
        self.assertFalse(subject._feedback_fuzz_manifest_shape(
            fuzz_manifest + b'\n[[bin]]\nname = "new_target"\n', api_manifest, fuzz_lock,
        ))
        self.assertFalse(subject._feedback_fuzz_manifest_shape(
            fuzz_manifest.replace(
                b'api-fixture = { path = "../crates/host/api" }', b'api-fixture = "1.0"',
            ), api_manifest, fuzz_lock,
        ))
        external_lock = fuzz_lock.replace(
            b'name = "api-fixture"\nversion = "0.1.0"\n',
            b'name = "api-fixture"\nversion = "0.1.0"\nsource = "registry"\n',
        )
        self.assertNotEqual(external_lock, fuzz_lock)
        self.assertFalse(subject._feedback_fuzz_manifest_shape(
            fuzz_manifest, api_manifest,
            external_lock,
        ))

    def test_feedback_fuzz_modules_require_one_exact_pair_per_target(self):
        targets = subject.CORE_CONTRACT_FUZZ_CORPUS_TARGETS | {"new_target"}
        valid = self._module_lines(targets)
        baseline = self._module_lines(subject.CORE_CONTRACT_FUZZ_CORPUS_TARGETS)
        new_pair = self._module_lines({"new_target"})
        self.assertTrue(subject._feedback_fuzz_modules_shape(valid, targets))
        self.assertTrue(subject._feedback_fuzz_modules_shape(
            valid + b'const MARKER: &str = "' + bytes((35,)) + b'";\n'
            + b"// " + bytes((35,)) + b" comment\n", targets,
        ))
        invalid = (
            baseline,
            valid + new_pair,
            valid + self._module_lines({"missing_target"}),
            valid.replace(b"../fuzz_targets/new_target.rs", b"../../fuzz_targets/new_target.rs"),
            valid.replace(b"mod new_target;", b"mod mismatched;"),
            valid + b"mod stray;\n",
            valid + b'include!("../fuzz_targets/new_target.rs");\n',
            valid + b'include_str!("../fuzz_targets/new_target.rs");\n',
            valid + b'include_str !("../fuzz_targets/new_target.rs");\n',
            valid + b'include!("unrelated.rs");\n',
            valid + b"// include anywhere is refused\n",
            (chr(35) + "[cfg(any())]\n").encode("ascii") + valid,
            (chr(35) + "[allow(dead_code)]\n").encode("ascii") + valid,
            ("use std::io; " + chr(35) + "[cfg(any())]\n").encode("ascii") + valid,
            ("use std::io; " + chr(35) + "[allow(dead_code)]\n").encode("ascii") + valid,
            valid + b"macro_rules! helper { () => {} }\n",
            valid + ("let quote = '" + '"' + "';\n").encode("ascii"),
            valid + ("let quote = '" + "\\" + '"' + "';\n").encode("ascii"),
            b"/*\n" + valid + b"\n*/",
            b'let hidden = r"' + valid + b'";\n',
            b'let hidden = r' + bytes((35,)) + b'"' + valid + b'"' + bytes((35,)) + b';\n',
            b'let hidden = "\n' + valid + b'";\n',
            valid.replace(b"new_target::fuzz", b"new_target::unused"),
            valid.replace(b"new_target::fuzz", b"// new_target::fuzz"),
            valid.replace(b"new_target::fuzz", b'"new_target::fuzz"'),
        )
        for payload in invalid:
            with self.subTest(payload=payload):
                self.assertFalse(subject._feedback_fuzz_modules_shape(payload, targets))

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

    def test_contract_tree_parser_refuses_traversal_and_unicode_lookalikes(self):
        unicode_slug = chr(0x0430) + "dr"
        for path in (
            "fuzz/fuzz_targets/../outside.rs",
            "docs/adr/0004-" + unicode_slug + ".md",
        ):
            payload = (
                b"100644 blob " + b"a" * 40 + b"\t" + path.encode("utf-8") + b"\x00"
            )
            result = subject.subprocess.CompletedProcess(("git",), 0, payload, b"")
            with self.subTest(path=path), patch.object(
                subject, "_run_process", return_value=result,
            ), self.assertRaises(subject.Refusal) as refusal:
                subject._contract_tree_entries("repository", "/usr/bin/git", {}, "a" * 40)
            self.assertEqual(
                (refusal.exception.reason, refusal.exception.stage, refusal.exception.core_check),
                ("bootstrap_snapshot_invalid", "bootstrap", "tree_entries"),
            )

    def test_contract_tree_parser_refuses_case_variants_and_hidden_traversal(self):
        for first, second in (
            ("packages/kernel-i18n/package.json", "packages/Kernel-I18n/package.json"),
            ("packages/host-api/src/ids.ts", "packages/host-api/src/IDS.ts"),
            ("packages/kernel-i18n/src/key.ts", "packages/kernel-i18n/src/./key.ts"),
        ):
            payload = b"".join(
                b"100644 blob " + b"a" * 40 + b"\t" + path.encode("utf-8") + b"\x00"
                for path in (first, second)
            )
            result = subject.subprocess.CompletedProcess(("git",), 0, payload, b"")
            with self.subTest(first=first, second=second), patch.object(
                subject, "_run_process", return_value=result,
            ), self.assertRaises(subject.Refusal) as refusal:
                subject._contract_tree_entries("repository", "/usr/bin/git", {}, "a" * 40)
            self.assertEqual(refusal.exception.core_check, "tree_entries")

    @staticmethod
    def _required_core_contract_entries(concern="core-contract"):
        paths = {
            ".gitignore", "AGENTS.md", "CLAUDE.md", "README.md", subject.RULES_LOCK_PATH,
            subject.RULES_DIRECTORY + "/settings.json", "/".join(subject.SIGNER_PATH_PARTS),
        } | set(subject.CORE_CONTRACT_ROOT_FILES)
        for crate_root in subject.CORE_CONTRACT_CRATE_ROOTS:
            prefix = "/".join(crate_root)
            paths.update(prefix + "/" + item for item in subject.CORE_CONTRACT_PACKAGE_FILES)
            paths.add(prefix + "/src/lib.rs")
        if concern in subject.FEEDBACK_PROFILE_CONCERNS:
            paths.update(subject.CORE_CONTRACT_FEEDBACK_FILES)
            paths.update(subject.CORE_CONTRACT_FOUNDATION_FILES)
            paths.update((
                "fuzz/corpus/identifiers/valid-seed",
                "fuzz/corpus/tool_error_codes/valid-seed",
                "fuzz/corpus/versions/valid-seed",
            ))
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

    def test_each_feedback_tree_requires_every_fixed_typescript_path(self):
        for concern in sorted(subject.FEEDBACK_PROFILE_CONCERNS):
            entries = self._required_core_contract_entries(concern)
            entries.pop("packages/host-api/src/streams.ts")
            with self.subTest(concern=concern), patch.object(
                subject, "_contract_tree_entries", side_effect=(dict(entries), entries),
            ), self.assertRaises(subject.Refusal) as refusal:
                subject._safe_core_contract_tree(
                    "repository", "/usr/bin/git", {}, "a" * 40, "b" * 40,
                    concern=concern,
                )
            self.assertEqual(
                (refusal.exception.reason, refusal.exception.stage, refusal.exception.core_check),
                ("bootstrap_snapshot_invalid", "bootstrap", "required_files"),
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
                **subject.CORE_CONTRACT_TREE_BY_CONCERN,
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
        self.assertNotIn("tree=core_administrative", line.split())

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
        self.assertNotIn("tree=core_contract", line.split())

    def test_feedback_receipt_preserves_profile_specific_tree_binding(self):
        binding = {
            "control_sha": "c" * 40,
            "run_id": "12",
            "run_attempt": "1",
            "image_os": "macos-test",
            "image_version": "1",
        }
        for concern, tree in subject.CORE_CONTRACT_TREE_BY_CONCERN.items():
            if concern == "core-contract":
                continue
            record = self._record(concern)
            record.update({"candidate_class": "signed-descendant", "source_sha": "d" * 40})
            with self.subTest(concern=concern):
                line = subject._format_success(record, binding)
                self.assertIn("concern=" + concern, line.split())
                self.assertIn("tree=" + tree, line.split())
                wrong = dict(record, tree="core_contract")
                with self.assertRaises(subject.Refusal):
                    subject._format_success(wrong, binding)

    def test_build_diagnostic_receipt_marks_only_the_validated_root_lock_tree(self):
        binding = {
            "control_sha": "c" * 40,
            "run_id": "12",
            "run_attempt": "1",
            "image_os": "macos-test",
            "image_version": "1",
        }
        record = self._record("core-build-diagnostic-return")
        record.update({"candidate_class": "signed-descendant", "source_sha": "d" * 40})
        legacy_line = subject._format_success(record, binding)
        self.assertIn("tree=core_build_diagnostic_return", legacy_line.split())

        record["tree"] = subject.CORE_CONTRACT_PACKAGE_LOCK_TREE
        lock_line = subject._format_success(record, binding)
        self.assertIn("tree=" + subject.CORE_CONTRACT_PACKAGE_LOCK_TREE, lock_line.split())

        record["tree"] = "core_build_diagnostic_return_unreviewed"
        with self.assertRaises(subject.Refusal):
            subject._format_success(record, binding)

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


class ControlInventoryPreparationTests(unittest.TestCase):
    def _paths(self, temporary):
        base = Path(temporary).resolve(strict=True)
        root = base / "control"
        runner_temp = base / "runner"
        root.mkdir()
        runner_temp.mkdir()
        return root, runner_temp

    def test_preparation_binds_blob_and_restores_only_the_fixed_objects(self):
        contents = b"SHA256:" + b"A" * 43 + b"\n"
        with tempfile.TemporaryDirectory() as temporary:
            root, runner_temp = self._paths(temporary)
            harness = _InventoryHarness(root, runner_temp, contents)
            with harness.patches():
                state = subject._prepare_control_inventory(root, "a" * 40, runner_temp)
                self.assertEqual(harness.fchown_calls, [(11, 0, 0), (12, 0, 0)])
                self.assertEqual((harness.ci_info.st_uid, harness.inventory_info.st_uid), (0, 0))
                subject._restore_control_inventory(state)
                self.assertEqual(
                    (harness.ci_info.st_uid, harness.ci_info.st_gid,
                     harness.inventory_info.st_uid, harness.inventory_info.st_gid),
                    (harness.runner_uid, 20, harness.runner_uid, 20),
                )
            self.assertEqual(harness.closed, [12, 11, 10])

    def test_wrong_git_blob_refuses_before_ownership_changes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root, runner_temp = self._paths(temporary)
            harness = _InventoryHarness(root, runner_temp, b"local\n", blob=b"pinned\n")
            with harness.patches(), self.assertRaises(subject.Refusal) as raised:
                subject._prepare_control_inventory(root, "a" * 40, runner_temp)
            self.assertEqual((raised.exception.reason, raised.exception.stage),
                             ("revocation_policy_invalid", "revocation"))
            self.assertEqual(harness.fchown_calls, [])
            self.assertEqual(harness.closed, [12, 11, 10])

    def test_linked_inventory_objects_are_rejected_without_repair(self):
        for mode, links in ((stat.S_IFREG | 0o644, 2), (stat.S_IFLNK | 0o777, 1)):
            with tempfile.TemporaryDirectory() as temporary:
                root, runner_temp = self._paths(temporary)
                harness = _InventoryHarness(root, runner_temp, b"")
                harness.inventory_info.st_mode = mode
                harness.inventory_info.st_nlink = links
                with harness.patches(), self.assertRaises(subject.Refusal):
                    subject._prepare_control_inventory(root, "a" * 40, runner_temp)
                self.assertEqual(harness.fchown_calls, [])
                self.assertEqual(harness.closed, [11, 10])

    def test_partial_preparation_failure_rolls_back_and_closes_every_descriptor(self):
        contents = b"SHA256:" + b"B" * 43 + b"\n"
        with tempfile.TemporaryDirectory() as temporary:
            root, runner_temp = self._paths(temporary)
            harness = _InventoryHarness(root, runner_temp, contents)
            harness.fail_inventory_chown = True
            with harness.patches(), self.assertRaises(subject.Refusal) as raised:
                subject._prepare_control_inventory(root, "a" * 40, runner_temp)
            self.assertEqual((raised.exception.reason, raised.exception.stage),
                             ("revocation_policy_invalid", "revocation"))
            self.assertEqual((harness.ci_info.st_uid, harness.inventory_info.st_uid),
                             (harness.runner_uid, harness.runner_uid))
            self.assertEqual(harness.fchown_calls,
                             [(11, 0, 0), (12, 0, 0), (11, harness.runner_uid, 20)])
            self.assertEqual(harness.closed, [12, 11, 10])

    def test_swapped_path_and_restore_failure_refuse_and_close_all_descriptors(self):
        contents = b""
        with tempfile.TemporaryDirectory() as temporary:
            root, runner_temp = self._paths(temporary)
            harness = _InventoryHarness(root, runner_temp, contents)
            with harness.patches():
                state = subject._prepare_control_inventory(root, "a" * 40, runner_temp)
                harness.swap_ci = True
                with self.assertRaises(subject.Refusal) as raised:
                    subject._restore_control_inventory(state)
                self.assertEqual((raised.exception.reason, raised.exception.stage),
                                 ("cleanup_incomplete", "cleanup"))
            self.assertEqual(harness.fchown_calls, [(11, 0, 0), (12, 0, 0)])
            self.assertEqual(harness.closed, [12, 11, 10])

        with tempfile.TemporaryDirectory() as temporary:
            root, runner_temp = self._paths(temporary)
            harness = _InventoryHarness(root, runner_temp, contents)
            with harness.patches():
                state = subject._prepare_control_inventory(root, "a" * 40, runner_temp)
                harness.fail_inventory_restore = True
                with self.assertRaises(subject.Refusal) as raised:
                    subject._restore_control_inventory(state)
                self.assertEqual((raised.exception.reason, raised.exception.stage),
                                 ("cleanup_incomplete", "cleanup"))
            self.assertEqual(harness.closed, [12, 11, 10])

    def test_close_only_keeps_root_ownership_when_cleanup_is_unconfirmed(self):
        contents = b"SHA256:" + b"C" * 43 + b"\n"
        with tempfile.TemporaryDirectory() as temporary:
            root, runner_temp = self._paths(temporary)
            harness = _InventoryHarness(root, runner_temp, contents)
            with harness.patches():
                state = subject._prepare_control_inventory(root, "a" * 40, runner_temp)
                subject._close_control_inventory(state)
                self.assertEqual((harness.ci_info.st_uid, harness.inventory_info.st_uid), (0, 0))
            self.assertEqual(harness.fchown_calls, [(11, 0, 0), (12, 0, 0)])
            self.assertEqual(harness.closed, [12, 11, 10])


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
