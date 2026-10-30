import hashlib
import io
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

if not sys.platform.startswith("linux"):
    raise unittest.SkipTest("the Linux source build suite runs only on Linux")

import foundation_node_feedback
import confinement_public_audit
import confinement_verdict
import linux_source_build
import macos_core_contract


class _SyntheticTrustedLicenseBoundary:
    def __init__(self, control_root):
        self.gate = linux_source_build.rust_license_gate
        self.source_sha = "a" * 40
        self.packages = (self.gate.Package("serde", "1.0.1", "b" * 64),)
        self.archive = self.gate.ArchivePackage(
            self.packages[0], self.packages[0].checksum, "MIT", "MIT", True,
            (("LICENSE-MIT", "d" * 64),),
        )
        self.checker = control_root / "checker.fixture"
        self.deny = control_root / "cargo-deny.fixture"
        self.policy = control_root / "deny-policy.fixture"
        self.checker.write_bytes(b"synthetic checker identity")
        self.deny.write_bytes(b"synthetic cargo-deny identity")
        self.policy.write_bytes(b"synthetic reviewed policy identity")
        self.identities = []
        self.requests = []
        self.cleaned = []

    def ports(self):
        return self.gate._validated_ports(self.gate.TrustedPorts(
            self, self, self, self, self, None,
        ))

    def validate(self, lock_bytes, identity):
        if hashlib.sha256(lock_bytes).hexdigest() != identity.lock_sha256:
            raise self.gate.LicenseGateRefusal("lock")
        self.identities.append(identity)
        return self.gate._validated_lock(identity, self.packages)

    def for_identity(self, identity):
        if identity.source_sha != self.source_sha:
            raise self.gate.LicenseGateRefusal("identity")
        return self.gate._validated_config(self.gate.GateConfig(
            identity, "2" * 40, str(self.checker), self._digest(self.checker),
            str(self.deny), str(self.checker.parent), self._digest(self.deny),
            "a" * 64, str(self.policy), self._digest(self.policy),
            True, True,
            self.gate._cargo_deny_argv_sha256(identity, str(self.policy)),
            True, True, "e" * 40, int(time.time()), True, True, None,
        ))

    def verify_complete(self, lock_bytes, identity, lock_packages):
        del lock_bytes, lock_packages
        return self.gate._validated_archives(identity, (self.archive,), "f" * 64)

    def cancelled(self):
        return False

    def run(self, request):
        self.requests.append(request)
        output = (b"result=conditional-pass authenticated=no\n"
                  if request.argv == ("--stdin-protocol",) else b"")
        return self.gate._process_result(
            request, (0, False, False, output, b""), request.executable_sha256,
        )

    def cleanup(self, request, result):
        self.cleaned.append((request, result))

    @staticmethod
    def _digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()


class LinuxSourceBuildTests(unittest.TestCase):
    def test_gate_order_matches_the_shared_macos_contracts(self):
        expected = (
            macos_core_contract.GATE_NAMES
            + macos_core_contract.PARSER_GATE_NAMES
            + foundation_node_feedback.NODE_GATE_NAMES
        )
        self.assertEqual(linux_source_build.GATES, expected)
        self.assertEqual(len(linux_source_build.GATES), 13)

    def test_source_job_steps_match_the_policy_audit_contract(self):
        self.assertEqual(
            linux_source_build.SOURCE_STEP_NAMES,
            (
                "Fetch exact public control",
                "Repeat preflight in source-read",
                "Record image and fetch pinned Rust and Node toolchains",
                "Harden runner paths before the proof",
                "Boundary self-test before source-reader mint",
                "Mint scoped source-reader token",
                "Verify selected installation identity",
                "Fetch exact source and verify binding, tree, signatures and lock provenance",
                "Revoke source-reader token and verify rejection",
                "Require trusted Rust licence admission",
                "Fetch npm tarballs by committed lock integrity",
                "Run trusted dependency audit",
                "Prepare offline project inputs",
                "Re-run positive controls immediately before the first project command",
                "Run all thirteen offline project gates",
                "Merge confinement phase records",
                "Forced faults must fail closed",
            ),
        )
        self.assertEqual(linux_source_build.VERDICT_STEP_NAMES, (
            "Fetch exact public control", "Repeat independent preflight",
            "Record verifier image and fetch pinned toolchains",
            "Harden verifier runner paths", "Run independent boundary self-test",
            "Mint verifier scoped source-reader token",
            "Verify source independently against binding, tree, signatures and lock",
            "Revoke verifier token and verify rejection",
            "Require trusted Rust licence admission independently",
            "Fetch independent npm tarballs by lock integrity",
            "Run independent trusted dependency audit",
            "Prepare independent offline project inputs",
            "Re-run independent positive controls before project execution",
            "Run independent thirteen offline project gates",
            "Merge independent confinement records", "Verify unprivileged proof handoff",
            "Publish confinement verdict",
        ))
        self.assertEqual(
            linux_source_build.OPTIONAL_SOURCE_STEPS,
            frozenset((
                "Mint scoped source-reader token",
                "Verify selected installation identity",
                "Fetch exact source and verify binding, tree, signatures and lock provenance",
                "Revoke source-reader token and verify rejection",
                "Require trusted Rust licence admission",
                "Fetch npm tarballs by committed lock integrity",
                "Run trusted dependency audit",
                "Prepare offline project inputs",
                "Run all thirteen offline project gates",
                "Forced faults must fail closed",
            )),
        )

    def test_source_step_contract_matches_workflow_in_source_and_synthetic_modes(self):
        workflow = (Path(__file__).resolve().parents[2]
                    / ".github/workflows/linux-source-admission.yml").read_text(encoding="utf-8")
        match = re.search(
            r"(?ms)^  linux-source-admission-source-read:\n(.*?)(?=^  linux-source-admission-verdict:)",
            workflow,
        )
        self.assertIsNotNone(match)
        actual_steps = tuple(re.findall(r"^      - name: (.+)$", match.group(1), re.MULTILINE))
        self.assertEqual(actual_steps, linux_source_build.SOURCE_STEP_NAMES)
        self.assertIn("Require trusted Rust licence admission", actual_steps)
        verdict_match = re.search(
            r"(?ms)^  linux-source-admission-verdict:\n(.*?)(?=^  linux-source-admission-audit:)",
            workflow,
        )
        self.assertIsNotNone(verdict_match)
        verdict_steps = tuple(re.findall(r"^      - name: (.+)$", verdict_match.group(1), re.MULTILINE))
        self.assertEqual(verdict_steps, linux_source_build.VERDICT_STEP_NAMES)
        self.assertIn("Require trusted Rust licence admission independently", verdict_steps)
        self.assertIn("Require trusted Rust licence admission independently",
                      linux_source_build.OPTIONAL_VERDICT_SYNTHETIC_STEPS)
        for mode in ("source", "synthetic"):
            expected = linux_source_build._expected_run(
                {"CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1",
                 "CI_MODE": mode, "REQUESTED_SOURCE_SHA": "b" * 40},
                "c" * 64,
            )
            job = expected["jobs"]["linux-source-admission-source-read"]
            if mode == "source":
                self.assertEqual(job["steps"], actual_steps + ("Post Mint scoped source-reader token",))
                self.assertNotIn("Require trusted Rust licence admission", job["optional_steps"])
            else:
                self.assertEqual(job["steps"], actual_steps)
                self.assertIn("Require trusted Rust licence admission", job["optional_steps"])

    def test_producer_and_independent_verifier_bind_license_gates_before_preparation(self):
        workflow = (Path(__file__).resolve().parents[2]
                    / ".github/workflows/linux-source-admission.yml").read_text(encoding="utf-8")
        blocks = {}
        for name in (
                "Require trusted Rust licence admission",
                "Fetch npm tarballs by committed lock integrity",
                "Prepare offline project inputs",
                "Run all thirteen offline project gates",
                "Require trusted Rust licence admission independently",
                "Fetch independent npm tarballs by lock integrity",
                "Prepare independent offline project inputs",
                "Run independent thirteen offline project gates"):
            match = re.search(
                r"(?ms)^      - name: " + re.escape(name)
                + r"\n(.*?)(?=^      - name: |^  linux-source-admission-)",
                workflow,
            )
            if match:
                blocks[name] = match.group(1)
        self.assertIn("Require trusted Rust licence admission", blocks)
        self.assertIn("REQUESTED_SOURCE_SHA: ${{ inputs.source_sha }}",
                      blocks["Require trusted Rust licence admission"])
        self.assertIn("REQUESTED_SOURCE_SHA", blocks["Run all thirteen offline project gates"])
        independent_gate = "\n".join(workflow.splitlines()[
            workflow.index("      - name: Revoke verifier token and verify rejection"):
            workflow.index("      - name: Fetch independent npm tarballs by lock integrity")
        ])
        self.assertIn("Require trusted Rust licence admission independently", independent_gate)
        self.assertIn("REQUESTED_SOURCE_SHA: ${{ inputs.source_sha }}", independent_gate)
        self.assertLess(workflow.index("Require trusted Rust licence admission"),
                        workflow.index("Fetch npm tarballs by committed lock integrity"))
        self.assertLess(workflow.index("Require trusted Rust licence admission independently"),
                        workflow.index("Fetch independent npm tarballs by lock integrity"))
        self.assertLess(workflow.index("Require trusted Rust licence admission"),
                        workflow.index("Prepare offline project inputs"))
        self.assertLess(workflow.index("Require trusted Rust licence admission independently"),
                        workflow.index("Prepare independent offline project inputs"))
        verifier_gates = workflow[workflow.index("      - name: Run independent thirteen offline project gates"):]
        verifier_gate_step = verifier_gates.split("\n      - name:", 1)[0]
        self.assertIn("REQUESTED_SOURCE_SHA", verifier_gate_step)
        self.assertIn("preserve-env=WORKER_PATH,CARGO_HOME,RUST_ROOT,NODE_BIN,RUNNER_TEMP,REQUESTED_SOURCE_SHA",
                      verifier_gates)
        self.assertIn("preserve-env=WORKER_PATH,CARGO_HOME,RUST_ROOT,NODE_BIN,RUNNER_TEMP,REQUESTED_SOURCE_SHA",
                      blocks["Run all thirteen offline project gates"])

    def test_expected_run_assigns_the_plain_verdict_job_and_action_post(self):
        base = {"CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1"}
        source = linux_source_build._expected_run({**base, "CI_MODE": "source"}, "b" * 64)
        synthetic = linux_source_build._expected_run({**base, "CI_MODE": "synthetic"}, "b" * 64)
        self.assertEqual(source["verdict_job"], "linux-source-admission-verdict")
        self.assertEqual(source["jobs"][source["verdict_job"]]["steps"], linux_source_build.VERDICT_STEP_NAMES)
        self.assertEqual(source["jobs"][source["verdict_job"]]["optional_steps"], ())
        self.assertEqual(
            synthetic["jobs"][synthetic["verdict_job"]]["optional_steps"],
            linux_source_build.OPTIONAL_VERDICT_SYNTHETIC_STEPS,
        )
        self.assertEqual(source["jobs"]["linux-source-admission-source-read"]["steps"][-1], "Post Mint scoped source-reader token")
        self.assertNotIn("Post Mint scoped source-reader token", synthetic["jobs"]["linux-source-admission-source-read"]["steps"])

    def test_toolchain_versions_are_pinned_and_node_digest_is_a_coordinator_constant(self):
        self.assertEqual(linux_source_build.NODE_VERSION, "24.22.1")
        self.assertEqual(linux_source_build.NPM_VERSION, "11.19.1")
        self.assertTrue(linux_source_build.NODE_LINUX_TARBALL_SHA256.startswith("COORDINATOR_FILL_"))
        self.assertEqual(len(linux_source_build.RUST_COMPONENTS), 5)
        for name, url, digest in linux_source_build.RUST_COMPONENTS:
            with self.subTest(component=name):
                self.assertIn("1.99.1-x86_64-unknown-linux-gnu.tar.gz", url)
                self.assertRegex(digest, r"\A[a-f0-9]{64}\Z")

    def test_project_read_paths_are_outside_runner_temp(self):
        self.assertEqual(str(linux_source_build.TOOLCHAIN_ROOT), "/tmp/kd-toolchains")
        self.assertEqual(str(linux_source_build.PROJECT_ROOT), "/tmp/kd-project-worker")
        self.assertNotIn("runner-temp", str(linux_source_build.TOOLCHAIN_ROOT))
        self.assertNotIn("runner-temp", str(linux_source_build.PROJECT_ROOT))

    def test_archive_path_checks_allow_directory_entries_and_safe_relative_links(self):
        self.assertTrue(linux_source_build._safe_tar_member("component/"))
        self.assertFalse(linux_source_build._safe_tar_member("../escape"))
        self.assertTrue(linux_source_build._safe_tar_link("../lib/node.js"))
        self.assertFalse(linux_source_build._safe_tar_link("/etc/passwd"))

    def test_cargo_lock_rejects_any_registry_or_git_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "Cargo.lock"
            lock.write_text(
                'version = 3\n\n[[package]]\nname = "example"\nversion = "1.0.0"\n',
                encoding="utf-8",
            )
            linux_source_build._validate_cargo_lock_sources(temporary)
            lock.write_text(
                'version = 3\n\n[[package]]\nname = "example"\nversion = "1.0.0"\n'
                'source = "registry+https://' + 'github.com/rust-lang/crates.io-index"\n',
                encoding="utf-8",
            )
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._validate_cargo_lock_sources(temporary)
            lock.write_text(
                'version = 3\n\n[[package]]\nname = "example"\nversion = "1.0.0"\n'
                'source = "git+https://example.invalid/repo"\n',
                encoding="utf-8",
            )
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._validate_cargo_lock_sources(temporary)

    def _root_descriptor(self, root):
        descriptor = linux_source_build._open_source_root(root)
        self.addCleanup(os.close, descriptor)
        return descriptor

    def test_cargo_lock_read_is_bounded_and_refuses_traversal_faults(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            lock = root / "Cargo.lock"
            lock.write_bytes(b"x" * 17)
            descriptor = self._root_descriptor(root)
            candidate = linux_source_build._rust_lock_paths(descriptor)[0]
            with patch.object(linux_source_build.rust_license_gate, "MAX_LOCK_BYTES", 16):
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._read_bounded_cargo_lock(descriptor, candidate)

            lock.write_bytes(b"version = 4\n")
            candidate = linux_source_build._rust_lock_paths(descriptor)[0]
            self.assertEqual(
                linux_source_build._read_bounded_cargo_lock(descriptor, candidate),
                b"version = 4\n",
            )

            with patch.object(linux_source_build.os, "scandir",
                              side_effect=PermissionError("synthetic traversal refusal")):
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._rust_lock_paths(descriptor)

            lock.write_text("changed after discovery\n", encoding="ascii")
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._read_bounded_cargo_lock(descriptor, candidate)

            lock.write_text("version = 4\n", encoding="ascii")
            candidate = linux_source_build._rust_lock_paths(descriptor)[0]
            original_read = os.read

            def replace_after_read(handle, maximum):
                payload = original_read(handle, maximum)
                lock.unlink()
                lock.write_bytes(b"replacement lock\n")
                return payload

            with patch.object(linux_source_build.os, "read", side_effect=replace_after_read):
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._read_bounded_cargo_lock(descriptor, candidate)

    def test_cargo_lock_traversal_refuses_swapped_ancestor_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            root = base / "source"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "Cargo.lock").write_bytes(b"outside lock\n")
            nested = root / "sub"
            nested.mkdir()
            (nested / "Cargo.lock").write_bytes(b"version = 4\n")
            descriptor = self._root_descriptor(root)
            candidate = linux_source_build._rust_lock_paths(descriptor)[0]
            self.assertEqual(candidate[0], ("sub", "Cargo.lock"))

            nested.rename(root / "moved")
            nested.symlink_to(outside, target_is_directory=True)
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._read_bounded_cargo_lock(descriptor, candidate)

            nested.unlink()
            nested.mkdir()
            (nested / "Cargo.lock").write_bytes(b"version = 4\n")
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._read_bounded_cargo_lock(descriptor, candidate)

    def test_cargo_lock_discovery_refuses_a_directory_swapped_before_its_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary).resolve()
            root = base / "source"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "Cargo.lock").write_bytes(b"outside lock\n")
            nested = root / "sub"
            nested.mkdir()
            (root / "Cargo.lock").write_bytes(b"version = 4\n")
            descriptor = self._root_descriptor(root)
            original = linux_source_build._open_verified_directory
            swapped = []

            def swap_then_open(root_fd, parts, identities):
                if parts == ("sub",) and not swapped:
                    swapped.append(True)
                    nested.rename(root / "moved")
                    nested.symlink_to(outside, target_is_directory=True)
                return original(root_fd, parts, identities)

            with patch.object(linux_source_build, "_open_verified_directory",
                              side_effect=swap_then_open):
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._rust_lock_paths(descriptor)
            self.assertEqual(swapped, [True])

    def test_cargo_lock_discovery_reports_a_vanished_directory_as_lock(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "source"
            root.mkdir()
            nested = root / "sub"
            nested.mkdir()
            (root / "Cargo.lock").write_bytes(b"version = 4\n")
            descriptor = self._root_descriptor(root)
            original = linux_source_build._open_verified_directory

            def remove_then_open(root_fd, parts, identities):
                if parts == ("sub",) and nested.exists():
                    nested.rmdir()
                return original(root_fd, parts, identities)

            with patch.object(linux_source_build, "_open_verified_directory",
                              side_effect=remove_then_open):
                with self.assertRaises(linux_source_build.SourceBuildRefusal) as refused:
                    linux_source_build._rust_lock_paths(descriptor)
            self.assertEqual(refused.exception.reason, "lock")

    def test_cargo_lock_discovery_skips_the_npm_tarball_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "source"
            tarballs = root / ".kd-npm-tarballs"
            tarballs.mkdir(parents=True)
            (root / "Cargo.lock").write_bytes(b"version = 4\n")
            for index in range(3):
                (tarballs / ("pkg-" + str(index) + ".tgz")).write_bytes(b"x")
            descriptor = self._root_descriptor(root)
            with patch.object(linux_source_build, "MAX_DIRECTORY_ENTRIES", 2):
                found = linux_source_build._rust_lock_paths(descriptor)
            self.assertEqual([item[0] for item in found], [("Cargo.lock",)])

    def test_cargo_lock_discovery_scans_a_nested_npm_tarball_named_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "source"
            nested = root / "sub" / ".kd-npm-tarballs"
            nested.mkdir(parents=True)
            (root / "Cargo.lock").write_bytes(b"version = 4\n")
            (nested / "Cargo.lock").write_bytes(b"version = 4\n")
            descriptor = self._root_descriptor(root)
            found = linux_source_build._rust_lock_paths(descriptor)
            self.assertEqual(
                sorted(item[0] for item in found),
                [("Cargo.lock",), ("sub", ".kd-npm-tarballs", "Cargo.lock")],
            )

    def test_cargo_lock_directory_entry_materialization_is_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for name in ("Cargo.lock", "one", "two"):
                (root / name).write_text("version = 4\n", encoding="ascii")
            descriptor = self._root_descriptor(root)
            with patch.object(linux_source_build, "MAX_DIRECTORY_ENTRIES", 2):
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._rust_lock_paths(descriptor)

            (root / "first").mkdir()
            (root / "second").mkdir()
            with patch.object(linux_source_build, "MAX_PENDING_DIRECTORIES", 1):
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._rust_lock_paths(descriptor)

    def test_project_config_files_are_refused_or_removed_before_tool_use(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo = root / ".cargo"
            cargo.mkdir()
            cargo_config = cargo / "config.custom"
            cargo_config.write_text("[build]\njobs = 2\n", encoding="utf-8")
            npmrc = root / ".npmrc"
            npmrc.write_text("registry=https://registry.npmjs.org/\n", encoding="utf-8")
            linux_source_build._neutralize_config_files(root)
            self.assertFalse(cargo_config.exists())
            self.assertFalse(npmrc.exists())
            cargo_config.write_text(
                '[source.crates-io]\nreplace-with = "alternate"\n', encoding="utf-8"
            )
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._neutralize_config_files(root)

    def test_gate_commands_are_offline_after_dependency_preparation(self):
        commands = linux_source_build._gate_commands(Path("/work"), "/rust", "/node")
        self.assertEqual(tuple(name for name, argv in commands), linux_source_build.GATES)
        for name, argv in commands:
            with self.subTest(gate=name):
                self.assertIn("--offline", argv)
        by_name = dict(commands)
        for name in ("node_dependency_prepare", "typescript_typecheck", "typescript_tests"):
            with self.subTest(gate=name):
                self.assertIn("--ignore-scripts", by_name[name])
        for name in ("node_dependency_prepare", "node_dependency_audit", "typescript_typecheck", "typescript_tests"):
            with self.subTest(gate=name):
                self.assertTrue(any(item.startswith("--workspaces") or item == "--workspaces" for item in by_name[name]))

    def test_runtime_gate_commands_are_selected_for_the_complete_workspace(self):
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary)
            runtime = project / "runtime"
            runtime.mkdir()
            (runtime / "Cargo.toml").write_text("[workspace]\n", encoding="ascii")
            (runtime / "Cargo.lock").write_text("version = 4\n", encoding="ascii")
            commands = linux_source_build._gate_commands(project, "/rust", "/node")
            self.assertEqual(
                tuple(name for name, argv in commands),
                linux_source_build.GATES + linux_source_build.RUNTIME_GATE_NAMES,
            )
            cargo = "/rust/bin/cargo"
            manifest = str(runtime / "Cargo.toml")
            self.assertEqual(commands[-3:], (
                ("runtime_format", (cargo, "--locked", "--offline", "fmt", "--manifest-path",
                                     manifest, "--all", "--", "--check")),
                ("runtime_clippy", (cargo, "clippy", "--offline", "--manifest-path", manifest,
                                     "--workspace", "--all-targets", "--locked", "--", "-D", "warnings")),
                ("runtime_tests", (cargo, "test", "--offline", "--manifest-path", manifest,
                                    "--workspace", "--all-targets", "--locked")),
            ))
            (runtime / "Cargo.lock").unlink()
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._gate_commands(project, "/rust", "/node")

    def test_project_root_refuses_a_hostile_symlink(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            link = root.parent / (root.name + "-link")
            link.symlink_to(root, target_is_directory=True)
            try:
                with patch.object(linux_source_build, "PROJECT_ROOT", link):
                    with self.assertRaises(linux_source_build.SourceBuildRefusal):
                        linux_source_build._open_project_root()
            finally:
                link.unlink()

    def test_gate_directories_refuse_hostile_symlinks_without_ownership_changes(self):
        for create in (False, True):
            with self.subTest(create=create), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                worker = root / "source"
                outside = Path(temporary) / "outside"
                worker.mkdir(parents=True)
                outside.mkdir()
                for name in (".tmp", "target", ".npm-cache", ".kd-cargo-home"):
                    (worker / name).mkdir()
                (worker / ".home").symlink_to(outside, target_is_directory=True)
                before = outside.stat()
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                with patch.object(linux_source_build, "PROJECT_ROOT", root), patch.object(
                    linux_source_build, "_open_project_root", side_effect=lambda: os.open(root, flags)
                ), patch.object(linux_source_build.linux_harness, "CHILD_UID", os.getuid()), patch.object(
                    linux_source_build.linux_harness, "CHILD_GID", os.getgid()
                ), patch.object(linux_source_build.os, "fchown", side_effect=AssertionError("unexpected chown")):
                    with self.assertRaises(linux_source_build.SourceBuildRefusal):
                        linux_source_build._project_gate_directories(worker, create=create)
                after = outside.stat()
                self.assertEqual((before.st_uid, before.st_gid, before.st_mode), (after.st_uid, after.st_gid, after.st_mode))

    def test_repeated_preflight_refuses_missing_binding_before_duplicate_check(self):
        sha = "a" * 40
        env = {
            "CI_EVENT_NAME": "workflow_dispatch", "CI_REPOSITORY": linux_source_build.REPOSITORY,
            "CI_SERVER_URL": "https://github.com", "CACHE_MODE": "none",
            "CI_SHA": sha, "GITHUB_SHA": sha, "CI_REF": "refs/heads/untrusted", "CI_MODE": "source",
        }
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, sha]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ), patch.object(linux_source_build, "_source_inputs", side_effect=linux_source_build.SourceBuildRefusal("binding")) as binding, patch.object(
            linux_source_build, "_require_no_duplicate"
        ) as duplicate:
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build.validate_dispatch(env, "token")
            binding.assert_called_once_with(env)
            duplicate.assert_not_called()

    def test_protected_source_binding_refuses_one_changed_fingerprint(self):
        sha = "a" * 40
        base = "b" * 40
        fingerprint = "c" * 64
        env = {
            "REQUESTED_SOURCE_SHA": sha, "REQUESTED_BASE_SHA": base,
            "REQUESTED_BASE_BRANCH": "main", "REQUESTED_FINGERPRINT": fingerprint,
            "CI_SHA": "d" * 40, "LINUX_SOURCE_ALLOWED_SHA": sha,
            "LINUX_SOURCE_ALLOWED_BASE_SHA": base, "LINUX_SOURCE_ALLOWED_BASE_BRANCH": "main",
            "LINUX_SOURCE_ALLOWED_FINGERPRINT": "e" * 64,
            "LINUX_SOURCE_ALLOWED_CONTROL_SHA": "d" * 40,
            "SOURCE_REPOSITORY_ID": "7", "SOURCE_REPOSITORY_OWNER": "owner",
            "SOURCE_REPOSITORY_NAME": "source", "SOURCE_READER_INSTALLATION_ID": "8",
            "SOURCE_READER_CLIENT_ID": "client", "LINUX_SOURCE_ACCEPTED_NODE_LOCK_SHA256": "f" * 64,
            "LINUX_SOURCE_ACCEPTED_MANIFEST_SHA256": "1" * 64,
            "LINUX_SOURCE_ACCEPTED_NODE_PROVENANCE_JSON": "{}",
            "LINUX_SOURCE_ENVIRONMENT_NAME": "source-read", "REQUESTED_ENVIRONMENT_NAME": "source-read",
        }
        with patch.object(linux_source_build, "_validate_provenance_binding") as provenance:
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build._source_inputs(env)
            provenance.assert_not_called()
            env["LINUX_SOURCE_ALLOWED_FINGERPRINT"] = fingerprint
            self.assertEqual(linux_source_build._source_inputs(env)["reviewed_diff_sha256"], fingerprint)
            provenance.assert_called_once()

    def test_default_checkout_environment_reaches_the_source_fetch(self):
        identity = {"owner": "owner", "name": "source", "repository_id": "7", "source_sha": "a" * 40}
        repository = {"id": 7, "private": True, "full_name": "owner/source"}
        marker = RuntimeError("source fetch reached")

        def git_call(unused_repo, *arguments, **unused_keywords):
            if arguments[:2] == ("remote", "add"):
                raise marker
            return subprocess.CompletedProcess(arguments, 0, b"", b"")

        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ, {"RUNNER_TEMP": temporary, "CI_REF": "refs/heads/untrusted", "SOURCE_READER_TOKEN": "token"}, clear=True
        ), patch.object(linux_source_build, "_source_inputs", return_value=identity), patch.object(
            linux_source_build, "_api_request", return_value=(200, repository)
        ), patch.object(linux_source_build, "_git", side_effect=git_call):
            with self.assertRaisesRegex(RuntimeError, "source fetch reached"):
                linux_source_build.checkout_source()

    def test_checkout_rejects_a_bad_signature_before_lock_or_project_work(self):
        source_sha = "a" * 40
        base_sha = "b" * 40
        identity = {
            "owner": "owner", "name": "source", "repository_id": "7", "source_sha": source_sha,
            "base_sha": base_sha, "base_branch": "main", "reviewed_diff_sha256": hashlib.sha256(b"").hexdigest(),
        }

        def git_call(unused_repo, *arguments, **unused_keywords):
            output = b""
            if arguments[:2] == ("rev-parse", "--verify"):
                reference = arguments[2]
                output = ((base_sha if reference.startswith("refs/remotes/") else "c" * 40 if reference == "HEAD^{tree}" else source_sha) + "\n").encode("ascii")
            return subprocess.CompletedProcess(arguments, 0, output, b"")

        with tempfile.TemporaryDirectory() as temporary, patch.object(
            linux_source_build, "_source_inputs", return_value=identity
        ), patch.object(linux_source_build, "_api_request", return_value=(200, {
            "id": 7, "private": True, "full_name": "owner/source",
        })), patch.object(linux_source_build, "_git", side_effect=git_call), patch.object(
            linux_source_build, "_verify_signatures", side_effect=linux_source_build.SourceBuildRefusal("signature")
        ) as signatures:
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "signature"):
                linux_source_build.checkout_source({
                    "RUNNER_TEMP": temporary, "CI_REF": "refs/heads/untrusted", "SOURCE_READER_TOKEN": "token",
                    "CI_WORKSPACE": temporary,
                })
            signatures.assert_called_once()

    def test_revoke_requires_the_unauthorized_response_and_writes_a_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"SOURCE_READER_TOKEN": "token", "RUNNER_TEMP": temporary}
            with patch.object(linux_source_build, "_api_request", side_effect=[(204, {}), (401, {})]) as api:
                self.assertEqual(linux_source_build.revoke_token(env), 0)
                self.assertEqual(api.call_count, 2)
                self.assertEqual(api.call_args.args[0], "/installation/repositories?per_page=1")
            receipt = json.loads((Path(temporary) / "kd-records" / "revocation.json").read_text(encoding="ascii"))
            self.assertTrue(receipt["rejected_after_revoke"])
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            linux_source_build, "_api_request", side_effect=[(204, {}), (200, {})]
        ):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "revocation"):
                linux_source_build.revoke_token({"SOURCE_READER_TOKEN": "token", "RUNNER_TEMP": temporary})
            self.assertFalse((Path(temporary) / "kd-records" / "revocation.json").exists())

    def test_real_gates_use_the_shared_stopping_launcher(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker = root / "source"
            worker.mkdir()
            (worker / "Cargo.lock").write_text("version = 4\n", encoding="ascii")
            control_root = root / "control"
            control_root.mkdir()
            boundary = _SyntheticTrustedLicenseBoundary(control_root)
            commands = tuple(
                (name, ("/usr/bin/true",)) for name in linux_source_build.GATES
            )
            with patch.object(
                linux_source_build.rust_license_gate, "TRUSTED_PORTS", boundary.ports(),
            ), patch.object(
                linux_source_build, "_project_gate_directories",
            ) as directories, patch.object(
                linux_source_build, "_gate_commands", return_value=commands,
            ), patch.object(
                linux_source_build, "_runtime_workspace_present", return_value=False,
            ), patch.object(
                linux_source_build.linux_session, "run_host",
                return_value=types.SimpleNamespace(
                    exit_code=0, timed_out=False, stdout=b"", stderr=b"",
                ),
            ) as session:
                self.assertEqual(linux_source_build.run_project_gates({
                    "RUNNER_TEMP": temporary, "WORKER_PATH": str(worker),
                    "CARGO_HOME": str(worker / ".kd-cargo-home"),
                    "RUST_ROOT": "/rust", "NODE_BIN": "/node",
                    "REQUESTED_SOURCE_SHA": boundary.source_sha,
                }), 0)
                self.assertEqual(directories.call_count, 13)
                self.assertEqual(session.call_count, 13)
                self.assertEqual(boundary.identities[0].profile, ".")
                self.assertEqual(boundary.identities[0].root, str(worker))
                for invocation in session.call_args_list:
                    launch = invocation.args[2]
                    self.assertEqual(launch[:3], ("/usr/bin/python3", "-B", "-c"))
                    self.assertEqual(launch[3], linux_source_build.linux_probes.LAUNCHER_SOURCE)
                    self.assertEqual(launch[4:], ("/usr/bin/true",))

    def test_license_gate_refusal_precedes_preparation_and_command_construction(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker = root / "source"
            worker.mkdir()
            (worker / "Cargo.lock").write_text("version = 4\n", encoding="ascii")
            with patch.object(linux_source_build.rust_license_gate, "TRUSTED_PORTS", None), patch.object(
                linux_source_build, "_project_gate_directories",
            ) as prepare, patch.object(linux_source_build, "_gate_commands") as construct, patch.object(
                linux_source_build.linux_session, "run_host",
            ) as execute:
                with self.assertRaises(linux_source_build.rust_license_gate.LicenseGateRefusal):
                    linux_source_build.run_project_gates({
                        "RUNNER_TEMP": temporary, "WORKER_PATH": str(worker),
                        "CARGO_HOME": str(worker / ".kd-cargo-home"),
                        "RUST_ROOT": "/rust", "NODE_BIN": "/node",
                        "REQUESTED_SOURCE_SHA": "a" * 40,
                    })
            prepare.assert_not_called()
            construct.assert_not_called()
            execute.assert_not_called()

    def test_runtime_gate_receipt_requires_every_selected_stage_to_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker = root / "source"
            worker.mkdir()
            (worker / "Cargo.lock").write_text("version = 4\n", encoding="ascii")
            runtime = worker / "runtime"
            runtime.mkdir(parents=True)
            (runtime / "Cargo.toml").write_text("[workspace]\n", encoding="ascii")
            (runtime / "Cargo.lock").write_text("version = 4\n", encoding="ascii")
            commands = tuple(
                (name, ("/usr/bin/true",))
                for name in linux_source_build.GATES + linux_source_build.RUNTIME_GATE_NAMES
            )
            (root / "control").mkdir()
            boundary = _SyntheticTrustedLicenseBoundary(root / "control")
            with patch.object(linux_source_build.rust_license_gate, "TRUSTED_PORTS", boundary.ports()), patch.object(
                linux_source_build, "_project_gate_directories"
            ), patch.object(
                linux_source_build, "_gate_commands", return_value=commands
            ), patch.object(linux_source_build.linux_session, "run_host", return_value=types.SimpleNamespace(
                exit_code=0, timed_out=False, stdout=b"", stderr=b""
            )):
                result = linux_source_build.run_project_gates({
                    "RUNNER_TEMP": temporary, "WORKER_PATH": str(worker),
                    "CARGO_HOME": str(worker / ".kd-cargo-home"), "RUST_ROOT": "/rust", "NODE_BIN": "/node",
                    "REQUESTED_SOURCE_SHA": boundary.source_sha,
                })
            self.assertEqual(result, 0)
            receipt = json.loads((Path(temporary) / "kd-records" / "gates.json").read_text(encoding="ascii"))
            self.assertEqual(receipt["selected_gates"], list(linux_source_build.GATES + linux_source_build.RUNTIME_GATE_NAMES))
            self.assertEqual(receipt["completed_gates"], receipt["selected_gates"])
            self.assertEqual(receipt["gate_count"], 16)
            self.assertEqual(
                [(item.source_sha, item.profile, item.root) for item in boundary.identities],
                [(boundary.source_sha, ".", str(worker)),
                 (boundary.source_sha, "runtime", str(runtime))],
            )

    @unittest.skipUnless(sys.platform.startswith("linux"), "the shared launcher stop uses Linux process facilities")
    def test_shared_launcher_really_stops_before_the_command_runs(self):
        stdout_reader, stdout_writer = os.pipe()
        stderr_reader, stderr_writer = os.pipe()
        launch = ("/usr/bin/python3", "-B", "-c", linux_source_build.linux_probes.LAUNCHER_SOURCE, "/usr/bin/true")
        spec = {"mode": "open", "keep_root": True, "limits": "probe", "env": {"PATH": "/usr/bin"}, "timeout": 5}
        try:
            code, timed_out = linux_source_build.linux_session.launch_and_collect(
                spec, launch, "/", (None, stdout_writer), (None, stderr_writer), False,
            )
            self.assertEqual(code, 0)
            self.assertFalse(timed_out)
        finally:
            for descriptor in (stdout_reader, stdout_writer, stderr_reader, stderr_writer):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_audit_command_passes_empty_arguments_to_the_shared_cli(self):
        audit = types.SimpleNamespace(main=Mock(return_value=0))
        canary = types.SimpleNamespace(compute_config=Mock(return_value="config"), PINNED_CONFIG=None)
        with patch.object(linux_source_build, "_audit_modules", return_value=(audit, None, canary)):
            self.assertEqual(linux_source_build.main(["audit"]), 0)
        self.assertEqual(audit.main.call_args.kwargs["arguments"], [])
        self.assertIs(audit.main.call_args.kwargs["environ"], os.environ)

    def test_synthetic_entry_points_use_only_independent_proof_and_job_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            records = Path(temporary) / "kd-records"
            records.mkdir()
            merged = {
                "channels": {name: {"status": "blocked", "before": True, "after": True}
                             for name in linux_source_build.linux_channels.CHANNELS},
                "memory_canary": "absent", "readable_file_canary": "absent",
            }
            (records / "merged.json").write_text(json.dumps(merged), encoding="ascii")
            (records / "merged.json").chmod(0o600)
            sha = "a" * 40
            env = {
                "RUNNER_TEMP": temporary, "CI_SHA": sha,
                "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1", "CI_MODE": "synthetic",
                "PRODUCER_RESULT": "success", "VERDICT_RECORD": "forged producer value",
                "CI_EVENT_NAME": "workflow_dispatch", "CI_REPOSITORY": linux_source_build.REPOSITORY,
                "CI_SERVER_URL": "https://github.com", "CACHE_MODE": "none",
                "GITHUB_SHA": sha, "CI_REF": "refs/heads/main", "GITHUB_TOKEN": "read-token",
            }
            with patch.dict(os.environ, env, clear=True), patch.object(
                linux_source_build, "_reference_sha", side_effect=[sha, "b" * 40]
            ) as references, patch.object(linux_source_build, "_comparison", return_value="ahead") as comparison:
                self.assertEqual(linux_source_build.main(["preflight"]), 0)
                self.assertEqual(references.call_count, 2)
                comparison.assert_called_once()
                output = io.StringIO()
                with patch.object(linux_source_build.sys, "stdout", output):
                    self.assertEqual(linux_source_build.main(["verdict"]), 0)
                record = confinement_verdict.decode_line(output.getvalue().strip())
                self.assertTrue(confinement_verdict.confinement_accepted(record))
                self.assertEqual(record["project_execution"], "not_started")
                self.assertEqual(record["token_revocation"], "not-applicable")

    def test_forged_producer_record_cannot_turn_a_failed_source_job_into_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            records = Path(temporary) / "kd-records"
            records.mkdir()
            merged = {
                "channels": {name: {"status": "blocked", "before": True, "after": True}
                             for name in confinement_verdict.CHANNELS},
                "memory_canary": "absent", "readable_file_canary": "absent",
            }
            (records / "merged.json").write_text(json.dumps(merged), encoding="ascii")
            (records / "merged.json").chmod(0o600)
            forged = {
                "os": "linux", "boundary": "linux-ns-seccomp-uid", "control_sha": "a" * 40,
                "run_id": 7, "run_attempt": 1, "channels": merged["channels"],
                "memory_canary": "absent", "readable_file_canary": "absent",
                "handoff": "not-applicable", "project_execution": "completed",
                "gates": 13, "failed": 0, "token_revocation": "confirmed",
            }
            self.assertTrue(confinement_verdict.run_accepted(forged))
            env = {
                "RUNNER_TEMP": temporary, "CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7",
                "GITHUB_RUN_ATTEMPT": "1", "CI_MODE": "source", "PRODUCER_RESULT": "failure",
                "VERDICT_RECORD": json.dumps(forged),
            }
            output = io.StringIO()
            with patch.object(linux_source_build.sys, "stdout", output):
                self.assertEqual(linux_source_build.emit_verdict(env), 1)
            record = confinement_verdict.decode_line(output.getvalue().strip())
            self.assertEqual(record["project_execution"], "not_started")
            self.assertEqual(record["gates"], 0)
            self.assertEqual(record["token_revocation"], "unconfirmed")
            env["PRODUCER_RESULT"] = "success"
            self.assertEqual(linux_source_build._verdict_record(env)["project_execution"], "not_started")
            with patch.object(linux_source_build.sys, "stdout", io.StringIO()):
                self.assertEqual(linux_source_build.emit_verdict(env), 1)
            env["PRODUCER_RESULT"] = "forged"
            self.assertEqual(linux_source_build._verdict_record(env)["project_execution"], "not_started")

    def test_verifier_receipts_alone_establish_source_claims_and_producer_only_vetoes(self):
        with tempfile.TemporaryDirectory() as temporary:
            records = Path(temporary) / "kd-records"
            records.mkdir()
            merged = {
                "channels": {name: {"status": "blocked", "before": True, "after": True}
                             for name in confinement_verdict.CHANNELS},
                "memory_canary": "absent", "readable_file_canary": "absent",
            }
            (records / "merged.json").write_text(json.dumps(merged), encoding="ascii")
            (records / "merged.json").chmod(0o600)
            gates = {
                "schema_version": 1,
                "selected_gates": list(linux_source_build.GATES),
                "completed_gates": list(linux_source_build.GATES),
                "gates": {name: "passed" for name in linux_source_build.GATES},
                "gate_count": 13,
                "failed": 0,
            }
            receipt = {
                "schema_version": 1, "status": "confirmed", "control_sha": "a" * 40,
                "run_id": "7", "run_attempt": "1", "installation_id": "19",
                "rejected_after_revoke": True,
            }
            (records / "gates.json").write_text(json.dumps(gates), encoding="ascii")
            (records / "revocation.json").write_text(json.dumps(receipt), encoding="ascii")
            env = {
                "RUNNER_TEMP": temporary, "CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7",
                "GITHUB_RUN_ATTEMPT": "1", "SOURCE_READER_INSTALLATION_ID": "19",
                "CI_MODE": "source", "PRODUCER_RESULT": "success",
            }
            trusted = linux_source_build._verdict_record(env)
            self.assertTrue(confinement_verdict.run_accepted(trusted))
            with patch.object(linux_source_build.sys, "stdout", io.StringIO()):
                self.assertEqual(linux_source_build.emit_verdict(env), 0)
            env["PRODUCER_RESULT"] = "failure"
            self.assertEqual(linux_source_build._verdict_record(env), trusted)
            with patch.object(linux_source_build.sys, "stdout", io.StringIO()):
                self.assertEqual(linux_source_build.emit_verdict(env), 1)
            env["PRODUCER_RESULT"] = "success"
            gates["gates"]["format"] = "not-run"
            (records / "gates.json").write_text(json.dumps(gates), encoding="ascii")
            self.assertEqual(linux_source_build._verdict_record(env)["project_execution"], "not_started")
            gates["gates"]["format"] = "passed"
            (records / "gates.json").write_text(json.dumps(gates), encoding="ascii")
            receipt["rejected_after_revoke"] = False
            (records / "revocation.json").write_text(json.dumps(receipt), encoding="ascii")
            self.assertEqual(linux_source_build._verdict_record(env)["token_revocation"], "unconfirmed")

    def test_runtime_receipt_records_all_three_stages_without_changing_public_summary_shape(self):
        with tempfile.TemporaryDirectory() as temporary:
            records = Path(temporary) / "kd-records"
            records.mkdir()
            merged = {
                "channels": {name: {"status": "blocked", "before": True, "after": True}
                             for name in confinement_verdict.CHANNELS},
                "memory_canary": "absent", "readable_file_canary": "absent",
            }
            (records / "merged.json").write_text(json.dumps(merged), encoding="ascii")
            (records / "merged.json").chmod(0o600)
            selected = linux_source_build.GATES + linux_source_build.RUNTIME_GATE_NAMES
            gates = {
                "schema_version": 1,
                "selected_gates": list(selected),
                "completed_gates": list(selected),
                "gates": {name: "passed" for name in selected},
                "gate_count": len(selected),
                "failed": 0,
            }
            receipt = {
                "schema_version": 1, "status": "confirmed", "control_sha": "a" * 40,
                "run_id": "7", "run_attempt": "1", "installation_id": "19",
                "rejected_after_revoke": True,
            }
            (records / "gates.json").write_text(json.dumps(gates), encoding="ascii")
            (records / "revocation.json").write_text(json.dumps(receipt), encoding="ascii")
            env = {
                "RUNNER_TEMP": temporary, "CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7",
                "GITHUB_RUN_ATTEMPT": "1", "SOURCE_READER_INSTALLATION_ID": "19",
                "CI_MODE": "source", "PRODUCER_RESULT": "success",
            }
            public_record = linux_source_build._verdict_record(env)
            self.assertEqual(public_record["gates"], 13)
            self.assertTrue(confinement_verdict.run_accepted(public_record))
            gates["completed_gates"] = list(selected[:-1])
            (records / "gates.json").write_text(json.dumps(gates), encoding="ascii")
            self.assertEqual(linux_source_build._verdict_record(env)["project_execution"], "not_started")

    def test_unprivileged_handoff_refuses_wrong_owner_mode_and_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            records = Path(temporary) / "kd-records"
            records.mkdir()
            path = records / "merged.json"
            path.write_text('{"channels":{}}', encoding="ascii")
            path.chmod(0o600)
            reader = os.getuid()
            with patch.object(linux_source_build.os, "getuid", return_value=reader + 1):
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build.verify_proof_handoff({"RUNNER_TEMP": temporary})
            self.assertEqual(linux_source_build.verify_proof_handoff({"RUNNER_TEMP": temporary}), 0)
            path.chmod(0o644)
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build.verify_proof_handoff({"RUNNER_TEMP": temporary})
            path.unlink()
            path.symlink_to(records / "missing.json")
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build.verify_proof_handoff({"RUNNER_TEMP": temporary})

    @unittest.skipUnless(hasattr(os, "memfd_create"), "the verifier key descriptor uses memfd_create, which only Linux provides")
    def test_verifier_mints_only_for_the_bound_installation_and_repository(self):
        token = "g" * 40
        identity = {"owner": "KeelDock", "name": "private-source", "repository_id": "41"}
        env = {
            "SOURCE_READER_CLIENT_ID": "Iv1.abc123", "SOURCE_READER_INSTALLATION_ID": "19",
            "SOURCE_READER_PRIVATE_KEY": "-----BEGIN PRIVATE KEY-----\nfixture\n-----END PRIVATE KEY-----\n",
        }
        installation = {"id": 19, "account": {"login": "keeldock"}}
        issued = {"token": token, "permissions": {"contents": "read", "metadata": "read"}}
        repositories = {"total_count": 1, "repositories": [{"id": 41, "name": "private-source"}]}
        with patch.object(linux_source_build, "_source_inputs", return_value=identity), patch.object(
            linux_source_build.subprocess, "run", return_value=types.SimpleNamespace(returncode=0, stdout=b"s" * 256)
        ), patch.object(linux_source_build, "_api_request", side_effect=[
            (200, installation), (201, issued), (200, repositories),
        ]) as api, patch.object(linux_source_build, "_write_output") as output:
            transcript = io.StringIO()
            with patch.object(linux_source_build.sys, "stdout", transcript):
                self.assertEqual(linux_source_build.mint_verifier_token(env), 0)
            self.assertIn("::add-mask::" + token, transcript.getvalue())
            self.assertNotIn("fixture", transcript.getvalue())
            output.assert_called_once_with(env, {"token": token, "installation_id": "19"})
            self.assertEqual(api.call_args_list[1].args[0], "/app/installations/19/access_tokens")
            self.assertEqual(api.call_args_list[1].kwargs["payload"], {
                "repositories": ["private-source"], "permissions": {"contents": "read"},
            })
        with patch.object(linux_source_build, "_source_inputs", return_value=identity), patch.object(
            linux_source_build.subprocess, "run", return_value=types.SimpleNamespace(returncode=0, stdout=b"s" * 256)
        ), patch.object(linux_source_build, "_api_request", side_effect=[
            (200, installation), (201, issued), (200, {"total_count": 2, "repositories": repositories["repositories"]}),
        ]):
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build.mint_verifier_token(env)

    def test_shared_auditor_rejects_verdict_outside_the_plain_run_step(self):
        expected = linux_source_build._expected_run({
            "CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1", "CI_MODE": "synthetic",
        }, "b" * 64)
        steps = [{"name": name, "conclusion": "success"} for name in linux_source_build.VERDICT_STEP_NAMES]
        job = {"steps": steps}
        line = confinement_verdict.encode_line({
            "os": "linux", "boundary": "linux-ns-seccomp-uid", "control_sha": "a" * 40,
            "run_id": 7, "run_attempt": 1,
            "channels": {name: {"status": "blocked", "before": True, "after": True}
                         for name in confinement_verdict.CHANNELS},
            "memory_canary": "absent", "readable_file_canary": "absent",
            "handoff": "not-applicable", "project_execution": "not_started",
            "gates": 0, "failed": 0, "token_revocation": "not-applicable",
        }).encode("ascii")
        headers = [bytes((35, 35)) + b"[group]Run verified command\n" for unused in steps]
        good = b"".join(headers) + line + b"\n"
        confinement_public_audit._check_section(good, job, expected)
        bad = b"".join(headers[:-1]) + line + b"\n" + headers[-1]
        with self.assertRaises(confinement_public_audit.AuditRefusal):
            confinement_public_audit._check_section(bad, job, expected)

    def _write_manifests(self, directory, root_extra=None, workspace_extra=None):
        root = {
            "name": "synthetic-root", "version": "1.0.0", "workspaces": ["packages/*"],
            "devDependencies": {"typescript": "6.0.3"},
        }
        root.update(root_extra or {})
        package = {"name": "@synthetic/host-api", "version": "1.0.0"}
        package.update(workspace_extra or {})
        base = Path(directory)
        (base / "packages/host-api").mkdir(parents=True)
        (base / "package.json").write_text(json.dumps(root), encoding="ascii")
        (base / "packages/host-api/package.json").write_text(json.dumps(package), encoding="ascii")
        return base

    def test_manifest_digest_binds_the_exact_root_override_and_refuses_everything_else(self):
        with tempfile.TemporaryDirectory() as directory:
            plain = linux_source_build._manifest_digest(self._write_manifests(Path(directory) / "plain"))
        with tempfile.TemporaryDirectory() as directory:
            allowed = linux_source_build._manifest_digest(self._write_manifests(
                Path(directory) / "allowed", {"overrides": {"lightningcss": "1.33.0"}},
            ))
        self.assertNotEqual(plain, allowed)
        for index, root_extra in enumerate((
            {"overrides": {"lightningcss": "1.32.0"}}, {"overrides": {"lightningcss": "^1.33.0"}},
            {"overrides": {"lightningcss": {"x": "1.33.0"}}}, {"overrides": {"other": "1.33.0"}},
            {"overrides": {}}, {"overrides": ["lightningcss"]}, {"overrides": "1.33.0"}, {"overrides": None},
            {"overrides": {"lightningcss": "1.33.0", "other": "1.0.0"}},
            {"resolutions": {"a": "1.0.0"}}, {"bundleDependencies": ["a"]}, {"bundledDependencies": ["a"]},
        )):
            with self.subTest(root=root_extra), tempfile.TemporaryDirectory() as directory:
                base = self._write_manifests(Path(directory) / ("r%d" % index), root_extra)
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._manifest_digest(base)
        for index, workspace_extra in enumerate((
            {"overrides": {"lightningcss": "1.33.0"}}, {"overrides": {}}, {"resolutions": {"a": "1.0.0"}},
        )):
            with self.subTest(workspace=workspace_extra), tempfile.TemporaryDirectory() as directory:
                base = self._write_manifests(Path(directory) / ("w%d" % index), None, workspace_extra)
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._manifest_digest(base)



if __name__ == "__main__":
    unittest.main(verbosity=2)
