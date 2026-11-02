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
import gate_table
import confinement_public_audit
import confinement_verdict
import log_canary
import linux_source_build
import macos_core_contract
import npm_admission_bootstrap


def _path_only_lock(count, prefix="member"):
    names = [prefix + "-" + str(index) for index in range(count)]
    text = "version = 4\n"
    for index, name in enumerate(names):
        text += '\n[[package]]\nname = "' + name + '"\nversion = "0.1.0"\n'
        if index == 0 and count > 1:
            text += "dependencies = [\n"
            for dependency in names[1:]:
                text += ' "' + dependency + '",\n'
            text += "]\n"
    return text


def _registry_lock():
    return _path_only_lock(1) + (
        '\n[[package]]\nname = "serde"\nversion = "1.0.1"\nsource = "'
        + linux_source_build.rust_license_gate.cargo_lock_receipt.REGISTRY_SOURCE
        + '"\nchecksum = "' + "b" * 64 + '"\n'
    )


class LinuxSourceBuildTests(unittest.TestCase):
    def test_gate_order_matches_the_shared_macos_contracts(self):
        expected = (
            macos_core_contract.GATE_NAMES
            + macos_core_contract.PARSER_GATE_NAMES
            + foundation_node_feedback.NODE_GATE_NAMES
        )
        self.assertEqual(linux_source_build.GATES, expected)
        self.assertEqual(len(linux_source_build.GATES), 15)

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
                "Run all offline project gates",
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
            "Run independent offline project gates",
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
                "Run all offline project gates",
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
                self.assertEqual(
                    job["steps"],
                    ("Set up job",) + actual_steps + ("Post Mint scoped source-reader token", "Complete job"),
                )
                self.assertNotIn("Require trusted Rust licence admission", job["optional_steps"])
            else:
                self.assertEqual(job["steps"], ("Set up job",) + actual_steps + ("Complete job",))
                self.assertIn("Require trusted Rust licence admission", job["optional_steps"])

    def test_producer_and_independent_verifier_bind_license_gates_before_preparation(self):
        workflow = (Path(__file__).resolve().parents[2]
                    / ".github/workflows/linux-source-admission.yml").read_text(encoding="utf-8")
        blocks = {}
        for name in (
                "Require trusted Rust licence admission",
                "Fetch npm tarballs by committed lock integrity",
                "Prepare offline project inputs",
                "Run all offline project gates",
                "Require trusted Rust licence admission independently",
                "Fetch independent npm tarballs by lock integrity",
                "Prepare independent offline project inputs",
                "Run independent offline project gates"):
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
        self.assertIn("REQUESTED_SOURCE_SHA", blocks["Run all offline project gates"])
        independent_gate = workflow[
            workflow.index("      - name: Revoke verifier token and verify rejection"):
            workflow.index("      - name: Fetch independent npm tarballs by lock integrity")
        ]
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
        verifier_gates = workflow[workflow.index("      - name: Run independent offline project gates"):]
        verifier_gate_step = verifier_gates.split("\n      - name:", 1)[0]
        self.assertIn("REQUESTED_SOURCE_SHA", verifier_gate_step)
        self.assertIn("preserve-env=WORKER_PATH,CARGO_HOME,RUST_ROOT,NODE_BIN,RUNNER_TEMP,REQUESTED_SOURCE_SHA",
                      verifier_gates)
        self.assertIn("preserve-env=WORKER_PATH,CARGO_HOME,RUST_ROOT,NODE_BIN,RUNNER_TEMP,REQUESTED_SOURCE_SHA",
                      blocks["Run all offline project gates"])

    def test_expected_run_assigns_the_plain_verdict_job_and_action_post(self):
        base = {"CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1"}
        source = linux_source_build._expected_run({**base, "CI_MODE": "source"}, "b" * 64)
        synthetic = linux_source_build._expected_run({**base, "CI_MODE": "synthetic"}, "b" * 64)
        self.assertEqual(source["verdict_job"], "linux-source-admission-verdict")
        edged_verdict = ("Set up job",) + linux_source_build.VERDICT_STEP_NAMES + ("Complete job",)
        self.assertEqual(source["jobs"][source["verdict_job"]]["steps"], edged_verdict)
        self.assertEqual(synthetic["jobs"][synthetic["verdict_job"]]["steps"], edged_verdict)
        for run in (source, synthetic):
            for name in ("settings", "unit"):
                steps = run["jobs"]["linux-source-admission-" + name]["steps"]
                self.assertEqual((steps[0], steps[-1]), ("Set up job", "Complete job"))
        self.assertEqual(source["jobs"][source["verdict_job"]]["optional_steps"], ())
        self.assertEqual(
            synthetic["jobs"][synthetic["verdict_job"]]["optional_steps"],
            linux_source_build.OPTIONAL_VERDICT_SYNTHETIC_STEPS,
        )
        source_steps = source["jobs"]["linux-source-admission-source-read"]["steps"]
        self.assertEqual(source_steps[0], "Set up job")
        self.assertEqual(source_steps[-2:], ("Post Mint scoped source-reader token", "Complete job"))
        synthetic_steps = synthetic["jobs"]["linux-source-admission-source-read"]["steps"]
        self.assertNotIn("Post Mint scoped source-reader token", synthetic_steps)
        self.assertEqual((synthetic_steps[0], synthetic_steps[-1]), ("Set up job", "Complete job"))

    def test_toolchain_versions_are_pinned_and_the_node_archive_digest_is_the_official_release_digest(self):
        self.assertEqual(linux_source_build.NODE_VERSION, "24.22.1")
        self.assertEqual(linux_source_build.NPM_VERSION, "11.19.1")
        self.assertRegex(linux_source_build.NODE_LINUX_TARBALL_SHA256, r"\A[a-f0-9]{64}\Z")
        self.assertEqual(
            linux_source_build.NODE_LINUX_TARBALL_SHA256,
            "6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6",
        )
        source = Path(linux_source_build.__file__).read_text(encoding="utf-8")
        self.assertIn('"/node-v" + NODE_VERSION + "-linux-x64.tar.xz"', source)
        self.assertIn('node_archive = root / "node-linux-x64.tar.xz"', source)
        self.assertNotIn("COORDINATOR_FILL" + "_NODE", linux_source_build.NODE_LINUX_TARBALL_SHA256)
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
            "LINUX_SOURCE_ENVIRONMENT_NAME": "linux-source-read", "REQUESTED_ENVIRONMENT_NAME": "linux-source-read",
        }
        with patch.object(linux_source_build, "_validate_provenance_binding") as provenance:
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build._source_inputs(env)
            provenance.assert_not_called()
            env["LINUX_SOURCE_ALLOWED_FINGERPRINT"] = fingerprint
            self.assertEqual(linux_source_build._source_inputs(env)["reviewed_diff_sha256"], fingerprint)
            self.assertEqual(env["LINUX_SOURCE_ENVIRONMENT_NAME"], linux_source_build.ENVIRONMENT_NAME)
            provenance.assert_called_once()
            for name, value in (("LINUX_SOURCE_ENVIRONMENT_NAME", "source-read"), ("REQUESTED_ENVIRONMENT_NAME", "source-read")):
                with self.subTest(name=name):
                    changed = dict(env, **{name: value})
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                        linux_source_build._source_inputs(changed)
            provenance.assert_called_once()

    def _environment_calls(self, environment_updates=None, branch_names=("main", "untrusted"),
                           listing_updates=None, status=200):
        environment = {
            "name": "linux-source-read", "can_admins_bypass": False,
            "deployment_branch_policy": {"custom_branch_policies": True, "protected_branches": False},
        }
        environment.update(environment_updates or {})
        entries = [{"id": index + 1, "name": name, "type": "branch"} for index, name in enumerate(branch_names)]
        listing = {"total_count": len(entries), "branch_policies": entries}
        listing.update(listing_updates or {})
        calls = []

        def fake(path, token, method="GET", payload=None, expected=(200,)):
            calls.append((path, method, token))
            if path.endswith("/deployment-branch-policies?per_page=100"):
                return 200, listing
            return status, (environment if status == 200 else None)

        return fake, calls

    def test_environment_readback_accepts_only_the_reviewed_names_and_branch_policy(self):
        fake, calls = self._environment_calls()
        with patch.object(linux_source_build, "_api_request", side_effect=fake):
            self.assertIsNone(linux_source_build._verify_environment("token"))
        base = "/repos/" + linux_source_build.REPOSITORY + "/environments/linux-source-read"
        self.assertEqual(calls, [
            (base, "GET", "token"),
            (base + "/deployment-branch-policies?per_page=100", "GET", "token"),
        ])
        self.assertEqual(linux_source_build.ENVIRONMENT_NAME, "linux-source-read")
        self.assertEqual(linux_source_build.ENVIRONMENT_BRANCHES, ("main", "untrusted"))
        fake, calls = self._environment_calls(branch_names=("untrusted", "main"))
        with patch.object(linux_source_build, "_api_request", side_effect=fake):
            self.assertIsNone(linux_source_build._verify_environment("token"))

    def test_environment_readback_refuses_every_other_policy_shape(self):
        refused_policy = {"custom_branch_policies": True, "protected_branches": False}
        cases = (
            {"status": 404},
            {"environment_updates": {"name": "source-read"}},
            {"environment_updates": {"can_admins_bypass": True}},
            {"environment_updates": {"can_admins_bypass": None}},
            {"environment_updates": {"can_admins_bypass": "false"}},
            {"environment_updates": {"deployment_branch_policy": None}},
            {"environment_updates": {"deployment_branch_policy": dict(refused_policy, custom_branch_policies=False)}},
            {"environment_updates": {"deployment_branch_policy": dict(refused_policy, protected_branches=True)}},
            {"environment_updates": {"deployment_branch_policy": {"custom_branch_policies": True}}},
            {"branch_names": ("main",)},
            {"branch_names": ("untrusted",)},
            {"branch_names": ()},
            {"branch_names": ("main", "untrusted", "develop")},
            {"branch_names": ("main", "develop")},
            {"branch_names": ("main", "main")},
            {"branch_names": ("main", "untrusted*")},
            {"listing_updates": {"total_count": 3}},
            {"listing_updates": {"total_count": "2"}},
            {"listing_updates": {"branch_policies": "main"}},
            {"listing_updates": {"branch_policies": [{"name": "main", "type": "tag"}, {"name": "untrusted", "type": "branch"}]}},
            {"listing_updates": {"branch_policies": [{"name": 7, "type": "branch"}, {"name": "untrusted", "type": "branch"}]}},
            {"listing_updates": {"branch_policies": ["main", "untrusted"]}},
        )
        for index, case in enumerate(cases):
            with self.subTest(index=index, case=case):
                fake, calls = self._environment_calls(**case)
                with patch.object(linux_source_build, "_api_request", side_effect=fake):
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                        linux_source_build._verify_environment("token")
        with patch.object(linux_source_build, "_api_request", side_effect=AssertionError("no request")):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build._verify_environment("token", "source-read")

    def test_api_path_check_refuses_traversal_but_accepts_the_compare_range(self):
        base = "a" * 40
        head = "b" * 40
        repository = linux_source_build.REPOSITORY
        accepted = (
            "/repos/" + repository + "/compare/" + base + "..." + head,
            "/repos/" + repository + "/git/ref/heads/main",
            "/repos/" + repository + "/environments/linux-source-read/deployment-branch-policies?per_page=100",
            "/repos/" + repository + "/actions/workflows/linux-source-admission.yml/runs?per_page=100&status=queued",
            "/installation/token",
        )
        for path in accepted:
            with self.subTest(path=path):
                self.assertTrue(linux_source_build._safe_api_path(path))
        refused = (
            "", "repos/x", "/", "/repos//x", "/repos/x/", "/repos/../x", "/repos/x/..", "/repos/./x",
            "/repos/%2e%2e/x", "/repos/%2E%2e/x", "/repos/x\\y", "/repos/x\x00", None, 7,
        )
        for path in refused:
            with self.subTest(path=path):
                self.assertFalse(linux_source_build._safe_api_path(path))
        with patch.object(linux_source_build.urllib.request, "build_opener", side_effect=AssertionError("no request")):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "network"):
                linux_source_build._api_request("/repos/../x", "token")

    def test_comparison_sends_the_range_to_the_api_and_refuses_non_commit_values(self):
        base = "a" * 40
        head = "b" * 40
        requests = []

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, kind, value, trace):
                return False

            def read(self, size=-1):
                return b'{"status":"ahead"}'

        class Opener:
            def open(self, request, timeout=None):
                requests.append(request.full_url)
                return Response()

        with patch.object(linux_source_build.urllib.request, "build_opener", return_value=Opener()):
            self.assertEqual(linux_source_build._comparison("token", linux_source_build.REPOSITORY, base, head), "ahead")
            self.assertEqual(requests, [
                linux_source_build.API_ROOT + "/repos/" + linux_source_build.REPOSITORY
                + "/compare/" + base + "..." + head,
            ])
            for bad_base, bad_head in (("main", head), (base, "../x"), (base[:-1], head), (None, head), (base, 7)):
                with self.subTest(base=bad_base, head=bad_head):
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "network"):
                        linux_source_build._comparison("token", linux_source_build.REPOSITORY, bad_base, bad_head)
            self.assertEqual(len(requests), 1)

    def test_synthetic_dispatch_reaches_the_environment_readback_through_the_real_comparison(self):
        sha = "a" * 40
        env = {
            "CI_EVENT_NAME": "workflow_dispatch", "CI_REPOSITORY": linux_source_build.REPOSITORY,
            "CI_SERVER_URL": "https://github.com", "CACHE_MODE": "none",
            "CI_SHA": sha, "GITHUB_SHA": sha, "CI_REF": "refs/heads/main", "CI_MODE": "synthetic",
            "REQUESTED_ENVIRONMENT_NAME": "linux-source-read", "LINUX_SOURCE_ENVIRONMENT_NAME": "",
        }
        requests = []

        class Response:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, kind, value, trace):
                return False

            def read(self, size=-1):
                return b'{"status":"identical"}'

        class Opener:
            def open(self, request, timeout=None):
                requests.append(request.full_url)
                return Response()

        with patch.object(linux_source_build, "_reference_sha", side_effect=[sha, sha]), patch.object(
            linux_source_build.urllib.request, "build_opener", return_value=Opener()
        ), patch.object(linux_source_build, "_verify_environment") as environment, patch.object(
            linux_source_build, "_source_inputs", side_effect=AssertionError("no source binding in synthetic")
        ):
            self.assertEqual(linux_source_build.validate_dispatch(env, "token"), "synthetic")
            environment.assert_called_once_with("token")
        self.assertEqual(requests, [
            linux_source_build.API_ROOT + "/repos/" + linux_source_build.REPOSITORY
            + "/compare/" + sha + "..." + sha,
        ])

    def test_dispatch_reads_back_the_environment_after_binding_and_before_the_duplicate_check(self):
        sha = "a" * 40
        env = {
            "CI_EVENT_NAME": "workflow_dispatch", "CI_REPOSITORY": linux_source_build.REPOSITORY,
            "CI_SERVER_URL": "https://github.com", "CACHE_MODE": "none",
            "CI_SHA": sha, "GITHUB_SHA": sha, "CI_REF": "refs/heads/untrusted", "CI_MODE": "source",
        }
        order = []
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, sha]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ), patch.object(
            linux_source_build, "_source_inputs", side_effect=lambda unused: order.append("binding") or {}
        ), patch.object(
            linux_source_build, "_verify_environment", side_effect=lambda token: order.append("environment")
        ), patch.object(
            linux_source_build, "_require_no_duplicate", side_effect=lambda token, unused: order.append("duplicate")
        ):
            self.assertEqual(linux_source_build.validate_dispatch(env, "token"), "source")
        self.assertEqual(order, ["binding", "environment", "duplicate"])
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, sha]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ), patch.object(linux_source_build, "_source_inputs", return_value={}), patch.object(
            linux_source_build, "_verify_environment", side_effect=linux_source_build.SourceBuildRefusal("binding")
        ), patch.object(linux_source_build, "_require_no_duplicate") as duplicate:
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build.validate_dispatch(env, "token")
            duplicate.assert_not_called()

    def test_quick_tier_is_untrusted_and_source_only_and_checks_duplicates_in_its_own_workflow(self):
        sha = "a" * 40
        base = {
            "CI_EVENT_NAME": "workflow_dispatch", "CI_REPOSITORY": linux_source_build.REPOSITORY,
            "CI_SERVER_URL": "https://github.com", "CACHE_MODE": "none",
            "CI_SHA": sha, "GITHUB_SHA": sha, "KD_LINUX_TIER": "quick",
        }
        self.assertEqual(
            linux_source_build.TIERS["quick"], ("core-linux-quick-return.yml", "Linux quick source "),
        )
        self.assertEqual(
            linux_source_build.TIERS["admission"], ("linux-source-admission.yml", "Linux admission source "),
        )
        for ref, mode in (
            ("refs/heads/main", "source"), ("refs/heads/main", "synthetic"),
            ("refs/heads/untrusted", "synthetic"),
        ):
            with self.subTest(ref=ref, mode=mode), patch.object(
                linux_source_build, "_reference_sha", side_effect=["b" * 40, sha]
            ), patch.object(linux_source_build, "_comparison", return_value="ahead"):
                with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
                    linux_source_build.validate_dispatch(dict(base, CI_REF=ref, CI_MODE=mode), "token")
        with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
            linux_source_build.validate_dispatch(
                dict(base, KD_LINUX_TIER="other", CI_REF="refs/heads/untrusted", CI_MODE="source"), "token",
            )
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, sha]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ), patch.object(linux_source_build, "_source_inputs", return_value={}), patch.object(
            linux_source_build, "_verify_environment"
        ), patch.object(linux_source_build, "_require_no_duplicate") as duplicate:
            env = dict(base, CI_REF="refs/heads/untrusted", CI_MODE="source")
            self.assertEqual(linux_source_build.validate_dispatch(env, "token"), "source")
            duplicate.assert_called_once_with("token", env)
        calls = []

        def runs(title):
            def fake(path, token, method="GET", payload=None, expected=(200,)):
                calls.append(path)
                status = "queued" if path.endswith("status=queued") else "in_progress"
                return 200, {"total_count": 1, "workflow_runs": [{
                    "id": 9, "display_title": title + sha, "status": status, "event": "workflow_dispatch",
                }]}
            return fake

        environment = {"GITHUB_RUN_ID": "5", "REQUESTED_SOURCE_SHA": sha, "KD_LINUX_TIER": "quick"}
        with patch.object(linux_source_build, "_api_request", side_effect=runs("Linux quick source ")):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "duplicate"):
                linux_source_build._require_no_duplicate("token", environment)
        self.assertTrue(calls[0].startswith(
            "/repos/" + linux_source_build.REPOSITORY + "/actions/workflows/core-linux-quick-return.yml/runs?"
        ))
        with patch.object(linux_source_build, "_api_request", side_effect=runs("Linux admission source ")):
            self.assertIsNone(linux_source_build._require_no_duplicate("token", environment))
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "duplicate"):
                linux_source_build._require_no_duplicate("token", {"GITHUB_RUN_ID": "5", "REQUESTED_SOURCE_SHA": sha})
        self.assertTrue(calls[-1].startswith(
            "/repos/" + linux_source_build.REPOSITORY + "/actions/workflows/linux-source-admission.yml/runs?"
        ))

    def test_quick_expected_run_describes_the_quick_workflow_and_never_a_verdict(self):
        request = "ab" * 32
        base = {
            "KD_LINUX_TIER": "quick", "KD_QUICK_REQUEST_ID": request, "CI_SHA": "a" * 40,
            "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1", "REQUESTED_SOURCE_SHA": "c" * 40,
            "CI_REF": "refs/heads/untrusted", "CI_MODE": "source",
        }
        expected = linux_source_build._expected_run(base, "b" * 64)
        self.assertEqual(expected["mode"], "quick")
        self.assertEqual(expected["os"], "linux")
        self.assertEqual(expected["ci_ref"], "untrusted")
        self.assertEqual(expected["workflow_path"], ".github/workflows/core-linux-quick-return.yml")
        self.assertEqual(expected["display_title"], "Linux quick source " + "c" * 40)
        self.assertEqual(expected["request_id"], request)
        self.assertEqual(expected["artifact_names"], ("linux-quick-" + request,))
        self.assertEqual(expected["cache_digest"], "b" * 64)
        self.assertEqual(expected["quick_job"], "core-linux-quick-return-producer")
        self.assertEqual(expected["auditor_job"], "core-linux-quick-return-audit")
        self.assertNotIn("verdict_job", expected)
        self.assertNotIn("verdict_step", expected)
        self.assertEqual(
            sorted(expected["jobs"]),
            [
                "core-linux-quick-return-producer", "core-linux-quick-return-settings",
                "core-linux-quick-return-unit",
            ],
        )
        producer = expected["jobs"]["core-linux-quick-return-producer"]["steps"]
        self.assertEqual(producer, linux_source_build.QUICK_PRODUCER_STEP_NAMES)
        self.assertEqual(producer[0], "Set up job")
        self.assertEqual(producer[-1], "Complete job")
        self.assertEqual(producer[-2], "Post Mint scoped source-reader token")
        for spec in expected["jobs"].values():
            self.assertEqual(spec["optional_steps"], ())
            self.assertFalse(any("verdict" in step.lower() for step in spec["steps"]))
        self.assertEqual(
            confinement_public_audit.parse_expected(json.dumps(expected), True), expected,
        )
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/core-linux-quick-return.yml").read_text(
            encoding="utf-8",
        )
        producer_text = workflow.split("  core-linux-quick-return-producer:\n", 1)[1].split("  core-linux-quick-return-audit:\n", 1)[0]
        names = re.findall(r"(?m)^      - name: (.*)$", producer_text)
        self.assertEqual(["Set up job"] + names + ["Post Mint scoped source-reader token", "Complete job"],
                         list(producer))
        settings = workflow.split("  core-linux-quick-return-settings:\n", 1)[1].split("  core-linux-quick-return-unit:\n", 1)[0]
        self.assertEqual(
            ["Set up job"] + re.findall(r"(?m)^      - name: (.*)$", settings) + ["Complete job"],
            list(linux_source_build.QUICK_SETTINGS_STEP_NAMES),
        )
        for broken in ({"KD_QUICK_REQUEST_ID": "short"}, {"KD_QUICK_REQUEST_ID": ""}):
            with self.subTest(broken=broken), self.assertRaises(confinement_public_audit.AuditRefusal):
                linux_source_build._expected_run({**base, **broken}, "b" * 64)
        admission = linux_source_build._expected_run(
            {"CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1", "CI_MODE": "source"}, "b" * 64,
        )
        self.assertEqual(admission["mode"], "candidate")
        self.assertIn("verdict_job", admission)

    def test_quick_audit_runs_the_quick_mode_of_the_public_audit(self):
        calls = []

        def fake_main(arguments=None, environ=None):
            calls.append(list(arguments))
            return 0

        canary = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        for tier, arguments in (("quick", ["quick"]), ("admission", [])):
            with self.subTest(tier=tier), patch.object(
                confinement_public_audit, "main", side_effect=fake_main,
            ), patch.object(log_canary, "PINNED_CONFIG", log_canary.PINNED_CONFIG):
                code = linux_source_build.run_audit({"KD_LINUX_TIER": tier, "KD_LINUX_LOG_CANARY": canary})
                self.assertEqual(code, 0)
                self.assertEqual(calls[-1], arguments)

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
            (worker / "Cargo.lock").write_text(_path_only_lock(4), encoding="ascii")
            source_sha = "a" * 40
            commands = tuple(
                (name, ("/usr/bin/true",)) for name in linux_source_build.GATES
            )
            with patch.object(
                linux_source_build.rust_license_gate, "require_lock_admission",
                wraps=linux_source_build.rust_license_gate.require_lock_admission,
            ) as admission, patch.object(
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
                    "REQUESTED_SOURCE_SHA": source_sha,
                }), 0)
                self.assertEqual(directories.call_count, 15)
                self.assertEqual(session.call_count, 15)
                durations = json.loads((root / "kd-records" / "gate-durations.json").read_text(encoding="ascii"))
                self.assertEqual(durations["schema_version"], 1)
                self.assertEqual(set(durations["durations_ms"]), set(linux_source_build.GATES))
                self.assertTrue(all(type(value) is int and value >= 0 for value in durations["durations_ms"].values()))
                identity = admission.call_args_list[0].args[1]
                self.assertEqual(identity.profile, ".")
                self.assertEqual(identity.root, str(worker))
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
            (worker / "Cargo.lock").write_text(_registry_lock(), encoding="ascii")
            with patch.object(linux_source_build.rust_license_gate, "TRUSTED_PORTS", None), patch.object(
                linux_source_build, "_project_gate_directories",
            ) as prepare, patch.object(linux_source_build, "_gate_commands") as construct, patch.object(
                linux_source_build.linux_session, "run_host",
            ) as execute:
                with self.assertRaises(linux_source_build.rust_license_gate.LicenseGateRefusal) as refused:
                    linux_source_build.run_project_gates({
                        "RUNNER_TEMP": temporary, "WORKER_PATH": str(worker),
                        "CARGO_HOME": str(worker / ".kd-cargo-home"),
                        "RUST_ROOT": "/rust", "NODE_BIN": "/node",
                        "REQUESTED_SOURCE_SHA": "a" * 40,
                    })
            self.assertEqual(refused.exception.reason, "archive_producer_unavailable")
            prepare.assert_not_called()
            construct.assert_not_called()
            execute.assert_not_called()

    def test_empty_lock_refuses_with_lock_before_preparation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker = root / "source"
            worker.mkdir()
            (worker / "Cargo.lock").write_text("version = 4\n", encoding="ascii")
            with patch.object(
                linux_source_build, "_project_gate_directories",
            ) as prepare, patch.object(linux_source_build, "_gate_commands") as construct:
                with self.assertRaises(linux_source_build.rust_license_gate.LicenseGateRefusal) as refused:
                    linux_source_build.run_project_gates({
                        "RUNNER_TEMP": temporary, "WORKER_PATH": str(worker),
                        "CARGO_HOME": str(worker / ".kd-cargo-home"),
                        "RUST_ROOT": "/rust", "NODE_BIN": "/node",
                        "REQUESTED_SOURCE_SHA": "a" * 40,
                    })
            self.assertEqual(refused.exception.reason, "lock")
            prepare.assert_not_called()
            construct.assert_not_called()

    def test_registry_free_license_gate_prints_one_counts_only_line(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.lock").write_text(_path_only_lock(4), encoding="ascii")
            (root / "fuzz").mkdir()
            (root / "fuzz" / "Cargo.lock").write_text(
                _path_only_lock(2, "fuzz"), encoding="ascii")
            (root / "runtime").mkdir()
            (root / "runtime" / "Cargo.lock").write_text(
                _path_only_lock(7, "runtime"), encoding="ascii")
            output = io.StringIO()
            with patch.object(linux_source_build.sys, "stdout", output):
                self.assertEqual(linux_source_build.run_rust_license_gate({
                    "SOURCE_PATH": str(root), "REQUESTED_SOURCE_SHA": "a" * 40,
                }), 0)
            self.assertEqual(output.getvalue(), "linux-rust-licence=registry-free locks=3\n")

    def test_registry_lock_license_gate_refuses_without_the_counts_line(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "Cargo.lock").write_text(_registry_lock(), encoding="ascii")
            output = io.StringIO()
            with patch.object(linux_source_build.sys, "stdout", output):
                with self.assertRaises(linux_source_build.rust_license_gate.LicenseGateRefusal):
                    linux_source_build.run_rust_license_gate({
                        "SOURCE_PATH": str(root), "REQUESTED_SOURCE_SHA": "a" * 40,
                    })
            self.assertEqual(output.getvalue(), "")

    def _gate_over_tree(self, files, links=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, text in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="ascii")
            for name, target in (links or {}).items():
                (root / name).symlink_to(target, target_is_directory=True)
            output = io.StringIO()
            with patch.object(linux_source_build.sys, "stdout", output):
                code = linux_source_build.run_rust_license_gate({
                    "SOURCE_PATH": str(root), "REQUESTED_SOURCE_SHA": "a" * 40,
                })
            return code, output.getvalue()

    def _assert_tree_refused(self, files, links=None):
        with self.assertRaises(linux_source_build.SourceBuildRefusal) as refused:
            self._gate_over_tree(files, links)
        self.assertEqual(refused.exception.reason, "lock")

    def test_manifests_that_reach_outside_the_root_or_patch_are_refused(self):
        member = '[package]\nname = "inner"\nversion = "0.1.0"\nedition = "2024"\n\n'
        cases = {
            "absolute_path": member + '[dependencies]\nfoo = { path = "/opt/outside/foo" }\n',
            "parent_path": member + '[dependencies]\nfoo = { path = "../../../outside" }\n',
            "dev_table": member + '[dev-dependencies.foo]\npath = "../../../outside"\n',
            "build_table": member + '[build-dependencies]\nfoo = { path = "../../../outside" }\n',
            "target_table": member + '[target.x86_64-unknown-linux-gnu.dependencies]\nfoo = { path = "../../../outside" }\n',
            "patch": member + '[patch.crates-io]\nfoo = { path = "vendor/foo" }\n',
            "replace": member + '[replace]\n',
            "unknown_shape": member + '[dependencies]\nfoo = 3\n',
        }
        for label, manifest in cases.items():
            with self.subTest(case=label):
                self._assert_tree_refused({
                    "Cargo.lock": _path_only_lock(1),
                    "crates/inner/Cargo.toml": manifest,
                })
        with self.subTest(case="workspace_member_outside"):
            self._assert_tree_refused({
                "Cargo.lock": _path_only_lock(1),
                "Cargo.toml": '[workspace]\nmembers = ["../outside"]\n',
            })

    def test_one_level_up_from_a_nested_manifest_stays_inside_and_passes(self):
        manifest = (
            '[package]\nname = "inner"\nversion = "0.1.0"\nedition = "2024"\n\n'
            '[dependencies]\nfoo = { path = "../../outside" }\n'
        )
        self.assertEqual(
            self._gate_over_tree({
                "Cargo.lock": _path_only_lock(1), "crates/inner/Cargo.toml": manifest,
            }),
            (0, "linux-rust-licence=registry-free locks=1\n"),
        )

    def test_paths_into_directories_the_walk_skips_are_refused(self):
        head = '[package]\nname = "inner"\nversion = "0.1.0"\nedition = "2024"\n\n'
        for name in ("node_modules", "target", ".git", ".kd-cargo-home", ".npm-cache",
                     ".kd-npm-tarballs", ".kd-other", ".cargo"):
            with self.subTest(directory=name):
                self._assert_tree_refused({
                    "Cargo.lock": _path_only_lock(1),
                    "Cargo.toml": head + '[dependencies]\nfoo = { path = "' + name + '/x" }\n',
                })
        with self.subTest(directory="nested"):
            self._assert_tree_refused({
                "Cargo.lock": _path_only_lock(1),
                "crates/inner/Cargo.toml": head
                + '[dependencies]\nfoo = { path = "../../node_modules/x" }\n',
            })

    def test_directory_symlinks_in_the_tree_are_refused(self):
        self._assert_tree_refused(
            {"Cargo.lock": _path_only_lock(1), "Cargo.toml": '[workspace]\nmembers = []\n'},
            links={"loop": "."},
        )

    def test_manifest_path_resolution_refuses_a_symlink_component(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "real").mkdir()
            (root / "real" / "lib.rs").write_text("", encoding="ascii")
            (root / "hop").symlink_to(".", target_is_directory=True)
            descriptor = self._root_descriptor(root)
            check = linux_source_build._require_physical_manifest_path
            check(descriptor, (), "real/lib.rs")
            check(descriptor, (), "real/missing/lib.rs")
            check(descriptor, ("real",), "../real/lib.rs")
            for value in ("hop/real/lib.rs", "hop/../x", "real/../hop/real", "../x"):
                with self.subTest(value=value):
                    with self.assertRaises(linux_source_build.SourceBuildRefusal) as refused:
                        check(descriptor, (), value)
                    self.assertEqual(refused.exception.reason, "lock")

    def test_manifest_parser_behaviour_the_confinement_check_relies_on(self):
        parse = linux_source_build.cargo_lock_bootstrap._parse_manifest
        document = parse(
            b'[package]\nname = "a"\nbuild = false\n\n'
            b'[workspace]\nmembers = ["crates/*"]\n\n'
            b'[dependencies]\nfoo = { path = "../foo" }\n\n'
            b'[dev-dependencies.bar]\npath = "../bar"\n\n'
            b'[target.x86_64-unknown-linux-gnu.dependencies]\nbaz = { path = "../baz" }\n\n'
            b'[patch.crates-io]\nfoo = { path = "vendor/foo" }\n\n'
            b'[[bin]]\nname = "a"\npath = "src/main.rs"\n'
        )
        self.assertIs(document["package"]["build"], False)
        self.assertEqual(document["workspace"]["members"], ["crates/*"])
        self.assertEqual(document["dependencies"]["foo"], {"path": "../foo"})
        self.assertEqual(document["dev-dependencies"]["bar"], {"path": "../bar"})
        target = document["target"]["x86_64-unknown-linux-gnu"]
        self.assertEqual(target["dependencies"]["baz"], {"path": "../baz"})
        self.assertEqual(document["patch"]["crates-io"]["foo"], {"path": "vendor/foo"})
        self.assertEqual(document["bin"], [{"name": "a", "path": "src/main.rs"}])
        self.assertIn("replace", parse(b"[replace]\n"))
        refused = (
            b'a = "x\\y"\n', b'a = """x"""\n', b"[a]\n[a]\n", b"[[patch.unused]]\n",
            b"", b"a = \x00\n",
        )
        for data in refused:
            with self.subTest(data=data):
                with self.assertRaises(Exception):
                    parse(data)

    def test_in_root_path_dependencies_and_workspace_members_pass(self):
        files = {
            "Cargo.lock": _path_only_lock(2),
            "Cargo.toml": '[workspace]\nmembers = ["crates/inner", "crates/sibling"]\n',
            "crates/inner/Cargo.toml": (
                '[package]\nname = "inner"\nversion = "0.1.0"\nedition = "2024"\n\n'
                '[dependencies]\nsibling = { path = "../sibling" }\n'
            ),
            "crates/sibling/Cargo.toml": (
                '[package]\nname = "sibling"\nversion = "0.1.0"\nedition = "2024"\n'
            ),
        }
        self.assertEqual(
            self._gate_over_tree(files),
            (0, "linux-rust-licence=registry-free locks=1\n"),
        )

    def test_tree_without_any_lock_refuses_with_lock(self):
        self._assert_tree_refused({"Cargo.toml": '[workspace]\nmembers = []\n'})

    def test_gate_receipt_from_trusted_ports_prints_no_counts_line(self):
        gate = linux_source_build.rust_license_gate
        with patch.object(gate, "require_lock_admission", return_value=object()):
            self.assertEqual(self._gate_over_tree({"Cargo.lock": _registry_lock()}), (0, ""))

    def test_runtime_gate_receipt_requires_every_selected_stage_to_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            worker = root / "source"
            worker.mkdir()
            (worker / "Cargo.lock").write_text(_path_only_lock(4), encoding="ascii")
            runtime = worker / "runtime"
            runtime.mkdir(parents=True)
            (runtime / "Cargo.toml").write_text("[workspace]\n", encoding="ascii")
            (runtime / "Cargo.lock").write_text(_path_only_lock(7, "runtime"), encoding="ascii")
            source_sha = "a" * 40
            commands = tuple(
                (name, ("/usr/bin/true",))
                for name in linux_source_build.GATES + linux_source_build.RUNTIME_GATE_NAMES
            )
            with patch.object(
                linux_source_build.rust_license_gate, "require_lock_admission",
                wraps=linux_source_build.rust_license_gate.require_lock_admission,
            ) as admission, patch.object(
                linux_source_build, "_project_gate_directories"
            ), patch.object(
                linux_source_build, "_gate_commands", return_value=commands
            ), patch.object(linux_source_build.linux_session, "run_host", return_value=types.SimpleNamespace(
                exit_code=0, timed_out=False, stdout=b"", stderr=b""
            )):
                result = linux_source_build.run_project_gates({
                    "RUNNER_TEMP": temporary, "WORKER_PATH": str(worker),
                    "CARGO_HOME": str(worker / ".kd-cargo-home"), "RUST_ROOT": "/rust", "NODE_BIN": "/node",
                    "REQUESTED_SOURCE_SHA": source_sha,
                })
            self.assertEqual(result, 0)
            receipt = json.loads((Path(temporary) / "kd-records" / "gates.json").read_text(encoding="ascii"))
            self.assertEqual(receipt["selected_gates"], list(linux_source_build.GATES + linux_source_build.RUNTIME_GATE_NAMES))
            self.assertEqual(receipt["completed_gates"], receipt["selected_gates"])
            self.assertEqual(receipt["gate_count"], 18)
            self.assertEqual(
                sorted((call.args[1].source_sha, call.args[1].profile, call.args[1].root)
                       for call in admission.call_args_list),
                sorted([(source_sha, ".", str(worker)),
                        (source_sha, "runtime", str(runtime))]),
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
            ) as references, patch.object(linux_source_build, "_comparison", return_value="ahead") as comparison, patch.object(
                linux_source_build, "_verify_environment"
            ) as environment:
                self.assertEqual(linux_source_build.main(["preflight"]), 0)
                self.assertEqual(references.call_count, 2)
                comparison.assert_called_once()
                environment.assert_called_once_with("read-token")
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
                "gates": 15, "failed": 0, "token_revocation": "confirmed",
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
                "gate_count": 15,
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
            self.assertEqual(trusted["gates"], 15)
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

    def test_runtime_receipt_records_all_three_stages_and_the_public_verdict_reports_sixteen_gates(self):
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
            self.assertEqual(public_record["gates"], 18)
            self.assertEqual(len(selected), 18)
            self.assertIn(" gates=18 failed=0 ", confinement_verdict.encode_line(public_record))
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

    def _write_manifests(self, directory, root_extra=None, workspace_extra=None, kernel_extra=None):
        root = {
            "name": "synthetic-root", "version": "1.0.0", "workspaces": ["packages/*"],
            "devDependencies": {"typescript": "6.0.3"},
        }
        root.update(root_extra or {})
        package = {"name": "@synthetic/host-api", "version": "1.0.0"}
        package.update(workspace_extra or {})
        base = Path(directory)
        (base / "packages/host-api").mkdir(parents=True)
        (base / "packages/kernel-i18n").mkdir(parents=True)
        kernel = {"name": "@synthetic/kernel-i18n", "version": "1.0.0"}
        kernel.update(kernel_extra or {})
        (base / "package.json").write_text(json.dumps(root), encoding="ascii")
        (base / "packages/host-api/package.json").write_text(json.dumps(package), encoding="ascii")
        (base / "packages/kernel-i18n/package.json").write_text(json.dumps(kernel), encoding="ascii")
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

    def test_manifest_digest_binds_every_reviewed_workspace_in_the_shared_order(self):
        self.assertEqual(
            linux_source_build.MANIFEST_WORKSPACE_PATHS,
            ("packages/host-api", "packages/kernel-i18n"),
        )
        with tempfile.TemporaryDirectory() as directory:
            baseline = linux_source_build._manifest_digest(self._write_manifests(Path(directory) / "base"))
        expected = {
            "root": {
                "name": "synthetic-root", "version": "1.0.0", "workspaces": ["packages/*"],
                "devDependencies": {"typescript": "6.0.3"},
            },
            "workspaces": [
                {"path": "packages/host-api", "name": "@synthetic/host-api", "version": "1.0.0"},
                {"path": "packages/kernel-i18n", "name": "@synthetic/kernel-i18n", "version": "1.0.0"},
            ],
        }
        encoded = json.dumps(
            expected, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False,
        ).encode("ascii")
        self.assertEqual(baseline, hashlib.sha256(encoded).hexdigest())
        for index, kernel_extra in enumerate((
            {"version": "1.0.1"}, {"name": "@synthetic/kernel-other"},
            {"dependencies": {"left-pad": "1.3.0"}}, {"devDependencies": {"typescript": "6.0.3"}},
        )):
            with self.subTest(kernel=kernel_extra), tempfile.TemporaryDirectory() as directory:
                changed = linux_source_build._manifest_digest(
                    self._write_manifests(Path(directory) / ("k%d" % index), None, None, kernel_extra)
                )
                self.assertNotEqual(changed, baseline)

    def test_manifest_digest_refuses_an_unreviewed_kernel_workspace_manifest(self):
        for index, kernel_extra in enumerate((
            {"overrides": {"lightningcss": "1.33.0"}}, {"resolutions": {"a": "1.0.0"}},
            {"bundleDependencies": ["a"]}, {"bundledDependencies": ["a"]},
            {"dependencies": {"left-pad": "git+https://example.invalid/left-pad.git"}},
            {"dependencies": {"left-pad": "file:../left-pad"}},
            {"dependencies": {"Bad Name": "1.0.0"}}, {"version": 1},
        )):
            with self.subTest(kernel=kernel_extra), tempfile.TemporaryDirectory() as directory:
                base = self._write_manifests(Path(directory) / ("k%d" % index), None, None, kernel_extra)
                with self.assertRaises(linux_source_build.SourceBuildRefusal):
                    linux_source_build._manifest_digest(base)
        with tempfile.TemporaryDirectory() as directory:
            base = self._write_manifests(Path(directory) / "missing")
            (base / "packages/kernel-i18n/package.json").unlink()
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._manifest_digest(base)
        with tempfile.TemporaryDirectory() as directory:
            base = self._write_manifests(Path(directory) / "narrow", {"workspaces": ["packages/host-api"]})
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._manifest_digest(base)


LOCK_SHA = "5" * 64
RESOLVER = {"node_version": "24.22.1", "npm_version": "11.19.1"}
LOCKED = {
    "node_modules/fixture-lib": {"version": "1.5.0", "dev": True},
    "node_modules/tool-a": {"version": "9.0.0", "dev": True},
    "node_modules/tool-a/node_modules/fixture-lib": {"version": "1.5.0", "dev": True},
    "node_modules/runtime-lib": {"version": "1.0.0"},
}


def _synthetic_receipt():
    return {
        "schema_version": 1, "record_type": "npm-admission-proposal-receipt",
        "context": {
            "repository": "owner/source", "filing": "filing-one", "source_sha": "a" * 40,
            "base_sha": "b" * 40, "base_branch": "develop", "reviewed_diff_fingerprint": "c" * 64,
            "control_sha": "d" * 40,
        },
        "inputs_sha256": "1" * 64, "request_doc_sha256": "2" * 64, "lock_sha256": LOCK_SHA,
        "archive_set_sha256": "3" * 64, "package_set_sha256": "4" * 64,
        "packages": [{
            "path": "node_modules/fixture-lib", "name": "fixture-lib", "version": "1.5.0",
            "integrity": "sha512-" + "A" * 86 + "==", "sha256": "8" * 64,
            "audit_record_id": "pending-review",
        }],
    }


def _synthetic_evidence(now, finding_changes=None, **changes):
    policy_epoch = (now - 7200) * 1000
    finding = {
        "advisory_id": "9000001", "allow_expires_at_ms": policy_epoch + 30 * 86400 * 1000,
        "allow_justification_sha256": "6" * 64, "allow_removal_condition": "fixture-adopted-by-consumers",
        "name": "fixture-lib", "range": "<2.0.0", "severity": "moderate", "version": "1.5.0",
    }
    finding.update(finding_changes or {})
    evidence = {
        "schema_version": 1, "receipt_sha256": "7" * 64, "lock_sha256": LOCK_SHA,
        "inputs_sha256": "1" * 64, "run_id": "1234567890", "run_attempt": 1,
        "generated_at": now - 600, "expiry": now + 3600, "policy_epoch_ms": policy_epoch,
        "cutoff_epoch_ms": policy_epoch - 7 * 86400 * 1000, "minimum_age_seconds": 604800,
        "registry_origin": "registry.npmjs.org", "resolver": dict(RESOLVER),
        "attestation_verification": "not_performed",
        "totals": {
            "packages": 1, "distinct_names": 1, "compressed_bytes": 10, "unpacked_bytes": 20,
            "file_count": 2, "install_script_packages": 0, "native_packages": 0,
            "unattested_packages": 1, "peer_checks": 0, "optional_peers_missing": 0,
        },
        "advisory": {
            "endpoint": "npm-bulk-advisory-v1", "fetched_at": now - 500, "valid_until": now + 85900,
            "request_sha256": "9" * 64, "response_sha256": "e" * 64, "package_count": 1,
            "finding_count": 1, "status": "allowed_findings", "findings": [finding],
        },
        "duplicates": [],
        "packages": [{
            "path": "node_modules/fixture-lib", "name": "fixture-lib", "version": "1.5.0",
            "sha256": "8" * 64, "published": "2026-01-01T00:00:00.000Z", "age_days": 100,
            "licence": "MIT", "licence_elected": "MIT", "licence_flags": [], "install_scripts": [],
            "native_count": 0, "native_sample": [], "attested": False, "publisher": "someone",
            "deprecated": False, "dev": True, "optional": False, "compressed_bytes": 10,
            "unpacked_bytes": 20, "file_count": 2, "direct": False,
        }],
    }
    evidence.update(changes)
    return evidence


def _project_provenance(receipt, evidence_bytes):
    evidence = json.loads(evidence_bytes)
    record = {
        name: evidence[name] for name in (
            "schema_version", "receipt_sha256", "lock_sha256", "resolver", "minimum_age_seconds",
            "policy_epoch_ms", "cutoff_epoch_ms", "generated_at", "expiry", "advisory",
        )
    }
    record["context"] = receipt["context"]
    record["evidence_sha256"] = hashlib.sha256(evidence_bytes).hexdigest()
    return record


def _encode(record):
    return json.dumps(record, sort_keys=True, separators=(",", ":"))


def _allow(now_ms, **changes):
    allow = {
        "name": "fixture-lib", "version": "1.5.0", "severity": "moderate", "advisory_id": "9000001",
        "range": "<2.0.0", "allow_justification_sha256": "6" * 64,
        "allow_expires_at_ms": now_ms + 86400 * 1000,
        "allow_removal_condition": "fixture-adopted-by-consumers",
    }
    allow.update(changes)
    return allow


def _vulnerability(name, severity="moderate", via=None, nodes=None):
    return {
        "name": name, "severity": severity, "isDirect": False, "via": via, "effects": [],
        "range": "<2.0.0", "nodes": nodes, "fixAvailable": True,
    }


def _advisory_via(name="fixture-lib", source=9000001, severity="moderate", url=None):
    return {
        "source": source, "name": name, "dependency": name, "title": "fixture advisory",
        "url": url or linux_source_build.ADVISORY_URL_PREFIX + "GHSA-aaaa-bbbb-cccc", "severity": severity,
        "cwe": [], "cvss": {"score": 0, "vectorString": None}, "range": "<2.0.0",
    }


def _audit_json(vulnerabilities, **counts):
    metadata = {"info": 0, "low": 0, "moderate": len(vulnerabilities), "high": 0, "critical": 0,
                "total": len(vulnerabilities)}
    metadata.update(counts)
    return json.dumps({
        "auditReportVersion": 2, "vulnerabilities": vulnerabilities,
        "metadata": {"vulnerabilities": metadata, "dependencies": {"total": 4}},
    }).encode("ascii")


def _honoured_report():
    return _audit_json({
        "fixture-lib": _vulnerability(
            "fixture-lib", via=[_advisory_via()],
            nodes=["node_modules/fixture-lib", "node_modules/tool-a/node_modules/fixture-lib"],
        ),
        "tool-a": _vulnerability("tool-a", via=["fixture-lib"], nodes=["node_modules/tool-a"]),
    })


class LinuxNodeProvenanceAndAuditTests(unittest.TestCase):
    def setUp(self):
        self.now = int(time.time())
        self.now_ms = self.now * 1000

    def _environment(self, record):
        return {
            "LINUX_SOURCE_ACCEPTED_NODE_PROVENANCE_JSON": record if type(record) is str else _encode(record),
            "LINUX_SOURCE_ACCEPTED_NODE_LOCK_SHA256": LOCK_SHA,
        }

    def _provenance(self, **evidence_changes):
        evidence = _synthetic_evidence(self.now, **evidence_changes)
        encoded = json.dumps(evidence, sort_keys=True, separators=(",", ":")).encode("ascii")
        return _project_provenance(_synthetic_receipt(), encoded)

    def _refused(self, record):
        with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "lock"):
            linux_source_build._validate_provenance_binding({}, self._environment(record))

    def test_provenance_shape_matches_the_trusted_receipt_and_evidence_structure(self):
        receipt = _synthetic_receipt()
        evidence = _synthetic_evidence(self.now)
        self.assertEqual(set(receipt), npm_admission_bootstrap.RECEIPT_FIELDS)
        self.assertEqual(set(receipt["context"]), npm_admission_bootstrap.TRUSTED_CONTEXT_FIELDS)
        self.assertEqual(set(evidence), npm_admission_bootstrap.EVIDENCE_FIELDS)
        self.assertEqual(set(evidence["advisory"]), npm_admission_bootstrap.ADVISORY_FIELDS)
        self.assertEqual(set(evidence["packages"][0]), npm_admission_bootstrap.EVIDENCE_PACKAGE_FIELDS)
        provenance = self._provenance()
        self.assertEqual(set(provenance), linux_source_build.PROVENANCE_FIELDS)
        self.assertEqual(
            linux_source_build.PROVENANCE_FIELDS - {"context", "evidence_sha256"},
            linux_source_build.PROVENANCE_FIELDS & npm_admission_bootstrap.EVIDENCE_FIELDS,
        )
        self.assertEqual(
            linux_source_build.PROVENANCE_CONTEXT_FIELDS, npm_admission_bootstrap.TRUSTED_CONTEXT_FIELDS,
        )
        self.assertEqual(
            linux_source_build.PROVENANCE_ADVISORY_FIELDS, npm_admission_bootstrap.ADVISORY_FIELDS,
        )
        self.assertEqual(set(provenance["advisory"]["findings"][0]), linux_source_build.PROVENANCE_FINDING_FIELDS)
        self.assertEqual(linux_source_build.PROVENANCE_RESOLVER_FIELDS, set(evidence["resolver"]))
        self.assertEqual(linux_source_build.NODE_VERSION, evidence["resolver"]["node_version"])
        self.assertEqual(linux_source_build.NPM_VERSION, evidence["resolver"]["npm_version"])
        self.assertLess(
            len(_encode(provenance)), linux_source_build.MAX_PROVENANCE_BYTES,
        )
        record = linux_source_build._validate_provenance_binding({}, self._environment(provenance))
        self.assertEqual(record["advisory"]["findings"][0]["advisory_id"], "9000001")

    def test_provenance_accepts_a_clear_advisory_result(self):
        record = self._provenance()
        record["advisory"] = dict(record["advisory"], status="clear", finding_count=0, findings=[])
        accepted = linux_source_build._validate_provenance_binding({}, self._environment(record))
        self.assertEqual(accepted["advisory"]["findings"], [])

    def test_provenance_refuses_fields_the_trusted_run_cannot_supply(self):
        for name in ("status", "age_status", "generation_attempts", "audit_status", "manifest_sha256"):
            with self.subTest(extra=name):
                self._refused(dict(self._provenance(), **{name: "passed"}))
        for name in linux_source_build.PROVENANCE_FIELDS:
            with self.subTest(missing=name):
                record = self._provenance()
                del record[name]
                self._refused(record)

    def test_provenance_refuses_a_changed_binding_or_stale_run(self):
        changes = {
            "lock": {"lock_sha256": "0" * 64},
            "node": {"resolver": {"node_version": "24.0.0", "npm_version": "11.19.1"}},
            "npm": {"resolver": {"node_version": "24.22.1", "npm_version": "10.0.0"}},
            "age": {"minimum_age_seconds": 86400},
            "cutoff": {"cutoff_epoch_ms": 1},
            "expired": {"expiry": self.now - 1},
            "future": {"generated_at": self.now + 3600},
            "before_policy": {"generated_at": 1},
            "receipt": {"receipt_sha256": "short"},
            "schema": {"schema_version": 2},
            "boolean": {"schema_version": True},
        }
        for label, change in changes.items():
            with self.subTest(change=label):
                self._refused(dict(self._provenance(), **change))
        for label, text in (("empty", ""), ("array", "[]"), ("text", "not json"), ("big", " " * 40000)):
            with self.subTest(text=label):
                self._refused(text)
        duplicate = _encode(self._provenance()).replace('"schema_version":1', '"schema_version":1,"schema_version":1')
        self._refused(duplicate)
        self._refused(_encode(self._provenance()).replace('"expiry":', '"expiry":NaN,"x":'))

    def test_provenance_refuses_an_unsound_allowed_finding(self):
        changes = {
            "high": {"severity": "high"},
            "critical": {"severity": "critical"},
            "unknown_severity": {"severity": "urgent"},
            "expired_at_fetch": {"allow_expires_at_ms": (self.now - 500) * 1000},
            "beyond_ttl": {"allow_expires_at_ms": (self.now - 7200) * 1000 + 91 * 86400 * 1000},
            "before_policy": {"allow_expires_at_ms": 1},
            "version": {"version": ">=1"},
            "name": {"name": "Not A Name"},
            "justification": {"allow_justification_sha256": "abc"},
            "identifier": {"advisory_id": "bad id"},
            "range": {"range": ""},
            "condition": {"allow_removal_condition": 5},
        }
        for label, change in changes.items():
            with self.subTest(change=label):
                evidence = _synthetic_evidence(self.now, finding_changes=change)
                encoded = json.dumps(evidence).encode("ascii")
                self._refused(_project_provenance(_synthetic_receipt(), encoded))
        record = self._provenance()
        advisory = record["advisory"]
        for label, change in {
            "count": {"finding_count": 2},
            "clear_with_findings": {"status": "clear"},
            "endpoint": {"endpoint": "other"},
            "request": {"request_sha256": "x"},
            "valid": {"valid_until": 1},
            "duplicate": {"findings": advisory["findings"] * 2, "finding_count": 2},
            "extra": {"findings": [dict(advisory["findings"][0], consumers=["a"])]},
        }.items():
            with self.subTest(advisory=label):
                self._refused(dict(record, advisory=dict(advisory, **change)))
        self._refused(dict(record, context=dict(record["context"], base_branch="feature")))
        self._refused(dict(record, context=dict(record["context"], source_sha="abc")))

    def test_audit_honours_exactly_the_recorded_findings(self):
        allows = [_allow(self.now_ms)]
        counts = linux_source_build._check_audit_report(_honoured_report(), allows, LOCKED, self.now_ms)
        self.assertEqual(counts, (2, 1, 1))
        github_form = [_allow(self.now_ms, advisory_id="GHSA-aaaa-bbbb-cccc")]
        self.assertEqual(
            linux_source_build._check_audit_report(_honoured_report(), github_form, LOCKED, self.now_ms), (2, 1, 1),
        )
        clean = _audit_json({})
        self.assertEqual(linux_source_build._check_audit_report(clean, allows, LOCKED, self.now_ms), (0, 0, 0))

    def _audit_refused(self, report, allows=None, packages=None, now_ms=None):
        with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "lock"):
            linux_source_build._check_audit_report(
                report, [_allow(self.now_ms)] if allows is None else allows,
                LOCKED if packages is None else packages, self.now_ms if now_ms is None else now_ms,
            )

    def test_audit_refuses_an_extra_finding(self):
        other = _audit_json({
            "fixture-lib": _vulnerability(
                "fixture-lib", via=[_advisory_via(), _advisory_via(source=9000002, url=linux_source_build.ADVISORY_URL_PREFIX + "GHSA-dddd-eeee-ffff")],
                nodes=["node_modules/fixture-lib"],
            ),
        })
        self._audit_refused(other)
        runtime = _audit_json({
            "runtime-lib": _vulnerability("runtime-lib", via=[_advisory_via("runtime-lib")], nodes=["node_modules/runtime-lib"]),
        })
        self._audit_refused(runtime)
        self._audit_refused(_honoured_report(), allows=[])
        self._audit_refused(_honoured_report(), allows=[_allow(self.now_ms, name="other-lib")])
        self._audit_refused(_honoured_report(), allows=[_allow(self.now_ms, advisory_id="9000002")])
        dangling = _audit_json({
            "tool-a": _vulnerability("tool-a", via=["fixture-lib"], nodes=["node_modules/tool-a"]),
        })
        self._audit_refused(dangling)
        selfish = _audit_json({
            "fixture-lib": _vulnerability("fixture-lib", via=["fixture-lib"], nodes=["node_modules/fixture-lib"]),
        })
        self._audit_refused(selfish)

    def test_audit_refuses_an_expired_allow(self):
        self._audit_refused(_honoured_report(), allows=[_allow(self.now_ms, allow_expires_at_ms=self.now_ms - 1)])
        self._audit_refused(_honoured_report(), now_ms=self.now_ms + 2 * 86400 * 1000)

    def test_audit_refuses_a_severity_above_the_recorded_one(self):
        high_via = _audit_json({
            "fixture-lib": _vulnerability(
                "fixture-lib", via=[_advisory_via(severity="high")], nodes=["node_modules/fixture-lib"],
            ),
        })
        self._audit_refused(high_via)
        high_entry = _audit_json({
            "fixture-lib": _vulnerability(
                "fixture-lib", severity="high", via=[_advisory_via()], nodes=["node_modules/fixture-lib"],
            ),
        })
        self._audit_refused(high_entry)
        critical = _audit_json({}, critical=1)
        self._audit_refused(critical)
        self._audit_refused(_audit_json({}, high=1))
        self._audit_refused(_honoured_report(), allows=[_allow(self.now_ms, severity="low")])
        self._audit_refused(_honoured_report(), allows=[_allow(self.now_ms, severity="high")])

    def test_audit_refuses_a_finding_that_is_not_development_only(self):
        runtime = dict(LOCKED, **{"node_modules/fixture-lib": {"version": "1.5.0"}})
        self._audit_refused(_honoured_report(), packages=runtime)
        nested = dict(LOCKED, **{"node_modules/tool-a/node_modules/fixture-lib": {"version": "1.5.0", "dev": False}})
        self._audit_refused(_honoured_report(), packages=nested)
        elsewhere = dict(LOCKED, **{"node_modules/other/node_modules/fixture-lib": {"version": "1.5.0"}})
        self._audit_refused(_honoured_report(), packages=elsewhere)
        newer = dict(LOCKED, **{"node_modules/fixture-lib": {"version": "1.6.0", "dev": True}})
        self._audit_refused(_honoured_report(), packages=newer)
        no_nodes = _audit_json({"fixture-lib": _vulnerability("fixture-lib", via=[_advisory_via()], nodes=[])})
        self._audit_refused(no_nodes)
        missing = _audit_json({"fixture-lib": _vulnerability("fixture-lib", via=[_advisory_via()], nodes=["node_modules/absent"])})
        self._audit_refused(missing)
        wrong_name = _audit_json({"fixture-lib": _vulnerability("fixture-lib", via=[_advisory_via()], nodes=["node_modules/runtime-lib"])})
        self._audit_refused(wrong_name)
        runtime_consumer = _audit_json({
            "fixture-lib": _vulnerability("fixture-lib", via=[_advisory_via()], nodes=["node_modules/fixture-lib"]),
            "runtime-lib": _vulnerability("runtime-lib", via=["fixture-lib"], nodes=["node_modules/runtime-lib"]),
        })
        self._audit_refused(runtime_consumer)

    def test_audit_refuses_malformed_json_and_shapes(self):
        good = json.loads(_honoured_report())
        for label, payload in {
            "empty": b"",
            "text": b"not json",
            "truncated": _honoured_report()[:-5],
            "non_utf8": b"\xff\xfe",
            "array": b"[]",
            "constant": b'{"auditReportVersion":2,"vulnerabilities":NaN,"metadata":{}}',
            "duplicate": b'{"auditReportVersion":2,"auditReportVersion":2,"vulnerabilities":{},"metadata":{}}',
            "error": json.dumps({"error": {"code": "ENOAUDIT", "summary": "x", "detail": "y"}}).encode("ascii"),
            "version": json.dumps(dict(good, auditReportVersion=1)).encode("ascii"),
            "extra_key": json.dumps(dict(good, extra={})).encode("ascii"),
            "vulnerabilities": json.dumps(dict(good, vulnerabilities=[])).encode("ascii"),
            "metadata": json.dumps(dict(good, metadata=[])).encode("ascii"),
            "counts": json.dumps(dict(good, metadata={"vulnerabilities": []})).encode("ascii"),
            "entry": json.dumps(dict(good, vulnerabilities={"fixture-lib": []})).encode("ascii"),
            "name": json.dumps(dict(good, vulnerabilities={"fixture-lib": _vulnerability("other", via=["x"], nodes=[])})).encode("ascii"),
            "via": json.dumps(dict(good, vulnerabilities={"fixture-lib": _vulnerability("fixture-lib", via=[], nodes=["node_modules/fixture-lib"])})).encode("ascii"),
            "via_type": json.dumps(dict(good, vulnerabilities={"fixture-lib": _vulnerability("fixture-lib", via=[5], nodes=["node_modules/fixture-lib"])})).encode("ascii"),
            "source_type": json.dumps(dict(good, vulnerabilities={"fixture-lib": _vulnerability("fixture-lib", via=[_advisory_via(source=True)], nodes=["node_modules/fixture-lib"])})).encode("ascii"),
            "nodes_type": json.dumps(dict(good, vulnerabilities={"fixture-lib": _vulnerability("fixture-lib", via=[_advisory_via()], nodes="node_modules/fixture-lib")})).encode("ascii"),
            "severity_type": json.dumps(dict(good, vulnerabilities={"fixture-lib": _vulnerability("fixture-lib", severity=["moderate"], via=[_advisory_via()], nodes=["node_modules/fixture-lib"])})).encode("ascii"),
            "key": json.dumps(dict(good, vulnerabilities={"Bad Name": _vulnerability("Bad Name", via=["x"], nodes=[])})).encode("ascii"),
            "deep": b"[" * 100000,
        }.items():
            with self.subTest(payload=label):
                self._audit_refused(payload)
        many = {"pkg-" + str(index): _vulnerability("pkg-" + str(index), via=["pkg-0"], nodes=[]) for index in range(linux_source_build.MAX_AUDIT_VULNERABILITIES + 1)}
        self._audit_refused(_audit_json(many))
        wide = _vulnerability("fixture-lib", via=["tool-a"] * (linux_source_build.MAX_AUDIT_VIA + 1), nodes=["node_modules/fixture-lib"])
        self._audit_refused(_audit_json({"fixture-lib": wide, "tool-a": _vulnerability("tool-a", via=["fixture-lib"], nodes=["node_modules/tool-a"])}))

    def _run_audit(self, returncode, stdout, allows=None, valid_until=None, entry=None, missing_node=False,
                   source_inputs=None, check_lock=None, run=None, stderr=b""):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "source").mkdir()
            (root / "source/package-lock.json").write_bytes(b"{}")
            (root / "bin").mkdir()
            if not missing_node:
                (root / "bin/node").write_bytes(b"")
            (root / "bin/npm").write_bytes(b"")
            env = {"SOURCE_PATH": str(root / "source"), "NODE_BIN": str(root / "bin"), "RUNNER_TEMP": str(root)}
            result = types.SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)
            record = {"advisory": {
                "findings": [_allow(self.now_ms)] if allows is None else allows,
                "valid_until": self.now + 3600 if valid_until is None else valid_until,
            }}
            output = io.StringIO()
            command = linux_source_build.run_trusted_audit if entry is None else entry
            with patch.object(linux_source_build, "_neutralize_config_files"), \
                    patch.object(linux_source_build, "_source_inputs", return_value={}, side_effect=source_inputs), \
                    patch.object(linux_source_build, "_check_lock_provenance", side_effect=check_lock), \
                    patch.object(linux_source_build, "_validate_provenance_binding", return_value=record), \
                    patch.object(linux_source_build, "_locked_packages", return_value=({"packages": LOCKED}, {})), \
                    patch.object(linux_source_build, "_run", return_value=result, side_effect=run), \
                    patch("sys.stdout", output):
                code = command(env)
            return code, output.getvalue()

    def test_trusted_audit_accepts_the_recorded_finding_with_counts_only(self):
        code, output = self._run_audit(1, _honoured_report())
        self.assertEqual(code, 0)
        self.assertEqual(output, "linux-node-audit=verified phase=trusted findings=2 allowed=1\n")
        code, output = self._run_audit(0, _audit_json({}))
        self.assertEqual((code, output), (0, "linux-node-audit=verified phase=trusted findings=0 allowed=0\n"))

    def test_trusted_audit_refuses_with_the_same_public_reason(self):
        extra = _audit_json({
            "runtime-lib": _vulnerability("runtime-lib", via=[_advisory_via("runtime-lib")], nodes=["node_modules/runtime-lib"]),
        })
        cases = (
            (1, extra, None), (1, _honoured_report(), []), (1, b"not json", None), (2, _honoured_report(), None),
            (1, _audit_json({}), None), (0, _honoured_report(), None), (1, b"", None),
            (1, _honoured_report(), [_allow(self.now_ms, allow_expires_at_ms=self.now_ms - 1)]),
        )
        for index, (returncode, stdout, allows) in enumerate(cases):
            with self.subTest(case=index), self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "lock"):
                self._run_audit(returncode, stdout, allows)


def _dispatch_audit(env):
    with patch.dict(os.environ, env):
        return linux_source_build._dispatch("trusted-audit")


def _lib(**changes):
    entry = _vulnerability("fixture-lib", via=[_advisory_via()], nodes=["node_modules/fixture-lib"])
    entry.update(changes)
    return entry


LINE_PATTERN = re.compile(
    r"linux-source-build=refused phase=trusted-audit reason=[a-z_]+ detail=audit_[a-z_]+( count=[0-9]{1,2})?\n"
)


class LinuxAuditDetailTests(unittest.TestCase):
    _run_audit = LinuxNodeProvenanceAndAuditTests._run_audit

    def setUp(self):
        self.now = int(time.time())
        self.now_ms = self.now * 1000

    def _detail(self, report, allows=None, packages=None, now_ms=None, stderr=b""):
        with self.assertRaises(linux_source_build.SourceBuildRefusal) as refused:
            linux_source_build._check_audit_report(
                report, [_allow(self.now_ms)] if allows is None else allows,
                LOCKED if packages is None else packages, self.now_ms if now_ms is None else now_ms, stderr,
            )
        self.assertEqual(refused.exception.reason, "lock")
        return refused.exception

    def _report_cases(self):
        good = json.loads(_honoured_report())
        many = {"pkg-" + str(index): _vulnerability("pkg-" + str(index), via=["pkg-0"], nodes=[])
                for index in range(linux_source_build.MAX_AUDIT_VULNERABILITIES + 1)}
        runtime = dict(LOCKED, **{"node_modules/fixture-lib": {"version": "1.5.0"}})
        newer = dict(LOCKED, **{"node_modules/fixture-lib": {"version": "1.6.0", "dev": True}})
        cycle = _audit_json({
            "tool-a": _vulnerability("tool-a", via=["fixture-lib"], nodes=["node_modules/tool-a"]),
            "fixture-lib": _vulnerability("fixture-lib", via=["tool-a"], nodes=["node_modules/fixture-lib"]),
        })
        low_root = _audit_json({
            "fixture-lib": _lib(severity="low", via=[_advisory_via(severity="low")]),
            "tool-a": _vulnerability("tool-a", via=["fixture-lib"], nodes=["node_modules/tool-a"]),
        }, low=1, moderate=1)
        return {
            "audit_json_empty": (b" \n\t", None, None, None),
            "audit_json_encoding": (b'{"fixture-marker": "\xff"}', None, None, None),
            "audit_json_prefix": (b"not json", None, None, None),
            "audit_json_trailing": (b'{"fixture-marker": 1}\n{}', None, None, None),
            "audit_json_duplicate": (b'{"fixture-marker": 1, "fixture-marker": 2}', None, None, None),
            "audit_json_syntax": (b'{"fixture-marker": }', None, None, None),
            "audit_json_not_object": (b"[]", None, None, None),
            "audit_top_keys": (json.dumps(dict(good, extra={})).encode("ascii"), None, None, None),
            "audit_version": (json.dumps(dict(good, auditReportVersion=1)).encode("ascii"), None, None, None),
            "audit_entry_shape": (json.dumps(dict(good, vulnerabilities=[])).encode("ascii"), None, None, None),
            "audit_meta": (json.dumps(dict(good, metadata=[])).encode("ascii"), None, None, None),
            "audit_limit": (_audit_json(many), None, None, None),
            "audit_count": (_audit_json({}, moderate=-1), None, None, None),
            "audit_high": (_audit_json({}, high=1), None, None, None),
            "audit_key_name": (_audit_json({"Bad Name": _lib(name="Bad Name")}), None, None, None),
            "audit_severity": (_audit_json({"fixture-lib": _lib(severity="high")}), None, None, None),
            "audit_via_shape": (_audit_json({"fixture-lib": _lib(via=[5])}), None, None, None),
            "audit_via_unknown": (_audit_json({"fixture-lib": _lib(via=["absent-lib"])}), None, None, None),
            "audit_advisory_unmatched": (_honoured_report(), [], None, None),
            "audit_allow_expired": (_honoured_report(), [_allow(self.now_ms, allow_expires_at_ms=self.now_ms - 1)], None, None),
            "audit_advisory_severity": (_audit_json({"fixture-lib": _lib(via=[_advisory_via(severity="high")])}), None, None, None),
            "audit_nodes_shape": (_audit_json({"fixture-lib": _lib(nodes=[])}), None, None, None),
            "audit_nondev": (_honoured_report(), None, runtime, None),
            "audit_version_not_allowed": (_honoured_report(), None, newer, None),
            "audit_consumer_over_ceiling": (low_root, [_allow(self.now_ms, severity="low")], None, None),
            "audit_consumer_unreached": (cycle, None, None, None),
        }

    def test_every_report_detail_token_is_produced_by_its_case(self):
        cases = self._report_cases()
        for token, (report, allows, packages, now_ms) in cases.items():
            with self.subTest(token=token):
                self.assertEqual(self._detail(report, allows, packages, now_ms).detail, token)

    def test_every_run_detail_token_is_produced_by_its_case(self):
        refusal = linux_source_build.SourceBuildRefusal("lock")
        cases = {
            "audit_toolchain": dict(returncode=1, stdout=b"", missing_node=True),
            "audit_provenance": dict(returncode=1, stdout=b"", source_inputs=refusal),
            "audit_advisory_expired": dict(returncode=1, stdout=_honoured_report(), valid_until=self.now - 1),
            "audit_run": dict(returncode=1, stdout=b"", run=OSError("x")),
            "audit_exit": dict(returncode=2, stdout=_honoured_report()),
            "audit_lock_changed": dict(returncode=1, stdout=_honoured_report(), check_lock=[None, refusal]),
            "audit_exit_mismatch": dict(returncode=0, stdout=_honoured_report()),
        }
        for token, arguments in cases.items():
            with self.subTest(token=token), self.assertRaises(linux_source_build.SourceBuildRefusal) as refused:
                self._run_audit(**arguments)
            self.assertEqual(refused.exception.detail, token)
        covered = set(self._report_cases()) | set(cases) | {
            "audit_json_empty_stderr_json", "audit_json_empty_stderr_text", "audit_unclassified", "audit_unexpected",
        }
        self.assertEqual(covered, set(linux_source_build.AUDIT_DETAILS))

    def _json_line(self, stdout, stderr=b""):
        code, output = self._run_audit(1, stdout, entry=_dispatch_audit, stderr=stderr)
        self.assertEqual(code, 1)
        for word in ("fixture-marker", "fixture-stderr", "leak"):
            self.assertNotIn(word, output)
        return output

    def test_empty_audit_output_is_split_by_the_shape_of_stderr(self):
        prefix = "linux-source-build=refused phase=trusted-audit reason=lock detail=audit_json_empty"
        for stderr in (b"", b" \n\t\n"):
            with self.subTest(stderr=stderr):
                self.assertEqual(self._json_line(b" \n\t", stderr), prefix + "\n")
        self.assertEqual(self._json_line(b""), prefix + "\n")
        self.assertEqual(
            self._json_line(b"", b'\n  {"fixture-stderr": 1}\n\n'), prefix + "_stderr_json count=1\n",
        )
        self.assertEqual(
            self._json_line(b"", b'{\n"fixture-stderr": 1,\n"leak": 2\n}\n'), prefix + "_stderr_json count=4\n",
        )
        self.assertEqual(
            self._json_line(b"", b"fixture-stderr one\n\n  \nfixture-stderr two\nleak\n"), prefix + "_stderr_text count=3\n",
        )
        self.assertEqual(self._json_line(b"\n", b"[fixture-stderr]\n"), prefix + "_stderr_text count=1\n")
        self.assertEqual(self._json_line(b"\n", b"fixture-stderr\n" * 150), prefix + "_stderr_text count=99\n")
        self.assertEqual(self._json_line(b"\n", b'{"fixture-stderr": 1}\n' * 150), prefix + "_stderr_json count=99\n")

    def test_non_utf8_audit_output_is_named_by_shape(self):
        self.assertEqual(
            self._json_line(b'{"fixture-marker": "\xff"}', b"fixture-stderr\n"),
            "linux-source-build=refused phase=trusted-audit reason=lock detail=audit_json_encoding\n",
        )

    def test_audit_output_not_starting_with_an_object_counts_lines_before_one(self):
        prefix = "linux-source-build=refused phase=trusted-audit reason=lock detail=audit_json_prefix"
        cases = (
            (b"fixture-marker is not json", 0), (b"\n  [1", 0), (b"npm warn fixture-marker\n{}", 1),
            (b"fixture-marker\n\n  \nleak\n  {", 2), (b"fixture-marker\n" * 150 + b"{}", 99),
            (b"fixture-marker\nleak\n", 0),
        )
        for stdout, count in cases:
            with self.subTest(stdout=stdout[:24]):
                self.assertEqual(self._json_line(stdout, b"fixture-stderr\n"), prefix + " count=" + str(count) + "\n")

    def test_audit_output_with_data_after_the_first_value_counts_lines(self):
        prefix = "linux-source-build=refused phase=trusted-audit reason=lock detail=audit_json_trailing"
        self.assertEqual(self._json_line(b'{"fixture-marker": 1} fixture-marker'), prefix + " count=1\n")
        self.assertEqual(self._json_line(b'{"fixture-marker": 1}\n\nfixture-marker\n{}\n'), prefix + " count=2\n")
        self.assertEqual(self._json_line(b'{}\n' + b"fixture-marker\n" * 150), prefix + " count=99\n")

    def test_audit_output_with_a_duplicate_key_is_named_by_shape(self):
        line = "linux-source-build=refused phase=trusted-audit reason=lock detail=audit_json_duplicate\n"
        for stdout in (
            b'{"fixture-marker": 1, "fixture-marker": 2}',
            b'{"vulnerabilities": {"fixture-marker": 1, "fixture-marker": 2}}',
        ):
            with self.subTest(stdout=stdout):
                self.assertEqual(self._json_line(stdout), line)

    def test_audit_output_that_fails_to_decode_is_named_by_shape(self):
        line = "linux-source-build=refused phase=trusted-audit reason=lock detail=audit_json_syntax\n"
        for stdout in (b'{"fixture-marker": }', b'{"fixture-marker": NaN}', b'{"fixture-marker": 1', b'{"a":' * 100000):
            with self.subTest(stdout=stdout[:24]):
                self.assertEqual(self._json_line(stdout), line)

    def test_audit_output_that_is_one_non_object_value_is_named_by_shape(self):
        line = "linux-source-build=refused phase=trusted-audit reason=lock detail=audit_json_not_object\n"
        for stdout in (b"[]", b'"fixture-marker"', b'  ["fixture-marker"]\n', b"-1", b"12.5", b"null", b"true", b"false"):
            with self.subTest(stdout=stdout):
                self.assertEqual(self._json_line(stdout, b"fixture-stderr\n"), line)
        prefix = "linux-source-build=refused phase=trusted-audit reason=lock detail=audit_json_prefix"
        self.assertEqual(self._json_line(b"[] fixture-marker"), prefix + " count=0\n")
        self.assertEqual(self._json_line(b'["fixture-marker"]\n{}'), prefix + " count=1\n")
        self.assertEqual(self._json_line(b'[{"fixture-marker": 1, "fixture-marker": 2}]'), prefix + " count=0\n")

    def test_top_level_key_count_is_reported_and_bounded(self):
        good = json.loads(_honoured_report())
        two = self._detail(json.dumps(dict(good, one=1, two=2)).encode("ascii"))
        self.assertEqual((two.detail, two.count), ("audit_top_keys", 2))
        wide = {"key" + str(index): index for index in range(150)}
        capped = self._detail(json.dumps(dict(good, **wide)).encode("ascii"))
        self.assertEqual(capped.count, linux_source_build.MAX_DETAIL_COUNT)
        self.assertEqual(self._detail(b"not json").count, 0)

    def test_public_line_carries_only_a_token_for_the_audit_phase(self):
        cases = {
            "audit_exit": dict(returncode=2, stdout=_honoured_report()),
            "audit_exit_mismatch": dict(returncode=0, stdout=_honoured_report()),
            "audit_advisory_unmatched": dict(returncode=1, stdout=_honoured_report(), allows=[]),
        }
        for token, arguments in cases.items():
            with self.subTest(token=token):
                code, output = self._run_audit(entry=_dispatch_audit, **arguments)
                self.assertEqual(code, 1)
                self.assertEqual(output, "linux-source-build=refused phase=trusted-audit reason=lock detail=" + token + "\n")
        good = json.loads(_honoured_report())
        code, output = self._run_audit(
            1, json.dumps(dict(good, one=1, two=2, three=3)).encode("ascii"), entry=_dispatch_audit,
        )
        self.assertEqual(
            output, "linux-source-build=refused phase=trusted-audit reason=lock detail=audit_top_keys count=3\n",
        )
        refusal = linux_source_build.SourceBuildRefusal("lock", "audit_json_syntax")
        self.assertEqual(linux_source_build._refusal_line("checkout", refusal), "linux-source-build=refused phase=checkout reason=lock\n")
        self.assertEqual(
            linux_source_build._refusal_line("trusted-audit", linux_source_build.SourceBuildRefusal("lock")),
            "linux-source-build=refused phase=trusted-audit reason=lock detail=audit_unclassified\n",
        )
        invented = linux_source_build.SourceBuildRefusal("lock", "fixture-lib 1.5.0", count=-3)
        self.assertIsNone(invented.detail)
        self.assertIsNone(invented.count)
        with patch.object(linux_source_build, "run_trusted_audit", side_effect=RuntimeError("fixture-lib")), \
                patch("sys.stdout", io.StringIO()) as output:
            self.assertEqual(linux_source_build._dispatch("trusted-audit"), 1)
        self.assertEqual(
            output.getvalue(), "linux-source-build=refused phase=trusted-audit reason=invalid detail=audit_unexpected\n",
        )

    def test_no_package_name_version_or_value_reaches_the_public_line(self):
        secret = "zz-secret-lib"
        entry = _vulnerability(secret, via=[_advisory_via(secret, source=7777777)], nodes=["node_modules/" + secret])
        report = _audit_json({secret: entry})
        lines = []
        for arguments in (
            dict(returncode=1, stdout=report, allows=[]),
            dict(returncode=1, stdout=report),
            dict(returncode=1, stdout=report.replace(secret.encode("ascii"), b"Bad Name")),
            dict(returncode=2, stdout=report),
            dict(returncode=1, stdout=json.dumps(dict(json.loads(report), **{secret: secret})).encode("ascii")),
        ):
            lines.append(self._run_audit(entry=_dispatch_audit, **arguments)[1])
        for line in lines:
            with self.subTest(line=line):
                self.assertRegex(line, LINE_PATTERN)
                for fragment in (secret, "7.7.7", "7777777", "GHSA", "Bad Name"):
                    self.assertNotIn(fragment, line)
        for token, (report, allows, packages, now_ms) in self._report_cases().items():
            error = self._detail(report, allows, packages, now_ms)
            line = linux_source_build._refusal_line("trusted-audit", error)
            self.assertRegex(line, LINE_PATTERN)
            self.assertIn(token, line)
            for fragment in ("fixture-lib", "tool-a", "runtime-lib", "9000001", "GHSA"):
                self.assertNotIn(fragment, line)

    def test_info_only_report_with_a_zero_exit_is_accepted(self):
        info = _audit_json(
            {"fixture-lib": _lib(severity="info", via=[_advisory_via(severity="info")])}, info=1, moderate=0,
        )
        self.assertEqual(
            linux_source_build._check_audit_report(info, [_allow(self.now_ms)], LOCKED, self.now_ms), (1, 1, 0),
        )
        code, output = self._run_audit(0, info)
        self.assertEqual((code, output), (0, "linux-node-audit=verified phase=trusted findings=1 allowed=1\n"))
        with self.assertRaises(linux_source_build.SourceBuildRefusal) as refused:
            self._run_audit(1, info)
        self.assertEqual(refused.exception.detail, "audit_exit_mismatch")

    def test_expected_exit_follows_the_low_and_moderate_counts(self):
        low = _audit_json({"fixture-lib": _lib(severity="low", via=[_advisory_via(severity="low")])}, low=1, moderate=0)
        self.assertEqual(linux_source_build._check_audit_report(low, [_allow(self.now_ms)], LOCKED, self.now_ms)[2], 1)
        self.assertEqual(linux_source_build._check_audit_report(_honoured_report(), [_allow(self.now_ms)], LOCKED, self.now_ms)[2], 1)
        self.assertEqual(self._detail(_audit_json({"fixture-lib": _lib()}, moderate=0)).detail, "audit_count")
        self.assertEqual(self._detail(_audit_json({}, moderate=1)).detail, "audit_count")

    def test_advisory_validity_window_is_enforced(self):
        self.assertEqual(self._run_audit(1, _honoured_report(), valid_until=self.now + 60)[0], 0)
        for valid_until in (self.now, self.now - 1):
            with self.subTest(valid_until=valid_until), self.assertRaises(linux_source_build.SourceBuildRefusal) as refused:
                self._run_audit(1, _honoured_report(), valid_until=valid_until)
            self.assertEqual(refused.exception.detail, "audit_advisory_expired")

    def test_consumer_chain_must_reach_a_matched_advisory(self):
        chain = _audit_json({
            "fixture-lib": _lib(),
            "tool-a": _vulnerability("tool-a", via=["fixture-lib"], nodes=["node_modules/tool-a"]),
            "tool-b": _vulnerability("tool-b", via=["tool-a"], nodes=["node_modules/tool-b"]),
        })
        packages = dict(LOCKED, **{"node_modules/tool-b": {"version": "1.0.0", "dev": True}})
        self.assertEqual(
            linux_source_build._check_audit_report(chain, [_allow(self.now_ms)], packages, self.now_ms), (3, 1, 1),
        )
        cycle = _audit_json({
            "tool-a": _vulnerability("tool-a", via=["tool-b"], nodes=["node_modules/tool-a"]),
            "tool-b": _vulnerability("tool-b", via=["tool-a"], nodes=["node_modules/tool-b"]),
        })
        self.assertEqual(self._detail(cycle, packages=packages).detail, "audit_consumer_unreached")
        detached = _audit_json({
            "fixture-lib": _lib(),
            "tool-a": _vulnerability("tool-a", via=["tool-b"], nodes=["node_modules/tool-a"]),
            "tool-b": _vulnerability("tool-b", via=["tool-a"], nodes=["node_modules/tool-b"]),
        })
        self.assertEqual(self._detail(detached, packages=packages).detail, "audit_consumer_unreached")


class QuickTierVerdictTests(unittest.TestCase):
    def test_the_quick_tier_can_never_emit_a_verdict(self):
        for mode in ("source", "synthetic", ""):
            env = {
                "KD_LINUX_TIER": "quick", "CI_MODE": mode, "CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7",
                "GITHUB_RUN_ATTEMPT": "1", "PRODUCER_RESULT": "success",
            }
            with self.subTest(mode=mode):
                output = io.StringIO()
                with patch.object(linux_source_build.sys, "stdout", output):
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
                        linux_source_build.emit_verdict(env)
                self.assertEqual(output.getvalue(), "")
        output = io.StringIO()
        with patch.dict(os.environ, {"KD_LINUX_TIER": "quick"}), patch.object(linux_source_build.sys, "stdout", output):
            self.assertEqual(linux_source_build.main(["verdict"]), 1)
        self.assertEqual(output.getvalue(), "linux-source-build=refused phase=verdict reason=identity\n")
        self.assertNotIn("KD-CONFINEMENT-VERDICT", output.getvalue())


class WindowsSourceBindingTests(unittest.TestCase):
    SOURCE = "a" * 40
    BASE = "b" * 40
    CONTROL = "d" * 40
    FINGERPRINT = "c" * 64

    def _environment(self, prefix="WINDOWS_SOURCE"):
        return {
            "REQUESTED_SOURCE_SHA": self.SOURCE, "REQUESTED_BASE_SHA": self.BASE,
            "REQUESTED_BASE_BRANCH": "main", "REQUESTED_FINGERPRINT": self.FINGERPRINT,
            "CI_SHA": self.CONTROL,
            prefix + "_ALLOWED_SHA": self.SOURCE, prefix + "_ALLOWED_BASE_SHA": self.BASE,
            prefix + "_ALLOWED_BASE_BRANCH": "main",
            prefix + "_ALLOWED_FINGERPRINT": self.FINGERPRINT,
            prefix + "_ALLOWED_CONTROL_SHA": self.CONTROL,
            "SOURCE_REPOSITORY_ID": "7", "SOURCE_REPOSITORY_OWNER": "owner",
            "SOURCE_REPOSITORY_NAME": "source", "SOURCE_READER_INSTALLATION_ID": "8",
            "SOURCE_READER_CLIENT_ID": "client",
            prefix + "_ACCEPTED_NODE_LOCK_SHA256": "f" * 64,
            prefix + "_ACCEPTED_MANIFEST_SHA256": "1" * 64,
            prefix + "_ACCEPTED_NODE_PROVENANCE_JSON": "{}",
            prefix + "_ENVIRONMENT_NAME": "linux-source-read",
            "REQUESTED_ENVIRONMENT_NAME": "linux-source-read",
        }

    def _dispatch_environment(self, ref, mode):
        return {
            "CI_EVENT_NAME": "workflow_dispatch", "CI_REPOSITORY": linux_source_build.REPOSITORY,
            "CI_SERVER_URL": "https://github.com", "CACHE_MODE": "none",
            "CI_SHA": self.CONTROL, "GITHUB_SHA": self.CONTROL, "CI_REF": ref, "CI_MODE": mode,
        }

    def test_prefixes_are_the_closed_pair(self):
        self.assertEqual(linux_source_build.LINUX_SOURCE_PREFIX, "LINUX_SOURCE")
        self.assertEqual(linux_source_build.WINDOWS_SOURCE_PREFIX, "WINDOWS_SOURCE")
        self.assertEqual(linux_source_build.SOURCE_PREFIXES, ("LINUX_SOURCE", "WINDOWS_SOURCE"))
        self.assertEqual(
            linux_source_build.WINDOWS_TIER, ("windows-source-admission.yml", "Windows admission source "),
        )

    def test_windows_binding_reads_only_the_windows_names(self):
        with patch.object(linux_source_build, "_validate_provenance_binding") as provenance:
            identity = linux_source_build._source_inputs(self._environment(), prefix="WINDOWS_SOURCE")
            self.assertEqual(identity["source_sha"], self.SOURCE)
            self.assertEqual(identity["reviewed_diff_sha256"], self.FINGERPRINT)
            self.assertEqual(identity["repository_id"], "7")
            provenance.assert_called_once()
            self.assertEqual(provenance.call_args.args[2], "WINDOWS_SOURCE")
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build._source_inputs(self._environment("LINUX_SOURCE"), prefix="WINDOWS_SOURCE")
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build._source_inputs(self._environment("WINDOWS_SOURCE"))
            provenance.assert_called_once()
            linux_source_build._source_inputs(self._environment("LINUX_SOURCE"))
            self.assertEqual(provenance.call_count, 2)

    def test_every_windows_binding_name_is_required_and_checked(self):
        for suffix in (
            "_ALLOWED_SHA", "_ALLOWED_BASE_SHA", "_ALLOWED_BASE_BRANCH", "_ALLOWED_FINGERPRINT",
            "_ALLOWED_CONTROL_SHA", "_ACCEPTED_NODE_LOCK_SHA256", "_ACCEPTED_MANIFEST_SHA256",
            "_ACCEPTED_NODE_PROVENANCE_JSON", "_ENVIRONMENT_NAME",
        ):
            changes = ("missing", "empty") if suffix == "_ACCEPTED_NODE_PROVENANCE_JSON" else ("missing", "empty", "other")
            for change in changes:
                environment = self._environment()
                name = "WINDOWS_SOURCE" + suffix
                if change == "missing":
                    del environment[name]
                elif change == "empty":
                    environment[name] = ""
                else:
                    environment[name] = "x" * 3
                with self.subTest(name=name, change=change), patch.object(
                    linux_source_build, "_validate_provenance_binding"
                ) as provenance:
                    with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                        linux_source_build._source_inputs(environment, prefix="WINDOWS_SOURCE")
                    provenance.assert_not_called()
        environment = self._environment()
        environment["WINDOWS_SOURCE_ENVIRONMENT_NAME"] = "source-read"
        environment["REQUESTED_ENVIRONMENT_NAME"] = "source-read"
        with patch.object(linux_source_build, "_validate_provenance_binding"):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build._source_inputs(environment, prefix="WINDOWS_SOURCE")

    def test_unknown_prefixes_are_refused_everywhere(self):
        for prefix in ("", "WINDOWS", "windows_source", "LINUX_SOURCE_", "MACOS_SOURCE", None, 5, b"LINUX_SOURCE"):
            with self.subTest(prefix=prefix):
                with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                    linux_source_build._source_inputs(self._environment("LINUX_SOURCE"), prefix=prefix)
                with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "lock"):
                    linux_source_build._validate_provenance_binding({}, {}, prefix)
                with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
                    linux_source_build.validate_dispatch({}, "token", prefix)

    def test_windows_provenance_text_comes_from_the_windows_variable(self):
        with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "lock"):
            linux_source_build._validate_provenance_binding(
                {}, {"LINUX_SOURCE_ACCEPTED_NODE_PROVENANCE_JSON": "{}"}, "WINDOWS_SOURCE",
            )
        with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "lock"):
            linux_source_build._validate_provenance_binding(
                {}, {"WINDOWS_SOURCE_ACCEPTED_NODE_PROVENANCE_JSON": "{}"},
            )

    def test_windows_source_dispatch_runs_only_on_untrusted_and_synthetic_only_on_main(self):
        order = []
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, self.CONTROL]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ), patch.object(
            linux_source_build, "_source_inputs", side_effect=lambda environ, prefix: order.append(prefix) or {}
        ), patch.object(
            linux_source_build, "_verify_environment", side_effect=lambda token: order.append("environment")
        ), patch.object(
            linux_source_build, "_require_no_duplicate",
            side_effect=lambda token, environ, workflow: order.append(workflow),
        ):
            env = self._dispatch_environment("refs/heads/untrusted", "source")
            self.assertEqual(linux_source_build.validate_dispatch(env, "token", "WINDOWS_SOURCE"), "source")
        self.assertEqual(order, ["WINDOWS_SOURCE", "environment", linux_source_build.WINDOWS_TIER])
        with patch.object(linux_source_build, "_reference_sha", side_effect=[self.CONTROL, self.CONTROL]), patch.object(
            linux_source_build, "_comparison", return_value="identical"
        ), patch.object(
            linux_source_build, "_source_inputs", side_effect=AssertionError("no binding for a main source run")
        ):
            env = self._dispatch_environment("refs/heads/main", "source")
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
                linux_source_build.validate_dispatch(env, "token", "WINDOWS_SOURCE")
        with patch.object(linux_source_build, "_reference_sha", side_effect=[self.CONTROL, self.CONTROL]), patch.object(
            linux_source_build, "_comparison", return_value="identical"
        ), patch.object(
            linux_source_build, "_source_inputs", side_effect=AssertionError("no binding in synthetic")
        ), patch.object(linux_source_build, "_verify_environment") as environment:
            env = self._dispatch_environment("refs/heads/main", "synthetic")
            self.assertEqual(linux_source_build.validate_dispatch(env, "token", "WINDOWS_SOURCE"), "synthetic")
            environment.assert_called_once_with("token")
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, self.CONTROL]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ):
            env = self._dispatch_environment("refs/heads/untrusted", "synthetic")
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
                linux_source_build.validate_dispatch(env, "token", "WINDOWS_SOURCE")

    def test_windows_dispatch_refuses_a_linux_tier_variable_and_a_stale_untrusted_branch(self):
        for tier in ("quick", "admission", "windows", ""):
            with self.subTest(tier=tier):
                env = dict(self._dispatch_environment("refs/heads/untrusted", "source"), KD_LINUX_TIER=tier)
                with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "identity"):
                    linux_source_build.validate_dispatch(env, "token", "WINDOWS_SOURCE")
        env = self._dispatch_environment("refs/heads/untrusted", "source")
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, "e" * 40]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "freshness"):
                linux_source_build.validate_dispatch(env, "token", "WINDOWS_SOURCE")
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, self.CONTROL]), patch.object(
            linux_source_build, "_comparison", return_value="diverged"
        ):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "untrusted"):
                linux_source_build.validate_dispatch(env, "token", "WINDOWS_SOURCE")

    def test_windows_duplicate_check_uses_the_windows_workflow_and_title(self):
        calls = []

        def runs(title):
            def fake(path, token, method="GET", payload=None, expected=(200,)):
                calls.append(path)
                status = "queued" if path.endswith("status=queued") else "in_progress"
                return 200, {"total_count": 1, "workflow_runs": [{
                    "id": 9, "display_title": title + self.SOURCE, "status": status, "event": "workflow_dispatch",
                }]}
            return fake

        environment = {"GITHUB_RUN_ID": "5", "REQUESTED_SOURCE_SHA": self.SOURCE}
        windows = linux_source_build.WINDOWS_TIER
        with patch.object(linux_source_build, "_api_request", side_effect=runs("Windows admission source ")):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "duplicate"):
                linux_source_build._require_no_duplicate("token", environment, workflow=windows)
        self.assertTrue(calls[0].startswith(
            "/repos/" + linux_source_build.REPOSITORY + "/actions/workflows/windows-source-admission.yml/runs?"
        ))
        with patch.object(linux_source_build, "_api_request", side_effect=runs("Linux admission source ")):
            self.assertIsNone(linux_source_build._require_no_duplicate("token", environment, workflow=windows))
        for workflow in (("linux-source-admission.yml", "Linux admission source "), ("x", "y"), "windows", ()):
            with self.subTest(workflow=workflow):
                with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "duplicate"):
                    linux_source_build._require_no_duplicate("token", environment, workflow=workflow)

    def test_windows_entry_points_print_fixed_lines(self):
        environment = {"GITHUB_TOKEN": "token"}
        for function, name, suffix in (
            (linux_source_build.windows_preflight, "windows-source-preflight", " cache-mode=none"),
        ):
            with patch.object(linux_source_build, "validate_dispatch", return_value="source") as dispatch:
                output = io.StringIO()
                with patch.object(linux_source_build.sys, "stdout", output):
                    self.assertEqual(function(environment), 0)
                self.assertEqual(output.getvalue(), name + "=verified mode=source" + suffix + "\n")
                self.assertEqual(dispatch.call_args.args[2], "WINDOWS_SOURCE")
            for error, reason in (
                (linux_source_build.SourceBuildRefusal("binding"), "binding"), (ValueError("x"), "invalid"),
            ):
                with patch.object(linux_source_build, "validate_dispatch", side_effect=error):
                    output = io.StringIO()
                    with patch.object(linux_source_build.sys, "stdout", output):
                        self.assertEqual(function(environment), 1)
                    self.assertEqual(output.getvalue(), name + "=refused reason=" + reason + "\n")
        audit = types.SimpleNamespace(
            _default_api_factory=Mock(return_value="api"), _collect_caches=Mock(return_value=[]),
            cache_inventory_digest=Mock(return_value="e" * 64),
        )
        with tempfile.TemporaryDirectory() as temporary:
            sink = Path(temporary) / "output"
            environment = {"GITHUB_TOKEN": "token", "GITHUB_OUTPUT": str(sink)}
            with patch.object(linux_source_build, "_audit_modules", return_value=(audit, None, None)), patch.object(
                linux_source_build, "validate_dispatch", return_value="synthetic"
            ) as dispatch:
                output = io.StringIO()
                with patch.object(linux_source_build.sys, "stdout", output):
                    self.assertEqual(linux_source_build.windows_snapshot(environment), 0)
                self.assertEqual(output.getvalue(), "windows-source-settings=verified mode=synthetic cache=snapped\n")
                self.assertEqual(dispatch.call_args.args, (environment, "token", "WINDOWS_SOURCE"))
            self.assertEqual(sink.read_text(encoding="ascii"), "cache_digest=" + "e" * 64 + "\n")
            with patch.object(linux_source_build, "_audit_modules", side_effect=ValueError("x")):
                output = io.StringIO()
                with patch.object(linux_source_build.sys, "stdout", output):
                    self.assertEqual(linux_source_build.windows_snapshot(environment), 1)
                self.assertEqual(output.getvalue(), "windows-source-settings=refused reason=invalid\n")

    def test_windows_commands_are_routed_by_the_dispatcher(self):
        for command, function in (
            ("windows-snapshot", "windows_snapshot"), ("windows-preflight", "windows_preflight"),
        ):
            with self.subTest(command=command), patch.object(linux_source_build, function, return_value=0) as target:
                self.assertEqual(linux_source_build.main([command]), 0)
                target.assert_called_once_with()
        self.assertEqual(linux_source_build.main(["windows-unknown"]), 2)

    def test_gate_commands_render_the_shared_table_including_the_feature_gates(self):
        commands = linux_source_build._gate_commands(Path("/work"), "/rust", "/node")
        self.assertEqual(
            commands,
            gate_table.render(
                gate_table.gate_templates(False), "/work", "/rust/bin/cargo", "/node/bin/node", "/node/bin/npm",
            ),
        )
        by_name = dict(commands)
        feature = ("--features", "dev-uat-policy-import")
        for name in ("api_feature_clippy", "api_feature_tests"):
            with self.subTest(gate=name):
                argv = by_name[name]
                self.assertEqual(argv[argv.index("--features"):argv.index("--features") + 2], feature)
                self.assertIn("/work/crates/host/api/Cargo.toml", argv)
        self.assertEqual(linux_source_build.GATES, gate_table.GATES)
        self.assertEqual(linux_source_build.RUNTIME_GATE_NAMES, gate_table.RUNTIME_GATE_NAMES)
        self.assertEqual(linux_source_build.RUNTIME_ROOT_FILES, gate_table.RUNTIME_ROOT_FILES)
        with patch.object(linux_source_build.gate_table, "render", side_effect=gate_table.GateTableRefusal("tool")):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "gate"):
                linux_source_build._gate_commands(Path("/work"), "/rust", "/node")


if __name__ == "__main__":
    unittest.main(verbosity=2)
