import tempfile
import unittest
from pathlib import Path

import foundation_node_feedback
import linux_source_build
import macos_core_contract


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
                "Fetch npm tarballs by committed lock integrity",
                "Run trusted dependency audit",
                "Prepare offline project inputs",
                "Re-run positive controls immediately before the first project command",
                "Run all thirteen offline project gates",
                "Merge confinement phase records",
                "Forced faults must fail closed",
                "Publish confinement verdict",
            ),
        )
        self.assertEqual(
            linux_source_build.OPTIONAL_SOURCE_STEPS,
            frozenset((
                "Mint scoped source-reader token",
                "Verify selected installation identity",
                "Fetch exact source and verify binding, tree, signatures and lock provenance",
                "Revoke source-reader token and verify rejection",
                "Fetch npm tarballs by committed lock integrity",
                "Run trusted dependency audit",
                "Prepare offline project inputs",
                "Run all thirteen offline project gates",
                "Forced faults must fail closed",
            )),
        )

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
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
