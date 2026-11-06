import hashlib
import unittest
from unittest.mock import patch

import macos_private_validation as subject
import test_macos_private_validation as validation_tests


class RuntimeWave70ProfileTests(unittest.TestCase):
    def setUp(self):
        self.fixture = validation_tests.RuntimeWorkspaceTreeTests()

    def test_wave_70a_and_70b_runtime_profiles_authenticate_inventory_and_app_sources(self):
        for roots in (subject.RUNTIME_WAVE_70A_CRATE_ROOTS, subject.RUNTIME_WAVE_70B_CRATE_ROOTS):
            with self.subTest(member_count=len(roots)):
                entries, blobs = self.fixture._wave70_profile_files(roots)
                marker, reads = self.fixture._validate(entries=entries, blobs=blobs)
                self.assertEqual(marker, "core_contract")
                self.assertIn(subject.cargo_lock_bootstrap.SOURCE_INVENTORY_PATH, reads)
                for frontend in (
                    "runtime/apps/test-shell-desktop/web/src/App.tsx",
                    "runtime/apps/test-shell-mobile/web/src/App.tsx",
                    "runtime/packages/host-ui/src/index.ts",
                ):
                    self.assertEqual(subject._runtime_workspace_mode(frontend, roots), "100644")
                for app in subject.RUNTIME_APP_TAURI_ROOTS:
                    prefix = "/".join(app)
                    self.assertEqual(subject._runtime_workspace_mode(prefix + "/src/lib.rs", roots), "100644")

    def test_wave_70_registry_locks_accept_pinned_tauri_and_bundled_sqlite_graph(self):
        roots = subject.RUNTIME_WAVE_70B_CRATE_ROOTS
        entries, blobs = self.fixture._wave70_profile_files(roots)
        lock_path = subject.RUNTIME_ROOT_LOCK_PATH
        lock_text = blobs[lock_path].decode("ascii")
        self.assertIn('name = "tauri"\nversion = "2.12.4"\nsource = "', lock_text)
        self.assertIn('name = "rusqlite"\nversion = "0.37.0"\nsource = "', lock_text)
        self.assertIn('name = "libsqlite3-sys"\nversion = "0.35.0"\nsource = "', lock_text)
        marker, unused_reads = self.fixture._validate(entries=entries, blobs=blobs)
        self.assertEqual(marker, "core_contract")

        registry = "registry+https:" + "/" * 2 + "github.com/rust-lang/crates.io-index"
        blobs[lock_path] = lock_text.replace(
            '"tauri 2.12.4 (' + registry + ')"',
            '"tauri 2.12.3 (' + registry + ')"',
        ).encode("ascii")
        self.assertEqual(self.fixture._refused(entries=entries, blobs=blobs), "cargo_lock_shape")

    def test_inventoried_build_script_is_refused_without_explicit_review(self):
        roots = subject.RUNTIME_WAVE_70A_CRATE_ROOTS
        entries, blobs = self.fixture._wave70_profile_files(roots, include_build_script=True)
        build_script = "runtime/crates/host/core/build.rs"
        digest = hashlib.sha256(blobs[build_script]).hexdigest()
        self.assertEqual(self.fixture._refused(entries=entries, blobs=blobs), "source_inventory")
        with patch.object(
            subject.cargo_lock_bootstrap, "TRUSTED_BUILD_SCRIPT_REVIEWS",
            ((build_script, digest, "b" * 40),),
        ):
            marker, unused_reads = self.fixture._validate(entries=entries, blobs=blobs)
        self.assertEqual(marker, "core_contract")

    def test_inventory_rows_and_source_digests_are_candidate_bound(self):
        roots = subject.RUNTIME_WAVE_70A_CRATE_ROOTS
        entries, blobs = self.fixture._wave70_profile_files(roots)
        inventory_path = subject.cargo_lock_bootstrap.SOURCE_INVENTORY_PATH
        blobs[inventory_path] = blobs[inventory_path].replace(b'owner = "9.5"', b'owner = ""')
        self.assertEqual(self.fixture._refused(entries=entries, blobs=blobs), "source_inventory")

        entries, blobs = self.fixture._wave70_profile_files(roots)
        config = "/".join(subject.RUNTIME_APP_TAURI_ROOTS[0]) + "/tauri.conf.json"
        blobs[config] = b'{"changed":true}\n'
        self.assertEqual(self.fixture._refused(entries=entries, blobs=blobs), "source_inventory")

    def test_runtime_profile_refuses_missing_or_extra_shell_members(self):
        roots = subject.RUNTIME_WAVE_70A_CRATE_ROOTS
        render = validation_tests._runtime_root_text
        self.assertEqual(subject._runtime_roots_from_manifest(render(roots)), roots)
        altered_profiles = (roots[:-1], roots + (subject.RUNTIME_APP_TAURI_ROOTS[0],))
        for altered in altered_profiles:
            with self.subTest(roots=altered):
                self.assertIsNone(subject._runtime_roots_from_manifest(render(altered)))
