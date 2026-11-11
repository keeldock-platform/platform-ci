"""Source-free binding and ordering checks; never launches Cargo."""
import copy
import inspect
import unittest

import bundle
import constraint_resolver
import rust_lock_generation as locks
import supervisor

CONTROL = "a" * 40


class LockGenerationTests(unittest.TestCase):
    def files(self):
        files = {}
        for name, path in zip(("root", "runtime", "fuzz"), constraint_resolver.PRODUCTION_MANIFESTS):
            files[path] = ('[package]\nname="%s"\nversion="0.1.0"\n'
                           '[dependencies]\nserde="^1.0"\n' % name).encode()
        prefix = bundle.BASELINE_NAMESPACE + "/"
        files[prefix + "Cargo.toml"] = b'[workspace]\nresolver="3"\nmembers=["crate"]\n'
        files[prefix + "crate/Cargo.toml"] = b'[package]\nname="baseline"\nversion="0.1.0"\n'
        return files

    def projection(self, files):
        prefix = bundle.BASELINE_NAMESPACE + "/"
        candidate = {name: value for name, value in files.items() if not name.startswith(prefix)}
        baseline = {name[len(prefix):]: value for name, value in files.items() if name.startswith(prefix)}
        return {"manifest_projection_sha256": "d" * 64, "manifest_constraints": {
            "candidate": constraint_resolver.build_manifest_constraint_envelope(
                manifests=candidate, source_commit=bundle.CORE_RUST_SOURCE_REVISION,
                control_sha=CONTROL, selected_manifests=list(constraint_resolver.PRODUCTION_MANIFESTS)),
            "baseline_runtime": constraint_resolver.build_manifest_constraint_envelope(
                manifests=baseline, source_commit=bundle.CORE_RUST_BASELINE_REVISION,
                control_sha=CONTROL, selected_manifests=["Cargo.toml"], allow_empty=True)}}

    def test_authenticated_manifest_changes_cannot_reuse_old_public_projection(self):
        files = self.files()
        projection = self.projection(files)
        locks.verify_manifest_constraints(files, projection, CONTROL)
        changed = dict(files)
        changed["runtime/Cargo.toml"] = changed["runtime/Cargo.toml"].replace(b'^1.0', b'^2.0')
        with self.assertRaisesRegex(bundle.Refusal, "source-constraint-projection-mismatch"):
            locks.verify_manifest_constraints(changed, projection, CONTROL)

    def test_project_configuration_refuses_before_cargo_even_with_unchanged_manifests(self):
        files = self.files()
        projection = self.projection(files)
        files["runtime/.cargo/config.toml"] = b'[net]\noffline=false\n'
        with self.assertRaisesRegex(bundle.Refusal, "source-constraint-projection-mismatch"):
            locks.verify_manifest_constraints(files, projection, CONTROL)

    def test_commands_are_fixed_offline_roots_and_override_source_configuration(self):
        for manifest, _lock in locks.LOCKS:
            argv = locks.command(manifest)
            self.assertEqual(argv[:3], ["/tools/rust/bin/cargo", "generate-lockfile", "--offline"])
            self.assertIn('net.offline=true', argv)
            self.assertIn('source.crates-io.replace-with="prepared-registry"', argv)
        with self.assertRaisesRegex(bundle.Refusal, "generated-lock-manifest"):
            locks.command("other/Cargo.toml")

    def test_generated_packages_must_be_in_verified_registry(self):
        projection = self.projection(self.files())
        row = {"name": "serde", "version": "1.0.0", "checksum": "b" * 64}
        prepared = {"schema": 2, "source_commit": bundle.CORE_RUST_SOURCE_REVISION,
                    "control_sha": CONTROL, "manifest_projection_sha256": "d" * 64,
                    "packages": [row], "baseline_external_packages": [],
                    "tool_hashes": {name: "e" * 64 for name in (
                        "cargo_sha256", "rustc_sha256", "cargo_version_output_sha256",
                        "rustc_version_output_sha256")},
                    "tool_provenance_status": "binary-hash-bound-origin-unverified"}
        payload = ('version = 4\n[[package]]\nname="serde"\nversion="1.0.0"\n'
                   'source="registry+https://github.com/rust-lang/crates.io-index"\n'
                   'checksum="%s"\n' % ("b" * 64)).encode()
        generated = {name: payload for _manifest, name in locks.LOCKS}
        record = locks.output_record(generated, prepared, projection, CONTROL)
        self.assertEqual(record["status"], "ephemeral-offline-generated-not-committed")
        generated["fuzz/Cargo.lock"] = payload.replace(b'version="1.0.0"', b'version="2.0.0"')
        with self.assertRaisesRegex(bundle.Refusal, "generated-lock-outside-registry"):
            locks.output_record(generated, prepared, projection, CONTROL)
        changed = dict(prepared, control_sha="c" * 40)
        with self.assertRaisesRegex(bundle.Refusal, "generated-lock-input-binding"):
            locks.validate_preparation(changed, projection, CONTROL)
        changed = dict(prepared, tool_hashes={})
        with self.assertRaisesRegex(bundle.Refusal, "generated-lock-input-binding"):
            locks.validate_preparation(changed, projection, CONTROL)

    def test_real_decrypt_callsite_checks_cut_and_source_before_generating(self):
        source = inspect.getsource(supervisor.Service._decrypt)
        self.assertLess(source.index("self._verify_network_cut()"), source.index("self._generate_offline_locks()"))
        self.assertLess(source.index("self._verify_projection_bindings()"), source.index("self._generate_offline_locks()"))
        self.assertLess(source.index("self._generate_offline_locks()"), source.index("self.decrypted = True"))
        generate = inspect.getsource(supervisor.Service._generate_offline_locks)
        self.assertLess(generate.index("verify_bounded_registry_tree"), generate.index("_run_profile_command"))


if __name__ == "__main__":
    unittest.main()
