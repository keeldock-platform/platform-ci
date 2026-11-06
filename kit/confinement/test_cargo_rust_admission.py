import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import cargo_lock_receipt as cargo
import cargo_rust_admission as subject
import rust_license_gate


REGISTRY_LOCK = (
    b"version = 3\n\n[[package]]\nname = \"example\"\nversion = \"1.0.0\"\n"
    b"source = \"registry+https:" + b"//github.com/rust-lang/crates.io-index\"\n"
    b"checksum = \"" + b"a" * 64 + b"\"\n"
)
PATH_LOCK = b"version = 3\n\n[[package]]\nname = \"example\"\nversion = \"1.0.0\"\n"


class CargoRustAdmissionTests(unittest.TestCase):
    def test_registry_free_lock_remains_local_and_does_not_need_a_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / "Cargo.toml").write_text("[package]\n", encoding="ascii")
            identity = rust_license_gate.Identity(
                "a" * 40, ".", temporary, hashlib.sha256(PATH_LOCK).hexdigest(),
            )
            result = subject.admit_lock(PATH_LOCK, temporary, "a" * 40, ".")
        self.assertIs(type(result), rust_license_gate.RegistryFreeReceipt)

    def test_runtime_profile_uses_its_resolved_manifest_root_for_gate_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / "Cargo.toml").write_text("[package]\n", encoding="ascii")
            runtime = source / "runtime"
            runtime.mkdir()
            (runtime / "Cargo.toml").write_text("[workspace]\n", encoding="ascii")
            captured = {}

            def gate(unused_lock_bytes, identity, unused_ports=None):
                captured["identity"] = identity
                return object()

            with patch.object(subject.rust_license_gate, "require_lock_admission", side_effect=gate):
                result = subject.admit_lock(PATH_LOCK, source, "a" * 40, "runtime")
        self.assertIsNotNone(result)
        self.assertEqual(captured["identity"].profile, "runtime")
        self.assertEqual(captured["identity"].root, str(runtime.resolve()))

    def test_runtime_profile_refuses_when_its_root_manifest_is_missing(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            (source / "Cargo.toml").write_text("[package]\n", encoding="ascii")
            (source / "runtime").mkdir()
            with patch.object(subject.rust_license_gate, "require_lock_admission") as gate:
                with self.assertRaises(subject.RustAdmissionRefusal):
                    subject.admit_lock(PATH_LOCK, source, "a" * 40, "runtime")
            gate.assert_not_called()

    def test_registry_lock_without_protected_receipt_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            (Path(temporary) / "Cargo.toml").write_text("[package]\n", encoding="ascii")
            with self.assertRaises(subject.RustAdmissionRefusal):
                subject.admit_lock(REGISTRY_LOCK, temporary, "a" * 40, ".")

    def test_receipt_paths_are_derived_from_source_relative_lock_path(self):
        with tempfile.TemporaryDirectory() as outer:
            source = Path(outer) / "source"
            evidence = Path(outer) / "evidence"
            source.mkdir()
            evidence.mkdir()
            relative = "runtime/Cargo.lock"
            key = hashlib.sha256(relative.encode("ascii")).hexdigest()
            receipt = b"{}"
            binding = b"{}"
            for suffix, payload in (("receipt", receipt), ("binding", binding)):
                path = evidence / (key + "." + suffix + ".json")
                path.write_bytes(payload)
                path.chmod(0o600)
            actual_receipt, actual_binding = subject.control_files_for_lock(
                evidence, source, relative,
            )
        self.assertEqual((actual_receipt, actual_binding), (receipt, binding))

    def test_registry_source_requires_checksum_and_exact_crates_io_source(self):
        parsed = cargo.parse_cargo_lock(REGISTRY_LOCK)
        self.assertEqual(parsed["packages"][0]["source"], cargo.REGISTRY_SOURCE)
        invalid = REGISTRY_LOCK.replace(cargo.REGISTRY_SOURCE.encode("ascii"), b"registry+https://example.test")
        with self.assertRaises(cargo.Refusal):
            cargo.parse_cargo_lock(invalid)


if __name__ == "__main__":
    unittest.main()
