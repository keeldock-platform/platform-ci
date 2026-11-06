import hashlib
from pathlib import Path
import tempfile
import unittest

import cargo_archive_producer
import cargo_lock_receipt as cargo
import cargo_vendor_producer as subject
import rust_license_gate
from test_cargo_archive_producer import _Opener, _Response, _crate_archive, _lock


class CargoVendorProducerTests(unittest.TestCase):
    def test_production_materializes_archives_and_binds_vendor_receipt(self):
        archive = _crate_archive()
        lock_bytes = _lock(archive)
        checksum = hashlib.sha256(archive).hexdigest()
        record = {
            "schema_version": 1,
            "repository": "keeldock/platform-ci",
            "workspace_path": "runtime",
            "source_sha": "a" * 40,
            "base_sha": "b" * 40,
            "base_branch": "main",
            "reviewed_diff_fingerprint": "c" * 64,
            "dependency_policy_revision": "policy-7",
            "control_sha": "d" * 40,
            "toolchain_hash": "e" * 64,
            "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
            "packages": [{
                "name": "fixture-crate",
                "version": "1.2.3",
                "checksum": checksum,
                "audit_record_id": "audit-fixture-crate-1",
            }],
        }
        receipt_bytes = cargo.encode_receipt(record)
        context = {field: record[field] for field in cargo.CONTEXT_FIELDS}
        context["receipt_sha256"] = hashlib.sha256(receipt_bytes).hexdigest()
        authorized = {
            ("fixture-crate", "1.2.3", checksum): "audit-fixture-crate-1",
        }
        package = rust_license_gate.Package("fixture-crate", "1.2.3", checksum)
        identity = rust_license_gate.Identity(
            record["source_sha"], record["workspace_path"], "/trusted/source/runtime",
            record["lock_sha256"],
        )
        archives = cargo_archive_producer.TrustedArchivePort(
            _Opener(_Response(archive)),
        ).verify_complete(lock_bytes, identity, (package,))
        gate_receipt = rust_license_gate.GateReceipt(
            identity, archives.archive_spdx_sha256, 1, "e" * 40, "f" * 64,
            "1" * 64, "2" * 64, "3" * 64, "4" * 40, 1_800_000_000,
            rust_license_gate._SEAL,
        )

        with tempfile.TemporaryDirectory() as temporary:
            vendor_root = Path(temporary) / "vendor"
            vendor_root.mkdir(mode=0o700)
            result = subject.produce_vendor_evidence(
                lock_bytes, receipt_bytes, context, authorized, gate_receipt,
                vendor_root,
                cargo_archive_producer.TrustedArchivePort(_Opener(_Response(archive))),
            )
            record_value = cargo._decode_ascii(
                result.vendor_receipt_bytes, 8192, "vendor-test",
            )
            self.assertTrue(result.vendor_directory.is_dir())
            self.assertEqual(result.vendor_sha256, cargo.vendor_tree_digest(vendor_root))
            self.assertEqual(
                result.trusted_vendor_receipt_sha256,
                hashlib.sha256(result.vendor_receipt_bytes).hexdigest(),
            )
            self.assertIn(hashlib.sha256(receipt_bytes).hexdigest(), record_value)
            self.assertIn(rust_license_gate.gate_receipt_sha256(gate_receipt), record_value)
            self.assertEqual(vendor_root.stat().st_mode & 0o777, 0o555)


if __name__ == "__main__":
    unittest.main()
