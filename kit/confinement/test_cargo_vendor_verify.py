import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import cargo_lock_receipt as cargo
import cargo_vendor_verify as subject


CHECKSUM = "a" * 64
LOCK_BYTES = (
    'version = 4\n\n'
    '[[package]]\n'
    'name = "serde"\n'
    'version = "1.0.1"\n'
    'source = "' + cargo.REGISTRY_SOURCE + '"\n'
    'checksum = "' + CHECKSUM + '"\n'
    'dependencies = []\n'
).encode("ascii")


def _lock_receipt(lock_bytes=LOCK_BYTES):
    return {
        "schema_version": 1,
        "repository": "sample/platform-ci",
        "workspace_path": "crates/platform",
        "source_sha": "b" * 40,
        "base_sha": "c" * 40,
        "base_branch": "main",
        "reviewed_diff_fingerprint": "d" * 64,
        "dependency_policy_revision": "policy-7",
        "control_sha": "e" * 40,
        "toolchain_hash": "f" * 64,
        "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "packages": [{
            "name": "serde",
            "version": "1.0.1",
            "checksum": CHECKSUM,
            "audit_record_id": "audit-serde-1",
        }],
    }


def _lock_context(record):
    context = {field: record[field] for field in cargo.CONTEXT_FIELDS}
    context["receipt_sha256"] = hashlib.sha256(cargo.encode_receipt(record)).hexdigest()
    return context


def _authorized_audits(record):
    return {
        (item["name"], item["version"], item["checksum"]): item["audit_record_id"]
        for item in record["packages"]
    }


def _write_vendor(directory, manifest_package=CHECKSUM):
    package = Path(directory) / "serde-1.0.1"
    source = package / "src"
    source.mkdir(parents=True)
    files = {
        "Cargo.toml": b"[package]\nname='serde'\nversion='1.0.1'\n",
        "src/lib.rs": b"pub fn value() -> u8 { 1 }\n",
    }
    file_hashes = {}
    for relative, content in files.items():
        path = package / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        file_hashes[relative] = hashlib.sha256(content).hexdigest()
    manifest = {
        "files": file_hashes,
        "package": manifest_package,
    }
    (package / ".cargo-checksum.json").write_text(
        json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
        encoding="ascii",
    )
    return cargo.make_vendor_read_only(directory)


def _vendor_receipt(record, vendor_digest, changes=None):
    value = {
        "schema_version": 1,
        "lock_receipt_sha256": hashlib.sha256(cargo.encode_receipt(record)).hexdigest(),
        "lock_sha256": record["lock_sha256"],
        "vendor_sha256": vendor_digest,
    }
    if changes:
        value.update(changes)
    data = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
    return data, hashlib.sha256(data).hexdigest()


def _verify(vendor, record, vendor_receipt, trusted_digest, lock_bytes=LOCK_BYTES):
    return subject.verify_vendor_tree(
        lock_bytes, record, _lock_context(record), _authorized_audits(record),
        vendor, vendor_receipt, trusted_digest,
    )


def _unfreeze(directory):
    root = Path(directory)
    if not root.exists():
        return
    for current, directories, files in os.walk(root, topdown=False, followlinks=False):
        current_path = Path(current)
        for name in files:
            path = current_path / name
            if not path.is_symlink():
                path.chmod(0o644)
        for name in directories:
            path = current_path / name
            if not path.is_symlink():
                path.chmod(0o755)
    root.chmod(0o755)


def _remove_cargo_environment(environment):
    for key in ("HOME", "CARGO_HOME", "RUSTUP_HOME"):
        os.rmdir(environment[key])


class CargoVendorVerifyTests(unittest.TestCase):
    def test_valid_vendor_is_bound_to_lock_receipt_and_forces_offline_config(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary) / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            try:
                result = _verify(vendor, record, receipt, trusted_digest)
                self.assertEqual(result["vendor_sha256"], digest)
                rendered = " ".join(result["cargo_arguments"])
                self.assertIn("net.offline=true", rendered)
                self.assertIn("source.crates-io.replace-with", rendered)
                self.assertIn("source.verified-vendor.directory", rendered)
                self.assertNotIn("CARGO_NET_OFFLINE", result["environment"])
                self.assertTrue(result["environment"]["CARGO_HOME"])
            finally:
                if "result" in locals():
                    _remove_cargo_environment(result["environment"])
                _unfreeze(vendor)

    def test_vendor_receipt_digest_must_be_from_trusted_handoff(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary) / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            try:
                with self.assertRaises(cargo.Refusal) as raised:
                    _verify(vendor, record, receipt, "0" * 64)
                self.assertEqual(raised.exception.reason, "cargo_vendor_invalid")
            finally:
                _unfreeze(vendor)

    def test_vendor_receipt_must_bind_the_exact_lock_receipt(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary) / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(
                record, digest, {"lock_receipt_sha256": "0" * 64},
            )
            try:
                with self.assertRaises(cargo.Refusal) as raised:
                    _verify(vendor, record, receipt, trusted_digest)
                self.assertEqual(raised.exception.reason, "cargo_vendor_invalid")
            finally:
                _unfreeze(vendor)

    def test_extra_or_missing_package_is_refused(self):
        record = _lock_receipt()
        for add_extra in (True, False):
            with self.subTest(add_extra=add_extra):
                with tempfile.TemporaryDirectory() as temporary:
                    vendor = Path(temporary) / "vendor"
                    vendor.mkdir()
                    digest = _write_vendor(vendor)
                    if add_extra:
                        vendor.chmod(0o755)
                        extra = vendor / "unreceipted-1.0.0"
                        extra.mkdir()
                        (extra / "Cargo.toml").write_text("unreceipted", encoding="ascii")
                        (extra / "Cargo.toml").chmod(0o444)
                        extra.chmod(0o555)
                        vendor.chmod(0o555)
                    else:
                        vendor.chmod(0o755)
                        package = vendor / "serde-1.0.1"
                        package.chmod(0o755)
                        for path in package.rglob("*"):
                            if path.is_file():
                                path.chmod(0o644)
                            elif path.is_dir():
                                path.chmod(0o755)
                        package.chmod(0o755)
                        for path in sorted(package.rglob("*"), key=lambda item: len(item.parts), reverse=True):
                            if path.is_dir():
                                path.rmdir()
                            else:
                                path.unlink()
                        package.rmdir()
                        vendor.chmod(0o555)
                    receipt, trusted_digest = _vendor_receipt(record, digest)
                    try:
                        with self.assertRaises(cargo.Refusal) as raised:
                            _verify(vendor, record, receipt, trusted_digest)
                        self.assertEqual(raised.exception.reason, "cargo_vendor_invalid")
                    finally:
                        _unfreeze(vendor)

    def test_changed_file_is_refused_even_when_vendor_checksum_is_rewritten(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary) / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            package = vendor / "serde-1.0.1"
            source = package / "src" / "lib.rs"
            checksum = package / ".cargo-checksum.json"
            source.chmod(0o644)
            source.write_bytes(b"pub fn value() -> u8 { 2 }\n")
            source.chmod(0o444)
            checksum.chmod(0o644)
            manifest = json.loads(checksum.read_text("ascii"))
            manifest["files"]["src/lib.rs"] = hashlib.sha256(source.read_bytes()).hexdigest()
            checksum.write_text(
                json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
                encoding="ascii",
            )
            checksum.chmod(0o444)
            try:
                with self.assertRaises(cargo.Refusal) as raised:
                    _verify(vendor, record, receipt, trusted_digest)
                self.assertEqual(raised.exception.reason, "cargo_vendor_invalid")
            finally:
                _unfreeze(vendor)

    def test_manifest_package_checksum_must_match_lock_receipt(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary) / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor, manifest_package="0" * 64)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            try:
                with self.assertRaises(cargo.Refusal) as raised:
                    _verify(vendor, record, receipt, trusted_digest)
                self.assertEqual(raised.exception.reason, "cargo_vendor_invalid")
            finally:
                _unfreeze(vendor)

    def test_file_hash_manifest_is_checked_independently_of_vendor_receipt(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary) / "vendor"
            vendor.mkdir()
            _write_vendor(vendor)
            source = vendor / "serde-1.0.1" / "src" / "lib.rs"
            source.chmod(0o644)
            source.write_bytes(b"pub fn value() -> u8 { 2 }\n")
            source.chmod(0o444)
            digest = cargo.vendor_tree_digest(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            try:
                with self.assertRaises(cargo.Refusal) as raised:
                    _verify(vendor, record, receipt, trusted_digest)
                self.assertEqual(raised.exception.reason, "cargo_vendor_invalid")
            finally:
                _unfreeze(vendor)

    def test_writable_vendor_tree_is_refused(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary) / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            (vendor / "serde-1.0.1" / "Cargo.toml").chmod(0o644)
            try:
                with self.assertRaises(cargo.Refusal) as raised:
                    _verify(vendor, record, receipt, trusted_digest)
                self.assertEqual(raised.exception.reason, "cargo_vendor_invalid")
            finally:
                _unfreeze(vendor)

    def test_lock_mismatch_is_refused_before_cargo_configuration(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary) / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            changed_lock = LOCK_BYTES.replace(b'version = "1.0.1"', b'version = "1.0.2"')
            try:
                with patch.object(
                        cargo, "cargo_config_for_vendor",
                        side_effect=AssertionError("configuration was requested")):
                    with self.assertRaises(cargo.Refusal) as raised:
                        _verify(vendor, record, receipt, trusted_digest, changed_lock)
                self.assertEqual(raised.exception.reason, "cargo_lock_mismatch")
            finally:
                _unfreeze(vendor)

    def test_duplicate_vendor_receipt_fields_are_refused(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary) / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, unused_trusted_digest = _vendor_receipt(record, digest)
            duplicate = receipt[:-1] + b',"schema_version":1}'
            trusted_digest = hashlib.sha256(duplicate).hexdigest()
            try:
                with self.assertRaises(cargo.Refusal) as raised:
                    _verify(vendor, record, duplicate, trusted_digest)
                self.assertEqual(raised.exception.reason, "cargo_vendor_invalid")
            finally:
                _unfreeze(vendor)


if __name__ == "__main__":
    unittest.main()
