import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
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


def _write_vendor(directory, manifest_package=CHECKSUM,
                  source_bytes=b"pub fn value() -> u8 { 1 }\n"):
    package = Path(directory) / "serde-1.0.1"
    source = package / "src"
    source.mkdir(parents=True)
    files = {
        "Cargo.toml": b"[package]\nname='serde'\nversion='1.0.1'\n",
        "src/lib.rs": source_bytes,
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


def _verify(vendor, record, vendor_receipt, trusted_digest, lock_bytes=LOCK_BYTES,
            staging_root=None):
    if staging_root is None:
        staging_root = vendor.parent
    with patch.object(subject, "_require_protected_ancestor"), patch.object(
            subject, "_require_read_only_mount"):
        return subject.verify_vendor_tree(
            lock_bytes, record, _lock_context(record), _authorized_audits(record),
            vendor, vendor_receipt, trusted_digest, staging_root,
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


def _remove_materialized(result):
    materialized = result["materialized_vendor_directory"]
    parent_fd = os.open(
        materialized.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        cargo._remove_stage(parent_fd, materialized.name)
    finally:
        os.close(parent_fd)


def _scan_vendor(vendor):
    descriptor = os.open(
        vendor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
    )
    try:
        return cargo.vendor_tree_inventory_fd(descriptor)
    finally:
        os.close(descriptor)


@unittest.skipIf(os.name == "nt", "native Windows handoff is not available")
class CargoVendorVerifyTests(unittest.TestCase):
    def _assert_scan_refusal(self, vendor, record, receipt, trusted_digest):
        with self.assertRaises(cargo.Refusal) as scanned:
            _scan_vendor(vendor)
        self.assertEqual(scanned.exception.reason, "cargo_archive_invalid")
        with self.assertRaises(cargo.Refusal) as verified:
            _verify(vendor, record, receipt, trusted_digest)
        self.assertEqual(verified.exception.reason, "cargo_vendor_invalid")

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
                materialized = result["materialized_vendor_directory"]
                self.assertNotEqual(materialized, vendor)
                self.assertEqual(materialized.parent, Path(temporary).resolve())
                self.assertEqual(materialized.parent.stat().st_uid, os.geteuid())
                self.assertEqual(materialized.parent.stat().st_mode & 0o777, 0o700)
                self.assertFalse(materialized.is_symlink())
                self.assertEqual(materialized.stat().st_mode & 0o777, 0o555)
                self.assertEqual(
                    (materialized / "serde-1.0.1" / "src" / "lib.rs").read_bytes(),
                    (vendor / "serde-1.0.1" / "src" / "lib.rs").read_bytes(),
                )
                self.assertEqual(cargo.vendor_tree_digest(materialized), digest)
                self.assertIn(
                    "source.verified-vendor.directory="
                    + json.dumps(str(materialized), ensure_ascii=True),
                    result["cargo_arguments"],
                )
                self.assertNotIn("CARGO_NET_OFFLINE", result["environment"])
                self.assertTrue(result["environment"]["CARGO_HOME"])
            finally:
                if "result" in locals():
                    _remove_cargo_environment(result["environment"])
                    _remove_materialized(result)
                _unfreeze(vendor)

    def test_non_private_staging_root_is_refused_before_configuration(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            vendor = base / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            staging_root = base / "public"
            staging_root.mkdir()
            staging_root.chmod(0o755)
            try:
                with patch.object(
                        cargo, "cargo_config_for_vendor",
                        side_effect=AssertionError("configuration was requested")):
                    with self.assertRaises(cargo.Refusal) as raised:
                        _verify(
                            vendor, record, receipt, trusted_digest,
                            staging_root=staging_root,
                        )
                self.assertEqual(raised.exception.reason, "cargo_vendor_invalid")
                self.assertEqual(list(staging_root.iterdir()), [])
            finally:
                _unfreeze(vendor)

    def test_wrong_cargo_path_discards_the_materialized_tree(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            vendor = base / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            original_config = cargo.cargo_config_for_vendor
            created_environment = {}

            def wrong_config(path):
                arguments, environment = original_config(path)
                created_environment.update(environment)
                wrong_setting = (
                    "source.verified-vendor.directory="
                    + json.dumps(str(vendor), ensure_ascii=True)
                )
                arguments = [
                    wrong_setting if value.startswith(
                        "source.verified-vendor.directory=",
                    ) else value for value in arguments
                ]
                return arguments, environment

            try:
                with patch.object(cargo, "cargo_config_for_vendor", side_effect=wrong_config):
                    with self.assertRaises(cargo.Refusal) as raised:
                        _verify(vendor, record, receipt, trusted_digest)
                self.assertEqual(raised.exception.reason, "cargo_vendor_invalid")
                self.assertEqual(list(base.iterdir()), [vendor])
                for key in ("HOME", "CARGO_HOME", "RUSTUP_HOME"):
                    self.assertFalse(Path(created_environment[key]).exists())
            finally:
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
                    original_digest = _write_vendor(vendor)
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
                    digest = cargo.vendor_tree_digest(vendor)
                    self.assertNotEqual(digest, original_digest)
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
            _write_vendor(vendor)
            (vendor / "serde-1.0.1" / "Cargo.toml").chmod(0o644)
            digest = cargo.vendor_tree_digest(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
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

    def test_unprotected_ancestor_is_refused_before_configuration(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary) / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            try:
                with patch.object(subject.os, "geteuid", return_value=1001), patch.object(
                        subject, "_require_read_only_mount"), patch.object(
                            cargo, "cargo_config_for_vendor",
                            side_effect=AssertionError("configuration was requested")):
                    with self.assertRaises(cargo.Refusal) as raised:
                        subject.verify_vendor_tree(
                            LOCK_BYTES, record, _lock_context(record),
                            _authorized_audits(record), vendor, receipt, trusted_digest,
                            vendor.parent,
                        )
                self.assertEqual(raised.exception.reason, "cargo_vendor_invalid")
            finally:
                _unfreeze(vendor)

    def test_writable_mount_is_refused_before_configuration(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary) / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            try:
                with patch.object(subject.os, "geteuid", return_value=1001), patch.object(
                        subject, "_require_protected_ancestor"), patch.object(
                            cargo, "cargo_config_for_vendor",
                            side_effect=AssertionError("configuration was requested")):
                    with self.assertRaises(cargo.Refusal) as raised:
                        subject.verify_vendor_tree(
                            LOCK_BYTES, record, _lock_context(record),
                            _authorized_audits(record), vendor, receipt, trusted_digest,
                            vendor.parent,
                        )
                self.assertEqual(raised.exception.reason, "cargo_vendor_invalid")
            finally:
                _unfreeze(vendor)

    @unittest.skipUnless(sys.platform == "linux", "Linux mount policy")
    def test_read_only_bind_mount_with_writable_superblock_is_refused(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary) / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            try:
                with patch.object(subject.os, "geteuid", return_value=1001), patch.object(
                        subject, "_require_protected_ancestor"), patch.object(
                            subject, "_read_only_superblocks", return_value=set()), patch.object(
                                subject.os, "fstatvfs",
                                return_value=SimpleNamespace(f_flag=os.ST_RDONLY)), patch.object(
                                    cargo, "cargo_config_for_vendor",
                                    side_effect=AssertionError("configuration was requested")):
                    with self.assertRaises(cargo.Refusal) as raised:
                        subject.verify_vendor_tree(
                            LOCK_BYTES, record, _lock_context(record),
                            _authorized_audits(record), vendor, receipt, trusted_digest,
                            vendor.parent,
                        )
                self.assertEqual(raised.exception.reason, "cargo_vendor_invalid")
            finally:
                _unfreeze(vendor)

    def test_nested_writable_mount_is_refused_by_inventory(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary) / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            source = vendor / "serde-1.0.1" / "src" / "lib.rs"
            target = source.stat()

            def require_read_only(descriptor, unused_superblocks):
                metadata = os.fstat(descriptor)
                if metadata.st_dev == target.st_dev and metadata.st_ino == target.st_ino:
                    subject._refuse()

            try:
                with patch.object(subject.os, "geteuid", return_value=1001), patch.object(
                        subject, "_require_protected_ancestor"), patch.object(
                            subject, "_require_read_only_mount",
                            side_effect=require_read_only), patch.object(
                                cargo, "cargo_config_for_vendor",
                                side_effect=AssertionError("configuration was requested")):
                    with self.assertRaises(cargo.Refusal) as raised:
                        subject.verify_vendor_tree(
                            LOCK_BYTES, record, _lock_context(record),
                            _authorized_audits(record), vendor, receipt, trusted_digest,
                            vendor.parent,
                        )
                self.assertEqual(raised.exception.reason, "cargo_vendor_invalid")
            finally:
                _unfreeze(vendor)

    def test_privileged_caller_is_refused_before_configuration(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary) / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            try:
                with patch.object(subject.os, "geteuid", return_value=0), patch.object(
                        subject, "_require_protected_ancestor"), patch.object(
                            subject, "_require_read_only_mount"), patch.object(
                                cargo, "cargo_config_for_vendor",
                                side_effect=AssertionError("configuration was requested")):
                    with self.assertRaises(cargo.Refusal) as raised:
                        subject.verify_vendor_tree(
                            LOCK_BYTES, record, _lock_context(record),
                            _authorized_audits(record), vendor, receipt, trusted_digest,
                            vendor.parent,
                        )
                self.assertEqual(raised.exception.reason, "cargo_vendor_invalid")
            finally:
                _unfreeze(vendor)

    def test_symlink_hardlink_and_special_file_are_refused_by_anchored_scan(self):
        record = _lock_receipt()
        for kind in ("symlink", "hardlink", "special"):
            with self.subTest(kind=kind):
                with tempfile.TemporaryDirectory() as temporary:
                    vendor = Path(temporary) / "vendor"
                    vendor.mkdir()
                    digest = _write_vendor(vendor)
                    receipt, trusted_digest = _vendor_receipt(record, digest)
                    source = vendor / "serde-1.0.1" / "src"
                    source.chmod(0o755)
                    try:
                        if kind == "symlink":
                            (source / "alias.rs").symlink_to("lib.rs")
                        elif kind == "hardlink":
                            os.link(source / "lib.rs", source / "alias.rs")
                        else:
                            os.mkfifo(source / "alias.rs")
                        source.chmod(0o555)
                        self._assert_scan_refusal(vendor, record, receipt, trusted_digest)
                    finally:
                        _unfreeze(vendor)

    def test_reparse_attribute_is_refused_by_anchored_scan(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary) / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            original_stat = os.stat

            def reparse_stat(path, *args, **kwargs):
                metadata = original_stat(path, *args, **kwargs)
                if path != "src" or "dir_fd" not in kwargs:
                    return metadata
                return SimpleNamespace(
                    st_mode=metadata.st_mode, st_dev=metadata.st_dev,
                    st_ino=metadata.st_ino, st_size=metadata.st_size,
                    st_nlink=metadata.st_nlink, st_mtime_ns=metadata.st_mtime_ns,
                    st_file_attributes=0x400,
                )

            try:
                with patch.object(cargo.os, "stat", side_effect=reparse_stat), patch.object(
                        cargo, "cargo_config_for_vendor",
                        side_effect=AssertionError("configuration was requested")):
                    self._assert_scan_refusal(
                        vendor, record, receipt, trusted_digest,
                    )
            finally:
                _unfreeze(vendor)

    def test_vendor_file_size_and_member_count_limits_are_enforced(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary) / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            try:
                for field, limit in (
                        ("MAX_FILE_BYTES", 10), ("MAX_TOTAL_BYTES", 10),
                        ("MAX_ARCHIVE_MEMBERS", 2)):
                    with self.subTest(field=field):
                        with patch.object(cargo, field, limit):
                            self._assert_scan_refusal(
                                vendor, record, receipt, trusted_digest,
                            )
            finally:
                _unfreeze(vendor)

    def test_missing_and_extra_checksum_entries_are_refused(self):
        record = _lock_receipt()
        for extra_entry in (False, True):
            with self.subTest(extra_entry=extra_entry):
                with tempfile.TemporaryDirectory() as temporary:
                    vendor = Path(temporary) / "vendor"
                    vendor.mkdir()
                    _write_vendor(vendor)
                    manifest_path = vendor / "serde-1.0.1" / ".cargo-checksum.json"
                    manifest_path.chmod(0o644)
                    manifest = json.loads(manifest_path.read_text("ascii"))
                    if extra_entry:
                        manifest["files"]["ghost.rs"] = "0" * 64
                    else:
                        del manifest["files"]["src/lib.rs"]
                    manifest_path.write_text(
                        json.dumps(
                            manifest, ensure_ascii=True, sort_keys=True,
                            separators=(",", ":"),
                        ),
                        encoding="ascii",
                    )
                    manifest_path.chmod(0o444)
                    digest = cargo.vendor_tree_digest(vendor)
                    receipt, trusted_digest = _vendor_receipt(record, digest)
                    try:
                        with self.assertRaises(cargo.Refusal) as raised:
                            _verify(vendor, record, receipt, trusted_digest)
                        self.assertEqual(raised.exception.reason, "cargo_vendor_invalid")
                    finally:
                        _unfreeze(vendor)

    def test_ancestor_swap_during_configuration_keeps_cargo_on_the_copy(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            parent = base / "handoff"
            parent.mkdir()
            vendor = parent / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            replacement = base / "replacement"
            replacement.mkdir()
            replacement_vendor = replacement / "vendor"
            replacement_vendor.mkdir()
            replacement_digest = _write_vendor(
                replacement_vendor, source_bytes=b"pub fn value() -> u8 { 9 }\n",
            )
            self.assertNotEqual(replacement_digest, digest)
            moved = base / "moved"
            original_config = cargo.cargo_config_for_vendor
            result = None

            def swap_then_config(path):
                parent.rename(moved)
                replacement.rename(parent)
                return original_config(path)

            try:
                with patch.object(cargo, "cargo_config_for_vendor", side_effect=swap_then_config):
                    result = _verify(
                        vendor, record, receipt, trusted_digest, staging_root=base,
                    )
                materialized = result["materialized_vendor_directory"]
                self.assertEqual(cargo.vendor_tree_digest(materialized), digest)
                self.assertEqual(cargo.vendor_tree_digest(vendor), replacement_digest)
                self.assertIn(
                    "source.verified-vendor.directory="
                    + json.dumps(str(materialized), ensure_ascii=True),
                    result["cargo_arguments"],
                )
            finally:
                if result is not None:
                    _remove_cargo_environment(result["environment"])
                    _remove_materialized(result)
                for path in (vendor, moved / "vendor", replacement_vendor):
                    _unfreeze(path)

    def test_ancestor_swap_after_return_cannot_change_cargo_tree(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            parent = base / "handoff"
            parent.mkdir()
            vendor = parent / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            replacement = base / "replacement"
            replacement.mkdir()
            replacement_vendor = replacement / "vendor"
            replacement_vendor.mkdir()
            replacement_digest = _write_vendor(
                replacement_vendor, source_bytes=b"pub fn value() -> u8 { 9 }\n",
            )
            self.assertNotEqual(replacement_digest, digest)
            moved = base / "moved"
            result = None
            try:
                result = _verify(
                    vendor, record, receipt, trusted_digest, staging_root=base,
                )
                parent.rename(moved)
                replacement.rename(parent)
                setting = [
                    value.split("=", 1)[1] for value in result["cargo_arguments"]
                    if value.startswith("source.verified-vendor.directory=")
                ]
                self.assertEqual(len(setting), 1)
                cargo_path = Path(json.loads(setting[0]))
                self.assertEqual(cargo_path, result["materialized_vendor_directory"])
                self.assertEqual(cargo.vendor_tree_digest(cargo_path), digest)
                self.assertEqual(cargo.vendor_tree_digest(vendor), replacement_digest)
                self.assertNotEqual(cargo_path, vendor)
            finally:
                if result is not None:
                    _remove_cargo_environment(result["environment"])
                    _remove_materialized(result)
                for path in (vendor, moved / "vendor", replacement_vendor):
                    _unfreeze(path)


@unittest.skipUnless(os.name == "nt", "Windows handoff refusal")
class WindowsVendorHandoffTests(unittest.TestCase):
    def test_windows_refuses_without_native_namespace_protection(self):
        record = _lock_receipt()
        with tempfile.TemporaryDirectory() as temporary:
            vendor = Path(temporary) / "vendor"
            vendor.mkdir()
            digest = _write_vendor(vendor)
            receipt, trusted_digest = _vendor_receipt(record, digest)
            try:
                with self.assertRaises(cargo.Refusal) as raised:
                    subject.verify_vendor_tree(
                        LOCK_BYTES, record, _lock_context(record),
                        _authorized_audits(record), vendor, receipt, trusted_digest,
                        vendor.parent,
                    )
                self.assertEqual(raised.exception.reason, "cargo_vendor_invalid")
            finally:
                _unfreeze(vendor)


if __name__ == "__main__":
    unittest.main()
