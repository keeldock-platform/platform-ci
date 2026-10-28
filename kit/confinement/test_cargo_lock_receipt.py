import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

import cargo_lock_receipt as subject


CHECKSUM = "a" * 64
INTERNAL_PREFIX = "keeldock" + "-"
LOCK_BYTES = (
    'version = 4\n\n'
    '[[package]]\n'
    'name = "serde"\n'
    'version = "1.0.1"\n'
    'source = "' + subject.REGISTRY_SOURCE + '"\n'
    'checksum = "' + CHECKSUM + '"\n'
    'dependencies = []\n'
).encode("ascii")


def _receipt(lock_bytes=LOCK_BYTES):
    return {
        "schema_version": 1,
        "repository": "keeldock/platform-ci",
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


def _tar_member(archive, name, data=b"", kind="file"):
    info = tarfile.TarInfo(name)
    info.mode = 0o777
    if kind == "directory":
        info.type = tarfile.DIRTYPE
        info.size = 0
        archive.addfile(info)
    elif kind == "symlink":
        info.type = tarfile.SYMTYPE
        info.linkname = "Cargo.toml"
        archive.addfile(info)
    elif kind == "hardlink":
        info.type = tarfile.LNKTYPE
        info.linkname = name.rsplit("/", 1)[0] + "/Cargo.toml"
        archive.addfile(info)
    elif kind == "device":
        info.type = tarfile.CHRTYPE
        archive.addfile(info)
    else:
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))


def _archive(extra=(), *, level=9, include_base=True):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        if include_base:
            _tar_member(archive, "serde-1.0.1/", kind="directory")
            _tar_member(archive, "serde-1.0.1/Cargo.toml", b"[package]\nname='serde'\n")
            _tar_member(archive, "serde-1.0.1/Cargo.toml.orig", b"[package]\nname='serde'\n")
            _tar_member(archive, "serde-1.0.1/src/", kind="directory")
            _tar_member(archive, "serde-1.0.1/src/lib.rs", b"pub fn value() -> u8 { 1 }\n")
        for entry in extra:
            if len(entry) == 2:
                name, payload = entry
                _tar_member(archive, name, payload)
            else:
                name, payload, kind = entry
                _tar_member(archive, name, payload, kind)
    return gzip.compress(raw.getvalue(), compresslevel=level, mtime=0)


def _assert_refused(test, callback, reason=None):
    with test.assertRaises(subject.Refusal) as raised:
        callback()
    if reason is not None:
        test.assertEqual(raised.exception.reason, reason)
    test.assertNotIn("serde", str(raised.exception))


class CargoLockReceiptTests(unittest.TestCase):
    def test_lock_parser_accepts_supported_versions_and_workspace_members(self):
        self.assertEqual(subject.parse_cargo_lock(LOCK_BYTES)["version"], 4)
        v3 = LOCK_BYTES.replace(b"version = 4", b"version = 3")
        self.assertEqual(subject.parse_cargo_lock(v3)["version"], 3)
        workspace = (
            'version = 4\n\n[[package]]\nname = "' + INTERNAL_PREFIX + 'core"\n'
            'version = "0.1.0"\ndependencies = [\n "serde 1.0.1",\n]\n\n'
            '[[package]]\nname = "serde"\nversion = "1.0.1"\nsource = "'
            + subject.REGISTRY_SOURCE + '"\nchecksum = "' + CHECKSUM + '"\n'
        ).encode("ascii")
        parsed = subject.parse_cargo_lock(workspace)
        self.assertEqual(len(parsed["packages"]), 2)

    def test_lock_parser_refuses_unknown_keys_and_malformed_toml(self):
        cases = (
            LOCK_BYTES.replace(b"dependencies = []", b"unexpected = []"),
            LOCK_BYTES.replace(b"version = 4", b"version = 2"),
            LOCK_BYTES.replace(b"[[package]]", b"[package]"),
            LOCK_BYTES + b"unknown = true\n",
            b"version = 4\n[[package]]\nname = 'serde'\n",
            b"\xef\xbb\xbf" + LOCK_BYTES,
            LOCK_BYTES.replace(b"name = \"serde\"", b"name = \"serde\"\nname = \"serde\""),
            LOCK_BYTES + b"[[metadata]]\n",
            LOCK_BYTES.replace(b"dependencies = []", b"dependencies = [,,]"),
        )
        for lock_bytes in cases:
            with self.subTest(size=len(lock_bytes)):
                _assert_refused(self, lambda: subject.parse_cargo_lock(lock_bytes), "cargo_lock_invalid")

    def test_lock_parser_refuses_bad_sources_checksums_duplicates_and_registry_names(self):
        no_checksum = LOCK_BYTES.replace(b'checksum = "' + CHECKSUM.encode() + b'"\n', b"")
        workspace_checksum = LOCK_BYTES.replace(
            b'source = "' + subject.REGISTRY_SOURCE.encode() + b'"\n', b"",
        )
        path_source = LOCK_BYTES.replace(
            subject.REGISTRY_SOURCE.encode(), b"path+file:///tmp/crate",
        )
        git_source = LOCK_BYTES.replace(
            subject.REGISTRY_SOURCE.encode(), b"git+https://example.invalid/repo",
        )
        alternate_source = LOCK_BYTES.replace(
            subject.REGISTRY_SOURCE.encode(), b"registry+https://example.invalid/index",
        )
        internal_name = LOCK_BYTES.replace(
            b'name = "serde"', ('name = "' + INTERNAL_PREFIX + 'private"').encode("ascii"),
        )
        duplicate = LOCK_BYTES + LOCK_BYTES[LOCK_BYTES.index(b"[[package]]"):]
        bad_checksum = LOCK_BYTES.replace(CHECKSUM.encode(), b"z" * 64)
        for lock_bytes in (
            no_checksum, workspace_checksum, path_source, git_source, alternate_source,
            internal_name, duplicate, bad_checksum,
        ):
            with self.subTest(lock=lock_bytes[:40]):
                _assert_refused(self, lambda: subject.parse_cargo_lock(lock_bytes), "cargo_lock_invalid")

    def test_lock_parser_bounds_input_and_validates_dependency_closure(self):
        _assert_refused(
            self, lambda: subject.parse_cargo_lock(b" " * (subject.MAX_LOCK_BYTES + 1)),
            "cargo_lock_invalid",
        )
        _assert_refused(self, lambda: subject.parse_cargo_lock(None), "cargo_lock_invalid")
        unresolved = LOCK_BYTES.replace(b"dependencies = []", b'dependencies = ["missing 1.0.0"]')
        alternate_edge = LOCK_BYTES.replace(
            b"dependencies = []",
            b'dependencies = ["serde 1.0.1 (git+https://example.invalid/repo)"]',
        )
        malformed_edge = LOCK_BYTES.replace(b"dependencies = []", b'dependencies = ["../serde"]')
        duplicate_edge = LOCK_BYTES.replace(
            b"dependencies = []", b'dependencies = ["serde 1.0.1", "serde 1.0.1"]',
        )
        for lock_bytes in (unresolved, alternate_edge, malformed_edge, duplicate_edge):
            _assert_refused(self, lambda: subject.parse_cargo_lock(lock_bytes), "cargo_lock_invalid")

    def test_receipt_encodes_and_decodes_only_canonical_json(self):
        record = _receipt()
        encoded = subject.encode_receipt(record)
        self.assertEqual(subject.decode_receipt(encoded), record)
        self.assertEqual(encoded, subject.encode_receipt(copy.deepcopy(record)))
        extra = copy.deepcopy(record)
        extra["unexpected"] = "private value"
        missing = copy.deepcopy(record)
        del missing["repository"]
        wrong_sha = copy.deepcopy(record)
        wrong_sha["source_sha"] = "z" * 40
        boolean_schema = copy.deepcopy(record)
        boolean_schema["schema_version"] = True
        internal_package = copy.deepcopy(record)
        internal_package["packages"][0]["name"] = INTERNAL_PREFIX + "private"
        extra_package_field = copy.deepcopy(record)
        extra_package_field["packages"][0]["extra"] = "hidden"
        for invalid in (extra, missing, wrong_sha, boolean_schema, internal_package, extra_package_field):
            _assert_refused(self, lambda: subject.encode_receipt(invalid), "cargo_receipt_invalid")

    def test_receipt_decoder_rejects_duplicates_noncanonical_bytes_and_oversize(self):
        encoded = subject.encode_receipt(_receipt())
        duplicate = encoded[:-1] + b',"schema_version":1}'
        noncanonical = json.dumps(_receipt(), sort_keys=False).encode("ascii")
        _assert_refused(self, lambda: subject.decode_receipt(duplicate), "cargo_receipt_invalid")
        _assert_refused(self, lambda: subject.decode_receipt(noncanonical), "cargo_receipt_invalid")
        _assert_refused(
            self, lambda: subject.decode_receipt(b" " * (subject.MAX_RECEIPT_BYTES + 1)),
            "cargo_receipt_invalid",
        )
        malformed = b'{"source_sha":"secret input"'
        with self.assertRaises(subject.Refusal) as raised:
            subject.decode_receipt(malformed)
        self.assertNotIn("secret input", str(raised.exception))
        _assert_refused(
            self, lambda: subject.decode_receipt(b"\xff"), "cargo_receipt_invalid",
        )

    def test_receipt_package_order_identity_and_audit_id_are_strict(self):
        record = _receipt()
        record["packages"].append({
            "name": "serde_json", "version": "1.0.0", "checksum": "1" * 64,
            "audit_record_id": "audit-json",
        })
        record["packages"].reverse()
        _assert_refused(self, lambda: subject.encode_receipt(record), "cargo_receipt_invalid")
        record["packages"].reverse()
        record["packages"][1]["name"] = "serde"
        _assert_refused(self, lambda: subject.encode_receipt(record), "cargo_receipt_invalid")
        record = _receipt()
        record["packages"][0]["audit_record_id"] = "../secret"
        _assert_refused(self, lambda: subject.encode_receipt(record), "cargo_receipt_invalid")
        for field, value in (("name", "bad/name"), ("version", "1.0"),
                             ("checksum", "q" * 64), ("audit_record_id", "bad id")):
            record = _receipt()
            record["packages"][0][field] = value
            _assert_refused(self, lambda: subject.encode_receipt(record), "cargo_receipt_invalid")

    def test_receipt_rejects_invalid_context_fields_individually(self):
        changes = (
            ("repository", "owner/repo/extra"),
            ("workspace_path", "../workspace"),
            ("base_sha", "g" * 40),
            ("base_branch", "bad branch"),
            ("reviewed_diff_fingerprint", "0" * 63),
            ("dependency_policy_revision", ""),
            ("control_sha", "g" * 40),
            ("toolchain_hash", "g" * 64),
            ("lock_sha256", "g" * 64),
            ("packages", "not a list"),
        )
        for field, value in changes:
            record = _receipt()
            record[field] = value
            with self.subTest(field=field):
                _assert_refused(
                    self, lambda: subject.encode_receipt(record), "cargo_receipt_invalid",
                )

    def test_lock_must_match_receipt_hash_and_package_audit_mapping(self):
        self.assertTrue(subject.verify_lock_against_receipt(LOCK_BYTES, _receipt()))
        _assert_refused(
            self,
            lambda: subject.verify_lock_against_receipt(LOCK_BYTES + b"\n", _receipt()),
            "cargo_lock_mismatch",
        )
        wrong_package = _receipt()
        wrong_package["packages"][0]["checksum"] = "1" * 64
        wrong_package["lock_sha256"] = hashlib.sha256(LOCK_BYTES).hexdigest()
        _assert_refused(
            self, lambda: subject.verify_lock_against_receipt(LOCK_BYTES, wrong_package),
            "cargo_lock_mismatch",
        )
        missing_package = _receipt()
        missing_package["packages"] = []
        _assert_refused(
            self, lambda: subject.verify_lock_against_receipt(LOCK_BYTES, missing_package),
            "cargo_lock_mismatch",
        )

    def test_archive_url_is_fixed_and_path_components_are_strict(self):
        self.assertEqual(
            subject.crate_archive_url("serde", "1.0.1"),
            "https://static.crates.io/crates/serde/serde-1.0.1.crate",
        )
        for name, version in (("../serde", "1.0.1"), (INTERNAL_PREFIX + "private", "1.0.1"),
                              ("serde", "1.0.1/evil"), ("serde", "01.0.1")):
            _assert_refused(
                self, lambda: subject.crate_archive_url(name, version), "cargo_archive_invalid",
            )

    def test_archive_verifier_accepts_a_well_formed_in_memory_fixture(self):
        data = _archive()
        digest = hashlib.sha256(data).hexdigest()
        self.assertTrue(subject.verify_archive("serde", "1.0.1", data, digest))
        implicit_root = _archive(
            (("serde-1.0.1/Cargo.toml", b"[package]\nname='serde'\n"),),
            include_base=False,
        )
        self.assertTrue(subject.verify_archive(
            "serde", "1.0.1", implicit_root, hashlib.sha256(implicit_root).hexdigest(),
        ))

    def test_archive_verifier_rejects_checksum_gzip_and_tar_mismatches(self):
        data = _archive()
        _assert_refused(
            self, lambda: subject.verify_archive("serde", "1.0.1", data, "0" * 64),
            "cargo_archive_invalid",
        )
        invalid_gzip = b"not gzip"
        _assert_refused(
            self,
            lambda: subject.verify_archive(
                "serde", "1.0.1", invalid_gzip, hashlib.sha256(invalid_gzip).hexdigest(),
            ),
            "cargo_archive_invalid",
        )
        truncated_gzip = b"\x1f\x8btruncated"
        _assert_refused(
            self,
            lambda: subject.verify_archive(
                "serde", "1.0.1", truncated_gzip, hashlib.sha256(truncated_gzip).hexdigest(),
            ),
            "cargo_archive_invalid",
        )

    def test_archive_verifier_rejects_paths_links_devices_collisions_and_roots(self):
        cases = (
            _archive((("serde-1.0.1/../outside", b"bad"),)),
            _archive((("/serde-1.0.1/absolute", b"bad"),)),
            _archive((("serde-1.0.1/src/link", b"", "symlink"),)),
            _archive((("serde-1.0.1/src/hard", b"", "hardlink"),)),
            _archive((("serde-1.0.1/src/device", b"", "device"),)),
            _archive((("other-1.0.1/file", b"bad"),)),
            _archive((("serde-1.0.1/SRC/lib.rs", b"collision"),)),
            _archive((("serde-1.0.1/src\\escape", b"bad"),)),
            _archive((("serde-1.0.1/duplicate", b"a"), ("serde-1.0.1/duplicate", b"b"))),
            _archive((("serde-1.0.1/other.txt", b"bad"), ("other-1.0.1/file", b"bad")), include_base=False),
            _archive((("serde-1.0.1/", b"", "directory"), ("serde-1.0.1/README", b"readme")), include_base=False),
        )
        for data in cases:
            digest = hashlib.sha256(data).hexdigest()
            _assert_refused(
                self, lambda: subject.verify_archive("serde", "1.0.1", data, digest),
                "cargo_archive_invalid",
            )

    def test_archive_verifier_rejects_bad_embedded_checksum_manifest(self):
        bad_manifest = b'{"files":{"Cargo.toml":"' + b"0" * 64 + b'"},"package":"' + b"0" * 64 + b'"}'
        data = _archive((("serde-1.0.1/.cargo-checksum.json", bad_manifest),))
        digest = hashlib.sha256(data).hexdigest()
        _assert_refused(
            self, lambda: subject.verify_archive("serde", "1.0.1", data, digest),
            "cargo_archive_invalid",
        )

    def test_vendor_checksum_manifest_checks_exact_file_hashes(self):
        file_hashes = {"Cargo.toml": "1" * 64, "Cargo.toml.orig": "2" * 64}
        valid = json.dumps({"files": file_hashes, "package": CHECKSUM}).encode("ascii")
        subject._parse_checksum_manifest(valid, CHECKSUM, file_hashes)
        invalid_manifests = (
            json.dumps({
                "files": {"Cargo.toml": "0" * 64, "Cargo.toml.orig": "2" * 64},
                "package": CHECKSUM,
            }).encode("ascii"),
            json.dumps({"files": file_hashes, "package": "0" * 64}).encode("ascii"),
            b'{"files":{},"files":{},"package":"' + CHECKSUM.encode("ascii") + b'"}',
        )
        for manifest in invalid_manifests:
            _assert_refused(
                self,
                lambda: subject._parse_checksum_manifest(manifest, CHECKSUM, file_hashes),
                "cargo_archive_invalid",
            )

    def test_archive_verifier_enforces_file_and_compression_limits(self):
        oversized = _archive((("serde-1.0.1/src/large.bin", b"x" * 33),), level=0)
        digest = hashlib.sha256(oversized).hexdigest()
        with patch.object(subject, "MAX_FILE_BYTES", 32):
            _assert_refused(
                self, lambda: subject.verify_archive("serde", "1.0.1", oversized, digest),
                "cargo_archive_invalid",
            )
        compressed = _archive()
        digest = hashlib.sha256(compressed).hexdigest()
        with patch.object(subject, "MAX_COMPRESSION_RATIO", 1):
            _assert_refused(
                self, lambda: subject.verify_archive("serde", "1.0.1", compressed, digest),
                "cargo_archive_invalid",
            )
        with patch.object(subject, "MAX_ARCHIVE_BYTES", 32):
            _assert_refused(
                self, lambda: subject.verify_archive("serde", "1.0.1", b"x" * 33, "0" * 64),
                "cargo_archive_invalid",
            )
        with patch.object(subject, "MAX_TOTAL_BYTES", 64):
            data = _archive()
            _assert_refused(
                self,
                lambda: subject.verify_archive(
                    "serde", "1.0.1", data, hashlib.sha256(data).hexdigest(),
                ),
                "cargo_archive_invalid",
            )
        with patch.object(subject, "MAX_ARCHIVE_MEMBERS", 2):
            data = _archive()
            _assert_refused(
                self, lambda: subject.verify_archive("serde", "1.0.1", data, hashlib.sha256(data).hexdigest()),
                "cargo_archive_invalid",
            )

    def test_extractor_writes_vendor_checksum_and_freezes_package_tree(self):
        data = _archive()
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            package_root = subject.extract_archive(
                "serde", "1.0.1", data, digest, temporary,
            )
            self.assertEqual((package_root / "Cargo.toml.orig").read_bytes(), b"[package]\nname='serde'\n")
            checksum = json.loads((package_root / ".cargo-checksum.json").read_text("ascii"))
            self.assertEqual(checksum["package"], digest)
            self.assertEqual(
                checksum["files"]["Cargo.toml.orig"],
                hashlib.sha256((package_root / "Cargo.toml.orig").read_bytes()).hexdigest(),
            )
            self.assertEqual((package_root / "Cargo.toml").stat().st_mode & 0o777, 0o444)
            self.assertEqual(package_root.stat().st_mode & 0o777, 0o555)
            first = subject.make_vendor_read_only(temporary)
            self.assertEqual(Path(temporary).stat().st_mode & 0o777, 0o555)
            self.assertEqual(first, subject.vendor_tree_digest(temporary))
            _assert_refused(
                self,
                lambda: subject.extract_archive("serde", "1.0.1", data, digest, temporary),
                "cargo_archive_invalid",
            )
            for item in sorted(package_root.rglob("*"), key=lambda value: len(value.parts), reverse=True):
                item.chmod(0o755 if item.is_dir() else 0o644)
            package_root.chmod(0o755)
            Path(temporary).chmod(0o755)

    def test_vendor_digest_rejects_links_and_changes_with_mode_or_content(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "serde-1.0.1"
            source.mkdir()
            item = source / "lib.rs"
            item.write_bytes(b"one")
            first = subject.vendor_tree_digest(root)
            item.write_bytes(b"two")
            second = subject.vendor_tree_digest(root)
            self.assertNotEqual(first, second)
            item.chmod(0o444)
            third = subject.vendor_tree_digest(root)
            self.assertNotEqual(second, third)
            item.chmod(0o644)
            item.unlink()
            try:
                item.symlink_to("missing")
            except OSError:
                self.skipTest("symbolic links are unavailable")
            _assert_refused(
                self, lambda: subject.vendor_tree_digest(root), "cargo_archive_invalid",
            )

    def test_cargo_configuration_scrubs_environment_and_forces_offline_vendor(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.dict(os.environ, {
                "CARGO_HOME": "untrusted", "CARGO_NET_OFFLINE": "false",
                "RUSTC_WRAPPER": "untrusted", "HTTP_PROXY": "proxy",
                "ftp_proxy": "proxy", "KEELDOCK_TEST": "retained",
            }, clear=True):
                arguments, environment = subject.cargo_config_for_vendor(temporary)
            self.addCleanup(os.rmdir, environment["CARGO_HOME"])
            rendered = " ".join(arguments)
            self.assertIn("net.offline=true", rendered)
            self.assertIn("registry.global-credential-providers=[]", rendered)
            self.assertIn("source.crates-io.replace-with", rendered)
            self.assertIn("patch.crates-io={}", rendered)
            self.assertIn("target.x86_64-unknown-linux-gnu.runner=[]", rendered)
            self.assertNotIn("CARGO_NET_OFFLINE", environment)
            self.assertNotIn("RUSTC_WRAPPER", environment)
            self.assertNotIn("HTTP_PROXY", environment)
            self.assertNotIn("ftp_proxy", environment)
            self.assertEqual(environment["KEELDOCK_TEST"], "retained")
            self.assertTrue(Path(environment["CARGO_HOME"]).is_dir())

    def test_cargo_configuration_refuses_unavailable_vendor_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = str(Path(temporary) / "missing")
            _assert_refused(
                self, lambda: subject.cargo_config_for_vendor(missing), "cargo_config_invalid",
            )


if __name__ == "__main__":
    unittest.main()
