import copy
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock, patch

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


def _trusted_context(record):
    context = {field: record[field] for field in subject.CONTEXT_FIELDS}
    context["receipt_sha256"] = hashlib.sha256(subject.encode_receipt(record)).hexdigest()
    return context


def _authorized_audits(record):
    return {
        (item["name"], item["version"], item["checksum"]): item["audit_record_id"]
        for item in record["packages"]
    }


def _verify_lock(lock_bytes=LOCK_BYTES, record=None, context=None, audits=None):
    if record is None:
        record = _receipt(lock_bytes)
    if context is None:
        context = _trusted_context(record)
    if audits is None:
        audits = _authorized_audits(record)
    return subject.verify_lock_against_receipt(lock_bytes, record, context, audits)


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
            LOCK_BYTES + b"dependencies = []\n",
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
        internal_underscore = LOCK_BYTES.replace(b'name = "serde"', b'name = "KeelDock_private"')
        duplicate = LOCK_BYTES + LOCK_BYTES[LOCK_BYTES.index(b"[[package]]"):]
        bad_checksum = LOCK_BYTES.replace(CHECKSUM.encode(), b"z" * 64)
        for lock_bytes in (
            no_checksum, workspace_checksum, path_source, git_source, alternate_source,
            internal_name, internal_underscore, duplicate, bad_checksum,
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

    def test_sparse_crates_io_identity_normalizes_packages_and_edges(self):
        sparse = subject.SPARSE_REGISTRY_SOURCE.encode("ascii")
        registry = subject.REGISTRY_SOURCE.encode("ascii")
        workspace = (
            b'version = 4\n[[package]]\nname = "local"\nversion = "0.1.0"\n'
            + b'dependencies = ["serde 1.0.1 (' + sparse + b')"]\n'
            + LOCK_BYTES.replace(b"version = 4\n\n", b"").replace(registry, sparse)
        )
        parsed = subject.parse_cargo_lock(workspace)
        self.assertEqual(parsed["packages"][0]["dependencies"][0][2], subject.REGISTRY_SOURCE)
        self.assertEqual(parsed["packages"][1]["source"], subject.REGISTRY_SOURCE)
        self.assertTrue(_verify_lock(workspace))

    def test_lock_parser_bounds_array_work_and_package_count(self):
        multiline = LOCK_BYTES.replace(b"dependencies = []", b"dependencies = [\n]")
        with patch.object(subject, "MAX_DEPENDENCY_ARRAY_LINES", 1):
            _assert_refused(self, lambda: subject.parse_cargo_lock(multiline), "cargo_lock_invalid")
        with patch.object(subject, "MAX_DEPENDENCY_ARRAY_BYTES", 1):
            _assert_refused(self, lambda: subject.parse_cargo_lock(LOCK_BYTES), "cargo_lock_invalid")
        one_dependency = LOCK_BYTES.replace(
            b"dependencies = []", b'dependencies = ["serde 1.0.1"]',
        )
        with patch.object(subject, "MAX_LOCK_DEPENDENCIES", 0):
            _assert_refused(
                self, lambda: subject.parse_cargo_lock(one_dependency), "cargo_lock_invalid",
            )
        second = (
            b'[[package]]\nname = "local"\nversion = "0.1.0"\n'
        )
        with patch.object(subject, "MAX_LOCK_PACKAGES", 1):
            _assert_refused(self, lambda: subject.parse_cargo_lock(LOCK_BYTES + second), "cargo_lock_invalid")

    def test_multiline_array_counts_raw_whitespace_and_comment_bytes(self):
        marker = chr(35).encode("ascii")
        for continuation in (b" " * 80, marker + b" " * 80):
            lock = LOCK_BYTES.replace(
                b"dependencies = []", b"dependencies = [\n" + continuation + b"\n]",
            )
            with patch.object(subject, "MAX_DEPENDENCY_ARRAY_BYTES", 64):
                _assert_refused(self, lambda: subject.parse_cargo_lock(lock), "cargo_lock_invalid")

    def test_multiline_array_counts_exact_line_terminators(self):
        for terminator in (b"\n", b"\r\n"):
            array = b"dependencies = [" + terminator + b"          ]" + terminator
            lock = LOCK_BYTES.replace(b"dependencies = []\n", array)
            with self.subTest(terminator=terminator):
                with patch.object(subject, "MAX_DEPENDENCY_ARRAY_BYTES", len(array) - 1):
                    _assert_refused(self, lambda: subject.parse_cargo_lock(lock), "cargo_lock_invalid")
                with patch.object(subject, "MAX_DEPENDENCY_ARRAY_BYTES", len(array)):
                    self.assertEqual(subject.parse_cargo_lock(lock)["version"], 4)

    def test_multiline_array_scans_each_nonempty_fragment_once(self):
        dependency = b'"serde 1.0.1",'
        lock = LOCK_BYTES.replace(
            b"dependencies = []", b"dependencies = [\n " + dependency + b"\n]",
        )
        original = subject._scan_array_fragment
        lengths = []

        def observe(fragment, *state):
            lengths.append(len(fragment))
            return original(fragment, *state)

        with patch.object(subject, "_scan_array_fragment", side_effect=observe):
            self.assertEqual(subject.parse_cargo_lock(lock)["version"], 4)
        self.assertEqual(lengths, [1, len(dependency), 1])

    def test_numeric_prerelease_leading_zero_refused_in_urls_lock_and_edges(self):
        _assert_refused(
            self, lambda: subject.crate_archive_url("serde", "1.0.0-01"), "cargo_archive_invalid",
        )
        bad_package = LOCK_BYTES.replace(b'version = "1.0.1"', b'version = "1.0.0-01"')
        _assert_refused(self, lambda: subject.parse_cargo_lock(bad_package), "cargo_lock_invalid")
        _assert_refused(
            self, lambda: subject._dependency_record("serde 1.0.0-01"), "cargo_lock_invalid",
        )
        self.assertIn("1.0.0-1+build.1", subject.crate_archive_url("serde", "1.0.0-1+build.1"))

    def test_registry_dependency_underscore_internal_name_refused(self):
        for source in (subject.REGISTRY_SOURCE, subject.SPARSE_REGISTRY_SOURCE):
            edge = "KeelDock_private 1.0.1 (" + source + ")"
            _assert_refused(self, lambda: subject._dependency_record(edge), "cargo_lock_invalid")

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
        internal_underscore = copy.deepcopy(record)
        internal_underscore["packages"][0]["name"] = "KeelDock_private"
        extra_package_field = copy.deepcopy(record)
        extra_package_field["packages"][0]["extra"] = "hidden"
        for invalid in (extra, missing, wrong_sha, boolean_schema, internal_package,
                        internal_underscore, extra_package_field):
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
        record["packages"][1]["version"] = "1.0.1"
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
        self.assertTrue(_verify_lock())
        record = _receipt()
        self.assertTrue(subject.verify_lock_against_receipt(
            LOCK_BYTES, subject.encode_receipt(record),
            _trusted_context(record), _authorized_audits(record),
        ))
        _assert_refused(
            self,
            lambda: _verify_lock(LOCK_BYTES + b"\n", _receipt()),
            "cargo_lock_mismatch",
        )
        wrong_package = _receipt()
        wrong_package["packages"][0]["checksum"] = "1" * 64
        wrong_package["lock_sha256"] = hashlib.sha256(LOCK_BYTES).hexdigest()
        _assert_refused(
            self, lambda: _verify_lock(LOCK_BYTES, wrong_package),
            "cargo_lock_mismatch",
        )
        missing_package = _receipt()
        missing_package["packages"] = []
        _assert_refused(
            self, lambda: _verify_lock(LOCK_BYTES, missing_package),
            "cargo_lock_mismatch",
        )

    def test_lock_receipt_requires_every_trusted_binding_and_provenance(self):
        record = _receipt()
        context = _trusted_context(record)
        changes = {
            "repository": "other/platform-ci",
            "workspace_path": "crates/other",
            "source_sha": "1" * 40,
            "base_sha": "2" * 40,
            "base_branch": "develop",
            "reviewed_diff_fingerprint": "3" * 64,
            "dependency_policy_revision": "policy-8",
            "control_sha": "4" * 40,
            "toolchain_hash": "5" * 64,
            "receipt_sha256": "6" * 64,
        }
        for field, value in changes.items():
            changed = dict(context)
            changed[field] = value
            with self.subTest(field=field):
                _assert_refused(
                    self,
                    lambda: _verify_lock(LOCK_BYTES, record, changed),
                    "cargo_lock_mismatch",
                )
        missing = dict(context)
        del missing["repository"]
        _assert_refused(self, lambda: _verify_lock(LOCK_BYTES, record, missing), "cargo_lock_mismatch")
        extra = dict(context)
        extra["unexpected"] = "value"
        _assert_refused(self, lambda: _verify_lock(LOCK_BYTES, record, extra), "cargo_lock_mismatch")

    def test_lock_receipt_requires_authorized_audit_mapping(self):
        record = _receipt()
        mapping = _authorized_audits(record)
        identity = next(iter(mapping))
        mapping[identity] = "audit-unreviewed"
        _assert_refused(
            self, lambda: _verify_lock(LOCK_BYTES, record, audits=mapping), "cargo_lock_mismatch",
        )
        _assert_refused(
            self, lambda: _verify_lock(LOCK_BYTES, record, audits={}), "cargo_lock_mismatch",
        )

    def test_archive_url_is_fixed_and_path_components_are_strict(self):
        self.assertEqual(
            subject.crate_archive_url("serde", "1.0.1"),
            "https://static.crates.io/crates/serde/serde-1.0.1.crate",
        )
        for name, version in (("../serde", "1.0.1"), (INTERNAL_PREFIX + "private", "1.0.1"),
                              ("KeelDock_private", "1.0.1"),
                              ("serde", "1.0.1/evil"), ("serde", "01.0.1")):
            _assert_refused(
                self, lambda: subject.crate_archive_url(name, version), "cargo_archive_invalid",
            )

    def test_archive_verifier_accepts_a_well_formed_in_memory_fixture(self):
        data = _archive()
        digest = hashlib.sha256(data).hexdigest()
        self.assertTrue(subject.verify_archive("serde", "1.0.1", data, digest))
        bare_directory = _archive((
            ("serde-1.0.1", b"", "directory"),
            ("serde-1.0.1/Cargo.toml", b"[package]\nname='serde'\n"),
        ), include_base=False)
        self.assertTrue(subject.verify_archive(
            "serde", "1.0.1", bare_directory, hashlib.sha256(bare_directory).hexdigest(),
        ))
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

    def test_archive_preflight_refuses_pax_and_gnu_long_name_headers(self):
        for format_name in (tarfile.PAX_FORMAT, tarfile.GNU_FORMAT):
            raw = io.BytesIO()
            with tarfile.open(fileobj=raw, mode="w", format=format_name) as archive:
                _tar_member(archive, "serde-1.0.1/Cargo.toml", b"[package]\n")
                if format_name == tarfile.PAX_FORMAT:
                    member = tarfile.TarInfo("serde-1.0.1/extra")
                    member.pax_headers = {"comment": "value"}
                    member.size = 1
                    archive.addfile(member, io.BytesIO(b"x"))
                else:
                    _tar_member(archive, "serde-1.0.1/" + "a" * 110, b"x")
            data = gzip.compress(raw.getvalue(), mtime=0)
            with self.subTest(format_name=format_name):
                if format_name == tarfile.PAX_FORMAT:
                    _assert_refused(
                        self, lambda: subject._preflight_tar_headers(raw.getvalue()),
                        "cargo_archive_invalid",
                    )
                _assert_refused(
                    self,
                    lambda: subject.verify_archive(
                        "serde", "1.0.1", data, hashlib.sha256(data).hexdigest(),
                    ),
                    "cargo_archive_invalid",
                )

    def test_archive_preflight_refuses_chained_extension_headers(self):
        raw = io.BytesIO()
        with tarfile.open(fileobj=raw, mode="w", format=tarfile.PAX_FORMAT) as archive:
            member = tarfile.TarInfo("serde-1.0.1/Cargo.toml")
            member.pax_headers = {"comment": "value"}
            content = b"[package]\n"
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
        archive_bytes = raw.getvalue()
        self.assertEqual(archive_bytes[156:157], b"x")
        extension_size = int(archive_bytes[124:136].strip(b"\x00 "), 8)
        extension_end = 512 + ((extension_size + 511) // 512) * 512
        chained = archive_bytes[:extension_end] + archive_bytes
        _assert_refused(
            self, lambda: subject._preflight_tar_headers(chained), "cargo_archive_invalid",
        )

    def test_archive_inspector_converts_tar_recursion_to_fixed_refusal(self):
        data = _archive()
        digest = hashlib.sha256(data).hexdigest()
        with patch.object(subject.tarfile, "open", side_effect=RecursionError):
            _assert_refused(
                self, lambda: subject.verify_archive("serde", "1.0.1", data, digest),
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
            _archive((("serde-1.0.1/src/rogue/", b"bad"),)),
            _archive((("serde-1.0.1/Cargo.toml", b"", "directory"),), include_base=False),
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
            data = _archive()
            _assert_refused(
                self, lambda: subject.verify_archive(
                    "serde", "1.0.1", data, hashlib.sha256(data).hexdigest(),
                ),
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
                self, lambda: subject._preflight_tar_headers(subject._bounded_gzip(data)),
                "cargo_archive_invalid",
            )
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

    def test_extractor_refuses_symlink_ancestor(self):
        data = _archive()
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            real = parent / "real"
            vendor = real / "vendor"
            vendor.mkdir(parents=True, mode=0o700)
            vendor.chmod(0o700)
            link = parent / "link"
            try:
                link.symlink_to("real", target_is_directory=True)
            except OSError:
                self.skipTest("symbolic links are unavailable")
            _assert_refused(
                self,
                lambda: subject.extract_archive("serde", "1.0.1", data, digest, link / "vendor"),
                "cargo_archive_invalid",
            )
            self.assertEqual(list(vendor.iterdir()), [])

    @unittest.skipIf(os.name == "nt", "POSIX descriptor walk")
    def test_extractor_accepts_trusted_symlink_above_private_root(self):
        data = _archive()
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            outer = Path(temporary)
            outer.chmod(0o755)
            real = outer / "real"
            real.mkdir(mode=0o755)
            vendor = real / "vendor"
            vendor.mkdir(mode=0o700)
            alias = outer / "alias"
            try:
                alias.symlink_to("real", target_is_directory=True)
            except OSError:
                self.skipTest("symbolic links are unavailable")
            package_root = subject.extract_archive(
                "serde", "1.0.1", data, digest, alias / "vendor",
            )
            self.assertEqual(package_root, (vendor / "serde-1.0.1").resolve())
            self.assertTrue((package_root / "Cargo.toml").is_file())
            for item in sorted(package_root.rglob("*"), key=lambda value: len(value.parts), reverse=True):
                item.chmod(0o755 if item.is_dir() else 0o644)
            package_root.chmod(0o755)

    @unittest.skipIf(os.name == "nt", "POSIX directory descriptors")
    def test_macos_extended_acl_on_ancestor_is_refused(self):
        library = Mock()
        library.acl_get_entry.return_value = 0
        library.acl_free.return_value = 0
        with tempfile.TemporaryDirectory() as temporary:
            ancestor_identity = subject._file_identity(Path(temporary).parent.stat())
            target_identity = subject._file_identity(Path(temporary).stat())
            inspected = []

            def get_acl(descriptor, acl_type):
                identity = subject._file_identity(os.fstat(descriptor))
                inspected.append(identity)
                if identity == ancestor_identity:
                    return 1
                subject.ctypes.set_errno(subject.errno.ENOENT)
                return None

            library.acl_get_fd_np.side_effect = get_acl
            with patch.object(subject.sys, "platform", "darwin"), patch.object(
                subject.ctypes, "CDLL", return_value=library,
            ):
                _assert_refused(
                    self,
                    lambda: subject._open_target_directory(temporary),
                    "cargo_archive_invalid",
                )
            self.assertEqual(inspected[-1], ancestor_identity)
            self.assertNotIn(target_identity, inspected)
        library.acl_get_entry.assert_called_once()
        library.acl_free.assert_called_once()

    @unittest.skipIf(os.name == "nt", "POSIX directory descriptors")
    def test_macos_extended_acl_on_private_target_is_refused(self):
        library = Mock()
        library.acl_get_entry.return_value = 0
        library.acl_free.return_value = 0
        with tempfile.TemporaryDirectory() as temporary:
            target_identity = subject._file_identity(Path(temporary).stat())

            def get_acl(descriptor, acl_type):
                if subject._file_identity(os.fstat(descriptor)) == target_identity:
                    return 1
                subject.ctypes.set_errno(subject.errno.ENOENT)
                return None

            library.acl_get_fd_np.side_effect = get_acl
            with patch.object(subject.sys, "platform", "darwin"), patch.object(
                subject.ctypes, "CDLL", return_value=library,
            ):
                _assert_refused(
                    self,
                    lambda: subject._open_target_directory(temporary),
                    "cargo_archive_invalid",
                )
        library.acl_get_entry.assert_called_once()
        library.acl_free.assert_called_once()

    def test_extractor_cleans_failed_private_staging(self):
        data = _archive()
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(subject.os, "write", side_effect=OSError("write failed")):
                _assert_refused(
                    self,
                    lambda: subject.extract_archive("serde", "1.0.1", data, digest, temporary),
                    "cargo_archive_invalid",
                )
            self.assertEqual(list(Path(temporary).iterdir()), [])

    @unittest.skipIf(os.name == "nt", "POSIX mode boundary")
    def test_extractor_requires_private_owned_target(self):
        data = _archive()
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "shared"
            target.mkdir(mode=0o755)
            target.chmod(0o755)
            _assert_refused(
                self,
                lambda: subject.extract_archive("serde", "1.0.1", data, digest, target),
                "cargo_archive_invalid",
            )
            self.assertEqual(list(target.iterdir()), [])

    @unittest.skipIf(os.name == "nt", "POSIX ancestor permissions")
    def test_extractor_refuses_writable_ancestor_of_private_target(self):
        data = _archive()
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            shared = Path(temporary) / "shared"
            shared.mkdir(mode=0o777)
            shared.chmod(0o777)
            target = shared / "private"
            target.mkdir(mode=0o700)
            _assert_refused(
                self,
                lambda: subject.extract_archive("serde", "1.0.1", data, digest, target),
                "cargo_archive_invalid",
            )
            self.assertEqual(list(target.iterdir()), [])

    @unittest.skipUnless(sys.platform == "darwin", "macOS system alias")
    def test_macos_system_temp_alias_returns_physical_path(self):
        if not Path("/var").is_symlink():
            self.skipTest("system temporary path has no alias")
        with tempfile.TemporaryDirectory(dir="/var/tmp") as temporary:
            descriptor, physical = subject._open_target_directory(temporary)
            try:
                expected = Path("/") / "private" / "var" / "tmp"
                self.assertTrue(str(physical).startswith(str(expected) + os.sep))
                self.assertEqual(subject._file_identity(os.fstat(descriptor)),
                                 subject._file_identity(physical.stat()))
            finally:
                os.close(descriptor)

    def test_extractor_refuses_staging_source_replacement_and_preserves_replacement(self):
        data = _archive()
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            swapped = []
            if os.name == "nt":
                publish = subject._publish_windows_stage

                def replace_source(stage, destination, identity):
                    moved = target / "moved"
                    os.rename(stage, moved)
                    stage.mkdir(mode=0o700)
                    swapped.append((stage, moved, identity))
                    publish(stage, destination, identity)

                publisher = "_publish_windows_stage"
            else:
                publish = subject._publish_stage

                def replace_source(parent_fd, stage_name, final_name, identity):
                    os.rename(stage_name, "moved", src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
                    os.mkdir(stage_name, mode=0o700, dir_fd=parent_fd)
                    swapped.append((stage_name, identity))
                    publish(parent_fd, stage_name, final_name, identity)

                publisher = "_publish_stage"
            with patch.object(subject, publisher, side_effect=replace_source):
                _assert_refused(
                    self,
                    lambda: subject.extract_archive("serde", "1.0.1", data, digest, target),
                    "cargo_archive_invalid",
                )
            self.assertEqual(len(swapped), 1)
            self.assertFalse((target / "serde-1.0.1").exists())
            if os.name == "nt":
                stage, moved, identity = swapped[0]
                self.assertEqual(list(stage.iterdir()), [])
                stage.rmdir()
                subject._remove_windows_stage(moved, identity)
            else:
                stage_name, identity = swapped[0]
                self.assertEqual(list((target / stage_name).iterdir()), [])
                parent_fd, unused_target = subject._open_target_directory(target)
                try:
                    os.rmdir(stage_name, dir_fd=parent_fd)
                    subject._remove_stage(parent_fd, "moved", identity)
                finally:
                    os.close(parent_fd)
            self.assertEqual(list(target.iterdir()), [])

    @unittest.skipIf(os.name == "nt", "POSIX publication API")
    def test_publication_refuses_source_substitution_during_rename(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent_fd, unused_target = subject._open_target_directory(temporary)
            try:
                os.mkdir("stage", mode=0o700, dir_fd=parent_fd)
                identity = subject._entry_identity(parent_fd, "stage")

                def substitute(old_fd, old_name, new_fd, new_name, unused_flag):
                    source = old_name.decode("ascii")
                    destination = new_name.decode("ascii")
                    os.rename(source, "moved", src_dir_fd=old_fd, dst_dir_fd=old_fd)
                    os.mkdir(source, mode=0o700, dir_fd=old_fd)
                    os.rename(source, destination, src_dir_fd=old_fd, dst_dir_fd=new_fd)
                    return 0

                symbol = "renameatx_np" if sys.platform == "darwin" else "renameat2"
                library = Mock()
                setattr(library, symbol, Mock(side_effect=substitute))
                with patch.object(subject.ctypes, "CDLL", return_value=library):
                    _assert_refused(
                        self,
                        lambda: subject._publish_stage(parent_fd, "stage", "published", identity),
                        "cargo_archive_invalid",
                    )
                self.assertEqual(subject._entry_identity(parent_fd, "moved"), identity)
                self.assertNotEqual(subject._entry_identity(parent_fd, "published"), identity)
                os.rmdir("moved", dir_fd=parent_fd)
                os.rmdir("published", dir_fd=parent_fd)
            finally:
                os.close(parent_fd)

    @unittest.skipIf(os.name == "nt", "POSIX publication API")
    def test_macos_no_replace_publication_uses_darwin_symbol(self):
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            parent_fd, unused_target = subject._open_target_directory(target)
            try:
                os.mkdir("stage", mode=0o700, dir_fd=parent_fd)
                identity = subject._entry_identity(parent_fd, "stage")
                flags = []

                def rename_call(old_fd, old_name, new_fd, new_name, flag):
                    flags.append(flag)
                    os.rename(old_name, new_name, src_dir_fd=old_fd, dst_dir_fd=new_fd)
                    return 0

                function = Mock(side_effect=rename_call)
                library = Mock(renameatx_np=function)
                with patch.object(subject.sys, "platform", "darwin"):
                    with patch.object(subject.ctypes, "CDLL", return_value=library):
                        subject._publish_stage(parent_fd, "stage", "published", identity)
                self.assertEqual(flags, [4])
                self.assertEqual(subject._entry_identity(parent_fd, "published"), identity)
                os.rmdir("published", dir_fd=parent_fd)
            finally:
                os.close(parent_fd)

    @unittest.skipIf(os.name == "nt", "POSIX descriptor race")
    def test_extractor_refuses_child_directory_replaced_during_write(self):
        data = _archive()
        digest = hashlib.sha256(data).hexdigest()
        open_directory = subject._open_relative_directory
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            vendor = parent / "vendor"
            outside = parent / "outside"
            vendor.mkdir(mode=0o700)
            outside.mkdir()
            replaced = [False]

            def swap_child(root_fd, parts):
                if parts == ["src"] and not replaced[0]:
                    os.rmdir("src", dir_fd=root_fd)
                    os.symlink(str(outside), "src", dir_fd=root_fd)
                    replaced[0] = True
                return open_directory(root_fd, parts)

            with patch.object(subject, "_open_relative_directory", side_effect=swap_child):
                _assert_refused(
                    self,
                    lambda: subject.extract_archive("serde", "1.0.1", data, digest, vendor),
                    "cargo_archive_invalid",
                )
            self.assertTrue(replaced[0])
            self.assertEqual(list(vendor.iterdir()), [])
            self.assertEqual(list(outside.iterdir()), [])

    def test_extractor_atomic_publish_never_replaces_existing_package(self):
        data = _archive()
        digest = hashlib.sha256(data).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            if os.name == "nt":
                publish = subject._publish_windows_stage

                def competing_writer(stage, destination, identity):
                    destination.mkdir()
                    publish(stage, destination, identity)

                publisher = "_publish_windows_stage"
            else:
                publish = subject._publish_stage

                def competing_writer(parent_fd, stage_name, final_name, identity):
                    os.mkdir(final_name, dir_fd=parent_fd)
                    publish(parent_fd, stage_name, final_name, identity)

                publisher = "_publish_stage"
            with patch.object(subject, publisher, side_effect=competing_writer):
                _assert_refused(
                    self,
                    lambda: subject.extract_archive("serde", "1.0.1", data, digest, temporary),
                    "cargo_archive_invalid",
                )
            self.assertEqual(
                sorted(item.name for item in Path(temporary).iterdir()), ["serde-1.0.1"],
            )
            self.assertEqual(list((Path(temporary) / "serde-1.0.1").iterdir()), [])

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
                "HOME": "untrusted", "RUSTUP_HOME": "untrusted",
                "RUSTUP_TOOLCHAIN": "attacker", "LANG": "C",
                "CARGO_ENCODED_RUSTFLAGS": "untrusted", "RUSTC_WRAPPER": "untrusted",
                "RUSTFLAGS": "untrusted", "RUSTDOC": "untrusted",
                "RUSTDOCFLAGS": "untrusted", "SSL_CERT_FILE": "untrusted",
                "SSL_CERT_DIR": "untrusted", "NIX_SSL_CERT_FILE": "untrusted",
                "REQUESTS_CA_BUNDLE": "untrusted", "CURL_CA_BUNDLE": "untrusted",
                "HTTP_PROXY": "proxy", "ftp_proxy": "proxy",
                "KEELDOCK_TEST": "untrusted", "PATH": "/attacker",
                "TMPDIR": "/attacker/tmp", "TEMP": "/attacker/temp", "TMP": "/attacker/tmp2",
            }, clear=True):
                with patch.object(subject.tempfile, "gettempdir", side_effect=AssertionError):
                    arguments, environment = subject.cargo_config_for_vendor(temporary)
            for key in ("HOME", "CARGO_HOME", "RUSTUP_HOME"):
                self.addCleanup(os.rmdir, environment[key])
            rendered = " ".join(arguments)
            self.assertIn("net.offline=true", rendered)
            self.assertIn("registry.global-credential-providers=[]", rendered)
            self.assertIn("source.crates-io.replace-with", rendered)
            self.assertIn("patch.crates-io={}", rendered)
            self.assertIn("target.x86_64-unknown-linux-gnu.runner=[]", rendered)
            for key in (
                "CARGO_NET_OFFLINE", "CARGO_ENCODED_RUSTFLAGS", "RUSTC_WRAPPER",
                "RUSTFLAGS", "RUSTDOC", "RUSTDOCFLAGS", "SSL_CERT_FILE",
                "SSL_CERT_DIR", "NIX_SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
                "CURL_CA_BUNDLE", "HTTP_PROXY", "ftp_proxy", "KEELDOCK_TEST",
                "RUSTUP_TOOLCHAIN",
            ):
                with self.subTest(key=key):
                    self.assertNotIn(key, environment)
            if os.name != "nt":
                self.assertEqual(environment["PATH"], "/usr/bin:/bin")
                self.assertEqual(environment["TMPDIR"], "/tmp")
            else:
                self.assertEqual(environment["TEMP"], environment["TMPDIR"])
                self.assertEqual(environment["TMP"], environment["TMPDIR"])
                self.assertNotEqual(environment["TEMP"], "/attacker/temp")
            self.assertEqual(environment["LANG"], "C")
            expected_keys = {"PATH", "TMPDIR", "HOME", "CARGO_HOME", "RUSTUP_HOME", "LANG"}
            if os.name == "nt":
                expected_keys.update(("TEMP", "TMP"))
            self.assertEqual(set(environment), expected_keys)
            self.assertEqual(len({environment[key] for key in ("HOME", "CARGO_HOME", "RUSTUP_HOME")}), 3)
            self.assertNotEqual(environment["HOME"], "untrusted")
            self.assertNotEqual(environment["RUSTUP_HOME"], "untrusted")
            for key in ("HOME", "CARGO_HOME", "RUSTUP_HOME"):
                with self.subTest(key=key):
                    self.assertTrue(Path(environment[key]).is_dir())
                    if os.name != "nt":
                        self.assertEqual(Path(environment[key]).stat().st_mode & 0o777, 0o700)

    def test_windows_temp_root_comes_from_profile_api(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve() / "Temp"
            root.mkdir()

            def known_folder(unused_window, folder, unused_token, unused_kind, buffer):
                self.assertEqual(folder, 0x001c)
                buffer.value = str(root.parent)
                return 0

            shell = Mock()
            shell.SHGetFolderPathW.side_effect = known_folder
            with patch.object(subject.ctypes, "windll", Mock(shell32=shell), create=True):
                with patch.object(subject.tempfile, "gettempdir", side_effect=AssertionError):
                    with patch.dict(os.environ, {"TMPDIR": "/attacker", "TEMP": "/attacker", "TMP": "/attacker"}):
                        self.assertEqual(subject._trusted_windows_temp_root(), str(root))

    def test_windows_temp_root_refuses_missing_profile_api(self):
        with patch.object(subject.ctypes, "windll", Mock(shell32=Mock(spec=[])), create=True):
            _assert_refused(
                self, subject._trusted_windows_temp_root, "cargo_config_invalid",
            )

    def test_windows_temp_root_refuses_reparse_ancestor(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary).resolve()
            real = parent / "real"
            (real / "Temp").mkdir(parents=True)
            link = parent / "link"
            try:
                link.symlink_to(real, target_is_directory=True)
            except OSError:
                self.skipTest("symbolic links are unavailable")

            def known_folder(unused_window, unused_folder, unused_token, unused_kind, buffer):
                buffer.value = str(link)
                return 0

            shell = Mock()
            shell.SHGetFolderPathW.side_effect = known_folder
            with patch.object(subject.ctypes, "windll", Mock(shell32=shell), create=True):
                _assert_refused(
                    self, subject._trusted_windows_temp_root, "cargo_config_invalid",
                )

    def test_cargo_configuration_refuses_unavailable_vendor_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            missing = str(Path(temporary) / "missing")
            _assert_refused(
                self, lambda: subject.cargo_config_for_vendor(missing), "cargo_config_invalid",
            )


if __name__ == "__main__":
    unittest.main()
