import unittest
from unittest.mock import patch

import cargo_lock_parser as subject


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


def _assert_refused(test, callback, reason=None):
    with test.assertRaises(subject.Refusal) as raised:
        callback()
    if reason is not None:
        test.assertEqual(raised.exception.reason, reason)
    test.assertNotIn("serde", str(raised.exception))


class CargoLockParserTests(unittest.TestCase):
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
        marker = b"\x23"
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
        bad_package = LOCK_BYTES.replace(b'version = "1.0.1"', b'version = "1.0.0-01"')
        _assert_refused(self, lambda: subject.parse_cargo_lock(bad_package), "cargo_lock_invalid")
        _assert_refused(
            self, lambda: subject._dependency_record("serde 1.0.0-01"), "cargo_lock_invalid",
        )

    def test_registry_dependency_underscore_internal_name_refused(self):
        for source in (subject.REGISTRY_SOURCE, subject.SPARSE_REGISTRY_SOURCE):
            edge = "KeelDock_private 1.0.1 (" + source + ")"
            _assert_refused(self, lambda: subject._dependency_record(edge), "cargo_lock_invalid")
