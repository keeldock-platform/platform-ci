"""Offline tests for trusted Cargo registry archive verification."""

import gzip
import hashlib
import io
import tarfile
import unittest

import cargo_archive_producer as producer
import rust_license_gate as gate


PACKAGE_NAME = "fixture-crate"
PACKAGE_VERSION = "1.2.3"
REGISTRY_SOURCE = "registry+https:" + chr(47) * 2 + "github.com/rust-lang/crates.io-index"


class _Response:
    status = 200

    def __init__(self, payload, url=None):
        self.payload = payload
        self.url = url or producer.ARCHIVE_ORIGIN + "/crates/fixture-crate/fixture-crate-1.2.3.crate"
        self.headers = {"Content-Length": str(len(payload))}
        self.closed = False

    def geturl(self):
        return self.url

    def getcode(self):
        return self.status

    def read(self, size=-1):
        if size is None or size < 0:
            size = len(self.payload)
        result, self.payload = self.payload[:size], self.payload[size:]
        return result

    def close(self):
        self.closed = True


class _Opener:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        return self.response


def _crate_archive(*, cargo_toml=None, files=(), traversal=False, symlink=False, notices=True):
    package_root = PACKAGE_NAME + "-" + PACKAGE_VERSION
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:") as archive:
        directory = tarfile.TarInfo(package_root + "/")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        rows = [("Cargo.toml", cargo_toml or b'[package]\nname = "fixture-crate"\nversion = "1.2.3"\nlicense = "MIT OR Apache-2.0"\n')]
        if notices:
            rows.extend((
                ("LICENSE-MIT", b"fixture MIT text\n"),
                ("LICENSE-APACHE", b"fixture Apache text\n"),
            ))
        rows.extend(files)
        if traversal:
            rows.append(("../escape", b"escape"))
        for path, payload in rows:
            item = tarfile.TarInfo(package_root + "/" + path)
            item.size = len(payload)
            archive.addfile(item, io.BytesIO(payload))
        if symlink:
            item = tarfile.TarInfo(package_root + "/linked-license")
            item.type = tarfile.SYMTYPE
            item.linkname = "LICENSE-MIT"
            archive.addfile(item)
    return gzip.compress(raw.getvalue(), mtime=0)


def _lock(archive, *, source=REGISTRY_SOURCE, checksum=None):
    digest = checksum or hashlib.sha256(archive).hexdigest()
    return (
        'version = 4\n\n[[package]]\nname = "fixture-crate"\nversion = "1.2.3"\n'
        'source = "' + source + '"\nchecksum = "' + digest + '"\n'
    ).encode("ascii")


class CargoArchiveProducerTests(unittest.TestCase):
    def setUp(self):
        self.archive = _crate_archive()
        self.lock = _lock(self.archive)
        self.identity = gate.Identity(
            "a" * 40, "runtime", "/trusted/source/runtime",
            hashlib.sha256(self.lock).hexdigest(),
        )
        self.package = gate.Package(
            PACKAGE_NAME, PACKAGE_VERSION, hashlib.sha256(self.archive).hexdigest(),
        )
        self.response = _Response(self.archive)
        self.opener = _Opener(self.response)

    def test_authenticated_archive_yields_exact_lock_coverage_and_source_binding(self):
        evidence = producer.TrustedArchivePort(self.opener).verify_complete(
            self.lock, self.identity, (self.package,),
        )
        self.assertEqual(evidence.identity, self.identity)
        self.assertEqual(len(evidence.packages), 1)
        self.assertEqual(evidence.packages[0].package, self.package)
        self.assertEqual(evidence.packages[0].spdx, "MIT OR Apache-2.0")
        self.assertEqual(
            [row[0] for row in evidence.packages[0].notice_files],
            ["LICENSE-APACHE", "LICENSE-MIT"],
        )
        self.assertEqual(len(self.opener.calls), 1)
        request, timeout = self.opener.calls[0]
        self.assertEqual(request.full_url, producer._archive_url(self.package))
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(timeout, producer.PROCESS_TIMEOUT_SECONDS)
        self.assertTrue(self.response.closed)
        self.assertTrue(gate._valid_hash(evidence.archive_spdx_sha256))

    def test_changed_source_lock_or_archive_bytes_refuse(self):
        changed_identity = gate.Identity(
            "b" * 40, self.identity.profile, self.identity.root, self.identity.lock_sha256,
        )
        changed = producer.TrustedArchivePort(_Opener(_Response(self.archive))).verify_complete(
            self.lock, changed_identity, (self.package,),
        )
        original = producer.TrustedArchivePort(_Opener(_Response(self.archive))).verify_complete(
            self.lock, self.identity, (self.package,),
        )
        self.assertNotEqual(changed.archive_spdx_sha256, original.archive_spdx_sha256)
        altered_response = _Response(self.archive + b"x")
        with self.assertRaises(gate.LicenseGateRefusal):
            producer.TrustedArchivePort(_Opener(altered_response)).verify_complete(
                self.lock, self.identity, (self.package,),
            )
        other = gate.Package(self.package.name, self.package.version, "b" * 64)
        with self.assertRaises(gate.LicenseGateRefusal):
            producer.TrustedArchivePort(self.opener).verify_complete(
                self.lock, self.identity, (other,),
            )

    def test_redirect_bad_length_unknown_license_and_missing_notices_refuse(self):
        redirected = _Response(
            self.archive, url="https://untrusted.invalid/fixture.crate",
        )
        invalid_archives = (
            (redirected, self.archive),
            (_Response(self.archive), _crate_archive(cargo_toml=(
                b'[package]\nname = "fixture-crate"\nversion = "1.2.3"\n'
                b'license = "LicenseRef-Unknown"\n'
            ), files=(("README.md", b"no license text"),))),
            (_Response(self.archive), _crate_archive(cargo_toml=(
                b'[package]\nname = "fixture-crate"\nversion = "1.2.3"\nlicense-file = "LICENSE"\n'
            ))),
        )
        for response, archive in invalid_archives:
            lock = _lock(archive)
            identity = gate.Identity("a" * 40, "runtime", self.identity.root,
                                     hashlib.sha256(lock).hexdigest())
            package = gate.Package(PACKAGE_NAME, PACKAGE_VERSION, hashlib.sha256(archive).hexdigest())
            response.payload = archive
            with self.subTest(response=response.url), self.assertRaises(gate.LicenseGateRefusal):
                producer.TrustedArchivePort(_Opener(response)).verify_complete(
                    lock, identity, (package,),
                )
        missing = _crate_archive(notices=False)
        with self.assertRaises(gate.LicenseGateRefusal):
            producer.TrustedArchivePort(_Opener(_Response(missing))).verify_complete(
                _lock(missing), gate.Identity(
                    "a" * 40, "runtime", self.identity.root,
                    hashlib.sha256(_lock(missing)).hexdigest(),
                ), (gate.Package(PACKAGE_NAME, PACKAGE_VERSION, hashlib.sha256(missing).hexdigest()),),
            )

    def test_archive_member_traversal_symlink_and_non_crates_registry_refuse(self):
        for payload, source in (
            (_crate_archive(traversal=True), REGISTRY_SOURCE),
            (_crate_archive(symlink=True), REGISTRY_SOURCE),
            (self.archive, "registry+https://example.invalid/index"),
        ):
            lock = _lock(payload, source=source)
            identity = gate.Identity(
                "a" * 40, "runtime", self.identity.root, hashlib.sha256(lock).hexdigest(),
            )
            package = gate.Package(PACKAGE_NAME, PACKAGE_VERSION, hashlib.sha256(payload).hexdigest())
            with self.subTest(source=source), self.assertRaises(gate.LicenseGateRefusal):
                producer.TrustedArchivePort(_Opener(_Response(payload))).verify_complete(
                    lock, identity, (package,),
                )

    def test_unset_archive_producer_is_a_license_gate_refusal(self):
        with self.assertRaises(gate.LicenseGateRefusal) as raised:
            gate.require_rust_license_gate(self.lock, self.identity, None)
        self.assertEqual(raised.exception.reason, "archive_producer_unavailable")


if __name__ == "__main__":
    unittest.main()
