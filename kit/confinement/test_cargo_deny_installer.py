"""Source-only checks for the pinned cargo-deny installation."""

import hashlib
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import cargo_deny_installer as subject


class _Response:
    def __init__(self, url, payload):
        self.url = url
        self.payload = payload
        self.status = 200
        self.headers = {"Content-Length": str(len(payload))}
        self.closed = False

    def geturl(self):
        return self.url

    def read(self, size=-1):
        result = self.payload[:size]
        self.payload = self.payload[len(result):]
        return result

    def close(self):
        self.closed = True


class _Opener:
    def __init__(self, response):
        self.response = response
        self.url = None

    def open(self, request, timeout):
        self.url = request.full_url
        return self.response


def _archive(binary):
    buffer = io.BytesIO()
    root = "cargo-deny-0.20.2-x86_64-unknown-linux-musl"
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        directory = tarfile.TarInfo(root)
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        member = tarfile.TarInfo(root + "/cargo-deny")
        member.size = len(binary)
        member.mode = 0o755
        archive.addfile(member, io.BytesIO(binary))
    return buffer.getvalue()


class CargoDenyInstallerTests(unittest.TestCase):
    def test_release_version_hashes_and_supported_platforms_are_pinned(self):
        self.assertEqual(subject.CARGO_DENY_VERSION, "0.20.2")
        self.assertEqual(subject.target_for("linux", "x86_64")[3],
                         "9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f")
        self.assertEqual(subject.target_for("darwin", "arm64")[1], "aarch64-apple-darwin")
        self.assertEqual(subject.target_for("windows", "amd64")[1], "x86_64-pc-windows-msvc")
        with self.assertRaises(subject.CargoDenyInstallRefusal):
            subject.target_for("darwin", "x86_64")

    def test_install_checks_release_archive_and_binary_before_use(self):
        binary = b"synthetic pinned cargo-deny binary"
        payload = _archive(binary)
        digest = hashlib.sha256(payload).hexdigest()
        key = ("linux", "x86_64")
        url = subject.CARGO_DENY_RELEASE_ORIGIN + "0.20.2/" + subject.target_for(*key)[2]
        opener = _Opener(_Response(url, payload))
        output = SimpleNamespace(returncode=0, stdout=b"cargo-deny 0.20.2\n", stderr=b"")
        with patch.dict(subject.RELEASES, {key: (subject.RELEASES[key][0], digest)}):
            with tempfile.TemporaryDirectory() as temporary:
                executable, receipt = subject.install(
                    Path(temporary) / "install", opener=opener,
                    runner=lambda *a, **k: output, system="linux", machine="x86_64",
                )
                record = subject.verify_installed(
                    executable, receipt, runner=lambda *a, **k: output,
                    system="linux", machine="x86_64",
                )
                self.assertEqual(opener.url, url)
                self.assertTrue(opener.response.closed)
                self.assertEqual(record["asset_sha256"], digest)
                self.assertEqual(record["executable_sha256"], hashlib.sha256(binary).hexdigest())
                executable.chmod(0o644)
                executable.write_bytes(b"substituted")
                with self.assertRaises(subject.CargoDenyInstallRefusal):
                    subject.verify_installed(
                        executable, receipt, runner=lambda *a, **k: output,
                        system="linux", machine="x86_64",
                    )

    def test_advisory_database_identity_and_24_hour_freshness_are_enforced(self):
        now = 1_800_000_000
        commit = "a" * 40
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / subject.RUSTSEC_ADVISORY_DATABASE_ID
            database.mkdir()

            def checked(origin=subject.RUSTSEC_ADVISORY_DATABASE_URL,
                        timestamp=str(now - 60), dirty=""):
                values = iter((origin, commit, timestamp, dirty))
                with patch.object(subject, "_git", side_effect=lambda *args, **kwargs: next(values)):
                    return subject.verify_advisory_database(database, git="git", now=now)

            self.assertEqual(checked(), (commit, now - 60))
            with self.assertRaises(subject.CargoDenyInstallRefusal):
                checked(origin="https://example.invalid/advisory-db")
            with self.assertRaises(subject.CargoDenyInstallRefusal):
                checked(timestamp=str(now - subject.MAX_ADVISORY_AGE_SECONDS - 1))
            with self.assertRaises(subject.CargoDenyInstallRefusal):
                checked(timestamp=str(now + 1))
            with self.assertRaises(subject.CargoDenyInstallRefusal):
                checked(dirty=" M advisory.toml")

    def test_bad_digest_redirect_and_wrong_version_refuse(self):
        with tempfile.TemporaryDirectory() as temporary:
            url = subject.CARGO_DENY_RELEASE_ORIGIN + "0.20.2/" + subject.target_for("linux", "x86_64")[2]
            with self.assertRaises(subject.CargoDenyInstallRefusal):
                subject.install(Path(temporary) / "bad", opener=_Opener(_Response(url, b"wrong")),
                                system="linux", machine="x86_64")
            with self.assertRaises(subject.CargoDenyInstallRefusal):
                subject._download(url, _Opener(_Response("https://example.invalid/a", b"wrong")))
            asset_url = "https://release-assets.githubusercontent.com/github-production-release-asset/asset?token=synthetic"
            self.assertEqual(subject._download(url, _Opener(_Response(asset_url, b"pinned"))), b"pinned")
            handler = subject._ApprovedReleaseRedirect()
            request = subject.urllib.request.Request(url)
            self.assertIsNotNone(handler.redirect_request(
                request, None, 302, "Found", {}, asset_url,
            ))
            with self.assertRaises(subject.CargoDenyInstallRefusal):
                handler.redirect_request(
                    request, None, 302, "Found", {}, "https://example.invalid/asset",
                )
            payload = _archive(b"synthetic binary")
            digest = hashlib.sha256(payload).hexdigest()
            key = ("linux", "x86_64")
            with patch.dict(subject.RELEASES, {key: (subject.RELEASES[key][0], digest)}):
                with self.assertRaises(subject.CargoDenyInstallRefusal):
                    subject.install(
                        Path(temporary) / "wrong-version", opener=_Opener(_Response(url, payload)),
                        runner=lambda *a, **k: SimpleNamespace(
                            returncode=0, stdout=b"cargo-deny 0.19.9\n", stderr=b"",
                        ), system="linux", machine="x86_64",
                    )


if __name__ == "__main__":
    unittest.main()
