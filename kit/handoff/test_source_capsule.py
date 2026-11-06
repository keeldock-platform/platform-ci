import contextlib
import hashlib
import hmac
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import source_capsule as subject

frame = subject.frame
preflight_module = subject.source_bundle_preflight

NOW = 1800000000
P256_POINT = bytes.fromhex(
    "04"
    "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
    "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
)
SHARED_X = bytes.fromhex("0123456789abcdef" * 4)
CANARY = "kd-canary-" + "7f" * 32
SOURCE_REPOSITORY_ID = 4242
HAS_GIT = shutil.which("git") is not None

try:
    import cryptography
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


class TestOnlyProvider:
    """Deterministic stand-in with a real keystream and tag, never used outside these tests."""

    def __init__(self, fail_seal_at=None, fail_sender=False):
        self.destroyed = False
        self.fail_seal_at = fail_seal_at
        self.fail_sender = fail_sender
        self.sealed = 0

    def sender_public_point(self):
        if self.fail_sender:
            raise ValueError("sender")
        return P256_POINT

    def derive_shared_x(self, peer_public_point):
        frame.validate_public_point(peer_public_point)
        return SHARED_X

    def destroy(self):
        self.destroyed = True

    @staticmethod
    def _xor(key, nonce, data):
        stream = hashlib.shake_256(bytes(key) + nonce).digest(len(data))
        return (int.from_bytes(data, "big") ^ int.from_bytes(stream, "big")).to_bytes(len(data), "big")

    def seal(self, key, nonce, plaintext, aad):
        if self.fail_seal_at is not None and self.sealed == self.fail_seal_at:
            raise ValueError("seal")
        self.sealed += 1
        ciphertext = self._xor(key, nonce, plaintext)
        tag = hmac.new(bytes(key), nonce + aad + ciphertext, hashlib.sha256).digest()[:16]
        return ciphertext, tag

    def open(self, key, nonce, ciphertext, tag, aad):
        expected = hmac.new(bytes(key), nonce + aad + ciphertext, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(tag, expected):
            raise ValueError("tag")
        return self._xor(key, nonce, ciphertext)


def accepting_preflight(stream):
    digest = hashlib.sha256()
    while True:
        block = stream.read(1024 * 1024)
        if not block:
            break
        digest.update(block)
    return preflight_module.Accepted(1, 1, 1, digest.hexdigest())


def encoded_key_record(created=NOW - 10, expires=NOW + 3600, point=P256_POINT, transfer=bytes(range(1, 17))):
    return frame.encode_key_record(frame.KeyRecord(
        1, bytes(range(20)), 7, 1, transfer, point, bytes.fromhex("66" * 32), created, expires,
    ))


def git(repository, *arguments):
    environment = {
        "PATH": "/usr/bin:/bin", "HOME": str(repository), "LANG": "C", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_AUTHOR_NAME": "fixture", "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
        "GIT_COMMITTER_NAME": "fixture", "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
        "GIT_AUTHOR_DATE": "2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE": "2026-01-01T00:00:00Z",
    }
    result = subprocess.run(
        ["git", "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + os.devnull, "-C", str(repository)]
        + list(arguments),
        env=environment, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    return result.stdout.decode("ascii").strip()


def make_repository(root, files, executable=()):
    repository = Path(root)
    repository.mkdir(parents=True, exist_ok=True)
    git(repository, "init", "-q")
    for relative, content in files.items():
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
        if relative in executable:
            path.chmod(0o755)
    git(repository, "add", "--all")
    git(repository, "commit", "-q", "-m", "fixture")
    return repository


def make_bundle(repository, destination, *arguments):
    git(repository, "bundle", "create", "-q", str(destination), *(arguments or ("HEAD",)))
    return Path(destination)


FILES = {
    "Cargo.toml": b"[workspace]\nmembers = []\n",
    "src/lib.rs": b"pub fn answer() -> u32 { 42 }\n",
    "bin/tool.sh": b"echo tool\n",
    "docs/note.txt": (CANARY + "\n").encode("ascii"),
    "docs/empty.txt": b"",
}


@unittest.skipUnless(HAS_GIT, "git is required")
class SourceFixtureMixin:
    @classmethod
    def build_fixture(cls):
        cls.root = Path(tempfile.mkdtemp(prefix="source-capsule-"))
        cls.repository = make_repository(cls.root / "repository", FILES, executable=("bin/tool.sh",))
        cls.source_sha = git(cls.repository, "rev-parse", "HEAD")
        cls.tree_id = git(cls.repository, "rev-parse", "HEAD^{tree}")
        cls.bundle = make_bundle(cls.repository, cls.root / "source.bundle")
        cls.length, cls.digest = subject.bundle_facts(cls.bundle, cls.source_sha, preflight=accepting_preflight)
        cls.manifest = subject.build_manifest(
            cls.repository, cls.source_sha, SOURCE_REPOSITORY_ID, cls.length, cls.digest,
        )

    @classmethod
    def remove_fixture(cls):
        shutil.rmtree(cls.root, ignore_errors=True)

    def assert_refusal(self, reason, callback, *arguments, **keywords):
        with self.assertRaises(subject.SourceCapsuleRefusal) as caught:
            callback(*arguments, **keywords)
        self.assertEqual(caught.exception.reason, reason)


@unittest.skipUnless(sys.platform.startswith("linux"), "the source capsule suite runs only on Linux")
class BundleAndManifestTests(SourceFixtureMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_fixture()

    @classmethod
    def tearDownClass(cls):
        cls.remove_fixture()

    def test_the_manifest_describes_every_file_of_the_commit_tree(self):
        manifest = self.manifest
        self.assertEqual(manifest.source_repository_id, SOURCE_REPOSITORY_ID)
        self.assertEqual(manifest.source_sha.hex(), self.source_sha)
        self.assertEqual(manifest.tree_id.hex(), self.tree_id)
        self.assertEqual(manifest.bundle_length, self.bundle.stat().st_size)
        self.assertEqual(manifest.bundle_sha256, hashlib.sha256(self.bundle.read_bytes()).digest())
        self.assertEqual([entry.path for entry in manifest.entries], sorted(FILES))
        for entry in manifest.entries:
            content = FILES[entry.path]
            with self.subTest(path=entry.path):
                self.assertEqual(entry.size, len(content))
                self.assertEqual(entry.sha256, hashlib.sha256(content).digest())
                self.assertEqual(entry.blob_id.hex(), git(self.repository, "rev-parse", "HEAD:" + entry.path))
                self.assertEqual(entry.mode, 0o100755 if entry.path == "bin/tool.sh" else 0o100644)
        frame.encode_manifest(manifest)

    def test_the_real_preflight_accepts_a_git_bundle_of_one_commit(self):
        length, digest = subject.bundle_facts(self.bundle, self.source_sha)
        self.assertEqual((length, digest), (self.length, self.digest))

    def test_the_bundle_must_hold_exactly_the_source_commit(self):
        other = make_repository(self.root / "other", {"a.txt": b"other\n"})
        other_bundle = make_bundle(other, self.root / "other.bundle")
        self.assert_refusal(
            "bundle-header", subject.bundle_facts, other_bundle, self.source_sha, preflight=accepting_preflight,
        )
        self.assert_refusal("source-sha", subject.bundle_facts, self.bundle, self.source_sha.upper())
        self.assert_refusal("source-sha", subject.bundle_facts, self.bundle, self.source_sha[:-1])
        self.assert_refusal("source-sha", subject.bundle_facts, self.bundle, None)

    def test_a_bundle_with_prerequisites_or_several_references_is_refused(self):
        repository = make_repository(self.root / "history", {"a.txt": b"one\n"})
        (repository / "a.txt").write_bytes(b"two\n")
        git(repository, "commit", "-q", "-a", "-m", "second")
        head = git(repository, "rev-parse", "HEAD")
        thin = make_bundle(repository, self.root / "thin.bundle", "HEAD", "^HEAD~1")
        self.assertIn(b"\n-", thin.read_bytes()[:4096])
        self.assert_refusal("bundle-header", subject.bundle_facts, thin, head, preflight=accepting_preflight)
        git(repository, "branch", "second-reference")
        double = make_bundle(repository, self.root / "double.bundle", "HEAD", "refs/heads/second-reference")
        self.assert_refusal("bundle-header", subject.bundle_facts, double, head, preflight=accepting_preflight)

    def test_non_bundles_and_unsafe_paths_are_refused(self):
        for name, content in (("empty", b""), ("text", b"not a bundle\n"), ("short", b"x")):
            path = self.root / ("bad-" + name)
            path.write_bytes(content)
            with self.subTest(name=name):
                reason = "bundle" if name == "empty" else "bundle-header"
                self.assert_refusal(reason, subject.bundle_facts, path, self.source_sha, preflight=accepting_preflight)
        link = self.root / "bundle-link"
        link.symlink_to(self.bundle)
        self.assert_refusal("bundle", subject.bundle_facts, link, self.source_sha, preflight=accepting_preflight)
        self.assert_refusal("bundle", subject.bundle_facts, self.root, self.source_sha, preflight=accepting_preflight)
        self.assert_refusal(
            "bundle", subject.bundle_facts, self.root / "missing", self.source_sha, preflight=accepting_preflight,
        )
        truncated = self.root / "truncated.bundle"
        truncated.write_bytes(self.bundle.read_bytes()[:-64])
        self.assert_refusal("bundle-preflight", subject.bundle_facts, truncated, self.source_sha)

    def test_the_preflight_verdict_and_digest_are_both_required(self):
        def refused(stream):
            return preflight_module.Refused("object-invalid")

        def wrong_digest(stream):
            return preflight_module.Accepted(1, 1, 1, "0" * 64)

        def broken(stream):
            raise RuntimeError("preflight")

        for preflight in (refused, wrong_digest, broken, lambda stream: None, lambda stream: "accepted"):
            with self.subTest(preflight=preflight):
                self.assert_refusal(
                    "bundle-preflight", subject.bundle_facts, self.bundle, self.source_sha, preflight=preflight,
                )

    def test_an_oversized_bundle_is_refused_before_it_is_read(self):
        with patch.object(subject.frame, "MAX_BUNDLE_BODY_BYTES", 16):
            self.assert_refusal(
                "bundle", subject.bundle_facts, self.bundle, self.source_sha, preflight=accepting_preflight,
            )

    def test_manifest_inputs_are_checked(self):
        arguments = (self.repository, self.source_sha, SOURCE_REPOSITORY_ID, self.length, self.digest)
        for index, bad, reason in (
            (1, "0" * 40, "git"), (1, "A" * 40, "source-sha"), (1, 7, "source-sha"),
            (2, 0, "input"), (2, True, "input"), (2, "7", "input"), (2, 1 << 64, "input"),
            (3, 0, "bundle"), (3, True, "bundle"), (3, frame.MAX_BUNDLE_BODY_BYTES + 1, "bundle"),
            (4, b"short", "bundle"), (4, "0" * 64, "bundle"),
        ):
            changed = list(arguments)
            changed[index] = bad
            with self.subTest(index=index, bad=bad):
                self.assert_refusal(reason, subject.build_manifest, *changed)
        self.assert_refusal("git", subject.build_manifest, self.root / "missing", *arguments[1:])

    def test_only_regular_files_with_frame_safe_ascii_paths_are_accepted(self):
        cases = {
            "symlink": ("entry-type", lambda repository: (
                os.symlink("a.txt", repository / "link"), git(repository, "add", "link"))),
            "gitlink": ("entry-type", lambda repository: git(
                repository, "update-index", "--add", "--cacheinfo", "160000,"
                + git(repository, "rev-parse", "HEAD") + ",module")),
            "non-ascii": ("manifest", lambda repository: (
                (repository / "caf\u00e9.txt").write_bytes(b"x"), git(repository, "add", "--all"))),
            "reserved": ("manifest", lambda repository: (
                (repository / "aux.txt").write_bytes(b"x"), git(repository, "add", "--all"))),
            "trailing-dot": ("manifest", lambda repository: (
                (repository / "name.").write_bytes(b"x"), git(repository, "add", "--all"))),
            "colon": ("manifest", lambda repository: (
                (repository / "a:b").write_bytes(b"x"), git(repository, "add", "--all"))),
            "long": ("manifest", lambda repository: (
                (repository / ("d" * 241)).write_bytes(b"x"), git(repository, "add", "--all"))),
        }
        for name, (reason, change) in cases.items():
            repository = make_repository(self.root / ("case-" + name), {"a.txt": b"a\n"})
            change(repository)
            git(repository, "commit", "-q", "-m", name)
            head = git(repository, "rev-parse", "HEAD")
            with self.subTest(name=name):
                self.assert_refusal(reason, subject.build_manifest, repository, head, 1, 100, bytes(32))

    def test_case_insensitive_duplicates_are_refused(self):
        repository = make_repository(self.root / "alias", {"Readme.txt": b"a", "readme.txt": b"b"})
        head = git(repository, "rev-parse", "HEAD")
        self.assert_refusal("manifest", subject.build_manifest, repository, head, 1, 100, bytes(32))

    def test_an_empty_tree_is_refused(self):
        repository = make_repository(self.root / "empty-tree", {"a.txt": b"a\n"})
        git(repository, "rm", "-q", "a.txt")
        git(repository, "commit", "-q", "-m", "empty")
        head = git(repository, "rev-parse", "HEAD")
        self.assert_refusal("tree", subject.build_manifest, repository, head, 1, 100, bytes(32))

    def test_a_blob_over_the_entry_limit_is_refused(self):
        with patch.object(subject.frame, "MAX_ENTRY_BYTES", 8):
            self.assert_refusal(
                "entry-limit", subject.build_manifest, self.repository, self.source_sha, 1, self.length, self.digest,
            )

    def test_too_many_entries_are_refused(self):
        with patch.object(subject.frame, "MAX_MANIFEST_ENTRIES", 2):
            self.assert_refusal(
                "entry-limit", subject.build_manifest, self.repository, self.source_sha, 1, self.length, self.digest,
            )

    def test_git_failures_and_unexpected_output_are_refused(self):
        class Completed:
            def __init__(self, returncode=0, stdout=b"", stderr=b""):
                self.returncode, self.stdout, self.stderr = returncode, stdout, stderr

        for result in (Completed(1), Completed(0, b"x", b"warning"), Completed(0, b"x" * (subject.GIT_OUTPUT_BYTES + 1))):
            with self.subTest(result=result.returncode, stderr=result.stderr):
                with patch.object(subject.subprocess, "run", return_value=result):
                    self.assert_refusal("git", subject.build_manifest, self.repository, self.source_sha, 1, 100, bytes(32))
        with patch.object(subject.subprocess, "run", side_effect=OSError("missing")):
            self.assert_refusal("git", subject.build_manifest, self.repository, self.source_sha, 1, 100, bytes(32))
        with patch.object(subject.subprocess, "run", return_value=Completed(0, b"b" * 40 + b"\n")):
            self.assert_refusal("source-sha", subject.build_manifest, self.repository, self.source_sha, 1, 100, bytes(32))


@unittest.skipUnless(sys.platform.startswith("linux"), "the source capsule suite runs only on Linux")
class SealedCapsuleTests(SourceFixtureMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_fixture()
        cls.key_record = encoded_key_record()
        cls.provider = TestOnlyProvider()
        cls.capsule = cls.root / "capsule.bin"
        cls.summary = subject.seal_capsule(
            cls.capsule, cls.key_record, cls.manifest, cls.bundle, cls.provider, cls.provider,
            clock=lambda: NOW,
        )

    @classmethod
    def tearDownClass(cls):
        cls.remove_fixture()

    def derive(self, path=None):
        with open(path or self.capsule, "rb") as stream:
            header_bytes = stream.read(frame.CAPSULE_HEADER_LENGTH)
        header = frame.decode_capsule_header(header_bytes)
        return frame.derive_aes_key(SHARED_X, header.hkdf_salt, frame.header_digest(header_bytes)), header

    def destination(self):
        return self.root / ("out-" + os.urandom(6).hex())

    @contextlib.contextmanager
    def altered(self, offset, value=None):
        with open(self.capsule, "r+b") as stream:
            stream.seek(offset)
            original = stream.read(1)
            stream.seek(offset)
            stream.write(bytes((original[0] ^ 1 if value is None else value,)))
        try:
            yield
        finally:
            with open(self.capsule, "r+b") as stream:
                stream.seek(offset)
                stream.write(original)

    def test_the_summary_binds_the_capsule_to_the_source_and_the_receiver_key(self):
        record = frame.decode_key_record(self.key_record)
        data = self.capsule.read_bytes()
        self.assertEqual(self.summary, {
            "capsule_sha256": hashlib.sha256(data).hexdigest(),
            "length": frame.CAPSULE_LENGTH,
            "key_id": record.key_id.hex(),
            "transfer_id": record.transfer_id.hex(),
            "source_sha": self.source_sha,
            "tree_id": self.tree_id,
            "bundle_sha256": self.digest.hex(),
            "bundle_length": self.length,
            "entries": len(FILES),
        })
        self.assertEqual(len(data), frame.CAPSULE_LENGTH)
        self.assertEqual(self.capsule.stat().st_mode & 0o777, 0o600)
        header = frame.decode_capsule_header(data[:frame.CAPSULE_HEADER_LENGTH])
        self.assertTrue(frame.validate_header_key_binding(header, self.key_record))
        self.assertEqual(header.sender_public_point, P256_POINT)
        self.assertEqual(header.intended_job_sha256, frame.RECEIVER_JOB_SHA256)
        self.assertTrue(self.provider.destroyed)

    def test_no_source_content_or_path_is_readable_in_the_capsule(self):
        needles = (CANARY.encode("ascii"), b"src/lib.rs", b"pub fn answer", b"[workspace]")
        overlap = max(len(needle) for needle in needles) - 1
        tail = b""
        with open(self.capsule, "rb") as stream:
            while True:
                block = stream.read(16 * 1024 * 1024)
                if not block:
                    break
                window = tail + block
                for needle in needles:
                    self.assertNotIn(needle, window)
                tail = window[-overlap:]

    def test_the_capsule_opens_to_the_same_bundle_and_manifest(self):
        key, header = self.derive()
        destination = self.destination()
        manifest = subject.open_capsule(self.capsule, self.key_record, key, self.provider, destination)
        self.assertEqual(manifest, self.manifest)
        self.assertEqual(destination.read_bytes(), self.bundle.read_bytes())
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)
        self.assertEqual(header.transfer_id, frame.decode_key_record(self.key_record).transfer_id)
        self.assert_refusal("output", subject.open_capsule, self.capsule, self.key_record, key, self.provider, destination)

    def test_a_changed_header_manifest_chunk_bundle_chunk_or_trailer_is_refused(self):
        key, unused = self.derive()
        for name, offset, value, reason in (
            ("header-binding", frame.HEADER_CONTROL_SHA_START, None, "capsule"),
            ("header-key-record-digest", frame.HEADER_KEY_RECORD_SHA256_START, None, "capsule"),
            ("manifest-ciphertext", frame.MANIFEST_REGION_START + 100, None, "capsule"),
            ("manifest-tag", frame.chunk_offset(3) + frame.CHUNK_PLAINTEXT_BYTES, None, "capsule"),
            ("bundle-ciphertext", frame.chunk_offset(100) + 5, None, "capsule"),
            ("first-bundle-chunk", frame.chunk_offset(frame.FIRST_BUNDLE_INDEX) + 1, None, "capsule"),
            ("trailer", frame.TRAILER_START + 5, 1, "padding"),
        ):
            destination = self.destination()
            with self.subTest(name=name), self.altered(offset, value):
                self.assert_refusal(reason, subject.open_capsule, self.capsule, self.key_record, key,
                                    self.provider, destination)
                self.assertFalse(destination.exists())
        destination = self.destination()
        self.assertEqual(
            subject.open_capsule(self.capsule, self.key_record, key, self.provider, destination), self.manifest,
        )

    def test_a_wrong_key_wrong_key_record_or_short_capsule_is_refused(self):
        key, unused = self.derive()
        destination = self.destination()
        self.assert_refusal("capsule", subject.open_capsule, self.capsule, self.key_record, bytes(32),
                            self.provider, destination)
        self.assertFalse(destination.exists())
        other = encoded_key_record(transfer=bytes(range(2, 18)))
        self.assert_refusal("capsule", subject.open_capsule, self.capsule, other, key, self.provider, destination)
        self.assert_refusal("capsule", subject.open_capsule, self.capsule, b"short", key, self.provider, destination)
        short = self.root / "short.bin"
        short.write_bytes(self.capsule.read_bytes()[:frame.CAPSULE_HEADER_LENGTH + 5])
        self.assert_refusal("capsule", subject.open_capsule, short, self.key_record, key, self.provider, destination)
        link = self.root / "capsule-link"
        link.symlink_to(self.capsule)
        self.assert_refusal("capsule", subject.open_capsule, link, self.key_record, key, self.provider, destination)


@unittest.skipUnless(HAS_GIT, "git is required")
@unittest.skipUnless(sys.platform.startswith("linux"), "the source capsule suite runs only on Linux")
class SealRefusalTests(SourceFixtureMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_fixture()
        cls.key_record = encoded_key_record()

    @classmethod
    def tearDownClass(cls):
        cls.remove_fixture()

    def seal(self, name="capsule.bin", key_record=None, manifest=None, bundle=None, provider=None,
             aead=None, **keywords):
        provider = TestOnlyProvider() if provider is None else provider
        keywords.setdefault("clock", lambda: NOW)
        return provider, subject.seal_capsule(
            self.root / name, self.key_record if key_record is None else key_record,
            self.manifest if manifest is None else manifest, self.bundle if bundle is None else bundle,
            provider, provider if aead is None else aead, **keywords,
        )

    def test_the_key_record_must_be_well_formed_current_and_short_lived(self):
        cases = {
            "zeros": bytes(frame.KEY_RECORD_LENGTH),
            "short": self.key_record[:-1],
            "long": self.key_record + b"x",
            "expired": encoded_key_record(created=NOW - 100, expires=NOW - 1),
            "not-yet-valid": encoded_key_record(created=NOW + 1000, expires=NOW + 2000),
            "too-long": encoded_key_record(created=NOW - 10, expires=NOW - 10 + 24 * 60 * 60 + 1),
            "text": "key",
        }
        for name, record in cases.items():
            provider = TestOnlyProvider()
            with self.subTest(name=name):
                with self.assertRaises(subject.SourceCapsuleRefusal) as caught:
                    self.seal("refused-" + name, key_record=record, provider=provider)
                self.assertEqual(caught.exception.reason, "key-record")
                self.assertTrue(provider.destroyed)
                self.assertFalse((self.root / ("refused-" + name)).exists())

    def test_a_boundary_key_record_lifetime_and_slack_are_accepted_by_the_check(self):
        for record in (
            encoded_key_record(created=NOW - 10, expires=NOW - 10 + 24 * 60 * 60),
            encoded_key_record(created=NOW + 300, expires=NOW + 3600),
        ):
            decoded = subject._check_key_record(record, NOW)
            self.assertEqual(decoded.run_id, 7)

    def test_a_non_manifest_or_unusable_provider_is_refused_and_destroyed(self):
        provider = TestOnlyProvider()
        with self.assertRaises(subject.SourceCapsuleRefusal) as caught:
            self.seal("not-a-manifest", manifest="manifest", provider=provider)
        self.assertEqual(caught.exception.reason, "manifest")
        self.assertTrue(provider.destroyed)
        provider = TestOnlyProvider(fail_sender=True)
        with self.assertRaises(subject.SourceCapsuleRefusal) as caught:
            self.seal("sender-fails", provider=provider)
        self.assertEqual(caught.exception.reason, "provider")
        self.assertTrue(provider.destroyed)

    def test_entropy_must_return_exact_bytes(self):
        for entropy in (lambda size: bytes(size - 1), lambda size: "x" * size, lambda size: None,
                        lambda size: (_ for _ in ()).throw(OSError("entropy"))):
            with self.subTest(entropy=entropy):
                provider = TestOnlyProvider()
                with self.assertRaises(subject.SourceCapsuleRefusal) as caught:
                    self.seal("entropy", provider=provider, entropy=entropy)
                self.assertEqual(caught.exception.reason, "provider")
                self.assertTrue(provider.destroyed)

    def test_an_existing_output_is_never_replaced(self):
        existing = self.root / "existing.bin"
        existing.write_bytes(b"keep")
        provider = TestOnlyProvider()
        with self.assertRaises(subject.SourceCapsuleRefusal) as caught:
            self.seal("existing.bin", provider=provider)
        self.assertEqual(caught.exception.reason, "output")
        self.assertEqual(existing.read_bytes(), b"keep")
        link = self.root / "output-link"
        link.symlink_to(existing)
        with self.assertRaises(subject.SourceCapsuleRefusal) as caught:
            self.seal("output-link")
        self.assertEqual(caught.exception.reason, "output")
        with self.assertRaises(subject.SourceCapsuleRefusal) as caught:
            self.seal("missing-directory/capsule.bin")
        self.assertEqual(caught.exception.reason, "output")

    def test_a_bundle_that_differs_from_the_manifest_leaves_no_capsule(self):
        changed = self.root / "changed.bundle"
        content = bytearray(self.bundle.read_bytes())
        content[-1] ^= 1
        changed.write_bytes(bytes(content))
        with self.assertRaises(subject.SourceCapsuleRefusal) as caught:
            self.seal("changed-content.bin", bundle=changed)
        self.assertEqual(caught.exception.reason, "mismatch")
        self.assertFalse((self.root / "changed-content.bin").exists())
        shorter = self.root / "shorter.bundle"
        shorter.write_bytes(bytes(content[:-1]))
        with self.assertRaises(subject.SourceCapsuleRefusal) as caught:
            self.seal("shorter.bin", bundle=shorter)
        self.assertEqual(caught.exception.reason, "mismatch")
        self.assertFalse((self.root / "shorter.bin").exists())
        link = self.root / "bundle-link"
        link.symlink_to(self.bundle)
        with self.assertRaises(subject.SourceCapsuleRefusal) as caught:
            self.seal("linked.bin", bundle=link)
        self.assertEqual(caught.exception.reason, "bundle")
        self.assertFalse((self.root / "linked.bin").exists())

    def test_a_sealing_failure_removes_the_partial_capsule(self):
        provider = TestOnlyProvider(fail_seal_at=3)
        with self.assertRaises(subject.SourceCapsuleRefusal) as caught:
            self.seal("partial.bin", provider=provider)
        self.assertEqual(caught.exception.reason, "capsule")
        self.assertFalse((self.root / "partial.bin").exists())

    def test_a_manifest_over_the_frame_limits_is_refused(self):
        entries = tuple(self.manifest.entries) + (self.manifest.entries[0],)
        duplicate = frame.Manifest(
            self.manifest.source_repository_id, self.manifest.source_sha, self.manifest.tree_id,
            self.manifest.bundle_sha256, self.manifest.bundle_length, entries,
        )
        with self.assertRaises(subject.SourceCapsuleRefusal) as caught:
            self.seal("duplicate.bin", manifest=duplicate)
        self.assertEqual(caught.exception.reason, "capsule")
        self.assertFalse((self.root / "duplicate.bin").exists())


@unittest.skipUnless(sys.platform.startswith("linux"), "the source capsule suite runs only on Linux")
class CommandLineTests(unittest.TestCase):
    def run_main(self, arguments):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = subject.main(arguments)
        return code, output.getvalue()

    def options(self, **changes):
        values = {
            "--repository": "/nonexistent/repository", "--source-sha": "a" * 40,
            "--source-repository-id": "4242", "--bundle": "/nonexistent/bundle",
            "--key-record": "/nonexistent/key", "--output": "/nonexistent/capsule",
            "--summary": "/nonexistent/summary",
        }
        values.update(changes)
        arguments = ["seal"]
        for name, value in values.items():
            arguments.extend((name, value))
        return arguments

    def test_malformed_command_lines_are_usage_errors(self):
        for arguments in (
            [], ["unseal"], ["seal", "--bogus", "x"], ["seal", "--source-sha"],
            ["seal", "--source-sha", "a" * 40, "--source-sha", "a" * 40],
            self.options() + ["--extra", "x"],
        ):
            with self.subTest(arguments=arguments):
                self.assertEqual(self.run_main(arguments), (2, ""))

    def test_refusals_print_one_closed_line_that_never_echoes_input(self):
        secret = "do-not-echo-this-value"
        cases = (
            (["seal"], "input"),
            (self.options(**{"--source-sha": secret}), "source-sha"),
            (self.options(**{"--source-repository-id": "0"}), "input"),
            (self.options(**{"--source-repository-id": secret}), "input"),
            (self.options(**{"--key-record": "/nonexistent/" + secret}), "key-record"),
        )
        for arguments, reason in cases:
            with self.subTest(reason=reason):
                code, text = self.run_main(arguments)
                self.assertEqual((code, text), (1, "source-capsule=refused reason=" + reason + "\n"))
                self.assertNotIn(secret, text)
        with patch.object(subject, "seal_from_arguments", side_effect=RuntimeError(secret)):
            self.assertEqual(
                self.run_main(self.options()), (1, "source-capsule=refused reason=internal\n"),
            )

    def test_a_sealed_capsule_prints_only_its_digest_and_identity(self):
        summary = {
            "capsule_sha256": "1" * 64, "length": frame.CAPSULE_LENGTH, "source_sha": "a" * 40,
            "tree_id": "b" * 40, "entries": 5,
        }
        with patch.object(subject, "seal_from_arguments", return_value=summary):
            code, text = self.run_main(self.options())
        self.assertEqual(code, 0)
        self.assertEqual(
            text,
            "source-capsule=sealed capsule-sha256=" + "1" * 64 + " length=" + str(frame.CAPSULE_LENGTH)
            + " source-sha=" + "a" * 40 + " tree=" + "b" * 40 + " entries=5\n",
        )


@unittest.skipUnless(HAS_GIT, "git is required")
@unittest.skipUnless(sys.platform.startswith("linux"), "the source capsule suite runs only on Linux")
class RealProviderTests(SourceFixtureMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not HAS_CRYPTOGRAPHY:
            if sys.platform.startswith("linux") and os.environ.get("GITHUB_ACTIONS") == "true":
                raise AssertionError("the pinned cryptography package is missing on Linux CI")
            raise unittest.SkipTest("the cryptography package is required")
        cls.build_fixture()

    @classmethod
    def tearDownClass(cls):
        cls.remove_fixture()

    def test_ecdh_agreement_and_aead_round_trip(self):
        sender = subject.CryptographyProvider()
        receiver = subject.CryptographyProvider()
        sender_point = sender.sender_public_point()
        receiver_point = receiver.sender_public_point()
        self.assertEqual((len(sender_point), sender_point[0]), (65, 4))
        self.assertEqual(frame.validate_public_point(receiver_point), receiver_point)
        shared = sender.derive_shared_x(receiver_point)
        self.assertEqual(shared, receiver.derive_shared_x(sender_point))
        self.assertEqual(len(shared), 32)
        key = bytearray(range(32))
        nonce = bytes(range(12))
        aad = b"context"
        ciphertext, tag = sender.seal(key, nonce, b"plaintext", aad)
        self.assertEqual((len(ciphertext), len(tag)), (9, 16))
        self.assertEqual(receiver.open(bytes(key), nonce, ciphertext, tag, aad), b"plaintext")
        for altered in ((ciphertext[:-1] + b"x", tag, aad), (ciphertext, tag[:-1] + b"x", aad),
                        (ciphertext, tag, b"other")):
            with self.assertRaises(Exception):
                receiver.open(bytes(key), nonce, *altered)
        sender.destroy()
        with self.assertRaises(subject.SourceCapsuleRefusal):
            sender.derive_shared_x(receiver_point)
        with self.assertRaises(subject.SourceCapsuleRefusal):
            sender.sender_public_point()

    def test_the_command_line_seals_a_capsule_that_the_receiver_key_opens(self):
        receiver = subject.CryptographyProvider()
        now = int(time.time())
        key_record = encoded_key_record(created=now - 10, expires=now + 3600, point=receiver.sender_public_point())
        key_path = self.root / "receiver.key"
        key_path.write_bytes(key_record)
        capsule = self.root / "real.capsule"
        summary_path = self.root / "real.summary"
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = subject.main([
                "seal", "--repository", str(self.repository), "--source-sha", self.source_sha,
                "--source-repository-id", str(SOURCE_REPOSITORY_ID), "--bundle", str(self.bundle),
                "--key-record", str(key_path), "--output", str(capsule), "--summary", str(summary_path),
            ])
        self.assertEqual(code, 0, output.getvalue())
        summary = json.loads(summary_path.read_text(encoding="ascii"))
        self.assertEqual(summary["capsule_sha256"], hashlib.sha256(capsule.read_bytes()).hexdigest())
        self.assertEqual(
            output.getvalue(),
            "source-capsule=sealed capsule-sha256=" + summary["capsule_sha256"] + " length=" + str(frame.CAPSULE_LENGTH)
            + " source-sha=" + self.source_sha + " tree=" + self.tree_id + " entries=" + str(len(FILES)) + "\n",
        )
        header_bytes = capsule.read_bytes()[:frame.CAPSULE_HEADER_LENGTH]
        header = frame.decode_capsule_header(header_bytes)
        shared = receiver.derive_shared_x(header.sender_public_point)
        key = frame.derive_aes_key(shared, header.hkdf_salt, frame.header_digest(header_bytes))
        destination = self.root / "real.bundle"
        manifest = subject.open_capsule(capsule, key_record, key, subject.CryptographyProvider(), destination)
        self.assertEqual(manifest.tree_id.hex(), self.tree_id)
        self.assertEqual(destination.read_bytes(), self.bundle.read_bytes())

    def test_the_command_line_removes_the_capsule_when_the_summary_cannot_be_written(self):
        receiver = subject.CryptographyProvider()
        now = int(time.time())
        key_path = self.root / "second.key"
        key_path.write_bytes(encoded_key_record(created=now - 10, expires=now + 3600, point=receiver.sender_public_point()))
        capsule = self.root / "orphan.capsule"
        existing = self.root / "existing.summary"
        existing.write_bytes(b"keep")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = subject.main([
                "seal", "--repository", str(self.repository), "--source-sha", self.source_sha,
                "--source-repository-id", str(SOURCE_REPOSITORY_ID), "--bundle", str(self.bundle),
                "--key-record", str(key_path), "--output", str(capsule), "--summary", str(existing),
            ])
        self.assertEqual((code, output.getvalue()), (1, "source-capsule=refused reason=output\n"))
        self.assertFalse(capsule.exists())
        self.assertEqual(existing.read_bytes(), b"keep")


if __name__ == "__main__":
    unittest.main(verbosity=2)
