"""Seal one reviewed source tree into a receiver-bound capsule, and open it again for verification.

Input: a prerequisite-free git bundle with exactly one ref equal to the source commit and its full history, the repository that holds that commit,
and the receiver key record. Output: one fixed-length capsule file as defined by capsule_frame.
The manifest lists every file of the commit tree with its mode, blob id, size and SHA-256, so the
receiver can check the unpacked tree against what the Linux leg verified. Only regular files are
accepted: a symbolic link, a submodule entry or a path the frame refuses fails the whole capsule.

Every refusal uses a closed reason and never reflects an input value. A capsule file is created
exclusively with owner-only access, and any failure after creation removes it.
"""

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path

CONFINEMENT_DIRECTORY = str(Path(__file__).resolve().parents[1] / "confinement")
if CONFINEMENT_DIRECTORY not in sys.path:
    sys.path.append(CONFINEMENT_DIRECTORY)

import capsule_frame as frame
import source_bundle_preflight


REASONS = frozenset((
    "input", "source-sha", "git", "tree", "entry-type", "entry-limit", "manifest", "bundle",
    "bundle-header", "bundle-preflight", "key-record", "provider", "output", "capsule", "mismatch",
    "padding", "internal",
))
SOURCE_SHA_RE = re.compile(r"[a-f0-9]{40}\Z")
REGULAR_MODES = {b"100644": 0o100644, b"100755": 0o100755}
BUNDLE_SIGNATURES = (bytes((35,)) + b" v2 git bundle\n", bytes((35,)) + b" v3 git bundle\n")
BUNDLE_LINE_BYTES = 4096
BUNDLE_HEADER_BYTES = 1024 * 1024
BLOCK_BYTES = 1024 * 1024
KEY_TIME_SLACK_SECONDS = 300
KEY_MAX_LIFETIME_SECONDS = 24 * 60 * 60
GIT_TIMEOUT_SECONDS = 600
GIT_OUTPUT_BYTES = 64 * 1024 * 1024
LISTING_FIELDS = 3
CLI_OPTIONS = frozenset((
    "--repository", "--source-sha", "--source-repository-id", "--bundle", "--key-record",
    "--output", "--summary",
))
READ_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
CREATE_FLAGS = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
)


class SourceCapsuleRefusal(ValueError):
    def __init__(self, reason):
        self.reason = reason if type(reason) is str and reason in REASONS else "internal"
        super().__init__(self.reason)


def _refuse(reason):
    raise SourceCapsuleRefusal(reason)


def _git_environment(repository):
    return {
        "PATH": "/usr/bin:/bin", "HOME": str(Path(repository).parent), "LANG": "C", "LC_ALL": "C",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_ATTR_NOSYSTEM": "1",
    }


def _git_command(repository, arguments):
    return ("git", "-c", "safe.directory=" + str(repository), "-C", str(repository)) + tuple(arguments)


def _git(repository, arguments):
    try:
        result = subprocess.run(
            _git_command(repository, arguments), env=_git_environment(repository), stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=GIT_TIMEOUT_SECONDS, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        _refuse("git")
    if result.returncode != 0 or result.stderr or len(result.stdout) > GIT_OUTPUT_BYTES:
        _refuse("git")
    return result.stdout


def _object_id(output, reason):
    text = output.strip()
    if SOURCE_SHA_RE.fullmatch(text.decode("ascii", "replace")) is None:
        _refuse(reason)
    return text.decode("ascii")


def _check_source_sha(value):
    if type(value) is not str or SOURCE_SHA_RE.fullmatch(value) is None:
        _refuse("source-sha")
    return value


def _check_repository_id(value):
    if type(value) is not int or not 1 <= value <= 0xFFFFFFFFFFFFFFFF:
        _refuse("input")
    return value


def _tree_listing(repository, source_sha):
    if _object_id(_git(repository, ("rev-parse", "--verify", source_sha + "^{commit}")), "source-sha") != source_sha:
        _refuse("source-sha")
    tree_id = _object_id(_git(repository, ("rev-parse", "--verify", source_sha + "^{tree}")), "tree")
    listing = _git(repository, ("ls-tree", "-r", "-z", "--full-tree", source_sha))
    if not listing:
        _refuse("tree")
    records = listing.split(b"\x00")
    if records.pop() != b"":
        _refuse("tree")
    if len(records) > frame.MAX_MANIFEST_ENTRIES:
        _refuse("entry-limit")
    entries = []
    for record in records:
        head, separator, raw_path = record.partition(b"\t")
        fields = head.split(b" ")
        if not separator or len(fields) != LISTING_FIELDS:
            _refuse("tree")
        mode, kind, object_id = fields
        if kind != b"blob" or mode not in REGULAR_MODES:
            _refuse("entry-type")
        try:
            path = raw_path.decode("ascii", "strict")
            blob_id = _object_id(object_id, "tree")
        except UnicodeError:
            _refuse("manifest")
        entries.append((path, REGULAR_MODES[mode], blob_id))
    entries.sort(key=lambda entry: entry[0].encode("ascii"))
    return tree_id, entries


def _blob_digests(repository, blob_ids):
    command = _git_command(repository, ("cat-file", "--batch"))
    results = {}
    try:
        process = subprocess.Popen(
            command, env=_git_environment(repository), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        _refuse("git")
    deadline = time.monotonic() + GIT_TIMEOUT_SECONDS
    try:
        for blob_id in blob_ids:
            if blob_id in results:
                continue
            if time.monotonic() > deadline:
                _refuse("git")
            process.stdin.write(blob_id.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline(128)
            parts = header.split(b" ")
            if (len(parts) != 3 or parts[0] != blob_id.encode("ascii") or parts[1] != b"blob"
                    or not parts[2].endswith(b"\n") or not parts[2][:-1].isdigit()):
                _refuse("git")
            size = int(parts[2][:-1])
            if size > frame.MAX_ENTRY_BYTES:
                _refuse("entry-limit")
            digest = hashlib.sha256()
            remaining = size
            while remaining:
                block = process.stdout.read(min(remaining, BLOCK_BYTES))
                if not block:
                    _refuse("git")
                digest.update(block)
                remaining -= len(block)
            if process.stdout.read(1) != b"\n":
                _refuse("git")
            results[blob_id] = (size, digest.digest())
    except SourceCapsuleRefusal:
        raise
    except (OSError, ValueError):
        _refuse("git")
    finally:
        try:
            process.stdin.close()
        except OSError:
            pass
        try:
            process.stdout.close()
        except OSError:
            pass
        try:
            process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    return results


def _open_regular(path, reason):
    try:
        before = os.lstat(path)
        if not stat.S_ISREG(before.st_mode):
            _refuse(reason)
        descriptor = os.open(path, READ_FLAGS)
    except OSError:
        _refuse(reason)
    try:
        info = os.fstat(descriptor)
        if (not stat.S_ISREG(info.st_mode) or info.st_dev != before.st_dev or info.st_ino != before.st_ino
                or info.st_size != before.st_size):
            _refuse(reason)
        return descriptor, info.st_size
    except BaseException:
        os.close(descriptor)
        raise


def _bundle_header_check(stream, source_sha):
    if stream.readline(BUNDLE_LINE_BYTES + 1) not in BUNDLE_SIGNATURES:
        _refuse("bundle-header")
    read = 0
    references = []
    while True:
        line = stream.readline(BUNDLE_LINE_BYTES + 1)
        read += len(line)
        if not line.endswith(b"\n") or len(line) > BUNDLE_LINE_BYTES or read > BUNDLE_HEADER_BYTES:
            _refuse("bundle-header")
        if line == b"\n":
            break
        if line.startswith(b"@"):
            if line != b"@object-format=sha1\n":
                _refuse("bundle-header")
            continue
        if line.startswith(b"-"):
            _refuse("bundle-header")
        object_id, separator, name = line[:-1].partition(b" ")
        if not separator or not name:
            _refuse("bundle-header")
        references.append(object_id)
    if references != [source_sha.encode("ascii")]:
        _refuse("bundle-header")


def bundle_facts(bundle_path, source_sha, preflight=source_bundle_preflight.preflight):
    """Return (length, sha256 bytes) of a bundle holding exactly source_sha with no prerequisites."""
    _check_source_sha(source_sha)
    descriptor, size = _open_regular(bundle_path, "bundle")
    with os.fdopen(descriptor, "rb") as stream:
        if not 0 < size <= frame.MAX_BUNDLE_BODY_BYTES:
            _refuse("bundle")
        _bundle_header_check(stream, source_sha)
        stream.seek(0)
        digest = hashlib.sha256()
        count = 0
        while True:
            block = stream.read(BLOCK_BYTES)
            if not block:
                break
            count += len(block)
            digest.update(block)
        if count != size:
            _refuse("bundle")
        stream.seek(0)
        try:
            result = preflight(stream)
        except Exception:
            _refuse("bundle-preflight")
    if getattr(result, "accepted", False) is not True or getattr(result, "bundle_sha256", None) != digest.hexdigest():
        _refuse("bundle-preflight")
    return size, digest.digest()


def build_manifest(repository, source_sha, source_repository_id, bundle_length, bundle_sha256):
    """Return the capsule manifest for the tree of source_sha, hashing every blob once."""
    _check_source_sha(source_sha)
    _check_repository_id(source_repository_id)
    if (type(bundle_length) is not int or not 0 < bundle_length <= frame.MAX_BUNDLE_BODY_BYTES
            or type(bundle_sha256) is not bytes or len(bundle_sha256) != 32):
        _refuse("bundle")
    tree_id, listing = _tree_listing(repository, source_sha)
    digests = _blob_digests(repository, [blob_id for unused_path, unused_mode, blob_id in listing])
    entries = tuple(
        frame.ManifestEntry(path, mode, bytes.fromhex(blob_id), digests[blob_id][0], digests[blob_id][1])
        for path, mode, blob_id in listing
    )
    manifest = frame.Manifest(
        source_repository_id, bytes.fromhex(source_sha), bytes.fromhex(tree_id), bundle_sha256,
        bundle_length, entries,
    )
    try:
        frame.encode_manifest(manifest)
    except frame.CapsuleRefusal:
        _refuse("manifest")
    return manifest


def _check_key_record(key_record_bytes, now):
    try:
        record = frame.decode_key_record(key_record_bytes)
    except frame.CapsuleRefusal:
        _refuse("key-record")
    if (record.created_at < 1 or record.created_at > now + KEY_TIME_SLACK_SECONDS
            or record.expires_at <= now
            or record.expires_at - record.created_at > KEY_MAX_LIFETIME_SECONDS):
        _refuse("key-record")
    return record


def _entropy(source, length):
    try:
        value = source(length)
    except Exception:
        _refuse("provider")
    if type(value) is not bytes or len(value) != length:
        _refuse("provider")
    return value


def _manifest_region(manifest):
    body = frame.encode_manifest(manifest)
    padding = bytes(frame.MANIFEST_PLAINTEXT_LENGTH - 8 - len(body))
    return frame.encode_manifest_region(manifest, padding)


def _bundle_blocks(bundle_path, bundle_length, bundle_sha256):
    descriptor, size = _open_regular(bundle_path, "bundle")
    digest = hashlib.sha256()
    pending = bundle_length.to_bytes(8, "big")
    emitted = 0
    remaining_file = bundle_length
    total = frame.BUNDLE_PLAINTEXT_LENGTH
    with os.fdopen(descriptor, "rb") as stream:
        if size != bundle_length:
            _refuse("mismatch")
        while emitted < total:
            wanted = frame.CHUNK_PLAINTEXT_BYTES
            block = bytearray(pending)
            pending = b""
            while len(block) < wanted and remaining_file:
                data = stream.read(min(wanted - len(block), remaining_file))
                if not data:
                    _refuse("mismatch")
                digest.update(data)
                remaining_file -= len(data)
                block.extend(data)
            if len(block) < wanted:
                block.extend(bytes(wanted - len(block)))
            emitted += wanted
            yield bytes(block)
        if remaining_file or stream.read(1):
            _refuse("mismatch")
    if digest.digest() != bundle_sha256:
        _refuse("mismatch")


def _destroy_quietly(provider):
    try:
        provider.destroy()
    except BaseException:
        pass


def _prepare(key_record_bytes, manifest, ecdh_provider, entropy, now):
    try:
        record = _check_key_record(key_record_bytes, now)
        if type(manifest) is not frame.Manifest:
            _refuse("manifest")
        region = _manifest_region(manifest)
        sender_point = ecdh_provider.sender_public_point()
        header = frame.CapsuleHeader(
            record.control_repository_id, record.control_sha, record.run_id, record.attempt,
            record.transfer_id, record.key_id, hashlib.sha256(key_record_bytes).digest(), sender_point,
            _entropy(entropy, 32), _entropy(entropy, 4), record.created_at, record.expires_at,
            record.workflow_ref_sha256, frame.RECEIVER_JOB_SHA256,
        )
        header_bytes = frame.encode_capsule_header(header)
        frame.validate_header_key_binding(header, key_record_bytes)
        key = frame.derive_ephemeral_capsule_key(ecdh_provider, record.receiver_public_point, header_bytes)
    except SourceCapsuleRefusal:
        _destroy_quietly(ecdh_provider)
        raise
    except frame.CapsuleRefusal:
        _destroy_quietly(ecdh_provider)
        _refuse("capsule")
    except Exception:
        _destroy_quietly(ecdh_provider)
        _refuse("provider")
    return record, region, header, header_bytes, key


def seal_capsule(output, key_record_bytes, manifest, bundle_path, ecdh_provider, aead_provider,
                 entropy=os.urandom, clock=time.time):
    """Write the capsule to output and return its summary; remove the file on any failure."""
    record, region, header, header_bytes, key = _prepare(
        key_record_bytes, manifest, ecdh_provider, entropy, int(clock()),
    )
    try:
        descriptor = os.open(output, CREATE_FLAGS, 0o600)
    except OSError:
        key.destroy()
        _refuse("output")
    created = True
    try:
        with os.fdopen(descriptor, "wb") as sink:
            with frame.EncryptionSession(aead_provider, key, header) as session:
                digest = hashlib.sha256()

                def put(data):
                    digest.update(data)
                    sink.write(data)

                put(header_bytes)
                for index in range(frame.MANIFEST_CHUNK_COUNT):
                    start = index * frame.CHUNK_PLAINTEXT_BYTES
                    chunk = session.seal_chunk(index, region[start:start + frame.CHUNK_PLAINTEXT_BYTES])
                    put(frame.encode_chunk(chunk.index, chunk.ciphertext, chunk.tag, chunk.kind))
                blocks = _bundle_blocks(bundle_path, manifest.bundle_length, manifest.bundle_sha256)
                for index, plaintext in zip(range(frame.FIRST_BUNDLE_INDEX, frame.CHUNK_COUNT), blocks):
                    chunk = session.seal_chunk(index, plaintext)
                    put(frame.encode_chunk(chunk.index, chunk.ciphertext, chunk.tag, chunk.kind))
                if next(blocks, None) is not None:
                    _refuse("mismatch")
                put(frame.encode_trailer(bytes(frame.TRAILER_LENGTH)))
            sink.flush()
            os.fsync(sink.fileno())
        if os.lstat(output).st_size != frame.CAPSULE_LENGTH:
            _refuse("capsule")
        created = False
    except SourceCapsuleRefusal:
        raise
    except frame.CapsuleRefusal:
        _refuse("capsule")
    except OSError:
        _refuse("output")
    except Exception:
        _refuse("provider")
    finally:
        if created:
            try:
                os.unlink(output)
            except OSError:
                pass
    return {
        "capsule_sha256": digest.hexdigest(),
        "length": frame.CAPSULE_LENGTH,
        "key_id": record.key_id.hex(),
        "transfer_id": record.transfer_id.hex(),
        "source_sha": manifest.source_sha.hex(),
        "tree_id": manifest.tree_id.hex(),
        "bundle_sha256": manifest.bundle_sha256.hex(),
        "bundle_length": manifest.bundle_length,
        "entries": len(manifest.entries),
    }


def _read_exact(descriptor, offset, length):
    os.lseek(descriptor, offset, os.SEEK_SET)
    chunks = []
    remaining = length
    while remaining:
        block = os.read(descriptor, min(remaining, BLOCK_BYTES))
        if not block:
            _refuse("capsule")
        chunks.append(block)
        remaining -= len(block)
    return b"".join(chunks)


def _open_bundle_region(descriptor, header, aes_key, aead_provider, manifest, manifest_region, sink):
    digest = hashlib.sha256()
    expected = manifest.bundle_length
    written = 0
    for index in range(frame.FIRST_BUNDLE_INDEX, frame.CHUNK_COUNT):
        raw = _read_exact(descriptor, frame.chunk_offset(index), frame.CHUNK_RECORD_LENGTH)
        chunk = frame.decode_chunk(raw, index)
        block = frame.open_chunk(aead_provider, aes_key, header, chunk, manifest_region)
        if index == frame.FIRST_BUNDLE_INDEX:
            if int.from_bytes(block[:8], "big") != expected:
                _refuse("mismatch")
            block = block[8:]
        take = min(len(block), expected - written)
        if take:
            sink.write(block[:take])
            digest.update(block[:take])
            written += take
        if any(block[take:]):
            _refuse("padding")
    if written != expected or digest.digest() != manifest.bundle_sha256:
        _refuse("mismatch")


def open_capsule(capsule_path, key_record_bytes, aes_key, aead_provider, bundle_destination):
    """Decrypt a capsule with a derived AES key, write the bundle, and return the verified manifest."""
    try:
        descriptor, size = _open_regular(capsule_path, "capsule")
        created = False
        try:
            if size != frame.CAPSULE_LENGTH:
                _refuse("capsule")
            header = frame.decode_capsule_header(_read_exact(descriptor, 0, frame.CAPSULE_HEADER_LENGTH))
            frame.validate_header_key_binding(header, key_record_bytes)
            manifest_region = _read_exact(descriptor, frame.MANIFEST_REGION_START, frame.MANIFEST_REGION_LENGTH)
            plain = bytearray()
            for index in range(frame.MANIFEST_CHUNK_COUNT):
                start = index * frame.CHUNK_RECORD_LENGTH
                chunk = frame.decode_chunk(manifest_region[start:start + frame.CHUNK_RECORD_LENGTH], index)
                plain.extend(frame.open_chunk(aead_provider, aes_key, header, chunk))
            manifest, padding = frame.decode_manifest_region(bytes(plain))
            if any(padding):
                _refuse("padding")
            try:
                sink_descriptor = os.open(bundle_destination, CREATE_FLAGS, 0o600)
            except OSError:
                _refuse("output")
            created = True
            with os.fdopen(sink_descriptor, "wb") as sink:
                _open_bundle_region(descriptor, header, aes_key, aead_provider, manifest, manifest_region, sink)
            if any(_read_exact(descriptor, frame.TRAILER_START, frame.TRAILER_LENGTH)):
                _refuse("padding")
            created = False
            return manifest
        finally:
            os.close(descriptor)
            if created:
                try:
                    os.unlink(bundle_destination)
                except OSError:
                    pass
    except SourceCapsuleRefusal:
        raise
    except frame.CapsuleRefusal:
        _refuse("capsule")
    except OSError:
        _refuse("output")
    except Exception:
        _refuse("internal")


class CryptographyProvider:
    """P-256 ECDH and AES-256-GCM from the cryptography package, imported only when constructed.

    One instance holds one ephemeral sender key that destroy() discards. The AES key reaches seal
    as the frame's mutable buffer and is copied once into the immutable key the library requires.
    """

    def __init__(self):
        try:
            from cryptography.hazmat.primitives.asymmetric import ec
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            _refuse("provider")
        self._ec = ec
        self._aead = AESGCM
        self._serialization = serialization
        self._private = ec.generate_private_key(ec.SECP256R1())

    def sender_public_point(self):
        if self._private is None:
            _refuse("provider")
        return self._private.public_key().public_bytes(
            self._serialization.Encoding.X962, self._serialization.PublicFormat.UncompressedPoint,
        )

    def derive_shared_x(self, peer_public_point):
        if self._private is None:
            _refuse("provider")
        peer = self._ec.EllipticCurvePublicKey.from_encoded_point(self._ec.SECP256R1(), peer_public_point)
        return self._private.exchange(self._ec.ECDH(), peer)

    def destroy(self):
        self._private = None

    def seal(self, key, nonce, plaintext, aad):
        sealed = self._aead(bytes(key)).encrypt(nonce, plaintext, aad)
        return sealed[:-frame.CHUNK_TAG_BYTES], sealed[-frame.CHUNK_TAG_BYTES:]

    def open(self, key, nonce, ciphertext, tag, aad):
        return self._aead(bytes(key)).decrypt(nonce, bytes(ciphertext) + bytes(tag), aad)


def _read_small(path, limit, reason):
    descriptor, size = _open_regular(path, reason)
    with os.fdopen(descriptor, "rb") as stream:
        if size > limit:
            _refuse(reason)
        data = stream.read(limit + 1)
    if len(data) != size:
        _refuse(reason)
    return data


def _write_summary(path, summary):
    try:
        descriptor = os.open(path, CREATE_FLAGS, 0o600)
    except OSError:
        _refuse("output")
    with os.fdopen(descriptor, "w", encoding="ascii") as sink:
        sink.write(json.dumps(summary, sort_keys=True, separators=(",", ":")) + "\n")


def seal_from_arguments(options):
    if set(options) != CLI_OPTIONS:
        _refuse("input")
    source_sha = _check_source_sha(options["--source-sha"])
    if re.fullmatch(r"[1-9][0-9]{0,19}", options["--source-repository-id"]) is None:
        _refuse("input")
    repository_id = _check_repository_id(int(options["--source-repository-id"]))
    key_record = _read_small(options["--key-record"], frame.KEY_RECORD_LENGTH, "key-record")
    length, bundle_digest = bundle_facts(options["--bundle"], source_sha)
    manifest = build_manifest(options["--repository"], source_sha, repository_id, length, bundle_digest)
    provider = CryptographyProvider()
    summary = seal_capsule(
        options["--output"], key_record, manifest, options["--bundle"], provider, provider,
    )
    try:
        _write_summary(options["--summary"], summary)
    except BaseException:
        try:
            os.unlink(options["--output"])
        except OSError:
            pass
        raise
    return summary


def main(arguments=None):
    actual = sys.argv[1:] if arguments is None else list(arguments)
    if not actual or actual[0] != "seal" or len(actual) % 2 != 1:
        return 2
    options = {}
    for name, value in zip(actual[1::2], actual[2::2]):
        if name not in CLI_OPTIONS or name in options:
            return 2
        options[name] = value
    try:
        summary = seal_from_arguments(options)
    except SourceCapsuleRefusal as error:
        sys.stdout.write("source-capsule=refused reason=" + error.reason + "\n")
        return 1
    except BaseException:
        sys.stdout.write("source-capsule=refused reason=internal\n")
        return 1
    sys.stdout.write(
        "source-capsule=sealed capsule-sha256=" + summary["capsule_sha256"] + " length=" + str(summary["length"])
        + " source-sha=" + summary["source_sha"] + " tree=" + summary["tree_id"]
        + " entries=" + str(summary["entries"]) + "\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
