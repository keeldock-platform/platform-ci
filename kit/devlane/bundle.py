"""Versioned AES-256-GCM envelope and safe source archive handling.

This module is deliberately data-only: it never imports or executes candidate
modules, package scripts, Git hooks, or archive members.
"""

import argparse
import base64
import hashlib
import io
import json
import os
import re
import secrets
import stat
import subprocess
import tarfile
import time
from pathlib import Path, PurePosixPath

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    AESGCM = None


MAGIC = b"KDLDEVL\x00"
VERSION = 1
MAX_HEADER = 16384
MAX_CIPHERTEXT = 64 * 1024 * 1024
MAX_EXPANDED = 512 * 1024 * 1024
MAX_FILES = 10_000
MAX_FILE = 32 * 1024 * 1024
ENVELOPE_FIELDS = frozenset((
    "format", "repository_id", "control_sha", "workflow_path", "profile",
    "wave_id", "bundle_id", "fetch_sha256", "expires",
))
MANIFEST_FIELDS = frozenset((
    "schema", "profile", "profile_revision", "source_revision", "tree_sha256",
    "files", "original_lockfiles", "fetch_sha256", "allowed_files", "allowed_tests",
    "frames", "limits",
))
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
GIT_SHA = re.compile(r"[a-f0-9]{40,64}\Z")
OPAQUE_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{7,63}\Z")
FORBIDDEN_COMPONENTS = frozenset((
    ".git", ".env", "node_modules", "target", "dist", "coverage",
    ".idea", ".vscode", ".pytest_cache", "__pycache__", ".next", ".turbo",
))
FORBIDDEN_NAMES = frozenset((
    ".npmrc", ".netrc", "id_rsa", "id_ed25519", "credentials", "secrets.json",
))


class Refusal(ValueError):
    """A fixed, non-sensitive refusal category."""


def _refuse(code):
    raise Refusal(code)


def _pairs_no_duplicates(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse("duplicate-json-key")
        result[key] = value
    return result


def strict_json(payload, max_bytes=MAX_HEADER):
    if type(payload) is not bytes or len(payload) > max_bytes:
        _refuse("json-size")
    try:
        text = payload.decode("utf-8", "strict")
        return json.loads(text, object_pairs_hook=_pairs_no_duplicates)
    except Refusal:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        _refuse("json-invalid")


def canonical_json(value):
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, RecursionError):
        _refuse("json-invalid")


def _valid_bindings(bindings):
    if type(bindings) is not dict or set(bindings) != ENVELOPE_FIELDS:
        _refuse("binding-shape")
    if bindings.get("format") != "kd-public-devlane-aesgcm-v1":
        _refuse("envelope-version")
    if type(bindings.get("repository_id")) is not str or not re.fullmatch(r"[1-9][0-9]{0,18}", bindings["repository_id"]):
        _refuse("binding-repository")
    if type(bindings.get("control_sha")) is not str or not GIT_SHA.fullmatch(bindings["control_sha"]):
        _refuse("binding-control")
    if bindings.get("workflow_path") != ".github/workflows/devlane-encrypted.yml":
        _refuse("binding-workflow")
    if bindings.get("profile") not in ("core-node", "core-rust"):
        _refuse("binding-profile")
    for name in ("wave_id", "bundle_id"):
        if type(bindings.get(name)) is not str or not OPAQUE_ID.fullmatch(bindings[name]):
            _refuse("binding-id")
    if type(bindings.get("fetch_sha256")) is not str or not SHA256.fullmatch(bindings["fetch_sha256"]):
        _refuse("binding-fetch")
    if type(bindings.get("expires")) is not int or bindings["expires"] <= 0:
        _refuse("binding-expiry")
    return bindings


def build_envelope(plaintext, key, bindings):
    if AESGCM is None:
        _refuse("crypto-unavailable")
    if type(key) is not bytes or len(key) != 32:
        _refuse("key-invalid")
    if type(plaintext) is not bytes or len(plaintext) > MAX_CIPHERTEXT - 64:
        _refuse("plaintext-size")
    header = canonical_json(_valid_bindings(dict(bindings)))
    if len(header) > MAX_HEADER:
        _refuse("header-size")
    prefix = MAGIC + VERSION.to_bytes(2, "big") + len(header).to_bytes(4, "big") + header
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, prefix)
    envelope = prefix + nonce + ciphertext
    if len(envelope) > MAX_CIPHERTEXT:
        _refuse("ciphertext-size")
    return envelope


def parse_envelope(envelope, key, expected, now=None):
    if AESGCM is None:
        _refuse("crypto-unavailable")
    if type(envelope) is not bytes or len(envelope) < len(MAGIC) + 6 + 12 + 16 or len(envelope) > MAX_CIPHERTEXT:
        _refuse("ciphertext-size")
    if envelope[:len(MAGIC)] != MAGIC:
        _refuse("envelope-magic")
    version_start = len(MAGIC)
    version = int.from_bytes(envelope[version_start:version_start + 2], "big")
    if version != VERSION:
        _refuse("envelope-version")
    header_length = int.from_bytes(envelope[version_start + 2:version_start + 6], "big")
    if header_length < 2 or header_length > MAX_HEADER:
        _refuse("header-size")
    header_start = version_start + 6
    header_end = header_start + header_length
    if header_end + 28 > len(envelope):
        _refuse("envelope-truncated")
    prefix = envelope[:header_end]
    header = _valid_bindings(strict_json(envelope[header_start:header_end], MAX_HEADER))
    expected = _valid_bindings(dict(expected))
    if header != expected:
        _refuse("binding-mismatch")
    now = int(time.time()) if now is None else now
    if type(now) is not int or header["expires"] <= now:
        _refuse("request-expired")
    if type(key) is not bytes or len(key) != 32:
        _refuse("key-invalid")
    nonce = envelope[header_end:header_end + 12]
    body = envelope[header_end + 12:]
    try:
        return AESGCM(key).decrypt(nonce, body, prefix)
    except Exception:
        _refuse("authentication-failed")


def _safe_member_name(name):
    if type(name) is not str or not name or "\\" in name or "\x00" in name:
        _refuse("archive-path")
    raw_parts = name.split("/")
    if any(part in ("", ".", "..") for part in raw_parts):
        _refuse("archive-path")
    path = PurePosixPath(name)
    if path.is_absolute() or any(part in ("", ".", "..") for part in path.parts):
        _refuse("archive-path")
    if re.match(r"^[A-Za-z]:", name) or name.startswith("//"):
        _refuse("archive-path")
    if any(part.lower() in FORBIDDEN_COMPONENTS or part.lower() in FORBIDDEN_NAMES
           or part.lower().startswith(".env") for part in path.parts):
        _refuse("archive-excluded-path")
    return path.as_posix()


def _manifest(payload, expected, inventory):
    value = strict_json(payload, 4 * 1024 * 1024)
    if type(value) is not dict or set(value) != MANIFEST_FIELDS or value.get("schema") != 1:
        _refuse("inner-manifest-shape")
    if value.get("profile") != expected["profile"] or value.get("fetch_sha256") != expected["fetch_sha256"]:
        _refuse("inner-binding-mismatch")
    if type(value.get("profile_revision")) is not int or value["profile_revision"] != 1:
        _refuse("inner-profile")
    if type(value.get("source_revision")) is not str or not GIT_SHA.fullmatch(value["source_revision"]):
        _refuse("inner-source-revision")
    if type(value.get("tree_sha256")) is not str or not SHA256.fullmatch(value["tree_sha256"]):
        _refuse("inner-tree-digest")
    files = value.get("files")
    if type(files) is not list or len(files) != len(inventory):
        _refuse("inner-file-list")
    expected_files = {}
    for row in files:
        if type(row) is not dict or set(row) != {"path", "size", "sha256"}:
            _refuse("inner-file-entry")
        name = _safe_member_name(row["path"])
        if name == ".devlane/manifest.json" or name in expected_files:
            _refuse("inner-file-duplicate")
        if type(row["size"]) is not int or row["size"] < 0 or row["size"] > MAX_FILE:
            _refuse("inner-file-size")
        if type(row["sha256"]) is not str or not SHA256.fullmatch(row["sha256"]):
            _refuse("inner-file-digest")
        expected_files[name] = (row["size"], row["sha256"])
    if expected_files != inventory:
        _refuse("inner-file-mismatch")
    for field in ("original_lockfiles", "allowed_files", "allowed_tests", "frames", "limits"):
        if type(value.get(field)) is not dict:
            _refuse("inner-manifest-entry")
    for path, digest in value["original_lockfiles"].items():
        canonical_path = _safe_member_name(path)
        if (canonical_path not in inventory or type(digest) is not str or not SHA256.fullmatch(digest)
                or inventory[canonical_path][1] != digest):
            _refuse("inner-lockfile-binding")
    for mapping in (value["allowed_files"], value["allowed_tests"], value["frames"]):
        public_ids = set()
        for private_name, public_id in mapping.items():
            if type(private_name) is not str or not private_name or len(private_name) > 2048:
                _refuse("inner-allowlist-entry")
            if type(public_id) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", public_id):
                _refuse("inner-allowlist-entry")
            if public_id in public_ids:
                _refuse("inner-allowlist-duplicate")
            public_ids.add(public_id)
    for path in value["allowed_files"]:
        if _safe_member_name(path) not in inventory:
            _refuse("inner-allowlist-file")
    if value["limits"] != {
        "ciphertext_bytes": MAX_CIPHERTEXT,
        "expanded_bytes": MAX_EXPANDED,
        "files": MAX_FILES,
        "file_bytes": MAX_FILE,
    }:
        _refuse("inner-limits")
    expected_tree_sha256 = hashlib.sha256(canonical_json(value["files"])).hexdigest()
    if value["tree_sha256"] != expected_tree_sha256:
        _refuse("inner-tree-digest")
    return value


def inspect_archive(archive_bytes, expected):
    if type(archive_bytes) is not bytes or len(archive_bytes) > MAX_CIPHERTEXT:
        _refuse("archive-size")
    inventory = {}
    directories = set()
    contents = {}
    expanded = 0
    try:
        import gzip
        compressed = gzip.GzipFile(fileobj=io.BytesIO(archive_bytes), mode="rb")
        expanded_archive = bytearray()
        while True:
            chunk = compressed.read(min(1024 * 1024, MAX_EXPANDED + 1 - len(expanded_archive)))
            if not chunk:
                break
            expanded_archive.extend(chunk)
            if len(expanded_archive) > MAX_EXPANDED:
                _refuse("archive-expanded-size")
        archive = tarfile.open(fileobj=io.BytesIO(expanded_archive), mode="r:")
        member_count = 0
        for member in archive:
            member_count += 1
            if member_count > MAX_FILES + 1:
                _refuse("archive-file-count")
            if member.pax_headers or member.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
                _refuse("archive-extended-header")
            raw_name = member.name
            if member.isdir() and raw_name.endswith("/"):
                raw_name = raw_name[:-1]
            name = _safe_member_name(raw_name)
            if name in contents or name in directories:
                _refuse("archive-duplicate")
            if member.isdir():
                if member.size != 0:
                    _refuse("archive-directory-size")
                directories.add(name)
                continue
            if not member.isreg() or member.linkname:
                _refuse("archive-member-type")
            if member.size < 0 or member.size > MAX_FILE:
                _refuse("archive-file-size")
            expanded += member.size
            if expanded > MAX_EXPANDED:
                _refuse("archive-expanded-size")
            stream = archive.extractfile(member)
            if stream is None:
                _refuse("archive-member-read")
            payload = stream.read(MAX_FILE + 1)
            if len(payload) != member.size or len(payload) > MAX_FILE:
                _refuse("archive-member-truncated")
            contents[name] = payload
            inventory[name] = (len(payload), hashlib.sha256(payload).hexdigest())
    except Refusal:
        raise
    except (tarfile.TarError, OSError, EOFError, ValueError, RecursionError):
        _refuse("archive-invalid")
    manifest_bytes = contents.pop(".devlane/manifest.json", None)
    inventory.pop(".devlane/manifest.json", None)
    if manifest_bytes is None:
        _refuse("inner-manifest-missing")
    manifest = _manifest(manifest_bytes, expected, inventory)
    return manifest, contents, directories


def extract_authenticated_archive(archive_bytes, destination, expected):
    manifest, contents, directories = inspect_archive(archive_bytes, expected)
    destination = Path(destination)
    if destination.exists() and any(destination.iterdir()):
        _refuse("workspace-not-empty")
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    for relative in sorted(directories, key=lambda item: (item.count("/"), item)):
        (destination / relative).mkdir(mode=0o700, parents=True, exist_ok=True)
    for relative, payload in contents.items():
        target = destination / relative
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(str(target), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
        except Exception:
            try:
                target.unlink()
            except OSError:
                pass
            raise
    return manifest


def _excluded_source_path(path):
    parts = PurePosixPath(path).parts
    name = PurePosixPath(path).name.lower()
    if any(part.lower() in FORBIDDEN_COMPONENTS for part in parts):
        return True
    if name in FORBIDDEN_NAMES or name.startswith(".env") or name.endswith((".log", ".trace", ".har")):
        return True
    if name in (".ds_store", "thumbs.db", "npm-debug.log", "yarn-error.log"):
        return True
    return False


def _git_blob(root, blob):
    """Read one Git blob with a hard output bound (never materialize an unbounded pipe)."""
    try:
        process = subprocess.Popen(
            ["git", "-C", str(root), "cat-file", "blob", blob],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, close_fds=True,
        )
        output = bytearray()
        deadline = time.monotonic() + 30
        while True:
            if time.monotonic() > deadline:
                process.kill()
                process.wait(timeout=2)
                _refuse("source-blob-timeout")
            chunk = process.stdout.read(min(65536, MAX_FILE + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
            if len(output) > MAX_FILE:
                process.kill()
                process.wait(timeout=2)
                _refuse("source-blob-size")
        process.stdout.close()
        if process.wait(timeout=2) != 0:
            _refuse("source-blob-unavailable")
        return bytes(output)
    except (OSError, subprocess.SubprocessError):
        _refuse("source-blob-unavailable")


def _validate_public_map(value, max_entries, code):
    if type(value) is not dict or len(value) > max_entries:
        _refuse(code)
    public_ids = set()
    for private_name, public_id in value.items():
        if (type(private_name) is not str or not private_name or len(private_name) > 2048
                or type(public_id) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}", public_id)
                or public_id in public_ids):
            _refuse(code)
        public_ids.add(public_id)
    return value


def build_source_archive(repository, revision, profile, fetch_sha256, source_files,
                         allowed_files, allowed_tests, frames):
    repository = Path(repository).resolve(strict=True)
    if type(revision) is not str or not GIT_SHA.fullmatch(revision):
        _refuse("source-revision-invalid")
    if profile not in ("core-node", "core-rust", "synthetic") or not SHA256.fullmatch(fetch_sha256):
        _refuse("source-profile-invalid")
    verify = subprocess.run(
        ["git", "-C", str(repository), "rev-parse", "--verify", revision + "^{commit}"],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=30,
    )
    if verify.returncode != 0 or verify.stdout.decode("ascii", "ignore").strip() != revision:
        _refuse("source-revision-mismatch")
    tree = subprocess.run(
        ["git", "-C", str(repository), "ls-tree", "-r", "-z", "--full-tree", revision],
        check=False, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60,
    )
    if tree.returncode != 0 or len(tree.stdout) > MAX_EXPANDED:
        _refuse("source-tree-unavailable")
    if type(source_files) is not list or not source_files or len(source_files) > MAX_FILES:
        _refuse("source-selection-invalid")
    selected = frozenset(_safe_member_name(item) for item in source_files)
    if len(selected) != len(source_files):
        _refuse("source-selection-duplicate")
    allowed_files = _validate_public_map(allowed_files, MAX_FILES, "source-file-map")
    allowed_tests = _validate_public_map(allowed_tests, MAX_FILES, "source-test-map")
    frames = _validate_public_map(frames, 10_000, "source-frame-map")
    if profile == "synthetic":
        _refuse("synthetic-bundle-forbidden")
    if profile == "core-node" and (not allowed_files or not allowed_tests):
        _refuse("source-allowlist-empty")
    blobs = []
    names = set()
    total = 0
    for row in tree.stdout.split(b"\x00"):
        if not row:
            continue
        try:
            metadata, raw_path = row.split(b"\t", 1)
            mode, kind, blob = metadata.split(b" ", 2)
            path = raw_path.decode("utf-8", "strict")
        except (ValueError, UnicodeDecodeError):
            _refuse("source-tree-entry")
        path = _safe_member_name(path)
        if selected is not None and path not in selected:
            continue
        if _excluded_source_path(path):
            continue
        if mode not in (b"100644", b"100755") or kind != b"blob" or not re.fullmatch(rb"[a-f0-9]{40,64}", blob):
            _refuse("source-member-type")
        if path in names:
            _refuse("source-duplicate")
        payload = _git_blob(repository, blob.decode("ascii"))
        total += len(payload)
        if total > MAX_EXPANDED:
            _refuse("source-expanded-size")
        names.add(path)
        blobs.append((path, payload))
    if set(selected) != names:
        _refuse("source-selection-mismatch")
    if not set(allowed_files).issubset(names):
        _refuse("source-file-map-unavailable")
    if not any(PurePosixPath(path).name in ("package-lock.json", "Cargo.lock") for path in names):
        _refuse("source-lockfile-missing")
    if len(blobs) > MAX_FILES:
        _refuse("source-file-count")
    inventory = [
        {"path": name, "size": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}
        for name, payload in sorted(blobs)
    ]
    tree_digest = hashlib.sha256(canonical_json(inventory)).hexdigest()
    lockfiles = {
        name: hashlib.sha256(payload).hexdigest()
        for name, payload in blobs
        if PurePosixPath(name).name in ("package-lock.json", "Cargo.lock")
    }
    manifest = {
        "schema": 1,
        "profile": profile,
        "profile_revision": 1,
        "source_revision": revision,
        "tree_sha256": tree_digest,
        "files": inventory,
        "original_lockfiles": lockfiles,
        "fetch_sha256": fetch_sha256,
        "allowed_files": allowed_files,
        "allowed_tests": allowed_tests,
        "frames": frames,
        "limits": {
            "ciphertext_bytes": MAX_CIPHERTEXT,
            "expanded_bytes": MAX_EXPANDED,
            "files": MAX_FILES,
            "file_bytes": MAX_FILE,
        },
    }
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for name, payload in sorted(blobs):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o600
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            archive.addfile(info, io.BytesIO(payload))
        manifest_bytes = canonical_json(manifest)
        info = tarfile.TarInfo(".devlane/manifest.json")
        info.size = len(manifest_bytes)
        info.mode = 0o600
        info.uid = info.gid = info.mtime = 0
        info.uname = info.gname = ""
        archive.addfile(info, io.BytesIO(manifest_bytes))
    result = output.getvalue()
    if len(result) > MAX_CIPHERTEXT - 128:
        _refuse("archive-size")
    return result


def read_key_file(path):
    try:
        mode = stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode)
        if mode & 0o077:
            _refuse("key-file-permissions")
        raw = Path(path).read_bytes()
    except OSError:
        _refuse("key-file-unavailable")
    raw = raw.strip()
    if len(raw) == 64 and re.fullmatch(rb"[a-f0-9]{64}", raw):
        key = bytes.fromhex(raw.decode("ascii"))
    else:
        try:
            key = base64.b64decode(raw, validate=True)
        except Exception:
            _refuse("key-file-invalid")
    if len(key) != 32:
        _refuse("key-file-invalid")
    return key


def write_private_key(path, key):
    path = Path(path)
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(key.hex().encode("ascii"))
            output.flush()
            os.fsync(output.fileno())
    except Exception:
        try:
            path.unlink()
        except OSError:
            pass
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(add_help=True)
    sub = parser.add_subparsers(dest="operation", required=True)
    create = sub.add_parser("create")
    create.add_argument("--request", required=True, help="owner-only coordinator JSON; values are never echoed")
    create.add_argument("--ciphertext", required=True)
    create.add_argument("--key-file", required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "create":
            request = strict_json(Path(args.request).read_bytes(), 1024 * 1024)
            required = {"repository", "source_revision", "profile", "fetch_sha256", "wave_id",
                        "bundle_id", "control_sha", "expires", "source_files", "allowed_files",
                        "allowed_tests", "frames"}
            if type(request) is not dict or set(request) != required:
                _refuse("producer-request-shape")
            key = AESGCM.generate_key(bit_length=256) if AESGCM is not None else None
            if key is None:
                _refuse("crypto-unavailable")
            bindings = {
                "format": "kd-public-devlane-aesgcm-v1",
                "repository_id": "1430960557",
                "control_sha": request["control_sha"],
                "workflow_path": ".github/workflows/devlane-encrypted.yml",
                "profile": request["profile"],
                "wave_id": request["wave_id"],
                "bundle_id": request["bundle_id"],
                "fetch_sha256": request["fetch_sha256"],
                "expires": request["expires"],
            }
            archive = build_source_archive(
                request["repository"], request["source_revision"], request["profile"],
                request["fetch_sha256"], request["source_files"], request["allowed_files"],
                request["allowed_tests"], request["frames"],
            )
            envelope = build_envelope(archive, key, bindings)
            write_private_key(args.key_file, key)
            descriptor = os.open(args.ciphertext, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output:
                output.write(envelope)
                output.flush()
                os.fsync(output.fileno())
            print("bundle_created=true bytes=%d sha256=%s" % (len(envelope), hashlib.sha256(envelope).hexdigest()))
        return 0
    except Refusal as error:
        print("devlane_refusal=" + str(error))
        return 2
    except Exception:
        print("devlane_refusal=operation-failed")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
