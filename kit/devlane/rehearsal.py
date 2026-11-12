"""Owner-side request builders for a source-free rehearsal wave and for ordinary waves.

The default rehearsal source is the hostile synthetic Node fixture; `--profile core-rust` selects the
reviewed hostile Rust fixture. Both plant source and key canaries and workflow-command text, and the
Rust tests fail if an isolation boundary is open. Each source lives in a throwaway local repository
under an owner-only directory, never in a checkout. Nothing here talks to GitHub or reads real source.
"""

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import time
from pathlib import Path

import bundle
import test_e2e as fixtures
import rust_rehearsal_fixture


NODE_VERSION = "24.22.1"
NPM_VERSION = "11.19.1"
DEFAULT_REHEARSAL_PROFILE = "core-node"
RUST_TOOLCHAIN = "1.99.1"
REHEARSAL_TEST = {"synthetic canary suite accepted test": "case_0001"}
REHEARSAL_FILE = {"packages/kernel-ui-kit/src/example.ts": "file_0001"}
DECIMAL = re.compile(r"[1-9][0-9]{0,18}\Z")


class Refusal(ValueError):
    pass


def _refuse(code):
    raise Refusal(code)


def _directory(path):
    """An existing owner-only directory that is not inside any Git work tree."""
    target = Path(path)
    try:
        metadata = os.lstat(str(target))
    except OSError:
        _refuse("directory-unavailable")
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077):
        _refuse("directory-permissions")
    probe = subprocess.run(["git", "-C", str(target), "rev-parse", "--is-inside-work-tree"],
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           check=False, timeout=30)
    if probe.returncode == 0:
        _refuse("directory-inside-checkout")
    return target.resolve(strict=True)


def _write_new(path, payload):
    descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(payload)
        output.flush()
        os.fsync(output.fileno())


def _git(repository, *arguments):
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "GIT_CONFIG_GLOBAL": os.devnull,
                   "GIT_CONFIG_SYSTEM": os.devnull, "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}
    result = subprocess.run(["git", "-C", str(repository), *arguments], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, check=False, timeout=60,
                            env=environment)
    if result.returncode != 0:
        _refuse("git-failed")
    return result.stdout.decode("utf-8", "strict").strip()


def synthetic_source(profile=DEFAULT_REHEARSAL_PROFILE):
    """Return the source fixture and its reviewed lock material for one fixed profile."""
    if profile == "core-rust":
        return None, rust_rehearsal_fixture.source_files()
    if profile != "core-node":
        _refuse("rehearsal-profile")
    lock = fixtures._node_lock_from_reviewed({"typescript": "6.0.3"})
    return lock, fixtures._node_source(lock)


def build_source(directory, profile=DEFAULT_REHEARSAL_PROFILE):
    root = _directory(directory)
    if profile not in ("core-node", "core-rust"):
        _refuse("rehearsal-profile")
    repository = root / "source-repo"
    if repository.exists() or repository.is_symlink():
        _refuse("rehearsal-source-exists")
    lock, files = synthetic_source(profile)
    repository.mkdir(mode=0o700)
    _git(repository, "init", "--quiet", "--initial-branch", "rehearsal")
    for name, payload in sorted(files.items()):
        target = repository / name
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        _write_new(target, payload)
    _git(repository, "add", "--all")
    _git(repository, "-c", "user.name=rehearsal", "-c", "user.email=rehearsal@invalid",
         "-c", "commit.gpgsign=false", "commit", "--quiet", "--no-verify", "--message", "rehearsal source")
    revision = _git(repository, "rev-parse", "HEAD")
    if not bundle.GIT_SHA.fullmatch(revision):
        _refuse("rehearsal-revision")
    request = {
        "schema": 1, "repository": str(repository), "source_revision": revision, "profile": profile,
        "tools": ({"node": NODE_VERSION, "npm": NPM_VERSION} if profile == "core-node"
                  else {"cargo": RUST_TOOLCHAIN, "rustc": RUST_TOOLCHAIN}),
        "playwright": [],
    }
    if profile == "core-node":
        request["lockfile"] = "package-lock.json"
    else:
        request["lockfiles"] = list(rust_rehearsal_fixture.LOCKFILES)
    _write_new(root / "projection-request.json", bundle.canonical_json(request) + b"\n")
    return revision


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(str(path), "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _opaque(value, code):
    if type(value) is not str or not bundle.OPAQUE_ID.fullmatch(value):
        _refuse(code)
    return value


def build_requests(directory, control_sha, control_run_id, wave_id, bundle_id, release_id, lifetime_seconds):
    root = _directory(directory)
    _opaque(wave_id, "wave-id")
    _opaque(bundle_id, "bundle-id")
    if (type(control_sha) is not str or not re.fullmatch(r"[a-f0-9]{40}", control_sha)
            or not DECIMAL.fullmatch(str(control_run_id)) or not DECIMAL.fullmatch(str(release_id))
            or type(lifetime_seconds) is not int or not 60 <= lifetime_seconds <= 3300):
        _refuse("request-input")
    request = bundle.strict_json((root / "projection-request.json").read_bytes(), 1024 * 1024)
    projection = root / "projection.json"
    if not projection.is_file() or projection.is_symlink():
        _refuse("projection-missing")
    projected = bundle.strict_json(projection.read_bytes(), 16 * 1024 * 1024)
    if (request.get("profile") not in ("core-node", "core-rust")
            or type(projected) is not dict or projected.get("profile") != request["profile"]):
        _refuse("projection-profile-mismatch")
    profile = request["profile"]
    allowed_files = REHEARSAL_FILE if profile == "core-node" else {}
    allowed_tests = REHEARSAL_TEST if profile == "core-node" else rust_rehearsal_fixture.TESTS
    expires = int(time.time()) + lifetime_seconds
    reserve = {
        "schema": 2, "wave_id": wave_id, "bundle_id": bundle_id, "control_run_id": str(control_run_id),
        "control_sha": control_sha, "profile": profile, "expires": expires, "release_id": str(release_id),
    }
    tracked = _git(request["repository"], "ls-files", "-z")
    source_files = sorted(item for item in tracked.split("\x00") if item)
    bundle_request = {
        "repository": request["repository"], "source_revision": request["source_revision"],
        "profile": profile, "fetch_sha256": _sha256_file(projection), "wave_id": wave_id,
        "bundle_id": bundle_id, "control_sha": control_sha, "expires": expires, "source_files": source_files,
        "allowed_files": dict(allowed_files), "allowed_tests": dict(allowed_tests), "frames": {},
    }
    _write_new(root / "reserve.json", bundle.canonical_json(reserve) + b"\n")
    _write_new(root / "bundle-request.json", bundle.canonical_json(bundle_request) + b"\n")
    return expires


def build_staged(directory):
    """The stage record for the ciphertext and projection already in the directory (any wave)."""
    root = _directory(directory)
    record = {"schema": 1}
    for name, source in (("bundle", "bundle.enc"), ("projection", "projection.json")):
        path = root / source
        if not path.is_file() or path.is_symlink():
            _refuse("staged-input-missing")
        record[name + "_sha256"] = _sha256_file(path)
        record[name + "_size"] = path.stat().st_size
    _write_new(root / "staged-assets.json", bundle.canonical_json(record) + b"\n")


def build_intent(directory, wave_id, bundle_asset_id, projection_asset_id, cache_baseline_sha256):
    root = _directory(directory)
    _opaque(wave_id, "wave-id")
    if (not DECIMAL.fullmatch(str(bundle_asset_id)) or not DECIMAL.fullmatch(str(projection_asset_id))
            or not bundle.SHA256.fullmatch(str(cache_baseline_sha256))):
        _refuse("intent-input")
    record = {
        "schema": 2, "wave_id": wave_id, "bundle_asset_id": str(bundle_asset_id),
        "projection_asset_id": str(projection_asset_id), "cache_baseline_sha256": cache_baseline_sha256,
    }
    _write_new(root / "intent.json", bundle.canonical_json(record) + b"\n")


def main(argv=None):
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="operation", required=True)
    source = sub.add_parser("source")
    source.add_argument("--directory", required=True)
    source.add_argument("--profile", choices=("core-node", "core-rust"), default=DEFAULT_REHEARSAL_PROFILE)
    requests = sub.add_parser("requests")
    requests.add_argument("--directory", required=True)
    requests.add_argument("--control-sha", required=True)
    requests.add_argument("--control-run-id", required=True)
    requests.add_argument("--wave-id", required=True)
    requests.add_argument("--bundle-id", required=True)
    requests.add_argument("--release-id", required=True)
    requests.add_argument("--lifetime-seconds", type=int, default=3000)
    staged = sub.add_parser("staged")
    staged.add_argument("--directory", required=True)
    intent = sub.add_parser("intent")
    intent.add_argument("--directory", required=True)
    intent.add_argument("--wave-id", required=True)
    intent.add_argument("--bundle-asset-id", required=True)
    intent.add_argument("--projection-asset-id", required=True)
    intent.add_argument("--cache-baseline-sha256", required=True)
    args = parser.parse_args(argv)
    try:
        if args.operation == "source":
            print("rehearsal_source=ready profile=%s revision=%s" % (
                args.profile, build_source(args.directory, args.profile)))
        elif args.operation == "requests":
            expires = build_requests(args.directory, args.control_sha, args.control_run_id, args.wave_id,
                                     args.bundle_id, args.release_id, args.lifetime_seconds)
            print("rehearsal_requests=ready expires=%d" % expires)
        elif args.operation == "staged":
            build_staged(args.directory)
            print("staged_request=ready")
        else:
            build_intent(args.directory, args.wave_id, args.bundle_asset_id, args.projection_asset_id,
                         args.cache_baseline_sha256)
            print("intent_request=ready")
        return 0
    except (Refusal, bundle.Refusal) as error:
        print("rehearsal_refusal=" + str(error))
        return 2
    except Exception:
        print("rehearsal_refusal=operation-failed")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
