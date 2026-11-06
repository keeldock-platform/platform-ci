"""Install and verify the reviewed cargo-deny release used by Rust admission."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request


CARGO_DENY_VERSION = "0.20.2"
CARGO_DENY_RELEASE_ORIGIN = (
    "https:" + "/" * 2 + "github.com/EmbarkStudios/cargo-deny/releases/download/"
)
RUSTSEC_ADVISORY_DATABASE_URL = "https:" + "/" * 2 + "github.com/RustSec/advisory-db"
RUSTSEC_ADVISORY_DATABASE_ID = "advisory-db-3157b0e258782691"
MAX_ADVISORY_AGE_SECONDS = 24 * 60 * 60
MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
MAX_EXECUTABLE_BYTES = 64 * 1024 * 1024
RELEASE_ASSET_HOSTS = frozenset((
    "objects.githubusercontent.com", "release-assets.githubusercontent.com",
))
RELEASES = {
    ("linux", "x86_64"): (
        "x86_64-unknown-linux-musl",
        "9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f",
    ),
    ("darwin", "arm64"): (
        "aarch64-apple-darwin",
        "fe67d82a10d8597a3549364cb733a3f9cc1bfff9031b7ae46384a9f2a72090c3",
    ),
    ("windows", "amd64"): (
        "x86_64-pc-windows-msvc",
        "975a22143262fd27476d19ee00c7af67978426e40e1dee94eed6bbade1cf87dc",
    ),
}
RECEIPT_FIELDS = frozenset((
    "schema_version", "version", "target", "asset_name", "asset_sha256",
    "executable_sha256",
))


class CargoDenyInstallRefusal(Exception):
    """Fail closed when the pinned checker or advisory database is unavailable."""


class _ApprovedReleaseRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        del response
        try:
            original = urllib.parse.urlsplit(request.full_url)
            target = urllib.parse.urlsplit(new_url)
        except (AttributeError, TypeError, ValueError):
            _refuse()
        if (original.scheme != "https" or original.hostname != "github.com"
                or original.port is not None or original.username is not None
                or original.password is not None or target.scheme != "https"
                or target.hostname not in RELEASE_ASSET_HOSTS or target.port is not None
                or target.username is not None or target.password is not None
                or not target.path.startswith("/")):
            _refuse()
        return super().redirect_request(request, None, code, message, headers, new_url)

    max_redirections = 3
    max_repeats = 1


def _refuse():
    raise CargoDenyInstallRefusal("cargo_deny_install_invalid")


def target_for(system=None, machine=None):
    system = platform.system().lower() if system is None else system.lower()
    machine = platform.machine().lower() if machine is None else machine.lower()
    if machine in ("aarch64", "arm64"):
        machine = "arm64"
    if machine in ("amd64", "x86_64"):
        machine = "amd64" if system == "windows" else "x86_64"
    try:
        triple, digest = RELEASES[(system, machine)]
    except KeyError:
        _refuse()
    asset_name = "cargo-deny-" + CARGO_DENY_VERSION + "-" + triple + ".tar.gz"
    return system, triple, asset_name, digest


def _read_response(response, requested_url):
    try:
        final_url = response.geturl()
        try:
            requested = urllib.parse.urlsplit(requested_url)
            final = urllib.parse.urlsplit(final_url)
        except (TypeError, ValueError):
            _refuse()
        if (requested.scheme != "https" or requested.hostname != "github.com"
                or final.scheme != "https" or final.port is not None
                or final.username is not None or final.password is not None
                or (final_url != requested_url and final.hostname not in RELEASE_ASSET_HOSTS)):
            _refuse()
        status = response.status if hasattr(response, "status") else response.getcode()
        if status != 200:
            _refuse()
        declared = response.headers.get("Content-Length")
        if declared is not None and (not declared.isdecimal() or int(declared) > MAX_ARCHIVE_BYTES):
            _refuse()
        payload = response.read(MAX_ARCHIVE_BYTES + 1)
        if not payload or len(payload) > MAX_ARCHIVE_BYTES:
            _refuse()
        if declared is not None and len(payload) != int(declared):
            _refuse()
        return payload
    finally:
        try:
            response.close()
        except BaseException:
            pass


def _download(url, opener=None):
    actual_opener = opener or urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _ApprovedReleaseRedirect(),
    )
    request = urllib.request.Request(
        url, headers={"Accept": "application/octet-stream", "User-Agent": "platform-ci-cargo-deny/1"},
        method="GET",
    )
    try:
        response = actual_opener.open(request, timeout=30)
    except (OSError, urllib.error.URLError, ValueError):
        _refuse()
    return _read_response(response, url)


def _archive_binary(payload, system, asset_name):
    binary_name = "cargo-deny.exe" if system == "windows" else "cargo-deny"
    candidates = []
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > 4096:
                _refuse()
            for member in members:
                name = member.name
                if (not name or name.startswith("/") or "\\" in name
                        or any(part in ("", ".", "..") for part in name.rstrip("/").split("/"))):
                    _refuse()
                if member.isdir():
                    continue
                if not member.isfile() or member.size < 0 or member.size > MAX_EXECUTABLE_BYTES:
                    _refuse()
                if name.rsplit("/", 1)[-1] == binary_name:
                    candidates.append(member)
            if len(candidates) != 1:
                _refuse()
            stream = archive.extractfile(candidates[0])
            if stream is None:
                _refuse()
            binary = stream.read(MAX_EXECUTABLE_BYTES + 1)
    except (OSError, EOFError, tarfile.TarError):
        _refuse()
    if not binary or len(binary) > MAX_EXECUTABLE_BYTES or len(binary) != candidates[0].size:
        _refuse()
    del asset_name
    return binary


def _version_output(executable, runner=None):
    run = subprocess.run if runner is None else runner
    try:
        result = run(
            [str(executable), "--version"], stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15, check=False,
            env={"HOME": str(Path(executable).parent), "LANG": "C", "LC_ALL": "C"},
        )
    except (OSError, subprocess.SubprocessError, TypeError):
        _refuse()
    expected = ("cargo-deny " + CARGO_DENY_VERSION).encode("ascii")
    output = getattr(result, "stdout", b"")
    if (getattr(result, "returncode", None) != 0 or type(output) is not bytes
            or output.strip() != expected):
        _refuse()
    return True


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def install(destination, *, opener=None, runner=None, system=None, machine=None):
    system, triple, asset_name, expected_asset_sha256 = target_for(system, machine)
    destination = Path(destination)
    if destination.exists() or destination.is_symlink():
        _refuse()
    destination.mkdir(parents=True, mode=0o700)
    url = CARGO_DENY_RELEASE_ORIGIN + CARGO_DENY_VERSION + "/" + asset_name
    payload = _download(url, opener)
    asset_sha256 = hashlib.sha256(payload).hexdigest()
    if asset_sha256 != expected_asset_sha256:
        _refuse()
    binary = _archive_binary(payload, system, asset_name)
    executable_name = "cargo-deny.exe" if system == "windows" else "cargo-deny"
    executable = destination / executable_name
    archive_path = destination / asset_name
    executable.write_bytes(binary)
    archive_path.write_bytes(payload)
    if system != "windows":
        executable.chmod(0o555)
    receipt = {
        "schema_version": 1,
        "version": CARGO_DENY_VERSION,
        "target": triple,
        "asset_name": asset_name,
        "asset_sha256": asset_sha256,
        "executable_sha256": hashlib.sha256(binary).hexdigest(),
    }
    receipt_path = destination / "cargo-deny-install.json"
    receipt_path.write_bytes(_canonical_json(receipt) + b"\n")
    receipt_path.chmod(0o444)
    if system != "windows":
        archive_path.chmod(0o444)
    _version_output(executable, runner)
    return executable, receipt_path


def verify_installed(executable, receipt_path, *, runner=None, system=None, machine=None):
    system, triple, asset_name, expected_asset_sha256 = target_for(system, machine)
    executable = Path(executable)
    receipt_path = Path(receipt_path)
    try:
        receipt_bytes = receipt_path.read_bytes()
        receipt = json.loads(receipt_bytes.decode("ascii"))
        payload = (receipt_path.parent / asset_name).read_bytes()
        binary = executable.read_bytes()
    except (OSError, UnicodeError, ValueError):
        _refuse()
    if (type(receipt) is not dict or set(receipt) != set(RECEIPT_FIELDS)
            or _canonical_json(receipt) + b"\n" != receipt_bytes
            or receipt["schema_version"] != 1 or receipt["version"] != CARGO_DENY_VERSION
            or receipt["target"] != triple or receipt["asset_name"] != asset_name
            or receipt["asset_sha256"] != expected_asset_sha256
            or hashlib.sha256(payload).hexdigest() != expected_asset_sha256
            or hashlib.sha256(binary).hexdigest() != receipt["executable_sha256"]
            or _archive_binary(payload, system, asset_name) != binary):
        _refuse()
    _version_output(executable, runner)
    return receipt


def advisory_database_path(cargo_home):
    return Path(cargo_home) / "advisory-dbs" / RUSTSEC_ADVISORY_DATABASE_ID


def _git(git, arguments, cwd=None):
    try:
        result = subprocess.run(
            [git, *arguments], cwd=cwd, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60,
            env={"PATH": os.environ.get("PATH", ""), "LANG": "C", "LC_ALL": "C"}, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        _refuse()
    if result.returncode != 0 or len(result.stdout) > 4096:
        _refuse()
    try:
        return result.stdout.decode("ascii", "strict").strip()
    except UnicodeDecodeError:
        _refuse()


def verify_advisory_database(path, *, git=None, now=None):
    path = Path(path)
    git_executable = git or shutil.which("git")
    if not git_executable or not path.is_dir() or path.is_symlink():
        _refuse()
    origin = _git(git_executable, ("remote", "get-url", "origin"), cwd=path)
    commit = _git(git_executable, ("rev-parse", "--verify", "HEAD"), cwd=path)
    generated = _git(git_executable, ("show", "-s", "--format=%ct", "HEAD"), cwd=path)
    dirty = _git(git_executable, ("status", "--porcelain", "--untracked-files=all"), cwd=path)
    if (origin != RUSTSEC_ADVISORY_DATABASE_URL or len(commit) != 40
            or any(character not in "0123456789abcdef" for character in commit)
            or not generated.isdecimal() or dirty):
        _refuse()
    generated_epoch = int(generated)
    current_time = int(time.time()) if now is None else now
    age = current_time - generated_epoch
    if age < 0 or age > MAX_ADVISORY_AGE_SECONDS:
        _refuse()
    return commit, generated_epoch


def prepare_advisories(cargo_home, *, git=None):
    cargo_home = Path(cargo_home)
    database_path = advisory_database_path(cargo_home)
    if database_path.exists() or database_path.is_symlink():
        _refuse()
    database_path.parent.mkdir(parents=True, mode=0o700, exist_ok=True)
    git_executable = git or shutil.which("git")
    if not git_executable:
        _refuse()
    _git(git_executable, (
        "clone", "--depth=1", "--filter=blob:none", "--no-tags",
        RUSTSEC_ADVISORY_DATABASE_URL, str(database_path),
    ))
    verify_advisory_database(database_path, git=git_executable)
    return database_path


def _main(argv=None):
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    install_parser = commands.add_parser("install")
    install_parser.add_argument("--destination", required=True)
    advisory_parser = commands.add_parser("prepare-advisories")
    advisory_parser.add_argument("--cargo-home", required=True)
    arguments = parser.parse_args(argv)
    try:
        if arguments.command == "install":
            executable, receipt = install(arguments.destination)
            print("cargo_deny_path=" + str(executable))
            print("cargo_deny_receipt=" + str(receipt))
        else:
            print("advisory_database_path=" + str(prepare_advisories(arguments.cargo_home)))
    except CargoDenyInstallRefusal:
        print("cargo-deny setup refused")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
