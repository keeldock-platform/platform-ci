"""Fetch and stage the fixed Rust supply-chain tools before the network cut."""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from contextlib import contextmanager
from contextlib import nullcontext
from pathlib import Path, PurePosixPath
from urllib.request import Request, urlopen


TOOLS = {
    "cargo-deny": (
        "https://github.com/EmbarkStudios/cargo-deny/releases/download/0.20.2/cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz",
        "9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f",
        "cargo-deny.tar.gz", "cargo-deny 0.20.2", "r:gz",
    ),
    "cargo-audit": (
        "https://github.com/RustSec/rustsec/releases/download/cargo-audit/v0.22.2/cargo-audit-x86_64-unknown-linux-gnu-v0.22.2.tgz",
        "ab28a1bdb54db4d5d8ad5981cf1f959410370b3d28250dbd35f6a44248620e39",
        "cargo-audit.tgz", "cargo-audit 0.22.2", "r:gz",
    ),
    "cargo-vet": (
        "https://github.com/mozilla/cargo-vet/releases/download/v0.10.3/cargo-vet-x86_64-unknown-linux-gnu.tar.xz",
        "e83878b80913fbe43629c28768e14ab51f4e86a4ba8f9dd08cc25b8dbc503c19",
        "cargo-vet.tar.xz", "cargo-vet 0.10.3", "r:xz",
    ),
}
ADVISORY_REPO = "https://github.com/RustSec/advisory-db.git"
MAX_ARCHIVE = 256 * 1024 * 1024
MAX_MEMBERS = 20_000
_DEADLINE_FILE = ""


class ToolingRefusal(ValueError):
    pass


def _remaining(cap):
    if not _DEADLINE_FILE:
        raise ToolingRefusal("deadline-file-required")
    from deadline import remaining
    return min(cap, remaining(_DEADLINE_FILE))


def _download(url, destination, expected_sha256):
    digest = hashlib.sha256()
    size = 0
    request = Request(url, headers={"User-Agent": "platform-ci-devlane/1"})
    with urlopen(request, timeout=_remaining(60)) as response, open(destination, "xb") as output:
        if response.status != 200:
            raise ToolingRefusal("tool-download-failed")
        while True:
            _remaining(60)
            chunk = response.read(64 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > MAX_ARCHIVE:
                raise ToolingRefusal("tool-archive-size")
            digest.update(chunk)
            output.write(chunk)
        output.flush()
        os.fsync(output.fileno())
    if size == 0 or digest.hexdigest() != expected_sha256:
        raise ToolingRefusal("tool-digest-mismatch")


def _safe_extract(archive_path, destination, mode):
    with tarfile.open(archive_path, mode) as archive:
        members = archive.getmembers()
        if not members or len(members) > MAX_MEMBERS:
            raise ToolingRefusal("tool-archive-members")
        for member in members:
            name = PurePosixPath(member.name)
            if (name.is_absolute() or not name.parts or ".." in name.parts
                    or member.issym() or member.islnk() or member.isdev() or member.isfifo()):
                raise ToolingRefusal("tool-archive-path")
        archive.extractall(destination, members=members, filter="data")


def _binary(root, name, version):
    candidates = [path for path in Path(root).rglob(name) if path.is_file() and not path.is_symlink()]
    if len(candidates) != 1:
        raise ToolingRefusal("tool-binary-missing")
    candidate = candidates[0]
    candidate.chmod(0o500)
    try:
        result = subprocess.run([str(candidate), "--version"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=_remaining(10),
                                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, check=False)
    except (OSError, subprocess.SubprocessError):
        raise ToolingRefusal("tool-version-unavailable") from None
    if result.returncode != 0 or result.stdout.decode("ascii", "strict").strip() != version:
        raise ToolingRefusal("tool-version-mismatch")
    return candidate


def _phase_context(phase_context, name):
    return phase_context(name) if phase_context is not None else nullcontext()


@contextmanager
def _staging_directory(phase_context):
    with _phase_context(phase_context, "tool-staging-create"):
        temporary = tempfile.TemporaryDirectory(prefix="devlane-rust-tools-")
    try:
        yield temporary.name
    except BaseException:
        try:
            temporary.cleanup()
        except BaseException:
            pass
        raise
    else:
        with _phase_context(phase_context, "tool-staging-cleanup"):
            temporary.cleanup()


def fetch_tools(output, deadline_file, *, phase_context=None):
    global _DEADLINE_FILE
    _DEADLINE_FILE = deadline_file
    with _phase_context(phase_context, "tool-fetch-setup"):
        if not _DEADLINE_FILE:
            raise ToolingRefusal("deadline-file-required")
        _remaining(60)
        output = Path(output)
        if output.exists() or output.is_symlink():
            raise ToolingRefusal("tool-output-exists")
        output.mkdir(mode=0o700, parents=True)
    with _staging_directory(phase_context) as temporary:
        temporary = Path(temporary)
        phase_names = {
            "cargo-deny": "tool-cargo-deny",
            "cargo-audit": "tool-cargo-audit",
            "cargo-vet": "tool-cargo-vet",
        }
        for name, (url, checksum, archive_name, version, mode) in TOOLS.items():
            prefix = phase_names[name]
            archive_path = temporary / archive_name
            with _phase_context(phase_context, prefix + "-download"):
                _download(url, archive_path, checksum)
            extract = temporary / (name + "-extract")
            with _phase_context(phase_context, prefix + "-extract"):
                extract.mkdir(mode=0o700)
                _safe_extract(archive_path, extract, mode)
            with _phase_context(phase_context, prefix + "-version"):
                binary = _binary(extract, name, version)
            with _phase_context(phase_context, prefix + "-copy"):
                shutil.copyfile(binary, output / name)
                (output / name).chmod(0o500)
        advisory = output / "advisory-db"
        with _phase_context(phase_context, "tool-advisory-clone"):
            result = subprocess.run(
                ["git", "clone", "--quiet", "--depth=1", "--filter=blob:none", "--", ADVISORY_REPO, str(advisory)],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=_remaining(180), env={"PATH": "/usr/bin:/bin", "GIT_TERMINAL_PROMPT": "0", "LC_ALL": "C"}, check=False,
            )
            if result.returncode != 0:
                raise ToolingRefusal("advisory-database-fetch-failed")
        with _phase_context(phase_context, "tool-advisory-revision"):
            commit = subprocess.run(["git", "-C", str(advisory), "rev-parse", "--verify", "HEAD"],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, timeout=_remaining(10), check=False)
            value = commit.stdout.decode("ascii", "strict").strip()
            if commit.returncode != 0 or len(value) != 40 or any(char not in "0123456789abcdef" for char in value):
                raise ToolingRefusal("advisory-database-revision")
            (output / "advisory-db-revision").write_text(value + "\n", encoding="ascii")
    with _phase_context(phase_context, "tool-fetch-finish"):
        print("rust_offline_tools=prepared")


def install(source, prepared, deadline_file):
    global _DEADLINE_FILE
    _DEADLINE_FILE = deadline_file
    if not _DEADLINE_FILE:
        raise ToolingRefusal("deadline-file-required")
    _remaining(60)
    source = Path(source).resolve(strict=True)
    prepared = Path(prepared).resolve(strict=True)
    if not source.is_dir() or not prepared.is_dir() or source.is_symlink() or prepared.is_symlink():
        raise ToolingRefusal("tool-tree-invalid")
    destination = prepared / "devlane-tools"
    if destination.exists() or destination.is_symlink():
        raise ToolingRefusal("tool-destination-exists")
    shutil.copytree(source, destination, symlinks=False)
    for name in TOOLS:
        path = destination / name
        if not path.is_file() or path.is_symlink():
            raise ToolingRefusal("tool-copy-invalid")
        path.chmod(0o555)
    for root, directories, files in os.walk(destination / "advisory-db", followlinks=False):
        for name in directories + files:
            path = Path(root) / name
            if path.is_symlink():
                raise ToolingRefusal("advisory-database-link")
            path.chmod(0o555 if path.is_dir() else 0o444)
    _remaining(60)
    print("rust_offline_tools=installed")


def main(argv=None):
    parser = argparse.ArgumentParser()
    subcommands = parser.add_subparsers(dest="operation", required=True)
    fetch_parser = subcommands.add_parser("fetch")
    fetch_parser.add_argument("--output", required=True)
    fetch_parser.add_argument("--deadline-file", required=True)
    install_parser = subcommands.add_parser("install")
    install_parser.add_argument("--source", required=True)
    install_parser.add_argument("--prepared", required=True)
    install_parser.add_argument("--deadline-file", required=True)
    args = parser.parse_args(argv)
    try:
        fetch_tools(args.output, args.deadline_file) if args.operation == "fetch" else install(
            args.source, args.prepared, args.deadline_file,
        )
        return 0
    except (ToolingRefusal, OSError, ValueError, tarfile.TarError, subprocess.SubprocessError, UnicodeError):
        print("rust_tooling_refusal=tooling-failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
