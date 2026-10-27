"""Pinned source-free Rust toolchain smoke for macOS arm64."""

from dataclasses import dataclass
import hashlib
import importlib.util
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import platform
import posixpath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


SCHEMA_VERSION = 1
CONCERN = "rust-toolchain-smoke"
TOOLCHAIN_VERSION = "1.99.1"
TARGET = "aarch64-apple-darwin"
RELEASE_DATE = "2026-10-15"
OFFICIAL_MANIFEST_SHA256 = "fb152be80975c194aa5fc684b2aec3a6e14e2b855efe2faa4e5f8ae6e590f463"
MAX_CONTROL_BYTES = 40
MAX_RUN_ID_BYTES = 19
MAX_PATH_BYTES = 1024
MAX_ARCHIVE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_DOWNLOAD_BYTES = 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100_000
MAX_MEMBER_BYTES = 1024 * 1024 * 1024
MAX_UNPACKED_COMPONENT_BYTES = 4 * 1024 * 1024 * 1024
MAX_TOTAL_PREFIX_BYTES = 4 * 1024 * 1024 * 1024
MAX_CAPTURE_BYTES = 65_536
MAX_DOWNLOAD_SECONDS = 120
MAX_INSTALL_SECONDS = 240
MAX_TOOL_SECONDS = 120
MAX_TOTAL_SECONDS = 15 * 60
REPORT_NAME = "rust-toolchain-smoke.json"
TEMP_ROOT = Path(chr(47) + "private" + chr(47) + "tmp")
TEMP_PREFIX = "rust-toolchain-smoke-"
WORKER_TRAVERSAL_MODE = 0o711
GH_RUN_VALUE_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
SHA256_RE = re.compile(r"[a-f0-9]{64}\Z")
SHA1_RE = re.compile(r"[a-f0-9]{40}\Z")
SAFE_COMPONENT_RE = re.compile(r"[a-z0-9-]+\Z")
ALLOWED_REDIRECT_HOSTS = frozenset(("static.rust-lang.org", "static-rust-lang-org.s3.amazonaws.com"))
ALLOWED_PAX_KEYS = frozenset((
    "path", "linkpath", "size", "mtime", "atime", "ctime", "uid", "gid",
    "uname", "gname", "hdrcharset",
))
REASONS = frozenset((
    "invalid_input", "unsupported_host", "runner_unavailable", "download_unavailable",
    "archive_hash_mismatch", "archive_invalid", "install_failed", "version_mismatch",
    "target_unavailable", "smoke_failed", "capture_invalid", "cleanup_incomplete",
    "internal_error",
))


@dataclass(frozen=True)
class Component:
    name: str
    archive_root: str
    url: str
    sha256: str
    version: str


COMPONENTS = (
    Component(
        "rustc", "rustc-1.99.1-aarch64-apple-darwin",
        "https://static.rust-lang.org/dist/2026-10-15/rustc-1.99.1-aarch64-apple-darwin.tar.xz",
        "23948a0a9c162fd2952defb3fb0462c44e8fcfd1a4ab8a274a1e1bdb2cf810a3",
        "1.99.1 (58cf8f9c3 2026-10-13)",
    ),
    Component(
        "rust-std", "rust-std-1.99.1-aarch64-apple-darwin",
        "https://static.rust-lang.org/dist/2026-10-15/rust-std-1.99.1-aarch64-apple-darwin.tar.xz",
        "fe79d6ab5a0321de26463999d8c112b8ad3eafbcbcf822d66a2300b45dde1031",
        "1.99.1 (58cf8f9c3 2026-10-13)",
    ),
    Component(
        "cargo", "cargo-1.99.1-aarch64-apple-darwin",
        "https://static.rust-lang.org/dist/2026-10-15/cargo-1.99.1-aarch64-apple-darwin.tar.xz",
        "685e563d94db1f003ffa5f5831439eec02569b9950b69867953c8213269c1eaf",
        "0.100.0 (5f94df478 2026-08-27)",
    ),
    Component(
        "rustfmt-preview", "rustfmt-1.99.1-aarch64-apple-darwin",
        "https://static.rust-lang.org/dist/2026-10-15/rustfmt-1.99.1-aarch64-apple-darwin.tar.xz",
        "8b80dda570f140ee9ced8799294e812bba847a025f185bae4cba85a2ba235570",
        "1.10.0",
    ),
    Component(
        "clippy-preview", "clippy-1.99.1-aarch64-apple-darwin",
        "https://static.rust-lang.org/dist/2026-10-15/clippy-1.99.1-aarch64-apple-darwin.tar.xz",
        "c463f31831196702fc544900a0dc4c1837905327507fbec751fe46e59ca098bf",
        "0.1.99",
    ),
)

EXPECTED_VERSIONS = {
    "rustc": "1.99.1 (58cf8f9c3 2026-10-13)",
    "rustfmt": "1.10.0",
    "clippy": "0.1.99",
}
CARGO_COMPONENT_VERSION = "0.100.0 (5f94df478 2026-08-27)"
CARGO_CLI_VERSION_RE = re.compile(
    r"cargo (?P<version>0\.100\.0|1\.99\.0|1\.99\.1) "
    r"\((?P<commit>[a-f0-9]{7,40}) (?P<date>[0-9]{4}-[0-9]{2}-[0-9]{2})\)\Z"
)

SYNTHETIC_CARGO_TOML = b'''[package]\nname = "rust-toolchain-smoke"\nversion = "0.0.0"\nedition = "2024"\n'''
SYNTHETIC_CARGO_LOCK = b'''version = 4\n\n[[package]]\nname = "rust-toolchain-smoke"\nversion = "0.0.0"\n'''
SYNTHETIC_LIB_RS = (
    b"pub fn smoke_value() -> u8 {\n    7\n}\n\n"
    + bytes((35, 91)) + b"cfg(test)]\nmod tests {\n    "
    + bytes((35, 91)) + b"test]\n    fn std_only_crate_runs_its_test() {\n"
    + b"        assert_eq!(super::smoke_value(), 7);\n    }\n}\n"
)


class Refusal(Exception):
    def __init__(self, reason):
        self.reason = reason if reason in REASONS else "internal_error"
        super().__init__(self.reason)


@dataclass(frozen=True)
class ToolchainPaths:
    root: Path
    prefix: Path
    rustc: Path
    cargo: Path
    rustfmt: Path
    cargo_fmt: Path
    cargo_clippy: Path
    clippy_driver: Path
    host: str
    rustc_version: str
    cargo_version: str
    rustfmt_version: str
    clippy_version: str
    component_hashes: tuple[tuple[str, str], ...]

    def __post_init__(self):
        paths = (self.root, self.prefix, self.rustc, self.cargo, self.rustfmt,
                 self.cargo_fmt, self.cargo_clippy, self.clippy_driver)
        if (any(not isinstance(path, Path) or not path.is_absolute()
                or len(os.fsencode(path)) > MAX_PATH_BYTES
                or any(character in str(path) for character in ("\n", "\r", "\x00"))
                for path in paths)
                or self.prefix.parent != self.root
                or any(self.prefix not in path.parents for path in paths[2:])
                or self.host != TARGET
                or any(type(value) is not str or not value.isascii() or len(value) > 128
                       for value in (self.rustc_version, self.cargo_version,
                                     self.rustfmt_version, self.clippy_version))
                or self.rustc_version != EXPECTED_VERSIONS["rustc"]
                or self.cargo_version not in ("0.100.0", "1.99.0", "1.99.1")
                or self.rustfmt_version != EXPECTED_VERSIONS["rustfmt"]
                or self.clippy_version != EXPECTED_VERSIONS["clippy"]
                or self.component_hashes != tuple((component.name, component.sha256)
                                                  for component in COMPONENTS)):
            raise Refusal("internal_error")

    def command_paths(self):
        return {
            "rustc": self.rustc,
            "cargo": self.cargo,
            "rustfmt": self.rustfmt,
            "cargo_fmt": self.cargo_fmt,
            "cargo_clippy": self.cargo_clippy,
            "clippy_driver": self.clippy_driver,
        }


def _load_control_sibling(module_name):
    if module_name not in ("macos_capability", "macos_reviewed_build"):
        raise ImportError
    directory = Path(__file__).resolve(strict=True).parent
    path = (directory / (module_name + ".py")).resolve(strict=True)
    if path.parent != directory or not path.is_file():
        raise ImportError
    loaded = sys.modules.get(module_name)
    if loaded is not None and getattr(loaded, "__file__", None):
        try:
            if Path(loaded.__file__).resolve(strict=True) == path:
                return loaded
        except OSError:
            pass
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    return module


def valid_control_sha(value):
    return type(value) is str and len(value) == MAX_CONTROL_BYTES and SHA1_RE.fullmatch(value) is not None


def _strict_context(environ, control_sha):
    if not valid_control_sha(control_sha):
        raise Refusal("invalid_input")
    if type(environ) is not dict:
        raise Refusal("invalid_input")
    run_id = environ.get("GITHUB_RUN_ID")
    run_attempt = environ.get("GITHUB_RUN_ATTEMPT")
    runner_temp = environ.get("RUNNER_TEMP")
    if (type(run_id) is not str or len(run_id) > MAX_RUN_ID_BYTES or GH_RUN_VALUE_RE.fullmatch(run_id) is None
            or type(run_attempt) is not str or len(run_attempt) > MAX_RUN_ID_BYTES
            or GH_RUN_VALUE_RE.fullmatch(run_attempt) is None
            or type(runner_temp) is not str or not runner_temp or len(os.fsencode(runner_temp)) > MAX_PATH_BYTES
            or "\n" in runner_temp or "\r" in runner_temp or "\x00" in runner_temp):
        raise Refusal("invalid_input")
    path = Path(runner_temp)
    try:
        canonical = path.resolve(strict=True)
        info = path.lstat()
    except BaseException:
        raise Refusal("runner_unavailable") from None
    if (not path.is_absolute() or canonical != path or stat.S_ISLNK(info.st_mode)
            or not stat.S_ISDIR(info.st_mode) or info.st_uid == 0):
        raise Refusal("runner_unavailable")
    return run_id, run_attempt, path


def _check_host():
    if (sys.platform != "darwin" or platform.system() != "Darwin"
            or platform.machine() not in ("arm64", "aarch64") or os.geteuid() != 0):
        raise Refusal("unsupported_host")


def _check_temp_root():
    try:
        info = TEMP_ROOT.lstat()
    except BaseException:
        raise Refusal("runner_unavailable") from None
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o1777):
        raise Refusal("runner_unavailable")


def _worker_traversal_root_is_safe(info, worker_uid):
    return (
        type(worker_uid) is int and 0 < worker_uid < 60000
        and type(info.st_uid) is int and info.st_uid == 0 and info.st_uid != worker_uid
        and stat.S_ISDIR(info.st_mode)
        and stat.S_IMODE(info.st_mode) == WORKER_TRAVERSAL_MODE
    )


def _verify_worker_traversal_root(path, worker_uid):
    try:
        info = Path(path).lstat()
    except BaseException:
        raise Refusal("runner_unavailable") from None
    if not _worker_traversal_root_is_safe(info, worker_uid):
        raise Refusal("runner_unavailable")


def _bounded_timeout(deadline, maximum):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise Refusal("smoke_failed")
    return min(float(maximum), remaining)


def _check_deadline(deadline):
    if time.monotonic() >= deadline:
        raise Refusal("smoke_failed")


def _valid_component(component):
    if type(component) is not Component:
        return False
    parsed = urllib.parse.urlsplit(component.url)
    return (
        SAFE_COMPONENT_RE.fullmatch(component.name) is not None
        and SAFE_COMPONENT_RE.fullmatch(component.archive_root.replace("-1.99.1-aarch64-apple-darwin", "")) is not None
        and parsed.scheme == "https"
        and parsed.hostname == "static.rust-lang.org"
        and parsed.port in (None, 443)
        and parsed.username is None and parsed.password is None
        and parsed.path == "/dist/" + RELEASE_DATE + "/" + Path(component.url).name
        and parsed.query == "" and parsed.fragment == ""
        and SHA256_RE.fullmatch(component.sha256) is not None
    )


class _PinnedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self):
        super().__init__()
        self.redirects = 0

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        old = urllib.parse.urlsplit(request.full_url)
        new = urllib.parse.urlsplit(new_url)
        self.redirects += 1
        if (self.redirects > 2 or new.scheme != "https"
                or (new.hostname or "").lower() not in ALLOWED_REDIRECT_HOSTS
                or new.port not in (None, 443) or new.username is not None or new.password is not None
                or new.query != old.query or new.path != old.path or new.fragment != ""):
            raise urllib.error.HTTPError(request.full_url, code, "redirect refused", headers, file_pointer)
        return super().redirect_request(request, file_pointer, code, message, headers, new_url)


def _download_component(component, destination, deadline):
    if not _valid_component(component):
        raise Refusal("invalid_input")
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise Refusal("runner_unavailable")
    download_deadline = min(deadline, time.monotonic() + MAX_DOWNLOAD_SECONDS)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _PinnedRedirect())
    descriptor = None
    created = False
    created_identity = None
    digest = hashlib.sha256()
    total = 0
    try:
        request = urllib.request.Request(component.url, headers={"Accept": "application/x-xz"}, method="GET")
        with opener.open(request, timeout=_bounded_timeout(download_deadline, MAX_DOWNLOAD_SECONDS)) as response:
            final = urllib.parse.urlsplit(response.geturl())
            if ((final.hostname or "").lower() not in ALLOWED_REDIRECT_HOSTS or final.scheme != "https"
                    or final.port not in (None, 443) or final.path != urllib.parse.urlsplit(component.url).path
                    or final.query or final.fragment):
                raise Refusal("download_unavailable")
            length = response.headers.get("Content-Length")
            if length is not None and (re.fullmatch(r"[0-9]{1,10}", length) is None
                                       or int(length) > MAX_ARCHIVE_BYTES):
                raise Refusal("archive_invalid")
            descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
            created = True
            opened_info = os.fstat(descriptor)
            created_identity = (opened_info.st_dev, opened_info.st_ino)
            while True:
                _check_deadline(download_deadline)
                chunk = response.read(64 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_ARCHIVE_BYTES:
                    raise Refusal("archive_invalid")
                digest.update(chunk)
                view = memoryview(chunk)
                while view:
                    written = os.write(descriptor, view)
                    if written <= 0:
                        raise OSError
                    view = view[written:]
            if length is not None and total != int(length):
                raise Refusal("download_unavailable")
            if total <= 0:
                raise Refusal("download_unavailable")
            if digest.hexdigest() != component.sha256:
                raise Refusal("archive_hash_mismatch")
            os.fchown(descriptor, 0, 0)
            os.fchmod(descriptor, 0o400)
            os.fsync(descriptor)
            os.close(descriptor)
            descriptor = None
        info = destination.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o400 or info.st_size != total):
            raise Refusal("runner_unavailable")
        return total
    except Refusal:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            try:
                info = destination.lstat()
                if (stat.S_ISREG(info.st_mode) and info.st_uid == 0
                        and (info.st_dev, info.st_ino) == created_identity):
                    destination.unlink()
            except OSError:
                pass
        raise
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if created:
            try:
                info = destination.lstat()
                if (stat.S_ISREG(info.st_mode) and info.st_uid == 0
                        and (info.st_dev, info.st_ino) == created_identity):
                    destination.unlink()
            except OSError:
                pass
        raise Refusal("download_unavailable") from None


def _safe_archive_name(value):
    if (type(value) is not str or not value or "\x00" in value or "\\" in value
            or not value.isascii() or len(value) > 4096):
        return None
    path = PurePosixPath(value)
    normalized = path.as_posix()
    if value.endswith("/"):
        value = value[:-1]
    if (path.is_absolute() or not path.parts or normalized != value
            or any(part in ("", ".", "..") for part in path.parts)):
        return None
    return normalized


def _safe_link_target(member_name, target, root, *, hardlink=False):
    if (type(target) is not str or not target or "\x00" in target or "\\" in target
            or not target.isascii() or len(target) > 4096):
        return False
    path = PurePosixPath(target)
    if path.is_absolute():
        return False
    if hardlink:
        resolved = posixpath.normpath(target)
    else:
        resolved = posixpath.normpath(posixpath.join(posixpath.dirname(member_name), target))
    return resolved == root or resolved.startswith(root + "/")


def _safe_pax_headers(member):
    headers = member.pax_headers
    if type(headers) is not dict or len(headers) > 16:
        return False
    for key, value in headers.items():
        if (type(key) is not str or key not in ALLOWED_PAX_KEYS or type(value) is not str
                or not key.isascii() or not value.isascii() or len(value) > 4096
                or "\x00" in value):
            return False
        if key in ("path", "linkpath"):
            if (key == "path" and _safe_archive_name(value) != member.name.rstrip("/")):
                return False
            if key == "linkpath" and value != member.linkname:
                return False
        elif key in ("uid", "gid", "size"):
            if re.fullmatch(r"[0-9]{1,12}", value) is None:
                return False
        elif key in ("mtime", "atime", "ctime"):
            if re.fullmatch(r"-?(?:0|[1-9][0-9]{0,11})(?:\.[0-9]{1,9})?", value) is None:
                return False
        elif key in ("uname", "gname"):
            if re.fullmatch(r"[A-Za-z0-9._-]{0,64}", value) is None:
                return False
        elif key == "hdrcharset" and value not in ("BINARY", "UTF-8"):
            return False
    return True


def _inspect_archive(path, component, deadline):
    if not _valid_component(component):
        raise Refusal("invalid_input")
    try:
        info = path.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o400 or not 0 < info.st_size <= MAX_ARCHIVE_BYTES):
            raise Refusal("archive_invalid")
        with path.open("rb") as raw:
            digest = hashlib.sha256()
            while True:
                _check_deadline(deadline)
                chunk = raw.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        if digest.hexdigest() != component.sha256:
            raise Refusal("archive_hash_mismatch")
        members = []
        seen = set()
        member_types = {}
        total = 0
        with tarfile.open(path, mode="r:xz") as archive:
            if archive.pax_headers:
                raise Refusal("archive_invalid")
            for member in archive:
                _check_deadline(deadline)
                if len(members) >= MAX_ARCHIVE_MEMBERS or not _safe_pax_headers(member):
                    raise Refusal("archive_invalid")
                name = _safe_archive_name(member.name)
                if (name is None or name in seen
                        or (name != component.archive_root
                            and not name.startswith(component.archive_root + "/"))):
                    raise Refusal("archive_invalid")
                if (not (member.isdir() or member.isreg() or member.issym() or member.islnk())
                        or member.isdev() or member.isfifo() or member.sparse is not None
                        or member.mode & (stat.S_ISUID | stat.S_ISGID)):
                    raise Refusal("archive_invalid")
                if member.isdir() and member.size != 0:
                    raise Refusal("archive_invalid")
                if member.issym() and (member.size != 0 or not _safe_link_target(
                        name, member.linkname, component.archive_root)):
                    raise Refusal("archive_invalid")
                if member.islnk() and (member.size != 0 or not _safe_link_target(
                        name, member.linkname, component.archive_root, hardlink=True)):
                    raise Refusal("archive_invalid")
                if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                    raise Refusal("archive_invalid")
                total += member.size
                if total > MAX_UNPACKED_COMPONENT_BYTES:
                    raise Refusal("archive_invalid")
                seen.add(name)
                member_types[name] = "directory" if member.isdir() else "file" if member.isreg() else "link"
                if member.isreg():
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise Refusal("archive_invalid")
                    read_total = 0
                    with stream:
                        while True:
                            _check_deadline(deadline)
                            chunk = stream.read(64 * 1024)
                            if not chunk:
                                break
                            read_total += len(chunk)
                            if read_total > member.size:
                                raise Refusal("archive_invalid")
                    if read_total != member.size:
                        raise Refusal("archive_invalid")
                members.append(member)
        if not members:
            raise Refusal("archive_invalid")
        for name, kind in member_types.items():
            parts = PurePosixPath(name).parts
            for index in range(1, len(parts)):
                parent = "/".join(parts[:index])
                if member_types.get(parent) in ("file", "link"):
                    raise Refusal("archive_invalid")
            if name == component.archive_root and kind != "directory":
                raise Refusal("archive_invalid")
            if kind == "link" and name in member_types and any(
                    name == "/".join(PurePosixPath(other).parts[:i])
                    for other in member_types if other != name
                    for i in range(1, len(PurePosixPath(other).parts))):
                raise Refusal("archive_invalid")
        for member in members:
            if member.islnk():
                target = _safe_archive_name(member.linkname)
                if target is None or member_types.get(target) != "file":
                    raise Refusal("archive_invalid")
        return tuple(members)
    except Refusal:
        raise
    except BaseException:
        raise Refusal("archive_invalid") from None


def _ensure_safe_parent(path, stop):
    path = Path(path)
    stop = Path(stop)
    try:
        relative = path.relative_to(stop)
    except ValueError:
        raise Refusal("archive_invalid") from None
    current = stop
    for part in relative.parts:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            os.mkdir(current, 0o700)
            info = current.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
            raise Refusal("archive_invalid")


def _extract_component(archive_path, component, destination, members, deadline):
    destination = Path(destination)
    package_root = destination / component.archive_root
    try:
        info = destination.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
            raise Refusal("runner_unavailable")
        os.mkdir(package_root, 0o700)
        directories = {component.archive_root}
        regular = []
        hardlinks = []
        symlinks = []
        for member in members:
            name = _safe_archive_name(member.name)
            if name is None:
                raise Refusal("archive_invalid")
            if member.isdir():
                directories.add(name)
            elif member.isreg():
                regular.append((member, name))
            elif member.islnk():
                hardlinks.append((member, name))
            else:
                symlinks.append((member, name))
            parts = PurePosixPath(name).parts
            directories.update("/".join(parts[:index]) for index in range(1, len(parts)))
        for name in sorted(directories, key=lambda value: (value.count("/"), value)):
            _check_deadline(deadline)
            if name == component.archive_root:
                continue
            path = destination.joinpath(*PurePosixPath(name).parts)
            _ensure_safe_parent(path.parent, destination)
            try:
                os.mkdir(path, 0o700)
            except FileExistsError:
                pass
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_ISLNK(info.st_mode):
                raise Refusal("archive_invalid")
            os.chmod(path, 0o555)
        with tarfile.open(archive_path, mode="r:xz") as archive:
            for member, name in regular:
                _check_deadline(deadline)
                path = destination.joinpath(*PurePosixPath(name).parts)
                _ensure_safe_parent(path.parent, destination)
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
                descriptor = os.open(path, flags, 0o400)
                try:
                    os.fchown(descriptor, 0, 0)
                    mode = (member.mode & 0o555) or 0o400
                    os.fchmod(descriptor, mode)
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise Refusal("archive_invalid")
                    remaining = member.size
                    with stream:
                        while remaining:
                            _check_deadline(deadline)
                            chunk = stream.read(min(64 * 1024, remaining))
                            if not chunk:
                                raise Refusal("archive_invalid")
                            view = memoryview(chunk)
                            while view:
                                written = os.write(descriptor, view)
                                if written <= 0:
                                    raise Refusal("archive_invalid")
                                view = view[written:]
                            remaining -= len(chunk)
                        if stream.read(1):
                            raise Refusal("archive_invalid")
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
        for member, name in hardlinks:
            _check_deadline(deadline)
            target = destination.joinpath(*PurePosixPath(member.linkname).parts)
            path = destination.joinpath(*PurePosixPath(name).parts)
            _ensure_safe_parent(path.parent, destination)
            target_info = target.lstat()
            if not stat.S_ISREG(target_info.st_mode) or target_info.st_uid != 0:
                raise Refusal("archive_invalid")
            os.link(target, path, follow_symlinks=False)
        for member, name in symlinks:
            _check_deadline(deadline)
            path = destination.joinpath(*PurePosixPath(name).parts)
            _ensure_safe_parent(path.parent, destination)
            os.symlink(member.linkname, path)
            os.chown(path, 0, 0, follow_symlinks=False)
        for member in members:
            _check_deadline(deadline)
            name = _safe_archive_name(member.name)
            path = destination.joinpath(*PurePosixPath(name).parts)
            info = path.lstat()
            if info.st_uid != 0:
                raise Refusal("archive_invalid")
            if member.isdir() and stat.S_IMODE(info.st_mode) & 0o022:
                raise Refusal("archive_invalid")
        return package_root
    except Refusal:
        raise
    except BaseException:
        raise Refusal("archive_invalid") from None


def _bounded_root_command(argv, cwd, env, capability, timeout):
    process = None
    captures = []
    try:
        process = subprocess.Popen(
            [str(value) for value in argv], cwd=str(cwd), env=env,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            close_fds=True, start_new_session=True,
        )
        captures = [capability._Capture(process.stdout), capability._Capture(process.stderr)]
        for capture in captures:
            capture.start()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            pass
        stopped = capability._terminate_probe_tree(process)
        joined_flags = []
        for capture in captures:
            joined_flags.append(capture.join())
        joined = all(joined_flags)
        if (not stopped or not joined or any(capture.overflow for capture in captures)
                or process.returncode is None):
            raise Refusal("cleanup_incomplete")
        stdout, stderr = (bytes(capture.data) for capture in captures)
        if process.returncode != 0 or len(stdout) > MAX_CAPTURE_BYTES or len(stderr) > MAX_CAPTURE_BYTES:
            raise Refusal("install_failed")
        return stdout, stderr
    except Refusal:
        if process is not None and process.poll() is None:
            try:
                capability._terminate_probe_tree(process)
            except BaseException:
                raise Refusal("cleanup_incomplete") from None
        raise
    except BaseException:
        if process is not None and process.poll() is None:
            try:
                capability._terminate_probe_tree(process)
            except BaseException:
                raise Refusal("cleanup_incomplete") from None
        raise Refusal("install_failed") from None


def _run_installer(package_root, prefix, temp_root, capability, deadline):
    installer = package_root / "install.sh"
    try:
        info = installer.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or not info.st_mode & 0o111 or info.st_mode & 0o022):
            raise Refusal("archive_invalid")
    except Refusal:
        raise
    except BaseException:
        raise Refusal("archive_invalid") from None
    env = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": "/var/empty",
        "TMPDIR": str(temp_root),
        "LANG": "C",
        "LC_ALL": "C",
    }
    _bounded_root_command(
        (installer, "--prefix=" + str(prefix), "--disable-ldconfig"),
        package_root,
        env,
        capability,
        _bounded_timeout(deadline, MAX_INSTALL_SECONDS),
    )


def _check_installed_tree(prefix, deadline):
    total = 0
    try:
        if prefix.resolve(strict=True) != prefix:
            raise ValueError
        for current, directories, files in os.walk(prefix, topdown=True, followlinks=False):
            _check_deadline(deadline)
            current_path = Path(current)
            current_info = current_path.lstat()
            if (not stat.S_ISDIR(current_info.st_mode) or current_info.st_uid != 0
                    or current_info.st_mode & 0o022):
                raise ValueError
            for name in list(directories) + files:
                path = current_path / name
                info = path.lstat()
                if info.st_uid != 0:
                    raise ValueError
                if stat.S_ISLNK(info.st_mode):
                    resolved = path.resolve(strict=True)
                    if prefix not in resolved.parents:
                        raise ValueError
                    if name in directories:
                        directories.remove(name)
                elif stat.S_ISDIR(info.st_mode):
                    if name not in directories or info.st_mode & 0o022:
                        raise ValueError
                elif stat.S_ISREG(info.st_mode):
                    if info.st_mode & 0o022:
                        raise ValueError
                    total += info.st_size
                    if info.st_nlink < 1 or total > MAX_TOTAL_PREFIX_BYTES:
                        raise ValueError
                else:
                    raise ValueError
        return total
    except Refusal:
        raise
    except BaseException:
        raise Refusal("install_failed") from None


def _required_tool_path(prefix, name):
    path = prefix / "bin" / name
    try:
        info = path.lstat()
        resolved = path.resolve(strict=True)
        if (not stat.S_ISREG(resolved.stat().st_mode) or resolved.stat().st_uid != 0
                or resolved.stat().st_mode & 0o022 or not os.access(resolved, os.X_OK)
                or prefix not in resolved.parents or (stat.S_ISLNK(info.st_mode) and prefix not in resolved.parents)):
            raise ValueError
        return path
    except BaseException:
        raise Refusal("install_failed") from None


def _install_pinned_toolchain(root, capability, deadline):
    prefix = root / "toolchain"
    staging = root / "staging"
    temp_root = root / "tmp"
    for directory, mode in ((prefix, 0o755), (staging, 0o700), (temp_root, 0o700)):
        os.mkdir(directory, mode)
        os.chown(directory, 0, 0)
        os.chmod(directory, mode)
    total_download = 0
    for index, component in enumerate(COMPONENTS):
        _check_deadline(deadline)
        archive = root / ("component-" + str(index) + ".tar.xz")
        try:
            total_download += _download_component(component, archive, deadline)
            if total_download > MAX_TOTAL_DOWNLOAD_BYTES:
                raise Refusal("archive_invalid")
            members = _inspect_archive(archive, component, deadline)
            package_root = _extract_component(archive, component, staging, members, deadline)
            _run_installer(package_root, prefix, temp_root, capability, deadline)
            _check_installed_tree(prefix, deadline)
        finally:
            if archive.exists():
                archive.unlink()
            package_root_path = staging / component.archive_root
            if package_root_path.exists():
                capability._remove_probe_tree(package_root_path)
    _check_installed_tree(prefix, deadline)
    if not (prefix / "lib" / "rustlib" / TARGET / "lib").is_dir():
        raise Refusal("target_unavailable")
    tools = {
        "rustc": _required_tool_path(prefix, "rustc"),
        "cargo": _required_tool_path(prefix, "cargo"),
        "rustdoc": _required_tool_path(prefix, "rustdoc"),
        "rustfmt": _required_tool_path(prefix, "rustfmt"),
        "cargo_fmt": _required_tool_path(prefix, "cargo-fmt"),
        "cargo_clippy": _required_tool_path(prefix, "cargo-clippy"),
        "clippy_driver": _required_tool_path(prefix, "clippy-driver"),
    }
    return prefix, tools


def _prepare_worker_storage(root, uid, capability):
    storage = root / "worker-storage"
    try:
        os.mkdir(storage, 0o700)
        identity = capability._prepare_storage_directory(storage, uid)
        for name in ("crate", "crate/src", "cargo-home", "target", "tmp", "rustup-home"):
            path = storage / name
            os.mkdir(path, 0o700)
            os.chown(path, uid, capability.PROBE_PRIMARY_GID)
            os.chmod(path, 0o700)
        for name, payload in (
            ("crate/Cargo.toml", SYNTHETIC_CARGO_TOML),
            ("crate/Cargo.lock", SYNTHETIC_CARGO_LOCK),
            ("crate/src/lib.rs", SYNTHETIC_LIB_RS),
        ):
            path = storage / name
            nofollow = getattr(os, "O_NOFOLLOW", None)
            if nofollow is None:
                raise OSError
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
            try:
                os.fchown(descriptor, uid, capability.PROBE_PRIMARY_GID)
                os.fchmod(descriptor, 0o600)
                written = 0
                while written < len(payload):
                    count = os.write(descriptor, payload[written:])
                    if count <= 0:
                        raise OSError
                    written += count
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            info = path.lstat()
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != uid
                    or info.st_nlink != 1 or path.read_bytes() != payload):
                raise OSError
        return storage, identity
    except Refusal:
        raise
    except BaseException:
        raise Refusal("runner_unavailable") from None


def _worker_environment(home, storage, prefix, tools, host_toolchain, worker_tools, capability, reviewed):
    base = reviewed._child_environment(home, storage, host_toolchain, worker_tools)
    base.update({
        "CARGO_HOME": str(storage / "cargo-home"),
        "CARGO_TARGET_DIR": str(storage / "target"),
        "CARGO_NET_OFFLINE": "true",
        "CARGO_TERM_COLOR": "never",
        "CARGO_INCREMENTAL": "0",
        "RUSTC": str(tools["rustc"]),
        "RUSTDOC": str(prefix / "bin" / "rustdoc"),
        "RUSTUP_HOME": str(storage / "rustup-home"),
    })
    prefix_bin = str(prefix / "bin")
    if (not Path(prefix_bin).is_absolute() or any(character in prefix_bin for character in (":", "\n", "\x00"))
            or len(os.fsencode(prefix_bin + ":" + base["PATH"])) > capability.MAX_TOOL_PATH_BYTES):
        raise Refusal("runner_unavailable")
    base["PATH"] = prefix_bin + ":" + base["PATH"]
    return base


def _run_worker_command(
    argv, uid, env, python_executable, capability, *, stage, deadline, timeout=MAX_TOOL_SECONDS,
):
    try:
        result = capability._run_as_probe_user(
            argv,
            uid,
            env=env,
            timeout=_bounded_timeout(deadline, timeout),
            failure_reason="native_preflight_unavailable",
            failure_check="probe_process_toolchain",
            python_executable=python_executable,
        )
    except capability.ProbeFailure as error:
        if not error.cleanup_complete:
            raise Refusal("cleanup_incomplete") from None
        raise Refusal("smoke_failed" if stage == "smoke" else "version_mismatch") from None
    except Refusal:
        raise
    except BaseException:
        raise Refusal("capture_invalid") from None
    if (type(result.returncode) is not int or type(result.stdout) is not bytes or type(result.stderr) is not bytes
            or len(result.stdout) > MAX_CAPTURE_BYTES or len(result.stderr) > MAX_CAPTURE_BYTES):
        raise Refusal("capture_invalid")
    if result.returncode != 0:
        raise Refusal("smoke_failed" if stage == "smoke" else "version_mismatch")
    return result


def _decode_single_line(raw):
    if type(raw) is not bytes or len(raw) > MAX_CAPTURE_BYTES or not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        raise Refusal("capture_invalid")
    try:
        return raw[:-1].decode("ascii", "strict")
    except UnicodeDecodeError:
        raise Refusal("capture_invalid") from None


def _read_toolchain_versions(prefix, tools, uid, env, python_executable, capability, deadline):
    rustc = _run_worker_command(
        (tools["rustc"], "-Vv"), uid, env, python_executable, capability,
        stage="version", timeout=20, deadline=deadline,
    )
    try:
        lines = rustc.stdout.decode("ascii", "strict").splitlines()
    except UnicodeDecodeError:
        raise Refusal("capture_invalid") from None
    expected_rustc = "rustc " + EXPECTED_VERSIONS["rustc"]
    if expected_rustc not in lines or "host: " + TARGET not in lines or "release: " + TOOLCHAIN_VERSION not in lines:
        raise Refusal("version_mismatch")
    cargo = _run_worker_command(
        (tools["cargo"], "--version"), uid, env, python_executable, capability,
        stage="version", timeout=20, deadline=deadline,
    )
    cargo_version_line = _decode_single_line(cargo.stdout)
    cargo_match = CARGO_CLI_VERSION_RE.fullmatch(cargo_version_line)
    if (cargo_match is None
            or (cargo_match.group("version") == "0.100.0"
                and cargo_version_line != "cargo " + CARGO_COMPONENT_VERSION)):
        raise Refusal("version_mismatch")
    rustfmt = _run_worker_command(
        (tools["rustfmt"], "--version"), uid, env, python_executable, capability,
        stage="version", timeout=20, deadline=deadline,
    )
    rustfmt_version = _decode_single_line(rustfmt.stdout)
    if not re.fullmatch(r"rustfmt 1\.10\.0(?:-stable)?(?: \([a-f0-9]{7,40} [0-9]{4}-[0-9]{2}-[0-9]{2}\))?", rustfmt_version):
        raise Refusal("version_mismatch")
    clippy = _run_worker_command(
        (tools["cargo_clippy"], "--version"), uid, env, python_executable, capability,
        stage="version", timeout=20, deadline=deadline,
    )
    clippy_version = _decode_single_line(clippy.stdout)
    if not re.fullmatch(r"clippy 0\.1\.99(?: \([a-f0-9]{7,40} [0-9]{4}-[0-9]{2}-[0-9]{2}\))?", clippy_version):
        raise Refusal("version_mismatch")
    return {
        "rustc": EXPECTED_VERSIONS["rustc"],
        "cargo": cargo_match.group("version"),
        "rustfmt": EXPECTED_VERSIONS["rustfmt"],
        "clippy": EXPECTED_VERSIONS["clippy"],
    }


def _run_smoke(storage, prefix, tools, uid, env, python_executable, capability, reviewed, deadline):
    cargo = str(tools["cargo"])
    manifest = str(storage / "crate" / "Cargo.toml")
    commands = (
        ("fmt", (cargo, "--offline", "fmt", "--manifest-path", manifest, "--", "--check")),
        ("clippy", (cargo, "--offline", "clippy", "--manifest-path", manifest, "--target", TARGET,
                    "--all-targets", "--locked", "--", "-D", "warnings")),
        ("test", (cargo, "--offline", "test", "--manifest-path", manifest, "--target", TARGET,
                  "--all-targets", "--locked")),
    )
    for name, argv in commands:
        result = _run_worker_command(
            argv, uid, env, python_executable, capability, stage="smoke",
            timeout=MAX_TOOL_SECONDS, deadline=deadline,
        )
        if result.stderr and len(result.stderr) > MAX_CAPTURE_BYTES:
            raise Refusal("capture_invalid")
        try:
            reviewed._worker_census(uid, python_executable, name)
        except BaseException:
            raise Refusal("cleanup_incomplete") from None


def _validated_receipt(control_sha, run_id, run_attempt, versions):
    record = {
        "schema_version": SCHEMA_VERSION,
        "concern": CONCERN,
        "status": "passed",
        "control_sha": control_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "host": TARGET,
        "toolchain": TOOLCHAIN_VERSION,
        "components": {component.name: component.sha256 for component in COMPONENTS},
        "versions": dict(versions),
        "target": TARGET,
        "smoke": {"fmt": "passed", "clippy": "passed", "test": "passed"},
        "source": "none",
        "offline": True,
        "cleanup": "complete",
    }
    if (len(record) != 15 or not valid_control_sha(record["control_sha"])
            or GH_RUN_VALUE_RE.fullmatch(run_id) is None or GH_RUN_VALUE_RE.fullmatch(run_attempt) is None
            or set(record["components"]) != {component.name for component in COMPONENTS}
            or set(record["versions"]) != {"rustc", "cargo", "rustfmt", "clippy"}
            or record["versions"].get("rustc") != EXPECTED_VERSIONS["rustc"]
            or record["versions"].get("cargo") not in ("0.100.0", "1.99.0", "1.99.1")
            or record["versions"].get("rustfmt") != EXPECTED_VERSIONS["rustfmt"]
            or record["versions"].get("clippy") != EXPECTED_VERSIONS["clippy"]
            or set(record["smoke"]) != {"fmt", "clippy", "test"}):
        raise Refusal("internal_error")
    return record


def _receipt_bytes(record):
    try:
        payload = (json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")
    except BaseException:
        raise Refusal("internal_error") from None
    if len(payload) > 8192:
        raise Refusal("internal_error")
    return payload


def _write_receipt(runner_temp, payload):
    destination = runner_temp / REPORT_NAME
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None:
        raise Refusal("runner_unavailable")
    descriptor = None
    created = False
    created_identity = None
    try:
        descriptor = os.open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o400)
        created = True
        opened_info = os.fstat(descriptor)
        created_identity = (opened_info.st_dev, opened_info.st_ino)
        os.fchown(descriptor, 0, 0)
        os.fchmod(descriptor, 0o444)
        offset = 0
        while offset < len(payload):
            count = os.write(descriptor, payload[offset:])
            if count <= 0:
                raise OSError
            offset += count
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        info = destination.lstat()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o444 or info.st_size != len(payload)
                or destination.read_bytes() != payload):
            raise OSError
    except BaseException:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if created:
            try:
                info = destination.lstat()
                if (stat.S_ISREG(info.st_mode) and info.st_uid == 0
                        and (info.st_dev, info.st_ino) == created_identity):
                    destination.unlink()
            except OSError:
                pass
        raise Refusal("runner_unavailable") from None
    return destination


def _remove_tree(path, capability):
    if path is None:
        return
    try:
        capability._remove_probe_tree(path)
    except BaseException:
        raise Refusal("cleanup_incomplete") from None


def _execute(control_sha, environ):
    started = time.monotonic()
    deadline = started + MAX_TOTAL_SECONDS
    capability = None
    reviewed = None
    root = None
    uid = None
    home_parent = None
    storage = None
    worker_toolchain = None
    worker_tools = None
    toolchain_paths = None
    versions = None
    failure = None
    try:
        run_id, run_attempt, runner_temp = _strict_context(environ, control_sha)
        _check_host()
        _check_temp_root()
        try:
            capability = _load_control_sibling("macos_capability")
            reviewed = _load_control_sibling("macos_reviewed_build")
            worker_toolchain = capability._resolve_trusted_toolchain()
            worker_tools = capability._resolve_worker_tools(worker_toolchain)
        except BaseException:
            raise Refusal("runner_unavailable") from None
        root = Path(tempfile.mkdtemp(prefix=TEMP_PREFIX, dir=TEMP_ROOT))
        os.chown(root, 0, 0)
        os.chmod(root, WORKER_TRAVERSAL_MODE)
        root_info = root.lstat()
        if (not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != 0
                or stat.S_IMODE(root_info.st_mode) != WORKER_TRAVERSAL_MODE):
            raise Refusal("runner_unavailable")
        prefix, paths = _install_pinned_toolchain(root, capability, deadline)
        _check_installed_tree(prefix, deadline)
        try:
            uid, home_parent, home = capability._create_probe_identity(runner_temp)
        except capability.ProbeFailure as error:
            if not error.cleanup_complete:
                raise Refusal("cleanup_incomplete") from None
            raise Refusal("runner_unavailable") from None
        except BaseException:
            raise Refusal("runner_unavailable") from None
        _verify_worker_traversal_root(root, uid)
        storage, storage_identity = _prepare_worker_storage(root, uid, capability)
        if uid <= 0 or uid == os.stat(runner_temp).st_uid:
            raise Refusal("runner_unavailable")
        env = _worker_environment(
            home, storage, prefix, paths, worker_toolchain, worker_tools, capability, reviewed,
        )
        _check_installed_tree(prefix, deadline)
        versions = _read_toolchain_versions(
            prefix, paths, uid, env, worker_toolchain["python"], capability, deadline,
        )
        if (versions is None or versions.get("rustc") != EXPECTED_VERSIONS["rustc"]
                or versions.get("cargo") not in ("0.100.0", "1.99.0", "1.99.1")
                or versions.get("rustfmt") != EXPECTED_VERSIONS["rustfmt"]
                or versions.get("clippy") != EXPECTED_VERSIONS["clippy"]):
            raise Refusal("version_mismatch")
        if time.monotonic() - started > MAX_TOTAL_SECONDS:
            raise Refusal("smoke_failed")
        toolchain_paths = ToolchainPaths(
            root=root, prefix=prefix,
            rustc=paths["rustc"], cargo=paths["cargo"], rustfmt=paths["rustfmt"],
            cargo_fmt=paths["cargo_fmt"], cargo_clippy=paths["cargo_clippy"],
            clippy_driver=paths["clippy_driver"], host=TARGET,
            rustc_version=versions["rustc"], cargo_version=versions["cargo"],
            rustfmt_version=versions["rustfmt"], clippy_version=versions["clippy"],
            component_hashes=tuple((component.name, component.sha256) for component in COMPONENTS),
        )
        _run_smoke(
            storage, prefix, toolchain_paths.command_paths(), uid, env,
            worker_toolchain["python"], capability, reviewed, deadline,
        )
        capability._verify_storage_directory(storage, storage_identity, uid)
    except Refusal as error:
        failure = error
    except BaseException:
        failure = Refusal("internal_error")
    cleanup_failed = False
    if uid is not None and capability is not None:
        try:
            reviewed._cleanup((storage, home_parent), uid, worker_toolchain)
            uid = None
        except BaseException:
            cleanup_failed = True
    if not cleanup_failed:
        try:
            _remove_tree(root, capability)
        except BaseException:
            cleanup_failed = True
    if cleanup_failed:
        failure = Refusal("cleanup_incomplete")
    if failure is not None:
        raise failure
    if time.monotonic() - started > MAX_TOTAL_SECONDS:
        raise Refusal("smoke_failed")
    run_id, run_attempt, runner_temp = _strict_context(environ, control_sha)
    record = _validated_receipt(control_sha, run_id, run_attempt, versions)
    payload = _receipt_bytes(record)
    _write_receipt(runner_temp, payload)
    return payload[:-1]


def _parse_args(argv):
    if type(argv) is not list or len(argv) != 2 or argv[0] != "--control-sha" or not valid_control_sha(argv[1]):
        raise Refusal("invalid_input")
    return argv[1]


def main(argv=None, environ=None):
    try:
        control_sha = _parse_args(sys.argv[1:] if argv is None else argv)
        output = _execute(control_sha, dict(os.environ) if environ is None else environ)
        sys.stdout.write("KD-RUST-SMOKE " + output.decode("ascii") + "\n")
        return 0
    except Refusal as error:
        sys.stdout.write("KD-RUST-REFUSAL reason=" + error.reason + "\n")
        return 1
    except BaseException:
        sys.stdout.write("KD-RUST-REFUSAL reason=internal_error\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
