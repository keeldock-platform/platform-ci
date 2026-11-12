"""Acquire the fixed official Node archive before candidate code is available.

The entry point requires Linux root and a protected /run ancestry. It never runs
archive members. Version execution and the existing sealed snapshot remain separate.
An outer process watchdog is still required for blocking kernel/network operations.
"""
from __future__ import annotations

import hashlib
import math
import os
from pathlib import Path
import posixpath
import re
import stat
import sys
import tarfile
from dataclasses import dataclass
from urllib.request import Request, urlopen
from urllib.parse import urlsplit

NODE_VERSION = "24.22.1"
NPM_VERSION = "11.19.1"
ARCHIVE_PREFIX = "node-v24.22.1-linux-x64"
ARCHIVE_URL = "https://nodejs.org/dist/v24.22.1/node-v24.22.1-linux-x64.tar.xz"
ARCHIVE_SHA256 = "6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6"
PROTECTED_BASE = Path("/run/platform-ci-devlane/node-vendor")
PREPARATION_ID = "nodejs-dist-v24.22.1-linux-x64-sha256"
DESKTOP_NODE_VERSION = "26.8.1"
DESKTOP_NPM_VERSION = "11.19.0"
DESKTOP_ARCHIVE_PREFIX = "node-v26.8.1-linux-x64"
DESKTOP_ARCHIVE_URL = "https://nodejs.org/dist/v26.8.1/node-v26.8.1-linux-x64.tar.xz"
DESKTOP_ARCHIVE_SHA256 = "3e301118d7df53d563b7e96c1617545f26e2f76f9724be668d6cab65c15dda5d"
DESKTOP_PREPARATION_ID = "nodejs-dist-v26.8.1-linux-x64-sha256"
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 100_000
MAX_DEPTH = 64
CHUNK = 1024 * 1024
SESSION_ID = re.compile(r"[a-z0-9][a-z0-9_-]{7,63}\Z")
NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
DIRECTORY = getattr(os, "O_DIRECTORY", 0)
CLOEXEC = getattr(os, "O_CLOEXEC", 0)
NONBLOCK = getattr(os, "O_NONBLOCK", 0)


class VendorNodeRefusal(ValueError):
    """A fixed category without a path, payload or exception message."""


@dataclass(frozen=True)
class VendorSource:
    cache_root: Path
    node_root: Path
    node: Path
    npm: Path
    archive_sha256: str
    preparation_id: str
    node_version: str = NODE_VERSION
    npm_version: str = NPM_VERSION


def _fail(code):
    raise VendorNodeRefusal(code)


def _distribution(profile):
    if profile == "desktop":
        return {
            "node_version": DESKTOP_NODE_VERSION,
            "npm_version": DESKTOP_NPM_VERSION,
            "archive_prefix": DESKTOP_ARCHIVE_PREFIX,
            "archive_url": DESKTOP_ARCHIVE_URL,
            "archive_sha256": DESKTOP_ARCHIVE_SHA256,
            "preparation_id": DESKTOP_PREPARATION_ID,
        }
    if profile in (None, "core-node"):
        return {
            "node_version": NODE_VERSION,
            "npm_version": NPM_VERSION,
            "archive_prefix": ARCHIVE_PREFIX,
            "archive_url": ARCHIVE_URL,
            "archive_sha256": ARCHIVE_SHA256,
            "preparation_id": PREPARATION_ID,
        }
    _fail("vendor-node-profile")


def _tick(remaining):
    try:
        seconds = remaining()
        if type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds <= 0:
            _fail("vendor-node-deadline")
        return min(float(seconds), 30.0)
    except VendorNodeRefusal:
        raise
    except Exception:
        _fail("vendor-node-deadline")


def _directory(fd, owner_uid):
    value = os.fstat(fd)
    if (not stat.S_ISDIR(value.st_mode) or value.st_uid != owner_uid
            or stat.S_IMODE(value.st_mode) & 0o022):
        _fail("vendor-node-directory")
    return value


def _open_protected_base():
    current = os.open("/", os.O_RDONLY | DIRECTORY | NOFOLLOW | CLOEXEC)
    try:
        _directory(current, 0)
        for part in PROTECTED_BASE.parts[1:]:
            try:
                os.mkdir(part, 0o700, dir_fd=current)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | DIRECTORY | NOFOLLOW | CLOEXEC, dir_fd=current)
            try:
                _directory(child, 0)
            except BaseException:
                os.close(child)
                raise
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _download(path, remaining, profile=None):
    distribution = _distribution(profile)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW | CLOEXEC, 0o600)
    try:
        request = Request(distribution["archive_url"], headers={"User-Agent": "platform-ci-devlane/1"})
        with urlopen(request, timeout=_tick(remaining)) as response:
            final = urlsplit(response.geturl())
            if (response.status != 200 or final.scheme != "https" or final.hostname != "nodejs.org"
                    or final.username is not None or final.password is not None
                    or final.port not in (None, 443)):
                _fail("vendor-node-origin")
            size = 0
            while True:
                _tick(remaining)
                chunk = response.read(CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > MAX_ARCHIVE_BYTES:
                    _fail("vendor-node-archive-size")
                view = memoryview(chunk)
                while view:
                    _tick(remaining)
                    count = os.write(fd, view)
                    if count <= 0:
                        _fail("vendor-node-archive-write")
                    view = view[count:]
        _tick(remaining)
        os.fsync(fd)
    finally:
        os.close(fd)


def _verified_archive(path, remaining, owner_uid, profile=None):
    distribution = _distribution(profile)
    fd = os.open(path, os.O_RDONLY | NOFOLLOW | NONBLOCK | CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != owner_uid or before.st_nlink != 1
                or before.st_mode & 0o022 or not 0 < before.st_size <= MAX_ARCHIVE_BYTES):
            _fail("vendor-node-archive-type")
        digest = hashlib.sha256()
        size = 0
        while True:
            _tick(remaining)
            chunk = os.read(fd, CHUNK)
            if not chunk:
                break
            digest.update(chunk)
            size += len(chunk)
            if size > MAX_ARCHIVE_BYTES:
                _fail("vendor-node-archive-size")
        after = os.fstat(fd)
        token = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
        if (size != before.st_size or token(before) != token(after)
                or digest.hexdigest() != distribution["archive_sha256"]):
            _fail("vendor-node-checksum")
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def _parts(member, archive_prefix=ARCHIVE_PREFIX):
    name = member.name.rstrip("/") if member.isdir() else member.name
    parts = name.split("/")
    if (len(name.encode("utf-8")) > 2048 or len(parts) > MAX_DEPTH
            or not parts or parts[0] != archive_prefix
            or any(part in ("", ".", "..") or "\\" in part or "\x00" in part for part in parts)):
        _fail("vendor-node-member-path")
    if len(parts) == 1 and not member.isdir():
        _fail("vendor-node-member-path")
    return parts[1:]


def _parents(root_fd, parts, owner_uid):
    current = os.dup(root_fd)
    try:
        _directory(current, owner_uid)
        for part in parts:
            try:
                os.mkdir(part, 0o700, dir_fd=current)
            except FileExistsError:
                pass
            child = os.open(part, os.O_RDONLY | DIRECTORY | NOFOLLOW | CLOEXEC, dir_fd=current)
            try:
                _directory(child, owner_uid)
            except BaseException:
                os.close(child)
                raise
            os.close(current)
            current = child
        return current
    except BaseException:
        os.close(current)
        raise


def _file(archive, member, parent_fd, name, remaining):
    source = archive.extractfile(member)
    if source is None:
        _fail("vendor-node-member-read")
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | NOFOLLOW | NONBLOCK | CLOEXEC,
                 0o600, dir_fd=parent_fd)
    try:
        left = member.size
        with source:
            while left:
                _tick(remaining)
                chunk = source.read(min(CHUNK, left))
                if not chunk:
                    _fail("vendor-node-member-size")
                left -= len(chunk)
                view = memoryview(chunk)
                while view:
                    _tick(remaining)
                    count = os.write(fd, view)
                    if count <= 0:
                        _fail("vendor-node-member-write")
                    view = view[count:]
        os.fchmod(fd, 0o555 if member.mode & 0o111 else 0o444)
    finally:
        os.close(fd)


def _link_target(parts, target):
    if (type(target) is not str or not target or target.startswith("/")
            or "\\" in target or "\x00" in target or len(target.encode("utf-8")) > 4096):
        _fail("vendor-node-link")
    normalized = posixpath.normpath(posixpath.join(*parts[:-1], target))
    if normalized in (".", "..") or normalized.startswith("../"):
        _fail("vendor-node-link")


def _finish_links(root, root_fd, links, remaining, owner_uid):
    for parts, target in links:
        _tick(remaining)
        parent = _parents(root_fd, parts[:-1], owner_uid)
        try:
            os.symlink(target, parts[-1], dir_fd=parent)
        finally:
            os.close(parent)
    for parts, _target in links:
        _tick(remaining)
        try:
            resolved = root.joinpath(*parts).resolve(strict=True)
            if not resolved.is_relative_to(root) or not (resolved.is_file() or resolved.is_dir()):
                _fail("vendor-node-link")
        except (OSError, RuntimeError):
            _fail("vendor-node-link")


def _extract(fd, root, remaining, owner_uid, profile=None):
    archive_prefix = _distribution(profile)["archive_prefix"]
    root.mkdir(mode=0o700)
    root_fd = os.open(root, os.O_RDONLY | DIRECTORY | NOFOLLOW | CLOEXEC)
    seen = set()
    links = []
    total = 0
    try:
        with os.fdopen(os.dup(fd), "rb") as source, tarfile.open(fileobj=source, mode="r:xz") as archive:
            for member in archive:
                _tick(remaining)
                parts = _parts(member, archive_prefix)
                key = "/".join(parts)
                if key in seen or len(seen) >= MAX_ENTRIES:
                    _fail("vendor-node-member-count")
                seen.add(key)
                if not parts:
                    continue
                if not (member.isdir() or member.isfile() or member.issym()):
                    _fail("vendor-node-member-type")
                if member.size < 0 or member.size > MAX_FILE_BYTES:
                    _fail("vendor-node-member-size")
                total += member.size
                if total > MAX_EXPANDED_BYTES:
                    _fail("vendor-node-expanded-size")
                parent = _parents(root_fd, parts[:-1], owner_uid)
                try:
                    if member.isdir():
                        child = _parents(root_fd, parts, owner_uid)
                        os.close(child)
                    elif member.issym():
                        _link_target(parts, member.linkname)
                        links.append((parts, member.linkname))
                    else:
                        _file(archive, member, parent, parts[-1], remaining)
                finally:
                    os.close(parent)
        _finish_links(root, root_fd, links, remaining, owner_uid)
    finally:
        os.close(root_fd)


def _seal(root, remaining):
    for current, directories, _files in os.walk(root, followlinks=False):
        _tick(remaining)
        for name in directories:
            path = Path(current) / name
            if not path.is_symlink():
                path.chmod(0o555)
    root.chmod(0o555)


def _layout(node_root):
    for name in ("bin/node", "lib/node_modules/npm/bin/npm-cli.js"):
        path = node_root / name
        if not path.is_file() or path.is_symlink():
            _fail("vendor-node-layout")
    try:
        expected = node_root / "lib/node_modules/npm/bin/npm-cli.js"
        if (not os.access(node_root / "bin/node", os.X_OK)
                or (node_root / "bin/npm").resolve(strict=True) != expected):
            _fail("vendor-node-layout")
    except (OSError, RuntimeError):
        _fail("vendor-node-layout")


def acquire_node_source(snapshot_id, deadline_file, profile="core-node"):
    """Return a fresh verified source for the existing Node snapshot producer.

    Call only in trusted preparation before decrypting or executing any candidate.
    On failure the private owned area is retained for the caller's outer teardown;
    no cleanup, mount-readonly or hard-preemption claim is implied by a timeout.
    """
    if sys.platform != "linux" or os.geteuid() != 0 or SESSION_ID.fullmatch(snapshot_id or "") is None:
        _fail("vendor-node-platform-or-id")
    distribution = _distribution(profile)
    import deadline
    remaining = lambda: deadline.remaining(deadline_file)
    _tick(remaining)
    base_fd = _open_protected_base()
    try:
        os.mkdir(snapshot_id, 0o700, dir_fd=base_fd)
    finally:
        os.close(base_fd)
    area = PROTECTED_BASE / snapshot_id
    archive = area / "node.tar.xz"
    _download(archive, remaining, profile)
    fd = _verified_archive(archive, remaining, 0, profile)
    cache = area / "cache"
    node_root = cache / "node" / distribution["node_version"] / "x64"
    try:
        node_root.parent.mkdir(parents=True, mode=0o700)
        _extract(fd, node_root, remaining, 0, profile)
    finally:
        os.close(fd)
    _layout(node_root)
    _seal(node_root, remaining)
    _tick(remaining)
    return VendorSource(cache, node_root, node_root / "bin/node", node_root / "bin/npm",
                        distribution["archive_sha256"], distribution["preparation_id"],
                        distribution["node_version"], distribution["npm_version"])


def source_node_root(snapshot_id, profile="desktop"):
    if SESSION_ID.fullmatch(snapshot_id or "") is None:
        _fail("vendor-node-platform-or-id")
    distribution = _distribution(profile)
    area = PROTECTED_BASE / snapshot_id
    paths = (
        Path("/run"), Path("/run/platform-ci-devlane"), PROTECTED_BASE, area,
        area / "cache", area / "cache/node",
        area / "cache/node" / distribution["node_version"],
    )
    for path in paths:
        try:
            metadata = os.lstat(path)
        except OSError:
            _fail("vendor-node-layout")
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) & 0o022):
            _fail("vendor-node-layout")
    root = area / "cache/node" / distribution["node_version"] / "x64"
    try:
        metadata = os.lstat(root)
    except OSError:
        _fail("vendor-node-layout")
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o555):
        _fail("vendor-node-layout")
    _layout(root)
    for name in ("bin", "lib", "lib/node_modules", "lib/node_modules/npm",
                 "lib/node_modules/npm/bin"):
        try:
            metadata = os.lstat(root / name)
        except OSError:
            _fail("vendor-node-layout")
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) != 0o555):
            _fail("vendor-node-layout")
    for name in ("bin/node", "lib/node_modules/npm/bin/npm-cli.js"):
        try:
            metadata = os.lstat(root / name)
        except OSError:
            _fail("vendor-node-layout")
        expected_mode = 0o555 if name == "bin/node" else 0o444
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0
                or stat.S_IMODE(metadata.st_mode) != expected_mode):
            _fail("vendor-node-layout")
    return root
