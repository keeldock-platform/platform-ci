"""Remove an owned directory tree after its consumer has been independently stopped."""

import os
import stat
from pathlib import Path


MAX_CLEANUP_ENTRIES = 250000
MAX_CLEANUP_DEPTH = 128


def _require(condition, prefix, code):
    if not condition:
        raise RuntimeError(prefix + code)


def remove_owned_tree(path, parent, *, prefix="owned-tree-cleanup-", deadline_check=None, last_name=None):
    root = Path(path)
    base = Path(parent)
    entries_seen = 0

    def check_deadline():
        if deadline_check is not None:
            deadline_check()

    def charge_entry(depth):
        nonlocal entries_seen
        check_deadline()
        entries_seen += 1
        _require(entries_seen <= MAX_CLEANUP_ENTRIES, prefix, "entry-limit")
        _require(depth <= MAX_CLEANUP_DEPTH, prefix, "depth-limit")

    check_deadline()
    _require(root.is_absolute() and base.is_absolute(), prefix, "path-invalid")
    _require(root.parent.resolve(strict=True) == base.resolve(strict=True), prefix, "parent-invalid")
    root_name = root.name
    parent_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    parent_fd = os.open(str(base.resolve(strict=True)), parent_flags)
    try:
        parent_stat = os.fstat(parent_fd)
        owner = os.getuid()
        _require(stat.S_ISDIR(parent_stat.st_mode) and parent_stat.st_uid == owner,
                 prefix, "parent-owner")
        try:
            root_stat = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            check_deadline()
            return
        _require(stat.S_ISDIR(root_stat.st_mode) and root_stat.st_uid == owner,
                 prefix, "root-owner")
        _require(not os.path.ismount(root), prefix, "root-mount")
        root_fd = os.open(root_name, directory_flags, dir_fd=parent_fd)
        try:
            opened_root = os.fstat(root_fd)
            _require((opened_root.st_dev, opened_root.st_ino, opened_root.st_uid) ==
                     (root_stat.st_dev, root_stat.st_ino, owner), prefix, "root-race")

            def clear_directory(directory_fd, directory_path):
                check_deadline()
                opened = os.fstat(directory_fd)
                _require(stat.S_ISDIR(opened.st_mode) and opened.st_uid == owner,
                         prefix, "directory-owner")
                _require(not os.path.ismount(directory_path), prefix, "directory-mount")
                os.fchmod(directory_fd, 0o700)
                depth = len(directory_path.parts) - len(root.parts)
                _require(depth <= MAX_CLEANUP_DEPTH, prefix, "depth-limit")
                entries = []
                with os.scandir(directory_fd) as iterator:
                    for entry in iterator:
                        charge_entry(depth + 1)
                        name = entry.name
                        _require(type(name) is str and name not in ("", ".", "..")
                                 and len(name) <= 4096, prefix, "member-name")
                        entries.append(name)
                if directory_path == root and last_name is not None:
                    _require(last_name in entries, prefix, "last-entry-missing")
                    entries.sort(key=lambda name: name == last_name)
                check_deadline()
                for name in entries:
                    charge_entry(depth + 1)
                    item = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                    _require(item.st_uid == owner, prefix, "member-owner")
                    child_path = directory_path / name
                    if stat.S_ISDIR(item.st_mode):
                        _require(not os.path.ismount(child_path), prefix, "directory-mount")
                        child_fd = os.open(name, directory_flags, dir_fd=directory_fd)
                        try:
                            child_opened = os.fstat(child_fd)
                            _require((child_opened.st_dev, child_opened.st_ino, child_opened.st_uid) ==
                                     (item.st_dev, item.st_ino, owner), prefix, "directory-race")
                            clear_directory(child_fd, child_path)
                        finally:
                            os.close(child_fd)
                        current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                        _require((current.st_dev, current.st_ino, current.st_uid) ==
                                 (item.st_dev, item.st_ino, owner), prefix, "directory-race")
                        os.rmdir(name, dir_fd=directory_fd)
                    elif stat.S_ISREG(item.st_mode) or stat.S_ISLNK(item.st_mode):
                        os.unlink(name, dir_fd=directory_fd)
                    else:
                        raise RuntimeError(prefix + "member-type")
                    check_deadline()

            check_deadline()
            clear_directory(root_fd, root)
        finally:
            os.close(root_fd)
        current_root = os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
        _require((current_root.st_dev, current_root.st_ino, current_root.st_uid) ==
                 (root_stat.st_dev, root_stat.st_ino, owner), prefix, "root-race")
        os.rmdir(root_name, dir_fd=parent_fd)
        check_deadline()
        try:
            os.stat(root_name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            return
        raise RuntimeError(prefix + "tree-remains")
    finally:
        os.close(parent_fd)
