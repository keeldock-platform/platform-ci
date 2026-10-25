import os
import stat
import time


class ScanIncomplete(Exception):
    pass


class CanaryPresent(ScanIncomplete):
    pass


def _inside(path, root):
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def scan_readable_roots(
    roots,
    needle,
    *,
    walk=None,
    open_file=None,
    stat_path=None,
    real_path=None,
    is_link=None,
    is_file=None,
    clock=None,
    deadline_seconds=180,
    max_files=1000000,
    max_bytes=68719476736,
    chunk_size=1048576,
):
    walk = os.walk if walk is None else walk
    open_file = open if open_file is None else open_file
    stat_path = os.stat if stat_path is None else stat_path
    real_path = os.path.realpath if real_path is None else real_path
    is_link = os.path.islink if is_link is None else is_link
    is_file = os.path.isfile if is_file is None else is_file
    clock = time.monotonic if clock is None else clock
    if (
        type(roots) not in (tuple, list)
        or not roots
        or type(needle) is not bytes
        or not needle
        or type(deadline_seconds) not in (int, float)
        or deadline_seconds <= 0
        or type(max_files) is not int
        or max_files <= 0
        or type(max_bytes) is not int
        or max_bytes <= 0
        or type(chunk_size) is not int
        or chunk_size <= 0
    ):
        raise ScanIncomplete("invalid_scan_configuration")
    if any(
        type(root) is not str
        or not os.path.isabs(root)
        or os.path.normpath(root) != root
        or ".." in root.split(os.sep)
        for root in roots
    ):
        raise ScanIncomplete("invalid_scan_root")
    root_set = tuple(dict.fromkeys(roots))
    if len(root_set) != len(roots):
        raise ScanIncomplete("duplicate_scan_root")
    canonical_roots = tuple(dict.fromkeys(real_path(root) for root in roots))
    allowed_roots = root_set + canonical_roots
    deadline = clock() + deadline_seconds
    visited = set()
    errors = []
    files_seen = 0
    bytes_seen = 0

    def ensure_time():
        if clock() > deadline:
            raise ScanIncomplete("scan_timeout")

    def allowed(path):
        return any(_inside(path, root) for root in allowed_roots)

    def onerror(error):
        errors.append(error)

    try:
        for root in root_set:
            root_metadata = stat_path(root)
            if not stat.S_ISDIR(root_metadata.st_mode):
                raise ScanIncomplete("scan_root_not_directory")
            for directory, subdirectories, filenames in walk(root, followlinks=True, onerror=onerror):
                ensure_time()
                if not allowed(real_path(directory)):
                    raise ScanIncomplete("walk_path_outside_roots")
                metadata = stat_path(directory)
                identity = (metadata.st_dev, metadata.st_ino)
                if identity in visited:
                    subdirectories[:] = []
                    continue
                visited.add(identity)
                retained = []
                for name in subdirectories:
                    candidate = os.path.join(directory, name)
                    target = real_path(candidate)
                    if not allowed(target):
                        raise ScanIncomplete("symlink_target_outside_roots")
                    retained.append(name)
                subdirectories[:] = retained
                for name in filenames:
                    ensure_time()
                    path = os.path.join(directory, name)
                    target = real_path(path)
                    if is_link(path) and not allowed(target):
                        raise ScanIncomplete("symlink_target_outside_roots")
                    if not allowed(target):
                        raise ScanIncomplete("readable_path_outside_roots")
                    metadata = stat_path(path)
                    if not stat.S_ISREG(metadata.st_mode) or not is_file(path):
                        raise ScanIncomplete("file_type_unavailable")
                    files_seen += 1
                    if files_seen > max_files:
                        raise ScanIncomplete("file_limit")
                    tail = b""
                    with open_file(path, "rb") as stream:
                        while True:
                            ensure_time()
                            chunk = stream.read(chunk_size)
                            if not chunk:
                                break
                            bytes_seen += len(chunk)
                            if bytes_seen > max_bytes:
                                raise ScanIncomplete("byte_limit")
                            combined = tail + chunk
                            if needle in combined:
                                raise CanaryPresent("canary_found")
                            tail = combined[-(len(needle) - 1):] if len(needle) > 1 else b""
            if errors:
                raise ScanIncomplete("walk_error")
    except (CanaryPresent, ScanIncomplete):
        raise
    except BaseException:
        raise ScanIncomplete("scan_io_error") from None
    if errors:
        raise ScanIncomplete("walk_error")
    return files_seen, bytes_seen
