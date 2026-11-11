"""Acquire and verify the fixed Node toolchain in a private control-owned tree."""

import hashlib
import json
import os
import re
import secrets
import stat
from collections import deque
from pathlib import Path

import bundle
import deadline as deadline_budget


PREPARATION_ID = "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1"
PROTECTED_SNAPSHOT_BASE = Path("/run/platform-ci-devlane/node-tools")
DEFAULT_SNAPSHOT_BASE = PROTECTED_SNAPSHOT_BASE
MANIFEST_NAME = ".devlane-node-snapshot.json"
MAX_ENTRIES = 100_000
MAX_BYTES = bundle.MAX_EXPANDED
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_LINK_HOPS = 40
MAX_LINK_PATH_DEPTH = 256
MAX_LINK_GRAPH_STEPS = MAX_ENTRIES * 32
CHUNK_SIZE = 1024 * 1024
SNAPSHOT_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_O_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_O_DIRECTORY = getattr(os, "O_DIRECTORY", 0)


class SnapshotRefusal(ValueError):
    """A finite refusal that carries no path or input content."""

    def __init__(self, code, *, cleanup_unconfirmed=False):
        self.code = code
        self.cleanup_unconfirmed = cleanup_unconfirmed
        self.cleanup_confirmed = False
        super().__init__(code)


def _refuse(code):
    raise SnapshotRefusal(code)


def valid_snapshot_id(value):
    return type(value) is str and SNAPSHOT_ID.fullmatch(value) is not None and value not in (".", "..")


def _remaining(deadline_file, *, cleanup=False):
    try:
        return (deadline_budget.cleanup_remaining(deadline_file) if cleanup
                else deadline_budget.remaining(deadline_file))
    except (OSError, deadline_budget.DeadlineRefusal):
        _refuse("node-snapshot-deadline")


def _time_check(deadline_file, *, cleanup=False):
    _remaining(deadline_file, cleanup=cleanup)


def _metadata_token(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _secure_directory(fd, allowed_uids, *, exact_mode=None):
    value = os.fstat(fd)
    if not stat.S_ISDIR(value.st_mode) or value.st_uid not in allowed_uids:
        _refuse("node-snapshot-source-owner")
    mode = stat.S_IMODE(value.st_mode)
    if exact_mode is not None:
        if mode != exact_mode:
            _refuse("node-snapshot-seal-invalid")
    elif mode & 0o022 or not mode & stat.S_IRUSR or not mode & stat.S_IXUSR:
        _refuse("node-snapshot-source-permissions")
    return value


def _secure_source_ancestor(value, allowed_uids):
    if not stat.S_ISDIR(value.st_mode) or value.st_uid not in allowed_uids:
        _refuse("node-snapshot-source-owner")
    mode = stat.S_IMODE(value.st_mode)
    if mode & 0o022 and not (value.st_uid == 0 and mode & stat.S_ISVTX):
        _refuse("node-snapshot-source-permissions")


def _open_absolute_directory(path):
    path = Path(path)
    if not path.is_absolute():
        _refuse("node-snapshot-source-layout")
    parts = path.parts
    if not parts or parts[0] != "/":
        _refuse("node-snapshot-source-layout")
    current = os.open("/", os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)
    opened = [("/", current, _metadata_token(os.fstat(current)))]
    try:
        for name in parts[1:]:
            if not name or name in (".", ".."):
                _refuse("node-snapshot-source-layout")
            child = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=current)
            opened.append((name, child, _metadata_token(os.fstat(child))))
            current = child
        return current, opened
    except Exception:
        for _name, descriptor, _token in reversed(opened):
            try:
                os.close(descriptor)
            except OSError:
                pass
        raise


def _close_chain(opened):
    for _name, descriptor, _token in reversed(opened):
        try:
            os.close(descriptor)
        except OSError:
            pass


def _check_source_chain(path, opened, allowed_uids):
    try:
        _current, fresh = _open_absolute_directory(path)
    except (OSError, SnapshotRefusal):
        _refuse("node-snapshot-source-changed")
    try:
        if len(fresh) != len(opened):
            _refuse("node-snapshot-source-changed")
        for (left_name, left_fd, left_token), (right_name, right_fd, right_token) in zip(opened, fresh):
            if (left_name != right_name
                    or left_token[:5] != right_token[:5]):
                _refuse("node-snapshot-source-changed")
            _secure_source_ancestor(os.fstat(right_fd), allowed_uids)
    finally:
        _close_chain(fresh)


def _safe_relative_link(relative, target):
    if type(target) is not str or not target or os.path.isabs(target):
        return False
    normalized = Path(os.path.normpath(str(Path(relative).parent / target)))
    return str(normalized) not in (".", "..") and not str(normalized).startswith("../")


def _entry_digest(entries):
    return hashlib.sha256(bundle.canonical_json(entries)).hexdigest()


def _append_row(rows, row, totals):
    row_bytes = len(bundle.canonical_json(row)) + 1
    manifest_rows_bytes = totals.get("manifest_rows_bytes", 0) + row_bytes
    if manifest_rows_bytes > MAX_MANIFEST_BYTES - 4096:
        _refuse("node-snapshot-limit")
    totals["manifest_rows_bytes"] = manifest_rows_bytes
    rows.append(row)


def _resolve_snapshot_link(root_fd, link_path, entries, control_uid, deadline_file, state, *, cleanup=False):
    pending = deque(link_path.split("/"))
    resolved = []
    directory_fds = [os.dup(root_fd)]
    hops = 0
    try:
        while pending:
            state["steps"] += 1
            if state["steps"] > MAX_LINK_GRAPH_STEPS:
                _refuse("node-snapshot-limit")
            if state["steps"] % 128 == 1:
                _time_check(deadline_file, cleanup=cleanup)
            component = pending.popleft()
            if component in ("", "."):
                continue
            if component == "..":
                if not resolved:
                    _refuse("node-snapshot-link-invalid")
                resolved.pop()
                os.close(directory_fds.pop())
                continue
            if component in (".", "..") or "/" in component or "\x00" in component:
                _refuse("node-snapshot-link-invalid")
            parent_fd = directory_fds[-1]
            relative = component if not resolved else "/".join((*resolved, component))
            expected = entries.get(relative)
            if expected is None:
                _refuse("node-snapshot-link-invalid")
            try:
                observed = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
            except OSError:
                _refuse("node-snapshot-link-invalid")
            if observed.st_uid != control_uid:
                _refuse("node-snapshot-link-invalid")
            if stat.S_ISLNK(observed.st_mode):
                if expected.get("kind") != "symlink":
                    _refuse("node-snapshot-link-invalid")
                try:
                    target = os.readlink(component, dir_fd=parent_fd)
                    current = os.stat(component, dir_fd=parent_fd, follow_symlinks=False)
                except OSError:
                    _refuse("node-snapshot-link-invalid")
                if (_metadata_token(observed) != _metadata_token(current)
                        or target != expected.get("target")
                        or not _safe_relative_link(relative, target)):
                    _refuse("node-snapshot-link-invalid")
                hops += 1
                if hops > MAX_LINK_HOPS:
                    _refuse("node-snapshot-link-invalid")
                target_parts = target.split("/")
                if target.endswith("/"):
                    target_parts.append(".")
                pending.extendleft(reversed(target_parts))
                continue
            if stat.S_ISDIR(observed.st_mode):
                if (expected.get("kind") != "directory"
                        or stat.S_IMODE(observed.st_mode) != 0o555
                        or len(resolved) >= MAX_LINK_PATH_DEPTH):
                    _refuse("node-snapshot-link-invalid")
                try:
                    child_fd = os.open(component, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW,
                                       dir_fd=parent_fd)
                except OSError:
                    _refuse("node-snapshot-link-invalid")
                opened = os.fstat(child_fd)
                if (not stat.S_ISDIR(opened.st_mode) or opened.st_uid != control_uid
                        or stat.S_IMODE(opened.st_mode) != 0o555
                        or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)):
                    os.close(child_fd)
                    _refuse("node-snapshot-link-invalid")
                resolved.append(component)
                directory_fds.append(child_fd)
                continue
            if (not stat.S_ISREG(observed.st_mode) or expected.get("kind") != "file"
                    or stat.S_IMODE(observed.st_mode) not in (0o444, 0o555)
                    or observed.st_nlink != 1 or pending):
                _refuse("node-snapshot-link-invalid")
    finally:
        for descriptor in reversed(directory_fds):
            try:
                os.close(descriptor)
            except OSError:
                pass


def _verify_link_graph(root_fd, rows, control_uid, deadline_file, *, cleanup=False):
    root = os.fstat(root_fd)
    if (not stat.S_ISDIR(root.st_mode) or root.st_uid != control_uid
            or stat.S_IMODE(root.st_mode) != 0o555):
        _refuse("node-snapshot-seal-invalid")
    entries = {}
    links = []
    for index, row in enumerate(rows):
        if index % 128 == 0:
            _time_check(deadline_file, cleanup=cleanup)
        relative = row.get("path")
        if type(relative) is not str or relative in entries:
            _refuse("node-snapshot-manifest-invalid")
        entries[relative] = row
        if row.get("kind") == "symlink":
            links.append(relative)
    if len(entries) > MAX_ENTRIES:
        _refuse("node-snapshot-limit")
    state = {"steps": 0}
    for index, relative in enumerate(links):
        if index % 128 == 0:
            _time_check(deadline_file, cleanup=cleanup)
        _resolve_snapshot_link(root_fd, relative, entries, control_uid, deadline_file, state,
                               cleanup=cleanup)


def _write_all(fd, payload):
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            _refuse("node-snapshot-copy-failed")
        view = view[written:]


def _bounded_names(directory_fd, deadline_file, *, cleanup=False, read_error="node-snapshot-source-read"):
    names = []
    try:
        with os.scandir(directory_fd) as entries:
            for index, entry in enumerate(entries):
                if index % 128 == 0:
                    _time_check(deadline_file, cleanup=cleanup)
                if len(names) >= MAX_ENTRIES:
                    _refuse("node-snapshot-limit")
                names.append(entry.name)
    except SnapshotRefusal:
        raise
    except OSError:
        _refuse(read_error)
    names.sort()
    return names


def _copy_directory(source_fd, destination_fd, prefix, allowed_uids, deadline_file, rows, totals,
                    source_tokens, test_checkpoint=None, checkpoint_state=None):
    before = _secure_directory(source_fd, allowed_uids)
    names = _bounded_names(source_fd, deadline_file)
    if MANIFEST_NAME in names:
        _refuse("node-snapshot-source-layout")
    for index, name in enumerate(names):
        if index % 128 == 0:
            _time_check(deadline_file)
        if name in (".", "..") or "/" in name or "\x00" in name:
            _refuse("node-snapshot-source-layout")
        relative = name if not prefix else prefix + "/" + name
        try:
            observed = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        except OSError:
            _refuse("node-snapshot-source-changed")
        if observed.st_uid not in allowed_uids:
            _refuse("node-snapshot-source-owner")
        if stat.S_ISDIR(observed.st_mode):
            mode = stat.S_IMODE(observed.st_mode)
            if mode & 0o022 or not mode & stat.S_IRUSR or not mode & stat.S_IXUSR or not mode & stat.S_IROTH or not mode & stat.S_IXOTH:
                _refuse("node-snapshot-source-permissions")
            child_source = child_target = None
            try:
                child_source = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=source_fd)
                os.mkdir(name, 0o700, dir_fd=destination_fd)
                child_target = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=destination_fd)
            except OSError:
                if child_source is not None:
                    os.close(child_source)
                if child_target is not None:
                    os.close(child_target)
                _refuse("node-snapshot-source-changed")
            try:
                source_meta = _secure_directory(child_source, allowed_uids)
                if (source_meta.st_dev, source_meta.st_ino) != (observed.st_dev, observed.st_ino):
                    _refuse("node-snapshot-source-changed")
                source_tokens[relative] = _metadata_token(source_meta)
                _append_row(rows, {"path": relative, "kind": "directory", "mode": 0o555}, totals)
                totals["entries"] += 1
                if totals["entries"] > MAX_ENTRIES:
                    _refuse("node-snapshot-limit")
                _copy_directory(child_source, child_target, relative, allowed_uids, deadline_file, rows,
                                totals, source_tokens, test_checkpoint, checkpoint_state)
            finally:
                os.close(child_source)
                os.close(child_target)
        elif stat.S_ISREG(observed.st_mode):
            mode = stat.S_IMODE(observed.st_mode)
            if mode & (0o022 | stat.S_ISUID | stat.S_ISGID) or not mode & stat.S_IRUSR or not mode & stat.S_IROTH:
                _refuse("node-snapshot-source-permissions")
            source_file = target_file = None
            digest = hashlib.sha256()
            size = 0
            try:
                try:
                    source_file = os.open(name, os.O_RDONLY | os.O_NONBLOCK | _O_NOFOLLOW, dir_fd=source_fd)
                except OSError:
                    _refuse("node-snapshot-source-changed")
                source_meta = os.fstat(source_file)
                if (not stat.S_ISREG(source_meta.st_mode)
                        or (source_meta.st_dev, source_meta.st_ino) != (observed.st_dev, observed.st_ino)):
                    _refuse("node-snapshot-source-changed")
                source_tokens[relative] = _metadata_token(source_meta)
                target_mode = 0o555 if mode & 0o111 else 0o444
                try:
                    target_file = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW,
                                          target_mode, dir_fd=destination_fd)
                except OSError:
                    _refuse("node-snapshot-copy-failed")
                while True:
                    _time_check(deadline_file)
                    chunk = os.read(source_file, CHUNK_SIZE)
                    if not chunk:
                        break
                    size += len(chunk)
                    totals["bytes"] += len(chunk)
                    if totals["bytes"] > MAX_BYTES or size > source_meta.st_size:
                        _refuse("node-snapshot-limit")
                    digest.update(chunk)
                    _write_all(target_file, chunk)
                    checkpoint_key = "copy_chunk:" + relative
                    if (test_checkpoint is not None and checkpoint_state is not None
                            and not checkpoint_state.get(checkpoint_key)):
                        checkpoint_state[checkpoint_key] = True
                        test_checkpoint("during-copy:" + relative)
                after = os.fstat(source_file)
                if (_metadata_token(source_meta) != _metadata_token(after)
                        or size != source_meta.st_size):
                    _refuse("node-snapshot-source-changed")
                os.fchmod(target_file, target_mode)
                os.fsync(target_file)
            finally:
                if source_file is not None:
                    os.close(source_file)
                if target_file is not None:
                    os.close(target_file)
            _append_row(rows, {"path": relative, "kind": "file", "mode": target_mode,
                               "size": size, "sha256": digest.hexdigest()}, totals)
            totals["entries"] += 1
            if totals["entries"] > MAX_ENTRIES:
                _refuse("node-snapshot-limit")
        elif stat.S_ISLNK(observed.st_mode):
            try:
                target = os.readlink(name, dir_fd=source_fd)
                after = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            except OSError:
                _refuse("node-snapshot-source-changed")
            if _metadata_token(observed) != _metadata_token(after):
                _refuse("node-snapshot-source-changed")
            if not _safe_relative_link(relative, target):
                _refuse("node-snapshot-link-invalid")
            source_tokens[relative] = _metadata_token(observed)
            try:
                os.symlink(target, name, dir_fd=destination_fd)
            except OSError:
                _refuse("node-snapshot-copy-failed")
            _append_row(rows, {"path": relative, "kind": "symlink", "target": target}, totals)
            totals["entries"] += 1
            if totals["entries"] > MAX_ENTRIES:
                _refuse("node-snapshot-limit")
        else:
            _refuse("node-snapshot-source-layout")
    after = _secure_directory(source_fd, allowed_uids)
    if _metadata_token(before) != _metadata_token(after):
        _refuse("node-snapshot-source-changed")


def _verify_source_directory(source_fd, prefix, allowed_uids, deadline_file, expected, totals,
                             source_tokens, expected_children):
    before = _secure_directory(source_fd, allowed_uids)
    names = _bounded_names(source_fd, deadline_file)
    if any(name in (".", "..") or "/" in name or "\x00" in name for name in names):
        _refuse("node-snapshot-source-layout")
    if names != expected_children.get(prefix, []):
        _refuse("node-snapshot-source-changed")
    for index, name in enumerate(names):
        if index % 128 == 0:
            _time_check(deadline_file)
        relative = name if not prefix else prefix + "/" + name
        observed = expected.get(relative)
        if observed is None:
            _refuse("node-snapshot-source-changed")
        try:
            metadata = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
        except OSError:
            _refuse("node-snapshot-source-changed")
        if metadata.st_uid not in allowed_uids:
            _refuse("node-snapshot-source-owner")
        kind = observed["kind"]
        if kind == "directory":
            if (not stat.S_ISDIR(metadata.st_mode)
                    or source_tokens.get(relative) != _metadata_token(metadata)):
                _refuse("node-snapshot-source-changed")
            try:
                child = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=source_fd)
            except OSError:
                _refuse("node-snapshot-source-changed")
            try:
                opened = os.fstat(child)
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
                    _refuse("node-snapshot-source-changed")
                _verify_source_directory(child, relative, allowed_uids, deadline_file, expected,
                                         totals, source_tokens, expected_children)
            finally:
                os.close(child)
        elif kind == "file":
            if not stat.S_ISREG(metadata.st_mode):
                _refuse("node-snapshot-source-changed")
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | _O_NOFOLLOW, dir_fd=source_fd)
            except OSError:
                _refuse("node-snapshot-source-changed")
            digest = hashlib.sha256()
            size = 0
            try:
                opened = os.fstat(fd)
                if ((opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino)
                        or source_tokens.get(relative) != _metadata_token(opened)):
                    _refuse("node-snapshot-source-changed")
                while True:
                    _time_check(deadline_file)
                    chunk = os.read(fd, CHUNK_SIZE)
                    if not chunk:
                        break
                    size += len(chunk)
                    totals["bytes"] += len(chunk)
                    if totals["bytes"] > MAX_BYTES:
                        _refuse("node-snapshot-limit")
                    digest.update(chunk)
                after = os.fstat(fd)
                if (_metadata_token(opened) != _metadata_token(after) or size != observed["size"]
                        or digest.hexdigest() != observed["sha256"]):
                    _refuse("node-snapshot-source-changed")
            finally:
                os.close(fd)
        elif kind == "symlink":
            if not stat.S_ISLNK(metadata.st_mode):
                _refuse("node-snapshot-source-changed")
            try:
                target = os.readlink(name, dir_fd=source_fd)
                after = os.stat(name, dir_fd=source_fd, follow_symlinks=False)
            except OSError:
                _refuse("node-snapshot-source-changed")
            if (target != observed["target"] or _metadata_token(metadata) != _metadata_token(after)
                    or source_tokens.get(relative) != _metadata_token(metadata)
                    or not _safe_relative_link(relative, target)):
                _refuse("node-snapshot-source-changed")
        else:
            _refuse("node-snapshot-manifest-invalid")
    after = _secure_directory(source_fd, allowed_uids)
    if _metadata_token(before) != _metadata_token(after):
        _refuse("node-snapshot-source-changed")


def _open_snapshot_base(base, control_uid, *, create=False, trusted_chain=False):
    base = Path(base)
    if not base.is_absolute():
        _refuse("node-snapshot-layout")
    if create and trusted_chain:
        current = Path("/")
        for part in base.parts[1:]:
            current = current / part
            try:
                os.mkdir(current, 0o755)
            except FileExistsError:
                pass
            except OSError:
                _refuse("node-snapshot-base-unavailable")
            try:
                value = os.lstat(current)
            except OSError:
                _refuse("node-snapshot-base-unavailable")
            if (not stat.S_ISDIR(value.st_mode) or stat.S_ISLNK(value.st_mode)
                    or value.st_uid != control_uid or stat.S_IMODE(value.st_mode) & 0o022):
                _refuse("node-snapshot-base-owner")
    elif create:
        try:
            base.mkdir(mode=0o755, parents=True, exist_ok=True)
        except OSError:
            _refuse("node-snapshot-base-unavailable")
    try:
        fd, chain = _open_absolute_directory(base)
    except (OSError, SnapshotRefusal):
        _refuse("node-snapshot-base-unavailable")
    value = _secure_directory(fd, frozenset((control_uid,)))
    if stat.S_IMODE(value.st_mode) & 0o022:
        _close_chain(chain)
        _refuse("node-snapshot-base-owner")
    if base == PROTECTED_SNAPSHOT_BASE:
        for _name, descriptor, _token in chain:
            try:
                anchor = os.fstat(descriptor)
            except OSError:
                _close_chain(chain)
                _refuse("node-snapshot-base-invalid")
            if (not stat.S_ISDIR(anchor.st_mode) or anchor.st_uid != control_uid
                    or stat.S_IMODE(anchor.st_mode) & 0o022):
                _close_chain(chain)
                _refuse("node-snapshot-base-owner")
    return fd, chain


def _confirm_snapshot_base_absent(base, control_uid):
    """Confirm that a missing base has no snapshot without following path links."""
    base = Path(base)
    if not base.is_absolute():
        _refuse("node-snapshot-base-invalid")
    current = os.open("/", os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW)
    protected = base == PROTECTED_SNAPSHOT_BASE
    parts = base.parts[1:]
    try:
        for index, name in enumerate(parts):
            try:
                child = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=current)
            except FileNotFoundError:
                return True
            except OSError:
                _refuse("node-snapshot-base-invalid")
            metadata = os.fstat(child)
            mode = stat.S_IMODE(metadata.st_mode)
            if not stat.S_ISDIR(metadata.st_mode):
                os.close(child)
                _refuse("node-snapshot-base-invalid")
            if protected:
                if metadata.st_uid != control_uid or mode & 0o022:
                    os.close(child)
                    _refuse("node-snapshot-base-owner")
            elif index == len(parts) - 1:
                if metadata.st_uid != control_uid or mode & 0o022:
                    os.close(child)
                    _refuse("node-snapshot-base-owner")
            else:
                safe_sticky = metadata.st_uid == 0 and bool(mode & stat.S_ISVTX)
                if (metadata.st_uid not in (0, control_uid)
                        or mode & 0o022 and not safe_sticky):
                    os.close(child)
                    _refuse("node-snapshot-base-owner")
            os.close(current)
            current = child
        return False
    finally:
        try:
            os.close(current)
        except OSError:
            pass


def _validate_source_layout(paths, owner_uid, cache_root=None, node_root=None, system_anchors=None,
                           deadline_file=None):
    import prepare

    return prepare.validate_node_toolchain(
        paths, owner_uid, tool_cache_root=cache_root, node_root=node_root,
        system_anchors=system_anchors, deadline_file=deadline_file,
    )


def _snapshot_source(root, runner_uid, deadline_file, *, control_uid, snapshot_base, snapshot_id,
                     source_paths=None,
                     source_cache_root=None, source_node_root=None, source_anchors=None,
                     test_checkpoint=None):
    paths = source_paths or {"node": str(Path(root) / "bin/node"), "npm": str(Path(root) / "bin/npm")}
    validated = _validate_source_layout(
        paths, runner_uid, source_cache_root, source_node_root, source_anchors,
        deadline_file=deadline_file,
    )
    source_root = Path(validated["root"])
    if test_checkpoint is not None:
        test_checkpoint("after-source-validation")
    allowed_uids = frozenset((0, runner_uid))
    try:
        source_fd, chain = _open_absolute_directory(source_root)
    except OSError:
        _refuse("node-snapshot-source-changed")
    stage = None
    committed = False
    base_fd = None
    base_chain = None
    try:
        for _name, descriptor, _token in chain:
            metadata = os.fstat(descriptor)
            _secure_source_ancestor(metadata, allowed_uids)
        _secure_directory(source_fd, allowed_uids)
        base_fd, base_chain = _open_snapshot_base(
            snapshot_base, control_uid, create=True, trusted_chain=snapshot_base == PROTECTED_SNAPSHOT_BASE,
        )
        if not valid_snapshot_id(snapshot_id):
            _refuse("node-snapshot-id")
        if os.stat(snapshot_id, dir_fd=base_fd, follow_symlinks=False):
            _refuse("node-snapshot-exists")
    except FileNotFoundError:
        pass
    except Exception:
        _close_chain(chain)
        if base_chain is not None:
            _close_chain(base_chain)
        raise
    try:
        stage = ".stage-" + snapshot_id + "-" + secrets.token_hex(8)
        os.mkdir(stage, 0o700, dir_fd=base_fd)
        stage_fd = os.open(stage, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=base_fd)
        rows = []
        totals = {"bytes": 0, "entries": 0, "manifest_rows_bytes": 0}
        source_tokens = {}
        try:
            checkpoint_state = {"copy_chunk": False}
            _copy_directory(source_fd, stage_fd, "", allowed_uids, deadline_file, rows, totals,
                            source_tokens, test_checkpoint, checkpoint_state)
            if test_checkpoint is not None:
                test_checkpoint("after-copy")
            _check_source_chain(source_root, chain, allowed_uids)
            expected = {row["path"]: row for row in rows}
            expected_children = {}
            for index, path in enumerate(expected):
                if index % 128 == 0:
                    _time_check(deadline_file)
                parent, separator, name = path.rpartition("/")
                parent = parent if separator else ""
                expected_children.setdefault(parent, []).append(name)
            for children in expected_children.values():
                children.sort()
            _verify_source_directory(source_fd, "", allowed_uids, deadline_file, expected,
                                     {"bytes": 0}, source_tokens, expected_children)
            if test_checkpoint is not None:
                test_checkpoint("after-source-verify")
            if rows != sorted(rows, key=lambda row: row["path"]):
                _refuse("node-snapshot-manifest-invalid")
            manifest_core = {
                "schema": 1, "snapshot_id": snapshot_id, "preparation": PREPARATION_ID,
                "node_version": "24.22.1", "npm_version": "11.19.1",
                "runner_uid": runner_uid,
                "entry_count": len(rows), "expanded_bytes": totals["bytes"], "entries": rows,
            }
            if totals["entries"] + 1 > MAX_ENTRIES:
                _refuse("node-snapshot-limit")
            manifest = dict(manifest_core)
            manifest["content_sha256"] = _entry_digest(manifest_core)
            payload = bundle.canonical_json(manifest) + b"\n"
            if (len(payload) > MAX_MANIFEST_BYTES
                    or len(payload) + totals["bytes"] > MAX_BYTES):
                _refuse("node-snapshot-limit")
            manifest_fd = os.open(MANIFEST_NAME, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _O_NOFOLLOW,
                                  0o444, dir_fd=stage_fd)
            try:
                _write_all(manifest_fd, payload)
                os.fchmod(manifest_fd, 0o444)
                os.fsync(manifest_fd)
            finally:
                os.close(manifest_fd)
            _seal_directories(stage_fd, control_uid, deadline_file)
            os.fchmod(stage_fd, 0o555)
            _verify_link_graph(stage_fd, rows, control_uid, deadline_file)
            os.fsync(stage_fd)
        finally:
            os.close(stage_fd)
        _time_check(deadline_file)
        _check_source_chain(source_root, chain, allowed_uids)
        try:
            os.stat(snapshot_id, dir_fd=base_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            _refuse("node-snapshot-exists")
        os.rename(stage, snapshot_id, src_dir_fd=base_fd, dst_dir_fd=base_fd)
        stage = None
        committed = True
        return validate_snapshot(snapshot_id, deadline_file, snapshot_base=snapshot_base,
                                 control_uid=control_uid, owner_uid=runner_uid)
    except Exception as error:
        cleanup_ok = True
        cleanup_attempted = committed or stage is not None
        if committed and base_fd is not None:
            try:
                metadata = os.stat(snapshot_id, dir_fd=base_fd, follow_symlinks=False)
                if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != control_uid:
                    _refuse("node-snapshot-cleanup-owner")
                _remove_tree_at(base_fd, snapshot_id, control_uid, deadline_file, cleanup=True)
            except Exception:
                cleanup_ok = False
        elif stage is not None and base_fd is not None:
            try:
                _remove_tree_at(base_fd, stage, control_uid, deadline_file, cleanup=True)
            except Exception:
                cleanup_ok = False
        if not cleanup_ok:
            try:
                error.cleanup_unconfirmed = True
            except Exception:
                pass
        elif cleanup_attempted:
            try:
                error.cleanup_confirmed = True
            except Exception:
                pass
        if isinstance(error, SnapshotRefusal):
            raise
        if isinstance(error, OSError):
            raise SnapshotRefusal("node-snapshot-copy-failed",
                                  cleanup_unconfirmed=not cleanup_ok) from None
        raise
    finally:
        _close_chain(chain)
        if base_chain is not None:
            _close_chain(base_chain)


def _seal_directories(root_fd, control_uid, deadline_file):
    for index, name in enumerate(_bounded_names(root_fd, deadline_file)):
        if name == MANIFEST_NAME:
            continue
        if index % 128 == 0:
            _time_check(deadline_file)
        metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if stat.S_ISDIR(metadata.st_mode):
            child = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=root_fd)
            try:
                _seal_directories(child, control_uid, deadline_file)
                current = os.fstat(child)
                if current.st_uid != control_uid:
                    _refuse("node-snapshot-seal-invalid")
                os.fchmod(child, 0o555)
            finally:
                os.close(child)


def create_snapshot(paths, snapshot_id, owner_uid, deadline_file, *, snapshot_base=None,
                    source_cache_root=None, source_node_root=None, source_anchors=None,
                    test_checkpoint=None):
    if not valid_snapshot_id(snapshot_id):
        _refuse("node-snapshot-id")
    if type(owner_uid) is not int or owner_uid < 1 or owner_uid > 60000:
        _refuse("node-toolchain-owner")
    base = DEFAULT_SNAPSHOT_BASE if snapshot_base is None else Path(snapshot_base)
    return _snapshot_source(
        Path(source_node_root) if source_node_root is not None else
        (Path(source_cache_root) / "node" / "24.22.1" / "x64" if source_cache_root is not None else
         Path("/opt/hostedtoolcache/node/24.22.1/x64")),
        owner_uid, deadline_file, control_uid=os.geteuid(), snapshot_base=base,
        snapshot_id=snapshot_id,
        source_paths=paths,
        source_cache_root=source_cache_root, source_node_root=source_node_root,
        source_anchors=source_anchors, test_checkpoint=test_checkpoint,
    )


def _snapshot_path(snapshot_id, snapshot_base):
    if not valid_snapshot_id(snapshot_id):
        _refuse("node-snapshot-id")
    return Path(snapshot_base) / snapshot_id


def _read_regular_at(directory_fd, name, max_bytes, expected_uid, deadline_file, expected_mode=None,
                     *, cleanup=False):
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | _O_NOFOLLOW, dir_fd=directory_fd)
    except OSError:
        _refuse("node-snapshot-manifest-invalid")
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != expected_uid
                or metadata.st_nlink != 1 or metadata.st_size < 0 or metadata.st_size > max_bytes
                or expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode):
            _refuse("node-snapshot-manifest-invalid")
        chunks = []
        total = 0
        while True:
            _time_check(deadline_file, cleanup=cleanup)
            chunk = os.read(fd, min(CHUNK_SIZE, max_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                _refuse("node-snapshot-limit")
        if total != metadata.st_size or _metadata_token(metadata) != _metadata_token(os.fstat(fd)):
            _refuse("node-snapshot-manifest-invalid")
        return b"".join(chunks)
    finally:
        os.close(fd)


def _snapshot_entries(root_fd, prefix, deadline_file, rows, totals, control_uid, *, cleanup=False):
    before = _secure_directory(root_fd, frozenset((control_uid,)), exact_mode=0o555 if prefix else None)
    names = _bounded_names(
        root_fd, deadline_file, cleanup=cleanup, read_error="node-snapshot-content-invalid",
    )
    if not prefix:
        if MANIFEST_NAME not in names:
            _refuse("node-snapshot-manifest-invalid")
        names.remove(MANIFEST_NAME)
    for index, name in enumerate(names):
        if index % 128 == 0:
            _time_check(deadline_file, cleanup=cleanup)
        if name in (".", "..") or "/" in name:
            _refuse("node-snapshot-content-invalid")
        relative = name if not prefix else prefix + "/" + name
        metadata = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        if metadata.st_uid != control_uid:
            _refuse("node-snapshot-seal-invalid")
        if stat.S_ISDIR(metadata.st_mode):
            if stat.S_IMODE(metadata.st_mode) != 0o555:
                _refuse("node-snapshot-seal-invalid")
            child = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=root_fd)
            try:
                _snapshot_entries(child, relative, deadline_file, rows, totals, control_uid,
                                  cleanup=cleanup)
            finally:
                os.close(child)
            _append_row(rows, {"path": relative, "kind": "directory", "mode": 0o555}, totals)
        elif stat.S_ISREG(metadata.st_mode):
            mode = stat.S_IMODE(metadata.st_mode)
            if mode not in (0o444, 0o555) or metadata.st_nlink != 1:
                _refuse("node-snapshot-seal-invalid")
            try:
                fd = os.open(name, os.O_RDONLY | os.O_NONBLOCK | _O_NOFOLLOW, dir_fd=root_fd)
            except OSError:
                _refuse("node-snapshot-content-invalid")
            digest = hashlib.sha256()
            size = 0
            try:
                opened = os.fstat(fd)
                if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != control_uid
                        or opened.st_nlink != 1 or stat.S_IMODE(opened.st_mode) != mode
                        or _metadata_token(opened) != _metadata_token(metadata)):
                    _refuse("node-snapshot-content-changed")
                while True:
                    _time_check(deadline_file, cleanup=cleanup)
                    chunk = os.read(fd, CHUNK_SIZE)
                    if not chunk:
                        break
                    size += len(chunk)
                    totals["bytes"] += len(chunk)
                    if totals["bytes"] > MAX_BYTES:
                        _refuse("node-snapshot-limit")
                    digest.update(chunk)
                if size != opened.st_size or _metadata_token(opened) != _metadata_token(os.fstat(fd)):
                    _refuse("node-snapshot-content-changed")
            finally:
                os.close(fd)
            _append_row(rows, {"path": relative, "kind": "file", "mode": mode,
                               "size": size, "sha256": digest.hexdigest()}, totals)
        elif stat.S_ISLNK(metadata.st_mode):
            try:
                target = os.readlink(name, dir_fd=root_fd)
                after = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
            except OSError:
                _refuse("node-snapshot-content-changed")
            if _metadata_token(metadata) != _metadata_token(after) or not _safe_relative_link(relative, target):
                _refuse("node-snapshot-link-invalid")
            _append_row(rows, {"path": relative, "kind": "symlink", "target": target}, totals)
        else:
            _refuse("node-snapshot-content-invalid")
        totals["entries"] += 1
        if totals["entries"] > MAX_ENTRIES:
            _refuse("node-snapshot-limit")
    after = _secure_directory(root_fd, frozenset((control_uid,)), exact_mode=0o555 if prefix else None)
    if prefix and _metadata_token(before) != _metadata_token(after):
        _refuse("node-snapshot-content-changed")


def validate_snapshot(snapshot_id, deadline_file, *, snapshot_base=None, control_uid=None, owner_uid=None,
                      cleanup=False):
    if not valid_snapshot_id(snapshot_id):
        _refuse("node-snapshot-id")
    control_uid = os.geteuid() if control_uid is None else control_uid
    base = DEFAULT_SNAPSHOT_BASE if snapshot_base is None else Path(snapshot_base)
    base_fd, base_chain = _open_snapshot_base(base, control_uid)
    try:
        try:
            root_fd = os.open(snapshot_id, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=base_fd)
        except OSError:
            _refuse("node-snapshot-missing")
        try:
            root_meta = os.fstat(root_fd)
            if root_meta.st_uid != control_uid or stat.S_IMODE(root_meta.st_mode) != 0o555:
                _refuse("node-snapshot-seal-invalid")
            raw = _read_regular_at(
                root_fd, MANIFEST_NAME, min(MAX_BYTES, MAX_MANIFEST_BYTES), control_uid,
                deadline_file, 0o444, cleanup=cleanup,
            )
            manifest = bundle.strict_json(raw, min(MAX_BYTES, 32 * 1024 * 1024))
            keys = {"schema", "snapshot_id", "preparation", "node_version", "npm_version", "runner_uid",
                    "entry_count", "expanded_bytes", "entries", "content_sha256"}
            if (type(manifest) is not dict or set(manifest) != keys or manifest["schema"] != 1
                    or manifest["snapshot_id"] != snapshot_id or manifest["preparation"] != PREPARATION_ID
                    or manifest["node_version"] != "24.22.1" or manifest["npm_version"] != "11.19.1"
                    or type(manifest["runner_uid"]) is not int or not 1 <= manifest["runner_uid"] <= 60000
                    or owner_uid is not None and manifest["runner_uid"] != owner_uid
                    or type(manifest["entries"]) is not list or len(manifest["entries"]) + 1 > MAX_ENTRIES):
                _refuse("node-snapshot-manifest-invalid")
            core = {key: manifest[key] for key in keys if key != "content_sha256"}
            if manifest["content_sha256"] != _entry_digest(core):
                _refuse("node-snapshot-manifest-invalid")
            rows = []
            totals = {"entries": 0, "bytes": 0, "manifest_rows_bytes": 0}
            _snapshot_entries(root_fd, "", deadline_file, rows, totals, control_uid, cleanup=cleanup)
            rows.sort(key=lambda row: row["path"])
            if (totals["bytes"] + len(raw) > MAX_BYTES
                    or rows != manifest["entries"] or totals["entries"] != manifest["entry_count"]
                    or totals["bytes"] != manifest["expanded_bytes"]):
                _refuse("node-snapshot-content-changed")
            _verify_link_graph(root_fd, rows, control_uid, deadline_file, cleanup=cleanup)
            paths = {row["path"]: row for row in rows}
            node = paths.get("bin/node")
            launcher = paths.get("bin/npm")
            npm_cli = paths.get("lib/node_modules/npm/bin/npm-cli.js")
            if (not node or node.get("kind") != "file" or node.get("mode") != 0o555
                    or not launcher or launcher.get("kind") != "symlink"
                    or launcher.get("target") != "../lib/node_modules/npm/bin/npm-cli.js"
                    or not npm_cli or npm_cli.get("kind") != "file"):
                _refuse("node-snapshot-content-invalid")
            root_path = base / snapshot_id
            return {"root": str(root_path), "node": str(root_path / "bin/node"),
                    "npm": str(root_path / "bin/npm"),
                    "npm_cli": str(root_path / "lib/node_modules/npm/bin/npm-cli.js"),
                    "snapshot_id": snapshot_id, "content_sha256": manifest["content_sha256"]}
        finally:
            os.close(root_fd)
    finally:
        _close_chain(base_chain)


def _remove_tree_at(parent_fd, name, control_uid, deadline_file, *, cleanup=False, check_state=None):
    if check_state is None:
        check_state = {"entries": 0}
    check_state["entries"] += 1
    if check_state["entries"] % 128 == 1:
        _time_check(deadline_file, cleanup=cleanup)
    if check_state["entries"] > MAX_ENTRIES:
        _refuse("node-snapshot-cleanup-incomplete")
    try:
        metadata = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    except OSError:
        _refuse("node-snapshot-cleanup-incomplete")
    if metadata.st_uid != control_uid:
        _refuse("node-snapshot-cleanup-owner")
    if stat.S_ISDIR(metadata.st_mode):
        try:
            child = os.open(name, os.O_RDONLY | _O_DIRECTORY | _O_NOFOLLOW, dir_fd=parent_fd)
        except OSError:
            _refuse("node-snapshot-cleanup-incomplete")
        try:
            opened = os.fstat(child)
            if opened.st_dev != metadata.st_dev or opened.st_ino != metadata.st_ino:
                _refuse("node-snapshot-cleanup-incomplete")
            os.fchmod(child, 0o700)
            for member in _bounded_names(
                    child, deadline_file, cleanup=cleanup,
                    read_error="node-snapshot-cleanup-incomplete"):
                _remove_tree_at(child, member, control_uid, deadline_file, cleanup=cleanup,
                                check_state=check_state)
        finally:
            os.close(child)
        try:
            os.rmdir(name, dir_fd=parent_fd)
        except OSError:
            _refuse("node-snapshot-cleanup-incomplete")
    elif stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        try:
            os.unlink(name, dir_fd=parent_fd)
        except OSError:
            _refuse("node-snapshot-cleanup-incomplete")
    else:
        _refuse("node-snapshot-cleanup-incomplete")


def remove_snapshot(snapshot_id, deadline_file, *, snapshot_base=None, control_uid=None, owner_uid=None):
    if not valid_snapshot_id(snapshot_id):
        _refuse("node-snapshot-id")
    control_uid = os.geteuid() if control_uid is None else control_uid
    base = DEFAULT_SNAPSHOT_BASE if snapshot_base is None else Path(snapshot_base)
    _remaining(deadline_file, cleanup=True)
    try:
        base_fd, chain = _open_snapshot_base(base, control_uid)
    except SnapshotRefusal as error:
        if error.code == "node-snapshot-base-unavailable" and _confirm_snapshot_base_absent(base, control_uid):
            return True
        raise
    try:
        try:
            os.stat(snapshot_id, dir_fd=base_fd, follow_symlinks=False)
        except FileNotFoundError:
            return True
        validate_snapshot(snapshot_id, deadline_file, snapshot_base=base, control_uid=control_uid,
                          owner_uid=owner_uid, cleanup=True)
        _remove_tree_at(base_fd, snapshot_id, control_uid, deadline_file, cleanup=True)
        try:
            os.stat(snapshot_id, dir_fd=base_fd, follow_symlinks=False)
        except FileNotFoundError:
            return True
        _refuse("node-snapshot-cleanup-incomplete")
    finally:
        _close_chain(chain)


