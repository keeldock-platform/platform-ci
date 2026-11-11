"""Streaming byte, deadline and crate-archive limits for the offline resolver."""
from __future__ import annotations

import hashlib
import gzip
import os
import selectors
import ssl
import signal
import stat
import subprocess
import time
import urllib.error
import urllib.request
import zlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import BinaryIO, Callable

CHUNK = 64 * 1024
MAX_RESPONSE_BYTES = 256 * 1024 * 1024
MAX_TOTAL_TRANSFER_BYTES = 8 * 1024 * 1024 * 1024
MAX_INDEX_BYTES = 16 * 1024 * 1024
MAX_TOTAL_INDEX_BYTES = 512 * 1024 * 1024
MAX_INDEX_LINE_BYTES = 1024 * 1024
MAX_INDEX_ROWS = 200_000
MAX_ARCHIVE_MEMBERS = 100_000
MAX_TOTAL_ARCHIVE_MEMBERS = 1_000_000
MAX_ARCHIVE_DEPTH = 32
MAX_MEMBER_EXPANDED_BYTES = 512 * 1024 * 1024
MAX_ARCHIVE_EXPANDED_BYTES = 1024 * 1024 * 1024
MAX_TOTAL_EXPANDED_BYTES = 8 * 1024 * 1024 * 1024
MAX_TAR_EXTENSION_BYTES = 64 * 1024
MAX_TAR_PATH_BYTES = 4096


class Refusal(ValueError):
    """Stable safe refusal code; never carries an input path or parser message."""


def _fail(code: str) -> None:
    raise Refusal(code)


@dataclass
class PhaseBudget:
    """One monotonic phase deadline and transfer/expansion counters."""
    deadline: float
    cleanup_deadline: float | None = None
    total_transfer_limit: int = MAX_TOTAL_TRANSFER_BYTES
    total_expanded_limit: int = MAX_TOTAL_EXPANDED_BYTES
    cancelled: Callable[[], bool] = lambda: False
    transferred: int = 0
    index_bytes: int = 0
    expanded: int = 0
    members: int = 0
    total_member_limit: int = MAX_TOTAL_ARCHIVE_MEMBERS

    @classmethod
    def start(cls, seconds: float, **kwargs) -> "PhaseBudget":
        if type(seconds) not in (int, float) or seconds <= 0:
            _fail("deadline-invalid")
        return cls(time.monotonic() + float(seconds), **kwargs)

    @classmethod
    def from_outer_deadlines(cls, work_deadline: float, cleanup_deadline: float,
                             **kwargs) -> "PhaseBudget":
        now = time.monotonic()
        if (type(work_deadline) not in (int, float) or type(cleanup_deadline) not in (int, float)
                or work_deadline <= now or cleanup_deadline < work_deadline):
            _fail("deadline-invalid")
        return cls(float(work_deadline), float(cleanup_deadline), **kwargs)

    def remaining(self, *, cleanup: bool = False) -> float:
        if not cleanup and self.cancelled():
            _fail("cancelled")
        end = self.cleanup_deadline if cleanup and self.cleanup_deadline is not None else self.deadline
        left = end - time.monotonic()
        if left <= 0:
            _fail("cleanup-deadline" if cleanup else "phase-deadline")
        return left

    def add_transfer(self, amount: int) -> None:
        self.remaining()
        if type(amount) is not int or amount < 0 or self.transferred + amount > self.total_transfer_limit:
            _fail("transfer-budget")
        self.transferred += amount

    def add_expanded(self, amount: int) -> None:
        self.remaining()
        if type(amount) is not int or amount < 0 or self.expanded + amount > self.total_expanded_limit:
            _fail("expanded-budget")
        self.expanded += amount

    def add_index(self, amount: int) -> None:
        self.remaining()
        if (type(amount) is not int or amount < 0
                or self.index_bytes + amount > MAX_TOTAL_INDEX_BYTES):
            _fail("index-aggregate-budget")
        self.index_bytes += amount

    def add_member(self) -> None:
        self.remaining()
        if self.members + 1 > self.total_member_limit:
            _fail("archive-total-member-count")
        self.members += 1


def run_bounded_process(argv: list[str], budget: PhaseBudget, *, cwd: str | Path,
                        env: dict[str, str], stdout=None, stderr=None,
                        expected: int = 0,
                        max_output_bytes: int | None = 8 * 1024 * 1024) -> int:
    """Stream captured output through a byte cap and reap under the outer deadlines."""
    if type(argv) is not list or not argv or any(type(item) is not str for item in argv):
        _fail("process-arguments")
    if (max_output_bytes is not None
            and (type(max_output_bytes) is not int or max_output_bytes < 0)):
        _fail("process-output-limit-invalid")



    budget.remaining()
    try:
        process = subprocess.Popen(
            argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL if stdout is None else subprocess.PIPE,
            stderr=subprocess.DEVNULL if stderr is None else subprocess.PIPE,
            close_fds=True, start_new_session=True,
        )
    except OSError:
        _fail("process-start")
    total = 0
    selector = selectors.DefaultSelector()
    streams = []
    for stream, destination in ((process.stdout, stdout), (process.stderr, stderr)):
        if stream is not None:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, destination)
            streams.append(stream)
    try:
        while selector.get_map() or process.poll() is None:
            left = budget.remaining()
            events = selector.select(min(0.05, left)) if selector.get_map() else []
            for key, _mask in events:
                stream = key.fileobj
                destination = key.data
                try:
                    chunk = os.read(stream.fileno(), CHUNK)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    stream.close()
                    continue
                total += len(chunk)
                if max_output_bytes is not None and total > max_output_bytes:
                    _fail("process-output-limit")
                try:
                    written = destination.write(chunk)
                except OSError:
                    _fail("process-output-write")
                if written is not None and written != len(chunk):
                    _fail("process-output-write")
            if not selector.get_map() and process.poll() is None:
                try:
                    process.wait(timeout=min(0.05, max(0.001, left)))
                except subprocess.TimeoutExpired:
                    pass
    except BaseException:
        _terminate_process_group(process, budget)
        raise
    finally:
        selector.close()
        for stream in streams:
            if not stream.closed:
                stream.close()
    try:
        if stdout is not None:
            stdout.flush()
        if stderr is not None:
            stderr.flush()
    except OSError:
        _fail("process-output-write")
    result = process.poll()
    if result != expected:
        _fail("process-exit")
    return result


def _terminate_process_group(process: subprocess.Popen, budget: PhaseBudget) -> None:
    """Terminate descendants and reap within the outer cleanup reserve."""
    pgid = process.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except OSError:
        _fail("process-cleanup")
    try:
        end = time.monotonic() + min(2.0, budget.remaining(cleanup=True))
    except Refusal:
        _fail("process-cleanup-deadline")
    while time.monotonic() < end:
        try:
            process.wait(timeout=min(0.05, max(0.001, end - time.monotonic())))
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(pgid, 0)
        except ProcessLookupError:
            return
        except OSError:
            break
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        _fail("process-cleanup")
    try:
        process.wait(timeout=min(3.0, budget.remaining(cleanup=True)))
    except (subprocess.TimeoutExpired, Refusal):
        _fail("process-cleanup-incomplete")
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return
    except OSError:
        return
    _fail("process-descendant-remains")


def remove_tree_bounded(path: str | Path, budget: PhaseBudget) -> None:
    """Remove a trusted scratch tree without following links and within cleanup reserve."""
    root = Path(path)
    try:
        root_info = root.lstat()
    except FileNotFoundError:
        return
    except OSError:
        _fail("cleanup-stat")
    if not root.is_absolute():
        _fail("cleanup-path")
    pending: list[tuple[Path, bool]] = [(root, False)]
    while pending:
        budget.remaining(cleanup=True)
        item, visited = pending.pop()
        try:
            metadata = item.lstat()
            if stat.S_ISLNK(metadata.st_mode) or stat.S_ISREG(metadata.st_mode):
                item.unlink()
            elif stat.S_ISDIR(metadata.st_mode):
                if visited:
                    item.rmdir()
                else:
                    pending.append((item, True))
                    with os.scandir(item) as entries:
                        children = [Path(entry.path) for entry in entries]
                    for child in reversed(children):
                        pending.append((child, False))
            else:
                _fail("cleanup-member-type")
        except Refusal:
            raise
        except OSError:
            _fail("cleanup-failed")
    if root.exists() or root.is_symlink():
        _fail("cleanup-tree-remains")


def read_index_lines(source: BinaryIO, budget: PhaseBudget, *, count_transfer: bool = True,
                     count_index: bool = True):
    """Yield bounded index lines while enforcing per-index, aggregate and row caps."""
    current_bytes = 0
    rows = 0
    while True:
        budget.remaining()
        line = source.readline(MAX_INDEX_LINE_BYTES + 1)
        if not line:
            return
        if type(line) is not bytes or len(line) > MAX_INDEX_LINE_BYTES:
            _fail("index-line-size")
        current_bytes += len(line)
        if current_bytes > MAX_INDEX_BYTES:
            _fail("index-file-size")
        if count_index:
            budget.add_index(len(line))
        if count_transfer:
            budget.add_transfer(len(line))
        rows += 1
        if rows > MAX_INDEX_ROWS:
            _fail("index-row-count")
        yield line


def stream_to_new_file(source: BinaryIO, destination: str | Path,
                       maximum: int, budget: PhaseBudget) -> tuple[int, str]:
    """Copy a response in bounded chunks while hashing; never hold the archive in memory."""
    if type(maximum) is not int or maximum <= 0 or maximum > MAX_RESPONSE_BYTES:
        _fail("response-limit")
    output = Path(destination)
    if output.exists() or output.is_symlink():
        _fail("destination-exists")
    try:
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError:
        _fail("destination-open")
    digest = hashlib.sha256()
    count = 0
    try:
        with os.fdopen(descriptor, "wb", closefd=True) as target:
            while True:
                budget.remaining()
                chunk = source.read(CHUNK)
                if not chunk:
                    break
                if type(chunk) is not bytes:
                    _fail("response-type")
                count += len(chunk)
                if count > maximum:
                    _fail("response-size")
                budget.add_transfer(len(chunk))
                digest.update(chunk)
                try:
                    target.write(chunk)
                except OSError:
                    _fail("disk-write")
            target.flush()
            os.fsync(target.fileno())
    except Refusal:
        try:
            output.unlink(missing_ok=True)
        except OSError:
            _fail("partial-file-cleanup")
        raise
    except (OSError, TimeoutError):
        try:
            output.unlink(missing_ok=True)
        except OSError:
            _fail("partial-file-cleanup")
        _fail("stream-read")
    return count, digest.hexdigest()


def fetch_official_to_new_file(url: str, destination: str | Path, maximum: int,
                               budget: PhaseBudget) -> tuple[int, str]:
    """Stream one response through the existing crates.io host and redirect policy."""
    import registry_prefetch

    if type(maximum) is not int or maximum <= 0 or maximum > MAX_RESPONSE_BYTES:
        _fail("response-limit")
    if not registry_prefetch._safe_url(url):
        _fail("registry-url")
    output = Path(destination)
    if output.exists() or output.is_symlink():
        _fail("destination-exists")
    output.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        registry_prefetch._RestrictedRedirect(),
    )
    request = urllib.request.Request(url, headers={
        "Accept-Encoding": "identity",
        "User-Agent": "keeldock-platform-registry/1",
    })
    try:
        timeout = min(5.0, budget.remaining())
        with opener.open(request, timeout=timeout) as response:
            if response.status != 200 or not registry_prefetch._safe_url(response.geturl()):
                _fail("registry-response")
            encoding = response.headers.get("Content-Encoding", "identity").lower()
            if encoding not in ("", "identity"):
                _fail("registry-encoding")
            length = response.headers.get("Content-Length")
            if length is not None and (not length.isascii() or not length.isdecimal()
                                       or int(length) > maximum):
                _fail("registry-response-size")
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL
                                 | getattr(os, "O_NOFOLLOW", 0), 0o600)
            digest = hashlib.sha256()
            count = 0
            try:
                with os.fdopen(descriptor, "wb", closefd=True) as target:
                    while True:
                        budget.remaining()
                        chunk = response.read(CHUNK)
                        if not chunk:
                            break
                        count += len(chunk)
                        if count > maximum:
                            _fail("registry-response-size")
                        budget.add_transfer(len(chunk))
                        digest.update(chunk)
                        try:
                            target.write(chunk)
                        except OSError:
                            _fail("disk-write")
                    target.flush()
                    os.fsync(target.fileno())
            except Refusal:
                try:
                    output.unlink(missing_ok=True)
                except OSError:
                    _fail("partial-file-cleanup")
                raise
            return count, digest.hexdigest()
    except Refusal:
        raise
    except (OSError, TimeoutError, urllib.error.URLError, ValueError):
        try:
            output.unlink(missing_ok=True)
        except OSError:
            _fail("partial-file-cleanup")
        _fail("registry-fetch")


def scan_crate_archive(path: str | Path, budget: PhaseBudget,
                       *, maximum_compressed: int = MAX_RESPONSE_BYTES) -> dict[str, int | str]:
    """Parse tar headers incrementally without tarfile's unbounded PAX allocations."""
    archive = Path(path)
    try:
        metadata = archive.lstat()
    except OSError:
        _fail("archive-file")
    if not stat.S_ISREG(metadata.st_mode):
        _fail("archive-file")
    try:
        compressed = metadata.st_size
    except OSError:
        _fail("archive-stat")
    if compressed <= 0 or compressed > maximum_compressed:
        _fail("archive-compressed-size")
    members = 0
    expanded = 0
    root_name: str | None = None

    def read_bytes(stream, count: int) -> bytes:
        nonlocal expanded
        if type(count) is not int or count < 0:
            _fail("archive-read-size")
        result = bytearray()
        while len(result) < count:
            budget.remaining()
            piece = stream.read(min(CHUNK, count - len(result)))
            if not piece:
                _fail("archive-truncated")
            expanded += len(piece)
            if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
                _fail("archive-expanded-size")
            budget.add_expanded(len(piece))
            result.extend(piece)
        return bytes(result)

    def skip_bytes(stream, count: int) -> None:
        nonlocal expanded
        remaining = count
        while remaining:
            budget.remaining()
            piece = stream.read(min(CHUNK, remaining))
            if not piece:
                _fail("archive-truncated")
            expanded += len(piece)
            if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
                _fail("archive-expanded-size")
            budget.add_expanded(len(piece))
            remaining -= len(piece)

    def octal(field: bytes) -> int:
        value = field.strip(b"\x00 ")
        if not value:
            return 0
        if any(byte < 48 or byte > 55 for byte in value):
            _fail("archive-header-number")
        return int(value, 8)

    def pax_rows(payload: bytes) -> dict[str, str]:
        rows: dict[str, str] = {}
        offset = 0
        allowed = {"path", "size", "mtime", "atime", "ctime", "uid", "gid", "uname", "gname", "comment"}
        while offset < len(payload):
            space = payload.find(b" ", offset)
            if space <= offset or space - offset > 10:
                _fail("archive-pax-record")
            digits = payload[offset:space]
            if not digits.isdigit():
                _fail("archive-pax-record")
            length = int(digits)
            end = offset + length
            if length <= space - offset + 2 or end > len(payload) or payload[end - 1:end] != b"\n":
                _fail("archive-pax-record")
            field = payload[space + 1:end - 1]
            key, separator, value = field.partition(b"=")
            if not separator:
                _fail("archive-pax-record")
            try:
                key_text = key.decode("ascii", "strict")
                value_text = value.decode("utf-8", "strict")
            except UnicodeDecodeError:
                _fail("archive-pax-encoding")
            if key_text not in allowed or key_text in rows or "\x00" in value_text:
                _fail("archive-pax-key")
            if key_text == "path" and not value_text:
                _fail("archive-pax-path")
            if key_text == "size" and (not value_text.isascii() or not value_text.isdecimal()):
                _fail("archive-pax-size")
            rows[key_text] = value_text
            if len(rows) > 32:
                _fail("archive-pax-count")
            offset = end
        return rows

    def validate_name(name: str, pending_path: str | None) -> tuple[str, str]:
        value = pending_path if pending_path is not None else name
        if (not value or "\\" in value or "\x00" in value
                or len(value.encode("utf-8", "strict")) > MAX_TAR_PATH_BYTES):
            _fail("archive-member-name")
        normalized = value.rstrip("/")
        parts = normalized.split("/")
        if (not normalized or normalized.startswith("/")
                or any(part in ("", ".", "..") for part in parts)):
            _fail("archive-member-path")
        if len(parts) > MAX_ARCHIVE_DEPTH:
            _fail("archive-member-depth")
        return normalized, parts[0]

    try:
        with archive.open("rb") as raw, gzip.GzipFile(fileobj=raw, mode="rb") as stream:
            pending_pax: dict[str, str] = {}
            pending_long_name: str | None = None
            zero_blocks = 0
            while True:
                budget.remaining()
                header = read_bytes(stream, 512)
                if header == bytes(512):
                    zero_blocks += 1
                    if zero_blocks == 2:
                        break
                    continue
                if zero_blocks:
                    _fail("archive-end-marker")
                members += 1
                if members > MAX_ARCHIVE_MEMBERS:
                    _fail("archive-member-count")
                budget.add_member()
                recorded_checksum = octal(header[148:156])
                checksum_header = header[:148] + (b" " * 8) + header[156:]
                if sum(checksum_header) != recorded_checksum:
                    _fail("archive-header-checksum")
                name_bytes = header[0:100].split(b"\x00", 1)[0]
                prefix_bytes = header[345:500].split(b"\x00", 1)[0]
                if prefix_bytes:
                    name_bytes = prefix_bytes + b"/" + name_bytes
                try:
                    header_name = name_bytes.decode("utf-8", "strict")
                except UnicodeDecodeError:
                    _fail("archive-member-encoding")
                size = octal(header[124:136])
                kind = header[156:157]
                if kind == b"x":
                    if pending_pax or pending_long_name is not None or size > MAX_TAR_EXTENSION_BYTES:
                        _fail("archive-extension-size")
                    extension = read_bytes(stream, size)
                    padding = (-size) % 512
                    if padding:
                        skip_bytes(stream, padding)
                    pending_pax = pax_rows(extension)
                    continue
                if kind == b"L":
                    if pending_long_name is not None or size > MAX_TAR_PATH_BYTES + 1:
                        _fail("archive-extension-size")
                    extension = read_bytes(stream, size)
                    if extension.endswith(b"\x00"):
                        extension = extension[:-1]
                    try:
                        pending_long_name = extension.decode("utf-8", "strict")
                    except UnicodeDecodeError:
                        _fail("archive-member-encoding")
                    padding = (-size) % 512
                    if padding:
                        skip_bytes(stream, padding)
                    continue
                if kind in (b"K", b"g"):
                    _fail("archive-special-member")
                name, first_component = validate_name(
                    header_name, pending_pax.get("path") or pending_long_name,
                )
                if "size" in pending_pax and int(pending_pax["size"]) != size:
                    _fail("archive-pax-size-mismatch")
                if root_name is None:
                    root_name = first_component
                if first_component != root_name:
                    _fail("archive-root-mismatch")
                if kind == b"5":
                    if size != 0:
                        _fail("archive-directory-size")
                    pending_pax = {}
                    pending_long_name = None
                    continue
                if kind not in (b"\x00", b"0"):
                    _fail("archive-special-member")
                if size > MAX_MEMBER_EXPANDED_BYTES:
                    _fail("archive-member-size")
                skip_bytes(stream, size)
                padding = (-size) % 512
                if padding:
                    skip_bytes(stream, padding)
                pending_pax = {}
                pending_long_name = None
            if zero_blocks != 2 or pending_pax or pending_long_name is not None or members == 0:
                _fail("archive-end-marker")
            while True:
                budget.remaining()
                suffix = stream.read(CHUNK)
                if not suffix:
                    break
                expanded += len(suffix)
                if expanded > MAX_ARCHIVE_EXPANDED_BYTES:
                    _fail("archive-expanded-size")
                budget.add_expanded(len(suffix))
                if any(suffix):
                    _fail("archive-trailing-data")
    except Refusal:
        raise
    except (OSError, EOFError, gzip.BadGzipFile, ValueError):
        _fail("archive-parse")
    if root_name is None:
        _fail("archive-empty")
    return {"members": members, "compressed_bytes": compressed,
            "expanded_bytes": expanded, "root": root_name}


def _index_subset(name: str, source: BinaryIO, wanted: dict[str, str],
                  budget: PhaseBudget) -> bytes:
    import json
    import registry_prefetch

    selected = {}
    for line in read_index_lines(source, budget, count_transfer=False):
        if not line.endswith(b"\n"):
            _fail("registry-index-line-termination")
        try:
            row = json.loads(line.decode("utf-8", "strict"),
                             object_pairs_hook=registry_prefetch._unique_pairs)
        except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
            _fail("registry-index-parse")
        if type(row) is not dict or row.get("name") != name:
            continue
        version = row.get("vers")
        if type(version) is not str or version not in wanted:
            continue
        checksum = row.get("cksum")
        if (set(row) - registry_prefetch.INDEX_FIELDS
                or not {"name", "vers", "deps", "cksum", "yanked"}.issubset(row)
                or type(checksum) is not str or checksum != wanted[version]
                or type(row.get("yanked")) is not bool or row["yanked"]
                or not registry_prefetch._valid_index_fields(row)):
            _fail("registry-index-record")
        if version in selected:
            _fail("registry-index-duplicate")
        selected[version] = row
    if set(selected) != set(wanted):
        _fail("registry-index-missing")

    def version_key(value: str) -> tuple[int, int, int]:
        return tuple(int(part) for part in value.split("."))

    output = bytearray()
    for version in sorted(selected, key=version_key):
        output.extend(json.dumps(selected[version], ensure_ascii=True, sort_keys=True,
                                 separators=(",", ":")).encode("ascii") + b"\n")
        if len(output) > MAX_INDEX_BYTES:
            _fail("registry-index-output-size")
    return bytes(output)


def verify_bounded_registry_tree(directory: str | Path, expected_packages: object,
                                 budget: PhaseBudget) -> dict[str, int]:
    """Recompute exact index/archive/member/expanded totals from the finished inventory."""
    import registry_prefetch

    rows = registry_prefetch._validate_packages(expected_packages)
    root = Path(directory)
    if not root.is_absolute() or root.is_symlink() or not root.is_dir():
        _fail("registry-tree")
    expected_crates = {row["name"] + "-" + row["version"] + ".crate": row for row in rows}
    by_name: dict[str, list[dict[str, str]]] = {}
    for row in rows:
        by_name.setdefault(row["name"], []).append(row)
    expected_indexes = {registry_prefetch.crate_index_path(name): items for name, items in by_name.items()}
    expected_directories = {"index"}
    for index_path in expected_indexes:
        parts = Path("index", index_path).parts
        for count in range(1, len(parts)):
            expected_directories.add(Path(*parts[:count]).as_posix())
    seen_crates: set[str] = set()
    seen_indexes: set[str] = set()
    seen_directories: set[str] = set()
    seen_config = False
    aggregate_archive = 0
    aggregate_expanded = 0
    aggregate_members = 0
    aggregate_index = 0
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        budget.remaining()
        base = Path(current)
        relative = base.relative_to(root)
        for name in directories:
            child = base / name
            if child.is_symlink():
                _fail("registry-symlink")
            rel = child.relative_to(root).as_posix()
            if rel not in expected_directories:
                _fail("registry-directory-extra")
            seen_directories.add(rel)
        for name in files:
            budget.remaining()
            path = base / name
            if path.is_symlink() or not path.is_file():
                _fail("registry-file")
            if relative.parts and relative.parts[0] == "index":
                index_rel = path.relative_to(root / "index").as_posix()
                if index_rel == "config.json":
                    if path.stat().st_size > 4096 or path.read_bytes() != registry_prefetch.LOCAL_INDEX_CONFIG:
                        _fail("registry-config-drift")
                    budget.add_transfer(path.stat().st_size)
                    seen_config = True
                    continue
                expected = expected_indexes.get(index_rel)
                if expected is None:
                    _fail("registry-index-extra")
                if path.stat().st_size > MAX_INDEX_BYTES:
                    _fail("registry-index-size")
                wanted = {row["version"]: row["checksum"] for row in expected}
                with path.open("rb") as source:
                    normalized = _index_subset(expected[0]["name"], source, wanted, budget)
                if path.stat().st_size != len(normalized):
                    _fail("registry-index-drift")
                with path.open("rb") as source:


                    offset = 0
                    while True:
                        budget.remaining()
                        chunk = source.read(CHUNK)
                        if not chunk:
                            break
                        if normalized[offset:offset + len(chunk)] != chunk:
                            _fail("registry-index-drift")
                        offset += len(chunk)
                seen_indexes.add(index_rel)
                aggregate_index += len(normalized)
            elif relative == Path("."):
                row = expected_crates.get(name)
                if row is None:
                    _fail("registry-crate-extra")
                digest = hashlib.sha256()
                size = 0
                with path.open("rb") as source:
                    while True:
                        budget.remaining()
                        chunk = source.read(CHUNK)
                        if not chunk:
                            break
                        size += len(chunk)
                        aggregate_archive += len(chunk)
                        if size > registry_prefetch.MAX_CRATE_BYTES:
                            _fail("registry-crate-size")
                        budget.add_transfer(len(chunk))
                        digest.update(chunk)
                if digest.hexdigest() != row["checksum"]:
                    _fail("registry-crate-checksum")
                scan = scan_crate_archive(path, budget, maximum_compressed=registry_prefetch.MAX_CRATE_BYTES)
                aggregate_expanded += int(scan["expanded_bytes"])
                aggregate_members += int(scan["members"])
                seen_crates.add(name)
            else:
                _fail("registry-path")
    if (not seen_config or seen_crates != set(expected_crates)
            or seen_indexes != set(expected_indexes) or seen_directories != expected_directories):
        _fail("registry-incomplete")
    if aggregate_index > MAX_TOTAL_INDEX_BYTES or aggregate_archive > MAX_TOTAL_TRANSFER_BYTES:
        _fail("registry-aggregate-size")
    return {"index_bytes": aggregate_index, "archive_bytes": aggregate_archive,
            "expanded_bytes": aggregate_expanded, "members": aggregate_members}


def build_bounded_registry(packages: object, destination: str | Path,
                           budget: PhaseBudget) -> tuple[list[dict[str, str]], dict[str, int]]:
    """Build the crates.io local registry with streamed bodies and exact revalidation."""
    import registry_prefetch

    rows = registry_prefetch._validate_packages(packages)
    root = Path(destination)
    if not root.is_absolute() or root.exists() or root.is_symlink():
        _fail("registry-root-exists")
    root.mkdir(mode=0o700, parents=True)
    (root / "index").mkdir(mode=0o700)
    try:
        registry_prefetch._write_new(root / "index" / "config.json", registry_prefetch.LOCAL_INDEX_CONFIG)
        by_name: dict[str, list[dict[str, str]]] = {}
        for row in rows:
            by_name.setdefault(row["name"], []).append(row)
        for name, entries in sorted(by_name.items()):
            budget.remaining()
            wanted = {row["version"]: row["checksum"] for row in entries}
            temporary = root / (".index-" + hashlib.sha256(name.encode("ascii")).hexdigest())
            url = "https://" + registry_prefetch.INDEX_HOST + "/" + registry_prefetch.crate_index_path(name)
            fetch_official_to_new_file(url, temporary, MAX_INDEX_BYTES, budget)
            try:
                with temporary.open("rb") as source:
                    filtered = _index_subset(name, source, wanted, budget)
            finally:
                temporary.unlink(missing_ok=True)
            registry_prefetch._write_new(
                root / "index" / registry_prefetch.crate_index_path(name), filtered)
        for row in rows:
            budget.remaining()
            archive = root / (row["name"] + "-" + row["version"] + ".crate")
            url = registry_prefetch._crate_url(row["name"], row["version"])
            _size, digest = fetch_official_to_new_file(
                url, archive, registry_prefetch.MAX_CRATE_BYTES, budget)
            if digest != row["checksum"]:
                archive.unlink(missing_ok=True)
                _fail("registry-crate-checksum")
        verified_budget = PhaseBudget(
            deadline=budget.deadline, cleanup_deadline=budget.cleanup_deadline,
            total_transfer_limit=budget.total_transfer_limit,
            total_expanded_limit=budget.total_expanded_limit,
            cancelled=budget.cancelled, total_member_limit=budget.total_member_limit,
        )
        inventory = verify_bounded_registry_tree(root, rows, verified_budget)



        budget.add_expanded(inventory["expanded_bytes"])
        for _ in range(inventory["members"]):
            budget.add_member()
        return rows, inventory
    except Refusal:
        try:
            remove_tree_bounded(root, budget)
        except Refusal:
            _fail("registry-build-cleanup")
        raise
    except (OSError, TimeoutError, gzip.BadGzipFile, zlib.error, ValueError):
        try:
            remove_tree_bounded(root, budget)
        except Refusal:
            _fail("registry-build-cleanup")
        _fail("registry-build-failed")
