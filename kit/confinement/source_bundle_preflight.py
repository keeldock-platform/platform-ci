"""Bound a Git bundle before a privileged Git parser sees its objects."""

import hashlib
import io
import re
import tempfile
import time
import zlib
from dataclasses import dataclass
from typing import Optional, Union


CHUNK_BYTES = 65536
HEADER_LINE_BYTES = 4096
HEADER_BYTES = 8 * 1024 * 1024
OBJECT_TYPES = {1: "commit", 2: "tree", 3: "blob", 4: "tag"}
HEX_BYTES = frozenset(b"0123456789abcdef")
REF_PATTERN = re.compile(rb"(?:HEAD|refs/[A-Za-z0-9._/-]+)\Z")
REFUSAL_REASONS = frozenset((
    "input-invalid", "input-size-limit", "input-error", "bundle-header-invalid",
    "pack-header-invalid", "object-count-limit", "object-type-invalid",
    "object-size-limit", "total-inflated-limit", "total-expanded-limit",
    "object-invalid", "delta-base-invalid", "delta-depth-limit", "thin-pack",
    "checksum-mismatch", "trailing-data", "truncated", "resource-limit",
    "internal-error",
))


@dataclass(frozen=True)
class BundleLimits:
    max_input_bytes: int = 268435448
    max_objects: int = 100000
    max_blob_bytes: int = 64 * 1024 * 1024
    max_metadata_bytes: int = 16 * 1024 * 1024
    max_total_inflated_bytes: int = 2 * 1024 * 1024 * 1024
    max_delta_depth: int = 32
    max_scratch_bytes: int = 3 * 1024 * 1024 * 1024
    max_cpu_seconds: int = 600
    max_wall_seconds: int = 600


@dataclass(frozen=True)
class Accepted:
    object_count: int
    total_inflated_bytes: int
    total_expanded_bytes: int
    bundle_sha256: str

    accepted: bool = True


@dataclass(frozen=True)
class Refused:
    reason: str

    accepted: bool = False


PreflightResult = Union[Accepted, Refused]


class _Refusal(Exception):
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def _refuse(reason):
    raise _Refusal(reason)


class _Deadline:
    def __init__(self, limits):
        self.wall_end = time.monotonic() + limits.max_wall_seconds
        self.cpu_end = time.process_time() + limits.max_cpu_seconds

    def check(self):
        if time.monotonic() > self.wall_end or time.process_time() > self.cpu_end:
            _refuse("resource-limit")


def _limits_valid(limits):
    defaults = BundleLimits()
    if type(limits) is not BundleLimits:
        return False
    for name in defaults.__dataclass_fields__:
        value = getattr(limits, name)
        if type(value) is not int or not 1 <= value <= getattr(defaults, name):
            return False
    return True


def _spool(source, target, limits, deadline):
    if type(source) is bytes:
        if len(source) > limits.max_input_bytes:
            _refuse("input-size-limit")
        blocks = (source[start:start + CHUNK_BYTES] for start in range(0, len(source), CHUNK_BYTES))
    elif hasattr(source, "read"):
        def stream_blocks():
            while True:
                try:
                    block = source.read(CHUNK_BYTES)
                except Exception:
                    _refuse("input-error")
                if type(block) is not bytes or len(block) > CHUNK_BYTES:
                    _refuse("input-invalid")
                if not block:
                    return
                yield block

        blocks = stream_blocks()
    else:
        _refuse("input-invalid")
    digest = hashlib.sha256()
    count = 0
    for block in blocks:
        deadline.check()
        count += len(block)
        if count > limits.max_input_bytes:
            _refuse("input-size-limit")
        if count > limits.max_scratch_bytes:
            _refuse("resource-limit")
        target.write(block)
        digest.update(block)
    target.seek(0)
    return count, digest.hexdigest()


def _header_line(source):
    line = source.readline(HEADER_LINE_BYTES + 1)
    if not line or not line.endswith(b"\n") or len(line) > HEADER_LINE_BYTES:
        _refuse("bundle-header-invalid")
    if b"\r" in line or b"\x00" in line:
        _refuse("bundle-header-invalid")
    return line


def _hex_id(raw, size):
    return len(raw) == size and all(byte in HEX_BYTES for byte in raw)


def _bundle_header(source, limits, deadline):
    magic = _header_line(source)
    marker = bytes((35,))
    if magic == marker + b" v2 git bundle\n":
        version = 2
    elif magic == marker + b" v3 git bundle\n":
        version = 3
    else:
        _refuse("bundle-header-invalid")
    algorithm = "sha1"
    capability_seen = False
    records_seen = False
    refs_seen = False
    ref_names = set()
    ref_ids = set()
    prerequisites = set()
    while True:
        deadline.check()
        line = _header_line(source)
        if source.tell() > HEADER_BYTES:
            _refuse("bundle-header-invalid")
        if line == b"\n":
            if not refs_seen:
                _refuse("bundle-header-invalid")
            return algorithm, ref_ids
        value = line[:-1]
        if value.startswith(b"@"):
            if version != 3 or capability_seen or records_seen:
                _refuse("bundle-header-invalid")
            if value == b"@object-format=sha1":
                algorithm = "sha1"
            elif value == b"@object-format=sha256":
                algorithm = "sha256"
            else:
                _refuse("bundle-header-invalid")
            capability_seen = True
            continue
        records_seen = True
        id_size = 40 if algorithm == "sha1" else 64
        if value.startswith(b"-"):
            if refs_seen or len(value) < id_size + 2:
                _refuse("bundle-header-invalid")
            object_id = value[1:1 + id_size]
            suffix = value[1 + id_size:]
            if not _hex_id(object_id, id_size) or not suffix.startswith(b" "):
                _refuse("bundle-header-invalid")
            if any(byte < 32 or byte > 126 for byte in suffix[1:]):
                _refuse("bundle-header-invalid")
            if object_id in prerequisites:
                _refuse("bundle-header-invalid")
            prerequisites.add(object_id)
            continue
        if len(value) < id_size + 2 or value[id_size:id_size + 1] != b" ":
            _refuse("bundle-header-invalid")
        if not _hex_id(value[:id_size], id_size):
            _refuse("bundle-header-invalid")
        name = value[id_size + 1:]
        if REF_PATTERN.fullmatch(name) is None or b".." in name or b"//" in name:
            _refuse("bundle-header-invalid")
        if name.endswith(b"/") or name.endswith(b"."):
            _refuse("bundle-header-invalid")
        if name in ref_names:
            _refuse("bundle-header-invalid")
        ref_names.add(name)
        ref_ids.add(bytes.fromhex(value[:id_size].decode("ascii")))
        refs_seen = True


def _pack_read(source, size, digest):
    block = source.read(size)
    if len(block) != size:
        _refuse("truncated")
    digest.update(block)
    return block


def _pack_byte(source, digest):
    return _pack_read(source, 1, digest)[0]


def _object_header(source, digest, limits):
    first = _pack_byte(source, digest)
    kind = (first >> 4) & 7
    if kind not in OBJECT_TYPES and kind not in (6, 7):
        _refuse("object-type-invalid")
    size = first & 15
    shift = 4
    byte = first
    while byte & 128:
        byte = _pack_byte(source, digest)
        size |= (byte & 127) << shift
        shift += 7
        if size > limits.max_blob_bytes or shift > 70:
            _refuse("object-size-limit")
    maximum = limits.max_blob_bytes if kind in (3, 6, 7) else limits.max_metadata_bytes
    if size > maximum:
        _refuse("object-size-limit")
    return kind, size


def _ofs_base(source, digest, offset):
    byte = _pack_byte(source, digest)
    distance = byte & 127
    while byte & 128:
        byte = _pack_byte(source, digest)
        distance = ((distance + 1) << 7) | (byte & 127)
        if distance > offset:
            _refuse("delta-base-invalid")
    if not 0 < distance <= offset:
        _refuse("delta-base-invalid")
    return offset - distance


def _inflate(source, declared, maximum, total_remaining, digest, sink, deadline):
    inflater = zlib.decompressobj()
    emitted = 0
    start = source.tell()
    while True:
        deadline.check()
        block_start = source.tell()
        block = source.read(CHUNK_BYTES)
        if not block:
            _refuse("truncated")
        allowance = min(CHUNK_BYTES, maximum - emitted, declared - emitted, total_remaining - emitted)
        probe = allowance == 0
        try:
            output = inflater.decompress(block, 1 if probe else allowance)
        except zlib.error:
            _refuse("object-invalid")
        used = len(block) - len(inflater.unused_data if inflater.eof else inflater.unconsumed_tail)
        if used < 0 or used > len(block):
            _refuse("object-invalid")
        source.seek(block_start + used)
        if digest is not None:
            digest.update(block[:used])
        if emitted + len(output) > maximum:
            _refuse("object-size-limit")
        if emitted + len(output) > total_remaining:
            _refuse("total-inflated-limit")
        if emitted + len(output) > declared:
            _refuse("object-invalid")
        if output:
            sink(output)
            emitted += len(output)
        if inflater.eof:
            if emitted != declared:
                _refuse("object-invalid")
            return source.tell() - start
        if not used and not output:
            _refuse("object-invalid")


@dataclass
class _Entry:
    offset: int
    kind: int
    declared: int
    compressed_start: int
    compressed_end: int
    base_offset: Optional[int] = None
    base_id: Optional[bytes] = None
    resolved_kind: Optional[int] = None
    result_size: int = 0
    result_offset: int = 0
    object_id: Optional[bytes] = None
    depth: int = 0


def _object_digest(kind, size, algorithm):
    digest = hashlib.new(algorithm)
    digest.update((OBJECT_TYPES[kind] + " " + str(size)).encode("ascii") + b"\x00")
    return digest


def _read_varint(source, deadline):
    value = 0
    shift = 0
    while True:
        deadline.check()
        byte = source.read(1)
        if not byte:
            _refuse("object-invalid")
        value |= (byte[0] & 127) << shift
        if shift > 70:
            _refuse("object-invalid")
        if not byte[0] & 128:
            return value
        shift += 7


def _apply_delta(delta, objects, base, target_size, digest, deadline):
    produced = 0
    position = delta.tell()
    end = delta.seek(0, io.SEEK_END)
    delta.seek(position)
    while delta.tell() < end:
        deadline.check()
        opcode = delta.read(1)
        if not opcode:
            _refuse("object-invalid")
        command = opcode[0]
        if command & 128:
            offset = 0
            size = 0
            for bit in range(4):
                if command & (1 << bit):
                    byte = delta.read(1)
                    if not byte:
                        _refuse("object-invalid")
                    offset |= byte[0] << (8 * bit)
            for bit in range(3):
                if command & (1 << (bit + 4)):
                    byte = delta.read(1)
                    if not byte:
                        _refuse("object-invalid")
                    size |= byte[0] << (8 * bit)
            if size == 0:
                size = 65536
            if offset + size > base.result_size or produced + size > target_size:
                _refuse("object-invalid")
            while size:
                deadline.check()
                count = min(size, CHUNK_BYTES)
                objects.seek(base.result_offset + offset)
                block = objects.read(count)
                if len(block) != count:
                    _refuse("internal-error")
                objects.seek(0, io.SEEK_END)
                objects.write(block)
                digest.update(block)
                offset += count
                size -= count
                produced += count
        elif command:
            if produced + command > target_size:
                _refuse("object-invalid")
            block = delta.read(command)
            if len(block) != command:
                _refuse("object-invalid")
            objects.seek(0, io.SEEK_END)
            objects.write(block)
            digest.update(block)
            produced += command
        else:
            _refuse("object-invalid")
    if produced != target_size:
        _refuse("object-invalid")


def _resolve_delta(entry, base, bundle, objects, limits, input_size, expanded, algorithm, deadline):
    depth = base.depth + 1
    if depth > limits.max_delta_depth:
        _refuse("delta-depth-limit")
    maximum = limits.max_blob_bytes if base.resolved_kind == 3 else limits.max_metadata_bytes
    if input_size + expanded + entry.declared > limits.max_scratch_bytes:
        _refuse("resource-limit")
    with tempfile.TemporaryFile() as delta:
        bundle.seek(entry.compressed_start)
        _inflate(bundle, entry.declared, limits.max_blob_bytes, entry.declared,
                 None, delta.write, deadline)
        if bundle.tell() != entry.compressed_end:
            _refuse("object-invalid")
        delta.seek(0)
        source_size = _read_varint(delta, deadline)
        target_size = _read_varint(delta, deadline)
        if source_size != base.result_size:
            _refuse("object-invalid")
        if target_size > maximum:
            _refuse("object-size-limit")
        if expanded + target_size > limits.max_total_inflated_bytes:
            _refuse("total-expanded-limit")
        if input_size + expanded + entry.declared + target_size > limits.max_scratch_bytes:
            _refuse("resource-limit")
        objects.seek(0, io.SEEK_END)
        result_offset = objects.tell()
        object_hash = _object_digest(base.resolved_kind, target_size, algorithm)
        _apply_delta(delta, objects, base, target_size, object_hash, deadline)
    entry.resolved_kind = base.resolved_kind
    entry.result_size = target_size
    entry.result_offset = result_offset
    entry.object_id = object_hash.digest()
    entry.depth = depth
    return target_size


def _parse(bundle, objects, limits, input_size, bundle_sha256, deadline):
    algorithm, ref_ids = _bundle_header(bundle, limits, deadline)
    checksum = hashlib.new(algorithm)
    header = _pack_read(bundle, 12, checksum)
    if header[:4] != b"PACK" or int.from_bytes(header[4:8], "big") not in (2, 3):
        _refuse("pack-header-invalid")
    count = int.from_bytes(header[8:12], "big")
    if count > limits.max_objects:
        _refuse("object-count-limit")
    entries = []
    offsets = {}
    ids = {}
    inflated = 0
    expanded = 0
    for unused in range(count):
        deadline.check()
        offset = bundle.tell()
        kind, declared = _object_header(bundle, checksum, limits)
        base_offset = None
        base_id = None
        if kind == 6:
            base_offset = _ofs_base(bundle, checksum, offset)
            if base_offset not in offsets:
                _refuse("delta-base-invalid")
        elif kind == 7:
            base_id = _pack_read(bundle, 20 if algorithm == "sha1" else 32, checksum)
        compressed_start = bundle.tell()
        maximum = limits.max_blob_bytes if kind in (3, 6, 7) else limits.max_metadata_bytes
        if kind in OBJECT_TYPES:
            if expanded + declared > limits.max_total_inflated_bytes:
                _refuse("total-expanded-limit")
            if input_size + expanded + declared > limits.max_scratch_bytes:
                _refuse("resource-limit")
            objects.seek(0, io.SEEK_END)
            result_offset = objects.tell()
            object_hash = _object_digest(kind, declared, algorithm)

            def sink(block):
                objects.write(block)
                object_hash.update(block)
        else:
            result_offset = 0
            object_hash = None

            def sink(block):
                return None

        consumed = _inflate(bundle, declared, maximum,
                            limits.max_total_inflated_bytes - inflated,
                            checksum, sink, deadline)
        entry = _Entry(offset, kind, declared, compressed_start, compressed_start + consumed,
                       base_offset, base_id)
        inflated += declared
        if kind in OBJECT_TYPES:
            expanded += declared
            entry.resolved_kind = kind
            entry.result_size = declared
            entry.result_offset = result_offset
            entry.object_id = object_hash.digest()
            if entry.object_id in ids:
                _refuse("object-invalid")
            ids[entry.object_id] = entry
        offsets[offset] = entry
        entries.append(entry)
    trailer = bundle.read(checksum.digest_size)
    if len(trailer) != checksum.digest_size:
        _refuse("truncated")
    if bundle.read(1):
        _refuse("trailing-data")
    if trailer != checksum.digest():
        _refuse("checksum-mismatch")
    pending = [entry for entry in entries if entry.resolved_kind is None]
    while pending:
        deadline.check()
        remaining = []
        progress = False
        for entry in pending:
            base = offsets.get(entry.base_offset) if entry.kind == 6 else ids.get(entry.base_id)
            if base is None or base.resolved_kind is None:
                remaining.append(entry)
                continue
            added = _resolve_delta(entry, base, bundle, objects, limits, input_size,
                                   expanded, algorithm, deadline)
            expanded += added
            if entry.object_id in ids:
                _refuse("object-invalid")
            ids[entry.object_id] = entry
            progress = True
        if not progress:
            _refuse("thin-pack")
        pending = remaining
    if not ref_ids.issubset(ids):
        _refuse("bundle-header-invalid")
    return Accepted(count, inflated, expanded, bundle_sha256)


def preflight(source, limits=BundleLimits()) -> PreflightResult:
    """Inspect every packed object and return an accepted record or fixed refusal."""
    try:
        if not _limits_valid(limits):
            _refuse("input-invalid")
        deadline = _Deadline(limits)
        with tempfile.TemporaryFile() as bundle, tempfile.TemporaryFile() as objects:
            input_size, bundle_sha256 = _spool(source, bundle, limits, deadline)
            return _parse(bundle, objects, limits, input_size, bundle_sha256, deadline)
    except _Refusal as error:
        return Refused(error.reason if error.reason in REFUSAL_REASONS else "internal-error")
    except KeyboardInterrupt:
        return Refused("resource-limit")
    except OSError:
        return Refused("resource-limit")
    except BaseException:
        return Refused("internal-error")
