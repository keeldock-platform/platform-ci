import hashlib
import hmac
import struct
import threading
import unicodedata
from bisect import bisect_left
from dataclasses import dataclass
from typing import Protocol, Sequence, Tuple


KEY_RECORD_LENGTH = 320
CAPSULE_HEADER_LENGTH = 65536
CAPSULE_LENGTH = 286261248
CHUNK_PLAINTEXT_BYTES = 1048576
CHUNK_TAG_BYTES = 16
CHUNK_RECORD_LENGTH = CHUNK_PLAINTEXT_BYTES + CHUNK_TAG_BYTES
MANIFEST_CHUNK_COUNT = 16
BUNDLE_CHUNK_COUNT = 256
CHUNK_COUNT = MANIFEST_CHUNK_COUNT + BUNDLE_CHUNK_COUNT
FIRST_MANIFEST_INDEX = 0
LAST_MANIFEST_INDEX = 15
FIRST_BUNDLE_INDEX = 16
LAST_BUNDLE_INDEX = 271
MANIFEST_REGION_START = CAPSULE_HEADER_LENGTH
MANIFEST_REGION_LENGTH = MANIFEST_CHUNK_COUNT * CHUNK_RECORD_LENGTH
BUNDLE_REGION_START = MANIFEST_REGION_START + MANIFEST_REGION_LENGTH
BUNDLE_REGION_LENGTH = BUNDLE_CHUNK_COUNT * CHUNK_RECORD_LENGTH
TRAILER_START = BUNDLE_REGION_START + BUNDLE_REGION_LENGTH
TRAILER_LENGTH = CAPSULE_LENGTH - TRAILER_START
MANIFEST_PLAINTEXT_LENGTH = MANIFEST_CHUNK_COUNT * CHUNK_PLAINTEXT_BYTES
BUNDLE_PLAINTEXT_LENGTH = BUNDLE_CHUNK_COUNT * CHUNK_PLAINTEXT_BYTES
MAX_MANIFEST_BODY_BYTES = MANIFEST_PLAINTEXT_LENGTH - 8
MAX_BUNDLE_BODY_BYTES = BUNDLE_PLAINTEXT_LENGTH - 8
MAX_MANIFEST_ENTRIES = 10000
MAX_ENTRY_BYTES = 64 * 1024 * 1024
MAX_TREE_BYTES = 1024 * 1024 * 1024
MAX_PATH_UTF16_UNITS = 240
VERSION = 1
SUITE = 1
KEY_RECORD_MAGIC = b"KDWHKEY1"
CAPSULE_MAGIC = b"KDWHCAP1"
MANIFEST_DOMAIN = b"KDWH-v1/manifest"
HKDF_DOMAIN = b"KDWH-v1/HKDF-AES256GCM"
AAD_DOMAIN = b"KDWH-v1/GCM-CHUNK"
GIT_OBJECT_FORMAT = "sha1"
RECEIVER_JOB_SHA256 = hashlib.sha256(b"windows-receiver").digest()
RUNNER_LABEL_SHA256 = hashlib.sha256(b"windows-2025").digest()

KEY_MAGIC_START = 0
KEY_VERSION_START = 8
KEY_SUITE_START = 10
KEY_CONTROL_REPOSITORY_ID_START = 12
KEY_CONTROL_SHA_START = 20
KEY_RUN_ID_START = 40
KEY_ATTEMPT_START = 48
KEY_TRANSFER_ID_START = 52
KEY_ID_START = 68
KEY_RECEIVER_POINT_START = 100
KEY_WORKFLOW_REF_SHA256_START = 165
KEY_RECEIVER_JOB_SHA256_START = 197
KEY_CREATED_AT_START = 229
KEY_EXPIRES_AT_START = 237
KEY_CAPSULE_LENGTH_START = 245
KEY_RUNNER_LABEL_SHA256_START = 253
KEY_RESERVED_START = 285

HEADER_MAGIC_START = 0
HEADER_VERSION_START = 8
HEADER_SUITE_START = 10
HEADER_FLAGS_START = 12
HEADER_CONTROL_REPOSITORY_ID_START = 16
HEADER_CONTROL_SHA_START = 24
HEADER_RUN_ID_START = 44
HEADER_ATTEMPT_START = 52
HEADER_TRANSFER_ID_START = 56
HEADER_KEY_ID_START = 72
HEADER_KEY_RECORD_SHA256_START = 104
HEADER_SENDER_POINT_START = 136
HEADER_HKDF_SALT_START = 201
HEADER_NONCE_PREFIX_START = 233
HEADER_CREATED_AT_START = 237
HEADER_EXPIRES_AT_START = 245
HEADER_WORKFLOW_REF_SHA256_START = 253
HEADER_INTENDED_JOB_SHA256_START = 285
HEADER_MANIFEST_CHUNK_COUNT_START = 317
HEADER_BUNDLE_CHUNK_COUNT_START = 321
HEADER_CHUNK_PLAINTEXT_BYTES_START = 325
HEADER_CAPSULE_LENGTH_START = 329
HEADER_RESERVED_START = 337

REASON_DOWNGRADE = "downgrade_refused"
REASON_LENGTH = "length_out_of_bounds"
REASON_NONCANONICAL = "noncanonical_encoding"
REASON_CHUNK_INDEX = "chunk_index_invalid"
REASON_TRAILING = "trailing_data"
REASON_MANIFEST_LIMIT = "manifest_limit"
REASON_POINT = "invalid_point"
REASON_STRUCTURE = "invalid_structure"
REASON_CRYPTO = "crypto_refused"
REASON_CODES = (
    REASON_DOWNGRADE,
    REASON_LENGTH,
    REASON_NONCANONICAL,
    REASON_CHUNK_INDEX,
    REASON_TRAILING,
    REASON_MANIFEST_LIMIT,
    REASON_POINT,
    REASON_STRUCTURE,
    REASON_CRYPTO,
)

PROVISIONAL_CHOICES = (
    "Windows destination aliases use NFC and casefold; the exact Windows equivalence algorithm is unspecified.",
)

_P256_FIELD = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_MAX_U64 = (1 << 64) - 1


class CapsuleRefusal(ValueError):
    def __init__(self, reason):
        if reason not in REASON_CODES:
            reason = REASON_STRUCTURE
        self.reason = reason
        super().__init__(reason)


def _refuse(reason):
    raise CapsuleRefusal(reason)


def _decode_call(callback, *args):
    try:
        return callback(*args)
    except CapsuleRefusal:
        raise
    except Exception:
        raise CapsuleRefusal(REASON_STRUCTURE) from None


def _is_bytes(value):
    return type(value) is bytes


def _check_bytes(value, length, reason=REASON_STRUCTURE):
    if not _is_bytes(value) or len(value) != length:
        _refuse(reason)


def _check_readonly_region(value, length, reason=REASON_STRUCTURE):
    if _is_bytes(value) and len(value) == length:
        return
    if (
        type(value) is memoryview
        and value.readonly
        and value.format == "B"
        and value.ndim == 1
        and value.c_contiguous
        and len(value) == length
        and type(value.obj) is bytes
    ):
        return
    _refuse(reason)


def _check_uint(value, maximum=_MAX_U64):
    if type(value) is not int or value < 0 or value > maximum:
        _refuse(REASON_STRUCTURE)


def _check_positive(value, maximum=_MAX_U64):
    _check_uint(value, maximum)
    if value == 0:
        _refuse(REASON_STRUCTURE)


def _u16(value):
    _check_uint(value, 65535)
    return struct.pack(">H", value)


def _u32(value):
    _check_uint(value, 0xFFFFFFFF)
    return struct.pack(">I", value)


def _u64(value):
    _check_uint(value)
    return struct.pack(">Q", value)


def _read_u16(data, offset):
    return struct.unpack_from(">H", data, offset)[0]


def _read_u32(data, offset):
    return struct.unpack_from(">I", data, offset)[0]


def _read_u64(data, offset):
    return struct.unpack_from(">Q", data, offset)[0]


def validate_public_point(point):
    _check_bytes(point, 65, REASON_POINT)
    if point[0] != 4:
        _refuse(REASON_POINT)
    x = int.from_bytes(point[1:33], "big")
    y = int.from_bytes(point[33:65], "big")
    if x >= _P256_FIELD or y >= _P256_FIELD:
        _refuse(REASON_POINT)
    if (y * y - (x * x * x - 3 * x + _P256_B)) % _P256_FIELD != 0:
        _refuse(REASON_POINT)
    return point


@dataclass(frozen=True)
class KeyRecord:
    control_repository_id: int
    control_sha: bytes
    run_id: int
    attempt: int
    transfer_id: bytes
    receiver_public_point: bytes
    workflow_ref_sha256: bytes
    created_at: int
    expires_at: int

    @property
    def key_id(self):
        return hashlib.sha256(self.receiver_public_point).digest()


@dataclass(frozen=True)
class CapsuleHeader:
    control_repository_id: int
    control_sha: bytes
    run_id: int
    attempt: int
    transfer_id: bytes
    receiver_key_id: bytes
    key_record_sha256: bytes
    sender_public_point: bytes
    hkdf_salt: bytes
    nonce_prefix: bytes
    created_at: int
    expires_at: int
    workflow_ref_sha256: bytes
    intended_job_sha256: bytes


@dataclass(frozen=True)
class ChunkRecord:
    index: int
    kind: int
    ciphertext: bytes
    tag: bytes


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    mode: int
    blob_id: bytes
    size: int
    sha256: bytes


@dataclass(frozen=True)
class Manifest:
    source_repository_id: int
    source_sha: bytes
    tree_id: bytes
    bundle_sha256: bytes
    bundle_length: int
    entries: Tuple[ManifestEntry, ...]


@dataclass(frozen=True)
class Capsule:
    header: CapsuleHeader
    manifest_chunks: Tuple[ChunkRecord, ...]
    bundle_chunks: Tuple[ChunkRecord, ...]
    trailer: bytes


class CapsuleView:
    """A bounded, read-only view retaining one immutable capsule bytes owner.

    Chunk and trailer views keep the original bytes alive. Consumers should
    authenticate and process one chunk at a time; no ciphertext is copied by
    decoding the complete capsule.
    """

    def __init__(self, data, header):
        _check_capsule_length(data)
        _validate_header(header)
        self._data = memoryview(data)
        self.header = header

    def chunk(self, index):
        kind = chunk_kind_for_index(index)
        start = chunk_offset(index)
        ciphertext = self._data[start:start + CHUNK_PLAINTEXT_BYTES]
        tag = self._data[start + CHUNK_PLAINTEXT_BYTES:start + CHUNK_RECORD_LENGTH]
        return ChunkRecord(index, kind, ciphertext, tag)

    @property
    def manifest_chunks(self):
        return tuple(self.chunk(index) for index in range(MANIFEST_CHUNK_COUNT))

    @property
    def bundle_chunks(self):
        return tuple(self.chunk(index) for index in range(FIRST_BUNDLE_INDEX, CHUNK_COUNT))

    @property
    def manifest_ciphertext_region(self):
        return self._data[MANIFEST_REGION_START:BUNDLE_REGION_START]

    @property
    def trailer(self):
        return self._data[TRAILER_START:CAPSULE_LENGTH]


_ENCRYPTION_KEYS_USED = set()
_ENCRYPTION_KEYS_LOCK = threading.Lock()
MAX_ENCRYPTION_SESSIONS = 10000


def _validate_key_record(record):
    if type(record) is not KeyRecord:
        _refuse(REASON_STRUCTURE)
    _check_positive(record.control_repository_id)
    _check_bytes(record.control_sha, 20)
    _check_positive(record.run_id)
    _check_positive(record.attempt, 0xFFFFFFFF)
    _check_bytes(record.transfer_id, 16)
    validate_public_point(record.receiver_public_point)
    _check_bytes(record.workflow_ref_sha256, 32)
    _check_uint(record.created_at)
    _check_uint(record.expires_at)
    if record.expires_at <= record.created_at:
        _refuse(REASON_STRUCTURE)


def encode_key_record(record):
    _validate_key_record(record)
    output = bytearray(KEY_RECORD_LENGTH)
    output[KEY_MAGIC_START:KEY_VERSION_START] = KEY_RECORD_MAGIC
    output[KEY_VERSION_START:KEY_SUITE_START] = _u16(VERSION)
    output[KEY_SUITE_START:KEY_CONTROL_REPOSITORY_ID_START] = _u16(SUITE)
    output[KEY_CONTROL_REPOSITORY_ID_START:KEY_CONTROL_SHA_START] = _u64(
        record.control_repository_id
    )
    output[KEY_CONTROL_SHA_START:KEY_RUN_ID_START] = record.control_sha
    output[KEY_RUN_ID_START:KEY_ATTEMPT_START] = _u64(record.run_id)
    output[KEY_ATTEMPT_START:KEY_TRANSFER_ID_START] = _u32(record.attempt)
    output[KEY_TRANSFER_ID_START:KEY_ID_START] = record.transfer_id
    output[KEY_ID_START:KEY_RECEIVER_POINT_START] = record.key_id
    output[KEY_RECEIVER_POINT_START:KEY_WORKFLOW_REF_SHA256_START] = record.receiver_public_point
    output[KEY_WORKFLOW_REF_SHA256_START:KEY_RECEIVER_JOB_SHA256_START] = record.workflow_ref_sha256
    output[KEY_RECEIVER_JOB_SHA256_START:KEY_CREATED_AT_START] = RECEIVER_JOB_SHA256
    output[KEY_CREATED_AT_START:KEY_EXPIRES_AT_START] = _u64(record.created_at)
    output[KEY_EXPIRES_AT_START:KEY_CAPSULE_LENGTH_START] = _u64(record.expires_at)
    output[KEY_CAPSULE_LENGTH_START:KEY_RUNNER_LABEL_SHA256_START] = _u64(CAPSULE_LENGTH)
    output[KEY_RUNNER_LABEL_SHA256_START:KEY_RESERVED_START] = RUNNER_LABEL_SHA256
    return bytes(output)


def _decode_key_record(data):
    if not _is_bytes(data):
        _refuse(REASON_STRUCTURE)
    if len(data) > KEY_RECORD_LENGTH:
        _refuse(REASON_TRAILING)
    if len(data) != KEY_RECORD_LENGTH:
        _refuse(REASON_LENGTH)
    if data[KEY_MAGIC_START:KEY_VERSION_START] != KEY_RECORD_MAGIC:
        _refuse(REASON_DOWNGRADE)
    if _read_u16(data, KEY_VERSION_START) != VERSION or _read_u16(data, KEY_SUITE_START) != SUITE:
        _refuse(REASON_DOWNGRADE)
    if data[KEY_RECEIVER_JOB_SHA256_START:KEY_CREATED_AT_START] != RECEIVER_JOB_SHA256:
        _refuse(REASON_STRUCTURE)
    if _read_u64(data, KEY_CAPSULE_LENGTH_START) != CAPSULE_LENGTH:
        _refuse(REASON_LENGTH)
    if data[KEY_RUNNER_LABEL_SHA256_START:KEY_RESERVED_START] != RUNNER_LABEL_SHA256:
        _refuse(REASON_STRUCTURE)
    if any(data[KEY_RESERVED_START:KEY_RECORD_LENGTH]):
        _refuse(REASON_STRUCTURE)
    record = KeyRecord(
        _read_u64(data, KEY_CONTROL_REPOSITORY_ID_START),
        data[KEY_CONTROL_SHA_START:KEY_RUN_ID_START],
        _read_u64(data, KEY_RUN_ID_START),
        _read_u32(data, KEY_ATTEMPT_START),
        data[KEY_TRANSFER_ID_START:KEY_ID_START],
        data[KEY_RECEIVER_POINT_START:KEY_WORKFLOW_REF_SHA256_START],
        data[KEY_WORKFLOW_REF_SHA256_START:KEY_RECEIVER_JOB_SHA256_START],
        _read_u64(data, KEY_CREATED_AT_START),
        _read_u64(data, KEY_EXPIRES_AT_START),
    )
    _validate_key_record(record)
    if data[KEY_ID_START:KEY_RECEIVER_POINT_START] != record.key_id:
        _refuse(REASON_STRUCTURE)
    return record


def decode_key_record(data):
    return _decode_call(_decode_key_record, data)


def _validate_header(header):
    if type(header) is not CapsuleHeader:
        _refuse(REASON_STRUCTURE)
    _check_positive(header.control_repository_id)
    _check_bytes(header.control_sha, 20)
    _check_positive(header.run_id)
    _check_positive(header.attempt, 0xFFFFFFFF)
    _check_bytes(header.transfer_id, 16)
    _check_bytes(header.receiver_key_id, 32)
    _check_bytes(header.key_record_sha256, 32)
    validate_public_point(header.sender_public_point)
    _check_bytes(header.hkdf_salt, 32)
    _check_bytes(header.nonce_prefix, 4)
    _check_uint(header.created_at)
    _check_uint(header.expires_at)
    if header.expires_at <= header.created_at:
        _refuse(REASON_STRUCTURE)
    _check_bytes(header.workflow_ref_sha256, 32)
    _check_bytes(header.intended_job_sha256, 32)
    if header.intended_job_sha256 != RECEIVER_JOB_SHA256:
        _refuse(REASON_STRUCTURE)


def encode_capsule_header(header):
    _validate_header(header)
    output = bytearray(CAPSULE_HEADER_LENGTH)
    output[HEADER_MAGIC_START:HEADER_VERSION_START] = CAPSULE_MAGIC
    output[HEADER_VERSION_START:HEADER_SUITE_START] = _u16(VERSION)
    output[HEADER_SUITE_START:HEADER_FLAGS_START] = _u16(SUITE)
    output[HEADER_FLAGS_START:HEADER_CONTROL_REPOSITORY_ID_START] = bytes(4)
    output[HEADER_CONTROL_REPOSITORY_ID_START:HEADER_CONTROL_SHA_START] = _u64(
        header.control_repository_id
    )
    output[HEADER_CONTROL_SHA_START:HEADER_RUN_ID_START] = header.control_sha
    output[HEADER_RUN_ID_START:HEADER_ATTEMPT_START] = _u64(header.run_id)
    output[HEADER_ATTEMPT_START:HEADER_TRANSFER_ID_START] = _u32(header.attempt)
    output[HEADER_TRANSFER_ID_START:HEADER_KEY_ID_START] = header.transfer_id
    output[HEADER_KEY_ID_START:HEADER_KEY_RECORD_SHA256_START] = header.receiver_key_id
    output[HEADER_KEY_RECORD_SHA256_START:HEADER_SENDER_POINT_START] = header.key_record_sha256
    output[HEADER_SENDER_POINT_START:HEADER_HKDF_SALT_START] = header.sender_public_point
    output[HEADER_HKDF_SALT_START:HEADER_NONCE_PREFIX_START] = header.hkdf_salt
    output[HEADER_NONCE_PREFIX_START:HEADER_CREATED_AT_START] = header.nonce_prefix
    output[HEADER_CREATED_AT_START:HEADER_EXPIRES_AT_START] = _u64(header.created_at)
    output[HEADER_EXPIRES_AT_START:HEADER_WORKFLOW_REF_SHA256_START] = _u64(header.expires_at)
    output[HEADER_WORKFLOW_REF_SHA256_START:HEADER_INTENDED_JOB_SHA256_START] = header.workflow_ref_sha256
    output[HEADER_INTENDED_JOB_SHA256_START:HEADER_MANIFEST_CHUNK_COUNT_START] = header.intended_job_sha256
    output[HEADER_MANIFEST_CHUNK_COUNT_START:HEADER_BUNDLE_CHUNK_COUNT_START] = _u32(
        MANIFEST_CHUNK_COUNT
    )
    output[HEADER_BUNDLE_CHUNK_COUNT_START:HEADER_CHUNK_PLAINTEXT_BYTES_START] = _u32(
        BUNDLE_CHUNK_COUNT
    )
    output[HEADER_CHUNK_PLAINTEXT_BYTES_START:HEADER_CAPSULE_LENGTH_START] = _u32(
        CHUNK_PLAINTEXT_BYTES
    )
    output[HEADER_CAPSULE_LENGTH_START:HEADER_RESERVED_START] = _u64(CAPSULE_LENGTH)
    return bytes(output)


def _decode_capsule_header(data):
    if not _is_bytes(data):
        _refuse(REASON_STRUCTURE)
    if len(data) > CAPSULE_HEADER_LENGTH:
        _refuse(REASON_TRAILING)
    if len(data) != CAPSULE_HEADER_LENGTH:
        _refuse(REASON_LENGTH)
    if data[HEADER_MAGIC_START:HEADER_VERSION_START] != CAPSULE_MAGIC:
        _refuse(REASON_DOWNGRADE)
    if _read_u16(data, HEADER_VERSION_START) != VERSION or _read_u16(data, HEADER_SUITE_START) != SUITE:
        _refuse(REASON_DOWNGRADE)
    if any(data[HEADER_FLAGS_START:HEADER_CONTROL_REPOSITORY_ID_START]):
        _refuse(REASON_STRUCTURE)
    if _read_u32(data, HEADER_MANIFEST_CHUNK_COUNT_START) != MANIFEST_CHUNK_COUNT:
        _refuse(REASON_STRUCTURE)
    if _read_u32(data, HEADER_BUNDLE_CHUNK_COUNT_START) != BUNDLE_CHUNK_COUNT:
        _refuse(REASON_STRUCTURE)
    if _read_u32(data, HEADER_CHUNK_PLAINTEXT_BYTES_START) != CHUNK_PLAINTEXT_BYTES:
        _refuse(REASON_STRUCTURE)
    if _read_u64(data, HEADER_CAPSULE_LENGTH_START) != CAPSULE_LENGTH:
        _refuse(REASON_LENGTH)
    if any(data[HEADER_RESERVED_START:CAPSULE_HEADER_LENGTH]):
        _refuse(REASON_STRUCTURE)
    header = CapsuleHeader(
        _read_u64(data, HEADER_CONTROL_REPOSITORY_ID_START),
        data[HEADER_CONTROL_SHA_START:HEADER_RUN_ID_START],
        _read_u64(data, HEADER_RUN_ID_START),
        _read_u32(data, HEADER_ATTEMPT_START),
        data[HEADER_TRANSFER_ID_START:HEADER_KEY_ID_START],
        data[HEADER_KEY_ID_START:HEADER_KEY_RECORD_SHA256_START],
        data[HEADER_KEY_RECORD_SHA256_START:HEADER_SENDER_POINT_START],
        data[HEADER_SENDER_POINT_START:HEADER_HKDF_SALT_START],
        data[HEADER_HKDF_SALT_START:HEADER_NONCE_PREFIX_START],
        data[HEADER_NONCE_PREFIX_START:HEADER_CREATED_AT_START],
        _read_u64(data, HEADER_CREATED_AT_START),
        _read_u64(data, HEADER_EXPIRES_AT_START),
        data[HEADER_WORKFLOW_REF_SHA256_START:HEADER_INTENDED_JOB_SHA256_START],
        data[HEADER_INTENDED_JOB_SHA256_START:HEADER_MANIFEST_CHUNK_COUNT_START],
    )
    _validate_header(header)
    return header


def decode_capsule_header(data):
    return _decode_call(_decode_capsule_header, data)


def validate_header_key_binding(header, key_record):
    if type(header) is not CapsuleHeader:
        _refuse(REASON_STRUCTURE)
    _validate_header(header)
    if _is_bytes(key_record):
        record_bytes = key_record
        record = decode_key_record(key_record)
    elif type(key_record) is KeyRecord:
        record = key_record
        record_bytes = encode_key_record(record)
    else:
        _refuse(REASON_STRUCTURE)
    if (
        header.control_repository_id != record.control_repository_id
        or header.control_sha != record.control_sha
        or header.run_id != record.run_id
        or header.attempt != record.attempt
        or header.transfer_id != record.transfer_id
        or header.receiver_key_id != record.key_id
        or header.key_record_sha256 != hashlib.sha256(record_bytes).digest()
        or header.created_at != record.created_at
        or header.expires_at != record.expires_at
        or header.workflow_ref_sha256 != record.workflow_ref_sha256
        or header.intended_job_sha256 != RECEIVER_JOB_SHA256
    ):
        _refuse(REASON_STRUCTURE)
    return True


def chunk_kind_for_index(index):
    if type(index) is not int or index < FIRST_MANIFEST_INDEX or index > LAST_BUNDLE_INDEX:
        _refuse(REASON_CHUNK_INDEX)
    if index <= LAST_MANIFEST_INDEX:
        return 0
    return 1


def chunk_offset(index):
    chunk_kind_for_index(index)
    return MANIFEST_REGION_START + index * CHUNK_RECORD_LENGTH


def encode_chunk(index, ciphertext, tag, kind=None):
    expected_kind = chunk_kind_for_index(index)
    if kind is not None and kind != expected_kind:
        _refuse(REASON_CHUNK_INDEX)
    _check_bytes(ciphertext, CHUNK_PLAINTEXT_BYTES, REASON_LENGTH)
    _check_bytes(tag, CHUNK_TAG_BYTES, REASON_LENGTH)
    return ciphertext + tag


def _decode_chunk(data, index, kind=None):
    expected_kind = chunk_kind_for_index(index)
    if kind is not None and kind != expected_kind:
        _refuse(REASON_CHUNK_INDEX)
    if not _is_bytes(data):
        _refuse(REASON_STRUCTURE)
    if len(data) > CHUNK_RECORD_LENGTH:
        _refuse(REASON_TRAILING)
    if len(data) != CHUNK_RECORD_LENGTH:
        _refuse(REASON_LENGTH)
    return ChunkRecord(
        index,
        expected_kind,
        data[:CHUNK_PLAINTEXT_BYTES],
        data[CHUNK_PLAINTEXT_BYTES:],
    )


def decode_chunk(data, index, kind=None):
    return _decode_call(_decode_chunk, data, index, kind)


def validate_global_indices(indices):
    if not isinstance(indices, Sequence):
        _refuse(REASON_CHUNK_INDEX)
    if len(indices) != CHUNK_COUNT:
        _refuse(REASON_CHUNK_INDEX)
    for expected, actual in enumerate(indices):
        if type(actual) is not int or actual != expected:
            _refuse(REASON_CHUNK_INDEX)
    return True


def validate_chunk_sequence(chunks):
    if not isinstance(chunks, Sequence):
        _refuse(REASON_CHUNK_INDEX)
    if any(type(chunk) is not ChunkRecord for chunk in chunks):
        _refuse(REASON_CHUNK_INDEX)
    validate_global_indices(tuple(chunk.index for chunk in chunks))
    for expected, chunk in enumerate(chunks):
        if type(chunk) is not ChunkRecord or chunk.kind != chunk_kind_for_index(expected):
            _refuse(REASON_CHUNK_INDEX)
        _check_bytes(chunk.ciphertext, CHUNK_PLAINTEXT_BYTES, REASON_LENGTH)
        _check_bytes(chunk.tag, CHUNK_TAG_BYTES, REASON_LENGTH)
    return True


def encode_trailer(data):
    _check_bytes(data, TRAILER_LENGTH, REASON_LENGTH)
    return data


def _decode_trailer(data):
    if not _is_bytes(data):
        _refuse(REASON_STRUCTURE)
    if len(data) > TRAILER_LENGTH:
        _refuse(REASON_TRAILING)
    if len(data) != TRAILER_LENGTH:
        _refuse(REASON_LENGTH)
    return data


def decode_trailer(data):
    return _decode_call(_decode_trailer, data)


def _cbor_length(major, value):
    _check_uint(value)
    if value < 24:
        return bytes(((major << 5) | value,))
    if value <= 0xFF:
        return bytes(((major << 5) | 24, value))
    if value <= 0xFFFF:
        return bytes(((major << 5) | 25,)) + struct.pack(">H", value)
    if value <= 0xFFFFFFFF:
        return bytes(((major << 5) | 26,)) + struct.pack(">I", value)
    return bytes(((major << 5) | 27,)) + struct.pack(">Q", value)


def _cbor_uint(value):
    return _cbor_length(0, value)


def _cbor_bytes(value):
    return _cbor_length(2, len(value)) + value


def _cbor_text(value):
    encoded = value.encode("utf-8")
    return _cbor_length(3, len(encoded)) + encoded


def _cbor_array(values):
    return _cbor_length(4, len(values)) + b"".join(values)


def _is_path_safe(path):
    if type(path) is not str or not path:
        return False
    if unicodedata.normalize("NFC", path) != path:
        return False
    try:
        encoded = path.encode("utf-8")
        utf16_units = len(path.encode("utf-16-le")) // 2
    except UnicodeError:
        return False
    if not encoded or utf16_units > MAX_PATH_UTF16_UNITS:
        return False
    if path.startswith("/") or "\\" in path:
        return False
    if any(ord(char) < 32 or 127 <= ord(char) <= 159 or char in '<>:"|?*' for char in path):
        return False
    for component in path.split("/"):
        if component in ("", ".", "..") or component.endswith((".", " ")):
            return False
        base = component.split(".", 1)[0].upper()
        if base in ("CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "CLOCK$"):
            return False
        reserved_digits = "123456789" + chr(185) + chr(178) + chr(179)
        if len(base) == 4 and base[:3] in ("COM", "LPT") and base[3] in reserved_digits:
            return False
    return True


def _validate_manifest(manifest):
    if type(manifest) is not Manifest:
        _refuse(REASON_STRUCTURE)
    _check_positive(manifest.source_repository_id)
    _check_bytes(manifest.source_sha, 20)
    _check_bytes(manifest.tree_id, 20)
    _check_bytes(manifest.bundle_sha256, 32)
    _check_uint(manifest.bundle_length)
    if manifest.bundle_length > MAX_BUNDLE_BODY_BYTES:
        _refuse(REASON_MANIFEST_LIMIT)
    if type(manifest.entries) not in (tuple, list):
        _refuse(REASON_STRUCTURE)
    if len(manifest.entries) > MAX_MANIFEST_ENTRIES:
        _refuse(REASON_MANIFEST_LIMIT)
    previous_path = None
    aliases = set()
    sorted_aliases = []
    total_size = 0
    for entry in manifest.entries:
        if type(entry) is not ManifestEntry:
            _refuse(REASON_STRUCTURE)
        if not _is_path_safe(entry.path):
            _refuse(REASON_MANIFEST_LIMIT)
        path_bytes = entry.path.encode("utf-8")
        if previous_path is not None and path_bytes <= previous_path:
            _refuse(REASON_MANIFEST_LIMIT)
        previous_path = path_bytes
        alias = unicodedata.normalize("NFC", entry.path).casefold()
        if alias in aliases:
            _refuse(REASON_MANIFEST_LIMIT)
        separator = alias.find("/")
        while separator != -1:
            if alias[:separator] in aliases:
                _refuse(REASON_MANIFEST_LIMIT)
            separator = alias.find("/", separator + 1)
        descendant_prefix = alias + "/"
        descendant_at = bisect_left(sorted_aliases, descendant_prefix)
        if descendant_at < len(sorted_aliases) and sorted_aliases[descendant_at].startswith(
            descendant_prefix
        ):
            _refuse(REASON_MANIFEST_LIMIT)
        aliases.add(alias)
        sorted_aliases.insert(bisect_left(sorted_aliases, alias), alias)
        if entry.mode not in (0o100644, 0o100755):
            _refuse(REASON_MANIFEST_LIMIT)
        _check_bytes(entry.blob_id, 20)
        _check_uint(entry.size)
        _check_bytes(entry.sha256, 32)
        if entry.size > MAX_ENTRY_BYTES:
            _refuse(REASON_MANIFEST_LIMIT)
        total_size += entry.size
        if total_size > MAX_TREE_BYTES:
            _refuse(REASON_MANIFEST_LIMIT)


def encode_manifest(manifest):
    _validate_manifest(manifest)
    entries = []
    for entry in manifest.entries:
        entries.append(
            _cbor_array(
                (
                    _cbor_text(entry.path),
                    _cbor_uint(entry.mode),
                    _cbor_bytes(entry.blob_id),
                    _cbor_uint(entry.size),
                    _cbor_bytes(entry.sha256),
                )
            )
        )
    output = b"".join(
        (
            _cbor_length(5, 8),
            _cbor_uint(1),
            _cbor_text(MANIFEST_DOMAIN.decode("ascii")),
            _cbor_uint(2),
            _cbor_uint(manifest.source_repository_id),
            _cbor_uint(3),
            _cbor_bytes(manifest.source_sha),
            _cbor_uint(4),
            _cbor_text(GIT_OBJECT_FORMAT),
            _cbor_uint(5),
            _cbor_bytes(manifest.tree_id),
            _cbor_uint(6),
            _cbor_bytes(manifest.bundle_sha256),
            _cbor_uint(7),
            _cbor_uint(manifest.bundle_length),
            _cbor_uint(8),
            _cbor_array(entries),
        )
    )
    if len(output) > MAX_MANIFEST_BODY_BYTES:
        _refuse(REASON_MANIFEST_LIMIT)
    return output


class _CborReader:
    def __init__(self, data):
        self.data = data
        self.offset = 0

    def _take(self, count):
        if count < 0 or self.offset + count > len(self.data):
            _refuse(REASON_LENGTH)
        start = self.offset
        self.offset += count
        return self.data[start:self.offset]

    def _argument(self, additional):
        if additional < 24:
            return additional
        if additional == 24:
            value = self._take(1)[0]
            if value < 24:
                _refuse(REASON_NONCANONICAL)
            return value
        if additional == 25:
            value = struct.unpack(">H", self._take(2))[0]
            if value <= 0xFF:
                _refuse(REASON_NONCANONICAL)
            return value
        if additional == 26:
            value = struct.unpack(">I", self._take(4))[0]
            if value <= 0xFFFF:
                _refuse(REASON_NONCANONICAL)
            return value
        if additional == 27:
            value = struct.unpack(">Q", self._take(8))[0]
            if value <= 0xFFFFFFFF:
                _refuse(REASON_NONCANONICAL)
            return value
        _refuse(REASON_NONCANONICAL)

    def read(self, depth=0):
        if depth > 8:
            _refuse(REASON_STRUCTURE)
        initial = self._take(1)[0]
        major = initial >> 5
        additional = initial & 31
        if major == 0:
            return self._argument(additional)
        if major in (2, 3):
            length = self._argument(additional)
            if length > MAX_MANIFEST_BODY_BYTES:
                _refuse(REASON_MANIFEST_LIMIT)
            raw = self._take(length)
            if major == 2:
                return raw
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                _refuse(REASON_NONCANONICAL)
        if major == 4:
            length = self._argument(additional)
            if length > MAX_MANIFEST_ENTRIES:
                _refuse(REASON_MANIFEST_LIMIT)
            return [self.read(depth + 1) for unused in range(length)]
        if major == 5:
            length = self._argument(additional)
            if length != 8:
                _refuse(REASON_STRUCTURE)
            output = {}
            previous_key = -1
            for unused in range(length):
                key = self.read(depth + 1)
                if type(key) is not int or key <= previous_key:
                    _refuse(REASON_NONCANONICAL)
                if key in output:
                    _refuse(REASON_NONCANONICAL)
                previous_key = key
                output[key] = self.read(depth + 1)
            return output
        _refuse(REASON_STRUCTURE)


def _manifest_from_value(value):
    if type(value) is not dict or tuple(value.keys()) != tuple(range(1, 9)):
        _refuse(REASON_STRUCTURE)
    if value[1] != MANIFEST_DOMAIN.decode("ascii"):
        _refuse(REASON_STRUCTURE)
    if type(value[2]) is not int or type(value[3]) is not bytes:
        _refuse(REASON_STRUCTURE)
    if value[4] != GIT_OBJECT_FORMAT or type(value[5]) is not bytes:
        _refuse(REASON_STRUCTURE)
    if type(value[6]) is not bytes or type(value[7]) is not int:
        _refuse(REASON_STRUCTURE)
    if type(value[8]) is not list:
        _refuse(REASON_STRUCTURE)
    entries = []
    for item in value[8]:
        if type(item) is not list or len(item) != 5:
            _refuse(REASON_STRUCTURE)
        path, mode, blob_id, size, digest = item
        if (
            type(path) is not str
            or type(mode) is not int
            or type(blob_id) is not bytes
            or type(size) is not int
            or type(digest) is not bytes
        ):
            _refuse(REASON_STRUCTURE)
        entries.append(ManifestEntry(path, mode, blob_id, size, digest))
    manifest = Manifest(value[2], value[3], value[5], value[6], value[7], tuple(entries))
    _validate_manifest(manifest)
    return manifest


def _decode_manifest(data):
    if not _is_bytes(data):
        _refuse(REASON_STRUCTURE)
    if len(data) > MAX_MANIFEST_BODY_BYTES:
        _refuse(REASON_MANIFEST_LIMIT)
    reader = _CborReader(data)
    value = reader.read()
    if reader.offset < len(data):
        _refuse(REASON_TRAILING)
    return _manifest_from_value(value)


def decode_manifest(data):
    return _decode_call(_decode_manifest, data)


def encode_length_prefixed_region(body, padding, capacity, maximum_body):
    if not _is_bytes(body) or not _is_bytes(padding):
        _refuse(REASON_STRUCTURE)
    _check_uint(capacity)
    _check_uint(maximum_body)
    if len(body) > maximum_body or len(body) > capacity - 8:
        _refuse(REASON_LENGTH)
    if len(padding) != capacity - 8 - len(body):
        _refuse(REASON_LENGTH)
    return _u64(len(body)) + body + padding


def _decode_length_prefixed_region(data, capacity, maximum_body):
    if not _is_bytes(data):
        _refuse(REASON_STRUCTURE)
    if len(data) < 8:
        _refuse(REASON_LENGTH)
    body_length = _read_u64(data, 0)
    if body_length > maximum_body or body_length > capacity - 8:
        _refuse(REASON_LENGTH)
    if len(data) != capacity:
        if len(data) > capacity:
            _refuse(REASON_TRAILING)
        _refuse(REASON_LENGTH)
    body_end = 8 + body_length
    return data[8:body_end], data[body_end:]


def decode_length_prefixed_region(data, capacity, maximum_body):
    return _decode_call(_decode_length_prefixed_region, data, capacity, maximum_body)


def encode_manifest_region(manifest, padding):
    body = encode_manifest(manifest)
    return encode_length_prefixed_region(
        body, padding, MANIFEST_PLAINTEXT_LENGTH, MAX_MANIFEST_BODY_BYTES
    )


def decode_manifest_region(data):
    body, padding = decode_length_prefixed_region(
        data, MANIFEST_PLAINTEXT_LENGTH, MAX_MANIFEST_BODY_BYTES
    )
    return decode_manifest(body), padding


def encode_bundle_region(bundle, padding):
    return encode_length_prefixed_region(
        bundle, padding, BUNDLE_PLAINTEXT_LENGTH, MAX_BUNDLE_BODY_BYTES
    )


def decode_bundle_region(data):
    return decode_length_prefixed_region(data, BUNDLE_PLAINTEXT_LENGTH, MAX_BUNDLE_BODY_BYTES)


def header_digest(header_bytes):
    _check_bytes(header_bytes, CAPSULE_HEADER_LENGTH, REASON_LENGTH)
    return hashlib.sha256(header_bytes).digest()


def manifest_ciphertext_digest(manifest_region):
    _check_readonly_region(manifest_region, MANIFEST_REGION_LENGTH, REASON_LENGTH)
    return hashlib.sha256(manifest_region).digest()


def make_nonce(nonce_prefix, index):
    _check_bytes(nonce_prefix, 4)
    chunk_kind_for_index(index)
    return nonce_prefix + _u64(index)


def make_aad(header_sha256, index, kind, manifest_ciphertext_region=None):
    _check_bytes(header_sha256, 32)
    expected_kind = chunk_kind_for_index(index)
    if type(kind) is not int or kind != expected_kind:
        _refuse(REASON_CHUNK_INDEX)
    if kind == 1:
        _check_readonly_region(manifest_ciphertext_region, MANIFEST_REGION_LENGTH, REASON_LENGTH)
        manifest_sha256 = manifest_ciphertext_digest(manifest_ciphertext_region)
    elif manifest_ciphertext_region is not None:
        _refuse(REASON_STRUCTURE)
    else:
        manifest_sha256 = None
    return _aad_with_digest(header_sha256, index, kind, manifest_sha256)


def _aad_with_digest(header_sha256, index, kind, manifest_sha256):
    aad = (
        AAD_DOMAIN
        + b"\x00"
        + header_sha256
        + _u64(index)
        + bytes((kind,))
        + _u32(CHUNK_COUNT)
    )
    if kind == 1:
        _check_bytes(manifest_sha256, 32, REASON_LENGTH)
        aad += manifest_sha256
    return aad


def _hkdf_sha256(input_key_material, salt, info, output_length):
    if not _is_bytes(input_key_material) or not _is_bytes(salt) or not _is_bytes(info):
        _refuse(REASON_STRUCTURE)
    _check_uint(output_length, 255 * 32)
    prk = hmac.new(salt, input_key_material, hashlib.sha256).digest()
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < output_length:
        previous = hmac.new(
            prk, previous + info + bytes((counter,)), hashlib.sha256
        ).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:output_length])


def derive_aes_key(shared_x, salt, header_sha256):
    _check_bytes(shared_x, 32)
    _check_bytes(salt, 32)
    _check_bytes(header_sha256, 32)
    info = HKDF_DOMAIN + b"\x00" + header_sha256
    return _hkdf_sha256(shared_x, salt, info, 32)


def derive_capsule_aes_key(shared_x, header_bytes):
    _check_bytes(shared_x, 32)
    header = decode_capsule_header(header_bytes)
    return derive_aes_key(shared_x, header.hkdf_salt, header_digest(header_bytes))


class AEADProvider(Protocol):
    def seal(self, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> Tuple[bytes, bytes]:
        ...

    def open(self, key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
        ...


class ECDHProvider(Protocol):
    def derive_shared_x(self, peer_public_point: bytes) -> bytes:
        ...


class PersistentKeyUseLedger(Protocol):
    def claim(self, key_sha256: bytes) -> bool:
        """Atomically and durably insert the 32-byte SHA-256 of the AES key.

        Return True only after the insert survives a restart. Return False if
        this digest was ever claimed, including by another process or host.
        Raise on storage uncertainty. Share one ledger across all senders that
        may hold the key, and retain claims until that key is irrecoverable.
        Never roll back a claim after failure, cancellation, or completion.
        """
        ...


def derive_shared_x(provider, peer_public_point):
    validate_public_point(peer_public_point)
    try:
        shared_x = provider.derive_shared_x(peer_public_point)
    except Exception:
        _refuse(REASON_CRYPTO)
    _check_bytes(shared_x, 32, REASON_CRYPTO)
    return shared_x


class EncryptionSession:
    """One single-use attempt for one derived AES key.

    A trusted persistent ledger must claim SHA-256(key) before the first seal.
    The claim is permanent, including after an error or interruption. The
    caller must supply the same durable ledger after process and host restart;
    fresh attempts require a fresh receiver key, sender key, salt, nonce
    prefix, and transfer ID as specified by the capsule design.
    """

    def __init__(self, provider, key, header, use_ledger):
        _check_bytes(key, 32)
        _validate_header(header)
        if not callable(getattr(provider, "seal", None)):
            _refuse(REASON_CRYPTO)
        if not callable(getattr(use_ledger, "claim", None)):
            _refuse(REASON_CRYPTO)
        header_sha256 = header_digest(encode_capsule_header(header))
        fingerprint = hashlib.sha256(key).digest()
        with _ENCRYPTION_KEYS_LOCK:
            if fingerprint in _ENCRYPTION_KEYS_USED or len(_ENCRYPTION_KEYS_USED) >= MAX_ENCRYPTION_SESSIONS:
                _refuse(REASON_CRYPTO)
            _ENCRYPTION_KEYS_USED.add(fingerprint)
        try:
            claimed = use_ledger.claim(fingerprint)
        except Exception:
            _refuse(REASON_CRYPTO)
        if claimed is not True:
            _refuse(REASON_CRYPTO)
        self._provider = provider
        self._key = key
        self._header_sha256 = header_sha256
        self._nonce_prefix = header.nonce_prefix
        self._next_index = 0
        self._failed = False
        self._lock = threading.Lock()
        self._manifest_hasher = hashlib.sha256()
        self._manifest_sha256 = None

    def __enter__(self):
        return self

    def __exit__(self, unused_type, unused_value, unused_traceback):
        self.abort()

    def abort(self):
        with self._lock:
            self._failed = True

    def seal_chunk(self, index, plaintext):
        with self._lock:
            if self._failed or self._next_index == CHUNK_COUNT:
                _refuse(REASON_CRYPTO)
            self._failed = True
            if type(index) is not int or index != self._next_index:
                _refuse(REASON_CHUNK_INDEX)
            _check_bytes(plaintext, CHUNK_PLAINTEXT_BYTES, REASON_LENGTH)
            kind = chunk_kind_for_index(index)
            aad = _aad_with_digest(self._header_sha256, index, kind, self._manifest_sha256)
            nonce = make_nonce(self._nonce_prefix, index)
            try:
                ciphertext, tag = self._provider.seal(self._key, nonce, plaintext, aad)
            except Exception:
                _refuse(REASON_CRYPTO)
            _check_bytes(ciphertext, CHUNK_PLAINTEXT_BYTES, REASON_CRYPTO)
            _check_bytes(tag, CHUNK_TAG_BYTES, REASON_CRYPTO)
            if kind == 0:
                self._manifest_hasher.update(ciphertext)
                self._manifest_hasher.update(tag)
                if index == LAST_MANIFEST_INDEX:
                    self._manifest_sha256 = self._manifest_hasher.digest()
            self._next_index += 1
            self._failed = False
            return ChunkRecord(index, kind, ciphertext, tag)


def open_chunk(provider, key, header, chunk, manifest_ciphertext_region=None):
    _check_bytes(key, 32)
    _validate_header(header)
    if type(chunk) is not ChunkRecord:
        _refuse(REASON_STRUCTURE)
    expected_kind = chunk_kind_for_index(chunk.index)
    if chunk.kind != expected_kind:
        _refuse(REASON_CHUNK_INDEX)
    _check_readonly_region(chunk.ciphertext, CHUNK_PLAINTEXT_BYTES, REASON_LENGTH)
    _check_readonly_region(chunk.tag, CHUNK_TAG_BYTES, REASON_LENGTH)
    aad = make_aad(
        header_digest(encode_capsule_header(header)),
        chunk.index,
        chunk.kind,
        manifest_ciphertext_region,
    )
    nonce = make_nonce(header.nonce_prefix, chunk.index)
    try:
        plaintext = provider.open(key, nonce, bytes(chunk.ciphertext), bytes(chunk.tag), aad)
    except Exception:
        _refuse(REASON_CRYPTO)
    _check_bytes(plaintext, CHUNK_PLAINTEXT_BYTES, REASON_CRYPTO)
    return plaintext


def _check_capsule_length(data):
    if not _is_bytes(data):
        _refuse(REASON_STRUCTURE)
    if len(data) > CAPSULE_LENGTH:
        _refuse(REASON_TRAILING)
    if len(data) != CAPSULE_LENGTH:
        _refuse(REASON_LENGTH)


def encode_capsule(capsule, key_record):
    """Yield a complete capsule as bounded pieces in wire order."""
    if type(capsule) is CapsuleView:
        header_bytes = encode_capsule_header(capsule.header)
        if capsule._data[:CAPSULE_HEADER_LENGTH] != header_bytes:
            _refuse(REASON_STRUCTURE)
        validate_header_key_binding(capsule.header, key_record)

        def view_parts():
            yield header_bytes
            for index in range(CHUNK_COUNT):
                start = chunk_offset(index)
                yield bytes(capsule._data[start:start + CHUNK_RECORD_LENGTH])
            yield bytes(capsule.trailer)

        return view_parts()
    if type(capsule) is not Capsule:
        _refuse(REASON_STRUCTURE)
    _validate_header(capsule.header)
    validate_header_key_binding(capsule.header, key_record)
    chunks = tuple(capsule.manifest_chunks) + tuple(capsule.bundle_chunks)
    validate_chunk_sequence(chunks)
    if len(capsule.manifest_chunks) != MANIFEST_CHUNK_COUNT:
        _refuse(REASON_CHUNK_INDEX)
    if len(capsule.bundle_chunks) != BUNDLE_CHUNK_COUNT:
        _refuse(REASON_CHUNK_INDEX)
    trailer = encode_trailer(capsule.trailer)
    header_bytes = encode_capsule_header(capsule.header)

    def parts():
        yield header_bytes
        for chunk in chunks:
            yield encode_chunk(chunk.index, chunk.ciphertext, chunk.tag, chunk.kind)
        yield trailer

    return parts()


def _decode_capsule(data, key_record):
    _check_capsule_length(data)
    header = decode_capsule_header(data[:CAPSULE_HEADER_LENGTH])
    validate_header_key_binding(header, key_record)
    return CapsuleView(data, header)


def decode_capsule(data, key_record):
    return _decode_call(_decode_capsule, data, key_record)
