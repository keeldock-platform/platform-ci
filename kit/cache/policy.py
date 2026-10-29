import base64
import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Mapping, Optional, Tuple
from urllib.parse import urlsplit
import zlib


SCHEMA = "public-archive-v1"
REPOSITORY_LIMIT = 3 * 1024 * 1024 * 1024
ENTRY_LIMIT = 512 * 1024 * 1024
SOURCE_LIMIT = 1024 * 1024 * 1024
IDLE_RETIREMENT_SECONDS = 14 * 24 * 60 * 60
MAX_FILES = 4096
MAX_PROJECTION_RECORDS = 4096
MAX_PROJECTION_BYTES = 1024 * 1024
MAX_CLEANUP_REQUESTS = 25
GITHUB_TOKEN_HOURLY_LIMIT = 1000
MAX_KEYS_PER_PARTITION = 2
CONCURRENCY_GROUP = "public-cache-maintenance"
CACHE_LIST_ENDPOINT = ("GET", "/repos/{repository}/actions/caches")
CACHE_DELETE_ENDPOINT = ("DELETE", "/repos/{repository}/actions/caches/{cache_id}")
PRIVATE_PRODUCT_NAME = "keel" + "dock"
PRIVATE_PACKAGE_PREFIX = PRIVATE_PRODUCT_NAME + "-"
PRIVATE_NPM_SCOPE = "@" + PRIVATE_PRODUCT_NAME + "/"
DEFAULT_CARGO_ARCHIVES = {"https://index.crates.io": "https://static.crates.io"}
DEFAULT_CARGO_ORIGINS = ("https://index.crates.io",)
DEFAULT_NPM_ORIGINS = ("https://registry.npmjs.org",)
DEFAULT_ARCHIVE_ORIGINS = ("https://static.crates.io", "https://registry.npmjs.org")

HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
SLOT_TOKEN = re.compile(r"[a-v2-7]{16,32}\Z")
SCHEMA_TOKEN = re.compile(r"[a-z0-9][a-z0-9-]{0,31}\Z")
IDENTITY_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,95}\Z")
KEY_COMPONENT_TOKEN = re.compile(r"[a-z0-9][a-z0-9_-]{0,95}\Z")
CARGO_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]{0,199}\Z")
NPM_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._-]{0,99}/)?[a-z0-9][a-z0-9._-]{0,99}\Z")
PACKAGE_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,127}\Z")
RESERVED_WINDOWS_NAMES = frozenset(
    ("con", "prn", "aux", "nul")
    + tuple("com" + str(index) for index in range(1, 10))
    + tuple("lpt" + str(index) for index in range(1, 10))
)


class CachePolicyError(ValueError):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


def _require(condition, code):
    if not condition:
        raise CachePolicyError(code)


def _canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _normalize_origin(value):
    _require(type(value) is str and value, "origin-invalid")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        host = parsed.hostname
    except ValueError:
        raise CachePolicyError("origin-invalid")
    _require(parsed.scheme.lower() == "https", "origin-scheme")
    _require(host is not None and parsed.username is None and parsed.password is None, "origin-invalid")
    _require(not parsed.query and not parsed.fragment, "origin-invalid")
    try:
        host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise CachePolicyError("origin-invalid")
    _require(port is None or port == 443, "origin-port")
    suffix = "" if port is None or port == 443 else ":" + str(port)
    return "https://" + host + suffix


def _registry_origin_set(values):
    return frozenset(_normalize_origin(value) for value in values)


def _validate_package(manager, package, version):
    if manager == "cargo":
        _require(type(package) is str and CARGO_NAME.fullmatch(package) is not None, "package-name")
        _require(not package.lower().startswith(PRIVATE_PACKAGE_PREFIX), "private-package")
    else:
        _require(type(package) is str and NPM_NAME.fullmatch(package) is not None, "package-name")
        lowered = package.lower()
        _require(not lowered.startswith(PRIVATE_PACKAGE_PREFIX) and not lowered.startswith(PRIVATE_NPM_SCOPE),
                 "private-package")
    _require(type(version) is str and PACKAGE_VERSION.fullmatch(version) is not None, "package-version")


@dataclass(frozen=True)
class ArchiveRecord:
    manager: str
    package: str
    version: str
    registry: str
    archive_origin: str
    digest_algorithm: str
    digest_value: str
    archive_format: str

    @property
    def archive_digest(self):
        return self.digest_algorithm + ":" + self.digest_value

    @property
    def archive_path(self):
        identity = {
            "manager": self.manager,
            "package": self.package,
            "version": self.version,
            "registry": self.registry,
            "digest": self.archive_digest,
            "format": self.archive_format,
        }
        token = hashlib.sha256(_canonical_json(identity)).hexdigest()
        return "archives/" + self.manager + "/" + token + ".archive"

    def public_value(self):
        return {
            "registry": self.registry,
            "package": self.package,
            "version": self.version,
            "archive_digest": self.archive_digest,
            "format": self.archive_format,
        }


@dataclass(frozen=True)
class PublicLockProjection:
    records: Tuple[ArchiveRecord, ...]
    allowed_cargo_origins: Tuple[str, ...] = DEFAULT_CARGO_ORIGINS
    allowed_npm_origins: Tuple[str, ...] = DEFAULT_NPM_ORIGINS
    allowed_archive_origins: Tuple[str, ...] = DEFAULT_ARCHIVE_ORIGINS

    def __post_init__(self):
        _require(type(self.records) is tuple, "projection-records")
        _require(len(self.records) <= MAX_PROJECTION_RECORDS, "projection-record-limit")
        cargo_origins = tuple(sorted(_registry_origin_set(self.allowed_cargo_origins)))
        npm_origins = tuple(sorted(_registry_origin_set(self.allowed_npm_origins)))
        archive_origins = tuple(sorted(_registry_origin_set(self.allowed_archive_origins)))
        object.__setattr__(self, "allowed_cargo_origins", cargo_origins)
        object.__setattr__(self, "allowed_npm_origins", npm_origins)
        object.__setattr__(self, "allowed_archive_origins", archive_origins)
        expected = []
        identities = set()
        logical_identities = {}
        for record in self.records:
            _validate_record(record)
            if record.manager == "cargo":
                _require(record.archive_format == "crate" and record.digest_algorithm == "sha256",
                         "cargo-archive-format")
                _require(record.registry in cargo_origins, "registry-not-allowed")
            else:
                _require(record.archive_format == "npm-tarball", "npm-archive-format")
                _require(record.registry in npm_origins, "registry-not-allowed")
            _require(record.archive_origin in archive_origins, "archive-origin-not-allowed")
            identity = _canonical_json(record.public_value())
            _require(identity not in identities, "projection-duplicate")
            identities.add(identity)
            expected.append((identity, record))
            logical = (record.manager, record.registry, record.package, record.version)
            previous = logical_identities.get(logical)
            _require(previous is None or previous == (record.archive_digest, record.archive_origin),
                     "duplicate-lock-conflict")
            logical_identities[logical] = (record.archive_digest, record.archive_origin)
        ordered = tuple(record for _, record in sorted(expected, key=lambda pair: pair[0]))
        _require(ordered == self.records, "projection-not-canonical")
        _ = self.canonical_bytes

    def validate(self):
        self.__post_init__()

    @classmethod
    def from_records(cls, records, allowed_cargo_origins=DEFAULT_CARGO_ORIGINS,
                     allowed_npm_origins=DEFAULT_NPM_ORIGINS,
                     allowed_archive_origins=DEFAULT_ARCHIVE_ORIGINS):
        selected = []
        for record in records:
            _require(len(selected) < MAX_PROJECTION_RECORDS, "projection-record-limit")
            selected.append(record)
        cargo_origins = _registry_origin_set(allowed_cargo_origins)
        npm_origins = _registry_origin_set(allowed_npm_origins)
        archive_origins = _registry_origin_set(allowed_archive_origins)
        identities = {}
        logical_identities = {}
        for record in selected:
            _validate_record(record)
            if record.manager == "cargo":
                _require(record.archive_format == "crate" and record.digest_algorithm == "sha256",
                         "cargo-archive-format")
                _require(record.registry in cargo_origins, "registry-not-allowed")
            else:
                _require(record.archive_format == "npm-tarball", "npm-archive-format")
                _require(record.registry in npm_origins, "registry-not-allowed")
            _require(record.archive_origin in archive_origins, "archive-origin-not-allowed")
            identity = _canonical_json(record.public_value())
            logical = (record.manager, record.registry, record.package, record.version)
            previous_digest = logical_identities.get(logical)
            current_identity = (record.archive_digest, record.archive_origin)
            _require(previous_digest is None or previous_digest == current_identity,
                     "duplicate-lock-conflict")
            logical_identities[logical] = current_identity
            identities[identity] = record
        ordered = tuple(sorted(identities.values(), key=lambda item: _canonical_json(item.public_value())))
        return cls(ordered, tuple(cargo_origins), tuple(npm_origins), tuple(archive_origins))

    @property
    def canonical_bytes(self):
        chunks = []
        size = 2
        for item in self.records:
            chunk = _canonical_json(item.public_value())
            size += len(chunk) + bool(chunks)
            _require(size <= MAX_PROJECTION_BYTES, "projection-output-limit")
            chunks.append(chunk)
        return b"[" + b",".join(chunks) + b"]"

    @property
    def digest(self):
        return hashlib.sha256(self.canonical_bytes).hexdigest()

    @property
    def managers(self):
        return frozenset(item.manager for item in self.records)


def _validate_record(record):
    _require(isinstance(record, ArchiveRecord), "record-invalid")
    _require(record.manager in ("cargo", "npm"), "package-manager")
    _validate_package(record.manager, record.package, record.version)
    _require(record.registry == _normalize_origin(record.registry), "registry-origin")
    _require(record.archive_origin == _normalize_origin(record.archive_origin), "archive-origin")
    _require(record.archive_format in ("crate", "npm-tarball"), "archive-format")
    if record.digest_algorithm == "sha256":
        _require(HEX_64.fullmatch(record.digest_value) is not None, "archive-digest")
    elif record.digest_algorithm in ("sha384", "sha512"):
        try:
            decoded = base64.b64decode(record.digest_value.encode("ascii"), validate=True)
        except (UnicodeError, ValueError):
            raise CachePolicyError("archive-digest")
        expected_length = 48 if record.digest_algorithm == "sha384" else 64
        _require(len(decoded) == expected_length, "archive-digest")
    else:
        raise CachePolicyError("archive-digest-algorithm")


def _toml_string(value):
    _require(type(value) is str and len(value) >= 2 and value[0] == '"' and value[-1] == '"', "lock-string")
    try:
        result = json.loads(value)
    except (TypeError, ValueError):
        raise CachePolicyError("lock-string")
    _require(type(result) is str, "lock-string")
    return result


def _cargo_registry(source, allowed_origins):
    _require(source.startswith("registry+"), "lock-source-type")
    value = source[len("registry+"):]
    try:
        parsed = urlsplit(value)
        _ = parsed.port
    except ValueError:
        raise CachePolicyError("registry-origin")
    _require(parsed.scheme.lower() == "https" and parsed.hostname is not None, "registry-origin")
    _require(parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment,
             "registry-origin")
    origin = _normalize_origin(value)
    host = parsed.hostname.lower()
    if host == "github.com":
        _require(origin == "https://github.com", "registry-origin")
        _require(parsed.netloc.lower() in ("github.com", "github.com:443"), "registry-origin")
        _require(parsed.path.rstrip("/") == "/rust-lang/crates.io-index", "registry-origin")
        registry = "https://index.crates.io"
    else:
        _require(parsed.path in ("", "/"), "registry-origin")
        registry = origin
        _require(registry in allowed_origins, "registry-not-allowed")
    return registry


def _parse_cargo_lock(payload, cargo_archive_origins, allowed_cargo_origins):
    if payload is None:
        return []
    if type(payload) is bytes:
        try:
            payload = payload.decode("utf-8")
        except UnicodeDecodeError:
            raise CachePolicyError("cargo-lock-encoding")
    _require(type(payload) is str, "cargo-lock-type")
    records = []
    package = None

    def finish():
        if package is None:
            return
        name = package.get("name")
        version = package.get("version")
        _require(type(name) is str and type(version) is str, "cargo-lock-package")
        if package.get("source") is None:
            return
        registry = _cargo_registry(package["source"], allowed_cargo_origins)
        archive_origin = cargo_archive_origins.get(registry)
        _require(archive_origin is not None, "archive-origin-not-configured")
        checksum = package.get("checksum")
        _require(type(checksum) is str and HEX_64.fullmatch(checksum) is not None, "cargo-checksum")
        record = ArchiveRecord(
            "cargo", name, version, registry, archive_origin, "sha256", checksum, "crate"
        )
        _validate_record(record)
        _require(len(records) < MAX_PROJECTION_RECORDS, "projection-record-limit")
        records.append(record)

    for raw_line in payload.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(chr(35)):
            continue
        if line == "[[package]]":
            finish()
            package = {}
            continue
        if line.startswith("[[") or line.startswith("["):
            finish()
            package = None
            continue
        if package is None or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key in ("name", "version", "source", "checksum"):
            _require(key not in package, "cargo-lock-duplicate-field")
            package[key] = _toml_string(value)
    finish()
    return records


def _npm_integrity(value):
    _require(type(value) is str and value, "npm-integrity")
    candidates = []
    for item in value.split():
        if "-" not in item:
            continue
        algorithm, encoded = item.split("-", 1)
        if algorithm not in ("sha256", "sha384", "sha512"):
            continue
        try:
            decoded = base64.b64decode(encoded.encode("ascii"), validate=True)
        except (UnicodeError, ValueError):
            continue
        expected_length = {"sha256": 32, "sha384": 48, "sha512": 64}[algorithm]
        if len(decoded) == expected_length:
            digest = decoded.hex() if algorithm == "sha256" else base64.b64encode(decoded).decode("ascii")
            candidates.append((algorithm, digest))
    _require(bool(candidates), "npm-integrity")
    strengths = {"sha256": 1, "sha384": 2, "sha512": 3}
    return sorted(candidates, key=lambda item: strengths[item[0]], reverse=True)[0]


def _npm_name_from_path(path):
    parts = path.split("/")
    positions = [index for index, value in enumerate(parts) if value == "node_modules"]
    _require(bool(positions), "npm-package-path")
    start = positions[-1] + 1
    _require(start < len(parts), "npm-package-path")
    if parts[start].startswith("@"):
        _require(start + 1 < len(parts), "npm-package-path")
        return parts[start] + "/" + parts[start + 1]
    return parts[start]


def _npm_record(name, value, allowed_origins):
    _require(type(name) is str and type(value) is dict, "npm-lock-package")
    version = value.get("version")
    resolved = value.get("resolved")
    integrity = value.get("integrity")
    _require(type(resolved) is str, "npm-resolved")
    try:
        parsed = urlsplit(resolved)
        _ = parsed.port
    except ValueError:
        raise CachePolicyError("npm-resolved")
    _require(parsed.scheme.lower() == "https" and parsed.hostname is not None, "npm-resolved")
    _require(parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment,
             "npm-resolved")
    origin = _normalize_origin(resolved)
    _require(origin in allowed_origins, "registry-not-allowed")
    _require(parsed.path not in ("", "/"), "npm-resolved")
    algorithm, digest_value = _npm_integrity(integrity)
    _validate_package("npm", name, version)
    record = ArchiveRecord(
        "npm", name, version, origin, origin, algorithm, digest_value, "npm-tarball"
    )
    _validate_record(record)
    return record


def _parse_legacy_npm_dependencies(dependencies, allowed_origins, records):
    _require(type(dependencies) is dict, "npm-lock-dependencies")
    for name, value in dependencies.items():
        _require(type(name) is str and type(value) is dict, "npm-lock-package")
        _require(len(records) < MAX_PROJECTION_RECORDS, "projection-record-limit")
        records.append(_npm_record(name, value, allowed_origins))
        nested = value.get("dependencies", {})
        if nested:
            _parse_legacy_npm_dependencies(nested, allowed_origins, records)


def _parse_npm_lock(payload, allowed_npm_origins):
    if payload is None:
        return []
    if type(payload) is bytes:
        try:
            payload = payload.decode("utf-8")
        except UnicodeDecodeError:
            raise CachePolicyError("npm-lock-encoding")
    _require(type(payload) is str, "npm-lock-type")
    try:
        document = json.loads(payload)
    except (TypeError, ValueError):
        raise CachePolicyError("npm-lock-json")
    _require(type(document) is dict, "npm-lock-root")
    records = []
    packages = document.get("packages")
    if packages is not None:
        _require(type(packages) is dict, "npm-lock-packages")
        for path, value in packages.items():
            _require(type(path) is str, "npm-package-path")
            if path == "":
                continue
            _require(type(value) is dict, "npm-lock-package")
            if value.get("link") is True:
                continue
            name = value.get("name") or _npm_name_from_path(path)
            _require(len(records) < MAX_PROJECTION_RECORDS, "projection-record-limit")
            records.append(_npm_record(name, value, allowed_npm_origins))
    else:
        _parse_legacy_npm_dependencies(document.get("dependencies", {}), allowed_npm_origins, records)
    return records


def project_public_locks(
    cargo_lock=None,
    npm_lock=None,
    cargo_archive_origins=None,
    allowed_cargo_origins=DEFAULT_CARGO_ORIGINS,
    allowed_npm_origins=DEFAULT_NPM_ORIGINS,
):
    cargo_map = dict(DEFAULT_CARGO_ARCHIVES if cargo_archive_origins is None else cargo_archive_origins)
    cargo_map = {_normalize_origin(key): _normalize_origin(value) for key, value in cargo_map.items()}
    cargo_allowed = _registry_origin_set(allowed_cargo_origins)
    npm_allowed = _registry_origin_set(allowed_npm_origins)
    records = _parse_cargo_lock(cargo_lock, cargo_map, cargo_allowed)
    records.extend(_parse_npm_lock(npm_lock, npm_allowed))
    archive_origins = tuple(cargo_map.values()) + tuple(npm_allowed)
    return PublicLockProjection.from_records(records, tuple(cargo_allowed), tuple(npm_allowed), archive_origins)


@dataclass(frozen=True)
class ProjectionDecision:
    projection: Optional[PublicLockProjection]
    seed_allowed: bool
    cache_read_allowed: bool
    cold_required: bool
    reason: str


def decide_public_projection(*args, **kwargs):
    try:
        projection = project_public_locks(*args, **kwargs)
    except CachePolicyError as error:
        if error.code not in ("projection-record-limit", "projection-output-limit"):
            raise
        return ProjectionDecision(None, False, False, True, error.code)
    return ProjectionDecision(projection, True, True, False, "within-bound")


def toolchain_identity_digest(toolchains):
    _require(isinstance(toolchains, Mapping) and bool(toolchains), "toolchains-invalid")
    normalized = {}
    for name, identity in toolchains.items():
        _require(type(name) is str and IDENTITY_TOKEN.fullmatch(name) is not None, "toolchain-name")
        _require(type(identity) is str and identity and len(identity) <= 256, "toolchain-identity")
        normalized[name] = identity
    return hashlib.sha256(_canonical_json(normalized)).hexdigest()


def build_cache_key(source_slot, operating_system, architecture, toolchains, projection, schema=SCHEMA):
    _require(type(source_slot) is str and SLOT_TOKEN.fullmatch(source_slot) is not None, "source-slot")
    _require(type(operating_system) is str and KEY_COMPONENT_TOKEN.fullmatch(operating_system) is not None,
             "operating-system")
    _require(type(architecture) is str and KEY_COMPONENT_TOKEN.fullmatch(architecture) is not None,
             "architecture")
    _require(type(schema) is str and SCHEMA_TOKEN.fullmatch(schema) is not None, "cache-schema")
    _require(isinstance(projection, PublicLockProjection), "projection-invalid")
    projection.validate()
    toolchain_digest = toolchain_identity_digest(toolchains)
    return ".".join((schema, source_slot, operating_system, architecture, toolchain_digest, projection.digest))


@dataclass(frozen=True)
class CacheArchiveClaim:
    path: str
    manager: str
    package: str
    version: str
    registry: str
    origin: str
    digest_algorithm: str
    digest_value: str
    kind: str
    payload_class: str


@dataclass(frozen=True)
class CacheArchive(CacheArchiveClaim):
    data: bytes = b""
    staging_token: object = field(default=None, repr=False, compare=False)


_STAGED_ARCHIVE = object()


class BoundedArchiveStager:
    def __init__(self, max_bytes=ENTRY_LIMIT, max_files=MAX_FILES):
        _require(type(max_bytes) is int and 0 < max_bytes <= ENTRY_LIMIT, "staging-size-limit")
        _require(type(max_files) is int and 0 < max_files <= MAX_FILES, "staging-file-limit")
        self.max_bytes = max_bytes
        self.max_files = max_files
        self.total_bytes = 0
        self.transport_bytes = 0
        self.file_count = 0

    def stage(self, claim, chunks, compression="none"):
        _require(isinstance(claim, CacheArchiveClaim), "staging-claim")
        _require(self.file_count < self.max_files, "staging-file-limit")
        _require(compression in ("none", "zlib"), "staging-compression")
        _path_equivalence(claim.path)
        _require(claim.kind == "file", "archive-entry-kind")
        _require(claim.payload_class == "public-archive", "resolver-metadata-cached")
        try:
            iterator = iter(chunks)
        except TypeError:
            raise CachePolicyError("staging-chunks")
        decompressor = zlib.decompressobj() if compression == "zlib" else None
        output = bytearray()
        transport_size = 0
        for chunk in iterator:
            _require(type(chunk) is bytes, "staging-chunks")
            transport_size += len(chunk)
            _require(self.transport_bytes + transport_size <= ENTRY_LIMIT, "staging-transport-limit")
            remaining = self.max_bytes - self.total_bytes - len(output)
            if decompressor is None:
                extracted = chunk
            else:
                try:
                    extracted = decompressor.decompress(chunk, remaining + 1)
                except zlib.error:
                    raise CachePolicyError("staging-compression")
            _require(len(extracted) <= remaining, "archive-size-limit")
            output.extend(extracted)
            if decompressor is not None:
                _require(not decompressor.unconsumed_tail, "archive-size-limit")
        if decompressor is not None:
            remaining = self.max_bytes - self.total_bytes - len(output)
            try:
                trailing = decompressor.flush(remaining + 1)
            except zlib.error:
                raise CachePolicyError("staging-compression")
            _require(len(trailing) <= remaining, "archive-size-limit")
            output.extend(trailing)
            _require(decompressor.eof and not decompressor.unused_data, "staging-compression")
        self.total_bytes += len(output)
        self.transport_bytes += transport_size
        self.file_count += 1
        return CacheArchive(
            claim.path, claim.manager, claim.package, claim.version, claim.registry,
            claim.origin, claim.digest_algorithm, claim.digest_value, claim.kind,
            claim.payload_class, bytes(output), _STAGED_ARCHIVE,
        )


@dataclass(frozen=True)
class CacheEntry:
    key: str
    schema: str
    repository: str
    source_slot: str
    operating_system: str
    architecture: str
    toolchain_digest: str
    projection_digest: str
    scope: str
    reported_size: int
    file_count: int
    archives: Tuple[CacheArchive, ...]
    resolver_metadata: Tuple[object, ...] = ()


@dataclass(frozen=True)
class RestoreExpectation:
    repository: str
    source_slot: str
    operating_system: str
    architecture: str
    toolchains: Mapping[str, str]
    projection: PublicLockProjection
    visible_scopes: Tuple[str, ...]
    trusted_seed_scopes: Tuple[str, ...]
    schema: str = SCHEMA
    cache_read_mode_proved: bool = False
    confinement_profile_approved: bool = False
    protected_root_custody_proved: bool = False

    @property
    def key(self):
        return build_cache_key(
            self.source_slot,
            self.operating_system,
            self.architecture,
            self.toolchains,
            self.projection,
            self.schema,
        )


def _path_equivalence(path):
    _require(type(path) is str and path and path.isascii(), "archive-path")
    _require("\\" not in path, "archive-path-backslash")
    _require(not path.startswith("/"), "archive-path-absolute")
    _require(":" not in path, "archive-path-colon")
    _require(not any(ord(char) < 32 for char in path), "archive-path-control")
    parts = path.split("/")
    _require(all(part not in ("", ".") for part in parts), "archive-path-component")
    _require(all(part != ".." for part in parts), "archive-path-traversal")
    for part in parts:
        _require(part == part.rstrip(" ."), "archive-path-trailing")
        base = part.split(".", 1)[0].casefold()
        _require(base not in RESERVED_WINDOWS_NAMES, "archive-path-reserved")
    canonical = unicodedata.normalize("NFC", path)
    return canonical.casefold()


def _verify_member(member, record):
    _require(isinstance(member, CacheArchive), "archive-entry-type")
    _path_equivalence(member.path)
    _require(member.kind == "file", "archive-entry-kind")
    _require(member.payload_class == "public-archive", "resolver-metadata-cached")
    _require(member.path == record.archive_path, "archive-path-identity")
    _require(member.manager == record.manager, "archive-manager")
    _require(member.package == record.package and member.version == record.version, "archive-package")
    _require(member.registry == record.registry, "archive-registry")
    _require(member.origin == record.archive_origin, "archive-origin")
    _require(member.digest_algorithm == record.digest_algorithm, "archive-digest-algorithm")
    _require(member.digest_value == record.digest_value, "archive-digest")
    _require(type(member.data) is bytes, "archive-bytes")
    _require(_digest_matches(member.data, record.digest_algorithm, record.digest_value), "archive-bytes-digest")


def _digest_matches(payload, algorithm, expected):
    if algorithm == "sha256":
        return hashlib.sha256(payload).hexdigest() == expected
    if algorithm == "sha384":
        actual = base64.b64encode(hashlib.sha384(payload).digest()).decode("ascii")
        return actual == expected
    if algorithm == "sha512":
        actual = base64.b64encode(hashlib.sha512(payload).digest()).decode("ascii")
        return actual == expected
    return False


def _verify_archives(archives, projection, max_bytes=ENTRY_LIMIT):
    _require(type(archives) in (tuple, list), "archive-manifest")
    _require(len(archives) <= MAX_FILES, "archive-file-count")
    expected = {record.archive_path: record for record in projection.records}
    seen_paths = set()
    seen_equivalent = set()
    total = 0
    verified = {}
    for member in archives:
        _require(isinstance(member, CacheArchive), "archive-entry-type")
        _require(member.staging_token is _STAGED_ARCHIVE, "archive-not-staged")
        _require(type(member.data) is bytes, "archive-bytes")
        total += len(member.data)
        _require(total <= max_bytes, "archive-size-limit")
        equivalent = _path_equivalence(member.path)
        _require(equivalent not in seen_equivalent, "archive-path-collision")
        seen_equivalent.add(equivalent)
        _require(member.path not in seen_paths, "archive-path-duplicate")
        seen_paths.add(member.path)
        record = expected.get(member.path)
        _require(record is not None, "archive-not-in-lock")
        _verify_member(member, record)
        verified[member.path] = bytes(bytearray(member.data))
    _require(seen_paths == set(expected), "archive-manifest-mismatch")
    return verified, total


def _recheck_copy(projection, copied, max_bytes=ENTRY_LIMIT):
    expected = {record.archive_path: record for record in projection.records}
    _require(set(copied) == set(expected), "protected-copy-manifest")
    total = 0
    for path, payload in copied.items():
        record = expected[path]
        _require(type(payload) is bytes, "protected-copy-digest")
        total += len(payload)
        _require(total <= max_bytes, "protected-copy-size-limit")
        _require(_digest_matches(payload, record.digest_algorithm, record.digest_value),
                 "protected-copy-digest")


def verify_protected_copy(projection, copied):
    _require(isinstance(projection, PublicLockProjection), "projection-invalid")
    _recheck_copy(projection, copied)
    return MappingProxyType(dict(copied))


@dataclass(frozen=True)
class CorruptionResponse:
    failures: int
    cache_usable: bool
    quarantine: bool
    reviewed_cleanup_request: bool


def record_corrupt_entry(previous_failures):
    _require(type(previous_failures) is int and previous_failures >= 0, "corruption-count")
    failures = previous_failures + 1
    repeated = failures >= 2
    return CorruptionResponse(failures, False, repeated, repeated)


def verify_restore(entry, expectation):
    _require(isinstance(expectation, RestoreExpectation), "restore-expectation")
    _require(isinstance(expectation.projection, PublicLockProjection), "projection-invalid")
    _require(SLOT_TOKEN.fullmatch(expectation.source_slot or "") is not None, "source-slot")
    _require(
        expectation.cache_read_mode_proved is True
        and expectation.confinement_profile_approved is True
        and expectation.protected_root_custody_proved is True,
        "restore-authority-unproved",
    )
    _require(entry is not None and isinstance(entry, CacheEntry), "cache-miss")
    _require(entry.key == expectation.key, "key-mismatch")
    _require(entry.schema == expectation.schema, "schema-mismatch")
    _require(entry.repository == expectation.repository, "repository-mismatch")
    _require(entry.source_slot == expectation.source_slot, "source-slot-mismatch")
    _require(entry.operating_system == expectation.operating_system, "operating-system-mismatch")
    _require(entry.architecture == expectation.architecture, "architecture-mismatch")
    _require(entry.toolchain_digest == toolchain_identity_digest(expectation.toolchains), "toolchain-mismatch")
    _require(entry.projection_digest == expectation.projection.digest, "projection-mismatch")
    _require(entry.scope in expectation.visible_scopes, "scope-not-visible")
    _require(entry.scope in expectation.trusted_seed_scopes, "untrusted-scope")
    _require(type(entry.reported_size) is int and 0 <= entry.reported_size <= ENTRY_LIMIT, "entry-size-limit")
    _require(type(entry.file_count) is int and entry.file_count == len(entry.archives), "entry-file-count")
    _require(entry.file_count <= MAX_FILES, "entry-file-count")
    _require(type(entry.resolver_metadata) is tuple, "entry-manifest")
    _require(not entry.resolver_metadata, "resolver-metadata-cached")
    copied, payload_size = _verify_archives(entry.archives, expectation.projection)
    _require(payload_size <= entry.reported_size, "entry-size-underreported")
    _recheck_copy(expectation.projection, copied)
    return MappingProxyType(copied)


@dataclass(frozen=True)
class ResolverMetadata:
    manager: str
    origin: str
    data: bytes
    from_cache: bool = False


@dataclass(frozen=True)
class ColdPreparation:
    archives: Tuple[CacheArchive, ...]
    resolver_metadata: Tuple[ResolverMetadata, ...]
    trusted_setup_complete: bool
    offline_ready: bool


@dataclass(frozen=True)
class FreshResolverPreparation:
    resolver_metadata: Tuple[ResolverMetadata, ...]
    trusted_setup_complete: bool
    offline_ready: bool


@dataclass(frozen=True)
class RestoreDecision:
    status: str
    reason: str
    cache_hit: bool
    verified: bool
    archives: Optional[Mapping[str, bytes]]
    resolver_metadata: Tuple[ResolverMetadata, ...] = ()


def _verify_resolver_preparation(preparation, projection):
    _require(isinstance(preparation, (ColdPreparation, FreshResolverPreparation)),
             "resolver-preparation-missing")
    _require(preparation.trusted_setup_complete is True and preparation.offline_ready is True,
             "resolver-setup-incomplete")
    _require(type(preparation.resolver_metadata) is tuple, "resolver-metadata-type")
    required_sources = frozenset((record.manager, record.registry) for record in projection.records)
    seen_sources = set()
    for metadata in preparation.resolver_metadata:
        _require(isinstance(metadata, ResolverMetadata), "resolver-metadata-type")
        _require(metadata.manager in ("cargo", "npm"), "resolver-manager")
        _require(metadata.from_cache is False, "resolver-metadata-cached")
        _require(type(metadata.data) is bytes and 0 < len(metadata.data) <= ENTRY_LIMIT,
                 "resolver-metadata-size")
        origin = _normalize_origin(metadata.origin)
        source = (metadata.manager, origin)
        _require(source in required_sources, "resolver-origin")
        seen_sources.add(source)
    _require(required_sources.issubset(seen_sources), "resolver-metadata-missing")
    return preparation.resolver_metadata


def _verify_cold_preparation(preparation, projection):
    _require(isinstance(preparation, ColdPreparation), "cold-preparation-missing")
    _verify_resolver_preparation(preparation, projection)
    copied, _ = _verify_archives(preparation.archives, projection)
    return MappingProxyType(copied)


def decide_restore(entry, expectation, cold_preparation=None, resolver_preparation=None):
    try:
        restored = verify_restore(entry, expectation)
    except CachePolicyError as error:
        cache_reason = error.code
    else:
        try:
            fresh_metadata = _verify_resolver_preparation(
                resolver_preparation if resolver_preparation is not None else cold_preparation,
                expectation.projection,
            )
        except CachePolicyError as error:
            cache_reason = error.code
        else:
            return RestoreDecision("cache", "verified-hit", True, True, restored, fresh_metadata)
    if cold_preparation is None:
        return RestoreDecision("cold-required", cache_reason, False, False, None)
    try:
        cold_archives = _verify_cold_preparation(cold_preparation, expectation.projection)
        return RestoreDecision(
            "cold", cache_reason, False, True, cold_archives, cold_preparation.resolver_metadata
        )
    except CachePolicyError:
        return RestoreDecision("fail", "cold-preparation-invalid", False, False, None)


@dataclass(frozen=True)
class ScopeContext:
    repository_namespace: str
    current_scope: str
    default_scope: str
    pull_request_scope: Optional[str] = None
    base_scope: Optional[str] = None
    independent_fork: bool = False


def provider_lookup_scopes(context):
    _require(isinstance(context, ScopeContext), "scope-context")
    namespace = context.repository_namespace
    _require(type(namespace) is str and namespace, "scope-namespace")
    if context.independent_fork:
        values = (context.current_scope, context.default_scope)
        return tuple(namespace + ":" + value for value in values if value)
    if context.pull_request_scope:
        base = context.base_scope or context.default_scope
        values = (context.pull_request_scope, base, context.default_scope)
    else:
        values = (context.current_scope, context.default_scope)
    result = []
    for value in values:
        if value and value not in result:
            result.append(value)
    return tuple(result)


def provider_write_scope(context):
    _require(isinstance(context, ScopeContext), "scope-context")
    if context.independent_fork:
        return context.repository_namespace + ":" + context.current_scope
    return context.pull_request_scope or context.current_scope


def validate_dispatch_origin(expected_repository, actual_repository, control_ref, allowed_refs):
    return (
        type(expected_repository) is str
        and bool(expected_repository)
        and actual_repository == expected_repository
        and type(control_ref) is str
        and control_ref in tuple(allowed_refs)
    )


def validate_dispatch_attempt(source_sha, previous_source_shas, reason_recorded,
                              watcher_count, watcher_interval_seconds):
    if type(source_sha) is not str or HEX_40.fullmatch(source_sha) is None:
        return False
    if type(previous_source_shas) not in (tuple, list):
        return False
    if any(type(value) is not str or HEX_40.fullmatch(value) is None for value in previous_source_shas):
        return False
    if source_sha in previous_source_shas and reason_recorded is not True:
        return False
    return (
        type(watcher_count) is int
        and watcher_count == 1
        and type(watcher_interval_seconds) is int
        and watcher_interval_seconds >= 300
    )


@dataclass(frozen=True)
class JobCapabilities:
    cache_mode: str
    source_read: bool
    candidate_execution: bool
    actions_write: bool
    source_free: bool


def job_capabilities(job_class, control_ref):
    if job_class == "projection" and control_ref == "refs/heads/main":
        return JobCapabilities("none", True, False, False, False)
    if job_class == "seed" and control_ref == "refs/heads/main":
        return JobCapabilities("write", False, False, False, True)
    if job_class == "worker" and control_ref in ("refs/heads/main", "refs/heads/untrusted"):
        return JobCapabilities("read", True, True, False, False)
    if job_class == "cleaner" and control_ref == "refs/heads/main":
        return JobCapabilities("none", False, False, True, True)
    return JobCapabilities("none", False, False, False, True)


def authorize_job_action(job_class, control_ref, action, candidate_process=False):
    caps = job_capabilities(job_class, control_ref)
    if candidate_process and action in (
        "cache_restore", "cache_save", "cache_reserve", "cache_delete", "post_job_save",
        "actions_api_delete", "source_read", "github_token",
    ):
        return False
    if action == "candidate_execute":
        return caps.candidate_execution
    if action == "cache_restore":
        return caps.cache_mode == "read"
    if action in ("cache_save", "cache_reserve"):
        return caps.cache_mode == "write"
    if action in ("cache_delete", "actions_api_delete"):
        return caps.actions_write and job_class == "cleaner"
    if action == "post_job_save":
        return False
    if action == "source_read":
        return caps.source_read
    if action == "source_free":
        return caps.source_free
    return False


def validate_cleaner_authority(control_ref, token_scope, actions_permission, cache_mode,
                               source_read, candidate_execution, private_app_key):
    return (
        control_ref == "refs/heads/main"
        and token_scope == "repository"
        and actions_permission == "write"
        and cache_mode == "none"
        and source_read is False
        and candidate_execution is False
        and private_app_key is False
    )


@dataclass(frozen=True)
class ConfinementEvidence:
    operating_system: str
    approved_profiles: Tuple[str, ...]
    whole_invocation_covered: bool
    network_denied: bool
    secret_access_denied: bool
    output_bounded: bool
    workflow_commands_blocked: bool
    runner_paths_blocked: bool
    cache_api_blocked: bool
    process_tree_contained: bool


EXECUTION_CLASSES = (
    "cargo-startup",
    "cargo-alias-config",
    "build-script",
    "procedural-macro",
    "generator-compiler",
    "generator",
    "child-process",
)
CONFINEMENT_ATTEMPTS = (
    "network",
    "private-canary-output",
    "workflow-command",
    "runner-summary-output-artifact",
    "cache-api",
    "survivor-process",
)


def candidate_execution_admitted(command_class, evidence):
    _require(command_class in EXECUTION_CLASSES, "candidate-command-class")
    _require(isinstance(evidence, ConfinementEvidence), "confinement-evidence")
    _require(evidence.operating_system in ("linux", "windows", "macos"), "confinement-os")
    if evidence.operating_system not in evidence.approved_profiles:
        return False
    return all(
        value is True
        for value in (
            evidence.whole_invocation_covered,
            evidence.network_denied,
            evidence.secret_access_denied,
            evidence.output_bounded,
            evidence.workflow_commands_blocked,
            evidence.runner_paths_blocked,
            evidence.cache_api_blocked,
            evidence.process_tree_contained,
        )
    )


@dataclass(frozen=True)
class TreeEntry:
    path: str
    data: bytes
    kind: str = "file"
    mode: int = 420


def _tree_digest(entries):
    _require(type(entries) in (tuple, list), "tree-manifest")
    _require(len(entries) <= MAX_FILES, "tree-file-count")
    canonical = {}
    equivalents = set()
    for entry in entries:
        _require(isinstance(entry, TreeEntry), "tree-entry-type")
        equivalent = _path_equivalence(entry.path)
        _require(entry.path.startswith("vendor/"), "tree-path-external")
        _require(equivalent not in equivalents, "tree-path-collision")
        equivalents.add(equivalent)
        _require(entry.kind == "file", "tree-entry-kind")
        _require(type(entry.data) is bytes, "tree-entry-bytes")
        _require(type(entry.mode) is int and 0 <= entry.mode <= 4095, "tree-entry-mode")
        canonical[entry.path] = entry
    digest = hashlib.sha256()
    for path in sorted(canonical):
        entry = canonical[path]
        path_bytes = path.encode("ascii")
        digest.update(len(path_bytes).to_bytes(4, "big"))
        digest.update(path_bytes)
        digest.update(entry.mode.to_bytes(4, "big"))
        digest.update(len(entry.data).to_bytes(8, "big"))
        digest.update(entry.data)
    return digest.hexdigest()


@dataclass(frozen=True)
class OverlayEvidence:
    trusted_vendor: Tuple[TreeEntry, ...]
    staged_vendor: Tuple[TreeEntry, ...]
    promoted_vendor: Tuple[TreeEntry, ...]
    expected_pin_sha: str
    actual_pin_sha: str
    expected_patches: Tuple[Tuple[str, str], ...]
    staged_patches: Tuple[Tuple[str, str], ...]
    expected_file_overrides: Tuple[Tuple[str, str], ...]
    staged_file_overrides: Tuple[Tuple[str, str], ...]
    expected_lock_sources: Tuple[Tuple[str, str], ...]
    staged_lock_sources: Tuple[Tuple[str, str], ...]
    stable_during_hashing: bool
    protected_after_promotion: bool
    alternate_configuration_sources: bool = False
    protected_paths: Tuple[str, ...] = ("vendor", "pin", "lock", "config")
    mutation_attempts: Tuple[str, ...] = ()
    blocked_mutations: Tuple[str, ...] = ()


def _validate_path_pairs(pairs, code):
    seen = set()
    for item in pairs:
        _require(type(item) is tuple and len(item) == 2, code)
        name, path = item
        _require(type(name) is str and name and type(path) is str, code)
        _require(name.isascii() and not any(ord(char) < 32 for char in name), code)
        key = name.casefold()
        _require(key not in seen, code + "-duplicate")
        seen.add(key)
        _path_equivalence(path)
        _require(path.startswith("vendor/"), code + "-external")


def _tree_pair_set(pairs):
    return tuple(sorted(tuple(item) for item in pairs))


def validate_overlay(evidence):
    _require(isinstance(evidence, OverlayEvidence), "overlay-evidence")
    _require(HEX_40.fullmatch(evidence.expected_pin_sha) is not None, "pin-identity")
    _require(evidence.actual_pin_sha == evidence.expected_pin_sha, "pin-identity")
    _require(evidence.stable_during_hashing is True, "tree-mutated-during-hash")
    _require(evidence.alternate_configuration_sources is False, "alternate-configuration")
    for values in (evidence.protected_paths, evidence.mutation_attempts, evidence.blocked_mutations):
        _require(type(values) is tuple and all(type(value) is str for value in values),
                 "promoted-mutation-record")
        _require(len(set(values)) == len(values), "promoted-mutation-record")
    protected = set(evidence.protected_paths)
    required_protected = {"vendor", "pin", "lock", "config"}
    _require(required_protected.issubset(protected), "promoted-path-mutable")
    attempts = set(evidence.mutation_attempts)
    blocked = set(evidence.blocked_mutations)
    _require(attempts.issubset(required_protected) and blocked.issubset(required_protected),
             "promoted-mutation-record")
    _require(attempts == blocked, "promoted-mutation-allowed")
    _validate_path_pairs(evidence.expected_patches, "patch-path")
    _validate_path_pairs(evidence.staged_patches, "patch-path")
    _validate_path_pairs(evidence.expected_file_overrides, "file-override")
    _validate_path_pairs(evidence.staged_file_overrides, "file-override")
    _require(_tree_pair_set(evidence.expected_patches) == _tree_pair_set(evidence.staged_patches),
             "patch-manifest")
    _require(_tree_pair_set(evidence.expected_file_overrides) == _tree_pair_set(evidence.staged_file_overrides),
             "file-override-manifest")
    _require(type(evidence.expected_lock_sources) is tuple and type(evidence.staged_lock_sources) is tuple,
             "lock-source-manifest")
    for source_record in evidence.expected_lock_sources + evidence.staged_lock_sources:
        _require(type(source_record) is tuple and len(source_record) == 2, "lock-source-manifest")
        _require(all(type(value) is str and value for value in source_record), "lock-source-manifest")
    _require(tuple(sorted(evidence.expected_lock_sources)) == tuple(sorted(evidence.staged_lock_sources)),
             "lock-source-mismatch")
    trusted_digest = _tree_digest(evidence.trusted_vendor)
    staged_digest = _tree_digest(evidence.staged_vendor)
    promoted_digest = _tree_digest(evidence.promoted_vendor)
    _require(staged_digest == trusted_digest, "staged-vendor-mismatch")
    _require(promoted_digest == staged_digest, "promoted-vendor-mismatch")
    _require(evidence.protected_after_promotion is True, "promoted-vendor-mutable")
    return {
        "trusted_tree_digest": trusted_digest,
        "staged_tree_digest": staged_digest,
        "promoted_tree_digest": promoted_digest,
    }


@dataclass(frozen=True)
class CacheRecord:
    cache_id: str
    source_slot: str
    key: str
    operating_system: str
    architecture: str
    projection_digest: str
    reported_size: int
    last_access_seconds: int
    scope: str = "refs/heads/main"


@dataclass(frozen=True)
class CacheInventory:
    entries: Tuple[CacheRecord, ...]
    complete: bool
    list_requests: int
    fresh: bool = True


@dataclass(frozen=True)
class CleanupPlan:
    deletions: Tuple[Tuple[str, str], ...]
    requests_used: int
    backlog: bool
    concurrency_group: str
    cancel_in_progress: bool
    cache_mode: str
    source_read: bool
    candidate_execution: bool
    actions_permission: str
    allowed_operations: Tuple[str, ...]


def _source_limit(source_count):
    _require(type(source_count) is int and source_count > 0, "source-count")
    return min(SOURCE_LIMIT, REPOSITORY_LIMIT // source_count)


def _validate_cache_record(item):
    _require(isinstance(item, CacheRecord), "inventory-entry")
    _require(type(item.cache_id) is str and 1 <= len(item.cache_id) <= 256, "inventory-cache-id")
    _require(type(item.key) is str and 1 <= len(item.key) <= 1024, "inventory-cache-key")
    _require(type(item.source_slot) is str and SLOT_TOKEN.fullmatch(item.source_slot) is not None,
             "inventory-source-slot")
    _require(type(item.operating_system) is str and KEY_COMPONENT_TOKEN.fullmatch(item.operating_system) is not None,
             "inventory-operating-system")
    _require(type(item.architecture) is str and KEY_COMPONENT_TOKEN.fullmatch(item.architecture) is not None,
             "inventory-architecture")
    _require(type(item.projection_digest) is str and HEX_64.fullmatch(item.projection_digest) is not None,
             "inventory-projection")
    _require(type(item.reported_size) is int and item.reported_size >= 0, "inventory-size")
    _require(type(item.last_access_seconds) is int and item.last_access_seconds >= 0, "inventory-time")
    _require(type(item.scope) is str and bool(item.scope), "inventory-scope")


def _validate_inventory(inventory):
    _require(isinstance(inventory, CacheInventory), "inventory-type")
    _require(type(inventory.complete) is bool, "inventory-complete")
    _require(type(inventory.list_requests) is int and inventory.list_requests >= 0, "inventory-requests")
    _require(type(inventory.fresh) is bool, "inventory-freshness")
    _require(type(inventory.entries) is tuple, "inventory-entries")
    for item in inventory.entries:
        _validate_cache_record(item)
    _require(len({item.cache_id for item in inventory.entries}) == len(inventory.entries),
             "inventory-duplicate-id")


def plan_cleanup(inventory, now_seconds, active_source_slots, current_projection_digests,
                 request_limit=MAX_CLEANUP_REQUESTS):
    _require(isinstance(inventory, CacheInventory), "inventory-type")
    _require(type(now_seconds) is int and now_seconds >= 0, "clock-value")
    _require(type(request_limit) is int and 1 <= request_limit <= MAX_CLEANUP_REQUESTS, "request-limit")
    slots = tuple(active_source_slots)
    _require(bool(slots) and all(type(slot) is str and SLOT_TOKEN.fullmatch(slot) is not None for slot in slots),
             "source-slots")
    _require(len(set(slots)) == len(slots), "source-slots")
    _source_limit(len(slots))
    _require(isinstance(current_projection_digests, Mapping), "projection-inventory")
    for partition, digest in current_projection_digests.items():
        _require(type(partition) is tuple and len(partition) == 3, "projection-inventory")
        _require(type(digest) is str and HEX_64.fullmatch(digest) is not None, "projection-inventory")
    if (not inventory.complete or inventory.fresh is not True
            or type(inventory.list_requests) is not int or inventory.list_requests < 1):
        return CleanupPlan((), 0, True, CONCURRENCY_GROUP, False, "none", False, False,
                           "write", (CACHE_LIST_ENDPOINT, CACHE_DELETE_ENDPOINT))
    if inventory.list_requests > request_limit:
        return CleanupPlan((), inventory.list_requests, True, CONCURRENCY_GROUP, False, "none", False,
                           False, "write", (CACHE_LIST_ENDPOINT, CACHE_DELETE_ENDPOINT))
    _validate_inventory(inventory)
    entries = tuple(inventory.entries)
    _require(len({item.cache_id for item in entries}) == len(entries), "inventory-duplicate-id")
    active = set(slots)
    source_caps = {slot: _source_limit(len(slots)) for slot in slots}
    by_id = {item.cache_id: item for item in entries}
    reasons = {}
    for item in entries:
        partition = (item.source_slot, item.operating_system, item.architecture)
        current_digest = current_projection_digests.get(partition)
        age = now_seconds - item.last_access_seconds
        if item.source_slot not in active:
            reasons[item.cache_id] = "orphaned-source"
        elif item.scope != "refs/heads/main":
            reasons[item.cache_id] = "non-main-scope"
        elif item.reported_size > ENTRY_LIMIT:
            reasons[item.cache_id] = "entry-over-limit"
        elif current_digest is not None and item.projection_digest != current_digest:
            reasons[item.cache_id] = "superseded"
        elif age >= IDLE_RETIREMENT_SECONDS:
            reasons[item.cache_id] = "idle"
    selected = {}
    precedence = {"orphaned-source": 0, "non-main-scope": 1, "entry-over-limit": 2,
                  "superseded": 3, "idle": 4}
    for cache_id in sorted(reasons, key=lambda value: (precedence[reasons[value]],
                                                        by_id[value].last_access_seconds, value)):
        selected[cache_id] = reasons[cache_id]

    def remaining():
        return [item for item in entries if item.cache_id not in selected]

    def over_budget(current):
        total = sum(item.reported_size for item in current)
        per_source = {}
        partitions = {}
        for item in current:
            per_source[item.source_slot] = per_source.get(item.source_slot, 0) + item.reported_size
            partition = (item.source_slot, item.operating_system, item.architecture)
            partitions[partition] = partitions.get(partition, 0) + 1
        if total > REPOSITORY_LIMIT:
            return "repository-over-budget", None
        for slot, size in per_source.items():
            if slot in source_caps and size > source_caps[slot]:
                return "source-over-budget", slot
        for partition, count in partitions.items():
            if count > MAX_KEYS_PER_PARTITION:
                return "partition-over-limit", partition
        return None, None

    while True:
        current = remaining()
        budget_reason, affected_slot = over_budget(current)
        if budget_reason is None:
            break
        if budget_reason == "partition-over-limit":
            possible = [item for item in current
                        if (item.source_slot, item.operating_system, item.architecture) == affected_slot]
        elif budget_reason == "source-over-budget":
            possible = [item for item in current if item.source_slot == affected_slot]
        else:
            possible = current
        if not possible:
            break
        victim = min(possible, key=lambda item: (item.last_access_seconds, item.cache_id))
        selected[victim.cache_id] = budget_reason

    delete_slots = max(0, request_limit - inventory.list_requests)
    ordered = sorted(selected, key=lambda value: (precedence.get(selected[value], 5),
                                                   by_id[value].last_access_seconds, value))
    chosen = ordered[:delete_slots]
    left = [value for value in ordered if value not in chosen]
    final_entries = [item for item in entries if item.cache_id not in chosen]
    still_over, _ = over_budget(final_entries)
    backlog = bool(left or still_over)
    return CleanupPlan(
        tuple((cache_id, selected[cache_id]) for cache_id in chosen),
        inventory.list_requests + len(chosen),
        backlog,
        CONCURRENCY_GROUP,
        False,
        "none",
        False,
        False,
        "write",
        (CACHE_LIST_ENDPOINT, CACHE_DELETE_ENDPOINT),
    )


@dataclass(frozen=True)
class AdmissionDecision:
    admitted: bool
    reason: str
    reservation_bytes: int
    repository_limit: int
    source_limit: int
    concurrency_group: str
    cancel_in_progress: bool


def admit_save(inventory, source_slots, source_slot, operating_system, architecture, key,
               staged_upper_bound, reservation_proven, packaging_overhead_included,
               cleanup_backlog=False, maintenance_in_progress=False):
    slots = tuple(source_slots)
    if (not slots or any(type(slot) is not str or SLOT_TOKEN.fullmatch(slot) is None for slot in slots)
            or len(set(slots)) != len(slots)):
        return AdmissionDecision(False, "source-slots-invalid", 0, REPOSITORY_LIMIT, 0,
                                 CONCURRENCY_GROUP, False)
    source_cap = _source_limit(len(slots)) if slots else 0
    def reject(reason, reservation=0):
        return AdmissionDecision(False, reason, reservation, REPOSITORY_LIMIT, source_cap,
                                 CONCURRENCY_GROUP, False)
    if source_slot not in slots:
        return reject("source-slot-unknown")
    if (not isinstance(inventory, CacheInventory) or not inventory.complete
            or type(inventory.list_requests) is not int or inventory.list_requests < 1):
        return reject("inventory-incomplete")
    if inventory.fresh is not True:
        return reject("inventory-stale")
    try:
        _validate_inventory(inventory)
    except CachePolicyError:
        return reject("inventory-invalid")
    if reservation_proven is not True or packaging_overhead_included is not True:
        return reject("reservation-unproved")
    if type(staged_upper_bound) is not int or staged_upper_bound <= 0:
        return reject("reservation-invalid")
    if staged_upper_bound > ENTRY_LIMIT:
        return reject("entry-limit", staged_upper_bound)
    if cleanup_backlog:
        return reject("cleanup-backlog", staged_upper_bound)
    if maintenance_in_progress:
        return reject("maintenance-concurrent", staged_upper_bound)
    if (type(operating_system) is not str or KEY_COMPONENT_TOKEN.fullmatch(operating_system) is None
            or type(architecture) is not str or KEY_COMPONENT_TOKEN.fullmatch(architecture) is None
            or type(key) is not str or not key):
        return reject("admission-identity-invalid", staged_upper_bound)
    entries = tuple(inventory.entries)
    if any(item.reported_size > ENTRY_LIMIT for item in entries):
        return reject("entry-over-limit-inventory", staged_upper_bound)
    if any(item.cache_id == key or item.key == key for item in entries):
        return reject("already-present", staged_upper_bound)
    partition = (source_slot, operating_system, architecture)
    partition_count = sum(
        1 for item in entries
        if (item.source_slot, item.operating_system, item.architecture) == partition
    )
    if partition_count >= MAX_KEYS_PER_PARTITION:
        return reject("partition-key-limit", staged_upper_bound)
    repository_used = sum(item.reported_size for item in entries)
    source_used = sum(item.reported_size for item in entries if item.source_slot == source_slot)
    if repository_used + staged_upper_bound > REPOSITORY_LIMIT:
        return reject("repository-capacity", staged_upper_bound)
    if source_used + staged_upper_bound > source_cap:
        return reject("source-capacity", staged_upper_bound)
    return AdmissionDecision(True, "reserved", staged_upper_bound, REPOSITORY_LIMIT, source_cap,
                             CONCURRENCY_GROUP, False)


@dataclass(frozen=True)
class SaveReconciliation:
    freeze_saves: bool
    reason: str
    reserved_bytes: int
    provider_reported_bytes: int


def reconcile_save(reserved_bytes, provider_reported_bytes):
    valid = type(reserved_bytes) is int and reserved_bytes > 0
    valid = valid and type(provider_reported_bytes) is int and provider_reported_bytes >= 0
    if not valid:
        return SaveReconciliation(True, "size-invalid", 0, 0)
    exceeded = provider_reported_bytes > reserved_bytes or provider_reported_bytes > ENTRY_LIMIT
    return SaveReconciliation(exceeded, "reservation-exceeded" if exceeded else "within-reservation",
                              reserved_bytes, provider_reported_bytes)


def classify_api_failure(status_code, headers):
    if status_code != 403:
        return "not-rate-limit-403"
    normalized = {str(key).lower(): str(value) for key, value in headers.items()}
    remaining = normalized.get("x-ratelimit-remaining")
    reset = normalized.get("x-ratelimit-reset")
    if remaining == "0" and reset is not None and reset.isdigit():
        return "wait-until-reset"
    return "authorization-defect"


@dataclass(frozen=True)
class PathComparison:
    output_equal: bool
    cold_wall_seconds: float
    warm_wall_seconds: float
    cold_runner_minutes: float
    warm_runner_minutes: float


def compare_cold_warm(cold_output_digest, warm_output_digest, cold_wall_seconds, warm_wall_seconds,
                      cold_runner_minutes, warm_runner_minutes):
    _require(HEX_64.fullmatch(cold_output_digest or "") is not None, "cold-output-digest")
    _require(HEX_64.fullmatch(warm_output_digest or "") is not None, "warm-output-digest")
    metrics = (cold_wall_seconds, warm_wall_seconds, cold_runner_minutes, warm_runner_minutes)
    _require(all(type(value) in (int, float) and value >= 0 for value in metrics), "performance-metrics")
    return PathComparison(
        cold_output_digest == warm_output_digest,
        float(cold_wall_seconds),
        float(warm_wall_seconds),
        float(cold_runner_minutes),
        float(warm_runner_minutes),
    )


def utc_timestamp(value):
    _require(isinstance(value, datetime) and value.tzinfo is not None, "timestamp-invalid")
    return int(value.astimezone(timezone.utc).timestamp())
