"""Fetch and authenticate crates.io archives for the trusted Rust licence gate."""

import gzip
import hashlib
import hmac
import io
import json
import re
import tarfile
import urllib.error
import urllib.request

import cargo_lock_receipt
import rust_license_gate


ARCHIVE_ORIGIN = "https://static.crates.io"
REGISTRY_SOURCE = cargo_lock_receipt.REGISTRY_SOURCE
MAX_ARCHIVE_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_FILES = 12000
MAX_PACKAGE_BYTES = 512 * 1024 * 1024
MAX_TAR_BYTES = MAX_PACKAGE_BYTES + MAX_ARCHIVE_FILES * 1024
MAX_CARGO_TOML_BYTES = 2 * 1024 * 1024
MAX_NOTICE_BYTES = 16 * 1024 * 1024
PROCESS_TIMEOUT_SECONDS = 30
PACKAGE_NAME_RE = re.compile(r"[a-zA-Z0-9_-]{1,128}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9.+_-]{1,128}\Z")
LICENSE_LINE_RE = re.compile(r'^\s*license\s*=\s*"([^"\r\n]{1,16384})"\s*\Z')
LICENSE_PATH_RE = re.compile(r"(?:^|/)(?:license|copying|notice|copyright)(?:[-_.][A-Za-z0-9._-]+)?\Z", re.I)


class ArchiveProducerRefusal(Exception):
    """A registry/archive refusal without package-derived detail."""


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        del request, response, code, message, headers, new_url
        return None


def _refuse():
    raise ArchiveProducerRefusal("cargo_archive_invalid")


def _archive_url(package):
    if (type(package) is not rust_license_gate.Package
            or PACKAGE_NAME_RE.fullmatch(package.name or "") is None
            or VERSION_RE.fullmatch(package.version or "") is None
            or re.fullmatch(r"[a-f0-9]{64}", package.checksum or "") is None):
        _refuse()
    return ARCHIVE_ORIGIN + "/crates/" + package.name + "/" + package.name + "-" + package.version + ".crate"


def _registry_packages(lock_bytes, identity):
    try:
        parsed = cargo_lock_receipt.parse_cargo_lock(lock_bytes)
    except cargo_lock_receipt.Refusal:
        _refuse()
    packages = tuple(sorted((
        rust_license_gate.Package(item["name"], item["version"], item["checksum"])
        for item in parsed["packages"]
        if item.get("source") == REGISTRY_SOURCE
    ), key=lambda item: (item.name, item.version, item.checksum)))
    if not packages or len(set((item.name, item.version, item.checksum) for item in packages)) != len(packages):
        _refuse()
    if (not rust_license_gate._identity_valid(identity) or not hmac.compare_digest(
            hashlib.sha256(lock_bytes).hexdigest(), identity.lock_sha256)):
        _refuse()
    return packages


def _read_response(response, requested_url):
    try:
        if response.geturl() != requested_url:
            _refuse()
        status = response.status if hasattr(response, "status") else response.getcode()
        if status != 200:
            _refuse()
        declared = response.headers.get("Content-Length")
        if declared is not None and (not declared.isdecimal() or int(declared) > MAX_ARCHIVE_BYTES):
            _refuse()
        chunks = []
        total = 0
        while True:
            block = response.read(min(65536, MAX_ARCHIVE_BYTES + 1 - total))
            if not block:
                break
            total += len(block)
            if total > MAX_ARCHIVE_BYTES:
                _refuse()
            chunks.append(block)
        payload = b"".join(chunks)
        if not payload or (declared is not None and int(declared) != len(payload)):
            _refuse()
        return payload
    finally:
        try:
            response.close()
        except BaseException:
            pass


def _license_and_notices(payload, package):
    expected_root = package.name + "-" + package.version
    try:
        stream = gzip.GzipFile(fileobj=io.BytesIO(payload), mode="rb")
        chunks = []
        total_tar_bytes = 0
        while True:
            block = stream.read(min(65536, MAX_TAR_BYTES + 1 - total_tar_bytes))
            if not block:
                break
            total_tar_bytes += len(block)
            if total_tar_bytes > MAX_TAR_BYTES:
                _refuse()
            chunks.append(block)
        tar_bytes = b"".join(chunks)
        stream.close()
        archive = tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:")
    except (OSError, EOFError, tarfile.TarError):
        _refuse()
    files = {}
    total = 0
    try:
        members = archive.getmembers()
        if not members or len(members) > MAX_ARCHIVE_FILES:
            _refuse()
        for member in members:
            name = member.name
            normalized_name = name[:-1] if member.isdir() and name.endswith("/") else name
            if (type(name) is not str or "\\" in name or name.startswith("/")
                    or any(part in ("", ".", "..") for part in normalized_name.split("/"))
                    or normalized_name.split("/", 1)[0] != expected_root):
                _refuse()
            if member.isdir():
                continue
            if not member.isfile() or member.issym() or member.islnk() or member.size < 0:
                _refuse()
            relative = (normalized_name[len(expected_root) + 1:]
                        if normalized_name.startswith(expected_root + "/") else "")
            if not relative or relative in files:
                _refuse()
            total += member.size
            if total > MAX_PACKAGE_BYTES:
                _refuse()
            extracted = archive.extractfile(member)
            if extracted is None:
                _refuse()
            data = extracted.read(member.size + 1)
            if len(data) != member.size:
                _refuse()
            files[relative] = data
    finally:
        archive.close()
    cargo_toml = files.get("Cargo.toml")
    if cargo_toml is None or not 0 < len(cargo_toml) <= MAX_CARGO_TOML_BYTES:
        _refuse()
    try:
        manifest = cargo_toml.decode("utf-8", "strict")
    except UnicodeDecodeError:
        _refuse()
    section = None
    licenses = []
    license_file_declared = False
    for line in manifest.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1]
            continue
        if section != "package":
            continue
        match = LICENSE_LINE_RE.fullmatch(line)
        if match is not None:
            licenses.append(match.group(1))
        if re.match(r"^\s*license-file\s*=", line):
            license_file_declared = True
    if len(licenses) != 1 or license_file_declared:
        _refuse()
    notice_files = []
    notice_bytes = 0
    for path, data in sorted(files.items()):
        if LICENSE_PATH_RE.search(path) is None:
            continue
        notice_bytes += len(data)
        if not data or notice_bytes > MAX_NOTICE_BYTES:
            _refuse()
        notice_files.append((path, hashlib.sha256(data).hexdigest()))
    if not notice_files:
        _refuse()
    return licenses[0], tuple(notice_files)


def _canonical_digest(identity, evidence_rows):
    record = {
        "schema_version": 1,
        "source_sha": identity.source_sha,
        "profile": identity.profile,
        "lock_sha256": identity.lock_sha256,
        "registry": REGISTRY_SOURCE,
        "archive_origin": ARCHIVE_ORIGIN,
        "packages": evidence_rows,
    }
    try:
        payload = json.dumps(
            record, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
        ).encode("ascii", "strict")
    except (TypeError, ValueError, UnicodeError):
        _refuse()
    return hashlib.sha256(payload).hexdigest()


class TrustedArchivePort:
    """No-proxy, no-redirect crates.io archive verifier for a returned lock."""

    def __init__(self, opener=None):
        self._opener = opener or urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirectHandler(),
        )

    def verify_complete(self, lock_bytes, identity, lock_packages, archive_consumer=None):
        try:
            expected = _registry_packages(lock_bytes, identity)
            supplied = tuple(lock_packages)
            if supplied != expected:
                _refuse()
            archive_packages = []
            evidence_rows = []
            for package in expected:
                url = _archive_url(package)
                request = urllib.request.Request(
                    url, headers={
                        "Accept": "application/octet-stream",
                        "User-Agent": "keeldock" + "-" + "cargo-admission/1",
                    },
                    method="GET",
                )
                try:
                    response = self._opener.open(request, timeout=PROCESS_TIMEOUT_SECONDS)
                except (OSError, urllib.error.URLError, ValueError):
                    _refuse()
                payload = _read_response(response, url)
                archive_sha256 = hashlib.sha256(payload).hexdigest()
                if not hmac.compare_digest(archive_sha256, package.checksum):
                    _refuse()
                spdx, notices = _license_and_notices(payload, package)
                if archive_consumer is not None:
                    if not callable(archive_consumer):
                        _refuse()
                    try:
                        archive_consumer(package, payload)
                    except (cargo_lock_receipt.Refusal, OSError, TypeError, ValueError):
                        _refuse()
                archive_packages.append(rust_license_gate.ArchivePackage(
                    package, archive_sha256, spdx, spdx, True, notices,
                ))
                evidence_rows.append({
                    "name": package.name,
                    "version": package.version,
                    "registry": REGISTRY_SOURCE,
                    "archive_url": url,
                    "checksum": package.checksum,
                    "archive_sha256": archive_sha256,
                    "spdx": spdx,
                    "notices": [{"path": path, "sha256": digest} for path, digest in notices],
                })
            return rust_license_gate._validated_archives(
                identity, tuple(archive_packages), _canonical_digest(identity, evidence_rows),
            )
        except ArchiveProducerRefusal:
            raise rust_license_gate.LicenseGateRefusal("archive") from None
