"""Fail-closed Rust licence gate for trusted source-admission control."""

from dataclasses import dataclass
import hashlib
import hmac
import os
import re
import time


UNSET = "UNSET"
TRUSTED_PORTS = None
MAX_LOCK_BYTES = 4 * 1024 * 1024
MAX_PACKAGES = 20000
MAX_OUTPUT_BYTES = 4096
MAX_CHECKER_INPUT_BYTES = 12_000_000
MAX_SPDX_BYTES = 1_048_576
MAX_NOTICE_FILES_PER_PACKAGE = 64
MAX_NOTICE_FILES_TOTAL = 20_000
MAX_NOTICE_PATH_BYTES = 512
MAX_IDENTITY_FILE_BYTES = 268_435_456
PROCESS_TIMEOUT_SECONDS = 120
MAX_ADVISORY_AGE_SECONDS = 24 * 60 * 60
SOURCE_RE = re.compile(r"[a-f0-9]{40}\Z")
HEX_RE = re.compile(r"[a-f0-9]{64}\Z")
PACKAGE_RE = re.compile(r"[a-zA-Z0-9_-]{1,128}\Z")
VERSION_RE = re.compile(r"[A-Za-z0-9.+_-]{1,128}\Z")
_SEAL = object()


class LicenseGateRefusal(Exception):
    """A safe, reason-coded refusal; it contains no source-derived data."""

    def __init__(self, reason="invalid"):
        self.reason = reason if reason in {
            "unset", "identity", "lock", "coverage", "archive", "checker",
            "cargo_deny", "timeout", "cancelled", "process", "substitution",
            "archive_producer_unavailable", "archive_context_unavailable",
            "cargo_deny_unqualified", "cargo_deny_cli_unqualified",
            "advisory_database_unavailable",
        } else "invalid"
        super().__init__(self.reason)


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    checksum: str


@dataclass(frozen=True)
class Identity:
    source_sha: str
    profile: str
    root: str
    lock_sha256: str


@dataclass(frozen=True)
class ValidatedLock:
    identity: Identity
    packages: tuple
    seal: object


@dataclass(frozen=True)
class ArchivePackage:
    package: Package
    archive_sha256: str
    spdx: str
    receipt_spdx: str
    notices_complete: bool
    notice_files: tuple


@dataclass(frozen=True)
class VerifiedArchives:
    """Sealed trusted-adapter output over an authenticated archive-SPDX profile."""

    identity: Identity
    packages: tuple
    archive_spdx_sha256: str
    seal: object


@dataclass(frozen=True)
class GateConfig:
    """Immutable output of the trusted source-free configuration authority."""

    identity: Identity
    checker_source_sha: str
    checker_path: str
    checker_sha256: str
    cargo_deny_path: str
    cargo_deny_home: str
    cargo_deny_sha256: str
    cargo_deny_qualification_sha256: str
    policy_path: str
    policy_sha256: str
    cargo_deny_provenance_qualified: bool
    cargo_deny_cli_qualified: bool
    cargo_deny_cli_argv_sha256: str
    r108_qualified: bool
    advisory_database_fresh: bool
    advisory_database_commit: str
    advisory_database_generated_at_epoch: int
    cargo_deny_issue_910_safe: bool
    cargo_deny_affected_patched_controls_qualified: bool
    seal: object


@dataclass(frozen=True)
class TrustedPorts:
    """Trusted source-free adapters; no production set is configured."""

    lock: object
    config: object
    archives: object
    process: object
    cancellation: object
    seal: object


@dataclass(frozen=True)
class ProcessRequest:
    executable: str
    checker_source_sha: str
    argv: tuple
    cwd: str
    stdin: bytes
    environment: tuple
    timeout_seconds: int
    output_limit: int
    cancellation: object
    executable_sha256: str
    policy_sha256: str
    cargo_deny_qualification_sha256: str
    advisory_database_commit: str
    identity: Identity
    archive_spdx_sha256: str

    @property
    def request_sha256(self):
        return _request_binding_sha256(self)


@dataclass(frozen=True)
class ProcessResult:
    exit_code: int
    timed_out: bool
    cancelled: bool
    stdout: bytes
    stderr: bytes
    request_sha256: str
    executable_sha256: str
    seal: object


@dataclass(frozen=True)
class GateReceipt:
    identity: Identity
    archive_spdx_sha256: str
    package_count: int
    checker_source_sha: str
    checker_sha256: str
    policy_sha256: str
    cargo_deny_sha256: str
    cargo_deny_qualification_sha256: str
    advisory_database_commit: str
    seal: object


def _refuse(reason):
    raise LicenseGateRefusal(reason)


def _valid_hash(value):
    return type(value) is str and HEX_RE.fullmatch(value) is not None


def _cargo_deny_argv(identity, policy_path):
    return (
        "--manifest-path", os.path.join(identity.root, "Cargo.toml"),
        "--config", policy_path, "--workspace", "--all-features", "--locked",
        "--offline", "check", "advisories", "bans", "licenses", "sources",
    )


def _cargo_deny_argv_sha256(identity, policy_path):
    argv = _cargo_deny_argv(identity, policy_path)
    digest = hashlib.sha256()
    digest.update(len(argv).to_bytes(8, "big"))
    for argument in argv:
        try:
            value = argument.encode("utf-8", "strict")
        except UnicodeEncodeError:
            _refuse("cargo_deny_cli_unqualified")
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def _identity_shape_valid(identity):
    return (
        type(identity) is Identity
        and SOURCE_RE.fullmatch(identity.source_sha or "") is not None
        and type(identity.profile) is str and 1 <= len(identity.profile) <= 64
        and type(identity.root) is str and os.path.isabs(identity.root)
        and os.path.normpath(identity.root) != os.path.sep
        and len(identity.root) <= 512
        and _valid_hash(identity.lock_sha256)
    )


def _identity_valid(identity):
    return (
        _identity_shape_valid(identity) and identity.profile != UNSET
    )


def _require_outside_source(path, source_root):
    try:
        source_real = os.path.realpath(source_root)
        path_real = os.path.realpath(path)
        common = os.path.commonpath((source_real, path_real))
    except (OSError, ValueError):
        _refuse("identity")
    if common == source_real or common == path_real:
        _refuse("identity")


def _package_valid(package):
    return (
        type(package) is Package
        and PACKAGE_RE.fullmatch(package.name or "") is not None
        and VERSION_RE.fullmatch(package.version or "") is not None
        and _valid_hash(package.checksum)
    )


def _canonical_packages(packages):
    if type(packages) is not tuple or not packages or len(packages) > MAX_PACKAGES:
        _refuse("coverage")
    keys = []
    for package in packages:
        if not _package_valid(package):
            _refuse("coverage")
        keys.append((package.name, package.version, package.checksum))
    if keys != sorted(keys) or len(set(keys)) != len(keys):
        _refuse("coverage")
    return keys


def _validated_archives(identity, packages, archive_spdx_sha256):
    """Private constructor used only by the trusted archive verifier port."""
    return VerifiedArchives(identity, packages, archive_spdx_sha256, _SEAL)


def _validated_lock(identity, packages):
    """Private constructor for a lock parser that verifies registry/checksum coverage."""
    return ValidatedLock(identity, packages, _SEAL)


def _validated_config(config):
    """Private constructor for the immutable trusted-control configuration port."""
    if type(config) is not GateConfig:
        _refuse("identity")
    return GateConfig(
        config.identity, config.checker_source_sha, config.checker_path,
        config.checker_sha256, config.cargo_deny_path, config.cargo_deny_home,
        config.cargo_deny_sha256,
        config.cargo_deny_qualification_sha256,
        config.policy_path, config.policy_sha256,
        config.cargo_deny_provenance_qualified, config.cargo_deny_cli_qualified,
        config.cargo_deny_cli_argv_sha256,
        config.r108_qualified, config.advisory_database_fresh,
        config.advisory_database_commit, config.advisory_database_generated_at_epoch,
        config.cargo_deny_issue_910_safe,
        config.cargo_deny_affected_patched_controls_qualified, _SEAL,
    )


def _validated_ports(ports):
    """Private constructor for ports supplied only by trusted source-free control."""
    if type(ports) is not TrustedPorts:
        _refuse("unset")
    return TrustedPorts(
        ports.lock, ports.config, ports.archives, ports.process,
        ports.cancellation, _SEAL,
    )


def _process_result(request, outcome, executable_sha256=None):
    """Private constructor for a request-bound controlled-process result."""
    if type(outcome) is not tuple or len(outcome) != 5:
        _refuse("process")
    executed = request.executable_sha256 if executable_sha256 is None else executable_sha256
    return ProcessResult(
        *outcome, request.request_sha256, executed, _SEAL,
    )


def _validate_lock(identity, evidence):
    if (type(evidence) is not ValidatedLock or evidence.seal is not _SEAL
            or evidence.identity != identity):
        _refuse("lock")
    _canonical_packages(evidence.packages)
    return evidence


def _validate_archives(identity, lock_packages, evidence):
    if evidence is None:
        _refuse("archive_producer_unavailable")
    if (type(evidence) is not VerifiedArchives or evidence.seal is not _SEAL
            or evidence.identity != identity or not _valid_hash(evidence.archive_spdx_sha256)
            or type(evidence.packages) is not tuple or len(evidence.packages) > MAX_PACKAGES):
        _refuse("archive")
    expected = _canonical_packages(lock_packages)
    observed = []
    expression_bytes = 0
    notice_file_count = 0
    for item in evidence.packages:
        if (type(item) is not ArchivePackage or not _package_valid(item.package)
                or not _valid_hash(item.archive_sha256)
                or type(item.spdx) is not str or not item.spdx or len(item.spdx) > 16384
                or type(item.receipt_spdx) is not str or item.receipt_spdx != item.spdx
                or item.notices_complete is not True
                or type(item.notice_files) is not tuple
                or len(item.notice_files) > MAX_NOTICE_FILES_PER_PACKAGE):
            _refuse("archive")
        try:
            expression_bytes += len(item.spdx.encode("ascii"))
        except UnicodeEncodeError:
            _refuse("archive")
        if expression_bytes > MAX_SPDX_BYTES:
            _refuse("archive")
        if not hmac.compare_digest(item.archive_sha256, item.package.checksum):
            _refuse("archive")
        notice_names = []
        notice_file_count += len(item.notice_files)
        if notice_file_count > MAX_NOTICE_FILES_TOTAL:
            _refuse("archive")
        for row in item.notice_files:
            if type(row) is not tuple or len(row) != 2 or type(row[0]) is not str:
                _refuse("archive")
            try:
                path_bytes = row[0].encode("utf-8", "strict")
            except UnicodeEncodeError:
                _refuse("archive")
            if (not row[0] or len(path_bytes) > MAX_NOTICE_PATH_BYTES
                    or row[0].startswith("/") or ".." in row[0].split("/")
                    or not _valid_hash(row[1])):
                _refuse("archive")
            notice_names.append(row[0])
        if notice_names != sorted(notice_names) or len(set(notice_names)) != len(notice_names):
            _refuse("archive")
        observed.append((item.package.name, item.package.version, item.package.checksum))
    if observed != expected:
        _refuse("coverage")
    return evidence


def _validate_config(config, identity):
    if (type(config) is not GateConfig or config.seal is not _SEAL
            or config.identity != identity):
        _refuse("identity")
    required = (
        config.checker_source_sha, config.checker_path, config.checker_sha256,
        config.cargo_deny_path, config.cargo_deny_home, config.cargo_deny_sha256,
        config.cargo_deny_qualification_sha256,
        config.policy_path, config.policy_sha256, config.advisory_database_commit,
        config.cargo_deny_cli_argv_sha256,
    )
    if any(type(value) is not str or not value or value == UNSET for value in required):
        _refuse("unset")
    if (SOURCE_RE.fullmatch(config.checker_source_sha) is None
            or not _valid_hash(config.checker_sha256)
            or not _valid_hash(config.cargo_deny_sha256)
            or not _valid_hash(config.cargo_deny_qualification_sha256)
            or not _valid_hash(config.policy_sha256)
            or not _valid_hash(config.cargo_deny_cli_argv_sha256)
            or SOURCE_RE.fullmatch(config.advisory_database_commit) is None):
        _refuse("identity")
    if config.cargo_deny_cli_qualified is not True:
        _refuse("cargo_deny_cli_unqualified")
    if (config.cargo_deny_provenance_qualified is not True
            or config.r108_qualified is not True):
        _refuse("cargo_deny_unqualified")
    if config.advisory_database_fresh is not True:
        _refuse("advisory_database_unavailable")
    if (type(config.advisory_database_generated_at_epoch) is not int
            or config.advisory_database_generated_at_epoch <= 0):
        _refuse("advisory_database_unavailable")
    database_age = int(time.time()) - config.advisory_database_generated_at_epoch
    if database_age < 0 or database_age > MAX_ADVISORY_AGE_SECONDS:
        _refuse("advisory_database_unavailable")
    if (config.cargo_deny_issue_910_safe is not True
            or config.cargo_deny_affected_patched_controls_qualified is not True):
        _refuse("cargo_deny_unqualified")
    if any(not os.path.isabs(path) for path in (
            config.checker_path, config.cargo_deny_path, config.cargo_deny_home,
            config.policy_path)):
        _refuse("identity")
    for path in (config.checker_path, config.cargo_deny_path, config.cargo_deny_home,
                 config.policy_path):
        _require_outside_source(path, identity.root)
    expected_argv_sha256 = _cargo_deny_argv_sha256(identity, config.policy_path)
    if not hmac.compare_digest(config.cargo_deny_cli_argv_sha256, expected_argv_sha256):
        _refuse("cargo_deny_cli_unqualified")
    return config


def _digest_file(path):
    digest = hashlib.sha256()
    total = 0
    try:
        with open(path, "rb") as stream:
            while True:
                block = stream.read(65536)
                if not block:
                    break
                total += len(block)
                if total > MAX_IDENTITY_FILE_BYTES:
                    _refuse("identity")
                digest.update(block)
    except OSError:
        _refuse("identity")
    return digest.hexdigest()


def _verify_binary(path, expected):
    actual = _digest_file(path)
    if not hmac.compare_digest(actual, expected):
        _refuse("substitution")


def _checker_input(packages):
    lines = ["KDL-LICENSE-SCOPE\t1\t" + str(len(packages))]
    for item in packages:
        package = item.package
        lines.append("lock\t" + package.name + "\t" + package.version + "\t" + package.checksum)
    for item in packages:
        package = item.package
        lines.append("receipt\t" + package.name + "\t" + package.version + "\t"
                     + package.checksum + "\t" + item.spdx)
    try:
        payload = ("\n".join(lines) + "\n").encode("ascii")
    except UnicodeEncodeError:
        _refuse("archive")
    if len(payload) > MAX_CHECKER_INPUT_BYTES:
        _refuse("coverage")
    return payload


def _request_binding_sha256(request):
    """Bind immutable process inputs for the trusted supervisor receipt."""
    if type(request.environment) is not tuple:
        _refuse("process")
    parts = [request.executable, request.checker_source_sha, str(len(request.argv))]
    parts.extend(request.argv)
    parts.extend((request.cwd, request.stdin, str(len(request.environment))))
    for row in request.environment:
        if type(row) is not tuple or len(row) != 2:
            _refuse("process")
        parts.extend(row)
    parts.extend((
        str(request.timeout_seconds), str(request.output_limit),
        request.executable_sha256, request.policy_sha256,
        request.cargo_deny_qualification_sha256,
        request.advisory_database_commit, request.identity.source_sha,
        request.identity.profile, request.identity.root, request.identity.lock_sha256,
        request.archive_spdx_sha256,
    ))
    digest = hashlib.sha256()
    for part in parts:
        if type(part) is str:
            try:
                value = part.encode("utf-8", "strict")
            except UnicodeEncodeError:
                _refuse("process")
        elif type(part) is bytes:
            value = part
        else:
            _refuse("process")
        digest.update(len(value).to_bytes(8, "big"))
        digest.update(value)
    return digest.hexdigest()


def _run_process(port, request, reason):
    result = None
    request_sha256 = request.request_sha256
    try:
        result = port.run(request)
        if (type(result) is not ProcessResult or result.seal is not _SEAL
                or result.request_sha256 != request_sha256
                or result.executable_sha256 != request.executable_sha256):
            _refuse("process")
        if (type(result.exit_code) is not int or type(result.timed_out) is not bool
                or type(result.cancelled) is not bool):
            _refuse("process")
        if result.cancelled:
            _refuse("cancelled")
        if result.timed_out:
            _refuse("timeout")
        if (type(result.stdout) is not bytes or type(result.stderr) is not bytes
                or len(result.stdout) > request.output_limit
                or len(result.stderr) > request.output_limit):
            _refuse("process")
        if result.exit_code != 0:
            _refuse(reason)
        return result.stdout
    except LicenseGateRefusal:
        raise
    except BaseException:
        _refuse("process")
    finally:
        try:
            port.cleanup(request, result)
        except BaseException:
            _refuse("process")


def _request(fields):
    return ProcessRequest(*fields)


def _run_license_checker(process_port, config, identity, evidence, cancellation):
    environment = (("HOME", "/dev/null"), ("LANG", "C"), ("LC_ALL", "C"))
    request = _request((
        config.checker_path, config.checker_source_sha, ("--stdin-protocol",), identity.root,
        _checker_input(evidence.packages), environment, PROCESS_TIMEOUT_SECONDS,
        MAX_OUTPUT_BYTES, cancellation, config.checker_sha256,
        config.policy_sha256, config.cargo_deny_qualification_sha256, UNSET,
        identity, evidence.archive_spdx_sha256,
    ))
    return _run_process(process_port, request, "checker")


def _run_cargo_deny(process_port, config, identity, archive_spdx_sha256, cancellation):
    environment = (
        ("CARGO_HOME", config.cargo_deny_home), ("HOME", config.cargo_deny_home),
        ("LANG", "C"), ("LC_ALL", "C"),
    )
    argv = _cargo_deny_argv(identity, config.policy_path)
    request = _request((
        config.cargo_deny_path, config.checker_source_sha, argv, identity.root, b"", environment,
        PROCESS_TIMEOUT_SECONDS, MAX_OUTPUT_BYTES, cancellation,
        config.cargo_deny_sha256, config.policy_sha256,
        config.cargo_deny_qualification_sha256,
        config.advisory_database_commit, identity, archive_spdx_sha256,
    ))
    return _run_process(process_port, request, "cargo_deny")


def require_rust_license_gate(lock_bytes, identity, ports):
    """Run all three required controls; return a sealed result for vendor verification."""
    if type(ports) is not TrustedPorts or ports.seal is not _SEAL:
        _refuse("archive_producer_unavailable")
    lock_port = ports.lock
    config_port = ports.config
    archive_port = ports.archives
    process_port = ports.process
    cancellation_port = ports.cancellation
    if (type(lock_bytes) is not bytes or not lock_bytes or len(lock_bytes) > MAX_LOCK_BYTES
            or not _identity_valid(identity)
            or not hmac.compare_digest(
                hashlib.sha256(lock_bytes).hexdigest(), identity.lock_sha256,
            )):
        _refuse("lock")
    if cancellation_port.cancelled():
        _refuse("cancelled")
    lock_evidence = _validate_lock(identity, lock_port.validate(lock_bytes, identity))
    lock_packages = lock_evidence.packages
    lock_keys = _canonical_packages(lock_packages)
    if config_port is None:
        _refuse("archive_context_unavailable")
    if archive_port is None:
        _refuse("archive_producer_unavailable")
    try:
        config = _validate_config(config_port.for_identity(identity), identity)
    except LicenseGateRefusal:
        raise
    except BaseException:
        _refuse("archive_context_unavailable")
    if cancellation_port.cancelled():
        _refuse("cancelled")
    try:
        evidence = archive_port.verify_complete(lock_bytes, identity, lock_packages)
    except LicenseGateRefusal:
        raise
    except BaseException:
        _refuse("archive_context_unavailable")
    evidence = _validate_archives(identity, lock_packages, evidence)
    if cancellation_port.cancelled():
        _refuse("cancelled")
    _verify_binary(config.checker_path, config.checker_sha256)
    _verify_binary(config.cargo_deny_path, config.cargo_deny_sha256)
    _verify_binary(config.policy_path, config.policy_sha256)
    if cancellation_port.cancelled():
        _refuse("cancelled")
    checker_out = _run_license_checker(
        process_port, config, identity, evidence, cancellation_port,
    )
    if checker_out != b"result=conditional-pass authenticated=no\n":
        _refuse("checker")
    if cancellation_port.cancelled():
        _refuse("cancelled")
    _run_cargo_deny(
        process_port, config, identity, evidence.archive_spdx_sha256, cancellation_port,
    )
    if cancellation_port.cancelled():
        _refuse("cancelled")
    return GateReceipt(
        identity, evidence.archive_spdx_sha256, len(lock_keys),
        config.checker_source_sha, config.checker_sha256,
        config.policy_sha256, config.cargo_deny_sha256,
        config.cargo_deny_qualification_sha256, config.advisory_database_commit, _SEAL,
    )


def require_gate_receipt(receipt, identity, lock_packages):
    """Validate the in-memory supervisor receipt before vendor bytes are exposed."""
    if (type(receipt) is not GateReceipt or receipt.seal is not _SEAL
            or receipt.identity != identity or not _valid_hash(receipt.archive_spdx_sha256)
            or receipt.package_count != len(lock_packages)
            or receipt.package_count != len(_canonical_packages(lock_packages))
            or SOURCE_RE.fullmatch(receipt.checker_source_sha or "") is None
            or not _valid_hash(receipt.checker_sha256)
            or not _valid_hash(receipt.policy_sha256)
            or not _valid_hash(receipt.cargo_deny_sha256)
            or not _valid_hash(receipt.cargo_deny_qualification_sha256)
            or SOURCE_RE.fullmatch(receipt.advisory_database_commit or "") is None):
        _refuse("unset")
    return receipt


def require_vendor_gate_receipt(receipt, source_sha, profile, lock_sha256, packages):
    """Bind the supervisor receipt to the exact authenticated vendor lock context."""
    if (type(receipt) is not GateReceipt or receipt.seal is not _SEAL
            or not _identity_valid(receipt.identity)
            or receipt.identity.source_sha != source_sha
            or receipt.identity.profile != profile
            or receipt.identity.lock_sha256 != lock_sha256
            or receipt.package_count != len(_canonical_packages(packages))
            or not _valid_hash(receipt.archive_spdx_sha256)
            or SOURCE_RE.fullmatch(receipt.checker_source_sha or "") is None
            or not _valid_hash(receipt.checker_sha256)
            or not _valid_hash(receipt.policy_sha256)
            or not _valid_hash(receipt.cargo_deny_sha256)
            or not _valid_hash(receipt.cargo_deny_qualification_sha256)
            or SOURCE_RE.fullmatch(receipt.advisory_database_commit or "") is None):
        _refuse("unset")
    return receipt


def require_configured_control(lock_bytes, identity, ports=None):
    """CLI integration guard; ports come from trusted control code, never candidate JSON."""
    if ports is None:
        if (type(lock_bytes) is not bytes or not _identity_shape_valid(identity)
                or len(lock_bytes) > MAX_LOCK_BYTES
                or hashlib.sha256(lock_bytes).hexdigest() != identity.lock_sha256):
            _refuse("lock")
        if identity.profile == UNSET:
            _refuse("archive_context_unavailable")
        _refuse("archive_producer_unavailable")
    if type(ports) is not TrustedPorts or ports.seal is not _SEAL:
        _refuse("archive_producer_unavailable")
    return require_rust_license_gate(
        lock_bytes, identity, ports,
    )
