"""Bounded Cargo lock bootstrap: forced settings, proposed receipt, evidence and return bundle.

Every check that needs no network runs before the first registry request. The
bundle limits here are the Cargo lock profile's own limits and never reuse the
Node lock channel size.
"""

import base64
import calendar
import datetime
import hashlib
import hmac
import http.client
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request

try:
    import cargo_lock_receipt as cargo
except ImportError:
    _receipt_path = Path(__file__).resolve(strict=True).parent / "cargo_lock_receipt.py"
    _receipt_spec = importlib.util.spec_from_file_location("cargo_lock_receipt", str(_receipt_path))
    if _receipt_spec is None or _receipt_spec.loader is None:
        raise ImportError("cargo lock receipt unavailable")
    cargo = importlib.util.module_from_spec(_receipt_spec)
    sys.modules["cargo_lock_receipt"] = cargo
    try:
        _receipt_spec.loader.exec_module(cargo)
    except BaseException:
        sys.modules.pop("cargo_lock_receipt", None)
        raise ImportError("cargo lock receipt unavailable") from None


SCHEMA_VERSION = 1
MAX_BUNDLE_BYTES = 1024 * 1024
MAX_LOCK_BYTES = 256 * 1024
MAX_RECEIPT_BYTES = 128 * 1024
MAX_EVIDENCE_BYTES = 192 * 1024
MAX_PACKAGES = 512
MAX_INDEX_ENTRY_BYTES = 4 * 1024 * 1024
MAX_API_BYTES = 64 * 1024
MAX_TREE_ENTRIES = 20_000
MIN_PACKAGE_AGE_SECONDS = 7 * 24 * 60 * 60
CLOCK_SKEW_SECONDS = 300
MAX_REQUEST_TTL_SECONDS = 24 * 60 * 60
PENDING_AUDIT_ID = "pending-review"
DEPENDENCY_POLICY_REVISION = "bootstrap-pending"
BUILD_INPUT_ALLOWLIST = ()
INDEX_HOST = "index.crates.io"
API_HOST = "crates.io"
USER_AGENT = "platform-ci-cargo-lock-bootstrap"
FETCH_TIMEOUT_SECONDS = 30
HEX64_RE = re.compile(r"[a-f0-9]{64}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
SOURCE_LINE_RE = re.compile(r"\s*source\s*=\s*\"([^\"]*)\"\s*\Z")
DEPENDENCY_SOURCE_RE = re.compile(r"\(([A-Za-z][A-Za-z0-9+.-]*\+[^()\"]*)\)")
CREATED_AT_RE = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.[0-9]{1,9})?(?:Z|\+00:00)\Z"
)
CRATE_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\Z")
FORBIDDEN_ENVIRONMENT_PREFIXES = (
    "CARGO_", "RUSTC", "RUSTUP", "RUSTFLAGS", "RUSTDOC", "GIT_", "SSL_", "CURL_",
)
PROXY_ENVIRONMENT_NAMES = frozenset((
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "FTP_PROXY", "PROXY",
))
TARGET_RUNNER_TRIPLES = (
    "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
    "x86_64-pc-windows-msvc", "aarch64-pc-windows-msvc",
    "x86_64-apple-darwin", "aarch64-apple-darwin",
)
CONTEXT_FIELDS = frozenset(cargo.CONTEXT_FIELDS)
EVIDENCE_FIELDS = frozenset((
    "schema_version", "receipt_sha256", "lock_sha256", "run_id", "run_attempt",
    "generated_at", "expiry", "minimum_age_seconds", "index_origin", "api_origin",
    "build_inputs", "packages",
))
EVIDENCE_PACKAGE_FIELDS = frozenset((
    "name", "version", "checksum", "index_entry_sha256", "created_at",
))
BUNDLE_FIELDS = frozenset(("schema_version", "lock_b64", "receipt_b64", "evidence_b64"))
REASONS = frozenset((
    "bootstrap_input_invalid", "bootstrap_config_refused", "bootstrap_environment_refused",
    "bootstrap_lock_refused", "bootstrap_mismatch", "bootstrap_source_refused",
    "bootstrap_package_too_young", "bootstrap_package_yanked", "bootstrap_evidence_invalid",
    "bootstrap_network_refused", "bootstrap_payload_too_large", "bootstrap_build_input_refused",
    "bootstrap_stale",
))
CARGO_REASON_MAP = {
    "cargo_lock_invalid": "bootstrap_lock_refused",
    "cargo_receipt_invalid": "bootstrap_mismatch",
    "cargo_lock_mismatch": "bootstrap_mismatch",
}


class BootstrapRefusal(Exception):
    """A refusal with a fixed reason that never contains caller-provided data."""

    def __init__(self, reason="bootstrap_input_invalid"):
        if reason not in REASONS:
            reason = "bootstrap_input_invalid"
        self.reason = reason
        super().__init__(reason)


def _refuse(reason="bootstrap_input_invalid"):
    raise BootstrapRefusal(reason)


def _call_cargo(function, *arguments):
    try:
        return function(*arguments)
    except cargo.Refusal as error:
        raise BootstrapRefusal(CARGO_REASON_MAP.get(error.reason, "bootstrap_mismatch")) from None


def _valid_hex(value):
    return type(value) is str and HEX64_RE.fullmatch(value) is not None


def _canonical(record, reason):
    try:
        return json.dumps(
            record, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("ascii", "strict")
    except (TypeError, ValueError, UnicodeError):
        _refuse(reason)


def _strict_json(data, maximum, reason, encoding="ascii"):
    if type(data) is not bytes or not 0 < len(data) <= maximum:
        _refuse(reason)
    try:
        return json.loads(
            data.decode(encoding, "strict"), object_pairs_hook=cargo._unique_json_pairs,
            parse_constant=cargo._reject_json_constant,
        )
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _refuse(reason)


def forced_config_items():
    """Return the Cargo settings the bootstrap forces, as ordered key and value pairs."""
    items = [
        ("registry.global-credential-providers", "[]"),
        ("registry.credential-provider", json.dumps("cargo:token")),
        ("source.crates-io.replace-with", json.dumps("fixed-crates-io")),
        ("source.fixed-crates-io.registry", json.dumps(cargo.SPARSE_REGISTRY_SOURCE)),
        ("patch.crates-io", "{}"),
        ("net.offline", "false"),
        ("net.git-fetch-with-cli", "false"),
        ("net.retry", "2"),
        ("http.proxy", json.dumps("")),
        ("http.multiplexing", "false"),
        ("http.timeout", "30"),
        ("http.check-revoke", "true"),
    ]
    for triple in TARGET_RUNNER_TRIPLES:
        items.append(("target." + triple + ".runner", "[]"))
    return tuple(items)


def bootstrap_config_arguments():
    """Return the forced Cargo command line settings for lock generation."""
    arguments = []
    for key, value in forced_config_items():
        arguments.extend(("--config", key + "=" + value))
    return tuple(arguments)


def generate_lockfile_command(cargo_executable, manifest_path):
    """Return the one Cargo command that resolves a lock without building or running code."""
    for value in (cargo_executable, manifest_path):
        if (type(value) is not str or not value.startswith("/") or len(value) > 4096
                or "\x00" in value or "\n" in value or "\r" in value):
            _refuse("bootstrap_input_invalid")
    if not manifest_path.endswith("/Cargo.toml"):
        _refuse("bootstrap_input_invalid")
    return (cargo_executable,) + bootstrap_config_arguments() + (
        "generate-lockfile", "--manifest-path", manifest_path,
    )


def injected_environment_names(parent):
    """Name every inherited variable that would reach Cargo configuration or networking."""
    if type(parent) is not dict:
        _refuse("bootstrap_environment_refused")
    names = []
    for name in parent:
        if type(name) is not str:
            _refuse("bootstrap_environment_refused")
        upper = name.upper()
        if (upper.startswith(FORBIDDEN_ENVIRONMENT_PREFIXES)
                or upper in PROXY_ENVIRONMENT_NAMES or upper.endswith("_PROXY")):
            names.append(name)
    return tuple(sorted(names))


def _environment_text(value, absolute):
    if (type(value) is not str or not value or len(value) > 4096 or "\x00" in value
            or "\n" in value or "\r" in value or (absolute and not value.startswith("/"))):
        _refuse("bootstrap_environment_refused")
    return value


def build_cargo_environment(parent, *, cargo_home, home, tmpdir, path):
    """Build the whole Cargo environment from fixed values; nothing is inherited from parent."""
    injected_environment_names(parent)
    return {
        "PATH": _environment_text(path, False),
        "HOME": _environment_text(home, True),
        "CARGO_HOME": _environment_text(cargo_home, True),
        "TMPDIR": _environment_text(tmpdir, True),
        "LANG": "C",
        "LC_ALL": "C",
    }


def require_fresh_directory(path):
    """Require an existing empty directory that is not a link."""
    try:
        directory = Path(path)
        info = directory.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ValueError
        if os.listdir(directory):
            raise ValueError
    except (OSError, ValueError, TypeError):
        _refuse("bootstrap_environment_refused")
    return True


def refuse_cargo_config(source_root):
    """Refuse any Cargo configuration in the tree or in any parent directory."""
    try:
        root = Path(source_root)
        if not root.is_absolute() or not root.is_dir() or root.is_symlink():
            raise ValueError
    except (OSError, ValueError, TypeError):
        _refuse("bootstrap_config_refused")
    count = 0
    failed = []

    def on_error(error):
        failed.append(error)

    for current, directories, files in os.walk(root, followlinks=False, onerror=on_error):
        for name in directories + files:
            count += 1
            if count > MAX_TREE_ENTRIES:
                _refuse("bootstrap_config_refused")
            entry = Path(current) / name
            if name.lower().startswith(".cargo") or entry.is_symlink():
                _refuse("bootstrap_config_refused")
    if failed:
        _refuse("bootstrap_config_refused")
    for parent in root.parents:
        if os.path.lexists(parent / ".cargo"):
            _refuse("bootstrap_config_refused")
    return True


def validate_build_inputs(inputs, allowed=BUILD_INPUT_ALLOWLIST):
    """Accept only allowlisted build inputs; the allowlist is empty until one is admitted."""
    if type(inputs) is not dict or type(allowed) is not tuple or len(inputs) > len(allowed):
        _refuse("bootstrap_build_input_refused")
    for name, value in inputs.items():
        if (type(name) is not str or name not in allowed or type(value) is not str
                or not 0 < len(value) <= 256 or not value.isascii() or not value.isprintable()):
            _refuse("bootstrap_build_input_refused")
    return dict(inputs)


def refuse_foreign_sources(lock_bytes):
    """Refuse any lock source other than the fixed crates.io registry before parsing."""
    if type(lock_bytes) is not bytes or not lock_bytes:
        _refuse("bootstrap_lock_refused")
    if len(lock_bytes) > MAX_LOCK_BYTES:
        _refuse("bootstrap_payload_too_large")
    try:
        text = lock_bytes.decode("ascii", "strict")
    except UnicodeError:
        _refuse("bootstrap_lock_refused")
    allowed = (cargo.REGISTRY_SOURCE, cargo.SPARSE_REGISTRY_SOURCE)
    for line in text.splitlines():
        match = SOURCE_LINE_RE.match(line)
        if match is not None and match.group(1) not in allowed:
            _refuse("bootstrap_source_refused")
    for match in DEPENDENCY_SOURCE_RE.finditer(text):
        if match.group(1) not in allowed:
            _refuse("bootstrap_source_refused")
    return True


def parse_lock(lock_bytes):
    refuse_foreign_sources(lock_bytes)
    return _call_cargo(cargo.parse_cargo_lock, lock_bytes)


def _registry_packages(lock):
    packages = sorted(
        (package["name"], package["version"], package["checksum"])
        for package in lock["packages"] if package.get("source") == cargo.REGISTRY_SOURCE
    )
    if not packages or len(packages) > MAX_PACKAGES:
        _refuse("bootstrap_lock_refused")
    return packages


def _check_context(trusted_context):
    if type(trusted_context) is not dict or set(trusted_context) != set(CONTEXT_FIELDS):
        _refuse("bootstrap_input_invalid")
    return trusted_context


def build_receipt(lock_bytes, trusted_context):
    """Build the canonical proposed receipt; every audit record stays pending review."""
    _check_context(trusted_context)
    packages = _registry_packages(parse_lock(lock_bytes))
    record = {"schema_version": SCHEMA_VERSION}
    record.update({field: trusted_context[field] for field in sorted(CONTEXT_FIELDS)})
    record["lock_sha256"] = hashlib.sha256(lock_bytes).hexdigest()
    record["packages"] = [
        {"name": name, "version": version, "checksum": checksum, "audit_record_id": PENDING_AUDIT_ID}
        for name, version, checksum in packages
    ]
    encoded = _call_cargo(cargo.encode_receipt, record)
    if len(encoded) > MAX_RECEIPT_BYTES:
        _refuse("bootstrap_payload_too_large")
    return encoded


def self_check(lock_bytes, receipt_bytes, trusted_context):
    """Verify lock and receipt against trusted context before any network request."""
    _check_context(trusted_context)
    if type(receipt_bytes) is not bytes or not receipt_bytes:
        _refuse("bootstrap_mismatch")
    if len(receipt_bytes) > MAX_RECEIPT_BYTES:
        _refuse("bootstrap_payload_too_large")
    refuse_foreign_sources(lock_bytes)
    receipt = _call_cargo(cargo.decode_receipt, receipt_bytes)
    expected = dict(trusted_context)
    expected["receipt_sha256"] = hashlib.sha256(receipt_bytes).hexdigest()
    audits = {}
    for package in receipt["packages"]:
        if package["audit_record_id"] != PENDING_AUDIT_ID:
            _refuse("bootstrap_mismatch")
        audits[(package["name"], package["version"], package["checksum"])] = PENDING_AUDIT_ID
    _call_cargo(cargo.verify_lock_against_receipt, lock_bytes, receipt_bytes, expected, audits)
    return receipt


def index_path(name):
    """Return the sparse index path of a crate."""
    if type(name) is not str or CRATE_NAME_RE.fullmatch(name) is None:
        _refuse("bootstrap_input_invalid")
    lowered = name.lower()
    if len(lowered) == 1:
        return "/1/" + lowered
    if len(lowered) == 2:
        return "/2/" + lowered
    if len(lowered) == 3:
        return "/3/" + lowered[0] + "/" + lowered
    return "/" + lowered[:2] + "/" + lowered[2:4] + "/" + lowered


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class RegistryFetcher:
    """Fetch index entries and version metadata from the two fixed crates.io origins only."""

    def __init__(self, opener=None):
        self._opener = opener if opener is not None else urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect(),
        )

    def _get(self, host, path, limit, accept):
        url = "https:" + chr(47) * 2 + host + path
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or parsed.hostname != host or parsed.port is not None
                or parsed.query or parsed.fragment or parsed.username or parsed.password):
            _refuse("bootstrap_network_refused")
        request = urllib.request.Request(
            url, headers={"Accept": accept, "User-Agent": USER_AGENT}, method="GET",
        )
        try:
            with self._opener.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
                if response.status != 200 or response.geturl() != url:
                    raise ValueError
                data = response.read(limit + 1)
        except (OSError, ValueError, http.client.HTTPException, urllib.error.URLError):
            _refuse("bootstrap_network_refused")
        if type(data) is not bytes or not 0 < len(data) <= limit:
            _refuse("bootstrap_network_refused")
        return data

    def index_entry(self, name):
        return self._get(INDEX_HOST, index_path(name), MAX_INDEX_ENTRY_BYTES, "text/plain")

    def version_metadata(self, name, version):
        if not cargo._valid_package_identity(name, version):
            _refuse("bootstrap_input_invalid")
        return self._get(
            API_HOST, "/api/v1/crates/" + name + "/" + version, MAX_API_BYTES, "application/json",
        )


def _parse_created_at(value):
    match = CREATED_AT_RE.fullmatch(value) if type(value) is str else None
    if match is None:
        _refuse("bootstrap_evidence_invalid")
    fields = tuple(int(part) for part in match.groups())
    try:
        moment = datetime.datetime(*fields)
    except ValueError:
        _refuse("bootstrap_evidence_invalid")
    epoch = calendar.timegm(moment.utctimetuple())
    normalized = "%04d-%02d-%02dT%02d:%02d:%02dZ" % fields
    return epoch, normalized


def _check_index_entry(index_bytes, name, version, checksum):
    if type(index_bytes) is not bytes or not 0 < len(index_bytes) <= MAX_INDEX_ENTRY_BYTES:
        _refuse("bootstrap_evidence_invalid")
    try:
        text = index_bytes.decode("utf-8", "strict")
    except UnicodeError:
        _refuse("bootstrap_evidence_invalid")
    found = None
    for line in text.split("\n"):
        if not line:
            continue
        try:
            record = json.loads(
                line, object_pairs_hook=cargo._unique_json_pairs,
                parse_constant=cargo._reject_json_constant,
            )
        except (ValueError, TypeError, RecursionError):
            _refuse("bootstrap_evidence_invalid")
        if type(record) is not dict or type(record.get("name")) is not str:
            _refuse("bootstrap_evidence_invalid")
        if record["name"].lower() != name.lower():
            _refuse("bootstrap_evidence_invalid")
        if record.get("vers") == version:
            if found is not None:
                _refuse("bootstrap_evidence_invalid")
            found = record
    if found is None or type(found.get("yanked")) is not bool or found.get("cksum") != checksum:
        _refuse("bootstrap_evidence_invalid")
    if found["yanked"]:
        _refuse("bootstrap_package_yanked")


def _check_version_metadata(api_bytes, name, version, checksum, now):
    record = _strict_json(api_bytes, MAX_API_BYTES, "bootstrap_evidence_invalid", "utf-8")
    entry = record.get("version") if type(record) is dict else None
    if (type(entry) is not dict or entry.get("crate") != name or entry.get("num") != version
            or entry.get("checksum") != checksum or type(entry.get("yanked")) is not bool):
        _refuse("bootstrap_evidence_invalid")
    if entry["yanked"]:
        _refuse("bootstrap_package_yanked")
    epoch, normalized = _parse_created_at(entry.get("created_at"))
    if epoch > now + CLOCK_SKEW_SECONDS:
        _refuse("bootstrap_evidence_invalid")
    if now - epoch < MIN_PACKAGE_AGE_SECONDS:
        _refuse("bootstrap_package_too_young")
    return normalized


def _check_times(now, expiry):
    if (type(now) is not int or type(expiry) is not int or now < 1 or expiry <= now
            or expiry - now > MAX_REQUEST_TTL_SECONDS):
        _refuse("bootstrap_stale")


def _check_run(run_id, run_attempt):
    if (type(run_id) is not str or DECIMAL_RE.fullmatch(run_id) is None
            or type(run_attempt) is not int or run_attempt != 1):
        _refuse("bootstrap_input_invalid")


def build_evidence(lock_bytes, receipt_bytes, trusted_context, *, run_id, run_attempt, now,
                   expiry, build_inputs, fetcher):
    """Record index entry hashes and registry creation times for every receipt package."""
    receipt = self_check(lock_bytes, receipt_bytes, trusted_context)
    inputs = validate_build_inputs(build_inputs)
    _check_run(run_id, run_attempt)
    _check_times(now, expiry)
    if fetcher is None or not callable(getattr(fetcher, "index_entry", None)) \
            or not callable(getattr(fetcher, "version_metadata", None)):
        _refuse("bootstrap_input_invalid")
    index_entries = {}
    packages = []
    for package in receipt["packages"]:
        name, version, checksum = package["name"], package["version"], package["checksum"]
        if name not in index_entries:
            index_bytes = fetcher.index_entry(name)
            if type(index_bytes) is not bytes:
                _refuse("bootstrap_evidence_invalid")
            index_entries[name] = (hashlib.sha256(index_bytes).hexdigest(), index_bytes)
        index_digest, index_bytes = index_entries[name]
        _check_index_entry(index_bytes, name, version, checksum)
        created_at = _check_version_metadata(
            fetcher.version_metadata(name, version), name, version, checksum, now,
        )
        packages.append({
            "name": name, "version": version, "checksum": checksum,
            "index_entry_sha256": index_digest, "created_at": created_at,
        })
    record = {
        "schema_version": SCHEMA_VERSION,
        "receipt_sha256": hashlib.sha256(receipt_bytes).hexdigest(),
        "lock_sha256": hashlib.sha256(lock_bytes).hexdigest(),
        "run_id": run_id,
        "run_attempt": run_attempt,
        "generated_at": now,
        "expiry": expiry,
        "minimum_age_seconds": MIN_PACKAGE_AGE_SECONDS,
        "index_origin": INDEX_HOST,
        "api_origin": API_HOST,
        "build_inputs": inputs,
        "packages": packages,
    }
    encoded = _canonical(record, "bootstrap_evidence_invalid")
    if len(encoded) > MAX_EVIDENCE_BYTES:
        _refuse("bootstrap_payload_too_large")
    return encoded


def validate_evidence(evidence_bytes, receipt_bytes, lock_bytes, *, now):
    """Check the evidence against its receipt and lock, its age rule, and its expiry."""
    if type(evidence_bytes) is not bytes or len(evidence_bytes) > MAX_EVIDENCE_BYTES:
        _refuse("bootstrap_payload_too_large" if type(evidence_bytes) is bytes
                else "bootstrap_evidence_invalid")
    record = _strict_json(evidence_bytes, MAX_EVIDENCE_BYTES, "bootstrap_evidence_invalid")
    if _canonical(record, "bootstrap_evidence_invalid") != evidence_bytes:
        _refuse("bootstrap_evidence_invalid")
    if type(record) is not dict or set(record) != set(EVIDENCE_FIELDS):
        _refuse("bootstrap_evidence_invalid")
    if (type(record["schema_version"]) is not int or record["schema_version"] != SCHEMA_VERSION
            or not _valid_hex(record["receipt_sha256"]) or not _valid_hex(record["lock_sha256"])
            or not hmac.compare_digest(record["receipt_sha256"], hashlib.sha256(receipt_bytes).hexdigest())
            or not hmac.compare_digest(record["lock_sha256"], hashlib.sha256(lock_bytes).hexdigest())
            or record["index_origin"] != INDEX_HOST or record["api_origin"] != API_HOST
            or type(record["minimum_age_seconds"]) is not int
            or record["minimum_age_seconds"] != MIN_PACKAGE_AGE_SECONDS):
        _refuse("bootstrap_evidence_invalid")
    _check_run(record["run_id"], record["run_attempt"])
    generated_at = record["generated_at"]
    expiry = record["expiry"]
    _check_times(generated_at, expiry)
    if type(now) is not int or now >= expiry or now < generated_at - CLOCK_SKEW_SECONDS:
        _refuse("bootstrap_stale")
    validate_build_inputs(record["build_inputs"])
    receipt = _call_cargo(cargo.decode_receipt, receipt_bytes)
    packages = record["packages"]
    if type(packages) is not list or len(packages) != len(receipt["packages"]):
        _refuse("bootstrap_evidence_invalid")
    for item, expected in zip(packages, receipt["packages"]):
        if (type(item) is not dict or set(item) != set(EVIDENCE_PACKAGE_FIELDS)
                or item["name"] != expected["name"] or item["version"] != expected["version"]
                or item["checksum"] != expected["checksum"]
                or not _valid_hex(item["index_entry_sha256"])):
            _refuse("bootstrap_evidence_invalid")
        epoch, normalized = _parse_created_at(item["created_at"])
        if normalized != item["created_at"]:
            _refuse("bootstrap_evidence_invalid")
        if generated_at - epoch < MIN_PACKAGE_AGE_SECONDS:
            _refuse("bootstrap_package_too_young")
    return record


def encode_bundle(lock_bytes, receipt_bytes, evidence_bytes):
    """Encode the single return payload under the Cargo lock profile's own limits."""
    for data, maximum in (
        (lock_bytes, MAX_LOCK_BYTES), (receipt_bytes, MAX_RECEIPT_BYTES),
        (evidence_bytes, MAX_EVIDENCE_BYTES),
    ):
        if type(data) is not bytes or not data:
            _refuse("bootstrap_input_invalid")
        if len(data) > maximum:
            _refuse("bootstrap_payload_too_large")
    encoded = _canonical({
        "schema_version": SCHEMA_VERSION,
        "lock_b64": base64.b64encode(lock_bytes).decode("ascii"),
        "receipt_b64": base64.b64encode(receipt_bytes).decode("ascii"),
        "evidence_b64": base64.b64encode(evidence_bytes).decode("ascii"),
    }, "bootstrap_input_invalid")
    if len(encoded) > MAX_BUNDLE_BYTES:
        _refuse("bootstrap_payload_too_large")
    return encoded


def decode_bundle(bundle_bytes):
    """Decode only canonical bounded bundle bytes into lock, receipt and evidence bytes."""
    if type(bundle_bytes) is not bytes or not bundle_bytes:
        _refuse("bootstrap_input_invalid")
    if len(bundle_bytes) > MAX_BUNDLE_BYTES:
        _refuse("bootstrap_payload_too_large")
    record = _strict_json(bundle_bytes, MAX_BUNDLE_BYTES, "bootstrap_input_invalid")
    if (type(record) is not dict or set(record) != set(BUNDLE_FIELDS)
            or type(record["schema_version"]) is not int or record["schema_version"] != SCHEMA_VERSION):
        _refuse("bootstrap_input_invalid")
    members = []
    for name, maximum in (
        ("lock_b64", MAX_LOCK_BYTES), ("receipt_b64", MAX_RECEIPT_BYTES),
        ("evidence_b64", MAX_EVIDENCE_BYTES),
    ):
        text = record[name]
        if type(text) is not str or not text:
            _refuse("bootstrap_input_invalid")
        try:
            data = base64.b64decode(text.encode("ascii"), validate=True)
        except (ValueError, UnicodeError):
            _refuse("bootstrap_input_invalid")
        if base64.b64encode(data).decode("ascii") != text or not data:
            _refuse("bootstrap_input_invalid")
        if len(data) > maximum:
            _refuse("bootstrap_payload_too_large")
        members.append(data)
    if encode_bundle(*members) != bundle_bytes:
        _refuse("bootstrap_input_invalid")
    return tuple(members)


def verify_bundle(bundle_bytes, trusted_context, *, now):
    """Fully re-verify a bundle: lock, receipt, evidence ages and expiry."""
    lock_bytes, receipt_bytes, evidence_bytes = decode_bundle(bundle_bytes)
    self_check(lock_bytes, receipt_bytes, trusted_context)
    validate_evidence(evidence_bytes, receipt_bytes, lock_bytes, now=now)
    return lock_bytes, receipt_bytes, evidence_bytes


def produce_bundle(lock_bytes, trusted_context, *, run_id, run_attempt, now, expiry,
                   build_inputs, fetcher):
    """Build, self-check and encode the return payload for one generated lock."""
    receipt_bytes = build_receipt(lock_bytes, trusted_context)
    self_check(lock_bytes, receipt_bytes, trusted_context)
    evidence_bytes = build_evidence(
        lock_bytes, receipt_bytes, trusted_context, run_id=run_id, run_attempt=run_attempt,
        now=now, expiry=expiry, build_inputs=build_inputs, fetcher=fetcher,
    )
    bundle = encode_bundle(lock_bytes, receipt_bytes, evidence_bytes)
    verify_bundle(bundle, trusted_context, now=now)
    return bundle
