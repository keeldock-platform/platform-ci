"""Bounded npm admission proposal: input checks, resolution command, evidence and return bundle.

The proposal reads a small fixed set of inert files from an exact source revision: the Node
version file, the npm settings file, the root and workspace manifests and the filed request
table. It never reads or runs candidate code. Every check that needs no network runs before
the resolver starts. The resolver is the pinned npm with scripts disabled, a fixed registry
origin, empty user and global settings, strict peers and a cooling cutoff. Afterwards a fixed
origin fetcher with no proxy, no credentials and no redirects reads package metadata, every
archive and the bulk advisory answer. Each archive is verified against its lock integrity and
inspected with the shared archive checks; the licence, cooling age, peer ranges and advisory
ranges are checked independently of npm. The result is a lock plus a receipt and an evidence
record in one bundle. The bundle is an untrusted proposal: nothing here admits a package.

The bundle limits here are the npm admission profile's own limits and never reuse the
single-use Node lock channel size. Provenance attestations are only recorded as offered or
not offered; their statements and signatures are not verified in this job.

Operating notes. The full metadata document of each package name is read, because only the
full document carries per-version publish times; it is capped at MAX_PACKUMENT_BYTES, and a
larger document fails the run closed with the network reason. If a real package ever exceeds
the cap, raise the constant together with a test and keep reading the full document. The
wall clock is read once by the caller before the resolver starts; that single reading serves
the request expiry and the policy-time checks. The advisory fetch time is read separately,
after the advisory answer arrives, and it alone decides whether an advisory allow record is
still unexpired. Every advisory must carry a severity of info, low, moderate, high or critical;
a missing, non-string or unknown value refuses the run and is never defaulted. Recorded findings
are held to the same set when the evidence is verified.

An advisory allow record is honoured only when all of these hold: the advisory severity is
not high or critical; every locked entry of the named package that the advisory covers is a
development-only entry; the record lists exactly the root direct dependencies whose
dependency paths reach those entries; and its expiry lies after the policy epoch, no more
than MAX_ALLOW_TTL_MS after it, and after the advisory fetch time.
"""

import base64
import calendar
import datetime
import hashlib
import hmac
import http.client
import importlib
import importlib.util
import io
import json
import posixpath
import re
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path


def _load_sibling(name):
    loaded = sys.modules.get(name)
    if loaded is not None:
        return loaded
    try:
        return importlib.import_module(name)
    except ImportError:
        pass
    path = Path(__file__).resolve(strict=True).parent / (name + ".py")
    spec = importlib.util.spec_from_file_location(name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError("npm admission sibling unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise ImportError("npm admission sibling unavailable") from None
    return module


adm = _load_sibling("npm_admission")
semver = _load_sibling("npm_semver")


SCHEMA_VERSION = 1
NODE_VERSION = "24.22.1"
NPM_VERSION = "11.19.1"
MAX_BUNDLE_BYTES = 3 * 1024 * 1024 + 512 * 1024
MAX_LOCK_BYTES = 1536 * 1024
MAX_RECEIPT_BYTES = 256 * 1024
MAX_EVIDENCE_BYTES = 640 * 1024
MAX_PACKAGES = 1024
MAX_MANIFEST_BYTES = 256 * 1024
MAX_REQUEST_DOC_BYTES = 512 * 1024
MAX_REQUEST_ROWS = 1024
MAX_PACKUMENT_BYTES = 16 * 1024 * 1024
MAX_ADVISORY_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 256
MAX_REQUESTS = 2048
MAX_TOTAL_METADATA_BYTES = 192 * 1024 * 1024
MIN_PACKAGE_AGE_SECONDS = 7 * 24 * 60 * 60
ADVISORY_MAX_AGE_SECONDS = 24 * 60 * 60
CLOCK_SKEW_SECONDS = 300
MAX_REQUEST_TTL_SECONDS = 24 * 60 * 60
FETCH_TIMEOUT_SECONDS = 60
REGISTRY_HOST = "registry.npmjs.org"
REGISTRY_URL = "https:" + chr(47) * 2 + REGISTRY_HOST + chr(47)
ADVISORY_PATH = "/-/npm/v1/security/advisories/bulk"
ADVISORY_ENDPOINT = "npm-bulk-advisory-v1"
USER_AGENT = "platform-ci-npm-admission-bootstrap"
PENDING_AUDIT_ID = "pending-review"
DOMAIN_INPUTS = b"npm-admission-inputs-v1\n"
RECORD_TYPE = "npm-admission-proposal-receipt"
ROOT_NAME = "keeldock" + "-core"
SCOPE = "@" + "keeldock" + "/"
WORKSPACE_PATHS = ("packages/host-api", "packages/kernel-i18n")
DEFAULT_FILING = "contract-ui-batch-a"
FILINGS = {
    DEFAULT_FILING: {
        "request_doc": "docs/dependencies/ui-npm-admission-batch-a.md",
        "overrides": {"lightningcss": "1.33.0"},
    },
}
NODE_VERSION_BYTES = (NODE_VERSION + "\n").encode("ascii")
NPMRC_BYTES = b"engine-strict=true\nsave-exact=true\nignore-scripts=true\n"
LIFECYCLE_SCRIPTS = (
    "preinstall", "install", "postinstall", "prepublish", "preprepare", "prepare", "postprepare",
    "dependencies", "prepack", "postpack",
)
MAX_ALLOW_TTL_MS = 90 * 24 * 60 * 60 * 1000
ALLOW_REFUSED_SEVERITIES = frozenset(("high", "critical"))
LOCK_EDGE_GROUPS = ("dependencies", "optionalDependencies", "peerDependencies")
DEPENDENCY_GROUPS = ("dependencies", "devDependencies", "optionalDependencies")
ROOT_KEYS = frozenset((
    "name", "version", "private", "packageManager", "engines", "workspaces", "scripts",
    "devDependencies", "dependencies", "optionalDependencies", "overrides",
))
WORKSPACE_KEYS = frozenset((
    "name", "version", "type", "types", "exports", "scripts", "dependencies", "devDependencies",
))
REQUEST_REQUIRED_COLUMNS = (
    "Package", "Version", "Published (UTC)", "dist.integrity (SRI)", "Licence",
)
REQUEST_ATTESTED_COLUMNS = ("Attest", "Attestations")
REQUEST_SHASUM_COLUMN = "dist.shasum"
REQUEST_TARBALL_COLUMN = "Canonical tarball"
REQUEST_START = "<!-- REGISTRY-FACTS-START -->"
REQUEST_END = "<!-- REGISTRY-FACTS-END -->"
TIME_RE = re.compile(
    r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
    r"(?:\.[0-9]{1,9})?(?:Z|\+00:00)\Z"
)
HEX64_RE = re.compile(r"[a-f0-9]{64}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
CONDITIONAL_LICENCES = frozenset((
    "MPL-2.0", "OFL-1.1", "EPL-1.0", "EPL-2.0", "CDDL-1.0", "CDDL-1.1", "CC-BY-4.0",
))
BUILTIN_LICENCES = frozenset((
    "MIT", "Apache-2.0", "MPL-2.0", "OFL-1.1", "ISC", "BSD-2-Clause", "BSD-3-Clause", "MIT-0",
    "BlueOak-1.0.0", "CC0-1.0", "Unicode-3.0",
))
SCOPED_LICENCES = {"CC-BY-4.0": ("caniuse-lite",)}
IDENTIFIER_RE = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9._:-]{0,127}\Z")
LICENCE_ID_RE = re.compile(r"[A-Za-z0-9.+-]{1,128}\Z")
HEX40_RE = re.compile(r"[a-f0-9]{40}\Z")
SEPARATOR_CELL_RE = re.compile(r":?-{3,}:?\Z")
POLICY_FILE = "dependency-policy.json"
MAX_POLICY_BYTES = 1024 * 1024
MAX_INPUT_BYTES = 1024 * 1024
POLICY_FIELDS = frozenset((
    "schema_version", "policy_epoch_ms", "direct", "singleton_names", "internal_names",
    "licence_elections",
    "licence_allowlist", "development_advisory_allows",
))
ALLOW_FIELDS = frozenset((
    "name", "advisory_id", "consumers", "justification_sha256", "expires_at_ms",
    "removal_condition",
))
SEVERITIES = frozenset(("info", "low", "moderate", "high", "critical"))
ALLOWABLE_SEVERITIES = SEVERITIES - ALLOW_REFUSED_SEVERITIES
TRUSTED_CONTEXT_FIELDS = frozenset((
    "repository", "filing", "source_sha", "base_sha", "base_branch",
    "reviewed_diff_fingerprint", "control_sha",
))
RECEIPT_FIELDS = frozenset((
    "schema_version", "record_type", "context", "inputs_sha256", "request_doc_sha256",
    "lock_sha256", "archive_set_sha256", "package_set_sha256", "packages",
))
RECEIPT_PACKAGE_FIELDS = frozenset((
    "path", "name", "version", "integrity", "sha256", "audit_record_id",
))
EVIDENCE_FIELDS = frozenset((
    "schema_version", "receipt_sha256", "lock_sha256", "inputs_sha256", "run_id", "run_attempt",
    "generated_at", "expiry", "policy_epoch_ms", "cutoff_epoch_ms", "minimum_age_seconds",
    "registry_origin", "resolver", "attestation_verification", "totals", "advisory",
    "duplicates", "packages",
))
EVIDENCE_PACKAGE_FIELDS = frozenset((
    "path", "name", "version", "sha256", "published", "age_days", "licence", "licence_elected",
    "licence_flags",
    "install_scripts", "native_count", "native_sample", "attested", "publisher", "deprecated",
    "dev", "optional", "compressed_bytes", "unpacked_bytes", "file_count", "direct",
))
ADVISORY_FIELDS = frozenset((
    "endpoint", "fetched_at", "valid_until", "request_sha256", "response_sha256",
    "package_count", "finding_count", "status", "findings",
))
BUNDLE_FIELDS = frozenset(("schema_version", "lock_b64", "receipt_b64", "evidence_b64"))
REASONS = frozenset((
    "npm_input_invalid", "npm_environment_refused", "npm_manifest_refused", "npm_request_refused",
    "npm_request_mismatch", "npm_lock_refused", "npm_network_refused", "npm_integrity_mismatch",
    "npm_package_too_young", "npm_package_deprecated", "npm_licence_refused", "npm_peer_refused",
    "npm_archive_refused", "npm_advisory_blocked", "npm_advisory_invalid", "npm_evidence_invalid",
    "npm_stale", "npm_payload_too_large", "npm_policy_refused",
))
ADM_REASON_MAP = {
    "npm_lock_invalid": "npm_lock_refused",
    "npm_receipt_invalid": "npm_evidence_invalid",
    "npm_archive_invalid": "npm_archive_refused",
    "npm_material_invalid": "npm_manifest_refused",
    "npm_context_mismatch": "npm_input_invalid",
    "npm_config_invalid": "npm_environment_refused",
}


class BootstrapRefusal(Exception):
    """A refusal with a fixed reason that never contains caller-provided data."""

    def __init__(self, reason="npm_input_invalid"):
        if reason not in REASONS:
            reason = "npm_input_invalid"
        self.reason = reason
        super().__init__(reason)


def _refuse(reason="npm_input_invalid"):
    raise BootstrapRefusal(reason)


def _call_adm(function, *arguments, **keywords):
    try:
        return function(*arguments, **keywords)
    except adm.Refusal as error:
        raise BootstrapRefusal(ADM_REASON_MAP.get(error.reason, "npm_lock_refused")) from None


def _valid_hex(value):
    return type(value) is str and HEX64_RE.fullmatch(value) is not None


def _sha256(data):
    return hashlib.sha256(data).hexdigest()


def _canonical(record, reason):
    try:
        return json.dumps(
            record, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("ascii", "strict")
    except (TypeError, ValueError, UnicodeError):
        _refuse(reason)


def _reject_constant(value):
    raise ValueError("constant")


def _strict_json(data, maximum, reason):
    if type(data) is not bytes or not 0 < len(data) <= maximum:
        _refuse(reason)
    try:
        text = data.decode("utf-8", "strict")
        if text.startswith(chr(0xFEFF)):
            raise ValueError("bom")
        return json.loads(
            text, object_pairs_hook=adm._unique_json_pairs, parse_constant=_reject_constant,
        )
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _refuse(reason)


def _ascii_text(value, maximum):
    return (
        type(value) is str and 0 < len(value) <= maximum and value.isascii()
        and value.isprintable()
    )


def _parse_time(value):
    match = TIME_RE.fullmatch(value) if type(value) is str else None
    if match is None:
        _refuse("npm_evidence_invalid")
    fields = tuple(int(part) for part in match.groups())
    try:
        moment = datetime.datetime(*fields)
    except ValueError:
        _refuse("npm_evidence_invalid")
    return calendar.timegm(moment.utctimetuple())


def _exact_version(value):
    return adm._valid_version(value) and "+" not in value


def _valid_name(name, extra=()):
    return adm._valid_package_name(name) and not adm._internal_name(name, extra)


def _scoped_name(path):
    return SCOPE + posixpath.basename(path)


def workspace_links():
    """Return the fixed workspace link map the lock must carry."""
    return {"node_modules/" + _scoped_name(path): path for path in WORKSPACE_PATHS}


def filing_for(selector):
    if type(selector) is not str or selector not in FILINGS:
        _refuse("npm_input_invalid")
    return FILINGS[selector]


def input_paths(selector):
    """Return the exact repository paths read from the source revision, in a fixed order."""
    filing = filing_for(selector)
    return (
        ".node-version", ".npmrc", "package.json",
    ) + tuple(path + "/package.json" for path in WORKSPACE_PATHS) + (
        POLICY_FILE, filing["request_doc"],
    )


def _check_scripts(scripts):
    if type(scripts) is not dict or len(scripts) > 64:
        _refuse("npm_manifest_refused")
    for name, value in scripts.items():
        if (not _ascii_text(name, 64) or not _ascii_text(value, 512) or name in LIFECYCLE_SCRIPTS):
            _refuse("npm_manifest_refused")


def _check_dependencies(value, internal):
    if type(value) is not dict or len(value) > 512:
        _refuse("npm_manifest_refused")
    for name, spec in value.items():
        if not _valid_name(name, internal) or not _exact_version(spec):
            _refuse("npm_manifest_refused")
    return dict(value)


def _manifest(data):
    manifest = _strict_json(data, MAX_MANIFEST_BYTES, "npm_manifest_refused")
    if type(manifest) is not dict:
        _refuse("npm_manifest_refused")
    return manifest


def _check_root(manifest, filing, internal):
    if (set(manifest) - ROOT_KEYS or manifest.get("name") != ROOT_NAME
            or not adm._valid_version(manifest.get("version")) or manifest.get("private") is not True
            or manifest.get("packageManager") != "npm@" + NPM_VERSION
            or manifest.get("engines") != {"node": NODE_VERSION, "npm": NPM_VERSION}
            or manifest.get("workspaces") != ["packages/*"]):
        _refuse("npm_manifest_refused")
    _check_scripts(manifest.get("scripts", {}))
    groups = {group: _check_dependencies(manifest.get(group, {}), internal) for group in DEPENDENCY_GROUPS}
    overrides = manifest.get("overrides", {})
    if overrides != filing["overrides"]:
        _refuse("npm_manifest_refused")
    return groups, dict(overrides)


def _check_workspace(manifest, path, internal):
    if (set(manifest) - WORKSPACE_KEYS or manifest.get("name") != _scoped_name(path)
            or not adm._valid_version(manifest.get("version"))):
        _refuse("npm_manifest_refused")
    _check_scripts(manifest.get("scripts", {}))
    return {
        group: _check_dependencies(manifest.get(group, {}), internal)
        for group in ("dependencies", "devDependencies")
    }


def _split_row(line):
    if not line.startswith("| ") or not line.endswith(" |"):
        _refuse("npm_request_refused")
    return [cell.strip() for cell in line[2:-2].split(" | ")]


def parse_request_doc(data):
    """Parse the filed registry facts table into rows keyed by name and version.

    The table is read by header name, so added or reordered columns do not matter; the
    required columns must be present once each, and any optional column that is present is
    validated and later compared with the registry.
    """
    if type(data) is not bytes or not 0 < len(data) <= MAX_REQUEST_DOC_BYTES:
        _refuse("npm_request_refused")
    try:
        text = data.decode("utf-8", "strict")
    except UnicodeError:
        _refuse("npm_request_refused")
    if text.count(REQUEST_START) != 1 or text.count(REQUEST_END) != 1:
        _refuse("npm_request_refused")
    start = text.index(REQUEST_START) + len(REQUEST_START)
    end = text.index(REQUEST_END)
    if end < start:
        _refuse("npm_request_refused")
    lines = [line for line in text[start:end].split("\n") if line.strip()]
    if len(lines) < 3 or len(lines) - 2 > MAX_REQUEST_ROWS:
        _refuse("npm_request_refused")
    header = _split_row(lines[0])
    separator = _split_row(lines[1])
    if (len(set(header)) != len(header) or len(separator) != len(header)
            or any(SEPARATOR_CELL_RE.fullmatch(cell) is None for cell in separator)
            or any(column not in header for column in REQUEST_REQUIRED_COLUMNS)):
        _refuse("npm_request_refused")
    attested_columns = [column for column in REQUEST_ATTESTED_COLUMNS if column in header]
    if len(attested_columns) > 1:
        _refuse("npm_request_refused")
    index = {column: header.index(column) for column in header}
    rows = {}
    for line in lines[2:]:
        cells = _split_row(line)
        if len(cells) != len(header):
            _refuse("npm_request_refused")
        name = cells[index["Package"]]
        version = cells[index["Version"]]
        published = cells[index["Published (UTC)"]]
        integrity = cells[index["dist.integrity (SRI)"]]
        licence = cells[index["Licence"]]
        shasum = cells[index[REQUEST_SHASUM_COLUMN]] if REQUEST_SHASUM_COLUMN in index else None
        tarball = cells[index[REQUEST_TARBALL_COLUMN]] if REQUEST_TARBALL_COLUMN in index else None
        attested = cells[index[attested_columns[0]]] if attested_columns else None
        if (not _valid_name(name) or not _exact_version(version) or TIME_RE.fullmatch(published) is None
                or not adm._valid_integrity(integrity) or not _ascii_text(licence, 128)
                or (shasum is not None and HEX40_RE.fullmatch(shasum) is None)
                or (tarball is not None and tarball != adm._canonical_tarball_url(name, version))
                or (attested is not None and attested not in ("yes", "no"))
                or (name, version) in rows):
            _refuse("npm_request_refused")
        rows[(name, version)] = {
            "published": published, "integrity": integrity, "licence": licence,
            "shasum": shasum, "attested": None if attested is None else attested == "yes",
        }
    return rows


def _check_name_list(value, maximum):
    if type(value) is not list or len(value) > maximum or len(set(value)) != len(value):
        _refuse("npm_policy_refused")
    for name in value:
        if not adm._valid_package_name(name):
            _refuse("npm_policy_refused")
    return tuple(value)


def _allow_expiry_bounded(expires_at_ms, policy_epoch_ms):
    """An allow lives strictly after the policy epoch and at most MAX_ALLOW_TTL_MS beyond it."""
    return policy_epoch_ms < expires_at_ms <= policy_epoch_ms + MAX_ALLOW_TTL_MS


def _check_allow(record, policy_epoch_ms):
    if (type(record) is not dict or set(record) != set(ALLOW_FIELDS)
            or not adm._valid_package_name(record["name"])
            or type(record["advisory_id"]) is not str
            or IDENTIFIER_RE.fullmatch(record["advisory_id"]) is None
            or type(record["removal_condition"]) is not str
            or IDENTIFIER_RE.fullmatch(record["removal_condition"]) is None
            or not _valid_hex(record["justification_sha256"])
            or type(record["expires_at_ms"]) is not int or record["expires_at_ms"] < 1
            or not _allow_expiry_bounded(record["expires_at_ms"], policy_epoch_ms)):
        _refuse("npm_policy_refused")
    consumers = _check_name_list(record["consumers"], 128)
    if not consumers:
        _refuse("npm_policy_refused")
    return {
        "name": record["name"], "advisory_id": record["advisory_id"], "consumers": consumers,
        "justification_sha256": record["justification_sha256"],
        "expires_at_ms": record["expires_at_ms"], "removal_condition": record["removal_condition"],
    }


def parse_policy(data):
    """Read the dependency policy as inert data and refuse any extra, missing or malformed field."""
    policy = _strict_json(data, MAX_POLICY_BYTES, "npm_policy_refused")
    if type(policy) is not dict or set(policy) != set(POLICY_FIELDS):
        _refuse("npm_policy_refused")
    if (type(policy["schema_version"]) is not int or policy["schema_version"] != SCHEMA_VERSION
            or type(policy["policy_epoch_ms"]) is not int or policy["policy_epoch_ms"] < 1
            or policy["policy_epoch_ms"] > adm.MAX_SAFE_INTEGER):
        _refuse("npm_policy_refused")
    direct = policy["direct"]
    internal = _check_name_list(policy["internal_names"], 1024)
    if type(direct) is not dict or len(direct) > 512:
        _refuse("npm_policy_refused")
    for name, version in direct.items():
        if not _valid_name(name, internal) or not _exact_version(version):
            _refuse("npm_policy_refused")
    singletons = _check_name_list(policy["singleton_names"], 1024)
    licences = policy["licence_allowlist"]
    if (type(licences) is not list or not 0 < len(licences) <= 1024 or len(set(licences)) != len(licences)
            or any(type(item) is not str or LICENCE_ID_RE.fullmatch(item) is None for item in licences)):
        _refuse("npm_policy_refused")
    if not frozenset(licences) <= BUILTIN_LICENCES:
        _refuse("npm_policy_refused")
    elections = policy["licence_elections"]
    if type(elections) is not dict or len(elections) > 256:
        _refuse("npm_policy_refused")
    for name, elected in elections.items():
        if (not adm._valid_package_name(name) or type(elected) is not str
                or LICENCE_ID_RE.fullmatch(elected) is None
                or not licence_permitted(name, elected, frozenset(licences))):
            _refuse("npm_policy_refused")
    allows = policy["development_advisory_allows"]
    if type(allows) is not list or len(allows) > 256:
        _refuse("npm_policy_refused")
    return {
        "policy_epoch_ms": policy["policy_epoch_ms"],
        "direct": dict(direct),
        "singleton_names": frozenset(singletons),
        "internal_names": internal,
        "licence_allowlist": frozenset(licences),
        "licence_elections": dict(elections),
        "advisory_allows": [_check_allow(record, policy["policy_epoch_ms"]) for record in allows],
    }


def _inputs_digest(files, paths):
    digest = hashlib.sha256()
    digest.update(DOMAIN_INPUTS)
    for path in sorted(paths):
        digest.update(path.encode("ascii") + b"\x00" + _sha256(files[path]).encode("ascii") + b"\n")
    return digest.hexdigest()


def check_inputs(files, selector):
    """Check every input file before any command runs and return the immutable plan."""
    filing = filing_for(selector)
    paths = input_paths(selector)
    if type(files) is not dict or set(files) != set(paths):
        _refuse("npm_input_invalid")
    for path in paths:
        if type(files[path]) is not bytes or not files[path]:
            _refuse("npm_input_invalid")
    if files[".node-version"] != NODE_VERSION_BYTES or files[".npmrc"] != NPMRC_BYTES:
        _refuse("npm_manifest_refused")
    policy = parse_policy(files[POLICY_FILE])
    internal = policy["internal_names"]
    root_manifest = _manifest(files["package.json"])
    root_groups, overrides = _check_root(root_manifest, filing, internal)
    root_direct = {}
    for group in root_groups.values():
        for name, version in group.items():
            if root_direct.setdefault(name, version) != version:
                _refuse("npm_manifest_refused")
    if not root_direct or root_direct != policy["direct"]:
        _refuse("npm_policy_refused")
    direct = dict(root_direct)
    workspaces = []
    for path in WORKSPACE_PATHS:
        manifest = _manifest(files[path + "/package.json"])
        groups = _check_workspace(manifest, path, internal)
        workspaces.append({
            "path": path, "name": manifest["name"], "version": manifest["version"],
            "dependencies": groups["dependencies"], "devDependencies": groups["devDependencies"],
        })
        for group in groups.values():
            for name, version in group.items():
                if direct.setdefault(name, version) != version:
                    _refuse("npm_manifest_refused")
    rows = parse_request_doc(files[filing["request_doc"]])
    for name, version in sorted(direct.items()):
        if (name, version) not in rows:
            _refuse("npm_request_mismatch")
    for name, version in sorted(overrides.items()):
        if (name, version) not in rows:
            _refuse("npm_request_mismatch")
    epoch = policy["policy_epoch_ms"]
    return {
        "filing": selector,
        "root": {
            "name": root_manifest["name"], "version": root_manifest["version"],
            "dependencies": root_groups["dependencies"],
            "devDependencies": root_groups["devDependencies"],
            "optionalDependencies": root_groups["optionalDependencies"],
        },
        "workspaces": workspaces,
        "direct": direct,
        "overrides": overrides,
        "rows": rows,
        "policy_epoch_ms": epoch,
        "cutoff_epoch_ms": epoch - MIN_PACKAGE_AGE_SECONDS * 1000,
        "singletons": policy["singleton_names"],
        "internal_names": internal,
        "licence_allowlist": policy["licence_allowlist"],
        "licence_elections": policy["licence_elections"],
        "advisory_allows": policy["advisory_allows"],
        "inputs_sha256": _inputs_digest(files, paths),
        "request_doc_sha256": _sha256(files[filing["request_doc"]]),
    }


def check_policy_time(plan, now):
    """Require the filing time to be in the past and at most one day old at run time."""
    if type(now) is not int or now < 1:
        _refuse("npm_stale")
    filed = plan["policy_epoch_ms"] // 1000
    if filed > now + CLOCK_SKEW_SECONDS or now - filed > MAX_REQUEST_TTL_SECONDS:
        _refuse("npm_stale")
    return filed


def project_paths(selector):
    """Return the files copied into the resolver project: manifests and settings only."""
    return tuple(
        path for path in input_paths(selector)
        if path in (".node-version", ".npmrc") or path.endswith("package.json")
    )


def _iso_cutoff(cutoff_ms):
    try:
        seconds, milliseconds = divmod(cutoff_ms, 1000)
        value = datetime.datetime.fromtimestamp(seconds, tz=datetime.timezone.utc)
        value = value.replace(microsecond=milliseconds * 1000)
        return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")
    except (OverflowError, OSError, ValueError, TypeError):
        _refuse("npm_input_invalid")


def _absolute(value):
    return (
        type(value) is str and 0 < len(value) <= 4096 and value.startswith(chr(47))
        and "\x00" not in value and "\n" not in value and "\r" not in value
    )


def resolve_command(node, npm_cli, cutoff_ms, user_config, global_config):
    """Return the one npm command that resolves a lock without installing or running code."""
    for value in (node, npm_cli, user_config, global_config):
        if not _absolute(str(value)):
            _refuse("npm_environment_refused")
    if str(user_config) == str(global_config) or type(cutoff_ms) is not int or cutoff_ms < 1:
        _refuse("npm_environment_refused")
    return (
        str(node), str(npm_cli), "--registry=" + REGISTRY_URL,
        "--userconfig=" + str(user_config), "--globalconfig=" + str(global_config),
        "--ignore-scripts", "--audit=false", "--fund=false", "--fetch-retries=0",
        "--fetch-timeout=30000", "--no-update-notifier", "--strict-peer-deps",
        "--min-release-age=7", "--before=" + _iso_cutoff(cutoff_ms),
        "install", "--package-lock-only", "--workspaces=true", "--include-workspace-root",
    )


def build_npm_environment(node, *, home, tmpdir, cache, user_config, global_config, node_options):
    """Build the whole resolver environment from fixed values; nothing is inherited."""
    for value in (node, home, tmpdir, cache, user_config, global_config):
        if not _absolute(str(value)):
            _refuse("npm_environment_refused")
    if type(node_options) is not str or not 0 < len(node_options) <= 1024:
        _refuse("npm_environment_refused")
    return {
        "PATH": str(Path(str(node)).parent) + ":/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(home),
        "TMPDIR": str(tmpdir),
        "LANG": "C",
        "LC_ALL": "C",
        "NODE_OPTIONS": node_options,
        "npm_config_cache": str(cache),
        "npm_config_registry": REGISTRY_URL,
        "npm_config_userconfig": str(user_config),
        "npm_config_globalconfig": str(global_config),
        "npm_config_ignore_scripts": "true",
        "npm_config_audit": "false",
        "npm_config_fund": "false",
        "npm_config_fetch_retries": "0",
        "npm_config_fetch_timeout": "30000",
        "npm_config_update_notifier": "false",
    }


def check_lock(lock_bytes, plan):
    """Check the resolved lock against the plan and return the parsed lock and registry entries."""
    if type(lock_bytes) is not bytes or not lock_bytes:
        _refuse("npm_lock_refused")
    if len(lock_bytes) > MAX_LOCK_BYTES:
        _refuse("npm_payload_too_large")
    links = workspace_links()
    internal = plan["internal_names"]
    lock = _call_adm(adm.parse_lock, lock_bytes, internal_names=internal, workspace_links=links)
    entries = _call_adm(
        adm.registry_entries, lock_bytes, internal_names=internal, workspace_links=links,
    )
    if not entries or len(entries) > MAX_PACKAGES:
        _refuse("npm_lock_refused")
    packages = lock["packages"]
    root = packages[""]
    expected = plan["root"]
    if (lock["name"] != expected["name"] or lock["version"] != expected["version"]
            or root.get("workspaces") != ["packages/*"]
            or root.get("engines") != {"node": NODE_VERSION, "npm": NPM_VERSION}):
        _refuse("npm_lock_refused")
    for group in DEPENDENCY_GROUPS:
        if root.get(group, {}) != expected[group]:
            _refuse("npm_lock_refused")
    for workspace in plan["workspaces"]:
        entry = packages[workspace["path"]]
        if (entry.get("name") != workspace["name"] or entry.get("version") != workspace["version"]
                or entry.get("dependencies", {}) != workspace["dependencies"]
                or entry.get("devDependencies", {}) != workspace["devDependencies"]):
            _refuse("npm_lock_refused")
    by_name = {}
    for path, entry in entries:
        by_name.setdefault(entry["name"], []).append((path, entry["version"]))
    for name, version in plan["direct"].items():
        if ("node_modules/" + name, version) not in by_name.get(name, []):
            _refuse("npm_lock_refused")
    for name in plan["singletons"]:
        if len(by_name.get(name, [])) > 1:
            _refuse("npm_lock_refused")
    for name, version in plan["overrides"].items():
        found = by_name.get(name, [])
        if len(found) != 1 or found[0][1] != version:
            _refuse("npm_lock_refused")
    for path, entry in entries:
        if entry.get("hasShrinkwrap") is True:
            _refuse("npm_lock_refused")
    return lock, entries


def _resolve_dependency(packages, path, name):
    current = path
    while True:
        candidate = (current + chr(47) if current else "") + "node_modules/" + name
        if candidate in packages:
            return candidate
        if not current:
            return None
        index = current.rfind("/node_modules/")
        current = current[:index] if index != -1 else ""


def check_peers(lock, entries):
    """Re-check every peer range against the locked tree; npm already ran with strict peers."""
    packages = lock["packages"]
    verified = 0
    optional_missing = 0
    for path, entry in entries:
        peers = entry.get("peerDependencies", {})
        meta = entry.get("peerDependenciesMeta", {})
        for name in sorted(peers):
            target = _resolve_dependency(packages, path, name)
            optional = type(meta.get(name)) is dict and meta[name].get("optional") is True
            if target is None:
                if not optional:
                    _refuse("npm_peer_refused")
                optional_missing += 1
                continue
            version = packages[target].get("version")
            if version is None:
                linked = packages.get(packages[target].get("resolved"))
                version = linked.get("version") if type(linked) is dict else None
            try:
                satisfied = semver.satisfies(version, peers[name])
            except semver.SemverError:
                _refuse("npm_peer_refused")
            if not satisfied:
                _refuse("npm_peer_refused")
            verified += 1
    return {"verified": verified, "optional_missing": optional_missing}


def licence_text(value):
    """Normalise a registry or archive licence field to one ASCII string, or None."""
    text = None
    if type(value) is str:
        text = value
    elif type(value) is dict and type(value.get("type")) is str:
        text = value["type"]
    elif (type(value) is list and value
            and all(type(item) is dict and type(item.get("type")) is str for item in value)):
        types = [item["type"] for item in value]
        text = types[0] if len(types) == 1 else "(" + " OR ".join(types) + ")"
    if text is None:
        return None
    text = text.strip()
    return text if _ascii_text(text, 256) else None


def _expression_alternatives(text):
    """Return the two identifiers of an exact two-way OR expression, or None for a plain licence."""
    inner = text[1:-1] if text.startswith("(") and text.endswith(")") else text
    if " OR " not in inner:
        return None
    parts = inner.split(" OR ")
    if len(parts) != 2 or any(LICENCE_ID_RE.fullmatch(part) is None for part in parts):
        _refuse("npm_licence_refused")
    return tuple(parts)


def licence_permitted(name, licence, allowlist):
    """A licence is permitted when it is allowlisted or is a named scoped exception for the package."""
    return licence in allowlist or name in SCOPED_LICENCES.get(licence, ())


def resolve_licence(name, text, plan):
    """Return the effective licence and its condition flags, or refuse.

    A plain licence must be permitted for the package. An exact two-way OR expression is
    accepted only when the policy elects one of its two identifiers for that package and the
    elected licence is permitted. An election for a package without an expression refuses.
    """
    if type(text) is not str or not text:
        _refuse("npm_licence_refused")
    elections = plan["licence_elections"]
    alternatives = _expression_alternatives(text)
    if alternatives is None:
        if name in elections:
            _refuse("npm_licence_refused")
        chosen = text
    else:
        chosen = elections.get(name)
        if chosen not in alternatives:
            _refuse("npm_licence_refused")
    if not licence_permitted(name, chosen, plan["licence_allowlist"]):
        _refuse("npm_licence_refused")
    return chosen, [chosen] if chosen in CONDITIONAL_LICENCES else []


def check_elections_used(plan, packages):
    """Every recorded election must belong to a package whose licence is an expression."""
    used = {item["name"] for item in packages if item["licence"] != item["licence_elected"]}
    if set(plan["licence_elections"]) != used:
        _refuse("npm_licence_refused")


def _archive_manifest(data):
    tar_bytes = _call_adm(adm._read_bounded_gzip, data)
    try:
        with tarfile.open(
            fileobj=io.BytesIO(tar_bytes), mode="r:", encoding="utf-8", errors="strict",
        ) as archive:
            member = archive.getmember("package/package.json")
            stream = archive.extractfile(member) if member.isreg() else None
            if stream is None or member.size > adm.MAX_PACKAGE_JSON_BYTES:
                _refuse("npm_archive_refused")
            with stream:
                content = stream.read(adm.MAX_PACKAGE_JSON_BYTES + 1)
    except BootstrapRefusal:
        raise
    except (KeyError, tarfile.TarError, OSError, ValueError, UnicodeError, EOFError):
        _refuse("npm_archive_refused")
    manifest = _call_adm(adm._load_json, content, adm.MAX_PACKAGE_JSON_BYTES, "npm_archive_invalid")
    if type(manifest) is not dict:
        _refuse("npm_archive_refused")
    return manifest


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class RegistryFetcher:
    """Read metadata, archives and advisories from the one fixed registry origin only."""

    def __init__(self, opener=None, deadline=None):
        self._opener = opener if opener is not None else urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect(),
        )
        self._deadline = deadline
        self.requests_made = 0
        self.bytes_read = 0

    def _exchange(self, path, limit, accept, body=None):
        if (type(path) is not str or not path.startswith(chr(47)) or "?" in path
                or chr(35) in path or len(path) > 1024):
            _refuse("npm_network_refused")
        if self._deadline is not None and time.monotonic() >= self._deadline:
            _refuse("npm_stale")
        if self.requests_made >= MAX_REQUESTS:
            _refuse("npm_network_refused")
        self.requests_made += 1
        url = REGISTRY_URL[:-1] + path
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or parsed.hostname != REGISTRY_HOST or parsed.port is not None
                or parsed.query or parsed.fragment or parsed.username or parsed.password):
            _refuse("npm_network_refused")
        headers = {"Accept": accept, "User-Agent": USER_AGENT}
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            url, data=body, headers=headers, method="GET" if body is None else "POST",
        )
        try:
            with self._opener.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
                if response.status != 200 or response.geturl() != url:
                    raise ValueError("response")
                data = response.read(limit + 1)
        except (OSError, ValueError, http.client.HTTPException, urllib.error.URLError):
            _refuse("npm_network_refused")
        if type(data) is not bytes or not 0 < len(data) <= limit:
            _refuse("npm_network_refused")
        self.bytes_read += len(data)
        if self.bytes_read > MAX_TOTAL_METADATA_BYTES + adm.MAX_TOTAL_COMPRESSED_BYTES:
            _refuse("npm_network_refused")
        return data

    def packument(self, name):
        if not _valid_name(name):
            _refuse("npm_input_invalid")
        return self._exchange(
            chr(47) + urllib.parse.quote(name, safe="@"), MAX_PACKUMENT_BYTES, "application/json",
        )

    def tarball(self, name, version):
        if not _valid_name(name) or not _exact_version(version):
            _refuse("npm_input_invalid")
        url = adm._canonical_tarball_url(name, version)
        return self._exchange(url[len(REGISTRY_URL) - 1:], adm.MAX_TARBALL_BYTES, "application/octet-stream")

    def advisories(self, body):
        if type(body) is not bytes or not body:
            _refuse("npm_input_invalid")
        return self._exchange(ADVISORY_PATH, MAX_ADVISORY_BYTES, "application/json", body)


def _packument_version(packument_bytes, name, version):
    record = _strict_json(packument_bytes, MAX_PACKUMENT_BYTES, "npm_evidence_invalid")
    if type(record) is not dict or record.get("name") != name:
        _refuse("npm_evidence_invalid")
    versions = record.get("versions")
    times = record.get("time")
    if type(versions) is not dict or type(times) is not dict or "unpublished" in times:
        _refuse("npm_evidence_invalid")
    manifest = versions.get(version)
    published = times.get(version)
    if type(manifest) is not dict or type(published) is not str:
        _refuse("npm_evidence_invalid")
    return manifest, published


def _entry_evidence(path, entry, manifest, published, archive, archive_licence, archive_sha1, plan,
                    now, direct):
    name = entry["name"]
    version = entry["version"]
    dist = manifest.get("dist")
    if type(dist) is not dict:
        _refuse("npm_evidence_invalid")
    if manifest.get("name") != name or manifest.get("version") != version:
        _refuse("npm_evidence_invalid")
    if dist.get("integrity") != entry["integrity"]:
        _refuse("npm_integrity_mismatch")
    if dist.get("tarball") != entry["resolved"]:
        _refuse("npm_integrity_mismatch")
    if "shasum" in dist and dist["shasum"] != archive_sha1:
        _refuse("npm_integrity_mismatch")
    published_epoch = _parse_time(published)
    if published_epoch > now + CLOCK_SKEW_SECONDS:
        _refuse("npm_evidence_invalid")
    age = plan["policy_epoch_ms"] // 1000 - published_epoch
    if age < MIN_PACKAGE_AGE_SECONDS:
        _refuse("npm_package_too_young")
    registry_licence = licence_text(manifest.get("license", manifest.get("licenses")))
    if registry_licence is None or registry_licence != archive_licence:
        _refuse("npm_licence_refused")
    if type(entry.get("license")) is str and entry["license"] != registry_licence:
        _refuse("npm_licence_refused")
    elected, flags = resolve_licence(name, registry_licence, plan)
    deprecated = bool(manifest.get("deprecated"))
    if deprecated and direct:
        _refuse("npm_package_deprecated")
    user = manifest.get("_npmUser")
    publisher = user.get("name") if type(user) is dict else None
    publisher = publisher if _ascii_text(publisher, 128) else ""
    attested = type(dist.get("attestations")) is dict
    row = plan["rows"].get((name, version))
    if row is not None and (
        row["published"] != published or row["integrity"] != entry["integrity"]
        or row["licence"] != registry_licence
        or (row["attested"] is not None and row["attested"] != attested)
        or (row["shasum"] is not None and row["shasum"] != archive_sha1)
    ):
        _refuse("npm_request_mismatch")
    native = archive["native_binaries"]
    return {
        "path": path, "name": name, "version": version, "sha256": archive["sha256"],
        "published": published, "age_days": age // 86400, "licence": registry_licence,
        "licence_elected": elected, "licence_flags": flags,
        "install_scripts": list(archive["install_scripts"]),
        "native_count": len(native), "native_sample": list(native[:4]),
        "attested": attested, "publisher": publisher, "deprecated": deprecated,
        "dev": entry.get("dev") is True, "optional": entry.get("optional") is True,
        "compressed_bytes": archive["compressed_bytes"], "unpacked_bytes": archive["unpacked_bytes"],
        "file_count": archive["file_count"], "direct": direct,
    }


def _advisory_body(entries):
    inventory = {}
    for path, entry in entries:
        inventory.setdefault(entry["name"], set()).add(entry["version"])
    return {name: sorted(versions) for name, versions in sorted(inventory.items())}


def _reachable_paths(packages, start):
    """Return every lock path reachable from one path over runtime, optional and peer edges."""
    seen = set()
    stack = [start]
    while stack:
        path = stack.pop()
        if path in seen:
            continue
        seen.add(path)
        entry = packages.get(path)
        if type(entry) is not dict:
            continue
        if entry.get("link") is True and type(entry.get("resolved")) is str:
            stack.append(entry["resolved"])
        for group in LOCK_EDGE_GROUPS:
            edges = entry.get(group, {})
            if type(edges) is not dict:
                continue
            for dependency in edges:
                target = _resolve_dependency(packages, path, dependency)
                if target is not None:
                    stack.append(target)
    return seen


def _direct_reach(lock, direct):
    """Map each root direct dependency to the set of lock paths its dependency paths reach."""
    packages = lock["packages"]
    reach = {}
    for name in sorted(direct):
        start = _resolve_dependency(packages, "", name)
        if start is not None:
            reach[name] = _reachable_paths(packages, start)
    return reach


def _allow_applies(record, name, versions, severity, entries, reach, fetched_ms, policy_epoch_ms):
    """Apply every allow rule to one record for one advisory on the locked versions it covers."""
    if severity in ALLOW_REFUSED_SEVERITIES:
        return False
    expires = record["expires_at_ms"]
    if not _allow_expiry_bounded(expires, policy_epoch_ms) or expires <= fetched_ms:
        return False
    affected = {
        path: entry for path, entry in entries
        if entry["name"] == name and entry["version"] in versions
    }
    if not affected or any(entry.get("dev") is not True for entry in affected.values()):
        return False
    consumers = set()
    covered = set()
    for root_name, reached in reach.items():
        hit = set(affected) & reached
        if hit:
            consumers.add(root_name)
            covered |= hit
    return covered == set(affected) and set(record["consumers"]) == consumers


def check_advisories(response_bytes, inventory, allows=(), direct=None, now_ms=0,
                     lock=None, entries=None, policy_epoch_ms=None):
    """Match the bulk advisory answer against the exact locked versions.

    Every advisory that applies to a locked version blocks the proposal unless a recorded
    allow covers it. An allow covers an advisory only when its severity is below high, every
    affected locked entry is development-only, the record names exactly the root direct
    dependencies that reach those entries, and its expiry is bounded after the policy epoch
    and still ahead of the advisory fetch time, which is the now_ms value given here.
    """
    record = _strict_json(response_bytes, MAX_ADVISORY_BYTES, "npm_advisory_invalid")
    if type(record) is not dict or set(record) - set(inventory):
        _refuse("npm_advisory_invalid")
    findings = []
    reach = None
    for name in sorted(record):
        items = record[name]
        if type(items) is not list or len(items) > 10_000:
            _refuse("npm_advisory_invalid")
        for item in items:
            if (type(item) is not dict or type(item.get("vulnerable_versions")) is not str
                    or not 0 < len(item["vulnerable_versions"]) <= 1024
                    or item.get("name", name) != name):
                _refuse("npm_advisory_invalid")
            severity = item.get("severity")
            if type(severity) is not str or severity not in SEVERITIES:
                _refuse("npm_advisory_invalid")
            identifier = item.get("id")
            if type(identifier) not in (int, str):
                _refuse("npm_advisory_invalid")
            identifiers = {str(identifier)}
            if type(item.get("github_advisory_id")) is str:
                identifiers.add(item["github_advisory_id"])
            versions = []
            for version in inventory[name]:
                try:
                    vulnerable = semver.satisfies(version, item["vulnerable_versions"])
                except semver.SemverError:
                    _refuse("npm_advisory_invalid")
                if vulnerable:
                    versions.append(version)
            if not versions:
                continue
            candidates = [
                allow for allow in allows
                if allow["name"] == name and allow["advisory_id"] in identifiers
            ]
            allowed = None
            if (candidates and type(lock) is dict and type(entries) is list
                    and type(policy_epoch_ms) is int):
                if reach is None:
                    reach = _direct_reach(lock, direct or {})
                for candidate in candidates:
                    if _allow_applies(candidate, name, frozenset(versions), severity, entries,
                                      reach, now_ms, policy_epoch_ms):
                        allowed = candidate
                        break
            if allowed is None:
                _refuse("npm_advisory_blocked")
            for version in versions:
                findings.append({
                    "name": name, "version": version, "severity": severity,
                    "advisory_id": allowed["advisory_id"], "range": item["vulnerable_versions"],
                    "allow_justification_sha256": allowed["justification_sha256"],
                    "allow_expires_at_ms": allowed["expires_at_ms"],
                    "allow_removal_condition": allowed["removal_condition"],
                })
                if len(findings) > MAX_FINDINGS:
                    _refuse("npm_payload_too_large")
    findings.sort(key=lambda item: (item["name"], item["version"], item["advisory_id"]))
    return findings


def _check_context(trusted_context):
    if type(trusted_context) is not dict or set(trusted_context) != set(TRUSTED_CONTEXT_FIELDS):
        _refuse("npm_input_invalid")
    for name, value in trusted_context.items():
        if not _ascii_text(value, 256):
            _refuse("npm_input_invalid")
    return dict(trusted_context)


def _check_times(now, expiry):
    if (type(now) is not int or type(expiry) is not int or now < 1 or expiry <= now
            or expiry - now > MAX_REQUEST_TTL_SECONDS):
        _refuse("npm_stale")


def _check_run(run_id, run_attempt):
    if (type(run_id) is not str or DECIMAL_RE.fullmatch(run_id) is None
            or type(run_attempt) is not int or run_attempt != 1):
        _refuse("npm_input_invalid")


def build_receipt(lock_bytes, plan, trusted_context, identities):
    """Build the canonical proposed receipt; every audit record stays pending review."""
    context = _check_context(trusted_context)
    if context["filing"] != plan["filing"]:
        _refuse("npm_input_invalid")
    lock_sha = _sha256(lock_bytes)
    record = {
        "schema_version": SCHEMA_VERSION,
        "record_type": RECORD_TYPE,
        "context": context,
        "inputs_sha256": plan["inputs_sha256"],
        "request_doc_sha256": plan["request_doc_sha256"],
        "lock_sha256": lock_sha,
        "archive_set_sha256": _call_adm(adm.archive_set_digest, identities),
        "package_set_sha256": _call_adm(adm.package_set_digest, lock_sha, identities),
        "packages": [dict(item, audit_record_id=PENDING_AUDIT_ID) for item in identities],
    }
    encoded = _canonical(record, "npm_evidence_invalid")
    if len(encoded) > MAX_RECEIPT_BYTES:
        _refuse("npm_payload_too_large")
    return encoded



def encode_bundle(lock_bytes, receipt_bytes, evidence_bytes):
    """Encode the single return payload under the npm admission profile's own limits."""
    for data, maximum in (
        (lock_bytes, MAX_LOCK_BYTES), (receipt_bytes, MAX_RECEIPT_BYTES),
        (evidence_bytes, MAX_EVIDENCE_BYTES),
    ):
        if type(data) is not bytes or not data:
            _refuse("npm_input_invalid")
        if len(data) > maximum:
            _refuse("npm_payload_too_large")
    encoded = _canonical({
        "schema_version": SCHEMA_VERSION,
        "lock_b64": base64.b64encode(lock_bytes).decode("ascii"),
        "receipt_b64": base64.b64encode(receipt_bytes).decode("ascii"),
        "evidence_b64": base64.b64encode(evidence_bytes).decode("ascii"),
    }, "npm_input_invalid")
    if len(encoded) > MAX_BUNDLE_BYTES:
        _refuse("npm_payload_too_large")
    return encoded


def decode_bundle(bundle_bytes):
    """Decode only canonical bounded bundle bytes into lock, receipt and evidence bytes."""
    if type(bundle_bytes) is not bytes or not bundle_bytes:
        _refuse("npm_input_invalid")
    if len(bundle_bytes) > MAX_BUNDLE_BYTES:
        _refuse("npm_payload_too_large")
    record = _strict_json(bundle_bytes, MAX_BUNDLE_BYTES, "npm_input_invalid")
    if (type(record) is not dict or set(record) != set(BUNDLE_FIELDS)
            or type(record["schema_version"]) is not int
            or record["schema_version"] != SCHEMA_VERSION):
        _refuse("npm_input_invalid")
    members = []
    for name, maximum in (
        ("lock_b64", MAX_LOCK_BYTES), ("receipt_b64", MAX_RECEIPT_BYTES),
        ("evidence_b64", MAX_EVIDENCE_BYTES),
    ):
        text = record[name]
        if type(text) is not str or not text:
            _refuse("npm_input_invalid")
        try:
            data = base64.b64decode(text.encode("ascii"), validate=True)
        except (ValueError, UnicodeError):
            _refuse("npm_input_invalid")
        if base64.b64encode(data).decode("ascii") != text or not data:
            _refuse("npm_input_invalid")
        if len(data) > maximum:
            _refuse("npm_payload_too_large")
        members.append(data)
    if encode_bundle(*members) != bundle_bytes:
        _refuse("npm_input_invalid")
    return tuple(members)


def validate_receipt(receipt_bytes, lock_bytes, plan, trusted_context):
    """Check the receipt against its lock, the plan and the trusted context."""
    if type(receipt_bytes) is not bytes or not 0 < len(receipt_bytes) <= MAX_RECEIPT_BYTES:
        _refuse("npm_evidence_invalid")
    record = _strict_json(receipt_bytes, MAX_RECEIPT_BYTES, "npm_evidence_invalid")
    if (type(record) is not dict or set(record) != set(RECEIPT_FIELDS)
            or _canonical(record, "npm_evidence_invalid") != receipt_bytes
            or record["schema_version"] != SCHEMA_VERSION or record["record_type"] != RECORD_TYPE
            or record["context"] != _check_context(trusted_context)
            or record["inputs_sha256"] != plan["inputs_sha256"]
            or record["request_doc_sha256"] != plan["request_doc_sha256"]
            or not hmac.compare_digest(record["lock_sha256"], _sha256(lock_bytes))):
        _refuse("npm_evidence_invalid")
    entries = _call_adm(adm.registry_entries, lock_bytes, workspace_links=workspace_links())
    packages = record["packages"]
    if type(packages) is not list or len(packages) != len(entries):
        _refuse("npm_evidence_invalid")
    identities = []
    for item, (path, entry) in zip(packages, entries):
        if (type(item) is not dict or set(item) != set(RECEIPT_PACKAGE_FIELDS)
                or item["path"] != path or item["name"] != entry["name"]
                or item["version"] != entry["version"] or item["integrity"] != entry["integrity"]
                or item["audit_record_id"] != PENDING_AUDIT_ID or not _valid_hex(item["sha256"])):
            _refuse("npm_evidence_invalid")
        identities.append({key: item[key] for key in ("path", "name", "version", "integrity", "sha256")})
    if (record["archive_set_sha256"] != _call_adm(adm.archive_set_digest, identities)
            or record["package_set_sha256"]
            != _call_adm(adm.package_set_digest, record["lock_sha256"], identities)):
        _refuse("npm_evidence_invalid")
    return record


def _finding_allowed(item, fetched_ms, policy_epoch_ms):
    """Re-check the parts of a recorded allow that the evidence alone can prove."""
    if type(item) is not dict:
        return False
    expires = item.get("allow_expires_at_ms")
    return (
        type(expires) is int and type(item.get("severity")) is str
        and item["severity"] in ALLOWABLE_SEVERITIES
        and _allow_expiry_bounded(expires, policy_epoch_ms) and expires > fetched_ms
    )


def validate_evidence(evidence_bytes, receipt_bytes, lock_bytes, receipt, plan, *, now):
    """Check the evidence against its receipt, lock and plan, the cooling rule and its expiry."""
    if type(evidence_bytes) is not bytes or not 0 < len(evidence_bytes) <= MAX_EVIDENCE_BYTES:
        _refuse("npm_evidence_invalid")
    record = _strict_json(evidence_bytes, MAX_EVIDENCE_BYTES, "npm_evidence_invalid")
    if (type(record) is not dict or set(record) != set(EVIDENCE_FIELDS)
            or _canonical(record, "npm_evidence_invalid") != evidence_bytes
            or record["schema_version"] != SCHEMA_VERSION
            or not hmac.compare_digest(record["receipt_sha256"], _sha256(receipt_bytes))
            or not hmac.compare_digest(record["lock_sha256"], _sha256(lock_bytes))
            or record["inputs_sha256"] != receipt["inputs_sha256"]
            or record["registry_origin"] != REGISTRY_HOST
            or record["minimum_age_seconds"] != MIN_PACKAGE_AGE_SECONDS
            or record["attestation_verification"] != "not_performed"):
        _refuse("npm_evidence_invalid")
    _check_run(record["run_id"], record["run_attempt"])
    generated = record["generated_at"]
    expiry = record["expiry"]
    _check_times(generated, expiry)
    if (type(now) is not int or now >= expiry or now < generated - CLOCK_SKEW_SECONDS
            or record["policy_epoch_ms"] != plan["policy_epoch_ms"]
            or record["cutoff_epoch_ms"] != plan["cutoff_epoch_ms"]):
        _refuse("npm_stale")
    check_policy_time(plan, generated)
    packages = record["packages"]
    if type(packages) is not list or len(packages) != len(receipt["packages"]):
        _refuse("npm_evidence_invalid")
    for item, expected in zip(packages, receipt["packages"]):
        if (type(item) is not dict or set(item) != set(EVIDENCE_PACKAGE_FIELDS)
                or item["path"] != expected["path"] or item["name"] != expected["name"]
                or item["version"] != expected["version"] or item["sha256"] != expected["sha256"]):
            _refuse("npm_evidence_invalid")
        if plan["policy_epoch_ms"] // 1000 - _parse_time(item["published"]) < MIN_PACKAGE_AGE_SECONDS:
            _refuse("npm_package_too_young")
        elected, flags = resolve_licence(item["name"], item["licence"], plan)
        if item["licence_elected"] != elected or item["licence_flags"] != flags:
            _refuse("npm_licence_refused")
    check_elections_used(plan, packages)
    advisory = record["advisory"]
    if (type(advisory) is not dict or set(advisory) != set(ADVISORY_FIELDS)
            or advisory["endpoint"] != ADVISORY_ENDPOINT
            or advisory["valid_until"] != advisory["fetched_at"] + ADVISORY_MAX_AGE_SECONDS
            or advisory["status"] not in ("clear", "allowed_findings")
            or type(advisory["findings"]) is not list
            or advisory["finding_count"] != len(advisory["findings"])
            or (advisory["status"] == "clear") != (not advisory["findings"])
            or any(not _finding_allowed(item, advisory["fetched_at"] * 1000, plan["policy_epoch_ms"])
                   for item in advisory["findings"])):
        _refuse("npm_evidence_invalid")
    return record


def verify_bundle(bundle_bytes, plan, trusted_context, *, now):
    """Fully re-verify a bundle: lock, receipt, evidence ages and expiry."""
    lock_bytes, receipt_bytes, evidence_bytes = decode_bundle(bundle_bytes)
    check_lock(lock_bytes, plan)
    receipt = validate_receipt(receipt_bytes, lock_bytes, plan, trusted_context)
    validate_evidence(evidence_bytes, receipt_bytes, lock_bytes, receipt, plan, now=now)
    return lock_bytes, receipt_bytes, evidence_bytes


def _by_name(entries):
    groups = {}
    for path, entry in entries:
        groups.setdefault(entry["name"], []).append((path, entry))
    return groups


def _path_key(item):
    return item["path"].encode("ascii", "strict")


def collect_evidence(lock, entries, plan, *, run_id, run_attempt, now, expiry, fetcher,
                     clock=None, node_version=NODE_VERSION, npm_version=NPM_VERSION):
    """Fetch metadata, archives and advisories; return the evidence record and archive identities."""
    _check_run(run_id, run_attempt)
    _check_times(now, expiry)
    check_policy_time(plan, now)
    if fetcher is None or not all(
        callable(getattr(fetcher, method, None)) for method in ("packument", "tarball", "advisories")
    ):
        _refuse("npm_input_invalid")
    peer_summary = check_peers(lock, entries)
    identities = []
    packages = []
    totals = {"compressed_bytes": 0, "unpacked_bytes": 0, "file_count": 0}
    matched_rows = set()
    groups = _by_name(entries)
    for name in sorted(groups):
        packument = fetcher.packument(name)
        if type(packument) is not bytes:
            _refuse("npm_evidence_invalid")
        for path, entry in groups[name]:
            version = entry["version"]
            manifest, published = _packument_version(packument, name, version)
            data = fetcher.tarball(name, version)
            archive = _call_adm(adm.verify_tarball, {
                "name": name, "version": version, "integrity": entry["integrity"],
                "resolved": entry["resolved"],
            }, data, internal_names=plan["internal_names"])
            archive_manifest = _archive_manifest(data)
            archive_licence = licence_text(
                archive_manifest.get("license", archive_manifest.get("licenses")),
            )
            for key in totals:
                totals[key] += archive[key]
            if (totals["compressed_bytes"] > adm.MAX_TOTAL_COMPRESSED_BYTES
                    or totals["unpacked_bytes"] > adm.MAX_TOTAL_UNPACKED_BYTES
                    or totals["file_count"] > adm.MAX_ARCHIVE_FILES):
                _refuse("npm_archive_refused")
            packages.append(_entry_evidence(
                path, entry, manifest, published, archive, archive_licence,
                hashlib.sha1(data).hexdigest(), plan, now,
                name in plan["direct"],
            ))
            if (name, version) in plan["rows"]:
                matched_rows.add((name, version))
            identities.append({
                "path": path, "name": name, "version": version,
                "integrity": entry["integrity"], "sha256": archive["sha256"],
            })
    if set(plan["rows"]) != matched_rows:
        _refuse("npm_request_mismatch")
    identities.sort(key=_path_key)
    packages.sort(key=_path_key)
    inventory = _advisory_body(entries)
    request_body = _canonical(inventory, "npm_advisory_invalid")
    response_bytes = fetcher.advisories(request_body)
    if type(response_bytes) is not bytes:
        _refuse("npm_advisory_invalid")
    check_elections_used(plan, packages)
    fetched_at = int((clock if clock is not None else time.time)())
    if fetched_at < now - CLOCK_SKEW_SECONDS:
        _refuse("npm_stale")
    findings = check_advisories(
        response_bytes, inventory, plan["advisory_allows"], plan["direct"], fetched_at * 1000,
        lock=lock, entries=entries, policy_epoch_ms=plan["policy_epoch_ms"],
    )
    names = {name: len(items) for name, items in groups.items()}
    record = {
        "schema_version": SCHEMA_VERSION,
        "receipt_sha256": None,
        "lock_sha256": None,
        "inputs_sha256": plan["inputs_sha256"],
        "run_id": run_id,
        "run_attempt": run_attempt,
        "generated_at": now,
        "expiry": expiry,
        "policy_epoch_ms": plan["policy_epoch_ms"],
        "cutoff_epoch_ms": plan["cutoff_epoch_ms"],
        "minimum_age_seconds": MIN_PACKAGE_AGE_SECONDS,
        "registry_origin": REGISTRY_HOST,
        "resolver": {"node_version": node_version, "npm_version": npm_version},
        "attestation_verification": "not_performed",
        "totals": {
            "packages": len(entries), "distinct_names": len(names),
            "compressed_bytes": totals["compressed_bytes"],
            "unpacked_bytes": totals["unpacked_bytes"], "file_count": totals["file_count"],
            "install_script_packages": sum(1 for item in packages if item["install_scripts"]),
            "native_packages": sum(1 for item in packages if item["native_count"]),
            "unattested_packages": sum(1 for item in packages if not item["attested"]),
            "peer_checks": peer_summary["verified"],
            "optional_peers_missing": peer_summary["optional_missing"],
        },
        "advisory": {
            "endpoint": ADVISORY_ENDPOINT, "fetched_at": fetched_at,
            "valid_until": fetched_at + ADVISORY_MAX_AGE_SECONDS,
            "request_sha256": _sha256(request_body), "response_sha256": _sha256(response_bytes),
            "package_count": len(inventory), "finding_count": len(findings),
            "status": "clear" if not findings else "allowed_findings", "findings": findings,
        },
        "duplicates": sorted(name for name, count in names.items() if count > 1)[:64],
        "packages": packages,
    }
    return record, identities


def build_evidence(record, lock_bytes, receipt_bytes):
    """Bind the collected evidence record to its lock and receipt and encode it canonically."""
    if type(record) is not dict:
        _refuse("npm_evidence_invalid")
    bound = dict(record)
    bound["receipt_sha256"] = _sha256(receipt_bytes)
    bound["lock_sha256"] = _sha256(lock_bytes)
    encoded = _canonical(bound, "npm_evidence_invalid")
    if len(encoded) > MAX_EVIDENCE_BYTES:
        _refuse("npm_payload_too_large")
    return encoded


def produce_bundle(lock_bytes, plan, trusted_context, *, run_id, run_attempt, now, expiry, fetcher,
                   clock=None, node_version=NODE_VERSION, npm_version=NPM_VERSION):
    """Check the lock, gather every piece of evidence and encode one self-verified bundle."""
    _check_context(trusted_context)
    lock, entries = check_lock(lock_bytes, plan)
    record, identities = collect_evidence(
        lock, entries, plan, run_id=run_id, run_attempt=run_attempt, now=now, expiry=expiry,
        fetcher=fetcher, clock=clock, node_version=node_version, npm_version=npm_version,
    )
    receipt_bytes = build_receipt(lock_bytes, plan, trusted_context, identities)
    evidence_bytes = build_evidence(record, lock_bytes, receipt_bytes)
    bundle = encode_bundle(lock_bytes, receipt_bytes, evidence_bytes)
    verify_bundle(bundle, plan, trusted_context, now=now)
    return bundle
