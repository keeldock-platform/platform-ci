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
import socket
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
MAX_PACKUMENT_BYTES = 96 * 1024 * 1024
MAX_ADVISORY_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 256
MAX_REQUESTS = 2 * MAX_PACKAGES + 1
FETCH_CHUNK_BYTES = 1024 * 1024
MAX_TOTAL_METADATA_BYTES = 1536 * 1024 * 1024
MIN_PACKAGE_AGE_SECONDS = 7 * 24 * 60 * 60
ADVISORY_MAX_AGE_SECONDS = 24 * 60 * 60
CLOCK_SKEW_SECONDS = 300
MAX_REQUEST_TTL_SECONDS = 24 * 60 * 60
FETCH_TIMEOUT_SECONDS = 60
FETCH_TIMEOUT_TYPES = (TimeoutError, socket.timeout)
MAX_COLLECTED_REFUSALS = 20
MAX_PACKAGES_AFTER_REFUSAL = 64
TOTAL_STOP_HEADS = frozenset(("archive_size", "archive_count"))
STOP_REFUSAL_REASONS = frozenset((
    "npm_stale", "npm_environment_refused", "npm_network_refused", "npm_payload_too_large",
))
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
UI_KIT_WORKSPACE_PATHS = ("packages/kernel-icons", "packages/kernel-ui-kit")
DEFAULT_FILING = "contract-ui-batch-a"
UI_BATCH_B_FILING = "contract-ui-batch-b"
FIXTURE_FILING = "quick-fixture"
CORE_WAVE_70A_FILING = "core-wave70a"
RUNTIME_WAVE_70A_FILING = "runtime-wave70a"
CORE_WAVE_70B_FILING = "core-wave70b"
RUNTIME_WAVE_70B_FILING = "runtime-wave70b"
CORE_WAVE_71B_FILING = "core-wave71b"
RUNTIME_WAVE_71B_FILING = "runtime-wave71b"
CORE_WAVE_70A_WORKSPACES = WORKSPACE_PATHS + UI_KIT_WORKSPACE_PATHS
CORE_WAVE_70B_WORKSPACES = CORE_WAVE_70A_WORKSPACES + ("packages/i18n",)
CORE_WAVE_71B_WORKSPACES = (
    "packages/host-api", "packages/kernel-i18n", "packages/kernel-icons",
    "packages/kernel-tokens", "packages/kernel-ui-kit", "packages/i18n",
    "packages/kernel-markdown", "packages/kernel-workers", "packages/extension-sdk",
    "packages/extension-mock",
)
CORE_WAVE_71B_MEMBER_EDGES = (
    ("packages/kernel-ui-kit", "packages/kernel-icons"),
    ("packages/kernel-ui-kit", "packages/kernel-tokens"),
    ("packages/i18n", "packages/kernel-i18n"),
    ("packages/extension-mock", "packages/extension-sdk"),
)
CORE_WAVE_71B_TEST_ONLY_WORKSPACES = ("packages/extension-mock",)
RUNTIME_WAVE_70_WORKSPACES = (
    "runtime/apps/test-shell-desktop/web",
    "runtime/apps/test-shell-mobile/web",
    "runtime/packages/host-ui",
)
RUNTIME_SHELL_WORKSPACES = RUNTIME_WAVE_70_WORKSPACES[:2]
RUNTIME_WAVE_70A_FILE_EDGES = tuple(
    (source, name, target)
    for source in RUNTIME_SHELL_WORKSPACES
    for name, target in (
        (SCOPE + "host-api", "packages/host-api"),
        (SCOPE + "kernel-ui-kit", "packages/kernel-ui-kit"),
    )
) + tuple(
    ("runtime/packages/host-ui", name, target)
    for name, target in (
        (SCOPE + "host-api", "packages/host-api"),
        (SCOPE + "kernel-ui-kit", "packages/kernel-ui-kit"),
    )
) + (("packages/kernel-ui-kit", SCOPE + "kernel-icons", "packages/kernel-icons"),)
RUNTIME_WAVE_70B_FILE_EDGES = RUNTIME_WAVE_70A_FILE_EDGES + tuple(
    (source, SCOPE + "i18n", "packages/i18n")
    for source in RUNTIME_WAVE_70_WORKSPACES
)
RUNTIME_WAVE_70A_MEMBER_EDGES = tuple(
    (source, "runtime/packages/host-ui") for source in RUNTIME_SHELL_WORKSPACES
)
RUNTIME_WAVE_70B_MEMBER_EDGES = RUNTIME_WAVE_70A_MEMBER_EDGES
RUNTIME_WAVE_70B_FILE_EDGES += (
    ("packages/i18n", SCOPE + "kernel-i18n", "packages/kernel-i18n"),
    ("runtime/packages/host-ui", SCOPE + "i18n", "packages/i18n"),
    ("runtime/packages/host-ui", SCOPE + "kernel-markdown", "packages/kernel-markdown"),
    ("runtime/packages/host-ui", SCOPE + "kernel-workers", "packages/kernel-workers"),
    ("runtime/packages/host-ui", SCOPE + "extension-sdk", "packages/extension-sdk"),
) + tuple(
    (source, SCOPE + "i18n", "packages/i18n") for source in RUNTIME_SHELL_WORKSPACES
)
RUNTIME_WAVE_71B_FILE_EDGES = tuple(
    (source, name, target)
    for source in RUNTIME_SHELL_WORKSPACES
    for name, target in (
        (SCOPE + "host-api", "packages/host-api"),
        (SCOPE + "kernel-ui-kit", "packages/kernel-ui-kit"),
        (SCOPE + "i18n", "packages/i18n"),
    )
) + tuple(
    ("runtime/packages/host-ui", name, target)
    for name, target in (
        (SCOPE + "host-api", "packages/host-api"),
        (SCOPE + "kernel-ui-kit", "packages/kernel-ui-kit"),
        (SCOPE + "i18n", "packages/i18n"),
        (SCOPE + "kernel-markdown", "packages/kernel-markdown"),
        (SCOPE + "kernel-workers", "packages/kernel-workers"),
        (SCOPE + "extension-sdk", "packages/extension-sdk"),
    )
) + (
    ("packages/kernel-ui-kit", SCOPE + "kernel-icons", "packages/kernel-icons"),
    ("packages/kernel-ui-kit", SCOPE + "kernel-tokens", "packages/kernel-tokens"),
    ("packages/i18n", SCOPE + "kernel-i18n", "packages/kernel-i18n"),
)
RUNTIME_WAVE_71B_MEMBER_EDGES = RUNTIME_WAVE_70A_MEMBER_EDGES
FILINGS = {
    DEFAULT_FILING: {
        "request_doc": "docs/dependencies/ui-npm-admission-batch-a.md",
        "workspaces": WORKSPACE_PATHS,
        "member_edges": (),
        "overrides": {"lightningcss": "1.33.0"},
    },
    UI_BATCH_B_FILING: {
        "request_doc": "docs/dependencies/ui-npm-admission-batch-b.md",
        "workspaces": WORKSPACE_PATHS + UI_KIT_WORKSPACE_PATHS,
        "member_edges": ((UI_KIT_WORKSPACE_PATHS[1], UI_KIT_WORKSPACE_PATHS[0]),),
        "overrides": {"lightningcss": "1.33.0"},
    },
    FIXTURE_FILING: {
        "request_doc": "docs/dependencies/quick-fixture.md",
        "workspaces": WORKSPACE_PATHS,
        "member_edges": (),
        "overrides": {},
    },
    CORE_WAVE_70A_FILING: {
        "root_kind": "core", "root_manifest": "package.json", "root_lock": "package-lock.json",
        "root_name": ROOT_NAME, "project_root": "", "node_version": ".node-version",
        "npmrc": ".npmrc", "workspace_patterns": ("packages/*",),
        "request_doc": "docs/dependencies/ui-npm-admission-batch-b.md",
        "workspaces": CORE_WAVE_70A_WORKSPACES,
        "member_edges": ((UI_KIT_WORKSPACE_PATHS[1], UI_KIT_WORKSPACE_PATHS[0]),),
        "file_edges": (), "overrides": {"lightningcss": "1.33.0"},
    },
    RUNTIME_WAVE_70A_FILING: {
        "root_kind": "runtime", "root_manifest": "runtime/package.json",
        "root_lock": "runtime/package-lock.json", "root_name": None, "project_root": "runtime",
        "node_version": "runtime/.node-version", "npmrc": "runtime/.npmrc",
        "workspace_patterns": tuple(path[len("runtime/"):] for path in RUNTIME_WAVE_70_WORKSPACES),
        "request_doc": "docs/dependencies/ui-npm-admission-batch-b.md",
        "workspaces": RUNTIME_WAVE_70_WORKSPACES, "member_edges": RUNTIME_WAVE_70A_MEMBER_EDGES,
        "file_edges": RUNTIME_WAVE_70A_FILE_EDGES, "overrides": {},
    },
    CORE_WAVE_70B_FILING: {
        "root_kind": "core", "root_manifest": "package.json", "root_lock": "package-lock.json",
        "root_name": ROOT_NAME, "project_root": "", "node_version": ".node-version",
        "npmrc": ".npmrc", "workspace_patterns": ("packages/*",),
        "request_doc": "docs/dependencies/ui-npm-admission-batch-b.md",
        "workspaces": CORE_WAVE_70B_WORKSPACES,
        "member_edges": (
            (UI_KIT_WORKSPACE_PATHS[1], UI_KIT_WORKSPACE_PATHS[0]),
            ("packages/i18n", "packages/kernel-i18n"),
        ),
        "file_edges": (), "overrides": {"lightningcss": "1.33.0"},
    },
    RUNTIME_WAVE_70B_FILING: {
        "root_kind": "runtime", "root_manifest": "runtime/package.json",
        "root_lock": "runtime/package-lock.json", "root_name": None, "project_root": "runtime",
        "node_version": "runtime/.node-version", "npmrc": "runtime/.npmrc",
        "workspace_patterns": tuple(path[len("runtime/"):] for path in RUNTIME_WAVE_70_WORKSPACES),
        "request_doc": "docs/dependencies/ui-npm-admission-batch-b.md",
        "workspaces": RUNTIME_WAVE_70_WORKSPACES, "member_edges": RUNTIME_WAVE_70B_MEMBER_EDGES,
        "file_edges": RUNTIME_WAVE_70B_FILE_EDGES, "overrides": {},
    },
    CORE_WAVE_71B_FILING: {
        "root_kind": "core", "root_manifest": "package.json", "root_lock": "package-lock.json",
        "root_name": ROOT_NAME, "project_root": "", "node_version": ".node-version",
        "npmrc": ".npmrc", "workspace_patterns": ("packages/*",),
        "request_doc": "docs/dependencies/npm-wave71b-core.md",
        "workspaces": CORE_WAVE_71B_WORKSPACES,
        "member_edges": CORE_WAVE_71B_MEMBER_EDGES,
        "test_only_workspaces": CORE_WAVE_71B_TEST_ONLY_WORKSPACES,
        "overrides": {"lightningcss": "1.33.0"},
    },
    RUNTIME_WAVE_71B_FILING: {
        "root_kind": "runtime", "root_manifest": "runtime/package.json",
        "root_lock": "runtime/package-lock.json", "root_name": None, "project_root": "runtime",
        "node_version": "runtime/.node-version", "npmrc": "runtime/.npmrc",
        "workspace_patterns": tuple(path[len("runtime/"):] for path in RUNTIME_WAVE_70_WORKSPACES),
        "request_doc": "docs/dependencies/npm-wave71b-runtime.md",
        "workspaces": RUNTIME_WAVE_70_WORKSPACES, "member_edges": RUNTIME_WAVE_71B_MEMBER_EDGES,
        "file_edges": RUNTIME_WAVE_71B_FILE_EDGES, "overrides": {},
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
    "0BSD",
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
    "lock_sha256", "archive_set_sha256", "package_set_sha256", "root_kind", "node_version",
    "npm_version", "members", "file_edges", "packages",
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


LOCK_DETAIL_MAX_BYTES = adm.DETAIL_MAX_BYTES
LOCK_DETAIL_GRAMMAR = adm.DETAIL_GRAMMAR
LOCK_DETAIL_RE = re.compile(LOCK_DETAIL_GRAMMAR)
LOCK_DETAIL_REASON_RE = re.compile(r"[a-z_]{1,40}\Z")
LOCK_DETAIL_MAX_VERSIONS = adm.DETAIL_MAX_VERSIONS


def _valid_lock_detail(text):
    return type(text) is str and len(text) <= LOCK_DETAIL_MAX_BYTES and LOCK_DETAIL_RE.match(text) is not None


def lock_detail(token, subject=None, versions=None, count=None):
    """Build the bounded, ASCII-only check identifier carried by one lock refusal.

    The token is a fixed lowercase word, the subject an npm name or lock path and the versions
    semver-shaped strings. Anything outside those shapes is replaced or dropped, never echoed,
    and versions are dropped whole until the text fits, so the result always matches the grammar."""
    text = adm.build_detail(token, () if subject is None else (subject,), versions, count)
    return text if _valid_lock_detail(text) else None


class BootstrapRefusal(Exception):
    """A refusal with a fixed reason that never contains caller-provided data."""

    def __init__(self, reason="npm_input_invalid", detail=None):
        if reason not in REASONS:
            reason = "npm_input_invalid"
        self.reason = reason
        self.detail = detail if _valid_lock_detail(detail) else None
        self.details = () if self.detail is None else (self.detail,)
        super().__init__(reason)


def _refuse(reason="npm_input_invalid", detail=None):
    raise BootstrapRefusal(reason, detail)


def _call_adm(function, *arguments, **keywords):
    try:
        return function(*arguments, **keywords)
    except adm.Refusal as error:
        shared = getattr(error, "reason", None)
        detail = None
        if type(shared) is str and LOCK_DETAIL_REASON_RE.match(shared) is not None:
            detail = lock_detail("shared_parser", shared)
            token = getattr(error, "detail", None)
            if detail is not None and _valid_lock_detail(token):
                combined = detail + ":" + token
                if _valid_lock_detail(combined):
                    detail = combined
        raise BootstrapRefusal(ADM_REASON_MAP.get(shared, "npm_lock_refused"), detail) from None


def bundle_detail(token, subject, *segments, fields=()):
    """Build the bounded check identifier of one bundle step refusal: a fixed token, the package
    as name@version or the word bundle, then fixed rule words and sanitised public values."""
    if type(subject) is not str:
        subject = "bundle"
    text = adm.build_detail(token, (subject,) + segments, fields=fields)
    return text if _valid_lock_detail(text) else None


def _bundle_refuse(reason, token, subject, *segments, fields=()):
    raise BootstrapRefusal(reason, bundle_detail(token, subject, *segments, fields=fields))


def _fetch_status(value):
    return str(value) if type(value) is int and 100 <= value <= 599 else "status"


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
        _refuse(reason, bundle_detail("canonical", "bundle", "encode"))


def _reject_constant(value):
    raise ValueError("constant")


def _strict_json(data, maximum, reason, detail=None):
    if type(data) is not bytes or not 0 < len(data) <= maximum:
        _refuse(reason, detail)
    try:
        text = data.decode("utf-8", "strict")
        if text.startswith(chr(0xFEFF)):
            raise ValueError("bom")
        return json.loads(
            text, object_pairs_hook=adm._unique_json_pairs, parse_constant=_reject_constant,
        )
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _refuse(reason, detail)


def _ascii_text(value, maximum):
    return (
        type(value) is str and 0 < len(value) <= maximum and value.isascii()
        and value.isprintable()
    )


def _parse_time(value, subject=None):
    match = TIME_RE.fullmatch(value) if type(value) is str else None
    if match is None:
        _bundle_refuse("npm_evidence_invalid", "evidence", subject, "time_format")
    fields = tuple(int(part) for part in match.groups())
    try:
        moment = datetime.datetime(*fields)
    except ValueError:
        _bundle_refuse("npm_evidence_invalid", "evidence", subject, "time_value")
    return calendar.timegm(moment.utctimetuple())


def _exact_version(value):
    return adm._valid_version(value) and "+" not in value


def _valid_name(name, extra=()):
    return adm._valid_package_name(name) and not adm._internal_name(name, extra)


def _scoped_name(path):
    if path == "runtime/apps/test-shell-desktop/web":
        return SCOPE + "test-shell-desktop"
    if path == "runtime/apps/test-shell-mobile/web":
        return SCOPE + "test-shell-mobile"
    return SCOPE + posixpath.basename(path)


def _lock_workspace_path(path, filing):
    project_root = filing.get("project_root", "")
    relative = path[len(project_root) + 1:] if project_root and path.startswith(project_root + "/") else path
    if relative.startswith("apps/"):
        return "packages/runtime/" + relative
    return relative


def _profile_file_spec(source, target):
    return "file:" + posixpath.relpath(target, source)


def _profile_file_lock_path(target, filing):
    project_root = filing.get("project_root", "")
    return posixpath.relpath(target, project_root or ".")


def workspace_links(selector=DEFAULT_FILING):
    """Return the fixed workspace link map the lock of one filing must carry."""
    filing = filing_for(selector)
    links = {
        "node_modules/" + _scoped_name(path): _lock_workspace_path(path, filing)
        for path in filing["workspaces"]
    }
    for source, name, target in filing.get("file_edges", ()):
        lock_path = target
        link_path = "node_modules/" + name
        previous = links.setdefault(link_path, lock_path)
        if previous != lock_path:
            _refuse("npm_input_invalid")
    return links


def filing_for(selector):
    if type(selector) is not str or selector not in FILINGS:
        _refuse("npm_input_invalid")
    return FILINGS[selector]


def input_paths(selector):
    """Return the exact repository paths read from the source revision, in a fixed order."""
    filing = filing_for(selector)
    root_manifest = filing.get("root_manifest", "package.json")
    package_paths = list(filing["workspaces"])
    extra_package_paths = set()
    for source, name, target in filing.get("file_edges", ()):
        extra_package_paths.update((source, target))
    return (
        filing.get("node_version", ".node-version"), filing.get("npmrc", ".npmrc"), root_manifest,
    ) + tuple(path + "/package.json" for path in package_paths + sorted(extra_package_paths - set(package_paths))) + (
        POLICY_FILE, filing["request_doc"],
    )


def _check_scripts(scripts):
    if type(scripts) is not dict or len(scripts) > 64:
        _refuse("npm_manifest_refused")
    for name, value in scripts.items():
        if (not _ascii_text(name, 64) or not _ascii_text(value, 512) or name in LIFECYCLE_SCRIPTS):
            _refuse("npm_manifest_refused")


def _manifest(data):
    manifest = _strict_json(data, MAX_MANIFEST_BYTES, "npm_manifest_refused")
    if type(manifest) is not dict:
        _refuse("npm_manifest_refused")
    return manifest


def _check_dependencies(value, internal, workspace_names=frozenset(), file_specs=None):
    if type(value) is not dict or len(value) > 512:
        _refuse("npm_manifest_refused")
    file_specs = {} if file_specs is None else file_specs
    for name, spec in value.items():
        if name in file_specs:
            if spec != file_specs[name]:
                _refuse("npm_manifest_refused")
        elif name in workspace_names:
            if not _exact_version(spec):
                _refuse("npm_manifest_refused")
        elif not _valid_name(name, internal) or not _exact_version(spec):
            _refuse("npm_manifest_refused")
    return dict(value)


def _check_root(manifest, filing, internal):
    if "root_name" in filing:
        root_name = filing["root_name"] or manifest.get("name")
    else:
        root_name = ROOT_NAME
    if (set(manifest) - ROOT_KEYS or manifest.get("name") != root_name
            or not adm._valid_version(manifest.get("version")) or manifest.get("private") is not True
            or manifest.get("packageManager") != "npm@" + NPM_VERSION
            or manifest.get("engines") != {"node": NODE_VERSION, "npm": NPM_VERSION}
            or manifest.get("workspaces") != list(filing.get("workspace_patterns", ("packages/*",)))):
        _refuse("npm_manifest_refused")
    _check_scripts(manifest.get("scripts", {}))
    groups = {group: _check_dependencies(manifest.get(group, {}), internal) for group in DEPENDENCY_GROUPS}
    overrides = manifest.get("overrides", {})
    if overrides != filing["overrides"]:
        _refuse("npm_manifest_refused")
    return groups, dict(overrides)


def _check_workspace(manifest, path, internal, workspace_names=frozenset(), file_specs=None):
    if (set(manifest) - WORKSPACE_KEYS or manifest.get("name") != _scoped_name(path)
            or not adm._valid_version(manifest.get("version"))):
        _refuse("npm_manifest_refused")
    _check_scripts(manifest.get("scripts", {}))
    return {
        group: _check_dependencies(manifest.get(group, {}), internal, workspace_names, file_specs)
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
    if direct and all(type(value) is dict for value in direct.values()):
        if set(direct) - {"core", "runtime"}:
            _refuse("npm_policy_refused")
        root_direct = {}
        for root_kind, dependencies in direct.items():
            if len(dependencies) > 512:
                _refuse("npm_policy_refused")
            for name, version in dependencies.items():
                if not _valid_name(name, internal) or not _exact_version(version):
                    _refuse("npm_policy_refused")
            root_direct[root_kind] = dict(dependencies)
    else:
        for name, version in direct.items():
            if not _valid_name(name, internal) or not _exact_version(version):
                _refuse("npm_policy_refused")
        root_direct = dict(direct)
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
        "direct": root_direct,
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
    node_path = filing.get("node_version", ".node-version")
    npmrc_path = filing.get("npmrc", ".npmrc")
    root_manifest_path = filing.get("root_manifest", "package.json")
    if files[node_path] != NODE_VERSION_BYTES or files[npmrc_path] != NPMRC_BYTES:
        _refuse("npm_manifest_refused")
    policy = parse_policy(files[POLICY_FILE])
    internal = policy["internal_names"]
    root_manifest = _manifest(files[root_manifest_path])
    root_groups, overrides = _check_root(root_manifest, filing, internal)
    root_policy_direct = policy["direct"]
    if root_policy_direct and all(type(value) is dict for value in root_policy_direct.values()):
        root_policy_direct = root_policy_direct.get(filing.get("root_kind"), {})
    root_direct = {}
    for group in root_groups.values():
        for name, version in group.items():
            if root_direct.setdefault(name, version) != version:
                _refuse("npm_manifest_refused")
    direct = dict(root_direct)
    package_paths = set(filing["workspaces"])
    for source, name, target in filing.get("file_edges", ()):
        package_paths.add(source)
        package_paths.add(target)
    for source, target in filing.get("member_edges", ()):
        package_paths.add(source)
        package_paths.add(target)
    file_specs_by_source = {}
    file_targets_by_source = {}
    for source, name, target in filing.get("file_edges", ()):
        file_specs_by_source.setdefault(source, {})[name] = _profile_file_spec(source, target)
        file_targets_by_source.setdefault(source, {})[name] = target
    package_records = {}
    for path in sorted(package_paths):
        data_path = path + "/package.json"
        manifest_bytes = files[data_path]
        manifest = _manifest(manifest_bytes)
        allowed_members = frozenset(
            _scoped_name(target) for source, target in filing.get("member_edges", ()) if source == path
        )
        file_specs = file_specs_by_source.get(path, {})
        link_names = allowed_members | frozenset(file_specs)
        groups = _check_workspace(manifest, path, internal, link_names, file_specs)
        record = {
            "path": path, "lock_path": _lock_workspace_path(path, filing),
            "name": manifest["name"], "version": manifest["version"],
            "manifest_sha256": _sha256(manifest_bytes),
            "dependencies": groups["dependencies"], "devDependencies": groups["devDependencies"],
            "lock_dependencies": {}, "lock_devDependencies": {},
        }
        for group in ("dependencies", "devDependencies"):
            lock_group = dict(groups[group])
            for name, target in file_targets_by_source.get(path, {}).items():
                if name in lock_group:
                    target_manifest = _manifest(files[target + "/package.json"])
                    if target_manifest.get("name") != name:
                        _refuse("npm_manifest_refused")
                    lock_group[name] = target_manifest["version"]
            record["lock_" + group] = lock_group
            for name, version in groups[group].items():
                if name in link_names:
                    continue
                if direct.setdefault(name, version) != version:
                    _refuse("npm_manifest_refused")
        package_records[path] = record
    if not direct or direct != root_policy_direct:
        _refuse("npm_policy_refused")
    workspaces = [package_records[path] for path in filing["workspaces"]]
    workspace_versions = {item["name"]: item["version"] for item in workspaces}
    file_edges = []
    for source, name, target in filing.get("file_edges", ()):
        source_record = package_records[source]
        target_record = package_records[target]
        if _scoped_name(target) != name or target_record["name"] != name:
            _refuse("npm_manifest_refused")
        file_edges.append({
            "source": source, "name": name, "target": target,
            "spec": _profile_file_spec(source, target),
            "source_manifest_sha256": source_record["manifest_sha256"],
            "target_manifest_sha256": target_record["manifest_sha256"],
        })
    for source, target in filing.get("member_edges", ()):
        if package_records[target]["name"] != _scoped_name(target):
            _refuse("npm_manifest_refused")
        source_record = package_records[source]
        target_name = package_records[target]["name"]
        for group in ("dependencies", "devDependencies"):
            if target_name in source_record[group] and source_record[group][target_name] != package_records[target]["version"]:
                _refuse("npm_manifest_refused")
    for item in workspaces:
        for group in ("dependencies", "devDependencies"):
            for name, spec in item[group].items():
                if name in workspace_versions and spec != workspace_versions[name]:
                    _refuse("npm_manifest_refused")
    test_only_names = {
        _scoped_name(path) for path in filing.get("test_only_workspaces", ())
    }
    if test_only_names:
        if any(name in group for group in root_groups.values() for name in test_only_names):
            _refuse("npm_manifest_refused")
        for source_record in package_records.values():
            if source_record["path"] in filing.get("test_only_workspaces", ()):
                continue
            if any(
                name in source_record["dependencies"] for name in test_only_names
            ):
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
            "workspaces": ["packages/*"],
        },
        "workspaces": workspaces,
        "source_packages": list(package_records.values()),
        "file_edges": file_edges,
        "workspace_names": workspace_versions,
        "workspace_patterns": list(filing.get("workspace_patterns", ("packages/*",))),
        "project_root": filing.get("project_root", ""),
        "root_kind": filing.get("root_kind", "core"),
        "node_version": NODE_VERSION, "npm_version": NPM_VERSION,
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
        _bundle_refuse("npm_stale", "stale", "bundle", "policy_now")
    filed = plan["policy_epoch_ms"] // 1000
    if filed > now + CLOCK_SKEW_SECONDS:
        _bundle_refuse("npm_stale", "stale", "bundle", "policy_future")
    if now - filed > MAX_REQUEST_TTL_SECONDS:
        _bundle_refuse("npm_stale", "stale", "bundle", "policy_age")
    return filed


def project_paths(selector):
    """Return the files copied into the resolver project: manifests and settings only."""
    filing = filing_for(selector)
    return tuple(path for path in input_paths(selector)
                 if path not in (POLICY_FILE, filing["request_doc"]))


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


def _normalize_profile_lock(lock_bytes, plan):
    """Validate local paths and convert the runtime lock to the shared parser's bounded shape."""
    if plan["root_kind"] != "runtime":
        return lock_bytes
    raw = _strict_json(lock_bytes, MAX_LOCK_BYTES, "npm_lock_refused")
    if type(raw) is not dict or type(raw.get("packages")) is not dict or "" not in raw["packages"]:
        _refuse("npm_lock_refused")
    packages = raw["packages"]
    filing = filing_for(plan["filing"])
    root = packages[""]
    if type(root) is not dict or root.get("workspaces") != plan["workspace_patterns"]:
        _refuse("npm_lock_refused")
    expected_link_paths = workspace_links(plan["filing"])
    raw_link_targets = {}
    normalized_targets = {}
    member_paths = {item["path"] for item in plan["workspaces"]}
    file_target_paths = {item["target"] for item in plan["file_edges"]}
    package_paths = set(member_paths) | file_target_paths
    project_root = plan["project_root"]
    for item in plan["source_packages"]:
        path = item["path"]
        relative = path[len(project_root) + 1:] if project_root and path.startswith(project_root + "/") else path
        if path in member_paths:
            raw_path = relative
            normalized_path = item["lock_path"]
        elif path in file_target_paths:
            raw_path = _profile_file_lock_path(path, filing)
            normalized_path = path
        else:
            continue
        if raw_path in raw_link_targets.values() or normalized_path in normalized_targets.values():
            _refuse("npm_lock_refused")
        raw_link_targets[path] = raw_path
        normalized_targets[path] = normalized_path
        entry = packages.get(raw_path)
        if type(entry) is not dict or entry.get("name") != item["name"] or entry.get("version") != item["version"]:
            _refuse("npm_lock_refused")
    for link_path, normalized_target in expected_link_paths.items():
        match_paths = [path for path, normalized in normalized_targets.items() if normalized == normalized_target]
        if len(match_paths) != 1:
            _refuse("npm_lock_refused")
        target_path = match_paths[0]
        actual_target = raw_link_targets[target_path]
        link = packages.get(link_path)
        if type(link) is not dict or link != {"resolved": actual_target, "link": True}:
            _refuse("npm_lock_refused")
    allowed_package_entries = {"", *raw_link_targets.values()}
    allowed_link_entries = set(expected_link_paths)
    local_names = {adm._package_name_from_lock_path(path) for path in expected_link_paths}
    for path in packages:
        if path in allowed_package_entries or path in allowed_link_entries:
            continue
        if path.startswith("node_modules/"):
            name = adm._package_name_from_lock_path(path)
            if name in local_names:
                _refuse("npm_lock_refused")
            continue
        _refuse("npm_lock_refused")
    raw_to_normalized = dict(zip(raw_link_targets.values(), normalized_targets.values()))
    transformed = {}
    for path, entry in packages.items():
        new_path = raw_to_normalized.get(path, path)
        if new_path in transformed:
            _refuse("npm_lock_refused")
        transformed_entry = dict(entry) if type(entry) is dict else entry
        if path in allowed_link_entries:
            target_path = next(target for link, target in expected_link_paths.items() if link == path)
            transformed_entry = {"resolved": target_path, "link": True}
        elif path == "":
            transformed_entry = dict(entry)
            transformed_entry["workspaces"] = ["packages/*"]
        else:
            source = next((item for item in plan["source_packages"] if raw_link_targets.get(item["path"]) == path), None)
            if source is not None:
                transformed_entry = dict(entry)
                for group in ("dependencies", "devDependencies"):
                    values = transformed_entry.get(group)
                    if type(values) is dict:
                        values = dict(values)
                        for edge in plan["file_edges"]:
                            if edge["source"] == source["path"] and edge["name"] in values:
                                if values[edge["name"]] != edge["spec"]:
                                    _refuse("npm_lock_refused")
                                values[edge["name"]] = next(
                                    item["version"] for item in plan["source_packages"]
                                    if item["path"] == edge["target"]
                                )
                        transformed_entry[group] = values
        transformed[new_path] = transformed_entry
    normalized = dict(raw)
    normalized["packages"] = transformed
    normalized_bytes = json.dumps(
        normalized, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode("ascii")
    return normalized_bytes


def check_lock(lock_bytes, plan):
    """Check the resolved lock against the plan and return the parsed lock and registry entries."""
    if type(lock_bytes) is not bytes or not lock_bytes:
        _refuse("npm_lock_refused", lock_detail("lock_empty"))
    if len(lock_bytes) > MAX_LOCK_BYTES:
        _bundle_refuse("npm_payload_too_large", "payload_size", "bundle", "lock")
    normalized_bytes = _normalize_profile_lock(lock_bytes, plan)
    links = workspace_links(plan["filing"])
    internal = plan["internal_names"]
    lock = _call_adm(adm.parse_lock, normalized_bytes, internal_names=internal, workspace_links=links)
    entries = _call_adm(
        adm.registry_entries, normalized_bytes, internal_names=internal, workspace_links=links,
    )
    if not entries or len(entries) > MAX_PACKAGES:
        _refuse("npm_lock_refused", lock_detail("entry_count", count=len(entries) if entries else 0))
    packages = lock["packages"]
    root = packages[""]
    expected = plan["root"]
    for field, same in (
        ("name", lock["name"] == expected["name"]),
        ("version", lock["version"] == expected["version"]),
        ("workspaces", root.get("workspaces") == plan["root"]["workspaces"]),
        ("engines", root.get("engines") == {"node": NODE_VERSION, "npm": NPM_VERSION}),
    ):
        if not same:
            _refuse("npm_lock_refused", lock_detail("root_identity", field))
    for group in DEPENDENCY_GROUPS:
        if root.get(group, {}) != expected[group]:
            _refuse("npm_lock_refused", lock_detail("root_group", group))
    for workspace in plan["workspaces"]:
        entry = packages[workspace["lock_path"]]
        if (entry.get("name") != workspace["name"] or entry.get("version") != workspace["version"]
                or entry.get("dependencies", {}) != workspace["lock_dependencies"]
                or entry.get("devDependencies", {}) != workspace["lock_devDependencies"]):
            _refuse("npm_lock_refused", lock_detail("workspace", workspace["path"]))
    for source_package in plan["source_packages"]:
        if source_package["path"] in {item["path"] for item in plan["workspaces"]}:
            continue
        entry = packages.get(source_package["lock_path"])
        if (type(entry) is not dict or entry.get("name") != source_package["name"]
                or entry.get("version") != source_package["version"]
                or entry.get("dependencies", {}) != source_package["lock_dependencies"]
                or entry.get("devDependencies", {}) != source_package["lock_devDependencies"]):
            _refuse("npm_lock_refused")
    by_name = {}
    for path, entry in entries:
        by_name.setdefault(entry["name"], []).append((path, entry["version"]))
    for name, version in plan["direct"].items():
        if ("node_modules/" + name, version) not in by_name.get(name, []):
            _refuse("npm_lock_refused", lock_detail(
                "direct_missing", name, [found[1] for found in by_name.get(name, [])],
            ))
    for name in plan["singletons"]:
        if len(by_name.get(name, [])) > 1:
            _refuse("npm_lock_refused", lock_detail(
                "singleton_duplicate", name, [found[1] for found in by_name[name]],
                count=len(by_name[name]),
            ))
    for name, version in plan["overrides"].items():
        found = by_name.get(name, [])
        if len(found) != 1 or found[0][1] != version:
            _refuse("npm_lock_refused", lock_detail(
                "override_mismatch", name, [item[1] for item in found], count=len(found),
            ))
    for path, entry in entries:
        if entry.get("hasShrinkwrap") is True:
            _refuse("npm_lock_refused", lock_detail("shrinkwrap", path))
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


def _entry_subject(path, entry):
    name = entry.get("name") if type(entry) is dict else None
    version = entry.get("version") if type(entry) is dict else None
    if type(name) is str and type(version) is str:
        return adm.package_subject(name, version)
    return adm.detail_text(path, 100)


def check_peers(lock, entries):
    """Re-check every peer range against the locked tree; npm already ran with strict peers."""
    packages = lock["packages"]
    verified = 0
    optional_missing = 0
    for path, entry in entries:
        peers = entry.get("peerDependencies", {})
        meta = entry.get("peerDependenciesMeta", {})
        subject = _entry_subject(path, entry)
        for name in sorted(peers):
            target = _resolve_dependency(packages, path, name)
            optional = type(meta.get(name)) is dict and meta[name].get("optional") is True
            peer_name = adm.detail_text(name, 60)
            if target is None:
                if not optional:
                    _bundle_refuse("npm_peer_refused", "peer", subject, peer_name, "missing")
                optional_missing += 1
                continue
            version = packages[target].get("version")
            if version is None:
                linked = packages.get(packages[target].get("resolved"))
                version = linked.get("version") if type(linked) is dict else None
            try:
                satisfied = semver.satisfies(version, peers[name])
            except semver.SemverError:
                _bundle_refuse("npm_peer_refused", "peer", subject, peer_name, "unparseable")
            if not satisfied:
                _bundle_refuse("npm_peer_refused", "peer", subject, peer_name, "range")
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


def _licence_refuse(subject, why, value):
    _bundle_refuse(
        "npm_licence_refused", "licence", subject, why,
        fields=(("id", adm.detail_text(value, 64, adm.DETAIL_FIELD_CHAR_RE)),),
    )


def _expression_alternatives(text, subject=None):
    """Return the two identifiers of an exact two-way OR expression, or None for a plain licence."""
    inner = text[1:-1] if text.startswith("(") and text.endswith(")") else text
    if " OR " not in inner:
        return None
    parts = inner.split(" OR ")
    if len(parts) != 2 or any(LICENCE_ID_RE.fullmatch(part) is None for part in parts):
        _licence_refuse(subject, "expression_shape", text)
    return tuple(parts)


def licence_permitted(name, licence, allowlist):
    """A licence is permitted when it is allowlisted or is a named scoped exception for the package."""
    return licence in allowlist or name in SCOPED_LICENCES.get(licence, ())


def resolve_licence(name, text, plan, subject=None):
    """Return the effective licence and its condition flags, or refuse.

    A plain licence must be permitted for the package. An exact two-way OR expression is
    accepted only when the policy elects one of its two identifiers for that package and the
    elected licence is permitted. An election for a package without an expression refuses.
    """
    if subject is None:
        subject = adm.package_subject(name)
    if type(text) is not str or not text:
        _licence_refuse(subject, "missing", None)
    elections = plan["licence_elections"]
    alternatives = _expression_alternatives(text, subject)
    if alternatives is None:
        if name in elections:
            _licence_refuse(subject, "election_without_expression", text)
        chosen = text
    else:
        chosen = elections.get(name)
        if chosen not in alternatives:
            _licence_refuse(subject, "election_missing", text)
    if not licence_permitted(name, chosen, plan["licence_allowlist"]):
        _licence_refuse(subject, "not_allowed", chosen)
    return chosen, [chosen] if chosen in CONDITIONAL_LICENCES else []


def check_elections_used(plan, packages):
    """Every recorded election must belong to a package whose licence is an expression."""
    used = {item["name"] for item in packages if item["licence"] != item["licence_elected"]}
    recorded = set(plan["licence_elections"])
    if recorded != used:
        unused = sorted(recorded - used)
        extra = sorted(used - recorded)
        culprit = (unused or extra)[0]
        _licence_refuse(
            adm.package_subject(culprit), "election_unused" if unused else "election_unrecorded",
            plan["licence_elections"].get(culprit),
        )


def _archive_manifest(data, name=None, version=None):
    subject = adm.package_subject(name, version) if name is not None else "bundle"
    tar_bytes = _call_adm(adm._read_bounded_gzip, data, subject)
    try:
        with tarfile.open(
            fileobj=io.BytesIO(tar_bytes), mode="r:", encoding="utf-8", errors="strict",
        ) as archive:
            first = archive.next()
            if first is None:
                raise KeyError("root")
            member = archive.getmember(first.name.split("/", 1)[0] + "/package.json")
            stream = archive.extractfile(member) if member.isreg() else None
            if stream is None or member.size > adm.MAX_PACKAGE_JSON_BYTES:
                _bundle_refuse("npm_archive_refused", "archive_manifest", subject, "unreadable")
            with stream:
                content = stream.read(adm.MAX_PACKAGE_JSON_BYTES + 1)
    except BootstrapRefusal:
        raise
    except (KeyError, tarfile.TarError, OSError, ValueError, UnicodeError, EOFError) as error:
        _bundle_refuse(
            "npm_archive_refused", "archive_manifest", subject, "read",
            adm.detail_text(type(error).__name__, 40),
        )
    try:
        manifest = _call_adm(
            adm._load_json, content, adm.MAX_PACKAGE_JSON_BYTES, "npm_archive_invalid", opaque_numbers=True,
        )
    except BootstrapRefusal as error:
        token = adm._detail_head(error.detail.split(":", 2)[-1] if error.detail else None)
        _bundle_refuse(error.reason, "archive_manifest", subject, token)
    if type(manifest) is not dict:
        _bundle_refuse("npm_archive_refused", "archive_manifest", subject, "shape")
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

    def _exchange(self, path, limit, accept, body=None, subject="fetch"):
        if (type(path) is not str or not path.startswith(chr(47)) or "?" in path
                or "\x23" in path or len(path) > 1024):
            _bundle_refuse("npm_network_refused", "fetch", subject, "path")
        if self._deadline is not None and time.monotonic() >= self._deadline:
            _bundle_refuse("npm_stale", "stale", subject, "fetch_deadline")
        if self.requests_made >= MAX_REQUESTS:
            _bundle_refuse("npm_network_refused", "fetch", subject, "request_cap")
        self.requests_made += 1
        url = REGISTRY_URL[:-1] + path
        parsed = urllib.parse.urlsplit(url)
        if (parsed.scheme != "https" or parsed.hostname != REGISTRY_HOST or parsed.port is not None
                or parsed.query or parsed.fragment or parsed.username or parsed.password):
            _bundle_refuse("npm_network_refused", "fetch", subject, "origin")
        headers = {"Accept": accept, "User-Agent": USER_AGENT}
        if body is not None:
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(
            url, data=body, headers=headers, method="GET" if body is None else "POST",
        )
        failure = "response"
        try:
            with self._opener.open(request, timeout=FETCH_TIMEOUT_SECONDS) as response:
                if response.status != 200 or response.geturl() != url:
                    failure = _fetch_status(response.status) if response.status != 200 else "url_changed"
                    raise ValueError("response")
                chunks = []
                remaining = limit + 1
                while remaining > 0:
                    if self._deadline is not None and time.monotonic() >= self._deadline:
                        _bundle_refuse("npm_stale", "stale", subject, "fetch_deadline")
                    chunk = response.read(min(FETCH_CHUNK_BYTES, remaining))
                    if type(chunk) is not bytes or not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                data = b"".join(chunks)
        except urllib.error.HTTPError as error:
            _bundle_refuse(
                "npm_network_refused", "fetch", subject, _fetch_status(getattr(error, "code", None)),
            )
        except urllib.error.URLError as error:
            timed_out = isinstance(getattr(error, "reason", None), FETCH_TIMEOUT_TYPES)
            _bundle_refuse(
                "npm_network_refused", "fetch", subject, "timeout" if timed_out else "connect",
            )
        except FETCH_TIMEOUT_TYPES:
            _bundle_refuse("npm_network_refused", "fetch", subject, "timeout")
        except (OSError, http.client.HTTPException):
            _bundle_refuse("npm_network_refused", "fetch", subject, "transport")
        except ValueError:
            _bundle_refuse("npm_network_refused", "fetch", subject, failure)
        if type(data) is not bytes or not 0 < len(data) <= limit:
            too_large = type(data) is bytes and len(data) > limit
            _bundle_refuse(
                "npm_network_refused", "fetch", subject, "too_large" if too_large else "empty",
            )
        self.bytes_read += len(data)
        if self.bytes_read > MAX_TOTAL_METADATA_BYTES + adm.MAX_TOTAL_COMPRESSED_BYTES:
            _bundle_refuse("npm_network_refused", "fetch", subject, "total_bytes")
        return data

    def packument(self, name):
        subject = adm.package_subject(name)
        if not _valid_name(name):
            _bundle_refuse("npm_input_invalid", "bundle_input", subject, "packument_name")
        return self._exchange(
            chr(47) + urllib.parse.quote(name, safe="@"), MAX_PACKUMENT_BYTES, "application/json",
            subject=subject,
        )

    def tarball(self, name, version):
        subject = adm.package_subject(name, version)
        if not _valid_name(name):
            _bundle_refuse("npm_input_invalid", "bundle_input", subject, "tarball_name")
        if not _exact_version(version):
            _bundle_refuse("npm_input_invalid", "bundle_input", subject, "tarball_version")
        url = adm._canonical_tarball_url(name, version)
        return self._exchange(
            url[len(REGISTRY_URL) - 1:], adm.MAX_TARBALL_BYTES, "application/octet-stream",
            subject=subject,
        )

    def advisories(self, body):
        if type(body) is not bytes or not body:
            _bundle_refuse("npm_input_invalid", "bundle_input", "advisories", "request_body")
        return self._exchange(
            ADVISORY_PATH, MAX_ADVISORY_BYTES, "application/json", body, subject="advisories",
        )


def _packument_version(packument_bytes, name, version, cache=None):
    """Return the manifest and publish time of one version. A cache dict, when given, keeps the
    parsed versions and times of this name so a packument is parsed once for all its versions."""
    subject = adm.package_subject(name, version)
    parsed = None if cache is None else cache.get(name)
    if parsed is None:
        record = _strict_json(
            packument_bytes, MAX_PACKUMENT_BYTES, "npm_evidence_invalid",
            bundle_detail("evidence", subject, "packument_json"),
        )
        if type(record) is not dict:
            _bundle_refuse("npm_evidence_invalid", "evidence", subject, "packument_shape")
        if record.get("name") != name:
            _bundle_refuse("npm_evidence_invalid", "evidence", subject, "packument_name")
        versions = record.get("versions")
        times = record.get("time")
        if type(versions) is not dict or type(times) is not dict:
            _bundle_refuse("npm_evidence_invalid", "evidence", subject, "packument_shape")
        if "unpublished" in times:
            _bundle_refuse("npm_evidence_invalid", "evidence", subject, "unpublished")
        parsed = (versions, times)
        if cache is not None:
            cache[name] = parsed
    versions, times = parsed
    manifest = versions.get(version)
    published = times.get(version)
    if type(manifest) is not dict:
        _bundle_refuse("npm_evidence_invalid", "evidence", subject, "packument_version")
    if type(published) is not str:
        _bundle_refuse("npm_evidence_invalid", "evidence", subject, "packument_time")
    return manifest, published


def _entry_evidence(path, entry, manifest, published, archive, archive_licence, archive_sha1, plan,
                    now, direct):
    name = entry["name"]
    version = entry["version"]
    subject = adm.package_subject(name, version)
    dist = manifest.get("dist")
    if type(dist) is not dict:
        _bundle_refuse("npm_evidence_invalid", "evidence", subject, "dist_shape")
    if manifest.get("name") != name:
        _bundle_refuse("npm_evidence_invalid", "evidence", subject, "manifest_name")
    if manifest.get("version") != version:
        _bundle_refuse("npm_evidence_invalid", "evidence", subject, "manifest_version")
    if dist.get("integrity") != entry["integrity"]:
        _bundle_refuse("npm_integrity_mismatch", "integrity_mismatch", subject, "dist_integrity")
    if dist.get("tarball") != entry["resolved"]:
        _bundle_refuse("npm_integrity_mismatch", "integrity_mismatch", subject, "dist_tarball")
    if "shasum" in dist and dist["shasum"] != archive_sha1:
        _bundle_refuse("npm_integrity_mismatch", "integrity_mismatch", subject, "dist_shasum")
    published_epoch = _parse_time(published, subject)
    if published_epoch > now + CLOCK_SKEW_SECONDS:
        _bundle_refuse("npm_evidence_invalid", "evidence", subject, "published_future")
    age = plan["policy_epoch_ms"] // 1000 - published_epoch
    if age < MIN_PACKAGE_AGE_SECONDS:
        _bundle_refuse(
            "npm_package_too_young", "too_young", subject, fields=(("age", max(age // 86400, 0)),),
        )
    registry_licence = licence_text(manifest.get("license", manifest.get("licenses")))
    if registry_licence is None:
        _licence_refuse(subject, "registry_missing", None)
    if registry_licence != archive_licence:
        _licence_refuse(subject, "archive_mismatch", registry_licence)
    if type(entry.get("license")) is str and entry["license"] != registry_licence:
        _licence_refuse(subject, "lock_mismatch", registry_licence)
    elected, flags = resolve_licence(name, registry_licence, plan, subject)
    deprecated = bool(manifest.get("deprecated"))
    if deprecated and direct:
        _bundle_refuse("npm_package_deprecated", "deprecated", subject)
    user = manifest.get("_npmUser")
    publisher = user.get("name") if type(user) is dict else None
    publisher = publisher if _ascii_text(publisher, 128) else ""
    attested = type(dist.get("attestations")) is dict
    row = plan["rows"].get((name, version))
    if row is not None:
        mismatch = None
        if row["published"] != published:
            mismatch = "published"
        elif row["integrity"] != entry["integrity"]:
            mismatch = "integrity"
        elif row["licence"] != registry_licence:
            mismatch = "licence"
        elif row["attested"] is not None and row["attested"] != attested:
            mismatch = "attested"
        elif row["shasum"] is not None and row["shasum"] != archive_sha1:
            mismatch = "shasum"
        if mismatch is not None:
            _bundle_refuse("npm_request_mismatch", "request_mismatch", subject, mismatch)
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


ADVISORY_CONSUMER_BUDGET = 280
MAX_SHOWN_CONSUMERS = 128


def _advisory_reach_fields(name, versions, direct, lock, entries):
    """Name, for a blocked advisory, whether every affected entry is development-only and which
    root direct dependencies reach it, so an allow record can be written to match exactly."""
    try:
        if type(lock) is not dict or type(entries) is not list:
            return ()
        affected = {
            path for path, entry in entries
            if entry.get("name") == name and entry.get("version") in versions
        }
        if not affected:
            return ()
        dev = all(entry.get("dev") is True for path, entry in entries if path in affected)
        reach = _direct_reach(lock, direct or {})
        consumers = sorted(root for root, reached in reach.items() if affected & reached)
        covered = set()
        for reached in reach.values():
            covered |= affected & reached
        unreached = len(affected - covered)
        shown = []
        used = 0
        for consumer in consumers:
            if len(shown) >= MAX_SHOWN_CONSUMERS:
                break
            if adm.DETAIL_FIELD_RE.match(consumer) is None:
                continue
            cost = len(consumer) + (1 if shown else 0)
            if used + cost > ADVISORY_CONSUMER_BUDGET:
                break
            shown.append(consumer)
            used += cost
        fields = [("dev", "yes" if dev else "no"), ("consumers", ",".join(shown) if shown else "none")]
        if len(shown) < len(consumers):
            fields.append(("more", str(len(consumers) - len(shown))))
        fields.append(("unreached", str(unreached)))
        return tuple(fields)
    except Exception:
        return ()


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
    record = _strict_json(
        response_bytes, MAX_ADVISORY_BYTES, "npm_advisory_invalid",
        bundle_detail("advisory_invalid", "advisories", "json"),
    )
    if type(record) is not dict:
        _bundle_refuse("npm_advisory_invalid", "advisory_invalid", "advisories", "shape")
    if set(record) - set(inventory):
        _bundle_refuse(
            "npm_advisory_invalid", "advisory_invalid", "advisories", "unknown_package",
            adm.detail_text(sorted(set(record) - set(inventory))[0], 60),
        )
    findings = []
    reach = None
    for name in sorted(record):
        items = record[name]
        package = adm.package_subject(name)
        if type(items) is not list or len(items) > 10_000:
            _bundle_refuse("npm_advisory_invalid", "advisory_invalid", package, "items_shape")
        for item in items:
            if (type(item) is not dict or type(item.get("vulnerable_versions")) is not str
                    or not 0 < len(item["vulnerable_versions"]) <= 1024
                    or item.get("name", name) != name):
                _bundle_refuse("npm_advisory_invalid", "advisory_invalid", package, "item_shape")
            severity = item.get("severity")
            if type(severity) is not str or severity not in SEVERITIES:
                _bundle_refuse("npm_advisory_invalid", "advisory_invalid", package, "severity")
            identifier = item.get("id")
            if type(identifier) not in (int, str):
                _bundle_refuse("npm_advisory_invalid", "advisory_invalid", package, "id_type")
            identifiers = {str(identifier)}
            if type(item.get("github_advisory_id")) is str:
                identifiers.add(item["github_advisory_id"])
            versions = []
            for version in inventory[name]:
                try:
                    vulnerable = semver.satisfies(version, item["vulnerable_versions"])
                except semver.SemverError:
                    _bundle_refuse("npm_advisory_invalid", "advisory_invalid", package, "range")
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
                advisory_id = item.get("github_advisory_id")
                if type(advisory_id) is not str:
                    advisory_id = str(identifier)
                _bundle_refuse(
                    "npm_advisory_blocked", "advisory", adm.package_subject(name, sorted(versions)[0]),
                    adm.detail_text(advisory_id, 64),
                    fields=(("severity", severity),) + _advisory_reach_fields(
                        name, frozenset(versions), direct, lock, entries,
                    ),
                )
            for version in versions:
                findings.append({
                    "name": name, "version": version, "severity": severity,
                    "advisory_id": allowed["advisory_id"], "range": item["vulnerable_versions"],
                    "allow_justification_sha256": allowed["justification_sha256"],
                    "allow_expires_at_ms": allowed["expires_at_ms"],
                    "allow_removal_condition": allowed["removal_condition"],
                })
                if len(findings) > MAX_FINDINGS:
                    _bundle_refuse("npm_payload_too_large", "payload_size", "advisories", "findings")
    findings.sort(key=lambda item: (item["name"], item["version"], item["advisory_id"]))
    return findings


def _check_context(trusted_context):
    if type(trusted_context) is not dict or set(trusted_context) != set(TRUSTED_CONTEXT_FIELDS):
        _bundle_refuse("npm_input_invalid", "bundle_input", "bundle", "context_shape")
    for name, value in trusted_context.items():
        if not _ascii_text(value, 256):
            _bundle_refuse(
                "npm_input_invalid", "bundle_input", "bundle", "context_value",
                adm.detail_text(name, 40),
            )
    return dict(trusted_context)


def _check_times(now, expiry):
    if (type(now) is not int or type(expiry) is not int or now < 1 or expiry <= now
            or expiry - now > MAX_REQUEST_TTL_SECONDS):
        _bundle_refuse("npm_stale", "stale", "bundle", "times")


def _check_run(run_id, run_attempt):
    if type(run_id) is not str or DECIMAL_RE.fullmatch(run_id) is None:
        _bundle_refuse("npm_input_invalid", "bundle_input", "bundle", "run_id")
    if type(run_attempt) is not int or run_attempt != 1:
        _bundle_refuse("npm_input_invalid", "bundle_input", "bundle", "run_attempt")


def build_receipt(lock_bytes, plan, trusted_context, identities):
    """Build the canonical proposed receipt; every audit record stays pending review."""
    context = _check_context(trusted_context)
    if context["filing"] != plan["filing"]:
        _bundle_refuse("npm_input_invalid", "bundle_input", "bundle", "filing")
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
        "root_kind": plan["root_kind"],
        "node_version": plan["node_version"],
        "npm_version": plan["npm_version"],
        "members": [{key: item[key] for key in (
            "path", "name", "version", "manifest_sha256",
        )} for item in plan["workspaces"]],
        "file_edges": [dict(item) for item in plan["file_edges"]],
        "packages": [dict(item, audit_record_id=PENDING_AUDIT_ID) for item in identities],
    }
    encoded = _canonical(record, "npm_evidence_invalid")
    if len(encoded) > MAX_RECEIPT_BYTES:
        _bundle_refuse("npm_payload_too_large", "payload_size", "bundle", "receipt")
    return encoded



def encode_bundle(lock_bytes, receipt_bytes, evidence_bytes):
    """Encode the single return payload under the npm admission profile's own limits."""
    for label, data, maximum in (
        ("lock", lock_bytes, MAX_LOCK_BYTES), ("receipt", receipt_bytes, MAX_RECEIPT_BYTES),
        ("evidence", evidence_bytes, MAX_EVIDENCE_BYTES),
    ):
        if type(data) is not bytes or not data:
            _bundle_refuse("npm_input_invalid", "bundle_input", "bundle", label + "_empty")
        if len(data) > maximum:
            _bundle_refuse("npm_payload_too_large", "payload_size", "bundle", label)
    encoded = _canonical({
        "schema_version": SCHEMA_VERSION,
        "lock_b64": base64.b64encode(lock_bytes).decode("ascii"),
        "receipt_b64": base64.b64encode(receipt_bytes).decode("ascii"),
        "evidence_b64": base64.b64encode(evidence_bytes).decode("ascii"),
    }, "npm_input_invalid")
    if len(encoded) > MAX_BUNDLE_BYTES:
        _bundle_refuse("npm_payload_too_large", "payload_size", "bundle", "bundle")
    return encoded


def decode_bundle(bundle_bytes):
    """Decode only canonical bounded bundle bytes into lock, receipt and evidence bytes."""
    if type(bundle_bytes) is not bytes or not bundle_bytes:
        _bundle_refuse("npm_input_invalid", "bundle_input", "bundle", "bundle_empty")
    if len(bundle_bytes) > MAX_BUNDLE_BYTES:
        _bundle_refuse("npm_payload_too_large", "payload_size", "bundle", "bundle")
    record = _strict_json(
        bundle_bytes, MAX_BUNDLE_BYTES, "npm_input_invalid",
        bundle_detail("bundle_input", "bundle", "bundle_json"),
    )
    if (type(record) is not dict or set(record) != set(BUNDLE_FIELDS)
            or type(record["schema_version"]) is not int
            or record["schema_version"] != SCHEMA_VERSION):
        _bundle_refuse("npm_input_invalid", "bundle_input", "bundle", "bundle_shape")
    members = []
    for name, maximum in (
        ("lock_b64", MAX_LOCK_BYTES), ("receipt_b64", MAX_RECEIPT_BYTES),
        ("evidence_b64", MAX_EVIDENCE_BYTES),
    ):
        text = record[name]
        if type(text) is not str or not text:
            _bundle_refuse("npm_input_invalid", "bundle_input", "bundle", "member_shape", name)
        try:
            data = base64.b64decode(text.encode("ascii"), validate=True)
        except (ValueError, UnicodeError):
            _bundle_refuse("npm_input_invalid", "bundle_input", "bundle", "member_base64", name)
        if base64.b64encode(data).decode("ascii") != text or not data:
            _bundle_refuse("npm_input_invalid", "bundle_input", "bundle", "member_base64", name)
        if len(data) > maximum:
            _bundle_refuse("npm_payload_too_large", "payload_size", "bundle", name)
        members.append(data)
    if encode_bundle(*members) != bundle_bytes:
        _bundle_refuse("npm_input_invalid", "bundle_input", "bundle", "bundle_canonical")
    return tuple(members)


def validate_receipt(receipt_bytes, lock_bytes, plan, trusted_context):
    """Check the receipt against its lock, the plan and the trusted context."""
    if type(receipt_bytes) is not bytes or not 0 < len(receipt_bytes) <= MAX_RECEIPT_BYTES:
        _evidence_refuse("receipt_size")
    record = _strict_json(
        receipt_bytes, MAX_RECEIPT_BYTES, "npm_evidence_invalid",
        bundle_detail("evidence", "bundle", "receipt_json"),
    )
    if type(record) is not dict or set(record) != set(RECEIPT_FIELDS):
        _evidence_refuse("receipt_shape")
    if _canonical(record, "npm_evidence_invalid") != receipt_bytes:
        _evidence_refuse("receipt_canonical")
    if record["schema_version"] != SCHEMA_VERSION or record["record_type"] != RECORD_TYPE:
        _evidence_refuse("receipt_type")
    if record["context"] != _check_context(trusted_context):
        _evidence_refuse("receipt_context")
    if (record["inputs_sha256"] != plan["inputs_sha256"]
            or record["request_doc_sha256"] != plan["request_doc_sha256"]):
        _evidence_refuse("receipt_inputs")
    expected_members = [{key: item[key] for key in (
        "path", "name", "version", "manifest_sha256",
    )} for item in plan["workspaces"]]
    if (record["root_kind"] != plan["root_kind"]
            or record["node_version"] != plan["node_version"]
            or record["npm_version"] != plan["npm_version"]
            or record["members"] != expected_members
            or record["file_edges"] != plan["file_edges"]):
        _evidence_refuse("receipt_inputs")
    if not hmac.compare_digest(record["lock_sha256"], _sha256(lock_bytes)):
        _evidence_refuse("receipt_lock")
    normalized_bytes = _normalize_profile_lock(lock_bytes, plan)
    entries = _call_adm(
        adm.registry_entries, normalized_bytes, workspace_links=workspace_links(plan["filing"]),
    )
    packages = record["packages"]
    if type(packages) is not list or len(packages) != len(entries):
        _evidence_refuse("receipt_packages")
    identities = []
    for item, (path, entry) in zip(packages, entries):
        subject = adm.package_subject(entry["name"], entry["version"])
        if type(item) is not dict or set(item) != set(RECEIPT_PACKAGE_FIELDS):
            _evidence_refuse("item_shape", subject)
        for field, expected in (
            ("path", path), ("name", entry["name"]), ("version", entry["version"]),
            ("integrity", entry["integrity"]),
        ):
            if item[field] != expected:
                _evidence_refuse("item_" + field, subject)
        if item["audit_record_id"] != PENDING_AUDIT_ID:
            _evidence_refuse("item_audit", subject)
        if not _valid_hex(item["sha256"]):
            _evidence_refuse("item_sha256", subject)
        identities.append({key: item[key] for key in ("path", "name", "version", "integrity", "sha256")})
    if (record["archive_set_sha256"] != _call_adm(adm.archive_set_digest, identities)
            or record["package_set_sha256"]
            != _call_adm(adm.package_set_digest, record["lock_sha256"], identities)):
        _evidence_refuse("receipt_digest")
    return record


def _evidence_refuse(what, subject="bundle"):
    _bundle_refuse("npm_evidence_invalid", "evidence", subject, what)


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
        _evidence_refuse("evidence_size")
    record = _strict_json(
        evidence_bytes, MAX_EVIDENCE_BYTES, "npm_evidence_invalid",
        bundle_detail("evidence", "bundle", "evidence_json"),
    )
    if type(record) is not dict or set(record) != set(EVIDENCE_FIELDS):
        _evidence_refuse("evidence_shape")
    if _canonical(record, "npm_evidence_invalid") != evidence_bytes:
        _evidence_refuse("evidence_canonical")
    if record["schema_version"] != SCHEMA_VERSION:
        _evidence_refuse("evidence_schema")
    if not hmac.compare_digest(record["receipt_sha256"], _sha256(receipt_bytes)):
        _evidence_refuse("evidence_receipt")
    if not hmac.compare_digest(record["lock_sha256"], _sha256(lock_bytes)):
        _evidence_refuse("evidence_lock")
    if record["inputs_sha256"] != receipt["inputs_sha256"]:
        _evidence_refuse("evidence_inputs")
    if (record["registry_origin"] != REGISTRY_HOST
            or record["minimum_age_seconds"] != MIN_PACKAGE_AGE_SECONDS
            or record["attestation_verification"] != "not_performed"):
        _evidence_refuse("evidence_constants")
    _check_run(record["run_id"], record["run_attempt"])
    generated = record["generated_at"]
    expiry = record["expiry"]
    _check_times(generated, expiry)
    if type(now) is not int or now >= expiry or now < generated - CLOCK_SKEW_SECONDS:
        _bundle_refuse("npm_stale", "stale", "bundle", "evidence_window")
    if (record["policy_epoch_ms"] != plan["policy_epoch_ms"]
            or record["cutoff_epoch_ms"] != plan["cutoff_epoch_ms"]):
        _bundle_refuse("npm_stale", "stale", "bundle", "evidence_policy")
    check_policy_time(plan, generated)
    packages = record["packages"]
    if type(packages) is not list or len(packages) != len(receipt["packages"]):
        _evidence_refuse("evidence_packages")
    for item, expected in zip(packages, receipt["packages"]):
        subject = adm.package_subject(expected["name"], expected["version"])
        if type(item) is not dict or set(item) != set(EVIDENCE_PACKAGE_FIELDS):
            _evidence_refuse("item_shape", subject)
        for field in ("path", "name", "version", "sha256"):
            if item[field] != expected[field]:
                _evidence_refuse("item_" + field, subject)
        published = _parse_time(item["published"], subject)
        age = plan["policy_epoch_ms"] // 1000 - published
        if age < MIN_PACKAGE_AGE_SECONDS:
            _bundle_refuse(
                "npm_package_too_young", "too_young", subject,
                fields=(("age", max(age // 86400, 0)),),
            )
        elected, flags = resolve_licence(item["name"], item["licence"], plan, subject)
        if item["licence_elected"] != elected or item["licence_flags"] != flags:
            _licence_refuse(subject, "elected_mismatch", item["licence"])
    check_elections_used(plan, packages)
    advisory = record["advisory"]
    if type(advisory) is not dict or set(advisory) != set(ADVISORY_FIELDS):
        _evidence_refuse("advisory_shape")
    if advisory["endpoint"] != ADVISORY_ENDPOINT:
        _evidence_refuse("advisory_endpoint")
    if advisory["valid_until"] != advisory["fetched_at"] + ADVISORY_MAX_AGE_SECONDS:
        _evidence_refuse("advisory_validity")
    if advisory["status"] not in ("clear", "allowed_findings"):
        _evidence_refuse("advisory_status")
    if type(advisory["findings"]) is not list or advisory["finding_count"] != len(advisory["findings"]):
        _evidence_refuse("advisory_findings")
    if (advisory["status"] == "clear") != (not advisory["findings"]):
        _evidence_refuse("advisory_status_findings")
    if any(not _finding_allowed(item, advisory["fetched_at"] * 1000, plan["policy_epoch_ms"])
           for item in advisory["findings"]):
        _evidence_refuse("advisory_allow")
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


def _check_inert_manifest(entry, manifest, subject):
    """Require an inert bundled entry to carry the same cpu list and bundled names as its archive."""
    if adm._inert_bundled_names(entry) is None:
        return
    if manifest.get("cpu") != entry.get("cpu"):
        _bundle_refuse("npm_archive_refused", "archive_manifest", subject, "inert_cpu")
    names = []
    for key in adm.BUNDLED_FIELDS:
        values = manifest.get(key)
        if values is None:
            continue
        if type(values) is not list or any(type(item) is not str for item in values):
            _bundle_refuse("npm_archive_refused", "archive_manifest", subject, "inert_bundle")
        names.extend(values)
    if sorted(names) != sorted(adm._bundled_names(entry)):
        _bundle_refuse("npm_archive_refused", "archive_manifest", subject, "inert_bundle")


def _collect_entry(path, entry, name, packument, plan, fetcher, now, totals, packument_cache=None):
    """Verify one locked entry and return its evidence. The run totals include the bytes of an
    entry that is then refused, so a refused package still counts toward the totals."""
    version = entry["version"]
    subject = adm.package_subject(name, version)
    manifest, published = _packument_version(packument, name, version, packument_cache)
    data = fetcher.tarball(name, version)
    archive_entry = {
        "name": name, "version": version, "integrity": entry["integrity"],
        "resolved": entry["resolved"],
    }
    for field in ("optional", "devOptional", "cpu", "bundledDependencies", "bundleDependencies"):
        if field in entry:
            archive_entry[field] = entry[field]
    archive, archive_manifest = _call_adm(
        adm.inspect_tarball, archive_entry, data, internal_names=plan["internal_names"],
    )
    if (adm._inert_bundled_names(archive_entry) is not None
            and archive.get("bundled_inert") is not True):
        _bundle_refuse("npm_archive_refused", "archive_manifest", subject, "inert_unverified")
    _check_inert_manifest(entry, archive_manifest, subject)
    archive_licence = licence_text(
        archive_manifest.get("license", archive_manifest.get("licenses")),
    )
    for key in totals:
        totals[key] += archive[key]
    if totals["compressed_bytes"] > adm.MAX_TOTAL_COMPRESSED_BYTES:
        _bundle_refuse("npm_archive_refused", "archive_size", subject, "total_compressed")
    if totals["unpacked_bytes"] > adm.MAX_TOTAL_UNPACKED_BYTES:
        _bundle_refuse("npm_archive_refused", "archive_size", subject, "total_unpacked")
    if totals["file_count"] > adm.MAX_ARCHIVE_FILES:
        _bundle_refuse("npm_archive_refused", "archive_count", subject, "total_files")
    package = _entry_evidence(
        path, entry, manifest, published, archive, archive_licence,
        hashlib.sha1(data).hexdigest(), plan, now, name in plan["direct"],
    )
    identity = {
        "path": path, "name": name, "version": version,
        "integrity": entry["integrity"], "sha256": archive["sha256"],
    }
    return package, identity


def _is_total_stop(detail):
    """Whether a detail is an archive running-total refusal: an archive_size or archive_count head
    whose last subject segment starts with total_."""
    if type(detail) is not str:
        return False
    segments = detail.split(" ", 1)[0].split(":")
    return len(segments) > 1 and segments[0] in TOTAL_STOP_HEADS and segments[-1].startswith("total_")


def _continues_after(error):
    """Whether the per-package loop may look at the next package after this refusal. A refusal
    that comes from the run deadline, the network or the environment, or from a running total,
    ends the loop at once."""
    if error.reason in STOP_REFUSAL_REASONS:
        return False
    return not _is_total_stop(error.detail)


def _record_refusal(refusals, error):
    """Remember a per-package refusal and say whether the loop continues. The list holds the
    first refusal and then up to nineteen more with distinct details, nothing else."""
    if not refusals:
        refusals.append(error)
    elif (error.detail is not None and len(refusals) < MAX_COLLECTED_REFUSALS
            and all(item.detail != error.detail for item in refusals)):
        refusals.append(error)
    return _continues_after(error) and len(refusals) < MAX_COLLECTED_REFUSALS


def _raise_first_refusal(refusals):
    first = refusals[0]
    if first.detail is not None:
        merged = [first.detail]
        for item in refusals:
            carried = getattr(item, "details", ())
            carried = tuple(carried) if type(carried) in (tuple, list) else ()
            for detail in (getattr(item, "detail", None),) + carried:
                if (detail is not None and len(merged) < MAX_COLLECTED_REFUSALS
                        and detail not in merged):
                    merged.append(detail)
        first.details = tuple(merged)
    raise first


def collect_evidence(lock, entries, plan, *, run_id, run_attempt, now, expiry, fetcher,
                     clock=None, node_version=NODE_VERSION, npm_version=NPM_VERSION):
    """Fetch metadata, archives and advisories; return the evidence record and archive identities."""
    _check_run(run_id, run_attempt)
    _check_times(now, expiry)
    check_policy_time(plan, now)
    if fetcher is None or not all(
        callable(getattr(fetcher, method, None)) for method in ("packument", "tarball", "advisories")
    ):
        _bundle_refuse("npm_input_invalid", "bundle_input", "bundle", "fetcher")
    peer_summary = check_peers(lock, entries)
    identities = []
    packages = []
    totals = {"compressed_bytes": 0, "unpacked_bytes": 0, "file_count": 0}
    matched_rows = set()
    groups = _by_name(entries)
    refusals = []
    after_refusal = 0
    for name in sorted(groups):
        if refusals and after_refusal >= MAX_PACKAGES_AFTER_REFUSAL:
            _raise_first_refusal(refusals)
        packument_cache = {}
        try:
            packument = fetcher.packument(name)
            if type(packument) is not bytes:
                _bundle_refuse(
                    "npm_evidence_invalid", "evidence", adm.package_subject(name),
                    "packument_type",
                )
        except BootstrapRefusal as error:
            if _record_refusal(refusals, error):
                continue
            _raise_first_refusal(refusals)
        except Exception:
            if refusals:
                _raise_first_refusal(refusals)
            raise
        for path, entry in groups[name]:
            if refusals:
                if after_refusal >= MAX_PACKAGES_AFTER_REFUSAL:
                    _raise_first_refusal(refusals)
                after_refusal += 1
            try:
                package, identity = _collect_entry(
                    path, entry, name, packument, plan, fetcher, now, totals, packument_cache,
                )
            except BootstrapRefusal as error:
                if error.detail is None:
                    error = BootstrapRefusal(error.reason, bundle_detail(
                        "package_step", adm.package_subject(name, entry["version"]),
                        adm.detail_text(error.reason, 40),
                    ))
                if _record_refusal(refusals, error):
                    continue
                _raise_first_refusal(refusals)
            except Exception:
                if refusals:
                    _raise_first_refusal(refusals)
                raise
            packages.append(package)
            if (name, entry["version"]) in plan["rows"]:
                matched_rows.add((name, entry["version"]))
            identities.append(identity)
    if refusals:
        _raise_first_refusal(refusals)
    if set(plan["rows"]) != matched_rows:
        _bundle_refuse(
            "npm_request_mismatch", "request_mismatch", "bundle", "unmatched_rows",
            fields=(("count", len(set(plan["rows"]) - matched_rows)),),
        )
    identities.sort(key=_path_key)
    packages.sort(key=_path_key)
    inventory = _advisory_body(entries)
    request_body = _canonical(inventory, "npm_advisory_invalid")
    response_bytes = fetcher.advisories(request_body)
    if type(response_bytes) is not bytes:
        _bundle_refuse("npm_advisory_invalid", "advisory_invalid", "advisories", "response_type")
    check_elections_used(plan, packages)
    fetched_at = int((clock if clock is not None else time.time)())
    if fetched_at < now - CLOCK_SKEW_SECONDS:
        _bundle_refuse("npm_stale", "stale", "bundle", "advisory_clock")
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
        _bundle_refuse("npm_evidence_invalid", "evidence", "bundle", "record_type")
    bound = dict(record)
    bound["receipt_sha256"] = _sha256(receipt_bytes)
    bound["lock_sha256"] = _sha256(lock_bytes)
    encoded = _canonical(bound, "npm_evidence_invalid")
    if len(encoded) > MAX_EVIDENCE_BYTES:
        _bundle_refuse("npm_payload_too_large", "payload_size", "bundle", "evidence")
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
