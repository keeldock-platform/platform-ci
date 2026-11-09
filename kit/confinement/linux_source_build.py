import base64
import hashlib
import hmac
import json
import os
import posixpath
import re
import shlex
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from pathlib import Path

import cargo_lock_bootstrap
import gate_table
import linux_harness
import linux_channels
import linux_probes
import linux_session


REPOSITORY = "keeldock-platform/platform-ci"
WORKFLOW_PATH = ".github/workflows/linux-source-admission.yml"
TIERS = {
    "admission": ("linux-source-admission.yml", "Linux admission source "),
    "quick": ("core-linux-quick-return.yml", "Linux quick source "),
}
LINUX_SOURCE_PREFIX = "LINUX_SOURCE"
WINDOWS_SOURCE_PREFIX = "WINDOWS_SOURCE"
SOURCE_PREFIXES = (LINUX_SOURCE_PREFIX, WINDOWS_SOURCE_PREFIX)
WINDOWS_TIER = ("windows-source-admission.yml", "Windows admission source ")
API_ROOT = "https://api.github.com"
API_VERSION = "2022-11-28"
TOOLCHAIN_ROOT = Path("/tmp/kd-toolchains")
PROJECT_ROOT = Path("/tmp/kd-project-worker")
NODE_VERSION = "24.22.1"
NPM_VERSION = "11.19.1"
NODE_LINUX_TARBALL_SHA256 = "6c172a9ab6718f7b801fb5a7bd486af2ee5e32758086a04b84fcce2aa77095e6"
BROWSER_FLAG_ENV = "KD_BROWSER_TIER"
BROWSER_ROOT_ENV = "BROWSER_ROOT"
BROWSER_ROOT_NAME = "browsers"
PLAYWRIGHT_VERSION = "1.64.1"
BROWSER_REVISION = "1248"
BROWSER_VERSION = "156.0.8078.4"
BROWSER_ARCHIVE_URL = (
    "https://storage.googleapis.com/chrome-for-testing-public/" + BROWSER_VERSION
    + "/linux64/chrome-headless-shell-linux64.zip"
)
BROWSER_ARCHIVE_SHA256 = "c3e50596aef52c58f8fda3c6b3411c33d34c88b177b3ed1c2243359fd3b8ba20"
BROWSER_ARCHIVE_MAX_BYTES = 192 * 1024 * 1024
BROWSER_UNPACKED_MAX_BYTES = 512 * 1024 * 1024
BROWSER_MAX_MEMBERS = 1024
BROWSER_DIRECTORY = "chromium_headless_shell-" + BROWSER_REVISION
BROWSER_PACKAGE_DIRECTORY = "chrome-headless-shell-linux64"
BROWSER_EXECUTABLE = "chrome-headless-shell"
BROWSER_MARKER = "INSTALLATION_COMPLETE"
BROWSER_APT_PACKAGES = (
    "fonts-liberation", "libasound2t64", "libatk-bridge2.0-0t64", "libatk1.0-0t64",
    "libatspi2.0-0t64", "libcairo2", "libcups2t64", "libdbus-1-3", "libdrm2", "libfontconfig1",
    "libfreetype6", "libgbm1", "libglib2.0-0t64", "libnspr4", "libnss3", "libpango-1.0-0",
    "libx11-6", "libxcb1", "libxcomposite1", "libxdamage1", "libxext6", "libxfixes3",
    "libxkbcommon0", "libxrandr2",
)
BROWSER_APT_COMMAND = (
    "/usr/bin/sudo", "-n", "/usr/bin/env", "DEBIAN_FRONTEND=noninteractive", "/usr/bin/apt-get",
    "-o", "Acquire::Retries=3",
)
BROWSER_APT_TIMEOUT_SECONDS = 900
BROWSER_WORKSPACE_PATHS = ("packages", "packages/kernel-ui-kit", "packages/kernel-ui-kit/package.json")
SYNTHETIC_LOG_CANARY = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
SOURCE_SHA_RE = re.compile(r"[a-f0-9]{40}\Z")
HEX64_RE = re.compile(r"[a-f0-9]{64}\Z")
RUST_CACHE_SCOPE_RE = re.compile(
    r"(?:rust|runtime-workspace|linux-source-admission|linux-source-verifier|linux-quick-return)\Z"
)
RUST_CACHE_OS_RE = re.compile(r"[A-Za-z0-9._-]{1,32}\Z")
RUST_CACHE_ARCHIVE_NAME = "rust-cache.tar"
RUST_CACHE_ARCHIVE_MAX_BYTES = 9 * 1024 * 1024 * 1024
RUST_CACHE_ENCRYPTED_OVERHEAD_MAX_BYTES = 1024 * 1024
RUST_CACHE_CORE_REPOSITORY = ("Moh-Bakr/" + "keeldock" + "-core")
RUST_CACHE_ENCRYPTION_KEY_RE = re.compile(r"[A-Za-z0-9+/]{42,44}={0,2}\Z")
RUST_CACHE_REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}\Z")
RUST_CACHE_TRUST_CLASSES = ("primary", "independent-verifier", "untrusted")
RUST_CACHE_KEY_RE = re.compile(
    r"kd-rust-v5-(?:Linux|macOS|Windows)-(?:x64|arm64)-"
    r"(?:rust|runtime-workspace|linux-source-admission|linux-source-verifier|linux-quick-return)-"
    r"(?:primary|independent-verifier|untrusted)-[a-f0-9]{40}-[a-f0-9]{40}-"
    r"[a-f0-9]{64}-[a-f0-9]{64}-[a-f0-9]{64}\Z"
)
RUST_CACHE_PRIMARY_REPOSITORY = REPOSITORY
IMAGE_RE = re.compile(r"[A-Za-z0-9._-]{1,64}\Z")
FINGERPRINT_RE = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
OWNER_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}\Z")
API_PATH_RE = re.compile(r"/[A-Za-z0-9._~/?&=-]*\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
SOURCE_TOKEN_RE = re.compile(r"[\x21\x23-\x2b\x2d-\x39\x3b-\x7e]{20,4096}\Z")
HEADER_TOKEN_RE = re.compile(r"[!-~]{1,4096}\Z")
LENGTH_BUCKETS = ((0, "0"), (19, "1-19"), (255, "20-255"), (1024, "256-1024"), (4096, "1025-4096"))
TOKEN_CLASS_NAMES = ("letters", "digits", "underscore", "dash", "dot", "other")
ENVIRONMENT_NAME = "linux-source-read"
ENVIRONMENT_BRANCHES = ("main", "untrusted")
ENVIRONMENT_ID_NAME = "LINUX_SOURCE_ENVIRONMENT_ID"
ENVIRONMENT_BRANCH_POLICY_ID_NAMES = {
    "main": "LINUX_SOURCE_MAIN_BRANCH_POLICY_ID",
    "untrusted": "LINUX_SOURCE_UNTRUSTED_BRANCH_POLICY_ID",
}
SOURCE_IDENTITY_NAMES = (
    "SOURCE_REPOSITORY_ID", "SOURCE_REPOSITORY_OWNER", "SOURCE_REPOSITORY_NAME",
    "SOURCE_READER_INSTALLATION_ID", "SOURCE_READER_CLIENT_ID",
)
SOURCE_HELD_NAMES = SOURCE_IDENTITY_NAMES + ("SOURCE_READER_PRIVATE_KEY", "SOURCE_READER_TOKEN")
GATES = gate_table.GATES
API_FEATURE_GATE_NAMES = gate_table.API_FEATURE_GATE_NAMES
RUNTIME_GATE_NAMES = gate_table.RUNTIME_GATE_NAMES
BROWSER_GATE_NAMES = gate_table.BROWSER_GATE_NAMES
RUNTIME_ROOT_FILES = gate_table.RUNTIME_ROOT_FILES
MAX_LOCK_DIRECTORIES = 100000
MAX_CARGO_LOCK_BYTES = 4 * 1024 * 1024
MAX_DIRECTORY_ENTRIES = 8192
MAX_TREE_ENTRIES = 1000000
MAX_PENDING_DIRECTORIES = 8192
RUST_COMPONENTS = (
    ("rust-std", "https://static.rust-lang.org/dist/2026-10-15/rust-std-1.99.1-x86_64-unknown-linux-gnu.tar.gz", "d1290c05994a59c029e562cb75be1bddc6fb11a4c501e1b7b0f61d119c6cbb12"),
    ("rustc", "https://static.rust-lang.org/dist/2026-10-15/rustc-1.99.1-x86_64-unknown-linux-gnu.tar.gz", "85e7c0e6f21636f714e2a42966011364a6cc56b6548126d32144d6ba90904966"),
    ("cargo", "https://static.rust-lang.org/dist/2026-10-15/cargo-1.99.1-x86_64-unknown-linux-gnu.tar.gz", "47babc028247e26577f8a1bf390b11f447ad9b7ab93f5c9a0dda078935fc149b"),
    ("rustfmt-preview", "https://static.rust-lang.org/dist/2026-10-15/rustfmt-1.99.1-x86_64-unknown-linux-gnu.tar.gz", "e3a88008061f485126fe24569c4d3e5a0f49462a06ee6339920f8f202124b13a"),
    ("clippy-preview", "https://static.rust-lang.org/dist/2026-10-15/clippy-1.99.1-x86_64-unknown-linux-gnu.tar.gz", "3c6d008544b6e456cc785c86f8ce3713f0d845b94be3a6c8a34662b8504561b5"),
)
NPM_USER_CONFIG_NAME = "user.npmrc"
NPM_GLOBAL_CONFIG_NAME = "global.npmrc"
GATE_CONFIG_UID = 0
GATE_CONFIG_GID = 0
MANIFEST_WORKSPACE_PATHS = gate_table.MANIFEST_WORKSPACE_PATHS
MANIFEST_GROUPS = gate_table.MANIFEST_GROUPS
MANIFEST_PACKAGE_RE = gate_table.MANIFEST_PACKAGE_RE
MANIFEST_VERSION_RE = gate_table.MANIFEST_VERSION_RE
MANIFEST_WORKSPACE_VERSION_RE = gate_table.MANIFEST_WORKSPACE_VERSION_RE
MAX_PACKAGE_JSON_BYTES = gate_table.MAX_PACKAGE_JSON_BYTES
SOURCE_STEP_NAMES = (
    "Fetch exact public control",
    "Repeat preflight in source-read",
    "Record image and fetch pinned Rust and Node toolchains",
    "Harden runner paths before the proof",
    "Boundary self-test before source-reader mint",
    "Mint scoped source-reader token",
    "Verify selected installation identity",
    "Fetch exact source and verify binding, tree, signatures and committed locks",
    "Revoke source-reader token and verify rejection",
    "Derive Rust cache key",
    "Prepare runner-local Rust cache staging",
    "Restore exact Rust build cache",
    "Import validated Rust build cache",
    "Fetch Rust dependencies from the committed lockfiles",
    "Fetch npm tarballs by committed lock integrity",
    "Prepare offline project inputs",
    "Re-run positive controls immediately before the first project command",
    "Run all offline project gates",
    "Merge confinement phase records",
    "Export validated Rust build cache after confined work",
    "Package the Rust build cache",
    "Save the exact Rust build cache",
    "Forced faults must fail closed",
)
VERDICT_STEP_NAMES = (
    "Fetch exact public control",
    "Repeat independent preflight",
    "Record verifier image and fetch pinned toolchains",
    "Harden verifier runner paths",
    "Run independent boundary self-test",
    "Mint verifier scoped source-reader token",
    "Verify source independently against binding, tree, signatures and lock",
    "Revoke verifier token and verify rejection",
    "Derive independent verifier Rust cache key",
    "Prepare independent verifier Rust cache staging",
    "Restore the independent verifier Rust build cache",
    "Import the independent verifier Rust cache",
    "Fetch verifier Rust dependencies from committed lockfiles",
    "Fetch independent npm tarballs by lock integrity",
    "Prepare independent offline project inputs",
    "Re-run independent positive controls before project execution",
    "Run independent offline project gates",
    "Merge independent confinement records",
    "Export the independent verifier Rust cache after confined work",
    "Package the independent verifier Rust cache",
    "Save the independent verifier Rust cache",
    "Verify unprivileged proof handoff",
    "Publish confinement verdict",
)
OPTIONAL_VERDICT_SYNTHETIC_STEPS = (
    "Mint verifier scoped source-reader token",
    "Verify source independently against binding, tree, signatures and lock",
    "Revoke verifier token and verify rejection",
    "Derive independent verifier Rust cache key",
    "Prepare independent verifier Rust cache staging",
    "Restore the independent verifier Rust build cache",
    "Import the independent verifier Rust cache",
    "Fetch verifier Rust dependencies from committed lockfiles",
    "Fetch independent npm tarballs by lock integrity",
    "Prepare independent offline project inputs",
    "Run independent offline project gates",
    "Export the independent verifier Rust cache after confined work",
    "Package the independent verifier Rust cache",
    "Save the independent verifier Rust cache",
)
CACHE_VERDICT_STEPS = (
    "Derive independent verifier Rust cache key",
    "Prepare independent verifier Rust cache staging",
    "Restore the independent verifier Rust build cache",
    "Import the independent verifier Rust cache",
    "Export the independent verifier Rust cache after confined work",
    "Package the independent verifier Rust cache",
    "Save the independent verifier Rust cache",
)
SETTINGS_STEP_NAMES = (
    "Fetch exact public control",
    "Prepare audit identity",
    "Snapshot cache inventory and validate preflight",
)
UNIT_STEP_NAMES = (
    "Fetch exact public control",
    "Run unprivileged source-free checks",
)
QUICK_WORKFLOW_PATH = ".github/workflows/core-linux-quick-return.yml"
QUICK_JOB_PREFIX = "core-linux-quick-return"
QUICK_SETTINGS_STEP_NAMES = (
    "Set up job",
    "Fetch exact public control",
    "Validate quick request and binding",
    "Snapshot cache inventory and validate preflight",
    "Complete job",
)
QUICK_UNIT_STEP_NAMES = (
    "Set up job",
    "Fetch exact public control",
    "Run unprivileged source-free checks",
    "Complete job",
)
QUICK_PRODUCER_STEP_NAMES = (
    "Set up job",
    "Fetch exact public control",
    "Repeat quick preflight before source read",
    "Record image and fetch pinned Rust and Node toolchains",
    "Harden runner paths before the proof",
    "Boundary self-test before source-reader mint",
    "Mint scoped source-reader token",
    "Verify selected installation identity",
    "Fetch exact source and verify binding, tree, signatures and committed locks",
    "Revoke source-reader token and verify rejection",
    "Fetch Rust dependencies from the committed lockfiles",
    "Fetch npm tarballs by committed lock integrity",
    "Prepare offline project inputs",
    "Re-run positive controls immediately before the first project command",
    "Run all offline project gates",
    "Merge confinement phase records",
    "Encrypt bounded quick return",
    "Upload the single encrypted member",
    "Record quick return counts",
    "Remove staged ciphertext",
    "Post Mint scoped source-reader token",
    "Complete job",
)
OPTIONAL_SOURCE_STEPS = frozenset((
    "Mint scoped source-reader token",
    "Verify selected installation identity",
    "Fetch exact source and verify binding, tree, signatures and committed locks",
    "Revoke source-reader token and verify rejection",
    "Derive Rust cache key",
    "Prepare runner-local Rust cache staging",
    "Restore exact Rust build cache",
    "Import validated Rust build cache",
    "Fetch Rust dependencies from the committed lockfiles",
    "Fetch npm tarballs by committed lock integrity",
    "Prepare offline project inputs",
    "Run all offline project gates",
    "Export validated Rust build cache after confined work",
    "Package the Rust build cache",
    "Save the exact Rust build cache",
    "Forced faults must fail closed",
))
CACHE_SOURCE_STEPS = (
    "Derive Rust cache key",
    "Prepare runner-local Rust cache staging",
    "Restore exact Rust build cache",
    "Import validated Rust build cache",
    "Export validated Rust build cache after confined work",
    "Package the Rust build cache",
    "Save the exact Rust build cache",
)


class SourceBuildRefusal(Exception):
    def __init__(self, reason="invalid"):
        self.reason = reason if reason in {
            "identity", "freshness", "untrusted", "source", "binding", "duplicate",
            "cache", "toolchain", "hash_mismatch", "token", "checkout", "signature",
            "revocation", "lock", "registry", "network", "gate", "boundary", "audit",
        } else "invalid"
        super().__init__(self.reason)


def _refusal_line(command, error):
    line = "linux-source-build=refused phase=" + command + " reason=" + error.reason
    return line + "\n"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _safe_api_path(path):
    if type(path) is not str or API_PATH_RE.fullmatch(path) is None or path.count("?") > 1:
        return False
    parts = path[1:].split("?", 1)[0].split("/")
    return all(part not in ("", ".", "..") for part in parts)


def _api_request(path, token, method="GET", payload=None, expected=(200,)):
    if not _safe_api_path(path):
        raise SourceBuildRefusal("network")
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": "Bearer " + token,
        "User-Agent": "kd-linux-source-read",
        "X-GitHub-Api-Version": API_VERSION,
    }
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if data is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(API_ROOT + path, data=data, headers=headers, method=method)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    try:
        with opener.open(request, timeout=20) as response:
            status = response.status
            body = response.read(8 * 1024 * 1024 + 1)
    except urllib.error.HTTPError as error:
        status = error.code
        body = b""
    except (OSError, urllib.error.URLError):
        raise SourceBuildRefusal("network") from None
    if status not in expected or len(body) > 8 * 1024 * 1024:
        raise SourceBuildRefusal("network")
    if status in (204, 401, 403):
        return status, None
    try:
        value = json.loads(body.decode("utf-8")) if body else None
    except (UnicodeError, ValueError):
        raise SourceBuildRefusal("network") from None
    return status, value


def _verify_reusable_dependency_caller(token, repository, source_sha, control_sha):
    if (type(repository) is not str or repository.casefold() != RUST_CACHE_CORE_REPOSITORY.casefold()
            or SOURCE_SHA_RE.fullmatch(source_sha) is None
            or SOURCE_SHA_RE.fullmatch(control_sha) is None):
        raise SourceBuildRefusal("identity")
    path = (
        "/repos/" + repository + "/contents/.github/workflows/dependency-checks.yml?ref="
        + urllib.parse.quote(source_sha, safe="")
    )
    unused_status, payload = _api_request(path, token)
    if (type(payload) is not dict or payload.get("path") != ".github/workflows/dependency-checks.yml"
            or payload.get("encoding") != "base64" or type(payload.get("content")) is not str
            or len(payload["content"]) > 180000):
        raise SourceBuildRefusal("identity")
    compact = re.sub(r"\s", "", payload["content"])
    if re.fullmatch(r"[A-Za-z0-9+/]*={0,2}", compact) is None:
        raise SourceBuildRefusal("identity")
    try:
        content = base64.b64decode(compact, validate=True).decode("utf-8")
    except (ValueError, UnicodeError):
        raise SourceBuildRefusal("identity") from None
    workflow_pins = re.findall(
        r"(?m)^\s*uses:\s*keeldock-platform/platform-ci/\.github/workflows/"
        r"core-dependency-checks\.yml@([a-f0-9]{40})\s*$", content,
    )
    control_pins = re.findall(r"(?m)^\s*control_sha:\s*([a-f0-9]{40})\s*$", content)
    if (workflow_pins != [control_sha] or control_pins != [control_sha]
            or content.count("source_sha: ${{ github.sha }}") != 1
            or content.count("secrets: inherit") != 1):
        raise SourceBuildRefusal("identity")
    return True


def _reference_sha(token, repository, branch):
    status, payload = _api_request(
        "/repos/" + repository + "/git/ref/heads/" + urllib.parse.quote(branch, safe="/"), token,
        expected=(200, 404),
    )
    if status == 404:
        return None
    target = payload.get("object") if type(payload) is dict else None
    sha = target.get("sha") if type(target) is dict else None
    if type(sha) is not str or SOURCE_SHA_RE.fullmatch(sha) is None:
        raise SourceBuildRefusal("network")
    return sha


def _comparison(token, repository, base, head):
    if (type(base) is not str or SOURCE_SHA_RE.fullmatch(base) is None
            or type(head) is not str or SOURCE_SHA_RE.fullmatch(head) is None):
        raise SourceBuildRefusal("binding")
    status, payload = _api_request(
        "/repos/" + repository + "/compare/" + base + "..." + head, token,
        expected=(200, 404),
    )
    if status == 404 or type(payload) is not dict:
        return "unavailable"
    state = payload.get("status")
    return state if state in ("ahead", "behind", "identical", "diverged") else "unavailable"


def _environment_prefix(environ):
    value = environ.get("KD_SOURCE_PREFIX", LINUX_SOURCE_PREFIX)
    if type(value) is not str or value not in SOURCE_PREFIXES:
        raise SourceBuildRefusal("binding")
    return value


def _request_binding(environ, prefix):
    """Check the dispatch request against the reviewed allow-list variables only.

    It reads no source repository identity, reader identity or secret, so the environment-free
    Windows settings job can run it; the full binding is _source_inputs."""
    if type(prefix) is not str or prefix not in SOURCE_PREFIXES:
        raise SourceBuildRefusal("binding")
    source_sha = environ.get("REQUESTED_SOURCE_SHA", "")
    base_sha = environ.get("REQUESTED_BASE_SHA", "")
    base_branch = environ.get("REQUESTED_BASE_BRANCH", "")
    fingerprint = environ.get("REQUESTED_FINGERPRINT", "")
    control_sha = environ.get("CI_SHA", "")
    if (SOURCE_SHA_RE.fullmatch(source_sha) is None or SOURCE_SHA_RE.fullmatch(base_sha) is None
            or base_branch not in ("main", "develop", "uat")
            or HEX64_RE.fullmatch(fingerprint) is None or SOURCE_SHA_RE.fullmatch(control_sha) is None):
        raise SourceBuildRefusal("binding")
    values = {
        prefix + "_ALLOWED_SHA": source_sha,
        prefix + "_ALLOWED_BASE_SHA": base_sha,
        prefix + "_ALLOWED_BASE_BRANCH": base_branch,
        prefix + "_ALLOWED_FINGERPRINT": fingerprint,
        prefix + "_ALLOWED_CONTROL_SHA": control_sha,
    }
    if any(environ.get(name) != value for name, value in values.items()):
        raise SourceBuildRefusal("binding")
    if not environ.get(prefix + "_ENVIRONMENT_NAME"):
        raise SourceBuildRefusal("binding")
    if (environ.get("REQUESTED_ENVIRONMENT_NAME") != environ[prefix + "_ENVIRONMENT_NAME"]
            or environ[prefix + "_ENVIRONMENT_NAME"] != ENVIRONMENT_NAME):
        raise SourceBuildRefusal("binding")
    return {
        "source_sha": source_sha,
        "base_sha": base_sha,
        "base_branch": base_branch,
        "reviewed_diff_sha256": fingerprint,
        "control_sha": control_sha,
    }


def _settings_binding(environ, prefix):
    """Bind a Windows settings dispatch without the source identity.

    The settings job has no environment, so it must hold no source repository identity, reader
    identity, reader key or reader token; any such name in its environment is refused. The
    source-read fetch job repeats the full _source_inputs binding before any token is minted."""
    if prefix != WINDOWS_SOURCE_PREFIX:
        raise SourceBuildRefusal("binding")
    if any(name in environ for name in SOURCE_HELD_NAMES):
        raise SourceBuildRefusal("binding")
    return _request_binding(environ, prefix)


def _source_inputs(environ, prefix=None):
    if prefix is None:
        prefix = _environment_prefix(environ)
    identity = _request_binding(environ, prefix)
    for name in SOURCE_IDENTITY_NAMES:
        if not environ.get(name):
            raise SourceBuildRefusal("binding")
    if (DECIMAL_RE.fullmatch(environ["SOURCE_REPOSITORY_ID"]) is None
            or DECIMAL_RE.fullmatch(environ["SOURCE_READER_INSTALLATION_ID"]) is None
            or not OWNER_RE.fullmatch(environ["SOURCE_REPOSITORY_OWNER"])
            or not OWNER_RE.fullmatch(environ["SOURCE_REPOSITORY_NAME"])):
        raise SourceBuildRefusal("binding")
    identity["repository_id"] = environ["SOURCE_REPOSITORY_ID"]
    identity["owner"] = environ["SOURCE_REPOSITORY_OWNER"]
    identity["name"] = environ["SOURCE_REPOSITORY_NAME"]
    return identity


def _environment_id(environ, variable):
    value = environ.get(variable)
    if type(value) is not str or DECIMAL_RE.fullmatch(value) is None:
        raise SourceBuildRefusal("binding")
    return int(value)


def _verify_environment(token, name=ENVIRONMENT_NAME, environ=None):
    if name != ENVIRONMENT_NAME:
        raise SourceBuildRefusal("binding")
    env = os.environ if environ is None else environ
    expected_environment_id = _environment_id(env, ENVIRONMENT_ID_NAME)
    expected_policy_ids = {
        branch: _environment_id(env, variable)
        for branch, variable in ENVIRONMENT_BRANCH_POLICY_ID_NAMES.items()
    }
    path = "/repos/" + REPOSITORY + "/environments/" + name
    status, environment = _api_request(path, token, expected=(200, 404))
    policy = environment.get("deployment_branch_policy") if type(environment) is dict else None
    if (status != 200 or type(environment) is not dict
            or type(environment.get("id")) is not int
            or environment.get("id") != expected_environment_id
            or environment.get("name") != name
            or environment.get("can_admins_bypass") is not False
            or type(policy) is not dict
            or policy.get("custom_branch_policies") is not True
            or policy.get("protected_branches") is not False):
        raise SourceBuildRefusal("binding")
    status, listing = _api_request(path + "/deployment-branch-policies?per_page=100", token)
    entries = listing.get("branch_policies") if type(listing) is dict else None
    if (type(entries) is not list or len(entries) > 100
            or type(listing.get("total_count")) is not int or listing["total_count"] != len(entries)):
        raise SourceBuildRefusal("binding")
    names = []
    policy_ids = {}
    for entry in entries:
        if (type(entry) is not dict or entry.get("type") != "branch"
                or type(entry.get("name")) is not str
                or type(entry.get("id")) is not int
                or entry["id"] < 1):
            raise SourceBuildRefusal("binding")
        names.append(entry["name"])
        policy_ids[entry["name"]] = entry["id"]
    if (sorted(names) != sorted(ENVIRONMENT_BRANCHES)
            or policy_ids != expected_policy_ids):
        raise SourceBuildRefusal("binding")


def _untrusted_core_pull_request(env):
    repository = env.get("CI_REPOSITORY", "")
    event = env.get("CI_EVENT_NAME", "")
    ref = env.get("CI_REF", "")
    base_ref = env.get("CI_BASE_REF", "")
    return (
        type(repository) is str
        and repository.casefold() == RUST_CACHE_CORE_REPOSITORY.casefold()
        and event == "pull_request"
        and base_ref in ("develop", "uat", "main")
        and re.fullmatch(r"refs/pull/[1-9][0-9]{0,18}/merge", ref) is not None
    )


def _source_reader_caller_allowed(env):
    repository = env.get("CI_REPOSITORY", "")
    event = env.get("CI_EVENT_NAME", "")
    ref = env.get("CI_REF", "")
    base_ref = env.get("CI_BASE_REF", "")
    if type(repository) is not str or type(event) is not str or type(ref) is not str:
        return False
    if repository.casefold() == REPOSITORY.casefold():
        return event == "workflow_dispatch" and ref in (
            "refs/heads/main", "refs/heads/untrusted",
        )
    if repository.casefold() != RUST_CACHE_CORE_REPOSITORY.casefold():
        return False
    if event == "push":
        return ref in (
            "refs/heads/develop", "refs/heads/uat", "refs/heads/main",
        ) and base_ref == ""
    if event == "pull_request":
        return _untrusted_core_pull_request(env)
    return False


def _tier(environ):
    tier = environ.get("KD_LINUX_TIER", "admission")
    if type(tier) is not str or tier not in TIERS:
        raise SourceBuildRefusal("identity")
    return tier


def _rust_cache_identity(env):
    repository = env.get("CI_REPOSITORY", "")
    repository_id = env.get("SOURCE_REPOSITORY_ID", "")
    source_sha = env.get("REQUESTED_SOURCE_SHA", "")
    control_sha = env.get("CONTROL_SHA", "")
    ci_sha = env.get("CI_SHA", "")
    trust_class = env.get("RUST_CACHE_TRUST_CLASS", "")
    if (type(repository) is not str or RUST_CACHE_REPOSITORY_RE.fullmatch(repository) is None
            or type(repository_id) is not str or DECIMAL_RE.fullmatch(repository_id) is None
            or type(source_sha) is not str or SOURCE_SHA_RE.fullmatch(source_sha) is None
            or type(control_sha) is not str or SOURCE_SHA_RE.fullmatch(control_sha) is None
            or type(ci_sha) is not str or SOURCE_SHA_RE.fullmatch(ci_sha) is None
            or trust_class not in RUST_CACHE_TRUST_CLASSES):
        raise SourceBuildRefusal("cache")
    return {
        "repository": repository,
        "repository_id": repository_id,
        "trust_class": trust_class,
        "source_sha": source_sha,
        "control_sha": control_sha,
    }


def _rust_cache_key(source, runner_os, scope, *, repository, repository_id, trust_class, source_sha, control_sha):
    if (type(runner_os) is not str or RUST_CACHE_OS_RE.fullmatch(runner_os) is None
            or type(scope) is not str or RUST_CACHE_SCOPE_RE.fullmatch(scope) is None):
        raise SourceBuildRefusal("cache")
    if (type(repository) is not str or RUST_CACHE_REPOSITORY_RE.fullmatch(repository) is None
            or type(repository_id) is not str or DECIMAL_RE.fullmatch(repository_id) is None
            or trust_class not in RUST_CACHE_TRUST_CLASSES
            or type(source_sha) is not str or SOURCE_SHA_RE.fullmatch(source_sha) is None
            or type(control_sha) is not str or SOURCE_SHA_RE.fullmatch(control_sha) is None):
        raise SourceBuildRefusal("cache")
    os_name, separator, architecture = runner_os.partition("-")
    if (separator != "-" or os_name not in ("Linux", "macOS", "Windows")
            or architecture.lower() not in ("x64", "arm64")):
        raise SourceBuildRefusal("cache")
    runner_key = os_name + "-" + architecture.lower()
    root = Path(source)
    toolchain = root / "rust-toolchain.toml"
    try:
        toolchain_info = toolchain.lstat()
        if not stat.S_ISREG(toolchain_info.st_mode) or toolchain_info.st_nlink != 1:
            raise SourceBuildRefusal("cache")
        toolchain_hash = hashlib.sha256(toolchain.read_bytes()).hexdigest()
        locks_hash = hashlib.sha256()
        lock_count = 0
        for relative in ("Cargo.lock", "fuzz/Cargo.lock", "runtime/Cargo.lock"):
            path = root / relative
            try:
                info = path.lstat()
            except FileNotFoundError:
                continue
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise SourceBuildRefusal("cache")
            content = path.read_bytes()
            locks_hash.update(relative.encode("ascii") + bytes((0,)) + content + bytes((0,)))
            lock_count += 1
        if lock_count == 0:
            raise SourceBuildRefusal("cache")
    except SourceBuildRefusal:
        raise
    except OSError:
        raise SourceBuildRefusal("cache") from None
    identity = {"repository": repository, "repository_id": repository_id, "trust_class": trust_class}
    identity_hash = hashlib.sha256(
        json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    return (
        "kd-rust-v5-" + runner_key + "-" + scope + "-" + trust_class + "-"
        + source_sha + "-" + control_sha + "-" + toolchain_hash + "-"
        + locks_hash.hexdigest() + "-" + identity_hash
    )

def _rust_cache_read_allowed(env):
    repository = env.get("CI_REPOSITORY", "")
    trust_class = env.get("RUST_CACHE_TRUST_CLASS", "")
    if (type(repository) is not str or RUST_CACHE_REPOSITORY_RE.fullmatch(repository) is None
            or trust_class not in RUST_CACHE_TRUST_CLASSES):
        return False
    event = env.get("CI_EVENT_NAME", "")
    ref = env.get("CI_REF", "")
    if event == "pull_request":
        return (trust_class in ("primary", "independent-verifier")
                and bool(re.fullmatch(r"refs/pull/[1-9][0-9]{0,18}/merge", ref)))
    if event == "push":
        if trust_class == "untrusted":
            return ref == "refs/heads/untrusted"
        return ref in ("refs/heads/develop", "refs/heads/uat", "refs/heads/main")
    if event == "workflow_dispatch":
        return ((ref == "refs/heads/main" and trust_class in ("primary", "independent-verifier"))
                or (ref == "refs/heads/untrusted" and trust_class == "untrusted"))
    return False


def _rust_cache_write_allowed(env):
    repository = env.get("CI_REPOSITORY", "")
    trust_class = env.get("RUST_CACHE_TRUST_CLASS", "")
    if (type(repository) is not str or RUST_CACHE_REPOSITORY_RE.fullmatch(repository) is None
            or trust_class not in ("primary", "independent-verifier")):
        return False
    return _rust_cache_write_context(env)


def _rust_cache_write_context(env):
    event = env.get("CI_EVENT_NAME", "")
    ref = env.get("CI_REF", "")
    return (
        (event == "push" and ref in ("refs/heads/develop", "refs/heads/uat", "refs/heads/main"))
        or (event == "workflow_dispatch" and ref == "refs/heads/main")
    )


def _rust_cache_requires_encryption(env):
    repository = env.get("CI_REPOSITORY", "")
    if type(repository) is not str or RUST_CACHE_REPOSITORY_RE.fullmatch(repository) is None:
        raise SourceBuildRefusal("cache")
    return repository.casefold() != RUST_CACHE_CORE_REPOSITORY.casefold()


def _rust_cache_encryption_key(env):
    value = env.get("KD_RUST_CACHE_ENCRYPTION_KEY_B64", "")
    if type(value) is not str or RUST_CACHE_ENCRYPTION_KEY_RE.fullmatch(value) is None:
        raise SourceBuildRefusal("cache")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, base64.binascii.Error):
        raise SourceBuildRefusal("cache") from None
    if len(decoded) != 32:
        raise SourceBuildRefusal("cache")
    return value


def _validate_rust_cache(env, source, expected_scope=None):
    mode = env.get("KD_RUST_CACHE_MODE", "none")
    if mode in ("", "none"):
        if any(env.get(name) for name in (
                "KD_RUST_CACHE_KEY", "KD_RUST_CACHE_DIR", "KD_RUST_CACHE_HIT", "RUST_CACHE_OS",
                "RUST_CACHE_SCOPE", "RUST_CACHE_TRUST_CLASS")):
            raise SourceBuildRefusal("cache")
        return None
    if mode != "read":
        raise SourceBuildRefusal("cache")
    key = env.get("KD_RUST_CACHE_KEY", "")
    cache_dir = env.get("KD_RUST_CACHE_DIR", "")
    runner_temp = env.get("RUNNER_TEMP", "")
    runner_os = env.get("RUST_CACHE_OS", "")
    scope = env.get("RUST_CACHE_SCOPE", "")
    hit = env.get("KD_RUST_CACHE_HIT", "")
    identity = _rust_cache_identity(env)
    if (RUST_CACHE_KEY_RE.fullmatch(key) is None or not Path(cache_dir).is_absolute()
            or not Path(runner_temp).is_absolute() or Path(cache_dir) != Path(runner_temp) / "kd-rust-cache"
            or hit not in ("true", "false")
            or not _rust_cache_read_allowed(env)
            or (expected_scope is not None and scope != expected_scope)
            or _rust_cache_key(source, runner_os, scope, **identity) != key):
        raise SourceBuildRefusal("cache")
    try:
        cache_info = Path(cache_dir).lstat()
        runner_uid = int(env.get("SUDO_UID", os.getuid())) if os.geteuid() == 0 else os.getuid()
        runner_gid = int(env.get("SUDO_GID", os.getgid())) if os.geteuid() == 0 else os.getgid()
        if (not stat.S_ISDIR(cache_info.st_mode)
                or (cache_info.st_uid, cache_info.st_gid) != (runner_uid, runner_gid)):
            raise SourceBuildRefusal("cache")
    except OSError:
        raise SourceBuildRefusal("cache") from None
    return {"directory": Path(cache_dir), "hit": hit == "true", "key": key}


def _optional_rust_cache(env, source, expected_scope=None):
    try:
        return _validate_rust_cache(env, source, expected_scope)
    except (SourceBuildRefusal, OSError, TypeError, ValueError):
        return None


def _discard_optional_cache_path(path):
    path = Path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return
    except OSError:
        raise SourceBuildRefusal("cache") from None
    try:
        if stat.S_ISDIR(info.st_mode):
            shutil.rmtree(path)
        else:
            path.unlink()
    except OSError:
        raise SourceBuildRefusal("cache") from None


def write_rust_cache_key(environ=None):
    env = os.environ if environ is None else environ
    try:
        if not _rust_cache_read_allowed(env):
            raise SourceBuildRefusal("cache")
        identity = _rust_cache_identity(env)
        key = _rust_cache_key(
            env.get("SOURCE_PATH", ""), env.get("RUST_CACHE_OS", ""),
            env.get("RUST_CACHE_SCOPE", ""), **identity,
        )
        output = env.get("GITHUB_OUTPUT")
        if not output:
            raise SourceBuildRefusal("cache")
        with open(output, "at", encoding="ascii") as sink:
            sink.write("cache_key=" + key + "\n")
        sys.stdout.write("linux-rust-cache-key=verified\n")
        return 0
    except SourceBuildRefusal as error:
        sys.stdout.write("linux-rust-cache-key=refused reason=" + error.reason + "\n")
        return 1
    except BaseException:
        sys.stdout.write("linux-rust-cache-key=refused reason=invalid\n")
        return 1


def validate_dispatch(environ, api_token=None, prefix=LINUX_SOURCE_PREFIX, source_identity=True):
    if type(prefix) is not str or prefix not in SOURCE_PREFIXES:
        raise SourceBuildRefusal("identity")
    windows = prefix == WINDOWS_SOURCE_PREFIX
    if windows and "KD_LINUX_TIER" in environ:
        raise SourceBuildRefusal("identity")
    if not windows and "KD_SOURCE_PREFIX" in environ:
        raise SourceBuildRefusal("identity")
    if source_identity is not True and source_identity is not False:
        raise SourceBuildRefusal("identity")
    if not source_identity and not windows:
        raise SourceBuildRefusal("identity")
    if not source_identity and any(name in environ for name in SOURCE_HELD_NAMES):
        raise SourceBuildRefusal("binding")
    tier = "admission" if windows else _tier(environ)
    if (environ.get("CI_EVENT_NAME") != "workflow_dispatch"
            or environ.get("CI_REPOSITORY") != REPOSITORY
            or environ.get("CI_SERVER_URL") != "https://github.com"
            or environ.get("CACHE_MODE") != "none"
            or environ.get("CI_SHA") != environ.get("GITHUB_SHA")):
        raise SourceBuildRefusal("identity")
    ref = environ.get("CI_REF", "")
    if ref not in ("refs/heads/main", "refs/heads/untrusted") or (tier == "quick" and ref != "refs/heads/untrusted"):
        raise SourceBuildRefusal("identity")
    if api_token is None:
        api_token = environ.get("GITHUB_TOKEN", "")
    if not api_token:
        raise SourceBuildRefusal("identity")
    live_main = _reference_sha(api_token, REPOSITORY, "main")
    live_untrusted = _reference_sha(api_token, REPOSITORY, "untrusted")
    if live_main is None:
        raise SourceBuildRefusal("freshness")
    if ref == "refs/heads/main" and live_main != environ.get("CI_SHA"):
        raise SourceBuildRefusal("freshness")
    if live_untrusted is None or _comparison(api_token, REPOSITORY, live_untrusted, live_main) not in ("ahead", "identical"):
        raise SourceBuildRefusal("untrusted")
    if ref == "refs/heads/untrusted" and live_untrusted != environ.get("CI_SHA"):
        raise SourceBuildRefusal("freshness")
    mode = environ.get("CI_MODE", "")
    if mode == "synthetic":
        if ref != "refs/heads/main" or tier == "quick":
            raise SourceBuildRefusal("identity")
        _verify_environment(api_token)
        return "synthetic"
    if mode != "source":
        raise SourceBuildRefusal("identity")
    if windows:
        if ref != "refs/heads/untrusted":
            raise SourceBuildRefusal("identity")
        if source_identity:
            _source_inputs(environ, prefix=prefix)
        else:
            _settings_binding(environ, prefix)
        _verify_environment(api_token)
        _require_no_duplicate(api_token, environ, workflow=WINDOWS_TIER)
        return "source"
    identity = _source_inputs(environ, prefix=LINUX_SOURCE_PREFIX)
    _verify_environment(api_token)
    _require_no_duplicate(api_token, environ)
    return "source"


def _require_no_duplicate(token, environ, workflow=None):
    run_id = environ.get("GITHUB_RUN_ID", "")
    source_sha = environ.get("REQUESTED_SOURCE_SHA", "")
    if workflow is not None and workflow != WINDOWS_TIER:
        raise SourceBuildRefusal("duplicate")
    workflow_file, title_prefix = TIERS[_tier(environ)] if workflow is None else workflow
    title = title_prefix + source_sha
    base = "/repos/" + REPOSITORY + "/actions/workflows/" + workflow_file + "/runs?per_page=100&status="
    for active_status in ("queued", "in_progress"):
        for attempt in range(3):
            status, payload = _api_request(base + active_status, token)
            runs = payload.get("workflow_runs") if type(payload) is dict else None
            if type(runs) is not list or len(runs) > 100 or type(payload.get("total_count")) is not int:
                raise SourceBuildRefusal("duplicate")
            for run in runs:
                if type(run) is not dict:
                    raise SourceBuildRefusal("duplicate")
                if (str(run.get("id")) != run_id and run.get("display_title") == title
                        and run.get("status") == active_status
                        and run.get("event") == "workflow_dispatch"):
                    raise SourceBuildRefusal("duplicate")
            if payload["total_count"] <= len(runs):
                break
            if attempt == 2:
                raise SourceBuildRefusal("duplicate")
            time.sleep(5)


def _audit_modules():
    try:
        import confinement_public_audit
        import confinement_verdict
        import log_canary
        from confinement_verdict import CHANNELS
    except ImportError:
        from . import confinement_public_audit, confinement_verdict, log_canary
        from .confinement_verdict import CHANNELS
    if tuple(linux_channels.CHANNELS) != tuple(CHANNELS):
        raise SourceBuildRefusal("boundary")
    return confinement_public_audit, confinement_verdict, log_canary


def _expected_quick_run(environ, cache_digest, cache_baseline=""):
    audit, unused_verdict, unused_canary = _audit_modules()
    request_id = environ.get("KD_QUICK_REQUEST_ID", "")
    source_sha = environ.get("REQUESTED_SOURCE_SHA", "")
    expected = {
        "repository": REPOSITORY,
        "os": "linux",
        "mode": "quick",
        "control_sha": environ.get("CI_SHA", "0" * 40),
        "run_id": int(environ.get("GITHUB_RUN_ID", "1")) if DECIMAL_RE.fullmatch(environ.get("GITHUB_RUN_ID", "")) else 1,
        "run_attempt": int(environ.get("GITHUB_RUN_ATTEMPT", "1")) if DECIMAL_RE.fullmatch(environ.get("GITHUB_RUN_ATTEMPT", "")) else 1,
        "workflow_path": QUICK_WORKFLOW_PATH,
        "ci_ref": "untrusted",
        "display_title": TIERS["quick"][1] + source_sha,
        "jobs": {
            QUICK_JOB_PREFIX + "-settings": {"steps": QUICK_SETTINGS_STEP_NAMES, "optional_steps": ()},
            QUICK_JOB_PREFIX + "-unit": {"steps": QUICK_UNIT_STEP_NAMES, "optional_steps": ()},
            QUICK_JOB_PREFIX + "-producer": {"steps": QUICK_PRODUCER_STEP_NAMES, "optional_steps": ()},
        },
        "quick_job": QUICK_JOB_PREFIX + "-producer",
        "request_id": request_id,
        "auditor_job": QUICK_JOB_PREFIX + "-audit",
        "artifact_names": ("linux-quick-" + request_id,),
        "cache_digest": cache_digest if HEX64_RE.fullmatch(cache_digest or "") else "0" * 64,
        "cache_baseline": cache_baseline,
    }
    audit.validate_expected_quick(expected)
    return expected


def _job_edges(names):
    return ("Set up job",) + tuple(names) + ("Complete job",)


def _expected_run(environ, cache_digest, cache_baseline=""):
    if _tier(environ) == "quick":
        return _expected_quick_run(environ, cache_digest, cache_baseline)
    audit, unused_verdict, unused_canary = _audit_modules()
    mode = environ.get("CI_MODE", "")
    if mode not in ("source", "synthetic"):
        mode = "source"
    source_sha = environ.get("REQUESTED_SOURCE_SHA", "")
    title = "Linux admission source " + (source_sha or "synthetic") if mode == "source" else "Linux admission synthetic synthetic"
    ci_ref = environ.get("CI_REF", "refs/heads/main").removeprefix("refs/heads/")
    if ci_ref not in ("main", "untrusted"):
        ci_ref = "main"
    all_steps = ["Set up job"] + list(SOURCE_STEP_NAMES)
    if mode == "source":
        all_steps.append("Post Mint scoped source-reader token")
        optional = tuple(sorted((*CACHE_SOURCE_STEPS, "Forced faults must fail closed")))
    else:
        optional = tuple(sorted(OPTIONAL_SOURCE_STEPS - {"Forced faults must fail closed"}))
    all_steps.append("Complete job")
    expected = {
        "repository": REPOSITORY,
        "os": "linux",
        "mode": "candidate" if mode == "source" else "synthetic",
        "control_sha": environ.get("CI_SHA", "0" * 40),
        "run_id": int(environ.get("GITHUB_RUN_ID", "1")) if DECIMAL_RE.fullmatch(environ.get("GITHUB_RUN_ID", "")) else 1,
        "run_attempt": int(environ.get("GITHUB_RUN_ATTEMPT", "1")) if DECIMAL_RE.fullmatch(environ.get("GITHUB_RUN_ATTEMPT", "")) else 1,
        "workflow_path": WORKFLOW_PATH,
        "ci_ref": ci_ref,
        "display_title": title,
        "jobs": {
            "linux-source-admission-settings": {"steps": _job_edges(SETTINGS_STEP_NAMES), "optional_steps": ()},
            "linux-source-admission-unit": {"steps": _job_edges(UNIT_STEP_NAMES), "optional_steps": ()},
            "linux-source-admission-source-read": {"steps": tuple(all_steps), "optional_steps": tuple(optional)},
            "linux-source-admission-verdict": {
                "steps": _job_edges(VERDICT_STEP_NAMES),
                "optional_steps": (
                    OPTIONAL_VERDICT_SYNTHETIC_STEPS if mode == "synthetic"
                    else CACHE_VERDICT_STEPS
                ),
            },
        },
        "verdict_job": "linux-source-admission-verdict",
        "verdict_step": "Publish confinement verdict",
        "auditor_job": "linux-source-admission-audit",
        "artifact_names": (),
        "cache_digest": cache_digest if HEX64_RE.fullmatch(cache_digest or "") else "0" * 64,
        "cache_baseline": cache_baseline,
    }
    audit.validate_expected(expected)
    return expected


def _write_output(environ, values):
    path = environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "at", encoding="ascii") as sink:
        for key, value in values.items():
            sink.write(key + "=" + value + "\n")


TOKEN_STAGES = (
    "input", "key_format", "key_write", "sign_exec", "sign_key", "sign_size",
    "installation", "issue", "permissions", "repositories",
)
APP_KEY_MARKERS = (
    ("-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----"),
    ("-----BEGIN PRIVATE KEY-----", "-----END PRIVATE KEY-----"),
)
APP_KEY_MAX_RAW = 32768
APP_KEY_MAX_DER = 8192
SIGN_KEY_MARKERS = (
    b"unable to load", b"could not read", b"no start line", b"bad decrypt",
    b"decoder routines", b"pem routines", b"asn1 encoding routines",
)


def _valid_source_token(value):
    return type(value) is str and SOURCE_TOKEN_RE.fullmatch(value) is not None


def _mask_line(token):
    return "::add-mask::" + token.replace("%", "%25") + "\n"


def _length_bucket(length):
    for limit, name in LENGTH_BUCKETS:
        if length <= limit:
            return name
    return "4097+"


def _token_classes(value):
    found = set()
    for character in value:
        if "a" <= character <= "z" or "A" <= character <= "Z":
            found.add("letters")
        elif "0" <= character <= "9":
            found.add("digits")
        elif character == "_":
            found.add("underscore")
        elif character == "-":
            found.add("dash")
        elif character == ".":
            found.add("dot")
        else:
            found.add("other")
    names = [name for name in TOKEN_CLASS_NAMES if name in found]
    return ",".join(names) if names else "none"


def _issue_shape(issued, token):
    present = "yes" if type(issued) is dict and "token" in issued else "no"
    if type(token) is str:
        kind, length, classes = "str", len(token), _token_classes(token)
    else:
        kind, length, classes = "other", 0, "none"
    return " present=" + present + " type=" + kind + " length=" + _length_bucket(length) + " classes=" + classes


TOKEN_DISCARD_RESULTS = ("deleted", "failed", "skipped")


def _discard_result_line(result):
    if result not in TOKEN_DISCARD_RESULTS:
        result = "failed"
    sys.stdout.write("linux-verifier-token-discard=" + result + "\n")
    sys.stdout.flush()


def _discard_issued_token(token, masked=False):
    if type(token) is not str or HEADER_TOKEN_RE.fullmatch(token) is None:
        _discard_result_line("skipped")
        return
    if not masked:
        sys.stdout.write(_mask_line(token))
        sys.stdout.flush()
    try:
        _api_request("/installation/token", token, method="DELETE", expected=(204,))
    except Exception:
        _discard_result_line("failed")
        return
    _discard_result_line("deleted")


def _token_refusal(stage, detail=""):
    sys.stdout.write("linux-verifier-token-diag stage=" + stage + detail + "\n")
    sys.stdout.flush()
    return SourceBuildRefusal("token")


def _app_key_pem(raw):
    if type(raw) is not str or len(raw) > APP_KEY_MAX_RAW:
        return ""
    for begin, end in APP_KEY_MARKERS:
        start = raw.find(begin)
        if start < 0:
            continue
        stop = raw.find(end, start + len(begin))
        if stop < 0:
            return ""
        body = raw[start + len(begin):stop]
        body = body.replace("\\\\n", "").replace("\\n", "").replace("\\r", "")
        compact = "".join(body.split())
        try:
            der = base64.b64decode(compact, validate=True)
        except (ValueError, UnicodeError):
            return ""
        if not der or len(der) > APP_KEY_MAX_DER or der[0] != 0x30:
            return ""
        encoded = base64.b64encode(der).decode("ascii")
        rows = [encoded[offset:offset + 64] for offset in range(0, len(encoded), 64)]
        return begin + "\n" + "\n".join(rows) + "\n" + end + "\n"
    return ""


def _sign_failure_stage(signed):
    errors = getattr(signed, "stderr", b"")
    text = errors.lower() if type(errors) is bytes else b""
    if any(marker in text for marker in SIGN_KEY_MARKERS):
        return "sign_key"
    return "sign_exec"


def mint_verifier_token(environ=None):
    env = os.environ if environ is None else environ
    identity = _source_inputs(env)
    client_id = env.get("SOURCE_READER_CLIENT_ID", "")
    installation_id = env.get("SOURCE_READER_INSTALLATION_ID", "")
    private_key = _app_key_pem(env.get("SOURCE_READER_PRIVATE_KEY", ""))
    if (re.fullmatch(r"[A-Za-z0-9_.-]{3,100}", client_id) is None
            or DECIMAL_RE.fullmatch(installation_id) is None):
        raise _token_refusal("input")
    if not private_key:
        raise _token_refusal("key_format")
    now = int(time.time())
    header = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').rstrip(b"=")
    claims = json.dumps({"iat": now - 60, "exp": now + 540, "iss": client_id}, separators=(",", ":")).encode("ascii")
    payload = base64.urlsafe_b64encode(claims).rstrip(b"=")
    signing_input = header + b"." + payload
    descriptor = -1
    try:
        try:
            descriptor = os.memfd_create("kd-app-key", os.MFD_CLOEXEC)
            key_bytes = private_key.encode("ascii")
            if os.write(descriptor, key_bytes) != len(key_bytes):
                raise _token_refusal("key_write")
            os.lseek(descriptor, 0, os.SEEK_SET)
        except (OSError, UnicodeError):
            raise _token_refusal("key_write") from None
        try:
            signed = subprocess.run(
                ["/usr/bin/openssl", "dgst", "-sha256", "-sign", "/proc/self/fd/" + str(descriptor)],
                input=signing_input, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=15, check=False, pass_fds=(descriptor,),
                env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            )
        except (OSError, subprocess.SubprocessError):
            raise _token_refusal("sign_exec") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if signed.returncode != 0 or not signed.stdout:
        raise _token_refusal(_sign_failure_stage(signed))
    if len(signed.stdout) < 64 or len(signed.stdout) > 1024:
        raise _token_refusal("sign_size")
    jwt = signing_input.decode("ascii") + "." + base64.urlsafe_b64encode(signed.stdout).rstrip(b"=").decode("ascii")
    unused, installation = _api_request("/app/installations/" + installation_id, jwt)
    account = installation.get("account") if type(installation) is dict else None
    if (type(installation) is not dict or installation.get("id") != int(installation_id)
            or type(account) is not dict or type(account.get("login")) is not str
            or account["login"].lower() != identity["owner"].lower()):
        raise _token_refusal("installation")
    unused, issued = _api_request(
        "/app/installations/" + installation_id + "/access_tokens", jwt, method="POST",
        payload={"repositories": [identity["name"]], "permissions": {"contents": "read"}}, expected=(201,),
    )
    token = issued.get("token") if type(issued) is dict else None
    if not _valid_source_token(token):
        _discard_issued_token(token)
        raise _token_refusal("issue", _issue_shape(issued, token))
    sys.stdout.write(_mask_line(token))
    sys.stdout.flush()
    permissions = issued.get("permissions")
    if (type(permissions) is not dict or permissions.get("contents") != "read"
            or set(permissions) - {"contents", "metadata"}
            or any(value != "read" for value in permissions.values())):
        _discard_issued_token(token, True)
        raise _token_refusal("permissions")
    try:
        unused, repositories = _api_request("/installation/repositories?per_page=100", token)
    except BaseException:
        _discard_issued_token(token, True)
        raise
    entries = repositories.get("repositories") if type(repositories) is dict else None
    if (type(entries) is not list or len(entries) != 1 or repositories.get("total_count") != 1
            or type(entries[0]) is not dict or entries[0].get("id") != int(identity["repository_id"])
            or entries[0].get("name") != identity["name"]):
        _discard_issued_token(token, True)
        raise _token_refusal("repositories")
    _write_output(env, {"token": token, "installation_id": installation_id})
    sys.stdout.write("linux-verifier-token=issued installation=verified scope=one-repository\n")
    return 0


def snapshot_and_preflight(environ=None):
    env = os.environ if environ is None else environ
    try:
        audit, unused_verdict, unused_canary = _audit_modules()
        expected = _expected_run(env, "0" * 64)
        _write_output(env, {"expected": json.dumps(expected, sort_keys=True, separators=(",", ":"))})
        token = env.get("GITHUB_TOKEN", "")
        api = audit._default_api_factory(token, REPOSITORY)
        digest, cache_baseline = audit.snapshot_cache_inventory(api, REPOSITORY)
        expected = _expected_run(env, digest, cache_baseline)
        _write_output(env, {
            "cache_digest": digest,
            "expected": json.dumps(expected, sort_keys=True, separators=(",", ":")),
        })
        state = validate_dispatch(env, token)
        sys.stdout.write("linux-source-settings=verified mode=" + state + " cache=snapped\n")
        return 0
    except SourceBuildRefusal as error:
        sys.stdout.write("linux-source-settings=refused reason=" + error.reason + "\n")
        return 1
    except Exception:
        sys.stdout.write("linux-source-settings=refused reason=invalid\n")
        return 1


def write_audit_identity(environ=None):
    env = os.environ if environ is None else environ
    try:
        expected = _expected_run(env, "0" * 64)
        _write_output(env, {"expected": json.dumps(expected, sort_keys=True, separators=(",", ":"))})
        sys.stdout.write("linux-source-audit-identity=prepared\n")
        return 0
    except BaseException:
        sys.stdout.write("linux-source-audit-identity=unavailable\n")
        return 1


def repeat_preflight(environ=None):
    env = os.environ if environ is None else environ
    try:
        mode = validate_dispatch(env)
        sys.stdout.write("linux-source-preflight=verified mode=" + mode + " cache-mode=none\n")
        return 0
    except SourceBuildRefusal as error:
        sys.stdout.write("linux-source-preflight=refused reason=" + error.reason + "\n")
        return 1
    except Exception:
        sys.stdout.write("linux-source-preflight=refused reason=invalid\n")
        return 1


def windows_snapshot(environ=None):
    env = os.environ if environ is None else environ
    try:
        audit, unused_verdict, unused_canary = _audit_modules()
        token = env.get("GITHUB_TOKEN", "")
        api = audit._default_api_factory(token, REPOSITORY)
        digest, cache_baseline = audit.snapshot_cache_digest(api, REPOSITORY)
        _write_output(env, {"cache_digest": digest})
        state = validate_dispatch(env, token, WINDOWS_SOURCE_PREFIX, source_identity=False)
        sys.stdout.write("windows-source-settings=verified mode=" + state + " cache=snapped\n")
        return 0
    except SourceBuildRefusal as error:
        sys.stdout.write("windows-source-settings=refused reason=" + error.reason + "\n")
        return 1
    except Exception:
        sys.stdout.write("windows-source-settings=refused reason=invalid\n")
        return 1


def windows_preflight(environ=None):
    env = os.environ if environ is None else environ
    try:
        mode = validate_dispatch(env, None, WINDOWS_SOURCE_PREFIX, source_identity=True)
        sys.stdout.write("windows-source-preflight=verified mode=" + mode + " cache-mode=none\n")
        return 0
    except SourceBuildRefusal as error:
        sys.stdout.write("windows-source-preflight=refused reason=" + error.reason + "\n")
        return 1
    except Exception:
        sys.stdout.write("windows-source-preflight=refused reason=invalid\n")
        return 1


def _download(url, expected_sha, destination, maximum):
    if HEX64_RE.fullmatch(expected_sha or "") is None:
        raise SourceBuildRefusal("toolchain")
    request = urllib.request.Request(url, headers={"User-Agent": "kd-linux-source-build"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    digest = hashlib.sha256()
    size = 0
    try:
        with opener.open(request, timeout=60) as response, open(destination, "wb") as target:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                size += len(block)
                if size > maximum:
                    raise SourceBuildRefusal("network")
                digest.update(block)
                target.write(block)
    except SourceBuildRefusal:
        raise
    except (OSError, urllib.error.URLError):
        raise SourceBuildRefusal("network") from None
    if not size or digest.hexdigest() != expected_sha:
        try:
            os.unlink(destination)
        except OSError:
            pass
        raise SourceBuildRefusal("hash_mismatch")
    os.chmod(destination, 0o400)
    return digest.hexdigest()


def _safe_tar_member(name):
    if type(name) is not str or not name or name.startswith("/") or "\\" in name or "\x00" in name:
        return False
    if name.endswith("/"):
        name = name[:-1]
        if not name or name.endswith("/"):
            return False
    parts = name.split("/")
    return all(part not in ("", ".", "..") for part in parts)


def _safe_tar_link(name):
    return (type(name) is str and bool(name) and not name.startswith("/")
            and "\\" not in name and "\x00" not in name)


def _extract_tar(archive_path, destination, mode):
    root = Path(destination).resolve()
    os.makedirs(root, mode=0o755, exist_ok=True)
    try:
        archive = tarfile.open(archive_path, mode)
    except (OSError, tarfile.TarError):
        raise SourceBuildRefusal("toolchain") from None
    with archive:
        members = archive.getmembers()
        if not members or len(members) > 200000:
            raise SourceBuildRefusal("toolchain")
        pending_links = []
        for member in members:
            if not _safe_tar_member(member.name):
                raise SourceBuildRefusal("toolchain")
            target = root.joinpath(*member.name.split("/"))
            if os.path.commonpath((str(root), str(target.resolve(strict=False)))) != str(root):
                raise SourceBuildRefusal("toolchain")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                os.chmod(target, member.mode & 0o755)
            elif member.isfile():
                target.parent.mkdir(parents=True, exist_ok=True)
                stream = archive.extractfile(member)
                if stream is None:
                    raise SourceBuildRefusal("toolchain")
                with stream, open(target, "wb") as sink:
                    shutil.copyfileobj(stream, sink, 1024 * 1024)
                os.chmod(target, member.mode & 0o755)
            elif member.issym() or member.islnk():
                pending_links.append((member, target))
            else:
                raise SourceBuildRefusal("toolchain")
        for member, target in pending_links:
            linkname = member.linkname
            if not _safe_tar_link(linkname):
                raise SourceBuildRefusal("toolchain")
            link_base = target.parent if member.issym() else root
            resolved = (link_base / linkname).resolve(strict=False)
            if os.path.commonpath((str(root), str(resolved))) != str(root):
                raise SourceBuildRefusal("toolchain")
            target.parent.mkdir(parents=True, exist_ok=True)
            if member.issym():
                os.symlink(linkname, target)
            else:
                if not resolved.is_file():
                    raise SourceBuildRefusal("toolchain")
                os.link(resolved, target)
    return root


def _extract_browser_archive(archive_path, destination):
    root = Path(destination).resolve()
    os.makedirs(root, mode=0o755, exist_ok=True)
    try:
        archive = zipfile.ZipFile(archive_path)
    except (OSError, zipfile.BadZipFile):
        raise SourceBuildRefusal("toolchain") from None
    with archive:
        members = archive.infolist()
        if not members or len(members) > BROWSER_MAX_MEMBERS:
            raise SourceBuildRefusal("toolchain")
        total = 0
        for member in members:
            name = member.filename
            if not _safe_tar_member(name) or name.split("/", 1)[0] != BROWSER_PACKAGE_DIRECTORY:
                raise SourceBuildRefusal("toolchain")
            target = root.joinpath(*name.rstrip("/").split("/"))
            if member.is_dir():
                target.mkdir(mode=0o755, parents=True, exist_ok=True)
                continue
            mode = member.external_attr >> 16
            if stat.S_IFMT(mode) not in (0, stat.S_IFREG):
                raise SourceBuildRefusal("toolchain")
            total += member.file_size
            if total > BROWSER_UNPACKED_MAX_BYTES:
                raise SourceBuildRefusal("toolchain")
            target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
            with archive.open(member) as stream, open(target, "xb") as sink:
                shutil.copyfileobj(stream, sink, 1024 * 1024)
            os.chmod(target, 0o755 if mode & stat.S_IXUSR else 0o644)
    executable = root / BROWSER_PACKAGE_DIRECTORY / BROWSER_EXECUTABLE
    if not executable.is_file() or not os.access(executable, os.X_OK):
        raise SourceBuildRefusal("toolchain")
    return root


def _install_browser_packages():
    environment = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}
    for argv in (
        BROWSER_APT_COMMAND + ("update",),
        BROWSER_APT_COMMAND + ("install", "--yes", "--no-install-recommends", "--") + BROWSER_APT_PACKAGES,
    ):
        try:
            subprocess.run(
                list(argv), env=environment, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, timeout=BROWSER_APT_TIMEOUT_SECONDS, check=True, close_fds=True,
            )
        except (OSError, subprocess.SubprocessError):
            raise SourceBuildRefusal("toolchain") from None


def _prepare_browser(root):
    browsers = Path(root) / BROWSER_ROOT_NAME
    browsers.mkdir(mode=0o755)
    _install_browser_packages()
    archive = Path(root) / "chrome-headless-shell-linux64.zip"
    _download(BROWSER_ARCHIVE_URL, BROWSER_ARCHIVE_SHA256, str(archive), BROWSER_ARCHIVE_MAX_BYTES)
    directory = browsers / BROWSER_DIRECTORY
    _extract_browser_archive(str(archive), str(directory))
    with open(directory / BROWSER_MARKER, "xb"):
        pass
    archive.unlink()
    return browsers


def _browser_installed(browser_root):
    try:
        if Path(browser_root) != TOOLCHAIN_ROOT / BROWSER_ROOT_NAME:
            return False
        executable = Path(browser_root) / BROWSER_DIRECTORY / BROWSER_PACKAGE_DIRECTORY / BROWSER_EXECUTABLE
        marker = Path(browser_root) / BROWSER_DIRECTORY / BROWSER_MARKER
        for path in (Path(browser_root), executable, marker):
            if path.is_symlink():
                return False
        return executable.is_file() and marker.is_file() and os.access(executable, os.X_OK)
    except OSError:
        return False


def prepare_toolchains(environ=None):
    env = os.environ if environ is None else environ
    records = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-records"
    root = TOOLCHAIN_ROOT
    if root.is_symlink():
        raise SourceBuildRefusal("toolchain")
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    records.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (IMAGE_RE.fullmatch(env.get("ImageOS", "")) is None
            or IMAGE_RE.fullmatch(env.get("ImageVersion", "")) is None):
        raise SourceBuildRefusal("toolchain")
    image_line = "linux-source-image schema=1 image-os=" + env["ImageOS"] + " image-version=" + env["ImageVersion"]
    (records / "image.txt").write_text(image_line + "\n", encoding="ascii")
    component_root = root / "rust-components"
    component_root.mkdir(mode=0o755, exist_ok=True)
    for name, url, digest in RUST_COMPONENTS:
        archive = root / (name + ".tar.gz")
        _download(url, digest, str(archive), 512 * 1024 * 1024)
        extracted = component_root / name
        _extract_tar(str(archive), str(extracted), "r:gz")
        installer = next(extracted.rglob("install.sh"), None)
        if installer is None:
            raise SourceBuildRefusal("toolchain")
        try:
            subprocess.run(
                ["/bin/sh", str(installer), "--prefix=" + str(root / "rust"), "--disable-ldconfig"],
                cwd=str(installer.parent),
                env={"PATH": "/usr/bin:/bin", "HOME": str(root), "LANG": "C", "LC_ALL": "C"},
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=180, check=True, close_fds=True,
            )
        except (OSError, subprocess.SubprocessError):
            raise SourceBuildRefusal("toolchain") from None
    if NODE_LINUX_TARBALL_SHA256.startswith("COORDINATOR_FILL_"):
        raise SourceBuildRefusal("toolchain")
    node_archive = root / "node-linux-x64.tar.xz"
    _download(
        "https://nodejs.org/dist/v" + NODE_VERSION + "/node-v" + NODE_VERSION + "-linux-x64.tar.xz",
        NODE_LINUX_TARBALL_SHA256,
        str(node_archive),
        128 * 1024 * 1024,
    )
    node_root = _extract_tar(str(node_archive), str(root / "node"), "r:xz")
    node_binary = next(node_root.rglob("bin/node"), None)
    if node_binary is None:
        raise SourceBuildRefusal("toolchain")
    npm_manifest = node_binary.parent.parent / "lib" / "node_modules" / "npm" / "package.json"
    browser_root = _prepare_browser(root) if env.get(BROWSER_FLAG_ENV) == "1" else None
    rustc = root / "rust" / "bin" / "rustc"
    cargo = root / "rust" / "bin" / "cargo"
    try:
        npm_record = json.loads(npm_manifest.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise SourceBuildRefusal("toolchain") from None
    if (not rustc.is_file() or not cargo.is_file()
            or type(npm_record) is not dict or npm_record.get("version") != NPM_VERSION):
        raise SourceBuildRefusal("toolchain")
    os.chmod(root, 0o755)
    for current, directories, files in os.walk(root, followlinks=False):
        os.chmod(current, 0o755)
        for name in files:
            path = Path(current) / name
            if path.is_symlink():
                continue
            mode = path.stat().st_mode
            os.chmod(path, 0o555 if mode & stat.S_IXUSR else 0o444)
    output = env.get("GITHUB_OUTPUT")
    if output:
        with open(output, "at", encoding="ascii") as sink:
            sink.write("rust_root=" + str(root / "rust") + "\n")
            sink.write("rust_sysroot=" + str(root / "rust") + "\n")
            sink.write("node_root=" + str(node_root) + "\n")
            sink.write("node_bin=" + str(node_binary.parent) + "\n")
            if browser_root is not None:
                sink.write("browser_root=" + str(browser_root) + "\n")
    sys.stdout.write(image_line + " toolchains=hash-verified\n")
    return 0


def _run(argv, cwd, environ=None, timeout=120, maximum=16 * 1024 * 1024):
    try:
        result = subprocess.run(
            [str(item) for item in argv], cwd=str(cwd), env=environ or {
                "PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
            },
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=timeout, check=False, close_fds=True,
        )
    except (OSError, subprocess.SubprocessError):
        raise SourceBuildRefusal("checkout") from None
    if len(result.stdout) > maximum or len(result.stderr) > maximum:
        raise SourceBuildRefusal("checkout")
    return result


def _git(repo, *args, token=None, timeout=300, maximum=32 * 1024 * 1024):
    env = {
        "PATH": "/usr/bin:/bin", "HOME": str(repo.parent), "TMPDIR": str(repo.parent),
        "LANG": "C", "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_ATTR_NOSYSTEM": "1", "GIT_CONFIG_COUNT": "3",
        "GIT_CONFIG_KEY_0": "core.hooksPath", "GIT_CONFIG_VALUE_0": "/dev/null",
        "GIT_CONFIG_KEY_1": "protocol.file.allow", "GIT_CONFIG_VALUE_1": "never",
        "GIT_CONFIG_KEY_2": "http.followRedirects", "GIT_CONFIG_VALUE_2": "false",
    }
    if token:
        authorization = "AUTHORIZATION: basic " + base64.b64encode(("x-access-token:" + token).encode("ascii")).decode("ascii")
        env["GIT_CONFIG_COUNT"] = "4"
        env["GIT_CONFIG_KEY_3"] = "http.https://github.com/.extraheader"
        env["GIT_CONFIG_VALUE_3"] = authorization
    return _run(("/usr/bin/git", "-c", "safe.directory=" + str(repo), *args), repo, env, timeout, maximum)


def _sha_output(result):
    if result.returncode != 0 or result.stderr:
        raise SourceBuildRefusal("checkout")
    try:
        value = result.stdout.decode("ascii").strip()
    except UnicodeError:
        raise SourceBuildRefusal("checkout") from None
    if SOURCE_SHA_RE.fullmatch(value) is None:
        raise SourceBuildRefusal("checkout")
    return value


def _signer_keys(payload):
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError:
        raise SourceBuildRefusal("signature") from None
    accepted = []
    fingerprints = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("\x23"):
            continue
        try:
            fields = shlex.split(stripped, comments=False, posix=True)
            key_positions = [index for index in (1, 2) if index < len(fields) and fields[index] == "ssh-ed25519"]
            if len(key_positions) != 1:
                raise ValueError
            position = key_positions[0]
            encoded = fields[position + 1]
            blob = base64.b64decode(encoded.encode("ascii"), validate=True)
            first_size = int.from_bytes(blob[:4], "big")
            second_offset = 4 + first_size
            second_size = int.from_bytes(blob[second_offset:second_offset + 4], "big")
            if (blob[4:second_offset] != b"ssh-ed25519" or second_size != 32
                    or second_offset + 4 + second_size != len(blob)):
                raise ValueError
            fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
            accepted.append((stripped + "\n").encode("ascii"))
            fingerprints[fingerprint] = b"ssh-ed25519 " + encoded.encode("ascii") + b"\n"
        except BaseException:
            raise SourceBuildRefusal("signature") from None
    if not accepted:
        raise SourceBuildRefusal("signature")
    return b"".join(accepted), fingerprints


def _check_committed_node_lock(lock_bytes, source_root):
    if len(lock_bytes) > 4 * 1024 * 1024 - 64 * 1024:
        raise SourceBuildRefusal("lock")
    _locked_packages(lock_bytes)
    lock_sha = hashlib.sha256(lock_bytes).hexdigest()
    manifest_digest = _manifest_digest(source_root)
    return lock_sha, manifest_digest


def _verify_signatures(repo, source, identity, control_root):
    signer_path = "docs/commit-signers"
    signers_result = _git(repo, "show", identity["base_sha"] + ":" + signer_path)
    if signers_result.returncode != 0 or signers_result.stderr:
        raise SourceBuildRefusal("signature")
    allowed_payload, key_map = _signer_keys(signers_result.stdout)
    revoked_path = control_root / "ci" / "revoked-signer-fingerprints"
    try:
        revoked_payload = revoked_path.read_bytes()
        committed = _git(control_root, "show", identity["control_sha"] + ":ci/revoked-signer-fingerprints")
    except OSError:
        raise SourceBuildRefusal("signature") from None
    if committed.returncode != 0 or committed.stderr or committed.stdout != revoked_payload:
        raise SourceBuildRefusal("signature")
    revoked = []
    if revoked_payload:
        if not revoked_payload.endswith(b"\n") or b"\r" in revoked_payload:
            raise SourceBuildRefusal("signature")
        for line in revoked_payload[:-1].decode("ascii", "strict").split("\n"):
            if FINGERPRINT_RE.fullmatch(line) is None or line in revoked:
                raise SourceBuildRefusal("signature")
            revoked.append(line)
    revocation_data = b"".join(key_map[name] for name in revoked if name in key_map)
    if any(name not in key_map for name in revoked):
        raise SourceBuildRefusal("signature")
    temporary = Path(tempfile.mkdtemp(prefix="linux-signatures-", dir=str(repo.parent)))
    try:
        allowed_path = temporary / "base-allowed-signers"
        revoked_file = temporary / "revoked-signers"
        allowed_path.write_bytes(allowed_payload)
        revoked_file.write_bytes(revocation_data)
        changed = _git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", "-z", identity["base_sha"], identity["source_sha"])
        if changed.returncode != 0 or changed.stderr:
            raise SourceBuildRefusal("signature")
        if signer_path.encode("ascii") in changed.stdout.split(b"\x00"):
            raise SourceBuildRefusal("signature")
        commits = _git(repo, "rev-list", "--topo-order", "--reverse", identity["base_sha"] + ".." + identity["source_sha"])
        if commits.returncode != 0 or commits.stderr or len(commits.stdout) > 4 * 1024 * 1024:
            raise SourceBuildRefusal("signature")
        commit_ids = commits.stdout.decode("ascii").splitlines()
        for commit in commit_ids:
            if SOURCE_SHA_RE.fullmatch(commit) is None:
                raise SourceBuildRefusal("signature")
            result = _git(
                repo, "-c", "gpg.format=ssh", "-c", "gpg.ssh.program=/usr/bin/ssh-keygen",
                "-c", "gpg.program=false", "-c", "gpg.x509.program=false",
                "-c", "gpg.ssh.allowedSignersFile=" + str(allowed_path),
                "-c", "gpg.ssh.revocationFile=" + str(revoked_file),
                "-c", "gpg.minTrustLevel=fully", "verify-commit", commit,
            )
            if result.returncode != 0:
                raise SourceBuildRefusal("signature")
    except UnicodeError:
        raise SourceBuildRefusal("signature") from None
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def checkout_source(environ=None):
    env = os.environ if environ is None else environ
    identity = _source_inputs(env)
    token = env.get("SOURCE_READER_TOKEN", "")
    if not _valid_source_token(token):
        raise SourceBuildRefusal("token")
    source_root = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-source-checkout"
    shutil.rmtree(source_root, ignore_errors=True)
    source_root.mkdir(mode=0o700, parents=True)
    repo = source_root / "repository"
    repo.mkdir(mode=0o700)
    init = _git(repo, "init", "--quiet")
    if init.returncode != 0 or init.stderr:
        raise SourceBuildRefusal("checkout")
    owner = identity["owner"]
    name = identity["name"]
    repository = owner + "/" + name
    repository_path = "/repos/" + urllib.parse.quote(owner, safe="") + "/" + urllib.parse.quote(name, safe="")
    status, repository_info = _api_request(repository_path, token)
    if (status != 200 or type(repository_info) is not dict
            or type(repository_info.get("id")) is not int
            or str(repository_info["id"]) != identity["repository_id"]
            or repository_info.get("private") is not True
            or repository_info.get("full_name") != repository):
        raise SourceBuildRefusal("source")
    eligible = env.get("CI_REF") == "refs/heads/untrusted"
    if env.get("CI_REF") == "refs/heads/main":
        for branch in ("develop", "uat", "main"):
            tip = _reference_sha(token, repository, branch)
            if tip is not None and _comparison(token, repository, identity["source_sha"], tip) in ("ahead", "identical"):
                eligible = True
                break
    if not eligible:
        raise SourceBuildRefusal("source")
    remote = "https://github.com/" + owner + "/" + name + ".git"
    added = _git(repo, "remote", "add", "source", remote)
    if added.returncode != 0:
        raise SourceBuildRefusal("checkout")
    base_ref = "refs/heads/" + identity["base_branch"]
    fetched_base = _git(
        repo, "fetch", "--quiet", "--no-tags", "source",
        base_ref + ":refs/remotes/source/base", token=token,
    )
    fetched_source = _git(repo, "fetch", "--quiet", "--no-tags", "source", identity["source_sha"], token=token)
    if fetched_base.returncode != 0 or fetched_source.returncode != 0:
        raise SourceBuildRefusal("checkout")
    base = _sha_output(_git(repo, "rev-parse", "--verify", "refs/remotes/source/base^{commit}"))
    if base != identity["base_sha"]:
        raise SourceBuildRefusal("binding")
    source_sha = _sha_output(_git(repo, "rev-parse", "--verify", identity["source_sha"] + "^{commit}"))
    if source_sha != identity["source_sha"]:
        raise SourceBuildRefusal("checkout")
    ancestor = _git(repo, "merge-base", "--is-ancestor", identity["base_sha"], identity["source_sha"])
    if ancestor.returncode != 0 or ancestor.stdout or ancestor.stderr:
        raise SourceBuildRefusal("binding")
    checked = _git(repo, "checkout", "--quiet", "--detach", identity["source_sha"])
    if checked.returncode != 0 or checked.stderr:
        raise SourceBuildRefusal("checkout")
    head = _sha_output(_git(repo, "rev-parse", "--verify", "HEAD"))
    tree = _sha_output(_git(repo, "rev-parse", "--verify", "HEAD^{tree}"))
    status = _git(repo, "status", "--porcelain", "--untracked-files=all")
    if head != identity["source_sha"] or status.returncode != 0 or status.stdout or status.stderr:
        raise SourceBuildRefusal("checkout")
    diff = _git(repo, "diff", "--binary", "--no-ext-diff", "--no-renames", identity["base_sha"], identity["source_sha"], maximum=64 * 1024 * 1024)
    if diff.returncode != 0 or diff.stderr or hashlib.sha256(diff.stdout).hexdigest() != identity["reviewed_diff_sha256"]:
        raise SourceBuildRefusal("binding")
    _verify_signatures(repo, source_root, identity, Path(env["CI_WORKSPACE"]))
    lock_path = repo / "package-lock.json"
    try:
        lock_bytes = lock_path.read_bytes()
    except OSError:
        raise SourceBuildRefusal("lock") from None
    lock_sha, manifest_sha = _check_committed_node_lock(lock_bytes, repo)
    _validate_cargo_lock_sources(repo)
    _neutralize_config_files(repo)
    write_out = env.get("GITHUB_OUTPUT")
    if write_out:
        with open(write_out, "at", encoding="ascii") as sink:
            sink.write("source_path=" + str(repo) + "\n")
            sink.write("source_tree=" + tree + "\n")
            sink.write("lock_sha256=" + lock_sha + "\n")
            sink.write("manifest_sha256=" + manifest_sha + "\n")
    sys.stdout.write("linux-source-checkout=verified source-sha=" + head + " tree=" + tree + " signatures=verified lock=committed\n")
    return 0


def revoke_token(environ=None):
    env = os.environ if environ is None else environ
    token = env.get("SOURCE_READER_TOKEN", "")
    if type(token) is not str or HEADER_TOKEN_RE.fullmatch(token) is None:
        raise SourceBuildRefusal("revocation")
    status, unused = _api_request("/installation/token", token, method="DELETE", expected=(204,))
    if status != 204:
        raise SourceBuildRefusal("revocation")
    status, unused = _api_request("/installation/repositories?per_page=1", token, expected=(401,))
    if status != 401:
        raise SourceBuildRefusal("revocation")
    records = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-records"
    records.mkdir(mode=0o700, parents=True, exist_ok=True)
    receipt = {
        "schema_version": 1,
        "status": "confirmed",
        "control_sha": env.get("CI_SHA", ""),
        "run_id": env.get("GITHUB_RUN_ID", ""),
        "run_attempt": env.get("GITHUB_RUN_ATTEMPT", ""),
        "installation_id": env.get("SOURCE_READER_INSTALLATION_ID", ""),
        "rejected_after_revoke": True,
    }
    (records / "revocation.json").write_text(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
    sys.stdout.write("linux-source-token=revoked rejection=verified receipt=positive\n")
    return 0


def verify_dependency_preflight(environ=None):
    env = os.environ if environ is None else environ
    source_sha = env.get("REQUESTED_SOURCE_SHA", "")
    control_sha = env.get("CONTROL_SHA", "")
    ci_sha = env.get("CI_SHA", "")
    ci_ref = env.get("CI_REF", "")
    if env.get("CI_REUSABLE_CALL") == "true":
        repository = env.get("CI_REPOSITORY", "")
        event = env.get("CI_EVENT_NAME", "")
        base_ref = env.get("CI_BASE_REF", "")
        branch_allowed = (
            (event == "push" and ci_ref in (
                "refs/heads/develop", "refs/heads/uat", "refs/heads/main",
            ) and base_ref == "")
            or (event == "pull_request" and base_ref in ("develop", "uat", "main")
                and re.fullmatch(r"refs/pull/[1-9][0-9]{0,18}/merge", ci_ref) is not None)
        )
        if (type(repository) is not str or repository.casefold() != RUST_CACHE_CORE_REPOSITORY.casefold()
                or env.get("CI_SERVER_URL") != "https://github.com"
                or env.get("CACHE_MODE") != "none"
                or ci_sha != env.get("GITHUB_SHA")
                or SOURCE_SHA_RE.fullmatch(ci_sha) is None
                or source_sha != ci_sha
                or SOURCE_SHA_RE.fullmatch(control_sha) is None
                or not branch_allowed):
            raise SourceBuildRefusal("identity")
        if not env.get("GITHUB_TOKEN"):
            raise SourceBuildRefusal("identity")
        _verify_reusable_dependency_caller(
            env["GITHUB_TOKEN"], repository, source_sha, control_sha,
        )
        sys.stdout.write("linux-dependency-preflight=verified cache=none mode=reusable\n")
        return 0
    if (env.get("CI_EVENT_NAME") != "workflow_dispatch"
            or env.get("CI_REPOSITORY") != REPOSITORY
            or env.get("CI_SERVER_URL") != "https://github.com"
            or env.get("CACHE_MODE") != "none"
            or env.get("CI_SHA") != env.get("GITHUB_SHA")
            or SOURCE_SHA_RE.fullmatch(source_sha) is None
            or SOURCE_SHA_RE.fullmatch(control_sha) is None
            or control_sha != ci_sha
            or ci_ref not in ("refs/heads/main", "refs/heads/untrusted")):
        raise SourceBuildRefusal("identity")
    token = env.get("GITHUB_TOKEN", "")
    if type(token) is not str or not token:
        raise SourceBuildRefusal("identity")
    live_main = _reference_sha(token, REPOSITORY, "main")
    live_untrusted = _reference_sha(token, REPOSITORY, "untrusted")
    if live_main is None:
        raise SourceBuildRefusal("freshness")
    if ci_ref == "refs/heads/main" and live_main != ci_sha:
        raise SourceBuildRefusal("freshness")
    if (live_untrusted is None
            or _comparison(token, REPOSITORY, live_untrusted, live_main) not in ("ahead", "identical")):
        raise SourceBuildRefusal("untrusted")
    if ci_ref == "refs/heads/untrusted" and live_untrusted != ci_sha:
        raise SourceBuildRefusal("freshness")
    _verify_environment(token)
    sys.stdout.write("linux-dependency-preflight=verified cache=none\n")
    return 0


def verify_source_reader(environ=None):
    env = os.environ if environ is None else environ
    if _untrusted_core_pull_request(env):
        source_sha = env.get("REQUESTED_SOURCE_SHA", "")
        control_sha = env.get("CONTROL_SHA", "")
        ci_sha = env.get("CI_SHA", "")
        ci_ref = env.get("CI_REF", "")
        ci_base_ref = env.get("CI_BASE_REF", "")
        github_token = env.get("GITHUB_TOKEN", "")
        repository = RUST_CACHE_CORE_REPOSITORY
        if (SOURCE_SHA_RE.fullmatch(source_sha) is None
                or SOURCE_SHA_RE.fullmatch(control_sha) is None
                or ci_sha != source_sha or ci_sha != env.get("GITHUB_SHA")
                or ci_ref != env.get("GITHUB_REF")
                or ci_base_ref != env.get("GITHUB_BASE_REF")
                or not github_token or any(name in env for name in SOURCE_HELD_NAMES)):
            raise SourceBuildRefusal("token")
        status, details = _api_request("/repos/" + repository, github_token)
        if (status != 200 or type(details) is not dict or details.get("private") is not True
                or type(details.get("full_name")) is not str
                or details["full_name"].casefold() != repository.casefold()):
            raise SourceBuildRefusal("source")
        status, commit = _api_request(
            "/repos/" + repository + "/commits/" + source_sha, github_token,
        )
        if status != 200 or type(commit) is not dict or commit.get("sha") != source_sha:
            raise SourceBuildRefusal("source")
        sys.stdout.write(
            "linux-source-reader=verified repository=core pull_request=untrusted secret_reader=none\n"
        )
        return 0
    token = env.get("SOURCE_READER_TOKEN", "")
    repository_id = env.get("SOURCE_REPOSITORY_ID", "")
    owner = env.get("SOURCE_REPOSITORY_OWNER", "")
    name = env.get("SOURCE_REPOSITORY_NAME", "")
    source_sha = env.get("REQUESTED_SOURCE_SHA", "")
    if (not _valid_source_token(token) or DECIMAL_RE.fullmatch(repository_id) is None
            or OWNER_RE.fullmatch(owner) is None or OWNER_RE.fullmatch(name) is None
            or SOURCE_SHA_RE.fullmatch(source_sha) is None
            or not _source_reader_caller_allowed(env)):
        raise SourceBuildRefusal("token")
    ci_ref = env.get("CI_REF", "")
    repository = owner + "/" + name
    path = "/repos/" + urllib.parse.quote(owner, safe="") + "/" + urllib.parse.quote(name, safe="")
    status, details = _api_request(path, token)
    if (status != 200 or type(details) is not dict or details.get("id") != int(repository_id)
            or details.get("private") is not True or details.get("full_name") != repository):
        raise SourceBuildRefusal("source")
    status, installation = _api_request("/installation/repositories?per_page=100", token)
    entries = installation.get("repositories") if type(installation) is dict else None
    if (status != 200 or type(entries) is not list or len(entries) != 1
            or installation.get("total_count") != 1 or type(entries[0]) is not dict
            or entries[0].get("id") != int(repository_id) or entries[0].get("full_name") != repository):
        raise SourceBuildRefusal("token")
    if ci_ref == "refs/heads/main":
        eligible = False
        for branch in ("develop", "uat", "main"):
            tip = _reference_sha(token, repository, branch)
            if tip is not None and _comparison(token, repository, source_sha, tip) in ("ahead", "identical"):
                eligible = True
                break
        if not eligible:
            raise SourceBuildRefusal("source")
    sys.stdout.write("linux-source-reader=verified repository=one-private-source permission=contents-read\n")
    return 0


def _npm_integrity(value):
    if type(value) is not str or not value.startswith("sha512-"):
        raise SourceBuildRefusal("lock")
    try:
        digest = base64.b64decode(value[7:].encode("ascii"), validate=True)
    except (ValueError, UnicodeError):
        raise SourceBuildRefusal("lock") from None
    if len(digest) != 64:
        raise SourceBuildRefusal("lock")
    return digest


def _locked_packages(lock_bytes):
    try:
        lock = json.loads(lock_bytes.decode("utf-8"))
    except (UnicodeError, ValueError):
        raise SourceBuildRefusal("lock") from None
    if (type(lock) is not dict or lock.get("lockfileVersion") != 3
            or type(lock.get("packages")) is not dict or len(lock["packages"]) > 50000):
        raise SourceBuildRefusal("lock")
    packages = {}
    for key, entry in lock["packages"].items():
        if not key or type(entry) is not dict or entry.get("link") is True:
            continue
        resolved = entry.get("resolved")
        if resolved is None:
            continue
        parsed = urllib.parse.urlsplit(resolved)
        if parsed.scheme != "https" or parsed.hostname != "registry.npmjs.org" or parsed.port:
            raise SourceBuildRefusal("lock")
        integrity = _npm_integrity(entry.get("integrity"))
        packages[resolved] = integrity
    if not packages:
        raise SourceBuildRefusal("lock")
    return lock, packages


def _manifest_json(path):
    try:
        return gate_table.manifest_json(path)
    except gate_table.GateTableRefusal:
        raise SourceBuildRefusal("lock") from None


MANIFEST_ROOT_OVERRIDES = gate_table.MANIFEST_ROOT_OVERRIDES


def _manifest_digest(source_root):
    try:
        return gate_table.manifest_digest(source_root)
    except gate_table.GateTableRefusal:
        raise SourceBuildRefusal("lock") from None


def _cargo_config_files(root):
    found = []
    for current, directories, files in os.walk(root, followlinks=False):
        directories[:] = [name for name in directories if not os.path.islink(os.path.join(current, name))]
        if Path(current).name == ".cargo":
            for name in files:
                if name.startswith("config"):
                    found.append(Path(current) / name)
    return found


def _neutralize_config_files(source_root):
    for current, directories, files in os.walk(source_root, followlinks=False):
        for name in list(directories):
            path = Path(current) / name
            if name == ".cargo" and path.is_symlink():
                path.unlink()
                directories.remove(name)
    for path in _cargo_config_files(source_root):
        if path.is_symlink():
            path.unlink()
            continue
        try:
            payload = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            raise SourceBuildRefusal("registry") from None
        if re.search(r"(?im)^\s*\[(?:source\.|registries\.)|^\s*(?:replace-with|registry)\s*=", payload):
            raise SourceBuildRefusal("registry")
        path.unlink()
    for current, directories, files in os.walk(source_root, followlinks=False):
        directories[:] = [name for name in directories if not os.path.islink(os.path.join(current, name))]
        for name in files:
            if name == ".npmrc":
                (Path(current) / name).unlink()


def fetch_npm_tarballs(environ=None):
    env = os.environ if environ is None else environ
    source = Path(env.get("SOURCE_PATH", ""))
    if not source.is_dir():
        raise SourceBuildRefusal("checkout")
    lock_bytes = (source / "package-lock.json").read_bytes()
    if env.get("KD_DEPENDENCY_ONLY") == "true":
        if SOURCE_SHA_RE.fullmatch(env.get("REQUESTED_SOURCE_SHA", "")) is None:
            raise SourceBuildRefusal("binding")
    else:
        _source_inputs(env)
    lock_sha, manifest_sha = _check_committed_node_lock(lock_bytes, source)
    unused_lock, packages = _locked_packages(lock_bytes)
    if env.get("KD_INCLUDE_RUNTIME_NPM_LOCK") == "true":
        runtime_lock = source / "runtime" / "package-lock.json"
        try:
            runtime_info = runtime_lock.lstat()
            runtime_lock_bytes = runtime_lock.read_bytes()
        except OSError:
            raise SourceBuildRefusal("lock") from None
        runtime_lock_sha = hashlib.sha256(runtime_lock_bytes).hexdigest()
        if (not stat.S_ISREG(runtime_info.st_mode) or runtime_info.st_nlink != 1
                or runtime_lock_sha != env.get("EXPECTED_RUNTIME_NODE_LOCK_SHA256")):
            raise SourceBuildRefusal("lock")
        unused_runtime_lock, runtime_packages = _locked_packages(runtime_lock_bytes)
        for url, integrity in runtime_packages.items():
            if url in packages and packages[url] != integrity:
                raise SourceBuildRefusal("lock")
            packages[url] = integrity
    records = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-records"
    cache = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-npm-tarballs"
    records.mkdir(mode=0o700, parents=True, exist_ok=True)
    cache.mkdir(mode=0o700, parents=True, exist_ok=True)
    mapping = {}
    for index, (url, expected) in enumerate(sorted(packages.items())):
        path = cache / (str(index) + ".tgz")
        _download_integrity(url, expected, str(path))
        mapping[url] = str(path)
    index_path = records / "npm-tarballs.json"
    index_path.write_text(json.dumps(mapping, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
    env_out = env.get("GITHUB_OUTPUT")
    if env_out:
        with open(env_out, "at", encoding="ascii") as sink:
            sink.write("tarball_index=" + str(index_path) + "\n")
            sink.write("lock_sha256=" + lock_sha + "\n")
            sink.write("manifest_sha256=" + manifest_sha + "\n")
    sys.stdout.write("linux-npm-tarballs=verified count=" + str(len(mapping)) + " integrity=sha512\n")
    return 0


def _download_integrity(url, expected, destination):
    request = urllib.request.Request(url, headers={"User-Agent": "kd-linux-source-build"})
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    digest = hashlib.sha512()
    count = 0
    try:
        with opener.open(request, timeout=45) as response, open(destination, "wb") as target:
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                count += len(block)
                if count > 256 * 1024 * 1024:
                    raise SourceBuildRefusal("network")
                digest.update(block)
                target.write(block)
    except SourceBuildRefusal:
        raise
    except (OSError, urllib.error.URLError):
        raise SourceBuildRefusal("network") from None
    if count == 0 or digest.digest() != expected:
        try:
            os.unlink(destination)
        except OSError:
            pass
        raise SourceBuildRefusal("hash_mismatch")
    os.chmod(destination, 0o400)


def _open_project_root():
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        parent = os.open("/tmp", flags)
    except OSError:
        raise SourceBuildRefusal("gate") from None
    parent_details = os.fstat(parent)
    if parent_details.st_uid != 0 or parent_details.st_mode & 0o022 and not parent_details.st_mode & stat.S_ISVTX:
        os.close(parent)
        raise SourceBuildRefusal("gate")
    try:
        try:
            os.mkdir(PROJECT_ROOT.name, 0o755, dir_fd=parent)
        except FileExistsError:
            pass
        root = os.open(PROJECT_ROOT.name, flags, dir_fd=parent)
    except OSError:
        raise SourceBuildRefusal("gate") from None
    finally:
        os.close(parent)
    try:
        details = os.fstat(root)
    except OSError:
        os.close(root)
        raise SourceBuildRefusal("gate") from None
    if details.st_uid != 0 or details.st_mode & 0o022:
        os.close(root)
        raise SourceBuildRefusal("gate")
    return root


def _project_gate_directories(worker, create=False):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    root = _open_project_root()
    try:
        if Path(worker) != PROJECT_ROOT / "source":
            raise SourceBuildRefusal("gate")
        project = os.open("source", flags, dir_fd=root)
        try:
            details = os.fstat(project)
            if details.st_uid != linux_harness.CHILD_UID or details.st_gid != linux_harness.CHILD_GID:
                raise SourceBuildRefusal("gate")
            for name in (".home", ".tmp", "target", ".npm-cache", ".kd-cargo-home"):
                made = False
                if create and name != ".kd-cargo-home":
                    try:
                        os.mkdir(name, 0o700, dir_fd=project)
                        made = True
                    except FileExistsError:
                        pass
                child = os.open(name, flags, dir_fd=project)
                try:
                    if made:
                        os.fchown(child, linux_harness.CHILD_UID, linux_harness.CHILD_GID)
                        os.fchmod(child, 0o700)
                    details = os.fstat(child)
                    if details.st_uid != linux_harness.CHILD_UID or details.st_gid != linux_harness.CHILD_GID:
                        raise SourceBuildRefusal("gate")
                    if name == ".home":
                        _gate_npm_config_files(child, create)
                finally:
                    os.close(child)
        finally:
            os.close(project)
    except OSError:
        raise SourceBuildRefusal("gate") from None
    finally:
        os.close(root)


def _gate_npm_config_files(home, create):
    identities = set()
    for name in (NPM_USER_CONFIG_NAME, NPM_GLOBAL_CONFIG_NAME):
        if create:
            descriptor = os.open(
                name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600, dir_fd=home,
            )
            try:
                os.fchown(descriptor, GATE_CONFIG_UID, GATE_CONFIG_GID)
                os.fchmod(descriptor, 0o444)
            finally:
                os.close(descriptor)
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=home)
        try:
            details = os.fstat(descriptor)
        finally:
            os.close(descriptor)
        if (not stat.S_ISREG(details.st_mode) or details.st_size != 0 or details.st_nlink != 1
                or stat.S_IMODE(details.st_mode) != 0o444
                or details.st_uid != GATE_CONFIG_UID or details.st_gid != GATE_CONFIG_GID):
            raise SourceBuildRefusal("gate")
        identities.add((details.st_dev, details.st_ino))
    if len(identities) != 2:
        raise SourceBuildRefusal("gate")


def _prepare_worker_tree(source, tarball_index, environ):
    source_sha = environ.get("REQUESTED_SOURCE_SHA", "")
    inventory_payload = None
    inventory_rows = ()
    original_inventory_sha256 = None
    inventory_file = Path(source) / cargo_lock_bootstrap.SOURCE_INVENTORY_PATH
    if inventory_file.exists():
        try:
            original_inventory_sha256 = cargo_lock_bootstrap.validate_runtime_source_inventory(
                source, source_sha,
            )
            inventory_payload = inventory_file.read_bytes()
            inventory_rows, parsed_sha256 = cargo_lock_bootstrap.parse_runtime_source_inventory(
                inventory_payload, source_sha,
            )
            if not hmac.compare_digest(original_inventory_sha256, parsed_sha256):
                raise SourceBuildRefusal("lock")
        except (OSError, cargo_lock_bootstrap.BootstrapRefusal):
            raise SourceBuildRefusal("lock") from None
    root = _open_project_root()
    os.close(root)
    worker = PROJECT_ROOT / "source"
    if worker.is_symlink():
        raise SourceBuildRefusal("gate")
    shutil.rmtree(worker, ignore_errors=True)
    shutil.copytree(source, worker, symlinks=True, ignore=shutil.ignore_patterns(".git"))
    for current, directories, files in os.walk(worker, followlinks=False):
        for name in directories + files:
            path = Path(current) / name
            if path.is_symlink():
                link = os.readlink(path)
                resolved = (path.parent / link).resolve(strict=False)
                if os.path.isabs(link) or os.path.commonpath((str(worker.resolve()), str(resolved))) != str(worker.resolve()):
                    raise SourceBuildRefusal("gate")
    _neutralize_config_files(worker)
    for current, directories, files in os.walk(worker, followlinks=False):
        directories[:] = [name for name in directories if not os.path.islink(os.path.join(current, name))]
        for name in list(files):
            path = Path(current) / name
            if name == ".npmrc":
                path.unlink()
            elif path.parent.name == ".cargo" and name.startswith("config"):
                path.unlink()
    try:
        mapping = json.loads(Path(tarball_index).read_text(encoding="ascii"))
    except (OSError, UnicodeError, ValueError):
        raise SourceBuildRefusal("lock") from None
    if type(mapping) is not dict or any(type(key) is not str or type(value) is not str for key, value in mapping.items()):
        raise SourceBuildRefusal("lock")
    tarball_root = worker / ".kd-npm-tarballs"
    try:
        tarball_root.mkdir(mode=0o755)
    except OSError:
        raise SourceBuildRefusal("gate") from None
    copied = {}
    package_integrities = {}
    lock_paths = [worker / "package-lock.json"]
    if environ.get("KD_INCLUDE_RUNTIME_NPM_LOCK") == "true":
        lock_paths.append(worker / "runtime" / "package-lock.json")
    for lock_path in lock_paths:
        try:
            lock = json.loads(lock_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, ValueError):
            raise SourceBuildRefusal("lock") from None
        for entry in lock.get("packages", {}).values():
            if type(entry) is not dict:
                continue
            url = entry.get("resolved")
            if url not in mapping:
                continue
            integrity = _npm_integrity(entry.get("integrity"))
            if url not in copied:
                source_tarball = Path(mapping[url])
                if source_tarball.is_symlink() or not source_tarball.is_file():
                    raise SourceBuildRefusal("lock")
                destination = tarball_root / (str(len(copied)) + ".tgz")
                shutil.copyfile(source_tarball, destination)
                digest = hashlib.sha512()
                with open(destination, "rb") as copied_file:
                    while True:
                        block = copied_file.read(1024 * 1024)
                        if not block:
                            break
                        digest.update(block)
                if digest.digest() != integrity:
                    destination.unlink()
                    raise SourceBuildRefusal("hash_mismatch")
                os.chown(destination, linux_harness.CHILD_UID, linux_harness.CHILD_GID)
                os.chmod(destination, 0o444)
                copied[url] = destination.resolve().as_uri()
            elif package_integrities[url] != integrity:
                raise SourceBuildRefusal("lock")
            package_integrities[url] = integrity
            entry["resolved"] = copied[url]
        lock_path.write_text(json.dumps(lock, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
    if set(copied) != set(mapping):
        raise SourceBuildRefusal("lock")
    for current, directories, files in os.walk(worker, followlinks=False):
        os.chown(current, linux_harness.CHILD_UID, linux_harness.CHILD_GID)
        os.chmod(current, 0o755)
        for name in files:
            path = Path(current) / name
            if path.is_symlink():
                continue
            os.chown(path, linux_harness.CHILD_UID, linux_harness.CHILD_GID)
            mode = path.stat().st_mode
            os.chmod(path, 0o755 if mode & stat.S_IXUSR else 0o644)
    if inventory_payload is not None:
        original_by_path = {row["path"]: row for row in inventory_rows}
        staged_rows = []
        deleted_paths = []
        modified_paths = []
        for path in sorted(original_by_path):
            row = dict(original_by_path[path])
            target = worker.joinpath(*path.split("/"))
            if not target.exists():
                if path != ".npmrc" and not path.endswith("/.npmrc"):
                    raise SourceBuildRefusal("lock")
                deleted_paths.append(path)
                continue
            if target.is_symlink() or not target.is_file():
                raise SourceBuildRefusal("lock")
            staged_digest = hashlib.sha256(target.read_bytes()).hexdigest()
            if staged_digest != row["sha256"]:
                if path not in ("package-lock.json", "runtime/package-lock.json"):
                    raise SourceBuildRefusal("lock")
                modified_paths.append(path)
                row["sha256"] = staged_digest
            staged_rows.append(row)
        inventory_lines = ["schema_version = 1"]
        inventory_fields = (
            "path", "sha256", "owner", "package", "target", "generator",
            "generator_version", "provenance",
        )
        for row in staged_rows:
            inventory_lines.append("[[files]]")
            inventory_lines.extend(key + ' = "' + row[key] + '"' for key in inventory_fields)
        staged_inventory = ("\n".join(inventory_lines) + "\n").encode("ascii")
        inventory_path = worker / cargo_lock_bootstrap.SOURCE_INVENTORY_PATH
        inventory_path.write_bytes(staged_inventory)
        os.chown(inventory_path, linux_harness.CHILD_UID, linux_harness.CHILD_GID)
        os.chmod(inventory_path, 0o444)
    return worker


def _validate_cargo_lock_sources(project):
    found = False
    for current, directories, files in os.walk(project, followlinks=False):
        directories[:] = [
            name for name in directories
            if name != ".git" and not os.path.islink(os.path.join(current, name))
        ]
        if "Cargo.lock" not in files:
            continue
        found = True
        try:
            payload = (Path(current) / "Cargo.lock").read_bytes()
        except OSError:
            raise SourceBuildRefusal("lock") from None
        if len(payload) > MAX_CARGO_LOCK_BYTES:
            raise SourceBuildRefusal("lock")
        try:
            cargo_lock_bootstrap.cargo.parse_cargo_lock(payload)
        except cargo_lock_bootstrap.cargo.Refusal:
            raise SourceBuildRefusal("registry") from None
    if not found:
        raise SourceBuildRefusal("lock")


def _directory_identity(metadata):
    return metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink


def _open_source_root(source):
    source = Path(source)
    if not source.is_absolute() or ".." in source.parts:
        raise SourceBuildRefusal("binding")
    if (not hasattr(os, "O_DIRECTORY") or not hasattr(os, "O_NOFOLLOW")
            or os.stat not in os.supports_dir_fd):
        raise SourceBuildRefusal("binding")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = None
    try:
        descriptor = os.open("/", flags)
        for component in source.parts[1:]:
            before = os.stat(component, dir_fd=descriptor, follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode):
                raise SourceBuildRefusal("binding")
            child = os.open(component, flags, dir_fd=descriptor)
            opened = os.fstat(child)
            if _directory_identity(opened) != _directory_identity(before):
                os.close(child)
                raise SourceBuildRefusal("binding")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except SourceBuildRefusal:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except (OSError, TypeError, ValueError):
        if descriptor is not None:
            os.close(descriptor)
        raise SourceBuildRefusal("binding") from None


def _open_verified_directory(root_fd, relative_parts, identities):
    if len(identities) != len(relative_parts) + 1:
        raise SourceBuildRefusal("lock")
    descriptors = []
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        current = os.dup(root_fd)
        descriptors.append(current)
        if _directory_identity(os.fstat(current)) != identities[0]:
            raise SourceBuildRefusal("lock")
        for index, component in enumerate(relative_parts, 1):
            before = os.stat(component, dir_fd=current, follow_symlinks=False)
            if (stat.S_ISLNK(before.st_mode) or not stat.S_ISDIR(before.st_mode)
                    or _directory_identity(before) != identities[index]):
                raise SourceBuildRefusal("lock")
            child = os.open(component, flags, dir_fd=current)
            opened = os.fstat(child)
            if _directory_identity(opened) != identities[index]:
                os.close(child)
                raise SourceBuildRefusal("lock")
            descriptors.append(child)
            current = child
        return descriptors
    except BaseException as error:
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError:
                pass
        if isinstance(error, OSError):
            raise SourceBuildRefusal("lock") from None
        raise


def _rust_lock_paths(root_fd, file_name="Cargo.lock", limit=32, require_any=True,
                     refuse_directory_links=False):
    ignored = RUST_WALK_IGNORED
    root_only_ignored = RUST_WALK_ROOT_IGNORED
    paths = []
    root_identity = _directory_identity(os.fstat(root_fd))
    pending = [((), (root_identity,))]
    visited = 0
    total_entries = 0
    while pending:
        relative_parts, identities = pending.pop()
        visited += 1
        if visited > MAX_LOCK_DIRECTORIES:
            raise SourceBuildRefusal("lock")
        descriptors = _open_verified_directory(root_fd, relative_parts, identities)
        current = descriptors[-1]
        entries_seen = 0
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    entries_seen += 1
                    total_entries += 1
                    if (entries_seen > MAX_DIRECTORY_ENTRIES
                            or total_entries > MAX_TREE_ENTRIES):
                        raise SourceBuildRefusal("lock")
                    name = entry.name
                    if name in ignored or (not relative_parts and name in root_only_ignored):
                        continue
                    metadata = os.stat(name, dir_fd=current, follow_symlinks=False)
                    if stat.S_ISLNK(metadata.st_mode):
                        if name == file_name:
                            raise SourceBuildRefusal("lock")
                        if refuse_directory_links:
                            try:
                                target = os.stat(name, dir_fd=current)
                            except OSError:
                                continue
                            if stat.S_ISDIR(target.st_mode):
                                raise SourceBuildRefusal("lock")
                        continue
                    child_parts = relative_parts + (name,)
                    if stat.S_ISDIR(metadata.st_mode):
                        if len(pending) >= MAX_PENDING_DIRECTORIES:
                            raise SourceBuildRefusal("lock")
                        pending.append((child_parts, identities + (_directory_identity(metadata),)))
                        continue
                    if name != file_name:
                        continue
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                        raise SourceBuildRefusal("lock")
                    paths.append((child_parts, identities, _stat_identity(metadata)))
                    if len(paths) > limit:
                        raise SourceBuildRefusal("lock")
        except SourceBuildRefusal:
            raise
        except OSError:
            raise SourceBuildRefusal("lock") from None
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)
    if not paths and require_any:
        raise SourceBuildRefusal("lock")
    return tuple(sorted(paths, key=lambda item: "/".join(item[0])))


def _stat_identity(metadata):
    return (
        metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_nlink,
        metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns,
    )


def _read_bounded_cargo_lock(root_fd, candidate):
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if nofollow is None or type(candidate) is not tuple or len(candidate) != 3:
        raise SourceBuildRefusal("lock")
    descriptor = None
    parent_descriptors = []
    try:
        relative_parts, ancestry, discovered_identity = candidate
        if (type(relative_parts) is not tuple or not relative_parts
                or type(ancestry) is not tuple):
            raise SourceBuildRefusal("lock")
        parent_parts = relative_parts[:-1]
        parent_descriptors = _open_verified_directory(root_fd, parent_parts, ancestry)
        parent_fd = parent_descriptors[-1]
        lock_name = relative_parts[-1]
        before = os.stat(lock_name, dir_fd=parent_fd, follow_symlinks=False)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size > MAX_CARGO_LOCK_BYTES):
            raise SourceBuildRefusal("lock")
        if discovered_identity != _stat_identity(before):
            raise SourceBuildRefusal("lock")
        descriptor = os.open(
            lock_name, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0),
            dir_fd=parent_fd,
        )
        opened = os.fstat(descriptor)
        if (_stat_identity(before) != _stat_identity(opened)
                or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1):
            raise SourceBuildRefusal("lock")
        content = bytearray()
        while len(content) <= MAX_CARGO_LOCK_BYTES:
            chunk = os.read(
                descriptor,
                min(65536, MAX_CARGO_LOCK_BYTES + 1 - len(content)),
            )
            if not chunk:
                break
            content.extend(chunk)
        if len(content) > MAX_CARGO_LOCK_BYTES:
            raise SourceBuildRefusal("lock")
        after = os.fstat(descriptor)
        path_after = os.stat(lock_name, dir_fd=parent_fd, follow_symlinks=False)
        if (_stat_identity(opened) != _stat_identity(after)
                or _stat_identity(after) != _stat_identity(path_after)
                or len(content) != after.st_size):
            raise SourceBuildRefusal("lock")
        current_ancestors = _open_verified_directory(root_fd, parent_parts, ancestry)
        try:
            for current_fd, expected_identity in zip(current_ancestors, ancestry):
                if _directory_identity(os.fstat(current_fd)) != expected_identity:
                    raise SourceBuildRefusal("lock")
        finally:
            for current_fd in reversed(current_ancestors):
                os.close(current_fd)
        return bytes(content)
    except SourceBuildRefusal:
        raise
    except (OSError, ValueError):
        raise SourceBuildRefusal("lock") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        for parent_fd in reversed(parent_descriptors):
            os.close(parent_fd)


def _require_source_root_identity(source, expected_identity):
    descriptor = _open_source_root(source)
    try:
        if _directory_identity(os.fstat(descriptor)) != expected_identity:
            raise SourceBuildRefusal("binding")
    finally:
        os.close(descriptor)


MANIFEST_DEPENDENCY_TABLES = (
    "dependencies", "dev-dependencies", "build-dependencies",
    "dev_dependencies", "build_dependencies",
)
MANIFEST_TARGET_TABLES = ("lib", "bin", "test", "bench", "example")
MAX_MANIFEST_FILES = 256
RUST_WALK_IGNORED = frozenset((".git", "target", "node_modules", ".kd-cargo-home", ".npm-cache"))
RUST_WALK_ROOT_IGNORED = frozenset((".kd-npm-tarballs",))


def _skipped_component(component):
    return (component in RUST_WALK_IGNORED or component in RUST_WALK_ROOT_IGNORED
            or component == ".cargo" or component.startswith(".kd-"))


def _require_physical_manifest_path(root_fd, directory_parts, value):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    stack = [os.dup(root_fd)]
    try:
        for component in tuple(directory_parts) + tuple(value.split("/")):
            if component in ("", "."):
                continue
            if component == "..":
                if len(stack) == 1:
                    raise SourceBuildRefusal("lock")
                os.close(stack.pop())
                continue
            try:
                before = os.stat(component, dir_fd=stack[-1], follow_symlinks=False)
            except FileNotFoundError:
                return
            if stat.S_ISLNK(before.st_mode):
                raise SourceBuildRefusal("lock")
            if not stat.S_ISDIR(before.st_mode):
                return
            stack.append(os.open(component, flags, dir_fd=stack[-1]))
    except OSError:
        raise SourceBuildRefusal("lock") from None
    finally:
        for descriptor in reversed(stack):
            os.close(descriptor)


def _require_confined_manifest_path(root_fd, parts, value):
    if (type(value) is not str or not value or value.startswith("/")
            or "\\" in value or ":" in value or "\x00" in value):
        raise SourceBuildRefusal("lock")
    directory = "/".join(parts) or "."
    resolved = posixpath.normpath(posixpath.join(directory, value))
    if resolved == ".." or resolved.startswith("../") or resolved.startswith("/"):
        raise SourceBuildRefusal("lock")
    if any(_skipped_component(item) for item in value.split("/") + resolved.split("/")):
        raise SourceBuildRefusal("lock")
    _require_physical_manifest_path(root_fd, parts, value)


def _require_confined_manifest(root_fd, parts, document):
    if type(document) is not dict or "patch" in document or "replace" in document:
        raise SourceBuildRefusal("lock")
    tables = [document[name] for name in MANIFEST_DEPENDENCY_TABLES if name in document]
    target = document.get("target")
    if target is not None:
        if type(target) is not dict:
            raise SourceBuildRefusal("lock")
        for entry in target.values():
            if type(entry) is not dict:
                raise SourceBuildRefusal("lock")
            tables.extend(entry[name] for name in MANIFEST_DEPENDENCY_TABLES if name in entry)
    workspace = document.get("workspace")
    if workspace is not None:
        if type(workspace) is not dict:
            raise SourceBuildRefusal("lock")
        if "dependencies" in workspace:
            tables.append(workspace["dependencies"])
        for key in ("members", "exclude", "default-members"):
            if key in workspace:
                if type(workspace[key]) is not list:
                    raise SourceBuildRefusal("lock")
                for item in workspace[key]:
                    _require_confined_manifest_path(root_fd, parts, item)
    package = document.get("package")
    if package is not None:
        if type(package) is not dict:
            raise SourceBuildRefusal("lock")
        for key in ("workspace", "build"):
            if key in package and type(package[key]) is not bool:
                _require_confined_manifest_path(root_fd, parts, package[key])
    for key in MANIFEST_TARGET_TABLES:
        value = document.get(key)
        entries = value if type(value) is list else ([] if value is None else [value])
        for entry in entries:
            if type(entry) is not dict:
                raise SourceBuildRefusal("lock")
            if "path" in entry:
                _require_confined_manifest_path(root_fd, parts, entry["path"])
    for table in tables:
        if type(table) is not dict:
            raise SourceBuildRefusal("lock")
        for spec in table.values():
            if type(spec) is str:
                continue
            if type(spec) is not dict:
                raise SourceBuildRefusal("lock")
            if "path" in spec:
                _require_confined_manifest_path(root_fd, parts, spec["path"])


def _require_confined_manifests(root_fd):
    candidates = _rust_lock_paths(root_fd, "Cargo.toml", MAX_MANIFEST_FILES, False, True)
    for candidate in candidates:
        data = _read_bounded_cargo_lock(root_fd, candidate)
        try:
            document = cargo_lock_bootstrap._parse_manifest(data)
        except Exception:
            raise SourceBuildRefusal("lock") from None
        _require_confined_manifest(root_fd, candidate[0][:-1], document)


def fetch_cargo_locks(environ=None):
    """Fetch Cargo sources named by committed locks before the confined offline build."""
    env = os.environ if environ is None else environ
    source = Path(env.get("SOURCE_PATH", ""))
    source_sha = env.get("REQUESTED_SOURCE_SHA", "")
    if SOURCE_SHA_RE.fullmatch(source_sha) is None:
        raise SourceBuildRefusal("binding")
    try:
        root_fd = _open_source_root(source)
    except SourceBuildRefusal:
        raise SourceBuildRefusal("binding") from None
    root_identity = _directory_identity(os.fstat(root_fd))
    manifests = []
    try:
        _require_source_root_identity(source, root_identity)
        _require_confined_manifests(root_fd)
        for candidate in _rust_lock_paths(root_fd):
            try:
                lock_bytes = _read_bounded_cargo_lock(root_fd, candidate)
                relative_parts = candidate[0][:-1]
                _require_source_root_identity(source, root_identity)
            except (OSError, ValueError):
                raise SourceBuildRefusal("lock") from None
            if not lock_bytes or len(lock_bytes) > MAX_CARGO_LOCK_BYTES:
                raise SourceBuildRefusal("lock")
            try:
                cargo_lock_bootstrap.cargo.parse_cargo_lock(lock_bytes)
            except cargo_lock_bootstrap.cargo.Refusal:
                raise SourceBuildRefusal("lock") from None
            relative = Path(*relative_parts) if relative_parts else Path()
            manifest = source / relative / "Cargo.toml"
            try:
                info = manifest.lstat()
            except OSError:
                raise SourceBuildRefusal("lock") from None
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise SourceBuildRefusal("lock")
            manifests.append(manifest)
    finally:
        os.close(root_fd)
    if not manifests:
        raise SourceBuildRefusal("lock")
    cache = _optional_rust_cache(env, source, env.get("RUST_CACHE_SCOPE"))
    cargo = Path(env.get("RUST_ROOT", "")) / "bin" / "cargo"
    fetch_home = Path(env.get("KD_CARGO_FETCH_HOME", ""))
    runner_temp = Path(env.get("RUNNER_TEMP", "/tmp"))
    try:
        if (not cargo.is_file() or not fetch_home.is_absolute() or fetch_home.is_symlink()
                or fetch_home.parent.resolve(strict=True) != runner_temp.resolve(strict=True)
                or fetch_home.exists()):
            raise SourceBuildRefusal("toolchain")
        fetch_home.mkdir(mode=0o700)
        config = fetch_home / "config.toml"
        config.write_text("\n", encoding="ascii")
        os.chmod(config, 0o600)
        if cache is not None and cache["hit"]:
            try:
                with tempfile.TemporaryDirectory(
                    prefix="kd-rust-cache-seed-", dir=runner_temp,
                ) as seed:
                    seed_home = Path(seed)
                    _copy_cargo_registry_cache(cache["directory"] / "cargo-home", seed_home)
                    for name in ("registry", "git"):
                        seeded = seed_home / name
                        if seeded.exists() or seeded.is_symlink():
                            shutil.move(str(seeded), str(fetch_home / name))
            except (OSError, shutil.Error, SourceBuildRefusal, ValueError):
                for name in ("registry", "git"):
                    _discard_optional_cache_path(fetch_home / name)
    except (OSError, ValueError):
        raise SourceBuildRefusal("toolchain") from None
    fetch_env = {
        "PATH": str(cargo.parent) + ":/usr/bin:/bin",
        "HOME": str(fetch_home),
        "TMPDIR": str(fetch_home),
        "CARGO_HOME": str(fetch_home),
        "CARGO_INCREMENTAL": "0",
        "CARGO_TERM_COLOR": "never",
        "LANG": "C",
        "LC_ALL": "C",
    }
    for manifest in sorted(manifests, key=lambda item: item.relative_to(source).as_posix()):
        result = _run(
            (str(cargo), "fetch", "--locked", "--manifest-path", str(manifest)),
            fetch_home,
            fetch_env,
            timeout=300,
            maximum=4 * 1024 * 1024,
        )
        if result.returncode != 0:
            raise SourceBuildRefusal("lock")
    output = env.get("GITHUB_OUTPUT")
    if output:
        with open(output, "at", encoding="ascii") as sink:
            sink.write("cargo_fetch_home=" + str(fetch_home) + "\n")
    sys.stdout.write("linux-cargo-fetch=committed-locks locks=" + str(len(manifests)) + " offline-build=ready\n")
    return 0


def _copy_cargo_registry_cache(source_home, destination_home, owner=None):
    entries = 0
    for name in ("registry", "git"):
        source_path = Path(source_home) / name
        destination_path = Path(destination_home) / name
        if not source_path.exists() and not source_path.is_symlink():
            continue
        entries += _copy_validated_cache_tree(
            source_path, destination_path, owner=owner,
            allow_existing_empty=True,
        )
    return entries


def _copy_validated_cache_tree(source, destination, owner=None, allow_existing_empty=False):
    source = Path(source)
    destination = Path(destination)
    try:
        root_info = source.lstat()
        if not stat.S_ISDIR(root_info.st_mode):
            raise SourceBuildRefusal("cache")
    except OSError:
        raise SourceBuildRefusal("cache") from None
    root_resolved = source.resolve(strict=True)
    entries = 0
    hardlink_counts = {}
    hardlink_totals = {}
    for current, directories, files in os.walk(source, followlinks=False):
        current_path = Path(current)
        for name in list(directories):
            item = current_path / name
            info = item.lstat()
            entries += 1
            if entries > MAX_TREE_ENTRIES:
                raise SourceBuildRefusal("cache")
            if stat.S_ISLNK(info.st_mode):
                link = os.readlink(item)
                resolved = (item.parent / link).resolve(strict=False)
                if os.path.isabs(link) or os.path.commonpath((str(root_resolved), str(resolved))) != str(root_resolved):
                    raise SourceBuildRefusal("cache")
                directories.remove(name)
            elif not stat.S_ISDIR(info.st_mode):
                raise SourceBuildRefusal("cache")
        for name in files:
            item = current_path / name
            info = item.lstat()
            entries += 1
            if entries > MAX_TREE_ENTRIES:
                raise SourceBuildRefusal("cache")
            if stat.S_ISLNK(info.st_mode):
                link = os.readlink(item)
                resolved = (item.parent / link).resolve(strict=False)
                if os.path.isabs(link) or os.path.commonpath((str(root_resolved), str(resolved))) != str(root_resolved):
                    raise SourceBuildRefusal("cache")
            elif not stat.S_ISREG(info.st_mode):
                raise SourceBuildRefusal("cache")
            else:
                inode = (info.st_dev, info.st_ino)
                hardlink_counts[inode] = hardlink_counts.get(inode, 0) + 1
                hardlink_totals[inode] = info.st_nlink
    if any(hardlink_counts[inode] != total for inode, total in hardlink_totals.items()):
        raise SourceBuildRefusal("cache")
    if destination.exists() or destination.is_symlink():
        try:
            info = destination.lstat()
            if (not allow_existing_empty or not stat.S_ISDIR(info.st_mode)
                    or any(destination.iterdir())):
                raise SourceBuildRefusal("cache")
        except OSError:
            raise SourceBuildRefusal("cache") from None
    else:
        try:
            destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        except OSError:
            raise SourceBuildRefusal("cache") from None
    try:
        shutil.copytree(source, destination, symlinks=True, dirs_exist_ok=allow_existing_empty)
        if owner is not None:
            for current, directories, files in os.walk(destination, followlinks=False):
                os.chown(current, owner[0], owner[1])
                os.chmod(current, 0o755)
                for name in directories + files:
                    item = Path(current) / name
                    if item.is_symlink():
                        continue
                    info = item.lstat()
                    if stat.S_ISDIR(info.st_mode):
                        os.chown(item, owner[0], owner[1])
                        os.chmod(item, 0o755)
                    elif stat.S_ISREG(info.st_mode):
                        os.chown(item, owner[0], owner[1])
                        os.chmod(item, 0o755 if info.st_mode & stat.S_IXUSR else 0o644)
                    else:
                        raise SourceBuildRefusal("cache")
    except (OSError, shutil.Error):
        raise SourceBuildRefusal("cache") from None
    return entries


def prepare_project(environ=None):
    env = os.environ if environ is None else environ
    source = Path(env.get("SOURCE_PATH", ""))
    cache = _optional_rust_cache(env, source, env.get("RUST_CACHE_SCOPE"))
    rust_root = Path(env.get("RUST_ROOT", ""))
    tarball_index = env.get("NPM_TARBALL_INDEX", "")
    cargo = rust_root / "bin" / "cargo"
    if not source.is_dir() or not cargo.is_file() or not tarball_index:
        raise SourceBuildRefusal("toolchain")
    lock_bytes = (source / "package-lock.json").read_bytes()
    if (hashlib.sha256(lock_bytes).hexdigest() != env.get("EXPECTED_NODE_LOCK_SHA256")
            or _manifest_digest(source) != env.get("EXPECTED_MANIFEST_SHA256")):
        raise SourceBuildRefusal("lock")
    if env.get("KD_INCLUDE_RUNTIME_NPM_LOCK") == "true":
        runtime_lock = source / "runtime" / "package-lock.json"
        try:
            runtime_info = runtime_lock.lstat()
            runtime_lock_sha = hashlib.sha256(runtime_lock.read_bytes()).hexdigest()
        except OSError:
            raise SourceBuildRefusal("lock") from None
        if (not stat.S_ISREG(runtime_info.st_mode) or runtime_info.st_nlink != 1
                or runtime_lock_sha != env.get("EXPECTED_RUNTIME_NODE_LOCK_SHA256")):
            raise SourceBuildRefusal("lock")
    _validate_cargo_lock_sources(source)
    worker = _prepare_worker_tree(source, tarball_index, env)
    if env.get("KD_INCLUDE_RUNTIME_NPM_LOCK") == "true":
        _ensure_test_shell_icons(worker)
    cargo_home = worker / ".kd-cargo-home"
    try:
        cargo_home.mkdir(mode=0o755)
    except OSError:
        raise SourceBuildRefusal("gate") from None
    config = cargo_home / "config.toml"
    config.write_text("\n", encoding="ascii")
    _copy_cargo_registry_cache(
        env.get("KD_CARGO_FETCH_HOME", ""), cargo_home,
        owner=(linux_harness.CHILD_UID, linux_harness.CHILD_GID),
    )
    os.chown(config, linux_harness.CHILD_UID, linux_harness.CHILD_GID)
    os.chmod(config, 0o444)
    os.chown(cargo_home, linux_harness.CHILD_UID, linux_harness.CHILD_GID)
    os.chmod(cargo_home, 0o755)
    _project_gate_directories(worker, create=True)
    if cache is not None and cache["hit"]:
        try:
            _copy_validated_cache_tree(
                cache["directory"] / "target", worker / "target",
                owner=(linux_harness.CHILD_UID, linux_harness.CHILD_GID), allow_existing_empty=True,
            )
        except (OSError, shutil.Error, SourceBuildRefusal, ValueError):
            target = worker / "target"
            _discard_optional_cache_path(target)
            target.mkdir(mode=0o700)
            os.chown(target, linux_harness.CHILD_UID, linux_harness.CHILD_GID)
    output = env.get("GITHUB_OUTPUT")
    if output:
        with open(output, "at", encoding="ascii") as sink:
            sink.write("worker_path=" + str(worker) + "\n")
            sink.write("cargo_home=" + str(cargo_home) + "\n")
    sys.stdout.write("linux-project-inputs=prepared cargo=locked-cache npm=integrity\n")
    return 0


def export_rust_cache(environ=None):
    env = os.environ if environ is None else environ
    try:
        if os.geteuid() != 0:
            raise SourceBuildRefusal("cache")
        runner_uid_text = env.get("SUDO_UID", "")
        runner_gid_text = env.get("SUDO_GID", "")
        if (type(runner_uid_text) is not str or DECIMAL_RE.fullmatch(runner_uid_text) is None
                or type(runner_gid_text) is not str or DECIMAL_RE.fullmatch(runner_gid_text) is None):
            raise SourceBuildRefusal("cache")
        runner_owner = (int(runner_uid_text), int(runner_gid_text))
        source = Path(env.get("SOURCE_PATH", ""))
        cache = _validate_rust_cache(env, source, env.get("RUST_CACHE_SCOPE"))
        if cache is None or not _rust_cache_write_allowed(env):
            raise SourceBuildRefusal("cache")
        if cache["hit"]:
            sys.stdout.write("linux-rust-cache=existing\n")
            return 0
        runner_temp = Path(env.get("RUNNER_TEMP", ""))
        try:
            temp_info = runner_temp.lstat()
            cache_info = cache["directory"].lstat()
            if ((temp_info.st_uid, temp_info.st_gid) != runner_owner
                    or (cache_info.st_uid, cache_info.st_gid) != runner_owner
                    or not stat.S_ISDIR(temp_info.st_mode)
                    or not stat.S_ISDIR(cache_info.st_mode)):
                raise SourceBuildRefusal("cache")
        except OSError:
            raise SourceBuildRefusal("cache") from None
        worker = Path(env.get("WORKER_PATH", ""))
        cargo_home = Path(env.get("CARGO_HOME", ""))
        if (not worker.is_absolute() or worker != PROJECT_ROOT / "source"
                or cargo_home != worker / ".kd-cargo-home"):
            raise SourceBuildRefusal("cache")
        try:
            worker_info = worker.lstat()
            target_info = (worker / "target").lstat()
            cargo_home_info = cargo_home.lstat()
            if (not stat.S_ISDIR(worker_info.st_mode)
                    or (worker_info.st_uid, worker_info.st_gid)
                    != (linux_harness.CHILD_UID, linux_harness.CHILD_GID)
                    or not stat.S_ISDIR(target_info.st_mode)
                    or (target_info.st_uid, target_info.st_gid)
                    != (linux_harness.CHILD_UID, linux_harness.CHILD_GID)
                    or target_info.st_mode & 0o077
                    or not stat.S_ISDIR(cargo_home_info.st_mode)
                    or (cargo_home_info.st_uid, cargo_home_info.st_gid)
                    != (linux_harness.CHILD_UID, linux_harness.CHILD_GID)):
                raise SourceBuildRefusal("cache")
        except OSError:
            raise SourceBuildRefusal("cache") from None
        target = cache["directory"] / "target"
        cargo_cache = cache["directory"] / "cargo-home"
        try:
            for staging in (target, cargo_cache):
                staging_info = staging.lstat()
                if (not stat.S_ISDIR(staging_info.st_mode)
                        or (staging_info.st_uid, staging_info.st_gid) != runner_owner):
                    raise SourceBuildRefusal("cache")
        except OSError:
            raise SourceBuildRefusal("cache") from None
        _copy_validated_cache_tree(
            worker / "target", target, owner=runner_owner, allow_existing_empty=True,
        )
        _copy_cargo_registry_cache(cargo_home, cargo_cache, owner=runner_owner)
        sys.stdout.write("linux-rust-cache=prepared\n")
        return 0
    except SourceBuildRefusal as error:
        sys.stdout.write("linux-rust-cache=refused reason=" + error.reason + "\n")
        return 1
    except BaseException:
        sys.stdout.write("linux-rust-cache=refused reason=invalid\n")
        return 1


def _cache_archive_members(archive):
    try:
        members = archive.getmembers()
    except (OSError, tarfile.TarError):
        raise SourceBuildRefusal("cache") from None
    if not members or len(members) > MAX_TREE_ENTRIES:
        raise SourceBuildRefusal("cache")
    names = set()
    kinds = {}
    total_bytes = 0
    roots = {"target": False, "cargo-home": False}
    for member in members:
        if type(member.name) is not str or not member.name or member.name.startswith("/"):
            raise SourceBuildRefusal("cache")
        name = member.name.rstrip("/")
        parts = name.split("/")
        if (not name or any(part in ("", ".", "..") for part in parts)
                or parts[0] not in roots or name in names):
            raise SourceBuildRefusal("cache")
        names.add(name)
        if member.isdir() and member.type == tarfile.DIRTYPE:
            kind = "directory"
        elif member.isreg() and member.type in (tarfile.REGTYPE, tarfile.AREGTYPE):
            if member.size < 0:
                raise SourceBuildRefusal("cache")
            kind = "file"
            total_bytes += member.size
            if total_bytes > RUST_CACHE_ARCHIVE_MAX_BYTES:
                raise SourceBuildRefusal("cache")
        elif member.issym() and member.type == tarfile.SYMTYPE:
            link = member.linkname
            resolved = posixpath.normpath(posixpath.join(posixpath.dirname(name), link))
            if (not link or posixpath.isabs(link) or resolved in (".", "..")
                    or resolved.startswith("../") or resolved.split("/", 1)[0] != parts[0]):
                raise SourceBuildRefusal("cache")
            kind = "symlink"
        else:
            raise SourceBuildRefusal("cache")
        kinds[name] = kind
        if len(parts) == 1 and kind == "directory":
            roots[name] = True
    if not all(roots.values()):
        raise SourceBuildRefusal("cache")
    for name, kind in kinds.items():
        parts = name.split("/")
        for length in range(1, len(parts)):
            ancestor = "/".join(parts[:length])
            if kinds.get(ancestor) != "directory":
                raise SourceBuildRefusal("cache")
    return members


def _run_rust_cache_gpg(operation, source, destination, key, homedir):
    if operation not in ("encrypt", "decrypt") or type(key) is not str:
        raise SourceBuildRefusal("cache")
    source = Path(source)
    destination = Path(destination)
    homedir = Path(homedir)
    try:
        homedir.mkdir(mode=0o700, parents=True, exist_ok=False)
    except OSError:
        raise SourceBuildRefusal("cache") from None
    arguments = [
        "gpg", "--batch", "--yes", "--no-tty", "--pinentry-mode", "loopback",
        "--homedir", str(homedir), "--passphrase-fd", "0",
    ]
    if operation == "encrypt":
        arguments.extend(("--symmetric", "--cipher-algo", "AES256"))
    else:
        arguments.append("--decrypt")
    arguments.extend(("--output", str(destination), str(source)))
    try:
        result = subprocess.run(
            arguments, input=key.encode("ascii") + b"\n", stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=2700, check=False,
        )
        output_info = destination.lstat()
    except (OSError, subprocess.TimeoutExpired):
        raise SourceBuildRefusal("cache") from None
    if result.returncode != 0 or not stat.S_ISREG(output_info.st_mode) or output_info.st_nlink != 1:
        raise SourceBuildRefusal("cache")


def _extract_rust_cache_archive(archive_path, cache_directory):
    try:
        archive = tarfile.open(archive_path, mode="r:")
    except (OSError, tarfile.TarError):
        raise SourceBuildRefusal("cache") from None
    with archive:
        members = _cache_archive_members(archive)
        directories = [member for member in members if member.isdir()]
        regular_files = [member for member in members if member.isreg()]
        symlinks = [member for member in members if member.issym()]
        for member in sorted(directories, key=lambda item: (item.name.count("/"), item.name)):
            path = cache_directory.joinpath(*member.name.rstrip("/").split("/"))
            try:
                path.mkdir(mode=0o755, parents=True, exist_ok=True)
                info = path.lstat()
                if not stat.S_ISDIR(info.st_mode):
                    raise SourceBuildRefusal("cache")
                os.chmod(path, 0o755)
            except OSError:
                raise SourceBuildRefusal("cache") from None
        for member in regular_files:
            path = cache_directory.joinpath(*member.name.split("/"))
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
            try:
                source = archive.extractfile(member)
                if source is None:
                    raise SourceBuildRefusal("cache")
                descriptor = os.open(path, flags, 0o755 if member.mode & 0o111 else 0o644)
                with os.fdopen(descriptor, "wb") as sink, source:
                    remaining = member.size
                    while remaining:
                        block = source.read(min(1024 * 1024, remaining))
                        if not block:
                            raise SourceBuildRefusal("cache")
                        sink.write(block)
                        remaining -= len(block)
            except SourceBuildRefusal:
                raise
            except (OSError, tarfile.TarError):
                raise SourceBuildRefusal("cache") from None
        for member in symlinks:
            path = cache_directory.joinpath(*member.name.split("/"))
            try:
                os.symlink(member.linkname, path)
            except OSError:
                raise SourceBuildRefusal("cache") from None


def import_rust_cache(environ=None):
    env = os.environ if environ is None else environ
    try:
        source = Path(env.get("SOURCE_PATH", ""))
        cache = _validate_rust_cache(env, source, env.get("RUST_CACHE_SCOPE"))
        if cache is None or not cache["hit"]:
            raise SourceBuildRefusal("cache")
        archive_path = cache["directory"] / RUST_CACHE_ARCHIVE_NAME
        runner_temp = Path(env.get("RUNNER_TEMP", ""))
        try:
            runner_owner = (os.getuid(), os.getgid())
            temp_info = runner_temp.lstat()
            archive_info = archive_path.lstat()
            if (not stat.S_ISDIR(temp_info.st_mode) or (temp_info.st_uid, temp_info.st_gid) != runner_owner
                    or not stat.S_ISREG(archive_info.st_mode) or archive_info.st_nlink != 1
                    or (archive_info.st_uid, archive_info.st_gid) != runner_owner
                    or archive_info.st_size <= 0
                    or archive_info.st_size > RUST_CACHE_ARCHIVE_MAX_BYTES + RUST_CACHE_ENCRYPTED_OVERHEAD_MAX_BYTES):
                raise SourceBuildRefusal("cache")
        except OSError:
            raise SourceBuildRefusal("cache") from None
        if _rust_cache_requires_encryption(env):
            key = _rust_cache_encryption_key(env)
            with tempfile.TemporaryDirectory(prefix="kd-rust-cache-import-", dir=runner_temp) as temporary:
                archive_plain = Path(temporary) / RUST_CACHE_ARCHIVE_NAME
                _run_rust_cache_gpg(
                    "decrypt", archive_path, archive_plain, key, Path(temporary) / "gnupg",
                )
                plain_info = archive_plain.lstat()
                if (plain_info.st_size <= 0 or plain_info.st_size > RUST_CACHE_ARCHIVE_MAX_BYTES
                        or not stat.S_ISREG(plain_info.st_mode) or plain_info.st_nlink != 1):
                    raise SourceBuildRefusal("cache")
                _extract_rust_cache_archive(archive_plain, cache["directory"])
        else:
            _extract_rust_cache_archive(archive_path, cache["directory"])
        sys.stdout.write("linux-rust-cache=imported\n")
        return 0
    except SourceBuildRefusal as error:
        sys.stdout.write("linux-rust-cache=refused reason=" + error.reason + "\n")
        return 1
    except BaseException:
        sys.stdout.write("linux-rust-cache=refused reason=invalid\n")
        return 1


def package_rust_cache(environ=None):
    env = os.environ if environ is None else environ
    try:
        source = Path(env.get("SOURCE_PATH", ""))
        cache = _validate_rust_cache(env, source, env.get("RUST_CACHE_SCOPE"))
        if cache is None or cache["hit"] or not _rust_cache_write_allowed(env):
            raise SourceBuildRefusal("cache")
        cache_directory = cache["directory"]
        runner_temp = Path(env.get("RUNNER_TEMP", ""))
        owner = (os.getuid(), os.getgid())
        staging_paths = (cache_directory / "target", cache_directory / "cargo-home")
        for path in staging_paths:
            try:
                info = path.lstat()
                if (not stat.S_ISDIR(info.st_mode) or (info.st_uid, info.st_gid) != owner):
                    raise SourceBuildRefusal("cache")
            except OSError:
                raise SourceBuildRefusal("cache") from None
        try:
            temp_info = runner_temp.lstat()
            temp_owner = (temp_info.st_uid, temp_info.st_gid)
        except FileNotFoundError:
            raise SourceBuildRefusal("cache") from None
        except OSError:
            raise SourceBuildRefusal("cache") from None
        cache_archive = cache_directory / RUST_CACHE_ARCHIVE_NAME
        try:
            archive_info = cache_archive.lstat()
        except FileNotFoundError:
            archive_info = None
        except OSError:
            raise SourceBuildRefusal("cache") from None
        if (not stat.S_ISDIR(temp_info.st_mode) or temp_owner != owner
                or (archive_info is not None
                    and (not stat.S_ISREG(archive_info.st_mode) or archive_info.st_nlink != 1
                         or (archive_info.st_uid, archive_info.st_gid) != owner))):
            raise SourceBuildRefusal("cache")
        with tempfile.TemporaryDirectory(prefix="kd-rust-cache-package-", dir=runner_temp) as temporary:
            archive_plain = Path(temporary) / RUST_CACHE_ARCHIVE_NAME
            with tarfile.open(archive_plain, mode="w", format=tarfile.PAX_FORMAT) as tar_writer:
                tar_writer.dereference = True
                for name in ("target", "cargo-home"):
                    tar_writer.add(str(cache_directory / name), arcname=name, recursive=True)
            if archive_plain.stat().st_size > RUST_CACHE_ARCHIVE_MAX_BYTES:
                raise SourceBuildRefusal("cache")
            if _rust_cache_requires_encryption(env):
                key = _rust_cache_encryption_key(env)
                archive_path = Path(temporary) / (RUST_CACHE_ARCHIVE_NAME + ".gpg")
                _run_rust_cache_gpg(
                    "encrypt", archive_plain, archive_path, key, Path(temporary) / "gnupg",
                )
            else:
                archive_path = archive_plain
            if archive_path.stat().st_size > RUST_CACHE_ARCHIVE_MAX_BYTES + RUST_CACHE_ENCRYPTED_OVERHEAD_MAX_BYTES:
                raise SourceBuildRefusal("cache")
            os.chmod(archive_path, 0o600)
            os.replace(archive_path, cache_archive)
        for path in staging_paths:
            shutil.rmtree(path)
        sys.stdout.write("linux-rust-cache=packaged\n")
        return 0
    except SourceBuildRefusal as error:
        sys.stdout.write("linux-rust-cache=refused reason=" + error.reason + "\n")
        return 1
    except BaseException:
        sys.stdout.write("linux-rust-cache=refused reason=invalid\n")
        return 1


def _png_chunk(kind, data):
    content = kind + data
    return struct.pack(">I", len(data)) + content + struct.pack(">I", zlib.crc32(content) & 0xFFFFFFFF)


def _test_shell_icon_png():
    width = height = 32
    rows = bytearray()
    background = (18, 36, 58, 255)
    mark = (100, 218, 235, 255)
    for y in range(height):
        rows.append(0)
        for x in range(width):
            upper = 7 <= y <= 16 and abs(x - (12 + 16 - y)) <= 2
            lower = 16 <= y <= 25 and abs(x - (12 + y - 16)) <= 2
            color = mark if (7 <= x <= 10 and 7 <= y <= 25) or upper or lower else background
            rows.extend(color)
    header = struct.pack(">2I5B", width, height, 8, 6, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + _png_chunk(b"IHDR", header) + _png_chunk(
        b"IDAT", zlib.compress(bytes(rows), level=9)
    ) + _png_chunk(b"IEND", b"")


def _ensure_test_shell_icons(worker):
    icon_bytes = _test_shell_icon_png()
    for shell in ("test-shell-desktop", "test-shell-mobile"):
        tauri_root = worker / "runtime" / "apps" / shell / "src-tauri"
        try:
            tauri_info = tauri_root.lstat()
        except OSError:
            raise SourceBuildRefusal("gate") from None
        if not stat.S_ISDIR(tauri_info.st_mode):
            raise SourceBuildRefusal("gate")
        icon_dir = tauri_root / "icons"
        try:
            icon_dir_info = icon_dir.lstat()
        except FileNotFoundError:
            try:
                icon_dir.mkdir(mode=0o755)
            except OSError:
                raise SourceBuildRefusal("gate") from None
        except OSError:
            raise SourceBuildRefusal("gate") from None
        else:
            if not stat.S_ISDIR(icon_dir_info.st_mode):
                raise SourceBuildRefusal("gate")
        icon = icon_dir / "icon.png"
        try:
            icon_info = icon.lstat()
        except FileNotFoundError:
            try:
                descriptor = os.open(
                    icon, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644
                )
                with os.fdopen(descriptor, "wb") as output:
                    output.write(icon_bytes)
            except OSError:
                raise SourceBuildRefusal("gate") from None
        except OSError:
            raise SourceBuildRefusal("gate") from None
        else:
            if not stat.S_ISREG(icon_info.st_mode) or icon_info.st_nlink != 1:
                raise SourceBuildRefusal("gate")


def _runtime_workspace_present(project):
    try:
        runtime_info = (project / "runtime").lstat()
    except FileNotFoundError:
        return False
    except OSError:
        raise SourceBuildRefusal("gate") from None
    if not stat.S_ISDIR(runtime_info.st_mode):
        raise SourceBuildRefusal("gate")
    present = []
    for relative_path in RUNTIME_ROOT_FILES:
        try:
            info = (project / relative_path).lstat()
        except FileNotFoundError:
            present.append(False)
            continue
        except OSError:
            raise SourceBuildRefusal("gate") from None
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise SourceBuildRefusal("gate")
        present.append(True)
    if any(present) and not all(present):
        raise SourceBuildRefusal("gate")
    return all(present)


def _ui_kit_workspace_present(project):
    for relative_path in BROWSER_WORKSPACE_PATHS:
        try:
            info = (project / relative_path).lstat()
        except FileNotFoundError:
            return False
        except OSError:
            raise SourceBuildRefusal("gate") from None
        if relative_path == BROWSER_WORKSPACE_PATHS[-1]:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
                raise SourceBuildRefusal("gate")
        elif not stat.S_ISDIR(info.st_mode):
            raise SourceBuildRefusal("gate")
    return True


def _gate_commands(project, rust_root, node_bin, browser=False):
    try:
        commands = gate_table.render(
            gate_table.gate_templates(_runtime_workspace_present(project), browser),
            str(project), str(Path(rust_root) / "bin" / "cargo"),
            str(Path(node_bin) / "node"), str(Path(node_bin) / "npm"),
        )
    except gate_table.GateTableRefusal:
        raise SourceBuildRefusal("gate") from None
    feature_commands = tuple((name, argv) for name, argv in commands if name in API_FEATURE_GATE_NAMES)
    if (tuple(name for name, unused in feature_commands) != API_FEATURE_GATE_NAMES
            or any(
                "--features" not in argv
                or argv[argv.index("--features") + 1:argv.index("--features") + 2]
                != (gate_table.API_FEATURE_NAME,)
                for unused_name, argv in feature_commands
            )):
        raise SourceBuildRefusal("gate")
    return commands


def _locked_build_commands(project, rust_root, include_runtime=True):
    cargo = str(Path(rust_root) / "bin" / "cargo")
    workspaces = (("root", "Cargo.toml"), ("fuzz", "fuzz/Cargo.toml"))
    if include_runtime:
        workspaces += (("runtime", "runtime/Cargo.toml"),)
    commands = []
    for name, manifest in workspaces:
        if not (project / manifest).is_file():
            if name == "root":
                raise SourceBuildRefusal("gate")
            continue
        scope = ("--manifest-path", manifest)
        if name != "fuzz":
            scope += ("--workspace",)
        for verb in ("build", "test"):
            arguments = (cargo, verb, "--locked", "--offline") + scope
            if name == "root":
                arguments += ("--all-targets",)
            commands.append((name + "_" + verb, arguments))
    return tuple(commands)


def _api_feature_gate_readback(environ):
    return environ.get("LINUX_API_FEATURE_GATE_NAMES") == ",".join(API_FEATURE_GATE_NAMES)


PROJECT_GATE_LIMITS = "project"
RUNTIME_GATE_LIMITS = "runtime"
PROJECT_GATE_TIMEOUT_SECONDS = 1800
GATE_CAUSES = ("timeout", "limit", "signal", "exit", "launch", "deadline")
PROJECT_GATE_BUDGET_SECONDS = 330 * 60
RUNTIME_WORKSPACE_TIMEOUT_SECONDS = 5400
LOCKED_BUILD_TIMEOUT_SECONDS = 1800
LOCKED_BUILD_BUDGET_SECONDS = 6900
LIMIT_SIGNALS = (signal.SIGXCPU, signal.SIGXFSZ, signal.SIGKILL)
JOB_WORKER_NAME = "Runner.Worker"
JOB_ANCESTOR_LIMIT = 32


def _job_elapsed_seconds(proc_root="/proc"):
    """Return the seconds since this job's runner worker process started.

    The worker starts when the job starts, so the gate budget counts from the job start and
    not from the gates step. Any ancestor that cannot be read refuses the gates.
    """
    try:
        root = Path(proc_root)
        pid = os.getppid()
        for unused in range(JOB_ANCESTOR_LIMIT):
            if type(pid) is not int or pid <= 1:
                break
            record = (root / str(pid) / "stat").read_text(encoding="ascii")
            name = record[record.index("(") + 1:record.rindex(")")]
            fields = record[record.rindex(")") + 2:].split()
            if name == JOB_WORKER_NAME:
                started = int(fields[19]) / os.sysconf("SC_CLK_TCK")
                uptime = float((root / "uptime").read_text(encoding="ascii").split()[0])
                elapsed = uptime - started
                if elapsed < 0:
                    break
                return elapsed
            pid = int(fields[1])
    except (OSError, ValueError, IndexError):
        pass
    raise SourceBuildRefusal("gate")


def _gate_cause(result):
    if getattr(result, "timed_out", False) is True:
        return "timeout"
    code = getattr(result, "exit_code", None)
    if type(code) is int and code < 0:
        if -code in LIMIT_SIGNALS:
            return "limit"
        return "signal"
    return "exit"


def _gate_refusal_line(completed, failed, gate, cause):
    line = "linux-project-gates=refused completed=" + str(completed) + " failed=" + str(failed)
    if gate in GATES + RUNTIME_GATE_NAMES + BROWSER_GATE_NAMES and cause in GATE_CAUSES:
        line += " gate=" + gate + " cause=" + cause
    return line + "\n"


def run_project_gates(environ=None):
    env = os.environ if environ is None else environ
    worker = Path(env.get("WORKER_PATH", ""))
    cargo_home = Path(env.get("CARGO_HOME", ""))
    rust_root = env.get("RUST_ROOT", "")
    node_bin = env.get("NODE_BIN", "")
    if not rust_root or not node_bin or cargo_home != worker / ".kd-cargo-home":
        raise SourceBuildRefusal("gate")
    _validate_cargo_lock_sources(worker)
    records = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-records"
    records.mkdir(mode=0o700, parents=True, exist_ok=True)
    browser_root = env.get(BROWSER_ROOT_ENV, "")
    if browser_root and not _browser_installed(browser_root):
        raise SourceBuildRefusal("gate")
    browser = _ui_kit_workspace_present(worker)
    if browser and not browser_root:
        raise SourceBuildRefusal("gate")
    commands = _gate_commands(worker, rust_root, node_bin, browser)
    selected_gates = tuple(name for name, unused_argv in commands)
    expected_gates = GATES + (RUNTIME_GATE_NAMES if _runtime_workspace_present(worker) else ())
    expected_gates += BROWSER_GATE_NAMES if browser else ()
    if selected_gates != expected_gates:
        raise SourceBuildRefusal("gate")
    outcomes = {name: "not-run" for name in selected_gates}
    durations = {}
    failure = (None, None)
    job_elapsed = _job_elapsed_seconds()
    budget_started = time.monotonic()
    for index, (name, argv) in enumerate(commands):
        if PROJECT_GATE_BUDGET_SECONDS - job_elapsed - (time.monotonic() - budget_started) < PROJECT_GATE_TIMEOUT_SECONDS:
            failure = (name, "deadline")
            break
        project_env = {
            "PATH": str(Path(node_bin)) + ":" + str(Path(rust_root) / "bin") + ":/usr/bin:/bin",
            "LANG": "C", "LC_ALL": "C", "HOME": str(worker / ".home"),
            "TMPDIR": str(worker / ".tmp"), "CARGO_HOME": str(cargo_home),
            "RUSTUP_HOME": str(Path(rust_root) / "rustup"),
            "CARGO_TARGET_DIR": str(worker / "target"), "CARGO_NET_OFFLINE": "true",
            "CARGO_INCREMENTAL": "0", "NPM_CONFIG_OFFLINE": "true",
            "NPM_CONFIG_CACHE": str(worker / ".npm-cache"),
            "NPM_CONFIG_USERCONFIG": str(worker / ".home" / NPM_USER_CONFIG_NAME),
            "NPM_CONFIG_GLOBALCONFIG": str(worker / ".home" / NPM_GLOBAL_CONFIG_NAME),
            "NPM_CONFIG_UPDATE_NOTIFIER": "false",
            "npm_config_offline": "true",
            "npm_config_cache": str(worker / ".npm-cache"),
            "npm_config_userconfig": str(worker / ".home" / NPM_USER_CONFIG_NAME),
            "npm_config_globalconfig": str(worker / ".home" / NPM_GLOBAL_CONFIG_NAME),
            "npm_config_update_notifier": "false",
            "PYTHONDONTWRITEBYTECODE": "1", "CI": "true",
        }
        browser_gate = name in BROWSER_GATE_NAMES
        if browser_gate:
            project_env["PLAYWRIGHT_BROWSERS_PATH"] = browser_root
            project_env["PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD"] = "1"
        nonce = os.urandom(12).hex()
        started = time.monotonic()
        try:
            _project_gate_directories(worker)
            launch = ("/usr/bin/python3", "-B", "-c", linux_probes.LAUNCHER_SOURCE, *argv)
            result = linux_session.run_host(
                str(env.get("RUNNER_TEMP", "/tmp")), nonce, launch, project_env, {},
                limits=PROJECT_GATE_LIMITS, timeout=PROJECT_GATE_TIMEOUT_SECONDS, cwd=str(worker),
                **({"loopback": True} if browser_gate else {}),
            )
        except BaseException:
            durations[name] = int((time.monotonic() - started) * 1000)
            outcomes[name] = "failed"
            failure = (name, "launch")
            break
        durations[name] = int((time.monotonic() - started) * 1000)
        (records / ("gate-" + str(index) + ".stdout")).write_bytes(result.stdout)
        (records / ("gate-" + str(index) + ".stderr")).write_bytes(result.stderr)
        if result.exit_code == 0 and not result.timed_out:
            outcomes[name] = "passed"
        else:
            outcomes[name] = "failed"
            failure = (name, _gate_cause(result))
            break
    completed_gates = [name for name in selected_gates if outcomes[name] == "passed"]
    (records / "gate-durations.json").write_text(
        json.dumps({"schema_version": 1, "durations_ms": durations}, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="ascii",
    )
    result = {
        "schema_version": 1, "selected_gates": list(selected_gates),
        "completed_gates": completed_gates, "gates": outcomes,
        "gate_count": sum(value != "not-run" for value in outcomes.values()),
        "failed": sum(value == "failed" for value in outcomes.values()),
    }
    (records / "gates.json").write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n", encoding="ascii")
    if result["failed"] or result["gate_count"] != len(selected_gates):
        sys.stdout.write(_gate_refusal_line(result["gate_count"], result["failed"], failure[0], failure[1]))
        return 1
    sys.stdout.write("linux-project-gates=passed gates=" + str(len(selected_gates)) + " failed=0 offline=true\n")
    return 0


def run_locked_builds(environ=None, include_runtime=True):
    """Build and test every supported Rust workspace in the no-network project sandbox."""
    env = os.environ if environ is None else environ
    worker = Path(env.get("WORKER_PATH", ""))
    cargo_home = Path(env.get("CARGO_HOME", ""))
    rust_root = env.get("RUST_ROOT", "")
    if not rust_root or cargo_home != worker / ".kd-cargo-home":
        raise SourceBuildRefusal("gate")
    _validate_cargo_lock_sources(worker)
    commands = _locked_build_commands(worker, rust_root, include_runtime=include_runtime)
    records = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-locked-build-records"
    records.mkdir(mode=0o700, parents=True, exist_ok=True)
    project_env = {
        "PATH": str(Path(rust_root) / "bin") + ":/usr/bin:/bin",
        "LANG": "C", "LC_ALL": "C", "HOME": str(worker / ".home"),
        "TMPDIR": str(worker / ".tmp"), "CARGO_HOME": str(cargo_home),
        "RUSTUP_HOME": str(Path(rust_root) / "rustup"),
        "CARGO_TARGET_DIR": str(worker / "target"), "CARGO_NET_OFFLINE": "true",
        "CARGO_INCREMENTAL": "0", "PYTHONDONTWRITEBYTECODE": "1", "CI": "true",
    }
    _project_gate_directories(worker)
    started = time.monotonic()
    outcomes = []
    for index, (name, argv) in enumerate(commands):
        if LOCKED_BUILD_BUDGET_SECONDS - (time.monotonic() - started) < LOCKED_BUILD_TIMEOUT_SECONDS:
            sys.stdout.write("linux-locked-builds=refused completed=" + str(len(outcomes)) + " reason=deadline\n")
            return 1
        nonce = os.urandom(12).hex()
        try:
            launch = ("/usr/bin/python3", "-B", "-c", linux_probes.LAUNCHER_SOURCE, *argv)
            result = linux_session.run_host(
                str(env.get("RUNNER_TEMP", "/tmp")), nonce, launch, project_env, {},
                limits=PROJECT_GATE_LIMITS, timeout=LOCKED_BUILD_TIMEOUT_SECONDS, cwd=str(worker),
            )
        except BaseException:
            sys.stdout.write("linux-locked-builds=refused completed=" + str(len(outcomes)) + " reason=launch\n")
            return 1
        (records / (str(index) + ".stdout")).write_bytes(result.stdout)
        (records / (str(index) + ".stderr")).write_bytes(result.stderr)
        if result.exit_code != 0 or result.timed_out:
            sys.stdout.write("linux-locked-builds=refused completed=" + str(len(outcomes)) + " failed=" + name + "\n")
            return 1
        outcomes.append(name)
    sys.stdout.write("linux-locked-builds=passed workspaces=" + str(len(commands) // 2) + " network=disabled locked=true\n")
    return 0


def run_dependency_locked_builds(environ=None):
    """Build root and fuzz Rust workspaces; the prepared runtime job owns runtime builds."""
    return run_locked_builds(environ, include_runtime=False)


def run_runtime_workspace(environ=None):
    """Run the caller-owned runtime suite inside the no-network, bounded project sandbox."""
    env = os.environ if environ is None else environ
    worker = Path(env.get("WORKER_PATH", ""))
    cargo_home = Path(env.get("CARGO_HOME", ""))
    rust_root = env.get("RUST_ROOT", "")
    node_bin = env.get("NODE_BIN", "")
    npm_bin = env.get("NPM_BIN", "")
    if (not rust_root or not node_bin or not npm_bin or cargo_home != worker / ".kd-cargo-home"
            or not (worker / "runtime" / "Cargo.lock").is_file()
            or not (worker / "runtime" / "package-lock.json").is_file()
            or not (worker / "runtime" / "scripts" / "check-workspace.mjs").is_file()):
        raise SourceBuildRefusal("gate")
    _validate_cargo_lock_sources(worker)
    _project_gate_directories(worker)
    project_env = {
        "PATH": str(Path(npm_bin)) + ":" + str(Path(node_bin)) + ":" + str(Path(rust_root) / "bin") + ":/usr/bin:/bin",
        "LANG": "C", "LC_ALL": "C", "HOME": str(worker / ".home"),
        "TMPDIR": str(worker / ".tmp"), "CARGO_HOME": str(cargo_home),
        "RUSTUP_HOME": str(Path(rust_root) / "rustup"),
        "CARGO_TARGET_DIR": str(worker / "target"), "CARGO_NET_OFFLINE": "true",
        "CARGO_INCREMENTAL": "0", "NPM_CONFIG_OFFLINE": "true",
        "NPM_CONFIG_CACHE": str(worker / ".npm-cache"),
        "NPM_CONFIG_USERCONFIG": str(worker / ".home" / NPM_USER_CONFIG_NAME),
        "NPM_CONFIG_GLOBALCONFIG": str(worker / ".home" / NPM_GLOBAL_CONFIG_NAME),
        "NPM_CONFIG_UPDATE_NOTIFIER": "false", "npm_config_offline": "true",
        "npm_config_cache": str(worker / ".npm-cache"),
        "npm_config_userconfig": str(worker / ".home" / NPM_USER_CONFIG_NAME),
        "npm_config_globalconfig": str(worker / ".home" / NPM_GLOBAL_CONFIG_NAME),
        "npm_config_update_notifier": "false", "PYTHONDONTWRITEBYTECODE": "1", "CI": "true",
    }
    npm = Path(npm_bin) / "npm"
    argv = (str(npm), "--prefix", "runtime", "run", "check:workspace")
    nonce = os.urandom(12).hex()
    try:
        result = linux_session.run_host(
            str(env.get("RUNNER_TEMP", "/tmp")), nonce,
            ("/usr/bin/python3", "-B", "-c", linux_probes.LAUNCHER_SOURCE, *argv),
            project_env, {}, limits=RUNTIME_GATE_LIMITS,
            timeout=RUNTIME_WORKSPACE_TIMEOUT_SECONDS, cwd=str(worker),
        )
    except BaseException:
        sys.stdout.write("linux-runtime-workspace=refused reason=launch\n")
        return 1
    records = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-runtime-workspace-records"
    records.mkdir(mode=0o700, parents=True, exist_ok=True)
    (records / "runtime.stdout").write_bytes(result.stdout)
    (records / "runtime.stderr").write_bytes(result.stderr)
    if result.exit_code != 0 or result.timed_out:
        reason = "timeout" if result.timed_out else _gate_cause(result)
        sys.stdout.write("linux-runtime-workspace=refused reason=" + reason + "\n")
        return 1
    sys.stdout.write("linux-runtime-workspace=passed network=disabled output=bounded\n")
    return 0


def _load_json(path):
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 65536:
            return None
        with os.fdopen(descriptor, "rt", encoding="ascii") as source:
            descriptor = -1
            value = json.loads(source.read(65537))
    except (OSError, UnicodeError, ValueError):
        return None
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    return value if type(value) is dict else None


def _handoff_record(records):
    path = records / "merged.json"
    try:
        info = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o600):
        return None
    return _load_json(path)


def verify_proof_handoff(environ=None):
    env = os.environ if environ is None else environ
    records = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-records"
    record = _handoff_record(records)
    if record is None or type(record.get("channels")) is not dict:
        raise SourceBuildRefusal("boundary")
    sys.stdout.write("linux-verifier-proof-handoff=readable owner=runner mode=0600\n")
    return 0


def _verified_gate_count(records, env):
    if not _api_feature_gate_readback(env):
        return 0
    gates = _load_json(records / "gates.json")
    revoke = _load_json(records / "revocation.json")
    if type(gates) is not dict or type(gates.get("selected_gates")) is not list:
        return 0
    selected_gates = tuple(gates["selected_gates"])
    expected_gate_sets = (
        GATES, GATES + RUNTIME_GATE_NAMES, GATES + BROWSER_GATE_NAMES, GATES + RUNTIME_GATE_NAMES + BROWSER_GATE_NAMES,
    )
    if (set(gates) != {
                "schema_version", "selected_gates", "completed_gates", "gates", "gate_count", "failed",
            }
            or selected_gates not in expected_gate_sets
            or not set(API_FEATURE_GATE_NAMES).issubset(selected_gates)
            or gates.get("completed_gates") != list(selected_gates)
            or revoke is None or gates.get("schema_version") != 1
            or type(gates.get("gates")) is not dict
            or set(gates["gates"]) != set(selected_gates)
            or any(gates["gates"][name] != "passed" for name in selected_gates)
            or type(gates.get("gate_count")) is not int
            or gates.get("gate_count") != len(selected_gates)
            or type(gates.get("failed")) is not int or gates.get("failed") != 0
            or revoke.get("schema_version") != 1 or revoke.get("status") != "confirmed"
            or revoke.get("control_sha") != env.get("CI_SHA")
            or revoke.get("run_id") != env.get("GITHUB_RUN_ID")
            or revoke.get("run_attempt") != env.get("GITHUB_RUN_ATTEMPT")
            or revoke.get("installation_id") != env.get("SOURCE_READER_INSTALLATION_ID")
            or revoke.get("rejected_after_revoke") is not True):
        return 0
    return len(selected_gates) - (len(BROWSER_GATE_NAMES) if selected_gates[-1:] == BROWSER_GATE_NAMES else 0)


def _verdict_record(environ):
    env = environ
    unused_audit, verdict, unused_canary = _audit_modules()
    records = Path(env.get("RUNNER_TEMP", "/tmp")) / "kd-records"
    merged = _handoff_record(records)
    try:
        mode = env.get("CI_MODE")
        if mode not in ("source", "synthetic"):
            raise ValueError
        if merged is None or type(merged.get("channels")) is not dict:
            raise ValueError
        channels = {
            name: {
                "status": merged["channels"][name]["status"],
                "before": merged["channels"][name]["before"],
                "after": merged["channels"][name]["after"],
            }
            for name in verdict.CHANNELS
        }
        memory = merged.get("memory_canary", "not-run")
        readable = merged.get("readable_file_canary", "not-run")
        verified_gates = _verified_gate_count(records, env) if mode == "source" else 0
        accepted_source = verified_gates > 0
        project = "completed" if accepted_source else "not_started"
        gate_count = verified_gates
        failed = 0
        token_state = "confirmed" if accepted_source else "not-applicable" if mode == "synthetic" else "unconfirmed"
        record = {
            "os": "linux", "boundary": "linux-ns-seccomp-uid",
            "control_sha": env.get("CI_SHA", ""),
            "run_id": int(env.get("GITHUB_RUN_ID", "0")),
            "run_attempt": int(env.get("GITHUB_RUN_ATTEMPT", "0")),
            "channels": channels,
            "memory_canary": memory,
            "readable_file_canary": readable,
            "handoff": "not-applicable",
            "project_execution": project,
            "gates": gate_count,
            "failed": failed,
            "token_revocation": token_state,
        }
    except BaseException:
        record = {
            "os": "linux", "boundary": "linux-ns-seccomp-uid",
            "control_sha": env.get("CI_SHA", "0" * 40),
            "run_id": int(env.get("GITHUB_RUN_ID", "1")) if DECIMAL_RE.fullmatch(env.get("GITHUB_RUN_ID", "")) else 1,
            "run_attempt": int(env.get("GITHUB_RUN_ATTEMPT", "1")) if DECIMAL_RE.fullmatch(env.get("GITHUB_RUN_ATTEMPT", "")) else 1,
            "channels": {name: {"status": "not-run", "before": False, "after": False} for name in verdict.CHANNELS},
            "memory_canary": "not-run", "readable_file_canary": "not-run",
            "handoff": "not-applicable", "project_execution": "not_started",
            "gates": 0, "failed": 0, "token_revocation": "not-applicable" if env.get("CI_MODE") == "synthetic" else "unconfirmed",
        }
    return record


def emit_verdict(environ=None):
    env = os.environ if environ is None else environ
    if _tier(env) == "quick":
        raise SourceBuildRefusal("identity")
    unused_audit, verdict, unused_canary = _audit_modules()
    record = _verdict_record(env)
    line = verdict.encode_line(record)
    sys.stdout.write(line + "\n")
    accepted = verdict.run_accepted(record) if env.get("CI_MODE") == "source" else verdict.confinement_accepted(record)
    return 0 if accepted and env.get("PRODUCER_RESULT") == "success" else 1


def run_audit(environ=None):
    env = os.environ if environ is None else environ
    try:
        audit, unused_verdict, log_canary = _audit_modules()
        value = env.get("KD_LINUX_LOG_CANARY", "")
        if env.get("CI_MODE") == "synthetic":
            value = SYNTHETIC_LOG_CANARY
        config = log_canary.compute_config(value)
        log_canary.PINNED_CONFIG = config
        code = audit.main(arguments=["quick"] if _tier(env) == "quick" else [], environ=env)
        return code
    except BaseException:
        sys.stdout.write("KD-CONFINEMENT-AUDIT schema=1 status=refused phase=log_canary reason=confinement_audit_invalid\n")
        return 1


def _dispatch(command):
    actions = {
        "rust-cache-key": write_rust_cache_key,
        "rust-cache-export": export_rust_cache,
        "rust-cache-import": import_rust_cache,
        "rust-cache-package": package_rust_cache,
        "snapshot": snapshot_and_preflight,
        "audit-expected": write_audit_identity,
        "preflight": repeat_preflight,
        "dependency-preflight": verify_dependency_preflight,
        "windows-snapshot": windows_snapshot,
        "windows-preflight": windows_preflight,
        "toolchains": prepare_toolchains,
        "mint-verifier-token": mint_verifier_token,
        "checkout": checkout_source,
        "revoke": revoke_token,
        "npm-tarballs": fetch_npm_tarballs,
        "rust-lock-fetch": fetch_cargo_locks,
        "prepare-project": prepare_project,
        "verify-source-reader": verify_source_reader,
        "dependency-locked-builds": run_dependency_locked_builds,
        "gates": run_project_gates,
        "runtime-workspace": run_runtime_workspace,
        "verify-handoff": verify_proof_handoff,
        "verdict": emit_verdict,
        "audit": run_audit,
    }
    action = actions.get(command)
    if action is None:
        return 2
    try:
        return action()
    except SourceBuildRefusal as error:
        sys.stdout.write(_refusal_line(command, error))
        return 1
    except BaseException:
        sys.stdout.write(_refusal_line(command, SourceBuildRefusal("invalid")))
        return 1


def main(arguments=None):
    actual = sys.argv[1:] if arguments is None else arguments
    if len(actual) != 1:
        return 2
    return _dispatch(actual[0])


if __name__ == "__main__":
    raise SystemExit(main())
