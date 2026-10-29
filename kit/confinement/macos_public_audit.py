import base64
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


REPOSITORY = "keeldock-platform/platform-ci"
APPROVED_HOST_RELEASES = (
    ("15.7.9", "20260907.0337.1"),
    ("15.8.2", "20261028.0489.1"),
)
APPROVED_HOST_RELEASE_FIRST_RUNS = {("15.8.2", "20261028.0489.1"): "40941660825"}
WORKFLOW_PATH = ".github/workflows/macos-capability.yml"
NATIVE_JOB_NAME = "macos-capability"
REVIEWED_WORKFLOW_PATH = ".github/workflows/macos-reviewed-build.yml"
REVIEWED_SNAPSHOT_JOB_NAME = "macos-public-snapshot"
REVIEWED_SMOKE_JOB_NAME = "macos-reviewed-smoke"
REVIEWED_AUDIT_JOB_NAME = "macos-public-surface-audit"
RUST_TOOLCHAIN_WORKFLOW_PATH = ".github/workflows/macos-rust-toolchain-smoke.yml"
RUST_TOOLCHAIN_SNAPSHOT_JOB_NAME = "macos-rust-toolchain-snapshot"
RUST_TOOLCHAIN_SMOKE_JOB_NAME = "macos-rust-toolchain-smoke"
RUST_TOOLCHAIN_AUDIT_JOB_NAME = "macos-rust-toolchain-audit"
CORE_CONTRACT_WORKFLOW_PATH = ".github/workflows/macos-core-contract.yml"
CORE_CONTRACT_SETTINGS_JOB_NAME = "macos-core-contract-settings"
CORE_CONTRACT_PRODUCER_JOB_NAME = "macos-core-contract"
CORE_CONTRACT_AUDIT_JOB_NAME = "macos-core-contract-audit"
CACHE_PROOF_WORKFLOW_PATH = ".github/workflows/macos-cache-proof.yml"
CACHE_PROOF_SNAPSHOT_JOB_NAME = "macos-cache-public-snapshot"
CACHE_PROOF_SEED_JOB_NAME = "macos-cache-seed"
CACHE_PROOF_POSITIVE_JOB_NAME = "macos-cache-positive"
CACHE_PROOF_NONE_JOB_NAME = "macos-cache-none-probe"
CACHE_PROOF_AUDIT_JOB_NAME = "macos-cache-public-audit"
CACHE_PROOF_CLEANUP_JOB_NAME = "macos-cache-cleanup"
CACHE_PROOF_ACTION_SHA = "3edfce9056124e459a23f683a21433670d47daca"
CACHE_PROOF_SEED_KEY_PREFIX = "macos-public-cache-seed-v1-"
CACHE_PROOF_NONE_WRITE_KEY_PREFIX = "macos-public-cache-none-write-v1-"
SOURCE_READER_ACTION_SHA = "64ab729a6294000f5aa4a4bc0b73d1f32bc45510"
BOOTSTRAP_SOURCE_REPOSITORY_IDS = {
    "rules-bootstrap": "1428198872",
    "core-bootstrap": "1430959909",
    "core-contract": "1430959909",
}
SOURCE_READER_CONFIGURATIONS = {
    "core": {
        "workflow_path": ".github/workflows/macos-source-reader-preflight.yml",
        "environment_name": "source-read",
        "environment_id": 25337167708,
        "branch_policy_id": 64386356,
    },
    "rules": {
        "workflow_path": ".github/workflows/macos-rules-reader-preflight.yml",
        "environment_name": "rules-source-read",
        "environment_id": 25357465381,
        "branch_policy_id": 64411429,
    },
    "rules-bootstrap": {
        "workflow_path": ".github/workflows/macos-rules-bootstrap.yml",
        "environment_name": "rules-source-read",
        "environment_id": 25357465381,
        "branch_policy_id": 64411429,
    },
    "core-bootstrap": {
        "workflow_path": ".github/workflows/macos-core-bootstrap.yml",
        "environment_name": "source-read",
        "environment_id": 25337167708,
        "branch_policy_id": 64386356,
    },
    "core-contract": {
        "workflow_path": CORE_CONTRACT_WORKFLOW_PATH,
        "environment_name": "source-read",
        "environment_id": 25337167708,
        "branch_policy_id": 64386356,
    },
}
SOURCE_READER_PHASES = {
    "source-reader-settings-core": ("settings", "core"),
    "source-reader-snapshot-core": ("snapshot", "core"),
    "source-reader-audit-core": ("audit", "core"),
    "source-reader-settings-rules": ("settings", "rules"),
    "source-reader-snapshot-rules": ("snapshot", "rules"),
    "source-reader-audit-rules": ("audit", "rules"),
    "rules-bootstrap-settings": ("settings", "rules-bootstrap"),
    "rules-bootstrap-snapshot": ("snapshot", "rules-bootstrap"),
    "rules-bootstrap-audit": ("bootstrap-audit", "rules-bootstrap"),
    "core-bootstrap-settings": ("settings", "core-bootstrap"),
    "core-bootstrap-snapshot": ("snapshot", "core-bootstrap"),
    "core-bootstrap-audit": ("bootstrap-audit", "core-bootstrap"),
    "core-contract-settings": ("settings", "core-contract"),
    "core-contract-snapshot": ("snapshot", "core-contract"),
    "core-contract-audit": ("contract-audit", "core-contract"),
}
SOURCE_READER_SETTINGS_JOB_NAME = "macos-source-reader-settings"
SOURCE_READER_TOKEN_JOB_NAME = "macos-source-reader-token"
SOURCE_READER_AUDIT_JOB_NAME = "macos-source-reader-audit"
RULES_BOOTSTRAP_SETTINGS_JOB_NAME = "macos-rules-bootstrap-settings"
RULES_BOOTSTRAP_PRODUCER_JOB_NAME = "macos-rules-bootstrap"
RULES_BOOTSTRAP_AUDIT_JOB_NAME = "macos-rules-bootstrap-audit"
CORE_BOOTSTRAP_SNAPSHOT_JOB_NAME = "macos-public-snapshot"
CORE_BOOTSTRAP_PRODUCER_JOB_NAME = "macos-core-bootstrap"
CORE_BOOTSTRAP_AUDIT_JOB_NAME = "macos-core-bootstrap-audit"
CORE_CONTRACT_SNAPSHOT_JOB_NAME = CORE_CONTRACT_SETTINGS_JOB_NAME
SOURCE_READER_SUCCESS_RECORD = (
    b'{"metadata":"verified","reason":"ok","repository_scope":"verified",'
    b'"revocation":"confirmed","schema_version":1,"status":"passed"}'
)
_GITHUB_LOG_TIMESTAMP = (
    rb"(?:[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    rb"(?:\.[0-9]+)?Z )?"
)
RUST_TOOLCHAIN_SUCCESS_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"KD-RUST-SMOKE (\{[^\r\n]{1,16384}\})(?=\r?(?:\n|$))"
)
RUST_TOOLCHAIN_REFUSAL_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"KD-RUST-REFUSAL reason=(invalid_input|unsupported_host|runner_unavailable|"
    rb"download_unavailable|archive_hash_mismatch|archive_invalid|install_failed|"
    rb"version_mismatch|target_unavailable|smoke_failed|capture_invalid|"
    rb"cleanup_incomplete|internal_error)(?=\r?(?:\n|$))"
)
SOURCE_READER_INSTALLATION_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"macos-source-reader-installation=verified schema=1 control-sha=([a-f0-9]{40}) "
    rb"run-id=([1-9][0-9]{0,18}) run-attempt=([1-9][0-9]{0,18}) "
    rb"installation-id=([1-9][0-9]{0,18})(?=\r?(?:\n|$))"
)
SOURCE_READER_SCOPE_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"macos-source-reader-scope=verified schema=1 action-sha="
    + SOURCE_READER_ACTION_SHA.encode("ascii")
    + rb" control-sha=([a-f0-9]{40}) "
    rb"run-id=([1-9][0-9]{0,18}) run-attempt=([1-9][0-9]{0,18}) "
    rb"installation-id=([1-9][0-9]{0,18}) repository-id=([1-9][0-9]{0,18}) "
    rb"repositories=1 permission=contents-read metadata=verified revocation=confirmed "
    rb"source-content=not-read(?=\r?(?:\n|$))"
)
SOURCE_READER_SUCCESS_RECORD_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP + re.escape(SOURCE_READER_SUCCESS_RECORD)
    + rb"(?=\r?(?:\n|$))"
)
API_ORIGIN = "https://api.github.com"
API_HOST = "api.github.com"
API_VERSION = "2022-11-28"
PAGE_SIZE = 100
MAX_API_BYTES = 2 * 1024 * 1024
MAX_TOTAL_API_BYTES = 16 * 1024 * 1024
MAX_LOG_BYTES = 32 * 1024 * 1024
MAX_CACHE_ITEMS = 10000
MAX_ARTIFACT_ITEMS = 1000
MAX_ANNOTATIONS = 10000
MAX_PAGES = 100
MAX_WORKFLOW_RUNS = PAGE_SIZE * MAX_PAGES
MAX_RECEIPT_BYTES = 16 * 1024
MAX_RUST_TOOLCHAIN_CAPTURE_BYTES = 16 * 1024
MAX_CORE_CONTRACT_CAPTURE_BYTES = 8192
MAX_CORE_CONTRACT_REFUSAL_BYTES = 512
ACTIVE_WORKFLOW_RUN_STATUSES = frozenset(
    ("queued", "in_progress", "waiting", "pending", "requested")
)
KNOWN_WORKFLOW_RUN_STATUSES = ACTIVE_WORKFLOW_RUN_STATUSES | {"completed"}
CONTROL_SHA_RE = re.compile(r"[a-f0-9]{40}\Z")
TOKEN_RE = re.compile(r"[A-Za-z0-9_./-]{20,512}\Z")
DECIMAL_RE = re.compile(r"[1-9][0-9]{0,18}\Z")
HEX_DIGEST_RE = re.compile(r"[a-f0-9]{64}\Z")
CACHE_PROOF_CLIENT_MARKER_RE = re.compile(
    rb"macos-cache-client=(read|write)-denied schema=1 action-sha="
    + CACHE_PROOF_ACTION_SHA.encode("ascii")
    + rb" key=(macos-public-cache-(?:seed-v1|none-write-v1)-[1-9][0-9]{0,18}-[1-9][0-9]{0,18}) "
    rb"control-sha=([a-f0-9]{40}) run-id=([1-9][0-9]{0,18}) "
    rb"run-attempt=([1-9][0-9]{0,18}) node=(24\.[0-9]+\.[0-9]+)"
    rb"(?=\r?(?:\n|$))"
)
REVIEWED_SMOKE_MARKER_RE = re.compile(
    rb"macos-build=synthetic-smoke-passed schema=1 source=none "
    rb"control-sha=([a-f0-9]{40}) run-id=([1-9][0-9]{0,18}) "
    rb"run-attempt=([1-9][0-9]{0,18}) "
    rb"image-os=(macos-?[0-9]{1,2}(?:-(?:arm64|x64|intel))?) "
    rb"image-version=[0-9]+(?:\.[0-9]+){1,3} "
    rb"macos-version=[0-9]+\.[0-9]+(?:\.[0-9]+)? "
    rb"architecture=(?:arm64|x86_64) "
    rb"(?:xcode=not-used xcode-build=not-used compiler-origin=command-line-tools|"
    rb"xcode=[0-9]+(?:\.[0-9]+){0,3} xcode-build=[A-Za-z0-9.]+ compiler-origin=xcode) "
    rb"clang=[0-9]+(?:\.[0-9]+){0,3} sdk=[0-9]+(?:\.[0-9]+){0,3} "
    rb"developer-mode=disabled privilege=separate-nonadmin sudo=denied "
    rb"compile=passed link=passed load-test=passed capture=passed "
    rb"summary-standin=write-denied real-summary=write-denied "
    rb"cleanup=complete seatbelt=not-run pf=not-run"
    rb"(?=\r?(?:\n|$))"
)
REVIEWED_NETWORK_SELFTEST_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"macos-network-observer=selftest-passed schema=1 mode=host-level "
    rb"control-sha=([a-f0-9]{40}) run-id=([1-9][0-9]{0,18}) "
    rb"run-attempt=([1-9][0-9]{0,18}) source-sha=none interface-count=1 "
    rb"dns-query-count=([1-9][0-9]{0,4}) tcp-syn-count=([1-9][0-9]{0,4}) "
    rb"dns-name-hashes=([a-f0-9]{64}(?:,[a-f0-9]{64}){0,15}) "
    rb"tcp-destination-hashes=([a-f0-9]{64}(?:,[a-f0-9]{64}){0,15}) "
    rb"hashes-truncated=(true|false) capture=private capture-limited=false cleanup=complete "
    rb"worker-attribution=not-claimed completeness=not-claimed "
    rb"network-blocking=not-claimed(?=\r?(?:\n|$))"
)
REVIEWED_SUMMARY_CONTROL_MARKER_RE = re.compile(
    rb"(?m)^(?:[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    rb"(?:\.[0-9]+)?Z )?macos-summary-control=trusted-write schema=1 "
    rb"control-sha=([a-f0-9]{40}) run-id=([1-9][0-9]{0,18}) "
    rb"run-attempt=([1-9][0-9]{0,18})(?=\r?(?:\n|$))"
)
RULES_BOOTSTRAP_PREFLIGHT_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"macos-rules-bootstrap=preflight-passed schema=1 control-sha=([a-f0-9]{40}) "
    rb"run-id=([1-9][0-9]{0,18}) run-attempt=([1-9][0-9]{0,18}) "
    rb"source-sha=([a-f0-9]{40}) base-sha=([a-f0-9]{40}) base-branch=(main|develop|uat) "
    rb"dash-version=0\.5\.13\.5 dash-bottle-sha256=0e104457d0d188129596ee04e4f88ab6039baf9a03e183820caf0aa333d581d0 "
    rb"dash-binary-sha256=([a-f0-9]{64}) reviewed-diff-sha256=([a-f0-9]{64})"
    rb"(?=\r?(?:\n|$))"
)
RULES_BOOTSTRAP_SUCCESS_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"macos-rules-bootstrap=passed schema=1 control-sha=([a-f0-9]{40}) "
    rb"run-id=([1-9][0-9]{0,18}) run-attempt=([1-9][0-9]{0,18}) "
    rb"source-sha=([a-f0-9]{40}) base-sha=([a-f0-9]{40}) base-branch=(main|develop|uat) "
    rb"candidate-class=(permanent-tip|signed-descendant) "
    rb"suites=rules\.hooks,rules\.sync,rules\.static,rules\.public,plan-ids "
    rb"token-revocation=confirmed-before-execution lease-cleanup=complete "
    rb"process-cleanup=complete identity-cleanup=complete "
    rb"summary-guard=append-sibling-create-readback-restore source-tree=uid-read-only "
    rb"dash-version=0\.5\.13\.5 dash-bottle-sha256=0e104457d0d188129596ee04e4f88ab6039baf9a03e183820caf0aa333d581d0 "
    rb"dash-binary-sha256=([a-f0-9]{64}) reviewed-diff-sha256=([a-f0-9]{64}) "
    rb"same-job-memory=not-verified(?=\r?(?:\n|$))"
)
RULES_BOOTSTRAP_NETWORK_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"macos-rules-network=observed schema=1 mode=host-level "
    rb"control-sha=([a-f0-9]{40}) run-id=([1-9][0-9]{0,18}) "
    rb"run-attempt=([1-9][0-9]{0,18}) source-sha=([a-f0-9]{40}) "
    rb"interface-count=([1-4]) dns-query-count=(0|[1-9][0-9]{0,4}) "
    rb"tcp-syn-count=(0|[1-9][0-9]{0,4}) "
    rb"dns-name-hashes=(none|[a-f0-9]{64}(?:,[a-f0-9]{64}){0,15}) "
    rb"tcp-destination-hashes=(none|[a-f0-9]{64}(?:,[a-f0-9]{64}){0,15}) "
    rb"hashes-truncated=(true|false) capture-limited=(true|false) "
    rb"capture=private cleanup=complete worker-attribution=not-claimed "
    rb"completeness=not-claimed network-blocking=not-claimed(?=\r?(?:\n|$))"
)
RULES_BOOTSTRAP_SUMMARY_CONTROL_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"macos-rules-summary-control=trusted-write schema=1 control-sha=([a-f0-9]{40}) "
    rb"run-id=([1-9][0-9]{0,18}) run-attempt=([1-9][0-9]{0,18}) "
    rb"source-sha=([a-f0-9]{40}) base-sha=([a-f0-9]{40}) reviewed-diff-sha256=([a-f0-9]{64})"
    rb"(?=\r?(?:\n|$))"
)
RULES_BOOTSTRAP_EARLY_SOURCE_REASONS = (
    "invalid_input",
    "context_unavailable",
    "configuration_unavailable",
    "source_reader_unavailable",
    "repository_scope_invalid",
    "source_fetch_unavailable",
    "revocation_unconfirmed",
    "base_invalid",
    "signature_invalid",
    "revocation_policy_invalid",
    "bootstrap_snapshot_invalid",
    "bootstrap_not_approved",
    "internal_error",
)
RULES_BOOTSTRAP_EARLY_SOURCE_REFUSAL_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"macos-rules-bootstrap=refused schema=1 reason=("
    + b"|".join(re.escape(reason.encode("ascii")) for reason in RULES_BOOTSTRAP_EARLY_SOURCE_REASONS)
    + rb") stage=source_lease control-sha=([a-f0-9]{40}) "
    rb"run-id=([1-9][0-9]{0,18}) run-attempt=([1-9][0-9]{0,18}) "
    rb"token-revocation=confirmed(?=\r?(?:\n|$))"
)
RULES_BOOTSTRAP_SOURCE_BINDING_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"macos-rules-source-binding=verified schema=1 control-sha=([a-f0-9]{40}) "
    rb"run-id=([1-9][0-9]{0,18}) run-attempt=([1-9][0-9]{0,18}) "
    rb"repository-id=([1-9][0-9]{0,18})(?=\r?(?:\n|$))"
)
CORE_BOOTSTRAP_PREFLIGHT_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"macos-core-bootstrap=preflight-passed schema=1 control-sha=([a-f0-9]{40}) "
    rb"run-id=([1-9][0-9]{0,18}) run-attempt=([1-9][0-9]{0,18}) "
    rb"source-sha=([a-f0-9]{40}) runner-summary=append-denied "
    rb"summary-sibling=create-denied summary-standin=write-denied cleanup=complete"
    rb"(?=\r?(?:\n|$))"
)
CORE_BOOTSTRAP_SUCCESS_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"macos-core-bootstrap=verified schema=1 control-sha=([a-f0-9]{40}) "
    rb"run-id=([1-9][0-9]{0,18}) run-attempt=([1-9][0-9]{0,18}) "
    rb"image-os=(macos-?[0-9]{1,2}(?:-(?:arm64|x64|intel))?) "
    rb"image-version=([0-9]+(?:\.[0-9]+){1,3}) "
    rb"source-repository-id=([1-9][0-9]{0,18}) source-sha=([a-f0-9]{40}) "
    rb"base-branch=main base-sha=([a-f0-9]{40}) concern=core-bootstrap "
    rb"source-signature=verified token-revocation=confirmed-before-execution "
    rb"rules-lock=present rules-lock-signature=declared-verified "
    rb"lock-format=3 manifest=matched signers-hash=well-formed fragment-hash=well-formed "
    rb"source-execution=not-run app-build=not-run worker-access=not-applicable cleanup=complete "
    rb"summary-control=append-denied summary-sibling=create-denied "
    rb"summary-standin=write-denied summary-sentinel=written(?=\r?(?:\n|$))"
)
CORE_BOOTSTRAP_SOURCE_BINDING_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"macos-core-source-binding=verified schema=1 control-sha=([a-f0-9]{40}) "
    rb"run-id=([1-9][0-9]{0,18}) run-attempt=([1-9][0-9]{0,18}) "
    rb"repository-id=([1-9][0-9]{0,18})(?=\r?(?:\n|$))"
)
CORE_CONTRACT_BINDING_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"macos-core-contract-binding=verified schema=1 control-sha=([a-f0-9]{40}) "
    rb"run-id=([1-9][0-9]{0,18}) run-attempt=([1-9][0-9]{0,18}) "
    rb"source-sha=([a-f0-9]{40}) base-sha=([a-f0-9]{40}) "
    rb"base-branch=(main|develop|uat) candidate-class=(permanent-tip|signed-descendant) "
    rb"reviewed-diff-sha256=([a-f0-9]{64})(?=\r?(?:\n|$))"
)
CORE_CONTRACT_READER_SCOPE_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"macos-core-contract-reader-scope=verified schema=1 control-sha=([a-f0-9]{40}) "
    rb"run-id=([1-9][0-9]{0,18}) run-attempt=([1-9][0-9]{0,18}) "
    rb"repository-id=([1-9][0-9]{0,18})(?=\r?(?:\n|$))"
)
CORE_CONTRACT_READER_INSTALLATION_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"macos-core-contract-reader-installation=verified schema=1 control-sha=([a-f0-9]{40}) "
    rb"run-id=([1-9][0-9]{0,18}) run-attempt=([1-9][0-9]{0,18}) "
    rb"installation-id=([1-9][0-9]{0,18})(?=\r?(?:\n|$))"
)
CORE_CONTRACT_SUCCESS_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"KD-CORE-CONTRACT (\{[^\r\n]{1,8192}\})(?=\r?(?:\n|$))"
)
CORE_CONTRACT_REFUSAL_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"KD-CORE-CONTRACT-REFUSAL (\{[^\r\n]{1,512}\})(?=\r?(?:\n|$))"
)
CORE_CONTRACT_SUMMARY_CONTROL_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"macos-core-contract-summary-control=trusted-write schema=1 "
    rb"control-sha=([a-f0-9]{40}) run-id=([1-9][0-9]{0,18}) "
    rb"run-attempt=([1-9][0-9]{0,18}) source-sha=([a-f0-9]{40}) "
    rb"base-sha=([a-f0-9]{40}) reviewed-diff-sha256=([a-f0-9]{64})"
    rb"(?=\r?(?:\n|$))"
)
CORE_CONTRACT_CLEANUP_MARKER_RE = re.compile(
    rb"(?m)^" + _GITHUB_LOG_TIMESTAMP
    + rb"macos-core-contract-cleanup=(confirmed|unconfirmed) schema=1 "
    rb"control-sha=([a-f0-9]{40}) run-id=([1-9][0-9]{0,18}) "
    rb"run-attempt=([1-9][0-9]{0,18})(?=\r?(?:\n|$))"
)
CORE_CONTRACT_REFUSAL_REASONS = frozenset((
    "invalid_input", "unsupported_host", "runner_unavailable", "source_validation_failed",
    "token_revocation_unconfirmed", "source_binding_mismatch", "source_diff_mismatch",
    "toolchain_install_failed", "toolchain_version_mismatch", "gate_failed",
    "network_observation_failed", "summary_guard_failed", "capture_invalid",
    "cleanup_incomplete", "internal_error",
))
CORE_CONTRACT_REFUSAL_STAGES = frozenset((
    "arguments", "context", "host", "source_validation", "source_lease", "source_tree",
    "source_diff", "toolchain_install", "worker_setup", "summary_guard", "observer",
    "format", "clippy", "workspace_tests", "api_tests", "mock_tests",
    "conformance_tests", "cleanup", "receipt", "internal",
))
CORE_CONTRACT_RUNTIME_REASONS = frozenset((
    "invalid_input", "context_unavailable", "configuration_unavailable",
    "source_reader_unavailable", "repository_scope_invalid", "source_fetch_unavailable",
    "revocation_unconfirmed", "base_invalid", "signature_invalid", "revocation_policy_invalid",
    "bootstrap_snapshot_invalid", "bootstrap_not_approved", "cleanup_incomplete", "internal_error",
))
CORE_CONTRACT_RUNTIME_STAGES = frozenset((
    "input", "context", "configuration", "source_scope", "fetch", "revoke",
    "history", "signature", "revocation", "bootstrap", "cleanup",
))
CORE_CONTRACT_FETCH_OPERATIONS = frozenset((
    "git_init", "remote_add", "base_fetch", "base_ref", "candidate_fetch",
    "source_ref", "shallow_check", "remote_remove", "source_snapshot",
))
CORE_CONTRACT_FETCH_CLASSES = frozenset((
    "exit_nonzero", "stderr_present", "process_failure", "unexpected_exception",
))
CORE_CONTRACT_BOOTSTRAP_CHECKS = frozenset((
    "tree_entries", "required_files", "path_mode", "base_policy", "rules_manifest",
    "rules_inventory", "rules_hash", "workspace_decode", "workspace_members",
    "cargo_lock_decode", "cargo_lock_shape", "toolchain", "package_decode",
    "package_build", "checkout", "lease_paths", "lease_acl", "lease_access", "lease_census",
))
CORE_CONTRACT_SOURCE_LEASE_OPEN_CLASSES = frozenset((
    "type_error", "attribute_error", "value_error", "permission_error", "not_found",
    "timeout", "os_error", "other",
))
CORE_CONTRACT_RUNTIME_DIAGNOSTICS = frozenset(
    "source_runtime_" + stage + "_" + reason
    for stage in CORE_CONTRACT_RUNTIME_STAGES
    for reason in CORE_CONTRACT_RUNTIME_REASONS
)
CORE_CONTRACT_FETCH_DIAGNOSTICS = frozenset(
    "source_fetch_" + operation + "_" + failure_class
    for operation in CORE_CONTRACT_FETCH_OPERATIONS
    for failure_class in CORE_CONTRACT_FETCH_CLASSES
)
CORE_CONTRACT_BOOTSTRAP_DIAGNOSTICS = frozenset(
    "source_bootstrap_" + check for check in CORE_CONTRACT_BOOTSTRAP_CHECKS
)
CORE_CONTRACT_SOURCE_LEASE_OPEN_DIAGNOSTICS = frozenset(
    "source_lease_open_" + error_class for error_class in CORE_CONTRACT_SOURCE_LEASE_OPEN_CLASSES
)
CORE_CONTRACT_GATE_DIAGNOSTICS = frozenset((
    "source_gate_spawn_failure", "source_gate_nonzero_exit", "source_gate_helper_failure",
    "source_gate_capture_invalid", "source_gate_capture_overflow",
))
CORE_CONTRACT_GATE_STAGES = frozenset((
    "format", "clippy", "workspace_tests", "api_tests", "mock_tests", "conformance_tests",
))
CORE_CONTRACT_SOURCE_GATES_SURVIVOR_CLASSES = (
    "python", "ps", "developer_shim", "helper_preferences", "helper_notifications",
    "helper_launch_services", "helper_security", "helper_trust", "helper_containers",
    "apple_system_path", "other", "unknown", "additional",
)
CORE_CONTRACT_SOURCE_GATES_CLEANUP_DIAGNOSTICS = frozenset(
    "source_gates_survivor_" + category for category in CORE_CONTRACT_SOURCE_GATES_SURVIVOR_CLASSES
) | frozenset((
    "source_gates_survivor_multiple", "source_gates_timeout", "source_gates_census",
    "source_gates_group_cleanup", "source_gates_capture_cleanup", "source_gates_restore",
    "source_gates_cleanup_unclassified", "source_gates_wait_uncertain",
    "source_gates_audit_request",
))
CORE_CONTRACT_SOURCE_GATES_NODE_REASONS_BY_SUBSTAGE = (
    ("none", (
        "invalid_input", "tool_unavailable", "accepted_provenance_invalid", "lock_missing",
        "lock_already_present", "manifest_invalid", "limit_exceeded", "deadline_exceeded",
        "capture_invalid", "contract_refused",
    )),
    ("runtime_version", (
        "toolchain_mismatch", "command_failed", "capture_invalid", "tool_unavailable",
        "deadline_exceeded",
    )),
    ("npm_version", (
        "toolchain_mismatch", "command_failed", "capture_invalid", "tool_unavailable",
        "deadline_exceeded",
    )),
    ("lock_generation", (
        "command_failed", "capture_invalid", "tool_unavailable", "deadline_exceeded",
    )),
    ("lock_validation", ("accepted_provenance_invalid",)),
    ("bulk_audit", (
        "limit_exceeded", "manifest_invalid", "lock_missing", "accepted_provenance_invalid",
        "audit_unavailable", "audit_response_invalid", "vulnerable_dependency",
        "deadline_exceeded", "capture_invalid", "command_failed", "tool_unavailable",
    )),
    ("npm_ci", ("command_failed", "capture_invalid", "tool_unavailable", "deadline_exceeded")),
    ("typecheck", ("command_failed", "capture_invalid", "tool_unavailable", "deadline_exceeded")),
    ("tests", ("command_failed", "capture_invalid", "tool_unavailable", "deadline_exceeded")),
)
CORE_CONTRACT_SOURCE_GATES_NODE_COMMAND_SUBSTAGES = (
    "runtime_version", "npm_version", "lock_generation", "bulk_audit", "npm_ci", "typecheck",
    "tests",
)
CORE_CONTRACT_SOURCE_GATES_NODE_COMMAND_CHECKS = (
    "spawn_failure", "nonzero_exit", "timeout", "capture_invalid", "capture_overflow",
    "helper_failure",
)
CORE_CONTRACT_SOURCE_GATES_NODE_DIAGNOSTIC_REASONS = {
    **{
        "source_gates_node_" + substage + "_" + reason:
            "capture_invalid" if reason == "capture_invalid" else "runner_unavailable"
        for substage, reasons in CORE_CONTRACT_SOURCE_GATES_NODE_REASONS_BY_SUBSTAGE
        for reason in reasons
    },
    **{
        "source_gates_node_" + substage + "_command_" + check: "runner_unavailable"
        for substage in CORE_CONTRACT_SOURCE_GATES_NODE_COMMAND_SUBSTAGES
        for check in CORE_CONTRACT_SOURCE_GATES_NODE_COMMAND_CHECKS
    },
}
CORE_CONTRACT_SOURCE_GATES_NODE_DIAGNOSTICS = frozenset(
    CORE_CONTRACT_SOURCE_GATES_NODE_DIAGNOSTIC_REASONS
)
CORE_CONTRACT_FOREIGN_CONTEXT_DIAGNOSTICS = frozenset((
    "context_guard_platform_unapproved", "context_guard_preflight_unavailable",
    "context_guard_pf_unavailable", "context_guard_pf_rules_unexpected",
    "context_guard_cleanup_incomplete", "context_rust_invalid_input",
    "context_rust_runner_unavailable", "context_rules_control_identity_invalid",
    "context_rules_context_unavailable",
))
CORE_CONTRACT_REFUSAL_DIAGNOSTICS = frozenset((
    "none", "unavailable", "load_controls", "review_binding", "host_preflight",
    "temp_root_check", "smoke_receipt", "token_input", "token_revocation",
    "disable_developer_mode", "resolve_host_toolchain", "resolve_worker_tools",
    "create_worker_identity", "create_run_directory", "create_source_storage",
    "prepare_worker_storage", "worker_identity_check", "worker_privilege_probe",
    "worker_privilege_probe_group_cleanup", "worker_privilege_probe_capture_cleanup",
    "worker_privilege_probe_census", "worker_privilege_probe_survivor",
    "worker_privilege_probe_timeout",
    "worker_privilege_census", "summary_guard_setup", "source_lease_request",
    "source_lease_open", "source_revocation_check", "source_lease_record",
    "source_path_validation", "source_tree_probe", "resolve_git", "git_diff_verification",
    "network_observer_start", "toolchain_install", "toolchain_tree_check",
    "worker_environment", "toolchain_version_probe", "toolchain_version_match",
    "source_gates", "worker_storage_verify", "cwd_restore", "network_observer_finish",
    "summary_guard_probe", "source_lease_cleanup", "worker_cleanup",
    "fallback_tree_cleanup", "summary_guard_finish", "success_receipt", "output_write",
    "cleanup_lease", "cleanup_storage", "cleanup_worker", "cleanup_summary",
    "cleanup_summary_census", "cleanup_summary_present", "cleanup_summary_present_python",
    "cleanup_summary_present_ps", "cleanup_summary_present_developer_shim",
    "cleanup_summary_present_helper_preferences", "cleanup_summary_present_helper_notifications",
    "cleanup_summary_present_helper_launch_services", "cleanup_summary_present_helper_security",
    "cleanup_summary_present_helper_trust", "cleanup_summary_present_helper_containers",
    "cleanup_summary_present_apple_system_path", "cleanup_summary_probe",
    "cleanup_summary_restore", "cleanup_summary_close", "cleanup_dash", "cleanup_unknown",
)) | (
    CORE_CONTRACT_RUNTIME_DIAGNOSTICS | CORE_CONTRACT_FETCH_DIAGNOSTICS
    | CORE_CONTRACT_BOOTSTRAP_DIAGNOSTICS | CORE_CONTRACT_SOURCE_LEASE_OPEN_DIAGNOSTICS
    | CORE_CONTRACT_GATE_DIAGNOSTICS | CORE_CONTRACT_SOURCE_GATES_CLEANUP_DIAGNOSTICS
    | CORE_CONTRACT_SOURCE_GATES_NODE_DIAGNOSTICS | CORE_CONTRACT_FOREIGN_CONTEXT_DIAGNOSTICS
)
CORE_CONTRACT_PRIVILEGE_PROBE_DIAGNOSTICS = frozenset((
    "worker_privilege_probe_group_cleanup", "worker_privilege_probe_capture_cleanup",
    "worker_privilege_probe_census", "worker_privilege_probe_survivor",
    "worker_privilege_probe_timeout",
))
CANARY_DOMAIN = b"keeldock" + b"-macos-ci-canary-v1\0"
CANARY_PREFIX = b"KD-MACOS-CI-CANARY-v1:"
REVIEWED_CANARY_PREFIX = b"KD-RB-CANARY-"
REVIEWED_SUMMARY_DIRECT_CANARY = b"KD-RB-SUMMARY-DIRECT-WRITE-CANARY-v1"
CANARY_COMMANDS = (
    b"::error file=canary.txt,line=1::",
    b"::warning::",
    b"::add-mask::",
    b"::set-output name=leak::",
    b"::group::",
    b"::endgroup::",
)
EXPECTED_CHANNELS = {
    "https": "blocked",
    "dns": "blocked",
    "redirect": "blocked",
    "proxy": "blocked",
    "runner_ipc": "blocked",
    "raw_logs": "captured_private",
    "artifact_upload": "pending_audit",
    "cache_upload": "pending_audit",
    "runner_files": "blocked",
    "process_memory": "blocked",
    "boundary_disablement": "blocked",
}
REASONS = frozenset(
    (
        "invalid_input",
        "api_unavailable",
        "api_status",
        "api_schema",
        "run_identity_mismatch",
        "pagination_incomplete",
        "inventory_changed",
        "artifact_found",
        "log_unavailable",
        "log_too_large",
        "log_format_unknown",
        "canary_exposed",
        "workflow_command_exposed",
        "receipt_invalid",
        "capture_invalid",
        "native_job_failed",
        "output_unavailable",
        "internal_error",
    )
)
CORE_CONTRACT_AUDIT_DIAGNOSTICS = frozenset((
    "run_validation_identity",
    "audit_job_run_id_mismatch",
    "audit_job_run_attempt_mismatch",
    "audit_job_head_sha_mismatch",
    "audit_job_status_queued",
    "audit_job_status_completed",
    "audit_job_status_not_in_progress",
))


class AuditRefusal(Exception):
    def __init__(self, reason):
        super().__init__()
        self.reason = reason if reason in REASONS else "internal_error"


def _fail(reason):
    raise AuditRefusal(reason)


class CoreContractAuditRefusal(AuditRefusal):
    def __init__(self, reason, diagnostic):
        super().__init__(reason)
        self.diagnostic = (
            diagnostic
            if type(diagnostic) is str and diagnostic in CORE_CONTRACT_AUDIT_DIAGNOSTICS
            else None
        )


def _fail_core_contract_audit_identity(diagnostic):
    raise CoreContractAuditRefusal("run_identity_mismatch", diagnostic)


def _exact_int(value, minimum=0):
    return type(value) is int and value >= minimum


def _no_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail("api_schema")
        result[key] = value
    return result


def _json_loads(raw, reason="api_schema"):
    if type(raw) is not bytes or len(raw) > MAX_API_BYTES:
        _fail(reason)
    try:
        return json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_no_duplicate_pairs)
    except AuditRefusal:
        raise
    except Exception:
        _fail(reason)


def _valid_sha(value):
    return type(value) is str and CONTROL_SHA_RE.fullmatch(value) is not None


def _positive_decimal(value):
    return type(value) is str and DECIMAL_RE.fullmatch(value) is not None


def derive_canary(control_sha):
    if not _valid_sha(control_sha):
        _fail("invalid_input")
    digest = hashlib.sha256(CANARY_DOMAIN + control_sha.encode("ascii")).hexdigest()[:32]
    return CANARY_PREFIX + digest.encode("ascii")


def _canary_variants(control_sha):
    value = derive_canary(control_sha)
    return {
        value,
        value.upper(),
        value.hex().encode("ascii"),
        base64.b64encode(value),
        base64.urlsafe_b64encode(value).rstrip(b"="),
        urllib.parse.quote_from_bytes(value, safe="").encode("ascii"),
    }


def derive_reviewed_canary(control_sha):
    if not _valid_sha(control_sha):
        _fail("invalid_input")
    return REVIEWED_CANARY_PREFIX + control_sha[:16].encode("ascii")


def _reviewed_canary_variants(control_sha):
    value = derive_reviewed_canary(control_sha)
    return {
        value,
        value.upper(),
        value.hex().encode("ascii"),
        base64.b64encode(value),
        base64.urlsafe_b64encode(value).rstrip(b"="),
        urllib.parse.quote_from_bytes(value, safe="").encode("ascii"),
    }


def _reviewed_summary_canary_variants():
    value = REVIEWED_SUMMARY_DIRECT_CANARY
    return {
        value,
        value.upper(),
        value.hex().encode("ascii"),
        base64.b64encode(value),
        base64.urlsafe_b64encode(value).rstrip(b"="),
        urllib.parse.quote_from_bytes(value, safe="").encode("ascii"),
    }


def canary_needles(control_sha):
    variants = _canary_variants(control_sha)
    values = set(variants)
    for command in CANARY_COMMANDS:
        for variant in variants:
            values.add(command + variant)
    return tuple(sorted(values, key=len, reverse=True))


def inspect_public_bytes(raw, control_sha):
    if type(raw) is not bytes:
        _fail("log_format_unknown")
    for command in CANARY_COMMANDS:
        if command in raw:
            _fail("workflow_command_exposed")
        for variant in _canary_variants(control_sha):
            if command + variant in raw:
                _fail("workflow_command_exposed")
    for needle in _canary_variants(control_sha):
        if needle and needle in raw:
            _fail("canary_exposed")


def inspect_reviewed_public_bytes(raw, control_sha):
    inspect_public_bytes(raw, control_sha)
    for needle in (
        _reviewed_canary_variants(control_sha)
        | _reviewed_summary_canary_variants()
    ):
        if needle and needle in raw:
            _fail("canary_exposed")


def inspect_cache_probe_public_bytes(raw, control_sha):
    if type(raw) is not bytes:
        _fail("log_format_unknown")
    if b"::" in raw:
        _fail("workflow_command_exposed")
    for forbidden in (
        b"Cache restore skipped",
        b"Cache save skipped",
        b"cache read denied:",
        b"cache write denied:",
        b"Cache not found for input keys:",
        b"Cache restored from key:",
        b"Cache saved with key:",
    ):
        if forbidden in raw:
            _fail("workflow_command_exposed")
    inspect_reviewed_public_bytes(raw, control_sha)


def _inspect_cache_client_markers(raw, control_sha, run_id, run_attempt, seed_key, write_key):
    matches = list(CACHE_PROOF_CLIENT_MARKER_RE.finditer(raw))
    if len(matches) != 2 or raw.count(b"macos-cache-client=") != 2:
        _fail("receipt_invalid")
    expected_keys = {b"read": seed_key.encode("ascii"), b"write": write_key.encode("ascii")}
    seen = set()
    for match in matches:
        mode = match.group(1)
        key = match.group(2)
        marker_sha = match.group(3)
        marker_run_id = match.group(4)
        marker_attempt = match.group(5)
        if (mode in seen or key != expected_keys.get(mode)
                or marker_sha != control_sha.encode("ascii")
                or marker_run_id != run_id.encode("ascii")
                or marker_attempt != run_attempt.encode("ascii")):
            _fail("receipt_invalid")
        seen.add(mode)
    if seen != {b"read", b"write"}:
        _fail("receipt_invalid")


def cache_inventory_digest(entries):
    if type(entries) is not list or len(entries) > MAX_CACHE_ITEMS:
        _fail("api_schema")
    normalized = []
    seen = set()
    required = {
        "id", "ref", "key", "version", "last_accessed_at", "created_at", "size_in_bytes"
    }
    for item in entries:
        if type(item) is not dict or set(item) != required:
            _fail("api_schema")
        if not _exact_int(item["id"], 1) or item["id"] in seen:
            _fail("api_schema")
        seen.add(item["id"])
        if (type(item["ref"]) is not str or type(item["key"]) is not str
                or type(item["version"]) is not str or type(item["created_at"]) is not str
                or (item["last_accessed_at"] is not None
                    and type(item["last_accessed_at"]) is not str)
                or not _exact_int(item["size_in_bytes"], 0)):
            _fail("api_schema")
        normalized.append({key: item[key] for key in sorted(required)})
    normalized.sort(key=lambda item: item["id"])
    canonical = json.dumps(normalized, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def validate_receipt(encoded, control_sha, run_id, run_attempt):
    if (not _valid_sha(control_sha) or not _positive_decimal(run_id)
            or not _positive_decimal(run_attempt)):
        _fail("receipt_invalid")
    if type(encoded) is not str or not encoded or len(encoded) > (MAX_RECEIPT_BYTES * 4 // 3 + 8):
        _fail("receipt_invalid")
    if re.fullmatch(r"[A-Za-z0-9_-]+", encoded) is None:
        _fail("receipt_invalid")
    padded = encoded + "=" * ((4 - len(encoded) % 4) % 4)
    try:
        raw = base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except Exception:
        _fail("receipt_invalid")
    if len(raw) > MAX_RECEIPT_BYTES or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != encoded:
        _fail("receipt_invalid")
    try:
        value = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=_no_duplicate_pairs)
    except AuditRefusal:
        _fail("receipt_invalid")
    except Exception:
        _fail("receipt_invalid")
    if type(value) is not dict or set(value) != {
        "schema_version", "run_id", "run_attempt", "control_sha", "boundary",
        "macos_product_version", "runner_image_os", "runner_image_version",
        "developer_mode", "pf", "sandbox_selftest", "positive_build", "channels",
        "private_source_executed",
    }:
        _fail("receipt_invalid")
    if (type(value["schema_version"]) is not int or value["schema_version"] != 2
            or not _exact_int(value["run_id"], 1) or value["run_id"] != int(run_id)
            or not _exact_int(value["run_attempt"], 1) or value["run_attempt"] != int(run_attempt)
            or value["control_sha"] != control_sha):
        _fail("receipt_invalid")
    fixed_values = {
        "boundary": "seatbelt-deny-default",
        "runner_image_os": "macos-15-arm64",
        "developer_mode": "disabled",
        "pf": "enforced",
        "sandbox_selftest": "enforced",
        "positive_build": "passed",
        "private_source_executed": False,
    }
    for key, expected in fixed_values.items():
        if type(value[key]) is not type(expected) or value[key] != expected:
            _fail("receipt_invalid")
    if (type(value["macos_product_version"]) is not str or type(value["runner_image_version"]) is not str
            or (value["macos_product_version"], value["runner_image_version"]) not in APPROVED_HOST_RELEASES):
        _fail("receipt_invalid")
    channels = value["channels"]
    if type(channels) is not dict or channels != EXPECTED_CHANNELS:
        _fail("receipt_invalid")
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        return None


class GitHubAPI:
    def __init__(self, token):
        if type(token) is not str or TOKEN_RE.fullmatch(token) is None:
            _fail("invalid_input")
        self._token = token
        self._total_json_bytes = 0
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _NoRedirect()
        )

    def _open(self, request, limit, allow_redirect=False):
        try:
            response = self._opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            if allow_redirect and error.code == 302:
                headers = error.headers
                error.close()
                return None, headers
            _fail("api_status")
        except Exception:
            _fail("api_unavailable")
        try:
            status = response.status
            if status != 200:
                _fail("api_status")
            length = response.headers.get("Content-Length")
            if length is not None:
                if not length.isascii() or not length.isdecimal() or int(length) > limit:
                    _fail("log_too_large" if limit == MAX_LOG_BYTES else "api_schema")
            data = response.read(limit + 1)
            if len(data) > limit:
                _fail("log_too_large" if limit == MAX_LOG_BYTES else "api_schema")
            if length is not None and len(data) != int(length):
                _fail("api_schema")
            return data, response.headers
        except AuditRefusal:
            raise
        except Exception:
            _fail("api_unavailable")
        finally:
            try:
                response.close()
            except Exception:
                pass

    def json(self, path):
        url = API_ORIGIN + path
        headers = {
            "Accept": "application/vnd.github+json",
            "Authorization": "Bearer " + self._token,
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": "macos-public-audit",
            "Accept-Encoding": "identity",
        }
        request = urllib.request.Request(url, headers=headers, method="GET")
        raw, response_headers = self._open(request, MAX_API_BYTES)
        self._total_json_bytes += len(raw)
        if self._total_json_bytes > MAX_TOTAL_API_BYTES:
            _fail("api_schema")
        content_type = response_headers.get_content_type()
        if (content_type != "application/json"
                or response_headers.get("Content-Encoding", "identity").lower() != "identity"):
            _fail("api_schema")
        return _json_loads(raw), response_headers

    def log_text(self, job_id):
        path = "/repos/keeldock-platform/platform-ci/actions/jobs/" + str(job_id) + "/logs"
        request = urllib.request.Request(
            API_ORIGIN + path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self._token,
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "macos-public-audit",
                "Accept-Encoding": "identity",
            },
            method="GET",
        )
        _, response_headers = self._open(request, 1, allow_redirect=True)
        location = response_headers.get("Location")
        if (type(location) is not str or not location or len(location) > 8192
                or any(ord(char) < 33 or ord(char) > 126 for char in location)):
            _fail("log_unavailable")
        _validate_log_location(location)
        blob_request = urllib.request.Request(
            location,
            headers={"Accept": "text/plain", "Accept-Encoding": "identity", "User-Agent": "macos-public-audit"},
            method="GET",
        )
        data, blob_headers = self._open(blob_request, MAX_LOG_BYTES)
        content_type = blob_headers.get_content_type()
        if content_type not in ("text/plain", "application/octet-stream"):
            _fail("log_format_unknown")
        content_length = blob_headers.get("Content-Length")
        if (content_length is None or not content_length.isascii()
                or not content_length.isdecimal() or int(content_length) != len(data)):
            _fail("log_format_unknown")
        if blob_headers.get("Content-Encoding", "identity").lower() != "identity":
            _fail("log_format_unknown")
        try:
            data.decode("utf-8", "strict")
        except Exception:
            _fail("log_format_unknown")
        return data

    def delete_cache(self, cache_id):
        if not _exact_int(cache_id, 1):
            _fail("invalid_input")
        path = "/repos/keeldock-platform/platform-ci/actions/caches/" + str(cache_id)
        request = urllib.request.Request(
            API_ORIGIN + path,
            headers={
                "Accept": "application/vnd.github+json",
                "Authorization": "Bearer " + self._token,
                "X-GitHub-Api-Version": API_VERSION,
                "User-Agent": "macos-cache-proof-cleanup",
                "Accept-Encoding": "identity",
            },
            method="DELETE",
        )
        try:
            response = self._opener.open(request, timeout=30)
        except urllib.error.HTTPError as error:
            error.close()
            _fail("api_status")
        except Exception:
            _fail("api_unavailable")
        try:
            if response.status != 204:
                _fail("api_status")
            if response.read(1):
                _fail("api_schema")
        except AuditRefusal:
            raise
        except Exception:
            _fail("api_unavailable")
        finally:
            try:
                response.close()
            except Exception:
                pass


def _validate_api_url(value, expected_path):
    if type(value) is not str or any(ord(char) < 32 or ord(char) == 127 for char in value):
        _fail("api_schema")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except Exception:
        _fail("api_schema")
    if (parsed.scheme != "https" or parsed.hostname != API_HOST or parsed.netloc != API_HOST
            or port is not None
            or parsed.username is not None or parsed.password is not None
            or parsed.path != expected_path or parsed.query or parsed.fragment):
        _fail("api_schema")


def _validate_log_location(value):
    try:
        parsed = urllib.parse.urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except Exception:
        _fail("log_unavailable")
    if (parsed.scheme != "https" or host is None or parsed.netloc != host
            or re.fullmatch(r"productionresultssa[0-9]+\.blob\.core\.windows\.net", host) is None
            or parsed.username is not None or parsed.password is not None
            or port is not None or parsed.fragment or not parsed.query):
        _fail("log_unavailable")


def _page_link_map(header_value, path, page, expected_last_page=None, fixed_query=None):
    if header_value is None or header_value == "":
        if expected_last_page is not None and expected_last_page > page:
            _fail("pagination_incomplete")
        if expected_last_page is None and page > 1:
            _fail("pagination_incomplete")
        return {"_last_page": expected_last_page if expected_last_page is not None else page}
    if type(header_value) is not str or len(header_value) > 65536:
        _fail("pagination_incomplete")
    result = {}
    segments = header_value.split(",")
    for segment in segments:
        match = re.fullmatch(r"\s*<([^<>]+)>\s*;\s*rel=\"([a-z]+)\"\s*", segment)
        if match is None:
            _fail("pagination_incomplete")
        url, relation = match.groups()
        if relation in result or relation not in {"first", "prev", "next", "last"}:
            _fail("pagination_incomplete")
        try:
            parsed = urllib.parse.urlsplit(url)
            query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True, strict_parsing=True)
            port = parsed.port
        except Exception:
            _fail("pagination_incomplete")
        expected_query_keys = {"page", "per_page"}
        if fixed_query is not None:
            expected_query_keys.update(fixed_query)
        if (parsed.scheme != "https" or parsed.hostname != API_HOST or parsed.netloc != API_HOST
                or port is not None
                or parsed.username is not None or parsed.password is not None or parsed.path != path
                or parsed.fragment or set(query) != expected_query_keys
                or len(query["page"]) != 1 or len(query["per_page"]) != 1
                or query["per_page"][0] != str(PAGE_SIZE)
                or not query["page"][0].isdecimal()):
            _fail("pagination_incomplete")
        if fixed_query is None and parsed.query not in (
                    "per_page=" + str(PAGE_SIZE) + "&page=" + query["page"][0],
                    "page=" + query["page"][0] + "&per_page=" + str(PAGE_SIZE),
                ):
            _fail("pagination_incomplete")
        if fixed_query is not None and any(
                len(query.get(key, ())) != 1 or query[key][0] != value
                for key, value in fixed_query.items()):
            _fail("pagination_incomplete")
        target_page = int(query["page"][0])
        if relation == "first" and target_page != 1:
            _fail("pagination_incomplete")
        result[relation] = target_page
    if "prev" in result and result["prev"] != page - 1:
        _fail("pagination_incomplete")
    if "next" in result and result["next"] != page + 1:
        _fail("pagination_incomplete")
    if expected_last_page is not None:
        last_page = expected_last_page
        if "last" in result and result["last"] != last_page:
            _fail("pagination_incomplete")
    else:
        if "next" in result and "last" not in result:
            _fail("pagination_incomplete")
        last_page = result.get("last", page)
    if last_page < page:
        _fail("pagination_incomplete")
    if last_page > page and result.get("next") != page + 1:
        _fail("pagination_incomplete")
    if last_page <= page and "next" in result:
        _fail("pagination_incomplete")
    if last_page > 1 and "last" in result and result.get("last") != last_page:
        _fail("pagination_incomplete")
    result["_last_page"] = last_page
    return result


def _query_path(path, page, fixed_query=None):
    if fixed_query is None:
        return path + "?per_page=" + str(PAGE_SIZE) + "&page=" + str(page)
    query = urllib.parse.urlencode(fixed_query)
    return path + "?" + query + "&per_page=" + str(PAGE_SIZE) + "&page=" + str(page)


def _read_counted_collection(api, path, key, maximum, item_validator, fixed_query=None):
    first, headers = api.json(_query_path(path, 1, fixed_query))
    if type(first) is not dict or type(first.get("total_count")) is not int or first["total_count"] < 0:
        _fail("api_schema")
    total = first["total_count"]
    items = first.get(key)
    if type(items) is not list or total > maximum:
        _fail("api_schema")
    pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    if pages > MAX_PAGES:
        _fail("pagination_incomplete")
    if len(items) != min(PAGE_SIZE, total):
        _fail("pagination_incomplete")
    _page_link_map(headers.get("Link"), path, 1, pages, fixed_query)
    collected = list(items)
    for page in range(2, pages + 1):
        body, page_headers = api.json(_query_path(path, page, fixed_query))
        if (type(body) is not dict or type(body.get("total_count")) is not int
                or body["total_count"] != total or type(body.get(key)) is not list):
            _fail("pagination_incomplete")
        expected_count = min(PAGE_SIZE, total - (page - 1) * PAGE_SIZE)
        if len(body[key]) != expected_count:
            _fail("pagination_incomplete")
        _page_link_map(page_headers.get("Link"), path, page, pages, fixed_query)
        collected.extend(body[key])
    if len(collected) != total:
        _fail("pagination_incomplete")
    seen_ids = set()
    for item in collected:
        if type(item) is not dict or not _exact_int(item.get("id"), 1) or item["id"] in seen_ids:
            _fail("api_schema")
        seen_ids.add(item["id"])
        item_validator(item)
    return collected


def _read_annotations(api, path):
    all_items = []
    page = 1
    expected_last_page = None
    while True:
        query_path = _query_path(path, page)
        body, headers = api.json(query_path)
        if type(body) is not list or len(body) > PAGE_SIZE:
            _fail("api_schema")
        if len(all_items) + len(body) > MAX_ANNOTATIONS:
            _fail("pagination_incomplete")
        links = _page_link_map(headers.get("Link"), path, page, expected_last_page)
        if expected_last_page is None:
            expected_last_page = links["_last_page"]
            if expected_last_page > MAX_PAGES:
                _fail("pagination_incomplete")
        elif links["_last_page"] != expected_last_page:
            _fail("pagination_incomplete")
        for item in body:
            if type(item) is not dict:
                _fail("api_schema")
            all_items.append(item)
        if "next" not in links:
            if len(body) == PAGE_SIZE and "last" not in links:
                _fail("pagination_incomplete")
            return all_items
        if len(body) != PAGE_SIZE:
            _fail("pagination_incomplete")
        page += 1
        if page > MAX_PAGES:
            _fail("pagination_incomplete")


def _validate_cache(item):
    if type(item) is not dict:
        _fail("api_schema")


def _validate_artifact(item):
    if (type(item) is not dict or not _exact_int(item.get("id"), 1)
            or type(item.get("name")) is not str or not _exact_int(item.get("size_in_bytes"), 0)
            or type(item.get("expired")) is not bool):
        _fail("api_schema")


def _validate_job_record(item):
    if (type(item) is not dict or not _exact_int(item.get("id"), 1)
            or not _exact_int(item.get("run_id"), 1)
            or not _exact_int(item.get("run_attempt"), 1)
            or type(item.get("name")) is not str or not _valid_sha(item.get("head_sha"))
            or type(item.get("status")) is not str
            or item.get("status") not in {"queued", "in_progress", "completed"}
            or type(item.get("check_run_url")) is not str):
        _fail("api_schema")


def _validate_job_steps(job):
    steps = job.get("steps")
    if type(steps) is not list or len(steps) > 100:
        _fail("api_schema")
    seen = set()
    all_success = bool(steps)
    for step in steps:
        if (type(step) is not dict or not _exact_int(step.get("number"), 1)
                or step["number"] in seen or type(step.get("name")) is not str
                or type(step.get("status")) is not str
                or step.get("status") not in {"queued", "in_progress", "completed"}
                or type(step.get("conclusion")) is not str
                or step.get("conclusion") not in {
                    "success", "failure", "cancelled", "skipped", "timed_out",
                    "action_required", "neutral", "stale", "startup_failure",
                }):
            _fail("api_schema")
        if step.get("status") != "completed" or step.get("conclusion") != "success":
            all_success = False
        seen.add(step["number"])
    return all_success


def _validate_run(api, run_id, run_attempt, control_sha, workflow_path=WORKFLOW_PATH):
    run_path = "/repos/keeldock-platform/platform-ci/actions/runs/" + run_id
    run, _ = api.json(run_path)
    repository = run.get("repository") if type(run) is dict else None
    if (type(run) is not dict or not _exact_int(run.get("id"), 1)
            or run["id"] != int(run_id) or type(run.get("run_attempt")) is not int
            or run["run_attempt"] != int(run_attempt) or run.get("head_sha") != control_sha
            or run.get("event") != "workflow_dispatch" or run.get("head_branch") != "main"
            or run.get("path") != workflow_path or type(repository) is not dict
            or repository.get("full_name") != REPOSITORY):
        _fail("run_identity_mismatch")
    return run


def _job_detail(api, job, run_id, run_attempt, control_sha, job_name):
    if (job.get("run_id") != int(run_id) or job.get("run_attempt") != int(run_attempt)
            or job.get("head_sha") != control_sha
            or job.get("status") != "completed"):
        _fail("run_identity_mismatch")
    detail_path = "/repos/keeldock-platform/platform-ci/actions/jobs/" + str(job["id"])
    detail, _ = api.json(detail_path)
    _validate_job_record(detail)
    if (detail.get("id") != job["id"] or detail.get("run_id") != int(run_id)
            or detail.get("run_attempt") != int(run_attempt) or detail.get("head_sha") != control_sha
            or detail.get("name") != job_name or detail.get("status") != "completed"
            or detail.get("conclusion") != job.get("conclusion")):
        _fail("run_identity_mismatch")
    steps_success = _validate_job_steps(detail)
    try:
        check_path = urllib.parse.urlsplit(detail["check_run_url"]).path
    except Exception:
        _fail("api_schema")
    check_id = re.fullmatch(
        r"/repos/keeldock-platform/platform-ci/check-runs/([1-9][0-9]{0,18})",
        check_path,
    )
    expected_check_path = check_id.group(0) if check_id is not None else None
    _validate_api_url(detail["check_run_url"], expected_check_path)
    if job.get("check_run_url") != detail.get("check_run_url"):
        _fail("run_identity_mismatch")
    return detail, int(check_id.group(1)), steps_success


def _native_job(api, run_id, run_attempt, control_sha):
    path = (
        "/repos/keeldock-platform/platform-ci/actions/runs/" + run_id
        + "/attempts/" + run_attempt + "/jobs"
    )
    jobs = _read_counted_collection(api, path, "jobs", 10000, _validate_job_record)
    matches = [job for job in jobs if type(job) is dict and job.get("name") == NATIVE_JOB_NAME]
    if len(matches) != 1:
        _fail("api_schema")
    return _job_detail(api, matches[0], run_id, run_attempt, control_sha, NATIVE_JOB_NAME)


def _reviewed_jobs(api, run_id, run_attempt, control_sha):
    path = (
        "/repos/keeldock-platform/platform-ci/actions/runs/" + run_id
        + "/attempts/" + run_attempt + "/jobs"
    )
    jobs = _read_counted_collection(api, path, "jobs", 10000, _validate_job_record)
    expected_names = {
        REVIEWED_SNAPSHOT_JOB_NAME,
        REVIEWED_SMOKE_JOB_NAME,
        REVIEWED_AUDIT_JOB_NAME,
    }
    if len(jobs) != len(expected_names) or {job.get("name") for job in jobs} != expected_names:
        _fail("api_schema")
    audit_job = next(job for job in jobs if job.get("name") == REVIEWED_AUDIT_JOB_NAME)
    if (audit_job.get("run_id") != int(run_id) or audit_job.get("run_attempt") != int(run_attempt)
            or audit_job.get("head_sha") != control_sha or audit_job.get("status") != "in_progress"):
        _fail("run_identity_mismatch")
    snapshot = next(job for job in jobs if job.get("name") == REVIEWED_SNAPSHOT_JOB_NAME)
    smoke = next(job for job in jobs if job.get("name") == REVIEWED_SMOKE_JOB_NAME)
    snapshot_detail = _job_detail(
        api, snapshot, run_id, run_attempt, control_sha, REVIEWED_SNAPSHOT_JOB_NAME
    )
    smoke_detail = _job_detail(
        api, smoke, run_id, run_attempt, control_sha, REVIEWED_SMOKE_JOB_NAME
    )
    steps = smoke_detail[0].get("steps", [])
    expected_steps = (
        "Set up job",
        "Fetch reviewed main control",
        "Validate source-free control tree",
        "Prove source-free network observer",
        "Run source-free reviewed build smoke",
        "Write trusted summary visibility control",
        "Complete job",
    )
    if [step.get("name") for step in steps if type(step) is dict] != list(expected_steps):
        _fail("api_schema")
    summary_steps = [
        step for step in steps
        if type(step) is dict and step.get("name") == "Write trusted summary visibility control"
    ]
    if len(summary_steps) != 1:
        _fail("api_schema")
    return snapshot_detail, smoke_detail


def _rust_toolchain_jobs(api, run_id, run_attempt, control_sha):
    path = (
        "/repos/keeldock-platform/platform-ci/actions/runs/" + run_id
        + "/attempts/" + run_attempt + "/jobs"
    )
    jobs = _read_counted_collection(api, path, "jobs", 10000, _validate_job_record)
    expected_names = {
        RUST_TOOLCHAIN_SNAPSHOT_JOB_NAME,
        RUST_TOOLCHAIN_SMOKE_JOB_NAME,
        RUST_TOOLCHAIN_AUDIT_JOB_NAME,
    }
    if len(jobs) != len(expected_names) or {job.get("name") for job in jobs} != expected_names:
        _fail("api_schema")
    by_name = {job["name"]: job for job in jobs}
    audit_job = by_name[RUST_TOOLCHAIN_AUDIT_JOB_NAME]
    if (audit_job.get("run_id") != int(run_id)
            or audit_job.get("run_attempt") != int(run_attempt)
            or audit_job.get("head_sha") != control_sha
            or audit_job.get("status") != "in_progress"):
        _fail("run_identity_mismatch")
    expected_steps = {
        RUST_TOOLCHAIN_SNAPSHOT_JOB_NAME: (
            "Set up job", "Fetch reviewed main control", "Snapshot cache inventory", "Complete job",
        ),
        RUST_TOOLCHAIN_SMOKE_JOB_NAME: (
            "Set up job", "Fetch reviewed main control", "Validate source-free control tree",
            "Run source-free reviewed build smoke", "Run source-free Rust toolchain smoke",
            "Write trusted summary visibility control", "Complete job",
        ),
    }
    details = {}
    for name in (RUST_TOOLCHAIN_SNAPSHOT_JOB_NAME, RUST_TOOLCHAIN_SMOKE_JOB_NAME):
        detail = _job_detail(api, by_name[name], run_id, run_attempt, control_sha, name)
        steps = detail[0].get("steps", [])
        if not (by_name[name].get("conclusion") != "success" and not steps):
            if [step.get("name") for step in steps if type(step) is dict] != list(expected_steps[name]):
                _fail("api_schema")
        details[name] = detail
    return details


def _inspect_rust_toolchain_snapshot(raw, control_sha, run_id, run_attempt):
    expected = (
        "macos-rust-toolchain-snapshot=ready schema=1 control-sha=" + control_sha
        + " run-id=" + run_id + " run-attempt=" + run_attempt
    ).encode("ascii")
    _require_source_reader_log_line(
        raw, expected, b"macos-rust-toolchain-snapshot="
    )


def _inspect_rust_toolchain_receipt(raw, control_sha, run_id, run_attempt):
    if type(raw) is not bytes:
        _fail("receipt_invalid")
    marker = b"KD-RUST-SMOKE "
    matches = list(RUST_TOOLCHAIN_SUCCESS_MARKER_RE.finditer(raw))
    if (len(matches) != 1 or raw.count(marker) != 1
            or b"KD-RUST-REFUSAL" in raw):
        _fail("receipt_invalid")
    payload = matches[0].group(1)
    if len(payload) > 16384:
        _fail("receipt_invalid")
    try:
        value = json.loads(payload.decode("ascii", "strict"), object_pairs_hook=_no_duplicate_pairs)
    except AuditRefusal:
        _fail("receipt_invalid")
    except Exception:
        _fail("receipt_invalid")
    required = {
        "schema_version", "concern", "status", "control_sha", "run_id", "run_attempt",
        "host", "toolchain", "components", "versions", "target", "smoke", "source",
        "offline", "cleanup",
    }
    if type(value) is not dict or set(value) != required:
        _fail("receipt_invalid")
    expected_components = {
        "rustc": "23948a0a9c162fd2952defb3fb0462c44e8fcfd1a4ab8a274a1e1bdb2cf810a3",
        "rust-std": "fe79d6ab5a0321de26463999d8c112b8ad3eafbcbcf822d66a2300b45dde1031",
        "cargo": "685e563d94db1f003ffa5f5831439eec02569b9950b69867953c8213269c1eaf",
        "rustfmt-preview": "8b80dda570f140ee9ced8799294e812bba847a025f185bae4cba85a2ba235570",
        "clippy-preview": "c463f31831196702fc544900a0dc4c1837905327507fbec751fe46e59ca098bf",
    }
    expected_versions = {
        "rustc": "1.99.1 (58cf8f9c3 2026-10-13)",
        "rustfmt": "1.10.0",
        "clippy": "0.1.99",
    }
    expected_smoke = {"fmt": "passed", "clippy": "passed", "test": "passed"}
    if (type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["concern"] != "rust-toolchain-smoke" or value["status"] != "passed"
            or value["control_sha"] != control_sha
            or type(value["run_id"]) is not str or not _positive_decimal(value["run_id"])
            or value["run_id"] != run_id
            or type(value["run_attempt"]) is not str
            or not _positive_decimal(value["run_attempt"])
            or value["run_attempt"] != run_attempt
            or value["host"] != "aarch64-apple-darwin" or value["toolchain"] != "1.99.1"
            or value["target"] != "aarch64-apple-darwin"
            or value["components"] != expected_components
            or type(value["versions"]) is not dict
            or set(value["versions"]) != {"rustc", "cargo", "rustfmt", "clippy"}
            or any(value["versions"].get(key) != version for key, version in expected_versions.items())
            or type(value["versions"].get("cargo")) is not str
            or value["versions"]["cargo"] not in {"0.100.0", "1.99.0", "1.99.1"}
            or value["smoke"] != expected_smoke
            or value["source"] != "none" or value["offline"] is not True
            or value["cleanup"] != "complete"):
        _fail("receipt_invalid")
    canonical = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    try:
        if canonical.encode("ascii") != payload:
            _fail("receipt_invalid")
    except UnicodeEncodeError:
        _fail("receipt_invalid")


def publish_rust_toolchain_receipt(environ=None, stdin=None, stdout=None):
    env = os.environ if environ is None else environ
    repository = env.get("GITHUB_REPOSITORY", "")
    event_name = env.get("GITHUB_EVENT_NAME", "")
    ref = env.get("GITHUB_REF", "")
    control_sha = env.get("CI_SHA", "")
    github_sha = env.get("GITHUB_SHA", "")
    run_id = env.get("GITHUB_RUN_ID", "")
    run_attempt = env.get("GITHUB_RUN_ATTEMPT", "")
    if (repository != REPOSITORY or event_name != "workflow_dispatch"
            or ref != "refs/heads/main" or not _valid_sha(control_sha)
            or github_sha != control_sha or not _positive_decimal(run_id)
            or not _positive_decimal(run_attempt)):
        _fail("invalid_input")
    source = sys.stdin.buffer if stdin is None else stdin
    destination = sys.stdout.buffer if stdout is None else stdout
    try:
        raw = source.read(MAX_RUST_TOOLCHAIN_CAPTURE_BYTES + 1)
        trailing = source.read(1)
    except Exception:
        _fail("capture_invalid")
    if (type(raw) is not bytes or len(raw) > MAX_RUST_TOOLCHAIN_CAPTURE_BYTES
            or trailing != b"" or not raw.startswith(b"KD-RUST-SMOKE ")
            or not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\r" in raw):
        _fail("capture_invalid")
    try:
        _inspect_rust_toolchain_receipt(raw, control_sha, run_id, run_attempt)
    except AuditRefusal:
        _fail("capture_invalid")
    try:
        remaining = memoryview(raw)
        while remaining:
            written = destination.write(remaining)
            if written is None or written <= 0:
                _fail("capture_invalid")
            remaining = remaining[written:]
        destination.flush()
    except AuditRefusal:
        raise
    except Exception:
        _fail("capture_invalid")
    return 0


def _core_contract_context(env, *, require_protected_binding):
    repository = env.get("GITHUB_REPOSITORY", "")
    event_name = env.get("GITHUB_EVENT_NAME", "")
    ref = env.get("GITHUB_REF", "")
    control_sha = env.get("CI_SHA", "")
    github_sha = env.get("GITHUB_SHA", "")
    run_id = env.get("GITHUB_RUN_ID", "")
    run_attempt = env.get("GITHUB_RUN_ATTEMPT", "")
    source_sha = env.get("REQUESTED_SOURCE_SHA", "")
    base_sha = env.get("REQUESTED_BASE_SHA", "")
    base_branch = env.get("REQUESTED_BASE_BRANCH", "")
    repository_id = env.get("SOURCE_REPOSITORY_ID", "")
    if (repository != REPOSITORY or event_name != "workflow_dispatch"
            or ref != "refs/heads/main" or not _valid_sha(control_sha)
            or github_sha != control_sha or not _positive_decimal(run_id)
            or not _positive_decimal(run_attempt) or not _valid_sha(source_sha)
            or not _valid_sha(base_sha) or base_branch not in {"main", "develop", "uat"}
            or repository_id != BOOTSTRAP_SOURCE_REPOSITORY_IDS["core-contract"]):
        _fail("invalid_input")
    reviewed_diff = env.get("CORE_CONTRACT_REVIEWED_DIFF_SHA256", "")
    if HEX_DIGEST_RE.fullmatch(reviewed_diff) is None:
        _fail("invalid_input")
    if require_protected_binding:
        candidate_ref = env.get("CORE_CONTRACT_REVIEWED_CANDIDATE_REF", "")
        if (env.get("CORE_CONTRACT_ALLOWED_SHA") != source_sha
                or env.get("CORE_CONTRACT_ALLOWED_CONTROL_SHA") != control_sha
                or env.get("CORE_CONTRACT_REVIEWED_SOURCE_SHA") != source_sha
                or env.get("CORE_CONTRACT_REVIEWED_BASE_SHA") != base_sha
                or env.get("CORE_CONTRACT_REVIEWED_BASE_BRANCH") != base_branch
                or type(candidate_ref) is not str):
            _fail("invalid_input")
        if source_sha == base_sha:
            if candidate_ref != "refs/heads/" + base_branch:
                _fail("invalid_input")
        else:
            if (re.fullmatch(
                    r"refs/heads/(?:feat|fix|chore|plan)/[A-Za-z0-9][A-Za-z0-9._/-]{0,126}",
                    candidate_ref,
                ) is None
                    or any(part in ("", ".", "..") for part in candidate_ref.removeprefix("refs/heads/").split("/"))
                    or ".." in candidate_ref or "@{" in candidate_ref or candidate_ref.endswith("/")):
                _fail("invalid_input")
    return {
        "control_sha": control_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "repository_id": repository_id,
        "source_sha": source_sha,
        "base_sha": base_sha,
        "base_branch": base_branch,
        "reviewed_diff_sha256": reviewed_diff,
        "candidate_class": "permanent-tip" if source_sha == base_sha else "signed-descendant",
    }


def _core_contract_success_value(payload, context, image_os, image_version):
    try:
        value = json.loads(payload.decode("ascii", "strict"), object_pairs_hook=_no_duplicate_pairs)
    except AuditRefusal:
        _fail("capture_invalid")
    except Exception:
        _fail("capture_invalid")
    required = {
        "schema_version", "concern", "status", "control_sha", "source_sha", "base_sha",
        "base_branch", "reviewed_diff_sha256", "run_id", "run_attempt", "repository_id",
        "candidate_class", "signer_authority", "signatures", "ancestry", "token_revocation",
        "offline", "image_os", "image_version", "toolchain_versions", "gates", "gate_count",
        "gates_passed", "gates_failed", "suites", "suite_count", "suites_passed",
        "suites_failed", "source_tree", "lease_cleanup", "process_cleanup", "identity_cleanup", "summary_guard",
        "summary_guard_bypass_test", "positive_sentinel", "network_observation",
    }
    if type(value) is not dict or set(value) != required:
        _fail("capture_invalid")
    expected = {
        "schema_version": 1,
        "concern": "core-contract",
        "status": "passed",
        "control_sha": context["control_sha"],
        "source_sha": context["source_sha"],
        "base_sha": context["base_sha"],
        "base_branch": context["base_branch"],
        "reviewed_diff_sha256": context["reviewed_diff_sha256"],
        "run_id": context["run_id"],
        "run_attempt": context["run_attempt"],
        "repository_id": context["repository_id"],
        "candidate_class": context["candidate_class"],
        "signer_authority": "bound_base",
        "signatures": "all_new_commits_verified",
        "ancestry": "base_ancestor",
        "token_revocation": "confirmed_before_execution",
        "offline": True,
        "image_os": image_os,
        "image_version": image_version,
        "gates": {
            "format": "passed", "clippy": "passed", "workspace_tests": "passed",
            "api_tests": "passed", "mock_tests": "passed", "conformance_tests": "passed",
        },
        "gate_count": 6,
        "gates_passed": 6,
        "gates_failed": 0,
        "suites": ["core.static", "core.host-api", "core.mock-host", "core.conformance"],
        "suite_count": 4,
        "suites_passed": 4,
        "suites_failed": 0,
        "source_tree": "uid_read_only",
        "lease_cleanup": "complete",
        "process_cleanup": "complete",
        "identity_cleanup": "complete",
        "summary_guard": "append_sibling_create_readback_restore",
        "summary_guard_bypass_test": "passed",
        "positive_sentinel": "passed",
        "network_observation": "captured",
    }
    for key, expected_value in expected.items():
        if type(expected_value) is int:
            if not _exact_int(value.get(key), 0) or value[key] != expected_value:
                _fail("capture_invalid")
        elif type(expected_value) is bool:
            if type(value.get(key)) is not bool or value[key] is not expected_value:
                _fail("capture_invalid")
        elif type(expected_value) is dict:
            if type(value.get(key)) is not dict or value[key] != expected_value:
                _fail("capture_invalid")
        elif type(expected_value) is list:
            if type(value.get(key)) is not list or value[key] != expected_value:
                _fail("capture_invalid")
        elif (type(value.get(key)) is not str
                or (expected_value is not None and value[key] != expected_value)):
            _fail("capture_invalid")
    versions = value.get("toolchain_versions")
    if (type(versions) is not dict or set(versions) != {"rustc", "cargo", "rustfmt", "clippy"}
            or any(type(item) is not str for item in versions.values())
            or versions.get("rustc") != "1.99.1 (58cf8f9c3 2026-10-13)"
            or versions.get("cargo") not in {"0.100.0", "1.99.0", "1.99.1"}
            or versions.get("rustfmt") != "1.10.0"
            or versions.get("clippy") != "0.1.99"):
        _fail("capture_invalid")
    receipt_image_os = value.get("image_os")
    receipt_image_version = value.get("image_version")
    if (type(receipt_image_os) is not str
            or (image_os is not None and receipt_image_os != image_os)
            or re.fullmatch(r"macos-?[0-9]{1,2}(?:-(?:arm64|x64|intel))?", receipt_image_os) is None
            or type(receipt_image_version) is not str
            or (image_version is not None and receipt_image_version != image_version)
            or re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", receipt_image_version) is None):
        _fail("capture_invalid")
    try:
        canonical = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    except Exception:
        _fail("capture_invalid")
    if canonical != payload:
        _fail("capture_invalid")
    return value


def _core_contract_runtime_failure_mapping(runtime_reason):
    if runtime_reason == "cleanup_incomplete":
        return "cleanup_incomplete", "cleanup"
    if runtime_reason == "revocation_unconfirmed":
        return "token_revocation_unconfirmed", "source_validation"
    if runtime_reason in {"signature_invalid", "base_invalid", "bootstrap_not_approved"}:
        return "source_binding_mismatch", "source_validation"
    if runtime_reason == "invalid_input":
        return "invalid_input", "source_validation"
    return "source_validation_failed", "source_validation"


def _core_contract_refusal_diagnostic_matches(value):
    diagnostic = value["diagnostic"]
    if diagnostic in CORE_CONTRACT_SOURCE_GATES_NODE_DIAGNOSTICS:
        return (
            value["stage"] == "worker_setup"
            and value["reason"] == CORE_CONTRACT_SOURCE_GATES_NODE_DIAGNOSTIC_REASONS[diagnostic]
        )
    if diagnostic in CORE_CONTRACT_GATE_DIAGNOSTICS:
        if value["stage"] not in CORE_CONTRACT_GATE_STAGES:
            return False
        if diagnostic == "source_gate_capture_invalid":
            return value["reason"] == "capture_invalid"
        if diagnostic == "source_gate_capture_overflow":
            return value["reason"] in {"gate_failed", "capture_invalid"}
        return value["reason"] == "gate_failed"
    if diagnostic in CORE_CONTRACT_RUNTIME_DIAGNOSTICS:
        for runtime_stage in CORE_CONTRACT_RUNTIME_STAGES:
            for runtime_reason in CORE_CONTRACT_RUNTIME_REASONS:
                if diagnostic == "source_runtime_" + runtime_stage + "_" + runtime_reason:
                    return (value["reason"], value["stage"]) == _core_contract_runtime_failure_mapping(
                        runtime_reason,
                    )
        return False
    if diagnostic in CORE_CONTRACT_FETCH_DIAGNOSTICS:
        return (
            value["reason"] == "source_validation_failed"
            and value["stage"] == "source_validation"
        )
    if diagnostic in CORE_CONTRACT_BOOTSTRAP_DIAGNOSTICS:
        return (
            value["reason"] == "source_validation_failed"
            and value["stage"] == "source_validation"
        )
    if diagnostic in CORE_CONTRACT_SOURCE_LEASE_OPEN_DIAGNOSTICS:
        return (
            value["reason"] == "source_validation_failed"
            and value["stage"] == "source_validation"
        )
    return True


def _core_contract_refusal_value(payload):
    try:
        value = json.loads(payload.decode("ascii", "strict"), object_pairs_hook=_no_duplicate_pairs)
    except AuditRefusal:
        _fail("capture_invalid")
    except Exception:
        _fail("capture_invalid")
    if (type(value) is not dict
            or set(value) != {"schema_version", "status", "stage", "reason", "diagnostic"}
            or type(value.get("schema_version")) is not int or value["schema_version"] != 1
            or type(value.get("status")) is not str or value["status"] != "refused"
            or type(value.get("stage")) is not str or value["stage"] not in CORE_CONTRACT_REFUSAL_STAGES
            or type(value.get("reason")) is not str or value["reason"] not in CORE_CONTRACT_REFUSAL_REASONS
            or type(value.get("diagnostic")) is not str
            or value["diagnostic"] not in CORE_CONTRACT_REFUSAL_DIAGNOSTICS):
        _fail("capture_invalid")
    if (value["diagnostic"] == "none"
            and value["stage"] not in {"arguments", "context", "host"}):
        _fail("capture_invalid")
    if (value["diagnostic"] in (
            CORE_CONTRACT_PRIVILEGE_PROBE_DIAGNOSTICS | CORE_CONTRACT_SOURCE_GATES_CLEANUP_DIAGNOSTICS)
            and (value["stage"] != "cleanup" or value["reason"] != "cleanup_incomplete")):
        _fail("capture_invalid")
    if not _core_contract_refusal_diagnostic_matches(value):
        _fail("capture_invalid")
    try:
        canonical = json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    except Exception:
        _fail("capture_invalid")
    if canonical != payload:
        _fail("capture_invalid")
    return value


def publish_core_contract_receipt(environ=None, stdin=None, stdout=None):
    env = os.environ if environ is None else environ
    context = _core_contract_context(env, require_protected_binding=True)
    image_os = env.get("ImageOS", "")
    image_version = env.get("ImageVersion", "")
    driver_status = env.get("DRIVER_EXIT_STATUS", "")
    if driver_status not in {"0", "1"}:
        _fail("invalid_input")
    source = sys.stdin.buffer if stdin is None else stdin
    destination = sys.stdout.buffer if stdout is None else stdout
    maximum = MAX_CORE_CONTRACT_CAPTURE_BYTES if driver_status == "0" else MAX_CORE_CONTRACT_REFUSAL_BYTES
    try:
        raw = source.read(maximum + 1)
        trailing = source.read(1)
    except Exception:
        _fail("capture_invalid")
    if (type(raw) is not bytes or len(raw) > maximum or trailing != b""
            or not raw.endswith(b"\n") or raw.count(b"\n") != 1 or b"\r" in raw):
        _fail("capture_invalid")
    success_prefix = b"KD-CORE-CONTRACT "
    refusal_prefix = b"KD-CORE-CONTRACT-REFUSAL "
    if driver_status == "0" and raw.startswith(success_prefix):
        _core_contract_success_value(raw[len(success_prefix):-1], context, image_os, image_version)
    elif driver_status == "1" and raw.startswith(refusal_prefix):
        _core_contract_refusal_value(raw[len(refusal_prefix):-1])
    else:
        _fail("capture_invalid")
    try:
        remaining = memoryview(raw)
        while remaining:
            written = destination.write(remaining)
            if written is None or written <= 0:
                _fail("capture_invalid")
            remaining = remaining[written:]
        destination.flush()
    except AuditRefusal:
        raise
    except Exception:
        _fail("capture_invalid")
    return 0


def _core_contract_audit_context(control_sha, run_id, run_attempt, env):
    source_sha = env.get("REQUESTED_SOURCE_SHA", "")
    base_sha = env.get("REQUESTED_BASE_SHA", "")
    base_branch = env.get("REQUESTED_BASE_BRANCH", "")
    reviewed_diff = env.get("REVIEWED_DIFF_SHA256", "")
    if (not _valid_sha(source_sha) or not _valid_sha(base_sha)
            or base_branch not in {"main", "develop", "uat"}
            or HEX_DIGEST_RE.fullmatch(reviewed_diff) is None):
        _fail("invalid_input")
    return {
        "control_sha": control_sha,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "repository_id": BOOTSTRAP_SOURCE_REPOSITORY_IDS["core-contract"],
        "source_sha": source_sha,
        "base_sha": base_sha,
        "base_branch": base_branch,
        "reviewed_diff_sha256": reviewed_diff,
        "candidate_class": "permanent-tip" if source_sha == base_sha else "signed-descendant",
    }


def _inspect_core_contract_receipt(raw, control_sha, run_id, run_attempt, env):
    if type(raw) is not bytes:
        _fail("receipt_invalid")
    success_marker = b"KD-CORE-CONTRACT "
    refusal_marker = b"KD-CORE-CONTRACT-REFUSAL "
    success = list(CORE_CONTRACT_SUCCESS_MARKER_RE.finditer(raw))
    refusals = list(CORE_CONTRACT_REFUSAL_MARKER_RE.finditer(raw))
    if raw.count(success_marker) == 1 and not refusals and len(success) == 1:
        context = _core_contract_audit_context(control_sha, run_id, run_attempt, env)
        if (context["control_sha"] != control_sha or context["run_id"] != run_id
                or context["run_attempt"] != run_attempt):
            _fail("receipt_invalid")
        payload = success[0].group(1)
        if len(payload) + len(success_marker) + 1 > MAX_CORE_CONTRACT_CAPTURE_BYTES:
            _fail("receipt_invalid")
        try:
            value = _core_contract_success_value(payload, context, None, None)
        except AuditRefusal:
            _fail("receipt_invalid")
        return "passed", value
    if raw.count(refusal_marker) == 1 and not success and len(refusals) == 1:
        payload = refusals[0].group(1)
        if len(payload) + len(refusal_marker) + 1 > MAX_CORE_CONTRACT_REFUSAL_BYTES:
            _fail("receipt_invalid")
        try:
            value = _core_contract_refusal_value(payload)
        except AuditRefusal:
            _fail("receipt_invalid")
        return "refused", value
    if success or refusals or success_marker in raw or refusal_marker in raw:
        _fail("receipt_invalid")
    return "absent", None


def _inspect_core_contract_binding_markers(
    raw, control_sha, run_id, run_attempt, env, *, require_summary=True, require_installation=True,
):
    context = _core_contract_audit_context(control_sha, run_id, run_attempt, env)
    binding = list(CORE_CONTRACT_BINDING_MARKER_RE.finditer(raw))
    scope = list(CORE_CONTRACT_READER_SCOPE_MARKER_RE.finditer(raw))
    installation = list(CORE_CONTRACT_READER_INSTALLATION_MARKER_RE.finditer(raw))
    summary = list(CORE_CONTRACT_SUMMARY_CONTROL_MARKER_RE.finditer(raw))
    if (len(binding) != 1 or raw.count(b"macos-core-contract-binding=") != 1
            or len(scope) != 1 or raw.count(b"macos-core-contract-reader-scope=") != 1
            or len(installation) > 1 or raw.count(b"macos-core-contract-reader-installation=") != len(installation)
            or (require_installation and len(installation) != 1)
            or len(summary) > 1 or raw.count(b"macos-core-contract-summary-control=") != len(summary)
            or (require_summary and len(summary) != 1)):
        _fail("receipt_invalid")
    expected_context = (
        control_sha.encode("ascii"), run_id.encode("ascii"), run_attempt.encode("ascii"),
        context["source_sha"].encode("ascii"), context["base_sha"].encode("ascii"),
        context["base_branch"].encode("ascii"), context["candidate_class"].encode("ascii"),
        context["reviewed_diff_sha256"].encode("ascii"),
    )
    if binding[0].groups() != expected_context:
        _fail("receipt_invalid")
    expected_scope = (
        control_sha.encode("ascii"), run_id.encode("ascii"), run_attempt.encode("ascii"),
        context["repository_id"].encode("ascii"),
    )
    if scope[0].groups() != expected_scope:
        _fail("receipt_invalid")
    if installation and installation[0].groups()[:3] != (
        control_sha.encode("ascii"), run_id.encode("ascii"), run_attempt.encode("ascii"),
    ):
        _fail("receipt_invalid")
    if summary and summary[0].groups() != (
        control_sha.encode("ascii"), run_id.encode("ascii"), run_attempt.encode("ascii"),
        context["source_sha"].encode("ascii"), context["base_sha"].encode("ascii"),
        context["reviewed_diff_sha256"].encode("ascii"),
    ):
        _fail("receipt_invalid")
    return context


def _inspect_core_contract_cleanup(raw, control_sha, run_id, run_attempt, *, required):
    marker = b"macos-core-contract-cleanup="
    matches = list(CORE_CONTRACT_CLEANUP_MARKER_RE.finditer(raw)) if type(raw) is bytes else []
    if required:
        if len(matches) != 1 or raw.count(marker) != 1 or matches[0].group(1) != b"confirmed":
            _fail("receipt_invalid")
        if matches[0].groups()[1:] != (
            control_sha.encode("ascii"), run_id.encode("ascii"), run_attempt.encode("ascii"),
        ):
            _fail("receipt_invalid")
    elif matches or (type(raw) is bytes and marker in raw):
        _fail("receipt_invalid")


def _cache_proof_keys(run_id, run_attempt):
    if not _positive_decimal(run_id) or not _positive_decimal(run_attempt):
        _fail("invalid_input")
    suffix = run_id + "-" + run_attempt
    return (
        CACHE_PROOF_SEED_KEY_PREFIX + suffix,
        CACHE_PROOF_NONE_WRITE_KEY_PREFIX + suffix,
    )


def _cache_proof_step_names(job, expected_names):
    steps = job.get("steps")
    actual = [step.get("name") for step in steps] if type(steps) is list else []
    if len(actual) != len(set(actual)) or any(name not in actual for name in expected_names):
        _fail("api_schema")


def _cache_proof_jobs(api, run_id, run_attempt, control_sha):
    path = (
        "/repos/keeldock-platform/platform-ci/actions/runs/" + run_id
        + "/attempts/" + run_attempt + "/jobs"
    )
    jobs = _read_counted_collection(api, path, "jobs", 10000, _validate_job_record)
    required_names = {
        CACHE_PROOF_SNAPSHOT_JOB_NAME,
        CACHE_PROOF_SEED_JOB_NAME,
        CACHE_PROOF_POSITIVE_JOB_NAME,
        CACHE_PROOF_NONE_JOB_NAME,
        CACHE_PROOF_AUDIT_JOB_NAME,
    }
    actual_names = {job.get("name") for job in jobs}
    if (not required_names.issubset(actual_names)
            or actual_names - required_names not in (set(), {CACHE_PROOF_CLEANUP_JOB_NAME})
            or len(jobs) != len(actual_names)):
        _fail("api_schema")
    by_name = {job["name"]: job for job in jobs}
    audit_job = by_name[CACHE_PROOF_AUDIT_JOB_NAME]
    if (audit_job.get("run_id") != int(run_id)
            or audit_job.get("run_attempt") != int(run_attempt)
            or audit_job.get("head_sha") != control_sha
            or audit_job.get("status") != "in_progress"):
        _fail("run_identity_mismatch")
    if CACHE_PROOF_CLEANUP_JOB_NAME in by_name:
        cleanup_job = by_name[CACHE_PROOF_CLEANUP_JOB_NAME]
        if (cleanup_job.get("run_id") != int(run_id)
                or cleanup_job.get("run_attempt") != int(run_attempt)
                or cleanup_job.get("head_sha") != control_sha
                or cleanup_job.get("status") != "queued"):
            _fail("run_identity_mismatch")
    expected_steps = {
        CACHE_PROOF_SNAPSHOT_JOB_NAME: (
            "Fetch reviewed main control",
            "Snapshot cache inventory",
        ),
        CACHE_PROOF_SEED_JOB_NAME: (
            "Fetch reviewed main control",
            "Prepare public cache fixture",
            "Save public cache fixture",
            "Confirm seed step completed",
        ),
        CACHE_PROOF_POSITIVE_JOB_NAME: (
            "Fetch reviewed main control",
            "Restore the known public cache fixture",
            "Verify exact fixture bytes after a cache hit",
        ),
        CACHE_PROOF_NONE_JOB_NAME: (
            "Fetch reviewed main control",
            "Fetch the exact pinned public cache client",
            "Require fixture is absent before the denied read",
            "Request the known fixture through the pinned cache client",
            "Verify the none-scoped read did not restore bytes",
            "Prepare a distinct public write probe",
            "Request a save through the pinned cache client",
            "Confirm save request completed",
        ),
    }
    details = {}
    for name, step_names in expected_steps.items():
        details[name] = _job_detail(api, by_name[name], run_id, run_attempt, control_sha, name)
        _cache_proof_step_names(details[name][0], step_names)
    return details


def _source_reader_configuration(kind):
    if type(kind) is not str or kind not in SOURCE_READER_CONFIGURATIONS:
        _fail("invalid_input")
    return SOURCE_READER_CONFIGURATIONS[kind]


def _validate_source_reader_branch_policy(item):
    if (type(item) is not dict or not _exact_int(item.get("id"), 1)
            or item.get("name") != "main" or item.get("type") != "branch"):
        _fail("api_schema")


def _verify_source_reader_environment(api, kind, control_sha, run_id, run_attempt):
    configuration = _source_reader_configuration(kind)
    environment_path = (
        "/repos/keeldock-platform/platform-ci/environments/"
        + configuration["environment_name"]
    )
    environment, _ = api.json(environment_path)
    branch_policy = environment.get("deployment_branch_policy") if type(environment) is dict else None
    if (type(environment) is not dict
            or type(environment.get("id")) is not int
            or environment.get("id") != configuration["environment_id"]
            or environment.get("name") != configuration["environment_name"]
            or type(branch_policy) is not dict
            or type(branch_policy.get("custom_branch_policies")) is not bool
            or branch_policy.get("custom_branch_policies") is not True
            or type(branch_policy.get("protected_branches")) is not bool
            or branch_policy.get("protected_branches") is not False):
        _fail("api_schema")
    policies_path = environment_path + "/deployment-branch-policies"
    policies = _read_counted_collection(
        api, policies_path, "branch_policies", 100, _validate_source_reader_branch_policy
    )
    if (len(policies) != 1
            or policies[0].get("id") != configuration["branch_policy_id"]
            or policies[0].get("name") != "main"
            or policies[0].get("type") != "branch"):
        _fail("api_schema")
    return (
        "macos-source-environment=verified schema=1 kind=" + kind
        + " name=" + configuration["environment_name"]
        + " environment-id=" + str(configuration["environment_id"])
        + " policy-id=" + str(configuration["branch_policy_id"])
        + " custom-branch-policies=true protected-branches=false branch=main branch-type=branch"
        + " control-sha=" + control_sha + " run-id=" + run_id + " run-attempt=" + run_attempt
    ).encode("ascii")


def _validate_bootstrap_workflow_run(item, workflow_id, workflow_path):
    repository = item.get("repository") if type(item) is dict else None
    if (type(item) is not dict
            or not _exact_int(item.get("run_attempt"), 1)
            or not _valid_sha(item.get("head_sha"))
            or not _exact_int(item.get("workflow_id"), 1)
            or item.get("workflow_id") != workflow_id
            or item.get("path") != workflow_path
            or item.get("event") != "workflow_dispatch"
            or item.get("head_branch") != "main"
            or type(item.get("status")) is not str
            or item.get("status") not in KNOWN_WORKFLOW_RUN_STATUSES
            or type(repository) is not dict
            or repository.get("full_name") != REPOSITORY):
        _fail("api_schema")


def _verify_bootstrap_dispatch_guard(api, kind, current_run, control_sha, run_id, run_attempt):
    configuration = _source_reader_configuration(kind)
    workflow_id = current_run.get("workflow_id") if type(current_run) is dict else None
    if (not _exact_int(workflow_id, 1)
            or type(current_run.get("status")) is not str
            or current_run.get("status") not in KNOWN_WORKFLOW_RUN_STATUSES):
        _fail("api_schema")
    workflow_path = configuration["workflow_path"]
    path = (
        "/repos/keeldock-platform/platform-ci/actions/workflows/"
        + str(workflow_id) + "/runs"
    )
    fixed_query = {"branch": "main", "event": "workflow_dispatch"}

    def validate_record(item):
        _validate_bootstrap_workflow_run(item, workflow_id, workflow_path)

    runs = _read_counted_collection(
        api, path, "workflow_runs", MAX_WORKFLOW_RUNS, validate_record,
        fixed_query=fixed_query,
    )
    current_matches = []
    for item in runs:
        if item["id"] == int(run_id):
            current_matches.append(item)
        elif item["status"] in ACTIVE_WORKFLOW_RUN_STATUSES:
            _fail("run_identity_mismatch")
    if len(current_matches) != 1:
        _fail("run_identity_mismatch")
    listed_current = current_matches[0]
    identity_fields = (
        "id", "run_attempt", "head_sha", "workflow_id", "path", "event", "head_branch"
    )
    if (any(listed_current.get(field) != current_run.get(field) for field in identity_fields)
            or listed_current["run_attempt"] != int(run_attempt)
            or listed_current["head_sha"] != control_sha
            or listed_current["path"] != workflow_path
            or listed_current["event"] != "workflow_dispatch"
            or listed_current["head_branch"] != "main"
            or listed_current["repository"].get("full_name") != REPOSITORY):
        _fail("run_identity_mismatch")
    return _bootstrap_dispatch_marker(kind, control_sha, run_id, run_attempt)


def _bootstrap_dispatch_marker(kind, control_sha, run_id, run_attempt):
    return (
        "macos-bootstrap-dispatch=single-active-verified schema=1 kind=" + kind
        + " control-sha=" + control_sha + " run-id=" + run_id
        + " run-attempt=" + run_attempt
    ).encode("ascii")


def _source_reader_step_names(job, expected_names):
    steps = job.get("steps")
    actual = [step.get("name") for step in steps] if type(steps) is list else []
    if len(actual) != len(set(actual)) or any(name not in actual for name in expected_names):
        _fail("api_schema")


def _source_reader_jobs(api, run_id, run_attempt, control_sha):
    path = (
        "/repos/keeldock-platform/platform-ci/actions/runs/" + run_id
        + "/attempts/" + run_attempt + "/jobs"
    )
    jobs = _read_counted_collection(api, path, "jobs", 10000, _validate_job_record)
    expected_names = {
        SOURCE_READER_SETTINGS_JOB_NAME,
        SOURCE_READER_TOKEN_JOB_NAME,
        SOURCE_READER_AUDIT_JOB_NAME,
    }
    if (len(jobs) != len(expected_names)
            or {job.get("name") for job in jobs} != expected_names):
        _fail("api_schema")
    by_name = {job["name"]: job for job in jobs}
    audit_job = by_name[SOURCE_READER_AUDIT_JOB_NAME]
    if (audit_job.get("run_id") != int(run_id)
            or audit_job.get("run_attempt") != int(run_attempt)
            or audit_job.get("head_sha") != control_sha
            or audit_job.get("status") != "in_progress"):
        _fail("run_identity_mismatch")
    expected_steps = {
        SOURCE_READER_SETTINGS_JOB_NAME: (
            "Fetch reviewed main control",
            "Validate source-free control tree",
            "Verify exact protected environment settings",
            "Snapshot public surfaces",
        ),
        SOURCE_READER_TOKEN_JOB_NAME: (
            "Fetch reviewed main control",
            "Validate source-reader scope configuration",
            "Mint scoped source-reader token",
            "Verify selected installation identity",
            "Verify one-repository read scope and revoke token",
            "Write trusted summary visibility control",
        ),
    }
    details = {}
    for name, step_names in expected_steps.items():
        details[name] = _job_detail(api, by_name[name], run_id, run_attempt, control_sha, name)
        _source_reader_step_names(details[name][0], step_names)
    return details


def _require_source_reader_log_line(raw, expected, marker):
    if (type(raw) is not bytes or not raw
            or len(re.findall(
                rb"(?m)^" + _GITHUB_LOG_TIMESTAMP + re.escape(expected) + rb"(?=\r?(?:\n|$))",
                raw,
            )) != 1
            or raw.count(marker) != 1):
        _fail("receipt_invalid")


def _inspect_source_reader_markers(settings_log, token_log, kind, control_sha, run_id, run_attempt):
    configuration = _source_reader_configuration(kind)
    expected_settings = (
        "macos-source-environment=verified schema=1 kind=" + kind
        + " name=" + configuration["environment_name"]
        + " environment-id=" + str(configuration["environment_id"])
        + " policy-id=" + str(configuration["branch_policy_id"])
        + " custom-branch-policies=true protected-branches=false branch=main branch-type=branch"
        + " control-sha=" + control_sha + " run-id=" + run_id + " run-attempt=" + run_attempt
    ).encode("ascii")
    snapshot_line = (
        "macos-source-reader-snapshot=ready schema=1 control-sha=" + control_sha
        + " run-id=" + run_id + " run-attempt=" + run_attempt
    ).encode("ascii")
    _require_source_reader_log_line(
        settings_log, expected_settings, b"macos-source-environment="
    )
    _require_source_reader_log_line(
        settings_log, snapshot_line, b"macos-source-reader-snapshot="
    )
    installation_matches = list(SOURCE_READER_INSTALLATION_MARKER_RE.finditer(token_log))
    scope_matches = list(SOURCE_READER_SCOPE_MARKER_RE.finditer(token_log))
    record_matches = list(SOURCE_READER_SUCCESS_RECORD_RE.finditer(token_log))
    if (len(installation_matches) != 1 or token_log.count(b"macos-source-reader-installation=") != 1
            or len(scope_matches) != 1 or token_log.count(b"macos-source-reader-scope=") != 1
            or len(record_matches) != 1 or token_log.count(b'{"metadata":') != 1):
        _fail("receipt_invalid")
    installation = installation_matches[0].groups()
    scope = scope_matches[0].groups()
    expected_sha = control_sha.encode("ascii")
    expected_run = run_id.encode("ascii")
    expected_attempt = run_attempt.encode("ascii")
    if (installation[:3] != (expected_sha, expected_run, expected_attempt)
            or scope[:3] != (expected_sha, expected_run, expected_attempt)
            or installation[3] != scope[3]
            or not _positive_decimal(scope[4].decode("ascii"))):
        _fail("receipt_invalid")
    _inspect_reviewed_summary_control_marker(token_log, control_sha, run_id, run_attempt)


def _source_reader_audit(api, kind, control_sha, run_id, run_attempt, env):
    configuration = _source_reader_configuration(kind)
    _validate_run(api, run_id, run_attempt, control_sha, configuration["workflow_path"])
    details = _source_reader_jobs(api, run_id, run_attempt, control_sha)
    settings_job, settings_check_id, settings_steps_success = details[SOURCE_READER_SETTINGS_JOB_NAME]
    token_job, token_check_id, token_steps_success = details[SOURCE_READER_TOKEN_JOB_NAME]
    settings_log = api.log_text(settings_job["id"])
    token_log = api.log_text(token_job["id"])
    inspect_reviewed_public_bytes(settings_log, control_sha)
    inspect_reviewed_public_bytes(token_log, control_sha)
    _scan_annotations(api, settings_job, settings_check_id, control_sha, reviewed=True)
    _scan_annotations(api, token_job, token_check_id, control_sha, reviewed=True)
    _fetch_artifacts(api, run_id)
    cache_digest = _fetch_caches(api, control_sha, reviewed=True)
    baseline = env.get("MACOS_CACHE_SNAPSHOT", "")
    if HEX_DIGEST_RE.fullmatch(baseline) is None or cache_digest != baseline:
        _fail("inventory_changed")
    settings_marker = _verify_source_reader_environment(
        api, kind, control_sha, run_id, run_attempt
    )
    if settings_job.get("conclusion") != "success" or not settings_steps_success:
        _fail("native_job_failed")
    if token_job.get("conclusion") != "success" or not token_steps_success:
        _fail("native_job_failed")
    _inspect_source_reader_markers(
        settings_log, token_log, kind, control_sha, run_id, run_attempt
    )
    expected_settings = (
        "macos-source-environment=verified schema=1 kind=" + kind
        + " name=" + configuration["environment_name"]
        + " environment-id=" + str(configuration["environment_id"])
        + " policy-id=" + str(configuration["branch_policy_id"])
        + " custom-branch-policies=true protected-branches=false branch=main branch-type=branch"
        + " control-sha=" + control_sha + " run-id=" + run_id + " run-attempt=" + run_attempt
    ).encode("ascii")
    if settings_marker != expected_settings:
        _fail("api_schema")
    print(
        "macos-source-reader-audit=verified schema=1 kind=" + kind
        + " control-sha=" + control_sha + " run-id=" + run_id
        + " run-attempt=" + run_attempt + " scope=one-private-repository-read"
        + " revocation=confirmed source-content=not-read"
    )
    return 0


def _bootstrap_job_steps(
    detail, expected_names, skipped_names=(), post_names=(), optional_post_actions=()
):
    steps = detail.get("steps")
    if type(steps) is not list or any(type(step) is not dict for step in steps):
        _fail("api_schema")
    step_names = [step.get("name") for step in steps]
    post_action_by_name = dict(optional_post_actions)
    if (len(post_action_by_name) != len(optional_post_actions)
            or not set(post_action_by_name).issubset(set(post_names))
            or not set(post_action_by_name.values()).issubset(set(expected_names))):
        _fail("api_schema")
    step_by_name = {step.get("name"): step for step in steps}
    if len(step_by_name) != len(steps):
        _fail("api_schema")
    present_posts = [name for name in post_names if name in step_by_name]
    for post_name in post_names:
        if post_name in step_by_name:
            continue
        action_step = step_by_name.get(post_action_by_name.get(post_name))
        if (action_step is None or action_step.get("status") != "completed"
                or action_step.get("conclusion") != "skipped"):
            _fail("api_schema")
    expected_api_names = ["Set up job", *expected_names, *present_posts, "Complete job"]
    if step_names != expected_api_names:
        _fail("api_schema")
    skipped_names = set(skipped_names)
    if (not skipped_names.issubset(set(expected_names))
            or skipped_names.intersection(post_names)):
        _fail("api_schema")
    success = True
    for step in steps:
        if type(step) is not dict:
            _fail("api_schema")
        if step["name"] in skipped_names:
            if step.get("status") != "completed" or step.get("conclusion") != "skipped":
                success = False
        elif step.get("status") != "completed" or step.get("conclusion") != "success":
            success = False
    return success


def _bootstrap_jobs(api, kind, run_id, run_attempt, control_sha):
    path = (
        "/repos/keeldock-platform/platform-ci/actions/runs/" + run_id
        + "/attempts/" + run_attempt + "/jobs"
    )
    jobs = _read_counted_collection(api, path, "jobs", 10000, _validate_job_record)
    if kind == "rules-bootstrap":
        expected_names = {
            RULES_BOOTSTRAP_SETTINGS_JOB_NAME,
            RULES_BOOTSTRAP_PRODUCER_JOB_NAME,
            RULES_BOOTSTRAP_AUDIT_JOB_NAME,
        }
        snapshot_name = RULES_BOOTSTRAP_SETTINGS_JOB_NAME
        producer_name = RULES_BOOTSTRAP_PRODUCER_JOB_NAME
        audit_name = RULES_BOOTSTRAP_AUDIT_JOB_NAME
        snapshot_steps = (
            "Fetch reviewed main control",
            "Validate source-free control tree",
            "Validate requested source identity",
            "Verify exact protected environment settings",
            "Snapshot public surfaces",
        )
        producer_steps = (
            "Fetch reviewed main control",
            "Validate source-free control tree",
            "Seal exact control signer inventory",
            "Prepare pinned public dash before token mint",
            "Preflight protected bootstrap and review binding",
            "Validate source-reader scope configuration",
            "Mint scoped source-reader token",
            "Verify selected installation identity",
            "Run fixed rules bootstrap",
            "Revoke token if bootstrap did not confirm",
            "Clean prepared dash",
            "Write trusted summary visibility control",
        )
        allowed_skips = ("Revoke token if bootstrap did not confirm",)
        snapshot_post_steps = ()
        producer_post_steps = ("Post Mint scoped source-reader token",)
        snapshot_optional_post_actions = ()
        producer_optional_post_actions = (
            ("Post Mint scoped source-reader token", "Mint scoped source-reader token"),
        )
    elif kind == "core-bootstrap":
        expected_names = {
            CORE_BOOTSTRAP_SNAPSHOT_JOB_NAME,
            CORE_BOOTSTRAP_PRODUCER_JOB_NAME,
            CORE_BOOTSTRAP_AUDIT_JOB_NAME,
        }
        snapshot_name = CORE_BOOTSTRAP_SNAPSHOT_JOB_NAME
        producer_name = CORE_BOOTSTRAP_PRODUCER_JOB_NAME
        audit_name = CORE_BOOTSTRAP_AUDIT_JOB_NAME
        snapshot_steps = (
            "Fetch control",
            "Audit source-read settings",
            "Snapshot cache",
        )
        producer_steps = (
            "Fetch control",
            "Test control",
            "Run reviewed smoke",
            "Protect inventory",
            "Core preflight",
            "Write trusted summary visibility control",
            "Validate reader settings",
            "Mint reader token",
            "Validate core bootstrap",
        )
        allowed_skips = ()
        snapshot_post_steps = ()
        producer_post_steps = ("Post Mint reader token",)
        snapshot_optional_post_actions = ()
        producer_optional_post_actions = (
            ("Post Mint reader token", "Mint reader token"),
        )
    else:
        _fail("invalid_input")
    if len(jobs) != len(expected_names) or {job.get("name") for job in jobs} != expected_names:
        _fail("api_schema")
    by_name = {job["name"]: job for job in jobs}
    audit_job = by_name[audit_name]
    if (audit_job.get("run_id") != int(run_id)
            or audit_job.get("run_attempt") != int(run_attempt)
            or audit_job.get("head_sha") != control_sha
            or audit_job.get("status") != "in_progress"):
        _fail("run_identity_mismatch")
    details = {}
    for name, expected_steps, post_steps, optional_posts in (
        (snapshot_name, snapshot_steps, snapshot_post_steps, snapshot_optional_post_actions),
        (producer_name, producer_steps, producer_post_steps, producer_optional_post_actions),
    ):
        detail = _job_detail(api, by_name[name], run_id, run_attempt, control_sha, name)
        skipped = allowed_skips if name == producer_name else ()
        details[name] = (
            detail[0], detail[1],
            _bootstrap_job_steps(detail[0], expected_steps, skipped, post_steps, optional_posts),
        )
    return details


def _core_contract_producer_steps_success(detail):
    steps = detail.get("steps")
    if type(steps) is not list or any(type(step) is not dict for step in steps):
        _fail("api_schema")
    expected = (
        "Fetch reviewed main control",
        "Validate source-free control tree",
        "Run source-free reviewed build smoke",
        "Run source-free Rust toolchain smoke",
        "Write trusted summary visibility control",
        "Validate protected contract binding",
        "Validate source-reader scope configuration",
        "Mint scoped source-reader token",
        "Verify selected installation identity",
        "Run fixed core contract",
        "Revoke token if contract did not confirm",
        "Write trusted contract summary control",
    )
    post_name = "Post Mint scoped source-reader token"
    step_names = [step.get("name") for step in steps]
    if not steps:
        return False
    post_present = post_name in step_names
    expected_names = ["Set up job", *expected]
    if post_present:
        expected_names.append(post_name)
    expected_names.append("Complete job")
    if step_names != expected_names or len(set(step_names)) != len(step_names):
        _fail("api_schema")
    by_name = {step["name"]: step for step in steps}
    contract = by_name["Run fixed core contract"]
    mint = by_name["Mint scoped source-reader token"]
    fallback = by_name["Revoke token if contract did not confirm"]
    summary = by_name["Write trusted contract summary control"]
    contract_passed = contract.get("status") == "completed" and contract.get("conclusion") == "success"
    if contract_passed:
        if (fallback.get("status") != "completed" or fallback.get("conclusion") != "skipped"
                or summary.get("status") != "completed" or summary.get("conclusion") != "success"):
            _fail("api_schema")
    else:
        if summary.get("status") != "completed" or summary.get("conclusion") != "skipped":
            _fail("api_schema")
        if mint.get("status") == "completed" and mint.get("conclusion") == "success":
            if fallback.get("status") != "completed" or fallback.get("conclusion") not in {"success", "failure"}:
                _fail("api_schema")
        elif fallback.get("status") != "completed" or fallback.get("conclusion") != "skipped":
            _fail("api_schema")
    if not post_present:
        if mint.get("status") == "completed" and mint.get("conclusion") == "success":
            _fail("api_schema")
    elif (by_name[post_name].get("status") != "completed"
            or by_name[post_name].get("conclusion") not in {"success", "failure"}):
        _fail("api_schema")
    success = True
    for step in steps:
        name = step.get("name")
        if name == "Revoke token if contract did not confirm" and contract_passed:
            continue
        if name == "Post Mint scoped source-reader token" and not post_present:
            continue
        if step.get("status") != "completed" or step.get("conclusion") != "success":
            success = False
    return success


def _core_contract_jobs(api, run_id, run_attempt, control_sha):
    path = (
        "/repos/keeldock-platform/platform-ci/actions/runs/" + run_id
        + "/attempts/" + run_attempt + "/jobs"
    )
    jobs = _read_counted_collection(api, path, "jobs", 10000, _validate_job_record)
    expected_names = {
        CORE_CONTRACT_SETTINGS_JOB_NAME,
        CORE_CONTRACT_PRODUCER_JOB_NAME,
        CORE_CONTRACT_AUDIT_JOB_NAME,
    }
    if len(jobs) != len(expected_names) or {job.get("name") for job in jobs} != expected_names:
        _fail("api_schema")
    by_name = {job["name"]: job for job in jobs}
    audit_job = by_name[CORE_CONTRACT_AUDIT_JOB_NAME]
    if audit_job.get("run_id") != int(run_id):
        _fail_core_contract_audit_identity("audit_job_run_id_mismatch")
    if audit_job.get("run_attempt") != int(run_attempt):
        _fail_core_contract_audit_identity("audit_job_run_attempt_mismatch")
    if audit_job.get("head_sha") != control_sha:
        _fail_core_contract_audit_identity("audit_job_head_sha_mismatch")
    if audit_job.get("status") != "in_progress":
        status_diagnostic = {
            "queued": "audit_job_status_queued",
            "completed": "audit_job_status_completed",
        }.get(audit_job.get("status"), "audit_job_status_not_in_progress")
        _fail_core_contract_audit_identity(status_diagnostic)
    details = {}
    for name in (CORE_CONTRACT_SETTINGS_JOB_NAME, CORE_CONTRACT_PRODUCER_JOB_NAME):
        detail = _job_detail(api, by_name[name], run_id, run_attempt, control_sha, name)
        if name == CORE_CONTRACT_SETTINGS_JOB_NAME:
            steps_success = _bootstrap_job_steps(
                detail[0], (
                    "Fetch reviewed main control",
                    "Validate requested source identity",
                    "Verify source-read environment",
                    "Snapshot cache inventory",
                ),
            ) if detail[0].get("steps") else False
        else:
            steps_success = _core_contract_producer_steps_success(detail[0])
        details[name] = (detail[0], detail[1], steps_success)
    return details


def _one_bootstrap_marker(raw, marker, pattern):
    matches = list(pattern.finditer(raw)) if type(raw) is bytes else []
    if len(matches) != 1 or raw.count(marker) != 1:
        _fail("receipt_invalid")
    return matches[0].groups()


def _inspect_bootstrap_settings_snapshot(raw, kind, control_sha, run_id, run_attempt):
    configuration = _source_reader_configuration(kind)
    expected_settings = (
        "macos-source-environment=verified schema=1 kind=" + kind
        + " name=" + configuration["environment_name"]
        + " environment-id=" + str(configuration["environment_id"])
        + " policy-id=" + str(configuration["branch_policy_id"])
        + " custom-branch-policies=true protected-branches=false branch=main branch-type=branch"
        + " control-sha=" + control_sha + " run-id=" + run_id + " run-attempt=" + run_attempt
    ).encode("ascii")
    prefix = "macos-" + kind + "-snapshot=ready schema=1 control-sha="
    expected_snapshot = (
        prefix + control_sha + " run-id=" + run_id + " run-attempt=" + run_attempt
    ).encode("ascii")
    _require_source_reader_log_line(
        raw, _bootstrap_dispatch_marker(kind, control_sha, run_id, run_attempt),
        b"macos-bootstrap-dispatch=",
    )
    _require_source_reader_log_line(raw, expected_settings, b"macos-source-environment=")
    _require_source_reader_log_line(raw, expected_snapshot, prefix.encode("ascii"))


def _inspect_rules_bootstrap_markers(raw, control_sha, run_id, run_attempt, env):
    source_sha = env.get("REQUESTED_SOURCE_SHA", "")
    base_sha = env.get("REQUESTED_BASE_SHA", "")
    base_branch = env.get("REQUESTED_BASE_BRANCH", "")
    reviewed_diff = env.get("REVIEWED_DIFF_SHA256", "")
    if (not _valid_sha(source_sha) or not _valid_sha(base_sha)
            or base_branch not in {"main", "develop", "uat"}
            or HEX_DIGEST_RE.fullmatch(reviewed_diff) is None):
        _fail("invalid_input")
    preflight = _one_bootstrap_marker(
        raw, b"macos-rules-bootstrap=preflight-passed", RULES_BOOTSTRAP_PREFLIGHT_MARKER_RE
    )
    success = _one_bootstrap_marker(
        raw, b"macos-rules-bootstrap=passed", RULES_BOOTSTRAP_SUCCESS_MARKER_RE
    )
    summary = _one_bootstrap_marker(
        raw, b"macos-rules-summary-control=trusted-write", RULES_BOOTSTRAP_SUMMARY_CONTROL_MARKER_RE
    )
    source_binding = _one_bootstrap_marker(
        raw, b"macos-rules-source-binding=verified", RULES_BOOTSTRAP_SOURCE_BINDING_MARKER_RE
    )
    expected = (control_sha.encode("ascii"), run_id.encode("ascii"), run_attempt.encode("ascii"))
    if (preflight[:3] != expected or success[:3] != expected or summary[:3] != expected
            or source_binding[:3] != expected):
        _fail("receipt_invalid")
    requested = (source_sha.encode("ascii"), base_sha.encode("ascii"), base_branch.encode("ascii"))
    if (preflight[3:6] != requested or success[3:6] != requested
            or summary[3:5] != requested[:2]):
        _fail("receipt_invalid")
    if (preflight[7] != reviewed_diff.encode("ascii") or success[5] != requested[2]
            or preflight[6] != success[7]):
        _fail("receipt_invalid")
    if success[8] != reviewed_diff.encode("ascii") or summary[5] != reviewed_diff.encode("ascii"):
        _fail("receipt_invalid")
    if source_binding[3] != BOOTSTRAP_SOURCE_REPOSITORY_IDS["rules-bootstrap"].encode("ascii"):
        _fail("receipt_invalid")
    _inspect_rules_network_observation(raw, control_sha, run_id, run_attempt, source_sha)


def _inspect_rules_network_observation(raw, control_sha, run_id, run_attempt, source_sha):
    marker = b"macos-rules-network="
    if type(raw) is not bytes or raw.count(marker) != 1:
        _fail("receipt_invalid")
    matches = list(RULES_BOOTSTRAP_NETWORK_MARKER_RE.finditer(raw))
    if len(matches) != 1:
        _fail("receipt_invalid")
    match = matches[0]
    expected = (
        control_sha.encode("ascii"), run_id.encode("ascii"),
        run_attempt.encode("ascii"), source_sha.encode("ascii"),
    )
    if match.groups()[:4] != expected:
        _fail("receipt_invalid")
    if int(match.group(6)) > 65535 or int(match.group(7)) > 65535:
        _fail("receipt_invalid")
    for group in (8, 9):
        hashes = match.group(group)
        if hashes == b"none":
            continue
        items = hashes.split(b",")
        if items != sorted(set(items)):
            _fail("receipt_invalid")


def _inspect_rules_early_source_refusal(raw, producer_job, control_sha, run_id, run_attempt, env):
    marker = b"macos-rules-bootstrap=refused"
    if type(raw) is not bytes:
        _fail("receipt_invalid")
    if raw.count(marker) == 0:
        return False
    if (raw.count(marker) != 1 or b"macos-rules-bootstrap=passed" in raw
            or b"macos-rules-network=" in raw or b"macos-rules-summary-control=" in raw):
        _fail("receipt_invalid")
    matches = list(RULES_BOOTSTRAP_EARLY_SOURCE_REFUSAL_MARKER_RE.finditer(raw))
    if len(matches) != 1:
        _fail("receipt_invalid")
    refusal = matches[0]
    expected_identity = (
        control_sha.encode("ascii"), run_id.encode("ascii"), run_attempt.encode("ascii"),
    )
    if refusal.groups()[1:] != expected_identity:
        _fail("receipt_invalid")

    source_sha = env.get("REQUESTED_SOURCE_SHA", "")
    base_sha = env.get("REQUESTED_BASE_SHA", "")
    base_branch = env.get("REQUESTED_BASE_BRANCH", "")
    reviewed_diff = env.get("REVIEWED_DIFF_SHA256", "")
    if (not _valid_sha(source_sha) or not _valid_sha(base_sha)
            or base_branch not in {"main", "develop", "uat"}
            or HEX_DIGEST_RE.fullmatch(reviewed_diff) is None):
        _fail("invalid_input")
    preflight = _one_bootstrap_marker(
        raw, b"macos-rules-bootstrap=preflight-passed", RULES_BOOTSTRAP_PREFLIGHT_MARKER_RE
    )
    source_binding = _one_bootstrap_marker(
        raw, b"macos-rules-source-binding=verified", RULES_BOOTSTRAP_SOURCE_BINDING_MARKER_RE
    )
    if (preflight[:3] != expected_identity or source_binding[:3] != expected_identity
            or preflight[3:6] != (
                source_sha.encode("ascii"), base_sha.encode("ascii"), base_branch.encode("ascii"),
            )
            or preflight[7] != reviewed_diff.encode("ascii")
            or source_binding[3] != BOOTSTRAP_SOURCE_REPOSITORY_IDS["rules-bootstrap"].encode("ascii")):
        _fail("receipt_invalid")

    step_by_name = {
        step.get("name"): step
        for step in producer_job.get("steps", [])
        if type(step) is dict and type(step.get("name")) is str
    }
    rules_step = step_by_name.get("Run fixed rules bootstrap")
    if (type(rules_step) is not dict or rules_step.get("status") != "completed"
            or rules_step.get("conclusion") != "failure"):
        _fail("receipt_invalid")
    for step_name in (
        "Fetch reviewed main control",
        "Validate source-free control tree",
        "Seal exact control signer inventory",
        "Prepare pinned public dash before token mint",
        "Preflight protected bootstrap and review binding",
        "Validate source-reader scope configuration",
        "Mint scoped source-reader token",
        "Verify selected installation identity",
    ):
        step = step_by_name.get(step_name)
        if (type(step) is not dict or step.get("status") != "completed"
                or step.get("conclusion") != "success"):
            _fail("receipt_invalid")
    return True


def _inspect_core_bootstrap_markers(raw, control_sha, run_id, run_attempt, env):
    source_sha = env.get("SOURCE_SHA", "")
    if not _valid_sha(source_sha):
        _fail("invalid_input")
    if type(raw) is not bytes or raw.count(b"macos-core-bootstrap=refused"):
        _fail("receipt_invalid")
    preflight = _one_bootstrap_marker(
        raw, b"macos-core-bootstrap=preflight-passed", CORE_BOOTSTRAP_PREFLIGHT_MARKER_RE
    )
    success = _one_bootstrap_marker(
        raw, b"macos-core-bootstrap=verified", CORE_BOOTSTRAP_SUCCESS_MARKER_RE
    )
    source_binding = _one_bootstrap_marker(
        raw, b"macos-core-source-binding=verified", CORE_BOOTSTRAP_SOURCE_BINDING_MARKER_RE
    )
    expected = (control_sha.encode("ascii"), run_id.encode("ascii"), run_attempt.encode("ascii"))
    if preflight[:3] != expected or success[:3] != expected or source_binding[:3] != expected:
        _fail("receipt_invalid")
    source = source_sha.encode("ascii")
    if preflight[3] != source or success[6] != source or success[7] != source:
        _fail("receipt_invalid")
    if success[5] != BOOTSTRAP_SOURCE_REPOSITORY_IDS["core-bootstrap"].encode("ascii"):
        _fail("receipt_invalid")
    if source_binding[3] != BOOTSTRAP_SOURCE_REPOSITORY_IDS["core-bootstrap"].encode("ascii"):
        _fail("receipt_invalid")
    _inspect_reviewed_smoke_marker(raw, control_sha, run_id, run_attempt)
    _inspect_reviewed_summary_control_marker(raw, control_sha, run_id, run_attempt)


def _bootstrap_audit(api, kind, control_sha, run_id, run_attempt, env):
    configuration = _source_reader_configuration(kind)
    _validate_run(api, run_id, run_attempt, control_sha, configuration["workflow_path"])
    details = _bootstrap_jobs(api, kind, run_id, run_attempt, control_sha)
    if kind == "rules-bootstrap":
        snapshot_name = RULES_BOOTSTRAP_SETTINGS_JOB_NAME
        producer_name = RULES_BOOTSTRAP_PRODUCER_JOB_NAME
        audit_name = RULES_BOOTSTRAP_AUDIT_JOB_NAME
    else:
        snapshot_name = CORE_BOOTSTRAP_SNAPSHOT_JOB_NAME
        producer_name = CORE_BOOTSTRAP_PRODUCER_JOB_NAME
        audit_name = CORE_BOOTSTRAP_AUDIT_JOB_NAME
    snapshot_job, snapshot_check_id, snapshot_steps_success = details[snapshot_name]
    producer_job, producer_check_id, producer_steps_success = details[producer_name]
    snapshot_log = api.log_text(snapshot_job["id"])
    producer_log = api.log_text(producer_job["id"])
    inspect_reviewed_public_bytes(snapshot_log, control_sha)
    inspect_reviewed_public_bytes(producer_log, control_sha)
    _scan_annotations(api, snapshot_job, snapshot_check_id, control_sha, reviewed=True)
    _scan_annotations(api, producer_job, producer_check_id, control_sha, reviewed=True)
    _fetch_artifacts(api, run_id)
    cache_digest = _fetch_caches(api, control_sha, reviewed=True)
    if (snapshot_job.get("conclusion") != "success" or not snapshot_steps_success
            or producer_job.get("conclusion") != "success" or not producer_steps_success):
        if kind == "rules-bootstrap":
            rules_step = next(
                step for step in producer_job.get("steps", [])
                if type(step) is dict and step.get("name") == "Run fixed rules bootstrap"
            )
            if (rules_step.get("status") == "completed"
                    and rules_step.get("conclusion") == "failure"
                    and b"macos-rules-network=" not in producer_log
                    and _inspect_rules_early_source_refusal(
                        producer_log, producer_job, control_sha, run_id, run_attempt, env
                    )):
                _fail("native_job_failed")
            if ((rules_step.get("status") == "completed"
                    and rules_step.get("conclusion") != "skipped")
                    or b"macos-rules-network=" in producer_log):
                source_sha = env.get("REQUESTED_SOURCE_SHA", "")
                if not _valid_sha(source_sha):
                    _fail("receipt_invalid")
                _inspect_rules_network_observation(
                    producer_log, control_sha, run_id, run_attempt, source_sha
                )
        _fail("native_job_failed")
    baseline = env.get("MACOS_CACHE_SNAPSHOT", "")
    if HEX_DIGEST_RE.fullmatch(baseline) is None or cache_digest != baseline:
        _fail("inventory_changed")
    settings_marker = _verify_source_reader_environment(
        api, kind, control_sha, run_id, run_attempt
    )
    expected_settings = (
        "macos-source-environment=verified schema=1 kind=" + kind
        + " name=" + configuration["environment_name"]
        + " environment-id=" + str(configuration["environment_id"])
        + " policy-id=" + str(configuration["branch_policy_id"])
        + " custom-branch-policies=true protected-branches=false branch=main branch-type=branch"
        + " control-sha=" + control_sha + " run-id=" + run_id + " run-attempt=" + run_attempt
    ).encode("ascii")
    if settings_marker != expected_settings:
        _fail("api_schema")
    _inspect_bootstrap_settings_snapshot(snapshot_log, kind, control_sha, run_id, run_attempt)
    if kind == "rules-bootstrap":
        _inspect_rules_bootstrap_markers(producer_log, control_sha, run_id, run_attempt, env)
    else:
        _inspect_core_bootstrap_markers(producer_log, control_sha, run_id, run_attempt, env)
    print(
        "macos-" + kind + "-audit=verified schema=1 control-sha=" + control_sha
        + " run-id=" + run_id + " run-attempt=" + run_attempt
        + " public-surfaces=logs,checks,annotations,artifacts,caches summary-ui=required"
        + " source-admission=not-authorized"
    )
    return 0


def _core_contract_audit(api, control_sha, run_id, run_attempt, env):
    configuration = _source_reader_configuration("core-contract")
    try:
        _validate_run(api, run_id, run_attempt, control_sha, configuration["workflow_path"])
    except AuditRefusal as error:
        if error.reason == "run_identity_mismatch":
            raise CoreContractAuditRefusal(
                error.reason, "run_validation_identity",
            ) from None
        raise
    details = _core_contract_jobs(api, run_id, run_attempt, control_sha)
    settings_job, settings_check_id, settings_steps_success = details[CORE_CONTRACT_SETTINGS_JOB_NAME]
    producer_job, producer_check_id, producer_steps_success = details[CORE_CONTRACT_PRODUCER_JOB_NAME]

    settings_log = api.log_text(settings_job["id"]) if settings_job.get("steps") else b""
    producer_log = api.log_text(producer_job["id"]) if producer_job.get("steps") else b""
    if settings_log:
        inspect_reviewed_public_bytes(settings_log, control_sha)
    if producer_log:
        inspect_reviewed_public_bytes(producer_log, control_sha)
    _scan_annotations(api, settings_job, settings_check_id, control_sha, reviewed=True)
    _scan_annotations(api, producer_job, producer_check_id, control_sha, reviewed=True)
    _fetch_artifacts(api, run_id)
    cache_digest = _fetch_caches(api, control_sha, reviewed=True)
    baseline = env.get("MACOS_CACHE_SNAPSHOT", "")
    if HEX_DIGEST_RE.fullmatch(baseline) is None or cache_digest != baseline:
        _fail("inventory_changed")

    settings_marker = _verify_source_reader_environment(
        api, "core-contract", control_sha, run_id, run_attempt
    )
    expected_settings = (
        "macos-source-environment=verified schema=1 kind=core-contract"
        + " name=" + configuration["environment_name"]
        + " environment-id=" + str(configuration["environment_id"])
        + " policy-id=" + str(configuration["branch_policy_id"])
        + " custom-branch-policies=true protected-branches=false branch=main branch-type=branch"
        + " control-sha=" + control_sha + " run-id=" + run_id + " run-attempt=" + run_attempt
    ).encode("ascii")
    if settings_marker != expected_settings:
        _fail("api_schema")
    if settings_job.get("conclusion") == "success" and settings_steps_success:
        _inspect_bootstrap_settings_snapshot(settings_log, "core-contract", control_sha, run_id, run_attempt)
    else:
        _fail("native_job_failed")

    producer_steps = {
        step.get("name"): step
        for step in producer_job.get("steps", [])
        if type(step) is dict and type(step.get("name")) is str
    }
    core_step = producer_steps.get("Run fixed core contract")
    mint_step = producer_steps.get("Mint scoped source-reader token")
    fallback_step = producer_steps.get("Revoke token if contract did not confirm")
    if core_step is None:
        if producer_log and (
            b"KD-CORE-CONTRACT " in producer_log or b"KD-CORE-CONTRACT-REFUSAL " in producer_log
        ):
            _inspect_core_contract_receipt(producer_log, control_sha, run_id, run_attempt, env)
        _fail("native_job_failed")

    if producer_log:
        if producer_steps.get("Run source-free reviewed build smoke", {}).get("conclusion") == "success":
            _inspect_reviewed_smoke_marker(producer_log, control_sha, run_id, run_attempt)
        if producer_steps.get("Run source-free Rust toolchain smoke", {}).get("conclusion") == "success":
            _inspect_rust_toolchain_receipt(producer_log, control_sha, run_id, run_attempt)
        elif b"KD-RUST-REFUSAL" in producer_log:
            matches = list(RUST_TOOLCHAIN_REFUSAL_MARKER_RE.finditer(producer_log))
            if len(matches) != 1 or producer_log.count(b"KD-RUST-REFUSAL") != 1:
                _fail("receipt_invalid")
        if producer_steps.get("Write trusted summary visibility control", {}).get("conclusion") == "success":
            _inspect_reviewed_summary_control_marker(producer_log, control_sha, run_id, run_attempt)

    contract_state, contract_value = _inspect_core_contract_receipt(
        producer_log, control_sha, run_id, run_attempt, env
    ) if producer_log else ("absent", None)
    if (producer_steps.get("Validate protected contract binding", {}).get("conclusion") == "success"
            and producer_steps.get("Validate source-reader scope configuration", {}).get("conclusion") == "success"):
        if contract_state == "passed":
            _inspect_core_contract_binding_markers(
                producer_log, control_sha, run_id, run_attempt, env, require_summary=True,
            )
        else:
            _inspect_core_contract_binding_markers(
                producer_log, control_sha, run_id, run_attempt, env, require_summary=False,
                require_installation=(
                    producer_steps.get("Verify selected installation identity", {}).get("conclusion") == "success"
                ),
            )
    if fallback_step is not None and fallback_step.get("conclusion") in {"success", "failure"}:
        _inspect_core_contract_cleanup(
            producer_log, control_sha, run_id, run_attempt, required=True,
        )
    else:
        _inspect_core_contract_cleanup(
            producer_log, control_sha, run_id, run_attempt, required=False,
        )

    if (producer_job.get("conclusion") != "success" or not producer_steps_success
            or contract_state != "passed" or type(contract_value) is not dict):
        _fail("native_job_failed")
    if (core_step.get("status") != "completed" or core_step.get("conclusion") != "success"
            or mint_step is None or mint_step.get("conclusion") != "success"
            or fallback_step is None or fallback_step.get("conclusion") != "skipped"):
        _fail("receipt_invalid")
    print(
        "macos-core-contract-audit=verified schema=1 control-sha=" + control_sha
        + " run-id=" + run_id + " run-attempt=" + run_attempt
        + " source-sha=" + env.get("REQUESTED_SOURCE_SHA", "")
        + " base-sha=" + env.get("REQUESTED_BASE_SHA", "")
        + " reviewed-diff-sha256=" + env.get("REVIEWED_DIFF_SHA256", "")
        + " public-surfaces=logs,checks,annotations,artifacts,caches summary-ui=required"
        + " source-admission=not-authorized"
    )
    return 0


def _inspect_reviewed_smoke_marker(raw, control_sha, run_id, run_attempt):
    matches = list(REVIEWED_SMOKE_MARKER_RE.finditer(raw))
    if len(matches) != 1 or raw.count(b"macos-build=") != 1:
        _fail("receipt_invalid")
    match = matches[0]
    if match.group(1) != control_sha.encode("ascii") or match.group(2) != run_id.encode("ascii") or match.group(3) != run_attempt.encode("ascii"):
        _fail("receipt_invalid")


def _inspect_reviewed_network_selftest_marker(raw, control_sha, run_id, run_attempt):
    if type(raw) is not bytes:
        _fail("receipt_invalid")
    matches = list(REVIEWED_NETWORK_SELFTEST_MARKER_RE.finditer(raw))
    marker = b"macos-network-observer="
    if len(matches) != 1 or raw.count(marker) != 1:
        _fail("receipt_invalid")
    match = matches[0]
    if (match.group(1) != control_sha.encode("ascii")
            or match.group(2) != run_id.encode("ascii")
            or match.group(3) != run_attempt.encode("ascii")
            or int(match.group(4)) > 65535 or int(match.group(5)) > 65535):
        _fail("receipt_invalid")
    for group in (6, 7):
        items = match.group(group).split(b",")
        if items != sorted(set(items)):
            _fail("receipt_invalid")


def _inspect_reviewed_summary_control_marker(raw, control_sha, run_id, run_attempt):
    matches = list(REVIEWED_SUMMARY_CONTROL_MARKER_RE.finditer(raw))
    if len(matches) != 1 or raw.count(b"macos-summary-control=") != 1:
        _fail("receipt_invalid")
    match = matches[0]
    if (match.group(1) != control_sha.encode("ascii")
            or match.group(2) != run_id.encode("ascii")
            or match.group(3) != run_attempt.encode("ascii")):
        _fail("receipt_invalid")


def _scan_annotations(api, job, check_id, control_sha, reviewed=False):
    check_path = "/repos/keeldock-platform/platform-ci/check-runs/" + str(check_id)
    check_run, _ = api.json(check_path)
    if (type(check_run) is not dict or not _exact_int(check_run.get("id"), 1)
            or check_run["id"] != check_id or check_run.get("head_sha") != control_sha
            or check_run.get("status") != "completed"
            or type(check_run.get("conclusion")) is not str
            or check_run.get("conclusion") != job.get("conclusion")):
        _fail("run_identity_mismatch")
    output = check_run.get("output")
    if (type(output) is not dict or not _exact_int(output.get("annotations_count"), 0)
            or output["annotations_count"] > MAX_ANNOTATIONS):
        _fail("api_schema")
    try:
        output_bytes = json.dumps(output, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    except Exception:
        _fail("api_schema")
    inspect = inspect_reviewed_public_bytes if reviewed else inspect_public_bytes
    inspect(output_bytes, control_sha)
    path = "/repos/keeldock-platform/platform-ci/check-runs/" + str(check_id) + "/annotations"
    items = _read_annotations(api, path)
    if len(items) != output["annotations_count"]:
        _fail("pagination_incomplete")
    for item in items:
        try:
            raw = json.dumps(item, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
        except Exception:
            _fail("api_schema")
        inspect(raw, control_sha)


def _fetch_artifacts(api, run_id):
    path = "/repos/keeldock-platform/platform-ci/actions/runs/" + run_id + "/artifacts"
    artifacts = _read_counted_collection(api, path, "artifacts", MAX_ARTIFACT_ITEMS, _validate_artifact)
    if artifacts:
        _fail("artifact_found")


def _fetch_cache_entries(api, control_sha, reviewed=False):
    path = "/repos/keeldock-platform/platform-ci/actions/caches"
    caches = _read_counted_collection(api, path, "actions_caches", MAX_CACHE_ITEMS, _validate_cache)
    for item in caches:
        try:
            raw = json.dumps(item, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
        except Exception:
            _fail("api_schema")
        inspect = inspect_reviewed_public_bytes if reviewed else inspect_public_bytes
        inspect(raw, control_sha)
    cache_inventory_digest(caches)
    return caches


def _fetch_caches(api, control_sha, reviewed=False):
    return cache_inventory_digest(_fetch_cache_entries(api, control_sha, reviewed))


def _snapshot(phase, api, control_sha, run_id, run_attempt, env):
    bootstrap_kind = {
        "rules-bootstrap-snapshot": "rules-bootstrap",
        "core-bootstrap-snapshot": "core-bootstrap",
    }.get(phase)
    workflow_path = (
        CACHE_PROOF_WORKFLOW_PATH if phase == "cache-proof-snapshot"
        else REVIEWED_WORKFLOW_PATH if phase == "reviewed-snapshot"
        else RUST_TOOLCHAIN_WORKFLOW_PATH if phase == "rust-toolchain-snapshot"
        else _source_reader_configuration(bootstrap_kind)["workflow_path"]
        if bootstrap_kind is not None else WORKFLOW_PATH
    )
    _validate_run(api, run_id, run_attempt, control_sha, workflow_path)
    caches = _fetch_cache_entries(
        api,
        control_sha,
        reviewed=phase in {
            "reviewed-snapshot", "cache-proof-snapshot",
            "rules-bootstrap-snapshot", "core-bootstrap-snapshot", "rust-toolchain-snapshot",
        },
    )
    if phase == "cache-proof-snapshot":
        seed_key, write_key = _cache_proof_keys(run_id, run_attempt)
        if any(item.get("key") in {seed_key, write_key} for item in caches):
            _fail("inventory_changed")
    digest = cache_inventory_digest(caches)
    if phase in {
        "snapshot", "reviewed-snapshot", "cache-proof-snapshot",
        "rules-bootstrap-snapshot", "core-bootstrap-snapshot", "rust-toolchain-snapshot",
    }:
        _write_output("cache_snapshot", digest, env)
        if phase == "cache-proof-snapshot":
            print("macos-cache-proof=snapshot-ready")
        elif bootstrap_kind is not None:
            print(
                "macos-" + bootstrap_kind + "-snapshot=ready schema=1 control-sha="
                + control_sha + " run-id=" + run_id + " run-attempt=" + run_attempt
            )
        elif phase == "rust-toolchain-snapshot":
            print(
                "macos-rust-toolchain-snapshot=ready schema=1 control-sha="
                + control_sha + " run-id=" + run_id + " run-attempt=" + run_attempt
            )
        else:
            print("macos-public-surface-audit=snapshot-ready")
        return 0
    baseline = env.get("MACOS_CACHE_SNAPSHOT", "")
    if HEX_DIGEST_RE.fullmatch(baseline) is None or digest != baseline:
        _fail("inventory_changed")
    return 0


def _write_output(key, value, env):
    if key != "cache_snapshot" or HEX_DIGEST_RE.fullmatch(value) is None:
        _fail("output_unavailable")
    output_path = env.get("GITHUB_OUTPUT", "")
    if not output_path or not os.path.isabs(output_path):
        _fail("output_unavailable")
    try:
        descriptor = os.open(output_path, os.O_WRONLY | os.O_APPEND)
        try:
            remaining = memoryview((key + "=" + value + "\n").encode("ascii"))
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    _fail("output_unavailable")
                remaining = remaining[written:]
        finally:
            os.close(descriptor)
    except Exception:
        _fail("output_unavailable")


def run(phase, environ=None, api=None):
    env = os.environ if environ is None else environ
    supported_phases = {
        "snapshot", "audit", "reviewed-snapshot", "reviewed-audit",
        "cache-proof-snapshot", "cache-proof-audit", "cache-proof-cleanup",
        "rust-toolchain-snapshot", "rust-toolchain-audit",
    } | set(SOURCE_READER_PHASES)
    if phase not in supported_phases:
        _fail("invalid_input")
    repository = env.get("GITHUB_REPOSITORY", "")
    run_id = env.get("GITHUB_RUN_ID", "")
    run_attempt = env.get("GITHUB_RUN_ATTEMPT", "")
    control_sha = env.get("CI_SHA", "")
    token = env.get("GITHUB_TOKEN", "")
    if (repository != REPOSITORY or not _positive_decimal(run_id)
            or not _positive_decimal(run_attempt) or not _valid_sha(control_sha)):
        _fail("invalid_input")
    if api is None:
        api = GitHubAPI(token)
    elif type(token) is not str or TOKEN_RE.fullmatch(token) is None:
        _fail("invalid_input")
    if phase in {
        "snapshot", "reviewed-snapshot", "cache-proof-snapshot", "rust-toolchain-snapshot",
    }:
        return _snapshot(phase, api, control_sha, run_id, run_attempt, env)

    if phase in SOURCE_READER_PHASES:
        operation, kind = SOURCE_READER_PHASES[phase]
        configuration = _source_reader_configuration(kind)
        if operation == "audit":
            return _source_reader_audit(api, kind, control_sha, run_id, run_attempt, env)
        if operation == "bootstrap-audit":
            return _bootstrap_audit(api, kind, control_sha, run_id, run_attempt, env)
        if operation == "contract-audit":
            return _core_contract_audit(api, control_sha, run_id, run_attempt, env)
        current_run = _validate_run(
            api, run_id, run_attempt, control_sha, configuration["workflow_path"]
        )
        if operation == "settings":
            if kind in {"rules-bootstrap", "core-bootstrap", "core-contract"}:
                print(
                    _verify_bootstrap_dispatch_guard(
                        api, kind, current_run, control_sha, run_id, run_attempt
                    ).decode("ascii")
                )
            print(
                _verify_source_reader_environment(
                    api, kind, control_sha, run_id, run_attempt
                ).decode("ascii")
            )
            return 0
        if operation == "snapshot":
            digest = _fetch_caches(api, control_sha, reviewed=True)
            _write_output("cache_snapshot", digest, env)
            snapshot_name = (
                "macos-source-reader-snapshot" if kind in {"core", "rules"}
                else "macos-" + kind + "-snapshot"
            )
            print(
                snapshot_name + "=ready schema=1 control-sha=" + control_sha
                + " run-id=" + run_id + " run-attempt=" + run_attempt
            )
            return 0

    if phase == "cache-proof-audit":
        _validate_run(api, run_id, run_attempt, control_sha, CACHE_PROOF_WORKFLOW_PATH)
        details = _cache_proof_jobs(api, run_id, run_attempt, control_sha)
        seed_key, write_key = _cache_proof_keys(run_id, run_attempt)
        log_by_name = {}
        for name in (
            CACHE_PROOF_SNAPSHOT_JOB_NAME,
            CACHE_PROOF_SEED_JOB_NAME,
            CACHE_PROOF_POSITIVE_JOB_NAME,
            CACHE_PROOF_NONE_JOB_NAME,
        ):
            job, check_id, steps_success = details[name]
            if job.get("conclusion") != "success" or not steps_success:
                _fail("native_job_failed")
            log_bytes = api.log_text(job["id"])
            if name == CACHE_PROOF_NONE_JOB_NAME:
                inspect_cache_probe_public_bytes(log_bytes, control_sha)
            else:
                inspect_reviewed_public_bytes(log_bytes, control_sha)
            _scan_annotations(api, job, check_id, control_sha, reviewed=True)
            log_by_name[name] = log_bytes
        _fetch_artifacts(api, run_id)
        caches = _fetch_cache_entries(api, control_sha, reviewed=True)
        seed_entries = [item for item in caches if item["key"] == seed_key]
        write_entries = [item for item in caches if item["key"] == write_key]
        if (len(seed_entries) != 1 or write_entries
                or seed_entries[0]["ref"] != "refs/heads/main"
                or not seed_entries[0]["version"]
                or seed_entries[0]["size_in_bytes"] <= 0):
            _fail("inventory_changed")
        baseline_entries = [item for item in caches if item["key"] not in {seed_key, write_key}]
        baseline_digest = env.get("MACOS_CACHE_SNAPSHOT", "")
        if (HEX_DIGEST_RE.fullmatch(baseline_digest) is None
                or cache_inventory_digest(baseline_entries) != baseline_digest):
            _fail("inventory_changed")
        expected_seed_line = (
            "macos-cache-seed=step-complete schema=1 run-id=" + run_id
            + " run-attempt=" + run_attempt
        ).encode("ascii")
        expected_positive_line = (
            "macos-cache-positive=restored schema=1 run-id=" + run_id
            + " run-attempt=" + run_attempt
        ).encode("ascii")
        expected_none_read_line = (
            "macos-cache-none-read=local-absent schema=1 run-id=" + run_id
            + " run-attempt=" + run_attempt
        ).encode("ascii")
        expected_none_save_line = (
            "macos-cache-none-save=request-finished schema=1 run-id=" + run_id
            + " run-attempt=" + run_attempt
        ).encode("ascii")
        expected_client_source_line = (
            "macos-cache-client-source=verified schema=1 action-sha=" + CACHE_PROOF_ACTION_SHA
        ).encode("ascii")
        snapshot_log = log_by_name[CACHE_PROOF_SNAPSHOT_JOB_NAME]
        seed_log = log_by_name[CACHE_PROOF_SEED_JOB_NAME]
        positive_log = log_by_name[CACHE_PROOF_POSITIVE_JOB_NAME]
        none_log = log_by_name[CACHE_PROOF_NONE_JOB_NAME]
        _inspect_cache_client_markers(
            none_log, control_sha, run_id, run_attempt, seed_key, write_key
        )
        if b"macos-cache-proof=snapshot-ready" not in snapshot_log:
            _fail("receipt_invalid")
        if (seed_log.count(expected_seed_line) != 1
                or b"Cache saved with key: " + seed_key.encode("ascii") not in seed_log):
            _fail("receipt_invalid")
        if (positive_log.count(expected_positive_line) != 1
                or b"Cache restored from key: " + seed_key.encode("ascii") not in positive_log):
            _fail("receipt_invalid")
        if (none_log.count(expected_client_source_line) != 1
                or none_log.count(expected_none_read_line) != 1
                or none_log.count(expected_none_save_line) != 1
                or b"Cache restored from key: " + seed_key.encode("ascii") in none_log
                or b"Cache saved with key: " + write_key.encode("ascii") in none_log):
            _fail("receipt_invalid")
        print("macos-cache-proof=seeded-positive-and-none-denials-audited")
        return 0

    if phase == "cache-proof-cleanup":
        _validate_run(api, run_id, run_attempt, control_sha, CACHE_PROOF_WORKFLOW_PATH)
        seed_key, write_key = _cache_proof_keys(run_id, run_attempt)
        fixture_keys = {seed_key, write_key}
        caches = _fetch_cache_entries(api, control_sha, reviewed=True)
        for item in caches:
            if item["key"] in fixture_keys:
                if item["ref"] != "refs/heads/main":
                    _fail("inventory_changed")
        for item in caches:
            if item["key"] in fixture_keys and item["ref"] == "refs/heads/main":
                if not hasattr(api, "delete_cache"):
                    _fail("api_unavailable")
                api.delete_cache(item["id"])
        remaining = _fetch_cache_entries(api, control_sha, reviewed=True)
        if any(item["key"] in fixture_keys for item in remaining):
            _fail("inventory_changed")
        print("macos-cache-cleanup=complete schema=1 run-id=" + run_id + " run-attempt=" + run_attempt)
        return 0

    if phase == "reviewed-audit":
        _validate_run(api, run_id, run_attempt, control_sha, REVIEWED_WORKFLOW_PATH)
        snapshot, smoke = _reviewed_jobs(api, run_id, run_attempt, control_sha)
        snapshot_log = api.log_text(snapshot[0]["id"])
        inspect_reviewed_public_bytes(snapshot_log, control_sha)
        smoke_log = api.log_text(smoke[0]["id"])
        inspect_reviewed_public_bytes(smoke_log, control_sha)
        _scan_annotations(api, snapshot[0], snapshot[1], control_sha, reviewed=True)
        _scan_annotations(api, smoke[0], smoke[1], control_sha, reviewed=True)
        _fetch_artifacts(api, run_id)
        cache_digest = _fetch_caches(api, control_sha, reviewed=True)
        baseline = env.get("MACOS_CACHE_SNAPSHOT", "")
        if HEX_DIGEST_RE.fullmatch(baseline) is None or cache_digest != baseline:
            _fail("inventory_changed")
        if (snapshot[0].get("conclusion") != "success" or not snapshot[2]
                or smoke[0].get("conclusion") != "success" or not smoke[2]):
            _fail("native_job_failed")
        _inspect_reviewed_smoke_marker(smoke_log, control_sha, run_id, run_attempt)
        _inspect_reviewed_network_selftest_marker(smoke_log, control_sha, run_id, run_attempt)
        _inspect_reviewed_summary_control_marker(smoke_log, control_sha, run_id, run_attempt)
        print("macos-public-surface-audit=synthetic-smoke-audited")
        return 0

    if phase == "rust-toolchain-audit":
        _validate_run(api, run_id, run_attempt, control_sha, RUST_TOOLCHAIN_WORKFLOW_PATH)
        details = _rust_toolchain_jobs(api, run_id, run_attempt, control_sha)
        snapshot_detail, snapshot_check_id, snapshot_steps_success = details[
            RUST_TOOLCHAIN_SNAPSHOT_JOB_NAME
        ]
        smoke_detail, smoke_check_id, smoke_steps_success = details[RUST_TOOLCHAIN_SMOKE_JOB_NAME]
        snapshot_log = api.log_text(snapshot_detail["id"]) if snapshot_detail.get("steps") else b""
        smoke_log = api.log_text(smoke_detail["id"]) if smoke_detail.get("steps") else b""
        if snapshot_log:
            inspect_reviewed_public_bytes(snapshot_log, control_sha)
        if smoke_log:
            inspect_reviewed_public_bytes(smoke_log, control_sha)
        _scan_annotations(
            api, snapshot_detail, snapshot_check_id, control_sha, reviewed=True
        )
        _scan_annotations(
            api, smoke_detail, smoke_check_id, control_sha, reviewed=True
        )
        _fetch_artifacts(api, run_id)
        cache_digest = _fetch_caches(api, control_sha, reviewed=True)
        baseline = env.get("MACOS_CACHE_SNAPSHOT", "")
        if HEX_DIGEST_RE.fullmatch(baseline) is None or cache_digest != baseline:
            _fail("inventory_changed")
        if (snapshot_detail.get("conclusion") != "success" or not snapshot_steps_success
                or smoke_detail.get("conclusion") != "success" or not smoke_steps_success):
            if smoke_log and b"KD-RUST-REFUSAL" in smoke_log:
                refusal = list(RUST_TOOLCHAIN_REFUSAL_MARKER_RE.finditer(smoke_log))
                if len(refusal) != 1 or smoke_log.count(b"KD-RUST-REFUSAL") != 1:
                    _fail("receipt_invalid")
            _fail("native_job_failed")
        _inspect_rust_toolchain_snapshot(
            snapshot_log, control_sha, run_id, run_attempt
        )
        _inspect_reviewed_smoke_marker(smoke_log, control_sha, run_id, run_attempt)
        _inspect_reviewed_summary_control_marker(smoke_log, control_sha, run_id, run_attempt)
        _inspect_rust_toolchain_receipt(smoke_log, control_sha, run_id, run_attempt)
        print(
            "macos-rust-toolchain-audit=verified schema=1 control-sha=" + control_sha
            + " run-id=" + run_id + " run-attempt=" + run_attempt
            + " public-surfaces=logs,checks,annotations,artifacts,caches summary-ui=required"
            + " source-admission=not-authorized"
        )
        return 0

    _validate_run(api, run_id, run_attempt, control_sha)
    job, check_id, steps_success = _native_job(api, run_id, run_attempt, control_sha)
    log_bytes = api.log_text(job["id"])
    inspect_public_bytes(log_bytes, control_sha)
    _scan_annotations(api, job, check_id, control_sha)
    _fetch_artifacts(api, run_id)
    cache_digest = _fetch_caches(api, control_sha)
    baseline = env.get("MACOS_CACHE_SNAPSHOT", "")
    if HEX_DIGEST_RE.fullmatch(baseline) is None or cache_digest != baseline:
        _fail("inventory_changed")
    if job.get("conclusion") != "success" or not steps_success:
        _fail("native_job_failed")
    validate_receipt(env.get("MACOS_NATIVE_RECEIPT_B64URL", ""), control_sha, run_id, run_attempt)
    print("macos-public-surface-audit=passed")
    return 0


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    if args and args[0] == "core-contract-publish":
        if len(args) != 1:
            print("macos-core-contract-publish=refused reason=invalid_input")
            return 2
        try:
            return publish_core_contract_receipt()
        except AuditRefusal as error:
            reason = error.reason if error.reason in {"invalid_input", "capture_invalid"} else "internal_error"
            print("macos-core-contract-publish=refused reason=" + reason)
            return 2
        except BaseException:
            print("macos-core-contract-publish=refused reason=internal_error")
            return 2
    if args and args[0] == "rust-toolchain-publish":
        if len(args) != 1:
            return _rust_toolchain_publish_refusal("invalid_input")
        try:
            return publish_rust_toolchain_receipt()
        except AuditRefusal as error:
            reason = error.reason if error.reason in {"invalid_input", "capture_invalid"} else "internal_error"
            return _rust_toolchain_publish_refusal(reason)
        except BaseException:
            return _rust_toolchain_publish_refusal("internal_error")
    if len(args) != 1 or args[0] not in ({
        "snapshot", "audit", "reviewed-snapshot", "reviewed-audit",
        "cache-proof-snapshot", "cache-proof-audit", "cache-proof-cleanup",
        "rust-toolchain-snapshot", "rust-toolchain-audit",
    } | set(SOURCE_READER_PHASES)):
        print("macos-public-surface-audit=refused reason=invalid_input")
        return 2
    try:
        return run(args[0])
    except CoreContractAuditRefusal as error:
        if (len(args) == 1 and args[0] == "core-contract-audit"
                and error.reason == "run_identity_mismatch"
                and type(error.diagnostic) is str
                and error.diagnostic in CORE_CONTRACT_AUDIT_DIAGNOSTICS):
            print("macos-core-contract-audit-diagnostic=" + error.diagnostic)
        print("macos-public-surface-audit=refused reason=" + error.reason)
        return 2
    except AuditRefusal as error:
        print("macos-public-surface-audit=refused reason=" + error.reason)
        return 2
    except BaseException:
        print("macos-public-surface-audit=refused reason=internal_error")
        return 2


def _rust_toolchain_publish_refusal(reason):
    if reason not in {"invalid_input", "capture_invalid", "internal_error"}:
        reason = "internal_error"
    try:
        sys.stdout.buffer.write(
            ("KD-RUST-REFUSAL reason=" + reason + "\n").encode("ascii")
        )
        sys.stdout.buffer.flush()
    except Exception:
        return 2
    return 2


if __name__ == "__main__":
    sys.exit(main())
