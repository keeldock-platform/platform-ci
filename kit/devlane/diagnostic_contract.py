"""Finite, source-free diagnostics for the dependency preparation boundary."""

import re

import network_probe


PREPARATION_STAGES = frozenset((
    "prepare-argument-parse", "prepare-deadline-check", "prepare-platform-check",
    "prepare-owner-identity", "prepare-projection-validation", "prepare-toolchain-selection",
    "prepare-node-toolchain-validation", "prepare-node-toolchain-snapshot",
    "prepare-node-snapshot-verification", "prepare-node-version-verification",
    "prepare-node-vendor-acquisition", "prepare-node-vendor-cleanup",
    "prepare-rust-toolchain-validation", "prepare-rust-version-verification",
    "prepare-tool-root-selection", "prepare-namespace-isolation", "prepare-root-mounts",
    "prepare-worker-setup", "prepare-dependency-install", "prepare-playwright-install",
    "prepare-cargo-vendor", "prepare-prepared-output-copy", "prepare-cleanup",
    "prepare-launch", "prepare-protocol",
))

E2E_PROGRESS_PHASES = frozenset((
    "harness-startup", "argument-parse", "deadline-validate", "fixture-toolchain-discovery",
    "fixture-toolchain-verify", "fixture-generation", "runner-preflight", "fixture-load",
    "tooling-root-create", "tooling-root-fetch", "tooling-root-cleanup", "scenario-construction",
    "scenario-run", "late-scenario-construction", "late-scenario-run", "tool-path-discovery",
    "rust-tool-path-resolution", "tool-fetch-setup", "tool-staging-create", "tool-staging-cleanup",
    "tool-advisory-clone", "tool-advisory-revision", "tool-fetch-finish",
    "tool-cargo-deny-download", "tool-cargo-deny-extract", "tool-cargo-deny-version", "tool-cargo-deny-copy",
    "tool-cargo-audit-download", "tool-cargo-audit-extract", "tool-cargo-audit-version", "tool-cargo-audit-copy",
    "tool-cargo-vet-download", "tool-cargo-vet-extract", "tool-cargo-vet-version", "tool-cargo-vet-copy",
    "tool-cargo-semver-checks-download", "tool-cargo-semver-checks-extract",
    "tool-cargo-semver-checks-version", "tool-cargo-semver-checks-copy",
    "scenario-projection-write", "scenario-dependency-prepare", "scenario-tool-install",
    "scenario-tool-verify", "scenario-after-prepare-hook", "scenario-variant-run",
    "scenario-node-snapshot-cleanup", "scenario-prepared-tree-cleanup", "scenario-projection-cleanup",
    "variant-root-setup", "variant-projection-write", "variant-source-build", "variant-archive-build",
    "variant-rust-archive-verify", "variant-envelope-build", "variant-context-build",
    "variant-context-validate", "variant-context-write", "variant-positive-control",
    "variant-supervisor-start", "variant-supervisor-start-command", "variant-supervisor-start-check",
    "variant-startup-tamper", "variant-startup-command", "variant-startup-refusal-check",
    "variant-supervisor-probe-command", "variant-supervisor-probe-check", "variant-key-create",
    "variant-decrypt", "variant-decrypt-check", "variant-key-cleanup", "variant-execute",
    "variant-summary-validate", "variant-host-cleanup", "variant-teardown-confirm",
    "variant-host-cleanup-finally", "variant-teardown-confirm-finally",
    *PREPARATION_STAGES,
    "production-e2e-diagnostic-file",
))
E2E_PROGRESS_SCENARIOS = frozenset((
    "synthetic-node", "real-node", "synthetic-rust-v1-refusal", "install-script-canary", "real-browser",
))
CLEANUP_SUBREASONS = frozenset((
    "umount-busy", "umount-missing", "tree-remove", "process-alive", "cgroup-nonempty",
))
E2E_PROGRESS_MAX_LINES = 4096

PREPARATION_REFUSAL_CODES = frozenset((
    "preparation-control-size", "preparation-control-type", "projection-baseline-constraints",
    "action-budget-invalid", "action-work-budget-insufficient", "asset-binding-mismatch",
    "asset-digest", "asset-id", "asset-size", "cargo-lock-checksum", "cargo-lock-dependencies",
    "cargo-lock-duplicate", "cargo-lock-invalid", "cargo-lock-package", "cargo-lock-package-count",
    "cargo-lock-parser-unavailable", "cargo-lock-shape", "cargo-lock-size", "cargo-lock-source",
    "cargo-lock-version", "cargo-vendor-missing", "control-run-id", "control-sha", "deadline-budget-invalid",
    "deadline-cleanup-reserve-invalid", "deadline-command-invalid", "deadline-file-invalid",
    "deadline-start-invalid", "dispatch-control-ref", "dispatch-input", "dispatch-origin",
    "dispatch-run-id", "dispatch-shape", "download-http", "download-redirect",
    "download-redirect-limit", "download-size", "duplicate-json-key", "input-id", "json-invalid",
    "json-size", "node-snapshot-base-invalid", "node-snapshot-base-owner",
    "node-snapshot-base-unavailable", "node-snapshot-cleanup-incomplete", "node-snapshot-cleanup-owner",
    "node-snapshot-content-changed", "node-snapshot-content-invalid", "node-snapshot-copy-failed",
    "node-snapshot-deadline", "node-snapshot-exists", "node-snapshot-id", "node-snapshot-layout",
    "node-snapshot-limit", "node-snapshot-link-invalid", "node-snapshot-manifest-invalid",
    "node-snapshot-manifest-invalid:link-row-path",
    "node-snapshot-manifest-invalid:source-row-kind",
    "node-snapshot-manifest-invalid:manifest-open",
    "node-snapshot-manifest-invalid:manifest-metadata",
    "node-snapshot-manifest-invalid:manifest-race",
    "node-snapshot-manifest-invalid:manifest-missing",
    "node-snapshot-manifest-invalid:manifest-shape",
    "node-snapshot-manifest-invalid:manifest-digest",
    "node-snapshot-manifest-invalid:unlisted-site",
    "node-snapshot-missing", "node-snapshot-seal-invalid", "node-snapshot-source-changed",
    "node-snapshot-source-layout", "node-snapshot-source-owner", "node-snapshot-source-permissions",
    "node-snapshot-source-read", "node-tool-layout", "node-toolchain-executable", "node-toolchain-missing",
    "node-toolchain-directory-control-access", "node-toolchain-directory-scan-access",
    "node-toolchain-file-control-access",
    "node-toolchain-owner", "node-toolchain-version",
    "node-toolchain-source-anchor-write-mode", "node-toolchain-source-cache-root-write-mode",
    "node-toolchain-source-root-anchor-write-mode", "node-toolchain-source-opt-anchor-write-mode",
    "node-toolchain-source-node-layout-write-mode", "node-toolchain-source-npm-layout-write-mode",
    "node-toolchain-source-npm-tree-write-mode", "node-toolchain-source-node-file-write-mode",
    "node-toolchain-source-npm-file-write-mode",
    "npm-toolchain-version", "offline-rust-preparation-not-ready", "npm-lock-bin",
    "npm-lock-coordinate-ambiguous", "npm-lock-coordinate-missing", "npm-lock-dependencies",
    "npm-lock-deprecated", "npm-lock-engine", "npm-lock-flag", "npm-lock-funding", "npm-lock-integrity",
    "npm-lock-license", "npm-lock-metadata", "npm-lock-package", "npm-lock-package-name",
    "npm-lock-packages", "npm-lock-path", "npm-lock-peer-meta", "npm-lock-platform",
    "npm-lock-root-dependencies", "npm-lock-root-metadata", "npm-lock-shape", "npm-lock-url",
    "npm-manifest-projection-mismatch", "npm-manifest-shape", "npm-workspaces-unsupported",
    "vendor-node-archive-size", "vendor-node-archive-type", "vendor-node-archive-write",
    "vendor-node-checksum", "vendor-node-deadline", "vendor-node-directory",
    "vendor-node-expanded-size", "vendor-node-layout", "vendor-node-link",
    "vendor-node-member-count", "vendor-node-member-path", "vendor-node-member-read",
    "vendor-node-member-size", "vendor-node-member-type", "vendor-node-member-write",
    "vendor-node-origin", "vendor-node-platform-or-id",
    "linux-root-required", "owner-identity", "preparation-failed", "preparation-log-size", "preparation-parser-refusal",
    "preparation-refusal-unlisted", "preparation-root-invalid", "preparation-timeout",
    "preparation-tool-unavailable", "prepared-file-count", "prepared-link-invalid",
    "prepared-member-type", "prepared-output-exists", "prepared-output-invalid",
    "prepared-output-member", "prepared-tree-size", "profile", "profile-binding",
    "projection-binding", "projection-cargo", "projection-cargo-coordinate", "projection-cargo-duplicate",
    "projection-cargo-entry", "projection-cargo-lock", "projection-cargo-manifest",
    "projection-cargo-workspace", "projection-cargo-workspace-path", "projection-cargo-workspace-set",
    "projection-cargo-workspaces", "projection-constraint-binding", "projection-constraint-count",
    "projection-constraint-digest", "projection-constraint-order", "projection-constraint-row",
    "projection-constraint-scopes", "projection-constraint-shape", "projection-constraint-size",
    "projection-manifest-digest", "projection-source-identity", "projection-node-workspaces", "projection-npm",
    "projection-npm-coordinate", "projection-npm-duplicate", "projection-npm-entry",
    "projection-npm-lock", "projection-npm-package", "projection-playwright",
    "projection-playwright-package", "projection-shape", "projection-tool-version", "projection-tools",
    "repository-identity", "request-expired", "request-expiry-range", "resolver-config-unavailable",
    "run-attempt", "rust-tool-layout", "rust-toolchain-missing", "rust-toolchain-path",
    "rust-toolchain-version", "total-deadline-exhausted", "total-deadline-unavailable",
    "toolchain-version", "playwright-browsers-missing", "playwright-cli-missing", "cleanup-incomplete",
))

PREPARATION_EXCEPTION_LABELS = frozenset((
    "assertion-error", "attribute-error", "file-exists", "file-not-found", "index-error",
    "is-directory", "json-decode-error", "key-error", "memory-error", "name-error",
    "not-directory", "os-error", "overflow-error", "permission-denied", "process-error",
    "process-exit-error", "process-timeout", "recursion-error", "runtime-error", "timeout-error",
    "type-error", "unicode-decode-error", "unicode-error", "unclassified", "value-error",
))

PREPARATION_PARENT_CATEGORIES = frozenset((
    "preparation-exception-unlisted", "preparation-output-canary", "preparation-output-invalid",
    "preparation-output-limit", "preparation-process-error", "preparation-process-exit",
    "preparation-process-start-error", "preparation-process-timeout", "preparation-refusal-unlisted",
    "prepared-tree-missing",
))

ACCEPTANCE_FAILURE_STAGES = frozenset((
    "rust-v2-preparation-tests", "rust-v2-lock-tests", "rust-v2-source-tests", "rust-v2-public-runtime",
    "crypto-dependency-probe", "acceptance-unit-tests", "coordinator-contract-tests",
    "rust-matrix-runner-tests", "rust-report-tests", "node-adapter-tests", "audit-contract-tests",
    "rehearsal-tests", "production-path-e2e",
))

TOOLING_E2E_PHASES = frozenset((
    "tooling-root-create", "tooling-root-fetch", "tooling-root-cleanup",
    "tool-staging-create", "tool-staging-cleanup", "tool-fetch-setup",
    "tool-advisory-clone", "tool-advisory-revision", "tool-fetch-finish",
    "tool-cargo-deny-download", "tool-cargo-deny-extract", "tool-cargo-deny-version",
    "tool-cargo-deny-copy", "tool-cargo-audit-download", "tool-cargo-audit-extract",
    "tool-cargo-audit-version", "tool-cargo-audit-copy", "tool-cargo-vet-download",
    "tool-cargo-vet-extract", "tool-cargo-vet-version", "tool-cargo-vet-copy",
    "tool-cargo-semver-checks-download", "tool-cargo-semver-checks-extract",
    "tool-cargo-semver-checks-version", "tool-cargo-semver-checks-copy",
    "scenario-tool-install", "scenario-tool-verify",
))
NETWORK_PROBE_E2E_STAGES = frozenset(("variant-supervisor-probe-check",))
NETWORK_PROBE_E2E_CATEGORIES = frozenset((
    "network-probe-command-failed", "network-probe-output-invalid",
    *("network-probe-refusal:" + code for code in network_probe.REFUSAL_CODES),
))
PUBLIC_DIAGNOSTIC_PHASES = PREPARATION_STAGES | TOOLING_E2E_PHASES | NETWORK_PROBE_E2E_STAGES
PREPARATION_E2E_CATEGORIES = frozenset(
    set(PREPARATION_REFUSAL_CODES)
    | {"prepare-" + label for label in PREPARATION_EXCEPTION_LABELS}
    | set(PREPARATION_PARENT_CATEGORIES)
    | {"tooling-refusal"}
    | NETWORK_PROBE_E2E_CATEGORIES
)

_REFUSAL_RESULT = re.compile(
    rb"dependency_preparation_refusal=stage=([a-z0-9-]{1,48}) "
    rb"code=([a-z0-9-]{1,48}(?::[a-z0-9-]{1,48})?) cleanup=(not-needed|confirmed|unconfirmed)"
    rb"(?: reason=(umount-busy|umount-missing|tree-remove|process-alive|cgroup-nonempty))?\n\Z"
)
_EXCEPTION_RESULT = re.compile(
    rb"dependency_preparation_exception=stage=([a-z0-9-]{1,48}) "
    rb"class=([a-z0-9-]{1,48}) cleanup=(not-needed|confirmed|unconfirmed)"
    rb"(?: reason=(umount-busy|umount-missing|tree-remove|process-alive|cgroup-nonempty))?\n\Z"
)
_E2E_REFUSAL = re.compile(
    r"devlane_production_e2e=refused stage=([a-z0-9-]{1,48}) "
    r"exception=([a-z0-9-]{1,48}(?::[a-z0-9-]{1,48}){0,2})"
    r"(?: (" + network_probe.ROUTE_DIAGNOSTIC_PATTERN + r"))?"
    r"(?: reason=([a-z0-9-]{1,48})(?: version=\"([A-Za-z0-9._+-][A-Za-z0-9 ._+-]{0,31})\")?)?"
    r"(?: cleanup=(unconfirmed))?\Z"
)
_E2E_RUNTIME_ERROR = re.compile(
    r"devlane_production_e2e=refused stage=(variant-execute|variant-summary-validate) "
    r"exception=runtime-error "
    r"class=RuntimeError frame=([A-Za-z0-9_-]{1,48}\.py):([1-9][0-9]{0,7}):"
    r"([A-Za-z_][A-Za-z0-9_]{0,63})(?: code=([a-z0-9-]{1,64}))?\Z"
)
E2E_REQUIRE_CODES = frozenset((
    "background-process-survived-cleanup", "browser-frame-not-reported", "cancel-target-did-not-start",
    "cancelled-execute-reported-success", "canary-after-cancel", "canary-in-command-output",
    "canary-in-summary",
    "deadline-file-required", "host-cleanup-root-remains", "install-script-canary-lacks-marker",
    "install-script-canary-missing", "install-script-canary-platform-package-missing", "install-script-ran",
    "linux-esbuild-native-package-missing", "linux-native-lock-entry-missing",
    "linux-rollup-native-package-missing",
    "linux-runner-user-required", "linux-tools-required", "node-snapshot-supervisor-unconfirmed",
    "positive-control-failed", "prepared-cleanup-supervisor-unconfirmed", "prepared-cleanup-tree-remains",
    "production-path-command-failed", "reviewed-lock-package-missing", "runner-root-already-exists",
    "rust-fixture-lock-missing", "rust-fixture-output-exists", "rust-fixture-path-required",
    "rust-fixture-rustfmt-toolchain", "rust-fixture-rustfmt-unavailable", "rust-fixture-rustup-home",
    "rust-fixture-source-missing", "rust-fixture-toolchain-version", "rust-matrix-advisory-database-binding",
    "rust-matrix-advisory-database-copy-binding", "rust-matrix-advisory-database-dirty",
    "rust-matrix-advisory-database-layout", "rust-matrix-advisory-database-missing",
    "rust-matrix-advisory-database-revision", "rust-matrix-archive-lock-bytes", "rust-matrix-archive-lock-set",
    "rust-matrix-envelope-lock-binding", "rust-matrix-envelope-lock-set", "rust-matrix-fixture-files",
    "rust-matrix-fixture-source-binding", "rust-matrix-fixture-vet-policy", "rust-matrix-listener-package",
    "rust-matrix-lock-snapshot-file-binding", "rust-matrix-lock-snapshot-mismatch",
    "rust-matrix-lock-snapshot-set", "rust-matrix-lock-snapshot-shape", "rust-matrix-lock-snapshot-size",
    "rust-matrix-policy-or-replay-fixture", "rust-matrix-projection-file-binding",
    "rust-matrix-projection-invalid", "rust-matrix-projection-paths", "rust-matrix-projection-snapshot",
    "rust-matrix-projection-snapshot-shape", "rust-matrix-root-dependency-projection",
    "rust-matrix-root-projection", "rust-matrix-suite-count", "rust-matrix-suite-set",
    "rust-matrix-summary-counts", "rust-matrix-summary-coverage-set", "rust-matrix-summary-not-all-pass",
    "rust-matrix-summary-profile", "rust-matrix-test-map", "rust-matrix-tool-copy-binding",
    "rust-matrix-tool-directory-access", "rust-matrix-tool-layout",
    "rust-matrix-tool-preparation-missing", "rust-matrix-tool-version",
    "rust-matrix-toolchain-mismatch", "rust-matrix-tools-layout", "rust-matrix-tools-link",
    "rust-matrix-tools-missing", "rust-matrix-v1-non-semver-failure",
    "rust-matrix-v1-semver-refusal", "rust-matrix-workspace-dependencies",
    "rust-matrix-workspace-projection", "rust-matrix-workspace-set", "rust-tool-cleanup-remains",
    "rustup-unavailable", "summary-after-decrypt-refusal", "summary-limits", "summary-schema-invalid",
    "supervisor-survived-cleanup", "test-failure-not-mapped", "unexpected-control-failure",
    "vitest-negative-control-summary",
    "workflow-identity-required",
))
RUST_MATRIX_REFUSAL_CODES = frozenset((
    "advisory-database-copy-exists", "advisory-database-link", "advisory-database-missing",
    "cargo-artifact-identity-conflict", "cargo-artifact-invalid", "cargo-build-incomplete",
    "cargo-finish-invalid", "cargo-manifest-path-invalid", "cargo-message-invalid",
    "cargo-reason-invalid", "cargo-test-path-invalid", "cargo-test-unavailable",
    "duplicate-json-key", "fuzz-replay-failed", "fuzz-replay-report-invalid",
    "input-file-changed", "input-file-invalid", "input-file-size", "json-invalid", "json-size",
    "matrix-capture-size", "matrix-phase-timeout", "matrix-profile-mismatch",
    "matrix-report-exists", "matrix-runner-failed", "matrix-workspace-mode",
    "rust-ignored-list-failed", "rust-ignored-list-invalid", "rust-test-coverage",
    "rust-test-duplicate", "rust-test-ignored", "rust-test-list-failed",
    "rust-test-list-invalid", "rust-test-list-size", "rust-test-map-invalid",
    "rust-test-output-size", "rust-test-result-invalid", "rust-test-scope-invalid",
    "rust-test-timeout", "total-deadline-exhausted", "total-deadline-invalid",
))
E2E_COMMAND_CALL_SITES = frozenset(("supervisor-client:execute",))
MAX_E2E_COMMAND_OUTPUT_BYTES = 16 * 1024
MAX_E2E_COMMAND_DIAGNOSTIC_LINES = 4
MAX_E2E_COMMAND_SUMMARY_RECORD_BYTES = 512
MAX_E2E_VITEST_DIAGNOSTIC_LINES = 2048
MAX_E2E_VITEST_DIAGNOSTIC_BYTES = 512
_E2E_COMMAND_FAILURE = re.compile(
    r"devlane_e2e_command=failed call=(supervisor-client:execute) "
    r"returncode=(-?(?:0|[1-9][0-9]{0,8}))\Z"
)
_E2E_COMMAND_SUPERVISOR_REFUSAL = re.compile(
    r"devlane_supervisor_refusal=([a-z0-9-]{1,64}(?::[a-z0-9-]{1,48}){0,2})"
    r"(?: (" + network_probe.ROUTE_DIAGNOSTIC_PATTERN + r"))?\Z"
)
_E2E_COMMAND_ADAPTER_REFUSAL = re.compile(
    r"typescript_reporter_refusal=(manifest-invalid|file-map-invalid|tsconfig-feature-unsupported|"
    r"tsconfig-invalid|tsconfig-option-unsupported|tsconfig-option-invalid|typescript-files-invalid|"
    r"typescript-unavailable|source-root-invalid|usage|input-file-invalid|input-file-truncated|"
    r"diagnostic-count|diagnostic-size|"
    r"reporter-failed|json-size|json-string|json-escape|json-control|json-depth|duplicate-json-key|"
    r"json-colon|json-object|json-array|json-value|json-trailing-data)\Z"
)
_E2E_RUST_MATRIX_REFUSAL = re.compile(
    r"rust_matrix=refused code=([a-z][a-z0-9-]{0,79})\Z"
)
_E2E_FAILURE_DIAGNOSTIC = re.compile(
    r"devlane_e2e_(?:vitest|failure)_diag=log name=[A-Za-z0-9][A-Za-z0-9._-]{0,63} "
    r"line=[1-9][0-9]{0,2} text=((?:[A-Za-z0-9._~:/,=@+!?(){} -]|%[0-9A-F]{2}){0,384})\Z"
)
_E2E_FAILURE_REPORT_DIAGNOSTIC = re.compile(
    r"devlane_e2e_(?:vitest|failure)_diag=report name=[A-Za-z0-9][A-Za-z0-9._-]{0,63} "
    r"kind=(directory|file|symlink|other|missing) bytes=(?:0|[1-9][0-9]{0,11})\Z"
)


def public_e2e_command_diagnostic(line):
    """Accept execute metadata, refusal lines, or one canonical public summary record."""
    if public_e2e_command_summary_record(line):
        return True
    if type(line) is not str or len(line.encode("ascii", "ignore")) > MAX_PUBLIC_DIAGNOSTIC_BYTES:
        return False
    if _E2E_COMMAND_FAILURE.fullmatch(line):
        return True
    return public_e2e_command_refusal(line)


def public_e2e_vitest_diagnostic(line):
    """Accept the legacy Vitest and profile-neutral bounded E2E diagnostics."""
    return public_e2e_failure_diagnostic(line)


def public_e2e_failure_diagnostic(line):
    """Accept only bounded, escaped raw-log and report-listing lines from synthetic E2E."""
    if type(line) is not str:
        return False
    try:
        payload = line.encode("ascii", "strict")
    except UnicodeEncodeError:
        return False
    if (len(payload) > MAX_E2E_VITEST_DIAGNOSTIC_BYTES or "::" in line
            or (chr(35) * 2 + "[") in line
            or any(marker in line for marker in (
                "SYNTHETIC_SOURCE_CANARY", "PRIVATE_SOURCE_CANARY", "KEYCANARY",
                "SYNTHETIC_KEY_CANARY", "PRIVATE_KEY_CANARY",
            ))):
        return False
    failure = _E2E_FAILURE_DIAGNOSTIC.fullmatch(line)
    if failure is not None:
        text = failure.group(1)
        if text.startswith("rust_matrix=refused"):
            refusal = _E2E_RUST_MATRIX_REFUSAL.fullmatch(text)
            return refusal is not None and refusal.group(1) in RUST_MATRIX_REFUSAL_CODES
        return True
    return _E2E_FAILURE_REPORT_DIAGNOSTIC.fullmatch(line) is not None


def public_e2e_command_summary_record(line):
    """Accept one line validated by the closed public summary record grammar."""
    if type(line) is not str:
        return False
    try:
        payload = line.encode("ascii", "strict")
    except UnicodeEncodeError:
        return False
    if len(payload) > MAX_E2E_COMMAND_SUMMARY_RECORD_BYTES:
        return False
    try:
        from filter import is_public_summary_record
    except ImportError:
        return False
    return is_public_summary_record(payload)


def public_e2e_command_refusal(line):
    """Accept only refusal lines emitted by the supervisor or its fixed adapters."""
    if type(line) is not str or len(line.encode("ascii", "ignore")) > MAX_PUBLIC_DIAGNOSTIC_BYTES:
        return False
    refusal = _E2E_COMMAND_SUPERVISOR_REFUSAL.fullmatch(line)
    if refusal:
        code, route = refusal.groups()
        return route is None or (code == "network-probe-refusal:network-route-unexpected"
                                 and network_probe.valid_route_diagnostic(route))
    if line == "rust_test_adapter=refused":
        return True
    rust_matrix = _E2E_RUST_MATRIX_REFUSAL.fullmatch(line)
    if rust_matrix is not None:
        return rust_matrix.group(1) in RUST_MATRIX_REFUSAL_CODES
    return _E2E_COMMAND_ADAPTER_REFUSAL.fullmatch(line) is not None


TOOLING_REFUSAL_CODES = frozenset((
    "deadline-file-required", "tool-download-failed", "tool-archive-size",
    "tool-digest-mismatch", "tool-archive-members", "tool-archive-path",
    "tool-binary-missing", "tool-version-unavailable", "tool-version-mismatch",
    "tool-binary-invalid", "tool-binary-size", "tool-output-exists",
    "tool-copy-invalid", "advisory-database-fetch-failed",
    "advisory-database-revision", "tool-tree-invalid", "tool-destination-exists",
    "advisory-database-link", "tooling-refusal-unlisted",
))
MAX_PREPARATION_OUTPUT_BYTES = 24576
MAX_PUBLIC_DIAGNOSTIC_BYTES = 384
MAX_ACCEPTANCE_DETAIL_BYTES = 384
PREPARATION_LOG_DIAGNOSTIC_STAGES = frozenset((
    "prepare-dependency-install", "prepare-playwright-install", "prepare-cargo-vendor",
))
PREPARATION_LOG_DIAGNOSTIC_LINES = 48
_PREPARATION_LOG_DIAGNOSTIC = re.compile(
    r"devlane_preparation_detail stage=([a-z0-9-]{1,48}) "
    r"index=(0|[1-9][0-9]{0,2}) text=([A-Za-z0-9 ._/:,@=!?()+-]{1,200})\Z"
)
_ACCEPTANCE_DETAIL = re.compile(
    r"devlane_acceptance_detail stage=([a-z0-9-]{1,64}) index=(0|[1-9][0-9]{0,2}) text=([ -~]{1,256})\Z"
)
_SYNTHETIC_CANARIES = (
    "SYNTHETIC_SOURCE_CANARY", "PRIVATE_SOURCE_CANARY", "SYNTHETIC_KEY_CANARY",
    "PRIVATE_KEY_CANARY", "KEYCANARY",
)
_WORKFLOW_GROUP_MARKER = chr(35) * 2 + "["


def parse_preparation_result(returncode, stdout, stderr):
    """Return the trusted failure tuple, or None for the one exact success shape."""
    if type(returncode) is not int or type(stdout) is not bytes or type(stderr) is not bytes:
        return "prepare-protocol", "preparation-output-invalid", "not-needed"
    if len(stdout) + len(stderr) > MAX_PREPARATION_OUTPUT_BYTES:
        return "prepare-protocol", "preparation-output-limit", "not-needed"
    if returncode == 0:
        if stdout == b"dependency_preparation=complete\n" and stderr == b"":
            return None
        return "prepare-protocol", "preparation-output-invalid", "not-needed"
    if returncode != 2:
        return "prepare-launch", "preparation-process-exit", "not-needed"
    if stdout:
        return "prepare-protocol", "preparation-output-invalid", "not-needed"
    refusal = _REFUSAL_RESULT.fullmatch(stderr)
    if refusal:
        stage, code, cleanup, cleanup_reason = (
            part.decode("ascii") if part is not None else "" for part in refusal.groups()
        )
        if stage not in PREPARATION_STAGES:
            return "prepare-protocol", "preparation-output-invalid", "not-needed"
        if cleanup_reason and cleanup != "unconfirmed":
            return "prepare-protocol", "preparation-output-invalid", "not-needed"
        if code == "cleanup-incomplete" and (stage != "prepare-cleanup" or cleanup != "unconfirmed"
                                               or cleanup_reason not in CLEANUP_SUBREASONS):
            return "prepare-protocol", "preparation-output-invalid", "not-needed"
        if code not in PREPARATION_REFUSAL_CODES:
            return stage, "preparation-refusal-unlisted", cleanup
        if cleanup_reason:
            return stage, code, cleanup, cleanup_reason
        return stage, code, cleanup
    exception = _EXCEPTION_RESULT.fullmatch(stderr)
    if exception:
        stage, label, cleanup, cleanup_reason = (
            part.decode("ascii") if part is not None else "" for part in exception.groups()
        )
        if stage not in PREPARATION_STAGES:
            return "prepare-protocol", "preparation-output-invalid", "not-needed"
        if cleanup_reason and cleanup != "unconfirmed":
            return "prepare-protocol", "preparation-output-invalid", "not-needed"
        if label not in PREPARATION_EXCEPTION_LABELS:
            if cleanup_reason:
                return stage, "preparation-exception-unlisted", cleanup, cleanup_reason
            return stage, "preparation-exception-unlisted", cleanup
        if cleanup_reason:
            return stage, "prepare-" + label, cleanup, cleanup_reason
        return stage, "prepare-" + label, cleanup
    return "prepare-protocol", "preparation-output-invalid", "not-needed"


def parse_preparation_log_diagnostics(payload):
    """Accept only bounded, scrubbed detail records from source-free preparation logs."""
    if type(payload) is not bytes or len(payload) > MAX_PREPARATION_OUTPUT_BYTES:
        return None
    if not payload:
        return ()
    if not payload.endswith(b"\n"):
        return None
    lines = payload[:-1].split(b"\n")
    if not 1 <= len(lines) <= PREPARATION_LOG_DIAGNOSTIC_LINES + 1:
        return None
    accepted = []
    selected_stage = None
    previous_index = -1
    hash_group = chr(35) * 2 + "["
    for raw_line in lines:
        try:
            line = raw_line.decode("ascii", "strict")
        except UnicodeDecodeError:
            return None
        match = _PREPARATION_LOG_DIAGNOSTIC.fullmatch(line)
        if match is None:
            return None
        stage, index, text = match.groups()
        if (stage not in PREPARATION_LOG_DIAGNOSTIC_STAGES or "::" in text
                or hash_group in text
                or any(marker in text for marker in (
                    "SYNTHETIC_SOURCE_CANARY", "PRIVATE_SOURCE_CANARY",
                    "SYNTHETIC_KEY_CANARY", "PRIVATE_KEY_CANARY", "KEYCANARY",
                ))):
            return None
        number = int(index)
        if (selected_stage is not None and stage != selected_stage) or number <= previous_index \
                or number > PREPARATION_LOG_DIAGNOSTIC_LINES:
            return None
        selected_stage = stage
        previous_index = number
        accepted.append(line)
    return tuple(accepted)


def public_preparation_diagnostic(line):
    """Accept only bounded preparation-stage diagnostics for the synthetic job log."""
    if type(line) is not str or len(line.encode("ascii", "ignore")) > MAX_PUBLIC_DIAGNOSTIC_BYTES:
        return False
    match = _E2E_REFUSAL.fullmatch(line)
    if not match:
        return False
    stage, category, route_detail, reason, version, cleanup = match.groups()
    if stage not in PUBLIC_DIAGNOSTIC_PHASES or category not in PREPARATION_E2E_CATEGORIES:
        return False
    if category in NETWORK_PROBE_E2E_CATEGORIES and stage not in NETWORK_PROBE_E2E_STAGES:
        return False
    if route_detail is not None and (
            category != "network-probe-refusal:network-route-unexpected"
            or not network_probe.valid_route_diagnostic(route_detail)):
        return False
    if category == "tooling-refusal":
        if reason not in TOOLING_REFUSAL_CODES:
            return False
        if version is not None and reason != "tool-version-mismatch":
            return False
    elif category == "cleanup-incomplete":
        if reason not in CLEANUP_SUBREASONS or cleanup != "unconfirmed" or version is not None:
            return False
    elif reason is not None:
        if reason not in CLEANUP_SUBREASONS or cleanup != "unconfirmed" or version is not None:
            return False
    elif version is not None:
        return False
    return cleanup is None or cleanup == "unconfirmed"


def public_e2e_runtime_diagnostic(line):
    """Accept a fixed RuntimeError frame and, when present, its fixed _require code."""
    if type(line) is not str or len(line.encode("ascii", "ignore")) > MAX_PUBLIC_DIAGNOSTIC_BYTES:
        return False
    match = _E2E_RUNTIME_ERROR.fullmatch(line)
    return match is not None and (match.group(5) is None or match.group(5) in E2E_REQUIRE_CODES)


_E2E_PROGRESS_LINE = re.compile(r"devlane_e2e_progress=(phase|scenario)=([a-z0-9-]{1,64})\Z")


def public_e2e_progress(line):
    """Accept only the fixed phase and scenario progress markers from the harness."""
    if type(line) is not str or len(line) > 96:
        return False
    match = _E2E_PROGRESS_LINE.fullmatch(line)
    if match is None:
        return False
    kind, name = match.groups()
    return name in (E2E_PROGRESS_PHASES if kind == "phase" else E2E_PROGRESS_SCENARIOS)


def public_acceptance_detail(line):
    """Accept one short, neutralized output line from a source-free control stage."""
    return acceptance_detail_stage(line) is not None


def acceptance_detail_stage(line):
    """Return the accepted source-free failure stage carried by one detail line."""
    if type(line) is not str or len(line.encode("ascii", "ignore")) > MAX_ACCEPTANCE_DETAIL_BYTES:
        return None
    match = _ACCEPTANCE_DETAIL.fullmatch(line)
    if match is None:
        return None
    stage, _index, text = match.groups()
    if (stage not in ACCEPTANCE_FAILURE_STAGES
            or "::" in text or _WORKFLOW_GROUP_MARKER in text
            or any(canary in text for canary in _SYNTHETIC_CANARIES)
            or "\x1b" in text or not all(ord(character) >= 32 for character in text)):
        return None
    return stage
