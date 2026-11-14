"""Platform-neutral refusal vocabularies shared by audits and the supervisor."""

import json
import signal
import subprocess

import network_probe


CLEANUP_SUBREASONS = frozenset((
    "umount-busy", "umount-missing", "tree-remove", "process-alive", "cgroup-nonempty",
))

DOWNLOAD_REFUSAL_CODES = frozenset((
    "download-http-1xx", "download-http-2xx", "download-http-3xx", "download-http-4xx",
    "download-http-5xx", "download-http-401", "download-http-403", "download-http-404",
    "download-http-410", "download-http-429", "download-http-other",
    "download-auth-invalid", "download-forbidden", "download-rate-limited",
    "download-redirect-invalid", "download-timeout",
))

REFUSAL_CODES = frozenset((
    "matrix-semver-cgroup-unavailable",
    "matrix-semver-cgroup-cleanup",
    "matrix-semver-context-write",
    "matrix-semver-cargo-home",
    "matrix-semver-inputs",
    "matrix-semver-process",
    "matrix-semver-runner-identity",
    "matrix-semver-runner-order",
    "matrix-semver-target",
    "matrix-semver-tool-binding",
    "matrix-semver-worker-channel",
    "matrix-semver-worker-peer",
    "crypto-dependency-install-failed", "crypto-dependency-verification-failed",
    "crypto-unavailable",
    "windows-node-runtime-invalid",
    "windows-npm-runtime-install-failed",
    "windows-npm-runtime-version-invalid",
    "source-free-diagnostics-context",
    "source-free-diagnostics-path",
    'matrix-semver-checkpoint-cgroup',
    'matrix-semver-checkpoint-cgroup-not-quiescent',
    'matrix-semver-checkpoint-command',
    'matrix-semver-checkpoint-contract',
    'matrix-semver-checkpoint-incomplete',
    'matrix-semver-checkpoint-lock-outside-closure',
    'matrix-semver-checkpoint-missing',
    'matrix-semver-checkpoint-order',
    'matrix-semver-checkpoint-peer',
    'matrix-semver-checkpoint-project-count',
    'matrix-semver-checkpoint-record-exists',
    'matrix-semver-checkpoint-record-size',
    'matrix-semver-checkpoint-record-write',
    'matrix-semver-checkpoint-request',
    'matrix-semver-checkpoint-snapshot',

    "allowlisted-file-too-large", "allowlisted-file-unavailable", "browser-profile-command",
    "bundle-binding-mismatch", "cargo-lock-binding-missing", "cargo-lock-projection-invalid",
    "offline-lock-generation-failed", "cargo-projection-mismatch", "cargo-vendor-missing", "cargo-workspace-count-mismatch",
    "cargo-workspace-lock-set", "cargo-workspace-projection-invalid", "cargo-workspace-projection-mismatch",
    "cleanup-incomplete", "cleanup-process-remains", "cleanup-receipt-invalid", "cleanup-root-invalid",
    "control-operation-invalid", "control-protocol-size", "control-protocol-truncated",
    "control-request-invalid", "control-response-invalid", "deadline-file-invalid", "decrypt-key-unavailable",
    "decrypt-manifest-unavailable", "decrypt-order", "decrypt-rejected", "decrypt-timeout",
    "dispatch-context-invalid", "dispatch-context-unavailable", "execution-cancelled", "execution-order",
    "firewall-unavailable", "input-size", "input-unavailable", "key-invalid", "linux-root-required",
    "linux-runner-required", "mount-source-unavailable", "network-namespace-changed",
    "network-probe-stage-failed",
    "network-namespace-not-isolated", "node-tool-layout",
    "node-snapshot-base-invalid", "node-snapshot-base-owner", "node-snapshot-base-unavailable",
    "node-snapshot-content-changed", "node-snapshot-content-invalid", "node-snapshot-deadline",
    "node-snapshot-id", "node-snapshot-layout", "node-snapshot-limit", "node-snapshot-link-invalid",
    "node-snapshot-manifest-invalid", "node-snapshot-manifest-invalid:link-row-path",
    "node-snapshot-manifest-invalid:source-row-kind",
    "node-snapshot-manifest-invalid:manifest-open",
    "node-snapshot-manifest-invalid:manifest-metadata",
    "node-snapshot-manifest-invalid:manifest-race",
    "node-snapshot-manifest-invalid:manifest-missing",
    "node-snapshot-manifest-invalid:manifest-shape",
    "node-snapshot-manifest-invalid:manifest-digest",
    "node-snapshot-manifest-invalid:unlisted-site",
    "node-snapshot-missing", "node-snapshot-seal-invalid",
    "node-toolchain-executable", "node-toolchain-missing", "node-toolchain-owner",
    "node-toolchain-directory-control-access", "node-toolchain-directory-scan-access",
    "node-toolchain-file-control-access",
    "node-toolchain-version", "npm-lock-binding-missing",
    "node-toolchain-source-anchor-write-mode", "node-toolchain-source-cache-root-write-mode",
    "node-toolchain-source-root-anchor-write-mode", "node-toolchain-source-opt-anchor-write-mode",
    "node-toolchain-source-node-layout-write-mode", "node-toolchain-source-npm-layout-write-mode",
    "node-toolchain-source-npm-tree-write-mode", "node-toolchain-source-node-file-write-mode",
    "node-toolchain-source-npm-file-write-mode",
    "npm-lock-projection-invalid", "npm-projection-mismatch", "positive-control-failed",
    "positive-control-unavailable", "prepared-file-count", "prepared-input-invalid", "prepared-link-invalid",
    "prepared-member-type", "prepared-tree-size", "probe-replay", "profile-command-invalid",
    "profile-command-set", "profile-config-invalid", "profile-config-unavailable", "profile-unknown",
    "projection-binding-mismatch", "projection-invalid", "raw-record-size", "record-count",
    "report-file-changed", "report-file-invalid", "report-file-size", "rust-matrix-coverage-incomplete",
    "rust-matrix-report-exists", "rust-matrix-report-incomplete", "rust-matrix-report-invalid",
    "rust-matrix-report-unavailable", "rust-matrix-status-mismatch", "rust-tool-layout",
    "rust-toolchain-missing", "rust-toolchain-path", "state-directory-not-empty",
    "state-directory-permissions", "summary-catalog-invalid", "summary-not-ready",
    "node-runtime-version-invalid", "npm-runtime-install-failed", "npm-runtime-version-invalid",
    "semver-temporary-input-missing", "source-set-projection-mismatch",
    "summary-response-invalid", "supervisor-failed", "supervisor-operation-failed",
    "supervisor-start-failed", "supervisor-start-timeout", "supervisor-unavailable", "swap-enabled",
    "swap-state-unavailable", "clang-path-invalid", "tool-digest-mismatch", "tool-file-unavailable",
    "tool-file-type-invalid", "tool-manifest-invalid", "tool-mode-invalid", "tool-owner-invalid", "tool-path-invalid", "tool-symlink",
    "tool-path-resolve-mismatch",
    "developer-clang-mismatch", "developer-dir-trust-invalid", "developer-dir-unexpected", "tool-version-mismatch",
    "tool-version-unavailable", "total-deadline-exhausted", "total-deadline-unavailable",
    "typescript-report-incomplete",
))
WINDOWS_ACL_CHECK_OPERATIONS = (
    ("root-decode", 7), ("owner-identity", 8), ("owner-user-read", 9),
    ("owner-token-read", 10), ("trusted-sid-build", 11), ("write-mask-build", 12),
    ("parent-resolve", 13), ("parent-item", 14), ("root-item", 15),
    ("child-enumerate", 16), ("item-reparse-check", 17), ("acl-read", 18),
    ("acl-owner-read", 19), ("acl-owner-translate", 20), ("acl-owner-compare", 21),
    ("acl-rules-read", 22), ("rule-propagation-read", 23),
    ("rule-propagation-compare", 24), ("rule-type-read", 25), ("rule-type-compare", 26),
    ("rule-identity-read", 27), ("rule-writer-compare", 28), ("rule-rights-read", 29),
    ("rule-rights-compare", 30), ("owner-output", 31),
)
WINDOWS_PREPARATION_ERROR_CLASSES = frozenset((
    "EPERM", "EACCES", "ENOTFOUND", "ECONNREFUSED", "ECONNRESET", "EAI_AGAIN", "ETIMEDOUT",
    "ENOTCACHED", "E401", "E403", "E404", "E408", "E429", "EINTEGRITY", "ENOENT", "ENOTDIR",
    "EISDIR", "ENOSPC", "other",
))
WINDOWS_PREPARE_REFUSAL_CODES = frozenset((
    "windows-prepare-powershell-start-failed", "windows-prepare-powershell-timeout",
    "windows-prepare-powershell-nonzero", "windows-prepare-npm-process-start-failed",
    "windows-prepare-npm-child-timeout-3600s", "windows-prepare-npm-work-deadline",
    "windows-prepare-playwright-process-start-failed", "windows-prepare-playwright-child-timeout-1800s",
    "windows-prepare-playwright-work-deadline", "windows-prepare-playwright-cli-missing",
    "windows-prepare-toolchain-unavailable", "windows-prepare-toolchain-process-start-failed",
    "windows-prepare-toolchain-process-timeout", "windows-prepare-toolchain-version-invalid",
    "windows-prepare-profile-create-failed", "windows-prepare-profile-cleanup-failed",
    "windows-prepare-workspace-copy-failed", "windows-prepare-output-invalid",
    "windows-prepare-projection-invalid", "windows-prepare-toolchain-invalid",
    "windows-prepare-token-bypass-traverse-absent",
    "windows-prepare-internal",
)) | frozenset(
    "windows-prepare-" + phase + "-failed-" + error_class
    for phase in ("npm", "playwright") for error_class in WINDOWS_PREPARATION_ERROR_CLASSES
)
WINDOWS_CLEANUP_REASON_CLASSES = frozenset((
    "sharing-violation", "access-denied", "not-found", "other",
))
WINDOWS_SHRED_REFUSAL_CODES = frozenset((
    "windows-cleanup-powershell-start-failed", "windows-cleanup-powershell-timeout",
    "windows-cleanup-powershell-nonzero", "windows-cleanup-firewall-failed",
    "windows-cleanup-root-check-failed", "windows-cleanup-precheckout-remove-failed",
    "windows-cleanup-profile-failed", "windows-cleanup-shred-root-invalid",
    "windows-cleanup-shred-enumerate-failed", "windows-cleanup-shred-entry-inspection-failed",
    "windows-cleanup-shred-reparse-remove-failed", "windows-cleanup-shred-overwrite-failed",
    "windows-cleanup-shred-file-remove-failed", "windows-cleanup-shred-directory-remove-failed",
    "windows-cleanup-shred-root-remove-failed", "windows-cleanup-shred-internal",
    "windows-cleanup-internal",
))
CRYPTO_CONTROL_REFUSAL_CODES = frozenset((
    "crypto-target-invalid", "crypto-acl-powershell-unavailable", "crypto-acl-reparse-point",
    "crypto-acl-owner-unresolved", "crypto-acl-owner-untrusted", "crypto-acl-writer-untrusted",
    "crypto-acl-protection-failed", "crypto-acl-process-failed", "crypto-acl-exit-other",
    "crypto-acl-stderr-nonempty", "crypto-acl-stdout-non-ascii", "crypto-acl-stdout-empty",
    "crypto-acl-stdout-multiple-lines", "crypto-acl-stdout-not-sid",
    "crypto-acl-stdout-bom-or-whitespace", "crypto-platform-invalid",
    "crypto-metadata-invalid", "crypto-file-invalid", "crypto-tree-invalid",
    "crypto-manifest-invalid", "crypto-seal-write-failed", "crypto-tree-mismatch",
    "crypto-import-invalid", "crypto-key-present", "crypto-script-invalid",
    "crypto-control-invalid",
)) | frozenset("crypto-acl-exit-" + str(code) for code in range(1, 32) if code not in (3, 4, 5, 6)) | frozenset(
    "crypto-acl-check-" + operation for operation, _code in WINDOWS_ACL_CHECK_OPERATIONS
)
MACOS_SUPERVISOR_START_REFUSAL_CODES = frozenset((
    "macos-root-required", "dispatch-context-invalid", "input-unavailable", "input-size",
    "projection-invalid", "positive-control-failed", "tool-version-mismatch",
    "tool-version-unavailable", "profile-config-invalid", "prepared-input-invalid",
    "state-directory-permissions", "firewall-unavailable", "macos-supervisor-start-internal",
    "macos-supervisor-start-boundary", "macos-supervisor-start-os-error",
    "macos-supervisor-start-value-error", "macos-supervisor-start-type-error",
))
MACOS_OPERATION_RAW_REFUSALS = {
    "prepare": frozenset((
        "macos-root-required", "dispatch-context-invalid", "input-unavailable", "state-directory-permissions",
        "profile-unknown", "deadline-file-invalid", "total-deadline-exhausted", "projection-invalid",
        "prepare-run-root-invalid", "prepared-output-invalid", "prepared-output-path-invalid",
        "prepared-output-exists", "preparation-path-invalid", "profile-config-invalid",
        "process-start-failed", "process-wait-failed", "log-too-large", "playwright-failed",
        "tool-runtime-dependencies-invalid",
        "process-cleanup-incomplete", "prepared-file-count",
        "prepared-link-invalid", "prepared-tree-size", "prepared-member-type", "prepared-input-invalid",
        "cleanup-incomplete",
    )),
    "probe": frozenset((
        "macos-root-required", "input-unavailable", "state-directory-permissions", "dispatch-context-invalid",
        "probe-replay", "firewall-unavailable", "profile-config-invalid", "positive-control-failed",
        "total-deadline-exhausted", "raw-record-size", "supervisor-operation-failed",
        "cleanup-process-inventory", "cleanup-process-termination", "cleanup-process-incomplete",
    )),
    "execute": frozenset((
        "macos-root-required", "input-unavailable", "state-directory-permissions", "dispatch-context-invalid",
        "execution-order", "profile-unknown", "profile-config-invalid", "firewall-unavailable",
        "tool-version-mismatch", "total-deadline-exhausted", "raw-record-size", "supervisor-operation-failed",
        "cleanup-process-inventory", "cleanup-process-termination", "cleanup-process-incomplete",
        "process-cleanup-incomplete", "tool-symlink", "tool-file-type-invalid", "tool-owner-invalid",
        "tool-mode-invalid", "tool-path-resolve-mismatch", "tool-file-unavailable", "report-file-invalid",
        "report-file-incomplete", "report-file-unavailable", "report-file-exists", "report-file-changed",
        "record-count", "summary-record-invalid", "summary-response-invalid", "summary-not-ready",
        "prepared-member-type", "prepared-link-invalid", "cleanup-incomplete",
    )),
    "cleanup": frozenset((
        "macos-root-required", "input-unavailable", "state-directory-permissions", "cleanup-root-invalid",
        "cleanup-intent-invalid", "cleanup-incomplete", "cleanup-process-inventory",
        "cleanup-process-termination", "cleanup-process-incomplete", "firewall-unavailable",
    )),
    "root-pf-cleanup": frozenset((
        "macos-root-required", "input-unavailable", "state-directory-permissions", "dispatch-context-invalid",
        "firewall-unavailable",
    )),
}
MACOS_NPM_PREPARATION_ERROR_CLASSES = frozenset((
    "EPERM", "EACCES", "ENOTFOUND", "ECONNREFUSED", "ECONNRESET", "EAI_AGAIN", "ETIMEDOUT",
    "ENOTCACHED", "E401", "E403", "E404", "E408", "E429", "EINTEGRITY", "ENOENT", "ENOTDIR",
    "EISDIR", "ENOSPC", "sandbox-deny", "node-start-failed", "killed-by-signal-4",
    "killed-by-signal-5", "killed-by-signal-6", "killed-by-signal-9", "killed-by-signal-10",
    "killed-by-signal-11", "killed-by-signal-15", "killed-by-signal-24", "killed-by-signal-25",
    "killed-by-signal-other", "other",
))
MACOS_OPERATION_RAW_REFUSALS["prepare"] |= frozenset(
    "npm-failed-" + error_class for error_class in MACOS_NPM_PREPARATION_ERROR_CLASSES
)
_MACOS_OPERATION_ALIASES = {
    "macos-root-required": "root-required", "prepare-run-root-invalid": "run-root-invalid",
    "prepared-output-invalid": "output-invalid", "prepared-output-path-invalid": "output-path-invalid",
    "prepared-output-exists": "output-exists", "prepared-file-count": "file-count",
    "prepared-link-invalid": "link-invalid", "prepared-tree-size": "tree-size",
    "prepared-member-type": "member-type", "prepared-input-invalid": "input-invalid",
    "preparation-path-invalid": "path-invalid", "cleanup-root-invalid": "root-invalid",
    "cleanup-intent-invalid": "intent-invalid", "cleanup-incomplete": "incomplete",
    "cleanup-process-inventory": "process-inventory", "cleanup-process-termination": "process-termination",
    "cleanup-process-incomplete": "process-incomplete",
}
_MACOS_OPERATION_PREFIXES = {
    "prepare": "macos-prepare", "probe": "macos-probe", "execute": "macos-execute",
    "cleanup": "macos-cleanup", "root-pf-cleanup": "macos-root-pf-cleanup",
}
MACOS_OPERATION_REFUSAL_CODE_MAPS = {
    operation: {
        raw_code: prefix + "-" + _MACOS_OPERATION_ALIASES.get(raw_code, raw_code)
        for raw_code in raw_codes
    }
    for operation, raw_codes in MACOS_OPERATION_RAW_REFUSALS.items()
    if (prefix := _MACOS_OPERATION_PREFIXES[operation])
}
_MACOS_OPERATION_EXCEPTION_CODES = {
    operation: frozenset((
        prefix + "-boundary", prefix + "-internal", prefix + "-os-error",
        prefix + "-value-error", prefix + "-type-error",
    ))
    for operation, prefix in _MACOS_OPERATION_PREFIXES.items()
}
MACOS_PREPARE_REFUSAL_CODES = frozenset(MACOS_OPERATION_REFUSAL_CODE_MAPS["prepare"].values()) | _MACOS_OPERATION_EXCEPTION_CODES["prepare"]
MACOS_PROBE_REFUSAL_CODES = frozenset(MACOS_OPERATION_REFUSAL_CODE_MAPS["probe"].values()) | _MACOS_OPERATION_EXCEPTION_CODES["probe"]
MACOS_EXECUTE_REFUSAL_CODES = frozenset(MACOS_OPERATION_REFUSAL_CODE_MAPS["execute"].values()) | _MACOS_OPERATION_EXCEPTION_CODES["execute"]
MACOS_CLEANUP_REFUSAL_CODES = frozenset(MACOS_OPERATION_REFUSAL_CODE_MAPS["cleanup"].values()) | _MACOS_OPERATION_EXCEPTION_CODES["cleanup"]
MACOS_ROOT_PF_CLEANUP_REFUSAL_CODES = frozenset(MACOS_OPERATION_REFUSAL_CODE_MAPS["root-pf-cleanup"].values()) | _MACOS_OPERATION_EXCEPTION_CODES["root-pf-cleanup"]
MACOS_OPERATION_REFUSAL_CODES = frozenset().union(
    MACOS_PREPARE_REFUSAL_CODES, MACOS_PROBE_REFUSAL_CODES, MACOS_EXECUTE_REFUSAL_CODES,
    MACOS_CLEANUP_REFUSAL_CODES, MACOS_ROOT_PF_CLEANUP_REFUSAL_CODES,
)
MACOS_PREFLIGHT_REFUSAL_CODES = frozenset((
    "macos-preflight-internal", "macos-root-identity-internal", "macos-preflight-host-identity",
    "macos-preflight-node-tools", "macos-preflight-command-line-tools", "macos-preflight-platform-policy",
    "macos-preflight-temp-permissions", "macos-preflight-root-helper", "macos-preflight-state-record",
    "macos-run-root-missing", "macos-state-directory-create", "macos-python3-unavailable",
    "macos-user-list", "macos-user-name-conflict", "macos-user-id-exhausted", "macos-user-create",
    "macos-user-attribute-set", "macos-worker-home-create", "macos-worker-home-permissions",
    "macos-user-verify", "macos-cleanup-intent-write", "macos-identity-record-write",
    "macos-runner-required", "profile-unknown", "dispatch-context-invalid", "state-directory-permissions",
    "node-toolchain-missing", "node-toolchain-version", "npm-toolchain-version",
    "node-runtime-version-invalid", "npm-runtime-install-failed", "npm-runtime-version-invalid",
    "tool-file-type-invalid", "tool-owner-invalid", "tool-mode-invalid", "tool-symlink",
    "tool-path-resolve-mismatch", "tool-file-unavailable",
    "clt-missing", "developer-dir-unexpected", "developer-dir-trust-invalid", "clang-path-invalid",
    "tool-digest-mismatch", "developer-clang-mismatch", "tool-version-unavailable",
    "supervisor-operation-failed", "raw-record-size",
))
DECRYPT_REFUSAL_CODES = frozenset((
    "archive-invalid", "auth-tag", "binding-mismatch", "crypto-unavailable",
    "child-import-failed", "child-no-output", "child-output-invalid", "child-panic",
    "child-script-unreadable", "child-spawn-failed", "decrypt-failed", "decrypt-timeout", "expired",
    "invalid-envelope", "key-format", "request-invalid", "truncated",
))
_DECRYPT_CHILD_SIGNAL_NAMES = (
    "SIGKILL", "SIGSEGV", "SIGABRT", "SIGSYS", "SIGXCPU", "SIGXFSZ", "SIGBUS", "SIGILL",
)
DECRYPT_CHILD_SIGNAL_CODES = {
    value: "child-signal-" + name for name in _DECRYPT_CHILD_SIGNAL_NAMES
    if (value := getattr(signal, name, None)) is not None
}
DECRYPT_CHILD_EXIT_CODES = frozenset((1, 2, 120, 126, 127))
DECRYPT_REFUSAL_CODES |= frozenset(DECRYPT_CHILD_SIGNAL_CODES.values())
DECRYPT_REFUSAL_CODES |= frozenset("child-exit-" + str(code) for code in DECRYPT_CHILD_EXIT_CODES)
DECRYPT_REFUSAL_CODES |= frozenset(("child-signal-other", "child-exit-other"))
DECRYPT_CHILD_ERROR_CLASSES = frozenset((
    "ModuleNotFoundError", "ImportError", "PermissionError", "FileNotFoundError", "OSError",
    "MemoryError", "PanicException", "SystemError", "UnicodeDecodeError",
))
DECRYPT_CHILD_ERROR_CODES = DECRYPT_CHILD_ERROR_CLASSES | frozenset(("other",))
NETWORK_PROBE_REFUSAL_CODES = frozenset(
    "network-probe-refusal:" + code for code in network_probe.REFUSAL_CODES
)
NETWORK_PROBE_DIAGNOSTIC_CODES = NETWORK_PROBE_REFUSAL_CODES | frozenset((
    "network-probe-command-failed", "network-probe-output-invalid", "network-probe-stage-failed",
))
REFUSAL_CODES |= NETWORK_PROBE_DIAGNOSTIC_CODES
REFUSAL_CODES |= frozenset("cleanup-incomplete:" + reason for reason in CLEANUP_SUBREASONS)
STARTUP_REFUSAL_CODES = frozenset((
    "deadline-file-invalid", "dispatch-context-invalid", "dispatch-context-unavailable",
    "firewall-unavailable", "input-size", "input-unavailable", "linux-root-required",
    "linux-runner-required", "mount-source-unavailable", "network-probe-stage-failed", "node-tool-layout",
    "node-snapshot-base-invalid", "node-snapshot-base-owner", "node-snapshot-base-unavailable",
    "node-snapshot-content-changed", "node-snapshot-content-invalid", "node-snapshot-deadline",
    "node-snapshot-id", "node-snapshot-layout", "node-snapshot-limit", "node-snapshot-link-invalid",
    "node-snapshot-manifest-invalid", "node-snapshot-manifest-invalid:link-row-path",
    "node-snapshot-manifest-invalid:source-row-kind",
    "node-snapshot-manifest-invalid:manifest-open",
    "node-snapshot-manifest-invalid:manifest-metadata",
    "node-snapshot-manifest-invalid:manifest-race",
    "node-snapshot-manifest-invalid:manifest-missing",
    "node-snapshot-manifest-invalid:manifest-shape",
    "node-snapshot-manifest-invalid:manifest-digest",
    "node-snapshot-manifest-invalid:unlisted-site",
    "node-snapshot-missing", "node-snapshot-seal-invalid",
    "node-toolchain-executable",
    "node-toolchain-directory-control-access", "node-toolchain-directory-scan-access",
    "node-toolchain-file-control-access",
    "node-toolchain-missing", "node-toolchain-owner",
    "node-toolchain-source-anchor-write-mode", "node-toolchain-source-cache-root-write-mode",
    "node-toolchain-source-root-anchor-write-mode", "node-toolchain-source-opt-anchor-write-mode",
    "node-toolchain-source-node-layout-write-mode", "node-toolchain-source-npm-layout-write-mode",
    "node-toolchain-source-npm-tree-write-mode", "node-toolchain-source-node-file-write-mode",
    "node-toolchain-source-npm-file-write-mode",
    "node-toolchain-version",
    "positive-control-failed", "positive-control-unavailable",
    "profile-config-invalid", "profile-config-unavailable", "profile-unknown",
    "projection-binding-mismatch", "projection-invalid", "report-file-changed", "report-file-invalid",
    "report-file-size", "rust-tool-layout", "rust-toolchain-missing", "rust-toolchain-path",
    "source-free-diagnostics-context", "source-free-diagnostics-path",
    "state-directory-not-empty", "state-directory-permissions", "supervisor-failed",
    "supervisor-operation-failed", "supervisor-start-failed", "supervisor-start-timeout",
    "swap-enabled", "swap-state-unavailable", "tool-manifest-invalid", "tool-path-invalid",
    "tool-version-mismatch", "tool-version-unavailable", "total-deadline-exhausted",
    "total-deadline-unavailable",
))
STARTUP_DIAGNOSTIC_PHASES = frozenset((
    "construct", "deadline", "projection", "linux", "swap", "priv-mount", "firewall",
    "root-mount", "probe-stage", "bundle-copy", "tools", "profile", "versions", "socket", "listen",
    "ready", "serve", "parent",
))
_STARTUP_EXCEPTION_LABELS = {
    AssertionError: "assertion", AttributeError: "attribute", FileExistsError: "file-exists",
    FileNotFoundError: "file-missing", IsADirectoryError: "is-directory", KeyError: "key",
    NameError: "name", NotADirectoryError: "not-directory", OSError: "os",
    PermissionError: "permission", RuntimeError: "runtime", TimeoutError: "timeout",
    TypeError: "type", ValueError: "value", UnicodeError: "unicode",
    UnicodeDecodeError: "unicode-decode", json.JSONDecodeError: "json-decode",
    subprocess.SubprocessError: "subprocess", subprocess.TimeoutExpired: "proc-timeout",
    subprocess.CalledProcessError: "proc-exit", ImportError: "import", ModuleNotFoundError: "module-missing",
    MemoryError: "memory", OverflowError: "overflow", IndexError: "index",
}
STARTUP_DIAGNOSTIC_CODES = frozenset(
    "child-" + phase + "-" + label
    for phase in STARTUP_DIAGNOSTIC_PHASES
    for label in {*_STARTUP_EXCEPTION_LABELS.values(), "unclassified"}
)


def _startup_exception_code(phase, error):
    trusted_phase = phase if phase in STARTUP_DIAGNOSTIC_PHASES else "serve"
    label = _STARTUP_EXCEPTION_LABELS.get(type(error), "unclassified")
    return "child-" + trusted_phase + "-" + label
