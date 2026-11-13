"""Platform-neutral refusal vocabularies shared by audits and the supervisor."""

import json
import signal
import subprocess

import network_probe


CLEANUP_SUBREASONS = frozenset((
    "umount-busy", "umount-missing", "tree-remove", "process-alive", "cgroup-nonempty",
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
    "crypto-dependency-install-failed",
    "crypto-dependency-verification-failed",
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
