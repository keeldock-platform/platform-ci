import base64
from contextlib import contextmanager
from dataclasses import dataclass
import datetime
import hashlib
import importlib.util
import json
import os
import posixpath
import re
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import MappingProxyType
import unicodedata
from pathlib import Path
import weakref


try:
    _CONTROL_DIRECTORY = Path(__file__).resolve(strict=True).parent
except BaseException:
    _CONTROL_DIRECTORY = None


def _load_control_sibling(module_name):
    if (
        _CONTROL_DIRECTORY is None
        or type(module_name) is not str
        or module_name not in {"macos_capability", "macos_reviewed_build"}
    ):
        raise ImportError("control module unavailable")
    candidate = _CONTROL_DIRECTORY / (module_name + ".py")
    try:
        info = candidate.lstat()
        path = candidate.resolve(strict=True)
        if path.parent != _CONTROL_DIRECTORY or not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise ImportError("control module unavailable")
    except BaseException:
        raise ImportError("control module unavailable") from None
    loaded = sys.modules.get(module_name)
    if loaded is not None:
        loaded_path = getattr(loaded, "__file__", None)
        if type(loaded_path) is str:
            try:
                if Path(loaded_path).resolve(strict=True) == path:
                    return loaded
            except OSError:
                pass
    spec = importlib.util.spec_from_file_location(module_name, str(path))
    if spec is None or spec.loader is None:
        raise ImportError("control module unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise ImportError("control module unavailable") from None
    return module


try:
    capability = _load_control_sibling("macos_capability")
    reviewed_build = _load_control_sibling("macos_reviewed_build")
except BaseException:
    capability = None
    reviewed_build = None


SCHEMA_VERSION = 1
SOURCE_SHA_PATTERN = re.compile(r"[a-f0-9]{40}\Z")
REPOSITORY_ID_PATTERN = re.compile(r"[1-9][0-9]{0,18}\Z")
SOURCE_TOKEN_PATTERN = re.compile(r"[!-~]{1,4096}\Z")
RUN_ID_PATTERN = re.compile(r"[1-9][0-9]{0,18}\Z")
RUN_ATTEMPT_PATTERN = re.compile(r"[1-9][0-9]{0,18}\Z")
OWNER_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
FINGERPRINT_PATTERN = re.compile(r"SHA256:[A-Za-z0-9+/]{43}\Z")
BRANCHES = frozenset(("main", "develop", "uat"))
CORE_RUST_BOOTSTRAP_BASE_BRANCH = "plan/core-contract-batch4"
CORE_RUST_BOOTSTRAP_BASE_SHA = "8296d2977a204edd2eafc06ed9e3280bf5480cbf"
FEEDBACK_PROFILE_CONCERNS = frozenset((
    "core-node-lock-return",
    "core-rust-format-return",
    "core-build-diagnostic-return",
    "core-rust-lock-return",
))
CORE_CONTRACT_CONCERNS = frozenset(("core-contract",)) | FEEDBACK_PROFILE_CONCERNS
SOURCE_DESCENDANT_CONCERNS = frozenset(("rules-bootstrap",)) | CORE_CONTRACT_CONCERNS
CONCERNS = frozenset(("core-bootstrap", "rules-bootstrap")) | CORE_CONTRACT_CONCERNS
REASONS = frozenset((
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
    "cleanup_incomplete",
    "internal_error",
))
STAGES = frozenset((
    "input", "context", "configuration", "source_scope", "fetch", "revoke",
    "history", "signature", "revocation", "bootstrap", "cleanup",
))
FETCH_DIAGNOSTIC_OPERATIONS = frozenset((
    "git_init", "remote_add", "base_fetch", "base_ref", "candidate_fetch",
    "source_ref", "shallow_check", "remote_remove", "source_snapshot",
))
FETCH_DIAGNOSTIC_CLASSES = frozenset((
    "exit_nonzero", "stderr_present", "process_failure", "unexpected_exception",
))
CORE_BOOTSTRAP_CHECKS = frozenset((
    "tree_entries",
    "required_files",
    "path_mode",
    "base_policy",
    "rules_manifest",
    "rules_inventory",
    "rules_hash",
    "workspace_decode",
    "workspace_members",
    "cargo_lock_decode",
    "cargo_lock_shape",
    "toolchain",
    "package_decode",
    "package_build",
    "checkout",
    "lease_paths",
    "lease_acl",
    "lease_access",
    "lease_census",
))
SOURCE_REPOSITORY_ID_ENV = "SOURCE_REPOSITORY_ID"
SOURCE_REPOSITORY_OWNER_ENV = "SOURCE_REPOSITORY_OWNER"
SOURCE_REPOSITORY_NAME_ENV = "SOURCE_REPOSITORY_NAME"
SOURCE_CANDIDATE_REF_ENV = "SOURCE_CANDIDATE_REF"
RULES_BOOTSTRAP_SOURCE_GATE_ENV = "RULES_BOOTSTRAP_ALLOWED_SHA"
RULES_BOOTSTRAP_CONTROL_GATE_ENV = "RULES_BOOTSTRAP_ALLOWED_CONTROL_SHA"
CORE_CONTRACT_SOURCE_GATE_ENV = "CORE_CONTRACT_ALLOWED_SHA"
CORE_CONTRACT_CONTROL_GATE_ENV = "CORE_CONTRACT_ALLOWED_CONTROL_SHA"
REVOCATION_INVENTORY = "ci/revoked-signer-fingerprints"
SIGNER_PATH_PARTS = ("docs", "commit-signers")
RULES_DIRECTORY = chr(46) + "claude"
RULES_LOCK_PATH = RULES_DIRECTORY + "/shared.lock"
CORE_CONTRACT_CRATE_ROOTS = (
    ("crates", "host", "api"),
    ("crates", "host", "mock"),
    ("crates", "host", "conformance"),
    ("crates", "kernel", "i18n"),
)
CORE_CONTRACT_CRATE_NAMES = {
    ("crates", "host", "api"): "keeldock-host-api",
    ("crates", "host", "mock"): "keeldock-host-mock",
    ("crates", "host", "conformance"): "keeldock-host-conformance",
    ("crates", "kernel", "i18n"): "keeldock-kernel-i18n",
}
CORE_CONTRACT_ROOT_FILES = frozenset((
    "Cargo.toml", "Cargo.lock", "rust-toolchain.toml", "rustfmt.toml", "clippy.toml",
))
CORE_CONTRACT_PACKAGE_LOCK_PATH = "package-lock.json"
CORE_CONTRACT_PACKAGE_LOCK_TREE = "core_build_diagnostic_return_with_package_lock"
MAX_FEEDBACK_LOCK_BYTES = 4 * 1024 * 1024 - 64 * 1024
CORE_CONTRACT_PACKAGE_FILES = frozenset(("Cargo.toml", "README.md", "CONTRACT.md", "CHANGELOG.md"))
CORE_CONTRACT_FEEDBACK_FILES = frozenset((
    ".node-version",
    ".npmrc",
    "package.json",
    "tsconfig.base.json",
    "packages/host-api/CHANGELOG.md",
    "packages/host-api/CONTRACT.md",
    "packages/host-api/README.md",
    "packages/host-api/package.json",
    "packages/host-api/tsconfig.json",
    "packages/host-api/src/budget.ts",
    "packages/host-api/src/effects.ts",
    "packages/host-api/src/entitlements.ts",
    "packages/host-api/src/errors.ts",
    "packages/host-api/src/ids.ts",
    "packages/host-api/src/index.ts",
    "packages/host-api/src/manifest.ts",
    "packages/host-api/src/metadata.ts",
    "packages/host-api/src/module.ts",
    "packages/host-api/src/plugin.ts",
    "packages/host-api/src/result.ts",
    "packages/host-api/src/streams.ts",
    "packages/host-api/src/version.ts",
    "packages/host-api/tests/budget-streams.test.ts",
    "packages/host-api/tests/entitlements-errors.test.ts",
    "packages/host-api/tests/ids-version.test.ts",
    "packages/host-api/tests/manifest-metadata.test.ts",
))
CORE_CONTRACT_FOUNDATION_FILES = frozenset((
    "docs/adr/0002-parser-corpus-workspace.md",
    "docs/adr/0003-npm-contract-workspace.md",
    "fuzz/ARCHITECTURE.md",
    "fuzz/Cargo.lock",
    "fuzz/Cargo.toml",
    "fuzz/README.md",
    "fuzz/fuzz_targets/identifiers.rs",
    "fuzz/fuzz_targets/tool_error_codes.rs",
    "fuzz/fuzz_targets/versions.rs",
    "fuzz/src/main.rs",
))
CORE_CONTRACT_FUZZ_CORPUS_TARGETS = frozenset((
    "identifiers", "tool_error_codes", "versions",
))
CORE_CONTRACT_KERNEL_FEEDBACK_FILES = frozenset((
    "crates/host/api/tests/fixtures/i18n-regression-v1.jsonl",
    "crates/host/api/tests/fixtures/i18n-v1.jsonl",
    "crates/kernel/i18n/src/cldr46_cardinal_rules.md",
    "packages/kernel-i18n/CHANGELOG.md",
    "packages/kernel-i18n/CONTRACT.md",
    "packages/kernel-i18n/README.md",
    "packages/kernel-i18n/data/cldr46_cardinal_rules.md",
    "packages/kernel-i18n/package.json",
    "packages/kernel-i18n/tests/support.ts",
    "packages/kernel-i18n/tsconfig.json",
))
CORE_CONTRACT_WORKSPACE_MEMBERS_PATTERN = re.compile(r"(?m)^members\s*=\s*\[([^\]]*)\]\s*$")
CORE_CONTRACT_WORKSPACE_MEMBER_PATTERN = re.compile(r'\s*"([A-Za-z0-9/_-]{1,128})"\s*(?:,|\Z)')
CORE_CONTRACT_PACKAGE_LOCK_CONCERNS = frozenset((
    "core-build-diagnostic-return", "core-rust-format-return",
))
CORE_CONTRACT_MANIFEST_SECTIONS = frozenset(("package", "dependencies", "dev-dependencies", "lints"))
CORE_CONTRACT_MANIFEST_INHERITED_KEYS = frozenset((
    "version.workspace", "edition.workspace", "rust-version.workspace", "publish.workspace",
))
CORE_CONTRACT_MANIFEST_DEPENDENCIES = frozenset(("keeldock" "-host-api", "keeldock" "-host-mock"))
CORE_CONTRACT_MANIFEST_SECTION_PATTERN = re.compile(r"\[([a-z-]{1,32})\]\Z")
CORE_CONTRACT_MANIFEST_ASSIGNMENT_PATTERN = re.compile(r"([A-Za-z0-9_.-]{1,64})\s*=\s*(.{1,512})\Z")
CORE_CONTRACT_MANIFEST_NAME_PATTERN = re.compile(r'"[a-z][a-z0-9]*(?:-[a-z0-9]+)*"\Z')
CORE_CONTRACT_MANIFEST_TEXT_PATTERN = re.compile(r'"[A-Za-z0-9 ,.:()-]{1,256}"\Z')
CORE_CONTRACT_MANIFEST_WORKSPACE_VALUE_PATTERN = re.compile(r"\{\s*workspace\s*=\s*true\s*\}\Z")
CORE_CONTRACT_MANIFEST_EXTERNAL_DEPENDENCIES = {
    "serde": re.compile(
        r'\{\s*version\s*=\s*"=1\.0\.229"\s*,\s*default-features\s*=\s*false\s*,\s*'
        r'features\s*=\s*\[\s*"derive"\s*,\s*"std"\s*\]\s*\}\Z'
    ),
    "serde_json": re.compile(
        r'\{\s*version\s*=\s*"=1\.0\.154"\s*,\s*default-features\s*=\s*false\s*,\s*'
        r'features\s*=\s*\[\s*"std"\s*\]\s*\}\Z'
    ),
    "schemars": re.compile(
        r'\{\s*version\s*=\s*"=1\.2\.3"\s*,\s*default-features\s*=\s*false\s*,\s*'
        r'features\s*=\s*\[\s*"derive"\s*,\s*"std"\s*\]\s*\}\Z'
    ),
}
CORE_CONTRACT_ROOT_PATH_DEPENDENCIES = {
    "keeldock" "-host-api": "crates/host/api",
    "keeldock" "-host-mock": "crates/host/mock",
}
CORE_CONTRACT_ROOT_ASSIGNMENT_PATTERN = re.compile(r"([a-z][a-z0-9_-]{0,63}) = (.{1,512})\Z")
CORE_CONTRACT_ROOT_ARRAY_ITEM = r'"[A-Za-z0-9/_-]{1,128}"'
CORE_CONTRACT_ROOT_ARRAY_PATTERN = re.compile(
    r"\[(?:\s*" + CORE_CONTRACT_ROOT_ARRAY_ITEM + r"(?:\s*,\s*" + CORE_CONTRACT_ROOT_ARRAY_ITEM
    + r")*\s*,?)?\s*\]\Z"
)
CORE_CONTRACT_ROOT_ARRAY_LINE_PATTERN = re.compile(CORE_CONTRACT_ROOT_ARRAY_ITEM + r",?\Z")
CORE_CONTRACT_ROOT_RESOLVER_PATTERN = re.compile(r'"[0-9]{1,2}"\Z')
CORE_CONTRACT_ROOT_VERSION_PATTERN = re.compile(r'"[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"\Z')
CORE_CONTRACT_ROOT_EDITION_PATTERN = re.compile(r'"[0-9]{4}"\Z')
CORE_CONTRACT_ROOT_BOOLEAN_PATTERN = re.compile(r"(?:true|false)\Z")
CORE_CONTRACT_ROOT_LEVEL_PATTERN = re.compile(r'"(?:forbid|deny|warn)"\Z')
CORE_CONTRACT_ROOT_LEVEL_TABLE_PATTERN = re.compile(
    r'\{\s*level\s*=\s*"(?:forbid|deny|warn)"\s*,\s*priority\s*=\s*-?[0-9]{1,3}\s*\}\Z'
)
CORE_CONTRACT_ROOT_KEYS = {
    "[workspace]": {
        "resolver": CORE_CONTRACT_ROOT_RESOLVER_PATTERN,
        "members": CORE_CONTRACT_ROOT_ARRAY_PATTERN,
        "exclude": CORE_CONTRACT_ROOT_ARRAY_PATTERN,
    },
    "[workspace.package]": {
        "version": CORE_CONTRACT_ROOT_VERSION_PATTERN,
        "edition": CORE_CONTRACT_ROOT_EDITION_PATTERN,
        "rust-version": CORE_CONTRACT_ROOT_VERSION_PATTERN,
        "publish": CORE_CONTRACT_ROOT_BOOLEAN_PATTERN,
    },
    "[workspace.dependencies]": {
        name: re.compile(r"\{\s*path\s*=\s*" + '"' + re.escape(path) + '"' + r"\s*\}\Z")
        for name, path in CORE_CONTRACT_ROOT_PATH_DEPENDENCIES.items()
    },
    "[workspace.lints.rust]": {
        "unsafe_code": CORE_CONTRACT_ROOT_LEVEL_PATTERN,
        "unsafe_op_in_unsafe_fn": CORE_CONTRACT_ROOT_LEVEL_PATTERN,
        "missing_docs": CORE_CONTRACT_ROOT_LEVEL_PATTERN,
        "unreachable_pub": CORE_CONTRACT_ROOT_LEVEL_PATTERN,
        "warnings": CORE_CONTRACT_ROOT_LEVEL_PATTERN,
    },
    "[workspace.lints.clippy]": {
        "all": CORE_CONTRACT_ROOT_LEVEL_TABLE_PATTERN,
        "unwrap_used": CORE_CONTRACT_ROOT_LEVEL_PATTERN,
        "expect_used": CORE_CONTRACT_ROOT_LEVEL_PATTERN,
        "panic": CORE_CONTRACT_ROOT_LEVEL_PATTERN,
        "indexing_slicing": CORE_CONTRACT_ROOT_LEVEL_PATTERN,
        "cast_possible_truncation": CORE_CONTRACT_ROOT_LEVEL_PATTERN,
        "undocumented_unsafe_blocks": CORE_CONTRACT_ROOT_LEVEL_PATTERN,
    },
}
CORE_CONTRACT_SNAKE_NAME_PATTERN = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)*\Z")
CORE_CONTRACT_TS_SOURCE_PATH_PATTERN = re.compile(
    r"packages/(?:host-api|kernel-i18n)/src/([a-z][a-z0-9]*(?:-[a-z0-9]+)*)\.ts\Z"
)
CORE_CONTRACT_TS_TEST_PATH_PATTERN = re.compile(
    r"packages/(?:host-api|kernel-i18n)/tests/([a-z][a-z0-9]*(?:-[a-z0-9]+)*)\.test\.ts\Z"
)
CORE_CONTRACT_ADR_PATH_PATTERN = re.compile(
    r"docs/adr/([0-9]{4})-([a-z][a-z0-9]*(?:-[a-z0-9]+)*)\.md\Z"
)
CORE_CONTRACT_FUZZ_TARGET_PATH_PATTERN = re.compile(
    r"fuzz/fuzz_targets/([a-z][a-z0-9]*(?:_[a-z0-9]+)*)\.rs\Z"
)
CORE_CONTRACT_FUZZ_CORPUS_PATH = re.compile(
    r"fuzz/corpus/([a-z][a-z0-9]*(?:_[a-z0-9]+)*)/[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z"
)
CORE_CONTRACT_TREE_BY_CONCERN = {
    "core-contract": "core_contract",
    "core-node-lock-return": "core_node_lock_return",
    "core-rust-format-return": "core_rust_format_return",
    "core-build-diagnostic-return": "core_build_diagnostic_return",
    "core-rust-lock-return": "core_rust_lock_return",
}
CORE_CONTRACT_RULES_TAG_PATTERN = re.compile(r"tag v(?:2\.0\.0|3\.0\.0)\Z")
CORE_CONTRACT_RUST_POLICY_FILES = frozenset((
    "deny.toml", "dependency-policy.toml", "supply-chain/audits.toml",
    "supply-chain/config.toml", "supply-chain/imports.lock",
))
CORE_CONTRACT_RUST_POLICY_OBJECTS = {
    "deny.toml": "4d42231927ec45b0fec267d689956dd3a8416076",
    "dependency-policy.toml": "4dac137e5233421a3242455bf1d384a3cc69bdb4",
    "supply-chain/audits.toml": "a19ea474cabfb9c36200e799072c2822eb391f1a",
    "supply-chain/config.toml": "b1c3c53dde85ac5a423e4079d0551c56ac73d64a",
    "supply-chain/imports.lock": "97800a9d48c227190f29d740c4c84fec5395cfcd",
}
CORE_CONTRACT_RUST_BOOTSTRAP_LOCK_OBJECT = "b589a4bd0c7b1d6d339658d7bbc57dd3ca89e53b"
CORE_CONTRACT_RULES_V2_LOCK_OBJECT = "685ad6816eac9355b4578105fcf4b7c7b9c69304"
CORE_CONTRACT_RULES_V3_LOCK_OBJECT = "567fdb4063a720109005e63949cdc14e21f4e82c"
CORE_CONTRACT_RULES_V3_CHANGED_PATHS = frozenset((
    "AGENTS.md", RULES_LOCK_PATH,
    RULES_DIRECTORY + "/rules/shared/agents-and-orchestration.md",
    RULES_DIRECTORY + "/rules/shared/ci-and-admission.md",
    RULES_DIRECTORY + "/rules/shared/rust.md",
    RULES_DIRECTORY + "/rules/shared/source-execution-confinement.md",
    RULES_DIRECTORY + "/rules/shared/supply-chain.md",
))
RUNTIME_WORKSPACE_DIRECTORY = "runtime"
RUNTIME_ROOT_MANIFEST_PATH = RUNTIME_WORKSPACE_DIRECTORY + "/Cargo.toml"
RUNTIME_ROOT_LOCK_PATH = RUNTIME_WORKSPACE_DIRECTORY + "/Cargo.lock"
RUNTIME_ROOT_FILES = frozenset((RUNTIME_ROOT_MANIFEST_PATH, RUNTIME_ROOT_LOCK_PATH))
RUNTIME_PART_PATTERN = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z")
RUNTIME_CRATES_DIRECTORY = (RUNTIME_WORKSPACE_DIRECTORY, "crates")
RUNTIME_FIXTURE_DIRECTORY = RUNTIME_CRATES_DIRECTORY + ("test-fixtures",)
RUNTIME_CRATE_ROOTS = tuple(
    RUNTIME_FIXTURE_DIRECTORY + (name,)
    for name in (
        "host-router", "fixture-data", "tool-a", "tool-b",
        "tool-bad-no-handler", "tool-bad-no-manifest",
    )
)
RUNTIME_CONFIG_FILES = ("rust-toolchain.toml", "rustfmt.toml", "clippy.toml")
MAX_RUNTIME_MEMBERS = 32
RUNTIME_MEMBERS_PATTERN = re.compile(r"(?m)^members\s*=\s*\[([^\]]*)\]\s*$")
RUNTIME_MEMBER_PATTERN = re.compile(r'\s*"([A-Za-z0-9][A-Za-z0-9/_-]{0,127})"\s*(?:,|\Z)')
RUNTIME_SECTION_PATTERN = re.compile(r"\[([a-z-]{1,32})\]\Z")
RUNTIME_ASSIGNMENT_PATTERN = re.compile(r"([A-Za-z0-9_.-]{1,64})\s*=\s*(.{1,512})\Z")
RUNTIME_DEPENDENCY_NAME_PATTERN = re.compile(r"[a-z][a-z0-9_]*(?:-[a-z0-9_]+)*\Z")
RUNTIME_PACKAGE_NAME_PATTERN = re.compile(r'"([a-z][a-z0-9]*(?:-[a-z0-9]+)*)"\Z')
RUNTIME_TEXT_PATTERN = re.compile(r'"[A-Za-z0-9 ,.:()-]{1,256}"\Z')
RUNTIME_LINT_KEY_PATTERN = re.compile(r"[a-z_][a-z0-9_:]{0,63}\Z")
RUNTIME_LINT_VALUE_PATTERN = re.compile(
    r'"(?:allow|warn|deny|forbid)"\Z'
    r'|\{\s*level\s*=\s*"(?:allow|warn|deny|forbid)"\s*,\s*priority\s*=\s*-?[0-9]{1,3}\s*\}\Z'
)
RUNTIME_ROOT_PATH_PATTERN = re.compile(r'\{\s*path\s*=\s*"([A-Za-z0-9][A-Za-z0-9/_-]{0,127})"\s*\}\Z')
RUNTIME_ROOT_SECTIONS = frozenset((
    "[workspace]", "[workspace.package]", "[workspace.dependencies]",
    "[workspace.lints.rust]", "[workspace.lints.clippy]",
))
RUNTIME_ROOT_PACKAGE_VALUES = {
    "version": re.compile(r'"[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}"\Z'),
    "edition": re.compile(r'"2024"\Z'),
    "rust-version": re.compile(r'"1\.99\.1"\Z'),
    "publish": re.compile(r"false\Z"),
}
RUNTIME_MANIFEST_SECTIONS = frozenset(("package", "dependencies", "dev-dependencies", "lints"))
RUNTIME_MANIFEST_INHERITED_KEYS = frozenset((
    "version.workspace", "edition.workspace", "rust-version.workspace", "publish.workspace",
))
RUNTIME_WORKSPACE_VALUE_PATTERN = re.compile(r"\{\s*workspace\s*=\s*true\s*\}\Z")
RUNTIME_LOCK_NAME_PATTERN = re.compile(r'name = "([a-z][a-z0-9_]*(?:-[a-z0-9_]+)*)"\Z')
RUNTIME_LOCK_VERSION_PATTERN = re.compile(r'version = "[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}"\Z')
RUNTIME_LOCK_DEPENDENCY_PATTERN = re.compile(r'\s*"([a-z][a-z0-9_]*(?:-[a-z0-9_]+)*)",?\Z')
CORE_CONTRACT_TOOLCHAIN = b'[toolchain]\nchannel = "1.99.1"\ncomponents = ["rustfmt", "clippy"]\nprofile = "minimal"\n'
MAX_SIGNER_BYTES = 65536
MAX_INVENTORY_BYTES = 16384
MAX_TREE_BYTES = 1024 * 1024
MAX_CORE_CONTRACT_FILE_BYTES = 1024 * 1024
MAX_CORE_CONTRACT_PATTERN_TOTAL_BYTES = MAX_TREE_BYTES
MAX_CORE_CONTRACT_NAME_LENGTH = 64
MAX_CORE_CONTRACT_TS_SOURCES = 64
MAX_CORE_CONTRACT_TS_TESTS = 64
MAX_CORE_CONTRACT_ADRS = 64
MAX_CORE_CONTRACT_FUZZ_TARGETS = 16
MAX_FUZZ_CORPUS_FILES = 256
MAX_FUZZ_CORPUS_FILE_BYTES = 4096
MAX_FUZZ_CORPUS_TOTAL_BYTES = 128 * 1024
MAX_GIT_OUTPUT = 65536
MAX_COMMITS = 20000
MAX_TREE_ENTRIES = 20000
COMMAND_TIMEOUT_SECONDS = 60


class Refusal(Exception):
    def __init__(self, reason, stage, source_diagnostic=None, core_check=None):
        self.reason = reason if type(reason) is str and reason in REASONS else "internal_error"
        self.stage = stage if type(stage) is str and stage in STAGES else "input"
        self.source_diagnostic = None
        self.core_check = None
        if (
            self.reason == "source_fetch_unavailable" and self.stage == "fetch"
            and type(source_diagnostic) is tuple and len(source_diagnostic) == 2
            and type(source_diagnostic[0]) is str
            and source_diagnostic[0] in FETCH_DIAGNOSTIC_OPERATIONS
            and type(source_diagnostic[1]) is str
            and source_diagnostic[1] in FETCH_DIAGNOSTIC_CLASSES
        ):
            self.source_diagnostic = source_diagnostic
        if (
            self.reason == "bootstrap_snapshot_invalid" and self.stage == "bootstrap"
            and type(core_check) is str and core_check in CORE_BOOTSTRAP_CHECKS
        ):
            self.core_check = core_check
        super().__init__(self.reason)


_REVOCATION_PROOF_SEAL = object()
_REVOCATION_PROOFS = weakref.WeakKeyDictionary()


class RevocationState:
    __slots__ = ("__weakref__",)

    def __repr__(self):
        return "RevocationState"


@dataclass(frozen=True, repr=False)
class SourceLease:
    source_path: Path
    record: object

    def __repr__(self):
        return "SourceLease"


def _full_sha(value):
    return type(value) is str and SOURCE_SHA_PATTERN.fullmatch(value) is not None


def _valid_base_selection(base_sha, base_branch, concern):
    if type(base_branch) is not str:
        return False
    if base_branch in BRANCHES:
        return True
    return (
        concern == "core-rust-lock-return"
        and base_branch == CORE_RUST_BOOTSTRAP_BASE_BRANCH
        and base_sha == CORE_RUST_BOOTSTRAP_BASE_SHA
    )


def parse_request(arguments):
    if type(arguments) not in (tuple, list) or len(arguments) != 8:
        raise Refusal("invalid_input", "input")
    if type(arguments[0]) is not str or arguments[0] != "--source-sha" or not _full_sha(arguments[1]):
        raise Refusal("invalid_input", "input")
    if type(arguments[2]) is not str or arguments[2] != "--base-sha" or not _full_sha(arguments[3]):
        raise Refusal("invalid_input", "input")
    if type(arguments[4]) is not str or arguments[4] != "--base-branch" or type(arguments[5]) is not str:
        raise Refusal("invalid_input", "input")
    if type(arguments[6]) is not str or arguments[6] != "--concern" or type(arguments[7]) is not str or arguments[7] not in CONCERNS:
        raise Refusal("invalid_input", "input")
    if not _valid_base_selection(arguments[3], arguments[5], arguments[7]):
        raise Refusal("invalid_input", "input")
    return {
        "source_sha": arguments[1],
        "base_sha": arguments[3],
        "base_branch": arguments[5],
        "concern": arguments[7],
    }


def _safe_context(control_sha, environ):
    if capability is None or reviewed_build is None:
        raise Refusal("context_unavailable", "context")
    try:
        binding = reviewed_build._binding(control_sha, environ)
        workspace = environ.get("CI_WORKSPACE", "")
        root = capability._check_context(control_sha, workspace)
    except Refusal:
        raise
    except capability.ProbeFailure:
        raise Refusal("context_unavailable", "context") from None
    except BaseException:
        raise Refusal("context_unavailable", "context") from None
    return binding, root


def _load_source_reader(root):
    try:
        path = (Path(__file__).resolve(strict=True).parent / "macos_source_reader.py").resolve(strict=True)
        if path.parent != Path(__file__).resolve(strict=True).parent or not path.is_file():
            raise ValueError
        spec = importlib.util.spec_from_file_location("macos_source_reader", str(path))
        if spec is None or spec.loader is None:
            raise ValueError
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    except BaseException:
        raise Refusal("source_reader_unavailable", "source_scope") from None


def _repository_configuration(reader, environ):
    try:
        repository_id_text = environ.get(SOURCE_REPOSITORY_ID_ENV, "")
        owner = environ.get(SOURCE_REPOSITORY_OWNER_ENV, "")
        repository = environ.get(SOURCE_REPOSITORY_NAME_ENV, "")
        if (
            type(repository_id_text) is not str
            or REPOSITORY_ID_PATTERN.fullmatch(repository_id_text) is None
            or type(owner) is not str
            or OWNER_PATTERN.fullmatch(owner) is None
            or type(repository) is not str
            or REPOSITORY_PATTERN.fullmatch(repository) is None
        ):
            raise ValueError
        token = environ.get(reader.TOKEN_ENV, "")
        if type(token) is not str or reader.TOKEN_PATTERN.fullmatch(token) is None:
            raise ValueError
        return int(repository_id_text), owner, repository, token
    except BaseException:
        raise Refusal("configuration_unavailable", "configuration") from None


def _verify_repository_scope(reader, repository_id, owner, repository, token):
    expected_name = owner + "/" + repository
    if reader.FULL_NAME_PATTERN.fullmatch(expected_name) is None:
        raise Refusal("configuration_unavailable", "configuration")
    try:
        status, body = reader._exchange("GET", reader.LIST_PATH, token)
        if status != 200:
            raise ValueError
        full_name = reader._repository_entry(body, repository_id)
        if full_name != expected_name:
            raise ValueError
        status, body = reader._exchange("GET", "/repos/" + full_name, token)
        if status != 200 or not reader._metadata_is_positive(body, repository_id, expected_name):
            raise ValueError
    except Refusal:
        raise
    except BaseException:
        raise Refusal("repository_scope_invalid", "source_scope") from None


def _resolve_trusted_executable(raw):
    try:
        return capability._resolve_trusted_path(raw).as_posix()
    except BaseException:
        raise Refusal("configuration_unavailable", "configuration") from None


def _base_git_environment(home, authorization=None):
    values = {
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "HOME": str(home),
        "TMPDIR": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_GRAFT_FILE": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
    }
    settings = [
        ("core.hooksPath", "/dev/null"),
        ("advice.graftFileDeprecated", "false"),
        ("fetch.fsckObjects", "true"),
        ("transfer.fsckObjects", "true"),
        ("protocol.version", "2"),
        ("protocol.https.allow", "always"),
        ("protocol.file.allow", "never"),
        ("protocol.ext.allow", "never"),
        ("credential.helper", ""),
        ("http.followRedirects", "false"),
        ("core.autocrlf", "false"),
        ("core.filemode", "true"),
        ("core.symlinks", "true"),
        ("core.attributesFile", "/dev/null"),
    ]
    if authorization is not None:
        settings.append(("http.https://github.com/.extraheader", authorization))
    values["GIT_CONFIG_COUNT"] = str(len(settings))
    for index, (key, value) in enumerate(settings):
        values["GIT_CONFIG_KEY_" + str(index)] = key
        values["GIT_CONFIG_VALUE_" + str(index)] = value
    return values


def _process_failure(stage):
    selected = stage if type(stage) is str and stage in STAGES else "fetch"
    reason = {
        "signature": "signature_invalid",
        "history": "base_invalid",
        "configuration": "revocation_policy_invalid",
        "revocation": "revocation_policy_invalid",
        "bootstrap": "bootstrap_snapshot_invalid",
        "cleanup": "cleanup_incomplete",
    }.get(selected, "source_fetch_unavailable")
    return Refusal(reason, selected)


def _stop_process(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except BaseException:
        raise Refusal("cleanup_incomplete", "cleanup") from None
    try:
        process.wait(timeout=5)
    except BaseException:
        raise Refusal("cleanup_incomplete", "cleanup") from None
    try:
        os.killpg(process.pid, 0)
    except ProcessLookupError:
        pass
    except BaseException:
        raise Refusal("cleanup_incomplete", "cleanup") from None
    else:
        raise Refusal("cleanup_incomplete", "cleanup")
    for stream in (process.stdout, process.stderr):
        if stream is not None and not stream.closed:
            try:
                stream.close()
            except OSError:
                raise Refusal("cleanup_incomplete", "cleanup") from None


def _run_process(
    argv,
    *,
    cwd,
    environ,
    timeout=COMMAND_TIMEOUT_SECONDS,
    max_output=MAX_GIT_OUTPUT,
    stage="fetch",
):
    try:
        process = subprocess.Popen(
            [str(part) for part in argv],
            cwd=str(cwd),
            env=environ,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            start_new_session=True,
        )
    except (OSError, subprocess.SubprocessError):
        raise _process_failure(stage) from None
    selector = None
    buffers = {"stdout": bytearray(), "stderr": bytearray()}
    streams = (("stdout", process.stdout), ("stderr", process.stderr))
    timed_out = False
    overflow = False
    failed = False
    deadline = time.monotonic() + timeout
    try:
        selector = selectors.DefaultSelector()
        for name, stream in streams:
            if stream is None:
                raise OSError
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            if not selector.get_map():
                time.sleep(min(remaining, 0.05))
                continue
            events = selector.select(min(remaining, 0.25))
            for key, unused_mask in events:
                name = key.data
                remaining_capacity = max_output + 1 - len(buffers[name])
                try:
                    payload = os.read(key.fd, min(8192, remaining_capacity))
                except BlockingIOError:
                    continue
                if not payload:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                buffers[name].extend(payload)
                if len(buffers[name]) > max_output:
                    overflow = True
                    break
            if overflow:
                break
    except BaseException:
        failed = True
    finally:
        if selector is not None:
            try:
                selector.close()
            except BaseException:
                failed = True
    if timed_out or overflow or failed:
        _stop_process(process)
        if failed:
            raise Refusal("cleanup_incomplete", "cleanup")
        raise _process_failure(stage)
    try:
        process.wait(timeout=5)
    except BaseException:
        _stop_process(process)
        raise Refusal("cleanup_incomplete", "cleanup") from None
    return subprocess.CompletedProcess(argv, process.returncode, bytes(buffers["stdout"]), bytes(buffers["stderr"]))


def _require_git_success(result, stage, *, operation=None):
    if result.returncode != 0 or result.stderr:
        reason = {
            "signature": "signature_invalid",
            "history": "base_invalid",
            "configuration": "revocation_policy_invalid",
            "bootstrap": "bootstrap_snapshot_invalid",
        }.get(stage, "source_fetch_unavailable")
        diagnostic = None
        if (
            stage == "fetch" and type(operation) is str
            and operation in FETCH_DIAGNOSTIC_OPERATIONS
        ):
            diagnostic = (
                operation,
                "exit_nonzero" if result.returncode != 0 else "stderr_present",
            )
        raise Refusal(reason, stage, diagnostic)
    return result.stdout


def _run_source_git(operation, argv, *, cwd, environ, timeout=COMMAND_TIMEOUT_SECONDS):
    if type(operation) is not str or operation not in FETCH_DIAGNOSTIC_OPERATIONS - {"source_snapshot"}:
        raise Refusal("source_fetch_unavailable", "fetch")
    try:
        result = _run_process(
            argv,
            cwd=cwd,
            environ=environ,
            timeout=timeout,
            stage="fetch",
        )
    except Refusal as error:
        if error.reason == "source_fetch_unavailable" and error.stage == "fetch":
            raise Refusal(
                error.reason, error.stage, (operation, "process_failure"),
            ) from None
        raise
    except BaseException:
        raise Refusal(
            "source_fetch_unavailable", "fetch", (operation, "unexpected_exception"),
        ) from None
    try:
        return _require_git_success(result, "fetch", operation=operation)
    except Refusal:
        raise
    except BaseException:
        raise Refusal(
            "source_fetch_unavailable", "fetch", (operation, "unexpected_exception"),
        ) from None


def _one_line_sha(payload):
    if type(payload) is not bytes or not payload.endswith(b"\n") or payload.count(b"\n") != 1:
        return None
    try:
        value = payload[:-1].decode("ascii")
    except UnicodeDecodeError:
        return None
    return value if _full_sha(value) else None


def _safe_temp_root(parent=None):
    path = None
    try:
        parent = "/tmp" if parent is None else str(parent)
        path = Path(tempfile.mkdtemp(prefix="macos-private-validation-", dir=parent))
        path = path.resolve(strict=True)
        os.chown(path, 0, 0)
        os.chmod(path, 0o700)
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_nlink < 2
        ):
            raise ValueError
        return path
    except BaseException:
        if path is not None:
            try:
                shutil.rmtree(path)
            except BaseException:
                raise Refusal("cleanup_incomplete", "cleanup") from None
        raise Refusal("configuration_unavailable", "configuration") from None


def _write_private_file(path, payload):
    descriptor = None
    try:
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None or type(payload) is not bytes or len(payload) > MAX_SIGNER_BYTES:
            raise ValueError
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | nofollow, 0o600)
        os.fchmod(descriptor, 0o600)
        os.fchown(descriptor, 0, 0)
        position = 0
        while position < len(payload):
            written = os.write(descriptor, payload[position:])
            if written <= 0:
                raise OSError
            position += written
        os.fsync(descriptor)
        info = os.fstat(descriptor)
        path_info = os.stat(path, follow_symlinks=False)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_nlink != 1
            or (info.st_dev, info.st_ino) != (path_info.st_dev, path_info.st_ino)
        ):
            raise ValueError
    except BaseException:
        raise Refusal("configuration_unavailable", "configuration") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise Refusal("cleanup_incomplete", "cleanup") from None


def _control_inventory(root, control_sha, git_executable, temp_root):
    descriptor = None
    try:
        control_root = Path(root).resolve(strict=True)
        if not control_root.is_dir():
            raise ValueError
        inventory_path = control_root / REVOCATION_INVENTORY
        parent_info = inventory_path.parent.lstat()
        info = inventory_path.lstat()
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != 0
            or parent_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
            or not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or info.st_nlink != 1
            or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
            or info.st_size > MAX_INVENTORY_BYTES
        ):
            raise ValueError
        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise ValueError
        descriptor = os.open(inventory_path, os.O_RDONLY | nofollow)
        opened_info = os.fstat(descriptor)
        current_info = inventory_path.lstat()
        if (
            not stat.S_ISREG(opened_info.st_mode)
            or opened_info.st_uid != 0
            or opened_info.st_nlink != 1
            or (opened_info.st_dev, opened_info.st_ino) != (info.st_dev, info.st_ino)
            or (current_info.st_dev, current_info.st_ino) != (info.st_dev, info.st_ino)
            or opened_info.st_size > MAX_INVENTORY_BYTES
        ):
            raise ValueError
        local_buffer = bytearray()
        while len(local_buffer) <= MAX_INVENTORY_BYTES:
            chunk = os.read(descriptor, min(4096, MAX_INVENTORY_BYTES + 1 - len(local_buffer)))
            if not chunk:
                break
            local_buffer.extend(chunk)
        if len(local_buffer) > MAX_INVENTORY_BYTES:
            raise ValueError
        local_bytes = bytes(local_buffer)
        env = _base_git_environment(temp_root)
        listing = _run_process(
            _control_git_command(
                git_executable, control_root, "ls-tree", "-z", control_sha, "--", REVOCATION_INVENTORY,
            ),
            cwd=control_root,
            environ=env,
            stage="revocation",
        )
        output = _require_git_success(listing, "configuration")
        entry = _parse_single_tree_entry(output, REVOCATION_INVENTORY)
        if entry is None or entry[0] != "100644" or entry[1] != "blob":
            raise ValueError
        blob_result = _run_process(
            _control_git_command(git_executable, control_root, "cat-file", "blob", entry[2]),
            cwd=control_root, environ=env,
            stage="revocation",
        )
        blob = _require_git_success(blob_result, "configuration")
        if len(blob) > MAX_INVENTORY_BYTES or local_bytes != blob:
            raise ValueError
        return _parse_fingerprint_inventory(blob)
    except Refusal:
        raise
    except BaseException:
        raise Refusal("revocation_policy_invalid", "revocation") from None
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                raise Refusal("cleanup_incomplete", "cleanup") from None


@dataclass(repr=False)
class _ControlInventoryOwnership:
    root: Path
    root_fd: int
    ci_fd: int
    inventory_fd: int
    root_identity: tuple
    ci_identity: tuple
    inventory_identity: tuple
    root_owner: tuple
    ci_owner: tuple
    inventory_owner: tuple
    root_mode: int
    ci_mode: int
    inventory_mode: int
    contents: bytes
    closed: bool = False


def _control_owner(info):
    return info.st_uid, info.st_gid


def _control_identity(info):
    return info.st_dev, info.st_ino


def _control_safe_mode(info):
    return not info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)


def _control_inventory_snapshot(state):
    root_info = os.fstat(state.root_fd)
    root_named = state.root.lstat()
    ci_info = os.fstat(state.ci_fd)
    ci_named = os.stat("ci", dir_fd=state.root_fd, follow_symlinks=False)
    inventory_info = os.fstat(state.inventory_fd)
    inventory_named = os.stat(
        "revoked-signer-fingerprints", dir_fd=state.ci_fd, follow_symlinks=False,
    )
    if (
        not stat.S_ISDIR(root_info.st_mode)
        or _control_identity(root_info) != state.root_identity
        or _control_identity(root_named) != state.root_identity
        or _control_owner(root_info) != state.root_owner
        or stat.S_IMODE(root_info.st_mode) != state.root_mode
        or not _control_safe_mode(root_info)
        or not stat.S_ISDIR(ci_info.st_mode)
        or _control_identity(ci_info) != state.ci_identity
        or _control_identity(ci_named) != state.ci_identity
        or _control_owner(ci_info) not in (state.ci_owner, (0, 0))
        or stat.S_IMODE(ci_info.st_mode) != state.ci_mode
        or not _control_safe_mode(ci_info)
        or not stat.S_ISREG(inventory_info.st_mode)
        or _control_identity(inventory_info) != state.inventory_identity
        or _control_identity(inventory_named) != state.inventory_identity
        or _control_owner(inventory_info) not in (state.inventory_owner, (0, 0))
        or inventory_info.st_nlink != 1
        or inventory_named.st_nlink != 1
        or stat.S_IMODE(inventory_info.st_mode) != state.inventory_mode
        or not _control_safe_mode(inventory_info)
        or inventory_info.st_size != len(state.contents)
        or inventory_info.st_size > MAX_INVENTORY_BYTES
    ):
        raise ValueError
    return root_info, ci_info, inventory_info


def _read_control_inventory_descriptor(descriptor):
    os.lseek(descriptor, 0, os.SEEK_SET)
    payload = bytearray()
    while len(payload) <= MAX_INVENTORY_BYTES:
        chunk = os.read(descriptor, min(4096, MAX_INVENTORY_BYTES + 1 - len(payload)))
        if not chunk:
            break
        payload.extend(chunk)
    if len(payload) > MAX_INVENTORY_BYTES:
        raise ValueError
    return bytes(payload)


def _close_control_inventory_descriptors(descriptors):
    failed = False
    for descriptor in reversed(descriptors):
        if descriptor is not None and descriptor >= 0:
            try:
                os.close(descriptor)
            except BaseException:
                failed = True
    if failed:
        raise Refusal("cleanup_incomplete", "cleanup") from None


def _restore_control_inventory(state):
    if type(state) is not _ControlInventoryOwnership or state.closed:
        raise Refusal("cleanup_incomplete", "cleanup")
    failed = False
    try:
        unused_root, ci_info, inventory_info = _control_inventory_snapshot(state)
        if _read_control_inventory_descriptor(state.inventory_fd) != state.contents:
            raise ValueError
        if _control_owner(inventory_info) != state.inventory_owner:
            os.fchown(state.inventory_fd, *state.inventory_owner)
        unused_root, ci_info, inventory_info = _control_inventory_snapshot(state)
        if (_control_owner(inventory_info) != state.inventory_owner
                or _read_control_inventory_descriptor(state.inventory_fd) != state.contents):
            raise ValueError
        if _control_owner(ci_info) != state.ci_owner:
            os.fchown(state.ci_fd, *state.ci_owner)
        unused_root, ci_info, inventory_info = _control_inventory_snapshot(state)
        if (_control_owner(ci_info) != state.ci_owner
                or _control_owner(inventory_info) != state.inventory_owner):
            raise ValueError
    except BaseException:
        failed = True
    finally:
        descriptors = (state.root_fd, state.ci_fd, state.inventory_fd)
        state.closed = True
        try:
            _close_control_inventory_descriptors(descriptors)
        except BaseException:
            failed = True
    if failed:
        raise Refusal("cleanup_incomplete", "cleanup") from None


def _close_control_inventory(state):
    if type(state) is not _ControlInventoryOwnership or state.closed:
        raise Refusal("cleanup_incomplete", "cleanup")
    failed = False
    try:
        unused_root, ci_info, inventory_info = _control_inventory_snapshot(state)
        if (_control_owner(ci_info) != (0, 0) or _control_owner(inventory_info) != (0, 0)
                or _read_control_inventory_descriptor(state.inventory_fd) != state.contents):
            raise ValueError
    except BaseException:
        failed = True
    finally:
        state.closed = True
        try:
            _close_control_inventory_descriptors((state.root_fd, state.ci_fd, state.inventory_fd))
        except BaseException:
            failed = True
    if failed:
        raise Refusal("cleanup_incomplete", "cleanup") from None


def _prepare_control_inventory(root, control_sha, runner_temp):
    descriptors = []
    state = None
    try:
        if not _full_sha(control_sha) or not isinstance(root, Path) or not isinstance(runner_temp, Path):
            raise ValueError
        runner_path = runner_temp.resolve(strict=True)
        runner_info = runner_temp.lstat()
        if (runner_path != runner_temp or not stat.S_ISDIR(runner_info.st_mode)
                or runner_info.st_uid == 0):
            raise ValueError
        runner_uid = runner_info.st_uid
        control_root = root.resolve(strict=True)
        root_named = control_root.lstat()
        if (control_root != root or not stat.S_ISDIR(root_named.st_mode)
                or root_named.st_uid not in (0, runner_uid) or not _control_safe_mode(root_named)):
            raise ValueError
        nofollow = getattr(os, "O_NOFOLLOW", None)
        directory = getattr(os, "O_DIRECTORY", None)
        if (nofollow is None or directory is None or os.open not in os.supports_dir_fd
                or os.stat not in os.supports_dir_fd or os.stat not in os.supports_follow_symlinks):
            raise ValueError
        flags = os.O_RDONLY | nofollow | directory | getattr(os, "O_CLOEXEC", 0)
        root_fd = os.open(control_root, flags)
        descriptors.append(root_fd)
        root_info = os.fstat(root_fd)
        if (_control_identity(root_info) != _control_identity(root_named)
                or not stat.S_ISDIR(root_info.st_mode)
                or root_info.st_uid not in (runner_uid, 0)
                or not _control_safe_mode(root_info)):
            raise ValueError
        ci_named = os.stat("ci", dir_fd=root_fd, follow_symlinks=False)
        if (not stat.S_ISDIR(ci_named.st_mode) or ci_named.st_uid not in (0, runner_uid)
                or not _control_safe_mode(ci_named)):
            raise ValueError
        ci_fd = os.open("ci", flags, dir_fd=root_fd)
        descriptors.append(ci_fd)
        ci_info = os.fstat(ci_fd)
        if (_control_identity(ci_info) != _control_identity(ci_named)
                or ci_info.st_uid not in (runner_uid, 0)
                or not _control_safe_mode(ci_info)):
            raise ValueError
        inventory_name = "revoked-signer-fingerprints"
        inventory_named = os.stat(inventory_name, dir_fd=ci_fd, follow_symlinks=False)
        if (not stat.S_ISREG(inventory_named.st_mode) or inventory_named.st_uid not in (0, runner_uid)
                or inventory_named.st_nlink != 1 or inventory_named.st_size > MAX_INVENTORY_BYTES
                or not _control_safe_mode(inventory_named)):
            raise ValueError
        inventory_fd = os.open(
            inventory_name, os.O_RDONLY | nofollow | getattr(os, "O_CLOEXEC", 0), dir_fd=ci_fd,
        )
        descriptors.append(inventory_fd)
        inventory_info = os.fstat(inventory_fd)
        if (_control_identity(inventory_info) != _control_identity(inventory_named)
                or inventory_info.st_uid not in (runner_uid, 0)
                or inventory_info.st_nlink != 1 or inventory_info.st_size > MAX_INVENTORY_BYTES
                or not stat.S_ISREG(inventory_info.st_mode) or not _control_safe_mode(inventory_info)):
            raise ValueError
        contents = _read_control_inventory_descriptor(inventory_fd)
        if len(contents) != inventory_info.st_size:
            raise ValueError
        root_after, ci_after, inventory_after = os.fstat(root_fd), os.fstat(ci_fd), os.fstat(inventory_fd)
        root_named_after = control_root.lstat()
        ci_named_after = os.stat("ci", dir_fd=root_fd, follow_symlinks=False)
        inventory_named_after = os.stat(inventory_name, dir_fd=ci_fd, follow_symlinks=False)
        if (
            _control_identity(root_after) != _control_identity(root_info)
            or _control_identity(root_named_after) != _control_identity(root_info)
            or _control_identity(ci_after) != _control_identity(ci_info)
            or _control_identity(ci_named_after) != _control_identity(ci_info)
            or _control_identity(inventory_after) != _control_identity(inventory_info)
            or _control_identity(inventory_named_after) != _control_identity(inventory_info)
            or _control_owner(root_after) != _control_owner(root_info)
            or _control_owner(ci_after) != _control_owner(ci_info)
            or _control_owner(inventory_after) != _control_owner(inventory_info)
            or stat.S_IMODE(root_after.st_mode) != stat.S_IMODE(root_info.st_mode)
            or stat.S_IMODE(ci_after.st_mode) != stat.S_IMODE(ci_info.st_mode)
            or stat.S_IMODE(inventory_after.st_mode) != stat.S_IMODE(inventory_info.st_mode)
            or not _control_safe_mode(root_after)
            or not _control_safe_mode(ci_after)
            or not _control_safe_mode(inventory_after)
            or inventory_after.st_nlink != 1
            or inventory_after.st_size != inventory_info.st_size
            or inventory_named_after.st_nlink != 1
            or inventory_after.st_mtime_ns != inventory_info.st_mtime_ns
            or inventory_after.st_ctime_ns != inventory_info.st_ctime_ns
        ):
            raise ValueError
        git_executable = _resolve_trusted_executable("/usr/bin/git")
        env = _base_git_environment(runner_path)
        listing = _run_process(
            _control_git_command(git_executable, control_root, "ls-tree", "-z", control_sha,
                                 "--", REVOCATION_INVENTORY),
            cwd=control_root, environ=env, stage="revocation",
        )
        entry = _parse_single_tree_entry(_require_git_success(listing, "configuration"), REVOCATION_INVENTORY)
        if entry is None or entry[0] != "100644" or entry[1] != "blob":
            raise ValueError
        blob_result = _run_process(
            _control_git_command(git_executable, control_root, "cat-file", "blob", entry[2]),
            cwd=control_root, environ=env, stage="revocation",
        )
        blob = _require_git_success(blob_result, "configuration")
        if len(blob) > MAX_INVENTORY_BYTES or contents != blob:
            raise ValueError
        _parse_fingerprint_inventory(blob)
        root_verified, ci_verified, inventory_verified = (
            os.fstat(root_fd), os.fstat(ci_fd), os.fstat(inventory_fd),
        )
        if (_control_identity(root_verified) != _control_identity(root_info)
                or _control_identity(control_root.lstat()) != _control_identity(root_info)
                or _control_owner(root_verified) != _control_owner(root_info)
                or stat.S_IMODE(root_verified.st_mode) != stat.S_IMODE(root_info.st_mode)
                or not _control_safe_mode(root_verified)
                or _control_identity(ci_verified) != _control_identity(ci_info)
                or _control_identity(os.stat("ci", dir_fd=root_fd, follow_symlinks=False)) != _control_identity(ci_info)
                or _control_owner(ci_verified) != _control_owner(ci_info)
                or stat.S_IMODE(ci_verified.st_mode) != stat.S_IMODE(ci_info.st_mode)
                or not _control_safe_mode(ci_verified)
                or _control_identity(inventory_verified) != _control_identity(inventory_info)
                or _control_identity(os.stat(inventory_name, dir_fd=ci_fd, follow_symlinks=False))
                != _control_identity(inventory_info)
                or _control_owner(inventory_verified) != _control_owner(inventory_info)
                or stat.S_IMODE(inventory_verified.st_mode) != stat.S_IMODE(inventory_info.st_mode)
                or not _control_safe_mode(inventory_verified)
                or inventory_verified.st_nlink != 1
                or inventory_verified.st_size != inventory_info.st_size
                or inventory_verified.st_mtime_ns != inventory_info.st_mtime_ns
                or inventory_verified.st_ctime_ns != inventory_info.st_ctime_ns
                or _read_control_inventory_descriptor(inventory_fd) != blob):
            raise ValueError
        state = _ControlInventoryOwnership(
            root=control_root, root_fd=root_fd, ci_fd=ci_fd, inventory_fd=inventory_fd,
            root_identity=_control_identity(root_info), ci_identity=_control_identity(ci_info),
            inventory_identity=_control_identity(inventory_info), root_owner=_control_owner(root_info),
            ci_owner=_control_owner(ci_info), inventory_owner=_control_owner(inventory_info),
            root_mode=stat.S_IMODE(root_info.st_mode), ci_mode=stat.S_IMODE(ci_info.st_mode),
            inventory_mode=stat.S_IMODE(inventory_info.st_mode), contents=blob,
        )
        _control_inventory_snapshot(state)
        os.fchown(ci_fd, 0, 0)
        _control_inventory_snapshot(state)
        os.fchown(inventory_fd, 0, 0)
        unused_root, ci_info, inventory_info = _control_inventory_snapshot(state)
        if (_control_owner(ci_info) != (0, 0) or _control_owner(inventory_info) != (0, 0)
                or _read_control_inventory_descriptor(inventory_fd) != blob):
            raise ValueError
        return state
    except Refusal as error:
        if state is not None:
            try:
                _restore_control_inventory(state)
            except BaseException:
                raise Refusal("cleanup_incomplete", "cleanup") from None
        else:
            try:
                _close_control_inventory_descriptors(descriptors)
            except BaseException:
                raise Refusal("cleanup_incomplete", "cleanup") from None
        raise error
    except BaseException:
        if state is not None:
            try:
                _restore_control_inventory(state)
            except BaseException:
                raise Refusal("cleanup_incomplete", "cleanup") from None
        else:
            try:
                _close_control_inventory_descriptors(descriptors)
            except BaseException:
                raise Refusal("cleanup_incomplete", "cleanup") from None
        raise Refusal("revocation_policy_invalid", "revocation") from None


def _control_git_command(git_executable, control_root, *arguments):
    try:
        resolved_root = Path(control_root).resolve(strict=True)
        if not resolved_root.is_dir() or not resolved_root.is_absolute():
            raise ValueError
        if type(git_executable) is not str or not git_executable.startswith("/"):
            raise ValueError
        if not arguments or any(type(argument) is not str or not argument for argument in arguments):
            raise ValueError
        return (
            git_executable,
            "-c",
            "safe.directory=" + resolved_root.as_posix(),
            *arguments,
        )
    except BaseException:
        raise Refusal("revocation_policy_invalid", "revocation") from None


def _parse_fingerprint_inventory(payload):
    if type(payload) is not bytes or len(payload) > MAX_INVENTORY_BYTES:
        raise Refusal("revocation_policy_invalid", "revocation")
    if payload == b"":
        return ()
    if not payload.endswith(b"\n") or b"\r" in payload:
        raise Refusal("revocation_policy_invalid", "revocation")
    fingerprints = []
    for raw_line in payload[:-1].split(b"\n"):
        try:
            line = raw_line.decode("ascii")
        except UnicodeDecodeError:
            raise Refusal("revocation_policy_invalid", "revocation") from None
        if FINGERPRINT_PATTERN.fullmatch(line) is None or line in fingerprints:
            raise Refusal("revocation_policy_invalid", "revocation")
        fingerprints.append(line)
    return tuple(fingerprints)


def _ssh_string(payload, offset):
    if type(payload) is not bytes or offset < 0 or offset + 4 > len(payload):
        raise ValueError
    size = int.from_bytes(payload[offset:offset + 4], "big")
    start = offset + 4
    end = start + size
    if end > len(payload):
        raise ValueError
    return payload[start:end], end


def _key_fingerprint(key_type, encoded_key):
    if key_type != "ssh-ed25519" or type(encoded_key) is not str:
        raise ValueError
    blob = base64.b64decode(encoded_key.encode("ascii"), validate=True)
    algorithm, offset = _ssh_string(blob, 0)
    public_key, offset = _ssh_string(blob, offset)
    if algorithm != b"ssh-ed25519" or len(public_key) != 32 or offset != len(blob):
        raise ValueError
    digest = base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return "SHA256:" + digest, blob


def _signer_timestamp(value):
    if type(value) is not str:
        raise ValueError
    formats = {
        8: "%Y%m%d",
        12: "%Y%m%d%H%M",
        14: "%Y%m%d%H%M%S",
    }
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", value) is not None:
        parsed = datetime.datetime.strptime(value, "%Y-%m-%d")
    else:
        normalized = value[:-1] if value.endswith("Z") else value
        format_string = formats.get(len(normalized))
        if format_string is None or re.fullmatch(r"[0-9]+", normalized) is None:
            raise ValueError
        parsed = datetime.datetime.strptime(normalized, format_string)
    return parsed.replace(tzinfo=datetime.timezone.utc)


def _signer_options(value):
    if type(value) is not str:
        raise ValueError
    options = value.split(",")
    if not options or len(options) > 3:
        raise ValueError
    parsed = {}
    for option in options:
        name, separator, option_value = option.partition("=")
        if not separator or name in parsed or not option_value:
            raise ValueError
        parsed[name] = option_value
    if parsed.get("namespaces") != "git":
        raise ValueError
    if set(parsed) - {"namespaces", "valid-after", "valid-before"}:
        raise ValueError
    valid_after = _signer_timestamp(parsed["valid-after"]) if "valid-after" in parsed else None
    valid_before = _signer_timestamp(parsed["valid-before"]) if "valid-before" in parsed else None
    if valid_after is not None and valid_before is not None and valid_after > valid_before:
        raise ValueError
    return parsed


def _signer_inventory(payload, *, current_time=None):
    if type(payload) is not bytes or not payload or len(payload) > MAX_SIGNER_BYTES:
        raise Refusal("signature_invalid", "signature")
    if current_time is None:
        current_time = datetime.datetime.now(datetime.timezone.utc)
    if (
        type(current_time) is not datetime.datetime
        or current_time.tzinfo is None
        or current_time.utcoffset() is None
    ):
        raise Refusal("signature_invalid", "signature")
    current_time = current_time.astimezone(datetime.timezone.utc)
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError:
        raise Refusal("signature_invalid", "signature") from None
    keys = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith(chr(35)):
            continue
        try:
            fields = shlex.split(line, comments=False, posix=True)
            key_positions = [index for index in (1, 2) if index < len(fields) and fields[index] == "ssh-ed25519"]
            if len(key_positions) != 1:
                raise ValueError
            key_position = key_positions[0]
            if len(fields) < key_position + 2:
                raise ValueError
            principal_field = fields[0]
            principals = principal_field.split(",")
            if not principals or any(re.fullmatch(r"[A-Za-z0-9_.+@-]{1,200}", item) is None for item in principals):
                raise ValueError
            options = {}
            if key_position == 2:
                options = _signer_options(fields[1])
            elif key_position != 1:
                raise ValueError
            if len(fields) != key_position + 2:
                raise ValueError
            encoded_key = fields[key_position + 1]
            fingerprint, blob = _key_fingerprint("ssh-ed25519", encoded_key)
            key_line = b"ssh-ed25519 " + encoded_key.encode("ascii") + b"\n"
            previous = keys.get(fingerprint)
            if previous is not None and previous[:2] != (key_line, blob):
                raise ValueError
            active_lines = list(previous[2]) if previous is not None else []
            valid_after = _signer_timestamp(options["valid-after"]) if "valid-after" in options else None
            valid_before = _signer_timestamp(options["valid-before"]) if "valid-before" in options else None
            if (valid_after is None or current_time >= valid_after) and (
                valid_before is None or current_time <= valid_before
            ):
                active_line = (line + "\n").encode("ascii")
                if active_line not in active_lines:
                    active_lines.append(active_line)
            keys[fingerprint] = (key_line, blob, tuple(active_lines))
        except BaseException:
            raise Refusal("signature_invalid", "signature") from None
    if not keys:
        raise Refusal("signature_invalid", "signature")
    if not _active_signer_payload(keys):
        raise Refusal("signature_invalid", "signature")
    return keys


def _active_signer_payload(signers):
    if type(signers) is not dict:
        raise Refusal("signature_invalid", "signature")
    return b"".join(
        line
        for value in signers.values()
        for line in value[2]
    )


def _revocation_payload(fingerprints, signers):
    if type(fingerprints) is not tuple or type(signers) is not dict:
        raise Refusal("revocation_policy_invalid", "revocation")
    unmatched = [fingerprint for fingerprint in fingerprints if fingerprint not in signers]
    if unmatched:
        raise Refusal("revocation_policy_invalid", "revocation")
    return b"".join(signers[fingerprint][0] for fingerprint in fingerprints)


def _parse_single_tree_entry(payload, expected_path):
    if (
        type(payload) is not bytes
        or not payload.endswith(b"\x00")
        or payload.count(b"\x00") != 1
    ):
        return None
    try:
        metadata, path_bytes = payload[:-1].split(b"\t", 1)
        fields = metadata.decode("ascii").split()
        path = path_bytes.decode("utf-8", "strict")
    except (ValueError, UnicodeDecodeError):
        return None
    if len(fields) != 3 or path != expected_path or re.fullmatch(r"[a-f0-9]{40}", fields[2]) is None:
        return None
    return fields[0], fields[1], fields[2]


def _source_entry(repository, git_executable, repo_env, commit, path, *, stage="bootstrap"):
    result = _run_process(
        (git_executable, "ls-tree", "-z", commit, "--", path),
        cwd=repository,
        environ=repo_env,
        stage=stage,
    )
    if result.returncode != 0 or result.stderr:
        raise _process_failure(stage)
    entry = _parse_single_tree_entry(result.stdout, path)
    if entry is None:
        raise _process_failure(stage)
    return entry


def _read_source_blob(repository, git_executable, repo_env, object_id, maximum):
    result = _run_process(
        (git_executable, "cat-file", "blob", object_id),
        cwd=repository,
        environ=repo_env,
        stage="signature",
    )
    if result.returncode != 0 or result.stderr or len(result.stdout) > maximum:
        raise Refusal("signature_invalid", "signature")
    return result.stdout


def _administrative_tree(repository, git_executable, repo_env, commit):
    result = _run_process(
        (git_executable, "ls-tree", "-r", "-z", commit),
        cwd=repository,
        environ=repo_env,
        max_output=MAX_TREE_BYTES,
        stage="bootstrap",
    )
    if result.returncode != 0 or result.stderr or len(result.stdout) > MAX_TREE_BYTES:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
    root_files = {".gitignore", "AGENTS.md", "CLAUDE.md", "README.md"}
    rules_lock = RULES_LOCK_PATH
    signers = "/".join(SIGNER_PATH_PARTS)
    known_paths = {
        rules_lock,
        RULES_DIRECTORY + "/settings.json",
        signers,
    }
    if result.stdout and not result.stdout.endswith(b"\x00"):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
    for raw_entry in result.stdout.split(b"\x00"):
        if not raw_entry:
            continue
        try:
            metadata, path_bytes = raw_entry.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split()
            path = path_bytes.decode("utf-8", "strict")
        except (ValueError, UnicodeDecodeError):
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap") from None
        if object_type != "blob" or re.fullmatch(r"[a-f0-9]{40}", object_id) is None:
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
        valid = (
            path in root_files and mode == "100644"
            or path in known_paths and mode == "100644"
            or path.startswith(RULES_DIRECTORY + "/rules/shared/")
            and path.endswith(".md") and mode == "100644"
            or path.startswith(RULES_DIRECTORY + "/hooks/shared/")
            and path.endswith(".sh") and mode == "100755"
        )
        if not valid:
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
    lock_entry = _source_entry(repository, git_executable, repo_env, commit, rules_lock)
    signer_entry = _source_entry(
        repository, git_executable, repo_env, commit, signers, stage="signature",
    )
    if lock_entry[:2] != ("100644", "blob") or signer_entry[:2] != ("100644", "blob"):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap")


def _safe_rules_tree(repository, git_executable, repo_env, commit):
    result = _run_process(
        (git_executable, "ls-tree", "-r", "-z", commit),
        cwd=repository,
        environ=repo_env,
        max_output=MAX_TREE_BYTES,
        stage="bootstrap",
    )
    if result.returncode != 0 or result.stderr or len(result.stdout) > MAX_TREE_BYTES:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
    if result.stdout and not result.stdout.endswith(b"\x00"):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
    folded = set()
    entries = 0
    for raw_entry in result.stdout.split(b"\x00"):
        if not raw_entry:
            continue
        entries += 1
        if entries > MAX_TREE_ENTRIES:
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
        try:
            metadata, path_bytes = raw_entry.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split()
            path = path_bytes.decode("utf-8", "strict")
        except (ValueError, UnicodeDecodeError):
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap") from None
        components = path.split("/")
        if (
            object_type != "blob"
            or mode not in ("100644", "100755")
            or re.fullmatch(r"[a-f0-9]{40}", object_id) is None
            or not path
            or path.startswith("/")
            or "\\" in path
            or any(part in ("", ".", "..") for part in components)
            or components[0] == ".git"
            or unicodedata.normalize("NFC", path) != path
            or re.fullmatch(r"[A-Za-z0-9._/-]+", path) is None
            or path.casefold() in folded
        ):
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
        folded.add(path.casefold())
    signer_entry = _source_entry(
        repository, git_executable, repo_env, commit, "/".join(SIGNER_PATH_PARTS), stage="signature",
    )
    if signer_entry[:2] != ("100644", "blob"):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap")


def _contract_tree_entries(repository, git_executable, repo_env, commit):
    result = _run_process(
        (git_executable, "ls-tree", "-r", "-z", commit),
        cwd=repository,
        environ=repo_env,
        max_output=MAX_TREE_BYTES,
        stage="bootstrap",
    )
    if result.returncode != 0 or result.stderr or len(result.stdout) > MAX_TREE_BYTES:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="tree_entries")
    if result.stdout and not result.stdout.endswith(b"\x00"):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="tree_entries")
    entries = {}
    folded = set()
    for raw_entry in result.stdout.split(b"\x00"):
        if not raw_entry:
            continue
        try:
            metadata, path_bytes = raw_entry.split(b"\t", 1)
            mode, object_type, object_id = metadata.decode("ascii").split()
            path = path_bytes.decode("utf-8", "strict")
        except (ValueError, UnicodeDecodeError):
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="tree_entries") from None
        components = path.split("/")
        if (
            len(entries) >= MAX_TREE_ENTRIES
            or object_type != "blob"
            or mode not in ("100644", "100755")
            or re.fullmatch(r"[a-f0-9]{40}", object_id) is None
            or not path
            or path.startswith("/")
            or "\\" in path
            or any(part in ("", ".", "..") for part in components)
            or components[0] == ".git"
            or unicodedata.normalize("NFC", path) != path
            or re.fullmatch(r"[A-Za-z0-9._/-]+", path) is None
            or path.casefold() in folded
        ):
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="tree_entries")
        entries[path] = (mode, object_id)
        folded.add(path.casefold())
    return entries


def _contract_blob(
    repository, git_executable, repo_env, entries, path, *, core_check,
    max_bytes=MAX_CORE_CONTRACT_FILE_BYTES,
):
    if (type(max_bytes) is not int or not 1 <= max_bytes <= MAX_FEEDBACK_LOCK_BYTES
            or max_bytes > MAX_CORE_CONTRACT_FILE_BYTES
            and (path != CORE_CONTRACT_PACKAGE_LOCK_PATH
                 or core_check != "package_decode" or max_bytes != MAX_FEEDBACK_LOCK_BYTES)):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check=core_check)
    entry = entries.get(path)
    if entry is None or entry[0] not in ("100644", "100755"):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check=core_check)
    try:
        result = _run_process(
            (git_executable, "cat-file", "blob", entry[1]),
            cwd=repository,
            environ=repo_env,
            max_output=max_bytes,
            stage="bootstrap",
        )
    except Refusal as error:
        if error.reason == "cleanup_incomplete":
            raise
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check=core_check) from None
    if result.returncode != 0 or result.stderr or len(result.stdout) > max_bytes:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check=core_check)
    return result.stdout


def _contract_blob_size(repository, git_executable, repo_env, entries, path, *, core_check):
    entry = entries.get(path)
    if entry is None or entry[0] not in ("100644", "100755"):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check=core_check)
    try:
        result = _run_process(
            (git_executable, "cat-file", "-s", entry[1]),
            cwd=repository,
            environ=repo_env,
            max_output=32,
            stage="bootstrap",
        )
    except Refusal as error:
        if error.reason == "cleanup_incomplete":
            raise
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check=core_check) from None
    if (result.returncode != 0 or result.stderr
            or re.fullmatch(rb"(?:0|[1-9][0-9]{0,19})\n", result.stdout) is None):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check=core_check)
    size = int(result.stdout[:-1])
    if size > MAX_CORE_CONTRACT_FILE_BYTES:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check=core_check)
    return size


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError
        result[key] = value
    return result


def _feedback_manifest_shape(root_payload, package_payload):
    try:
        root_manifest = json.loads(
            root_payload.decode("utf-8", "strict"), object_pairs_hook=_unique_json_object,
        )
        package_manifest = json.loads(
            package_payload.decode("utf-8", "strict"), object_pairs_hook=_unique_json_object,
        )
    except (AttributeError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        return False
    if type(root_manifest) is not dict or type(package_manifest) is not dict:
        return False
    scripts = root_manifest.get("scripts")
    package_scripts = package_manifest.get("scripts")
    engines = root_manifest.get("engines")
    return (
        root_manifest.get("private") is True
        and root_manifest.get("workspaces") == ["packages/*"]
        and root_manifest.get("packageManager") == "npm@11.19.1"
        and type(engines) is dict
        and engines.get("node") == "24.22.1"
        and engines.get("npm") == "11.19.1"
        and type(scripts) is dict
        and all(type(name) is str and type(value) is str for name, value in scripts.items())
        and type(package_manifest.get("name")) is str
        and type(package_manifest.get("version")) is str
        and package_manifest.get("type") == "module"
        and type(package_manifest.get("exports")) is dict
        and type(package_scripts) is dict
        and all(type(name) is str and type(value) is str for name, value in package_scripts.items())
        and not any(name in package_scripts for name in ("preinstall", "install", "postinstall"))
    )


def _feedback_fuzz_manifest_shape(fuzz_payload, api_payload, lock_payload):
    if any(type(payload) is not bytes or len(payload) > MAX_CORE_CONTRACT_FILE_BYTES
           for payload in (fuzz_payload, api_payload, lock_payload)):
        return False
    try:
        fuzz_text = fuzz_payload.decode("utf-8", "strict")
        api_text = api_payload.decode("utf-8", "strict")
        lock_text = lock_payload.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return False
    if any("\r" in text for text in (fuzz_text, api_text, lock_text)):
        return False

    def parse_sections(text):
        sections = {}
        current = None
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(chr(35)):
                continue
            if stripped.startswith("[["):
                return None
            section = re.fullmatch(r"\[([A-Za-z0-9_.-]{1,128})\]", stripped)
            if section is not None:
                current = section.group(1)
                if current in sections:
                    return None
                sections[current] = {}
                continue
            assignment = re.fullmatch(r"([A-Za-z0-9_.-]{1,128})\s*=\s*(.{1,4096})", stripped)
            if current is None or assignment is None:
                return None
            key, value = assignment.groups()
            selected = sections[current]
            if key in selected:
                return None
            selected[key] = value.strip()
        return sections

    fuzz_sections = parse_sections(fuzz_text)
    api_sections = parse_sections(api_text)
    if fuzz_sections is None or api_sections is None:
        return False
    package = fuzz_sections.get("package")
    dependencies = fuzz_sections.get("dependencies")
    workspace = fuzz_sections.get("workspace")
    lints = fuzz_sections.get("lints.rust")
    api_package = api_sections.get("package")
    if (set(fuzz_sections) != {"package", "dependencies", "workspace", "lints.rust"}
            or set(api_sections) != {"package", "dependencies", "lints"}
            or type(package) is not dict or type(dependencies) is not dict
            or type(workspace) is not dict or type(lints) is not dict
            or type(api_package) is not dict):
        return False
    if (set(package) != {"name", "description", "version", "edition", "rust-version", "publish"}
            or set(api_package) != {
                "name", "description", "version.workspace", "edition.workspace",
                "rust-version.workspace", "publish.workspace",
            }
            or re.fullmatch(r'"[A-Za-z0-9_-]{1,64}"', package.get("name", "")) is None
            or re.fullmatch(r'"[^"]{1,256}"', package.get("description", "")) is None
            or re.fullmatch(r'"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?"', package.get("version", "")) is None
            or package.get("edition") != '"2024"'
            or package.get("rust-version") != '"1.99.1"'
            or package.get("publish") != "false"
            or any(api_package.get(name) != "true" for name in (
                "version.workspace", "edition.workspace", "rust-version.workspace", "publish.workspace",
            ))
            or re.fullmatch(r'"[^"]{1,256}"', api_package.get("description", "")) is None
            or set(workspace) != {"resolver"} or workspace.get("resolver") != '"3"'
            or set(lints) != {"unsafe_code", "warnings"}
            or lints.get("unsafe_code") != '"forbid"'
            or lints.get("warnings") != '"deny"'):
        return False
    api_name_raw = api_package.get("name", "")
    if re.fullmatch(r'"[A-Za-z0-9_-]{1,64}"', api_name_raw) is None:
        return False
    api_name = api_name_raw[1:-1]
    fuzz_name = package["name"][1:-1]
    if (set(dependencies) != {api_name}
            or dependencies[api_name] != '{ path = "../crates/host/api" }'):
        return False

    prefix_and_packages = re.split(r"(?m)^\[\[package\]\]\s*$", lock_text)
    if len(prefix_and_packages) != 3 or re.search(r"(?m)^\s*(?:source|checksum)\s*=", lock_text):
        return False
    comment_line = r"(?m)^" + re.escape(chr(35)) + r".*$"
    if (re.findall(r"(?m)^version\s*=\s*(4)\s*$", prefix_and_packages[0]) != ["4"]
            or re.sub(comment_line, "", prefix_and_packages[0]).strip() != "version = 4"):
        return False
    parsed_lock = {}
    for block in prefix_and_packages[1:]:
        name_matches = re.findall(r'(?m)^name\s*=\s*"([A-Za-z0-9_-]{1,64})"\s*$', block)
        version_matches = re.findall(r'(?m)^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?)"\s*$', block)
        dependency_blocks = re.findall(r"(?ms)^dependencies\s*=\s*\[\n(.*?)^\]$", block)
        if len(name_matches) != 1 or len(version_matches) != 1 or len(dependency_blocks) > 1:
            return False
        name = name_matches[0]
        dependencies_in_lock = []
        if dependency_blocks:
            dependencies_in_lock = re.findall(r'^\s*"([A-Za-z0-9_-]{1,64})",\s*$', dependency_blocks[0], re.M)
            normalized = re.sub(r'^\s*"[A-Za-z0-9_-]{1,64}",\s*$', "", dependency_blocks[0], flags=re.M)
            if normalized.strip():
                return False
        allowed_lines = re.sub(comment_line, "", block)
        allowed_lines = re.sub(r'(?m)^name\s*=\s*"[A-Za-z0-9_-]{1,64}"\s*$', "", allowed_lines)
        allowed_lines = re.sub(r'(?m)^version\s*=\s*"[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9.-]+)?"\s*$', "", allowed_lines)
        allowed_lines = re.sub(r"(?ms)^dependencies\s*=\s*\[\n.*?^\]$", "", allowed_lines)
        if allowed_lines.strip() or name in parsed_lock:
            return False
        parsed_lock[name] = dependencies_in_lock
    return parsed_lock == {fuzz_name: [api_name], api_name: []}


def _feedback_fuzz_modules_shape(main_payload, target_names):
    if (type(main_payload) is not bytes or len(main_payload) > MAX_CORE_CONTRACT_FILE_BYTES
            or type(target_names) not in (set, frozenset)
            or not CORE_CONTRACT_FUZZ_CORPUS_TARGETS.issubset(target_names)
            or len(target_names) > MAX_CORE_CONTRACT_FUZZ_TARGETS
            or any(type(name) is not str or len(name) > MAX_CORE_CONTRACT_NAME_LENGTH
                   or CORE_CONTRACT_SNAKE_NAME_PATTERN.fullmatch(name) is None
                   for name in target_names)):
        return False
    try:
        text = main_payload.decode("utf-8", "strict")
    except UnicodeDecodeError:
        return False
    raw_string = re.compile(r"\b(?:b|c)?r" + re.escape(chr(35)) + r'*"')
    char_quote = "'"
    if ("\r" in text or "/*" in text or "include" in text or "macro_rules" in text
            or raw_string.search(text)
            or char_quote + '"' + char_quote in text
            or char_quote + "\\" + '"' + char_quote in text):
        return False
    quoted = False
    escaped = False
    for character in text:
        if quoted:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                quoted = False
            elif character == "\n":
                return False
        elif character == '"':
            quoted = True
    if quoted:
        return False
    module = re.compile(r"^\s*(?:pub(?:\([^)]*\))?\s+)?mod\b")
    declared = set()
    references = set()
    reference_patterns = {
        name: re.compile(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"::fuzz(?![A-Za-z0-9_])")
        for name in target_names
    }
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        code = re.sub(r'"(?:\\.|[^"\\])*"', '""', line).split("//", 1)[0]
        if chr(35) in code:
            if index + 1 >= len(lines):
                return False
            match = re.fullmatch(
                re.escape(chr(35)) + r'\[path = "\.\./fuzz_targets/([a-z][a-z0-9]*(?:_[a-z0-9]+)*)\.rs"\]',
                line,
            )
            if match is None:
                return False
            name = match.group(1)
            if (name not in target_names or name in declared
                    or lines[index + 1] != "mod " + name + ";"):
                return False
            declared.add(name)
            index += 2
            continue
        if module.match(line):
            return False
        for name in target_names - references:
            if reference_patterns[name].search(code):
                references.add(name)
        index += 1
    return declared == references == set(target_names)


def _feedback_corpus_paths_shape(corpus_paths, target_names=None):
    if target_names is None:
        target_names = CORE_CONTRACT_FUZZ_CORPUS_TARGETS
    if (type(target_names) not in (set, frozenset)
            or not CORE_CONTRACT_FUZZ_CORPUS_TARGETS.issubset(target_names)
            or any(type(name) is not str or len(name) > MAX_CORE_CONTRACT_NAME_LENGTH
                   or CORE_CONTRACT_SNAKE_NAME_PATTERN.fullmatch(name) is None
                   for name in target_names)):
        return False
    if (type(corpus_paths) is not list or not 1 <= len(corpus_paths) <= MAX_FUZZ_CORPUS_FILES
            or any(type(path) is not str for path in corpus_paths)
            or len(set(corpus_paths)) != len(corpus_paths)):
        return False
    targets = set()
    for path in corpus_paths:
        match = CORE_CONTRACT_FUZZ_CORPUS_PATH.fullmatch(path)
        if match is None:
            return False
        targets.add(match.group(1))
    return CORE_CONTRACT_FUZZ_CORPUS_TARGETS.issubset(targets) and targets.issubset(target_names)


def _feedback_corpus_shape(corpus_paths, payloads, target_names=None):
    if (not _feedback_corpus_paths_shape(corpus_paths, target_names)
            or type(payloads) is not dict or set(payloads) != set(corpus_paths)):
        return False
    total_bytes = 0
    for path in corpus_paths:
        payload = payloads[path]
        if type(payload) is not bytes or len(payload) > MAX_FUZZ_CORPUS_FILE_BYTES:
            return False
        try:
            payload.decode("utf-8", "strict")
        except UnicodeDecodeError:
            return False
        total_bytes += len(payload)
        if total_bytes > MAX_FUZZ_CORPUS_TOTAL_BYTES:
            return False
    return True


def _core_contract_admin_mode(path):
    root_files = {".gitignore", "AGENTS.md", "CLAUDE.md", "README.md"}
    known_paths = {
        RULES_LOCK_PATH,
        RULES_DIRECTORY + "/settings.json",
        "/".join(SIGNER_PATH_PARTS),
    }
    if path in root_files or path in known_paths or path in CORE_CONTRACT_RUST_POLICY_FILES:
        return "100644"
    if path.startswith(RULES_DIRECTORY + "/rules/shared/") and path.endswith(".md"):
        return "100644"
    if path.startswith(RULES_DIRECTORY + "/hooks/shared/") and path.endswith(".sh"):
        return "100755"
    return None


def _core_contract_foundation_path(path):
    return (
        type(path) is str
        and (
            path in CORE_CONTRACT_FEEDBACK_FILES
            or path in CORE_CONTRACT_FOUNDATION_FILES
            or path in CORE_CONTRACT_KERNEL_FEEDBACK_FILES
            or _core_contract_ts_source_name(path) is not None
            or _core_contract_ts_test_name(path) is not None
            or _core_contract_adr_parts(path) is not None
            or _core_contract_fuzz_target_name(path) is not None
            or CORE_CONTRACT_FUZZ_CORPUS_PATH.fullmatch(path) is not None
        )
    )


def _core_contract_workspace_members(workspace_text):
    arrays = CORE_CONTRACT_WORKSPACE_MEMBERS_PATTERN.findall(workspace_text)
    if len(arrays) != 1:
        return None
    body = arrays[0]
    members = []
    position = 0
    while True:
        match = CORE_CONTRACT_WORKSPACE_MEMBER_PATTERN.match(body, position)
        if match is None:
            break
        members.append(match.group(1))
        position = match.end()
    if body[position:].strip():
        return None
    return members


def _core_contract_crate_manifest_shape(text, *, crate_root=None, require_first_batch=False):
    if type(text) is not str or "\r" in text or "\x00" in text:
        return False
    section = None
    keys = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(chr(35)):
            continue
        header = CORE_CONTRACT_MANIFEST_SECTION_PATTERN.fullmatch(stripped)
        if header is not None:
            section = header.group(1)
            if section not in CORE_CONTRACT_MANIFEST_SECTIONS or section in keys:
                return False
            keys[section] = set()
            continue
        assignment = CORE_CONTRACT_MANIFEST_ASSIGNMENT_PATTERN.fullmatch(stripped)
        if section is None or assignment is None:
            return False
        key, value = assignment.group(1), assignment.group(2).strip()
        if key in keys[section]:
            return False
        keys[section].add(key)
        if section == "package":
            if key == "name":
                expected_name = CORE_CONTRACT_CRATE_NAMES.get(crate_root)
                valid = (
                    CORE_CONTRACT_MANIFEST_NAME_PATTERN.fullmatch(value) is not None
                    and (expected_name is None or value == '"' + expected_name + '"')
                )
            elif key == "description":
                valid = CORE_CONTRACT_MANIFEST_TEXT_PATTERN.fullmatch(value) is not None
            elif key in CORE_CONTRACT_MANIFEST_INHERITED_KEYS:
                valid = value == "true"
            else:
                valid = False
        elif section == "dependencies":
            valid = (
                key in CORE_CONTRACT_MANIFEST_DEPENDENCIES
                and CORE_CONTRACT_MANIFEST_WORKSPACE_VALUE_PATTERN.fullmatch(value) is not None
            ) or (
                crate_root == CORE_CONTRACT_CRATE_ROOTS[0]
                and key in CORE_CONTRACT_MANIFEST_EXTERNAL_DEPENDENCIES
                and CORE_CONTRACT_MANIFEST_EXTERNAL_DEPENDENCIES[key].fullmatch(value) is not None
            )
        elif section == "dev-dependencies":
            valid = (
                key in CORE_CONTRACT_MANIFEST_DEPENDENCIES
                and CORE_CONTRACT_MANIFEST_WORKSPACE_VALUE_PATTERN.fullmatch(value) is not None
            )
        else:
            valid = key == "workspace" and value == "true"
        if not valid:
            return False
    if "package" not in keys or "name" not in keys["package"]:
        return False
    if crate_root == CORE_CONTRACT_CRATE_ROOTS[0] and require_first_batch:
        return (
            keys.get("dependencies") == set(CORE_CONTRACT_MANIFEST_EXTERNAL_DEPENDENCIES)
            and "dev-dependencies" not in keys
        )
    return True


def _core_contract_workspace_paths_shape(workspace_text):
    if type(workspace_text) is not str or "\r" in workspace_text or "\x00" in workspace_text:
        return False
    section = None
    seen = {}
    open_array = False
    for line in workspace_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(chr(35)):
            continue
        if open_array:
            if stripped == "]":
                open_array = False
            elif CORE_CONTRACT_ROOT_ARRAY_LINE_PATTERN.fullmatch(stripped) is None:
                return False
            continue
        if stripped.startswith("["):
            if stripped not in CORE_CONTRACT_ROOT_KEYS or stripped in seen:
                return False
            section = stripped
            seen[section] = set()
            continue
        assignment = CORE_CONTRACT_ROOT_ASSIGNMENT_PATTERN.fullmatch(stripped)
        if section is None or assignment is None:
            return False
        key, value = assignment.group(1), assignment.group(2)
        shape = CORE_CONTRACT_ROOT_KEYS[section].get(key)
        if shape is None or key in seen[section]:
            return False
        seen[section].add(key)
        if shape is CORE_CONTRACT_ROOT_ARRAY_PATTERN and value == "[":
            open_array = True
        elif shape.fullmatch(value) is None:
            return False
    return not open_array and "members" in seen.get("[workspace]", ())


def _core_contract_path_name(path, pattern):
    if type(path) is not str:
        return None
    match = pattern.fullmatch(path)
    if match is None:
        return None
    name = match.group(1)
    return name if len(name) <= MAX_CORE_CONTRACT_NAME_LENGTH else None


def _core_contract_ts_source_name(path):
    return _core_contract_path_name(path, CORE_CONTRACT_TS_SOURCE_PATH_PATTERN)


def _core_contract_ts_test_name(path):
    return _core_contract_path_name(path, CORE_CONTRACT_TS_TEST_PATH_PATTERN)


def _core_contract_adr_parts(path):
    if type(path) is not str:
        return None
    match = CORE_CONTRACT_ADR_PATH_PATTERN.fullmatch(path)
    if match is None or len(match.group(2)) > MAX_CORE_CONTRACT_NAME_LENGTH:
        return None
    return match.group(1), match.group(2)


def _core_contract_fuzz_target_name(path):
    return _core_contract_path_name(path, CORE_CONTRACT_FUZZ_TARGET_PATH_PATTERN)


def _core_contract_pattern_paths(entries):
    return {
        "ts_sources": {
            path for path in entries if _core_contract_ts_source_name(path) is not None
        },
        "ts_tests": {
            path for path in entries if _core_contract_ts_test_name(path) is not None
        },
        "adrs": {
            path for path in entries if _core_contract_adr_parts(path) is not None
        },
        "fuzz_targets": {
            path for path in entries if _core_contract_fuzz_target_name(path) is not None
        },
    }


def _core_contract_package_mode(path, *, feedback_profile=False):
    package_files = CORE_CONTRACT_PACKAGE_FILES
    for crate_root in CORE_CONTRACT_CRATE_ROOTS:
        prefix = "/".join(crate_root)
        if path.startswith(prefix + "/"):
            relative = path[len(prefix) + 1:]
            if relative in package_files:
                return "100644"
            if (
                relative.startswith(("src/", "tests/"))
                and relative.endswith(".rs")
                and relative.rsplit("/", 1)[-1] != "build.rs"
            ):
                return "100644"
    if feedback_profile and _core_contract_foundation_path(path):
        return "100644"
    return None


def _core_contract_expected_mode(path, *, concern="core-contract"):
    if type(concern) is not str or concern not in CORE_CONTRACT_CONCERNS:
        return None
    if path == CORE_CONTRACT_PACKAGE_LOCK_PATH:
        return "100644" if concern in CORE_CONTRACT_PACKAGE_LOCK_CONCERNS else None
    if path in CORE_CONTRACT_ROOT_FILES:
        return "100644"
    admin_mode = _core_contract_admin_mode(path)
    if admin_mode is not None:
        return admin_mode
    return _core_contract_package_mode(
        path, feedback_profile=concern in FEEDBACK_PROFILE_CONCERNS,
    )


def _runtime_member_listing(crate_roots):
    return [
        posixpath.relpath("/".join(root), RUNTIME_WORKSPACE_DIRECTORY) for root in crate_roots
    ]


def _runtime_root_admitted(root):
    return (
        type(root) is tuple and len(root) == len(RUNTIME_CRATES_DIRECTORY) + 2
        and root[:len(RUNTIME_CRATES_DIRECTORY)] == RUNTIME_CRATES_DIRECTORY
        and all(
            type(part) is str and RUNTIME_PART_PATTERN.fullmatch(part) is not None
            for part in root[len(RUNTIME_CRATES_DIRECTORY):]
        )
    )


def _runtime_workspace_path(path):
    return type(path) is str and (
        path == RUNTIME_WORKSPACE_DIRECTORY or path.startswith(RUNTIME_WORKSPACE_DIRECTORY + "/")
    )


def _runtime_workspace_present(entries):
    return any(path in entries for path in RUNTIME_ROOT_FILES)


def _runtime_workspace_mode(path, crate_roots):
    if path in RUNTIME_ROOT_FILES or path in (
        RUNTIME_WORKSPACE_DIRECTORY + "/" + name for name in RUNTIME_CONFIG_FILES
    ):
        return "100644"
    for root in crate_roots:
        prefix = "/".join(root)
        if path.startswith(prefix + "/"):
            relative = path[len(prefix) + 1:]
            if relative == "Cargo.toml":
                return "100644"
            if (
                relative.startswith(("src/", "tests/"))
                and relative.endswith(".rs")
                and relative.rsplit("/", 1)[-1] != "build.rs"
            ):
                return "100644"
    return None


def _runtime_workspace_members(workspace_text):
    arrays = RUNTIME_MEMBERS_PATTERN.findall(workspace_text)
    if len(arrays) != 1:
        return None
    body = arrays[0]
    members = []
    position = 0
    while True:
        match = RUNTIME_MEMBER_PATTERN.match(body, position)
        if match is None:
            break
        members.append(match.group(1))
        position = match.end()
    if body[position:].strip():
        return None
    return members


def _runtime_root_manifest_shape(text, crate_roots):
    if type(text) is not str or "\r" in text or "\x00" in text or ".." in text:
        return False
    expected = _runtime_member_listing(crate_roots)
    if _runtime_workspace_members(text) != expected:
        return False
    section = None
    seen = {}
    in_members = False
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(chr(35)):
            continue
        if in_members:
            if "]" in stripped:
                in_members = False
            continue
        if stripped.startswith("["):
            if stripped not in RUNTIME_ROOT_SECTIONS or stripped in seen:
                return False
            section = stripped
            seen[section] = set()
            continue
        assignment = RUNTIME_ASSIGNMENT_PATTERN.fullmatch(stripped)
        if section is None or assignment is None:
            return False
        key, value = assignment.group(1), assignment.group(2).strip()
        if key in seen[section]:
            return False
        seen[section].add(key)
        if section == "[workspace]":
            if key == "resolver":
                valid = value == '"3"'
            elif key == "members":
                valid = True
                in_members = "]" not in value
            else:
                valid = False
        elif section == "[workspace.package]":
            pattern = RUNTIME_ROOT_PACKAGE_VALUES.get(key)
            valid = pattern is not None and pattern.fullmatch(value) is not None
        elif section == "[workspace.dependencies]":
            match = RUNTIME_ROOT_PATH_PATTERN.fullmatch(value)
            valid = (
                RUNTIME_DEPENDENCY_NAME_PATTERN.fullmatch(key) is not None
                and match is not None and match.group(1) in expected
            )
        else:
            valid = (
                RUNTIME_LINT_KEY_PATTERN.fullmatch(key) is not None
                and RUNTIME_LINT_VALUE_PATTERN.fullmatch(value) is not None
            )
        if not valid:
            return False
    return seen.get("[workspace]") == {"resolver", "members"}


def _runtime_declared_dependencies(text):
    names = set()
    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_section = stripped == "[workspace.dependencies]"
            continue
        if in_section and stripped and not stripped.startswith(chr(35)):
            names.add(stripped.split("=", 1)[0].strip())
    return names


def _runtime_crate_manifest_name(text, declared):
    if type(text) is not str or "\r" in text or "\x00" in text or ".." in text:
        return None
    section = None
    keys = {}
    name = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith(chr(35)):
            continue
        header = RUNTIME_SECTION_PATTERN.fullmatch(stripped)
        if header is not None:
            section = header.group(1)
            if section not in RUNTIME_MANIFEST_SECTIONS or section in keys:
                return None
            keys[section] = set()
            continue
        assignment = RUNTIME_ASSIGNMENT_PATTERN.fullmatch(stripped)
        if section is None or assignment is None:
            return None
        key, value = assignment.group(1), assignment.group(2).strip()
        if key in keys[section]:
            return None
        keys[section].add(key)
        if section == "package":
            if key == "name":
                match = RUNTIME_PACKAGE_NAME_PATTERN.fullmatch(value)
                valid = match is not None
                name = match.group(1) if match is not None else None
            elif key == "description":
                valid = RUNTIME_TEXT_PATTERN.fullmatch(value) is not None
            elif key in RUNTIME_MANIFEST_INHERITED_KEYS:
                valid = value == "true"
            else:
                valid = False
        elif section in ("dependencies", "dev-dependencies"):
            valid = (
                key in declared
                and RUNTIME_WORKSPACE_VALUE_PATTERN.fullmatch(value) is not None
            )
        else:
            valid = key == "workspace" and value == "true"
        if not valid:
            return None
    package = keys.get("package")
    if (
        name is None or package is None
        or not (RUNTIME_MANIFEST_INHERITED_KEYS | {"name"}).issubset(package)
    ):
        return None
    return name


def _runtime_lock_package_names(text):
    if type(text) is not str or "\r" in text or "\x00" in text:
        return None
    packages = []
    top_version = False
    in_dependencies = False
    for line in text.split("\n"):
        if in_dependencies:
            if line == "]":
                in_dependencies = False
                continue
            match = RUNTIME_LOCK_DEPENDENCY_PATTERN.fullmatch(line)
            if match is None:
                return None
            packages[-1]["dependencies"].append(match.group(1))
            continue
        if not line or line.startswith(chr(35)):
            continue
        if line == "[[package]]":
            packages.append({"name": None, "version": None, "dependencies": [], "listed": False})
            continue
        if not packages:
            if line == "version = 4" and not top_version:
                top_version = True
                continue
            return None
        current = packages[-1]
        name_match = RUNTIME_LOCK_NAME_PATTERN.fullmatch(line)
        if name_match is not None and current["name"] is None:
            current["name"] = name_match.group(1)
        elif RUNTIME_LOCK_VERSION_PATTERN.fullmatch(line) is not None and current["version"] is None:
            current["version"] = line
        elif line == "dependencies = [" and not current["listed"]:
            current["listed"] = True
            in_dependencies = True
        else:
            return None
    if in_dependencies or not top_version or len(packages) > MAX_RUNTIME_MEMBERS:
        return None
    names = [package["name"] for package in packages]
    if (
        any(package["name"] is None or package["version"] is None for package in packages)
        or len(set(names)) != len(names)
        or any(dependency not in names for package in packages for dependency in package["dependencies"])
    ):
        return None
    return set(names)


def _check_runtime_workspace(repository, git_executable, repo_env, entries):
    crate_roots = RUNTIME_CRATE_ROOTS
    if (
        type(crate_roots) is not tuple or len(crate_roots) > MAX_RUNTIME_MEMBERS
        or len(set(crate_roots)) != len(crate_roots)
        or any(not _runtime_root_admitted(root) for root in crate_roots)
    ):
        raise Refusal("bootstrap_not_approved", "configuration")
    required = set(RUNTIME_ROOT_FILES)
    for root in crate_roots:
        prefix = "/".join(root)
        required.add(prefix + "/Cargo.toml")
        if prefix + "/src/lib.rs" not in entries and prefix + "/src/main.rs" not in entries:
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="required_files")
    if not required.issubset(entries):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="required_files")
    for path, (mode, unused_object_id) in entries.items():
        if _runtime_workspace_path(path) and (
            mode != "100644" or _runtime_workspace_mode(path, crate_roots) != "100644"
            or _core_contract_expected_mode(path, concern="core-contract") is not None
        ):
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="path_mode")
    toolchain_path = RUNTIME_WORKSPACE_DIRECTORY + "/rust-toolchain.toml"
    if toolchain_path in entries and _contract_blob(
        repository, git_executable, repo_env, entries, toolchain_path, core_check="toolchain",
    ) != CORE_CONTRACT_TOOLCHAIN:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="toolchain")
    for name in RUNTIME_CONFIG_FILES[1:]:
        path = RUNTIME_WORKSPACE_DIRECTORY + "/" + name
        if path in entries and _contract_blob(
            repository, git_executable, repo_env, entries, path, core_check="package_decode",
        ) != _contract_blob(
            repository, git_executable, repo_env, entries, name, core_check="package_decode",
        ):
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="package_decode")
    root_payload = _contract_blob(
        repository, git_executable, repo_env, entries, RUNTIME_ROOT_MANIFEST_PATH,
        core_check="workspace_decode",
    )
    try:
        root_text = root_payload.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="workspace_decode") from None
    if not _runtime_root_manifest_shape(root_text, crate_roots):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="workspace_members")
    declared = _runtime_declared_dependencies(root_text)
    names = []
    for root in crate_roots:
        payload = _contract_blob(
            repository, git_executable, repo_env, entries, "/".join(root) + "/Cargo.toml",
            core_check="package_decode",
        )
        try:
            manifest_text = payload.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="package_decode") from None
        name = _runtime_crate_manifest_name(manifest_text, declared)
        if name is None:
            raise Refusal(
                "bootstrap_snapshot_invalid", "bootstrap",
                core_check="package_build" if "build" in manifest_text else "package_decode",
            )
        names.append(name)
    if len(set(names)) != len(names):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="package_decode")
    lock_payload = _contract_blob(
        repository, git_executable, repo_env, entries, RUNTIME_ROOT_LOCK_PATH,
        core_check="cargo_lock_decode",
    )
    try:
        lock_text = lock_payload.decode("ascii", "strict")
    except UnicodeDecodeError:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="cargo_lock_decode") from None
    if _runtime_lock_package_names(lock_text) != set(names):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="cargo_lock_shape")


def _parse_rules_file_manifest(payload):
    try:
        text = payload.decode("ascii", "strict")
        lines = text.splitlines()
    except (AttributeError, UnicodeDecodeError):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap") from None
    if b"\r" in payload or not payload.endswith(b"\n"):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
    for required in ("format 3", "profile full", "signature verified"):
        if lines.count(required) != 1:
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
    tags = [line for line in lines if line.startswith("tag ")]
    if len(tags) != 1 or CORE_CONTRACT_RULES_TAG_PATTERN.fullmatch(tags[0]) is None:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
    files = {}
    folded = set()
    rules_prefix = RULES_DIRECTORY + "/rules/shared/"
    hooks_prefix = RULES_DIRECTORY + "/hooks/shared/"
    for line in lines:
        if not line.startswith("file "):
            continue
        fields = line.split(" ")
        if len(fields) != 3:
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
        path, digest = fields[1], fields[2]
        allowed = (
            path == "AGENTS.md"
            or path.startswith(rules_prefix) and path.endswith(".md")
            or path.startswith(hooks_prefix) and path.endswith(".sh")
        )
        if (
            not allowed
            or re.fullmatch(r"[a-f0-9]{64}", digest) is None
            or path.casefold() in folded
        ):
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
        files[path] = digest
        folded.add(path.casefold())
    if (
        "AGENTS.md" not in files
        or not any(path.startswith(rules_prefix) for path in files)
        or not any(path.startswith(hooks_prefix) for path in files)
    ):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
    return files


def _rules_file_manifest(payload):
    try:
        return _parse_rules_file_manifest(payload)
    except Refusal as error:
        if error.reason == "bootstrap_snapshot_invalid" and error.stage == "bootstrap":
            raise Refusal(error.reason, error.stage, core_check="rules_manifest") from None
        raise


def _core_contract_policy_matches_base(base_entries, entries):
    signer_path = "/".join(SIGNER_PATH_PARTS)
    policy_paths = {
        path: entry for path, entry in entries.items()
        if path == "AGENTS.md" or path == signer_path or path.startswith(RULES_DIRECTORY + "/")
    }
    base_policy_paths = {
        path: entry for path, entry in base_entries.items()
        if path == "AGENTS.md" or path == signer_path or path.startswith(RULES_DIRECTORY + "/")
    }
    if policy_paths == base_policy_paths:
        return True
    if (
        base_policy_paths.get(RULES_LOCK_PATH) != ("100644", CORE_CONTRACT_RULES_V2_LOCK_OBJECT)
        or policy_paths.get(RULES_LOCK_PATH) != ("100644", CORE_CONTRACT_RULES_V3_LOCK_OBJECT)
        or base_policy_paths.get(signer_path) != policy_paths.get(signer_path)
    ):
        return False
    changed_paths = {
        path for path in set(base_policy_paths) | set(policy_paths)
        if base_policy_paths.get(path) != policy_paths.get(path)
    }
    return changed_paths == CORE_CONTRACT_RULES_V3_CHANGED_PATHS


def _core_contract_rust_policy_matches(entries):
    present = CORE_CONTRACT_RUST_POLICY_FILES.intersection(entries)
    if not present:
        return True
    if present != CORE_CONTRACT_RUST_POLICY_FILES:
        return False
    return all(
        entries[path] == ("100644", object_id)
        for path, object_id in CORE_CONTRACT_RUST_POLICY_OBJECTS.items()
    )


def _safe_core_contract_tree(
    repository, git_executable, repo_env, base_commit, commit, *, concern="core-contract",
):
    if type(concern) is not str or concern not in CORE_CONTRACT_CONCERNS:
        raise Refusal("bootstrap_not_approved", "configuration")
    base_entries = _contract_tree_entries(repository, git_executable, repo_env, base_commit)
    entries = _contract_tree_entries(repository, git_executable, repo_env, commit)
    signer_path = "/".join(SIGNER_PATH_PARTS)
    required = {
        ".gitignore", "AGENTS.md", "CLAUDE.md", "README.md", RULES_LOCK_PATH,
        RULES_DIRECTORY + "/settings.json", signer_path,
    } | set(CORE_CONTRACT_ROOT_FILES)
    if concern == "core-rust-lock-return":
        required.update(CORE_CONTRACT_RUST_POLICY_FILES)
    for crate_root in CORE_CONTRACT_CRATE_ROOTS:
        prefix = "/".join(crate_root)
        required.update(prefix + "/" + path for path in CORE_CONTRACT_PACKAGE_FILES)
        required.add(prefix + "/src/lib.rs")
    if not required.issubset(entries):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="required_files")
    if (concern == "core-rust-lock-return"
            and entries.get("Cargo.lock") != ("100644", CORE_CONTRACT_RUST_BOOTSTRAP_LOCK_OBJECT)):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="cargo_lock_shape")
    foundation_present = any(
        _core_contract_foundation_path(path)
        for path in entries
        if path not in CORE_CONTRACT_ROOT_FILES
    )
    package_lock_present = CORE_CONTRACT_PACKAGE_LOCK_PATH in entries
    if (concern in CORE_CONTRACT_PACKAGE_LOCK_CONCERNS and package_lock_present
            and not foundation_present):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="required_files")
    if concern == "core-node-lock-return" and not foundation_present:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="required_files")
    if foundation_present:
        if concern not in FEEDBACK_PROFILE_CONCERNS:
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="path_mode")
        if not CORE_CONTRACT_FEEDBACK_FILES.issubset(entries) or not CORE_CONTRACT_FOUNDATION_FILES.issubset(entries):
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="required_files")
        pattern_paths = _core_contract_pattern_paths(entries)
        pattern_limits = (
            ("ts_sources", MAX_CORE_CONTRACT_TS_SOURCES),
            ("ts_tests", MAX_CORE_CONTRACT_TS_TESTS),
            ("adrs", MAX_CORE_CONTRACT_ADRS),
            ("fuzz_targets", MAX_CORE_CONTRACT_FUZZ_TARGETS),
        )
        if any(len(pattern_paths[name]) > maximum for name, maximum in pattern_limits):
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="tree_entries")
        adr_numbers = [
            _core_contract_adr_parts(path)[0] for path in pattern_paths["adrs"]
        ]
        if len(adr_numbers) != len(set(adr_numbers)):
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="tree_entries")
        baseline_pattern_paths = set(CORE_CONTRACT_FEEDBACK_FILES) | set(CORE_CONTRACT_FOUNDATION_FILES)
        pattern_total_bytes = 0
        for path in sorted(set().union(*pattern_paths.values()) - baseline_pattern_paths):
            pattern_total_bytes += _contract_blob_size(
                repository, git_executable, repo_env, entries, path,
                core_check="tree_entries",
            )
            if pattern_total_bytes > MAX_CORE_CONTRACT_PATTERN_TOTAL_BYTES:
                raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="tree_entries")
        target_names = {
            _core_contract_fuzz_target_name(path) for path in pattern_paths["fuzz_targets"]
        }
        corpus_paths = []
        for path in entries:
            if path.startswith("fuzz/corpus/"):
                if (CORE_CONTRACT_FUZZ_CORPUS_PATH.fullmatch(path) is None
                        or len(corpus_paths) >= MAX_FUZZ_CORPUS_FILES):
                    raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="tree_entries")
                corpus_paths.append(path)
        if not _feedback_corpus_paths_shape(corpus_paths, target_names):
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="tree_entries")
        corpus_payloads = {}
        corpus_total_bytes = 0
        for path in corpus_paths:
            payload = _contract_blob(
                repository, git_executable, repo_env, entries, path,
                core_check="tree_entries", max_bytes=MAX_FUZZ_CORPUS_FILE_BYTES,
            )
            corpus_total_bytes += len(payload)
            if corpus_total_bytes > MAX_FUZZ_CORPUS_TOTAL_BYTES:
                raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="tree_entries")
            try:
                payload.decode("utf-8", "strict")
            except UnicodeDecodeError:
                raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="tree_entries") from None
            corpus_payloads[path] = payload
        if not _feedback_corpus_shape(corpus_paths, corpus_payloads, target_names):
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="tree_entries")
        root_package = _contract_blob(
            repository, git_executable, repo_env, entries, "package.json", core_check="package_decode",
        )
        host_package = _contract_blob(
            repository, git_executable, repo_env, entries,
            "packages/host-api/package.json", core_check="package_decode",
        )
        if not _feedback_manifest_shape(root_package, host_package):
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="package_decode")
        fuzz_manifest = _contract_blob(
            repository, git_executable, repo_env, entries, "fuzz/Cargo.toml", core_check="package_decode",
        )
        fuzz_lock = _contract_blob(
            repository, git_executable, repo_env, entries, "fuzz/Cargo.lock", core_check="package_decode",
        )
        api_cargo = _contract_blob(
            repository, git_executable, repo_env, entries,
            "/".join(CORE_CONTRACT_CRATE_ROOTS[0]) + "/Cargo.toml", core_check="package_decode",
        )
        if not _feedback_fuzz_manifest_shape(fuzz_manifest, api_cargo, fuzz_lock):
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="package_decode")
        fuzz_main = _contract_blob(
            repository, git_executable, repo_env, entries, "fuzz/src/main.rs",
            core_check="package_decode",
        )
        if not _feedback_fuzz_modules_shape(fuzz_main, target_names):
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="package_decode")
        if concern in CORE_CONTRACT_PACKAGE_LOCK_CONCERNS and package_lock_present:
            if entries[CORE_CONTRACT_PACKAGE_LOCK_PATH][0] != "100644":
                raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="path_mode")
            package_lock = _contract_blob(
                repository, git_executable, repo_env, entries, CORE_CONTRACT_PACKAGE_LOCK_PATH,
                core_check="package_decode", max_bytes=MAX_FEEDBACK_LOCK_BYTES,
            )
            if not package_lock:
                raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="package_decode")
    runtime_present = _runtime_workspace_present(entries)
    for path, (mode, unused_object_id) in entries.items():
        if runtime_present and _runtime_workspace_path(path):
            continue
        expected_mode = _core_contract_expected_mode(path, concern=concern)
        if mode != expected_mode or expected_mode is None:
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="path_mode")
    if not _core_contract_rust_policy_matches(entries):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="package_decode")
    if not _core_contract_policy_matches_base(base_entries, entries):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="base_policy")

    lock_payload = _contract_blob(
        repository, git_executable, repo_env, entries, RULES_LOCK_PATH,
        core_check="rules_manifest",
    )
    manifest = _rules_file_manifest(lock_payload)
    installed_paths = {
        path for path in entries
        if path == "AGENTS.md"
        or path.startswith(RULES_DIRECTORY + "/rules/shared/")
        or path.startswith(RULES_DIRECTORY + "/hooks/shared/")
    }
    if installed_paths != set(manifest):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="rules_inventory")
    total_rules_bytes = 0
    for path, expected_hash in manifest.items():
        payload = _contract_blob(
            repository, git_executable, repo_env, entries, path,
            core_check="rules_hash",
        )
        total_rules_bytes += len(payload)
        if total_rules_bytes > MAX_TREE_BYTES or hashlib.sha256(payload).hexdigest() != expected_hash:
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="rules_hash")
    workspace = _contract_blob(
        repository, git_executable, repo_env, entries, "Cargo.toml",
        core_check="workspace_decode",
    )
    try:
        workspace_text = workspace.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="workspace_decode") from None
    if _core_contract_workspace_members(workspace_text) != [
        "/".join(root) for root in CORE_CONTRACT_CRATE_ROOTS
    ]:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="workspace_members")
    if not _core_contract_workspace_paths_shape(workspace_text):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="workspace_members")

    lock_text = _contract_blob(
        repository, git_executable, repo_env, entries, "Cargo.lock",
        core_check="cargo_lock_decode",
    )
    try:
        lock_text = lock_text.decode("utf-8", "strict")
    except UnicodeDecodeError:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="cargo_lock_decode") from None
    if (
        re.search(r"(?m)^version\s*=\s*4\s*$", lock_text) is None
        or len(re.findall(r"(?m)^\[\[package\]\]$", lock_text)) != len(CORE_CONTRACT_CRATE_ROOTS)
        or re.search(r"(?m)^\s*source\s*=", lock_text) is not None
    ):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="cargo_lock_shape")
    if _contract_blob(
        repository, git_executable, repo_env, entries, "rust-toolchain.toml",
        core_check="toolchain",
    ) != CORE_CONTRACT_TOOLCHAIN:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="toolchain")
    for crate_root in CORE_CONTRACT_CRATE_ROOTS:
        payload = _contract_blob(
            repository, git_executable, repo_env, entries, "/".join(crate_root) + "/Cargo.toml",
            core_check="package_decode",
        )
        try:
            manifest_text = payload.decode("utf-8", "strict")
        except UnicodeDecodeError:
            raise Refusal("bootstrap_snapshot_invalid", "bootstrap", core_check="package_decode") from None
        if not _core_contract_crate_manifest_shape(
            manifest_text,
            crate_root=crate_root,
            require_first_batch=concern == "core-rust-lock-return",
        ):
            raise Refusal(
                "bootstrap_snapshot_invalid", "bootstrap",
                core_check="package_build" if "build" in manifest_text else "package_decode",
            )
    if runtime_present:
        _check_runtime_workspace(repository, git_executable, repo_env, entries)
    tree_kind = CORE_CONTRACT_TREE_BY_CONCERN[concern]
    if concern == "core-build-diagnostic-return" and package_lock_present:
        tree_kind = CORE_CONTRACT_PACKAGE_LOCK_TREE
    return tree_kind


LEASE_ACCESS_SCRIPT = '''\
import errno
import os
import sys

uid = int(sys.argv[1])
root, source, signer = sys.argv[2:]
if os.getuid() != uid or os.geteuid() != uid:
    raise SystemExit(20)
if not os.listdir(source):
    raise SystemExit(21)
with open(signer, "rb") as stream:
    stream.read(1)

def denied(action):
    try:
        action()
    except OSError as error:
        if error.errno in (errno.EACCES, errno.EPERM):
            return
    raise SystemExit(22)

denied(lambda: open(signer, "ab").close())
denied(lambda: os.mkdir(os.path.join(root, "lease-write-probe"), 0o700))
os.write(1, b"KD-MPV:lease-acl=verified\\n")
'''


LEASE_ACL_MARKER = b"KD-MPV:lease-acl=verified\n"
MAX_TEMP_PATHS = 100000


def _run_acl_command(chmod_executable, arguments):
    result = _run_process(
        (chmod_executable, *arguments),
        cwd="/",
        environ={"PATH": "/bin:/usr/bin", "HOME": "/", "LANG": "C", "LC_ALL": "C"},
        timeout=15,
        stage="bootstrap",
    )
    if result.returncode != 0 or result.stderr or len(result.stdout) > MAX_GIT_OUTPUT:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap")


def _acl_entries(path, ls_executable):
    result = _run_process(
        (ls_executable, "-lde", str(path)),
        cwd="/",
        environ={"PATH": "/bin:/usr/bin", "HOME": "/", "LANG": "C", "LC_ALL": "C"},
        timeout=15,
        stage="bootstrap",
    )
    if result.returncode != 0 or result.stderr or len(result.stdout) > MAX_GIT_OUTPUT:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
    try:
        lines = result.stdout.decode("ascii").splitlines()
    except UnicodeDecodeError:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap") from None
    if not lines:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
    return lines[1:]


def _verify_acl_rule(path, ls_executable, username, rights):
    entries = _acl_entries(path, ls_executable)
    if len(entries) != 1:
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
    entry = entries[0]
    if not entry.startswith(" ") or entry.startswith("  "):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
    entry = entry[1:]
    prefix = "0: user:" + username + " allow "
    if not entry.startswith(prefix):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap")
    actual = entry[len(prefix):].split(",")
    if len(actual) != len(set(actual)) or set(actual) != set(rights):
        raise Refusal("bootstrap_snapshot_invalid", "bootstrap")


def _add_storage_search_acl(storage_root):
    added = False
    try:
        chmod = _resolve_trusted_executable("/bin/chmod")
        ls = _resolve_trusted_executable("/bin/ls")
        username = capability.USERNAME
        if _acl_entries(storage_root, ls):
            raise ValueError
        _run_acl_command(chmod, ["+a", username + " allow search", str(storage_root)])
        added = True
        _verify_acl_rule(storage_root, ls, username, ("search",))
    except Refusal:
        if added:
            try:
                _remove_storage_search_acl(storage_root)
            except BaseException:
                raise Refusal("cleanup_incomplete", "cleanup") from None
        raise
    except BaseException:
        if added:
            try:
                _remove_storage_search_acl(storage_root)
            except BaseException:
                raise Refusal("cleanup_incomplete", "cleanup") from None
        raise Refusal("bootstrap_not_approved", "configuration") from None


def _remove_storage_search_acl(storage_root):
    try:
        chmod = _resolve_trusted_executable("/bin/chmod")
        ls = _resolve_trusted_executable("/bin/ls")
        username = capability.USERNAME
        entries = _acl_entries(storage_root, ls)
        if entries:
            _verify_acl_rule(storage_root, ls, username, ("search",))
            _run_acl_command(chmod, ["-a", username + " allow search", str(storage_root)])
            if _acl_entries(storage_root, ls):
                raise ValueError
        info = storage_root.lstat()
        with os.scandir(storage_root) as entries:
            empty = next(entries, None) is None
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700
            or not empty
        ):
            raise ValueError
    except BaseException:
        raise Refusal("cleanup_incomplete", "cleanup") from None


def _lease_paths(temporary, *, core_contract=False):
    directories = [temporary]
    files = []
    count = 1
    try:
        for current, names, file_names in os.walk(temporary, topdown=True, followlinks=False):
            current_path = Path(current)
            for name in names:
                path = current_path / name
                info = path.lstat()
                if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
                    raise ValueError
                directories.append(path)
                count += 1
            for name in file_names:
                path = current_path / name
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
                    raise ValueError
                files.append((path, bool(info.st_mode & 0o111)))
                count += 1
            if count > MAX_TEMP_PATHS:
                raise Refusal(
                    "bootstrap_snapshot_invalid", "bootstrap",
                    core_check="lease_census" if core_contract else None,
                )
    except Refusal:
        raise
    except BaseException:
        raise Refusal(
            "bootstrap_snapshot_invalid", "bootstrap",
            core_check="lease_paths" if core_contract else None,
        ) from None
    return directories, files


def _grant_worker_readonly(temporary, source_path, storage_root, worker_uid, *, core_contract=False):
    check = "lease_paths"
    try:
        username = capability.USERNAME
        chmod = _resolve_trusted_executable("/bin/chmod")
        directories, files = _lease_paths(temporary, core_contract=core_contract)
        check = "lease_acl"
        directory_rule = username + " allow list,search,read,readattr,readextattr,readsecurity"
        file_rule = username + " allow read,readattr,readextattr,readsecurity"
        executable_rule = username + " allow read,execute,readattr,readextattr,readsecurity"
        for start in range(0, len(directories), 64):
            paths = [str(path) for path in directories[start:start + 64]]
            _run_acl_command(chmod, ["-N", *paths])
            _run_acl_command(chmod, ["700", *paths])
            _run_acl_command(chmod, ["+a", directory_rule, *paths])
        regular_files = [str(path) for path, executable in files if not executable]
        executable_files = [str(path) for path, executable in files if executable]
        for paths, mode, rule in (
            (regular_files, "600", file_rule),
            (executable_files, "700", executable_rule),
        ):
            for start in range(0, len(paths), 64):
                selected = paths[start:start + 64]
                _run_acl_command(chmod, ["-N", *selected])
                _run_acl_command(chmod, [mode, *selected])
                _run_acl_command(chmod, ["+a", rule, *selected])
        for path in directories:
            info = path.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
                raise ValueError
        for path, executable in files:
            info = path.lstat()
            expected_mode = 0o700 if executable else 0o600
            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != expected_mode:
                raise ValueError
        check = "lease_access"
        python_executable = capability._resolve_trusted_toolchain()["python"]
        source_signers = source_path.joinpath(*SIGNER_PATH_PARTS)
        if not source_signers.is_file() or (temporary / "lease-write-probe").exists():
            raise ValueError
        environment = {
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            "HOME": "/",
            "TMPDIR": str(storage_root),
            "LANG": "C",
            "LC_ALL": "C",
        }
        result = capability._run_as_probe_user(
            (
                python_executable, "-I", "-S", "-B", "-c", LEASE_ACCESS_SCRIPT,
                str(worker_uid), str(temporary), str(source_path), str(source_signers),
            ),
            worker_uid,
            env=environment,
            timeout=10,
            failure_reason="native_preflight_unavailable",
            python_executable=python_executable,
        )
        if result.returncode != 0 or result.stdout != LEASE_ACL_MARKER or result.stderr:
            raise ValueError
        return python_executable
    except Refusal as error:
        if (
            core_contract
            and error.reason == "bootstrap_snapshot_invalid"
            and error.stage == "bootstrap"
            and error.core_check is None
        ):
            raise Refusal(error.reason, error.stage, core_check=check) from None
        raise
    except BaseException:
        raise Refusal(
            "bootstrap_snapshot_invalid", "bootstrap",
            core_check=check if core_contract else None,
        ) from None


def _assert_worker_absent(worker_uid, python_executable):
    try:
        presence = capability._probe_uid_processes_present(
            worker_uid,
            include_survivor_classes=True,
            python_executable=python_executable,
        )
        present, unused_classes = capability._presence_result(presence)
        if present:
            raise ValueError
    except BaseException:
        raise Refusal("cleanup_incomplete", "cleanup") from None


def _worktree_add_arguments(git_executable, source_path, commit):
    return (
        git_executable, "worktree", "add", "--quiet", "--detach", "--no-checkout",
        str(source_path), commit,
    )


def _checkout_source(repository, git_executable, repo_env, temporary, commit, *, core_contract=False):
    source_path = temporary / "source"
    try:
        add_result = _run_process(
            _worktree_add_arguments(git_executable, source_path, commit),
            cwd=repository,
            environ=repo_env,
        )
        _require_git_success(add_result, "bootstrap")
        checkout_result = _run_process(
            (git_executable, "-C", str(source_path), "checkout", "--quiet", "--detach", commit),
            cwd=source_path,
            environ=repo_env,
        )
        _require_git_success(checkout_result, "bootstrap")
    except Refusal as error:
        if (
            core_contract
            and error.reason == "bootstrap_snapshot_invalid"
            and error.stage == "bootstrap"
        ):
            raise Refusal(error.reason, error.stage, core_check="checkout") from None
        raise
    try:
        root = temporary.resolve(strict=True)
        source = source_path.resolve(strict=True)
        if source.parent != root:
            raise ValueError
        for current, directories, files in os.walk(source, topdown=True, followlinks=False):
            current_path = Path(current)
            current_info = current_path.lstat()
            if (
                not stat.S_ISDIR(current_info.st_mode)
                or current_info.st_uid != 0
                or current_info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
            ):
                raise ValueError
            for name in directories + files:
                child = current_path / name
                info = child.lstat()
                if (
                    stat.S_ISLNK(info.st_mode)
                    or info.st_uid != 0
                    or info.st_mode & (stat.S_IWGRP | stat.S_IWOTH | stat.S_ISUID | stat.S_ISGID)
                ):
                    raise ValueError
                if name in files and not stat.S_ISREG(info.st_mode):
                    raise ValueError
                if name in directories and not stat.S_ISDIR(info.st_mode):
                    raise ValueError
    except BaseException:
        raise Refusal(
            "bootstrap_snapshot_invalid", "bootstrap",
            core_check="checkout" if core_contract else None,
        ) from None
    return source


def _commit_list(repository, git_executable, repo_env, base_sha, source_sha):
    result = _run_process(
        (git_executable, "rev-list", "--topo-order", "--reverse", base_sha + ".." + source_sha),
        cwd=repository,
        environ=repo_env,
        max_output=MAX_COMMITS * 41,
        stage="history",
    )
    if result.returncode != 0 or result.stderr or len(result.stdout) > MAX_COMMITS * 41:
        raise Refusal("base_invalid", "history")
    if result.stdout and not result.stdout.endswith(b"\n"):
        raise Refusal("base_invalid", "history")
    commits = []
    for raw_line in result.stdout.splitlines():
        try:
            value = raw_line.decode("ascii")
        except UnicodeDecodeError:
            raise Refusal("base_invalid", "history") from None
        if not _full_sha(value) or len(commits) >= MAX_COMMITS:
            raise Refusal("base_invalid", "history")
        commits.append(value)
    return tuple(commits)


def _changed_paths(repository, git_executable, repo_env, commit):
    result = _run_process(
        (
            git_executable, "diff-tree", "-m", "--no-commit-id", "--name-only", "-r", "-z", commit,
        ),
        cwd=repository,
        environ=repo_env,
        max_output=MAX_TREE_BYTES,
        stage="history",
    )
    if result.returncode != 0 or result.stderr or len(result.stdout) > MAX_TREE_BYTES:
        raise Refusal("base_invalid", "history")
    try:
        return tuple(value.decode("utf-8", "strict") for value in result.stdout.split(b"\x00") if value)
    except UnicodeDecodeError:
        raise Refusal("base_invalid", "history") from None


def _verify_commit(repository, git_executable, repo_env, ssh_keygen, allowed_path, revoked_path, commit):
    result = _run_process(
        (
            git_executable,
            "-c", "gpg.format=ssh",
            "-c", "gpg.ssh.program=" + ssh_keygen,
            "-c", "gpg.program=false",
            "-c", "gpg.x509.program=false",
            "-c", "gpg.ssh.allowedSignersFile=" + str(allowed_path),
            "-c", "gpg.ssh.revocationFile=" + str(revoked_path),
            "-c", "gpg.minTrustLevel=fully",
            "verify-commit", commit,
        ),
        cwd=repository,
        environ=repo_env,
        stage="signature",
    )
    if result.returncode != 0 or len(result.stdout) > MAX_GIT_OUTPUT or len(result.stderr) > MAX_GIT_OUTPUT:
        raise Refusal("signature_invalid", "signature")


def _reader_revocation_passed(result):
    return (
        type(result) is dict
        and set(result) == {
            "schema_version", "status", "reason", "repository_scope", "metadata", "revocation",
        }
        and type(result.get("schema_version")) is int
        and result.get("schema_version") == 1
        and result.get("status") == "passed"
        and result.get("reason") == "ok"
        and result.get("repository_scope") == "verified"
        and result.get("metadata") == "verified"
        and result.get("revocation") == "confirmed"
    )


def _restore_token_if_missing(environ, token_name, token):
    try:
        current = environ.get(token_name)
        if current is None:
            environ[token_name] = token
            return True
        return current == token
    except BaseException:
        return False


def _revoke_token(
    reader,
    environ,
    *,
    revocation_state=None,
    retained_token=None,
    repository_id=None,
    request=None,
    binding=None,
):
    token_name = reader.TOKEN_ENV
    token = retained_token
    if token is None:
        try:
            token = environ.get(token_name)
        except BaseException:
            token = None
    if type(token) is not str or SOURCE_TOKEN_PATTERN.fullmatch(token) is None:
        raise Refusal("revocation_unconfirmed", "revoke")
    try:
        current_token = environ.get(token_name)
    except BaseException:
        current_token = None
    if current_token != token:
        raise Refusal("revocation_unconfirmed", "revoke")
    if revocation_state is not None and _revocation_proof_values(
        token, repository_id, request, binding,
    ) is None:
        raise Refusal("revocation_unconfirmed", "revoke")
    try:
        result = reader.run(environ=environ)
    except BaseException:
        _restore_token_if_missing(environ, token_name, token)
        raise Refusal("revocation_unconfirmed", "revoke") from None
    if not _reader_revocation_passed(result):
        _restore_token_if_missing(environ, token_name, token)
        raise Refusal("revocation_unconfirmed", "revoke")
    if revocation_state is not None:
        try:
            _record_revocation_proof(
                revocation_state, token, repository_id, request, binding,
            )
        except Refusal:
            _restore_token_if_missing(environ, token_name, token)
            raise
    try:
        environ.pop(token_name, None)
        if token_name in environ:
            raise OSError
    except BaseException:
        raise Refusal("cleanup_incomplete", "cleanup") from None
    return result


def _remove_tree(path):
    try:
        shutil.rmtree(path)
        try:
            os.lstat(path)
        except FileNotFoundError:
            return
        raise OSError
    except FileNotFoundError:
        return
    except BaseException:
        raise Refusal("cleanup_incomplete", "cleanup") from None


def _check_request(request):
    expected = {"source_sha", "base_sha", "base_branch", "concern"}
    if (
        type(request) is not dict
        or set(request) != expected
        or not _full_sha(request.get("source_sha"))
        or not _full_sha(request.get("base_sha"))
        or type(request.get("base_branch")) is not str
        or type(request.get("concern")) is not str
        or request["concern"] not in CONCERNS
        or not _valid_base_selection(
            request.get("base_sha"), request.get("base_branch"), request.get("concern"),
        )
    ):
        raise Refusal("invalid_input", "input")
    return True


def _check_rules_bootstrap_gate(request, environ):
    if request["concern"] != "rules-bootstrap":
        return
    control_sha = environ.get("CI_SHA", "")
    if (
        not _full_sha(control_sha)
        or environ.get(RULES_BOOTSTRAP_SOURCE_GATE_ENV) != request["source_sha"]
        or environ.get(RULES_BOOTSTRAP_CONTROL_GATE_ENV) != control_sha
    ):
        raise Refusal("bootstrap_not_approved", "configuration")


def _check_core_contract_gate(request, environ):
    if request["concern"] not in CORE_CONTRACT_CONCERNS:
        return
    control_sha = environ.get("CI_SHA", "")
    if (
        not _full_sha(control_sha)
        or environ.get(CORE_CONTRACT_SOURCE_GATE_ENV) != request["source_sha"]
        or environ.get(CORE_CONTRACT_CONTROL_GATE_ENV) != control_sha
    ):
        raise Refusal("bootstrap_not_approved", "configuration")


def _check_source_ref_binding(request, environ):
    candidate_ref = environ.get(SOURCE_CANDIDATE_REF_ENV, "")
    if request["concern"] == "core-bootstrap" and request["source_sha"] != request["base_sha"]:
        raise Refusal("bootstrap_not_approved", "configuration")
    if request["source_sha"] == request["base_sha"]:
        if candidate_ref and candidate_ref != "refs/heads/" + request["base_branch"]:
            raise Refusal("bootstrap_not_approved", "configuration")
        return None
    if request["concern"] not in SOURCE_DESCENDANT_CONCERNS or type(candidate_ref) is not str:
        raise Refusal("bootstrap_not_approved", "configuration")
    if re.fullmatch(r"refs/heads/(?:feat|fix|chore|plan)/[A-Za-z0-9][A-Za-z0-9._/-]{0,126}", candidate_ref) is None:
        raise Refusal("bootstrap_not_approved", "configuration")
    path = candidate_ref.removeprefix("refs/heads/")
    components = path.split("/")
    if any(
        not component
        or component in (".", "..")
        or component.startswith(".")
        or component.endswith(".")
        or component.endswith(".lock")
        for component in components
    ) or ".." in path or "@{" in path or path.endswith("/"):
        raise Refusal("bootstrap_not_approved", "configuration")
    return candidate_ref


def _check_worker_identity(root, worker_uid):
    if type(worker_uid) is not int or worker_uid <= 0 or worker_uid >= 60000:
        raise Refusal("bootstrap_not_approved", "configuration")
    try:
        runner_uid = os.stat(root).st_uid
        identity = _run_process(
            ("/usr/bin/id", "-u", capability.USERNAME),
            cwd="/",
            environ={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"},
            timeout=5,
            stage="configuration",
        )
        if (
            runner_uid == 0
            or worker_uid == runner_uid
            or identity.returncode != 0
            or identity.stderr
            or identity.stdout != (str(worker_uid) + "\n").encode("ascii")
        ):
            raise ValueError
    except BaseException:
        raise Refusal("bootstrap_not_approved", "configuration") from None


def _validate_storage_root(storage_root):
    try:
        if not isinstance(storage_root, (str, Path)) or not str(storage_root).startswith("/"):
            raise ValueError
        supplied = Path(storage_root)
        named = supplied.lstat()
        resolved = supplied.resolve(strict=True)
        parent = Path("/tmp").resolve(strict=True)
        parent_info = parent.lstat()
        info = resolved.lstat()
        with os.scandir(resolved) as entries:
            empty = next(entries, None) is None
        if (
            (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)
            or resolved.parent != parent
            or not stat.S_ISDIR(parent_info.st_mode)
            or parent_info.st_uid != 0
            or not parent_info.st_mode & stat.S_ISVTX
            or not stat.S_ISDIR(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != 0o700
            or info.st_nlink < 2
            or not empty
        ):
            raise ValueError
        return resolved
    except BaseException:
        raise Refusal("bootstrap_not_approved", "configuration") from None


def _validate_binding(binding):
    if (
        type(binding) is not dict
        or set(binding) != {"control_sha", "run_id", "run_attempt", "image_os", "image_version"}
        or not _full_sha(binding.get("control_sha"))
    ):
        raise Refusal("invalid_input", "input")


def _revocation_proof_values(token, repository_id, request, binding):
    try:
        if type(repository_id) is int and repository_id > 0:
            repository_text = str(repository_id)
        elif type(repository_id) is str and REPOSITORY_ID_PATTERN.fullmatch(repository_id) is not None:
            repository_text = repository_id
        else:
            return None
        if type(token) is not str or SOURCE_TOKEN_PATTERN.fullmatch(token) is None:
            return None
        _check_request(request)
        _validate_binding(binding)
        token_digest = hashlib.sha256(token.encode("ascii", "strict")).digest()
        return (
            _REVOCATION_PROOF_SEAL,
            token_digest,
            repository_text,
            binding["control_sha"],
            request["source_sha"],
            request["base_sha"],
            request["base_branch"],
            request["concern"],
            binding["run_id"],
            binding["run_attempt"],
        )
    except BaseException:
        return None


def _record_revocation_proof(state, token, repository_id, request, binding):
    if type(state) is not RevocationState or state in _REVOCATION_PROOFS:
        raise Refusal("revocation_unconfirmed", "revoke")
    values = _revocation_proof_values(token, repository_id, request, binding)
    if values is None:
        raise Refusal("revocation_unconfirmed", "revoke")
    try:
        _REVOCATION_PROOFS[state] = values
    except BaseException:
        raise Refusal("revocation_unconfirmed", "revoke") from None


def revocation_confirmed(state, retained_token, expected_repository_id, request, binding):
    if type(state) is not RevocationState:
        return False
    expected = _revocation_proof_values(
        retained_token, expected_repository_id, request, binding,
    )
    if expected is None:
        return False
    try:
        recorded = _REVOCATION_PROOFS.get(state)
    except BaseException:
        return False
    return type(recorded) is tuple and recorded == expected


@contextmanager
def validated_source(
    request,
    binding,
    root,
    environ,
    *,
    worker_uid=None,
    storage_root=None,
    revocation_state=None,
):
    _check_request(request)
    _check_rules_bootstrap_gate(request, environ)
    _check_core_contract_gate(request, environ)
    candidate_ref = _check_source_ref_binding(request, environ)
    _validate_binding(binding)
    if revocation_state is not None and (
        type(revocation_state) is not RevocationState
        or revocation_state in _REVOCATION_PROOFS
    ):
        raise Refusal("invalid_input", "input")
    current_binding, current_root = _safe_context(binding["control_sha"], environ)
    try:
        supplied_root = Path(root).resolve(strict=True)
    except BaseException:
        raise Refusal("context_unavailable", "context") from None
    if current_binding != binding or current_root != supplied_root:
        raise Refusal("context_unavailable", "context")
    worker_required = request["concern"] in SOURCE_DESCENDANT_CONCERNS
    if worker_required:
        _check_worker_identity(current_root, worker_uid)
        storage_root = _validate_storage_root(storage_root)
    storage_acl = False
    temporary = None
    worker_python = None
    try:
        if worker_required:
            storage_acl = True
            _add_storage_search_acl(storage_root)
        record, temporary, source_path = _source_snapshot(
            request,
            binding,
            current_root,
            environ,
            candidate_ref=candidate_ref,
            retain=True,
            temp_parent=storage_root if worker_required else None,
            revocation_state=revocation_state,
        )
        worker_access = "not_applicable"
        if worker_required:
            worker_python = _grant_worker_readonly(
                temporary,
                source_path,
                storage_root,
                worker_uid,
                core_contract=request["concern"] in CORE_CONTRACT_CONCERNS,
            )
            worker_access = "uid_read_only"
        record["repository_scope"] = "verified"
        record["metadata"] = "verified"
        record["control_sha"] = binding["control_sha"]
        record["run_id"] = binding["run_id"]
        record["run_attempt"] = binding["run_attempt"]
        record["image_os"] = binding["image_os"]
        record["image_version"] = binding["image_version"]
        record["token_revocation"] = "confirmed_before_yield"
        record["signer_authority"] = "bound_base"
        record["signatures"] = "all_new_commits_verified"
        record["ancestry"] = "base_ancestor"
        record["revocation_policy"] = "current_control_fingerprints"
        if request["concern"] not in CORE_CONTRACT_CONCERNS:
            record["tree"] = {
                "core-bootstrap": "core_administrative",
                "rules-bootstrap": "rules_regular_files",
            }[request["concern"]]
        record["worker_access"] = worker_access
        record["source_execution"] = "not_run_at_yield"
        record["cleanup"] = "lease_open"
        lease = SourceLease(source_path, MappingProxyType(dict(record)))
    except BaseException:
        _revoke_on_early_refusal(environ, revocation_state, request, binding)
        cleanup_safe = True
        if worker_required and temporary is not None:
            try:
                census_python = worker_python or capability._resolve_trusted_toolchain()["python"]
                _assert_worker_absent(worker_uid, census_python)
            except BaseException:
                cleanup_safe = False
        if not cleanup_safe:
            raise Refusal("cleanup_incomplete", "cleanup") from None
        if temporary is not None:
            _remove_tree(temporary)
        if storage_acl:
            _remove_storage_search_acl(storage_root)
        raise
    try:
        yield lease
    finally:
        cleanup_error = None
        cleanup_safe = True
        if worker_required:
            try:
                _assert_worker_absent(worker_uid, worker_python)
            except BaseException:
                cleanup_error = Refusal("cleanup_incomplete", "cleanup")
                cleanup_safe = False
        if cleanup_safe:
            try:
                if temporary is not None:
                    _remove_tree(temporary)
            except BaseException:
                cleanup_error = Refusal("cleanup_incomplete", "cleanup")
            if storage_acl:
                try:
                    _remove_storage_search_acl(storage_root)
                except BaseException:
                    cleanup_error = Refusal("cleanup_incomplete", "cleanup")
        if cleanup_error is not None:
            raise cleanup_error


def _source_snapshot(
    request,
    binding,
    root,
    environ,
    *,
    candidate_ref=None,
    retain=False,
    temp_parent=None,
    revocation_state=None,
):
    _check_request(request)
    _check_core_contract_gate(request, environ)
    if candidate_ref != _check_source_ref_binding(request, environ):
        raise Refusal("bootstrap_not_approved", "configuration")
    git_executable = _resolve_trusted_executable("/usr/bin/git")
    ssh_keygen = _resolve_trusted_executable("/usr/bin/ssh-keygen")
    temporary = _safe_temp_root(temp_parent)
    repository = temporary / "repository.git"
    env = None
    git_environment = None
    signer_payload = None
    reader = None
    token = None
    repository_id = None
    authorization = None
    signer_path = "/".join(SIGNER_PATH_PARTS)
    revocation_result = None
    pending_failure = None
    transferred = False
    try:
        fingerprints = _control_inventory(root, binding["control_sha"], git_executable, temporary)
        reader = _load_source_reader(root)
        repository_id, owner, repository_name, token = _repository_configuration(reader, environ)
        _verify_repository_scope(reader, repository_id, owner, repository_name, token)
        authorization = "AUTHORIZATION: basic " + base64.b64encode(
            ("x-access-token:" + token).encode("ascii")
        ).decode("ascii")
        git_environment = _base_git_environment(temporary, authorization)
        _run_source_git(
            "git_init",
            (git_executable, "init", "--quiet", "--bare", str(repository)),
            cwd=temporary,
            environ=_base_git_environment(temporary),
        )
        remote_url = "https://github.com/" + owner + "/" + repository_name + ".git"
        _run_source_git(
            "remote_add",
            (git_executable, "remote", "add", "source", remote_url),
            cwd=repository,
            environ=git_environment,
        )
        branch_ref = "refs/heads/" + request["base_branch"]
        destination_ref = "refs/remotes/source/" + request["base_branch"]
        _run_source_git(
            "base_fetch",
            (
                git_executable, "fetch", "--quiet", "--no-tags",
                "source", branch_ref + ":" + destination_ref,
            ),
            cwd=repository,
            environ=git_environment,
            timeout=300,
        )
        branch_payload = _run_source_git(
            "base_ref",
            (git_executable, "rev-parse", "--verify", destination_ref + "^{commit}"),
            cwd=repository,
            environ=git_environment,
        )
        actual_base = _one_line_sha(branch_payload)
        if actual_base != request["base_sha"]:
            raise Refusal("base_invalid", "history")
        source_ref = destination_ref
        if candidate_ref is not None:
            candidate_destination = "refs/remotes/source/candidate"
            _run_source_git(
                "candidate_fetch",
                (
                    git_executable, "fetch", "--quiet", "--no-tags",
                    "source", candidate_ref + ":" + candidate_destination,
                ),
                cwd=repository,
                environ=git_environment,
                timeout=300,
            )
            source_ref = candidate_destination
        source_payload = _run_source_git(
            "source_ref",
            (git_executable, "rev-parse", "--verify", source_ref + "^{commit}"),
            cwd=repository,
            environ=git_environment,
        )
        if _one_line_sha(source_payload) != request["source_sha"]:
            raise Refusal("base_invalid", "history")
        shallow_payload = _run_source_git(
            "shallow_check",
            (git_executable, "rev-parse", "--is-shallow-repository"),
            cwd=repository,
            environ=git_environment,
        )
        if shallow_payload != b"false\n":
            raise Refusal("base_invalid", "history")
        signer_entry = _source_entry(
            repository, git_executable, git_environment, request["base_sha"], signer_path,
            stage="signature",
        )
        if signer_entry[:2] != ("100644", "blob"):
            raise Refusal("signature_invalid", "signature")
        signer_payload = _read_source_blob(
            repository, git_executable, git_environment, signer_entry[2], MAX_SIGNER_BYTES,
        )
        _run_source_git(
            "remote_remove",
            (git_executable, "remote", "remove", "source"),
            cwd=repository,
            environ=git_environment,
        )
        git_environment = None
    except Refusal as error:
        pending_failure = error
    except BaseException:
        pending_failure = Refusal(
            "source_fetch_unavailable", "fetch", ("source_snapshot", "unexpected_exception"),
        )
    finally:
        if git_environment is not None:
            git_environment.clear()
        if reader is not None and token is not None:
            try:
                revocation_result = _revoke_token(
                    reader,
                    environ,
                    revocation_state=revocation_state,
                    retained_token=token,
                    repository_id=repository_id,
                    request=request,
                    binding=binding,
                )
            except Refusal as error:
                pending_failure = error
        authorization = None
        token = None
    if pending_failure is not None:
        _remove_tree(temporary)
        raise pending_failure
    if revocation_result is None:
        _remove_tree(temporary)
        raise Refusal("revocation_unconfirmed", "revoke")
    try:
        env = _base_git_environment(temporary)
        signer_keys = _signer_inventory(signer_payload)
        revoked_payload = _revocation_payload(fingerprints, signer_keys)
        base_allowed_path = temporary / "base-allowed-signers"
        current_allowed_path = temporary / "current-allowed-signers"
        revoked_path = temporary / "revoked-signers"
        _write_private_file(base_allowed_path, signer_payload)
        _write_private_file(current_allowed_path, _active_signer_payload(signer_keys))
        _write_private_file(revoked_path, revoked_payload)
        shallow = _run_process(
            (git_executable, "rev-parse", "--is-shallow-repository"),
            cwd=repository,
            environ=env,
        )
        if _require_git_success(shallow, "history") != b"false\n":
            raise Refusal("base_invalid", "history")
        ancestry = _run_process(
            (git_executable, "merge-base", "--is-ancestor", request["base_sha"], request["source_sha"]),
            cwd=repository,
            environ=env,
        )
        if ancestry.returncode != 0 or ancestry.stdout or ancestry.stderr:
            raise Refusal("base_invalid", "history")
        commits = _commit_list(
            repository, git_executable, env, request["base_sha"], request["source_sha"],
        )
        if request["source_sha"] == request["base_sha"]:
            commits_to_verify = (request["base_sha"],)
        else:
            commits_to_verify = commits
            if not commits_to_verify:
                raise Refusal("base_invalid", "history")
        for commit in commits_to_verify:
            if commit != request["base_sha"] and signer_path in _changed_paths(
                repository, git_executable, env, commit,
            ):
                raise Refusal("signature_invalid", "signature")
            _verify_commit(
                repository,
                git_executable,
                env,
                ssh_keygen,
                base_allowed_path if commit == request["base_sha"] else current_allowed_path,
                revoked_path,
                commit,
            )
        if request["concern"] == "core-bootstrap":
            _administrative_tree(repository, git_executable, env, request["source_sha"])
            rules_lock = "present"
            tree_kind = "core_administrative"
        elif request["concern"] == "rules-bootstrap":
            _safe_rules_tree(repository, git_executable, env, request["source_sha"])
            rules_lock = "not-applicable"
            tree_kind = "rules_regular_files"
        elif request["concern"] in CORE_CONTRACT_CONCERNS:
            tree_kind = _safe_core_contract_tree(
                repository, git_executable, env, request["base_sha"], request["source_sha"],
                concern=request["concern"],
            )
            rules_lock = "present"
        else:
            raise Refusal("bootstrap_not_approved", "configuration")
        source_path = _checkout_source(
            repository, git_executable, env, temporary, request["source_sha"],
            core_contract=request["concern"] in CORE_CONTRACT_CONCERNS,
        )
        record = {
            "repository_id": str(repository_id),
            "source_sha": request["source_sha"],
            "base_sha": request["base_sha"],
            "base_branch": request["base_branch"],
            "concern": request["concern"],
            "candidate_class": "permanent-tip" if request["source_sha"] == request["base_sha"] else "signed-descendant",
            "signature": "verified",
            "rules_lock": rules_lock,
            "tree": tree_kind,
            "source_execution": "not_run",
            "app_build": "not_run",
            "cleanup": "lease_open" if retain else "complete",
        }
        if retain:
            transferred = True
            return record, temporary, source_path
        return record
    finally:
        if not transferred:
            _remove_tree(temporary)


def _format_success(record, binding):
    required = {
        "repository_id", "source_sha", "base_sha", "base_branch", "concern",
        "candidate_class", "signature", "rules_lock", "tree", "source_execution", "app_build", "cleanup",
        "control_sha", "run_id", "run_attempt", "image_os", "image_version",
        "repository_scope", "metadata", "token_revocation", "signer_authority",
        "signatures", "ancestry", "revocation_policy", "worker_access",
    }
    if type(record) is not dict or set(record) != required:
        raise Refusal("internal_error", "input")
    if (
        record["control_sha"] != binding["control_sha"]
        or record["run_id"] != binding["run_id"]
        or record["run_attempt"] != binding["run_attempt"]
        or record["image_os"] != binding["image_os"]
        or record["image_version"] != binding["image_version"]
        or REPOSITORY_ID_PATTERN.fullmatch(record["repository_id"]) is None
        or not _full_sha(record["source_sha"])
        or not _full_sha(record["base_sha"])
        or record["concern"] not in CONCERNS
        or not _valid_base_selection(record["base_sha"], record["base_branch"], record["concern"])
        or record["candidate_class"] not in {"permanent-tip", "signed-descendant"}
        or (record["candidate_class"] == "permanent-tip") != (record["source_sha"] == record["base_sha"])
        or (record["concern"] == "core-bootstrap" and record["source_sha"] != record["base_sha"])
    ):
        raise Refusal("internal_error", "input")
    expected_tree = {
        "core-bootstrap": "core_administrative",
        "rules-bootstrap": "rules_regular_files",
        **CORE_CONTRACT_TREE_BY_CONCERN,
    }.get(record.get("concern"))
    if (record.get("concern") == "core-build-diagnostic-return"
            and record.get("tree") == CORE_CONTRACT_PACKAGE_LOCK_TREE):
        expected_tree = CORE_CONTRACT_PACKAGE_LOCK_TREE
    fixed = {
        "signature": "verified",
        "rules_lock": "not-applicable" if record.get("concern") == "rules-bootstrap" else "present",
        "tree": expected_tree,
        "source_execution": "not_run_at_yield",
        "repository_scope": "verified",
        "metadata": "verified",
        "token_revocation": "confirmed_before_yield",
        "signer_authority": "bound_base",
        "signatures": "all_new_commits_verified",
        "ancestry": "base_ancestor",
        "revocation_policy": "current_control_fingerprints",
        "worker_access": "not_applicable" if record.get("concern") == "core-bootstrap" else "uid_read_only",
        "app_build": "not_run",
        "cleanup": "complete",
    }
    if any(record[key] != value for key, value in fixed.items()):
        raise Refusal("internal_error", "input")
    fields = [
        "macos-private-validation=verified",
        "schema=" + str(SCHEMA_VERSION),
        "control-sha=" + binding["control_sha"],
        "run-id=" + binding["run_id"],
        "run-attempt=" + binding["run_attempt"],
        "image-os=" + binding["image_os"],
        "image-version=" + binding["image_version"],
        "source-repository-id=" + record["repository_id"],
        "source-sha=" + record["source_sha"],
        "base-branch=" + record["base_branch"],
        "base-sha=" + record["base_sha"],
        "concern=" + record["concern"],
        "candidate-class=" + record["candidate_class"],
        "signature=verified",
        "rules-lock=" + record["rules_lock"],
        "source-execution=not-run",
        "app-build=not-run",
        "cleanup=complete",
    ]
    if record["concern"] in FEEDBACK_PROFILE_CONCERNS:
        fields.append("tree=" + record["tree"])
    return " ".join(fields)


def _safe_identity_fields(control_sha, environ):
    sha = control_sha if _full_sha(control_sha) else "unknown"
    run_id = environ.get("GITHUB_RUN_ID", "")
    attempt = environ.get("GITHUB_RUN_ATTEMPT", "")
    if RUN_ID_PATTERN.fullmatch(run_id) is None:
        run_id = "unknown"
    if RUN_ATTEMPT_PATTERN.fullmatch(attempt) is None:
        attempt = "unknown"
    return sha, run_id, attempt


def _format_refusal(error, control_sha, environ, request=None):
    if type(error) is not Refusal:
        error = Refusal("internal_error", "input")
    reason = error.reason if error.reason in REASONS else "internal_error"
    stage = error.stage if error.stage in STAGES else "input"
    sha, run_id, attempt = _safe_identity_fields(control_sha, environ)
    source_sha = request["source_sha"] if type(request) is dict and _full_sha(request.get("source_sha")) else "unknown"
    base_sha = request["base_sha"] if type(request) is dict and _full_sha(request.get("base_sha")) else "unknown"
    return (
        "macos-private-validation=refused schema=1 reason=" + reason + " stage=" + stage
        + " control-sha=" + sha + " run-id=" + run_id + " run-attempt=" + attempt
        + " source-sha=" + source_sha + " base-sha=" + base_sha
    )


def _revoke_on_early_refusal(environ, revocation_state=None, request=None, binding=None):
    token_name = "SOURCE_READER_TOKEN"
    token = environ.get(token_name, "")
    if type(token) is not str or SOURCE_TOKEN_PATTERN.fullmatch(token) is None:
        return False
    repository_id = environ.get(SOURCE_REPOSITORY_ID_ENV, "")
    if revocation_state is not None and revocation_confirmed(
        revocation_state, token, repository_id, request, binding,
    ):
        return True
    try:
        root = Path(__file__).resolve(strict=True).parents[2]
        reader = _load_source_reader(root)
        _revoke_token(
            reader,
            environ,
            revocation_state=revocation_state,
            retained_token=token,
            repository_id=repository_id,
            request=request,
            binding=binding,
        )
        return True
    except BaseException:
        return False


def main(arguments=None):
    actual_arguments = sys.argv[1:] if arguments is None else arguments
    environment = os.environ
    control_sha = environment.get("CI_SHA", "")
    request = None
    try:
        request = parse_request(actual_arguments)
        binding, root = _safe_context(control_sha, environment)
        with validated_source(request, binding, root, environment) as lease:
            record = dict(lease.record)
        record["cleanup"] = "complete"
        line = _format_success(record, binding)
    except Refusal as error:
        _revoke_on_early_refusal(environment)
        line = _format_refusal(error, control_sha, environment, request)
        sys.stdout.write(line + "\n")
        return 1
    except BaseException:
        _revoke_on_early_refusal(environment)
        line = _format_refusal(Refusal("internal_error", "input"), control_sha, environment, request)
        sys.stdout.write(line + "\n")
        return 1
    sys.stdout.write(line + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
