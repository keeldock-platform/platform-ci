import json
import re
from dataclasses import dataclass


SHADOW_MODE = "shadow"
BASE_SHA_PATTERN = re.compile(r"[a-f0-9]{40}\Z")


@dataclass(frozen=True)
class PathChange:
    path: str
    kind: str = "modified"


@dataclass(frozen=True)
class SuiteEdge:
    path_prefix: str
    suite_id: str
    edge_name: str


@dataclass(frozen=True)
class SelectionReport:
    mode: str
    would_select: tuple
    effective_suites: tuple
    reasons: tuple

    @property
    def escalated(self):
        return bool(self.reasons)

    @property
    def skipped_suites(self):
        return ()


MCP_HOST_FEATURE_OWNERS = (
    ("settings", "core.settings-schema"),
    ("ui", "core.shell-ui"),
    ("workspace", "core.workspace"),
    ("logs", "core.log"),
    ("search", "core.search"),
    ("diagnostics", "core.diagnostics"),
    ("windows", "core.windows"),
    ("legacy-import", "core.legacy-import"),
    ("ai", "core.ai"),
)


MCP_HOST_REVERSE_EDGES = tuple(
    edge
    for feature, owner_suite in MCP_HOST_FEATURE_OWNERS
    for edge in (
        SuiteEdge(
            "crates/host/mcp-host/" + feature,
            "core.mcp-host",
            "mcp-host-feature",
        ),
        SuiteEdge(
            "crates/host/mcp-host/" + feature,
            owner_suite,
            "mcp-host-owner",
        ),
    )
)


MCP_HOST_SHARED_EDGES = tuple(
    edge
    for feature, _ in MCP_HOST_FEATURE_OWNERS
    for edge in (
        SuiteEdge(
            "crates/host/mcp-host/" + feature,
            "core.static",
            "source-static",
        ),
        SuiteEdge(
            "crates/host/mcp-host/" + feature,
            "core.feature-states",
            "host-feature-states",
        ),
    )
)


SUITE_EDGES = MCP_HOST_REVERSE_EDGES + MCP_HOST_SHARED_EDGES
FULL_SET_PREFIXES = (
    ".github",
    "kit/selector",
    ".cargo",
    "vendor",
)
FULL_SET_NAMES = frozenset(
    (
        "cargo.toml",
        "cargo.lock",
        "deny.toml",
        "build.rs",
        "package.json",
        "package-lock.json",
        "pnpm-lock.yaml",
        "bun.lockb",
        "rust-toolchain",
        "rust-toolchain.toml",
        ".tool-versions",
        "toolchain.toml",
        "tauri.conf.json",
        "tauri.conf.json5",
        "tauri.conf.jsonc",
        "playwright.config.ts",
        "playwright.config.js",
        "playwright.config.mjs",
        "playwright.config.cjs",
        "setup-tests.ts",
        "setup-tests.js",
        "setuptests.ts",
        "setuptests.js",
        "appium.config.ts",
        "appium.config.js",
        "wdio.conf.ts",
        "wdio.conf.js",
    )
)


def _full_suite_tuple(full_suite_ids):
    if type(full_suite_ids) in (str, bytes):
        raise ValueError("invalid-full-suite-set")
    try:
        suites = tuple(sorted(set(full_suite_ids)))
    except (TypeError, ValueError):
        raise ValueError("invalid-full-suite-set")
    if not suites or any(type(suite_id) is not str or not suite_id for suite_id in suites):
        raise ValueError("invalid-full-suite-set")
    return suites


def _path_is_within(path, prefix):
    return path == prefix or path.startswith(prefix + "/")


def _safe_relative_path(path):
    if type(path) is not str or not path or "\\" in path or path.startswith("/"):
        return False
    parts = path.split("/")
    return all(part not in ("", ".", "..") for part in parts)


def _requires_full_set(path):
    if any(_path_is_within(path, prefix) for prefix in FULL_SET_PREFIXES):
        return True
    parts = path.split("/")
    lowered_parts = tuple(part.lower() for part in parts)
    if any(part in FULL_SET_NAMES for part in lowered_parts):
        return True
    if any(part.endswith(".lock") for part in lowered_parts):
        return True
    if any(part.startswith("tsconfig") for part in lowered_parts):
        return True
    if any(part.startswith("tauri.conf") for part in lowered_parts):
        return True
    if any(part.startswith("vite.config.") for part in lowered_parts):
        return True
    if any(part.startswith("capabilities") for part in lowered_parts):
        return True
    if any(part in ("baselines", "visual-baselines", "__screenshots__") for part in lowered_parts):
        return True
    return False


def _coerce_change(change):
    if type(change) is str:
        return PathChange(change)
    if isinstance(change, PathChange):
        return change
    if type(change) is tuple and len(change) == 2:
        return PathChange(change[0], change[1])
    raise ValueError("invalid-change")


def _edge_matches(path, edge):
    return _path_is_within(path, edge.path_prefix)


def select_suites(
    changes,
    full_suite_ids,
    base_sha,
    catalogue=SUITE_EDGES,
    base_resolved=False,
):
    """Return shadow selections while always retaining the full effective set."""
    full_suites = _full_suite_tuple(full_suite_ids)
    reasons = []
    if (
        type(base_resolved) is not bool
        or not base_resolved
        or type(base_sha) is not str
        or BASE_SHA_PATTERN.fullmatch(base_sha) is None
    ):
        reasons.append("unresolved-base")

    try:
        change_list = tuple(_coerce_change(change) for change in changes)
    except (TypeError, ValueError):
        change_list = ()
        reasons.append("invalid-change-input")

    if not change_list:
        reasons.append("empty-change-set")

    try:
        edges = tuple(catalogue)
    except TypeError:
        edges = ()
        reasons.append("invalid-catalogue")
    if any(
        not isinstance(edge, SuiteEdge)
        or not _safe_relative_path(edge.path_prefix)
        or type(edge.suite_id) is not str
        or not edge.suite_id
        or type(edge.edge_name) is not str
        or not edge.edge_name
        for edge in edges
    ):
        edges = ()
        reasons.append("invalid-catalogue")

    selected = set()
    for change in change_list:
        path = change.path
        if not _safe_relative_path(path):
            reasons.append("invalid-path")
            continue
        if type(change.kind) is not str or change.kind.lower() not in ("added", "modified", "a", "m"):
            reasons.append("delete-rename-or-unknown-change")
            continue
        if _requires_full_set(path):
            reasons.append("protected-input")
            continue
        matching_edges = tuple(
            edge for edge in edges if _edge_matches(path, edge)
        )
        if not matching_edges:
            reasons.append("unmapped-path")
            continue
        selected.update(edge.suite_id for edge in matching_edges)

    unique_reasons = tuple(sorted(set(reasons)))
    if unique_reasons:
        would_select = full_suites
    else:
        would_select = tuple(sorted(selected))
    return SelectionReport(
        mode=SHADOW_MODE,
        would_select=would_select,
        effective_suites=full_suites,
        reasons=unique_reasons,
    )


def format_shadow_report(report):
    """Serialize a report without changing the suites that will run."""
    payload = {
        "mode": report.mode,
        "would_select": list(report.would_select),
        "effective_suites": list(report.effective_suites),
        "skipped_suites": list(report.skipped_suites),
        "escalated": report.escalated,
        "reasons": list(report.reasons),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))
