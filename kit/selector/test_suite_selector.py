import json
import unittest

from suite_selector import (
    MCP_HOST_REVERSE_EDGES,
    PathChange,
    SHADOW_MODE,
    SUITE_EDGES,
    SuiteEdge,
    format_shadow_report,
    select_suites,
)


GOOD_BASE_SHA = "a" * 40
EXPECTED_MCP_REVERSE_EDGES = (
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
FULL_SUITES = frozenset(
    (
        "core.mcp-host",
        "core.settings-schema",
        "core.shell-ui",
        "core.workspace",
        "core.log",
        "core.search",
        "core.diagnostics",
        "core.windows",
        "core.legacy-import",
        "core.ai",
        "core.static",
    )
)


class SuiteSelectorTests(unittest.TestCase):
    def test_every_mcp_feature_change_selects_host_and_owning_suite(self):
        for feature, owner_suite in EXPECTED_MCP_REVERSE_EDGES:
            with self.subTest(feature=feature):
                changed_path = "crates/host/mcp-host/" + feature + "/command.rs"
                report = select_suites(
                    (changed_path,), FULL_SUITES, GOOD_BASE_SHA, base_resolved=True
                )
                self.assertEqual(report.mode, SHADOW_MODE)
                self.assertFalse(report.escalated)
                self.assertEqual(
                    report.would_select,
                    tuple(sorted(("core.mcp-host", owner_suite))),
                )

    def test_required_reverse_edges_select_both_suites_from_one_changed_path(self):
        required = {
            "windows": "core.windows",
            "legacy-import": "core.legacy-import",
            "ai": "core.ai",
        }
        for feature, owner_suite in required.items():
            with self.subTest(feature=feature):
                report = select_suites(
                    (PathChange("crates/host/mcp-host/" + feature + "/only.rs"),),
                    FULL_SUITES,
                    GOOD_BASE_SHA,
                    base_resolved=True,
                )
                self.assertEqual(
                    set(report.would_select),
                    {"core.mcp-host", owner_suite},
                )

    def test_removing_any_required_reverse_edge_fails_its_fixture(self):
        for edge in MCP_HOST_REVERSE_EDGES:
            with self.subTest(path=edge.path_prefix, suite=edge.suite_id):
                mutated_catalogue = tuple(
                    candidate for candidate in SUITE_EDGES if candidate != edge
                )
                report = select_suites(
                    (edge.path_prefix + "/only.rs",),
                    FULL_SUITES,
                    GOOD_BASE_SHA,
                    catalogue=mutated_catalogue,
                    base_resolved=True,
                )
                feature = edge.path_prefix.rsplit("/", 1)[1]
                owner_suite = dict(EXPECTED_MCP_REVERSE_EDGES)[feature]
                expected = tuple(sorted(("core.mcp-host", owner_suite)))
                self.assertNotEqual(report.would_select, expected)

    def test_base_sha_must_be_resolved_and_canonical(self):
        for base_sha in (None, "a" * 39, "A" * 40):
            with self.subTest(base_sha=base_sha):
                report = select_suites(
                    ("crates/host/mcp-host/windows/file.rs",),
                    FULL_SUITES,
                    base_sha,
                    base_resolved=True,
                )
                self.assertTrue(report.escalated)
                self.assertEqual(report.would_select, tuple(sorted(FULL_SUITES)))
                self.assertIn("unresolved-base", report.reasons)

    def test_unmapped_or_protected_paths_escalate_to_full_set(self):
        for path in (
            "crates/host/unowned/file.rs",
            "Cargo.lock",
            "package-lock.json",
            ".github/workflows/public-policy.yml",
            "kit/selector/suite_selector.py",
        ):
            with self.subTest(path=path):
                report = select_suites(
                    (path,), FULL_SUITES, GOOD_BASE_SHA, base_resolved=True
                )
                self.assertTrue(report.escalated)
                self.assertEqual(report.would_select, tuple(sorted(FULL_SUITES)))

    def test_valid_sha_with_unresolved_base_escalates_to_full_set(self):
        report = select_suites(
            ("crates/host/mcp-host/windows/file.rs",),
            FULL_SUITES,
            GOOD_BASE_SHA,
        )
        self.assertTrue(report.escalated)
        self.assertIn("unresolved-base", report.reasons)
        self.assertEqual(report.would_select, tuple(sorted(FULL_SUITES)))

    def test_deletions_renames_and_invalid_paths_escalate(self):
        changes = (
            PathChange("crates/host/mcp-host/windows/file.rs", "deleted"),
            PathChange("crates/host/mcp-host/windows/new.rs", "renamed"),
            PathChange("../outside.rs"),
        )
        report = select_suites(changes, FULL_SUITES, GOOD_BASE_SHA, base_resolved=True)
        self.assertTrue(report.escalated)
        self.assertEqual(report.would_select, tuple(sorted(FULL_SUITES)))

    def test_shadow_report_always_keeps_the_full_effective_suite_set(self):
        report = select_suites(
            ("crates/host/mcp-host/ai/completion.rs",),
            FULL_SUITES,
            GOOD_BASE_SHA,
            base_resolved=True,
        )
        self.assertEqual(report.effective_suites, tuple(sorted(FULL_SUITES)))
        self.assertEqual(report.skipped_suites, ())
        self.assertEqual(report.mode, "shadow")
        payload = json.loads(format_shadow_report(report))
        self.assertEqual(payload["effective_suites"], list(sorted(FULL_SUITES)))
        self.assertEqual(payload["skipped_suites"], [])
        self.assertEqual(payload["would_select"], ["core.ai", "core.mcp-host"])
        self.assertFalse(payload["escalated"])

    def test_duplicate_paths_do_not_duplicate_suite_ids(self):
        report = select_suites(
            (
                "crates/host/mcp-host/windows/one.rs",
                "crates/host/mcp-host/windows/two.rs",
            ),
            FULL_SUITES,
            GOOD_BASE_SHA,
            base_resolved=True,
        )
        self.assertEqual(report.would_select, ("core.mcp-host", "core.windows"))

    def test_catalogue_contains_each_documented_owner_edge(self):
        for feature, owner_suite in EXPECTED_MCP_REVERSE_EDGES:
            expected_prefix = "crates/host/mcp-host/" + feature
            self.assertIn(
                SuiteEdge(expected_prefix, "core.mcp-host", "mcp-host-feature"),
                MCP_HOST_REVERSE_EDGES,
            )
            self.assertIn(
                SuiteEdge(expected_prefix, owner_suite, "mcp-host-owner"),
                MCP_HOST_REVERSE_EDGES,
            )


if __name__ == "__main__":
    unittest.main()
