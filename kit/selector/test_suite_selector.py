import json
import unittest
from pathlib import Path

from ci19_catalogue import (
    EXPECTED_OWNERS,
    CatalogueError,
    parse_catalogue,
    validate_snapshot,
)
from suite_selector import (
    ci19_canonical_catalogue,
    MCP_HOST_FEATURE_OWNERS,
    MCP_HOST_REVERSE_EDGES,
    MCP_HOST_SHARED_EDGES,
    PathChange,
    SHADOW_MODE,
    SUITE_EDGES,
    SuiteEdge,
    format_shadow_report,
    select_suites,
    validate_ci19_catalogue,
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
    ("ai", "core.ai"),
)
FULL_SUITES = frozenset(
    (
        "core.mcp-host",
        "core.feature-states",
        "core.settings-schema",
        "core.shell-ui",
        "core.workspace",
        "core.log",
        "core.search",
        "core.diagnostics",
        "core.windows",
        "core.ai",
        "core.static",
    )
)


class SuiteSelectorTests(unittest.TestCase):
    def test_staged_ci19_snapshot_matches_the_exact_owner_pairs(self):
        fixture = Path(__file__).resolve().parent / "fixtures" / "ci19_mcp_feature_owners.json"
        raw = fixture.read_bytes()
        self.assertEqual(validate_snapshot(raw), EXPECTED_MCP_REVERSE_EDGES)
        self.assertEqual(EXPECTED_OWNERS, EXPECTED_MCP_REVERSE_EDGES)

    def test_ci19_snapshot_rejects_missing_renamed_or_duplicate_pairs(self):
        fixture = Path(__file__).resolve().parent / "fixtures" / "ci19_mcp_feature_owners.json"
        snapshot = json.loads(fixture.read_text(encoding="ascii"))
        for mutation in ("missing", "renamed", "duplicate", "wrong-digest"):
            changed = json.loads(json.dumps(snapshot))
            if mutation == "missing":
                changed["owners"].pop()
            elif mutation == "renamed":
                changed["owners"][0]["folder"] = "settings-schema"
            elif mutation == "duplicate":
                changed["owners"][1] = dict(changed["owners"][0])
            else:
                changed["catalogue_sha256"] = "0" * 64
            payload = (json.dumps(changed, sort_keys=True, indent=2) + "\n").encode("ascii")
            with self.subTest(mutation=mutation):
                with self.assertRaises(CatalogueError):
                    validate_snapshot(payload)

    def test_ci19_catalogue_parser_accepts_only_the_eight_active_owner_edges(self):
        markdown = "\n".join(
            "| `%s` | core | area | `crates/host/mcp-host/%s/**` |"
            % (suite, folder)
            for folder, suite in reversed(EXPECTED_MCP_REVERSE_EDGES)
        )
        self.assertEqual(parse_catalogue(markdown), EXPECTED_MCP_REVERSE_EDGES)
        with self.assertRaises(CatalogueError):
            parse_catalogue(markdown.replace("mcp-host/ai/**", "mcp-host/log/**", 1))

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
                    tuple(
                        sorted(("core.mcp-host", owner_suite, "core.static", "core.feature-states"))
                    ),
                )

    def test_required_reverse_edges_select_both_suites_from_one_changed_path(self):
        required = {
            "windows": "core.windows",
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
                    {"core.mcp-host", owner_suite, "core.static", "core.feature-states"},
                )

    def test_removing_any_required_reverse_edge_escalates_to_the_full_set(self):
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
                self.assertTrue(report.escalated)
                self.assertEqual(report.would_select, tuple(sorted(FULL_SUITES)))
                self.assertIn("invalid-catalogue", report.reasons)

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

    def test_wave_70_runtime_inventory_and_xtask_changes_are_protected_inputs(self):
        for path in (
            "runtime/admission/inventory.toml",
            "runtime/apps/test-shell-desktop/src-tauri/src/main.rs",
            "runtime/apps/test-shell-mobile/src-tauri/tauri.conf.json",
            "runtime/crates/host/entitlements/src/lib.rs",
            "runtime/crates/services/vault/src/lib.rs",
            "tools/xtask/src/main.rs",
        ):
            with self.subTest(path=path):
                report = select_suites(
                    (path,), FULL_SUITES, GOOD_BASE_SHA, base_resolved=True,
                )
                self.assertTrue(report.escalated)
                self.assertEqual(report.would_select, tuple(sorted(FULL_SUITES)))
                self.assertIn("protected-input", report.reasons)

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
        self.assertEqual(
            payload["would_select"],
            ["core.ai", "core.feature-states", "core.mcp-host", "core.static"],
        )
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
        self.assertEqual(
            report.would_select,
            ("core.feature-states", "core.mcp-host", "core.static", "core.windows"),
        )

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
            self.assertIn(
                SuiteEdge(expected_prefix, "core.static", "source-static"),
                MCP_HOST_SHARED_EDGES,
            )
            self.assertIn(
                SuiteEdge(expected_prefix, "core.feature-states", "host-feature-states"),
                MCP_HOST_SHARED_EDGES,
            )

    def test_ci19_owners_match_the_eight_active_catalogue_folders(self):
        self.assertEqual(ci19_canonical_catalogue, "repos/16-ci-suite-catalogue.md")
        self.assertEqual(MCP_HOST_FEATURE_OWNERS, EXPECTED_MCP_REVERSE_EDGES)
        self.assertEqual(len(MCP_HOST_FEATURE_OWNERS), 8)
        self.assertNotIn("legacy-import", dict(MCP_HOST_FEATURE_OWNERS))
        catalogue = "\n".join(
            "| `" + suite + "` | core | source | `crates/host/mcp-host/" + feature + "/**` |"
            for feature, suite in EXPECTED_MCP_REVERSE_EDGES
        )
        self.assertEqual(
            validate_ci19_catalogue(catalogue),
            EXPECTED_MCP_REVERSE_EDGES,
        )

    def test_ci19_catalogue_rejects_missing_renamed_duplicate_and_invented_folders(self):
        canonical = [
            "| `" + suite + "` | core | source | `crates/host/mcp-host/" + feature + "/**` |"
            for feature, suite in EXPECTED_MCP_REVERSE_EDGES
        ]
        mutations = (
            canonical[:-1],
            [line.replace("/settings/**", "/settings-ui/**") for line in canonical],
            canonical + [canonical[0]],
            canonical + ["| `core.extra` | core | source | `crates/host/mcp-host/extra/**` |"],
            canonical + ["| `core.legacy-import` | core | source | `crates/host/mcp-host/legacy-import/**` |"],
        )
        for mutated in mutations:
            with self.subTest(lines=len(mutated)):
                with self.assertRaisesRegex(ValueError, "invalid-ci19-catalogue"):
                    validate_ci19_catalogue("\n".join(mutated))

    def test_noncanonical_catalogue_edges_escalate_to_full_set(self):
        edge = MCP_HOST_REVERSE_EDGES[0]
        mutations = (
            tuple(candidate for candidate in SUITE_EDGES if candidate != edge),
            SUITE_EDGES + (edge,),
            tuple(
                SuiteEdge("crates/host/mcp-host/invented", "core.invented", "mcp-host-owner")
                if candidate == edge else candidate
                for candidate in SUITE_EDGES
            ),
        )
        for catalogue in mutations:
            with self.subTest(size=len(catalogue)):
                report = select_suites(
                    ("crates/host/mcp-host/settings/only.rs",),
                    FULL_SUITES,
                    GOOD_BASE_SHA,
                    catalogue=catalogue,
                    base_resolved=True,
                )
                self.assertTrue(report.escalated)
                self.assertEqual(report.would_select, tuple(sorted(FULL_SUITES)))
                self.assertIn("invalid-catalogue", report.reasons)

    def test_ci_control_changes_are_always_full_set_inputs(self):
        for path in (
            "kit/confinement/feedback_request.py",
            "kit/cache/policy.py",
            "ci/policy.json",
            "core-runtime/test_separation.py",
            "repos/16-ci-suite-catalogue.md",
        ):
            with self.subTest(path=path):
                report = select_suites(
                    (path,), FULL_SUITES, GOOD_BASE_SHA, base_resolved=True,
                )
                self.assertTrue(report.escalated)
                self.assertIn("protected-input", report.reasons)


if __name__ == "__main__":
    unittest.main()
