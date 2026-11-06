import copy
import unittest

import feature_states as subject


def inventory():
    return {
        "schema_version": 1,
        "source_sha": "a" * 40,
        "catalogue_sha256": "b" * 64,
        "features": [
            {
                "id": "tokens", "requires": [], "uses": [],
                "assertions": ["tokens-state", "tokens-export"],
                "suite_ids": ["core.tokens"], "mcp_keys": [], "mcp_linked": False,
            },
            {
                "id": "ui", "requires": ["tokens"], "uses": [],
                "assertions": ["ui-state", "ui-route"],
                "suite_ids": ["core.ui"], "mcp_keys": ["ui.route"], "mcp_linked": True,
            },
            {
                "id": "search", "requires": [], "uses": ["tokens"],
                "assertions": ["search-state"], "suite_ids": ["core.search"],
                "mcp_keys": ["search.query"], "mcp_linked": False,
            },
        ],
        "matrix_arms": ["linux", "windows"],
        "shard_count": 4,
        "max_cases": 100,
        "max_assertions": 1000,
        "mcp_catalogue_keys": ["ui.route"],
    }


class FeatureStateCoverageTests(unittest.TestCase):
    def test_generation_is_deterministic_pairwise_complete_and_bounded(self):
        source = inventory()
        first = subject.generate_coverage(source)
        second = subject.generate_coverage(source)
        self.assertEqual(first, second)
        self.assertEqual(first["required_pairs"], first["covered_pairs"])
        self.assertGreater(len(first["required_pairs"]), 0)
        self.assertLessEqual(len(first["cases"]), source["max_cases"])
        self.assertLessEqual(first["assertion_count"], source["max_assertions"])
        self.assertEqual(first["features"], ["search", "tokens", "ui"])
        self.assertEqual(
            first["suite_runs"],
            [
                {"suite_id": suite, "matrix_arm": arm}
                for suite in ("core.search", "core.tokens", "core.ui")
                for arm in ("linux", "windows")
            ],
        )
        self.assertTrue(all(0 <= case["shard"] < source["shard_count"] for case in first["cases"]))

    def test_dependency_closure_excludes_impossible_pairs_and_mcp_absence_is_enforced(self):
        result = subject.generate_coverage(inventory())
        self.assertNotIn("ui=licensed&tokens=disabled", result["required_pairs"])
        states = [case["states"] for case in result["cases"]]
        self.assertTrue(all(
            state["ui"] == "disabled" or state["tokens"] != "disabled"
            for state in states
        ))
        disabled = next(case for case in result["cases"] if case["states"]["ui"] == "disabled")
        enabled = next(case for case in result["cases"] if case["states"]["ui"] == "free")
        self.assertNotIn("ui.route", disabled["mcp_visible"])
        self.assertIn("ui.route", enabled["mcp_visible"])
        self.assertNotIn("search.query", enabled["mcp_visible"])

    def test_coverage_validation_refuses_a_missing_case_assertion_arm_or_catalogue_edge(self):
        source = inventory()
        result = subject.generate_coverage(source)
        subject.validate_coverage(source, result)
        mutations = []
        missing_case = copy.deepcopy(result)
        missing_case["cases"].pop()
        mutations.append(missing_case)
        missing_assertion = copy.deepcopy(result)
        missing_assertion["cases"][0]["assertions"] = []
        mutations.append(missing_assertion)
        missing_arm = copy.deepcopy(result)
        missing_arm["suite_runs"].pop()
        mutations.append(missing_arm)
        bad_link = copy.deepcopy(result)
        bad_link["cases"][0]["mcp_visible"].append("ui.route")
        mutations.append(bad_link)
        for mutated in mutations:
            with self.subTest(cases=len(mutated["cases"])):
                with self.assertRaisesRegex(subject.FeatureStateError, "coverage-manifest-incomplete"):
                    subject.validate_coverage(source, mutated)

    def test_inventory_rejects_bad_edges_cycles_unlinked_keys_and_excessive_budgets(self):
        source = inventory()
        source["features"][0]["requires"] = ["missing"]
        with self.assertRaisesRegex(subject.FeatureStateError, "inventory-invalid"):
            subject.generate_coverage(source)

        source = inventory()
        source["features"][0]["requires"] = ["ui"]
        with self.assertRaisesRegex(subject.FeatureStateError, "dependency-cycle"):
            subject.generate_coverage(source)

        source = inventory()
        source["features"][1]["mcp_keys"] = ["unknown.route"]
        with self.assertRaisesRegex(subject.FeatureStateError, "mcp-link-unresolved"):
            subject.generate_coverage(source)

        source = inventory()
        source["max_cases"] = subject.MAX_CASES + 1
        with self.assertRaisesRegex(subject.FeatureStateError, "inventory-limit"):
            subject.generate_coverage(source)


if __name__ == "__main__":
    unittest.main()
