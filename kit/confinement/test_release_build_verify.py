import copy
import hashlib
import json
import unittest
from dataclasses import replace
from datetime import datetime, timezone

from release_build_verify import (
    EMPTY_ALLOWLIST,
    MAX_MANIFEST_BYTES,
    REFUSAL_CODES,
    BuildArtifact,
    BuildComparisonContext,
    BuildVerificationRefusal,
    EnvironmentValue,
    allowlist_from_mapping,
    compare_builds,
    encode_canonical_json,
    manifest_from_mapping,
    parse_manifest,
)


def digest(label):
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class ReleaseBuildVerifyTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)
        self.input_manifest_sha256 = digest("sealed-build-input-manifest")
        self.inputs = {
            "input_manifest_sha256": self.input_manifest_sha256,
            "source_sha": "a" * 40,
            "lock_receipts": [
                {
                    "name": "Cargo.lock",
                    "lock_sha256": digest("cargo-lock"),
                    "receipt_sha256": digest("cargo-receipt"),
                }
            ],
            "toolchain_identities": [
                {"name": "rustc", "version": "1.91.0", "sha256": digest("rustc")}
            ],
            "image_identities": [{"name": "linux-image", "sha256": digest("image")}],
            "environment_allowlist": [
                {"name": "SOURCE_DATE_EPOCH", "value": "1793274000"}
            ],
        }
        self.artifacts = [
            {"path": "release/app.bin", "size": 4, "sha256": digest("app")},
            {"path": "release/sbom.json", "size": 5, "sha256": digest("sbom")},
        ]
        self.left = self.manifest("build-a-001", "2026-10-29T10:00:00Z")
        self.right = self.manifest("build-b-001", "2026-10-29T10:01:00Z")
        self.context = BuildComparisonContext(
            self.input_manifest_sha256,
            tuple(item["path"] for item in self.artifacts),
            self.now,
        )

    def manifest(self, build_id, created_at, **changes):
        return {
            "schema_version": 2,
            "build_id": build_id,
            "created_at": created_at,
            "inputs": copy.deepcopy(changes.get("inputs", self.inputs)),
            "artifacts": copy.deepcopy(changes.get("artifacts", self.artifacts)),
            "observations": copy.deepcopy(changes.get("observations", {})),
        }

    def raw(self, value):
        return json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("ascii")

    def large_manifest(self, value, environment_count, observation_count):
        changed = copy.deepcopy(value)
        changed["inputs"]["environment_allowlist"] = [
            {"name": "VAR_%03d" % index, "value": "v" * 1024}
            for index in range(environment_count)
        ]
        changed["observations"] = {
            "obs_%03d" % index: "o" * 1024
            for index in range(observation_count)
        }
        return changed

    def compare(self, left=None, right=None, allowlist=EMPTY_ALLOWLIST, context=None):
        left_value = self.left if left is None else left
        right_value = self.right if right is None else right
        return compare_builds(
            parse_manifest(encode_canonical_json(left_value)),
            parse_manifest(encode_canonical_json(right_value)),
            self.context if context is None else context,
            allowlist,
        )

    def assert_refusal(self, code, **options):
        with self.assertRaises(BuildVerificationRefusal) as refusal:
            self.compare(**options)
        self.assertEqual(refusal.exception.code, code)

    def test_accepts_fresh_builds_with_equal_inputs_and_artifacts(self):
        result = self.compare()
        self.assertTrue(result.accepted)
        self.assertEqual(result.mode, "shadow")
        self.assertEqual(result.build_a_id, "build-a-001")
        self.assertEqual(result.build_b_id, "build-b-001")
        self.assertEqual(result.input_manifest_sha256, self.input_manifest_sha256)
        self.assertEqual(
            result.expected_output_paths_sha256,
            hashlib.sha256(
                encode_canonical_json(list(self.context.expected_output_paths))
            ).hexdigest(),
        )
        self.assertEqual(
            result.build_a_manifest_sha256,
            hashlib.sha256(encode_canonical_json(self.left)).hexdigest(),
        )
        self.assertEqual(
            result.build_b_manifest_sha256,
            hashlib.sha256(encode_canonical_json(self.right)).hexdigest(),
        )
        self.assertEqual(result.build_a_output_set_sha256, result.build_b_output_set_sha256)
        self.assertEqual(result.allowed_differences, ())
        self.assertEqual(len(result.comparison_sha256), 64)

    def test_refuses_input_identity_mismatch(self):
        changed = copy.deepcopy(self.right)
        changed["inputs"]["source_sha"] = "b" * 40
        self.assert_refusal("input_mismatch", right=changed)

    def test_refuses_different_sealed_input_manifest_digests(self):
        changed = copy.deepcopy(self.right)
        changed["inputs"]["input_manifest_sha256"] = digest("different-sealed-inputs")
        self.assert_refusal("input_mismatch", right=changed)

    def test_refuses_shared_digest_that_differs_from_trusted_input(self):
        changed_left = copy.deepcopy(self.left)
        changed_right = copy.deepcopy(self.right)
        changed_left["inputs"]["input_manifest_sha256"] = digest("wrong-sealed-inputs")
        changed_right["inputs"]["input_manifest_sha256"] = digest("wrong-sealed-inputs")
        self.assert_refusal("input_mismatch", left=changed_left, right=changed_right)

    def test_refuses_trusted_input_digest_that_differs_from_both_builds(self):
        context = replace(self.context, input_manifest_sha256=digest("other-inputs"))
        self.assert_refusal("input_mismatch", context=context)

    def test_refuses_missing_artifact(self):
        changed = copy.deepcopy(self.right)
        changed["artifacts"].pop(0)
        self.assert_refusal("artifact_missing", right=changed)

    def test_refuses_artifact_omitted_by_both_builds(self):
        changed_left = copy.deepcopy(self.left)
        changed_right = copy.deepcopy(self.right)
        changed_left["artifacts"].pop(0)
        changed_right["artifacts"].pop(0)
        self.assert_refusal("artifact_missing", left=changed_left, right=changed_right)

    def test_refuses_expected_output_missing_from_both_builds(self):
        context = replace(
            self.context,
            expected_output_paths=("release/app.bin", "release/sbom.json", "release/updates.bin"),
        )
        self.assert_refusal("artifact_missing", context=context)

    def test_refuses_unexpected_output_in_both_builds(self):
        context = replace(self.context, expected_output_paths=("release/app.bin",))
        self.assert_refusal("artifact_extra", context=context)

    def test_refuses_extra_artifact(self):
        changed = copy.deepcopy(self.right)
        changed["artifacts"].append(
            {"path": "release/z-extra.bin", "size": 1, "sha256": digest("extra")}
        )
        self.assert_refusal("artifact_extra", right=changed)

    def test_refuses_artifact_digest_mismatch(self):
        changed = copy.deepcopy(self.right)
        changed["artifacts"][0]["sha256"] = digest("changed-app")
        self.assert_refusal("artifact_digest_mismatch", right=changed)

    def test_refuses_artifact_size_mismatch(self):
        changed = copy.deepcopy(self.right)
        changed["artifacts"][0]["size"] = 6
        self.assert_refusal("artifact_size_mismatch", right=changed)

    def test_refuses_observation_difference_without_an_allowlist_entry(self):
        left = self.manifest(
            "build-a-001", "2026-10-29T10:00:00Z", observations={"runner_id": "runner-a"}
        )
        right = self.manifest(
            "build-b-001", "2026-10-29T10:01:00Z", observations={"runner_id": "runner-b"}
        )
        self.assert_refusal("unallowlisted_difference", left=left, right=right)

    def test_accepts_only_a_justified_versioned_observation_allowance(self):
        left = self.manifest(
            "build-a-001", "2026-10-29T10:00:00Z", observations={"runner_id": "runner-a"}
        )
        right = self.manifest(
            "build-b-001", "2026-10-29T10:01:00Z", observations={"runner_id": "runner-b"}
        )
        allowlist = allowlist_from_mapping(
            {
                "version": 2,
                "entries": [
                    {
                        "field": "observations.runner_id",
                        "justification": "runner instance identity changes per build",
                    }
                ],
            }
        )
        result = self.compare(left, right, allowlist)
        self.assertEqual(result.allowlist_version, 2)
        self.assertEqual(result.allowed_differences, ("observations.runner_id",))

    def test_comparison_digest_binds_allowed_observation_values(self):
        allowlist = allowlist_from_mapping(
            {
                "version": 2,
                "entries": [
                    {
                        "field": "observations.runner_id",
                        "justification": "runner instance identity changes per build",
                    }
                ],
            }
        )
        first_left = self.manifest(
            "build-a-001", "2026-10-29T10:00:00Z", observations={"runner_id": "runner-a"}
        )
        first_right = self.manifest(
            "build-b-001", "2026-10-29T10:01:00Z", observations={"runner_id": "runner-b"}
        )
        second_left = copy.deepcopy(first_left)
        second_right = copy.deepcopy(first_right)
        second_left["observations"]["runner_id"] = "runner-c"
        second_right["observations"]["runner_id"] = "runner-d"
        first = self.compare(first_left, first_right, allowlist)
        second = self.compare(second_left, second_right, allowlist)
        self.assertEqual(first.allowed_differences, second.allowed_differences)
        self.assertNotEqual(first.build_a_manifest_sha256, second.build_a_manifest_sha256)
        self.assertNotEqual(first.build_b_manifest_sha256, second.build_b_manifest_sha256)
        self.assertNotEqual(first.comparison_sha256, second.comparison_sha256)

    def test_comparison_digest_binds_equal_observation_values(self):
        first_left = self.manifest(
            "build-a-001", "2026-10-29T10:00:00Z", observations={"runner_id": "same-a"}
        )
        first_right = self.manifest(
            "build-b-001", "2026-10-29T10:01:00Z", observations={"runner_id": "same-a"}
        )
        second_left = copy.deepcopy(first_left)
        second_right = copy.deepcopy(first_right)
        second_left["observations"]["runner_id"] = "same-b"
        second_right["observations"]["runner_id"] = "same-b"
        first = self.compare(first_left, first_right)
        second = self.compare(second_left, second_right)
        self.assertEqual(first.allowed_differences, ())
        self.assertEqual(second.allowed_differences, ())
        self.assertNotEqual(first.comparison_sha256, second.comparison_sha256)

    def test_refuses_stale_build_identity(self):
        stale = copy.deepcopy(self.left)
        stale["created_at"] = "2026-10-27T11:59:59Z"
        self.assert_refusal("build_identity_stale", left=stale)

    def test_refuses_reused_build_identity(self):
        reused = copy.deepcopy(self.right)
        reused["build_id"] = self.left["build_id"]
        self.assert_refusal("build_identity_reused", right=reused)

    def test_refuses_build_identity_seen_in_prior_evidence(self):
        self.assert_refusal(
            "build_identity_reused",
            context=replace(self.context, seen_build_ids=("build-b-001",)),
        )

    def test_refuses_oversize_manifest(self):
        with self.assertRaises(BuildVerificationRefusal) as refusal:
            parse_manifest(b"x" * (MAX_MANIFEST_BYTES + 1))
        self.assertEqual(refusal.exception.code, "manifest_oversize")

    def test_accepts_bounded_bytes_and_model_manifests(self):
        left = self.large_manifest(self.left, 100, 20)
        right = self.large_manifest(self.right, 100, 20)
        left_raw = self.raw(left)
        right_raw = self.raw(right)
        self.assertLessEqual(len(left_raw), MAX_MANIFEST_BYTES)
        self.assertLessEqual(len(right_raw), MAX_MANIFEST_BYTES)
        self.assertTrue(compare_builds(left_raw, right_raw, self.context).accepted)
        self.assertTrue(
            compare_builds(
                manifest_from_mapping(left), manifest_from_mapping(right), self.context
            ).accepted
        )

    def test_refuses_oversize_bytes_mapping_and_model_equally(self):
        changed = self.large_manifest(self.left, 128, 20)
        raw = self.raw(changed)
        self.assertGreater(len(raw), MAX_MANIFEST_BYTES)
        baseline = parse_manifest(encode_canonical_json(self.left))
        model = replace(
            baseline,
            inputs=replace(
                baseline.inputs,
                environment_allowlist=tuple(
                    EnvironmentValue(item["name"], item["value"])
                    for item in changed["inputs"]["environment_allowlist"]
                ),
            ),
            observations=tuple(sorted(changed["observations"].items())),
        )
        for value in (raw, model):
            with self.assertRaises(BuildVerificationRefusal) as refusal:
                compare_builds(
                    value, parse_manifest(encode_canonical_json(self.right)), self.context
                )
            self.assertEqual(refusal.exception.code, "manifest_oversize")
        with self.assertRaises(BuildVerificationRefusal) as refusal:
            manifest_from_mapping(changed)
        self.assertEqual(refusal.exception.code, "manifest_oversize")

    def test_refuses_excess_structural_tokens_for_bytes_and_model(self):
        changed = copy.deepcopy(self.left)
        changed["artifacts"] = [
            {"path": "release/output-%03d.bin" % index, "size": 1, "sha256": digest("part")}
            for index in range(512)
        ]
        raw = self.raw(changed)
        self.assertLess(len(raw), MAX_MANIFEST_BYTES)
        baseline = parse_manifest(encode_canonical_json(self.left))
        model = replace(
            baseline,
            artifacts=tuple(
                BuildArtifact(item["path"], item["size"], item["sha256"])
                for item in changed["artifacts"]
            ),
        )
        for value in (raw, model):
            with self.assertRaises(BuildVerificationRefusal) as refusal:
                compare_builds(
                    value, parse_manifest(encode_canonical_json(self.right)), self.context
                )
            self.assertEqual(refusal.exception.code, "manifest_malformed")

    def test_refuses_noncanonical_manifest(self):
        raw = encode_canonical_json(self.left) + b"\n"
        with self.assertRaises(BuildVerificationRefusal) as refusal:
            parse_manifest(raw)
        self.assertEqual(refusal.exception.code, "manifest_malformed")

    def test_refuses_previous_manifest_schema(self):
        changed = copy.deepcopy(self.left)
        changed["schema_version"] = 1
        with self.assertRaises(BuildVerificationRefusal) as refusal:
            parse_manifest(encode_canonical_json(changed))
        self.assertEqual(refusal.exception.code, "manifest_malformed")

    def test_refuses_duplicate_manifest_keys(self):
        with self.assertRaises(BuildVerificationRefusal) as refusal:
            parse_manifest(b'{"schema_version":1,"schema_version":1}')
        self.assertEqual(refusal.exception.code, "manifest_malformed")

    def test_parser_seed_mutations_accept_only_models_or_stable_refusals(self):
        canonical = encode_canonical_json(self.left)
        candidates = [b"", b"null", b"[]", b"{}", canonical[: len(canonical) // 2]]
        step = max(1, len(canonical) // 16)
        for offset in range(0, len(canonical), step):
            changed = bytearray(canonical)
            changed[offset] ^= 1
            candidates.append(bytes(changed))
        for payload in candidates:
            try:
                parsed = parse_manifest(payload)
                self.assertEqual(parsed.schema_version, 2)
            except BuildVerificationRefusal as refusal:
                self.assertIn(refusal.code, REFUSAL_CODES)

    def test_refuses_unjustified_allowlist_entry(self):
        with self.assertRaises(BuildVerificationRefusal) as refusal:
            allowlist_from_mapping(
                {
                    "version": 1,
                    "entries": [{"field": "observations.runner_id", "justification": "  "}],
                }
            )
        self.assertEqual(refusal.exception.code, "allowlist_invalid")


if __name__ == "__main__":
    unittest.main()
