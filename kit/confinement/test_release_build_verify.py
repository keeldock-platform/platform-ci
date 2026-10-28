import copy
import hashlib
import unittest
from datetime import datetime, timezone

from release_build_verify import (
    EMPTY_ALLOWLIST,
    MAX_MANIFEST_BYTES,
    REFUSAL_CODES,
    BuildVerificationRefusal,
    allowlist_from_mapping,
    compare_builds,
    encode_canonical_json,
    parse_manifest,
)


def digest(label):
    return hashlib.sha256(label.encode("ascii")).hexdigest()


class ReleaseBuildVerifyTests(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 10, 29, 12, 0, 0, tzinfo=timezone.utc)
        self.inputs = {
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

    def manifest(self, build_id, created_at, inputs=None, artifacts=None, observations=None):
        return {
            "schema_version": 1,
            "build_id": build_id,
            "created_at": created_at,
            "inputs": copy.deepcopy(self.inputs if inputs is None else inputs),
            "artifacts": copy.deepcopy(self.artifacts if artifacts is None else artifacts),
            "observations": copy.deepcopy({} if observations is None else observations),
        }

    def compare(self, left=None, right=None, allowlist=EMPTY_ALLOWLIST, seen_build_ids=()):
        left_value = self.left if left is None else left
        right_value = self.right if right is None else right
        return compare_builds(
            parse_manifest(encode_canonical_json(left_value)),
            parse_manifest(encode_canonical_json(right_value)),
            self.now,
            allowlist,
            seen_build_ids,
        )

    def assert_refusal(
        self, code, left=None, right=None, allowlist=EMPTY_ALLOWLIST, seen_build_ids=()
    ):
        with self.assertRaises(BuildVerificationRefusal) as refusal:
            self.compare(left, right, allowlist, seen_build_ids)
        self.assertEqual(refusal.exception.code, code)

    def test_accepts_fresh_builds_with_equal_inputs_and_artifacts(self):
        result = self.compare()
        self.assertTrue(result.accepted)
        self.assertEqual(result.mode, "shadow")
        self.assertEqual(result.build_a_id, "build-a-001")
        self.assertEqual(result.build_b_id, "build-b-001")
        self.assertEqual(result.build_a_output_set_sha256, result.build_b_output_set_sha256)
        self.assertEqual(result.allowed_differences, ())
        self.assertEqual(len(result.comparison_sha256), 64)

    def test_refuses_input_identity_mismatch(self):
        changed = copy.deepcopy(self.right)
        changed["inputs"]["source_sha"] = "b" * 40
        self.assert_refusal("input_mismatch", right=changed)

    def test_refuses_missing_artifact(self):
        changed = copy.deepcopy(self.right)
        changed["artifacts"].pop(0)
        self.assert_refusal("artifact_missing", right=changed)

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
            "build_identity_reused", seen_build_ids=("build-b-001",)
        )

    def test_refuses_oversize_manifest(self):
        with self.assertRaises(BuildVerificationRefusal) as refusal:
            parse_manifest(b"x" * (MAX_MANIFEST_BYTES + 1))
        self.assertEqual(refusal.exception.code, "manifest_oversize")

    def test_refuses_noncanonical_manifest(self):
        raw = encode_canonical_json(self.left) + b"\n"
        with self.assertRaises(BuildVerificationRefusal) as refusal:
            parse_manifest(raw)
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
                self.assertEqual(parsed.schema_version, 1)
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
