import copy
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import baselines_prepare
from baselines_prepare import (
    BaselinesRefusal,
    MAX_BLOCK_BYTES,
    MAX_SAFE_INTEGER,
    audit_summary,
    build_synthetic_block,
    canonical_bytes,
    check_runner_identity,
    compute_statistic,
    inspect_workflow_uses,
    load_block,
    probe_native_tools,
    render_summary,
    run_preparation,
    validate_action_pins,
    validate_block,
    validate_job_permissions,
    validate_lane_controls,
    validate_row,
    validate_run_context,
)

ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = ROOT / ".github/workflows/baselines-prepare.yml"
CONTROL_SHA = "a" * 40
RUN_ID = 123456789
RUN_ATTEMPT = 2
DIGEST = "1" * 64
IMAGE_VERSIONS = {"linux": "20261001.1.0", "windows": "20261001.2.0", "macos": "20261001.3"}
IMAGE_OS = {"linux": "ubuntu24", "windows": "win25", "macos": "macos15"}
RUNNER_OS = {"linux": "Linux", "windows": "Windows", "macos": "macOS"}
RUNNER_ARCH = {"linux": "x64", "windows": "x64", "macos": "arm64"}


def environment(platform, summary=None):
    values = {
        "GITHUB_SHA": CONTROL_SHA,
        "GITHUB_REPOSITORY": "keeldock-platform/platform-ci",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_RUN_ID": str(RUN_ID),
        "GITHUB_RUN_ATTEMPT": str(RUN_ATTEMPT),
        "RUNNER_ENVIRONMENT": "github-hosted",
        "RUNNER_OS": RUNNER_OS[platform],
        "RUNNER_ARCH": RUNNER_ARCH[platform].upper(),
        "ImageOS": IMAGE_OS[platform],
        "ImageVersion": IMAGE_VERSIONS[platform],
        "PATH": os.defpath,
    }
    if summary is not None:
        values["GITHUB_STEP_SUMMARY"] = str(summary)
    return values


def runner(platform):
    return check_runner_identity(platform, environment(platform))


def native_row(**changes):
    row = {
        "suite_id": "startup",
        "metric_id": "native.startup.splash",
        "variant_id": "cold",
        "batch_index": 0,
        "batch_kind": "primary",
        "observation_count": 3,
        "unit": "us",
        "status": "ok",
        "values": [30, 10, 20],
        "statistic_name": "median_x2",
        "statistic_value": 40,
        "profile_mode": "empty-cold",
        "seed_digest": DIGEST,
        "setup_count": 0,
        "primer_count": 0,
        "isolation_code": 0,
        "termination_code": 0,
        "cleanup_code": 0,
    }
    row.update(changes)
    return row


class RunContextTests(unittest.TestCase):
    def test_accepts_the_manual_main_context_and_returns_run_identity(self):
        self.assertEqual(
            validate_run_context(environment("linux"), CONTROL_SHA), (RUN_ID, RUN_ATTEMPT)
        )

    def test_refuses_every_context_deviation(self):
        for name, value in (
            ("GITHUB_SHA", "b" * 40),
            ("GITHUB_REPOSITORY", "other-owner/other-repo"),
            ("GITHUB_RUN_ID", "9" * 16),
            ("GITHUB_RUN_ATTEMPT", "9007199254740992"),
            ("GITHUB_EVENT_NAME", "push"),
            ("GITHUB_REF", "refs/heads/feature"),
            ("GITHUB_RUN_ID", "0"),
            ("GITHUB_RUN_ID", "12 3"),
            ("GITHUB_RUN_ATTEMPT", ""),
            ("GITHUB_RUN_ATTEMPT", "9" * 17),
        ):
            with self.subTest(name=name, value=value):
                changed = environment("linux")
                changed[name] = value
                with self.assertRaisesRegex(BaselinesRefusal, "run_context_invalid"):
                    validate_run_context(changed, CONTROL_SHA)
        missing = environment("linux")
        del missing["GITHUB_RUN_ID"]
        with self.assertRaisesRegex(BaselinesRefusal, "run_context_invalid"):
            validate_run_context(missing, CONTROL_SHA)
        for bad in ("A" * 40, "a" * 39, "a" * 40 + "\n", None, 7):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(BaselinesRefusal, "control_sha_invalid"):
                    validate_run_context(environment("linux"), bad)


class RunnerIdentityTests(unittest.TestCase):
    def test_accepts_the_three_hosted_classes(self):
        for platform in ("linux", "windows", "macos"):
            with self.subTest(platform=platform):
                result = check_runner_identity(platform, environment(platform))
                self.assertEqual(result["platform"], platform)
                self.assertEqual(result["image_os"], IMAGE_OS[platform])
                self.assertEqual(result["image_version"], IMAGE_VERSIONS[platform])

    def test_refuses_wrong_environment_os_architecture_and_image(self):
        cases = (
            ("RUNNER_ENVIRONMENT", "self-hosted", "runner_environment"),
            ("RUNNER_OS", "Windows", "runner_os"),
            ("RUNNER_ARCH", "ARM64", "runner_architecture"),
            ("ImageOS", "ubuntu22", "runner_image"),
            ("ImageOS", "Ubuntu24", "runner_image"),
            ("ImageVersion", "latest", "runner_image"),
            ("ImageVersion", "", "runner_image"),
        )
        for name, value, code in cases:
            with self.subTest(name=name, value=value):
                changed = environment("linux")
                changed[name] = value
                with self.assertRaisesRegex(BaselinesRefusal, code):
                    check_runner_identity("linux", changed)
        for name in ("RUNNER_ENVIRONMENT", "RUNNER_OS", "RUNNER_ARCH", "ImageOS", "ImageVersion"):
            with self.subTest(missing=name):
                changed = environment("macos")
                del changed[name]
                with self.assertRaises(BaselinesRefusal):
                    check_runner_identity("macos", changed)

    def test_refuses_unknown_platform(self):
        for platform in ("freebsd", "", None, ["linux"]):
            with self.subTest(platform=platform):
                with self.assertRaisesRegex(BaselinesRefusal, "platform_unknown"):
                    check_runner_identity(platform, environment("linux"))


class ActionPinTests(unittest.TestCase):
    def write_files(self, root, files):
        for name, text in files.items():
            path = Path(root) / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")

    def write_workflows(self, root, files):
        self.write_files(root, {".github/workflows/" + name: text for name, text in files.items()})

    def a_pin(self):
        return sorted(baselines_prepare.reviewed_pins())[0]

    def test_actual_repository_yaml_files_use_only_reviewed_full_sha_pins(self):
        result = validate_action_pins(ROOT)
        self.assertGreaterEqual(result["workflows"], 3)
        self.assertGreaterEqual(result["remote_pins"], 1)
        self.assertGreaterEqual(result["local_references"], 1)

    def test_reviewed_pins_come_from_the_shared_policy_constants(self):
        pins = baselines_prepare.reviewed_pins()
        policy = baselines_prepare.load_policy()
        self.assertIn(
            ("actions/create-github-app-token", policy.MACOS_SOURCE_READER_ACTION_SHA), pins
        )
        self.assertIn(("actions/cache/restore", policy.MACOS_CACHE_PROOF_ACTION_SHA), pins)
        self.assertIn(("actions/cache/save", policy.MACOS_CACHE_PROOF_ACTION_SHA), pins)
        names = {name for name, sha in pins}
        for name in ("actions/checkout", "actions/setup-node", "actions/upload-artifact"):
            self.assertIn(name, names)

    def test_extracts_block_flow_and_quoted_key_references(self):
        sha = "a" * 40
        text = "\n".join(
            (
                "jobs:",
                "  one:",
                "    uses: ./.github/workflows/other.yml",
                "    steps:",
                "      - name: step",
                "        uses: actions/checkout@" + sha,
                "      - uses: ./kit/bootstrap",
                "      - {uses: actions/one@" + sha + "}",
                "      - { name: flow, uses: actions/two@" + sha + " }",
                "      - {\"uses\": \"actions/three@" + sha + "\"}",
                "      - 'uses': 'actions/four@" + sha + "'",
                "        \"uses\": actions/five@" + sha,
                "      - run: echo uses: not-a-reference",
            )
        )
        self.assertEqual(
            inspect_workflow_uses(text),
            [
                "./.github/workflows/other.yml",
                "actions/checkout@" + sha,
                "./kit/bootstrap",
                "actions/one@" + sha,
                "actions/two@" + sha,
                "actions/three@" + sha,
                "actions/four@" + sha,
                "actions/five@" + sha,
                "not-a-reference",
            ],
        )
        self.assertEqual(inspect_workflow_uses("      - run: echo using: node"), [])

    def test_accepts_a_reviewed_pin_and_local_reference(self):
        pin = self.a_pin()
        with tempfile.TemporaryDirectory() as temporary:
            self.write_workflows(
                temporary,
                {
                    "one.yml": "jobs:\n  a:\n    steps:\n      - uses: "
                    + pin[0]
                    + "@"
                    + pin[1]
                    + "\n      - uses: ./kit/bootstrap\n"
                },
            )
            result = validate_action_pins(temporary)
        self.assertEqual(result, {"workflows": 1, "remote_pins": 1, "local_references": 1})

    def test_scans_yaml_extension_and_nested_action_files(self):
        pin = self.a_pin()
        bad = "jobs:\n  a:\n    steps:\n      - uses: actions/checkout@main\n"
        for relative in (
            ".github/workflows/two.yaml",
            "kit/nested/deeper/action.yml",
            "kit/nested/action.yaml",
        ):
            with self.subTest(relative=relative):
                with tempfile.TemporaryDirectory() as temporary:
                    self.write_workflows(
                        temporary,
                        {"one.yml": "jobs:\n  a:\n    steps:\n      - uses: " + pin[0] + "@" + pin[1] + "\n"},
                    )
                    self.write_files(temporary, {relative: bad})
                    with self.assertRaisesRegex(BaselinesRefusal, "pin_malformed"):
                        validate_action_pins(temporary)

    def test_refuses_mutable_short_unreviewed_and_escaping_references(self):
        pin = self.a_pin()
        cases = (
            ("actions/checkout@main", "pin_malformed"),
            ("actions/checkout@v4", "pin_malformed"),
            ("actions/checkout@" + "a" * 39, "pin_malformed"),
            ("actions/checkout@" + "A" * 40, "pin_malformed"),
            ("actions/checkout", "pin_malformed"),
            ("docker://alpine:3", "pin_malformed"),
            ("./../outside", "pin_malformed"),
            ("actions/checkout@" + "a" * 40, "pin_unreviewed"),
            (pin[0] + "@" + "b" * 40, "pin_unreviewed"),
            ("other/action@" + pin[1], "pin_unreviewed"),
        )
        shapes = (
            "jobs:\n  a:\n    steps:\n      - uses: {}\n",
            "jobs:\n  a:\n    steps:\n      - {{uses: {}}}\n",
            "jobs:\n  a:\n    steps:\n      - {{\"uses\": \"{}\"}}\n",
            "jobs:\n  a:\n    steps:\n      - 'uses': '{}'\n",
        )
        for reference, code in cases:
            for shape in shapes:
                with self.subTest(reference=reference, shape=shape):
                    with tempfile.TemporaryDirectory() as temporary:
                        self.write_workflows(temporary, {"one.yml": shape.format(reference)})
                        with self.assertRaisesRegex(BaselinesRefusal, code):
                            validate_action_pins(temporary)

    def test_refuses_a_missing_workflow_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(BaselinesRefusal, "workflow_unavailable"):
                validate_action_pins(temporary)
        with tempfile.TemporaryDirectory() as temporary:
            self.write_files(temporary, {"kit/nested/action.yml": "name: x\n"})
            with self.assertRaisesRegex(BaselinesRefusal, "workflow_unavailable"):
                validate_action_pins(temporary)


class JobPermissionTests(unittest.TestCase):
    def test_actual_lane_workflow_has_closed_permissions_and_cache_mode(self):
        self.assertEqual(validate_job_permissions(ROOT), 1)
        text = WORKFLOW.read_text(encoding="utf-8")
        self.assertEqual(validate_lane_controls(text), 1)
        for expected in (
            "  workflow_dispatch:\n",
            "permissions: {}\n",
            "cache-mode: none\n",
            "runs-on: ${{ matrix.runner }}\n",
            "runner: ubuntu-24.04\n",
            "runner: windows-2025\n",
            "runner: macos-15\n",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, text)
        for forbidden in (
            "uses:",
            "secrets.",
            "inputs:",
            "upload-artifact",
            "download-artifact",
            "attest",
            "cache:",
            "outputs:",
            "contents: read",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)

    def test_lane_controls_refuse_widened_permissions_and_cache_changes(self):
        base = WORKFLOW.read_text(encoding="utf-8")
        mutations = (
            ("permissions_invalid", base.replace("\npermissions: {}\n", "\npermissions:\n  contents: read\n", 1)),
            ("permissions_invalid", base.replace("    permissions: {}\n", "    permissions:\n      id-token: write\n", 1)),
            ("permissions_invalid", base.replace("    permissions: {}\n", "", 1)),
            ("permissions_invalid", base.replace("\npermissions: {}\n", "\n", 1)),
            ("permissions_invalid", base.replace("PYTHONDONTWRITEBYTECODE", "TOKEN: ${{ secrets.TOKEN }}\n      PYTHONDONTWRITEBYTECODE", 1)),
            ("permissions_invalid", base.replace("    timeout-minutes: 20\n", "    timeout-minutes: 20\n    secrets: inherit\n", 1)),
            ("cache_mode_invalid", base.replace("\ncache-mode: none\n", "\n", 1)),
            ("cache_mode_invalid", base.replace("    cache-mode: none\n", "", 1)),
            ("cache_mode_invalid", base.replace("    cache-mode: none\n", "    cache-mode: read\n", 1)),
        )
        for code, changed in mutations:
            with self.subTest(code=code, size=len(changed)):
                self.assertNotEqual(changed, base)
                with self.assertRaisesRegex(BaselinesRefusal, code):
                    validate_lane_controls(changed)

    def test_every_repository_workflow_declares_one_top_level_permissions_block(self):
        directory = ROOT / ".github/workflows"
        for path in sorted(directory.glob("*.yml")):
            with self.subTest(workflow=path.name):
                baselines_prepare.validate_top_level_permissions(path.read_text(encoding="utf-8"))
        with self.assertRaisesRegex(BaselinesRefusal, "permissions_invalid"):
            baselines_prepare.validate_top_level_permissions("name: x\njobs: {}\n")
        with self.assertRaisesRegex(BaselinesRefusal, "permissions_invalid"):
            baselines_prepare.validate_top_level_permissions(
                "permissions: {}\njobs: {}\npermissions: {}\n"
            )


class NativeToolTests(unittest.TestCase):
    def test_probe_reports_every_declared_tool_without_paths(self):
        for platform in ("linux", "windows", "macos"):
            with self.subTest(platform=platform):
                with mock.patch.object(baselines_prepare.shutil, "which", return_value="tool"):
                    result = probe_native_tools(platform, environment(platform))
                self.assertEqual(
                    [name for name, required, present in result],
                    [name for name, required in baselines_prepare.NATIVE_TOOLS[platform]],
                )
                self.assertTrue(all(present for name, required, present in result))

    def test_probe_marks_absent_tools(self):
        with mock.patch.object(baselines_prepare.shutil, "which", return_value=None):
            result = probe_native_tools("linux", environment("linux"))
        self.assertTrue(all(not present for name, required, present in result))
        self.assertTrue(any(required for name, required, present in result))

    def test_probe_refuses_unknown_platform(self):
        with self.assertRaisesRegex(BaselinesRefusal, "platform_unknown"):
            probe_native_tools("plan9", environment("linux"))


class StatisticTests(unittest.TestCase):
    def test_nearest_rank_estimators(self):
        values = list(range(1, 41))
        self.assertEqual(compute_statistic("p95", values), 38)
        self.assertEqual(compute_statistic("p05", values), 2)
        self.assertEqual(compute_statistic("median_x2", values), 41)
        self.assertEqual(compute_statistic("median_x2", [5, 1, 3]), 6)
        self.assertEqual(compute_statistic("median_x2", [9]), 18)
        self.assertEqual(compute_statistic("median_x2", [4, 1]), 5)
        self.assertEqual(compute_statistic("min", values), 1)
        self.assertEqual(compute_statistic("max", values), 40)
        self.assertEqual(compute_statistic("p95", [7]), 7)
        self.assertEqual(compute_statistic("p95", [5, 1, 3]), 5)

    def test_refuses_unknown_names_and_empty_vectors(self):
        for name, values in (("p99", [1]), ("median", [1]), (None, [1]), ("p95", []), ("p95", None), ("max", "1")):
            with self.subTest(name=name):
                with self.assertRaisesRegex(BaselinesRefusal, "record_statistic"):
                    compute_statistic(name, values)


class RecordRowTests(unittest.TestCase):
    def test_accepts_a_native_row_and_a_plain_row(self):
        self.assertTrue(validate_row(native_row()))
        plain = {
            key: value
            for key, value in native_row(
                suite_id="ipc",
                metric_id="ipc.echo-64",
                variant_id="default",
            ).items()
            if key not in baselines_prepare.NATIVE_ROW_FIELDS
        }
        self.assertTrue(validate_row(plain))

    def test_native_fields_are_required_for_native_metrics_and_refused_otherwise(self):
        missing = native_row()
        del missing["profile_mode"]
        with self.assertRaisesRegex(BaselinesRefusal, "record_fields"):
            validate_row(missing)
        extra = native_row(suite_id="ipc", metric_id="ipc.echo-64", variant_id="default")
        with self.assertRaisesRegex(BaselinesRefusal, "record_fields"):
            validate_row(extra)
        unknown = native_row()
        unknown["path"] = "forbidden"
        with self.assertRaisesRegex(BaselinesRefusal, "record_fields"):
            validate_row(unknown)

    def test_refuses_each_invalid_row_value(self):
        cases = (
            ("metric_id", "native.startup.unknown"),
            ("suite_id", "memory"),
            ("unit", "bytes"),
            ("variant_id", "other"),
            ("status", "passed"),
            ("batch_kind", "extra"),
            ("batch_index", 9),
            ("batch_index", -1),
            ("batch_index", True),
            ("batch_kind", "confirmation"),
            ("observation_count", 4),
            ("observation_count", True),
            ("values", [30, 10, -20]),
            ("values", [30, 10, 2.5]),
            ("values", [30, 10, True]),
            ("values", [30, 10, MAX_SAFE_INTEGER + 1]),
            ("values", "abc"),
            ("statistic_name", "mean"),
            ("statistic_value", 20),
            ("statistic_value", 40.0),
            ("profile_mode", "warm"),
            ("seed_digest", "G" * 64),
            ("setup_count", 1001),
            ("primer_count", -1),
            ("isolation_code", 256),
            ("termination_code", "0"),
            ("cleanup_code", None),
        )
        for field, value in cases:
            with self.subTest(field=field, value=value):
                with self.assertRaises(BaselinesRefusal):
                    validate_row(native_row(**{field: value}))
        with self.assertRaises(BaselinesRefusal):
            validate_row("row")
        with self.assertRaises(BaselinesRefusal):
            validate_row({"metric_id": ["x"]})

    def test_vector_length_is_bounded_by_the_registered_maximum(self):
        long_values = list(range(21))
        with self.assertRaisesRegex(BaselinesRefusal, "record_row"):
            validate_row(
                native_row(
                    values=long_values,
                    observation_count=21,
                    statistic_value=compute_statistic("median_x2", long_values),
                )
            )
        limit = list(range(1000))
        row = {
            key: value
            for key, value in native_row(
                suite_id="ipc",
                metric_id="ipc.echo-64",
                variant_id="default",
                values=limit,
                observation_count=1000,
                statistic_value=compute_statistic("median_x2", limit),
            ).items()
            if key not in baselines_prepare.NATIVE_ROW_FIELDS
        }
        self.assertTrue(validate_row(row))
        row["values"] = list(range(1001))
        row["observation_count"] = 1001
        with self.assertRaisesRegex(BaselinesRefusal, "record_row"):
            validate_row(row)

    def test_failed_rows_carry_partial_vectors_and_no_statistic(self):
        row = native_row(status="failed", values=[1, 2], observation_count=2, statistic_value=None)
        self.assertTrue(validate_row(row))
        row = native_row(status="invalid", values=[], observation_count=0, statistic_value=None)
        self.assertTrue(validate_row(row))
        with self.assertRaisesRegex(BaselinesRefusal, "record_statistic"):
            validate_row(native_row(status="failed", statistic_value=40))
        with self.assertRaisesRegex(BaselinesRefusal, "record_row"):
            validate_row(native_row(values=[], observation_count=0))

    def test_primary_and_confirmation_index_ranges_are_disjoint(self):
        for index in range(7):
            self.assertTrue(validate_row(native_row(batch_index=index)))
        for index in (7, 8):
            self.assertTrue(validate_row(native_row(batch_index=index, batch_kind="confirmation")))
            with self.assertRaisesRegex(BaselinesRefusal, "record_row"):
                validate_row(native_row(batch_index=index))
        with self.assertRaisesRegex(BaselinesRefusal, "record_row"):
            validate_row(native_row(batch_index=0, batch_kind="confirmation"))


class ProfileModeTests(unittest.TestCase):
    def test_cold_and_warm_variants_require_matching_profile_modes(self):
        for mode in ("empty-warm", "prepared-warm"):
            self.assertTrue(validate_row(native_row(variant_id="warm", profile_mode=mode)))
        for mode in ("empty-cold", "prepared-cold"):
            self.assertTrue(validate_row(native_row(variant_id="cold", profile_mode=mode)))
            with self.assertRaisesRegex(BaselinesRefusal, "record_row"):
                validate_row(native_row(variant_id="warm", profile_mode=mode))
        for mode in ("empty-warm", "prepared-warm"):
            with self.assertRaisesRegex(BaselinesRefusal, "record_row"):
                validate_row(native_row(variant_id="cold", profile_mode=mode))
        self.assertTrue(validate_row(native_row(variant_id="default", profile_mode="empty-warm")))

    def test_profile_mode_is_part_of_the_duplicate_row_key(self):
        block = build_synthetic_block(runner("linux"), CONTROL_SHA, RUN_ID, RUN_ATTEMPT)
        first = native_row(variant_id="default", profile_mode="empty-cold")
        second = native_row(variant_id="default", profile_mode="prepared-cold")
        block["rows"] = [first, second]
        self.assertTrue(validate_block(block))
        block["rows"] = [first, copy.deepcopy(first)]
        with self.assertRaisesRegex(BaselinesRefusal, "record_row"):
            validate_block(block)


class SyntheticRecordTests(unittest.TestCase):
    def block(self, platform="linux"):
        return build_synthetic_block(runner(platform), CONTROL_SHA, RUN_ID, RUN_ATTEMPT)

    def test_synthetic_block_is_valid_maximum_size_and_within_the_bound(self):
        block = self.block()
        self.assertTrue(validate_block(block))
        self.assertEqual(block["identity"]["evidence_class"], "synthetic")
        rows = block["rows"]
        self.assertGreater(len(rows), 9)
        self.assertLessEqual(len(rows), baselines_prepare.MAX_ROWS)
        self.assertEqual(len({(r["metric_id"], r["variant_id"], r["batch_index"]) for r in rows}), len(rows))
        for row in rows:
            self.assertIn(row["metric_id"], baselines_prepare.METRICS)
            self.assertTrue(all(len(str(value)) == 16 for value in row["values"]))
            self.assertLessEqual(len(row["values"]), 1000)
        self.assertEqual(len(rows[0]["values"]), 1000)
        size = len(canonical_bytes(block))
        self.assertGreater(size, 261000)
        self.assertLessEqual(size, MAX_BLOCK_BYTES)

    def test_canonical_serialization_is_stable_ascii_and_digest_bound(self):
        first = canonical_bytes(self.block())
        second = canonical_bytes(json.loads(first.decode("ascii")))
        self.assertEqual(first, second)
        self.assertEqual(first, first.decode("ascii").encode("ascii"))
        self.assertNotIn(b" ", first)
        self.assertNotIn(b"\n", first)

    def test_load_block_round_trips_and_refuses_malformed_payloads(self):
        block = self.block()
        payload = canonical_bytes(block)
        self.assertEqual(load_block(payload), block)
        duplicate = payload.replace(b'{"batch_index":0,', b'{"batch_index":0,"batch_index":0,', 1)
        self.assertNotEqual(duplicate, payload)
        for bad, code in (
            (duplicate, "record_malformed"),
            (payload[:-1], "record_malformed"),
            (b"[]", "record_fields"),
            (b"NaN", "record_malformed"),
            (b"\xff", "record_malformed"),
            (payload + b" " * MAX_BLOCK_BYTES, "record_oversize"),
            ("text", "record_malformed"),
        ):
            with self.subTest(code=code):
                with self.assertRaisesRegex(BaselinesRefusal, code):
                    load_block(bad)

    def test_block_validation_refuses_identity_and_row_defects(self):
        def mutate(change):
            block = copy.deepcopy(self.block())
            change(block)
            return block

        mutations = (
            lambda block: block.__setitem__("schema", "other"),
            lambda block: block.__setitem__("extra", 1),
            lambda block: block["identity"].__setitem__("source_sha", "z" * 40),
            lambda block: block["identity"].__setitem__("run_id", 0),
            lambda block: block["identity"].__setitem__("platform", "plan9"),
            lambda block: block["identity"].__setitem__("evidence_class", "other"),
            lambda block: block["identity"].__setitem__("image_version", "latest"),
            lambda block: block["identity"].__setitem__("toolchain", [{"name": "ruby", "version": "1"}]),
            lambda block: block["identity"].__setitem__(
                "toolchain",
                [{"name": "python", "version": "3"}, {"name": "python", "version": "4"}],
            ),
            lambda block: block["identity"].__setitem__("account_name", "forbidden"),
            lambda block: block["rows"].append(copy.deepcopy(block["rows"][0])),
            lambda block: block.__setitem__("rows", []),
            lambda block: block["rows"][0].__setitem__("values", block["rows"][0]["values"] + [1]),
        )
        for index, change in enumerate(mutations):
            with self.subTest(mutation=index):
                with self.assertRaises(BaselinesRefusal):
                    validate_block(mutate(change))

    def test_block_over_the_byte_bound_is_refused_not_truncated(self):
        block = self.block()
        extra = copy.deepcopy(block["rows"][0])
        extra["metric_id"] = "grid.virtual-1m-200"
        extra["suite_id"] = "grid"
        extra["values"] = extra["values"][:120]
        extra["observation_count"] = 120
        extra["statistic_value"] = compute_statistic("p95", extra["values"])
        block["rows"].append(extra)
        with self.assertRaisesRegex(BaselinesRefusal, "record_oversize"):
            validate_block(block)


class SummaryAuditTests(unittest.TestCase):
    def rendered(self, platform="linux"):
        block = build_synthetic_block(runner(platform), CONTROL_SHA, RUN_ID, RUN_ATTEMPT)
        return block, render_summary(block)

    def test_round_trip_through_surrounding_summary_content(self):
        block, text = self.rendered()
        surrounded = "earlier line\n\n" + text + "\nlater line\n"
        result = audit_summary(surrounded, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, "linux")
        self.assertEqual(result, block)
        lines = text.split("\n")
        self.assertEqual(len(lines), 6)
        self.assertTrue(lines[0].startswith("baseline-evidence-v1-begin rows=" + str(len(block["rows"])) + " "))
        self.assertTrue(lines[4].startswith("baseline-evidence-v1-end digest="))

    def test_audit_refuses_wrong_binding(self):
        block, text = self.rendered()
        for args in (
            ("b" * 40, RUN_ID, RUN_ATTEMPT, "linux"),
            (CONTROL_SHA, RUN_ID + 1, RUN_ATTEMPT, "linux"),
            (CONTROL_SHA, RUN_ID, RUN_ATTEMPT + 1, "linux"),
            (CONTROL_SHA, RUN_ID, RUN_ATTEMPT, "windows"),
        ):
            with self.subTest(args=args):
                with self.assertRaisesRegex(BaselinesRefusal, "audit_mismatch"):
                    audit_summary(text, *args)

    def test_audit_refuses_tampering_truncation_and_duplicates(self):
        block, text = self.rendered()
        lines = text.split("\n")
        payload_line = lines[2]
        tampered_payload = payload_line.replace('"method_version":1', '"method_version":2', 1)
        self.assertNotEqual(tampered_payload, payload_line)
        cases = (
            ("audit_mismatch", "\n".join(lines[:2] + [tampered_payload] + lines[3:])),
            ("audit_mismatch", text.replace("digest=" + lines[4].split("=")[1], "digest=" + "0" * 64, 1)),
            ("audit_mismatch", text.replace("rows=" + str(len(block["rows"])) + " ", "rows=1 ", 1)),
            ("audit_mismatch", text.replace("bytes=", "bytes=1", 1)),
            ("summary_markers", ""),
            ("summary_markers", text + text),
            ("summary_markers", "\n".join(lines[:4] + lines[5:])),
            ("summary_shape", text.replace(chr(96) * 3 + "text", chr(96) * 3 + "json", 1)),
            ("summary_shape", text.replace("evidence-class=synthetic", "evidence-class=synthetic extra=1", 1)),
            ("summary_shape", "\n".join([lines[0]] + lines[1:3] + ["", lines[3], lines[4]])),
        )
        for code, changed in cases:
            with self.subTest(code=code, size=len(changed)):
                with self.assertRaisesRegex(BaselinesRefusal, code):
                    audit_summary(changed, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, "linux")
        with self.assertRaisesRegex(BaselinesRefusal, "summary_shape"):
            audit_summary(None, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, "linux")

    def summary_for_payload(self, block, payload):
        fence = chr(96) * 3
        identity = block["identity"]
        digest = baselines_prepare.hashlib.sha256(payload).hexdigest()
        header = " ".join(
            (
                baselines_prepare.BEGIN_MARKER,
                "rows=" + str(len(block["rows"])),
                "bytes=" + str(len(payload)),
                "digest=" + digest,
                "control-sha=" + identity["control_sha"],
                "run-id=" + str(identity["run_id"]),
                "run-attempt=" + str(identity["run_attempt"]),
                "platform=" + identity["platform"],
                "evidence-class=" + identity["evidence_class"],
            )
        )
        footer = baselines_prepare.END_MARKER + " digest=" + digest
        return "\n".join((header, fence + "text", payload.decode("ascii"), fence, footer)) + "\n"

    def test_a_non_canonical_but_self_consistent_payload_is_refused(self):
        block = build_synthetic_block(runner("linux"), CONTROL_SHA, RUN_ID, RUN_ATTEMPT)
        block["rows"] = block["rows"][:3]
        spaced = json.dumps(block, sort_keys=True, separators=(", ", ": ")).encode("ascii")
        unsorted = json.dumps(block, separators=(",", ":")).encode("ascii")
        for payload in (spaced, unsorted):
            with self.subTest(size=len(payload)):
                self.assertNotEqual(payload, canonical_bytes(block))
                self.assertLessEqual(len(payload), MAX_BLOCK_BYTES)
                self.assertEqual(load_block(payload), block)
                text = self.summary_for_payload(block, payload)
                with self.assertRaisesRegex(BaselinesRefusal, "audit_mismatch"):
                    audit_summary(text, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, "linux")

    def test_the_lane_refuses_measured_evidence_and_runner_mismatches(self):
        block = build_synthetic_block(runner("linux"), CONTROL_SHA, RUN_ID, RUN_ATTEMPT)
        self.assertTrue(baselines_prepare.check_lane_block(block, runner("linux")))
        measured = copy.deepcopy(block)
        measured["identity"]["evidence_class"] = "measured"
        self.assertTrue(validate_block(measured))
        text = render_summary(measured)
        self.assertEqual(
            audit_summary(text, CONTROL_SHA, RUN_ID, RUN_ATTEMPT, "linux"), measured
        )
        with self.assertRaisesRegex(BaselinesRefusal, "audit_mismatch"):
            baselines_prepare.check_lane_block(measured, runner("linux"))
        for field, value in (
            ("image_version", "20250101.1.0"),
            ("image_os", "ubuntu22"),
            ("architecture", "arm64"),
            ("platform", "windows"),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(block)
                changed["identity"][field] = value
                with self.assertRaisesRegex(BaselinesRefusal, "audit_mismatch"):
                    baselines_prepare.check_lane_block(changed, runner("linux"))

    def test_append_refuses_text_that_would_pass_the_summary_limit(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = str(Path(temporary) / "summary")
            baselines_prepare.append_summary(path, "x" * (baselines_prepare.MAX_SUMMARY_BYTES - 10))
            with self.assertRaisesRegex(BaselinesRefusal, "summary_oversize"):
                baselines_prepare.append_summary(path, "y" * 11)
            baselines_prepare.append_summary(path, "y" * 10)
            self.assertEqual(
                len(baselines_prepare.read_summary(path)), baselines_prepare.MAX_SUMMARY_BYTES
            )

    def test_audit_refuses_non_ascii_payload(self):
        block, text = self.rendered()
        lines = text.split("\n")
        lines[2] = lines[2][:10] + "\u00e9" + lines[2][11:]
        with self.assertRaisesRegex(BaselinesRefusal, "summary_shape"):
            audit_summary("\n".join(lines), CONTROL_SHA, RUN_ID, RUN_ATTEMPT, "linux")

    def test_summary_file_helpers_require_absolute_paths_and_bound_size(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = str(Path(temporary) / "summary")
            baselines_prepare.append_summary(path, "one\n")
            baselines_prepare.append_summary(path, "two\n")
            self.assertEqual(baselines_prepare.read_summary(path), "one\ntwo\n")
            with open(path, "ab") as target:
                target.write(b"x" * baselines_prepare.MAX_SUMMARY_BYTES)
            with self.assertRaisesRegex(BaselinesRefusal, "summary_oversize"):
                baselines_prepare.read_summary(path)
        for bad in (None, "", "relative/summary"):
            with self.subTest(bad=bad):
                with self.assertRaisesRegex(BaselinesRefusal, "summary_unavailable"):
                    baselines_prepare.append_summary(bad, "x")
                with self.assertRaisesRegex(BaselinesRefusal, "summary_unavailable"):
                    baselines_prepare.read_summary(bad)


class PreparationRunTests(unittest.TestCase):
    def run_lane(self, platform, which_result="tool"):
        with tempfile.TemporaryDirectory() as temporary:
            summary = Path(temporary) / "summary.md"
            summary.write_text("previous step output\n", encoding="utf-8")
            lines = []
            with mock.patch.object(baselines_prepare.shutil, "which", return_value=which_result):
                try:
                    result = run_preparation(
                        ROOT,
                        platform,
                        CONTROL_SHA,
                        environment(platform, summary),
                        emit=lines.append,
                    )
                finally:
                    content = summary.read_text(encoding="utf-8")
        return result, lines, content

    def test_each_platform_prepares_and_writes_one_audited_block(self):
        for platform in ("linux", "windows", "macos"):
            with self.subTest(platform=platform):
                result, lines, content = self.run_lane(platform)
                self.assertEqual(result["platform"], platform)
                self.assertGreater(result["rows"], 9)
                self.assertEqual(result["jobs"], 1)
                self.assertEqual(result["tools_present"], result["tools_total"])
                self.assertLessEqual(result["bytes"], MAX_BLOCK_BYTES)
                self.assertTrue(content.startswith("previous step output\n"))
                self.assertEqual(content.count("baseline-evidence-v1-begin "), 1)
                self.assertEqual(content.count("baseline-evidence-v1-end "), 1)
                self.assertEqual(len(lines), len(baselines_prepare.NATIVE_TOOLS[platform]))
                for line in lines:
                    self.assertTrue(line.startswith("native-tool name="))

    def test_a_missing_required_tool_refuses_before_any_record_is_written(self):
        with tempfile.TemporaryDirectory() as temporary:
            summary = Path(temporary) / "summary.md"
            summary.write_text("", encoding="utf-8")
            with mock.patch.object(baselines_prepare.shutil, "which", return_value=None):
                with self.assertRaisesRegex(BaselinesRefusal, "native_tool_missing"):
                    run_preparation(
                        ROOT,
                        "linux",
                        CONTROL_SHA,
                        environment("linux", summary),
                        emit=lambda line: None,
                    )
            self.assertEqual(summary.read_text(encoding="utf-8"), "")

    def test_missing_summary_path_refuses(self):
        with mock.patch.object(baselines_prepare.shutil, "which", return_value="tool"):
            with self.assertRaisesRegex(BaselinesRefusal, "summary_unavailable"):
                run_preparation(
                    ROOT, "linux", CONTROL_SHA, environment("linux"), emit=lambda line: None
                )

    def test_main_prints_the_slice_verdict_and_every_outstanding_proof(self):
        with tempfile.TemporaryDirectory() as temporary:
            summary = Path(temporary) / "summary.md"
            summary.write_text("", encoding="utf-8")
            arguments = ["--root", str(ROOT), "--platform", "linux", "--control-sha", CONTROL_SHA]
            output = io.StringIO()
            with mock.patch.object(baselines_prepare.shutil, "which", return_value="tool"):
                with redirect_stdout(output):
                    status = baselines_prepare.main(arguments, environment("linux", summary))
            lines = output.getvalue().splitlines()
            self.assertEqual(status, 0)
            prefix = "baselines-prepare-slice=pins-permissions-identity-record-channel result=ok "
            self.assertTrue(lines[-1].startswith(prefix))
            self.assertIn("step1-complete=no", lines[-1])
            self.assertIn("control-sha=" + CONTROL_SHA, lines[-1])
            self.assertIn("digest=", lines[-1])
            outstanding = [
                line[len(baselines_prepare.OUTSTANDING_PREFIX):]
                for line in lines
                if line.startswith(baselines_prepare.OUTSTANDING_PREFIX)
            ]
            self.assertEqual(tuple(outstanding), baselines_prepare.OUTSTANDING_PROOFS)
            self.assertEqual(len(outstanding), 10)
            self.assertNotIn("baselines-prepare=ok", output.getvalue())
            output = io.StringIO()
            changed = environment("linux", summary)
            changed["GITHUB_EVENT_NAME"] = "push"
            with redirect_stdout(output):
                status = baselines_prepare.main(arguments, changed)
            self.assertEqual(status, 1)
            lines = output.getvalue().splitlines()
            self.assertEqual(
                lines[-1],
                "baselines-prepare-slice=pins-permissions-identity-record-channel "
                "result=refused code=run_context_invalid",
            )
            self.assertEqual(len(lines), 11)

    def test_a_missing_optional_tool_does_not_refuse(self):
        required = {
            name for name, is_required in baselines_prepare.NATIVE_TOOLS["linux"] if is_required
        }
        optional = {
            name for name, is_required in baselines_prepare.NATIVE_TOOLS["linux"] if not is_required
        }
        self.assertTrue(optional)

        def which(name, path=None):
            return "tool" if name in required else None

        with tempfile.TemporaryDirectory() as temporary:
            summary = Path(temporary) / "summary.md"
            summary.write_text("", encoding="utf-8")
            lines = []
            with mock.patch.object(baselines_prepare.shutil, "which", side_effect=which):
                result = run_preparation(
                    ROOT, "linux", CONTROL_SHA, environment("linux", summary), emit=lines.append
                )
        self.assertEqual(result["tools_present"], len(required))
        self.assertEqual(result["tools_total"], len(required) + len(optional))
        self.assertTrue(any("required=no present=no" in line for line in lines))

    def test_a_summary_that_already_holds_a_begin_marker_refuses(self):
        with tempfile.TemporaryDirectory() as temporary:
            summary = Path(temporary) / "summary.md"
            summary.write_text(
                baselines_prepare.BEGIN_MARKER + " rows=1 forged\n", encoding="utf-8"
            )
            with mock.patch.object(baselines_prepare.shutil, "which", return_value="tool"):
                with self.assertRaisesRegex(BaselinesRefusal, "summary_markers"):
                    run_preparation(
                        ROOT,
                        "linux",
                        CONTROL_SHA,
                        environment("linux", summary),
                        emit=lambda line: None,
                    )

    def test_a_summary_too_full_for_the_record_refuses_without_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            summary = Path(temporary) / "summary.md"
            filler = b"x" * (baselines_prepare.MAX_SUMMARY_BYTES - 1000)
            summary.write_bytes(filler)
            with mock.patch.object(baselines_prepare.shutil, "which", return_value="tool"):
                with self.assertRaisesRegex(BaselinesRefusal, "summary_oversize"):
                    run_preparation(
                        ROOT,
                        "linux",
                        CONTROL_SHA,
                        environment("linux", summary),
                        emit=lambda line: None,
                    )
            self.assertEqual(summary.read_bytes(), filler)

    def test_refusal_codes_are_closed_and_do_not_echo_values(self):
        self.assertEqual(BaselinesRefusal("unlisted").code, "record_malformed")
        self.assertEqual(BaselinesRefusal(7).code, "record_malformed")
        self.assertEqual(str(BaselinesRefusal("pin_unreviewed")), "pin_unreviewed")


if __name__ == "__main__":
    unittest.main(verbosity=2)
