import base64
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import tomllib
import unittest

import cargo_deny_qualification as subject
import cargo_deny_installer
import rust_license_gate


class QualificationEvidenceTests(unittest.TestCase):
    def test_empty_reviewed_bundle_keeps_every_flag_false(self):
        payload = Path(__file__).with_name("cargo_deny_qualification_reviewed.json").read_bytes()
        context = {
            "tool_version": "0.20.2",
            "policy_sha256": "a" * 64,
            "advisory_database_commit": "b" * 40,
            "advisory_database_generated_at_epoch": 1,
        }
        flags, evidence_sha256 = subject.derive_flags(payload, context)
        self.assertEqual(set(flags), {
            "cargo_deny_provenance_qualified", "cargo_deny_cli_qualified", "r108_qualified",
            "cargo_deny_issue_910_safe", "cargo_deny_affected_patched_controls_qualified",
        })
        self.assertTrue(all(value is False for value in flags.values()))
        self.assertEqual(evidence_sha256, hashlib.sha256(payload).hexdigest())

    def test_hand_set_qualification_flags_are_not_a_valid_bundle(self):
        payload = json.dumps({
            "schema_version": 1,
            "records": [],
            "r108_qualified": True,
            "cargo_deny_issue_910_safe": True,
        }, sort_keys=True, separators=(",", ":")).encode("ascii")
        flags, unused_digest = subject.derive_flags(payload, {})
        self.assertTrue(all(value is False for value in flags.values()))

    def test_review_digest_binds_record_bytes(self):
        reviewed = subject.review_record(
            {"record_type": "r108", "schema_version": 1},
            "reviewer-id", "review-ticket-1", reviewed_at=1,
        )
        self.assertTrue(subject._reviewed(reviewed))
        reviewed["record_type"] = "issue_910"
        self.assertFalse(subject._reviewed(reviewed))

    def test_platform_mapping_is_windows_import_safe(self):
        self.assertEqual(subject.platform_key("win32", "AMD64"), "windows-x86_64")

    def test_control_fixture_digests_are_stable_and_distinct(self):
        digests = {
            name: subject.fixture_sha256(name)
            for name in ("issue_910", "affected", "patched")
        }
        self.assertEqual(len(set(digests.values())), 3)
        self.assertTrue(all(subject._valid_hash(value) for value in digests.values()))

    def test_observation_records_include_binary_and_environment_bindings(self):
        identity = rust_license_gate.Identity("a" * 40, ".", os.getcwd(), "b" * 64)
        observation, unused_stdout, unused_stderr = subject.capture_observation(
            sys.executable, ("-c", "print('bound')"), os.getcwd(),
            {"HOME": os.environ.get("HOME", "/tmp"), "LANG": "C"}, identity,
            "c" * 64, "d" * 64, "e" * 40, "f" * 64,
        )
        self.assertEqual(observation["executable_sha256"], rust_license_gate._digest_file(sys.executable))
        self.assertEqual(observation["environment_keys"], ["HOME", "LANG"])
        self.assertTrue(subject._valid_hash(observation["environment_sha256"]))
        self.assertTrue(subject._check_process_observation(observation, expected_exit="zero"))

    def test_pinned_policy_checks_the_full_graph_without_target_pruning(self):
        policy = tomllib.loads(Path(__file__).with_name("cargo_deny_policy.toml").read_text("ascii"))
        self.assertNotIn("targets", policy["graph"])
        self.assertTrue(policy["graph"]["all-features"])
        self.assertFalse(policy["bans"]["build"]["include-dependencies"])
        self.assertTrue(policy["bans"]["multiple-versions-include-dev"])
        self.assertTrue(policy["licenses"]["include-dev"])
        self.assertTrue(policy["licenses"]["include-build"])
        self.assertEqual(policy["advisories"]["ignore"], [])

    def test_reviewed_bundle_qualifies_only_exact_invocations_and_installed_binary(self):
        bundle, context = _valid_bundle()
        flags, unused_digest = subject.derive_flags(bundle, context)
        self.assertTrue(all(flags.values()))
        flags, unused_digest = subject.derive_flags(bundle, None)
        self.assertTrue(all(value is False for value in flags.values()))

        payload = _decode_bundle(bundle)
        issue = _record(payload, "issue_910")
        observation = issue["platform_results"]["linux-x86_64"]["observation"]
        observation["argv"].extend(("--exclude", "vulnerable-crate"))
        observation["argv_sha256"] = subject._digest(observation["argv"])
        _reseal(issue)
        flags, unused_digest = subject.derive_flags(_encode_bundle(payload), context)
        self.assertFalse(flags["cargo_deny_issue_910_safe"])

        bundle, context = _valid_bundle()
        payload = _decode_bundle(bundle)
        r108 = _record(payload, "r108")
        observation = r108["checks"]["linux-x86_64"]["bans"]
        observation["argv"].extend(("--exclude", "vulnerable-crate"))
        observation["argv_sha256"] = subject._digest(observation["argv"])
        _reseal(r108)
        flags, unused_digest = subject.derive_flags(_encode_bundle(payload), context)
        self.assertFalse(flags["cargo_deny_cli_qualified"])
        self.assertFalse(flags["r108_qualified"])

        bundle, context = _valid_bundle()
        payload = _decode_bundle(bundle)
        issue = _record(payload, "issue_910")
        issue["platform_results"]["linux-x86_64"]["observation"]["executable_sha256"] = "f" * 64
        _reseal(issue)
        flags, unused_digest = subject.derive_flags(_encode_bundle(payload), context)
        self.assertFalse(flags["cargo_deny_issue_910_safe"])

        bundle, context = _valid_bundle()
        payload = _decode_bundle(bundle)
        issue = _record(payload, "issue_910")
        issue["platform_results"]["linux-x86_64"]["observation"]["executable_sha256"] = "f" * 64
        _reseal(issue)
        controls = _record(payload, "affected_patched")
        controls["platform_results"]["linux-x86_64"]["patched"]["fixture_sha256"] = "0" * 64
        _reseal(controls)
        flags, unused_digest = subject.derive_flags(_encode_bundle(payload), context)
        self.assertFalse(flags["cargo_deny_affected_patched_controls_qualified"])
        self.assertFalse(flags["cargo_deny_issue_910_safe"])

        wrong_install = dict(context, installed_executable_sha256="e" * 64)
        flags, unused_digest = subject.derive_flags(bundle, wrong_install)
        self.assertFalse(any(flags.values()))

    def test_capture_uses_the_bounded_production_subprocess_adapter(self):
        identity = rust_license_gate.Identity("a" * 40, ".", os.getcwd(), "b" * 64)
        observation, stdout, stderr = subject.capture_observation(
            sys.executable, ("-c", "print('adapter-capture')"), os.getcwd(),
            {"HOME": os.environ.get("HOME", "/tmp"), "LANG": "C", "LC_ALL": "C"},
            identity, "c" * 64, "d" * 64, "e" * 40, "f" * 64,
        )
        self.assertEqual(stdout, b"adapter-capture\n")
        self.assertEqual(stderr, b"")
        self.assertEqual(observation["argv"], ["-c", "print('adapter-capture')"])
        self.assertEqual(observation["argv_sha256"], subject._digest(observation["argv"]))
        self.assertTrue(subject._check_process_observation(observation, expected_exit="zero"))


def _valid_bundle():
    context = {
        "tool_version": subject.TOOL_VERSION,
        "policy_sha256": "a" * 64,
        "advisory_database_commit": "b" * 40,
        "advisory_database_generated_at_epoch": 1,
    }
    binaries = {
        platform_name: format(index + 1, "064x")
        for index, platform_name in enumerate(subject.PLATFORMS)
    }
    runtime_context = dict(
        context,
        installed_platform="linux-x86_64",
        installed_executable_sha256=binaries["linux-x86_64"],
    )
    release_map = {
        "linux-x86_64": cargo_deny_installer.RELEASES[("linux", "x86_64")],
        "darwin-arm64": cargo_deny_installer.RELEASES[("darwin", "arm64")],
        "windows-x86_64": cargo_deny_installer.RELEASES[("windows", "amd64")],
    }
    artifacts = {
        platform_name: {"asset_sha256": asset_sha256, "binary_sha256": binaries[platform_name]}
        for platform_name, (unused_target, asset_sha256) in release_map.items()
    }
    checks = {}
    for platform_name in subject.PLATFORMS:
        checks[platform_name] = {
            name: _observation(
                platform_name, name, "fixtures/cargo-deny/issue-910-cycle/Cargo.toml",
                binaries[platform_name], context, 0, b"ok",
            )
            for name in ("advisories", "bans", "licenses", "sources")
        }
    dependency_observation = _observation(
        "linux-x86_64", "advisories", "fixtures/cargo-deny/issue-910-cycle/Cargo.toml",
        binaries["linux-x86_64"], context, 0, b"ok",
    )
    dependency_chain = {
        "lock_sha256": dependency_observation["lock_sha256"],
        "manifest_sha256": dependency_observation["manifest_sha256"],
        "advisory_check": dependency_observation,
        "packages": [{"name": "example", "version": "1.0.0", "checksum": "c" * 64}],
        "unpatched_advisories": [],
    }
    r108 = {
        "schema_version": 1,
        "record_type": "r108",
        "context": context,
        "release_provenance_sha256": "d" * 64,
        "platform_artifacts": artifacts,
        "target_triples": list(subject.GRAPH_TARGETS),
        "toolchain": {
            platform_name: {
                "version": subject.TOOLCHAIN_VERSION,
                "build_sha256": "e" * 64,
                "target": subject.PLATFORM_TOOLCHAIN_TARGETS[platform_name],
            }
            for platform_name in subject.PLATFORMS
        },
        "checks": checks,
        "dependency_chain": dependency_chain,
        "exceptions": [],
    }
    issue_results = {}
    controls_results = {}
    for platform_name in subject.PLATFORMS:
        issue_observation = _observation(
            platform_name, "bans", "fixtures/cargo-deny/issue-910-cycle/Cargo.toml",
            binaries[platform_name], context, 0, b"ok",
        )
        issue_results[platform_name] = {
            "fixture_sha256": subject.fixture_sha256("issue_910"),
            "coverage": _all_coverage(),
            "observation": issue_observation,
        }
        affected_observation = _observation(
            platform_name, "advisories",
            "fixtures/cargo-deny/rustsec-2020-0071-affected/Cargo.toml",
            binaries[platform_name], context, 1, b"RUSTSEC-2020-0071",
        )
        patched_observation = _observation(
            platform_name, "advisories",
            "fixtures/cargo-deny/rustsec-2020-0071-patched/Cargo.toml",
            binaries[platform_name], context, 0, b"ok",
        )
        controls_results[platform_name] = {
            "advisory": "RUSTSEC-2020-0071",
            "affected": {
                "fixture_sha256": subject.fixture_sha256("affected"),
                "coverage": _all_coverage(),
                "observation": affected_observation,
                "diagnostic_sha256": hashlib.sha256(b"RUSTSEC-2020-0071").hexdigest(),
            },
            "patched": {
                "fixture_sha256": subject.fixture_sha256("patched"),
                "coverage": _all_coverage(),
                "observation": patched_observation,
            },
        }
    issue_record = {
        "schema_version": 1,
        "record_type": "issue_910",
        "context": context,
        "platform_results": issue_results,
    }
    controls_record = {
        "schema_version": 1,
        "record_type": "affected_patched",
        "context": context,
        "platform_results": controls_results,
    }
    records = [
        subject.review_record(r108, "test-reviewer", "test", reviewed_at=1),
        subject.review_record(issue_record, "test-reviewer", "test", reviewed_at=1),
        subject.review_record(controls_record, "test-reviewer", "test", reviewed_at=1),
    ]
    return _encode_bundle({"schema_version": 1, "records": records}), runtime_context


def _observation(platform_name, check_name, manifest, binary_sha256, context, exit_code, output):
    directory = subject.FIXTURE_DIRECTORIES[
        {"issue_910": "issue_910", "bans": "issue_910"}.get(check_name, check_name)
    ] if check_name in ("issue_910", "bans") else ""
    if not directory:
        directory = manifest.split("/")[-2]
    fixture_key = {
        "issue-910-cycle": "issue_910",
        "rustsec-2020-0071-affected": "affected",
        "rustsec-2020-0071-patched": "patched",
    }[directory]
    argv = [
        "--manifest-path", manifest,
        "--config", "cargo_deny_policy.toml",
        "--workspace", "--all-features", "--locked", "--offline", "check", check_name,
    ]
    encoded = base64.b64encode(output).decode("ascii")
    digest = hashlib.sha256(output).hexdigest()
    return {
        "exit_code": exit_code,
        "timed_out": False,
        "cancelled": False,
        "stdout_sha256": digest,
        "stderr_sha256": hashlib.sha256(b"").hexdigest(),
        "argv_sha256": subject._digest(argv),
        "argv": argv,
        "executable_sha256": binary_sha256,
        "environment_sha256": "f" * 64,
        "environment_keys": ["CARGO_HOME", "HOME", "LANG", "LC_ALL", "PATH"],
        "config_sha256": context["policy_sha256"],
        "manifest_sha256": subject.fixture_file_sha256(fixture_key, "Cargo.toml"),
        "lock_sha256": subject.fixture_file_sha256(fixture_key, "Cargo.lock"),
        "cwd_sha256": "1" * 64,
        "timeout_seconds": 120,
        "output_limit": 4096,
        "stdout_b64": encoded,
        "stderr_b64": "",
    }


def _all_coverage():
    return {
        "all_features": True,
        "all_targets": True,
        "development_dependencies": True,
        "build_dependencies": True,
    }


def _decode_bundle(bundle):
    return json.loads(bundle.decode("ascii"))


def _encode_bundle(payload):
    return subject._canonical_bytes(payload) + b"\n"


def _record(payload, record_type):
    return next(record for record in payload["records"] if record["record_type"] == record_type)


def _reseal(record):
    review = record.pop("review")
    record.update(subject.review_record(record, review["reviewer"], review["reference"], review["reviewed_at"]))


if __name__ == "__main__":
    unittest.main()
