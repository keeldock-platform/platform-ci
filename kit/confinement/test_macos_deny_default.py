import ast
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import unittest
from contextlib import ExitStack, redirect_stderr, redirect_stdout
from pathlib import Path, PurePosixPath
from types import SimpleNamespace
from unittest.mock import patch

import macos_canary_scan
import macos_deny_default as deny


CONTROL_SHA = "ab" * 20
IDENTITY = {
    "product_version": "15.7.9",
    "image_os": "macos15",
    "runner_image_os": "macos-15-arm64",
    "image_version": "20260907.0337.1",
    "architecture": "arm64",
}
EXPECTED_CHANNELS = (
    "https",
    "dns",
    "redirect",
    "proxy",
    "runner_ipc",
    "raw_logs",
    "artifact_upload",
    "cache_upload",
    "runner_files",
    "process_memory",
    "boundary_disablement",
)
EXPECTED_CHANNEL_STATES = {
    "https": "blocked",
    "dns": "blocked",
    "redirect": "blocked",
    "proxy": "blocked",
    "runner_ipc": "blocked",
    "raw_logs": "captured_private",
    "artifact_upload": "pending_audit",
    "cache_upload": "pending_audit",
    "runner_files": "blocked",
    "process_memory": "blocked",
    "boundary_disablement": "blocked",
}
REQUIRED_PROOF_TRUE = (
    "actions_environment",
    "artifact_upload",
    "boundary_disablement",
    "cache_upload",
    "environment_canary",
    "dns",
    "dns_resolver",
    "https",
    "launchctl",
    "logger_attempted",
    "native_pass",
    "os_log_attempted",
    "outside_write",
    "positive_read",
    "positive_write",
    "process_memory",
    "proxy",
    "raw_log_channels",
    "redirect",
    "runner_files",
    "runner_ipc",
    "staging_write",
    "syslog",
)
EXPECTED_PROOF_KEYS = set(REQUIRED_PROOF_TRUE) | {
    "memory_canary",
    "readable_file_canary",
    "tty",
}


def synthetic_path(*parts):
    return os.path.abspath(os.path.join(os.sep, "synthetic", *parts))


class PosixFixturePath:
    def __init__(self, value):
        self.value = PurePosixPath(str(value))

    def resolve(self, strict=False):
        return self.value


def directory_metadata(device=1, inode=1):
    return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_dev=device, st_ino=inode)


def regular_metadata(device=1, inode=2):
    return SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_dev=device, st_ino=inode)


def valid_proof():
    evidence = dict.fromkeys(REQUIRED_PROOF_TRUE, True)
    evidence.update(
        {
            "memory_canary": "absent",
            "readable_file_canary": "absent",
            "tty": "blocked",
        }
    )
    return evidence


def proof_output(proof, canary):
    lines = [marker + canary for marker in deny.WORKFLOW_MARKERS]
    lines.append(b"KD-PROOF:" + json.dumps(proof, sort_keys=True, separators=(",", ":")).encode("ascii"))
    lines.append(canary)
    return b"\n".join(lines) + b"\n", canary + b"\n"


class CanaryScannerTests(unittest.TestCase):
    def setUp(self):
        self.root = os.path.normpath(os.path.abspath(os.path.join(os.sep, "synthetic-safe")))
        self.directory = self.root

    def walk(self, filenames=(), subdirectories=(), error=None):
        directory = self.directory

        def adapter(root, *, followlinks, onerror):
            if error is not None:
                onerror(error)
            yield directory, list(subdirectories), list(filenames)

        return adapter

    def scan(self, payloads=None, **options):
        payloads = {} if payloads is None else payloads

        def open_file(path, mode):
            return io.BytesIO(payloads[path])

        def stat_path(path):
            if path == self.root:
                return directory_metadata()
            return regular_metadata()

        return macos_canary_scan.scan_readable_roots(
            [self.root],
            b"canary-marker",
            walk=options.pop("walk", self.walk()),
            open_file=options.pop("open_file", open_file),
            stat_path=options.pop("stat_path", stat_path),
            real_path=options.pop("real_path", lambda path: path),
            is_link=options.pop("is_link", lambda _path: False),
            is_file=options.pop("is_file", lambda _path: True),
            clock=options.pop("clock", lambda: 1),
            **options,
        )

    def test_partial_walk_with_error_is_never_credited_as_a_complete_scan(self):
        with self.assertRaises(macos_canary_scan.ScanIncomplete):
            self.scan(
                payloads={os.path.join(self.root, "first"): b"safe"},
                walk=self.walk(filenames=("first",), error=OSError("walk failed")),
            )

    def test_walk_iterator_failure_is_refused_after_partial_results(self):
        def broken_walk(_root, *, followlinks, onerror):
            yield self.directory, [], ["first"]
            raise OSError("walk failed")

        with self.assertRaises(macos_canary_scan.ScanIncomplete):
            self.scan(payloads={os.path.join(self.root, "first"): b"safe"}, walk=broken_walk)

    def test_scan_timeout_file_limit_and_byte_limit_refuse_partial_evidence(self):
        with self.subTest(kind="timeout"):
            ticks = iter((1, 3, 3, 3, 3))
            with self.assertRaises(macos_canary_scan.ScanIncomplete):
                self.scan(clock=lambda: next(ticks), deadline_seconds=1)
        with self.subTest(kind="file_limit"):
            with self.assertRaises(macos_canary_scan.ScanIncomplete):
                self.scan(
                    payloads={
                        os.path.join(self.root, "one"): b"",
                        os.path.join(self.root, "two"): b"",
                    },
                    walk=self.walk(filenames=("one", "two")),
                    max_files=1,
                )
        with self.subTest(kind="byte_limit"):
            with self.assertRaises(macos_canary_scan.ScanIncomplete):
                self.scan(
                    payloads={os.path.join(self.root, "one"): b"four"},
                    walk=self.walk(filenames=("one",)),
                    max_bytes=3,
                    chunk_size=2,
                )

    def test_canary_split_across_chunks_is_still_detected(self):
        needle = b"canary-marker"
        first = needle[:5]
        second = needle[5:]
        payload = b"prefix" + first + second + b"suffix"
        with self.assertRaises(macos_canary_scan.CanaryPresent):
            self.scan(
                payloads={os.path.join(self.root, "one"): payload},
                walk=self.walk(filenames=("one",)),
                chunk_size=len(first) + 1,
            )

    def test_symlink_targets_and_noncanonical_paths_outside_roots_refuse(self):
        escaped = os.path.normpath(os.path.join(self.root, "link"))
        with self.subTest(kind="directory_link"):
            with self.assertRaises(macos_canary_scan.ScanIncomplete):
                self.scan(
                    walk=self.walk(subdirectories=("link",)),
                    real_path=lambda path: os.path.join(os.sep, "synthetic-outside") if path == escaped else path,
                    is_link=lambda path: path == escaped,
                )
        with self.subTest(kind="file_link"):
            file_path = os.path.join(self.root, "link")
            with self.assertRaises(macos_canary_scan.ScanIncomplete):
                self.scan(
                    walk=self.walk(filenames=("link",)),
                    real_path=lambda path: os.path.join(os.sep, "synthetic-outside") if path == file_path else path,
                    is_link=lambda path: path == file_path,
                )

    def test_invalid_roots_and_unreadable_files_refuse_the_scan(self):
        with self.assertRaises(macos_canary_scan.ScanIncomplete):
            macos_canary_scan.scan_readable_roots(
                [self.root, self.root], b"marker", real_path=lambda path: path
            )

        def unreadable(_root, *, followlinks, onerror):
            raise PermissionError("unreadable")
            yield

        with self.assertRaises(macos_canary_scan.ScanIncomplete):
            self.scan(walk=unreadable)

        def stat_error(path):
            if path == os.path.join(self.root, "broken"):
                raise OSError("metadata unavailable")
            if path == self.root:
                return directory_metadata()
            return regular_metadata()

        with self.assertRaises(macos_canary_scan.ScanIncomplete):
            self.scan(
                walk=self.walk(filenames=("broken",)),
                stat_path=stat_error,
            )

    def test_root_metadata_and_sibling_prefixes_are_not_treated_as_covered(self):
        with self.subTest(kind="root_metadata"):
            with self.assertRaises(macos_canary_scan.ScanIncomplete):
                self.scan(stat_path=lambda _path: regular_metadata())
        sibling = os.path.join(self.root, "..", "synthetic-safe-private", "secret")
        with self.subTest(kind="sibling_prefix"):
            with self.assertRaises(macos_canary_scan.ScanIncomplete):
                self.scan(
                    walk=self.walk(filenames=(os.path.join("..", "synthetic-safe-private", "secret"),)),
                    real_path=os.path.normpath,
                )


class DenyDefaultPolicyTests(unittest.TestCase):
    def assert_proof_refusal(self, stdout, stderr, canary):
        with self.assertRaises(deny.Refusal) as raised:
            deny._validate_proof_payload(stdout, stderr, canary)
        self.assertEqual(raised.exception.reason, "channel_not_blocked")
        self.assertIn(raised.exception.stage, deny.STAGES)
        if raised.exception.channel is not None:
            self.assertIn(raised.exception.channel, deny.CHANNELS)
        return raised.exception

    def test_refusal_diagnostics_use_only_fixed_safe_values(self):
        valid = deny.Refusal("channel_not_blocked", stage="walk", channel="runner_files")
        self.assertEqual(valid.reason, "channel_not_blocked")
        self.assertEqual(valid.stage, "walk")
        self.assertEqual(valid.channel, "runner_files")
        self.assertEqual(
            deny.refusal_line(valid),
            "macos-confinement=refused reason=channel_not_blocked stage=walk channel=runner_files",
        )
        invalid = deny.Refusal(
            "untrusted-reason",
            stage="untrusted-stage",
            channel="untrusted-channel",
        )
        self.assertEqual(invalid.reason, "native_preflight_unavailable")
        self.assertEqual(invalid.stage, "preflight")
        self.assertIsNone(invalid.channel)
        self.assertNotIn("untrusted", str(invalid))
        self.assertEqual(
            deny.refusal_line(invalid),
            "macos-confinement=refused reason=native_preflight_unavailable stage=preflight",
        )

    def test_canary_is_bound_to_a_full_lowercase_control_sha(self):
        expected = deny.CANARY_PREFIX + hashlib.sha256(
            deny.CANARY_DOMAIN + CONTROL_SHA.encode("ascii")
        ).hexdigest()[:32].encode("ascii")
        self.assertEqual(deny.canary_bytes(CONTROL_SHA), expected)
        for invalid in (CONTROL_SHA.upper(), CONTROL_SHA[:-1], CONTROL_SHA + "0", None, 1):
            with self.subTest(value_type=type(invalid).__name__):
                with self.assertRaises(deny.Refusal):
                    deny.canary_bytes(invalid)

    def test_profile_denies_by_default_without_broad_system_allow_rules(self):
        with patch.object(deny, "Path", PosixFixturePath):
            profile = deny.profile_text(
                "/synthetic/workspace",
                "/synthetic/storage",
                {
                    "developer_directory": "/synthetic/developer",
                    "sdk": "/synthetic/sdk",
                },
            )
        self.assertIn("(deny default)", profile)
        self.assertIn("(deny network*)", profile)
        self.assertIn("(deny mach-lookup)", profile)
        self.assertIn("(deny mach-register)", profile)
        self.assertNotIn("(allow default)", profile)
        self.assertNotIn("(allow network", profile)
        self.assertNotIn("(allow mach", profile)
        self.assertNotIn("system.sb", profile)
        sysctl_line = next(
            line for line in profile.splitlines() if line.startswith("(allow sysctl-read")
        )
        self.assertEqual(
            set(re.findall(r'\(sysctl-name "([^"]+)"\)', sysctl_line)),
            {"hw.machine", "hw.ncpu", "hw.pagesize", "kern.ostype", "kern.osrelease", "kern.osversion"},
        )
        self.assertNotEqual(sysctl_line, "(allow sysctl-read)")

    def test_profile_path_quoting_is_canonical_and_escapes_profile_metacharacters(self):
        self.assertEqual(deny._quote_profile_path('/safe/a"b\\c'), '"/safe/a\\"b\\\\c"')
        invalid_paths = (
            "relative",
            "/safe/../outside",
            "/safe//outside",
            "/safe/./outside",
            "/safe/",
            "/safe/line\nbreak",
            "/safe/" + "x" * 4091,
        )
        for path in invalid_paths:
            with self.subTest(path_length=len(path)):
                with self.assertRaises(deny.Refusal):
                    deny._quote_profile_path(path)

    def test_channel_inventory_is_exact_and_every_channel_has_a_distinct_finite_state(self):
        self.assertEqual(deny.CHANNELS, EXPECTED_CHANNELS)
        self.assertEqual(len(set(deny.CHANNELS)), 11)
        receipt = deny._native_receipt(CONTROL_SHA, "12345", "2", dict(IDENTITY))
        self.assertEqual(receipt["channels"], EXPECTED_CHANNEL_STATES)
        self.assertEqual(len(receipt["channels"]), 11)
        self.assertEqual(receipt["positive_build"], "passed")

    def test_receipt_requires_exact_schema_and_host_identity_provenance(self):
        receipt = deny._native_receipt(CONTROL_SHA, "12345", "2", dict(IDENTITY))
        self.assertEqual(
            set(receipt),
            {
                "schema_version",
                "run_id",
                "run_attempt",
                "control_sha",
                "boundary",
                "macos_product_version",
                "runner_image_os",
                "runner_image_version",
                "developer_mode",
                "pf",
                "sandbox_selftest",
                "positive_build",
                "channels",
                "private_source_executed",
            },
        )
        self.assertEqual(receipt["schema_version"], 2)
        self.assertEqual(receipt["run_id"], 12345)
        self.assertEqual(receipt["run_attempt"], 2)
        self.assertEqual(receipt["control_sha"], CONTROL_SHA)
        self.assertIs(receipt["private_source_executed"], False)

        invalid_identities = []
        for name in IDENTITY:
            changed = dict(IDENTITY)
            changed[name] = "unapproved"
            invalid_identities.append(changed)
        invalid_identities.extend(
            (
                {key: value for key, value in IDENTITY.items() if key != "architecture"},
                dict(IDENTITY, extra="untrusted"),
                None,
                list(IDENTITY.items()),
            )
        )
        for identity in invalid_identities:
            with self.subTest(identity=repr(identity)):
                with self.assertRaises(deny.Refusal):
                    deny._native_receipt(CONTROL_SHA, "12345", "2", identity)

    def test_receipt_accepts_each_approved_host_release_and_refuses_a_mixed_pair(self):
        self.assertEqual(
            deny.APPROVED_HOST_RELEASES,
            (("15.7.9", "20260907.0337.1"), ("15.8.2", "20261028.0489.1")),
        )
        for product, image_version in deny.APPROVED_HOST_RELEASES:
            with self.subTest(product=product):
                identity = dict(IDENTITY, product_version=product, image_version=image_version)
                receipt = deny._native_receipt(CONTROL_SHA, "12345", "2", identity)
                self.assertEqual(receipt["macos_product_version"], product)
                self.assertEqual(receipt["runner_image_version"], image_version)
        for product, image_version in (("15.8.2", "20260907.0337.1"), ("15.7.9", "20261028.0489.1")):
            with self.subTest(mixed=(product, image_version)):
                identity = dict(IDENTITY, product_version=product, image_version=image_version)
                with self.assertRaises(deny.Refusal):
                    deny._native_receipt(CONTROL_SHA, "12345", "2", identity)

    def test_receipt_rejects_caller_forged_control_and_run_identity(self):
        for control_sha in ("a" * 12, CONTROL_SHA.upper(), "g" * 40, CONTROL_SHA + "0", None):
            with self.subTest(identity_type=type(control_sha).__name__):
                with self.assertRaises(deny.Refusal):
                    deny._native_receipt(control_sha, "12345", "2", dict(IDENTITY))
        invalid_numbers = ("0", "-1", "+1", " 1", "1 ", "1.5", "1e2", "", None, True, 1.5)
        for invalid in invalid_numbers:
            with self.subTest(value=repr(invalid)):
                with self.assertRaises(deny.Refusal):
                    deny._native_receipt(CONTROL_SHA, invalid, "2", dict(IDENTITY))
                with self.assertRaises(deny.Refusal):
                    deny._native_receipt(CONTROL_SHA, "12345", invalid, dict(IDENTITY))

    def test_proof_validator_accepts_only_complete_private_negative_evidence(self):
        canary = deny.canary_bytes(CONTROL_SHA)
        self.assertEqual(set(valid_proof()), EXPECTED_PROOF_KEYS)
        stdout, stderr = proof_output(valid_proof(), canary)
        self.assertEqual(deny._validate_proof_payload(stdout, stderr, canary), valid_proof())
        for state in ("blocked", "unavailable"):
            with self.subTest(tty=state):
                evidence = valid_proof()
                evidence["tty"] = state
                stdout, stderr = proof_output(evidence, canary)
                self.assertEqual(deny._validate_proof_payload(stdout, stderr, canary), evidence)

    def test_proof_validator_rejects_successful_sensitive_reads_and_ignored_logs(self):
        canary = deny.canary_bytes(CONTROL_SHA)
        mutations = (
            ("runner_files", False),
            ("process_memory", False),
            ("readable_file_canary", "present"),
            ("memory_canary", "present"),
            ("raw_log_channels", False),
            ("logger_attempted", False),
            ("syslog", False),
            ("os_log_attempted", False),
            ("environment_canary", False),
        )
        for field, value in mutations:
            with self.subTest(field=field):
                evidence = valid_proof()
                evidence[field] = value
                stdout, stderr = proof_output(evidence, canary)
                refusal = self.assert_proof_refusal(stdout, stderr, canary)
                expected = {
                    "runner_files": ("seatbelt_channels", "runner_files"),
                    "process_memory": ("seatbelt_channels", "process_memory"),
                    "readable_file_canary": ("walk", "runner_files"),
                    "memory_canary": ("memory_positive", "process_memory"),
                    "raw_log_channels": ("seatbelt_channels", "raw_logs"),
                }.get(field)
                if expected is not None:
                    self.assertEqual((refusal.stage, refusal.channel), expected)

    def test_proof_validator_rejects_missing_probes_and_unexpected_types(self):
        canary = deny.canary_bytes(CONTROL_SHA)
        for field in ("dns_resolver", "environment_canary", "launchctl", "positive_read", "positive_write", "tty"):
            with self.subTest(missing=field):
                evidence = valid_proof()
                del evidence[field]
                stdout, stderr = proof_output(evidence, canary)
                self.assert_proof_refusal(stdout, stderr, canary)
        for field, value in (("https", 1), ("native_pass", "true"), ("tty", True),
                             ("readable_file_canary", True), ("memory_canary", None)):
            with self.subTest(field=field):
                evidence = valid_proof()
                evidence[field] = value
                stdout, stderr = proof_output(evidence, canary)
                self.assert_proof_refusal(stdout, stderr, canary)
        for state in ("reached", "unproved", "unknown"):
            with self.subTest(tty=state):
                evidence = valid_proof()
                evidence["tty"] = state
                stdout, stderr = proof_output(evidence, canary)
                refusal = self.assert_proof_refusal(stdout, stderr, canary)
                if state == "reached":
                    self.assertEqual((refusal.stage, refusal.channel), ("seatbelt_channels", "raw_logs"))
        stdout, stderr = proof_output(list(valid_proof().items()), canary)
        self.assert_proof_refusal(stdout, stderr, canary)

    def test_proof_validator_rejects_malformed_duplicate_or_ambiguous_output(self):
        canary = deny.canary_bytes(CONTROL_SHA)
        stdout, stderr = proof_output(valid_proof(), canary)
        proof_line = next(line for line in stdout.splitlines() if line.startswith(b"KD-PROOF:"))
        duplicate = proof_line[:-1] + b',"https":false}'
        with self.subTest(kind="duplicate_key"):
            payload = stdout.replace(proof_line, duplicate)
            self.assert_proof_refusal(payload, stderr, canary)
        with self.subTest(kind="duplicate_proof"):
            self.assert_proof_refusal(stdout + proof_line + b"\n", stderr, canary)
        with self.subTest(kind="malformed_json"):
            payload = stdout.replace(proof_line, b"KD-PROOF:{")
            self.assert_proof_refusal(payload, stderr, canary)
        with self.subTest(kind="secret_in_proof"):
            evidence = valid_proof()
            evidence["unexpected"] = canary.decode("ascii")
            payload, error_output = proof_output(evidence, canary)
            self.assert_proof_refusal(payload, error_output, canary)
        with self.subTest(kind="canary_missing_from_stdout"):
            no_canary_stdout = stdout.replace(canary, b"KD-REDACTED-CANARY")
            self.assertNotIn(canary, no_canary_stdout)
            self.assertIn(proof_line, no_canary_stdout)
            self.assert_proof_refusal(no_canary_stdout, stderr, canary)
        with self.subTest(kind="canary_missing_from_stderr"):
            self.assert_proof_refusal(stdout, b"", canary)
        with self.subTest(kind="workflow_marker_missing"):
            missing_marker = deny.WORKFLOW_MARKERS[0] + canary
            payload = stdout.replace(missing_marker, b"")
            self.assert_proof_refusal(payload, stderr, canary)

    def test_positive_controls_remain_required_before_receipt_construction(self):
        source_tree = ast.parse(Path(deny.__file__).read_text(encoding="utf-8"))
        proof_function = next(
            node for node in source_tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "_run_proof"
        )
        calls = []
        for node in ast.walk(proof_function):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
                calls.append((node.func.id, node.lineno))
        receipt_line = min(line for name, line in calls if name == "_native_receipt")
        for required in (
            "_run_memory_positive_control",
            "_run_positive_controls",
            "_run_log_positive_controls",
            "_run_ipc_positive_controls",
            "_run_hostile_fixture",
            "_probe_pf_denial",
        ):
            with self.subTest(control=required):
                matching = [line for name, line in calls if name == required and line < receipt_line]
                self.assertTrue(matching)

    def test_only_bounded_positive_observations_opt_into_image_checks(self):
        source_tree = ast.parse(Path(deny.__file__).read_text(encoding="utf-8"))
        functions = {
            node.name: node
            for node in source_tree.body
            if isinstance(node, ast.FunctionDef)
        }
        positive_controls = (
            "_run_positive_controls",
            "_probe_pf_denial",
            "_run_memory_positive_control",
            "_run_log_positive_controls",
            "_run_ipc_positive_controls",
        )
        for name in positive_controls:
            calls = [
                node for node in ast.walk(functions[name])
                if isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "_run_confined"
            ]
            with self.subTest(control=name):
                self.assertEqual(len(calls), 1)
                options = {keyword.arg: keyword.value for keyword in calls[0].keywords}
                self.assertIn("trusted_control", options)
                self.assertIsInstance(options["trusted_control"], ast.Constant)
                self.assertIs(options["trusted_control"].value, True)

        hostile_calls = [
            node for node in ast.walk(functions["_run_hostile_fixture"])
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "_run_confined"
        ]
        self.assertEqual(len(hostile_calls), 1)
        self.assertNotIn("trusted_control", {keyword.arg for keyword in hostile_calls[0].keywords})
        confined = functions["_run_confined"]
        keyword_defaults = dict(zip(
            [argument.arg for argument in confined.args.kwonlyargs],
            confined.args.kw_defaults,
        ))
        self.assertIn("trusted_control", keyword_defaults)
        self.assertIsInstance(keyword_defaults["trusted_control"], ast.Constant)
        self.assertIs(keyword_defaults["trusted_control"].value, False)

    def test_runner_file_positive_read_is_paired_with_hostile_runner_file_probe(self):
        positive_tree = ast.parse(deny._positive_control_script())
        positive_open = next(
            node for node in ast.walk(positive_tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "open"
            and node.args
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == "runner_file"
        )
        self.assertEqual(positive_open.args[1].value, "rb")
        runner_file_result = next(
            node for node in ast.walk(positive_tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "runner_file_result" for target in node.targets)
        )
        self.assertIsInstance(runner_file_result.value, ast.Compare)
        results = next(
            node.value for node in ast.walk(positive_tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "results" for target in node.targets)
        )
        positive_fields = {
            key.value: value
            for key, value in zip(results.keys, results.values)
            if isinstance(key, ast.Constant) and type(key.value) is str
        }
        self.assertIn("runner_file", positive_fields)
        self.assertIsInstance(positive_fields["runner_file"], ast.Name)
        self.assertEqual(positive_fields["runner_file"].id, "runner_file_result")

        hostile_tree = ast.parse(deny._hostile_script())

        def is_runner_files_target(target):
            if not isinstance(target, ast.Subscript) or not isinstance(target.value, ast.Name):
                return False
            index = target.slice.value if isinstance(target.slice, ast.Index) else target.slice
            return target.value.id == "result" and isinstance(index, ast.Constant) and index.value == "runner_files"

        hostile_result = next(
            node.value for node in ast.walk(hostile_tree)
            if isinstance(node, ast.Assign)
            and any(is_runner_files_target(target) for target in node.targets)
        )
        readable_probe = next(
            node for node in ast.walk(hostile_result)
            if isinstance(node, ast.GeneratorExp)
            and isinstance(node.elt, ast.Call)
            and isinstance(node.elt.func, ast.Name)
            and node.elt.func.id == "file_denied"
            and node.elt.args
            and isinstance(node.elt.args[0], ast.Name)
            and node.elt.args[0].id == "path"
        )
        iterator = readable_probe.generators[0].iter
        self.assertIsInstance(iterator, ast.BinOp)
        self.assertIsInstance(iterator.op, ast.Add)
        self.assertIsInstance(iterator.left, ast.Name)
        self.assertIsInstance(iterator.right, ast.Name)
        self.assertEqual(iterator.left.id, "runner_paths")
        self.assertEqual(iterator.right.id, "control_files")

    def test_memory_probe_validates_own_send_right_before_exact_target_failure(self):
        tree = ast.parse(deny._hostile_script())
        memory_probe = next(
            node for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "memory_denied"
        )
        calls = [node for node in ast.walk(memory_probe) if isinstance(node, ast.Call)]
        own_port_type = next(
            node for node in calls
            if isinstance(node.func, ast.Name) and node.func.id == "port_type"
        )
        self.assertEqual(len(own_port_type.args), 3)
        self.assertEqual(own_port_type.args[0].id, "task")
        self.assertEqual(own_port_type.args[1].id, "task")
        self.assertIsInstance(own_port_type.args[2], ast.Call)
        self.assertEqual(own_port_type.args[2].func.attr, "byref")
        self.assertEqual(own_port_type.args[2].args[0].id, "own_type")

        send_type_constant = next(
            node for node in ast.walk(memory_probe)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "MACH_PORT_TYPE_SEND" for target in node.targets)
        )
        self.assertIsInstance(send_type_constant.value, ast.BinOp)
        self.assertIsInstance(send_type_constant.value.op, ast.LShift)
        self.assertEqual(send_type_constant.value.left.value, 1)
        self.assertEqual(send_type_constant.value.right.value, 16)
        send_right_bit = next(
            node for node in ast.walk(memory_probe)
            if isinstance(node, ast.BinOp)
            and isinstance(node.left, ast.Attribute)
            and isinstance(node.left.value, ast.Name)
            and node.left.value.id == "own_type"
            and node.left.attr == "value"
            and isinstance(node.op, ast.BitAnd)
            and isinstance(node.right, ast.Name)
            and node.right.id == "MACH_PORT_TYPE_SEND"
        )
        self.assertTrue(any(
            isinstance(node, ast.UnaryOp)
            and isinstance(node.op, ast.Not)
            and node.operand is send_right_bit
            for node in ast.walk(memory_probe)
        ))

        failure_check = next(
            node for node in ast.walk(memory_probe)
            if isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Name)
            and node.left.id == "task_status"
            and len(node.ops) == 1
            and isinstance(node.ops[0], ast.NotEq)
        )
        self.assertEqual(failure_check.comparators[0].id, "KERN_FAILURE")
        port_type_assignment = next(
            node for node in ast.walk(memory_probe)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "port_type" for target in node.targets)
        )
        self.assertEqual(port_type_assignment.value.attr, "mach_port_type")

    def test_cleanup_failure_prevents_receipt_output_and_success_status(self):
        counters = {"requests": 0, "tls": 0, "dns": 0}

        class Tripwires:
            def __init__(self, *_args):
                self.state = SimpleNamespace(counts=lambda: dict(counters))
                self.http_port = 8101
                self.tls4_port = 8102
                self.tls6_port = 8103

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

        class PfGuard:
            def verify(self, **_kwargs):
                return None

            def close(self):
                return None

        def successful_network_controls(*_args, **_kwargs):
            counters["requests"] += 5
            counters["tls"] += 3
            counters["dns"] += 3

        memory_target = SimpleNamespace(pid=702, poll=lambda: None, stdout=None, stderr=None)
        sandbox_output = subprocess.CompletedProcess([], 0, b"KD-BUILD:passed\n", b"")
        guard = SimpleNamespace(
            check_platform=lambda: SimpleNamespace(as_dict=lambda: dict(IDENTITY)),
            install_pf=lambda *_args: PfGuard(),
        )
        private_tree = synthetic_path("home-parent")
        event_order = []

        def remove_private_tree(path):
            if os.fspath(path) == private_tree:
                event_order.append("private_tree_failure")
                raise OSError("private tree cleanup failed")

        def hostile_fixture(*_args, **_kwargs):
            event_order.append("hostile_fixture")

        actual_native_receipt = deny._native_receipt

        def build_receipt(*args, **kwargs):
            event_order.append("native_receipt")
            return actual_native_receipt(*args, **kwargs)

        output = io.StringIO()
        workspace = synthetic_path("workspace")
        toolchain = {
            "python": synthetic_path("python"),
            "clang": synthetic_path("clang"),
            "linker": synthetic_path("linker"),
            "sdk": synthetic_path("sdk"),
            "developer_directory": synthetic_path("developer"),
        }
        with ExitStack() as stack:
            stack.enter_context(
                patch.dict(
                    os.environ,
                    {
                        "CI_WORKSPACE": workspace,
                        "RUNNER_HOME": synthetic_path("runner"),
                        "GITHUB_RUN_ID": "12345",
                        "GITHUB_RUN_ATTEMPT": "2",
                    },
                )
            )
            stack.enter_context(patch.object(deny, "boundary_guard", guard))
            stack.enter_context(
                patch.object(deny.capability, "_check_context", return_value=Path(workspace))
            )
            stack.enter_context(
                patch.object(deny.capability, "_resolve_trusted_toolchain", return_value=dict(toolchain))
            )
            stack.enter_context(
                patch.object(deny.capability, "_resolve_sandbox_exec", return_value=synthetic_path("sandbox-exec"))
            )
            stack.enter_context(patch.object(deny.capability, "_disable_developer_mode"))
            stack.enter_context(
                patch.object(
                    deny.capability,
                    "_protect_runner_controls",
                    return_value=(
                        501,
                        (Path(synthetic_path("runner-temp")),),
                        (Path(synthetic_path("github-env")),),
                    ),
                )
            )
            stack.enter_context(
                patch.object(
                    deny.capability,
                    "_create_probe_identity",
                    return_value=(502, Path(synthetic_path("home-parent")), Path(synthetic_path("home"))),
                )
            )
            stack.enter_context(
                patch.object(
                    deny,
                    "_prepare_resolver_fixture",
                    return_value=("synthetic-resolver", ("probe-a.invalid", "probe-b.invalid", "probe-c.invalid", "probe-d.invalid")),
                )
            )
            resolver_removal = stack.enter_context(patch.object(deny, "_remove_resolver_fixture"))
            runner_env_state = object()
            runner_env_plant = stack.enter_context(
                patch.object(deny, "_plant_runner_env_canary", return_value=runner_env_state)
            )
            runner_env_restore = stack.enter_context(patch.object(deny, "_restore_runner_env_canary"))
            stack.enter_context(
                patch.object(deny.capability, "_prepare_storage_directory", return_value=object())
            )
            stack.enter_context(patch.object(deny.capability, "_verify_storage_directory"))
            stack.enter_context(patch.object(deny.capability, "_probe_uid_processes_present", return_value=False))
            tree_removal = stack.enter_context(
                patch.object(deny.capability, "_remove_probe_tree", side_effect=remove_private_tree)
            )
            system_run = stack.enter_context(patch.object(deny.capability, "_run"))
            stack.enter_context(patch.object(deny, "_trusted_root_path"))
            stack.enter_context(patch.object(deny, "_copy_canary_scanner", return_value=Path(synthetic_path("control-kit"))))
            stack.enter_context(patch.object(deny, "_descriptor_policy", return_value=object()))
            stack.enter_context(patch.object(deny, "_write_profile", return_value=Path(synthetic_path("profile"))))
            stack.enter_context(patch.object(deny, "_run_confined", return_value=sandbox_output))
            stack.enter_context(patch.object(deny, "_run_profile_selftest", return_value=True))
            stack.enter_context(
                patch.object(
                    deny,
                    "_canary_files",
                    return_value=((), (Path(synthetic_path("outside", "runner-files", ".credentials")),)),
                )
            )
            stack.enter_context(patch.object(deny, "_verify_profile_unchanged"))
            stack.enter_context(patch.object(deny, "_verify_developer_mode_disabled"))
            stack.enter_context(patch.object(deny, "_create_local_tls_identity", return_value=("cert", "key")))
            stack.enter_context(patch.object(deny, "_start_memory_target", return_value=memory_target))
            stack.enter_context(patch.object(deny, "_verify_memory_target"))
            stack.enter_context(patch.object(deny, "_stop_memory_target"))
            stack.enter_context(patch.object(deny, "_run_memory_positive_control"))
            positive_controls = stack.enter_context(
                patch.object(deny, "_run_positive_controls", side_effect=successful_network_controls)
            )
            stack.enter_context(patch.object(deny, "_run_log_positive_controls"))
            stack.enter_context(patch.object(deny, "_run_ipc_positive_controls"))
            hostile_fixture_mock = stack.enter_context(
                patch.object(deny, "_run_hostile_fixture", side_effect=hostile_fixture)
            )
            stack.enter_context(patch.object(deny, "_probe_pf_denial"))
            stack.enter_context(patch.object(deny, "_unified_log_is_clear", return_value=True))
            stack.enter_context(patch.object(deny, "_Tripwires", Tripwires))
            stack.enter_context(patch.object(deny.tempfile, "mkdtemp", side_effect=(
                synthetic_path("scratch"),
                synthetic_path("outside"),
                synthetic_path("storage"),
            )))
            stack.enter_context(patch.object(deny.os, "chmod", create=True))
            stack.enter_context(patch.object(deny.os, "chown", create=True))
            stack.enter_context(patch.object(Path, "resolve", autospec=True, side_effect=lambda path, *_args, **_kwargs: path))
            stack.enter_context(
                patch.object(
                    Path,
                    "lstat",
                    autospec=True,
                    return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=501),
                )
            )
            stack.enter_context(patch.object(Path, "stat", autospec=True, return_value=SimpleNamespace(st_uid=501)))
            stack.enter_context(patch.object(Path, "read_bytes", autospec=True, return_value=b"profile"))
            stack.enter_context(patch.object(Path, "write_text", autospec=True, return_value=1))
            stack.enter_context(patch.object(Path, "write_bytes", autospec=True, return_value=1))
            stack.enter_context(patch.object(deny.shutil, "rmtree"))
            receipt = stack.enter_context(patch.object(deny, "_native_receipt", side_effect=build_receipt))
            step_output = stack.enter_context(patch.object(deny, "_write_step_output"))
            subprocess_call = stack.enter_context(patch.object(deny.subprocess, "run", create=True))
            popen_call = stack.enter_context(patch.object(deny.subprocess, "Popen", create=True))
            os_guards = {}
            for name in ("geteuid", "getuid", "kill", "killpg", "waitpid"):
                os_guards[name] = stack.enter_context(
                    patch.object(deny.os, name, return_value=0, create=True)
                )
            with redirect_stdout(output):
                status = deny.main(["--control-sha", CONTROL_SHA])

        self.assertEqual(status, 1)
        line = output.getvalue().rstrip("\n")
        parts = line.split()
        self.assertGreaterEqual(len(parts), 2)
        self.assertEqual(
            parts[:3],
            ["macos-confinement=refused", "reason=cleanup_incomplete", "stage=cleanup"],
        )
        fields = parts[2:]
        diagnostics = {}
        for field in fields:
            name, value = field.split("=", 1)
            self.assertIn(name, {"stage", "channel"})
            diagnostics[name] = value
        self.assertEqual(diagnostics["stage"], "cleanup")
        self.assertIn(diagnostics["stage"], deny.STAGES)
        if "channel" in diagnostics:
            self.assertIn(diagnostics["channel"], deny.CHANNELS)
        receipt.assert_called_once()
        self.assertEqual(hostile_fixture_mock.call_count, 2)
        self.assertEqual(positive_controls.call_count, 2)
        self.assertEqual(
            event_order,
            ["hostile_fixture", "hostile_fixture", "native_receipt", "private_tree_failure"],
        )
        expected_runner_file = Path(synthetic_path("outside", "runner-files", ".credentials"))
        for call in positive_controls.call_args_list:
            self.assertEqual(call.args[8], expected_runner_file)
        for call in hostile_fixture_mock.call_args_list:
            self.assertEqual(call.kwargs["runner_file_paths"], (expected_runner_file,))
        tree_removal.assert_any_call(Path(private_tree))
        resolver_removal.assert_called_once_with("synthetic-resolver")
        runner_env_plant.assert_called_once_with(
            Path(synthetic_path("github-env")), deny.canary_bytes(CONTROL_SHA), 501
        )
        runner_env_restore.assert_called_once_with(runner_env_state)
        system_run.assert_not_called()
        step_output.assert_not_called()
        subprocess_call.assert_not_called()
        popen_call.assert_not_called()
        for mocked in os_guards.values():
            mocked.assert_not_called()

    def test_main_has_no_caller_supplied_platform_identity_or_receipt_option(self):
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            with self.assertRaises(SystemExit) as raised:
                deny.main(["--control-sha", CONTROL_SHA, "--image-os", "macos15"])
        self.assertEqual(raised.exception.code, 2)

    def test_isolated_help_exits_before_native_preflight(self):
        arguments = [
            sys.executable,
            "-I",
            "-S",
            "-B",
            deny.__file__,
            "--help",
        ]
        environment = {"PATH": os.environ.get("PATH", ""), "LANG": "C", "LC_ALL": "C"}
        try:
            result = subprocess.run(
                arguments,
                env=environment,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=10,
                check=False,
                close_fds=True,
            )
        except subprocess.TimeoutExpired:
            self.fail("isolated help did not exit promptly")
        except OSError:
            self.fail("isolated help could not start")
        self.assertEqual(result.returncode, 0)
        self.assertTrue(result.stderr == b"")
        self.assertLess(len(result.stdout), 4096)
        try:
            output = result.stdout.decode("ascii", "strict")
        except UnicodeDecodeError:
            self.fail("isolated help was not plain text")
        self.assertNotIn("\r", output.replace("\r\n", ""))
        output = output.replace("\r\n", "\n")
        program = Path(deny.__file__).name
        group = "optional arguments" if sys.version_info < (3, 10) else "options"
        expected = re.fullmatch(
            r"usage: " + re.escape(program)
            + r" \[-h\] --control-sha CONTROL_SHA\n\n"
            + re.escape(group)
            + r":\n  -h, --help\s+show this help message and exit\n"
            + r"  --control-sha CONTROL_SHA\s*\n?",
            output,
        )
        self.assertIsNotNone(expected)

    def test_platform_identity_is_checked_before_any_probe_child_path(self):
        order = []

        def fail_identity(*_args, **_kwargs):
            order.append("identity")
            raise deny.capability.ProbeFailure("native_preflight_unavailable")

        guard = SimpleNamespace(
            check_platform=lambda: order.append("platform") or SimpleNamespace(as_dict=lambda: dict(IDENTITY))
        )
        with ExitStack() as stack:
            stack.enter_context(patch.dict(os.environ, {"CI_WORKSPACE": synthetic_path("workspace")}))
            stack.enter_context(patch.object(deny, "boundary_guard", guard))
            stack.enter_context(
                patch.object(
                    deny.capability,
                    "_check_context",
                    side_effect=lambda *_: order.append("context") or Path(synthetic_path("workspace")),
                )
            )
            stack.enter_context(
                patch.object(
                    deny.capability,
                    "_resolve_trusted_toolchain",
                    side_effect=lambda: order.append("toolchain") or {},
                )
            )
            stack.enter_context(
                patch.object(
                    deny.capability,
                    "_resolve_sandbox_exec",
                    side_effect=lambda: order.append("sandbox") or synthetic_path("sandbox-exec"),
                )
            )
            stack.enter_context(
                patch.object(deny.capability, "_disable_developer_mode", side_effect=lambda: order.append("developer"))
            )
            stack.enter_context(
                patch.object(
                    deny.capability,
                    "_protect_runner_controls",
                    side_effect=lambda *_: order.append("runner") or (501, (), ()),
                )
            )
            stack.enter_context(
                patch.object(deny.capability, "_create_probe_identity", side_effect=fail_identity)
            )
            run = stack.enter_context(patch.object(deny.subprocess, "run", create=True))
            popen = stack.enter_context(patch.object(deny.subprocess, "Popen", create=True))
            os_guards = {}
            for name in ("geteuid", "getuid", "kill", "killpg", "waitpid"):
                os_guards[name] = stack.enter_context(
                    patch.object(deny.os, name, return_value=0, create=True)
                )
            with self.assertRaises(deny.Refusal) as raised:
                deny._run_proof(CONTROL_SHA)
        self.assertEqual(order, ["platform", "context", "toolchain", "sandbox", "developer", "runner", "identity"])
        self.assertEqual(raised.exception.reason, "native_preflight_unavailable")
        self.assertEqual(raised.exception.stage, "probe_identity")
        self.assertIsNone(raised.exception.channel)
        run.assert_not_called()
        popen.assert_not_called()
        for mocked in os_guards.values():
            mocked.assert_not_called()

    def test_embedded_fixture_sources_parse_without_execution(self):
        scripts = (
            deny._hostile_script(),
            deny._positive_control_script(),
            deny._pf_probe_script(),
            deny._log_control_script(),
            deny._memory_positive_script(),
        )
        for index, source in enumerate(scripts):
            with self.subTest(fixture=index):
                parsed = ast.parse(source)
                self.assertTrue(parsed.body)
                compile(parsed, "<embedded-fixture>", "exec")

        source_tree = ast.parse(Path(deny.__file__).read_text(encoding="utf-8"))

        def literal_source(node):
            if isinstance(node, ast.Constant) and type(node.value) is str:
                return node.value
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
                left = literal_source(node.left)
                right = literal_source(node.right)
                if left is not None and right is not None:
                    return left + right
            return None

        embedded = []
        for node in ast.walk(source_tree):
            if not isinstance(node, ast.Assign):
                continue
            names = [target.id for target in node.targets if isinstance(target, ast.Name)]
            if any(name in ("script", "build_script") for name in names):
                text = literal_source(node.value)
                if text is not None:
                    embedded.append(text)
        self.assertGreaterEqual(len(embedded), 2)
        for index, source in enumerate(embedded):
            with self.subTest(assembled_fixture=index):
                parsed = ast.parse(source)
                self.assertTrue(parsed.body)
                compile(parsed, "<assembled-fixture>", "exec")

    def test_fixture_channel_successes_are_never_literal_true_assignments(self):
        tree = ast.parse(deny._hostile_script())
        channel_fields = {
            "https", "dns", "redirect", "proxy", "runner_ipc", "artifact_upload",
            "cache_upload", "runner_files", "process_memory", "boundary_disablement",
            "raw_log_channels", "environment_canary",
        }
        assignments = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if not isinstance(target, ast.Subscript) or not isinstance(target.value, ast.Name):
                    continue
                if target.value.id != "result":
                    continue
                index = target.slice.value if isinstance(target.slice, ast.Index) else target.slice
                if isinstance(index, ast.Constant) and type(index.value) is str:
                    assignments[index.value] = node.value
        self.assertTrue(channel_fields.issubset(assignments))
        for field in channel_fields:
            with self.subTest(field=field):
                value = assignments[field]
                self.assertFalse(isinstance(value, ast.Constant) and value.value is True)
        expected_assignment = next(
            node.value for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "expected" for target in node.targets)
        )
        expected_fields = {element.value for element in expected_assignment.elts if isinstance(element, ast.Constant)}
        self.assertTrue(channel_fields.issubset(expected_fields))
        pass_assignment = next(
            node.value for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(isinstance(target, ast.Name) and target.id == "passed" for target in node.targets)
        )
        self.assertIsInstance(pass_assignment, ast.BoolOp)
        self.assertIsInstance(pass_assignment.op, ast.And)

        def conjunction_terms(expression):
            if isinstance(expression, ast.BoolOp) and isinstance(expression.op, ast.And):
                terms = []
                for value in expression.values:
                    terms.extend(conjunction_terms(value))
                return terms
            return [expression]

        terms = conjunction_terms(pass_assignment)
        channel_gate = next(
            node for node in terms
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "all"
        )
        self.assertEqual(len(channel_gate.args), 1)
        channel_iterator = channel_gate.args[0]
        self.assertIsInstance(channel_iterator, ast.GeneratorExp)
        self.assertEqual(len(channel_iterator.generators), 1)
        channel_generator = channel_iterator.generators[0]
        self.assertIsInstance(channel_generator.iter, ast.Name)
        self.assertEqual(channel_generator.iter.id, "expected")
        self.assertIsInstance(channel_iterator.elt, ast.Compare)
        self.assertIsInstance(channel_iterator.elt.ops[0], ast.Is)
        self.assertIsInstance(channel_iterator.elt.comparators[0], ast.Constant)
        self.assertIs(channel_iterator.elt.comparators[0].value, True)
        channel_observation = channel_iterator.elt.left
        self.assertIsInstance(channel_observation, ast.Call)
        self.assertIsInstance(channel_observation.func, ast.Attribute)
        self.assertEqual(channel_observation.func.attr, "get")
        self.assertIsInstance(channel_observation.func.value, ast.Name)
        self.assertEqual(channel_observation.func.value.id, "result")
        self.assertEqual(channel_observation.args[0].id, "channel")
        self.assertEqual(channel_generator.target.id, "channel")
        self.assertEqual(
            expected_fields - channel_fields,
            {
                "actions_environment",
                "dns_resolver",
                "outside_write",
                "positive_read",
                "positive_write",
                "staging_write",
            },
        )

        file_scan_gate = next(
            node for node in terms
            if isinstance(node, ast.Compare)
            and isinstance(node.left, ast.Call)
            and isinstance(node.left.func, ast.Attribute)
            and node.left.func.attr == "get"
            and node.left.args
            and isinstance(node.left.args[0], ast.Constant)
            and node.left.args[0].value == "readable_file_canary"
        )
        self.assertIsInstance(file_scan_gate.ops[0], ast.Eq)
        self.assertEqual(file_scan_gate.comparators[0].value, "absent")

        log_gate = assignments["raw_log_channels"]
        self.assertIsInstance(log_gate, ast.BoolOp)
        self.assertIsInstance(log_gate.op, ast.And)
        log_observations = set()
        for value in log_gate.values:
            self.assertIsInstance(value, ast.Compare)
            self.assertIsInstance(value.ops[0], ast.Is)
            self.assertIsInstance(value.comparators[0], ast.Constant)
            self.assertIs(value.comparators[0].value, True)
            self.assertIsInstance(value.left, ast.Call)
            self.assertIsInstance(value.left.func, ast.Attribute)
            self.assertEqual(value.left.func.attr, "get")
            log_observations.add(value.left.args[0].value)
        self.assertEqual(log_observations, {"syslog", "logger_attempted", "os_log_attempted"})

        native_pass_assignment = assignments["native_pass"]
        self.assertIsInstance(native_pass_assignment, ast.Name)
        self.assertEqual(native_pass_assignment.id, "passed")
        self.assertFalse(isinstance(pass_assignment, ast.Constant) and pass_assignment.value is True)


if __name__ == "__main__":
    unittest.main()
