"""Portable source-free acceptance tests for the encrypted dev lane."""

import gzip
import hashlib
import inspect
import threading
import io
import json
import os
import shutil
import signal
import subprocess
import tempfile
import tarfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import bundle
import fetch
import filter as public_filter
import host_cleanup
import isolated_cleanup
import network_probe
import permit
import prepare
import supervisor
import test_e2e


CONTROL_SHA = "a" * 40
FETCH_SHA = "b" * 64
KEY = bytes(range(32))
BINDINGS = {
    "format": "kd-public-devlane-aesgcm-v1",
    "repository_id": "1430960557",
    "control_sha": CONTROL_SHA,
    "workflow_path": ".github/workflows/devlane-encrypted.yml",
    "profile": "core-node",
    "wave_id": "wave-test-0001",
    "bundle_id": "bundle-test-0001",
    "fetch_sha256": FETCH_SHA,
    "expires": 2_000_000_000,
}


def _archive(members):
    body = io.BytesIO()
    with tarfile.open(fileobj=body, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, payload, kind in members:
            info = tarfile.TarInfo(name)
            info.uid = info.gid = info.mtime = 0
            info.mode = 0o600
            if kind == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = "source.ts"
                archive.addfile(info)
            elif kind == "directory":
                info.type = tarfile.DIRTYPE
                info.size = 0
                archive.addfile(info)
            else:
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
    return gzip.compress(body.getvalue(), mtime=0)


def _manifest(files, profile="core-node"):
    file_rows = [
        {"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        for name, data in sorted(files.items())
    ]
    return {
        "schema": 1,
        "profile": profile,
        "profile_revision": 1,
        "source_revision": CONTROL_SHA,
        "tree_sha256": hashlib.sha256(bundle.canonical_json(file_rows)).hexdigest(),
        "files": file_rows,
        "original_lockfiles": {},
        "fetch_sha256": FETCH_SHA,
        "allowed_files": {"src/example.ts": "file_0001"},
        "allowed_tests": {"suite::case": "case_0001"},
        "frames": {},
        "limits": {
            "ciphertext_bytes": bundle.MAX_CIPHERTEXT,
            "expanded_bytes": bundle.MAX_EXPANDED,
            "files": bundle.MAX_FILES,
            "file_bytes": bundle.MAX_FILE,
        },
    }


def _sealed_archive(members):
    files = {name: payload for name, payload, kind in members if kind == "file"}
    manifest = _manifest(files)
    all_members = list(members) + [
        (".devlane/manifest.json", bundle.canonical_json(manifest), "file")
    ]
    return _archive(all_members)


class FilterAcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.allowlists = {
            "files": {"src/example.ts": "file_0001"},
            "tests": {"suite::case": "case_0001"},
            "frames": {},
            "stages": ["typecheck", "unit"],
            "codes": ["TS2322", "DEVLANE_FAILURE"],
            "max_lines": {"src/example.ts": 200},
            "suites": [],
        }

    def test_source_secret_and_unknown_code_never_reach_public_summary(self):
        source = "const planted = 'PRIVATE_SOURCE_CANARY'; API_KEY='SECRET_CANARY'"
        rows = [
            json.dumps({"kind": "diagnostic", "stage": "typecheck", "code": "TS2322",
                        "file": "src/example.ts", "line": 7, "level": "error"}).encode("utf-8"),
            b'{"kind":"diagnostic","stage":"unit","code":"PRIVATE_SOURCE_CANARY"}',
        ]
        output = public_filter.filter_records(rows, self.allowlists)
        self.assertNotIn(b"PRIVATE_SOURCE_CANARY", output)
        self.assertNotIn(b"SECRET_CANARY", output)
        self.assertIn(b'"file":"file_0001"', output)
        self.assertIn(b'"code":"DEVLANE_FAILURE"', output)
        hostile = json.dumps({"kind": "diagnostic", "stage": "unit", "code": "TS2322",
                              "message": source, "token": "SECRET_CANARY"}).encode("utf-8")
        with self.assertRaises(public_filter.FilterRefusal) as caught:
            public_filter.filter_records([hostile], self.allowlists)
        self.assertNotIn(source.encode("utf-8"), str(caught.exception).encode("utf-8"))
        self.assertNotIn(b"SECRET_CANARY", str(caught.exception).encode("utf-8"))

    def test_closed_schema_rejects_injection_and_unmapped_names(self):
        drive_path = "C:" + chr(92) + "private" + chr(92) + "source.ts"
        unc_path = chr(92) * 2 + "server" + chr(92) + "share" + chr(92) + "source.ts"
        slash_path = chr(47) + "private" + chr(47) + "source.ts"
        pseudo_path = "<" + "anonymous" + ">"
        attacks = [
            b"::warning::SECRET_CANARY",
            b'{"kind":"test","stage":"unit","test":"SECRET_CANARY"}',
            b'{"kind":"diagnostic","stage":"typecheck","code":"TS2322","file":"../../private.ts"}',
            json.dumps({"kind": "diagnostic", "stage": "typecheck", "code": "TS2322", "file": drive_path}).encode(),
            json.dumps({"kind": "diagnostic", "stage": "typecheck", "code": "TS2322", "file": unc_path}).encode(),
            json.dumps({"kind": "diagnostic", "stage": "typecheck", "code": "TS2322", "file": slash_path}).encode(),
            json.dumps({"kind": "diagnostic", "stage": "typecheck", "code": "TS2322", "file": pseudo_path}).encode(),
            b'{"kind":"diagnostic","stage":"typecheck","code":"TS2322","level":"error","level":"warning"}',
            b'{"kind":"diagnostic","stage":"typecheck","code":"TS2322","message":"SECRET_CANARY"}',
            b'{"kind":"diagnostic","stage":"typecheck","code":"TS2322"}\r',
            b'{"kind":"diagnostic","stage":"typecheck","code":"TS2322"}\r\n',
            b'{"kind":"diagnostic","stage":"typecheck","code":"TS2322"}\x1b[31m',
            b'\xff',
        ]
        for attack in attacks:
            with self.subTest(attack=attack[:40]):
                with self.assertRaises(public_filter.FilterRefusal):
                    public_filter.filter_records([attack], self.allowlists)

    def test_invalid_level_and_missing_or_duplicate_frame_coverage_fail(self):
        with self.assertRaises(public_filter.FilterRefusal):
            public_filter.filter_records([
                b'{"kind":"diagnostic","stage":"unit","code":"TS2322","level":"info"}'
            ], self.allowlists)
        self.allowlists["frames"] = {"private frame name": "frame_0001"}
        with self.assertRaises(public_filter.FilterRefusal):
            public_filter.filter_records([], self.allowlists, required_frames=("frame_0001",))
        row = b'{"kind":"frame","frame":"private frame name","status":"pass"}'
        with self.assertRaises(public_filter.FilterRefusal):
            public_filter.filter_records([row, row], self.allowlists, required_frames=("frame_0001",))

    def test_raw_record_and_summary_limits_fail_closed(self):
        with self.assertRaises(public_filter.FilterRefusal):
            public_filter.filter_records([b" " * (public_filter.MAX_RAW_RECORD_BYTES + 1)], self.allowlists)
        rows = [b'{"kind":"control","stage":"unit","status":"fail"}'] * 101
        with self.assertRaises(public_filter.FilterRefusal):
            public_filter.filter_records(rows, self.allowlists)


class EnvelopeAcceptanceTests(unittest.TestCase):
    def test_generated_key_file_is_private_and_exactly_secret_input_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            key_path = Path(temporary) / "key.hex"
            bundle.write_private_key(key_path, KEY)
            self.assertEqual(key_path.read_bytes(), KEY.hex().encode("ascii"))
            self.assertEqual(key_path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(bundle.read_key_file(key_path), KEY)

    def test_round_trip_and_tamper_wrong_key_expiry_binding_and_trailing_bytes(self):
        archive = _sealed_archive([("src/example.ts", b"synthetic source fixture", "file")])
        envelope = bundle.build_envelope(archive, KEY, BINDINGS)
        self.assertEqual(bundle.parse_envelope(envelope, KEY, BINDINGS, now=1_900_000_000), archive)
        for payload, key, expected, now in (
            (envelope[:-1] + bytes((envelope[-1] ^ 1,)), KEY, BINDINGS, 1_900_000_000),
            (envelope, bytes(reversed(KEY)), BINDINGS, 1_900_000_000),
            (envelope, KEY, {**BINDINGS, "wave_id": "wave-test-0002"}, 1_900_000_000),
            (envelope, KEY, BINDINGS, 2_000_000_000),
            (envelope + b"trailing", KEY, BINDINGS, 1_900_000_000),
        ):
            with self.subTest(now=now, expected=expected["wave_id"]):
                with self.assertRaises(bundle.Refusal):
                    bundle.parse_envelope(payload, key, expected, now=now)

    def test_duplicate_json_keys_fail(self):
        with self.assertRaises(bundle.Refusal):
            bundle.strict_json(b'{"schema":1,"schema":1}')

    def test_archive_traversal_symlink_duplicate_and_lock_binding_fail(self):
        cases = (
            [("../escape", b"x", "file")],
            [("src/link", b"", "symlink")],
            [("src/example.ts", b"one", "file"), ("src/example.ts", b"two", "file")],
            [(".env.local", b"sensitive", "file")],
        )
        for members in cases:
            with self.subTest(members=members):
                with self.assertRaises(bundle.Refusal):
                    bundle.inspect_archive(_sealed_archive(members), BINDINGS)

    def test_archive_file_and_expansion_limits_are_checked(self):
        too_large = b"x" * (bundle.MAX_FILE + 1)
        with self.assertRaises(bundle.Refusal):
            bundle.inspect_archive(_sealed_archive([("src/large.ts", too_large, "file")]), BINDINGS)


class OneRunPermitAcceptanceTests(unittest.TestCase):
    def _environment(self, **changes):
        environment = {
            "CI_SHA": CONTROL_SHA, "CI_CONTROL_RUN_ID": "12345", "DEVLANE_PROFILE": "core-node",
            "DEVLANE_WAVE_ID": "wave-test-0001", "DEVLANE_BUNDLE_ID": "bundle-test-0001",
            "CI_RUN_ID": "54321", "CI_RUN_ATTEMPT": "1",
            "DEVLANE_EXPIRES": str(int(time.time()) + 1800),
        }
        environment.update(changes)
        return environment

    def test_control_evidence_is_bound_to_the_exact_reviewed_sha_and_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            evidence = Path(temporary) / "permit.json"
            permit.create_control(evidence, CONTROL_SHA, "12345")
            permit.verify_control(evidence, CONTROL_SHA, "12345")
            for sha, run_id in (("f" * 40, "12345"), (CONTROL_SHA, "54321")):
                with self.subTest(sha=sha, run_id=run_id), self.assertRaises(permit.PermitRefusal):
                    permit.verify_control(evidence, sha, run_id)

    def test_bundle_permit_is_single_run_and_rejects_wrong_or_duplicate_claims(self):
        with tempfile.TemporaryDirectory() as temporary:
            claim_path = Path(temporary) / "permit.json"
            first = self._environment()
            claim = permit.claim(claim_path, first)
            self.assertEqual(claim["run_id"], "54321")
            self.assertEqual(permit.verify_claim(claim_path, first), claim)
            with self.assertRaisesRegex(permit.PermitRefusal, "bundle-run-already-claimed"):
                permit.claim(claim_path, first)
            wrong_run = self._environment(CI_RUN_ID="54322")
            with self.assertRaisesRegex(permit.PermitRefusal, "bundle-run-permit-binding"):
                permit.verify_claim(claim_path, wrong_run)
            wrong_bundle = self._environment(DEVLANE_BUNDLE_ID="bundle-test-0002")
            with self.assertRaisesRegex(permit.PermitRefusal, "bundle-run-permit-binding"):
                permit.verify_claim(claim_path, wrong_bundle)


class FetchProjectionAcceptanceTests(unittest.TestCase):
    def test_dispatch_identity_and_npm_projection_are_strict(self):
        identity = {
            "repository": fetch.REPOSITORY,
            "repository_id": fetch.REPOSITORY_ID,
            "server_url": "https://github.com",
            "event": "workflow_dispatch",
            "ref": "refs/heads/main",
            "control_sha": CONTROL_SHA,
            "control_run_id": "12345",
            "workflow_path": fetch.WORKFLOW_PATH,
            "run_attempt": 1,
            "profile": "core-node",
            "wave_id": "wave-test-0001",
            "bundle_id": "bundle-test-0001",
            "bundle_asset_id": "123456",
            "bundle_sha256": FETCH_SHA,
            "bundle_size": 100,
            "projection_asset_id": "123457",
            "projection_sha256": "c" * 64,
            "projection_size": 200,
            "expires": 2_000_000_000,
        }
        self.assertEqual(fetch.validate_dispatch(identity, now=1_999_999_000), identity)
        for changed in (
            {**identity, "event": "pull_request"},
            {**identity, "ref": "refs/pull/5/merge"},
            {**identity, "run_attempt": 2},
            {**identity, "repository": "attacker/repo"},
        ):
            with self.subTest(changed=changed):
                with self.assertRaises(bundle.Refusal):
                    fetch.validate_dispatch(changed, now=1_999_999_000)

        integrity = "sha512-" + "A" * 86 + "=="
        package_lock = {
            "name": "private-project-name-is-not-copied",
            "version": "4.5.6",
            "lockfileVersion": 3,
            "requires": True,
            "packages": {
                "": {"name": "private-project-name-is-not-copied", "version": "4.5.6",
                     "devDependencies": {"typescript": "^5.8.0"}},
                "node_modules/typescript": {
                    "version": "5.8.2", "resolved": "https://registry.npmjs.org/typescript/-/typescript-5.8.2.tgz",
                    "integrity": integrity, "dev": True,
                },
            },
        }
        package, projected_lock, coordinates = fetch.project_npm_lock(
            json.dumps(package_lock, separators=(",", ":")).encode("utf-8")
        )
        projection = {
            "schema": 1, "profile": "core-node", "npm": coordinates, "cargo": [],
            "playwright": [], "tools": {"node": "24.22.1", "npm": "11.19.1"}, "cargo_workspaces": [],
            "npm_package": package, "npm_lock": projected_lock,
        }
        sanitized = fetch.validate_projection(json.dumps(projection).encode("utf-8"), "core-node")
        self.assertEqual(sanitized["npm_package"]["name"], "devlane-projection")
        self.assertNotIn("private-project-name-is-not-copied", json.dumps(sanitized))
        self.assertTrue(fetch.validate_npm_manifest_binding(
            b'{"devDependencies":{"typescript":"^5.8.0"}}', sanitized["npm_package"]
        ))
        for manifest in (
            b'{"devDependencies":{"typescript":"^5.9.0"}}',
            b'{"dependencies":{"private-package":"file:../private"}}',
            b'{"workspaces":["packages/*"]}',
        ):
            with self.subTest(manifest=manifest):
                with self.assertRaises(fetch.Refusal):
                    fetch.validate_npm_manifest_binding(manifest, sanitized["npm_package"])

    def test_cargo_sync_workspaces_are_projected_without_private_paths(self):
        lock = (
            'version = 3\n\n[[package]]\nname = "serde"\nversion = "1.0.200"\n'
            'source = "registry+https:' + chr(47) * 2 + 'github.com/rust-lang/crates.io-index"\n'
            'checksum = "' + "a" * 64 + '"\n'
        ).encode("ascii")
        root_manifest, root_lock, cargo = fetch.project_cargo_lock(lock)
        sync_manifest, sync_lock, _ = fetch.project_cargo_lock(lock)
        projection = {
            "schema": 1, "profile": "core-rust", "npm": [], "cargo": cargo,
            "playwright": [], "tools": {"cargo": "1.99.1", "rustc": "1.99.1"},
            "cargo_manifest": root_manifest, "cargo_lock": root_lock,
            "cargo_workspaces": [{"path": "fuzz/Cargo.lock", "manifest": sync_manifest, "lock": sync_lock},
                                 {"path": "runtime/Cargo.lock", "manifest": sync_manifest, "lock": sync_lock}],
        }
        sanitized = fetch.validate_projection(json.dumps(projection).encode("utf-8"), "core-rust")
        self.assertEqual([item["path"] for item in sanitized["cargo_workspaces"]],
                         ["fuzz/Cargo.lock", "runtime/Cargo.lock"])
        self.assertNotIn("private/workspace/path", json.dumps(sanitized))


class NetworkProbeAcceptanceTests(unittest.TestCase):
    def _evidence(self):
        return {
            "namespace_inode": 20, "interfaces": ["lo"], "routes": 0, "loopback": True,
            "probes": {name: False for name in (
                "ipv4_https", "ipv6_https", "dns_udp", "dns_tcp", "doh_direct_ip", "metadata"
            )},
            "proxy_environment": {}, "extra_fds": [], "identity": "65534:65534",
        }

    def test_expected_offline_evidence_passes_and_positive_connectivity_fails(self):
        self.assertTrue(network_probe.validate_probe(self._evidence(), 10))
        evidence = self._evidence()
        evidence["probes"]["ipv4_https"] = True
        with self.assertRaises(network_probe.ProbeRefusal):
            network_probe.validate_probe(evidence, 10)

    def test_structural_and_inherited_descriptor_mutations_fail(self):
        for field, value in (("interfaces", ["lo", "eth0"]), ("routes", 1),
                             ("loopback", False), ("extra_fds", [8]),
                             ("proxy_environment", {"HTTPS_PROXY": "http://host"}),
                             ("namespace_inode", 10)):
            evidence = self._evidence()
            evidence[field] = value
            with self.subTest(field=field):
                with self.assertRaises(network_probe.ProbeRefusal):
                    network_probe.validate_probe(evidence, 10)

    def test_pre_cut_positive_control_requires_reachable_external_socket(self):
        class Connected:
            def close(self):
                pass
        self.assertTrue(network_probe.positive_control(connector=lambda *_args, **_kwargs: Connected())["connected"])
        def offline(*_args, **_kwargs):
            raise OSError("synthetic")
        with self.assertRaises(network_probe.ProbeRefusal):
            network_probe.positive_control(connector=offline)


class SupervisorOrderAcceptanceTests(unittest.TestCase):
    def setUp(self):
        supervisor.CANCEL_REQUESTED.clear()
        supervisor.ACTIVE_DEADLINE_FILE = ""

    def tearDown(self):
        supervisor.CANCEL_REQUESTED.clear()
        supervisor.ACTIVE_DEADLINE_FILE = ""

    def test_decrypt_request_is_rejected_until_probe_passes(self):
        service = supervisor.Service.__new__(supervisor.Service)
        service.probe_passed = False
        service.decrypted = False
        service.execution_done = False
        with self.assertRaises(supervisor.SupervisorRefusal):
            supervisor.Service._decrypt(service, "synthetic-test-key")
        calls = []

        def probe():
            calls.append("probe")
            service.probe_passed = True
            return {"ok": True}

        def decrypt(key):
            if not service.probe_passed:
                raise supervisor.SupervisorRefusal("decrypt-order")
            calls.append(("decrypt", key))
            service.decrypted = True
            return {"ok": True}

        service._probe = probe
        service._decrypt = decrypt
        with self.assertRaises(supervisor.SupervisorRefusal):
            service.request({"op": "decrypt", "key": "synthetic-test-key"})
        self.assertEqual(calls, [])
        self.assertEqual(service.request({"op": "probe"}), {"ok": True})
        self.assertEqual(service.request({"op": "decrypt", "key": "synthetic-test-key"}), {"ok": True})
        self.assertEqual(calls, ["probe", ("decrypt", "synthetic-test-key")])

    def test_chroot_workers_change_directory_inside_the_isolated_root(self):
        class Process:
            pid = 100

            def wait(self, timeout=None):
                return 0

            def poll(self):
                return 0

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "workspace/source").mkdir(parents=True)
            with patch.object(supervisor.subprocess, "Popen", return_value=Process()) as popen, \
                    patch.object(supervisor, "_kill_workload_descendants"):
                self.assertEqual(supervisor._run_profile_command(
                    root, ["npm", "test"], "unit", "/workspace/raw/unit.log", {}, timeout=1
                ), 0)
                self.assertEqual(popen.call_args.kwargs["cwd"], "/")
                argv = popen.call_args.args[0]
                self.assertEqual(argv[argv.index("/bin/sh") + 2], 'cd /workspace/source && exec "$@"')
                self.assertEqual(supervisor._run_control_adapter(
                    root, ["node", "adapter"], "unit", {}, "adapter.log", timeout=1
                ), 0)
                self.assertEqual(popen.call_args.kwargs["cwd"], "/")
                self.assertIn('cd /workspace/source && exec "$@"', popen.call_args.args[0])

    def test_child_timeout_and_cancellation_are_bounded_and_kill_the_process_group(self):
        class Process:
            pid = 401

            def poll(self):
                return None

            def wait(self, timeout=None):
                return 0

        process = Process()
        with patch.object(supervisor.os, "killpg") as killpg, \
                patch.object(supervisor.CANCEL_REQUESTED, "is_set", return_value=True):
            self.assertEqual(supervisor._wait_child(process, 30), 130)
            killpg.assert_called_once_with(401, signal.SIGTERM)
        with patch.object(supervisor.os, "killpg") as killpg, \
                patch.object(supervisor.time, "monotonic", side_effect=[0.0, 2.0]), \
                patch.object(supervisor.time, "sleep"):
            with patch.object(supervisor.CANCEL_REQUESTED, "is_set", return_value=False):
                self.assertEqual(supervisor._wait_child(process, 1), 124)
            killpg.assert_called_once_with(401, signal.SIGTERM)

    def test_decrypt_client_clears_key_environment_on_success_and_refusal(self):
        args = type("Args", (), {"operation": "decrypt", "state_dir": chr(47) + "private/state"})()
        prior = os.environ.pop("DEVLANE_DECRYPT_KEY", None)
        try:
            for outcome in (None, supervisor.SupervisorRefusal("decrypt-rejected")):
                os.environ["DEVLANE_DECRYPT_KEY"] = "synthetic-key-canary"
                if outcome is None:
                    rpc = patch.object(supervisor, "_rpc", return_value={"ok": True})
                else:
                    rpc = patch.object(supervisor, "_rpc", side_effect=outcome)
                with rpc, patch("sys.stdout", io.StringIO()):
                    if outcome is None:
                        self.assertEqual(supervisor._client(args), 0)
                    else:
                        with self.assertRaises(supervisor.SupervisorRefusal):
                            supervisor._client(args)
                self.assertNotIn("DEVLANE_DECRYPT_KEY", os.environ)
        finally:
            os.environ.pop("DEVLANE_DECRYPT_KEY", None)
            if prior is not None:
                os.environ["DEVLANE_DECRYPT_KEY"] = prior

    def test_supervisor_finally_cleans_up_after_startup_refusal(self):
        args = type("Args", (), {
            "state_dir": tempfile.mkdtemp(), "context": "context", "workspace": "workspace",
            "prepared": "prepared", "bundle": "bundle", "projection": "projection",
            "deadline_file": "deadline",
            "host_net_inode": 1, "owner_uid": os.getuid(), "node_snapshot_id": "",
            "cargo_path": "", "rustc_path": "",
        })()
        service = type("Service", (), {
            "prepare": lambda self: (_ for _ in ()).throw(
                supervisor.SupervisorRefusal("projection-binding-mismatch")
            ),
            "cleanup_calls": 0,
            "_cleanup": lambda self: setattr(self, "cleanup_calls", self.cleanup_calls + 1) or {"ok": True},
        })()
        try:
            with patch.object(supervisor, "Service", return_value=service), \
                    patch.object(supervisor, "_kill_workload_descendants") as kill_children:
                self.assertEqual(supervisor._serve(args), 2)
                self.assertEqual(service.cleanup_calls, 1)
                self.assertGreaterEqual(kill_children.call_count, 1)
                refusal = bundle.strict_json(
                    (Path(args.state_dir) / supervisor.STARTUP_REFUSAL_NAME).read_bytes(), 1024,
                )
                self.assertEqual(refusal, {"code": "projection-binding-mismatch"})
        finally:
            supervisor.CANCEL_REQUESTED.clear()
            import shutil
            shutil.rmtree(args.state_dir, ignore_errors=True)


class ReportingFailOpenTests(unittest.TestCase):
    """An adapter report only counts when the adapter demonstrably completed."""

    FAILURE = supervisor._control_failure("unit")

    def _root(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name)
        (root / "workspace/raw").mkdir(parents=True)
        (root / "scratch/reports").mkdir(parents=True)
        return temporary, root

    def test_timed_out_adapter_with_a_precreated_empty_report_is_a_failure(self):
        """Fails on the old code, which returned [] (success) for both profiles."""
        temporary, root = self._root()
        with temporary:
            (root / "workspace/raw/unit.log").write_bytes(
                b'{"reason":"build-finished","success":true}\n')
            manifest = {"allowed_files": {}, "frames": {}}

            def timed_out(*args, **kwargs):
                (root / "scratch/reports/rust-tests.jsonl").write_bytes(b"")
                return 124

            with patch.object(supervisor, "_run_control_adapter", side_effect=timed_out):
                records = supervisor._adapter_records(root, "core-rust", manifest, [("unit", 0)], {})
            self.assertEqual(records, [self.FAILURE])

            (root / "scratch/reports/vitest.json").write_bytes(b"{}")

            def node_timed_out(*args, **kwargs):
                (root / "scratch/reports/adapter.jsonl").write_bytes(b"")
                return 124

            with patch.object(supervisor, "_run_control_adapter", side_effect=node_timed_out):
                records = supervisor._adapter_records(
                    root, "core-node", manifest, [("typecheck", 0), ("unit", 0)], {}, {"typescript": 0})
            self.assertIn(self.FAILURE, records)
            self.assertNotEqual(records, [])

    def test_adapter_status_must_agree_with_a_complete_regular_report(self):
        temporary, root = self._root()
        with temporary:
            output = root / "scratch/reports/out.jsonl"
            test_record = b'{"kind":"test","stage":"unit","test":"case_0001"}\n'
            control = self.FAILURE + b"\n"
            cases = (
                ("rust clean", b"", 0, "tests", []),
                ("rust failing test", test_record, 1, "tests", [test_record[:-1]]),
                ("rust failing status without records", b"", 1, "tests", [self.FAILURE]),
                ("rust records with clean status", test_record, 0, "tests", [self.FAILURE]),
                ("adapter refused", control, 2, "tests", [self.FAILURE]),
                ("signal exit", b"", 137, "tests", [self.FAILURE]),
                ("interrupted write", test_record[:-4], 1, "tests", [self.FAILURE]),
                ("node clean", test_record, 0, "node", [test_record[:-1]]),
                ("node control failure", control, 1, "node", [control[:-1]]),
                ("node control failure with clean status", control, 0, "node", [self.FAILURE]),
                ("node failing status without control record", test_record, 1, "node", [self.FAILURE]),
                ("garbage", b"not-json\n", 0, "node", [self.FAILURE]),
            )
            for label, payload, status, rule, expected in cases:
                with self.subTest(label):
                    if output.exists():
                        output.unlink()
                    output.write_bytes(payload)
                    self.assertEqual(supervisor._adapter_lines(output, status, "unit", rule=rule), expected)
            output.unlink()
            self.assertEqual(supervisor._adapter_lines(output, 0, "unit", rule="tests"), [self.FAILURE])

    def test_special_files_are_rejected_without_blocking(self):
        temporary, root = self._root()
        with temporary:
            fifo = root / "scratch/reports/fifo.jsonl"
            os.mkfifo(fifo)
            link = root / "scratch/reports/link.jsonl"
            link.symlink_to(root / "workspace/raw")
            for path in (fifo, link):
                outcome = []

                def attempt(path=path):
                    try:
                        supervisor._read_regular(path, 1024)
                        outcome.append("read")
                    except supervisor.SupervisorRefusal as refusal:
                        outcome.append(refusal.code)

                worker = threading.Thread(target=attempt, daemon=True)
                worker.start()
                worker.join(5)
                self.assertFalse(worker.is_alive(), "reading a special file blocked")
                self.assertEqual(outcome, ["report-file-invalid"])
                self.assertEqual(supervisor._adapter_lines(path, 0, "unit", rule="tests"), [self.FAILURE])


class CleanupLifecycleTests(unittest.TestCase):
    def _proc(self, root, entries):
        """Build a fake host /proc: pid -> (ppid, cmdline, pid-namespace id)."""
        namespaces = Path(root) / "namespaces"
        namespaces.mkdir()
        for identifier in {value[2] for value in entries.values()} | {"host"}:
            (namespaces / identifier).write_bytes(b"")
        proc = Path(root) / "proc"
        (proc / "self/ns").mkdir(parents=True)
        (proc / "self/ns/pid").symlink_to(namespaces / "host")
        for pid, (parent, command, namespace) in entries.items():
            entry = proc / str(pid)
            (entry / "ns").mkdir(parents=True)
            (entry / "stat").write_text("%d (python3) S %d 1 1 0" % (pid, parent), encoding="ascii")
            (entry / "cmdline").write_bytes(command.replace(" ", chr(0)).encode("utf-8"))
            (entry / "ns/pid").symlink_to(namespaces / namespace)
        return proc

    def test_host_pid_of_the_namespaced_supervisor_is_resolved_not_namespace_relative_one(self):
        """Fails on the old code, which recorded the namespace-relative PID (1) as a host PID."""
        with tempfile.TemporaryDirectory() as temporary:
            state = "/runner/devlane-1/state"
            serve = "python3 kit/devlane/supervisor.py _serve --state-dir " + state
            proc = self._proc(temporary, {
                100: (1, "sudo -n unshare --net " + serve, "host"),
                101: (100, "unshare --net " + serve, "host"),
                102: (101, serve, "inner"),
                103: (102, "python3 workload", "inner"),
                200: (1, "python3 kit/devlane/supervisor.py _serve --state-dir /runner/other/state", "other"),
            })
            with patch.object(isolated_cleanup, "PROC", str(proc)):
                self.assertEqual(isolated_cleanup.discover_namespace_pid(100, state), 102)
                self.assertIsNone(isolated_cleanup.discover_namespace_pid(103, state))

    def test_ambiguous_or_foreign_supervisors_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            state = "/runner/devlane-1/state"
            serve = "python3 kit/devlane/supervisor.py _serve --state-dir " + state
            proc = self._proc(temporary, {
                100: (1, "sudo " + serve, "host"),
                101: (100, serve, "inner"),
                102: (100, serve, "inner2"),
            })
            with patch.object(isolated_cleanup, "PROC", str(proc)), self.assertRaises(RuntimeError):
                isolated_cleanup.discover_namespace_pid(100, state)
        with tempfile.TemporaryDirectory() as temporary:
            state_dir = Path(temporary) / "state"
            state_dir.mkdir()
            (state_dir / "host-pid").write_text("1", encoding="ascii")
            with self.assertRaises(RuntimeError):
                isolated_cleanup._pid(state_dir)

    def test_host_deadline_covers_every_bounded_wait_of_the_cleanup_client(self):
        """Fails on the old code: the host allowed 30 s while the client alone allowed 45 s for its RPC."""
        client_worst_case = (isolated_cleanup.CANCEL_RPC_SECONDS + isolated_cleanup.CLEANUP_RPC_SECONDS
                             + isolated_cleanup.EXIT_WAIT_SECONDS * isolated_cleanup.EXIT_WAITS
                             + isolated_cleanup.FALLBACK_SECONDS)
        self.assertEqual(isolated_cleanup.CLEANUP_BUDGET_SECONDS, client_worst_case)
        self.assertGreater(host_cleanup.HOST_DEADLINE_SECONDS, client_worst_case)
        source = inspect.getsource(host_cleanup.clean)
        self.assertIn("_cleanup_timeout(deadline_file, HOST_DEADLINE_SECONDS)", source)
        self.assertNotIn("timeout=30", source)
        sleeps = inspect.getsource(isolated_cleanup._fallback_terminate)
        for fixed in ("timeout=5", "_wait_absent(pid, 3)", "_wait_process_group_absent(parent_pid, 5)"):
            self.assertIn(fixed, sleeps)


class PreparationDefectTests(unittest.TestCase):
    def test_resolver_configuration_is_copied_into_the_online_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "etc").mkdir()
            with patch.object(prepare, "Path", wraps=Path) as wrapped:
                real_read = Path.read_bytes

                def read_bytes(self):
                    if str(self) == "/etc/resolv.conf":
                        return b"nameserver 127.0.0.53\n"
                    if str(self) == "/etc/nsswitch.conf":
                        return b"hosts: files dns\n"
                    return real_read(self)

                with patch.object(Path, "read_bytes", read_bytes):
                    prepare._write_resolver(root)
            self.assertEqual((root / "etc/resolv.conf").read_bytes(), b"nameserver 127.0.0.53\n")
            self.assertEqual((root / "etc/nsswitch.conf").read_bytes(), b"hosts: files dns\n")
            with patch.object(Path, "read_bytes", side_effect=OSError), self.assertRaises(bundle.Refusal):
                prepare._write_resolver(root)

    def test_only_real_toolchain_binaries_are_accepted_for_rust(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            real = root / "toolchain/bin/cargo"
            real.parent.mkdir(parents=True)
            real.write_bytes(b"")
            proxy_target = root / "cargo-home/bin/rustup"
            proxy_target.parent.mkdir(parents=True)
            proxy_target.write_bytes(b"")
            proxy = root / "cargo-home/bin/cargo"
            proxy.symlink_to(proxy_target)
            self.assertEqual(prepare._resolve_rust_tool(str(real), "cargo"), str(real.resolve()))
            for bad in (str(proxy), "", str(root / "missing")):
                with self.subTest(path=bad), self.assertRaises(bundle.Refusal):
                    prepare._resolve_rust_tool(bad, "cargo")

    def test_vendor_command_has_no_unsupported_flag_and_browsers_are_not_copied_onto_themselves(self):
        worker = inspect.getsource(prepare._run_worker)
        self.assertNotIn("--all-features", worker)
        self.assertNotIn('(prepared / "cargo-vendor").mkdir', worker)
        self.assertNotIn('_copy_tree(work / "prepared/ms-playwright"', worker)
        self.assertIn("playwright-browsers-missing", worker)
        self.assertNotIn("subprocess", inspect.getsource(prepare._resolve_rust_tool))
        self.assertFalse(hasattr(prepare, "_rust_toolchain_paths"))

    def test_workspace_source_is_handed_to_the_unprivileged_decryptor_before_extraction(self):
        source = inspect.getsource(supervisor._mount_minimal_root)
        ensure = source.index('_ensure_directory(root / "workspace/source", 0o700)')
        self.assertIn('os.chown(str(root / "workspace/source"), WORKER_UID, WORKER_GID)', source[ensure:])


class RealLockfileAndFixtureTests(unittest.TestCase):
    def test_every_e2e_node_fixture_passes_the_production_projection_validators(self):
        """Fails on the old fixture (a stripped lock refused with npm-lock-shape) and on the old validator (real lock metadata refused: license, libc, nested node_modules, `||` ranges)."""
        for scenario in test_e2e.scenarios():
            with self.subTest(scenario["name"]):
                files = scenario["files"]()
                fetch.validate_npm_manifest_binding(files["package.json"], scenario["projection"]["npm_package"])
                package, lock, _ = fetch.project_npm_lock(files["package-lock.json"])
                self.assertEqual(package, scenario["projection"]["npm_package"])
                self.assertEqual(lock, scenario["projection"]["npm_lock"])
                fetch.validate_projection(scenario["payload"], "core-node")

    def test_real_npm_lock_metadata_is_accepted_and_only_needed_fields_are_projected(self):
        lock = test_e2e._node_lock_from_reviewed({"typescript": "6.0.3", "vite": "8.3.5", "vitest": "5.0.5"})
        packages = lock["packages"]
        self.assertTrue(any("/node_modules/" in path for path in packages))
        self.assertTrue(any("||" in str(value.get("engines", "")) for value in packages.values()))
        self.assertTrue(any(value.get("hasInstallScript") for value in packages.values()))
        self.assertTrue(any("libc" in value for value in packages.values()))
        _, projected, _ = fetch.project_npm_lock(bundle.canonical_json(lock))
        for entry in projected["packages"].values():
            self.assertFalse({"license", "funding", "deprecated", "hasInstallScript"} & set(entry))
        self.assertTrue(any("libc" in entry for entry in projected["packages"].values()))

    REAL_CARGO_LOCK = (
        "version = 4\n\n"
        '[[package]]\nname = "devlane-projection"\nversion = "0.0.0"\ndependencies = [\n "fastrand",\n "itoa",\n]\n\n'
        '[[package]]\nname = "fastrand"\nversion = "2.3.0"\nsource = "registry+https:' + chr(47) * 2 + 'github.com/rust-lang/crates.io-index"\n'
        'checksum = "37909eebbb50d72f9059c3b6d82c0463f2ff062c9e95845c43a6c9c0355411be"\n\n'
        '[[package]]\nname = "itoa"\nversion = "1.0.15"\nsource = "registry+https:' + chr(47) * 2 + 'github.com/rust-lang/crates.io-index"\n'
        'checksum = "4a5f13b858c8d314ee3e8f639011f7ccefe71f97f96e50151fb991f267928e2c"\n'
    )

    def test_a_cargo_generated_lock_with_real_dependencies_projects_to_a_valid_projection(self):
        """Captured from `cargo generate-lockfile` (cargo 1.97, lock version 4) for two pinned crates."""
        fuzz_lock = (b'version = 4\n\n[[package]]\nname = "devlane-matrix-fuzz-replay"\n'
                     b'version = "0.0.0"\n')
        runtime_lock = (b'version = 4\n\n[[package]]\nname = "devlane-matrix-listener"\n'
                        b'version = "0.0.0"\n')
        projection, payload = test_e2e._rust_projection(
            self.REAL_CARGO_LOCK.encode("utf-8"), fuzz_lock, runtime_lock,
        )
        self.assertEqual([row["name"] for row in projection["cargo"]], ["fastrand", "itoa"])
        self.assertEqual([item["path"] for item in projection["cargo_workspaces"]],
                         ["fuzz/Cargo.lock", "runtime/Cargo.lock"])
        fetch.validate_projection(payload, "core-rust")

    def test_unsafe_lock_shapes_and_specs_are_still_refused(self):
        lock = test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
        for mutate in (
            lambda value: value["packages"]["node_modules/typescript"].update(resolved="git+ssh://example.invalid/x.git"),
            lambda value: value["packages"]["node_modules/typescript"].update(license="x" * 300),
            lambda value: value["packages"]["node_modules/typescript"].update(unexpected="field"),
            lambda value: value["packages"].update({"packages/local": dict(value["packages"]["node_modules/typescript"])}),
            lambda value: value["packages"]["node_modules/typescript"].update(dependencies={"x": "git+https://e.invalid/x"}),
        ):
            candidate = json.loads(json.dumps(lock))
            mutate(candidate)
            with self.subTest(mutation=mutate), self.assertRaises(fetch.Refusal):
                fetch.project_npm_lock(bundle.canonical_json(candidate))
        for bad in ("git+https://x/y.git", "file:../x", "npm:other@1.0.0", "1.0.0 || ", "|| 1", "latest", "1.0.0;rm"):
            self.assertFalse(fetch._valid_npm_spec(bad), bad)


class InstallScriptSuppressionTests(unittest.TestCase):
    """A package that declares an install script is projected and installed as inert files."""

    def test_a_public_package_with_an_install_script_marker_projects_without_the_marker(self):
        lock = test_e2e._node_lock_from_reviewed({"fsevents": "2.3.3"})
        self.assertTrue(lock["packages"]["node_modules/fsevents"].get("hasInstallScript"))
        package, projected, rows = fetch.project_npm_lock(bundle.canonical_json(lock))
        self.assertIn("node_modules/fsevents", projected["packages"])
        self.assertNotIn("hasInstallScript", projected["packages"]["node_modules/fsevents"])
        self.assertNotIn("hasInstallScript", json.dumps(projected))
        for refused in (
            lambda value: value["packages"]["node_modules/fsevents"].update(resolved="git+https://example.invalid/x.git"),
            lambda value: value["packages"]["node_modules/fsevents"].update(resolved="file:../fsevents"),
            lambda value: value["packages"]["node_modules/fsevents"].pop("integrity"),
            lambda value: value["packages"]["node_modules/fsevents"].update(link=True),
        ):
            candidate = json.loads(json.dumps(lock))
            refused(candidate)
            with self.subTest(mutation=refused), self.assertRaises(fetch.Refusal):
                fetch.project_npm_lock(bundle.canonical_json(candidate))

    def test_production_script_suppression_layers_each_stop_a_real_install_script(self):
        npm = shutil.which("npm")
        if npm is None:
            self.skipTest("npm is not available")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            package = root / "package"
            package.mkdir()
            (package / "package.json").write_text(json.dumps({
                "name": "canary-install", "version": "1.0.0",
                "scripts": {"install": "node -e \"require('fs').writeFileSync(process.env.INIT_CWD + '/CANARY', 'ran')\""},
            }), encoding="utf-8")
            base = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(root / "home"), "LC_ALL": "C",
                    "npm_config_cache": str(root / "cache"), "npm_config_update_notifier": "false"}
            (root / "home").mkdir()
            packed = subprocess.run([npm, "pack", "--silent", "--pack-destination", str(root)], cwd=package,
                                    env=base, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=120)
            if packed.returncode != 0:
                self.skipTest("npm pack is unavailable")
            tarball = root / packed.stdout.decode().strip().splitlines()[-1]
            production_npmrc = prepare.NPMRC_TEXT
            self.assertIn("ignore-scripts=true", production_npmrc)
            self.assertEqual(prepare.SCRIPT_SUPPRESSION_ENVIRONMENT, {"NPM_CONFIG_IGNORE_SCRIPTS": "true"})
            self.assertIn("--ignore-scripts", prepare.NPM_CI_ARGUMENTS)
            cases = {
                "none": ({}, [], False),
                "npmrc": ({}, [], True),
                "environment": (prepare.SCRIPT_SUPPRESSION_ENVIRONMENT, [], False),
                "flag": ({}, ["--ignore-scripts"], False),
            }
            outcome = {}
            for name, (extra_environment, extra_arguments, use_npmrc) in cases.items():
                project = root / ("project-" + name)
                project.mkdir()
                (project / "package.json").write_text(json.dumps({"name": "app", "version": "1.0.0", "private": True}),
                                                      encoding="utf-8")
                if use_npmrc:
                    (project / ".npmrc").write_text(production_npmrc, encoding="ascii")
                result = subprocess.run(
                    [npm, "install", str(tarball), "--offline", "--no-audit", "--no-fund", *extra_arguments],
                    cwd=project, env={**base, **extra_environment}, stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE, timeout=240)
                self.assertEqual(result.returncode, 0, name)
                self.assertTrue((project / "node_modules/canary-install/package.json").is_file(), name)
                outcome[name] = (project / "CANARY").exists()
            self.assertTrue(outcome["none"], "control experiment: without suppression the script must run")
            self.assertEqual({key: value for key, value in outcome.items() if key != "none"},
                             {"npmrc": False, "environment": False, "flag": False})


if __name__ == "__main__":
    unittest.main()
