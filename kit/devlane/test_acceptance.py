"""Portable source-free acceptance tests for the encrypted dev lane."""

import gzip
import hashlib
import inspect
import threading
import io
import contextlib
import json
import os
import shutil
import signal
import subprocess
import tempfile
import tarfile
import time
import tomllib
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import bundle
import diagnostic_contract
import fetch
import filter as public_filter
import host_cleanup
import isolated_cleanup
import network_probe
import node_tool_snapshot
import permit
import prepare
import project
import rust_matrix_runner
import rust_tooling
import supervisor
import test_e2e
import test_node_vendor_source
import test_node_vendor_source_r2


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

    def test_unit_failure_subreason_is_a_fixed_public_vocabulary(self):
        record = b'{"kind":"control","stage":"unit","status":"fail","code":"DEVLANE_FAILURE","subreason":"adapter-failed"}'
        expected = b'{"code":"DEVLANE_FAILURE","kind":"control","stage":"unit","status":"fail","subreason":"adapter-failed"}\n'
        self.assertEqual(public_filter.filter_records([record], self.allowlists), expected)
        for changed in (
            record.replace(b"adapter-failed", b"private-adapter-error"),
            record.replace(b'"stage":"unit"', b'"stage":"typecheck"'),
            record.replace(b'"status":"fail"', b'"status":"pass"'),
        ):
            with self.subTest(changed=changed), self.assertRaises(public_filter.FilterRefusal):
                public_filter.filter_records([changed], self.allowlists)


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


class SourceSelectionAcceptanceTests(unittest.TestCase):
    revision = "1" * 40
    lock_oid = "2" * 40
    forbidden_oid = "3" * 40

    def _build(self, forbidden_path=".npmrc", selected=None):
        selected = ["Cargo.lock"] if selected is None else selected
        tree = (
            ("100644 blob " + self.forbidden_oid + "\t" + forbidden_path + "\0"
             + "100644 blob " + self.lock_oid + "\tCargo.lock\0").encode("utf-8")
        )

        def git(argv, **_kwargs):
            result = type("Result", (), {"returncode": 0})()
            result.stdout = ((self.revision + "\n").encode("ascii")
                             if "rev-parse" in argv else tree)
            return result

        def read_blob(_repository, oid):
            self.assertEqual(oid, self.lock_oid, "excluded source blob must never be read")
            return b"version = 4\n"

        with tempfile.TemporaryDirectory() as temporary, \
                patch.object(bundle.subprocess, "run", side_effect=git), \
                patch.object(bundle, "_git_blob", side_effect=read_blob):
            return bundle.build_source_archive(
                temporary, self.revision, "core-node", FETCH_SHA, selected,
                {"Cargo.lock": "file_0001"}, {"suite::case": "case_0001"}, {},
            )

    def test_excluded_forbidden_source_path_does_not_block_selected_archive(self):
        archive = self._build()
        manifest, files, _directories = bundle.inspect_archive(archive, BINDINGS)
        self.assertEqual([row["path"] for row in manifest["files"]], ["Cargo.lock"])
        self.assertEqual(files, {"Cargo.lock": b"version = 4\n"})

    def test_selected_forbidden_source_paths_still_refuse_before_blob_reads(self):
        for name in (".npmrc", ".env", "nested/credentials"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary, \
                    patch.object(bundle.subprocess, "run", side_effect=self._git_metadata) as run_git, \
                    patch.object(bundle, "_git_blob") as read_blob:
                with self.assertRaisesRegex(bundle.Refusal, "archive-excluded-path"):
                    bundle.build_source_archive(
                        temporary, self.revision, "core-node", FETCH_SHA,
                        ["Cargo.lock", name], {"Cargo.lock": "file_0001"},
                        {"suite::case": "case_0001"}, {},
                    )
                self.assertEqual(run_git.call_count, 2, "only immutable Git metadata is inspected")
                read_blob.assert_not_called()

    def _git_metadata(self, argv, **_kwargs):
        tree = ("100644 blob " + self.forbidden_oid + "\t.npmrc\0"
                + "100644 blob " + self.lock_oid + "\tCargo.lock\0").encode("utf-8")
        result = type("Result", (), {"returncode": 0})()
        result.stdout = ((self.revision + "\n").encode("ascii")
                         if "rev-parse" in argv else tree)
        return result

    def test_unselected_forbidden_source_paths_are_not_read_or_rejected(self):
        for name in (".npmrc", ".env", "nested/credentials", "node_modules/hidden.js"):
            with self.subTest(name=name):
                archive = self._build(name)
                manifest, files, _directories = bundle.inspect_archive(archive, BINDINGS)
                self.assertEqual([row["path"] for row in manifest["files"]], ["Cargo.lock"])
                self.assertEqual(files["Cargo.lock"], b"version = 4\n")


class AuthenticatedSourceSetAcceptanceTests(unittest.TestCase):
    def test_current_source_set_binds_full_and_selected_maps_with_one_scoped_exclusion(self):
        source_sets = bundle._expected_core_rust_source_sets()
        self.assertEqual(source_sets["domain"], "keeldock" + "-core/core-rust-candidate-baseline/v1")
        candidate = source_sets["candidate"]
        self.assertEqual(candidate["source_revision"], "9d6cc9e68694e17857d7702e83654131804a1bda")
        self.assertEqual(candidate["tree_oid"], "958e13e531d1b2601f241a91a9f80a44ac04d889")
        self.assertEqual(candidate["full_map_sha256"],
                         "d6ef344e2129babea26ac39c04bacf7eb4cbd3d770acb8416b2fe11a1c334eab")
        self.assertEqual(candidate["selected_map_sha256"],
                         "ca99e9c82c8ea07bc4a1d73d881da673dc5f71194c0db4c61c179da5d248b6b3")
        self.assertEqual(candidate["selected_file_count"], 2636)
        self.assertEqual(candidate["selected_bytes"], 16619832)
        self.assertEqual(source_sets["exclusions"], [
            {"path": ".npmrc", "status": "untransferred-unscanned"},
        ])
        baseline = source_sets["baseline_runtime"]
        self.assertEqual(baseline["source_revision"], "bb1258247ebbbcfec7f112c67dd15902a0f4d4d1")
        self.assertEqual(baseline["map_sha256"],
                         "e0a6b6b1c822658b2d55555c2e790193d0fff402632d7df8c22e2d031e5cb1f3")
        self.assertEqual((baseline["file_count"], baseline["bytes"]), (59, 253657))

    def _crosslink_fixture(self, top_revision=None):
        candidate = {
            "Cargo.toml": b"x", "Cargo.lock": b"x",
            "runtime/Cargo.toml": b"x", "runtime/Cargo.lock": b"x",
            "fuzz/Cargo.toml": b"x", "fuzz/Cargo.lock": b"x",
        }
        baseline = {"Cargo.toml": b"y", "Cargo.lock": b"z"}
        candidate_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in candidate.items()}
        baseline_hashes = {name: hashlib.sha256(data).hexdigest() for name, data in baseline.items()}
        source_revision = "1" * 40
        patch_values = {
            "CORE_RUST_SOURCE_REVISION": source_revision,
            "CORE_RUST_SOURCE_TREE": "2" * 40,
            "CORE_RUST_FULL_MAP_SHA256": "a" * 64,
            "CORE_RUST_SELECTED_MAP_SHA256": bundle.r4_source_map_sha256(candidate_hashes),
            "CORE_RUST_SELECTED_FILE_COUNT": len(candidate),
            "CORE_RUST_SELECTED_TOTAL_BYTES": sum(map(len, candidate.values())),
            "CORE_RUST_SELECTED_MANIFEST_SHA256": {
                name: candidate_hashes[name]
                for name in ("Cargo.toml", "runtime/Cargo.toml", "fuzz/Cargo.toml")
            },
            "CORE_RUST_BASELINE_REVISION": "4" * 40,
            "CORE_RUST_BASELINE_MAP_SHA256": bundle.r4_source_map_sha256(baseline_hashes),
            "CORE_RUST_BASELINE_FILE_COUNT": len(baseline),
            "CORE_RUST_BASELINE_TOTAL_BYTES": sum(map(len, baseline.values())),
            "CORE_RUST_BASELINE_RUNTIME_MANIFEST_SHA256": baseline_hashes["Cargo.toml"],
            "CORE_RUST_BASELINE_RUNTIME_LOCK_SHA256": baseline_hashes["Cargo.lock"],
        }
        content = dict(candidate)
        content.update({bundle.BASELINE_NAMESPACE + "/" + name: data for name, data in baseline.items()})
        inventory = {name: (len(data), hashlib.sha256(data).hexdigest()) for name, data in content.items()}
        files = [
            {"path": name, "size": size, "sha256": digest}
            for name, (size, digest) in sorted(inventory.items())
        ]
        value = {
            "schema": 2, "profile": "core-rust", "profile_revision": 1,
            "source_revision": top_revision or source_revision,
            "tree_sha256": hashlib.sha256(bundle.canonical_json(files)).hexdigest(),
            "files": files,
            "original_lockfiles": {
                name: candidate_hashes[name]
                for name in ("Cargo.lock", "runtime/Cargo.lock", "fuzz/Cargo.lock")
            },
            "fetch_sha256": FETCH_SHA,
            "allowed_files": {"Cargo.lock": "file_0001"},
            "allowed_tests": {
                "root::Cargo.toml::case": "case_0001",
                "runtime::runtime/Cargo.toml::case": "case_0002",
                "listener::runtime/crates/services/listener/Cargo.toml::case": "case_0003",
            },
            "frames": {},
            "limits": {
                "ciphertext_bytes": bundle.MAX_CIPHERTEXT,
                "expanded_bytes": bundle.MAX_EXPANDED,
                "files": bundle.MAX_FILES,
                "file_bytes": bundle.MAX_FILE,
            },
        }
        with patch.multiple(bundle, **patch_values):
            value["source_sets"] = bundle._expected_core_rust_source_sets()
            return value, inventory, patch_values

    def test_v2_manifest_top_level_source_revision_matches_candidate_source_set(self):
        value, inventory, patch_values = self._crosslink_fixture()
        with patch.multiple(bundle, **patch_values):
            parsed = bundle._manifest(
                bundle.canonical_json(value),
                {"profile": "core-rust", "fetch_sha256": FETCH_SHA}, inventory,
            )
        self.assertEqual(parsed["source_revision"], parsed["source_sets"]["candidate"]["source_revision"])

    def test_v2_manifest_refuses_candidate_source_revision_attribution_mismatch(self):
        value, inventory, patch_values = self._crosslink_fixture("3" * 40)
        with patch.multiple(bundle, **patch_values):
            with self.assertRaisesRegex(bundle.Refusal, "inner-source-revision-mismatch"):
                bundle._manifest(
                    bundle.canonical_json(value),
                    {"profile": "core-rust", "fetch_sha256": FETCH_SHA}, inventory,
                )

    def test_v2_manifest_still_refuses_malformed_top_level_source_revision(self):
        value, inventory, patch_values = self._crosslink_fixture("invalid")
        with patch.multiple(bundle, **patch_values):
            with self.assertRaisesRegex(bundle.Refusal, "inner-source-revision$"):
                bundle._manifest(
                    bundle.canonical_json(value),
                    {"profile": "core-rust", "fetch_sha256": FETCH_SHA}, inventory,
                )

    def test_v2_bundle_binds_candidate_and_baseline_only_after_encrypted_transfer(self):
        candidate = {
            "Cargo.toml": b"[workspace]\n",
            "Cargo.lock": b"version = 3\n",
            "runtime/Cargo.toml": b"[workspace]\n",
            "runtime/Cargo.lock": b"version = 3\n",
            "fuzz/Cargo.toml": b"[package]\n",
            "fuzz/Cargo.lock": b"version = 3\n",
        }
        baseline = {
            "Cargo.toml": b"[package]\nname = 'baseline'\n",
            "Cargo.lock": b"version = 3\n",
            "src/lib.rs": b"pub fn baseline() {}\n",
        }
        candidate_map = {name: hashlib.sha256(payload).hexdigest() for name, payload in candidate.items()}
        baseline_map = {name: hashlib.sha256(payload).hexdigest() for name, payload in baseline.items()}
        candidate_digest = bundle.r4_source_map_sha256(candidate_map)
        baseline_digest = bundle.r4_source_map_sha256(baseline_map)
        candidate_bytes = sum(map(len, candidate.values()))
        baseline_bytes = sum(map(len, baseline.values()))
        revision = "1" * 40
        tree_oid = "2" * 40
        blob_oids = {name: ("%040x" % (index + 3)) for index, name in enumerate(candidate)}
        metadata_rows = [
            ("100644", "blob", blob_oids[name], name) for name in candidate
        ] + [("100644", "blob", "9" * 40, ".npmrc")]
        tree_bytes = b"".join(
            (mode + " " + kind + " " + oid + "\t" + name + "\0").encode("utf-8")
            for mode, kind, oid, name in metadata_rows
        )
        payload_by_oid = {blob_oids[name]: payload for name, payload in candidate.items()}

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repo"
            repository.mkdir()
            baseline_root = root / "baseline"
            for name, payload in baseline.items():
                target = baseline_root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(payload)

            def git(argv, **_kwargs):
                result = type("Result", (), {"returncode": 0})()
                if any(type(item) is str and item.endswith("^{tree}") for item in argv):
                    result.stdout = (tree_oid + "\n").encode("ascii")
                elif "rev-parse" in argv:
                    result.stdout = (revision + "\n").encode("ascii")
                else:
                    result.stdout = tree_bytes
                return result

            def read_blob(_repository, oid):
                self.assertNotEqual(oid, "9" * 40, "excluded .npmrc blob must never be read")
                return payload_by_oid[oid]

            patch_values = {
                "CORE_RUST_SOURCE_REVISION": revision,
                "CORE_RUST_SOURCE_TREE": tree_oid,
                "CORE_RUST_FULL_MAP_SHA256": "a" * 64,
                "CORE_RUST_SELECTED_MAP_SHA256": candidate_digest,
                "CORE_RUST_SELECTED_FILE_COUNT": len(candidate),
                "CORE_RUST_SELECTED_TOTAL_BYTES": candidate_bytes,
                "CORE_RUST_SELECTED_MANIFEST_SHA256": {
                    name: candidate_map[name] for name in ("Cargo.toml", "runtime/Cargo.toml", "fuzz/Cargo.toml")
                },
                "CORE_RUST_BASELINE_REVISION": "4" * 40,
                "CORE_RUST_BASELINE_MAP_SHA256": baseline_digest,
                "CORE_RUST_BASELINE_FILE_COUNT": len(baseline),
                "CORE_RUST_BASELINE_TOTAL_BYTES": baseline_bytes,
                "CORE_RUST_BASELINE_RUNTIME_MANIFEST_SHA256": baseline_map["Cargo.toml"],
                "CORE_RUST_BASELINE_RUNTIME_LOCK_SHA256": baseline_map["Cargo.lock"],
            }
            with patch.multiple(bundle, **patch_values), \
                    patch.object(bundle.subprocess, "run", side_effect=git), \
                    patch.object(bundle, "_git_blob", side_effect=read_blob):
                source_sets = bundle._expected_core_rust_source_sets()
                archive_bytes = bundle.build_source_archive(
                    repository, revision, "core-rust", FETCH_SHA, list(candidate),
                    {"Cargo.lock": "file_0001"},
                    {"root::Cargo.toml::case": "case_0001",
                     "runtime::runtime/Cargo.toml::case": "case_0002",
                     "listener::runtime/crates/services/listener/Cargo.toml::case": "case_0003"},
                    {}, baseline_runtime_root=baseline_root, source_sets=source_sets,
                )
                expected = dict(BINDINGS, profile="core-rust")
                manifest, contents, _directories = bundle.inspect_archive(archive_bytes, expected)

        self.assertEqual(manifest["schema"], 2)
        self.assertEqual(manifest["source_sets"], source_sets)
        self.assertNotIn(".npmrc", contents)
        self.assertEqual(contents[".devlane/baseline-runtime/Cargo.lock"], baseline["Cargo.lock"])
        self.assertEqual(contents["Cargo.lock"], candidate["Cargo.lock"])

    def test_v2_manifest_rejects_candidate_or_baseline_map_drift(self):
        inventory = {
            "Cargo.toml": (1, "a" * 64),
            "Cargo.lock": (1, "a" * 64),
            ".devlane/baseline-runtime/Cargo.toml": (1, "b" * 64),
            ".devlane/baseline-runtime/Cargo.lock": (1, "b" * 64),
        }
        with patch.multiple(
                bundle,
                CORE_RUST_SELECTED_FILE_COUNT=2,
                CORE_RUST_SELECTED_TOTAL_BYTES=2,
                CORE_RUST_SELECTED_MAP_SHA256=bundle.r4_source_map_sha256({
                    "Cargo.toml": "a" * 64, "Cargo.lock": "a" * 64}),
                CORE_RUST_SELECTED_MANIFEST_SHA256={"Cargo.toml": "a" * 64},
                CORE_RUST_BASELINE_FILE_COUNT=2,
                CORE_RUST_BASELINE_TOTAL_BYTES=2,
                CORE_RUST_BASELINE_MAP_SHA256=bundle.r4_source_map_sha256({
                    "Cargo.toml": "b" * 64, "Cargo.lock": "b" * 64}),
                CORE_RUST_BASELINE_RUNTIME_MANIFEST_SHA256="b" * 64,
                CORE_RUST_BASELINE_RUNTIME_LOCK_SHA256="b" * 64):
            source_sets = bundle._expected_core_rust_source_sets()
            bundle._validate_core_rust_source_sets(source_sets, inventory)
            changed = dict(source_sets)
            changed["candidate"] = dict(source_sets["candidate"], selected_map_sha256="c" * 64)
            with self.assertRaisesRegex(bundle.Refusal, "source-sets-candidate-binding"):
                bundle._validate_core_rust_source_sets(changed, inventory)


class NodeVendorIntegrationAcceptanceTests(unittest.TestCase):
    def test_official_source_flows_through_the_existing_snapshot_and_exact_node(self):
        self.assertEqual(node_tool_snapshot.PREPARATION_ID,
                         "nodejs-dist-v24.22.1-linux-x64-sha256")
        validated = {"node": "/sealed/node/bin/node", "npm_cli": "/sealed/node/npm-cli.js"}
        self.assertEqual(prepare.node_version_commands(validated), {
            "node": [validated["node"], "--version"],
            "npm": [validated["node"], validated["npm_cli"], "--version"],
        })
        prepare_source = inspect.getsource(prepare.main)
        self.assertIn("node_vendor_source.acquire_node_source", prepare_source)
        self.assertIn("node_tool_snapshot.create_snapshot", prepare_source)
        workflow = (Path(__file__).resolve().parents[2]
                    / ".github/workflows/devlane-encrypted.yml").read_text(encoding="utf-8")
        prepare_step = workflow.split("- name: Prepare dependencies before the cut", 1)[1].split(
            "- name:", 1,
        )[0]
        self.assertNotIn("actions/setup-node@", workflow)
        self.assertNotIn("/opt/hostedtoolcache", workflow + prepare_source)
        self.assertNotIn("command -v node", prepare_step)
        self.assertNotIn("command -v npm", prepare_step)
        self.assertIn('--deadline-file "$RUN_ROOT/deadline.json"', prepare_step)
        self.assertIn("node_vendor_source.PROTECTED_BASE", inspect.getsource(host_cleanup.clean_node_vendor_source))

    def test_owned_vendor_cleanup_unlinks_symlink_without_touching_external_tree(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            base = root / "node-vendor"
            area = base / "test-cleanup"
            outside = root / "outside"
            outside.mkdir()
            marker = outside / "marker"
            marker.write_text("preserved", encoding="ascii")
            (area / "cache").mkdir(parents=True)
            (area / "cache" / "escape").symlink_to(outside, target_is_directory=True)
            (area / "cache" / "data").write_text("fixture", encoding="ascii")
            with patch.object(host_cleanup.node_vendor_source, "PROTECTED_BASE", base):
                self.assertTrue(host_cleanup.clean_node_vendor_source("test-cleanup", control_uid=os.getuid()))
            self.assertFalse(area.exists())
            self.assertEqual(marker.read_text(encoding="ascii"), "preserved")


class OfflineProjectionV2AcceptanceTests(unittest.TestCase):
    def _constraint_envelope(self, source_commit, package, requirement, ident, *, empty=False):
        envelope = {
            "schema": 2,
            "profile": "core-rust",
            "source_commit": source_commit,
            "control_sha": CONTROL_SHA,
            "toolchain": "1.99.1",
            "target_set": ["x86_64-unknown-linux-gnu"],
            "resolution_mode": "external-all-features-all-targets-v2",
            "resolver_version": "3" if empty else "2",
            "constraints": [] if empty else [{"id": ident, "package": package, "version_req": requirement}],
        }
        digest_input = {key: envelope[key] for key in (
            "schema", "profile", "toolchain", "target_set", "resolution_mode", "resolver_version",
        )}
        digest_input["constraints"] = [] if empty else [{"package": package, "version_req": requirement}]
        envelope["manifest_projection_sha256"] = hashlib.sha256(bundle.canonical_json(digest_input)).hexdigest()
        return envelope

    def _request(self):
        return {
            "schema": 2,
            "profile": "core-rust",
            "control_sha": CONTROL_SHA,
            "tools": {"cargo": "1.99.1", "rustc": "1.99.1"},
            "source_sets": bundle._expected_core_rust_source_sets(),
            "manifest_constraints": {
                "candidate": self._constraint_envelope(
                    bundle.CORE_RUST_SOURCE_REVISION, "serde", "^1.0", "d000001"),
                "baseline_runtime": self._constraint_envelope(
                    bundle.CORE_RUST_BASELINE_REVISION, "tokio", "^1.0", "d000002", empty=True),
            },
        }

    def test_projection_producer_binds_sanitized_candidate_and_baseline_constraints(self):
        payload = project.build_projection(self._request())
        value = fetch.validate_projection(payload, "core-rust", expected_control_sha=CONTROL_SHA)
        self.assertEqual(value["schema"], 2)
        self.assertEqual(set(value), {
            "schema", "profile", "tools", "source_sets", "manifest_constraints", "manifest_projection_sha256",
        })
        self.assertEqual(value["source_sets"]["candidate"]["selected_file_count"],
                         bundle.CORE_RUST_SELECTED_FILE_COUNT)
        self.assertEqual(value["source_sets"]["baseline_runtime"]["file_count"],
                         bundle.CORE_RUST_BASELINE_FILE_COUNT)

    def test_projection_requires_both_external_scopes_and_exact_control_binding(self):
        request = self._request()
        del request["manifest_constraints"]["baseline_runtime"]
        with self.assertRaisesRegex(bundle.Refusal, "projection-constraint-scopes"):
            project.build_projection(request)
        payload = project.build_projection(self._request())
        with self.assertRaisesRegex(fetch.Refusal, "projection-constraint-binding"):
            fetch.validate_projection(payload, "core-rust", expected_control_sha="c" * 40)

    def test_projection_refuses_private_package_namespace_and_missing_constraints(self):
        request = self._request()
        request["manifest_constraints"]["candidate"] = self._constraint_envelope(
            bundle.CORE_RUST_SOURCE_REVISION, "keeldock" + "-private", "^1", "d000001")
        with self.assertRaisesRegex(bundle.Refusal, "projection-constraint-row"):
            project.build_projection(request)
        request = self._request()
        request["manifest_constraints"]["candidate"] = self._constraint_envelope(
            bundle.CORE_RUST_SOURCE_REVISION, "serde", "^1", "d000001", empty=True)
        with self.assertRaisesRegex(fetch.Refusal, "projection-constraint-count"):
            project.build_projection(request)

    def test_pinned_baseline_rejects_added_external_constraints(self):
        request = self._request()
        request["manifest_constraints"]["baseline_runtime"] = self._constraint_envelope(
            bundle.CORE_RUST_BASELINE_REVISION, "serde", "^1", "d000002")
        with self.assertRaisesRegex(fetch.Refusal, "projection-baseline-constraints"):
            project.build_projection(request)

    def test_projection_input_cannot_supply_plaintext_baseline_paths(self):
        request = self._request()
        request["baseline_source_root"] = chr(47) + "private/baseline"
        with self.assertRaisesRegex(bundle.Refusal, "projection-request-shape"):
            project.build_projection(request)


class PostCutBaselineStagingAcceptanceTests(unittest.TestCase):
    def _baseline_binding(self, files):
        hashes = {name: hashlib.sha256(payload).hexdigest() for name, payload in files.items()}
        return {
            "source_revision": bundle.CORE_RUST_BASELINE_REVISION,
            "map_sha256": bundle.r4_source_map_sha256(hashes),
            "file_count": len(files),
            "bytes": sum(map(len, files.values())),
            "namespace": bundle.BASELINE_NAMESPACE,
            "runtime_manifest_sha256": hashes["Cargo.toml"],
            "runtime_lock_sha256": hashes["Cargo.lock"],
        }

    def _make_input(self, source_root, files):
        baseline = source_root / ".devlane/baseline-runtime"
        for name, payload in files.items():
            target = baseline / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(payload)
        return baseline

    def test_authenticated_baseline_moves_to_root_owned_readonly_mount_after_cut(self):
        files = {"Cargo.toml": b"[package]\n", "Cargo.lock": b"version = 3\n"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "workspace/source"
            source_root.mkdir(parents=True)
            namespace_root = root
            self._make_input(source_root, files)
            mounts = []
            source_sets = {"baseline_runtime": self._baseline_binding(files)}
            try:
                with patch.object(supervisor.os, "chown"), \
                        patch.object(supervisor, "_mount_bind", side_effect=lambda source, target, readonly: mounts.append(
                            (Path(source), Path(target), readonly))):
                    mountpoint = supervisor._stage_baseline_runtime_after_cut(
                        source_root, namespace_root, source_sets,
                    )
                self.assertEqual(mountpoint, root / "workspace/semver-baseline/runtime")
                self.assertEqual(len(mounts), 1)
                self.assertTrue(mounts[0][2], "baseline mount must be read-only")
                staged = root / "workspace/.devlane-baseline-input/runtime"
                self.assertEqual((staged / "Cargo.lock").read_bytes(), files["Cargo.lock"])
                self.assertEqual((staged / "Cargo.lock").stat().st_mode & 0o777, 0o444)
                self.assertEqual(staged.stat().st_mode & 0o777, 0o555)
                self.assertFalse((source_root / ".devlane").exists())
                decrypt_source = inspect.getsource(supervisor.Service._decrypt)
                self.assertLess(decrypt_source.index("self._verify_network_cut()"),
                                decrypt_source.index("_stage_baseline_runtime_after_cut("))
                self.assertLess(decrypt_source.index("self._verify_projection_bindings()"),
                                decrypt_source.index("_stage_baseline_runtime_after_cut("))
            finally:
                for path in sorted(root.rglob("*"), key=lambda item: len(item.parts), reverse=True):
                    if path.is_dir() and not path.is_symlink():
                        path.chmod(0o700)
                    elif path.exists() and not path.is_symlink():
                        path.chmod(0o600)

    def test_network_cut_is_rechecked_before_execute_and_filter_but_not_required_for_cleanup(self):
        execute_source = inspect.getsource(supervisor.Service._execute)
        verify = execute_source.index("self._verify_network_cut()")
        self.assertLess(verify, execute_source.index("_run_profile_command("))
        self.assertLess(verify, execute_source.index("output_filter.filter_records("))
        decrypt_source = inspect.getsource(supervisor.Service._decrypt)
        self.assertLess(decrypt_source.index("self._verify_network_cut()"),
                        decrypt_source.index("subprocess.Popen("))
        cleanup_source = inspect.getsource(supervisor.Service._cleanup)
        self.assertNotIn("_verify_network_cut()", cleanup_source)
        self.assertIn("_shred_tree", cleanup_source)

    def test_symlinked_baseline_is_refused_without_touching_external_canary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "workspace/source"
            source_root.mkdir(parents=True)
            source_parent = source_root / ".devlane"
            source_parent.mkdir()
            outside = root / "outside"
            outside.mkdir()
            canary = outside / "canary.txt"
            canary.write_text("external-canary", encoding="ascii")
            (source_parent / "baseline-runtime").symlink_to(outside, target_is_directory=True)
            with patch.object(supervisor, "_mount_bind") as mount_bind:
                with self.assertRaisesRegex(supervisor.SupervisorRefusal, "prepared-input-invalid"):
                    supervisor._stage_baseline_runtime_after_cut(
                        source_root, root, {"baseline_runtime": self._baseline_binding({
                            "Cargo.toml": b"x", "Cargo.lock": b"y",
                        })},
                    )
                mount_bind.assert_not_called()
            self.assertEqual(canary.read_text(encoding="ascii"), "external-canary")


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
        source_free = {**identity, "wave_class": fetch.SOURCE_FREE_WAVE_CLASS}
        self.assertEqual(fetch.validate_dispatch(source_free, now=1_999_999_000), source_free)
        for changed in (
            {**identity, "event": "pull_request"},
            {**identity, "ref": "refs/pull/5/merge"},
            {**identity, "run_attempt": 2},
            {**identity, "repository": "attacker/repo"},
            {**identity, "wave_class": "encrypted"},
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
                    patch.object(supervisor, "_signal_workload_descendants") as signal_children, \
                    patch.object(supervisor, "_kill_workload_descendants") as kill_children:
                self.assertEqual(supervisor._serve(args), 2)
                self.assertEqual(service.cleanup_calls, 1)
                self.assertGreaterEqual(signal_children.call_count, 1)
                kill_children.assert_not_called()
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
    ADAPTER_FAILURE = supervisor._control_failure("unit", "adapter-failed")
    REPORT_MISSING = supervisor._control_failure("unit", "report-missing")
    VITEST_FAILURE = supervisor._control_failure("unit", "vitest-failed")
    FILTER_FAILURE = b'{"code":"DEVLANE_FAILURE","kind":"control","stage":"unit","status":"fail","subreason":"filter-refused"}\n'

    def test_filter_refusal_has_only_a_fixed_public_subreason(self):
        self.assertEqual(supervisor._filter_failure_summary(), self.FILTER_FAILURE)

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
            self.assertEqual(records, [self.REPORT_MISSING])

            (root / "scratch/reports/vitest.json").write_bytes(b"{}")

            def node_timed_out(*args, **kwargs):
                (root / "scratch/reports/adapter.jsonl").write_bytes(b"")
                return 124

            with patch.object(supervisor, "_run_control_adapter", side_effect=node_timed_out):
                records = supervisor._adapter_records(
                    root, "core-node", manifest, [("typecheck", 0), ("unit", 0)], {}, {"typescript": 0})
            self.assertIn(self.ADAPTER_FAILURE, records)

            (root / "scratch/reports/vitest.json").unlink()
            records = supervisor._adapter_records(
                root, "core-node", manifest, [("typecheck", 0), ("unit", 1)], {}, {"typescript": 0})
            self.assertIn(self.REPORT_MISSING, records)
            self.assertNotIn(self.VITEST_FAILURE, records)

    def test_vitest_nonzero_with_a_valid_adapter_record_has_a_fixed_subreason(self):
        temporary, root = self._root()
        with temporary:
            (root / "scratch/reports/vitest.json").write_text("{}", encoding="ascii")
            manifest = {"allowed_files": {}, "allowed_tests": {"fixture test": "case_0001"}, "frames": {}}

            def adapter_records(_root, _command, _stage, _tools, _log_name, *, timeout):
                output = _root / "scratch/reports/adapter.jsonl"
                output.write_bytes(b'{"kind":"test","stage":"unit","test":"case_0001"}\n')
                return 0

            with patch.object(supervisor, "_run_control_adapter", side_effect=adapter_records):
                records = supervisor._adapter_records(
                    root, "core-node", manifest, [("unit", 1)], {}, {"typescript": 0})
            self.assertIn(b'{"kind":"test","stage":"unit","test":"case_0001"}', records)
            self.assertIn(self.VITEST_FAILURE, records)

    def test_clean_typescript_report_may_be_empty(self):
        temporary, root = self._root()
        with temporary:
            (root / "scratch/reports/typescript.jsonl").write_bytes(b"")
            (root / "scratch/reports/vitest.json").write_bytes(b"{}")
            manifest = {"allowed_files": {}, "allowed_tests": {}, "frames": {}}

            def clean_adapter(_root, _command, _stage, _tools, _log_name, *, timeout):
                (_root / "scratch/reports/adapter.jsonl").write_bytes(b"")
                return 0

            with patch.object(supervisor, "_run_control_adapter", side_effect=clean_adapter):
                records = supervisor._adapter_records(
                    root, "core-node", manifest, [("typecheck", 0), ("unit", 0)], {},
                    {"typescript": 0},
                )
            self.assertEqual(records, [])

    def test_browser_media_outputs_become_a_fixed_failure_before_playwright_report_mapping(self):
        media_paths = (
            "scratch/playwright-results/nested/failure.png",
            "scratch/playwright-results/trace.zip",
            "scratch/reports/nested/video.webm",
        )
        for media_path in media_paths:
            with self.subTest(media_path=media_path):
                temporary, root = self._root()
                with temporary:
                    media = root / media_path
                    media.parent.mkdir(parents=True, exist_ok=True)
                    media.write_bytes(b"media")
                    (root / "scratch/reports/typescript.jsonl").write_bytes(b"")
                    (root / "scratch/reports/vitest.json").write_bytes(b"{}")
                    manifest = {"allowed_files": {}, "allowed_tests": {},
                                "frames": {"browser frame": "frame_0001"}}

                    def unit_adapter(_root, _command, _stage, _tools, _log_name, *, timeout):
                        (_root / "scratch/reports/adapter.jsonl").write_bytes(b"")
                        return 0

                    with patch.object(supervisor, "_run_control_adapter", side_effect=unit_adapter) as adapter:
                        records = supervisor._adapter_records(
                            root, "core-node", manifest,
                            [("typecheck", 0), ("unit", 0), ("browser", 0)], {}, {"typescript": 0},
                        )
                    self.assertEqual(adapter.call_count, 1)
                    self.assertEqual(records, [supervisor._control_failure("browser")])

    def test_missing_rust_matrix_report_reaches_the_rehearsal_coverage_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "scratch/reports").mkdir(parents=True)
            records = supervisor._adapter_records(
                root, "core-rust", {"allowed_files": {}, "allowed_tests": {}, "frames": {}},
                [], {}, {"rust_matrix": 2},
            )
            self.assertEqual(records, [supervisor._control_failure("unit", "report-missing")])
            profile = json.loads((Path(__file__).resolve().parents[2]
                                  / "ci/devlane-profiles.json").read_text())['profiles']['core-rust']
            allowlists = {
                "files": {}, "tests": {}, "frames": {}, "stages": profile["stages"],
                "codes": sorted(set(profile["diagnostic_codes"] + ["DEVLANE_FAILURE"])),
                "max_lines": {}, "suites": sorted(profile["rust_matrix"]["coverage_ids"]),
            }
            summary = public_filter.filter_records(records, allowlists)
            scenario = {"profile": "core-rust", "allowed_files": {},
                        "allowed_tests": {}, "frames": {},
                        "expect_semver_execution_refusal": True}
            with self.assertRaisesRegex(RuntimeError, "rust-matrix-summary-coverage-set"):
                test_e2e._summary_records(summary, scenario)

    def test_rust_matrix_refusal_prints_a_fixed_reason_code(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "profiles.json"
            profile_path.write_text("{}", encoding="ascii")
            output = io.StringIO()
            profile = {"profiles": {"core-rust": {"rust_matrix": rust_matrix_runner.EXPECTED_MATRIX}}}
            with patch.object(rust_matrix_runner.bundle, "strict_json", return_value=profile), \
                    patch.object(rust_matrix_runner, "run",
                                 side_effect=rust_matrix_runner.MatrixRefusal("advisory-database-missing")), \
                    contextlib.redirect_stderr(output):
                result = rust_matrix_runner.main([
                    str(profile_path), "fixed-config", str(root / "report.jsonl"), "--deadline", "1",
                ])
            self.assertEqual(result, 2)
            line = output.getvalue().strip()
            self.assertEqual(line, "rust_matrix=refused code=advisory-database-missing")
            self.assertTrue(diagnostic_contract.public_e2e_command_diagnostic(line))
            self.assertEqual(
                rust_matrix_runner._refusal_code(rust_matrix_runner.MatrixRefusal("private/path")),
                "matrix-runner-failed",
            )

    def test_rust_tool_install_makes_the_copied_staging_root_worker_traversable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "staging"
            prepared = root / "prepared"
            source.mkdir(mode=0o700)
            prepared.mkdir(mode=0o755)
            for name in rust_tooling.TOOLS:
                (source / name).write_text("fixture tool", encoding="ascii")
            (source / rust_tooling.SEMVER_RECEIPT).write_text("{}", encoding="ascii")
            advisory = source / "advisory-db/crates/fixture"
            advisory.mkdir(parents=True, mode=0o700)
            (advisory / "RUSTSEC-2026-0001.md").write_text("fixture advisory", encoding="ascii")
            for current, directories, _files in os.walk(source, topdown=False):
                os.chmod(current, 0o700)
                for directory in directories:
                    os.chmod(Path(current) / directory, 0o700)

            with patch.object(rust_tooling, "_remaining", return_value=30):
                rust_tooling.install(str(source), str(prepared), "fixed-deadline")

            tools = prepared / "devlane-tools"
            self.assertEqual(tools.stat().st_mode & 0o777, 0o555)
            for current, directories, _files in os.walk(tools, followlinks=False):
                for directory in (".", *directories):
                    path = Path(current) if directory == "." else Path(current) / directory
                    self.assertEqual(path.stat().st_mode & 0o777, 0o555)

    def test_adapter_status_must_agree_with_a_complete_regular_report(self):
        temporary, root = self._root()
        with temporary:
            output = root / "scratch/reports/out.jsonl"
            test_record = b'{"kind":"test","stage":"unit","test":"case_0001"}\n'
            control = self.FAILURE + b"\n"
            cases = (
                ("rust clean", b"", 0, "tests", []),
                ("rust failing test", test_record, 1, "tests", [test_record[:-1]]),
                ("rust failing status without records", b"", 1, "tests", [self.ADAPTER_FAILURE]),
                ("rust records with clean status", test_record, 0, "tests", [self.ADAPTER_FAILURE]),
                ("adapter refused", control, 2, "tests", [self.ADAPTER_FAILURE]),
                ("signal exit", b"", 137, "tests", [self.ADAPTER_FAILURE]),
                ("interrupted write", test_record[:-4], 1, "tests", [self.ADAPTER_FAILURE]),
                ("node clean", test_record, 0, "node", [test_record[:-1]]),
                ("node control failure", control, 1, "node", [self.ADAPTER_FAILURE]),
                ("node control failure with clean status", control, 0, "node", [self.ADAPTER_FAILURE]),
                ("node failing status without control record", test_record, 1, "node", [self.ADAPTER_FAILURE]),
                ("garbage", b"not-json\n", 0, "node", [self.ADAPTER_FAILURE]),
            )
            for label, payload, status, rule, expected in cases:
                with self.subTest(label):
                    if output.exists():
                        output.unlink()
                    output.write_bytes(payload)
                    self.assertEqual(supervisor._adapter_lines(output, status, "unit", rule=rule), expected)
            output.unlink()
            self.assertEqual(supervisor._adapter_lines(output, 0, "unit", rule="tests"), [self.ADAPTER_FAILURE])

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
                self.assertEqual(supervisor._adapter_lines(path, 0, "unit", rule="tests"), [self.ADAPTER_FAILURE])


class CleanupLifecycleTests(unittest.TestCase):
    def test_host_cleanup_accepts_only_fixed_isolated_cleanup_reasons(self):
        for reason in diagnostic_contract.CLEANUP_SUBREASONS:
            stderr = ("cleanup_reason=" + reason + "\ncleanup_receipt=unconfirmed\n").encode("ascii")
            self.assertEqual(host_cleanup._isolated_cleanup_reason(stderr), reason)
        self.assertEqual(host_cleanup._isolated_cleanup_reason(
            b"cleanup_reason=private-path\ncleanup_receipt=unconfirmed\n"), "")
        self.assertEqual(host_cleanup._isolated_cleanup_reason(
            b"cleanup_reason=umount-busy\nprivate-path\n"), "")

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
    def test_preparation_mount_ledger_unmounts_proc_before_parent_mounts(self):
        root = Path("/prep/root")
        targets = (root, root / "dev", root / "proc", root / "work")
        mounted = set(targets)
        commands = []

        def unmount(argv, **_kwargs):
            commands.append(tuple(argv))
            mounted.remove(Path(argv[-1]))

        original = list(prepare.MOUNT_TARGETS)
        try:
            prepare.MOUNT_TARGETS[:] = targets
            with patch.object(prepare.os.path, "ismount", side_effect=lambda path: Path(path) in mounted), \
                    patch.object(prepare, "_bounded_timeout", return_value=5), \
                    patch.object(prepare.subprocess, "run", side_effect=unmount):
                reason = prepare._unmount_tracked_mounts()
        finally:
            prepare.MOUNT_TARGETS[:] = original
        self.assertEqual(reason, "")
        self.assertEqual([command[-1] for command in commands], [str(path) for path in reversed(targets)])
        self.assertEqual(mounted, set())
        source = Path(prepare.__file__).read_text(encoding="utf-8")
        self.assertIn('"mount", "-t", "proc"', source)
        self.assertIn("cleanup_reason = _unmount_tracked_mounts()", source)

    def test_preparation_unmount_reports_fixed_missing_or_busy_reasons(self):
        target = Path("/prep/root/proc")
        original = list(prepare.MOUNT_TARGETS)
        try:
            prepare.MOUNT_TARGETS[:] = (target,)
            with patch.object(prepare.os.path, "ismount", return_value=False):
                self.assertEqual(prepare._unmount_tracked_mounts(), "umount-missing")

            mounted = {target}
            commands = []

            def reject_unmount(argv, **_kwargs):
                commands.append(tuple(argv))
                raise subprocess.CalledProcessError(32, argv)

            with patch.object(prepare.os.path, "ismount", side_effect=lambda path: Path(path) in mounted), \
                    patch.object(prepare, "_bounded_timeout", return_value=5), \
                    patch.object(prepare.subprocess, "run", side_effect=reject_unmount):
                reason = prepare._unmount_tracked_mounts()
            self.assertEqual(reason, "umount-busy")
            self.assertEqual(commands, [("umount", str(target)), ("umount", "-l", str(target))])
        finally:
            prepare.MOUNT_TARGETS[:] = original

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

    def test_node_worker_has_writable_exec_temp_cache_and_worker_sized_limits(self):
        mount_source = inspect.getsource(supervisor._mount_minimal_root)
        device_source = inspect.getsource(supervisor._make_worker_devices)
        self.assertIn('_mount_tmpfs(root / "tmp", "512m", "01777", "nosuid,nodev")', mount_source)
        self.assertIn('_mount_tmpfs(root / "workspace", "4g", "0755", "nosuid,nodev")', mount_source)
        self.assertIn('_mount_tmpfs(root / "scratch", "4g", "0755", "nosuid,nodev")', mount_source)
        self.assertIn('"proc", str(root / "proc")', mount_source)
        self.assertIn('_make_worker_devices(root / "dev")', mount_source)
        self.assertIn('("null", 0o666, 1, 3)', device_source)
        self.assertIn("os.chmod(device, mode)", device_source)
        self.assertIn('_mount_tmpfs(root / "dev/shm", "512m", "01777")', mount_source)
        executable_mounts = [line for line in mount_source.splitlines()
                             if "_mount_tmpfs(root /" in line]
        self.assertTrue(executable_mounts)
        self.assertTrue(all("noexec" not in line for line in executable_mounts))
        self.assertIn('"ro,nosuid,nodev,noexec"', mount_source)
        prepare_source = inspect.getsource(prepare._prepare_root)
        self.assertIn("size=512m,mode=01777,nosuid,nodev", prepare_source)
        self.assertNotIn("noexec", prepare_source)

        environment = supervisor._worker_environment("unit", Path("/unused"), {"node_dir": "/tools/node/bin"})
        self.assertEqual(environment["HOME"], "/devlane-home")
        self.assertEqual(environment["TMPDIR"], "/scratch/tmp")
        self.assertEqual(environment["XDG_CACHE_HOME"], "/scratch/tmp")
        self.assertNotIn("NODE_OPTIONS", environment)
        self.assertEqual(environment["PATH"].split(":")[0], "/tools/node/bin")

        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(supervisor.os, "chown"):
                supervisor._prepare_writable_scratch(Path(temporary))
            self.assertTrue((Path(temporary) / "scratch/tmp/vitest-cache").is_dir())

        limits = []
        with patch.object(supervisor.resource, "setrlimit",
                          side_effect=lambda limit, value: limits.append((limit, value))), \
                patch.object(supervisor.os, "umask"):
            supervisor._limited_child()
        requested = dict(limits)
        self.assertEqual(requested[supervisor.resource.RLIMIT_NPROC], (1024, 1024))
        self.assertEqual(requested[supervisor.resource.RLIMIT_NOFILE], (8192, 8192))
        self.assertEqual(requested[supervisor.resource.RLIMIT_CPU], (1200, 1200))
        self.assertNotIn(supervisor.resource.RLIMIT_AS, requested)

    def test_rust_chroot_mounts_host_alternatives_readonly_for_the_gnu_linker(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            host_alternatives = Path(temporary) / "alternatives"
            host_alternatives.mkdir()
            expected_base_mounts = (
                ("/usr", root / "usr"), ("/lib", root / "lib"), ("/lib64", root / "lib64"),
            )
            self.assertEqual(supervisor._host_toolchain_mounts(root)[:3], expected_base_mounts)
            with patch.object(Path, "is_dir", return_value=True):
                self.assertEqual(supervisor._host_toolchain_mounts(root)[-1],
                                 (Path("/etc/alternatives"), root / "etc/alternatives"))
            mount_sources = expected_base_mounts + ((host_alternatives, root / "etc/alternatives"),)
            mounted = []
            with patch.object(supervisor, "_host_toolchain_mounts",
                              return_value=mount_sources), \
                    patch.object(supervisor, "_mount_tmpfs"), \
                    patch.object(supervisor, "_mount_bind",
                                 side_effect=lambda source, target, readonly=False:
                                 mounted.append((Path(source), Path(target), readonly))), \
                    patch.object(supervisor, "_mount_fs"), \
                    patch.object(supervisor, "_make_worker_devices"), \
                    patch.object(supervisor.os, "chown"):
                supervisor._mount_minimal_root(root, Path("/unused"), Path("/unused"), Path(temporary))
            expected_readonly = ((Path(host), Path(guest), True) for host, guest in mount_sources
                                 if Path(host).exists())
            self.assertTrue(all(mount in mounted for mount in expected_readonly))

        rust_environment = supervisor._worker_environment(
            "unit", Path("/unused"), {"rust_dir": "/tools/rust/bin"},
        )
        self.assertEqual(rust_environment["CC"], "/usr/bin/cc")
        self.assertEqual(rust_environment["CARGO_TARGET_" + "X" + "86_64_UNKNOWN_LINUX_GNU_LINKER"],
                         "/usr/bin/cc")

    def test_rust_matrix_worker_gets_writable_raw_logs_and_vendor_cargo_home(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ownership = []
            with patch.object(supervisor.os, "chown",
                              side_effect=lambda path, uid, gid: ownership.append((path, uid, gid))):
                supervisor._prepare_writable_scratch(root)

            for relative in ("scratch/raw", "scratch/target", "scratch/cargo-home"):
                path = root / relative
                self.assertTrue(path.is_dir())
                self.assertIn((str(path), supervisor.WORKER_UID, supervisor.WORKER_GID), ownership)
            self.assertEqual((root / "scratch/raw").stat().st_mode & 0o777, 0o700)
            cargo_config = (root / "scratch/cargo-home/config.toml").read_text(encoding="ascii")
            self.assertIn('[source.crates-io]\nreplace-with = "vendored-sources"', cargo_config)
            self.assertIn('[source.vendored-sources]\ndirectory = "/prepared/cargo-vendor"', cargo_config)
            self.assertIn("[net]\noffline = true", cargo_config)

        rust_environment = supervisor._worker_environment(
            "unit", Path("/unused"), {"rust_dir": "/tools/rust/bin"},
        )
        self.assertEqual(rust_environment["HOME"], "/devlane-home")
        self.assertEqual(rust_environment["CARGO_HOME"], "/scratch/cargo-home")
        self.assertEqual(rust_environment["CARGO_TARGET_DIR"], "/scratch/target")
        self.assertEqual(rust_environment["LD_LIBRARY_PATH"], "/tools/rust/lib")


class RustMatrixHostConfigurationTests(unittest.TestCase):
    def test_matrix_process_gets_an_explicit_gnu_linker(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = Mock(pid=321, wait=Mock(return_value=0))
            with patch.object(rust_matrix_runner, "RAW", temporary), \
                    patch.object(rust_matrix_runner, "_remaining", return_value=30), \
                    patch.object(rust_matrix_runner.subprocess, "Popen", return_value=process) as spawn:
                rust_matrix_runner._run("fixed-linker-environment", ["true"], time.monotonic() + 30)
            environment = spawn.call_args.kwargs["env"]
            self.assertEqual(environment["CC"], "/usr/bin/cc")
            self.assertEqual(environment["CARGO_TARGET_" + "X" + "86_64_UNKNOWN_LINUX_GNU_LINKER"],
                             "/usr/bin/cc")

    def test_deny_audit_and_vet_argv_match_the_offline_matrix_contract(self):
        deny_policy = tomllib.loads(test_e2e.RUST_FIXTURE_SOURCES["deny.toml"].decode("ascii"))
        advisories = deny_policy["advisories"]
        self.assertEqual(advisories["yanked"], "deny")
        self.assertEqual(advisories["unmaintained"], "workspace")
        self.assertEqual(advisories["ignore"], [])
        self.assertNotIn("yanked", deny_policy)
        self.assertNotIn("unmaintained", deny_policy)

        checks = []

        def simple(records, suite, argv, deadline, timeout=1800):
            checks.append((suite, argv))
            records.append({"kind": "coverage", "stage": "unit", "suite": suite,
                            "total": 1, "passed": 1, "failed": 0, "ignored": 0})
            return True

        def rust_arm(records, scope, manifest, workspace_mode, mode, config, deadline):
            suffix = "all-features" if mode == "all" else "default"
            records.append({"kind": "coverage", "stage": "unit", "suite": scope + "-" + suffix,
                            "total": 1, "passed": 1, "failed": 0, "ignored": 0})
            return True

        def replay(records, mode, deadline):
            suffix = "all-features" if mode == "all" else "default"
            records.append({"kind": "coverage", "stage": "unit", "suite": "fuzz-replay-" + suffix,
                            "total": 1, "passed": 1, "failed": 0, "ignored": 0})
            return True

        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "matrix.jsonl"
            deadline = time.monotonic() + 60
            with patch.object(rust_matrix_runner, "_copy_advisory_database"), \
                    patch.object(rust_matrix_runner, "_simple_check", side_effect=simple), \
                    patch.object(rust_matrix_runner, "_rust_test_arm", side_effect=rust_arm), \
                    patch.object(rust_matrix_runner, "_fuzz_replay", side_effect=replay), \
                    patch.object(rust_matrix_runner, "_semver_check",
                                 side_effect=lambda records, _deadline:
                                 records.extend(rust_matrix_runner.semver_stage.records_for_exit(0)) or True):
                result = rust_matrix_runner.run(
                    rust_matrix_runner.EXPECTED_MATRIX, "fixed-test-map", str(report), deadline,
                )
        self.assertEqual(result, 0)

        deny = next(argv for suite, argv in checks if suite == "deny-root")
        self.assertEqual(deny[1:], [
            "--manifest-path", "/workspace/source/Cargo.toml", "--config", "/workspace/source/deny.toml",
            "--workspace", "--all-features", "--offline", "--locked", "check",
        ])
        audit = next(argv for suite, argv in checks if suite == "audit-root")
        self.assertEqual(audit[1:7], ["audit", "--deny", "unsound", "--no-fetch", "--no-yanked", "--db"])
        self.assertEqual(audit[7], "/scratch/cargo-home/advisory-dbs/" +
                         rust_matrix_runner.ADVISORY_DB_DIRECTORY)
        self.assertEqual(audit[8:], ["--file", "/workspace/source/Cargo.lock"])
        expected_vet = {
            "vet-root": ("/workspace/source/Cargo.toml", "/workspace/source/supply-chain"),
            "vet-runtime": ("/workspace/source/runtime/Cargo.toml", "/workspace/source/runtime/supply-chain"),
            "vet-fuzz": ("/workspace/source/fuzz/Cargo.toml", "/workspace/source/supply-chain"),
        }
        for suite, (manifest, store) in expected_vet.items():
            with self.subTest(suite=suite):
                argv = next(argv for name, argv in checks if name == suite)
                self.assertEqual(argv[1:], [
                    "vet", "check", "--manifest-path", manifest, "--store-path", store, "--locked", "--frozen",
                ])

    def test_public_fixture_contract_includes_vet_stores_and_licensed_manifests(self):
        root = Path(__file__).resolve().parents[2]
        profile = json.loads((root / "ci/devlane-profiles.json").read_text(encoding="utf-8"))["profiles"]["core-rust"]
        matrix = rust_matrix_runner.EXPECTED_MATRIX
        self.assertEqual(profile["rust_matrix"], matrix)
        self.assertEqual(matrix["toolchain"], "1.99.1")
        self.assertEqual(matrix["tool_versions"], {
            "cargo_deny": "0.20.2", "cargo_audit": "0.22.2", "cargo_vet": "0.10.3",
        })
        self.assertEqual(set(test_e2e.RUST_LOCKFILES), {
            "Cargo.lock", "fuzz/Cargo.lock", "runtime/Cargo.lock",
        })
        self.assertEqual(len(matrix["coverage_ids"]), 23)
        self.assertEqual(set(test_e2e.RUST_FIXTURE_TESTS), {
            "root::Cargo.toml::tests::child_has_no_control_secrets_or_sockets",
            "runtime::runtime/crates/services/listener/Cargo.toml::tests::listener_fixture_is_reachable",
            "fuzz::fuzz/Cargo.toml::tests::corpus_fixture_is_present",
            "listener::runtime/crates/services/listener/Cargo.toml::tests::listener_fixture_is_reachable",
        })
        for path in (
            "fuzz/corpus/valid-object.json", "fuzz/corpus/valid-array.json",
            "runtime/crates/services/listener/Cargo.toml",
        ):
            self.assertIn(path, test_e2e.RUST_FIXTURE_SOURCES)
        for path in (
            "supply-chain/audits.toml", "supply-chain/config.toml", "supply-chain/imports.lock",
            "runtime/supply-chain/audits.toml", "runtime/supply-chain/config.toml",
            "runtime/supply-chain/imports.lock",
        ):
            self.assertIn(path, test_e2e.RUST_FIXTURE_SOURCES)
        for path, header in (
            ("supply-chain/config.toml", bytes((35,)) + b" cargo-vet config file"),
            ("supply-chain/audits.toml", bytes((35,)) + b" cargo-vet audits file"),
            ("supply-chain/imports.lock", bytes((35,)) + b" cargo-vet imports lock"),
            ("runtime/supply-chain/config.toml", bytes((35,)) + b" cargo-vet config file"),
            ("runtime/supply-chain/audits.toml", bytes((35,)) + b" cargo-vet audits file"),
            ("runtime/supply-chain/imports.lock", bytes((35,)) + b" cargo-vet imports lock"),
        ):
            if path.endswith("imports.lock"):
                self.assertEqual(test_e2e.RUST_FIXTURE_SOURCES[path], bytes((10,)) + header + b"\n")
            else:
                self.assertTrue(test_e2e.RUST_FIXTURE_SOURCES[path].startswith(bytes((10,)) + header + b"\n\n"))
        for path in (
            "Cargo.toml", "crates/support/Cargo.toml", "fuzz/Cargo.toml",
            "runtime/crates/services/listener/Cargo.toml",
        ):
            with self.subTest(manifest=path):
                manifest = tomllib.loads(test_e2e.RUST_FIXTURE_SOURCES[path].decode("utf-8"))
                self.assertEqual(manifest["package"]["license"], "MIT")
                self.assertFalse(manifest["package"]["publish"])
        self.assertTrue(set(test_e2e.RUST_LOCKFILES).issubset(test_e2e.RUST_FIXTURE_SOURCES))
        _manifest, _lock, dependencies = fetch.project_cargo_lock(test_e2e.RUST_FIXTURE_SOURCES["Cargo.lock"])
        self.assertEqual({(row["name"], row["version"]) for row in dependencies},
                         {("fastrand", "2.5.0"), ("itoa", "1.0.19")})
        self.assertTrue(all(test_e2e.RUST_FIXTURE_SOURCES[path] for path in test_e2e.RUST_LOCKFILES))
        tooling_versions = {name: row[3].rsplit(" ", 1)[-1] for name, row in rust_tooling.TOOLS.items()}
        self.assertEqual(tooling_versions, {
            "cargo-deny": "0.20.2", "cargo-audit": "0.22.2", "cargo-vet": "0.10.3",
            "cargo-semver-checks": "0.51.0",
        })
        semver_tool = rust_tooling.TOOLS["cargo-semver-checks"]
        self.assertEqual(semver_tool[1], rust_matrix_runner.semver_stage.SEMVER_ASSET_SHA256)
        self.assertEqual(semver_tool[3], "cargo-semver-checks 0.51.0")
        generator = inspect.getsource(test_e2e._write_rust_fixture)
        self.assertIn("source_files()", generator)
        self.assertIn('"metadata", "--locked", "--offline"', generator)
        self.assertNotIn("generate-lockfile", generator)
        contract = inspect.getsource(test_e2e._validate_rust_fixture)
        self.assertIn("fetch.validate_projection", contract)
        self.assertIn("fetch.project_cargo_lock", contract)
        self.assertIn("bundle.inspect_archive", contract)
        install = inspect.getsource(test_e2e._run_scenario)
        self.assertIn("rust_tooling.install", install)
        self.assertIn('_phase_call("scenario-tool-verify", _verify_prepared_rust_tools, prepared, rust_tool_cache)',
                      install)
        self.assertLess(install.index("rust_tooling.install"), install.index('_phase_call("scenario-variant-run"'))
        main = inspect.getsource(test_e2e.main)
        self.assertLess(main.index("rust_tooling.fetch_tools"), main.index('_phase_call("scenario-run", _run_scenario'))
        prepared_tools = inspect.getsource(test_e2e._verify_prepared_rust_tools)
        self.assertIn("rust_tooling._hash_prepared_binary(path)", prepared_tools)
        self.assertIn("semver_stage.verify_tool(source)", prepared_tools)
        self.assertIn("semver_stage.verify_tool(tools)", prepared_tools)
        self.assertIn('"advisory-db"', prepared_tools)
        self.assertIn('"advisory-db-revision"', prepared_tools)
        self.assertIn("advisory-database-binding", prepared_tools)
        rustfmt = inspect.getsource(test_e2e._verify_rust_toolchain)
        self.assertIn('"which", "--toolchain", RUST_VERSION, "rustfmt"', rustfmt)


class RealLockfileAndFixtureTests(unittest.TestCase):
    def test_rust_summary_counts_only_allow_the_semver_refusal_arm_to_fail(self):
        suites = rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"]
        scenario = {"profile": "core-rust", "allowed_files": {}, "allowed_tests": {}, "frames": {}}

        def summary(refusal=False, failing_suite=None):
            rows = []
            for suite in suites:
                stage = ("format" if suite.startswith("fmt-") else
                         "deny" if suite.startswith("deny-") else
                         "audit" if suite.startswith("audit-") else
                         "vet" if suite.startswith("vet-") else
                         "semver" if suite == "semver-runtime" else "unit")
                fails = (suite == failing_suite
                         or (refusal and suite == "semver-runtime"))
                rows.append({
                    "kind": "coverage", "stage": stage, "suite": suite,
                    "total": 1, "passed": 0 if fails else 1,
                    "failed": 1 if fails else 0, "ignored": 0,
                })
            if refusal:
                rows.append({
                    "kind": "control", "stage": "semver", "status": "fail",
                    "code": "DEVLANE_SEMVER_EXECUTION",
                })
            return b"".join(sorted(
                json.dumps(row, sort_keys=True, separators=(",", ":")).encode("ascii") + b"\n"
                for row in rows
            ))

        passing = test_e2e._summary_records(summary(), scenario)
        self.assertEqual(len([row for row in passing if row["kind"] == "coverage"]), 23)

        refusal_scenario = {**scenario, "expect_semver_execution_refusal": True}
        refused = test_e2e._summary_records(summary(refusal=True), refusal_scenario)
        semver = next(row for row in refused if row.get("suite") == "semver-runtime")
        self.assertEqual([semver[name] for name in ("total", "passed", "failed", "ignored")], [1, 0, 1, 0])
        for suite in suites:
            if suite == "semver-runtime":
                continue
            with self.subTest(failing_suite=suite), self.assertRaisesRegex(
                    RuntimeError, "rust-matrix-summary-counts"):
                test_e2e._summary_records(summary(refusal=True, failing_suite=suite), refusal_scenario)
        with self.assertRaisesRegex(RuntimeError, "rust-matrix-summary-counts"):
            test_e2e._summary_records(summary(failing_suite="semver-runtime"), scenario)

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

    def test_late_node_manifests_include_the_typescript_reporter_runtime(self):
        for builder in (test_e2e._install_script_canary_manifest, test_e2e._browser_manifest):
            with self.subTest(builder=builder.__name__):
                manifest = json.loads(builder())
                self.assertEqual(
                    manifest["devDependencies"]["typescript"], test_e2e.TYPESCRIPT_VERSION,
                )

    def test_real_npm_lock_metadata_is_accepted_and_only_needed_fields_are_projected(self):
        lock = test_e2e._node_lock_from_reviewed({
            "typescript": "6.0.3", "vite": "8.3.5", "vitest": "5.0.5",
            "esbuild": "0.27.0", "rollup": "4.44.2",
        })
        packages = lock["packages"]
        self.assertTrue(any("/node_modules/" in path for path in packages))
        self.assertTrue(any("||" in str(value.get("engines", "")) for value in packages.values()))
        self.assertTrue(any(value.get("hasInstallScript") for value in packages.values()))
        self.assertTrue(any("libc" in value for value in packages.values()))
        _, projected, _ = fetch.project_npm_lock(bundle.canonical_json(lock))
        for entry in projected["packages"].values():
            self.assertFalse({"license", "funding", "deprecated", "hasInstallScript"} & set(entry))
        self.assertTrue(any("libc" in entry for entry in projected["packages"].values()))
        linux_native = packages["node_modules/@rolldown/binding-linux-x64-gnu"]
        self.assertTrue(linux_native["optional"])
        self.assertEqual((linux_native["os"], linux_native["cpu"], linux_native["libc"]),
                         (["linux"], ["x64"], ["glibc"]))
        self.assertIn("node_modules/@rolldown/binding-linux-x64-gnu", projected["packages"])
        self.assertTrue(test_e2e._validate_linux_native_lock(lock))
        fixture_packages = json.loads(test_e2e.SYNTHETIC_LOCK.read_text(encoding="utf-8"))["packages"]
        for package_path in ("node_modules/@esbuild/linux-x64", "node_modules/@rollup/rollup-linux-x64-gnu"):
            native = fixture_packages[package_path]
            self.assertTrue(native["optional"])
            self.assertEqual((native["os"], native["cpu"]), (["linux"], ["x64"]))

    def test_real_vitest_fixture_uses_threads_and_a_writable_scratch_cache(self):
        real_node = next(scenario for scenario in test_e2e.scenarios() if scenario["name"] == "real-node")
        files = real_node["files"]()
        config = files["packages/kernel-ui-kit/vitest.config.ts"].decode("ascii")
        self.assertIn("pool: 'threads'", config)
        self.assertIn("cacheDir: '/scratch/tmp/vitest-cache'", config)
        self.assertIn("tests/**/*.test.ts", config)
        self.assertIn("--include=optional", prepare.NPM_CI_ARGUMENTS)
        self.assertIn("--ignore-scripts", prepare.NPM_CI_ARGUMENTS)

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

    def test_linux_native_optional_packages_are_required_from_the_fixture_lock(self):
        lock = {"packages": {
            "node_modules/@esbuild/linux-x64": {
                "optional": True, "os": ["linux"], "cpu": ["x64"],
            },
            "node_modules/@rollup/rollup-linux-x64-gnu": {
                "optional": True, "os": ["linux"], "cpu": ["x64"],
            },
        }}
        self.assertTrue(test_e2e._validate_linux_native_lock(lock))
        for path, changes in (
                ("node_modules/@esbuild/linux-x64", {"os": ["darwin"]}),
                ("node_modules/@esbuild/linux-x64", {"optional": False}),
                ("node_modules/@rollup/rollup-linux-x64-gnu", {"cpu": ["arm64"]}),):
            candidate = json.loads(json.dumps(lock))
            candidate["packages"][path].update(changes)
            with self.subTest(path=path, changes=changes), self.assertRaisesRegex(
                    RuntimeError, "linux-native-lock-entry-missing"):
                test_e2e._validate_linux_native_lock(candidate)
        missing = json.loads(json.dumps(lock))
        del missing["packages"]["node_modules/@rollup/rollup-linux-x64-gnu"]
        with self.assertRaisesRegex(RuntimeError, "linux-native-lock-entry-missing"):
            test_e2e._validate_linux_native_lock(missing)

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

    def test_install_script_canary_requires_linux_x64_native_packages(self):
        with tempfile.TemporaryDirectory() as temporary:
            modules = Path(temporary) / "node_modules"
            launcher = modules / "esbuild/bin/esbuild"
            esbuild_binary = modules / "@esbuild/linux-x64/bin/esbuild"
            rollup_binary = modules / "@rollup/rollup-linux-x64-gnu/rollup.linux-x64-gnu.node"
            launcher.parent.mkdir(parents=True)
            esbuild_binary.parent.mkdir(parents=True)
            rollup_binary.parent.mkdir(parents=True)
            launcher.write_text(chr(35) + "!/bin/sh\n" + chr(35)
                                + " lifecycle script did not replace this placeholder\n", encoding="ascii")
            esbuild_binary.write_bytes(b"linux esbuild binary")
            rollup_binary.write_bytes(b"linux rollup native module")
            os.chmod(esbuild_binary, 0o755)
            os.chmod(rollup_binary, 0o644)
            with patch.object(test_e2e.sys, "platform", "linux"), \
                    patch.object(test_e2e.os, "uname", return_value=SimpleNamespace(machine="x86_64")):
                test_e2e._install_script_canary_check(temporary)
                rollup_binary.unlink()
                with self.assertRaisesRegex(RuntimeError, "linux-rollup-native-package-missing"):
                    test_e2e._install_script_canary_check(temporary)

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


def load_tests(loader, standard_tests, _pattern):
    standard_tests.addTests(loader.loadTestsFromModule(test_node_vendor_source))
    standard_tests.addTests(loader.loadTestsFromModule(test_node_vendor_source_r2))
    return standard_tests


if __name__ == "__main__":
    unittest.main()
