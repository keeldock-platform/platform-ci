"""Source-free checks for the owner-side immutable Git projection reader."""

import hashlib
import json
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import bundle
import fetch
import project


class SourceProjectionTests(unittest.TestCase):
    def candidate(self):
        files = {}
        for index, name in enumerate(("Cargo.toml", "runtime/Cargo.toml", "fuzz/Cargo.toml")):
            files[name] = ('[package]\nname="private_sample_%d"\nversion="0.1.0"\n'
                           '[dependencies]\nserde="^1.0"\n' % index).encode()
        return files

    def read_candidate(self, files, *, mode=b"100644", wrong_tree=False):
        revision = bundle.CORE_RUST_SOURCE_REVISION
        oids = {name: "%040x" % (index + 1) for index, name in enumerate(files)}
        payloads = {oids[name]: value for name, value in files.items()}
        entries = [mode + b" blob " + oids[name].encode() + b"\t" + name.encode() + b"\x00"
                   for name in files]
        entries.append(b"120000 blob " + b"f" * 40 + b"\t.npmrc\x00")
        replies = [revision.encode() + b"\n",
                   ("0" * 40 if wrong_tree else bundle.CORE_RUST_SOURCE_TREE).encode() + b"\n",
                   b"".join(entries)]
        expected = {name: hashlib.sha256(value).hexdigest() for name, value in files.items()}
        with patch.object(project.subprocess, "run", side_effect=[
                SimpleNamespace(returncode=0, stdout=value) for value in replies]), \
                patch.object(bundle, "CORE_RUST_SELECTED_FILE_COUNT", len(files)), \
                patch.object(bundle, "CORE_RUST_SELECTED_MANIFEST_SHA256", expected), \
                patch.object(bundle, "_git_blob", side_effect=lambda _repo, oid: payloads[oid]) as blob:
            result = project._source_manifests(Path(__file__).parent, revision)
            self.assertEqual(blob.call_count, len(files))
            self.assertNotIn("f" * 40, [call.args[1] for call in blob.call_args_list])
            return result

    def test_exact_tree_reads_only_selected_manifests_and_never_excluded_blob(self):
        files = self.candidate()
        self.assertEqual(self.read_candidate(files), files)

    def test_wrong_candidate_tree_refuses_before_blob_reads(self):
        with self.assertRaisesRegex(bundle.Refusal, "projection-source-tree"):
            self.read_candidate(self.candidate(), wrong_tree=True)

    def test_executable_manifest_is_refused(self):
        with self.assertRaisesRegex(bundle.Refusal, "projection-source-type"):
            self.read_candidate(self.candidate(), mode=b"100755")

    def test_baseline_reader_keeps_only_immutable_runtime_manifest(self):
        payload = b'[workspace]\nresolver="3"\nmembers=[]\n'
        rows = (b"100644 blob " + b"1" * 40 + b"\truntime/Cargo.toml\x00"
                b"100644 blob " + b"2" * 40 + b"\truntime/Cargo.lock\x00"
                b"160000 commit " + b"3" * 40 + b"\toutside\x00")
        replies = [bundle.CORE_RUST_BASELINE_REVISION.encode(), rows]
        with patch.object(project.subprocess, "run", side_effect=[
                SimpleNamespace(returncode=0, stdout=value) for value in replies]), \
                patch.object(bundle, "CORE_RUST_BASELINE_FILE_COUNT", 2), \
                patch.object(bundle, "CORE_RUST_BASELINE_RUNTIME_MANIFEST_SHA256",
                             hashlib.sha256(payload).hexdigest()), \
                patch.object(bundle, "_git_blob", return_value=payload) as blob:
            actual = project._source_manifests(
                Path(__file__).parent, bundle.CORE_RUST_BASELINE_REVISION, baseline=True)
        self.assertEqual(actual, {"Cargo.toml": payload})
        self.assertEqual(blob.call_count, 1)
        self.assertEqual(blob.call_args.args[1], "1" * 40)

    def test_owner_builder_serializes_public_constraints_without_private_names_or_paths(self):
        baseline = {"Cargo.toml": b'[workspace]\nresolver="3"\nmembers=["member"]\n',
                    "member/Cargo.toml": b'[package]\nname="private_baseline"\nversion="0.1.0"\n'}
        with patch.object(project, "_source_manifests", side_effect=[self.candidate(), baseline]):
            output = project.build_source_bound_rust_projection("owner-repository", "a" * 40)
        parsed = fetch.validate_projection(output, "core-rust", expected_control_sha="a" * 40)
        self.assertEqual(parsed["manifest_constraints"]["baseline_runtime"]["constraints"], [])
        self.assertEqual(len(parsed["manifest_constraints"]["candidate"]["constraints"]), 1)
        for marker in (b"private_sample", b"private_baseline", b"owner-repository"):
            self.assertNotIn(marker, output)
        self.assertNotIn("Cargo.toml", json.dumps(parsed["manifest_constraints"]))

    def test_missing_control_identity_refuses_before_any_git_reader(self):
        with patch.object(project, "_source_manifests") as read:
            with self.assertRaisesRegex(bundle.Refusal, "projection-source-control"):
                project.build_source_bound_rust_projection("unused", None)
            read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
