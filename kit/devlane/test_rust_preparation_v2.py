"""Source-free regressions for pre-cut registry preparation."""
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import bundle
import constraint_resolver
import project
import rust_preparation_v2 as worker
import rust_preparation_smoke as smoke
import test_acceptance as acceptance

CONTROL_SHA = acceptance.CONTROL_SHA


class PreparationTests(unittest.TestCase):
    def request(self):
        return acceptance.OfflineProjectionV2AcceptanceTests()._request()

    def test_empty_baseline_is_explicit_and_candidate_default_still_refuses(self):
        kwargs = dict(source_commit="a" * 40, control_sha="b" * 40,
                      constraints=[], resolver_version="3")
        with self.assertRaisesRegex(constraint_resolver.Refusal, "constraint-count"):
            constraint_resolver.build_constraint_envelope(**kwargs)
        envelope = constraint_resolver.build_constraint_envelope(**kwargs, allow_empty=True)
        constraint_resolver.validate_constraints(
            envelope, expected_source_sha="a" * 40, expected_control_sha="b" * 40,
            allow_empty=True)
        with self.assertRaisesRegex(constraint_resolver.Refusal, "constraint-count"):
            constraint_resolver.validate_constraints(
                envelope, expected_source_sha="a" * 40, expected_control_sha="b" * 40)

    def test_public_constraints_reach_resolver_and_archives_share_one_budget(self):
        payload = project.build_projection(self.request())
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            deadline_file = root / "deadline.json"
            deadline_file.write_bytes(bundle.canonical_json({
                "schema": 1, "work_deadline": time.monotonic() + 100,
                "cleanup_reserve": 10, "job_seconds": 200}))
            result = {"packages": [], "resolver_lock": b"public resolver lock",
                      "tool_hashes": {"cargo_sha256": "a" * 64},
                      "tool_provenance_status": "binary-hash-bound-origin-unverified"}
            with patch.object(worker.constraint_resolver, "run_cargo_fixed_point", return_value=result) as resolve, \
                    patch.object(worker.bounded_registry_io, "build_bounded_registry",
                                 return_value=([], {"members": 0})) as archive:
                record = worker.prepare(payload, control_sha=CONTROL_SHA, scratch=root,
                                        output=root / "output", deadline_file=deadline_file)
            self.assertIs(resolve.call_args.kwargs["phase_budget"], archive.call_args.args[2])
            self.assertEqual(resolve.call_args.args[0], self.request()["manifest_constraints"]["candidate"])
            self.assertEqual(record["baseline_external_packages"], [])
            self.assertEqual((root / "output/cargo-config.toml").read_text(), worker.CONFIG)
            self.assertEqual({p.name for p in (root / "output").iterdir()},
                             {"projection.json", "cargo-config.toml", "registry-preparation.json"})

    def test_wrong_control_refuses_before_resolution_or_writes(self):
        with patch.object(worker.constraint_resolver, "run_cargo_fixed_point") as resolve:
            with self.assertRaisesRegex(bundle.Refusal, "projection-constraint-binding"):
                worker.prepare(project.build_projection(self.request()), control_sha="c" * 40,
                               scratch=Path("/unused"), output=Path("/unused-output"),
                               deadline_file="/unused-deadline")
            resolve.assert_not_called()

    def test_fifo_input_refuses_without_waiting_for_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            fifo = Path(temporary) / "input"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(bundle.Refusal, "rust-preparation-input-type"):
                worker.read_input(fifo)

    def test_cli_refuses_owner_machine_before_reading_input(self):
        with patch.object(worker.sys, "platform", "darwin"), patch.object(worker, "read_input") as read:
            with self.assertRaisesRegex(bundle.Refusal, "rust-preparation-worker-required"):
                worker.main(["--control-sha", CONTROL_SHA])
            read.assert_not_called()

    def test_public_linux_smoke_refuses_owner_machine_before_creating_files(self):
        args = ["--cargo-path", "unused", "--rustc-path", "unused", "--control-sha", CONTROL_SHA,
                "--deadline-file", "unused", "--owner-uid", "1001", "--owner-gid", "1001"]
        with patch.object(smoke.sys, "platform", "darwin"), patch.object(smoke, "smoke") as execute:
            with self.assertRaisesRegex(bundle.Refusal, "linux-root-required"):
                smoke.main(args)
            execute.assert_not_called()

    def test_smoke_preserves_the_preparation_child_file_limit_without_privileged_raise(self):
        def child(*_args, **kwargs):
            kwargs["preexec_fn"]()
            return type("Child", (), {"wait": lambda _self, **_kwargs: 0})()
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(smoke.deadline, "remaining", return_value=10), \
                    patch.object(smoke.subprocess, "Popen", side_effect=child), \
                    patch.object(smoke.resource, "setrlimit") as limits:
                smoke.run(["unused"], Path(temporary), "fixture", "unused", {})
            self.assertIn((smoke.resource.RLIMIT_FSIZE, (4 * 1024 * 1024, 256 * 1024 * 1024)),
                          [call.args for call in limits.call_args_list])


if __name__ == "__main__":
    unittest.main()
