import hashlib
import io
import json
import os
import subprocess
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import foundation_node_feedback
import confinement_public_audit
import confinement_verdict
import linux_source_build
import macos_core_contract


class LinuxSourceBuildTests(unittest.TestCase):
    def test_gate_order_matches_the_shared_macos_contracts(self):
        expected = (
            macos_core_contract.GATE_NAMES
            + macos_core_contract.PARSER_GATE_NAMES
            + foundation_node_feedback.NODE_GATE_NAMES
        )
        self.assertEqual(linux_source_build.GATES, expected)
        self.assertEqual(len(linux_source_build.GATES), 13)

    def test_source_job_steps_match_the_policy_audit_contract(self):
        self.assertEqual(
            linux_source_build.SOURCE_STEP_NAMES,
            (
                "Fetch exact public control",
                "Repeat preflight in source-read",
                "Record image and fetch pinned Rust and Node toolchains",
                "Harden runner paths before the proof",
                "Boundary self-test before source-reader mint",
                "Mint scoped source-reader token",
                "Verify selected installation identity",
                "Fetch exact source and verify binding, tree, signatures and lock provenance",
                "Revoke source-reader token and verify rejection",
                "Fetch npm tarballs by committed lock integrity",
                "Run trusted dependency audit",
                "Prepare offline project inputs",
                "Re-run positive controls immediately before the first project command",
                "Run all thirteen offline project gates",
                "Merge confinement phase records",
                "Forced faults must fail closed",
            ),
        )
        self.assertEqual(linux_source_build.VERDICT_STEP_NAMES, (
            "Fetch exact public control", "Record verifier image and Rust sysroot",
            "Harden verifier runner paths", "Run independent boundary self-test",
            "Re-run independent positive controls", "Merge independent confinement records",
            "Publish confinement verdict",
        ))
        self.assertEqual(
            linux_source_build.OPTIONAL_SOURCE_STEPS,
            frozenset((
                "Mint scoped source-reader token",
                "Verify selected installation identity",
                "Fetch exact source and verify binding, tree, signatures and lock provenance",
                "Revoke source-reader token and verify rejection",
                "Fetch npm tarballs by committed lock integrity",
                "Run trusted dependency audit",
                "Prepare offline project inputs",
                "Run all thirteen offline project gates",
                "Forced faults must fail closed",
            )),
        )

    def test_expected_run_assigns_the_plain_verdict_job_and_action_post(self):
        base = {"CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1"}
        source = linux_source_build._expected_run({**base, "CI_MODE": "source"}, "b" * 64)
        synthetic = linux_source_build._expected_run({**base, "CI_MODE": "synthetic"}, "b" * 64)
        self.assertEqual(source["verdict_job"], "linux-source-admission-verdict")
        self.assertEqual(source["jobs"][source["verdict_job"]]["steps"], linux_source_build.VERDICT_STEP_NAMES)
        self.assertEqual(source["jobs"]["linux-source-admission-source-read"]["steps"][-1], "Post Mint scoped source-reader token")
        self.assertNotIn("Post Mint scoped source-reader token", synthetic["jobs"]["linux-source-admission-source-read"]["steps"])

    def test_toolchain_versions_are_pinned_and_node_digest_is_a_coordinator_constant(self):
        self.assertEqual(linux_source_build.NODE_VERSION, "24.22.1")
        self.assertEqual(linux_source_build.NPM_VERSION, "11.19.1")
        self.assertTrue(linux_source_build.NODE_LINUX_TARBALL_SHA256.startswith("COORDINATOR_FILL_"))
        self.assertEqual(len(linux_source_build.RUST_COMPONENTS), 5)
        for name, url, digest in linux_source_build.RUST_COMPONENTS:
            with self.subTest(component=name):
                self.assertIn("1.99.1-x86_64-unknown-linux-gnu.tar.gz", url)
                self.assertRegex(digest, r"\A[a-f0-9]{64}\Z")

    def test_project_read_paths_are_outside_runner_temp(self):
        self.assertEqual(str(linux_source_build.TOOLCHAIN_ROOT), "/tmp/kd-toolchains")
        self.assertEqual(str(linux_source_build.PROJECT_ROOT), "/tmp/kd-project-worker")
        self.assertNotIn("runner-temp", str(linux_source_build.TOOLCHAIN_ROOT))
        self.assertNotIn("runner-temp", str(linux_source_build.PROJECT_ROOT))

    def test_archive_path_checks_allow_directory_entries_and_safe_relative_links(self):
        self.assertTrue(linux_source_build._safe_tar_member("component/"))
        self.assertFalse(linux_source_build._safe_tar_member("../escape"))
        self.assertTrue(linux_source_build._safe_tar_link("../lib/node.js"))
        self.assertFalse(linux_source_build._safe_tar_link("/etc/passwd"))

    def test_cargo_lock_rejects_any_registry_or_git_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            lock = Path(temporary) / "Cargo.lock"
            lock.write_text(
                'version = 3\n\n[[package]]\nname = "example"\nversion = "1.0.0"\n',
                encoding="utf-8",
            )
            linux_source_build._validate_cargo_lock_sources(temporary)
            lock.write_text(
                'version = 3\n\n[[package]]\nname = "example"\nversion = "1.0.0"\n'
                'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
                encoding="utf-8",
            )
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._validate_cargo_lock_sources(temporary)
            lock.write_text(
                'version = 3\n\n[[package]]\nname = "example"\nversion = "1.0.0"\n'
                'source = "git+https://example.invalid/repo"\n',
                encoding="utf-8",
            )
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._validate_cargo_lock_sources(temporary)

    def test_project_config_files_are_refused_or_removed_before_tool_use(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cargo = root / ".cargo"
            cargo.mkdir()
            cargo_config = cargo / "config.custom"
            cargo_config.write_text("[build]\njobs = 2\n", encoding="utf-8")
            npmrc = root / ".npmrc"
            npmrc.write_text("registry=https://registry.npmjs.org/\n", encoding="utf-8")
            linux_source_build._neutralize_config_files(root)
            self.assertFalse(cargo_config.exists())
            self.assertFalse(npmrc.exists())
            cargo_config.write_text(
                '[source.crates-io]\nreplace-with = "alternate"\n', encoding="utf-8"
            )
            with self.assertRaises(linux_source_build.SourceBuildRefusal):
                linux_source_build._neutralize_config_files(root)

    def test_gate_commands_are_offline_after_dependency_preparation(self):
        commands = linux_source_build._gate_commands(Path("/work"), "/rust", "/node")
        self.assertEqual(tuple(name for name, argv in commands), linux_source_build.GATES)
        for name, argv in commands:
            with self.subTest(gate=name):
                self.assertIn("--offline", argv)
        by_name = dict(commands)
        for name in ("node_dependency_prepare", "typescript_typecheck", "typescript_tests"):
            with self.subTest(gate=name):
                self.assertIn("--ignore-scripts", by_name[name])
        for name in ("node_dependency_prepare", "node_dependency_audit", "typescript_typecheck", "typescript_tests"):
            with self.subTest(gate=name):
                self.assertTrue(any(item.startswith("--workspaces") or item == "--workspaces" for item in by_name[name]))

    def test_project_root_refuses_a_hostile_symlink(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary)
            link = root.parent / (root.name + "-link")
            link.symlink_to(root, target_is_directory=True)
            try:
                with patch.object(linux_source_build, "PROJECT_ROOT", link):
                    with self.assertRaises(linux_source_build.SourceBuildRefusal):
                        linux_source_build._open_project_root()
            finally:
                link.unlink()

    def test_gate_directories_refuse_hostile_symlinks_without_ownership_changes(self):
        for create in (False, True):
            with self.subTest(create=create), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "root"
                worker = root / "source"
                outside = Path(temporary) / "outside"
                worker.mkdir(parents=True)
                outside.mkdir()
                for name in (".tmp", "target", ".npm-cache", ".kd-cargo-home"):
                    (worker / name).mkdir()
                (worker / ".home").symlink_to(outside, target_is_directory=True)
                before = outside.stat()
                flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
                with patch.object(linux_source_build, "PROJECT_ROOT", root), patch.object(
                    linux_source_build, "_open_project_root", side_effect=lambda: os.open(root, flags)
                ), patch.object(linux_source_build.linux_harness, "CHILD_UID", os.getuid()), patch.object(
                    linux_source_build.linux_harness, "CHILD_GID", os.getgid()
                ), patch.object(linux_source_build.os, "fchown", side_effect=AssertionError("unexpected chown")):
                    with self.assertRaises(linux_source_build.SourceBuildRefusal):
                        linux_source_build._project_gate_directories(worker, create=create)
                after = outside.stat()
                self.assertEqual((before.st_uid, before.st_gid, before.st_mode), (after.st_uid, after.st_gid, after.st_mode))

    def test_repeated_preflight_refuses_missing_binding_before_duplicate_check(self):
        sha = "a" * 40
        env = {
            "CI_EVENT_NAME": "workflow_dispatch", "CI_REPOSITORY": linux_source_build.REPOSITORY,
            "CI_SERVER_URL": "https://github.com", "CACHE_MODE": "none",
            "CI_SHA": sha, "GITHUB_SHA": sha, "CI_REF": "refs/heads/untrusted", "CI_MODE": "source",
        }
        with patch.object(linux_source_build, "_reference_sha", side_effect=["b" * 40, sha]), patch.object(
            linux_source_build, "_comparison", return_value="ahead"
        ), patch.object(linux_source_build, "_source_inputs", side_effect=linux_source_build.SourceBuildRefusal("binding")) as binding, patch.object(
            linux_source_build, "_require_no_duplicate"
        ) as duplicate:
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build.validate_dispatch(env, "token")
            binding.assert_called_once_with(env)
            duplicate.assert_not_called()

    def test_protected_source_binding_refuses_one_changed_fingerprint(self):
        sha = "a" * 40
        base = "b" * 40
        fingerprint = "c" * 64
        env = {
            "REQUESTED_SOURCE_SHA": sha, "REQUESTED_BASE_SHA": base,
            "REQUESTED_BASE_BRANCH": "main", "REQUESTED_FINGERPRINT": fingerprint,
            "CI_SHA": "d" * 40, "LINUX_SOURCE_ALLOWED_SHA": sha,
            "LINUX_SOURCE_ALLOWED_BASE_SHA": base, "LINUX_SOURCE_ALLOWED_BASE_BRANCH": "main",
            "LINUX_SOURCE_ALLOWED_FINGERPRINT": "e" * 64,
            "LINUX_SOURCE_ALLOWED_CONTROL_SHA": "d" * 40,
            "SOURCE_REPOSITORY_ID": "7", "SOURCE_REPOSITORY_OWNER": "owner",
            "SOURCE_REPOSITORY_NAME": "source", "SOURCE_READER_INSTALLATION_ID": "8",
            "SOURCE_READER_CLIENT_ID": "client", "LINUX_SOURCE_ACCEPTED_NODE_LOCK_SHA256": "f" * 64,
            "LINUX_SOURCE_ACCEPTED_MANIFEST_SHA256": "1" * 64,
            "LINUX_SOURCE_ACCEPTED_NODE_PROVENANCE_JSON": "{}",
            "LINUX_SOURCE_ENVIRONMENT_NAME": "source-read", "REQUESTED_ENVIRONMENT_NAME": "source-read",
        }
        with patch.object(linux_source_build, "_validate_provenance_binding") as provenance:
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "binding"):
                linux_source_build._source_inputs(env)
            provenance.assert_not_called()
            env["LINUX_SOURCE_ALLOWED_FINGERPRINT"] = fingerprint
            self.assertEqual(linux_source_build._source_inputs(env)["reviewed_diff_sha256"], fingerprint)
            provenance.assert_called_once()

    def test_default_checkout_environment_reaches_the_source_fetch(self):
        identity = {"owner": "owner", "name": "source", "repository_id": "7", "source_sha": "a" * 40}
        repository = {"id": 7, "private": True, "full_name": "owner/source"}
        marker = RuntimeError("source fetch reached")

        def git_call(unused_repo, *arguments, **unused_keywords):
            if arguments[:2] == ("remote", "add"):
                raise marker
            return subprocess.CompletedProcess(arguments, 0, b"", b"")

        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ, {"RUNNER_TEMP": temporary, "CI_REF": "refs/heads/untrusted", "SOURCE_READER_TOKEN": "token"}, clear=True
        ), patch.object(linux_source_build, "_source_inputs", return_value=identity), patch.object(
            linux_source_build, "_api_request", return_value=(200, repository)
        ), patch.object(linux_source_build, "_git", side_effect=git_call):
            with self.assertRaisesRegex(RuntimeError, "source fetch reached"):
                linux_source_build.checkout_source()

    def test_checkout_rejects_a_bad_signature_before_lock_or_project_work(self):
        source_sha = "a" * 40
        base_sha = "b" * 40
        identity = {
            "owner": "owner", "name": "source", "repository_id": "7", "source_sha": source_sha,
            "base_sha": base_sha, "base_branch": "main", "reviewed_diff_sha256": hashlib.sha256(b"").hexdigest(),
        }

        def git_call(unused_repo, *arguments, **unused_keywords):
            output = b""
            if arguments[:2] == ("rev-parse", "--verify"):
                reference = arguments[2]
                output = ((base_sha if reference.startswith("refs/remotes/") else "c" * 40 if reference == "HEAD^{tree}" else source_sha) + "\n").encode("ascii")
            return subprocess.CompletedProcess(arguments, 0, output, b"")

        with tempfile.TemporaryDirectory() as temporary, patch.object(
            linux_source_build, "_source_inputs", return_value=identity
        ), patch.object(linux_source_build, "_api_request", return_value=(200, {
            "id": 7, "private": True, "full_name": "owner/source",
        })), patch.object(linux_source_build, "_git", side_effect=git_call), patch.object(
            linux_source_build, "_verify_signatures", side_effect=linux_source_build.SourceBuildRefusal("signature")
        ) as signatures:
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "signature"):
                linux_source_build.checkout_source({
                    "RUNNER_TEMP": temporary, "CI_REF": "refs/heads/untrusted", "SOURCE_READER_TOKEN": "token",
                    "CI_WORKSPACE": temporary,
                })
            signatures.assert_called_once()

    def test_revoke_requires_the_unauthorized_response_and_writes_a_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            env = {"SOURCE_READER_TOKEN": "token", "RUNNER_TEMP": temporary}
            with patch.object(linux_source_build, "_api_request", side_effect=[(204, {}), (401, {})]) as api:
                self.assertEqual(linux_source_build.revoke_token(env), 0)
                self.assertEqual(api.call_count, 2)
                self.assertEqual(api.call_args.args[0], "/installation/repositories?per_page=1")
            receipt = json.loads((Path(temporary) / "kd-records" / "revocation.json").read_text(encoding="ascii"))
            self.assertTrue(receipt["rejected_after_revoke"])
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            linux_source_build, "_api_request", side_effect=[(204, {}), (200, {})]
        ):
            with self.assertRaisesRegex(linux_source_build.SourceBuildRefusal, "revocation"):
                linux_source_build.revoke_token({"SOURCE_READER_TOKEN": "token", "RUNNER_TEMP": temporary})
            self.assertFalse((Path(temporary) / "kd-records" / "revocation.json").exists())

    def test_real_gates_use_the_shared_stopping_launcher(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            linux_source_build, "_project_gate_directories"
        ) as directories, patch.object(linux_source_build, "_gate_commands", return_value=tuple(
            (name, ("/usr/bin/true",)) for name in linux_source_build.GATES
        )), patch.object(linux_source_build.linux_session, "run_host", return_value=types.SimpleNamespace(
            exit_code=0, timed_out=False, stdout=b"", stderr=b""
        )) as session:
            worker = linux_source_build.PROJECT_ROOT / "source"
            self.assertEqual(linux_source_build.run_project_gates({
                "RUNNER_TEMP": temporary, "WORKER_PATH": str(worker),
                "CARGO_HOME": str(worker / ".kd-cargo-home"), "RUST_ROOT": "/rust", "NODE_BIN": "/node",
            }), 0)
            self.assertEqual(directories.call_count, 13)
            self.assertEqual(session.call_count, 13)
            for invocation in session.call_args_list:
                launch = invocation.args[2]
                self.assertEqual(launch[:3], ("/usr/bin/python3", "-B", "-c"))
                self.assertEqual(launch[3], linux_source_build.linux_probes.LAUNCHER_SOURCE)
                self.assertEqual(launch[4:], ("/usr/bin/true",))

    def test_shared_launcher_really_stops_before_the_command_runs(self):
        stdout_reader, stdout_writer = os.pipe()
        stderr_reader, stderr_writer = os.pipe()
        launch = ("/usr/bin/python3", "-B", "-c", linux_source_build.linux_probes.LAUNCHER_SOURCE, "/usr/bin/true")
        spec = {"mode": "open", "keep_root": True, "limits": "probe", "env": {"PATH": "/usr/bin"}, "timeout": 5}
        try:
            code, timed_out = linux_source_build.linux_session.launch_and_collect(
                spec, launch, "/", (None, stdout_writer), (None, stderr_writer), False,
            )
            self.assertEqual(code, 0)
            self.assertFalse(timed_out)
        finally:
            for descriptor in (stdout_reader, stdout_writer, stderr_reader, stderr_writer):
                try:
                    os.close(descriptor)
                except OSError:
                    pass

    def test_audit_command_passes_empty_arguments_to_the_shared_cli(self):
        audit = types.SimpleNamespace(main=Mock(return_value=0))
        canary = types.SimpleNamespace(compute_config=Mock(return_value="config"), PINNED_CONFIG=None)
        with patch.object(linux_source_build, "_audit_modules", return_value=(audit, None, canary)):
            self.assertEqual(linux_source_build.main(["audit"]), 0)
        self.assertEqual(audit.main.call_args.kwargs["arguments"], [])
        self.assertIs(audit.main.call_args.kwargs["environ"], os.environ)

    def test_synthetic_entry_points_use_only_independent_proof_and_job_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            records = Path(temporary) / "kd-records"
            records.mkdir()
            merged = {
                "channels": {name: {"status": "blocked", "before": True, "after": True}
                             for name in linux_source_build.linux_channels.CHANNELS},
                "memory_canary": "absent", "readable_file_canary": "absent",
            }
            (records / "merged.json").write_text(json.dumps(merged), encoding="ascii")
            sha = "a" * 40
            env = {
                "RUNNER_TEMP": temporary, "CI_SHA": sha,
                "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1", "CI_MODE": "synthetic",
                "PRODUCER_RESULT": "success", "VERDICT_RECORD": "forged producer value",
                "CI_EVENT_NAME": "workflow_dispatch", "CI_REPOSITORY": linux_source_build.REPOSITORY,
                "CI_SERVER_URL": "https://github.com", "CACHE_MODE": "none",
                "GITHUB_SHA": sha, "CI_REF": "refs/heads/main", "GITHUB_TOKEN": "read-token",
            }
            with patch.dict(os.environ, env, clear=True), patch.object(
                linux_source_build, "_reference_sha", side_effect=[sha, "b" * 40]
            ) as references, patch.object(linux_source_build, "_comparison", return_value="ahead") as comparison:
                self.assertEqual(linux_source_build.main(["preflight"]), 0)
                self.assertEqual(references.call_count, 2)
                comparison.assert_called_once()
                output = io.StringIO()
                with patch.object(linux_source_build.sys, "stdout", output):
                    self.assertEqual(linux_source_build.main(["verdict"]), 0)
                record = confinement_verdict.decode_line(output.getvalue().strip())
                self.assertTrue(confinement_verdict.confinement_accepted(record))
                self.assertEqual(record["project_execution"], "not_started")
                self.assertEqual(record["token_revocation"], "not-applicable")

    def test_forged_producer_record_cannot_turn_a_failed_source_job_into_acceptance(self):
        with tempfile.TemporaryDirectory() as temporary:
            records = Path(temporary) / "kd-records"
            records.mkdir()
            merged = {
                "channels": {name: {"status": "blocked", "before": True, "after": True}
                             for name in confinement_verdict.CHANNELS},
                "memory_canary": "absent", "readable_file_canary": "absent",
            }
            (records / "merged.json").write_text(json.dumps(merged), encoding="ascii")
            forged = {
                "os": "linux", "boundary": "linux-ns-seccomp-uid", "control_sha": "a" * 40,
                "run_id": 7, "run_attempt": 1, "channels": merged["channels"],
                "memory_canary": "absent", "readable_file_canary": "absent",
                "handoff": "not-applicable", "project_execution": "completed",
                "gates": 13, "failed": 0, "token_revocation": "confirmed",
            }
            self.assertTrue(confinement_verdict.run_accepted(forged))
            env = {
                "RUNNER_TEMP": temporary, "CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7",
                "GITHUB_RUN_ATTEMPT": "1", "CI_MODE": "source", "PRODUCER_RESULT": "failure",
                "VERDICT_RECORD": json.dumps(forged),
            }
            output = io.StringIO()
            with patch.object(linux_source_build.sys, "stdout", output):
                self.assertEqual(linux_source_build.emit_verdict(env), 1)
            record = confinement_verdict.decode_line(output.getvalue().strip())
            self.assertEqual(record["project_execution"], "not_started")
            self.assertEqual(record["gates"], 0)
            self.assertEqual(record["token_revocation"], "unconfirmed")
            env["PRODUCER_RESULT"] = "success"
            self.assertEqual(linux_source_build._verdict_record(env)["project_execution"], "completed")
            env["PRODUCER_RESULT"] = "forged"
            self.assertEqual(linux_source_build._verdict_record(env)["project_execution"], "not_started")

    def test_shared_auditor_rejects_verdict_outside_the_plain_run_step(self):
        expected = linux_source_build._expected_run({
            "CI_SHA": "a" * 40, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1", "CI_MODE": "synthetic",
        }, "b" * 64)
        steps = [{"name": name, "conclusion": "success"} for name in linux_source_build.VERDICT_STEP_NAMES]
        job = {"steps": steps}
        line = confinement_verdict.encode_line({
            "os": "linux", "boundary": "linux-ns-seccomp-uid", "control_sha": "a" * 40,
            "run_id": 7, "run_attempt": 1,
            "channels": {name: {"status": "blocked", "before": True, "after": True}
                         for name in confinement_verdict.CHANNELS},
            "memory_canary": "absent", "readable_file_canary": "absent",
            "handoff": "not-applicable", "project_execution": "not_started",
            "gates": 0, "failed": 0, "token_revocation": "not-applicable",
        }).encode("ascii")
        headers = [bytes((35, 35)) + b"[group]Run verified command\n" for unused in steps]
        good = b"".join(headers) + line + b"\n"
        confinement_public_audit._check_section(good, job, expected)
        bad = b"".join(headers[:-1]) + line + b"\n" + headers[-1]
        with self.assertRaises(confinement_public_audit.AuditRefusal):
            confinement_public_audit._check_section(bad, job, expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
