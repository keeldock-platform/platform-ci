"""The rehearsal and owner request builders produce inputs the real tools accept."""

import ast
import base64
import contextlib
import hashlib
import io
import inspect
import json
import os
import re
import shutil
import shlex
import subprocess
import sys
import tarfile
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock

import bundle
import coordinator
import project
import rehearsal
import supervisor
import test_e2e


CONTROL_SHA = "a" * 40
WAVE = "rehearsal-wave-0001"
BUNDLE = "rehearsal-bundle-0001"


def _private_directory(parent):
    path = Path(parent) / "owner"
    path.mkdir(mode=0o700)
    os.chmod(path, 0o700)
    return path


@unittest.skipUnless(shutil.which("git"), "git is required")
class RehearsalBuilderTests(unittest.TestCase):
    def test_source_is_a_private_throwaway_repository_with_a_valid_projection_request(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = _private_directory(temporary)
            revision = rehearsal.build_source(owner)
            repository = owner / "source-repo"
            head = subprocess.run(["git", "-C", str(repository), "rev-parse", "HEAD"], check=True,
                                  stdout=subprocess.PIPE).stdout.decode().strip()
            self.assertEqual(head, revision)
            request = json.loads((owner / "projection-request.json").read_text(encoding="utf-8"))
            self.assertEqual(request["repository"], str(repository.resolve()))
            self.assertEqual(request["profile"], "core-node")
            projection = project.build_projection(request)
            self.assertEqual(json.loads(projection)["profile"], "core-node")
            with self.assertRaises(rehearsal.Refusal):
                rehearsal.build_source(owner)

    def test_rust_source_projects_its_committed_locks_and_builds_requests_for_the_encrypted_lane(self):
        if bundle.AESGCM is None:
            self.skipTest("cryptography is required")
        with tempfile.TemporaryDirectory() as temporary:
            owner = _private_directory(temporary)
            revision = rehearsal.build_source(owner, "core-rust")
            request = json.loads((owner / "projection-request.json").read_text(encoding="utf-8"))
            self.assertEqual(request["source_revision"], revision)
            self.assertEqual(request["profile"], "core-rust")
            self.assertEqual(request["tools"], {"cargo": "1.99.1", "rustc": "1.99.1"})
            self.assertEqual(request["lockfiles"], ["Cargo.lock", "fuzz/Cargo.lock", "runtime/Cargo.lock"])
            source = Path(request["repository"])
            for relative in request["lockfiles"]:
                self.assertIn(relative, subprocess.run(
                    ["git", "-C", str(source), "ls-files"], check=True,
                    stdout=subprocess.PIPE).stdout.decode("utf-8").splitlines())
            self.assertIn("crates/support", (source / "Cargo.toml").read_text(encoding="ascii"))
            root_source = (source / "src/lib.rs").read_text(encoding="ascii")
            self.assertIn("SYNTHETIC_SOURCE_CANARY_7f8c", root_source)
            self.assertIn("KEYCANARY-73A10X", root_source)
            projection_path = owner / "projection.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(project.main(["--request", str(owner / "projection-request.json"),
                                               "--output", str(projection_path)]), 0)
            projection = bundle.strict_json(projection_path.read_bytes())
            self.assertEqual(projection["profile"], "core-rust")
            self.assertEqual({item["name"] for item in projection["cargo"]}, {"fastrand", "itoa"})
            expires = rehearsal.build_requests(owner, CONTROL_SHA, "1234", WAVE, BUNDLE, "77", 3000)
            reserve = json.loads((owner / "reserve.json").read_text(encoding="utf-8"))
            bundle_request = json.loads((owner / "bundle-request.json").read_text(encoding="utf-8"))
            self.assertEqual(reserve["profile"], "core-rust")
            self.assertEqual(reserve["expires"], expires)
            self.assertEqual(bundle_request["profile"], "core-rust")
            self.assertEqual(bundle_request["allowed_files"], {})
            self.assertEqual(bundle_request["allowed_tests"], rehearsal.rust_rehearsal_fixture.TESTS)
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(bundle.main(["create", "--request", str(owner / "bundle-request.json"),
                                              "--ciphertext", str(owner / "bundle.enc"),
                                              "--key-file", str(owner / "key.hex")]), 0)
            key = bundle.read_key_file(owner / "key.hex")
            bindings = {
                "format": "kd-public-devlane-aesgcm-v1", "repository_id": "1430960557",
                "control_sha": CONTROL_SHA, "workflow_path": ".github/workflows/devlane-encrypted.yml",
                "profile": "core-rust", "wave_id": WAVE, "bundle_id": BUNDLE,
                "fetch_sha256": bundle_request_digest(owner), "expires": expires,
            }
            archive = bundle.parse_envelope((owner / "bundle.enc").read_bytes(), key, bindings)
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as opened:
                names = set(opened.getnames())
            self.assertTrue(set(request["lockfiles"]).issubset(names))
            self.assertIn("runtime/crates/services/listener/src/lib.rs", names)

    def test_directory_must_be_owner_only_and_outside_every_checkout(self):
        with tempfile.TemporaryDirectory() as temporary:
            open_directory = Path(temporary) / "open"
            open_directory.mkdir(mode=0o755)
            os.chmod(open_directory, 0o755)
            with self.assertRaisesRegex(rehearsal.Refusal, "directory-permissions"):
                rehearsal.build_source(open_directory)
            outer = Path(temporary) / "checkout"
            outer.mkdir()
            subprocess.run(["git", "-C", str(outer), "init", "--quiet"], check=True)
            inner = outer / "owner"
            inner.mkdir(mode=0o700)
            with self.assertRaisesRegex(rehearsal.Refusal, "directory-inside-checkout"):
                rehearsal.build_source(inner)
            with self.assertRaisesRegex(rehearsal.Refusal, "directory-unavailable"):
                rehearsal.build_source(Path(temporary) / "missing")

    def test_requests_feed_the_real_bundle_producer_and_the_coordinator_ledger(self):
        if bundle.AESGCM is None:
            self.skipTest("cryptography is required")
        with tempfile.TemporaryDirectory() as temporary:
            owner = _private_directory(temporary)
            rehearsal.build_source(owner)
            self.assertEqual(project.main(["--request", str(owner / "projection-request.json"),
                                           "--output", str(owner / "projection.json")]), 0)
            with self.assertRaisesRegex(rehearsal.Refusal, "request-input"):
                rehearsal.build_requests(owner, "b" * 39, "1234", WAVE, BUNDLE, "77", 3000)
            expires = rehearsal.build_requests(owner, CONTROL_SHA, "1234", WAVE, BUNDLE, "77", 3000)
            reserve = json.loads((owner / "reserve.json").read_text(encoding="utf-8"))
            self.assertEqual(reserve["expires"], expires)
            self.assertEqual(
                set(reserve), {"schema", "wave_id", "bundle_id", "control_run_id", "control_sha", "profile",
                               "expires", "release_id"})
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(bundle.main(["create", "--request", str(owner / "bundle-request.json"),
                                              "--ciphertext", str(owner / "bundle.enc"),
                                              "--key-file", str(owner / "key.hex")]), 0)
            key = bundle.read_key_file(owner / "key.hex")
            bindings = {
                "format": "kd-public-devlane-aesgcm-v1", "repository_id": "1430960557",
                "control_sha": CONTROL_SHA, "workflow_path": ".github/workflows/devlane-encrypted.yml",
                "profile": "core-node", "wave_id": WAVE, "bundle_id": BUNDLE,
                "fetch_sha256": bundle_request_digest(owner), "expires": expires,
            }
            archive = bundle.parse_envelope((owner / "bundle.enc").read_bytes(), key, bindings)
            with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as opened:
                names = set(opened.getnames())
            self.assertIn(".devlane/manifest.json", names)
            self.assertIn("packages/kernel-ui-kit/src/example.ts", names)
            self.assertNotIn(".git", " ".join(names))

            rehearsal.build_staged(owner)
            staged = json.loads((owner / "staged-assets.json").read_text(encoding="utf-8"))
            self.assertEqual(staged["bundle_size"], (owner / "bundle.enc").stat().st_size)
            rehearsal.build_intent(owner, WAVE, "111", "222", "d" * 64)
            intent = json.loads((owner / "intent.json").read_text(encoding="utf-8"))
            self.assertEqual(intent["schema"], 2)

            ledger = Path(temporary) / "ledger"
            with mock.patch.object(coordinator, "_control_record"), \
                    mock.patch.object(coordinator, "_verify_secret_absent"), \
                    mock.patch.object(coordinator, "_release_assets", return_value=[]), \
                    mock.patch.object(coordinator, "_cache_records", return_value=[]), \
                    mock.patch.object(coordinator, "cache_inventory_digest", return_value="d" * 64), \
                    mock.patch.object(coordinator, "_verify_asset"), \
                    contextlib.redirect_stdout(io.StringIO()):
                coordinator.reserve_wave(ledger, reserve)
                coordinator.stage_bundle(ledger, WAVE, staged)
                coordinator.record_intent(ledger, intent)
            self.assertEqual(coordinator._read(ledger / (WAVE + ".json"))["state"], "assets-attached")

    def test_intent_and_request_inputs_are_validated(self):
        with tempfile.TemporaryDirectory() as temporary:
            owner = _private_directory(temporary)
            for arguments in (("bad", "1", "2", "d" * 64), (WAVE, "0", "2", "d" * 64), (WAVE, "1", "x", "d" * 64),
                              (WAVE, "1", "2", "d" * 63)):
                with self.subTest(arguments=arguments), self.assertRaises(rehearsal.Refusal):
                    rehearsal.build_intent(owner, *arguments)
            self.assertFalse((owner / "intent.json").exists())
            with self.assertRaisesRegex(rehearsal.Refusal, "staged-input-missing"):
                rehearsal.build_staged(owner)


class ProcedureDocumentTests(unittest.TestCase):
    """The committed procedure only names commands, subcommands and flags the tools really have."""

    root = Path(__file__).resolve().parents[2]
    text = (root / "docs/devlane-procedure.md").read_text(encoding="utf-8")

    @staticmethod
    def _integrated_contract_errors(text):
        errors = []
        try:
            dispatch_start = text.index("8. Install the key, dispatch once, reconcile and arm timed revocation")
            dispatch_end = text.index("\n9. After the coordinator returns successfully", dispatch_start)
            dispatch = text[dispatch_start:dispatch_end]
        except ValueError:
            dispatch = ""
            errors.append("integrated dispatch section")
        try:
            recovery_start = text.index("12. Before reserving any later wave")
            recovery_end = text.index("\n**Rehearsal wave", recovery_start)
            recovery = text[recovery_start:recovery_end]
        except ValueError:
            recovery = ""
            errors.append("pending-secret recovery section")

        required_dispatch = (
            ("kit/devlane/coordinator.py dispatch-wave", "single dispatch operation"),
            ("--key-file \"$DEVLANE_PRIVATE/key.hex\"", "key-file binding"),
            ("300-second reconciliation deadline", "timed reconciliation deadline"),
            ("watcher follows only the ledger-bound run", "ledger-bound watcher"),
            ("revokes when the decrypt step concludes or the run ends", "decrypt/run revocation"),
            ("revokes at the deadline if no run becomes visible", "deadline revocation"),
            ("Failed or ambiguous dispatch responses still reconcile; no second dispatch is issued", "no redispatch"),
        )
        errors.extend(label for phrase, label in required_dispatch if phrase not in dispatch)
        if "DEVLANE_DECRYPT_KEY" not in text or "environment" not in text:
            errors.append("environment secret binding")
        if "recover-pending-secrets" not in recovery:
            errors.append("pending-secret recovery command")
        if "blocks `reserve-wave` until recovery completes" not in recovery:
            errors.append("reservation blocked until recovery")
        return errors

    def test_every_documented_tool_invocation_exists_with_its_flags(self):
        import re
        pattern = re.compile(r"python3 -B kit/devlane/([a-z_]+)\.py((?: [a-z-]+)?)((?: --[a-z0-9-]+(?: \S+)?)*)")
        seen = set()
        for script, operation, rest in pattern.findall(self.text):
            operation = operation.strip()
            flags = re.findall(r"--[a-z0-9-]+", rest)
            if operation.startswith("--"):
                flags.insert(0, operation)
                operation = ""
            command = [sys.executable, "-B", str(self.root / "kit/devlane" / (script + ".py"))]
            if operation:
                command.append(operation)
            result = subprocess.run(command + ["--help"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, timeout=60, check=False)
            self.assertEqual(result.returncode, 0, (script, operation))
            help_text = result.stdout.decode("utf-8", "replace")
            for flag in flags:
                self.assertIn(flag, help_text, (script, operation, flag))
            seen.add((script, operation))
        for expected in (("coordinator", "dispatch-wave"), ("coordinator", "recover-pending-secrets"),
                         ("coordinator", "reserve-wave"), ("coordinator", "record-control-evidence"),
                         ("coordinator", "cleanup-terminal"), ("rehearsal", "source"),
                         ("rehearsal", "requests"), ("project", ""), ("bundle", "create")):
            self.assertIn(expected, seen)
        for retired in (("coordinator", "await-decrypt-and-revoke"), ("coordinator", "mark-secret-installing"),
                        ("coordinator", "mark-secret-installed"), ("coordinator", "reconcile-dispatch")):
            self.assertNotIn(retired, seen)

    def test_rust_rehearsal_procedure_and_workflow_cover_the_same_profile_path(self):
        for phrase in (
            "rehearsal.py source --directory \"$DEVLANE_PRIVATE\" --profile core-rust",
            "three committed `Cargo.lock` files", "`itoa` and `fastrand`",
            "all 22 non-SemVer suites pass", "DEVLANE_SEMVER_EXECUTION",
            "production schema-2 Rust preparation and SemVer execution path",
        ):
            self.assertIn(phrase, self.text)
        workflow = (self.root / ".github/workflows/devlane-encrypted.yml").read_text(encoding="utf-8")
        self.assertIn("- core-rust", workflow)
        self.assertIn("if: ${{ inputs.profile == 'core-rust' }}", workflow)
        self.assertIn('--profile "$DEVLANE_PROFILE"', workflow)
        self.assertEqual(rehearsal.build_source.__defaults__, ("core-node",))

    def test_the_procedure_states_the_integrated_dispatch_and_recovery_contract(self):
        for phrase in ("Install the key, dispatch once, reconcile and arm timed revocation as one coordinator operation",
                       "DEVLANE_DECRYPT_KEY", "devlane-decrypt", "dispatch-wave", "300-second reconciliation deadline",
                       "watcher follows only the ledger-bound run", "revokes at the deadline if no run becomes visible",
                       "Failed or ambiguous dispatch responses still reconcile; no second dispatch is issued",
                       "Before reserving any later wave, explicitly recover durable secret obligations",
                       "recover-pending-secrets", "Rehearsal wave (required before the first private wave)",
                       "within_limit=true", "Duplicate refusal", "terminal_cleanup=complete",
                       "audit disposition `accepted`", "Claim this bundle for one run before decryption",
                       "record-control-evidence", "Dependency disclosure", "Records side channel", "Report integrity"):
            self.assertIn(phrase, self.text)
        self.assertNotIn("DEVLANE_DECRYPT_KEY=", self.text)
        self.assertNotIn("--body", self.text)
        self.assertNotIn("gh secret set", self.text)
        self.assertEqual(self._integrated_contract_errors(self.text), [])

    def test_contract_rejects_removed_dispatch_key_revocation_and_recovery_obligations(self):
        dispatch_start = self.text.index("8. Install the key, dispatch once, reconcile and arm timed revocation")
        dispatch_end = self.text.index("\n9. After the coordinator returns successfully", dispatch_start)
        dispatch = self.text[dispatch_start:dispatch_end]
        recovery_start = self.text.index("12. Before reserving any later wave")
        recovery_end = self.text.index("\n**Rehearsal wave", recovery_start)
        recovery = self.text[recovery_start:recovery_end]

        self.assertIn("--key-file \"$DEVLANE_PRIVATE/key.hex\"", dispatch)
        self.assertIn("DEVLANE_DECRYPT_KEY", self.text)
        self.assertIn("300-second reconciliation deadline", dispatch)
        self.assertIn("watcher follows only the ledger-bound run", dispatch)
        self.assertIn("recover-pending-secrets", recovery)
        self.assertIn("blocks `reserve-wave` until recovery completes", recovery)

        mutations = []
        for changed_dispatch, label, expected_error in (
            (dispatch.replace("kit/devlane/coordinator.py dispatch-wave", "kit/devlane/coordinator.py manual-dispatch", 1),
             "dispatch operation", "single dispatch operation"),
            (dispatch.replace('--key-file "$DEVLANE_PRIVATE/key.hex"', "", 1), "key-file binding", "key-file binding"),
            (dispatch.replace("300-second reconciliation deadline", "bounded reconciliation", 1), "timed revocation",
             "timed reconciliation deadline"),
            (dispatch.replace("watcher follows only the ledger-bound run", "watcher follows the run", 1), "run binding",
             "ledger-bound watcher"),
        ):
            mutations.append((self.text[:dispatch_start] + changed_dispatch + self.text[dispatch_end:], label, expected_error))
        mutations.append((self.text.replace("DEVLANE_DECRYPT_KEY", "UNBOUND_DECRYPT_KEY"), "environment secret",
                          "environment secret binding"))
        changed_recovery = recovery.replace("recover-pending-secrets", "recover-secrets", 1).replace(
            "blocks `reserve-wave` until recovery completes", "permits reservation", 1)
        mutations.append((self.text[:recovery_start] + changed_recovery + self.text[recovery_end:],
                          "recovery command and gate", "pending-secret recovery command"))
        for changed, label, expected_error in mutations:
            with self.subTest(missing=label):
                self.assertIn(expected_error, self._integrated_contract_errors(changed))

    def test_the_synthetic_workflow_names_match_the_coordinator_environment(self):
        encrypted = (self.root / ".github/workflows/devlane-encrypted.yml").read_text(encoding="utf-8")
        synthetic = (self.root / ".github/workflows/devlane-synthetic.yml").read_text(encoding="utf-8")
        self.assertIn("environment: " + coordinator.DECRYPT_ENVIRONMENT, encrypted)
        self.assertIn(coordinator.SECRET_NAME, encrypted)
        self.assertIn(coordinator.DECRYPT_STEP, encrypted)
        rust_version = json.loads((self.root / "ci/devlane-profiles.json").read_text(encoding="utf-8"))[
            "profiles"]["core-rust"]["rust_matrix"]["toolchain"]
        self.assertEqual(rehearsal.fixtures.RUST_VERSION, rust_version)
        self.assertIn("rustup toolchain install " + rust_version + " --profile minimal", synthetic)
        encrypted_steps = coordinator.public_audit.parse_workflow(
            self.root / ".github/workflows/devlane-encrypted.yml",
        )[coordinator.RUN_JOB_NAME]["steps"]
        synthetic_steps = coordinator.public_audit.parse_workflow(
            self.root / ".github/workflows/devlane-synthetic.yml",
        )["devlane-synthetic"]["steps"]
        encrypted_names = [step["name"] for step in encrypted_steps]
        synthetic_names = [step["name"] for step in synthetic_steps]
        self.assertLess(encrypted_names.index("Prepare hosted Linux isolation state"),
                        encrypted_names.index(coordinator.DECRYPT_STEP))
        self.assertLess(synthetic_names.index("Prepare hosted Linux isolation state"),
                        synthetic_names.index("Run full source-free production-path acceptance"))


class ProductionExecuteFixtureTests(unittest.TestCase):
    root = Path(__file__).resolve().parents[2]
    profiles = bundle.strict_json((root / "ci/devlane-profiles.json").read_bytes())

    def _assert_node_profile_targets(self, files):
        profile = self.profiles["profiles"]["core-node"]
        for command in profile["commands"]:
            self.assertEqual(command[0:2], ["npm", "--prefix"])
            package_directory = Path(command[2]).relative_to("/workspace/source")
            package_path = (package_directory / "package.json").as_posix()
            self.assertIn(package_path, files)
            package = bundle.strict_json(files[package_path])
            scripts = package.get("scripts", {})
            script = "test" if command[3] == "test" else command[4]
            self.assertIn(script, scripts, (package_path, command))
            if command[3] == "test" and scripts[script].startswith("node "):
                runner = (package_directory / scripts[script].split()[1]).as_posix()
                self.assertIn(runner, files)
        self.assertIn("packages/kernel-ui-kit/src/example.ts", files)

    def test_node_execute_fixtures_match_every_profile_package_and_allowed_source_path(self):
        synthetic_lock = test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
        real_lock = test_e2e._node_lock_from_reviewed(
            {"typescript": "6.0.3", "vite": "8.3.5", "vitest": "5.0.5"},
        )
        browser_lock = {"packages": {"": {"devDependencies": {"@playwright/test": "1.54.2"}}}}
        fixtures = (
            test_e2e._node_source(synthetic_lock),
            test_e2e._real_node_source(real_lock),
            test_e2e._browser_source(browser_lock),
        )
        for files in fixtures:
            with self.subTest(files=sorted(files)):
                self._assert_node_profile_targets(files)
                self.assertTrue({"packages/kernel-ui-kit/src/example.ts"}.issubset(files))

        browser = fixtures[-1]
        browser_command = self.profiles["profiles"]["core-node"]["browser_command"]
        config_argument = next(item for item in browser_command if item.startswith("--config="))
        self.assertEqual(browser_command[3:], [
            "--config=/workspace/source/packages/kernel-ui-kit/browser/playwright.config.ts",
            "--reporter=json", "--output=/scratch/playwright-results/run", "--trace=off",
        ])
        config_path = Path(config_argument.partition("=")[2]).relative_to("/workspace/source").as_posix()
        self.assertIn(config_path, browser)
        browser_config = browser[config_path].decode("ascii")
        self.assertIn("screenshot: 'off'", browser_config)
        self.assertIn("video: 'off'", browser_config)
        self.assertIn("trace: 'off'", browser_config)
        self.assertIn("chromiumSandbox: false", browser_config)
        self.assertIn(
            "args: ['--no-sandbox', '--no-zygote', '--enable-logging=stderr', '--v=1', "
            "'--disable-gpu', '--disable-dev-shm-usage', '--disable-features=AudioServiceOutOfProcess']",
            browser_config,
        )
        self.assertIn("packages/kernel-ui-kit/browser/frame.spec.mjs", browser)
        self.assertNotIn("packages/kernel-ui-kit/browser/frame.spec.ts", browser)

        node_probe = test_e2e._probe_script()
        self.assertIn("/proc/1/root/ho' + 'me/runner", node_probe)
        self.assertIn("if (process.platform === 'linux')", node_probe)
        self.assertNotIn("/proc/1/root/home", node_probe)

        scenarios = test_e2e.scenarios()
        for scenario in scenarios:
            source = scenario["files"]()
            self.assertTrue(set(scenario["allowed_files"]).issubset(source))

    def test_rust_execute_fixture_matches_the_fixed_matrix_paths_and_supervised_runner(self):
        matrix = test_e2e.rust_matrix_runner.EXPECTED_MATRIX
        self.assertEqual(self.profiles["profiles"]["core-rust"]["rust_matrix"], matrix)
        fixture_root = self.root / "kit/devlane/fixtures/core-rust-rehearsal"
        for row in [*matrix["workspaces"], matrix["listener"]]:
            manifest = Path(row["manifest"]).relative_to("/workspace/source")
            lockfile = Path(row["lock"]).relative_to("/workspace/source")
            self.assertTrue((fixture_root / manifest).is_file(), str(manifest))
            self.assertTrue((fixture_root / lockfile).is_file(), str(lockfile))
        rust_source = (fixture_root / "src/lib.rs").read_text(encoding="ascii")
        self.assertIn('"/proc/1/root/ho".to_owned() + "me/runner"', rust_source)
        self.assertNotIn("/proc/1/root/home", rust_source)

        execute = test_e2e.supervisor.Service._execute.__code__.co_consts
        self.assertIn("/control/devlane/rust_matrix_runner.py", execute)
        self.assertIn("/scratch/reports/rust-matrix.jsonl", execute)


def bundle_request_digest(owner):
    return json.loads((owner / "bundle-request.json").read_text(encoding="utf-8"))["fetch_sha256"]


class ProductionFailureDiagnosticsTests(unittest.TestCase):
    def test_execute_status_contract_distinguishes_expected_node_and_rust_failures(self):
        self.assertEqual(test_e2e._expected_execute_status(
            {"name": "synthetic-node"}, "accept"), 0)
        self.assertEqual(test_e2e._expected_execute_status(
            {"name": "synthetic-node"}, "failing-test"), 1)
        self.assertEqual(test_e2e._expected_execute_status(
            {"name": "real-node"}, "accept-with-failure"), 1)
        self.assertEqual(test_e2e._expected_execute_status(
            {"name": "synthetic-rust-v1-refusal", "expect_semver_execution_refusal": True},
            "accept"), 1)
        with self.assertRaisesRegex(RuntimeError, "execute-expectation-profile-mismatch"):
            test_e2e._expected_execute_status(
                {"name": "synthetic-rust-v1-refusal"}, "accept")

    def test_execute_command_failure_prints_only_bounded_public_diagnostics(self):
        result = subprocess.CompletedProcess(
            ["supervisor.py", "execute"], 2,
            b"ignored command output\n", b"devlane_supervisor_refusal=execution-order\nprivate detail\n",
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            test_e2e._report_command_failure("supervisor-client:execute", result)
        lines = output.getvalue().splitlines()
        self.assertEqual(lines, [
            "devlane_e2e_command=failed call=supervisor-client:execute returncode=2",
            "devlane_supervisor_refusal=execution-order",
        ])
        self.assertTrue(all(test_e2e.diagnostic_contract.public_e2e_command_diagnostic(line)
                            for line in lines))

        summary = (
            b'{"code":"DEVLANE_FAILURE","kind":"control","stage":"unit",'
            b'"status":"fail","subreason":"vitest-failed"}\n'
            b'{"kind":"test","stage":"unit","test":"case_0002"}\n'
            b'private detail\n'
        )
        result = subprocess.CompletedProcess(
            ["supervisor.py", "execute"], 1, summary,
            b"devlane_supervisor_refusal=execution-order\n",
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            test_e2e._report_command_failure("supervisor-client:execute", result)
        lines = output.getvalue().splitlines()
        self.assertEqual(lines, [
            "devlane_e2e_command=failed call=supervisor-client:execute returncode=1",
            '{"code":"DEVLANE_FAILURE","kind":"control","stage":"unit","status":"fail","subreason":"vitest-failed"}',
            '{"kind":"test","stage":"unit","test":"case_0002"}',
            "devlane_supervisor_refusal=execution-order",
        ])
        self.assertTrue(all(test_e2e.diagnostic_contract.public_e2e_command_diagnostic(line)
                            for line in lines))

        bounded_lines = b"".join(
            ('{"kind":"test","stage":"unit","test":"case_%04d"}\n' % index).encode("ascii")
            for index in range(1, 7)
        )
        bounded = subprocess.CompletedProcess(["supervisor.py", "execute"], 1, bounded_lines, b"")
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            test_e2e._report_command_failure("supervisor-client:execute", bounded)
        self.assertEqual(len(output.getvalue().splitlines()),
                         1 + test_e2e.diagnostic_contract.MAX_E2E_COMMAND_DIAGNOSTIC_LINES)

        canary = subprocess.CompletedProcess(
            ["supervisor.py", "execute"], 1,
            b"SYNTHETIC_SOURCE_CANARY_7f8c\n", b"devlane_supervisor_refusal=execution-order\n",
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            test_e2e._report_command_failure("supervisor-client:execute", canary)
        self.assertEqual(output.getvalue().splitlines(), [
            "devlane_e2e_command=failed call=supervisor-client:execute returncode=1",
            "devlane_supervisor_refusal=execution-order",
        ])

        oversized = subprocess.CompletedProcess(
            ["supervisor.py", "execute"], 1,
            b"x" * (test_e2e.diagnostic_contract.MAX_E2E_COMMAND_OUTPUT_BYTES + 1), b"",
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            test_e2e._report_command_failure("supervisor-client:execute", oversized)
        self.assertEqual(output.getvalue(),
                         "devlane_e2e_command=failed call=supervisor-client:execute returncode=1\n")

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            test_e2e._report_command_failure("private:callsite", result)
        self.assertEqual(output.getvalue(), "")

    def test_unit_failure_raw_diagnostics_are_bounded_scanned_and_neutralized(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "devlane-vitest-local-synthetic-node-accept.json"
            raw = root / "workspace/raw"
            reports = root / "scratch/reports"
            raw.mkdir(parents=True)
            reports.mkdir(parents=True)
            rows = ["unit line %03d" % index for index in range(150)]
            rows[40] = "::error::safe diagnostic"
            rows[41] = chr(35) * 2 + "[group]safe diagnostic"
            rows[-1] = "SYNTHETIC_SOURCE_CANARY_7f8c must be skipped"
            (raw / "unit.log").write_text("\n".join(rows) + "\n", encoding="utf-8")
            (raw / "adapter-run.log").write_text(
                "adapter started\nKEYCANARY-73A10X must be skipped\nadapter finished\n", encoding="ascii",
            )
            (reports / "vitest.json").write_text("{}", encoding="ascii")
            (reports / "adapter.jsonl").write_text("", encoding="ascii")
            summary = (b'{"code":"DEVLANE_FAILURE","kind":"control","stage":"unit",'
                       b'"status":"fail","subreason":"vitest-failed"}\n')
            service = object.__new__(supervisor.Service)
            service.root = root
            service.failure_diagnostics_file = destination
            service.owner_uid = os.getuid()
            service.context = {"wave_class": supervisor.fetch.SOURCE_FREE_WAVE_CLASS, "profile": "core-node"}
            service.summary = summary
            self.assertTrue(service._capture_failure_diagnostics())
            metadata = destination.stat()
            self.assertEqual(metadata.st_uid, os.getuid())
            self.assertEqual(metadata.st_mode & 0o777, 0o600)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                test_e2e._emit_synthetic_failure_diagnostics(destination, summary)
            lines = output.getvalue().splitlines()

        self.assertLessEqual(len(lines), test_e2e.diagnostic_contract.MAX_E2E_VITEST_DIAGNOSTIC_LINES)
        self.assertTrue(all(test_e2e.diagnostic_contract.public_e2e_vitest_diagnostic(line) for line in lines))
        self.assertTrue(any("name=unit.log line=1 text=unit line 030" in line for line in lines))
        self.assertFalse(any("name=unit.log line=120 text=unit line 149" in line for line in lines))
        self.assertTrue(any("adapter finished" in line for line in lines))
        self.assertTrue(any("name=reports kind=directory bytes=0" in line for line in lines))
        self.assertTrue(any("name=vitest.json kind=file bytes=2" in line for line in lines))
        rendered = "\n".join(lines)
        for marker in ("SYNTHETIC_SOURCE_CANARY", "KEYCANARY-73A10X", "::error::", chr(35) * 2 + "[group]"):
            self.assertNotIn(marker, rendered)
        self.assertFalse(destination.exists())

    def test_node_failure_diagnostics_keep_their_original_log_count_bound(self):
        summary = (b'{"code":"DEVLANE_FAILURE","kind":"control","stage":"unit",'
                   b'"status":"fail","subreason":"vitest-failed"}\n')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "workspace/raw"
            raw.mkdir(parents=True)
            (root / "scratch/reports").mkdir(parents=True)
            for index in range(20):
                (raw / ("unit-%02d.log" % index)).write_text("source-free log\n", encoding="ascii")
            destination = root / "devlane-vitest-local-synthetic-node-accept.json"
            service = object.__new__(supervisor.Service)
            service.root = root
            service.failure_diagnostics_file = destination
            service.owner_uid = os.getuid()
            service.context = {
                "wave_class": supervisor.fetch.SOURCE_FREE_WAVE_CLASS,
                "profile": "core-node",
            }
            service.summary = summary
            self.assertTrue(service._capture_failure_diagnostics())
            document = bundle.strict_json(destination.read_bytes())
            self.assertEqual(len(document["logs"]), supervisor.MAX_SYNTHETIC_NODE_DIAGNOSTIC_LOGS)

    def test_browser_failure_diagnostics_prioritize_bounded_canary_scanned_stderr(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "workspace/raw"
            raw.mkdir(parents=True)
            (root / "scratch/reports").mkdir(parents=True)
            rows = ["browser diagnostic line %03d" % index for index in range(140)]
            long_error = "ERROR:content/browser/zygote_host detail=" + ("x" * 500)
            rows[120] = long_error
            long_report_error = "pw:browser chromium stderr=" + ("y" * 500)
            rows[-2] = ("x" * 400) + "PRIVATE_SOURCE_CANARY must be skipped"
            (raw / "browser.stderr.log").write_text("\n".join(rows) + "\n", encoding="ascii")
            (raw / "browser.log").write_text(long_report_error + "\n", encoding="ascii")
            destination = root / "devlane-vitest-local-synthetic-browser-accept.json"
            service = object.__new__(supervisor.Service)
            service.root = root
            service.failure_diagnostics_file = destination
            service.owner_uid = os.getuid()
            service.context = {
                "wave_class": supervisor.fetch.SOURCE_FREE_WAVE_CLASS,
                "profile": "core-node",
            }
            service.summary = b""
            self.assertTrue(service._capture_failure_diagnostics(execution_failed=True))
            document = bundle.strict_json(destination.read_bytes())
            self.assertEqual(document["subreason"], "execute-failed")
            self.assertEqual(document["logs"][0]["name"], "browser.stderr.log")
            self.assertEqual(document["logs"][1]["name"], "browser.log")
            raw_tail = [base64.b64decode(line) for line in document["logs"][0]["lines"]]
            self.assertLessEqual(len(raw_tail), supervisor.MAX_SYNTHETIC_DIAGNOSTIC_TAIL_LINES)
            self.assertTrue(all(
                len(line) <= supervisor.MAX_SYNTHETIC_BROWSER_DIAGNOSTIC_LINE_BYTES for line in raw_tail
            ))
            self.assertIn(long_error.encode("ascii"), raw_tail)
            browser_log_tail = [base64.b64decode(line) for line in document["logs"][1]["lines"]]
            self.assertIn(long_report_error.encode("ascii"), browser_log_tail)
            self.assertFalse(any(b"PRIVATE_SOURCE_CANARY" in line for line in raw_tail))
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                test_e2e._emit_synthetic_failure_diagnostics(
                    destination, b"", execution_failed=True,
                )
            rendered = output.getvalue()
            self.assertIn("name=browser.stderr.log", rendered)
            self.assertIn("browser diagnostic line 139", rendered)
            self.assertIn(long_error, rendered)
            self.assertIn(long_report_error, rendered)
            self.assertNotIn("PRIVATE_SOURCE_CANARY", rendered)
            self.assertTrue(all(test_e2e.diagnostic_contract.public_e2e_failure_diagnostic(line)
                                for line in rendered.splitlines()))

    def test_supervisor_devices_keep_worker_writable_modes_under_private_umask(self):
        with tempfile.TemporaryDirectory() as temporary:
            dev = Path(temporary) / "dev"
            dev.mkdir()
            old_umask = os.umask(0o077)
            try:
                def mock_mknod(path, _mode, _device):
                    Path(path).touch()

                with mock.patch.object(supervisor.os, "mknod", side_effect=mock_mknod):
                    supervisor._make_worker_devices(dev)
            finally:
                os.umask(old_umask)

            self.assertEqual((dev / "null").stat().st_mode & 0o777, 0o666)
            self.assertEqual((dev / "zero").stat().st_mode & 0o777, 0o666)
            self.assertEqual((dev / "random").stat().st_mode & 0o777, 0o444)
            self.assertEqual((dev / "urandom").stat().st_mode & 0o777, 0o444)

    def test_synthetic_write_report_matches_the_pinned_worker_runtime_and_scratch_layout(self):
        lock = test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
        files = test_e2e._node_source(lock)
        root_package = bundle.strict_json(files["package.json"])
        ui_package = bundle.strict_json(files["packages/kernel-ui-kit/package.json"])
        script = files["packages/kernel-ui-kit/tests/write-report.mjs"].decode("ascii")
        profile = bundle.strict_json((test_e2e.ROOT / "ci/devlane-profiles.json").read_bytes())["profiles"]["core-node"]
        unit_command = profile["commands"][1]
        environment = supervisor._worker_environment("unit", Path("/unused"), {"node_dir": "/tools/node/bin"})

        self.assertEqual(root_package["type"], "module")
        self.assertEqual(ui_package["type"], "module")
        self.assertEqual(ui_package["scripts"]["test"], "node tests/write-report.mjs")
        self.assertEqual(unit_command[0:4], ["npm", "--prefix", "/workspace/source/packages/kernel-ui-kit", "test"])
        self.assertIn("--outputFile=/scratch/reports/vitest.json", unit_command)
        self.assertIn("import fs from 'node:fs'", script)
        self.assertIn("import { spawn } from 'node:child_process'", script)
        self.assertIn("fs.writeFileSync(output", script)
        self.assertIn("/scratch/reports/vitest.json", script)
        self.assertEqual(environment["PATH"], "/tools/node/bin:/usr/bin:/bin")
        self.assertNotIn("RUNNER_TEMP", environment)
        self.assertNotIn("GITHUB_RUN_ID", environment)
        self.assertEqual(supervisor.node_tool_prepare.NODE_VERSION, "24.22.1")
        self.assertEqual(supervisor.node_tool_prepare.NPM_VERSION, "11.19.1")
        scratch_source = inspect.getsource(supervisor._prepare_writable_scratch)
        self.assertIn('"scratch/reports"', scratch_source)
        self.assertIn("os.chown(str(path), WORKER_UID, WORKER_GID)", scratch_source)

    def test_run_temp_supervisor_dump_survives_the_workflow_quiet_capture(self):
        summary = (b'{"code":"DEVLANE_FAILURE","kind":"control","stage":"typecheck",'
                   b'"status":"fail"}\n')
        with tempfile.TemporaryDirectory() as temporary:
            runner_temp = Path(temporary)
            root = runner_temp / "namespace-root"
            raw = root / "workspace/raw"
            reports = root / "scratch/reports"
            scratch_raw = root / "scratch/raw"
            raw.mkdir(parents=True)
            reports.mkdir(parents=True)
            scratch_raw.mkdir(parents=True)
            for name in ("typecheck.log", "unit.log", "style.log", "audit.log", "install.log",
                         "typecheck-adapter.log", "adapter-run.log"):
                (raw / name).write_text(name + " started\n", encoding="ascii")
            (raw / "typecheck-adapter.log").write_text(
                "typescript_reporter_refusal=typescript-unavailable\n"
                "PRIVATE_KEY_CANARY must be skipped\n", encoding="ascii",
            )
            (raw / "typecheck.stderr.log").write_text(
                "Error: spawn /tools/node/bin/node EACCES\n", encoding="ascii",
            )
            (scratch_raw / "unit.stdout").write_text("worker refusal code=tool-missing\n", encoding="ascii")
            (reports / "vitest.json").write_text("{}", encoding="ascii")
            destination = runner_temp / "devlane-vitest-local-synthetic-node-accept.json"
            service = object.__new__(supervisor.Service)
            service.root = root
            service.failure_diagnostics_file = destination
            service.owner_uid = os.getuid()
            service.context = {
                "wave_class": supervisor.fetch.SOURCE_FREE_WAVE_CLASS,
                "profile": "core-node",
            }
            service.summary = summary
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                self.assertTrue(service._capture_failure_diagnostics(execution_failed=True))
            stored = bundle.strict_json(destination.read_bytes())
            self.assertEqual(stored["subreason"], "execute-failed")
            self.assertTrue({"typecheck.log", "unit.log", "style.log", "audit.log", "install.log",
                             "typecheck-adapter.log", "adapter-run.log", "unit.stdout"}
                            <= {item["name"] for item in stored["logs"]})
            self.assertFalse(any(b"PRIVATE_KEY_CANARY" in base64.b64decode(line)
                                 for item in stored["logs"] for line in item["lines"]))

            metadata = destination.stat()
            self.assertEqual(metadata.st_uid, os.getuid())
            self.assertEqual(metadata.st_mode & 0o777, 0o600)
            driver = runner_temp / "harness-failure.py"
            command_source = (
                "import sys; sys.stdout.buffer.write(" + repr(summary) + "); "
                "sys.stderr.write('devlane_supervisor_refusal=execution-order\\n'); sys.exit(1)"
            )
            driver.write_text(
                "import sys\n"
                "import test_e2e\n"
                "command = [sys.executable, '-c', " + repr(command_source) + "]\n"
                "test_e2e._run(command, expected=0, diagnostic_callsite='supervisor-client:execute', "
                "on_result=lambda result: test_e2e._emit_synthetic_failure_diagnostics("
                "sys.argv[1], result.stdout, execution_failed=(result.returncode != 0)))\n",
                encoding="ascii",
            )

            workflow = (test_e2e.ROOT / ".github/workflows/devlane-synthetic.yml").read_text(encoding="utf-8")
            workflow_lines = workflow.splitlines()
            start = next(index for index, line in enumerate(workflow_lines) if line.strip() == "quiet() {")
            end = next(index for index in range(start + 1, len(workflow_lines))
                       if workflow_lines[index].strip() == "}")
            quiet_function = textwrap.dedent("\n".join(workflow_lines[start:end + 1]))
            self.assertIn('acceptance_diagnostics.py --stage "$stage" --file "$out"', quiet_function)
            shell = (quiet_function + "\nquiet production-path-e2e python3 -B "
                     + shlex.quote(str(driver)) + " " + shlex.quote(str(destination)))
            environment = os.environ.copy()
            environment["RUNNER_TEMP"] = str(runner_temp)
            environment["PYTHONPATH"] = str(Path(test_e2e.__file__).resolve().parent)
            result = subprocess.run(
                ["/bin/bash", "-c", shell], cwd=test_e2e.ROOT, env=environment,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True, check=False,
            )

        self.assertEqual(result.returncode, 1, result.stderr.decode("utf-8", "replace"))
        output_lines = result.stdout.decode("utf-8", "replace").splitlines()
        self.assertIn("devlane_acceptance=refused stage=production-path-e2e", output_lines)
        self.assertIn("devlane_supervisor_refusal=execution-order", output_lines)
        diagnostic_lines = [line for line in output_lines if line.startswith("devlane_e2e_failure_diag=")]
        self.assertTrue(diagnostic_lines, result.stdout.decode("utf-8", "replace")
                        + result.stderr.decode("utf-8", "replace"))
        self.assertTrue(all(test_e2e.diagnostic_contract.public_e2e_vitest_diagnostic(line)
                            for line in diagnostic_lines))
        self.assertTrue(any("spawn /tools/node/bin/node EACCES" in line for line in diagnostic_lines))
        self.assertTrue(any("typescript_reporter_refusal=typescript-unavailable" in line
                            for line in diagnostic_lines))
        self.assertTrue(any("name=unit.stdout" in line for line in diagnostic_lines))
        self.assertTrue(any("name=style.log" in line for line in diagnostic_lines))
        self.assertTrue(any("name=audit.log" in line for line in diagnostic_lines))
        self.assertTrue(any("name=install.log" in line for line in diagnostic_lines))
        self.assertNotIn("PRIVATE_KEY_CANARY", "\n".join(output_lines))
        self.assertIn("devlane_e2e_failure_diag=report name=vitest.json kind=file bytes=2", diagnostic_lines)
        self.assertFalse(destination.exists())

    def test_failure_diagnostic_capture_requires_source_free_context_and_fixed_unit_failure(self):
        summary = (b'{"code":"DEVLANE_FAILURE","kind":"control","stage":"unit",'
                   b'"status":"fail","subreason":"vitest-failed"}\n')
        for wave_class, profile, payload in (
                ("encrypted", "core-node", summary),
                (supervisor.fetch.SOURCE_FREE_WAVE_CLASS, "core-node",
                 b'{"kind":"control","stage":"unit","status":"fail","subreason":"typecheck-failed"}\n')):
            with self.subTest(wave_class=wave_class, profile=profile), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                (root / "workspace/raw").mkdir(parents=True)
                (root / "scratch/reports").mkdir(parents=True)
                destination = root / "devlane-vitest-local-synthetic-node-accept.json"
                service = object.__new__(supervisor.Service)
                service.root = root
                service.failure_diagnostics_file = destination
                service.owner_uid = os.getuid()
                service.context = {"wave_class": wave_class, "profile": profile}
                service.summary = payload
                self.assertFalse(service._capture_failure_diagnostics())
                self.assertFalse(destination.exists())

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "workspace/raw").mkdir(parents=True)
            (root / "scratch/reports").mkdir(parents=True)
            destination = root / "devlane-vitest-local-synthetic-node-accept.json"
            service = object.__new__(supervisor.Service)
            service.root = root
            service.failure_diagnostics_file = destination
            service.owner_uid = os.getuid()
            service.context = {"wave_class": "encrypted", "profile": "core-node"}
            service.summary = None
            self.assertFalse(service._capture_failure_diagnostics(execution_failed=True))
            self.assertFalse(destination.exists())

        semver_summary = (b'{"code":"DEVLANE_SEMVER_EXECUTION","kind":"control",'
                          b'"stage":"semver","status":"fail"}\n')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "workspace/raw").mkdir(parents=True)
            (root / "workspace/raw/semver-analyzer.log").write_text(
                "semver current scenario log\n", encoding="ascii",
            )
            (root / "scratch/reports").mkdir(parents=True)
            destination = root / "devlane-rust-matrix-local-synthetic-rust-accept.json"
            service = object.__new__(supervisor.Service)
            service.root = root
            service.failure_diagnostics_file = destination
            service.owner_uid = os.getuid()
            service.context = {
                "wave_class": supervisor.fetch.SOURCE_FREE_WAVE_CLASS,
                "profile": "core-rust",
            }
            service.summary = semver_summary
            self.assertTrue(service._capture_failure_diagnostics())
            document = bundle.strict_json(destination.read_bytes())
            self.assertEqual([item["name"] for item in document["logs"]], ["semver-analyzer.log"])

    def test_source_free_diagnostics_context_allows_both_synthetic_profiles_only(self):
        for profile in ("core-node", "core-rust"):
            context = {"wave_class": supervisor.fetch.SOURCE_FREE_WAVE_CLASS, "profile": profile}
            self.assertTrue(supervisor._source_free_diagnostics_context(context))
            context["wave_class"] = "encrypted"
            self.assertFalse(supervisor._source_free_diagnostics_context(context))
        self.assertFalse(supervisor._source_free_diagnostics_context({
            "wave_class": supervisor.fetch.SOURCE_FREE_WAVE_CLASS, "profile": "synthetic",
        }))

    def test_e2e_marks_the_current_scenario_before_building_its_projection(self):
        source = inspect.getsource(test_e2e._run_scenario)
        self.assertLess(source.index('_progress("scenario="'),
                        source.index('_phase_call("scenario-projection-write"'))

    def test_rust_matrix_failure_diagnostics_capture_the_failing_arm_logs(self):
        summary = (b'{"failed":1,"ignored":0,"kind":"coverage","passed":0,'
                   b'"stage":"format","suite":"fmt-root","total":1}\n')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "scratch/raw"
            reports = root / "scratch/reports"
            raw.mkdir(parents=True)
            reports.mkdir(parents=True)
            rows = ["matrix output %03d" % index for index in range(150)]
            rows[-1] = "SYNTHETIC_SOURCE_CANARY_7f8c must be skipped"
            (raw / "fmt-root.stdout").write_text("\n".join(rows) + "\n", encoding="ascii")
            (raw / "fmt-root.stderr").write_text(
                "compiler started\nKEYCANARY-73A10X must be skipped\n", encoding="ascii",
            )
            (reports / "rust-matrix.jsonl").write_text("{}\n", encoding="ascii")
            destination = root / "devlane-rust-matrix-local-synthetic-rust-accept.json"
            service = object.__new__(supervisor.Service)
            service.root = root
            service.failure_diagnostics_file = destination
            service.owner_uid = os.getuid()
            service.context = {
                "wave_class": supervisor.fetch.SOURCE_FREE_WAVE_CLASS,
                "profile": "core-rust",
            }
            service.summary = summary
            self.assertTrue(service._capture_failure_diagnostics())
            captured = bundle.strict_json(destination.read_bytes())
            self.assertTrue(all(len(item["lines"]) <= supervisor.MAX_SYNTHETIC_RUST_DIAGNOSTIC_TAIL_LINES
                                for item in captured["logs"]))
            self.assertEqual(test_e2e._synthetic_failure_subreason(summary, "core-rust"), "rust-matrix-failed")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                test_e2e._emit_synthetic_failure_diagnostics(destination, summary, "core-rust")
            lines = output.getvalue().splitlines()

        self.assertTrue(any("name=fmt-root.stdout" in line for line in lines))
        self.assertTrue(any("name=rust-matrix.jsonl kind=file" in line for line in lines))
        rendered = "\n".join(lines)
        self.assertNotIn("SYNTHETIC_SOURCE_CANARY", rendered)
        self.assertNotIn("KEYCANARY-73A10X", rendered)
        self.assertTrue(all(test_e2e.diagnostic_contract.public_e2e_failure_diagnostic(line) for line in lines))

    def test_rust_matrix_runner_refusal_captures_bounded_current_arm_logs(self):
        summary = (b'{"code":"DEVLANE_FAILURE","kind":"control","stage":"unit",'
                   b'"status":"fail","subreason":"report-missing"}\n')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            raw = root / "scratch/raw"
            workspace_raw = root / "workspace/raw"
            reports = root / "scratch/reports"
            raw.mkdir(parents=True)
            workspace_raw.mkdir(parents=True)
            reports.mkdir(parents=True)
            for stem in supervisor._SYNTHETIC_RUST_MATRIX_LOG_STEMS:
                for stream in ("stdout", "stderr"):
                    path = raw / (stem + "." + stream)
                    path.write_text("matrix arm " + stem + " " + stream + "\n", encoding="ascii")
            (raw / "compile-root-default.stdout").write_text(
                "compile-root-default safe tail\nSYNTHETIC_SOURCE_CANARY_7f8c\n", encoding="ascii",
            )
            (raw / "compile-listener-all-features.stderr").write_text(
                "listener safe tail\nKEYCANARY-73A10X must be skipped\n", encoding="ascii",
            )
            (workspace_raw / "rust-matrix-adapter.log").write_text(
                "rust_matrix=refused code=matrix-runner-failed\n", encoding="ascii",
            )
            (workspace_raw / "semver-analyzer.log").write_text(
                "semver tool exited 101\n", encoding="ascii",
            )
            (workspace_raw / "style.log").write_text("previous node scenario\n", encoding="ascii")
            (workspace_raw / "unit.log").write_text("previous node unit log\n", encoding="ascii")
            (reports / "rust-matrix.jsonl").write_text("{}\n", encoding="ascii")
            destination = root / "devlane-rust-matrix-local-synthetic-rust-accept.json"
            service = object.__new__(supervisor.Service)
            service.root = root
            service.failure_diagnostics_file = destination
            service.owner_uid = os.getuid()
            service.context = {
                "wave_class": supervisor.fetch.SOURCE_FREE_WAVE_CLASS,
                "profile": "core-rust",
            }
            service.summary = summary
            self.assertTrue(service._capture_failure_diagnostics())
            document = bundle.strict_json(destination.read_bytes())
            self.assertEqual(len(document["logs"]), 46)
            self.assertEqual(supervisor.MAX_SYNTHETIC_DIAGNOSTIC_LOGS, 48)
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                test_e2e._emit_synthetic_failure_diagnostics(destination, summary, "core-rust")
            lines = output.getvalue().splitlines()

        rendered = "\n".join(lines)
        self.assertIn("name=fmt-root.stdout", rendered)
        self.assertIn("name=deny-runtime.stderr", rendered)
        self.assertIn("name=audit-fuzz.stdout", rendered)
        self.assertIn("name=vet-fuzz.stderr", rendered)
        self.assertIn("name=compile-listener-all-features.stderr", rendered)
        self.assertIn("name=replay-fuzz-replay-default.stderr", rendered)
        self.assertIn("name=rust-matrix-adapter.log", rendered)
        self.assertIn("name=semver-analyzer.log", rendered)
        self.assertNotIn("name=style.log", rendered)
        self.assertNotIn("name=unit.log", rendered)
        self.assertNotIn("SYNTHETIC_SOURCE_CANARY", rendered)
        self.assertNotIn("KEYCANARY-73A10X", rendered)
        self.assertTrue(all(test_e2e.diagnostic_contract.public_e2e_failure_diagnostic(line) for line in lines))

    def test_rust_matrix_diagnostics_survive_real_quiet_capture_without_prior_node_logs(self):
        summary = (b'{"code":"DEVLANE_FAILURE","kind":"control","stage":"unit",'
                   b'"status":"fail","subreason":"report-missing"}\n')
        with tempfile.TemporaryDirectory() as temporary:
            runner_temp = Path(temporary)
            root = runner_temp / "namespace-root"
            raw = root / "scratch/raw"
            reports = root / "scratch/reports"
            workspace_raw = root / "workspace/raw"
            raw.mkdir(parents=True)
            reports.mkdir(parents=True)
            workspace_raw.mkdir(parents=True)
            for stem in ("fmt-root", "deny-root", "compile-listener-all-features"):
                (raw / (stem + ".stdout")).write_text(stem + " current rust log\n", encoding="ascii")
            (raw / "compile-listener-all-features.stderr").write_text(
                "current rust log\nPRIVATE_KEY_CANARY must be skipped\n", encoding="ascii",
            )
            (workspace_raw / "rust-matrix-adapter.log").write_text(
                "rust_matrix=refused code=matrix-runner-failed\n", encoding="ascii",
            )
            (workspace_raw / "semver-analyzer.log").write_text("semver current log\n", encoding="ascii")
            (reports / "rust-matrix.jsonl").write_text("{}\n", encoding="ascii")
            destination = runner_temp / "devlane-rust-matrix-local-synthetic-rust-accept.json"
            service = object.__new__(supervisor.Service)
            service.root = root
            service.failure_diagnostics_file = destination
            service.owner_uid = os.getuid()
            service.context = {
                "wave_class": supervisor.fetch.SOURCE_FREE_WAVE_CLASS,
                "profile": "core-rust",
            }
            service.summary = summary
            with mock.patch.dict(os.environ, {"RUNNER_TEMP": str(runner_temp)}):
                self.assertTrue(service._capture_failure_diagnostics())

            driver = runner_temp / "harness-rust-failure.py"
            command_source = (
                "import sys; sys.stdout.buffer.write(" + repr(summary) + "); sys.exit(1)"
            )
            previous_node_line = (
                "devlane_e2e_failure_diag=log name=unit.log line=1 text=previous-node-output"
            )
            driver.write_text(
                "import sys\n"
                "import test_e2e\n"
                "print(" + repr(previous_node_line) + ", flush=True)\n"
                "print('devlane_e2e_progress=scenario=synthetic-rust-v1-refusal', flush=True)\n"
                "command = [sys.executable, '-c', " + repr(command_source) + "]\n"
                "test_e2e._run(command, expected=0, diagnostic_callsite='supervisor-client:execute', "
                "on_result=lambda completed: test_e2e._emit_synthetic_failure_diagnostics("
                "sys.argv[1], completed.stdout, 'core-rust'))\n",
                encoding="ascii",
            )
            workflow = (test_e2e.ROOT / ".github/workflows/devlane-synthetic.yml").read_text(encoding="utf-8")
            workflow_lines = workflow.splitlines()
            start = next(index for index, line in enumerate(workflow_lines) if line.strip() == "quiet() {")
            end = next(index for index in range(start + 1, len(workflow_lines))
                       if workflow_lines[index].strip() == "}")
            quiet_function = textwrap.dedent("\n".join(workflow_lines[start:end + 1]))
            shell = (quiet_function + "\nquiet production-path-e2e python3 -B "
                     + shlex.quote(str(driver)) + " " + shlex.quote(str(destination)))
            environment = os.environ.copy()
            environment["RUNNER_TEMP"] = str(runner_temp)
            environment["PYTHONPATH"] = str(Path(test_e2e.__file__).resolve().parent)
            result = subprocess.run(
                ["/bin/bash", "-c", shell], cwd=test_e2e.ROOT, env=environment,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True, check=False,
            )

        self.assertEqual(result.returncode, 1, result.stderr.decode("utf-8", "replace"))
        lines = result.stdout.decode("utf-8", "replace").splitlines()
        diagnostics = [line for line in lines if line.startswith("devlane_e2e_failure_diag=")]
        self.assertTrue(any("name=fmt-root.stdout" in line for line in diagnostics))
        self.assertTrue(any("name=compile-listener-all-features.stdout" in line for line in diagnostics))
        self.assertTrue(any("name=rust-matrix-adapter.log" in line for line in diagnostics))
        self.assertFalse(any("name=unit.log" in line for line in diagnostics))
        self.assertNotIn("PRIVATE_KEY_CANARY", "\n".join(lines))
        self.assertTrue(all(test_e2e.diagnostic_contract.public_e2e_failure_diagnostic(line)
                            for line in diagnostics))

    def test_preparation_log_sideband_is_bounded_and_canary_scanned(self):
        preparation = supervisor.node_tool_prepare
        prior = preparation.SOURCE_FREE_DIAGNOSTICS
        prior_stage = preparation.PREPARATION_STAGE
        try:
            with tempfile.TemporaryDirectory() as temporary:
                log = Path(temporary) / "prepare-playwright.log"
                log.write_bytes(b"ordinary preparation output\n" * 2000)
                preparation.SOURCE_FREE_DIAGNOSTICS = False
                hidden = io.StringIO()
                with contextlib.redirect_stdout(hidden):
                    preparation._emit_preparation_log_diagnostics(log, "prepare-playwright-install")
                self.assertEqual(hidden.getvalue(), "")

                preparation.SOURCE_FREE_DIAGNOSTICS = True
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    preparation._emit_preparation_log_diagnostics(log, "prepare-playwright-install")
                records = output.getvalue().encode("ascii")
                parsed = test_e2e.diagnostic_contract.parse_preparation_log_diagnostics(records)
                self.assertIsNotNone(parsed)
                self.assertLessEqual(len(parsed), test_e2e.diagnostic_contract.PREPARATION_LOG_DIAGNOSTIC_LINES + 1)
                self.assertLessEqual(len(records), test_e2e.diagnostic_contract.MAX_PREPARATION_OUTPUT_BYTES)
                self.assertTrue(all("ordinary preparation output" in line
                                    or "earlier-log-content-omitted" in line for line in parsed))

                log.write_bytes(b"PRIVATE_SOURCE_CANARY\n" + b"ordinary preparation output\n" * 2000)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    preparation._emit_preparation_log_diagnostics(log, "prepare-playwright-install")
                self.assertEqual(output.getvalue(),
                                 "devlane_preparation_detail stage=prepare-playwright-install "
                                 "index=0 text=canary-redacted\n")
                self.assertNotIn("PRIVATE_SOURCE_CANARY", output.getvalue())

                preparation.PREPARATION_STAGE = "prepare-playwright-install"
                cases = (
                    ("failed", "preparation-failed", b"download failed\n"),
                    ("timeout", "preparation-timeout", b"download timed out\n"),
                    ("unavailable", "preparation-tool-unavailable", b""),
                )
                for label, code, payload in cases:
                    log = Path(temporary) / (label + ".log")
                    emitted = io.StringIO()

                    class FailedProcess:
                        pid = 987654

                        def __init__(self, _argv, **kwargs):
                            if payload:
                                kwargs["stdout"].write(payload)
                            self.wait_count = 0

                        def wait(self, timeout=None):
                            self.wait_count += 1
                            if label == "timeout" and self.wait_count == 1:
                                raise subprocess.TimeoutExpired("prepare", timeout)
                            return 1

                    unavailable = OSError("tool unavailable") if label == "unavailable" else FailedProcess
                    with self.subTest(label=label), \
                            mock.patch.object(preparation, "_bounded_timeout", return_value=10), \
                            mock.patch.object(preparation, "_kill_children"), \
                            mock.patch.object(preparation.os, "killpg"), \
                            mock.patch.object(preparation.subprocess, "Popen", side_effect=unavailable), \
                            contextlib.redirect_stdout(emitted):
                        with self.assertRaises(supervisor.bundle.Refusal) as caught:
                            preparation.run(["tool"], timeout=10, log=log, environment={})
                    self.assertEqual(caught.exception.args[0], code)
                    parsed = test_e2e.diagnostic_contract.parse_preparation_log_diagnostics(
                        emitted.getvalue().encode("ascii"),
                    )
                    self.assertIsNotNone(parsed)
                    self.assertTrue(all("stage=prepare-playwright-install" in line for line in parsed))
        finally:
            preparation.SOURCE_FREE_DIAGNOSTICS = prior
            preparation.PREPARATION_STAGE = prior_stage

    def test_preparation_file_size_limit_covers_the_pinned_chromium_binary(self):
        preparation = supervisor.node_tool_prepare
        pinned_chromium_bytes = 458078440
        self.assertGreater(preparation.MAX_PREPARATION_FILE_SIZE, pinned_chromium_bytes)
        self.assertLess(preparation.MAX_LOG, pinned_chromium_bytes)
        prepare_directory = str(Path(preparation.__file__).resolve().parent)
        with tempfile.TemporaryDirectory() as temporary:
            target = str(Path(temporary) / "chromium")
            program = (
                "import pathlib,sys; sys.path.insert(0, " + repr(prepare_directory) + "); "
                "import prepare; prepare._limits(); file=pathlib.Path(sys.argv[1]).open('wb'); "
                "file.truncate(458078440); file.close(); print(pathlib.Path(sys.argv[1]).stat().st_size)"
            )
            old_program = program.replace(
                "prepare._limits()",
                "__import__('resource').setrlimit(__import__('resource').RLIMIT_FSIZE, "
                "(prepare.MAX_LOG, prepare.MAX_LOG))",
            )
            old_target = str(Path(temporary) / "old-limit-chromium")
            old_result = subprocess.run(
                [sys.executable, "-B", "-c", old_program, old_target], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, check=False,
            )
            self.assertNotEqual(old_result.returncode, 0)
            result = subprocess.run(
                [sys.executable, "-B", "-c", program, target], stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr.decode("utf-8", "replace"))
            self.assertEqual(result.stdout, b"458078440\n")

    def test_harness_emits_only_matching_source_free_preparation_log_details(self):
        detail = ("devlane_preparation_detail stage=prepare-playwright-install index=1 "
                  "text=chrome-linux/chrome write failed with EFBIG\n").encode("ascii")
        refusal = ("dependency_preparation_refusal=stage=prepare-playwright-install "
                   "code=preparation-failed cleanup=confirmed\n").encode("ascii")
        with mock.patch.object(test_e2e, "_process_run", return_value=subprocess.CompletedProcess(
                ["prepare.py"], 2, detail, refusal)):
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(test_e2e.PreparationRefusalMismatch) as caught:
                    test_e2e._run_preparation(["prepare.py"], source_free_diagnostics=True)
        self.assertEqual(caught.exception.phase, "prepare-playwright-install")
        self.assertEqual(caught.exception.category, "preparation-failed")
        self.assertEqual(stderr.getvalue(), detail.decode("ascii"))

        with mock.patch.object(test_e2e, "_process_run", return_value=subprocess.CompletedProcess(
                ["prepare.py"], 2, detail, refusal)):
            with self.assertRaises(test_e2e.PreparationRefusalMismatch) as caught:
                test_e2e._run_preparation(["prepare.py"])
        self.assertEqual(caught.exception.category, "preparation-output-invalid")

        canary_detail = ("devlane_preparation_detail stage=prepare-playwright-install index=1 "
                         "text=KEYCANARY-73A10X-redacted\n").encode("ascii")
        with mock.patch.object(test_e2e, "_process_run", return_value=subprocess.CompletedProcess(
                ["prepare.py"], 2, canary_detail, refusal)):
            with self.assertRaises(test_e2e.PreparationRefusalMismatch) as caught:
                test_e2e._run_preparation(["prepare.py"], source_free_diagnostics=True)
        self.assertEqual(caught.exception.category, "preparation-output-canary")

    def test_preparation_log_diagnostics_survive_real_quiet_capture(self):
        detail = ("devlane_preparation_detail stage=prepare-playwright-install index=1 "
                  "text=chrome-linux/chrome write failed with EFBIG\n").encode("ascii")
        refusal = ("dependency_preparation_refusal=stage=prepare-playwright-install "
                   "code=preparation-failed cleanup=confirmed\n").encode("ascii")
        with tempfile.TemporaryDirectory() as temporary:
            runner_temp = Path(temporary)
            driver = runner_temp / "harness-preparation-failure.py"
            completed = "subprocess.CompletedProcess(['prepare.py'], 2, " + repr(detail) + ", " + repr(refusal) + ")"
            driver.write_text(
                "import subprocess, sys\n"
                "from unittest.mock import patch\n"
                "import test_e2e\n"
                "completed = " + completed + "\n"
                "with patch.object(test_e2e, '_process_run', return_value=completed):\n"
                "    try:\n"
                "        test_e2e._run_preparation(['prepare.py'], source_free_diagnostics=True)\n"
                "    except test_e2e.PreparationRefusalMismatch:\n"
                "        print('devlane_production_e2e=refused stage=prepare-playwright-install "
                "exception=preparation-failed', file=sys.stderr)\n"
                "        raise SystemExit(1)\n"
                "raise SystemExit(0)\n",
                encoding="ascii",
            )
            workflow = (test_e2e.ROOT / ".github/workflows/devlane-synthetic.yml").read_text(encoding="utf-8")
            workflow_lines = workflow.splitlines()
            start = next(index for index, line in enumerate(workflow_lines) if line.strip() == "quiet() {")
            end = next(index for index in range(start + 1, len(workflow_lines))
                       if workflow_lines[index].strip() == "}")
            quiet_function = textwrap.dedent("\n".join(workflow_lines[start:end + 1]))
            shell = (quiet_function + "\nquiet production-path-e2e python3 -B "
                     + shlex.quote(str(driver)))
            environment = os.environ.copy()
            environment["RUNNER_TEMP"] = str(runner_temp)
            environment["PYTHONPATH"] = str(Path(test_e2e.__file__).resolve().parent)
            result = subprocess.run(
                ["/bin/bash", "-c", shell], cwd=test_e2e.ROOT, env=environment,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                close_fds=True, check=False,
            )

        self.assertEqual(result.returncode, 1, result.stderr.decode("utf-8", "replace"))
        lines = result.stdout.decode("utf-8", "replace").splitlines()
        self.assertIn("devlane_acceptance=refused stage=production-path-e2e", lines)
        self.assertTrue(any("devlane_preparation_detail stage=prepare-playwright-install "
                            "index=1 text=chrome-linux/chrome write failed with EFBIG" in line
                            for line in lines))
        self.assertTrue(all(test_e2e.diagnostic_contract.public_acceptance_detail(line) for line in lines
                            if line.startswith("devlane_acceptance_detail ")))

    def test_unit_failure_raw_diagnostics_only_run_for_the_fixed_failure_reasons(self):
        for subreason in ("vitest-failed", "report-missing", "adapter-failed"):
            summary = ('{"code":"DEVLANE_FAILURE","kind":"control","stage":"unit",'
                       '"status":"fail","subreason":"%s"}\n'
                       % subreason).encode("ascii")
            self.assertEqual(test_e2e._synthetic_failure_subreason(summary), subreason)
        rust_summary = (b'{"failed":1,"ignored":0,"kind":"coverage","passed":0,'
                        b'"stage":"format","suite":"fmt-root","total":1}\n')
        self.assertEqual(test_e2e._synthetic_failure_subreason(rust_summary, "core-rust"), "rust-matrix-failed")
        rust_unit_summary = (b'{"failed":1,"ignored":0,"kind":"coverage","passed":0,'
                             b'"stage":"unit","suite":"root-default","total":1}\n')
        self.assertEqual(test_e2e._synthetic_failure_subreason(rust_unit_summary, "core-rust"), "rust-matrix-failed")
        self.assertEqual(test_e2e._synthetic_failure_subreason(
            b'{"code":"DEVLANE_FAILURE","kind":"control","stage":"unit",'
            b'"status":"fail","subreason":"vitest-failed"}\n', "core-rust"), "")
        self.assertEqual(test_e2e._synthetic_failure_subreason(
            b'{"code":"DEVLANE_FAILURE","kind":"control","stage":"typecheck",'
            b'"status":"fail"}\n', execution_failed=True), "execute-failed")
        self.assertEqual(test_e2e._synthetic_failure_subreason(
            b'{"code":"DEVLANE_FAILURE","kind":"control","stage":"typecheck",'
            b'"status":"fail"}\n'), "")
        for summary in (
            b'{"kind":"control","stage":"unit","status":"fail","subreason":"typecheck-failed"}\n',
            b'{"kind":"control","stage":"browser","status":"fail","subreason":"adapter-failed"}\n',
            b'{"kind":"control","stage":"unit","status":"fail","subreason":"vitest-failed"} KEYCANARY-73A10X\n',
        ):
            self.assertEqual(test_e2e._synthetic_failure_subreason(summary), "")

    def test_committed_rust_fixture_passes_the_e2e_projection_and_archive_contract(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = dict(test_e2e.RUST_FIXTURE_SOURCES)
            projection, projection_bytes = test_e2e._rust_projection(
                files["Cargo.lock"], files["fuzz/Cargo.lock"], files["runtime/Cargo.lock"])
            lock_hashes = {path: hashlib.sha256(files[path]).hexdigest() for path in test_e2e.RUST_LOCKFILES}
            snapshot = {
                "schema": 1, "toolchain": test_e2e.RUST_VERSION,
                "lockfiles": {path: {"sha256": lock_hashes[path], "size": len(files[path])}
                              for path in test_e2e.RUST_LOCKFILES},
                "projection_sha256": hashlib.sha256(projection_bytes).hexdigest(),
            }
            for relative, payload in files.items():
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(payload)
            (root / ".devlane-projection.json").write_bytes(projection_bytes)
            (root / ".devlane-lock-snapshot.json").write_bytes(bundle.canonical_json(snapshot) + b"\n")
            with mock.patch.object(test_e2e, "CONTROL_SHA", CONTROL_SHA):
                archive = test_e2e._validate_rust_fixture(
                    root, files, projection, projection_bytes, snapshot)
            manifest, archived_files, _ = bundle.inspect_archive(archive, {
                "profile": "core-rust", "fetch_sha256": snapshot["projection_sha256"],
            })
            self.assertEqual(set(manifest["original_lockfiles"]), set(test_e2e.RUST_LOCKFILES))
            self.assertEqual({path: archived_files[path] for path in test_e2e.RUST_LOCKFILES},
                             {path: files[path] for path in test_e2e.RUST_LOCKFILES})

    def test_fixture_loader_checks_the_real_snapshot_before_projection_validation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            files = dict(test_e2e.RUST_FIXTURE_SOURCES)
            files.update({name: b"synthetic-lock-loader-only" for name in test_e2e.RUST_LOCKFILES})
            for name, body in files.items():
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(body)
            projection_bytes = b"synthetic-projection-loader-only"
            snapshot = {"schema": 1, "toolchain": test_e2e.RUST_VERSION,
                        "lockfiles": {}, "projection_sha256": "a" * 64}
            (root / ".devlane-projection.json").write_bytes(projection_bytes)
            snapshot_path = root / ".devlane-lock-snapshot.json"
            snapshot_path.write_bytes(bundle.canonical_json(snapshot))
            projection = {"synthetic": True}
            with mock.patch.object(test_e2e.fetch, "validate_projection", return_value=projection) as validate, \
                    mock.patch.object(test_e2e, "_validate_rust_fixture") as verify:
                actual = test_e2e._load_rust_fixture(root)
                self.assertEqual(actual, (projection, projection_bytes, snapshot, files))
                validate.assert_called_once_with(projection_bytes, "core-rust")
                verify.assert_called_once_with(root, files, projection, projection_bytes, snapshot)
                snapshot["projection_sha256"] = "invalid"
                snapshot_path.write_bytes(bundle.canonical_json(snapshot))
                validate.reset_mock()
                verify.reset_mock()
                with self.assertRaisesRegex(RuntimeError, "rust-matrix-projection-snapshot-shape"):
                    test_e2e._load_rust_fixture(root)
                validate.assert_not_called()
                verify.assert_not_called()

    def test_name_errors_keep_a_finite_diagnostic_category(self):
        state = test_e2e._DiagnosticState()
        with self.assertRaises(NameError):
            with state.phase("fixture-load"):
                raise NameError("private-canary-must-not-be-rendered")
        self.assertEqual(state.refusal_line(NameError()),
                         "devlane_production_e2e=refused stage=fixture-load exception=name-error")

    def test_variant_execute_runtime_error_reports_only_its_innermost_devlane_frame(self):
        for phase in ("variant-execute", "variant-summary-validate"):
            with self.subTest(phase=phase):
                state = test_e2e._DiagnosticState()

                def throw_require_runtime_error():
                    test_e2e._require(False, "summary-schema-invalid")

                try:
                    with state.phase(phase):
                        throw_require_runtime_error()
                except RuntimeError as error:
                    line = state.refusal_line(error)
                self.assertRegex(
                    line,
                    r"^devlane_production_e2e=refused stage=" + phase + r" exception=runtime-error "
                    r"class=RuntimeError frame=test_e2e\.py:[1-9][0-9]*:_require "
                    r"code=summary-schema-invalid$",
                )
                for private in ("/runner", "/source", "KEYCANARY-73A10X", "private"):
                    self.assertNotIn(private, line)
                self.assertTrue(test_e2e.diagnostic_contract.public_e2e_runtime_diagnostic(line))

        generic = test_e2e._DiagnosticState()

        def throw_generic_runtime_error():
            raise RuntimeError("private /runner/source KEYCANARY-73A10X")

        try:
            with generic.phase("variant-summary-validate"):
                throw_generic_runtime_error()
        except RuntimeError as error:
            generic_line = generic.refusal_line(error)
        self.assertIn("frame=test_rehearsal.py:", generic_line)
        self.assertNotIn(" code=", generic_line)
        self.assertTrue(test_e2e.diagnostic_contract.public_e2e_runtime_diagnostic(generic_line))

        outside_frame = test_e2e._DiagnosticState()
        error = RuntimeError("detail")
        outside_frame.capture("variant-summary-validate", error)
        self.assertIsNone(outside_frame.runtime_frame)
        self.assertEqual(outside_frame.refusal_line(error),
                         "devlane_production_e2e=refused stage=variant-summary-validate exception=runtime-error")

    def test_e2e_require_code_allowlist_matches_all_fixed_require_call_sites(self):
        source = Path(test_e2e.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        codes = set()
        passthrough_require_calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id == "_require":
                self.assertGreaterEqual(len(node.args), 2)
                code = node.args[1]
                if isinstance(code, ast.Constant) and type(code.value) is str:
                    codes.add(code.value)
                else:
                    self.assertIsInstance(code, ast.Name)
                    self.assertEqual(code.id, "code")
                    passthrough_require_calls.append(node)
            elif node.func.id == "_scan_output":
                self.assertGreaterEqual(len(node.args), 2)
                code = node.args[1]
                self.assertIsInstance(code, ast.Constant)
                self.assertIs(type(code.value), str)
                codes.add(code.value)
        self.assertEqual(len(passthrough_require_calls), 1)
        self.assertEqual(codes, test_e2e.diagnostic_contract.E2E_REQUIRE_CODES)

    def test_empty_success_summary_is_a_valid_execute_summary(self):
        self.assertTrue(test_e2e._summary_has_valid_terminator(b""))
        self.assertTrue(test_e2e._summary_has_valid_terminator(b'{"kind":"test"}\n'))
        self.assertFalse(test_e2e._summary_has_valid_terminator(b'{"kind":"test"}'))
        self.assertFalse(test_e2e._summary_has_valid_terminator(""))
        self.assertEqual(test_e2e._summary_records(b"", test_e2e.scenarios()[0]), [])

    def test_tooling_refusal_reports_allowlisted_reason_and_sanitized_version_probe(self):
        state = test_e2e._DiagnosticState()
        private_path = chr(47) + "private/runner"
        error = test_e2e.rust_tooling.ToolingRefusal(
            "tool-version-mismatch",
            version_output=(b"cargo-semver-checks 0.51.0\n"
                            + private_path.encode("ascii") + b"\n"),
        )
        state.capture("tool-cargo-semver-checks-version", error)
        line = state.refusal_line(error)
        self.assertEqual(
            line,
            'devlane_production_e2e=refused stage=tool-cargo-semver-checks-version '
            'exception=tooling-refusal reason=tool-version-mismatch '
            'version="cargo-semver-checks 0.51.0"',
        )
        self.assertTrue(test_e2e.diagnostic_contract.public_preparation_diagnostic(line))
        self.assertLessEqual(len(line.encode("ascii")),
                             test_e2e.diagnostic_contract.MAX_PUBLIC_DIAGNOSTIC_BYTES)
        self.assertNotIn(private_path, line)
        self.assertTrue(
            test_e2e.rust_tooling.TOOLING_REFUSAL_CODES
            <= test_e2e.diagnostic_contract.TOOLING_REFUSAL_CODES,
        )
        with tempfile.TemporaryDirectory() as temporary:
            diagnostic = Path(temporary) / "diagnostic"
            self.assertTrue(test_e2e._write_diagnostic_file(str(diagnostic), line))
            self.assertEqual(test_e2e._read_reportable_diagnostic_file(str(diagnostic)), line)

        self.assertEqual(
            test_e2e._public_tool_version_line(
                b"cargo " + private_path.encode("ascii") + b"\x1b[31m",
            ),
            "cargo _private_runner__31m",
        )
        self.assertEqual(
            test_e2e._public_tool_version_line(b"cargo KEYCANARY-73A10X 0.51.0"),
            "redacted",
        )
        self.assertLessEqual(len(test_e2e._public_tool_version_line(b"x" * 200)), 32)

        invalid_lines = (
            "devlane_production_e2e=refused stage=tool-cargo-semver-checks-version "
            "exception=tooling-refusal",
            "devlane_production_e2e=refused stage=tool-cargo-semver-checks-version "
            "exception=tooling-refusal reason=private-path",
            "devlane_production_e2e=refused stage=tool-cargo-semver-checks-version "
            "exception=tooling-refusal reason=tool-binary-missing version=\"cargo 0.51.0\"",
            "devlane_production_e2e=refused stage=tool-cargo-semver-checks-version "
            "exception=runtime-error reason=tool-version-mismatch",
        )
        for invalid in invalid_lines:
            with self.subTest(line=invalid):
                self.assertFalse(test_e2e.diagnostic_contract.public_preparation_diagnostic(invalid))

        missing = test_e2e.rust_tooling.ToolingRefusal("tool-binary-missing")
        state.reset()
        state.capture("tool-cargo-semver-checks-version", missing)
        missing_line = state.refusal_line(missing)
        self.assertIn("reason=tool-binary-missing", missing_line)
        self.assertNotIn("version=", missing_line)
        self.assertTrue(test_e2e.diagnostic_contract.public_preparation_diagnostic(missing_line))

        untrusted = test_e2e.rust_tooling.ToolingRefusal(
            "private path KEYCANARY-73A10X",
            version_output=b"cargo KEYCANARY-73A10X\n",
        )
        state.reset()
        state.capture("tool-cargo-semver-checks-version", untrusted)
        untrusted_line = state.refusal_line(untrusted)
        self.assertIn("reason=tooling-refusal-unlisted", untrusted_line)
        self.assertNotIn("private path", untrusted_line)
        self.assertNotIn("KEYCANARY", untrusted_line)

    def test_every_production_phase_has_a_bounded_allowlisted_failure_line(self):
        private_path = chr(47) + "private/runner"
        secret_marker = "SYNTHETIC_SOURCE_CANARY KEYCANARY-73A10X " + private_path + "/candidate"
        for phase in sorted(test_e2e.DIAGNOSTIC_PHASES):
            with self.subTest(phase=phase):
                state = test_e2e._DiagnosticState()
                try:
                    with state.phase(phase):
                        raise RuntimeError(secret_marker)
                except RuntimeError as error:
                    line = state.refusal_line(error)
                self.assertRegex(
                    line,
                    r"devlane_production_e2e=refused stage=[a-z0-9-]{1,48} exception=[a-z0-9-]{1,48}(?::[a-z0-9-]{1,48}){0,2}",
                )
                self.assertLessEqual(len(line), 160)
                for forbidden in ("SYNTHETIC_SOURCE_CANARY", "KEYCANARY-73A10X", private_path, "candidate"):
                    self.assertNotIn(forbidden, line)

    def test_exception_classes_use_exact_allowlist_categories(self):
        private_path = chr(47) + "private/runner"
        cases = (
            (RuntimeError, "runtime-error"),
            (PermissionError, "permission-denied"),
            (test_e2e.rust_tooling.ToolingRefusal, "tooling-refusal"),
            (test_e2e.deadline_budget.DeadlineRefusal, "deadline-refusal"),
            (test_e2e.urllib_error.URLError, "url-error"),
            (json.JSONDecodeError, "json-decode-error"),
        )
        for error_type, category in cases:
            with self.subTest(exception=error_type.__name__):
                state = test_e2e._DiagnosticState()
                error = (error_type("SYNTHETIC_SOURCE_CANARY " + private_path + " KEYCANARY-73A10X", "", 0)
                         if error_type is json.JSONDecodeError else
                         error_type("SYNTHETIC_SOURCE_CANARY " + private_path + " KEYCANARY-73A10X"))
                try:
                    with state.phase("tool-fetch-setup"):
                        raise error
                except Exception as caught:
                    line = state.refusal_line(caught)
                self.assertIn("exception=" + category, line)
                self.assertNotIn("SYNTHETIC_SOURCE_CANARY", line)
                self.assertNotIn(private_path, line)
                self.assertNotIn("KEYCANARY-73A10X", line)

        class DerivedRuntimeError(RuntimeError):
            pass

        state = test_e2e._DiagnosticState()
        error = DerivedRuntimeError("private detail")
        try:
            with state.phase("variant-execute"):
                raise error
        except DerivedRuntimeError as caught:
            line = state.refusal_line(caught)
        self.assertTrue(line.endswith("exception=unclassified"))
        self.assertNotIn("private detail", line)

    def test_later_cleanup_error_does_not_replace_the_first_execution_failure(self):
        state = test_e2e._DiagnosticState()
        try:
            with state.phase("variant-execute"):
                raise RuntimeError("first failure with SYNTHETIC_SOURCE_CANARY and a private path")
        except RuntimeError:
            pass
        try:
            with state.phase("variant-host-cleanup-finally"):
                raise PermissionError("later KEYCANARY cleanup failure")
        except PermissionError:
            pass
        self.assertEqual(state.first_failure, ("variant-execute", "runtime-error"))
        line = state.refusal_line(RuntimeError("unused"))
        self.assertIn("stage=variant-execute exception=runtime-error", line)
        self.assertNotIn("KEYCANARY", line)
        self.assertNotIn("private path", line)

    def test_tool_staging_cleanup_error_preserves_the_original_failure(self):
        class TemporaryDirectory:
            name = "/trusted/staging-fixture"

            @staticmethod
            def cleanup():
                raise PermissionError("KEYCANARY cleanup detail")

        state = test_e2e._DiagnosticState()
        with mock.patch.object(test_e2e.rust_tooling.tempfile, "TemporaryDirectory",
                               return_value=TemporaryDirectory()):
            with self.assertRaisesRegex(RuntimeError, "original-stage-failure"):
                with state.phase("variant-execute"):
                    with test_e2e.rust_tooling._staging_directory(state.phase):
                        with state.phase("tool-cargo-deny-version"):
                            raise RuntimeError("original-stage-failure")
        self.assertEqual(state.first_failure, ("tool-cargo-deny-version", "runtime-error"))
        line = state.refusal_line(RuntimeError("unused"))
        self.assertIn("stage=tool-cargo-deny-version exception=runtime-error", line)
        self.assertNotIn("KEYCANARY", line)

    def test_trusted_isolated_rust_runner_import_smoke_is_part_of_source_free_acceptance(self):
        root = Path(__file__).resolve().parents[2]
        runner = root / "kit/devlane/rust_matrix_runner.py"
        supervisor_source = (root / "kit/devlane/supervisor.py").read_text(encoding="utf-8")
        runner_source = runner.read_text(encoding="utf-8")
        self.assertIn('"/usr/bin/python3", "-B", "-I", "-S", "/control/devlane/rust_matrix_runner.py"',
                      supervisor_source)
        self.assertIn('control_root / "kit/devlane", root / "control/devlane", readonly=True', supervisor_source)
        self.assertIn("sys.path.insert(0, str(Path(__file__).resolve().parent))", runner_source)
        self.assertNotIn("/workspace/source/rust_matrix_runner.py", supervisor_source)
        result = subprocess.run(
            [sys.executable, "-B", "-I", "-S", str(runner)],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn(b"the following arguments are required", result.stderr)
        self.assertNotIn(b"ModuleNotFoundError", result.stderr)


if __name__ == "__main__":
    unittest.main()
