"""The rehearsal and owner request builders produce inputs the real tools accept."""

import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import bundle
import coordinator
import project
import rehearsal
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
            self.assertIn("src/example.ts", names)
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


def bundle_request_digest(owner):
    return json.loads((owner / "bundle-request.json").read_text(encoding="utf-8"))["fetch_sha256"]


class ProductionFailureDiagnosticsTests(unittest.TestCase):
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
