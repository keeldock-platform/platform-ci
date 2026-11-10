"""The rehearsal and owner request builders produce inputs the real tools accept."""

import contextlib
import io
import json
import os
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


def bundle_request_digest(owner):
    return json.loads((owner / "bundle-request.json").read_text(encoding="utf-8"))["fetch_sha256"]


if __name__ == "__main__":
    unittest.main()
