"""Source-free replay, identity and cleanup-lifecycle tests."""

import contextlib
import io
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import bundle
import coordinator


CONTROL_SHA = "a" * 40
BUNDLE_SHA = "b" * 64
PROJECTION_SHA = "c" * 64
CACHE_SHA = "d" * 64


def _request(wave_id="wave-test-0001", bundle_id="bundle-test-0001"):
    return {
        "schema": 2, "wave_id": wave_id, "bundle_id": bundle_id,
        "control_run_id": "12345", "control_sha": CONTROL_SHA, "profile": "core-node",
        "expires": int(time.time()) + 1800, "release_id": "77",
    }


def _ledger_record(wave_id="wave-test-0001", bundle_id="bundle-test-0001", state="assets-staged"):
    return {
        "schema": 2, "wave_id": wave_id, "bundle_id": bundle_id, "control_run_id": "12345",
        "control_sha": CONTROL_SHA, "profile": "core-node", "release_id": "77",
        "bundle_asset_name": "devlane-" + wave_id + "-" + bundle_id + ".enc",
        "projection_asset_name": "devlane-" + wave_id + "-" + bundle_id + ".projection.json",
        "bundle_asset_id": "111", "bundle_sha256": BUNDLE_SHA, "bundle_size": 1024,
        "projection_asset_id": "222", "projection_sha256": PROJECTION_SHA, "projection_size": 512,
        "expires": int(time.time()) + 1800, "cache_baseline_sha256": CACHE_SHA,
        "state": state, "created_at": coordinator._timestamp(), "updated_at": None,
        "run_id": None, "authorized_run_id": None, "run_attempt": None,
        "cleanup_attempts": [], "dispatch_requested_at": None,
        "cleanup_obligations": {
            "secret": {"state": "installed"},
            "bundle_asset": {"state": "upload-pending", "name": "devlane-" + wave_id + "-" + bundle_id + ".enc"},
            "projection_asset": {"state": "upload-pending", "name": "devlane-" + wave_id + "-" + bundle_id + ".projection.json"},
            "logs": {"state": "not-created"}, "artifacts": {"state": "not-created"},
            "run": {"state": "not-dispatched"},
            "replay_guard": {"state": "not-created", "retain_until": int(time.time()) + 1800},
        },
    }


def _write_record(root, record):
    path = Path(root) / (record["wave_id"] + ".json")
    coordinator._write_atomic(path, record)
    return path


class CoordinatorLedgerAcceptanceTests(unittest.TestCase):
    def _new_ledger(self, temporary):
        ledger = Path(temporary) / "ledger"
        ledger.mkdir(mode=0o700)
        record = {
            "schema": 1, "control_sha": CONTROL_SHA, "control_run_id": "12345",
            "status": "passed", "verified_at": coordinator._timestamp(),
        }
        (ledger / ("control-evidence-" + CONTROL_SHA + "-12345.json")).write_bytes(bundle.canonical_json(record))
        return ledger

    def test_one_open_wave_and_bundle_replay_are_refused(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._new_ledger(temporary)
            with mock.patch.object(coordinator, "_verify_secret_absent"), contextlib.redirect_stdout(io.StringIO()):
                coordinator.reserve_wave(ledger, _request())
                with self.assertRaisesRegex(coordinator.Refusal, "wave-already-open"):
                    coordinator.reserve_wave(ledger, _request("wave-test-0002", "bundle-test-0002"))
                record = coordinator._read(ledger / "wave-test-0001.json")
                record["state"] = "deleted"
                coordinator._write_atomic(ledger / "wave-test-0001.json", record)
                with self.assertRaisesRegex(coordinator.Refusal, "bundle-replay"):
                    coordinator.reserve_wave(ledger, _request("wave-test-0003", "bundle-test-0001"))

    def test_assets_are_recorded_before_upload_and_attached_by_release_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._new_ledger(temporary)
            with mock.patch.object(coordinator, "_verify_secret_absent"), \
                    mock.patch.object(coordinator, "_release_assets", return_value=[]), \
                    mock.patch.object(coordinator, "_cache_records", return_value=[]), \
                    mock.patch.object(coordinator, "cache_inventory_digest", return_value=CACHE_SHA), \
                    mock.patch.object(coordinator, "_verify_asset") as verify, \
                    contextlib.redirect_stdout(io.StringIO()):
                coordinator.reserve_wave(ledger, _request())
                coordinator.stage_bundle(ledger, "wave-test-0001", {
                    "schema": 1, "bundle_sha256": BUNDLE_SHA, "bundle_size": 1024,
                    "projection_sha256": PROJECTION_SHA, "projection_size": 512,
                })
                staged = coordinator._read(ledger / "wave-test-0001.json")
                self.assertEqual(staged["state"], "assets-staged")
                self.assertEqual(staged["cleanup_obligations"]["bundle_asset"]["state"], "upload-pending")
                coordinator.record_intent(ledger, {
                    "schema": 2, "wave_id": "wave-test-0001", "bundle_asset_id": "111",
                    "projection_asset_id": "222", "cache_baseline_sha256": CACHE_SHA,
                })
                self.assertEqual(verify.call_count, 2)
                attached = coordinator._read(ledger / "wave-test-0001.json")
                self.assertEqual(attached["state"], "assets-attached")

    def test_wrong_wave_run_log_cannot_be_attached_or_cleaned(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._new_ledger(temporary)
            path = _write_record(ledger, _ledger_record(state="dispatch-requested"))
            with mock.patch.object(coordinator, "_verify_run_identity", return_value={"status": "completed"}), \
                    mock.patch.object(coordinator, "_verify_dispatch_log", side_effect=coordinator.Refusal("run-wave-binding")), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(coordinator.Refusal, "run-wave-binding"):
                    coordinator.transition(ledger, "wave-test-0001", "attach-run", "54321")
            record = coordinator._read(path)
            self.assertIsNone(record["run_id"])
            self.assertIsNone(record["authorized_run_id"])

    def test_ambiguous_dispatch_uses_complete_paged_inventory_and_never_picks_one(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._new_ledger(temporary)
            record = _ledger_record(state="dispatch-requested")
            record["dispatch_requested_at"] = coordinator._timestamp()
            _write_record(ledger, record)
            def run(identifier):
                return {
                    "id": identifier, "path": coordinator.fetch.WORKFLOW_PATH,
                    "head_branch": "main", "head_sha": CONTROL_SHA,
                    "event": "workflow_dispatch", "run_attempt": 1,
                }
            pages = [
                {"total_count": 2, "workflow_runs": [run(54321)]},
                {"total_count": 2, "workflow_runs": [run(54322)]},
            ]
            result = type("Result", (), {"returncode": 0, "stdout": json.dumps(pages).encode()})()
            with mock.patch.object(coordinator.subprocess, "run", return_value=result) as command, \
                    mock.patch.object(coordinator, "_verify_dispatch_log"), \
                    mock.patch.object(coordinator, "transition") as transition, \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(coordinator.Refusal, "dispatch-multiple-matches"):
                    coordinator.reconcile_dispatch(ledger, "wave-test-0001")
            self.assertIn("--paginate", command.call_args.args[0])
            transition.assert_not_called()
            self.assertIsNone(coordinator._read(ledger / "wave-test-0001.json")["run_id"])

    def test_dispatch_reconciliation_keeps_wrong_wave_run_pending(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._new_ledger(temporary)
            record = _ledger_record(state="dispatch-requested")
            record["dispatch_requested_at"] = coordinator._timestamp()
            _write_record(ledger, record)
            page = [{"total_count": 1, "workflow_runs": [{
                "id": 54321, "path": coordinator.fetch.WORKFLOW_PATH,
                "head_branch": "main", "head_sha": CONTROL_SHA,
                "event": "workflow_dispatch", "run_attempt": 1,
            }]}]
            result = type("Result", (), {"returncode": 0, "stdout": json.dumps(page).encode()})()
            with mock.patch.object(coordinator.subprocess, "run", return_value=result), \
                    mock.patch.object(coordinator, "_verify_dispatch_log",
                                      side_effect=coordinator.Refusal("run-wave-binding")), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertFalse(coordinator.reconcile_dispatch(ledger, "wave-test-0001"))
            self.assertEqual(coordinator._read(ledger / "wave-test-0001.json")["state"], "dispatch-requested")
            with self.assertRaisesRegex(coordinator.Refusal, "wave-id"):
                coordinator.reconcile_dispatch(ledger, "../outside")

    def test_successful_cleanup_revokes_secret_first_and_closes_only_after_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._new_ledger(temporary)
            record = _ledger_record()
            record["cleanup_obligations"]["secret"] = {"state": "not-installed"}
            record["cleanup_obligations"]["bundle_asset"] = {"state": "not-uploaded"}
            record["cleanup_obligations"]["projection_asset"] = {"state": "not-uploaded"}
            _write_record(ledger, record)
            calls = []

            def status(endpoint):
                calls.append(("status", endpoint))
                return 404

            with mock.patch.object(coordinator, "_gh_status", side_effect=status), \
                    contextlib.redirect_stdout(io.StringIO()):
                coordinator.cleanup_terminal(ledger, "wave-test-0001")
            updated = coordinator._read(ledger / "wave-test-0001.json")
            self.assertEqual(updated["state"], "deleted")
            self.assertTrue(calls[0][1].endswith("/environments/devlane-decrypt/secrets/DEVLANE_DECRYPT_KEY"))

    def test_refused_secret_delete_does_not_skip_asset_deletions_or_close_wave(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._new_ledger(temporary)
            record = _ledger_record()
            _write_record(ledger, record)
            assets = [
                {"id": 111, "name": record["bundle_asset_name"], "size": 1024, "state": "uploaded", "digest": "sha256:" + BUNDLE_SHA},
                {"id": 222, "name": record["projection_asset_name"], "size": 512, "state": "uploaded", "digest": "sha256:" + PROJECTION_SHA},
            ]
            attempts = []

            def status(endpoint):
                if endpoint.endswith("/environments/devlane-decrypt/secrets/DEVLANE_DECRYPT_KEY"):
                    return 200
                if endpoint.endswith("/releases/assets/111"):
                    return 200
                return 404

            def delete(endpoint):
                attempts.append(endpoint)
                if endpoint.endswith("/environments/devlane-decrypt/secrets/DEVLANE_DECRYPT_KEY") or endpoint.endswith("/releases/assets/111"):
                    raise coordinator.Refusal("github-delete-failed")

            with mock.patch.object(coordinator, "_gh_status", side_effect=status), \
                    mock.patch.object(coordinator, "_gh_delete", side_effect=delete), \
                    mock.patch.object(coordinator, "_release_assets", return_value=assets), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(coordinator.Refusal, "cleanup-incomplete"):
                    coordinator.cleanup_terminal(ledger, "wave-test-0001")
            updated = coordinator._read(ledger / "wave-test-0001.json")
            self.assertNotEqual(updated["state"], "deleted")
            self.assertIn("/releases/assets/111", " ".join(attempts))
            self.assertIn("/releases/assets/222", " ".join(attempts))
            self.assertNotEqual(updated["cleanup_obligations"]["secret"]["state"], "absent")

    def test_interrupted_delete_is_resumed_after_process_lock_is_released(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._new_ledger(temporary)
            record = _ledger_record()
            record["cleanup_obligations"]["secret"] = {"state": "absent"}
            record["cleanup_obligations"]["projection_asset"] = {"state": "not-uploaded"}
            _write_record(ledger, record)
            assets = [{"id": 111, "name": record["bundle_asset_name"], "size": 1024,
                       "state": "uploaded", "digest": "sha256:" + BUNDLE_SHA}]

            def interrupted_delete(endpoint):
                assets.clear()
                raise KeyboardInterrupt()

            with mock.patch.object(coordinator, "_gh_status", return_value=404), \
                    mock.patch.object(coordinator, "_release_assets", side_effect=lambda _release: list(assets)), \
                    mock.patch.object(coordinator, "_gh_delete", side_effect=interrupted_delete), \
                    contextlib.redirect_stdout(io.StringIO()):
                with self.assertRaises(KeyboardInterrupt):
                    coordinator.cleanup_terminal(ledger, "wave-test-0001")
                interrupted = coordinator._read(ledger / "wave-test-0001.json")
                self.assertEqual(interrupted["cleanup_obligations"]["bundle_asset"]["state"], "delete-pending")
                coordinator.cleanup_terminal(ledger, "wave-test-0001")
            updated = coordinator._read(ledger / "wave-test-0001.json")
            self.assertEqual(updated["state"], "deleted")

    def test_intent_bounds_and_private_ledger_modes_are_enforced(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._new_ledger(temporary)
            bad = _request()
            bad["expires"] = int(time.time()) + 7200
            with self.assertRaisesRegex(coordinator.Refusal, "reservation-bounds"):
                coordinator.reserve_wave(ledger, bad)
            self.assertEqual(ledger.stat().st_mode & 0o777, 0o700)
            with self.assertRaises(bundle.Refusal):
                bundle.strict_json(b'{"schema":1,"schema":1}')


def _attached_record(state="run-attached", run_id="54321"):
    record = _ledger_record(state=state)
    record["dispatch_requested_at"] = coordinator._timestamp()
    record.update({"run_id": run_id, "authorized_run_id": run_id, "run_attempt": 1})
    record["cleanup_obligations"].update({
        "secret": {"state": "absent"},
        "bundle_asset": {"state": "absent"}, "projection_asset": {"state": "absent"},
        "run": {"state": "present", "run_id": run_id},
        "logs": {"state": "present", "run_id": run_id},
        "artifacts": {"state": "inventory-pending", "run_id": run_id},
    })
    return record


class RunLifecycleTests(unittest.TestCase):
    def _ledger(self, temporary):
        return CoordinatorLedgerAcceptanceTests()._new_ledger(temporary)

    def _cleanup(self, ledger, *, status, delete=None, identity=True, artifacts=(), disposition="accepted"):
        stack = contextlib.ExitStack()
        stack.enter_context(mock.patch.object(coordinator, "_gh_status", side_effect=status))
        stack.enter_context(mock.patch.object(coordinator, "_gh_delete", side_effect=delete or (lambda endpoint: None)))
        stack.enter_context(mock.patch.object(coordinator, "_release_assets", return_value=[]))
        stack.enter_context(mock.patch.object(coordinator, "_artifact_ids", return_value=list(artifacts)))
        stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
        if identity:
            stack.enter_context(mock.patch.object(coordinator, "_verify_terminal", return_value={"conclusion": "success"}))
            stack.enter_context(mock.patch.object(coordinator, "_verify_run_identity", return_value={"conclusion": "success"}))
            stack.enter_context(mock.patch.object(coordinator, "_verify_wave_marker"))
            stack.enter_context(mock.patch.object(coordinator, "_terminal_audit_disposition", return_value=disposition))
        return stack

    def test_run_deleted_but_ledger_stale_is_reconciled_from_absence(self):
        """Fails on the old code: the 404 run made identity validation fail and logs, artifacts and run stayed delete-pending forever (reproduced as cleanup-incomplete)."""
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._ledger(temporary)
            record = _attached_record(state="run-delete-pending")
            record["cleanup_obligations"]["run"] = {
                "state": "delete-pending", "run_id": "54321",
                "identity_verified": {"run_id": "54321", "run_attempt": 1, "wave_id": record["wave_id"],
                                      "bundle_id": record["bundle_id"], "control_sha": CONTROL_SHA},
            }
            record["cleanup_obligations"]["logs"] = {"state": "delete-pending", "run_id": "54321"}
            record["cleanup_obligations"]["artifacts"] = {"state": "delete-pending", "run_id": "54321"}
            _write_record(ledger, record)
            with mock.patch.object(coordinator, "_gh_status", return_value=404), \
                    mock.patch.object(coordinator, "_release_assets", return_value=[]), \
                    mock.patch.object(coordinator, "_verify_terminal",
                                      side_effect=coordinator.Refusal("run-identity-mismatch")), \
                    contextlib.redirect_stdout(io.StringIO()):
                coordinator.cleanup_terminal(ledger, "wave-test-0001")
            updated = coordinator._read(ledger / "wave-test-0001.json")
            self.assertEqual(updated["state"], "deleted")
            for name in ("secret", "logs", "artifacts", "run"):
                self.assertEqual(updated["cleanup_obligations"][name]["state"], "absent", name)

    def test_every_run_delete_response_and_write_boundary_is_recoverable(self):
        run_endpoint = "/actions/runs/54321"
        for label in ("response-lost-but-deleted", "delete-fails-then-retry", "crash-after-delete-before-write"):
            with self.subTest(label), tempfile.TemporaryDirectory() as temporary:
                ledger = self._ledger(temporary)
                _write_record(ledger, _attached_record())
                state = {"run_present": True, "deletes": 0}

                def status(endpoint):
                    if endpoint.endswith(run_endpoint) or run_endpoint + "/" in endpoint:
                        return 200 if state["run_present"] else 404
                    return 404

                def delete(endpoint):
                    if endpoint.endswith(run_endpoint):
                        state["deletes"] += 1
                        if label == "response-lost-but-deleted":
                            state["run_present"] = False
                            raise coordinator.Refusal("github-delete-failed")
                        if label == "delete-fails-then-retry" and state["deletes"] == 1:
                            raise coordinator.Refusal("github-delete-failed")
                        state["run_present"] = False
                        if label == "crash-after-delete-before-write":
                            raise KeyboardInterrupt()

                with self._cleanup(ledger, status=status, delete=delete):
                    if label == "delete-fails-then-retry":
                        with self.assertRaisesRegex(coordinator.Refusal, "cleanup-incomplete"):
                            coordinator.cleanup_terminal(ledger, "wave-test-0001")
                        self.assertEqual(coordinator._read(ledger / "wave-test-0001.json")["state"],
                                         "run-delete-pending")
                    elif label == "crash-after-delete-before-write":
                        with self.assertRaises(KeyboardInterrupt):
                            coordinator.cleanup_terminal(ledger, "wave-test-0001")
                        self.assertNotEqual(coordinator._read(ledger / "wave-test-0001.json")["state"], "deleted")
                    if label != "response-lost-but-deleted":
                        coordinator.cleanup_terminal(ledger, "wave-test-0001")
                    else:
                        coordinator.cleanup_terminal(ledger, "wave-test-0001")
                updated = coordinator._read(ledger / "wave-test-0001.json")
                self.assertEqual(updated["state"], "deleted")
                self.assertEqual(updated["cleanup_obligations"]["run"]["state"], "absent")

    def test_run_delete_is_attempted_even_when_log_and_artifact_deletion_fail(self):
        """Fails on the old code, which refused the run DELETE with run-delete-prerequisite."""
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._ledger(temporary)
            _write_record(ledger, _attached_record())
            present = {"run": True}
            deleted = []

            def status(endpoint):
                if "/actions/runs/54321" in endpoint:
                    return 200 if present["run"] else 404
                return 404

            def delete(endpoint):
                deleted.append(endpoint)
                if endpoint.endswith("/logs") or "/actions/artifacts/" in endpoint:
                    raise coordinator.Refusal("github-delete-failed")
                if endpoint.endswith("/actions/runs/54321"):
                    present["run"] = False

            with self._cleanup(ledger, status=status, delete=delete, artifacts=[9001]):
                coordinator.cleanup_terminal(ledger, "wave-test-0001")
            self.assertTrue(any(item.endswith("/actions/runs/54321") for item in deleted))
            updated = coordinator._read(ledger / "wave-test-0001.json")
            self.assertEqual(updated["state"], "deleted")
            self.assertEqual(updated["cleanup_obligations"]["logs"]["state"], "absent")
            self.assertEqual(updated["cleanup_obligations"]["artifacts"]["state"], "absent")

    def test_terminal_marking_revokes_the_secret_before_any_public_surface_is_collected(self):
        """Fails on the old code: audit and log collection ran while the secret was installed."""
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._ledger(temporary)
            _write_record(ledger, _attached_record())
            order = []
            with mock.patch.object(coordinator, "_revoke_secret", side_effect=lambda: order.append("revoke")), \
                    mock.patch.object(coordinator, "_verify_terminal",
                                      side_effect=lambda *a: order.append("verify") or {"conclusion": "success"}), \
                    mock.patch.object(coordinator, "_verify_wave_marker",
                                      side_effect=lambda *a, **k: order.append("marker")), \
                    mock.patch.object(coordinator, "_terminal_audit_disposition",
                                      side_effect=lambda *a, **k: order.append("audit") or "accepted"), \
                    contextlib.redirect_stdout(io.StringIO()):
                coordinator.transition(ledger, "wave-test-0001", "mark-terminal")
            self.assertEqual(order, ["revoke", "verify", "marker", "audit"])
            record = coordinator._read(ledger / "wave-test-0001.json")
            self.assertEqual(record["state"], "terminal")
            self.assertEqual(record["cleanup_obligations"]["secret"]["state"], "absent")

    def test_failed_revocation_blocks_terminal_marking_and_is_resumable(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._ledger(temporary)
            _write_record(ledger, _attached_record())
            with mock.patch.object(coordinator, "_revoke_secret", side_effect=coordinator.Refusal("secret-state-ambiguous")), \
                    mock.patch.object(coordinator, "_terminal_audit_disposition") as audit:
                with self.assertRaisesRegex(coordinator.Refusal, "secret-state-ambiguous"):
                    coordinator.transition(ledger, "wave-test-0001", "mark-terminal")
                audit.assert_not_called()
            record = coordinator._read(ledger / "wave-test-0001.json")
            self.assertEqual(record["state"], "run-attached")
            self.assertEqual(record["cleanup_obligations"]["secret"]["state"], "secret-delete-pending")
            with mock.patch.object(coordinator, "_revoke_secret"), contextlib.redirect_stdout(io.StringIO()):
                coordinator.revoke_secret(ledger, "wave-test-0001")
            self.assertEqual(coordinator._read(ledger / "wave-test-0001.json")["cleanup_obligations"]["secret"]["state"],
                             "absent")

    def test_secret_install_is_verified_against_environment_secret_metadata(self):
        """The key lives only in the restricted environment; a repository-wide copy refuses."""
        documented = {"name": "DEVLANE_DECRYPT_KEY", "created_at": "2026-11-10T00:00:00Z",
                      "updated_at": "2026-11-10T00:00:00Z"}
        seen = []

        def json_of(endpoint):
            seen.append(endpoint)
            return documented

        with mock.patch.object(coordinator, "_gh_json", side_effect=json_of), \
                mock.patch.object(coordinator, "_gh_status", return_value=404) as status:
            self.assertTrue(coordinator._verify_secret_present().endswith("/environments/devlane-decrypt/secrets/DEVLANE_DECRYPT_KEY"))
        self.assertEqual(seen, ["repos/keeldock-platform/platform-ci/environments/devlane-decrypt/secrets/DEVLANE_DECRYPT_KEY"])
        self.assertTrue(status.call_args_list[0].args[0].endswith("/actions/secrets/DEVLANE_DECRYPT_KEY"))
        for broken in ({**documented, "name": "OTHER"}, {"name": "DEVLANE_DECRYPT_KEY"}, [], None):
            with self.subTest(broken=broken), mock.patch.object(coordinator, "_gh_json", return_value=broken), \
                    mock.patch.object(coordinator, "_gh_status", return_value=404), \
                    self.assertRaisesRegex(coordinator.Refusal, "secret-install-unverified"):
                coordinator._verify_secret_present()
        with mock.patch.object(coordinator, "_gh_json", return_value=documented), \
                mock.patch.object(coordinator, "_gh_status", return_value=200), \
                self.assertRaisesRegex(coordinator.Refusal, "secret-repository-scope"):
            coordinator._verify_secret_present()

    def test_environment_must_exist_and_admit_only_main_before_the_key_is_installed(self):
        base = "repos/keeldock-platform/platform-ci/environments/devlane-decrypt"
        good_environment = {"name": "devlane-decrypt", "can_admins_bypass": False,
                            "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True}}
        good_policies = {"total_count": 1, "branch_policies": [{"id": 1, "name": "main", "type": "branch"}]}

        def serve(environment, policies):
            return lambda endpoint: environment if endpoint == base else policies if endpoint == base + "/deployment-branch-policies" else self.fail(endpoint)

        with mock.patch.object(coordinator, "_gh_json", side_effect=serve(good_environment, good_policies)):
            coordinator._verify_environment()
        broken = (
            (dict(good_environment, name="other"), good_policies),
            (dict(good_environment, can_admins_bypass=True), good_policies),
            ({k: v for k, v in good_environment.items() if k != "can_admins_bypass"}, good_policies),
            ({"name": "devlane-decrypt", "deployment_branch_policy": None}, good_policies),
            ({"name": "devlane-decrypt", "deployment_branch_policy": {"protected_branches": True, "custom_branch_policies": False}}, good_policies),
            (good_environment, {"total_count": 0, "branch_policies": []}),
            (good_environment, {"total_count": 2, "branch_policies": [
                {"name": "main", "type": "branch"}, {"name": "develop", "type": "branch"}]}),
            (good_environment, {"total_count": 1, "branch_policies": [{"name": "develop", "type": "branch"}]}),
            (good_environment, {"total_count": 1, "branch_policies": [{"name": "main", "type": "tag"}]}),
            (good_environment, {"total_count": 1, "branch_policies": [{"name": "*", "type": "branch"}]}),
            (good_environment, []),
            (None, None),
        )
        for environment, policies in broken:
            with self.subTest(environment=environment, policies=policies), \
                    mock.patch.object(coordinator, "_gh_json", side_effect=serve(environment, policies)), \
                    self.assertRaisesRegex(coordinator.Refusal, "environment-unrestricted"):
                coordinator._verify_environment()

    def test_marking_the_install_refuses_an_unrestricted_environment_and_changes_nothing(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._ledger(temporary)
            record = _ledger_record(state="assets-attached")
            _write_record(ledger, record)
            with mock.patch.object(coordinator, "_verify_environment",
                                   side_effect=coordinator.Refusal("environment-unrestricted")), \
                    self.assertRaisesRegex(coordinator.Refusal, "environment-unrestricted"):
                coordinator.transition(ledger, "wave-test-0001", "mark-secret-installing")
            self.assertEqual(coordinator._read(ledger / "wave-test-0001.json")["state"], "assets-attached")
            with mock.patch.object(coordinator, "_verify_environment"), contextlib.redirect_stdout(io.StringIO()):
                coordinator.transition(ledger, "wave-test-0001", "mark-secret-installing")
            self.assertEqual(coordinator._read(ledger / "wave-test-0001.json")["state"], "secret-installing")

    def test_marking_the_install_complete_repeats_the_environment_check(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._ledger(temporary)
            _write_record(ledger, _ledger_record(state="secret-installing"))
            with mock.patch.object(coordinator, "_verify_environment",
                                   side_effect=coordinator.Refusal("environment-unrestricted")) as verify, \
                    mock.patch.object(coordinator, "_verify_secret_present") as present, \
                    self.assertRaisesRegex(coordinator.Refusal, "environment-unrestricted"):
                coordinator.transition(ledger, "wave-test-0001", "mark-secret-installed")
            verify.assert_called_once()
            present.assert_not_called()
            self.assertEqual(coordinator._read(ledger / "wave-test-0001.json")["state"], "secret-installing")

    def test_absence_and_revocation_cover_the_environment_secret_and_any_repository_wide_copy(self):
        env, repo = "/environments/devlane-decrypt/secrets/DEVLANE_DECRYPT_KEY", "/actions/secrets/DEVLANE_DECRYPT_KEY"
        with mock.patch.object(coordinator, "_gh_status", return_value=404) as status:
            coordinator._verify_secret_absent()
        self.assertEqual([call.args[0].endswith(env) for call in status.call_args_list], [True, False])
        for present in (env, repo):
            with self.subTest(present=present), mock.patch.object(
                    coordinator, "_gh_status", side_effect=lambda endpoint, present=present: 200 if endpoint.endswith(present) else 404), \
                    self.assertRaisesRegex(coordinator.Refusal, "secret-already-installed"):
                coordinator._verify_secret_absent()
        live = {env: True, repo: True}

        def status_of(endpoint):
            for suffix, present in live.items():
                if endpoint.endswith(suffix):
                    return 200 if present else 404
            raise AssertionError(endpoint)

        def delete(endpoint):
            for suffix in live:
                if endpoint.endswith(suffix):
                    live[suffix] = False

        with mock.patch.object(coordinator, "_gh_status", side_effect=status_of), \
                mock.patch.object(coordinator, "_gh_delete", side_effect=delete):
            coordinator._revoke_secret()
        self.assertEqual(live, {env: False, repo: False})
        with mock.patch.object(coordinator, "_gh_status", return_value=500), \
                self.assertRaisesRegex(coordinator.Refusal, "secret-state-ambiguous"):
            coordinator._revoke_secret()

    def test_installation_never_targets_the_repository_wide_secret_endpoint(self):
        source = Path(coordinator.__file__).read_text(encoding="utf-8")
        self.assertEqual(source.count("_repository_secret_endpoint()"), 4)
        self.assertNotIn('"PUT"', source)
        self.assertNotIn("--method PUT", source)
        self.assertEqual(coordinator.DECRYPT_ENVIRONMENT, "devlane-decrypt")

    def test_reconciliation_can_attach_a_run_found_during_cleanup_recovery(self):
        """Fails on the old code: attach-run only accepted dispatch-requested."""
        for state in ("cleanup-failed", "cleanup-in-progress"):
            with self.subTest(state), tempfile.TemporaryDirectory() as temporary:
                ledger = self._ledger(temporary)
                record = _ledger_record(state=state)
                record["dispatch_requested_at"] = coordinator._timestamp()
                record["cleanup_obligations"]["run"] = {"state": "dispatch-ambiguous"}
                _write_record(ledger, record)
                with mock.patch.object(coordinator, "_verify_run_identity", return_value={"status": "completed"}), \
                        mock.patch.object(coordinator, "_verify_run_binding"), \
                        contextlib.redirect_stdout(io.StringIO()):
                    coordinator.transition(ledger, "wave-test-0001", "attach-run", "54321")
                updated = coordinator._read(ledger / "wave-test-0001.json")
                self.assertEqual(updated["state"], state)
                self.assertEqual(updated["authorized_run_id"], "54321")
                self.assertEqual(updated["cleanup_obligations"]["run"]["state"], "present")
                with self.assertRaisesRegex(coordinator.Refusal, "ledger-transition"), \
                        mock.patch.object(coordinator, "_verify_run_identity", return_value={"status": "completed"}), \
                        mock.patch.object(coordinator, "_verify_run_binding"):
                    coordinator.transition(ledger, "wave-test-0001", "attach-run", "54322")

    def test_run_that_failed_before_the_marker_binds_through_its_dispatch_title(self):
        record = _ledger_record(state="dispatch-requested")
        title = coordinator.expected_run_title(record)
        self.assertEqual(title, "devlane wave=wave-test-0001 bundle=bundle-test-0001")
        with mock.patch.object(coordinator, "_verify_dispatch_log",
                               side_effect=coordinator.Refusal("run-wave-binding")) as marker:
            self.assertEqual(coordinator._verify_run_binding("54321", record, {"display_title": title}), "title")
            marker.assert_not_called()
            for wrong in ({"display_title": title + " "}, {"display_title": "devlane wave=other bundle=x"}, {}, None):
                with self.subTest(run=wrong), self.assertRaisesRegex(coordinator.Refusal, "run-wave-binding"):
                    coordinator._verify_run_binding("54321", record, wrong)
        with mock.patch.object(coordinator, "_verify_dispatch_log") as marker:
            self.assertEqual(coordinator._verify_run_binding("54321", record, {"display_title": "x"}), "marker")
            marker.assert_called_once()

    def test_pending_reconciliation_exits_distinctly_from_attached(self):
        with mock.patch.object(coordinator, "reconcile_dispatch", return_value=False):
            self.assertEqual(coordinator.main(["reconcile-dispatch", "--ledger", "x", "--wave-id", "wave-test-0001"]), 3)
        with mock.patch.object(coordinator, "reconcile_dispatch", return_value=True):
            self.assertEqual(coordinator.main(["reconcile-dispatch", "--ledger", "x", "--wave-id", "wave-test-0001"]), 0)

    def test_validated_diagnostics_are_preserved_privately_before_deletion_or_deletion_is_held(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._ledger(temporary)
            record = _attached_record()
            name = coordinator._preserve_diagnostics(ledger, record, [b'{"kind":"control","stage":"unit","status":"fail"}'])
            target = ledger / name
            self.assertEqual(name, "diagnostics-wave-test-0001.jsonl")
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(target.read_bytes(), b'{"kind":"control","stage":"unit","status":"fail"}\n')
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._ledger(temporary)
            _write_record(ledger, _attached_record())
            deleted = []
            with self._cleanup(ledger, status=lambda endpoint: 200 if "/actions/runs/54321" in endpoint else 404,
                               delete=deleted.append, disposition="preserve-failed"):
                with self.assertRaisesRegex(coordinator.Refusal, "cleanup-incomplete"):
                    coordinator.cleanup_terminal(ledger, "wave-test-0001")
            self.assertFalse(any("/actions/runs/54321" in item for item in deleted))
            self.assertNotEqual(coordinator._read(ledger / "wave-test-0001.json")["state"], "deleted")


class TimedRevocationTests(unittest.TestCase):
    """Revoke as soon as Decrypt authenticated bundle concludes: mandatory, timed, and never skipped."""

    @staticmethod
    def _jobs(step_status, job_status="in_progress", step_done="2026-11-10T12:00:10Z"):
        step = {"name": "Decrypt authenticated bundle", "status": step_status}
        if step_status == "completed":
            step["completed_at"] = step_done
        return {"jobs": [{"name": "devlane-encrypted-run", "status": job_status,
                          "completed_at": "2026-11-10T12:30:00Z", "steps": [
                              {"name": "Probe isolation before decryption", "status": "completed"}, step]}]}

    def _attached(self, temporary):
        ledger = CoordinatorLedgerAcceptanceTests()._new_ledger(temporary)
        record = _ledger_record(state="run-attached")
        record["run_id"] = record["authorized_run_id"] = "54321"
        record["run_attempt"] = 1
        _write_record(ledger, record)
        return ledger

    def _await(self, ledger, responses, clock_values, timeout_seconds=7200, revoke_args=None):
        revoke_args = revoke_args or {}
        calls, naps = [], []
        times = iter(clock_values)

        def serve(endpoint):
            calls.append(endpoint)
            item = responses.pop(0) if len(responses) > 1 else responses[0]
            if isinstance(item, BaseException):
                raise item
            return item

        with mock.patch.object(coordinator, "_gh_json", side_effect=serve), \
                mock.patch.object(coordinator, "revoke_secret", **revoke_args) as revoke, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            result = coordinator.await_decrypt_and_revoke(
                ledger, "wave-test-0001", 2, timeout_seconds, sleep=naps.append, clock=lambda: next(times))
        return result, revoke, calls, naps, output.getvalue()

    def test_key_is_revoked_only_after_the_decrypt_step_concludes_and_the_latency_is_reported(self):
        concluded = _epoch_of("2026-11-10T12:00:10Z")
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._attached(temporary)
            responses = [self._jobs("queued"), self._jobs("in_progress"), self._jobs("completed")]
            result, revoke, calls, naps, output = self._await(ledger, responses, [0, 0, 0, concluded + 7])
            self.assertTrue(result)
            revoke.assert_called_once()
            self.assertEqual(len(calls), 3)
            self.assertEqual(naps, [2, 2])
            self.assertIn("revoke_latency_seconds=7 limit=120 within_limit=true timed_out=false", output)
            self.assertTrue(all("/actions/runs/54321/jobs" in call for call in calls))

    def test_a_late_revocation_is_reported_as_outside_the_limit_not_hidden(self):
        concluded = _epoch_of("2026-11-10T12:00:10Z")
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._attached(temporary)
            result, revoke, _, _, output = self._await(ledger, [self._jobs("completed")], [0, concluded + 400])
            self.assertFalse(result)
            revoke.assert_called_once()
            self.assertIn("revoke_latency_seconds=400 limit=120 within_limit=false", output)

    def test_a_run_that_ends_before_decrypt_still_gets_its_key_revoked(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._attached(temporary)
            response = self._jobs("queued", job_status="completed")
            result, revoke, _, _, _ = self._await(ledger, [response], [0, _epoch_of("2026-11-10T12:30:05Z")])
            self.assertTrue(result)
            revoke.assert_called_once()

    def test_timeout_revokes_anyway_and_never_reports_success(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._attached(temporary)
            result, revoke, _, _, output = self._await(
                ledger, [self._jobs("in_progress")], [0, 10, 70, 80], timeout_seconds=60)
            self.assertFalse(result)
            revoke.assert_called_once()
            self.assertIn("timed_out=true", output)

    def test_a_transient_poll_error_is_retried_and_the_key_is_still_revoked_in_time(self):
        concluded = _epoch_of("2026-11-10T12:00:10Z")
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._attached(temporary)
            responses = [coordinator.Refusal("github-api-unavailable"), {"jobs": [{"name": "devlane-encrypted-run", "steps": None}]},
                         self._jobs("completed")]
            result, revoke, calls, naps, output = self._await(ledger, responses, [0, 0, 0, 0, concluded + 5])
            self.assertTrue(result)
            revoke.assert_called_once()
            self.assertEqual(len(calls), 3)
            self.assertEqual(naps, [2, 2])
            self.assertIn("within_limit=true timed_out=false poll_failed=false", output)

    def test_a_poll_that_keeps_failing_still_revokes_then_reports_late_not_a_crash(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._attached(temporary)
            result, revoke, _, _, output = self._await(
                ledger, [coordinator.Refusal("github-api-unavailable")], [0, 10, 70, 80], timeout_seconds=60)
            self.assertFalse(result)
            revoke.assert_called_once()
            self.assertIn("within_limit=false timed_out=true poll_failed=true", output)

    def test_an_interruption_during_the_poll_still_runs_the_revocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._attached(temporary)
            calls = []
            with mock.patch.object(coordinator, "_decrypt_conclusion", side_effect=KeyboardInterrupt), \
                    mock.patch.object(coordinator, "revoke_secret", side_effect=lambda *a: calls.append(a)), \
                    self.assertRaises(KeyboardInterrupt):
                coordinator.await_decrypt_and_revoke(ledger, "wave-test-0001", 2, 7200, sleep=lambda s: None, clock=lambda: 0)
            self.assertEqual(len(calls), 1)

    def test_a_failed_revocation_is_exit_two_and_a_late_one_after_poll_failure_is_exit_three(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = self._attached(temporary)
            with self.assertRaisesRegex(coordinator.Refusal, "secret-state-ambiguous"):
                self._await(ledger, [self._jobs("completed")], [0, 0],
                            revoke_args={"side_effect": coordinator.Refusal("secret-state-ambiguous")})
        with mock.patch.object(coordinator, "await_decrypt_and_revoke",
                               side_effect=coordinator.Refusal("secret-state-ambiguous")), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(coordinator.main(["await-decrypt-and-revoke", "--ledger", "x", "--wave-id", "wave-test-0001"]), 2)

    def test_only_an_attached_run_can_be_awaited(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = CoordinatorLedgerAcceptanceTests()._new_ledger(temporary)
            _write_record(ledger, _ledger_record(state="dispatch-requested"))
            with mock.patch.object(coordinator, "_gh_json") as gh, \
                    self.assertRaisesRegex(coordinator.Refusal, "revoke-await-state"):
                coordinator.await_decrypt_and_revoke(ledger, "wave-test-0001")
            gh.assert_not_called()

    def test_command_line_exit_codes_distinguish_in_time_from_late(self):
        for within, expected in ((True, 0), (False, 3)):
            with mock.patch.object(coordinator, "await_decrypt_and_revoke", return_value=within):
                self.assertEqual(coordinator.main(["await-decrypt-and-revoke", "--ledger", "x", "--wave-id",
                                                   "wave-test-0001"]), expected)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(coordinator.main(["await-decrypt-and-revoke", "--ledger", "x", "--wave-id",
                                               "wave-test-0001", "--timeout-seconds", "5"]), 2)
        self.assertEqual(coordinator.MAX_REVOKE_LATENCY_SECONDS, 120)


def _epoch_of(value):
    return coordinator._epoch(value)


class OwnerSequenceTests(unittest.TestCase):
    """The complete owner sequence against an in-memory GitHub, including a run that failed
    before it could print the in-run marker."""

    def test_whole_sequence_with_a_pre_marker_failure_ends_with_everything_verified_absent(self):
        with tempfile.TemporaryDirectory() as temporary:
            ledger = CoordinatorLedgerAcceptanceTests()._new_ledger(temporary)
            wave, bundle_id = "wave-test-0001", "bundle-test-0001"
            title = "devlane wave=%s bundle=%s" % (wave, bundle_id)
            github = {"secret": False, "run": False, "logs": True, "assets": {}, "artifacts": [4001]}
            record_names = {
                "bundle": "devlane-%s-%s.enc" % (wave, bundle_id),
                "projection": "devlane-%s-%s.projection.json" % (wave, bundle_id),
            }

            def run_record(status="completed"):
                return {"id": 54321, "path": coordinator.fetch.WORKFLOW_PATH, "event": "workflow_dispatch",
                        "run_attempt": 1, "head_branch": "main", "head_sha": CONTROL_SHA, "status": status,
                        "conclusion": "failure", "display_title": title,
                        "repository": {"full_name": coordinator.fetch.REPOSITORY,
                                       "id": int(coordinator.fetch.REPOSITORY_ID)}}

            def status(endpoint):
                if endpoint.endswith("/environments/devlane-decrypt/secrets/DEVLANE_DECRYPT_KEY"):
                    return 200 if github["secret"] else 404
                if endpoint.endswith("/actions/secrets/DEVLANE_DECRYPT_KEY"):
                    return 404
                if endpoint.endswith("/actions/runs/54321/logs"):
                    return 200 if github["run"] and github["logs"] else 404
                if "/actions/runs/54321" in endpoint:
                    return 200 if github["run"] else 404
                if "/actions/artifacts/" in endpoint:
                    return 200 if github["artifacts"] else 404
                if "/releases/assets/" in endpoint:
                    return 200 if int(endpoint.rsplit("/", 1)[1]) in github["assets"] else 404
                return 404

            def gh_json(endpoint):
                if endpoint.endswith("/environments/devlane-decrypt"):
                    return {"name": "devlane-decrypt", "can_admins_bypass": False, "deployment_branch_policy": {
                        "protected_branches": False, "custom_branch_policies": True}}
                if endpoint.endswith("/environments/devlane-decrypt/deployment-branch-policies"):
                    return {"total_count": 1, "branch_policies": [{"id": 7, "name": "main", "type": "branch"}]}
                if endpoint.endswith("/environments/devlane-decrypt/secrets/DEVLANE_DECRYPT_KEY"):
                    return {"name": "DEVLANE_DECRYPT_KEY", "created_at": "2026-11-10T00:00:00Z",
                            "updated_at": "2026-11-10T00:00:00Z"}
                if endpoint.endswith("/actions/runs/54321"):
                    return run_record()
                if "/releases/assets/" in endpoint:
                    identifier = endpoint.rsplit("/", 1)[1]
                    return github["assets"][int(identifier)]
                raise AssertionError(endpoint)

            def delete(endpoint):
                if endpoint.endswith("/environments/devlane-decrypt/secrets/DEVLANE_DECRYPT_KEY"):
                    github["secret"] = False
                elif endpoint.endswith("/actions/runs/54321"):
                    github["run"] = False
                elif endpoint.endswith("/logs"):
                    github["logs"] = False
                elif "/releases/assets/" in endpoint:
                    github["assets"].pop(int(endpoint.rsplit("/", 1)[1]), None)
                elif "/actions/artifacts/" in endpoint:
                    github["artifacts"] = []

            patches = [
                mock.patch.object(coordinator, "_gh_status", side_effect=status),
                mock.patch.object(coordinator, "_gh_json", side_effect=gh_json),
                mock.patch.object(coordinator, "_gh_delete", side_effect=delete),
                mock.patch.object(coordinator, "_release_assets", side_effect=lambda _release: list(github["assets"].values())),
                mock.patch.object(coordinator, "_artifact_ids", side_effect=lambda _run: list(github["artifacts"])),
                mock.patch.object(coordinator, "_cache_records", return_value=[]),
                mock.patch.object(coordinator, "cache_inventory_digest", return_value=CACHE_SHA),
                mock.patch.object(coordinator, "_cli_token", return_value="x"),
                mock.patch.object(coordinator.public_audit, "validate_final_public_surfaces",
                                  side_effect=coordinator.public_audit.AuditRefusal("audit-contract")),
                mock.patch.object(coordinator, "_workflow_run_pages", side_effect=lambda _endpoint: [run_record()]),
                mock.patch.object(coordinator, "_run_log_bundle", side_effect=coordinator.Refusal("run-logs-unavailable")),
            ]
            with contextlib.ExitStack() as stack, contextlib.redirect_stdout(io.StringIO()):
                for patch in patches:
                    stack.enter_context(patch)
                request = _request(wave, bundle_id)
                with mock.patch.object(coordinator, "_verify_secret_absent"):
                    coordinator.reserve_wave(ledger, request)
                coordinator.stage_bundle(ledger, wave, {
                    "schema": 1, "bundle_sha256": BUNDLE_SHA, "bundle_size": 1024,
                    "projection_sha256": PROJECTION_SHA, "projection_size": 512})
                github["assets"] = {
                    111: {"id": 111, "name": record_names["bundle"], "size": 1024, "state": "uploaded",
                          "digest": "sha256:" + BUNDLE_SHA},
                    222: {"id": 222, "name": record_names["projection"], "size": 512, "state": "uploaded",
                          "digest": "sha256:" + PROJECTION_SHA},
                }
                coordinator.record_intent(ledger, {
                    "schema": 2, "wave_id": wave, "bundle_asset_id": "111", "projection_asset_id": "222",
                    "cache_baseline_sha256": CACHE_SHA})
                coordinator.transition(ledger, wave, "mark-secret-installing")
                github["secret"] = True
                coordinator.transition(ledger, wave, "mark-secret-installed")
                coordinator.transition(ledger, wave, "mark-dispatch-requested")
                github["run"] = True
                """The run failed before printing any marker: its dispatch title still binds it."""
                self.assertTrue(coordinator.reconcile_dispatch(ledger, wave))
                self.assertEqual(coordinator._read(ledger / (wave + ".json"))["state"], "run-attached")
                coordinator.revoke_secret(ledger, wave)
                self.assertFalse(github["secret"])
                coordinator.transition(ledger, wave, "mark-terminal")
                terminal = coordinator._read(ledger / (wave + ".json"))
                self.assertEqual(terminal["cleanup_attempts"][-1]["audit_disposition"], "refused")
                coordinator.cleanup_terminal(ledger, wave)
            final = coordinator._read(ledger / (wave + ".json"))
            self.assertEqual(final["state"], "deleted")
            self.assertEqual((github["secret"], github["run"], github["logs"], github["assets"], github["artifacts"]),
                             (False, False, False, {}, []))
            for name in ("secret", "bundle_asset", "projection_asset", "logs", "artifacts", "run"):
                self.assertEqual(final["cleanup_obligations"][name]["state"], "absent", name)


if __name__ == "__main__":
    unittest.main()
