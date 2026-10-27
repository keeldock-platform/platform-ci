"""Synthetic filesystem tests for the owner-side feedback lifecycle."""

import base64
import contextlib
import hashlib
import json
import os
import stat
import sys
import tempfile
import threading
import types
import unittest
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeoutError
from unittest import mock

import feedback_admin as subject
import feedback_request


NOW = 1_800_000_000
CI_REPOSITORY_ID = 987654321
ACTOR_LOGIN = "synthetic-reviewer"
RUN_ID = 24680
ARTIFACT_ID = 97531
SPKI = b"synthetic public key encoding" * 12
PRIVATE_KEY = b"synthetic private key fixture"
PLAINTEXT = b"synthetic reviewed payload\n"


def _fields(kind="lock", expiry=NOW + 3600):
    profile = feedback_request.PROFILE_BY_KIND[kind]
    return {
        "kind": kind,
        "repository_id": "1430959909",
        "source_sha": "d" * 40,
        "base_sha": "e" * 40,
        "control_sha": "f" * 40,
        "base_branch": "develop",
        "reviewed_diff_sha256": "1" * 64,
        "expiry": expiry,
    }


def _expectation():
    return {
        "root": {
            "name": "fixture-root",
            "version": "1.0.0",
            "workspaces": ["packages/*"],
            "devDependencies": {"typescript": "6.0.3"},
        },
        "workspaces": [{
            "path": "packages/client-api",
            "name": "@fixture/client-api",
            "version": "1.0.0",
        }],
    }


def _fake_helper(message, *, plaintext_pipe=False):
    if message["operation"] == "keygen":
        fd = os.open(message["private_key_path"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, PRIVATE_KEY)
            os.fchmod(fd, 0o400)
            os.fsync(fd)
        finally:
            os.close(fd)
        result = {
            "schema_version": 1,
            "public_spki_base64": base64.b64encode(SPKI).decode("ascii"),
            "recipient_fingerprint": hashlib.sha256(SPKI).hexdigest(),
            "modulus_length": 3072,
            "public_exponent": "65537",
        }
        return json.dumps(result).encode("ascii"), bytearray()
    if message["operation"] == "decrypt" and plaintext_pipe:
        return b'{"schema_version":1,"ok":true}\n', bytearray(PLAINTEXT)
    raise AssertionError("unexpected helper operation")


@unittest.skipUnless(os.name == "posix" and subject.fcntl is not None,
                     "owner filesystem wrapper requires POSIX semantics")
class FeedbackAdminTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.clock_patch = mock.patch.object(subject.time, "time", return_value=NOW)
        self.clock_patch.start()
        self.directory = os.path.realpath(os.path.join(self.temporary.name, "private-state"))
        self.admin = subject.FeedbackAdmin(
            self.directory,
            node_runtime_path="/synthetic/qualified/node",
            node_runtime_sha256="a" * 64,
            ci_repository_id=CI_REPOSITORY_ID,
            actor_login=ACTOR_LOGIN,
            summary_job_names=("synthetic-settings", "synthetic-prepare",
                               "synthetic-producer", "synthetic-audit"),
        )
        self.helper_patch = mock.patch.object(self.admin, "_run_helper", side_effect=_fake_helper)
        self.helper_patch.start()

    def tearDown(self):
        self.helper_patch.stop()
        self.clock_patch.stop()
        self.temporary.cleanup()

    def create(self, kind="lock", expiry=NOW + 3600):
        return self.admin.create_request(
            _fields(kind, expiry),
            expected_manifest=_expectation() if kind == "lock" else None,
            reviewed_rust_paths=["src/lib.rs"] if kind == "rust_patch" else None,
            confirm_reviewed=True,
        )

    def evidence_for(self, request, *, run_id=RUN_ID, artifact_id=ARTIFACT_ID):
        profile = feedback_request.PROFILE_BY_KIND[request["kind"]]
        context_fields = (
            __import__("node_lock_receipt").CONTEXT_FIELDS
            if request["kind"] == "lock"
            else __import__("node_lock_receipt").FEEDBACK_CONTEXT_FIELDS
        )
        context = {name: request[name] for name in context_fields if name in request}
        context.update({
            "run_id": str(run_id),
            "producer_job": profile["producer_job"],
            "run_attempt": 1,
        })
        if profile["profile_id"] != 1:
            context["kind"] = request["kind"]
        receipt = {"artifact_id": artifact_id}
        api_evidence = {"run": {"id": run_id}}
        return {
            "receipt": receipt,
            "api_evidence": api_evidence,
            "producer_output": {"artifact_id": artifact_id, "archive_digest": "b" * 64},
            "archive_bytes": b"synthetic archive bytes",
            "ci_repository_id": CI_REPOSITORY_ID,
            "actor_login": ACTOR_LOGIN,
            "artifact_name": "synthetic-artifact",
            "now": NOW,
        }, {"context": context, "ciphertext": b"synthetic authenticated ciphertext"}

    def summary_gate(self, request, *, run_id=RUN_ID, artifact_id=ARTIFACT_ID):
        return {
            "confirmed": True,
            "request_id": request["request_id"],
            "protected_repository_id": request["repository_id"],
            "protected_ref": request["workflow_ref"],
            "source_sha": request["source_sha"],
            "control_sha": request["control_sha"],
            "run_id": run_id,
            "run_attempt": 1,
            "artifact_id": artifact_id,
            "reviewed_at": NOW - 30,
            "ledger_ref": "synthetic-ledger-record-1",
            "summary_sections": [
                {"job_name": name, "status": "completed", "complete": True,
                 "observer_record_id": "observer-record-" + str(index)}
                for index, name in enumerate(self.admin.summary_job_names, start=1)
            ],
        }

    def install_collector(self, evidence):
        module = types.ModuleType("feedback_api")
        module.collect_feedback_evidence = lambda api, request, **kwargs: evidence
        return mock.patch.dict(sys.modules, {"feedback_api": module})

    def test_request_creation_persists_private_key_and_only_returns_public_material(self):
        result = self.create()
        self.assertEqual(set(result), {"request", "canonical_record", "public_spki_base64", "recipient_fingerprint"})
        self.assertEqual(result["request"]["recipient_fingerprint"], hashlib.sha256(SPKI).hexdigest())
        self.assertNotIn(PRIVATE_KEY, repr(result).encode("utf-8"))
        key_path = os.path.join(self.directory, "key-" + result["request"]["nonce"] + ".der")
        info = os.stat(key_path, follow_symlinks=False)
        self.assertEqual(stat.S_IMODE(info.st_mode), 0o400)
        self.assertEqual(info.st_nlink, 1)

    def test_request_expectation_is_bounded_before_private_state_or_key_creation(self):
        oversized = _expectation()
        oversized["root"]["name"] = "x" * (subject.MAX_PACKET_BYTES + 1)
        with self.assertRaises(subject.FeedbackAdminRefusal):
            self.admin.create_request(_fields(), expected_manifest=oversized, confirm_reviewed=True)
        self.assertFalse(os.path.exists(self.directory))

    def test_protocol_size_budget_accepts_large_ascii_payloads_below_wire_limit(self):
        protocol = {"payload_base64": "A" * 1_400_000}
        encoded = subject._json_bytes(protocol, subject.MAX_NODE_INPUT_BYTES)
        self.assertLess(len(encoded), subject.MAX_NODE_INPUT_BYTES)
        with self.assertRaises(subject.FeedbackAdminRefusal):
            subject._json_bytes({"payload_base64": "A" * subject.MAX_NODE_INPUT_BYTES},
                                subject.MAX_NODE_INPUT_BYTES)

    def test_crypto_helper_receives_a_clock_refreshed_after_runtime_qualification(self):
        clock = [NOW]
        captured = {}

        class FakeProcess:
            returncode = 0

            def communicate(self, *, input, timeout):
                captured["message"] = json.loads(input.decode("ascii"))
                return b'{"schema_version":1,"ok":true}\n', None

        def qualify():
            clock[0] = NOW + 1
            return "/synthetic/qualified/node"

        message = {
            "operation": "decrypt",
            "private_key_path": "/synthetic/keys/key.der",
            "context": {"expiry": NOW + 60},
            "now": NOW,
            "envelope_base64": "AA==",
        }
        with mock.patch.object(subject.time, "time", side_effect=lambda: clock[0]), \
                mock.patch.object(self.admin, "_qualified_node", side_effect=qualify), \
                mock.patch("subprocess.Popen", return_value=FakeProcess()):
            stdout, unused_plaintext = self.admin._run_helper(message)
        self.assertEqual(captured["message"]["now"], NOW + 1)
        self.assertEqual(stdout, b'{"schema_version":1,"ok":true}\n')

    def test_request_keygen_delay_past_expiry_removes_key_and_refuses_creation(self):
        expiry = NOW + 60
        clock = [NOW]

        def delayed_keygen(message, *, plaintext_pipe=False):
            result = _fake_helper(message, plaintext_pipe=plaintext_pipe)
            clock[0] = expiry
            return result

        with mock.patch.object(subject.time, "time", side_effect=lambda: clock[0]), \
                mock.patch.object(self.admin, "_run_helper", side_effect=delayed_keygen):
            with self.assertRaises(subject.FeedbackAdminRefusal):
                self.admin.create_request(
                    _fields(expiry=expiry), expected_manifest=_expectation(), confirm_reviewed=True,
                )

        self.assertEqual([name for name in os.listdir(self.directory) if name.startswith("key-")], [])
        self.assertEqual([name for name in os.listdir(self.directory) if name.startswith("packet-")], [])
        self.assertFalse(os.path.exists(os.path.join(self.directory, "state.json")))

    def test_request_lock_wait_past_exception_end_refuses_before_keygen(self):
        clock = [feedback_request.EXCEPTION_END - 1]
        entered_wait = threading.Event()
        helper_called = []
        original_lock = self.admin._locked_directory

        @contextlib.contextmanager
        def observed_lock(*, create):
            entered_wait.set()
            with original_lock(create=create) as dir_fd:
                yield dir_fd

        def create():
            return self.admin.create_request(
                _fields(expiry=feedback_request.EXCEPTION_END),
                expected_manifest=_expectation(), confirm_reviewed=True,
            )

        executor = ThreadPoolExecutor(max_workers=1)
        try:
            with mock.patch.object(subject.time, "time", side_effect=lambda: clock[0]), \
                    mock.patch.object(self.admin, "_run_helper",
                                      side_effect=lambda *args, **kwargs: helper_called.append(True)):
                with original_lock(create=True):
                    with mock.patch.object(self.admin, "_locked_directory", side_effect=observed_lock):
                        future = executor.submit(create)
                        self.assertTrue(entered_wait.wait(timeout=5))
                        with self.assertRaises(FutureTimeoutError):
                            future.result(timeout=0.05)
                        clock[0] = feedback_request.EXCEPTION_END
                with self.assertRaises(subject.FeedbackAdminRefusal):
                    future.result(timeout=5)
        finally:
            executor.shutdown(wait=True)

        self.assertFalse(helper_called)
        self.assertEqual([name for name in os.listdir(self.directory) if name.startswith("key-")], [])
        self.assertEqual([name for name in os.listdir(self.directory) if name.startswith("packet-")], [])
        self.assertFalse(os.path.exists(os.path.join(self.directory, "state.json")))

    def test_wrong_run_binding_refuses_before_plaintext_and_keeps_request_retryable(self):
        result = self.create()
        evidence, trusted = self.evidence_for(result["request"], run_id=RUN_ID + 1)
        module = types.ModuleType("feedback_api")
        module.collect_feedback_evidence = lambda api, request, **kwargs: evidence
        gate = self.summary_gate(result["request"])
        with mock.patch.dict(sys.modules, {"feedback_api": module}), \
                mock.patch.object(subject.node_lock_receipt, "validate_receipt", return_value=trusted):
            with self.assertRaises(subject.FeedbackAdminRefusal):
                self.admin.consume_return(result["request"]["request_id"], object(),
                                          manual_summary_review=gate)
        state = self._state()
        self.assertEqual(state["requests"][0]["status"], feedback_request.ACTIVE_STATUS)
        self.assertFalse(os.path.exists(os.path.join(self.directory,
                         "return-" + result["request"]["request_id"] + "-lock.payload")))

    def test_success_consumes_and_retires_key_before_private_output(self):
        result = self.create()
        request = result["request"]
        evidence, trusted = self.evidence_for(request)
        gate = self.summary_gate(request)
        with self.install_collector(evidence), \
                mock.patch.object(subject.node_lock_receipt, "validate_receipt", return_value=trusted):
            returned = self.admin.consume_return(request["request_id"], object(),
                                                 manual_summary_review=gate)
        self.assertEqual(returned["kind"], "lock")
        self.assertTrue(returned["bootstrap_lock_consumed"])
        with open(returned["private_output_path"], "rb") as output:
            self.assertEqual(output.read(), PLAINTEXT)
        state = self._state()
        self.assertTrue(state["bootstrap_lock_consumed"])
        self.assertEqual(state["requests"][0]["status"], "consumed")
        self.assertEqual(state["requests"][0]["key_state"], "retired")
        self.assertFalse(os.path.exists(os.path.join(self.directory, "key-" + request["nonce"] + ".der")))
        with self.install_collector(evidence), \
                mock.patch.object(subject.node_lock_receipt, "validate_receipt", return_value=trusted):
            with self.assertRaises(subject.FeedbackAdminRefusal):
                self.admin.consume_return(request["request_id"], object(),
                                          manual_summary_review=gate)
        with self.assertRaises(subject.FeedbackAdminRefusal):
            self.create()

    def test_summary_job_set_is_ordered_and_must_match_the_reviewed_template(self):
        result = self.create()
        gate = self.summary_gate(result["request"])
        gate["summary_sections"].reverse()
        with self.assertRaises(subject.FeedbackAdminRefusal):
            self.admin._validate_summary_claim(gate, result["request"], NOW)

    def test_bad_summary_claim_is_rejected_before_api_collection(self):
        result = self.create()
        gate = self.summary_gate(result["request"])
        gate["summary_sections"] = gate["summary_sections"][:-1]
        collector_called = []
        module = types.ModuleType("feedback_api")
        module.collect_feedback_evidence = lambda *args, **kwargs: collector_called.append(True)
        with mock.patch.dict(sys.modules, {"feedback_api": module}):
            with self.assertRaises(subject.FeedbackAdminRefusal):
                self.admin.consume_return(result["request"]["request_id"], object(),
                                          manual_summary_review=gate)
        self.assertEqual(collector_called, [])
        self.assertEqual(self._state()["requests"][0]["status"], feedback_request.ACTIVE_STATUS)

    def test_invalid_receipt_does_not_release_plaintext_or_burn_retry_state(self):
        result = self.create()
        request = result["request"]
        evidence, unused_trusted = self.evidence_for(request)
        gate = self.summary_gate(request)
        with self.install_collector(evidence), \
                mock.patch.object(subject.node_lock_receipt, "validate_receipt",
                                  side_effect=subject.node_lock_receipt.Refusal):
            with self.assertRaises(subject.FeedbackAdminRefusal):
                self.admin.consume_return(request["request_id"], object(),
                                          manual_summary_review=gate)
        self.assertEqual(self._state()["requests"][0]["status"], feedback_request.ACTIVE_STATUS)
        self.assertFalse(any(name.startswith("return-") for name in os.listdir(self.directory)))

    def test_expiry_retires_key_and_keeps_tombstone(self):
        result = self.create(expiry=NOW + 60)
        request = result["request"]
        with mock.patch.object(subject.time, "time", return_value=request["expiry"]):
            self.assertEqual(self.admin.expire_requests(), 1)
        self.assertFalse(os.path.exists(os.path.join(self.directory, "key-" + request["nonce"] + ".der")))
        state = self._state()
        self.assertEqual(state["requests"][0]["status"], "expired")
        self.assertEqual(state["requests"][0]["key_state"], "retired")

    def test_expiry_cleanup_resamples_clock_after_waiting_for_state_lock(self):
        result = self.create(expiry=NOW + 60)
        request = result["request"]
        clock = [NOW]
        entered_wait = threading.Event()
        original_lock = self.admin._locked_directory

        @contextlib.contextmanager
        def observed_lock(*, create):
            entered_wait.set()
            with original_lock(create=create) as dir_fd:
                yield dir_fd

        executor = ThreadPoolExecutor(max_workers=1)
        try:
            with mock.patch.object(subject.time, "time", side_effect=lambda: clock[0]):
                with original_lock(create=False):
                    with mock.patch.object(self.admin, "_locked_directory", side_effect=observed_lock):
                        future = executor.submit(self.admin.expire_requests)
                        self.assertTrue(entered_wait.wait(timeout=5))
                        with self.assertRaises(FutureTimeoutError):
                            future.result(timeout=0.05)
                        clock[0] = request["expiry"]
                self.assertEqual(future.result(timeout=5), 1)
        finally:
            executor.shutdown(wait=True)

        self.assertFalse(os.path.exists(os.path.join(self.directory, "key-" + request["nonce"] + ".der")))
        state = self._state()
        self.assertEqual(state["requests"][0]["status"], "expired")
        self.assertEqual(state["requests"][0]["key_state"], "retired")

    def test_first_operation_at_exception_end_retires_any_remaining_key(self):
        result = self.create()
        request = result["request"]
        with mock.patch.object(subject.time, "time", return_value=feedback_request.EXCEPTION_END):
            with self.assertRaises(subject.FeedbackAdminRefusal):
                self.admin.consume_return(request["request_id"], object(), manual_summary_review={})
        self.assertFalse(os.path.exists(os.path.join(self.directory, "key-" + request["nonce"] + ".der")))
        state = self._state()
        self.assertEqual(state["requests"][0]["status"], "expired")
        self.assertEqual(state["requests"][0]["key_state"], "retired")

    def test_explicit_abandon_retires_key_without_consuming_bootstrap_lock(self):
        result = self.create()
        request = result["request"]
        self.assertEqual(self.admin.abandon_request(request["request_id"]), {
            "request_id": request["request_id"], "status": "abandoned",
        })
        self.assertFalse(os.path.exists(os.path.join(self.directory, "key-" + request["nonce"] + ".der")))
        state = self._state()
        self.assertFalse(state["bootstrap_lock_consumed"])
        self.assertEqual(state["requests"][0]["status"], "abandoned")
        self.assertEqual(state["requests"][0]["key_state"], "retired")

    def test_all_closed_return_profiles_can_register_with_profile_specific_expectations(self):
        patch_request = self.create("rust_patch", expiry=NOW + 60)["request"]
        self.assertEqual(patch_request["kind"], "rust_patch")
        with mock.patch.object(subject.time, "time", return_value=patch_request["expiry"]):
            self.admin.expire_requests()
        diagnostic = self.create("build_diagnostics")["request"]
        self.assertEqual(diagnostic["kind"], "build_diagnostics")

    def test_private_state_directory_rejects_symlink_aliases(self):
        base = os.path.realpath(self.temporary.name)
        real = os.path.join(base, "real-state")
        os.mkdir(real, 0o700)
        alias = os.path.join(base, "state-alias")
        os.symlink(real, alias)
        other = subject.FeedbackAdmin(
            alias,
            node_runtime_path="/synthetic/qualified/node",
            node_runtime_sha256="a" * 64,
            ci_repository_id=CI_REPOSITORY_ID,
            actor_login=ACTOR_LOGIN,
            summary_job_names=("synthetic-settings", "synthetic-prepare",
                               "synthetic-producer", "synthetic-audit"),
        )
        with self.assertRaises(subject.FeedbackAdminRefusal):
            with other._locked_directory(create=False):
                pass

    def test_concurrent_consumers_release_at_most_one_output(self):
        result = self.create()
        request = result["request"]
        evidence, trusted = self.evidence_for(request)
        gate = self.summary_gate(request)
        outcomes = []

        def consume():
            try:
                return self.admin.consume_return(request["request_id"], object(),
                                                 manual_summary_review=gate)
            except subject.FeedbackAdminRefusal:
                return None

        with self.install_collector(evidence), \
                mock.patch.object(subject.node_lock_receipt, "validate_receipt", return_value=trusted):
            with ThreadPoolExecutor(max_workers=2) as executor:
                outcomes = list(executor.map(lambda unused: consume(), range(2)))
        successes = [item for item in outcomes if item is not None]
        self.assertEqual(len(successes), 1)

    def test_lock_wait_expiry_retires_key_before_collector_or_decrypt(self):
        result = self.create(expiry=NOW + 60)
        request = result["request"]
        gate = self.summary_gate(request)
        clock = [NOW]
        entered_wait = threading.Event()
        collector_called = []
        module = types.ModuleType("feedback_api")
        module.collect_feedback_evidence = lambda *args, **kwargs: collector_called.append(True)
        original_lock = self.admin._locked_directory

        @contextlib.contextmanager
        def observed_lock(*, create):
            entered_wait.set()
            with original_lock(create=create) as dir_fd:
                yield dir_fd

        def consume():
            try:
                return self.admin.consume_return(request["request_id"], object(),
                                                 manual_summary_review=gate)
            except subject.FeedbackAdminRefusal:
                return None

        executor = ThreadPoolExecutor(max_workers=1)
        try:
            with mock.patch.object(subject.time, "time", side_effect=lambda: clock[0]), \
                    mock.patch.dict(sys.modules, {"feedback_api": module}):
                with original_lock(create=False):
                    with mock.patch.object(self.admin, "_locked_directory", side_effect=observed_lock):
                        future = executor.submit(consume)
                        self.assertTrue(entered_wait.wait(timeout=5))
                        with self.assertRaises(FutureTimeoutError):
                            future.result(timeout=0.05)
                        clock[0] = request["expiry"]
                self.assertIsNone(future.result(timeout=5))
        finally:
            executor.shutdown(wait=True)
        self.assertFalse(collector_called)
        self.assertFalse(os.path.exists(os.path.join(self.directory, "key-" + request["nonce"] + ".der")))
        self.assertEqual(self._state()["requests"][0]["status"], "expired")
        self.assertFalse(os.path.exists(os.path.join(self.directory,
                         "return-" + request["request_id"] + "-lock.payload")))

    def test_lock_wait_crossing_exception_end_retires_under_held_lock(self):
        with mock.patch.object(subject.time, "time", return_value=feedback_request.EXCEPTION_END - 60):
            result = self.admin.create_request(
                _fields(expiry=feedback_request.EXCEPTION_END),
                expected_manifest=_expectation(), confirm_reviewed=True,
            )
        request = result["request"]
        clock = [feedback_request.EXCEPTION_END - 1]
        entered_wait = threading.Event()
        original_lock = self.admin._locked_directory

        @contextlib.contextmanager
        def observed_lock(*, create):
            entered_wait.set()
            with original_lock(create=create) as dir_fd:
                yield dir_fd

        def consume():
            try:
                return self.admin.consume_return(request["request_id"], object(),
                                                 manual_summary_review={})
            except subject.FeedbackAdminRefusal:
                return None

        executor = ThreadPoolExecutor(max_workers=1)
        try:
            with mock.patch.object(subject.time, "time", side_effect=lambda: clock[0]):
                with original_lock(create=False):
                    with mock.patch.object(self.admin, "_locked_directory", side_effect=observed_lock):
                        future = executor.submit(consume)
                        self.assertTrue(entered_wait.wait(timeout=5))
                        with self.assertRaises(FutureTimeoutError):
                            future.result(timeout=0.05)
                        clock[0] = feedback_request.EXCEPTION_END
                self.assertIsNone(future.result(timeout=5))
        finally:
            executor.shutdown(wait=True)
        self.assertFalse(os.path.exists(os.path.join(self.directory, "key-" + request["nonce"] + ".der")))
        state = self._state()
        self.assertEqual(state["requests"][0]["status"], "expired")
        self.assertFalse(state["bootstrap_lock_consumed"])

    def test_collector_delay_past_expiry_retires_key_without_decrypt(self):
        result = self.create(expiry=NOW + 60)
        request = result["request"]
        evidence, trusted = self.evidence_for(request)
        gate = self.summary_gate(request)
        clock = [NOW]
        collector_called = []
        helper_called = []
        module = types.ModuleType("feedback_api")

        def collect(api, value, **kwargs):
            collector_called.append(True)
            clock[0] = request["expiry"]
            return evidence

        module.collect_feedback_evidence = collect

        def forbidden_helper(*args, **kwargs):
            helper_called.append(True)
            raise AssertionError("must not decrypt")

        with mock.patch.object(subject.time, "time", side_effect=lambda: clock[0]), \
                mock.patch.dict(sys.modules, {"feedback_api": module}), \
                mock.patch.object(subject.node_lock_receipt, "validate_receipt", return_value=trusted), \
                mock.patch.object(self.admin, "_run_helper", side_effect=forbidden_helper):
            with self.assertRaises(subject.FeedbackAdminRefusal):
                self.admin.consume_return(request["request_id"], object(), manual_summary_review=gate)
        self.assertEqual(collector_called, [True])
        self.assertFalse(helper_called)
        self.assertFalse(os.path.exists(os.path.join(self.directory, "key-" + request["nonce"] + ".der")))
        self.assertEqual(self._state()["requests"][0]["status"], "expired")
        self.assertFalse(os.path.exists(os.path.join(self.directory,
                         "return-" + request["request_id"] + "-lock.payload")))

    def test_helper_delay_past_expiry_discards_plaintext_and_retires_key(self):
        result = self.create(expiry=NOW + 60)
        request = result["request"]
        evidence, trusted = self.evidence_for(request)
        gate = self.summary_gate(request)
        clock = [NOW]
        helper_plaintext = bytearray(PLAINTEXT)
        module = types.ModuleType("feedback_api")
        module.collect_feedback_evidence = lambda api, value, **kwargs: evidence

        def slow_helper(message, *, plaintext_pipe=False):
            clock[0] = request["expiry"]
            return b'{"schema_version":1,"ok":true}\n', helper_plaintext

        with mock.patch.object(subject.time, "time", side_effect=lambda: clock[0]), \
                mock.patch.dict(sys.modules, {"feedback_api": module}), \
                mock.patch.object(subject.node_lock_receipt, "validate_receipt", return_value=trusted), \
                mock.patch.object(self.admin, "_run_helper", side_effect=slow_helper):
            with self.assertRaises(subject.FeedbackAdminRefusal):
                self.admin.consume_return(request["request_id"], object(), manual_summary_review=gate)
        self.assertEqual(helper_plaintext, bytearray(len(PLAINTEXT)))
        self.assertFalse(os.path.exists(os.path.join(self.directory, "key-" + request["nonce"] + ".der")))
        state = self._state()
        self.assertEqual(state["requests"][0]["status"], "expired")
        self.assertFalse(state["bootstrap_lock_consumed"])
        self.assertFalse(os.path.exists(os.path.join(self.directory,
                         "return-" + request["request_id"] + "-lock.payload")))

    def test_output_write_crossing_expiry_removes_private_file(self):
        result = self.create(expiry=NOW + 60)
        request = result["request"]
        evidence, trusted = self.evidence_for(request)
        gate = self.summary_gate(request)
        clock = [NOW]
        module = types.ModuleType("feedback_api")
        module.collect_feedback_evidence = lambda api, value, **kwargs: evidence
        original_release = self.admin._release_private_output

        def delayed_release(dir_fd, value, profile, plaintext):
            output_path = original_release(dir_fd, value, profile, plaintext)
            clock[0] = request["expiry"]
            return output_path

        with mock.patch.object(subject.time, "time", side_effect=lambda: clock[0]), \
                mock.patch.dict(sys.modules, {"feedback_api": module}), \
                mock.patch.object(subject.node_lock_receipt, "validate_receipt", return_value=trusted), \
                mock.patch.object(self.admin, "_release_private_output", side_effect=delayed_release):
            with self.assertRaises(subject.FeedbackAdminRefusal):
                self.admin.consume_return(request["request_id"], object(), manual_summary_review=gate)

        state = self._state()
        self.assertEqual(state["requests"][0]["status"], "consumed")
        self.assertEqual(state["requests"][0]["key_state"], "retired")
        self.assertFalse(os.path.exists(os.path.join(self.directory,
                         "return-" + request["request_id"] + "-lock.payload")))

    def test_failure_after_tombstone_never_releases_or_replays_plaintext(self):
        result = self.create()
        request = result["request"]
        evidence, trusted = self.evidence_for(request)
        gate = self.summary_gate(request)
        with self.install_collector(evidence), \
                mock.patch.object(subject.node_lock_receipt, "validate_receipt", return_value=trusted), \
                mock.patch.object(self.admin, "_release_private_output", side_effect=subject.FeedbackAdminRefusal):
            with self.assertRaises(subject.FeedbackAdminRefusal):
                self.admin.consume_return(request["request_id"], object(),
                                          manual_summary_review=gate)
        state = self._state()
        self.assertEqual(state["requests"][0]["status"], "consumed")
        self.assertEqual(state["requests"][0]["key_state"], "retired")
        self.assertFalse(os.path.exists(os.path.join(self.directory,
                         "return-" + request["request_id"] + "-lock.payload")))

    def _state(self):
        with self.admin._locked_directory(create=False) as dir_fd:
            return self.admin._read_state(dir_fd)


class UnsupportedPlatformTests(unittest.TestCase):
    def test_constructor_refuses_when_posix_locking_is_unavailable(self):
        arguments = {
            "node_runtime_path": "/synthetic/qualified/node",
            "node_runtime_sha256": "a" * 64,
            "ci_repository_id": CI_REPOSITORY_ID,
            "actor_login": ACTOR_LOGIN,
            "summary_job_names": ("synthetic-job",),
        }
        if os.name == "posix" and subject.fcntl is not None:
            with mock.patch.object(subject, "fcntl", None):
                with self.assertRaises(subject.FeedbackAdminRefusal):
                    subject.FeedbackAdmin(os.path.abspath("synthetic-state"), **arguments)
        else:
            with self.assertRaises(subject.FeedbackAdminRefusal):
                subject.FeedbackAdmin(os.path.abspath("synthetic-state"), **arguments)


if __name__ == "__main__":
    unittest.main()
