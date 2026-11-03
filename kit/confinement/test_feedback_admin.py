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


def _spki_for_key_path(path):
    name = os.path.basename(path)
    if not name.startswith("key-") or not name.endswith(".der"):
        raise AssertionError("unexpected synthetic key name")
    return SPKI + bytes.fromhex(name[4:-4])


def _fake_helper(message, *, plaintext_pipe=False):
    if message["operation"] == "keygen":
        nonce = os.path.basename(message["private_key_path"])[4:-4]
        nonce_bytes = bytes.fromhex(nonce)
        private_key = PRIVATE_KEY + nonce_bytes
        public_spki = _spki_for_key_path(message["private_key_path"])
        fd = os.open(message["private_key_path"], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            os.write(fd, private_key)
            os.fchmod(fd, 0o400)
            os.fsync(fd)
        finally:
            os.close(fd)
        result = {
            "schema_version": 1,
            "public_spki_base64": base64.b64encode(public_spki).decode("ascii"),
            "recipient_fingerprint": hashlib.sha256(public_spki).hexdigest(),
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

    def test_reviewed_rust_path_list_is_bounded_at_the_four_crate_headroom(self):
        def paths(count):
            return ["crates/kernel/i18n/src/module_" + str(index) + ".rs" for index in range(count)]

        self.assertTrue(subject._valid_reviewed_rust_paths(paths(1)))
        self.assertTrue(subject._valid_reviewed_rust_paths(paths(512)))
        self.assertFalse(subject._valid_reviewed_rust_paths(paths(513)))
        self.assertFalse(subject._valid_reviewed_rust_paths([]))
        self.assertFalse(subject._valid_reviewed_rust_paths(paths(1) * 2))

    def test_request_creation_persists_private_key_and_only_returns_public_material(self):
        result = self.create()
        self.assertEqual(set(result), {"request", "canonical_record", "public_spki_base64", "recipient_fingerprint"})
        expected_spki = _spki_for_key_path(
            os.path.join(self.directory, "key-" + result["request"]["nonce"] + ".der"),
        )
        self.assertEqual(result["request"]["recipient_fingerprint"], hashlib.sha256(expected_spki).hexdigest())
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
            stdout, unused_plaintext = subject.FeedbackAdmin._run_helper(self.admin, message)
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

    def test_collector_receives_the_canonical_run_id_and_complete_evidence_contract(self):
        result = self.create()
        request = result["request"]
        evidence, trusted = self.evidence_for(request)
        gate = self.summary_gate(request)
        api_client = object()
        calls = []
        module = types.ModuleType("feedback_api")

        def collect(api, collector_request, **kwargs):
            calls.append((api, collector_request, dict(kwargs)))
            return evidence

        module.collect_feedback_evidence = collect
        self.assertEqual(set(evidence), set(subject.EVIDENCE_FIELDS))
        with mock.patch.dict(sys.modules, {"feedback_api": module}), \
                mock.patch.object(subject.node_lock_receipt, "validate_receipt", return_value=trusted):
            self.admin.consume_return(request["request_id"], api_client, manual_summary_review=gate)

        self.assertEqual(len(calls), 1)
        self.assertIs(calls[0][0], api_client)
        self.assertEqual(calls[0][1], request)
        self.assertEqual(set(calls[0][2]), {"expected_actor_login", "run_id", "run_attempt", "now"})
        self.assertEqual(calls[0][2]["expected_actor_login"], ACTOR_LOGIN)
        self.assertEqual(calls[0][2]["run_id"], str(RUN_ID))
        self.assertIs(type(calls[0][2]["run_id"]), str)
        self.assertEqual(calls[0][2]["run_attempt"], 1)
        self.assertIs(type(calls[0][2]["run_attempt"]), int)
        self.assertEqual(calls[0][2]["now"], NOW)
        self.assertIs(type(calls[0][2]["now"]), int)

    def test_consumer_source_directory_is_forwarded_only_for_reviewed_rust_paths(self):
        result = self.create(kind="rust_patch")
        request = result["request"]
        evidence, trusted = self.evidence_for(request)
        gate = self.summary_gate(request)
        source_directory = os.path.join(self.temporary.name, "reviewed-source")
        helper_messages = []

        self.helper_calls = 0

        def helper(message, *, plaintext_pipe=False):
            self.helper_calls += 1
            helper_messages.append(dict(message))
            return _fake_helper(message, plaintext_pipe=plaintext_pipe)

        with self.install_collector(evidence), \
                mock.patch.object(subject.node_lock_receipt, "validate_receipt", return_value=trusted), \
                mock.patch.object(self.admin, "_run_helper", side_effect=helper):
            self.admin.consume_return(
                request["request_id"], object(), manual_summary_review=gate,
                rust_source_directory=source_directory,
            )

        self.assertEqual(len(helper_messages), 1)
        self.assertEqual(helper_messages[0]["rust_source_directory"], source_directory)
        self.assertEqual(helper_messages[0]["reviewed_rust_paths"], ["src/lib.rs"])

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

    def consume_npm_return(self, plaintext):
        request = self.create("npm_admission")["request"]
        evidence, trusted = self.evidence_for(request)
        gate = self.summary_gate(request)

        self.helper_calls = 0

        def helper(message, *, plaintext_pipe=False):
            self.helper_calls += 1
            if message["operation"] == "decrypt":
                return b'{"schema_version":1,"ok":true}\n', bytearray(plaintext)
            return _fake_helper(message, plaintext_pipe=plaintext_pipe)

        with self.install_collector(evidence), \
                mock.patch.object(subject.node_lock_receipt, "validate_receipt", return_value=trusted), \
                mock.patch.object(self.admin, "_run_helper", side_effect=helper):
            returned = self.admin.consume_return(request["request_id"], object(), manual_summary_review=gate)
        return request, returned

    def test_an_npm_diagnostic_return_is_written_as_a_diagnostic_and_never_as_an_admission(self):
        diagnostic = (b"KD-NPM-DIAGNOSTICS schema=1 step=npm_resolve reason=eresolve\n"
                      b"stderr:\n  npm error code ERESOLVE\nreport:\n  Found: y@2.0.0\n")
        request, returned = self.consume_npm_return(diagnostic)
        self.assertEqual(returned["kind"], "npm_admission")
        self.assertEqual(returned["payload_variant"], "npm_diagnostics")
        self.assertFalse(returned["bootstrap_lock_consumed"])
        self.assertTrue(returned["private_output_path"].endswith("-npm-diagnostics.payload"))
        self.assertEqual(os.path.basename(returned["private_output_path"]),
                         "return-" + request["request_id"] + "-npm-diagnostics.payload")
        with open(returned["private_output_path"], "rb") as output:
            self.assertEqual(output.read(), diagnostic)
        self.assertFalse(os.path.exists(os.path.join(
            self.directory, "return-" + request["request_id"] + "-npm-admission.payload")))
        entry = self._state()["requests"][0]
        self.assertEqual((entry["status"], entry["key_state"]), ("consumed", "retired"))

    def check_admission_payload(self, plaintext):
        request, returned = self.consume_npm_return(plaintext)
        self.assertNotIn("payload_variant", returned)
        self.assertEqual(set(returned), {
            "request_id", "kind", "private_output_path", "bootstrap_lock_consumed",
        })
        self.assertTrue(returned["private_output_path"].endswith("-npm-admission.payload"))
        with open(returned["private_output_path"], "rb") as output:
            self.assertEqual(output.read(), plaintext)

    def test_an_npm_admission_payload_is_still_written_as_an_admission_payload(self):
        self.check_admission_payload(PLAINTEXT)

    def test_only_a_payload_that_starts_with_the_closed_prefix_is_a_diagnostic(self):
        self.check_admission_payload(b" KD-NPM-DIAGNOSTICS schema=1 step=npm_resolve reason=eresolve\n")

    def test_a_bundle_shaped_payload_is_written_as_an_admission_payload(self):
        self.check_admission_payload(b'{"evidence_b64":"AA==","lock_b64":"AA==","receipt_b64":"AA==","schema_version":1}')

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
        self.assertNotEqual(diagnostic["recipient_fingerprint"], patch_request["recipient_fingerprint"])

    def test_the_linux_quick_kind_registers_on_the_untrusted_ref_and_is_released_under_its_own_name(self):
        quick = self.create("linux_quick")["request"]
        self.assertEqual(quick["kind"], "linux_quick")
        self.assertEqual(quick["concern"], "core-linux-quick-return")
        self.assertEqual(quick["workflow_ref"], "refs/heads/untrusted")
        self.assertEqual(quick["workflow_path"], ".github/workflows/core-linux-quick-return.yml")
        self.assertEqual(self._state()["requests"][0]["kind"], "linux_quick")
        profile = feedback_request.PROFILE_BY_KIND["linux_quick"]
        stub = types.SimpleNamespace(state_directory="/unused")
        with mock.patch.object(subject, "_create_named") as create:
            path = subject.FeedbackAdmin._release_private_output(
                stub, -1, {"request_id": "a" * 64}, profile, b"x" * profile["max_payload_bytes"],
            )
        create.assert_called_once()
        self.assertTrue(path.endswith("-linux-quick.payload"))
        with mock.patch.object(subject, "_create_named") as create:
            with self.assertRaises(subject.FeedbackAdminRefusal):
                subject.FeedbackAdmin._release_private_output(
                    stub, -1, {"request_id": "a" * 64}, profile, b"x" * (profile["max_payload_bytes"] + 1),
                )
        create.assert_not_called()

    def quick_evidence(self, request, *, run_id=RUN_ID):
        profile = feedback_request.PROFILE_BY_KIND["linux_quick"]
        fields = __import__("node_lock_receipt").FEEDBACK_CONTEXT_FIELDS
        context = {name: request[name] for name in fields if name in request}
        context.update({
            "run_id": str(run_id), "producer_job": profile["producer_job"], "run_attempt": 1,
        })
        return {
            "kind": "linux_quick",
            "context": context,
            "ciphertext": b"KDLEsynthetic quick ciphertext",
            "run_id": run_id,
            "artifact_id": ARTIFACT_ID,
            "artifact_digest": "b" * 64,
            "ci_repository_id": CI_REPOSITORY_ID,
            "actor_login": ACTOR_LOGIN,
            "now": NOW,
        }

    def test_quick_return_is_collected_decrypted_under_the_rebuilt_context_and_released_once(self):
        request = self.create("linux_quick")["request"]
        evidence = self.quick_evidence(request)
        calls = []
        module = types.ModuleType("feedback_api")

        def collect(api, collector_request, **kwargs):
            calls.append((collector_request, dict(kwargs)))
            return evidence

        module.collect_feedback_evidence = collect
        messages = []

        self.helper_calls = 0

        def helper(message, *, plaintext_pipe=False):
            self.helper_calls += 1
            messages.append(dict(message))
            return _fake_helper(message, plaintext_pipe=plaintext_pipe)

        with mock.patch.dict(sys.modules, {"feedback_api": module}), \
                mock.patch.object(self.admin, "_run_helper", side_effect=helper):
            returned = self.admin.consume_return(
                request["request_id"], object(), manual_summary_review=None, run_id=str(RUN_ID),
            )
        self.assertEqual(calls[0][0], request)
        self.assertEqual(calls[0][1]["run_id"], str(RUN_ID))
        self.assertEqual(calls[0][1]["run_attempt"], 1)
        self.assertEqual(returned["kind"], "linux_quick")
        self.assertFalse(returned["bootstrap_lock_consumed"])
        self.assertTrue(returned["private_output_path"].endswith("-linux-quick.payload"))
        with open(returned["private_output_path"], "rb") as output:
            self.assertEqual(output.read(), PLAINTEXT)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0]["operation"], "decrypt")
        self.assertEqual(messages[0]["context"], evidence["context"])
        self.assertEqual(messages[0]["context"]["nonce"], request["nonce"])
        self.assertEqual(messages[0]["context"]["expiry"], request["expiry"])
        self.assertEqual(messages[0]["context"]["workflow_ref"], "refs/heads/untrusted")
        self.assertEqual(base64.b64decode(messages[0]["envelope_base64"]), evidence["ciphertext"])
        self.assertEqual(self._state()["requests"][0]["status"], "consumed")
        with mock.patch.dict(sys.modules, {"feedback_api": module}):
            with self.assertRaises(subject.FeedbackAdminRefusal):
                self.admin.consume_return(
                    request["request_id"], object(), manual_summary_review=None, run_id=str(RUN_ID),
                )

    def consume_with_screens(self, verdict_screens, parts, mutate_frames=None, mutate_fillers=None, pad=True):
        request = self.create("linux_quick")["request"]
        evidence = self.quick_evidence(request)
        evidence["ciphertext"] = b"KDLEverdict"
        manifest, frames = _screens_set(SCREEN_FILES, request_id=request["request_id"])
        if verdict_screens == "ok":
            verdict_screens = manifest
        if mutate_frames is not None:
            frames = mutate_frames(frames)
        real_count = len(frames)
        if pad:
            fillers = [_screens_filler_frame(index, request["request_id"]) for index in range(real_count, subject.SCREENS_MAX_PARTS)]
            frames = frames + (fillers if mutate_fillers is None else mutate_fillers(fillers))
        verdict = _screens_frame(json.dumps({"screens": verdict_screens}).encode("ascii"))
        if parts:
            evidence["screens"] = [b"KDLEpart" + bytes([index]) for index in range(len(frames))]
        module = types.ModuleType("feedback_api")
        module.collect_feedback_evidence = lambda api, collector_request, **kwargs: evidence
        by_envelope = {b"KDLEverdict": verdict}
        for index, frame in enumerate(frames):
            by_envelope[b"KDLEpart" + bytes([index])] = frame

        self.helper_calls = 0

        def helper(message, *, plaintext_pipe=False):
            self.helper_calls += 1
            return b'{"schema_version":1,"ok":true}\n', bytearray(by_envelope[base64.b64decode(message["envelope_base64"])])

        with mock.patch.dict(sys.modules, {"feedback_api": module}), \
                mock.patch.object(subject, "SCREENS_PART_BYTES", 100), \
                mock.patch.object(self.admin, "_run_helper", side_effect=helper):
            returned = self.admin.consume_return(
                request["request_id"], object(), manual_summary_review=None, run_id=str(RUN_ID),
            )
        return request, verdict, returned

    def test_an_ok_screens_block_is_decrypted_checked_and_written_beside_the_verdict(self):
        request, verdict, returned = self.consume_with_screens("ok", True)
        with open(returned["private_output_path"], "rb") as output:
            self.assertEqual(output.read(), verdict)
        name = "return-" + request["request_id"] + "-linux-quick-screens"
        self.assertEqual(returned["screens_directory"], os.path.join(self.directory, name))
        root = os.path.join(self.directory, name)
        for path, data in SCREEN_FILES:
            with open(os.path.join(root, *path.split("/")), "rb") as source:
                self.assertEqual(source.read(), data)
        self.assertEqual(self._state()["requests"][0]["status"], "consumed")

    def assert_screens_skipped(self, block, parts, mutate=None, mutate_fillers=None):
        request, verdict, returned = self.consume_with_screens(block, parts, mutate, mutate_fillers)
        self.assertNotIn("screens_directory", returned)
        with open(returned["private_output_path"], "rb") as output:
            self.assertEqual(output.read(), verdict)
        self.assertFalse(os.path.exists(os.path.join(
            self.directory, "return-" + request["request_id"] + "-linux-quick-screens",
        )))
        self.assertEqual(self._state()["requests"][0]["status"], "consumed")

    def test_a_none_or_refused_screens_block_never_fails_the_verdict(self):
        self.assert_screens_skipped({"status": "none"}, False)

    def test_a_refused_screens_block_with_or_without_parts_never_fails_the_verdict(self):
        self.assert_screens_skipped({"status": "refused"}, True)

    def test_an_ok_block_without_returned_parts_never_fails_the_verdict(self):
        self.assert_screens_skipped("ok", False)

    def test_a_corrupt_part_never_fails_the_verdict(self):
        self.assert_screens_skipped("ok", True, lambda frames: [frames[0][:-1] + b"!"] + frames[1:])

    def test_a_missing_part_never_fails_the_verdict(self):
        self.assert_screens_skipped("ok", True, lambda frames: frames[:-1])

    def test_every_filler_part_is_decrypted_checked_and_discarded(self):
        request, verdict, returned = self.consume_with_screens("ok", True)
        self.assertEqual(self.helper_calls, 1 + subject.SCREENS_MAX_PARTS)
        name = os.path.join(self.directory, "return-" + request["request_id"] + "-linux-quick-screens")
        written = sorted(
            os.path.relpath(os.path.join(base, item), name)
            for base, unused, items in os.walk(name) for item in items
        )
        self.assertEqual(written, sorted(path for path, data in SCREEN_FILES))

    def test_a_none_block_with_only_filler_parts_decrypts_nothing_beyond_the_verdict(self):
        self.assert_screens_skipped({"status": "none"}, True)
        self.assertEqual(self.helper_calls, 1)

    def test_a_tampered_filler_part_never_fails_the_verdict(self):
        request_id = SCREENS_REQUEST
        for label, change in (
            ("kind", lambda fillers: [_screens_filler_frame(0, request_id, kind="screens-part")] + fillers[1:]),
            ("extra", lambda fillers: [_screens_filler_frame(0, request_id, extra={"x": 1})] + fillers[1:]),
            ("too_many", lambda fillers: fillers + [fillers[-1]]),
            ("garbage", lambda fillers: [b"x" * subject.MAX_PLAINTEXT_BYTES] + fillers[1:]),
        ):
            with self.subTest(label=label):
                self.assert_screens_skipped("ok", True, mutate_fillers=change)

    def test_a_garbage_manifest_never_fails_the_verdict(self):
        self.assert_screens_skipped({"status": "ok", "files": "x"}, True)

    def test_quick_return_refuses_each_inconsistent_input_and_keeps_the_request_retryable(self):
        request = self.create("linux_quick")["request"]
        good = self.quick_evidence(request)
        wrong_context = dict(good)
        wrong_context["context"] = dict(good["context"], nonce="0" * 64)
        wrong_run = self.quick_evidence(request, run_id=RUN_ID + 1)
        wrong_actor = dict(good, actor_login="someone-else")
        extra = dict(good, extra=1)
        cases = (
            (good, {"manual_summary_review": self.summary_gate(request), "run_id": str(RUN_ID)}),
            (good, {"manual_summary_review": None, "run_id": None}),
            (good, {"manual_summary_review": None, "run_id": RUN_ID}),
            (good, {"manual_summary_review": None, "run_id": str(RUN_ID), "rust_source_directory": "/x"}),
            (wrong_context, {"manual_summary_review": None, "run_id": str(RUN_ID)}),
            (wrong_run, {"manual_summary_review": None, "run_id": str(RUN_ID)}),
            (wrong_actor, {"manual_summary_review": None, "run_id": str(RUN_ID)}),
            (extra, {"manual_summary_review": None, "run_id": str(RUN_ID)}),
        )
        for evidence, arguments in cases:
            with self.subTest(arguments=sorted(arguments)), self.install_collector(evidence):
                with self.assertRaises(subject.FeedbackAdminRefusal):
                    self.admin.consume_return(request["request_id"], object(), **arguments)
        self.assertEqual(self._state()["requests"][0]["status"], feedback_request.ACTIVE_STATUS)
        self.assertEqual(
            [name for name in os.listdir(self.directory) if name.startswith("return-")], [],
        )

    def test_a_collector_refusal_for_a_quick_request_releases_nothing(self):
        request = self.create("linux_quick")["request"]
        module = types.ModuleType("feedback_api")

        def refuse(api, collector_request, **kwargs):
            raise RuntimeError("closed")

        module.collect_feedback_evidence = refuse
        with mock.patch.dict(sys.modules, {"feedback_api": module}):
            with self.assertRaises(subject.FeedbackAdminRefusal):
                self.admin.consume_return(
                    request["request_id"], object(), manual_summary_review=None, run_id=str(RUN_ID),
                )
        self.assertEqual(self._state()["requests"][0]["status"], feedback_request.ACTIVE_STATUS)

    def test_other_kinds_refuse_a_run_id_argument_and_keep_the_summary_flow(self):
        result = self.create()
        request = result["request"]
        evidence, trusted = self.evidence_for(request)
        gate = self.summary_gate(request)
        with self.install_collector(evidence), \
                mock.patch.object(subject.node_lock_receipt, "validate_receipt", return_value=trusted):
            with self.assertRaises(subject.FeedbackAdminRefusal):
                self.admin.consume_return(
                    request["request_id"], object(), manual_summary_review=gate, run_id=str(RUN_ID),
                )
            returned = self.admin.consume_return(
                request["request_id"], object(), manual_summary_review=gate,
            )
        self.assertEqual(returned["kind"], "lock")
        diagnostics = self.create("build_diagnostics")["request"]
        with self.assertRaises(subject.FeedbackAdminRefusal):
            self.admin.consume_return(
                diagnostics["request_id"], object(), manual_summary_review=None,
            )

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

    def test_private_directory_closes_each_owned_descriptor_once(self):
        os.mkdir(self.directory, 0o700)
        real_open = subject.os.open
        real_close = subject.os.close
        active = {}
        opened = []
        closed = []
        generation = [0]

        def tracked_open(path, flags, mode=0o777, *, dir_fd=None):
            descriptor = real_open(path, flags, mode, dir_fd=dir_fd)
            generation[0] += 1
            ownership = (generation[0], threading.get_ident())
            active[descriptor] = ownership
            opened.append((descriptor, ownership))
            return descriptor

        def tracked_close(descriptor):
            ownership = active.get(descriptor)
            if ownership is None or ownership[1] != threading.get_ident():
                raise AssertionError("descriptor close had no matching open in this thread")
            del active[descriptor]
            closed.append((descriptor, ownership))
            real_close(descriptor)

        try:
            with mock.patch.object(subject.os, "open", side_effect=tracked_open), \
                    mock.patch.object(subject.os, "close", side_effect=tracked_close):
                returned = subject._private_dir(self.directory, create=False)
                self.assertEqual(set(active), {returned})
                self.assertTrue(stat.S_ISDIR(os.fstat(returned).st_mode))
                tracked_close(returned)
            self.assertEqual(active, {})
            self.assertEqual(len(opened), len(closed))
            self.assertEqual(sorted(opened), sorted(closed))
        finally:
            for descriptor in list(active):
                try:
                    real_close(descriptor)
                except OSError:
                    pass

    def test_concurrent_consumers_release_at_most_one_output(self):
        result = self.create()
        request = result["request"]
        evidence, trusted = self.evidence_for(request)
        gate = self.summary_gate(request)
        second_lock_attempt = threading.Event()
        attempt_lock = threading.Lock()
        lock_attempts = [0]
        stage_trace = []
        trace_lock = threading.Lock()
        original_lock = self.admin._locked_directory

        @contextlib.contextmanager
        def observed_lock(*, create):
            with attempt_lock:
                lock_attempts[0] += 1
                if lock_attempts[0] == 2:
                    second_lock_attempt.set()
            with original_lock(create=create) as dir_fd:
                yield dir_fd

        module = types.ModuleType("feedback_api")

        def collect(api, collector_request, **kwargs):
            with trace_lock:
                stage_trace.append("collector")
            if not second_lock_attempt.wait(timeout=5):
                with trace_lock:
                    stage_trace.append("collector_wait_timeout")
            return evidence

        module.collect_feedback_evidence = collect

        def validate(*args, **kwargs):
            with trace_lock:
                stage_trace.append("receipt")
            return trusted

        self.helper_calls = 0

        def helper(message, *, plaintext_pipe=False):
            self.helper_calls += 1
            with trace_lock:
                stage_trace.append("decrypt")
            return _fake_helper(message, plaintext_pipe=plaintext_pipe)

        original_summary = self.admin._write_summary_gate
        original_release = self.admin._release_private_output

        def write_summary(*args, **kwargs):
            with trace_lock:
                stage_trace.append("summary")
            return original_summary(*args, **kwargs)

        def release_output(*args, **kwargs):
            with trace_lock:
                stage_trace.append("release")
            return original_release(*args, **kwargs)

        def consume():
            try:
                return self.admin.consume_return(request["request_id"], object(),
                                                 manual_summary_review=gate)
            except subject.FeedbackAdminRefusal:
                return "refused"

        with mock.patch.dict(sys.modules, {"feedback_api": module}), \
                mock.patch.object(subject.node_lock_receipt, "validate_receipt", side_effect=validate), \
                mock.patch.object(self.admin, "_run_helper", side_effect=helper), \
                mock.patch.object(self.admin, "_write_summary_gate", side_effect=write_summary), \
                mock.patch.object(self.admin, "_release_private_output", side_effect=release_output), \
                mock.patch.object(self.admin, "_locked_directory", side_effect=observed_lock):
            with ThreadPoolExecutor(max_workers=2) as executor:
                futures = [executor.submit(consume) for unused in range(2)]
                outcomes = [future.result(timeout=10) for future in futures]
        successes = [item for item in outcomes if isinstance(item, dict)]
        refusals = [item for item in outcomes if item == "refused"]
        self.assertEqual(len(successes), 1, f"outcomes={outcomes!r}; stages={stage_trace!r}")
        self.assertEqual(len(refusals), 1, f"outcomes={outcomes!r}; stages={stage_trace!r}")
        self.assertEqual(lock_attempts[0], 2)
        self.assertNotIn("collector_wait_timeout", stage_trace)
        self.assertEqual(stage_trace.count("collector"), 1, f"stages={stage_trace!r}")
        self.assertEqual(stage_trace.count("decrypt"), 1, f"stages={stage_trace!r}")
        self.assertEqual(stage_trace.count("summary"), 1, f"stages={stage_trace!r}")
        self.assertEqual(stage_trace.count("release"), 1, f"stages={stage_trace!r}")
        self.assertTrue(os.path.isfile(successes[0]["private_output_path"]))
        self.assertEqual(self._state()["requests"][0]["status"], "consumed")
        self.assertFalse(os.path.exists(os.path.join(
            self.directory, "key-" + request["nonce"] + ".der",
        )))

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


class ProfilePayloadLimitTests(unittest.TestCase):
    def test_release_refuses_plaintext_over_the_profile_limit_before_touching_storage(self):
        stub = types.SimpleNamespace(state_directory="/unused")
        for kind, profile in feedback_request.PROFILE_BY_KIND.items():
            with self.subTest(kind=kind):
                oversize = b"x" * (profile["max_payload_bytes"] + 1)
                with mock.patch.object(subject, "_create_named") as create:
                    with self.assertRaises(subject.FeedbackAdminRefusal):
                        subject.FeedbackAdmin._release_private_output(
                            stub, -1, {"request_id": "a" * 64}, profile, oversize,
                        )
                create.assert_not_called()
        patch_profile = feedback_request.PROFILE_BY_KIND["rust_patch"]
        self.assertEqual(patch_profile["max_payload_bytes"], 4 * 1024 * 1024 - 64 * 1024)
        self.assertEqual(patch_profile["max_payload_bytes"], subject.MAX_PLAINTEXT_BYTES)
        with mock.patch.object(subject, "_create_named") as create:
            path = subject.FeedbackAdmin._release_private_output(
                stub, -1, {"request_id": "a" * 64}, patch_profile, b"x" * patch_profile["max_payload_bytes"],
            )
        create.assert_called_once()
        self.assertTrue(path.endswith("-patch.payload"))
        cargo = feedback_request.PROFILE_BY_KIND["cargo_lock"]
        with mock.patch.object(subject, "_create_named") as create:
            path = subject.FeedbackAdmin._release_private_output(
                stub, -1, {"request_id": "a" * 64}, cargo, b"x" * cargo["max_payload_bytes"],
            )
        create.assert_called_once()
        self.assertTrue(path.endswith("-cargo-lock.payload"))
        with self.assertRaises(subject.FeedbackAdminRefusal):
            subject.FeedbackAdmin._release_private_output(
                stub, -1, {"request_id": "a" * 64}, dict(cargo, max_payload_bytes="1"), b"x",
            )

    def test_the_diagnostic_file_name_is_reserved_for_the_npm_admission_kind_and_its_prefix(self):
        stub = types.SimpleNamespace(state_directory="/unused")
        diagnostic = b"KD-NPM-DIAGNOSTICS schema=1 step=npm_lock reason=npm_lock_refused\nstderr:\nreport:\n"
        for kind, profile in feedback_request.PROFILE_BY_KIND.items():
            for plaintext in (diagnostic, bytearray(diagnostic)):
                with self.subTest(kind=kind, plaintext=type(plaintext).__name__):
                    with mock.patch.object(subject, "_create_named"):
                        path = subject.FeedbackAdmin._release_private_output(
                            stub, -1, {"request_id": "a" * 64}, profile, plaintext,
                        )
                    self.assertEqual(
                        path.endswith("-npm-diagnostics.payload"),
                        kind == feedback_request.NPM_ADMISSION_KIND,
                    )
        npm = feedback_request.PROFILE_BY_KIND[feedback_request.NPM_ADMISSION_KIND]
        for plaintext in (b"", b"KD-NPM-DIAGNOSTICS", b"kd-npm-diagnostics ", b'{"schema_version":1}'):
            with self.subTest(plaintext=plaintext):
                self.assertFalse(subject._is_npm_diagnostic(npm, plaintext))
        self.assertTrue(subject._is_npm_diagnostic(npm, diagnostic))


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


SCREENS_REQUEST = "ab" * 32


def _screens_filler_frame(index, request_id, kind="screens-filler", extra=None):
    body = {"schema_version": 1, "kind": kind, "request_id": request_id, "index": index}
    body.update(extra or {})
    return _screens_frame(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii"))


def _png(width=2, height=3, colour=2, depth=8, filler=b"", end=True):
    header = width.to_bytes(4, "big") + height.to_bytes(4, "big") + bytes((depth, colour, 0, 0, 0))
    return (
        b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + header + b"\x00\x00\x00\x00" + filler
        + (b"\x00\x00\x00\x00IEND\xaeB`\x82" if end else b"\x00" * 12)
    )


def _screens_frame(body):
    header = b"KD-LINUX-QUICK-PAYLOAD 1 " + (b"%08d" % len(body)) + b"\n"
    return header + body + b" " * (subject.MAX_PLAINTEXT_BYTES - len(header) - len(body))


def _screens_set(files, part_bytes=100, request_id=SCREENS_REQUEST):
    files = sorted(files)
    stream = b"".join(data for unused, data in files)
    chunks = [stream[start:start + part_bytes] for start in range(0, len(stream), part_bytes)]
    manifest = {
        "status": "ok", "schema_version": 1, "count": len(files), "bytes": len(stream),
        "parts": len(chunks), "stream_sha256": hashlib.sha256(stream).hexdigest(),
        "files": [
            {"path": path, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
            for path, data in files
        ],
    }
    frames = []
    for index, chunk in enumerate(chunks):
        frames.append(_screens_frame(json.dumps({
            "schema_version": 1, "kind": "screens-part", "request_id": request_id, "index": index,
            "count": len(chunks), "sha256": hashlib.sha256(chunk).hexdigest(),
            "data_b64": base64.b64encode(chunk).decode("ascii"),
        }, sort_keys=True, separators=(",", ":")).encode("ascii")))
    return manifest, frames


SCREEN_FILES = [
    ("01-tokens/frame-one--light--rest.png", _png(filler=b"a" * 70)),
    ("01-tokens/frame-one--dark--rest.png", _png(4, 4, filler=b"b" * 90)),
    ("02-states/frame-two--light--focus.png", _png(8, 8, filler=b"c" * 30)),
]


class ScreensReturnTests(unittest.TestCase):
    def assert_refused(self, function, *arguments):
        with self.assertRaises(subject.FeedbackAdminRefusal):
            function(*arguments)

    def assemble(self, manifest, frames):
        with mock.patch.object(subject, "SCREENS_PART_BYTES", 100):
            return subject.assemble_screens(manifest, frames, SCREENS_REQUEST)

    def test_the_bounds_are_the_producer_bounds(self):
        self.assertEqual(
            (subject.SCREENS_MAX_FILES, subject.SCREENS_MAX_BYTES, subject.SCREENS_PART_BYTES, subject.SCREENS_MAX_PARTS),
            (200, 48 * 1024 * 1024, 3_000_000, 17),
        )

    def test_parts_assemble_into_the_exact_files(self):
        manifest, frames = _screens_set(SCREEN_FILES)
        self.assertGreater(len(frames), 1)
        self.assertEqual(self.assemble(manifest, frames), sorted(SCREEN_FILES))

    def test_manifests_with_escaping_or_malformed_paths_are_refused(self):
        good = "01-tokens/frame-one--light--rest.png"
        for path in (
            "../01-tokens/frame-one--light--rest.png", "01-tokens/../frame-one--light--rest.png",
            "/01-tokens/frame-one--light--rest.png", "01-tokens/sub/frame-one--light--rest.png",
            "frame-one--light--rest.png", "01-tokens\\frame-one--light--rest.png",
            "01-tokens/Frame-one--light--rest.png", "01-tokens/frame-one--light.png",
            "01-tokens/frame-one--light--rest.PNG", "Tokens/frame-one--light--rest.png",
            "01-tokens//frame-one--light--rest.png", "01-tokens/frame-one--light--rest.png\n",
            "01-tokens/.frame--light--rest.png", "./01-tokens/frame-one--light--rest.png",
        ):
            with self.subTest(path=path):
                manifest, frames = _screens_set([(path, SCREEN_FILES[0][1])])
                manifest["files"][0]["path"] = path
                self.assert_refused(self.assemble, manifest, frames)
        manifest, frames = _screens_set([(good, SCREEN_FILES[0][1])])
        self.assertEqual(len(self.assemble(manifest, frames)), 1)

    def test_manifest_shape_count_order_and_totals_are_checked(self):
        manifest, frames = _screens_set(SCREEN_FILES)
        for name, change in (
            ("extra_field", lambda value: value.update({"extra": 1})),
            ("status", lambda value: value.update({"status": "refused"})),
            ("schema", lambda value: value.update({"schema_version": 2})),
            ("count", lambda value: value.update({"count": 2})),
            ("bytes", lambda value: value.update({"bytes": value["bytes"] + 1})),
            ("parts", lambda value: value.update({"parts": value["parts"] + 1})),
            ("stream_hash", lambda value: value.update({"stream_sha256": "0" * 64})),
            ("order", lambda value: value["files"].reverse()),
            ("duplicate", lambda value: value["files"].__setitem__(1, dict(value["files"][0]))),
            ("file_field", lambda value: value["files"][0].update({"mode": 1})),
            ("file_size", lambda value: value["files"][0].update({"size": 10})),
            ("file_hash", lambda value: value["files"][0].update({"sha256": "0" * 64})),
        ):
            with self.subTest(change=name):
                changed = json.loads(json.dumps(manifest))
                change(changed)
                self.assert_refused(self.assemble, changed, frames)
        self.assert_refused(self.assemble, None, frames)
        with mock.patch.object(subject, "SCREENS_MAX_FILES", 2):
            self.assert_refused(self.assemble, manifest, frames)
        with mock.patch.object(subject, "SCREENS_MAX_BYTES", manifest["bytes"] - 1):
            self.assert_refused(self.assemble, manifest, frames)
        with mock.patch.object(subject, "SCREENS_MAX_FILE_BYTES", len(SCREEN_FILES[1][1]) - 1):
            self.assert_refused(self.assemble, manifest, frames)

    def test_part_frames_are_bound_to_the_manifest_the_request_and_their_hashes(self):
        manifest, frames = _screens_set(SCREEN_FILES)

        def with_part(position, **changes):
            body = subject._unframe_screens_part(frames[position], subject.MAX_PLAINTEXT_BYTES)
            body.update(changes)
            changed = list(frames)
            changed[position] = _screens_frame(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("ascii"))
            return changed

        for name, changed in (
            ("index", with_part(0, index=1)),
            ("count", with_part(0, count=99)),
            ("request", with_part(0, request_id="cd" * 32)),
            ("kind", with_part(0, kind="other")),
            ("hash", with_part(0, sha256="0" * 64)),
            ("base64", with_part(0, data_b64="!!!!")),
            ("empty", with_part(0, data_b64="")),
            ("noncanonical", with_part(0, data_b64=base64.b64encode(b"x" * 100).decode("ascii")[:-2] + "==")),
            ("extra", with_part(0, extra=1)),
            ("missing_part", frames[:-1]),
            ("extra_part", frames + [frames[0]]),
            ("short_frame", [frames[0][:-1]] + frames[1:]),
            ("not_bytes", ["text"] + frames[1:]),
            ("reordered", list(reversed(frames))),
        ):
            with self.subTest(change=name):
                self.assert_refused(self.assemble, manifest, changed)
        self.assert_refused(self.assemble, manifest, tuple(frames))
        with mock.patch.object(subject, "SCREENS_PART_BYTES", 100):
            self.assert_refused(subject.assemble_screens, manifest, frames, "short")

    def test_files_that_are_not_bounded_png_bytes_are_refused_even_with_matching_hashes(self):
        for name, data in (
            ("text", b"not a png at all" * 4), ("no_end", _png(end=False)), ("width", _png(width=0)),
            ("colour", _png(colour=5)), ("area", _png(width=16384, height=16384)),
        ):
            with self.subTest(case=name):
                manifest, frames = _screens_set([("01-tokens/frame-one--light--rest.png", data)])
                self.assert_refused(self.assemble, manifest, frames)

    @unittest.skipUnless(os.name == "posix" and subject.fcntl is not None,
                         "owner filesystem wrapper requires POSIX semantics")
    def test_write_creates_one_private_tree_once_and_never_outside_it(self):
        with tempfile.TemporaryDirectory() as directory:
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                name = subject.write_screens_directory(dir_fd, SCREENS_REQUEST, sorted(SCREEN_FILES))
                self.assertEqual(name, "return-" + SCREENS_REQUEST + "-linux-quick-screens")
                root = os.path.join(directory, name)
                for path, data in SCREEN_FILES:
                    target = os.path.join(root, *path.split("/"))
                    with open(target, "rb") as source:
                        self.assertEqual(source.read(), data)
                    self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)
                self.assertEqual(sorted(os.listdir(root)), ["01-tokens", "02-states"])
                self.assertEqual(os.listdir(directory), [name])
                self.assert_refused(subject.write_screens_directory, dir_fd, SCREENS_REQUEST, sorted(SCREEN_FILES))
            finally:
                os.close(dir_fd)

    @unittest.skipUnless(os.name == "posix" and subject.fcntl is not None,
                         "owner filesystem wrapper requires POSIX semantics")
    def test_a_partly_written_tree_is_removed_so_a_retry_can_write_it_again(self):
        with tempfile.TemporaryDirectory() as directory:
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                real = subject._create_named
                calls = []

                def flaky(*arguments, **options):
                    calls.append(arguments)
                    if len(calls) == 2:
                        raise OSError("disk full")
                    return real(*arguments, **options)

                with mock.patch.object(subject, "_create_named", side_effect=flaky):
                    self.assert_refused(subject.write_screens_directory, dir_fd, SCREENS_REQUEST, sorted(SCREEN_FILES))
                self.assertEqual(os.listdir(directory), [])
                name = subject.write_screens_directory(dir_fd, SCREENS_REQUEST, sorted(SCREEN_FILES))
                self.assertEqual(os.listdir(directory), [name])
            finally:
                os.close(dir_fd)

    @unittest.skipUnless(os.name == "posix" and subject.fcntl is not None,
                         "owner filesystem wrapper requires POSIX semantics")
    def test_write_refuses_bad_names_bytes_counts_and_a_planted_link_before_writing(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            dir_fd = os.open(directory, os.O_RDONLY)
            try:
                good = SCREEN_FILES[0]
                for files in (
                    [], [("../escape/frame-one--light--rest.png", good[1])],
                    [("01-tokens/frame-one--light--rest.png", b"not a png at all" * 4)],
                    [good, good], "text", [("01-tokens/frame-one--light--rest.png", _png(end=False))],
                ):
                    with self.subTest(files=repr(files)[:40]):
                        self.assert_refused(subject.write_screens_directory, dir_fd, SCREENS_REQUEST, files)
                with mock.patch.object(subject, "SCREENS_MAX_FILES", 1):
                    self.assert_refused(subject.write_screens_directory, dir_fd, SCREENS_REQUEST, sorted(SCREEN_FILES))
                self.assert_refused(subject.write_screens_directory, dir_fd, "short", [good])
                self.assertEqual(os.listdir(directory), [])
                os.symlink(outside, os.path.join(directory, "return-" + SCREENS_REQUEST + "-linux-quick-screens"))
                self.assert_refused(subject.write_screens_directory, dir_fd, SCREENS_REQUEST, [good])
                self.assertEqual(os.listdir(outside), [])
            finally:
                os.close(dir_fd)


if __name__ == "__main__":
    unittest.main()
