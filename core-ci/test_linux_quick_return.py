import base64
import hashlib
import io
import json
import os
import re
import stat
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import linux_quick_return as subject


__all__ = [
    "FrameTests", "PayloadTests", "BindingTests", "CryptoTests", "OutputTests",
    "CommandTests", "PublicLineTests", "SourceShapeTests",
]

ROOT = Path(__file__).resolve().parents[1]
REQUEST = "ab" * 32
NONCE = "07" * 32
EXPIRY = "1800003600"
DER = b"\x30\x82" + bytes(range(256)) * 2
SPKI = base64.b64encode(DER).decode("ascii")
FINGERPRINT = hashlib.sha256(DER).hexdigest()
GATES = (
    "format", "clippy", "workspace_tests", "api_tests", "mock_tests", "conformance_tests",
    "parser_format", "parser_clippy", "parser_replay", "node_dependency_prepare",
    "node_dependency_audit", "typescript_typecheck", "typescript_tests",
)
RUNTIME_GATES = ("runtime_format", "runtime_clippy", "runtime_tests")
CHANNELS = (
    "https", "dns", "redirect", "proxy", "runner_ipc", "raw_logs", "artifact_upload",
    "cache_upload", "runner_files", "process_memory", "boundary_disablement",
)
POSIX_OUTPUT = unittest.skipUnless(
    os.name == "posix" and hasattr(os, "fchown") and hasattr(os, "O_NOFOLLOW"),
    "the ciphertext hand-off uses POSIX descriptor operations",
)


def environment(**updates):
    values = {
        "KD_QUICK_REQUEST_ID": REQUEST, "KD_QUICK_ALLOWED_REQUEST_ID": REQUEST,
        "KD_QUICK_RECIPIENT_SPKI_B64": SPKI, "KD_QUICK_ALLOWED_RECIPIENT_FINGERPRINT": FINGERPRINT,
        "KD_QUICK_ALLOWED_NONCE": NONCE, "KD_QUICK_ALLOWED_EXPIRY": EXPIRY,
        "CI_SHA": "a" * 40, "REQUESTED_SOURCE_SHA": "b" * 40, "REQUESTED_BASE_SHA": "c" * 40,
        "REQUESTED_BASE_BRANCH": "develop", "REQUESTED_FINGERPRINT": "d" * 64,
        "SOURCE_REPOSITORY_ID": "77", "GITHUB_RUN_ID": "4242", "GITHUB_RUN_ATTEMPT": "1",
        "ImageOS": "ubuntu24", "ImageVersion": "20261028.1.1",
    }
    values.update(updates)
    return values


def write_records(directory, failed_at=None, runtime=False, streams=None):
    records = Path(directory) / "kd-records"
    records.mkdir(parents=True)
    selected = GATES + (RUNTIME_GATES if runtime else ())
    outcomes = {}
    for index, name in enumerate(selected):
        if failed_at is None or index < failed_at:
            outcomes[name] = "passed"
        elif index == failed_at:
            outcomes[name] = "failed"
        else:
            outcomes[name] = "not-run"
    gates = {
        "schema_version": 1, "selected_gates": list(selected),
        "completed_gates": [name for name in selected if outcomes[name] == "passed"],
        "gates": outcomes,
        "gate_count": sum(value != "not-run" for value in outcomes.values()),
        "failed": sum(value == "failed" for value in outcomes.values()),
    }
    durations = {name: 10 * (index + 1) for index, name in enumerate(selected) if outcomes[name] != "not-run"}
    (records / "gates.json").write_text(json.dumps(gates), encoding="ascii")
    (records / "gate-durations.json").write_text(
        json.dumps({"schema_version": 1, "durations_ms": durations}), encoding="ascii",
    )
    for index, name in enumerate(selected):
        if outcomes[name] != "not-run":
            for stream in ("stdout", "stderr"):
                default = ("gate " + name + " " + stream + "\n").encode("ascii")
                data = (streams or {}).get((index, stream), default)
                (records / ("gate-" + str(index) + "." + stream)).write_bytes(data)
    merged = {
        "channels": {name: {"status": "blocked", "before": True, "after": True} for name in CHANNELS},
        "memory_canary": "absent", "readable_file_canary": "absent",
    }
    (records / "merged.json").write_text(json.dumps(merged), encoding="ascii")
    receipt = {
        "schema_version": 1, "status": "confirmed", "control_sha": "a" * 40, "run_id": "4242",
        "run_attempt": "1", "installation_id": "19", "rejected_after_revoke": True,
    }
    (records / "revocation.json").write_text(json.dumps(receipt), encoding="ascii")
    return records


def refusal_reason(function, *arguments):
    with unittest.TestCase().assertRaises(subject.QuickRefusal) as caught:
        function(*arguments)
    return caught.exception.reason


class FrameTests(unittest.TestCase):
    def test_frame_is_one_fixed_size_and_round_trips(self):
        small = subject.frame_payload(json.dumps({"a": 1}).encode("ascii"))
        large = subject.frame_payload(json.dumps({"a": "x" * 50000}).encode("ascii"))
        self.assertEqual(len(small), subject.PADDED_BYTES)
        self.assertEqual(len(large), subject.PADDED_BYTES)
        self.assertLessEqual(subject.PADDED_BYTES, 4 * 1024 * 1024)
        self.assertEqual(subject.unframe_payload(small), {"a": 1})
        self.assertEqual(subject.unframe_payload(large), {"a": "x" * 50000})
        self.assertEqual(small[subject.HEADER_BYTES + len('{"a": 1}'):], b" " * (subject.PADDED_BYTES - subject.HEADER_BYTES - len('{"a": 1}')))
        self.assertTrue(all(byte < 0x80 and (byte >= 0x20 or byte == 0x0A) for byte in small))
        self.assertTrue(small.startswith(subject.FRAME_PREFIX))

    def test_frame_limits_and_tampering_are_refused(self):
        maximum = subject.frame_payload(b"x" * subject.MAX_BODY_BYTES)
        self.assertEqual(len(maximum), subject.PADDED_BYTES)
        self.assertEqual(refusal_reason(subject.frame_payload, b"x" * (subject.MAX_BODY_BYTES + 1)), "limit")
        self.assertEqual(refusal_reason(subject.frame_payload, "text"), "limit")
        good = subject.frame_payload(b"{}")
        cases = []
        tampered = bytearray(good)
        tampered[-1] = ord("x")
        cases.append(bytes(tampered))
        tampered = bytearray(good)
        tampered[len(subject.FRAME_PREFIX)] = ord("x")
        cases.append(bytes(tampered))
        tampered = bytearray(good)
        tampered[0] = ord("X")
        cases.append(bytes(tampered))
        tampered = bytearray(good)
        tampered[subject.HEADER_BYTES - 1] = ord(" ")
        cases.append(bytes(tampered))
        cases.append(good[:-1])
        cases.append(good + b" ")
        cases.append(subject.frame_payload(b"{").replace(b"{", b"{"))
        for index, data in enumerate(cases):
            with self.subTest(index=index):
                self.assertEqual(refusal_reason(subject.unframe_payload, data), "payload")
        self.assertEqual(refusal_reason(subject.unframe_payload, "text"), "payload")


class PayloadTests(unittest.TestCase):
    def build(self, **keywords):
        with tempfile.TemporaryDirectory() as directory:
            records = write_records(directory, **keywords)
            payload, selected, passed, failed = subject.build_payload(records, environment(), REQUEST)
        return subject.unframe_payload(payload), len(payload), selected, passed, failed

    def test_outcome_duration_tail_and_identity_are_recorded_for_a_failed_gate(self):
        document, size, selected, passed, failed = self.build(failed_at=2)
        self.assertEqual((size, selected, passed, failed), (subject.PADDED_BYTES, 13, 2, 1))
        self.assertEqual(document["tier"], "quick")
        self.assertEqual(document["admission"], "never")
        self.assertEqual(document["concern"], "core-linux-quick-return")
        self.assertEqual(document["request_id"], REQUEST)
        self.assertEqual(document["run_id"], 4242)
        self.assertEqual(document["run_attempt"], 1)
        self.assertEqual(document["control_sha"], "a" * 40)
        self.assertEqual(document["source_sha"], "b" * 40)
        self.assertEqual(document["base_sha"], "c" * 40)
        self.assertEqual(document["base_branch"], "develop")
        self.assertEqual(document["reviewed_diff_sha256"], "d" * 64)
        self.assertEqual(document["image_os"], "ubuntu24")
        self.assertEqual(document["gates_selected"], 13)
        self.assertEqual(document["gates_passed"], 2)
        self.assertEqual(document["gates_failed"], 1)
        gates = document["gates"]
        self.assertEqual([gate["name"] for gate in gates], list(GATES))
        self.assertEqual([gate["outcome"] for gate in gates[:4]], ["passed", "passed", "failed", "not-run"])
        self.assertEqual(gates[0]["duration_ms"], 10)
        self.assertEqual(gates[2]["duration_ms"], 30)
        self.assertIsNone(gates[3]["duration_ms"])
        self.assertEqual(gates[2]["stdout_tail"], "gate workspace_tests stdout\n")
        self.assertEqual(gates[2]["stderr_tail"], "gate workspace_tests stderr\n")
        self.assertEqual(gates[3]["stdout_tail"], "")
        self.assertFalse(gates[2]["stdout_cut"])
        self.assertEqual(document["revocation"], {"status": "confirmed", "rejected_after_revoke": True})
        self.assertEqual(document["boundary"]["memory_canary"], "absent")
        self.assertEqual(document["boundary"]["channels"]["https"], "blocked/1/1")
        self.assertEqual(len(document["boundary"]["channels"]), 11)
        serialized = json.dumps(document)
        for forbidden in ("installation", "owner", "SOURCE_REPOSITORY", "token", "private"):
            self.assertNotIn(forbidden, serialized)

    def test_sixteen_gates_are_reported_when_the_runtime_workspace_ran(self):
        document, size, selected, passed, failed = self.build(runtime=True)
        self.assertEqual((size, selected, passed, failed), (subject.PADDED_BYTES, 16, 16, 0))
        self.assertEqual([gate["name"] for gate in document["gates"][-3:]], list(RUNTIME_GATES))

    def test_tails_are_bounded_utf8_safe_and_report_the_full_size(self):
        data = ("\u00e9" * 100000).encode("utf-8") + b"\n"
        document, size, selected, passed, failed = self.build(streams={(0, "stderr"): data})
        gate = document["gates"][0]
        self.assertEqual(gate["stderr_bytes"], len(data))
        self.assertTrue(gate["stderr_cut"])
        self.assertLessEqual(len(gate["stderr_tail"].encode("utf-8")), subject.STREAM_TAIL_BYTES)
        self.assertNotIn("\ufffd", gate["stderr_tail"])
        self.assertTrue(gate["stderr_tail"].endswith("\n"))
        self.assertFalse(gate["stdout_cut"])

    def test_hostile_control_character_tails_still_fit_the_fixed_size(self):
        hostile = b"\x01" * subject.STREAM_TAIL_BYTES
        streams = {}
        for index in range(16):
            streams[(index, "stdout")] = hostile
            streams[(index, "stderr")] = hostile
        document, size, selected, passed, failed = self.build(runtime=True, streams=streams)
        self.assertEqual((size, selected), (subject.PADDED_BYTES, 16))
        total = sum(len(gate["stdout_tail"]) + len(gate["stderr_tail"]) for gate in document["gates"])
        self.assertLess(total, 32 * subject.STREAM_TAIL_BYTES)
        self.assertEqual([gate["outcome"] for gate in document["gates"]], ["passed"] * 16)

    def test_credential_like_lines_are_screened_before_encryption(self):
        secrets = (
            "token_" + "ghp_" + "a" * 24 + "\n",
            "key " + "AKIA" + "A" * 16 + " leaked\n",
            "-----BEGIN RSA PRIVATE KEY-----\n",
            "Authorization: Bearer " + "x" * 30 + "\n",
            "fetch https://user:pw@example.invalid/path\n",
            "pass" + "word=" + "hunter2hunter2\n",
        )
        text = "error: expected one of `;`\n" + "".join(secrets) + "note: done\n"
        stream = text.encode("utf-8")
        document, size, selected, passed, failed = self.build(streams={(1, "stdout"): stream})
        tail = document["gates"][1]["stdout_tail"]
        self.assertEqual(tail, "error: expected one of `;`\n" + "[screened]\n" * len(secrets) + "note: done\n")
        self.assertEqual(document["gates"][1]["screened_lines"], len(secrets))
        for gate in document["gates"]:
            for key in ("stdout_tail", "stderr_tail"):
                self.assertFalse(any(pattern.search(gate[key]) for pattern in subject.CREDENTIAL_PATTERNS))

    def test_assignment_split_across_lines_replaces_the_whole_tail(self):
        text, count = subject.screen_text("pass" + "word:\n" + "abcdefghijk\n")
        self.assertEqual(text, "[screened]\n")
        self.assertEqual(count, 2)
        self.assertEqual(subject.screen_text("plain output\n"), ("plain output\n", 0))
        self.assertEqual(subject.screen_text(""), ("", 0))

    def test_malformed_or_missing_gate_records_are_refused(self):
        def tamper(mutate):
            with tempfile.TemporaryDirectory() as directory:
                records = write_records(directory, failed_at=3)
                path = records / "gates.json"
                value = json.loads(path.read_text(encoding="ascii"))
                mutate(value)
                path.write_text(json.dumps(value), encoding="ascii")
                return refusal_reason(subject.build_payload, records, environment(), REQUEST)

        mutations = (
            lambda value: value.update(schema_version=2),
            lambda value: value.update(extra=1),
            lambda value: value.update(failed=0),
            lambda value: value.update(gate_count=1),
            lambda value: value.update(selected_gates=value["selected_gates"][:5]),
            lambda value: value.update(selected_gates=["Bad Name"] + value["selected_gates"][1:]),
            lambda value: value.update(selected_gates=[["format"]] + value["selected_gates"][1:]),
            lambda value: value.update(completed_gates=[]),
            lambda value: value["gates"].update(format="done"),
            lambda value: value.update(gates=[]),
        )
        for index, mutate in enumerate(mutations):
            with self.subTest(index=index):
                self.assertEqual(tamper(mutate), "records")
        with tempfile.TemporaryDirectory() as directory:
            records = write_records(directory)
            (records / "gates.json").unlink()
            self.assertEqual(refusal_reason(subject.build_payload, records, environment(), REQUEST), "records")
        with tempfile.TemporaryDirectory() as directory:
            records = write_records(directory)
            (records / "gates.json").write_bytes(b"x" * (subject.MAX_RECORD_BYTES + 1))
            self.assertEqual(refusal_reason(subject.build_payload, records, environment(), REQUEST), "records")
        with tempfile.TemporaryDirectory() as directory:
            records = write_records(directory)
            (records / "gates.json").write_bytes(b"[1]")
            self.assertEqual(refusal_reason(subject.build_payload, records, environment(), REQUEST), "records")

    def test_optional_records_may_be_absent_without_blocking_the_feedback(self):
        with tempfile.TemporaryDirectory() as directory:
            records = write_records(directory, failed_at=0)
            for name in ("merged.json", "gate-durations.json", "revocation.json", "gate-0.stderr"):
                (records / name).unlink()
            payload, selected, passed, failed = subject.build_payload(records, environment(), REQUEST)
        document = subject.unframe_payload(payload)
        self.assertEqual((selected, passed, failed), (13, 0, 1))
        self.assertIsNone(document["boundary"])
        self.assertIsNone(document["revocation"])
        self.assertIsNone(document["gates"][0]["duration_ms"])
        self.assertEqual(document["gates"][0]["stderr_tail"], "")

    @unittest.skipUnless(os.name == "posix" and hasattr(os, "symlink") and hasattr(os, "O_NOFOLLOW"), "needs POSIX links")
    def test_a_symlinked_record_is_refused(self):
        with tempfile.TemporaryDirectory() as directory:
            records = write_records(directory)
            target = Path(directory) / "elsewhere.json"
            target.write_bytes((records / "gates.json").read_bytes())
            (records / "gates.json").unlink()
            os.symlink(str(target), str(records / "gates.json"))
            self.assertEqual(refusal_reason(subject.build_payload, records, environment(), REQUEST), "records")

    def test_payload_binding_must_be_complete(self):
        with tempfile.TemporaryDirectory() as directory:
            records = write_records(directory)
            for name in ("CI_SHA", "REQUESTED_SOURCE_SHA", "REQUESTED_BASE_SHA", "REQUESTED_FINGERPRINT"):
                with self.subTest(name=name):
                    self.assertEqual(
                        refusal_reason(subject.build_payload, records, environment(**{name: ""}), REQUEST), "binding",
                    )


class BindingTests(unittest.TestCase):
    def test_request_binding_accepts_only_the_allowed_request_and_recipient(self):
        self.assertEqual(subject.request_binding(environment()), (REQUEST, SPKI, FINGERPRINT))
        cases = (
            ({"KD_QUICK_REQUEST_ID": "AB" * 32}, "request"),
            ({"KD_QUICK_REQUEST_ID": "ab" * 31}, "request"),
            ({"KD_QUICK_REQUEST_ID": "cd" * 32}, "request"),
            ({"KD_QUICK_ALLOWED_REQUEST_ID": ""}, "request"),
            ({"KD_QUICK_RECIPIENT_SPKI_B64": ""}, "recipient"),
            ({"KD_QUICK_RECIPIENT_SPKI_B64": SPKI.rstrip("=")}, "recipient"),
            ({"KD_QUICK_RECIPIENT_SPKI_B64": "!" * 688}, "recipient"),
            ({"KD_QUICK_RECIPIENT_SPKI_B64": base64.b64encode(b"\x30\x82" + b"a" * 10).decode("ascii")}, "recipient"),
            ({"KD_QUICK_RECIPIENT_SPKI_B64": base64.b64encode(b"\x31\x82" + b"a" * 300).decode("ascii")}, "recipient"),
            ({"KD_QUICK_RECIPIENT_SPKI_B64": base64.b64encode(b"\x30\x82" + b"a" * 5000).decode("ascii")}, "recipient"),
            ({"KD_QUICK_ALLOWED_RECIPIENT_FINGERPRINT": "0" * 64}, "recipient"),
            ({"KD_QUICK_ALLOWED_RECIPIENT_FINGERPRINT": FINGERPRINT.upper()}, "recipient"),
        )
        for updates, reason in cases:
            with self.subTest(updates=sorted(updates)):
                self.assertEqual(refusal_reason(subject.request_binding, environment(**updates)), reason)
        values = environment()
        del values["KD_QUICK_ALLOWED_RECIPIENT_FINGERPRINT"]
        self.assertEqual(refusal_reason(subject.request_binding, values), "recipient")

    def test_source_binding_requires_exact_shapes_and_the_first_attempt(self):
        self.assertEqual(subject.source_binding(environment())["base_branch"], "develop")
        cases = (
            {"CI_SHA": "a" * 39}, {"REQUESTED_SOURCE_SHA": "B" * 40}, {"REQUESTED_BASE_SHA": ""},
            {"REQUESTED_FINGERPRINT": "d" * 63}, {"REQUESTED_BASE_BRANCH": "main2"},
            {"REQUESTED_BASE_BRANCH": "untrusted"}, {"SOURCE_REPOSITORY_ID": "0"},
            {"SOURCE_REPOSITORY_ID": "7" * 17}, {"GITHUB_RUN_ID": "01"}, {"GITHUB_RUN_ATTEMPT": "2"},
        )
        for updates in cases:
            with self.subTest(updates=updates):
                self.assertEqual(refusal_reason(subject.source_binding, environment(**updates)), "binding")

    def test_context_binding_accepts_only_the_registered_nonce_and_a_bounded_expiry(self):
        self.assertEqual(subject.context_binding(environment()), (NONCE, int(EXPIRY)))
        cases = (
            {"KD_QUICK_ALLOWED_NONCE": ""}, {"KD_QUICK_ALLOWED_NONCE": "AB" * 32},
            {"KD_QUICK_ALLOWED_NONCE": "07" * 31}, {"KD_QUICK_ALLOWED_EXPIRY": ""},
            {"KD_QUICK_ALLOWED_EXPIRY": "0"}, {"KD_QUICK_ALLOWED_EXPIRY": "01800003600"},
            {"KD_QUICK_ALLOWED_EXPIRY": "x"}, {"KD_QUICK_ALLOWED_EXPIRY": str(subject.EXCEPTION_END + 1)},
        )
        for updates in cases:
            with self.subTest(updates=updates):
                self.assertEqual(refusal_reason(subject.context_binding, environment(**updates)), "request")
                self.assertEqual(refusal_reason(subject.run_preflight, environment(**updates)), "request")
        values = environment()
        del values["KD_QUICK_ALLOWED_NONCE"]
        self.assertEqual(refusal_reason(subject.context_binding, values), "request")

    def test_preflight_prints_one_fixed_line_and_never_the_recipient_key(self):
        line = subject.run_preflight(environment())
        self.assertEqual(
            line,
            "KD-LINUX-QUICK-PREFLIGHT schema=1 request-id=" + REQUEST + " tier=quick admission=never status=verified",
        )
        output = io.StringIO()
        self.assertEqual(subject.main(["preflight"], environment(), output), 0)
        self.assertEqual(output.getvalue(), line + "\n")
        self.assertNotIn(SPKI, output.getvalue())
        output = io.StringIO()
        self.assertEqual(subject.main(["preflight"], environment(KD_QUICK_ALLOWED_REQUEST_ID="0" * 64), output), 1)
        self.assertEqual(
            output.getvalue(), "KD-LINUX-QUICK-REFUSAL schema=1 tier=quick admission=never reason=request\n",
        )
        self.assertNotIn(SPKI, output.getvalue())


class CryptoTests(unittest.TestCase):
    def payload(self):
        return subject.frame_payload(b"{}")

    def test_crypto_input_binds_the_untrusted_quick_profile_and_a_bounded_expiry(self):
        binding = subject.source_binding(environment())
        record = subject.crypto_input(self.payload(), REQUEST, SPKI, FINGERPRINT, binding, 1800000000, "07" * 32)
        self.assertEqual(set(record), {"schema_version", "kind", "payload_b64", "context", "recipient_spki_b64", "now"})
        self.assertEqual(record["schema_version"], 1)
        self.assertEqual(record["kind"], "linux_quick")
        self.assertEqual(record["now"], 1800000000)
        self.assertEqual(record["recipient_spki_b64"], SPKI)
        self.assertEqual(base64.b64decode(record["payload_b64"]), self.payload())
        context = record["context"]
        self.assertEqual(
            set(context),
            {
                "request_id", "nonce", "recipient_fingerprint", "concern", "kind", "repository_id",
                "source_sha", "base_sha", "control_sha", "base_branch", "reviewed_diff_sha256",
                "workflow_ref", "run_id", "producer_job", "run_attempt", "expiry",
            },
        )
        self.assertEqual(context["concern"], "core-linux-quick-return")
        self.assertEqual(context["kind"], "linux_quick")
        self.assertEqual(context["workflow_ref"], "refs/heads/untrusted")
        self.assertEqual(context["producer_job"], "core-linux-quick-return-producer")
        self.assertEqual(context["run_attempt"], 1)
        self.assertEqual(context["run_id"], "4242")
        self.assertEqual(context["repository_id"], "77")
        self.assertEqual(context["recipient_fingerprint"], FINGERPRINT)
        self.assertEqual(context["nonce"], "07" * 32)
        self.assertGreater(context["expiry"], record["now"])
        self.assertLess(context["expiry"] - record["now"], 24 * 60 * 60)

    def test_crypto_input_uses_the_bound_expiry_and_refuses_one_outside_the_window(self):
        binding = subject.source_binding(environment())
        now = 1800000000
        record = subject.crypto_input(self.payload(), REQUEST, SPKI, FINGERPRINT, binding, now, NONCE, now + 3600)
        self.assertEqual(record["context"]["expiry"], now + 3600)
        for expiry in (now, now - 1, now + 24 * 60 * 60 + 1, subject.EXCEPTION_END + 1, "1800003600", True):
            with self.subTest(expiry=expiry):
                self.assertEqual(
                    refusal_reason(
                        subject.crypto_input, self.payload(), REQUEST, SPKI, FINGERPRINT, binding, now, NONCE, expiry,
                    ),
                    "request",
                )

    def test_crypto_input_refuses_an_unpadded_payload_and_a_bad_nonce(self):
        binding = subject.source_binding(environment())
        self.assertEqual(
            refusal_reason(subject.crypto_input, b"short", REQUEST, SPKI, FINGERPRINT, binding, 1, "07" * 32), "payload",
        )
        self.assertEqual(
            refusal_reason(subject.crypto_input, self.payload(), REQUEST, SPKI, FINGERPRINT, binding, 1, "07"), "payload",
        )

    def test_encryptor_is_run_with_a_minimal_environment_and_its_output_is_checked(self):
        calls = []

        def runner(arguments, **keywords):
            calls.append((arguments, keywords))
            return types.SimpleNamespace(returncode=0, stdout=b"KDLE" + b"x" * 40, stderr=b"")

        record = {"schema_version": 1, "kind": "linux_quick"}
        node = Path(tempfile.gettempdir()) / "node-bin" / "node"
        helper = Path(tempfile.gettempdir()) / "control" / "feedback_producer_crypto.mjs"
        self.assertEqual(subject.encrypt_payload(record, node, helper, runner), b"KDLE" + b"x" * 40)
        arguments, keywords = calls[0]
        self.assertEqual(arguments, (str(node), str(helper)))
        self.assertEqual(json.loads(keywords["input"].decode("ascii")), record)
        self.assertEqual(set(keywords["env"]), {"PATH", "HOME", "LANG", "LC_ALL"})
        self.assertEqual(keywords["env"]["PATH"], str(node.parent))
        self.assertFalse(keywords["check"])
        self.assertTrue(keywords["close_fds"])
        self.assertLessEqual(keywords["timeout"], 120)

    def test_encryptor_failures_are_closed_and_carry_no_detail(self):
        node = Path(tempfile.gettempdir()) / "node-bin" / "node"
        helper = Path(tempfile.gettempdir()) / "control" / "feedback_producer_crypto.mjs"

        def outcome(**fields):
            values = {"returncode": 0, "stdout": b"KDLE" + b"x", "stderr": b""}
            values.update(fields)
            return lambda arguments, **keywords: types.SimpleNamespace(**values)

        def raises(error):
            def runner(arguments, **keywords):
                raise error
            return runner

        cases = (
            (outcome(returncode=1), "encryptor"),
            (outcome(stderr=b"KD-FEEDBACK-ENCRYPTION-REFUSAL unsupported_kind\n"), "encryptor"),
            (outcome(stdout=b""), "encryptor"),
            (outcome(stdout=b"nope"), "encryptor"),
            (outcome(stdout=b"KDLE" + b"x" * subject.MAX_CIPHERTEXT_BYTES), "limit"),
            (raises(OSError()), "encryptor"),
            (raises(subject.subprocess.TimeoutExpired("node", 1)), "encryptor"),
        )
        for index, (runner, reason) in enumerate(cases):
            with self.subTest(index=index):
                self.assertEqual(
                    refusal_reason(subject.encrypt_payload, {"kind": "linux_quick"}, node, helper, runner), reason,
                )
        self.assertEqual(
            refusal_reason(subject.encrypt_payload, {}, Path("node"), helper, outcome()), "encryptor",
        )
        self.assertEqual(
            refusal_reason(subject.encrypt_payload, {}, Path(tempfile.gettempdir()) / "node-bin" / "other", helper, outcome()), "encryptor",
        )
        self.assertEqual(
            refusal_reason(subject.encrypt_payload, {"pad": "x" * subject.MAX_NODE_INPUT_BYTES}, node, helper, outcome()),
            "limit",
        )

    def test_the_encryptor_is_the_reviewed_producer_helper_in_the_shared_confinement_kit(self):
        helper = Path(subject.__file__).resolve().parents[1] / "kit" / "confinement" / "feedback_producer_crypto.mjs"
        self.assertTrue(helper.is_file())


class OutputTests(unittest.TestCase):
    @POSIX_OUTPUT
    def test_ciphertext_is_staged_once_as_a_read_only_member_in_a_private_directory(self):
        data = b"KDLE" + b"y" * 1000
        with tempfile.TemporaryDirectory() as directory:
            digest = subject.write_ciphertext(directory, data, os.getuid(), os.getgid())
            self.assertEqual(digest, hashlib.sha256(data).hexdigest())
            staged = Path(directory) / "kd-quick-upload"
            member = staged / "linux-quick-return-v1.enc"
            self.assertEqual(stat.S_IMODE(staged.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(member.stat().st_mode), 0o400)
            self.assertEqual(member.read_bytes(), data)
            self.assertEqual(sorted(path.name for path in staged.iterdir()), ["linux-quick-return-v1.enc"])
            self.assertEqual(
                refusal_reason(subject.write_ciphertext, directory, data, os.getuid(), os.getgid()), "output",
            )

    @POSIX_OUTPUT
    def test_invalid_ciphertext_or_ids_are_refused_before_anything_is_written(self):
        with tempfile.TemporaryDirectory() as directory:
            for data, uid, gid in (
                (b"", 0, 0), ("text", 0, 0), (b"x" * (subject.MAX_CIPHERTEXT_BYTES + 1), 0, 0),
                (b"KDLE", "0", 0), (b"KDLE", 0, None),
            ):
                with self.subTest(uid=uid, gid=gid):
                    self.assertEqual(refusal_reason(subject.write_ciphertext, directory, data, uid, gid), "output")
            self.assertEqual(list(Path(directory).iterdir()), [])
            self.assertEqual(
                refusal_reason(subject.write_ciphertext, str(Path(directory) / "missing"), b"KDLE", 0, 0), "output",
            )


class CommandTests(unittest.TestCase):
    ARGUMENTS = ["encrypt", "--reader-uid", "1000", "--reader-gid", "1000"]

    def staged_environment(self, directory, **updates):
        output = Path(directory) / "github-output"
        output.write_text("", encoding="ascii")
        return environment(
            RUNNER_TEMP=directory, NODE_BIN=os.sep + "opt" + os.sep + "node-bin", GITHUB_OUTPUT=str(output), **updates,
        )

    def fixed_clock(self):
        original = subject.run_encrypt
        return patch.object(
            subject, "run_encrypt", lambda env, arguments: original(env, arguments, clock=lambda: 1800000000.9),
        )

    @POSIX_OUTPUT
    def test_encrypt_builds_the_payload_calls_the_helper_once_and_stages_the_member(self):
        with tempfile.TemporaryDirectory() as directory:
            write_records(directory, failed_at=4)
            env = self.staged_environment(directory)
            ciphertext = b"KDLE" + b"z" * 64
            with patch.object(subject, "encrypt_payload", return_value=ciphertext) as encrypt:
                result = subject.run_encrypt(
                    env, ["--reader-uid", str(os.getuid()), "--reader-gid", str(os.getgid())],
                    clock=lambda: 1800000000.9,
                )
            self.assertIsNone(result)
            self.assertEqual(encrypt.call_count, 1)
            record, node, helper = encrypt.call_args.args
            self.assertEqual(node, Path(os.sep + "opt" + os.sep + "node-bin") / "node")
            self.assertEqual(helper.name, "feedback_producer_crypto.mjs")
            self.assertEqual(record["now"], 1800000000)
            self.assertEqual(record["context"]["nonce"], NONCE)
            self.assertEqual(record["context"]["expiry"], int(EXPIRY))
            self.assertEqual(record["context"]["request_id"], REQUEST)
            document =subject.unframe_payload(base64.b64decode(record["payload_b64"]))
            self.assertEqual(document["gates_passed"], 4)
            self.assertEqual(document["gates"][4]["outcome"], "failed")
            member = Path(directory) / "kd-quick-upload" / "linux-quick-return-v1.enc"
            self.assertEqual(member.read_bytes(), ciphertext)
            lines = Path(env["GITHUB_OUTPUT"]).read_text(encoding="ascii").splitlines()
            self.assertEqual(
                lines,
                [
                    "gates_selected=13", "gates_passed=4", "gates_failed=1",
                    "ciphertext_sha256=" + hashlib.sha256(ciphertext).hexdigest(),
                ],
            )

    def test_a_refused_encryption_prints_one_closed_line_and_stages_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            write_records(directory)
            env = self.staged_environment(directory)
            for reason in ("encryptor", "limit"):
                output = io.StringIO()
                with self.fixed_clock(), patch.object(subject, "encrypt_payload", side_effect=subject.QuickRefusal(reason)):
                    self.assertEqual(subject.main(self.ARGUMENTS, env, output), 1)
                self.assertEqual(
                    output.getvalue(),
                    "KD-LINUX-QUICK-REFUSAL schema=1 tier=quick admission=never reason=" + reason + "\n",
                )
            self.assertFalse((Path(directory) / "kd-quick-upload").exists())
            self.assertEqual(Path(env["GITHUB_OUTPUT"]).read_text(encoding="ascii"), "")

    def test_unexpected_failures_never_leak_detail(self):
        with tempfile.TemporaryDirectory() as directory:
            write_records(directory)
            env = self.staged_environment(directory)
            output = io.StringIO()
            with self.fixed_clock(), patch.object(subject, "encrypt_payload", side_effect=RuntimeError(SPKI)):
                self.assertEqual(subject.main(self.ARGUMENTS, env, output), 1)
            self.assertEqual(
                output.getvalue(), "KD-LINUX-QUICK-REFUSAL schema=1 tier=quick admission=never reason=invalid\n",
            )

    def test_missing_records_or_toolchain_stop_before_the_helper_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            env = self.staged_environment(directory)
            with patch.object(subject, "encrypt_payload") as encrypt:
                output = io.StringIO()
                self.assertEqual(subject.main(self.ARGUMENTS, env, output), 1)
                self.assertIn("reason=records", output.getvalue())
                output = io.StringIO()
                self.assertEqual(subject.main(self.ARGUMENTS, dict(env, NODE_BIN=""), output), 1)
                self.assertIn("reason=binding", output.getvalue())
            encrypt.assert_not_called()

    def test_usage_errors_are_closed(self):
        output = io.StringIO()
        self.assertEqual(subject.main([], environment(), output), 2)
        self.assertIn("reason=usage", output.getvalue())
        for arguments in (
            ["unknown"], ["preflight", "extra"], ["record", "extra"], ["encrypt"],
            ["encrypt", "--reader-uid", "1", "--reader-gid"],
            ["encrypt", "--reader-gid", "1", "--reader-uid", "1"],
            ["encrypt", "--reader-uid", "-1", "--reader-gid", "1"],
            ["encrypt", "--reader-uid", "1", "--reader-gid", "1", "--more", "1"],
        ):
            with self.subTest(arguments=arguments):
                output = io.StringIO()
                self.assertEqual(subject.main(arguments, environment(), output), 1)
                self.assertEqual(
                    output.getvalue(),
                    "KD-LINUX-QUICK-REFUSAL schema=1 tier=quick admission=never reason=usage\n",
                )


class PublicLineTests(unittest.TestCase):
    LINE = re.compile(
        r"KD-LINUX-QUICK schema=1 request-id=[a-f0-9]{64} tier=quick admission=never"
        r" gates-selected=[0-9]{1,2} gates-passed=[0-9]{1,2} failed=[0-9]{1,2} status=encrypted\Z"
    )

    def test_the_public_line_is_fixed_and_carries_only_counts(self):
        line = subject.quick_line(REQUEST, 13, 12, 1)
        self.assertEqual(
            line,
            "KD-LINUX-QUICK schema=1 request-id=" + REQUEST
            + " tier=quick admission=never gates-selected=13 gates-passed=12 failed=1 status=encrypted",
        )
        self.assertRegex(line, self.LINE)
        self.assertTrue(line.isascii())
        self.assertNotIn(chr(35), line)

    def test_invalid_counts_or_identity_are_refused(self):
        for arguments in (
            ("short", 13, 13, 0), (REQUEST, 19, 1, 0), (REQUEST, 13, 14, 0), (REQUEST, 13, 1, 14),
            (REQUEST, 13, -1, 0), (REQUEST, 13, True, 0), (REQUEST, "13", 1, 0), (None, 13, 1, 0),
        ):
            with self.subTest(arguments=arguments):
                self.assertEqual(refusal_reason(subject.quick_line, *arguments), "invalid")

    def test_record_reads_the_counts_from_the_environment_and_prints_the_line(self):
        env = {
            "KD_QUICK_REQUEST_ID": REQUEST, "KD_QUICK_GATES_SELECTED": "16",
            "KD_QUICK_GATES_PASSED": "16", "KD_QUICK_GATES_FAILED": "0",
        }
        output = io.StringIO()
        self.assertEqual(subject.main(["record"], env, output), 0)
        self.assertEqual(output.getvalue(), subject.quick_line(REQUEST, 16, 16, 0) + "\n")
        for name, value in (
            ("KD_QUICK_GATES_SELECTED", "01"), ("KD_QUICK_GATES_PASSED", ""),
            ("KD_QUICK_GATES_FAILED", "x"), ("KD_QUICK_GATES_PASSED", "19"),
        ):
            with self.subTest(name=name, value=value):
                output = io.StringIO()
                self.assertEqual(subject.main(["record"], dict(env, **{name: value}), output), 1)
                self.assertEqual(
                    output.getvalue(),
                    "KD-LINUX-QUICK-REFUSAL schema=1 tier=quick admission=never reason=invalid\n",
                )

    def test_refusal_reasons_are_a_closed_vocabulary(self):
        self.assertEqual(
            subject.refusal_line("anything else"),
            "KD-LINUX-QUICK-REFUSAL schema=1 tier=quick admission=never reason=invalid",
        )
        for reason in subject.REASONS:
            self.assertRegex(subject.refusal_line(reason), r"reason=[a-z]+\Z")


class SourceShapeTests(unittest.TestCase):
    def test_module_is_standalone_commentless_and_never_emits_an_admission_verdict(self):
        source = (Path(subject.__file__)).read_text(encoding="utf-8")
        self.assertNotIn(chr(35), source)
        self.assertTrue(source.isascii())
        imports = set(re.findall(r"(?m)^(?:import|from) ([a-z0-9_]+)", source))
        self.assertEqual(
            imports,
            {"base64", "hashlib", "json", "os", "re", "stat", "subprocess", "sys", "time", "pathlib"},
        )
        for forbidden in ("run_accepted", "confinement_verdict", "admission=accepted", "KD-CONFINEMENT"):
            self.assertNotIn(forbidden, source)
        self.assertEqual(subject.TIER, "quick")
        self.assertEqual(subject.ADMISSION, "never")
        self.assertLessEqual(subject.PADDED_BYTES, 4 * 1024 * 1024 - 64 * 1024)
        self.assertLessEqual(subject.MAX_CIPHERTEXT_BYTES, 4 * 1024 * 1024)

    def test_stream_budget_fits_the_payload_before_escaping(self):
        self.assertLess(2 * subject.MAX_GATES * subject.STREAM_TAIL_BYTES, subject.MAX_BODY_BYTES)
        self.assertEqual(subject.MIN_GATES, 13)
        self.assertEqual(subject.MAX_GATES, 18)


if __name__ == "__main__":
    unittest.main(verbosity=2)
