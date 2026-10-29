import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import test_macos_feedback_producer as base


CONTROL_DIRECTORY = Path(__file__).resolve().parent
producer = base.producer
NODE = shutil.which("node")
REAL_NODE = NODE is not None and sys.platform in ("darwin", "linux")
KEY_SCRIPT = (
    "const c = require('node:crypto');"
    "const k = c.generateKeyPairSync('rsa', {modulusLength: 3072, publicExponent: 65537});"
    "process.stdout.write(k.publicKey.export({type: 'spki', format: 'der'}));"
)


def load_module(name):
    path = CONTROL_DIRECTORY / (name + ".py")
    spec = importlib.util.spec_from_file_location(name + "_limits_under_test", str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def synthetic_rust_patch(maximum):
    chunks = []
    paths = []
    total = 0
    pairs = 500
    while len(paths) < 400:
        path = "crates/host/api/src/limit_%03d.rs" % len(paths)
        body = "".join(
            "-    let value_%06d = old_call_with_padding_%06d(1);\n" % (index, index)
            + "+    let value_%06d = new_call_with_padding_%06d(2);\n" % (index, index)
            for index in range(pairs)
        )
        chunk = (
            "diff --git a/%s b/%s\n--- a/%s\n+++ b/%s\n@@ -1,%d +1,%d @@\n" % (path, path, path, path, pairs, pairs)
            + body
        ).encode("ascii")
        if total + len(chunk) > maximum:
            break
        chunks.append(chunk)
        paths.append(path)
        total += len(chunk)
    return b"".join(chunks), paths


class Helpers(object):
    def call_without_plain_exceptions(self, name, function):
        try:
            return function()
        except producer.FeedbackRefusal as refusal:
            return refusal
        except Exception as error:
            self.fail("plain exception %s escaped %s: %s" % (type(error).__name__, name, error))

    def dispatch(self, spki=None):
        context = mock.patch.object(base, "SPKI", base.SPKI if spki is None else spki)
        with context:
            unused_request, environment = base._dispatch("rust_patch")
            return producer.validate_dispatch("rust_patch", environment, now=base.NOW)

    def refusal_for(self, payload, paths, run_result=None, input_error=None):
        dispatch = self.dispatch()
        result = {"payload_bytes": payload, "reviewed_rust_paths": paths}
        node = Path(NODE or "/usr/bin/node")
        runner = mock.patch.object(producer.subprocess, "run", return_value=run_result)
        if input_error is not None:
            runner = mock.patch.object(producer.subprocess, "run", side_effect=input_error)
        with runner, mock.patch.object(producer.time, "time", return_value=base.NOW):
            return self.call_without_plain_exceptions(
                "encrypt_after_cleanup",
                lambda: producer.encrypt_after_cleanup(dispatch, result, node))



class OutputPathRefusals(Helpers, unittest.TestCase):
    def test_node_refusal_codes_map_to_fixed_details_and_unknown_text_stays_generic(self):
        paths = ["crates/host/api/src/lib.rs"]
        cases = (
            (b"KD-FEEDBACK-ENCRYPTION-REFUSAL credential_like_content\n", "node_credential_like_content"),
            (b"KD-FEEDBACK-ENCRYPTION-REFUSAL limit_exceeded\n", "node_limit_exceeded"),
            (b"KD-FEEDBACK-ENCRYPTION-REFUSAL invalid_rust_patch\n", "node_invalid_rust_patch"),
            (b"KD-FEEDBACK-ENCRYPTION-REFUSAL\n", "node_exit"),
            (b"KD-FEEDBACK-ENCRYPTION-REFUSAL free text with a path\n", "node_exit"),
            (b"unexpected warning text\n", "node_exit"),
        )
        for stderr, detail in cases:
            with self.subTest(detail=detail, stderr=stderr[:40]):
                outcome = self.refusal_for(
                    b"diff", paths, SimpleNamespace(returncode=1, stdout=b"", stderr=stderr))
                self.assertIsInstance(outcome, producer.FeedbackRefusal)
                self.assertEqual((outcome.reason, outcome.detail), ("payload_invalid", detail))

    def test_every_encrypt_failure_site_has_its_own_detail(self):
        paths = ["crates/host/api/src/lib.rs"]
        outcome = self.refusal_for(
            b"diff", paths, SimpleNamespace(returncode=0, stdout=b"not an envelope", stderr=b""))
        self.assertEqual(outcome.detail, "output_shape")
        outcome = self.refusal_for(
            b"diff", paths,
            SimpleNamespace(returncode=0, stdout=b"KDLE" + b"x" * producer.MAX_CIPHERTEXT_BYTES, stderr=b""))
        self.assertEqual(outcome.detail, "output_size")
        outcome = self.refusal_for(b"diff", paths, input_error=OSError("spawn"))
        self.assertEqual(outcome.detail, "spawn")
        outcome = self.refusal_for(b"a" * (5 * 1024 * 1024), paths, SimpleNamespace(
            returncode=0, stdout=b"", stderr=b""))
        self.assertEqual(outcome.detail, "input_size")
        outcome = self.refusal_for(b"", paths, SimpleNamespace(returncode=0, stdout=b"", stderr=b""))
        self.assertEqual(outcome.detail, "payload_missing")

    def test_output_write_refusals_carry_details_and_never_plain_exceptions(self):
        dispatch = self.dispatch()
        member = dispatch["profile"]["member_name"]
        with tempfile.TemporaryDirectory() as temporary:
            outcome = self.call_without_plain_exceptions(
                "write_output",
                lambda: producer.write_output(Path(temporary), dispatch, b"KDLE" + b"x" * 64))
            if isinstance(outcome, producer.FeedbackRefusal):
                self.assertEqual(outcome.reason, "output_unavailable")
                self.assertIn(outcome.detail, ("output_write", "output_directory"))
        outcome = self.call_without_plain_exceptions(
            "write_output", lambda: producer.write_output(Path("/nonexistent"), dispatch, b""))
        self.assertIsInstance(outcome, producer.FeedbackRefusal)
        self.assertEqual(outcome.detail, "output_member")
        self.assertEqual(member, "rust-format-return-v1.enc")

    def test_maximum_size_ciphertext_reaches_the_write_without_a_plain_exception(self):
        dispatch = self.dispatch()
        ciphertext = b"KDLE" + b"x" * (producer.MAX_CIPHERTEXT_BYTES - 4)
        with tempfile.TemporaryDirectory() as temporary:
            outcome = self.call_without_plain_exceptions(
                "write_output", lambda: producer.write_output(Path(temporary), dispatch, ciphertext))
        if isinstance(outcome, producer.FeedbackRefusal):
            self.assertIn(outcome.detail, ("output_write", "output_directory"))
        else:
            self.assertEqual(outcome["member_size"], producer.MAX_CIPHERTEXT_BYTES)
        too_large = self.call_without_plain_exceptions(
            "write_output", lambda: producer.write_output(Path("/nonexistent"), dispatch, ciphertext + b"x"))
        self.assertEqual(too_large.detail, "output_member")


@unittest.skipUnless(REAL_NODE, "a node executable is required for the real encryption path")
class NearLimitPatchThroughRealEncryption(Helpers, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = subprocess.run(
            [NODE, "-e", KEY_SCRIPT], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=120, check=False)
        if result.returncode != 0 or not result.stdout:
            raise unittest.SkipTest("the node runtime could not generate a recipient key")
        cls.spki = result.stdout

    def test_a_patch_near_the_byte_limit_encrypts_within_the_ciphertext_frame(self):
        patch, paths = synthetic_rust_patch(producer.MAX_PATCH_BYTES)
        self.assertLessEqual(len(patch), producer.MAX_PATCH_BYTES)
        self.assertGreater(len(patch), producer.MAX_PATCH_BYTES - 60_000)
        self.assertLessEqual(patch.count(b"\n"), 131_072)
        dispatch = self.dispatch(self.spki)
        result = {"payload_bytes": patch, "reviewed_rust_paths": paths}
        with mock.patch.object(producer.time, "time", return_value=base.NOW):
            outcome = self.call_without_plain_exceptions(
                "encrypt_after_cleanup",
                lambda: producer.encrypt_after_cleanup(dispatch, result, Path(NODE)))
        self.assertNotIsInstance(
            outcome, producer.FeedbackRefusal,
            "near-limit patch was refused with detail %r" % getattr(outcome, "detail", None))
        self.assertEqual(outcome[:4], b"KDLE")
        self.assertLessEqual(len(outcome), producer.MAX_CIPHERTEXT_BYTES)

    def test_credential_like_patch_text_is_reported_by_its_node_reason(self):
        patch, paths = synthetic_rust_patch(200_000)
        patch = patch.replace(
            b"-    let value_000001 = old_call_with_padding_000001(1);\n",
            b"-    let token = CancellationToken::new();\n", 1)
        dispatch = self.dispatch(self.spki)
        result = {"payload_bytes": patch, "reviewed_rust_paths": paths}
        with mock.patch.object(producer.time, "time", return_value=base.NOW):
            outcome = self.call_without_plain_exceptions(
                "encrypt_after_cleanup",
                lambda: producer.encrypt_after_cleanup(dispatch, result, Path(NODE)))
        self.assertIsInstance(outcome, producer.FeedbackRefusal)
        self.assertEqual(outcome.detail, "node_credential_like_content")


class SuccessReceiptDiagnosticTests(unittest.TestCase):
    def test_producer_core_and_audit_detail_tables_are_identical(self):
        core = load_module("macos_core_contract")
        audit = load_module("macos_public_audit")
        details = producer.ENCRYPT_DETAILS | producer.NODE_DETAILS
        self.assertEqual(set(core.SUCCESS_RECEIPT_DETAILS), details)
        self.assertEqual(
            core.SUCCESS_RECEIPT_DIAGNOSTICS, frozenset("success_receipt_" + name for name in details))
        self.assertEqual(
            audit.CORE_CONTRACT_SUCCESS_RECEIPT_DIAGNOSTICS, core.SUCCESS_RECEIPT_DIAGNOSTICS)
        self.assertLessEqual(core.SUCCESS_RECEIPT_DIAGNOSTICS, core.DIAGNOSTICS)
        self.assertLessEqual(
            audit.CORE_CONTRACT_SUCCESS_RECEIPT_DIAGNOSTICS, audit.CORE_CONTRACT_REFUSAL_DIAGNOSTICS)

    def test_success_receipt_diagnostics_survive_attach_formatting_and_normalisation(self):
        core = load_module("macos_core_contract")
        failure_module = load_module("feedback_failure")
        token = "success_receipt_node_credential_like_content"
        failure = core.Refusal("internal_error", "internal", diagnostic=token)
        attached = core._FailureDiagnostics().attach(failure, failure.diagnostic)
        self.assertEqual(attached.diagnostic, token)
        payload = core._format_refusal(attached)
        raw = b"KD-FEEDBACK-PRODUCER-REFUSAL " + payload + b"\n"
        self.assertEqual(failure_module.normalize_refusal(raw), raw)
        other = core.Refusal("runner_unavailable", "receipt", diagnostic=token)
        self.assertNotEqual(core._FailureDiagnostics().attach(other, other.diagnostic).diagnostic, token)

    def test_refusal_detail_is_limited_to_the_fixed_tables(self):
        self.assertIsNone(producer.FeedbackRefusal("payload_invalid", "free text").detail)
        self.assertIsNone(producer.FeedbackRefusal("payload_invalid").detail)
        self.assertEqual(producer.FeedbackRefusal("payload_invalid", "spawn").detail, "spawn")
        self.assertEqual(
            producer._node_detail(b"KD-FEEDBACK-ENCRYPTION-REFUSAL limit_exceeded\n"), "node_limit_exceeded")
        self.assertEqual(producer._node_detail(b"\xff\xfe"), "node_exit")


if __name__ == "__main__":
    unittest.main(verbosity=2)
