"""Hosted end-to-end coverage for the owner feedback release path."""

import base64
import copy
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

try:
    from . import feedback_admin, feedback_request, node_lock_receipt
    from .test_feedback_api import ProviderShapedAPI
except ImportError:
    import feedback_admin
    import feedback_request
    import node_lock_receipt
    from test_feedback_api import ProviderShapedAPI


NOW = 1_800_000_000
PROTECTED_REPOSITORY_ID = "1430959909"
CI_REPOSITORY_ID = 1
ACTOR_LOGIN = "fixture-actor"
MAX_NODE_BYTES = 8 * 1024 * 1024
NODE_ENCRYPT_SCRIPT = r"""
import { createPublicKey } from 'node:crypto';
const chunks = [];
let size = 0;
for await (const chunk of process.stdin) {
  size += chunk.byteLength;
  if (size > 8 * 1024 * 1024) throw new Error('fixture input exceeds limit');
  chunks.push(chunk);
}
const input = JSON.parse(Buffer.concat(chunks, size).toString('utf8'));
const { encryptDevelopmentFeedback } = await import(input.module_url);
const publicKey = createPublicKey({
  key: Buffer.from(input.public_spki_base64, 'base64'), format: 'der', type: 'spki',
});
const envelope = encryptDevelopmentFeedback({
  payloadBytes: Buffer.from(input.payload_base64, 'base64'),
  context: input.context,
  recipientPublicKey: publicKey,
  expectedManifest: input.expected_manifest,
  now: input.now,
});
process.stdout.write(Buffer.from(envelope).toString('base64'));
"""

LOCK_EXPECTATION = {
    "root": {
        "name": "fixture-root",
        "version": "1.0.0",
        "workspaces": ["packages/*"],
        "devDependencies": {"typescript": "6.0.3"},
    },
    "workspaces": [
        {
            "path": "packages/client-api",
            "name": "@fixture/client-api",
            "version": "1.0.0",
            "dependencies": {"@fixture/shared": "1.0.0"},
        },
        {"path": "packages/shared", "name": "@fixture/shared", "version": "1.0.0"},
    ],
}


def _lock_bytes():
    lock = {
        "name": "fixture-root",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {
                "name": "fixture-root",
                "version": "1.0.0",
                "workspaces": ["packages/*"],
                "devDependencies": {"typescript": "6.0.3"},
            },
            "packages/client-api": {
                "name": "@fixture/client-api",
                "version": "1.0.0",
                "dependencies": {"@fixture/shared": "1.0.0"},
            },
            "packages/shared": {"name": "@fixture/shared", "version": "1.0.0"},
            "node_modules/@fixture/client-api": {"resolved": "packages/client-api", "link": True},
            "node_modules/@fixture/shared": {"resolved": "packages/shared", "link": True},
            "node_modules/typescript": {
                "version": "6.0.3",
                "resolved": "https://registry.npmjs.org/typescript/-/typescript-6.0.3.tgz",
                "integrity": "sha512-" + "A" * 86 + "==",
            },
        },
    }
    return (json.dumps(lock, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")


class EncryptedProviderShapedAPI(ProviderShapedAPI):
    def __init__(self, request, now):
        self.encrypted_frame = b"fixture-frame-pending"
        super().__init__(request, now)

    def _archive(self, request):
        profile = feedback_request.PROFILES[request["concern"]]
        result = io.BytesIO()
        with zipfile.ZipFile(result, "w", compression=zipfile.ZIP_STORED) as archive:
            info = zipfile.ZipInfo(profile["member_name"])
            info.create_system = 3
            info.external_attr = 0o600 << 16
            archive.writestr(info, self.encrypted_frame)
        return result.getvalue()

    def replace_frame(self, frame):
        self.encrypted_frame = bytes(frame)
        self.archive = self._archive(self.request_record)
        self.logs = self._logs()


def _qualified_node_runtime():
    candidate = shutil.which("node")
    if candidate is None:
        raise AssertionError("pinned Node runtime is unavailable")
    path = os.path.realpath(candidate)
    version = subprocess.run(
        [path, "--version"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, cwd=os.sep, env={"PATH": os.defpath},
        timeout=5, check=False, close_fds=True,
    )
    if version.returncode != 0 or version.stdout not in (b"v24.22.1\n", b"v24.22.1\r\n"):
        raise AssertionError("hosted integration requires the pinned Node release")
    digest = hashlib.sha256()
    size = 0
    with open(path, "rb") as runtime:
        while True:
            chunk = runtime.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > feedback_admin.MAX_RUNTIME_BYTES:
                raise AssertionError("pinned Node runtime exceeds the configured bound")
            digest.update(chunk)
    return path, digest.hexdigest()


def _encrypt_fixture(node_path, public_spki_base64, context, now):
    module_url = Path(__file__).resolve().with_name("development_feedback.mjs").as_uri()
    payload = _lock_bytes()
    message = {
        "module_url": module_url,
        "public_spki_base64": public_spki_base64,
        "context": context,
        "expected_manifest": LOCK_EXPECTATION,
        "now": now,
        "payload_base64": base64.b64encode(payload).decode("ascii"),
    }
    encoded = json.dumps(message, separators=(",", ":")).encode("ascii")
    if len(encoded) > MAX_NODE_BYTES:
        raise AssertionError("synthetic encryption input exceeds the configured bound")
    result = subprocess.run(
        [node_path, "--input-type=module", "-e", NODE_ENCRYPT_SCRIPT],
        input=encoded, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        cwd=os.sep, env={"PATH": os.defpath}, timeout=60, check=False, close_fds=True,
    )
    if result.returncode != 0 or not result.stdout:
        raise AssertionError("the pinned Node encryption fixture failed")
    try:
        frame = base64.b64decode(result.stdout, validate=True)
    except Exception as error:
        raise AssertionError("the pinned Node encryption fixture returned invalid bytes") from error
    if not frame or base64.b64encode(frame) != result.stdout:
        raise AssertionError("the pinned Node encryption fixture returned noncanonical bytes")
    return frame


def _context_for(request, api):
    profile = feedback_request.PROFILES[request["concern"]]
    context = {
        name: request[name]
        for name in node_lock_receipt.CONTEXT_FIELDS
        if name in request
    }
    context.update({
        "run_id": str(api.run_id),
        "producer_job": profile["producer_job"],
        "run_attempt": 1,
    })
    return context


def _summary_review(request, api, job_names):
    return {
        "confirmed": True,
        "request_id": request["request_id"],
        "protected_repository_id": request["repository_id"],
        "protected_ref": request["workflow_ref"],
        "source_sha": request["source_sha"],
        "control_sha": request["control_sha"],
        "run_id": api.run_id,
        "run_attempt": 1,
        "artifact_id": api.artifact_id,
        "reviewed_at": NOW - 30,
        "ledger_ref": "synthetic-observer-ledger-1",
        "summary_sections": [
            {
                "job_name": name,
                "status": "completed",
                "complete": True,
                "observer_record_id": "synthetic-observer-record-" + str(index),
            }
            for index, name in enumerate(job_names, start=1)
        ],
    }


@unittest.skipUnless(os.name == "posix" and feedback_admin.fcntl is not None,
                     "native owner-wrapper integration requires POSIX filesystem semantics")
class FeedbackAdminHostedIntegrationTests(unittest.TestCase):
    def test_real_key_encryption_authenticated_collection_release_and_replay_refusal(self):
        node_path, node_hash = _qualified_node_runtime()
        profile = feedback_request.PROFILES["core-node-lock-return"]
        job_names = (
            profile["producer_job"] + "-settings",
            profile["producer_job"] + "-prepare",
            profile["producer_job"],
            profile["auditor_job"],
        )
        request_fields = {
            "kind": profile["kind"],
            "repository_id": PROTECTED_REPOSITORY_ID,
            "source_sha": "a" * 40,
            "base_sha": "b" * 40,
            "control_sha": "c" * 40,
            "base_branch": "develop",
            "reviewed_diff_sha256": "d" * 64,
            "expiry": NOW + 3600,
        }

        with tempfile.TemporaryDirectory(prefix="feedback-admin-integration-") as temporary:
            state_directory = os.path.realpath(os.path.join(temporary, "owner-state"))
            admin = feedback_admin.FeedbackAdmin(
                state_directory,
                node_runtime_path=node_path,
                node_runtime_sha256=node_hash,
                ci_repository_id=CI_REPOSITORY_ID,
                actor_login=ACTOR_LOGIN,
                summary_job_names=job_names,
            )
            with mock.patch.object(feedback_admin.time, "time", return_value=NOW):
                created = admin.create_request(
                    request_fields, expected_manifest=LOCK_EXPECTATION, confirm_reviewed=True,
                )
                request = created["request"]
                api = EncryptedProviderShapedAPI(request, NOW)
                context = _context_for(request, api)
                encrypted_frame = _encrypt_fixture(
                    node_path, created["public_spki_base64"], context, NOW,
                )
                api.replace_frame(encrypted_frame)
                review = _summary_review(request, api, job_names)
                key_path = os.path.join(state_directory, "key-" + request["nonce"] + ".der")
                key_info = os.stat(key_path, follow_symlinks=False)
                self.assertTrue(stat.S_ISREG(key_info.st_mode))
                self.assertEqual(stat.S_IMODE(key_info.st_mode), 0o400)
                self.assertEqual(key_info.st_nlink, 1)

                wrong_actor_api = copy.copy(api)
                wrong_actor_api.actor = "different-fixture-actor"
                with self.assertRaises(feedback_admin.FeedbackAdminRefusal):
                    admin.consume_return(request["request_id"], wrong_actor_api,
                                         manual_summary_review=review)
                self.assertFalse(os.path.exists(os.path.join(
                    state_directory, "return-" + request["request_id"] + "-lock.payload",
                )))

                corrupted = bytearray(encrypted_frame)
                corrupted[-1] ^= 1
                corrupted_api = copy.copy(api)
                corrupted_api.replace_frame(corrupted)
                with self.assertRaises(feedback_admin.FeedbackAdminRefusal):
                    admin.consume_return(request["request_id"], corrupted_api,
                                         manual_summary_review=review)
                self.assertTrue(os.path.exists(key_path))
                self.assertFalse(os.path.exists(os.path.join(
                    state_directory, "return-" + request["request_id"] + "-lock.payload",
                )))

                released = admin.consume_return(
                    request["request_id"], api, manual_summary_review=review,
                )
                output_path = released["private_output_path"]
                output_info = os.stat(output_path, follow_symlinks=False)
                self.assertTrue(stat.S_ISREG(output_info.st_mode))
                self.assertEqual(stat.S_IMODE(output_info.st_mode), 0o600)
                self.assertEqual(output_info.st_nlink, 1)
                with open(output_path, "rb") as output:
                    self.assertEqual(output.read(), _lock_bytes())
                self.assertFalse(os.path.exists(key_path))
                with admin._locked_directory(create=False) as dir_fd:
                    state = admin._read_state(dir_fd)
                self.assertTrue(state["bootstrap_lock_consumed"])
                self.assertEqual(state["requests"][0]["status"], "consumed")
                self.assertEqual(state["requests"][0]["key_state"], "retired")
                with self.assertRaises(feedback_admin.FeedbackAdminRefusal):
                    admin.consume_return(request["request_id"], api, manual_summary_review=review)
                self.assertEqual(
                    [name for name in os.listdir(state_directory) if name.startswith("return-")],
                    [os.path.basename(output_path)],
                )


if __name__ == "__main__":
    unittest.main()
