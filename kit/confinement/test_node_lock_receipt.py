import copy
import hashlib
import io
import stat
import struct
import unittest
import zipfile

import node_lock_receipt as subject


NOW = 1_800_000_000
CI_REPOSITORY_ID = 987654321
ACTOR_LOGIN = "review-owner"
ARTIFACT_NAME = "node-lock-return-24680-1"
RUN_ID = 24680
PRODUCER_JOB_ID = 13579
AUDITOR_JOB_ID = 13580
ARTIFACT_ID = 97531


def _request():
    return {
        "request_id": "a" * 64,
        "nonce": "b" * 64,
        "recipient_fingerprint": "c" * 64,
        "concern": subject.CONCERN,
        "repository_id": "1430959909",
        "source_sha": "d" * 40,
        "base_sha": "e" * 40,
        "control_sha": "f" * 40,
        "base_branch": "develop",
        "reviewed_diff_sha256": "1" * 64,
        "workflow_ref": subject.WORKFLOW_REF,
        "expiry": NOW + 3600,
    }


def _make_zip(payload=b"synthetic encrypted envelope", *, name=subject.ZIP_MEMBER,
              mode=(stat.S_IFREG | 0o600) << 16, compression=zipfile.ZIP_STORED, extra=()):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        info = zipfile.ZipInfo(name)
        info.create_system = 3
        info.compress_type = compression
        info.external_attr = mode
        archive.writestr(info, payload)
        for extra_name, extra_payload in extra:
            archive.writestr(extra_name, extra_payload)
    return stream.getvalue()


def _zip_with_nul_suffix():
    archive = _make_zip()
    end = archive.rfind(b"PK\x05\x06")
    central_offset = struct.unpack_from("<I", archive, end + 16)[0]
    central_size = struct.unpack_from("<I", archive, end + 12)[0]
    local_name_size = struct.unpack_from("<H", archive, 26)[0]
    central_name_size = struct.unpack_from("<H", archive, central_offset + 28)[0]
    local_header = bytearray(archive[:30])
    central_header = bytearray(archive[central_offset:central_offset + 46])
    end_record = bytearray(archive[end:])
    struct.pack_into("<H", local_header, 26, local_name_size + 1)
    struct.pack_into("<H", central_header, 28, central_name_size + 1)
    struct.pack_into("<I", end_record, 12, central_size + 1)
    struct.pack_into("<I", end_record, 16, central_offset + 1)
    local_name_end = 30 + local_name_size
    central_name_start = central_offset + 46
    central_name_end = central_name_start + central_name_size
    return bytes(
        local_header
        + archive[30:local_name_end] + b"\x00"
        + archive[local_name_end:central_offset]
        + central_header
        + archive[central_name_start:central_name_end] + b"\x00"
        + archive[central_name_end:end]
        + end_record
    )


def _zip_with_unreferenced_record():
    archive = _make_zip()
    end = archive.rfind(b"PK\x05\x06")
    central_offset = struct.unpack_from("<I", archive, end + 16)[0]
    hidden_name = b"hidden.bin"
    hidden_record = struct.pack(
        "<4s5H3I2H", b"PK\x03\x04", 20, 0, zipfile.ZIP_STORED, 0, 0,
        0, 0, 0, len(hidden_name), 0,
    ) + hidden_name
    updated = bytearray(archive[:central_offset] + hidden_record + archive[central_offset:])
    struct.pack_into("<I", updated, len(updated) - 22 + 16, central_offset + len(hidden_record))
    return bytes(updated)


def _zip_with_descriptor(payload=b"synthetic encrypted envelope"):
    archive = _make_zip(payload)
    end = archive.rfind(b"PK\x05\x06")
    central_offset = struct.unpack_from("<I", archive, end + 16)[0]
    name_size = struct.unpack_from("<H", archive, 26)[0]
    data_end = 30 + name_size + len(payload)
    crc = struct.unpack_from("<I", archive, central_offset + 16)[0]
    descriptor = struct.pack("<4sIII", b"PK\x07\x08", crc, len(payload), len(payload))
    updated = bytearray(archive[:data_end] + descriptor + archive[data_end:])
    struct.pack_into("<H", updated, 6, 0x0008)
    struct.pack_into("<III", updated, 14, 0, 0, 0)
    new_central_offset = central_offset + len(descriptor)
    struct.pack_into("<H", updated, new_central_offset + 8, 0x0008)
    struct.pack_into("<I", updated, len(updated) - 22 + 16, new_central_offset)
    return bytes(updated)


def _zip_with_hidden_tail(compression, payload=b"synthetic encrypted envelope"):
    archive = _make_zip(payload, compression=compression)
    end = archive.rfind(b"PK\x05\x06")
    central_offset = struct.unpack_from("<I", archive, end + 16)[0]
    compressed_size = struct.unpack_from("<I", archive, central_offset + 20)[0]
    local_name_size, local_extra_size = struct.unpack_from("<HH", archive, 26)
    data_end = 30 + local_name_size + local_extra_size + compressed_size
    hidden_tail = b"hidden plaintext suffix"
    updated = bytearray(archive[:data_end] + hidden_tail + archive[data_end:])
    new_compressed_size = compressed_size + len(hidden_tail)
    new_central_offset = central_offset + len(hidden_tail)
    struct.pack_into("<I", updated, 18, new_compressed_size)
    struct.pack_into("<I", updated, new_central_offset + 20, new_compressed_size)
    struct.pack_into("<I", updated, len(updated) - 22 + 16, new_central_offset)
    return bytes(updated)


def _fixture():
    request = _request()
    payload = b"synthetic encrypted envelope"
    archive_bytes = _make_zip(payload)
    archive_digest = hashlib.sha256(archive_bytes).hexdigest()
    ciphertext_digest = hashlib.sha256(payload).hexdigest()
    context = dict(request)
    context.update({
        "run_id": str(RUN_ID),
        "producer_job": subject.PRODUCER_JOB,
        "run_attempt": 1,
    })
    receipt = {
        "schema_version": subject.SCHEMA_VERSION,
        "status": "passed",
        "job_name": subject.PRODUCER_JOB,
        **context,
        "artifact_id": ARTIFACT_ID,
        "ciphertext_digest": ciphertext_digest,
        "archive_digest": archive_digest,
        "job_id": PRODUCER_JOB_ID,
        "size": len(archive_bytes),
        "retention": 1,
        "member_size": len(payload),
        "archive_size": len(archive_bytes),
    }
    run = {
        "id": RUN_ID,
        "repository_id": CI_REPOSITORY_ID,
        "head_sha": request["control_sha"],
        "workflow_path": subject.WORKFLOW_PATH,
        "workflow_ref": subject.WORKFLOW_REF,
        "event": "workflow_dispatch",
        "status": "completed",
        "conclusion": "success",
        "actor_login": ACTOR_LOGIN,
        "run_attempt": 1,
    }
    def job(job_id, name):
        return {
            "id": job_id,
            "name": name,
            "run_id": RUN_ID,
            "run_attempt": 1,
            "head_sha": request["control_sha"],
            "status": "completed",
            "conclusion": "success",
        }
    artifact = {
        "id": ARTIFACT_ID,
        "name": ARTIFACT_NAME,
        "repository_id": CI_REPOSITORY_ID,
        "run_id": RUN_ID,
        "head_sha": request["control_sha"],
        "digest": archive_digest,
        "size": len(archive_bytes),
        "retention": 1,
        "expires_at": NOW + 80_000,
        "expired": False,
    }
    api_evidence = {
        "run": run,
        "jobs": [
            job(PRODUCER_JOB_ID, subject.PRODUCER_JOB),
            job(AUDITOR_JOB_ID, subject.AUDITOR_JOB),
        ],
        "artifacts": [artifact],
        "request_history": {
            "complete": True,
            "matches": [{
                "request_id": request["request_id"],
                "run_id": str(RUN_ID),
                "run_attempt": 1,
            }],
        },
    }
    producer_output = {"artifact_id": ARTIFACT_ID, "archive_digest": archive_digest}
    arguments = {
        "ci_repository_id": CI_REPOSITORY_ID,
        "actor_login": ACTOR_LOGIN,
        "artifact_name": ARTIFACT_NAME,
        "now": NOW,
    }
    return request, receipt, api_evidence, producer_output, archive_bytes, arguments


class NodeLockReceiptTests(unittest.TestCase):
    def validate(self, fixture=None, **changes):
        values = list(fixture or _fixture())
        for name, value in changes.items():
            values[2][name] = value
        return subject.validate_receipt(*values[:5], **values[5])

    def assert_refused(self, *values, **kwargs):
        with self.assertRaises(subject.Refusal) as raised:
            subject.validate_receipt(*values, **kwargs)
        self.assertEqual(raised.exception.reason, "receipt_invalid")
        self.assertEqual(str(raised.exception), "receipt_invalid")

    def test_context_encoding_matches_the_fixed_node_field_order(self):
        request, unused_receipt, unused_api, unused_output, unused_archive, unused_args = _fixture()
        context = dict(request)
        context.update({"run_id": str(RUN_ID), "producer_job": subject.PRODUCER_JOB, "run_attempt": 1})
        expected = (
            "node-lock-return-context-v1\n"
            "request_id=" + "a" * 64 + "\n"
            "nonce=" + "b" * 64 + "\n"
            "recipient_fingerprint=" + "c" * 64 + "\n"
            "concern=" + subject.CONCERN + "\n"
            "repository_id=1430959909\n"
            "source_sha=" + "d" * 40 + "\n"
            "base_sha=" + "e" * 40 + "\n"
            "control_sha=" + "f" * 40 + "\n"
            "base_branch=develop\n"
            "reviewed_diff_sha256=" + "1" * 64 + "\n"
            "workflow_ref=" + subject.WORKFLOW_REF + "\n"
            "run_id=" + str(RUN_ID) + "\n"
            "producer_job=" + subject.PRODUCER_JOB + "\n"
            "run_attempt=1\n"
            "expiry=" + str(NOW + 3600) + "\n"
        ).encode("ascii")
        self.assertEqual(subject.canonical_context(context), expected)

    def test_valid_receipt_returns_only_the_bound_member_and_expected_context(self):
        fixture = _fixture()
        result = self.validate(fixture)
        self.assertEqual(result["ciphertext"], b"synthetic encrypted envelope")
        self.assertEqual(result["context"]["source_sha"], fixture[0]["source_sha"])
        self.assertEqual(result["context"]["run_id"], str(RUN_ID))
        self.assertEqual(result["context"]["producer_job"], subject.PRODUCER_JOB)
        self.assertEqual(set(result), {"context", "ciphertext"})

    def test_receipt_context_tampering_is_refused_without_echoing_values(self):
        for field, value in (
            ("request_id", "0" * 64),
            ("nonce", "0" * 64),
            ("recipient_fingerprint", "0" * 64),
            ("source_sha", "0" * 40),
            ("base_sha", "0" * 40),
            ("control_sha", "0" * 40),
            ("reviewed_diff_sha256", "0" * 64),
            ("expiry", NOW + 3500),
            ("run_attempt", True),
            ("expiry", float(NOW + 3600)),
        ):
            fixture = _fixture()
            fixture[1][field] = value
            with self.subTest(field=field):
                self.assert_refused(*fixture[:5], **fixture[5])

    def test_pre_reviewed_request_and_expiry_are_closed_and_bounded(self):
        for field, value in (
            ("nonce", "bad\nvalue"),
            ("request_id", "A" * 64),
            ("repository_id", "01430995909"),
            ("workflow_ref", "refs/heads/feature"),
            ("expiry", NOW),
        ):
            fixture = _fixture()
            fixture[0][field] = value
            with self.subTest(field=field):
                self.assert_refused(*fixture[:5], **fixture[5])
        fixture = _fixture()
        fixture[0]["expiry"] = NOW + subject.MAX_REQUEST_TTL_SECONDS + 1
        self.assert_refused(*fixture[:5], **fixture[5])

    def test_run_actor_workflow_and_attempt_mismatches_are_refused(self):
        cases = (
            ("actor_login", "untrusted-actor"),
            ("workflow_path", "other.yml"),
            ("workflow_ref", "refs/heads/feature"),
            ("event", "pull_request"),
            ("head_sha", "0" * 40),
            ("run_attempt", 2),
            ("status", "cancelled"),
            ("conclusion", "failure"),
        )
        for field, value in cases:
            fixture = _fixture()
            fixture[2]["run"][field] = value
            with self.subTest(field=field):
                self.assert_refused(*fixture[:5], **fixture[5])

    def test_producer_and_auditor_jobs_must_be_unique_successful_and_run_bound(self):
        cases = (
            (0, "name", "unexpected-job"),
            (0, "run_id", RUN_ID + 1),
            (0, "run_attempt", 2),
            (0, "head_sha", "0" * 40),
            (0, "status", "cancelled"),
            (0, "conclusion", "failure"),
            (1, "name", "unexpected-auditor"),
            (1, "status", "in_progress"),
            (1, "conclusion", "cancelled"),
        )
        for index, field, value in cases:
            fixture = _fixture()
            fixture[2]["jobs"][index][field] = value
            with self.subTest(job=index, field=field):
                self.assert_refused(*fixture[:5], **fixture[5])
        fixture = _fixture()
        fixture[2]["jobs"].append(copy.deepcopy(fixture[2]["jobs"][0]))
        self.assert_refused(*fixture[:5], **fixture[5])

    def test_replay_history_requires_a_complete_single_current_request_match(self):
        for mutate in (
            lambda history: history.update({"complete": False}),
            lambda history: history["matches"].append({
                "request_id": "a" * 64, "run_id": "99999", "run_attempt": 1,
            }),
            lambda history: history["matches"][0].update({"run_attempt": 2}),
            lambda history: history["matches"][0].update({"run_id": "99999"}),
        ):
            fixture = _fixture()
            mutate(fixture[2]["request_history"])
            self.assert_refused(*fixture[:5], **fixture[5])

    def test_artifact_and_uploader_metadata_must_match_the_api_and_archive(self):
        cases = (
            ("id", ARTIFACT_ID + 1),
            ("name", "different-run-artifact"),
            ("repository_id", 123),
            ("run_id", RUN_ID + 1),
            ("head_sha", "0" * 40),
            ("digest", "0" * 64),
            ("size", 1),
            ("retention", 90),
            ("expires_at", NOW - 1),
            ("expires_at", NOW + subject.MAX_REQUEST_TTL_SECONDS + 1),
            ("expired", True),
        )
        for field, value in cases:
            fixture = _fixture()
            fixture[2]["artifacts"][0][field] = value
            with self.subTest(field=field):
                self.assert_refused(*fixture[:5], **fixture[5])
        fixture = _fixture()
        fixture[3]["artifact_id"] += 1
        self.assert_refused(*fixture[:5], **fixture[5])
        fixture = _fixture()
        fixture[3]["archive_digest"] = "0" * 64
        self.assert_refused(*fixture[:5], **fixture[5])
        fixture = _fixture()
        fixture[2]["artifacts"].append(copy.deepcopy(fixture[2]["artifacts"][0]))
        self.assert_refused(*fixture[:5], **fixture[5])
        fixture = _fixture()
        fixture[2]["artifacts"].clear()
        self.assert_refused(*fixture[:5], **fixture[5])

    def test_archive_and_ciphertext_digests_sizes_and_ids_are_recomputed(self):
        for field in ("artifact_id", "ciphertext_digest", "archive_digest", "job_id", "size", "retention",
                      "member_size", "archive_size", "schema_version", "status", "job_name"):
            fixture = _fixture()
            if field in (
                "artifact_id", "job_id", "size", "retention", "member_size", "archive_size", "schema_version",
            ):
                fixture[1][field] = fixture[1][field] + 1
            elif field in ("ciphertext_digest", "archive_digest"):
                fixture[1][field] = "0" * 64
            elif field in ("job_name", "status"):
                fixture[1][field] = "refused"
            else:
                fixture[1][field] = "other-job"
            with self.subTest(field=field):
                self.assert_refused(*fixture[:5], **fixture[5])
        fixture = _fixture()
        self.assert_refused(*fixture[:4], b"x" * (subject.MAX_ARCHIVE_BYTES + 1), **fixture[5])

    def test_zip_requires_one_safe_fixed_regular_member(self):
        cases = (
            _make_zip(name="../lock-return-v1.enc"),
            _make_zip(name="nested/lock-return-v1.enc"),
            _make_zip(name="lock-return-v1.enc/"),
            _zip_with_nul_suffix(),
            _make_zip(extra=(("extra.bin", b"x"),)),
            _make_zip(mode=(stat.S_IFLNK | 0o777) << 16),
            _make_zip(mode=(stat.S_IFREG | 0o755) << 16),
        )
        for archive_bytes in cases:
            with self.assertRaises(subject.Refusal):
                subject._zip_member(archive_bytes)

    def test_zip_framing_rejects_unreferenced_data_and_accepts_valid_descriptor(self):
        archive = _make_zip()
        cases = (
            _zip_with_unreferenced_record(),
            b"unreferenced-prefix" + archive,
            archive + b"unreferenced-suffix",
        )
        for archive_bytes in cases:
            with self.subTest(size=len(archive_bytes)):
                with self.assertRaises(subject.Refusal):
                    subject._zip_member(archive_bytes)
        self.assertEqual(subject._zip_member(_zip_with_descriptor()), b"synthetic encrypted envelope")
        invalid_descriptor = bytearray(_zip_with_descriptor())
        name_size = struct.unpack_from("<H", invalid_descriptor, 26)[0]
        data_end = 30 + name_size + len(b"synthetic encrypted envelope")
        invalid_descriptor[data_end + 4] ^= 1
        with self.assertRaises(subject.Refusal):
            subject._zip_member(bytes(invalid_descriptor))

    def test_deflate_stream_must_consume_bounded_member_and_match_crc(self):
        payload = b"synthetic encrypted envelope"
        valid_deflate = _make_zip(payload, compression=zipfile.ZIP_DEFLATED)
        self.assertEqual(subject._zip_member(valid_deflate), payload)
        for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
            with self.subTest(compression=compression):
                with self.assertRaises(subject.Refusal):
                    subject._zip_member(_zip_with_hidden_tail(compression))
        oversized = _make_zip(
            b"x" * (subject.MAX_MEMBER_BYTES + 1), compression=zipfile.ZIP_DEFLATED,
        )
        with self.assertRaises(subject.Refusal):
            subject._zip_member(oversized)

    def test_zip_member_mode_without_file_type_is_allowed_only_when_non_executable(self):
        fixture = list(_fixture())
        payload = b"synthetic encrypted envelope"
        fixture[4] = _make_zip(payload, mode=0o600 << 16)
        archive_digest = hashlib.sha256(fixture[4]).hexdigest()
        fixture[1]["archive_digest"] = archive_digest
        fixture[1]["ciphertext_digest"] = hashlib.sha256(payload).hexdigest()
        fixture[1]["size"] = len(fixture[4])
        fixture[1]["archive_size"] = len(fixture[4])
        fixture[1]["member_size"] = len(payload)
        fixture[2]["artifacts"][0]["digest"] = archive_digest
        fixture[2]["artifacts"][0]["size"] = len(fixture[4])
        fixture[3]["archive_digest"] = archive_digest
        self.assertEqual(self.validate(fixture)["ciphertext"], payload)

    def test_encrypted_and_oversized_deflate_members_are_refused(self):
        fixture = _fixture()
        encrypted = bytearray(fixture[4])
        local = encrypted.find(b"PK\x03\x04")
        central = encrypted.find(b"PK\x01\x02")
        local_flags = struct.unpack_from("<H", encrypted, local + 6)[0] | 1
        central_flags = struct.unpack_from("<H", encrypted, central + 8)[0] | 1
        struct.pack_into("<H", encrypted, local + 6, local_flags)
        struct.pack_into("<H", encrypted, central + 8, central_flags)
        with self.assertRaises(subject.Refusal):
            subject._zip_member(bytes(encrypted))

        oversized = _make_zip(
            b"x" * (subject.MAX_MEMBER_BYTES + 1), compression=zipfile.ZIP_DEFLATED,
        )
        with self.assertRaises(subject.Refusal):
            subject._zip_member(oversized)


if __name__ == "__main__":
    unittest.main()
