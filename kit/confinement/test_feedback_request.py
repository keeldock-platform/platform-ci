import hashlib
import unittest

import feedback_request as subject


NOW = 1_800_000_000


def _fields(kind="rust_patch", *, now=NOW, expiry=None):
    profile = subject.PROFILE_BY_KIND[kind]
    return {
        "kind": kind,
        "concern": profile["concern"],
        "ci_repository_id": "987654321",
        "workflow_path": profile["workflow_path"],
        "workflow_ref": subject.workflow_ref_for_kind(kind),
        "repository_id": "1430959909",
        "source_sha": "d" * 40,
        "base_sha": "e" * 40,
        "control_sha": "f" * 40,
        "base_branch": "develop",
        "reviewed_diff_sha256": "1" * 64,
        "recipient_fingerprint": "2" * 64,
        "nonce": "3" * 64,
        "expiry": expiry if expiry is not None else now + 3600,
    }


class FeedbackRequestTests(unittest.TestCase):
    def assert_refused(self, operation, *args, **kwargs):
        with self.assertRaises(subject.RequestRefusal) as raised:
            operation(*args, **kwargs)
        self.assertEqual(raised.exception.reason, "request_invalid")

    def test_canonical_record_round_trips_and_hashes_the_exact_preimage(self):
        request = subject.create_request(_fields(), now=NOW)
        record = subject.encode_request(request, now=NOW)
        preimage = record.rsplit(b"request_id=", 1)[0]
        self.assertEqual(request["request_id"], hashlib.sha256(preimage).hexdigest())
        self.assertEqual(subject.parse_request(record, now=NOW), request)
        self.assertIn(b"kind=rust_patch\nconcern=core-rust-format-return\n", preimage)

    def test_parser_rejects_duplicates_reordering_unknown_fields_and_noncanonical_bytes(self):
        request = subject.create_request(_fields(), now=NOW)
        record = subject.encode_request(request, now=NOW)
        bad_records = (
            record.replace(b"kind=rust_patch\n", b"kind=rust_patch\nkind=rust_patch\n", 1),
            record.replace(b"kind=rust_patch\nconcern=", b"concern=", 1).replace(
                b"concern=core-rust-format-return\n", b"concern=core-rust-format-return\nkind=rust_patch\n", 1,
            ),
            record.replace(b"kind=rust_patch\n", b"unknown=rust_patch\n", 1),
            record.replace(b"expiry=1800003600\n", b"expiry=01800003600\n", 1),
            record + b"trailing",
            record + b" " * subject.MAX_REQUEST_BYTES,
        )
        for bad_record in bad_records:
            with self.subTest(size=len(bad_record)):
                self.assert_refused(subject.parse_request, bad_record, now=NOW)

    def test_only_non_dependency_feedback_profiles_remain(self):
        self.assertEqual(
            sorted(subject.PROFILE_BY_KIND),
            ["build_diagnostics", "linux_quick", "rust_patch"],
        )
        for kind, concern, workflow in (
            ("lock", "core-node-lock-return", ".github/workflows/node-lock-return.yml"),
            ("cargo_lock", "core-rust-lock-return", ".github/workflows/core-rust-lock-return.yml"),
            ("npm_admission", "core-npm-admission-return", ".github/workflows/core-npm-admission-return.yml"),
        ):
            fields = _fields("rust_patch")
            fields.update(kind=kind, concern=concern, workflow_path=workflow)
            self.assert_refused(subject.create_request, fields, now=NOW)

    def test_registered_profiles_are_exactly_bound_to_kind_and_workflow(self):
        for kind in subject.PROFILE_BY_KIND:
            with self.subTest(kind=kind):
                fields = _fields(kind)
                request = subject.create_request(fields, now=NOW)
                self.assertEqual(subject.validate_request(request, now=NOW), subject.PROFILE_BY_KIND[kind])
                changed = dict(fields, workflow_path=".github/workflows/other.yml")
                self.assert_refused(subject.create_request, changed, now=NOW)

    def test_request_values_digest_and_expiry_are_strict(self):
        cases = (
            ("source_sha", "F" * 40), ("base_sha", "x" * 40),
            ("reviewed_diff_sha256", "0" * 63), ("recipient_fingerprint", "A" * 64),
            ("nonce", "B" * 64), ("repository_id", "01430995909"),
            ("ci_repository_id", "0987654321"), ("base_branch", "feature"),
            ("workflow_ref", "refs/heads/other"),
        )
        for field, value in cases:
            fields = _fields()
            fields[field] = value
            with self.subTest(field=field):
                self.assert_refused(subject.create_request, fields, now=NOW)
        self.assert_refused(
            subject.create_request, _fields(expiry=NOW + subject.MAX_REQUEST_TTL_SECONDS + 1), now=NOW,
        )
        self.assert_refused(subject.create_request, _fields(expiry=subject.EXCEPTION_END + 1), now=NOW)
        request = subject.create_request(_fields(), now=NOW)
        tampered = dict(request, source_sha="0" * 40)
        self.assert_refused(subject.validate_request, tampered, now=NOW)
        self.assert_refused(subject.validate_request, request, now=request["expiry"])

    def test_consumption_is_one_use_and_allows_a_fresh_request_after_retirement(self):
        request = subject.create_request(_fields(), now=NOW)
        initial = subject.empty_state()
        active = subject.register_request(initial, request, now=NOW)
        self.assertEqual(initial, subject.empty_state())
        consumed = subject.consume_request(active, request["request_id"], now=NOW + 1)
        entry = consumed["requests"][0]
        self.assertEqual(entry["status"], "consumed")
        self.assertEqual(entry["key_state"], "retirement_required")
        self.assertEqual(entry["tombstone_until"], subject.EXCEPTION_END)
        retired = subject.mark_key_retired(consumed, request["request_id"])
        self.assertEqual(retired["requests"][0]["key_state"], "retired")
        self.assert_refused(subject.consume_request, retired, request["request_id"], now=NOW + 2)
        self.assert_refused(subject.register_request, retired, request, now=NOW + 2)
        fields = _fields("build_diagnostics", expiry=NOW + 7200)
        fields.update(nonce="4" * 64, recipient_fingerprint="5" * 64)
        fresh = subject.create_request(fields, now=NOW)
        self.assertEqual(subject.register_request(retired, fresh, now=NOW + 2)["requests"][1]["kind"],
                         "build_diagnostics")

    def test_state_never_reuses_nonce_or_recipient_key_fingerprint(self):
        request = subject.create_request(_fields(), now=NOW)
        state = subject.register_request(subject.empty_state(), request, now=NOW)
        for changed in (dict(_fields(), recipient_fingerprint="5" * 64),
                        dict(_fields(), nonce="6" * 64)):
            self.assert_refused(
                subject.register_request, state, subject.create_request(changed, now=NOW), now=NOW,
            )

    def test_expiry_and_abandonment_retire_keys_and_preserve_tombstones(self):
        expiring = subject.create_request(_fields(expiry=NOW + 60), now=NOW)
        state = subject.register_request(subject.empty_state(), expiring, now=NOW)
        self.assert_refused(subject.expire_request, state, expiring["request_id"], now=NOW + 59)
        expired = subject.expire_request(state, expiring["request_id"], now=NOW + 60)
        self.assertEqual(expired["requests"][0]["status"], "expired")
        expired = subject.mark_key_retired(expired, expiring["request_id"])
        self.assertEqual(expired["requests"][0]["key_state"], "retired")
        self.assert_refused(subject.register_request, expired, expiring, now=NOW + 60)
        retry = subject.create_request(_fields(expiry=NOW + 180), now=NOW)
        state = subject.register_request(subject.empty_state(), retry, now=NOW)
        abandoned = subject.abandon_request(state, retry["request_id"])
        self.assertEqual(abandoned["requests"][0]["status"], "abandoned")
        self.assertEqual(abandoned["requests"][0]["key_state"], "retirement_required")
        self.assert_refused(subject.register_request, abandoned, retry, now=NOW + 1)

    def test_state_rejects_duplicate_ids_and_inconsistent_tombstones(self):
        request = subject.create_request(_fields(), now=NOW)
        state = subject.register_request(subject.empty_state(), request, now=NOW)
        duplicate = dict(state, requests=[state["requests"][0], dict(state["requests"][0])])
        self.assert_refused(subject.register_request, duplicate, request, now=NOW)
        malformed = dict(state, requests=[dict(state["requests"][0], tombstone_until=subject.EXCEPTION_END)])
        self.assert_refused(subject.register_request, malformed, request, now=NOW)

    def test_quick_profile_binds_untrusted_and_is_consumed_once(self):
        profile = subject.PROFILE_BY_KIND["linux_quick"]
        self.assertEqual(profile["profile_id"], 6)
        self.assertEqual(profile["max_payload_bytes"], 4 * 1024 * 1024 - 64 * 1024)
        self.assertEqual(subject.workflow_ref_for_kind("linux_quick"), "refs/heads/untrusted")
        self.assertEqual(subject.workflow_ref_for_kind("rust_patch"), "refs/heads/main")
        fields = _fields("linux_quick")
        request = subject.create_request(fields, now=NOW)
        state = subject.register_request(subject.empty_state(), request, now=NOW)
        consumed = subject.consume_request(state, request["request_id"], now=NOW + 1)
        self.assertEqual(consumed["requests"][0]["kind"], "linux_quick")
        self.assertEqual(consumed["requests"][0]["status"], "consumed")


if __name__ == "__main__":
    unittest.main()
