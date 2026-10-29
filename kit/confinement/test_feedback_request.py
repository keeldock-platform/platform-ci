import hashlib
import unittest

import feedback_request as subject


NOW = 1_800_000_000


def _fields(kind="lock", *, now=NOW, expiry=None):
    profile = subject.PROFILE_BY_KIND[kind]
    return {
        "kind": kind,
        "concern": profile["concern"],
        "ci_repository_id": "987654321",
        "workflow_path": profile["workflow_path"],
        "workflow_ref": subject.WORKFLOW_REF,
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
        self.assertEqual(str(raised.exception), "request_invalid")

    def test_canonical_record_round_trips_and_hashes_the_exact_preimage(self):
        fields = _fields()
        request = subject.create_request(fields, now=NOW)
        record = subject.encode_request(request, now=NOW)
        preimage = record.rsplit(b"request_id=", 1)[0]
        expected = (
            "node-feedback-request-v1\n"
            "kind=lock\n"
            "concern=core-node-lock-return\n"
            "ci_repository_id=987654321\n"
            "workflow_path=.github/workflows/node-lock-return.yml\n"
            "workflow_ref=refs/heads/main\n"
            "repository_id=1430959909\n"
            "source_sha=" + "d" * 40 + "\n"
            "base_sha=" + "e" * 40 + "\n"
            "control_sha=" + "f" * 40 + "\n"
            "base_branch=develop\n"
            "reviewed_diff_sha256=" + "1" * 64 + "\n"
            "recipient_fingerprint=" + "2" * 64 + "\n"
            "nonce=" + "3" * 64 + "\n"
            "expiry=" + str(NOW + 3600) + "\n"
        ).encode("ascii")
        self.assertEqual(preimage, expected)
        self.assertEqual(request["request_id"], hashlib.sha256(preimage).hexdigest())
        self.assertEqual(subject.parse_request(record, now=NOW), request)

    def test_parser_rejects_duplicates_reordering_unknown_fields_and_noncanonical_bytes(self):
        request = subject.create_request(_fields(), now=NOW)
        record = subject.encode_request(request, now=NOW)
        bad_records = (
            record.replace(b"kind=lock\n", b"kind=lock\nkind=lock\n", 1),
            record.replace(b"kind=lock\nconcern=", b"concern=", 1).replace(
                b"concern=core-node-lock-return\n", b"concern=core-node-lock-return\nkind=lock\n", 1,
            ),
            record.replace(b"kind=lock\n", b"unknown=lock\n", 1),
            record.replace(b"expiry=1800003600\n", b"expiry=01800003600\n", 1),
            record + b"trailing",
            record + b" " * subject.MAX_REQUEST_BYTES,
        )
        for bad_record in bad_records:
            with self.subTest(size=len(bad_record)):
                self.assert_refused(subject.parse_request, bad_record, now=NOW)

    def test_all_registered_profiles_are_exactly_bound_to_kind_and_workflow(self):
        for kind in subject.PROFILE_BY_KIND:
            with self.subTest(kind=kind):
                fields = _fields(kind)
                request = subject.create_request(fields, now=NOW)
                self.assertEqual(subject.validate_request(request, now=NOW), subject.PROFILE_BY_KIND[kind])
                changed = dict(fields)
                changed["workflow_path"] = ".github/workflows/other.yml"
                self.assert_refused(subject.create_request, changed, now=NOW)

    def test_request_values_digest_and_expiry_are_strict(self):
        cases = (
            ("source_sha", "F" * 40),
            ("base_sha", "x" * 40),
            ("reviewed_diff_sha256", "0" * 63),
            ("recipient_fingerprint", "A" * 64),
            ("nonce", "B" * 64),
            ("repository_id", "01430995909"),
            ("ci_repository_id", "0987654321"),
            ("base_branch", "feature"),
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
        self.assert_refused(
            subject.create_request, _fields(expiry=subject.EXCEPTION_END + 1), now=NOW,
        )
        request = subject.create_request(_fields(), now=NOW)
        tampered = dict(request)
        tampered["source_sha"] = "0" * 40
        self.assert_refused(subject.validate_request, tampered, now=NOW)
        self.assert_refused(subject.validate_request, request, now=request["expiry"])

    def test_consumption_is_one_use_and_bootstrap_lock_is_global(self):
        request = subject.create_request(_fields(), now=NOW)
        initial = subject.empty_state()
        active = subject.register_request(initial, request, now=NOW)
        self.assertEqual(initial, subject.empty_state())
        consumed = subject.consume_request(active, request["request_id"], now=NOW + 1)
        entry = consumed["requests"][0]
        self.assertTrue(consumed["bootstrap_lock_consumed"])
        self.assertEqual(entry["status"], "consumed")
        self.assertEqual(entry["key_state"], "retirement_required")
        self.assertEqual(entry["tombstone_until"], subject.EXCEPTION_END)
        retired = subject.mark_key_retired(consumed, request["request_id"])
        self.assertEqual(retired["requests"][0]["key_state"], "retired")
        self.assert_refused(subject.consume_request, retired, request["request_id"], now=NOW + 2)
        self.assert_refused(subject.register_request, retired, request, now=NOW + 2)
        second_fields = _fields(expiry=NOW + 7200)
        second_fields["nonce"] = "4" * 64
        second_fields["recipient_fingerprint"] = "5" * 64
        second_lock = subject.create_request(second_fields, now=NOW)
        self.assert_refused(subject.register_request, retired, second_lock, now=NOW + 2)

    def test_state_never_reuses_nonce_or_recipient_key_fingerprint(self):
        request = subject.create_request(_fields(), now=NOW)
        state = subject.register_request(subject.empty_state(), request, now=NOW)
        reused_nonce = _fields()
        reused_nonce["recipient_fingerprint"] = "5" * 64
        self.assert_refused(
            subject.register_request,
            state,
            subject.create_request(reused_nonce, now=NOW),
            now=NOW,
        )
        reused_key = _fields()
        reused_key["nonce"] = "6" * 64
        self.assert_refused(
            subject.register_request,
            state,
            subject.create_request(reused_key, now=NOW),
            now=NOW,
        )

    def test_expiry_and_abandonment_retire_keys_without_consuming_bootstrap(self):
        expiring = subject.create_request(_fields(expiry=NOW + 60), now=NOW)
        state = subject.register_request(subject.empty_state(), expiring, now=NOW)
        self.assert_refused(subject.expire_request, state, expiring["request_id"], now=NOW + 59)
        expired = subject.expire_request(state, expiring["request_id"], now=NOW + 60)
        self.assertFalse(expired["bootstrap_lock_consumed"])
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
        duplicate = dict(state)
        duplicate["requests"] = [state["requests"][0], dict(state["requests"][0])]
        self.assert_refused(subject.register_request, duplicate, request, now=NOW)
        malformed = dict(state)
        malformed["requests"] = [dict(state["requests"][0], tombstone_until=subject.EXCEPTION_END)]
        self.assert_refused(subject.register_request, malformed, request, now=NOW)


def _cargo_fields(index, *, now=NOW, expiry=None):
    fields = _fields("cargo_lock", now=now, expiry=expiry)
    fields["nonce"] = format(index + 1, "x") * 64
    fields["recipient_fingerprint"] = format(index + 1, "x") * 64
    return fields


class CargoLockProfileTests(unittest.TestCase):
    def assert_refused(self, operation, *args, **kwargs):
        with self.assertRaises(subject.RequestRefusal) as raised:
            operation(*args, **kwargs)
        self.assertEqual(raised.exception.reason, "request_invalid")

    def test_profile_is_a_fourth_closed_profile_that_never_aliases_the_lock_kind(self):
        profile = subject.PROFILE_BY_KIND["cargo_lock"]
        self.assertEqual(profile["profile_id"], 4)
        self.assertEqual(profile["concern"], "core-rust-lock-return")
        self.assertEqual(profile["workflow_path"], ".github/workflows/core-rust-lock-return.yml")
        self.assertEqual(profile["producer_job"], "core-rust-lock-return")
        self.assertEqual(profile["auditor_job"], "core-rust-lock-return-audit")
        self.assertEqual(profile["member_name"], "rust-lock-return-v1.enc")
        self.assertIs(subject.PROFILES["core-rust-lock-return"], profile)
        self.assertNotEqual(profile["kind"], "lock")
        self.assertEqual(
            sorted(subject.PROFILE_BY_KIND), ["build_diagnostics", "cargo_lock", "lock", "rust_patch"],
        )
        self.assertEqual(
            len({item["member_name"] for item in subject.PROFILES.values()}), len(subject.PROFILES),
        )
        for item in subject.PROFILES.values():
            self.assertEqual(set(item), set(subject.PROFILE_FIELDS))

    def test_cargo_lock_has_its_own_bounded_payload_limits(self):
        profile = subject.PROFILE_BY_KIND["cargo_lock"]
        node_profile = subject.PROFILE_BY_KIND["lock"]
        self.assertEqual(node_profile["max_payload_bytes"], 4 * 1024 * 1024 - 64 * 1024)
        self.assertEqual(profile["max_payload_bytes"], subject.CARGO_LOCK_MAX_PAYLOAD_BYTES)
        self.assertLess(profile["max_payload_bytes"], node_profile["max_payload_bytes"])

        def encoded(size):
            return 4 * ((size + 2) // 3)

        total = (
            encoded(subject.CARGO_LOCK_MAX_LOCK_BYTES) + encoded(subject.CARGO_LOCK_MAX_RECEIPT_BYTES)
            + encoded(subject.CARGO_LOCK_MAX_EVIDENCE_BYTES) + 256
        )
        self.assertLessEqual(total, profile["max_payload_bytes"])

    def test_requests_bind_the_cargo_lock_kind_concern_and_workflow_exactly(self):
        request = subject.create_request(_cargo_fields(0), now=NOW)
        record = subject.encode_request(request, now=NOW)
        self.assertIn(b"kind=cargo_lock\nconcern=core-rust-lock-return\n", record)
        self.assertEqual(subject.parse_request(record, now=NOW), request)
        for name, value in (
            ("kind", "lock"), ("concern", "core-node-lock-return"),
            ("workflow_path", ".github/workflows/node-lock-return.yml"),
            ("workflow_path", ".github/workflows/core-rust-format-return.yml"),
        ):
            changed = _cargo_fields(0)
            changed[name] = value
            with self.subTest(name=name, value=value):
                self.assert_refused(subject.create_request, changed, now=NOW)

    def test_each_request_is_consumed_once_without_touching_the_node_lock_flag(self):
        request = subject.create_request(_cargo_fields(0), now=NOW)
        active = subject.register_request(subject.empty_state(), request, now=NOW)
        self.assertEqual(subject.cargo_lock_consumed_count(active), 0)
        consumed = subject.consume_request(active, request["request_id"], now=NOW + 1)
        self.assertEqual(subject.cargo_lock_consumed_count(consumed), 1)
        self.assertFalse(consumed["bootstrap_lock_consumed"])
        entry = consumed["requests"][0]
        self.assertEqual(entry["kind"], "cargo_lock")
        self.assertEqual(entry["status"], "consumed")
        self.assertEqual(entry["key_state"], "retirement_required")
        self.assertEqual(entry["tombstone_until"], subject.EXCEPTION_END)
        self.assert_refused(subject.consume_request, consumed, request["request_id"], now=NOW + 2)
        retired = subject.mark_key_retired(consumed, request["request_id"])
        self.assert_refused(subject.consume_request, retired, request["request_id"], now=NOW + 2)
        self.assert_refused(subject.register_request, retired, request, now=NOW + 2)
        node_lock = subject.create_request(_fields("lock", expiry=NOW + 7200), now=NOW)
        with_node_lock = subject.register_request(retired, node_lock, now=NOW + 2)
        self.assertEqual(with_node_lock["requests"][1]["kind"], "lock")

    def test_a_consumed_node_lock_does_not_block_and_is_not_blocked_by_cargo_locks(self):
        node_lock = subject.create_request(_fields("lock"), now=NOW)
        state = subject.register_request(subject.empty_state(), node_lock, now=NOW)
        state = subject.consume_request(state, node_lock["request_id"], now=NOW + 1)
        self.assertTrue(state["bootstrap_lock_consumed"])
        self.assertEqual(subject.cargo_lock_consumed_count(state), 0)
        cargo_request = subject.create_request(_cargo_fields(0), now=NOW)
        state = subject.register_request(state, cargo_request, now=NOW + 2)
        state = subject.consume_request(state, cargo_request["request_id"], now=NOW + 3)
        self.assertTrue(state["bootstrap_lock_consumed"])
        self.assertEqual(subject.cargo_lock_consumed_count(state), 1)

    def test_only_one_cargo_lock_request_is_active_at_a_time(self):
        first = subject.create_request(_cargo_fields(0), now=NOW)
        second = subject.create_request(_cargo_fields(1), now=NOW)
        state = subject.register_request(subject.empty_state(), first, now=NOW)
        self.assert_refused(subject.register_request, state, second, now=NOW)
        state = subject.abandon_request(state, first["request_id"])
        state = subject.register_request(state, second, now=NOW)
        self.assertEqual(subject.cargo_lock_consumed_count(state), 0)

    def test_the_number_of_consumed_cargo_locks_is_capped(self):
        state = subject.empty_state()
        for index in range(subject.CARGO_LOCK_MAX_CONSUMED):
            request = subject.create_request(_cargo_fields(index), now=NOW)
            state = subject.register_request(state, request, now=NOW)
            state = subject.consume_request(state, request["request_id"], now=NOW + 1)
        self.assertEqual(subject.cargo_lock_consumed_count(state), subject.CARGO_LOCK_MAX_CONSUMED)
        self.assertFalse(state["bootstrap_lock_consumed"])
        extra = subject.create_request(_cargo_fields(subject.CARGO_LOCK_MAX_CONSUMED), now=NOW)
        self.assert_refused(subject.register_request, state, extra, now=NOW + 2)

    def test_stale_and_replayed_requests_are_refused(self):
        request = subject.create_request(_cargo_fields(0, expiry=NOW + 60), now=NOW)
        self.assert_refused(subject.register_request, subject.empty_state(), request, now=NOW + 60)
        self.assert_refused(subject.register_request, subject.empty_state(), request, now=NOW + 3600)
        state = subject.register_request(subject.empty_state(), request, now=NOW)
        self.assert_refused(subject.consume_request, state, request["request_id"], now=NOW + 60)
        self.assert_refused(subject.consume_request, state, "0" * 64, now=NOW + 1)
        self.assert_refused(subject.consume_request, state, request["request_id"], now=0)
        expired = subject.expire_request(state, request["request_id"], now=NOW + 60)
        self.assertEqual(subject.cargo_lock_consumed_count(expired), 0)
        self.assert_refused(subject.consume_request, expired, request["request_id"], now=NOW + 30)
        self.assert_refused(subject.register_request, expired, request, now=NOW + 61)
        replay = subject.create_request(_cargo_fields(0, expiry=NOW + 600), now=NOW)
        self.assert_refused(subject.register_request, expired, replay, now=NOW + 61)

    def test_an_expired_active_request_blocks_new_registration_until_resolved(self):
        old = subject.create_request(_cargo_fields(0, expiry=NOW + 60), now=NOW)
        state = subject.register_request(subject.empty_state(), old, now=NOW)
        fresh = subject.create_request(_cargo_fields(1, expiry=NOW + 3000), now=NOW + 61)
        self.assert_refused(subject.register_request, state, fresh, now=NOW + 61)

    def test_build_inputs_are_refused_unless_the_profile_allowlists_them(self):
        self.assertEqual(subject.PROFILE_BY_KIND["cargo_lock"]["build_inputs"], ())
        self.assertEqual(subject.validate_build_inputs("cargo_lock", {}), {})
        for kind in ("cargo_lock", "lock", "rust_patch", "build_diagnostics"):
            with self.subTest(kind=kind):
                self.assert_refused(
                    subject.validate_build_inputs, kind, {"LIBSQLITE3_FLAGS": "-DSQLITE_ENABLE_FTS5"},
                )
                self.assert_refused(subject.validate_build_inputs, kind, {"": "x"})
        for kind, inputs in (
            ("unknown", {}), (None, {}), ("cargo_lock", []), ("cargo_lock", None),
            ("cargo_lock", "LIBSQLITE3_FLAGS"),
        ):
            with self.subTest(kind=kind, inputs=repr(inputs)):
                self.assert_refused(subject.validate_build_inputs, kind, inputs)


class WorkspaceSelectorTests(unittest.TestCase):
    def assert_refused(self, operation, *args, **kwargs):
        with self.assertRaises(subject.RequestRefusal):
            operation(*args, **kwargs)

    def test_absent_selector_keeps_the_canonical_record_and_means_contract(self):
        fields = _fields("cargo_lock")
        request = subject.create_request(fields, now=NOW)
        record = subject.encode_request(request, now=NOW)
        self.assertNotIn(b"workspace=", record)
        self.assertEqual(subject.request_workspace(request), "contract")
        self.assertEqual(subject.parse_request(record, now=NOW), request)

    def test_runtime_selector_is_a_bound_canonical_line_for_the_lock_profile_only(self):
        fields = _fields("cargo_lock")
        fields["workspace"] = "runtime"
        request = subject.create_request(fields, now=NOW)
        record = subject.encode_request(request, now=NOW)
        preimage = record.rsplit(b"request_id=", 1)[0]
        self.assertTrue(preimage.endswith(b"expiry=" + str(NOW + 3600).encode("ascii") + b"\nworkspace=runtime\n"))
        self.assertEqual(subject.parse_request(record, now=NOW), request)
        self.assertEqual(subject.request_workspace(request), "runtime")
        plain = subject.create_request(_fields("cargo_lock"), now=NOW)
        self.assertNotEqual(plain["request_id"], request["request_id"])
        for kind in ("lock", "rust_patch", "build_diagnostics"):
            other = _fields(kind)
            other["workspace"] = "runtime"
            with self.subTest(kind=kind):
                self.assert_refused(subject.create_request, other, now=NOW)

    def test_every_other_selector_value_is_refused(self):
        for value in ("contract", "", "Runtime", "runtime/", "../runtime", "other", None, 1, b"runtime"):
            fields = _fields("cargo_lock")
            fields["workspace"] = value
            with self.subTest(value=value):
                self.assert_refused(subject.create_request, fields, now=NOW)

    def test_selector_line_cannot_be_dropped_reordered_or_duplicated(self):
        fields = _fields("cargo_lock")
        fields["workspace"] = "runtime"
        record = subject.encode_request(subject.create_request(fields, now=NOW), now=NOW)
        for bad in (
            record.replace(b"workspace=runtime\n", b"", 1),
            record.replace(b"workspace=runtime\n", b"workspace=runtime\nworkspace=runtime\n", 1),
            record.replace(b"workspace=runtime\n", b"workspace=contract\n", 1),
            record.replace(b"workspace=runtime\n", b"unknown=runtime\n", 1),
        ):
            with self.subTest(bad=bad):
                self.assert_refused(subject.parse_request, bad, now=NOW)


if __name__ == "__main__":
    unittest.main()
