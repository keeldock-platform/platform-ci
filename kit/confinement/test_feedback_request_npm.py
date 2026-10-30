import unittest

import feedback_request as subject


NOW = 1_800_000_000
KIND = "npm_admission"


def _fields(index=0, *, now=NOW, expiry=None, kind=KIND):
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
        "recipient_fingerprint": format(index + 1, "064x"),
        "nonce": format(index + 1, "064x"),
        "expiry": expiry if expiry is not None else now + 3600,
    }


class NpmAdmissionProfileTests(unittest.TestCase):
    def assert_refused(self, operation, *args, **kwargs):
        with self.assertRaises(subject.RequestRefusal) as raised:
            operation(*args, **kwargs)
        self.assertEqual(raised.exception.reason, "request_invalid")

    def test_profile_is_a_fifth_closed_profile_with_its_own_job_and_member(self):
        profile = subject.PROFILE_BY_KIND[KIND]
        self.assertEqual(profile["profile_id"], 5)
        self.assertEqual(profile["concern"], "core-npm-admission-return")
        self.assertEqual(profile["workflow_path"], ".github/workflows/core-npm-admission-return.yml")
        self.assertEqual(profile["producer_job"], "core-npm-admission-return")
        self.assertEqual(profile["auditor_job"], "core-npm-admission-return-audit")
        self.assertEqual(profile["member_name"], "npm-admission-return-v1.enc")
        self.assertIs(subject.PROFILES["core-npm-admission-return"], profile)
        self.assertEqual(profile["build_inputs"], ())
        self.assertEqual(sorted(item["profile_id"] for item in subject.PROFILES.values()), [1, 2, 3, 4, 5])
        for other in ("lock", "cargo_lock", "rust_patch", "build_diagnostics"):
            with self.subTest(other=other):
                self.assertNotEqual(subject.PROFILE_BY_KIND[other]["member_name"], profile["member_name"])
                self.assertNotEqual(subject.PROFILE_BY_KIND[other]["workflow_path"], profile["workflow_path"])

    def test_payload_limits_are_the_profiles_own_and_fit_the_envelope(self):
        profile = subject.PROFILE_BY_KIND[KIND]
        node_profile = subject.PROFILE_BY_KIND["lock"]
        self.assertEqual(profile["max_payload_bytes"], subject.NPM_ADMISSION_MAX_PAYLOAD_BYTES)
        self.assertLessEqual(profile["max_payload_bytes"], node_profile["max_payload_bytes"])
        self.assertGreater(profile["max_payload_bytes"], subject.CARGO_LOCK_MAX_PAYLOAD_BYTES)

        def encoded(size):
            return 4 * ((size + 2) // 3)

        total = (
            encoded(subject.NPM_ADMISSION_MAX_LOCK_BYTES) + encoded(subject.NPM_ADMISSION_MAX_RECEIPT_BYTES)
            + encoded(subject.NPM_ADMISSION_MAX_EVIDENCE_BYTES) + 256
        )
        self.assertLessEqual(total, profile["max_payload_bytes"])

    def test_requests_bind_the_kind_concern_and_workflow_exactly(self):
        request = subject.create_request(_fields(), now=NOW)
        record = subject.encode_request(request, now=NOW)
        self.assertIn(b"kind=npm_admission\nconcern=core-npm-admission-return\n", record)
        self.assertNotIn(b"workspace=", record)
        self.assertEqual(subject.parse_request(record, now=NOW), request)
        self.assertEqual(subject.validate_request(request, now=NOW), subject.PROFILE_BY_KIND[KIND])
        for name, value in (
            ("kind", "cargo_lock"), ("kind", "lock"), ("concern", "core-rust-lock-return"),
            ("workflow_path", ".github/workflows/core-rust-lock-return.yml"),
            ("workflow_path", ".github/workflows/node-lock-return.yml"),
        ):
            changed = _fields()
            changed[name] = value
            with self.subTest(name=name, value=value):
                self.assert_refused(subject.create_request, changed, now=NOW)

    def test_other_kinds_cannot_use_this_profiles_concern_or_workflow(self):
        for kind in ("lock", "cargo_lock", "rust_patch", "build_diagnostics"):
            changed = _fields(kind=kind)
            changed["concern"] = "core-npm-admission-return"
            with self.subTest(kind=kind):
                self.assert_refused(subject.create_request, changed, now=NOW)

    def test_the_filing_selector_is_optional_closed_and_never_valid_for_other_kinds(self):
        default = subject.create_request(_fields(), now=NOW)
        self.assertEqual(subject.request_filing(default), subject.NPM_DEFAULT_FILING)
        self.assertIn(subject.NPM_DEFAULT_FILING, subject.NPM_FILING_SELECTORS)
        selected = _fields()
        selected["workspace"] = subject.NPM_DEFAULT_FILING
        request = subject.create_request(selected, now=NOW)
        record = subject.encode_request(request, now=NOW)
        self.assertIn(b"\nworkspace=" + subject.NPM_DEFAULT_FILING.encode("ascii") + b"\nrequest_id=", record)
        self.assertEqual(subject.parse_request(record, now=NOW), request)
        self.assertEqual(subject.request_filing(request), subject.NPM_DEFAULT_FILING)
        self.assertNotEqual(request["request_id"], default["request_id"])
        for value in ("runtime", "contract", "", "other-filing", "Contract-Ui-Batch-A"):
            changed = _fields()
            changed["workspace"] = value
            with self.subTest(value=value):
                self.assert_refused(subject.create_request, changed, now=NOW)
        for kind in ("lock", "rust_patch", "build_diagnostics"):
            changed = _fields(kind=kind)
            changed["workspace"] = subject.NPM_DEFAULT_FILING
            with self.subTest(kind=kind):
                self.assert_refused(subject.create_request, changed, now=NOW)
        cargo = _fields(kind="cargo_lock")
        cargo["workspace"] = subject.NPM_DEFAULT_FILING
        self.assert_refused(subject.create_request, cargo, now=NOW)
        runtime = _fields(kind="cargo_lock")
        runtime["workspace"] = "runtime"
        self.assertEqual(subject.request_workspace(subject.create_request(runtime, now=NOW)), "runtime")
        self.assert_refused(subject.request_filing, None)

    def test_each_request_is_consumed_once_without_touching_other_kinds(self):
        request = subject.create_request(_fields(), now=NOW)
        active = subject.register_request(subject.empty_state(), request, now=NOW)
        self.assertEqual(subject.npm_admission_consumed_count(active), 0)
        consumed = subject.consume_request(active, request["request_id"], now=NOW + 1)
        self.assertEqual(subject.npm_admission_consumed_count(consumed), 1)
        self.assertEqual(subject.cargo_lock_consumed_count(consumed), 0)
        self.assertFalse(consumed["bootstrap_lock_consumed"])
        entry = consumed["requests"][0]
        self.assertEqual((entry["kind"], entry["status"]), (KIND, "consumed"))
        self.assertEqual(entry["key_state"], "retirement_required")
        self.assertEqual(entry["tombstone_until"], subject.EXCEPTION_END)
        self.assert_refused(subject.consume_request, consumed, request["request_id"], now=NOW + 2)
        self.assert_refused(subject.register_request, consumed, request, now=NOW + 2)
        node_lock = subject.create_request(_fields(5, kind="lock", expiry=NOW + 7200), now=NOW)
        with_node_lock = subject.register_request(consumed, node_lock, now=NOW + 2)
        self.assertEqual(with_node_lock["requests"][1]["kind"], "lock")

    def test_a_consumed_node_lock_neither_blocks_nor_is_blocked_by_npm_admission(self):
        node_lock = subject.create_request(_fields(kind="lock"), now=NOW)
        state = subject.register_request(subject.empty_state(), node_lock, now=NOW)
        state = subject.consume_request(state, node_lock["request_id"], now=NOW + 1)
        self.assertTrue(state["bootstrap_lock_consumed"])
        request = subject.create_request(_fields(1), now=NOW)
        state = subject.register_request(state, request, now=NOW + 2)
        state = subject.consume_request(state, request["request_id"], now=NOW + 3)
        self.assertTrue(state["bootstrap_lock_consumed"])
        self.assertEqual(subject.npm_admission_consumed_count(state), 1)

    def test_an_active_cargo_lock_does_not_block_npm_admission(self):
        cargo = subject.create_request(_fields(0, kind="cargo_lock"), now=NOW)
        state = subject.register_request(subject.empty_state(), cargo, now=NOW)
        request = subject.create_request(_fields(1), now=NOW)
        state = subject.register_request(state, request, now=NOW)
        self.assertEqual(len(state["requests"]), 2)

    def test_only_one_request_is_active_at_a_time(self):
        first = subject.create_request(_fields(0), now=NOW)
        second = subject.create_request(_fields(1), now=NOW)
        state = subject.register_request(subject.empty_state(), first, now=NOW)
        self.assert_refused(subject.register_request, state, second, now=NOW)
        state = subject.abandon_request(state, first["request_id"])
        state = subject.register_request(state, second, now=NOW)
        self.assertEqual(subject.npm_admission_consumed_count(state), 0)

    def test_the_number_of_consumed_requests_is_capped(self):
        state = subject.empty_state()
        for index in range(subject.NPM_ADMISSION_MAX_CONSUMED):
            request = subject.create_request(_fields(index), now=NOW)
            state = subject.register_request(state, request, now=NOW)
            state = subject.consume_request(state, request["request_id"], now=NOW + 1)
        self.assertEqual(subject.npm_admission_consumed_count(state), subject.NPM_ADMISSION_MAX_CONSUMED)
        self.assertFalse(state["bootstrap_lock_consumed"])
        extra = subject.create_request(_fields(subject.NPM_ADMISSION_MAX_CONSUMED), now=NOW)
        self.assert_refused(subject.register_request, state, extra, now=NOW + 2)

    def test_stale_and_replayed_requests_are_refused(self):
        request = subject.create_request(_fields(0, expiry=NOW + 60), now=NOW)
        self.assert_refused(subject.register_request, subject.empty_state(), request, now=NOW + 60)
        state = subject.register_request(subject.empty_state(), request, now=NOW)
        self.assert_refused(subject.consume_request, state, request["request_id"], now=NOW + 60)
        expired = subject.expire_request(state, request["request_id"], now=NOW + 60)
        self.assertEqual(subject.npm_admission_consumed_count(expired), 0)
        self.assert_refused(subject.register_request, expired, request, now=NOW + 61)

    def test_build_inputs_are_refused_unless_the_profile_allowlists_them(self):
        self.assertEqual(subject.validate_build_inputs(KIND, {}), {})
        for inputs in ({"registry": "other"}, {"NPM_TOKEN": "x"}, [], None, "x"):
            with self.subTest(inputs=inputs):
                self.assert_refused(subject.validate_build_inputs, KIND, inputs)


if __name__ == "__main__":
    unittest.main()
