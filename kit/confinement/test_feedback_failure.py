"""Tests for the bounded refusal normalizer used by producer workflows."""

import io
import json
import unittest

import feedback_failure as subject
import macos_core_contract as core_contract


CANARY = "untrusted-failure-canary-91c2"


def _record(**updates):
    record = {
        "diagnostic": "worker_privilege_census",
        "reason": "runner_unavailable",
        "schema_version": 1,
        "stage": "worker_setup",
        "status": "refused",
    }
    record.update(updates)
    return record


def _line(record):
    encoded = json.dumps(record, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")
    return subject.REFUSAL_PREFIX + encoded + b"\n"


class FeedbackFailureTests(unittest.TestCase):
    def test_allowlists_match_the_trusted_core_refusal_contract(self):
        self.assertEqual(subject.REASONS, core_contract.REASONS)
        self.assertEqual(subject.STAGES, core_contract.STAGES)
        self.assertEqual(subject.DIAGNOSTICS, core_contract.DIAGNOSTICS)
        self.assertEqual(subject.NO_OPERATION_STAGES, core_contract.NO_OPERATION_STAGES)

    def test_one_canonical_refusal_is_reserialized_without_changing_allowed_fields(self):
        raw = _line(_record())
        self.assertEqual(subject.normalize_refusal(raw), raw)

    def test_source_gates_cleanup_diagnostics_are_accepted_and_unlisted_values_are_not(self):
        for diagnostic in sorted(core_contract.SOURCE_GATES_CLEANUP_DIAGNOSTICS):
            raw = _line(_record(
                diagnostic=diagnostic, reason="cleanup_incomplete", stage="cleanup",
            ))
            with self.subTest(diagnostic=diagnostic):
                self.assertEqual(subject.normalize_refusal(raw), raw)
            for wrong in ({"stage": "worker_setup"}, {"reason": "runner_unavailable"}):
                bad = _line(_record(
                    diagnostic=diagnostic, **{"reason": "cleanup_incomplete", "stage": "cleanup", **wrong},
                ))
                with self.subTest(diagnostic=diagnostic, wrong=wrong):
                    self.assertEqual(
                        subject.normalize_refusal(bad), subject._format_record(subject.UNAVAILABLE_RECORD),
                    )
        for diagnostic in sorted(core_contract.PRIVILEGE_PROBE_CHECK_DIAGNOSTICS.values()):
            accepted = _line(_record(
                diagnostic=diagnostic, reason="cleanup_incomplete", stage="cleanup",
            ))
            rejected = _line(_record(diagnostic=diagnostic))
            with self.subTest(privilege_probe=diagnostic):
                self.assertEqual(subject.normalize_refusal(accepted), accepted)
                self.assertEqual(
                    subject.normalize_refusal(rejected), subject._format_record(subject.UNAVAILABLE_RECORD),
                )
        for unlisted in ("source_gates_survivor_" + CANARY, "source_gates_survivor_"):
            output = subject.normalize_refusal(_line(_record(
                diagnostic=unlisted, reason="cleanup_incomplete", stage="cleanup",
            )))
            with self.subTest(unlisted=unlisted):
                self.assertEqual(output, subject._format_record(subject.UNAVAILABLE_RECORD))
                self.assertNotIn(CANARY.encode("ascii"), output)

    def test_known_no_operation_diagnostic_is_accepted_only_at_no_operation_stage(self):
        valid = _line(_record(
            diagnostic="none", reason="invalid_input", stage="arguments",
        ))
        self.assertEqual(subject.normalize_refusal(valid), valid)
        invalid = _line(_record(stage="worker_setup", diagnostic="none"))
        self.assertEqual(subject.normalize_refusal(invalid), subject._format_record(subject.UNAVAILABLE_RECORD))

    def test_unknown_values_and_fields_are_replaced_without_leaking_canary(self):
        for field, value in (
            ("reason", CANARY),
            ("stage", CANARY),
            ("diagnostic", CANARY),
        ):
            with self.subTest(field=field):
                output = subject.normalize_refusal(_line(_record(**{field: value})))
                self.assertEqual(output, subject._format_record(subject.UNAVAILABLE_RECORD))
                self.assertNotIn(CANARY.encode("ascii"), output)
        extra = _record()
        extra[CANARY] = "unexpected"
        output = subject.normalize_refusal(_line(extra))
        self.assertEqual(output, subject._format_record(subject.UNAVAILABLE_RECORD))
        self.assertNotIn(CANARY.encode("ascii"), output)

    def test_duplicate_keys_mixed_records_and_trailing_bytes_fail_closed(self):
        duplicate = (
            subject.REFUSAL_PREFIX
            + b'{"diagnostic":"worker_privilege_census","reason":"runner_unavailable",'
            + b'"reason":"' + CANARY.encode("ascii") + b'","schema_version":1,'
            + b'"stage":"worker_setup","status":"refused"}\n'
        )
        valid = _line(_record())
        for raw in (
            duplicate,
            valid + valid,
            valid[:-1] + b" trailing\n",
            valid[:-1],
            b"KD-FEEDBACK-PRODUCER " + valid[len(subject.REFUSAL_PREFIX):],
        ):
            with self.subTest(raw_size=len(raw)):
                output = subject.normalize_refusal(raw)
                self.assertEqual(output, subject._format_record(subject.UNAVAILABLE_RECORD))
                self.assertNotIn(CANARY.encode("ascii"), output)

    def test_schema_status_types_and_input_bound_are_closed(self):
        for record in (
            _record(schema_version=True),
            _record(status="passed"),
            _record(extra="field"),
        ):
            self.assertEqual(
                subject.normalize_refusal(_line(record)),
                subject._format_record(subject.UNAVAILABLE_RECORD),
            )
        self.assertEqual(
            subject.normalize_refusal(b"x" * (subject.MAX_INPUT_BYTES + 1)),
            subject._format_record(subject.UNAVAILABLE_RECORD),
        )

    def test_cli_emits_one_safe_line_for_malformed_input(self):
        output = io.StringIO()
        status = subject.main([], stdin=io.BytesIO(b"untrusted " + CANARY.encode("ascii")), stdout=output)
        self.assertEqual(status, 0)
        self.assertEqual(output.getvalue(), subject._format_record(subject.UNAVAILABLE_RECORD).decode("ascii"))
        self.assertNotIn(CANARY, output.getvalue())

    def test_cli_negative_fixtures_never_echo_untrusted_values_or_extra_records(self):
        duplicate = (
            subject.REFUSAL_PREFIX
            + b'{"diagnostic":"worker_privilege_census","reason":"runner_unavailable",'
            + b'"reason":"' + CANARY.encode("ascii") + b'","schema_version":1,'
            + b'"stage":"worker_setup","status":"refused"}\n'
        )
        mixed = _line(_record()) + _line(_record())
        trailing = _line(_record())[:-1] + b" trailing\n"
        unknown = _line(_record(diagnostic=CANARY))
        expected = subject._format_record(subject.UNAVAILABLE_RECORD).decode("ascii")
        for raw in (duplicate, mixed, trailing, unknown):
            with self.subTest(raw_size=len(raw)):
                output = io.StringIO()
                status = subject.main([], stdin=io.BytesIO(raw), stdout=output)
                self.assertEqual(status, 0)
                self.assertEqual(output.getvalue(), expected)
                self.assertNotIn(CANARY, output.getvalue())


if __name__ == "__main__":
    unittest.main()
