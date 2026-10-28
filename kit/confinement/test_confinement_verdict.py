"""Tests for the closed eleven-channel confinement verdict."""

import copy
import re
import unittest

import confinement_verdict as subject


SHA = "0123456789abcdef0123456789abcdef01234567"
SECRET = "secret-looking-value-77aa"
BLOCKED_TOKENS = " ".join(name + "=blocked/1/1" for name in subject.CHANNELS)
LINUX_LINE = (
    "KD-CONFINEMENT-VERDICT schema=1 confinement=accepted os=linux boundary=linux-ns-seccomp-uid"
    " control-sha=" + SHA + " run-id=40123456789 run-attempt=1 " + BLOCKED_TOKENS
    + " memory-canary=absent readable-file-canary=absent handoff=not-applicable"
    " project-execution=completed gates=13 failed=0 token-revocation=confirmed"
)
WINDOWS_LINE = (
    LINUX_LINE.replace("os=linux boundary=linux-ns-seccomp-uid", "os=windows boundary=lpac-job")
    .replace("handoff=not-applicable", "handoff=verified")
)


def _record(os_name="linux", **updates):
    record = {
        "os": os_name,
        "boundary": subject.BOUNDARIES[os_name],
        "control_sha": SHA,
        "run_id": 40123456789,
        "run_attempt": 1,
        "channels": {
            name: {"status": "blocked", "before": True, "after": True} for name in subject.CHANNELS
        },
        "memory_canary": "absent",
        "readable_file_canary": "absent",
        "handoff": "not-applicable" if os_name == "linux" else "verified",
        "project_execution": "completed",
        "gates": 13,
        "failed": 0,
        "token_revocation": "confirmed",
    }
    record.update(updates)
    return record


def _with_channel(os_name="linux", channel="https", **entry):
    record = _record(os_name)
    record["channels"][channel] = dict(record["channels"][channel], **entry)
    return record


def _refusal_reason(raw):
    with unittest.TestCase().assertRaises(subject.VerdictRefusal) as caught:
        subject.decode_line(raw)
    return caught.exception.reason


class VocabularyTests(unittest.TestCase):
    def test_the_eleven_channels_are_exactly_the_closed_set(self):
        self.assertEqual(len(subject.CHANNELS), 11)
        self.assertEqual(
            subject.CHANNELS,
            (
                "https", "dns", "redirect", "proxy", "runner_ipc", "raw_logs", "artifact_upload",
                "cache_upload", "runner_files", "process_memory", "boundary_disablement",
            ),
        )
        self.assertEqual(subject.CHANNEL_STATUSES, ("blocked", "observed-leak", "not-run"))
        self.assertEqual(subject.CANARY_RESULTS, ("absent", "present", "not-run"))
        self.assertEqual(subject.OPERATING_SYSTEMS, ("linux", "windows"))
        self.assertEqual(subject.REQUIRED_GATES, 13)

    def test_field_order_covers_every_record_field_once(self):
        self.assertEqual(len(subject.FIELD_ORDER), len(set(subject.FIELD_ORDER)))
        self.assertEqual(len(subject.FIELD_ORDER), 7 + 11 + 7)

    def test_public_line_never_carries_a_plan_identifier_or_comment_character(self):
        for line in (LINUX_LINE, WINDOWS_LINE):
            self.assertEqual(re.findall(r"(?<![A-Za-z0-9])[A-Z][0-9]{2,3}(?![0-9])", line), [])
            self.assertNotIn(chr(35), line)


class EncodeTests(unittest.TestCase):
    def test_linux_line_is_exactly_the_fixed_format(self):
        self.assertEqual(subject.encode_line(_record()), LINUX_LINE)

    def test_windows_line_is_exactly_the_fixed_format(self):
        self.assertEqual(subject.encode_line(_record("windows")), WINDOWS_LINE)

    def test_line_is_single_line_ascii_and_bounded(self):
        for line in (LINUX_LINE, WINDOWS_LINE):
            self.assertNotIn("\n", line)
            self.assertTrue(line.isascii())
            self.assertLess(len(line), subject.MAX_LINE_BYTES)
        worst = _record()
        for name in subject.CHANNELS:
            worst["channels"][name]["status"] = "observed-leak"
        worst["run_id"] = subject.MAX_RUN_ID
        worst["run_attempt"] = 99
        worst["project_execution"] = "failed"
        worst["token_revocation"] = "unconfirmed"
        self.assertLess(len(subject.encode_line(worst)), subject.MAX_LINE_BYTES)

    def test_round_trip_for_both_operating_systems(self):
        for os_name, line in (("linux", LINUX_LINE), ("windows", WINDOWS_LINE)):
            with self.subTest(os=os_name):
                record = subject.decode_line(line)
                self.assertEqual(record, _record(os_name))
                self.assertEqual(subject.encode_line(record), line)
                self.assertEqual(subject.decode_line(line.encode("ascii") + b"\n"), record)
                self.assertEqual(subject.decode_line(line + "\n"), record)

    def test_confinement_is_derived_and_cannot_be_asserted(self):
        self.assertIn("confinement=accepted", subject.encode_line(_record()))
        self.assertIn("confinement=refused", subject.encode_line(_with_channel(status="observed-leak")))

    def test_every_valid_status_combination_round_trips(self):
        for channel in subject.CHANNELS:
            for status in subject.CHANNEL_STATUSES:
                for before in (True, False):
                    for after in (True, False):
                        if status == "not-run" and (before or after):
                            continue
                        record = _with_channel(channel=channel, status=status, before=before, after=after)
                        with self.subTest(channel=channel, status=status, before=before, after=after):
                            self.assertEqual(subject.decode_line(subject.encode_line(record)), record)


class AcceptanceTests(unittest.TestCase):
    def test_all_blocked_with_all_controls_and_absent_canaries_is_accepted(self):
        for os_name in subject.OPERATING_SYSTEMS:
            self.assertTrue(subject.confinement_accepted(_record(os_name)))
            self.assertTrue(subject.run_accepted(_record(os_name)))

    def test_any_channel_that_is_not_blocked_refuses(self):
        for channel in subject.CHANNELS:
            for status in ("observed-leak", "not-run"):
                record = _with_channel(channel=channel, status=status, before=False, after=False)
                with self.subTest(channel=channel, status=status):
                    self.assertFalse(subject.confinement_accepted(record))
                    self.assertFalse(subject.run_accepted(record))
                    self.assertIn("confinement=refused", subject.encode_line(record))

    def test_a_positive_control_that_did_not_fire_before_or_after_refuses(self):
        for channel in subject.CHANNELS:
            for field in ("before", "after"):
                record = _with_channel(channel=channel, **{field: False})
                with self.subTest(channel=channel, field=field):
                    self.assertFalse(subject.confinement_accepted(record))

    def test_a_canary_that_is_present_or_not_run_refuses(self):
        for field in ("memory_canary", "readable_file_canary"):
            for result in ("present", "not-run"):
                with self.subTest(field=field, result=result):
                    self.assertFalse(subject.confinement_accepted(_record(**{field: result})))

    def test_windows_requires_a_verified_handoff(self):
        for result in ("failed", "not-run"):
            self.assertFalse(subject.confinement_accepted(_record("windows", handoff=result)))
        self.assertTrue(subject.confinement_accepted(_record("windows", handoff="verified")))

    def test_run_acceptance_also_needs_all_gates_passing_and_revocation_confirmed(self):
        cases = (
            {"project_execution": "not_started", "gates": 0},
            {"project_execution": "failed"},
            {"gates": 12},
            {"failed": 1},
            {"token_revocation": "unconfirmed"},
            {"token_revocation": "not-applicable"},
        )
        for updates in cases:
            with self.subTest(updates=updates):
                record = _record(**updates)
                self.assertTrue(subject.confinement_accepted(record))
                self.assertFalse(subject.run_accepted(record))


class RecordValidationTests(unittest.TestCase):
    def assert_schema_refusal(self, record, reason=None):
        with self.assertRaises(subject.VerdictRefusal) as caught:
            subject.validate_record(record)
        if reason is not None:
            self.assertEqual(caught.exception.reason, reason)
        with self.assertRaises(subject.VerdictRefusal):
            subject.encode_line(record)

    def test_missing_extra_and_non_dict_records_are_refused(self):
        self.assert_schema_refusal(None, "schema")
        self.assert_schema_refusal([], "schema")
        for field in sorted(subject.RECORD_FIELDS):
            record = _record()
            del record[field]
            with self.subTest(missing=field):
                self.assert_schema_refusal(record, "schema")
        self.assert_schema_refusal(_record(extra=1), "schema")

    def test_channel_set_must_be_exact(self):
        for channel in subject.CHANNELS:
            record = _record()
            del record["channels"][channel]
            with self.subTest(dropped=channel):
                self.assert_schema_refusal(record, "schema")
        record = _record()
        record["channels"]["extra"] = {"status": "blocked", "before": True, "after": True}
        self.assert_schema_refusal(record, "schema")
        record = _record()
        record["channels"]["https"]["extra"] = True
        self.assert_schema_refusal(record, "schema")
        record = _record()
        del record["channels"]["dns"]["after"]
        self.assert_schema_refusal(record, "schema")
        record = _record()
        record["channels"]["dns"] = "blocked"
        self.assert_schema_refusal(record, "schema")

    def test_values_are_type_and_vocabulary_checked(self):
        bad_updates = (
            {"os": "macos"}, {"os": "Linux"}, {"os": None},
            {"boundary": "lpac-job"}, {"boundary": "other"},
            {"control_sha": SHA.upper()}, {"control_sha": SHA[:-1]}, {"control_sha": 5},
            {"run_id": 0}, {"run_id": True}, {"run_id": "7"}, {"run_id": subject.MAX_RUN_ID + 1},
            {"run_attempt": 0}, {"run_attempt": 100}, {"run_attempt": 1.0},
            {"memory_canary": "missing"}, {"readable_file_canary": ""},
            {"handoff": "ok"}, {"project_execution": "done"}, {"token_revocation": "yes"},
            {"gates": 14}, {"gates": -1}, {"gates": True}, {"failed": 14}, {"failed": "0"},
        )
        for updates in bad_updates:
            with self.subTest(updates=updates):
                self.assert_schema_refusal(_record(**updates))
        for entry in ({"status": "open"}, {"status": 1}, {"before": 1}, {"after": "yes"}, {"before": None}):
            with self.subTest(entry=entry):
                self.assert_schema_refusal(_with_channel(**entry), "value")

    def test_inconsistent_combinations_are_refused(self):
        self.assert_schema_refusal(_with_channel(status="not-run"), "inconsistent")
        self.assert_schema_refusal(_with_channel(status="not-run", before=False), "inconsistent")
        self.assert_schema_refusal(_record("linux", handoff="verified"), "inconsistent")
        self.assert_schema_refusal(_record("windows", handoff="not-applicable"), "inconsistent")
        self.assert_schema_refusal(_record(failed=2, gates=1), "inconsistent")
        self.assert_schema_refusal(_record(project_execution="not_started", gates=1, failed=0), "inconsistent")
        self.assert_schema_refusal(_record(project_execution="completed", gates=0, failed=0), "inconsistent")


class DecodeTests(unittest.TestCase):
    def test_dropped_channel_extra_field_and_duplicate_field_are_refused(self):
        self.assertEqual(_refusal_reason(LINUX_LINE.replace(" dns=blocked/1/1", "")), "missing_field")
        self.assertEqual(_refusal_reason(LINUX_LINE + " extra=1"), "unknown_field")
        self.assertEqual(_refusal_reason(LINUX_LINE.replace(" dns=blocked/1/1", " dns=blocked/1/1 dns=blocked/1/1")), "duplicate")
        self.assertEqual(_refusal_reason(LINUX_LINE + " failed=0"), "duplicate")
        self.assertEqual(_refusal_reason(LINUX_LINE.replace(" dns=", " dnz=")), "unknown_field")

    def test_each_field_may_be_dropped_only_with_refusal(self):
        for key in subject.FIELD_ORDER:
            tokens = LINUX_LINE.split(" ")
            kept = [token for token in tokens if not token.startswith(key + "=")]
            self.assertEqual(len(kept), len(tokens) - 1)
            with self.subTest(key=key):
                self.assertEqual(_refusal_reason(" ".join(kept)), "missing_field")

    def test_reordered_fields_are_refused(self):
        tokens = LINUX_LINE.split(" ")
        swapped = tokens[:]
        swapped[9], swapped[10] = swapped[10], swapped[9]
        self.assertEqual(_refusal_reason(" ".join(swapped)), "order")

    def test_malformed_framing_is_refused(self):
        cases = (
            "", "\n", " " + LINUX_LINE, LINUX_LINE + " ", LINUX_LINE.replace(" dns=", "  dns="),
            LINUX_LINE.replace("KD-CONFINEMENT-VERDICT", "kd-confinement-verdict"),
            "OTHER " + LINUX_LINE.split(" ", 1)[1],
            LINUX_LINE + "\n\n", LINUX_LINE + "\r\n", LINUX_LINE.replace(" dns=", "\tdns="),
            LINUX_LINE.replace("schema=1", "schema"), LINUX_LINE.replace("schema=1", "=1"),
            LINUX_LINE.replace("schema=1", "schema="), LINUX_LINE.replace("schema=1", "schema=1=1"),
            LINUX_LINE + " " + chr(233), LINUX_LINE.replace("absent", "abs" + chr(233) + "nt", 1),
        )
        for raw in cases:
            with self.subTest(raw=raw[:40]):
                self.assertIn(_refusal_reason(raw), subject.REFUSAL_REASONS)
        for raw in (None, 5, [LINUX_LINE], bytearray(LINUX_LINE.encode("ascii"))):
            with self.subTest(kind=type(raw).__name__):
                self.assertEqual(_refusal_reason(raw), "malformed")
        self.assertEqual(_refusal_reason(LINUX_LINE.encode("utf-8") + chr(233).encode("utf-8")), "malformed")

    def test_oversized_input_is_refused(self):
        self.assertEqual(_refusal_reason(LINUX_LINE + " " + "a=1 " * 400), "size")
        self.assertEqual(_refusal_reason(("a" * 2000).encode("ascii")), "size")

    def test_values_are_checked(self):
        cases = {
            "schema=1": "schema=2",
            "confinement=accepted": "confinement=maybe",
            "os=linux": "os=macos",
            "run-id=40123456789": "run-id=0401",
            "run-attempt=1": "run-attempt=0",
            "gates=13": "gates=14",
            "failed=0": "failed=01",
            "https=blocked/1/1": "https=blocked/2/1",
            "dns=blocked/1/1": "dns=blocked/1",
            "proxy=blocked/1/1": "proxy=open/1/1",
            "memory-canary=absent": "memory-canary=missing",
            "control-sha=" + SHA: "control-sha=" + SHA[:-1],
        }
        for old, new in cases.items():
            with self.subTest(old=old):
                self.assertEqual(_refusal_reason(LINUX_LINE.replace(old, new)), "value")
        self.assertEqual(
            _refusal_reason(LINUX_LINE.replace("run-id=40123456789", "run-id=9007199254740992")), "value",
        )

    def test_boundary_must_match_the_operating_system(self):
        self.assertEqual(_refusal_reason(LINUX_LINE.replace("os=linux", "os=windows")), "value")
        self.assertEqual(_refusal_reason(WINDOWS_LINE.replace("os=windows", "os=linux")), "value")

    def test_a_line_that_claims_acceptance_for_a_leaking_record_is_refused(self):
        leaking = LINUX_LINE.replace("https=blocked/1/1", "https=observed-leak/1/1")
        self.assertEqual(_refusal_reason(leaking), "inconsistent")
        unfired = LINUX_LINE.replace("https=blocked/1/1", "https=blocked/1/0")
        self.assertEqual(_refusal_reason(unfired), "inconsistent")
        present = LINUX_LINE.replace("readable-file-canary=absent", "readable-file-canary=present")
        self.assertEqual(_refusal_reason(present), "inconsistent")
        honest = leaking.replace("confinement=accepted", "confinement=refused")
        record = subject.decode_line(honest)
        self.assertFalse(subject.confinement_accepted(record))

    def test_a_line_that_claims_refusal_for_a_proved_record_is_refused(self):
        self.assertEqual(
            _refusal_reason(LINUX_LINE.replace("confinement=accepted", "confinement=refused")), "inconsistent",
        )

    def test_refusals_never_reflect_input(self):
        raw = LINUX_LINE.replace("memory-canary=absent", "memory-canary=" + SECRET)
        with self.assertRaises(subject.VerdictRefusal) as caught:
            subject.decode_line(raw)
        self.assertNotIn(SECRET, str(caught.exception))
        self.assertNotIn(SECRET, repr(caught.exception.args))
        self.assertIn(caught.exception.reason, subject.REFUSAL_REASONS)
        self.assertEqual(subject.VerdictRefusal(SECRET).reason, "malformed")

    def test_decoder_does_not_mutate_or_alias_shared_state(self):
        first = subject.decode_line(LINUX_LINE)
        second = subject.decode_line(LINUX_LINE)
        first["channels"]["https"]["status"] = "observed-leak"
        self.assertEqual(second, _record())
        snapshot = copy.deepcopy(_record())
        subject.encode_line(snapshot)
        self.assertEqual(snapshot, _record())


class FindLinesTests(unittest.TestCase):
    def test_lines_are_found_with_and_without_a_timestamp_and_bom(self):
        line = LINUX_LINE.encode("ascii")
        stamped = b"2026-10-28T10:11:12.1234567Z " + line
        log = b"\xef\xbb\xbf" + b"first\r\n" + stamped + b"\nlast\n" + line
        self.assertEqual(subject.find_lines(log), [line, line])

    def test_a_prefix_inside_another_line_is_not_a_verdict_line(self):
        line = LINUX_LINE.encode("ascii")
        log = b"echo " + line + b"\nprefix " + line + b"\n"
        self.assertEqual(subject.find_lines(log), [])

    def test_non_bytes_logs_are_refused(self):
        with self.assertRaises(subject.VerdictRefusal):
            subject.find_lines(LINUX_LINE)


if __name__ == "__main__":
    unittest.main()
