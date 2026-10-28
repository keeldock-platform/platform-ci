import ast
import json
import unittest

import linux_channels as channels
import linux_probes as probes
from linux_channels import BoundaryRefusal


__all__ = [
    "LinuxChannelModelTests",
    "LinuxAttemptJudgementTests",
    "LinuxRecordTests",
    "LinuxProbeSourceTests",
    "LinuxReviewFixChannelTests",
]

EXPECTED_CHANNELS = (
    "https",
    "dns",
    "redirect",
    "proxy",
    "runner_ipc",
    "raw_logs",
    "artifact_upload",
    "cache_upload",
    "runner_files",
    "process_memory",
    "boundary_disablement",
)
NONCE = "0123456789abcdef01234567"


def lines(*items):
    return ("".join(item + chr(10) for item in items)).encode("ascii")


def passing(channel):
    rules = channels.ATTEMPT_RULES[channel]
    return lines(*("KDATT " + name + " " + accepted[0] for name, accepted in rules))


def record(phase="selftest", status="blocked", control=True, fixtures="complete", result="accepted", reason="none"):
    value = channels.empty_record(phase)
    for name in channels.CHANNELS:
        value["channels"][name] = {"status": status, "control": control}
    value["memory_canary"] = "absent"
    value["readable_file_canary"] = "absent"
    value["fixtures"] = fixtures
    value["result"] = result
    value["reason"] = reason
    return value


class LinuxChannelModelTests(unittest.TestCase):
    def test_eleven_channels_use_the_shared_cross_platform_identifiers(self):
        self.assertEqual(channels.CHANNELS, EXPECTED_CHANNELS)
        self.assertEqual(len(set(channels.CHANNELS)), 11)

    def test_every_channel_has_a_probe_plan_or_a_dedicated_runner(self):
        planned = set(channels.ATTEMPT_RULES)
        dedicated = {"runner_files"}
        self.assertEqual(planned | dedicated, set(channels.CHANNELS))
        for channel in planned:
            names = [name for name, accepted in channels.ATTEMPT_RULES[channel]]
            self.assertEqual(len(names), len(set(names)))

    def test_network_channels_all_have_control_markers_bound_to_the_nonce(self):
        for channel in channels.NETWORK_CHANNELS:
            with self.subTest(channel=channel):
                markers = channels.control_markers(channel, NONCE, True)
                self.assertTrue(markers)
                for listener, marker in markers:
                    self.assertIn(NONCE, marker)
                    self.assertRegex(listener, r"^[a-z0-9_]+$")
        self.assertEqual(
            len(channels.control_markers("https", NONCE, True)),
            len(channels.control_markers("https", NONCE, False)) + 1,
        )
        with self.assertRaises(ValueError):
            channels.control_markers("raw_logs", NONCE, False)
        with self.assertRaises(ValueError):
            channels.control_markers("https", "short", False)

    def test_boundary_control_subset_is_part_of_the_attempt_plan(self):
        names = {name for name, accepted in channels.ATTEMPT_RULES["boundary_disablement"]}
        self.assertTrue(set(channels.BOUNDARY_CONTROL_ATTEMPTS) <= names)
        self.assertTrue(set(channels.OPTIONAL_ATTEMPTS["boundary_disablement"]) <= names)

    def test_refusal_normalises_unknown_values_to_closed_vocabulary(self):
        refusal = BoundaryRefusal("not-a-reason", "not-a-channel", 1000)
        self.assertEqual((refusal.reason, refusal.channel, refusal.detail), ("environment", None, None))
        refusal = BoundaryRefusal("channel_leak", "https", 23)
        self.assertEqual((refusal.reason, refusal.channel, refusal.detail), ("channel_leak", "https", 23))
        for reason in channels.REASONS:
            self.assertEqual(BoundaryRefusal(reason).reason, reason)

    def test_public_lines_are_closed_and_refusal_always_blocks_project_execution(self):
        self.assertEqual(
            channels.channel_line("selftest", "https", "blocked", True),
            "KD-LINUX-CHANNEL schema=1 phase=selftest channel=https status=blocked control=1",
        )
        self.assertEqual(
            channels.canary_line("recheck", "absent", "absent"),
            "KD-LINUX-CANARY schema=1 phase=recheck memory-canary=absent readable-file-canary=absent",
        )
        accepted = channels.verdict_line("recheck", None, 11)
        self.assertEqual(
            accepted,
            "linux-source-boundary=accepted phase=recheck channels=11/11 project-execution=permitted",
        )
        refused = channels.verdict_line("recheck", BoundaryRefusal("control_not_fired", "dns", 7), 10)
        self.assertEqual(
            refused,
            "linux-source-boundary=refused phase=recheck reason=control_not_fired channel=dns detail=7 project-execution=not_started",
        )
        for bad in (
            lambda: channels.channel_line("other", "https", "blocked", True),
            lambda: channels.channel_line("selftest", "other", "blocked", True),
            lambda: channels.channel_line("selftest", "https", "open", True),
            lambda: channels.canary_line("selftest", "maybe", "absent"),
            lambda: channels.verdict_line("selftest", None, 12),
            lambda: channels.readback_line("selftest", (("ptrace-scope", "3"),)),
            lambda: channels.readback_line(
                "selftest",
                (("ptrace-scope", "BAD VALUE"), ("project-uid", "1"), ("usr-submounts", "ro"), ("runner-uid-distinct", "1")),
            ),
        ):
            with self.assertRaises(ValueError):
                bad()
        readback = channels.readback_line(
            "selftest",
            (("ptrace-scope", "3"), ("project-uid", "65534"), ("usr-submounts", "ro"), ("runner-uid-distinct", "1")),
        )
        self.assertEqual(
            readback,
            "KD-LINUX-READBACK schema=1 phase=selftest ptrace-scope=3 project-uid=65534 usr-submounts=ro runner-uid-distinct=1",
        )


class LinuxAttemptJudgementTests(unittest.TestCase):
    def test_every_channel_with_a_plan_judges_its_expected_output_as_ok(self):
        for channel, rules in channels.ATTEMPT_RULES.items():
            with self.subTest(channel=channel):
                optional = channels.OPTIONAL_ATTEMPTS.get(channel, ())
                self.assertEqual(channels.judge_attempts(rules, passing(channel), optional), "ok")

    def test_allowed_results_are_leaks_and_missing_or_extra_names_are_refused(self):
        rules = channels.ATTEMPT_RULES["https"]
        output = lines("KDATT tls-ipv4 allowed", "KDATT tls-ipv6 denied", "KDATT tls-hostname denied")
        self.assertEqual(channels.judge_attempts(rules, output), "leak")
        self.assertEqual(channels.judge_attempts(rules, lines("KDATT tls-ipv4 denied")), "incomplete")
        extra = passing("https") + lines("KDATT unknown denied")
        self.assertEqual(channels.judge_attempts(rules, extra), "unexpected")
        duplicate = passing("https") + lines("KDATT tls-ipv4 denied")
        self.assertEqual(channels.judge_attempts(rules, duplicate), "unexpected")
        other = lines("KDATT tls-ipv4 other", "KDATT tls-ipv6 denied", "KDATT tls-hostname denied")
        self.assertEqual(channels.judge_attempts(rules, other), "unexpected")
        self.assertEqual(channels.judge_attempts(rules, b""), "incomplete")

    def test_not_applicable_is_accepted_only_for_named_optional_attempts(self):
        rules = channels.ATTEMPT_RULES["boundary_disablement"]
        output = passing("boundary_disablement").replace(b"KDATT sudo denied", b"KDATT sudo na")
        optional = channels.OPTIONAL_ATTEMPTS["boundary_disablement"]
        self.assertEqual(channels.judge_attempts(rules, output, optional), "ok")
        self.assertEqual(channels.judge_attempts(rules, output, ()), "unexpected")
        required = passing("boundary_disablement").replace(b"KDATT setuid-root denied", b"KDATT setuid-root na")
        self.assertEqual(channels.judge_attempts(rules, required, optional), "unexpected")

    def test_forged_malformed_and_non_ascii_lines_never_count_as_proof(self):
        parsed = channels.parse_attempts(b"KDATT bad\nKDATT x denied extra\nKDATT \xff denied\nnoise KDATT a denied\n")
        self.assertEqual(parsed, [("invalid", "other")] * 3)
        rules = channels.ATTEMPT_RULES["redirect"]
        self.assertEqual(channels.judge_attempts(rules, b"KDATT http-redirect denied extra\n"), "unexpected")
        self.assertEqual(channels.judge_attempts(rules, b"  KDATT http-redirect denied\n"), "incomplete")

    def test_control_attempts_are_required_allowed_and_skipped_by_the_judgement(self):
        rules = channels.ATTEMPT_RULES["process_memory"]
        names = channels.control_names("process_memory")
        self.assertEqual(names, ("control-self-memory", "control-peer-environ"))
        output = passing("process_memory")
        self.assertEqual(channels.judge_attempts(rules, output), "ok")
        self.assertTrue(channels.control_attempts_allowed(output, names))
        weak = output.replace(b"KDATT control-peer-environ allowed", b"KDATT control-peer-environ denied")
        self.assertEqual(channels.judge_attempts(rules, weak), "ok")
        self.assertFalse(channels.control_attempts_allowed(weak, names))
        self.assertFalse(channels.control_attempts_allowed(output, ()))
        leak = output.replace(b"KDATT mem-read denied", b"KDATT mem-read allowed")
        self.assertEqual(channels.judge_attempts(rules, leak), "leak")

    def test_nonce_validation_is_exact(self):
        self.assertTrue(channels.valid_nonce(NONCE))
        for bad in ("", "A" * 24, NONCE + "0", NONCE[:-1], None, 5, "g" * 24):
            self.assertFalse(channels.valid_nonce(bad))


class LinuxRecordTests(unittest.TestCase):
    def test_valid_records_round_trip_and_are_bounded(self):
        value = record()
        text = channels.dump_record(value)
        self.assertLess(len(text), 4096)
        self.assertEqual(channels.load_record(text), value)
        self.assertTrue(channels.record_accepts(value))

    def test_records_refuse_unknown_keys_values_and_inconsistent_states(self):
        mutations = []
        base = record()
        extra = json.loads(json.dumps(base))
        extra["extra"] = 1
        mutations.append(extra)
        missing = json.loads(json.dumps(base))
        del missing["fixtures"]
        mutations.append(missing)
        bad_status = json.loads(json.dumps(base))
        bad_status["channels"]["https"]["status"] = "open"
        mutations.append(bad_status)
        bad_channel = json.loads(json.dumps(base))
        del bad_channel["channels"]["dns"]
        mutations.append(bad_channel)
        not_run_control = json.loads(json.dumps(base))
        not_run_control["channels"]["https"] = {"status": "not-run", "control": True}
        mutations.append(not_run_control)
        inconsistent = json.loads(json.dumps(base))
        inconsistent["reason"] = "channel_leak"
        mutations.append(inconsistent)
        accepted_without_none = json.loads(json.dumps(base))
        accepted_without_none["result"] = "refused"
        mutations.append(accepted_without_none)
        for index, value in enumerate(mutations):
            with self.subTest(index=index):
                with self.assertRaises(ValueError):
                    channels.dump_record(value)
        with self.assertRaises(ValueError):
            channels.load_record("x" * 9000)
        with self.assertRaises(ValueError):
            channels.load_record("[]")

    def test_acceptance_needs_every_channel_blocked_with_a_fired_control(self):
        value = record()
        self.assertTrue(channels.record_accepts(value))
        for name in channels.CHANNELS:
            for status, control in (("observed-leak", True), ("not-run", False), ("blocked", False)):
                changed = json.loads(json.dumps(value))
                changed["channels"][name] = {"status": status, "control": control}
                with self.subTest(name=name, status=status, control=control):
                    self.assertFalse(channels.record_accepts(changed))
        for key in ("memory_canary", "readable_file_canary"):
            for state in ("present", "not-run"):
                changed = json.loads(json.dumps(value))
                changed[key] = state
                self.assertFalse(channels.record_accepts(changed))
        self.assertFalse(channels.record_accepts(record(fixtures="failed")))
        self.assertTrue(channels.record_accepts(record(fixtures="not-run"), require_fixtures=False))

    def test_merge_marks_before_and_after_controls_and_the_worst_status(self):
        selftest = record("selftest")
        recheck = record("recheck", fixtures="not-run")
        merged = channels.merge_records(selftest, recheck)
        self.assertTrue(merged["accepted"])
        self.assertEqual(set(merged["channels"]), set(channels.CHANNELS))
        for entry in merged["channels"].values():
            self.assertEqual(entry, {"status": "blocked", "before": True, "after": True})
        recheck["channels"]["dns"] = {"status": "blocked", "control": False}
        recheck["result"] = "refused"
        recheck["reason"] = "control_not_fired"
        merged = channels.merge_records(selftest, recheck)
        self.assertFalse(merged["accepted"])
        self.assertEqual(merged["channels"]["dns"], {"status": "blocked", "before": True, "after": False})
        recheck["channels"]["https"] = {"status": "observed-leak", "control": True}
        self.assertEqual(channels.merge_records(selftest, recheck)["channels"]["https"]["status"], "observed-leak")
        recheck["channels"]["proxy"] = {"status": "not-run", "control": False}
        self.assertEqual(channels.merge_records(selftest, recheck)["channels"]["proxy"]["status"], "not-run")

    def test_merge_requires_the_right_phases_and_combines_canaries_conservatively(self):
        with self.assertRaises(ValueError):
            channels.merge_records(record("recheck"), record("recheck"))
        with self.assertRaises(ValueError):
            channels.merge_records(record("selftest"), record("selftest"))
        selftest = record("selftest")
        recheck = record("recheck", fixtures="not-run")
        recheck["memory_canary"] = "present"
        recheck["result"] = "refused"
        recheck["reason"] = "canary_present"
        merged = channels.merge_records(selftest, recheck)
        self.assertEqual(merged["memory_canary"], "present")
        self.assertFalse(merged["accepted"])
        self.assertEqual(channels.combine_canary("absent", "not-run"), "not-run")
        self.assertEqual(channels.combine_canary("absent", "absent"), "absent")
        self.assertEqual(channels.combine_canary("not-run", "present"), "present")


class LinuxProbeSourceTests(unittest.TestCase):
    def test_probe_and_launcher_sources_are_valid_standalone_python(self):
        ast.parse(probes.PROBE_SOURCE)
        ast.parse(probes.LAUNCHER_SOURCE)
        self.assertEqual(probes.PROBE_SOURCE, probes.PREAMBLE + probes.PROBE_BODY)

    def test_every_planned_attempt_is_implemented_by_the_probe_program(self):
        for channel, rules in channels.ATTEMPT_RULES.items():
            for name, accepted in rules:
                with self.subTest(channel=channel, name=name):
                    self.assertIn('"' + name + '"', probes.PROBE_SOURCE)
            self.assertIn('"' + channel + '"', probes.PROBE_SOURCE)

    def test_probe_program_never_contains_a_comment_marker_or_secret_material(self):
        for source in (probes.PROBE_SOURCE, probes.LAUNCHER_SOURCE):
            self.assertNotIn(chr(35), source)
            self.assertNotIn("KD_CANARY_SECRET", source)
            self.assertNotIn("kd-synthetic-standin", source)

    def test_launcher_stops_itself_before_exec_so_the_supervisor_can_read_back_state(self):
        tree = ast.parse(probes.LAUNCHER_SOURCE)
        calls = [
            node.func.attr
            for node in ast.walk(tree)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        ]
        self.assertEqual(sorted(calls), ["execv", "getpid", "kill"])
        self.assertLess(probes.LAUNCHER_SOURCE.index("SIGSTOP"), probes.LAUNCHER_SOURCE.index("execv"))
        self.assertIn("SIGSTOP", probes.LAUNCHER_SOURCE)

    def test_probe_classifies_ssl_errors_as_not_denied_and_unknown_errors_as_other(self):
        self.assertIn("ssl.SSLError", probes.PROBE_SOURCE)
        self.assertIn('"other"', probes.PROBE_SOURCE)
        self.assertIn("contained", probes.PROBE_SOURCE)



class LinuxReviewFixChannelTests(unittest.TestCase):
    def test_records_carry_bounded_fixture_attempt_counts_and_merge_keeps_them(self):
        value = record()
        value["fixture_attempts"] = {"controlled": 20, "uncontrolled": 25}
        self.assertEqual(channels.load_record(channels.dump_record(value)), value)
        for bad in ({"controlled": 1}, {"controlled": -1, "uncontrolled": 0}, {"controlled": True, "uncontrolled": 0}, {"controlled": 501, "uncontrolled": 0}, [], {"controlled": 1, "uncontrolled": 1, "x": 1}):
            changed = json.loads(json.dumps(value))
            changed["fixture_attempts"] = bad
            with self.assertRaises(ValueError):
                channels.dump_record(changed)
        merged = channels.merge_records(value, record("recheck", fixtures="not-run"))
        self.assertEqual(merged["fixture_attempts"], {"controlled": 20, "uncontrolled": 25})

    def test_no_new_privs_is_read_from_proc_status_not_cleared(self):
        names = [name for name, accepted in channels.ATTEMPT_RULES["boundary_disablement"]]
        self.assertIn("nnp-set", names)
        self.assertNotIn("nnp-clear", names)
        self.assertIn("NoNewPrivs:", probes.PROBE_SOURCE)
        self.assertNotIn("prctl(38", probes.PROBE_SOURCE)


if __name__ == "__main__":
    unittest.main(verbosity=2)
