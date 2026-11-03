import ast
import json
import re
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
    "LinuxFixtureDiagnosticLineTests",
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
            (("ptrace-scope", "3"), ("project-uid", "62000"), ("usr-submounts", "ro"), ("runner-uid-distinct", "1")),
        )
        self.assertEqual(
            readback,
            "KD-LINUX-READBACK schema=1 phase=selftest ptrace-scope=3 project-uid=62000 usr-submounts=ro runner-uid-distinct=1",
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

    def test_first_unaccepted_names_the_rule_index_and_ignores_controls_and_optional_na(self):
        rules = channels.ATTEMPT_RULES["process_memory"]
        good = passing("process_memory")
        self.assertIsNone(channels.first_unaccepted(rules, good))
        other = good.replace(b"KDATT ptrace-attach denied", b"KDATT ptrace-attach other")
        self.assertEqual(channels.first_unaccepted(rules, other), 2)
        leak = good.replace(b"KDATT mem-read denied", b"KDATT mem-read allowed")
        self.assertIsNone(channels.first_unaccepted(rules, leak))
        weak = good.replace(b"KDATT control-peer-environ allowed", b"KDATT control-peer-environ other")
        self.assertIsNone(channels.first_unaccepted(rules, weak))
        boundary_rules = channels.ATTEMPT_RULES["boundary_disablement"]
        na = lines(*("KDATT " + name + (" na" if name == "sudo" else " denied") for name, accepted in boundary_rules))
        self.assertEqual(channels.first_unaccepted(boundary_rules, na), 9)
        self.assertIsNone(channels.first_unaccepted(boundary_rules, na, channels.OPTIONAL_ATTEMPTS["boundary_disablement"]))

    def test_fixture_lines_are_closed_and_bounded(self):
        line = channels.fixture_line("selftest", "proc_macro", BoundaryRefusal("fixture_incomplete", None, 3))
        self.assertEqual(
            line, "KD-LINUX-FIXTURE schema=1 phase=selftest form=proc_macro result=refused reason=fixture_incomplete detail=3"
        )
        self.assertNotIn("detail", channels.fixture_line("recheck", "shell", BoundaryRefusal("fixture_allowed")))
        for phase, form in (("other", "shell"), ("selftest", "Shell"), ("selftest", "a b"), ("selftest", 5), ("selftest", "x" * 21)):
            with self.assertRaises(ValueError):
                channels.fixture_line(phase, form, BoundaryRefusal("fixture_allowed"))

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

    def test_socketpair_routes_are_pinned_attempts_in_raw_logs_and_runner_ipc(self):
        self.assertEqual(
            [name for name, accepted in channels.ATTEMPT_RULES["raw_logs"]],
            ["stdout-markers", "tty-open", "syslog-socket", "journal-socket", "syslog-pair", "journal-pair"],
        )
        self.assertEqual(
            [name for name, accepted in channels.ATTEMPT_RULES["runner_ipc"]],
            ["unix-path", "unix-abstract", "unix-pair-connect", "fd-inventory"],
        )
        for channel, name in (("raw_logs", "syslog-pair"), ("raw_logs", "journal-pair"), ("runner_ipc", "unix-pair-connect")):
            with self.subTest(name=name):
                self.assertEqual(dict(channels.ATTEMPT_RULES[channel])[name], channels.DENIED)
        self.assertEqual(sum(len(rules) for rules in channels.ATTEMPT_RULES.values()), 44)
        body = probes.PROBE_BODY
        raw = body[body.index("def run_raw_logs():"):body.index("def hunt():")]
        self.assertIn("socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)", raw)
        self.assertIn('attempt("syslog-pair", pair_datagram("/dev/log"))', raw)
        self.assertIn('attempt("journal-pair", pair_datagram("/run/systemd/journal/socket"))', raw)
        self.assertLess(raw.index('attempt("journal-socket"'), raw.index('attempt("syslog-pair"'))
        ipc = body[body.index("def run_runner_ipc():"):body.index("def run_raw_logs():")]
        self.assertIn("socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)", ipc)
        self.assertIn('first.connect(cfg["unix_path"])', ipc)
        self.assertIn('attempt("unix-pair-connect", unix_pair_connect, accepted=NET_DENIED + (errno.EISCONN,))', ipc)
        self.assertNotIn("SOCK_DGRAM", ipc)
        self.assertEqual(body.count('("s-" + nonce)'), 1)
        self.assertNotIn(("runner_ipc", "s-" + NONCE), channels.control_markers("runner_ipc", NONCE, False))
        self.assertEqual(channels.parse_attempts(passing("raw_logs"))[-2:], [("syslog-pair", "denied"), ("journal-pair", "denied")])
        self.assertEqual(channels.judge_attempts(channels.ATTEMPT_RULES["raw_logs"], passing("raw_logs")), "ok")
        leaked = passing("raw_logs").replace(b"KDATT journal-pair denied", b"KDATT journal-pair allowed")
        self.assertEqual(channels.judge_attempts(channels.ATTEMPT_RULES["raw_logs"], leaked), "leak")
        stale = passing("runner_ipc").replace(b"KDATT unix-pair-connect denied\n", b"")
        self.assertEqual(channels.judge_attempts(channels.ATTEMPT_RULES["runner_ipc"], stale), "incomplete")

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
        self.assertEqual(
            sorted(calls),
            ["close", "close", "dup2", "execv", "getpid", "kill", "pipe", "set_inheritable"],
        )
        self.assertLess(probes.LAUNCHER_SOURCE.index("SIGSTOP"), probes.LAUNCHER_SOURCE.index("execv"))
        self.assertIn("SIGSTOP", probes.LAUNCHER_SOURCE)

    def test_launcher_gives_the_program_an_end_of_file_stdin_only_after_it_is_verified_and_resumed(self):
        source = probes.LAUNCHER_SOURCE
        self.assertLess(source.index("SIGSTOP"), source.index("os.pipe()"))
        self.assertLess(source.index("os.pipe()"), source.index("os.close(writer)"))
        self.assertLess(source.index("os.close(writer)"), source.index("os.set_inheritable(reader, True)"))
        self.assertLess(source.index("os.set_inheritable(reader, True)"), source.index("execv"))
        self.assertIn("os.dup2(reader, 0)", source)
        self.assertNotIn("socketpair", source)
        self.assertNotIn("/dev/null", source)

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


class LinuxFixtureDiagnosticLineTests(unittest.TestCase):
    LINE = re.compile(
        r"^KD-LINUX-FIXTURE-DIAG schema=1 phase=selftest form=[a-z_]{1,20} stream=stderr line=[A-Za-z0-9 ._:/=+,()'" + chr(34) + r"-]*$"
    )

    def lines(self, stderr, needles=(), header=None, nonce=NONCE, form="build_rs", phase="selftest"):
        return channels.fixture_diag_lines(phase, form, stderr, nonce, needles, header)

    def texts(self, produced):
        prefix = "KD-LINUX-FIXTURE-DIAG schema=1 phase=selftest form=build_rs stream=stderr line="
        return [line[len(prefix):] for line in produced]

    def test_a_diagnostic_line_has_the_exact_public_shape(self):
        self.assertEqual(
            channels.diag_line("selftest", "build_rs", "error: linking with gcc failed"),
            "KD-LINUX-FIXTURE-DIAG schema=1 phase=selftest form=build_rs stream=stderr line=error: linking with gcc failed",
        )
        produced = self.lines(b"first\nsecond line: ok\n")
        self.assertEqual(self.texts(produced), ["first", "second line: ok"])
        for line in produced:
            self.assertRegex(line, self.LINE)
            self.assertFalse(line.startswith("::"))

    def test_every_character_outside_the_allowed_set_becomes_a_question_mark(self):
        raw = b"error[E0463]: can't find crate\tfor `std` <x> {y} $z @ % ! ~ ; | * \\ \xc3\xa9"
        produced = self.lines(raw)
        self.assertEqual(len(produced), 1)
        text = self.texts(produced)[0]
        self.assertEqual(text, "error?E0463?: can't find crate?for ?std? ?x? ?y? ?z ? ? ? ? ? ? ? ? ??")
        for character in text:
            self.assertTrue(character in channels.DIAG_ALPHABET or character == "?")
        self.assertIn("'", channels.DIAG_ALPHABET)
        self.assertIn(chr(34), channels.DIAG_ALPHABET)
        self.assertNotIn("[", channels.DIAG_ALPHABET)
        self.assertNotIn(chr(10), channels.DIAG_ALPHABET)

    def test_each_line_is_capped_at_two_hundred_characters(self):
        produced = self.lines(("ab " * 100).encode("ascii") + b"\nshort\n")
        texts = self.texts(produced)
        self.assertEqual(len(texts[0]), 200)
        self.assertEqual(texts[1], "short")
        with self.assertRaises(ValueError):
            channels.diag_line("selftest", "build_rs", "a" * 201)

    def test_at_most_twenty_lines_are_kept_from_the_end_of_the_stream(self):
        stderr = "".join("line " + str(index) + chr(10) for index in range(60)).encode("ascii")
        texts = self.texts(self.lines(stderr))
        self.assertEqual(len(texts), channels.DIAG_MAX_LINES)
        self.assertEqual(texts[0], "line 40")
        self.assertEqual(texts[-1], "line 59")
        with_header = self.texts(self.lines(stderr, header="kd-host exit=134"))
        self.assertEqual(len(with_header), channels.DIAG_MAX_LINES)
        self.assertEqual(with_header[0], "kd-host exit=134")
        self.assertEqual(with_header[1], "line 41")
        self.assertEqual(with_header[-1], "line 59")
        self.assertEqual(self.lines(b""), ())
        self.assertEqual(self.lines(b"\n\n  \n"), ())

    def test_a_truncated_first_line_of_a_long_stream_is_dropped(self):
        stderr = b"cut off tail text\n" * 1500
        self.assertGreater(len(stderr), channels.DIAG_TAIL_BYTES)
        texts = self.texts(self.lines(stderr))
        self.assertEqual(texts, ["cut off tail text"] * channels.DIAG_MAX_LINES)

    def test_lines_carrying_the_nonce_a_canary_form_or_a_marker_are_dropped(self):
        needle = b"kd-synthetic-standin-NOT-A-SECRET"
        stderr = b"\n".join((
            b"keep one",
            b"::error::fx-secret-" + NONCE.encode("ascii"),
            b"   ::add-mask::value",
            b"prefix fx-npm-" + NONCE.upper().encode("ascii") + b" suffix",
            b"seen " + needle + b" here",
            b"seen " + needle.lower() + b" lower",
            b"marker kd-log-" + NONCE.encode("ascii"),
            b"env KD_CANARY_SECRET=value",
            b"keep two",
        ))
        texts = self.texts(self.lines(stderr, (needle,)))
        self.assertEqual(texts, ["keep one", "keep two"])

    def test_token_like_runs_longer_than_thirty_two_characters_are_dropped(self):
        thirty_two = "g" * 32
        stderr = "\n".join((
            "keep " + thirty_two,
            "drop " + "g" * 33,
            "drop " + "0123456789abcdef" * 3,
            "drop " + "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo" + "/+AAAA",
            "keep path /usr/lib/x86_64-linux-gnu/crt1.o",
            "keep core::fmt::Formatter::write_str",
        )).encode("ascii")
        texts = self.texts(self.lines(stderr))
        self.assertEqual(len(texts), 3)
        self.assertEqual(texts[0], "keep " + thirty_two)
        self.assertTrue(texts[1].startswith("keep path"))
        self.assertTrue(texts[2].startswith("keep core"))
        self.assertEqual(sum(1 for text in texts if text.startswith("drop")), 0)

    def test_a_hex_run_of_twenty_or_more_characters_is_dropped_but_shorter_runs_stay(self):
        stderr = "\n".join((
            "keep " + "abcdef0123456789abc",
            "drop " + "abcdef0123456789abcd",
            "drop " + "0123456789ABCDEF0123456789abcdef",
            "drop prefix-" + "ab12" * 8,
        )).encode("ascii")
        self.assertEqual(self.texts(self.lines(stderr)), ["keep abcdef0123456789abc"])

    def test_base64url_values_are_caught_on_the_raw_line_including_dash_and_underscore(self):
        part = "QUJDREVGR0hJSktMTU5P"
        stderr = "\n".join((
            "drop " + part + "-" + part,
            "drop " + part + "_" + part,
            "drop " + "x" * 16 + "_" + "y" * 16 + "-" + "z" * 4,
            "keep " + "x" * 16 + "_" + "y" * 15,
        )).encode("ascii")
        self.assertEqual(self.texts(self.lines(stderr)), ["keep " + "x" * 16 + "_" + "y" * 15])

    def test_a_hosted_runner_sysroot_listing_line_is_kept(self):
        line = "drwxr-xr-x 9 1001 118 4096 Nov  2 04:38 /tmp/kd-toolchains/rust/stable-x86_64-unknown-linux-gnu"
        cleaned = channels.diag_clean(line)
        self.assertFalse(channels.diag_unsafe(line, cleaned, NONCE, ()))
        self.assertTrue(channels.diag_unsafe("k" * 33, "k" * 33, NONCE, ()))
        self.assertTrue(channels.diag_unsafe("k" * 20 + "-" + "k" * 20, "k" * 20 + "-" + "k" * 20, NONCE, ()))

    def test_the_token_scan_also_runs_on_the_raw_line_before_cleaning(self):
        token = "g" * 20 + "_" + "g" * 20
        wide = "k " * 101 + token
        cleaned = channels.diag_clean(wide)
        self.assertEqual(len(cleaned), channels.DIAG_MAX_CHARS)
        self.assertNotIn(token, cleaned)
        self.assertIsNone(channels.DIAG_TOKEN.search(cleaned))
        self.assertIsNone(channels.DIAG_TOKEN_URL.search(cleaned))
        self.assertIsNotNone(channels.DIAG_TOKEN_URL.search(wide))
        self.assertTrue(channels.diag_unsafe(wide, cleaned, NONCE, ()))
        self.assertFalse(channels.diag_unsafe(cleaned, cleaned, NONCE, ()))
        self.assertFalse(channels.diag_unsafe("plain text", "plain text", NONCE, ()))

    def test_a_bare_hex_needle_drops_a_short_fragment_line(self):
        needle = b"0123456789abcdef"
        stderr = b"keep one\nvalue 0123456789ABCDEF here\nkeep two\n"
        self.assertEqual(self.texts(self.lines(stderr, (needle,))), ["keep one", "keep two"])
        self.assertEqual(self.texts(self.lines(stderr)), ["keep one", "value 0123456789ABCDEF here", "keep two"])

    def test_diag_line_accepts_the_replacement_character_and_rejects_other_characters(self):
        self.assertEqual(
            channels.diag_line("selftest", "build_rs", "a?b"),
            "KD-LINUX-FIXTURE-DIAG schema=1 phase=selftest form=build_rs stream=stderr line=a?b",
        )
        for text in ("a[b", "a`b", "a" + chr(10) + "b", "a" + chr(233), "a$b", 5, None):
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    channels.diag_line("selftest", "build_rs", text)

    def test_lines_without_any_letter_or_digit_are_dropped(self):
        self.assertEqual(self.lines(b"-----\n???\n[]{}<>\n   \n.\n"), ())

    def test_only_the_selftest_phase_can_ever_produce_a_diagnostic(self):
        stderr = b"error: something\n"
        self.assertEqual(len(self.lines(stderr)), 1)
        for phase in ("recheck", "source", "project", "build", "", "SELFTEST", None, 5):
            with self.subTest(phase=phase):
                self.assertEqual(self.lines(stderr, phase=phase), ())
                with self.assertRaises(ValueError):
                    channels.diag_line(phase, "build_rs", "error")
        self.assertEqual(channels.DIAG_PHASES, ("selftest",))

    def test_the_form_must_be_a_fixture_name(self):
        for form in ("Shell", "a b", 5, None, "x" * 21, ""):
            with self.assertRaises(ValueError):
                channels.fixture_diag_lines("selftest", form, b"error\n", NONCE, ())
            with self.assertRaises(ValueError):
                channels.diag_line("selftest", form, "error")

    def test_the_stream_must_be_bytes_and_the_header_is_filtered_like_any_line(self):
        self.assertEqual(self.lines("text"), ())
        self.assertEqual(self.lines(None), ())
        self.assertEqual(self.texts(self.lines(b"", header="kd-host ok")), ["kd-host ok"])
        self.assertEqual(self.lines(b"", header="kd-host " + NONCE), ())

    def test_refusal_evidence_is_a_header_and_bytes_pair_or_nothing(self):
        good = ("kd-host exit=1", b"error\n")
        self.assertEqual(BoundaryRefusal("fixture_incomplete", None, 1, good).evidence, good)
        self.assertIsNone(BoundaryRefusal("fixture_incomplete").evidence)
        for bad in ("text", ("a", "b"), (b"a", b"b"), ("a",), ["a", b"b"], 5):
            self.assertIsNone(BoundaryRefusal("fixture_incomplete", None, 1, bad).evidence)

if __name__ == "__main__":
    unittest.main(verbosity=2)
