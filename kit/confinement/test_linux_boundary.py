import base64
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import linux_boundary as boundary
import linux_channels as channels
import linux_fixtures as fixtures
import linux_harness as harness
import linux_probes as probes
import linux_session as session
from linux_channels import BoundaryRefusal


__all__ = [
    "LinuxBoundaryDecisionTests",
    "LinuxBoundaryPhaseTests",
    "LinuxBoundaryFaultTests",
    "LinuxBoundaryCommandTests",
    "LinuxBoundaryReviewFixTests",
    "LinuxBoundarySecondReviewTests",
    "LinuxBoundaryProcessMemoryTests",
    "LinuxBoundaryFixtureDiagnosticTests",
    "LinuxBoundaryFixtureStderrDiagnosticTests",
]

SHA = "a" * 40


def arguments(**changes):
    values = {
        "control_sha": SHA,
        "record": None,
        "runner_uid": 1001,
        "runner_home": None,
        "runner_temp": None,
        "rust_sysroot": None,
        "synthetic_standin": True,
    }
    values.update(changes)
    return SimpleNamespace(**values)


def make(**changes):
    emitter = boundary.Emitter(io.StringIO())
    return boundary.Boundary(arguments(**changes), emitter), emitter


def blocked(channel):
    return boundary.Outcome("blocked", True)


def result(stdout=b"", timed_out=False):
    return SimpleNamespace(stdout=stdout, stderr=b"", timed_out=timed_out, readback={})


def realistic(subject, outcome):
    for form in fixtures.FORMS[:outcome[0]]:
        total = len(fixtures.fixture_rules(form))
        uncontrolled = len(fixtures.uncontrolled_attempts(form))
        subject.fixture_controlled += total - uncontrolled
        subject.fixture_uncontrolled += uncontrolled
    return outcome


class LinuxBoundaryDecisionTests(unittest.TestCase):
    def test_not_run_outcomes_can_never_claim_a_fired_control(self):
        self.assertFalse(boundary.Outcome("not-run", True).control)
        self.assertTrue(boundary.Outcome("blocked", True).control)

    def test_decision_table_maps_each_observation_to_one_closed_reason(self):
        subject, unused = make()
        cases = (
            (result(timed_out=True), "ok", [], True, "not-run", "attempt_incomplete"),
            (result(), "ok", [("https4", b"x")], True, "observed-leak", "channel_leak"),
            (result(), "leak", [], True, "observed-leak", "channel_leak"),
            (result(), "unexpected", [], True, "not-run", "attempt_unexpected"),
            (result(), "incomplete", [], True, "not-run", "attempt_incomplete"),
            (result(), "ok", [], False, "blocked", "control_not_fired"),
            (result(), "ok", [], True, "blocked", None),
        )
        for index, (observed, verdict, leaks, control, status, reason) in enumerate(cases):
            with self.subTest(index=index):
                outcome = subject.decide(observed, verdict, leaks, control)
                self.assertEqual(outcome.status, status)
                self.assertEqual(None if outcome.refusal is None else outcome.refusal.reason, reason)
                if status == "not-run":
                    self.assertFalse(outcome.control)
                elif status == "blocked":
                    self.assertEqual(outcome.control, control)

    def test_transcript_scan_finds_markers_workflow_commands_and_canary_forms(self):
        nonce = "0123456789abcdef01234567"
        needles = (b"canary-value-0123456789",)
        self.assertEqual(boundary.transcript_hits(["clean line", "another"], nonce, needles), 0)
        self.assertEqual(boundary.transcript_hits(["x kd-log-" + nonce], nonce, needles), 1)
        self.assertEqual(boundary.transcript_hits(["::error::anything"], nonce, needles), 1)
        self.assertEqual(boundary.transcript_hits(["has canary-value-0123456789 inside"], nonce, needles), 1)
        self.assertEqual(boundary.transcript_hits(["a", "::b", "kd-log-" + nonce], nonce, needles), 2)

    def test_control_sha_must_be_a_full_hex_digest_equal_to_the_checked_out_head(self):
        for bad in ("", "abc", SHA.upper(), None, SHA + "0"):
            with self.assertRaises(BoundaryRefusal):
                boundary.verify_control_sha(bad)
        with patch("linux_boundary.subprocess.run", return_value=SimpleNamespace(stdout=(SHA + "\n").encode())):
            boundary.verify_control_sha(SHA)
        with patch("linux_boundary.subprocess.run", return_value=SimpleNamespace(stdout=(("b" * 40) + "\n").encode())):
            with self.assertRaises(BoundaryRefusal):
                boundary.verify_control_sha(SHA)

    def test_readback_before_the_drop_checks_scope_user_namespaces_and_distinct_uid(self):
        subject, unused = make()

        def sysctl(path):
            values = {"ptrace_scope": "3", "max_user_namespaces": "0", "unprivileged_bpf_disabled": "2", "perf_event_paranoid": "4"}
            return values[path.rsplit("/", 1)[1]]

        with patch("linux_boundary.harness._read_sysctl", side_effect=sysctl):
            subject.readback_before_drop()
            self.assertEqual(subject.scope, "3")
            with self.assertRaises(BoundaryRefusal) as raised:
                subject.readback_before_drop(lambda path: "1")
            self.assertEqual((raised.exception.reason, raised.exception.detail), ("readback_failed", 61))
        with patch("linux_boundary.harness._read_sysctl", side_effect=lambda path: "3" if "ptrace" in path else "1"):
            with self.assertRaises(BoundaryRefusal) as raised:
                subject.readback_before_drop()
            self.assertEqual(raised.exception.detail, 62)
        shared, unused = make(runner_uid=harness.CHILD_UID)
        with patch("linux_boundary.harness._read_sysctl", side_effect=sysctl):
            with self.assertRaises(BoundaryRefusal) as raised:
                shared.readback_before_drop()
            self.assertEqual(raised.exception.detail, 23)

    def test_prepare_refuses_without_root_and_a_non_standin_canary_in_synthetic_mode(self):
        subject, unused = make()
        with patch("linux_boundary.os.geteuid", return_value=1000):
            with self.assertRaises(BoundaryRefusal):
                subject.prepare(True)
        other, unused = make()
        with patch("linux_boundary.os.geteuid", return_value=0), \
             patch("linux_boundary.verify_control_sha"), \
             patch.object(boundary.Boundary, "readback_before_drop"), \
             patch.dict(os.environ, {"KD_CANARY_SECRET": "x" * 40}):
            with self.assertRaises(BoundaryRefusal):
                other.prepare(False)


class LinuxBoundaryPhaseTests(unittest.TestCase):
    def phase(self, phase="selftest", fixtures_result=(5, None), outcomes=None, memory="absent", readable="absent"):
        subject, emitter = make()
        subject.memory_canary = memory
        subject.readable_canary = readable
        subject.scope = "3"
        table = outcomes or {}
        with patch.object(boundary.Boundary, "run_channel", side_effect=lambda channel: table.get(channel, blocked(channel))), \
             patch.object(boundary.Boundary, "run_fixtures", side_effect=lambda: realistic(subject, fixtures_result)):
            record, refusal = boundary.run_phase(subject, phase, phase == "selftest")
        return record, refusal, emitter.stream.getvalue().splitlines()

    def test_a_fully_proved_selftest_is_accepted_with_eleven_channel_lines(self):
        record, refusal, output = self.phase()
        self.assertIsNone(refusal)
        self.assertTrue(channels.record_accepts(record))
        self.assertEqual(len([line for line in output if line.startswith("KD-LINUX-CHANNEL")]), 11)
        self.assertIn("KD-LINUX-FIXTURES schema=1 phase=selftest forms=5/5 result=complete controlled=24 uncontrolled=30", output)
        self.assertEqual(record["fixture_attempts"], {"controlled": 24, "uncontrolled": 30})
        self.assertEqual(
            output[-1],
            "linux-source-boundary=accepted phase=selftest channels=11/11 project-execution=permitted",
        )
        self.assertTrue(any(line.startswith("KD-LINUX-CANARY") and "memory-canary=absent" in line for line in output))
        self.assertTrue(any(line.startswith("KD-LINUX-READBACK") for line in output))

    def test_recheck_skips_fixtures_and_still_accepts(self):
        record, refusal, output = self.phase("recheck", fixtures_result=(0, BoundaryRefusal("fixture_incomplete")))
        self.assertIsNone(refusal)
        self.assertEqual(record["fixtures"], "not-run")
        self.assertFalse(any("FIXTURES" in line for line in output))
        self.assertTrue(output[-1].endswith("project-execution=permitted"))

    def test_any_single_unproved_channel_refuses_and_blocks_project_execution(self):
        for channel in channels.CHANNELS:
            for outcome, reason in (
                (boundary.Outcome("observed-leak", True, BoundaryRefusal("channel_leak", channel)), "channel_leak"),
                (boundary.Outcome("blocked", False, BoundaryRefusal("control_not_fired", channel)), "control_not_fired"),
                (boundary.Outcome("not-run", False, BoundaryRefusal("attempt_incomplete", channel)), "attempt_incomplete"),
            ):
                with self.subTest(channel=channel, reason=reason):
                    record, refusal, output = self.phase(outcomes={channel: outcome})
                    self.assertEqual(refusal.reason, reason)
                    self.assertEqual(record["result"], "refused")
                    self.assertFalse(channels.record_accepts(record))
                    self.assertTrue(output[-1].endswith("project-execution=not_started"))
                    self.assertIn("reason=" + reason, output[-1])
                    self.assertEqual(len([line for line in output if line.startswith("KD-LINUX-CHANNEL")]), 11)

    def test_a_silent_unproved_channel_without_a_refusal_still_refuses(self):
        record, refusal, output = self.phase(outcomes={"dns": boundary.Outcome("blocked", False)})
        self.assertEqual(refusal.reason, "control_not_fired")
        self.assertTrue(output[-1].endswith("project-execution=not_started"))

    def test_failed_fixtures_and_present_canaries_refuse(self):
        record, refusal, output = self.phase(fixtures_result=(4, BoundaryRefusal("fixture_allowed")))
        self.assertEqual(refusal.reason, "fixture_allowed")
        self.assertEqual(record["fixtures"], "failed")
        self.assertIn("forms=4/5 result=failed", " ".join(output))
        for memory, readable in (("present", "absent"), ("absent", "present"), ("not-run", "absent")):
            record, refusal, output = self.phase(memory=memory, readable=readable)
            self.assertEqual(refusal.reason, "canary_present")
            self.assertTrue(output[-1].endswith("project-execution=not_started"))

    def test_public_output_stays_inside_the_closed_vocabulary(self):
        record, refusal, output = self.phase(outcomes={"https": boundary.Outcome("observed-leak", True, BoundaryRefusal("channel_leak", "https", 7))})
        allowed = (
            "KD-LINUX-CHANNEL ", "KD-LINUX-CANARY ", "KD-LINUX-READBACK ", "KD-LINUX-FIXTURES ", "linux-source-boundary=",
        )
        for line in output:
            self.assertTrue(line.startswith(allowed), line)
            self.assertRegex(line, r"^[A-Za-z0-9 =/_.-]+$")
            self.assertNotIn("::", line)

    def test_record_files_are_private_and_validated(self):
        record, refusal, output = self.phase()
        with tempfile.TemporaryDirectory() as base:
            path = os.path.join(base, "record.json")
            boundary.write_record(path, record)
            self.assertEqual(os.stat(path).st_mode & 0o077, 0)
            with open(path) as source:
                self.assertEqual(channels.load_record(source.read()), record)
            with self.assertRaises(FileExistsError):
                boundary.write_record(path, record)
            link = os.path.join(base, "link.json")
            os.symlink(path, link)
            with self.assertRaises(OSError):
                boundary.write_record(link, record)
        refused = boundary.refused_record("recheck", BoundaryRefusal("environment"))
        self.assertEqual(refused["result"], "refused")
        channels.validate_record(refused)

    def test_run_channel_converts_exceptions_into_not_run_outcomes_with_the_channel_named(self):
        subject, unused = make()
        with patch.object(boundary.Boundary, "network_channel", side_effect=BoundaryRefusal("readback_failed", None, 95)):
            outcome = subject.run_channel("https")
        self.assertEqual(outcome.status, "not-run")
        self.assertEqual((outcome.refusal.reason, outcome.refusal.channel, outcome.refusal.detail), ("readback_failed", "https", 95))
        with patch.object(boundary.Boundary, "network_channel", side_effect=harness.ProofFailure(47)):
            outcome = subject.run_channel("dns")
        self.assertEqual((outcome.refusal.reason, outcome.refusal.detail), ("readback_failed", 47))
        with patch.object(boundary.Boundary, "network_channel", return_value=boundary.Outcome("blocked", False, BoundaryRefusal("control_not_fired"))):
            self.assertEqual(subject.run_channel("proxy").refusal.channel, "proxy")


class LinuxBoundaryFaultTests(unittest.TestCase):
    def test_fault_table_expects_a_closed_refusal_reason_for_every_fault(self):
        self.assertEqual(len(boundary.FAULTS), 10)
        for name, reason in boundary.FAULTS.items():
            self.assertIn(reason, channels.REASONS)
            self.assertRegex(name, r"^[a-z-]+$")
        for required in ("network-open", "control-dead", "usr-writable", "uid-root", "canary-readable", "canary-env", "scope-lowered", "fixture-allowed", "fixture-truncated", "recheck-dead"):
            self.assertIn(required, boundary.FAULTS)

    def test_every_fault_is_dispatched_and_reports_refused_when_the_expected_reason_occurs(self):
        for name, expected in boundary.FAULTS.items():
            subject, emitter = make()
            subject.scope = "3"
            refusal = BoundaryRefusal(expected, "https")
            with self.subTest(name=name), \
                 patch.object(boundary.Boundary, "run_channel", return_value=boundary.Outcome("not-run", False, refusal)) as run_channel, \
                 patch.object(boundary.Boundary, "fixture_outcome", side_effect=BoundaryRefusal(expected)) as fixture_outcome, \
                 patch("linux_boundary.harness._read_sysctl", return_value="3"):
                self.assertTrue(boundary.run_fault(subject, name))
            text = emitter.stream.getvalue()
            self.assertIn("linux-forced-fault name=" + name + " result=refused reason=" + expected, text)
            self.assertIsNone(subject.fault)
            if name == "recheck-dead":
                self.assertIn("phase=recheck", text)
                self.assertIn("project-execution=not_started", text)
            if name.startswith("fixture-"):
                fixture_outcome.assert_called_once()
                run_channel.assert_not_called()

    def real_network_boundary(self):
        subject, emitter = make()
        store = session.EventStore()
        subject.tripwires = SimpleNamespace(
            store=store,
            ipv6=False,
            config=lambda: {"nonce": subject.nonce, "ports": {"https4": 1111, "dns_udp": 53}, "unix_path": "/ipc/docker.sock", "abstract_name": "kd-x"},
        )

        def chroot(argv, env, mode="confined", **options):
            config = json.loads(argv[-1])
            channel = argv[-2]
            if mode == "open":
                if config["ports"]["https4"] != 9 and channel == "https":
                    store.record("https4", ("v4-" + subject.nonce + " host-" + subject.nonce).encode())
                return result(b"")
            rules = channels.ATTEMPT_RULES[channel]
            return result(("".join("KDATT " + name + " " + accepted[0] + chr(10) for name, accepted in rules)).encode())

        subject.chroot = chroot
        return subject

    def test_recheck_dead_is_injected_by_the_real_network_channel_for_https_only(self):
        subject = self.real_network_boundary()
        healthy = subject.network_channel("https")
        self.assertEqual((healthy.status, healthy.control, healthy.refusal), ("blocked", True, None))
        subject.fault = "recheck-dead"
        dead = subject.network_channel("https")
        self.assertEqual(dead.refusal.reason, "control_not_fired")
        self.assertFalse(dead.control)
        self.assertEqual(subject.run_channel("https").refusal.reason, "control_not_fired")
        subject.fault = None
        self.assertTrue(boundary.run_fault(subject, "recheck-dead"))

    def test_a_fault_that_does_not_refuse_or_refuses_for_another_reason_is_reported_unexpected(self):
        subject, emitter = make()
        with patch.object(boundary.Boundary, "run_channel", return_value=boundary.Outcome("blocked", True)):
            self.assertFalse(boundary.run_fault(subject, "network-open"))
        self.assertIn("result=unexpected reason=none expected=channel_leak", emitter.stream.getvalue())
        subject, emitter = make()
        wrong = boundary.Outcome("not-run", False, BoundaryRefusal("attempt_incomplete", "https"))
        with patch.object(boundary.Boundary, "run_channel", return_value=wrong):
            self.assertFalse(boundary.run_fault(subject, "network-open"))
        self.assertIn("result=unexpected reason=attempt_incomplete", emitter.stream.getvalue())

    def test_scope_fault_uses_the_real_readback_with_an_injected_value(self):
        subject, emitter = make()
        with patch("linux_boundary.harness._read_sysctl", return_value="0"):
            self.assertTrue(boundary.run_fault(subject, "scope-lowered"))
        self.assertIn("name=scope-lowered result=refused reason=readback_failed", emitter.stream.getvalue())

    def test_fixture_faults_use_the_python_and_shell_forms(self):
        for name, form in (("fixture-allowed", "python"), ("fixture-truncated", "shell")):
            subject, unused = make()
            with patch.object(boundary.Boundary, "fixture_outcome", side_effect=BoundaryRefusal(boundary.FAULTS[name])) as call:
                boundary.run_fault(subject, name)
            call.assert_called_once_with(form)

    def test_missing_rust_toolchain_fails_closed_for_the_rust_forms_only(self):
        subject, unused = make()
        for form in fixtures.NEEDS_RUSTC:
            with self.assertRaises(BoundaryRefusal) as raised:
                subject.fixture_outcome(form)
            self.assertEqual(raised.exception.reason, "fixture_incomplete")


class LinuxBoundaryCommandTests(unittest.TestCase):
    def test_merge_reports_acceptance_only_when_both_phases_are_proved(self):
        selftest = channels.empty_record("selftest")
        recheck = channels.empty_record("recheck")
        for record in (selftest, recheck):
            for name in channels.CHANNELS:
                record["channels"][name] = {"status": "blocked", "control": True}
            record["memory_canary"] = "absent"
            record["readable_file_canary"] = "absent"
            record["result"] = "accepted"
            record["reason"] = "none"
        selftest["fixtures"] = "complete"
        with tempfile.TemporaryDirectory() as base:
            first = os.path.join(base, "a.json")
            second = os.path.join(base, "b.json")
            merged = os.path.join(base, "merged.json")
            for path, record in ((first, selftest), (second, recheck)):
                boundary.write_record(path, record)
            out = io.StringIO()
            with patch("linux_boundary.sys.stdout", out):
                code = boundary.main(["merge", "--selftest", first, "--recheck", second, "--out", merged])
            self.assertEqual(code, 0)
            self.assertIn("accepted=1 channels=11/11 memory-canary=absent readable-file-canary=absent fixtures=complete", out.getvalue())
            with open(merged) as source:
                self.assertTrue(json.loads(source.read())["accepted"])
            recheck["channels"]["dns"] = {"status": "blocked", "control": False}
            os.unlink(second)
            boundary.write_record(second, recheck)
            out = io.StringIO()
            with patch("linux_boundary.sys.stdout", out):
                self.assertEqual(boundary.main(["merge", "--selftest", first, "--recheck", second]), 1)
            self.assertIn("accepted=0", out.getvalue())
            out = io.StringIO()
            with patch("linux_boundary.sys.stdout", out):
                self.assertEqual(boundary.main(["merge", "--selftest", first, "--recheck", os.path.join(base, "absent.json")]), 1)
            self.assertIn("project-execution=not_started", out.getvalue())

    def test_merge_hands_root_written_record_to_runner_through_its_open_descriptor(self):
        selftest = channels.empty_record("selftest")
        recheck = channels.empty_record("recheck")
        for record in (selftest, recheck):
            for name in channels.CHANNELS:
                record["channels"][name] = {"status": "blocked", "control": True}
            record["memory_canary"] = "absent"
            record["readable_file_canary"] = "absent"
            record["result"] = "accepted"
            record["reason"] = "none"
        selftest["fixtures"] = "complete"
        with tempfile.TemporaryDirectory() as base:
            first = os.path.join(base, "a.json")
            second = os.path.join(base, "b.json")
            output = os.path.join(base, "merged.json")
            boundary.write_record(first, selftest)
            boundary.write_record(second, recheck)
            command = ["merge", "--selftest", first, "--recheck", second,
                       "--out", output, "--reader-uid", str(os.getuid()),
                       "--reader-gid", str(os.getgid())]
            original = os.fchown
            with patch.object(boundary.os, "fchown", wraps=original) as chown:
                self.assertEqual(boundary.main(command), 0)
            chown.assert_called_once()
            self.assertIsInstance(chown.call_args.args[0], int)
            self.assertEqual(chown.call_args.args[1:], (os.getuid(), os.getgid()))
            self.assertEqual(os.stat(output).st_mode & 0o777, 0o600)
            with open(output, encoding="ascii") as source:
                self.assertTrue(json.load(source)["accepted"])
            command[command.index(output)] = os.path.join(base, "failed.json")
            with patch.object(boundary.os, "fchown", side_effect=PermissionError):
                self.assertEqual(boundary.main(command), 1)
            linked = os.path.join(base, "linked")
            os.symlink(base, linked)
            command[command.index(os.path.join(base, "failed.json"))] = os.path.join(linked, "escape.json")
            self.assertEqual(boundary.main(command), 1)
            self.assertFalse(os.path.exists(os.path.join(base, "escape.json")))
            if sys.platform == "linux":
                root_output = os.path.join(base, "root-merged.json")
                command[command.index(os.path.join(linked, "escape.json"))] = root_output
                result = subprocess.run(
                    ["sudo", "-n", sys.executable, "-B", boundary.__file__, *command],
                    stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                    timeout=30, check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout.decode("ascii", errors="replace"))
                self.assertEqual(os.stat(root_output).st_uid, os.getuid())
                self.assertEqual(os.stat(root_output).st_mode & 0o777, 0o600)
                with open(root_output, encoding="ascii") as source:
                    self.assertTrue(json.load(source)["accepted"])

    def test_command_line_requires_a_record_path_and_a_runner_uid_and_validates_paths(self):
        out = io.StringIO()
        with patch("linux_boundary.sys.stdout", out):
            self.assertEqual(boundary.main(["selftest", "--runner-uid", "1"]), 2)
            self.assertEqual(boundary.main(["selftest", "--record", "/tmp/x/record.json"]), 2)
            self.assertNotEqual(boundary.main(["selftest", "--record", "relative.json", "--runner-uid", "1"]), 0)
        parser = boundary.build_parser()
        parsed = parser.parse_args(["recheck", "--rust-sysroot", "/opt/toolchain", "--synthetic-standin"])
        self.assertEqual(parsed.rust_sysroot, "/opt/toolchain")
        self.assertTrue(parsed.synthetic_standin)
        with self.assertRaises(SystemExit):
            parser.parse_args(["bogus"])
        with self.assertRaises(SystemExit):
            parser.parse_args(["recheck", "--rust-sysroot", "relative"])
        self.assertIsNone(boundary.optional_path(""))

    def test_boundary_commands_match_the_modes_the_workflow_invokes(self):
        parser = boundary.build_parser()
        for command in ("selftest", "recheck", "faults", "merge"):
            self.assertEqual(parser.parse_args([command]).command, command)



class LinuxBoundaryReviewFixTests(unittest.TestCase):
    def test_artifact_and_cache_positive_controls_launch_after_real_spec_validation(self):
        for standin in (True, False):
            with self.subTest(synthetic_standin=standin), tempfile.TemporaryDirectory() as base:
                subject, unused = make(synthetic_standin=standin)
                subject.workdir = base
                subject.ipc_dir = os.path.join(base, "ipc")
                os.mkdir(subject.ipc_dir)
                store = session.EventStore()
                subject.tripwires = SimpleNamespace(
                    store=store,
                    ipv6=False,
                    config=lambda: {
                        "nonce": subject.nonce,
                        "ports": {"artifact": 2111, "cache": 2222},
                        "unix_path": "/ipc/docker.sock",
                        "abstract_name": "kd-" + subject.nonce,
                    },
                )
                launches = []

                def fake_run(command, **kwargs):
                    self.assertIn("--inside", command)
                    self.assertNotIn("--net", command)
                    with open(command[-1], "rt", encoding="utf-8") as source:
                        spec = json.load(source)
                    channel = spec["argv"][-2]
                    config = json.loads(spec["argv"][-1])
                    launches.append(channel)
                    self.assertEqual(spec["mode"], "open")
                    self.assertEqual(spec["env"], boundary.BASE_ENV)
                    self.assertFalse(any(key.startswith("ACTIONS_") or "TOKEN" in key for key in spec["env"]))
                    self.assertIs(config["positive_control"], True)
                    self.assertEqual(spec["files"]["/probe.py"], [probes.PROBE_SOURCE, 0o444])
                    listener = "artifact" if channel == "artifact_upload" else "cache"

                    def fake_urlopen(request, timeout):
                        self.assertEqual(timeout, 1)
                        self.assertEqual(request.get_header("Authorization"), "Bearer tripwire-token-" + subject.nonce)
                        self.assertIn(":" + str(config["ports"][listener]) + "/", request.full_url)
                        store.record(listener, request.full_url.encode("ascii"))
                        return io.BytesIO(b"live")

                    output = io.StringIO()
                    with patch.dict(os.environ, spec["env"], clear=True), \
                         patch.object(sys, "argv", spec["argv"][-3:]), \
                         patch.object(sys, "stdout", output), \
                         patch("urllib.request.urlopen", side_effect=fake_urlopen), \
                         patch("os.makedirs"), \
                         patch("builtins.open", return_value=io.BytesIO()):
                        exec(compile(probes.PROBE_SOURCE, "/probe.py", "exec"), {"__name__": "control_probe"})
                        self.assertEqual(os.environ["ACTIONS_RUNTIME_TOKEN"], "tripwire-token-" + subject.nonce)
                    transcript = output.getvalue()
                    self.assertIn("KDATT env-hunt allowed\n", transcript)
                    self.assertIn("KDATT endpoint-post allowed\n", transcript)
                    reply = {
                        "exit": 0,
                        "timeout": False,
                        "stdout": base64.b64encode(transcript.encode("ascii")).decode("ascii"),
                        "stderr": "",
                        "readback": {},
                    }
                    return SimpleNamespace(stdout=session.RESULT_PREFIX + json.dumps(reply).encode("ascii") + b"\n")

                with patch("linux_session.subprocess.run", side_effect=fake_run), \
                     patch("linux_session.netns_inode", return_value=77), \
                     patch("linux_session.shutil.which", return_value="/usr/bin/unshare"):
                    for channel in ("artifact_upload", "cache_upload"):
                        with self.subTest(channel=channel):
                            self.assertTrue(subject.network_control(channel, False))
                self.assertEqual(launches, ["artifact_upload", "cache_upload"])

    def test_readback_also_requires_bpf_and_perf_restrictions(self):
        subject, unused = make()
        base = {"ptrace_scope": "3", "max_user_namespaces": "0", "unprivileged_bpf_disabled": "2", "perf_event_paranoid": "4"}
        for key, value, detail in (
            ("unprivileged_bpf_disabled", "0", 64),
            ("perf_event_paranoid", "1", 65),
            ("perf_event_paranoid", "x", 65),
        ):
            values = dict(base, **{key: value})
            with patch("linux_boundary.harness._read_sysctl", side_effect=lambda path, values=values: values[path.rsplit("/", 1)[1]]):
                with self.assertRaises(BoundaryRefusal) as raised:
                    subject.readback_before_drop()
            self.assertEqual(raised.exception.detail, detail)
        for value in ("1", "2"):
            values = dict(base, unprivileged_bpf_disabled=value)
            with patch("linux_boundary.harness._read_sysctl", side_effect=lambda path, values=values: values[path.rsplit("/", 1)[1]]):
                subject.readback_before_drop()

    def test_the_proof_only_verifies_runner_paths_and_never_hardens_them(self):
        import inspect
        for method in (boundary.Boundary.runner_files_outcome, boundary.Boundary.channel_runner_files, boundary.Boundary.prepare):
            self.assertNotIn("harden_runner_paths", inspect.getsource(method))
        self.assertIn("harden_runner_paths", inspect.getsource(boundary.run_harden))

    def test_verification_refuses_when_the_temp_and_runner_diag_targets_are_not_both_present(self):
        subject, unused = make()
        subject.targets = ["/w/_temp", "/w"]
        subject.required = ["/w/_temp"]
        subject.workdir = "/tmp/unused-workdir"
        subject.nonce = "0123456789abcdef01234567"
        with patch("linux_boundary.canaries.plant_writable_control", return_value=("/c", "/c/f")), \
             patch("linux_boundary.canaries.run_walker", return_value={"tested": 4, "leaks": [2, 3]}), \
             patch("linux_boundary.os.path.lexists", return_value=True):
            with self.assertRaises(BoundaryRefusal) as raised:
                subject.runner_files_outcome()
        self.assertEqual(raised.exception.reason, "scan_incomplete")

    def test_harden_step_hardens_then_requires_every_target_unreadable(self):
        args = arguments(runner_home="/h", runner_temp="/w/_temp")
        targets = ["/w/_temp", "/r/_diag", "/h"]
        with patch("linux_boundary.os.geteuid", return_value=0), \
             patch("linux_boundary.canaries.runner_root", return_value="/r"), \
             patch("linux_boundary.canaries.runner_targets", return_value=targets), \
             patch("linux_boundary.canaries.harden_runner_paths", return_value=2) as harden:
            out = io.StringIO()
            with patch("linux_boundary.sys.stdout", out), \
                 patch("linux_boundary.canaries.run_walker", return_value={"leaks": [], "tested": 3}):
                self.assertEqual(boundary.run_harden(args), 0)
            self.assertEqual(out.getvalue(), "KD-LINUX-HARDEN schema=1 result=accepted targets=3 changed=2 readable=0\n")
            harden.assert_called_once_with(targets)
            out = io.StringIO()
            with patch("linux_boundary.sys.stdout", out), \
                 patch("linux_boundary.canaries.run_walker", return_value={"leaks": [1], "tested": 3}):
                self.assertEqual(boundary.run_harden(args), 1)
            self.assertIn("KD-LINUX-HARDEN schema=1 result=refused reason=readback_failed channel=runner_files", out.getvalue())
            self.assertNotIn("phase=", out.getvalue())
            self.assertTrue(out.getvalue().strip().endswith("project-execution=not_started"))
        with patch("linux_boundary.os.geteuid", return_value=0), \
             patch("linux_boundary.canaries.runner_root", return_value=None), \
             patch("linux_boundary.canaries.runner_targets", return_value=["/w/_temp"]):
            out = io.StringIO()
            with patch("linux_boundary.sys.stdout", out):
                self.assertEqual(boundary.run_harden(args), 1)
            self.assertIn("reason=scan_incomplete", out.getvalue())
        with patch("linux_boundary.os.geteuid", return_value=1000):
            out = io.StringIO()
            with patch("linux_boundary.sys.stdout", out):
                self.assertEqual(boundary.run_harden(args), 1)
            self.assertIn("reason=environment", out.getvalue())

    def test_real_mode_places_a_derived_canary_and_never_the_secret_itself(self):
        secret = "r" * 40
        placed = []
        for standin, expect_secret in ((False, False), (True, True)):
            subject, unused = make(synthetic_standin=standin)
            value = boundary.canaries.STANDIN_VALUE if standin else secret
            with patch("linux_boundary.os.geteuid", return_value=0), \
                 patch("linux_boundary.verify_control_sha"), \
                 patch.object(boundary.Boundary, "readback_before_drop"), \
                 patch("linux_boundary.session.TripwireSet"), \
                 patch("linux_boundary.canaries.place_canaries", side_effect=lambda directory, values, **kw: placed.append(list(values))), \
                 patch("linux_boundary.canaries.plant_control_files"), \
                 patch("linux_boundary.canaries.runner_root", return_value=None), \
                 patch.dict(os.environ, {"KD_CANARY_SECRET": value}):
                subject.prepare(False)
            try:
                self.assertEqual(value in placed[-1], expect_secret)
                self.assertEqual(len(placed[-1]), 2)
                needles = subject.secret_needles
                self.assertIn(value.encode(), needles)
                self.assertIn(subject.derived_canary.encode(), needles)
                self.assertEqual(subject.derived_canary, boundary.canaries.derive_canary(value, "kd-linux-file-placement"))
            finally:
                subject.close()

    def test_vm_readv_self_read_control_uses_the_reviewed_syscall_number(self):
        self.assertEqual(boundary.PROCESS_VM_READV, 310)
        self.assertTrue(boundary.vm_readv_self_control("0123456789abcdef01234567"))



class LinuxBoundarySecondReviewTests(unittest.TestCase):
    def test_kernel_restriction_sets_permissive_bpf_and_perf_values_and_leaves_strict_ones(self):
        cases = (
            ({"bpf": "0", "perf": "2"}, [("bpf", "1"), ("perf", "3")]),
            ({"bpf": "0", "perf": "x"}, [("bpf", "1"), ("perf", "3")]),
            ({"bpf": "1", "perf": "3"}, []),
            ({"bpf": "2", "perf": "4"}, []),
            ({"bpf": "2", "perf": "-1"}, [("perf", "3")]),
        )
        paths = {boundary.BPF_SYSCTL: "bpf", boundary.PERF_SYSCTL: "perf"}
        for current, expected in cases:
            writes = []
            with self.subTest(current=current), \
                 patch("linux_boundary.harness._read_sysctl", side_effect=lambda path, current=current: current[paths[path]]), \
                 patch("linux_boundary.harness._set_sysctl", side_effect=lambda path, value: writes.append((paths[path], value))):
                boundary.restrict_kernel()
            self.assertEqual(writes, expected)

    def test_prepare_applies_the_restriction_after_the_base_kernel_setup_and_converts_failures(self):
        order = []
        subject, unused = make()
        with patch("linux_boundary.os.geteuid", return_value=0), patch("linux_boundary.verify_control_sha"), \
             patch("linux_boundary.harness._prepare_kernel", side_effect=lambda: order.append("base")), \
             patch("linux_boundary.restrict_kernel", side_effect=lambda: order.append("restrict")), \
             patch.object(boundary.Boundary, "readback_before_drop", side_effect=lambda: order.append("readback") or (_ for _ in ()).throw(BoundaryRefusal("environment"))):
            with self.assertRaises(BoundaryRefusal):
                subject.prepare(True)
        self.assertEqual(order, ["base", "restrict", "readback"])
        failing, unused = make()
        with patch("linux_boundary.os.geteuid", return_value=0), patch("linux_boundary.verify_control_sha"), \
             patch("linux_boundary.harness._prepare_kernel"), \
             patch("linux_boundary.restrict_kernel", side_effect=harness.ProofFailure(43)):
            with self.assertRaises(BoundaryRefusal) as raised:
                failing.prepare(True)
        self.assertEqual((raised.exception.reason, raised.exception.detail), ("readback_failed", 43))

    def test_canary_env_fault_hands_the_peer_only_the_derived_canary(self):
        subject, unused = make()
        subject.canary = "real-secret-value-0123456789"
        subject.derived_canary = "d" * 64
        captured = {}

        def peer(token, extra=None):
            captured["extra"] = extra
            raise BoundaryRefusal("environment")

        subject.fault = "canary-env"
        with patch("linux_boundary.session.start_peer", side_effect=peer):
            with self.assertRaises(BoundaryRefusal):
                subject.channel_process_memory()
        self.assertEqual(captured["extra"], {"KD_CANARY_SECRET": "d" * 64})
        self.assertNotIn(subject.canary, captured["extra"].values())


MEMORY_REFUSED = (
    b"KDATT mem-read denied\nKDATT environ-read denied\nKDATT ptrace-attach denied\n"
    b"KDATT process-vm-readv denied\nKDATT control-self-memory allowed\nKDATT control-peer-environ allowed\n"
)


class LinuxBoundaryProcessMemoryTests(unittest.TestCase):
    def memory(self, stdout, scope="3", scan=None):
        subject, unused = make()
        subject.workdir = "/work"
        subject.public_dir = "/work/public"
        subject.secret_needles = (b"needle",)
        captured = {}
        reply = SimpleNamespace(stdout=stdout, stderr=b"", timed_out=False, readback={"ptrace_scope": scope}, exit_code=0)

        def host(*args, **kwargs):
            captured["kwargs"] = kwargs
            return reply

        verdict = scan or {"secret": False, "readable_control": True}
        with patch("linux_boundary.session.start_peer", return_value=SimpleNamespace(pid=4321)), \
             patch("linux_boundary.session.stop_peer"), \
             patch("linux_boundary.session.run_host", side_effect=host), \
             patch("linux_boundary.canaries.run_walker", return_value={}), \
             patch("linux_boundary.canaries.evaluate_environ", return_value=verdict), \
             patch("linux_boundary.vm_readv_self_control", return_value=True), \
             patch("linux_boundary.find_pids", return_value=[]):
            outcome = subject.channel_process_memory()
        return outcome, subject, captured

    def test_the_memory_attempts_run_in_the_host_pid_namespace(self):
        outcome, unused, captured = self.memory(MEMORY_REFUSED)
        self.assertTrue(captured["kwargs"]["host_pids"])
        self.assertEqual((outcome.status, outcome.control), ("blocked", True))

    def test_eperm_attempts_under_scope_three_count_as_blocked_with_the_readback(self):
        outcome, subject, unused = self.memory(MEMORY_REFUSED)
        self.assertIsNone(outcome.refusal)
        self.assertEqual(subject.memory_canary, "absent")

    def test_a_missing_scope_readback_refuses(self):
        for scope in ("0", "1", "2", "unread"):
            with self.subTest(scope=scope):
                with self.assertRaises(BoundaryRefusal) as raised:
                    self.memory(MEMORY_REFUSED, scope=scope)
                self.assertEqual(raised.exception.reason, "readback_failed")

    def test_unreachable_targets_are_never_counted_as_blocked(self):
        other = MEMORY_REFUSED.replace(b"KDATT mem-read denied", b"KDATT mem-read other")
        dead_peer = MEMORY_REFUSED.replace(b"KDATT control-peer-environ allowed", b"KDATT control-peer-environ other")
        for stdout in (other, dead_peer):
            with self.subTest(stdout=stdout):
                outcome, subject, unused = self.memory(stdout)
                self.assertNotEqual((outcome.status, outcome.control), ("blocked", True))

    def test_an_unexpected_attempt_names_its_rule_index_and_stays_not_run(self):
        other = MEMORY_REFUSED.replace(b"KDATT ptrace-attach denied", b"KDATT ptrace-attach other")
        outcome, subject, unused = self.memory(other)
        self.assertEqual(outcome.status, "not-run")
        self.assertFalse(outcome.control)
        self.assertEqual((outcome.refusal.reason, outcome.refusal.detail), ("attempt_unexpected", 2))
        self.assertEqual(subject.memory_canary, "present")

    def test_a_readable_secret_is_a_leak_even_when_every_attempt_is_denied(self):
        outcome, unused, unused2 = self.memory(MEMORY_REFUSED, scan={"secret": True, "readable_control": True})
        self.assertEqual(outcome.status, "observed-leak")

    def test_the_probe_rejects_targets_that_are_not_refused_with_a_permission_error(self):
        self.assertIn("stray", probes.PROBE_SOURCE)
        self.assertIn("errno.EPERM, errno.EACCES", probes.PROBE_SOURCE)


class LinuxBoundaryFixtureDiagnosticTests(unittest.TestCase):
    def test_each_failed_fixture_form_is_named_with_a_closed_vocabulary_line(self):
        subject, emitter = make()

        def outcome(form):
            if form == "shell":
                return None
            raise BoundaryRefusal("fixture_incomplete", None, 3)

        with patch.object(boundary.Boundary, "fixture_outcome", side_effect=outcome):
            completed, first = subject.run_fixtures()
        self.assertEqual(completed, 1)
        self.assertEqual(first.reason, "fixture_incomplete")
        output = emitter.stream.getvalue().splitlines()
        self.assertEqual(len(output), 4)
        self.assertIn("KD-LINUX-FIXTURE schema=1 phase=selftest form=build_rs result=refused reason=fixture_incomplete detail=3", output)
        for line in output:
            self.assertRegex(line, r"^[A-Za-z0-9 =/_.-]+$")

    def test_a_proof_failure_is_reported_for_its_form(self):
        subject, emitter = make()
        with patch.object(boundary.Boundary, "fixture_outcome", side_effect=harness.ProofFailure(25)):
            completed, first = subject.run_fixtures()
        self.assertEqual(completed, 0)
        self.assertEqual(len(emitter.stream.getvalue().splitlines()), 5)
        self.assertIn("form=npm_postinstall result=refused reason=readback_failed detail=25", emitter.stream.getvalue())

    def test_exit_detail_is_bounded(self):
        self.assertEqual(boundary.exit_detail(SimpleNamespace(exit_code=3)), 3)
        for code in (127, 128, 137, 200, 255):
            self.assertEqual(boundary.exit_detail(SimpleNamespace(exit_code=code)), code)
        for code in (256, -128, None, "x", True):
            self.assertIsNone(boundary.exit_detail(SimpleNamespace(exit_code=code)))
        self.assertIsNone(boundary.exit_detail(SimpleNamespace()))

    def test_signal_deaths_are_reported_with_the_shell_convention(self):
        self.assertEqual(boundary.exit_detail(SimpleNamespace(exit_code=-9)), 137)
        self.assertEqual(boundary.exit_detail(SimpleNamespace(exit_code=-6)), 134)
        self.assertEqual(BoundaryRefusal("fixture_incomplete", None, 134).detail, 134)
        self.assertEqual(BoundaryRefusal("fixture_incomplete", None, 255).detail, 255)
        self.assertIsNone(BoundaryRefusal("fixture_incomplete", None, 256).detail)

    def test_node_binary_uses_the_image_node_only_when_its_real_path_is_under_usr_and_never_binds(self):
        subject, unused = make()
        with patch("linux_boundary.shutil.which", return_value="/usr/local/bin/node"), \
             patch("linux_boundary.os.path.realpath", return_value="/usr/local/n/versions/node/20.1.0/bin/node"):
            self.assertEqual(subject.node_binary(), ("/usr/local/n/versions/node/20.1.0/bin/node", None))

    def test_node_binary_fails_closed_with_host_codes_distinct_from_the_driver_codes(self):
        subject, unused = make()
        with patch("linux_boundary.shutil.which", return_value=None):
            with self.assertRaises(BoundaryRefusal) as raised:
                subject.node_binary()
        self.assertEqual((raised.exception.reason, raised.exception.detail), ("fixture_incomplete", fixtures.HOST_NODE_ABSENT))
        for real in ("/opt/hostedtoolcache/node/20/bin/node", "/node", "/etc/node", "/usr/bin/a b"):
            with patch("linux_boundary.shutil.which", return_value="/usr/bin/node"), \
                 patch("linux_boundary.os.path.realpath", return_value=real):
                with self.assertRaises(BoundaryRefusal) as raised:
                    subject.node_binary()
            self.assertEqual((raised.exception.reason, raised.exception.detail), ("fixture_incomplete", fixtures.HOST_NODE_UNSAFE))
        driver = fixtures.fixture_files("npm_postinstall")["/fixtures/npm_postinstall/run.sh"][0]
        for code in (fixtures.HOST_NODE_ABSENT, fixtures.HOST_NODE_UNSAFE, fixtures.HOST_NODE_PINNED_INVALID):
            self.assertNotIn("exit " + str(code), driver)

    def test_pinned_node_is_bound_read_only_non_recursively_at_a_fixed_target(self):
        pinned = "/tmp/kd-toolchains/node/node-v24.1.0-linux-x64/bin"
        subject, unused = make(node_bin=pinned)
        with patch("linux_boundary.os.path.realpath", return_value=pinned + "/node"), \
             patch("linux_boundary.os.access", return_value=True):
            node, bind = subject.node_binary()
        self.assertEqual(node, "/kd-node/node")
        self.assertEqual(bind, {"source": pinned, "target": "/kd-node", "ro": True, "rec": False})
        with patch("linux_boundary.os.path.realpath", return_value="/elsewhere/node"), \
             patch("linux_boundary.os.access", return_value=True):
            with self.assertRaises(BoundaryRefusal) as raised:
                subject.node_binary()
        self.assertEqual(raised.exception.detail, fixtures.HOST_NODE_PINNED_INVALID)
        with patch("linux_boundary.os.path.realpath", return_value=pinned + "/node"), \
             patch("linux_boundary.os.access", return_value=False):
            with self.assertRaises(BoundaryRefusal):
                subject.node_binary()
        for bad in ("/etc", "/tmp", "/work/bin", "/ipc", "/fixtures/bin", "/tmp/kd-toolchains/node/../../../etc/bin"):
            bad_subject, unused = make(node_bin=bad)
            with self.assertRaises(BoundaryRefusal) as raised:
                bad_subject.node_binary()
            self.assertEqual(raised.exception.detail, fixtures.HOST_NODE_PINNED_INVALID)

    def run_fixture(self, form, **changes):
        subject, unused = make(rust_sysroot="/opt/rust", **changes)
        subject.tripwires = SimpleNamespace(
            ports={"https4": 1, "udp": 2, "dns_udp": 3, "proxy": 4},
            store=SimpleNamespace(clear=lambda: None, seen=lambda name, marker: True, snapshot=lambda: []),
        )
        subject.ipc_dir = "/ipc-source"
        lines = b"".join(
            b"KDATT " + name.encode("ascii") + b" " + (b"contained" if accepted == channels.CONTAINED else b"denied") + b"\n"
            for name, accepted in fixtures.fixture_rules(form)
        )
        calls = []

        def fake_chroot(argv, env, mode="confined", files=None, binds=None, **options):
            calls.append((env, binds))
            return result(lines)

        with patch.object(boundary.Boundary, "chroot", side_effect=fake_chroot), \
             patch.object(boundary.Boundary, "node_binary", return_value=("/kd-node/node", {"source": "/tmp/kd-toolchains/node/n/bin", "target": "/kd-node", "ro": True, "rec": False})):
            subject.fixture_outcome(form)
        return calls

    def test_node_environment_and_bind_exist_only_for_the_npm_form(self):
        for form in fixtures.FORMS:
            calls = self.run_fixture(form)
            self.assertEqual(len(calls), 2)
            for env, binds in calls:
                with self.subTest(form=form):
                    self.assertEqual("KD_NODE" in env, form == "npm_postinstall")
                    targets = [item["target"] for item in binds]
                    self.assertEqual("/kd-node" in targets, form == "npm_postinstall")
                    self.assertEqual("/opt/rust" in targets, form in fixtures.NEEDS_RUSTC)
                    for item in binds:
                        if item["target"] in ("/kd-node", "/opt/rust"):
                            self.assertTrue(item["ro"])
                            self.assertIs(item["rec"], False)

    def test_a_node_lookup_refusal_flows_through_run_fixtures(self):
        subject, emitter = make(rust_sysroot="/opt/rust")
        subject.tripwires = SimpleNamespace(
            ports={"https4": 1, "udp": 2, "dns_udp": 3, "proxy": 4},
            store=SimpleNamespace(clear=lambda: None, seen=lambda name, marker: True, snapshot=lambda: []),
        )
        subject.ipc_dir = "/ipc-source"
        with patch.object(boundary.Boundary, "node_binary", side_effect=BoundaryRefusal("fixture_incomplete", None, fixtures.HOST_NODE_UNSAFE)), \
             patch.object(boundary.Boundary, "chroot", side_effect=BoundaryRefusal("environment")):
            completed, first = subject.run_fixtures()
        output = emitter.stream.getvalue()
        self.assertEqual(first.reason, "environment")
        self.assertIn("form=npm_postinstall result=refused reason=fixture_incomplete detail=" + str(fixtures.HOST_NODE_UNSAFE), output)
        self.assertEqual(completed, 0)

    def test_node_bin_argument_is_optional_and_absolute(self):
        parser = boundary.build_parser()
        self.assertIsNone(parser.parse_args(["selftest", "--node-bin", ""]).node_bin)
        self.assertEqual(parser.parse_args(["selftest", "--node-bin", "/tmp/kd-toolchains/node/x/bin"]).node_bin, "/tmp/kd-toolchains/node/x/bin")
        with self.assertRaises(SystemExit):
            parser.parse_args(["selftest", "--node-bin", "relative"])


class LinuxBoundaryFixtureStderrDiagnosticTests(unittest.TestCase):
    PREFIX = "KD-LINUX-FIXTURE-DIAG"

    def scaffold(self, **changes):
        subject, emitter = make(rust_sysroot="/opt/rust", **changes)
        subject.tripwires = SimpleNamespace(
            ports={"https4": 1, "udp": 2, "dns_udp": 3, "proxy": 4},
            store=SimpleNamespace(clear=lambda: None, seen=lambda name, marker: True, snapshot=lambda: []),
            config=lambda: {"nonce": "n", "ports": {"https4": 1}, "unix_path": "/ipc/docker.sock", "abstract_name": "kd-x"},
        )
        subject.ipc_dir = "/ipc-source"
        subject.phase = "selftest"
        return subject, emitter

    def ran(self, exit_code=0, stdout=b"", stderr=b"", timed_out=False):
        return SimpleNamespace(exit_code=exit_code, stdout=stdout, stderr=stderr, timed_out=timed_out, readback={})

    def diag_lines(self, emitter):
        return [line for line in emitter.stream.getvalue().splitlines() if line.startswith(self.PREFIX)]

    def refusing(self, evidence, reason="fixture_incomplete", forms=("build_rs",)):
        def outcome(form):
            if form in forms:
                raise BoundaryRefusal(reason, None, 3, evidence)

        return patch.object(boundary.Boundary, "fixture_outcome", side_effect=outcome)

    def test_an_incomplete_fixture_prints_its_stderr_tail_right_after_its_refusal_line(self):
        subject, emitter = self.scaffold()
        evidence = ("kd-host open_exit=3 exit=3", b"error: linking with gcc failed\nld: cannot find crt1.o\n")
        with self.refusing(evidence):
            completed, first = subject.run_fixtures()
        output = emitter.stream.getvalue().splitlines()
        head = "KD-LINUX-FIXTURE-DIAG schema=1 phase=selftest form=build_rs stream=stderr line="
        self.assertEqual(output[0], "KD-LINUX-FIXTURE schema=1 phase=selftest form=build_rs result=refused reason=fixture_incomplete detail=3")
        self.assertEqual(output[1:4], [head + "kd-host open_exit=3 exit=3", head + "error: linking with gcc failed", head + "ld: cannot find crt1.o"])
        self.assertEqual(len(output), 4)
        self.assertEqual((completed, first.reason), (4, "fixture_incomplete"))

    def test_a_fresh_boundary_has_an_unset_phase_and_prints_no_diagnostic(self):
        subject, emitter = make(rust_sysroot="/opt/rust")
        self.assertEqual(subject.phase, "unset")
        self.assertNotIn(subject.phase, channels.DIAG_PHASES)
        subject.emit_diagnostic("build_rs", BoundaryRefusal("fixture_incomplete", None, 3, ("kd-host exit=3", b"error: boom\n")))
        self.assertEqual(self.diag_lines(emitter), [])
        self.assertEqual(emitter.stream.getvalue(), "")

    def test_a_formatting_error_never_aborts_the_run_and_prints_one_fixed_line(self):
        subject, emitter = self.scaffold()
        evidence = ("kd-host exit=3", b"error: boom\n")
        for error in (ValueError("diag-line"), UnicodeError("x"), TypeError("x")):
            emitter.stream.seek(0)
            emitter.stream.truncate()
            with self.subTest(error=type(error).__name__), self.refusing(evidence), \
                 patch.object(channels, "fixture_diag_lines", side_effect=error):
                completed, first = subject.run_fixtures()
            self.assertEqual((completed, first.reason), (4, "fixture_incomplete"))
            shown = self.diag_lines(emitter)
            self.assertEqual(shown, ["KD-LINUX-FIXTURE-DIAG schema=1 phase=selftest form=unknown stream=stderr line=unavailable"])
            self.assertNotIn("boom", emitter.stream.getvalue())

    def test_a_malformed_evidence_pair_is_also_contained(self):
        subject, emitter = self.scaffold()
        subject.emit_diagnostic("build_rs", BoundaryRefusal("fixture_incomplete", None, 3, ("only-one",)))
        self.assertEqual(len(self.diag_lines(emitter)), 1)
        self.assertTrue(self.diag_lines(emitter)[0].endswith("line=unavailable"))

    def test_a_tripwire_event_is_refused_as_allowed_before_the_incomplete_verdict_and_prints_nothing(self):
        subject, emitter = self.scaffold()
        subject.tripwires.store.snapshot = lambda: ["tripwire-event"]
        calls = [self.ran(0, b"", b"open\n"), self.ran(None, b"", b"error: escaped\n", True)]
        with patch.object(boundary.Boundary, "chroot", side_effect=calls):
            with self.assertRaises(BoundaryRefusal) as raised:
                subject.fixture_outcome("shell")
        self.assertEqual(raised.exception.reason, "fixture_allowed")
        self.assertIsNone(raised.exception.evidence)

    def test_the_bare_hex_bodies_of_the_placed_canaries_are_dropped_from_a_diagnostic(self):
        subject, emitter = self.scaffold()
        subject.nonce_canary = "kd-nonce-0123456789abcdef"
        subject.derived_canary = "fedcba9876543210"
        subject.bare_needles = (b"0123456789abcdef", b"fedcba9876543210")
        stderr = b"error: first\nbody 0123456789ABCDEF seen\nderived fedcba9876543210 seen\nerror: last\n"
        with self.refusing(("kd-host exit=3", stderr)):
            subject.run_fixtures()
        shown = [line.split("line=", 1)[1] for line in self.diag_lines(emitter)]
        self.assertEqual(shown, ["kd-host exit=3", "error: first", "error: last"])
        self.assertNotIn("0123456789", emitter.stream.getvalue())

    def test_only_an_incomplete_refusal_with_evidence_prints_anything(self):
        evidence = ("kd-host exit=3", b"error: boom\n")
        for reason, attached in (("fixture_allowed", evidence), ("attempt_unexpected", evidence), ("control_not_fired", evidence), ("fixture_incomplete", None)):
            subject, emitter = self.scaffold()
            with self.subTest(reason=reason, attached=attached is not None):
                with self.refusing(attached, reason):
                    subject.run_fixtures()
                self.assertEqual(self.diag_lines(emitter), [])

    def test_no_other_phase_emits_a_diagnostic_even_when_the_fixture_runner_is_called(self):
        evidence = ("kd-host exit=3", b"error: boom\n")
        for phase in ("recheck", "source", "project", "", "other"):
            subject, emitter = self.scaffold()
            subject.phase = phase
            with self.subTest(phase=phase):
                with self.refusing(evidence):
                    subject.run_fixtures()
                self.assertEqual(self.diag_lines(emitter), [])
        subject, emitter = self.scaffold()
        with self.refusing(evidence):
            subject.run_fixtures()
        self.assertEqual(len(self.diag_lines(emitter)), 2)

    def test_the_recheck_phase_path_never_emits_a_diagnostic_and_the_selftest_path_does(self):
        evidence = ("kd-host exit=3", b"error: boom\n")
        for phase, expected in (("selftest", 2), ("recheck", 0)):
            subject, emitter = self.scaffold()
            with self.subTest(phase=phase), self.refusing(evidence), \
                 patch.object(boundary.Boundary, "run_channel", side_effect=lambda channel: blocked(channel)):
                boundary.run_phase(subject, phase, True)
                self.assertEqual(subject.phase, phase)
                self.assertEqual(len(self.diag_lines(emitter)), expected)
            subject, emitter = self.scaffold()
            with self.subTest(phase=phase, fixtures=False), self.refusing(evidence), \
                 patch.object(boundary.Boundary, "run_channel", side_effect=lambda channel: blocked(channel)):
                boundary.run_phase(subject, phase, False)
                self.assertEqual(self.diag_lines(emitter), [])

    def test_the_source_build_path_never_references_the_diagnostic(self):
        base = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(base, "linux_source_build.py"), "rt", encoding="utf-8") as source:
            text = source.read()
        for name in ("FIXTURE-DIAG", "fixture_diag", "diag_line", "emit_diagnostic", "linux_boundary", "run_fixtures"):
            self.assertNotIn(name, text)
        with open(os.path.join(base, "linux_boundary.py"), "rt", encoding="utf-8") as source:
            text = source.read()
        self.assertEqual(text.count("emit_diagnostic("), 2)
        self.assertEqual(text.count("fixture_diag_lines("), 1)

    def test_forced_faults_never_emit_a_diagnostic(self):
        subject, emitter = self.scaffold()
        with patch.object(boundary.Boundary, "chroot", return_value=self.ran(0, b"", b"error: boom\n")):
            boundary.run_fault(subject, "fixture-truncated")
        output = emitter.stream.getvalue()
        self.assertEqual(self.diag_lines(emitter), [])
        self.assertIn("linux-forced-fault name=fixture-truncated", output)

    def test_the_refusal_carries_the_exit_codes_the_last_attempt_and_the_confined_stderr(self):
        subject, emitter = self.scaffold()
        stdout = b"KDATT tcp-connect denied\nKDATT udp-send denied\n"
        stderr = b"kd-diag limits nproc=256\nnode: assertion failed\n"
        calls = [self.ran(0, stdout, b"open stderr\n"), self.ran(-6, stdout, stderr)]
        with patch.object(boundary.Boundary, "chroot", side_effect=calls), \
             patch.object(boundary.Boundary, "node_binary", return_value=("/kd-node/node", None)):
            with self.assertRaises(BoundaryRefusal) as raised:
                subject.fixture_outcome("npm_postinstall")
        refusal = raised.exception
        self.assertEqual((refusal.reason, refusal.detail), ("fixture_incomplete", 134))
        self.assertEqual(refusal.evidence, ("kd-host open_exit=0 exit=134 timed_out=0 attempts=2 last=udp-send", stderr))

    def test_a_timeout_and_an_empty_run_are_described_too(self):
        subject, emitter = self.scaffold()
        calls = [self.ran(0, b"", b""), self.ran(None, b"", b"", True)]
        with patch.object(boundary.Boundary, "chroot", side_effect=calls):
            with self.assertRaises(BoundaryRefusal) as raised:
                subject.fixture_outcome("shell")
        self.assertEqual(raised.exception.evidence[0], "kd-host open_exit=0 exit=None timed_out=1 attempts=0 last=none")
        self.assertIsNone(raised.exception.detail)

    def test_other_refusals_carry_no_evidence(self):
        subject, emitter = self.scaffold()
        full = b"".join(
            b"KDATT " + name.encode("ascii") + b" " + (b"contained" if accepted == channels.CONTAINED else b"allowed") + b"\n"
            for name, accepted in fixtures.fixture_rules("shell")
        )
        calls = [self.ran(0, full, b"x\n"), self.ran(0, full, b"x\n")]
        with patch.object(boundary.Boundary, "chroot", side_effect=calls):
            with self.assertRaises(BoundaryRefusal) as raised:
                subject.fixture_outcome("shell")
        self.assertEqual(raised.exception.reason, "fixture_allowed")
        self.assertIsNone(raised.exception.evidence)

    def test_printed_lines_drop_the_run_nonce_the_canary_forms_and_workflow_commands(self):
        subject, emitter = self.scaffold()
        subject.secret_needles = (b"canary-needle-value-0001", b"Y2FuYXJ5LW5lZWRsZS12YWx1ZS0wMDAx")
        nonce = subject.nonce.encode("ascii")
        stderr = b"\n".join((
            b"error: first useful line",
            b"::error::fx-secret-" + nonce,
            b"fx-npm-" + nonce + b" echoed",
            b"leak canary-needle-value-0001 seen",
            b"leak Y2FuYXJ5LW5lZWRsZS12YWx1ZS0wMDAx seen",
            b"kd-log-" + nonce,
            b"error: last useful line",
        ))
        with self.refusing(("kd-host exit=3", stderr)):
            subject.run_fixtures()
        shown = self.diag_lines(emitter)
        self.assertEqual([line.split("line=", 1)[1] for line in shown], ["kd-host exit=3", "error: first useful line", "error: last useful line"])
        text = emitter.stream.getvalue()
        self.assertNotIn(subject.nonce, text)
        self.assertNotIn("canary-needle", text)
        self.assertNotIn("Y2FuYXJ5", text)
        for line in emitter.lines:
            self.assertFalse(line.startswith("::"))

    def test_the_raw_log_scan_stays_clean_with_diagnostics_and_still_detects_a_real_leak(self):
        subject, emitter = self.scaffold()
        subject.secret_needles = (b"canary-needle-value-0001",)
        with self.refusing(("kd-host exit=3", b"error: boom\nkd-diag stage=compile exit=3\n")):
            subject.run_fixtures()
        self.assertEqual(len(self.diag_lines(emitter)), 3)
        self.assertEqual(boundary.transcript_hits(emitter.lines, subject.nonce, subject.secret_needles), 0)
        marker = ("kd-log-" + subject.nonce).encode("ascii")
        rules = channels.ATTEMPT_RULES["raw_logs"]
        stdout = marker + b"\n" + b"".join(b"KDATT " + name.encode("ascii") + b" " + accepted[0].encode("ascii") + b"\n" for name, accepted in rules)
        raw = self.ran(0, stdout, marker + b"\n")
        with patch.object(boundary.Boundary, "chroot", return_value=raw):
            outcome = subject.channel_raw_logs()
        self.assertEqual((outcome.status, outcome.control), ("blocked", True))
        emitter.lines.append(self.PREFIX + " schema=1 phase=selftest form=build_rs stream=stderr line=x " + "kd-log-" + subject.nonce)
        with patch.object(boundary.Boundary, "chroot", return_value=raw):
            outcome = subject.channel_raw_logs()
        self.assertEqual(outcome.status, "observed-leak")
        emitter.lines.pop()
        emitter.lines.append(self.PREFIX + " schema=1 phase=selftest form=build_rs stream=stderr line=has canary-needle-value-0001")
        with patch.object(boundary.Boundary, "chroot", return_value=raw):
            outcome = subject.channel_raw_logs()
        self.assertEqual(outcome.status, "observed-leak")

    def test_printed_diagnostics_stay_inside_the_public_alphabet_and_the_line_budget(self):
        subject, emitter = self.scaffold()
        stderr = b"".join(b"rustc says [" + str(index).encode("ascii") + b"] `x` {y}\n" for index in range(80))
        with self.refusing(("kd-host exit=3", stderr), forms=("build_rs", "proc_macro")):
            subject.run_fixtures()
        shown = self.diag_lines(emitter)
        self.assertEqual(len(shown), 2 * channels.DIAG_MAX_LINES)
        for line in shown:
            self.assertRegex(line, r"^KD-LINUX-FIXTURE-DIAG schema=1 phase=selftest form=(build_rs|proc_macro) stream=stderr line=[A-Za-z0-9 ._:/=+,()'" + chr(34) + r"?-]{1,200}$")
        self.assertTrue(shown[-1].endswith("rustc says ?79? ?x? ?y?"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
