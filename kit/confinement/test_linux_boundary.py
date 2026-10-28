import io
import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import linux_boundary as boundary
import linux_channels as channels
import linux_fixtures as fixtures
import linux_harness as harness
from linux_channels import BoundaryRefusal


__all__ = [
    "LinuxBoundaryDecisionTests",
    "LinuxBoundaryPhaseTests",
    "LinuxBoundaryFaultTests",
    "LinuxBoundaryCommandTests",
    "LinuxBoundaryReviewFixTests",
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
             patch.object(boundary.Boundary, "run_fixtures", return_value=fixtures_result):
            record, refusal = boundary.run_phase(subject, phase, phase == "selftest")
        return record, refusal, emitter.stream.getvalue().splitlines()

    def test_a_fully_proved_selftest_is_accepted_with_eleven_channel_lines(self):
        record, refusal, output = self.phase()
        self.assertIsNone(refusal)
        self.assertTrue(channels.record_accepts(record))
        self.assertEqual(len([line for line in output if line.startswith("KD-LINUX-CHANNEL")]), 11)
        self.assertIn("KD-LINUX-FIXTURES schema=1 phase=selftest forms=5/5 result=complete", output)
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
        import linux_session as session
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
            self.assertEqual(out.getvalue(), "KD-LINUX-HARDEN schema=1 targets=3 changed=2 readable=0\n")
            harden.assert_called_once_with(targets)
            out = io.StringIO()
            with patch("linux_boundary.sys.stdout", out), \
                 patch("linux_boundary.canaries.run_walker", return_value={"leaks": [1], "tested": 3}):
                self.assertEqual(boundary.run_harden(args), 1)
            self.assertIn("reason=readback_failed channel=runner_files", out.getvalue())
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
