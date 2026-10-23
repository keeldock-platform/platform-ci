import io
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import macos_capability


CONTROL_SHA = "a" * 40


def descriptor_output(pids=(101, 102)):
    lines = []
    for pid in pids:
        lines.extend(("p" + str(pid), "fcwd", "tDIR", "n/tmp", "ftxt", "tREG", "n/usr/bin/python3"))
        lines.extend(("f1", "tPIPE", "n->0xa41e4580bb63aaf3"))
        lines.extend(("f2", "tPIPE", "n->0x2c6caff2d92a6b2b"))
    return "\n".join(lines) + "\n"


def native_snapshot(pids=(101, 102)):
    result = {}
    for index, pid in enumerate(pids):
        base = 0x1000 + index * 0x100
        result[pid] = {
            1: {"mode": "w", "type": "PIPE", "name": "->0x%x" % base},
            2: {"mode": "w", "type": "PIPE", "name": "->0x%x" % (base + 1)},
        }
    return result


class FixedOutcomeTests(unittest.TestCase):
    def test_control_sha_is_full_lowercase_hex_only(self):
        self.assertTrue(macos_capability.valid_sha(CONTROL_SHA))
        for value in (CONTROL_SHA[:12], CONTROL_SHA.upper(), "g" * 40, CONTROL_SHA + "0", None):
            with self.subTest(value_type=type(value).__name__):
                self.assertFalse(macos_capability.valid_sha(value))

    def test_success_still_refuses_overall_confinement(self):
        self.assertEqual(
            macos_capability.safe_output(True),
            "macos-capability=observed\nmacos-confinement=refused reason=incomplete_channel_evidence\n",
        )

    def test_refusal_reason_is_limited_to_fixed_classes(self):
        self.assertEqual(
            macos_capability.safe_output(False, "descriptor_readback_unavailable"),
            "macos-capability=refused reason=descriptor_readback_unavailable\n"
            "macos-confinement=refused reason=incomplete_channel_evidence\n",
        )
        self.assertEqual(
            macos_capability.safe_output(False, "raw-private-error"),
            "macos-capability=refused reason=native_preflight_unavailable\n"
            "macos-confinement=refused reason=incomplete_channel_evidence\n",
        )

    def test_native_probe_uses_checkout_workspace_not_reserved_runner_parent(self):
        runner_parent = "/runner/work/platform-ci"
        checkout_root = runner_parent + "/platform-ci"
        with patch.dict(
            os.environ,
            {"CI_WORKSPACE": checkout_root, "RUNNER_WORKSPACE": runner_parent},
        ):
            with patch.object(
                macos_capability,
                "_check_context",
                side_effect=macos_capability.ProbeFailure("control_identity_invalid"),
            ) as check_context:
                with self.assertRaisesRegex(macos_capability.ProbeFailure, "control_identity_invalid"):
                    macos_capability.run_native_probe(CONTROL_SHA)

        check_context.assert_called_once_with(CONTROL_SHA, checkout_root)


class DescriptorReadbackTests(unittest.TestCase):
    def read_snapshot(self, payload, pids=(101, 102)):
        result = subprocess.CompletedProcess([], 0, payload.encode("utf-8"), b"")
        native = native_snapshot(pids)
        with patch.object(macos_capability, "_run", return_value=result):
            with patch.object(macos_capability, "_native_descriptor_snapshot", side_effect=lambda pid: native[pid]):
                return macos_capability._descriptor_snapshot(list(pids))

    def test_realistic_lsof_pipe_output_without_access_mode_uses_native_readback(self):
        result = self.read_snapshot(descriptor_output())
        self.assertEqual(set(result), {101, 102})
        self.assertEqual(set(result[101]), {1, 2})
        self.assertEqual(result[101][1]["mode"], "w")
        self.assertEqual(result[101][2]["mode"], "w")
        self.assertNotEqual(result[101][1]["name"], result[101][2]["name"])

    def test_lsof_is_requested_for_types_and_names_without_access_mode(self):
        payload = descriptor_output((101,))
        result = subprocess.CompletedProcess([], 0, payload.encode("utf-8"), b"")
        native = native_snapshot((101,))
        with patch.object(macos_capability, "_run", return_value=result) as run:
            with patch.object(macos_capability, "_native_descriptor_snapshot", side_effect=lambda pid: native[pid]):
                snapshot = macos_capability._descriptor_snapshot([101])
        run.assert_called_once_with(
            ["/usr/sbin/lsof", "-nP", "-Fpfnt", "-p", "101"],
            timeout=10,
        )
        self.assertEqual(snapshot[101][1]["mode"], "w")
        self.assertEqual(snapshot[101][2]["mode"], "w")

    def test_lsof_readback_refuses_missing_extra_non_pipe_or_shared_descriptors(self):
        base = descriptor_output((101,))
        mutations = (
            base.replace("f1\ntPIPE", "f0\ntPIPE"),
            base + "f3\ntPIPE\nn->0xfeed\n",
            base.replace("f1\ntPIPE", "f1\ntREG"),
            base.replace("n->0x2c6caff2d92a6b2b", "n->0xa41e4580bb63aaf3"),
            base.replace("f2\ntPIPE\nn->0x2c6caff2d92a6b2b\n", ""),
            base.replace("fcwd", "fother"),
            descriptor_output((101,)),
        )
        pids = ((101,), (101,), (101,), (101,), (101,), (101,), (101, 102))
        for index, (payload, expected_pids) in enumerate(zip(mutations, pids)):
            with self.subTest(mutation_index=index):
                with self.assertRaisesRegex(macos_capability.ProbeFailure, "descriptor_readback_unavailable"):
                    self.read_snapshot(payload, expected_pids)

    def test_native_readback_refuses_unallowed_descriptors_modes_types_and_shared_pipes(self):
        payload = descriptor_output((101,))
        mutations = (
            {1: {"mode": "w", "type": "PIPE", "name": "->1"}},
            {1: {"mode": "w", "type": "PIPE", "name": "->1"}, 2: {"mode": "w", "type": "PIPE", "name": "->2"}, 3: {"mode": "w", "type": "PIPE", "name": "->3"}},
            {0: {"mode": "rw", "type": "CHR", "name": "/dev/null"}, 1: {"mode": "w", "type": "PIPE", "name": "->1"}, 2: {"mode": "w", "type": "PIPE", "name": "->2"}},
            {1: {"mode": "r", "type": "PIPE", "name": "->1"}, 2: {"mode": "w", "type": "PIPE", "name": "->2"}},
            {1: {"mode": "w", "type": "PIPE", "name": "->1"}, 2: {"mode": "u", "type": "PIPE", "name": "->2"}},
            {1: {"mode": "w", "type": "PIPE", "name": "->1"}, 2: {"mode": "w", "type": "PIPE", "name": "->1"}},
        )
        for index, native in enumerate(mutations):
            result = subprocess.CompletedProcess([], 0, payload.encode("utf-8"), b"")
            with self.subTest(mutation_index=index):
                with patch.object(macos_capability, "_run", return_value=result):
                    with patch.object(macos_capability, "_native_descriptor_snapshot", return_value=native):
                        with self.assertRaisesRegex(macos_capability.ProbeFailure, "descriptor_readback_unavailable"):
                            macos_capability._descriptor_snapshot([101])

    def test_probe_requires_observed_forked_grandchild_and_all_process_roles(self):
        roles = {
            "capabilityprobe",
            "capabilitychild",
            "sh",
            "sleep",
            "capability-child",
            "forked-grandchild",
            "python3",
            "clang",
        }
        self.assertTrue(macos_capability._roles_complete(roles))
        roles.remove("forked-grandchild")
        self.assertFalse(macos_capability._roles_complete(roles))
        observed = macos_capability._observe_roles(
            {"capabilityprobe", "capabilitychild", "capability-child", "clang"},
            {"capabilityprobe": 1, "capabilitychild": 1, "capability-child": 2, "clang": 1},
        )
        self.assertIn("forked-grandchild", observed)


class ProbeTeardownTests(unittest.TestCase):
    def test_process_table_error_terminates_and_reaps_injected_probe_group(self):
        process = type(
            "StubProcess",
            (),
            {"pid": 12345, "stdout": io.BytesIO(), "stderr": io.BytesIO(), "returncode": None},
        )()
        process.poll = lambda: process.returncode
        group = {process.pid}

        def terminate_group(process_to_stop):
            self.assertIs(process_to_stop, process)
            group.discard(process_to_stop.pid)
            process_to_stop.returncode = -15
            return not group and process_to_stop.poll() is not None

        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(
                macos_capability,
                "_process_table",
                side_effect=macos_capability.ProbeFailure("descriptor_readback_unavailable"),
            ):
                with patch.object(macos_capability, "_terminate_probe_tree", side_effect=terminate_group) as teardown:
                    with self.assertRaisesRegex(
                        macos_capability.ProbeFailure,
                        "descriptor_readback_unavailable",
                    ):
                        macos_capability._observe_probe(
                            "unused",
                            "unused",
                            "unused",
                            501,
                            "unused",
                        )
        self.assertIsNotNone(process.poll(), "probe root process was not reaped")
        self.assertFalse(group, "probe process group was not terminated")
        teardown.assert_called_once_with(process)

    def test_terminate_probe_tree_escalates_with_injected_group_operations(self):
        class StubProcess:
            pid = 12345

            def __init__(self):
                self.returncode = None
                self.wait_calls = 0

            def poll(self):
                return self.returncode

            def wait(self, timeout):
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise subprocess.TimeoutExpired("stub-probe", timeout)
                self.returncode = -9
                return self.returncode

        process = StubProcess()
        with patch.object(macos_capability.os, "killpg", create=True) as killpg:
            with patch.object(macos_capability.signal, "SIGKILL", 9, create=True):
                with patch.object(
                    macos_capability,
                    "_wait_probe_group_gone",
                    side_effect=(False, True),
                ) as group_gone:
                    self.assertTrue(macos_capability._terminate_probe_tree(process))
        self.assertEqual(
            [(call.args[0], call.args[1]) for call in killpg.call_args_list],
            [(process.pid, macos_capability.signal.SIGTERM), (process.pid, 9)],
        )
        self.assertEqual(process.wait_calls, 2)
        self.assertEqual(group_gone.call_count, 2)

    def test_process_table_error_runs_teardown_contract_on_every_platform(self):
        process = type(
            "StubProcess",
            (),
            {"pid": 12345, "stdout": io.BytesIO(), "stderr": io.BytesIO(), "poll": lambda self: None},
        )()
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(
                macos_capability,
                "_process_table",
                side_effect=macos_capability.ProbeFailure("descriptor_readback_unavailable"),
            ):
                with patch.object(macos_capability, "_terminate_probe_tree", return_value=True) as teardown:
                    with self.assertRaisesRegex(
                        macos_capability.ProbeFailure,
                        "descriptor_readback_unavailable",
                    ):
                        macos_capability._observe_probe(
                            "unused",
                            "unused",
                            "unused",
                            501,
                            "unused",
                        )
        teardown.assert_called_once_with(process)

    def test_unproven_teardown_does_not_close_stream_under_live_capture(self):
        class LockedStream:
            def __init__(self):
                self.closed = False
                self.close_calls = 0

            def close(self):
                self.close_calls += 1
                raise RuntimeError("close blocked behind active capture read")

        stdout = LockedStream()
        stderr = LockedStream()
        process = type(
            "StubProcess",
            (),
            {"pid": 12345, "stdout": stdout, "stderr": stderr, "poll": lambda self: None},
        )()
        with patch.object(macos_capability.subprocess, "Popen", return_value=process):
            with patch.object(
                macos_capability,
                "_process_table",
                side_effect=macos_capability.ProbeFailure("descriptor_readback_unavailable"),
            ):
                with patch.object(macos_capability, "_terminate_probe_tree", return_value=False):
                    with patch.object(macos_capability._Capture, "start"):
                        with patch.object(macos_capability._Capture, "join", return_value=False):
                            with self.assertRaisesRegex(
                                macos_capability.ProbeFailure,
                                "sandbox_behavior_unavailable",
                            ) as raised:
                                macos_capability._observe_probe(
                                    "unused",
                                    "unused",
                                    "unused",
                                    501,
                                    "unused",
                                )
        self.assertFalse(raised.exception.cleanup_complete)
        self.assertEqual(stdout.close_calls, 0)
        self.assertEqual(stderr.close_calls, 0)

    def test_unproven_teardown_keeps_account_and_scratch_state(self):
        with tempfile.TemporaryDirectory(prefix="macos-probe-cleanup-guard-") as directory:
            root = os.path.join(directory, "workspace")
            marker = os.path.join(root, "kit", "confinement", "macos_capability.swift")
            os.makedirs(os.path.dirname(marker))
            with open(marker, "w", encoding="utf-8") as handle:
                handle.write("// public synthetic probe\n")
            home_parent = os.path.join(directory, "home-parent")
            home = os.path.join(home_parent, "home")
            os.mkdir(home_parent)
            os.mkdir(home)
            scratch_paths = []

            def make_scratch(prefix, dir):
                path = os.path.join(directory, prefix + str(len(scratch_paths)))
                os.mkdir(path)
                scratch_paths.append(path)
                return path

            failure = macos_capability.ProbeFailure("sandbox_behavior_unavailable", cleanup_complete=False)
            with patch.dict(os.environ, {"CI_WORKSPACE": root}):
                with patch.object(macos_capability, "_check_context", return_value=Path(root)):
                    with patch.object(macos_capability, "_disable_developer_mode"):
                        with patch.object(macos_capability, "_protect_runner_controls", return_value=(501, (), ())):
                            with patch.object(macos_capability, "_create_probe_identity", return_value=(502, home_parent, home)):
                                with patch.object(macos_capability.tempfile, "mkdtemp", side_effect=make_scratch):
                                    with patch.object(macos_capability, "_verify_runner_controls_are_private"):
                                        with patch.object(macos_capability, "_run_as_probe_user"):
                                            with patch.object(macos_capability, "_build_signed_probe", return_value="unused"):
                                                with patch.object(macos_capability, "_observe_probe", side_effect=failure):
                                                    with patch.object(macos_capability, "_run") as run:
                                                        with self.assertRaisesRegex(
                                                            macos_capability.ProbeFailure,
                                                            "sandbox_behavior_unavailable",
                                                        ):
                                                            macos_capability.run_native_probe("a" * 40)
            self.assertTrue(os.path.isdir(home_parent))
            self.assertTrue(os.path.isdir(home))
            self.assertTrue(all(os.path.isdir(path) for path in scratch_paths))
            run.assert_not_called()
            shutil.rmtree(home_parent, ignore_errors=True)
            for path in scratch_paths:
                shutil.rmtree(path, ignore_errors=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
