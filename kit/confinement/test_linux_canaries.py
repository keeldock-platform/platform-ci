import base64
import os
import re
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import linux_canaries as canaries
from linux_channels import BoundaryRefusal


__all__ = ["LinuxCanaryTests", "LinuxCanaryWalkTests", "LinuxReviewFixCanaryTests"]

NONCE = "0123456789abcdef01234567"
ROOT = Path(__file__).resolve().parents[2]


class LinuxCanaryTests(unittest.TestCase):
    def test_standin_is_a_fixed_sixty_four_character_non_secret_matching_the_workflow(self):
        self.assertEqual(len(canaries.STANDIN_VALUE), 64)
        self.assertTrue(canaries.valid_canary(canaries.STANDIN_VALUE))
        self.assertIn("NOT-A-SECRET", canaries.STANDIN_VALUE)
        workflow = (ROOT / ".github/workflows/linux-source-admission.yml").read_text(encoding="utf-8")
        self.assertEqual(workflow.count("KD_CANARY_SECRET: " + canaries.STANDIN_VALUE), 3)
        self.assertNotIn("secrets.", workflow)

    def test_canary_validation_bounds_and_environment_loading(self):
        for bad in (None, "", "a" * 15, "a" * 257, "has space in it 12345", "caf" + chr(233) + "x" * 20):
            self.assertFalse(canaries.valid_canary(bad))
        self.assertTrue(canaries.valid_canary("a" * 16))
        self.assertEqual(canaries.load_canary({canaries.CANARY_ENV_NAME: "b" * 20}), "b" * 20)
        with self.assertRaises(BoundaryRefusal):
            canaries.load_canary({})
        with self.assertRaises(BoundaryRefusal):
            canaries.load_canary({canaries.CANARY_ENV_NAME: "short"})

    def test_needles_cover_raw_hex_base64_urlsafe_and_utf16_forms(self):
        value = "kd-example-canary-value-0123456789+/"
        needles = canaries.needles_for(value)
        raw = value.encode()
        self.assertIn(raw, needles)
        self.assertIn(raw.hex().encode(), needles)
        self.assertIn(base64.b64encode(raw), needles)
        self.assertIn(base64.b64encode(raw).rstrip(b"="), needles)
        self.assertIn(base64.urlsafe_b64encode(raw), needles)
        self.assertIn(value.encode("utf-16-le"), needles)
        self.assertEqual(list(needles), sorted(needles))
        with self.assertRaises(ValueError):
            canaries.needles_for("short")

    def test_nonce_canary_and_control_tokens_are_unique_and_scoped(self):
        self.assertNotEqual(canaries.new_nonce_canary(), canaries.new_nonce_canary())
        self.assertTrue(canaries.valid_canary(canaries.new_nonce_canary()))
        tokens = {canaries.control_token(kind, NONCE) for kind in ("readable", "private", "environ")}
        self.assertEqual(len(tokens), 3)
        with self.assertRaises(ValueError):
            canaries.control_token("other", NONCE)

    def test_placed_canaries_are_not_world_accessible_unless_a_fault_asks(self):
        with tempfile.TemporaryDirectory() as base:
            directory = os.path.join(base, "canary")
            placed = canaries.place_canaries(directory, ["v" * 20, "w" * 20])
            self.assertEqual([os.path.basename(path) for path in placed], ["env-file", "script-file"])
            for path in placed:
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode) & 0o077, 0)
            leaked = canaries.place_canaries(directory, ["v" * 20, "w" * 20], world_readable=True)
            self.assertEqual(os.path.basename(leaked[-1]), "leak-file")
            self.assertEqual(stat.S_IMODE(os.stat(leaked[-1]).st_mode), 0o644)

    def test_control_files_are_one_readable_and_one_private(self):
        with tempfile.TemporaryDirectory() as base:
            readable, private = canaries.plant_control_files(os.path.join(base, "control"), NONCE)
            self.assertEqual(stat.S_IMODE(os.stat(readable).st_mode), 0o644)
            self.assertEqual(stat.S_IMODE(os.stat(private).st_mode), 0o600)
            self.assertIn(canaries.control_token("readable", NONCE), Path(readable).read_text())
            self.assertIn(canaries.control_token("private", NONCE), Path(private).read_text())

    def test_job_cutoff_uses_the_worker_start_or_falls_back_to_boot_time(self):
        fields = ["S"] + ["0"] * 18 + ["500"] + ["0"] * 5
        stat_text = "123 (Runner.Worker) " + " ".join(fields)
        self.assertEqual(canaries.parse_stat_start_ticks(stat_text), 500)
        self.assertEqual(canaries.parse_stat_start_ticks("1 (a) b) " + " ".join(fields)), 500)
        boot = "cpu 1 2 3\nbtime 1000\nprocesses 5\n"
        self.assertEqual(canaries.parse_boot_time(boot), 1000)
        expected = 1000 * 10 ** 9 + (500 * 10 ** 9) // 100 - canaries.JOB_START_SLACK_NS
        self.assertEqual(canaries.job_cutoff_ns(stat_text, boot, 100), expected)
        self.assertEqual(canaries.job_cutoff_ns(None, boot, 100), 1000 * 10 ** 9 - canaries.BOOT_SLACK_NS)
        for bad in ("", "no paren", "1 (a) S 1"):
            with self.assertRaises(ValueError):
                canaries.parse_stat_start_ticks(bad)
        with self.assertRaises(ValueError):
            canaries.parse_boot_time("cpu 1\n")

    def test_runner_targets_cover_temp_work_diag_credentials_and_command_files(self):
        with tempfile.TemporaryDirectory() as base:
            home = os.path.join(base, "home")
            work = os.path.join(home, "work", "_temp")
            os.makedirs(os.path.join(work, "_runner_file_commands"))
            Path(work, "_runner_file_commands", "set_env_1").write_text("x")
            runner = os.path.join(home, "runners", "2.0")
            os.makedirs(os.path.join(runner, "_diag"))
            Path(runner, ".credentials").write_text("x")
            Path(runner, ".runner").write_text("x")
            os.makedirs(os.path.join(home, ".ssh"))
            targets = canaries.runner_targets(home, work)
            for expected in (
                work,
                os.path.dirname(work),
                os.path.join(work, "_runner_file_commands", "set_env_1"),
                os.path.join(runner, "_diag"),
                os.path.join(runner, ".credentials"),
                os.path.join(runner, ".runner"),
                os.path.join(home, ".ssh"),
                home,
            ):
                self.assertIn(expected, targets)
            self.assertEqual(len(targets), len(set(targets)))
            self.assertEqual(canaries.runner_targets(None, None), [])

    def test_hardening_removes_other_access_and_reads_it_back(self):
        with tempfile.TemporaryDirectory() as base:
            path = os.path.join(base, "dir")
            os.mkdir(path, 0o755)
            os.chmod(path, 0o755)
            link = os.path.join(base, "link")
            os.symlink(path, link)
            self.assertEqual(canaries.harden_runner_paths([path, link, os.path.join(base, "missing")]), 1)
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode) & 0o007, 0)
            self.assertEqual(canaries.harden_runner_paths([path]), 0)
            with patch("linux_canaries.os.chmod"):
                os.chmod(path, 0o755)
            os.chmod(path, 0o755)
            with patch("linux_canaries.os.chmod"):
                with self.assertRaises(BoundaryRefusal):
                    canaries.harden_runner_paths([path])


class LinuxCanaryWalkTests(unittest.TestCase):
    def test_walk_finds_needles_in_recent_files_and_reports_groups(self):
        with tempfile.TemporaryDirectory() as base:
            Path(base, "hit").write_bytes(b"prefix-" + b"s" * 20 + b"-suffix")
            Path(base, "control").write_bytes(b"c" * 24)
            Path(base, "clean").write_bytes(b"nothing to see here at all")
            os.mkdir(os.path.join(base, "nested"))
            Path(base, "nested", "deep").write_bytes(b"x" + b"s" * 20)
            needles = [(0, b"s" * 20), (1, b"c" * 24), (2, b"p" * 24)]
            result = canaries.walk_tree(needles, 0, time.monotonic() + 30, (base,))
            self.assertTrue(result["complete"])
            groups = sorted((os.path.basename(path), group) for path, group in result["hits"])
            self.assertEqual(groups, [("control", 1), ("deep", 0), ("hit", 0)])
            evaluated = canaries.evaluate_walk(result)
            self.assertEqual(evaluated, {"secret": True, "readable_control": True, "private_control": False})

    def test_walk_ignores_files_older_than_the_cutoff_and_detects_chunk_boundaries(self):
        with tempfile.TemporaryDirectory() as base:
            Path(base, "old").write_bytes(b"s" * 20)
            future = time.time_ns() + 10 ** 12
            self.assertEqual(canaries.walk_tree([(0, b"s" * 20)], future, time.monotonic() + 30, (base,))["hits"], [])
            with patch.object(canaries, "SCAN_CHUNK", 8):
                Path(base, "split").write_bytes(b"aaaa" + b"s" * 20 + b"bbbb")
                result = canaries.walk_tree([(0, b"s" * 20)], 0, time.monotonic() + 30, (base,))
            self.assertIn("split", [os.path.basename(path) for path, group in result["hits"]])

    def test_walk_reports_incomplete_when_the_deadline_has_passed(self):
        with tempfile.TemporaryDirectory() as base:
            result = canaries.walk_tree([(0, b"s" * 20)], 0, time.monotonic() - 1, (base,))
            self.assertFalse(result["complete"])
            with self.assertRaises(BoundaryRefusal) as raised:
                canaries.evaluate_walk(result)
            self.assertEqual(raised.exception.reason, "scan_incomplete")

    def test_evaluation_refuses_malformed_replies(self):
        for bad in ({}, {"hits": "x", "complete": True}, {"hits": [["p"]], "complete": True}, {"hits": [["p", "g"]], "complete": True}):
            with self.assertRaises(BoundaryRefusal):
                canaries.evaluate_walk(bad)
        for bad in ({}, {"hits": [], "readable": "1"}, {"hits": [[1]], "readable": 1}):
            with self.assertRaises(BoundaryRefusal):
                canaries.evaluate_environ(bad)
        ok = canaries.evaluate_environ({"hits": [[5, 1], [6, 0]], "readable": 3})
        self.assertEqual(ok, {"secret": True, "readable_control": True, "private_control": False, "readable": True})

    def test_needle_encoding_round_trips_and_rejects_short_values(self):
        items = canaries.encode_needles([(0, (b"a" * 20, b"b" * 20)), (1, (b"c" * 20,))])
        self.assertEqual(canaries.decode_needles(items), [(0, b"a" * 20), (0, b"b" * 20), (1, b"c" * 20)])
        for bad in ([], [[0, "6161"]], [[0]], [["0", "61" * 20]], [[0, 5]]):
            with self.assertRaises(ValueError):
                canaries.decode_needles(bad)

    def test_path_probe_reports_leaks_by_original_index(self):
        with tempfile.TemporaryDirectory() as base:
            readable = os.path.join(base, "readable")
            Path(readable).write_text("x")
            result = canaries.probe_paths([(3, readable), (7, base)], NONCE)
            self.assertEqual(result["tested"], 2)
            self.assertEqual(result["leaks"], [3, 7])
            self.assertEqual(os.listdir(base), ["readable"])

    def test_walker_refuses_without_root_and_the_environment_is_scrubbed(self):
        import io
        request = b'{"mode": "walk"}'
        with patch("linux_canaries.os.geteuid", return_value=1000):
            self.assertEqual(canaries.walker_main(io.BytesIO(request), io.BytesIO()), 2)
        self.assertNotIn(canaries.CANARY_ENV_NAME, canaries.WALKER_ENV)
        self.assertEqual(set(canaries.WALKER_ENV), {"PATH", "LANG", "LC_ALL", "PYTHONDONTWRITEBYTECODE"})
        self.assertIsNone(re.fullmatch(canaries.ABSOLUTE_PATH.pattern, "relative/path"))



class LinuxReviewFixCanaryTests(unittest.TestCase):
    def test_runner_root_comes_from_the_worker_executable_layout_only(self):
        self.assertEqual(canaries.runner_root_from_exe("/opt/runner/bin.2.1.0/Runner.Worker"), "/opt/runner")
        for bad in (None, "", "relative", "/opt/runner/bin.2.1.0/Other", "/opt/runner/lib/Runner.Worker", "/opt/run ner/bin/Runner.Worker"):
            self.assertIsNone(canaries.runner_root_from_exe(bad))

    def test_required_unreadable_targets_are_temp_and_the_runner_diag(self):
        self.assertEqual(canaries.required_unreadable("/w/_temp", "/r"), ["/w/_temp", "/r/_diag"])
        self.assertEqual(canaries.required_unreadable("/w/_temp", None), ["/w/_temp"])
        self.assertEqual(canaries.required_unreadable(None, None), [])

    def test_targets_include_the_runner_root_diag_work_temp_and_credentials(self):
        with tempfile.TemporaryDirectory() as base:
            root = os.path.join(base, "runner")
            os.makedirs(os.path.join(root, "_diag"))
            os.makedirs(os.path.join(root, "_work", "_temp"))
            Path(root, ".credentials").write_text("x")
            targets = canaries.runner_targets(None, os.path.join(root, "_work", "_temp"), root)
            for name in ("_diag", "_work", "_work/_temp", ".credentials"):
                self.assertIn(os.path.join(root, name), targets)
            self.assertNotIn(os.path.join(root, ".runner"), targets)

    def test_derived_canary_is_a_keyed_digest_not_the_secret(self):
        secret = "s" * 40
        derived = canaries.derive_canary(secret, "label")
        self.assertEqual(len(derived), 64)
        self.assertNotIn(secret, derived)
        self.assertNotEqual(derived, canaries.derive_canary(secret, "other"))
        self.assertNotEqual(derived, canaries.derive_canary("t" * 40, "label"))
        self.assertTrue(canaries.valid_canary(derived))
        with self.assertRaises(ValueError):
            canaries.derive_canary("short", "label")


if __name__ == "__main__":
    unittest.main(verbosity=2)
