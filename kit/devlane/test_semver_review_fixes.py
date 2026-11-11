import ast
import hashlib
import inspect
import os
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import constraint_resolver
import semver_cargo_wrapper
import semver_offline_cache
import semver_stage
import supervisor


class Budget:
    def remaining(self, *_args):
        return 30


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _tool_receipts(root, outputs):
    tool_root = root / "tools"
    binary = tool_root / "bin"
    binary.mkdir(parents=True)
    (tool_root / "lib").mkdir()
    hashes = {}
    for name in ("cargo", "rustc"):
        path = binary / name
        path.write_bytes(("synthetic-" + name).encode("ascii"))
        hashes[name + "_sha256"] = _sha(path.read_bytes())
        hashes[name + "_version_output_sha256"] = _sha(outputs[name])
    return tool_root, hashes


def _run_receipts(tool_root, hashes, outputs):
    calls = []

    def runner(argv, **kwargs):
        calls.append((argv, kwargs))
        name = Path(argv[0]).name
        return subprocess.CompletedProcess(argv, 0, outputs[name], b"")

    semver_offline_cache._verify_rust_tool_receipts(
        tool_root, hashes, Budget(), run_process=runner,
    )
    return calls


def _swap_regular_for_fifo(module, path, reader):
    path.write_bytes(b"x")
    original = os.open
    swapped = False

    def replacing_open(target, flags, *args, **kwargs):
        nonlocal swapped
        if os.fspath(target) == os.fspath(path) and not swapped:
            swapped = True
            path.unlink()
            os.mkfifo(path)
        return original(target, flags, *args, **kwargs)

    started = time.monotonic()
    expected = (
        semver_offline_cache.Refusal, semver_stage.SemverRefusal,
        semver_cargo_wrapper.WrapperRefusal, supervisor.SupervisorRefusal,
    )
    with patch.object(module.os, "open", side_effect=replacing_open):
        with unittest.TestCase().assertRaises(expected):
            reader(path)
    return time.monotonic() - started, swapped


class ToolReceiptTests(unittest.TestCase):
    def test_consumer_matches_actual_verbose_producer_commands_and_loader(self):
        source = inspect.getsource(constraint_resolver.run_cargo_fixed_point)
        tree = ast.parse(source)
        producer_calls = {}
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Name):
                continue
            if node.func.id != "tool_version" or len(node.args) < 4:
                continue
            executable = node.args[0].id
            producer_calls[executable] = (
                ast.literal_eval(node.args[1]), ast.literal_eval(node.args[2]),
                ast.literal_eval(node.args[3]),
            )
        self.assertEqual(producer_calls, {
            "cargo": (["--version", "--verbose"], b"cargo 1.99.1 ",
                      b"host: x86_64-unknown-linux-gnu"),
            "rustc": (["-vV"], b"rustc 1.99.1 ",
                      b"host: x86_64-unknown-linux-gnu"),
        })
        self.assertIn('"LD_LIBRARY_PATH": str(Path(executable).parent.parent / "lib")', source)
        outputs = {
            "cargo": (b"cargo 1.99.1 (synthetic)\nrelease: 1.99.1\n"
                      b"host: x86_64-unknown-linux-gnu\n"),
            "rustc": (b"rustc 1.99.1 (synthetic)\nbinary: rustc\n"
                      b"host: x86_64-unknown-linux-gnu\n"),
        }
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            tool_root, hashes = _tool_receipts(Path(temporary), outputs)
            calls = _run_receipts(tool_root, hashes, outputs)
            self.assertEqual([call[0][1:] for call in calls], [
                ["--version", "--verbose"], ["-vV"],
            ])
            for argv, kwargs in calls:
                tool = Path(argv[0])
                self.assertEqual(kwargs["env"], {
                    "PATH": str(tool.parent) + ":/usr/bin:/bin",
                    "LC_ALL": "C",
                    "LD_LIBRARY_PATH": str(tool.parent.parent / "lib"),
                })
        plain = dict(outputs)
        plain["cargo"] = b"cargo 1.99.1\n"
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            tool_root, hashes = _tool_receipts(Path(temporary), outputs)
            hashes["cargo_version_output_sha256"] = _sha(plain["cargo"])
            with self.assertRaises(semver_offline_cache.Refusal):
                _run_receipts(tool_root, hashes, plain)

    def test_wrapper_environment_and_color_are_operation_scoped(self):
        self.assertEqual(semver_stage._pins()["offline_cache"], semver_stage.OFFLINE_CACHE_PIN)
        self.assertEqual(semver_cargo_wrapper._cargo_environment()["LD_LIBRARY_PATH"],
                         "/tools/rust/lib")
        with self.assertRaises(semver_cargo_wrapper.WrapperRefusal):
            semver_cargo_wrapper._parse_cargo_arguments([
                "metadata", "--format-version", "1", "--manifest-path",
                "/workspace/source/runtime/Cargo.toml", "--color=never",
            ])
        update = semver_cargo_wrapper._parse_cargo_arguments([
            "update", "--manifest-path",
            "/scratch/semver-target/semver-checks/local-synthetic/Cargo.toml",
            "--color=never",
        ])
        self.assertEqual(update["operation"], "update")


class BoundedReaderTests(unittest.TestCase):
    def test_hardlinks_refuse_in_every_snapshot_reader(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            root = Path(temporary)
            source = root / "input"
            alias = root / "alias"
            source.write_bytes(b"synthetic")
            os.link(source, alias)
            readers = (
                lambda: semver_offline_cache._read_file(source, 128),
                lambda: semver_stage._read_fixed_file(source, 128),
                lambda: semver_stage._hash_file(source),
                lambda: semver_cargo_wrapper._read_context(source),
            )
            for reader in readers:
                with self.subTest(reader=reader):
                    with self.assertRaises(Exception):
                        reader()
            tree = root / "tree"
            tree.mkdir()
            member = tree / "Cargo.toml"
            member.write_bytes(b"[package]\n")
            os.link(member, tree / "alias")
            with self.assertRaises(semver_offline_cache.Refusal):
                semver_offline_cache.source_map_digest(tree, Budget())
            with self.assertRaises(semver_offline_cache.Refusal):
                semver_offline_cache.tree_digest(tree, Budget())

    def test_regular_to_fifo_races_refuse_without_blocking(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            root = Path(temporary)
            cases = [
                (semver_offline_cache, root / "cache", lambda path: semver_offline_cache._read_file(path, 128)),
                (semver_stage, root / "fixed", lambda path: semver_stage._read_fixed_file(path, 128)),
                (semver_stage, root / "hash", lambda path: semver_stage._hash_file(path)),
                (semver_cargo_wrapper, root / "context", lambda path: semver_cargo_wrapper._read_context(path)),
            ]
            for module, path, reader in cases:
                with self.subTest(path=path.name):
                    elapsed, swapped = _swap_regular_for_fifo(module, path, reader)
                    self.assertTrue(swapped, path.name)
                    self.assertLess(elapsed, 1.0)
            tree = root / "tree"
            tree.mkdir()
            member = tree / "Cargo.toml"
            elapsed, swapped = _swap_regular_for_fifo(
                semver_offline_cache, member,
                lambda _path: semver_offline_cache.source_map_digest(tree, Budget()),
            )
            self.assertTrue(swapped)
            self.assertLess(elapsed, 1.0)
            tree2 = root / "tree2"
            tree2.mkdir()
            member2 = tree2 / "Cargo.toml"
            elapsed, swapped = _swap_regular_for_fifo(
                semver_offline_cache, member2,
                lambda _path: semver_offline_cache.tree_digest(tree2, Budget()),
            )
            self.assertTrue(swapped)
            self.assertLess(elapsed, 1.0)

    def test_roster_is_bounded_unique_canonical_positive_and_race_safe(self):
        service = object.__new__(supervisor.Service)
        service.deadline_file = "unused"
        valid = b"100\n200\n"
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            path = Path(temporary) / "cgroup.procs"
            path.write_bytes(valid)
            with patch.object(supervisor.deadline_budget, "remaining", return_value=30):
                self.assertEqual(service._semver_read_cgroup_roster(path), frozenset({100, 200}))
                for payload in (
                    b"100\n200\n200\n", b"0\n", b"+100\n", b"0100\n",
                    b"2147483648\n", b"100", b"\n", b"100\n" * 1025,
                ):
                    path.write_bytes(payload)
                    with self.subTest(payload=payload[:40]):
                        with self.assertRaises(supervisor.SupervisorRefusal):
                            service._semver_read_cgroup_roster(path)
                path.write_bytes(valid)
                alias = Path(temporary) / "alias"
                os.link(path, alias)
                with self.assertRaises(supervisor.SupervisorRefusal):
                    service._semver_read_cgroup_roster(path)
            path.unlink()
            os.mkfifo(path)
            with patch.object(supervisor.deadline_budget, "remaining", return_value=30):
                with self.assertRaises(supervisor.SupervisorRefusal):
                    service._semver_read_cgroup_roster(path)

    def test_small_readers_check_deadlines_during_incremental_reads(self):
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            path = Path(temporary) / "bounded"
            path.write_bytes(b"x" * 20_000)
            with patch.object(semver_offline_cache.time, "monotonic",
                              side_effect=[0.0, 0.0, 6.0]):
                with self.assertRaises(semver_offline_cache.Refusal):
                    semver_offline_cache._read_file(path, 30_000, Budget())
            roster = Path(temporary) / "cgroup.procs"
            roster.write_bytes(b"100\n200\n")
            service = object.__new__(supervisor.Service)
            service.deadline_file = "unused"
            with patch.object(supervisor.deadline_budget, "remaining", return_value=30), \
                    patch.object(supervisor.time, "monotonic", side_effect=[0.0, 0.0, 6.0]):
                with self.assertRaises(supervisor.SupervisorRefusal):
                    service._semver_read_cgroup_roster(roster)

    def test_roster_fifo_replacement_after_lstat_is_nonblocking(self):
        service = object.__new__(supervisor.Service)
        service.deadline_file = "unused"
        with tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()) as temporary:
            path = Path(temporary) / "cgroup.procs"
            elapsed, swapped = _swap_regular_for_fifo(
                supervisor, path, service._semver_read_cgroup_roster,
            )
        self.assertTrue(swapped)
        self.assertLess(elapsed, 1.0)


class SupervisorCheckpointTests(unittest.TestCase):
    def test_rejected_first_events_do_not_allocate_project_trackers(self):
        binding = {
            "source_commit": "a" * 40,
            "control_sha": "b" * 40,
            "manifest_projection_sha256": "c" * 64,
            "candidate_git_tree_map_sha256": "d" * 64,
            "candidate_transfer_map_sha256": "e" * 64,
            "baseline_source_map_sha256": "f" * 64,
            "semver_tool_binary_sha256": "1" * 64,
        }
        valid = {
            "manifest_sha256": "a" * 64,
            "project_map_without_lock_sha256": "b" * 64,
            "project_file_count_without_lock": 1,
            "project_tree_bytes_without_lock": 1,
            "project_map_sha256": "b" * 64,
            "project_file_count": 1,
            "project_tree_bytes": 1,
            "lock_sha256": None,
            "lock_size": None,
        }
        invalid = dict(valid)
        invalid.update({
            "project_map_sha256": "c" * 64,
            "project_file_count": 2,
            "project_tree_bytes": 2,
            "lock_sha256": "d" * 64,
            "lock_size": 1,
        })
        active = {
            "checkpoint_binding": binding,
            "trackers": {},
            "events": [],
            "work_deadline": time.monotonic() + 30,
            "cleanup_deadline": time.monotonic() + 60,
        }
        service = object.__new__(supervisor.Service)
        service.root = Path(tempfile.gettempdir())
        service.semver_active = active
        service.semver_active_lock = threading.Lock()
        supervisor.CANCEL_REQUESTED.clear()
        paths = (
            "/scratch/semver-target/semver-checks/local-synthetic-one/Cargo.toml",
            "/scratch/semver-target/semver-checks/local-synthetic-two/Cargo.toml",
        )
        with patch.object(supervisor.Service, "_semver_checkpoint_peer",
                          return_value={"project_kind": "local"}), \
                patch.object(supervisor.Service, "_semver_checkpoint_snapshot",
                             return_value=invalid):
            for manifest in paths:
                request = {"op": "semver-checkpoint", "event": "before-update",
                           "operation": "update", "manifest": manifest}
                with self.assertRaises(supervisor.SupervisorRefusal):
                    service._semver_checkpoint(request, 200)
                self.assertEqual(active["trackers"], {})
                self.assertEqual(active["events"], [])
        with patch.object(supervisor.Service, "_semver_checkpoint_peer",
                          return_value={"project_kind": "local"}), \
                patch.object(supervisor.Service, "_semver_checkpoint_snapshot",
                             return_value=valid):
            request = {"op": "semver-checkpoint", "event": "before-update",
                       "operation": "update", "manifest": paths[0]}
            self.assertEqual(service._semver_checkpoint(request, 200), {"ok": True})
        self.assertEqual(set(active["trackers"]), {str(Path(paths[0]).parent)})
        self.assertEqual(len(active["events"]), 1)


if __name__ == "__main__":
    unittest.main()
