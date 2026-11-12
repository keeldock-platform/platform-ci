"""Source-free regressions for the closed Core PR1 Rust matrix."""

import argparse
import ast
import builtins
import contextlib
import io
import json
import inspect
import multiprocessing
import os
import re
import signal
import shutil
import stat
import sys
import subprocess
import tempfile
import time
import tomllib
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import public_audit
import network_probe
import acceptance_diagnostics
import filter as output_filter
import fetch
import rust_matrix_runner
import rust_tooling
import cgroup_exec
import deadline as deadline_budget
import diagnostic_contract
import node_tool_snapshot
import host_cleanup
import supervisor
import test_e2e


def _term_split_group(marker):
    marker = Path(marker)
    child_code = (
        "import pathlib,signal,sys,time; signal.signal(signal.SIGTERM, signal.SIG_IGN); "
        "pathlib.Path(sys.argv[1] + '.ready').write_text('ready'); time.sleep(30)"
    )
    leader_code = (
        "import pathlib,signal,subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable, '-c', sys.argv[2], sys.argv[1]]); "
        "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); "
        "pathlib.Path(sys.argv[1] + '.leader').write_text(str(__import__('os').getpid())); "
        "ready=pathlib.Path(sys.argv[1] + '.ready'); "
        "exec('while not ready.exists(): time.sleep(0.005)'); "
        "signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); time.sleep(30)"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", leader_code, str(marker), child_code],
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    end = time.monotonic() + 4
    while time.monotonic() < end:
        if marker.exists() and Path(str(marker) + ".ready").exists():
            return process, int(marker.read_text(encoding="ascii"))
        time.sleep(0.01)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=3)
    raise AssertionError("descendant fixture did not become ready")


def _assert_pid_gone(test, pid):
    end = time.monotonic() + 4
    while time.monotonic() < end:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.02)
    test.fail("TERM-ignoring descendant survived group cleanup")


def _fifo_snapshot_child(kind, fixture, deadline_file, snapshot_base, snapshot_id,
                         parent_device, parent_inode, trigger_count, result_connection):
    real_open = os.open
    open_count = 0
    observed_nonblock = False
    opened_fifo = False
    target_name = node_tool_snapshot.MANIFEST_NAME if kind == "manifest" else "node"

    def open_with_fifo_swap(path, flags, *args, **kwargs):
        nonlocal open_count, observed_nonblock, opened_fifo
        triggered = False
        directory_fd = kwargs.get("dir_fd")
        if path == target_name and directory_fd is not None and not flags & node_tool_snapshot._O_DIRECTORY:
            try:
                metadata = os.fstat(directory_fd)
            except OSError:
                metadata = None
            if (metadata is not None and metadata.st_dev == parent_device
                    and metadata.st_ino == parent_inode):
                open_count += 1
                triggered = open_count == trigger_count
                if triggered:
                    observed_nonblock = bool(flags & getattr(os, "O_NONBLOCK", 0))
                    if kind in ("manifest", "snapshot-content"):
                        os.fchmod(directory_fd, 0o755)
                    try:
                        os.unlink(path, dir_fd=directory_fd)
                        os.mkfifo(path, 0o600, dir_fd=directory_fd)
                    finally:
                        if kind in ("manifest", "snapshot-content"):
                            os.fchmod(directory_fd, 0o555)
        descriptor = real_open(path, flags, *args, **kwargs)
        if triggered:
            opened_fifo = stat.S_ISFIFO(os.fstat(descriptor).st_mode)
        return descriptor

    os.open = open_with_fifo_swap
    try:
        if kind in ("copy", "source-verification"):
            preparation = supervisor.node_tool_prepare
            preparation.NODE_TOOL_CACHE_ROOT = fixture["cache"]
            preparation.NODE_TOOL_ROOT = fixture["node_root"]
            preparation.NODE_TOOL_SYSTEM_ANCHORS = ((fixture["anchor"], os.getuid()),)
            node_tool_snapshot.create_snapshot(
                fixture["paths"], snapshot_id, os.getuid(), str(deadline_file),
                snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                source_node_root=fixture["node_root"],
                source_anchors=((fixture["anchor"], os.getuid()),),
            )
        else:
            node_tool_snapshot.validate_snapshot(
                snapshot_id, str(deadline_file), snapshot_base=snapshot_base,
                owner_uid=os.getuid(),
            )
        result = ("accepted", "", open_count, observed_nonblock, opened_fifo)
    except node_tool_snapshot.SnapshotRefusal as error:
        result = ("refused", error.code, open_count, observed_nonblock, opened_fifo)
    except BaseException as error:
        result = ("error", type(error).__name__, open_count, observed_nonblock, opened_fifo)
    finally:
        os.open = real_open
        result_connection.send(result)
        result_connection.close()


class _RootEffectiveUIDProxy:
    def __getattr__(self, name):
        return getattr(os, name)

    @staticmethod
    def geteuid():
        return 0


class _MixedOwnerMetadataProxy:
    _STAT_FIELDS = (
        "st_dev", "st_ino", "st_mode", "st_nlink", "st_uid", "st_gid", "st_size",
        "st_atime", "st_mtime", "st_ctime", "st_atime_ns", "st_mtime_ns", "st_ctime_ns",
    )

    def __init__(self, root_owned_path):
        self.root_owned_path = Path(root_owned_path).absolute()
        self.fd_paths = {}
        self.source_owners = []

    def __getattr__(self, name):
        return getattr(os, name)

    def open(self, path, flags, *args, **kwargs):
        directory_fd = kwargs.get("dir_fd")
        if directory_fd is None:
            absolute = Path(path)
            if not absolute.is_absolute():
                absolute = Path.cwd() / absolute
        else:
            absolute = self.fd_paths.get(directory_fd, Path.cwd()) / os.fsdecode(path)
        descriptor = os.open(path, flags, *args, **kwargs)
        self.fd_paths[descriptor] = Path(os.path.normpath(str(absolute)))
        return descriptor

    def close(self, descriptor):
        self.fd_paths.pop(descriptor, None)
        return os.close(descriptor)

    def _absolute(self, path, directory_fd):
        if directory_fd is None:
            absolute = Path(path)
            return absolute if absolute.is_absolute() else Path.cwd() / absolute
        return self.fd_paths.get(directory_fd, Path.cwd()) / os.fsdecode(path)

    def _reported(self, metadata, absolute):
        absolute = Path(os.path.normpath(str(absolute)))
        owner = 0 if absolute == self.root_owned_path else metadata.st_uid
        if absolute == self.root_owned_path:
            self.source_owners.append((str(absolute), owner))
        values = {name: getattr(metadata, name) for name in self._STAT_FIELDS
                  if hasattr(metadata, name)}
        values["st_uid"] = owner
        return SimpleNamespace(**values)

    def stat(self, path, *args, **kwargs):
        metadata = os.stat(path, *args, **kwargs)
        return self._reported(metadata, self._absolute(path, kwargs.get("dir_fd")))

    def fstat(self, descriptor):
        metadata = os.fstat(descriptor)
        absolute = self.fd_paths.get(descriptor)
        return self._reported(metadata, absolute) if absolute is not None else metadata


def _coverage(records, suite):
    total = 1
    records.append({
        "kind": "coverage", "stage": rust_matrix_runner._stage_for(suite),
        "suite": suite, "total": total, "passed": total, "failed": 0, "ignored": 0,
    })
    return True


class RustMatrixRunnerTests(unittest.TestCase):
    def _summary_scenario(self):
        return {
            "profile": "core-rust", "allowed_files": {},
            "allowed_tests": test_e2e.RUST_FIXTURE_TESTS, "frames": {},
        }

    def _summary_payload(self, records):
        profile_root = json.loads((Path(__file__).resolve().parents[2] / "ci/devlane-profiles.json").read_text())
        profile = profile_root["profiles"]["core-rust"]
        allowlists = {
            "files": {}, "tests": {item: item for item in test_e2e.RUST_FIXTURE_TESTS.values()},
            "frames": {}, "stages": profile["stages"],
            "codes": sorted(set(profile["diagnostic_codes"] + ["DEVLANE_FAILURE"])),
            "max_lines": {}, "suites": sorted(profile["rust_matrix"]["coverage_ids"]),
        }
        return output_filter.filter_records(
            [json.dumps(row, sort_keys=True, separators=(",", ":")).encode() for row in records],
            allowlists,
        )

    def _coverage_rows(self):
        rows = []
        for suite in rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"]:
            total = 2 if suite.startswith("fuzz-replay-") else 1
            rows.append({
                "kind": "coverage", "stage": rust_matrix_runner._stage_for(suite),
                "suite": suite, "total": total, "passed": total, "failed": 0, "ignored": 0,
            })
        return rows

    def _write_node_toolchain_fixture(self, root):
        root = Path(root).resolve()
        anchor = root / "trusted-system-anchor"
        cache = anchor / "hostedtoolcache"
        node_root = cache / "node" / "24.22.1" / "x64"
        node_bin = node_root / "bin"
        npm_root = node_root / "lib/node_modules/npm"
        npm_cli = node_root / "lib/node_modules/npm/bin/npm-cli.js"
        npm_link = node_bin / "npm"
        log_path = root / "node-fixture-log.jsonl"
        for directory in (
            anchor, cache, cache / "node", cache / "node/24.22.1", node_root,
            node_bin, node_root / "lib", node_root / "lib/node_modules",
            npm_root, npm_root / "bin", npm_root / "node_modules",
        ):
            directory.mkdir(mode=0o755, parents=True, exist_ok=True)
            directory.chmod(0o700 if directory == anchor else 0o755)
        node = node_bin / "node"
        node.write_text(
            chr(35) + "!" + sys.executable + "\n"
            "import json, os, sys\n"
            "log_path = " + repr(str(log_path)) + "\n"
            "with open(log_path, 'a', encoding='utf-8') as output:\n"
            "    output.write(json.dumps({'executable': sys.argv[0], 'argv': sys.argv[1:], "
            "'path': os.environ.get('PATH', ''), "
            "'node_options': os.environ.get('NODE_OPTIONS', ''), "
            "'npm_userconfig': os.environ.get('NPM_CONFIG_USERCONFIG', '')}) + '\\n')\n"
            "if sys.argv[1:] == ['--version']:\n"
            "    print('v24.22.1')\n"
            "elif len(sys.argv[1:]) == 2 and sys.argv[1].endswith('npm-cli.js') and sys.argv[2] == '--version':\n"
            "    print('11.19.1')\n"
            "else:\n"
            "    raise SystemExit(97)\n",
            encoding="utf-8",
        )
        node.chmod(0o755)
        npm_cli.write_text(chr(35) + "!/usr/bin/env node\n", encoding="ascii")
        npm_cli.chmod(0o755)
        npm_shared = npm_root / "node_modules/shared.js"
        npm_shared.write_text("synthetic shared npm module fixture\n", encoding="ascii")
        npm_shared.chmod(0o644)
        (npm_root / "node_modules/shared-link.js").symlink_to("shared.js")
        npm_link.symlink_to("../lib/node_modules/npm/bin/npm-cli.js")
        return {
            "anchor": anchor, "cache": cache, "node_root": node_root, "node": node,
            "npm": npm_link, "npm_cli": npm_cli, "npm_root": npm_root,
            "log": log_path,
            "paths": {"node": str(node), "npm": str(npm_link), "cargo": "", "rustc": ""},
        }

    def _write_node_vendor_fixture(self, root, snapshot_id):
        base = Path(root).resolve() / "node-vendor"
        area = base / snapshot_id
        area.mkdir(mode=0o700, parents=True)
        fixture = self._write_node_toolchain_fixture(area)
        cache = area / "cache"
        cache.mkdir(mode=0o700)
        shutil.move(str(fixture["cache"] / "node"), str(cache / "node"))
        fixture["anchor"] = area
        fixture["anchor_uid"] = os.getuid()
        fixture["cache"] = cache
        fixture["node_root"] = cache / "node" / "24.22.1" / "x64"
        fixture["node"] = fixture["node_root"] / "bin/node"
        fixture["npm"] = fixture["node_root"] / "bin/npm"
        fixture["npm_cli"] = fixture["node_root"] / "lib/node_modules/npm/bin/npm-cli.js"
        fixture["npm_root"] = fixture["node_root"] / "lib/node_modules/npm"
        fixture["paths"] = {"node": str(fixture["node"]), "npm": str(fixture["npm"]),
                            "cargo": "", "rustc": ""}
        external_log = base.parent / (snapshot_id + "-node-fixture-log.jsonl")
        node_source = fixture["node"].read_text(encoding="utf-8")
        fixture["node"].write_text(node_source.replace(str(fixture["log"]), str(external_log)), encoding="utf-8")
        fixture["node"].chmod(0o755)
        fixture["log"] = external_log
        vendor = supervisor.node_tool_prepare.node_vendor_source.VendorSource(
            cache, fixture["node_root"], fixture["node"], fixture["npm"],
            supervisor.node_tool_prepare.node_vendor_source.ARCHIVE_SHA256,
            supervisor.node_tool_prepare.node_vendor_source.PREPARATION_ID,
        )
        return base, area, fixture, vendor

    @contextlib.contextmanager
    def _node_fixture_policy(self, fixture):
        node_tool_prepare = supervisor.node_tool_prepare
        anchor_uid = fixture.get("anchor_uid", os.getuid())
        with patch.object(node_tool_prepare, "NODE_TOOL_CACHE_ROOT", fixture["cache"]), \
                patch.object(node_tool_prepare, "NODE_TOOL_ROOT", fixture["node_root"]), \
                patch.object(node_tool_snapshot, "SHARED_TOOLCHAIN_ANCHOR", fixture["anchor"]), \
                patch.object(node_tool_prepare, "NODE_TOOL_SYSTEM_ANCHORS",
                             ((fixture["anchor"], anchor_uid),)):
            yield

    @contextlib.contextmanager
    def _node_anchor_metadata(self, fixture):
        anchor_uid = fixture.get("anchor_uid", os.getuid())
        if anchor_uid == os.getuid():
            yield
            return
        real_lstat = os.lstat

        def lstat_with_anchor_owner(path, *args, **kwargs):
            metadata = real_lstat(path, *args, **kwargs)
            if Path(path) == fixture["anchor"]:
                return SimpleNamespace(st_mode=metadata.st_mode, st_uid=anchor_uid, st_gid=metadata.st_gid)
            return metadata

        with patch.object(os, "lstat", side_effect=lstat_with_anchor_owner):
            yield

    def _create_node_snapshot(self, fixture, snapshot_base, snapshot_id, deadline_path):
        snapshot_base = Path(snapshot_base).resolve()
        with self._node_fixture_policy(fixture):
            snapshot = node_tool_snapshot.create_snapshot(
                fixture["paths"], snapshot_id, os.getuid(), str(deadline_path),
                snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                source_node_root=fixture["node_root"],
                source_anchors=((fixture["anchor"], os.getuid()),),
            )
        return snapshot_base, snapshot

    def _run_fifo_snapshot_child(self, kind, fixture, deadline_path, snapshot_base,
                                 snapshot_id, parent, trigger_count):
        context_name = "fork" if "fork" in multiprocessing.get_all_start_methods() else "spawn"
        context = multiprocessing.get_context(context_name)
        receiver, sender = context.Pipe(duplex=False)
        metadata = Path(parent).stat()
        process = context.Process(
            target=_fifo_snapshot_child,
            args=(kind, fixture, str(deadline_path), str(snapshot_base), snapshot_id,
                  metadata.st_dev, metadata.st_ino, trigger_count, sender),
        )
        process.start()
        sender.close()
        try:
            if not receiver.poll(3):
                if process.is_alive():
                    process.terminate()
                    process.join(0.25)
                if process.is_alive():
                    process.kill()
                    process.join(1)
                self.fail("FIFO race child exceeded its bounded wait")
            result = receiver.recv()
            process.join(1)
            if process.is_alive():
                process.kill()
                process.join(1)
                self.fail("FIFO race child did not exit after reporting")
            self.assertEqual(process.exitcode, 0)
            return result
        finally:
            receiver.close()

    def _rewrite_snapshot_manifest_for_fixture(self, snapshot_root, deadline_path):
        root = Path(snapshot_root)
        root.chmod(0o700)
        root_fd = os.open(root, os.O_RDONLY | node_tool_snapshot._O_DIRECTORY
                          | node_tool_snapshot._O_NOFOLLOW)
        try:
            manifest = json.loads((root / node_tool_snapshot.MANIFEST_NAME).read_text(encoding="utf-8"))
            rows = []
            totals = {"entries": 0, "bytes": 0, "manifest_rows_bytes": 0}
            node_tool_snapshot._snapshot_entries(
                root_fd, "", str(deadline_path), rows, totals, os.getuid(),
            )
            rows.sort(key=lambda row: row["path"])
            core = {key: value for key, value in manifest.items() if key != "content_sha256"}
            core["entries"] = rows
            core["entry_count"] = totals["entries"]
            core["expanded_bytes"] = totals["bytes"]
            rewritten = dict(core)
            rewritten["content_sha256"] = node_tool_snapshot._entry_digest(core)
            payload = supervisor.bundle.canonical_json(rewritten) + b"\n"
            os.unlink(node_tool_snapshot.MANIFEST_NAME, dir_fd=root_fd)
            descriptor = os.open(
                node_tool_snapshot.MANIFEST_NAME,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | node_tool_snapshot._O_NOFOLLOW,
                0o444, dir_fd=root_fd,
            )
            try:
                view = memoryview(payload)
                while view:
                    count = os.write(descriptor, view)
                    view = view[count:]
                os.fchmod(descriptor, 0o444)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fchmod(root_fd, 0o555)
        finally:
            os.close(root_fd)

    @contextlib.contextmanager
    def _forbid_external_canary_open(self, canary):
        canary = Path(canary).absolute()
        canary_stat = canary.stat()
        parent_stat = canary.parent.stat()
        attempts = []
        real_os_open = os.open
        real_builtin_open = builtins.open
        real_io_open = io.open

        def matches(path, directory_fd=None):
            try:
                decoded = os.fsdecode(path)
                if directory_fd is not None:
                    parent = os.fstat(directory_fd)
                    if ((parent.st_dev, parent.st_ino) == (parent_stat.st_dev, parent_stat.st_ino)
                            and decoded == canary.name):
                        return True
                candidate = Path(decoded)
                if not candidate.is_absolute():
                    candidate = Path.cwd() / candidate
                return candidate.resolve(strict=False) == canary
            except (OSError, TypeError, ValueError):
                return False

        def guarded_os_open(path, flags, *args, **kwargs):
            if matches(path, kwargs.get("dir_fd")):
                attempts.append("os.open")
                raise AssertionError("control attempted to open the external canary")
            descriptor = real_os_open(path, flags, *args, **kwargs)
            try:
                opened = os.fstat(descriptor)
                if (opened.st_dev, opened.st_ino) == (canary_stat.st_dev, canary_stat.st_ino):
                    attempts.append("os.open")
                    os.close(descriptor)
                    raise AssertionError("control opened the external canary")
            except OSError:
                pass
            return descriptor

        def guarded_io_open(file, *args, **kwargs):
            if matches(file):
                attempts.append("io.open")
                raise AssertionError("control attempted to read the external canary")
            return real_io_open(file, *args, **kwargs)

        def guarded_builtin_open(file, *args, **kwargs):
            if matches(file):
                attempts.append("builtins.open")
                raise AssertionError("control attempted to read the external canary")
            return real_builtin_open(file, *args, **kwargs)

        with patch.object(os, "open", side_effect=guarded_os_open), \
                patch.object(io, "open", side_effect=guarded_io_open), \
                patch.object(builtins, "open", side_effect=guarded_builtin_open):
            yield attempts

    def test_harness_parses_complete_producer_shaped_rust_summary(self):
        payload = self._summary_payload(self._coverage_rows())
        records = test_e2e._summary_records(payload, self._summary_scenario())
        self.assertEqual({row["suite"] for row in records if row["kind"] == "coverage"},
                         set(rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"]))

    def test_harness_rejects_every_incomplete_or_nonpassing_rust_summary_shape(self):
        rows = self._coverage_rows()
        mutations = {
            "missing-suite": rows[:-1],
            "extra-suite": rows + [{
                "kind": "coverage", "stage": "unit", "suite": "unexpected-suite",
                "total": 1, "passed": 1, "failed": 0, "ignored": 0,
            }],
            "duplicate-suite": rows + [dict(rows[0]), {
                "kind": "control", "stage": "unit", "status": "fail", "code": "DEVLANE_FAILURE",
            }],
            "skipped-suite": rows + [{
                "kind": "control", "stage": "unit", "status": "skip",
            }],
            "failure-record-in-pass-summary": rows + [{
                "kind": "test", "stage": "unit",
                "test": next(iter(test_e2e.RUST_FIXTURE_TESTS.values())),
            }],
            "invalid-counts": [dict(rows[0], ignored=1)] + rows[1:],
            "invalid-total-type": [dict(rows[0], total=True)] + rows[1:],
        }
        for label, changed in mutations.items():
            with self.subTest(label=label):
                try:
                    payload = self._summary_payload(changed)
                except output_filter.FilterRefusal:
                    continue
                with self.assertRaises((RuntimeError, output_filter.FilterRefusal)):
                    test_e2e._summary_records(payload, self._summary_scenario())

    def test_preparation_cli_reports_only_finite_codes_classes_and_parser_failures(self):
        for code in diagnostic_contract.PREPARATION_REFUSAL_CODES:
            if code == "cleanup-incomplete":
                continue
            line = ("dependency_preparation_refusal=stage=prepare-node-toolchain-validation "
                    "code=" + code + " cleanup=confirmed\n").encode("ascii")
            self.assertEqual(
                diagnostic_contract.parse_preparation_result(2, b"", line),
                ("prepare-node-toolchain-validation", code, "confirmed"),
            )
        for reason in diagnostic_contract.CLEANUP_SUBREASONS:
            line = ("dependency_preparation_refusal=stage=prepare-cleanup "
                    "code=cleanup-incomplete cleanup=unconfirmed reason=" + reason + "\n").encode("ascii")
            self.assertEqual(
                diagnostic_contract.parse_preparation_result(2, b"", line),
                ("prepare-cleanup", "cleanup-incomplete", "unconfirmed", reason),
            )
            exception_line = ("dependency_preparation_exception=stage=prepare-cleanup "
                              "class=os-error cleanup=unconfirmed reason=" + reason + "\n").encode("ascii")
            self.assertEqual(
                diagnostic_contract.parse_preparation_result(2, b"", exception_line),
                ("prepare-cleanup", "prepare-os-error", "unconfirmed", reason),
            )
        for label in diagnostic_contract.PREPARATION_EXCEPTION_LABELS:
            line = ("dependency_preparation_exception=stage=prepare-node-version-verification "
                    "class=" + label + " cleanup=not-needed\n").encode("ascii")
            self.assertEqual(
                diagnostic_contract.parse_preparation_result(2, b"", line),
                ("prepare-node-version-verification", "prepare-" + label, "not-needed"),
            )
        self.assertIsNone(diagnostic_contract.parse_preparation_result(
            0, b"dependency_preparation=complete\n", b"",
        ))
        negative = (
            (2, b"", b"usage: prepare.py --projection private-path\n"),
            (2, b"unexpected", b"dependency_preparation_refusal=stage=prepare-node-toolchain-validation "
             b"code=node-toolchain-owner cleanup=not-needed\n"),
            (2, b"", b"dependency_preparation_refusal=stage=prepare-node-toolchain-validation "
             b"code=unknown-private-code cleanup=not-needed\n"),
            (2, b"", b"dependency_preparation_exception=stage=prepare-node-toolchain-validation "
             b"class=UnknownPrivateError cleanup=not-needed\n"),
            (2, b"", b"dependency_preparation_refusal=stage=private-path "
             b"code=node-toolchain-owner cleanup=not-needed\n"),
            (2, b"", b"dependency_preparation_refusal=stage=prepare-node-toolchain-validation "
             b"code=node-toolchain-owner cleanup=not-needed\nprivate-path\n"),
            (0, b"dependency_preparation=complete\nprivate-canary\n", b""),
            (2, b"", b"dependency_preparation_refusal=stage=prepare-node-toolchain-validation "
             b"code=node-toolchain-owner cleanup=unconfirmed\n" * 80),
            (2, b"", b"dependency_preparation_refusal=stage=prepare-cleanup "
             b"code=cleanup-incomplete cleanup=unconfirmed\n"),
            (2, b"", b"dependency_preparation_refusal=stage=prepare-cleanup "
             b"code=cleanup-incomplete cleanup=confirmed reason=umount-busy\n"),
            (2, b"", b"dependency_preparation_refusal=stage=prepare-cleanup "
             b"code=cleanup-incomplete cleanup=unconfirmed reason=private-path\n"),
            (2, b"", b"dependency_preparation_exception=stage=prepare-cleanup "
             b"class=os-error cleanup=confirmed reason=tree-remove\n"),
            (1, b"", b"sudo: private-runner-path\n"),
        )
        for returncode, stdout, stderr in negative:
            with self.subTest(returncode=returncode, stderr=stderr[:40]):
                parsed = diagnostic_contract.parse_preparation_result(returncode, stdout, stderr)
                self.assertIsNotNone(parsed)
                self.assertIn(parsed[1], diagnostic_contract.PREPARATION_E2E_CATEGORIES)
                self.assertNotIn("private-path", parsed[1])
                self.assertNotIn("private-canary", parsed[1])

    def test_node_snapshot_manifest_refusal_sites_are_closed_and_publicly_reportable(self):
        source = Path(node_tool_snapshot.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        sites = {
            node.args[0].value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "_manifest_invalid"
            and node.args and isinstance(node.args[0], ast.Constant)
        }
        expected_sites = node_tool_snapshot.MANIFEST_INVALID_SITES - {"unlisted-site"}
        self.assertEqual(sites, expected_sites)
        self.assertFalse(public_audit.REFUSAL_LINE.fullmatch(
            "devlane_supervisor_refusal=node-snapshot-manifest-invalid:private-site",
        ))
        for site in node_tool_snapshot.MANIFEST_INVALID_SITES:
            code = "node-snapshot-manifest-invalid:" + site
            line = ("dependency_preparation_refusal=stage=prepare-node-toolchain-snapshot "
                    "code=" + code + " cleanup=not-needed\n").encode("ascii")
            self.assertEqual(
                diagnostic_contract.parse_preparation_result(2, b"", line),
                ("prepare-node-toolchain-snapshot", code, "not-needed"),
            )
            public_line = (
                "devlane_production_e2e=refused stage=prepare-node-toolchain-snapshot "
                "exception=" + code
            )
            self.assertTrue(diagnostic_contract.public_preparation_diagnostic(public_line))
            self.assertTrue(public_audit.REFUSAL_LINE.fullmatch(
                "devlane_supervisor_refusal=" + code,
            ))
            with patch.object(test_e2e, "_process_run", return_value=subprocess.CompletedProcess(
                    ["prepare.py"], 2, b"", line)):
                with self.assertRaises(test_e2e.PreparationRefusalMismatch) as caught:
                    test_e2e._run_preparation(["prepare.py"])
            self.assertEqual(caught.exception.category, code)
            state = test_e2e._DiagnosticState()
            state.capture("scenario-dependency-prepare", caught.exception)
            self.assertEqual(
                state.refusal_line(caught.exception),
                "devlane_production_e2e=refused stage=prepare-node-toolchain-snapshot "
                "exception=" + code,
            )

    def test_preparation_diagnostic_allowlists_cover_the_actual_validator_call_graph(self):
        root = Path(__file__).resolve().parents[2] / "kit/devlane"
        preparation = supervisor.node_tool_prepare

        def result_strings(expression):
            if isinstance(expression, ast.Constant) and type(expression.value) is str:
                return {expression.value}
            if isinstance(expression, ast.IfExp):
                return result_strings(expression.body) | result_strings(expression.orelse)
            return set()

        def functions(filename):
            tree = ast.parse((root / filename).read_text(encoding="utf-8"))
            return {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}

        prepare_functions = functions("prepare.py")
        direct_codes = set()
        stages = set()
        for function in prepare_functions.values():
            for node in ast.walk(function):
                if isinstance(node, ast.Call) and node.args:
                    name = node.func.id if isinstance(node.func, ast.Name) else (
                        node.func.attr if isinstance(node.func, ast.Attribute) else ""
                    )
                    if name in ("refuse", "_node_refuse"):
                        direct_codes.update(result_strings(node.args[0]))
                    if name == "_set_preparation_stage":
                        stages.update(item.value for item in ast.walk(node.args[0])
                                      if isinstance(item, ast.Constant) and type(item.value) is str)

        fetch_functions = functions("fetch.py")
        bundle_functions = functions("bundle.py")
        queue = [
            (fetch_functions, "validate_projection"), (bundle_functions, "strict_json"),
            (bundle_functions, "_pairs_no_duplicates"),
        ]
        seen = set()
        reachable_codes = set()
        while queue:
            table, name = queue.pop()
            key = (id(table), name)
            if key in seen or name not in table:
                continue
            seen.add(key)
            function = table[name]
            local_calls = set()
            for node in ast.walk(function):
                if not isinstance(node, ast.Call):
                    continue
                called = node.func.id if isinstance(node.func, ast.Name) else (
                    node.func.attr if isinstance(node.func, ast.Attribute) else ""
                )
                if called in table:
                    local_calls.add(called)
                if called in ("_fail", "_refuse") and node.args:
                    reachable_codes.update(result_strings(node.args[0]))
                if called == "_validate_npm_dependency_map" and len(node.args) > 1:
                    reachable_codes.update(item.value for item in ast.walk(node.args[1])
                                           if isinstance(item, ast.Constant) and type(item.value) is str)
            queue.extend((table, called) for called in local_calls)

        reachable_codes.update(("deadline-file-invalid", "total-deadline-exhausted"))
        self.assertTrue(direct_codes <= diagnostic_contract.PREPARATION_REFUSAL_CODES,
                        sorted(direct_codes - diagnostic_contract.PREPARATION_REFUSAL_CODES))
        self.assertTrue(reachable_codes <= diagnostic_contract.PREPARATION_REFUSAL_CODES,
                        sorted(reachable_codes - diagnostic_contract.PREPARATION_REFUSAL_CODES))
        self.assertTrue(stages <= diagnostic_contract.PREPARATION_STAGES,
                        sorted(stages - diagnostic_contract.PREPARATION_STAGES))
        self.assertTrue(
            set(preparation._PREPARATION_EXCEPTION_CATEGORIES.values())
            <= diagnostic_contract.PREPARATION_EXCEPTION_LABELS,
        )

    def test_preparation_cli_parser_refusal_has_no_argparse_text(self):
        preparation = supervisor.node_tool_prepare
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = preparation.main([])
        self.assertEqual(result, 2)
        self.assertEqual(
            stderr.getvalue(),
            "dependency_preparation_refusal=stage=prepare-argument-parse "
            "code=preparation-parser-refusal cleanup=not-needed\n",
        )

    def test_prepare_main_emits_each_allowlisted_refusal_and_exact_exception_without_reflection(self):
        preparation = supervisor.node_tool_prepare
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            projection_path = root / "projection.json"
            projection_path.write_bytes(b"synthetic projection placeholder")
            deadline_path = root / "deadline.json"
            deadline_budget.create(deadline_path, 1800, 10, 1810)
            arguments = [
                "--projection", str(projection_path), "--output", str(root / "prepared"),
                "--profile", "core-node", "--owner-uid", str(os.getuid()),
                "--owner-gid", str(os.getgid()), "--deadline-file", str(deadline_path),
            ]

            for code in sorted(diagnostic_contract.PREPARATION_REFUSAL_CODES):
                if code == "cleanup-incomplete":
                    continue
                with self.subTest(code=code):
                    stderr = io.StringIO()
                    with patch.object(preparation.sys, "platform", "linux"), \
                            patch.object(preparation.os, "geteuid", return_value=0), \
                            patch.object(preparation.fetch, "validate_projection",
                                         side_effect=supervisor.bundle.Refusal(code)), \
                            contextlib.redirect_stdout(io.StringIO()), \
                            contextlib.redirect_stderr(stderr):
                        self.assertEqual(preparation.main(arguments), 2)
                    expected = (
                        "dependency_preparation_refusal=stage=prepare-projection-validation "
                        "code=" + code + " cleanup=not-needed\n"
                    )
                    self.assertEqual(stderr.getvalue(), expected)
                    self.assertEqual(
                        diagnostic_contract.parse_preparation_result(2, b"", stderr.getvalue().encode("ascii")),
                        ("prepare-projection-validation", code, "not-needed"),
                    )

            def exception_for(exception_type):
                private = "private-path KEYCANARY-73A10X"
                if exception_type is json.JSONDecodeError:
                    return exception_type(private, "synthetic", 0)
                if exception_type is UnicodeDecodeError:
                    return exception_type("ascii", b"x", 0, 1, private)
                if exception_type is subprocess.TimeoutExpired:
                    return exception_type([private], 1)
                if exception_type is subprocess.CalledProcessError:
                    return exception_type(7, [private])
                return exception_type(private)

            for exception_type, label in preparation._PREPARATION_EXCEPTION_CATEGORIES.items():
                with self.subTest(exception=exception_type.__name__):
                    stderr = io.StringIO()
                    with patch.object(preparation.sys, "platform", "linux"), \
                            patch.object(preparation.os, "geteuid", return_value=0), \
                            patch.object(preparation.fetch, "validate_projection",
                                         side_effect=exception_for(exception_type)), \
                            contextlib.redirect_stdout(io.StringIO()), \
                            contextlib.redirect_stderr(stderr):
                        self.assertEqual(preparation.main(arguments), 2)
                    expected = (
                        "dependency_preparation_exception=stage=prepare-projection-validation "
                        "class=" + label + " cleanup=not-needed\n"
                    )
                    self.assertEqual(stderr.getvalue(), expected)
                    self.assertNotIn("private-path", stderr.getvalue())
                    self.assertNotIn("KEYCANARY-73A10X", stderr.getvalue())
                    self.assertEqual(
                        diagnostic_contract.parse_preparation_result(2, b"", stderr.getvalue().encode("ascii")),
                        ("prepare-projection-validation", "prepare-" + label, "not-needed"),
                    )

            stderr = io.StringIO()
            with patch.object(preparation.sys, "platform", "linux"), \
                    patch.object(preparation.os, "geteuid", return_value=0), \
                    patch.object(preparation.fetch, "validate_projection",
                                 side_effect=RuntimeError("private-path KEYCANARY-73A10X")), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
                self.assertEqual(preparation.main(arguments), 2)
            self.assertEqual(
                stderr.getvalue(),
                "dependency_preparation_exception=stage=prepare-projection-validation "
                "class=runtime-error cleanup=not-needed\n",
            )
            self.assertNotIn("private-path", stderr.getvalue())
            self.assertNotIn("KEYCANARY-73A10X", stderr.getvalue())

    def test_harness_preserves_preparation_stage_and_cleanup_state_without_output_reflection(self):
        state = test_e2e._DiagnosticState()
        mismatch = test_e2e.PreparationRefusalMismatch(
            "prepare-node-toolchain-validation", "node-toolchain-owner", "unconfirmed",
        )
        state.capture("scenario-dependency-prepare", mismatch)
        line = state.refusal_line(RuntimeError("private path KEYCANARY-73A10X"))
        self.assertEqual(
            line,
            "devlane_production_e2e=refused stage=prepare-node-toolchain-validation "
            "exception=node-toolchain-owner cleanup=unconfirmed",
        )
        self.assertTrue(diagnostic_contract.public_preparation_diagnostic(line))
        self.assertNotIn("private path", line)
        self.assertNotIn("KEYCANARY-73A10X", line)

    def test_preparation_cleanup_subreason_is_bounded_and_public(self):
        for reason in diagnostic_contract.CLEANUP_SUBREASONS:
            payload = ("dependency_preparation_refusal=stage=prepare-cleanup "
                       "code=cleanup-incomplete cleanup=unconfirmed reason=" + reason + "\n").encode("ascii")
            with patch.object(test_e2e, "_process_run", return_value=subprocess.CompletedProcess(
                    ["prepare.py"], 2, b"", payload)):
                with self.assertRaises(test_e2e.PreparationRefusalMismatch) as caught:
                    test_e2e._run_preparation(["prepare.py"])
            state = test_e2e._DiagnosticState()
            state.capture("scenario-dependency-prepare", caught.exception)
            public_line = state.refusal_line(caught.exception)
            self.assertEqual(public_line, "devlane_production_e2e=refused stage=prepare-cleanup "
                             "exception=cleanup-incomplete reason=" + reason + " cleanup=unconfirmed")
            self.assertTrue(diagnostic_contract.public_preparation_diagnostic(public_line))

        with patch.object(test_e2e, "_process_run", return_value=subprocess.CompletedProcess(
                ["prepare.py"], 2, b"", b"dependency_preparation_exception=stage=prepare-protocol "
                b"class=unclassified cleanup=not-needed\n")):
            with self.assertRaises(test_e2e.PreparationRefusalMismatch) as caught:
                test_e2e._run_preparation(["prepare.py"])
        self.assertEqual(caught.exception.category, "prepare-unclassified")

        with patch.object(test_e2e, "_process_run", return_value=subprocess.CompletedProcess(
                ["prepare.py"], 2, b"", b"private path KEYCANARY-73A10X\n")):
            with self.assertRaises(test_e2e.PreparationRefusalMismatch) as caught:
                test_e2e._run_preparation(["prepare.py"])
        self.assertEqual(caught.exception.category, "preparation-output-canary")

    def test_preparation_diagnostic_report_file_is_private_write_once_and_allowlisted(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "diagnostic"
            state = test_e2e._DiagnosticState()
            error = test_e2e.PreparationRefusalMismatch(
                "prepare-node-toolchain-validation", "node-toolchain-owner",
            )
            state.capture("scenario-dependency-prepare", error)
            line = state.refusal_line(error)
            self.assertTrue(test_e2e._write_diagnostic_file(str(path), line))
            self.assertFalse(test_e2e._write_diagnostic_file(str(path), line))
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            with patch.object(diagnostic_contract, "MAX_PUBLIC_DIAGNOSTIC_BYTES", len(line)):
                self.assertEqual(test_e2e._read_reportable_diagnostic_file(str(path)), line)

            invalid_path = Path(temporary) / "invalid"
            invalid_path.write_text(
                "devlane_production_e2e=refused stage=prepare-node-toolchain-validation "
                "exception=private-path\n", encoding="ascii",
            )
            invalid_path.chmod(0o600)
            self.assertIsNone(test_e2e._read_reportable_diagnostic_file(str(invalid_path)))

    def test_failed_readonly_remount_keeps_the_successful_bind_mount_in_cleanup_set(self):
        preparation = supervisor.node_tool_prepare
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, target = root / "source", root / "target"
            source.mkdir()
            target.mkdir()
            calls = [
                subprocess.CompletedProcess(["mount"], 0),
                subprocess.CalledProcessError(32, ["mount"]),
            ]
            with patch.object(preparation, "MOUNT_TARGETS", []), \
                    patch.object(preparation, "_bounded_timeout", return_value=5), \
                    patch.object(preparation.subprocess, "run", side_effect=calls) as run:
                with self.assertRaises(subprocess.CalledProcessError):
                    preparation._mount(source, target)
                self.assertEqual(preparation.MOUNT_TARGETS, [target])
                self.assertEqual(run.call_count, 2)

    def test_startup_negative_requires_the_intended_projection_refusal(self):
        good = subprocess.CompletedProcess(
            ["supervisor.py", "start"], 2, b"",
            b"devlane_supervisor_refusal=projection-binding-mismatch\n",
        )
        self.assertIsNone(test_e2e._assert_startup_projection_refusal(good))

        refusals = test_e2e.STARTUP_REFUSAL_CODES - {"projection-binding-mismatch"}
        failures = [
            ("unexpected-success", subprocess.CompletedProcess(["supervisor.py", "start"], 0, b"", b""),
             "startup-unexpected-success"),
            ("exit-one", subprocess.CompletedProcess(["supervisor.py", "start"], 1, b"", b""),
             "startup-exit-one"),
            ("signal", subprocess.CompletedProcess(["supervisor.py", "start"], -9, b"", b""),
             "startup-exit-signal"),
            ("unexpected-exit", subprocess.CompletedProcess(["supervisor.py", "start"], 3, b"", b""),
             "startup-exit-unexpected"),
            ("parser", subprocess.CompletedProcess(["supervisor.py", "start"], 2, b"",
             b"usage: supervisor.py start --deadline-file DEADLINE_FILE\n"), "startup-parser-refusal"),
            ("import", subprocess.CompletedProcess(["supervisor.py", "start"], 1, b"",
             b"Traceback (most recent call last):\nModuleNotFoundError: private-path\n"),
             "startup-import-failure"),
            ("traceback", subprocess.CompletedProcess(["supervisor.py", "start"], 1, b"",
             b"Traceback (most recent call last):\nRuntimeError: private-canary\n"), "startup-traceback"),
            ("stdout", subprocess.CompletedProcess(["supervisor.py", "start"], 2, b"private-path", b""),
             "startup-stdout-unexpected"),
            ("canary", subprocess.CompletedProcess(["supervisor.py", "start"], 2, b"",
             b"devlane_supervisor_refusal=KEYCANARY-73A10X\n"), "startup-output-canary"),
            ("empty-stderr", subprocess.CompletedProcess(["supervisor.py", "start"], 2, b"", b""),
             "startup-stderr-empty"),
            ("malformed-stderr", subprocess.CompletedProcess(["supervisor.py", "start"], 2, b"",
             b"private path and raw diagnostic\n"), "startup-stderr-invalid"),
            ("unknown-refusal", subprocess.CompletedProcess(["supervisor.py", "start"], 2, b"",
             b"devlane_supervisor_refusal=unknown-private-code\n"), "startup-refusal-unlisted"),
        ]
        failures.extend(
            (code, subprocess.CompletedProcess(["supervisor.py", "start"], 2, b"",
             ("devlane_supervisor_refusal=" + code + "\n").encode("ascii")), code)
            for code in sorted(refusals)
        )
        for name, result, category in failures:
            with self.subTest(result=name):
                with self.assertRaises(test_e2e.StartupRefusalMismatch) as caught:
                    test_e2e._assert_startup_projection_refusal(result)
                self.assertEqual(caught.exception.category, category)
                state = test_e2e._DiagnosticState()
                state.capture("variant-startup-refusal-check", caught.exception)
                line = state.refusal_line(caught.exception)
                self.assertRegex(line, r"stage=variant-startup-refusal-check exception=[a-z0-9-]{1,48}(?::[a-z0-9-]{1,48}){0,2}$")
                for marker in ("private-path", "private-canary", "KEYCANARY-73A10X", "unknown-private-code"):
                    self.assertNotIn(marker, line)

    def test_positive_supervisor_status_and_refusal_results_are_finite(self):
        passing = (
            (test_e2e._assert_supervisor_start_ready, b"offline_supervisor=ready\n"),
            (test_e2e._assert_supervisor_probe_pass, b"network_cut_probe=pass\n"),
            (test_e2e._assert_supervisor_decrypt_pass, b"authenticated_decryption=pass\n"),
        )
        for check, marker in passing:
            with self.subTest(success=marker):
                result = subprocess.CompletedProcess(["supervisor.py"], 0, marker, b"")
                self.assertIsNone(check(result))

        errors = (
            (subprocess.CompletedProcess(["supervisor.py"], 0, b"", b""), "startup-success-output-missing"),
            (subprocess.CompletedProcess(["supervisor.py"], 0, b"wrong marker", b""),
             "startup-success-output-invalid"),
            (subprocess.CompletedProcess(["supervisor.py"], 0, b"offline_supervisor=ready\n", b"private path"),
             "startup-success-stderr"),
            (subprocess.CompletedProcess(["supervisor.py"], 1, b"", b""), "startup-exit-one"),
            (subprocess.CompletedProcess(["supervisor.py"], -9, b"", b""), "startup-exit-signal"),
            (subprocess.CompletedProcess(["supervisor.py"], 3, b"", b""), "startup-exit-unexpected"),
            (subprocess.CompletedProcess(["supervisor.py"], 2, b"", b""), "startup-stderr-empty"),
            (subprocess.CompletedProcess(["supervisor.py"], 2, b"", b"private diagnostic\n"),
             "startup-stderr-invalid"),
            (subprocess.CompletedProcess(["supervisor.py"], 2, b"unexpected", b""),
             "startup-stdout-unexpected"),
            (subprocess.CompletedProcess(["supervisor.py"], 2, b"", b"devlane_supervisor_refusal=KEYCANARY-73A10X\n"),
             "startup-output-canary"),
            (subprocess.CompletedProcess(["supervisor.py"], 2, b"", b"usage: supervisor.py start\n"),
             "startup-parser-refusal"),
            (subprocess.CompletedProcess(["supervisor.py"], 1, b"",
             b"Traceback (most recent call last):\nModuleNotFoundError: private path\n"),
             "startup-import-failure"),
            (subprocess.CompletedProcess(["supervisor.py"], 1, b"",
             b"Traceback (most recent call last):\nRuntimeError: private path\n"), "startup-traceback"),
            (subprocess.CompletedProcess(["supervisor.py"], 2, b"",
             b"devlane_supervisor_refusal=unknown-private-code\n"), "startup-refusal-unlisted"),
        )
        refusals = sorted(test_e2e.SUPERVISOR_REFUSAL_CODES)
        for code in refusals:
            errors += ((subprocess.CompletedProcess(
                ["supervisor.py"], 2, b"", ("devlane_supervisor_refusal=" + code + "\n").encode("ascii"),
            ), code),)

        for result, category in errors:
            with self.subTest(category=category):
                with self.assertRaises(test_e2e.StartupRefusalMismatch) as caught:
                    test_e2e._assert_supervisor_start_ready(result)
                self.assertEqual(caught.exception.category,
                                 test_e2e._REFUSAL_CATEGORY_ALIASES.get(category, category))
                if category in test_e2e.SUPERVISOR_REFUSAL_CODES:
                    self.assertEqual(caught.exception.refusal_code, category)
                state = test_e2e._DiagnosticState()
                state.capture("variant-supervisor-start-check", caught.exception)
                line = state.refusal_line(caught.exception)
                self.assertRegex(line, r"stage=variant-supervisor-start-check exception=[a-z0-9-]{1,48}(?::[a-z0-9-]{1,48}){0,2}$")
                for marker in ("private path", "private diagnostic", "KEYCANARY-73A10X", "unknown-private-code"):
                    self.assertNotIn(marker, line)

    def test_supervisor_refusal_registry_covers_literal_production_refusals(self):
        source = Path(supervisor.__file__).read_text(encoding="utf-8")
        tree = ast.parse(source)
        literal_codes = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not node.args:
                continue
            function = node.func
            name = function.id if isinstance(function, ast.Name) else (
                function.attr if isinstance(function, ast.Attribute) else ""
            )
            if name not in ("_refuse", "SupervisorRefusal"):
                continue
            value = node.args[0]
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                literal_codes.add(value.value)
        self.assertTrue(literal_codes)
        self.assertLessEqual(literal_codes, supervisor.REFUSAL_CODES)
        self.assertLessEqual(supervisor.STARTUP_REFUSAL_CODES, supervisor.REFUSAL_CODES)
        self.assertTrue(supervisor.STARTUP_DIAGNOSTIC_CODES)
        self.assertTrue(all(re.fullmatch(r"child-[a-z0-9-]{1,26}", code)
                            and len(code) <= 32 for code in supervisor.STARTUP_DIAGNOSTIC_CODES))

    def test_actual_supervisor_start_parser_requires_deadline_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self._write_projection_startup_fixture(root)
            command = ["start"]
            for name in ("state_dir", "context", "workspace", "prepared", "bundle", "projection",
                         "positive_control"):
                command.extend(("--" + name.replace("_", "-"), getattr(args, name)))
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                with self.assertRaises(SystemExit) as caught:
                    supervisor.main(command)
            self.assertEqual(caught.exception.code, 2)
            self.assertIn("--deadline-file", stderr.getvalue())
            self.assertFalse(Path(args.state_dir).exists())

    def test_actual_supervisor_startup_exceptions_keep_finite_child_stage_and_class(self):
        known = (
            ("firewall", RuntimeError("private path and canary"), "child-firewall-runtime"),
            ("tools", PermissionError("private path"), "child-tools-permission"),
            ("versions", FileNotFoundError("private path"), "child-versions-file-missing"),
            ("profile", TypeError("private path"), "child-profile-type"),
            ("ready", ValueError("private path"), "child-ready-value"),
        )
        for phase, error, code in known:
            with self.subTest(phase=phase, code=code):
                self.assertEqual(supervisor._startup_exception_code(phase, error), code)
                self.assertIn(code, supervisor.STARTUP_DIAGNOSTIC_CODES)
                self.assertLessEqual(len(code), 32)
        self.assertEqual(supervisor._startup_exception_code("not-a-phase", RuntimeError("private")),
                         "child-serve-runtime")
        self.assertEqual(supervisor._startup_exception_code("tools", Exception("private")),
                         "child-tools-unclassified")
        for phase in supervisor.STARTUP_DIAGNOSTIC_PHASES:
            for exception_type, label in supervisor._STARTUP_EXCEPTION_LABELS.items():
                if exception_type is subprocess.TimeoutExpired:
                    error = exception_type("source-free", 1)
                elif exception_type is subprocess.CalledProcessError:
                    error = exception_type(1, "source-free")
                elif exception_type is UnicodeDecodeError:
                    error = exception_type("ascii", b"source-free", 0, 1, "fixture")
                elif exception_type is json.JSONDecodeError:
                    error = exception_type("source-free", "fixture", 0)
                else:
                    error = exception_type("source-free")
                code = supervisor._startup_exception_code(phase, error)
                self.assertEqual(code, "child-" + phase + "-" + label)
                self.assertIn(code, supervisor.STARTUP_DIAGNOSTIC_CODES)
                self.assertLessEqual(len(code), 32)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            state = root / "state"
            state.mkdir(mode=0o700)
            args = ["_serve", "--state-dir", str(state), "--context", str(root / "context"),
                    "--workspace", str(root), "--prepared", str(root), "--bundle", str(root / "bundle"),
                    "--projection", str(root / "projection"), "--deadline-file", str(root / "deadline"),
                    "--host-net-inode", "193847", "--owner-uid", str(os.getuid())]

            class FailingService:
                startup_phase = "firewall"

                def prepare(self):
                    raise RuntimeError("private path KEYCANARY-73A10X")

                def _cleanup(self):
                    return None

            with patch.object(supervisor, "Service", return_value=FailingService()), \
                    patch.object(supervisor, "_kill_workload_descendants"), \
                    patch.object(supervisor, "_signal_workload_descendants"), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                result = supervisor.main(args)
            receipt = (state / supervisor.STARTUP_REFUSAL_NAME).read_bytes()
            self.assertEqual(result, 2)
            self.assertEqual(receipt, b'{"code":"child-firewall-runtime"}')
            self.assertNotIn(b"private path", receipt)
            self.assertNotIn(b"KEYCANARY-73A10X", receipt)

    def test_actual_supervisor_parent_maps_only_allowlisted_child_start_receipts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self._write_projection_startup_fixture(root)
            projection, _payload = test_e2e._node_projection(
                test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
            )
            self._bind_projection_payload(args, projection)
            command = ["start"]
            for name in ("state_dir", "context", "workspace", "prepared", "bundle", "projection",
                         "positive_control", "deadline_file"):
                command.extend(("--" + name.replace("_", "-"), getattr(args, name)))
            command.extend(("--node-snapshot-id", "test-parent-refusal"))
            real_stat = os.stat

            def stat_with_control_namespace(path, *positional, **keywords):
                if os.fspath(path) == "/proc/self/ns/net":
                    return SimpleNamespace(st_ino=193847)
                return real_stat(path, *positional, **keywords)

            for receipt_code, expected in (
                ("child-firewall-runtime", "child-firewall-runtime"),
                ("node-toolchain-version", "node-toolchain-version"),
                ("private-path-and-key", "supervisor-start-failed"),
            ):
                with self.subTest(receipt=receipt_code):
                    state = Path(args.state_dir)
                    state.mkdir(mode=0o700)

                    def fake_spawn(argv, **_kwargs):
                        child_state = Path(argv[argv.index("--state-dir") + 1])
                        (child_state / supervisor.STARTUP_REFUSAL_NAME).write_text(
                            json.dumps({"code": receipt_code}), encoding="ascii",
                        )
                        return SimpleNamespace(pid=48124, poll=lambda: 0)

                    stdout, stderr = io.StringIO(), io.StringIO()
                    with patch.object(supervisor.sys, "platform", "linux"), \
                            patch.object(supervisor.os, "stat", side_effect=stat_with_control_namespace), \
                            patch.object(supervisor.subprocess, "Popen", side_effect=fake_spawn), \
                            contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                        result_code = supervisor.main(command)
                    result = subprocess.CompletedProcess(
                        ["supervisor.py", *command], result_code,
                        stdout.getvalue().encode(), stderr.getvalue().encode(),
                    )
                    with self.assertRaises(test_e2e.StartupRefusalMismatch) as caught:
                        test_e2e._assert_supervisor_start_ready(result)
                    self.assertEqual(caught.exception.category, expected)
                    self.assertNotIn("private-path-and-key", stderr.getvalue())
                    self.assertFalse((state / supervisor.PID_NAME).exists())
                    self.assertFalse((state / supervisor.STARTUP_REFUSAL_NAME).is_symlink())
                    (state / supervisor.STARTUP_REFUSAL_NAME).unlink()
                    state.rmdir()

    def test_actual_positive_supervisor_parent_launch_uses_the_fixed_ready_receipt(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self._write_projection_startup_fixture(root)
            projection, _payload = test_e2e._node_projection(
                test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
            )
            self._bind_projection_payload(args, projection)
            context = json.loads(Path(args.context).read_text(encoding="ascii")); context["wave_class"] = test_e2e.fetch.SOURCE_FREE_WAVE_CLASS; Path(args.context).write_bytes(test_e2e.bundle.canonical_json(context) + b"\n")
            diagnostic_path = root / "devlane-vitest-local-synthetic-node-accept.json"
            command = ["start"]
            for name in ("state_dir", "context", "workspace", "prepared", "bundle", "projection",
                         "positive_control", "deadline_file"):
                command.extend(("--" + name.replace("_", "-"), getattr(args, name)))
            command.extend(("--node-snapshot-id", "test-parent-ready", "--failure-diagnostics-file", str(diagnostic_path)))
            spawned = []

            def fake_spawn(argv, **kwargs):
                spawned.append((argv, kwargs))
                state = Path(argv[argv.index("--state-dir") + 1])
                (state / supervisor.READY_NAME).write_text('{"ready":true}', encoding="ascii")
                return SimpleNamespace(pid=48123, poll=lambda: None)

            real_stat = os.stat

            def stat_with_control_namespace(path, *positional, **keywords):
                if os.fspath(path) == "/proc/self/ns/net":
                    return SimpleNamespace(st_ino=193847)
                return real_stat(path, *positional, **keywords)

            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.dict(os.environ, {"RUNNER_TEMP": str(root)}), \
                    patch.object(supervisor.sys, "platform", "linux"), \
                    patch.object(supervisor.os, "stat", side_effect=stat_with_control_namespace), \
                    patch.object(supervisor.subprocess, "Popen", side_effect=fake_spawn), \
                    contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                code = supervisor.main(command)
            result = subprocess.CompletedProcess(
                ["supervisor.py", *command], code, stdout.getvalue().encode(), stderr.getvalue().encode(),
            )
            self.assertIsNone(test_e2e._assert_supervisor_start_ready(result), stderr.getvalue())
            self.assertEqual(code, 0)
            self.assertEqual(len(spawned), 1)
            argv, options = spawned[0]
            self.assertEqual(argv[:11], "sudo -n --preserve-env=RUNNER_TEMP unshare --net --mount --pid --ipc --fork --mount-proc --kill-child".split())
            self.assertEqual(argv[11:14], [sys.executable, str(Path(supervisor.__file__).resolve()), "_serve"])
            self.assertEqual(argv[argv.index("--deadline-file") + 1], str(Path(args.deadline_file).resolve()))
            self.assertEqual(argv[argv.index("--node-snapshot-id") + 1], "test-parent-ready")
            self.assertEqual(argv[argv.index("--failure-diagnostics-file") + 1], str(diagnostic_path))
            self.assertNotIn("--node-path", argv)
            self.assertNotIn("--npm-path", argv)
            self.assertEqual(options["stdin"], subprocess.DEVNULL)
            self.assertEqual(options["stdout"], subprocess.DEVNULL)
            self.assertEqual(options["stderr"], subprocess.DEVNULL)
            self.assertTrue(options["close_fds"])
            self.assertTrue(options["start_new_session"])
            self.assertEqual(options["env"], {
                "PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1",
                "RUNNER_TEMP": str(root.resolve()),
            })
            self.assertTrue(os.access(options["env"]["RUNNER_TEMP"], os.W_OK))

    def test_actual_service_prepare_positive_platform_seams_follow_validated_projection(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self._write_projection_startup_fixture(root)
            node_fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            snapshot_id = "test-service-positive"
            snapshot_base, snapshot = self._create_node_snapshot(
                node_fixture, root / "snapshot-base", snapshot_id, args.deadline_file,
            )
            projection, _payload = test_e2e._node_projection(
                test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
            )
            self._bind_projection_payload(args, projection)
            previous_deadline_file = supervisor.ACTIVE_DEADLINE_FILE
            real_run = subprocess.run
            version_calls = []
            events = []

            def record(name, value=None):
                def call(*_args, **_kwargs):
                    events.append(name)
                    return value
                return call

            def recording_run(argv, **kwargs):
                version_calls.append((list(argv), dict(kwargs)))
                return real_run(argv, **kwargs)

            try:
                service = supervisor.Service(
                    args.state_dir, args.context, args.workspace, args.prepared, args.bundle,
                    args.projection, 193847, os.getuid(),
                    {"node_snapshot_id": snapshot_id, "cargo": "", "rustc": ""},
                    args.deadline_file,
                )
                with patch.object(node_tool_snapshot, "DEFAULT_SNAPSHOT_BASE", snapshot_base), \
                        patch.dict(os.environ, {"PATH": "/ambient-poison", "NODE_OPTIONS": "--require ignored",
                                                "NPM_CONFIG_USERCONFIG": "/ambient-poison/npmrc"}), \
                        patch.object(supervisor, "_require_linux_root", side_effect=record("root")), \
                        patch.object(supervisor, "_require_swap_disabled", side_effect=record("swap")), \
                        patch.object(supervisor, "_mount_private", side_effect=record("private-mount")), \
                        patch.object(supervisor, "_configure_firewall", side_effect=record("firewall")), \
                        patch.object(supervisor, "_mount_minimal_root", side_effect=record("minimal-root")), \
                        patch.object(supervisor, "_mount_bind", side_effect=record("bundle-bind")), \
                        patch.object(supervisor, "_read_profiles", side_effect=record("profile-read", {"schema": 1})), \
                        patch.object(supervisor.subprocess, "run", side_effect=recording_run):
                    self.assertTrue(service.prepare())
                self.assertEqual(events, ["root", "swap", "private-mount", "firewall", "minimal-root",
                                          "bundle-bind", "bundle-bind", "profile-read"])
                self.assertEqual(service.projection_value, projection)
                self.assertEqual(service.startup_phase, "ready")
                self.assertEqual(service.tool_info["node_root"], snapshot["root"])
                self.assertEqual(supervisor._worker_environment("unit", service.root, service.tool_info)["PATH"],
                                 "/tools/node/bin:/usr/bin:/bin")
                snapshot_node = str(Path(snapshot["root"]) / "bin/node")
                snapshot_cli = str(Path(snapshot["root"]) / "lib/node_modules/npm/bin/npm-cli.js")
                expected_commands = [
                    [snapshot_node, "--version"],
                    [snapshot_node, snapshot_cli, "--version"],
                ] * 2
                self.assertEqual([call[0] for call in version_calls], expected_commands)
                for _argv, kwargs in version_calls:
                    self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
                fixture_rows = [json.loads(line) for line in node_fixture["log"].read_text().splitlines()]
                self.assertEqual([(row["executable"], row["argv"]) for row in fixture_rows], [
                    (snapshot_node, ["--version"]),
                    (snapshot_node, [snapshot_cli, "--version"]),
                    (snapshot_node, ["--version"]),
                    (snapshot_node, [snapshot_cli, "--version"]),
                ])
                self.assertTrue(all(row["path"] == "/usr/bin:/bin" for row in fixture_rows))
                self.assertTrue(all(row["node_options"] == "" and row["npm_userconfig"] == ""
                                    for row in fixture_rows))
            finally:
                supervisor.ACTIVE_DEADLINE_FILE = previous_deadline_file
                node_tool_snapshot.remove_snapshot(
                    snapshot_id, args.deadline_file, snapshot_base=snapshot_base, owner_uid=os.getuid(),
                )

    def test_node_preflight_uses_exact_node_for_resolved_npm_cli_without_ambient_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            deadline_path = root / "deadline.json"
            deadline_budget.create(deadline_path, 120, 10, 130)
            snapshot_id = "test-node-preflight"
            snapshot_base, snapshot = self._create_node_snapshot(
                fixture, root / "snapshot-base", snapshot_id, deadline_path,
            )
            poison = root / "ambient-poison"
            poison.mkdir()
            poison_node = poison / "node"
            poison_node.write_text(chr(35) + "!" + sys.executable + "\nraise SystemExit('ambient-node-ran')\n", encoding="utf-8")
            poison_node.chmod(0o755)
            projection = {"tools": {"node": "24.22.1", "npm": "11.19.1"}}
            real_run = subprocess.run
            calls = []

            def recording_run(argv, **kwargs):
                calls.append((list(argv), dict(kwargs)))
                return real_run(argv, **kwargs)

            previous_deadline_file = supervisor.ACTIVE_DEADLINE_FILE
            try:
                with patch.object(node_tool_snapshot, "DEFAULT_SNAPSHOT_BASE", snapshot_base), \
                    patch.object(supervisor, "ACTIVE_DEADLINE_FILE", str(deadline_path)), \
                    patch.object(supervisor.subprocess, "run", side_effect=recording_run), \
                    patch.dict(os.environ, {"PATH": str(poison), "NODE_OPTIONS": "--require ambient-canary",
                                            "NPM_CONFIG_USERCONFIG": str(poison / "npmrc")}):
                    info = supervisor._preflight_tools(
                        "core-node", projection,
                        {"node_snapshot_id": snapshot_id, "cargo": None, "rustc": None}, os.getuid(),
                    )
                snapshot_node = str(Path(snapshot["root"]) / "bin/node")
                snapshot_cli = str(Path(snapshot["root"]) / "lib/node_modules/npm/bin/npm-cli.js")
                self.assertEqual([argv for argv, _kwargs in calls], [
                    [snapshot_node, "--version"],
                    [snapshot_node, snapshot_cli, "--version"],
                ])
                for _argv, kwargs in calls:
                    self.assertEqual(kwargs["env"], {"PATH": "/usr/bin:/bin", "LC_ALL": "C"})
                self.assertEqual(info["node_root"], snapshot["root"])
                self.assertEqual(info["paths"]["npm"], str(Path(snapshot["root"]) / "bin/npm"))
                self.assertEqual(info["paths"]["npm_cli"], snapshot_cli)
                fixture_rows = [json.loads(line) for line in fixture["log"].read_text().splitlines()]
                self.assertEqual([(row["executable"], row["argv"]) for row in fixture_rows], [
                    (snapshot_node, ["--version"]),
                    (snapshot_node, [snapshot_cli, "--version"]),
                ])
                self.assertTrue(all(row["path"] == "/usr/bin:/bin" for row in fixture_rows))
                self.assertTrue(all(row["node_options"] == "" and row["npm_userconfig"] == ""
                                    for row in fixture_rows))
            finally:
                supervisor.ACTIVE_DEADLINE_FILE = previous_deadline_file
                node_tool_snapshot.remove_snapshot(
                    snapshot_id, str(deadline_path), snapshot_base=snapshot_base, owner_uid=os.getuid(),
                )

    def test_service_prepare_keeps_using_snapshot_after_source_permissions_change(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self._write_projection_startup_fixture(root)
            fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            snapshot_id = "test-service-source-change"
            snapshot_base, snapshot = self._create_node_snapshot(
                fixture, root / "snapshot-base", snapshot_id, args.deadline_file,
            )
            projection, _payload = test_e2e._node_projection(
                test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
            )
            self._bind_projection_payload(args, projection)
            previous_deadline_file = supervisor.ACTIVE_DEADLINE_FILE
            real_preflight = supervisor._preflight_tools
            real_run = subprocess.run
            calls = []

            def preflight_then_make_bin_untrusted(profile, value, paths, owner_uid):
                result = real_preflight(profile, value, paths, owner_uid)
                (fixture["node_root"] / "bin").chmod(0o777)
                return result

            def recording_run(argv, **kwargs):
                calls.append(list(argv))
                return real_run(argv, **kwargs)

            try:
                service = supervisor.Service(
                    args.state_dir, args.context, args.workspace, args.prepared, args.bundle,
                    args.projection, 193847, os.getuid(),
                    {"node_snapshot_id": snapshot_id, "cargo": "", "rustc": ""}, args.deadline_file,
                )
                with patch.object(node_tool_snapshot, "DEFAULT_SNAPSHOT_BASE", snapshot_base), \
                        patch.object(supervisor, "_require_linux_root"), \
                        patch.object(supervisor, "_require_swap_disabled"), \
                        patch.object(supervisor, "_mount_private"), \
                        patch.object(supervisor, "_configure_firewall"), \
                        patch.object(supervisor, "_mount_minimal_root"), \
                        patch.object(supervisor, "_mount_bind"), \
                        patch.object(supervisor, "_preflight_tools", side_effect=preflight_then_make_bin_untrusted), \
                        patch.object(supervisor, "_read_profiles", return_value={"schema": 1}), \
                        patch.object(supervisor.subprocess, "run", side_effect=recording_run):
                    self.assertTrue(service.prepare())
                snapshot_node = str(Path(snapshot["root"]) / "bin/node")
                snapshot_cli = str(Path(snapshot["root"]) / "lib/node_modules/npm/bin/npm-cli.js")
                self.assertEqual(calls, [
                    [snapshot_node, "--version"],
                    [snapshot_node, snapshot_cli, "--version"],
                    [snapshot_node, "--version"],
                    [snapshot_node, snapshot_cli, "--version"],
                ])
                fixture_rows = [json.loads(line) for line in fixture["log"].read_text().splitlines()]
                self.assertEqual(len(fixture_rows), 4)
                self.assertTrue(all(row["executable"] == snapshot_node for row in fixture_rows))
            finally:
                supervisor.ACTIVE_DEADLINE_FILE = previous_deadline_file
                (fixture["node_root"] / "bin").chmod(0o755)
                node_tool_snapshot.remove_snapshot(
                    snapshot_id, args.deadline_file, snapshot_base=snapshot_base, owner_uid=os.getuid(),
                )

    def test_prepare_node_version_path_executes_only_from_the_sealed_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            deadline_path = root / "deadline.json"
            deadline_budget.create(deadline_path, 60, 5, 65)
            snapshot_id = "test-npm-shebang"
            snapshot_base, snapshot = self._create_node_snapshot(
                fixture, root / "snapshot-base", snapshot_id, deadline_path,
            )
            snapshot_id = "test-prepare-version"
            snapshot_base, snapshot = self._create_node_snapshot(
                fixture, root / "snapshot-base", snapshot_id, deadline_path,
            )
            real_run = subprocess.run
            calls = []

            def recording_run(argv, **kwargs):
                calls.append((list(argv), dict(kwargs)))
                return real_run(argv, **kwargs)

            try:
                with patch.object(supervisor.node_tool_prepare, "DEADLINE_FILE", str(deadline_path)), \
                    patch.object(supervisor.subprocess, "run", side_effect=recording_run):
                    validated = node_tool_snapshot.validate_snapshot(
                        snapshot_id, str(deadline_path), snapshot_base=snapshot_base,
                        owner_uid=os.getuid(),
                    )
                    results = supervisor.node_tool_prepare.run_node_versions(
                        validated, supervisor.node_tool_prepare._prepare_node_version_process,
                    )
                snapshot_node = str(Path(snapshot["root"]) / "bin/node")
                snapshot_cli = str(Path(snapshot["root"]) / "lib/node_modules/npm/bin/npm-cli.js")
                self.assertEqual(validated["node"], snapshot_node)
                self.assertEqual(validated["npm_cli"], snapshot_cli)
                self.assertEqual(results["node"].stdout.strip(), b"v24.22.1")
                self.assertEqual(results["npm"].stdout.strip(), b"11.19.1")
                self.assertEqual([argv for argv, _kwargs in calls], [
                    [snapshot_node, "--version"], [snapshot_node, snapshot_cli, "--version"],
                ])
                self.assertTrue(all(kwargs["env"] == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
                                    for _argv, kwargs in calls))
                fixture_rows = [json.loads(line) for line in fixture["log"].read_text().splitlines()]
                self.assertTrue(all(row["executable"] == snapshot_node for row in fixture_rows))
                self.assertTrue(all(row["node_options"] == "" and row["npm_userconfig"] == ""
                                    for row in fixture_rows))
            finally:
                node_tool_snapshot.remove_snapshot(
                    snapshot_id, str(deadline_path), snapshot_base=snapshot_base, owner_uid=os.getuid(),
                )

    def test_prepare_main_parser_uses_snapshot_for_both_version_checks_before_mount_setup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            snapshot_id = "test-prepare-main"
            vendor_base, vendor_area, fixture, vendor = self._write_node_vendor_fixture(root, snapshot_id)
            _projection, payload = test_e2e._node_projection(
                test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
            )
            projection_path = root / "projection.json"
            projection_path.write_bytes(payload)
            deadline_path = root / "deadline.json"
            deadline_budget.create(deadline_path, 60, 5, 65)
            preparation = supervisor.node_tool_prepare
            snapshot_base = root / "snapshot-base"
            expected = [
                [str(snapshot_base / snapshot_id / "bin/node"), "--version"],
                [str(snapshot_base / snapshot_id / "bin/node"),
                 str(snapshot_base / snapshot_id / "lib/node_modules/npm/bin/npm-cli.js"), "--version"],
            ]
            real_run = subprocess.run
            calls = []
            stderr = io.StringIO()

            def record_then_stop(argv, **kwargs):
                command = list(argv)
                calls.append((command, dict(kwargs)))
                if command in expected:
                    return real_run(argv, **kwargs)
                raise supervisor.bundle.Refusal("preparation-failed")

            arguments = [
                "--projection", str(projection_path), "--output", str(root / "prepared"),
                "--profile", "core-node", "--owner-uid", str(os.getuid()),
                "--owner-gid", str(os.getgid()), "--deadline-file", str(deadline_path),
                "--node-snapshot-id", snapshot_id,
            ]
            with self._node_fixture_policy(fixture), self._node_anchor_metadata(fixture), \
                    patch.object(preparation.sys, "platform", "linux"), \
                    patch.object(preparation, "os", _RootEffectiveUIDProxy()), \
                    patch.object(preparation.node_vendor_source, "PROTECTED_BASE", vendor_base), \
                    patch.object(preparation, "_node_vendor_system_anchors",
                                 return_value=((vendor_area, os.getuid()),)), \
                    patch.object(preparation.node_vendor_source, "acquire_node_source",
                                 return_value=vendor), \
                    patch.object(node_tool_snapshot, "DEFAULT_SNAPSHOT_BASE", snapshot_base), \
                    patch.object(preparation.subprocess, "run", side_effect=record_then_stop), \
                    patch.object(preparation, "_kill_children"), \
                    patch.object(preparation, "MOUNT_TARGETS", []), \
                    contextlib.redirect_stderr(stderr):
                result = preparation.main(arguments)

            self.assertEqual(result, 2)
            self.assertEqual(stderr.getvalue(),
                             "dependency_preparation_refusal=stage=prepare-namespace-isolation "
                             "code=preparation-failed cleanup=confirmed\n", calls)
            self.assertEqual([command for command, _kwargs in calls], expected + [[
                "mount", "--make-rprivate", "/",
            ]])
            self.assertFalse(vendor_area.exists())
            self.assertTrue(all(kwargs.get("env") == {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
                                for _command, kwargs in calls[:2]))
            fixture_rows = [json.loads(line) for line in fixture["log"].read_text().splitlines()]
            snapshot_node = str(snapshot_base / snapshot_id / "bin/node")
            snapshot_cli = str(snapshot_base / snapshot_id / "lib/node_modules/npm/bin/npm-cli.js")
            self.assertEqual([(row["executable"], row["argv"]) for row in fixture_rows], [
                (snapshot_node, ["--version"]),
                (snapshot_node, [snapshot_cli, "--version"]),
            ])
            self.assertEqual(list(snapshot_base.iterdir()), [])

    def test_npm_shebang_sibling_is_not_used_by_fixed_node_version_commands(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            poison = root / "ambient-poison"
            poison.mkdir()
            (poison / "node").write_text(
                chr(35) + "!" + sys.executable + "\nprint('wrong-sibling-node')\n", encoding="utf-8",
            )
            (poison / "node").chmod(0o755)
            deadline_path = root / "deadline.json"
            deadline_budget.create(deadline_path, 60, 5, 65)
            snapshot_id = "test-snapshot-shebang"
            snapshot_base, snapshot = self._create_node_snapshot(
                fixture, root / "snapshot-base", snapshot_id, deadline_path,
            )

            sibling_result = subprocess.run(
                [str(fixture["npm"]), "--version"],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=5,
                env={"PATH": str(poison) + os.pathsep + str(fixture["node_root"] / "bin")},
                check=False,
            )
            self.assertEqual(sibling_result.returncode, 0)
            self.assertEqual(sibling_result.stdout.strip(), b"wrong-sibling-node")

            try:
                with patch.object(supervisor.node_tool_prepare, "DEADLINE_FILE", str(deadline_path)), \
                        patch.object(node_tool_snapshot, "DEFAULT_SNAPSHOT_BASE", snapshot_base), \
                        patch.dict(os.environ, {"PATH": str(poison), "NODE_OPTIONS": "--require ambient-canary"}):
                    validated = node_tool_snapshot.validate_snapshot(
                        snapshot_id, str(deadline_path), snapshot_base=snapshot_base, owner_uid=os.getuid(),
                    )
                    results = supervisor.node_tool_prepare.run_node_versions(
                        validated, supervisor.node_tool_prepare._prepare_node_version_process,
                    )
                snapshot_node = str(Path(snapshot["root"]) / "bin/node")
                snapshot_cli = str(Path(snapshot["root"]) / "lib/node_modules/npm/bin/npm-cli.js")
                self.assertEqual(validated["node"], snapshot_node)
                self.assertEqual(results["node"].stdout.strip(), b"v24.22.1")
                self.assertEqual(results["npm"].stdout.strip(), b"11.19.1")
                fixture_rows = [json.loads(line) for line in fixture["log"].read_text().splitlines()]
                self.assertEqual([(row["executable"], row["argv"]) for row in fixture_rows], [
                    (snapshot_node, ["--version"]),
                    (snapshot_node, [snapshot_cli, "--version"]),
                ])
                self.assertTrue(all(row["path"] == "/usr/bin:/bin" for row in fixture_rows))
                self.assertTrue(all(row["node_options"] == "" for row in fixture_rows))
            finally:
                node_tool_snapshot.remove_snapshot(
                    snapshot_id, str(deadline_path), snapshot_base=snapshot_base, owner_uid=os.getuid(),
                )

    def test_control_only_node_source_normalizes_snapshot_before_versions_and_mount(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary).resolve()
            fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            deadline_path = root / "deadline.json"
            deadline_budget.create(deadline_path, 120, 10, 130)
            source_members = list(fixture["node_root"].rglob("*"))
            for member in reversed(source_members):
                if member.is_symlink():
                    continue
                if member.is_dir():
                    member.chmod(0o700)
                else:
                    member.chmod(0o700 if member in (fixture["node"], fixture["npm_cli"]) else 0o600)
            fixture["node_root"].chmod(0o700)
            os.chown(fixture["anchor"], -1, os.getgid())
            fixture["anchor_uid"] = 0
            fixture["anchor"].chmod(0o2770)
            fixture["cache"].chmod(0o750)

            sealed_cache = root / "sealed-tool-cache"
            snapshot_base = sealed_cache / "node" / "24.22.1"
            snapshot_id = "x64"
            snapshot = None
            service_root = root / "service"
            service_root.mkdir()
            startup = self._write_projection_startup_fixture(service_root)
            projection, _payload = test_e2e._node_projection(
                test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
            )
            self._bind_projection_payload(startup, projection)
            service = supervisor.Service(
                startup.state_dir, startup.context, startup.workspace, startup.prepared,
                startup.bundle, startup.projection, 193847, os.getuid(),
                {"node_snapshot_id": snapshot_id, "cargo": None, "rustc": None}, startup.deadline_file,
            )
            mount_sources = []
            calls = []
            real_run = subprocess.run
            previous_deadline_file = supervisor.ACTIVE_DEADLINE_FILE
            try:
                with self._node_fixture_policy(fixture), self._node_anchor_metadata(fixture):
                    source_validation = supervisor.node_tool_prepare.validate_node_toolchain(
                        fixture["paths"], os.getuid(), tool_cache_root=fixture["cache"],
                        node_root=fixture["node_root"],
                        system_anchors=((fixture["anchor"], fixture["anchor_uid"]),),
                        deadline_file=str(deadline_path),
                        trusted_source_group_gid=os.getgid(),
                    )
                    snapshot = node_tool_snapshot.create_snapshot(
                        fixture["paths"], snapshot_id, os.getuid(), str(deadline_path),
                        snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                        source_node_root=fixture["node_root"],
                        source_anchors=((fixture["anchor"], fixture["anchor_uid"]),),
                        trusted_source_group_gid=os.getgid(),
                    )
                with patch.object(node_tool_snapshot, "DEFAULT_SNAPSHOT_BASE", snapshot_base), \
                        patch.object(supervisor.node_tool_prepare, "DEADLINE_FILE", str(deadline_path)), \
                        patch.object(supervisor, "ACTIVE_DEADLINE_FILE", str(deadline_path)):
                    validated = node_tool_snapshot.validate_snapshot(
                        snapshot_id, str(deadline_path), snapshot_base=snapshot_base, owner_uid=os.getuid(),
                    )
                    prepared_results = supervisor.node_tool_prepare.run_node_versions(
                        validated, supervisor.node_tool_prepare._prepare_node_version_process,
                    )
                    with patch.object(supervisor.subprocess, "run", side_effect=lambda argv, **kwargs: (
                            calls.append(list(argv)) or real_run(argv, **kwargs))), \
                            patch.object(supervisor, "_require_linux_root"), \
                            patch.object(supervisor, "_require_swap_disabled"), \
                            patch.object(supervisor, "_mount_private"), \
                            patch.object(supervisor, "_configure_firewall"), \
                            patch.object(supervisor, "_mount_minimal_root"), \
                            patch.object(supervisor, "_mount_bind",
                                         side_effect=lambda source, _target, **_kwargs:
                                         mount_sources.append(Path(source).resolve())), \
                            patch.object(supervisor, "_read_profiles", return_value={"schema": 1}):
                        self.assertTrue(service.prepare())

                snapshot_root = Path(snapshot["root"])
                node = snapshot_root / "bin/node"
                npm_cli = snapshot_root / "lib/node_modules/npm/bin/npm-cli.js"
                npm_shared = snapshot_root / "lib/node_modules/npm/node_modules/shared.js"
                npm_link = snapshot_root / "bin/npm"
                self.assertEqual((stat.S_IMODE(fixture["anchor"].stat().st_mode),
                                  stat.S_IMODE(fixture["cache"].stat().st_mode),
                                  stat.S_IMODE(fixture["node_root"].stat().st_mode),
                                  stat.S_IMODE(fixture["npm_root"].stat().st_mode),
                                  stat.S_IMODE((fixture["npm_root"] / "node_modules").stat().st_mode),
                                  stat.S_IMODE(fixture["node"].stat().st_mode),
                                  stat.S_IMODE(fixture["npm_cli"].stat().st_mode),
                                  stat.S_IMODE((fixture["npm_root"] / "node_modules/shared.js").stat().st_mode)),
                                 (0o2770, 0o750, 0o700, 0o700, 0o700, 0o700, 0o700, 0o600))
                self.assertEqual(source_validation["root"], str(fixture["node_root"]))
                self.assertEqual(validated["root"], str(snapshot_root))
                self.assertEqual((stat.S_IMODE(snapshot_root.stat().st_mode),
                                  stat.S_IMODE(node.stat().st_mode),
                                  stat.S_IMODE(npm_cli.stat().st_mode),
                                  stat.S_IMODE(npm_shared.stat().st_mode)),
                                 (0o555, 0o555, 0o555, 0o444))
                self.assertEqual(os.readlink(npm_link), "../lib/node_modules/npm/bin/npm-cli.js")
                self.assertEqual(prepared_results["node"].stdout.strip(), b"v24.22.1")
                self.assertEqual(prepared_results["npm"].stdout.strip(), b"11.19.1")
                self.assertEqual(calls, [
                    [str(node), "--version"],
                    [str(node), str(npm_cli), "--version"],
                    [str(node), "--version"],
                    [str(node), str(npm_cli), "--version"],
                ])
                self.assertEqual(mount_sources.count(snapshot_root.resolve()), 1)
                self.assertNotIn(fixture["node_root"].resolve(), mount_sources)
                fixture_rows = [json.loads(line) for line in fixture["log"].read_text().splitlines()]
                self.assertEqual(len(fixture_rows), 6)
                self.assertTrue(all(row["executable"] == str(node) for row in fixture_rows))
                self.assertEqual([row["argv"] for row in fixture_rows], [
                    ["--version"], [str(npm_cli), "--version"],
                    ["--version"], [str(npm_cli), "--version"],
                    ["--version"], [str(npm_cli), "--version"],
                ])
            finally:
                supervisor.ACTIVE_DEADLINE_FILE = previous_deadline_file
                if snapshot is not None:
                    node_tool_snapshot.remove_snapshot(
                        snapshot_id, str(deadline_path), snapshot_base=snapshot_base,
                        owner_uid=os.getuid(),
                    )
                for member in source_members:
                    if member.is_symlink():
                        continue
                    if member.is_dir():
                        member.chmod(0o755)
                    else:
                        current_mode = stat.S_IMODE(member.stat().st_mode)
                        member.chmod(0o755 if current_mode & 0o111 else 0o644)
                fixture["node_root"].chmod(0o755)

    def test_node_snapshot_is_the_only_tree_checked_and_mounted_after_source_replacement(self):
        with tempfile.TemporaryDirectory() as source_tmp, tempfile.TemporaryDirectory() as snapshot_tmp:
            source_root = Path(source_tmp).resolve()
            snapshot_base = Path(snapshot_tmp).resolve() / "snapshots"
            fixture = self._write_node_toolchain_fixture(source_root / "node-fixture")
            deadline_path = source_root / "deadline.json"
            deadline_budget.create(deadline_path, 120, 10, 130)
            snapshot_id = "test-r10-stable"
            with self._node_fixture_policy(fixture):
                snapshot = node_tool_snapshot.create_snapshot(
                    fixture["paths"], snapshot_id, os.getuid(), str(deadline_path),
                    snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                    source_node_root=fixture["node_root"], source_anchors=((fixture["anchor"], os.getuid()),),
                )
            snapshot_root = Path(snapshot["root"])
            snapshot_node = snapshot_root / "bin/node"
            snapshot_cli = snapshot_root / "lib/node_modules/npm/bin/npm-cli.js"
            saved_node = snapshot_node.read_bytes()
            saved_cli = snapshot_cli.read_bytes()
            marker = source_root / "mutable-tool-ran"
            original_root = fixture["node_root"]
            saved_root = original_root.with_name("x64-saved")
            outside_root = original_root.with_name("x64-outside")
            outside_root.mkdir()
            sentinel = outside_root / "sentinel"
            sentinel.write_text("preserve", encoding="ascii")
            before_mode = stat.S_IMODE(sentinel.stat().st_mode)
            (outside_root / "node").write_text("synthetic outside replacement\n", encoding="ascii")
            service_root = source_root / "service"
            service_root.mkdir()
            startup = self._write_projection_startup_fixture(service_root)
            projection, _projection_bytes = test_e2e._node_projection(
                test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
            )
            self._bind_projection_payload(startup, projection)
            service = supervisor.Service(
                startup.state_dir, startup.context, startup.workspace, startup.prepared,
                startup.bundle, startup.projection, 193847, os.getuid(),
                {"node_snapshot_id": snapshot_id, "cargo": None, "rustc": None}, startup.deadline_file,
            )
            mount_sources = []
            real_run = subprocess.run
            calls = []
            source_replaced = False

            def mutate_source_after_snapshot_validation():
                fixture["node"].write_text(
                    chr(35) + "!" + sys.executable + "\nfrom pathlib import Path\n"
                    "Path(" + repr(str(marker)) + ").write_text('replacement')\n"
                    "print('v24.22.1')\n",
                    encoding="utf-8",
                )
                fixture["node"].chmod(0o755)
                fixture["npm_cli"].write_text("replacement npm command\n", encoding="ascii")
                fixture["npm_cli"].chmod(0o755)
                original_root.rename(saved_root)
                original_root.symlink_to(outside_root, target_is_directory=True)

            def recording_run(argv, **kwargs):
                nonlocal source_replaced
                calls.append(list(argv))
                result = real_run(argv, **kwargs)
                if not source_replaced and list(argv) == [str(snapshot_node), "--version"]:
                    mutate_source_after_snapshot_validation()
                    source_replaced = True
                return result

            try:
                with patch.object(supervisor.node_tool_snapshot, "DEFAULT_SNAPSHOT_BASE", snapshot_base), \
                        patch.object(supervisor.subprocess, "run", side_effect=recording_run), \
                        patch.object(supervisor, "_require_linux_root"), \
                        patch.object(supervisor, "_require_swap_disabled"), \
                        patch.object(supervisor, "_mount_private"), \
                        patch.object(supervisor, "_configure_firewall"), \
                        patch.object(supervisor, "_mount_minimal_root"), \
                        patch.object(supervisor, "_mount_bind",
                                     side_effect=lambda source, _target, **_kwargs: mount_sources.append(Path(source).resolve())), \
                        patch.object(supervisor, "_read_profiles", return_value={"schema": 1}):
                    service.prepare()
                self.assertEqual(snapshot_node.read_bytes(), saved_node)
                self.assertEqual(snapshot_cli.read_bytes(), saved_cli)
                self.assertFalse(marker.exists())
                self.assertTrue(source_replaced)
                self.assertEqual(calls, [
                    [str(snapshot_node), "--version"],
                    [str(snapshot_node), str(snapshot_cli), "--version"],
                    [str(snapshot_node), "--version"],
                    [str(snapshot_node), str(snapshot_cli), "--version"],
                ])
                self.assertEqual(mount_sources.count(snapshot_root.resolve()), 1)
                self.assertNotIn(original_root.resolve(), mount_sources)
                self.assertEqual(sentinel.read_text(encoding="ascii"), "preserve")
                self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), before_mode)
                rows = [json.loads(line) for line in fixture["log"].read_text().splitlines()]
                self.assertEqual(len(rows), 4)
                self.assertTrue(all(row["executable"] == str(snapshot_node) for row in rows))
                self.assertEqual(
                    [row["argv"][0] for row in rows if len(row["argv"]) == 2],
                    [str(snapshot_cli), str(snapshot_cli)],
                )
            finally:
                if original_root.is_symlink():
                    original_root.unlink()
                if saved_root.exists():
                    saved_root.rename(original_root)
                node_tool_snapshot.remove_snapshot(
                    snapshot_id, str(deadline_path), snapshot_base=snapshot_base, owner_uid=os.getuid(),
                )

    def test_node_snapshot_detects_source_change_during_copy_and_removes_partial_tree(self):
        with tempfile.TemporaryDirectory() as source_tmp, tempfile.TemporaryDirectory() as snapshot_tmp:
            source_root = Path(source_tmp).resolve()
            fixture = self._write_node_toolchain_fixture(source_root / "node-fixture")
            deadline_path = source_root / "deadline.json"
            deadline_budget.create(deadline_path, 120, 10, 130)
            snapshot_base = Path(snapshot_tmp).resolve() / "snapshots"
            changing_file = fixture["npm_root"] / "bin/zz-large-fixture.js"
            changing_file.write_bytes(b"A" * (node_tool_snapshot.CHUNK_SIZE * 2 + 17))
            changing_file.chmod(0o644)

            def mutate_during_copy(checkpoint):
                if checkpoint == "during-copy:lib/node_modules/npm/bin/zz-large-fixture.js":
                    changing_file.write_bytes(b"B" * (node_tool_snapshot.CHUNK_SIZE * 2 + 17))

            with self._node_fixture_policy(fixture), self.assertRaises(node_tool_snapshot.SnapshotRefusal) as caught:
                node_tool_snapshot.create_snapshot(
                    fixture["paths"], "test-r10-change", os.getuid(), str(deadline_path),
                    snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                    source_node_root=fixture["node_root"], source_anchors=((fixture["anchor"], os.getuid()),),
                    test_checkpoint=mutate_during_copy,
                )
            self.assertEqual(caught.exception.code, "node-snapshot-source-changed")
            self.assertTrue(caught.exception.cleanup_confirmed)
            self.assertEqual(list(snapshot_base.iterdir()), [])

    def test_node_snapshot_sorts_real_node_header_directory_and_sibling_rows(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary).resolve()
            fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            header_dir = fixture["node_root"] / "include/node/uv"
            header_dir.mkdir(parents=True)
            (header_dir / "aix.h").write_bytes(b"real-shaped libuv header\n")
            (fixture["node_root"] / "include/node/uv.h").write_bytes(b"real-shaped libuv API\n")
            deadline_path = root / "deadline.json"
            deadline_budget.create(deadline_path, 120, 10, 130)
            snapshot_base = root / "snapshots"
            snapshot_id = "test-real-node-row-order"

            with self._node_fixture_policy(fixture):
                snapshot = node_tool_snapshot.create_snapshot(
                    fixture["paths"], snapshot_id, os.getuid(), str(deadline_path),
                    snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                    source_node_root=fixture["node_root"],
                    source_anchors=((fixture["anchor"], os.getuid()),),
                )
            try:
                manifest = json.loads(
                    (Path(snapshot["root"]) / node_tool_snapshot.MANIFEST_NAME).read_text(encoding="utf-8"),
                )
                paths = [row["path"] for row in manifest["entries"]]
                self.assertEqual(paths, sorted(paths))
                self.assertLess(paths.index("include/node/uv.h"),
                                paths.index("include/node/uv/aix.h"))
            finally:
                node_tool_snapshot.remove_snapshot(
                    snapshot_id, str(deadline_path), snapshot_base=snapshot_base,
                    owner_uid=os.getuid(),
                )

    def test_fifo_replacements_during_copy_and_second_source_verification_are_bounded(self):
        for kind, trigger_count in (("copy", 1), ("source-verification", 2)):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir="/tmp") as temporary:
                root = Path(temporary).resolve()
                fixture = self._write_node_toolchain_fixture(root / "node-fixture")
                deadline_path = root / "deadline.json"
                deadline_budget.create(deadline_path, 60, 10, 70)
                snapshot_base = root / "snapshots"
                result = self._run_fifo_snapshot_child(
                    kind, fixture, deadline_path, snapshot_base,
                    "test-fifo-" + kind, fixture["node"].parent, trigger_count,
                )
                self.assertEqual(result, ("refused", "node-snapshot-source-changed", trigger_count, True, True))
                self.assertTrue(snapshot_base.is_dir())
                self.assertEqual(list(snapshot_base.iterdir()), [])

    def test_fifo_replacements_during_snapshot_and_manifest_reads_are_bounded(self):
        for kind, parent_name in (("snapshot-content", "bin"), ("manifest", ".")):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(dir="/tmp") as temporary:
                root = Path(temporary).resolve()
                fixture = self._write_node_toolchain_fixture(root / "node-fixture")
                deadline_path = root / "deadline.json"
                deadline_budget.create(deadline_path, 60, 10, 70)
                snapshot_base, snapshot = self._create_node_snapshot(
                    fixture, root / "snapshots", "test-fifo-read-" + kind, deadline_path,
                )
                parent = Path(snapshot["root"]) / parent_name
                result = self._run_fifo_snapshot_child(
                    kind, fixture, deadline_path, snapshot_base,
                    "test-fifo-read-" + kind, parent, 1,
                )
                expected_code = "node-snapshot-manifest-invalid:manifest-metadata" if kind == "manifest" \
                    else "node-snapshot-content-changed"
                self.assertEqual(result, ("refused", expected_code, 1, True, True))

    def test_late_composed_link_escapes_are_refused_before_external_canary_open(self):
        for shape in ("short", "long"):
            with self.subTest(shape=shape), tempfile.TemporaryDirectory(dir="/tmp") as temporary:
                root = Path(temporary).resolve()
                fixture = self._write_node_toolchain_fixture(root / "node-fixture")
                deadline_path = root / "deadline.json"
                deadline_budget.create(deadline_path, 60, 10, 70)
                snapshot_base = root / "snapshots"
                snapshot_id = "test-link-escape-" + shape
                outside = root / "outside"
                outside.write_bytes(b"external-canary\n")
                outside.chmod(0o440)
                before = outside.stat()
                before_bytes = outside.read_bytes()
                snapshot_path = snapshot_base / snapshot_id
                hops = len(snapshot_path.parts)
                self.assertLessEqual(hops, node_tool_snapshot.MAX_LINK_HOPS)
                long_target = "/".join(
                    ["a"] + ["b"] * (hops - 1) + [".."] * hops + list(outside.parts[1:])
                )
                target = "a/b/../../outside" if shape == "short" else long_target
                self.assertTrue(node_tool_snapshot._safe_relative_link("escape", target))

                def introduce_after_validation(checkpoint):
                    if checkpoint == "after-source-validation":
                        link_parent = fixture["node_root"] / "a"
                        link_parent.mkdir()
                        (link_parent / "b").symlink_to(".")
                        (fixture["node_root"] / "escape").symlink_to(target)

                with self._node_fixture_policy(fixture), self._forbid_external_canary_open(outside) as opens, \
                        patch.object(subprocess, "Popen", side_effect=AssertionError("unexpected process")), \
                        patch.object(subprocess, "run", side_effect=AssertionError("unexpected process")), \
                        self.assertRaises(node_tool_snapshot.SnapshotRefusal) as caught:
                    node_tool_snapshot.create_snapshot(
                        fixture["paths"], snapshot_id, os.getuid(), str(deadline_path),
                        snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                        source_node_root=fixture["node_root"],
                        source_anchors=((fixture["anchor"], os.getuid()),),
                        test_checkpoint=introduce_after_validation,
                    )
                self.assertEqual(caught.exception.code, "node-snapshot-link-invalid")
                self.assertTrue(caught.exception.cleanup_confirmed)
                self.assertEqual(opens, [])
                self.assertEqual(list(snapshot_base.iterdir()), [])
                after = outside.stat()
                self.assertEqual(outside.read_bytes(), before_bytes)
                self.assertEqual((after.st_dev, after.st_ino, after.st_mode, after.st_size,
                                  after.st_mtime_ns, after.st_ctime_ns),
                                 (before.st_dev, before.st_ino, before.st_mode, before.st_size,
                                  before.st_mtime_ns, before.st_ctime_ns))

    def test_snapshot_graph_rejects_cycles_dangling_links_hop_limit_and_absolute_targets(self):
        cases = ("cycle", "dangling", "hop-limit", "absolute")
        for case in cases:
            with self.subTest(case=case), tempfile.TemporaryDirectory(dir="/tmp") as temporary:
                root = Path(temporary).resolve()
                fixture = self._write_node_toolchain_fixture(root / "node-fixture")
                deadline_path = root / "deadline.json"
                deadline_budget.create(deadline_path, 60, 10, 70)
                snapshot_base = root / "snapshots"
                snapshot_id = "test-link-" + case

                def introduce_after_validation(checkpoint):
                    if checkpoint != "after-source-validation":
                        return
                    node_root = fixture["node_root"]
                    if case == "cycle":
                        (node_root / "links").mkdir()
                        (node_root / "links/one").symlink_to("two")
                        (node_root / "links/two").symlink_to("one")
                    elif case == "dangling":
                        (node_root / "dangling").symlink_to("missing-target")
                    elif case == "hop-limit":
                        link_root = node_root / "links"
                        link_root.mkdir()
                        count = node_tool_snapshot.MAX_LINK_HOPS + 2
                        for index in range(count):
                            name = "chain-" + str(index)
                            target = ("chain-" + str(index + 1) if index + 1 < count
                                      else "../bin/node")
                            (link_root / name).symlink_to(target)
                    else:
                        (node_root / "absolute").symlink_to(str(root / "outside"))

                with self._node_fixture_policy(fixture), \
                        self.assertRaises(node_tool_snapshot.SnapshotRefusal) as caught:
                    node_tool_snapshot.create_snapshot(
                        fixture["paths"], snapshot_id, os.getuid(), str(deadline_path),
                        snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                        source_node_root=fixture["node_root"],
                        source_anchors=((fixture["anchor"], os.getuid()),),
                        test_checkpoint=introduce_after_validation,
                    )
                self.assertEqual(caught.exception.code, "node-snapshot-link-invalid")
                self.assertTrue(caught.exception.cleanup_confirmed)
                self.assertEqual(list(snapshot_base.iterdir()), [])

    def test_validate_snapshot_rejects_rehashed_composed_escape_without_external_access(self):
        with tempfile.TemporaryDirectory(dir="/tmp") as temporary:
            root = Path(temporary).resolve()
            fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            deadline_path = root / "deadline.json"
            deadline_budget.create(deadline_path, 60, 10, 70)
            snapshot_base = root / "snapshots"
            snapshot_id = "test-link-revalidation"
            outside = root / "outside"
            outside.write_bytes(b"external-canary\n")
            outside.chmod(0o440)
            before = outside.stat()
            before_bytes = outside.read_bytes()

            def add_valid_graph_after_source_validation(checkpoint):
                if checkpoint == "after-source-validation":
                    link_parent = fixture["node_root"] / "a"
                    link_parent.mkdir()
                    (link_parent / "b").symlink_to(".")
                    (fixture["node_root"] / "escape").symlink_to("a/b")

            with self._node_fixture_policy(fixture):
                snapshot = node_tool_snapshot.create_snapshot(
                    fixture["paths"], snapshot_id, os.getuid(), str(deadline_path),
                    snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                    source_node_root=fixture["node_root"],
                    source_anchors=((fixture["anchor"], os.getuid()),),
                    test_checkpoint=add_valid_graph_after_source_validation,
                )
            snapshot_root = Path(snapshot["root"])
            snapshot_root.chmod(0o700)
            root_fd = os.open(snapshot_root, os.O_RDONLY | node_tool_snapshot._O_DIRECTORY
                               | node_tool_snapshot._O_NOFOLLOW)
            try:
                os.unlink("escape", dir_fd=root_fd)
                os.symlink("a/b/../../outside", "escape", dir_fd=root_fd)
            finally:
                os.close(root_fd)
            self._rewrite_snapshot_manifest_for_fixture(snapshot_root, deadline_path)
            try:
                with self._forbid_external_canary_open(outside) as opens, \
                        self.assertRaises(node_tool_snapshot.SnapshotRefusal) as caught:
                    node_tool_snapshot.validate_snapshot(
                        snapshot_id, str(deadline_path), snapshot_base=snapshot_base,
                        owner_uid=os.getuid(),
                    )
                self.assertEqual(caught.exception.code, "node-snapshot-link-invalid")
                self.assertEqual(opens, [])
                after = outside.stat()
                self.assertEqual(outside.read_bytes(), before_bytes)
                self.assertEqual((after.st_dev, after.st_ino, after.st_mode, after.st_size,
                                  after.st_mtime_ns, after.st_ctime_ns),
                                 (before.st_dev, before.st_ino, before.st_mode, before.st_size,
                                  before.st_mtime_ns, before.st_ctime_ns))
            finally:
                snapshot_root.chmod(0o700)
                root_fd = os.open(snapshot_root, os.O_RDONLY | node_tool_snapshot._O_DIRECTORY
                                  | node_tool_snapshot._O_NOFOLLOW)
                try:
                    os.unlink("escape", dir_fd=root_fd)
                    os.symlink("a/b", "escape", dir_fd=root_fd)
                finally:
                    os.close(root_fd)
                self._rewrite_snapshot_manifest_for_fixture(snapshot_root, deadline_path)
                node_tool_snapshot.remove_snapshot(
                    snapshot_id, str(deadline_path), snapshot_base=snapshot_base,
                    owner_uid=os.getuid(),
                )

    def test_node_snapshot_manifest_budget_refuses_and_removes_partial_tree(self):
        with tempfile.TemporaryDirectory() as source_tmp, tempfile.TemporaryDirectory() as snapshot_tmp:
            source_root = Path(source_tmp).resolve()
            fixture = self._write_node_toolchain_fixture(source_root / "node-fixture")
            deadline_path = source_root / "deadline.json"
            deadline_budget.create(deadline_path, 120, 10, 130)
            snapshot_base = Path(snapshot_tmp).resolve() / "snapshots"
            with self._node_fixture_policy(fixture), \
                    patch.object(node_tool_snapshot, "MAX_MANIFEST_BYTES", 1024), \
                    self.assertRaises(node_tool_snapshot.SnapshotRefusal) as caught:
                node_tool_snapshot.create_snapshot(
                    fixture["paths"], "test-r10-manifest-limit", os.getuid(), str(deadline_path),
                    snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                    source_node_root=fixture["node_root"],
                    source_anchors=((fixture["anchor"], os.getuid()),),
                )
            self.assertEqual(caught.exception.code, "node-snapshot-limit")
            self.assertTrue(caught.exception.cleanup_confirmed)
            self.assertEqual(list(snapshot_base.iterdir()), [])

    def test_node_snapshot_refuses_source_root_symlink_swap_after_validation(self):
        with tempfile.TemporaryDirectory() as source_tmp, tempfile.TemporaryDirectory() as snapshot_tmp:
            source_root = Path(source_tmp).resolve()
            fixture = self._write_node_toolchain_fixture(source_root / "node-fixture")
            deadline_path = source_root / "deadline.json"
            deadline_budget.create(deadline_path, 120, 10, 130)
            snapshot_base = Path(snapshot_tmp).resolve() / "snapshots"
            original_root = fixture["node_root"]
            saved_root = original_root.with_name("x64-saved")
            outside_root = original_root.with_name("x64-outside")
            outside_root.mkdir()
            sentinel = outside_root / "sentinel"
            sentinel.write_text("preserve", encoding="ascii")
            before_mode = stat.S_IMODE(sentinel.stat().st_mode)

            def swap_after_validation(checkpoint):
                if checkpoint == "after-source-validation":
                    original_root.rename(saved_root)
                    original_root.symlink_to(outside_root, target_is_directory=True)

            try:
                with self._node_fixture_policy(fixture), self.assertRaises(node_tool_snapshot.SnapshotRefusal) as caught:
                    node_tool_snapshot.create_snapshot(
                        fixture["paths"], "test-r10-precopy-swap", os.getuid(), str(deadline_path),
                        snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                        source_node_root=fixture["node_root"],
                        source_anchors=((fixture["anchor"], os.getuid()),), test_checkpoint=swap_after_validation,
                    )
                self.assertEqual(caught.exception.code, "node-snapshot-source-changed")
                self.assertFalse(snapshot_base.exists())
                self.assertEqual(sentinel.read_text(encoding="ascii"), "preserve")
                self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), before_mode)
            finally:
                if original_root.is_symlink():
                    original_root.unlink()
                if saved_root.exists():
                    saved_root.rename(original_root)

    def test_node_snapshot_refuses_root_symlink_swap_during_copy(self):
        with tempfile.TemporaryDirectory() as source_tmp, tempfile.TemporaryDirectory() as snapshot_tmp:
            source_root = Path(source_tmp).resolve()
            fixture = self._write_node_toolchain_fixture(source_root / "node-fixture")
            deadline_path = source_root / "deadline.json"
            deadline_budget.create(deadline_path, 120, 10, 130)
            snapshot_base = Path(snapshot_tmp).resolve() / "snapshots"
            original_root = fixture["node_root"]
            saved_root = original_root.with_name("x64-saved")
            outside_root = original_root.with_name("x64-outside")
            outside_root.mkdir()
            sentinel = outside_root / "sentinel"
            sentinel.write_text("preserve", encoding="ascii")
            before_mode = stat.S_IMODE(sentinel.stat().st_mode)

            def swap_after_copy(checkpoint):
                if checkpoint == "after-copy":
                    original_root.rename(saved_root)
                    original_root.symlink_to(outside_root, target_is_directory=True)

            try:
                with self._node_fixture_policy(fixture), self.assertRaises(node_tool_snapshot.SnapshotRefusal) as caught:
                    node_tool_snapshot.create_snapshot(
                        fixture["paths"], "test-r10-swap", os.getuid(), str(deadline_path),
                        snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                        source_node_root=fixture["node_root"],
                        source_anchors=((fixture["anchor"], os.getuid()),), test_checkpoint=swap_after_copy,
                    )
                self.assertEqual(caught.exception.code, "node-snapshot-source-changed")
                self.assertEqual(list(snapshot_base.iterdir()), [])
                self.assertTrue(caught.exception.cleanup_confirmed)
                self.assertEqual(sentinel.read_text(encoding="ascii"), "preserve")
                self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), before_mode)
            finally:
                if original_root.is_symlink():
                    original_root.unlink()
                if saved_root.exists():
                    saved_root.rename(original_root)

    def test_node_snapshot_refuses_source_symlink_escape_without_changing_target(self):
        with tempfile.TemporaryDirectory() as source_tmp, tempfile.TemporaryDirectory() as snapshot_tmp:
            source_root = Path(source_tmp).resolve()
            fixture = self._write_node_toolchain_fixture(source_root / "node-fixture")
            deadline_path = source_root / "deadline.json"
            deadline_budget.create(deadline_path, 120, 10, 130)
            snapshot_base = Path(snapshot_tmp).resolve() / "snapshots"
            outside = source_root / "outside"
            outside.mkdir(mode=0o700)
            sentinel = outside / "sentinel"
            sentinel.write_text("preserve", encoding="ascii")
            before_mode = stat.S_IMODE(sentinel.stat().st_mode)
            (fixture["npm_root"] / "outside-link").symlink_to(sentinel)
            with self._node_fixture_policy(fixture), self.assertRaises(supervisor.bundle.Refusal) as caught:
                node_tool_snapshot.create_snapshot(
                    fixture["paths"], "test-r10-escape", os.getuid(), str(deadline_path),
                    snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                    source_node_root=fixture["node_root"], source_anchors=((fixture["anchor"], os.getuid()),),
                )
            self.assertEqual(caught.exception.args[0], "node-tool-layout")
            self.assertEqual(sentinel.read_text(encoding="ascii"), "preserve")
            self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), before_mode)
            self.assertFalse(snapshot_base.exists())

    def test_node_snapshot_accepts_mixed_root_and_runner_owned_tool_content(self):
        with tempfile.TemporaryDirectory() as source_tmp, tempfile.TemporaryDirectory() as snapshot_tmp:
            source_root = Path(source_tmp).resolve()
            fixture = self._write_node_toolchain_fixture(source_root / "node-fixture")
            deadline_path = source_root / "deadline.json"
            deadline_budget.create(deadline_path, 120, 10, 130)
            snapshot_base = Path(snapshot_tmp).resolve() / "snapshots"
            self.assertEqual(
                supervisor.node_tool_prepare._trusted_toolchain_owner_uids(os.getuid()),
                frozenset((0, os.getuid())),
            )
            mixed_owner_view = _MixedOwnerMetadataProxy(fixture["node"])
            with self._node_fixture_policy(fixture), patch.object(node_tool_snapshot, "os", mixed_owner_view):
                snapshot = node_tool_snapshot.create_snapshot(
                    fixture["paths"], "test-r10-mixed", os.getuid(), str(deadline_path),
                    snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                    source_node_root=fixture["node_root"], source_anchors=((fixture["anchor"], os.getuid()),),
                )
            self.assertIn((str(fixture["node"]), 0), mixed_owner_view.source_owners)
            self.assertEqual(fixture["npm_cli"].stat().st_uid, os.getuid())
            self.assertEqual(Path(snapshot["root"]).stat().st_uid, os.getuid())
            manifest = json.loads((Path(snapshot["root"]) / node_tool_snapshot.MANIFEST_NAME).read_text())
            self.assertEqual(manifest["preparation"], node_tool_snapshot.PREPARATION_ID)
            self.assertEqual(manifest["runner_uid"], os.getuid())
            self.assertEqual(manifest["node_version"], "24.22.1")
            self.assertEqual(manifest["npm_version"], "11.19.1")
            run_job = public_audit.parse_workflow(".github/workflows/devlane-encrypted.yml")[public_audit.RUN_JOB]
            self.assertFalse(any((step.get("uses") or "").startswith("actions/setup-node@")
                                 for step in run_job["steps"]))
            self.assertEqual(node_tool_snapshot.PREPARATION_ID,
                             "nodejs-dist-v24.22.1-linux-x64-sha256")
            self.assertEqual(
                node_tool_snapshot.validate_snapshot(
                    "test-r10-mixed", str(deadline_path), snapshot_base=snapshot_base,
                    owner_uid=os.getuid(),
                )["content_sha256"],
                snapshot["content_sha256"],
            )
            node_tool_snapshot.remove_snapshot(
                "test-r10-mixed", str(deadline_path), snapshot_base=snapshot_base, owner_uid=os.getuid(),
            )
            self.assertFalse(Path(snapshot["root"]).exists())

    def test_node_snapshot_cleanup_refuses_symlinked_snapshot_without_touching_target(self):
        with tempfile.TemporaryDirectory() as source_tmp, tempfile.TemporaryDirectory() as snapshot_tmp:
            source_root = Path(source_tmp).resolve()
            snapshot_base = Path(snapshot_tmp).resolve() / "snapshots"
            fixture = self._write_node_toolchain_fixture(source_root / "node-fixture")
            deadline_path = source_root / "deadline.json"
            deadline_budget.create(deadline_path, 120, 10, 130)
            outside = source_root / "outside"
            outside.mkdir(mode=0o700)
            sentinel = outside / "sentinel"
            sentinel.write_text("preserve", encoding="ascii")
            before_mode = stat.S_IMODE(sentinel.stat().st_mode)
            with self._node_fixture_policy(fixture):
                snapshot = node_tool_snapshot.create_snapshot(
                    fixture["paths"], "test-r10-cleanup", os.getuid(), str(deadline_path),
                    snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                    source_node_root=fixture["node_root"], source_anchors=((fixture["anchor"], os.getuid()),),
                )
            saved_root = snapshot_base / "test-r10-cleanup-saved"
            Path(snapshot["root"]).rename(saved_root)
            (snapshot_base / "test-r10-cleanup").symlink_to(outside, target_is_directory=True)
            with self.assertRaises(node_tool_snapshot.SnapshotRefusal):
                node_tool_snapshot.remove_snapshot(
                    "test-r10-cleanup", str(deadline_path), snapshot_base=snapshot_base,
                    owner_uid=os.getuid(),
                )
            self.assertEqual(sentinel.read_text(encoding="ascii"), "preserve")
            self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode), before_mode)

    def test_node_snapshot_cleanup_confirms_safely_absent_base_without_creating_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            deadline_path = root / "deadline.json"
            deadline_budget.create(deadline_path, 120, 10, 130)
            absent_base = root / "not-created" / "snapshots"
            self.assertTrue(node_tool_snapshot.remove_snapshot(
                "test-r10-absent", str(deadline_path), snapshot_base=absent_base,
                control_uid=os.geteuid(), owner_uid=os.getuid(),
            ))
            self.assertFalse(absent_base.exists())

    def test_node_snapshot_cleanup_uses_the_reserved_deadline_after_work_expires(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            deadline_path = root / "deadline.json"
            deadline_budget.create(deadline_path, 120, 120, 240)
            snapshot_base, snapshot = self._create_node_snapshot(
                fixture, root / "snapshot-base", "test-cleanup-reserve", deadline_path,
            )
            deadline = deadline_budget._read(deadline_path)
            deadline["work_deadline"] = time.monotonic() - 1
            deadline_path.write_text(json.dumps(deadline, sort_keys=True, separators=(",", ":")) + "\n")
            with self.assertRaises(deadline_budget.DeadlineRefusal):
                deadline_budget.remaining(deadline_path)
            self.assertGreater(deadline_budget.cleanup_remaining(deadline_path), 0)
            self.assertTrue(node_tool_snapshot.remove_snapshot(
                "test-cleanup-reserve", str(deadline_path), snapshot_base=snapshot_base,
                owner_uid=os.getuid(),
            ))
            self.assertFalse(Path(snapshot["root"]).exists())

    def test_node_snapshot_parser_ids_cannot_escape_the_controlled_base(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            deadline_path = root / "deadline.json"
            deadline_budget.create(deadline_path, 120, 10, 130)
            snapshot_base = root / "snapshots"
            outside = root / "outside"
            outside.mkdir()
            sentinel = outside / "sentinel"
            sentinel.write_text("preserve", encoding="ascii")
            for operation in (node_tool_snapshot.validate_snapshot, node_tool_snapshot.remove_snapshot):
                with self.subTest(operation=operation.__name__), self.assertRaises(node_tool_snapshot.SnapshotRefusal) as caught:
                    operation("../outside", str(deadline_path), snapshot_base=snapshot_base)
                self.assertEqual(caught.exception.code, "node-snapshot-id")
            self.assertEqual(sentinel.read_text(encoding="ascii"), "preserve")
            self.assertFalse(snapshot_base.exists())

    def test_node_snapshot_workflow_arguments_match_the_real_cli_parsers(self):
        prepare = supervisor.node_tool_prepare
        prepared_args = prepare._argument_parser().parse_args([
            "--projection", "projection", "--output", "prepared", "--profile", "core-node",
            "--owner-uid", "501", "--owner-gid", "20", "--node-snapshot-id", "devlane-123-1",
            "--deadline-file", "deadline",
        ])
        self.assertEqual(prepared_args.deadline_file, "deadline")
        self.assertEqual(prepared_args.node_snapshot_id, "devlane-123-1")
        with self.assertRaises(supervisor.bundle.Refusal):
            prepare._argument_parser().parse_args([
                "--projection", "projection", "--output", "prepared", "--profile", "core-node",
                "--owner-uid", "501", "--owner-gid", "20", "--node-path", "/opt/node/bin/node",
                "--node-snapshot-id", "devlane-123-1", "--deadline-file", "deadline",
            ])
        with self.assertRaises(supervisor.bundle.Refusal):
            prepare._argument_parser().parse_args([
                "--projection", "projection", "--output", "prepared", "--profile", "core-node",
                "--owner-uid", "501", "--owner-gid", "20", "--node-snapshot-id", "devlane-123-1",
            ])
        supervisor_args = supervisor._argument_parser().parse_args([
            "start", "--state-dir", "state", "--context", "context", "--workspace", "workspace",
            "--prepared", "prepared", "--bundle", "bundle", "--projection", "projection",
            "--positive-control", "positive", "--node-snapshot-id", "devlane-123-1",
            "--deadline-file", "deadline",
        ])
        self.assertEqual(supervisor_args.node_snapshot_id, "devlane-123-1")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            supervisor._argument_parser().parse_args([
                "start", "--state-dir", "state", "--context", "context", "--workspace", "workspace",
                "--prepared", "prepared", "--bundle", "bundle", "--projection", "projection",
                "--positive-control", "positive", "--node-snapshot-id", "devlane-123-1",
            ])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            supervisor._argument_parser().parse_args([
                "start", "--state-dir", "state", "--context", "context", "--workspace", "workspace",
                "--prepared", "prepared", "--bundle", "bundle", "--projection", "projection",
                "--positive-control", "positive", "--deadline-file", "deadline", "--node-path", "unsafe",
            ])
        cleanup_args = host_cleanup._argument_parser().parse_args([
            "--root", "root", "--runner-temp", "temp", "--deadline-file", "deadline",
            "--node-snapshot-id", "devlane-123-1",
        ])
        self.assertEqual(cleanup_args.deadline_file, "deadline")
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            host_cleanup._argument_parser().parse_args([
                "--root", "root", "--runner-temp", "temp", "--node-snapshot-id", "devlane-123-1",
            ])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            host_cleanup.main([
                "--snapshot-only", "--owner-uid", "501", "--deadline-file", "deadline",
            ])
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            host_cleanup.main([
                "--snapshot-only", "--node-snapshot-id", "devlane-123-1", "--deadline-file", "deadline",
            ])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            deadline_path = root / "deadline.json"
            deadline_budget.create(deadline_path, 60, 10, 70)
            observed = []

            def record_snapshot_cleanup(argv, **kwargs):
                observed.append((list(argv), dict(kwargs)))
                return subprocess.CompletedProcess(
                    argv, 0, b"node_snapshot_cleanup=confirmed\nnode_vendor_cleanup=confirmed\n", b"",
                )

            with patch.object(host_cleanup.subprocess, "run", side_effect=record_snapshot_cleanup), \
                    patch.object(host_cleanup, "_cleanup_timeout", return_value=10):
                self.assertTrue(host_cleanup.clean_node_snapshot("devlane-123-1", str(deadline_path)))
            command, options = observed[0]
            self.assertEqual(command[:3], ["sudo", "-n", sys.executable])
            parser_args = host_cleanup._argument_parser().parse_args(command[command.index("--snapshot-only"):])
            self.assertTrue(parser_args.snapshot_only)
            self.assertEqual(parser_args.node_snapshot_id, "devlane-123-1")
            self.assertEqual(parser_args.owner_uid, os.getuid())
            self.assertEqual(parser_args.deadline_file, str(deadline_path))
            self.assertEqual(options["env"], {
                "PATH": "/usr/bin:/bin", "LC_ALL": "C", "PYTHONDONTWRITEBYTECODE": "1",
            })

    def test_node_vendor_cleanup_removes_only_the_owned_area_without_following_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            base = root / "node-vendor"
            area = base / "test-vendor-cleanup"
            outside = root / "outside"
            outside.mkdir()
            canary = outside / "canary.txt"
            canary.write_text("unchanged", encoding="ascii")
            (area / "cache" / "node").mkdir(parents=True)
            (area / "cache" / "node" / "bin").mkdir()
            (area / "cache" / "node" / "bin" / "escape").symlink_to(outside, target_is_directory=True)
            (area / "cache" / "node" / "payload").write_text("fixture", encoding="ascii")
            for current, directories, _files in os.walk(area):
                Path(current).chmod(0o555)
                for name in directories:
                    child = Path(current) / name
                    if not child.is_symlink():
                        child.chmod(0o555)
            with patch.object(host_cleanup.node_vendor_source, "PROTECTED_BASE", base):
                self.assertTrue(host_cleanup.clean_node_vendor_source(
                    "test-vendor-cleanup", control_uid=os.getuid(),
                ))
            self.assertFalse(area.exists())
            self.assertEqual(canary.read_text(encoding="ascii"), "unchanged")
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/devlane-encrypted.yml").read_text()
        prepare_step = workflow.split("- name: Prepare dependencies before the cut", 1)[1].split("- name:", 1)[0]
        start_step = workflow.split("- name: Cut network and start the isolated supervisor", 1)[1].split("- name:", 1)[0]
        cleanup_step = workflow.split("- name: Shred runner-local workspace", 1)[1].split("  devlane-encrypted-audit:", 1)[0]
        self.assertIn("--deadline-file", prepare_step)
        self.assertIn("--node-snapshot-id", prepare_step)
        self.assertIn("--deadline-file", start_step)
        self.assertIn("--node-snapshot-id", start_step)
        self.assertNotIn("--node-path", start_step)
        self.assertNotIn("--npm-path", start_step)
        self.assertIn("--deadline-file", cleanup_step)
        self.assertIn("--node-snapshot-id", cleanup_step)
        self.assertNotIn("/opt/hostedtoolcache", inspect.getsource(supervisor._mount_minimal_root))
        run_job = public_audit.parse_workflow(".github/workflows/devlane-encrypted.yml")[public_audit.RUN_JOB]
        steps = run_job["steps"]
        prepare_index = next(i for i, step in enumerate(steps)
                             if step["name"] == "Prepare dependencies before the cut")
        decrypt_index = next(i for i, step in enumerate(steps)
                             if step["name"] == "Decrypt authenticated bundle")
        self.assertLess(prepare_index, decrypt_index)
        rust_step = workflow.split("- name: Install pinned Rust toolchain", 1)[1].split("- name:", 1)[0]
        self.assertIn("if: ${{ inputs.profile == 'core-rust' || inputs.profile == 'desktop' || inputs.profile == 'local-sync-rust' }}", rust_step)
        self.assertFalse(any((step.get("uses") or "").startswith("actions/setup-node@") for step in steps))
        self.assertIn("node_vendor_source.acquire_node_source", inspect.getsource(supervisor.node_tool_prepare.main))
        self.assertNotIn("/opt/hostedtoolcache", workflow)

    def test_node_toolchain_rejects_untrusted_owners_permissions_and_layouts_before_execution(self):
        cases = (
            ("world-writable-cache", "node-toolchain-source-cache-root-write-mode"),
            ("world-writable-bin", "node-toolchain-source-node-layout-write-mode"),
            ("world-writable-node", "node-toolchain-source-node-file-write-mode"),
            ("world-writable-npm-parent", "node-toolchain-source-npm-layout-write-mode"),
            ("group-writable-anchor", "node-toolchain-source-opt-anchor-write-mode"),
            ("trusted-anchor-foreign-group", "node-toolchain-source-opt-anchor-write-mode"),
            ("trusted-anchor-world-writable", "node-toolchain-source-opt-anchor-write-mode"),
            ("foreign-owner-shared-anchor", "node-toolchain-owner"),
            ("group-writable-npm-subtree", "node-toolchain-source-npm-tree-write-mode"),
            ("group-writable-npm-file", "node-toolchain-source-npm-file-write-mode"),
            ("bad-owner-cache", "node-toolchain-owner"),
            ("bad-owner-bin", "node-toolchain-owner"),
            ("bad-owner-node", "node-toolchain-owner"),
            ("bad-owner-npm-link", "node-toolchain-owner"),
            ("bad-owner-npm-cli", "node-toolchain-owner"),
            ("bad-owner-npm-dependency", "node-toolchain-owner"),
            ("missing-node", "node-toolchain-missing"),
            ("missing-npm-cli", "node-toolchain-missing"),
            ("owner-inaccessible-node", "node-toolchain-file-control-access"),
            ("owner-inaccessible-npm-directory", "node-toolchain-directory-control-access"),
            ("non-executable-node", "node-toolchain-executable"),
            ("symlinked-node", "node-tool-layout"),
            ("alternate-node-name", "node-tool-layout"),
            ("npm-escape-link", "node-tool-layout"),
            ("npm-nested-escape-link", "node-tool-layout"),
            ("world-writable-npm-dependency-dir", "node-toolchain-source-npm-tree-write-mode"),
            ("world-writable-npm-dependency-file", "node-toolchain-source-npm-file-write-mode"),
            ("npm-cli-writable", "node-toolchain-source-npm-file-write-mode"),
        )
        for label, expected_code in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture = self._write_node_toolchain_fixture(root / "node-fixture")
                deadline_path = root / "deadline.json"
                deadline_budget.create(deadline_path, 60, 5, 65)
                snapshot_base = root / "snapshot-base"
                paths = dict(fixture["paths"])
                owner_target = None
                foreign_group_target = None
                trusted_source_group_gid = None
                if label == "world-writable-cache":
                    fixture["cache"].chmod(0o777)
                elif label == "world-writable-bin":
                    (fixture["node_root"] / "bin").chmod(0o777)
                elif label == "world-writable-node":
                    fixture["node"].chmod(0o777)
                elif label == "world-writable-npm-parent":
                    (fixture["node_root"] / "lib/node_modules/npm/bin").chmod(0o777)
                elif label == "group-writable-anchor":
                    fixture["anchor"].chmod(0o775)
                    foreign_group_target = fixture["anchor"]
                elif label == "trusted-anchor-foreign-group":
                    os.chown(fixture["anchor"], -1, os.getgid())
                    fixture["anchor"].chmod(0o2770)
                    foreign_group_target = fixture["anchor"]
                    trusted_source_group_gid = os.getgid()
                elif label == "trusted-anchor-world-writable":
                    os.chown(fixture["anchor"], -1, os.getgid())
                    fixture["anchor"].chmod(0o2777)
                    trusted_source_group_gid = os.getgid()
                elif label == "foreign-owner-shared-anchor":
                    os.chown(fixture["anchor"], -1, os.getgid())
                    fixture["anchor"].chmod(0o2770)
                    owner_target = fixture["anchor"]
                    trusted_source_group_gid = os.getgid()
                elif label == "group-writable-npm-subtree":
                    (fixture["npm_root"] / "node_modules").chmod(0o775)
                    foreign_group_target = fixture["npm_root"] / "node_modules"
                elif label == "group-writable-npm-file":
                    (fixture["npm_root"] / "node_modules/shared.js").chmod(0o664)
                    foreign_group_target = fixture["npm_root"] / "node_modules/shared.js"
                elif label == "bad-owner-cache":
                    owner_target = fixture["cache"]
                elif label == "bad-owner-bin":
                    owner_target = fixture["node_root"] / "bin"
                elif label == "bad-owner-node":
                    owner_target = fixture["node"]
                elif label == "bad-owner-npm-link":
                    owner_target = fixture["npm"]
                elif label == "bad-owner-npm-cli":
                    owner_target = fixture["npm_cli"]
                elif label == "bad-owner-npm-dependency":
                    owner_target = fixture["npm_root"] / "node_modules/shared.js"
                elif label == "missing-node":
                    fixture["node"].unlink()
                elif label == "missing-npm-cli":
                    fixture["npm_cli"].unlink()
                elif label == "owner-inaccessible-node":
                    fixture["node"].chmod(0o000)
                elif label == "owner-inaccessible-npm-directory":
                    (fixture["npm_root"] / "node_modules").chmod(0o300)
                elif label == "non-executable-node":
                    fixture["node"].chmod(0o644)
                elif label == "symlinked-node":
                    real_node = fixture["node_root"] / "bin/node-real"
                    fixture["node"].rename(real_node)
                    fixture["node"].symlink_to(real_node.name)
                elif label == "alternate-node-name":
                    alternate = fixture["node_root"] / "bin/validated-node"
                    alternate.write_bytes(fixture["node"].read_bytes())
                    alternate.chmod(0o755)
                    fixture["node"].write_text(
                        chr(35) + "!" + sys.executable + "\nprint('wrong-sibling-node')\n", encoding="utf-8",
                    )
                    fixture["node"].chmod(0o755)
                    paths["node"] = str(alternate)
                elif label == "npm-escape-link":
                    fixture["npm"].unlink()
                    outside = root / "outside-npm-cli.js"
                    outside.write_text("outside synthetic npm cli fixture\n", encoding="ascii")
                    fixture["npm"].symlink_to(outside)
                elif label == "npm-nested-escape-link":
                    nested_link = fixture["npm_root"] / "node_modules/shared-link.js"
                    nested_link.unlink()
                    outside = root / "outside-npm-module.js"
                    outside.write_text("outside synthetic npm module fixture\n", encoding="ascii")
                    nested_link.symlink_to(outside)
                elif label == "world-writable-npm-dependency-dir":
                    (fixture["npm_root"] / "node_modules").chmod(0o777)
                elif label == "world-writable-npm-dependency-file":
                    (fixture["npm_root"] / "node_modules/shared.js").chmod(0o666)
                elif label == "npm-cli-writable":
                    fixture["npm_cli"].chmod(0o666)

                with self._node_fixture_policy(fixture):
                    if owner_target is None and foreign_group_target is None:
                        with patch.object(supervisor.subprocess, "run",
                                          side_effect=AssertionError("version command ran before trust refusal")):
                            with self.assertRaises(supervisor.bundle.Refusal) as caught:
                                node_tool_snapshot.create_snapshot(
                                    paths, "test-invalid-layout", os.getuid(), str(deadline_path),
                                    snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                                    source_node_root=fixture["node_root"],
                                    source_anchors=((fixture["anchor"], os.getuid()),),
                                    trusted_source_group_gid=trusted_source_group_gid,
                                )
                    else:
                        original_lstat = os.lstat

                        def lstat_with_untrusted_metadata(path, *args, **kwargs):
                            metadata = original_lstat(path, *args, **kwargs)
                            values = {"st_mode": metadata.st_mode, "st_uid": metadata.st_uid,
                                      "st_gid": metadata.st_gid}
                            if Path(path) == owner_target:
                                values["st_uid"] = os.getuid() + 1
                            if Path(path) == foreign_group_target:
                                values["st_gid"] = os.getgid() + 1
                            if values["st_uid"] != metadata.st_uid or values["st_gid"] != metadata.st_gid:
                                return SimpleNamespace(**values)
                            return metadata

                        with patch.object(supervisor.node_tool_prepare.os, "lstat",
                                          side_effect=lstat_with_untrusted_metadata), \
                                patch.object(supervisor.subprocess, "run",
                                             side_effect=AssertionError("version command ran before owner refusal")):
                            with self.assertRaises(supervisor.bundle.Refusal) as caught:
                                node_tool_snapshot.create_snapshot(
                                    paths, "test-invalid-owner", os.getuid(), str(deadline_path),
                                    snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                                    source_node_root=fixture["node_root"],
                                    source_anchors=((fixture["anchor"], os.getuid()),),
                                    trusted_source_group_gid=trusted_source_group_gid,
                                )
                self.assertEqual(caught.exception.args[0], expected_code)
                self.assertFalse(snapshot_base.exists())
                if label == "owner-inaccessible-node":
                    fixture["node"].chmod(0o755)
                elif label == "owner-inaccessible-npm-directory":
                    (fixture["npm_root"] / "node_modules").chmod(0o755)

    def test_root_source_anchor_never_accepts_runner_group_write_authority(self):
        with tempfile.TemporaryDirectory() as temporary:
            fixture = self._write_node_toolchain_fixture(Path(temporary) / "node-fixture")
            real_lstat = os.lstat

            def group_writable_root(path, *args, **kwargs):
                if Path(path) == Path("/"):
                    return SimpleNamespace(
                        st_mode=stat.S_IFDIR | 0o2775,
                        st_uid=0,
                        st_gid=os.getgid(),
                    )
                return real_lstat(path, *args, **kwargs)

            with patch.object(supervisor.node_tool_prepare.os, "lstat", side_effect=group_writable_root):
                with self.assertRaises(supervisor.bundle.Refusal) as caught:
                    supervisor.node_tool_prepare.validate_node_toolchain(
                        fixture["paths"], os.getuid(), tool_cache_root=fixture["cache"],
                        node_root=fixture["node_root"],
                        system_anchors=((Path("/"), 0), (Path("/opt"), 0)),
                        trusted_source_group_gid=os.getgid(),
                    )

        self.assertEqual(caught.exception.args[0], "node-toolchain-source-root-anchor-write-mode")

    def test_snapshot_rechecks_shared_anchor_before_descriptor_copy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            os.chown(fixture["anchor"], -1, os.getgid())
            fixture["anchor"].chmod(0o2770)
            deadline_path = root / "deadline.json"
            deadline_budget.create(deadline_path, 60, 5, 65)
            snapshot_base = root / "snapshot-base"

            def change_anchor_after_preflight(stage):
                if stage == "after-source-validation":
                    fixture["anchor"].chmod(0o2777)

            try:
                with self._node_fixture_policy(fixture):
                    with self.assertRaises(node_tool_snapshot.SnapshotRefusal) as caught:
                        node_tool_snapshot.create_snapshot(
                            fixture["paths"], "anchor-race", os.getuid(), str(deadline_path),
                            snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                            source_node_root=fixture["node_root"],
                            source_anchors=((fixture["anchor"], os.getuid()),),
                            trusted_source_group_gid=os.getgid(),
                            test_checkpoint=change_anchor_after_preflight,
                        )
            finally:
                fixture["anchor"].chmod(0o2770)

            self.assertEqual(caught.exception.code, "node-toolchain-source-opt-anchor-write-mode")
            self.assertFalse(snapshot_base.exists())

    def test_node_toolchain_scan_permission_failures_have_finite_refusal(self):
        for denied_directory in ("npm_root", "npm_node_modules"):
            with self.subTest(directory=denied_directory), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                fixture = self._write_node_toolchain_fixture(root / "node-fixture")
                deadline_path = root / "deadline.json"
                deadline_budget.create(deadline_path, 60, 5, 65)
                snapshot_base = root / "snapshot-base"
                denied_path = (fixture["npm_root"] if denied_directory == "npm_root"
                               else fixture["npm_root"] / "node_modules")
                real_scandir = os.scandir

                def refuse_scandir(path, *args, **kwargs):
                    if Path(path) == denied_path:
                        raise PermissionError("synthetic permission fixture")
                    return real_scandir(path, *args, **kwargs)

                with self._node_fixture_policy(fixture), \
                        patch.object(supervisor.subprocess, "run",
                                     side_effect=AssertionError("version command ran before scan refusal")), \
                        patch.object(supervisor.node_tool_prepare.os, "scandir", side_effect=refuse_scandir):
                    with self.assertRaises(supervisor.bundle.Refusal) as caught:
                        node_tool_snapshot.create_snapshot(
                            fixture["paths"], "test-scan-access", os.getuid(), str(deadline_path),
                            snapshot_base=snapshot_base, source_cache_root=fixture["cache"],
                            source_node_root=fixture["node_root"],
                            source_anchors=((fixture["anchor"], os.getuid()),),
                        )
                self.assertEqual(caught.exception.args[0], "node-toolchain-directory-scan-access")
                self.assertFalse(snapshot_base.exists())

    def test_root_owned_path_ancestors_and_runner_owned_node_tree_use_only_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            fixture = self._write_node_toolchain_fixture(root / "node-fixture")
            deadline_path = root / "deadline.json"
            deadline_budget.create(deadline_path, 60, 5, 65)
            snapshot_id = "test-mixed-owner-snapshot"
            snapshot_base, snapshot = self._create_node_snapshot(
                fixture, root / "snapshot-base", snapshot_id, deadline_path,
            )
            preparation = supervisor.node_tool_prepare
            supervisor_paths = {"node_snapshot_id": snapshot_id, "cargo": None, "rustc": None}
            previous_deadline_file = supervisor.ACTIVE_DEADLINE_FILE
            real_run = subprocess.run
            calls = []

            def recording_run(argv, **kwargs):
                calls.append((list(argv), dict(kwargs)))
                return real_run(argv, **kwargs)

            try:
                with patch.object(node_tool_snapshot, "DEFAULT_SNAPSHOT_BASE", snapshot_base), \
                        patch.object(preparation, "DEADLINE_FILE", str(deadline_path)), \
                        patch.object(supervisor, "ACTIVE_DEADLINE_FILE", str(deadline_path)), \
                        patch.object(supervisor.subprocess, "run", side_effect=recording_run):
                    validated = node_tool_snapshot.validate_snapshot(
                        snapshot_id, str(deadline_path), snapshot_base=snapshot_base, owner_uid=os.getuid(),
                    )
                    prepared_results = preparation.run_node_versions(
                        validated, preparation._prepare_node_version_process,
                    )
                    supervisor_info = supervisor._preflight_tools(
                        "core-node", {"tools": {"node": "24.22.1", "npm": "11.19.1"}},
                        supervisor_paths, os.getuid(),
                    )
                self.assertEqual(preparation._trusted_toolchain_owner_uids(os.getuid()),
                                 frozenset((0, os.getuid())))
                with self.assertRaises(supervisor.bundle.Refusal) as worker_owner:
                    preparation._trusted_toolchain_owner_uids(preparation.UID)
                self.assertEqual(str(worker_owner.exception), "node-toolchain-owner")
                snapshot_node = str(Path(snapshot["root"]) / "bin/node")
                snapshot_cli = str(Path(snapshot["root"]) / "lib/node_modules/npm/bin/npm-cli.js")
                self.assertEqual(validated["node"], snapshot_node)
                self.assertEqual(prepared_results["node"].stdout.strip(), b"v24.22.1")
                self.assertEqual(prepared_results["npm"].stdout.strip(), b"11.19.1")
                self.assertEqual(supervisor_info["paths"]["node"], snapshot_node)
                rows = [json.loads(line) for line in fixture["log"].read_text().splitlines()]
                self.assertEqual(len(rows), 4)
                self.assertEqual([row["argv"] for row in rows], [
                    ["--version"], [snapshot_cli, "--version"],
                    ["--version"], [snapshot_cli, "--version"],
                ])
                self.assertTrue(all(row["executable"] == snapshot_node for row in rows))
                self.assertTrue(all(row["path"] == "/usr/bin:/bin" and row["node_options"] == "" for row in rows))
                self.assertEqual([argv for argv, _kwargs in calls], [
                    [snapshot_node, "--version"], [snapshot_node, snapshot_cli, "--version"],
                    [snapshot_node, "--version"], [snapshot_node, snapshot_cli, "--version"],
                ])
            finally:
                supervisor.ACTIVE_DEADLINE_FILE = previous_deadline_file
                node_tool_snapshot.remove_snapshot(
                    snapshot_id, str(deadline_path), snapshot_base=snapshot_base, owner_uid=os.getuid(),
                )

    def test_encrypted_workflow_supplies_runner_uid_before_privileged_prepare(self):
        root = Path(__file__).resolve().parents[2]
        job = public_audit.parse_workflow(root / ".github/workflows/devlane-encrypted.yml")[
            public_audit.RUN_JOB
        ]
        source = "\n".join(next(
            step["run"] for step in job["steps"] if step["name"] == "Prepare dependencies before the cut"
        ))
        owner_capture = source.index('owner_uid="$EUID"')
        group_capture = source.index('owner_gid="$(python3 -B kit/devlane/deadline.py run --file "$RUN_ROOT/deadline.json" -- id -g)"')
        privileged_call = source.index("sudo -n unshare")
        self.assertLess(owner_capture, privileged_call)
        self.assertLess(group_capture, privileged_call)
        self.assertIn('--owner-uid "$owner_uid"', source)
        self.assertIn('--owner-gid "$owner_gid"', source)
        self.assertNotIn("command -v node", source)
        self.assertNotIn("command -v npm", source)
        self.assertNotIn("--node-path", source)
        self.assertNotIn("--npm-path", source)

        steps = job["steps"]
        prepare_index = next(i for i, step in enumerate(steps) if step["name"] == "Prepare dependencies before the cut")
        decrypt_index = next(i for i, step in enumerate(steps) if step["name"] == "Decrypt authenticated bundle")
        workflow = (Path(__file__).resolve().parents[2] / ".github/workflows/devlane-encrypted.yml").read_text()
        run_job_source = workflow.split("  devlane-encrypted-run:", 1)[1].split("  devlane-encrypted-audit:", 1)[0]
        self.assertRegex(run_job_source, r"(?m)^    runs-on: \$\{\{ inputs\.runner \}\}$")
        self.assertLess(prepare_index, decrypt_index)
        self.assertFalse(any((step.get("uses") or "").startswith("actions/setup-node@") for step in steps))
        preparation = supervisor.node_tool_prepare
        self.assertIn("node_vendor_source.acquire_node_source", inspect.getsource(preparation.main))
        self.assertIsNone(preparation.NODE_TOOL_SYSTEM_ANCHORS)
        self.assertIsNone(preparation.NODE_TOOL_CACHE_ROOT)

        self.assertEqual(preparation.TRUSTED_TOOLCHAIN_SYSTEM_UID, 0)
        self.assertEqual(preparation._trusted_toolchain_owner_uids(os.getuid()),
                         frozenset((0, os.getuid())))
        self.assertNotIn(preparation.UID, preparation._trusted_toolchain_owner_uids(os.getuid()))

    def test_e2e_node_prepare_uses_current_prepare_cli_without_legacy_node_flags(self):
        preparation = supervisor.node_tool_prepare
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            prepared = root / "prepared"
            captured = {}
            paths = {
                "cargo": "/toolchain/bin/cargo", "rustc": "/toolchain/bin/rustc",
            }

            def prepare(command, **_kwargs):
                captured["command"] = list(command)
                prepared.mkdir()

            with patch.object(test_e2e, "_tool_paths", return_value=dict(paths)), \
                    patch.object(test_e2e, "_run_preparation", side_effect=prepare), \
                    patch.object(test_e2e, "DEADLINE_FILE", str(root / "deadline.json")), \
                    patch.object(test_e2e, "CONTROL_SHA", "a" * 40):
                resolved = test_e2e._prepare(
                    "core-node", root / "projection.json", prepared,
                )

            command = captured["command"]
            script = str(Path(test_e2e.ROOT) / "kit/devlane/prepare.py")
            arguments = command[command.index(script) + 1:]
            parsed = preparation._argument_parser().parse_args(arguments)
            self.assertEqual(parsed.profile, "core-node")
            self.assertEqual(parsed.cargo_path, paths["cargo"])
            self.assertEqual(parsed.rustc_path, paths["rustc"])
            self.assertTrue(parsed.node_snapshot_id)
            self.assertNotIn("--node-path", arguments)
            self.assertNotIn("--npm-path", arguments)
            self.assertEqual(resolved["cargo"], paths["cargo"])

    def test_prepare_main_reports_exact_owner_and_exception_categories_without_reflection(self):
        preparation = supervisor.node_tool_prepare
        for failure_kind in ("foreign-owner", "version-permission"):
            with self.subTest(failure_kind=failure_kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                snapshot_id = "test-prepare-failure"
                vendor_base, vendor_area, fixture, vendor = self._write_node_vendor_fixture(root, snapshot_id)
                lock = test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
                _projection, payload = test_e2e._node_projection(lock)
                projection_path = root / "projection.json"
                projection_path.write_bytes(payload)
                deadline_path = root / "deadline.json"
                deadline_budget.create(deadline_path, 60, 5, 65)
                snapshot_base = root / "snapshot-base"
                arguments = [
                    "--projection", str(projection_path), "--output", str(root / "prepared"),
                    "--profile", "core-node", "--owner-uid", str(os.getuid()),
                    "--owner-gid", str(os.getgid()), "--deadline-file", str(deadline_path),
                    "--node-snapshot-id", snapshot_id,
                ]
                real_lstat = os.lstat

                def lstat_with_foreign_owner(path, *args, **kwargs):
                    metadata = real_lstat(path, *args, **kwargs)
                    if failure_kind == "foreign-owner" and Path(path) == fixture["cache"]:
                        return SimpleNamespace(st_mode=metadata.st_mode, st_uid=os.getuid() + 1)
                    return metadata

                stderr = io.StringIO()
                command_calls = []

                def refuse_version_or_mount(argv, **kwargs):
                    command_calls.append(list(argv))
                    if failure_kind == "version-permission":
                        raise PermissionError("private path KEYCANARY-73A10X")
                    raise AssertionError("version command ran before owner refusal")

                snapshot_node = str(snapshot_base / snapshot_id / "bin/node")

                previous_deadline = preparation.DEADLINE_FILE
                try:
                    with self._node_fixture_policy(fixture), \
                            patch.object(preparation.sys, "platform", "linux"), \
                            patch.object(preparation, "os", _RootEffectiveUIDProxy()), \
                            patch.object(preparation.node_vendor_source, "PROTECTED_BASE", vendor_base), \
                            patch.object(preparation, "_node_vendor_system_anchors",
                                         return_value=((vendor_area, os.getuid()),)), \
                            patch.object(preparation.node_vendor_source, "acquire_node_source",
                                         return_value=vendor), \
                            patch.object(node_tool_snapshot, "DEFAULT_SNAPSHOT_BASE", snapshot_base), \
                            patch.object(preparation.os, "lstat", side_effect=lstat_with_foreign_owner), \
                            patch.object(preparation.subprocess, "run", side_effect=refuse_version_or_mount), \
                            patch.object(preparation, "_kill_children"), \
                            patch.object(preparation, "MOUNT_TARGETS", []), \
                            contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(stderr):
                        result = preparation.main(arguments)
                finally:
                    preparation.DEADLINE_FILE = previous_deadline

                self.assertEqual(result, 2)
                self.assertEqual(command_calls, [] if failure_kind == "foreign-owner" else [
                    [snapshot_node, "--version"],
                ])
                expected = (
                    "dependency_preparation_refusal=stage=prepare-node-toolchain-snapshot "
                    "code=node-toolchain-owner cleanup=confirmed\n"
                    if failure_kind == "foreign-owner" else
                    "dependency_preparation_exception=stage=prepare-node-version-verification "
                    "class=permission-denied cleanup=confirmed\n"
                )
                self.assertEqual(stderr.getvalue(), expected)
                self.assertNotIn("private path", stderr.getvalue())
                self.assertNotIn("KEYCANARY-73A10X", stderr.getvalue())

    def test_actual_start_requires_snapshot_identity_without_system_fallback(self):
        for case in ("missing-snapshot", "invalid-snapshot"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                args = self._write_projection_startup_fixture(root)
                projection, _payload = test_e2e._node_projection(
                    test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
                )
                self._bind_projection_payload(args, projection)
                command = ["start"]
                for name in ("state_dir", "context", "workspace", "prepared", "bundle", "projection",
                             "positive_control", "deadline_file"):
                    command.extend(("--" + name.replace("_", "-"), getattr(args, name)))
                expected = "node-snapshot-id"
                if case == "invalid-snapshot":
                    command.extend(("--node-snapshot-id", "../outside"))
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.object(supervisor.sys, "platform", "linux"), \
                        patch.object(supervisor.shutil, "which") as which, \
                        patch.object(supervisor.subprocess, "Popen") as spawn, \
                        contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    result = supervisor.main(command)
                self.assertEqual(result, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "devlane_supervisor_refusal=" + expected + "\n")
                which.assert_not_called()
                spawn.assert_not_called()
                Path(args.state_dir).rmdir()

        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
            supervisor._argument_parser().parse_args([
                "start", "--state-dir", "state", "--context", "context", "--workspace", "workspace",
                "--prepared", "prepared", "--bundle", "bundle", "--projection", "projection",
                "--positive-control", "positive", "--deadline-file", "deadline", "--node-path", "unsafe",
            ])
        self.assertEqual(caught.exception.code, 2)

    def test_actual_supervisor_probe_and_decrypt_clients_emit_only_fixed_success_markers(self):
        with patch.object(supervisor, "_rpc", return_value={"ok": True}) as rpc:
            probe_out, probe_err = io.StringIO(), io.StringIO()
            with contextlib.redirect_stdout(probe_out), contextlib.redirect_stderr(probe_err):
                probe_code = supervisor.main(["probe", "--state-dir", "/source-free/state"])
            probe = subprocess.CompletedProcess(
                ["supervisor.py", "probe"], probe_code, probe_out.getvalue().encode(), probe_err.getvalue().encode(),
            )
            self.assertIsNone(test_e2e._assert_supervisor_probe_pass(probe))
            rpc.assert_called_once_with("/source-free/state", {"op": "probe"})

        rpc.reset_mock()
        rpc.return_value = {"ok": True}
        with patch.dict(os.environ, {"DEVLANE_DECRYPT_KEY": "a" * 64}):
            decrypt_out, decrypt_err = io.StringIO(), io.StringIO()
            with patch.object(supervisor, "_rpc", rpc), \
                    contextlib.redirect_stdout(decrypt_out), contextlib.redirect_stderr(decrypt_err):
                decrypt_code = supervisor.main(["decrypt", "--state-dir", "/source-free/state"])
            self.assertNotIn("DEVLANE_DECRYPT_KEY", os.environ)
        decrypt = subprocess.CompletedProcess(
            ["supervisor.py", "decrypt"], decrypt_code,
            decrypt_out.getvalue().encode(), decrypt_err.getvalue().encode(),
        )
        self.assertIsNone(test_e2e._assert_supervisor_decrypt_pass(decrypt))
        rpc.assert_called_once_with("/source-free/state", {"op": "decrypt", "key": "a" * 64})

        class RefusingSocket:
            def __init__(self):
                response = json.dumps({"ok": False, "code": "decrypt-rejected"},
                                      separators=(",", ":")).encode("ascii")
                self.buffer = len(response).to_bytes(4, "big") + response
                self.sent = b""

            def settimeout(self, _timeout):
                return None

            def connect(self, _path):
                return None

            def sendall(self, value):
                self.sent += value

            def recv(self, amount):
                value, self.buffer = self.buffer[:amount], self.buffer[amount:]
                return value

            def close(self):
                return None

        refusing_socket = RefusingSocket()
        with patch.dict(os.environ, {"DEVLANE_DECRYPT_KEY": "b" * 64}):
            refused_out, refused_err = io.StringIO(), io.StringIO()
            with patch.object(supervisor.socket, "socket", return_value=refusing_socket), \
                    contextlib.redirect_stdout(refused_out), contextlib.redirect_stderr(refused_err):
                refused_code = supervisor.main(["decrypt", "--state-dir", "/source-free/state"])
            self.assertNotIn("DEVLANE_DECRYPT_KEY", os.environ)
        refused = subprocess.CompletedProcess(
            ["supervisor.py", "decrypt"], refused_code,
            refused_out.getvalue().encode(), refused_err.getvalue().encode(),
        )
        self.assertIsNone(test_e2e._assert_supervisor_refusal(refused, "decrypt-rejected"))
        self.assertNotIn(b"b" * 64, refused.stdout + refused.stderr)
        self.assertTrue(refusing_socket.sent.startswith((len(b'{"op":"decrypt","key":"' + b"b" * 64 + b'"}')).to_bytes(4, "big")))

    def test_network_probe_failure_sites_and_refusal_reason_are_distinct(self):
        service = object.__new__(supervisor.Service)
        service.root = Path("/source-free/root")
        service.host_net_inode = 100
        service.probe_namespace_inode = None

        def verify(result=None, error=None):
            with patch.object(supervisor.network_probe, "firewall_snapshot",
                              return_value={"netns_inode": 200}), \
                    patch.object(supervisor.subprocess, "run",
                                 side_effect=error if error is not None else None,
                                 return_value=result), \
                    patch.object(supervisor, "_bounded_timeout", return_value=30), \
                    patch.object(supervisor.os, "stat", return_value=SimpleNamespace(st_ino=200)):
                return service._verify_network_cut()

        def verify_with_diagnostic(result=None, error=None):
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                try:
                    verify(result, error)
                except supervisor.SupervisorRefusal as refusal:
                    return refusal, output.getvalue()
            self.fail("probe unexpectedly passed")

        self.assertTrue(verify(subprocess.CompletedProcess(
            ["network_probe.py"], 0, b"network_probe=pass\n", b"")))
        refusal = "network-probe-refusal:network-address-unexpected"
        cases = (
            (subprocess.CompletedProcess(
                ["network_probe.py"], 2, b"", b"network_probe_refusal=network-address-unexpected\n"),
             refusal),
            (subprocess.CompletedProcess(["network_probe.py"], 2, b"", b"private-path\n"),
             "network-probe-command-failed"),
            (subprocess.CompletedProcess(["network_probe.py"], 0, b"wrong\n", b""),
             "network-probe-output-invalid"),
        )
        for result, expected in cases:
            with self.subTest(expected=expected):
                caught, diagnostic = verify_with_diagnostic(result)
                self.assertEqual(caught.code, expected)
                expected_probe_code = (
                    "network_probe_refusal=network-address-unexpected\n"
                    if expected == refusal else
                    "network_probe_refusal=probe-output-invalid\n"
                    if expected == "network-probe-output-invalid" else
                    "network_probe_refusal=probe-command-failed\n"
                )
                self.assertEqual(diagnostic, expected_probe_code)

        route_detail = (
            "route[table=main,type=unicast,family=4,dst=0.0.0.0/0,"
            "oif=lo,proto=boot,scope=universe]"
        )
        detailed = subprocess.CompletedProcess(
            ["network_probe.py"], 2, b"",
            ("network_probe_refusal=network-route-unexpected " + route_detail + "\n").encode("ascii"),
        )
        caught, diagnostic = verify_with_diagnostic(detailed)
        self.assertEqual(caught.code,
                         "network-probe-refusal:network-route-unexpected " + route_detail)
        self.assertEqual(diagnostic, "network_probe_refusal=network-route-unexpected " + route_detail + "\n")
        caught, diagnostic = verify_with_diagnostic(error=subprocess.TimeoutExpired(["network_probe.py"], 30))
        self.assertEqual(caught.code, "network-probe-command-failed")
        self.assertEqual(diagnostic, "network_probe_refusal=probe-command-timeout\n")

    def test_supervisor_probe_uses_staged_chroot_copy_and_namespace_root_as_working_directory(self):
        service = object.__new__(supervisor.Service)
        service.root = Path("/source-free/root")
        service.host_net_inode = 100
        service.probe_namespace_inode = None
        result = subprocess.CompletedProcess(["network_probe.py"], 0, b"network_probe=pass\n", b"")
        runner = Mock(return_value=result)
        with patch.object(supervisor.network_probe, "firewall_snapshot", return_value={"netns_inode": 200}), \
                patch.object(supervisor.subprocess, "run", runner), \
                patch.object(supervisor, "_bounded_timeout", return_value=30), \
                patch.object(supervisor.os, "stat", return_value=SimpleNamespace(st_ino=200)):
            service._verify_network_cut()
        argv = runner.call_args.args[0]
        self.assertEqual(argv[13], "/control/network_probe.py")
        self.assertEqual(runner.call_args.kwargs["cwd"], str(service.root))

    def test_network_probe_diagnostic_preserves_only_fixed_refusal_code(self):
        code = "network-probe-refusal:network-address-unexpected"
        result = subprocess.CompletedProcess(
            ["supervisor.py", "probe"], 2, b"",
            ("devlane_supervisor_refusal=" + code + "\n").encode("ascii"),
        )
        test_e2e.DIAGNOSTICS.reset()
        try:
            with self.assertRaises(test_e2e.StartupRefusalMismatch) as caught:
                with test_e2e.DIAGNOSTICS.phase("variant-supervisor-probe-check"):
                    test_e2e._assert_supervisor_probe_pass(result)
            self.assertEqual(caught.exception.category, code)
            line = test_e2e.DIAGNOSTICS.refusal_line(caught.exception)
            self.assertEqual(
                line,
                "devlane_production_e2e=refused stage=variant-supervisor-probe-check exception=" + code,
            )
            self.assertTrue(diagnostic_contract.public_preparation_diagnostic(line))
            self.assertFalse(diagnostic_contract.public_preparation_diagnostic(
                line.replace("network-address-unexpected", "private-path"),
            ))
        finally:
            test_e2e.DIAGNOSTICS.reset()

        structure_code = (
            "network-probe-refusal:network-structure-invalid:netlink-message-port-id"
        )
        structure_result = subprocess.CompletedProcess(
            ["supervisor.py", "probe"], 2, b"",
            ("devlane_supervisor_refusal=" + structure_code + "\n").encode("ascii"),
        )
        test_e2e.DIAGNOSTICS.reset()
        try:
            with self.assertRaises(test_e2e.StartupRefusalMismatch) as caught:
                with test_e2e.DIAGNOSTICS.phase("variant-supervisor-probe-check"):
                    test_e2e._assert_supervisor_probe_pass(structure_result)
            self.assertEqual(caught.exception.category, structure_code)
            line = test_e2e.DIAGNOSTICS.refusal_line(caught.exception)
            self.assertEqual(
                line,
                "devlane_production_e2e=refused stage=variant-supervisor-probe-check exception="
                + structure_code,
            )
            self.assertTrue(diagnostic_contract.public_preparation_diagnostic(line))
        finally:
            test_e2e.DIAGNOSTICS.reset()

        route_detail = (
            "route[table=main,type=unicast,family=4,dst=0.0.0.0/0,"
            "oif=lo,proto=boot,scope=universe]"
        )
        detailed_code = "network-probe-refusal:network-route-unexpected " + route_detail
        detailed = subprocess.CompletedProcess(
            ["supervisor.py", "probe"], 2, b"",
            ("devlane_supervisor_refusal=" + detailed_code + "\n").encode("ascii"),
        )
        test_e2e.DIAGNOSTICS.reset()
        try:
            with self.assertRaises(test_e2e.StartupRefusalMismatch) as caught:
                with test_e2e.DIAGNOSTICS.phase("variant-supervisor-probe-check"):
                    test_e2e._assert_supervisor_probe_pass(detailed)
            self.assertEqual(caught.exception.category, detailed_code)
            line = test_e2e.DIAGNOSTICS.refusal_line(caught.exception)
            self.assertEqual(
                line,
                "devlane_production_e2e=refused stage=variant-supervisor-probe-check exception="
                + detailed_code,
            )
            self.assertTrue(diagnostic_contract.public_preparation_diagnostic(line))
            self.assertFalse(diagnostic_contract.public_preparation_diagnostic(
                line.replace("oif=lo", "oif=private/path"),
            ))
        finally:
            test_e2e.DIAGNOSTICS.reset()

    def test_network_route_detail_reaches_the_printed_acceptance_line(self):
        route_detail = (
            "route[table=n9999999999,type=n999,family=6,"
            "dst=ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128,"
            "oif=abcdefghijklmno,proto=n999,scope=n999]"
        )
        probe_result = subprocess.CompletedProcess(
            ["network_probe.py"], 2, b"",
            ("network_probe_refusal=network-route-unexpected " + route_detail + "\n").encode("ascii"),
        )
        service = object.__new__(supervisor.Service)
        service.root = Path("/source-free/root")
        service.host_net_inode = 100
        service.probe_namespace_inode = None
        with patch.object(supervisor.network_probe, "firewall_snapshot",
                          return_value={"netns_inode": 200}), \
                patch.object(supervisor.subprocess, "run", return_value=probe_result), \
                patch.object(supervisor, "_bounded_timeout", return_value=30):
            with self.assertRaises(supervisor.SupervisorRefusal) as caught:
                service._verify_network_cut()
        self.assertEqual(
            caught.exception.code,
            "network-probe-refusal:network-route-unexpected " + route_detail,
        )

        supervisor_stdout, supervisor_stderr = io.StringIO(), io.StringIO()
        with patch.object(supervisor, "_rpc", side_effect=caught.exception), \
                contextlib.redirect_stdout(supervisor_stdout), \
                contextlib.redirect_stderr(supervisor_stderr):
            self.assertEqual(supervisor.main(["probe", "--state-dir", "/source-free/state"]), 2)
        supervisor_result = subprocess.CompletedProcess(
            ["supervisor.py", "probe"], 2,
            supervisor_stdout.getvalue().encode("ascii"),
            supervisor_stderr.getvalue().encode("ascii"),
        )

        test_e2e.DIAGNOSTICS.reset()
        try:
            with self.assertRaises(test_e2e.StartupRefusalMismatch) as e2e_failure:
                with test_e2e.DIAGNOSTICS.phase("variant-supervisor-probe-check"):
                    test_e2e._assert_supervisor_probe_pass(supervisor_result)
            line = test_e2e.DIAGNOSTICS.refusal_line(e2e_failure.exception)
            self.assertEqual(
                line,
                "devlane_production_e2e=refused stage=variant-supervisor-probe-check "
                "exception=network-probe-refusal:network-route-unexpected " + route_detail,
            )
            self.assertTrue(diagnostic_contract.public_preparation_diagnostic(line))

            with tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "acceptance.log"
                output.write_text(line + "\n", encoding="ascii")
                printed = io.StringIO()
                with contextlib.redirect_stdout(printed):
                    self.assertEqual(acceptance_diagnostics.main([
                        "--stage", "production-path-e2e", "--file", str(output),
                    ]), 0)
                self.assertEqual(printed.getvalue(), line + "\n")
        finally:
            test_e2e.DIAGNOSTICS.reset()

    def _write_projection_startup_fixture(self, root):
        workspace = root / "workspace"
        prepared = root / "prepared"
        workspace.mkdir()
        prepared.mkdir()
        bundle_path = root / "bundle.enc"
        bundle_bytes = b"source-free encrypted envelope placeholder"
        bundle_path.write_bytes(bundle_bytes)
        projection_path = root / "projection.json"
        _projection, projection_bytes = test_e2e._node_projection(
            test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
        )
        projection_path.write_bytes(projection_bytes + b" ")
        now = int(time.time())
        context = {
            "repository": test_e2e.fetch.REPOSITORY, "repository_id": test_e2e.fetch.REPOSITORY_ID,
            "server_url": "https://github.com", "event": "workflow_dispatch", "ref": "refs/heads/main",
            "control_sha": "a" * 40, "control_run_id": "123456", "workflow_path": test_e2e.fetch.WORKFLOW_PATH,
            "run_attempt": 1, "profile": "core-node", "wave_id": "startup-wave-0001",
            "bundle_id": "startup-bundle-0001", "bundle_asset_id": "1234567",
            "bundle_sha256": test_e2e.hashlib.sha256(bundle_bytes).hexdigest(), "bundle_size": len(bundle_bytes),
            "projection_asset_id": "1234568", "projection_sha256": test_e2e.hashlib.sha256(projection_bytes).hexdigest(),
            "projection_size": len(projection_bytes), "expires": now + 1800,
        }
        context_path = root / "context.json"
        context_path.write_bytes(test_e2e.bundle.canonical_json(context) + b"\n")
        positive_path = root / "positive-control.json"
        positive_path.write_bytes(test_e2e.bundle.canonical_json(
            {"connected": True, "target": "public-tls-control"}
        ) + b"\n")
        deadline_path = root / "deadline.json"
        deadline_budget.create(deadline_path, 60, 5, 65)
        return argparse.Namespace(
            state_dir=str(root / "state"), context=str(context_path), workspace=str(workspace),
            prepared=str(prepared), bundle=str(bundle_path), projection=str(projection_path),
            positive_control=str(positive_path), deadline_file=str(deadline_path),
            node_path="", npm_path="", cargo_path="", rustc_path="",
        )

    def _bind_projection_payload(self, args, value):
        payload = test_e2e.bundle.canonical_json(value)
        Path(args.projection).write_bytes(payload)
        context = json.loads(Path(args.context).read_text(encoding="ascii"))
        context["projection_sha256"] = test_e2e.hashlib.sha256(payload).hexdigest()
        context["projection_size"] = len(payload)
        Path(args.context).write_bytes(test_e2e.bundle.canonical_json(context) + b"\n")

    def test_actual_start_refuses_a_tampered_projection_before_state_or_child_setup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self._write_projection_startup_fixture(root)
            command = ["start"]
            for name in ("state_dir", "context", "workspace", "prepared", "bundle", "projection",
                         "positive_control", "deadline_file"):
                command.extend(("--" + name.replace("_", "-"), getattr(args, name)))
            stdout, stderr = io.StringIO(), io.StringIO()
            with patch.object(supervisor.sys, "platform", "linux"), \
                    patch.object(supervisor.subprocess, "Popen") as spawn:
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    result = supervisor.main(command)
            self.assertEqual(result, 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertEqual(stderr.getvalue(), "devlane_supervisor_refusal=projection-binding-mismatch\n")
            self.assertIsNone(test_e2e._assert_startup_projection_refusal(subprocess.CompletedProcess(
                ["supervisor.py", *command], result, stdout.getvalue().encode(), stderr.getvalue().encode(),
            )))
            self.assertFalse(Path(args.state_dir).exists())
            spawn.assert_not_called()

    def test_actual_service_prepare_binds_projection_before_root_swap_firewall_or_mounts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self._write_projection_startup_fixture(root)
            previous_deadline_file = supervisor.ACTIVE_DEADLINE_FILE
            try:
                service = supervisor.Service(
                    args.state_dir, args.context, args.workspace, args.prepared, args.bundle,
                    args.projection, 1, os.getuid(), {}, args.deadline_file,
                )
                with patch.object(supervisor, "_require_linux_root") as linux_root, \
                        patch.object(supervisor, "_require_swap_disabled") as swap, \
                        patch.object(supervisor, "_mount_private") as private_mount, \
                        patch.object(supervisor, "_configure_firewall") as firewall, \
                        patch.object(supervisor, "_mount_minimal_root") as minimal_root, \
                        patch.object(supervisor, "_mount_bind") as bind:
                    with self.assertRaises(supervisor.SupervisorRefusal) as caught:
                        service.prepare()
                self.assertEqual(caught.exception.code, "projection-binding-mismatch")
                for setup in (linux_root, swap, private_mount, firewall, minimal_root, bind):
                    setup.assert_not_called()
            finally:
                supervisor.ACTIVE_DEADLINE_FILE = previous_deadline_file

    def test_invalid_bound_projection_has_a_fixed_refusal_before_service_setup(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            args = self._write_projection_startup_fixture(root)
            projection, _payload = test_e2e._node_projection(
                test_e2e._node_lock_from_reviewed({"typescript": "6.0.3"})
            )
            projection["playwright"] = [{}]
            self._bind_projection_payload(args, projection)
            previous_deadline_file = supervisor.ACTIVE_DEADLINE_FILE
            try:
                service = supervisor.Service(
                    args.state_dir, args.context, args.workspace, args.prepared, args.bundle,
                    args.projection, 1, os.getuid(), {}, args.deadline_file,
                )
                with patch.object(supervisor, "_require_linux_root") as linux_root, \
                        patch.object(supervisor, "_require_swap_disabled") as swap, \
                        patch.object(supervisor, "_mount_private") as private_mount, \
                        patch.object(supervisor, "_configure_firewall") as firewall, \
                        patch.object(supervisor, "_mount_minimal_root") as minimal_root:
                    with self.assertRaises(supervisor.SupervisorRefusal) as caught:
                        service.prepare()
                self.assertEqual(caught.exception.code, "projection-invalid")
                for setup in (linux_root, swap, private_mount, firewall, minimal_root):
                    setup.assert_not_called()

                command = ["start"]
                for name in ("state_dir", "context", "workspace", "prepared", "bundle", "projection",
                             "positive_control", "deadline_file"):
                    command.extend(("--" + name.replace("_", "-"), getattr(args, name)))
                stdout, stderr = io.StringIO(), io.StringIO()
                with patch.object(supervisor.sys, "platform", "linux"), \
                        contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    result = supervisor.main(command)
                self.assertEqual(result, 2)
                self.assertEqual(stdout.getvalue(), "")
                self.assertEqual(stderr.getvalue(), "devlane_supervisor_refusal=projection-invalid\n")
                with self.assertRaises(test_e2e.StartupRefusalMismatch) as mismatch:
                    test_e2e._assert_startup_projection_refusal(subprocess.CompletedProcess(
                        ["supervisor.py", *command], result, stdout.getvalue().encode(), stderr.getvalue().encode(),
                    ))
                self.assertEqual(mismatch.exception.category, "projection-invalid")
                self.assertFalse(Path(args.state_dir).exists())
            finally:
                supervisor.ACTIVE_DEADLINE_FILE = previous_deadline_file

    def test_isolated_rust_runner_launch_imports_only_the_trusted_control_siblings(self):
        root = Path(__file__).resolve().parents[2]
        supervisor_source = inspect.getsource(supervisor)
        runner_source = (root / "kit/devlane/rust_matrix_runner.py").read_text(encoding="utf-8")
        self.assertIn('"/usr/bin/python3", "-B", "-I", "-S", "/control/devlane/rust_matrix_runner.py"',
                      supervisor_source)
        self.assertIn('control_root / "kit/devlane", root / "control/devlane", readonly=True',
                      supervisor_source)
        self.assertNotIn("/workspace/source/rust_matrix_runner.py", supervisor_source)
        self.assertIn("sys.path.insert(0, str(Path(__file__).resolve().parent))", runner_source)
        with tempfile.TemporaryDirectory() as temporary:
            candidate = Path(temporary)
            (candidate / "bundle.py").write_text(
                "raise RuntimeError('candidate-import-canary')\n", encoding="ascii",
            )
            (candidate / "rust_test_runner.py").write_text(
                "raise RuntimeError('candidate-import-canary')\n", encoding="ascii",
            )
            environment = os.environ.copy()
            environment["PYTHONPATH"] = str(candidate)
            result = subprocess.run(
                [sys.executable, "-B", "-I", "-S", str(root / "kit/devlane/rust_matrix_runner.py")],
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=candidate, env=environment, timeout=10, check=False,
            )
            self.assertEqual(result.returncode, 2, result.stderr.decode("utf-8", "replace"))
            self.assertIn(b"the following arguments are required", result.stderr)
            self.assertNotIn(b"ModuleNotFoundError", result.stderr)
            self.assertNotIn(b"candidate-import-canary", result.stderr)

    def test_standalone_cargo_vet_child_receives_the_trusted_cargo_path(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = Mock(pid=321, wait=Mock(return_value=0))
            with patch.object(rust_matrix_runner, "RAW", temporary), \
                    patch.object(rust_matrix_runner, "_remaining", return_value=30), \
                    patch.object(rust_matrix_runner.subprocess, "Popen", return_value=process) as spawn:
                code, _ = rust_matrix_runner._run(
                    "fixed-vet-environment",
                    ["/prepared/devlane-tools/cargo-vet", "vet", "check", "--locked", "--frozen"],
                    time.monotonic() + 30,
                )
            self.assertEqual(code, 0)
            child_env = spawn.call_args.kwargs["env"]
            self.assertEqual(child_env["CARGO"], "/tools/rust/bin/cargo")
            self.assertEqual(child_env["CARGO_HOME"], "/scratch/cargo-home")
            self.assertEqual(child_env["CARGO_NET_OFFLINE"], "true")

    def test_advisory_database_copy_matches_cargo_deny_default_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = root / "tools"
            source = tools / "advisory-db" / "crates" / "fixture"
            source.mkdir(parents=True)
            (source / "RUSTSEC-2026-0001.md").write_text("source-free advisory", encoding="ascii")
            cargo_home = root / "cargo-home"
            cargo_home.mkdir()
            with patch.object(rust_matrix_runner, "TOOLS_ROOT", str(tools)), \
                    patch.object(rust_matrix_runner, "_remaining", return_value=30):
                rust_matrix_runner._copy_advisory_database(30, cargo_home=str(cargo_home))
            expected = cargo_home / "advisory-dbs" / rust_matrix_runner.ADVISORY_DB_DIRECTORY
            self.assertEqual((expected / "crates/fixture/RUSTSEC-2026-0001.md").read_text(encoding="ascii"),
                             "source-free advisory")
            self.assertFalse((cargo_home / "advisory-db").exists())

    def test_shared_harness_deadline_caps_repeated_phase_timeout(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "deadline.json"
            deadline_budget.create(path, 45, 5, 50)
            with patch.object(test_e2e, "DEADLINE_FILE", str(path)):
                self.assertLessEqual(test_e2e._bounded_timeout(3600), 45)
                self.assertLessEqual(test_e2e._bounded_timeout(2400), 45)
        source = inspect.getsource(test_e2e._run_variant)
        self.assertIn('"--deadline-file", DEADLINE_FILE', source)

    def test_prepared_readonly_database_cleanup_never_follows_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous_temp = test_e2e.RUNNER_TEMP
            try:
                test_e2e.RUNNER_TEMP = root.resolve()
                prepared = root / "devlane-e2e-owned"
                database = prepared / "devlane-tools/advisory-db/crates"
                database.mkdir(parents=True)
                (database / "public.md").write_text("synthetic advisory", encoding="ascii")
                os.chmod(database, 0o555)
                external = root / "outside"
                external.mkdir()
                outside_mode = external.stat().st_mode & 0o777
                outside_file = external / "must-remain"
                outside_file.write_text("outside", encoding="ascii")
                (prepared / "escape").symlink_to(external, target_is_directory=True)
                test_e2e._remove_owned_prepared_tree(prepared)
                self.assertFalse(prepared.exists())
                self.assertTrue(outside_file.exists())
                self.assertEqual(external.stat().st_mode & 0o777, outside_mode)
            finally:
                test_e2e.RUNNER_TEMP = previous_temp

    def test_key_unlink_failure_still_tears_down_and_preserves_original_error(self):
        for failure_phase in ("start", "decrypt"):
            with self.subTest(phase=failure_phase), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary).resolve()
                scenario = {"profile": "core-node", "name": "unlink-negative",
                            "files": lambda **_kwargs: {}, "allowed_files": {},
                            "allowed_tests": {}, "frames": {}}
                lifecycle = test_e2e._SupervisorLifecycle(root / "devlane-unlink-negative")
                original_unlink = Path.unlink
                def refuse_key(path, *args, **kwargs):
                    if path.name == "synthetic-key.hex":
                        raise PermissionError("synthetic-unlink-failure")
                    return original_unlink(path, *args, **kwargs)
                def process_run(command, **kwargs):
                    if failure_phase in command:
                        raise RuntimeError("original-" + failure_phase + "-failure")
                    marker = (b"offline_supervisor=ready\n" if "start" in command else
                              b"network_cut_probe=pass\n" if "probe" in command else b"")
                    return subprocess.CompletedProcess(command, 0, marker, b"")
                with patch.object(test_e2e, "RUNNER_TEMP", root), \
                        patch.object(test_e2e, "RUN_ID", "unlink-negative"), \
                        patch.object(test_e2e, "_archive", return_value=b"archive"), \
                        patch.object(test_e2e.bundle, "build_envelope", return_value=b"envelope"), \
                        patch.object(test_e2e.bundle, "write_private_key"), \
                        patch.object(test_e2e.bundle, "read_key_file", return_value=b"key"), \
                        patch.object(test_e2e.fetch, "validate_dispatch"), \
                        patch.object(test_e2e, "_positive_control"), \
                        patch.object(test_e2e, "_process_run", side_effect=process_run), \
                        patch.object(Path, "unlink", refuse_key), \
                        patch.object(test_e2e.host_cleanup, "clean") as clean, \
                        patch.object(lifecycle, "confirm_teardown") as confirm:
                    with self.assertRaisesRegex(RuntimeError, "original-" + failure_phase + "-failure"):
                        test_e2e._run_variant(scenario, b"{}", root / "prepared",
                                              {name: "" for name in ("node", "npm", "cargo", "rustc")},
                                              b"k" * 32, "accept", lifecycle)
                    clean.assert_called_once()
                    confirm.assert_called_once()
                    self.assertTrue(lifecycle.start_attempted)
                    self.assertFalse(lifecycle.cleanup_confirmed)

    def test_prepared_tree_is_preserved_when_supervisor_teardown_is_unconfirmed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            previous_temp, previous_run = test_e2e.RUNNER_TEMP, test_e2e.RUN_ID
            test_e2e.RUNNER_TEMP = root
            test_e2e.RUN_ID = "lifecycle-negative"
            scenario = {
                "name": "lifecycle-negative", "profile": "core-node", "payload": b"{}",
                "variants": ("accept",),
            }
            prepared = root / "devlane-e2e-lifecycle-negative-lifecycle-negative"
            marker = prepared / "readonly.db"

            def prepare_fixture(_profile, _projection, destination):
                destination.mkdir()
                (destination / marker.name).write_text("source-free database", encoding="ascii")
                os.chmod(marker, 0o444)
                os.chmod(destination, 0o555)
                return {name: "" for name in ("node", "npm", "cargo", "rustc")}

            evidence = []

            def fail_after_start_attempt(*args):
                lifecycle = args[-1]
                evidence.append(lifecycle)
                lifecycle.note_start_attempt()
                raise RuntimeError("original-execution-failure")

            try:
                with patch.object(test_e2e, "_prepare", side_effect=prepare_fixture), \
                        patch.object(test_e2e, "_run_variant", side_effect=fail_after_start_attempt), \
                        patch.object(test_e2e, "_remove_owned_prepared_tree") as remove_tree:
                    with self.assertRaisesRegex(RuntimeError, "original-execution-failure"):
                        test_e2e._run_scenario(scenario)
                    remove_tree.assert_not_called()
                self.assertEqual(len(evidence), 1)
                self.assertTrue(evidence[0].start_attempted)
                self.assertFalse(evidence[0].cleanup_confirmed)
                self.assertTrue(prepared.is_dir())
                self.assertEqual(prepared.stat().st_mode & 0o777, 0o555)
                self.assertEqual(marker.stat().st_mode & 0o777, 0o444)
            finally:
                if prepared.exists():
                    os.chmod(prepared, 0o700)
                    os.chmod(marker, 0o600)
                    marker.unlink()
                    prepared.rmdir()
                test_e2e.RUNNER_TEMP, test_e2e.RUN_ID = previous_temp, previous_run

    def test_prepared_rust_tool_verification_refuses_a_symlink_escape(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            prepared = base / "prepared"
            tools = prepared / "devlane-tools"
            source = base / "source"
            tools.mkdir(parents=True)
            source.mkdir()
            outside = base / "outside-tool"
            outside.write_text("outside", encoding="ascii")
            for name in rust_tooling.TOOLS:
                (tools / name).symlink_to(outside) if name == "cargo-deny" else (tools / name).write_text("tool")
                (source / name).write_text("tool")
            (tools / "advisory-db").mkdir()
            (tools / "advisory-db-revision").write_text("0" * 40, encoding="ascii")
            for entry in rust_tooling.TOOLS:
                (source / entry).write_text("tool")
            (tools / rust_tooling.SEMVER_RECEIPT).write_text("{}", encoding="ascii")
            outside_mode = outside.stat().st_mode & 0o777
            with patch.object(test_e2e.semver_stage, "verify_tool"), \
                    self.assertRaisesRegex(RuntimeError, "rust-matrix-tool-layout"):
                test_e2e._verify_prepared_rust_tools(prepared, source)
            self.assertEqual(outside.stat().st_mode & 0o777, outside_mode)

    def test_trusted_profile_is_exactly_the_runner_contract_and_has_no_commands(self):
        root = Path(__file__).resolve().parents[2]
        profile_path = root / "ci/devlane-profiles.json"
        document = json.loads(profile_path.read_text(encoding="utf-8"))
        profile = document["profiles"]["core-rust"]
        self.assertEqual(profile["rust_matrix"], rust_matrix_runner.EXPECTED_MATRIX)
        self.assertEqual(profile["commands"], [])
        self.assertEqual(profile["stages"], ["format", "deny", "audit", "vet", "unit", "semver"])
        self.assertEqual(profile["budget_seconds"], 8700)

    def test_fixed_matrix_runs_each_tool_and_every_workspace_feature_arm(self):
        checks = []
        arms = []
        semver_stages = []

        def simple(records, suite, argv, deadline, timeout=1800):
            checks.append((suite, argv))
            return _coverage(records, suite)

        def rust_arm(records, scope, manifest, workspace_mode, feature_set, config, deadline):
            arms.append((scope, manifest, workspace_mode, feature_set))
            suffix = "all-features" if feature_set == "all" else "default"
            return _coverage(records, scope + "-" + suffix)

        def replay(records, feature_set, deadline):
            suffix = "all-features" if feature_set == "all" else "default"
            return _coverage(records, "fuzz-replay-" + suffix)

        def semver(records, deadline):
            semver_stages.append(deadline)
            records.extend(rust_matrix_runner.semver_stage.records_for_exit(0))
            return True

        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "matrix.jsonl"
            deadline = time.monotonic() + 60
            with patch.object(rust_matrix_runner, "_copy_advisory_database"), \
                    patch.object(rust_matrix_runner, "_simple_check", side_effect=simple), \
                    patch.object(rust_matrix_runner, "_rust_test_arm", side_effect=rust_arm), \
                    patch.object(rust_matrix_runner, "_fuzz_replay", side_effect=replay), \
                    patch.object(rust_matrix_runner, "_semver_check", side_effect=semver):
                result = rust_matrix_runner.run(
                    rust_matrix_runner.EXPECTED_MATRIX, "fixed-test-map", str(report), deadline,
                )
            self.assertEqual(result, 0)
            records = [json.loads(line) for line in report.read_text(encoding="ascii").splitlines()]
            suites = [row["suite"] for row in records if row["kind"] == "coverage"]
            self.assertEqual(suites, rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"])
            self.assertEqual(len(checks), 12)
            self.assertEqual(len(arms), 8)
            self.assertEqual(semver_stages, [deadline])
            self.assertEqual(
                {(scope, workspace_mode, mode) for scope, _, workspace_mode, mode in arms},
                {(scope, workspace_mode, mode)
                 for scope, workspace_mode in (("root", "workspace"), ("runtime", "workspace"),
                                                ("fuzz", "package"), ("listener", "package"))
                 for mode in ("default", "all")},
            )
            self.assertEqual(
                {manifest for scope, manifest, _, _ in arms if scope == "listener"},
                {"/workspace/source/runtime/crates/services/listener/Cargo.toml"},
            )
            self.assertEqual(
                [row["suite"] for row in records if row["kind"] == "coverage"][-3:],
                ["fuzz-replay-default", "fuzz-replay-all-features", "semver-runtime"],
            )
            self.assertTrue(all(row["ignored"] == 0 for row in records))
            fmt_argv = {suite: argv for suite, argv in checks if suite.startswith("fmt-")}
            self.assertIn("--all", fmt_argv["fmt-root"])
            self.assertIn("--all", fmt_argv["fmt-runtime"])
            self.assertNotIn("--all", fmt_argv["fmt-fuzz"])

    def test_cargo_test_uses_only_workspace_flag_for_actual_workspaces(self):
        for scope, mode, manifest, expected_workspace_flag in (
            ("root", "workspace", "/workspace/source/Cargo.toml", True),
            ("runtime", "workspace", "/workspace/source/runtime/Cargo.toml", True),
            ("fuzz", "package", "/workspace/source/fuzz/Cargo.toml", False),
            ("listener", "package", "/workspace/source/runtime/crates/services/listener/Cargo.toml", False),
        ):
            with self.subTest(scope=scope), tempfile.TemporaryDirectory() as temporary:
                captured = []
                compile_log = Path(temporary) / "compile.jsonl"
                compile_log.write_text("", encoding="ascii")
                with patch.object(rust_matrix_runner, "_run", return_value=(1, compile_log)) as run:
                    records = []
                    result = rust_matrix_runner._rust_test_arm(
                        records, scope, manifest, mode, "default", "fixed-map", time.monotonic() + 30,
                    )
                    captured.extend(run.call_args.args[1])
                self.assertFalse(result)
                self.assertEqual("--workspace" in captured, expected_workspace_flag)
                self.assertIn("--all-targets", captured)
                self.assertIn("--locked", captured)
                self.assertIn("--offline", captured)
                self.assertIn("--no-run", captured)

    def test_fuzz_replay_requires_a_valid_positive_corpus_count(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "captured.stdout"
            calls = []
            counts = iter((87, 0))

            def command(label, argv, deadline, timeout=1800, cwd=None, json_stdout=False):
                calls.append((label, argv))
                output.write_text("Replayed %d parser corpus seeds.\n" % next(counts), encoding="ascii")
                return 0, output

            records = []
            with patch.object(rust_matrix_runner, "_run", side_effect=command):
                self.assertTrue(rust_matrix_runner._fuzz_replay(records, "all", time.monotonic() + 30))
            self.assertEqual(records[0]["suite"], "fuzz-replay-all-features")
            self.assertEqual((records[0]["total"], records[0]["passed"], records[0]["ignored"]), (87, 87, 0))
            self.assertIn("--all-features", calls[0][1])
            with patch.object(rust_matrix_runner, "_run", side_effect=command):
                records = []
                self.assertFalse(rust_matrix_runner._fuzz_replay(records, "default", time.monotonic() + 30))
            self.assertEqual(records, [{
                "kind": "control", "stage": "unit", "status": "fail", "code": "DEVLANE_FAILURE",
            }])

    def test_empty_fuzz_test_coverage_refuses_the_matrix(self):
        def simple(records, suite, argv, deadline, timeout=1800):
            records.append(rust_matrix_runner._coverage(suite, 1, 0))
            return True

        def rust_arm(records, scope, manifest, workspace_mode, feature_set, config, deadline):
            suite = scope + ("-all-features" if feature_set == "all" else "-default")
            total = 0 if scope == "fuzz" else 1
            records.append(rust_matrix_runner._coverage(suite, total, 0))
            return True

        def replay(records, feature_set, deadline):
            suffix = "all-features" if feature_set == "all" else "default"
            records.append(rust_matrix_runner._coverage("fuzz-replay-" + suffix, 17, 0))
            return True

        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "matrix.jsonl"
            with patch.object(rust_matrix_runner, "_copy_advisory_database"), \
                    patch.object(rust_matrix_runner, "_simple_check", side_effect=simple), \
                    patch.object(rust_matrix_runner, "_rust_test_arm", side_effect=rust_arm), \
                    patch.object(rust_matrix_runner, "_fuzz_replay", side_effect=replay):
                result = rust_matrix_runner.run(
                    rust_matrix_runner.EXPECTED_MATRIX, "fixed-map", str(report), time.monotonic() + 60,
                )
            self.assertEqual(result, 1)
            self.assertIn(b'"status":"fail"', report.read_bytes())

    def test_every_workspace_audit_denies_unsound_without_ignores(self):
        audit_calls = {}
        def simple(records, suite, argv, deadline, timeout=1800):
            if suite.startswith("audit-"):
                audit_calls[suite] = argv
            return _coverage(records, suite)
        def arm(records, scope, manifest, workspace_mode, feature_set, config, deadline):
            return _coverage(records, scope + ("-all-features" if feature_set == "all" else "-default"))
        def replay(records, feature_set, deadline):
            return _coverage(records, "fuzz-replay-" + ("all-features" if feature_set == "all" else "default"))
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(rust_matrix_runner, "_copy_advisory_database"), \
                    patch.object(rust_matrix_runner, "_simple_check", side_effect=simple), \
                    patch.object(rust_matrix_runner, "_rust_test_arm", side_effect=arm), \
                    patch.object(rust_matrix_runner, "_fuzz_replay", side_effect=replay), \
                    patch.object(rust_matrix_runner, "_semver_check",
                                 side_effect=lambda records, _deadline:
                                 records.extend(rust_matrix_runner.semver_stage.records_for_exit(0)) or True):
                result = rust_matrix_runner.run(rust_matrix_runner.EXPECTED_MATRIX, "fixed-map",
                                               str(Path(temporary) / "report.jsonl"), time.monotonic() + 60)
        self.assertEqual(result, 0)
        self.assertEqual(set(audit_calls), {"audit-root", "audit-runtime", "audit-fuzz"})
        for argv in audit_calls.values():
            self.assertEqual(argv[1:7], [
                "audit", "--deny", "unsound", "--no-fetch", "--no-yanked", "--db",
            ])
            self.assertIn("--file", argv)
            self.assertFalse(any(arg == "--ignore" or arg.startswith("--ignore=") for arg in argv))

    def test_candidate_matrix_mutation_is_rejected_before_execution(self):
        matrix = json.loads(json.dumps(rust_matrix_runner.EXPECTED_MATRIX))
        matrix["workspaces"][0]["manifest"] = "/workspace/source/other/Cargo.toml"
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "matrix.jsonl"
            with patch.object(rust_matrix_runner, "_copy_advisory_database") as copy_db:
                with self.assertRaisesRegex(rust_matrix_runner.MatrixRefusal, "matrix-profile-mismatch"):
                    rust_matrix_runner.run(matrix, "fixed-test-map", str(report), time.monotonic() + 30)
            copy_db.assert_not_called()
            self.assertFalse(report.exists())

    def test_deadline_exhaustion_before_every_fixed_matrix_arm_refuses_without_spawning(self):
        expired = time.monotonic() - 1
        for suite in rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"][:12]:
            with self.subTest(suite=suite):
                records = []
                with patch.object(rust_matrix_runner.subprocess, "Popen") as spawn:
                    self.assertFalse(rust_matrix_runner._simple_check(
                        records, suite, ["fixed-tool"], expired,
                    ))
                    spawn.assert_not_called()
                self.assertTrue(any(row.get("kind") == "control" for row in records))
        arms = [(item["id"], item["manifest"], item["mode"])
                for item in rust_matrix_runner.EXPECTED_MATRIX["workspaces"]]
        listener = rust_matrix_runner.EXPECTED_MATRIX["listener"]
        arms.append((listener["id"], listener["manifest"], listener["mode"]))
        for scope, manifest, workspace_mode in arms:
            for feature_set in rust_matrix_runner.EXPECTED_MATRIX["feature_sets"]:
                with self.subTest(scope=scope, feature_set=feature_set):
                    records = []
                    with patch.object(rust_matrix_runner.subprocess, "Popen") as spawn:
                        self.assertFalse(rust_matrix_runner._rust_test_arm(
                            records, scope, manifest, workspace_mode, feature_set,
                            "fixed-test-map", expired,
                        ))
                        spawn.assert_not_called()
                    self.assertTrue(any(row.get("kind") == "control" for row in records))
        for feature_set in rust_matrix_runner.EXPECTED_MATRIX["feature_sets"]:
            with self.subTest(fuzz_replay=feature_set):
                records = []
                with patch.object(rust_matrix_runner.subprocess, "Popen") as spawn:
                    self.assertFalse(rust_matrix_runner._fuzz_replay(records, feature_set, expired))
                    spawn.assert_not_called()
                self.assertTrue(any(row.get("kind") == "control" for row in records))

    def test_deadline_expiry_inside_each_matrix_process_class_kills_child_group(self):
        cases = ("fixed-check", "cargo-test-build", "fuzz-replay")
        with tempfile.TemporaryDirectory() as temporary:
            for index, kind in enumerate(cases, start=1):
                with self.subTest(process_class=kind):
                    process = Mock(pid=320 + index, wait=Mock(side_effect=[
                        subprocess.TimeoutExpired(kind, 10), 0, 0,
                    ]))
                    records = []
                    deadline = time.monotonic() + 60
                    with patch.object(rust_matrix_runner, "RAW", temporary), \
                            patch.object(rust_matrix_runner, "_remaining", side_effect=[10, 0]), \
                            patch.object(rust_matrix_runner.subprocess, "Popen", return_value=process), \
                            patch.object(rust_matrix_runner.os, "killpg") as kill:
                        if kind == "fixed-check":
                            self.assertFalse(rust_matrix_runner._simple_check(
                                records, "fmt-root", ["fixed-tool"], deadline,
                            ))
                        elif kind == "cargo-test-build":
                            self.assertFalse(rust_matrix_runner._rust_test_arm(
                                records, "root", "/workspace/source/Cargo.toml", "workspace", "default",
                                "fixed-test-map", deadline,
                            ))
                        else:
                            self.assertFalse(rust_matrix_runner._fuzz_replay(records, "default", deadline))
                    self.assertEqual([call.args for call in kill.call_args_list], [
                        (process.pid, signal.SIGTERM), (process.pid, signal.SIGKILL),
                    ])
                    self.assertTrue(any(row.get("kind") == "control" for row in records))

    def test_real_term_exiting_leader_does_not_leave_term_ignoring_descendant(self):
        with tempfile.TemporaryDirectory() as temporary:
            process, descendant = _term_split_group(Path(temporary) / "descendant.pid")
            try:
                with patch.object(rust_matrix_runner, "TERM_GRACE_SECONDS", 0.05):
                    rust_matrix_runner._kill(process)
                self.assertIsNotNone(process.poll())
                _assert_pid_gone(self, descendant)
            finally:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)

    def test_total_deadline_exhausted_during_fixed_check_kills_the_child_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            process = Mock(
                pid=321,
                wait=Mock(side_effect=[
                    subprocess.TimeoutExpired("fixed-cargo-check", 10), 0, 0,
                ]),
            )
            with patch.object(rust_matrix_runner, "RAW", temporary), \
                    patch.object(rust_matrix_runner, "_remaining", side_effect=[10, 0]), \
                    patch.object(rust_matrix_runner.subprocess, "Popen", return_value=process), \
                    patch.object(rust_matrix_runner.os, "killpg") as kill, \
                    patch.object(rust_matrix_runner.time, "sleep"):
                with self.assertRaisesRegex(rust_matrix_runner.MatrixRefusal, "total-deadline-exhausted"):
                    rust_matrix_runner._run("fixed-deadline-check", ["cargo", "check"], time.monotonic() + 60)
            self.assertEqual([call.args for call in kill.call_args_list], [
                (process.pid, signal.SIGTERM), (process.pid, signal.SIGKILL),
            ])

    def test_zero_exit_without_complete_coverage_cannot_pass(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "matrix.jsonl"
            original = rust_matrix_runner._rust_test_arm

            def missing_listener_arm(records, scope, manifest, workspace_mode, feature_set, config, deadline):
                if scope == "listener" and feature_set == "all":
                    return True
                return original(records, scope, manifest, workspace_mode, feature_set, config, deadline)

            with patch.object(rust_matrix_runner, "_copy_advisory_database"), \
                    patch.object(rust_matrix_runner, "_simple_check",
                                 side_effect=lambda records, suite, argv, deadline, timeout=1800:
                                 _coverage(records, suite)), \
                    patch.object(rust_matrix_runner, "_rust_test_arm", side_effect=missing_listener_arm):
                result = rust_matrix_runner.run(
                    rust_matrix_runner.EXPECTED_MATRIX, "fixed-test-map", str(report), time.monotonic() + 60,
                )
            self.assertEqual(result, 1)
            records = [json.loads(line) for line in report.read_text(encoding="ascii").splitlines()]
            self.assertNotIn("listener-all-features", [row.get("suite") for row in records])
            self.assertTrue(any(row.get("kind") == "control" and row.get("status") == "fail"
                                for row in records))

    def test_public_audit_accepts_only_complete_opaque_core_coverage_records(self):
        records = []
        for suite in rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"]:
            total = 1
            if suite.startswith("fuzz-replay-"):
                total = 87
            records.append({
                "kind": "coverage", "stage": rust_matrix_runner._stage_for(suite),
                "suite": suite, "total": total, "passed": total, "failed": 0, "ignored": 0,
            })
        canonical = sorted([
            json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
            for row in records
        ])
        public_audit.validate_summary_records(canonical, "core-rust")
        changed = list(canonical)
        row = json.loads(changed[-1])
        row["suite"] = "private-workspace-name"
        changed[-1] = json.dumps(row, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        with self.assertRaises(public_audit.AuditRefusal):
            public_audit.validate_summary_records(changed, "core-rust")


class SemverExecutableIntegrationTests(unittest.TestCase):
    def test_matrix_runner_client_sends_fixed_request_and_reads_fragmented_reply(self):
        semver = rust_matrix_runner.semver_stage
        client_socket, server_socket = semver.socket.socketpair()
        failures = []
        expected_records = semver.records_for_exit(0)

        def receive_exact(connection, size):
            result = bytearray()
            while len(result) < size:
                chunk = connection.recv(size - len(result))
                if not chunk:
                    raise AssertionError("synthetic worker request truncated")
                result.extend(chunk)
            return bytes(result)

        def serve():
            try:
                size = int.from_bytes(receive_exact(server_socket, 4), "big")
                self.assertEqual(receive_exact(server_socket, size), b'{"op":"semver-stage"}')
                payload = json.dumps(
                    {"ok": True, "records": expected_records}, sort_keys=True,
                    separators=(",", ":"), ensure_ascii=True,
                ).encode("ascii")
                framed = len(payload).to_bytes(4, "big") + payload
                for offset in range(0, len(framed), 1):
                    server_socket.sendall(framed[offset:offset + 1])
            except BaseException as error:
                failures.append(error)
            finally:
                server_socket.close()

        class OneByteClient:
            def settimeout(self, value):
                client_socket.settimeout(value)

            def connect(self, _path):
                return None

            def sendall(self, value):
                client_socket.sendall(value)

            def recv(self, size):
                return client_socket.recv(min(size, 1))

            def close(self):
                client_socket.close()

        server_thread = supervisor.threading.Thread(target=serve)
        server_thread.start()
        with patch.object(semver.socket, "socket", return_value=OneByteClient()):
            records = semver.request_stage(time.monotonic() + 5)
        server_thread.join(timeout=5)
        self.assertFalse(server_thread.is_alive())
        self.assertEqual(failures, [])
        self.assertEqual(records, expected_records)

    def test_legacy_schema_e2e_is_only_a_semver_refusal_negative_control(self):
        rows = []
        expected = rust_matrix_runner.EXPECTED_MATRIX["coverage_ids"]
        for suite in expected:
            failed = int(suite == "semver-runtime")
            rows.append({
                "kind": "coverage", "stage": rust_matrix_runner._stage_for(suite),
                "suite": suite, "total": 1, "passed": 1 - failed,
                "failed": failed, "ignored": 0,
            })
        rows.append({
            "kind": "control", "stage": "semver", "status": "fail",
            "code": "DEVLANE_SEMVER_EXECUTION",
        })
        scenario = {
            "profile": "core-rust", "allowed_files": {}, "allowed_tests": {}, "frames": {},
            "expect_semver_execution_refusal": True,
        }
        profile = test_e2e.bundle.strict_json(
            (test_e2e.ROOT / "ci/devlane-profiles.json").read_bytes()
        )["profiles"]["core-rust"]
        allowlists = {
            "files": {}, "tests": {}, "frames": {}, "stages": list(profile["stages"]),
            "codes": sorted(set(profile.get("diagnostic_codes", []) + ["DEVLANE_FAILURE"])),
            "max_lines": {}, "suites": sorted(expected),
        }
        summary = output_filter.filter_records(
            [test_e2e.bundle.canonical_json(row) for row in rows], allowlists,
        )
        parsed = test_e2e._summary_records(summary, scenario)
        semver = [row for row in parsed if row.get("kind") == "coverage"
                  and row.get("suite") == "semver-runtime"]
        self.assertEqual(semver[0]["failed"], 1)

        scenario["expect_semver_execution_refusal"] = False
        with self.assertRaises(RuntimeError):
            test_e2e._summary_records(summary, scenario)

    def test_schema_one_semver_stage_refuses_before_any_launch(self):
        service = object.__new__(supervisor.Service)
        service.context = {"profile": "core-rust"}
        service.manifest = {"schema": 1}
        service.baseline_staged = False
        with patch.object(supervisor.CANCEL_REQUESTED, "is_set", return_value=False), \
                patch.object(supervisor.subprocess, "Popen") as popen:
            records = service._run_semver_stage()
        popen.assert_not_called()
        self.assertEqual(records, rust_matrix_runner.semver_stage.records_for_exit(101))

    def _run_semver_stage_with_synthetic_boundaries(self, *, exit_code=0,
                                                   cancel_on_spawn=False,
                                                   report_error=None, cleanup_result=True):
        events = []
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "namespace-root"
        (root / "workspace/raw").mkdir(parents=True)
        service = object.__new__(supervisor.Service)
        service.context = {"profile": "core-rust", "control_sha": "1" * 40}
        service.manifest = {
            "schema": 2, "source_revision": rust_matrix_runner.semver_stage.SOURCE_REVISION,
            "fetch_sha256": "2" * 64,
        }
        service.projection_value = {"manifest_projection_sha256": "2" * 64}
        service.baseline_staged = True
        service.deadline_file = Path("synthetic-deadline")
        service.deadline = time.monotonic() + 30
        service.root = root
        service.semver_active = None
        service.semver_active_lock = supervisor.threading.Lock()
        service.semver_checkpoint_record = None
        outer = {"work_deadline": service.deadline, "cleanup_reserve": 10}
        binary_sha = "3" * 64
        identity = {
            "source_commit": service.manifest["source_revision"],
            "control_sha": service.context["control_sha"],
            "manifest_projection_sha256": service.projection_value["manifest_projection_sha256"],
            "candidate_full_source_map_sha256": "4" * 64,
            "baseline_source_map_sha256": "5" * 64,
            "semver_tool_binary_sha256": binary_sha,
        }
        source_maps = {
            "baseline_source_map_sha256": "5" * 64,
            "candidate_source_map_sha256": "6" * 64,
            "candidate_full_source_map_sha256": "4" * 64,
        }
        source_sets = {
            "candidate": {"full_map_sha256": "7" * 64},
            "baseline_runtime": {"map_sha256": "5" * 64},
        }
        prepared = {
            "candidate_selected_map_after_ephemeral_lock_overlay": "8" * 64,
            "generated_lock_status": "ephemeral-offline-generated-not-committed",
            "generated_lock_sha256": {"Cargo.lock": "9" * 64},
            "rust_tool_hashes": {},
            "rust_tool_provenance_status": "binary-hash-bound-origin-unverified",
            "registry_tree_sha256": "a" * 64,
            "_registry_package_rows": [],
        }

        class Job:
            path = Path("/synthetic-cgroup")
            attach_fd = 73

            def close_attach(self):
                events.append("close-attach")

        class Process:
            pid = 874

            def wait(self, timeout=None):
                events.append("wait")
                return exit_code

            def poll(self):
                return exit_code

        job = Job()

        def read_file(path, _maximum, _budget=None):
            name = Path(path).name
            return {
                "semver-tool-receipt.json": b"receipt",
                "registry-preparation.json": b"preparation",
                "generated-locks.json": b"generated",
            }[name]

        def strict_json(payload, _maximum):
            return {
                b"receipt": {"binary_sha256": binary_sha},
                b"preparation": {},
                b"generated": {},
            }[payload]

        def spawn(command, **kwargs):
            events.append("spawn")
            if cancel_on_spawn:
                supervisor.CANCEL_REQUESTED.set()
            process = Process()
            spawn.call = (command, kwargs)
            return process

        def report(_active, *, require_complete):
            events.append("report")
            self.assertTrue(require_complete)
            if report_error is not None:
                raise supervisor.SupervisorRefusal(report_error)

        with patch.object(supervisor.deadline_budget, "_read", return_value=outer), \
                patch.object(rust_matrix_runner.semver_stage, "verify_tool",
                             side_effect=lambda *_args, **_kwargs: events.append("tool") or Path("/prepared/tool")), \
                patch.object(rust_matrix_runner.semver_stage, "offline_cache_input_identity",
                             return_value=identity), \
                patch.object(rust_matrix_runner.semver_stage, "offline_cache_source_maps",
                             return_value=source_maps), \
                patch.object(rust_matrix_runner.semver_stage, "offline_cache_source_sets",
                             return_value=source_sets), \
                patch.object(supervisor.semver_offline_cache, "_read_file", side_effect=read_file), \
                patch.object(supervisor.bundle, "strict_json", side_effect=strict_json), \
                patch.object(service, "_semver_mountinfo_text",
                             side_effect=lambda _budget: events.append("mountinfo") or "synthetic-mountinfo\n"), \
                patch.object(service, "_prepare_semver_scratch",
                             side_effect=lambda *_args: events.append("scratch")), \
                patch.object(supervisor.semver_offline_cache, "validate_rust_v2_semver_inputs",
                             side_effect=lambda *_args, **kwargs:
                             events.append(("validate", kwargs["mountinfo"])) or prepared), \
                patch.object(rust_matrix_runner.semver_stage, "verify_run_inputs",
                             side_effect=lambda *_args, **_kwargs: events.append("verify")), \
                patch.object(service, "_create_semver_cgroup",
                             side_effect=lambda *_args: events.append("cgroup") or job), \
                patch.object(service, "_semver_cleanup_cgroup",
                             side_effect=lambda *_args: events.append("reap") or cleanup_result), \
                patch.object(service, "_write_semver_checkpoint_record", side_effect=report), \
                patch.object(supervisor.subprocess, "Popen", side_effect=spawn) as popen:
            supervisor.CANCEL_REQUESTED.clear()
            self.last_stage_probe = {"service": service, "events": events}
            try:
                records = service._run_semver_stage()
            finally:
                self.last_stage_probe["cancelled"] = supervisor.CANCEL_REQUESTED.is_set()
                supervisor.CANCEL_REQUESTED.clear()
        return service, records, events, popen, spawn

    def test_failed_cleanup_keeps_process_tracked_and_escalates_without_records(self):
        try:
            with self.assertRaisesRegex(supervisor.SupervisorRefusal, "matrix-semver-cgroup-cleanup"):
                self._run_semver_stage_with_synthetic_boundaries(cleanup_result=False)
            probe = self.last_stage_probe
            self.assertEqual(probe["events"].count("reap"), 2)
            self.assertNotIn("report", probe["events"])
            self.assertTrue(probe["cancelled"])
            active = probe["service"].semver_active
            self.assertIsNotNone(active)
            self.assertTrue(active["cleanup_failed"])
            self.assertIn(874, supervisor.ACTIVE_CHILDREN)
        finally:
            with supervisor.ACTIVE_CHILDREN_LOCK:
                supervisor.ACTIVE_CHILDREN.discard(874)
            supervisor.CANCEL_REQUESTED.clear()

    def test_actual_semver_stage_orders_receipt_validation_launch_reap_then_report(self):
        service, records, events, popen, spawn = self._run_semver_stage_with_synthetic_boundaries()
        self.assertEqual(records, rust_matrix_runner.semver_stage.records_for_exit(0))
        self.assertEqual(
            events,
            ["tool", "mountinfo", "scratch", ("validate", "synthetic-mountinfo\n"),
             "verify", "cgroup", "spawn", "wait",
             "close-attach", "reap", "report"],
        )
        self.assertIsNone(service.semver_active)
        command, kwargs = spawn.call
        self.assertIn("/control/devlane/cgroup_exec.py", command)
        self.assertEqual(command[-len(rust_matrix_runner.semver_stage.fixed_argv()):],
                         rust_matrix_runner.semver_stage.fixed_argv())
        self.assertEqual(kwargs["pass_fds"], (73,))
        self.assertNotIn("preexec_fn", kwargs)
        self.assertTrue(kwargs["env"]["PATH"].startswith("/scratch/semver-cargo-bin:"))
        self.assertEqual(kwargs["env"]["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(kwargs["env"]["CARGO_TARGET_DIR"], "/scratch/semver-target")
        popen.assert_called_once()

    def test_semver_scratch_context_matches_the_fixed_wrapper_schema(self):
        binding = {
            "source_commit": "1" * 40,
            "control_sha": "2" * 40,
            "manifest_projection_sha256": "3" * 64,
            "candidate_git_tree_map_sha256": "4" * 64,
            "candidate_transfer_map_sha256": "5" * 64,
            "baseline_source_map_sha256": "6" * 64,
            "semver_tool_binary_sha256": "7" * 64,
        }
        expected_source_maps = {
            "baseline_source_map_sha256": "8" * 64,
            "candidate_source_map_sha256": "9" * 64,
            "candidate_full_source_map_sha256": "a" * 64,
        }
        with tempfile.TemporaryDirectory() as temporary:
            service = object.__new__(supervisor.Service)
            service.root = Path(temporary).resolve()
            (service.root / "scratch/semver-state").mkdir(parents=True)
            with patch.object(supervisor.os, "chown") as chown, \
                    patch.object(supervisor.os, "fchown") as fchown:
                service._prepare_semver_scratch(
                    binding, expected_source_maps, 100.0, 110.0,
                )
            cargo_home = service.root / "scratch/semver-cargo-home"
            cargo_bin = service.root / "scratch/semver-cargo-bin"
            shim = cargo_bin / "cargo"
            self.assertEqual(cargo_home.stat().st_mode & 0o7777, 0o1777)
            self.assertEqual(cargo_home.stat().st_uid, os.getuid())
            self.assertEqual(cargo_bin.stat().st_mode & 0o777, 0o755)
            self.assertEqual(cargo_bin.stat().st_uid, os.getuid())
            self.assertEqual(shim.stat().st_mode & 0o777, 0o555)
            self.assertEqual(shim.stat().st_uid, os.getuid())
            chown.assert_called_once_with(service.root / "scratch/semver-target",
                                          supervisor.WORKER_UID, supervisor.WORKER_GID)
            self.assertEqual(fchown.call_count, 3)
            for name in ("config.toml", "config"):
                config = cargo_home / name
                self.assertEqual(config.read_bytes(), supervisor.semver_offline_cache.CARGO_CONFIG)
                self.assertEqual(config.stat().st_mode & 0o777, 0o440)
            context = json.loads(
                (service.root / "scratch/semver-state/context.json").read_text(encoding="ascii"),
            )
        self.assertEqual(set(context), {
            "schema", "authenticated_binding", "expected_source_maps",
            "work_deadline", "cleanup_deadline",
        })
        self.assertEqual(context["schema"], "keeldock.semver-worker-context.v2")
        self.assertEqual(context["authenticated_binding"], binding)
        self.assertEqual(context["expected_source_maps"], expected_source_maps)
        self.assertEqual(context["work_deadline"], 100.0)
        self.assertEqual(context["cleanup_deadline"], 110.0)

    def test_cgroup_creation_refuses_and_removes_an_incomplete_new_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            mountinfo = "36 25 0:32 / %s rw - cgroup2 cgroup rw\n" % root
            service = object.__new__(supervisor.Service)
            budget = Mock()
            budget.remaining.return_value = 10.0
            with patch.object(supervisor, "SEMVER_CGROUP_ROOT", root), \
                    patch.object(supervisor.os.path, "ismount", return_value=True):
                with self.assertRaisesRegex(
                        supervisor.SupervisorRefusal, "matrix-semver-cgroup-unavailable"):
                    service._create_semver_cgroup(mountinfo, budget)
            self.assertEqual(list(root.iterdir()), [])

    def test_actual_semver_stage_failure_cancel_and_incomplete_checkpoint_fail_closed(self):
        service, records, events, _popen, _spawn = self._run_semver_stage_with_synthetic_boundaries(
            exit_code=101,
        )
        self.assertEqual(records, rust_matrix_runner.semver_stage.records_for_exit(101))
        self.assertLess(events.index("reap"), events.index("report"))
        self.assertIsNone(service.semver_active)

        service, records, events, _popen, _spawn = self._run_semver_stage_with_synthetic_boundaries(
            cancel_on_spawn=True,
        )
        self.assertEqual(records, rust_matrix_runner.semver_stage.records_for_exit(101))
        self.assertIn("reap", events)
        self.assertNotIn("report", events)
        self.assertIsNone(service.semver_active)

        service, records, events, _popen, _spawn = self._run_semver_stage_with_synthetic_boundaries(
            report_error="matrix-semver-checkpoint-incomplete",
        )
        self.assertEqual(records, rust_matrix_runner.semver_stage.records_for_exit(101))
        self.assertLess(events.index("reap"), events.index("report"))
        self.assertIsNone(service.semver_active)

    def test_worker_socket_uses_kernel_peer_credentials_and_no_service_lock(self):
        class Connection:
            def __init__(self, request, credentials):
                payload = json.dumps(request, sort_keys=True, separators=(",", ":")).encode("ascii")
                self.incoming = bytearray(len(payload).to_bytes(4, "big") + payload)
                self.credentials = credentials
                self.outgoing = bytearray()

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def settimeout(self, _timeout):
                pass

            def getsockopt(self, _level, _option, _size):
                return self.credentials

            def recv(self, size):
                chunk = bytes(self.incoming[:size])
                del self.incoming[:size]
                return chunk

            def sendall(self, payload):
                self.outgoing.extend(payload)

        service = object.__new__(supervisor.Service)
        service.dispatch_semver_worker = Mock(return_value={"ok": True})
        peer = Connection(
            {"op": "semver-stage"},
            __import__("struct").pack("3i", 713, supervisor.WORKER_UID, supervisor.WORKER_GID),
        )
        with patch.object(supervisor.socket, "SO_PEERCRED", 17, create=True):
            service._handle_semver_worker_connection(peer)
        self.assertEqual(
            service.dispatch_semver_worker.call_args.args,
            ({"op": "semver-stage"}, 713, supervisor.WORKER_UID, supervisor.WORKER_GID),
        )
        size = int.from_bytes(peer.outgoing[:4], "big")
        self.assertEqual(json.loads(peer.outgoing[4:4 + size]), {"ok": True})
        self.assertNotIn("SERVICE_LOCK", inspect.getsource(supervisor.Service._handle_semver_worker_connection))

        rejected = Connection(
            {"op": "semver-stage"},
            __import__("struct").pack("3i", 713, 1234, supervisor.WORKER_GID),
        )
        with patch.object(supervisor.socket, "SO_PEERCRED", 17, create=True):
            service._handle_semver_worker_connection(rejected)
        self.assertEqual(service.dispatch_semver_worker.call_count, 1)
        size = int.from_bytes(rejected.outgoing[:4], "big")
        self.assertEqual(json.loads(rejected.outgoing[4:4 + size])["ok"], False)

    def test_semver_stage_broker_requires_exact_runner_pid_parent_uid_and_argv(self):
        def make_service(*, parent=None, uid=supervisor.WORKER_UID, arguments=None):
            service = object.__new__(supervisor.Service)
            service.matrix_runner_ready = supervisor.threading.Event()
            service.matrix_runner_ready.set()
            service.matrix_runner_lock = supervisor.threading.Lock()
            service.matrix_runner_active = {"pid": 713, "semver_requested": False}
            service.semver_active = None
            service.semver_active_lock = supervisor.threading.Lock()
            service.deadline_file = Path("synthetic-deadline")
            service.deadline = 456.0
            runner_parent = os.getpid() if parent is None else parent
            status = (
                "Name:\tpython3\nPPid:\t%d\nUid:\t1000\t%d\t%d\t%d\n"
                % (runner_parent, uid, uid, uid)
            ).encode("ascii")
            words = arguments or [
                "/usr/bin/python3", "-B", "-I", "-S",
                "/control/devlane/rust_matrix_runner.py",
                "/control/profiles.json", "/trusted/adapter-config.json",
                "/scratch/reports/rust-matrix.jsonl", "--deadline", "456.0",
            ]
            command = b"\x00".join(item.encode("ascii") for item in words) + b"\x00"
            service._semver_proc_bytes = Mock(
                side_effect=lambda _pid, name, _maximum, _budget=None:
                status if name == "status" else command,
            )
            service._run_semver_stage = Mock(
                return_value=rust_matrix_runner.semver_stage.records_for_exit(0),
            )
            return service

        outer = {"work_deadline": time.monotonic() + 30, "cleanup_reserve": 10}
        with patch.object(supervisor.deadline_budget, "_read", return_value=outer):
            service = make_service()
            self.assertEqual(service._semver_stage_request(713)["records"][0]["passed"], 1)
            service._run_semver_stage.assert_called_once_with()

            for service in (
                make_service(parent=os.getpid() + 2),
                make_service(uid=777),
                make_service(arguments=["/usr/bin/python3", "-B", "-I", "-S",
                                       "/control/devlane/rust_matrix_runner.py", "extra"]),
            ):
                with self.assertRaises(supervisor.SupervisorRefusal):
                    service._semver_stage_request(713)
                service._run_semver_stage.assert_not_called()

    def test_checkpoint_callback_accepts_complete_sequence_and_does_not_retain_rejected_first_event(self):
        binding = {
            "source_commit": "1" * 40,
            "control_sha": "2" * 40,
            "manifest_projection_sha256": "3" * 64,
            "candidate_git_tree_map_sha256": "4" * 64,
            "candidate_transfer_map_sha256": "5" * 64,
            "baseline_source_map_sha256": "6" * 64,
            "semver_tool_binary_sha256": "7" * 64,
        }
        base = {
            "manifest_sha256": "8" * 64,
            "project_map_without_lock_sha256": "9" * 64,
            "project_file_count_without_lock": 1,
            "project_tree_bytes_without_lock": 10,
            "project_map_sha256": "9" * 64,
            "project_file_count": 1,
            "project_tree_bytes": 10,
            "lock_sha256": None,
            "lock_size": None,
        }
        locked = dict(base)
        locked.update({
            "project_map_sha256": "a" * 64,
            "project_file_count": 2,
            "project_tree_bytes": 15,
            "lock_sha256": "b" * 64,
            "lock_size": 5,
        })

        def make_service():
            service = object.__new__(supervisor.Service)
            service.semver_active_lock = supervisor.threading.Lock()
            active = {
                "ready": supervisor.threading.Event(), "trackers": {}, "events": [],
                "checkpoint_binding": binding,
            }
            active["ready"].set()
            service.semver_active = active
            service._semver_checkpoint_peer = Mock(return_value={"project_kind": "local"})
            service._semver_checkpoint_snapshot = Mock(
                side_effect=lambda _root, _active: base,
            )
            return service, active

        manifest = "/scratch/semver-target/semver-checks/local-alpha/Cargo.toml"
        sequence = (
            ("before-update", "update", base),
            ("after-update", "update", locked),
            ("after-metadata", "metadata", locked),
            ("after-doc", "doc", locked),
        )
        service, active = make_service()
        supervisor.CANCEL_REQUESTED.clear()
        service._semver_checkpoint_snapshot.side_effect = [row for _event, _op, row in sequence]
        try:
            for event, operation, _snapshot in sequence:
                result = service._semver_checkpoint({
                    "op": "semver-checkpoint", "event": event,
                    "operation": operation, "manifest": manifest,
                }, 900, supervisor.WORKER_UID)
                self.assertEqual(result, {"ok": True})
            self.assertEqual(active["trackers"]["/scratch/semver-target/semver-checks/local-alpha"].finish()[
                "checkpoint_count"], 4)
            self.assertEqual(len(active["events"]), 4)
        finally:
            supervisor.CANCEL_REQUESTED.clear()

        service, active = make_service()
        service._semver_checkpoint_snapshot.return_value = base
        with self.assertRaisesRegex(supervisor.SupervisorRefusal, "matrix-semver-checkpoint-contract"):
            service._semver_checkpoint({
                "op": "semver-checkpoint", "event": "after-update",
                "operation": "update", "manifest": manifest,
            }, 900, supervisor.WORKER_UID)
        self.assertEqual(active["trackers"], {})
        self.assertEqual(active["events"], [])

    def test_cgroup_launcher_attaches_before_fixed_privilege_drop_and_exec(self):
        class ExecReached(BaseException):
            pass

        with tempfile.NamedTemporaryFile(delete=False) as cgroup_control:
            cgroup_control_path = Path(cgroup_control.name)
        descriptor = os.open(cgroup_control_path, os.O_RDONLY)
        try:
            arguments = ["--cgroup-fd", str(descriptor), "--",
                         *cgroup_exec.SET_PRIV_PREFIX, *cgroup_exec.SEMVER_ARGUMENTS]
            writes = []
            calls = []

            def write(fd, payload):
                writes.append((fd, payload))
                return len(payload)

            def execve(path, command, environment):
                calls.append((path, command, environment))
                raise ExecReached()

            with patch.object(cgroup_exec.os, "geteuid", return_value=0), \
                    patch.object(cgroup_exec.resource, "setrlimit") as setrlimit, \
                    patch.object(cgroup_exec.os, "umask"):
                with self.assertRaises(ExecReached):
                    cgroup_exec.main(arguments, write=write, execve=execve)
            self.assertEqual(writes, [(descriptor, (str(os.getpid()) + "\n").encode("ascii"))])
            self.assertEqual(calls[0][0], "/usr/bin/setpriv")
            self.assertEqual(calls[0][1], [*cgroup_exec.SET_PRIV_PREFIX, *cgroup_exec.SEMVER_ARGUMENTS])
            self.assertEqual(setrlimit.call_count, 5)
        finally:
            try:
                os.close(descriptor)
            except OSError:
                pass
            cgroup_control_path.unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
