"""Mac-runnable validation for the hosted Windows adapter's fixed inputs."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import sandbox_windows as windows


class WindowsSandboxValidationTests(unittest.TestCase):
    def test_only_the_core_node_profile_is_enabled(self):
        self.assertEqual(windows.validate_profile("core-node"), "core-node")
        for profile in ("core-rust", "desktop", "", None):
            with self.subTest(profile=profile), self.assertRaises(windows.WindowsBoundaryRefusal):
                windows.validate_profile(profile)

    def test_appcontainer_names_and_sids_are_closed(self):
        self.assertEqual(windows.validate_profile_name("KDDevLane" + "a" * 32), "KDDevLane" + "a" * 32)
        self.assertEqual(windows.validate_package_sid("S-1-15-2-1-2-3-4-5-6-7"),
                         "S-1-15-2-1-2-3-4-5-6-7")
        for value in ("KDDevLane../../x", "KDDevLane" + "A" * 32, "S-1-15-2-1-2-3-4-5-6-7-8", "S-1-15-2-x"):
            with self.subTest(value=value), self.assertRaises(windows.WindowsBoundaryRefusal):
                (windows.validate_profile_name if value.startswith("KD") else windows.validate_package_sid)(value)

    def test_decrypt_refusals_keep_public_diagnostic_categories(self):
        self.assertEqual(windows._public_decrypt_refusal(windows.WindowsBoundaryRefusal("key-invalid")),
                         "key-format")
        self.assertEqual(windows._public_decrypt_refusal(windows.WindowsBoundaryRefusal("bundle-binding")),
                         "binding-mismatch")
        self.assertEqual(windows._public_decrypt_refusal(windows.bundle.Refusal("authentication-failed")),
                         "auth-tag")
        self.assertEqual(windows._public_decrypt_refusal(windows.fetch.Refusal("projection-invalid")),
                         "binding-mismatch")

    def test_workload_environment_must_be_offline_and_cannot_carry_credentials(self):
        entries = [
            "PATH=C:\\node;C:\\Windows\\System32", "NPM_CONFIG_IGNORE_SCRIPTS=true",
            "NPM_CONFIG_OFFLINE=true", "TEMP=D:\\scratch",
        ]
        self.assertEqual(len(windows.validate_environment(entries)), len(entries))
        for bad in (
            entries + ["DEVLANE_DECRYPT_KEY=" + "a" * 64],
            entries + ["GITHUB_TOKEN=secret"],
            [entry for entry in entries if not entry.startswith("NPM_CONFIG_OFFLINE=")],
            [entry.replace("IGNORE_SCRIPTS=true", "IGNORE_SCRIPTS=false") for entry in entries],
        ):
            with self.subTest(bad=bad), self.assertRaises(windows.WindowsBoundaryRefusal):
                windows.validate_environment(bad)

    def test_profile_commands_map_only_fixed_workspace_and_scratch_paths(self):
        node = r"C:\hostedtoolcache\windows\node\24.22.1\x64\node.exe"
        npm = r"C:\hostedtoolcache\windows\node\24.22.1\x64\node_modules\npm\bin\npm-cli.js"
        source = r"D:\a\_temp\devlane-123\workspace\source"
        scratch = r"D:\a\_temp\devlane-123\scratch"
        executable, arguments = windows.validate_command(
            ["npm", "--prefix", "/workspace/source", "run", "typecheck"],
            node=node, npm_cli=npm, source=source, scratch=scratch, stages=["typecheck"],
        )
        self.assertEqual(executable, node)
        self.assertEqual(arguments, [npm, "--prefix", source, "run", "typecheck"])
        for command in (
            ["npm", "--prefix", "/workspace/source/../other", "run", "typecheck"],
            ["node", "--eval", "require('fs').writeFileSync('/workspace/private', 'x')"],
            ["powershell.exe", "-Command", "exit 0"],
        ):
            with self.subTest(command=command), self.assertRaises(windows.WindowsBoundaryRefusal):
                windows.validate_command(command, node=node, npm_cli=npm, source=source,
                                         scratch=scratch, stages=["unit"])

    def test_profile_command_translation_consumes_embedded_path_suffixes(self):
        node = r"C:\hostedtoolcache\windows\node\24.22.1\x64\node.exe"
        npm = r"C:\hostedtoolcache\windows\node\24.22.1\x64\node_modules\npm\bin\npm-cli.js"
        source = r"D:\a\_temp\devlane-123\workspace\source"
        scratch = r"D:\a\_temp\devlane-123\scratch"
        executable, arguments = windows.validate_command(
            ["npm", "--prefix", "/workspace/source", "run", "unit", "--", "--config=/workspace/source/vitest.config.ts",
             "--outputFile=/scratch/reports/vitest.json"],
            node=node, npm_cli=npm, source=source, scratch=scratch, stages=["unit"],
        )
        self.assertEqual(executable, node)
        self.assertEqual(arguments[-2], "--config=" + str(windows.PureWindowsPath(source) / "vitest.config.ts"))
        self.assertEqual(arguments[-1], "--outputFile=" + str(windows.PureWindowsPath(scratch) / "reports" / "vitest.json"))

    def test_native_launcher_terminates_a_created_process_on_assignment_failure(self):
        source = (Path(windows.__file__).with_name("sandbox_windows_native.cs")).read_text(encoding="utf-8")
        self.assertIn("TerminateProcess(process, JobExitCode)", source)
        self.assertIn("WaitForSingleObject(process, 10000) != WaitObject0", source)
        self.assertLess(source.index("TerminateProcess(process, JobExitCode)"), source.index("Close(process)"))

    def test_shred_tree_removes_oversize_and_reparse_entries_after_plaintext(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            source = root / "workspace" / "source"
            scratch = root / "scratch"
            source.mkdir(parents=True)
            scratch.mkdir()
            clear = Path(temporary) / "outside-canary"
            clear.write_text("preserve", encoding="ascii")
            (source / "private.txt").write_text("plaintext", encoding="ascii")
            huge = scratch / "hostile.bin"
            with huge.open("wb") as output:
                output.truncate(1024 * 1024 * 1024 + 1)
            (scratch / "outside-link").symlink_to(clear)
            receipt = windows.shred_tree(root, plaintext_root=source, overwrite_limit=1024)
            self.assertIn("reparse=1", receipt)
            self.assertFalse(root.exists())
            self.assertEqual(clear.read_text(encoding="ascii"), "preserve")

    def test_cleanup_attempts_plaintext_wipe_after_firewall_and_profile_failures(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            root.mkdir()
            state = root / "state.json"
            state.write_text("{}", encoding="ascii")
            with mock.patch.object(windows, "remove_firewall", side_effect=windows.WindowsBoundaryRefusal()), \
                    mock.patch.object(windows, "delete_profile", side_effect=windows.WindowsBoundaryRefusal()), \
                    mock.patch.object(windows, "shred_tree", return_value="wiped\n") as wipe, \
                    self.assertRaisesRegex(windows.WindowsBoundaryRefusal, "cleanup-incomplete"):
                windows.cleanup_runner(state, root)
            wipe.assert_called_once_with(root, plaintext_root=None)

    def test_windows_archive_names_reject_aliases_and_path_escapes(self):
        self.assertEqual(windows._windows_archive_name("packages/core/src/index.js"),
                         "packages/core/src/index.js")
        for value in (
            "../outside.txt", "folder/../outside.txt", "CON.txt", "nul", "file:stream", "bad?.js",
            "trailing.", "trailing ", "folder//entry.js",
        ):
            with self.subTest(value=value), self.assertRaises(windows.WindowsBoundaryRefusal):
                windows._windows_archive_name(value)

    def test_predecrypt_probe_uses_fresh_dns_and_both_ip_families(self):
        script = windows.probe_script(
            r"D:\\scratch\\probe.txt", listener_port=54321,
            outside_canary=r"D:\\a\\_temp\\canary", outside_write=r"D:\\a\\_temp\\write",
            other_drive_canary=r"C:\\Windows\\Temp\\canary", other_drive_write=r"C:\\Windows\\Temp\\write",
            pipe_path=r"\\.\pipe\spoolss",
        )
        self.assertIn("attempt('1.1.1.1',443,4)", script)
        self.assertIn("attempt('2606:4700:4700::1111',443,6)", script)
        self.assertIn("attempt('127.0.0.1',54321,4)", script)
        self.assertIn("attempt('127.0.0.1',445,4)", script)
        self.assertIn("pipe\\\\spoolss", script)
        self.assertIn("dns.resolve4('example.com'", script)
        self.assertNotIn("dns.lookup", script)
        self.assertIn("readProbe", script)
        self.assertIn("writeProbe", script)

    def test_dependency_preparation_runs_downloaded_code_in_network_capable_lpac(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "run"
            state_dir = root / "state"
            state_dir.mkdir(parents=True)
            state = state_dir / "preparation.json"
            projection = root / "projection.json"
            projection.write_text("{}", encoding="ascii")
            output = root / "prepared-root"
            node = root / "node.exe"
            npm = root / "npm-cli.js"
            node.write_text("", encoding="ascii")
            npm.write_text("", encoding="ascii")
            requests = []

            def isolated(_state, request, _run_root):
                requests.append(dict(request))
                project = Path(request["working_directory"])
                modules = project / "node_modules"
                modules.mkdir(exist_ok=True)
                (modules / "playwright").mkdir(exist_ok=True)
                (modules / "playwright" / "cli.js").write_text("", encoding="ascii")
                return {"status": "pass", "exit_code": 0, "token": "lpac=verified", "job": "assigned kill_on_close=enabled breakaway=disabled"}

            with mock.patch.object(windows.sys, "platform", "win32"), \
                    mock.patch.object(windows.fetch, "validate_projection", return_value={
                        "npm_package": {}, "npm_lock": {}, "playwright": ["chromium"],
                    }), \
                    mock.patch.object(windows, "_npm_tools", return_value=(node, npm)), \
                    mock.patch.object(windows, "_deadline_remaining", return_value=600), \
                    mock.patch.object(windows, "create_profile", return_value={}), \
                    mock.patch.object(windows, "delete_profile"), \
                    mock.patch.object(windows, "_native_run", side_effect=isolated):
                windows.prepare_dependencies(projection, output, root / "deadline.json", state)

            self.assertEqual(len(requests), 2)
            for request in requests:
                self.assertTrue(request["internet_client"])
                self.assertIn(str(output / "project"), request["write_paths"])
                self.assertIn(str(output / "npm-cache"), request["write_paths"])
                self.assertIn(str(output / "prepared" / "ms-playwright"), request["write_paths"])
                self.assertEqual(request["environment"][0].startswith("PATH="), True)
                self.assertIn("NPM_CONFIG_IGNORE_SCRIPTS=true", request["environment"])
                self.assertIn("NPM_CONFIG_OFFLINE=false", request["environment"])
            self.assertTrue((output / "prepared" / "toolchain.json").is_file())

    def test_filtered_summary_carries_diagnostic_test_and_browser_records(self):
        manifest = {
            "allowed_files": {},
            "allowed_tests": {"private test title": "case_0001"},
            "frames": {"private frame title": "frame_0001"},
        }
        summary = windows.filtered_summary(
            manifest, "core-node", [("typecheck", "pass"), ("unit", "fail"), ("browser", "pass")],
            extra_records=[
                {"kind": "diagnostic", "stage": "typecheck", "code": "TS2322", "level": "error"},
                {"kind": "test", "stage": "unit", "test": "case_0001"},
                {"kind": "frame", "frame": "frame_0001", "status": "fail"},
            ], unit_failure_subreason="vitest-failed",
        )
        records = [json.loads(line) for line in summary.splitlines()]
        self.assertIn({"kind": "test", "stage": "unit", "test": "case_0001"}, records)
        self.assertIn({"kind": "frame", "frame": "frame_0001", "status": "fail"}, records)
        self.assertIn({"kind": "diagnostic", "stage": "typecheck", "code": "TS2322", "level": "error"}, records)
        self.assertIn({"kind": "control", "stage": "unit", "status": "fail", "code": "DEVLANE_FAILURE"}, records)
        self.assertIn({"kind": "control", "stage": "unit", "status": "fail", "code": "DEVLANE_FAILURE",
                       "subreason": "vitest-failed"}, records)

    def test_missing_adapter_outputs_and_report_directories_are_handled_without_following_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            absent = root / "reports" / "adapter.jsonl"
            windows._remove_adapter_output(absent)
            self.assertFalse(windows._browser_media_outputs_present(root))
            with self.assertRaises(windows.WindowsBoundaryRefusal):
                windows._read_adapter_records(absent)

    def test_adapter_records_must_be_bounded_canonical_json_lines(self):
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "adapter.jsonl"
            report.write_text('{"kind":"frame","frame":"frame_0001","status":"pass"}\n', encoding="ascii")
            self.assertEqual(windows._read_adapter_records(report), [
                {"kind": "frame", "frame": "frame_0001", "status": "pass"},
            ])
            report.write_text('{"kind":"frame"}', encoding="ascii")
            with self.assertRaises(windows.WindowsBoundaryRefusal):
                windows._read_adapter_records(report)


if __name__ == "__main__":
    unittest.main()
