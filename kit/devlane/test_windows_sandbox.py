"""Mac-runnable validation for the hosted Windows adapter's fixed inputs."""

import json
import tempfile
import unittest
from pathlib import Path

import sandbox_windows as windows


class WindowsSandboxValidationTests(unittest.TestCase):
    def test_only_the_core_node_profile_is_enabled(self):
        self.assertEqual(windows.validate_profile("core-node"), "core-node")
        for profile in ("core-rust", "desktop", "", None):
            with self.subTest(profile=profile), self.assertRaises(windows.WindowsBoundaryRefusal):
                windows.validate_profile(profile)

    def test_appcontainer_names_and_sids_are_closed(self):
        self.assertEqual(windows.validate_profile_name("KDDevLane" + "a" * 32), "KDDevLane" + "a" * 32)
        self.assertEqual(windows.validate_package_sid("S-1-15-2-1-2-3-4-5-6-7-8"),
                         "S-1-15-2-1-2-3-4-5-6-7-8")
        for value in ("KDDevLane../../x", "KDDevLane" + "A" * 32, "S-1-15-2-1-2", "S-1-15-2-x"):
            with self.subTest(value=value), self.assertRaises(windows.WindowsBoundaryRefusal):
                (windows.validate_profile_name if value.startswith("KD") else windows.validate_package_sid)(value)

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
        script = windows.probe_script(r"D:\\scratch\\probe.txt")
        self.assertIn("attempt('1.1.1.1',4)", script)
        self.assertIn("attempt('2606:4700:4700::1111',6)", script)
        self.assertIn("dns.resolve4('example.com'", script)
        self.assertNotIn("dns.lookup", script)

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
