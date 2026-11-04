import hashlib
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "kit/bootstrap"))

from public_tree import ACTION_VERSION_COMMENT_PATTERN, MAX_FILE_BYTES, PINNED_FILE_SHA256, PLATFORM_FILES, inspect_text

RUNNER = ROOT / "kit/confinement/windows_source_run.ps1"
FRAME = ROOT / "kit/confinement/capsule_frame.ps1"
LIBRARY = ROOT / "kit/confinement/windows_confinement.ps1"
WORKFLOW = ROOT / ".github/workflows/lane-h-windows-receiver.yml"
SHIM = ROOT / "kit/confinement/windows_npm_link_shim.cjs"


class WindowsSourceRunTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.runner = RUNNER.read_text(encoding="utf-8")
        cls.frame = FRAME.read_text(encoding="utf-8")
        cls.library = LIBRARY.read_text(encoding="utf-8")
        cls.workflow = WORKFLOW.read_text(encoding="utf-8")

    def list_values(self, name):
        found = re.search(r"^\$" + name + r" = @\((.*?)\n\)$", self.runner, re.M | re.S)
        if found is None:
            found = re.search(r"^\$" + name + r" = @\((.*)\)$", self.runner, re.M)
        self.assertIsNotNone(found, name)
        return re.findall(r"'([^']+)'", found.group(1))

    def test_files_pass_the_public_tree_rules(self):
        for path in (RUNNER, FRAME, WORKFLOW, SHIM, Path(__file__)):
            with self.subTest(path=path.name):
                payload = path.read_bytes()
                self.assertLessEqual(len(payload), MAX_FILE_BYTES)
                inspect_text(payload.decode("utf-8"), "platform")
                for line in payload.decode("ascii").splitlines():
                    if chr(35) in line:
                        self.assertIsNotNone(ACTION_VERSION_COMMENT_PATTERN.fullmatch(line))
                payload.decode("ascii")

    def test_every_reused_function_and_variable_exists_in_the_confinement_script(self):
        for name in self.list_values("RequiredFunctions"):
            with self.subTest(name=name):
                self.assertIsNotNone(re.search(r"^function " + re.escape(name) + r"\b", self.library, re.M))
        for name in self.list_values("LibraryVariables"):
            with self.subTest(name=name):
                self.assertIsNotNone(re.search(r"^\$" + re.escape(name) + r" = ", self.library, re.M))
        self.assertNotIn("Write-Line", self.list_values("RequiredFunctions"))

    def test_public_output_is_an_allow_listed_prefix_set_and_diagnostics_are_dropped(self):
        self.assertIn("function Write-Line([string]$text) {\n    if ($text -cmatch $script:PublicLinePattern)", self.runner)
        pattern = re.search(r"PublicLinePattern = '([^']+)'", self.runner).group(1)
        self.assertNotIn("kd-diag", pattern)
        self.assertIn("if ($statement.Name -cne 'Write-Line')", self.runner)

    def test_probe_link_libraries_match_the_confinement_script(self):
        libs = re.compile(r"-l kernel32 -l ws2_32 -l advapi32 -l userenv -l ole32 -l oleaut32")
        self.assertIsNotNone(libs.search(self.runner))
        self.assertIsNotNone(libs.search(self.library))

    def test_log_canary_is_validated_scanned_and_never_printed(self):
        self.assertIn("(?:[0-9a-f]{2}){32,128}", self.runner)
        self.assertIn("Test-LogCanary $combined", self.runner)
        self.assertIn("$script:LogCanary)", self.runner)
        self.assertIn("if ($script:LogNeedles.Count -eq 0) { return $true }", self.runner)
        self.assertIn("$script:CanaryNeedle = $script:LogCanary", self.runner)
        self.assertNotRegex(self.runner, r"Write-Line[^\n]*LogCanary")

    def test_failure_text_is_a_closed_token_so_project_data_cannot_leave(self):
        self.assertIn("$reason -cnotmatch '^[a-z][a-z0-9_]{0,40}$'", self.runner)
        self.assertNotIn("Get-CleanText $reason", self.runner)
        self.assertNotIn("ExitCode.ToString", self.runner)
        self.assertIn("$run.ExitCode).ToString(", self.runner.split("function Write-GateDiag", 1)[1].split("\n}\n", 1)[0])
        gate_line = re.search(r"Write-Line \('windows-source-gate=' \+ \$index \+ ' id=' \+ \$gate.Id \+ ' result=' \+ \$result \+ ' hang=' \+ \$hang \+ \$causeText\)", self.runner)
        self.assertIsNotNone(gate_line)

    def test_gates_run_confined_with_a_boundary_proof_and_the_hang_guard(self):
        self.assertIn("$sandbox.Run($true, $exe, $commandLine, $project, $gateEnvironment", self.runner)
        self.assertIn("[uint32]$run.HandleCount -ne 3", self.runner)
        self.assertIn("Test-LpacTokenText $tokenText", self.runner)
        self.assertIn("([uint64]$run.CpuMs * 10) -ge ([uint64]$run.ElapsedMs * 8)", self.runner)
        self.assertIn("'busy'", self.runner)
        self.assertNotIn("--pool=threads", self.runner)
        self.assertNotIn("'pipe'", self.runner)

    def test_gate_plan_comes_from_the_shared_table_emit_and_is_validated(self):
        self.assertIn("$GateTableScript = 'gate_table.py'", self.runner)
        self.assertIn("$GateTableEmitCommand = 'emit'", self.runner)
        self.assertIn("$GateTableManifestCommand = 'manifest-digest'", self.runner)
        self.assertIn("$RequiredGateCount = 15", self.runner)
        self.assertIn("$MaxGateCount = 18", self.runner)
        self.assertIn("$selection = 'runtime'", self.runner)
        for token in ("'^[a-z][a-z_]{2,40}$'", "$gate.Keys.Count -ne 2", "$gates.Count -ne $expectedCount",
                      "$plan.Keys.Count -ne 2", "[string]$gate['name']"):
            self.assertIn(token, self.runner)
        for stale in ("GateTableGatesCommand", "$gate['cwd']", "$gate['runtime']", "$gate['id']", "-lt 13"):
            self.assertNotIn(stale, self.runner)
        self.assertNotIn("'workspace_tests'", self.runner)
        self.assertNotRegex(self.runner, r"\$gates.Count -gt 24(?!\d)")

    def test_each_config_neutralisation_runs_right_after_the_tree_check_and_before_any_tool(self):
        tree = self.runner.index("Test-ProjectTree $project $manifest.Entries")
        neutral = self.runner.index("Remove-SourceConfigFiles $project\n", tree)
        digest = self.runner.index("$GateTableManifestCommand, '--root'")
        plan = self.runner.index("$phase = 'gate_plan'")
        self.assertLess(tree, neutral)
        self.assertLess(neutral, digest)
        self.assertLess(digest, plan)
        self.assertIn("core.hooksPath=NUL", self.runner)
        self.assertIn("[string]$env:CI_SOURCE_SHA -cne $bound['source_sha']", self.runner)

    def test_npm_user_and_global_config_are_two_distinct_empty_files(self):
        self.assertIn("'NPM_CONFIG_USERCONFIG=' + (Join-Path $root 'empty-user.npmrc')", self.runner)
        self.assertIn("'NPM_CONFIG_GLOBALCONFIG=' + (Join-Path $root 'empty-global.npmrc')", self.runner)
        self.assertNotIn("nul.npmrc", self.runner)
        self.assertIn("NPM_CONFIG_UPDATE_NOTIFIER=false", self.runner)

    def test_a_truncated_gate_capture_counts_as_a_log_canary_hit(self):
        block = self.runner.split("if ($run.Truncated -or (Test-LogCanary $combined)) {", 1)[1].split("\n        }\n", 1)[0]
        block = self.runner.split("if ($run.Truncated -or (Test-LogCanary $combined)) {", 1)[1].split("}", 1)[0]
        self.assertIn("$outcome.Canary = 'present'", block)
        self.assertIn("$script:RefusalReason = 'log_canary'", block)

    def test_the_tree_listing_cap_covers_the_manifest_entry_limit(self):
        self.assertIn("$ListingLimit = 3145728", self.runner)
        self.assertGreaterEqual(3145728, 10000 * (53 + 240 + 1))
        self.assertIn("$MaxManifestEntries = 10000", self.runner)
        self.assertIn("--full-tree', $bound['source_sha']) $script:Layout.Private 300 $ListingLimit", self.runner)

    def test_a_failed_gate_carries_one_closed_cause_and_never_a_number_or_output(self):
        function = self.runner.split("function Get-GateCause", 1)[1].split("\n}\n", 1)[0]
        for token in ("return 'launch'", "return 'timeout'", "return 'limit'", "return 'signal'", "return 'exit'"):
            self.assertIn(token, function)
        self.assertEqual(set(re.findall(r"return '([a-z]+)'", function)), {"launch", "timeout", "limit", "signal", "exit"})
        self.assertNotRegex(function, r"Write-Line|\.Stdout|\.Stderr")
        self.assertIn("$causeText = ' cause=' + $gateCause", self.runner)
        self.assertIn("if (-not $passed) {", self.runner)
        self.assertIn("@('timeout', 'limit', 'signal', 'exit', 'launch', 'deadline') -ccontains $script:GateCause", self.runner)
        self.assertIn("result=not_run hang=none cause=deadline", self.runner)
        self.assertIn("$script:GateCause = 'deadline'", self.runner)
        self.assertIn("$gateText += ' cause=' + $script:GateCause", self.runner)
        self.assertNotRegex(self.runner, r"' cause=' \+ \[string\]\$run\.ExitCode")

    def test_gate_diagnostics_are_synthetic_only_scanned_first_closed_and_never_in_source_mode(self):
        diag = re.compile(re.search(r"DiagLinePattern = '([^']+)'", self.runner).group(1))
        public = re.compile(re.search(r"PublicLinePattern = '([^']+)'", self.runner).group(1))
        for accepted in (
            "windows-source-gate-diag id=format exit=0xc0000142",
            "windows-source-gate-diag id=clippy_runtime exit=0x00000001",
            "windows-source-gate-diag-line error: example output",
            "windows-source-gate-diag-line ",
            "windows-source-gate-diag-line " + "a" * 300,
        ):
            with self.subTest(accepted=accepted[:48]):
                self.assertIsNotNone(diag.fullmatch(accepted))
                self.assertIsNone(public.fullmatch(accepted))
        for refused in (
            "windows-source-gate-diag id=Format exit=0xc0000142",
            "windows-source-gate-diag id=format exit=0xC0000142",
            "windows-source-gate-diag id=format exit=0x1",
            "windows-source-gate-diag id=format exit=0xc0000142 extra",
            "windows-source-gate-diag-line " + "a" * 301,
            "windows-source-gate-diag-line \x01",
            "windows-source-gate-diag-line " + chr(233),
            "windows-source-gate-diag-linex",
            "windows-source-gate=1 id=format result=failed hang=none cause=signal",
        ):
            with self.subTest(refused=refused[:48]):
                self.assertIsNone(diag.fullmatch(refused))
        self.assertNotRegex(self.runner, r"Write-Line \('windows-source-gate-diag")
        self.assertEqual(self.runner.count("$script:RunMode = "), 2)
        self.assertIn("$script:RunMode = ''\n", self.runner)
        self.assertIn("\n            $script:RunMode = $runMode\n", self.runner)
        self.assertLess(self.runner.index("@('synthetic', 'source') -cnotcontains $runMode) { throw 'control' }"),
                        self.runner.index("$script:RunMode = $runMode"))
        for name in ("Write-SyntheticDiag", "Write-GateDiag"):
            with self.subTest(function=name):
                body = self.runner.split("function " + name, 1)[1].split("\n}\n", 1)[0]
                self.assertIn("\n    if ($script:RunMode -cne 'synthetic') { return }\n", body)
        self.assertEqual(len(re.findall(r"Write-GateDiag\b", self.runner)), 2)
        call = "if (-not $passed -and $script:RunMode -ceq 'synthetic') { Write-GateDiag $gate.Id $run }"
        self.assertEqual(self.runner.count(call), 1)
        result_line = self.runner.index("Write-Line ('windows-source-gate=' + $index + ' id=' + $gate.Id + ' result=' + $result")
        canary = self.runner.index("if ($run.Truncated -or (Test-LogCanary $combined)) {")
        boundary = self.runner.index("if (-not $boundary) {\n            $outcome.Boundary = 'failed'")
        self.assertLess(result_line, canary)
        self.assertLess(canary, self.runner.index(call))
        self.assertLess(self.runner.index(call), boundary)
        self.assertGreater(boundary, self.runner.index("function Invoke-SourceGates"))
        emit = self.runner.split("function Write-GateDiag", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("' exit=0x' + ([uint32]$run.ExitCode).ToString('x8')", emit)
        self.assertEqual(self.runner.count("$run.ExitCode).ToString("), 1)
        self.assertLess(emit.index("$run.Stderr) $DiagStderrLines"), emit.index("$run.Stdout) $DiagStdoutLines"))
        for token in ("$DiagStderrLines = 40", "$DiagStdoutLines = 20", "$DiagLineLimit = 300"):
            self.assertIn(token, self.runner)
        clean = self.runner.split("function Get-DiagLineText", 1)[1].split("\n}\n", 1)[0]
        for token in ("$script:Redactions", "'[^ -~]', '?'", "'kd-confinement'", "$value.Substring(0, $DiagLineLimit)",
                      "$item.Replace('\\', '/')", "$item.Replace('\\', '\\\\')"):
            self.assertIn(token, clean)
        self.assertNotIn("Write-Line", clean)
        tail = self.runner.split("function Get-DiagTail", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("System.Collections.Generic.Queue[string]", tail)
        self.assertIn("$queue.Dequeue()", tail)
        self.assertNotIn("+=", tail)
        writer = self.runner.split("function Write-SyntheticDiag", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("-not (Test-LogCanary $text)", writer)
        self.assertNotIn("windows-source-gate-diag", self.workflow)

    def test_a_failed_gate_reported_at_cleanup_names_its_cause_only_in_synthetic_mode(self):
        catch = self.runner.split("} catch {\n    $reason = ", 1)[1].split("$refusal = ", 1)[0]
        self.assertIn("if ($phase -ceq 'gates' -and $script:GateFailure -gt 0) {", catch)
        self.assertIn(
            "} elseif ($script:RunMode -ceq 'synthetic' -and $phase -ceq 'cleanup_links' -and $script:GateFailure -gt 0) {",
            catch,
        )
        self.assertEqual(catch.count("$gateText = ' gate=' + $script:GateFailure"), 2)
        self.assertLess(catch.index("-ceq 'gates'"), catch.index("-ceq 'cleanup_links'"))
        self.assertLess(self.runner.index("$phase = 'cleanup_links'"), self.runner.index("if ($gateOutcome.Failed -ne 0 -or $gateOutcome.Failure -ne 0) { throw $script:RefusalReason }"))

    def test_a_normal_nonzero_exit_is_exit_and_only_ntstatus_codes_are_signal_or_limit(self):
        function = self.runner.split("function Get-GateCause", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("$code = [uint64][uint32]$run.ExitCode", function)
        self.assertIsNone(re.search(r"0[xX][0-9A-Fa-f]", function))
        limit_line = re.search(r"if \(([^\n]*)\) \{ return 'limit' \}", function).group(1)
        limits = {int(value) for value in re.findall(r"\$code -eq ([0-9]+)", limit_line)}
        self.assertEqual(limits, {0x4b44574b, 0xC0000044, 0xC000012D, 0xC0000017})
        found = re.search(r"\$code -ge ([0-9]+) -and \$code -le ([0-9]+)\) \{ return 'signal' \}", function)
        self.assertIsNotNone(found)
        low, high = int(found.group(1)), int(found.group(2))
        self.assertEqual((low, high), (0xC0000000, 0xCFFFFFFF))
        self.assertEqual(function.count("return 'signal'"), 1)

        def classify(code):
            if code in limits:
                return "limit"
            if low <= code <= high:
                return "signal"
            return "exit"

        for code, expected in (
            (1, "exit"), (2, "exit"), (101, "exit"), (255, "exit"), (0x7FFFFFFF, "exit"), (0xBFFFFFFF, "exit"),
            (0xC0000005, "signal"), (0xC0000142, "signal"), (0xC0000409, "signal"), (0xCFFFFFFF, "signal"),
            (0xD0000000, "exit"), (0xFFFFF030, "exit"), (0xFFFFFFFF, "exit"),
            (0xC0000044, "limit"), (0xC000012D, "limit"), (0xC0000017, "limit"), (0x4b44574b, "limit"),
        ):
            with self.subTest(code=code):
                self.assertEqual(classify(code), expected)
        self.assertLess(function.index("return 'timeout'"), function.index("return 'limit'"))
        self.assertLess(function.index("return 'limit'"), function.index("return 'signal'"))
        self.assertLess(function.index("return 'signal'"), function.index("if ($code -ne 0) { return 'exit' }"))

    def test_empty_tool_configs_stop_the_formatter_and_linter_probing_ancestor_directories(self):
        function = self.runner.split("function Initialize-ToolConfigs", 1)[1].split("\n}\n", 1)[0]
        for token in (
            "'.rustfmt.toml', 'rustfmt.toml'", "'.clippy.toml', 'clippy.toml'",
            "[IO.File]::WriteAllText((Join-Path $project $names[1]), '', $encoding)",
            "-PathType Leaf)) { throw 'tool_config' }", "[IO.FileAttributes]::ReparsePoint",
        ):
            with self.subTest(token=token):
                self.assertIn(token, function)
        self.assertEqual(self.runner.count("Initialize-ToolConfigs $project\n"), 1)
        order = [self.runner.index(token) for token in (
            "Write-Line ('windows-source-tree=verified", "$phase = 'tool_configs'", "$phase = 'npm_tarballs'",
            "$phase = 'gate_plan'", "$phase = 'gates'")]
        self.assertEqual(order, sorted(order))
        self.assertEqual(self.runner.count("--config-path"), 1)
        probes = self.function_body("Get-SourceProbes")
        self.assertEqual(probes.count("--config-path"), 1)
        owner = [line for line in probes.splitlines() if "--config-path" in line]
        self.assertEqual(len(owner), 1)
        self.assertTrue(owner[0].lstrip().startswith("@{ Id = 'rustfmt_file_check_config'; "))
        for name in ("Initialize-ToolConfigs", "Get-GatePlan", "New-GateEnvironment", "Invoke-SourceGates", "Invoke-SourceProbes"):
            with self.subTest(function=name):
                self.assertNotIn("--config-path", self.function_body(name))
        self.assertNotIn("CLIPPY_CONF_DIR", self.runner)

    def function_body(self, name):
        return self.runner.split("function " + name, 1)[1].split("\n}\n", 1)[0]

    def test_probe_lines_share_the_synthetic_diag_pattern_and_never_the_public_one(self):
        diag = re.compile(re.search(r"DiagLinePattern = '([^']+)'", self.runner).group(1))
        public = re.compile(re.search(r"PublicLinePattern = '([^']+)'", self.runner).group(1))
        for accepted in (
            "windows-source-probe id=cargo_version exit=0x00000000",
            "windows-source-probe id=cargo_fmt_verbose exit=0xc0000142",
            "windows-source-probe-line error: example output",
            "windows-source-probe-line tool_configs rustfmt.toml=wrote clippy.toml=present",
            "windows-source-probe-line absent id=cargo_fmt_exe_version",
            "windows-source-probe-line ",
            "windows-source-probe-line " + "a" * 300,
            "windows-source-gate-diag id=format exit=0x00000001",
        ):
            with self.subTest(accepted=accepted[:48]):
                self.assertIsNotNone(diag.fullmatch(accepted))
                self.assertIsNone(public.fullmatch(accepted))
        for refused in (
            "windows-source-probe id=Cargo exit=0x00000000",
            "windows-source-probe id=cargo_version exit=0x0",
            "windows-source-probe id=cargo_version exit=0xC0000142",
            "windows-source-probe id=cargo_version exit=0x00000000 extra",
            "windows-source-probe-line " + "a" * 301,
            "windows-source-probe-line \x01",
            "windows-source-probe-line " + chr(233),
            "windows-source-probe-linex",
            "windows-source-probes id=cargo_version exit=0x00000000",
            "windows-source-probe=1",
            "windows-source-probe",
        ):
            with self.subTest(refused=refused[:48]):
                self.assertIsNone(diag.fullmatch(refused))
        self.assertNotRegex(self.runner, r"Write-Line \('windows-source-probe")

    def test_the_probe_matrix_has_fixed_ids_and_the_exact_commands_with_the_staged_binaries(self):
        body = self.function_body("Get-SourceProbes")
        ids = re.findall(r"@\{ Id = '([^']+)'", body)
        self.assertEqual(ids, [
            "cargo_version", "cargo_fmt_version", "cargo_fmt_exe_version", "rustfmt_version",
            "cargo_metadata", "rustfmt_file_check", "rustfmt_file_check_config", "cargo_fmt_verbose",
            "rustfmt_stdin_check", "rustfmt_relative_check", "rustc_version", "cargo_check_api",
            "node_realpath",
        ])
        for name in ids:
            self.assertRegex(name, r"^[a-z][a-z_]{2,40}$")
        for token in (
            "$cargo = Join-Path $rustBin 'cargo.exe'",
            "$rustfmt = Join-Path $rustBin 'rustfmt.exe'",
            "$cargoFmt = Join-Path $rustBin 'cargo-fmt.exe'",
            "$manifest = Join-Path $project 'Cargo.toml'",
            "$library = Join-Path $project 'crates\\host\\api\\src\\lib.rs'",
            "Argv = [string[]]@($cargo, '--version') }",
            "Argv = [string[]]@($cargo, 'fmt', '--version') }",
            "Needs = $cargoFmt; Extra = $none; Argv = [string[]]@($cargoFmt, '--version') }",
            "Argv = [string[]]@($rustfmt, '--version') }",
            "Argv = [string[]]@($cargo, 'metadata', '--locked', '--format-version', '1', '--offline', '--no-deps', '--manifest-path', $manifest) }",
            "Needs = $library; Extra = $none; Argv = [string[]]@($rustfmt, '--edition', '2024', '--check', $library) }",
            "Extra = [string[]]@('RUST_BACKTRACE=1'); Argv = [string[]]@($cargo, '--locked', '--offline', 'fmt', '--manifest-path', $manifest, '--all', '--verbose', '--', '--check') }",
            "$rustfmtConfig = Join-Path $project 'rustfmt.toml'",
            "Needs = $rustfmtConfig; Extra = $none; Argv = [string[]]@($rustfmt, '--edition', '2024', '--check', '--config-path', $rustfmtConfig, $library) }",
        ):
            with self.subTest(token=token[:60]):
                self.assertIn(token, body)
        self.assertEqual(self.runner.count("RUST_BACKTRACE=1"), 1)
        self.assertEqual(body.count("Extra = $none"), 11)
        self.assertEqual(len(re.findall(r"Needs = '';", body)), 6)
        self.assertIn("Get-GatePlan $project ($layout.RustBin + '\\cargo.exe')", self.runner)
        synthetic = ROOT / "kit/confinement/synthetic_project"
        self.assertTrue((synthetic / "Cargo.toml").is_file())
        self.assertTrue((synthetic / "crates/host/api/src/lib.rs").is_file())
        self.assertIn('edition = "2024"', (synthetic / "crates/host/api/Cargo.toml").read_text(encoding="utf-8"))

    def test_the_probe_matrix_runs_only_in_synthetic_mode_right_before_the_gates_and_never_changes_them(self):
        call = "$phase = 'gates'\n            Invoke-SourceProbes $box $project $layout.RustBin\n            $gateOutcome = Invoke-SourceGates $box $plan $project $recordsDirectory\n"
        self.assertEqual(self.runner.count(call), 1)
        self.assertEqual(len(re.findall(r"Invoke-SourceProbes\b", self.runner)), 2)
        self.assertEqual(len(re.findall(r"Get-SourceProbes\b", self.runner)), 2)
        self.assertEqual(len(re.findall(r"Write-ProbeDiag\b", self.runner)), 8)
        for name, call in (
            ("Invoke-SourceProbes", "Write-ProbeDiag $probe.Id $run"),
            ("Invoke-FinalPathProbe", "Write-ProbeDiag $id $run"),
            ("Test-OtherContainerFinalPath", "Write-ProbeDiag 'finalpath_other' $run"),
            ("Invoke-NpmLinkProbe", "Write-ProbeDiag 'npm_link_probe' $run"),
            ("Invoke-NpmLinkTargetProbe", "Write-ProbeDiag 'npm_link_targets' $run"),
            ("Invoke-NpmReparseProbe", "Write-ProbeDiag ('npm_reparse_' + $stage) $run"),
            ("Write-VolumeFacts", "Write-ProbeDiag ('volopen_' + $role) $run"),
        ):
            with self.subTest(caller=name):
                self.assertEqual(self.function_body(name).count("Write-ProbeDiag"), 1)
                self.assertIn(call, self.function_body(name))
        order = [self.runner.index(token) for token in (
            "Initialize-ToolConfigs $project\n", "$tarballs = Initialize-NpmTarballs $project",
            "$phase = 'gate_plan'", "$plan = Get-GatePlan", "$phase = 'gates'\n            Invoke-SourceProbes",
            "$gateOutcome = Invoke-SourceGates")]
        self.assertEqual(order, sorted(order))
        self.assertEqual(len(set(order)), 6)
        for name in ("Invoke-SourceProbes", "Write-ProbeDiag"):
            body = self.function_body(name)
            with self.subTest(function=name):
                self.assertTrue(body.split("\n", 1)[1].startswith("    if ($script:RunMode -cne 'synthetic') { return }\n"))
        probes = self.function_body("Invoke-SourceProbes")
        self.assertLess(probes.index("-cne 'synthetic'"), probes.index("$sandbox.Run("))
        self.assertEqual(probes.count("$sandbox.Run("), 1)
        self.assertNotIn("'source'", probes)
        self.assertEqual(probes.count("'synthetic'"), 1)
        for name in ("Invoke-SourceProbes", "Write-ProbeDiag", "Get-SourceProbes"):
            body = self.function_body(name)
            with self.subTest(function=name):
                for forbidden in (
                    "$outcome", "$script:GateFailure", "$script:RefusalReason", "$script:GateCause", "throw",
                    "Grant-", "Set-LowIntegrityLabel", "Write-Line", "[Console]", "$exitCode", "$script:Redactions =",
                    "Remove-", "WriteAllText", "New-Item",
                ):
                    self.assertNotIn(forbidden, body)
        self.assertTrue(self.function_body("Write-ProbeDiag").endswith("    } catch {\n        return\n    }"))
        self.assertTrue(self.function_body("Invoke-SourceProbes").endswith(
            "    } catch {\n        try { Write-SyntheticDiag 'windows-source-probe-line aborted' } catch { return }\n        return\n    }"))
        self.assertEqual(len(re.findall(r"(?m)^\s*Grant-Access ", self.runner)), 2)

    def test_each_probe_is_bounded_in_time_and_uses_the_gate_launcher_and_environment(self):
        for token in ("$ProbeSeconds = 60\n", "$ProbeStderrLines = 20\n", "$ProbeStdoutLines = 10\n"):
            self.assertIn("\n" + token, self.runner)
        self.assertLessEqual(int(re.search(r"\n\$ProbeSeconds = ([0-9]+)\n", self.runner).group(1)), 60)
        probes = self.function_body("Invoke-SourceProbes")
        for token in (
            "$environment = New-GateEnvironment\n",
            "$remaining = (Get-RemainingSeconds) - 900\n",
            "if ($remaining -lt 60) { return }\n",
            "$seconds = $ProbeSeconds\n",
            "if ($seconds -gt $remaining) { $seconds = $remaining }\n",
            "$probeEnvironment = [string[]]($baseEnvironment + $probe.Extra)\n",
            "$baseEnvironment = @($environment | Where-Object { $extraNames -notcontains ([string]$_).Split([char]61)[0] })\n",
            "if ($probe.Seconds -gt 0) { $seconds = [int]$probe.Seconds }\n",
            "$run = $sandbox.Run($true, [string]$probe.Argv[0], (ConvertTo-CommandLine $probe.Argv), $project, $probeEnvironment, ($seconds * 1000), [uint32]32)\n",
            "Write-ProbeDiag $probe.Id $run\n",
        ):
            with self.subTest(token=token[:50]):
                self.assertIn(token, probes)
        self.assertEqual(probes.count("New-GateEnvironment"), 1)
        self.assertNotIn("Start-Process", probes)
        self.assertNotIn("Invoke-TrustedProcess", probes)

    def test_probe_output_is_sanitised_bounded_and_suppressed_whole_on_any_canary_hit(self):
        body = self.function_body("Write-ProbeDiag")
        self.assertIn("if ($run.Truncated -or (Test-LogCanary ([string]$run.Stdout + \"`n\" + [string]$run.Stderr))) {\n", body)
        self.assertIn("$code = [uint32]$run.ExitCode\n", body)
        self.assertIn("$lines = @('windows-source-probe id=' + $id + ' exit=0x' + $code.ToString('x8'))\n", body)
        self.assertIn("Get-DiagTail ([string]$run.Stderr) $ProbeStderrLines", body)
        self.assertIn("Get-DiagTail ([string]$run.Stdout) $ProbeStdoutLines", body)
        self.assertEqual(body.count("(Get-DiagLineText ([string]$line))"), 2)
        self.assertEqual(body.count("windows-source-probe-line "), 5)
        self.assertLess(body.index("$run.Stderr) $ProbeStderrLines"), body.index("$run.Stdout) $ProbeStdoutLines"))
        rescan = body.index("if (Test-LogCanary $line) {")
        printing = body.index("Write-SyntheticDiag $line")
        self.assertLess(body.index("$run.Truncated"), rescan)
        self.assertLess(rescan, printing)
        self.assertEqual(body.count("Write-SyntheticDiag"), 3)
        self.assertEqual(body.count("Write-SyntheticDiag ('windows-source-probe-line suppressed id=' + $id)"), 2)
        self.assertEqual(self.runner.count("$run.ExitCode).ToString("), 1)
        writer = self.function_body("Write-SyntheticDiag")
        self.assertIn("-not (Test-LogCanary $text)", writer)
        self.assertIn("if ($script:LogNeedles.Count -eq 0) { return $true }", self.runner)

    def test_the_tool_config_step_reports_whether_it_wrote_or_found_each_file_in_one_synthetic_line(self):
        function = self.function_body("Initialize-ToolConfigs")
        self.assertIn("$script:ToolConfigState = @()\n", function)
        self.assertIn("$script:ToolConfigState += ($names[1] + '=wrote')", function)
        self.assertIn("} else {\n            $script:ToolConfigState += ($names[1] + '=present')", function)
        self.assertLess(function.index("WriteAllText"), function.index("'=wrote'"))
        self.assertEqual(self.runner.count("$script:ToolConfigState = @()\n"), 2)
        probes = self.function_body("Invoke-SourceProbes")
        line = "Write-SyntheticDiag ('windows-source-probe-line tool_configs ' + ($script:ToolConfigState -join ' '))\n"
        self.assertIn(line, probes)
        self.assertLess(probes.index(line), probes.index("foreach ($probe in"))
        self.assertEqual(self.runner.count("tool_configs '"), 1)

    def test_every_probe_prints_a_launch_state_line_so_an_unstarted_process_cannot_look_like_exit_zero(self):
        body = self.function_body("Write-ProbeDiag")
        for token in (
            "$failure = Get-Token ([string]$run.Failure) '^[a-z_]{0,40}$'\n",
            "if ($failure.Length -eq 0) { $failure = 'none' }\n",
            "if ($run.Created) { $started = 'true' }\n",
            "if ($run.TimedOut) { $timedOut = 'true' }\n",
            "if ($run.Exited) { $exited = 'true' }\n",
            "$lines += ('windows-source-probe-line state started=' + $started + ' failure=' + $failure + ' create_error=' + ([uint32]$run.CreateError).ToString() + ' timed_out=' + $timedOut + ' exited=' + $exited)\n",
        ):
            with self.subTest(token=token[:50]):
                self.assertIn(token, body)
        for default in ("$started = 'false'\n", "$timedOut = 'false'\n", "$exited = 'false'\n"):
            self.assertIn(default, body)
        header = body.index("$lines = @('windows-source-probe id=")
        state = body.index("windows-source-probe-line state started=")
        first_output = body.index("Get-DiagTail ([string]$run.Stderr)")
        self.assertLess(header, state)
        self.assertLess(state, first_output)
        diag = re.compile(re.search(r"DiagLinePattern = '([^']+)'", self.runner).group(1))
        for accepted in (
            "windows-source-probe-line state started=true failure=none create_error=0 timed_out=false exited=true",
            "windows-source-probe-line state started=false failure=create create_error=5 timed_out=false exited=false",
            "windows-source-probe-line state started=true failure=none create_error=0 timed_out=true exited=false",
            "windows-source-probe-line suppressed id=cargo_version",
            "windows-source-probe-line aborted",
        ):
            with self.subTest(accepted=accepted[:60]):
                self.assertIsNotNone(diag.fullmatch(accepted))
        for field in ("Failure", "CreateError", "Created", "Exited", "TimedOut"):
            self.assertIsNotNone(re.search(r"public [a-z]+ " + field + r"\b", self.library_cs()), field)

    def library_cs(self):
        return (ROOT / "kit/confinement/windows_confinement.cs").read_text(encoding="utf-8")

    def test_the_verbose_format_probe_is_exactly_the_gate_command_plus_verbose_and_a_backtrace(self):
        table = (ROOT / "kit/confinement/gate_table.py").read_text(encoding="utf-8")
        gate = re.search(r"def _format\(manifest\):\n    return \(([^\n]+)\)\n", table).group(1)
        self.assertEqual(gate, 'CARGO, "--locked", "--offline", "fmt", "--manifest-path", manifest, "--all", "--", "--check"')
        self.assertIn('("format", _format(workspace))', table)
        self.assertIn('WORKSPACE_MANIFEST = PROJECT + "/Cargo.toml"', table)
        line = [item for item in self.function_body("Get-SourceProbes").splitlines() if "'cargo_fmt_verbose'" in item]
        self.assertEqual(len(line), 1)
        argv = re.search(r"Argv = \[string\[\]\]@\(([^)]*)\)", line[0]).group(1)
        probe = [item.strip() for item in argv.split(",")]
        self.assertEqual(probe.count("'--verbose'"), 1)
        probe.remove("'--verbose'")
        expected = {"CARGO": "$cargo", "manifest": "$manifest"}
        converted = []
        for item in gate.split(", "):
            item = item.strip()
            converted.append(expected[item] if item in expected else "'" + item.strip('"') + "'")
        self.assertEqual(probe, converted)
        self.assertEqual(probe.index("'--manifest-path'") + 1, probe.index("$manifest"))
        self.assertLess(probe.index("'--all'"), probe.index("'--'"))
        self.assertIn("Extra = [string[]]@('RUST_BACKTRACE=1')", line[0])

    def test_a_config_path_probe_follows_the_plain_file_probe_so_lookup_can_be_told_from_formatting(self):
        body = self.function_body("Get-SourceProbes")
        ids = re.findall(r"@\{ Id = '([^']+)'", body)
        self.assertEqual(ids.index("rustfmt_file_check_config"), ids.index("rustfmt_file_check") + 1)
        plain = [item for item in body.splitlines() if "'rustfmt_file_check'" in item][0]
        config = [item for item in body.splitlines() if "'rustfmt_file_check_config'" in item][0]
        self.assertIn("'--edition', '2024', '--check', $library)", plain)
        self.assertIn("'--edition', '2024', '--check', '--config-path', $rustfmtConfig, $library)", config)
        self.assertIn("Needs = $rustfmtConfig;", config)
        self.assertIn("$rustfmtConfig = Join-Path $project 'rustfmt.toml'", body)
        self.assertIn("'rustfmt.toml'", self.function_body("Initialize-ToolConfigs"))

    def test_every_mode_keeps_running_the_remaining_gates_after_an_ordinary_failure_and_only_synthetic_after_a_timeout_or_boundary_failure(self):
        body = self.function_body("Invoke-SourceGates")
        self.assertEqual(body.count("$keepGoing = ($script:RunMode -ceq 'synthetic')\n"), 1)
        self.assertEqual(body.count("$keepGoing"), 4)
        self.assertEqual(body.count("            if ($run.TimedOut -and -not $keepGoing) { return $outcome }\n"), 1)
        self.assertNotIn("if (-not $keepGoing)", body)
        self.assertEqual(body.count("            if (-not ($keepGoing -and -not $run.Created)) { return $outcome }\n            continue\n"), 1)
        self.assertEqual(body.count("return $outcome"), 5)
        self.assertEqual(body.count("'synthetic'"), 2)
        self.assertNotIn("'source'", body)
        self.assertEqual(self.runner.count("$keepGoing"), 4)
        canary = body.split("if ($run.Truncated -or (Test-LogCanary $combined)) {", 1)[1].split("\n        }\n", 1)[0]
        self.assertTrue(canary.rstrip().endswith("return $outcome"))
        self.assertNotIn("$keepGoing", canary)
        deadline = body.split("if ($remaining -lt 60) {", 1)[1].split("\n        }\n", 1)[0]
        self.assertTrue(deadline.rstrip().endswith("return $outcome"))
        self.assertNotIn("$keepGoing", deadline)
        gate = body.split("            $script:RefusalReason = 'gate'\n", 1)[1]
        self.assertTrue(gate.startswith("                Write-Line (Get-GateDetail $index $gate $combined $run.PeakProcessMemory)\n            }\n            $outcome.Failed += 1\n            if ($run.TimedOut -and -not $keepGoing) { return $outcome }\n        }\n    }\n    return $outcome"))
        self.assertIn("Write-GateDiag $gate.Id $run }", body)

    def test_a_later_gate_cannot_mask_an_earlier_failure_in_the_recorded_result(self):
        body = self.function_body("Invoke-SourceGates")
        first = re.findall(
            r"if \(\$outcome\.Failure -eq 0\) \{\n\s+\$outcome\.Failure = \$index\n\s+\$script:RefusalReason = '([a-z]+)'\n", body)
        self.assertEqual(first, ["deadline", "gate"])
        self.assertEqual(len(re.findall(
            r"if \(\$script:RefusalReason -cne 'boundary'\) \{\n\s+\$outcome\.Failure = \$index\n\s+\$script:RefusalReason = 'boundary'\n\s+\$script:GateCause = \$gateCause\n\s+\}\n", body)), 1)
        self.assertEqual(body.count("$outcome.Failure = $index"), 4)
        self.assertEqual(body.count("if ($outcome.Failure -eq 0)"), 3)
        self.assertEqual(body.count("$outcome.Failed += 1"), 5)
        self.assertEqual(body.count("$outcome.Count += 1"), 3)
        self.assertIn("            $outcome.Count += 1\n            $outcome.Failed += 1\n            if ($outcome.Failure -eq 0) {\n", body)
        self.assertEqual(body.count("$script:GateCause = "), 4)
        self.assertIn("            if ($outcome.Failure -eq 0) { $script:GateCause = $gateCause }\n", body)
        self.assertIn("            $gateCause = Get-GateCause $run $boundary\n", body)
        self.assertIn(
            "            $outcome.Failure = $index\n            $script:GateCause = $gateCause\n            $outcome.Failed += 1\n"
            "            $script:RefusalReason = 'log_canary'\n            return $outcome\n", body)
        self.assertNotIn("$outcome.Failure = 0", body)
        self.assertNotIn("$outcome.Failed = ", body)
        self.assertNotIn("$outcome.Failed -= ", body)
        self.assertEqual(self.runner.count("$script:GateFailure = [int]$gateOutcome.Failure\n"), 1)

    def test_the_final_result_is_refused_whenever_any_gate_failed_and_cleanup_still_runs(self):
        refuse = "if ($gateOutcome.Failed -ne 0 -or $gateOutcome.Failure -ne 0) { throw $script:RefusalReason }\n"
        self.assertEqual(self.runner.count(refuse), 1)
        self.assertEqual(self.runner.count("windows-source-run=observed"), 1)
        self.assertLess(self.runner.index(refuse), self.runner.index("windows-source-run=observed"))
        self.assertLess(self.runner.index("Write-PrivateRecord $record\n"), self.runner.index(refuse))
        self.assertIn("if ($gateOutcome.Failed -eq 0 -and $gateOutcome.Failure -eq 0 -and $gateOutcome.Count -eq $plan.Count) { $projectExecution = 'completed' }", self.runner)
        self.assertIn("failed = [int]$gateOutcome.Failed\n", self.runner)
        self.assertIn("failed=0 log_canary=absent project_execution=completed'", self.runner)
        cleanup = self.runner.index("$cleanupLine = 'windows-source-cleanup='")
        emit = "    if ($refusal) {\n        Write-Line $refusal\n        Write-Line $cleanupLine\n        exit 1\n    }\n"
        self.assertEqual(self.runner.count(emit), 1)
        self.assertLess(cleanup, self.runner.index(emit))
        self.assertLess(self.runner.index("$refusal = 'windows-source-run=refused phase='"), cleanup)

    def test_the_added_probes_are_fixed_ids_with_the_exact_commands_and_synthetic_only(self):
        body = self.function_body("Get-SourceProbes")
        ids = re.findall(r"@\{ Id = '([^']+)'", body)
        self.assertEqual(ids[-5:], ["rustfmt_stdin_check", "rustfmt_relative_check", "rustc_version", "cargo_check_api", "node_realpath"])
        self.assertEqual(len(ids), len(set(ids)))
        for token in (
            "$rustc = Join-Path $rustBin 'rustc.exe'\n",
            "$cmd = Join-Path ([string]$env:SystemRoot) 'System32\\cmd.exe'\n",
            "$apiManifest = Join-Path $project 'crates\\host\\api\\Cargo.toml'\n",
            "$relativeLibrary = 'crates\\host\\api\\src\\lib.rs'\n",
            "@{ Id = 'rustfmt_stdin_check'; Needs = $stdinFile; Extra = $none; Argv = [string[]]@($cmd, '/d', '/s', '/c', ('type ' + $stdinFile + ' | ' + $rustfmt + ' --edition 2024 --check')) },\n",
            "@{ Id = 'rustfmt_relative_check'; Needs = $library; Extra = $none; Argv = [string[]]@($rustfmt, '--edition', '2024', '--check', $relativeLibrary) },\n",
            "@{ Id = 'rustc_version'; Needs = ''; Extra = $none; Argv = [string[]]@($rustc, '-vV') },\n",
            "@{ Id = 'cargo_check_api'; Needs = $apiManifest; Extra = [string[]]@($probeTarget); Seconds = $ProbeCargoCheckSeconds; Argv = [string[]]@($cargo, 'check', '--locked', '--offline', '--manifest-path', $apiManifest) },\n",
        ):
            with self.subTest(token=token[:60]):
                self.assertEqual(body.count(token), 1)
        self.assertEqual(self.runner.count("function Get-SourceProbes([string]$project, [string]$rustBin, [string]$stdinFile, [string]$scratchRoot) {\n"), 1)
        self.assertNotIn("--config-path", "".join(item for item in body.splitlines(True) if "rustfmt_stdin_check" in item or "rustfmt_relative_check" in item))
        probes = self.function_body("Invoke-SourceProbes")
        self.assertIn("$stdinFile = Join-Path $script:Lpac.Root 'kd-stdin-input.rs'\n", probes)
        self.assertIn("foreach ($probe in @(Get-SourceProbes $project $rustBin $stdinFile $script:Lpac.Root)) {\n", probes)
        self.assertEqual(probes.count("Copy-Item "), 1)
        self.assertLess(probes.index("-cne 'synthetic'"), probes.index("Copy-Item "))
        self.assertLess(probes.index("Copy-Item "), probes.index("$sandbox.Run("))
        self.assertEqual(len(re.findall(r"Get-SourceProbes\b", self.runner)), 2)
        self.assertIn("$probeTarget = 'CARGO_TARGET_DIR=' + (Join-Path $scratchRoot 'probe-target')\n", body)
        self.assertEqual(body.count("$probeTarget"), 2)
        self.assertEqual(body.count("Seconds = "), 1)
        self.assertIn("\n$ProbeCargoCheckSeconds = 180\n", self.runner)
        self.assertEqual(len(re.findall(r"\$ProbeCargoCheckSeconds\b", self.runner)), 2)
        gate_environment = self.function_body("New-GateEnvironment")
        self.assertNotIn("probe-target", gate_environment)
        self.assertEqual(self.runner.count("probe-target"), 1)

    def layout_parent(self):
        return dict(re.findall(r"\$layout\.([A-Za-z]+) = Join-Path \$layout\.([A-Za-z]+) ", self.runner))

    def layout_root(self, name):
        parents = self.layout_parent()
        for unused in range(16):
            if name not in parents:
                return name
            name = parents[name]
        self.fail("layout cycle")

    def test_every_directory_the_gate_environment_references_is_under_a_granted_root(self):
        self.assertEqual(len(re.findall(r"(?m)^\s*Grant-Access ", self.runner)), 2)
        self.assertIn("Grant-Access $layout.ReadOnly $script:Sid 'ReadAndExecute, Synchronize' $true\n", self.runner)
        self.assertIn("Grant-Access $script:Lpac.Root $script:Sid 'Modify, Synchronize' $true\n", self.runner)
        self.assertIn("ReadOnly = (Join-Path $baseDirectory 'ro')", self.runner)
        self.assertIn("$script:Lpac = New-ScratchSet (Join-Path $baseDirectory 'scratch')", self.runner)
        self.assertIn("$script:Lpac.Project = Join-Path $script:Lpac.Root 'project'", self.runner)
        stage = self.library.split("function New-StageEnvironment", 1)[1].split("\n}\n", 1)[0]
        gate = self.runner.split("function New-GateEnvironment", 1)[1].split("\n}\n", 1)[0]
        self.assertIn("$base = New-StageEnvironment $script:Lpac 'target'", gate)
        self.assertIn("StartsWith('KD_', [StringComparison]::Ordinal)", gate)
        self.assertIn("$root = $script:Lpac.Root", gate)
        lines = [line for line in stage.splitlines() if "('KD_" not in line]
        stage_text = "\n".join(lines)
        used = set(re.findall(r"\$layout\.([A-Za-z]+)", stage_text + gate))
        self.assertEqual(used, {"RustBin", "NodeDir", "MsvcBin", "MsvcLib", "SdkUcrt", "SdkUm"})
        for name in sorted(used):
            with self.subTest(layout=name):
                self.assertEqual(self.layout_root(name), "ReadOnly")
        for name in ("RustPrefix", "NpmCli", "Tarballs", "ProbeDir", "ProbeExe", "TestDir", "NodeTest", "ShimDir", "NpmLinkShim", "NpmLinkMap"):
            with self.subTest(layout=name):
                self.assertEqual(self.layout_root(name), "ReadOnly")
        for name in ("Downloads", "Private", "Base"):
            self.assertNotIn("$layout." + name, stage_text + gate)
        self.assertNotIn("$script:Control", gate + stage_text)
        scratch_fields = set(re.findall(r"\$scratch\.([A-Za-z]+)", stage_text))
        self.assertEqual(scratch_fields, {"Tmp", "Profile", "CargoHome", "Root"})
        constructor = self.library.split("function New-ScratchSet", 1)[1].split("\n}\n", 1)[0]
        for field in ("Tmp", "Profile", "CargoHome", "Crate"):
            self.assertIsNotNone(re.search(field + r" = \(Join-Path \$root '[a-z-]+'\)", constructor), field)
        self.assertIn("Root = $root", constructor)
        self.assertIn("('CARGO_TARGET_DIR=' + (Join-Path $scratch.Root $targetName))", stage)
        for name in re.findall(r"\(Join-Path \$root '([A-Za-z.-]+)'\)", gate):
            self.assertRegex(name, r"^(npm-cache|empty-user\.npmrc|empty-global\.npmrc|npm-prefix)$")
        self.assertEqual(set(re.findall(r"\$env:([A-Za-z]+)", stage_text + gate)), {"SystemRoot", "SystemDrive"})
        self.assertIn("Get-GatePlan $project ($layout.RustBin + '\\cargo.exe') ($layout.NodeDir + '\\node.exe') $layout.NpmCli", self.runner)
        self.assertIn("$project = $script:Lpac.Project", self.runner)

    def test_key_is_destroyed_before_any_project_step_and_again_in_cleanup(self):
        order = [self.runner.index(token) for token in (
            "$phase = 'decrypt'", "$phase = 'materialize'", "$phase = 'npm_tarballs'", "$phase = 'gates'")]
        self.assertEqual(order, sorted(order))
        self.assertIn("key=destroyed x_order=", self.runner)
        self.assertIn("'-Mode', 'destroy'", self.runner)
        self.assertIn("'capsule-destroy=observed key=destroyed'", self.runner)

    def test_capsule_digest_and_bound_values_are_checked_before_decrypt(self):
        self.assertLess(self.runner.index("$phase = 'capsule_verify'"), self.runner.index("$phase = 'decrypt'"))
        self.assertIn("(Get-FileSha256 $capsulePath) -cne $bound['capsule_sha256']", self.runner)
        self.assertIn("$bound['revocation'] -cne 'confirmed'", self.runner)
        self.assertIn("lock_digest", self.runner)
        self.assertIn("manifest_digest", self.runner)

    def test_tree_is_checked_against_the_manifest_with_no_extra_files_or_links(self):
        for token in ("tree_extra", "tree_missing", "tree_hash", "tree_link", "core.symlinks=false", "core.protectNTFS=true",
                      "(100644|100755) blob", "[StringComparer]::Ordinal"):
            self.assertIn(token, self.runner)

    def test_configs_are_neutralised_and_cargo_sources_refused(self):
        self.assertIn("'.npmrc'", self.runner)
        self.assertIn("(?im)^\\s*\\[(?:source\\.|registries\\.)|^\\s*(?:replace-with|registry)\\s*=", self.runner)
        self.assertIn("'^\\s*source\\s*='", self.runner)

    def test_npm_tarballs_are_registry_only_integrity_checked_and_copied_not_moved(self):
        self.assertIn("$uri.Host -cne 'registry.npmjs.org'", self.runner)
        self.assertIn("Assert-Sri $downloaded $integrity 'npm'", self.runner)
        self.assertNotIn("Move-Item", self.runner)

    def test_removals_are_confined_to_harness_roots(self):
        calls = re.findall(r"(?m)^\s*Remove-TreeNoFollow ", self.runner)
        self.assertEqual(len(calls), 1)
        wrapper = self.runner.index("function Remove-WithinRoots")
        self.assertGreater(self.runner.index("    Remove-TreeNoFollow $normal"), wrapper)
        self.assertIn("throw 'remove_root'", self.runner)
        self.assertIn("(Test-PathBelow $normal $system)", self.runner)

    def test_canaries_are_rechecked_so_not_found_is_attributable(self):
        self.assertEqual(self.runner.count("if (-not (Test-CanariesPresent))"), 2)

    def test_exit_zero_requires_verified_cleanup_and_destroyed_key(self):
        tail = self.runner[self.runner.index("if ($cleanup -ne 'verified'"):]
        for token in ("$nullRestore -ne 'verified'", "@('verified', 'not_applied') -cnotcontains $mountRestore", "$keyCleanup -ne 'destroyed'", "$tempState -ne 'removed'", "$processState -ne 'none'"):
            self.assertIn(token, tail)

    def test_deadline_stops_gates_before_the_job_timeout(self):
        self.assertIn("AddMinutes(285)", self.runner)
        self.assertIn("(Get-RemainingSeconds) - 900", self.runner)
        self.assertIsNotNone(re.search(r"timeout-minutes: 330\n", self.workflow))

    def test_frame_driver_keeps_the_vector_refusal_list_and_adds_a_separate_closed_list(self):
        self.assertIn("$script:RefusalReasons = @(\n    'compiler_missing',\n    'compile_failed',\n    'vector_generation_failed',\n    'vector_mismatch',\n    'encoding'\n)", self.frame)
        self.assertIn("$script:DecryptRefusalReasons", self.frame)
        self.assertIn("Remove-ReceiverKey $KeyName", self.frame)
        self.assertIn("CngExportPolicies]::None", self.frame)
        self.assertIn("key=destroyed", self.frame)

    def test_workflow_candidate_job_is_scoped_and_uses_the_environment_secret(self):
        self.assertIn("inputs.profile == 'candidate'", self.workflow)
        self.assertIn("refs/heads/untrusted", self.workflow)
        self.assertIn("KD_WINDOWS_LOG_CANARY", self.workflow)
        self.assertIn("windows-source-exec", self.workflow)
        self.assertNotIn("SOURCE_READER", self.workflow)
        self.assertNotIn("SOURCE_REPOSITORY", self.workflow)
        for name in ("windows_confinement.cs", "windows_confinement.ps1", "windows_probe.rs"):
            self.assertNotIn(name, self.workflow)

    def test_workflow_has_one_job_the_source_input_and_only_the_verifier_publishes_the_verdict(self):
        self.assertEqual(re.findall(r"(?m)^  ([A-Za-z0-9_-]+):\n", self.workflow.split("\njobs:\n", 1)[1]), ["windows-candidate"])
        self.assertIn("    name: role-windows-${{ inputs.role }}-v1\n", self.workflow)
        self.assertIn("      source_sha:\n        required: false\n        type: string\n", self.workflow)
        self.assertIn("CI_SOURCE_SHA: ${{ inputs.source_sha }}", self.workflow)
        self.assertIn("--ref $env:KD_REF", self.workflow)
        step = self.workflow.split("      - name: Publish confinement verdict\n", 1)[1]
        self.assertTrue(step.startswith("        if: ${{ always() && inputs.role == 'verifier' }}\n"))
        self.assertIn("confinement_verdict.py windows-run --record", step)
        self.assertIn("--role $env:KD_ROLE --mode $env:KD_MODE", step)
        self.assertEqual(self.workflow.count("Publish confinement verdict"), 1)
        self.assertNotIn("KD-CONFINEMENT-VERDICT", self.workflow)
        self.assertEqual(self.workflow.count("uses: actions/attest@"), 1)

    def test_the_mount_manager_ladder_is_fixed_ordered_and_escalates_only_in_synthetic_mode(self):
        self.assertIn("\n$MountManagerRungs = @('device', 'volume', 'drive_link', 'mpm_link', 'global_dir')\n", self.runner)
        self.assertIn(
            "\n$MountManagerKinds = @{ device = 'mountmgr'; volume = 'volume'; drive_link = 'drive_link'; mpm_link = 'mpm_link'; global_dir = 'global_dir' }\n",
            self.runner)
        self.assertIn("\n$MountManagerSourceRungs = 2\n", self.runner)
        self.assertIn("\n$MountManagerProbeSeconds = 30\n", self.runner)
        ladder = self.function_body("Invoke-MountManagerLadder")
        self.assertIn("    $limit = $MountManagerSourceRungs\n    if ($script:RunMode -ceq 'synthetic') { $limit = $MountManagerRungs.Count }\n", ladder)
        self.assertEqual(ladder.count("$limit = "), 2)
        self.assertNotIn("'source'", ladder)
        order = (
            "[void](Invoke-FinalPathProbe $sandbox $false 'finalpath_control')",
            "$state.FinalPath = Invoke-FinalPathProbe $sandbox $true 'finalpath_none'",
            "for ($index = 0; $index -lt $limit; $index++) {",
            "$rung = [string]$MountManagerRungs[$index]",
            "$lease = [KeelDock.Platform.WindowsConfinement.DeviceLease]::Open($kind, $script:Sid, $leaseDrive)",
            "$script:MountLeases = @($script:MountLeases) + @($lease)",
            "$rungState = [string]$lease.Apply()",
            "if ($rungState -ceq 'applied') { $rungReadback = [string]$lease.Readback() }",
            "$finalPath = Invoke-FinalPathProbe $sandbox $true ('finalpath_' + $rung)",
            "Write-Line ('windows-confinement-mountmgr-rung=' + $rung + ' state=' + $rungState + ' error=' + $rungError + ' readback=' + $rungReadback + ' finalpath=' + $finalPath)",
            "        if ($rungState -cne 'applied') {\n            $state.State = 'failed'\n            return $state\n        }\n",
            "            $state.Readback = 'mismatch'\n            return $state\n",
            "        if ($finalPath -ceq 'ok') {\n            $state.State = 'applied'\n            return $state\n        }\n",
        )
        positions = [ladder.index(item) for item in order]
        self.assertEqual(positions, sorted(positions))
        self.assertTrue(ladder.endswith("    }\n    return $state"))
        self.assertIn("if ($rungState -ceq 'applied' -and $rungReadback -ceq 'match') {", ladder)
        for rung in ("device", "volume", "drive_link", "mpm_link", "global_dir", "none", "control", "other"):
            self.assertRegex("finalpath_" + rung, r"^[a-z][a-z_]{2,40}$")
        probe = self.function_body("Invoke-FinalPathProbe")
        for token in (
            "$arguments = 'finalpath ' + $script:Lpac.Root",
            "$run = Invoke-ConfinedProbe $sandbox $arguments $MountManagerProbeSeconds",
            "$run = $sandbox.Run($false, $exe,",
            "Write-ProbeDiag $id $run",
            "if (-not (Test-ChannelRunValid $run $confined)) { return 'denied' }",
            "if ((Get-ProbeValue $text 'n_dos') -ceq 'ok' -and (Get-ProbeValue $text 'canon') -ceq 'ok') { return 'ok' }",
        ):
            with self.subTest(token=token[:60]):
                self.assertIn(token, probe)
        self.assertNotIn("Write-Line", probe)
        main = self.runner.index("$phase = 'null_lease'")
        steps = (
            "if ($nullState -ne 'applied' -or $nullReadback -ne 'match') { throw 'null_lease' }\n",
            "            $script:MountState = Invoke-MountManagerLadder $box\n",
            "            if ($script:MountState.Readback -cne 'match') { throw 'mountmgr_readback' }\n",
            "            if ($script:MountState.State -cne 'applied' -and $runMode -cne 'synthetic') { throw ('mountmgr_' + $script:MountState.State) }\n",
            "$phase = 'container_temp'",
            "$phase = 'channels_before'",
        )
        positions = [self.runner.index(item, main) for item in steps]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(self.runner.count("Invoke-MountManagerLadder $box"), 1)

    def test_the_mount_manager_summary_has_a_per_sid_negative_control_and_fixed_tokens(self):
        other = self.function_body("Test-OtherContainerFinalPath")
        for token in (
            "if ($null -eq $script:OtherBox -or [string]::IsNullOrEmpty($script:OtherFolder)) { return 'unknown' }",
            "$container = Join-Path $script:OtherFolder 'AC'",
            "Copy-Item -LiteralPath $script:Layout.ProbeExe -Destination $exe",
            "$run = $script:OtherBox.Run($true, $exe,",
            "Write-ProbeDiag 'finalpath_other' $run",
            "if (-not (Test-ChannelRunValid $run $true)) { return 'unknown' }",
            "if ($device -ceq 'ok' -or $name -ceq 'ok') { return 'granted' }",
        ):
            with self.subTest(token=token[:60]):
                self.assertIn(token, other)
        self.assertTrue(other.endswith("    return 'denied'"))
        self.assertEqual(set(re.findall(r"return '([a-z]+)'", other)), {"unknown", "granted", "denied"})
        self.assertIn(
            "            Test-OtherContainerNul $box\n            $script:MountState.Other = Test-OtherContainerFinalPath\n", self.runner)
        summary = ("Write-Line ('windows-confinement-mountmgr=' + $script:MountState.State + ' rung=' + $script:MountState.Rung"
                   " + ' objects=' + $script:MountState.Objects + ' readback=' + $script:MountState.Readback + ' finalpath='"
                   " + $script:MountState.FinalPath + ' other=' + $script:MountState.Other)")
        self.assertEqual(self.runner.count(summary), 1)
        self.assertIn(
            "if ($script:MountState.Objects -gt 0 -and $script:MountState.Other -cne 'denied' -and $runMode -cne 'synthetic') { throw 'mountmgr_other' }",
            self.runner)
        public = re.compile(re.search(r"PublicLinePattern = '([^']+)'", self.runner).group(1))
        diag = re.compile(re.search(r"DiagLinePattern = '([^']+)'", self.runner).group(1))
        for line in (
            "windows-confinement-mountmgr=applied rung=device objects=1 readback=match finalpath=ok other=denied",
            "windows-confinement-mountmgr=insufficient rung=global_dir objects=4 readback=match finalpath=denied other=unknown",
            "windows-confinement-mountmgr-rung=device state=applied error=0 readback=match finalpath=ok",
            "windows-confinement-mountmgr-rung=global_dir state=failed error=5 readback=na finalpath=na",
            "windows-source-npm-links=created count=1 verified=1",
            "windows-source-npm-link-shim=loaded links=2 map_sha256=" + "0" * 64,
            "windows-source-npm-reify=verified hidden_lock=present",
        ):
            with self.subTest(line=line[:60]):
                self.assertIsNotNone(public.fullmatch(line))
                self.assertIsNone(diag.fullmatch(line))
        for line in ("windows-source-probe id=finalpath_device exit=0x00000000", "windows-source-probe id=npm_link_probe exit=0x00000000",
                     "windows-source-probe-line npm_link npm_link step=fsctl error=5"):
            with self.subTest(line=line[:60]):
                self.assertIsNotNone(diag.fullmatch(line))

    def test_the_volume_rung_is_read_attributes_only_names_the_denied_object_and_keeps_the_negative_controls(self):
        ladder = self.function_body("Invoke-MountManagerLadder")
        for token in (
            "$state = @{ State = 'insufficient'; Rung = 'none'; Objects = 0; Readback = 'match'; FinalPath = 'denied'; Other = 'unknown'; Volume = 'none' }",
            "if ($rung -ceq 'drive_link' -or $rung -ceq 'volume') { $leaseDrive = $drive }",
            "if ($rung -ceq 'volume') { $state.Volume = 'leased' }",
            "if ($rung -cne 'device' -and $rung -cne 'volume') { $script:Channel.LeaseObjects = @($script:Channel.LeaseObjects) + @(($kind + ' ' + $leaseDrive).Trim()) }",
        ):
            with self.subTest(token=token[:60]):
                self.assertIn(token, ladder)
        probe = self.function_body("Invoke-FinalPathProbe")
        self.assertIn("    if ($confined) {\n        $script:FinalPathText = $text\n", probe)
        self.assertIn("        foreach ($key in $VolumeBoundaryTokens) {\n            if ((Get-ProbeValue $text $key) -ceq 'ok') { $script:VolumeBoundary = 'breached' }\n        }\n", probe)
        self.assertIn("\n$VolumeBoundaryTokens = @('volr', 'volrd', 'voldac', 'volown', 'volusn', 'volusnu', 'volenum', 'volntfs', 'volbmp')\n", self.runner)
        self.assertIn("\n$VolumeControlTokens = @('volusn', 'volusnu', 'volenum', 'volntfs', 'volbmp')\n", self.runner)
        clean = self.function_body("Test-VolumeBoundaryClean")
        for token in (
            "if ((Get-ProbeValue $text 'vol') -cne 'ok') { return $false }",
            "foreach ($key in $VolumeBoundaryTokens) {",
            "if ($VolumeControlTokens -ccontains $key) {\n            if ($value -cne 'err5') { return $false }\n        } elseif ($value -cnotmatch '^err[0-9]{1,10}$') {\n            return $false\n        }",
        ):
            with self.subTest(token=token[:60]):
                self.assertIn(token, clean)
        self.assertTrue(clean.endswith("    return $true"))
        self.assertEqual(clean.count("return $true"), 1)
        gate = "            if ($rung -ceq 'volume' -and -not (Test-VolumeBoundaryClean $script:FinalPathText)) { $finalPath = 'unproven' }\n"
        self.assertIn("            $finalPath = Invoke-FinalPathProbe $sandbox $true ('finalpath_' + $rung)\n" + gate + "            $state.FinalPath = $finalPath\n", ladder)
        self.assertEqual(self.runner.count("Test-VolumeBoundaryClean"), 2)
        self.assertLess(probe.index("$script:VolumeBoundary = 'breached'"), probe.index("return 'ok'"))
        self.assertIn("\n$script:FinalPathText = ''\n$script:VolumeBoundary = 'denied'\n", self.runner)
        self.assertEqual(self.runner.count("$script:VolumeBoundary = 'breached'"), 1)
        detail = self.function_body("Get-MountManagerDetail")
        self.assertIn("foreach ($key in @('mpm', 'vol', 'qdvp', 'qpts', 'n_dos', 'canon')) {", detail)
        self.assertIn("foreach ($pair in @('mpm=mountmgr', 'vol=volume', 'qdvp=query', 'n_dos=name', 'canon=canon')) {", detail)
        self.assertIn("if ($parts[0] -ceq 'vol' -and $script:MountState.Volume -cne 'leased') { continue }", detail)
        self.assertLess(detail.index("{ continue }"), detail.index("$denied = $parts[1]"))
        self.assertIn("if ($values['n_dos'] -cne 'ok' -or $values['canon'] -cne 'ok') {", detail)
        self.assertNotIn("Write-Line", detail)
        main = self.runner.index("$script:MountState = Invoke-MountManagerLadder $box")
        steps = (
            "            if ($script:MountState.Readback -cne 'match') { throw 'mountmgr_readback' }\n",
            "            Write-Line (Get-MountManagerDetail)\n",
            "            if ($script:VolumeBoundary -cne 'denied') { throw 'mountmgr_volume' }\n",
            "            if ($script:MountState.State -cne 'applied' -and $runMode -cne 'synthetic') { throw ('mountmgr_' + $script:MountState.State) }\n",
        )
        positions = [self.runner.index(item, main) for item in steps]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(self.runner.count("Get-MountManagerDetail"), 2)
        other = self.function_body("Test-OtherContainerFinalPath")
        for token in (
            "$drive = ([string]$script:Layout.Base).Substring(0, 1)",
            "('\"' + $exe + '\" finalpath ' + $container + ' ' + $drive)",
            "$volume = Get-ProbeValue $text 'vol'",
            "-or $volume -cnotmatch '^(ok|err[0-9]{1,10})$') { return 'unknown' }",
            "if ($volume -ceq 'ok' -and $script:MountState.Volume -ceq 'leased') { return 'granted' }",
        ):
            with self.subTest(token=token[:60]):
                self.assertIn(token, other)
        self.assertLess(other.index("$script:MountState.Volume -ceq 'leased'"), other.index("    return 'denied'"))
        public = re.compile(re.search(r"PublicLinePattern = '([^']+)'", self.runner).group(1))
        for line in (
            "windows-confinement-mountmgr-detail=none mpm=ok vol=err5 qdvp=ok qpts=ok n_dos=ok canon=ok volume_boundary=denied",
            "windows-confinement-mountmgr-detail=volume mpm=ok vol=err5 qdvp=err5 qpts=err5 n_dos=err5 canon=err5 volume_boundary=denied",
            "windows-confinement-mountmgr-rung=volume state=applied error=0 readback=match finalpath=ok",
            "windows-confinement-mountmgr-rung=volume state=applied error=0 readback=match finalpath=unproven",
        ):
            with self.subTest(line=line[:60]):
                self.assertIsNotNone(public.fullmatch(line))

    def test_the_layout_lives_on_the_system_volume_and_the_volume_facts_name_both_volumes(self):
        prepare = self.runner[self.runner.index("$phase = 'workspace_prepare'"):self.runner.index("$phase = 'lpac_profile'")]
        for token in (
            "$systemRoot = [IO.Path]::GetPathRoot([Environment]::SystemDirectory)",
            "if ($systemRoot -cnotmatch '^[A-Za-z]:\\\\$') { throw 'workspace_path' }",
            "$baseDirectory = Join-Path $systemRoot ('kd-source-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))",
            "if ($baseDirectory -notmatch '^[A-Za-z]:\\\\[A-Za-z0-9_.\\\\-]+$') { throw 'workspace_path' }",
            "Register-RemovalRoot $baseDirectory",
        ):
            with self.subTest(token=token[:60]):
                self.assertIn(token, prepare)
        self.assertNotIn("Join-Path $runnerTemp ('kd-source-'", self.runner)
        self.assertIn("\n$VolumeOpenTokens = @('vdos', 'vnt', 'vguid', 'vqdvp', 'vqpts')\n", self.runner)
        facts = self.function_body("Write-VolumeFacts")
        for token in (
            "foreach ($entry in @(@('base', $baseDrive, [string]$script:Lpac.Root), @('temp', $tempDrive, $tempRoot))) {",
            "[KeelDock.Platform.WindowsConfinement.VolumeFacts]::Describe($drive, [string]$entry[2])",
            "[KeelDock.Platform.WindowsConfinement.VolumeFacts]::VolumeNumber($drive)",
            "[KeelDock.Platform.WindowsConfinement.VolumeFacts]::VolumeGuid($drive)",
            "if ($facts -cnotmatch '^[a-z0-9=._ -]{1,400}$') { $facts = 'state=invalid' }",
            "if ($number -cnotmatch '^[0-9]{1,4}$') { $number = '-' }",
            "if ($guid -cnotmatch '^\\{[0-9A-Fa-f-]{36}\\}$') { $guid = '-' }",
            "Write-Line ('windows-confinement-volume-facts=' + $role + ' same_volume=' + $same + ' ' + $facts)",
            "$run = Invoke-ConfinedProbe $sandbox ('volopen ' + $drive + ' ' + $number + ' ' + $guid) $MountManagerProbeSeconds",
            "Write-ProbeDiag ('volopen_' + $role) $run",
            "if (Test-ChannelRunValid $run $true) {",
            "if ($value -cmatch '^(ok|na|err[0-9]{1,10}|usage_drive)$') { $values[$key] = $value }",
            "$line = 'windows-confinement-volume-open=' + $role",
        ):
            with self.subTest(token=token[:60]):
                self.assertIn(token, facts)
        for forbidden in ("DeviceLease", "Apply()", "Grant-", "Set-Acl", "$script:MountLeases"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, facts)
        main = self.runner.index("$script:MountState = Invoke-MountManagerLadder $box")
        steps = (
            "            Write-Line (Get-MountManagerDetail)\n",
            "            Write-VolumeFacts $box\n",
            "            if ($script:VolumeBoundary -cne 'denied') { throw 'mountmgr_volume' }\n",
        )
        positions = [self.runner.index(item, main) for item in steps]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(self.runner.count("Write-VolumeFacts $box"), 1)
        self.assertRegex("volopen_base", r"^[a-z][a-z_]{2,40}$")
        self.assertRegex("volopen_temp", r"^[a-z][a-z_]{2,40}$")
        public = re.compile(re.search(r"PublicLinePattern = '([^']+)'", self.runner).group(1))
        for line in (
            "windows-confinement-volume-facts=base same_volume=no qdd=harddisk num=3 ntdev=same guid=ok guiddev=same leaseobj=same"
            " fs=ntfs fsflags=0x03e706ff dtype=fixed bus=scsi rmv=0 label=none deny=none allow=ba.sy.wd",
            "windows-confinement-volume-open=temp vdos=err5 vnt=err5 vguid=err5 vqdvp=err5 vqpts=err5",
        ):
            with self.subTest(line=line[:60]):
                self.assertIsNotNone(public.fullmatch(line))

    def test_the_system_volume_base_is_created_protected_checked_for_space_and_its_ancestor_aces_are_revoked(self):
        prepare = self.runner[self.runner.index("$phase = 'workspace_prepare'"):self.runner.index("$phase = 'lpac_profile'")]
        space = (
            "            $baseFree = [uint64](New-Object System.IO.DriveInfo($systemRoot)).AvailableFreeSpace\n"
            "            Write-Line ('windows-confinement-volume-space=base free_gib=' + [string][math]::Floor($baseFree / 1073741824))\n"
            "            if ($baseFree -lt 21474836480) { throw 'workspace_space' }\n"
        )
        self.assertIn(space, prepare)
        self.assertLess(prepare.index("throw 'workspace_space'"), prepare.index("$baseDirectory = Join-Path $systemRoot"))
        self.assertEqual(21474836480, 20 * 1073741824)
        protected = (
            "            $baseSecurity = New-Object System.Security.AccessControl.DirectorySecurity\n"
            "            $baseSecurity.SetAccessRuleProtection($true, $false)\n"
            "            foreach ($ownerSid in @('S-1-5-18', 'S-1-5-32-544', [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)) {\n"
            "                $baseSecurity.AddAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule((New-Object System.Security.Principal.SecurityIdentifier($ownerSid)), 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')))\n"
            "            }\n"
            "            [void][System.IO.FileSystemAclExtensions]::CreateDirectory($baseSecurity, $layout.Base)\n"
            "            foreach ($directory in @($layout.Downloads, $layout.ReadOnly, $layout.Private, $script:Lpac.Root, $script:Control.Root)) {\n"
        )
        self.assertIn(protected, prepare)
        self.assertNotIn("@($layout.Base, $layout.Downloads", self.runner)
        self.assertEqual(self.runner.count("FileSystemAclExtensions]::CreateDirectory("), 1)
        self.assertEqual(self.runner.count("AddAccessRule("), 1)
        for forbidden in ("S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-15-2"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, prepare)
        self.assertLess(self.runner.index("CreateDirectory($baseSecurity, $layout.Base)"), self.runner.index("Grant-Access $layout.ReadOnly"))
        public = re.compile(re.search(r"PublicLinePattern = '([^']+)'", self.runner).group(1))
        for line in (
            "windows-confinement-volume-space=base free_gib=0",
            "windows-confinement-volume-space=base free_gib=112",
            "windows-confinement-volume-space=after free_gib=0",
            "windows-confinement-volume-space=after free_gib=112",
            "windows-confinement-volume-space=after free_gib=unknown",
        ):
            with self.subTest(line=line):
                self.assertIsNotNone(public.fullmatch(line))
        after = (
            "            $afterGib = 'unknown'\n"
            "            try { $afterGib = [string][math]::Floor([uint64](New-Object System.IO.DriveInfo($systemRoot)).AvailableFreeSpace / 1073741824) } catch { $afterGib = 'unknown' }\n"
            "            Write-Line ('windows-confinement-volume-space=after free_gib=' + $afterGib)\n"
        )
        self.assertIn(after, self.runner)
        self.assertLess(self.runner.index("$gateOutcome = Invoke-SourceGates"), self.runner.index(after))
        self.assertLess(self.runner.index(after), self.runner.index("$phase = 'channels_after'"))
        revoke = self.function_body("Revoke-NonPropagating")
        for token in (
            "$bytes = [KeelDock.Platform.WindowsConfinement.NonPropagatingDacl]::Read($path)",
            "for ($index = $descriptor.DiscretionaryAcl.Count - 1; $index -ge 0; $index--) {",
            "$ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed -and $ace.AccessMask -eq 1048704 -and [int]$ace.AceFlags -eq 0",
            "$descriptor.DiscretionaryAcl.RemoveAce($index)",
            "if ($removed -ne 1) { throw 'ancestor_revoke' }",
            "[KeelDock.Platform.WindowsConfinement.NonPropagatingDacl]::Write($path, $updated)",
        ):
            with self.subTest(token=token[:60]):
                self.assertIn(token, revoke)
        self.assertIn("\n$script:GrantedAncestors = @()\n", self.runner)
        self.assertIn(
            "                Grant-NonPropagating $ancestorPath $script:Sid\n"
            "                $script:GrantedAncestors = @($script:GrantedAncestors) + @($ancestorPath)\n",
            self.runner,
        )
        tail = self.runner[self.runner.index("$nullRestore = 'not_applied'"):]
        for token in (
            "    $ancestorState = 'not_applied'\n",
            "        for ($ancestorIndex = $grantedAncestors.Count - 1; $ancestorIndex -ge 0; $ancestorIndex--) {\n",
            "                Revoke-NonPropagating $ancestor $script:Sid\n",
            "                if ($ancestorState -cne 'failed') { $ancestorState = 'revoked' }\n",
            "    if ($ancestorState -eq 'failed') { $cleanup = 'incomplete' }\n",
            "-or @('revoked', 'not_applied') -cnotcontains $ancestorState -or",
        ):
            with self.subTest(token=token[:60]):
                self.assertIn(token, tail)
        order = ("Remove-WithinRoots $baseDirectory", "Revoke-NonPropagating $ancestor $script:Sid", "$cleanupLine = 'windows-source-cleanup='")
        positions = [tail.index(item) for item in order]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(self.runner.count("Revoke-NonPropagating"), 2)
        self.assertIsNotNone(public.fullmatch(
            "windows-source-cleanup=verified null_restore=verified mountmgr_restore=verified key=destroyed profile=deleted"
            " temp_dir=removed ancestors=revoked links=verified processes=none liveness=job"))

    def test_the_npm_link_target_probe_runs_npm_realpath_confined_and_prints_only_fixed_tokens(self):
        script = re.search(r'^\$NpmLinkTargetScript = "([^"]+)"$', self.runner, re.M).group(1)
        self.assertIsNone(re.search(r"[\s\"$`]", script))
        self.assertIn("'@npmcli','arborist','lib','realpath.js'", script)
        self.assertIn("a(l,new(Map),new(Map),0)", script)
        self.assertEqual(
            re.findall(r"'([a-z]+)='\+", script),
            ["index", "lstat", "readlink", "stat", "native", "pkg", "arborist"])
        self.assertIn("['kd-probe','npmlink',", script)
        self.assertIn("filter((n)=>k[n].link).slice(0,MAXLINKS).map(", script)
        self.assertEqual(script.count("MAXLINKS"), 1)
        self.assertNotIn("console", script)
        probe = self.function_body("Invoke-NpmLinkTargetProbe")
        self.assertTrue(probe.split("\n", 1)[1].startswith(
            "    if ($script:RunMode -cne 'synthetic') { return }\n    if ($null -eq $script:NpmLinkShim) { return }\n"))
        self.assertIn("$argv = [string[]]@($node, '--require', [string]$script:Layout.NpmLinkShim, '-e', $NpmLinkTargetScript.Replace('MAXLINKS', [string]$MaxNpmLinks))", probe)
        self.assertNotIn("$argv = [string[]]@($node, '-e',", probe)
        self.assertNotIn("Write-Line", probe)
        steps = self.function_body("Invoke-NpmLinkSteps")
        call = "    if ($created -gt 0) { Invoke-NpmLinkTargetProbe $sandbox $project ([string]@($gate.Then)[0]) $shimEnvironment }\n"
        self.assertIn("Invoke-NpmLinkProbe $sandbox $project ([string]@($script:NpmLinks)[0].Target) }\n" + call, steps)
        self.assertLess(steps.index(call), steps.index("$second = $sandbox.Run("))
        diag = re.compile(re.search(r"DiagLinePattern = '([^']+)'", self.runner).group(1))
        for line in (
            "windows-source-probe id=npm_link_targets exit=0x00000000",
            "windows-source-probe-line kd-probe npmlink index=0 lstat=ok readlink=ok stat=ok native=ok pkg=ok arborist=ok",
        ):
            with self.subTest(line=line[:60]):
                self.assertIsNotNone(diag.fullmatch(line))

    def test_the_mount_manager_leases_are_restored_in_reverse_before_the_profile_and_reported(self):
        tail = self.runner[self.runner.index("$nullRestore = 'not_applied'"):]
        for token in (
            "    $mountRestore = 'not_applied'\n",
            "        $leases = @($script:MountLeases)\n",
            "        for ($leaseIndex = $leases.Count - 1; $leaseIndex -ge 0; $leaseIndex--) {\n",
            "            $leaseRestore = [string]$leases[$leaseIndex].Restore()\n",
            "            if ($leaseRestore -cne 'verified' -and $leaseRestore -cne 'not_applied') { $mountRestore = 'failed' }\n",
            "        $mountRestore = 'failed'\n",
            "    if ($mountRestore -eq 'failed') { $cleanup = 'incomplete' }\n",
            "' null_restore=' + $nullRestore + ' mountmgr_restore=' + $mountRestore + ' key=' + $keyCleanup",
        ):
            with self.subTest(token=token[:60]):
                self.assertIn(token, tail)
        order = ("$script:NullLease.Restore()", "$leases[$leaseIndex].Restore()", "Get-JobLiveness", "$box.Dispose()",
                 "$script:OtherBox.Dispose()", "Remove-WithinRoots $baseDirectory", "$cleanupLine = 'windows-source-cleanup='")
        positions = [tail.index(item) for item in order]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(self.runner.count(".Restore()"), 2)

    def test_the_junction_acl_lease_is_removed_with_its_cleanup_token(self):
        for token in ("NpmLinkLease", "Grant-NpmLinkLeases", "Restore-NpmLinkLeases", "Test-NpmLinkLease", "Read-NpmLinkAcl",
                      "Get-NpmLinkPrior", "Get-AclHex", "ReadLinkDacl", "WriteLinkDacl", "OpenNoFollowError", "npm_link_lease",
                      "npm-link-lease", "npm_link_restore", "$linkRestore", "'after'"):
            with self.subTest(token=token):
                self.assertNotIn(token, self.runner)
        native = (ROOT / "kit/confinement/windows_confinement.cs").read_text(encoding="utf-8")
        self.assertNotIn("npm_link_lease", native)
        native = native[native.index("public static class JunctionMaker"):]
        for token in ("ReadLinkDacl", "WriteLinkDacl", "OpenNoFollowError", "GetKernelObjectSecurity", "SetKernelObjectSecurity",
                      "WriteDac", "ReadControl", "DaclSecurityInformation", "MaxDescriptorBytes"):
            with self.subTest(native=token):
                self.assertNotIn(token, native)
        tail = self.runner[self.runner.index("$nullRestore = 'not_applied'"):]
        self.assertIn("' temp_dir=' + $tempState + ' ancestors=' + $ancestorState + ' links=' + $linksState + ' processes=' + $processState + ' liveness=job'", tail)
        self.assertIn("-cnotcontains $mountRestore -or $keyCleanup -ne 'destroyed' -or", tail)

    def test_the_npm_link_shim_is_staged_read_only_from_the_pinned_file(self):
        self.assertIn("\n$NpmLinkShimFile = 'windows_npm_link_shim.cjs'\n", self.runner)
        pinned = re.search(r"^\$NpmLinkShimSha256 = '([0-9a-f]{64})'$", self.runner, re.M).group(1)
        self.assertEqual(hashlib.sha256(SHIM.read_bytes()).hexdigest(), pinned)
        self.assertEqual(PINNED_FILE_SHA256["kit/confinement/windows_npm_link_shim.cjs"], pinned)
        self.assertIn("kit/confinement/windows_npm_link_shim.cjs", PLATFORM_FILES)
        self.assertIn("\n$NpmLinkShimGates = @('node_dependency_audit')\n", self.runner)
        self.assertIn("\n$MaxNpmLinkMapBytes = 65536\n", self.runner)
        self.assertIn("\n$script:NpmLockDigest = ''\n$script:NpmLinkShim = $null\n", self.runner)
        for token in (
            "$layout.ShimDir = Join-Path $layout.ReadOnly 'shim'\n",
            "$layout.NpmLinkShim = Join-Path $layout.ShimDir 'npm_link_shim.cjs'\n",
            "$layout.NpmLinkMap = Join-Path $layout.ShimDir 'npm_link_map.json'\n",
            "foreach ($directory in @($layout.RustPrefix, $layout.NodeDir, $layout.ProbeDir, $layout.TestDir, $layout.Tarballs, $layout.ShimDir)) {\n",
        ):
            with self.subTest(token=token[:60]):
                self.assertEqual(self.runner.count(token), 1)
        stage = (
            "            if ([string]$npmPackage.version -cne $NpmVersion) { throw 'npm_version' }\n"
            "            $shimSource = Join-Path $PSScriptRoot $NpmLinkShimFile\n"
            "            $shimRaw = [IO.File]::ReadAllBytes($shimSource)\n"
            "            $shimText = [Text.Encoding]::Latin1.GetString($shimRaw)\n"
            "            if ($shimRaw.Length -lt 1 -or $shimText -cmatch '[^\\x00-\\x7F]') { throw 'npm_link_shim' }\n"
            "            $shimText = $shimText.Replace(\"`r`n\", \"`n\")\n"
            "            if ($shimText.Contains(\"`r\")) { throw 'npm_link_shim' }\n"
            "            $shimBytes = [Text.Encoding]::ASCII.GetBytes($shimText)\n"
            "            if ([Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($shimBytes)).ToLowerInvariant() -cne $NpmLinkShimSha256) { throw 'npm_link_shim' }\n"
            "            [System.IO.File]::WriteAllBytes($layout.NpmLinkShim, $shimBytes)\n"
            "            [IO.File]::SetAttributes($layout.NpmLinkShim, [IO.FileAttributes]::ReadOnly)\n"
            "            if ((Get-FileSha256 $layout.NpmLinkShim) -cne $NpmLinkShimSha256) { throw 'npm_link_shim' }\n"
            "\n            $phase = 'stage_msvc'\n"
        )
        self.assertEqual(self.runner.count(stage), 1)
        self.assertLess(self.runner.index(stage), self.runner.index("$phase = 'gates'\n"))
        self.assertNotIn("Copy-Item -LiteralPath $shimSource", self.runner)
        self.assertEqual(self.runner.count("$NpmLinkShimFile"), 2)
        shim_bytes = SHIM.read_bytes()
        self.assertNotIn(b"\r", shim_bytes)
        self.assertEqual(shim_bytes.decode("ascii").encode("ascii"), shim_bytes)
        crlf = shim_bytes.replace(b"\n", b"\r\n")
        self.assertEqual(crlf.decode("ascii").replace("\r\n", "\n").encode("ascii"), shim_bytes)

    def test_npm_config_files_are_swept_and_rewritten_immediately_before_the_stepped_npm_gate(self):
        body = self.function_body("Reset-NpmConfigFiles")
        order = (
            "    foreach ($entry in @(Get-SourceWalk $project '.npmrc' $false)) {\n        [IO.File]::Delete($entry.Substring(2))\n    }\n",
            "    if (@(Get-SourceWalk $project '.npmrc' $false).Count -ne 0) { throw 'npm_config' }\n",
            "    foreach ($name in @('empty-user.npmrc', 'empty-global.npmrc')) {\n",
            "        $path = Join-Path $script:Lpac.Root $name\n",
            "if (([int]$info.Attributes -band ([int][IO.FileAttributes]::ReparsePoint -bor [int][IO.FileAttributes]::Directory)) -ne 0) { throw 'npm_config' }\n            [IO.File]::Delete($path)\n",
            "        [IO.File]::WriteAllText($path, '', (New-Object System.Text.UTF8Encoding($false)))\n",
            "if (([int]$written.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0 -or $written.Length -ne 0) { throw 'npm_config' }",
        )
        positions = [body.index(item) for item in order]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(body.count("throw 'npm_config'"), 3)
        self.assertNotIn("Write-Line", body)
        self.assertNotIn("RunMode", body)
        self.assertIn("foreach ($npmConfigName in @('empty-user.npmrc', 'empty-global.npmrc')) { [IO.File]::WriteAllText((Join-Path $script:Lpac.Root $npmConfigName), '', $encoding) }", self.runner)
        gates = self.function_body("Invoke-SourceGates")
        call = "        if ($gate.Id -ceq $NpmSteppedGate) { Reset-NpmConfigFiles $project }\n        $argv = [string[]]$gate.Argv\n"
        self.assertEqual(gates.count(call), 1)
        self.assertLess(gates.index(call), gates.index("$run = $sandbox.Run($true, $exe, $commandLine, $project, $gateEnvironment"))
        self.assertEqual(self.runner.count("Reset-NpmConfigFiles"), 2)
        self.assertLess(self.runner.index("Remove-SourceConfigFiles $project\n"), self.runner.index("$gateOutcome = Invoke-SourceGates"))

    def test_the_npm_link_map_is_written_read_only_from_the_verified_plan_and_announced_without_paths(self):
        body = self.function_body("Initialize-NpmLinkShim")
        order = (
            "    $shim = [string]$script:Layout.NpmLinkShim\n    $mapPath = [string]$script:Layout.NpmLinkMap\n",
            "if ((Get-FileSha256 $shim) -cne $NpmLinkShimSha256) { throw 'npm_link_shim' }",
            "if (Test-Path -LiteralPath $mapPath) { throw 'npm_link_shim' }",
            "foreach ($link in @($script:NpmLinks)) {",
            "$linkRelative = ([string]$link.Link).Replace('/', '\\')",
            "$targetRelative = ([string]$link.Target).Replace('/', '\\')",
            "$entry = [ordered]@{ link = (Join-Path $project $linkRelative); target = (Join-Path $project $targetRelative) }",
            r"if ($value -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9@._\\-]+$' -or $value -match '(^|\\)\.\.?(\\|$)' -or $value.Length -gt 1000) { throw 'npm_link_shim' }",
            "if ($entries.Count -lt 1 -or $entries.Count -gt $MaxNpmLinks) { throw 'npm_link_shim' }",
            "$json = ConvertTo-Json -InputObject ([ordered]@{ schema_version = 1; links = [object[]]$entries }) -Depth 4 -Compress",
            "[IO.File]::WriteAllText($mapPath, $json, (New-Object System.Text.UTF8Encoding($false)))",
            "[IO.File]::SetAttributes($mapPath, [IO.FileAttributes]::ReadOnly)",
            "if (([IO.File]::GetAttributes($mapPath) -band [IO.FileAttributes]::ReadOnly) -eq 0) { throw 'npm_link_shim' }",
            "$bytes = [byte[]][KeelDock.Platform.WindowsConfinement.JunctionMaker]::ReadNoFollow($mapPath, $MaxNpmLinkMapBytes)",
            "if ([Text.Encoding]::ASCII.GetString($bytes) -cne $json) { throw 'npm_link_shim' }",
            "$digest = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant()",
            "$script:NpmLinkShim = @{ Count = $entries.Count; Sha256 = $digest; Environment = [string[]]@(('KD_NPM_LINK_MAP=' + $mapPath), ('KD_NPM_LINK_MAP_SHA256=' + $digest)) }",
            "Write-Line ('windows-source-npm-link-shim=loaded links=' + $entries.Count + ' map_sha256=' + $digest)",
        )
        positions = [body.index(item) for item in order]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(body.count("throw 'npm_link_shim'"), 6)
        self.assertEqual(body.count("Write-Line"), 1)
        self.assertNotIn("RunMode", body)
        self.assertEqual(self.runner.count("KD_NPM_LINK_MAP"), 2)
        self.assertEqual(self.runner.count("Initialize-NpmLinkShim"), 2)
        public = re.compile(re.search(r"PublicLinePattern = '([^']+)'", self.runner).group(1))
        self.assertIsNotNone(public.fullmatch("windows-source-npm-link-shim=loaded links=2 map_sha256=" + "a" * 64))
        add = self.function_body("Add-NpmLinkShim")
        for token in (
            "    if ($null -eq $script:NpmLinkShim) { return , $argv }\n",
            "    $node = [string]$script:Layout.NodeDir + '\\node.exe'\n",
            "    if ($argv.Count -lt 3 -or $argv[0] -cne $node -or $argv[1] -cne [string]$script:Layout.NpmCli) { throw 'npm_link_shim' }\n",
            "    return , ([string[]](@($argv[0], '--require', [string]$script:Layout.NpmLinkShim) + @($argv[1..($argv.Count - 1)])))",
        ):
            with self.subTest(token=token[:60]):
                self.assertIn(token, add)
        environment = self.function_body("Get-NpmLinkShimEnvironment")
        self.assertIn("    if ($null -eq $script:NpmLinkShim) { return , $environment }\n", environment)
        self.assertIn("    return , ([string[]](@($environment) + @($script:NpmLinkShim.Environment)))", environment)
        self.assertEqual(self.runner.count("Add-NpmLinkShim"), 3)
        self.assertEqual(self.runner.count("Get-NpmLinkShimEnvironment"), 3)
        self.assertEqual(self.runner.count("'--require'"), 2)
        self.assertIn("    if ($script:RunMode -cne 'synthetic') { return }\n    if ($null -eq $script:NpmLinkShim) { return }\n",
                      self.function_body("Invoke-NpmLinkTargetProbe"))

    def test_the_npm_link_shim_preload_reads_only_its_hashed_map_and_never_writes_spawns_or_connects(self):
        shim = SHIM.read_text(encoding="ascii")
        self.assertEqual(re.findall(r"require\('([a-z:]+)'\)", shim), ["node:fs", "node:path", "node:crypto"])
        self.assertEqual(shim.count("require("), 3)
        for forbidden in ("writeFile", "appendFile", "WriteStream", "writeSync", "child_process", "spawn", "exec", "fork",
                          "node:net", "node:http", "node:https", "node:dgram", "node:tls", "node:dns", "fetch", "WebSocket",
                          "Worker", "symlink", "unlink", "rmSync", "rmdir", "mkdir", "rename", "chmod", "chown", "utimes",
                          "openSync", "fs.open", "copyFile", "cpSync", "truncate", "process.binding", "eval(", "Function(",
                          "import(", "console", "process.stdout", "process.stderr", "process.exit", "setTimeout",
                          "setInterval", "module.exports", "globalThis"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, shim)
        self.assertEqual(set(re.findall(r"\bfs\.([A-Za-z]+)", shim)),
                         {"readFileSync", "constants", "promises", "Stats", "lstat", "lstatSync", "readlink", "readlinkSync"})
        self.assertEqual(shim.count("readFileSync"), 1)
        self.assertEqual(set(re.findall(r"\bpromises\.([A-Za-z]+)", shim)), {"lstat", "readlink"})
        self.assertIn("const MAP_VARIABLE = 'KD_NPM_LINK_MAP';\nconst HASH_VARIABLE = 'KD_NPM_LINK_MAP_SHA256';\n", shim)
        self.assertIn("const refuse = (reason) => {\n  throw new Error('npm_link_shim refused ' + reason);\n};\n", shim)
        self.assertLess(shim.index("const links = loadMap();"), shim.index("\nfs.lstat = "))

    def test_the_npm_link_shim_refuses_a_missing_mismatched_or_malformed_map_before_wrapping(self):
        shim = SHIM.read_text(encoding="ascii")
        load = shim[shim.index("const loadMap = "):shim.index("const links = loadMap();")]
        order = (
            "  const mapPath = process.env[MAP_VARIABLE];\n  const expected = process.env[HASH_VARIABLE];\n"
            "  delete process.env[MAP_VARIABLE];\n  delete process.env[HASH_VARIABLE];\n",
            "|| !PRINTABLE.test(mapPath) || !path.isAbsolute(mapPath)) refuse('map_path');",
            "if (typeof expected !== 'string' || !HEX.test(expected)) refuse('map_hash');",
            "const payload = fs.readFileSync(mapPath);",
            "if (payload.length < 2 || payload.length > MAX_MAP_BYTES) refuse('map_size');",
            "const actual = crypto.createHash('sha256').update(payload).digest('hex');",
            "if (actual !== expected) refuse('map_hash');",
            "if (!PRINTABLE.test(text)) refuse('map_text');",
            "map = JSON.parse(text);",
            "refuse('map_json');",
            "if (!plainObject(map) || !keysAre(map, 'links,schema_version') || map.schema_version !== 1",
            "|| !Array.isArray(map.links)) refuse('map_shape');",
            "if (map.links.length < 1 || map.links.length > MAX_LINKS) refuse('map_count');",
            "if (!plainObject(entry) || !keysAre(entry, 'link,target')) refuse('map_entry');",
            "if (!windowsPath(entry.link) || !windowsPath(entry.target) || !LINK_TAIL.test(entry.link)) refuse('map_path');",
            "if (project.length < 3 || !target.startsWith(project + '\\\\') || target.includes(MODULES)",
            "|| target.endsWith('\\\\node_modules') || links.has(key)) refuse('map_entry');",
            "links.set(key, entry.target);",
            "  return links;\n",
        )
        positions = [load.index(item) for item in order]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(len(re.findall(r"refuse\('([a-z_]+)'\)", load)), 11)
        self.assertEqual(sorted(set(re.findall(r"refuse\('([a-z_]+)'\)", load))),
                         ["map_count", "map_entry", "map_hash", "map_json", "map_path", "map_shape", "map_size", "map_text"])
        self.assertIn("const MAX_MAP_BYTES = 65536;\nconst MAX_LINKS = 64;\n", shim)
        self.assertIn(r"if (!/^[A-Za-z]:\\/.test(value)) return false;", shim)
        self.assertIn("if (!SEGMENT.test(segment) || DOTS.test(segment)) return false;", shim)
        self.assertIn("return path.win32.normalize(value) === value;", shim)
        self.assertIn(r"const LINK_TAIL = /\\node_modules\\(?:@[a-z0-9][a-z0-9._-]{0,99}\\)?[a-z0-9][a-z0-9._-]{0,99}$/;", shim)
        self.assertIn("&& Object.getPrototypeOf(value) === Object.prototype;", shim)
        guard = "for (const item of [realLstat, realLstatSync, realReadlink, realReadlinkSync, realPromiseLstat, realPromiseReadlink]) {\n  if (typeof item !== 'function') refuse('fs_shape');\n}\n"
        self.assertIn(guard, shim)
        self.assertLess(shim.index(guard), shim.index("\nfs.lstat = "))

    def test_the_npm_link_shim_wraps_exactly_six_functions_and_passes_every_unlisted_path_through(self):
        shim = SHIM.read_text(encoding="ascii")
        assigned = re.findall(r"^((?:fs|promises)\.[A-Za-z]+) = (?:async )?function ([A-Za-z]+)\(", shim, re.M)
        self.assertEqual(assigned, [
            ("fs.lstat", "lstat"), ("fs.lstatSync", "lstatSync"), ("promises.lstat", "lstat"),
            ("fs.readlink", "readlink"), ("fs.readlinkSync", "readlinkSync"), ("promises.readlink", "readlink")])
        self.assertEqual(len(re.findall(r"^(?:fs|promises)\.[A-Za-z]+ = ", shim, re.M)), 6)
        bodies = re.split(r"\n(?=(?:fs|promises)\.[A-Za-z]+ = )", shim)[1:]
        self.assertEqual(len(bodies), 6)
        passes = (
            ("realLstat", "  if (target === undefined || typeof done !== 'function' || bigintRequested(options)) {\n    return Reflect.apply(realLstat, this, arguments);\n  }\n  process.nextTick(done, null, linkStats(target));\n"),
            ("realLstatSync", "  if (target === undefined || bigintRequested(options)) return Reflect.apply(realLstatSync, this, arguments);\n  return linkStats(target);\n"),
            ("realPromiseLstat", "  if (target === undefined || bigintRequested(options)) return Reflect.apply(realPromiseLstat, this, arguments);\n  return linkStats(target);\n"),
            ("realReadlink", "  if (value === undefined || typeof done !== 'function') return Reflect.apply(realReadlink, this, arguments);\n  process.nextTick(done, null, value);\n"),
            ("realReadlinkSync", "  if (value === undefined) return Reflect.apply(realReadlinkSync, this, arguments);\n  return value;\n"),
            ("realPromiseReadlink", "  if (value === undefined) return Reflect.apply(realPromiseReadlink, this, arguments);\n  return value;\n"),
        )
        for body, (real, tail) in zip(bodies, passes):
            with self.subTest(real=real):
                self.assertTrue(body.split("\n", 2)[1] == "  const target = lookup(candidate);")
                self.assertIn(tail, body)
                self.assertEqual(body.count("Reflect.apply("), 1)
                self.assertEqual(body.count("Reflect.apply(" + real + ", this, arguments)"), 1)
        lookup = shim[shim.index("const lookup = "):shim.index("const bigintRequested = ")]
        self.assertIn("  if (typeof candidate !== 'string' || candidate.length < 4 || candidate.length > MAX_PATH_LENGTH) return undefined;\n", lookup)
        self.assertIn("  return links.get(path.win32.resolve(candidate).toLowerCase());\n", lookup)
        self.assertIn("const key = entry.link.toLowerCase();", shim)
        self.assertIn("const LINK_MODE = (typeof constants.S_IFLNK === 'number' ? constants.S_IFLNK : 0o120000) | 0o666;\n", shim)
        self.assertEqual(0o120000, 0xA000)
        stats = shim[shim.index("const linkStats = "):shim.index("const linkValue = ")]
        for token in (
            "const stats = Object.create(STATS_PROTOTYPE);",
            "mode: LINK_MODE, nlink: 1,",
            "size: Buffer.byteLength(target, 'utf8'),",
            "['isSymbolicLink', true], ['isDirectory', false], ['isFile', false], ['isBlockDevice', false],",
            "['isCharacterDevice', false], ['isFIFO', false], ['isSocket', false],",
            "Object.defineProperty(stats, name, { value: () => answer, writable: true, enumerable: false, configurable: true });",
        ):
            with self.subTest(token=token[:60]):
                self.assertIn(token, stats)
        value = shim[shim.index("const linkValue = "):shim.index("\nfs.lstat = ")]
        self.assertIn("if (encoding === undefined || encoding === null || encoding === 'utf8' || encoding === 'utf-8') return target;", value)
        self.assertIn("if (encoding === 'buffer') return Buffer.from(target, 'utf8');\n  return undefined;", value)

    def test_the_reparse_probe_runs_confined_once_on_the_first_junction_before_the_shim(self):
        probe = self.function_body("Invoke-NpmReparseProbe")
        self.assertTrue(probe.split("\n", 1)[1].startswith("    if ($script:RunMode -cne 'synthetic') { return }\n"))
        self.assertIn("$relative = ([string]@($script:NpmLinks)[0].Link).Replace('/', '\\')", probe)
        self.assertIn("$run = Invoke-ConfinedProbe $sandbox ('reparse ' + $link) $MountManagerProbeSeconds", probe)
        self.assertNotIn("Write-Line", probe)
        self.assertEqual(self.runner.count("Invoke-NpmReparseProbe $sandbox $project '"), 1)
        diag = re.compile(re.search(r"DiagLinePattern = '([^']+)'", self.runner).group(1))
        for line in (
            "windows-source-probe id=npm_reparse_before exit=0x00000000",
            "windows-source-probe-line kd-probe reparse open0=ok openra=ok openrc=ok follow=ok basic0=ok basicra=ok get0=ok getra=ok trust=0 cause=none",
            "windows-source-probe-line kd-probe reparse open0=ok openra=ok openrc=ok follow=ok basic0=ok basicra=ok get0=err5 getra=err5 trust=0 cause=fsctl_policy",
            "windows-source-probe-line kd-probe reparse open0=err5 openra=err5 openrc=err5 follow=ok basic0=na basicra=na get0=na getra=na trust=1 cause=open_policy",
        ):
            with self.subTest(line=line[:60]):
                self.assertIsNotNone(diag.fullmatch(line))

    def test_the_gate_plan_requires_exactly_the_windows_stepped_npm_gate(self):
        plan = self.function_body("Get-GatePlan")
        for token in (
            "@('-B', $gateScript, $GateTableEmitCommand, $selection, $GateTablePlatform)",
            "if ($name -cne $NpmSteppedGate -or $steps.Count -ne 2) { throw 'gate_plan' }",
            "$then = [string[]](Expand-GateArgv @($steps[1]) $cargo $node $npm $project)",
            "if ($name -ceq $NpmSteppedGate) { throw 'gate_plan' }",
            "Argv = [string[]](Expand-GateArgv $argv $cargo $node $npm $project); Then = $then",
            "if ($gates.Count -ne $expectedCount -or $stepped -ne 1) { throw 'gate_plan' }",
        ):
            with self.subTest(token=token[:60]):
                self.assertIn(token, plan)
        self.assertIn("\n$GateTablePlatform = 'windows'\n", self.runner)
        self.assertIn("\n$NpmSteppedGate = 'node_dependency_prepare'\n", self.runner)
        expand = self.function_body("Expand-GateArgv")
        for token in ("if ($items.Count -lt 2 -or $items.Count -gt 64) { throw 'gate_plan' }",
                      "if ($argument -cmatch '\\{[a-z_]*\\}') { throw 'gate_plan' }", "$argument.Replace('/', '\\')"):
            self.assertIn(token, expand)
        gates = self.function_body("Invoke-SourceGates")
        shim = (
            "        $argv = [string[]]$gate.Argv\n"
            "        $gateEnvironment = $environment\n"
            "        if ($NpmLinkShimGates -ccontains $gate.Id) {\n"
            "            $argv = [string[]](Add-NpmLinkShim $argv)\n"
            "            $gateEnvironment = [string[]](Get-NpmLinkShimEnvironment $environment)\n"
            "        }\n"
            "        $exe = [string]$argv[0]\n"
            "        $commandLine = ConvertTo-CommandLine $argv\n"
        )
        run = "        $run = $sandbox.Run($true, $exe, $commandLine, $project, $gateEnvironment, ($seconds * 1000), $GateMaxProcesses)\n"
        stepped = "        if ($null -ne $gate.Then) { $run = Invoke-NpmLinkSteps $sandbox $gate $project $environment $run }\n"
        self.assertIn(shim + run + stepped + "        $outcome.Count += 1\n", gates)
        self.assertNotIn("$gate.Argv[0]", gates)
        self.assertEqual(re.findall(r"^\$NpmLinkShimGates = (.*)$", self.runner, re.M), ["@('node_dependency_audit')"])

    def test_the_stepped_npm_gate_runs_trusted_links_between_two_confined_steps_and_rechecks_the_lock(self):
        steps = self.function_body("Invoke-NpmLinkSteps")
        order = (
            "if (-not (Test-GateBoundary $first) -or $first.TimedOut -or $first.ExitCode -ne 0) { return $first }",
            "[KeelDock.Platform.WindowsConfinement.JunctionMaker]::Create($project, [string]$link.Link, [string]$link.Target)",
            "if ([KeelDock.Platform.WindowsConfinement.JunctionMaker]::Verify($project, [string]$link.Link, [string]$link.Target)) { $verified += 1 }",
            "Write-Line ('windows-source-npm-links=created count=' + $created + ' verified=' + $verified)",
            "if ($verified -ne @($script:NpmLinks).Count) { throw 'npm_link' }",
            "    if ($created -gt 0) { Invoke-NpmReparseProbe $sandbox $project 'before' }\n",
            "    if ($created -gt 0) { Initialize-NpmLinkShim $project }\n",
            "    $shimEnvironment = [string[]](Get-NpmLinkShimEnvironment $environment)\n",
            "Invoke-NpmLinkProbe $sandbox $project",
            "Invoke-NpmLinkTargetProbe $sandbox $project ([string]@($gate.Then)[0]) $shimEnvironment",
            "if ($remaining -lt 60) { throw 'deadline' }",
            "    $then = [string[]](Add-NpmLinkShim ([string[]]$gate.Then))\n",
            "    $then = [string[]](@($then[0], '--max-old-space-size=6144') + @($then[1..($then.Count - 1)]))\n",
            "$second = $sandbox.Run($true, $then[0], (ConvertTo-CommandLine $then), $project, $shimEnvironment, ($seconds * 1000), $GateMaxProcesses)",
            "$merged.Stdout = [string]$first.Stdout + \"`n\" + [string]$second.Stdout",
            "$merged.Truncated = [bool]($first.Truncated -or $second.Truncated)",
            "if (-not (Test-GateBoundary $second) -or $second.TimedOut -or $second.ExitCode -ne 0) { return $merged }",
            "if (-not [KeelDock.Platform.WindowsConfinement.JunctionMaker]::Verify($project, [string]$link.Link, [string]$link.Target)) { throw 'npm_link' }",
            "if ((Get-NoFollowDigest (Join-Path $project 'package-lock.json')) -cne $script:NpmLockDigest) { throw 'npm_lock_changed' }",
            "\n    return $merged",
        )
        positions = [steps.index(item) for item in order]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(steps.count("Write-Line"), 2)
        self.assertEqual(self.runner.count("--max-old-space-size=6144"), 1)
        self.assertEqual(steps.count("--max-old-space-size=6144"), 1)
        reify = (
            "    try {\n        [void][KeelDock.Platform.WindowsConfinement.JunctionMaker]::ReadNoFollow((Join-Path $project 'node_modules\\.package-lock.json'), $MaxLockBytes)\n"
            "    } catch {\n        throw 'npm_reify_missing'\n    }\n    Write-Line 'windows-source-npm-reify=verified hidden_lock=present'\n    return $merged"
        )
        self.assertTrue(steps.endswith(reify))
        self.assertLess(steps.index("throw 'npm_lock_changed'"), steps.index("throw 'npm_reify_missing'"))
        self.assertEqual(steps.count("$sandbox.Run("), 1)
        for field in ("Failure", "Created", "TimedOut", "Exited", "ExitCode", "Token", "Job", "HandleCount", "CpuMs", "ElapsedMs"):
            self.assertIsNotNone(re.search(r"'" + field + r"'", steps), field)
        self.assertNotIn("'Stdout', ", steps)
        tarballs = self.function_body("Initialize-NpmTarballs")
        for token in (
            "if ($entry['link'] -isnot [bool]) { throw 'npm_link' }",
            "$links += @{ Key = [string]$key; Resolved = $entry['resolved'] }",
            "$script:NpmLinks = @(Get-NpmLinkPlan $lock['packages'] $links)",
            "$script:NpmLockDigest = Get-NoFollowDigest $lockPath",
        ):
            with self.subTest(token=token[:60]):
                self.assertIn(token, tarballs)
        self.assertLess(tarballs.index("WriteAllText($lockPath"), tarballs.index("$script:NpmLockDigest = Get-NoFollowDigest $lockPath"))
        self.assertIn("[KeelDock.Platform.WindowsConfinement.JunctionMaker]::ReadNoFollow($path, $MaxLockBytes)", self.function_body("Get-NoFollowDigest"))
        probe = self.function_body("Invoke-NpmLinkProbe")
        self.assertTrue(probe.split("\n", 1)[1].startswith("    if ($script:RunMode -cne 'synthetic') { return }\n"))
        self.assertIn("$link = Join-Path $project 'node_modules\\kd-probe-link'", probe)
        self.assertNotIn("Write-Line", probe)
        self.assertEqual(self.runner.count("Remove-WithinRoots $baseDirectory"), 1)

    def link_plan_model(self):
        plan = self.function_body("Get-NpmLinkPlan")
        key_pattern = re.search(r"if \(\$key -cnotmatch '([^']+)'", plan).group(1)
        path_pattern = re.search(r"\$path -cnotmatch '([^']+)'", self.function_body("Test-NpmLinkPath")).group(1)
        reserved = re.search(r"^\$ReservedNames = '([^']+)'$", self.runner, re.M).group(1)
        self.assertIn("if ($items.Count -gt $MaxNpmLinks) { throw 'npm_link' }", plan)
        self.assertIn("\n$MaxNpmLinks = 64\n", self.runner)
        self.assertIn("if (@($resolved.Split('/')) -icontains 'node_modules') { throw 'npm_link' }", plan)
        self.assertIn("$packages[$resolved].ContainsKey('link')", plan)
        self.assertIn("(Test-NpmLinkPath $key 3)", plan)
        self.assertIn("(Test-NpmLinkPath $resolved 8)", plan)

        def path_ok(path, maximum):
            if len(path) < 1 or len(path) > 200 or re.search(path_pattern, path) is None:
                return False
            parts = path.split("/")
            if len(parts) > maximum:
                return False
            for part in parts:
                if not part or len(part) > 100 or part.startswith(".") or part.endswith("."):
                    return False
                if re.search(reserved, part, re.I):
                    return False
            return True

        def accepted(key, resolved, packages):
            if re.search(key_pattern, key) is None or not path_ok(key, 3):
                return False
            if type(resolved) is not str or not path_ok(resolved, 8):
                return False
            if "node_modules" in [part.lower() for part in resolved.split("/")]:
                return False
            return resolved in packages and "link" not in packages[resolved]

        return accepted

    def test_link_validation_accepts_only_lockfile_workspace_links_inside_the_project(self):
        accepted = self.link_plan_model()
        packages = {
            "packages/kernel-i18n": {"name": "fixture-kernel-i18n"},
            "packages/linked": {"link": True},
            "node_modules/y": {"version": "1.0.0"},
        }
        for key, resolved in (
            ("node_modules/fixture-kernel-i18n", "packages/kernel-i18n"),
            ("node_modules/@synthetic/kernel-i18n", "packages/kernel-i18n"),
        ):
            with self.subTest(key=key):
                self.assertTrue(accepted(key, resolved, packages))
        for key, resolved in (
            ("node_modules/x", "../outside"),
            ("node_modules/x", "packages/../kernel-i18n"),
            ("node_modules/x", "./packages/kernel-i18n"),
            ("node_modules/x", "C:/x"),
            ("node_modules/x", "/packages/kernel-i18n"),
            ("node_modules/x", "packages\\kernel-i18n"),
            ("node_modules/x", "packages/kernel-i18n/"),
            ("node_modules/x", "packages/missing"),
            ("node_modules/x", "packages/linked"),
            ("node_modules/x", "node_modules/y"),
            ("node_modules/x", 5),
            ("node_modules/x", None),
            ("packages/a/node_modules/x", "packages/kernel-i18n"),
            ("node_modules/../x", "packages/kernel-i18n"),
            ("node_modules/X", "packages/kernel-i18n"),
            ("node_modules/con", "packages/kernel-i18n"),
            ("node_modules/x.", "packages/kernel-i18n"),
            ("node_modules/x y", "packages/kernel-i18n"),
            ("node_modules", "packages/kernel-i18n"),
            ("node_modules/@scope", "packages/kernel-i18n"),
            ("node_modules/a/b/c", "packages/kernel-i18n"),
            ("/node_modules/x", "packages/kernel-i18n"),
        ):
            with self.subTest(key=key, resolved=resolved):
                self.assertFalse(accepted(key, resolved, packages))

    def test_the_node_realpath_probe_is_one_unquoted_argument_that_prints_only_a_fixed_token(self):
        script = re.search(r'^\$NodeRealpathScript = "([^"]+)"$', self.runner, re.M).group(1)
        self.assertIsNone(re.search(r"[\s\"$`]", script))
        self.assertIn("realpathSync.native('.')", script)
        self.assertIn("promises.realpath('.')", script)
        self.assertEqual(re.findall(r"process\.stdout\.write\('([a-z=]+)'", script), ["realpath=ok", "realpath="])
        self.assertIn("process.stdout.write('realpath='+e.code)", script)
        body = self.function_body("Get-SourceProbes")
        self.assertIn("$node = Join-Path ([string]$script:Layout.NodeDir) 'node.exe'\n", body)
        self.assertTrue(body.rstrip().endswith(
            "@{ Id = 'node_realpath'; Needs = $node; Extra = $none; Argv = [string[]]@($node, '-e', $NodeRealpathScript) }\n    )"))

    def test_source_mode_runs_the_same_gates_with_only_the_designed_lease_default(self):
        self.assertEqual(self.runner.count("$runMode -cne 'synthetic'"), 2)
        self.assertEqual(self.runner.count("$MountManagerSourceRungs"), 2)
        for name in ("Invoke-NpmLinkSteps", "Get-GatePlan", "Expand-GateArgv", "Get-NpmLinkPlan", "Initialize-NpmTarballs",
                     "Initialize-NpmLinkShim", "Add-NpmLinkShim", "Get-NpmLinkShimEnvironment"):
            with self.subTest(function=name):
                self.assertNotIn("RunMode", self.function_body(name))
                self.assertNotIn("$runMode", self.function_body(name))

    def test_the_detail_line_is_built_only_from_fixed_tokens_with_bucketed_counts_and_no_passed_count(self):
        body = self.function_body("Get-GateDetail")
        self.assertTrue(body.startswith("([int]$index, $gate, [string]$combined, $peak) {\n"))
        self.assertIn("$peakText = [string]$peak\n        if ($peakText -cmatch '^[0-9]{1,19}$') {\n            $peakBytes = [uint64]$peakText\n", body)
        for bucket in ("lt1g", "1to2g", "2to4g", "4to8g", "ge8g"):
            self.assertIn("$mem = '" + bucket + "'", body)
        self.assertEqual(body.count("$mem = 'unknown'"), 2)
        for limit in ("1073741824", "2147483648", "4294967296", "8589934592"):
            self.assertIn("$peakBytes -lt " + limit + ")", body)
        for token in (
            "$items = @($gate.Argv | ForEach-Object { [string]$_ })",
            "'(^|[\\\\/])cargo\\.exe$'", "'(^|[\\\\/])npm-cli\\.js$'",
            "'error\\[(E[0-9]{4})\\]'", "'LNK[0-9]{4}'",
            "'test result: FAILED\\. ([0-9]+) passed; ([0-9]+) failed'",
            "'os error ([0-9]{1,5})'", "'panicked at'",
            "'npm (?:error|ERR!) code ([A-Z0-9_]{2,32})'",
            "$kind = 'compile'", "$kind = 'link'", "$kind = 'test'", "$kind = 'os_error'", "$kind = 'npm'",
            "$code = 'os' + [int]$osError.Groups[1].Value",
            "if ([regex]::IsMatch($text, 'panicked at')) { $code = 'panics' }",
            "$code = 'other'", "$GateDetailNpmCodes -ccontains",
            "if ($failedText.Length -gt 6) { $failedText = '999999' }",
            "if ($failedCount -ge 10) { $failedBucket = 'many' } elseif ($failedCount -ge 2) { $failedBucket = 'few' } else { $failedBucket = [string]$failedCount }",
        ):
            self.assertIn(token, body)
        self.assertNotIn("$argv", body)
        self.assertNotIn("passed=", body)
        self.assertNotIn("passedCount", body)
        self.assertNotIn("passedSum", body)
        self.assertNotIn("$code = 'panics' +", body)
        self.assertLess(body.index("$kind = 'compile'"), body.index("$kind = 'link'"))
        self.assertLess(body.index("$kind = 'link'"), body.index("$kind = 'test'"))
        self.assertLess(body.index("$kind = 'test'"), body.index("$kind = 'os_error'"))
        self.assertIn("    } catch {\n        $kind = 'unknown'\n        $code = 'none'\n        $failedBucket = '0'\n        $mem = 'unknown'\n    }\n", body)
        self.assertIn(
            "    return ('windows-source-gate-detail=' + $index + ' id=' + $gate.Id + ' tool=' + $tool + ' kind=' + $kind"
            " + ' failed=' + $failedBucket + ' code=' + $code + ' mem=' + $mem)", body)
        self.assertEqual(body.count("return "), 1)
        self.assertNotIn("Write-Line", body)
        self.assertNotIn("throw", body)
        listed = re.findall(r"^\$GateDetailNpmCodes = @\((.*)\)$", self.runner, re.M)
        self.assertEqual(len(listed), 1)
        npm_codes = re.findall(r"'([A-Z0-9_]+)'", listed[0])
        self.assertEqual(npm_codes, [
            "ENOTCACHED", "EBADPLATFORM", "ENOENT", "EPERM", "EACCES", "EBUSY", "ENOTEMPTY", "EEXIST", "ELOOP", "ENAMETOOLONG",
            "EINTEGRITY", "EUSAGE", "ELIFECYCLE", "ERESOLVE", "EJSONPARSE", "ENOLOCK", "ENOTSUP", "EINVAL", "EMFILE", "ENOSPC",
            "ECONNREFUSED", "ENOTFOUND", "EAI_AGAIN", "ETARGET", "E404", "EOVERRIDE", "EWORKSPACEMISSING", "ENOWORKSPACES",
            "EINVALIDTAGNAME", "EINVALIDPACKAGENAME", "EUNKNOWNTYPE"])
        public = re.compile(re.search(r"PublicLinePattern = '([^']+)'", self.runner).group(1))
        shim_reasons = re.findall(r"'([a-z_]+)'", re.findall(r"^\$GateDetailShimReasons = @\((.*)\)$", self.runner, re.M)[0])
        node_codes = re.findall(r"'ERR_([A-Z_]+)'", re.findall(r"^\$GateDetailNodeCodes = @\((.*)\)$", self.runner, re.M)[0])
        npm_tokens = ("module_not_found", "null_property", "not_function", "not_iterable", "stack_overflow", "heap",
                      "exit_handler", "invalid_version", "typeerror", "rangeerror", "syntaxerror", "referenceerror", "npm_error_line")
        shaped = re.compile(
            r"windows-source-gate-detail=[1-9][0-9]* id=[a-z][a-z_]{2,40} tool=(cargo|npm|other)"
            r" kind=(compile|link|test|os_error|npm|unknown) failed=(0|1|few|many)"
            r" code=(" + "|".join(npm_codes) + r"|other|none|panics|E[0-9]{4}|LNK[0-9]{4}|os[0-9]{1,5}"
            r"|shim_(" + "|".join(shim_reasons) + r"|other)|node_(ERR_(" + "|".join(node_codes) + r")|other)"
            r"|" + "|".join(npm_tokens) + r") mem=(lt1g|1to2g|2to4g|4to8g|ge8g|unknown)")
        for line in (
            "windows-source-gate-detail=3 id=workspace_tests tool=cargo kind=test failed=few code=panics mem=lt1g",
            "windows-source-gate-detail=3 id=workspace_tests tool=cargo kind=test failed=1 code=none mem=lt1g",
            "windows-source-gate-detail=12 id=node_dependency_prepare tool=npm kind=npm failed=0 code=ENOTCACHED mem=lt1g",
            "windows-source-gate-detail=1 id=format tool=other kind=unknown failed=0 code=none mem=lt1g",
            "windows-source-gate-detail=3 id=workspace_tests tool=cargo kind=compile failed=0 code=E0432 mem=lt1g",
            "windows-source-gate-detail=3 id=workspace_tests tool=cargo kind=link failed=0 code=LNK1181 mem=lt1g",
            "windows-source-gate-detail=3 id=workspace_tests tool=cargo kind=os_error failed=0 code=os32 mem=lt1g",
            "windows-source-gate-detail=3 id=workspace_tests tool=cargo kind=test failed=many code=panics mem=lt1g",
            "windows-source-gate-detail=12 id=node_dependency_prepare tool=npm kind=npm failed=0 code=shim_map_entry mem=lt1g",
            "windows-source-gate-detail=12 id=node_dependency_prepare tool=npm kind=npm failed=0 code=shim_other mem=unknown",
            "windows-source-gate-detail=12 id=node_dependency_prepare tool=npm kind=npm failed=0 code=node_ERR_REQUIRE_ESM mem=1to2g",
            "windows-source-gate-detail=12 id=node_dependency_prepare tool=npm kind=npm failed=0 code=node_other mem=2to4g",
            "windows-source-gate-detail=12 id=node_dependency_prepare tool=npm kind=npm failed=0 code=null_property mem=4to8g",
            "windows-source-gate-detail=12 id=node_dependency_prepare tool=npm kind=npm failed=0 code=npm_error_line mem=ge8g",
        ):
            with self.subTest(line=line):
                self.assertRegex(line, public)
                self.assertIsNotNone(shaped.fullmatch(line))
                self.assertLess(len(line), 480)
        for line in (
            "windows-source-gate-detail=3 id=workspace_tests tool=cargo kind=test failed=2 code=none mem=lt1g",
            "windows-source-gate-detail=3 id=workspace_tests tool=cargo kind=test failed=few passed=4 code=none mem=lt1g",
            "windows-source-gate-detail=3 id=workspace_tests tool=cargo kind=test failed=few code=panics3 mem=lt1g",
            "windows-source-gate-detail=3 id=workspace_tests tool=cargo kind=npm failed=0 code=EWHATEVER mem=lt1g",
            "windows-source-gate-detail=12 id=node_dependency_prepare tool=npm kind=npm failed=0 code=shim_xyz mem=lt1g",
            "windows-source-gate-detail=12 id=node_dependency_prepare tool=npm kind=npm failed=0 code=node_ERR_FOO mem=lt1g",
            "windows-source-gate-detail=12 id=node_dependency_prepare tool=npm kind=npm failed=0 code=node_ERR_other mem=lt1g",
            "windows-source-gate-detail=12 id=node_dependency_prepare tool=npm kind=npm failed=0 code=null_properties mem=lt1g",
            "windows-source-gate-detail=12 id=node_dependency_prepare tool=npm kind=npm failed=0 code=heap mem=huge",
            "windows-source-gate-detail=12 id=node_dependency_prepare tool=npm kind=npm failed=0 code=heap",
            "windows-source-gate-detail=12 id=node_dependency_prepare tool=npm kind=npm failed=0 code=heap mem=lt1g extra=1",
        ):
            with self.subTest(rejected=line):
                self.assertIsNone(shaped.fullmatch(line))

    def test_the_gate_runs_use_the_raised_process_limit_and_the_probes_keep_thirty_two(self):
        self.assertEqual(re.findall(r"^\$GateMaxProcesses = (.*)$", self.runner, re.M), ["[uint32]128"])
        self.assertEqual(self.runner.count("$GateMaxProcesses"), 3)
        self.assertIn("$gateEnvironment, ($seconds * 1000), $GateMaxProcesses)", self.function_body("Invoke-SourceGates"))
        self.assertIn("$shimEnvironment, ($seconds * 1000), $GateMaxProcesses)", self.function_body("Invoke-NpmLinkSteps"))
        self.assertEqual(self.runner.count("[uint32]32)"), 5)
        self.assertNotIn("[uint32]32", self.function_body("Invoke-SourceGates"))
        self.assertNotIn("[uint32]32", self.function_body("Invoke-NpmLinkSteps"))

    def test_an_npm_failure_without_an_error_code_is_classified_by_the_first_matching_fixed_rule(self):
        body = self.function_body("Get-GateDetail")
        shim = re.findall(r"^\$GateDetailShimReasons = @\((.*)\)$", self.runner, re.M)
        node = re.findall(r"^\$GateDetailNodeCodes = @\((.*)\)$", self.runner, re.M)
        self.assertEqual(len(shim), 1)
        self.assertEqual(len(node), 1)
        self.assertEqual(re.findall(r"'([a-z_]+)'", shim[0]), [
            "fs_shape", "map_count", "map_entry", "map_hash", "map_json", "map_path", "map_shape", "map_size", "map_text"])
        self.assertEqual(re.findall(r"'([A-Z_]+)'", node[0]), [
            "ERR_INVALID_ARG_TYPE", "ERR_INVALID_ARG_VALUE", "ERR_MODULE_NOT_FOUND", "ERR_REQUIRE_ESM", "ERR_INVALID_URL",
            "ERR_INVALID_FILE_URL_PATH", "ERR_UNSUPPORTED_ESM_URL_SCHEME", "ERR_OUT_OF_RANGE", "ERR_FS_EISDIR", "ERR_INVALID_STATE",
            "ERR_ACCESS_DENIED", "ERR_UNKNOWN_FILE_EXTENSION", "ERR_STREAM_PREMATURE_CLOSE", "ERR_INVALID_PACKAGE_CONFIG",
            "ERR_PACKAGE_PATH_NOT_EXPORTED"])
        order = (
            "'npm_link_shim refused ([a-z_]{2,20})'",
            "'\\b(ERR_[A-Z_]{3,48})\\b'",
            "$code = 'shim_other'",
            "$GateDetailShimReasons -ccontains",
            "$code = 'shim_' + [string]$shim.Groups[1].Value",
            "$code = 'node_other'",
            "$GateDetailNodeCodes -ccontains",
            "$code = 'node_' + [string]$nodeError.Groups[1].Value",
            "'MODULE_NOT_FOUND|Cannot find module')) { $code = 'module_not_found'",
            "'Cannot read properties of (?:null|undefined)')) { $code = 'null_property'",
            "'is not a function')) { $code = 'not_function'",
            "'is not iterable')) { $code = 'not_iterable'",
            "'Maximum call stack size exceeded')) { $code = 'stack_overflow'",
            "'JavaScript heap out of memory|FATAL ERROR')) { $code = 'heap'",
            "'Exit handler never called')) { $code = 'exit_handler'",
            "'Invalid Version')) { $code = 'invalid_version'",
            "'TypeError')) { $code = 'typeerror'",
            "'RangeError')) { $code = 'rangeerror'",
            "'SyntaxError')) { $code = 'syntaxerror'",
            "'ReferenceError')) { $code = 'referenceerror'",
            "'(?m)^npm (?:error|ERR!)')) { $code = 'npm_error_line'",
        )
        positions = [body.index(item) for item in order]
        self.assertEqual(positions[2:], sorted(positions[2:]))
        self.assertLess(positions[0], positions[2])
        self.assertLess(positions[1], positions[2])
        self.assertLess(body.index("$code = 'other'"), positions[0])
        self.assertLess(body.index("} else {\n                $shim = "), positions[0])
        self.assertEqual(body.count("$code = 'none'"), 2)
        self.assertNotIn("$code = $text", body)
        self.assertNotIn("Value + '_'", body)
        self.assertEqual(self.runner.count("$GateDetailShimReasons -ccontains"), 1)
        self.assertEqual(self.runner.count("$GateDetailNodeCodes -ccontains"), 1)

    def test_the_detail_line_is_emitted_once_only_for_the_first_ordinary_failure_after_the_canary_and_boundary_checks(self):
        body = self.function_body("Invoke-SourceGates")
        emit = "                Write-Line (Get-GateDetail $index $gate $combined $run.PeakProcessMemory)\n"
        self.assertEqual(self.runner.count("Get-GateDetail $index $gate $combined $run.PeakProcessMemory"), 1)
        self.assertEqual(body.count(emit), 1)
        self.assertEqual(self.runner.count("windows-source-gate-detail="), 1)
        self.assertEqual(body.count("windows-source-gate-detail"), 0)
        canary = body.index("if ($run.Truncated -or (Test-LogCanary $combined)) {")
        boundary = body.index("if (-not $boundary) {\n            $outcome.Boundary = 'failed'")
        ordinary = body.index("        if (-not $passed) {\n            if ($outcome.Failure -eq 0) {\n                $outcome.Failure = $index\n                $script:RefusalReason = 'gate'\n" + emit)
        self.assertLess(canary, boundary)
        self.assertLess(boundary, ordinary)
        self.assertLess(ordinary, body.index(emit))
        self.assertNotIn("Get-GateDetail", body[:ordinary])
        self.assertNotIn("Get-GateDetail", body[body.index(emit) + len(emit):])
        self.assertIn(emit + "            }\n            $outcome.Failed += 1\n", body)
        deadline = body.split("if ($remaining -lt 60) {", 1)[1].split("\n        }\n", 1)[0]
        self.assertNotIn("Get-GateDetail", deadline)

    def test_source_mode_continues_after_an_ordinary_failure_but_still_stops_at_canary_truncation_boundary_deadline_and_timeout(self):
        body = self.function_body("Invoke-SourceGates")
        ordinary = body.split("        if (-not $passed) {\n            if ($outcome.Failure -eq 0) {\n                $outcome.Failure = $index\n                $script:RefusalReason = 'gate'\n", 1)[1]
        self.assertEqual(ordinary, "                Write-Line (Get-GateDetail $index $gate $combined $run.PeakProcessMemory)\n            }\n            $outcome.Failed += 1\n            if ($run.TimedOut -and -not $keepGoing) { return $outcome }\n        }\n    }\n    return $outcome")
        boundary = body.split("        if (-not $boundary) {\n", 1)[1].split("\n        }\n", 1)[0]
        self.assertIn("if (-not ($keepGoing -and -not $run.Created)) { return $outcome }", boundary)
        self.assertLess(body.index("if (-not $boundary) {"), body.index("if ($run.TimedOut -and -not $keepGoing)"))
        self.assertLess(body.index("if ($run.Truncated -or (Test-LogCanary $combined)) {"), body.index("if (-not $boundary) {"))
        canary = body.split("if ($run.Truncated -or (Test-LogCanary $combined)) {", 1)[1].split("\n        }\n", 1)[0]
        self.assertTrue(canary.rstrip().endswith("return $outcome"))
        self.assertNotIn("$run.TimedOut", canary)
        deadline = body.split("if ($remaining -lt 60) {", 1)[1].split("\n        }\n", 1)[0]
        self.assertTrue(deadline.rstrip().endswith("return $outcome"))
        self.assertEqual(body.count("return $outcome"), 5)
        self.assertIn("$passed = ($boundary -and -not $run.TimedOut -and $run.ExitCode -eq 0)", body)
        self.assertEqual(self.runner.count("if ($gateOutcome.Failed -ne 0 -or $gateOutcome.Failure -ne 0) { throw $script:RefusalReason }\n"), 1)

    def test_after_a_source_mode_failure_the_npm_stepped_shim_and_dependent_node_gates_are_skipped_not_run(self):
        body = self.function_body("Invoke-SourceGates")
        skip = (
            "        if (-not $keepGoing -and $outcome.Failure -ne 0 -and (($gate.Id -ceq $NpmSteppedGate) -or ($NpmLinkShimGates -ccontains $gate.Id) -or ($nodeBlocked -and (Test-NodeGate $gate)))) {\n"
            "            if ($gate.Id -ceq $NpmSteppedGate) { $nodeBlocked = $true }\n"
            "            $outcome.Count += 1\n"
            "            $outcome.Failed += 1\n"
            "            Write-Line ('windows-source-gate=' + $index + ' id=' + $gate.Id + ' result=not_run hang=none cause=skipped')\n"
            "            continue\n"
            "        }\n")
        self.assertEqual(body.count(skip), 1)
        self.assertEqual(body.count("cause=skipped"), 1)
        start = body.index(skip)
        self.assertLess(start, body.index("Reset-NpmConfigFiles"))
        self.assertLess(start, body.index("Add-NpmLinkShim"))
        self.assertLess(start, body.index("Invoke-NpmLinkSteps"))
        self.assertLess(start, body.index("$sandbox.Run("))
        self.assertLess(start, body.index("if ($remaining -lt 60) {"))
        self.assertNotIn("Failure", skip.replace("$outcome.Failure -ne 0", ""))
        self.assertNotIn("RefusalReason", skip)
        self.assertNotIn("GateCause", skip)
        self.assertIn("        if ($gate.Id -ceq $NpmSteppedGate -and -not $passed) { $nodeBlocked = $true }\n", body)
        self.assertEqual(body.count("$nodeBlocked = $true"), 2)
        self.assertEqual(body.count("$nodeBlocked = $false"), 1)
        node = self.function_body("Test-NodeGate")
        self.assertIn("'(^|[\\\\/])(node\\.exe|npm-cli\\.js)$'", node)
        self.assertIn("$gate.Argv", node)
        public = re.compile(re.search(r"PublicLinePattern = '([^']+)'", self.runner).group(1))
        self.assertRegex("windows-source-gate=14 id=node_dependency_audit result=not_run hang=none cause=skipped", public)
        self.assertIn("if ($gateOutcome.Failed -ne 0 -or $gateOutcome.Failure -ne 0) { throw $script:RefusalReason }\n", self.runner)


if __name__ == "__main__":
    unittest.main()
