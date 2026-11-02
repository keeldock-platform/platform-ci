import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "kit/bootstrap"))

from public_tree import ACTION_VERSION_COMMENT_PATTERN, MAX_FILE_BYTES, inspect_text

RUNNER = ROOT / "kit/confinement/windows_source_run.ps1"
FRAME = ROOT / "kit/confinement/capsule_frame.ps1"
LIBRARY = ROOT / "kit/confinement/windows_confinement.ps1"
WORKFLOW = ROOT / ".github/workflows/lane-h-windows-receiver.yml"


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
        for path in (RUNNER, FRAME, WORKFLOW, Path(__file__)):
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
        gate_line = re.search(r"Write-Line \('windows-source-gate=' \+ \$index \+ ' id=' \+ \$gate.Id \+ ' result=' \+ \$result \+ ' hang=' \+ \$hang \+ \$causeText\)", self.runner)
        self.assertIsNotNone(gate_line)

    def test_gates_run_confined_with_a_boundary_proof_and_the_hang_guard(self):
        self.assertIn("$sandbox.Run($true, $exe, $commandLine, $project, $environment", self.runner)
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
        self.assertIn("if ($run.Truncated -or (Test-LogCanary $combined)) {", self.runner)
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
        self.assertIn("$causeText = ' cause=' + $script:GateCause", self.runner)
        self.assertIn("if (-not $passed) {", self.runner)
        self.assertIn("@('timeout', 'limit', 'signal', 'exit', 'launch') -ccontains $script:GateCause", self.runner)
        self.assertIn("$gateText += ' cause=' + $script:GateCause", self.runner)
        self.assertNotRegex(self.runner, r"' cause=' \+ \[string\]\$run\.ExitCode")

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
        for token in ("$nullRestore -ne 'verified'", "$keyCleanup -ne 'destroyed'", "$tempState -ne 'removed'", "$processState -ne 'none'"):
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


if __name__ == "__main__":
    unittest.main()
