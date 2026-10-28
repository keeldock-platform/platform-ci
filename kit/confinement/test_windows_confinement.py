import fnmatch
import re
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "kit/bootstrap"))

from public_tree import MAX_FILE_BYTES, inspect_text

NATIVE = ROOT / "kit/confinement/windows_confinement.cs"
WRAPPER = ROOT / "kit/confinement/windows_confinement.ps1"
WORKFLOW = ROOT / ".github/workflows/windows-confinement.yml"
CONFINED_STAGES = (
    "cmd_exec",
    "acl_ro_read",
    "acl_scratch_write",
    "acl_ro_write_denied",
    "acl_downloads_denied",
    "acl_downloads_listable",
    "rustc_version",
    "cargo_version",
    "link_banner",
    "rust_build",
    "rust_test",
    "node_version",
    "node_bindings",
)


class WindowsConfinementSpikeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NATIVE.read_text(encoding="utf-8")
        cls.wrapper = WRAPPER.read_text(encoding="utf-8")

    def test_files_pass_the_public_tree_rules(self):
        for path in (NATIVE, WRAPPER, WORKFLOW):
            with self.subTest(path=path.name):
                payload = path.read_bytes()
                self.assertLessEqual(len(payload), MAX_FILE_BYTES)
                inspect_text(payload.decode("utf-8"), "platform")
                self.assertNotIn(chr(35).encode("ascii"), payload)

    def test_native_module_builds_a_low_privilege_job_bound_child(self):
        for required in (
            "CreateAppContainerProfile",
            "DeleteAppContainerProfile",
            "ProcThreadAttributeSecurityCapabilities",
            "ProcThreadAttributeAllApplicationPackagesPolicy",
            "ProcThreadAttributeHandleList",
            "ProcessCreationAllApplicationPackagesOptOut",
            "capabilities.CapabilityCount = 0",
            "CreateSuspended",
            "JobObjectLimitKillOnJobClose",
            "JobObjectLimitActiveProcess",
            "JobObjectLimitProcessMemory",
            "LowIntegrityRid",
            "TokenIsLessPrivilegedAppContainer",
            "StartfUseStdHandles",
            "SetHandleInformation(read, HandleFlagInherit, 0)",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.native)
        flags = re.search(r"private const uint JobLimitFlags = ([^;]+);", self.native)
        self.assertIsNotNone(flags)
        self.assertNotIn("Breakaway", flags.group(1))
        self.assertIn("breakaway=disabled", self.native)
        self.assertIn("JobObjectLimitBreakawayOk | JobObjectLimitSilentBreakawayOk", self.native)
        for forbidden in ("Process.Start", "ProcessStartInfo", "CREATE_BREAKAWAY", "CreateBreakaway"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.native)

    def test_native_module_assigns_the_job_and_checks_the_token_before_resuming(self):
        order = (
            "CreateProcessW(executable",
            "AssignProcessToJobObject(job, process)",
            "ReadJob(job, process, maxProcesses)",
            "ReadToken(process, confined, profileSid)",
            "ResumeThread(thread)",
            "WaitForSingleObject(process, (uint)timeoutMs)",
        )
        positions = [self.native.index(item) for item in order]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("Native.TerminateJobObject(job, JobKillExitCode)", self.native)
        self.assertEqual(self.native.count("handleBuffer = Marshal.AllocHGlobal(IntPtr.Size * 2)"), 1)

    def test_wrapper_pins_exact_toolchains_by_hash_and_allows_only_known_hosts(self):
        self.assertIn("$RustVersion = '1.99.1'", self.wrapper)
        self.assertIn("$RustTarget = 'x86_64-pc-windows-msvc'", self.wrapper)
        self.assertIn("$NodeVersion = '24.22.1'", self.wrapper)
        digests = re.findall(r"Sha256 = '([0-9a-f]{64})'", self.wrapper)
        self.assertEqual(len(digests), 4)
        self.assertEqual(len(set(digests)), 4)
        integrity = re.findall(r"Sri = '(sha512-[A-Za-z0-9+/]{86}==)'", self.wrapper)
        self.assertEqual(len(integrity), 2)
        self.assertIn(
            "$AllowedHosts = @('static.rust-lang.org', 'nodejs.org', 'registry.npmjs.org')",
            self.wrapper,
        )
        urls = re.findall(r"https://[A-Za-z0-9.-]+/", self.wrapper)
        self.assertTrue(urls)
        for url in urls:
            with self.subTest(url=url):
                self.assertIn(url, (
                    "https://static.rust-lang.org/",
                    "https://nodejs.org/",
                    "https://registry.npmjs.org/",
                    "https://github.com/",
                ))
        self.assertIn("$AllowedHosts -notcontains $uri.Host", self.wrapper)
        self.assertIn("hash_mismatch", self.wrapper)

    def function_body(self, name):
        match = re.search(r"^function " + re.escape(name) + r"\b.*?^\}$", self.wrapper, re.S | re.M)
        self.assertIsNotNone(match, name)
        return match.group(0)

    def test_wrapper_runs_the_control_first_then_the_confined_ladder(self):
        names = re.findall(r"Name = '([a-z_]+)'; Exe", self.wrapper)
        self.assertEqual(tuple(names), CONFINED_STAGES)
        control = "$controlOutcomes = Invoke-Ladder $box $false $script:Control"
        confined = "$confinedOutcomes = Invoke-Ladder $box $true $script:Lpac"
        self.assertIn(control, self.wrapper)
        self.assertIn(confined, self.wrapper)
        self.assertLess(self.wrapper.index(control), self.wrapper.index(confined))

    def test_function_output_goes_to_the_console_not_the_return_value(self):
        self.assertNotIn("Write-Output", self.wrapper)
        self.assertNotIn("Write-Host", self.wrapper)
        self.assertIn("[Console]::Out.WriteLine($text)", self.function_body("Write-Line"))
        for name in re.findall(r"^function ([A-Za-z-]+)", self.wrapper, re.M):
            body = self.function_body(name)
            with self.subTest(function=name):
                self.assertNotIn("Write-Output", body)
                for line in body.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("& "):
                        self.assertIn("Out-Null", stripped)
        ladder = self.function_body("Invoke-Ladder")
        self.assertIn("Write-Line ('windows-confinement-stage='", ladder)
        self.assertIn("Write-Line ('kd-diag stage='", ladder)
        self.assertTrue(ladder.rstrip().endswith("return $outcomes\n}"))
        self.assertEqual(ladder.count("return "), 1)
        self.assertIn("Write-Line ('kd-diag stage='", self.function_body("Write-DiagLines"))
        self.assertIn("$sandbox.Run(", ladder)
        self.assertIn("$result = $sandbox.Run(", ladder)

    def clean(self, text):
        pattern = re.search(r"\[regex\]::Replace\(\$value, '(\[\^[^']+)', '\?'\)", self.wrapper)
        self.assertIsNotNone(pattern)
        self.assertIn('$value.Replace("`r", \'\')', self.function_body("Get-CleanText"))
        return re.sub(pattern.group(1), "?", text.replace("\r", ""))

    def test_diagnostic_text_cannot_inject_runner_commands(self):
        hostile = (
            "ok\r::add-mask::value",
            "::error::boom",
            "line\n::set-output name=x::y",
            chr(35) * 2 + "[group]x",
            "a%0Ab%0D",
            "\r\n::warning::x",
            "x ::stop-commands::token",
            "path D:\\a\\_temp\\x: failed [1]",
        )
        for text in hostile:
            with self.subTest(text=text):
                cleaned = self.clean(text)
                for forbidden in (chr(13), chr(35), "[", "]", "%", ":", "<", ">", "\\"):
                    self.assertNotIn(forbidden, cleaned)
                for line in cleaned.split("\n"):
                    self.assertFalse(line.lstrip().startswith("::"))
        self.assertEqual(self.clean("ok\r::x"), "ok??x")
        self.assertEqual(self.clean("v1.2-3_a=b/c, d"), "v1.2-3_a=b/c, d")
        diag = self.function_body("Write-DiagLines")
        self.assertIn("' line=' + $trimmed", diag)
        self.assertIn("Write-Line ('kd-diag stage='", diag)

    def token_accepted(self, text):
        patterns = re.findall(r"\$tokenText -like '([^']+)'", self.function_body("Invoke-Ladder"))
        self.assertEqual(len(patterns), 4)
        return all(fnmatch.fnmatchcase(text, pattern) for pattern in patterns)

    def test_container_proof_requires_every_token_fact_explicitly(self):
        good = "appcontainer=1,capabilities=0,integrity=0x1000,lpac=1,sid=match,aap=absent"
        self.assertTrue(self.token_accepted(good))
        for bad in (
            good.replace("lpac=1", "lpac=unreadable"),
            good.replace("lpac=1", "lpac=0"),
            good.replace("sid=match", "sid=mismatch"),
            good.replace("aap=absent", "aap=present"),
            good.replace("appcontainer=1", "appcontainer=0"),
            "appcontainer=0,integrity=0x3000",
            "none",
            "unknown",
        ):
            with self.subTest(token=bad):
                self.assertFalse(self.token_accepted(bad))
        for required in (
            'lpac != "1"',
            'sidState != "match"',
            'applicationPackages != "absent"',
            "TokenAppContainerSid",
            "TokenGroups",
            'AllApplicationPackagesSid = "S-1-15-2-1"',
            "Native.EqualSid(actual, expectedSid)",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.native)
        self.assertNotIn("lpac=unknown", self.native)
        self.assertNotIn('"unknown"', self.native)
        self.assertIn("$lpacProven", self.function_body("Invoke-Ladder"))
        self.assertIn("-not $confinedOutcomes[$key].Token", self.wrapper)

    def test_control_never_runs_over_container_writable_paths(self):
        self.assertIn("$script:Control = New-ScratchSet (Join-Path $baseDirectory 'control')", self.wrapper)
        self.assertIn("$script:Lpac = New-ScratchSet (Join-Path $baseDirectory 'scratch')", self.wrapper)
        self.assertNotIn("Grant-Access $script:Control", self.wrapper)
        self.assertNotIn("$layout.Scratch", self.wrapper)
        self.assertIn("$script:Control.Root, $script:Control.Tmp, $script:Control.Crate", self.function_body("Test-Acl"))
        self.assertIn("'unexpected_rule'", self.function_body("Test-Acl"))
        ladder = self.function_body("Invoke-Ladder")
        self.assertNotIn("$script:Lpac", ladder)
        self.assertNotIn("$script:Control", ladder)
        self.assertIn("$scratch.Root", ladder)
        environment = self.function_body("New-StageEnvironment")
        for name in ("TEMP", "TMP", "CARGO_HOME", "USERPROFILE", "CARGO_TARGET_DIR"):
            with self.subTest(name=name):
                line = [item for item in environment.splitlines() if "('" + name + "=" in item]
                self.assertEqual(len(line), 1)
                self.assertIn("$scratch.", line[0])
        specs = self.function_body("Get-StageSpecs")
        control_branch = specs.split("} else {", 1)[1].split("    }\n    $specs +=", 1)[0]
        self.assertNotIn("$script:Lpac", control_branch)
        self.assertNotIn("ReadOnly", control_branch)
        self.assertIn("$cargoManifest = Join-Path $scratch.Crate", specs)

    def test_negative_acl_stages_require_the_specific_denial_and_a_listing_control(self):
        specs = self.function_body("Get-StageSpecs")
        confined_branch = specs.split("} else {", 1)[0]
        control_branch = specs.split("} else {", 1)[1]
        denied = re.search(r"Name = 'acl_downloads_denied'.*", confined_branch).group(0)
        self.assertIn("-match 'Access is denied'", denied)
        self.assertIn("$r.ExitCode -ne 0", denied)
        write_denied = re.search(r"Name = 'acl_ro_write_denied'.*", confined_branch).group(0)
        self.assertIn("-match 'Access is denied'", write_denied)
        self.assertIn("copy /y nul ' + $layout.ReadOnly", write_denied)
        self.assertIn("-not (Test-Path -LiteralPath ($script:Layout.ReadOnly", write_denied)
        listable = re.search(r"Name = 'acl_downloads_listable'.*", control_branch).group(0)
        self.assertIn("$r.ExitCode -eq 0", listable)
        self.assertIn("dir /b ' + $layout.Downloads", listable)
        self.assertIn("rustc\\.tar\\.gz", listable)
        self.assertIn(
            "$confinedOutcomes['acl_downloads_denied'].Passed -and $confinedOutcomes['acl_ro_write_denied'].Passed -and $controlOutcomes['acl_downloads_listable'].Passed",
            self.wrapper,
        )
        self.assertIn("-and $aclNegative -eq 'denied'", self.wrapper)

    def test_summary_does_not_overclaim_the_vitest_or_rolldown_steps(self):
        for required in (" css_transform=", " rolldown=load_only", " vitest=not_run", " rolldown_call=not_run"):
            with self.subTest(required=required):
                self.assertIn(required, self.wrapper)
        self.assertIn("name=minifies_a_stylesheet result=pass", self.wrapper)

    def test_cleanup_and_reader_shutdown_are_surfaced(self):
        self.assertIn("public bool CleanupComplete", self.native)
        self.assertIn("cleanupComplete = false;", self.native)
        self.assertIn("if (-not $box.CleanupComplete) { $cleanup = 'incomplete' }", self.wrapper)
        self.assertIn("private static bool JoinReader(Thread reader)", self.native)
        self.assertIn("if (outJoined)", self.native)
        self.assertIn("if (errJoined)", self.native)
        self.assertIn('result.Failure = "reader_join";', self.native)
        self.assertNotIn("CloseOne(ref outRead);\n                CloseOne(ref errRead);", self.native)

    def test_ancestor_grants_stop_at_the_runner_temp_directory(self):
        self.assertEqual(self.wrapper.count("Grant-Access (Split-Path -Parent $layout.Base)"), 1)
        self.assertNotIn("while ($parent)", self.wrapper)
        self.assertEqual(len(re.findall(r"^\s*Grant-Access ", self.wrapper, re.M)), 3)
        self.assertIn("Grant-Access $layout.ReadOnly $script:Sid 'ReadAndExecute, Synchronize' $true", self.wrapper)
        self.assertIn("Grant-Access $script:Lpac.Root $script:Sid 'Modify, Synchronize' $true", self.wrapper)
        self.assertIn("'ReadAttributes, Synchronize' $false", self.wrapper)

    def test_worst_case_runtime_fits_eighty_percent_of_the_job_timeout(self):
        specs = self.function_body("Get-StageSpecs")
        confined_branch, rest = specs.split("} else {", 1)
        control_branch, common = rest.split("    }\n    $specs +=", 1)
        common = "$specs +=" + common

        def total(text):
            return sum(int(value) for value in re.findall(r"Timeout = ([0-9]+);", text))

        ladders = total(confined_branch) + total(common) + total(control_branch) + total(common)
        downloads = len(re.findall(r"\bFile = '", self.wrapper))
        attempts = int(re.search(r"\$attempt -ge ([0-9]+)", self.wrapper).group(1))
        per_attempt = int(re.search(r"-TimeoutSec ([0-9]+)", self.wrapper).group(1))
        staging_allowance = 600
        worst = ladders + downloads * attempts * per_attempt + staging_allowance
        workflow = WORKFLOW.read_text(encoding="utf-8")
        minutes = [int(value) for value in re.findall(r"timeout-minutes: ([0-9]+)", workflow)]
        self.assertEqual(len(minutes), 2)
        self.assertLessEqual(worst, minutes[1] * 60 * 0.8)

    def test_wrapper_reports_stable_lines_and_fails_closed(self):
        for required in (
            "windows-confinement-spike=observed rust=",
            "windows-confinement-spike=refused phase=",
            "windows-confinement-image=recorded",
            "windows-confinement-stage=",
            "windows-confinement-compile=observed result=compiled",
            "windows-confinement-cleanup=",
            "first_failure=",
            "control_rust=",
            "control_node=",
            "acl_negative=",
            "ValidateSet('spike', 'compile')",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.wrapper)
        self.assertIn("$env:CI_REF -ne 'refs/heads/main'", self.wrapper)
        self.assertIn("$env:CI_REPOSITORY -ne 'keeldock-platform/platform-ci'", self.wrapper)
        for forbidden in ("Invoke-Expression", "iex ", "RunAs", "Set-ExecutionPolicy", "Start-Process", "SetEnvironmentVariable"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.wrapper)

    def test_workflow_runs_only_source_free_checks(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        for required in (
            "windows_confinement.ps1 -Mode compile",
            "windows_confinement.ps1 -Mode spike",
            "test_windows_confinement.py",
        ):
            with self.subTest(required=required):
                self.assertIn(required, workflow)
        for forbidden in ("secrets.", "source-read", "environment:", "id-token", "uses:"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, workflow)


if __name__ == "__main__":
    unittest.main(verbosity=2)
