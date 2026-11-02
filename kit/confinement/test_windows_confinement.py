import fnmatch
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "kit/bootstrap"))

from public_tree import MAX_FILE_BYTES, inspect_text

NATIVE = ROOT / "kit/confinement/windows_confinement.cs"
WRAPPER = ROOT / "kit/confinement/windows_confinement.ps1"
PROBE = ROOT / "kit/confinement/windows_probe.rs"
WORKFLOW = ROOT / ".github/workflows/windows-confinement.yml"
CONFINED_STAGES = (
    "cmd_exec",
    "acl_ro_read",
    "acl_scratch_write",
    "acl_ro_write_denied",
    "acl_downloads_denied",
    "nul_open",
    "nul_write_dac",
    "stdin_eof",
    "temp_dir",
    "network_tcp_ipv4",
    "network_tcp_ipv6",
    "network_tcp_host",
    "network_dns",
    "network_udp",
    "canary_runner_temp",
    "canary_workspace",
    "canary_profile",
    "canary_scratch_control",
    "spawn_piped",
    "spawn_output",
    "acl_downloads_listable",
    "network_control",
    "rustc_version",
    "cargo_version",
    "link_banner",
    "rust_build",
    "rust_test",
    "node_version",
    "node_bindings",
    "node_child",
)
PROBE_COMMANDS = (
    "wsa",
    "connect",
    "dns",
    "udp",
    "nul",
    "nuldac",
    "write",
    "read",
    "list",
    "stat",
    "stdin",
    "spawn",
    "tempdir",
    "echo",
)
EXPECTED_SUMMARY = (
    ("rust", "compiled"),
    ("node", "ran"),
    ("node_child", "ran"),
    ("first_failure", "none"),
    ("lpac", "verified"),
    ("lpac_basis", "attr"),
    ("capabilities", "registryRead"),
    ("job", "verified"),
    ("acl", "verified"),
    ("scratch_write", "ok"),
    ("ro_write", "denied"),
    ("downloads", "denied"),
    ("nul_open", "ok"),
    ("nul_write_dac", "denied"),
    ("stdin", "eof_pipe"),
    ("temp_dir", "verified"),
    ("spawn_piped", "ok"),
    ("network", "blocked"),
    ("canary", "absent"),
    ("control_rust", "compiled"),
    ("control_node", "ran"),
    ("css_transform", "ok"),
)


class WindowsConfinementSpikeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.native = NATIVE.read_text(encoding="utf-8")
        cls.wrapper = WRAPPER.read_text(encoding="utf-8")
        cls.probe = PROBE.read_text(encoding="utf-8")

    def test_files_pass_the_public_tree_rules(self):
        for path in (NATIVE, WRAPPER, PROBE, WORKFLOW):
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
            "capabilities.CapabilityCount = 1",
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
            "ReadToken(process, confined, profileSid, registryReadSidText, result)",
            "ResumeThread(thread)",
            "WaitForSingleObject(process, (uint)timeoutMs)",
        )
        positions = [self.native.index(item) for item in order]
        self.assertEqual(positions, sorted(positions))
        self.assertIn("Native.TerminateJobObject(job, JobKillExitCode)", self.native)
        self.assertEqual(self.native.count("handleBuffer = Marshal.AllocHGlobal(IntPtr.Size * 3)"), 1)

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

    def test_rust_component_names_are_exact_and_refusals_report_bounded_names(self):
        self.assertIn("rustc = 'rustc'", self.wrapper)
        self.assertIn("cargo = 'cargo'", self.wrapper)
        self.assertIn("rust_std = ('rust-std-' + $RustTarget)", self.wrapper)
        for root in (
            "Root = ('rustc-' + $RustVersion + '-' + $RustTarget)",
            "Root = ('cargo-' + $RustVersion + '-' + $RustTarget)",
            "Root = ('rust-std-' + $RustVersion + '-' + $RustTarget)",
        ):
            with self.subTest(root=root):
                self.assertIn(root, self.wrapper)
        self.assertIn("$expectedComponent = $ExpectedRustComponents[$item.Name]", self.wrapper)
        self.rust_component_guard()
        self.assertIn("expected_component=", self.wrapper)
        self.assertIn("observed_component=", self.wrapper)
        safe_name = self.function_body("Get-SafeComponentName")
        self.assertIn("'[^A-Za-z0-9._-]'", safe_name)
        self.assertIn("$value.Substring(0, 64)", safe_name)

    def rust_component_guard(self):
        stage = self.wrapper.split("$phase = 'stage_rust'", 1)[1].split("$phase = 'stage_node'", 1)[0]
        branch = re.search(
            r"(?m)^[ \t]*if \(-not \[string\]::Equals\(\$name, \$expectedComponent, "
            r"\[StringComparison\]::Ordinal\)\) \{\n"
            r"[ \t]*\$componentNameExpected = \$expectedComponent\n"
            r"[ \t]*\$componentNameObserved = \$name\n"
            r"[ \t]*throw 'component_name'\n"
            r"[ \t]*\}$",
            stage,
        )
        self.assertIsNotNone(branch)
        self.assertLess(stage.index("$expectedComponent = $ExpectedRustComponents[$item.Name]"), branch.start())
        self.assertLess(branch.end(), stage.index("$componentSource = Join-Path $componentRoot $name"))
        return branch.group(0)

    def test_rust_component_guard_rejects_unexpected_names_in_windows_ci(self):
        if sys.platform != "win32":
            self.skipTest("PowerShell component guard runs in Windows CI")
        script = (
            "$ErrorActionPreference = 'Stop'\n"
            "function Test-Component([string]$name, [string]$expectedComponent) {\n"
            + self.rust_component_guard()
            + "\n}\n"
            + """
Test-Component 'rustc' 'rustc'
Test-Component 'cargo' 'cargo'
Test-Component 'rust-std-x86_64-pc-windows-msvc' 'rust-std-x86_64-pc-windows-msvc'
$cases = @(
    @{ Expected = 'rustc'; Observed = 'wrong' }
    @{ Expected = 'rustc'; Observed = 'RUSTC' }
    @{ Expected = 'rustc'; Observed = 'rustc/cargo' }
    @{ Expected = 'rustc'; Observed = ('rustc' + [char]92 + 'cargo') }
    @{ Expected = 'rustc'; Observed = '../rustc' }
    @{ Expected = 'rustc'; Observed = 'rustc/../cargo' }
    @{ Expected = 'rustc'; Observed = ('rust' + [char]0 + 'c') }
    @{ Expected = 'rustc'; Observed = ('rust' + [char]0x00AD + 'c') }
    @{ Expected = 'rustc'; Observed = ('rust' + [char]0x200B + 'c') }
    @{ Expected = 'rust-std-x86_64-pc-windows-msvc'; Observed = 'rust-std-x86-64-pc-windows-msvc' }
)
foreach ($case in $cases) {
    $rejected = $false
    try {
        Test-Component $case.Observed $case.Expected
    } catch {
        if ($_.Exception.Message -ne 'component_name') { throw }
        $rejected = $true
    }
    if (-not $rejected) { throw 'accepted_bad_component' }
}
"""
        )
        result = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def function_body(self, name, source=None):
        match = re.search(r"^function " + re.escape(name) + r"\b.*?^\}$", self.wrapper if source is None else source, re.S | re.M)
        self.assertIsNotNone(match, name)
        return match.group(0)

    def test_wrapper_runs_the_control_first_then_the_confined_ladder(self):
        names = re.findall(r"Name = '([a-z0-9_]+)'; Exe", self.wrapper)
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
        for name in re.findall(r"^function ([A-Za-z0-9-]+)", self.wrapper, re.M):
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
        proof = re.search(r"^ *\$lpacProven = (.+)$", self.function_body("Invoke-Ladder"), re.M)
        self.assertIsNotNone(proof)
        patterns = re.findall(r"\$tokenText -like '([^']+)'", proof.group(1))
        self.assertEqual(len(patterns), 7)
        return all(fnmatch.fnmatchcase(text, pattern) for pattern in patterns)

    def test_container_proof_requires_every_token_fact_explicitly(self):
        good = "appcontainer=1,capabilities=1,integrity=0x1000,lpac=attr,cap=registryRead,sid=match,aap=absent"
        self.assertTrue(self.token_accepted(good))
        for bad in (
            good.replace("lpac=attr", "lpac=none"),
            good.replace("lpac=attr", "lpac=unreadable"),
            good.replace("lpac=attr", "lpac=aap_only"),
            good.replace("capabilities=1", "capabilities=0"),
            good.replace("capabilities=1", "capabilities=2"),
            good.replace("cap=registryRead", "cap=mismatch"),
            good.replace("sid=match", "sid=mismatch"),
            good.replace("aap=absent", "aap=present"),
            good.replace("appcontainer=1", "appcontainer=0"),
            good.replace("integrity=0x1000", "integrity=0x2000"),
            "appcontainer=1,capabilities=0,integrity=0x1000,lpac=1,sid=match,arap=present,aap=absent",
            "appcontainer=0,integrity=0x3000",
            "none",
            "unknown",
        ):
            with self.subTest(token=bad):
                self.assertFalse(self.token_accepted(bad))
        for required in (
            'sidState != "match"',
            'applicationPackages != "absent"',
            "TokenAppContainerSid",
            "TokenGroups",
            "TokenRestrictedSids",
            'AllApplicationPackagesSid = "S-1-15-2-1"',
            "GroupEnabled = 0x00000004",
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
        scratch_write = re.search(r"Name = 'acl_scratch_write'.*", specs).group(0)
        self.assertIn("$scratch.Tmp + '\\kd_write.txt'", scratch_write)
        self.assertIn("$script:Lpac.Tmp + '\\kd_write.txt'", scratch_write)
        control_branch = specs.split("} else {", 1)[1].split("    }\n    $specs +=", 1)[0]
        self.assertNotIn("$script:Lpac", control_branch)
        self.assertNotIn("ReadOnly", control_branch)
        self.assertIn("$cargoManifest = Join-Path $scratch.Crate", specs)

    def test_scratch_grants_match_low_integrity_inherited_write_paths(self):
        self.assertIn("Grant-Access $script:Lpac.Root $script:Sid 'Modify, Synchronize' $true", self.wrapper)
        self.assertIn("Set-LowIntegrityLabel $script:Lpac.Root", self.wrapper)
        low_label = self.function_body("Set-LowIntegrityLabel")
        self.assertIn("'/setintegritylevel' '(OI)(CI)L'", low_label)
        self.assertIn("if ($LASTEXITCODE -ne 0) { throw 'integrity_set' }", low_label)
        check_label = self.function_body("Test-LowIntegrityLabel")
        self.assertIn("Mandatory Label\\\\Low Mandatory Level", check_label)
        self.assertIn("Test-LowIntegrityLabel $script:Lpac.Root", self.function_body("Test-Acl"))
        acl = self.function_body("Test-Acl")
        for path in ("$script:Lpac.Tmp", "$script:Lpac.Profile", "$script:Lpac.CargoHome", "$script:Lpac.Crate"):
            with self.subTest(path=path):
                self.assertIn(path, acl)
        self.assertIn("-not $entries[0].IsInherited", acl)
        self.assertIn("$entries[0].AccessControlType -ne 'Allow'", acl)
        self.assertIn("$entries[0].FileSystemRights -band $modifyMask", acl)
        environment = self.function_body("New-StageEnvironment")
        for name in ("TEMP", "TMP"):
            line = next(item for item in environment.splitlines() if "('" + name + "=" in item)
            self.assertIn("$scratch.Tmp", line)

    def test_only_the_confinement_workflow_loads_the_spike_native_and_wrapper_files(self):
        names = ("windows_confinement.cs", "windows_confinement.ps1", "windows_probe.rs")
        allowed = {WORKFLOW.resolve()}
        candidates = list((ROOT / ".github").rglob("*.yml")) + list((ROOT / "kit").rglob("action.yml"))
        self.assertGreater(len(candidates), 1)
        for path in candidates:
            if path.resolve() in allowed:
                continue
            text = path.read_text(encoding="utf-8")
            for name in names:
                with self.subTest(path=path.name, name=name):
                    self.assertNotIn(name, text)
        template = (ROOT / "kit/bootstrap/policy_windows.py").read_text(encoding="utf-8")
        start = template.index('WINDOWS_CONFINEMENT_WORKFLOW_TEMPLATE = """')
        end = template.index('"""', start + 60)
        for path in sorted((ROOT / "kit/bootstrap").glob("policy_*.py")):
            text = path.read_text(encoding="utf-8")
            for name in names:
                if path.name == "policy_windows.py":
                    for match in re.finditer(re.escape(name), text):
                        with self.subTest(path=path.name, name=name, offset=match.start()):
                            self.assertTrue(start <= match.start() < end)
                else:
                    with self.subTest(path=path.name, name=name):
                        self.assertNotIn(name, text)

    def test_scripts_have_no_line_starting_with_an_operator(self):
        starts = re.compile(r"^\s*-(and|or|band|bor|eq|ne|not)\b")
        ends = re.compile(r"(?:-(?:and|or|band|bor|eq|ne)|,|\|)\s*$")
        for path in (WRAPPER,):
            lines = path.read_text(encoding="utf-8").splitlines()
            for number, line in enumerate(lines[1:], 2):
                if starts.match(line):
                    with self.subTest(path=path.name, line=number):
                        self.assertRegex(lines[number - 2], ends)

    def test_syntax_check_step_runs_before_the_compile_step(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        check = text.index("      - name: Check PowerShell script syntax\n")
        self.assertLess(check, text.index("      - name: Compile native confinement module\n"))
        block = text[check:text.index("      - name: Compile native confinement module\n")]
        self.assertIn("[System.Management.Automation.Language.Parser]::ParseFile", block)
        for name in ("windows_confinement.ps1",):
            self.assertIn("'" + name + "'", block)
        self.assertIn("if ($bad -ne 0) { exit 1 }", block)
        self.assertNotIn("if:", block)

    def test_negative_acl_stages_require_the_specific_denial_and_a_listing_control(self):
        specs = self.function_body("Get-StageSpecs")
        confined_branch = specs.split("} else {", 1)[0]
        control_branch = specs.split("} else {", 1)[1]
        denied = re.search(r"Name = 'acl_downloads_denied'.*", confined_branch).group(0)
        self.assertIn("-match 'Access is denied'", denied)
        self.assertIn("$r.ExitCode -ne 0", denied)
        self.assertIn("type ", denied)
        self.assertIn("$layout.Downloads", denied)
        self.assertIn("acl_probe.txt", denied)
        self.assertNotIn("> nul", denied)
        self.assertIn("New-Item -ItemType File -Path (Join-Path $layout.Downloads 'acl_probe.txt')", self.wrapper)
        write_denied = re.search(r"Name = 'acl_ro_write_denied'.*", confined_branch).group(0)
        self.assertIn("Exe = $probe", write_denied)
        self.assertIn("'write ' + $layout.ReadOnly", write_denied)
        self.assertIn("kd-probe write create=err5", write_denied)
        self.assertIn("-not (Test-Path -LiteralPath ($script:Layout.ReadOnly", write_denied)
        listable = re.search(r"Name = 'acl_downloads_listable'.*", control_branch).group(0)
        self.assertIn("$r.ExitCode -eq 0", listable)
        self.assertIn("dir /b ' + $layout.Downloads", listable)
        self.assertIn("rustc\\.tar\\.gz", listable)
        self.assertIn(
            "if ((Test-Passed $confinedOutcomes @('acl_downloads_denied')) -and (Test-Passed $controlOutcomes @('acl_downloads_listable'))) { $observed['downloads'] = 'denied' }",
            self.wrapper,
        )
        self.assertIn(
            "if (Test-Passed $confinedOutcomes @('acl_ro_write_denied')) { $observed['ro_write'] = 'denied' }",
            self.wrapper,
        )

    def test_summary_does_not_overclaim_the_vitest_or_rolldown_steps(self):
        for required in ("css_transform = 'ok'", " rolldown=load_only", " vitest=not_run", " rolldown_call=not_run"):
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

    def test_ancestor_grants_cover_the_full_chain_without_propagation(self):
        self.assertIn("$ancestorPath = $layout.Base", self.wrapper)
        self.assertIn("$ancestorPath = Split-Path -Parent $ancestorPath", self.wrapper)
        self.assertIn("while ($ancestorPath) {", self.wrapper)
        self.assertIn("Grant-NonPropagating $ancestorPath $script:Sid", self.wrapper)
        self.assertIn("$phase = 'acl_ancestors'", self.wrapper)
        self.assertNotIn("catch {\n            $ancestorFailures", self.wrapper)
        self.assertEqual(len(re.findall(r"^\s*Grant-Access ", self.wrapper, re.M)), 2)
        self.assertIn("Grant-Access $layout.ReadOnly $script:Sid 'ReadAndExecute, Synchronize' $true", self.wrapper)
        self.assertIn("Grant-Access $script:Lpac.Root $script:Sid 'Modify, Synchronize' $true", self.wrapper)
        self.assertNotIn("'ReadAttributes, Synchronize' $false", self.wrapper)
        grant = self.function_body("Grant-NonPropagating")
        for required in ("NonPropagatingDacl]::Read", "NonPropagatingDacl]::Write", "AceFlags]::None", "1048704", "InsertAce($index, $ace)"):
            with self.subTest(required=required):
                self.assertIn(required, grant)
        self.assertNotIn("SetAccessControl", grant)
        self.assertNotIn("Set-Acl", self.wrapper)
        self.assertEqual(0x80 | 0x100000, 1048704)
        for required in ("SetFileSecurityW", "GetFileSecurityW", "DaclSecurityInformation = 0x00000004"):
            with self.subTest(required=required):
                self.assertIn(required, self.native)
        self.assertNotIn("SetNamedSecurityInfo", self.native)
        self.assertNotIn("preserve-symlinks", self.wrapper)
        acl = self.function_body("Test-Acl")
        for required in (
            "foreach ($path in $script:AncestorPaths)",
            "$entries.Count -ne 1",
            "$entries[0].FileSystemRights -ne $attributeMask",
            "[System.Security.AccessControl.FileSystemRights]'ReadAttributes, Synchronize'",
            "$entries[0].IsInherited",
            "$entries[0].InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None",
            "$entries[0].PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None",
            "'ancestor_rule'",
        ):
            with self.subTest(required=required):
                self.assertIn(required, acl)
        self.assertNotIn("$script:Layout.Base,", acl)

    def test_downloads_are_bounded_by_a_total_deadline(self):
        body = self.function_body("Invoke-Download")
        self.assertIn("CancelAfter([TimeSpan]::FromSeconds(120))", body)
        self.assertIn("$cancel.Token", body)
        self.assertIn("ResponseHeadersRead", body)
        self.assertNotIn("Invoke-WebRequest", self.wrapper)
        self.assertNotIn("-TimeoutSec", self.wrapper)
        self.assertIn("MaxAutomaticRedirections = 5", body)
        self.assertIn("$client.Dispose()", body)

    def test_async_results_are_captured_or_discarded(self):
        calls = re.findall(r"(?m)^\s*(.*(?:GetAsync|ReadAsStreamAsync|CopyToAsync)\(.*)$", self.wrapper)
        self.assertEqual(len(calls), 3)
        for call in calls:
            with self.subTest(call=call.strip()):
                self.assertRegex(call, r"^\s*(?:\$[A-Za-z][A-Za-z0-9_]*\s*=\s*|\[void\])")
                self.assertIn(".GetAwaiter().GetResult()", call)
        self.assertIn("return [string]$target", self.function_body("Invoke-Download"))

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
        per_attempt = int(re.search(r"CancelAfter\(\[TimeSpan\]::FromSeconds\(([0-9]+)\)\)", self.wrapper).group(1))
        probe_build = int(re.search(r"\$probeEnvironment, ([0-9]+), \[uint32\]32\)", self.wrapper).group(1)) // 1000
        staging_allowance = 600 + probe_build
        worst = ladders + downloads * attempts * per_attempt + staging_allowance
        workflow = WORKFLOW.read_text(encoding="utf-8")
        minutes = [int(value) for value in re.findall(r"timeout-minutes: ([0-9]+)", workflow)]
        self.assertEqual(len(minutes), 2)
        self.assertLessEqual(worst, minutes[1] * 60 * 0.8)

    def test_wrapper_reports_stable_lines_and_fails_closed(self):
        for required in (
            "windows-confinement-spike=observed",
            "windows-confinement-null=",
            "windows-confinement-temp=verified location=scratch_profile inherited_acl=verified label=low",
            "windows-confinement-probe=built",
            "windows-confinement-spike=refused phase=",
            "windows-confinement-image=recorded",
            "windows-confinement-stage=",
            "windows-confinement-compile=observed result=compiled",
            "windows-confinement-cleanup=",
            "first_failure = 'none'",
            "control_rust = 'compiled'",
            "control_node = 'ran'",
            "ValidateSet('spike', 'compile')",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.wrapper)
        self.assertIn("$env:CI_REF -ne 'refs/heads/main'", self.wrapper)
        self.assertIn("$env:CI_REPOSITORY -ne 'keeldock-platform/platform-ci'", self.wrapper)
        for forbidden in ("Invoke-Expression", "iex ", "RunAs", "Set-ExecutionPolicy", "Start-Process", "SetEnvironmentVariable"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.wrapper)

    def test_ancestor_count_does_not_replace_acl_readback_paths(self):
        self.assertIn("$script:AncestorPaths = @()", self.wrapper)
        self.assertIn("$script:AncestorPaths += $ancestorPath", self.wrapper)
        self.assertIn("$ancestorCount = $script:AncestorPaths.Count", self.wrapper)
        self.assertIn("scratch=modify ancestors_read_attributes=' + $ancestorCount", self.wrapper)
        self.assertNotRegex(
            self.wrapper,
            r"(?im)^\s*\$ancestors\s*=\s*\$script:Ancestors\.Count\b",
        )
        self.assertIn("foreach ($path in $script:AncestorPaths)", self.function_body("Test-Acl"))
        self.assertIn("if ($aclState -ne 'verified') { throw 'acl_readback' }", self.wrapper)

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

    def test_windows_has_no_source_mode_so_the_rust_licence_gate_is_linux_only(self):
        """Windows has no source mode, so the Rust licence gate is Linux source admission only."""
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("CI_MODE", workflow)
        self.assertNotIn("CI_MODE", self.wrapper)
        self.assertNotIn("Assert-RustLicenseAdmission", self.wrapper)
        self.assertNotIn("archive_producer_unavailable", self.wrapper)

    def test_capability_is_exactly_registry_read(self):
        self.assertEqual(self.native.count("Native.DeriveCapabilitySidsFromName("), 1)
        self.assertIn('private const string RegistryReadCapability = "registryRead";', self.native)
        self.assertEqual(self.native.count('"registryRead"'), 1)
        self.assertIn(
            "Native.DeriveCapabilitySidsFromName(RegistryReadCapability, out groupSids, out groupCount, out capabilitySids, out capabilityCount)",
            self.native,
        )
        self.assertIn("capabilities.CapabilityCount = 1;", self.native)
        self.assertIn("capabilities.Capabilities = capabilityArray;", self.native)
        self.assertIn("Marshal.WriteInt32(capabilityArray, IntPtr.Size, unchecked((int)GroupEnabled));", self.native)
        self.assertIn("private const uint GroupEnabled = 0x00000004;", self.native)
        self.assertIn("if (capabilityCount != 1 || capabilitySids == IntPtr.Zero)", self.native)
        self.assertIn("FreeOne(ref capabilityArray);", self.native)
        self.assertIn("FreeOne(ref capabilitySid);", self.native)
        self.assertNotIn("string[] capabilityNames", self.native)
        for name, text in (("native", self.native), ("wrapper", self.wrapper), ("probe", self.probe)):
            with self.subTest(source=name):
                self.assertIsNone(re.search(r"""["']lpac[A-Z]""", text))
                for forbidden in (
                    "internetClient",
                    "privateNetworkClientServer",
                    "enterpriseAuthentication",
                    "sharedUserCertificates",
                    "documentsLibrary",
                    "picturesLibrary",
                    "videosLibrary",
                    "musicLibrary",
                    "removableStorage",
                    "DeriveCapabilitySidsFromName",
                ):
                    if name == "native" and forbidden == "DeriveCapabilitySidsFromName":
                        continue
                    self.assertNotIn(forbidden, text)

    def test_aap_opt_out_attribute_is_kept(self):
        for required in (
            "private const uint ProcThreadAttributeAllApplicationPackagesPolicy = 0x0002000f;",
            "private const uint ProcessCreationAllApplicationPackagesOptOut = 0x00000001;",
            "Marshal.WriteInt32(policyBuffer, unchecked((int)ProcessCreationAllApplicationPackagesOptOut));",
            "ProcThreadAttributeAllApplicationPackagesPolicy, policyBuffer, new UIntPtr(4)",
            "int attributeCount = confined ? 3 : 1;",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.native)

    def test_token_requires_the_noallapppkg_attribute_and_the_exact_capability(self):
        for forbidden in (
            "SpikeAllowUnreadableLpac",
            "aap_only",
            "AllRestrictedApplicationPackagesSid",
            "ReadAllRestrictedApplicationPackagesState",
            "arap=",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.native)
                self.assertNotIn(forbidden, self.wrapper)
        for required in (
            "private const int TokenSecurityAttributes = 39;",
            "private const int TokenIsLessPrivilegedAppContainer = 46;",
            '"WIN://NOALLAPPPKG"',
            "string attribute = ReadNoAllAppPkgAttribute(token);",
            'attribute != "present"',
            'return "unreadable";',
            "capabilityCount != 1",
            "!capabilityMatches",
            "ReadSidInTokenSet(token, TokenCapabilities, expectedCapabilitySid, false)",
            'applicationPackages != "absent"',
            'sidState != "match"',
            "result.Class46 = class46;",
            '" lpac=" + (attribute == "present" ? "attr" : "none")',
            '" cap=" + (capabilityMatches ? RegistryReadCapability : "mismatch")',
            'throw new InvalidOperationException(text + " attr=" + attribute);',
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.native)
        ladder = self.function_body("Invoke-Ladder")
        self.assertIn("lpac=attr", ladder)
        self.assertIn("cap=registryRead", ladder)
        self.assertNotIn("lpac=1", ladder)
        self.assertNotIn("arap", ladder)

    def test_null_lease_mask_and_trustee_are_fixed(self):
        lease = self.native[self.native.index("public sealed class NullDeviceLease"):self.native.index("public sealed class Sandbox")]
        self.assertIn("private const uint LeaseMask = 0x0012019F;", lease)
        self.assertIn(r'private const string DevicePath = "\\\\.\\NUL";', lease)
        self.assertEqual(0x0012019F & (0x00040000 | 0x00080000 | 0x00010000), 0)
        self.assertIn("entry.AccessPermissions = LeaseMask;", lease)
        self.assertIn("entry.Trustee.Name = sid;", lease)
        self.assertIn("Native.ConvertStringSidToSidW(packageSid, out sid)", lease)
        self.assertIn('!packageSid.StartsWith("S-1-15-2-", StringComparison.Ordinal)', lease)
        for forbidden in ("S-1-15-2-1", "S-1-15-2-2", "S-1-1-0", "S-1-5-18", "S-1-5-32", "Everyone"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, lease)
        for required in (
            "if (after.Count != before.Count + 1)",
            "if (!SameBytes(after[index], before[index]))",
            "after.RemoveAt(found);",
            "attempt < 2",
            "WriteOriginal(attempt == 1)",
            "Native.SetKernelObjectSecurity(handle, DaclInformation, copy)",
            "SameBytes(ReadDescriptor(), original)",
        ):
            with self.subTest(required=required):
                self.assertIn(required, lease)
        wrapper = self.wrapper
        self.assertIn("[KeelDock.Platform.WindowsConfinement.NullDeviceLease]::Open($script:Sid)", wrapper)
        self.assertIn("windows-confinement-null=' + $nullState + ' mask=0x0012019f trustee=package readback=' + $nullReadback", wrapper)
        self.assertIn("if ($nullState -ne 'applied' -or $nullReadback -ne 'match') { throw 'null_lease' }", wrapper)
        control = wrapper.index("$controlOutcomes = Invoke-Ladder $box $false $script:Control")
        opened = wrapper.index("NullDeviceLease]::Open($script:Sid)")
        temp = wrapper.index("Initialize-ContainerTemp $box")
        confined = wrapper.index("$confinedOutcomes = Invoke-Ladder $box $true $script:Lpac")
        self.assertLess(control, opened)
        self.assertLess(opened, temp)
        self.assertLess(temp, confined)
        tail = wrapper[wrapper.index("$nullRestore = 'not_applied'"):]
        restore = tail.index("$script:NullLease.Restore()")
        canaries = tail.index("Remove-Canaries")
        dispose = tail.index("$box.Dispose()")
        base = tail.index("Remove-Item -LiteralPath $baseDirectory")
        self.assertLess(restore, canaries)
        self.assertLess(canaries, dispose)
        self.assertLess(dispose, base)
        self.assertIn("if ($nullRestore -eq 'failed') { $cleanup = 'incomplete' }", tail)
        self.assertIn(
            "if ($cleanup -ne 'verified' -or $nullRestore -ne 'verified' -or $profileText -ne 'deleted' -or $tempState -ne 'removed') { $exitCode = 1 }",
            tail,
        )

    def test_stdin_is_a_closed_pipe_and_the_handle_list_is_three(self):
        native = self.native
        self.assertIn("CreateEofStdin(out inRead);", native)
        self.assertIn("startup.StartupInfo.hStdInput = inRead;", native)
        self.assertNotIn("hStdInput = IntPtr.Zero", native)
        self.assertIn("Marshal.WriteIntPtr(handleBuffer, 0, inRead);", native)
        self.assertIn("Marshal.WriteIntPtr(handleBuffer, IntPtr.Size, outWrite);", native)
        self.assertIn("Marshal.WriteIntPtr(handleBuffer, IntPtr.Size * 2, errWrite);", native)
        self.assertIn("result.HandleCount = 3;", native)
        self.assertIn("new UIntPtr((uint)(IntPtr.Size * 3))", native)
        body = native[native.index("private static void CreateEofStdin"):native.index("private static string ReadNoAllAppPkgAttribute")]
        self.assertIn("attributes.InheritHandle = 1;", body)
        self.assertIn("Native.SetHandleInformation(write, HandleFlagInherit, 0)", body)
        self.assertLess(body.index("SetHandleInformation(write"), body.index("Native.CloseHandle(write);"))
        self.assertIn("CloseOne(ref errWrite);\n                CloseOne(ref inRead);\n\n                result.Failure = \"assign\";", native)
        self.assertLess(native.index("Native.CreateProcessW(executable"), native.index("CloseOne(ref inRead);"))
        self.assertIn("$r.HandleCount -eq 3", self.function_body("Get-StageSpecs"))
        self.assertIn("Handles = ([uint32]$result.HandleCount -eq 3)", self.function_body("Invoke-Ladder"))
        self.assertIn("' handles=' + $result.HandleCount", self.function_body("Invoke-Ladder"))
        self.assertIn("if ((Test-Passed $confinedOutcomes @('stdin_eof')) -and $allHandles) { $observed['stdin'] = 'eof_pipe' }", self.wrapper)

    def test_container_temp_is_computed_from_the_scratch_profile_and_cross_checked(self):
        body = self.function_body("Initialize-ContainerTemp")
        for required in (
            "[string]$sandbox.ProfileName",
            "[string]$script:Lpac.Profile",
            "(Join-Path $profileRoot 'Packages') $profileName) 'AC') 'Temp'",
            r"'\\Packages\\KDW[0-9a-f]{32}\\AC\\Temp$'",
            "if ($expected -notmatch $shape) { throw 'shape' }",
            "if (-not (Test-PathUnder $expected $script:Lpac.Root)) { throw 'shape' }",
            "if (-not $inherited) { throw 'acl' }",
            "if (-not (Test-LowIntegrityLabel $expected)) { throw 'label' }",
            "Invoke-ConfinedProbe $sandbox 'tempdir' 30",
            "if (-not (Test-ContainerTempReport ([string]$run.Stdout))) { throw 'identity' }",
            "windows-confinement-temp=verified location=scratch_profile inherited_acl=verified label=low",
        ):
            with self.subTest(required=required):
                self.assertIn(required, body)
        self.assertLess(body.index("throw 'shape'"), body.index("New-Item -ItemType Directory"))
        self.assertLess(body.index("New-Item -ItemType Directory"), body.index("Invoke-ConfinedProbe"))
        self.assertLess(body.index("Invoke-ConfinedProbe"), body.index("throw 'identity'"))
        for forbidden in ("Grant-Access", "Grant-NonPropagating", "Set-LowIntegrityLabel", "SetAccessControl", "icacls"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, body)
        report = self.function_body("Test-ContainerTempReport")
        self.assertIn("'^exists=yes writable=yes path=(.+)$'", report)
        self.assertIn("(Get-NormalPath $found.Groups[1].Value) -ceq (Get-NormalPath $script:ExpectedTemp)", report)
        normal = self.function_body("Get-NormalPath")
        for required in ("'\\\\?\\'", "ToLowerInvariant()", "EndsWith('\\')"):
            self.assertIn(required, normal)
        self.assertIn("public string ProfileName", self.native)
        self.assertIn('profileName = "KDW" + Guid.NewGuid().ToString("N");', self.native)
        environment = self.function_body("New-StageEnvironment")
        for name in ("USERPROFILE", "APPDATA", "LOCALAPPDATA"):
            line = [item for item in environment.splitlines() if "('" + name + "=" in item]
            self.assertEqual(len(line), 1)
            self.assertIn("$scratch.Profile", line[0])
        specs = self.function_body("Get-StageSpecs")
        stage = re.search(r"Name = 'temp_dir'.*", specs).group(0)
        self.assertIn("Quiet = $true", stage)
        self.assertIn("Test-ContainerTempReport $r.Stdout", stage)
        ladder = self.function_body("Invoke-Ladder")
        self.assertIn("$quiet = $spec.ContainsKey('Quiet')", ladder)
        self.assertIn("if (-not $quiet) {", ladder)
        self.assertIn("} elseif (-not $quiet) {", ladder)
        self.assertLess(self.wrapper.index("$phase = 'container_temp'"), self.wrapper.index("Initialize-ContainerTemp $box"))

    def test_no_registry_lease_and_no_scheduled_task(self):
        for name in ("windows_confinement_recovery.ps1", "test_windows_confinement_recovery.ps1"):
            with self.subTest(removed=name):
                self.assertFalse((ROOT / "kit/confinement" / name).exists())
        for path in (NATIVE, WRAPPER, PROBE, WORKFLOW):
            text = path.read_text(encoding="utf-8")
            for forbidden in (
                "schtasks",
                "ScheduledTask",
                "Register-ScheduledTask",
                "HKLM:",
                "HKCU:",
                "RegSetKeySecurity",
                "RegistryAccessRule",
                "Grant-WinsockCatalogRead",
                "WinsockCatalog",
                "NativeRegistryProbe",
                "NtOpenKey",
                "reg.exe",
                "native-probe",
                "Get-LpacBehaviour",
                "Invoke-ConfinedLadder",
            ):
                with self.subTest(path=path.name, forbidden=forbidden):
                    self.assertNotIn(forbidden, text)
        self.assertNotIn("pwsh.exe", self.wrapper)
        self.assertNotIn("$PSHOME", self.wrapper)
        self.assertNotIn("windows_confinement_recovery", WORKFLOW.read_text(encoding="utf-8"))

    def test_probe_vocabulary_is_closed(self):
        text = self.probe
        self.assertTrue(text.isascii())
        self.assertNotIn(chr(35), text)
        start = text.index("let text = match command {")
        section = text[start:text.index("};", start)]
        arms = re.findall(r'^\s*"([a-z_]+)" => ', section, re.M)
        self.assertEqual(sorted(arms), sorted(PROBE_COMMANDS))
        self.assertIn('_ => String::from("usage"),', section)
        spawn = text[text.index("fn probe_spawn"):text.index("fn probe_tempdir")]
        self.assertEqual(re.findall(r'^\s*"([a-z_]+)" => status_text', spawn, re.M), ["inherit", "piped_no_null", "output"])
        self.assertIn('println!("kd-probe {} {}", command, text);', text)
        for forbidden in ("LoadLibrary", "CreateNamedPipe", "CreatePipe", "CreateSemaphore", "CreateMutex", "std::io::pipe", "pipe_make", "pipe_open", "pipe_squat", "identity"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, text)
        specs = self.function_body("Get-StageSpecs")
        used = set(re.findall(r"Exe = \$probe; Arguments = \(?'([a-z_]+)", specs))
        self.assertTrue(used)
        self.assertLessEqual(used, set(PROBE_COMMANDS))
        fields = ("Name", "Exe", "Arguments", "Timeout", "Check")
        lines = [line for line in specs.splitlines() if "$specs += @{" in line]
        self.assertEqual(len(lines), len(CONFINED_STAGES))
        for line in lines:
            found = tuple(re.findall(r"(\w+) = ", line.split("Check =", 1)[0] + "Check = "))
            with self.subTest(line=line.strip()[:60]):
                self.assertIn(found, (fields, fields[:4] + ("Quiet", "Check")))
        self.assertIn("-l kernel32 -l ws2_32", self.wrapper)
        self.assertIn("$phase = 'build_probe'", self.wrapper)
        self.assertLess(self.wrapper.index("$phase = 'build_probe'"), self.wrapper.index("$phase = 'acl_readback'"))
        self.assertIn("$layout.ProbeExe = Join-Path $layout.ProbeDir 'kd_probe.exe'", self.wrapper)

    def test_ladder_has_no_copy_nul_and_no_piped_node_child(self):
        specs = self.function_body("Get-StageSpecs")
        self.assertNotIn("copy /y nul", specs)
        self.assertNotIn("copy /y nul", self.wrapper)
        child = re.search(r"\$NodeChildText = @'\n(.*?)\n'@", self.wrapper, re.S)
        self.assertIsNotNone(child)
        child_text = child.group(1)
        self.assertIn("stdio: 'inherit'", child_text)
        self.assertIn("spawnSync", child_text)
        self.assertIn("node:worker_threads", child_text)
        for forbidden in ("'pipe'", '"pipe"', "fork(", ".spawn(", "exec(", "execSync"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, child_text)
        bindings = re.search(r"\$NodeTestText = @'\n(.*?)\n'@", self.wrapper, re.S).group(1)
        self.assertNotIn("'pipe'", bindings)
        self.assertNotIn("child_process", bindings)
        for line in specs.splitlines():
            if "node.exe" in line:
                with self.subTest(line=line.strip()[:40]):
                    self.assertNotIn("pipe", line.lower())
        stage = re.search(r"Name = 'node_child'.*", specs).group(0)
        self.assertIn("Arguments = $layout.NodeChild", stage)
        self.assertIn("kd-node-child spawn=ok worker=ok", stage)
        self.assertIn("Timeout = 60", stage)
        self.assertIn("$layout.NodeChild = Join-Path $layout.TestDir 'kd_child.js'", self.wrapper)

    def test_no_rust_lld_reference(self):
        for path in (NATIVE, WRAPPER, PROBE, WORKFLOW):
            text = path.read_text(encoding="utf-8")
            with self.subTest(path=path.name):
                self.assertIsNone(re.search(r"(?i)rust-lld|rust_lld|lld-link|linker-flavor|\blld\b", text))
        self.assertIn(
            "RUSTFLAGS=-C linker=' + $layout.MsvcBin + '\\link.exe -C debuginfo=0 -C link-arg=/DEBUG:NONE",
            self.function_body("New-StageEnvironment"),
        )
        self.assertIn("-C linker=' + $layout.MsvcBin + '\\link.exe", self.wrapper)

    def test_summary_line_shape_and_exit_zero_requires_every_token(self):
        found = re.search(r"\$expectedTokens = \[ordered\]@\{ (.+) \}\n", self.wrapper)
        self.assertIsNotNone(found)
        pairs = tuple(re.findall(r"([a-z_]+) = '([A-Za-z_]+)'", found.group(1)))
        self.assertEqual(pairs, EXPECTED_SUMMARY)
        for required in (
            "$summary = 'windows-confinement-spike=observed'",
            "$summary += ' ' + $key + '=' + $observed[$key]",
            "if ($observed[$key] -cne $expectedTokens[$key]) { $allExpected = $false }",
            "Write-Line ($summary + ' rolldown=load_only vitest=not_run rolldown_call=not_run')",
            "if ($allExpected) { $exitCode = 0 }",
            "'windows-confinement-cleanup=' + $cleanup + ' null_restore=' + $nullRestore + ' profile=' + $profileText + ' temp_dir=' + $tempState",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.wrapper)
        self.assertEqual(self.wrapper.count("$exitCode = 0"), 2)
        for key, _ in EXPECTED_SUMMARY:
            with self.subTest(key=key):
                self.assertIn("$observed['" + key + "'] = ", self.wrapper)
        ladder = self.function_body("Invoke-Ladder")
        for required in (
            "' hang=' + $hang",
            "' cpu_ms=' + $result.CpuMs",
            "' peak_process_mib=' + (Get-Mib $result.PeakProcessMemory)",
            "' peak_job_mib=' + (Get-Mib $result.PeakJobMemory)",
            "' class46=' + $class46Text",
            "$hang = 'slow'",
            "$hang = 'busy'",
            "([uint64]$result.CpuMs * 10) -ge ([uint64]$result.ElapsedMs * 8)",
        ):
            with self.subTest(required=required):
                self.assertIn(required, ladder)
        for required in ("private static void ReadCpu(IntPtr job, RunResult result)", "ReadPeaks(job, result);", "ReadCpu(job, result);", "result.CpuMs = "):
            with self.subTest(required=required):
                self.assertIn(required, self.native)
        self.assertEqual(self.wrapper.count("windows-confinement-null="), 1)
        self.assertIn("mask=0x0012019f", self.wrapper)


if __name__ == "__main__":
    unittest.main(verbosity=2)
