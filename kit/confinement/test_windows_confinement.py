import fnmatch
import re
import shutil
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "kit/bootstrap"))
sys.path.insert(0, str(ROOT / "kit/confinement"))

from public_tree import MAX_FILE_BYTES, inspect_text
from linux_channels import CHANNELS as LINUX_CHANNELS

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
    "network_control_ipv6",
    "network_control_dns",
    "network_control_udp",
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
    "append",
    "pipemake",
    "pipeopen",
    "procopen",
    "conout",
    "eventlog",
    "envhunt",
    "marker",
    "regread",
    "regcreate",
    "dacopen",
    "walk",
    "jobbreak",
    "jobmember",
    "profile",
    "scm",
    "symlink",
    "hardlink",
    "tokenraise",
    "tokenpriv",
    "taskreg",
    "wmi",
    "wfp",
    "procpeer",
    "peerwait",
)
CHANNEL_ATTEMPTS = {
    "https": ("tls-ipv4", "tls-ipv6", "tls-hostname"),
    "dns": ("getaddrinfo", "unique-name", "udp-query", "tcp-query"),
    "redirect": ("http-redirect",),
    "proxy": ("proxy-env-http", "proxy-connect"),
    "runner_ipc": (
        "pipe-root-create",
        "pipe-existing-open",
        "pipe-runner-open",
        "process-open-runner",
        "handle-inventory",
        "named-pipe-local",
    ),
    "raw_logs": ("stdout-markers", "conout-open", "eventlog"),
    "artifact_upload": ("env-hunt", "endpoint-post", "staging-write"),
    "cache_upload": ("env-hunt", "endpoint-post", "cache-write"),
    "runner_files": (
        "canary-reads",
        "diag-read",
        "command-files",
        "cng-keys",
        "registry-canary",
        "bounded-walk",
        "walk-control-scratch",
    ),
    "process_memory": ("mem-read", "environ-read", "debug-attach", "control-self-memory", "control-peer-memory"),
    "boundary_disablement": (
        "job-breakaway",
        "job-membership",
        "profile-create",
        "scm-open",
        "nul-write-dac",
        "ancestor-write-dac",
        "hklm-write",
        "hkcu-write",
        "symlink",
        "hardlink-ro",
        "integrity-raise",
        "privilege-enable",
        "task-register",
        "wmi",
        "wfp",
    ),
}
DENIAL_CODES = {
    "err2",
    "err3",
    "err5",
    "err6",
    "err1300",
    "err1314",
    "err10013",
    "err11003",
    "hr80070005",
    "hr800706d9",
    "hr80041003",
}
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
    ("ipv6", "blocked"),
    ("ipv6_control", "open"),
    ("canary", "absent"),
    ("control_rust", "compiled"),
    ("control_node", "ran"),
    ("css_transform", "ok"),
    ("channels_before", "blocked"),
    ("channels_after", "blocked"),
    ("channel_controls", "fired"),
    ("dns_after", "open"),
    ("fixtures", "contained"),
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
        other_seconds = int(re.search(r"\$script:OtherContainerSeconds = ([0-9]+)", self.wrapper).group(1))
        staging_allowance = 600 + probe_build + 2 * other_seconds
        dns_after = int(re.search(r"Name = 'network_control_dns'; Exe = \$probe; Arguments = 'dns github\.com'; Timeout = ([0-9]+);", specs).group(1))
        worst = ladders + downloads * attempts * per_attempt + staging_allowance + dns_after + self.channel_budget() + self.fixture_budget()
        workflow = WORKFLOW.read_text(encoding="utf-8")
        minutes = [int(value) for value in re.findall(r"timeout-minutes: ([0-9]+)", workflow)]
        self.assertEqual(len(minutes), 2)
        self.assertEqual(minutes[1], 240)
        self.assertLessEqual(worst, minutes[1] * 60 * 0.8)

    def channel_attempt_lines(self):
        body = self.function_body("Get-ChannelAttempts")
        return [line for line in body.splitlines() if line.strip().startswith("$attempts += @{")]

    def channel_field(self, line, field):
        found = re.search(r"(?<![A-Za-z])" + field + r" = ('[^']*'|\$true|@\([^)]*\)|[0-9]+)", line)
        return None if found is None else found.group(1)

    def fixture_budget(self):
        def number(name):
            found = re.search(r"^\$" + name + r" = ([0-9]+)$", self.wrapper, re.M)
            self.assertIsNotNone(found, name)
            return int(found.group(1))

        forms = re.search(r"^\$FixtureForms = @\((.*)\)$", self.wrapper, re.M)
        self.assertIsNotNone(forms)
        cargo_forms = len(re.findall(r"'([a-z_]+)'", forms.group(1))) - 1
        return (
            2 * cargo_forms * (number("FixtureCargoSeconds") + 3)
            + 2 * (number("FixtureNodeSeconds") + 3)
            + 2 * (number("FixtureSpawnSeconds") + 3)
        )

    def channel_budget(self):
        multipliers = {"{pid}": 3, "{runner_pipe}": 6, "{drive}": 2}

        def runs(line, field, timeout):
            raw = self.channel_field(line, field)
            if raw is None:
                return 0
            total = 0
            for template in re.findall(r"'([^']*)'", raw):
                count = 1
                for token, factor in multipliers.items():
                    if token in template:
                        count *= factor
                total += (timeout + 3) * count
            return total

        budget = 0
        for line in self.channel_attempt_lines():
            timeout = int(self.channel_field(line, "Timeout"))
            control_timeout = self.channel_field(line, "ControlTimeout")
            control = int(control_timeout) if control_timeout else timeout
            budget += 2 * runs(line, "Runs", timeout) + runs(line, "ControlRuns", control)
        return budget

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
        base = tail.index("Remove-TreeNoFollow $baseDirectory")
        self.assertLess(restore, canaries)
        self.assertLess(canaries, dispose)
        self.assertLess(dispose, base)
        self.assertIn("if ($nullRestore -eq 'failed') { $cleanup = 'incomplete' }", tail)
        self.assertIn(
            "if ($cleanup -ne 'verified' -or $nullRestore -ne 'verified' -or $profileText -ne 'deleted' -or $tempState -ne 'removed' -or $linksState -ne 'verified' -or $processState -ne 'none') { $exitCode = 1 }",
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
        self.assertNotIn("result.HandleCount = 3;", native)
        self.assertIn("uint handleListSize = (uint)(IntPtr.Size * 3);", native)
        self.assertIn("new UIntPtr(handleListSize)", native)
        self.assertIn("result.HandleCount = MeasureHandleList(handleBuffer, handleListSize, handleListExpected);", native)
        create = native.index("Native.CreateProcessW(executable")
        measure = native.index("result.HandleCount = MeasureHandleList(")
        self.assertLess(create, measure)
        self.assertLess(measure, native.index("CloseOne(ref outWrite);", measure))
        self.assertLess(measure, native.index("Native.ResumeThread(thread)"))
        helper = native[native.index("private static uint MeasureHandleList"):native.index("private static void CreateEofStdin")]
        for required in (
            "sizeBytes % (uint)IntPtr.Size",
            "Marshal.ReadIntPtr(buffer, index * IntPtr.Size)",
            "entry != expected[index]",
            "Native.GetHandleInformation(entry, out flags)",
            "(flags & HandleFlagInherit) == 0",
            "return 0;",
        ):
            with self.subTest(required=required):
                self.assertIn(required, helper)
        self.assertIn("handles_method=list_attr_readback", self.function_body("Invoke-Ladder"))
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
        for forbidden in ("LoadLibraryA", "LoadLibraryW", "CreatePipe", "CreateSemaphore", "CreateMutex", "std::io::pipe", "pipe_make", "pipe_open", "pipe_squat", "identity", "DebugActiveProcess", "ReadProcessMemory", "ITaskService", "RegisterTaskDefinition"):
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
        self.assertIn("-l kernel32 -l ws2_32 -l advapi32 -l userenv -l ole32 -l oleaut32 -o ' + $probeBuilt", self.wrapper)
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
        pairs = tuple(re.findall(r"([a-z_0-9]+) = '([A-Za-z_]+)'", found.group(1)))
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
            "handles_method=list_attr_readback cpu_ms=' + $result.CpuMs",
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

    def test_network_blocked_is_a_closed_set_of_denial_codes(self):
        wrapper = self.wrapper
        self.assertIn("$NetworkDeniedConnect = @('err10013')", wrapper)
        self.assertIn("$NetworkDeniedResolve = @('err10013', 'err11001')", wrapper)
        self.assertIn("$NetworkDeniedUdp = @('err10013')", wrapper)
        self.assertIn("$NetworkUnroutableConnect = @('err10047', 'err10051')", wrapper)
        body = self.function_body("Get-NetworkState")
        for required in (
            "'wsa=failed'",
            "if ($text -ceq 'resolve=ok connect=open') { return 'open' }",
            "'^resolve=ok connect=(err[0-9]{1,5})$'",
            "'^resolve=(err[0-9]{1,5})$'",
            "'^resolve=ok count=[1-9][0-9]*$'",
            "if ($text -ceq 'send=ok recv=data') { return 'open' }",
            "'^send=(err[0-9]{1,5})$'",
            "$NetworkDeniedConnect -ccontains",
            "$NetworkDeniedResolve -ccontains",
            "$NetworkDeniedUdp -ccontains",
            "$NetworkUnroutableConnect -ccontains",
            "if ($text -ceq 'resolve=empty') { return 'unroutable' }",
        ):
            with self.subTest(required=required):
                self.assertIn(required, body)
        self.assertEqual(body.count("return 'blocked'"), 4)
        self.assertEqual(body.count("return 'unexpected'"), 4)
        self.assertEqual(body.count("return 'unroutable'"), 2)
        self.assertNotIn("return 'blocked'\n}", body)
        self.assertTrue(body.rstrip().endswith("return 'unexpected'\n}"))
        for forbidden in ("err10061", "err10060", "err10047", "err10051", "err10065", "connect=err'", "-match 'recv"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, body)
        codes = set(re.findall(r"err[0-9]+", wrapper[wrapper.index("$NetworkDeniedConnect"):wrapper.index("$NetworkUnroutableConnect")]))
        self.assertEqual(codes, {"err10013", "err11001", "err11003"})
        unroutable = set(re.findall(r"err[0-9]+", wrapper[wrapper.index("$NetworkUnroutableConnect"):wrapper.index("function Get-NetworkState")]))
        self.assertEqual(unroutable, {"err10047", "err10051"})
        specs = self.function_body("Get-StageSpecs")
        confined = specs.split("} else {", 1)[0]
        for stage, kind in (
            ("network_tcp_ipv4", "connect"),
            ("network_tcp_ipv6", "connect"),
            ("network_tcp_host", "connect"),
            ("network_dns", "dns"),
            ("network_udp", "udp"),
        ):
            line = re.search(r"Name = '" + stage + r"'.*", confined).group(0)
            with self.subTest(stage=stage):
                if stage == "network_tcp_ipv6":
                    self.assertIn("(Get-NetworkState $r.Stdout 'connect') -cin @('blocked', 'unroutable')", line)
                elif stage in ("network_tcp_host", "network_dns"):
                    self.assertIn("(Get-NetworkState $r.Stdout '" + kind + "') -cin @('blocked', 'blocked_resolve')", line)
                elif stage == "network_udp":
                    self.assertIn("(Get-NetworkState $r.Stdout 'udp') -cin @('blocked', 'blocked_bind')", line)
                else:
                    self.assertIn("(Get-NetworkState $r.Stdout '" + kind + "') -ceq 'blocked'", line)
        self.assertIn(
            "fn probe_connect",
            self.probe,
        )
        connect = self.probe[self.probe.index("fn probe_connect"):self.probe.index("fn probe_dns")]
        self.assertIn('if last == "none" || last == "err10013" {', connect)

    def network_state_model(self, text, kind):
        wrapper = self.wrapper

        def names(var):
            found = re.search(r"^\$" + var + r" = @\((.*)\)$", wrapper, re.M)
            self.assertIsNotNone(found, var)
            return re.findall(r"'(err[0-9]+)'", found.group(1))

        connect = names("NetworkDeniedConnect")
        resolve = names("NetworkDeniedResolve")
        udp = names("NetworkDeniedUdp")
        host = names("NetworkDeniedHostResolve")
        bind = names("NetworkDeniedBind")
        unroutable = names("NetworkUnroutableConnect")
        if not text:
            return "no_output"
        if text == "wsa=failed":
            return "wsa_failed"
        if kind == "connect":
            if text == "resolve=ok connect=open":
                return "open"
            found = re.fullmatch(r"resolve=ok connect=(err[0-9]{1,5})", text)
            if found and found.group(1) in connect:
                return "blocked"
            found = re.fullmatch(r"resolve=(err[0-9]{1,5})", text)
            if found and found.group(1) in resolve:
                return "blocked"
            if found and found.group(1) in host:
                return "blocked_resolve"
            if text == "resolve=empty":
                return "unroutable"
            found = re.fullmatch(r"resolve=ok connect=(err[0-9]{1,5})", text)
            if found and found.group(1) in unroutable:
                return "unroutable"
            return "unexpected"
        if kind == "dns":
            if re.fullmatch(r"resolve=ok count=[1-9][0-9]*", text):
                return "open"
            found = re.fullmatch(r"resolve=(err[0-9]{1,5})", text)
            if found and found.group(1) in resolve:
                return "blocked"
            if found and found.group(1) in host:
                return "blocked_resolve"
            return "unexpected"
        if kind == "udp":
            if text == "send=ok recv=data":
                return "open"
            found = re.fullmatch(r"send=(err[0-9]{1,5})", text)
            if found and found.group(1) in udp:
                return "blocked"
            found = re.fullmatch(r"bind=(err[0-9]{1,5})", text)
            if found and found.group(1) in bind:
                return "blocked_bind"
            return "unexpected"
        return "unexpected"

    def test_lpac_resolve_and_bind_denials_are_accepted_only_on_their_own_stages(self):
        wrapper = self.wrapper
        self.assertIn("$NetworkDeniedHostResolve = @('err11003')", wrapper)
        self.assertIn("$NetworkDeniedBind = @('err10013')", wrapper)
        body = self.function_body("Get-NetworkState")
        self.assertEqual(body.count("return 'blocked_resolve'"), 2)
        self.assertEqual(body.count("return 'blocked_bind'"), 1)
        self.assertEqual(body.count("$NetworkDeniedHostResolve -ccontains"), 2)
        self.assertEqual(body.count("$NetworkDeniedBind -ccontains"), 1)
        self.assertIn("'^bind=(err[0-9]{1,5})$'", body)
        specs = self.function_body("Get-StageSpecs")
        confined, control = specs.split("} else {", 1)
        accepted = {
            "network_tcp_host": ("connect", "@('blocked', 'blocked_resolve')"),
            "network_dns": ("dns", "@('blocked', 'blocked_resolve')"),
            "network_udp": ("udp", "@('blocked', 'blocked_bind')"),
        }
        for stage in ("network_tcp_ipv4", "network_tcp_ipv6", "network_tcp_host", "network_dns", "network_udp"):
            line = re.search(r"Name = '" + stage + r"'.*", confined).group(0)
            with self.subTest(stage=stage):
                if stage in accepted:
                    kind, states = accepted[stage]
                    self.assertIn("(Get-NetworkState $r.Stdout '" + kind + "') -cin " + states, line)
                else:
                    self.assertNotIn("blocked_", line)
        self.assertNotIn("blocked_", control)
        self.assertEqual(wrapper.count("'blocked_resolve'"), 4)
        self.assertEqual(wrapper.count("'blocked_bind'"), 2)
        for stage in ("network_control", "network_control_ipv6", "network_control_dns", "network_control_udp"):
            line = re.search(r"Name = '" + stage + r"'.*", control).group(0)
            with self.subTest(control=stage):
                self.assertNotIn("blocked", line)
        self.assertIn("if ($networkDenied -and $networkControls) { $observed['network'] = 'blocked' }", wrapper)
        self.assertIn("if ($networkDenied -and -not $networkControls) { $observed['network'] = 'inconclusive' }", wrapper)
        self.assertIn("if (($ipv6Control -ceq 'open') -and ($ipv6Confined -ceq 'blocked')) { $observed['ipv6'] = 'blocked' }", wrapper)

    def test_network_state_model_accepts_the_observed_lpac_denials_and_refuses_near_misses(self):
        model = self.network_state_model
        self.assertEqual(model("resolve=err11003", "connect"), "blocked_resolve")
        self.assertEqual(model("resolve=err11003", "dns"), "blocked_resolve")
        self.assertEqual(model("bind=err10013", "udp"), "blocked_bind")
        self.assertEqual(model("resolve=ok connect=err10013", "connect"), "blocked")
        self.assertEqual(model("resolve=err11001", "dns"), "blocked")
        self.assertEqual(model("send=err10013", "udp"), "blocked")
        for text, kind in (
            ("resolve=err11003 connect=open", "connect"),
            ("resolve=ok connect=err11003", "connect"),
            ("resolve=err11004", "connect"),
            ("resolve=err11004", "dns"),
            ("resolve=ERR11003", "dns"),
            ("resolve=err110031", "dns"),
            ("resolve=ok count=0", "dns"),
            ("bind=err11001", "udp"),
            ("bind=err11003", "udp"),
            ("bind=err10048", "udp"),
            ("bind=err10013 send=ok", "udp"),
            ("bind=err10013", "connect"),
            ("bind=err10013", "dns"),
            ("send=err11003", "udp"),
            ("resolve=err11003", "udp"),
            ("bind=", "udp"),
            ("bind=err", "udp"),
        ):
            with self.subTest(text=text, kind=kind):
                self.assertEqual(model(text, kind), "unexpected")
        for text, kind in (
            ("resolve=err11003", "connect"),
            ("resolve=err11003", "dns"),
            ("bind=err10013", "udp"),
        ):
            with self.subTest(control=text, kind=kind):
                self.assertNotEqual(model(text, kind), "open")

    def test_network_controls_are_unconfined_and_must_be_open(self):
        specs = self.function_body("Get-StageSpecs")
        confined, control = specs.split("} else {", 1)
        control = control.split("    }\n    $specs +=", 1)[0]
        expected = (
            ("network_control", "connect", "connect 1.1.1.1:443"),
            ("network_control_ipv6", "connect", "connect [2606:4700:4700::1111]:443"),
            ("network_control_dns", "dns", "dns github.com"),
            ("network_control_udp", "udp", "udp 1.1.1.1:53"),
        )
        for stage, kind, arguments in expected:
            line = re.search(r"Name = '" + stage + r"'.*", control).group(0)
            with self.subTest(stage=stage):
                self.assertIn("Arguments = '" + arguments + "'", line)
                if stage == "network_control_ipv6":
                    self.assertIn("(Get-NetworkState $r.Stdout 'connect') -cin @('open', 'unroutable')", line)
                else:
                    self.assertIn("(Get-NetworkState $r.Stdout '" + kind + "') -ceq 'open'", line)
                self.assertNotIn(stage, confined)
        self.assertIn("$networkControls = Test-Passed $controlOutcomes @('network_control', 'network_control_ipv6', 'network_control_dns', 'network_control_udp')", self.wrapper)
        self.assertIn("if ($networkDenied -and $networkControls) { $observed['network'] = 'blocked' }", self.wrapper)
        self.assertIn("if ($networkDenied -and -not $networkControls) { $observed['network'] = 'inconclusive' }", self.wrapper)
        for required in (
            "if ((Test-Passed $controlOutcomes @('network_control_ipv6'))) { $ipv6Control = Get-NetworkState $controlOutcomes['network_control_ipv6'].Stdout 'connect' }",
            "if ((Test-Passed $confinedOutcomes @('network_tcp_ipv6'))) { $ipv6Confined = Get-NetworkState $confinedOutcomes['network_tcp_ipv6'].Stdout 'connect' }",
            "if (($ipv6Control -ceq 'open') -and ($ipv6Confined -ceq 'blocked')) { $observed['ipv6'] = 'blocked' }",
            "if (($ipv6Control -ceq 'unroutable') -and ($ipv6Confined -cin @('blocked', 'unroutable'))) { $observed['ipv6'] = 'not_applicable' }",
            "-and -not (($ipv6Control -ceq 'open') -and ($ipv6Confined -ceq 'unroutable'))",
            "ipv6 = 'blocked'; ipv6_control = 'open'",
            "if ($observed['ipv6'] -ceq 'not_applicable') { $expectedTokens['ipv6'] = 'not_applicable'; $expectedTokens['ipv6_control'] = 'unroutable' }",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.wrapper)

    def test_ipv6_summary_keys_and_not_applicable_pair_are_consistent(self):
        found = re.search(r"\$expectedTokens = \[ordered\]@\{ (.+) \}\n", self.wrapper)
        self.assertIsNotNone(found)
        keys = [key for key, _ in re.findall(r"([a-z_0-9]+) = '([A-Za-z_]+)'", found.group(1))]
        self.assertNotIn("control", keys)
        self.assertEqual(keys.index("ipv6_control"), keys.index("ipv6") + 1)
        self.assertEqual(keys.index("ipv6"), keys.index("network") + 1)
        self.assertNotIn("$observed['control']", self.wrapper)
        self.assertNotIn("$expectedTokens['control']", self.wrapper)
        self.assertIn("if ($ipv6Control -ceq 'unroutable') { $observed['ipv6_control'] = 'unroutable' }", self.wrapper)
        self.assertIn("if ($ipv6Control -ceq 'open') { $observed['ipv6_control'] = 'open' }", self.wrapper)
        self.assertIn("$observed['ipv6_control'] = 'failed'", self.wrapper)
        self.assertEqual(
            self.wrapper.count("$expectedTokens['ipv6'] = 'not_applicable'; $expectedTokens['ipv6_control'] = 'unroutable'"),
            1,
        )

    def test_dns_denial_code_is_tied_to_names_the_unconfined_control_resolved(self):
        specs = self.function_body("Get-StageSpecs")
        confined, control = specs.split("} else {", 1)
        control = control.split("    }\n    $specs +=", 1)[0]
        control_names = set(re.findall(r"Arguments = 'dns ([^' ]+)'", control))
        self.assertEqual(control_names, {"github.com"})
        confined_dns = re.findall(r"Arguments = 'dns ([^' ]+)'", confined)
        self.assertEqual(confined_dns, ["github.com"])
        confined_hosts = re.findall(r"Arguments = 'connect ([A-Za-z][^' :]*):[0-9]+'", confined)
        self.assertEqual(confined_hosts, ["github.com"])
        for name in confined_dns + confined_hosts:
            self.assertIn(name, control_names)
        self.assertIn("$NetworkDeniedResolve = @('err10013', 'err11001')", self.wrapper)
        self.assertEqual(self.wrapper.count("$NetworkDeniedResolve -ccontains"), 2)
        self.assertNotIn("registry.npmjs.org:443", specs)

    def test_lease_ace_check_pins_type_flags_and_size(self):
        start = self.native.index("private bool IsLeaseAce")
        body = self.native[start:self.native.index("private void WriteOriginal")]
        for required in (
            "ace[0] != 0 || ace[1] != 0",
            "int sidLength = 8 + (ace[9] * 4);",
            "BitConverter.ToUInt16(ace, 2) != ace.Length || ace.Length != 8 + sidLength",
            "BitConverter.ToUInt32(ace, 4) == LeaseMask",
            "string.Equals(SidText(ace, 8), packageSid, StringComparison.Ordinal)",
        ):
            with self.subTest(required=required):
                self.assertIn(required, body)

    def test_a_second_distinct_container_must_be_denied_on_nul_after_the_grant(self):
        body = self.function_body("Test-OtherContainerNul")
        for required in (
            "[KeelDock.Platform.WindowsConfinement.Sandbox]::Create()",
            "-ceq [string]$script:Sid",
            "throw 'nul_other_not_distinct'",
            "throw 'nul_other_control'",
            "throw 'nul_other_launch'",
            "throw 'nul_other_not_denied'",
            "-cnotmatch 'Access is denied'",
            "windows-confinement-nul-other=denied container=distinct error=5 control=granted",
        ):
            with self.subTest(required=required):
                self.assertIn(required, body)
        self.assertLess(body.index("$first.Run("), body.index("$other.Run("))
        self.assertIn("$phase = 'nul_other_container'\n        Test-OtherContainerNul $box", self.wrapper)
        opened = self.wrapper.index("NullDeviceLease]::Open($script:Sid)")
        other = self.wrapper.index("Test-OtherContainerNul $box")
        confined = self.wrapper.index("$confinedOutcomes = Invoke-Ladder $box $true $script:Lpac")
        self.assertLess(opened, other)
        self.assertLess(other, confined)
        tail = self.wrapper[self.wrapper.index("$nullRestore = 'not_applied'"):]
        self.assertLess(tail.index("$script:NullLease.Restore()"), tail.index("$script:OtherBox.Dispose()"))
        self.assertLess(tail.index("$script:OtherBox.Dispose()"), tail.index("Remove-TreeNoFollow $baseDirectory"))

    def test_temp_probe_failure_prints_a_closed_reason(self):
        body = self.function_body("Initialize-ContainerTemp")
        for required in (
            "$probeReason = 'probe_exit'",
            "$probeReason = 'probe_launch'",
            "$probeReason = 'probe_not_exited'",
            "$probeReason = 'probe_timeout'",
            "windows-confinement-temp=failed reason=' + $probeReason",
            "throw $probeReason",
        ):
            with self.subTest(required=required):
                self.assertIn(required, body)
        self.assertNotIn("throw 'probe'", body)

    NETWORK_CASES = (
        ("resolve=ok connect=open", "connect"),
        ("resolve=ok connect=err10013", "connect"),
        ("resolve=ok connect=err10051", "connect"),
        ("resolve=ok connect=err10047", "connect"),
        ("resolve=ok connect=err10061", "connect"),
        ("resolve=err11003", "connect"),
        ("resolve=err11001", "connect"),
        ("resolve=err10013", "connect"),
        ("resolve=err11004", "connect"),
        ("resolve=empty", "connect"),
        ("resolve=err11003 connect=open", "connect"),
        ("resolve=ok connect=err11003", "connect"),
        ("wsa=failed", "connect"),
        ("", "connect"),
        ("resolve=ok count=3", "dns"),
        ("resolve=ok count=0", "dns"),
        ("resolve=err11003", "dns"),
        ("resolve=err11001", "dns"),
        ("resolve=err10013", "dns"),
        ("resolve=err11004", "dns"),
        ("resolve=ERR11003", "dns"),
        ("resolve=err110031", "dns"),
        ("send=ok recv=data", "udp"),
        ("send=err10013", "udp"),
        ("send=err11003", "udp"),
        ("bind=err10013", "udp"),
        ("bind=err10013 send=ok", "udp"),
        ("bind=err10048", "udp"),
        ("bind=err11003", "udp"),
        ("bind=", "udp"),
        ("bind=err", "udp"),
        ("resolve=err11003", "udp"),
        ("bind=err10013", "connect"),
        ("bind=err10013", "dns"),
    )

    def write_pwsh_script(self, directory, body):
        path = Path(directory) / "check.ps1"
        path.write_text(body, encoding="utf-8")
        return path

    def run_pwsh(self, body, timeout=180):
        import tempfile

        with tempfile.TemporaryDirectory() as directory:
            path = self.write_pwsh_script(directory, body)
            result = subprocess.run(
                ["pwsh", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", str(path)],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result.stdout

    def top_level_line(self, name):
        found = re.search(r"^\$" + re.escape(name) + r" = .*$", self.wrapper, re.M)
        self.assertIsNotNone(found, name)
        return found.group(0)

    def test_network_state_model_is_tied_to_the_wrapper_by_running_the_extracted_functions(self):
        if shutil.which("pwsh") is None:
            self.skipTest("pwsh is not available")
        lines = [self.top_level_line(name) for name in (
            "NetworkDeniedConnect",
            "NetworkDeniedResolve",
            "NetworkDeniedUdp",
            "NetworkDeniedHostResolve",
            "NetworkDeniedBind",
            "NetworkUnroutableConnect",
        )]
        cases = ",\n".join(
            "    @('" + kind + "', '" + text + "')" for text, kind in self.NETWORK_CASES
        )
        body = (
            "$ErrorActionPreference = 'Stop'\n"
            + "\n".join(lines)
            + "\n"
            + self.function_body("Get-ProbeText")
            + "\n"
            + self.function_body("Get-NetworkState")
            + "\n$cases = @(\n"
            + cases
            + "\n)\n"
            + "foreach ($case in $cases) {\n"
            + "    $stdout = 'kd-probe ' + $case[0] + ' ' + $case[1]\n"
            + "    Write-Output ($case[0] + '|' + $case[1] + '|' + (Get-NetworkState $stdout $case[0]))\n"
            + "}\n"
        )
        output = self.run_pwsh(body)
        rows = [line.split("|") for line in output.splitlines() if line.count("|") == 2]
        self.assertEqual(len(rows), len(self.NETWORK_CASES))
        for (text, kind), (row_kind, row_text, state) in zip(self.NETWORK_CASES, rows):
            with self.subTest(text=text, kind=kind):
                self.assertEqual((row_kind, row_text), (kind, text))
                self.assertEqual(state, self.network_state_model(text.strip(), kind))
        trimmed = {(row[0], row[1]): row[2] for row in rows}
        self.assertEqual(trimmed[("dns", "resolve=ERR11003")], "unexpected")
        self.assertEqual(trimmed[("dns", "resolve=err11003")], "blocked_resolve")
        self.assertEqual(trimmed[("udp", "bind=err10013")], "blocked_bind")

    def test_trailing_space_is_trimmed_by_the_wrapper_before_classification(self):
        self.assertIn("$trimmed = $line.Trim()", self.function_body("Get-ProbeText"))
        self.assertEqual(self.network_state_model("resolve=err11003".strip(), "dns"), "blocked_resolve")

    BANK = {
        "connect": ("resolve=ok connect=open", "resolve=ok connect=err10013", "resolve=ok connect=err10061", "resolve=ok connect=err10060", "resolve=ok connect=err10051", "resolve=err11003", "resolve=err11001", "resolve=err10013", "resolve=empty", "wsa=failed", ""),
        "dns": ("resolve=ok count=2", "resolve=ok count=0", "resolve=err11003", "resolve=err11001", "resolve=err11004", "resolve=err10013", "wsa=failed"),
        "udp": ("send=ok recv=data", "send=ok recv=err10060", "send=err10013", "bind=err10013", "bind=err10048", "wsa=failed"),
        "envhunt": ("found=0", "found=1", "found=12", "found=usage", "found="),
        "pipemake": ("create=ok", "create=err5", "create=err2", "create=err231", "create=usage"),
        "pipeopen": ("open=ok", "open=err5", "open=err2", "open=err231", "open=usage"),
        "procopen": ("open=ok", "open=err5", "open=err87", "open=usage"),
        "echo": ("result=ok", "result=fail", "result=usage"),
        "conout": ("open=ok", "open=err5", "open=err6", "open=err2", "open=err3", "open=err87"),
        "eventlog": ("open=ok", "open=err5", "open=err1722"),
        "write": ("create=ok write=ok", "create=err5", "create=err80", "create=ok write=err5"),
        "read": ("open=ok read=ok bytes=36", "open=ok read=ok bytes=0", "open=err5", "open=err2", "open=err3", "open=err32", "open=ok read=err5"),
        "append": ("open=ok", "open=err5", "open=err2", "open=err32"),
        "list": ("list=ok count=3", "list=err5", "list=err2"),
        "regread": ("open=ok", "open=err5", "open=err2"),
        "regcreate": ("create=ok", "create=err5", "create=err1314"),
        "walk": ("scanned=10 found=0", "scanned=10 found=1", "scanned=0 found=usage", "scanned=x found=1"),
        "jobbreak": ("spawn=ok", "spawn=err5", "spawn=err2"),
        "jobmember": ("injob=yes", "injob=no", "injob=err87"),
        "profile": ("create=ok", "create=hr80070005", "create=hr800706d9", "create=hr800700b7", "create=hr80070057"),
        "scm": ("open=ok", "open=err5", "open=err1722"),
        "nuldac": ("result=ok", "result=err5", "result=err2"),
        "dacopen": ("open=ok", "open=err5", "open=err2"),
        "symlink": ("create=ok", "create=err5", "create=err1314", "create=err183"),
        "hardlink": ("create=ok", "create=err5", "create=err1314", "create=err183", "create=err17"),
        "tokenraise": ("open=ok set=ok", "open=ok set=err5", "open=ok set=err1314", "open=err5 set=na", "open=err87 set=na", "open=ok set=err87"),
        "tokenpriv": ("adjust=ok", "adjust=err5", "adjust=err1300", "adjust=err87", "adjust=err6", "open=err5", "open=err6"),
        "taskreg": ("create=ok connect=ok", "create=ok connect=hr80070005", "create=ok connect=hr800706d9", "create=hr80040154", "create=ok connect=hr80041003"),
        "wmi": ("create=ok connect=ok", "create=ok connect=hr80070005", "create=ok connect=hr80041003", "create=hr80040154", "create=ok connect=hr800706ba"),
        "wfp": ("open=ok", "open=err5", "open=err1722", "open=err1062"),
        "procpeer": ("open=ok", "open=err5", "open=err87", "spawn=err5", "spawn=err2"),
    }

    def attempt_model(self, line, text):
        allow = re.search(r"(?<![A-Za-z])Allow = '([^']*)'", line).group(1)
        confined = re.search(r"ConfinedAllow = '([^']*)'", line)
        if confined:
            allow = confined.group(1)
        deny = re.search(r"Deny = '([^']*)'", line).group(1)
        expect = re.search(r"Expect = '([a-z]+)'", line).group(1)
        if not text:
            return "other"
        if re.search(allow, text):
            return "allowed"
        if re.search(deny, text):
            return "contained" if expect == "contained" else "denied"
        na = re.search(r"NaPattern = '([^']*)'", line)
        if na and re.search(na.group(1), text):
            return "not_applicable"
        return "other"

    def test_attempt_classifier_matches_the_python_model_for_every_attempt_under_pwsh(self):
        if shutil.which("pwsh") is None:
            self.skipTest("pwsh is not available")
        bank = ",\n".join(
            "    @('" + command + "', '" + text + "')"
            for command, texts in self.BANK.items()
            for text in texts
        )
        body = (
            "$ErrorActionPreference = 'Stop'\n"
            "$script:Redactions = @()\n"
            + self.function_body("Get-CleanText")
            + "\n"
            + self.function_body("Get-ProbeText")
            + "\n"
            + self.function_body("Get-TextClass")
            + "\n"
            + self.function_body("Get-AttemptResult")
            + "\n"
            + self.function_body("Get-ChannelAttempts")
            + "\n$bank = @(\n"
            + bank
            + "\n)\n"
            + "foreach ($attempt in (Get-ChannelAttempts)) {\n"
            + "    if ($attempt.ContainsKey('Marker')) { continue }\n"
            + "    $command = ($attempt.Runs[0] -split ' ')[0]\n"
            + "    foreach ($entry in $bank) {\n"
            + "        if ($entry[0] -cne $command) { continue }\n"
            + "        $run = @{ Stdout = ('kd-probe ' + $command + ' ' + $entry[1]) }\n"
            + "        Write-Output ($attempt.Channel + '/' + $attempt.Name + '|' + $entry[1] + '|' + (Get-AttemptResult $run $command $attempt))\n"
            + "    }\n"
            + "}\n"
        )
        output = self.run_pwsh(body)
        rows = [line.split("|") for line in output.splitlines() if line.count("|") == 2]
        lines = {}
        for line in self.channel_attempt_lines():
            if "Marker = $true" in line:
                continue
            channel = re.search(r"Channel = '([a-z_]+)'", line).group(1)
            name = re.search(r"Name = '([a-z0-9-]+)'", line).group(1)
            lines[channel + "/" + name] = line
        expected_rows = sum(len(self.BANK.get(re.findall(r"'([^']*)'", self.channel_field(line, "Runs"))[0].split(" ")[0], ())) for line in lines.values())
        self.assertEqual(len(rows), expected_rows)
        self.assertGreater(len(rows), 200)
        results = {}
        for key, text, result in rows:
            with self.subTest(attempt=key, text=text):
                self.assertEqual(result, self.attempt_model(lines[key], text))
            results[(key, text)] = result
        self.assertEqual(results[("boundary_disablement/symlink", "create=err1314")], "denied")
        self.assertEqual(results[("boundary_disablement/symlink", "create=err183")], "other")
        self.assertEqual(results[("boundary_disablement/privilege-enable", "adjust=err1300")], "denied")
        self.assertEqual(results[("boundary_disablement/privilege-enable", "adjust=ok")], "allowed")
        self.assertEqual(results[("runner_files/bounded-walk", "scanned=10 found=0")], "contained")
        self.assertEqual(results[("runner_files/bounded-walk", "scanned=10 found=1")], "allowed")
        self.assertEqual(results[("dns/unique-name", "resolve=err11001")], "other")
        self.assertEqual(results[("dns/getaddrinfo", "resolve=err11003")], "denied")
        self.assertEqual(results[("runner_ipc/pipe-root-create", "create=err5")], "denied")
        self.assertEqual(results[("runner_ipc/pipe-root-create", "create=err231")], "other")
        self.assertEqual(results[("process_memory/control-peer-memory", "open=ok")], "allowed")
        self.assertEqual(results[("process_memory/control-peer-memory", "open=err5")], "not_applicable")
        self.assertEqual(results[("process_memory/control-peer-memory", "spawn=err5")], "other")
        self.assertEqual(results[("boundary_disablement/task-register", "create=ok connect=ok")], "allowed")
        self.assertEqual(results[("boundary_disablement/task-register", "create=ok connect=hr80070005")], "denied")
        self.assertEqual(results[("boundary_disablement/task-register", "create=ok connect=hr800706d9")], "other")
        self.assertEqual(results[("boundary_disablement/task-register", "create=hr80040154")], "other")
        self.assertEqual(results[("boundary_disablement/wmi", "create=ok connect=hr80041003")], "denied")
        self.assertEqual(results[("boundary_disablement/wmi", "create=ok connect=hr800706ba")], "other")
        self.assertEqual(results[("boundary_disablement/wfp", "open=err5")], "denied")
        self.assertEqual(results[("boundary_disablement/wfp", "open=err1722")], "other")
        self.assertEqual(results[("boundary_disablement/wfp", "open=ok")], "allowed")
        self.assertEqual(results[("boundary_disablement/profile-create", "create=ok")], "allowed")

    def test_expansion_of_channel_runs_skips_unresolved_placeholders_under_pwsh(self):
        if shutil.which("pwsh") is None:
            self.skipTest("pwsh is not available")
        body = (
            "$ErrorActionPreference = 'Stop'\n"
            + self.function_body("Expand-ChannelRun")
            + "\n"
            "$script:Channel = @{ Pids = @(11, 22); RunnerPipes = @(); Drives = @('C:\\', 'D:\\'); Scalars = @{ port = '4242'; diag_file = ''; needle = 'abc' } }\n"
            "foreach ($template in @('procopen {pid} dup', 'pipeopen {runner_pipe}', 'walk {drive} 150 {needle}', 'read {diag_file}', 'connect 127.0.0.1:{port}', 'pipeopen {pipe}', 'read {unknown}', 'echo')) {\n"
            "    $items = @(Expand-ChannelRun $template)\n"
            "    Write-Output ($template + '|' + $items.Count + '|' + ($items -join ';'))\n"
            "}\n"
        )
        output = self.run_pwsh(body)
        rows = {line.split("|")[0]: line.split("|")[1:] for line in output.splitlines() if line.count("|") == 2}
        self.assertEqual(rows["procopen {pid} dup"], ["2", "procopen 11 dup;procopen 22 dup"])
        self.assertEqual(rows["pipeopen {runner_pipe}"][0], "0")
        self.assertEqual(rows["walk {drive} 150 {needle}"], ["2", "walk C:\\ 150 abc;walk D:\\ 150 abc"])
        self.assertEqual(rows["read {diag_file}"][0], "0")
        self.assertEqual(rows["connect 127.0.0.1:{port}"], ["1", "connect 127.0.0.1:4242"])
        self.assertEqual(rows["pipeopen {pipe}"], ["1", "pipeopen {pipe}"])
        self.assertEqual(rows["read {unknown}"][0], "0")
        self.assertEqual(rows["echo"], ["1", "echo"])

    def test_channel_table_mirrors_the_linux_channel_set_and_pins_every_attempt(self):
        self.assertEqual(len(LINUX_CHANNELS), 11)
        found = re.search(r"^\$ChannelNames = @\((.*)\)$", self.wrapper, re.M)
        self.assertIsNotNone(found)
        self.assertEqual(tuple(re.findall(r"'([a-z_]+)'", found.group(1))), tuple(LINUX_CHANNELS))
        self.assertEqual(tuple(CHANNEL_ATTEMPTS), tuple(LINUX_CHANNELS))
        seen = {}
        for line in self.channel_attempt_lines():
            channel = re.search(r"Channel = '([a-z_]+)'", line).group(1)
            name = re.search(r"Name = '([a-z0-9-]+)'", line).group(1)
            seen.setdefault(channel, []).append(name)
        self.assertEqual({key: tuple(value) for key, value in seen.items()}, CHANNEL_ATTEMPTS)
        for line in self.channel_attempt_lines():
            with self.subTest(line=line.strip()[:70]):
                self.assertTrue(line.rstrip().endswith("}"))
                self.assertTrue(line.isascii())
                self.assertIsNone(re.search(r"\b(?:Remove|Set|Grant)-", line))

    def test_every_attempt_has_a_closed_narrow_denial_rule_and_a_control(self):
        no_codes = {
            "proxy-env-http",
            "env-hunt",
            "bounded-walk",
            "walk-control-scratch",
            "handle-inventory",
            "stdout-markers",
            "job-membership",
            "control-peer-memory",
        }
        no_control = {
            "pipe-runner-open",
            "handle-inventory",
            "named-pipe-local",
            "walk-control-scratch",
            "control-self-memory",
            "job-breakaway",
            "nul-write-dac",
        }
        expect_allowed = {"named-pipe-local", "walk-control-scratch", "control-self-memory", "control-peer-memory"}

        def denial_codes(pattern):
            codes = {"err" + value for value in re.findall(r"err([0-9]+)", pattern)}
            for group in re.findall(r"err\(([0-9|]+)\)", pattern):
                codes.update("err" + item for item in group.split("|"))
            codes.update(re.findall(r"hr[0-9a-f]{8}", pattern))
            return codes

        without_control = set()
        for line in self.channel_attempt_lines():
            name = re.search(r"Name = '([a-z0-9-]+)'", line).group(1)
            expect = re.search(r"Expect = '([a-z]+)'", line).group(1)
            allow = re.search(r"(?<![A-Za-z])Allow = '([^']*)'", line).group(1)
            deny = re.search(r"Deny = '([^']*)'", line).group(1)
            with self.subTest(attempt=name):
                self.assertIn(expect, ("denied", "contained", "allowed"))
                self.assertEqual(expect == "allowed", name in expect_allowed)
                for pattern in (allow, deny):
                    for piece in re.sub(r"\([^)]*\)", "G", pattern).split("|"):
                        self.assertTrue(piece.startswith("^") and piece.endswith("$"), pattern)
                codes = denial_codes(deny)
                self.assertLessEqual(codes, DENIAL_CODES)
                if not codes:
                    self.assertIn(name, no_codes)
                self.assertFalse(denial_codes(allow))
                runs = re.findall(r"'([^']*)'", self.channel_field(line, "Runs"))
                self.assertTrue(runs)
                for run in runs:
                    self.assertIn(run.split(" ")[0], PROBE_COMMANDS)
                controls = re.findall(r"'([^']*)'", self.channel_field(line, "ControlRuns"))
                if not controls:
                    without_control.add(name)
                for control in controls:
                    self.assertIn(control.split(" ")[0], PROBE_COMMANDS)
        self.assertEqual(without_control, no_control)
        for channel, names in CHANNEL_ATTEMPTS.items():
            controlled = [
                line
                for line in self.channel_attempt_lines()
                if "Channel = '" + channel + "'" in line and self.channel_field(line, "ControlRuns") != "@()"
            ]
            with self.subTest(channel=channel):
                self.assertTrue(controlled)

    def test_network_channel_attempts_pair_each_name_with_an_identical_unconfined_control(self):
        for line in self.channel_attempt_lines():
            channel = re.search(r"Channel = '([a-z_]+)'", line).group(1)
            if channel not in ("https", "dns", "redirect", "proxy", "artifact_upload", "cache_upload"):
                continue
            if "Name = 'env-hunt'" in line or "Name = 'staging-write'" in line or "Name = 'cache-write'" in line:
                continue
            with self.subTest(line=line.strip()[:60]):
                self.assertEqual(self.channel_field(line, "Runs"), self.channel_field(line, "ControlRuns"))
        unique = next(line for line in self.channel_attempt_lines() if "Name = 'unique-name'" in line)
        self.assertIn("ControlAllow = '^resolve=err(11001|11004)$'", unique)
        self.assertNotIn("11001", re.search(r"Deny = '([^']*)'", unique).group(1))
        wrapper = self.wrapper
        self.assertIn("'ACTIONS_RUNTIME_TOKEN=kd-sentinel'", wrapper)
        self.assertIn("'HTTPS_PROXY=kd-sentinel'", wrapper)
        for line in self.channel_attempt_lines():
            if "envhunt" in line:
                with self.subTest(line=line.strip()[:60]):
                    self.assertIn("ControlEnvironment = $true", line)

    def test_channel_suite_runs_before_and_after_the_ladder_and_dns_is_rechecked(self):
        wrapper = self.wrapper
        order = (
            "$phase = 'channel_fixtures'",
            "$controlOutcomes = Invoke-Ladder $box $false $script:Control",
            "$phase = 'channels_before'",
            "$channelsBefore = Invoke-ChannelPhase $box 'selftest' $true",
            "$confinedOutcomes = Invoke-Ladder $box $true $script:Lpac",
            "$phase = 'channels_after'",
            "$channelsAfter = Invoke-ChannelPhase $box 'recheck' $false",
            "$dnsAfterOutcomes = Invoke-Ladder $box $false $script:Control @('network_control_dns') '_after'",
            "$phase = 'cleanup_links'\n        Initialize-LinkFixtures\n",
            "$firstFailure = 'none'",
        )
        positions = [wrapper.index(item) for item in order]
        self.assertEqual(positions, sorted(positions))
        self.assertLess(wrapper.index("Test-OtherContainerNul $box"), wrapper.index("$channelsBefore = "))
        self.assertIn("if ($dnsAfter -cne 'open') { $networkControls = $false }", wrapper)
        self.assertIn("if (Test-Passed $dnsAfterOutcomes @('network_control_dns')) { $dnsAfter = 'open' }", wrapper)
        self.assertIn("$observed['dns_after'] = $dnsAfter", wrapper)
        self.assertLess(wrapper.index("$dnsAfter = 'failed'"), wrapper.index("if ($networkDenied -and $networkControls)"))
        ladder = self.function_body("Invoke-Ladder")
        self.assertIn("[string[]]$only = @()", ladder.splitlines()[0])
        self.assertIn("[string]$suffix = ''", ladder.splitlines()[0])
        self.assertIn("if ($only.Count -gt 0 -and ($only -cnotcontains $spec.Name)) { continue }", ladder)
        self.assertIn("$spec.Name + $suffix + ' confined='", ladder)
        specs = self.function_body("Get-StageSpecs")
        control_branch = specs.split("} else {", 1)[1]
        self.assertIn("Name = 'network_control_dns'", control_branch)
        self.assertEqual(wrapper.count("Invoke-Ladder $box $false $script:Control"), 2)

    def test_channel_reports_are_fixed_lines_and_informational_attempts_never_gate(self):
        phase = self.function_body("Invoke-ChannelPhase")
        for required in (
            "windows-confinement-attempt='",
            "windows-confinement-channel='",
            "' status=' + $entry.Status",
            "$entry.Status = 'observed-leak'",
            "$entry.Status = 'refused'",
            "$entry.Reason = 'fixture_incomplete'",
        ):
            with self.subTest(required=required):
                self.assertIn(required, phase)
        self.assertLess(phase.index("if ($informational) {"), phase.index("$entry.Attempts += 1"))
        attempt = self.function_body("Invoke-ChannelAttempt")
        for reason in ("control_not_fired", "channel_leak", "attempt_unexpected", "attempt_incomplete", "fixture_incomplete"):
            with self.subTest(reason=reason):
                self.assertIn("'" + reason + "'", attempt)
        self.assertIn("$outcome.Result = 'not_applicable'", attempt)
        self.assertIn("if ($controlRuns -eq 0) {", attempt)
        self.assertLess(attempt.index("Invoke-ChannelRun $sandbox $false"), attempt.index("Invoke-ChannelRun $sandbox $true"))
        run = self.function_body("Invoke-ChannelRun")
        self.assertIn("$sandbox.Run($confined,", run)
        self.assertIn("finally {", run)
        valid = self.function_body("Test-ChannelRunValid")
        for required in ("$run.TimedOut", "$run.ExitCode -ne 0", "[uint32]$run.HandleCount -ne 3", "Test-LpacTokenText $tokenText", "-like 'assigned,*'"):
            with self.subTest(required=required):
                self.assertIn(required, valid)
        ladder = self.function_body("Invoke-Ladder")
        proof = re.search(r"^ *\$lpacProven = (.+)$", ladder, re.M).group(1)
        helper = self.function_body("Test-LpacTokenText")
        self.assertEqual(
            re.findall(r"\$tokenText -like '([^']+)'", proof),
            re.findall(r"\$tokenText -like '([^']+)'", helper),
        )

    def test_channel_fixtures_add_no_acl_and_use_a_user_only_pipe(self):
        pipe = self.function_body("New-TrustedPipe")
        self.assertEqual(pipe.count("AddAccessRule"), 1)
        for required in ("WindowsIdentity]::GetCurrent().User", "PipeAccessRights]::FullControl", "NamedPipeServerStreamAcl]::Create"):
            with self.subTest(required=required):
                self.assertIn(required, pipe)
        for forbidden in ("S-1-15-2", "S-1-1-0", "WorldSid", "Everyone", "AuthenticatedUser", "AnonymousSid"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, pipe)
        context = self.function_body("Initialize-ChannelContext")
        for forbidden in ("SetAccessControl", "Set-Acl", "Grant-Access", "Grant-NonPropagating", "icacls", "AddAccessRule"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, context)
        self.assertEqual(context.count("New-RegistryCanary $hive"), 1)
        self.assertEqual(self.function_body("New-RegistryCanary").count("$hive.CreateSubKey($path)"), 1)
        self.assertIn("$path = 'Software\\KeelDock\\Canary'", self.function_body("New-RegistryCanary"))
        self.assertIn("[Microsoft.Win32.Registry]::CurrentUser, [Microsoft.Win32.Registry]::LocalMachine", context)
        removal = self.function_body("Remove-ChannelFixtures")
        self.assertIn("DeleteSubKeyTree('Software\\KeelDock', $false)", removal)
        self.assertIn("'kd-att-*.tmp'", removal)
        self.assertIn("$script:Listener.Stop()", removal)
        self.assertIn("[System.Net.IPAddress]::Loopback, 0", context)
        self.assertIn("Software\\\\KeelDock\\\\Canary", self.probe)
        self.assertIn("Software\\\\KeelDock\\\\Att", self.probe)
        for shape in ("channel_env", "channel_file", "channel_registry", "channel_needle"):
            with self.subTest(shape=shape):
                self.assertIn("throw '" + shape + "'", self.wrapper)
        tail = self.wrapper[self.wrapper.index("$nullRestore = 'not_applied'"):]
        self.assertLess(tail.index("Remove-Canaries"), tail.index("Remove-ChannelFixtures"))
        self.assertLess(tail.index("Remove-ChannelFixtures"), tail.index("$box.Dispose()"))

    def test_registry_canary_has_an_explicit_protected_acl_and_is_read_back(self):
        body = self.function_body("New-RegistryCanary")
        for required in (
            "SetAccessRuleProtection($true, $false)",
            "@('S-1-5-18', 'S-1-5-32-544', [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)",
            "$key.SetAccessControl($security)",
            "GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)",
            "if (-not $readback.AreAccessRulesProtected) { throw 'channel_registry' }",
            "if ($rules.Count -ne $allowed.Count) { throw 'channel_registry' }",
            "$rule.IsInherited",
            "$allowed -cnotcontains $sidText",
            "StartsWith('S-1-15-2-'",
            "StartsWith('S-1-15-3-'",
            "RegistryRights]::FullControl) { throw 'channel_registry' }",
        ):
            with self.subTest(required=required):
                self.assertIn(required, body)
        self.assertEqual(body.count("$security.AddAccessRule($rule)"), 1)
        self.assertLess(body.index("$key.SetAccessControl($security)"), body.index("GetAccessControl("))
        self.assertLess(body.index("$key.SetAccessControl($security)"), body.index("$key.SetValue('canary', $value)"))
        for forbidden in ("S-1-15-2-1'", "S-1-1-0", "AllRestricted"):
            self.assertNotIn(forbidden, body)
        self.assertNotIn("RegistryAccessRule", self.wrapper.replace(body, ""))
        for path in (NATIVE, PROBE, WORKFLOW):
            self.assertNotIn("RegistryAccessRule", path.read_text(encoding="utf-8"))

    def test_cleanup_asserts_the_job_process_lists_are_empty_before_any_removal(self):
        self.assertNotIn("Get-ContainerProcessCount", self.wrapper)
        liveness = self.function_body("Get-JobLiveness")
        for required in ("$sandbox.JobState($waitSeconds * 1000)", "return 'unknown'", "$state = 'alive'"):
            with self.subTest(required=required):
                self.assertIn(required, liveness)
        for forbidden in (".Path", "Test-PathUnder", "ImageName", "Get-Process"):
            self.assertNotIn(forbidden, liveness)
        tail = self.wrapper[self.wrapper.index("$nullRestore = 'not_applied'"):]
        check = tail.index("Get-JobLiveness @($box, $script:OtherBox) 10")
        self.assertLess(check, tail.index("Remove-Canaries"))
        self.assertLess(check, tail.index("Remove-ChannelFixtures"))
        self.assertLess(check, tail.index("Remove-ReparsePoints $script:ProfileFolder"))
        self.assertLess(check, tail.index("Remove-TreeNoFollow $script:ProfileFolder"))
        self.assertLess(check, tail.index("Remove-TreeNoFollow $baseDirectory"))
        self.assertGreaterEqual(tail.count("$processState -eq 'none'"), 5)
        self.assertIn("' processes=' + $processState + ' liveness=job'", tail)
        self.assertIn("if ($processState -ne 'none') { $cleanup = 'incomplete' }", tail)
        self.assertIn("$processState = 'unknown'", tail)
        self.assertEqual(len(re.findall(r"(?m)^try \{\n    Remove-(?:Canaries|ChannelFixtures)\n\} catch \{", tail)), 2)

    def test_native_sandbox_keeps_every_job_handle_and_reports_the_assigned_process_count(self):
        native = self.native
        for required in (
            "private readonly List<IntPtr> retainedJobs",
            "RetainJob(ref job);",
            "public string JobState(int waitMs)",
            "JobObjectBasicProcessIdList = 3",
            "Native.QueryInformationJobObject(job, JobObjectBasicProcessIdList, buffer, (uint)size, out returned)",
            "ErrorMoreData = 234",
            "return Marshal.ReadInt32(buffer, 0);",
            'return alive ? "alive" : "none";',
            'return "unreadable";',
        ):
            with self.subTest(required=required):
                self.assertIn(required, native)
        run = native[native.index("public RunResult Run("):native.index("private static IntPtr CreateJob")]
        self.assertNotIn("CloseOne(ref job);", run)
        self.assertLess(run.index("Native.TerminateJobObject(job, JobKillExitCode);\n                }\n                else if (process"), run.index("RetainJob(ref job);"))
        dispose = native[native.index("public void Dispose()"):native.index("private void RetainJob")]
        self.assertIn("Native.CloseHandle(retained);", dispose)

    def test_hosts_are_current_and_every_not_applicable_path_is_pinned(self):
        wrapper = self.wrapper
        self.assertNotIn("artifactcache", wrapper)
        context = self.function_body("Initialize-ChannelContext")
        self.assertIn("$resultsFromEnv = Get-ChannelHost 'ACTIONS_RESULTS_URL' ''", context)
        self.assertIn("$cacheFromEnv = Get-ChannelHost 'ACTIONS_CACHE_URL' ''", context)
        self.assertIn("$cacheHost = $resultsHost\n    $cacheSource = 'results'", context)
        self.assertIn("$cacheSource = 'env'", context)
        self.assertIn("' results_host=' + $hostSource + ' cache_host=' + $cacheSource + ' results_ip='", context)
        self.assertIn("results-receiver.actions.githubusercontent.com", wrapper)
        self.assertNotIn("throw 'channel_host'", wrapper)
        lines = self.channel_attempt_lines()
        optional = {
            re.search(r"Channel = '([a-z_]+)'; Name = '([a-z0-9-]+)'", line).groups()
            for line in lines
            if "Optional = $true" in line
        }
        self.assertEqual(
            optional,
            {("runner_ipc", "pipe-runner-open"), ("runner_files", "diag-read"), ("cache_upload", "endpoint-post")},
        )
        na = {re.search(r"Name = '([a-z0-9-]+)'", line).group(1) for line in lines if "NaPattern" in line}
        self.assertEqual(na, {"pipe-runner-open", "control-peer-memory"})
        control_na = {
            re.search(r"Name = '([a-z0-9-]+)'", line).group(1)
            for line in lines
            if "ControlNa" in line
        }
        self.assertEqual(control_na, {"tls-ipv6"})
        ipv6 = next(line for line in lines if "Name = 'tls-ipv6'" in line)
        self.assertIn("ControlNa = '^resolve=ok connect=err(10047|10051)$|^resolve=empty$'", ipv6)
        self.assertIn("Deny = '^resolve=ok connect=err10013$'", ipv6)
        attempt = self.function_body("Invoke-ChannelAttempt")
        self.assertIn("$attempt.ContainsKey('ControlNa')", attempt)
        self.assertIn("$outcome.Control = 'na'", attempt)
        pipe = next(line for line in lines if "Name = 'pipe-runner-open'" in line)
        self.assertIn("NaPattern = '^open=err2$'", pipe)
        self.assertNotIn("231", re.search(r"NaPattern = '([^']*)'", pipe).group(1))
        self.assertNotIn("231", re.search(r"Deny = '([^']*)'", pipe).group(1))
        peer = next(line for line in lines if "Name = 'control-peer-memory'" in line)
        self.assertIn("NaPattern = '^open=err5$'", peer)
        self.assertIn("Deny = '^open=never$'", peer)
        self.assertIn("Expect = 'allowed'", peer)
        self.assertIn("$attempt.ContainsKey('NaPattern') -or $optional", attempt)
        self.assertIn("'not_applicable'", self.function_body("Get-TextClass"))

    def test_a_missing_runner_pipe_is_not_applicable_only_while_the_pipe_is_still_absent(self):
        lines = self.channel_attempt_lines()
        rechecked = {
            re.search(r"Name = '([a-z0-9-]+)'", line).group(1)
            for line in lines
            if "NaRecheck" in line
        }
        self.assertEqual(rechecked, {"pipe-runner-open"})
        pipe = next(line for line in lines if "Name = 'pipe-runner-open'" in line)
        self.assertIn("NaRecheck = 'pipe'", pipe)
        attempt = self.function_body("Invoke-ChannelAttempt")
        recheck = (
            "if ($result -ceq 'not_applicable' -and $attempt.ContainsKey('NaRecheck') "
            "-and (Test-PipeListed (($arguments -split ' ')[1]))) { $result = 'other' }"
        )
        self.assertIn(recheck, attempt)
        self.assertLess(attempt.index("Get-AttemptResult $run $command $attempt"), attempt.index(recheck))
        self.assertLess(attempt.index(recheck), attempt.index("$results += $result"))
        listed = self.function_body("Test-PipeListed")
        self.assertIn("[System.IO.Directory]::GetFiles('\\\\.\\pipe\\')", listed)
        self.assertIn("-ceq $leaf", listed)
        self.assertIn("} catch {\n        return $true\n    }", listed)
        self.assertTrue(listed.rstrip().endswith("return $false\n}"))

    def test_a_channel_needs_a_gating_boundary_attempt_that_was_not_skipped(self):
        phase = self.function_body("Invoke-ChannelPhase")
        for required in (
            "NotApplicable = 0; Boundary = 0;",
            "$entry.NotApplicable += 1",
            "elseif ($basis -ceq 'boundary' -and $attempt.Expect -cne 'allowed' -and $outcome.Reason -ceq 'none') {",
            "$entry.Boundary += 1",
            "if ($entry.Boundary -eq 0 -and $entry.Status -ceq 'blocked') {",
            "' not_applicable=' + $entry.NotApplicable + ' boundary=' + $entry.Boundary + ' informational='",
        ):
            with self.subTest(required=required):
                self.assertIn(required, phase)
        self.assertLess(phase.index("if ($informational) {"), phase.index("$entry.Attempts += 1"))
        self.assertLess(phase.index("$entry.Attempts += 1"), phase.index("$entry.NotApplicable += 1"))
        self.assertNotIn("if ($entry.Attempts -eq 0", phase)
        gating = {}
        for line in self.channel_attempt_lines():
            channel = re.search(r"Channel = '([a-z_]+)'", line).group(1)
            if "Informational = $true" in line or "Expect = 'allowed'" in line or "Basis = 'harness'" in line:
                continue
            if "Optional = $true" in line or "NaPattern" in line:
                continue
            gating.setdefault(channel, []).append(re.search(r"Name = '([a-z0-9-]+)'", line).group(1))
        self.assertEqual(set(gating), set(LINUX_CHANNELS))
        for channel, names in gating.items():
            with self.subTest(channel=channel):
                self.assertTrue(names)

    def test_confined_self_deleting_creates_are_leaks_and_controls_stay_exact(self):
        lines = self.channel_attempt_lines()
        pattern = "ConfinedAllow = '^create=ok( delete=(err[0-9]+|hr[0-9a-f]{8}))?$'"
        found = {
            re.search(r"Name = '([a-z0-9-]+)'", line).group(1)
            for line in lines
            if "ConfinedAllow" in line
        }
        self.assertEqual(found, {"profile-create", "hklm-write", "hkcu-write"})
        for line in lines:
            if "ConfinedAllow" in line:
                with self.subTest(line=line.strip()[:70]):
                    self.assertIn(pattern, line)
                    self.assertIn("Allow = '^create=ok$'", line)
                    for text in ("create=ok", "create=ok delete=err5", "create=ok delete=hr80070005"):
                        self.assertEqual(self.attempt_model(line, text), "allowed")
                    for text in ("create=ok delete=", "create=ok delete=errx", "create=ok write=ok"):
                        self.assertNotEqual(self.attempt_model(line, text), "allowed")
        attempt = self.function_body("Invoke-ChannelAttempt")
        self.assertIn("$controlAllow = [string]$attempt.Allow", attempt)
        self.assertNotIn("ConfinedAllow", attempt)
        self.assertIn("ConfinedAllow", self.function_body("Get-TextClass"))

    def test_attempt_results_use_the_not_applicable_spelling_not_the_linux_na_token(self):
        for name in ("Get-TextClass", "Get-AttemptResult", "Invoke-ChannelAttempt"):
            body = self.function_body(name)
            with self.subTest(function=name):
                self.assertNotIn("'na'", body.replace("$outcome.Control = 'na'", ""))
        tokens = set()
        for name in ("Get-TextClass", "Get-AttemptResult", "Invoke-ChannelAttempt"):
            tokens.update(re.findall(r"return '([a-z_]+)'", self.function_body(name)))
            tokens.update(re.findall(r"\$outcome\.Result = '([a-z_]+)'", self.function_body(name)))
        self.assertLessEqual(tokens, {"other", "allowed", "denied", "contained", "not_applicable"})
        self.assertIn("not_applicable", tokens)

    def test_harness_invariants_and_console_attempt_are_labelled_and_never_boundary_evidence(self):
        lines = self.channel_attempt_lines()
        basis = {
            re.search(r"Name = '([a-z0-9-]+)'", line).group(1)
            for line in lines
            if "Basis = 'harness'" in line
        }
        self.assertEqual(basis, {"proxy-env-http", "env-hunt", "stdout-markers", "job-membership"})
        for line in lines:
            if "envhunt" in line:
                self.assertIn("Expect = 'contained'", line)
        informational = {
            re.search(r"Name = '([a-z0-9-]+)'", line).group(1)
            for line in lines
            if "Informational = $true" in line
        }
        self.assertEqual(informational, {"named-pipe-local", "conout-open", "task-register", "wmi", "wfp"})
        leak_guarded = {
            re.search(r"Name = '([a-z0-9-]+)'", line).group(1)
            for line in lines
            if "LeakGuard = $true" in line
        }
        self.assertEqual(leak_guarded, {"task-register", "wmi", "wfp"})
        for line in lines:
            if "LeakGuard" in line:
                self.assertIn("Informational = $true", line)
                self.assertIn("Expect = 'denied'", line)
        self.assertIn("' basis=' + $basis", self.function_body("Invoke-ChannelPhase"))

    def test_probe_buffers_and_deletes_are_exact(self):
        probe = self.probe
        raise_body = probe[probe.index("fn probe_tokenraise"):probe.index("fn probe_tokenpriv")]
        self.assertIn("let mut buffer: [usize; 4]", raise_body)
        self.assertNotIn("[u8; 12]", raise_body)
        self.assertIn("buffer.as_mut_ptr().wrapping_add(2) as usize", raise_body)
        self.assertIn(", 28)", raise_body)
        self.assertGreaterEqual(4 * 8, 28)
        self.assertIn('format!("create=ok delete=hr{:08x}", removed as u32)', probe)
        self.assertIn('format!("create=ok delete=err{}", removed)', probe)

    def test_profile_create_denies_access_denied_and_the_lpac_rpc_endpoint_failure(self):
        line = next(item for item in self.channel_attempt_lines() if "Name = 'profile-create'" in item)
        self.assertIn("Deny = '^create=hr80070005$|^create=hr800706d9$'", line)
        self.assertIn("Allow = '^create=ok$'", line)
        self.assertEqual(self.attempt_model(line, "create=hr800706d9"), "denied")
        self.assertEqual(self.attempt_model(line, "create=hr80070005"), "denied")
        self.assertEqual(self.attempt_model(line, "create=ok"), "allowed")
        self.assertEqual(self.attempt_model(line, "create=hr80070057"), "other")

    def test_tokenpriv_probe_reports_open_failures_separately_and_the_attempt_pins_the_forms(self):
        body = self.probe[self.probe.index("fn probe_tokenpriv"):self.probe.index("fn main")]
        self.assertIn("OpenProcessToken(GetCurrentProcess(), 0x0028, &mut token)", body)
        self.assertIn("if opened == 0 || token == 0", body)
        self.assertIn('format!("open=err{}", last)', body)
        self.assertLess(body.index('format!("open=err{}", last)'), body.index("AdjustTokenPrivileges"))
        self.assertIn("SetLastError(0)", body)
        self.assertIn("let mut state: [u32; 4] = [1, 20, 0, 2];", body)
        self.assertNotIn("LookupPrivilegeValueW", self.probe)
        self.assertIn('String::from("adjust=ok")', body)
        self.assertIn('format!("adjust=err{}", last)', body)
        line = next(item for item in self.channel_attempt_lines() if "Name = 'privilege-enable'" in item)
        self.assertIn("Allow = '^adjust=ok$'", line)
        self.assertIn("Deny = '^adjust=err1300$|^open=err5$'", line)
        for text, result in (
            ("adjust=ok", "allowed"),
            ("adjust=err1300", "denied"),
            ("open=err5", "denied"),
            ("adjust=err6", "other"),
            ("open=err6", "other"),
            ("adjust=err5", "other"),
        ):
            self.assertEqual(self.attempt_model(line, text), result, text)

    def test_pipe_acl_assembly_is_loaded_explicitly_and_the_pipe_works_in_windows_ci(self):
        body = self.function_body("New-TrustedPipe")
        self.assertLess(body.index("Add-Type -AssemblyName System.IO.Pipes.AccessControl"), body.index("New-Object System.IO.Pipes.PipeSecurity"))
        if sys.platform != "win32" or shutil.which("pwsh") is None:
            self.skipTest("the pipe check runs in Windows CI")
        script = (
            "$ErrorActionPreference = 'Stop'\n"
            + body
            + "\n$pipe = New-TrustedPipe ('kd-trusted-' + [Guid]::NewGuid().ToString('N').Substring(0, 12))\n"
            "$pipe.Dispose()\n"
            "Write-Output 'pipe=ok'\n"
        )
        self.assertIn("pipe=ok", self.run_pwsh(script))

    def test_the_scratch_needle_differs_from_the_needle_planted_outside_the_container(self):
        wrapper = self.wrapper
        self.assertIn("if ($canaryFile -ceq $script:CanaryControl) { $canaryValue = $script:CanaryScratchNeedle }", wrapper)
        self.assertIn("$script:CanaryNeedle -ceq $script:CanaryScratchNeedle) { throw 'channel_needle' }", wrapper)
        scratch = next(line for line in self.channel_attempt_lines() if "Name = 'walk-control-scratch'" in line)
        self.assertIn("walk {scratch_tmp} 30 {scratch_needle}", scratch)
        self.assertNotIn("{needle}", scratch)
        outside = next(line for line in self.channel_attempt_lines() if "Name = 'bounded-walk'" in line)
        self.assertIn("walk {drive} 150 {needle}", outside)
        self.assertIn("walk {control_root} 30 {needle}", outside)
        self.assertNotIn("scratch_needle", outside)
        self.assertIn("Join-Path $script:Control.Root 'kd_walk_control.txt'), $script:CanaryNeedle", wrapper)
        context = self.function_body("Initialize-ChannelContext")
        self.assertIn("New-RegistryCanary $hive $script:CanaryNeedle", context)

    def test_probe_commands_are_bounded_and_never_write_runner_command_files(self):
        probe = self.probe
        for required in (
            "if needle.len() < 16 || needle.len() > 64 {",
            "value > 0 && value <= 600",
            "meta.file_attributes() & 0x400 != 0",
            "if depth < 40 {",
            "valid_token(id, \"-\", 40)",
            "valid_token(name, \".-_{}\", 120)",
            "OpenOptions::new().append(true)",
            "creation_flags(0x0100_0000)",
            "0x082A",
        ):
            with self.subTest(required=required):
                self.assertIn(required, probe)
        append = probe[probe.index("fn probe_append"):probe.index("fn probe_pipemake")]
        self.assertNotIn("write_all", append)
        self.assertNotIn("write!", append)
        self.assertIn('println!("::debug::kd-marker");', probe)
        for forbidden in ("OpenOptions::new().write(true).append", "set_len", "remove_file(path"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, append)
        self.assertEqual(probe.count("DeleteAppContainerProfile(name.as_ptr())"), 1)
        self.assertEqual(probe.count("RegDeleteKeyW(root, sub.as_ptr())"), 1)

    def test_cleanup_deletes_by_handle_and_never_traverses_reparse_points(self):
        for name, native_name in (("Remove-TreeNoFollow", "Remove"), ("Remove-ReparsePoints", "RemoveLinks")):
            body = self.function_body(name)
            with self.subTest(function=name):
                self.assertIn("[KeelDock.Platform.WindowsConfinement.HandleRemover]::" + native_name + "($path)", body)
                for forbidden in ("Remove-Item", "-Recurse", "Get-ChildItem", "GetFileSystemEntries", "[System.IO.Directory]::Delete", "[System.IO.File]::Delete", "SetAttributes", "robocopy", "rmdir", "cmd.exe"):
                    self.assertNotIn(forbidden, body)
        self.assertNotIn("Remove-Item", self.wrapper)
        self.assertNotIn("GetFileSystemEntries", self.wrapper)
        self.assertNotIn("[System.IO.Directory]::Delete", self.wrapper)
        self.assertNotIn("[System.IO.File]::Delete($path)", self.wrapper)
        native = self.native
        remover = native[native.index("public static class HandleRemover"):native.index("public sealed class Sandbox")]
        for required in (
            "FlagBackupSemantics = 0x02000000",
            "FlagOpenReparsePoint = 0x00200000",
            "AttributeReparsePoint = 0x00000400",
            "ClassDispositionInfoEx = 21",
            "DispositionDeletePosixIgnoreReadOnly = 0x13",
            "ClassFullDirectoryRestartInfo = 15",
            "uint flags = FlagBackupSemantics | FlagOpenReparsePoint;",
            "Native.CreateFileW(path, access, ShareRead | ShareWrite, IntPtr.Zero, OpenExisting, flags, IntPtr.Zero)",
            "Native.SetFileInformationByHandle(handle, ClassDispositionInfoEx, buffer, 4)",
            "Native.GetFileInformationByHandleEx(handle, infoClass, buffer, (uint)DirectoryBufferBytes)",
            'string trimmed = path.TrimEnd(\'\\\\\');',
            'return "\\\\\\\\?\\\\" + trimmed;',
        ):
            with self.subTest(required=required):
                self.assertIn(required, remover)
        self.assertNotIn("ShareDelete", remover)
        for forbidden in ("Directory.Delete", "File.Delete", "Directory.GetFiles", "Directory.EnumerateFileSystemEntries", "DeleteFileW", "RemoveDirectoryW", "FindFirstFile", "Process.Start"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, remover)
        entry = remover[remover.index("private static void RemoveEntry"):remover.index("private static class Native")]
        self.assertLess(entry.index("ReadInformation(handle, out attributes, out links);"), entry.index("(attributes & AttributeReparsePoint) != 0"))
        self.assertLess(entry.index("(attributes & AttributeReparsePoint) != 0"), entry.index("ListEntries(handle, names, kinds);"))
        reparse = entry[entry.index("(attributes & AttributeReparsePoint) != 0"):entry.index("(attributes & AttributeDirectory) != 0")]
        self.assertIn("DeleteByHandle(handle, attributes, links);\n                    return;", reparse)
        self.assertNotIn("RemoveEntry(", reparse)
        self.assertIn("if (linksOnly && plain)", entry)
        self.assertIn("if (depth > MaxDepth)", entry)
        delete = remover[remover.index("private static void DeleteByHandle"):remover.index("private static void RemoveEntry")]
        self.assertIn("(attributes & AttributeReadOnly) != 0 && links <= 1 && (attributes & AttributeReparsePoint) == 0", delete)
        self.assertIn('throw new InvalidOperationException("remove_failed step=delete error="', delete)
        self.assertIn("Remove-TreeNoFollow $item", self.function_body("Remove-Canaries"))
        tail = self.wrapper[self.wrapper.index("$nullRestore = 'not_applied'"):]
        self.assertLess(tail.index("Remove-ReparsePoints $script:ProfileFolder"), tail.index("$box.Dispose()"))
        self.assertLess(tail.index("Remove-ReparsePoints $script:OtherFolder"), tail.index("$script:OtherBox.Dispose()"))
        self.assertLess(tail.index("Remove-TreeNoFollow $script:ProfileFolder"), tail.index("$script:OtherBox.Dispose()"))
        self.assertLess(tail.index("Remove-TreeNoFollow $baseDirectory"), tail.index("$linksState = 'verified'"))
        for required in (
            "if ($script:PlantedJunctions -lt 3) { $linksState = 'incomplete' }",
            "$linksState = 'followed'",
            "[IO.File]::ReadAllText($script:TrapSentinel) -cne 'kd-sentinel'",
            "Remove-TreeNoFollow $script:TrapDirectory",
            "' links=' + $linksState",
            "Write-CleanupDetail 'trap' $_",
        ):
            with self.subTest(required=required):
                self.assertIn(required, tail)
        detail = self.function_body("Write-CleanupDetail")
        self.assertIn("Get-CleanText $message 160", detail)

    def test_link_fixtures_plant_junctions_and_symlinks_inside_container_writable_trees(self):
        body = self.function_body("Initialize-LinkFixtures")
        for required in (
            "Join-Path $env:RUNNER_TEMP ('kd-trap-' + $suffix)",
            "(Join-Path $script:Lpac.Tmp 'kd_junction')",
            "(Join-Path $nested 'kd_junction')",
            "(Join-Path $packageAc 'kd_junction')",
            "$packageAc = Join-Path $script:ProfileFolder 'AC'",
            "New-LinkFixture 'Junction' $junction $trap",
            "New-LinkFixture 'SymbolicLink' (Join-Path $script:Lpac.Tmp 'kd_symlink_dir') $trap",
            "New-LinkFixture 'SymbolicLink' (Join-Path $nested 'kd_symlink_file') $sentinel",
            "throw 'link_fixture'",
        ):
            with self.subTest(required=required):
                self.assertIn(required, body)
        link = self.function_body("New-LinkFixture")
        self.assertIn("New-Item -ItemType $kind -Path $path -Value $target | Out-Null", link)
        for forbidden in ("Grant-", "icacls", "SetAccessControl", "Set-Acl"):
            self.assertNotIn(forbidden, body)

    def test_cleanup_helpers_unlink_junctions_and_symlinks_without_following_in_windows_ci(self):
        if sys.platform != "win32" or shutil.which("pwsh") is None:
            self.skipTest("junction cleanup runs in Windows CI")
        body = (
            "$ErrorActionPreference = 'Stop'\n"
            + "Add-Type -Path '" + str(NATIVE) + "'\n"
            + self.function_body("Remove-TreeNoFollow")
            + "\n"
            + self.function_body("Remove-ReparsePoints")
            + "\n"
            "$root = Join-Path ([IO.Path]::GetTempPath()) ('kd-cleanup-' + [Guid]::NewGuid().ToString('N'))\n"
            "try {\n"
            "    $trap = Join-Path $root 'trap'\n"
            "    $tree = Join-Path $root 'tree'\n"
            "    $sentinel = Join-Path $trap 'inner\\sentinel.txt'\n"
            "    New-Item -ItemType Directory -Path (Join-Path $trap 'inner') -Force | Out-Null\n"
            "    [IO.File]::WriteAllText($sentinel, 'kd-sentinel')\n"
            "    New-Item -ItemType Directory -Path (Join-Path $tree 'nested\\deeper') -Force | Out-Null\n"
            "    [IO.File]::WriteAllText((Join-Path $tree 'readonly.txt'), 'x')\n"
            "    [IO.File]::SetAttributes((Join-Path $tree 'readonly.txt'), [System.IO.FileAttributes]::ReadOnly)\n"
            "    $links = @((Join-Path $tree 'junction'), (Join-Path $tree 'nested\\deeper\\junction'))\n"
            "    foreach ($link in $links) { New-Item -ItemType Junction -Path $link -Value $trap | Out-Null }\n"
            "    $symlinks = 0\n"
            "    try { New-Item -ItemType SymbolicLink -Path (Join-Path $tree 'symdir') -Value $trap | Out-Null; $symlinks += 1 } catch { }\n"
            "    try { New-Item -ItemType SymbolicLink -Path (Join-Path $tree 'symfile') -Value $sentinel | Out-Null; $symlinks += 1 } catch { }\n"
            "    $shared = Join-Path $root 'shared.txt'\n"
            "    [IO.File]::WriteAllText($shared, 'shared')\n"
            "    [IO.File]::SetAttributes($shared, [System.IO.FileAttributes]::ReadOnly)\n"
            "    New-Item -ItemType HardLink -Path (Join-Path $tree 'nested\\hard.txt') -Value $shared | Out-Null\n"
            "    Remove-ReparsePoints $tree\n"
            "    if (-not (Test-Path -LiteralPath $sentinel)) { throw 'links_pass_followed' }\n"
            "    if (Test-Path -LiteralPath (Join-Path $tree 'junction')) { throw 'junction_left' }\n"
            "    if (-not (Test-Path -LiteralPath (Join-Path $tree 'readonly.txt'))) { throw 'files_removed_by_links_pass' }\n"
            "    foreach ($link in $links) { if (-not (Test-Path -LiteralPath (Split-Path -Parent $link))) { throw 'parent_missing' } }\n"
            "    foreach ($link in $links) { New-Item -ItemType Junction -Path $link -Value $trap | Out-Null }\n"
            "    Remove-TreeNoFollow $tree\n"
            "    if (Test-Path -LiteralPath $tree) { throw 'tree_left' }\n"
            "    if (-not (Test-Path -LiteralPath $sentinel)) { throw 'tree_followed' }\n"
            "    if ([IO.File]::ReadAllText($sentinel) -cne 'kd-sentinel') { throw 'sentinel_changed' }\n"
            "    if (-not (Test-Path -LiteralPath $shared)) { throw 'shared_removed' }\n"
            "    if (([int][IO.File]::GetAttributes($shared) -band 1) -eq 0) { throw 'shared_attributes_changed' }\n"
            "    Write-Output ('cleanup-links=verified symlinks=' + $symlinks)\n"
            "} finally {\n"
            "    if (Test-Path -LiteralPath $root) { Remove-ReparsePoints $root; Remove-TreeNoFollow $root }\n"
            "}\n"
        )
        output = self.run_pwsh(body)
        self.assertIn("cleanup-links=verified", output)

    def test_wrapper_does_not_carry_the_probe_apis_or_a_task_registration(self):
        for forbidden in ("DebugActiveProcess", "CoCreateInstance", "FwpmEngineOpen", "OpenSCManager", "RegisterEventSource", "schtasks"):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, self.wrapper)
        self.assertIn("HandleRemover", self.wrapper)
        self.assertNotIn("-band 1024", self.wrapper)

    def test_gate_four_attempts_use_closed_probe_forms_and_unverified_codes_stay_informational(self):
        import uuid

        probe = self.probe
        words = {
            "taskreg_clsid": ("0F87369F-A4E5-4CFC-BD3E-73E6154572DD", "let clsid: [u32; 4] = [{}];"),
            "taskreg_iid": ("2FABA4C7-4DA9-4013-9697-20CC3FD40F85", "let iid: [u32; 4] = [{}];"),
            "wmi_clsid": ("4590F811-1D3A-11D0-891F-00AA004B2E24", "let clsid: [u32; 4] = [{}];"),
            "wmi_iid": ("DC12A687-737F-11CF-884D-00AA004B2E24", "let iid: [u32; 4] = [{}];"),
        }
        for name, (guid, template) in words.items():
            raw = uuid.UUID(guid).bytes_le
            values = [int.from_bytes(raw[index:index + 4], "little") for index in range(0, 16, 4)]
            text = ", ".join("0x{:08X}".format(value) for value in values)
            with self.subTest(guid=name):
                self.assertIn(template.format(text), probe)
        task = probe[probe.index("fn probe_taskreg"):probe.index("fn probe_wmi")]
        wmi = probe[probe.index("fn probe_wmi"):probe.index("fn probe_wfp")]
        wfp = probe[probe.index("fn probe_wfp"):probe.index("fn probe_procpeer")]
        peer = probe[probe.index("fn probe_procpeer"):probe.index("fn main")]
        self.assertIn("vtable_entry(object, 10)", task)
        self.assertIn("extern \"system\" fn(*mut u8, *mut u8, *mut u8, *mut u8, *mut u8) -> i32", task)
        self.assertIn('format!("create=ok connect=hr{:08x}", connected as u32)', task)
        self.assertIn("vtable_entry(object, 3)", wmi)
        self.assertIn('SysAllocString(namespace.as_ptr())', wmi)
        self.assertIn('wide("ROOT\\\\CIMV2")', wmi)
        self.assertIn("LoadLibraryExW(library.as_ptr(), 0, 0x0800)", wfp)
        self.assertIn("open=load_err", wfp)
        self.assertEqual(probe.count("LoadLibraryExW("), 2)
        self.assertNotIn("-l fwpuclnt", self.wrapper)
        self.assertIn("FwpmEngineOpen0\\0", wfp)
        self.assertIn("(ptr::null(), 10, ptr::null_mut(), ptr::null(), &mut engine)", wfp)
        self.assertIn('format!("open=err{}", status)', wfp)
        self.assertIn("close(engine);", wfp)
        self.assertIn("command.arg(\"peerwait\");", peer)
        self.assertIn("OpenProcess(0x1010, 0, child.id())", peer)
        self.assertIn("drop(child.stdin.take());", peer)
        self.assertLess(peer.index("OpenProcess(0x1010, 0, child.id())"), peer.index("drop(child.stdin.take());"))
        for body in (task, wmi, wfp, peer):
            for forbidden in ("ReadProcessMemory", "WriteProcessMemory", "RegisterTaskDefinition", "CreateService", "FwpmFilterAdd", "FwpmTransactionBegin"):
                self.assertNotIn(forbidden, body)
        self.assertEqual(probe.count("CoCreateInstance("), 3)
        for library in ("ole32", "oleaut32"):
            self.assertIn("-l " + library + " ", self.wrapper)
        lines = {
            re.search(r"Name = '([a-z0-9-]+)'", line).group(1): line
            for line in self.channel_attempt_lines()
        }
        for name, command in (("task-register", "taskreg"), ("wmi", "wmi"), ("wfp", "wfp")):
            with self.subTest(attempt=name):
                line = lines[name]
                self.assertIn("Channel = 'boundary_disablement'", line)
                self.assertIn("Informational = $true; LeakGuard = $true", line)
                self.assertIn("Runs = @('" + command + "'); ControlRuns = @('" + command + "')", line)
        self.assertIn("Channel = 'process_memory'", lines["control-peer-memory"])
        self.assertEqual(self.attempt_model(lines["wmi"], "create=ok connect=hr80041003"), "denied")
        self.assertEqual(self.attempt_model(lines["wmi"], "create=ok connect=hr80070005"), "denied")
        self.assertEqual(self.attempt_model(lines["task-register"], "create=ok connect=hr80041003"), "other")
        self.assertEqual(self.attempt_model(lines["task-register"], "create=ok connect=ok"), "allowed")
        self.assertEqual(self.attempt_model(lines["wfp"], "open=err1722"), "other")

    def test_a_leak_on_a_leak_guarded_informational_attempt_still_fails_the_channel(self):
        phase = self.function_body("Invoke-ChannelPhase")
        guard = (
            "if ($attempt.ContainsKey('LeakGuard') -and $outcome.Reason -ceq 'channel_leak' -and $entry.Status -ceq 'blocked') {\n"
            "                $entry.Status = 'observed-leak'\n"
            "                $entry.Reason = 'channel_leak'\n"
            "            }\n"
            "            continue"
        )
        self.assertIn(guard, phase)
        self.assertLess(phase.index("$entry.Informational += 1"), phase.index(guard))
        self.assertLess(phase.index(guard), phase.index("$entry.Attempts += 1"))

    FIXTURE_RUST = (
        "net-external",
        "net-loopback",
        "dns-lookup",
        "read-canary",
        "write-escape",
        "env-hunt",
        "pipe-open",
        "child-network",
        "child-write",
        "child-cmd",
        "output-exfil",
    )
    FIXTURE_NODE = (
        "net-external",
        "net-loopback",
        "dns-lookup",
        "read-canary",
        "write-escape",
        "env-hunt",
        "pipe-open",
        "output-exfil",
        "spawn-pipe",
    )
    FIXTURE_SAME_AS_CHANNEL = {
        "net-external": ("https", "tls-ipv4"),
        "net-loopback": ("proxy", "proxy-connect"),
        "dns-lookup": ("dns", "getaddrinfo"),
        "read-canary": ("runner_files", "canary-reads"),
        "write-escape": ("artifact_upload", "staging-write"),
        "env-hunt": ("artifact_upload", "env-hunt"),
        "pipe-open": ("runner_ipc", "pipe-existing-open"),
        "child-network": ("https", "tls-ipv4"),
        "child-write": ("artifact_upload", "staging-write"),
    }

    def fixture_attempt_lines(self, node):
        body = self.function_body("Get-FixtureAttempts")
        head, tail = body.split("    } else {", 1)
        text = head if node else tail
        return [line for line in text.splitlines() if line.strip().startswith("$attempts += @{")]

    def fixture_source(self, name):
        found = re.search(r"^\$" + name + r" = @'\n(.*?)\n'@$", self.wrapper, re.S | re.M)
        self.assertIsNotNone(found, name)
        return found.group(1)

    def test_fixture_forms_mirror_the_linux_forms_and_every_form_has_a_control(self):
        forms = re.search(r"^\$FixtureForms = @\((.*)\)$", self.wrapper, re.M)
        self.assertEqual(tuple(re.findall(r"'([a-z_]+)'", forms.group(1))), ("build_rs", "test", "binary", "node_install"))
        rust = self.fixture_source("FixtureRustText")
        node = self.fixture_source("FixtureNodeText")
        for text in (rust, node):
            self.assertTrue(text.isascii())
            self.assertNotIn(chr(35), text)
        self.assertEqual(tuple(re.findall(r'report\("([a-z-]+)"', rust)), self.FIXTURE_RUST)
        self.assertEqual(tuple(re.findall(r"report\('([a-z-]+)'", node)), (self.FIXTURE_NODE[-1],) + self.FIXTURE_NODE[:-1])
        for required in (
            "TcpStream::connect_timeout(&addresses[0], Duration::from_secs(8))",
            "(host, 443u16).to_socket_addrs()",
            "OpenOptions::new().write(true).create_new(true).open(path)",
            "Command::new(&probe).args(arguments).output()",
            'println!("::debug::kd-fx-marker");',
            'eprintln!("::debug::kd-fx-marker");',
            'report("output-exfil", "text=ok");',
        ):
            with self.subTest(required=required):
                self.assertIn(required, rust)
        for required in (
            "net.connect(options)",
            "fs.openSync(path, 'wx')",
            "stdio: 'pipe'",
            "if (mode === 'spawn-pipe') {",
            "process.exit(0);",
        ):
            with self.subTest(required=required):
                self.assertIn(required, node)
        spawn_branch = node[node.index("if (mode === 'spawn-pipe') {"):node.index("report('net-external'")]
        self.assertIn("process.exit(0);", spawn_branch)
        self.assertEqual(node.count("spawnSync("), 1)
        for forbidden in ("child_process.exec", "fork(", "eval(", "Function("):
            self.assertNotIn(forbidden, node)
        sources = self.function_body("Initialize-FixtureSources")
        for required in (
            "$sources['build_rs\\build.rs'] = $mainText",
            "$sources['build_rs\\src\\main.rs'] = \"fn main() {}`n\"",
            "$sources['test\\src\\lib.rs'] = $libText",
            "$sources['binary\\src\\main.rs'] = $mainText",
            "$sources['node_install\\install.js'] = $nodeText",
            "$sources['node_install\\package.json'] = $FixtureNodePackage",
            ".Replace('KDHASH', $hash)",
            "foreach ($set in @($script:Lpac, $script:Control)) {",
        ):
            with self.subTest(required=required):
                self.assertIn(required, sources)
        for forbidden in ("Grant-", "icacls", "SetAccessControl", "Set-Acl"):
            self.assertNotIn(forbidden, sources)
        self.assertIn('"scripts":{"postinstall":"node install.js"}', self.wrapper)
        order = (
            "[IO.File]::WriteAllText($layout.NodeChild,",
            "Initialize-FixtureSources\n",
            "$phase = 'canaries'",
        )
        positions = [self.wrapper.index(item) for item in order]
        self.assertEqual(positions, sorted(positions))

    def test_fixture_attempts_use_the_channel_suite_codes_and_no_generic_code(self):
        channel = {}
        for line in self.channel_attempt_lines():
            key = (
                re.search(r"Channel = '([a-z_]+)'", line).group(1),
                re.search(r"Name = '([a-z0-9-]+)'", line).group(1),
            )
            channel[key] = (
                re.search(r"(?<![A-Za-z])Allow = '([^']*)'", line).group(1),
                re.search(r"Deny = '([^']*)'", line).group(1),
                re.search(r"Expect = '([a-z]+)'", line).group(1),
            )
        for node, expected in ((False, self.FIXTURE_RUST), (True, self.FIXTURE_NODE)):
            lines = self.fixture_attempt_lines(node)
            names = tuple(re.search(r"Name = '([a-z0-9-]+)'", line).group(1) for line in lines)
            with self.subTest(node=node):
                self.assertEqual(names, expected)
            for line in lines:
                name = re.search(r"Name = '([a-z0-9-]+)'", line).group(1)
                allow = re.search(r"(?<![A-Za-z])Allow = '([^']*)'", line).group(1)
                deny = re.search(r"Deny = '([^']*)'", line).group(1)
                expect = re.search(r"Expect = '([a-z]+)'", line).group(1)
                with self.subTest(node=node, attempt=name):
                    self.assertTrue(line.isascii())
                    for pattern in (allow, deny):
                        for piece in re.sub(r"\([^)]*\)", "G", pattern).split("|"):
                            self.assertTrue(piece.startswith("^") and piece.endswith("$"), pattern)
                    self.assertIn(expect, ("denied", "contained", "allowed") if name == "child-cmd" else ("denied", "contained"))
                    if not node and name in self.FIXTURE_SAME_AS_CHANNEL:
                        self.assertEqual((allow, deny, expect), channel[self.FIXTURE_SAME_AS_CHANNEL[name]])
                    if not node:
                        codes = {"err" + value for value in re.findall(r"err([0-9]+)", deny)}
                        for group in re.findall(r"err\(([0-9|]+)\)", deny):
                            codes.update("err" + item for item in group.split("|"))
                        self.assertLessEqual(codes, DENIAL_CODES)
                    else:
                        codes = set(re.findall(r"E[A-Z_]+", deny))
                        gating = "Informational" not in line
                        self.assertLessEqual(codes, {"EACCES", "EPERM", "ENOENT"} if gating else {"EAI_FAIL", "EACCES"})
                        self.assertNotIn(".*", deny)
        informational = {
            re.search(r"Name = '([a-z0-9-]+)'", line).group(1)
            for line in self.fixture_attempt_lines(True) + self.fixture_attempt_lines(False)
            if "Informational = $true" in line
        }
        self.assertEqual(informational, {"dns-lookup", "spawn-pipe"})
        for line in self.fixture_attempt_lines(True):
            if "Informational" in line:
                self.assertIn("LeakGuard = $true", line)
        spawn = next(line for line in self.fixture_attempt_lines(True) if "Name = 'spawn-pipe'" in line)
        self.assertIn("Separate = $true", spawn)
        self.assertIn("Allow = '^spawn=ok$'", spawn)
        markers = {
            re.search(r"Name = '([a-z0-9-]+)'", line).group(1)
            for line in self.fixture_attempt_lines(True) + self.fixture_attempt_lines(False)
            if "Marker = $true" in line
        }
        self.assertEqual(markers, {"output-exfil"})
        harness = {
            re.search(r"Name = '([a-z0-9-]+)'", line).group(1)
            for line in self.fixture_attempt_lines(False)
            if "Basis = 'harness'" in line
        }
        self.assertEqual(harness, {"env-hunt", "output-exfil"})

    def test_fixtures_run_confined_after_the_selftest_and_before_the_recheck_and_gate_the_summary(self):
        wrapper = self.wrapper
        order = (
            "$channelsBefore = Invoke-ChannelPhase $box 'selftest' $true",
            "$phase = 'fixtures'\n        $fixtureState = Invoke-FixturePhase $box",
            "$confinedOutcomes = Invoke-Ladder $box $true $script:Lpac",
            "$channelsAfter = Invoke-ChannelPhase $box 'recheck' $false",
            "$observed['fixtures'] = $fixtureState",
        )
        positions = [wrapper.index(item) for item in order]
        self.assertEqual(positions, sorted(positions))
        self.assertEqual(wrapper.count("Invoke-FixturePhase $box"), 1)
        self.assertEqual(wrapper.count("Invoke-ChannelPhase $box 'selftest'"), 1)
        phase = self.function_body("Invoke-FixturePhase")
        for required in (
            "windows-confinement-fixture=' + $form + ' status='",
            "windows-confinement-fixtures=' + $state + ' forms='",
            "$state = 'observed-leak'",
            "if ($state -cne 'observed-leak' -and $contained -ne $FixtureForms.Count) { $state = 'refused' }",
            "' controlled=' + $controlled + ' uncontrolled=0'",
        ):
            with self.subTest(required=required):
                self.assertIn(required, phase)
        form = self.function_body("Invoke-FixtureForm")
        control = form.index("Invoke-FixtureRun $sandbox $form $false ''")
        confined = form.index("Invoke-FixtureRun $sandbox $form $true ''")
        self.assertLess(control, confined)
        self.assertLess(form.index("Set-FixtureRefusal $report 'refused' 'control_not_fired'"), confined)
        for required in (
            "Test-ChannelRunValid $control $false",
            "Test-ChannelRunValid $run $true",
            "Set-FixtureRefusal $report 'refused' 'fixture_incomplete'",
            "Set-FixtureRefusal $report 'observed-leak' 'fixture_allowed'",
            "Set-FixtureRefusal $report 'refused' 'attempt_unexpected'",
            "if ($names -cnotcontains [string]$seen) {",
            "$result = Get-TextClass $text $attempt",
            "if ($result -ceq [string]$attempt.Expect) { continue }",
            "::debug::kd-fx-marker\\s*$')) { $result = 'contained' }",
        ):
            with self.subTest(required=required):
                self.assertIn(required, form)
        self.assertIn("return $report", form)
        refusal = self.function_body("Set-FixtureRefusal")
        self.assertIn("$upgrade = ($status -ceq 'observed-leak') -and ($report.Status -cne 'observed-leak')", refusal)
        separate = self.function_body("Invoke-FixtureSeparate")
        self.assertLess(separate.index("Invoke-FixtureRun $sandbox $form $false $attempt.Name"), separate.index("Invoke-FixtureRun $sandbox $form $true $attempt.Name"))
        self.assertIn("if ($result -ceq 'allowed') { Set-FixtureRefusal $report 'observed-leak' 'fixture_allowed' }", separate)
        self.assertIn("elseif ($attempt.ContainsKey('RequireHang') -and ($result -cne 'timeout' -or $hang -cne [string]$attempt.RequireHang))", separate)
        self.assertNotIn("Test-ChannelRunValid", separate.split("Invoke-FixtureRun $sandbox $form $true $attempt.Name")[1])
        self.assertNotIn("-cnotmatch ':'", form)
        self.assertIn("$hang = 'busy'", separate)
        self.assertIn("([uint64]$run.CpuMs * 10) -ge ([uint64]$run.ElapsedMs * 8)", separate)

    def test_fixture_runs_use_the_stage_environment_offline_and_only_trusted_values(self):
        body = self.function_body("Invoke-FixtureRun")
        for required in (
            "$scratch = $script:Lpac",
            "New-StageEnvironment $scratch ('target-fx-' + $form)",
            "if (-not $confined) { $environment = [string[]]($environment + $FixtureSentinelEnvironment) }",
            "'build -vv --offline --manifest-path '",
            "'test --offline --manifest-path '",
            "' -- --nocapture'",
            "'run --offline --manifest-path '",
            "$sandbox.Run($confined, $exe,",
            "$pipe = New-TrustedPipe $pipeName",
            "$pipe.Dispose()",
            "throw 'fixture_form'",
        ):
            with self.subTest(required=required):
                self.assertIn(required, body)
        names = re.findall(r"'(KD_[A-Z_]+)='", body)
        self.assertEqual(set(names), {"KD_PROBE", "KD_FX_NONCE", "KD_FX_PORT", "KD_FX_TEMP", "KD_FX_CANARY", "KD_FX_PIPE"})
        for name in names:
            self.assertFalse(name.startswith(("ACTIONS_", "GITHUB_", "RUNNER_")))
        sentinel = self.top_level_line("FixtureSentinelEnvironment")
        for name in re.findall(r"'([A-Z_]+)=kd-sentinel'", sentinel):
            self.assertTrue(name.startswith(("ACTIONS_", "GITHUB_", "RUNNER_")))
        self.assertNotIn("PROXY", sentinel)
        self.assertNotIn("$script:Control, ", body)
        for name in (
            "$FixtureCargoSeconds",
            "$FixtureNodeSeconds",
            "$FixtureSpawnSeconds",
        ):
            self.assertIn(name, body)
        for forbidden in ("Start-Process", "Invoke-Expression"):
            self.assertNotIn(forbidden, body)

    FIXTURE_BANK = {
        "net-external": ("resolve=ok connect=open", "resolve=ok connect=err10013", "resolve=ok connect=err10061", "resolve=err11003", ""),
        "net-loopback": ("resolve=ok connect=open", "resolve=ok connect=err10013", "resolve=ok connect=err10061", "resolve=empty"),
        "dns-lookup": ("resolve=ok count=2", "resolve=ok count=0", "resolve=err11003", "resolve=err10013", "resolve=err11001"),
        "read-canary": ("open=ok read=ok bytes=16", "open=err5", "open=err2", "open=err3", "open=err32", "open=ok read=err5"),
        "write-escape": ("create=ok write=ok", "create=err5", "create=err80", "create=ok write=err5"),
        "env-hunt": ("found=0", "found=3", "found=usage"),
        "pipe-open": ("open=ok", "open=err5", "open=err2", "open=err231"),
        "child-network": ("resolve=ok connect=open", "resolve=ok connect=err10013", "child=err5", "child=noline"),
        "child-write": ("create=ok write=ok", "create=err5", "child=err5"),
        "child-cmd": ("exit=7", "exit=1", "exit=none", "child=err5"),
    }
    FIXTURE_NODE_BANK = {
        "net-external": ("connect=open", "connect=EACCES", "connect=ECONNREFUSED", "connect=timeout", "connect=EPERM"),
        "net-loopback": ("connect=open", "connect=EACCES", "connect=ECONNREFUSED"),
        "dns-lookup": ("resolve=ok", "resolve=EAI_FAIL", "resolve=EACCES", "resolve=ENOTFOUND", "resolve=timeout"),
        "read-canary": ("open=ok read=ok bytes=16", "open=EPERM", "open=ENOENT", "open=EBUSY", "open=ok read=EPERM"),
        "write-escape": ("create=ok write=ok", "create=EPERM", "create=EEXIST", "create=EACCES"),
        "env-hunt": ("found=0", "found=2"),
        "pipe-open": ("open=ok", "open=EPERM", "open=ENOENT"),
        "spawn-pipe": ("spawn=ok", "spawn=ETIMEDOUT", "spawn=fail"),
    }

    def test_fixture_classifier_matches_the_python_model_under_pwsh(self):
        if shutil.which("pwsh") is None:
            self.skipTest("pwsh is not available")
        cases = []
        for form, bank in (("build_rs", self.FIXTURE_BANK), ("node_install", self.FIXTURE_NODE_BANK)):
            for name, texts in bank.items():
                for text in texts:
                    cases.append((form, name, text))
        entries = ",\n".join("    @('" + form + "', '" + name + "', '" + text + "')" for form, name, text in cases)
        body = (
            "$ErrorActionPreference = 'Stop'\n"
            + self.function_body("Get-TextClass")
            + "\n"
            + self.function_body("Get-FixtureAttempts")
            + "\n$cases = @(\n"
            + entries
            + "\n)\n"
            + "foreach ($case in $cases) {\n"
            + "    foreach ($attempt in @(Get-FixtureAttempts $case[0])) {\n"
            + "        if ($attempt.Name -cne $case[1]) { continue }\n"
            + "        Write-Output ($case[0] + '/' + $case[1] + '|' + $case[2] + '|' + (Get-TextClass $case[2] $attempt))\n"
            + "    }\n"
            + "}\n"
        )
        output = self.run_pwsh(body)
        rows = [line.split("|") for line in output.splitlines() if line.count("|") == 2]
        self.assertEqual(len(rows), len(cases))
        lines = {}
        for node in (False, True):
            for line in self.fixture_attempt_lines(node):
                lines[("node_install" if node else "build_rs") + "/" + re.search(r"Name = '([a-z0-9-]+)'", line).group(1)] = line
        for key, text, result in rows:
            with self.subTest(attempt=key, text=text):
                self.assertEqual(result, self.attempt_model(lines[key], text))
        results = {(key, text): result for key, text, result in rows}
        self.assertEqual(results[("build_rs/net-external", "resolve=ok connect=err10013")], "denied")
        self.assertEqual(results[("build_rs/net-external", "resolve=ok connect=err10061")], "other")
        self.assertEqual(results[("build_rs/write-escape", "create=err5")], "contained")
        self.assertEqual(results[("build_rs/write-escape", "create=ok write=ok")], "allowed")
        self.assertEqual(results[("build_rs/env-hunt", "found=0")], "contained")
        self.assertEqual(results[("build_rs/pipe-open", "open=err231")], "other")
        self.assertEqual(results[("build_rs/child-network", "child=err5")], "other")
        self.assertEqual(results[("node_install/net-external", "connect=EACCES")], "denied")
        self.assertEqual(results[("node_install/net-external", "connect=EPERM")], "other")
        self.assertEqual(results[("node_install/spawn-pipe", "spawn=ok")], "allowed")
        self.assertEqual(results[("node_install/spawn-pipe", "spawn=fail")], "other")
        self.assertEqual(results[("node_install/dns-lookup", "resolve=ok")], "allowed")
        self.assertEqual(results[("node_install/dns-lookup", "resolve=ENOTFOUND")], "other")

    def fixture_line_model(self, text):
        pattern = re.compile(r"^(?:\[[A-Za-z0-9_.+-]{1,40} [0-9][A-Za-z0-9_.+-]{0,20}\] )?KDATT ([a-z0-9-]{1,40}) ([A-Za-z0-9_=. -]{1,100})$")
        items = {}
        valid = True
        for line in text.split("\n"):
            trimmed = line.strip()
            if "KDATT " not in trimmed:
                continue
            found = pattern.match(trimmed)
            if not found or found.group(1) in items:
                valid = False
                continue
            items[found.group(1)] = found.group(2)
        return valid, items

    def test_fixture_line_parser_is_strict_and_matches_the_python_model_under_pwsh(self):
        if shutil.which("pwsh") is None:
            self.skipTest("pwsh is not available")
        cases = (
            "KDATT net-external resolve=ok connect=err10013",
            "[kd_fx 0.1.0] KDATT read-canary open=err5\\nKDATT env-hunt found=0",
            "KDATT a open=ok\\nKDATT a open=err5",
            "KDATT net-external resolve=ok connect=err10013 extra!",
            "prefix KDATT net-external resolve=ok connect=err10013",
            "KDATT NET open=ok",
            "noise only\\nrunning 1 test",
            "KDATT write-escape create=err5\\r\\nKDATT output-exfil text=ok",
        )
        entries = ",\n".join("    '" + case + "'" for case in cases)
        body = (
            "$ErrorActionPreference = 'Stop'\n"
            + self.function_body("Get-FixtureLines")
            + "\n$cases = @(\n"
            + entries
            + "\n)\n"
            + "foreach ($case in $cases) {\n"
            + "    $text = $case.Replace('\\n', \"`n\").Replace('\\r', \"`r\")\n"
            + "    $parsed = Get-FixtureLines $text\n"
            + "    $keys = (@($parsed.Items.Keys) | Sort-Object) -join ','\n"
            + "    Write-Output ($case + '|' + $parsed.Valid.ToString().ToLowerInvariant() + '|' + $keys)\n"
            + "}\n"
        )
        output = self.run_pwsh(body)
        rows = [line.split("|") for line in output.splitlines() if line.count("|") == 2]
        self.assertEqual(len(rows), len(cases))
        for (case, valid, keys), expected in zip(rows, cases):
            text = expected.replace("\\n", "\n").replace("\\r", "\r")
            model_valid, model_items = self.fixture_line_model(text)
            with self.subTest(case=case):
                self.assertEqual(valid, str(model_valid).lower())
                self.assertEqual(keys, ",".join(sorted(model_items)))
        self.assertEqual(self.fixture_line_model("KDATT a x=1\nKDATT a x=2")[0], False)

    def test_fixture_budget_is_part_of_the_worst_case_and_the_timeout_is_justified(self):
        budget = self.fixture_budget()
        self.assertEqual(budget, 2 * 3 * 243 + 2 * 63 + 2 * 33)
        workflow = WORKFLOW.read_text(encoding="utf-8")
        template = (ROOT / "kit/bootstrap/policy_windows.py").read_text(encoding="utf-8")
        self.assertIn("    timeout-minutes: 240\n", workflow)
        self.assertEqual(template.count("    timeout-minutes: 240\n"), 1)
        self.assertNotIn("    timeout-minutes: 200\n", workflow + template)

    def test_leak_guards_run_and_judge_the_confined_attempt_whatever_the_control_and_exit_code(self):
        attempt = self.function_body("Invoke-ChannelAttempt")
        self.assertIn("if (-not $attempt.ContainsKey('LeakGuard')) {\n                $outcome.Reason = 'control_not_fired'\n                return $outcome\n            }", attempt)
        self.assertLess(attempt.index("$outcome.Control = 'not_fired'"), attempt.index("Invoke-ChannelRun $sandbox $true"))
        self.assertIn("$runValid = Test-ChannelRunValid $run $true", attempt)
        self.assertIn("if ($runValid -or $attempt.ContainsKey('LeakGuard')) { $result = Get-AttemptResult $run $command $attempt }", attempt)
        self.assertIn("if (-not $runValid -and $result -cne 'allowed') { $result = 'invalid' }", attempt)
        separate = self.function_body("Invoke-FixtureSeparate")
        tail = separate.split("Invoke-FixtureRun $sandbox $form $true $attempt.Name")[1]
        self.assertIn("if ($text -cmatch $attempt.Allow) {", tail)
        self.assertNotIn("$control", tail.split("Write-Line")[0])
        spawn = next(line for line in self.fixture_attempt_lines(True) if "Name = 'spawn-pipe'" in line)
        self.assertIn("RequireHang = 'busy'", spawn)

    def test_cleanup_verifies_every_child_final_path_and_refuses_unsafe_roots(self):
        native = self.native
        remover = native[native.index("public static class HandleRemover"):native.index("public sealed class Sandbox")]
        for required in (
            "private static string FinalPath(IntPtr handle)",
            "Native.GetFinalPathNameByHandleW(handle, buffer, (uint)FinalPathChars, 0)",
            "string here = FinalPath(handle);",
            "!string.Equals(here, expectedFinal, StringComparison.OrdinalIgnoreCase)",
            'throw new InvalidOperationException("remove_failed step=verify error=redirected");',
            'RemoveEntry(path + "\\\\" + names[index], here + "\\\\" + names[index], depth + 1, linksOnly);',
            "RemoveEntry(Extend(path), null, 0, false);",
            "RemoveEntry(Extend(path), null, 0, true);",
            "if (parts.Length < 2)",
            'part == "." || part == ".."',
        ):
            with self.subTest(required=required):
                self.assertIn(required, remover)
        entry = remover[remover.index("private static void RemoveEntry"):remover.index("private static class Native")]
        self.assertLess(entry.index("string here = FinalPath(handle);"), entry.index("DeleteByHandle(handle, attributes, links);"))
        self.assertLess(entry.index("remove_failed step=verify"), entry.index("ReadInformation(handle"))
        self.assertIn("Delete | Synchronize | FileReadAttributes\n", remover)

    def test_taskreg_variants_are_separate_24_byte_buffers_and_wfp_loads_at_run_time(self):
        probe = self.probe
        task = probe[probe.index("fn probe_taskreg"):probe.index("fn probe_wmi")]
        for name in ("server", "user", "domain", "secret"):
            self.assertIn("let mut " + name + ": [u64; 3] = [0, 0, 0];", task)
        self.assertNotIn("empty", task)
        self.assertEqual(task.count("as_mut_ptr() as *mut u8"), 4)
        self.assertNotIn("FwpmEngineOpen0(", probe.split("fn probe_wfp")[0])
        self.assertIn("LoadLibraryExW(library.as_ptr(), 0, 0x0800)", probe)
        self.assertNotIn("fwpuclnt", self.wrapper.split("-o ' + $probeBuilt")[0].split("$probeArguments = ")[1])


if __name__ == "__main__":
    unittest.main(verbosity=2)
