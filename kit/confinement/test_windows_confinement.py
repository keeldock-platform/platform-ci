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
RECOVERY = ROOT / "kit/confinement/windows_confinement_recovery.ps1"
RECOVERY_TEST = ROOT / "kit/confinement/test_windows_confinement_recovery.ps1"
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
        cls.recovery = RECOVERY.read_text(encoding="utf-8")
        cls.recovery_test = RECOVERY_TEST.read_text(encoding="utf-8")

    def test_files_pass_the_public_tree_rules(self):
        for path in (NATIVE, WRAPPER, RECOVERY, RECOVERY_TEST, WORKFLOW):
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
        names = re.findall(r"Name = '([a-z_]+)'; Exe", self.wrapper)
        self.assertEqual(tuple(names), CONFINED_STAGES)
        control = "$controlOutcomes = Invoke-Ladder $box $false $script:Control"
        confined = "$confinedOutcomes = Invoke-ConfinedLadder $box $script:Lpac"
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
        self.assertEqual(len(patterns), 5)
        return all(fnmatch.fnmatchcase(text, pattern) for pattern in patterns)

    def test_container_proof_requires_every_token_fact_explicitly(self):
        good = "appcontainer=1,capabilities=0,integrity=0x1000,lpac=1,sid=match,arap=present,aap=absent"
        self.assertTrue(self.token_accepted(good))
        for bad in (
            good.replace("lpac=1", "lpac=unreadable"),
            good.replace("lpac=1", "lpac=aap_only"),
            good.replace("lpac=1", "lpac=0"),
            good.replace("sid=match", "sid=mismatch"),
            good.replace("arap=present", "arap=absent"),
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
            "TokenRestrictedSids",
            'AllApplicationPackagesSid = "S-1-15-2-1"',
            'AllRestrictedApplicationPackagesSid = "S-1-15-2-2"',
            "ReadAllRestrictedApplicationPackagesState",
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

    def test_winsock_catalog_access_is_package_scoped_read_only_and_restored(self):
        grant = self.function_body("Grant-WinsockCatalogRead", self.recovery)
        self.assertIn("WinSock2\\Parameters'", grant)
        self.assertLess(grant.index("New-CatalogLease"), grant.index("Start-CatalogRecovery"))
        self.assertLess(grant.index("Start-CatalogRecovery"), grant.index("Add-CatalogRead"))
        self.assertIn("Restore-WinsockCatalogAcl $script:WinsockCatalogLease", grant)
        self.assertLess(grant.index("Restore-WinsockCatalogAcl"), grant.index("Stop-CatalogRecovery"))
        self.assertLess(grant.index("Stop-CatalogRecovery"), grant.index("$script:WinsockCatalogLease = $null"))
        self.assertNotIn("SetAccessControl", grant)
        add = self.function_body("Add-CatalogRead", self.recovery)
        self.assertIn("RegistryRights]::ReadKey", add)
        self.assertIn("RegistryRights]::ChangePermissions", add)
        self.assertIn("RegistryAccessRule($identity", add)
        self.assertIn("$security.AddAccessRule($rule)", add)
        self.assertIn("$writeMask =", add)
        self.assertIn("-not $entry.IsInherited", add)
        self.assertLess(add.index("WriteAllText([string]$lease.ArmedFile"), add.index("$key.SetAccessControl($security)"))
        self.assertIn("Restore-CatalogAcl $lease", self.function_body("Restore-WinsockCatalogAcl", self.recovery))
        restore = self.function_body("Restore-CatalogAcl", self.recovery)
        self.assertIn("Restore-CatalogKey", restore)
        self.assertIn("$index -ge 0; $index--", restore)
        key_restore = self.function_body("Restore-CatalogKey", self.recovery)
        self.assertIn("$sddl", key_restore)
        self.assertIn("$key.SetAccessControl($restore)", key_restore)
        self.assertIn("GetSecurityDescriptorSddlForm", key_restore)
        self.assertIn("winsock_restore_readback", key_restore)
        confined = self.function_body("Invoke-ConfinedLadder")
        self.assertIn("Grant-WinsockCatalogRead $script:Sid", confined)
        self.assertIn("finally", confined)
        self.assertIn("Restore-WinsockCatalogAcl $script:WinsockCatalogLease", confined)
        self.assertIn("Stop-CatalogRecovery $script:WinsockCatalogLease", confined)
        self.assertIn("$script:WinsockCatalogLease = $null", confined)
        self.assertIn("$phase = 'winsock_acl'", self.wrapper)
        self.assertNotIn("internetClient", self.wrapper)
        self.assertNotIn("internetClient", self.recovery)
        self.assertNotIn("privateNetworkClientServer", self.wrapper)
        self.assertIn("capabilities.CapabilityCount = 0", self.native)

    def test_winsock_grants_are_explicit_per_key_over_a_closed_key_set(self):
        asserted = self.function_body("Assert-CatalogPath", self.recovery)
        for part in ("Protocol_Catalog9|NameSpace_Catalog5", "Catalog_Entries|Catalog_Entries64", "[0-9]{12}", "-cmatch"):
            self.assertIn(part, asserted)
        paths = self.function_body("Get-CatalogKeyPaths", self.recovery)
        for part in ("'Protocol_Catalog9'", "'NameSpace_Catalog5'", "'Catalog_Entries'", "'Catalog_Entries64'", "Get-CatalogNumberedChildren"):
            self.assertIn(part, paths)
        children = self.function_body("Get-CatalogNumberedChildren", self.recovery)
        self.assertIn("'^[0-9]{12}\\z'", children)
        lease = self.function_body("New-CatalogLease", self.recovery)
        self.assertIn("KeyList", lease)
        self.assertIn("OriginalSddl = (Get-CatalogAclSddl $item)", lease)
        add = self.function_body("Add-CatalogRead", self.recovery)
        self.assertIn("foreach ($item in @($lease.KeyList))", add)
        self.assertIn("InheritanceFlags]::None, [System.Security.AccessControl.PropagationFlags]::None", add)
        self.assertIn("-ne [string]$item.OriginalSddl", add)
        self.assertIn("$entry.PropagationFlags -eq", add)
        self.assertLess(add.index("-ne [string]$item.OriginalSddl"), add.index("$key.SetAccessControl($security)"))
        watch = self.function_body("Invoke-CatalogWatch", self.recovery)
        self.assertIn("@($data.KeyList)", watch)
        self.assertIn("Assert-CatalogPath ([string]$item.Path)", watch)

    def test_confined_ladder_probes_each_granted_catalog_key_before_other_stages(self):
        probe = self.function_body("Get-WinsockProbeSpecs")
        for part in ("'winsock_key_'", "Get-NativeProbeArguments", "$script:WinsockCatalogLease", "$r.ExitCode -eq 0", "status=ok"):
            self.assertIn(part, probe)
        self.assertNotIn("reg.exe", probe)
        self.assertNotIn("query HKLM", probe)
        for name in ("parameters", "protocol_catalog", "namespace_catalog", "protocol_entries64", "namespace_entries64", "protocol_entry", "namespace_entry64"):
            self.assertIn("Name = '" + name + "'", probe)
        specs = self.function_body("Get-StageSpecs")
        self.assertLess(specs.index("Get-WinsockProbeSpecs"), specs.index("Name = 'cmd_exec'"))

    def test_native_registry_probe_uses_full_nt_names_and_a_closed_identifier_set(self):
        for required in (
            "NtOpenKey",
            "ObjectCaseInsensitive",
            "KeyQueryValue",
            "\\\\REGISTRY\\\\MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\WinSock2\\\\Parameters",
            "\\\\REGISTRY\\\\MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control\\\\Nls\\\\CodePage",
            "HasNumericSuffix(probeId, \"winsock_protocol_entry_\", 12)",
            "HasHexSuffix(probeId, \"lpac_discriminator_arap_\", 32)",
            "status=",
            "access_denied",
            "object_name_not_found",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.native)
        self.assertIn("IsKnownProbeId($probeId)", self.wrapper)
        self.assertIn("NativeRegistryProbe]::Probe($ProbeId)", self.wrapper)
        self.assertIn("ValidateSet('spike', 'compile', 'native-probe')", self.wrapper)
        self.assertIn("Copy-Item -LiteralPath $PSCommandPath -Destination $layout.NativeProbeScript", self.wrapper)
        self.assertIn("$script:Layout.NativeProbeScript", self.wrapper)
        self.assertIn("$script:Layout.NativeProbeSource", self.wrapper)
        self.assertIn("$script:Layout.NativeProbeRecovery", self.function_body("Test-Acl"))
        arguments = self.function_body("Get-NativeProbeArguments")
        self.assertIn("IsKnownProbeId($probeId)", arguments)
        self.assertIn("-ProbeId ' + $probeId", arguments)
        self.assertNotIn("ScratchPaths", arguments)
        self.assertIn('throw new InvalidOperationException("registry_probe_id")', self.native)
        self.assertNotIn("reg.exe", self.wrapper)
        self.assertNotIn("query HKLM", self.wrapper)

    def test_package_sid_and_path_shapes_are_checked_in_the_unprivileged_job(self):
        text = WORKFLOW.read_text(encoding="utf-8")
        step = text.index("      - name: Check package SID and catalog path shapes without registry access\n")
        self.assertLess(text.index("      - name: Compile native confinement module\n"), step)
        self.assertLess(step, text.index("  windows-confinement-spike:\n"))
        block = text[step:text.index("      - name: Exercise registry recovery after forced cancellation\n")]
        self.assertIn("test_windows_confinement_recovery.ps1 -Mode sid", block)
        self.assertNotIn("if:", block)
        self.assertIn("if ($Mode -eq 'sid') {", self.recovery_test)
        self.assertNotIn("OpenBaseKey", self.recovery_test.split("if ($Mode -eq 'sid') {", 1)[1].split("exit 0", 1)[0])

    def test_probe_specs_carry_the_same_confinement_fields_as_cmd_exec(self):
        probe = self.function_body("Get-WinsockProbeSpecs")
        specs = self.function_body("Get-StageSpecs")
        cmd_line = re.search(r"Name = 'cmd_exec'.*", specs).group(0)
        fields = ("Name", "Exe", "Arguments", "Timeout", "Check")
        cmd_fields = re.findall(r"(\w+) = ", cmd_line.split("Check =", 1)[0] + "Check = ")
        self.assertEqual(tuple(cmd_fields), fields)
        spec_lines = [line for line in probe.splitlines() if "$specs += @{" in line]
        self.assertEqual(len(spec_lines), 2)
        for line in spec_lines:
            with self.subTest(line=line):
                found = re.findall(r"(\w+) = ", line.split("Check =", 1)[0] + "Check = ")
                self.assertEqual(tuple(found), fields)
                self.assertNotIn("confined", line.lower())
        ladder = self.function_body("Invoke-Ladder")
        self.assertEqual(ladder.count("$sandbox.Run($confined,"), 1)
        self.assertIn("lpac_default_key_control", probe)
        self.assertIn("Get-NativeProbeArguments 'lpac_default_key_control'", probe)

    def test_discriminator_stages_follow_the_key_probes_and_precede_the_other_confined_stages(self):
        specs = self.function_body("Get-StageSpecs")
        probes = specs.index("Get-WinsockProbeSpecs")
        discriminator = specs.index("Get-LpacDiscriminatorSpecs")
        self.assertLess(probes, discriminator)
        self.assertLess(discriminator, specs.index("Name = 'cmd_exec'"))
        body = self.function_body("Get-LpacDiscriminatorSpecs")
        self.assertLess(body.index("lpac_discriminator_arap"), body.index("lpac_discriminator_aap"))
        lines = [line for line in body.splitlines() if "$specs += @{" in line]
        self.assertEqual(len(lines), 2)
        self.assertIn("ScratchPaths.Arap", lines[0])
        self.assertIn("$arapArguments", lines[0])
        self.assertIn("status=ok", lines[0])
        self.assertIn("ScratchPaths.Aap", lines[1])
        self.assertIn("$aapArguments", lines[1])
        self.assertIn("status=access_denied ntstatus=0xC0000022", lines[1])
        for line in lines:
            self.assertIn("Exe = $probeExe", line)
            self.assertNotIn("query HKLM", line)

    @staticmethod
    def behaviour_model(arap, aap):
        if arap is None or aap is None or not arap["ran"] or not aap["ran"]:
            return "inconclusive"
        if "status=ok" not in arap["output"]:
            return "inconclusive"
        if "status=ok" in aap["output"]:
            return "not_lpac"
        if "status=access_denied ntstatus=0xC0000022" in aap["output"]:
            return "behavioural"
        return "inconclusive"

    def test_behaviour_verdict_maps_the_three_outcomes(self):
        body = self.function_body("Get-LpacBehaviour")
        returns = re.findall(r"return '([a-z_]+)'", body)
        self.assertEqual(returns, ["inconclusive", "inconclusive", "not_lpac", "behavioural", "inconclusive"])
        for required in (
            "-not $arap.Ran -or -not $aap.Ran",
            "$arap.Stdout -notmatch 'status=ok'",
            "$aap.Stdout -match 'status=ok'",
            "$aap.Stdout -match 'status=access_denied ntstatus=0xC0000022'",
        ):
            self.assertIn(required, body)
        readable = {"ran": True, "exit": 0, "output": "native-registry-probe status=ok"}
        denied = {"ran": True, "exit": 0, "output": "native-registry-probe status=access_denied ntstatus=0xC0000022"}
        other = {"ran": True, "exit": 0, "output": "native-registry-probe status=object_name_not_found ntstatus=0xC0000034"}
        not_run = {"ran": False, "exit": 0, "output": ""}
        self.assertEqual(self.behaviour_model(readable, denied), "behavioural")
        self.assertEqual(self.behaviour_model(readable, readable), "not_lpac")
        self.assertEqual(self.behaviour_model(denied, denied), "inconclusive")
        self.assertEqual(self.behaviour_model(readable, other), "inconclusive")
        self.assertEqual(self.behaviour_model(readable, not_run), "inconclusive")
        self.assertEqual(self.behaviour_model(None, denied), "inconclusive")

    def test_token_state_uses_the_behaviour_verdict_without_loosening_the_exit_rule(self):
        self.assertIn("$lpacBehaviour = Get-LpacBehaviour $confinedOutcomes", self.wrapper)
        for required in (
            "if ($lpacBehaviour -eq 'not_lpac') {",
            "$tokenState = 'not_lpac'",
            "} elseif ($lpacBehaviour -eq 'behavioural') {",
            "if ($containerConsistent) {",
            "$lpacBasis = 'behavioural'",
            "$tokenState = 'inconclusive'",
            "' lpac=' + $lpacText + ' lpac_behaviour=' + $lpacBehaviour",
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.wrapper)
        consistent = "$confinedOutcomes[$key].Token -or $confinedOutcomes[$key].AapOnly"
        self.assertIn(consistent, self.wrapper)
        self.assertLess(self.wrapper.index("$lpacBehaviour = Get-LpacBehaviour"), self.wrapper.index("windows-confinement-spike=observed"))
        self.assertIn("-and $tokenState -eq 'verified'", self.wrapper)
        self.assertIn("Ran = ($result.Failure -eq '' -and $result.Exited -and -not $result.TimedOut)", self.wrapper)

    def test_scratch_discriminator_keys_are_created_restored_and_deleted_through_the_lease(self):
        lease = self.function_body("New-CatalogLease", self.recovery)
        self.assertIn("ScratchPaths", lease)
        self.assertIn("ScratchList", lease)
        self.assertIn("ConfinementRecoveryTest", lease)
        create = self.function_body("New-CatalogScratchKey", self.recovery)
        for required in (
            "SetAccessRuleProtection($true, $false)",
            "'S-1-5-18'",
            "'S-1-5-32-544'",
            "$readSid",
            "InheritanceFlags]::None, [System.Security.AccessControl.PropagationFlags]::None",
            "AreAccessRulesProtected",
            "-ne ($actual -join ',')",
            "-cne 'S-1-15-2-1' -and $readSid -cne 'S-1-15-2-2'",
        ):
            with self.subTest(required=required):
                self.assertIn(required, create)
        add = self.function_body("Add-CatalogScratchKeys", self.recovery)
        self.assertLess(add.index("'S-1-15-2-1'"), add.index("'S-1-15-2-2'"))
        self.assertLess(add.index("ScratchPaths.Aap"), add.index("ScratchPaths.Arap"))
        grant = self.function_body("Grant-WinsockCatalogRead", self.recovery)
        self.assertLess(grant.index("Start-CatalogRecovery"), grant.index("Add-CatalogScratchKeys"))
        self.assertLess(grant.index("Add-CatalogScratchKeys"), grant.index("Add-CatalogRead"))
        self.assertLess(grant.index("Restore-WinsockCatalogAcl"), grant.index("Remove-CatalogScratchKeys"))
        restore = self.function_body("Restore-WinsockCatalogAcl", self.recovery)
        self.assertLess(restore.index("Restore-CatalogAcl $lease"), restore.index("Remove-CatalogScratchKeys"))
        remove = self.function_body("Remove-CatalogScratchKeys", self.recovery)
        self.assertIn("$index -ge 0; $index--", remove)
        self.assertIn("DeleteSubKeyTree($path, $false)", remove)
        self.assertIn("'winsock_scratch_cleanup'", remove)
        self.assertIn("Assert-ScratchPath $path", remove)
        start = self.function_body("Start-CatalogRecovery", self.recovery)
        self.assertIn("ScratchPaths = @($lease.ScratchList)", start)
        watch = self.function_body("Invoke-CatalogWatch", self.recovery)
        self.assertIn("Remove-CatalogScratchKeys @($data.ScratchPaths)", watch)
        self.assertIn("Assert-ScratchPath ([string]$item)", watch)
        self.assertLess(watch.index("Restore-CatalogAcl $data"), watch.index("Remove-CatalogScratchKeys"))
        self.assertIn("-cmatch '^SOFTWARE\\\\KeelDock\\\\ConfinementRecoveryTest\\\\[a-f0-9]{32}\\z'", self.function_body("Assert-ScratchPath", self.recovery))
        for reason in ("'winsock_scratch_create'", "'winsock_scratch_cleanup'"):
            self.assertIn(reason, grant)
            self.assertIn(reason, self.wrapper)
        self.assertIn("Add-CatalogScratchKeys $lease", self.recovery_test)
        self.assertIn("recovery_test_scratch", self.recovery_test)
        self.assertIn("-Mode sid", WORKFLOW.read_text(encoding="utf-8"))

    def test_only_the_confinement_workflow_loads_the_spike_native_and_wrapper_files(self):
        names = ("windows_confinement.cs", "windows_confinement.ps1", "windows_confinement_recovery.ps1")
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

    def test_catalog_restore_is_attempted_even_when_scratch_deletion_fails(self):
        restore = self.function_body("Restore-WinsockCatalogAcl", self.recovery)
        first = restore.index("Restore-CatalogAcl $lease")
        second = restore.index("Remove-CatalogScratchKeys")
        self.assertLess(first, second)
        head = restore[:second]
        self.assertEqual(head.count("} catch {"), 1)
        self.assertLess(first, head.index("} catch {"))
        tail = restore[second:]
        self.assertIn("} catch {", tail)
        self.assertIn("if (-not $failure) { $failure = [string]$_.Exception.Message }", tail)
        self.assertIn("if ($failure) { throw $failure }", tail)
        self.assertEqual(restore.count("throw "), 1)
        watch = self.function_body("Invoke-CatalogWatch", self.recovery)
        restore_loop = watch.index("Restore-CatalogAcl $data")
        scratch_loop = watch.index("Remove-CatalogScratchKeys")
        self.assertLess(restore_loop, scratch_loop)
        between = watch[restore_loop:scratch_loop]
        self.assertNotIn("throw ", between)
        self.assertNotIn("return", between)
        self.assertIn("if (-not $restored -or -not $scratchGone) {", watch)
        self.assertLess(scratch_loop, watch.index("if (-not $restored -or -not $scratchGone) {"))
        grant = self.function_body("Grant-WinsockCatalogRead", self.recovery)
        armed_branch = grant[grant.index("Restore-WinsockCatalogAcl"):grant.index("Remove-CatalogScratchKeys")]
        self.assertIn("} else {", armed_branch)

    def test_winsock_recovery_survives_forced_parent_exit(self):
        start = self.function_body("Start-CatalogRecovery", self.recovery)
        watch = self.function_body("Invoke-CatalogWatch", self.recovery)
        for required in (
            "New-ScheduledTaskPrincipal -UserId 'SYSTEM'",
            "[IO.FileSystemAclExtensions]::Create($info, $security)",
            "S-1-5-32-544",
            "Get-FileHash -LiteralPath $copy",
            "-DeleteExpiredTaskAfter",
            "$trigger.EndBoundary",
            "GetFolderPath('CommonApplicationData')",
            "$shellHome.StartsWith($programFiles",
            "Contains('\"')",
            "Copy-Item -LiteralPath $source -Destination $copy",
            "Register-ScheduledTask",
            "Start-ScheduledTask",
            "Test-Path -LiteralPath $ready",
        ):
            self.assertIn(required, start)
        self.assertLess(start.index("Register-ScheduledTask"), start.index("Start-ScheduledTask"))
        self.assertLess(start.index("Start-ScheduledTask"), start.index("Test-Path -LiteralPath $ready"))
        self.assertIn("GetProcessById", watch)
        self.assertIn("ParentStartTicks", watch)
        self.assertIn("$parent.WaitForExit(250)", watch)
        self.assertIn("Restore-CatalogAcl $data", watch)
        self.assertIn("-not (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $record) 'armed'))", watch)
        self.assertIn("$child.Kill()", self.recovery_test)
        self.assertTrue(self.recovery_test.rstrip().endswith("exit 0"))
        self.assertIn("Get-CatalogAclSddl $Path) -eq $original", self.recovery_test)
        self.assertIn("-not (Test-Path -LiteralPath $directory)", self.recovery_test)
        self.assertIn("Remove-CatalogRecoveryFolder $record", watch)
        self.assertIn("-ne $recordHash", watch)
        self.assertIn("'recovery_test_leak'", self.recovery_test)
        self.assertIn("Grant-WinsockCatalogRead 'S-1-15-2-1-1-1-1-1-1-1' $Path -ForceReadbackFailure", self.recovery_test)
        self.assertIn("-not (Get-ScheduledTask -TaskName $taskName", self.recovery_test)
        self.assertIn("'^S-1-15-2-(?:[0-9]{1,10}-){6}[0-9]{1,10}\\z'", self.recovery)
        self.assertIn("$badSids = @('S-1-15-2-1-1-1-1-1-1-1-1', 'S-1-15-2-1-1-1-1-1-1', 'S-1-15-2-1-1-1-1-1-1-12345678901'", self.recovery_test)
        self.assertIn("'recovery_test_sid'", self.recovery_test)
        self.assertIn("test_windows_confinement_recovery.ps1 -Mode parent", WORKFLOW.read_text(encoding="utf-8"))

    def test_winsock_errors_use_fixed_reasons_and_verified_rollback(self):
        grant = self.function_body("Grant-WinsockCatalogRead", self.recovery)
        self.assertIn("Restore-WinsockCatalogAcl $script:WinsockCatalogLease", grant)
        self.assertIn("throw 'winsock_restore_failed'", grant)
        self.assertIn("throw $reason", grant)
        for name in ("Get-CatalogAclSddl", "Add-CatalogRead", "Restore-CatalogAcl", "Start-CatalogRecovery", "Stop-CatalogRecovery"):
            body = self.function_body(name, self.recovery)
            self.assertNotRegex(body, r"(?m)^\s*throw\s*$")
        self.assertIn("if ($phase -eq 'winsock_acl')", self.wrapper)
        self.assertIn("$reason = 'winsock_registry_error'", self.wrapper)
        self.assertIn("'winsock_grant_failed'", self.wrapper)
        self.assertIn("'winsock_restore_failed'", self.wrapper)
        add = self.function_body("Add-CatalogRead", self.recovery)
        self.assertIn("if ($ForceReadbackFailure) { throw 'winsock_catalog_readback' }", add)
        self.assertLess(add.index("$key.SetAccessControl($security)"), add.rindex("if ($ForceReadbackFailure)"))
        self.assertIn("-ForceReadbackFailure:$ForceReadbackFailure", grant)
        self.assertIn("Test-Path -LiteralPath ([string]$script:WinsockCatalogLease.ArmedFile)", grant)
        self.assertLess(grant.index("ArmedFile"), grant.index("Restore-WinsockCatalogAcl"))
        self.assertIn("Assert-CatalogPath $path", grant)
        confined = self.function_body("Invoke-ConfinedLadder")
        self.assertLess(confined.index("Grant-WinsockCatalogRead"), confined.index("$script:phase = 'ladder'"))
        self.assertIn("-ForceReadbackFailure", self.recovery_test)
        self.assertIn("recovery_test_lease", self.recovery_test)
        self.assertIn("Restore-CatalogAcl $lease", self.recovery_test)
        self.assertIn("$_.Exception.Message -ne 'winsock_restore_failed'", self.recovery_test)

    def test_task_removal_is_confirmed_before_the_recovery_folder_is_deleted(self):
        stop = self.function_body("Stop-CatalogRecovery", self.recovery)
        unregister = stop[stop.index("Unregister-ScheduledTask"):]
        self.assertIn("-ErrorAction Stop", unregister.splitlines()[0])
        absent = "if (Test-CatalogTaskPresent ([string]$lease.TaskName)) { throw 'winsock_recovery_stop' }"
        self.assertIn(absent, stop)
        self.assertLess(stop.index(absent), stop.index("$lease.TaskRegistered = $false"))
        self.assertLess(stop.index(absent), stop.index("Remove-Item"))
        self.assertNotIn("Unregister-ScheduledTask -TaskName ([string]$lease.TaskName) -Confirm:$false -ErrorAction SilentlyContinue", stop)
        remove = self.function_body("Remove-CatalogRecoveryFolder", self.recovery)
        gone = "if ($present) { return }"
        self.assertIn(gone, remove)
        self.assertLess(remove.index("Unregister-ScheduledTask"), remove.index(gone))
        helper = self.function_body("Test-CatalogTaskPresent", self.recovery)
        self.assertIn("Get-ScheduledTask -TaskName $taskName -ErrorAction Stop", helper)
        self.assertIn("CategoryInfo.Category -eq 'ObjectNotFound'", helper)
        self.assertNotIn("SilentlyContinue", helper)
        self.assertIn("if ($lease.TaskName -and $lease.RecoveryDirectory) {", stop)
        self.assertNotIn("Get-ScheduledTask", stop)
        self.assertLess(remove.index(gone), remove.index("Remove-Item"))

    def test_unarmed_lease_never_restores_the_live_key(self):
        restore = self.function_body("Restore-WinsockCatalogAcl", self.recovery)
        self.assertIn("-not (Test-Path -LiteralPath ([string]$lease.ArmedFile))", restore)
        self.assertNotIn("return", restore)
        self.assertLess(restore.index("ArmedFile"), restore.index("Restore-CatalogAcl $lease"))
        confined = self.function_body("Invoke-ConfinedLadder")
        self.assertIn("Restore-WinsockCatalogAcl $script:WinsockCatalogLease", confined)

    def test_scripts_have_no_line_starting_with_an_operator(self):
        starts = re.compile(r"^\s*-(and|or|band|bor|eq|ne|not)\b")
        ends = re.compile(r"(?:-(?:and|or|band|bor|eq|ne)|,|\|)\s*$")
        for path in (WRAPPER, RECOVERY, RECOVERY_TEST):
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
        for name in ("windows_confinement.ps1", "windows_confinement_recovery.ps1", "test_windows_confinement_recovery.ps1"):
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
        for required in ("NonPropagatingDacl]::Read", "NonPropagatingDacl]::Write", "AceFlags]::None", "1048704", "InsertAce(0, $ace)"):
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

    def test_unreadable_container_flag_hedge_is_spike_only_and_never_verifies(self):
        self.assertEqual(self.native.count("private const bool SpikeAllowUnreadableLpac = true;"), 1)
        for required in (
            'lpac != "1" && SpikeAllowUnreadableLpac && lpac == "unreadable" && sidState == "match"',
            '&& applicationPackages == "absent")',
            '(lpac == "1" && restrictedApplicationPackages != "present")',
            'reported = "aap_only";',
            '(lpac != "1" && reported != "aap_only")',
        ):
            with self.subTest(required=required):
                self.assertIn(required, self.native)
        self.assertNotIn('lpac == "0" &&', self.native)
        self.assertNotIn('restrictedApplicationPackages == "present" && applicationPackages', self.native)
        self.assertIn("arap=present", self.wrapper)
        self.assertIn("lpac=aap_only", self.wrapper)
        self.assertIn("$tokenState = 'aap_only'", self.wrapper)
        self.assertIn("-and $tokenState -eq 'verified'", self.wrapper)

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
            "ValidateSet('spike', 'compile', 'native-probe')",
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
