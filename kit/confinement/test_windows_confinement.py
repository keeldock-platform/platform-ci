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
    "acl_downloads_denied",
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
            "ReadToken(process, confined)",
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

    def test_wrapper_runs_the_stage_ladder_in_order_with_a_unconfined_control(self):
        names = re.findall(r"Name = '([a-z_]+)'; Exe", self.wrapper)
        self.assertEqual(tuple(names), CONFINED_STAGES)
        self.assertIn("$confinedOutcomes = Invoke-Ladder $box $true", self.wrapper)
        self.assertIn("$controlOutcomes = Invoke-Ladder $box $false", self.wrapper)
        self.assertLess(
            self.wrapper.index("Invoke-Ladder $box $true"),
            self.wrapper.index("Invoke-Ladder $box $false"),
        )

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

    def test_wrapper_grants_the_container_sid_only_read_execute_and_scratch_modify(self):
        self.assertIn("Grant-Access $layout.ReadOnly $script:Sid 'ReadAndExecute, Synchronize' $true", self.wrapper)
        self.assertIn("Grant-Access $layout.Scratch $script:Sid 'Modify, Synchronize' $true", self.wrapper)
        self.assertIn("'ReadAttributes, Synchronize' $false", self.wrapper)
        self.assertEqual(self.wrapper.count("Grant-Access $"), 3)
        self.assertIn("unexpected_rule", self.wrapper)

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
