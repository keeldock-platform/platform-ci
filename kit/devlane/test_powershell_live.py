import base64
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from types import SimpleNamespace

import control_python


def _powershell_command(script, powershell):
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text",
            "-EncodedCommand", encoded]


_SAFE_EXIT_CODES = frozenset(range(32))
_SAFE_FAILURE_STAGES = frozenset((
    "powershell-missing", "fixture-create", "protected-run", "protected-parse", "extra-writer-exit",
))
_SAFE_FIXTURE_OPERATIONS = frozenset((
    "owner-identity", "protected-directory-create", "extra-writer-directory-create",
    "security-build", "acl-protection", "owner-rule-add", "system-rule-add",
    "administrators-rule-add", "everyone-rule-add", "inherit-only-rule-add",
    "apply-root-acl", "apply-protected-acl", "apply-extra-writer-acl", "other",
))
_SID = re.compile(rb"S-1-(?:[0-9]+-)*[0-9]+\Z")
_FIXTURE_DIAGNOSTIC = re.compile(
    rb"windows_acl_fixture_failure=operation=([a-z-]+) exception=([A-Za-z][A-Za-z0-9_]{0,63}) "
    rb"hresult=(0x[A-F0-9]{8})\Z"
)


def _fixture_diagnostic(payload):
    if type(payload) is not bytes or not payload:
        return None
    normalized = payload.replace(b"\r\n", b"\n")
    if b"\r" in normalized:
        return None
    if normalized.endswith(b"\n"):
        normalized = normalized[:-1]
    if b"\n" in normalized:
        return None
    match = _FIXTURE_DIAGNOSTIC.fullmatch(normalized)
    if match is None:
        return None
    operation, exception_type, hresult = (part.decode("ascii") for part in match.groups())
    if operation not in _SAFE_FIXTURE_OPERATIONS:
        return None
    return operation, exception_type, hresult


def _stdout_shape(payload):
    if type(payload) is not bytes or not payload:
        return "empty"
    if _fixture_diagnostic(payload) is not None:
        return "fixture-diagnostic"
    if control_python._powershell_acl_check_diagnostic(payload) is not None:
        return "check-diagnostic"
    if b"\xef\xbb\xbf" in payload:
        return "bom-or-whitespace"
    try:
        payload.decode("ascii", "strict")
    except UnicodeError:
        return "not-sid"
    normalized = payload.replace(b"\r\n", b"\n")
    if b"\r" in normalized:
        return "bom-or-whitespace"
    lines = normalized.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    if not lines or not lines[0]:
        return "empty"
    if len(lines) != 1:
        return "multiple-lines"
    if any(byte in b" \t\v\f" for byte in lines[0]):
        return "bom-or-whitespace"
    return "sid" if _SID.fullmatch(lines[0]) else "not-sid"


def _failure(stage, result=None):
    if stage not in _SAFE_FAILURE_STAGES:
        stage = "fixture-create"
    code = getattr(result, "returncode", None)
    exit_text = str(code) if type(code) is int and code in _SAFE_EXIT_CODES else "other"
    stderr = getattr(result, "stderr", b"")
    stdout = getattr(result, "stdout", b"")
    stderr_text = "present" if type(stderr) is bytes and stderr else "empty"
    diagnostic = _fixture_diagnostic(stdout) if stage == "fixture-create" else None
    if diagnostic is None and stage in ("protected-run", "extra-writer-exit"):
        diagnostic = control_python._powershell_acl_check_diagnostic(stdout)
    operation, exception_type, hresult = diagnostic if diagnostic is not None else ("none", "none", "none")
    print("windows_acl_live=failed stage=%s exit=%s stderr=%s stdout=%s operation=%s exception=%s hresult=%s" % (
        stage, exit_text, stderr_text, _stdout_shape(stdout), operation, exception_type, hresult,
    ))
    return 1


def _create_acl_fixtures(root, powershell):
    encoded_root = base64.b64encode(str(root).encode("utf-8")).decode("ascii")
    script = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__ROOT__'))
$script:FixtureOperations = @(
    'owner-identity', 'protected-directory-create', 'extra-writer-directory-create',
    'security-build', 'acl-protection', 'owner-rule-add', 'system-rule-add',
    'administrators-rule-add', 'everyone-rule-add', 'inherit-only-rule-add',
    'apply-root-acl', 'apply-protected-acl', 'apply-extra-writer-acl', 'other'
)
function Get-FixtureExceptionDiagnostic([object]$Failure) {
    $exception = $Failure.Exception
    $exceptionType = 'other'
    $exceptionHResult = 0
    for ($depth = 0; $depth -lt 4 -and $null -ne $exception; $depth++) {
        try { $name = [string]$exception.GetType().Name }
        catch { $name = '' }
        if ($name -cmatch '^[A-Za-z][A-Za-z0-9_]{0,63}$') {
            $exceptionType = $name
            try { $exceptionHResult = [int]$exception.HResult }
            catch { $exceptionHResult = 0 }
        }
        try { $exception = $exception.InnerException }
        catch { $exception = $null }
    }
    return $exceptionType + ' hresult=0x' + (('{0:x8}' -f $exceptionHResult).ToUpperInvariant())
}
function Stop-Fixture([string]$Operation, [int]$Code, [object]$Failure) {
    if ($script:FixtureOperations -cnotcontains $Operation) { $Operation = 'other' }
    Write-Output ('windows_acl_fixture_failure=operation=' + $Operation + ' exception=' + (Get-FixtureExceptionDiagnostic $Failure))
    exit $Code
}
function Add-FixtureRule(
    [System.Security.AccessControl.DirectorySecurity]$Security,
    [System.Security.Principal.SecurityIdentifier]$Principal,
    [System.Security.AccessControl.FileSystemRights]$Rights,
    [System.Security.AccessControl.InheritanceFlags]$Inheritance,
    [System.Security.AccessControl.PropagationFlags]$Propagation,
    [string]$Operation,
    [int]$Code
) {
    try {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $Principal, $Rights, $Inheritance, $Propagation,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$Security.AddAccessRule($rule)
    } catch { Stop-Fixture $Operation $Code $_ }
}
try { $identity = [Security.Principal.WindowsIdentity]::GetCurrent(); $owner = $identity.User }
catch { Stop-Fixture 'owner-identity' 1 $_ }
try {
    $system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
    $administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    $everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
} catch { Stop-Fixture 'owner-identity' 1 $_ }
function Set-PrivateAcl([string]$Path, [bool]$ExtraWriter, [bool]$InheritOnlyWriter, [string]$ApplyOperation, [int]$ApplyCode) {
    try { $security = [System.Security.AccessControl.DirectorySecurity]::new() }
    catch { Stop-Fixture 'security-build' 4 $_ }
    try { [void]$security.SetAccessRuleProtection($true, $false) }
    catch { Stop-Fixture 'acl-protection' 5 $_ }
    $inheritance = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor `
        [Security.AccessControl.InheritanceFlags]::ObjectInherit
    Add-FixtureRule $security $owner ([Security.AccessControl.FileSystemRights]::FullControl) $inheritance `
        ([Security.AccessControl.PropagationFlags]::None) 'owner-rule-add' 6
    Add-FixtureRule $security $system ([Security.AccessControl.FileSystemRights]::FullControl) $inheritance `
        ([Security.AccessControl.PropagationFlags]::None) 'system-rule-add' 7
    Add-FixtureRule $security $administrators ([Security.AccessControl.FileSystemRights]::FullControl) $inheritance `
        ([Security.AccessControl.PropagationFlags]::None) 'administrators-rule-add' 8
    if ($ExtraWriter) {
        Add-FixtureRule $security $everyone ([Security.AccessControl.FileSystemRights]::Modify) `
            ([Security.AccessControl.InheritanceFlags]::None) ([Security.AccessControl.PropagationFlags]::None) `
            'everyone-rule-add' 9
    }
    if ($InheritOnlyWriter) {
        Add-FixtureRule $security $everyone ([Security.AccessControl.FileSystemRights]::Modify) $inheritance `
            ([Security.AccessControl.PropagationFlags]::InheritOnly) 'inherit-only-rule-add' 10
    }
    try { ([IO.DirectoryInfo]$Path).SetAccessControl($security) }
    catch { Stop-Fixture $ApplyOperation $ApplyCode $_ }
}
Set-PrivateAcl $root $false $true 'apply-root-acl' 11
try { New-Item -ItemType Directory -Path (Join-Path $root 'protected') -ErrorAction Stop | Out-Null }
catch { Stop-Fixture 'protected-directory-create' 2 $_ }
try { New-Item -ItemType Directory -Path (Join-Path $root 'extra-writer') -ErrorAction Stop | Out-Null }
catch { Stop-Fixture 'extra-writer-directory-create' 3 $_ }
Set-PrivateAcl (Join-Path $root 'protected') $false $false 'apply-protected-acl' 12
Set-PrivateAcl (Join-Path $root 'extra-writer') $true $false 'apply-extra-writer-acl' 13
'''.replace("__ROOT__", encoded_root)
    return subprocess.run(
        _powershell_command(script, powershell), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
    )


def main():
    if os.name != "nt":
        print("windows_acl_live=skipped platform")
        return 0
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
        "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    if not powershell.is_file():
        return _failure("powershell-missing")
    root = None
    stage = "fixture-create"
    result = None
    try:
        root = Path(tempfile.mkdtemp(prefix="devlane-acl-"))
        result = _create_acl_fixtures(root, powershell)
        if result.returncode != 0 or result.stdout or result.stderr:
            return _failure(stage, result)
        stage = "protected-run"
        protected = subprocess.run(
            control_python._powershell_acl_command(root / "protected", powershell),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False,
        )
        if protected.returncode != 0 or protected.stderr:
            return _failure(stage, protected)
        stage = "protected-parse"
        try:
            control_python._powershell_acl_stdout_sid(protected.stdout)
        except (RuntimeError, ValueError):
            return _failure(stage, protected)
        stage = "extra-writer-exit"
        extra_writer = subprocess.run(
            control_python._powershell_acl_command(root / "extra-writer", powershell),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False,
        )
        if extra_writer.returncode != 6 or extra_writer.stdout or extra_writer.stderr:
            return _failure(stage, extra_writer)
        print("windows_acl_live=pass cases=2")
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError) as error:
        return _failure(stage, error)
    finally:
        if root is not None:
            shutil.rmtree(root, ignore_errors=True)


class LiveDiagnosticTests(unittest.TestCase):
    def test_stdout_shape_is_reduced_to_fixed_classes(self):
        cases = (
            (b"", "empty"),
            (b"S-1-5-21\nother\n", "multiple-lines"),
            (b"not-a-sid\n", "not-sid"),
            (b" \xef\xbb\xbfS-1-5-21\n", "bom-or-whitespace"),
            (b"S-1-5-21\r\n", "sid"),
        )
        for payload, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(_stdout_shape(payload), expected)

    def test_failure_marker_contains_only_allowlisted_facts(self):
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(_failure(
                "protected-parse",
                SimpleNamespace(returncode=2, stdout=b"privateSID", stderr=b"private path"),
            ), 1)
        self.assertEqual(
            output.getvalue(),
            "windows_acl_live=failed stage=protected-parse exit=2 stderr=present stdout=not-sid operation=none exception=none hresult=none\n",
        )

    def test_fixture_diagnostic_is_exact_and_allowlisted_before_emission(self):
        payload = b"windows_acl_fixture_failure=operation=apply-protected-acl exception=IOException hresult=0x80070005\r\n"
        self.assertEqual(_fixture_diagnostic(payload), ("apply-protected-acl", "IOException", "0x80070005"))
        self.assertEqual(_stdout_shape(payload), "fixture-diagnostic")
        self.assertIsNone(_fixture_diagnostic(
            b"windows_acl_fixture_failure=operation=private-path exception=IOException hresult=0x80070005\n",
        ))
        self.assertIsNone(_fixture_diagnostic(
            b"windows_acl_fixture_failure=operation=apply-root-acl exception=private-type hresult=0x80070005\n",
        ))
        self.assertIsNone(_fixture_diagnostic(
            b"windows_acl_fixture_failure=operation=apply-root-acl exception=IOException hresult=0x80070005\nextra\n",
        ))
        self.assertIsNone(_fixture_diagnostic(
            b"windows_acl_fixture_failure=operation=apply-root-acl exception=IOException hresult=0x8007000f\n",
        ))
        output = StringIO()
        with redirect_stdout(output):
            _failure("fixture-create", SimpleNamespace(
                returncode=11, stdout=payload, stderr=b"private path and identity",
            ))
        self.assertEqual(
            output.getvalue(),
            "windows_acl_live=failed stage=fixture-create exit=11 stderr=present "
            "stdout=fixture-diagnostic operation=apply-protected-acl exception=IOException hresult=0x80070005\n",
        )

    def test_acl_check_diagnostic_is_exact_and_maps_only_known_exit_operations(self):
        payload = b"windows_acl_check_failure=operation=child-enumerate exception=AclReadError_2 hresult=0x80070005\r\n"
        self.assertEqual(control_python._powershell_acl_check_diagnostic(payload),
                         ("child-enumerate", "AclReadError_2", "0x80070005"))
        self.assertEqual(control_python._powershell_acl_exit_reason(
            16, payload, b"",
        ), "crypto-acl-check-child-enumerate")
        self.assertEqual(control_python._powershell_acl_exit_reason(
            17, payload, b"",
        ), "crypto-acl-exit-17")
        self.assertIsNone(control_python._powershell_acl_check_diagnostic(
            b"windows_acl_check_failure=operation=private-path exception=IOException hresult=0x80070005\n",
        ))
        self.assertIsNone(control_python._powershell_acl_check_diagnostic(
            b"windows_acl_check_failure=operation=acl-read exception=private-type hresult=0x80070005\n",
        ))
        self.assertIsNone(control_python._powershell_acl_check_diagnostic(
            b"windows_acl_check_failure=operation=acl-read exception=IOException hresult=0x8007000f\n",
        ))
        self.assertIsNone(control_python._powershell_acl_check_diagnostic(
            payload + b"extra\n",
        ))
        output = StringIO()
        with redirect_stdout(output):
            _failure("protected-run", SimpleNamespace(
                returncode=16, stdout=payload, stderr=b"private path and identity",
            ))
        self.assertEqual(
            output.getvalue(),
            "windows_acl_live=failed stage=protected-run exit=16 stderr=present "
            "stdout=check-diagnostic operation=child-enumerate exception=AclReadError_2 hresult=0x80070005\n",
        )


if __name__ == "__main__":
    raise SystemExit(main())
