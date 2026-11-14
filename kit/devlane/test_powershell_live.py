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


_SAFE_EXIT_CODES = frozenset((0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15))
_SAFE_FAILURE_STAGES = frozenset((
    "powershell-missing", "fixture-create", "protected-run", "protected-parse", "extra-writer-exit",
))
_SID = re.compile(rb"S-1-(?:[0-9]+-)*[0-9]+\Z")


def _stdout_shape(payload):
    if type(payload) is not bytes or not payload:
        return "empty"
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
    print("windows_acl_live=failed stage=%s exit=%s stderr=%s stdout=%s" % (
        stage, exit_text, stderr_text, _stdout_shape(stdout),
    ))
    return 1


def _create_acl_fixtures(root, powershell):
    encoded_root = base64.b64encode(str(root).encode("utf-8")).decode("ascii")
    script = r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$root = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__ROOT__'))
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$owner = $identity.User
$system = [Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$administrators = [Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$everyone = [Security.Principal.SecurityIdentifier]::new('S-1-1-0')
function Set-PrivateAcl([string]$Path, [bool]$ExtraWriter, [bool]$InheritOnlyWriter = $false) {
    $security = New-Object System.Security.AccessControl.DirectorySecurity
    [void]$security.SetAccessRuleProtection($true, $false)
    $security.SetOwner($owner)
    $principals = @($owner, $system, $administrators)
    foreach ($principal in $principals) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $principal,
            [Security.AccessControl.FileSystemRights]::FullControl,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
    }
    if ($ExtraWriter) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $everyone,
            [Security.AccessControl.FileSystemRights]::Modify,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
    }
    if ($InheritOnlyWriter) {
        $rule = [Security.AccessControl.FileSystemAccessRule]::new(
            $everyone,
            [Security.AccessControl.FileSystemRights]::Modify,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::InheritOnly,
            [Security.AccessControl.AccessControlType]::Allow
        )
        [void]$security.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $Path -AclObject $security -ErrorAction Stop | Out-Null
}
Set-PrivateAcl $root $false $true
New-Item -ItemType Directory -Path (Join-Path $root 'protected') -ErrorAction Stop | Out-Null
New-Item -ItemType Directory -Path (Join-Path $root 'extra-writer') -ErrorAction Stop | Out-Null
Set-PrivateAcl (Join-Path $root 'protected') $false
Set-PrivateAcl (Join-Path $root 'extra-writer') $true
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
            "windows_acl_live=failed stage=protected-parse exit=2 stderr=present stdout=not-sid\n",
        )


if __name__ == "__main__":
    raise SystemExit(main())
