import base64
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

import control_python


def _powershell_command(script, powershell):
    encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
    return [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text",
            "-EncodedCommand", encoded]


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
function Set-PrivateAcl([string]$Path, [bool]$ExtraWriter) {
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
    Set-Acl -LiteralPath $Path -AclObject $security -ErrorAction Stop | Out-Null
}
New-Item -ItemType Directory -Path (Join-Path $root 'protected') -ErrorAction Stop | Out-Null
New-Item -ItemType Directory -Path (Join-Path $root 'extra-writer') -ErrorAction Stop | Out-Null
Set-PrivateAcl $root $false
Set-PrivateAcl (Join-Path $root 'protected') $false
Set-PrivateAcl (Join-Path $root 'extra-writer') $true
'''.replace("__ROOT__", encoded_root)
    result = subprocess.run(
        _powershell_command(script, powershell), stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
    )
    return result.returncode == 0 and not result.stdout and not result.stderr


def main():
    if os.name != "nt":
        print("windows_acl_live=skipped platform")
        return 0
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
        "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    if not powershell.is_file():
        print("windows_acl_live=failed")
        return 1
    root = None
    try:
        root = Path(tempfile.mkdtemp(prefix="devlane-acl-"))
        if not _create_acl_fixtures(root, powershell):
            print("windows_acl_live=failed")
            return 1
        protected = subprocess.run(
            control_python._powershell_acl_command(root / "protected", powershell),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False,
        )
        if protected.returncode != 0 or protected.stderr:
            print("windows_acl_live=failed")
            return 1
        control_python._powershell_acl_stdout_sid(protected.stdout)
        extra_writer = subprocess.run(
            control_python._powershell_acl_command(root / "extra-writer", powershell),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False,
        )
        if extra_writer.returncode != 6:
            print("windows_acl_live=failed")
            return 1
        print("windows_acl_live=pass cases=2")
        return 0
    except (OSError, RuntimeError, subprocess.SubprocessError, ValueError):
        print("windows_acl_live=failed")
        return 1
    finally:
        if root is not None:
            shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    raise SystemExit(main())
