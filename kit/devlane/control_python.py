"""Load the pinned control-only Python dependencies inside trusted processes."""

import argparse
import base64
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import runpy
import stat
import subprocess
import sys

import refusal_codes


MANIFEST_NAME = ".control-crypto-manifest.json"
MAX_FILES = 10000
MAX_TREE_BYTES = 512 * 1024 * 1024
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
PINNED_VERSIONS = {
    "cffi": "2.1.1",
    "cryptography": "50.0.2",
    "pycparser": "3.12",
}
SHA256 = re.compile(r"[a-f0-9]{64}\Z")
_POWERSHELL_ACL_EXIT_REASONS = {
    3: "crypto-acl-reparse-point",
    4: "crypto-acl-owner-unresolved",
    5: "crypto-acl-owner-untrusted",
    6: "crypto-acl-writer-untrusted",
}
_POWERSHELL_ACL_CHECK_EXIT_REASONS = {
    code: (operation, "crypto-acl-check-" + operation)
    for operation, code in refusal_codes.WINDOWS_ACL_CHECK_OPERATIONS
}
_POWERSHELL_ACL_EXCEPTION_TYPES = frozenset((
    "UnauthorizedAccessException", "PrivilegeNotHeldException", "InvalidOperationException",
    "ArgumentException", "IdentityNotMappedException", "IOException", "other",
))
_POWERSHELL_ACL_CHECK_DIAGNOSTIC = re.compile(
    rb"windows_acl_check_failure=operation=([a-z-]+) exception=([A-Za-z]+)\Z"
)


def _powershell_acl_check_diagnostic(payload):
    if type(payload) is not bytes:
        return None
    normalized = payload.replace(b"\r\n", b"\n")
    if normalized.endswith(b"\n"):
        normalized = normalized[:-1]
    if b"\r" in normalized or b"\n" in normalized:
        return None
    match = _POWERSHELL_ACL_CHECK_DIAGNOSTIC.fullmatch(normalized)
    if match is None:
        return None
    operation, exception_type = (part.decode("ascii") for part in match.groups())
    if (exception_type not in _POWERSHELL_ACL_EXCEPTION_TYPES
            or operation not in {pair[0] for pair in _POWERSHELL_ACL_CHECK_EXIT_REASONS.values()}):
        return None
    return operation, exception_type


def _powershell_acl_exit_reason(exit_code, stdout=b"", stderr=b""):
    diagnostic = _powershell_acl_check_diagnostic(stdout)
    if diagnostic is not None and not stderr:
        operation, _exception_type = diagnostic
        for expected_exit, (expected_operation, reason) in _POWERSHELL_ACL_CHECK_EXIT_REASONS.items():
            if expected_exit == exit_code and expected_operation == operation:
                return reason
    if exit_code == 0:
        return None
    if exit_code in _POWERSHELL_ACL_EXIT_REASONS:
        return _POWERSHELL_ACL_EXIT_REASONS[exit_code]
    if type(exit_code) is int and 1 <= exit_code <= 31:
        return "crypto-acl-exit-" + str(exit_code)
    return "crypto-acl-exit-other"


class CryptoRefusal(ValueError):
    def __init__(self, reason):
        super().__init__("crypto-unavailable")
        self.reason = reason


def _refuse(reason="crypto-control-invalid"):
    if reason not in refusal_codes.CRYPTO_CONTROL_REFUSAL_CODES:
        reason = "crypto-control-invalid"
    raise CryptoRefusal(reason)


def _canonical_root(value):
    try:
        root = Path(value)
        if not root.is_absolute() or root.name != "control-python-deps":
            _refuse("crypto-target-invalid")
        if root.resolve(strict=True) != root:
            _refuse("crypto-target-invalid")
        metadata = root.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            _refuse("crypto-target-invalid")
        parent = root.parent.lstat()
        if not stat.S_ISDIR(parent.st_mode) or stat.S_ISLNK(parent.st_mode):
            _refuse("crypto-target-invalid")
        return root
    except CryptoRefusal:
        raise
    except (OSError, RuntimeError, TypeError, ValueError):
        _refuse("crypto-target-invalid")


def _powershell_acl_script(root):
    encoded_root = base64.b64encode(str(root).encode("utf-8")).decode("ascii")
    return r'''
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
function Stop-AclCheck([string]$Operation, [int]$Code, [object]$Failure) {
    $exception = $Failure.Exception
    $exceptionType = 'other'
    for ($depth = 0; $depth -lt 3 -and $null -ne $exception; $depth++) {
        $name = $exception.GetType().Name
        if (@('UnauthorizedAccessException', 'PrivilegeNotHeldException', 'InvalidOperationException',
              'ArgumentException', 'IdentityNotMappedException', 'IOException') -ccontains $name) {
            $exceptionType = $name
            break
        }
        $exception = $exception.InnerException
    }
    if (@('root-decode', 'owner-identity', 'owner-user-read', 'owner-token-read', 'trusted-sid-build',
          'write-mask-build', 'parent-resolve', 'parent-item', 'root-item', 'child-enumerate',
          'item-reparse-check', 'acl-read', 'acl-owner-read', 'acl-owner-translate', 'acl-owner-compare',
          'acl-rules-read', 'rule-propagation-read', 'rule-propagation-compare', 'rule-type-read',
          'rule-type-compare', 'rule-identity-read', 'rule-writer-compare', 'rule-rights-read',
          'rule-rights-compare', 'owner-output') -cnotcontains $Operation) {
        $Operation = 'owner-output'
        $Code = 31
    }
    Write-Output ('windows_acl_check_failure=operation=' + $Operation + ' exception=' + $exceptionType)
    exit $Code
}
try {
try { $root = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__ROOT__')) }
catch { Stop-AclCheck 'root-decode' 7 $_ }
try { $identity = [Security.Principal.WindowsIdentity]::GetCurrent() }
catch { Stop-AclCheck 'owner-identity' 8 $_ }
try { $ownerSid = $identity.User.Value; if ([string]::IsNullOrWhiteSpace($ownerSid)) { throw [InvalidOperationException]::new() } }
catch { Stop-AclCheck 'owner-user-read' 9 $_ }
try { $tokenOwnerSid = $identity.Owner.Value; if ([string]::IsNullOrWhiteSpace($tokenOwnerSid)) { throw [InvalidOperationException]::new() } }
catch { Stop-AclCheck 'owner-token-read' 10 $_ }
try {
    $trustedOwners = @($ownerSid, $tokenOwnerSid, 'S-1-5-18', 'S-1-5-32-544')
    $trustedWriters = @($ownerSid, $tokenOwnerSid, 'S-1-5-18', 'S-1-5-32-544')
} catch { Stop-AclCheck 'trusted-sid-build' 11 $_ }
try {
    $writeMask = [long]0x40000000 -bor [long]0x00000116 -bor [long]0x00010000 -bor `
                 [long]0x00000040 -bor [long]0x00040000 -bor [long]0x00080000
} catch { Stop-AclCheck 'write-mask-build' 12 $_ }
try { $parentPath = Split-Path -Parent $root }
catch { Stop-AclCheck 'parent-resolve' 13 $_ }
$items = @()
try {
    $parentItems = @(Get-Item -LiteralPath $parentPath -ErrorAction Stop)
    if ($parentItems.Count -ne 1) { throw [InvalidOperationException]::new() }
    $items += $parentItems
} catch { Stop-AclCheck 'parent-item' 14 $_ }
try {
    $rootItems = @(Get-Item -LiteralPath $root -ErrorAction Stop)
    if ($rootItems.Count -ne 1) { throw [InvalidOperationException]::new() }
    $items += $rootItems
} catch { Stop-AclCheck 'root-item' 15 $_ }
try { $children = @(Get-ChildItem -LiteralPath $root -Force -Recurse -ErrorAction Stop); $items += $children }
catch { Stop-AclCheck 'child-enumerate' 16 $_ }
foreach ($item in @($items)) {
    try { $isReparsePoint = (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) }
    catch { Stop-AclCheck 'item-reparse-check' 17 $_ }
    if ($isReparsePoint) { exit 3 }
    try { $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop }
    catch { Stop-AclCheck 'acl-read' 18 $_ }
    try {
        $ownerReference = $acl.GetOwner([Security.Principal.SecurityIdentifier])
        if ($null -eq $ownerReference) { throw [InvalidOperationException]::new() }
    } catch { Stop-AclCheck 'acl-owner-read' 19 $_ }
    try { $itemOwner = $ownerReference.Value }
    catch { Stop-AclCheck 'acl-owner-translate' 20 $_ }
    if ([string]::IsNullOrWhiteSpace($itemOwner)) { exit 4 }
    try { $ownerTrusted = $trustedOwners -ccontains $itemOwner }
    catch { Stop-AclCheck 'acl-owner-compare' 21 $_ }
    if (-not $ownerTrusted) { exit 5 }
    try { $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) }
    catch { Stop-AclCheck 'acl-rules-read' 22 $_ }
    foreach ($rule in $rules) {
        try { $propagation = $rule.PropagationFlags }
        catch { Stop-AclCheck 'rule-propagation-read' 23 $_ }
        try { $inheritOnly = (($propagation -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0) }
        catch { Stop-AclCheck 'rule-propagation-compare' 24 $_ }
        if ($inheritOnly) { continue }
        try { $ruleType = $rule.AccessControlType }
        catch { Stop-AclCheck 'rule-type-read' 25 $_ }
        try { $isAllow = ($ruleType -eq [Security.AccessControl.AccessControlType]::Allow) }
        catch { Stop-AclCheck 'rule-type-compare' 26 $_ }
        if (-not $isAllow) { continue }
        try { $sid = $rule.IdentityReference.Value }
        catch { Stop-AclCheck 'rule-identity-read' 27 $_ }
        try { $trustedWriter = $trustedWriters -ccontains $sid }
        catch { Stop-AclCheck 'rule-writer-compare' 28 $_ }
        if ($trustedWriter) { continue }
        try { $rights = [long]$rule.FileSystemRights }
        catch { Stop-AclCheck 'rule-rights-read' 29 $_ }
        try { $hasWriteRights = (($rights -band $writeMask) -ne 0) }
        catch { Stop-AclCheck 'rule-rights-compare' 30 $_ }
        if ($hasWriteRights) { exit 6 }
    }
}
try { [Console]::Out.WriteLine($ownerSid) }
catch { Stop-AclCheck 'owner-output' 31 $_ }
} catch { Stop-AclCheck 'owner-output' 31 $_ }
'''.replace("__ROOT__", encoded_root)


def _powershell_acl_command(root, powershell=None):
    if powershell is None:
        powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
            "System32/WindowsPowerShell/v1.0/powershell.exe"
        )
    encoded_script = base64.b64encode(_powershell_acl_script(root).encode("utf-16le")).decode("ascii")
    return [str(powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-OutputFormat", "Text",
            "-EncodedCommand", encoded_script]


def _powershell_acl_stdout_sid(payload):
    if type(payload) is not bytes:
        _refuse("crypto-acl-stdout-non-ascii")
    if payload.startswith(b"\xef\xbb\xbf"):
        payload = payload[3:]
    if b"\xef\xbb\xbf" in payload:
        _refuse("crypto-acl-stdout-bom-or-whitespace")
    try:
        payload.decode("ascii", "strict")
    except UnicodeError:
        _refuse("crypto-acl-stdout-non-ascii")
    if not payload:
        _refuse("crypto-acl-stdout-empty")
    normalized = payload.replace(b"\r\n", b"\n")
    if b"\r" in normalized:
        _refuse("crypto-acl-stdout-bom-or-whitespace")
    lines = normalized.split(b"\n")
    if lines[-1] == b"":
        lines.pop()
    if not lines or not lines[0]:
        _refuse("crypto-acl-stdout-empty")
    if len(lines) != 1:
        _refuse("crypto-acl-stdout-multiple-lines")
    line = lines[0]
    if any(byte in b" \t\v\f" for byte in line):
        _refuse("crypto-acl-stdout-bom-or-whitespace")
    if re.fullmatch(rb"S-1-(?:[0-9]+-)*[0-9]+", line) is None:
        _refuse("crypto-acl-stdout-not-sid")
    return line.decode("ascii")


def _powershell_acl_owner(root):
    """Return the current Windows SID after checking the control tree ACLs."""
    powershell = Path(os.environ.get("SystemRoot", r"C:\Windows")) / (
        "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    try:
        if not powershell.is_file():
            _refuse("crypto-acl-powershell-unavailable")
        result = subprocess.run(
            _powershell_acl_command(root, powershell),
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30, check=False,
        )
    except CryptoRefusal:
        raise
    except OSError:
        _refuse("crypto-acl-powershell-unavailable")
    except (subprocess.SubprocessError, UnicodeError, ValueError):
        _refuse("crypto-acl-process-failed")
    if result.returncode != 0:
        _refuse(_powershell_acl_exit_reason(result.returncode, result.stdout, result.stderr))
    if result.stderr:
        _refuse("crypto-acl-stderr-nonempty")
    return _powershell_acl_stdout_sid(result.stdout)


def _expected_owner(platform_name, owner_uid=None):
    if platform_name == "macos":
        if type(owner_uid) is not int or owner_uid <= 0 or owner_uid > 2**31 - 1:
            _refuse("crypto-platform-invalid")
        return owner_uid
    if platform_name == "windows":
        if owner_uid is not None:
            _refuse("crypto-platform-invalid")
        return None
    _refuse("crypto-platform-invalid")


def _check_posix_metadata(path, *, expected_uid, directory):
    try:
        metadata = path.lstat()
    except OSError:
        _refuse("crypto-metadata-invalid")
    if (metadata.st_uid != expected_uid or metadata.st_mode & 0o022
            or directory != stat.S_ISDIR(metadata.st_mode)
            or (not directory and not stat.S_ISREG(metadata.st_mode))
            or stat.S_ISLNK(metadata.st_mode)):
        _refuse("crypto-metadata-invalid")
    return metadata


def _hash_regular_file(path, *, expected_uid, platform_name):
    if platform_name == "macos":
        before = _check_posix_metadata(path, expected_uid=expected_uid, directory=False)
    else:
        try:
            before = path.lstat()
        except OSError:
            _refuse("crypto-file-invalid")
        if (stat.S_ISLNK(before.st_mode) or not stat.S_ISREG(before.st_mode)
                or getattr(before, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
            _refuse("crypto-file-invalid")
    digest = hashlib.sha256()
    count = 0
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        descriptor = os.open(str(path), flags)
        with os.fdopen(descriptor, "rb") as stream:
            opened = os.fstat(stream.fileno())
            if (not stat.S_ISREG(opened.st_mode) or opened.st_ino != before.st_ino
                    or opened.st_size != before.st_size):
                _refuse("crypto-file-invalid")
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    break
                count += len(chunk)
                if count > MAX_TREE_BYTES:
                    _refuse("crypto-file-invalid")
                digest.update(chunk)
    except (OSError, CryptoRefusal):
        _refuse("crypto-file-invalid")
    if count != before.st_size:
        _refuse("crypto-file-invalid")
    return count, digest.hexdigest()


def _tree_rows(root, *, platform_name, expected_uid=None):
    rows = []
    total = 0
    pending = [root]
    while pending:
        directory = pending.pop()
        if platform_name == "macos":
            metadata = _check_posix_metadata(directory, expected_uid=expected_uid, directory=True)
        else:
            try:
                metadata = directory.lstat()
            except OSError:
                _refuse("crypto-tree-invalid")
            if (not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)
                    or getattr(metadata, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
                _refuse("crypto-tree-invalid")
        del metadata
        try:
            with os.scandir(directory) as scanner:
                entries = sorted(scanner, key=lambda entry: entry.name, reverse=True)
        except OSError:
            _refuse("crypto-tree-invalid")
        for entry in entries:
            path = Path(entry.path)
            if path == root / MANIFEST_NAME:
                continue
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                _refuse("crypto-tree-invalid")
            if stat.S_ISLNK(info.st_mode):
                _refuse("crypto-tree-invalid")
            if stat.S_ISDIR(info.st_mode):
                pending.append(path)
                continue
            if not stat.S_ISREG(info.st_mode):
                _refuse("crypto-tree-invalid")
            size, digest = _hash_regular_file(path, expected_uid=expected_uid, platform_name=platform_name)
            total += size
            if total > MAX_TREE_BYTES or len(rows) >= MAX_FILES:
                _refuse("crypto-tree-invalid")
            rows.append({"path": path.relative_to(root).as_posix(), "size": size, "sha256": digest})
    rows.sort(key=lambda row: row["path"])
    if not rows:
        _refuse("crypto-tree-invalid")
    return rows


def _canonical_rows(rows):
    return json.dumps(rows, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _manifest_path(root):
    return root / MANIFEST_NAME


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _refuse("crypto-manifest-invalid")
        result[key] = value
    return result


def seal(target, platform_name, owner_uid=None):
    root = _canonical_root(target)
    if platform_name == "macos":
        owner = _expected_owner(platform_name, owner_uid)
        parent = _check_posix_metadata(root.parent, expected_uid=owner, directory=True)
        del parent
        _check_posix_metadata(root, expected_uid=owner, directory=True)
    elif platform_name == "windows":
        if owner_uid is not None:
            _refuse("crypto-platform-invalid")
        owner = _powershell_acl_owner(root)
    else:
        _refuse("crypto-platform-invalid")
    rows = _tree_rows(root, platform_name=platform_name, expected_uid=owner)
    tree_digest = hashlib.sha256(_canonical_rows(rows)).hexdigest()
    manifest = json.dumps({
        "schema": 1,
        "platform": platform_name,
        "owner": owner,
        "files": rows,
        "tree_sha256": tree_digest,
    }, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
    if len(manifest) > MAX_MANIFEST_BYTES:
        _refuse("crypto-manifest-invalid")
    path = _manifest_path(root)
    try:
        descriptor = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o444)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(manifest)
            stream.flush()
            os.fsync(stream.fileno())
        if platform_name == "windows":
            path.chmod(0o444)
    except OSError:
        _refuse("crypto-seal-write-failed")
    return owner


def _read_manifest(root, platform_name, expected_owner):
    path = _manifest_path(root)
    if platform_name == "macos":
        _check_posix_metadata(path, expected_uid=expected_owner, directory=False)
    try:
        info = path.lstat()
        if (stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode)
                or info.st_size > MAX_MANIFEST_BYTES):
            _refuse("crypto-manifest-invalid")
        payload = path.read_bytes()
        manifest = json.loads(payload.decode("ascii", "strict"), object_pairs_hook=_unique_pairs)
    except CryptoRefusal:
        raise
    except (OSError, UnicodeError, ValueError, TypeError):
        _refuse("crypto-manifest-invalid")
    if (type(manifest) is not dict or set(manifest) != {"schema", "platform", "owner", "files", "tree_sha256"}
            or type(manifest["schema"]) is not int or manifest["schema"] != 1
            or manifest["platform"] != platform_name
            or manifest["owner"] != expected_owner or type(manifest["files"]) is not list
            or type(manifest["tree_sha256"]) is not str or not SHA256.fullmatch(manifest["tree_sha256"])):
        _refuse("crypto-manifest-invalid")
    return manifest


def validate(target, platform_name, owner_uid=None):
    root = _canonical_root(target)
    if platform_name == "macos":
        owner = _expected_owner(platform_name, owner_uid)
        _check_posix_metadata(root.parent, expected_uid=owner, directory=True)
        _check_posix_metadata(root, expected_uid=owner, directory=True)
    elif platform_name == "windows":
        if owner_uid is not None:
            _refuse("crypto-platform-invalid")
        owner = _powershell_acl_owner(root)
    else:
        _refuse("crypto-platform-invalid")
    manifest = _read_manifest(root, platform_name, owner)
    rows = _tree_rows(root, platform_name=platform_name, expected_uid=owner)
    if (rows != manifest["files"]
            or hashlib.sha256(_canonical_rows(rows)).hexdigest() != manifest["tree_sha256"]):
        _refuse("crypto-tree-mismatch")
    return root


def _import_pinned_crypto(root):
    sys.path.insert(0, str(root))
    importlib.invalidate_caches()
    try:
        import cffi
        import cryptography
        import pycparser
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        modules = (cffi, cryptography, pycparser)
        if (tuple(module.__version__ for module in modules)
                != (PINNED_VERSIONS["cffi"], PINNED_VERSIONS["cryptography"], PINNED_VERSIONS["pycparser"])
                or AESGCM is None):
            _refuse("crypto-import-invalid")
        for module in modules:
            module_path = Path(module.__file__).resolve(strict=True)
            if not module_path.is_relative_to(root):
                _refuse("crypto-import-invalid")
    except Exception:
        _refuse("crypto-import-invalid")


def _run_script(root, script, arguments, *, platform_name, owner_uid, key_absent):
    try:
        validated_root = validate(root, platform_name, owner_uid)
        if key_absent and "DEVLANE_DECRYPT_KEY" in os.environ:
            _refuse("crypto-key-present")
        _import_pinned_crypto(validated_root)
        script_path = Path(script)
        if not script_path.is_absolute():
            script_path = Path.cwd() / script_path
        if not script_path.is_file() or script_path.is_symlink():
            _refuse("crypto-script-invalid")
    except CryptoRefusal:
        if Path(script).name in ("sandbox_macos.py", "sandbox_windows.py") and arguments[:1] == ["decrypt"]:
            print("devlane_supervisor_refusal=decrypt-rejected", file=sys.stderr)
            print("decrypt_refusal=crypto-unavailable", file=sys.stderr)
            return 2
        return 2
    sys.argv = [str(script_path), *arguments]
    runpy.run_path(str(script_path), run_name="__main__")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--platform", choices=("macos", "windows"), required=True)
    parser.add_argument("--owner-uid", type=int)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("seal")
    check = commands.add_parser("check")
    check.add_argument("--require-key-absent", action="store_true")
    run = commands.add_parser("run")
    run.add_argument("script")
    run.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    try:
        if args.command == "seal":
            seal(args.target, args.platform, args.owner_uid)
            return 0
        if args.command == "check":
            root = validate(args.target, args.platform, args.owner_uid)
            if args.require_key_absent and "DEVLANE_DECRYPT_KEY" in os.environ:
                _refuse("crypto-key-present")
            _import_pinned_crypto(root)
            return 0
        return _run_script(
            args.target, args.script, args.arguments, platform_name=args.platform,
            owner_uid=args.owner_uid, key_absent=False,
        )
    except CryptoRefusal as error:
        if args.command in ("seal", "check"):
            reason = (error.reason if error.reason in refusal_codes.CRYPTO_CONTROL_REFUSAL_CODES
                      else "crypto-control-invalid")
            print("devlane_crypto_refusal=" + reason, file=sys.stderr)
        return 2
    except Exception:
        if args.command in ("seal", "check"):
            print("devlane_crypto_refusal=crypto-control-invalid", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
