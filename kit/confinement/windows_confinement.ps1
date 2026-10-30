param(
    [ValidateSet('spike', 'compile', 'native-probe')]
    [string]$Mode = 'spike',
    [string]$ProbeId = ''
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$phase = 'control_identity'
$script:Redactions = @()
$exitCode = 1
$refusal = $null
$cleanup = 'verified'
$box = $null
$baseDirectory = $null
$componentNameExpected = $null
$componentNameObserved = $null
$script:WinsockCatalogLease = $null
. (Join-Path $PSScriptRoot 'windows_confinement_recovery.ps1')

$RustVersion = '1.99.1'
$RustTarget = 'x86_64-pc-windows-msvc'
$RustDate = '2026-10-15'
$NodeVersion = '24.22.1'
$ExpectedRustComponents = @{
    rustc = 'rustc'
    cargo = 'cargo'
    rust_std = ('rust-std-' + $RustTarget)
}
$Downloads = @(
    @{ Name = 'rustc'; File = 'rustc.tar.gz'; Url = ('https://static.rust-lang.org/dist/' + $RustDate + '/rustc-' + $RustVersion + '-' + $RustTarget + '.tar.gz'); Sha256 = '4e211ed2047e7890a8aea79fc8a88922d4c0e87a325349323d56c958d8da5d3a'; Root = ('rustc-' + $RustVersion + '-' + $RustTarget) },
    @{ Name = 'cargo'; File = 'cargo.tar.gz'; Url = ('https://static.rust-lang.org/dist/' + $RustDate + '/cargo-' + $RustVersion + '-' + $RustTarget + '.tar.gz'); Sha256 = 'bbf6e9295b69c9de8f2610e3e5bb90217d23826b7f2adac698262663a58ad899'; Root = ('cargo-' + $RustVersion + '-' + $RustTarget) },
    @{ Name = 'rust_std'; File = 'rust-std.tar.gz'; Url = ('https://static.rust-lang.org/dist/' + $RustDate + '/rust-std-' + $RustVersion + '-' + $RustTarget + '.tar.gz'); Sha256 = 'e856f160e01c31fe35aa7255579eed0774029882692d694736106f5883a96f22'; Root = ('rust-std-' + $RustVersion + '-' + $RustTarget) }
)
$NodeDownload = @{ Name = 'node'; File = 'node.zip'; Url = ('https://nodejs.org/dist/v' + $NodeVersion + '/node-v' + $NodeVersion + '-win-x64.zip'); Sha256 = 'd2046d28c2c3dcd211ac5145c0bf30e2047ef9dfb306693c8c6e2eccd8b95fa5' }
$NpmDownloads = @(
    @{ Name = 'lightningcss'; File = 'lightningcss.tgz'; Url = 'https://registry.npmjs.org/lightningcss-win32-x64-msvc/-/lightningcss-win32-x64-msvc-1.33.0.tgz'; Sri = 'sha512-OlEICDx/Xl0FqSp4bry8zFnCvGpig3Gl4gCquvYwHuqJKEC1+n9NgDniFvqHGmMv1ZkqDJrDqKKSykTDX+ehuA==' },
    @{ Name = 'rolldown'; File = 'rolldown.tgz'; Url = 'https://registry.npmjs.org/@rolldown/binding-win32-x64-msvc/-/binding-win32-x64-msvc-1.2.14.tgz'; Sri = 'sha512-9mE94bf2GZUaR/fUSXCMpBoWkctu421Mi0ORpm4zqfbkjKep7RxzPFa5etcGs5h+2KApoWBOA/hAJa/7saGgEQ==' }
)
$AllowedHosts = @('static.rust-lang.org', 'nodejs.org', 'registry.npmjs.org')

$CargoManifestText = "[package]`nname = `"kd_spike`"`nversion = `"0.1.0`"`nedition = `"2021`"`n`n[lib]`npath = `"src/lib.rs`"`n"
$RustSourceText = @'
pub fn add(left: u32, right: u32) -> u32 {
    left + right
}

KDHASH[cfg(test)]
mod tests {
    use super::*;

    KDHASH[test]
    fn adds_two_numbers() {
        assert_eq!(add(2, 3), 5);
    }
}
'@
$NodeTestText = @'
import { createRequire } from 'node:module';
import process from 'node:process';

const require = createRequire(import.meta.url);
const registered = [];
let currentSuite = '';

function describe(name, body) {
  currentSuite = name;
  body();
  currentSuite = '';
}

function it(name, body) {
  registered.push({ suite: currentSuite, name, body });
}

function expect(actual) {
  return {
    toBe(expected) {
      if (actual !== expected) {
        throw new Error('expected ' + String(expected) + ' received ' + String(actual));
      }
    },
    toContain(expected) {
      if (String(actual).indexOf(expected) < 0) {
        throw new Error('expected text containing ' + String(expected) + ' received ' + String(actual));
      }
    },
    toBeGreaterThan(expected) {
      if (!(actual > expected)) {
        throw new Error('expected above ' + String(expected) + ' received ' + String(actual));
      }
    },
  };
}

function label(text) {
  return String(text).replace(/[^A-Za-z0-9_.-]+/g, '_');
}

describe('runtime', () => {
  it('reports the pinned node on win32 x64', () => {
    expect(process.platform).toBe('win32');
    expect(process.arch).toBe('x64');
    expect(process.versions.node).toBe('24.22.1');
  });
});

describe('lightningcss win32 binding', () => {
  it('loads the native binding', () => {
    const binding = require(process.env.KD_LIGHTNINGCSS_NODE);
    expect(typeof binding.transform).toBe('function');
  });
  it('minifies a stylesheet', () => {
    const binding = require(process.env.KD_LIGHTNINGCSS_NODE);
    const output = binding.transform({ filename: 'kd.css', code: Buffer.from('a { color: red; }'), minify: true });
    expect(Buffer.from(output.code).toString('utf8')).toContain('color:red');
  });
});

describe('rolldown win32 binding', () => {
  it('loads the native binding', () => {
    const binding = require(process.env.KD_ROLLDOWN_NODE);
    expect(Object.keys(binding).length).toBeGreaterThan(0);
  });
});

let passed = 0;
let failed = 0;
for (const test of registered) {
  let outcome = 'pass';
  let message = '';
  try {
    test.body();
    passed += 1;
  } catch (error) {
    outcome = 'fail';
    failed += 1;
    message = String(error && error.message ? error.message : error).slice(0, 200);
  }
  console.log('kd-node-test suite=' + label(test.suite) + ' name=' + label(test.name) + ' result=' + outcome + (message ? ' message=' + label(message) : ''));
}
console.log('kd-node-summary passed=' + passed + ' failed=' + failed);
process.exitCode = failed === 0 ? 0 : 1;
'@

function Write-Line([string]$text) {
    [Console]::Out.WriteLine($text)
}

function Get-CleanText([string]$text, [int]$limit) {
    $value = [string]$text
    foreach ($item in $script:Redactions) {
        if (-not [string]::IsNullOrEmpty($item) -and $item.Length -gt 3) {
            $value = [regex]::Replace($value, [regex]::Escape($item), 'ROOT', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
        }
    }
    $value = $value.Replace("`r", '')
    $value = [regex]::Replace($value, '[^A-Za-z0-9 ._=/,\n-]', '?')
    if ($value.Length -gt $limit) { $value = $value.Substring(0, $limit) }
    return $value
}

function Get-SafeComponentName([string]$text) {
    $value = [regex]::Replace([string]$text, '[^A-Za-z0-9._-]', '_')
    if ($value.Length -gt 64) { $value = $value.Substring(0, 64) }
    if ($value.Length -eq 0) { return 'empty' }
    return $value
}

function Get-Token([string]$text, [string]$pattern) {
    $value = [string]$text
    if ($value -match $pattern) { return $value }
    return 'unknown'
}

function Write-DiagLines([string]$stage, [string]$stream, [string]$text) {
    $clean = Get-CleanText $text 2500
    foreach ($line in ($clean -split "`n")) {
        $trimmed = $line.TrimEnd()
        if ($trimmed.Length -gt 0) {
            Write-Line ('kd-diag stage=' + $stage + ' stream=' + $stream + ' line=' + $trimmed)
        }
    }
}

function Get-StatusName([uint32]$code) {
    switch ($code) {
        3221225781 { return 'dll_not_found' }
        3221225794 { return 'dll_init_failed' }
        3221225477 { return 'access_violation' }
        3221225506 { return 'access_denied_status' }
        3221226356 { return 'heap_corruption' }
        3221225485 { return 'status_invalid_parameter' }
        3221225595 { return 'bad_image_format' }
        3221225785 { return 'entrypoint_not_found' }
        3221226505 { return 'stack_buffer_overrun' }
        1262769995 { return 'job_terminated_by_harness' }
        default { return 'none' }
    }
}

function Invoke-Download($item) {
    $uri = [Uri]$item.Url
    if ($uri.Scheme -ne 'https' -or $AllowedHosts -notcontains $uri.Host) { throw 'download_host' }
    $target = Join-Path $script:Layout.Downloads $item.File
    $attempt = 0
    while ($true) {
        $attempt += 1
        $handler = New-Object System.Net.Http.HttpClientHandler
        $handler.MaxAutomaticRedirections = 5
        $client = New-Object System.Net.Http.HttpClient($handler)
        $cancel = New-Object System.Threading.CancellationTokenSource
        $cancel.CancelAfter([TimeSpan]::FromSeconds(120))
        $stream = $null
        $file = $null
        try {
            $response = $client.GetAsync($item.Url, [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead, $cancel.Token).GetAwaiter().GetResult()
            [void]$response.EnsureSuccessStatusCode()
            $stream = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
            $file = [IO.File]::Create($target)
            [void]$stream.CopyToAsync($file, 81920, $cancel.Token).GetAwaiter().GetResult()
            break
        } catch {
            if ($attempt -ge 2) { throw 'download_failed' }
            Start-Sleep -Seconds (5 * $attempt)
        } finally {
            if ($file) { $file.Dispose() }
            if ($stream) { $stream.Dispose() }
            $client.Dispose()
            $cancel.Dispose()
        }
    }
    return [string]$target
}

function Assert-Sha256([string]$path, [string]$expected, [string]$name) {
    $actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
    if ($actual -ne $expected) {
        $script:phase = 'fetch_hash_mismatch_' + $name
        throw 'hash_mismatch'
    }
}

function Assert-Sri([string]$path, [string]$sri, [string]$name) {
    if ($sri -notmatch '^sha512-([A-Za-z0-9+/]{86}==)$') { throw 'sri_shape' }
    $actual = [Convert]::ToBase64String([Convert]::FromHexString((Get-FileHash -Algorithm SHA512 -LiteralPath $path).Hash))
    if ($actual -ne $Matches[1]) {
        $script:phase = 'fetch_hash_mismatch_' + $name
        throw 'hash_mismatch'
    }
}

function Invoke-Tar([string]$archive, [string]$destination) {
    New-Item -ItemType Directory -Path $destination | Out-Null
    $tar = Join-Path $env:SystemRoot 'System32\tar.exe'
    & $tar -xzf $archive -C $destination | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'tar_failed' }
}

function Copy-Tree([string]$source, [string]$destination) {
    New-Item -ItemType Directory -Force -Path $destination | Out-Null
    & robocopy $source $destination /E /COPY:DAT /R:1 /W:1 /MT:16 /NFL /NDL /NJH /NJS /NP | Out-Null
    if ($LASTEXITCODE -ge 8) { throw 'robocopy_failed' }
    $global:LASTEXITCODE = 0
}

function Grant-Access([string]$path, [string]$sid, [string]$rights, [bool]$inherit) {
    $info = New-Object System.IO.DirectoryInfo($path)
    $security = [System.IO.FileSystemAclExtensions]::GetAccessControl($info, [System.Security.AccessControl.AccessControlSections]::Access)
    $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $flags = [System.Security.AccessControl.InheritanceFlags]::None
    if ($inherit) {
        $flags = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    }
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, [System.Security.AccessControl.FileSystemRights]$rights, $flags, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
    $security.AddAccessRule($rule)
    [System.IO.FileSystemAclExtensions]::SetAccessControl($info, $security)
}

function Set-LowIntegrityLabel([string]$path) {
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    & $icacls $path '/setintegritylevel' '(OI)(CI)L' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'integrity_set' }
    $global:LASTEXITCODE = 0
}

function Test-LowIntegrityLabel([string]$path) {
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    $output = & $icacls $path 2>$null
    $code = $LASTEXITCODE
    $global:LASTEXITCODE = 0
    if ($code -ne 0) { return $false }
    return [bool]($output -match 'Mandatory Label\\Low Mandatory Level:(?:\(I\))?\(OI\)\(CI\)\(NW\)')
}

function Grant-NonPropagating([string]$path, [string]$sid) {
    $bytes = [KeelDock.Platform.WindowsConfinement.NonPropagatingDacl]::Read($path)
    $descriptor = New-Object System.Security.AccessControl.RawSecurityDescriptor($bytes, 0)
    if ($null -eq $descriptor.DiscretionaryAcl) { throw 'dacl_missing' }
    $identity = New-Object System.Security.Principal.SecurityIdentifier($sid)
    $ace = New-Object System.Security.AccessControl.CommonAce([System.Security.AccessControl.AceFlags]::None, [System.Security.AccessControl.AceQualifier]::AccessAllowed, 1048704, $identity, $false, $null)
    $descriptor.DiscretionaryAcl.InsertAce(0, $ace)
    $updated = New-Object byte[] $descriptor.BinaryLength
    $descriptor.GetBinaryForm($updated, 0)
    [KeelDock.Platform.WindowsConfinement.NonPropagatingDacl]::Write($path, $updated)
}

function Get-SidRules([string]$path, [string]$sid) {
    $security = Get-Acl -LiteralPath $path
    $rules = $security.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
    return @($rules | Where-Object { $_.IdentityReference.Value -eq $sid })
}

function New-ScratchSet([string]$root) {
    return @{
        Root = $root
        Tmp = (Join-Path $root 'tmp')
        Profile = (Join-Path $root 'profile')
        CargoHome = (Join-Path $root 'cargo-home')
        Crate = (Join-Path $root 'crate')
    }
}

function Test-Acl {
    $sid = $script:Sid
    $writeMask = [System.Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteAttributes, WriteExtendedAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    $readMask = [System.Security.AccessControl.FileSystemRights]'ReadAndExecute'
    $ro = @(Get-SidRules $script:Layout.ReadOnly $sid)
    if ($ro.Count -ne 1 -or ($ro[0].FileSystemRights -band $writeMask) -ne 0 -or ($ro[0].FileSystemRights -band $readMask) -ne $readMask -or $ro[0].AccessControlType -ne 'Allow') { return 'ro_rule' }
    $scratch = @(Get-SidRules $script:Lpac.Root $sid)
    $modifyMask = [System.Security.AccessControl.FileSystemRights]'Modify'
    if ($scratch.Count -ne 1 -or ($scratch[0].FileSystemRights -band $modifyMask) -ne $modifyMask -or $scratch[0].AccessControlType -ne 'Allow') { return 'scratch_rule' }
    foreach ($path in @($script:Layout.Downloads, $script:Control.Root, $script:Control.Tmp, $script:Control.Crate)) {
        if (@(Get-SidRules $path $sid).Count -ne 0) { return 'unexpected_rule' }
    }
    $attributeMask = [System.Security.AccessControl.FileSystemRights]'ReadAttributes, Synchronize'
    foreach ($path in $script:AncestorPaths) {
        $entries = @(Get-SidRules $path $sid)
        if ($entries.Count -ne 1) { return 'ancestor_rule' }
        if ($entries[0].FileSystemRights -ne $attributeMask -or $entries[0].AccessControlType -ne 'Allow' -or $entries[0].IsInherited) { return 'ancestor_rule' }
        if ($entries[0].InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None -or $entries[0].PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) { return 'ancestor_rule' }
    }
    foreach ($path in @(($script:Layout.RustBin + '\rustc.exe'), ($script:Layout.MsvcBin + '\link.exe'), ($script:Layout.NodeDir + '\node.exe'), $script:Layout.LightningcssBinding, $script:Layout.RolldownBinding, $script:Layout.NodeTest, $script:Layout.NativeProbeScript, $script:Layout.NativeProbeSource, $script:Layout.NativeProbeRecovery)) {
        if (@(Get-SidRules $path $sid).Count -lt 1) { return 'not_inherited' }
    }
    foreach ($path in @($script:Lpac.Tmp, $script:Lpac.Profile, $script:Lpac.CargoHome, $script:Lpac.Crate, (Join-Path $script:Lpac.Crate 'src'))) {
        $entries = @(Get-SidRules $path $sid)
        if ($entries.Count -ne 1 -or -not $entries[0].IsInherited -or $entries[0].AccessControlType -ne 'Allow' -or ($entries[0].FileSystemRights -band $modifyMask) -ne $modifyMask) { return 'scratch_not_inherited' }
        if (-not (Test-LowIntegrityLabel $path)) { return 'scratch_integrity' }
    }
    if (-not (Test-LowIntegrityLabel $script:Lpac.Root)) { return 'scratch_integrity' }
    return 'verified'
}

function New-StageEnvironment([hashtable]$scratch, [string]$targetName) {
    $layout = $script:Layout
    $searchPath = @($layout.RustBin, $layout.NodeDir, $layout.MsvcBin, (Join-Path $env:SystemRoot 'System32'), $env:SystemRoot) -join ';'
    return [string[]]@(
        ('SystemRoot=' + $env:SystemRoot),
        ('windir=' + $env:SystemRoot),
        ('SystemDrive=' + $env:SystemDrive),
        ('ComSpec=' + (Join-Path $env:SystemRoot 'System32\cmd.exe')),
        ('PATH=' + $searchPath),
        ('TEMP=' + $scratch.Tmp),
        ('TMP=' + $scratch.Tmp),
        ('USERPROFILE=' + $scratch.Profile),
        ('APPDATA=' + $scratch.Profile),
        ('LOCALAPPDATA=' + $scratch.Profile),
        ('CARGO_HOME=' + $scratch.CargoHome),
        ('CARGO_TARGET_DIR=' + (Join-Path $scratch.Root $targetName)),
        ('CARGO_INCREMENTAL=0'),
        ('CARGO_NET_OFFLINE=true'),
        ('CARGO_BUILD_JOBS=2'),
        ('CARGO_TERM_COLOR=never'),
        ('NO_COLOR=1'),
        ('RUSTC=' + $layout.RustBin + '\rustc.exe'),
        ('LIB=' + $layout.MsvcLib + ';' + $layout.SdkUcrt + ';' + $layout.SdkUm),
        ('RUSTFLAGS=-C linker=' + $layout.MsvcBin + '\link.exe -C debuginfo=0 -C link-arg=/DEBUG:NONE'),
        ('KD_LIGHTNINGCSS_NODE=' + $layout.LightningcssBinding),
        ('KD_ROLLDOWN_NODE=' + $layout.RolldownBinding)
    )
}

function Get-NativeProbeArguments([string]$probeId) {
    if (-not [KeelDock.Platform.WindowsConfinement.NativeRegistryProbe]::IsKnownProbeId($probeId)) { throw 'registry_probe_id' }
    return ('-NoLogo -NoProfile -NonInteractive -File "' + $script:Layout.NativeProbeScript + '" -Mode native-probe -ProbeId ' + $probeId)
}

function Get-WinsockProbeSpecs {
    $lease = $script:WinsockCatalogLease
    if ($null -eq $lease) { return @() }
    $probeExe = Join-Path $PSHOME 'pwsh.exe'
    $classes = @(
        @{ Name = 'parameters'; Pattern = '^Parameters\z'; ProbeId = 'winsock_parameters' },
        @{ Name = 'protocol_catalog'; Pattern = '^Parameters\\Protocol_Catalog9\z'; ProbeId = 'winsock_protocol_catalog' },
        @{ Name = 'namespace_catalog'; Pattern = '^Parameters\\NameSpace_Catalog5\z'; ProbeId = 'winsock_namespace_catalog' },
        @{ Name = 'protocol_entries'; Pattern = '^Parameters\\Protocol_Catalog9\\Catalog_Entries\z'; ProbeId = 'winsock_protocol_entries' },
        @{ Name = 'protocol_entries64'; Pattern = '^Parameters\\Protocol_Catalog9\\Catalog_Entries64\z'; ProbeId = 'winsock_protocol_entries64' },
        @{ Name = 'namespace_entries'; Pattern = '^Parameters\\NameSpace_Catalog5\\Catalog_Entries\z'; ProbeId = 'winsock_namespace_entries' },
        @{ Name = 'namespace_entries64'; Pattern = '^Parameters\\NameSpace_Catalog5\\Catalog_Entries64\z'; ProbeId = 'winsock_namespace_entries64' },
        @{ Name = 'protocol_entry'; Pattern = '^Parameters\\Protocol_Catalog9\\Catalog_Entries\\[0-9]{12}\z'; ProbePrefix = 'winsock_protocol_entry_' },
        @{ Name = 'protocol_entry64'; Pattern = '^Parameters\\Protocol_Catalog9\\Catalog_Entries64\\[0-9]{12}\z'; ProbePrefix = 'winsock_protocol_entry64_' },
        @{ Name = 'namespace_entry'; Pattern = '^Parameters\\NameSpace_Catalog5\\Catalog_Entries\\[0-9]{12}\z'; ProbePrefix = 'winsock_namespace_entry_' },
        @{ Name = 'namespace_entry64'; Pattern = '^Parameters\\NameSpace_Catalog5\\Catalog_Entries64\\[0-9]{12}\z'; ProbePrefix = 'winsock_namespace_entry64_' }
    )
    $prefix = 'SYSTEM\CurrentControlSet\Services\WinSock2\'
    $specs = @()
    foreach ($class in $classes) {
        foreach ($item in @($lease.KeyList)) {
            $path = [string]$item.Path
            if (-not $path.StartsWith($prefix, [StringComparison]::Ordinal)) { continue }
            if ($path.Substring($prefix.Length) -cmatch $class.Pattern) {
                $probeId = [string]$class.ProbeId
                if ($class.ContainsKey('ProbePrefix')) { $probeId = [string]$class.ProbePrefix + [string]$path.Substring($path.LastIndexOf('\') + 1) }
                $probeArguments = Get-NativeProbeArguments $probeId
                $specs += @{ Name = ('winsock_key_' + $class.Name); Exe = $probeExe; Arguments = $probeArguments; Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match 'status=ok' } }
                break
            }
        }
    }
    $controlName = 'lpac_default_key_control'
    $controlArguments = Get-NativeProbeArguments 'lpac_default_key_control'
    $specs += @{ Name = $controlName; Exe = $probeExe; Arguments = $controlArguments; Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match 'status=ok' } }
    return $specs
}

function Get-LpacDiscriminatorSpecs {
    $lease = $script:WinsockCatalogLease
    if ($null -eq $lease -or $null -eq $lease.ScratchPaths) { return @() }
    $probeExe = Join-Path $PSHOME 'pwsh.exe'
    $arapName = 'lpac_discriminator_arap'
    $aapName = 'lpac_discriminator_aap'
    $arapPath = [string]$lease.ScratchPaths.Arap
    $aapPath = [string]$lease.ScratchPaths.Aap
    Assert-ScratchPath $arapPath
    Assert-ScratchPath $aapPath
    $arapId = 'lpac_discriminator_arap_' + $arapPath.Substring($arapPath.LastIndexOf('\') + 1)
    $aapId = 'lpac_discriminator_aap_' + $aapPath.Substring($aapPath.LastIndexOf('\') + 1)
    $specs = @()
    $arapArguments = Get-NativeProbeArguments $arapId
    $aapArguments = Get-NativeProbeArguments $aapId
    $specs += @{ Name = $arapName; Exe = $probeExe; Arguments = $arapArguments; Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match 'status=ok' } }
    $specs += @{ Name = $aapName; Exe = $probeExe; Arguments = $aapArguments; Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match 'status=access_denied ntstatus=0xC0000022' } }
    return $specs
}

function Get-LpacBehaviour($outcomes) {
    $arap = $outcomes['lpac_discriminator_arap']
    $aap = $outcomes['lpac_discriminator_aap']
    if ($null -eq $arap -or $null -eq $aap -or -not $arap.Ran -or -not $aap.Ran) { return 'inconclusive' }
    if ($arap.Stdout -notmatch 'status=ok') { return 'inconclusive' }
    if ($aap.Stdout -match 'status=ok') { return 'not_lpac' }
    if ($aap.Stdout -match 'status=access_denied ntstatus=0xC0000022') { return 'behavioural' }
    return 'inconclusive'
}

function Get-StageSpecs([bool]$confined, [hashtable]$scratch) {
    $layout = $script:Layout
    $cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $cargoManifest = Join-Path $scratch.Crate 'Cargo.toml'
    $specs = @()
    if ($confined) {
        $specs += @(Get-WinsockProbeSpecs)
        $specs += @(Get-LpacDiscriminatorSpecs)
        $specs += @{ Name = 'cmd_exec'; Exe = $cmd; Arguments = '/d /c echo kd-lpac-cmd'; Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match 'kd-lpac-cmd' } }
        $specs += @{ Name = 'acl_ro_read'; Exe = $cmd; Arguments = ('/d /c dir /b ' + $layout.RustBin); Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match 'rustc\.exe' } }
        $specs += @{ Name = 'acl_scratch_write'; Exe = $cmd; Arguments = ('/d /c copy /y nul ' + $scratch.Tmp + '\kd_write.txt'); Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and (Test-Path -LiteralPath ($script:Lpac.Tmp + '\kd_write.txt')) } }
        $specs += @{ Name = 'acl_ro_write_denied'; Exe = $cmd; Arguments = ('/d /c copy /y nul ' + $layout.ReadOnly + '\kd_write_probe.txt'); Timeout = 30; Check = { param($r) $r.ExitCode -ne 0 -and (($r.Stdout + $r.Stderr) -match 'Access is denied') -and -not (Test-Path -LiteralPath ($script:Layout.ReadOnly + '\kd_write_probe.txt')) } }
        $specs += @{ Name = 'acl_downloads_denied'; Exe = $cmd; Arguments = ('/d /c type "' + $layout.Downloads + '\acl_probe.txt"'); Timeout = 30; Check = { param($r) $r.ExitCode -ne 0 -and (($r.Stdout + $r.Stderr) -match 'Access is denied') } }
    } else {
        $specs += @{ Name = 'acl_downloads_listable'; Exe = $cmd; Arguments = ('/d /c dir /b ' + $layout.Downloads); Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match 'rustc\.tar\.gz' } }
    }
    $specs += @{ Name = 'rustc_version'; Exe = ($layout.RustBin + '\rustc.exe'); Arguments = '--version --verbose'; Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match '(?m)^rustc 1\.99\.1 ' -and $r.Stdout -match '(?m)^host: x86_64-pc-windows-msvc' } }
    $specs += @{ Name = 'cargo_version'; Exe = ($layout.RustBin + '\cargo.exe'); Arguments = '--version'; Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match '(?m)^cargo (0\.100\.0|1\.99\.[01]) ' } }
    $specs += @{ Name = 'link_banner'; Exe = ($layout.MsvcBin + '\link.exe'); Arguments = '/?'; Timeout = 30; Check = { param($r) $r.Stdout -match 'Incremental Linker' } }
    $specs += @{ Name = 'rust_build'; Exe = ($layout.RustBin + '\cargo.exe'); Arguments = ('build --offline --manifest-path ' + $cargoManifest); Timeout = 240; Check = { param($r) $r.ExitCode -eq 0 } }
    $specs += @{ Name = 'rust_test'; Exe = ($layout.RustBin + '\cargo.exe'); Arguments = ('test --offline --manifest-path ' + $cargoManifest); Timeout = 240; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match 'test result: ok\. 1 passed; 0 failed' } }
    $specs += @{ Name = 'node_version'; Exe = ($layout.NodeDir + '\node.exe'); Arguments = '--version'; Timeout = 30; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout.Trim() -eq 'v24.22.1' } }
    $specs += @{ Name = 'node_bindings'; Exe = ($layout.NodeDir + '\node.exe'); Arguments = $layout.NodeTest; Timeout = 60; Check = { param($r) $r.ExitCode -eq 0 -and $r.Stdout -match 'kd-node-summary passed=4 failed=0' } }
    return $specs
}

function Assert-RustLicenseAdmission([bool]$confined) {
    if (-not $confined -or $env:CI_MODE -ne 'source') { return }
    throw 'archive_producer_unavailable'
}

function Invoke-Ladder($sandbox, [bool]$confined, [hashtable]$scratch) {
    $outcomes = [ordered]@{}
    Assert-RustLicenseAdmission $confined
    $targetName = 'target-control'
    if ($confined) { $targetName = 'target-lpac' }
    $environment = New-StageEnvironment $scratch $targetName
    foreach ($spec in (Get-StageSpecs $confined $scratch)) {
        $commandLine = '"' + $spec.Exe + '" ' + $spec.Arguments
        $result = $sandbox.Run($confined, $spec.Exe, $commandLine, $scratch.Root, $environment, ([int]$spec.Timeout * 1000), [uint32]32)
        $passed = $false
        if ($result.Failure -eq '' -and $result.Exited -and -not $result.TimedOut) {
            $passed = [bool](& $spec.Check $result)
        }
        $exitText = '0x' + ([uint32]$result.ExitCode).ToString('x8')
        $jobText = Get-Token ($result.Job -replace ' ', ',') '^[A-Za-z0-9=,_.-]{1,120}$'
        $tokenText = Get-Token ($result.Token -replace ' ', ',') '^[A-Za-z0-9=,_.-]{1,120}$'
        $failureText = Get-Token $result.Failure '^[a-z_]{0,24}$'
        $verdict = 'failed'
        if ($passed) { $verdict = 'ok' }
        Write-Line ('windows-confinement-stage=' + $spec.Name + ' confined=' + $confined.ToString().ToLowerInvariant() + ' result=' + $verdict + ' exit=' + $exitText + ' status=' + (Get-StatusName ([uint32]$result.ExitCode)) + ' ms=' + $result.ElapsedMs + ' timed_out=' + $result.TimedOut.ToString().ToLowerInvariant() + ' failure=' + $failureText + ' create_error=' + $result.CreateError + ' job=' + $jobText + ' token=' + $tokenText)
        if (-not $passed) {
            if ($result.Detail) { Write-DiagLines $spec.Name 'detail' $result.Detail }
            Write-DiagLines $spec.Name 'stdout' $result.Stdout
            Write-DiagLines $spec.Name 'stderr' $result.Stderr
        } else {
            $firstLine = ($result.Stdout -split "`n" | Where-Object { $_.Trim().Length -gt 0 } | Select-Object -First 1)
            if ($firstLine) { Write-Line ('kd-diag stage=' + $spec.Name + ' stream=first line=' + (Get-CleanText $firstLine.Trim() 160)) }
        }
        $lpacProven = ($tokenText -like 'appcontainer=1,*') -and ($tokenText -like '*,lpac=1,*') -and ($tokenText -like '*,sid=match,*') -and ($tokenText -like '*,arap=present,*') -and ($tokenText -like '*,aap=absent')
        $outcomes[$spec.Name] = @{ Passed = $passed; Job = ($jobText -like 'assigned,*'); Token = $lpacProven; AapOnly = ($tokenText -like '*,lpac=aap_only,*'); Stdout = [string]$result.Stdout; Ran = ($result.Failure -eq '' -and $result.Exited -and -not $result.TimedOut); ExitCode = [uint32]$result.ExitCode; Output = ([string]$result.Stdout + [string]$result.Stderr) }
    }
    return $outcomes
}

function Invoke-ConfinedLadder($sandbox, [hashtable]$scratch) {
    try {
        $script:WinsockCatalogLease = Grant-WinsockCatalogRead $script:Sid
        $script:phase = 'ladder'
        return Invoke-Ladder $sandbox $true $scratch
    } finally {
        if ($script:WinsockCatalogLease) {
            try {
                Restore-WinsockCatalogAcl $script:WinsockCatalogLease
                Stop-CatalogRecovery $script:WinsockCatalogLease
            } catch {
                $script:phase = 'winsock_acl'
                throw
            }
            $script:WinsockCatalogLease = $null
        }
    }
}


try {
    if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) { throw 'platform' }
    $phase = 'runtime'
    [void](Add-Type -Path (Join-Path $PSScriptRoot 'windows_confinement.cs') -ErrorAction Stop)
    if ($Mode -eq 'native-probe') {
        $phase = 'native_probe'
        Write-Line ([KeelDock.Platform.WindowsConfinement.NativeRegistryProbe]::Probe($ProbeId))
        $exitCode = 0
    } elseif ($Mode -eq 'compile') {
        Write-Line 'windows-confinement-compile=observed result=compiled'
        $exitCode = 0
    } else {
        $phase = 'control_identity'
        if ($env:CI_EVENT_NAME -ne 'workflow_dispatch' -or $env:CI_REF -ne 'refs/heads/main') { throw 'control' }
        if ($env:CI_REPOSITORY -ne 'keeldock-platform/platform-ci' -or $env:CI_SERVER_URL -ne 'https://github.com') { throw 'control' }
        if ($env:CI_SHA -notmatch '^[a-f0-9]{40}$') { throw 'control' }
        $root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
        $workspace = [IO.Path]::GetFullPath($env:CI_WORKSPACE)
        if (-not [string]::Equals($root, $workspace, [StringComparison]::OrdinalIgnoreCase)) { throw 'control' }
        $actualSha = git -C $root rev-parse --verify HEAD 2>$null
        if ($LASTEXITCODE -ne 0 -or $actualSha.Trim() -ne $env:CI_SHA) { throw 'control' }

        $phase = 'image_record'
        $imageOs = Get-Token $env:ImageOS '^[A-Za-z0-9._-]{1,32}$'
        $imageVersion = Get-Token $env:ImageVersion '^[A-Za-z0-9._-]{1,32}$'
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
        $vsPath = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath | Select-Object -First 1)
        $vsVersion = (& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationVersion | Select-Object -First 1)
        if (-not $vsPath -or -not (Test-Path -LiteralPath $vsPath)) { throw 'msvc_missing' }
        $msvcVersion = (Get-Content -LiteralPath (Join-Path $vsPath 'VC\Auxiliary\Build\Microsoft.VCToolsVersion.default.txt') | Select-Object -First 1).Trim()
        $msvcRoot = Join-Path $vsPath ('VC\Tools\MSVC\' + $msvcVersion)
        $sdkLibRoot = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\Lib'
        $sdkVersion = (Get-ChildItem -LiteralPath $sdkLibRoot -Directory | Where-Object { $_.Name -match '^10\.0\.[0-9]+\.[0-9]+$' -and (Test-Path -LiteralPath (Join-Path $_.FullName 'ucrt\x64\ucrt.lib')) -and (Test-Path -LiteralPath (Join-Path $_.FullName 'um\x64\kernel32.lib')) } | Sort-Object { [Version]$_.Name } -Descending | Select-Object -First 1).Name
        if (-not $sdkVersion) { throw 'sdk_missing' }
        $msvcBinSource = Join-Path $msvcRoot 'bin\Hostx64\x64'
        $msvcLibSource = Join-Path $msvcRoot 'lib\x64'
        $sdkUcrtSource = Join-Path $sdkLibRoot ($sdkVersion + '\ucrt\x64')
        $sdkUmSource = Join-Path $sdkLibRoot ($sdkVersion + '\um\x64')
        foreach ($source in @($msvcBinSource, $msvcLibSource, $sdkUcrtSource, $sdkUmSource)) {
            if (-not (Test-Path -LiteralPath $source -PathType Container)) { throw 'msvc_layout' }
        }
        if (-not (Test-Path -LiteralPath (Join-Path $msvcBinSource 'link.exe'))) { throw 'msvc_layout' }
        Write-Line ('windows-confinement-image=recorded image_os=' + $imageOs + ' image_version=' + $imageVersion + ' vs_version=' + (Get-Token ([string]$vsVersion) '^[0-9.]{1,32}$') + ' msvc_version=' + (Get-Token $msvcVersion '^[0-9.]{1,32}$') + ' sdk_version=' + (Get-Token $sdkVersion '^[0-9.]{1,32}$') + ' os_build=' + (Get-Token ([Environment]::OSVersion.Version.ToString()) '^[0-9.]{1,32}$') + ' powershell=' + (Get-Token $PSVersionTable.PSVersion.ToString() '^[0-9A-Za-z.-]{1,32}$'))

        $phase = 'workspace_prepare'
        $baseDirectory = Join-Path $env:RUNNER_TEMP ('kd-confinement-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
        if ($baseDirectory -notmatch '^[A-Za-z]:\\[A-Za-z0-9_.\\-]+$') { throw 'workspace_path' }
        $script:Redactions = @($baseDirectory, $env:RUNNER_TEMP, $env:CI_WORKSPACE)
        $script:Layout = @{
            Base = $baseDirectory
            Downloads = (Join-Path $baseDirectory 'dl')
            ReadOnly = (Join-Path $baseDirectory 'ro')
        }
        $script:Lpac = New-ScratchSet (Join-Path $baseDirectory 'scratch')
        $script:Control = New-ScratchSet (Join-Path $baseDirectory 'control')
        $layout = $script:Layout
        $layout.RustPrefix = Join-Path $layout.ReadOnly 'rust'
        $layout.RustBin = Join-Path $layout.RustPrefix 'bin'
        $layout.NodeDir = Join-Path $layout.ReadOnly 'node'
        $layout.MsvcBin = Join-Path $layout.ReadOnly 'msvc\bin'
        $layout.MsvcLib = Join-Path $layout.ReadOnly 'msvc\lib'
        $layout.SdkUcrt = Join-Path $layout.ReadOnly 'sdk\ucrt'
        $layout.SdkUm = Join-Path $layout.ReadOnly 'sdk\um'
        $layout.NativeProbe = Join-Path $layout.ReadOnly 'native-probe'
        $layout.NativeProbeScript = Join-Path $layout.NativeProbe 'windows_confinement.ps1'
        $layout.NativeProbeSource = Join-Path $layout.NativeProbe 'windows_confinement.cs'
        $layout.NativeProbeRecovery = Join-Path $layout.NativeProbe 'windows_confinement_recovery.ps1'
        $layout.NpmDir = Join-Path $layout.ReadOnly 'npm'
        $layout.TestDir = Join-Path $layout.ReadOnly 'tests'
        $layout.NodeTest = Join-Path $layout.TestDir 'kd_bindings.test.mjs'
        $layout.LightningcssBinding = Join-Path $layout.NpmDir 'lightningcss.node'
        $layout.RolldownBinding = Join-Path $layout.NpmDir 'rolldown.node'
        foreach ($directory in @($layout.Base, $layout.Downloads, $layout.ReadOnly, $script:Lpac.Root, $script:Control.Root)) {
            New-Item -ItemType Directory -Path $directory | Out-Null
        }
        New-Item -ItemType File -Path (Join-Path $layout.Downloads 'acl_probe.txt') | Out-Null

        $phase = 'lpac_profile'
        $box = [KeelDock.Platform.WindowsConfinement.Sandbox]::Create()
        $script:Sid = $box.SidText

        $phase = 'acl_grant'
        Grant-Access $layout.ReadOnly $script:Sid 'ReadAndExecute, Synchronize' $true
        Grant-Access $script:Lpac.Root $script:Sid 'Modify, Synchronize' $true
        Set-LowIntegrityLabel $script:Lpac.Root
        $phase = 'acl_ancestors'
        $script:AncestorPaths = @()
        $ancestorPath = $layout.Base
        while ($ancestorPath) {
            $script:AncestorPaths += $ancestorPath
            $ancestorPath = Split-Path -Parent $ancestorPath
        }
        foreach ($ancestorPath in $script:AncestorPaths) {
            Grant-NonPropagating $ancestorPath $script:Sid
        }
        $ancestorCount = $script:AncestorPaths.Count
        $ancestorFailures = 0
        $phase = 'acl_grant'
        foreach ($set in @($script:Lpac, $script:Control)) {
            foreach ($directory in @($set.Tmp, $set.Profile, $set.CargoHome, $set.Crate, (Join-Path $set.Crate 'src'))) {
                New-Item -ItemType Directory -Force -Path $directory | Out-Null
            }
        }
        foreach ($directory in @($layout.RustPrefix, $layout.NodeDir, $layout.NativeProbe, $layout.NpmDir, $layout.TestDir)) {
            New-Item -ItemType Directory -Force -Path $directory | Out-Null
        }
        Copy-Item -LiteralPath $PSCommandPath -Destination $layout.NativeProbeScript
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows_confinement.cs') -Destination $layout.NativeProbeSource
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'windows_confinement_recovery.ps1') -Destination $layout.NativeProbeRecovery
        Write-Line ('windows-confinement-acl=granted ro=read_execute scratch=modify ancestors_read_attributes=' + $ancestorCount + ' ancestors_failed=' + $ancestorFailures)

        $phase = 'fetch'
        foreach ($item in ($Downloads + @($NodeDownload))) {
            $path = Invoke-Download $item
            Assert-Sha256 $path $item.Sha256 $item.Name
        }
        foreach ($item in $NpmDownloads) {
            $path = Invoke-Download $item
            Assert-Sri $path $item.Sri $item.Name
        }
        Write-Line 'windows-confinement-fetch=verified rust_components=3 node=1 npm_bindings=2'

        $phase = 'stage_rust'
        foreach ($item in $Downloads) {
            $extract = Join-Path $layout.Downloads ('x-' + $item.Name)
            Invoke-Tar (Join-Path $layout.Downloads $item.File) $extract
            $componentRoot = Join-Path $extract $item.Root
            $expectedComponent = $ExpectedRustComponents[$item.Name]
            foreach ($component in (Get-Content -LiteralPath (Join-Path $componentRoot 'components'))) {
                $name = $component.Trim()
                if ($name.Length -eq 0) { continue }
                if (-not [string]::Equals($name, $expectedComponent, [StringComparison]::Ordinal)) {
                    $componentNameExpected = $expectedComponent
                    $componentNameObserved = $name
                    throw 'component_name'
                }
                $componentSource = Join-Path $componentRoot $name
                if (-not (Test-Path -LiteralPath $componentSource -PathType Container)) { throw 'component_missing' }
                Copy-Item -Path (Join-Path $componentSource '*') -Destination $layout.RustPrefix -Recurse -Force
            }
        }
        foreach ($required in @((Join-Path $layout.RustBin 'rustc.exe'), (Join-Path $layout.RustBin 'cargo.exe'), (Join-Path $layout.RustPrefix ('lib\rustlib\' + $RustTarget + '\lib')))) {
            if (-not (Test-Path -LiteralPath $required)) { throw 'rust_layout' }
        }

        $phase = 'stage_node'
        $nodeExtract = Join-Path $layout.Downloads 'x-node'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        [System.IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $layout.Downloads $NodeDownload.File), $nodeExtract)
        Copy-Item -LiteralPath (Join-Path $nodeExtract ('node-v' + $NodeVersion + '-win-x64\node.exe')) -Destination (Join-Path $layout.NodeDir 'node.exe')

        $phase = 'stage_npm'
        foreach ($item in $NpmDownloads) {
            $extract = Join-Path $layout.Downloads ('x-' + $item.Name)
            Invoke-Tar (Join-Path $layout.Downloads $item.File) $extract
            $binaries = @(Get-ChildItem -LiteralPath $extract -Recurse -File -Filter '*.node')
            if ($binaries.Count -ne 1) { throw 'npm_binding_missing' }
            Copy-Item -LiteralPath $binaries[0].FullName -Destination (Join-Path $layout.NpmDir ($item.Name + '.node'))
        }

        $phase = 'stage_msvc'
        Copy-Tree $msvcBinSource $layout.MsvcBin
        Copy-Tree $msvcLibSource $layout.MsvcLib
        Copy-Tree $sdkUcrtSource $layout.SdkUcrt
        Copy-Tree $sdkUmSource $layout.SdkUm

        $phase = 'stage_sources'
        $hash = [string][char]35
        $encoding = New-Object System.Text.UTF8Encoding($false)
        foreach ($set in @($script:Lpac, $script:Control)) {
            [IO.File]::WriteAllText((Join-Path $set.Crate 'Cargo.toml'), $CargoManifestText, $encoding)
            [IO.File]::WriteAllText((Join-Path $set.Crate 'src\lib.rs'), $RustSourceText.Replace('KDHASH', $hash).Replace("`r`n", "`n"), $encoding)
        }
        [IO.File]::WriteAllText($layout.NodeTest, $NodeTestText.Replace("`r`n", "`n"), $encoding)

        $phase = 'acl_readback'
        $aclState = Test-Acl
        Write-Line ('windows-confinement-acl=' + $aclState)
        if ($aclState -ne 'verified') { throw 'acl_readback' }

        $phase = 'ladder'
        $controlOutcomes = Invoke-Ladder $box $false $script:Control
        $phase = 'winsock_acl'
        $confinedOutcomes = Invoke-ConfinedLadder $box $script:Lpac
        $phase = 'ladder'

        $firstFailure = 'none'
        foreach ($key in $confinedOutcomes.Keys) {
            if (-not $confinedOutcomes[$key].Passed) { $firstFailure = $key; break }
        }
        $rust = 'failed'
        if ($confinedOutcomes['rust_build'].Passed -and $confinedOutcomes['rust_test'].Passed) { $rust = 'compiled' }
        $node = 'failed'
        if ($confinedOutcomes['node_version'].Passed -and $confinedOutcomes['node_bindings'].Passed) { $node = 'ran' }
        $controlRust = 'failed'
        if ($controlOutcomes['rust_build'].Passed -and $controlOutcomes['rust_test'].Passed) { $controlRust = 'compiled' }
        $controlNode = 'failed'
        if ($controlOutcomes['node_version'].Passed -and $controlOutcomes['node_bindings'].Passed) { $controlNode = 'ran' }
        $cssTransform = 'failed'
        if ($confinedOutcomes['node_bindings'].Stdout -match 'name=minifies_a_stylesheet result=pass') { $cssTransform = 'ok' }
        $aclNegative = 'denied'
        if (-not ($confinedOutcomes['acl_downloads_denied'].Passed -and $confinedOutcomes['acl_ro_write_denied'].Passed -and $controlOutcomes['acl_downloads_listable'].Passed)) { $aclNegative = 'failed' }
        $jobState = 'verified'
        $tokenState = 'verified'
        foreach ($key in $confinedOutcomes.Keys) {
            if (-not $confinedOutcomes[$key].Job) { $jobState = 'unverified' }
            if (-not $confinedOutcomes[$key].Token) { $tokenState = 'unverified' }
        }
        foreach ($key in $confinedOutcomes.Keys) {
            if ($tokenState -eq 'unverified' -and $confinedOutcomes[$key].AapOnly) { $tokenState = 'aap_only' }
        }
        $lpacBehaviour = Get-LpacBehaviour $confinedOutcomes
        $lpacBasis = 'token'
        $containerConsistent = $true
        foreach ($key in $confinedOutcomes.Keys) {
            if (-not ($confinedOutcomes[$key].Token -or $confinedOutcomes[$key].AapOnly)) { $containerConsistent = $false }
        }
        if ($lpacBehaviour -eq 'not_lpac') {
            $tokenState = 'not_lpac'
        } elseif ($lpacBehaviour -eq 'behavioural') {
            if ($containerConsistent) {
                if ($tokenState -ne 'verified') { $lpacBasis = 'behavioural' }
                $tokenState = 'verified'
            }
        } elseif ($tokenState -ne 'verified') {
            $tokenState = 'inconclusive'
        }
        $lpacText = $tokenState
        if ($lpacBasis -eq 'behavioural') { $lpacText = 'behavioural' }
        Write-Line ('windows-confinement-spike=observed rust=' + $rust + ' node=' + $node + ' first_failure=' + $firstFailure + ' lpac=' + $lpacText + ' lpac_behaviour=' + $lpacBehaviour + ' job=' + $jobState + ' acl=' + $aclState + ' acl_negative=' + $aclNegative + ' control_rust=' + $controlRust + ' control_node=' + $controlNode + ' css_transform=' + $cssTransform + ' rolldown=load_only vitest=not_run rolldown_call=not_run')
        if ($rust -eq 'compiled' -and $node -eq 'ran' -and $firstFailure -eq 'none' -and $jobState -eq 'verified' -and $tokenState -eq 'verified' -and $aclNegative -eq 'denied') { $exitCode = 0 }
    }
} catch {
    $reason = [string]$_.Exception.Message
    if ($phase -eq 'winsock_acl') {
        if ($reason -notin @('winsock_catalog_path', 'winsock_catalog_missing', 'winsock_catalog_changed', 'winsock_catalog_readback', 'winsock_recovery_acl', 'winsock_recovery_ready', 'winsock_recovery_start', 'winsock_recovery_stop', 'winsock_registry_read', 'winsock_package_sid', 'winsock_scratch_create', 'winsock_scratch_cleanup', 'winsock_grant_failed', 'winsock_restore_failed', 'winsock_restore_readback', 'winsock_restore_state')) {
            $reason = 'winsock_registry_error'
        }
    } else {
        $reason = Get-CleanText $reason 120
        $reason = [regex]::Replace($reason, '[^A-Za-z0-9._ -]', '_').Trim().Replace(' ', '_')
        if ($reason.Length -eq 0) { $reason = 'unspecified' }
    }
    $safePhase = [regex]::Replace([string]$phase, '[^A-Za-z0-9_]', '_')
    $componentDiagnostic = ''
    if ($null -ne $componentNameExpected) {
        $componentDiagnostic = ' expected_component=' + (Get-SafeComponentName $componentNameExpected) + ' observed_component=' + (Get-SafeComponentName $componentNameObserved)
    }
    $refusal = 'windows-confinement-spike=refused phase=' + $safePhase + ' reason=' + $reason + $componentDiagnostic
}

try {
    if ($script:WinsockCatalogLease) {
        try {
            Restore-WinsockCatalogAcl $script:WinsockCatalogLease
            Stop-CatalogRecovery $script:WinsockCatalogLease
            $script:WinsockCatalogLease = $null
        } catch {
            $cleanup = 'incomplete'
        }
    }
} catch {
    $cleanup = 'incomplete'
}

try {
    if ($box -ne $null) {
        $box.Dispose()
        if (-not $box.CleanupComplete) { $cleanup = 'incomplete' }
    }
    if ($baseDirectory -and (Test-Path -LiteralPath $baseDirectory)) {
        Remove-Item -LiteralPath $baseDirectory -Recurse -Force
    }
} catch {
    $cleanup = 'incomplete'
}

if ($refusal) {
    Write-Line ($refusal + ' cleanup=' + $cleanup)
    exit 1
}
if ($Mode -eq 'spike') {
    Write-Line ('windows-confinement-cleanup=' + $cleanup)
    if ($cleanup -ne 'verified') { $exitCode = 1 }
}
exit $exitCode
