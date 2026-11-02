param(
    [ValidateSet('compile', 'keygen', 'run')]
    [string]$Mode = 'compile'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$phase = 'control_identity'
$exitCode = 1
$refusal = $null
$cleanup = 'verified'
$box = $null
$baseDirectory = $null
$libraryLoaded = $false
$script:Redactions = @()
$script:NullLease = $null
$script:ExpectedTemp = $null
$script:ProfileFolder = $null
$script:OtherBox = $null
$script:OtherFolder = $null
$script:OtherContainerSeconds = 30
$script:Canaries = @()
$script:CanaryRunnerTemp = ''
$script:CanaryWorkspace = ''
$script:CanaryProfile = ''
$script:CanaryControl = ''
$script:CanaryNeedle = ''
$script:CanaryScratchNeedle = ''
$script:Channel = $null
$script:Listener = $null
$script:ChannelRegistry = $false
$script:TrapDirectory = $null
$script:TrapSentinel = $null
$script:PlantedJunctions = 0
$script:PlantedSymlinks = 0
$script:LogCanary = ''
$script:LogNeedles = @()
$script:Deadline = [DateTime]::UtcNow.AddMinutes(285)
$script:GateFailure = 0
$script:GateCause = ''
$script:RefusalReason = ''
$script:PublicLinePattern = '^(windows-source|windows-confinement|capsule-decrypt|capsule-destroy)[a-z-]*=[ -~]{0,480}$'

$NpmVersion = '11.19.1'
$GateTableScript = 'gate_table.py'
$GateTableEmitCommand = 'emit'
$RequiredGateCount = 15
$MaxGateCount = 18
$GateTableManifestCommand = 'manifest-digest'
$GateLongSeconds = 900
$GateShortSeconds = 300
$GateLongPattern = '(^|_)(clippy|tests|replay|prepare|typecheck)$'
$MaxManifestEntries = 10000
$MaxTarballs = 6000
$CaptureLimit = 1048576
$ListingLimit = 3145728
$RequiredFunctions = @(
    'Get-CleanText', 'Get-Token', 'Write-DiagLines', 'Invoke-Download', 'Assert-Sha256', 'Assert-Sri', 'Invoke-Tar', 'Copy-Tree',
    'Grant-Access', 'Set-LowIntegrityLabel', 'Test-LowIntegrityLabel', 'Grant-NonPropagating', 'Get-SidRules', 'New-ScratchSet',
    'New-StageEnvironment', 'Get-NormalPath', 'Test-PathUnder', 'Get-Mib', 'Test-Passed', 'Invoke-ConfinedProbe',
    'Initialize-ContainerTemp', 'Test-OtherContainerNul', 'Remove-TreeNoFollow', 'Remove-ReparsePoints', 'Get-JobLiveness',
    'Write-CleanupDetail', 'Register-RemovalRoot', 'Remove-Canaries', 'Initialize-LinkFixtures', 'Initialize-ChannelContext', 'Remove-ChannelFixtures',
    'Test-LpacTokenText', 'Invoke-ChannelPhase', 'Get-ChannelBlockedCount', 'Get-ChannelControlState', 'Initialize-FixtureSources',
    'Invoke-FixturePhase', 'Get-StatusName'
)
$LibraryVariables = @(
    'RustVersion', 'RustTarget', 'RustDate', 'NodeVersion', 'ExpectedRustComponents', 'Downloads', 'NodeDownload', 'AllowedHosts',
    'FixtureRustText', 'FixtureNodeText', 'FixtureNodePackage', 'FixtureForms', 'FixtureCargoSeconds', 'FixtureNodeSeconds',
    'FixtureSpawnSeconds', 'FixtureSentinelEnvironment', 'NetworkDeniedConnect', 'NetworkDeniedResolve', 'NetworkDeniedUdp',
    'NetworkDeniedHostResolve', 'NetworkDeniedBind', 'NetworkUnroutableConnect', 'ChannelNames', 'ChannelSentinelEnvironment'
)
$RecordChannelNames = @('https', 'dns', 'redirect', 'proxy', 'runner_ipc', 'raw_logs', 'artifact_upload', 'cache_upload', 'runner_files', 'process_memory', 'boundary_disablement')
$ReservedNames = '^(con|prn|aux|nul|com[1-9]|lpt[1-9])(\..*)?$'
$FrameDriverReasons = @('key_unavailable', 'input_invalid', 'capsule_invalid', 'binding_mismatch', 'agreement_failed', 'crypto_refused', 'manifest_invalid', 'bundle_mismatch', 'output_failed', 'destroy_failed')

function Write-Line([string]$text) {
    if ($text -cmatch $script:PublicLinePattern) { [Console]::Out.WriteLine($text) }
}

function Get-LibraryText {
    $path = Join-Path $PSScriptRoot 'windows_confinement.ps1'
    $tokens = $null
    $errors = $null
    $tree = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    if ($errors -and $errors.Count -ne 0) { throw 'library_parse' }
    $found = @()
    $parts = @()
    foreach ($statement in $tree.EndBlock.Statements) {
        if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) {
            if ($statement.Name -cne 'Write-Line') {
                $parts += $statement.Extent.Text
                $found += [string]$statement.Name
            }
        } elseif ($statement -is [System.Management.Automation.Language.AssignmentStatementAst]) {
            $target = $statement.Left
            if (($target -is [System.Management.Automation.Language.VariableExpressionAst]) -and ($LibraryVariables -ccontains [string]$target.VariablePath.UserPath)) {
                $parts += $statement.Extent.Text
                $found += ('$' + [string]$target.VariablePath.UserPath)
            }
        }
    }
    foreach ($name in $RequiredFunctions) {
        if ($found -cnotcontains $name) { throw 'library_missing' }
    }
    foreach ($name in $LibraryVariables) {
        if ($found -cnotcontains ('$' + $name)) { throw 'library_missing' }
    }
    return ($parts -join "`n")
}

function Test-HexValue([string]$value, [int]$length) {
    return [bool]($value -cmatch ('^[0-9a-f]{' + $length + '}$'))
}

function Get-FileSha256([string]$path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $path).Hash.ToLowerInvariant()
}

function Get-RemainingSeconds {
    return [int][math]::Floor(($script:Deadline - [DateTime]::UtcNow).TotalSeconds)
}

function Invoke-TrustedProcess([string]$file, [string[]]$arguments, [string]$workingDirectory, [hashtable]$environment, [int]$seconds, [int]$limit) {
    $info = New-Object System.Diagnostics.ProcessStartInfo
    $info.FileName = $file
    foreach ($argument in $arguments) { [void]$info.ArgumentList.Add($argument) }
    $info.WorkingDirectory = $workingDirectory
    $info.UseShellExecute = $false
    $info.RedirectStandardInput = $true
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    $info.CreateNoWindow = $true
    $info.Environment.Clear()
    foreach ($key in $environment.Keys) { $info.Environment[[string]$key] = [string]$environment[$key] }
    $process = [System.Diagnostics.Process]::Start($info)
    try {
        $process.StandardInput.Close()
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit($seconds * 1000)) {
            try { $process.Kill($true) } catch { $null = $_ }
            $process.WaitForExit()
            return @{ ExitCode = -1; TimedOut = $true; Stdout = ''; Stderr = '' }
        }
        $process.WaitForExit()
        $out = [string]$outTask.GetAwaiter().GetResult()
        $err = [string]$errTask.GetAwaiter().GetResult()
        if ($out.Length -gt $limit -or $err.Length -gt $limit) { throw 'process_output_limit' }
        return @{ ExitCode = [int]$process.ExitCode; TimedOut = $false; Stdout = $out; Stderr = $err }
    } finally {
        $process.Dispose()
    }
}

function Get-TrustedTool([string]$name) {
    $command = @(Get-Command $name -CommandType Application -ErrorAction Stop | Select-Object -First 1)
    $path = [string]$command[0].Source
    if ($path -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_. ()\\-]+$') { throw 'tool_path' }
    return $path
}

function Test-PathBelow([string]$path, [string]$root) {
    if ([string]::IsNullOrEmpty($root) -or [string]::IsNullOrEmpty($path)) { return $false }
    $prefix = $root.Replace('/', '\').TrimEnd('\').ToLowerInvariant() + '\'
    return ($path.Replace('/', '\').ToLowerInvariant() + '\').StartsWith($prefix, [StringComparison]::Ordinal)
}

function Get-TrustedEnvironment([string]$toolPath, [string]$homePath) {
    return @{
        SystemRoot = $env:SystemRoot
        windir = $env:SystemRoot
        PATH = ((Split-Path -Parent $toolPath) + ';' + (Join-Path $env:SystemRoot 'System32') + ';' + $env:SystemRoot)
        TEMP = $homePath
        TMP = $homePath
        HOME = $homePath
        USERPROFILE = $homePath
        GIT_CONFIG_NOSYSTEM = '1'
        GIT_CONFIG_GLOBAL = 'NUL'
        GIT_ATTR_NOSYSTEM = '1'
        GIT_TERMINAL_PROMPT = '0'
        PYTHONDONTWRITEBYTECODE = '1'
        PYTHONIOENCODING = 'ascii'
    }
}

function Invoke-Keygen {
    $directory = [string]$env:KD_KEY_DIRECTORY
    $runnerTemp = [string]$env:RUNNER_TEMP
    if ($directory -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_.\\-]+$' -or $runnerTemp -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_.\\-]+$') { throw 'key_directory' }
    if (-not (Test-PathBelow $directory $runnerTemp)) { throw 'key_directory' }
    if (Test-Path -LiteralPath $directory) { throw 'key_directory' }
    New-Item -ItemType Directory -Path $directory | Out-Null
    $name = 'kd-receiver-' + [Guid]::NewGuid().ToString('N')
    $provider = [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
    $parameters = New-Object System.Security.Cryptography.CngKeyCreationParameters
    $parameters.ExportPolicy = [System.Security.Cryptography.CngExportPolicies]::None
    $parameters.KeyUsage = [System.Security.Cryptography.CngKeyUsages]::KeyAgreement
    $parameters.Provider = $provider
    $parameters.KeyCreationOptions = [System.Security.Cryptography.CngKeyCreationOptions]::None
    $key = [System.Security.Cryptography.CngKey]::Create([System.Security.Cryptography.CngAlgorithm]::ECDiffieHellmanP256, $name, $parameters)
    try {
        if ($key.ExportPolicy -ne [System.Security.Cryptography.CngExportPolicies]::None) { throw 'key_policy' }
        $blob = $key.Export([System.Security.Cryptography.CngKeyBlobFormat]::EccPublicBlob)
        if ($blob.Length -ne 72) { throw 'key_blob' }
        $point = New-Object byte[] 65
        $point[0] = 4
        [Array]::Copy($blob, 8, $point, 1, 64)
    } finally {
        $key.Dispose()
    }
    [IO.File]::WriteAllBytes((Join-Path $directory 'public-point.bin'), $point)
    [IO.File]::WriteAllText((Join-Path $directory 'key-name.txt'), $name, (New-Object System.Text.UTF8Encoding($false)))
    Write-Line 'windows-source-keygen=observed key=p256 export_policy=none persisted=user point_bytes=65'
}

function ConvertTo-Base64Url([string]$text) {
    return $text.Replace('+', '-').Replace('/', '_')
}

function Get-InteriorEncoding([byte[]]$data, [int]$shift, [bool]$url) {
    $padded = New-Object byte[] ($shift + $data.Length)
    [Array]::Copy($data, 0, $padded, $shift, $data.Length)
    $encoded = [Convert]::ToBase64String($padded)
    if ($url) { $encoded = ConvertTo-Base64Url $encoded }
    $start = [int][math]::Ceiling((8 * $shift) / 6)
    $stop = [int][math]::Floor((8 * ($shift + $data.Length)) / 6)
    return $encoded.Substring($start, $stop - $start)
}

function Get-LogNeedles([string]$value) {
    if ($value -cnotmatch '^(?:[0-9a-f]{2}){32,128}$') { throw 'log_canary' }
    if (@($value.ToCharArray() | Select-Object -Unique).Count -lt 12) { throw 'log_canary' }
    $ascii = [System.Text.Encoding]::ASCII.GetBytes($value)
    $utf16 = [System.Text.Encoding]::Unicode.GetBytes($value)
    $decoded = [Convert]::FromHexString($value)
    $needles = @($value, [BitConverter]::ToString($ascii).Replace('-', '').ToLowerInvariant(), ($value.ToCharArray() -join [string][char]0))
    foreach ($source in @($ascii, $utf16, $decoded)) {
        foreach ($shift in @(0, 1, 2)) {
            $needles += Get-InteriorEncoding $source $shift $false
            $needles += Get-InteriorEncoding $source $shift $true
        }
    }
    return @($needles | Select-Object -Unique)
}

function Test-LogCanary([string]$text) {
    if ($script:LogNeedles.Count -eq 0) { return $true }
    $views = @([string]$text, ([string]$text).Replace([string][char]0, ''))
    foreach ($view in $views) {
        foreach ($needle in $script:LogNeedles) {
            if ($view.IndexOf($needle, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
        }
    }
    return $false
}

function Test-SourceAcl {
    $sid = $script:Sid
    $layout = $script:Layout
    $writeMask = [System.Security.AccessControl.FileSystemRights]'WriteData, AppendData, WriteAttributes, WriteExtendedAttributes, Delete, DeleteSubdirectoriesAndFiles, ChangePermissions, TakeOwnership'
    $readMask = [System.Security.AccessControl.FileSystemRights]'ReadAndExecute'
    $modifyMask = [System.Security.AccessControl.FileSystemRights]'Modify'
    $ro = @(Get-SidRules $layout.ReadOnly $sid)
    if ($ro.Count -ne 1 -or ($ro[0].FileSystemRights -band $writeMask) -ne 0 -or ($ro[0].FileSystemRights -band $readMask) -ne $readMask -or $ro[0].AccessControlType -ne 'Allow') { return 'ro_rule' }
    $scratch = @(Get-SidRules $script:Lpac.Root $sid)
    if ($scratch.Count -ne 1 -or ($scratch[0].FileSystemRights -band $modifyMask) -ne $modifyMask -or $scratch[0].AccessControlType -ne 'Allow') { return 'scratch_rule' }
    foreach ($path in @($layout.Downloads, $layout.Private, $script:Control.Root, $script:Control.Tmp, $script:Control.Crate)) {
        if (@(Get-SidRules $path $sid).Count -ne 0) { return 'unexpected_rule' }
    }
    $attributeMask = [System.Security.AccessControl.FileSystemRights]'ReadAttributes, Synchronize'
    foreach ($path in $script:AncestorPaths) {
        $entries = @(Get-SidRules $path $sid)
        if ($entries.Count -ne 1) { return 'ancestor_rule' }
        if ($entries[0].FileSystemRights -ne $attributeMask -or $entries[0].AccessControlType -ne 'Allow' -or $entries[0].IsInherited) { return 'ancestor_rule' }
        if ($entries[0].InheritanceFlags -ne [System.Security.AccessControl.InheritanceFlags]::None -or $entries[0].PropagationFlags -ne [System.Security.AccessControl.PropagationFlags]::None) { return 'ancestor_rule' }
    }
    foreach ($path in @(($layout.RustBin + '\rustc.exe'), ($layout.RustBin + '\cargo.exe'), ($layout.RustBin + '\rustfmt.exe'), ($layout.RustBin + '\clippy-driver.exe'), ($layout.MsvcBin + '\link.exe'), ($layout.NodeDir + '\node.exe'), $layout.NpmCli, $layout.NodeTest, $layout.ProbeExe, ($layout.Tarballs))) {
        if (@(Get-SidRules $path $sid).Count -lt 1) { return 'not_inherited' }
    }
    foreach ($path in @($script:Lpac.Tmp, $script:Lpac.Profile, $script:Lpac.CargoHome, $script:Lpac.Project)) {
        $entries = @(Get-SidRules $path $sid)
        if ($entries.Count -ne 1 -or -not $entries[0].IsInherited -or $entries[0].AccessControlType -ne 'Allow' -or ($entries[0].FileSystemRights -band $modifyMask) -ne $modifyMask) { return 'scratch_not_inherited' }
        if (-not (Test-LowIntegrityLabel $path)) { return 'scratch_integrity' }
    }
    if (-not (Test-LowIntegrityLabel $script:Lpac.Root)) { return 'scratch_integrity' }
    return 'verified'
}

function ConvertTo-CommandLine([string[]]$arguments) {
    $parts = @()
    foreach ($argument in $arguments) {
        if ($argument.Length -eq 0 -or $argument -match '[\s"]') {
            $parts += ('"' + $argument.Replace('"', '\"') + '"')
        } else {
            $parts += $argument
        }
    }
    return ($parts -join ' ')
}

function Test-ChannelRecord($report, [string]$name) {
    return ($report[$name].Status -ceq 'blocked')
}

function Get-ChannelRecordEntry($before, $after, [string]$name) {
    $status = 'not-run'
    $firedBefore = $false
    $firedAfter = $false
    if ($before[$name].Status -ceq 'observed-leak' -or $after[$name].Status -ceq 'observed-leak') {
        $status = 'observed-leak'
    } elseif ($before[$name].Status -ceq 'blocked' -and $after[$name].Status -ceq 'blocked') {
        $firedBefore = ($before[$name].ControlsMissed -eq 0 -and $before[$name].ControlsFired -gt 0)
        $firedAfter = ($after[$name].ControlsMissed -eq 0 -and $after[$name].ControlsFired -gt 0)
        $status = 'blocked'
    }
    return [ordered]@{ status = $status; before = $firedBefore; after = $firedAfter }
}

function Write-PrivateRecord($record) {
    $directory = Join-Path $env:RUNNER_TEMP 'kd-records'
    New-Item -ItemType Directory -Force -Path $directory | Out-Null
    $json = ConvertTo-Json -InputObject $record -Depth 8 -Compress
    [IO.File]::WriteAllText((Join-Path $directory 'windows-source-run.json'), ($json + "`n"), (New-Object System.Text.UTF8Encoding($false)))
}

function Read-BoundValues([string]$directory) {
    $path = Join-Path $directory 'bound.json'
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -gt 8192) { throw 'bound_values' }
    $bound = [IO.File]::ReadAllText($path, (New-Object System.Text.UTF8Encoding($false, $true))) | ConvertFrom-Json -AsHashtable
    $expected = @('capsule_sha256', 'source_sha', 'tree_id', 'lock_sha256', 'manifest_sha256', 'revocation')
    if (@($bound.Keys).Count -ne $expected.Count) { throw 'bound_values' }
    foreach ($key in $expected) {
        if (-not $bound.ContainsKey($key) -or $bound[$key] -isnot [string]) { throw 'bound_values' }
    }
    if (-not (Test-HexValue $bound['capsule_sha256'] 64) -or -not (Test-HexValue $bound['lock_sha256'] 64) -or -not (Test-HexValue $bound['manifest_sha256'] 64)) { throw 'bound_values' }
    if (-not (Test-HexValue $bound['source_sha'] 40) -or -not (Test-HexValue $bound['tree_id'] 40)) { throw 'bound_values' }
    if ($bound['revocation'] -cne 'confirmed') { throw 'revocation' }
    return $bound
}

function Invoke-FrameDriver([string[]]$arguments, [int]$seconds) {
    $pwsh = [string](Get-Process -Id $PID).Path
    if ($pwsh -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_. ()\\-]+$') { throw 'frame_driver' }
    $driver = Join-Path $PSScriptRoot 'capsule_frame.ps1'
    $workDirectory = [string]$env:RUNNER_TEMP
    if ($script:Layout -and $script:Layout.Private -and (Test-Path -LiteralPath $script:Layout.Private -PathType Container)) { $workDirectory = [string]$script:Layout.Private }
    $environment = @{ SystemRoot = $env:SystemRoot; windir = $env:SystemRoot; PATH = ((Split-Path -Parent $pwsh) + ';' + (Join-Path $env:SystemRoot 'System32')); TEMP = $workDirectory; TMP = $workDirectory; USERPROFILE = $env:USERPROFILE; APPDATA = $env:APPDATA; LOCALAPPDATA = $env:LOCALAPPDATA }
    return Invoke-TrustedProcess $pwsh (@('-NoProfile', '-NonInteractive', '-File', $driver) + $arguments) $workDirectory $environment $seconds 4096
}

function Get-FrameDriverReason([string]$stdout) {
    $match = [regex]::Match([string]$stdout, '^capsule-decrypt=refused reason=([a-z_]{1,24}) key=(destroyed|present)\r?\n?$')
    if ($match.Success -and ($FrameDriverReasons -ccontains $match.Groups[1].Value)) { return $match.Groups[1].Value }
    return 'driver_output'
}

function Test-SourcePath([string]$path) {
    if ($path.Length -lt 1 -or $path.Length -gt 240) { return $false }
    if ($path -cnotmatch '^[ -~]+$') { return $false }
    if ($path -cmatch '[\\:*?"<>|]') { return $false }
    foreach ($component in $path.Split('/')) {
        if ($component.Length -eq 0 -or $component -ceq '.' -or $component -ceq '..') { return $false }
        if ($component.EndsWith('.') -or $component.EndsWith(' ') -or $component.StartsWith(' ')) { return $false }
        if ($component -imatch $ReservedNames) { return $false }
        if ($component -ieq '.git' -or $component -ieq 'git~1') { return $false }
    }
    return $true
}

function Read-SourceManifest([string]$path) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -gt 4194304) { throw 'manifest_file' }
    $text = [IO.File]::ReadAllText($path, (New-Object System.Text.UTF8Encoding($false, $true)))
    if (-not $text.EndsWith("`n")) { throw 'manifest_file' }
    $lines = $text.Substring(0, $text.Length - 1).Split("`n")
    if ($lines.Count -lt 4 -or $lines.Count -gt ($MaxManifestEntries + 3)) { throw 'manifest_file' }
    $source = [regex]::Match($lines[0], '^source ([0-9a-f]{40})$')
    $tree = [regex]::Match($lines[1], '^tree ([0-9a-f]{40})$')
    $bundle = [regex]::Match($lines[2], '^bundle ([0-9a-f]{64}) ([0-9]{1,10})$')
    if (-not $source.Success -or -not $tree.Success -or -not $bundle.Success) { throw 'manifest_file' }
    $entries = @()
    $seen = New-Object System.Collections.Hashtable([StringComparer]::OrdinalIgnoreCase)
    for ($index = 3; $index -lt $lines.Count; $index++) {
        $match = [regex]::Match($lines[$index], '^entry (33188|33261) ([0-9]{1,10}) ([0-9a-f]{64}) ([0-9a-f]{40}) ([ -~]{1,240})$')
        if (-not $match.Success) { throw 'manifest_file' }
        $entryPath = $match.Groups[5].Value
        if (-not (Test-SourcePath $entryPath)) { throw 'path_unsafe' }
        if ($seen.ContainsKey($entryPath)) { throw 'path_unsafe' }
        $seen[$entryPath] = $true
        $entries += @{ Mode = [int]$match.Groups[1].Value; Size = [uint64]$match.Groups[2].Value; Sha256 = $match.Groups[3].Value; BlobId = $match.Groups[4].Value; Path = $entryPath }
    }
    if ($entries.Count -lt 1) { throw 'manifest_file' }
    return @{ Source = $source.Groups[1].Value; Tree = $tree.Groups[1].Value; BundleSha256 = $bundle.Groups[1].Value; BundleLength = [uint64]$bundle.Groups[2].Value; Entries = $entries }
}

function Test-ProjectTree([string]$root, $entries) {
    $expected = New-Object System.Collections.Hashtable([StringComparer]::Ordinal)
    foreach ($entry in $entries) { $expected[[string]$entry.Path] = $entry }
    $prefix = $root.TrimEnd('\') + '\'
    $seen = 0
    foreach ($file in [IO.Directory]::EnumerateFiles($root, '*', [IO.SearchOption]::AllDirectories)) {
        $info = New-Object IO.FileInfo($file)
        if (([int]$info.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'tree_link' }
        $relative = $file.Substring($prefix.Length).Replace('\', '/')
        if (-not $expected.ContainsKey($relative)) { throw 'tree_extra' }
        $entry = $expected[$relative]
        if ([uint64]$info.Length -ne [uint64]$entry.Size) { throw 'tree_size' }
        if ((Get-FileSha256 $file) -cne [string]$entry.Sha256) { throw 'tree_hash' }
        $seen += 1
    }
    if ($seen -ne $expected.Count) { throw 'tree_missing' }
}

function Invoke-GitStep([string[]]$arguments, [string]$workingDirectory, [int]$seconds, [int]$limit = 1048576) {
    $result = Invoke-TrustedProcess $script:GitPath $arguments $workingDirectory $script:GitEnvironment $seconds $limit
    if ($result.TimedOut -or $result.ExitCode -ne 0) { throw 'git_step' }
    return [string]$result.Stdout
}

function Import-SourceBundle($bound, $manifest, [string]$bundlePath, [string]$project) {
    $repository = Join-Path $script:Layout.Private 'repo'
    $gitDirectory = Join-Path $repository '.git'
    New-Item -ItemType Directory -Path $repository | Out-Null
    [void](Invoke-GitStep @('init', '--quiet', '--template=', $repository) $script:Layout.Private 120)
    [void](Invoke-GitStep @('--git-dir', $gitDirectory, 'bundle', 'unbundle', $bundlePath) $script:Layout.Private 600)
    $kind = (Invoke-GitStep @('--git-dir', $gitDirectory, 'cat-file', '-t', $bound['source_sha']) $script:Layout.Private 120).Trim()
    if ($kind -cne 'commit') { throw 'source_commit' }
    $tree = (Invoke-GitStep @('--git-dir', $gitDirectory, 'rev-parse', ($bound['source_sha'] + '^{tree}')) $script:Layout.Private 120).Trim()
    if ($tree -cne $bound['tree_id'] -or $tree -cne $manifest.Tree) { throw 'tree_id' }
    $listing = Invoke-GitStep @('--git-dir', $gitDirectory, 'ls-tree', '-r', '-z', '--full-tree', $bound['source_sha']) $script:Layout.Private 300 $ListingLimit
    $rows = @($listing.Split([char]0) | Where-Object { $_.Length -gt 0 })
    if ($rows.Count -ne $manifest.Entries.Count) { throw 'tree_listing' }
    $byPath = New-Object System.Collections.Hashtable([StringComparer]::Ordinal)
    foreach ($entry in $manifest.Entries) { $byPath[[string]$entry.Path] = $entry }
    foreach ($row in $rows) {
        $match = [regex]::Match($row, '^(100644|100755) blob ([0-9a-f]{40})\t([ -~]+)$')
        if (-not $match.Success -or -not $byPath.ContainsKey($match.Groups[3].Value)) { throw 'tree_listing' }
        $entry = $byPath[$match.Groups[3].Value]
        $mode = 33188
        if ($match.Groups[1].Value -ceq '100755') { $mode = 33261 }
        if ($entry.BlobId -cne $match.Groups[2].Value -or [int]$entry.Mode -ne $mode) { throw 'tree_listing' }
    }
    $checkout = @('--git-dir', $gitDirectory, '--work-tree', $project, '-c', 'core.autocrlf=false', '-c', 'core.symlinks=false', '-c', 'core.protectNTFS=true', '-c', 'core.longpaths=true', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=NUL', '-c', 'core.eol=lf', 'checkout', '--force', $bound['source_sha'], '--', '.')
    [void](Invoke-GitStep $checkout $project 600)
}

function Get-SourceWalk([string]$project, [string]$pattern, [bool]$directories) {
    $found = @()
    $pending = New-Object System.Collections.Generic.Queue[string]
    $pending.Enqueue($project)
    $flat = New-Object System.IO.EnumerationOptions
    $flat.RecurseSubdirectories = $false
    $flat.AttributesToSkip = [IO.FileAttributes]::None
    $flat.IgnoreInaccessible = $false
    $flat.MatchCasing = [System.IO.MatchCasing]::CaseInsensitive
    while ($pending.Count -gt 0) {
        $current = $pending.Dequeue()
        foreach ($child in [IO.Directory]::EnumerateDirectories($current, '*', $flat)) {
            $info = New-Object IO.DirectoryInfo($child)
            if (([int]$info.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) {
                if ($info.Name -ieq '.cargo') { $found += ('L|' + $child) }
                continue
            }
            if ($directories -and $info.Name -ieq $pattern) { $found += ('D|' + $child) }
            $pending.Enqueue($child)
        }
        if (-not $directories) {
            foreach ($file in [IO.Directory]::EnumerateFiles($current, $pattern, $flat)) { $found += ('F|' + $file) }
        }
    }
    return $found
}

function Remove-SourceConfigFiles([string]$project) {
    foreach ($entry in @(Get-SourceWalk $project '.cargo' $true)) {
        $kind = $entry.Substring(0, 1)
        $directory = $entry.Substring(2)
        if ($kind -ceq 'L') {
            [IO.Directory]::Delete($directory)
            continue
        }
        foreach ($file in @([IO.Directory]::EnumerateFiles($directory, 'config*', [IO.SearchOption]::TopDirectoryOnly))) {
            $info = New-Object IO.FileInfo($file)
            if (([int]$info.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) {
                [IO.File]::Delete($file)
                continue
            }
            $payload = [IO.File]::ReadAllText($file, (New-Object System.Text.UTF8Encoding($false, $true)))
            if ($payload -match '(?im)^\s*\[(?:source\.|registries\.)|^\s*(?:replace-with|registry)\s*=') { throw 'registry' }
            [IO.File]::Delete($file)
        }
    }
    foreach ($entry in @(Get-SourceWalk $project '.npmrc' $false)) {
        [IO.File]::Delete($entry.Substring(2))
    }
    $locks = 0
    foreach ($entry in @(Get-SourceWalk $project 'Cargo.lock' $false)) {
        $file = $entry.Substring(2)
        $item = Get-Item -LiteralPath $file -Force
        if ($item.Length -gt 4194304) { throw 'lock' }
        foreach ($line in [IO.File]::ReadAllLines($file)) {
            if ($line -match '^\s*source\s*=') { throw 'registry' }
        }
        $locks += 1
    }
    if ($locks -lt 1) { throw 'lock' }
}

function Remove-WithinRoots([string]$path) {
    $roots = @($script:Layout.Base, $script:ProfileFolder, $script:OtherFolder, $script:TrapDirectory)
    foreach ($canary in @($script:Canaries)) { $roots += [string]$canary }
    $normal = ([string]$path).Replace('/', '\').TrimEnd('\')
    if ($normal -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_.\\-]+$' -or $normal -match '(^|\\)\.\.?(\\|$)') { throw 'remove_root' }
    $system = ([string]$env:SystemRoot).TrimEnd('\')
    if (($normal -ieq $system) -or (Test-PathBelow $normal $system)) { throw 'remove_root' }
    $inside = $false
    foreach ($root in $roots) {
        if ([string]::IsNullOrEmpty($root)) { continue }
        $rootNormal = ([string]$root).Replace('/', '\').TrimEnd('\')
        if ($rootNormal.Length -lt 4 -or $rootNormal.IndexOf('\') -lt 0 -or $rootNormal -match '^[A-Za-z]:$') { continue }
        if (($normal -ieq $rootNormal) -or (Test-PathBelow $normal $rootNormal)) { $inside = $true }
    }
    if (-not $inside) { throw 'remove_root' }
    Remove-TreeNoFollow $normal
}

function Test-CanariesPresent {
    foreach ($file in @($script:CanaryRunnerTemp, $script:CanaryWorkspace, $script:CanaryProfile, $script:CanaryControl)) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { return $false }
        if ([IO.File]::ReadAllText($file) -cne $(if ($file -ceq $script:CanaryControl) { $script:CanaryScratchNeedle } else { $script:CanaryNeedle })) { return $false }
    }
    return $true
}

function Test-PlatformList($list, [string]$value) {
    if ($null -eq $list) { return $true }
    $items = @($list)
    $allowed = $false
    foreach ($item in $items) {
        $text = [string]$item
        if ($text -ceq ('!' + $value)) { return $false }
        if ($text -ceq $value) { $allowed = $true }
    }
    $positive = @($items | Where-Object { -not ([string]$_).StartsWith('!', [StringComparison]::Ordinal) })
    if ($positive.Count -eq 0) { return $true }
    return $allowed
}

function Initialize-NpmTarballs([string]$project) {
    $lockPath = Join-Path $project 'package-lock.json'
    $text = [IO.File]::ReadAllText($lockPath, (New-Object System.Text.UTF8Encoding($false, $true)))
    $lock = $text | ConvertFrom-Json -AsHashtable -Depth 100
    if ($lock['lockfileVersion'] -ne 3 -or $lock['packages'] -isnot [System.Collections.IDictionary]) { throw 'npm_lock' }
    if ($lock['packages'].Count -gt 50000) { throw 'npm_lock' }
    New-Item -ItemType Directory -Force -Path $script:Layout.Tarballs | Out-Null
    $mapping = @{}
    $count = 0
    foreach ($key in @($lock['packages'].Keys)) {
        $entry = $lock['packages'][$key]
        if ([string]$key -eq '' -or $entry -isnot [System.Collections.IDictionary] -or $entry['link'] -eq $true) { continue }
        $resolved = $entry['resolved']
        if ($null -eq $resolved) { continue }
        $uri = $null
        if ($resolved -isnot [string] -or -not [Uri]::TryCreate($resolved, [UriKind]::Absolute, [ref]$uri)) { throw 'npm_lock' }
        if ($uri.Scheme -ne 'https' -or $uri.Host -cne 'registry.npmjs.org' -or -not $uri.IsDefaultPort) { throw 'npm_lock' }
        $integrity = [string]$entry['integrity']
        if ($integrity -cnotmatch '^sha512-[A-Za-z0-9+/]{86}==$') { throw 'npm_lock' }
        if ($entry.ContainsKey('libc')) { continue }
        if (-not (Test-PlatformList $entry['os'] 'win32') -or -not (Test-PlatformList $entry['cpu'] 'x64')) { continue }
        if (-not $mapping.ContainsKey($resolved)) {
            if ($count -ge $MaxTarballs) { throw 'npm_lock' }
            $name = [string]$count + '.tgz'
            $item = @{ Name = 'npm'; File = $name; Url = $resolved; Sri = $integrity }
            $downloaded = Invoke-Download $item
            Assert-Sri $downloaded $integrity 'npm'
            $target = Join-Path $script:Layout.Tarballs $name
            Copy-Item -LiteralPath $downloaded -Destination $target
            Remove-Item -LiteralPath $downloaded -Force
            $mapping[$resolved] = ([Uri]$target).AbsoluteUri
            $count += 1
        }
        $entry['resolved'] = $mapping[$resolved]
    }
    if ($count -lt 1) { throw 'npm_lock' }
    $json = ConvertTo-Json -InputObject $lock -Depth 100 -Compress
    [IO.File]::WriteAllText($lockPath, ($json + "`n"), (New-Object System.Text.UTF8Encoding($false)))
    return $count
}

function Get-GatePlan([string]$project, [string]$cargo, [string]$node, [string]$npm) {
    $python = Get-TrustedTool 'python.exe'
    $gateScript = Join-Path $PSScriptRoot $GateTableScript
    $runtime = Test-RuntimeWorkspace $project
    $selection = 'base'
    $expectedCount = $RequiredGateCount
    if ($runtime) {
        $selection = 'runtime'
        $expectedCount = $MaxGateCount
    }
    $result = Invoke-TrustedProcess $python @('-B', $gateScript, $GateTableEmitCommand, $selection) $PSScriptRoot (Get-TrustedEnvironment $python $script:Layout.Private) 120 65536
    if ($result.TimedOut -or $result.ExitCode -ne 0) { throw 'gate_plan' }
    $plan = [string]$result.Stdout | ConvertFrom-Json -AsHashtable
    if ($plan.Keys.Count -ne 2 -or $plan['schema_version'] -ne 1 -or $plan['gates'] -isnot [System.Collections.IEnumerable]) { throw 'gate_plan' }
    $gates = @()
    $names = @{}
    foreach ($gate in @($plan['gates'])) {
        if ($gate -isnot [System.Collections.IDictionary] -or $gate.Keys.Count -ne 2) { throw 'gate_plan' }
        $name = [string]$gate['name']
        if ($name -cnotmatch '^[a-z][a-z_]{2,40}$' -or $names.ContainsKey($name)) { throw 'gate_plan' }
        $names[$name] = $true
        $argv = @($gate['argv'])
        if ($argv.Count -lt 2 -or $argv.Count -gt 64) { throw 'gate_plan' }
        $expanded = @()
        foreach ($item in $argv) {
            $argument = [string]$item
            if ($argument.Length -gt 400 -or $argument -cnotmatch '^[ -~]+$') { throw 'gate_plan' }
            $withProject = $argument.StartsWith('{project}', [StringComparison]::Ordinal)
            if ($withProject -and $argument.Length -gt 9 -and $argument[9] -ne '/') { throw 'gate_plan' }
            $argument = $argument.Replace('{cargo}', $cargo).Replace('{node}', $node).Replace('{npm}', $npm).Replace('{project}', $project)
            if ($argument -cmatch '\{[a-z_]*\}') { throw 'gate_plan' }
            if ($withProject) { $argument = $argument.Replace('/', '\') }
            $expanded += $argument
        }
        $gates += @{ Id = $name; Argv = [string[]]$expanded }
    }
    if ($gates.Count -ne $expectedCount) { throw 'gate_plan' }
    return $gates
}

function Test-RuntimeWorkspace([string]$project) {
    $directory = Join-Path $project 'runtime'
    if (-not (Test-Path -LiteralPath $directory)) { return $false }
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { throw 'runtime_workspace' }
    $present = @()
    foreach ($name in @('Cargo.toml', 'Cargo.lock')) {
        $path = Join-Path $directory $name
        if (Test-Path -LiteralPath $path) {
            if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw 'runtime_workspace' }
            $present += $true
        } else {
            $present += $false
        }
    }
    if (($present -contains $true) -and ($present -contains $false)) { throw 'runtime_workspace' }
    return ($present[0] -eq $true)
}

function New-GateEnvironment {
    $base = New-StageEnvironment $script:Lpac 'target'
    $kept = @($base | Where-Object { -not ([string]$_).StartsWith('KD_', [StringComparison]::Ordinal) })
    $root = $script:Lpac.Root
    $extra = @(
        'CI=true',
        'NPM_CONFIG_OFFLINE=true',
        'npm_config_offline=true',
        ('NPM_CONFIG_CACHE=' + (Join-Path $root 'npm-cache')),
        ('NPM_CONFIG_USERCONFIG=' + (Join-Path $root 'empty-user.npmrc')),
        ('NPM_CONFIG_GLOBALCONFIG=' + (Join-Path $root 'empty-global.npmrc')),
        ('NPM_CONFIG_PREFIX=' + (Join-Path $root 'npm-prefix')),
        'NPM_CONFIG_UPDATE_NOTIFIER=false',
        'NPM_CONFIG_AUDIT=false',
        'NPM_CONFIG_FUND=false'
    )
    return [string[]]($kept + $extra)
}

function Get-GateSeconds([string]$id) {
    if ($id -cmatch $GateLongPattern) { return $GateLongSeconds }
    return $GateShortSeconds
}

function Test-GateBoundary($run) {
    if ($run.Failure -ne '' -or -not $run.Exited -or [uint32]$run.HandleCount -ne 3) { return $false }
    $tokenText = Get-Token (([string]$run.Token) -replace ' ', ',') '^[A-Za-z0-9=,_.-]{1,160}$'
    $jobText = Get-Token (([string]$run.Job) -replace ' ', ',') '^[A-Za-z0-9=,_.-]{1,120}$'
    return ((Test-LpacTokenText $tokenText) -and ($jobText -like 'assigned,*'))
}

function Get-GateCause($run, [bool]$boundary) {
    if ($run.Failure -ne '' -or -not $run.Exited) { return 'launch' }
    if ($run.TimedOut) { return 'timeout' }
    $code = [uint32]$run.ExitCode
    if ($code -eq 0x4b44574b -or $code -eq 0xC0000044 -or $code -eq 0xC000012D -or $code -eq 0xC0000017) { return 'limit' }
    if ($code -ge 0xC0000000) { return 'signal' }
    if ($code -ne 0) { return 'exit' }
    if (-not $boundary) { return 'launch' }
    return 'exit'
}

function Invoke-SourceGates($sandbox, $plan, [string]$project, [string]$recordsDirectory) {
    $environment = New-GateEnvironment
    $outcome = @{ Count = 0; Failed = 0; Canary = 'absent'; Boundary = 'verified'; Failure = 0 }
    $index = 0
    foreach ($gate in $plan) {
        $index += 1
        $seconds = Get-GateSeconds $gate.Id
        $remaining = (Get-RemainingSeconds) - 900
        if ($remaining -lt 60) {
            $outcome.Failure = $index
            $outcome.Failed += 1
            $script:RefusalReason = 'deadline'
            $script:GateCause = 'deadline'
            Write-Line ('windows-source-gate=' + $index + ' id=' + $gate.Id + ' result=not_run hang=none cause=deadline')
            return $outcome
        }
        if ($seconds -gt $remaining) { $seconds = $remaining }
        $exe = [string]$gate.Argv[0]
        $commandLine = ConvertTo-CommandLine $gate.Argv
        $run = $sandbox.Run($true, $exe, $commandLine, $project, $environment, ($seconds * 1000), [uint32]32)
        $outcome.Count += 1
        $combined = [string]$run.Stdout + "`n" + [string]$run.Stderr
        [IO.File]::WriteAllText((Join-Path $recordsDirectory ('gate-' + $index + '.stdout')), [string]$run.Stdout, (New-Object System.Text.UTF8Encoding($false)))
        [IO.File]::WriteAllText((Join-Path $recordsDirectory ('gate-' + $index + '.stderr')), [string]$run.Stderr, (New-Object System.Text.UTF8Encoding($false)))
        $hang = 'none'
        if ($run.TimedOut) {
            $hang = 'slow'
            if (([uint64]$run.CpuMs * 10) -ge ([uint64]$run.ElapsedMs * 8)) { $hang = 'busy' }
        }
        $boundary = Test-GateBoundary $run
        $passed = ($boundary -and -not $run.TimedOut -and $run.ExitCode -eq 0)
        $result = 'failed'
        if ($passed) { $result = 'passed' }
        $causeText = ''
        if (-not $passed) {
            $script:GateCause = Get-GateCause $run $boundary
            $causeText = ' cause=' + $script:GateCause
        }
        Write-Line ('windows-source-gate=' + $index + ' id=' + $gate.Id + ' result=' + $result + ' hang=' + $hang + $causeText)
        if ($run.Truncated -or (Test-LogCanary $combined)) {
            $outcome.Canary = 'present'
            $outcome.Failure = $index
            $outcome.Failed += 1
            $script:RefusalReason = 'log_canary'
            return $outcome
        }
        if (-not $boundary) {
            $outcome.Boundary = 'failed'
            $outcome.Failure = $index
            $outcome.Failed += 1
            $script:RefusalReason = 'boundary'
            return $outcome
        }
        if (-not $passed) {
            $outcome.Failure = $index
            $outcome.Failed += 1
            $script:RefusalReason = 'gate'
            return $outcome
        }
    }
    return $outcome
}

try {
    if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) { throw 'platform' }
    if ($Mode -eq 'keygen') {
        $phase = 'keygen'
        if ($env:CI_EVENT_NAME -ne 'workflow_dispatch') { throw 'control' }
        Invoke-Keygen
        $exitCode = 0
    } else {
        $phase = 'runtime'
        [void](Add-Type -Path (Join-Path $PSScriptRoot 'windows_confinement.cs') -ErrorAction Stop)
        $phase = 'library'
        . ([scriptblock]::Create((Get-LibraryText)))
        $libraryLoaded = $true
        if ($Mode -eq 'compile') {
            Write-Line 'windows-source-run-compile=observed result=compiled'
            $exitCode = 0
        } else {
            $phase = 'control_identity'
            $role = [string]$env:CI_ROLE
            $runMode = [string]$env:CI_MODE
            if ($env:CI_EVENT_NAME -ne 'workflow_dispatch') { throw 'control' }
            if (@('producer', 'verifier') -cnotcontains $role -or @('synthetic', 'source') -cnotcontains $runMode) { throw 'control' }
            $expectedRef = 'refs/heads/main'
            if ($runMode -ceq 'source') { $expectedRef = 'refs/heads/untrusted' }
            if ($env:CI_REF -cne $expectedRef) { throw 'control' }
            if ($env:CI_REPOSITORY -ne 'keeldock-platform/platform-ci' -or $env:CI_SERVER_URL -ne 'https://github.com') { throw 'control' }
            if ($env:CI_SHA -notmatch '^[a-f0-9]{40}$') { throw 'control' }
            $root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
            $workspace = [IO.Path]::GetFullPath($env:CI_WORKSPACE)
            if (-not [string]::Equals($root, $workspace, [StringComparison]::OrdinalIgnoreCase)) { throw 'control' }
            $actualSha = git -C $root rev-parse --verify HEAD 2>$null
            if ($LASTEXITCODE -ne 0 -or $actualSha.Trim() -ne $env:CI_SHA) { throw 'control' }
            Write-Line ('windows-source-run=started role=' + $role + ' mode=' + $runMode)

            $phase = 'inputs'
            $runnerTemp = [string]$env:RUNNER_TEMP
            $keyDirectory = [string]$env:KD_KEY_DIRECTORY
            $capsuleDirectory = [string]$env:KD_CAPSULE_DIRECTORY
            foreach ($item in @($runnerTemp, $keyDirectory, $capsuleDirectory)) {
                if ($item -cnotmatch '^[A-Za-z]:\\[A-Za-z0-9_.\\-]+$') { throw 'inputs' }
            }
            if (-not (Test-PathBelow $keyDirectory $runnerTemp) -or -not (Test-PathBelow $capsuleDirectory $runnerTemp)) { throw 'inputs' }
            $keyName = ([IO.File]::ReadAllText((Join-Path $keyDirectory 'key-name.txt'))).Trim()
            if ($keyName -cnotmatch '^kd-receiver-[0-9a-f]{32}$') { throw 'inputs' }
            $keyRecord = Join-Path $keyDirectory 'key-record.bin'
            $capsulePath = Join-Path $capsuleDirectory 'capsule.bin'
            $script:LogCanary = [string]$env:KD_WINDOWS_LOG_CANARY
            $script:LogNeedles = Get-LogNeedles $script:LogCanary
            $script:Redactions = @($runnerTemp, $env:CI_WORKSPACE, $script:LogCanary)

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
            $baseDirectory = Join-Path $runnerTemp ('kd-source-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
            if ($baseDirectory -notmatch '^[A-Za-z]:\\[A-Za-z0-9_.\\-]+$') { throw 'workspace_path' }
            $recordsDirectory = Join-Path $runnerTemp 'kd-records'
            New-Item -ItemType Directory -Force -Path $recordsDirectory | Out-Null
            $script:Redactions = @($baseDirectory, $runnerTemp, $env:CI_WORKSPACE, $script:LogCanary)
            Register-RemovalRoot $baseDirectory
            $script:Layout = @{
                Base = $baseDirectory
                Downloads = (Join-Path $baseDirectory 'dl')
                ReadOnly = (Join-Path $baseDirectory 'ro')
                Private = (Join-Path $baseDirectory 'priv')
            }
            $script:Lpac = New-ScratchSet (Join-Path $baseDirectory 'scratch')
            $script:Lpac.Project = Join-Path $script:Lpac.Root 'project'
            $script:Control = New-ScratchSet (Join-Path $baseDirectory 'control')
            $layout = $script:Layout
            $layout.RustPrefix = Join-Path $layout.ReadOnly 'rust'
            $layout.RustBin = Join-Path $layout.RustPrefix 'bin'
            $layout.NodeDir = Join-Path $layout.ReadOnly 'node'
            $layout.NpmCli = Join-Path $layout.NodeDir 'node_modules\npm\bin\npm-cli.js'
            $layout.MsvcBin = Join-Path $layout.ReadOnly 'msvc\bin'
            $layout.MsvcLib = Join-Path $layout.ReadOnly 'msvc\lib'
            $layout.SdkUcrt = Join-Path $layout.ReadOnly 'sdk\ucrt'
            $layout.SdkUm = Join-Path $layout.ReadOnly 'sdk\um'
            $layout.ProbeDir = Join-Path $layout.ReadOnly 'probe'
            $layout.ProbeExe = Join-Path $layout.ProbeDir 'kd_probe.exe'
            $layout.TestDir = Join-Path $layout.ReadOnly 'tests'
            $layout.NodeTest = Join-Path $layout.TestDir 'kd_ro.txt'
            $layout.Tarballs = Join-Path $layout.ReadOnly 'tarballs'
            foreach ($directory in @($layout.Base, $layout.Downloads, $layout.ReadOnly, $layout.Private, $script:Lpac.Root, $script:Control.Root)) {
                New-Item -ItemType Directory -Path $directory | Out-Null
            }
            New-Item -ItemType File -Path (Join-Path $layout.Downloads 'acl_probe.txt') | Out-Null

            $phase = 'lpac_profile'
            $box = [KeelDock.Platform.WindowsConfinement.Sandbox]::Create()
            $script:Sid = $box.SidText
            $script:ProfileFolder = Join-Path (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::LocalApplicationData)) 'Packages') $box.ProfileName
            Register-RemovalRoot $script:ProfileFolder

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
            $phase = 'acl_grant'
            foreach ($set in @($script:Lpac, $script:Control)) {
                foreach ($directory in @($set.Tmp, $set.Profile, $set.CargoHome, $set.Crate)) {
                    New-Item -ItemType Directory -Force -Path $directory | Out-Null
                }
            }
            New-Item -ItemType Directory -Force -Path $script:Lpac.Project | Out-Null
            foreach ($directory in @($layout.RustPrefix, $layout.NodeDir, $layout.ProbeDir, $layout.TestDir, $layout.Tarballs)) {
                New-Item -ItemType Directory -Force -Path $directory | Out-Null
            }
            $encoding = New-Object System.Text.UTF8Encoding($false)
            [IO.File]::WriteAllText($layout.NodeTest, 'kd-readonly', $encoding)
            foreach ($npmConfigName in @('empty-user.npmrc', 'empty-global.npmrc')) { [IO.File]::WriteAllText((Join-Path $script:Lpac.Root $npmConfigName), '', $encoding) }
            Write-Line ('windows-confinement-acl=granted ro=read_execute scratch=modify ancestors_read_attributes=' + $script:AncestorPaths.Count + ' ancestors_failed=0')

            $phase = 'fetch'
            $sourceDownloads = @($Downloads)
            foreach ($extra in @('rustfmt', 'clippy')) {
                $sourceDownloads += @{ Name = $extra; File = ($extra + '.tar.gz'); Url = ('https://static.rust-lang.org/dist/' + $RustDate + '/' + $extra + '-' + $RustVersion + '-' + $RustTarget + '.tar.gz'); Sha256 = ''; Root = ($extra + '-' + $RustVersion + '-' + $RustTarget) }
            }
            $extraHashes = @{ rustfmt = '1af7310f4a462eaaa4b737f0325196f2e3a06e8218b3abf68fad0e0ce0310383'; clippy = '36b27d3986ad62f7f17199013706ec568fb7349e29ac983f57b6f9af991cdf03' }
            foreach ($item in $sourceDownloads) {
                if ($extraHashes.ContainsKey($item.Name)) { $item.Sha256 = $extraHashes[$item.Name] }
            }
            $expectedComponents = @{ rustc = 'rustc'; cargo = 'cargo'; rust_std = ('rust-std-' + $RustTarget); rustfmt = 'rustfmt-preview'; clippy = 'clippy-preview' }
            foreach ($item in ($sourceDownloads + @($NodeDownload))) {
                $path = Invoke-Download $item
                Assert-Sha256 $path $item.Sha256 $item.Name
            }
            Write-Line 'windows-source-fetch=verified rust_components=5 node=1'

            $phase = 'stage_rust'
            foreach ($item in $sourceDownloads) {
                $extract = Join-Path $layout.Downloads ('x-' + $item.Name)
                Invoke-Tar (Join-Path $layout.Downloads $item.File) $extract
                $componentRoot = Join-Path $extract $item.Root
                $expectedComponent = $expectedComponents[$item.Name]
                foreach ($component in (Get-Content -LiteralPath (Join-Path $componentRoot 'components'))) {
                    $name = $component.Trim()
                    if ($name.Length -eq 0) { continue }
                    if (-not [string]::Equals($name, $expectedComponent, [StringComparison]::Ordinal)) { throw 'component_name' }
                    $componentSource = Join-Path $componentRoot $name
                    if (-not (Test-Path -LiteralPath $componentSource -PathType Container)) { throw 'component_missing' }
                    Copy-Item -Path (Join-Path $componentSource '*') -Destination $layout.RustPrefix -Recurse -Force
                }
            }
            foreach ($required in @('rustc.exe', 'cargo.exe', 'rustfmt.exe', 'cargo-fmt.exe', 'clippy-driver.exe', 'cargo-clippy.exe')) {
                if (-not (Test-Path -LiteralPath (Join-Path $layout.RustBin $required))) { throw 'rust_layout' }
            }
            if (-not (Test-Path -LiteralPath (Join-Path $layout.RustPrefix ('lib\rustlib\' + $RustTarget + '\lib')))) { throw 'rust_layout' }

            $phase = 'stage_node'
            $nodeExtract = Join-Path $layout.Downloads 'x-node'
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            [System.IO.Compression.ZipFile]::ExtractToDirectory((Join-Path $layout.Downloads $NodeDownload.File), $nodeExtract)
            $nodeRoot = Join-Path $nodeExtract ('node-v' + $NodeVersion + '-win-x64')
            Copy-Item -LiteralPath (Join-Path $nodeRoot 'node.exe') -Destination (Join-Path $layout.NodeDir 'node.exe')
            Copy-Tree (Join-Path $nodeRoot 'node_modules\npm') (Join-Path $layout.NodeDir 'node_modules\npm')
            if (-not (Test-Path -LiteralPath $layout.NpmCli -PathType Leaf)) { throw 'npm_layout' }
            $npmPackage = Get-Content -LiteralPath (Join-Path $layout.NodeDir 'node_modules\npm\package.json') -Raw | ConvertFrom-Json
            if ([string]$npmPackage.version -cne $NpmVersion) { throw 'npm_version' }

            $phase = 'stage_msvc'
            Copy-Tree $msvcBinSource $layout.MsvcBin
            Copy-Tree $msvcLibSource $layout.MsvcLib
            Copy-Tree $sdkUcrtSource $layout.SdkUcrt
            Copy-Tree $sdkUmSource $layout.SdkUm

            $phase = 'stage_sources'
            Initialize-FixtureSources

            $phase = 'canaries'
            $canarySuffix = [Guid]::NewGuid().ToString('N').Substring(0, 8)
            $canaryDirectory = Join-Path $runnerTemp ('kd-canary-' + $canarySuffix)
            $script:CanaryRunnerTemp = Join-Path $canaryDirectory 'canary.txt'
            $script:CanaryWorkspace = Join-Path $env:CI_WORKSPACE ('kd-canary-' + $canarySuffix + '.txt')
            $script:CanaryProfile = Join-Path $env:USERPROFILE ('kd-canary-' + $canarySuffix + '.txt')
            $script:CanaryControl = Join-Path $script:Lpac.Tmp 'kd_canary_control.txt'
            $script:Canaries += $canaryDirectory
            $script:Canaries += $script:CanaryWorkspace
            $script:Canaries += $script:CanaryProfile
            foreach ($rootItem in $script:Canaries) { Register-RemovalRoot $rootItem }
            $canaryFiles = @($script:CanaryRunnerTemp, $script:CanaryWorkspace, $script:CanaryProfile, $script:CanaryControl)
            foreach ($canaryFile in $canaryFiles) {
                if ($canaryFile -notmatch '^[A-Za-z]:\\[A-Za-z0-9_.\\-]+$') { throw 'canary_path' }
            }
            New-Item -ItemType Directory -Path $canaryDirectory | Out-Null
            $script:CanaryNeedle = $script:LogCanary
            $script:CanaryScratchNeedle = [Guid]::NewGuid().ToString('N')
            foreach ($canaryFile in $canaryFiles) {
                $canaryValue = $script:CanaryNeedle
                if ($canaryFile -ceq $script:CanaryControl) { $canaryValue = $script:CanaryScratchNeedle }
                [IO.File]::WriteAllText($canaryFile, $canaryValue, $encoding)
            }

            $phase = 'channel_fixtures'
            Initialize-ChannelContext

            $phase = 'build_probe'
            $probeBuilt = Join-Path $script:Control.Root 'kd_probe_build.exe'
            $probeSource = Join-Path $PSScriptRoot 'windows_probe.rs'
            $probeRustc = Join-Path $layout.RustBin 'rustc.exe'
            $probeArguments = '--edition 2021 -C opt-level=1 -C debuginfo=0 -C link-arg=/DEBUG:NONE -C linker=' + $layout.MsvcBin + '\link.exe -l kernel32 -l ws2_32 -l advapi32 -l userenv -l ole32 -l oleaut32 -o ' + $probeBuilt + ' ' + $probeSource
            $probeEnvironment = New-StageEnvironment $script:Control 'target-probe-build'
            $probeBuild = $box.Run($false, $probeRustc, ('"' + $probeRustc + '" ' + $probeArguments), $script:Control.Root, $probeEnvironment, 240000, [uint32]32)
            if ($probeBuild.Failure -ne '' -or -not $probeBuild.Exited -or $probeBuild.TimedOut -or $probeBuild.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $probeBuilt)) { throw 'probe_build' }
            Copy-Item -LiteralPath $probeBuilt -Destination $layout.ProbeExe
            Write-Line ('windows-confinement-probe=built ms=' + $probeBuild.ElapsedMs)

            $phase = 'acl_readback'
            $aclState = Test-SourceAcl
            Write-Line ('windows-confinement-acl=' + $aclState)
            if ($aclState -ne 'verified') { throw 'acl_readback' }

            $phase = 'null_lease'
            $script:NullLease = [KeelDock.Platform.WindowsConfinement.NullDeviceLease]::Open($script:Sid)
            $nullState = [string]$script:NullLease.Apply()
            $nullReadback = 'mismatch'
            if ($nullState -eq 'applied') { $nullReadback = [string]$script:NullLease.Readback() }
            Write-Line ('windows-confinement-null=' + $nullState + ' mask=0x0012019f trustee=package readback=' + $nullReadback)
            if ($nullState -ne 'applied' -or $nullReadback -ne 'match') { throw 'null_lease' }

            $phase = 'container_temp'
            Initialize-ContainerTemp $box

            $phase = 'nul_other_container'
            Test-OtherContainerNul $box

            $phase = 'channels_before'
            $channelsBefore = Invoke-ChannelPhase $box 'selftest' $true
            if ((Get-ChannelBlockedCount $channelsBefore) -ne $ChannelNames.Count) { $script:RefusalReason = 'channels_before'; throw 'boundary' }
            if (-not (Test-CanariesPresent)) { $script:RefusalReason = 'canary_missing'; throw 'boundary' }

            $phase = 'fixtures'
            $fixtureState = Invoke-FixturePhase $box
            if ($fixtureState -cne 'contained') { $script:RefusalReason = 'fixtures'; throw 'boundary' }

            $phase = 'capsule_verify'
            $bound = Read-BoundValues $capsuleDirectory
            if ($runMode -ceq 'source' -and ([string]$env:CI_SOURCE_SHA -cne $bound['source_sha'])) { throw 'binding' }
            $capsuleItem = Get-Item -LiteralPath $capsulePath -Force -ErrorAction Stop
            if ($capsuleItem.PSIsContainer -or ([int]$capsuleItem.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'capsule_file' }
            if ((Get-FileSha256 $capsulePath) -cne $bound['capsule_sha256']) { throw 'capsule_digest' }
            Write-Line 'windows-source-capsule=verified digest=bound revocation=confirmed'

            $phase = 'decrypt'
            $decryptDirectory = Join-Path $layout.Private 'capsule'
            New-Item -ItemType Directory -Path $decryptDirectory | Out-Null
            $driver = Invoke-FrameDriver @('-Mode', 'decrypt', '-KeyName', $keyName, '-KeyRecord', $keyRecord, '-Capsule', $capsulePath, '-OutputDirectory', $decryptDirectory) 900
            $decryptLine = [regex]::Match([string]$driver.Stdout, '^(capsule-decrypt=observed result=decrypted entries=[0-9]{1,5} bundle_bytes=[0-9]{1,10} key=destroyed x_order=(?:be|le))\r?\n?$')
            if ($driver.TimedOut -or $driver.ExitCode -ne 0 -or -not $decryptLine.Success) {
                $script:RefusalReason = Get-FrameDriverReason ([string]$driver.Stdout)
                throw 'decrypt'
            }
            Write-Line $decryptLine.Groups[1].Value
            $keyState = 'destroyed'

            $phase = 'materialize'
            $manifest = Read-SourceManifest (Join-Path $decryptDirectory 'manifest.tsv')
            if ($manifest.Source -cne $bound['source_sha'] -or $manifest.Tree -cne $bound['tree_id']) { throw 'binding' }
            $bundlePath = Join-Path $decryptDirectory 'bundle.bin'
            $bundleItem = Get-Item -LiteralPath $bundlePath -Force -ErrorAction Stop
            if ([uint64]$bundleItem.Length -ne $manifest.BundleLength -or (Get-FileSha256 $bundlePath) -cne $manifest.BundleSha256) { throw 'bundle_digest' }
            $script:GitPath = Get-TrustedTool 'git.exe'
            $gitHome = Join-Path $layout.Private 'home'
            New-Item -ItemType Directory -Path $gitHome | Out-Null
            $script:GitEnvironment = Get-TrustedEnvironment $script:GitPath $gitHome
            $project = $script:Lpac.Project
            Import-SourceBundle $bound $manifest $bundlePath $project
            Test-ProjectTree $project $manifest.Entries
            Remove-SourceConfigFiles $project
            $lockSha = Get-FileSha256 (Join-Path $project 'package-lock.json')
            if ($lockSha -cne $bound['lock_sha256']) { throw 'lock_digest' }
            $python = Get-TrustedTool 'python.exe'
            $digest = Invoke-TrustedProcess $python @('-B', (Join-Path $PSScriptRoot $GateTableScript), $GateTableManifestCommand, '--root', $project) $PSScriptRoot (Get-TrustedEnvironment $python $layout.Private) 120 4096
            if ($digest.TimedOut -or $digest.ExitCode -ne 0 -or ([string]$digest.Stdout).Trim() -cne $bound['manifest_sha256']) { throw 'manifest_digest' }
            Write-Line ('windows-source-tree=verified entries=' + $manifest.Entries.Count + ' lock=match manifest=match tree=match configs=neutralized')
            Remove-WithinRoots $decryptDirectory
            Remove-WithinRoots (Join-Path $layout.Private 'repo')
            if ((Test-Path -LiteralPath $decryptDirectory) -or (Test-Path -LiteralPath (Join-Path $layout.Private 'repo'))) { throw 'private_cleanup' }

            $phase = 'npm_tarballs'
            $tarballs = Initialize-NpmTarballs $project
            Write-Line ('windows-source-npm=prepared tarballs=' + $tarballs + ' integrity=sha512')
            $aclAfter = Test-SourceAcl
            if ($aclAfter -ne 'verified') { throw 'acl_readback' }

            $phase = 'gate_plan'
            $plan = Get-GatePlan $project ($layout.RustBin + '\cargo.exe') ($layout.NodeDir + '\node.exe') $layout.NpmCli
            Write-Line ('windows-source-gate-plan=ready gates=' + $plan.Count)

            $phase = 'gates'
            $gateOutcome = Invoke-SourceGates $box $plan $project $recordsDirectory
            $script:GateFailure = [int]$gateOutcome.Failure

            $phase = 'channels_after'
            $channelsAfter = Invoke-ChannelPhase $box 'recheck' $true
            if (-not (Test-CanariesPresent)) { $script:RefusalReason = 'canary_missing'; throw 'boundary' }

            $phase = 'cleanup_links'
            Initialize-LinkFixtures

            $channelRecord = [ordered]@{}
            foreach ($name in $RecordChannelNames) {
                $channelRecord[$name] = Get-ChannelRecordEntry $channelsBefore $channelsAfter $name
            }
            $channelsAllBlocked = $true
            foreach ($name in $RecordChannelNames) {
                $entry = $channelRecord[$name]
                if ($entry.status -cne 'blocked' -or -not $entry.before -or -not $entry.after) { $channelsAllBlocked = $false }
            }
            $memoryCanary = 'present'
            if ((Test-ChannelRecord $channelsBefore 'process_memory') -and (Test-ChannelRecord $channelsAfter 'process_memory')) { $memoryCanary = 'absent' }
            $fileCanary = 'present'
            if ((Test-ChannelRecord $channelsBefore 'runner_files') -and (Test-ChannelRecord $channelsAfter 'runner_files') -and $gateOutcome.Canary -ceq 'absent') { $fileCanary = 'absent' }
            $projectExecution = 'failed'
            if ($gateOutcome.Failed -eq 0 -and $gateOutcome.Count -eq $plan.Count) { $projectExecution = 'completed' }
            $record = [ordered]@{
                schema_version = 1
                os = 'windows'
                boundary = 'lpac-job'
                role = $role
                mode = $runMode
                channels = $channelRecord
                memory_canary = $memoryCanary
                readable_file_canary = $fileCanary
                handoff = 'verified'
                project_execution = $projectExecution
                gates = [int]$gateOutcome.Count
                failed = [int]$gateOutcome.Failed
                token_revocation = 'confirmed'
                log_canary = [string]$gateOutcome.Canary
            }
            Write-PrivateRecord $record
            if ($gateOutcome.Failed -ne 0) { throw $script:RefusalReason }
            if (-not $channelsAllBlocked) { $script:RefusalReason = 'channels_after'; throw 'boundary' }
            $summary = 'windows-source-run=observed role=' + $role + ' mode=' + $runMode + ' lpac=verified capabilities=registryRead job=verified acl=verified channels_before=blocked channels_after=blocked channel_controls=fired fixtures=contained handoff=verified key=destroyed tree=verified lock=match manifest=match gates=' + $gateOutcome.Count + ' failed=0 log_canary=absent project_execution=completed'
            Write-Line $summary
            $exitCode = 0
        }
    }
} catch {
    $reason = [string]$_.Exception.Message
    $detailText = ''
    if ($reason -cnotmatch '^[a-z][a-z0-9_]{0,40}$') {
        $typeName = [regex]::Replace([string]$_.Exception.GetType().Name, '[^A-Za-z]', '')
        if ($typeName.Length -gt 40) { $typeName = $typeName.Substring(0, 40) }
        $detailText = ' type=' + $typeName
        $reason = 'unexpected'
    }
    if ($script:RefusalReason.Length -gt 0 -and $script:RefusalReason -cne $reason -and $script:RefusalReason -cmatch '^[a-z][a-z0-9_]{0,40}$') { $detailText = ' detail=' + $script:RefusalReason }
    $safePhase = [regex]::Replace([string]$phase, '[^A-Za-z0-9_]', '_')
    $gateText = ''
    if ($phase -ceq 'gates' -and $script:GateFailure -gt 0) {
        $gateText = ' gate=' + $script:GateFailure
        if (@('timeout', 'limit', 'signal', 'exit', 'launch', 'deadline') -ccontains $script:GateCause) { $gateText += ' cause=' + $script:GateCause }
    }
    $refusal = 'windows-source-run=refused phase=' + $safePhase + ' reason=' + $reason + $detailText + $gateText
}

if ($Mode -eq 'run' -and $libraryLoaded) {
    $nullRestore = 'not_applied'
    try {
        if ($script:NullLease -ne $null) { $nullRestore = [string]$script:NullLease.Restore() }
    } catch {
        $nullRestore = 'failed'
    }
    if ($nullRestore -eq 'failed') { $cleanup = 'incomplete' }

    $processState = 'none'
    try {
        $processState = Get-JobLiveness @($box, $script:OtherBox) 10
    } catch {
        $processState = 'unknown'
    }
    if ($processState -ne 'none') { $cleanup = 'incomplete' }

    $keyCleanup = 'not_applicable'
    try {
        $keyNameText = ''
        if ($env:KD_KEY_DIRECTORY -and (Test-Path -LiteralPath (Join-Path $env:KD_KEY_DIRECTORY 'key-name.txt'))) { $keyNameText = ([IO.File]::ReadAllText((Join-Path $env:KD_KEY_DIRECTORY 'key-name.txt'))).Trim() }
        if ($keyNameText -cmatch '^kd-receiver-[0-9a-f]{32}$') {
            $destroy = Invoke-FrameDriver @('-Mode', 'destroy', '-KeyName', $keyNameText) 120
            $keyCleanup = 'destroyed'
            if ($destroy.TimedOut -or $destroy.ExitCode -ne 0 -or ([string]$destroy.Stdout).Trim() -cne 'capsule-destroy=observed key=destroyed') { $keyCleanup = 'failed' }
        }
    } catch {
        $keyCleanup = 'failed'
    }
    if ($keyCleanup -ceq 'failed') { $cleanup = 'incomplete' }

    try {
        Remove-Canaries
    } catch {
        $cleanup = 'incomplete'
    }

    try {
        Remove-ChannelFixtures
    } catch {
        $cleanup = 'incomplete'
    }

    try {
        if ($processState -eq 'none' -and $script:ProfileFolder -and (Test-Path -LiteralPath $script:ProfileFolder)) { Remove-ReparsePoints $script:ProfileFolder }
        if ($processState -eq 'none' -and $script:OtherFolder -and (Test-Path -LiteralPath $script:OtherFolder)) { Remove-ReparsePoints $script:OtherFolder }
    } catch {
        $cleanup = 'incomplete'
    }

    $profileState = 'not_created'
    try {
        if ($box -ne $null) {
            $box.Dispose()
            if (-not $box.CleanupComplete) { $cleanup = 'incomplete' }
            $profileState = 'deleted_by_api'
            if ($processState -eq 'none' -and $script:ProfileFolder -and (Test-Path -LiteralPath $script:ProfileFolder)) {
                Remove-WithinRoots $script:ProfileFolder
                $profileState = 'removed_manually'
            }
            if ($script:ProfileFolder -and (Test-Path -LiteralPath $script:ProfileFolder)) { $profileState = 'failed' }
        }
    } catch {
        $profileState = 'failed'
    }
    if ($profileState -eq 'failed') { $cleanup = 'incomplete' }

    try {
        if ($script:OtherBox -ne $null) {
            $script:OtherBox.Dispose()
            if (-not $script:OtherBox.CleanupComplete) { $cleanup = 'incomplete' }
            if ($processState -eq 'none' -and $script:OtherFolder -and (Test-Path -LiteralPath $script:OtherFolder)) {
                Remove-WithinRoots $script:OtherFolder
            }
            if ($script:OtherFolder -and (Test-Path -LiteralPath $script:OtherFolder)) { $cleanup = 'incomplete' }
        }
    } catch {
        $cleanup = 'incomplete'
    }

    $tempState = 'removed'
    try {
        if ($processState -eq 'none' -and $baseDirectory -and (Test-Path -LiteralPath $baseDirectory)) {
            Remove-WithinRoots $baseDirectory
        }
        if ($baseDirectory -and (Test-Path -LiteralPath $baseDirectory)) { $tempState = 'failed' }
        if ($script:ExpectedTemp -and (Test-Path -LiteralPath $script:ExpectedTemp)) { $tempState = 'failed' }
    } catch {
        $tempState = 'failed'
    }
    if ($tempState -eq 'failed') { $cleanup = 'incomplete' }

    $linksState = 'not_planted'
    try {
        if ($script:TrapDirectory) {
            $linksState = 'verified'
            if ($script:PlantedJunctions -lt 3) { $linksState = 'incomplete' }
            if (-not (Test-Path -LiteralPath $script:TrapSentinel -PathType Leaf)) { $linksState = 'followed' }
            elseif ([IO.File]::ReadAllText($script:TrapSentinel) -cne 'kd-sentinel') { $linksState = 'followed' }
            Remove-WithinRoots $script:TrapDirectory
            if (Test-Path -LiteralPath $script:TrapDirectory) { $linksState = 'failed' }
        }
    } catch {
        $linksState = 'failed'
    }
    if (@('verified', 'not_planted') -cnotcontains $linksState) { $cleanup = 'incomplete' }

    $profileText = 'deleted'
    if (@('deleted_by_api', 'removed_manually') -cnotcontains $profileState) { $profileText = $profileState }
    $cleanupLine = 'windows-source-cleanup=' + $cleanup + ' null_restore=' + $nullRestore + ' key=' + $keyCleanup + ' profile=' + $profileText + ' temp_dir=' + $tempState + ' links=' + $linksState + ' processes=' + $processState + ' liveness=job'
    if ($refusal) {
        Write-Line $refusal
        Write-Line $cleanupLine
        exit 1
    }
    Write-Line $cleanupLine
    if ($cleanup -ne 'verified' -or $nullRestore -ne 'verified' -or $keyCleanup -ne 'destroyed' -or $profileText -ne 'deleted' -or $tempState -ne 'removed' -or $linksState -ne 'verified' -or $processState -ne 'none') { $exitCode = 1 }
    exit $exitCode
}

if ($refusal) {
    Write-Line $refusal
    exit 1
}
exit $exitCode
