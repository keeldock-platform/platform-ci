param(
    [ValidateSet('parent', 'child', 'sid')]
    [string]$Mode = 'parent',
    [string]$Path = '',
    [string]$Marker = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows_confinement_recovery.ps1')

$goodSids = @('S-1-15-2-1-1-1-1-1-1-1', 'S-1-15-2-4294967295-1-2-3-4-5-6')
$badSids = @('S-1-15-2-1-1-1-1-1-1-1-1', 'S-1-15-2-1-1-1-1-1-1', 'S-1-15-2-1-1-1-1-1-1-12345678901', "S-1-15-2-1-1-1-1-1-1-1`n", 'S-1-15-2-1-1-1-1-1-1-a', 'S-1-15-2-1-1-1-1-1--1')
$prefix = 'SYSTEM\CurrentControlSet\Services\WinSock2\Parameters'
$goodPaths = @($prefix, ($prefix + '\Protocol_Catalog9'), ($prefix + '\NameSpace_Catalog5'), ($prefix + '\Protocol_Catalog9\Catalog_Entries'), ($prefix + '\NameSpace_Catalog5\Catalog_Entries64'), ($prefix + '\Protocol_Catalog9\Catalog_Entries64\000000000001'))
$badPaths = @(($prefix + '\Other'), ($prefix + '\Protocol_Catalog9\Other'), ($prefix + '\Protocol_Catalog9\Catalog_Entries\1'), ($prefix + '\Protocol_Catalog9\Catalog_Entries\000000000001\x'), ($prefix + "\Protocol_Catalog9`n"), 'SYSTEM\CurrentControlSet\Services\WinSock2', 'SOFTWARE\KeelDock\ConfinementRecoveryTest\short')

if ($Mode -eq 'sid') {
    foreach ($item in $goodSids) {
        if (-not (Test-PackageSid $item)) { throw 'recovery_test_sid' }
    }
    foreach ($item in $badSids) {
        if (Test-PackageSid $item) { throw 'recovery_test_sid' }
    }
    foreach ($item in $goodPaths) { Assert-CatalogPath $item }
    $scratchPrefix = 'SOFTWARE\KeelDock\ConfinementRecoveryTest\'
    Assert-ScratchPath ($scratchPrefix + ('a1' * 16))
    foreach ($item in @(($scratchPrefix + ('a1' * 15)), ($scratchPrefix + ('A1' * 16)), ($scratchPrefix + ('a1' * 16) + '\000000000001'), ($scratchPrefix + ('a1' * 16) + "`n"), $prefix, ($prefix + '\Protocol_Catalog9'), 'SOFTWARE\KeelDock\ConfinementRecoveryTest')) {
        $refused = $false
        try { Assert-ScratchPath $item } catch {
            if ($_.Exception.Message -ne 'winsock_catalog_path') { throw }
            $refused = $true
        }
        if (-not $refused) { throw 'recovery_test_path' }
    }
    foreach ($item in $badPaths) {
        $refused = $false
        try { Assert-CatalogPath $item } catch {
            if ($_.Exception.Message -ne 'winsock_catalog_path') { throw }
            $refused = $true
        }
        if (-not $refused) { throw 'recovery_test_path' }
    }
    exit 0
}

if ($Mode -eq 'child') {
    $lease = New-CatalogLease $Path 'S-1-15-2-1-1-1-1-1-1-1'
    try {
        Start-CatalogRecovery $lease (Join-Path $PSScriptRoot 'windows_confinement_recovery.ps1')
        Add-CatalogScratchKeys $lease
        Add-CatalogRead $lease
        [IO.File]::WriteAllText($Marker, ([string]$lease.RecoveryDirectory + "`n" + [string]$lease.ScratchList[0] + "`n" + [string]$lease.ScratchList[1]))
        while ($true) { Start-Sleep -Seconds 1 }
    } finally {
        Restore-CatalogAcl $lease
        Stop-CatalogRecovery $lease
    }
    exit 0
}

$Path = 'SOFTWARE\KeelDock\ConfinementRecoveryTest\' + [Guid]::NewGuid().ToString('N')
$Marker = Join-Path $env:RUNNER_TEMP ('kd-recovery-' + [Guid]::NewGuid().ToString('N'))
$base = $null
$child = $null
$original = $null
$originalChild = $null
$childPath = $null
$directory = $null
$scratchList = $null
try {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $key = $base.CreateSubKey($Path)
    if (-not $key) { throw 'recovery_test_create' }
    $key.Dispose()
    $childPath = $Path + '\000000000001'
    $childKey = $base.CreateSubKey($childPath)
    if (-not $childKey) { throw 'recovery_test_create' }
    $childKey.Dispose()
    $original = Get-CatalogAclSddl $Path
    $originalChild = Get-CatalogAclSddl $childPath
    $arguments = '-NoProfile -NonInteractive -File "' + $PSCommandPath + '" -Mode child -Path "' + $Path + '" -Marker "' + $Marker + '"'
    $child = Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') -ArgumentList $arguments -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while (-not (Test-Path -LiteralPath $Marker)) {
        if ($child.HasExited -or [DateTime]::UtcNow -ge $deadline) { throw 'recovery_test_child' }
        Start-Sleep -Milliseconds 100
    }
    $markerLines = [IO.File]::ReadAllText($Marker) -split "`n"
    $directory = $markerLines[0]
    $scratchList = @($markerLines[1], $markerLines[2])
    foreach ($scratch in $scratchList) {
        if ($null -eq (Get-CatalogSubKeyNames $scratch)) { throw 'recovery_test_scratch' }
    }
    if ((Get-CatalogAclSddl $Path) -eq $original -or (Get-CatalogAclSddl $childPath) -eq $originalChild) { throw 'recovery_test_not_mutated' }
    $child.Kill()
    if (-not $child.WaitForExit(5000)) { throw 'recovery_test_kill' }
    $taskName = Split-Path -Leaf $directory
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    $restored = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Get-CatalogAclSddl $Path) -eq $original -and (Get-CatalogAclSddl $childPath) -eq $originalChild -and $null -eq (Get-CatalogSubKeyNames $scratchList[0]) -and $null -eq (Get-CatalogSubKeyNames $scratchList[1]) -and -not (Test-Path -LiteralPath $directory) -and
            -not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
            $restored = $true
            break
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not $restored) { throw 'recovery_test_restore' }
    $common = [Environment]::GetFolderPath('CommonApplicationData')
    $before = @(Get-ChildItem -LiteralPath $common -Directory -Force -Filter 'KDWindowsConfinementRecovery_*').Count
    $reason = ''
    $testParent = 'SOFTWARE\KeelDock\ConfinementRecoveryTest'
    $parentKey = $base.OpenSubKey($testParent, $false)
    $keysBefore = @($parentKey.GetSubKeyNames()).Count
    $parentKey.Dispose()
    try { Grant-WinsockCatalogRead 'S-1-15-2-1-1-1-1-1-1-1' $Path -ForceReadbackFailure } catch { $reason = [string]$_.Exception.Message }
    if ($reason -ne 'winsock_catalog_readback') { throw 'recovery_test_injection' }
    if ($script:WinsockCatalogLease) { throw 'recovery_test_lease' }
    $parentKey = $base.OpenSubKey($testParent, $false)
    $keysAfter = @($parentKey.GetSubKeyNames()).Count
    $parentKey.Dispose()
    if ($keysAfter -ne $keysBefore) { throw 'recovery_test_scratch' }
    if ((Get-CatalogAclSddl $Path) -ne $original -or (Get-CatalogAclSddl $childPath) -ne $originalChild) { throw 'recovery_test_rollback' }
    $after = @(Get-ChildItem -LiteralPath $common -Directory -Force -Filter 'KDWindowsConfinementRecovery_*').Count
    if ($after -ne $before) { throw 'recovery_test_leak' }
    if (@(Get-ScheduledTask -TaskName 'KDWindowsConfinementRecovery_*' -ErrorAction SilentlyContinue).Count -ne 0) { throw 'recovery_test_leak' }
    $caught = $false
    try { Restore-CatalogAcl @{ Path = $Path; KeyList = @(@{ Path = $Path; OriginalSddl = 'invalid' }) } } catch {
        if ($_.Exception.Message -ne 'winsock_restore_failed') { throw }
        $caught = $true
    }
    if (-not $caught -or (Get-CatalogAclSddl $Path) -ne $original -or (Get-CatalogAclSddl $childPath) -ne $originalChild) { throw 'recovery_test_reason' }
    foreach ($badSid in $badSids) {
        $refused = $false
        try { [void](New-CatalogLease $Path $badSid) } catch {
            if ($_.Exception.Message -ne 'winsock_package_sid') { throw }
            $refused = $true
        }
        if (-not $refused) { throw 'recovery_test_sid' }
    }
} finally {
    if ($child) {
        if (-not $child.HasExited) { $child.Kill(); [void]$child.WaitForExit(5000) }
        $child.Dispose()
    }
    if ($original) {
        try { Restore-CatalogAcl @{ Path = $Path; KeyList = @(@{ Path = $Path; OriginalSddl = $original }, @{ Path = $childPath; OriginalSddl = $originalChild }) } } catch { }
    }
    if ($scratchList -and $scratchList[0] -and $scratchList[1]) {
        try { Remove-CatalogScratchKeys $scratchList } catch { }
    }
    if ($directory) {
        $taskName = Split-Path -Leaf $directory
        try { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction Stop } catch { }
        if (Test-Path -LiteralPath $directory) { Remove-Item -LiteralPath $directory -Recurse -Force -ErrorAction SilentlyContinue }
    }
    if ($base) {
        try { $base.DeleteSubKeyTree($Path, $false) } catch { }
        $base.Dispose()
    }
    if (Test-Path -LiteralPath $Marker) { Remove-Item -LiteralPath $Marker -Force }
}
exit 0
