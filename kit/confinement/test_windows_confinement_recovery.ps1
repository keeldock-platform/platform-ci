param(
    [ValidateSet('parent', 'child')]
    [string]$Mode = 'parent',
    [string]$Path = '',
    [string]$Marker = ''
)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'windows_confinement_recovery.ps1')

if ($Mode -eq 'child') {
    $lease = New-CatalogLease $Path 'S-1-15-2-1-1-1-1-1-1-1-1'
    try {
        Start-CatalogRecovery $lease (Join-Path $PSScriptRoot 'windows_confinement_recovery.ps1')
        Add-CatalogRead $lease
        [IO.File]::WriteAllText($Marker, [string]$lease.RecoveryDirectory)
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
$directory = $null
try {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $key = $base.CreateSubKey($Path)
    if (-not $key) { throw 'recovery_test_create' }
    $key.Dispose()
    $original = Get-CatalogAclSddl $Path
    $arguments = '-NoProfile -NonInteractive -File "' + $PSCommandPath + '" -Mode child -Path "' + $Path + '" -Marker "' + $Marker + '"'
    $child = Start-Process -FilePath (Join-Path $PSHOME 'pwsh.exe') -ArgumentList $arguments -PassThru
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while (-not (Test-Path -LiteralPath $Marker)) {
        if ($child.HasExited -or [DateTime]::UtcNow -ge $deadline) { throw 'recovery_test_child' }
        Start-Sleep -Milliseconds 100
    }
    $directory = [IO.File]::ReadAllText($Marker)
    if ((Get-CatalogAclSddl $Path) -eq $original) { throw 'recovery_test_not_mutated' }
    $child.Kill()
    if (-not $child.WaitForExit(5000)) { throw 'recovery_test_kill' }
    $ack = Join-Path $directory 'ack'
    $taskName = Split-Path -Leaf $directory
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    $restored = $false
    while ([DateTime]::UtcNow -lt $deadline) {
        if ((Get-CatalogAclSddl $Path) -eq $original -and (Test-Path -LiteralPath $ack) -and
            ([IO.File]::ReadAllText($ack) -eq 'restored') -and
            -not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
            $restored = $true
            break
        }
        Start-Sleep -Milliseconds 100
    }
    if (-not $restored) { throw 'recovery_test_restore' }
    $lease = New-CatalogLease $Path 'S-1-15-2-1-1-1-1-1-1-1-1'
    try {
        Start-CatalogRecovery $lease (Join-Path $PSScriptRoot 'windows_confinement_recovery.ps1')
        $caught = $false
        try { Add-CatalogRead $lease -ForceReadbackFailure } catch {
            if ($_.Exception.Message -ne 'winsock_catalog_readback') { throw }
            $caught = $true
        }
        if (-not $caught -or (Get-CatalogAclSddl $Path) -eq $original) { throw 'recovery_test_injection' }
        Restore-CatalogAcl $lease
        Stop-CatalogRecovery $lease
        $lease = $null
        if ((Get-CatalogAclSddl $Path) -ne $original) { throw 'recovery_test_rollback' }
    } finally {
        if ($lease) {
            try { Restore-CatalogAcl $lease; Stop-CatalogRecovery $lease } catch { }
        }
    }
    $caught = $false
    try { Restore-CatalogAcl @{ Path = $Path; OriginalSddl = 'invalid' } } catch {
        if ($_.Exception.Message -ne 'winsock_restore_failed') { throw }
        $caught = $true
    }
    if (-not $caught -or (Get-CatalogAclSddl $Path) -ne $original) { throw 'recovery_test_reason' }
} finally {
    if ($child) {
        if (-not $child.HasExited) { $child.Kill(); [void]$child.WaitForExit(5000) }
        $child.Dispose()
    }
    if ($original) {
        try { Restore-CatalogAcl @{ Path = $Path; OriginalSddl = $original } } catch { }
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
