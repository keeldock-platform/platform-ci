param(
    [ValidateSet('library', 'watch')]
    [string]$RecoveryMode = 'library',
    [string]$LeaseFile = '',
    [string]$ReadyFile = '',
    [string]$DoneFile = '',
    [string]$AckFile = ''
)

function Assert-CatalogPath([string]$path) {
    $production = 'SYSTEM\CurrentControlSet\Services\WinSock2\Parameters\Protocol_Catalog9'
    $testPrefix = 'SOFTWARE\KeelDock\ConfinementRecoveryTest\'
    if ($path -eq $production) { return }
    if ($path.StartsWith($testPrefix, [StringComparison]::Ordinal) -and
        $path.Substring($testPrefix.Length) -match '^[a-f0-9]{32}$') { return }
    throw 'winsock_catalog_path'
}

function Get-CatalogAclSddl([string]$path) {
    Assert-CatalogPath $path
    $base = $null
    $key = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $rights = [System.Security.AccessControl.RegistryRights]::ReadKey -bor [System.Security.AccessControl.RegistryRights]::ChangePermissions
        $key = $base.OpenSubKey($path, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $rights)
        if ($null -eq $key) { throw 'winsock_catalog_missing' }
        $security = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
        return $security.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access)
    } catch {
        if ($_.Exception.Message -eq 'winsock_catalog_missing') { throw 'winsock_catalog_missing' }
        throw 'winsock_registry_read'
    } finally {
        if ($key) { $key.Dispose() }
        if ($base) { $base.Dispose() }
    }
}

function New-CatalogLease([string]$path, [string]$sid) {
    Assert-CatalogPath $path
    if ($sid -notmatch '^S-1-15-2-(?:[0-9]+-){7}[0-9]+$') { throw 'winsock_package_sid' }
    return @{ Path = $path; Sid = $sid; OriginalSddl = (Get-CatalogAclSddl $path) }
}

function Add-CatalogRead($lease, [switch]$ForceReadbackFailure) {
    Assert-CatalogPath ([string]$lease.Path)
    if (-not $lease.TaskRegistered -or -not $lease.ReadyFile -or -not (Test-Path -LiteralPath ([string]$lease.ReadyFile))) {
        throw 'winsock_recovery_state'
    }
    if ($ForceReadbackFailure -and -not ([string]$lease.Path).StartsWith('SOFTWARE\KeelDock\ConfinementRecoveryTest\', [StringComparison]::Ordinal)) {
        throw 'winsock_grant_failed'
    }
    $base = $null
    $key = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $rights = [System.Security.AccessControl.RegistryRights]::ReadKey -bor [System.Security.AccessControl.RegistryRights]::ChangePermissions
        $key = $base.OpenSubKey([string]$lease.Path, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $rights)
        if ($null -eq $key) { throw 'winsock_catalog_missing' }
        $security = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
        if ($security.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access) -ne [string]$lease.OriginalSddl) {
            throw 'winsock_catalog_changed'
        }
        $identity = New-Object System.Security.Principal.SecurityIdentifier([string]$lease.Sid)
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule($identity, [System.Security.AccessControl.RegistryRights]::ReadKey, [System.Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
        if (-not $lease.ArmedFile) { throw 'winsock_recovery_state' }
        [IO.File]::WriteAllText([string]$lease.ArmedFile, 'armed')
        $key.SetAccessControl($security)
        if ($ForceReadbackFailure) { throw 'winsock_catalog_readback' }
        $readBack = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
        $rules = $readBack.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        $writeMask = [System.Security.AccessControl.RegistryRights]'SetValue, CreateSubKey, Delete, ChangePermissions, TakeOwnership'
        $found = $false
        foreach ($entry in $rules) {
            if ($entry.IdentityReference.Value -eq [string]$lease.Sid -and $entry.AccessControlType -eq 'Allow'
                -and -not $entry.IsInherited -and $entry.InheritanceFlags -eq [System.Security.AccessControl.InheritanceFlags]::None
                -and ($entry.RegistryRights -band [System.Security.AccessControl.RegistryRights]::ReadKey) -eq [System.Security.AccessControl.RegistryRights]::ReadKey
                -and ($entry.RegistryRights -band $writeMask) -eq 0) { $found = $true }
        }
        if (-not $found) { throw 'winsock_catalog_readback' }
    } catch {
        if ($_.Exception.Message -in @('winsock_catalog_missing', 'winsock_catalog_changed', 'winsock_catalog_readback')) { throw $_.Exception.Message }
        throw 'winsock_grant_failed'
    } finally {
        if ($key) { $key.Dispose() }
        if ($base) { $base.Dispose() }
    }
}

function Restore-CatalogAcl($lease) {
    if ($null -eq $lease -or [string]::IsNullOrEmpty([string]$lease.OriginalSddl)) { throw 'winsock_restore_state' }
    Assert-CatalogPath ([string]$lease.Path)
    $base = $null
    $key = $null
    try {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
        $rights = [System.Security.AccessControl.RegistryRights]::ReadKey -bor [System.Security.AccessControl.RegistryRights]::ChangePermissions
        $key = $base.OpenSubKey([string]$lease.Path, [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, $rights)
        if ($null -eq $key) { throw 'winsock_catalog_missing' }
        $restore = New-Object System.Security.AccessControl.RegistrySecurity
        $restore.SetSecurityDescriptorSddlForm([string]$lease.OriginalSddl, [System.Security.AccessControl.AccessControlSections]::Access)
        $key.SetAccessControl($restore)
        $actual = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::Access)
        if ($actual.GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]::Access) -ne [string]$lease.OriginalSddl) {
            throw 'winsock_restore_readback'
        }
    } catch {
        if ($_.Exception.Message -eq 'winsock_restore_readback') { throw 'winsock_restore_readback' }
        throw 'winsock_restore_failed'
    } finally {
        if ($key) { $key.Dispose() }
        if ($base) { $base.Dispose() }
    }
}

function Start-CatalogRecovery($lease, [string]$source) {
    try {
        $name = 'KDWindowsConfinementRecovery_' + [Guid]::NewGuid().ToString('N')
        $directory = Join-Path $env:ProgramData $name
        $lease.RecoveryDirectory = $directory
        $lease.TaskName = $name
        $info = [IO.Directory]::CreateDirectory($directory)
        $security = New-Object System.Security.AccessControl.DirectorySecurity
        $security.SetAccessRuleProtection($true, $false)
        foreach ($sidText in @('S-1-5-18', 'S-1-5-32-544')) {
            $identity = New-Object System.Security.Principal.SecurityIdentifier($sidText)
            $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, [System.Security.AccessControl.FileSystemRights]::FullControl, [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit', [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
            $security.AddAccessRule($rule)
        }
        [IO.FileSystemAclExtensions]::SetAccessControl($info, $security)
        $readBack = [IO.FileSystemAclExtensions]::GetAccessControl($info)
        $entries = @($readBack.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        if ($entries.Count -ne 2 -or @($entries | Where-Object { $_.IsInherited -or $_.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544') }).Count -ne 0) {
            throw 'winsock_recovery_acl'
        }
        $copy = Join-Path $directory 'recovery.ps1'
        $record = Join-Path $directory 'lease.json'
        $ready = Join-Path $directory 'ready'
        $done = Join-Path $directory 'done'
        $ack = Join-Path $directory 'ack'
        $lease.ArmedFile = Join-Path $directory 'armed'
        $lease.ReadyFile = $ready
        $lease.DoneFile = $done
        $lease.AckFile = $ack
        Copy-Item -LiteralPath $source -Destination $copy -ErrorAction Stop
        $parent = [Diagnostics.Process]::GetCurrentProcess()
        $data = @{ Path = [string]$lease.Path; OriginalSddl = [string]$lease.OriginalSddl; ParentPid = $parent.Id; ParentStartTicks = $parent.StartTime.ToUniversalTime().Ticks }
        [IO.File]::WriteAllText($record, ($data | ConvertTo-Json -Compress), (New-Object System.Text.UTF8Encoding($false)))
        $arguments = '-NoProfile -NonInteractive -File "' + $copy + '" -RecoveryMode watch -LeaseFile "' + $record + '" -ReadyFile "' + $ready + '" -DoneFile "' + $done + '" -AckFile "' + $ack + '"'
        $action = New-ScheduledTaskAction -Execute (Join-Path $PSHOME 'pwsh.exe') -Argument $arguments
        $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddHours(2)
        $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
        $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 3) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
        Register-ScheduledTask -TaskName $name -Action $action -Trigger $trigger -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
        $lease.TaskRegistered = $true
        Start-ScheduledTask -TaskName $name -ErrorAction Stop
        $deadline = [DateTime]::UtcNow.AddSeconds(30)
        while (-not (Test-Path -LiteralPath $ready)) {
            if ([DateTime]::UtcNow -ge $deadline) { throw 'winsock_recovery_ready' }
            Start-Sleep -Milliseconds 100
        }
    } catch {
        if ($_.Exception.Message -in @('winsock_recovery_acl', 'winsock_recovery_ready')) { throw $_.Exception.Message }
        throw 'winsock_recovery_start'
    }
}

function Stop-CatalogRecovery($lease) {
    try {
        if ($lease.TaskRegistered) {
            if (Test-Path -LiteralPath ([string]$lease.ReadyFile)) {
                [IO.File]::WriteAllText([string]$lease.DoneFile, 'done')
                $deadline = [DateTime]::UtcNow.AddSeconds(30)
                while (-not (Test-Path -LiteralPath ([string]$lease.AckFile))) {
                    if ([DateTime]::UtcNow -ge $deadline) { throw 'winsock_recovery_stop' }
                    Start-Sleep -Milliseconds 100
                }
                if ([IO.File]::ReadAllText([string]$lease.AckFile) -ne 'done') { throw 'winsock_recovery_stop' }
            }
            Unregister-ScheduledTask -TaskName ([string]$lease.TaskName) -Confirm:$false -ErrorAction Stop
            $lease.TaskRegistered = $false
        }
        if ($lease.RecoveryDirectory -and (Test-Path -LiteralPath ([string]$lease.RecoveryDirectory))) {
            Remove-Item -LiteralPath ([string]$lease.RecoveryDirectory) -Recurse -Force -ErrorAction Stop
        }
    } catch {
        throw 'winsock_recovery_stop'
    }
}

function Invoke-CatalogWatch([string]$record, [string]$ready, [string]$done, [string]$ack) {
    $data = Get-Content -LiteralPath $record -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    Assert-CatalogPath ([string]$data.Path)
    if ([string]::IsNullOrEmpty([string]$data.OriginalSddl)) { throw 'winsock_recovery_record' }
    $parent = $null
    try { $parent = [Diagnostics.Process]::GetProcessById([int]$data.ParentPid) } catch { }
    if ($parent -and $parent.StartTime.ToUniversalTime().Ticks -ne [long]$data.ParentStartTicks) { $parent = $null }
    if ($parent) {
        [IO.File]::WriteAllText($ready, 'ready')
        while ($true) {
            if (Test-Path -LiteralPath $done) {
                [IO.File]::WriteAllText($ack, 'done')
                return
            }
            if ($parent.WaitForExit(250)) { break }
        }
    }
    if ((Test-Path -LiteralPath $done) -or -not (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $record) 'armed'))) {
        try { Unregister-ScheduledTask -TaskName (Split-Path -Leaf (Split-Path -Parent $record)) -Confirm:$false -ErrorAction Stop } catch { }
        return
    }
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try {
            Restore-CatalogAcl $data
            [IO.File]::WriteAllText($done, 'restored')
            [IO.File]::WriteAllText($ack, 'restored')
            try {
                Unregister-ScheduledTask -TaskName (Split-Path -Leaf (Split-Path -Parent $record)) -Confirm:$false -ErrorAction Stop
            } catch { }
            return
        } catch {
            Start-Sleep -Seconds 1
        }
    }
    [IO.File]::WriteAllText($ack, 'failed')
    throw 'winsock_recovery_failed'
}

if ($RecoveryMode -eq 'watch') {
    $ErrorActionPreference = 'Stop'
    Invoke-CatalogWatch $LeaseFile $ReadyFile $DoneFile $AckFile
}
