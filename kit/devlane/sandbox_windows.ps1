param(
    [ValidateSet('create', 'firewall-install', 'firewall-remove', 'run', 'delete')]
    [string]$Mode,
    [Parameter(Mandatory = $true)]
    [string]$StateFile,
    [string]$RequestFile
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$cleanupReason = $null
$script:OwnedRoots = @()
function Write-LauncherPhase([string]$Phase) {
    if ($Phase -notin @('types-load', 'appcontainer-sid', 'token-create', 'acl-grant', 'job-create',
            'process-create-suspended', 'job-assign', 'resume', 'wait', 'exit')) { throw }
    [Console]::Out.WriteLine('windows_launcher_phase=' + $Phase)
    [Console]::Out.Flush()
}
function Start-CleanupBudget {
    $script:WindowsCleanupTimer = [Diagnostics.Stopwatch]::StartNew()
    $script:WindowsCleanupEntries = 0
}
function Assert-CleanupBudgetTime {
    if ($script:WindowsCleanupTimer.ElapsedMilliseconds -gt 600000) {
        $script:cleanupReason = 'other'
        throw
    }
}
function Add-CleanupBudgetEntry([int]$PendingCount = 0) {
    Assert-CleanupBudgetTime
    if ($script:WindowsCleanupEntries -ge 250000 -or $PendingCount -ge 250000) {
        $script:cleanupReason = 'other'
        throw
    }
    $script:WindowsCleanupEntries++
}
function Get-CleanupPathInfo([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Length -gt 4096 -or
            -not [IO.Path]::IsPathRooted($Path)) { throw }
    $fullPath = [IO.Path]::GetFullPath($Path)
    $root = [IO.Path]::GetPathRoot($fullPath)
    if ([string]::IsNullOrEmpty($root) -or $root.Length -ne 3 -or $fullPath.StartsWith('\\') -or
            $fullPath.StartsWith('\\?\') -or $fullPath.StartsWith('\\.\')) { throw }
    $current = $root
    $item = $null
    $remainder = $fullPath.Substring($root.Length)
    $components = @($remainder.Split([char[]]@('\'), [System.StringSplitOptions]::RemoveEmptyEntries))
    $paths = [Collections.Generic.List[string]]::new()
    $paths.Add($root)
    foreach ($component in $components) {
        $current = [IO.Path]::Combine($current, $component)
        $paths.Add($current)
    }
    foreach ($currentPath in $paths) {
        try { $item = Get-Item -LiteralPath $currentPath -Force -ErrorAction Stop }
        catch {
            if ($_.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound -or
                    $_.Exception -is [IO.FileNotFoundException] -or
                    $_.Exception -is [IO.DirectoryNotFoundException]) { return $null }
            throw
        }
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw }
        [void][KeelDock.Platform.DevLaneWindows.Boundary]::AssertCleanupEntry(
            [string]$currentPath, [bool]$item.PSIsContainer)
    }
    return [pscustomobject]@{ Path = $fullPath; Item = $item }
}
function Assert-OwnedPath([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path.Length -gt 4096) { throw }
    $fullPath = [IO.Path]::GetFullPath($Path)
    foreach ($ownedRoot in $script:OwnedRoots) {
        $rootPath = [IO.Path]::GetFullPath([string]$ownedRoot).TrimEnd([char]92)
        if ([string]::Equals($fullPath, $rootPath, [StringComparison]::OrdinalIgnoreCase) -or
            $fullPath.StartsWith($rootPath + '\', [StringComparison]::OrdinalIgnoreCase)) {
            return $fullPath
        }
    }
    throw
}
function Assert-CleanupTreeSafe([string]$Path) {
    $rootInfo = Get-CleanupPathInfo $Path
    if ($null -eq $rootInfo) { return }
    if (-not $rootInfo.Item.PSIsContainer) { throw }
    $pending = [Collections.Generic.Stack[string]]::new()
    Add-CleanupBudgetEntry $pending.Count
    $pending.Push($rootInfo.Path)
    while ($pending.Count -gt 0) {
        Assert-CleanupBudgetTime
        $currentPath = $pending.Pop()
        $entry = Get-CleanupPathInfo $currentPath
        if ($null -eq $entry) { throw }
        if (-not $entry.Item.PSIsContainer) { continue }
        foreach ($child in [IO.Directory]::EnumerateFileSystemEntries($entry.Path)) {
            $name = [IO.Path]::GetFileName($child)
            if ($name -eq '.' -or $name -eq '..') { continue }
            Add-CleanupBudgetEntry $pending.Count
            if ($child.Length -gt 4096) { throw }
            $depth = @($child.Substring([IO.Path]::GetPathRoot($child).Length).Split(
                [char[]]@('\'), [System.StringSplitOptions]::RemoveEmptyEntries)).Count
            if ($depth -gt 1024) { throw }
            $pending.Push($child)
        }
    }
}
function Invoke-CleanupIcacls([string]$Path, [string[]]$Arguments) {
    $Path = Assert-OwnedPath $Path
    $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
    & $icacls $Path @Arguments '/L' '/Q' 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) { throw }
}
function Set-CleanupStorageAccess([string]$Path) {
    $Path = Assert-OwnedPath $Path
    Invoke-CleanupIcacls $Path @('/setowner', '*S-1-5-32-544')
    Invoke-CleanupIcacls $Path @('/grant', '*S-1-5-32-544:(F)')
}
try {
    Write-LauncherPhase 'types-load'
    Add-Type -Path (Join-Path $scriptRoot 'sandbox_windows_native.cs') -ErrorAction Stop
    $statePath = [IO.Path]::GetFullPath($StateFile)
    if ($Mode -eq 'create') {
        if (Test-Path -LiteralPath $statePath) { throw }
        $profileName = 'KDDevLane' + [Guid]::NewGuid().ToString('N')
        $sid = [KeelDock.Platform.DevLaneWindows.Boundary]::CreateProfile($profileName)
        $ruleName = 'KD-DevLane-' + $env:CI_RUN_ID
        try {
            $value = [ordered]@{ schema = 1; profile_name = $profileName; package_sid = $sid; firewall_rule = $ruleName; owned_roots = @(); acl_grants = @(); integrity_grants = @(); job_state = 'none' }
            $json = $value | ConvertTo-Json -Compress
            [IO.File]::WriteAllText($statePath, $json + "`n", [Text.UTF8Encoding]::new($false))
        } catch {
            [void][KeelDock.Platform.DevLaneWindows.Boundary]::DeleteProfile($profileName)
            throw
        }
        Write-Output 'windows_sandbox_profile=created appcontainer=lpac capabilities=empty'
        exit 0
    }
    $state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
    if ($state.schema -ne 1 -or $state.profile_name -notmatch '^KDDevLane[a-f0-9]{32}$' -or
            $state.package_sid -notmatch '^S-1-15-2-(?:[0-9]+-){6}[0-9]+$' -or
            $state.firewall_rule -ne ('KD-DevLane-' + $env:CI_RUN_ID) -or
            $null -eq $state.owned_roots -or $null -eq $state.acl_grants -or $null -eq $state.integrity_grants -or
            @($state.owned_roots).Count -gt 128 -or
            $state.job_state -notin @('none', 'pending', 'terminated-empty')) { throw }
    if ($Mode -eq 'firewall-install') {
        $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw }
        if (Get-NetFirewallRule -Name $state.firewall_rule -ErrorAction SilentlyContinue) { throw }
        New-NetFirewallRule -Name $state.firewall_rule -DisplayName $state.firewall_rule -Group 'KeelDock devlane' `
            -Direction Outbound -Action Block -Enabled True -Profile Any -RemoteAddress Any -Package $state.package_sid | Out-Null
        $rules = @(Get-NetFirewallRule -Name $state.firewall_rule -ErrorAction Stop)
        if ($rules.Count -ne 1 -or -not $rules[0].Enabled -or $rules[0].Direction -ne 'Outbound' -or
            $rules[0].Action -ne 'Block' -or $rules[0].Profile -ne 'Any') { throw }
        $application = Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $rules[0] -ErrorAction Stop
        $address = Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rules[0] -ErrorAction Stop
        if ($application.Package -ne $state.package_sid -or @($address.RemoteAddress) -notcontains 'Any') { throw }
        Write-Output 'windows_firewall=installed direction=outbound action=block package=verified remote=any'
        exit 0
    }
    if ($Mode -eq 'firewall-remove') {
        Remove-NetFirewallRule -Name $state.firewall_rule -ErrorAction SilentlyContinue
        if (@(Get-NetFirewallRule -Name $state.firewall_rule -ErrorAction SilentlyContinue).Count -ne 0) { throw }
        Write-Output 'windows_firewall=removed'
        exit 0
    }
    if ($Mode -eq 'run') {
        $request = Get-Content -LiteralPath $RequestFile -Raw | ConvertFrom-Json
        if ($request.schema -ne 1 -or $request.profile_name -ne $state.profile_name -or
            $request.package_sid -ne $state.package_sid -or
            $request.executable -notmatch '^[A-Za-z]:\\[^\r\n]{1,240}\.exe$' -or
            $request.working_directory -notmatch '^[A-Za-z]:\\[^\r\n]{1,240}$' -or
            @($request.arguments).Count -gt 128 -or @($request.environment).Count -gt 128) { throw }
        $internetClient = $false
        if ($request.PSObject.Properties.Name -contains 'internet_client') {
            if ($request.internet_client -isnot [bool]) { throw }
            $internetClient = [bool]$request.internet_client
        }
        $sid = [Security.Principal.SecurityIdentifier]::new([string]$state.package_sid)
        $grants = [Collections.Generic.List[object]]::new()
        foreach ($grant in @($state.acl_grants)) { $grants.Add($grant) }
        $integrityGrants = [Collections.Generic.List[string]]::new()
        foreach ($path in @($state.integrity_grants)) { $integrityGrants.Add([string]$path) }
        function Add-TrackedGrant([string]$path, [string]$rightsName, [int]$inheritanceValue) {
            $path = Assert-OwnedPath $path
            $inheritance = [Security.AccessControl.InheritanceFlags]$inheritanceValue
            $rights = [Enum]::Parse([Security.AccessControl.FileSystemRights], $rightsName)
            $existing = @($grants | Where-Object { $_.path -eq $path -and $_.rights -eq $rightsName -and $_.inheritance -eq $inheritanceValue })
            if ($existing.Count -gt 0) { return }
            $pathInfo = Get-CleanupPathInfo $path
            if ($null -eq $pathInfo) { throw }
            if ($inheritanceValue -ne 0) {
                if (-not $pathInfo.Item.PSIsContainer) { throw }
                Assert-CleanupTreeSafe $pathInfo.Path
            }
            $acl = Get-Acl -LiteralPath $path
            $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, $rights, $inheritance,
                [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
            $grants.Add([pscustomobject]@{ path = $path; rights = $rightsName; inheritance = $inheritanceValue })
            Save-State
            [void]$acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $path -AclObject $acl
        }
        function Save-State {
            $state.owned_roots = @($script:OwnedRoots)
            $state.acl_grants = @($grants)
            $state.integrity_grants = @($integrityGrants)
            $temporaryState = $statePath + '.tmp'
            $json = $state | ConvertTo-Json -Depth 8 -Compress
            [IO.File]::WriteAllText($temporaryState, $json + "`n", [Text.UTF8Encoding]::new($false))
            Move-Item -LiteralPath $temporaryState -Destination $statePath -Force
        }
        function Add-TrackedIntegrityGrant([string]$path) {
            $path = Assert-OwnedPath $path
            if ($integrityGrants.Contains($path)) { return }
            $pathInfo = Get-CleanupPathInfo $path
            if ($null -eq $pathInfo -or -not $pathInfo.Item.PSIsContainer) { throw }
            Assert-CleanupTreeSafe $pathInfo.Path
            $integrityGrants.Add($path)
            Save-State
            Invoke-CleanupIcacls $path @('/setintegritylevel', '(OI)(CI)L')
        }
        Write-LauncherPhase 'acl-grant'
        Start-CleanupBudget
        $basePath = [IO.Path]::GetFullPath([string]$request.access_root)
        $baseInfo = Get-CleanupPathInfo $basePath
        if ($null -eq $baseInfo -or -not $baseInfo.Item.PSIsContainer) { throw }
        $recordedRoots = @($state.owned_roots)
        if ($recordedRoots.Count -gt 1 -or
                ($recordedRoots.Count -eq 1 -and
                 -not [string]::Equals([IO.Path]::GetFullPath([string]$recordedRoots[0]), $baseInfo.Path,
                    [StringComparison]::OrdinalIgnoreCase))) { throw }
        $script:OwnedRoots = @($baseInfo.Path)
        $state.owned_roots = @($script:OwnedRoots)
        Save-State
        [void](Assert-OwnedPath $statePath)
        [void](Assert-OwnedPath ([IO.Path]::GetFullPath($RequestFile)))
        foreach ($path in @([string]$request.executable, [string]$request.working_directory)) {
            [void](Assert-OwnedPath $path)
        }
        foreach ($entry in @($request.read_paths)) {
            $path = Assert-OwnedPath ([string]$entry)
            $item = Get-Item -LiteralPath $path -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw }
            Add-TrackedGrant $path 'ReadAndExecute' $(if ($item.PSIsContainer) { 3 } else { 0 })
        }
        foreach ($entry in @($request.write_paths)) {
            $path = Assert-OwnedPath ([string]$entry)
            $item = Get-Item -LiteralPath $path -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw }
            if (-not $item.PSIsContainer) { throw }
            Add-TrackedGrant $path 'Modify' 3
            Add-TrackedIntegrityGrant $path
        }
        Save-State
        $environment = [string[]]@($request.environment)
        $arguments = [string[]]@($request.arguments)
        $state.job_state = 'pending'
        Save-State
        $result = [KeelDock.Platform.DevLaneWindows.Boundary]::Run(
            [string]$state.profile_name, [string]$state.package_sid, [string]$request.executable,
            $arguments, [string]$request.working_directory, $environment, [int]$request.timeout_milliseconds, $internetClient)
        if ($result.Failure -eq 'process-start-failed') {
            $state.job_state = 'none'
            Save-State
            [ordered]@{ status = 'process-start-failed'; exit_code = [uint32]0; token = ''; job = '' } |
                ConvertTo-Json -Compress
            exit 0
        }
        if ($result.Failure -eq 'token-bypass-traverse-absent') {
            if (-not $result.Created -or -not $result.Exited -or
                    $result.AppContainer -notlike 'lpac=verified*bypass_traverse=absent' -or
                    $result.Job -notlike 'assigned kill_on_close=enabled breakaway=disabled* terminated=confirmed empty=confirmed') { throw }
            $state.job_state = 'terminated-empty'
            Save-State
            [ordered]@{ status = 'token-bypass-traverse-absent'; exit_code = [uint32]$result.ExitCode;
                token = $result.AppContainer; job = $result.Job } | ConvertTo-Json -Compress
            exit 0
        }
        if (-not $result.Created -or -not $result.Exited -or $result.AppContainer -notlike 'lpac=verified*' -or
            $result.Job -notlike 'assigned kill_on_close=enabled breakaway=disabled* terminated=confirmed empty=confirmed') { throw }
        $state.job_state = 'terminated-empty'
        Save-State
        $status = if ($result.TimedOut) { 'timeout' } elseif ($result.ExitCode -eq 0) { 'pass' } else { 'fail' }
        [ordered]@{ status = $status; exit_code = [uint32]$result.ExitCode; token = $result.AppContainer; job = $result.Job } |
            ConvertTo-Json -Compress
        exit 0
    }
    if ($Mode -eq 'delete') {
        $script:OwnedRoots = @($state.owned_roots | ForEach-Object { [IO.Path]::GetFullPath([string]$_) })
        $expectedRunRoot = [IO.Directory]::GetParent([IO.Directory]::GetParent($statePath).FullName).FullName
        $expectedPackagesRoot = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Packages'
        $expectedProfileRoot = Join-Path $expectedPackagesRoot ([string]$state.profile_name)
        $expectedStorageRoot = [IO.Path]::GetFullPath((Join-Path $expectedProfileRoot 'AC'))
        if ($script:OwnedRoots.Count -gt 2) { throw }
        for ($index = 0; $index -lt $script:OwnedRoots.Count; $index++) {
            $ownedRoot = $script:OwnedRoots[$index]
            if (-not ([string]::Equals($ownedRoot, $expectedRunRoot, [StringComparison]::OrdinalIgnoreCase) -or
                    [string]::Equals($ownedRoot, $expectedStorageRoot, [StringComparison]::OrdinalIgnoreCase)) -or
                    ($index -gt 0 -and [string]::Equals($ownedRoot, $script:OwnedRoots[$index - 1],
                        [StringComparison]::OrdinalIgnoreCase))) { throw }
        }
        foreach ($ownedRoot in $script:OwnedRoots) {
            $ownedInfo = Get-CleanupPathInfo $ownedRoot
            if ($null -eq $ownedInfo -or -not $ownedInfo.Item.PSIsContainer) { throw }
        }
        [KeelDock.Platform.DevLaneWindows.Boundary]::AssertCleanupQuiescent(
            [string]$state.package_sid, [string]$state.job_state)
        Remove-NetFirewallRule -Name $state.firewall_rule -ErrorAction SilentlyContinue
        if (@(Get-NetFirewallRule -Name $state.firewall_rule -ErrorAction SilentlyContinue).Count -ne 0) { throw }
        function Clear-AppContainerStorage([string]$PackageSid, [string]$ProfileName) {
            $actual = [IO.Path]::GetFullPath([KeelDock.Platform.DevLaneWindows.Boundary]::GetProfileFolderPath($PackageSid))
            $packages = [IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Packages'))
            $expected = [IO.Path]::GetFullPath((Join-Path (Join-Path $packages $ProfileName) 'AC'))
            if (-not [string]::Equals($actual, $expected, [StringComparison]::OrdinalIgnoreCase)) { throw }
            $rootInfo = Get-CleanupPathInfo $actual
            if ($null -eq $rootInfo) { return 'missing' }
            if (-not $rootInfo.Item.PSIsContainer) { throw }
            $storageRoots = @($script:OwnedRoots | Where-Object {
                        [string]::Equals($_, $actual, [StringComparison]::OrdinalIgnoreCase)
                    })
            if ($storageRoots.Count -eq 0) {
                $script:OwnedRoots = @($script:OwnedRoots) + @($actual)
                $state.owned_roots = @($script:OwnedRoots)
                $temporaryState = $statePath + '.tmp'
                $json = $state | ConvertTo-Json -Depth 8 -Compress
                [IO.File]::WriteAllText($temporaryState, $json + "`n", [Text.UTF8Encoding]::new($false))
                Move-Item -LiteralPath $temporaryState -Destination $statePath -Force
            }
            $restorePrivilege = [KeelDock.Platform.DevLaneWindows.Boundary]::EnableCleanupRestorePrivilege()
            try {
                $pending = [Collections.Generic.Stack[string]]::new()
                $entries = [Collections.Generic.List[object]]::new()
                Add-CleanupBudgetEntry $pending.Count
                $pending.Push($rootInfo.Path)
                while ($pending.Count -gt 0) {
                    Assert-CleanupBudgetTime
                    $path = $pending.Pop()
                    $entry = Get-CleanupPathInfo $path
                    if ($null -eq $entry) { throw }
                    $depth = @($entry.Path.Substring([IO.Path]::GetPathRoot($entry.Path).Length).Split(
                        [char[]]@('\'), [System.StringSplitOptions]::RemoveEmptyEntries)).Count
                    if ($depth -gt 1024) { throw }
                    Set-CleanupStorageAccess $entry.Path
                    $entries.Add([pscustomobject]@{
                        Path = $entry.Path
                        IsDirectory = [bool]$entry.Item.PSIsContainer
                        Attributes = [IO.FileAttributes]$entry.Item.Attributes
                    })
                    if ($entry.Item.PSIsContainer) {
                        foreach ($child in [IO.Directory]::EnumerateFileSystemEntries($entry.Path)) {
                            $name = [IO.Path]::GetFileName($child)
                            if ($name -eq '.' -or $name -eq '..') { continue }
                            Add-CleanupBudgetEntry $pending.Count
                            if ($child.Length -gt 4096) { throw }
                            $pending.Push($child)
                        }
                    }
                }
                for ($index = $entries.Count - 1; $index -ge 0; $index--) {
                    Assert-CleanupBudgetTime
                    $entry = $entries[$index]
                    $attributes = [IO.FileAttributes]$entry.Attributes
                    if (($attributes -band [IO.FileAttributes]::ReadOnly) -ne 0) {
                        $writableAttributes = [IO.FileAttributes]([int]$attributes -band (-bnot [int][IO.FileAttributes]::ReadOnly))
                        [IO.File]::SetAttributes($entry.Path, $writableAttributes)
                    }
                    if ($entry.IsDirectory) { [IO.Directory]::Delete($entry.Path, $false) }
                    else { [IO.File]::Delete($entry.Path) }
                }
            } finally { $restorePrivilege.Dispose() }
            return 'deleted'
        }
        Write-LauncherPhase 'acl-grant'
        Start-CleanupBudget
        foreach ($grant in @($state.acl_grants)) {
            $path = Assert-OwnedPath ([string]$grant.path)
            $pathInfo = Get-CleanupPathInfo $path
            if ($null -eq $pathInfo) { continue }
            if ([int]$grant.inheritance -ne 0) {
                if (-not $pathInfo.Item.PSIsContainer) { throw }
                Assert-CleanupTreeSafe $pathInfo.Path
            }
            Invoke-CleanupIcacls $pathInfo.Path @('/remove:g', ('*' + [string]$state.package_sid))
        }
        foreach ($path in @($state.integrity_grants)) {
            $path = Assert-OwnedPath ([string]$path)
            $pathInfo = Get-CleanupPathInfo $path
            if ($null -eq $pathInfo) { continue }
            if (-not $pathInfo.Item.PSIsContainer) { throw }
            Assert-CleanupTreeSafe $pathInfo.Path
            Invoke-CleanupIcacls $pathInfo.Path @('/setintegritylevel', '(OI)(CI)M')
        }
        [void](Clear-AppContainerStorage ([string]$state.package_sid) ([string]$state.profile_name))
        [KeelDock.Platform.DevLaneWindows.Boundary]::AssertCleanupQuiescent(
            [string]$state.package_sid, [string]$state.job_state)
        $deleteResult = [KeelDock.Platform.DevLaneWindows.Boundary]::DeleteProfile([string]$state.profile_name)
        if ($deleteResult -ne 'deleted') {
            $cleanupReason = [string]$deleteResult
            throw
        }
        Remove-Item -LiteralPath $statePath -Force
        Write-Output 'windows_sandbox_cleanup=confirmed firewall=removed profile=deleted'
        exit 0
    }
    throw
} catch {
    if ($Mode -eq 'delete' -and $null -eq $cleanupReason) {
        $code = ([int]$_.Exception.HResult) -band 65535
        if ($code -in @(32, 33)) { $cleanupReason = 'sharing-violation' }
        elseif ($code -eq 5) { $cleanupReason = 'access-denied' }
        elseif ($code -in @(2, 3)) { $cleanupReason = 'not-found' }
        else { $cleanupReason = 'other' }
    }
    if ($Mode -eq 'delete' -and $cleanupReason -in @('sharing-violation', 'access-denied', 'not-found', 'other')) {
        Write-Output ('windows_cleanup_reason=' + $cleanupReason)
    }
    Write-Output 'windows_sandbox=refused code=boundary'
    exit 1
}
