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
function Write-LauncherPhase([string]$Phase) {
    if ($Phase -notin @('types-load', 'appcontainer-sid', 'token-create', 'acl-grant', 'job-create',
            'process-create-suspended', 'job-assign', 'resume', 'wait', 'exit')) { throw }
    [Console]::Out.WriteLine('windows_launcher_phase=' + $Phase)
    [Console]::Out.Flush()
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
            $value = [ordered]@{ schema = 1; profile_name = $profileName; package_sid = $sid; firewall_rule = $ruleName; acl_grants = @(); integrity_grants = @() }
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
            $null -eq $state.acl_grants -or $null -eq $state.integrity_grants) { throw }
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
            $inheritance = [Security.AccessControl.InheritanceFlags]$inheritanceValue
            $rights = [Enum]::Parse([Security.AccessControl.FileSystemRights], $rightsName)
            $existing = @($grants | Where-Object { $_.path -eq $path -and $_.rights -eq $rightsName -and $_.inheritance -eq $inheritanceValue })
            if ($existing.Count -gt 0) { return }
            $acl = Get-Acl -LiteralPath $path
            $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, $rights, $inheritance,
                [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
            $grants.Add([pscustomobject]@{ path = $path; rights = $rightsName; inheritance = $inheritanceValue })
            Save-State
            [void]$acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $path -AclObject $acl
        }
        function Save-State {
            $state.acl_grants = @($grants)
            $state.integrity_grants = @($integrityGrants)
            $temporaryState = $statePath + '.tmp'
            $json = $state | ConvertTo-Json -Depth 8 -Compress
            [IO.File]::WriteAllText($temporaryState, $json + "`n", [Text.UTF8Encoding]::new($false))
            Move-Item -LiteralPath $temporaryState -Destination $statePath -Force
        }
        function Add-TrackedIntegrityGrant([string]$path) {
            if ($integrityGrants.Contains($path)) { return }
            $integrityGrants.Add($path)
            Save-State
            $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
            & $icacls $path '/setintegritylevel' '(OI)(CI)L' 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) { throw }
        }
        Write-LauncherPhase 'acl-grant'
        $basePath = [IO.Path]::GetFullPath([string]$request.access_root)
        $ancestor = [IO.DirectoryInfo]::new($basePath)
        while ($null -ne $ancestor) {
            $item = Get-Item -LiteralPath $ancestor.FullName -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw }
            Add-TrackedGrant $ancestor.FullName 'Traverse, Synchronize' 0
            $ancestor = $ancestor.Parent
        }
        foreach ($entry in @($request.read_paths)) {
            $path = [IO.Path]::GetFullPath([string]$entry)
            $item = Get-Item -LiteralPath $path -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw }
            $system32Path = [IO.Path]::GetFullPath((Join-Path $env:SystemRoot 'System32'))
            if ([string]::Equals($path, $system32Path, [StringComparison]::OrdinalIgnoreCase)) { continue }
            $directoryPath = if ($item.PSIsContainer) { $path } else { Split-Path -Parent $path }
            $ancestor = [IO.DirectoryInfo]::new($directoryPath)
            while ($null -ne $ancestor) {
                $parentItem = Get-Item -LiteralPath $ancestor.FullName -Force
                if (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw }
                Add-TrackedGrant $ancestor.FullName 'Traverse, Synchronize' 0
                $ancestor = $ancestor.Parent
            }
            Add-TrackedGrant $path 'ReadAndExecute' $(if ($item.PSIsContainer) { 3 } else { 0 })
        }
        foreach ($entry in @($request.write_paths)) {
            $path = [IO.Path]::GetFullPath([string]$entry)
            $item = Get-Item -LiteralPath $path -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw }
            if (-not $item.PSIsContainer) { throw }
            Add-TrackedGrant $path 'Modify' 3
            Add-TrackedIntegrityGrant $path
        }
        Save-State
        $environment = [string[]]@($request.environment)
        $arguments = [string[]]@($request.arguments)
        $result = [KeelDock.Platform.DevLaneWindows.Boundary]::Run(
            [string]$state.profile_name, [string]$state.package_sid, [string]$request.executable,
            $arguments, [string]$request.working_directory, $environment, [int]$request.timeout_milliseconds, $internetClient)
        if ($result.Failure -eq 'process-start-failed') {
            [ordered]@{ status = 'process-start-failed'; exit_code = [uint32]0; token = ''; job = '' } |
                ConvertTo-Json -Compress
            exit 0
        }
        if (-not $result.Created -or -not $result.Exited -or $result.AppContainer -notlike 'lpac=verified*' -or
            $result.Job -notlike 'assigned kill_on_close=enabled breakaway=disabled*') { throw }
        $status = if ($result.TimedOut) { 'timeout' } elseif ($result.ExitCode -eq 0) { 'pass' } else { 'fail' }
        [ordered]@{ status = $status; exit_code = [uint32]$result.ExitCode; token = $result.AppContainer; job = $result.Job } |
            ConvertTo-Json -Compress
        exit 0
    }
    if ($Mode -eq 'delete') {
        Remove-NetFirewallRule -Name $state.firewall_rule -ErrorAction SilentlyContinue
        if (@(Get-NetFirewallRule -Name $state.firewall_rule -ErrorAction SilentlyContinue).Count -ne 0) { throw }
        function Get-CleanupReason([object]$Failure) {
            if ($null -eq $Failure -or $null -eq $Failure.Exception) { return 'other' }
            $code = ([int]$Failure.Exception.HResult) -band 65535
            if ($code -in @(32, 33)) { return 'sharing-violation' }
            if ($code -eq 5) { return 'access-denied' }
            if ($code -in @(2, 3)) { return 'not-found' }
            return 'other'
        }
        function Restore-AppContainerStorage([string]$Root) {
            if (-not (Test-Path -LiteralPath $Root)) { return }
            $takeown = Join-Path $env:SystemRoot 'System32\takeown.exe'
            $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
            $pending = [Collections.Generic.Stack[string]]::new()
            $pending.Push($Root)
            $entryCount = 1
            while ($pending.Count -gt 0) {
                $path = $pending.Pop()
                $item = Get-Item -LiteralPath $path -Force
                if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw }
                if ($item.PSIsContainer) {
                    foreach ($entry in Get-ChildItem -LiteralPath $path -Force) {
                        $entryCount++
                        if ($entryCount -gt 250000) { throw }
                        $pending.Push($entry.FullName)
                    }
                }
            }
            & $takeown '/F' $Root '/A' '/R' '/D' 'Y' *> $null
            if ($LASTEXITCODE -ne 0) { $script:cleanupReason = 'other'; throw }
            & $icacls $Root '/reset' '/T' '/C' '/Q' *> $null
            if ($LASTEXITCODE -ne 0) { $script:cleanupReason = 'other'; throw }
            & $icacls $Root '/grant:r' '*S-1-5-32-544:(OI)(CI)F' '/C' '/Q' *> $null
            if ($LASTEXITCODE -ne 0) { $script:cleanupReason = 'other'; throw }
        }
        function Clear-AppContainerStorage([string]$PackageSid, [string]$ProfileName) {
            $actual = [IO.Path]::GetFullPath([KeelDock.Platform.DevLaneWindows.Boundary]::GetProfileFolderPath($PackageSid))
            $packages = [IO.Path]::GetFullPath((Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Packages'))
            $expected = [IO.Path]::GetFullPath((Join-Path (Join-Path $packages $ProfileName) 'AC'))
            if (-not [string]::Equals($actual, $expected, [StringComparison]::OrdinalIgnoreCase)) { throw }
            if (-not (Test-Path -LiteralPath $actual)) { return }
            Restore-AppContainerStorage $actual
            Remove-Item -LiteralPath $actual -Recurse -Force
        }
        $sid = [Security.Principal.SecurityIdentifier]::new([string]$state.package_sid)
        Write-LauncherPhase 'acl-grant'
        foreach ($grant in @($state.acl_grants)) {
            $path = [string]$grant.path
            if (-not (Test-Path -LiteralPath $path)) { continue }
            $acl = Get-Acl -LiteralPath $path
            $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid,
                [Enum]::Parse([Security.AccessControl.FileSystemRights], [string]$grant.rights),
                [Security.AccessControl.InheritanceFlags][int]$grant.inheritance,
                [Security.AccessControl.PropagationFlags]::None,
                [Security.AccessControl.AccessControlType]::Allow)
            $acl.RemoveAccessRuleSpecific($rule)
            Set-Acl -LiteralPath $path -AclObject $acl
        }
        $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
        foreach ($path in @($state.integrity_grants)) {
            if (-not (Test-Path -LiteralPath ([string]$path))) { continue }
            & $icacls ([string]$path) '/setintegritylevel' '(OI)(CI)M' 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) { $cleanupReason = 'other'; throw }
        }
        try { Clear-AppContainerStorage ([string]$state.package_sid) ([string]$state.profile_name) }
        catch {
            if ($null -eq $cleanupReason) { $cleanupReason = Get-CleanupReason $_ }
            throw
        }
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
