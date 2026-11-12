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
try {
    Add-Type -Path (Join-Path $scriptRoot 'sandbox_windows_native.cs') -ErrorAction Stop
    $statePath = [IO.Path]::GetFullPath($StateFile)
    if ($Mode -eq 'create') {
        if (Test-Path -LiteralPath $statePath) { throw }
        $profileName = 'KDDevLane' + [Guid]::NewGuid().ToString('N')
        $sid = [KeelDock.Platform.DevLaneWindows.Boundary]::CreateProfile($profileName)
        $ruleName = 'KD-DevLane-' + $env:CI_RUN_ID
        try {
            $value = [ordered]@{ schema = 1; profile_name = $profileName; package_sid = $sid; firewall_rule = $ruleName; acl_grants = @() }
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
        if ($state.schema -ne 1 -or $state.profile_name -notmatch '^KDDevLane[a-f0-9]{32}$'
        -or $state.package_sid -notmatch '^S-1-15-2-(?:[0-9]+-){7}[0-9]+$'
            -or $state.firewall_rule -ne ('KD-DevLane-' + $env:CI_RUN_ID)
            -or $null -eq $state.acl_grants) { throw }
    if ($Mode -eq 'firewall-install') {
        $principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw }
        if (Get-NetFirewallRule -Name $state.firewall_rule -ErrorAction SilentlyContinue) { throw }
        New-NetFirewallRule -Name $state.firewall_rule -DisplayName $state.firewall_rule -Group 'KeelDock devlane' `
            -Direction Outbound -Action Block -Enabled True -Profile Any -RemoteAddress Any -Package $state.package_sid | Out-Null
        $rules = @(Get-NetFirewallRule -Name $state.firewall_rule -ErrorAction Stop)
        if ($rules.Count -ne 1 -or -not $rules[0].Enabled -or $rules[0].Direction -ne 'Outbound'
            -or $rules[0].Action -ne 'Block' -or $rules[0].Profile -ne 'Any') { throw }
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
        if ($request.schema -ne 1 -or $request.profile_name -ne $state.profile_name
            -or $request.package_sid -ne $state.package_sid
            -or $request.executable -notmatch '^[A-Za-z]:\\[^\r\n]{1,240}\.exe$'
            -or $request.working_directory -notmatch '^[A-Za-z]:\\[^\r\n]{1,240}$'
            -or @($request.arguments).Count -gt 128 -or @($request.environment).Count -gt 128) { throw }
        $sid = [Security.Principal.SecurityIdentifier]::new([string]$state.package_sid)
        $grants = [Collections.Generic.List[object]]::new()
        foreach ($grant in @($state.acl_grants)) { $grants.Add($grant) }
        function Add-TrackedGrant([string]$path, [string]$rightsName, [int]$inheritanceValue) {
            $inheritance = [Security.AccessControl.InheritanceFlags]$inheritanceValue
            $rights = [Enum]::Parse([Security.AccessControl.FileSystemRights], $rightsName)
            $existing = @($grants | Where-Object { $_.path -eq $path -and $_.rights -eq $rightsName -and $_.inheritance -eq $inheritanceValue })
            if ($existing.Count -gt 0) { return }
            $acl = Get-Acl -LiteralPath $path
            $rule = [Security.AccessControl.FileSystemAccessRule]::new($sid, $rights, $inheritance,
                [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
            [void]$acl.AddAccessRule($rule)
            Set-Acl -LiteralPath $path -AclObject $acl
            $grants.Add([pscustomobject]@{ path = $path; rights = $rightsName; inheritance = $inheritanceValue })
        }
        function Save-State {
            $state.acl_grants = @($grants)
            $temporaryState = $statePath + '.tmp'
            $json = $state | ConvertTo-Json -Depth 8 -Compress
            [IO.File]::WriteAllText($temporaryState, $json + "`n", [Text.UTF8Encoding]::new($false))
            Move-Item -LiteralPath $temporaryState -Destination $statePath -Force
        }
        $basePath = [IO.Path]::GetFullPath([string]$request.access_root)
        $ancestor = [IO.DirectoryInfo]::new($basePath)
        while ($null -ne $ancestor) {
            $item = Get-Item -LiteralPath $ancestor.FullName -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw }
            Add-TrackedGrant $ancestor.FullName 'Traverse, Synchronize' 0
            Save-State
            $ancestor = $ancestor.Parent
        }
        foreach ($entry in @($request.read_paths)) {
            $path = [IO.Path]::GetFullPath([string]$entry)
            $item = Get-Item -LiteralPath $path -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw }
            $ancestor = [IO.DirectoryInfo]::new($path)
            while ($null -ne $ancestor) {
                $parentItem = Get-Item -LiteralPath $ancestor.FullName -Force
                if (($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw }
                Add-TrackedGrant $ancestor.FullName 'Traverse, Synchronize' 0
                Save-State
                $ancestor = $ancestor.Parent
            }
            Add-TrackedGrant $path 'ReadAndExecute' 3
            Save-State
        }
        foreach ($entry in @($request.write_paths)) {
            $path = [IO.Path]::GetFullPath([string]$entry)
            $item = Get-Item -LiteralPath $path -Force
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw }
            Add-TrackedGrant $path 'Modify' 3
            Save-State
            $icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
            & $icacls $path '/setintegritylevel' '(OI)(CI)L' 2>$null | Out-Null
            if ($LASTEXITCODE -ne 0) { throw }
        }
        Save-State
        $environment = [string[]]@($request.environment)
        $arguments = [string[]]@($request.arguments)
        $result = [KeelDock.Platform.DevLaneWindows.Boundary]::Run(
            [string]$state.profile_name, [string]$state.package_sid, [string]$request.executable,
            $arguments, [string]$request.working_directory, $environment, [int]$request.timeout_milliseconds)
        if (-not $result.Created -or -not $result.Exited -or $result.AppContainer -notlike 'lpac=verified*'
            -or $result.Job -notlike 'assigned kill_on_close=enabled breakaway=disabled*') { throw }
        $status = if ($result.TimedOut) { 'timeout' } elseif ($result.ExitCode -eq 0) { 'pass' } else { 'fail' }
        [ordered]@{ status = $status; exit_code = [uint32]$result.ExitCode; token = $result.AppContainer; job = $result.Job } |
            ConvertTo-Json -Compress
        exit 0
    }
    if ($Mode -eq 'delete') {
        Remove-NetFirewallRule -Name $state.firewall_rule -ErrorAction SilentlyContinue
        if (@(Get-NetFirewallRule -Name $state.firewall_rule -ErrorAction SilentlyContinue).Count -ne 0) { throw }
        $sid = [Security.Principal.SecurityIdentifier]::new([string]$state.package_sid)
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
        if (-not [KeelDock.Platform.DevLaneWindows.Boundary]::DeleteProfile([string]$state.profile_name)) { throw }
        Remove-Item -LiteralPath $statePath -Force
        Write-Output 'windows_sandbox_cleanup=confirmed firewall=removed profile=deleted'
        exit 0
    }
    throw
} catch {
    Write-Output 'windows_sandbox=refused code=boundary'
    exit 1
}
