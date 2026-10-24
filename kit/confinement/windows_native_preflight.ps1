$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$phase = 'control_identity'
try {
    if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) { throw }
    if ($env:CI_EVENT_NAME -ne 'workflow_dispatch' -or $env:CI_REF -ne 'refs/heads/main') { throw }
    if ($env:CI_REPOSITORY -ne 'keeldock-platform/platform-ci' -or $env:CI_SERVER_URL -ne 'https://github.com') { throw }
    if ($env:CI_SHA -notmatch '^[a-f0-9]{40}$') { throw }
    $root = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
    $workspace = [IO.Path]::GetFullPath($env:CI_WORKSPACE)
    $current = [IO.Path]::GetFullPath((Get-Location).Path)
    if (-not [string]::Equals($root, $workspace, [StringComparison]::OrdinalIgnoreCase)) { throw }
    if (-not [string]::Equals($root, $current, [StringComparison]::OrdinalIgnoreCase)) { throw }
    $actualSha = git -C $root rev-parse --verify HEAD 2>$null
    if ($LASTEXITCODE -ne 0 -or $actualSha.Trim() -ne $env:CI_SHA) { throw }
    $phase = 'runtime'
    [void](Add-Type -Path (Join-Path $PSScriptRoot 'windows_native_preflight.cs') -ErrorAction Stop)
    $phase = 'native'
    $result = [KeelDock.Platform.WindowsNativePreflight.Probe]::Run()
    if ($result -eq 'windows-native-preflight=observed appcontainer=lpac token=verified capabilities=empty integrity=low job=assigned limits=verified termination=verified cng=p256-user nonexportable=verified acl=verified destruction=verified cleanup=verified') {
        Write-Output $result
        exit 0
    }
    if ($result -match '^windows-native-preflight=refused check=(lpac_profile|job_setup|child_attribute_list|child_security_capabilities|child_lpac_policy|child_system_executable|child_process_create|child_process_create_access_denied|child_process_create_invalid_parameter|child_process_create_other|child_job_assignment|child_job_readback|token_readback|job_readback|cng_key|cng_acl|cng_export|cleanup|runtime) reason=native_preflight_unavailable cleanup=(verified|incomplete)$') {
        Write-Output $result
        exit 1
    }
    Write-Output 'windows-native-preflight=refused check=runtime reason=native_preflight_unavailable cleanup=incomplete'
    exit 1
} catch {
    $cleanup = 'verified'
    if ($phase -eq 'native') { $cleanup = 'incomplete' }
    Write-Output ('windows-native-preflight=refused check=' + $phase + ' reason=native_preflight_unavailable cleanup=' + $cleanup)
    exit 1
}
