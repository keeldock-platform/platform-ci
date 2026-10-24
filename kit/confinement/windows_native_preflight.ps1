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
    $createProcessFailurePrefix = 'windows-native-preflight=refused check=child_process_create win32_createprocess_error='
    if ($result.StartsWith($createProcessFailurePrefix, [StringComparison]::Ordinal)) {
        $cleanup = 'incomplete'
        if ($result.Length -le 256) {
            $createProcessFailurePattern = '^windows-native-preflight=refused check=child_process_create win32_createprocess_error=([0-9]+) reason=native_preflight_unavailable cleanup=verified\z'
            $match = [regex]::Match($result, $createProcessFailurePattern)
            if ($match.Success) {
                $cleanup = 'verified'
                $errorText = $match.Groups[1].Value
                $canonical = $errorText -eq '0' -or $errorText -match '^[1-9][0-9]*$'
                [UInt64]$errorValue = 0
                $parsed = $canonical -and [UInt64]::TryParse(
                    $errorText,
                    [System.Globalization.NumberStyles]::None,
                    [System.Globalization.CultureInfo]::InvariantCulture,
                    [ref]$errorValue
                )
                if ($parsed -and $errorValue -le [UInt32]::MaxValue) {
                    Write-Output $result
                    exit 1
                }
            }
        }
        Write-Output ('windows-native-preflight=refused check=child_process_create_other reason=native_preflight_unavailable cleanup=' + $cleanup)
        exit 1
    }
    if ($result -match '^windows-native-preflight=refused check=(lpac_profile|job_setup|child_attribute_list|child_security_capabilities|child_lpac_policy|child_system_executable|child_environment|child_process_create_other|child_job_assignment|child_job_readback|token_open|token_appcontainer_read|token_appcontainer_check|token_lpac_check|token_capabilities_read|token_capabilities_check|token_sid_read|token_sid_check|token_integrity_read|token_integrity_check|job_readback|cng_key|cng_acl|cng_acl_support_read|cng_acl_token_open|cng_acl_user_read|cng_acl_user_check|cng_acl_system_sid|cng_acl_owner_read|cng_acl_owner_check|cng_acl_owner_extract|cng_acl_owner_absent|cng_acl_owner_validate|cng_acl_owner_user_match|cng_acl_owner_default_read|cng_acl_owner_default_validate|cng_acl_owner_default_compare|cng_acl_owner_matches_token_default|cng_acl_owner_matches_other|cng_acl_dacl_read|cng_acl_dacl_check|cng_acl_count_read|cng_acl_ace_read|cng_acl_ace_shape|cng_acl_ace_sid|cng_acl_ace_policy|cng_acl_user_allow_check|cng_export|cleanup|runtime) reason=native_preflight_unavailable cleanup=(verified|incomplete)\z') {
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
