param(
    [ValidateSet('compile', 'vectors')]
    [string]$Mode = 'compile'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$script:RefusalReasons = @(
    'compiler_missing',
    'compile_failed',
    'vector_generation_failed',
    'vector_mismatch',
    'encoding'
)

function Write-Refusal([string]$Reason) {
    if ($script:RefusalReasons -notcontains $Reason) { $Reason = 'vector_generation_failed' }
    [Console]::Out.WriteLine('capsule-frame=refused reason=' + $Reason)
}

if (-not (Get-Command Add-Type -ErrorAction SilentlyContinue)) {
    Write-Refusal 'compiler_missing'
    exit 1
}

try {
    if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) {
        Write-Refusal 'compile_failed'
        exit 1
    }
    [void](Add-Type -Path (Join-Path $PSScriptRoot 'capsule_frame.cs') -ErrorAction Stop)
} catch {
    Write-Refusal 'compile_failed'
    exit 1
}

if ($Mode -eq 'vectors') {
    try {
        $json = [KeelDock.Platform.CapsuleFrame.VectorGenerator]::GenerateJson()
    } catch {
        Write-Refusal 'vector_generation_failed'
        exit 1
    }
    if ($json -isnot [string] -or $json.Length -eq 0) {
        Write-Refusal 'vector_mismatch'
        exit 1
    }
    if ($json -match '[^\x00-\x7F]') {
        Write-Refusal 'encoding'
        exit 1
    }
    if ($json.Contains("`r") -or $json.Contains("`n")) {
        Write-Refusal 'vector_mismatch'
        exit 1
    }
    [Console]::Out.WriteLine($json)
} else {
    [Console]::Out.WriteLine('capsule-frame-compile=observed result=compiled')
}
exit 0
