param(
    [ValidateSet('compile', 'vectors')]
    [string]$Mode = 'compile'
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
try {
    if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) { throw }
    [void](Add-Type -Path (Join-Path $PSScriptRoot 'capsule_frame.cs') -ErrorAction Stop)
    if ($Mode -eq 'vectors') {
        [Console]::Out.WriteLine([KeelDock.Platform.CapsuleFrame.VectorGenerator]::GenerateJson())
    } else {
        [Console]::Out.WriteLine('capsule-frame-compile=observed result=compiled')
    }
    exit 0
} catch {
    [Console]::Out.WriteLine('capsule-frame=refused reason=compile_or_vector_failure')
    exit 1
}
