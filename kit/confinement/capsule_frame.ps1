param(
    [ValidateSet('compile', 'vectors', 'decrypt', 'destroy')]
    [string]$Mode = 'compile',
    [string]$KeyName = '',
    [string]$KeyRecord = '',
    [string]$Capsule = '',
    [string]$OutputDirectory = ''
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
$script:DecryptRefusalReasons = @(
    'key_unavailable',
    'input_invalid',
    'capsule_invalid',
    'binding_mismatch',
    'agreement_failed',
    'crypto_refused',
    'manifest_invalid',
    'bundle_mismatch',
    'output_failed',
    'destroy_failed'
)
$script:KeyNamePattern = '^kd-receiver-[0-9a-f]{32}$'
$script:PathPattern = '^[A-Za-z]:\\[A-Za-z0-9_.\\-]+$'

function Write-Refusal([string]$Reason) {
    if ($script:RefusalReasons -notcontains $Reason) { $Reason = 'vector_generation_failed' }
    [Console]::Out.WriteLine('capsule-frame=refused reason=' + $Reason)
}

function Write-DecryptRefusal([string]$Reason, [string]$KeyState) {
    if ($script:DecryptRefusalReasons -cnotcontains $Reason) { $Reason = 'crypto_refused' }
    if (@('destroyed', 'present') -cnotcontains $KeyState) { $KeyState = 'present' }
    [Console]::Out.WriteLine('capsule-decrypt=refused reason=' + $Reason + ' key=' + $KeyState)
}

function Remove-ReceiverKey([string]$Name) {
    $provider = [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
    try {
        if ([System.Security.Cryptography.CngKey]::Exists($Name, $provider)) {
            $key = [System.Security.Cryptography.CngKey]::Open($Name, $provider)
            $key.Delete()
        }
    } catch {
        return 'present'
    }
    try {
        if ([System.Security.Cryptography.CngKey]::Exists($Name, $provider)) { return 'present' }
    } catch {
        return 'present'
    }
    try {
        $again = [System.Security.Cryptography.CngKey]::Open($Name, $provider)
        $again.Dispose()
        return 'present'
    } catch {
        return 'destroyed'
    }
}

function Read-BoundedFile([string]$Path, [long]$Length) {
    if ($Path -cnotmatch $script:PathPattern) { throw 'input_invalid' }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Length -ne $Length) { throw 'input_invalid' }
    if (([int]$item.Attributes -band [int][IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'input_invalid' }
    return , [IO.File]::ReadAllBytes($item.FullName)
}

function Get-SharedSecret([string]$Name, [byte[]]$Point) {
    $provider = [System.Security.Cryptography.CngProvider]::MicrosoftSoftwareKeyStorageProvider
    $own = $null
    $ecdh = $null
    $peer = $null
    try {
        try {
            $own = [System.Security.Cryptography.CngKey]::Open($Name, $provider)
        } catch {
            throw 'key_unavailable'
        }
        if ([string]$own.Algorithm.Algorithm -cne 'ECDH_P256') { throw 'key_unavailable' }
        if ($own.ExportPolicy -ne [System.Security.Cryptography.CngExportPolicies]::None) { throw 'key_unavailable' }
        $x = New-Object byte[] 32
        $y = New-Object byte[] 32
        [Array]::Copy($Point, 1, $x, 0, 32)
        [Array]::Copy($Point, 33, $y, 0, 32)
        $q = New-Object System.Security.Cryptography.ECPoint
        $q.X = $x
        $q.Y = $y
        $parameters = New-Object System.Security.Cryptography.ECParameters
        $parameters.Curve = [System.Security.Cryptography.ECCurve]::CreateFromValue('1.2.840.10045.3.1.7')
        $parameters.Q = $q
        try {
            $peer = [System.Security.Cryptography.ECDiffieHellman]::Create($parameters)
            $ecdh = New-Object System.Security.Cryptography.ECDiffieHellmanCng($own)
            $secret = $ecdh.DeriveRawSecretAgreement($peer.PublicKey)
        } catch {
            throw 'agreement_failed'
        }
        if ($secret.Length -ne 32) { throw 'agreement_failed' }
        return , $secret
    } finally {
        if ($ecdh) { $ecdh.Dispose() }
        if ($peer) { $peer.Dispose() }
        if ($own) { $own.Dispose() }
    }
}

function Open-Chunk([byte[]]$Key, $Chunk, [byte[]]$Nonce, [byte[]]$Aad) {
    $plain = New-Object byte[] ([KeelDock.Platform.CapsuleFrame.CapsuleCodec]::ChunkPlaintextBytes)
    $aes = [System.Security.Cryptography.AesGcm]::new($Key, 16)
    try {
        $aes.Decrypt($Nonce, $Chunk.Ciphertext, $Chunk.Tag, $plain, $Aad)
    } finally {
        $aes.Dispose()
    }
    return , $plain
}

function Get-ChunkAad([byte[]]$HeaderSha, $Chunk, [byte[]]$ManifestRegion) {
    $region = $null
    if ($Chunk.Kind -eq 1) { $region = $ManifestRegion }
    return , [KeelDock.Platform.CapsuleFrame.CapsuleCodec]::MakeAad($HeaderSha, [uint32]$Chunk.Index, [byte]$Chunk.Kind, $region)
}

function Get-ChunkKey([byte[]]$Secret, [byte[]]$HeaderBytes, $View, [byte[]]$HeaderSha, [byte[]]$ManifestRegion) {
    $first = $View.GetChunk([uint32]0)
    $nonce = [KeelDock.Platform.CapsuleFrame.CapsuleCodec]::MakeNonce($View.Header.NoncePrefix, [uint32]0)
    $aad = Get-ChunkAad $HeaderSha $first $ManifestRegion
    $reversed = [byte[]]$Secret.Clone()
    [Array]::Reverse($reversed)
    foreach ($candidate in @(@('be', $Secret), @('le', $reversed))) {
        $key = [KeelDock.Platform.CapsuleFrame.CapsuleCodec]::DeriveCapsuleAesKey([byte[]]$candidate[1], $HeaderBytes)
        try {
            [void](Open-Chunk $key $first $nonce $aad)
            return @{ Key = $key; Order = [string]$candidate[0] }
        } catch {
            continue
        }
    }
    throw 'crypto_refused'
}

function Get-ManifestText($Manifest) {
    $codec = [KeelDock.Platform.CapsuleFrame.CapsuleCodec]
    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add('source ' + $codec::ToHex($Manifest.SourceSha))
    $lines.Add('tree ' + $codec::ToHex($Manifest.TreeId))
    $lines.Add('bundle ' + $codec::ToHex($Manifest.BundleSha256) + ' ' + [string]$Manifest.BundleLength)
    foreach ($entry in $Manifest.Entries) {
        $lines.Add('entry ' + [string]$entry.Mode + ' ' + [string]$entry.Size + ' ' + $codec::ToHex($entry.Sha256) + ' ' + $codec::ToHex($entry.BlobId) + ' ' + [string]$entry.Path)
    }
    return (($lines -join "`n") + "`n")
}

function Write-NewFile([string]$Path, [byte[]]$Bytes) {
    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
        $stream.Write($Bytes, 0, $Bytes.Length)
    } catch {
        throw 'output_failed'
    } finally {
        if ($stream) { $stream.Dispose() }
    }
}

function Invoke-CapsuleDecrypt {
    $codec = [KeelDock.Platform.CapsuleFrame.CapsuleCodec]
    if ($KeyName -cnotmatch $script:KeyNamePattern) { throw 'input_invalid' }
    if ($OutputDirectory -cnotmatch $script:PathPattern -or -not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) { throw 'input_invalid' }
    $recordBytes = Read-BoundedFile $KeyRecord ([long]$codec::KeyRecordLength)
    $capsuleBytes = Read-BoundedFile $Capsule ([long]$codec::CapsuleLength)
    try {
        $record = $codec::DecodeKeyRecord($recordBytes)
        $view = $codec::DecodeCapsule($capsuleBytes, $recordBytes)
    } catch {
        throw 'capsule_invalid'
    }
    $header = $view.Header
    $now = [uint64][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    if ($record.ExpiresAt -le $now -or $header.ExpiresAt -le $now -or $header.CreatedAt -gt ($now + 300)) { throw 'capsule_invalid' }
    try {
        $point = $codec::ValidatePublicPoint($header.SenderPublicPoint)
        $receiver = $codec::ValidatePublicPoint($record.ReceiverPublicPoint)
    } catch {
        throw 'capsule_invalid'
    }
    if ($receiver.Length -ne 65 -or $point.Length -ne 65) { throw 'capsule_invalid' }
    $headerBytes = New-Object byte[] ($codec::CapsuleHeaderLength)
    [Array]::Copy($capsuleBytes, 0, $headerBytes, 0, $headerBytes.Length)
    try {
        $headerSha = $codec::HeaderDigest($headerBytes)
        $manifestRegion = $view.GetManifestCiphertextRegion()
        $trailer = $codec::DecodeTrailer($view.GetTrailer())
    } catch {
        throw 'capsule_invalid'
    }
    $secret = Get-SharedSecret $KeyName $point
    $selected = $null
    try {
        $selected = Get-ChunkKey $secret $headerBytes $view $headerSha $manifestRegion
    } finally {
        [Array]::Clear($secret, 0, $secret.Length)
    }
    $manifestPlain = New-Object byte[] ($codec::ManifestPlaintextLength)
    $bundlePlain = New-Object byte[] ($codec::BundlePlaintextLength)
    $size = $codec::ChunkPlaintextBytes
    try {
        for ($index = 0; $index -lt $codec::ChunkCount; $index++) {
            $chunk = $view.GetChunk([uint32]$index)
            $nonce = $codec::MakeNonce($header.NoncePrefix, [uint32]$index)
            $aad = Get-ChunkAad $headerSha $chunk $manifestRegion
            $plain = Open-Chunk $selected.Key $chunk $nonce $aad
            if ($chunk.Kind -eq 0) {
                [Array]::Copy($plain, 0, $manifestPlain, $index * $size, $size)
            } else {
                [Array]::Copy($plain, 0, $bundlePlain, ($index - $codec::ManifestChunkCount) * $size, $size)
            }
        }
    } catch {
        throw 'crypto_refused'
    } finally {
        [Array]::Clear($selected.Key, 0, $selected.Key.Length)
    }
    try {
        $decoded = $codec::DecodeManifestRegion($manifestPlain)
        $manifest = $decoded.Item1
        $bundleParts = $codec::DecodeBundleRegion($bundlePlain)
        $bundle = $bundleParts.Item1
    } catch {
        throw 'manifest_invalid'
    }
    if ([uint64]$bundle.Length -ne [uint64]$manifest.BundleLength) { throw 'bundle_mismatch' }
    $actual = $codec::ToHex($codec::Sha256($bundle))
    if ($actual -cne $codec::ToHex($manifest.BundleSha256)) { throw 'bundle_mismatch' }
    $text = New-Object System.Text.UTF8Encoding($false)
    Write-NewFile (Join-Path $OutputDirectory 'manifest.tsv') ($text.GetBytes((Get-ManifestText $manifest)))
    Write-NewFile (Join-Path $OutputDirectory 'bundle.bin') $bundle
    return @{ Entries = $manifest.Entries.Count; Bytes = $bundle.Length; Order = $selected.Order }
}

function Invoke-DecryptMode {
    $outcome = $null
    $failure = ''
    try {
        $outcome = Invoke-CapsuleDecrypt
    } catch {
        $failure = [string]$_.Exception.Message
    }
    $state = 'present'
    if ($KeyName -cmatch $script:KeyNamePattern) { $state = Remove-ReceiverKey $KeyName }
    if ($state -cne 'destroyed') {
        Write-DecryptRefusal 'destroy_failed' 'present'
        return 1
    }
    if ($failure.Length -gt 0 -or $null -eq $outcome) {
        Write-DecryptRefusal $failure 'destroyed'
        return 1
    }
    [Console]::Out.WriteLine('capsule-decrypt=observed result=decrypted entries=' + $outcome.Entries + ' bundle_bytes=' + $outcome.Bytes + ' key=destroyed x_order=' + $outcome.Order)
    return 0
}

function Invoke-DestroyMode {
    if ($KeyName -cnotmatch $script:KeyNamePattern) {
        Write-DecryptRefusal 'input_invalid' 'present'
        return 1
    }
    $state = Remove-ReceiverKey $KeyName
    if ($state -cne 'destroyed') {
        Write-DecryptRefusal 'destroy_failed' 'present'
        return 1
    }
    [Console]::Out.WriteLine('capsule-destroy=observed key=destroyed')
    return 0
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

if ($Mode -eq 'decrypt') {
    exit (Invoke-DecryptMode)
}
if ($Mode -eq 'destroy') {
    exit (Invoke-DestroyMode)
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
