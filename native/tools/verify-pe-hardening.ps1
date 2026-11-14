param(
    [Parameter(Mandatory = $true)]
    [string]$Path,
    [switch]$RequireAuthenticode,
    [switch]$RequireIntegrityManifest,
    [string]$ExpectedSignerCertificateSha256
)

$ErrorActionPreference = 'Stop'
$resolved = (Resolve-Path -LiteralPath $Path).Path
$bytes = [System.IO.File]::ReadAllBytes($resolved)

function Read-U16([int]$Offset) {
    if ($Offset -lt 0 -or $Offset + 2 -gt $bytes.Length) {
        throw "Truncated PE field at offset $Offset"
    }
    return [BitConverter]::ToUInt16($bytes, $Offset)
}

function Read-U32([int]$Offset) {
    if ($Offset -lt 0 -or $Offset + 4 -gt $bytes.Length) {
        throw "Truncated PE field at offset $Offset"
    }
    return [BitConverter]::ToUInt32($bytes, $Offset)
}

function Get-CertificateSha256(
    [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
) {
    if ($null -eq $Certificate) {
        throw 'Authenticode signature does not contain a signer certificate'
    }
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString(
            $sha256.ComputeHash($Certificate.RawData))).Replace('-', '').ToLowerInvariant()
    } finally {
        $sha256.Dispose()
    }
}

if ($bytes.Length -lt 0x100 -or $bytes[0] -ne 0x4d -or $bytes[1] -ne 0x5a) {
    throw "$resolved is not a valid DOS/PE image"
}
$peOffset = [int](Read-U32 0x3c)
$validSignature = $peOffset + 24 -le $bytes.Length -and
    $bytes[$peOffset] -eq 0x50 -and
    $bytes[$peOffset + 1] -eq 0x45 -and
    $bytes[$peOffset + 2] -eq 0 -and
    $bytes[$peOffset + 3] -eq 0
if (-not $validSignature) {
    throw "$resolved has an invalid PE signature"
}
$machine = Read-U16 ($peOffset + 4)
if ($machine -ne 0x8664) {
    throw "Expected an x86-64 PE image, found machine 0x$($machine.ToString('x4'))"
}

$optional = $peOffset + 24
$magic = Read-U16 $optional
if ($magic -ne 0x20b) {
    throw "Expected a PE32+ image, found optional-header magic 0x$($magic.ToString('x4'))"
}
$dllCharacteristics = Read-U16 ($optional + 70)
$required = @{
    HIGH_ENTROPY_VA = 0x0020
    DYNAMIC_BASE = 0x0040
    NX_COMPAT = 0x0100
    GUARD_CF = 0x4000
}
foreach ($entry in $required.GetEnumerator()) {
    if (($dllCharacteristics -band $entry.Value) -eq 0) {
        throw "Missing PE hardening flag $($entry.Key) in $resolved"
    }
}

# PE32+ data directory 10 is the Load Configuration Directory. A non-empty
# directory is required for the CFG function table and guard metadata.
$loadConfigDirectory = $optional + 112 + 10 * 8
$loadConfigRva = Read-U32 $loadConfigDirectory
$loadConfigSize = Read-U32 ($loadConfigDirectory + 4)
if ($loadConfigRva -eq 0 -or $loadConfigSize -eq 0) {
    throw "PE image advertises CFG without a Load Configuration Directory"
}

$authenticodeStatus = 'not-required'
$authenticodeCertificateSha256 = 'not-required'
if ($RequireAuthenticode) {
    $expectedSigner = if (-not [string]::IsNullOrWhiteSpace(
            $ExpectedSignerCertificateSha256)) {
        $ExpectedSignerCertificateSha256.Trim()
    } else {
        $env:WINDOWS_CODESIGN_CERT_SHA256
    }
    if ([string]::IsNullOrWhiteSpace($expectedSigner) -or
        -not [regex]::IsMatch($expectedSigner, '\A[0-9a-fA-F]{64}\z') -or
        $expectedSigner -match '\A0{64}\z') {
        throw 'RequireAuthenticode also requires a non-zero 64-character signer certificate SHA-256'
    }
    $expectedSigner = $expectedSigner.ToLowerInvariant()
    $signature = Get-AuthenticodeSignature -LiteralPath $resolved
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "Authenticode signature is not valid for ${resolved}: $($signature.Status)"
    }
    $authenticodeCertificateSha256 = Get-CertificateSha256 $signature.SignerCertificate
    if ($authenticodeCertificateSha256 -cne $expectedSigner) {
        throw 'Authenticode signer certificate SHA-256 does not match the protected release identity'
    }
    $authenticodeStatus = 'valid'
}

$manifestStatus = 'not-required'
if ($RequireIntegrityManifest) {
    $manifestPath = "$resolved.integrity"
    if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
        throw "Missing integrity manifest: $manifestPath"
    }
    $manifest = [System.IO.File]::ReadAllBytes($manifestPath)
    if ($manifest.Length -ne 160) {
        throw "Integrity manifest must contain exactly 160 bytes: $manifestPath"
    }
    $magic = [Text.Encoding]::ASCII.GetString($manifest, 0, 8)
    if ($magic -ne 'SKYINT02') {
        throw "Integrity manifest has an invalid magic header: $manifestPath"
    }

    $repositoryRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $verifierPath = if ($env:SKYLICENSE_MANIFEST_VERIFIER) {
        $env:SKYLICENSE_MANIFEST_VERIFIER
    } else {
        Join-Path $repositoryRoot 'target\release\verify_artifact.exe'
    }
    if (-not (Test-Path -LiteralPath $verifierPath -PathType Leaf)) {
        throw "Full manifest verifier was not found: $verifierPath"
    }
    $verificationOutput = & $verifierPath $resolved 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Artifact manifest verification failed:`n$($verificationOutput -join [Environment]::NewLine)"
    }
    if ($verificationOutput -notcontains 'verified=true') {
        throw "Artifact manifest verifier did not report verified=true"
    }
    $verificationOutput | Write-Output
    $manifestStatus = 'cryptographically-valid'
}

Write-Output "pe_hardening_verified=true"
Write-Output "dll_characteristics=0x$($dllCharacteristics.ToString('x4'))"
Write-Output "load_config_size=$loadConfigSize"
Write-Output "authenticode=$authenticodeStatus"
Write-Output "authenticode_certificate_sha256=$authenticodeCertificateSha256"
Write-Output "integrity_manifest=$manifestStatus"
