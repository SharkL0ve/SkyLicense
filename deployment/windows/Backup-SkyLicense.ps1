[CmdletBinding()]
param(
    [string] $DeploymentRoot = 'C:\ProgramData\SkyLicense',
    [string] $BackupRoot = 'C:\ProgramData\SkyLicenseBackups',
    [string] $JavaPath = 'C:\Program Files\Eclipse Adoptium\jdk-17\bin\java.exe'
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($DeploymentRoot)
$backupRoot = [IO.Path]::GetFullPath($BackupRoot)
$rootPrefix = $root.TrimEnd('\') + '\'
if ($backupRoot.Equals($root, [StringComparison]::OrdinalIgnoreCase) -or
    $backupRoot.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw 'BackupRoot must be outside DeploymentRoot'
}
if (-not (Test-Path -LiteralPath $JavaPath -PathType Leaf)) {
    throw "Java executable not found: $JavaPath"
}

$jar = Join-Path $root 'SkyLicense-Server.jar'
$timestamp = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ')
$archive = Join-Path $backupRoot "skylicense-$timestamp.skybackup"
$env:SKYLICENSE_OPERATION_LOG_HMAC_KEY_FILE = Join-Path $root 'secrets\operation-log-hmac.txt'
$env:SKYLICENSE_MFA_ENCRYPTION_KEY_FILE = Join-Path $root 'secrets\mfa-encryption-key.txt'
$env:SKYLICENSE_BACKUP_HMAC_KEY_FILE = Join-Path $root 'secrets\backup-hmac.txt'
$tlsPasswordFile = Join-Path $root 'secrets\tls-key-password.txt'
if (Test-Path -LiteralPath $tlsPasswordFile -PathType Leaf) {
    $env:SKYLICENSE_TLS_KEY_PASSWORD_FILE = $tlsPasswordFile
}

$service = Get-Service -Name SkyLicense -ErrorAction Stop
if ($service.Status -notin @('Running', 'Stopped')) {
    throw "SkyLicense service is in a transitional state: $($service.Status)"
}
$wasRunning = $service.Status -eq 'Running'
try {
    if ($wasRunning) {
        Stop-Service -Name SkyLicense -ErrorAction Stop
        (Get-Service -Name SkyLicense).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(45))
    }
    Push-Location $root
    try {
        & $JavaPath -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading `
            -jar $jar --create-backup $archive
        if ($LASTEXITCODE -ne 0) { throw 'Backup creation failed' }
        & $JavaPath -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading `
            -jar $jar --verify-backup $archive
        if ($LASTEXITCODE -ne 0) { throw 'Backup verification failed' }
    } finally {
        Pop-Location
    }
} finally {
    if ($wasRunning) { Start-Service -Name SkyLicense }
}

Write-Host "Verified backup: $archive"
