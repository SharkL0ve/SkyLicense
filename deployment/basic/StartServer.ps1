$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath (Join-Path $PSScriptRoot 'runtime')
$env:SKYLICENSE_OPERATION_LOG_HMAC_KEY_FILE = Join-Path (Get-Location).Path 'secrets\operation-log-hmac.txt'
$env:SKYLICENSE_MFA_ENCRYPTION_KEY_FILE = Join-Path (Get-Location).Path 'secrets\mfa-encryption-key.txt'
Remove-Item Env:\SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD_FILE -ErrorAction SilentlyContinue
if (-not (Test-Path -LiteralPath '.\web_magiclicense.db')) {
    $env:SKYLICENSE_BOOTSTRAP_ADMIN_PASSWORD_FILE = Join-Path (Get-Location).Path 'secrets\bootstrap-admin.txt'
}
java -jar ..\SkyLicense-Server.jar --validate-config
if ($LASTEXITCODE -ne 0) { throw 'Deployment preflight failed' }
java -XX:+DisableAttachMechanism -XX:-EnableDynamicAgentLoading -jar ..\SkyLicense-Server.jar
exit $LASTEXITCODE
