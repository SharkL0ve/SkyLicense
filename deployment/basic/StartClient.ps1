param([string]$Endpoint = 'localhost:13331', [string]$Program = 'DemoApp', [string]$Version = '1.0.0')
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath (Join-Path $PSScriptRoot 'customer')
$env:SKYLICENSE_LICENSE_FILE_SECRET_FILE = Join-Path (Get-Location).Path 'secrets\license-file-secret.txt'
$env:SKYLICENSE_BASIC_CA_CERT_FILE = Join-Path (Get-Location).Path 'ca-cert.pem'
java -cp '.;..\SkyLicense-basic.jar' cn.sky.license.BasicLauncher $Endpoint $Program $Version
exit $LASTEXITCODE
