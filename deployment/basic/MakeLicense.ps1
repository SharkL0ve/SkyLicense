$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath (Join-Path $PSScriptRoot 'customer')
$env:SKYLICENSE_LICENSE_FILE_SECRET_FILE = Join-Path (Get-Location).Path 'secrets\license-file-secret.txt'
java -cp ..\SkyLicense-basic.jar cn.sky.license.LicenseFileTool .\license.dat
exit $LASTEXITCODE
