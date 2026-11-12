$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
java -cp .\SkyLicense-basic.jar .\SetupLocal.java server runtime
if ($LASTEXITCODE -ne 0) { throw 'Server setup failed' }
java -cp .\SkyLicense-basic.jar .\SetupLocal.java client customer
if ($LASTEXITCODE -ne 0) { throw 'Customer setup failed' }
