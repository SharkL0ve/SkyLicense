[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string] $DeploymentRoot,
    [Parameter(Mandatory = $true)]
    [string] $ServiceAccount,
    [Parameter(Mandatory = $true)]
    [string] $WinSWPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{64}$')]
    [string] $ExpectedWinSWSha256,
    [string] $BackupRoot = 'C:\ProgramData\SkyLicenseBackups'
)

$ErrorActionPreference = 'Stop'
$root = [IO.Path]::GetFullPath($DeploymentRoot)
$backupRoot = [IO.Path]::GetFullPath($BackupRoot)
$wrapperSource = [IO.Path]::GetFullPath($WinSWPath)
$wrapper = Join-Path $root 'SkyLicense.exe'

foreach ($required in @(
    'SkyLicense-Server.jar',
    'SkyLicense.xml',
    'config.json',
    'certs\auth-chain.pem',
    'certs\auth-key.pem')) {
    if (-not (Test-Path -LiteralPath (Join-Path $root $required) -PathType Leaf)) {
        throw "Required deployment file is missing: $required"
    }
}
if (-not (Test-Path -LiteralPath (Join-Path $root 'resources') -PathType Container)) {
    throw 'Required resources directory is missing'
}

$actualHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $wrapperSource).Hash
if ($actualHash -ine $ExpectedWinSWSha256) {
    throw "WinSW SHA-256 mismatch: expected $ExpectedWinSWSha256, got $actualHash"
}

$secrets = Join-Path $root 'secrets'
New-Item -ItemType Directory -Force -Path $secrets | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $root 'logs') | Out-Null
New-Item -ItemType Directory -Force -Path $backupRoot | Out-Null

# Resolve the account before making any ACL change. A gMSA is recommended.
$account = New-Object System.Security.Principal.NTAccount($ServiceAccount)
$sid = $account.Translate([System.Security.Principal.SecurityIdentifier]).Value

Copy-Item -LiteralPath $wrapperSource -Destination $wrapper -Force
& $wrapper install
if ($LASTEXITCODE -ne 0) { throw 'WinSW service installation failed' }

function Set-ServiceIdentity([string] $Name, [string] $Identity) {
    $service = Get-CimInstance Win32_Service -Filter "Name='$Name'"
    if ($Identity.EndsWith('$')) {
        $result = Invoke-CimMethod -InputObject $service -MethodName Change -Arguments @{
            StartName = $Identity
            StartPassword = $null
        }
        if ($result.ReturnValue -ne 0) {
            throw "Unable to configure gMSA service identity: $($result.ReturnValue)"
        }
        return
    }

    $secure = Read-Host "Password for $Identity" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        $plain = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
        $result = Invoke-CimMethod -InputObject $service -MethodName Change -Arguments @{
            StartName = $Identity
            StartPassword = $plain
        }
        if ($result.ReturnValue -ne 0) {
            throw "Unable to configure service identity: $($result.ReturnValue)"
        }
    } finally {
        $plain = $null
        [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
    }
}

function ConvertTo-FileSystemRights([string] $Rights) {
    switch ($Rights.Replace('(OI)', '').Replace('(CI)', '')) {
        'F' { return [System.Security.AccessControl.FileSystemRights]::FullControl }
        'M' { return [System.Security.AccessControl.FileSystemRights]::Modify }
        'R' { return [System.Security.AccessControl.FileSystemRights]::Read }
        'RX' { return [System.Security.AccessControl.FileSystemRights]::ReadAndExecute }
        default { throw "Unsupported ACL rights: $Rights" }
    }
}

function Set-OwnerOnlyAcl([string] $Path, [string] $Rights, [switch] $Recurse) {
    $ownerArguments = @($Path, '/setowner', $ServiceAccount)
    if ($Recurse) { $ownerArguments += @('/T', '/C') }
    & icacls.exe @ownerArguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Unable to assign owner: $Path" }

    $rootItem = Get-Item -Force -LiteralPath $Path
    $targets = if ($Recurse) {
        @(
            Get-ChildItem -Force -LiteralPath $Path -Recurse |
                Sort-Object { $_.FullName.Length } -Descending
        ) + @($rootItem)
    } else {
        @($rootItem)
    }
    $fileSystemRights = ConvertTo-FileSystemRights $Rights
    $inheritChildren = $Rights.Contains('(OI)') -or $Rights.Contains('(CI)')

    foreach ($target in $targets) {
        $acl = if ($target.PSIsContainer) {
            [System.Security.AccessControl.DirectorySecurity]::new()
        } else {
            [System.Security.AccessControl.FileSecurity]::new()
        }
        $acl.SetAccessRuleProtection($true, $false)
        $inheritance = if ($target.PSIsContainer -and $inheritChildren) {
            [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
                [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
        } else {
            [System.Security.AccessControl.InheritanceFlags]::None
        }
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $account,
            $fileSystemRights,
            $inheritance,
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow)
        [void] $acl.AddAccessRule($rule)
        $target.SetAccessControl($acl)
    }
}

Set-ServiceIdentity 'SkyLicense' $ServiceAccount

# Permit the same account to query/start/stop its service for the offline backup
# task while preserving all existing service-control entries.
$currentSddl = (& sc.exe sdshow SkyLicense | Where-Object { $_ -match '^D:' } | Select-Object -First 1).Trim()
if (-not $currentSddl) { throw 'Unable to read the SkyLicense service security descriptor' }
if ($currentSddl -notmatch [regex]::Escape($sid)) {
    $ace = "(A;;LCRPWP;;;$sid)"
    $auditIndex = $currentSddl.IndexOf('S:')
    $updatedSddl = if ($auditIndex -ge 0) {
        $currentSddl.Substring(0, $auditIndex) + $ace + $currentSddl.Substring($auditIndex)
    } else {
        $currentSddl + $ace
    }
    & sc.exe sdset SkyLicense $updatedSddl | Out-Host
    if ($LASTEXITCODE -ne 0) { throw 'Unable to delegate service backup controls' }
}

# Change ownership while the installing administrator can still traverse the
# tree. ACLs are then narrowed from leaves toward the root; root is last.
& icacls.exe $root /setowner $ServiceAccount /T /C | Out-Host
if ($LASTEXITCODE -ne 0) { throw 'Unable to assign deployment ownership' }

# Normalize leaves before their parent directories become inaccessible to the
# installing administrator. Each object is narrowed only once.
$readOnlyRootFiles = @(
    (Join-Path $root 'config.json'),
    (Join-Path $root 'SkyLicense-Server.jar'),
    (Join-Path $root 'SkyLicense.xml')
)
$executableRootFiles = @((Join-Path $root 'SkyLicense.exe'))
$databaseFiles = @(
    Get-ChildItem -LiteralPath $root -Filter 'web_magiclicense.db*' -File |
        ForEach-Object { $_.FullName }
)
$handledRootFiles = @($readOnlyRootFiles + $executableRootFiles + $databaseFiles)
Get-ChildItem -LiteralPath $root -File | Where-Object {
    $_.FullName -notin $handledRootFiles
} | ForEach-Object {
    Set-OwnerOnlyAcl $_.FullName 'F'
}

$certificateDirectory = Join-Path $root 'certs'
Get-ChildItem -LiteralPath $certificateDirectory -Recurse -File | ForEach-Object {
    Set-OwnerOnlyAcl $_.FullName 'R'
}
Get-ChildItem -LiteralPath $certificateDirectory -Recurse -Directory |
    Sort-Object { $_.FullName.Length } -Descending |
    ForEach-Object { Set-OwnerOnlyAcl $_.FullName '(OI)(CI)RX' }
Set-OwnerOnlyAcl $certificateDirectory '(OI)(CI)RX'
Set-OwnerOnlyAcl (Join-Path $root 'resources') '(OI)(CI)M' -Recurse
Set-OwnerOnlyAcl (Join-Path $root 'logs') '(OI)(CI)M' -Recurse
foreach ($readOnlyFile in $readOnlyRootFiles) {
    Set-OwnerOnlyAcl $readOnlyFile 'R'
}
foreach ($executableFile in $executableRootFiles) {
    Set-OwnerOnlyAcl $executableFile 'RX'
}
foreach ($databaseFile in $databaseFiles) {
    Set-OwnerOnlyAcl $databaseFile 'M'
}
Set-OwnerOnlyAcl $secrets '(OI)(CI)R' -Recurse
Set-OwnerOnlyAcl $backupRoot '(OI)(CI)M' -Recurse
Set-OwnerOnlyAcl $root '(OI)(CI)F'

Write-Host 'Service installed. Run --validate-config as the service account before starting.'
