param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$resolvedPath = (Resolve-Path -LiteralPath $Path).Path
$lines = [System.IO.File]::ReadAllLines($resolvedPath)
$unsupported = @(
    '-Wl,-znostart-stop-gc'
    '"-Wl,-znostart-stop-gc"'
)
$filtered = [string[]]@($lines | Where-Object { $_ -notin $unsupported })

if ($filtered.Length -ne $lines.Length) {
    $utf8NoBom = [System.Text.UTF8Encoding]::new($false)
    [System.IO.File]::WriteAllLines($resolvedPath, $filtered, $utf8NoBom)
}
