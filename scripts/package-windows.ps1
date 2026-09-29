param(
    [Parameter(Mandatory = $true)]
    [string]$ExePath,

    [Parameter(Mandatory = $true)]
    [string]$OutDir,

    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [string]$CommitSha
)

$ErrorActionPreference = "Stop"

$exe = Resolve-Path $ExePath
$out = [System.IO.Path]::GetFullPath($OutDir)
$stage = Join-Path $out "stage"
$releaseExe = Join-Path $out "password-manager.exe"
$zip = Join-Path $out "password-manager-windows-x64.zip"
$hashes = Join-Path $out "SHA256SUMS.txt"

if (Test-Path $out) {
    Remove-Item -Recurse -Force $out
}
New-Item -ItemType Directory -Force -Path $stage | Out-Null

Copy-Item $exe $releaseExe
Copy-Item $releaseExe (Join-Path $stage "password-manager.exe")
Copy-Item "README.md" (Join-Path $stage "README.md")

@"
Password Manager
Version: $Version
Commit: $CommitSha
Target: x86_64-pc-windows-msvc
Built by: GitHub Actions
"@ | Set-Content -Encoding UTF8 (Join-Path $stage "BUILD-INFO.txt")

Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip -CompressionLevel Optimal

$exeHash = (Get-FileHash $releaseExe -Algorithm SHA256).Hash.ToLowerInvariant()
$zipHash = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()

@(
    "$exeHash *password-manager.exe"
    "$zipHash *password-manager-windows-x64.zip"
) | Set-Content -Encoding ascii $hashes

Remove-Item -Recurse -Force $stage

Write-Host "exe=$releaseExe"
Write-Host "package=$zip"
Write-Host "hashes=$hashes"
