param(
    [Parameter(Mandatory = $true)]
    [string]$ReleaseDirectory
)

$ErrorActionPreference = "Stop"

$release = Resolve-Path $ReleaseDirectory
$exe = Join-Path $release "password-manager.exe"
$hashFile = Join-Path $release "SHA256SUMS.txt"
$report = Join-Path $release "windows10-level4-report.txt"

if (-not (Test-Path $exe)) {
    throw "password-manager.exe not found in $release"
}
if (-not (Test-Path $hashFile)) {
    throw "SHA256SUMS.txt not found in $release"
}

$os = Get-CimInstance Win32_OperatingSystem
$computer = Get-CimInstance Win32_ComputerSystem
if ($os.Caption -notmatch "Windows 10") {
    throw "Level 4 requires a real Windows 10 machine. Detected: $($os.Caption)"
}

$expectedLine = Get-Content $hashFile | Where-Object { $_ -match '\*password-manager\.exe$' } | Select-Object -First 1
if (-not $expectedLine) {
    throw "No password-manager.exe hash found in SHA256SUMS.txt"
}
$expectedHash = ($expectedLine -split '\s+')[0].ToLowerInvariant()
$actualHash = (Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()
if ($actualHash -ne $expectedHash) {
    throw "SHA-256 mismatch for password-manager.exe"
}

& $exe --self-test
if ($LASTEXITCODE -ne 0) {
    throw "Automated release self-test failed."
}

@"
Password Manager - Windows 10 Level 4 Report
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss K")
Computer: $($computer.Name)
OS: $($os.Caption)
Version: $($os.Version)
Build: $($os.BuildNumber)
Architecture: $($os.OSArchitecture)
Executable SHA-256: $actualHash

AUTOMATED
[PASS] Release SHA-256 matches SHA256SUMS.txt
[PASS] --self-test create/save/open/reveal/backup/restore roundtrip

MANUAL ACCEPTANCE
[ ] Launch normally and create a fresh vault
[ ] Unlock an existing vault after closing/reopening the app
[ ] Add, edit, favorite, recycle, restore, and permanently delete a synthetic entry
[ ] Search, categories, favorites, and recycle-bin navigation behave correctly
[ ] Chinese IME works in name, username, category, and notes fields
[ ] Unicode / emoji / long text render and persist correctly
[ ] DPI 100% renders without clipping
[ ] DPI 125% renders without clipping
[ ] DPI 150% renders without clipping
[ ] DPI 200% renders without clipping
[ ] Ctrl+F focuses search
[ ] Ctrl+N opens a new entry
[ ] Ctrl+S saves current edit / validates persisted vault
[ ] Ctrl+L locks the vault
[ ] Screenshot protection blocks supported Windows capture paths when enabled
[ ] Disabling screenshot protection restores normal supported capture behavior
[ ] Copy password; after 30 seconds the clipboard is cleared if unchanged
[ ] Copy password, then copy unrelated text before 30 seconds; unrelated text remains
[ ] Win+L, unlock Windows, and confirm the vault is locked
[ ] Put Windows to sleep/resume and confirm the vault is locked
[ ] Encrypted backup creation and restore succeed
[ ] Google/Chrome CSV Preview shows New / Duplicate / Update / Conflict correctly
[ ] Reimport does not silently overwrite weak-identity conflicts
[ ] No plaintext password appears in app logs or generated report

Fill PASS/FAIL notes below:
"@ | Set-Content -Encoding UTF8 $report

Write-Host "Automated Windows 10 Level 4 checks passed."
Write-Host "Complete the manual acceptance items in: $report"
