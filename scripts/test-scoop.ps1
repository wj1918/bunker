# Test Scoop (Option A), winget (Option B), and GitHub Releases (Option C) installation
# Run: powershell -ExecutionPolicy Bypass -File scripts\test-scoop.ps1

$ErrorActionPreference = "Continue"
$failed = 0
$passed = 0

function Test-Step {
    param([string]$Name, [scriptblock]$Block)
    Write-Host "`n--- $Name ---" -ForegroundColor Cyan
    try {
        & $Block
        Write-Host "PASS: $Name" -ForegroundColor Green
        $script:passed++
    } catch {
        Write-Host "FAIL: $Name - $_" -ForegroundColor Red
        $script:failed++
    }
}

# Capture both stdout and stderr as plain text
function Invoke-Cmd {
    param([string]$Cmd)
    $output = cmd /c "$Cmd 2>&1"
    return ($output | Out-String)
}

# Ensure scoop is in PATH
$env:PATH = "$env:USERPROFILE\scoop\shims;$env:PATH"

# Update Windows Defender definitions to latest
Write-Host "Updating Windows Defender definitions..." -ForegroundColor Yellow
& "C:\Program Files\Windows Defender\MpCmdRun.exe" -SignatureUpdate -MMPC 2>$null
$status = Get-MpComputerStatus
$sigAge = ((Get-Date) - $status.AntivirusSignatureLastUpdated).TotalHours
Write-Host "Defender version: $($status.AntivirusSignatureVersion) (updated $([math]::Round($sigAge, 1))h ago)" -ForegroundColor Cyan
if ($sigAge -gt 24) {
    Write-Host "WARNING: Defender definitions are over 24h old!" -ForegroundColor Red
}

# Clean up any previous install
Write-Host "Cleaning up previous install..." -ForegroundColor Yellow
scoop uninstall bunker 2>$null
scoop bucket rm bunker 2>$null
scoop cache rm bunker 2>$null

Test-Step "Add bucket" {
    $output = Invoke-Cmd "scoop bucket add bunker https://github.com/wj1918/bunker"
    if ($output -notmatch "added successfully") { throw "Unexpected: $output" }
}

Test-Step "Install from local manifest" {
    $manifest = (Resolve-Path "$PSScriptRoot\..\bucket\bunker.json").Path
    $output = Invoke-Cmd "scoop install `"$manifest`""
    if ($output -notmatch "installed successfully") { throw "Install failed: $output" }
    if ($output -notmatch "ok\.") { throw "Hash check not confirmed: $output" }
}

Test-Step "Files present" {
    $prefix = (scoop prefix bunker).Trim()
    $expected = @("bunker.exe", "config.yaml", "README.md")
    foreach ($file in $expected) {
        if (-not (Test-Path "$prefix\$file")) { throw "$file missing from $prefix" }
    }
}

Test-Step "Shim exists" {
    $shim = "$env:USERPROFILE\scoop\shims\bunker.exe"
    if (-not (Test-Path $shim)) { throw "Shim not found at $shim" }
}

Test-Step "Config persisted" {
    $persist = "$env:USERPROFILE\scoop\persist\bunker\config.yaml"
    if (-not (Test-Path $persist)) { throw "Persisted config not found at $persist" }
}

Test-Step "bunker --help" {
    $output = Invoke-Cmd "bunker --help"
    if ($output -notmatch "listen_addr") { throw "Missing listen_addr in help" }
    if ($output -notmatch "--config") { throw "Missing --config in help" }
    if ($output -notmatch "--init") { throw "Missing --init in help" }
}

Test-Step "bunker --init" {
    $testDir = Join-Path $env:TEMP "bunker-test-$(Get-Random)"
    New-Item -ItemType Directory -Path $testDir | Out-Null
    try {
        Push-Location $testDir
        $output = Invoke-Cmd "bunker --init"
        if (-not (Test-Path "config.yaml")) { throw "config.yaml not created" }
        $content = Get-Content "config.yaml" -Raw
        if ($content -notmatch "listen_addr") { throw "Invalid config content" }
        Pop-Location
    } finally {
        Remove-Item -Recurse -Force $testDir 2>$null
    }
}

Test-Step "Config auto-detection from exe dir" {
    $testDir = Join-Path $env:TEMP "bunker-test-$(Get-Random)"
    New-Item -ItemType Directory -Path $testDir | Out-Null
    try {
        Push-Location $testDir
        # Run bunker with a timeout - it may start successfully and block
        $outFile = Join-Path $env:TEMP "bunker-test-output-$(Get-Random).txt"
        $proc = Start-Process -FilePath "bunker" -RedirectStandardError $outFile -WindowStyle Hidden -PassThru
        Start-Sleep -Seconds 3
        if (!$proc.HasExited) { Stop-Process -Id $proc.Id -Force 2>$null }
        $output = if (Test-Path $outFile) { Get-Content $outFile -Raw } else { "" }
        Remove-Item $outFile -Force 2>$null
        if ($output -notmatch "Loading config from:.*scoop.*config\.yaml") {
            throw "Config not auto-detected from exe dir. Output: $output"
        }
        Pop-Location
    } finally {
        Remove-Item -Recurse -Force $testDir 2>$null
    }
}

Test-Step "bunker --install from temp dir" {
    $testDir = Join-Path $env:TEMP "bunker-test-$(Get-Random)"
    New-Item -ItemType Directory -Path $testDir | Out-Null
    try {
        Push-Location $testDir
        $output = Invoke-Cmd "bunker --install"
        if ($output -notmatch "added to Windows startup") { throw "Install failed: $output" }
        $reg = Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Bunker" -ErrorAction Stop
        $val = $reg.Bunker
        $prefix = (scoop prefix bunker).Trim()
        if ($val -notmatch [regex]::Escape($prefix)) {
            throw "Registry should use app dir ($prefix), got: $val"
        }
        Pop-Location
    } finally {
        Remove-Item -Recurse -Force $testDir 2>$null
    }
}

Test-Step "bunker --uninstall" {
    $output = Invoke-Cmd "bunker --uninstall"
    if ($output -notmatch "removed from Windows startup") { throw "Uninstall failed: $output" }
    try {
        Get-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Bunker" -ErrorAction Stop
        throw "Registry entry still exists after uninstall"
    } catch [System.Management.Automation.PSArgumentException] {
        # Expected - key doesn't exist
    }
}

Test-Step "Version matches release" {
    $info = Invoke-Cmd "scoop info bunker"
    $release = (gh release view --json tagName --jq '.tagName' 2>$null).Trim()
    $version = $release -replace '^v', ''
    if ($info -notmatch [regex]::Escape($version)) {
        throw "Version $version not found in scoop info"
    }
}

Test-Step "Code signature valid" {
    $prefix = (scoop prefix bunker).Trim()
    $sig = Get-AuthenticodeSignature "$prefix\bunker.exe"
    if ($sig.Status -ne "Valid") { throw "Signature status: $($sig.Status) - $($sig.StatusMessage)" }
    $subject = $sig.SignerCertificate.Subject
    if ($subject -notmatch "O=Jun Wang") { throw "Unexpected signer: $subject" }
    $issuer = $sig.SignerCertificate.Issuer
    if ($issuer -notmatch "Microsoft") { throw "Unexpected issuer: $issuer" }
}

Test-Step "SmartScreen trusted" {
    $prefix = (scoop prefix bunker).Trim()
    $sig = Get-AuthenticodeSignature "$prefix\bunker.exe"
    if ($sig.SignerCertificate.Issuer -notmatch "Microsoft") {
        throw "Not Microsoft-issued cert - SmartScreen may warn. Issuer: $($sig.SignerCertificate.Issuer)"
    }
    if ($sig.TimeStamperCertificate -eq $null) {
        throw "No timestamp - signature will expire with cert"
    }
}

Test-Step "Windows Defender scan" {
    $prefix = (scoop prefix bunker).Trim()
    $exe = "$prefix\bunker.exe"
    $output = & "C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File $exe 2>&1 | Out-String
    if ($output -notmatch "found no threats") { throw "Defender flagged bunker.exe: $output" }
}

Test-Step "SHA256 matches release" {
    $prefix = (scoop prefix bunker).Trim()
    $manifest = Get-Content "$prefix\manifest.json" | ConvertFrom-Json
    $manifestHash = $manifest.architecture.'64bit'.hash

    $sums = (gh release download v0.1.0 --pattern "SHA256SUMS.txt" --output - 2>$null) | Out-String
    $releaseHash = ($sums.Trim() -split '\s+')[0]

    if ($manifestHash -ne $releaseHash) {
        throw "Hash mismatch: manifest=$manifestHash release=$releaseHash"
    }
}

Test-Step "Checkver detects version" {
    $scoopDir = (scoop prefix scoop).Trim()
    $output = Invoke-Cmd "powershell -ExecutionPolicy Bypass -File `"$scoopDir\bin\checkver.ps1`" bunker -Dir `"$PSScriptRoot\..\bucket`""
    $release = (gh release view --json tagName --jq '.tagName' 2>$null).Trim() -replace '^v', ''
    if ($output -notmatch [regex]::Escape($release)) {
        throw "checkver did not detect version $release. Output: $output"
    }
}

Test-Step "Autoupdate computes hash" {
    $scoopDir = (scoop prefix scoop).Trim()
    $output = Invoke-Cmd "powershell -ExecutionPolicy Bypass -File `"$scoopDir\bin\checkver.ps1`" bunker -Dir `"$PSScriptRoot\..\bucket`" -ForceUpdate"
    if ($output -notmatch "Autoupdating bunker") { throw "Autoupdate did not trigger. Output: $output" }
    if ($output -notmatch "Found:.*using") { throw "Hash not computed. Output: $output" }
    # Verify the hash in updated manifest matches release
    $manifest = Get-Content "$PSScriptRoot\..\bucket\bunker.json" | ConvertFrom-Json
    $manifestHash = $manifest.architecture.'64bit'.hash
    $release = (gh release view --json tagName --jq '.tagName' 2>$null).Trim()
    $sums = (gh release download $release --pattern "SHA256SUMS.txt" --output - 2>$null) | Out-String
    $releaseHash = ($sums.Trim() -split '\s+')[0]
    if ($manifestHash -ne $releaseHash) {
        throw "Autoupdate hash mismatch: manifest=$manifestHash release=$releaseHash"
    }
}

Test-Step "Scoop uninstall" {
    $output = Invoke-Cmd "scoop uninstall bunker"
    if ($output -notmatch "was uninstalled") { throw "Uninstall failed: $output" }
    if (Test-Path "$env:USERPROFILE\scoop\apps\bunker\current") { throw "App dir still exists" }
}

# --- Option B: winget install ---
Write-Host "`n=== Option B: winget ===" -ForegroundColor Yellow
$wingetManifestDir = "$PSScriptRoot\..\winget\manifests"

Test-Step "Winget validate manifest" {
    if (-not (Test-Path $wingetManifestDir)) { throw "Manifest dir not found: $wingetManifestDir" }
    $output = winget validate $wingetManifestDir 2>&1 | Out-String
    if ($output -notmatch "succeeded") { throw "Validation failed: $output" }
}

Test-Step "Winget install from manifest" {
    $output = winget install --manifest $wingetManifestDir --accept-source-agreements 2>&1 | Out-String
    if ($output -notmatch "Successfully installed") { throw "Install failed: $output" }
}

$wingetPkgDir = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages"
$wingetBunkerDir = Get-ChildItem $wingetPkgDir -Directory -Filter "Bunker*" -ErrorAction SilentlyContinue | Select-Object -First 1

Test-Step "Winget files present" {
    if (-not $wingetBunkerDir) { throw "Bunker package dir not found in $wingetPkgDir" }
    $expected = @("bunker.exe", "config.yaml", "README.md")
    foreach ($file in $expected) {
        if (-not (Test-Path "$($wingetBunkerDir.FullName)\$file")) { throw "$file missing from $($wingetBunkerDir.FullName)" }
    }
}

Test-Step "Winget bunker --help" {
    $output = cmd /c "$($wingetBunkerDir.FullName)\bunker.exe --help 2>&1" | Out-String
    if ($output -notmatch "listen_addr") { throw "Missing listen_addr in help" }
    if ($output -notmatch "--config") { throw "Missing --config in help" }
}

Test-Step "Winget code signature valid" {
    $sig = Get-AuthenticodeSignature "$($wingetBunkerDir.FullName)\bunker.exe"
    if ($sig.Status -ne "Valid") { throw "Signature status: $($sig.Status) - $($sig.StatusMessage)" }
    if ($sig.SignerCertificate.Subject -notmatch "O=Jun Wang") { throw "Unexpected signer: $($sig.SignerCertificate.Subject)" }
    if ($sig.SignerCertificate.Issuer -notmatch "Microsoft") { throw "Unexpected issuer: $($sig.SignerCertificate.Issuer)" }
}

Test-Step "Winget Defender scan" {
    $output = & "C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File "$($wingetBunkerDir.FullName)\bunker.exe" 2>&1 | Out-String
    if ($output -notmatch "found no threats") { throw "Defender flagged bunker.exe: $output" }
}

Test-Step "Winget uninstall" {
    $output = winget uninstall --id Bunker.Bunker --version 0.1.0 --source winget 2>&1 | Out-String
    if ($output -notmatch "Successfully uninstalled") { throw "Uninstall failed: $output" }
}

Test-Step "Winget install via moniker" {
    $output = winget install bunker --accept-source-agreements 2>&1 | Out-String
    if ($output -notmatch "Successfully installed") { throw "Install failed: $output" }
}

Test-Step "Winget uninstall via moniker" {
    $output = winget uninstall bunker 2>&1 | Out-String
    if ($output -notmatch "Successfully uninstalled") { throw "Uninstall failed: $output" }
}

# --- Option C: GitHub Releases download ---
Write-Host "`n=== Option C: GitHub Releases ===" -ForegroundColor Yellow
$bunkerDir = "C:\Bunker"
if (Test-Path $bunkerDir) { Remove-Item -Recurse -Force $bunkerDir }

Test-Step "Download release zip" {
    New-Item -ItemType Directory -Path $bunkerDir | Out-Null
    $release = (gh release view --json tagName --jq '.tagName' 2>$null).Trim()
    $url = "https://github.com/wj1918/bunker/releases/download/$release/bunker-$release-x86_64-pc-windows-msvc.zip"
    Invoke-WebRequest -Uri $url -OutFile "$bunkerDir\bunker.zip"
    if (-not (Test-Path "$bunkerDir\bunker.zip")) { throw "Download failed" }
}

Test-Step "Release SHA256 matches" {
    $hash = (Get-FileHash "$bunkerDir\bunker.zip" -Algorithm SHA256).Hash
    $release = (gh release view --json tagName --jq '.tagName' 2>$null).Trim()
    $sums = (gh release download $release --pattern "SHA256SUMS.txt" --output - 2>$null) | Out-String
    $releaseHash = ($sums.Trim() -split '\s+')[0]
    if ($hash -ne $releaseHash) { throw "Hash mismatch: download=$hash release=$releaseHash" }
}

Test-Step "Extract zip" {
    Expand-Archive "$bunkerDir\bunker.zip" -DestinationPath $bunkerDir
    Remove-Item "$bunkerDir\bunker.zip"
    $expected = @("bunker.exe", "config.yaml", "README.md")
    foreach ($file in $expected) {
        if (-not (Test-Path "$bunkerDir\$file")) { throw "$file missing from $bunkerDir" }
    }
}

Test-Step "Release code signature valid" {
    $sig = Get-AuthenticodeSignature "$bunkerDir\bunker.exe"
    if ($sig.Status -ne "Valid") { throw "Signature status: $($sig.Status) - $($sig.StatusMessage)" }
    if ($sig.SignerCertificate.Subject -notmatch "O=Jun Wang") { throw "Unexpected signer: $($sig.SignerCertificate.Subject)" }
}

Test-Step "Release SmartScreen trusted" {
    $sig = Get-AuthenticodeSignature "$bunkerDir\bunker.exe"
    if ($sig.SignerCertificate.Issuer -notmatch "Microsoft") {
        throw "Not Microsoft-issued cert. Issuer: $($sig.SignerCertificate.Issuer)"
    }
    if ($sig.TimeStamperCertificate -eq $null) {
        throw "No timestamp - signature will expire with cert"
    }
}

Test-Step "Release bunker --help" {
    $output = cmd /c "$bunkerDir\bunker.exe --help 2>&1" | Out-String
    if ($output -notmatch "listen_addr") { throw "Missing listen_addr in help" }
    if ($output -notmatch "--config") { throw "Missing --config in help" }
}

Test-Step "Release Defender scan" {
    $output = & "C:\Program Files\Windows Defender\MpCmdRun.exe" -Scan -ScanType 3 -File "$bunkerDir\bunker.exe" 2>&1 | Out-String
    if ($output -notmatch "found no threats") { throw "Defender flagged bunker.exe: $output" }
}

# Clean up Option B
if (Test-Path $bunkerDir) { Remove-Item -Recurse -Force $bunkerDir }

# Summary
Write-Host "`n=============================" -ForegroundColor White
Write-Host "Results: $passed passed, $failed failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "=============================" -ForegroundColor White

exit $failed
