# Test Scoop package installation and functionality
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

Test-Step "Install and hash check" {
    $output = Invoke-Cmd "scoop install bunker"
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

Test-Step "Version matches release" {
    $info = Invoke-Cmd "scoop info bunker"
    $release = (gh release view --json tagName --jq '.tagName' 2>$null).Trim()
    $version = $release -replace '^v', ''
    if ($info -notmatch [regex]::Escape($version)) {
        throw "Version $version not found in scoop info"
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

# Summary
Write-Host "`n=============================" -ForegroundColor White
Write-Host "Results: $passed passed, $failed failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Red" })
Write-Host "=============================" -ForegroundColor White

exit $failed
