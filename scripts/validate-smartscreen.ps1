# validate-smartscreen.ps1
# Quick PowerShell wrapper to compile and run the SmartScreen validation test.
#
# Usage:
#   .\validate-smartscreen.ps1 <path-to-exe> [source-url]
#
# Examples:
#   .\validate-smartscreen.ps1 .\bunker.exe
#   .\validate-smartscreen.ps1 .\bunker.exe "https://github.com/wj1918/bunker/releases/download/v0.1.0/bunker-v0.1.0-x86_64-pc-windows-msvc.zip"
#   .\validate-smartscreen.ps1 .\bunker.exe -AddMOTW    # also stamps Zone.Identifier before testing

param(
    [Parameter(Mandatory=$true, Position=0)]
    [string]$ExePath,

    [Parameter(Position=1)]
    [string]$SourceUrl = "https://github.com/wj1918/bunker/releases",

    [switch]$AddMOTW
)

$ErrorActionPreference = "Stop"
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$csFile = Join-Path $scriptDir "SmartScreenTest.cs"
$testExe = Join-Path $env:TEMP "SmartScreenTest.exe"
$ExePath = Resolve-Path $ExePath

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Winget SmartScreen Validation Test"    -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Step 0: Optionally add MOTW to simulate internet download
if ($AddMOTW) {
    Write-Host "[Prep] Adding Mark-of-the-Web (ZoneId=3) to simulate internet download..." -ForegroundColor Yellow
    Set-Content -LiteralPath $ExePath -Stream Zone.Identifier -Value "[ZoneTransfer]`r`nZoneId=3"
    Write-Host "        Done." -ForegroundColor Green
    Write-Host ""
}

# Step 1: Compile the C# test
Write-Host "[1/3] Compiling SmartScreenTest.cs..." -ForegroundColor Yellow
$csc = Join-Path ([System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()) "csc.exe"
$compileOutput = & $csc /nologo /out:$testExe $csFile 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "  Compilation failed:" -ForegroundColor Red
    Write-Host $compileOutput
    exit 2
}
Write-Host "       Compiled to $testExe" -ForegroundColor Green
Write-Host ""

# Step 2: Run the test
Write-Host "[2/3] Running security check..." -ForegroundColor Yellow
Write-Host ""
& $testExe $ExePath $SourceUrl
$result = $LASTEXITCODE
Write-Host ""

# Step 3: Report
Write-Host "[3/3] Result" -ForegroundColor Yellow
if ($result -eq 0) {
    Write-Host "       PASS - File should pass winget validation" -ForegroundColor Green
} else {
    Write-Host "       FAIL - File will be blocked by winget validation" -ForegroundColor Red
    Write-Host ""
    Write-Host "  To fix, sign the exe with a code-signing certificate:" -ForegroundColor Yellow
    Write-Host "    - Azure Trusted Signing (~`$10/month)" -ForegroundColor Gray
    Write-Host "    - SignPath.io (free for OSS)" -ForegroundColor Gray
    Write-Host "    - SSL.com OV cert (~`$70/year)" -ForegroundColor Gray
}

Write-Host ""
exit $result
