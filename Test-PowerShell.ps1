# Simple PowerShell Test Script
# This script tests basic PowerShell functionality

Write-Host "=== POWERShell TEST SCRIPT ===" -ForegroundColor Cyan
Write-Host "Script started at: $(Get-Date)" -ForegroundColor White
Write-Host "PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor White
Write-Host "Execution policy: $(Get-ExecutionPolicy)" -ForegroundColor White
Write-Host "Current user: $env:USERNAME" -ForegroundColor White
Write-Host "Computer name: $env:COMPUTERNAME" -ForegroundColor White
Write-Host "Current directory: $(Get-Location)" -ForegroundColor White

# Test basic commands
Write-Host "`n=== Testing Basic Commands ===" -ForegroundColor Yellow
try {
    $OS = Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber
    Write-Host "OS Info: $($OS.Caption) $($OS.Version) Build $($OS.BuildNumber)" -ForegroundColor Green
} catch {
    Write-Host "WMI test failed: $($_.Exception.Message)" -ForegroundColor Red
}

try {
    $Services = Get-Service | Where-Object {$_.Name -like "*ccm*"} | Select-Object Name, Status
    Write-Host "CCM Services found: $($Services.Count)" -ForegroundColor Green
    foreach ($Service in $Services) {
        Write-Host "  $($Service.Name) - $($Service.Status)" -ForegroundColor White
    }
} catch {
    Write-Host "Service test failed: $($_.Exception.Message)" -ForegroundColor Red
}

# Test admin privileges
Write-Host "`n=== Testing Administrative Privileges ===" -ForegroundColor Yellow
$IsAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")
if ($IsAdmin) {
    Write-Host "Running as Administrator: $IsAdmin" -ForegroundColor Green
} else {
    Write-Host "Running as Administrator: $IsAdmin" -ForegroundColor Red
}

# Test file operations
Write-Host "`n=== Testing File Operations ===" -ForegroundColor Yellow
$TestPath = "C:\Windows\System32"
if (Test-Path $TestPath) {
    Write-Host "Can access $TestPath - True" -ForegroundColor Green
} else {
    Write-Host "Can access $TestPath - False" -ForegroundColor Red
}

Write-Host "`n=== Test Complete ===" -ForegroundColor Cyan
Write-Host "Press Enter to continue..." -ForegroundColor White
Read-Host
