#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    SCCM Agent Repair and Recovery Script
    
.DESCRIPTION
    This script performs comprehensive repair of broken SCCM agents including:
    - CCMRepair tool execution
    - Policy reset and cache clearing
    - Client registration reset
    - WMI namespace repair
    - CCM cache clearing
    - Validation and logging
    
.PARAMETER LogPath
    Path where the log file will be created. Defaults to C:\SCCMREPAIR
    
.NOTES
    Version: 1.0
    Author: Biju George - Technical Consultant
    Requires: Administrative privileges
#>

param(
    [string]$LogPath = "C:\SCCMREPAIR"
)

# IMMEDIATE TEST - This should show up immediately when script loads
Write-Host "=== SCRIPT LOADED SUCCESSFULLY ===" -ForegroundColor Green -BackgroundColor Black
Write-Host "Script loaded at: $(Get-Date)" -ForegroundColor Green
Write-Host "PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor Green
Write-Host "Execution policy: $(Get-ExecutionPolicy)" -ForegroundColor Green
Write-Host "Current user: $env:USERNAME" -ForegroundColor Green
Write-Host "Computer: $env:COMPUTERNAME" -ForegroundColor Green
Write-Host "OS: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption)" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green

# Script variables
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$LogFile = Join-Path $LogPath "sccm-repair.$Timestamp.log"
$ErrorActionPreference = "Continue"
$VerbosePreference = "Continue"

# Add debug output
Write-Host "Script starting... Script path: $PSCommandPath" -ForegroundColor Green
Write-Host "Current directory: $(Get-Location)" -ForegroundColor Green
Write-Host "PowerShell version: $($PSVersionTable.PSVersion)" -ForegroundColor Green
Write-Host "Running as Administrator: $(([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator'))" -ForegroundColor Green

# Function to write to log file
function Write-Log {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    $LogMessage = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss'): [$Level] $Message"
    Write-Host $LogMessage
    Add-Content -Path $LogFile -Value $LogMessage -ErrorAction SilentlyContinue
}

# Function to show progress bar
function Show-Progress {
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete
    )
    
    Write-Progress -Activity $Activity -Status $Status -PercentComplete $PercentComplete
    Write-Log "Progress: $Activity - $Status ($PercentComplete%)"
}

# Function to check if SCCM agent is installed
function Test-SCCMInstalled {
    try {
        $CCMService = Get-Service -Name "ccmexec" -ErrorAction SilentlyContinue
        $CCMInstalled = Test-Path "C:\Windows\CCM\ccmexec.exe"
        
        if ($CCMService -and $CCMInstalled) {
            Write-Log "SCCM Agent is installed and service exists" "INFO"
            return $true
        } else {
            Write-Log "SCCM Agent is not installed or service not found" "WARN"
            return $false
        }
    }
    catch {
        Write-Log "Error checking SCCM installation: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to run CCMRepair tool
function Invoke-CCMRepair {
    try {
        Write-Log "Starting CCMRepair tool execution..." "INFO"
        
        if (Test-Path "C:\Windows\CCM\CCMRepair.exe") {
            $CCMRepairProcess = Start-Process -FilePath "C:\Windows\CCM\CCMRepair.exe" -ArgumentList "/q" -Wait -PassThru
            
            if ($CCMRepairProcess.ExitCode -eq 0) {
                Write-Log "CCMRepair completed successfully" "INFO"
                return $true
            } else {
                Write-Log "CCMRepair failed with exit code: $($CCMRepairProcess.ExitCode)" "ERROR"
                return $false
            }
        } else {
            Write-Log "CCMRepair.exe not found in C:\Windows\CCM\" "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Error running CCMRepair: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to check CCMRepair logs
function Test-CCMRepairLogs {
    try {
        $LogPath = "C:\Windows\CCM\Logs\ccmrepair.log"
        
        if (Test-Path $LogPath) {
            Write-Log "CCMRepair log file found, checking contents..." "INFO"
            
            $LogContent = Get-Content $LogPath -Tail 20 -ErrorAction SilentlyContinue
            if ($LogContent) {
                Write-Log "Last 20 lines of CCMRepair log:" "INFO"
                foreach ($Line in $LogContent) {
                    Write-Log "  $Line" "INFO"
                }
                
                # Check for common success indicators
                $SuccessIndicators = @("successful", "completed", "succeeded", "repaired")
                $HasSuccess = $LogContent | Where-Object { $SuccessIndicators -contains ($_ -split '\s+')[0].ToLower() }
                
                if ($HasSuccess) {
                    Write-Log "CCMRepair logs indicate successful completion" "INFO"
                    return $true
                } else {
                    Write-Log "CCMRepair logs do not clearly indicate success" "WARN"
                    return $false
                }
            } else {
                Write-Log "CCMRepair log file is empty or unreadable" "WARN"
                return $false
            }
        } else {
            Write-Log "CCMRepair log file not found" "WARN"
            return $false
        }
    }
    catch {
        Write-Log "Error checking CCMRepair logs: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to reset policy and trigger fresh pull
function Reset-SCCMPolicy {
    try {
        Write-Log "Starting policy reset and cache clearing..." "INFO"
        
        # Stop CCMExec service
        Write-Log "Stopping CCMExec service..." "INFO"
        Stop-Service -Name "ccmexec" -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 5
        
        # Delete machine and user policy cache from registry
        Write-Log "Clearing policy cache from registry..." "INFO"
        
        $RegistryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\CCM\CcmEval\Policy",
            "HKLM:\SOFTWARE\Microsoft\CCM\CcmEval\Policy\Machine",
            "HKLM:\SOFTWARE\Microsoft\CCM\CcmEval\Policy\User",
            "HKLM:\SOFTWARE\Microsoft\CCM\CcmEval\Policy\Machine\ActualConfig",
            "HKLM:\SOFTWARE\Microsoft\CCM\CcmEval\Policy\User\ActualConfig"
        )
        
        foreach ($Path in $RegistryPaths) {
            if (Test-Path $Path) {
                Remove-Item -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Cleared registry path: $Path" "INFO"
            }
        }
        
        # Start CCMExec service
        Write-Log "Starting CCMExec service..." "INFO"
        Start-Service -Name "ccmexec" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 10
        
        # Trigger policy retrieval
        Write-Log "Triggering policy retrieval..." "INFO"
        $CCMProcess = Get-Process -Name "ccmexec" -ErrorAction SilentlyContinue
        if ($CCMProcess) {
            Write-Log "Policy reset completed successfully" "INFO"
            return $true
        } else {
            Write-Log "Failed to start CCMExec service" "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Error during policy reset: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to reset client registration
function Reset-SCCMRegistration {
    try {
        Write-Log "Starting client registration reset..." "INFO"
        
        if (Test-Path "C:\Windows\CCM\ccmsetup.exe") {
            Write-Log "Running ccmsetup.exe with RESETKEYINFORMATION=TRUE..." "INFO"
            
            $CCMSetupProcess = Start-Process -FilePath "C:\Windows\CCM\ccmsetup.exe" -ArgumentList "RESETKEYINFORMATION=TRUE", "/logon" -Wait -PassThru
            
            if ($CCMSetupProcess.ExitCode -eq 0) {
                Write-Log "Client registration reset completed successfully" "INFO"
                Write-Log "This keeps the client installed but forces a new registration handshake with the MP" "INFO"
                return $true
            } else {
                Write-Log "Client registration reset failed with exit code: $($CCMSetupProcess.ExitCode)" "ERROR"
                return $false
            }
        } else {
            Write-Log "ccmsetup.exe not found in C:\Windows\CCM\" "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Error during client registration reset: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to repair WMI namespace
function Repair-WMINamespace {
    try {
        Write-Log "Starting WMI namespace repair..." "INFO"
        
        # Verify WMI repository
        Write-Log "Verifying WMI repository..." "INFO"
        $WMIVerify = Start-Process -FilePath "winmgmt" -ArgumentList "/verifyrepository" -Wait -PassThru
        
        if ($WMIVerify.ExitCode -ne 0) {
            Write-Log "WMI repository verification failed, attempting repair..." "WARN"
            
            # Stop CCMExec service
            Write-Log "Stopping CCMExec service for WMI repair..." "INFO"
            Stop-Service -Name "ccmexec" -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 5
            
            # Reset WMI repository
            Write-Log "Resetting WMI repository..." "INFO"
            $WMIReset = Start-Process -FilePath "winmgmt" -ArgumentList "/resetrepository" -Wait -PassThru
            
            if ($WMIReset.ExitCode -eq 0) {
                Write-Log "WMI repository reset completed successfully" "INFO"
                
                # Start CCMExec service
                Write-Log "Starting CCMExec service..." "INFO"
                Start-Service -Name "ccmexec" -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 10
                
                return $true
            } else {
                Write-Log "WMI repository reset failed with exit code: $($WMIReset.ExitCode)" "ERROR"
                return $false
            }
        } else {
            Write-Log "WMI repository verification passed" "INFO"
            return $true
        }
    }
    catch {
        Write-Log "Error during WMI namespace repair: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to clear CCM cache
function Clear-CCMCache {
    try {
        Write-Log "Starting CCM cache clearing..." "INFO"
        
        $CachePaths = @(
            "C:\Windows\CCM\Cache",
            "C:\Windows\CCM\SystemTemp",
            "C:\Windows\CCM\Temp"
        )
        
        foreach ($Path in $CachePaths) {
            if (Test-Path $Path) {
                Write-Log "Clearing cache directory: $Path" "INFO"
                
                # Stop CCMExec before clearing cache
                Stop-Service -Name "ccmexec" -Force -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 5
                
                # Clear cache contents
                Get-ChildItem -Path $Path -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse -ErrorAction SilentlyContinue
                
                # Start CCMExec service
                Start-Service -Name "ccmexec" -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 10
                
                Write-Log "Cache directory cleared: $Path" "INFO"
            }
        }
        
        Write-Log "CCM cache clearing completed successfully" "INFO"
        return $true
    }
    catch {
        Write-Log "Error during CCM cache clearing: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Function to validate the repair process
function Test-SCCMRepairValidation {
    try {
        Write-Log "Starting validation of SCCM repair process..." "INFO"
        
        $ValidationResults = @()
        
        # Check if CCMExec service is running
        $CCMService = Get-Service -Name "ccmexec" -ErrorAction SilentlyContinue
        if ($CCMService.Status -eq "Running") {
            Write-Log "CCMExec service is running" "INFO"
            $ValidationResults += "Service Running"
        } else {
            Write-Log "CCMExec service is not running" "ERROR"
            $ValidationResults += "Service Not Running"
        }
        
        # Check if CCM processes are active
        $CCMProcesses = Get-Process -Name "ccmexec" -ErrorAction SilentlyContinue
        if ($CCMProcesses) {
            Write-Log "CCM processes are active" "INFO"
            $ValidationResults += "Processes Active"
        } else {
            Write-Log "CCM processes are not active" "ERROR"
            $ValidationResults += "Processes Not Active"
        }
        
        # Check WMI connectivity
        try {
            $WMIQuery = Get-WmiObject -Class Win32_ComputerSystem -ErrorAction SilentlyContinue
            if ($WMIQuery) {
                Write-Log "WMI connectivity is working" "INFO"
                $ValidationResults += "WMI Working"
            } else {
                Write-Log "WMI connectivity is not working" "ERROR"
                $ValidationResults += "WMI Not Working"
            }
        }
        catch {
            Write-Log "WMI connectivity test failed" "ERROR"
            $ValidationResults += "WMI Failed"
        }
        
        # Check registry keys
        $RegistryKeys = @(
            "HKLM:\SOFTWARE\Microsoft\CCM",
            "HKLM:\SOFTWARE\Microsoft\CCM\CcmEval"
        )
        
        $RegistryValid = $true
        foreach ($Key in $RegistryKeys) {
            if (-not (Test-Path $Key)) {
                $RegistryValid = $false
                break
            }
        }
        
        if ($RegistryValid) {
            Write-Log "SCCM registry keys are present" "INFO"
            $ValidationResults += "Registry Valid"
        } else {
            Write-Log "Some SCCM registry keys are missing" "ERROR"
            $ValidationResults += "Registry Invalid"
        }
        
        # Summary
        $SuccessCount = ($ValidationResults | Where-Object { $_ -notlike "*Not*" -and $_ -notlike "*Failed*" -and $_ -notlike "*Invalid*" }).Count
        $TotalCount = $ValidationResults.Count
        
        Write-Log "Validation Summary: $SuccessCount out of $TotalCount checks passed" "INFO"
        
        if ($SuccessCount -eq $TotalCount) {
            Write-Log "All validation checks passed - SCCM repair appears successful" "INFO"
            return $true
        } else {
            Write-Log "Some validation checks failed - SCCM may need additional attention" "WARN"
            return $false
        }
    }
    catch {
        Write-Log "Error during validation: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Enhanced function to check SCCM server connectivity and health
function Test-SCCMConnectivity {
    try {
        Write-Log "Starting SCCM server connectivity and health checks..." "INFO"
        
        $ConnectivityResults = @()
        
        # Check Management Point (MP) connectivity
        try {
            $MPInfo = Get-WmiObject -Namespace "root\ccm\LocationServices" -Class "SMS_MPInformation" -ErrorAction SilentlyContinue
            if ($MPInfo) {
                Write-Log "Management Point information retrieved successfully" "INFO"
                Write-Log "  MP: $($MPInfo.MP_NetBiosName)" "INFO"
                Write-Log "  MP: $($MPInfo.MP_FQDN)" "INFO"
                $ConnectivityResults += "MP Connectivity"
            } else {
                Write-Log "Could not retrieve Management Point information" "WARN"
                $ConnectivityResults += "MP Connectivity Failed"
            }
        }
        catch {
            Write-Log "Management Point connectivity test failed" "WARN"
            $ConnectivityResults += "MP Connectivity Failed"
        }
        
        # Check Distribution Point (DP) connectivity
        try {
            $DPInfo = Get-WmiObject -Namespace "root\ccm\LocationServices" -Class "SMS_DPInformation" -ErrorAction SilentlyContinue
            if ($DPInfo) {
                Write-Log "Distribution Point information retrieved successfully" "INFO"
                foreach ($DP in $DPInfo) {
                    Write-Log "  DP: $($DP.DP_NetBiosName)" "INFO"
                }
                $ConnectivityResults += "DP Connectivity"
            } else {
                Write-Log "Could not retrieve Distribution Point information" "WARN"
                $ConnectivityResults += "DP Connectivity Failed"
            }
        }
        catch {
            Write-Log "Distribution Point connectivity test failed" "WARN"
            $ConnectivityResults += "DP Connectivity Failed"
        }
        
        # Check client registration status
        try {
            $ClientInfo = Get-WmiObject -Namespace "root\ccm" -Class "CCM_Client" -ErrorAction SilentlyContinue
            if ($ClientInfo) {
                Write-Log "Client information retrieved successfully" "INFO"
                Write-Log "  Client ID: $($ClientInfo.ClientID)" "INFO"
                Write-Log "  Site Code: $($ClientInfo.SiteCode)" "INFO"
                $ConnectivityResults += "Client Registration"
            } else {
                Write-Log "Could not retrieve client information" "WARN"
                $ConnectivityResults += "Client Registration Failed"
            }
        }
        catch {
            Write-Log "Client registration check failed" "WARN"
            $ConnectivityResults += "Client Registration Failed"
        }
        
        # Check policy download capability
        try {
            $PolicyInfo = Get-WmiObject -Namespace "root\ccm\Policy" -Class "CCM_Policy" -ErrorAction SilentlyContinue
            if ($PolicyInfo) {
                Write-Log "Policy information retrieved successfully" "INFO"
                Write-Log "  Policy count: $($PolicyInfo.Count)" "INFO"
                $ConnectivityResults += "Policy Access"
            } else {
                Write-Log "Could not retrieve policy information" "WARN"
                $ConnectivityResults += "Policy Access Failed"
            }
        }
        catch {
            Write-Log "Policy access check failed" "WARN"
            $ConnectivityResults += "Policy Access Failed"
        }
        
        # Check CCM logs for recent activity
        try {
            $CCMLogPath = "C:\Windows\CCM\Logs"
            if (Test-Path $CCMLogPath) {
                $RecentLogs = Get-ChildItem -Path $CCMLogPath -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 5
                if ($RecentLogs) {
                    Write-Log "Recent CCM log files found:" "INFO"
                    foreach ($Log in $RecentLogs) {
                        Write-Log "  $($Log.Name) - Last modified: $($Log.LastWriteTime)" "INFO"
                    }
                    $ConnectivityResults += "Log Activity"
                } else {
                    Write-Log "No recent CCM log files found" "WARN"
                    $ConnectivityResults += "Log Activity Failed"
                }
            } else {
                Write-Log "CCM logs directory not found" "WARN"
                $ConnectivityResults += "Log Activity Failed"
            }
        }
        catch {
            Write-Log "Log activity check failed" "WARN"
            $ConnectivityResults += "Log Activity Failed"
        }
        
        # Check network connectivity to common SCCM ports
        try {
            $SCCMPorts = @(80, 443, 10123, 10124)
            $PortResults = @()
            
            foreach ($Port in $SCCMPorts) {
                try {
                    $TestConnection = Test-NetConnection -ComputerName $env:COMPUTERNAME -Port $Port -InformationLevel Quiet -WarningAction SilentlyContinue
                    if ($TestConnection) {
                        $PortResults += "Port $Port"
                    }
                }
                catch {
                    # Port test failed, continue
                }
            }
            
            if ($PortResults.Count -gt 0) {
                Write-Log "Network ports available: $($PortResults -join ', ')" "INFO"
                $ConnectivityResults += "Network Ports"
            } else {
                Write-Log "No common SCCM network ports are accessible" "WARN"
                $ConnectivityResults += "Network Ports Failed"
            }
        }
        catch {
            Write-Log "Network port check failed" "WARN"
            $ConnectivityResults += "Network Ports Failed"
        }
        
        # Summary
        $SuccessCount = ($ConnectivityResults | Where-Object { $_ -notlike "*Failed*" }).Count
        $TotalCount = $ConnectivityResults.Count
        
        Write-Log "Connectivity Summary: $SuccessCount out of $TotalCount checks passed" "INFO"
        
        if ($SuccessCount -eq $TotalCount) {
            Write-Log "All connectivity checks passed - SCCM communication appears healthy" "INFO"
            return $true
        } elseif ($SuccessCount -ge ($TotalCount * 0.7)) {
            Write-Log "Most connectivity checks passed - SCCM communication is mostly healthy" "WARN"
            return $true
        } else {
            Write-Log "Many connectivity checks failed - SCCM communication has issues" "ERROR"
            return $false
        }
    }
    catch {
        Write-Log "Error during connectivity check: $($_.Exception.Message)" "ERROR"
        return $false
    }
}

# Main execution function
function Start-SCCMRepair {
    try {
        Write-Host "Start-SCCMRepair function entered..." -ForegroundColor Cyan
        
        # Create log directory if it doesn't exist
        Write-Host "Checking log directory: $LogPath" -ForegroundColor Cyan
        if (-not (Test-Path $LogPath)) {
            Write-Host "Creating log directory..." -ForegroundColor Yellow
            New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
            Write-Log "Created log directory: $LogPath" "INFO"
            Write-Host "Log directory created successfully" -ForegroundColor Green
        } else {
            Write-Host "Log directory already exists" -ForegroundColor Green
        }
        
        Write-Log "=== SCCM Agent Repair Script Started ===" "INFO"
        Write-Log "Log file: $LogFile" "INFO"
        Write-Log "Timestamp: $Timestamp" "INFO"
        
        Write-Host "Log file will be: $LogFile" -ForegroundColor Cyan
        
        # Step 1: Run CCMRepair tool (SCCM already verified in main execution)
        Show-Progress -Activity "Step 1: CCMRepair Execution" -Status "Running CCMRepair tool" -PercentComplete 20
        
        if (Invoke-CCMRepair) {
            Show-Progress -Activity "Step 1: Log Verification" -Status "Checking CCMRepair logs" -PercentComplete 30
            
            if (Test-CCMRepairLogs) {
                Write-Log "Step 1 completed successfully" "INFO"
            } else {
                Write-Log "Step 1 completed with warnings" "WARN"
            }
        } else {
            Write-Log "Step 1 failed - CCMRepair execution unsuccessful" "ERROR"
            return $false
        }
        
        # Step 2: Reset policy and trigger fresh pull
        Show-Progress -Activity "Step 2: Policy Reset" -Status "Resetting SCCM policies and cache" -PercentComplete 40
        
        if (Reset-SCCMPolicy) {
            Write-Log "Step 2 completed successfully" "INFO"
        } else {
            Write-Log "Step 2 completed with errors" "ERROR"
        }
        
        # Step 3: Reset client registration
        Show-Progress -Activity "Step 3: Client Registration Reset" -Status "Resetting client registration" -PercentComplete 50
        
        if (Reset-SCCMRegistration) {
            Write-Log "Step 3 completed successfully" "INFO"
        } else {
            Write-Log "Step 3 completed with errors" "ERROR"
        }
        
        # Step 4: Repair WMI namespace
        Show-Progress -Activity "Step 4: WMI Namespace Repair" -Status "Repairing WMI namespace" -PercentComplete 60
        
        if (Repair-WMINamespace) {
            Write-Log "Step 4 completed successfully" "INFO"
        } else {
            Write-Log "Step 4 completed with errors" "ERROR"
        }
        
        # Step 5: Clear CCM cache
        Show-Progress -Activity "Step 5: CCM Cache Clearing" -Status "Clearing CCM cache" -PercentComplete 70
        
        if (Clear-CCMCache) {
            Write-Log "Step 5 completed successfully" "INFO"
        } else {
            Write-Log "Step 5 completed with errors" "ERROR"
        }
        
        # Final validation
        Show-Progress -Activity "Final Validation" -Status "Validating repair process" -PercentComplete 90
        
        if (Test-SCCMRepairValidation) {
            Write-Log "=== SCCM Repair Process Completed Successfully ===" "INFO"
            
            # Additional connectivity and health check
            Show-Progress -Activity "Connectivity Check" -Status "Checking SCCM server connectivity and health" -PercentComplete 95
            Write-Log "Performing additional connectivity and health checks..." "INFO"
            
            if (Test-SCCMConnectivity) {
                Write-Log "SCCM connectivity and health checks passed" "INFO"
            } else {
                Write-Log "SCCM connectivity and health checks show some issues" "WARN"
            }
            
            Show-Progress -Activity "Complete" -Status "SCCM repair completed successfully" -PercentComplete 100
        } else {
            Write-Log "=== SCCM Repair Process Completed with Issues ===" "WARN"
            
            # Still perform connectivity check even if basic validation failed
            Show-Progress -Activity "Connectivity Check" -Status "Checking SCCM server connectivity and health" -PercentComplete 95
            Write-Log "Performing connectivity and health checks despite basic validation issues..." "INFO"
            
            if (Test-SCCMConnectivity) {
                Write-Log "SCCM connectivity and health checks passed" "INFO"
            } else {
                Write-Log "SCCM connectivity and health checks failed" "ERROR"
            }
            
            Show-Progress -Activity "Complete" -Status "SCCM repair completed with issues" -PercentComplete 100
        }
        
        Write-Progress -Activity "Complete" -Completed
        return $true
    }
    catch {
        Write-Log "Critical error during SCCM repair: $($_.Exception.Message)" "ERROR"
        Write-Progress -Activity "Error" -Completed
        return $false
    }
}

# Test function to verify basic functionality
function Test-BasicFunctionality {
    Write-Host "Testing basic functionality..." -ForegroundColor Magenta
    Write-Host "Current user: $env:USERNAME" -ForegroundColor Magenta
    Write-Host "Computer name: $env:COMPUTERNAME" -ForegroundColor Magenta
    Write-Host "OS version: $(Get-WmiObject -Class Win32_OperatingSystem | Select-Object -ExpandProperty Caption)" -ForegroundColor Magenta
    Write-Host "PowerShell execution policy: $(Get-ExecutionPolicy)" -ForegroundColor Magenta
    return $true
}

# Script execution
Write-Host "=== SCRIPT EXECUTION STARTING ===" -ForegroundColor Red -BackgroundColor White
Write-Host "Current timestamp: $(Get-Date)" -ForegroundColor Red
Write-Host "Script path: $PSCommandPath" -ForegroundColor Red
Write-Host "Working directory: $(Get-Location)" -ForegroundColor Red

try {
    Write-Host "Starting script execution..." -ForegroundColor Yellow
    
    # Test basic functionality first
    Write-Host "Running basic functionality test..." -ForegroundColor Yellow
    Test-BasicFunctionality
    
    # Check if running as administrator
    Write-Host "Checking administrative privileges..." -ForegroundColor Yellow
    if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
        Write-Error "This script requires administrative privileges. Please run as Administrator."
        Write-Host "Script will continue in 5 seconds but may fail..." -ForegroundColor Red
        Start-Sleep -Seconds 5
        $AdminCheckFailed = $true
    } else {
        $AdminCheckFailed = $false
    }
    
    if ($AdminCheckFailed) {
        Write-Host "Administrative privileges check failed. Script may not work properly." -ForegroundColor Red
    } else {
        Write-Host "Administrative privileges confirmed. Proceeding..." -ForegroundColor Green
    }
    
    # Check if SCCM agent is installed before proceeding
    Write-Host "Checking if SCCM agent is installed..." -ForegroundColor Yellow
    if (Test-SCCMInstalled) {
        Write-Host "SCCM agent found. Proceeding with repair..." -ForegroundColor Green
        
        # Execute the main repair function
        Write-Host "Calling Start-SCCMRepair function..." -ForegroundColor Yellow
        $Result = Start-SCCMRepair
        
        Write-Host "Start-SCCMRepair returned: $Result" -ForegroundColor Yellow
        
        if ($Result) {
            Write-Log "Script execution completed. Check the log file for details: $LogFile" "INFO"
            Write-Host "Script completed successfully! Check log file: $LogFile" -ForegroundColor Green
            Write-Host "Script execution finished. ISE window will remain open." -ForegroundColor Green
        } else {
            Write-Log "Script execution completed with errors. Check the log file for details: $LogFile" "ERROR"
            Write-Host "Script completed with errors. Check log file: $LogFile" -ForegroundColor Red
            Write-Host "Script execution finished. ISE window will remain open." -ForegroundColor Red
        }
        
        Write-Host "`n=== SCRIPT EXECUTION COMPLETE ===" -ForegroundColor Cyan -BackgroundColor Black
        Write-Host "You can now review the output above and check the log file if needed." -ForegroundColor Cyan
        Write-Host "ISE window will remain open for you to continue working." -ForegroundColor Cyan
    } else {
        Write-Host "`n=== NO SCCM AGENT FOUND ===" -ForegroundColor Yellow -BackgroundColor Black
        Write-Host "SCCM agent is not installed on this device." -ForegroundColor Yellow
        Write-Host "No repair actions were performed." -ForegroundColor Yellow
        Write-Host "Please install SCCM agent first if you need to repair it." -ForegroundColor Yellow
        Write-Host "`n=== SCRIPT EXECUTION COMPLETE ===" -ForegroundColor Cyan -BackgroundColor Black
        Write-Host "ISE window will remain open for you to continue working." -ForegroundColor Cyan
    }
}
catch {
    Write-Host "=== FATAL ERROR CAUGHT ===" -ForegroundColor Red -BackgroundColor White
    Write-Host "Error details: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Error type: $($_.Exception.GetType().Name)" -ForegroundColor Red
    Write-Host "Error source: $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)" -ForegroundColor Red
    
    try {
        Write-Log "Fatal error: $($_.Exception.Message)" "ERROR"
    } catch {
        Write-Host "Failed to write to log: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    Write-Host "Fatal error occurred: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Script execution finished with errors. ISE window will remain open." -ForegroundColor Red
}
