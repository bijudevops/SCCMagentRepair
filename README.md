# SCCM Agent Repair Script

A comprehensive PowerShell script designed to automatically repair broken SCCM (System Center Configuration Manager) agents on Windows devices.

## Features

- **Automated Repair Process**: No user intervention required
- **Progress Tracking**: Visual progress bars for each step
- **Comprehensive Logging**: Detailed logging to `C:\SCCMREPAIR\sccm-repair.timestamp.log`
- **Error Handling**: Robust error handling with graceful fallbacks
- **Administrative Privileges**: Automatically checks for required permissions

## Prerequisites

- Windows PowerShell 5.1 or higher
- Administrative privileges
- SCCM agent must be installed on the target device

## What the Script Does

### Step 1: SCCM Installation Check & CCMRepair
- Verifies SCCM agent is installed
- Runs the CCMRepair tool if available
- Checks and displays CCMRepair logs from `C:\Windows\CCM\Logs\ccmrepair.log`

### Step 2: Policy Reset & Cache Clearing
- Stops the CCMExec service
- Deletes machine and user policy cache from registry
- Restarts CCMExec service
- Triggers immediate policy retrieval

### Step 3: Client Registration Reset
- Runs `ccmsetup.exe RESETKEYINFORMATION=TRUE /logon`
- Forces new registration handshake with Management Point
- Keeps client installation intact

### Step 4: WMI Namespace Repair
- Verifies WMI repository integrity
- If failing, stops CCMExec service
- Resets WMI repository using `winmgmt /resetrepository`
- Restarts CCMExec service

### Step 5: CCM Cache Clearing
- Clears CCM cache directories
- Removes temporary files
- Restarts services as needed

### Final Validation
- Comprehensive health check of SCCM components
- Service status verification
- WMI connectivity testing
- Registry key validation

## Usage

### Basic Usage
```powershell
.\SCCM-Repair.ps1
```

### Custom Log Path
```powershell
.\SCCM-Repair.ps1 -LogPath "D:\CustomLogs"
```

### Running from Command Line
```cmd
powershell.exe -ExecutionPolicy Bypass -File "SCCM-Repair.ps1"
```

### Running from Task Scheduler
- Create a new task
- Set action to: `powershell.exe`
- Arguments: `-ExecutionPolicy Bypass -File "C:\Path\To\SCCM-Repair.ps1"`
- Run with highest privileges

## Output

### Console Output
- Real-time progress updates
- Step-by-step status information
- Success/failure indicators

### Log File
- Location: `C:\SCCMREPAIR\sccm-repair.YYYYMMDD-HHMMSS.log`
- Timestamped entries
- Detailed error information
- Success/failure status for each step

## Exit Codes

- **0**: Script completed successfully
- **1**: Script completed with errors or failed

## Safety Features

- **Service Management**: Properly stops/starts services with appropriate delays
- **Registry Operations**: Uses `-ErrorAction SilentlyContinue` for non-critical operations
- **Process Verification**: Confirms successful operations before proceeding
- **Rollback Capability**: Individual step failures don't prevent subsequent steps

## Troubleshooting

### Common Issues

1. **Access Denied**: Ensure script is run as Administrator
2. **SCCM Not Found**: Verify SCCM agent is installed
3. **Service Won't Start**: Check Windows Event Logs for service errors
4. **WMI Issues**: May require manual WMI repository rebuild

### Manual Recovery

If the script fails, check:
- Windows Event Logs
- SCCM client logs in `C:\Windows\CCM\Logs\`
- Script log file for detailed error information

## Version History

- **v1.0**: Initial release with comprehensive repair functionality

## Support

This script is designed for IT administrators familiar with SCCM. For issues:
1. Check the log file for detailed error information
2. Verify SCCM agent installation status
3. Review Windows Event Logs
4. Consult SCCM documentation for manual recovery procedures

## Disclaimer

This script modifies system services and registry keys. Always test in a non-production environment first and ensure you have proper backups before running on production systems.
