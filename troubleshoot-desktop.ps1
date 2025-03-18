# Windows System Information Collection Script
# This script finds recently executed programs, installed software, and SCCM deployment history

# Create a timestamp for the log file
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$logPath = "$env:USERPROFILE\Desktop\SystemInfo-$timestamp.log"

# Function to write to both console and log file
function Write-OutputAndLog {
    param([string]$message)
    Write-Output $message
    Add-Content -Path $logPath -Value $message
}

Write-OutputAndLog "=== Windows System Information Collection ==="
Write-OutputAndLog "Date and Time: $(Get-Date)"
Write-OutputAndLog "Computer Name: $env:COMPUTERNAME"
Write-OutputAndLog "User: $env:USERNAME"
Write-OutputAndLog "`n"

# 1. Find .exe files executed in the last hour
Write-OutputAndLog "=== Recently Executed Programs (Last Hour) ==="
try {
    $oneHourAgo = (Get-Date).AddHours(-1)
    
    # Method 1: Check Process Creation Events from Security Log
    Write-OutputAndLog "Method 1: Process Creation Events (Security Log)"
    $securityEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Security'
        Id = 4688  # Process creation
        StartTime = $oneHourAgo
    } -ErrorAction SilentlyContinue
    
    if ($securityEvents) {
        $securityEvents | ForEach-Object {
            $eventXML = [xml]$_.ToXml()
            $processName = $eventXML.Event.EventData.Data | Where-Object { $_.Name -eq 'NewProcessName' } | Select-Object -ExpandProperty '#text'
            if ($processName -and $processName -like "*.exe") {
                $processTime = $_.TimeCreated
                Write-OutputAndLog "  [Security] $processTime - $processName"
            }
        }
    } else {
        Write-OutputAndLog "  No security events found or insufficient permissions."
    }
    
    # Method 2: Check Application Execution from Windows Event Log
    Write-OutputAndLog "`nMethod 2: Application Execution (System/Application Logs)"
    $appEvents = Get-WinEvent -FilterHashtable @{
        LogName = @('Application', 'System')
        StartTime = $oneHourAgo
    } -ErrorAction SilentlyContinue | Where-Object { 
        $_.Message -like "*.exe*" -or $_.ProcessId -ne $null
    }
    
    if ($appEvents) {
        $appEvents | ForEach-Object {
            $eventTime = $_.TimeCreated
            if ($_.Message -match "([a-zA-Z]:\\[^\.]+\.exe)") {
                Write-OutputAndLog "  [Event] $eventTime - $($Matches[1])"
            }
        }
    } else {
        Write-OutputAndLog "  No application execution events found."
    }
    
    # Method 3: Check from Process Start Time
    Write-OutputAndLog "`nMethod 3: Currently Running Processes (started in last hour)"
    $runningProcesses = Get-Process | Where-Object { $_.StartTime -ge $oneHourAgo }
    
    if ($runningProcesses) {
        $runningProcesses | ForEach-Object {
            $processName = $_.Path
            $processTime = $_.StartTime
            if ($processName) {
                Write-OutputAndLog "  [Process] $processTime - $processName"
            }
        }
    } else {
        Write-OutputAndLog "  No currently running processes started in the last hour."
    }
    
    # Method 4: Check from Prefetch Files (requires admin rights)
    Write-OutputAndLog "`nMethod 4: Prefetch Files (requires admin rights)"
    $prefetchPath = "C:\Windows\Prefetch\*.pf"
    
    if (Test-Path $prefetchPath) {
        $recentPrefetch = Get-ChildItem -Path $prefetchPath | Where-Object { $_.LastWriteTime -ge $oneHourAgo }
        
        if ($recentPrefetch) {
            $recentPrefetch | ForEach-Object {
                $prefetchName = $_.Name -replace '\.pf$', ''
                $prefetchTime = $_.LastWriteTime
                Write-OutputAndLog "  [Prefetch] $prefetchTime - $prefetchName"
            }
        } else {
            Write-OutputAndLog "  No prefetch files updated in the last hour."
        }
    } else {
        Write-OutputAndLog "  Prefetch directory not accessible (requires admin rights)."
    }
}
catch {
    Write-OutputAndLog "Error retrieving executed programs: $_"
}
Write-OutputAndLog "`n"

# 2. Software Installation History
Write-OutputAndLog "=== Software Installation History ==="
try {
    # Method 1: Windows Installer Events
    Write-OutputAndLog "Method 1: Windows Installer Events"
    $installerEvents = Get-WinEvent -FilterHashtable @{
        LogName = 'Application'
        ProviderName = 'MsiInstaller'
    } -ErrorAction SilentlyContinue
    
    if ($installerEvents) {
        $installerEvents | Where-Object { $_.Id -eq 1033 -or $_.Id -eq 1034 } | ForEach-Object {
            $eventTime = $_.TimeCreated
            $eventMessage = $_.Message
            $productName = if ($eventMessage -match "Product: ([^-]+)") { $Matches[1].Trim() } else { "Unknown Product" }
            $action = if ($_.Id -eq 1033) { "Installation completed" } else { "Removal completed" }
            Write-OutputAndLog "  [MSI] $eventTime - $action - $productName"
        }
    } else {
        Write-OutputAndLog "  No Windows Installer events found."
    }
    
    # Method 2: Get-Package cmdlet (PowerShell 5.0+)
    Write-OutputAndLog "`nMethod 2: Installed Software (Get-Package)"
    if (Get-Command Get-Package -ErrorAction SilentlyContinue) {
        $packages = Get-Package -ErrorAction SilentlyContinue
        if ($packages) {
            $packages | Sort-Object -Property InstallDate -Descending | ForEach-Object {
                $installDate = if ($_.InstallDate) { $_.InstallDate } else { "Unknown" }
                Write-OutputAndLog "  [Package] $installDate - $($_.Name) ($($_.Version))"
            }
        } else {
            Write-OutputAndLog "  No packages found."
        }
    } else {
        Write-OutputAndLog "  Get-Package cmdlet not available."
    }
    
    # Method 3: Registry Installed Software
    Write-OutputAndLog "`nMethod 3: Registry Installed Software"
    $uninstallKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    $apps = @()
    foreach ($key in $uninstallKeys) {
        if (Test-Path $key) {
            $apps += Get-ItemProperty $key | 
                Where-Object { $_.DisplayName -ne $null } | 
                Select-Object DisplayName, Publisher, DisplayVersion, InstallDate
        }
    }
    
    if ($apps) {
        $apps | Sort-Object -Property InstallDate -Descending | ForEach-Object {
            $installDate = if ($_.InstallDate) { 
                try {
                    # Try to parse YYYYMMDD format
                    [DateTime]::ParseExact($_.InstallDate, "yyyyMMdd", $null).ToString("yyyy-MM-dd")
                } catch {
                    $_.InstallDate
                }
            } else { "Unknown" }
            
            Write-OutputAndLog "  [Registry] $installDate - $($_.DisplayName) ($($_.DisplayVersion))"
        }
    } else {
        Write-OutputAndLog "  No installed software found in registry."
    }
}
catch {
    Write-OutputAndLog "Error retrieving software installation history: $_"
}
Write-OutputAndLog "`n"

# 3. SCCM Deployment History
Write-OutputAndLog "=== SCCM Deployment History ==="
try {
    # First, check if ConfigMgr client is installed
    $ccmExecPath = "C:\Windows\CCM\CcmExec.exe"
    if (Test-Path $ccmExecPath) {
        Write-OutputAndLog "SCCM Client is installed. Retrieving deployment history..."
        
        # Method 1: WMI Query for Software Distribution
        Write-OutputAndLog "Method 1: WMI Query for Software Distribution"
        $deployments = Get-WmiObject -Namespace "root\ccm\SoftMgmtAgent" -Class CCM_ExecutionRequestEx -ErrorAction SilentlyContinue
        
        if ($deployments) {
            $deployments | Sort-Object -Property StartTime -Descending | ForEach-Object {
                $startTime = if ($_.StartTime) { [Management.ManagementDateTimeConverter]::ToDateTime($_.StartTime) } else { "Unknown" }
                $endTime = if ($_.EndTime) { [Management.ManagementDateTimeConverter]::ToDateTime($_.EndTime) } else { "Unknown" }
                $status = switch ($_.State) {
                    0 { "Unknown" }
                    1 { "Pending" }
                    2 { "Executing" }
                    3 { "Completed" }
                    4 { "Failed" }
                    5 { "Canceled" }
                    default { "Unknown" }
                }
                
                Write-OutputAndLog "  [SCCM] Start: $startTime, End: $endTime - Status: $status - $($_.ClientID)"
            }
        } else {
            Write-OutputAndLog "  No SCCM deployments found via WMI."
        }
        
        # Method 2: SCCM Update History
        Write-OutputAndLog "`nMethod 2: SCCM Update History"
        $updates = Get-WmiObject -Namespace "root\ccm\SoftwareUpdates\UpdatesStore" -Class CCM_UpdateStatus -ErrorAction SilentlyContinue
        
        if ($updates) {
            $updates | Sort-Object -Property Date -Descending | ForEach-Object {
                $updateDate = if ($_.Date) { [Management.ManagementDateTimeConverter]::ToDateTime($_.Date) } else { "Unknown" }
                $status = switch ($_.Status) {
                    0 { "Unknown" }
                    1 { "Detected" }
                    2 { "Presented" }
                    3 { "Downloaded" }
                    4 { "Installed" }
                    5 { "Failed" }
                    6 { "WaitReboot" }
                    7 { "PendingSoftReboot" }
                    default { "Unknown" }
                }
                
                Write-OutputAndLog "  [Update] $updateDate - Status: $status - $($_.Title)"
            }
        } else {
            Write-OutputAndLog "  No SCCM update history found."
        }
        
        # Method 3: SCCM Application History
        Write-OutputAndLog "`nMethod 3: SCCM Application History from WMI"
        $appHistory = Get-WmiObject -Namespace "root\ccm\ClientSDK" -Class CCM_AppDeploymentType -ErrorAction SilentlyContinue
        
        if ($appHistory) {
            $appHistory | Sort-Object -Property LastInstallTime -Descending | ForEach-Object {
                $installTime = if ($_.LastInstallTime) { [Management.ManagementDateTimeConverter]::ToDateTime($_.LastInstallTime) } else { "Unknown" }
                $appName = $_.AppName
                $state = switch ($_.InstallState) {
                    0 { "Unknown" }
                    1 { "Installed" }
                    2 { "Not Installed" }
                    3 { "Pending Install" }
                    4 { "Failed" }
                    default { "Unknown" }
                }
                
                Write-OutputAndLog "  [App] $installTime - Status: $state - $appName"
            }
        } else {
            Write-OutputAndLog "  No SCCM application history found."
        }
        
        # Method 4: Check SCCM Log Files
        Write-OutputAndLog "`nMethod 4: SCCM Log Files"
        $sccmLogPath = "C:\Windows\CCM\Logs"
        
        if (Test-Path $sccmLogPath) {
            $recentLogs = Get-ChildItem -Path $sccmLogPath -Filter "*.log" | Sort-Object LastWriteTime -Descending | Select-Object -First 5
            
            foreach ($log in $recentLogs) {
                Write-OutputAndLog "  Log File: $($log.Name) - Last Modified: $($log.LastWriteTime)"
                $logContent = Get-Content -Path $log.FullName -Tail 20
                $deploymentMatches = $logContent | Select-String -Pattern "Deployment|deployment|install|Install|update|Update" -Context 0,1
                
                foreach ($match in $deploymentMatches) {
                    Write-OutputAndLog "    $($match.Line)"
                }
            }
        } else {
            Write-OutputAndLog "  SCCM log directory not found."
        }
    } else {
        Write-OutputAndLog "SCCM Client does not appear to be installed on this system."
    }
}
catch {
    Write-OutputAndLog "Error retrieving SCCM deployment history: $_"
}

# Summary
Write-OutputAndLog "`n=== Summary ==="
Write-OutputAndLog "Script completed at $(Get-Date)"
Write-OutputAndLog "Log file saved to: $logPath"
Write-OutputAndLog "Note: Some operations may require administrative privileges for complete results."

Write-Output "`nScript execution completed. Results have been saved to: $logPath"