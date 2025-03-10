<#
.SYNOPSIS
    Monitors VM migrations between Nutanix hosts using Prism Central API.
.DESCRIPTION
    This script connects to Nutanix Prism Central, retrieves VM and host information,
    tracks VM migrations between hosts, and reports changes to the console and a CSV file.
.PARAMETER PrismCentralAddress
    The address of the Nutanix Prism Central instance.
.PARAMETER CsvFilePath
    The path where the CSV file will be saved.
.PARAMETER DataRetrievalInterval
    The interval in minutes between data retrievals. Default is 1 minute.
.PARAMETER MaxScriptRuntimeMin
    The maximum time in minutes the script should run. Default is 60 minutes.
.PARAMETER MaxAttemptsWhenError
    The maximum number of retry attempts when an API error occurs. Default is 3.
.EXAMPLE
    .\NutanixVmMigrationMonitor.ps1 -PrismCentralAddress "prism.example.com" -CsvFilePath "vm_migrations.csv" -DataRetrievalInterval 1 -MaxScriptRuntimeMin 60 -MaxAttemptsWhenError 3
.NOTES
    Requires PowerShell 5.1 or 7.x
    Compatible with Nutanix Prism Central v3 API
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$PrismCentralAddress,
    
    [Parameter(Mandatory = $true)]
    [string]$CsvFilePath,
    
    [Parameter(Mandatory = $false)]
    [int]$DataRetrievalInterval = 1,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxScriptRuntimeMin = 60,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxAttemptsWhenError = 3
)


function Initialize-NutanixConnection {
    <#
    .SYNOPSIS
        Initializes connection parameters for Nutanix Prism Central API.
    .DESCRIPTION
        Sets up connection details including API endpoint URLs and credentials.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PrismCentralAddress
    )
    
    process {
        try {
            # Configure TLS 1.2
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            
            # Get credentials
            Write-Host "Enter credentials for Nutanix Prism Central"
            $credentials = Get-Credential
            
            # Create auth header
            $authHeader = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $credentials.UserName, $credentials.GetNetworkCredential().Password)))
            
            # Set up connection details
            $connectionInfo = @{
                BaseUrl = "https://{0}:9440/api/nutanix/v3" -f $PrismCentralAddress
                Headers = @{
                    "Content-Type" = "application/json"
                    "Accept" = "application/json"
                    "Authorization" = "Basic $authHeader"
                }
            }
            
            Write-Verbose -Message ("Connection initialized for Nutanix Prism Central at {0}" -f $PrismCentralAddress)
            return $connectionInfo
        }
        catch {
            $errorMessage = "Failed to initialize connection: {0}" -f $_.Exception.Message
            Write-Error -Message $errorMessage
            throw $errorMessage
        }
    }
}

function Invoke-NutanixApiRequest {
    <#
    .SYNOPSIS
        Executes a REST API request to Nutanix Prism Central.
    .DESCRIPTION
        Makes an HTTP request to the Nutanix API with error handling and retry logic.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$ConnectionInfo,
        
        [Parameter(Mandatory = $true)]
        [string]$Endpoint,
        
        [Parameter(Mandatory = $false)]
        [Microsoft.PowerShell.Commands.WebRequestMethod]$Method = "POST",
        
        [Parameter(Mandatory = $false)]
        [string]$Body = $null,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 3
    )
    
    process {
        $uri = "{0}/{1}" -f $ConnectionInfo.BaseUrl, $Endpoint
        $attemptCount = 0
        $success = $false
        $result = $null
        
        while (-not $success -and $attemptCount -lt $MaxAttempts) {
            $attemptCount++
            try {
                $params = @{
                    Uri = $uri
                    Method = $Method
                    Headers = $ConnectionInfo.Headers
                    ContentType = "application/json"
                    UseBasicParsing = $true
                    ErrorAction = "Stop"
                }
                
                if (-not [string]::IsNullOrEmpty($Body)) {
                    $params.Add("Body", $Body)
                }
                
                # Use different syntax based on PowerShell version
                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $params.Add("SkipCertificateCheck", $true)
                    $response = Invoke-RestMethod @params
                }
                else {
                    # Ignore certificate validation for PowerShell 5.1
                    if (-not ([System.Management.Automation.PSTypeName]'TrustAllCertsPolicy').Type) {
                        Add-Type -TypeDefinition @"
                        using System.Net;
                        using System.Security.Cryptography.X509Certificates;
                        public class TrustAllCertsPolicy : ICertificatePolicy {
                            public bool CheckValidationResult(
                                ServicePoint srvPoint, X509Certificate certificate,
                                WebRequest request, int certificateProblem) {
                                return true;
                            }
                        }
"@
                    }
                    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                    $response = Invoke-RestMethod @params
                }
                
                $success = $true
                $result = $response
                Write-Verbose -Message ("API request to {0} successful" -f $Endpoint)
            }
            catch {
                $errorMessage = "Attempt {0}/{1}: API request to {2} failed: {3}" -f $attemptCount, $MaxAttempts, $Endpoint, $_.Exception.Message
                Write-Warning -Message $errorMessage
                
                if ($attemptCount -ge $MaxAttempts) {
                    Write-Error -Message ("Maximum retry attempts reached for API request to {0}" -f $Endpoint)
                    throw $_
                }
                
                # Wait before retrying with exponential backoff
                $backoffSeconds = [math]::Pow(2, $attemptCount)
                Write-Verbose -Message ("Waiting {0} seconds before retry..." -f $backoffSeconds)
                Start-Sleep -Seconds $backoffSeconds
            }
        }
        
        return $result
    }
}

function Get-NutanixVmDetails {
    <#
    .SYNOPSIS
        Retrieves detailed information about VMs from Nutanix Prism Central.
    .DESCRIPTION
        Gets a list of all VMs with their associated hosts and metrics using the Nutanix API v3.
        Handles pagination to retrieve all VMs regardless of their count.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$ConnectionInfo,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 3
    )
    
    process {
        try {
            $allVms = [System.Collections.ArrayList]::new()
            $offset = 0
            $length = 500 # Maximum number of VMs per page
            $hasMoreResults = $true
            
            # Loop for pagination
            while ($hasMoreResults) {
                $body = @{
                    kind = "vm"
                    offset = $offset
                    length = $length
                    sort_order = "ASCENDING"
                    sort_attribute = "name"
                } | ConvertTo-Json
                
                $response = Invoke-NutanixApiRequest -ConnectionInfo $ConnectionInfo -Endpoint "vms/list" -Method "POST" -Body $body -MaxAttempts $MaxAttempts
                
                if ($response.entities.Length -eq 0) {
                    $hasMoreResults = $false
                }
                else {
                    # Process each VM to get its details and metrics
                    foreach ($vm in $response.entities) {
                        $vmDetails = [PSCustomObject]@{
                            VmUuid = $vm.metadata.uuid
                            VmName = $vm.spec.name
                            ClusterUuid = $vm.spec.cluster_reference.uuid
                            ClusterName = $vm.spec.cluster_reference.name
                            HostUuid = $vm.status.resources.host_reference.uuid
                            HostName = $vm.status.resources.host_reference.name
                            CpuUsage = $null # Will be populated from stats API
                            PrismCentral = $PrismCentralAddress
                        }
                        
                        # Get VM CPU metrics
                        $vmDetails.CpuUsage = Get-VmCpuUsage -ConnectionInfo $ConnectionInfo -VmUuid $vmDetails.VmUuid -MaxAttempts $MaxAttempts
                        
                        [void]$allVms.Add($vmDetails)
                    }
                    
                    $offset += $length
                    Write-Verbose -Message ("Retrieved {0} VMs" -f $allVms.Count)
                }
            }
            
            return $allVms
        }
        catch {
            $errorMessage = "Failed to retrieve VM details: {0}" -f $_.Exception.Message
            Write-Error -Message $errorMessage
            throw $errorMessage
        }
    }
}

function Get-VmCpuUsage {
    <#
    .SYNOPSIS
        Gets the current CPU usage for a specific VM.
    .DESCRIPTION
        Retrieves CPU usage metrics for a VM from the Nutanix metrics API.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$ConnectionInfo,
        
        [Parameter(Mandatory = $true)]
        [string]$VmUuid,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 3
    )
    
    process {
        try {
            $body = @{
                entity_uuid = $VmUuid
                metric_query = @{
                    metric_group_name = "vm_stat"
                    metric_names = @("hypervisor_cpu_usage_ppm")
                    interval_in_secs = 60
                    count = 1
                }
            } | ConvertTo-Json -Depth 4
            
            $response = Invoke-NutanixApiRequest -ConnectionInfo $ConnectionInfo -Endpoint "metrics/query" -Method "POST" -Body $body -MaxAttempts $MaxAttempts
            
            # Extract CPU usage percentage (converting from ppm)
            if ($response.group_results -and $response.group_results.entity_results -and $response.group_results.entity_results[0].data[0].values) {
                $cpuUsagePpm = $response.group_results.entity_results[0].data[0].values[0].values[0]
                return [math]::Round($cpuUsagePpm / 10000, 2)  # Convert from ppm to percentage and round to 2 decimal places
            }
            
            return $null
        }
        catch {
            Write-Warning -Message ("Failed to get CPU usage for VM {0}: {1}" -f $VmUuid, $_.Exception.Message)
            return $null
        }
    }
}

function Compare-VmHostChanges {
    <#
    .SYNOPSIS
        Compares current VM host assignments with previous data.
    .DESCRIPTION
        Identifies VMs that have moved between hosts by comparing current and previous data.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$CurrentVmData,
        
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$PreviousVmData
    )
    
    process {
        try {
            $changes = [System.Collections.ArrayList]::new()
            
            foreach ($currentVm in $CurrentVmData) {
                $previousVm = $PreviousVmData | Where-Object { $_.VmUuid -eq $currentVm.VmUuid }
                
                if ($previousVm -and $previousVm.HostUuid -ne $currentVm.HostUuid) {
                    $change = [PSCustomObject]@{
                        Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                        VmName = $currentVm.VmName
                        VmUuid = $currentVm.VmUuid
                        VmCpuUsage = $currentVm.CpuUsage
                        HostnameNew = $currentVm.HostName
                        HostUuidNew = $currentVm.HostUuid
                        HostnamePrevious = $previousVm.HostName
                        HostUuidPrevious = $previousVm.HostUuid
                        PrismCentral = $currentVm.PrismCentral
                        ClusterName = $currentVm.ClusterName
                    }
                    
                    [void]$changes.Add($change)
                }
            }
            
            return $changes
        }
        catch {
            $errorMessage = "Failed to compare VM host changes: {0}" -f $_.Exception.Message
            Write-Error -Message $errorMessage
            throw $errorMessage
        }
    }
}

function Export-VmChangesToCsv {
    <#
    .SYNOPSIS
        Exports VM host change data to a CSV file.
    .DESCRIPTION
        Appends detected VM host changes to the specified CSV file.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$Changes,
        
        [Parameter(Mandatory = $true)]
        [string]$CsvFilePath
    )
    
    process {
        try {
            if ($Changes.Count -gt 0) {
                # Define CSV format (select required fields only)
                $csvData = $Changes | Select-Object Timestamp, VmName, VmCpuUsage, HostnameNew, HostnamePrevious, PrismCentral, ClusterName
                
                # Check if file exists, if not create with headers
                if (-not (Test-Path -Path $CsvFilePath)) {
                    $csvData | Export-Csv -Path $CsvFilePath -NoTypeInformation
                    Write-Verbose -Message ("Created new CSV file at {0}" -f $CsvFilePath)
                }
                else {
                    # Append to existing file without headers
                    $csvData | Export-Csv -Path $CsvFilePath -NoTypeInformation -Append
                    Write-Verbose -Message ("Appended {0} changes to CSV file {1}" -f $Changes.Count, $CsvFilePath)
                }
            }
        }
        catch {
            $errorMessage = "Failed to export changes to CSV: {0}" -f $_.Exception.Message
            Write-Error -Message $errorMessage
            throw $errorMessage
        }
    }
}

function Format-OutputMessage {
    <#
    .SYNOPSIS
        Formats change details for console output.
    .DESCRIPTION
        Creates a formatted string for console output showing VM migration details.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Change
    )
    
    process {
        $formattedMessage = @"
[{0}] VM Migration Detected:
  VM Name: {1}
  CPU Usage: {2}%
  Previous Host: {3}
  New Host: {4}
  Cluster: {5}
  Prism Central: {6}
"@ -f $Change.Timestamp, $Change.VmName, $Change.VmCpuUsage, $Change.HostnamePrevious, $Change.HostnameNew, $Change.ClusterName, $Change.PrismCentral
        
        return $formattedMessage
    }
}

function Start-VmMigrationMonitor {
    <#
    .SYNOPSIS
        Main function to monitor VM migrations over time.
    .DESCRIPTION
        Runs a continuous monitoring loop to detect and report VM migrations between hosts.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$ConnectionInfo,
        
        [Parameter(Mandatory = $true)]
        [string]$CsvFilePath,
        
        [Parameter(Mandatory = $true)]
        [int]$DataRetrievalInterval,
        
        [Parameter(Mandatory = $true)]
        [int]$MaxScriptRuntimeMin,
        
        [Parameter(Mandatory = $true)]
        [int]$MaxAttemptsWhenError
    )
    
    process {
        try {
            $startTime = Get-Date
            $endTime = $startTime.AddMinutes($MaxScriptRuntimeMin)
            $previousVmData = $null
            $iterationCount = 0
            
            Write-Host ("Starting VM migration monitoring for {0} minutes..." -f $MaxScriptRuntimeMin)
            Write-Host ("Data will be saved to {0}" -f $CsvFilePath)
            
            while ((Get-Date) -lt $endTime) {
                $iterationCount++
                Write-Host ("----- Iteration {0} | {1} -----" -f $iterationCount, (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
                
                # Get current VM data
                $currentVmData = Get-NutanixVmDetails -ConnectionInfo $ConnectionInfo -MaxAttempts $MaxAttemptsWhenError
                Write-Host ("Retrieved data for {0} VMs" -f $currentVmData.Count)
                
                # Skip comparison on first run
                if ($null -ne $previousVmData) {
                    # Compare with previous data to detect changes
                    $changes = Compare-VmHostChanges -CurrentVmData $currentVmData -PreviousVmData $previousVmData
                    
                    if ($changes.Count -gt 0) {
                        Write-Host ("{0} VM migrations detected" -f $changes.Count) -ForegroundColor Yellow
                        
                        # Output changes to console
                        foreach ($change in $changes) {
                            $formattedMessage = Format-OutputMessage -Change $change
                            Write-Host $formattedMessage -ForegroundColor Green
                        }
                        
                        # Export changes to CSV
                        Export-VmChangesToCsv -Changes $changes -CsvFilePath $CsvFilePath
                    }
                    else {
                        Write-Host "No VM migrations detected in this interval" -ForegroundColor Cyan
                    }
                }
                else {
                    Write-Host "First run - establishing baseline data" -ForegroundColor Cyan
                }
                
                # Store current data for next comparison
                $previousVmData = $currentVmData
                
                # Wait for next interval if not last iteration
                $remainingTime = $endTime - (Get-Date)
                if ($remainingTime.TotalMinutes -gt 0) {
                    $waitTime = [Math]::Min($DataRetrievalInterval * 60, $remainingTime.TotalSeconds)
                    Write-Host ("Waiting {0} seconds until next check..." -f $waitTime)
                    Start-Sleep -Seconds $waitTime
                }
            }
            
            Write-Host "Maximum script runtime reached. Monitoring complete."
        }
        catch {
            $errorMessage = "VM migration monitoring failed: {0}" -f $_.Exception.Message
            Write-Error -Message $errorMessage
            throw $errorMessage
        }
    }
}

function Main {
    <#
    .SYNOPSIS
        Main entry point for the script.
    .DESCRIPTION
        Initializes the connection and starts the monitoring process.
    #>
    [CmdletBinding()]
    param ()
    
    process {
        try {
            # Verify parameters
            if ($DataRetrievalInterval -lt 1) {
                throw "Data retrieval interval must be at least 1 minute"
            }
            
            if ($MaxScriptRuntimeMin -lt 1) {
                throw "Maximum script runtime must be at least 1 minute"
            }
            
            # Initialize connection to Nutanix Prism Central
            Write-Host ("Connecting to Nutanix Prism Central at {0}..." -f $PrismCentralAddress)
            $connectionInfo = Initialize-NutanixConnection -PrismCentralAddress $PrismCentralAddress
            
            # Start monitoring
            Start-VmMigrationMonitor -ConnectionInfo $connectionInfo -CsvFilePath $CsvFilePath -DataRetrievalInterval $DataRetrievalInterval -MaxScriptRuntimeMin $MaxScriptRuntimeMin -MaxAttemptsWhenError $MaxAttemptsWhenError
        }
        catch {
            $errorMessage = "Script execution failed: {0}" -f $_.Exception.Message
            Write-Error -Message $errorMessage
            exit 1
        }
    }
}

# Execute main function
Main