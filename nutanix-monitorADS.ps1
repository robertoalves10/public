#Requires -Version 5.1
<#
.SYNOPSIS
    Monitors Nutanix VMs for host changes through Prism Central API.

.DESCRIPTION
    This script connects to Nutanix Prism Central REST API, retrieves VM information,
    and monitors for host changes. It runs in a loop at specified intervals and
    logs any changes to a CSV file.

.PARAMETER PrismCentralAddress
    The address of the Nutanix Prism Central server.

.PARAMETER OutputCsvPath
    Path to the CSV file where results will be saved.

.PARAMETER DataRetrievalIntervalSeconds
    How often to query the API (in seconds). Default is 60 seconds (1 minute).

.PARAMETER MaxScriptRuntimeMinutes
    Maximum time for the script to run (in minutes). Default is 60 minutes.

.PARAMETER MaxAttemptsWhenError
    Maximum number of retry attempts when encountering API errors. Default is 3.

.EXAMPLE
    .\NutanixVMMonitor.ps1 -PrismCentralAddress "prism.example.com" -OutputCsvPath "vm_changes.csv" -DataRetrievalIntervalSeconds 60 -MaxScriptRuntimeMinutes 120 -MaxAttemptsWhenError 5
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$PrismCentralAddress,
    
    [Parameter(Mandatory = $true)]
    [string]$OutputCsvPath,
    
    [Parameter(Mandatory = $false)]
    [int]$DataRetrievalIntervalSeconds = 60,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxScriptRuntimeMinutes = 60,
    
    [Parameter(Mandatory = $false)]
    [int]$MaxAttemptsWhenError = 3
)

#region Functions

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
            $credentials = Get-Credential -Message "Enter credentials for Nutanix Prism Central"
            
            # Set up connection details
            $connectionInfo = @{
                BaseUrl = "https://{0}:9440/api/nutanix/v3" -f $PrismCentralAddress
                Credentials = $credentials
                Headers = @{
                    "Content-Type" = "application/json"
                    "Accept" = "application/json"
                }
            }
            
            Write-Verbose -Message "Connection initialized for Nutanix Prism Central at $PrismCentralAddress"
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
                    Credential = $ConnectionInfo.Credentials
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
                    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy
                    $response = Invoke-RestMethod @params
                }
                
                $success = $true
                $result = $response
                Write-Verbose -Message "API request to $Endpoint successful"
            }
            catch {
                $errorMessage = "Attempt {0}/{1}: API request to {2} failed: {3}" -f $attemptCount, $MaxAttempts, $Endpoint, $_.Exception.Message
                Write-Warning -Message $errorMessage
                
                if ($attemptCount -ge $MaxAttempts) {
                    Write-Error -Message "Maximum retry attempts reached for API request to $Endpoint"
                    throw $_
                }
                
                # Wait before retrying with exponential backoff
                $backoffSeconds = [math]::Pow(2, $attemptCount)
                Write-Verbose -Message "Waiting {0} seconds before retry..." -f $backoffSeconds
                Start-Sleep -Seconds $backoffSeconds
            }
        }
        
        return $result
    }
}

function Get-NutanixVmList {
    <#
    .SYNOPSIS
        Retrieves the list of VMs from Nutanix Prism Central.
    .DESCRIPTION
        Queries the Nutanix API to get information about all VMs including their host assignments.
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
            # Request body for VM list query
            $body = @{
                kind = "vm"
                length = 500  # Adjust based on your environment size
                offset = 0
                filter = ""
            } | ConvertTo-Json
            
            # Get VM list
            $vmListResponse = Invoke-NutanixApiRequest -ConnectionInfo $ConnectionInfo -Endpoint "vms/list" -Body $body -MaxAttempts $MaxAttempts
            
            # Process VM list to extract required information
            $vmList = @()
            foreach ($vm in $vmListResponse.entities) {
                # Get VM host information
                $hostUuid = $vm.status.resources.host_reference.uuid
                $hostName = $vm.status.resources.host_reference.name
                
                # Get cluster information
                $clusterUuid = $vm.status.cluster_reference.uuid
                $clusterName = $vm.status.cluster_reference.name
                
                # Get CPU usage
                $cpuUsage = 0
                if ($vm.status.resources.PSObject.Properties.Name -contains "usage_stats" -and 
                    $vm.status.resources.usage_stats.PSObject.Properties.Name -contains "cpu_usage_ppm") {
                    $cpuUsage = [math]::Round(($vm.status.resources.usage_stats.cpu_usage_ppm / 10000), 2)
                }
                
                # Create VM object
                $vmInfo = [PSCustomObject]@{
                    VMName = $vm.status.name
                    VMCPU_Usage = $cpuUsage
                    HostName = $hostName
                    HostUuid = $hostUuid
                    ClusterName = $clusterName
                    ClusterUuid = $clusterUuid
                    PrismCentral = $PrismCentralAddress
                }
                
                $vmList += $vmInfo
            }
            
            return $vmList
        }
        catch {
            $errorMessage = "Failed to retrieve VM list: {0}" -f $_.Exception.Message
            Write-Error -Message $errorMessage
            throw $errorMessage
        }
    }
}

function Compare-VMHostChanges {
    <#
    .SYNOPSIS
        Compares current VM host assignments with previous results.
    .DESCRIPTION
        Identifies VMs that have moved to different hosts between two data collections.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$CurrentVMs,
        
        [Parameter(Mandatory = $true)]
        [array]$PreviousVMs
    )
    
    process {
        try {
            $changes = @()
            $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            
            foreach ($currentVM in $CurrentVMs) {
                $previousVM = $PreviousVMs | Where-Object { $_.VMName -eq $currentVM.VMName }
                
                if ($previousVM -and $currentVM.HostName -ne $previousVM.HostName) {
                    $change = [PSCustomObject]@{
                        Timestamp = $timestamp
                        VMName = $currentVM.VMName
                        VMCPU_Usage = $currentVM.VMCPU_Usage
                        HostName_New = $currentVM.HostName
                        HostName_Previous = $previousVM.HostName
                        PrismCentral = $currentVM.PrismCentral
                        ClusterName = $currentVM.ClusterName
                    }
                    
                    $changes += $change
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

function Export-ChangesToCsv {
    <#
    .SYNOPSIS
        Exports VM host changes to a CSV file.
    .DESCRIPTION
        Appends detected host changes to the specified CSV file.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Changes,
        
        [Parameter(Mandatory = $true)]
        [string]$CsvPath
    )
    
    process {
        try {
            if ($Changes.Count -gt 0) {
                # Create directory if it doesn't exist
                $directory = Split-Path -Path $CsvPath -Parent
                if (-not [string]::IsNullOrEmpty($directory) -and -not (Test-Path -Path $directory)) {
                    New-Item -Path $directory -ItemType Directory -Force | Out-Null
                }
                
                # Check if file exists to determine if header is needed
                $fileExists = Test-Path -Path $CsvPath
                
                # Export to CSV
                $Changes | Export-Csv -Path $CsvPath -NoTypeInformation -Append:$fileExists
                
                Write-Verbose -Message "{0} VM host changes exported to {1}" -f $Changes.Count, $CsvPath
            }
            else {
                Write-Verbose -Message "No VM host changes to export"
            }
        }
        catch {
            $errorMessage = "Failed to export changes to CSV: {0}" -f $_.Exception.Message
            Write-Error -Message $errorMessage
            throw $errorMessage
        }
    }
}

function Start-VMHostMonitoring {
    <#
    .SYNOPSIS
        Main function that orchestrates the VM host monitoring.
    .DESCRIPTION
        Runs monitoring loop at specified intervals to detect VM host changes.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$ConnectionInfo,
        
        [Parameter(Mandatory = $true)]
        [string]$OutputCsvPath,
        
        [Parameter(Mandatory = $false)]
        [int]$IntervalSeconds = 60,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxRuntimeMinutes = 60,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 3
    )
    
    process {
        try {
            Write-Host "Starting VM host monitoring..."
            Write-Host "Press Ctrl+C to stop the script at any time."
            
            # Calculate end time
            $endTime = (Get-Date).AddMinutes($MaxRuntimeMinutes)
            
            # Initialize previous VM list
            $previousVMs = Get-NutanixVmList -ConnectionInfo $ConnectionInfo -MaxAttempts $MaxAttempts
            Write-Host ("{0} - Initial VM data collected. Found {1} VMs." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $previousVMs.Count)
            
            # Monitoring loop
            while ((Get-Date) -lt $endTime) {
                try {
                    # Wait for the specified interval
                    Start-Sleep -Seconds $IntervalSeconds
                    
                    # Get current VM list
                    $currentVMs = Get-NutanixVmList -ConnectionInfo $ConnectionInfo -MaxAttempts $MaxAttempts
                    Write-Host ("{0} - VM data collected. Found {1} VMs." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $currentVMs.Count)
                    
                    # Compare and find changes
                    $changes = Compare-VMHostChanges -CurrentVMs $currentVMs -PreviousVMs $previousVMs
                    
                    # Report and export changes
                    if ($changes.Count -gt 0) {
                        Write-Host ("{0} - Detected {1} VM host changes:" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $changes.Count) -ForegroundColor Yellow
                        
                        foreach ($change in $changes) {
                            Write-Host ("  VM: {0} moved from {1} to {2}" -f $change.VMName, $change.HostName_Previous, $change.HostName_New) -ForegroundColor Yellow
                        }
                        
                        # Export changes to CSV
                        Export-ChangesToCsv -Changes $changes -CsvPath $OutputCsvPath
                    }
                    else {
                        Write-Host ("{0} - No VM host changes detected." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
                    }
                    
                    # Update previous VM list for next iteration
                    $previousVMs = $currentVMs
                }
                catch {
                    $errorMessage = "Error during monitoring iteration: {0}" -f $_.Exception.Message
                    Write-Warning -Message $errorMessage
                    # Continue to next iteration despite errors
                }
            }
            
            Write-Host ("{0} - Maximum runtime of {1} minutes reached. Monitoring stopped." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $MaxRuntimeMinutes)
        }
        catch {
            $errorMessage = "VM host monitoring failed: {0}" -f $_.Exception.Message
            Write-Error -Message $errorMessage
            throw $errorMessage
        }
    }
}

#endregion

#region Main Script

try {
    # Initialize connection to Nutanix Prism Central
    $connectionInfo = Initialize-NutanixConnection -PrismCentralAddress $PrismCentralAddress
    
    # Start monitoring
    Start-VMHostMonitoring -ConnectionInfo $connectionInfo `
                          -OutputCsvPath $OutputCsvPath `
                          -IntervalSeconds $DataRetrievalIntervalSeconds `
                          -MaxRuntimeMinutes $MaxScriptRuntimeMinutes `
                          -MaxAttempts $MaxAttemptsWhenError
}
catch {
    Write-Error -Message "Script execution failed: $($_.Exception.Message)"
    exit 1
}

#endregion