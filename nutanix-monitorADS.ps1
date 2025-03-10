<#
.SYNOPSIS
    Monitors Nutanix VM host changes and logs them to a CSV file.
.DESCRIPTION
    This script connects to Nutanix Prism Central REST API, retrieves VMs and their hosts,
    runs in a loop to detect host changes, and logs the changes to a CSV file.
.PARAMETER PrismCentralAddress
    The address of Nutanix Prism Central.
.PARAMETER CsvFilePath
    Path to the CSV file for logging VM host changes.
.PARAMETER DataRetrievalInterval
    Interval in minutes between data retrieval cycles. Default is 1 minute.
.PARAMETER MaxScriptRuntimeMin
    Maximum runtime of the script in minutes. Default is 60 minutes.
.PARAMETER MaxAttemptsWhenError
    Maximum number of retry attempts when API calls fail. Default is 3.
.NOTES
    Author: Script generated per requirements
    Date: March 10, 2025
    Requirements: PowerShell 5.1 or 7, connectivity to Nutanix Prism Central
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

# Import functions (assumed to be in the same file for this example)
# In a real-world scenario, these would be in a separate module

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

function Get-FormattedTimestamp {
    <#
    .SYNOPSIS
        Returns the current timestamp in a standardized format.
    .DESCRIPTION
        Provides a consistent timestamp format for logging and display.
    #>
    [CmdletBinding()]
    param()
    
    process {
        return Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    }
}

function Write-TimestampedMessage {
    <#
    .SYNOPSIS
        Writes a message to the console with a timestamp prefix.
    .DESCRIPTION
        Prepends a timestamp to any message output to the console.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,
        
        [Parameter(Mandatory = $false)]
        [System.ConsoleColor]$ForegroundColor
    )
    
    process {
        $timestamp = Get-FormattedTimestamp
        $formattedMessage = "[{0}] {1}" -f $timestamp, $Message
        
        if ($PSBoundParameters.ContainsKey('ForegroundColor')) {
            Write-Host $formattedMessage -ForegroundColor $ForegroundColor
        }
        else {
            Write-Host $formattedMessage
        }
    }
}

function Get-NutanixClusters {
    <#
    .SYNOPSIS
        Retrieves all clusters from Nutanix Prism Central.
    .DESCRIPTION
        Gets a list of all Nutanix clusters registered with Prism Central.
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
            Write-TimestampedMessage -Message "Retrieving clusters from Prism Central..."
            
            $endpoint = "clusters/list"
            $body = @{
                kind = "cluster"
                length = 500
            } | ConvertTo-Json
            
            $clusterList = @()
            $offset = 0
            $totalEntities = 0
            
            # Handle paging
            do {
                $body = @{
                    kind = "cluster"
                    offset = $offset
                    length = 500
                } | ConvertTo-Json
                
                $response = Invoke-NutanixApiRequest -ConnectionInfo $ConnectionInfo -Endpoint $endpoint -Body $body -MaxAttempts $MaxAttempts
                
                if ($response.entities.Count -gt 0) {
                    $clusterList += $response.entities
                }
                
                $offset += $response.entities.Count
                $totalEntities = $response.metadata.total_matches
                
                Write-TimestampedMessage -Message ("Retrieved {0}/{1} clusters" -f $offset, $totalEntities)
                
            } while ($offset -lt $totalEntities -and $response.entities.Count -gt 0)
            
            Write-TimestampedMessage -Message ("Successfully retrieved {0} clusters" -f $clusterList.Count) -ForegroundColor Green
            return $clusterList
        }
        catch {
            $errorMessage = "Failed to retrieve clusters: {0}" -f $_.Exception.Message
            Write-TimestampedMessage -Message $errorMessage -ForegroundColor Red
            throw $errorMessage
        }
    }
}

function Get-NutanixVmsWithHosts {
    <#
    .SYNOPSIS
        Retrieves all VMs with their host information from Nutanix Prism Central.
    .DESCRIPTION
        Gets a list of all VMs with their current host assignments from Prism Central.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [hashtable]$ConnectionInfo,
        
        [Parameter(Mandatory = $true)]
        [array]$Clusters,
        
        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 3
    )
    
    process {
        try {
            Write-TimestampedMessage -Message "Retrieving VMs and their hosts from Prism Central..."
            
            $endpoint = "vms/list"
            $vmList = @()
            $offset = 0
            $totalEntities = 0
            
            # Create a lookup table for cluster information
            $clusterLookup = @{}
            foreach ($cluster in $Clusters) {
                $clusterLookup[$cluster.metadata.uuid] = $cluster.spec.name
            }
            
            # Handle paging for VM retrieval
            do {
                $body = @{
                    kind = "vm"
                    offset = $offset
                    length = 500
                } | ConvertTo-Json
                
                $response = Invoke-NutanixApiRequest -ConnectionInfo $ConnectionInfo -Endpoint $endpoint -Body $body -MaxAttempts $MaxAttempts
                
                if ($response.entities.Count -gt 0) {
                    foreach ($vm in $response.entities) {
                        # Get the cluster name from the lookup table
                        $clusterName = $clusterLookup[$vm.spec.cluster_reference.uuid]
                        
                        # Create a custom object with only the required properties
                        $vmInfo = [PSCustomObject]@{
                            VmName = $vm.spec.name
                            VmUuid = $vm.metadata.uuid
                            HostName = $vm.status.resources.host_reference.name
                            HostUuid = $vm.status.resources.host_reference.uuid
                            ClusterName = $clusterName
                            ClusterUuid = $vm.spec.cluster_reference.uuid
                        }
                        
                        $vmList += $vmInfo
                    }
                }
                
                $offset += $response.entities.Count
                $totalEntities = $response.metadata.total_matches
                
                Write-TimestampedMessage -Message ("Retrieved {0}/{1} VMs" -f $offset, $totalEntities)
                
            } while ($offset -lt $totalEntities -and $response.entities.Count -gt 0)
            
            Write-TimestampedMessage -Message ("Successfully retrieved {0} VMs with their host information" -f $vmList.Count) -ForegroundColor Green
            return $vmList
        }
        catch {
            $errorMessage = "Failed to retrieve VMs with host information: {0}" -f $_.Exception.Message
            Write-TimestampedMessage -Message $errorMessage -ForegroundColor Red
            throw $errorMessage
        }
    }
}

function Compare-VmHostAssignments {
    <#
    .SYNOPSIS
        Compares current VM host assignments with previous ones to detect changes.
    .DESCRIPTION
        Identifies VMs that have moved to a different host since the last check.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$CurrentVms,
        
        [Parameter(Mandatory = $true)]
        [array]$PreviousVms
    )
    
    process {
        try {
            Write-TimestampedMessage -Message "Comparing VM host assignments..."
            
            # Create lookup table for previous VM host assignments
            $previousVmLookup = @{}
            foreach ($vm in $PreviousVms) {
                $previousVmLookup[$vm.VmUuid] = $vm
            }
            
            # Find VMs that have changed hosts
            $changedVms = @()
            foreach ($currentVm in $CurrentVms) {
                if ($previousVmLookup.ContainsKey($currentVm.VmUuid)) {
                    $previousVm = $previousVmLookup[$currentVm.VmUuid]
                    
                    # Check if the host has changed
                    if ($currentVm.HostUuid -ne $previousVm.HostUuid) {
                        $timestamp = Get-FormattedTimestamp
                        
                        $changedVm = [PSCustomObject]@{
                            Timestamp = $timestamp
                            VmName = $currentVm.VmName
                            HostName_New = $currentVm.HostName
                            HostName_Previous = $previousVm.HostName
                            PrismCentral = $PrismCentralAddress
                            ClusterName = $currentVm.ClusterName
                        }
                        
                        $changedVms += $changedVm
                    }
                }
            }
            
            Write-TimestampedMessage -Message ("Detected {0} VMs that changed hosts" -f $changedVms.Count)
            return $changedVms
        }
        catch {
            $errorMessage = "Failed to compare VM host assignments: {0}" -f $_.Exception.Message
            Write-TimestampedMessage -Message $errorMessage -ForegroundColor Red
            throw $errorMessage
        }
    }
}

function Export-VmChangesToCsv {
    <#
    .SYNOPSIS
        Exports VM host change information to a CSV file.
    .DESCRIPTION
        Appends detected VM host changes to the specified CSV file.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$ChangedVms,
        
        [Parameter(Mandatory = $true)]
        [string]$CsvFilePath
    )
    
    process {
        try {
            if ($ChangedVms.Count -gt 0) {
                # Create directory if it doesn't exist
                $directory = Split-Path -Path $CsvFilePath -Parent
                if (-not (Test-Path -Path $directory -PathType Container) -and $directory -ne "") {
                    New-Item -Path $directory -ItemType Directory -Force | Out-Null
                }
                
                # Check if file exists to determine if header is needed
                $fileExists = Test-Path -Path $CsvFilePath -PathType Leaf
                
                # Export to CSV
                $ChangedVms | Export-Csv -Path $CsvFilePath -NoTypeInformation -Append:$fileExists
                
                Write-TimestampedMessage -Message ("Exported {0} VM changes to {1}" -f $ChangedVms.Count, $CsvFilePath) -ForegroundColor Green
            }
            else {
                Write-TimestampedMessage -Message "No VM changes to export"
            }
        }
        catch {
            $errorMessage = "Failed to export VM changes to CSV: {0}" -f $_.Exception.Message
            Write-TimestampedMessage -Message $errorMessage -ForegroundColor Red
            throw $errorMessage
        }
    }
}

function Start-NutanixVmMonitoring {
    <#
    .SYNOPSIS
        Main function that monitors Nutanix VMs for host changes.
    .DESCRIPTION
        Runs a continuous monitoring loop that checks for VM host changes at specified intervals.
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
    
    process {
        try {
            Write-TimestampedMessage -Message "Starting Nutanix VM host monitoring" -ForegroundColor Cyan
            Write-TimestampedMessage -Message ("Prism Central: {0}" -f $PrismCentralAddress)
            Write-TimestampedMessage -Message ("CSV File: {0}" -f $CsvFilePath)
            Write-TimestampedMessage -Message ("Data Retrieval Interval: {0} minute(s)" -f $DataRetrievalInterval)
            Write-TimestampedMessage -Message ("Maximum Runtime: {0} minute(s)" -f $MaxScriptRuntimeMin)
            Write-TimestampedMessage -Message ("Maximum Error Retry Attempts: {0}" -f $MaxAttemptsWhenError)
            
            # Initialize connection to Nutanix Prism Central
            $connectionInfo = Initialize-NutanixConnection -PrismCentralAddress $PrismCentralAddress
            
            # Get initial list of clusters
            $clusters = Get-NutanixClusters -ConnectionInfo $connectionInfo -MaxAttempts $MaxAttemptsWhenError
            
            # Get initial VM list with host information
            $previousVms = Get-NutanixVmsWithHosts -ConnectionInfo $connectionInfo -Clusters $clusters -MaxAttempts $MaxAttemptsWhenError
            
            # Calculate script end time
            $startTime = Get-Date
            $endTime = $startTime.AddMinutes($MaxScriptRuntimeMin)
            
            Write-TimestampedMessage -Message ("Initial VM data retrieved. Beginning monitoring until {0}" -f $endTime) -ForegroundColor Cyan
            
            # Main monitoring loop
            while ((Get-Date) -lt $endTime) {
                # Sleep for the specified interval
                $sleepSeconds = $DataRetrievalInterval * 60
                Write-TimestampedMessage -Message ("Waiting {0} minute(s) until next check..." -f $DataRetrievalInterval)
                Start-Sleep -Seconds $sleepSeconds
                
                # Check if we've exceeded the runtime
                if ((Get-Date) -ge $endTime) {
                    Write-TimestampedMessage -Message "Maximum script runtime reached. Exiting..." -ForegroundColor Yellow
                    break
                }
                
                try {
                    # Get latest VM list
                    $currentVms = Get-NutanixVmsWithHosts -ConnectionInfo $connectionInfo -Clusters $clusters -MaxAttempts $MaxAttemptsWhenError
                    
                    # Compare with previous list to find changes
                    $changedVms = Compare-VmHostAssignments -CurrentVms $currentVms -PreviousVms $previousVms
                    
                    # Export changes to CSV
                    Export-VmChangesToCsv -ChangedVms $changedVms -CsvFilePath $CsvFilePath
                    
                    # Update previous VM list for next iteration
                    $previousVms = $currentVms
                }
                catch {
                    $errorMessage = "Error in monitoring cycle: {0}" -f $_.Exception.Message
                    Write-TimestampedMessage -Message $errorMessage -ForegroundColor Red
                }
            }
            
            Write-TimestampedMessage -Message "Monitoring completed" -ForegroundColor Cyan
        }
        catch {
            $errorMessage = "Fatal error in monitoring script: {0}" -f $_.Exception.Message
            Write-TimestampedMessage -Message $errorMessage -ForegroundColor Red
            throw $errorMessage
        }
    }
}

# Start monitoring
try {
    Write-TimestampedMessage -Message "Nutanix VM Host Monitoring Script" -ForegroundColor Cyan
    Write-TimestampedMessage -Message "-------------------------------" -ForegroundColor Cyan
    
    Start-NutanixVmMonitoring `
        -PrismCentralAddress $PrismCentralAddress `
        -CsvFilePath $CsvFilePath `
        -DataRetrievalInterval $DataRetrievalInterval `
        -MaxScriptRuntimeMin $MaxScriptRuntimeMin `
        -MaxAttemptsWhenError $MaxAttemptsWhenError
}
catch {
    $errorMessage = "Script execution failed: {0}" -f $_.Exception.Message
    Write-TimestampedMessage -Message $errorMessage -ForegroundColor Red
    exit 1
}