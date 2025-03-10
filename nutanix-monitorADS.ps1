#Requires -Version 5.1

<#
.SYNOPSIS
    Monitors Nutanix VMs for host migrations via Prism Central API
.DESCRIPTION
    This script connects to Nutanix Prism Central, retrieves VM information
    at specified intervals, and reports when VMs migrate between hosts.
    Results are displayed and saved to a CSV file.
.PARAMETER PrismCentralAddress
    The address of the Nutanix Prism Central server
.PARAMETER CsvFilePath
    Path and filename for the CSV output
.PARAMETER DataRetrievalInterval
    Interval in minutes between API calls (default: 1)
.PARAMETER MaxScriptRuntimeMin
    Maximum runtime in minutes for the script (default: 60)
.PARAMETER MaxAttemptsWhenError
    Maximum number of retry attempts when an API call fails (default: 3)
.EXAMPLE
    .\Nutanix-VM-Migration-Monitor.ps1 -PrismCentralAddress "prism.example.com" -CsvFilePath "vm-migrations.csv" -DataRetrievalInterval 5 -MaxScriptRuntimeMin 120 -MaxAttemptsWhenError 5
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

#region Functions

function Initialize-Environment {
    [CmdletBinding()]
    param()
    
    process {
        Write-Verbose "Initializing environment settings"
        
        # Force TLS 1.2
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        
        # Ignore SSL certificate errors if needed
        if ($PSVersionTable.PSVersion.Major -ge 6) {
            $script:SkipCertificateCheck = @{SkipCertificateCheck = $true}
        }
        else {
            Add-Type -TypeDefinition @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
            [System.Net.ServicePointManager]::CertificatePolicy = New-Object -TypeName TrustAllCertsPolicy
            $script:SkipCertificateCheck = @{}
        }
    }
}

function Connect-NutanixAPI {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PrismCentralAddress
    )
    
    process {
        try {
            Write-Verbose "Prompting for Nutanix credentials"
            $credentials = Get-Credential -Message "Enter credentials for Nutanix Prism Central ($PrismCentralAddress)"
            
            if (-not $credentials) {
                throw "Credentials are required to connect to Nutanix Prism Central"
            }
            
            $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(
                "{0}:{1}" -f $credentials.UserName, $credentials.GetNetworkCredential().Password))
            
            $script:Headers = @{
                "Authorization" = "Basic $base64AuthInfo"
                "Content-Type" = "application/json"
                "Accept" = "application/json"
            }
            
            $apiBase = "https://{0}:9440/api/nutanix/v3" -f $PrismCentralAddress
            $script:ApiBaseUrl = $apiBase
            
            # Test connection
            $testUrl = "{0}/clusters" -f $apiBase
            $testParams = @{
                Method = "GET"
                Uri = $testUrl
                Headers = $script:Headers
                ErrorAction = "Stop"
            }
            
            if ($PSVersionTable.PSVersion.Major -ge 6) {
                $testParams += $script:SkipCertificateCheck
            }
            
            $testResult = Invoke-RestMethod @testParams
            
            Write-Verbose "Successfully connected to Nutanix Prism Central API"
            return $true
        }
        catch {
            Write-Error "Failed to connect to Nutanix Prism Central: $_"
            return $false
        }
    }
}

function Get-NutanixClusterInfo {
    [CmdletBinding()]
    param()
    
    process {
        try {
            Write-Verbose "Retrieving Nutanix cluster information"
            
            $clusterUrl = "{0}/clusters/list" -f $script:ApiBaseUrl
            $clusterBody = @{
                kind = "cluster"
                length = 500
            } | ConvertTo-Json
            
            $clusters = @{}
            $offset = 0
            $totalEntities = 501 # Set higher than length to ensure first page runs
            
            while ($offset -lt $totalEntities) {
                $pageBody = $clusterBody | ConvertFrom-Json
                $pageBody.offset = $offset
                $pageBodyJson = $pageBody | ConvertTo-Json
                
                $params = @{
                    Method = "POST"
                    Uri = $clusterUrl
                    Headers = $script:Headers
                    Body = $pageBodyJson
                    ErrorAction = "Stop"
                }
                
                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $params += $script:SkipCertificateCheck
                }
                
                $response = Invoke-RestMethod @params
                
                $totalEntities = $response.metadata.total_matches
                
                foreach ($entity in $response.entities) {
                    $clusters[$entity.metadata.uuid] = $entity.spec.name
                }
                
                $offset += $response.entities.Count
                
                if ($response.entities.Count -eq 0) {
                    break
                }
            }
            
            return $clusters
        }
        catch {
            Write-Error "Failed to retrieve cluster information: $_"
            return @{}
        }
    }
}

function Get-NutanixVMList {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $false)]
        [int]$AttemptCount = 0
    )
    
    process {
        try {
            Write-Verbose "Retrieving Nutanix VM information"
            
            $vmUrl = "{0}/vms/list" -f $script:ApiBaseUrl
            $vmBody = @{
                kind = "vm"
                length = 500
            } | ConvertTo-Json
            
            $vms = @()
            $offset = 0
            $totalEntities = 501 # Set higher than length to ensure first page runs
            
            while ($offset -lt $totalEntities) {
                $pageBody = $vmBody | ConvertFrom-Json
                $pageBody.offset = $offset
                $pageBodyJson = $pageBody | ConvertTo-Json
                
                $params = @{
                    Method = "POST"
                    Uri = $vmUrl
                    Headers = $script:Headers
                    Body = $pageBodyJson
                    ErrorAction = "Stop"
                }
                
                if ($PSVersionTable.PSVersion.Major -ge 6) {
                    $params += $script:SkipCertificateCheck
                }
                
                $response = Invoke-RestMethod @params
                
                $totalEntities = $response.metadata.total_matches
                
                $vms += $response.entities
                
                $offset += $response.entities.Count
                
                if ($response.entities.Count -eq 0) {
                    break
                }
            }
            
            return $vms
        }
        catch {
            Write-Error "Failed to retrieve VM information: $_"
            
            if ($AttemptCount -lt $MaxAttemptsWhenError) {
                $nextAttempt = $AttemptCount + 1
                Write-Warning "Retry attempt $nextAttempt of $MaxAttemptsWhenError for VM list retrieval"
                Start-Sleep -Seconds 10
                return Get-NutanixVMList -AttemptCount $nextAttempt
            }
            else {
                Write-Error "Maximum retry attempts reached. Returning empty VM list."
                return @()
            }
        }
    }
}

function Get-NutanixVMDetails {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$VMs,
        
        [Parameter(Mandatory = $true)]
        [hashtable]$ClusterInfo,
        
        [Parameter(Mandatory = $false)]
        [int]$AttemptCount = 0
    )
    
    process {
        try {
            Write-Verbose "Processing VM details for $($VMs.Count) VMs"
            
            $vmDetails = @()
            
            foreach ($vm in $VMs) {
                $vmDetail = [PSCustomObject]@{
                    VMName = $vm.spec.name
                    VMID = $vm.metadata.uuid
                    HostID = $vm.status.resources.host_reference.uuid
                    HostName = $vm.status.resources.host_reference.name
                    ClusterID = $vm.status.cluster_reference.uuid
                    ClusterName = $ClusterInfo[$vm.status.cluster_reference.uuid]
                    CPUUsage = [math]::Round(($vm.status.resources.power_state -eq "ON" ? $vm.status.resources.hypervisor_cpu_usage_ppm / 10000 : 0), 2)
                    PowerState = $vm.status.resources.power_state
                }
                
                $vmDetails += $vmDetail
            }
            
            return $vmDetails
        }
        catch {
            Write-Error "Failed to process VM details: $_"
            
            if ($AttemptCount -lt $MaxAttemptsWhenError) {
                $nextAttempt = $AttemptCount + 1
                Write-Warning "Retry attempt $nextAttempt of $MaxAttemptsWhenError for VM details processing"
                Start-Sleep -Seconds 10
                return Get-NutanixVMDetails -VMs $VMs -ClusterInfo $ClusterInfo -AttemptCount $nextAttempt
            }
            else {
                Write-Error "Maximum retry attempts reached. Returning empty VM details."
                return @()
            }
        }
    }
}

function Compare-VMHostMigrations {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$CurrentVMDetails,
        
        [Parameter(Mandatory = $true)]
        [array]$PreviousVMDetails,
        
        [Parameter(Mandatory = $true)]
        [string]$PrismCentralAddress
    )
    
    process {
        Write-Verbose "Comparing VM host migrations"
        
        $migrations = @()
        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        
        foreach ($currentVM in $CurrentVMDetails) {
            $previousVM = $PreviousVMDetails | Where-Object { $_.VMID -eq $currentVM.VMID }
            
            if ($previousVM -and $currentVM.HostID -ne $previousVM.HostID) {
                $migration = [PSCustomObject]@{
                    Timestamp = $timestamp
                    VMName = $currentVM.VMName
                    VMCpuUsage = $currentVM.CPUUsage
                    HostName_New = $currentVM.HostName
                    HostName_Previous = $previousVM.HostName
                    PrismCentral = $PrismCentralAddress
                    ClusterName = $currentVM.ClusterName
                }
                
                $migrations += $migration
            }
        }
        
        return $migrations
    }
}

function Export-MigrationsToCsv {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [array]$Migrations,
        
        [Parameter(Mandatory = $true)]
        [string]$CsvFilePath
    )
    
    process {
        try {
            Write-Verbose "Exporting migrations to CSV: $CsvFilePath"
            
            if (-not (Test-Path -Path $CsvFilePath -IsValid)) {
                throw "Invalid CSV file path: $CsvFilePath"
            }
            
            $csvFolder = Split-Path -Path $CsvFilePath -Parent
            
            if (-not [string]::IsNullOrEmpty($csvFolder) -and -not (Test-Path -Path $csvFolder)) {
                New-Item -Path $csvFolder -ItemType Directory -Force | Out-Null
            }
            
            # Append migrations to the CSV file
            $Migrations | Export-Csv -Path $CsvFilePath -NoTypeInformation -Append
            
            Write-Verbose "Successfully exported $($Migrations.Count) migrations to CSV"
        }
        catch {
            Write-Error "Failed to export migrations to CSV: $_"
        }
    }
}

function Start-VMHostMigrationMonitor {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$PrismCentralAddress,
        
        [Parameter(Mandatory = $true)]
        [string]$CsvFilePath,
        
        [Parameter(Mandatory = $true)]
        [int]$DataRetrievalInterval,
        
        [Parameter(Mandatory = $true)]
        [int]$MaxScriptRuntimeMin
    )
    
    process {
        Write-Host "Starting Nutanix VM Migration Monitor"
        Write-Host "Prism Central: $PrismCentralAddress"
        Write-Host "CSV File: $CsvFilePath"
        Write-Host "Interval: $DataRetrievalInterval minute(s)"
        Write-Host "Max Runtime: $MaxScriptRuntimeMin minute(s)"
        Write-Host "Press Ctrl+C to stop the monitor"
        Write-Host "----------------------------------------------"
        
        # Initialize previous VM details
        $previousVMDetails = @()
        
        # Calculate end time
        $endTime = (Get-Date).AddMinutes($MaxScriptRuntimeMin)
        
        # Get cluster information
        $clusterInfo = Get-NutanixClusterInfo
        
        # Initialize CSV file with headers if it doesn't exist
        if (-not (Test-Path -Path $CsvFilePath)) {
            $csvHeaders = [PSCustomObject]@{
                Timestamp = ""
                VMName = ""
                VMCpuUsage = ""
                HostName_New = ""
                HostName_Previous = ""
                PrismCentral = ""
                ClusterName = ""
            }
            
            $csvHeaders | Export-Csv -Path $CsvFilePath -NoTypeInformation
        }
        
        # Start monitoring loop
        while ((Get-Date) -lt $endTime) {
            $cycleStartTime = Get-Date
            
            try {
                # Get current VM details
                $vms = Get-NutanixVMList
                $currentVMDetails = Get-NutanixVMDetails -VMs $vms -ClusterInfo $clusterInfo
                
                # If we have previous VM details, compare for migrations
                if ($previousVMDetails.Count -gt 0) {
                    $migrations = Compare-VMHostMigrations -CurrentVMDetails $currentVMDetails -PreviousVMDetails $previousVMDetails -PrismCentralAddress $PrismCentralAddress
                    
                    # If there are migrations, report and export them
                    if ($migrations.Count -gt 0) {
                        Write-Host ("{0} VM migrations detected at {1}" -f $migrations.Count, (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
                        
                        foreach ($migration in $migrations) {
                            Write-Host ("VM: {0} | CPU: {1}% | New Host: {2} | Previous Host: {3} | Cluster: {4}" -f 
                                $migration.VMName, 
                                $migration.VMCpuUsage, 
                                $migration.HostName_New, 
                                $migration.HostName_Previous, 
                                $migration.ClusterName)
                        }
                        
                        Export-MigrationsToCsv -Migrations $migrations -CsvFilePath $CsvFilePath
                    }
                    else {
                        Write-Host ("No VM migrations detected at {0}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
                    }
                }
                else {
                    Write-Host ("Initial VM data collected at {0}, monitoring for changes..." -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"))
                }
                
                # Update previous VM details
                $previousVMDetails = $currentVMDetails
            }
            catch {
                Write-Error "Error in monitoring cycle: $_"
            }
            
            # Calculate time to wait
            $cycleEndTime = Get-Date
            $cycleDuration = ($cycleEndTime - $cycleStartTime).TotalSeconds
            $waitTimeSeconds = ($DataRetrievalInterval * 60) - $cycleDuration
            
            if ($waitTimeSeconds -gt 0) {
                Write-Verbose "Waiting for $waitTimeSeconds seconds until next data collection"
                Start-Sleep -Seconds $waitTimeSeconds
            }
        }
        
        Write-Host "Maximum script runtime reached. Monitoring stopped."
    }
}

#endregion

# Main script execution
try {
    # Initialize environment
    Initialize-Environment
    
    # Connect to Nutanix API
    $connected = Connect-NutanixAPI -PrismCentralAddress $PrismCentralAddress
    
    if (-not $connected) {
        throw "Failed to connect to Nutanix Prism Central API"
    }
    
    # Start monitor
    Start-VMHostMigrationMonitor -PrismCentralAddress $PrismCentralAddress -CsvFilePath $CsvFilePath -DataRetrievalInterval $DataRetrievalInterval -MaxScriptRuntimeMin $MaxScriptRuntimeMin
}
catch {
    Write-Error "Script execution failed: $_"
    exit 1
}