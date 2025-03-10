<#
.SYNOPSIS
    Monitors VM migrations between hosts in Nutanix environments.

.DESCRIPTION
    This script connects to Nutanix Prism Central REST API v3, retrieves VM information,
    and monitors VM migrations between hosts. Results are saved to a JSON file and
    migrations are logged to a CSV file.

.PARAMETER PrismCentralAddress
    The address of the Nutanix Prism Central instance.

.PARAMETER CsvFileName
    The name of the CSV file to save migration data.

.PARAMETER DataRetrievalInterval
    The interval in minutes between data retrievals.

.PARAMETER MaxScriptRuntimeMin
    The maximum runtime for the script in minutes.

.PARAMETER MaxAttemptsWhenError
    The maximum number of retry attempts when an error occurs.

.EXAMPLE
    .\NutanixVMMigrationMonitor.ps1 -PrismCentralAddress "prismcentral.example.com" -CsvFileName "vm_migrations.csv" -DataRetrievalInterval 1 -MaxScriptRuntimeMin 60 -MaxAttemptsWhenError 3
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PrismCentralAddress,

    [Parameter(Mandatory = $true)]
    [string]$CsvFileName,

    [Parameter(Mandatory = $false)]
    [int]$DataRetrievalInterval = 1,

    [Parameter(Mandatory = $false)]
    [int]$MaxScriptRuntimeMin = 60,

    [Parameter(Mandatory = $false)]
    [int]$MaxAttemptsWhenError = 3
)

#Region Functions

function Write-LogMessage {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[{0}] [{1}] {2}" -f $timestamp, $Level, $Message
    Write-Host $logMessage
}

function Get-Credential {
    [CmdletBinding()]
    param()

    $credential = $null
    try {
        $credential = [System.Management.Automation.PSCredential]::new(
            (Read-Host -Prompt "Enter username for Prism Central"),
            (Read-Host -Prompt "Enter password for Prism Central" -AsSecureString)
        )
    }
    catch {
        Write-LogMessage -Message "Error getting credentials: $_" -Level 'ERROR'
        throw "Failed to get credentials: $_"
    }
    return $credential
}

function Invoke-NutanixApiCall {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrismCentralAddress,

        [Parameter(Mandatory = $true)]
        [string]$Endpoint,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [Microsoft.PowerShell.Commands.WebRequestMethod]$Method = 'POST',

        [Parameter(Mandatory = $false)]
        [object]$Body = $null,

        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 3,

        [Parameter(Mandatory = $false)]
        [int]$RetryDelaySeconds = 5
    )

    $uri = "https://{0}:9440/api/nutanix/v3/{1}" -f $PrismCentralAddress, $Endpoint
    $headers = @{
        'Content-Type' = 'application/json'
        'Accept'       = 'application/json'
    }

    # Convert body to JSON if it's not a string
    if ($Body -and $Body -isnot [string]) {
        $bodyJson = $Body | ConvertTo-Json -Depth 10
    }
    else {
        $bodyJson = $Body
    }

    $attempt = 1
    $response = $null

    while ($attempt -le $MaxAttempts) {
        try {
            # Ignore SSL certificate validation for lab environments
            [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            
            $params = @{
                Uri         = $uri
                Method      = $Method
                Headers     = $headers
                Credential  = $Credential
                ContentType = 'application/json'
            }
            
            if ($bodyJson) {
                $params.Add('Body', $bodyJson)
            }

            $response = Invoke-RestMethod @params -ErrorAction Stop
            break
        }
        catch {
            if ($attempt -lt $MaxAttempts) {
                $statusCode = $_.Exception.Response.StatusCode.value__
                $warningMsg = "Attempt $attempt of $MaxAttempts failed with status code $statusCode. Retrying in $RetryDelaySeconds seconds..."
                Write-LogMessage -Message $warningMsg -Level 'WARNING'
                Start-Sleep -Seconds $RetryDelaySeconds
                $attempt++
            }
            else {
                $errorDetails = "Status code: $($_.Exception.Response.StatusCode.value__), Message: $($_.Exception.Message)"
                Write-LogMessage -Message "API call failed after $MaxAttempts attempts: $errorDetails" -Level 'ERROR'
                throw "Failed to call Nutanix API: $errorDetails"
            }
        }
    }

    return $response
}

function Get-NutanixClusters {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrismCentralAddress,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 3
    )

    $body = @{
        kind = "cluster"
        length = 500
    }

    try {
        $response = Invoke-NutanixApiCall -PrismCentralAddress $PrismCentralAddress -Endpoint "clusters/list" -Credential $Credential -Body $body -MaxAttempts $MaxAttempts
        
        # Create a hashtable for quick lookup
        $clusters = @{}
        foreach ($cluster in $response.entities) {
            $clusters[$cluster.metadata.uuid] = $cluster.spec.name
        }
        
        return $clusters
    }
    catch {
        Write-LogMessage -Message "Error retrieving Nutanix clusters: $_" -Level 'ERROR'
        throw "Failed to retrieve clusters: $_"
    }
}

function Get-NutanixVMs {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PrismCentralAddress,

        [Parameter(Mandatory = $true)]
        [System.Management.Automation.PSCredential]$Credential,

        [Parameter(Mandatory = $true)]
        [hashtable]$Clusters,

        [Parameter(Mandatory = $false)]
        [int]$MaxAttempts = 3
    )

    $body = @{
        kind = "vm"
        length = 500
    }

    try {
        $response = Invoke-NutanixApiCall -PrismCentralAddress $PrismCentralAddress -Endpoint "vms/list" -Credential $Credential -Body $body -MaxAttempts $MaxAttempts
        
        $processedVMs = @()
        
        foreach ($vm in $response.entities) {
            $vmHostUuid = $vm.status.resources.host_reference.uuid
            $vmClusterUuid = $vm.status.cluster_reference.uuid
            
            # Get CPU usage if available
            $cpuUsage = 0
            if ($vm.status.resources.PSObject.Properties.Name -contains 'stats') {
                if ($vm.status.resources.stats.PSObject.Properties.Name -contains 'hypervisor_cpu_usage_ppm') {
                    # Convert PPM (parts per million) to percentage
                    $cpuUsage = [math]::Round($vm.status.resources.stats.hypervisor_cpu_usage_ppm / 10000, 2)
                }
            }
            
            $processedVM = [PSCustomObject]@{
                VMName      = $vm.spec.name
                VMUuid      = $vm.metadata.uuid
                HostUuid    = $vmHostUuid
                HostName    = $vm.status.resources.host_reference.name
                ClusterUuid = $vmClusterUuid
                ClusterName = $Clusters[$vmClusterUuid]
                CPUUsage    = $cpuUsage
                PowerState  = $vm.status.resources.power_state
                Timestamp   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
            }
            
            $processedVMs += $processedVM
        }
        
        return $processedVMs
    }
    catch {
        Write-LogMessage -Message "Error retrieving Nutanix VMs: $_" -Level 'ERROR'
        throw "Failed to retrieve VMs: $_"
    }
}

function Save-DataToJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Data,

        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    try {
        $Data | ConvertTo-Json -Depth 10 | Out-File -FilePath $FilePath -Force
        Write-LogMessage -Message "Data saved to JSON file: $FilePath"
        return $true
    }
    catch {
        Write-LogMessage -Message "Error saving data to JSON file: $_" -Level 'ERROR'
        return $false
    }
}

function Get-DataFromJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    try {
        if (Test-Path -Path $FilePath) {
            $data = Get-Content -Path $FilePath -Raw | ConvertFrom-Json
            Write-LogMessage -Message "Successfully loaded data from JSON file: $FilePath"
            return $data
        }
        else {
            Write-LogMessage -Message "JSON file not found: $FilePath" -Level 'WARNING'
            return $null
        }
    }
    catch {
        Write-LogMessage -Message "Error loading data from JSON file: $_" -Level 'ERROR'
        return $null
    }
}

function Save-MigrationToCsv {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Migration,

        [Parameter(Mandatory = $true)]
        [string]$FilePath
    )

    try {
        # Check if file exists to determine if header is needed
        $fileExists = Test-Path -Path $FilePath
        
        # Export to CSV
        $Migration | Export-Csv -Path $FilePath -NoTypeInformation -Append -Force
        
        if (-not $fileExists) {
            Write-LogMessage -Message "Created new CSV file: $FilePath"
        }
        
        Write-LogMessage -Message "Migration record saved to CSV file: $FilePath"
    }
    catch {
        Write-LogMessage -Message "Error saving migration to CSV file: $_" -Level 'ERROR'
    }
}

function Compare-VMHosts {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [array]$CurrentVMs,

        [Parameter(Mandatory = $true)]
        [array]$PreviousVMs,

        [Parameter(Mandatory = $true)]
        [string]$PrismCentralAddress,

        [Parameter(Mandatory = $true)]
        [string]$CsvFilePath
    )

    $migrations = @()
    
    foreach ($currentVM in $CurrentVMs) {
        $previousVM = $PreviousVMs | Where-Object { $_.VMUuid -eq $currentVM.VMUuid }
        
        if ($previousVM -and $currentVM.HostUuid -ne $previousVM.HostUuid) {
            $migration = [PSCustomObject]@{
                Timestamp        = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
                VMName           = $currentVM.VMName
                VMCpu_Usage      = $currentVM.CPUUsage
                HostName_New     = $currentVM.HostName
                HostName_Previous = $previousVM.HostName
                PrismCentral     = $PrismCentralAddress
                ClusterName      = $currentVM.ClusterName
            }
            
            $migrations += $migration
            
            # Save each migration to CSV
            Save-MigrationToCsv -Migration $migration -FilePath $CsvFilePath
            
            # Output to console
            $logMsg = "VM Migration Detected: $($migration.VMName) moved from $($migration.HostName_Previous) to $($migration.HostName_New)"
            Write-LogMessage -Message $logMsg
        }
    }
    
    return $migrations
}

function Get-LatestJsonFile {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$BaseFileName
    )

    try {
        # Search for any file matching the pattern
        $filePattern = "$($BaseFileName)_*.json"
        $files = Get-ChildItem -Path $filePattern -ErrorAction SilentlyContinue
        
        if ($files -and $files.Count -gt 0) {
            # Get the most recent file
            $latestFile = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1
            Write-LogMessage -Message "Found latest JSON file: $($latestFile.Name)"
            return $latestFile.FullName
        }
        else {
            Write-LogMessage -Message "No previous JSON files found matching pattern: $filePattern" -Level 'WARNING'
            return $null
        }
    }
    catch {
        Write-LogMessage -Message "Error finding latest JSON file: $_" -Level 'ERROR'
        return $null
    }
}

#EndRegion Functions

#Region Main Script Execution

try {
    Write-LogMessage -Message "Starting Nutanix VM Migration Monitor"
    $startMsg = "Prism Central: $PrismCentralAddress, CSV File: $CsvFileName, Interval: $DataRetrievalInterval min, Max Runtime: $MaxScriptRuntimeMin min"
    Write-LogMessage -Message $startMsg
    
    # Get credentials
    $credential = Get-Credential
    
    # Initialize variables
    $scriptStartTime = Get-Date
    $previousVMs = @()
    $jsonBaseFileName = "NutanixVMData"
    $currentJsonFilePath = "$($jsonBaseFileName)_$(Get-Date -Format "yyyyMMdd_HHmmss").json"
    
    # Check for previous JSON file to load as baseline
    $previousJsonFilePath = Get-LatestJsonFile -BaseFileName $jsonBaseFileName
    if ($previousJsonFilePath) {
        $previousVMs = Get-DataFromJson -FilePath $previousJsonFilePath
        if ($previousVMs) {
            Write-LogMessage -Message "Loaded $($previousVMs.Count) VMs from previous JSON file as baseline"
        }
    }
    
    # Main loop
    while ($true) {
        $currentTime = Get-Date
        $elapsedMinutes = ($currentTime - $scriptStartTime).TotalMinutes
        
        # Check if maximum script runtime has been reached
        if ($elapsedMinutes -ge $MaxScriptRuntimeMin) {
            Write-LogMessage -Message "Maximum script runtime of $MaxScriptRuntimeMin minutes reached. Exiting."
            break
        }
        
        try {
            # Get clusters for reference
            $clusters = Get-NutanixClusters -PrismCentralAddress $PrismCentralAddress -Credential $credential -MaxAttempts $MaxAttemptsWhenError
            
            # Get VMs with host information
            $currentVMs = Get-NutanixVMs -PrismCentralAddress $PrismCentralAddress -Credential $credential -Clusters $clusters -MaxAttempts $MaxAttemptsWhenError
            
            # Save current data to JSON
            $jsonSaveSuccess = Save-DataToJson -Data $currentVMs -FilePath $currentJsonFilePath
            
            # Compare with previous data if available
            if ($previousVMs -and $previousVMs.Count -gt 0) {
                $migrations = Compare-VMHosts -CurrentVMs $currentVMs -PreviousVMs $previousVMs -PrismCentralAddress $PrismCentralAddress -CsvFilePath $CsvFileName
                
                # Count of detected migrations
                $migrationCount = if ($migrations) { $migrations.Count } else { 0 }
                Write-LogMessage -Message "Detected $migrationCount VM migrations in this cycle"
            }
            else {
                Write-LogMessage -Message "First run, establishing baseline VM host data."
            }
            
            # Store current data for next comparison
            $previousVMs = $currentVMs
            
            # Update JSON filename for next iteration (keep one file per hour to avoid too many files)
            if ((Get-Date).Minute -eq 0) {
                $currentJsonFilePath = "$($jsonBaseFileName)_$(Get-Date -Format "yyyyMMdd_HHmmss").json"
            }
            
            # Wait for next interval
            $nextRunTime = $currentTime.AddMinutes($DataRetrievalInterval)
            $waitSeconds = [math]::Max(1, ($nextRunTime - (Get-Date)).TotalSeconds)
            
            Write-LogMessage -Message "Next check in $([math]::Round($waitSeconds)) seconds at $($nextRunTime.ToString("HH:mm:ss"))"
            Start-Sleep -Seconds $waitSeconds
        }
        catch {
            Write-LogMessage -Message "Error in main loop: $_" -Level 'ERROR'
            
            # Try to load previous state from JSON if current query failed
            if (-not $previousVMs -or $previousVMs.Count -eq 0) {
                $lastJsonFile = Get-LatestJsonFile -BaseFileName $jsonBaseFileName
                if ($lastJsonFile) {
                    $previousVMs = Get-DataFromJson -FilePath $lastJsonFile
                    if ($previousVMs) {
                        Write-LogMessage -Message "Recovered $($previousVMs.Count) VMs from JSON file after error"
                    }
                }
            }
            
            # Wait before retry
            Start-Sleep -Seconds 30
        }
    }
}
catch {
    Write-LogMessage -Message "Fatal error in script: $_" -Level 'ERROR'
    exit 1
}
finally {
    Write-LogMessage -Message "Script execution completed"
}

#EndRegion Main Script Execution