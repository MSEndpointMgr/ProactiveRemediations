<#
.SYNOPSIS
    Proaction Remediation script for cleaning up the local harddrive.

.DESCRIPTION
    This is the detection script for a Proactive Remediation in Endpoint Analytics used by the Disk Cleanup solution.

.EXAMPLE
    .\Detection.ps1

.NOTES
    FileName:    Detection.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2024-11-25
    Updated:     2024-11-25

    Version history:
    1.0.0 - (2024-11-25) Script created
#>
Begin {
    # Define the proactive remediation name
    $ProactiveRemediationName = "DiskCleanup"

    # Set company name
    $CompanyName = "<company_name>"

    # Define if any modules must be present on the device for this proactive remediation to execute properly
    # Set to $null if no modules are to be installed
    $Modules = @()

    # Enable TLS 1.2 support for downloading modules from PSGallery
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

    # Install required modules for script execution
    if ($Modules -ne $null) {
        foreach ($Module in $Modules) {
            try {
                $CurrentModule = Get-InstalledModule -Name $Module -ErrorAction "Stop" -Verbose:$false
                if ($CurrentModule -ne $null) {
                    $LatestModuleVersion = (Find-Module -Name $Module -ErrorAction "Stop" -Verbose:$false).Version
                    if ($LatestModuleVersion -gt $CurrentModule.Version) {
                        $UpdateModuleInvocation = Update-Module -Name $Module -Force -AcceptLicense -ErrorAction "Stop" -Confirm:$false -Verbose:$false
                    }
                }
            }
            catch [System.Exception] {
                try {
                    # Install NuGet package provider
                    $PackageProvider = Install-PackageProvider -Name "NuGet" -Force -Verbose:$false
            
                    # Install current missing module
                    Install-Module -Name $Module -Force -AcceptLicense -ErrorAction "Stop" -Confirm:$false -Verbose:$false
                }
                catch [System.Exception] {
                    Write-Warning -Message "An error occurred while attempting to install $($Module) module. Error message: $($_.Exception.Message)"
                }
            }
        }
    }
}
Process {
    # Functions
    function Write-LogEntry {
        param (
            [parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
            [ValidateNotNullOrEmpty()]
            [string]$Value,
    
            [parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
            [ValidateNotNullOrEmpty()]
            [ValidateSet("1", "2", "3")]
            [string]$Severity,
    
            [parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
            [ValidateNotNullOrEmpty()]
            [string]$FileName = "$($ProactiveRemediationName).log"
        )
        # Check if the script is running as SYSTEM, else use the user's temp folder for the log file location
        if ([Security.Principal.WindowsIdentity]::GetCurrent().IsSystem -eq $true) {
            $LogFilePath = Join-Path -Path (Join-Path -Path $env:ProgramData -ChildPath "Microsoft\IntuneManagementExtension\Logs") -ChildPath $FileName
        }
        else {
            $LogFilePath = Join-Path -Path (Join-Path -Path $env:TEMP -ChildPath "RemediationScript\Logs") -ChildPath $FileName
        }

        # Create log folder path if it does not exist
        try {
            $LogFolderPath = Split-Path -Path $LogFilePath -Parent
            if (-not(Test-Path -Path $LogFolderPath)) {
                New-Item -ItemType "Directory" -Path $LogFolderPath -Force -ErrorAction "Stop" | Out-Null
            }
        }
        catch [System.Exception] {
            Write-Warning -Message "An error occurred while attempting to create the log folder path. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
        
        # Construct time stamp for log entry
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), "+", (Get-WmiObject -Class Win32_TimeZone | Select-Object -ExpandProperty Bias))
        
        # Construct date for log entry
        $Date = (Get-Date -Format "MM-dd-yyyy")
        
        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)
        
        # Construct final log entry
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""$($ProactiveRemediationName)"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"
        
        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry $($ProactiveRemediationName).log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }
    }

    # Initial logging details for detection script
    Write-LogEntry -Value "[$($ProactiveRemediationName)-Detection] - Initializing" -Severity 1

    # Declare error message variable
    $ErrorMessage = $null

    # Assign variable for remediation script triggering
    # This variable must be set to $true if the remediation script is to be triggered
    $TriggerRemediation = $false

    # Declare variable for script execution history
    $ExecutionHistoryRegistryPath = "HKLM:\SOFTWARE\$($CompanyName)\ProactiveRemediations\$($ProactiveRemediationName)"
    $ExecutionHistoryRegistryValue = "Count"

    # Create registry key if it does not exist
    if (-not(Test-Path -Path $ExecutionHistoryRegistryPath)) {
        try {
            New-Item -Path $ExecutionHistoryRegistryPath -Force -ErrorAction "Stop" | Out-Null
        }
        catch [System.Exception] {
            $ErrorMessage = "An error occurred while attempting to create the registry key '$($ExecutionHistoryRegistryPath)'. Error message: $($_.Exception.Message)"
            Write-LogEntry -Value $ErrorMessage -Severity 3
        }
    }

    # Create registry value if it does not exist
    $ExecutionHistoryRegistryValuePresence = Get-ItemProperty -Path $ExecutionHistoryRegistryPath -Name $ExecutionHistoryRegistryValue -ErrorAction "SilentlyContinue"
    if ($ExecutionHistoryRegistryValuePresence -eq $null) {
        try {
            New-ItemProperty -Path $ExecutionHistoryRegistryPath -Name $ExecutionHistoryRegistryValue -Value 0 -PropertyType "String" -Force -ErrorAction "Stop" | Out-Null
        }
        catch [System.Exception] {
            $ErrorMessage = "An error occurred while attempting to create the registry value '$($ExecutionHistoryRegistryValue)' in $($ExecutionHistoryRegistryPath). Error message: $($_.Exception.Message)"
            Write-LogEntry -Value $ErrorMessage -Severity 3
        }
    }

    # Retrieve current execution history count
    $ExecutionHistoryCount = [int](Get-ItemProperty -Path $ExecutionHistoryRegistryPath -Name $ExecutionHistoryRegistryValue -ErrorAction "SilentlyContinue").$ExecutionHistoryRegistryValue
    if (($ExecutionHistoryCount -ne $null) -and ($ExecutionHistoryCount -le 100)) {
        try {
            # Retrieve Windows build number
            Write-LogEntry -Value "Retrieving Windows build number from WMI class: Win32_OperatingSystem" -Severity 1
            $WindowsBuildNumber = (Get-CimInstance -ClassName "Win32_OperatingSystem" -ErrorAction "Stop" | Select-Object -ExpandProperty "BuildNumber")
    
            # Determine Windows version based on build number
            switch ($WindowsBuildNumber) {
                { $PSItem -in 19000..19045 } { 
                    $WindowsVersion = "Windows 10"
                }
                { $PSItem -in 22000..29000 } {
                    $WindowsVersion = "Windows 11"
                }
            }
    
            try {
                # Retrieve free disk space on system drive
                Write-LogEntry -Value "Retrieving free disk space on system drive from WMI class: Win32_LogicalDisk" -Severity 1
                $FreeDiskSpace = [math]::Round((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'" -ErrorAction "Stop" | Select-Object -ExpandProperty FreeSpace) / 1GB)
    
                # Determine whether the remediation script should execute based on if device have upgraded to Windows 11 or not already
                if ($WindowsVersion -like "Windows 11") {
                    Write-LogEntry -Value "Device is running Windows 11, no further action required" -Severity 1
                }
                else {
                    Write-LogEntry -Value "Device is running Windows 10, checking for available disk space" -Severity 1
                    if ($FreeDiskSpace -lt 64) {
                        Write-LogEntry -Value "Free disk space on system drive is less than 64GB, cleanup remediation required" -Severity 1
                        $TriggerRemediation = $true
                    }
                    else {
                        Write-LogEntry -Value "Free disk space on system drive is greater than 64GB, no further action required" -Severity 1
                    }
                }
            }
            catch [System.Exception] {
                $ErrorMessage = "An error occurred while attempting to retrieve free disk space on system drive. Error message: $($_.Exception.Message)"
                Write-LogEntry -Value $ErrorMessage -Severity 3
            }
        }
        catch [System.Exception] {
            $ErrorMessage = "An error occurred while attempting to retrieve Windows build number. Error message: $($_.Exception.Message)"
            Write-LogEntry -Value $ErrorMessage -Severity 3
        }
    }
    else {
        Write-LogEntry -Value "The maximum number of '3' allowed executions has been reached. Exiting script" -Severity 1
    }

    # Handle output based on error message or completed execution
    if ($ErrorMessage -ne $null) {
        Write-Output -InputObject $ErrorMessage
    }
    elseif ($ExecutionHistoryCount -gt 99) {
        Write-Output -InputObject "Maximum number of allowed executions reached"
    }
    else {
        Write-Output -InputObject "Cleanup completed. Free disk space: $($FreeDiskSpace) GB"
    }

    # Trigger remediation script
    if ($TriggerRemediation -eq $true) {
        # Increment execution history count and update registry value
        $ExecutionHistoryCount++
        Set-ItemProperty -Path $ExecutionHistoryRegistryPath -Name $ExecutionHistoryRegistryValue -Value $ExecutionHistoryCount -ErrorAction "SilentlyContinue"

        # Log remediation script trigger
        Write-LogEntry -Value "Triggering remediation script" -Severity 1
        Write-LogEntry -Value "[$($ProactiveRemediationName)-Detection] - Completed" -Severity 1
        exit 1
    }
    else {
        Write-LogEntry -Value "[$($ProactiveRemediationName)-Detection] - Completed" -Severity 1
    }
}