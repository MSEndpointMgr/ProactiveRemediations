<#
.SYNOPSIS
    Proaction Remediation script for cleaning up the local harddrive.

.DESCRIPTION
    This is the remediation script for a Proactive Remediation in Endpoint Analytics used by the Disk Cleanup solution.

.EXAMPLE
    .\Remediation.ps1

.NOTES
    FileName:    Remediation.ps1
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

    # Enable TLS 1.2 support for downloading modules from PSGallery
	[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
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

    function Get-OutlookDefaultProfileFilePathAllUserProfiles {
        Begin {
            # Declare list to store user profiles
            $UserProfileList = New-Object -TypeName "System.Collections.Generic.List[System.Object]"
    
            # Declare variable to store system specific profiles
            $SystemProfiles = "S-1-5-18", "S-1-5-19", "S-1-5-20"
        }
        Process {
            # Retrieve all user profiles, exclude system specific profiles
            $RegistryUserProfileListKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
            Write-LogEntry -Value "Reading list of user profiles from: $($RegistryUserProfileListKey)" -Severity 1
            
            try {
                $UserProfiles = Get-ChildItem -Path $RegistryUserProfileListKey -ErrorAction "Stop"
                foreach ($UserProfile in $UserProfiles) {
                    Write-LogEntry -Value "Found user profile: $($UserProfile.PSChildName)" -Severity 1
    
                    try {
                        # Convert current user profile SID to NTAccount
                        $NTAccountSID = New-Object -TypeName "System.Security.Principal.SecurityIdentifier" -ArgumentList $UserProfile.PSChildName
                        $NTAccount = $NTAccountSID.Translate([Security.Principal.NTAccount])
    
                        # Get user profile properties
                        $ProfileProperties = Get-ItemProperty -Path $UserProfile.PSPath | Where-Object { ($PSItem.ProfileImagePath) }
    
                        # Determine if user profile is a local account
                        $LocalAccount = Get-CimInstance -ClassName "Win32_Account" -Filter "SID like '$($UserProfile.PSChildName)'"
    
                        # Add user profile to list if it is not a system profile and matches the corporate domain name
                        if ($UserProfile.PSChildName -notin $SystemProfiles) {
                            if ($LocalAccount -eq $null) {
                                Write-LogEntry -Value "User profile is not a local account, adding to user list" -Severity 1
                                $UserProfileList.Add([PSCustomObject]@{
                                    SID = $UserProfile.PSChildName
                                    NTAccount = $NTAccount.Value
                                    ProfileImagePath = $ProfileProperties.ProfileImagePath
                                })
                            }
                            else {
                                Write-LogEntry -Value "User profile is a local account, skipping" -Severity 2
                            }
                        }
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value "Failed to translate and process user profile: $($UserProfile.PSChildName). Error message: $($_.Exception.Message)" -Severity 3
                    }
                }
    
                # Handle user profile list construction completion output
                Write-LogEntry -Value "User profile list construction completed" -Severity 1
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to construct list of user profiles. Error message: $($_.Exception.Message)" -Severity 3
            }
    
            # Continue if user profiles were found
            if ($UserProfileList.Count -ge 1) {
                Write-LogEntry -Value "Total count of '$($UserProfileList.Count)' user profiles to be processed" -Severity 1
    
                # Construct a list object to contain Outlook default profile file path for each user profile
                $OutlookDefaultProfileFilePathList = New-Object -TypeName "System.Collections.Generic.List[System.Object]"
    
                # Process each user profile in list and load user registry hive
                foreach ($UserProfile in $UserProfileList) {
                    Write-LogEntry -Value "Processing current user profile for account: $($UserProfile.NTAccount)" -Severity 1
    
                    # Load user registry hive
                    $UserRegistryHiveFilePath = Join-Path -Path $UserProfile.ProfileImagePath -ChildPath "NTUSER.DAT"
                    Write-LogEntry -Value "User registry hive local file path: $($UserRegistryHiveFilePath)" -Severity 1
                    
                    # Check if user registry hive exists
                    $UserRegistryPath = "Registry::HKEY_USERS\$($UserProfile.SID)"
                    Write-LogEntry -Value "Check if user registry hive registry path exist: $($UserRegistryPath)" -Severity 1
                    
                    # Test if user registry hive is currently loaded
                    if (Test-Path -Path $UserRegistryPath) {
                        Write-LogEntry -Value "User registry hive is currently loaded: $($UserRegistryPath)" -Severity 1
                        $UserRegistryHiveLoadRequired = $false
                    }
                    else {
                        Write-LogEntry -Value "User registry hive is not currently loaded: $($UserRegistryPath)" -Severity 1
                        $UserRegistryHiveLoadRequired = $true
                    }
    
                    # Load user registry hive if required
                    if ($UserRegistryHiveLoadRequired -eq $true) {
                        # Load user registry hive from local file path
                        if (Test-Path -Path $UserRegistryHiveFilePath -PathType "Leaf") {
                            # Declare variable for reg.exe executable path
                            $RegExecutable = Join-Path -Path $env:Windir -ChildPath "System32\reg.exe"
    
                            # Declare arguments for reg.exe to load the current user profile registry hive
                            $RegArguments = "load ""HKEY_USERS\$($UserProfile.SID)"" ""$($UserRegistryHiveFilePath)"""
                            
                            try {
                                # Load current user profile registry hive
                                Write-LogEntry -Value "Invoking command: $($RegExecutable) $($RegArguments)" -Severity 1
                                Start-Process -FilePath $RegExecutable -ArgumentList $RegArguments -Wait -ErrorAction "Stop"
                                Write-LogEntry -Value "Successfully loaded user registry hive: $($UserRegistryHiveFilePath)" -Severity 1
                            }
                            catch [System.Exception] {
                                Write-LogEntry -Value "Failed to load user registry hive: $($UserRegistryHiveFilePath)" -Severity 3
                            }
                        }
                        else {
                            Write-LogEntry -Value "User registry hive could not be found: $($UserRegistryPath)" -Severity 3
                        }
                    }
    
                    try {
                        # Retrieve Outlook default profile value
                        Write-LogEntry -Value "Reading Outlook default profile for user: $($UserProfile.NTAccount)" -Severity 1                                
                        $DefaultProfile = Get-ItemPropertyValue -Path "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Office\16.0\Outlook" -Name "DefaultProfile" -ErrorAction "Stop"
                        Write-LogEntry -Value "Outlook default profile value: $($DefaultProfile)" -Severity 1
    
                        try {
                            # Locate the registry key that contains the registry value named as 001f6610
                            $DefaultProfileSettingsRegistryPath = "Registry::HKEY_USERS\$($UserProfile.SID)\SOFTWARE\Microsoft\Office\16.0\Outlook\Profiles\$($DefaultProfile)"
                            Write-LogEntry -Value "Outlook default profile settings registry path: $($DefaultProfileSettingsRegistryPath)" -Severity 1

                            try {
                                # Retrieve the registry item that contains the registry value named as 001f6610
                                $DefaultProfileSettingsItem = Get-ChildItem -Path $DefaultProfileSettingsRegistryPath -ErrorAction "Stop" | Where-Object { $PSItem.Property -like "001f6610" }
                                if ($DefaultProfileSettingsItem -ne $null) {
                                    # Declare variable for Outlook default profile settings registry path
                                    $DefaultProfileSettingsPath = Join-Path -Path "Registry::" -ChildPath $DefaultProfileSettingsItem.Name
                                    Write-LogEntry -Value "Outlook default profile settings item path: $($DefaultProfileSettingsPath)" -Severity 1

                                    if (Test-Path -Path $DefaultProfileSettingsPath) {
                                        # Retrieve Outlook default profile file path byte value representation
                                        $OutlookDefaultProfileByteArray = [byte[]](Get-ItemPropertyValue -Path $DefaultProfileSettingsPath -Name "001f6610")
            
                                        # Convert byte array to string
                                        $OutlookDefaultProfileFilePath = [System.Text.Encoding]::Unicode.GetString($OutlookDefaultProfileByteArray).TrimEnd([char]0)
                                        Write-LogEntry -Value "Outlook default profile file path: $($OutlookDefaultProfileFilePath)" -Severity 1
            
                                        # Construct custom object to store user profile details and Outlook default profile file path
                                        $UserProfileDetails = [PSCustomObject]@{
                                            SID = $UserProfile.SID
                                            NTAccount = $UserProfile.NTAccount
                                            ProfileImagePath = $UserProfile.ProfileImagePath
                                            OutlookDefaultProfileFilePath = $OutlookDefaultProfileFilePath
                                        }
            
                                        # Add Outlook default profile file path to list
                                        $OutlookDefaultProfileFilePathList.Add($UserProfileDetails)
                                    }
                                    else {
                                        Write-LogEntry -Value "Outlook default profile settings path could not be found: $($DefaultProfileSettingsPath)" -Severity 3
                                    }
                                }
                                else {
                                    Write-LogEntry -Value "Registry value named as '001f6610' could not be found in any of the sub keys of: $($DefaultProfileSettingsRegistryPath)" -Severity 3
                                }
                            }
                            catch [System.Exception] {
                                Write-LogEntry -Value "Failed to locate registry key that contains the registry value named as '001f6610'" -Severity 3
                            }
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value "Failed to determine Outlook default profile file path for user: $($UserProfile.NTAccount)" -Severity 3
                        }
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value "Failed to determine Outlook default profile value for user: $($UserProfile.NTAccount)" -Severity 3
                    }
    
                    # Unload user registry hive
                    if ($UserRegistryHiveLoadRequired -eq $true) {
                        try {
                            # Initiate garbage collection to release user registry hive
                            Write-LogEntry -Value "Initiating garbage collection before user hive unload command" -Severity 1
                            [GC]::Collect()
                            [GC]::WaitForPendingFinalizers()
                            Start-Sleep -Seconds 5
    
                            # Unload current user profile registry hive
                            $RegArguments = "unload ""HKEY_USERS\$($UserProfile.SID)"""
                            Write-LogEntry -Value "Invoking command: $($RegExecutable) $($RegArguments)" -Severity 1
                            Start-Process -FilePath $RegExecutable -ArgumentList $RegArguments -Wait -ErrorAction "Stop"
                            Write-LogEntry -Value "Successfully unloaded user registry hive: $($UserRegistryHiveFilePath)" -Severity 1
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value "Failed to unload user registry hive: $($UserRegistryHiveFilePath)" -Severity 3
                        }
                    }                
                }
    
                # Handle return value
                return $OutlookDefaultProfileFilePathList
            }
            else {
                Write-LogEntry -Value "No user profiles found" -Severity 2
            }
        }
    }

    # Handle initial value for exit code variable
    $ExitCode = 0

    # Initial logging details for remediation script
    Write-LogEntry -Value "[$($ProactiveRemediationName)-Remediation] - Initializing" -Severity 1

    # Retrieve free disk space on system drive
    Write-LogEntry -Value "Retrieving free disk space on system drive from WMI class: Win32_LogicalDisk" -Severity 1
    $FreeDiskSpaceBefore = [math]::Round((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'" -ErrorAction "Stop" | Select-Object -ExpandProperty FreeSpace) / 1GB, 2)
    Write-LogEntry -Value "Free disk space on system drive: $($FreeDiskSpaceBefore) GB" -Severity 1

    try {
        # Clear existing sage run settings
        Write-LogEntry -Value "Removing existing CleanMgr.exe sage run settings" -Severity 1
        Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\*" -Name "StateFlags0001" -ErrorAction "SilentlyContinue" | Remove-ItemProperty -Name "StateFlags0001" -ErrorAction "Stop"

        # Enable sage run settings
        $SageRunSettings = @("Update Cleanup", "Temporary Files", "Delivery Optimization Files", "Previous Installations", "Downloaded Program Files", "Recycle Bin", "Internet Cache Files", "Device Driver Packages", "Thumbnail Cache")
        foreach ($SageRunSetting in $SageRunSettings) {
            try {
                Write-LogEntry -Value "Enabling '$($SageRunSetting)' sage run setting" -Severity 1
                $RegistryValue = New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\$($SageRunSetting)" -Name "StateFlags0001" -Value 2 -PropertyType DWord -ErrorAction "Stop"
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to enable '$($SageRunSetting)' sage run setting. Error message: $($_.Exception.Message)" -Severity 3
                $ExitCode = 1
            }
        }

        try {
            # Declare variables for scheduled task creation for path and name
            $TaskPath = "\"
            $TaskName = "Disk Cleanup"

            # Check if scheduled task already exists
            $ScheduledTaskExists = Get-ScheduledTask -TaskName $TaskName -ErrorAction "SilentlyContinue"
            if ($ScheduledTaskExists -ne $null) {
                Write-LogEntry -Value "Scheduled task already exists: $($TaskName)" -Severity 1

                try {
                    # Unregister scheduled task
                    Write-LogEntry -Value "Unregistering scheduled task: $($TaskName)" -Severity 1
                    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction "Stop"
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to unregister scheduled task. Error message: $($_.Exception.Message)" -Severity 3
                    $ExitCode = 1
                }
            }

            try {
                # Construct required scheduled task objects with action, principal and settings
                $TaskAction = New-ScheduledTaskAction -Execute "CleanMgr.exe" -Argument "/sagerun:1"
                $TaskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -Hidden -DontStopIfGoingOnBatteries -Compatibility "Win8" -MultipleInstances "IgnoreNew" -ErrorAction Stop
                $TaskPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType "ServiceAccount" -RunLevel "Highest" -ErrorAction "Stop"

                try {
                    # Register scheduled task with constructed objects
                    Write-LogEntry -Value "Registering scheduled task: $($TaskName)" -Severity 1
                    $ScheduledTask = New-ScheduledTask -Action $TaskAction -Principal $TaskPrincipal -Settings $TaskSettings -ErrorAction "Stop"
                    $ScheduledTask = Register-ScheduledTask -InputObject $ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction "Stop"

                    try {
                        # Run scheduled task
                        Write-LogEntry -Value "Running scheduled task: $($TaskName)" -Severity 1
                        Start-ScheduledTask -TaskName $TaskName -ErrorAction "Stop"

                        # Construct stop watch object to measure elapsed time and define timeout of 30 minutes
                        $StopWatch = [System.Diagnostics.Stopwatch]::StartNew()
                        $Timeout = 1800

                        # Wait for scheduled task to complete
                        Write-LogEntry -Value "Waiting for scheduled task to complete" -Severity 1
                        while ($StopWatch.Elapsed.TotalSeconds -lt $Timeout) {
                            $ScheduledTaskState = Get-ScheduledTask -TaskName $TaskName | Select-Object -ExpandProperty "State"
                            if ($ScheduledTaskState -eq "Ready") {
                                Write-LogEntry -Value "Scheduled task completed" -Severity 1
                                break
                            }
                            else {
                                Start-Sleep -Seconds 1
                            }
                        }

                        # Stop stop watch object
                        $StopWatch.Stop()

                        # Handle final log output for scheduled task completion
                        Write-LogEntry -Value "Disk Cleanup activities completed" -Severity 1
                    }
                    catch [System.Exception] {
                        Write-LogEntry -Value "Failed to run scheduled task. Error message: $($_.Exception.Message)" -Severity 3
                        $ExitCode = 1
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to register scheduled task. Error message: $($_.Exception.Message)" -Severity 3
                    $ExitCode = 1
                }
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to construct scheduled task objects. Error message: $($_.Exception.Message)" -Severity 3
                $ExitCode = 1
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Failed to execute Disk Cleanup utility. Error message: $($_.Exception.Message)" -Severity 3
            $ExitCode = 1
        }
    }
    catch [System.Exception] {
        Write-LogEntry -Value "Failed to clear CleanMgr.exe sage run settings. Error message: $($_.Exception.Message)" -Severity 3
        $ExitCode = 1
    }

    try {
        # Retrieve Outlook .ost file paths for all user profiles
        Write-LogEntry -Value "Initiating cleanup of Outlook unused .ost files" -Severity 1
        $OutlookDefaultProfileFilePathList = Get-OutlookDefaultProfileFilePathAllUserProfiles

        if ($OutlookDefaultProfileFilePathList -ne $null) {
            # Find all .ost files in all users' Outlook app data folders
            $OutlookOSTFiles = Get-ChildItem -Path "$($env:SystemDrive)\Users\*\AppData\Local\Microsoft\Outlook" -Filter "*.ost" -Recurse -ErrorAction "SilentlyContinue"
            if ($OutlookOSTFiles -ne $null) {
                Write-LogEntry -Value "Found a total of '$($OutlookOSTFiles.Count)' Outlook .ost files in all users' specific Outlook app data folder" -Severity 1

                # Remove all .ost files found, except if they're in the list of default profile file paths list
                foreach ($OutlookOSTFile in $OutlookOSTFiles) {
                    Write-LogEntry -Value "Checking if current .ost file '$($OutlookOSTFile.FullName)' is in the list of default profiles" -Severity 1
                    if ($OutlookDefaultProfileFilePathList.OutlookDefaultProfileFilePath -notcontains $OutlookOSTFile.FullName) {
                        # Determine the count of days since the .ost file was last accessed
                        $LastAccessTime = (Get-Item -Path $OutlookOSTFile.FullName).LastAccessTime
                        $DaysSinceLastAccess = [math]::Round((New-TimeSpan -Start $LastAccessTime -End (Get-Date)).TotalDays)
                        Write-LogEntry -Value "Last access time for current .ost file: $($LastAccessTime). Days since last access: $($DaysSinceLastAccess)" -Severity 1

                        # Remove .ost file if it has not been accessed within the last 90 days
                        if ($DaysSinceLastAccess -ge 90) {
                            try {
                                # Remove .ost file
                                Write-LogEntry -Value "Removing Outlook .ost file: $($OutlookOSTFile.FullName)" -Severity 1
                                Remove-Item -Path $OutlookOSTFile.FullName -Force -ErrorAction "Stop"
                            }
                            catch [System.Exception] {
                                Write-LogEntry -Value "Failed to remove Outlook .ost file '$($OutlookOSTFile.FullName)'. Error message: $($_.Exception.Message)" -Severity 3
                                $ExitCode = 1
                            }
                        }
                        else {
                            Write-LogEntry -Value "Skipping removal of Outlook .ost file '$($OutlookOSTFile.FullName)' since it was last accessed within the 90 day threshold" -Severity 1
                        }
                    }
                    else {
                        Write-LogEntry -Value "Skipping removal of Outlook .ost file: $($OutlookOSTFile.FullName)" -Severity 1
                    }
                }

                # Handle cleanup completion log output
                Write-LogEntry -Value "Cleanup of Outlook .ost files completed" -Severity 1
            }
            else {
                Write-LogEntry -Value "No Outlook .ost files found in any user's specific Outlook app data folder" -Severity 1
            }
        }
    }
    catch [System.Exception] {
        Write-LogEntry -Value "Failed to process Outlook .ost files. Error message: $($_.Exception.Message)" -Severity 3
        $ExitCode = 1
    }

    # Locate Teams cache folders for all user profiles and clean the content of the folders
    try {
        # Retrieve Teams cache folders for all user profiles
        Write-LogEntry -Value "Initiating cleanup of Teams cache folders" -Severity 1
        $TeamsCacheFolders = Get-ChildItem -Path "$($env:SystemDrive)\Users\*\AppData\Roaming\Microsoft\Teams\Cache" -ErrorAction "SilentlyContinue"
        if ($TeamsCacheFolders -ne $null) {
            Write-LogEntry -Value "Found a total of '$($TeamsCacheFolders.Count)' Teams cache folders in all user's specific Teams app data folder" -Severity 1

            # Clean the content of all Teams cache folders found
            foreach ($TeamsCacheFolder in $TeamsCacheFolders) {
                if (Test-Path -Path $TeamsCacheFolder.FullName) {
                    # Get count of files and folders present in the Teams cache folder
                    $TeamsCacheFolderItems = Get-ChildItem -Path $TeamsCacheFolder.FullName -Recurse -ErrorAction "SilentlyContinue"
                    $TeamsCacheFoldersItemsCount = ($TeamsCacheFolderItems | Measure-Object).Count
                    Write-LogEntry -Value "Found a total of '$($TeamsCacheFoldersItemsCount)' items in Teams cache folder: $($TeamsCacheFolder.FullName)" -Severity 1

                    # Attempt to remove each item in the Teams cache folder
                    Write-LogEntry -Value "Removing items from Teams cache folder: $($TeamsCacheFolder.FullName)" -Severity 1
                    foreach ($TeamsCacheFolderItem in $TeamsCacheFolderItems) {
                        try {
                            # Remove item from Teams cache folder
                            Remove-Item -Path $TeamsCacheFolderItem.FullName -Recurse -Force -Confirm:$false -ErrorAction "Stop"
                        }
                        catch [System.Exception] {
                            Write-LogEntry -Value "Failed to remove item from Teams cache folder '$($TeamsCacheFolder.FullName)'. Error message: $($_.Exception.Message)" -Severity 3
                        }
                    }
                }
                else {
                    Write-LogEntry -Value "Teams cache folder '$($TeamsCacheFolder.FullName)' does not exist" -Severity 2
                }
            }

            # Handle cleanup completion log output
            Write-LogEntry -Value "Cleanup of Teams cache folders completed" -Severity 1
        }
        else {
            Write-LogEntry -Value "No Teams cache folders found in any users' specific Teams app data folder" -Severity 1
        }
    }
    catch [System.Exception] {
        Write-LogEntry -Value "Failed to process Teams cache folders. Error message: $($_.Exception.Message)" -Severity 3
        $ExitCode = 1
    }

    # Retrieve free disk space on system drive after cleanup
    $FreeDiskSpaceAfter = [math]::Round((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'" -ErrorAction "Stop" | Select-Object -ExpandProperty FreeSpace) / 1GB, 2)
    $CleanedUpDiskSpace = [math]::Round($FreeDiskSpaceAfter - $FreeDiskSpaceBefore, 2)
    Write-LogEntry -Value "Cleanup activities cleaned up a total of: $($CleanedUpDiskSpace) GB" -Severity 1

    # Final logging details for remediation script
    Write-LogEntry -Value "[$($ProactiveRemediationName)-Remediation] - Completed" -Severity 1

    # Handle output
    Write-Output -InputObject "Cleaned up a total of: $($CleanedUpDiskSpace) GB"

    # Handle exit code
    exit $ExitCode
}