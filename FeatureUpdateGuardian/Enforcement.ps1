<#
.SYNOPSIS
    Proactive Remediation script for ensuring stability and optimization prior to a Windows Feature Update.

.DESCRIPTION
    This is the enforcement script for a Proactive Remediation in Endpoint Analytics used for ensuring stability and optimization prior to a Windows Feature Update.

.EXAMPLE
    .\Enforcement.ps1

.NOTES
    FileName:    Enforcement.ps1
    Author:      Nickolaj Andersen
    Contact:     @NickolajA
    Created:     2025-12-02
    Updated:     2026-01-23

    Version history:
    1.0.0 - (2025-12-02) Script created
    1.0.1 - (2026-01-23) Added more cleanup routines in local app data folders
#>
Begin {
    # Define the proactive remediation name
    $ProactiveRemediationName = "FeatureUpdateGuardian"

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
        # Always use the IntuneManagementExtension logs folder
        $LogFilePath = Join-Path -Path (Join-Path -Path $env:ProgramData -ChildPath "Microsoft\IntuneManagementExtension\Logs") -ChildPath $FileName

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

    function Remove-SpecificFiles {
        param (
            [Parameter(Mandatory = $true)]
            [string[]]$FilePaths
        )

        Begin {
            # Log beginning of specific files removal process
            Write-LogEntry -Value "Beginning process for removal of specific files" -Severity 1
            Write-LogEntry -Value "Total specific files provided for processing: $($FilePaths.Count)" -Severity 1
        }

        Process {
            # Process each specific file
            foreach ($FilePath in $FilePaths) {
                # Log current file being processed
                Write-LogEntry -Value "Processing specific file: $($FilePath)" -Severity 1

                # Check if file exists
                if (Test-Path -Path $FilePath -PathType Leaf) {
                    try {
                        # Remove the specific file
                        Remove-Item -Path $FilePath -Force -ErrorAction Stop

                        # Log successful removal
                        Write-LogEntry -Value "Successfully removed specific file: $($FilePath)" -Severity 1
                    }
                    catch [System.Exception] {
                        # Log failure to remove file
                        Write-LogEntry -Value "Failed to remove specific file: $($FilePath). Error message: $($_.Exception.Message)" -Severity 3
                    }
                }
                else {
                    # Log file not found
                    Write-LogEntry -Value "Specific file not found: $($FilePath)" -Severity 2
                }
            }
        }

        End {
            # Log completion of specific files removal
            Write-LogEntry -Value "Specific files removal process completed" -Severity 1
        }
    }

    function Clear-DirectoryContents {
        param (
            [Parameter(Mandatory = $true)]
            [string[]]$DirectoryPaths
        )

        Begin {
            # Log beginning of directory contents clearing process
            Write-LogEntry -Value "Beginning process for clearing directory contents" -Severity 1
            Write-LogEntry -Value "Total directories provided for processing: $($DirectoryPaths.Count)" -Severity 1
        }

        Process {
            # Process each directory
            foreach ($DirectoryPath in $DirectoryPaths) {
                # Log current directory being processed
                Write-LogEntry -Value "Processing directory: $($DirectoryPath)" -Severity 1

                # Check if directory exists
                if (Test-Path -Path $DirectoryPath -PathType Container) {
                    try {
                        # Remove all contents recursively
                        Remove-Item -Path "$($DirectoryPath)\*" -Recurse -Force -ErrorAction SilentlyContinue

                        # Log successful clearing
                        Write-LogEntry -Value "Successfully cleared contents of directory: $($DirectoryPath)" -Severity 1
                    }
                    catch [System.Exception] {
                        # Log failure to clear directory
                        Write-LogEntry -Value "Failed to clear directory: $($DirectoryPath). Error message: $($_.Exception.Message)" -Severity 3
                    }
                }
                else {
                    # Log directory not found
                    Write-LogEntry -Value "Directory not found: $($DirectoryPath)" -Severity 2
                }
            }
        }

        End {
            # Log completion of directory contents clearing
            Write-LogEntry -Value "Directory contents clearing process completed" -Severity 1
        }
    }

    # Initial logging details for enforcement script
    Write-LogEntry -Value "[$($ProactiveRemediationName)-Enforcement] - Initializing" -Severity 1

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
            }
        }

        try {
            # Declare variables for scheduled task creation for path and name
            $TaskPath = "\"
            $TaskName = "FeatureUpdate - Disk Cleanup"

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
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to register scheduled task. Error message: $($_.Exception.Message)" -Severity 3
                }
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Failed to construct scheduled task objects. Error message: $($_.Exception.Message)" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Failed to execute Disk Cleanup utility. Error message: $($_.Exception.Message)" -Severity 3
        }
    }
    catch [System.Exception] {
        Write-LogEntry -Value "Failed to clear CleanMgr.exe sage run settings. Error message: $($_.Exception.Message)" -Severity 3
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
    }

    # LocalAppData caches cleanup
    try {
        Write-LogEntry -Value "Beginning LocalAppData caches cleanup process for all user profiles" -Severity 1

        # Declare lists for directories and specific files
        $DirectoryPathsList = New-Object -TypeName "System.Collections.Generic.List[string]"
        $SpecificFilesList = New-Object -TypeName "System.Collections.Generic.List[string]"

        # Retrieve all user profiles, exclude system specific profiles
        $RegistryUserProfileListKey = "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
        $SystemProfiles = "S-1-5-18", "S-1-5-19", "S-1-5-20"
        Write-LogEntry -Value "Reading list of user profiles from: $($RegistryUserProfileListKey)" -Severity 1

        $UserProfiles = Get-ChildItem -Path $RegistryUserProfileListKey -ErrorAction "Stop"
        $UserProfileList = New-Object -TypeName "System.Collections.Generic.List[System.Object]"

        foreach ($UserProfile in $UserProfiles) {
            if ($UserProfile.PSChildName -notin $SystemProfiles) {
                try {
                    $ProfileProperties = Get-ItemProperty -Path $UserProfile.PSPath -ErrorAction "Stop"
                    if ($ProfileProperties.ProfileImagePath) {
                        # Determine if user profile is a local account
                        $LocalAccount = Get-CimInstance -ClassName "Win32_Account" -Filter "SID like '$($UserProfile.PSChildName)'" -ErrorAction "SilentlyContinue"
                        
                        if ($LocalAccount -eq $null) {
                            Write-LogEntry -Value "Found user profile (non-local): $($ProfileProperties.ProfileImagePath)" -Severity 1
                            $UserProfileList.Add([PSCustomObject]@{
                                SID = $UserProfile.PSChildName
                                ProfileImagePath = $ProfileProperties.ProfileImagePath
                            })
                        }
                        else {
                            Write-LogEntry -Value "Skipping local account: $($ProfileProperties.ProfileImagePath)" -Severity 2
                        }
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to process user profile: $($UserProfile.PSChildName). Error message: $($_.Exception.Message)" -Severity 3
                }
            }
        }

        Write-LogEntry -Value "Found $($UserProfileList.Count) user profiles to process for cache cleanup" -Severity 1

        # Process each user profile
        foreach ($UserProfile in $UserProfileList) {
            Write-LogEntry -Value "Processing cache cleanup for user profile: $($UserProfile.ProfileImagePath)" -Severity 1

            # General Temp directory
            $LocalAppDataTempPath = Join-Path -Path $UserProfile.ProfileImagePath -ChildPath "AppData\Local\Temp"
            Write-LogEntry -Value "Checking general temp directory: $($LocalAppDataTempPath)" -Severity 1
            if (Test-Path $LocalAppDataTempPath) {
                Write-LogEntry -Value "Found general temp directory, adding to directory list" -Severity 1
                $DirectoryPathsList.Add($LocalAppDataTempPath)
            }
            else {
                Write-LogEntry -Value "General temp directory not found" -Severity 2
            }

            # Microsoft Edge caches
            $EdgeUserDataPath = Join-Path -Path $UserProfile.ProfileImagePath -ChildPath "AppData\Local\Microsoft\Edge\User Data"
            Write-LogEntry -Value "Checking Edge base directory: $($EdgeUserDataPath)" -Severity 1
            if (Test-Path $EdgeUserDataPath) {
                try {
                    Write-LogEntry -Value "Retrieving list of Edge profiles from base directory" -Severity 1
                    $EdgeProfiles = Get-ChildItem $EdgeUserDataPath -Directory -ErrorAction Stop | Where-Object { $_.Name -match 'Default|Profile \d+|Guest Profile' }
                    Write-LogEntry -Value "Found $($EdgeProfiles.Count) Edge profiles matching criteria" -Severity 1

                    if ($EdgeProfiles.Count -eq 0) {
                        Write-LogEntry -Value "No Edge profiles found matching the criteria" -Severity 2
                    }

                    $EdgeCacheSubfolders = @('Cache', 'Code Cache', 'GPUCache', 'DawnCache', 'Service Worker\CacheStorage')
                    Write-LogEntry -Value "Defined Edge cache subfolders to check: $($EdgeCacheSubfolders -join ', ')" -Severity 1

                    foreach ($EdgeProfile in $EdgeProfiles) {
                        Write-LogEntry -Value "Processing Edge profile: $($EdgeProfile.Name)" -Severity 1

                        foreach ($CacheSubfolder in $EdgeCacheSubfolders) {
                            $EdgeCacheTargetPath = Join-Path -Path $EdgeProfile.FullName -ChildPath $CacheSubfolder
                            Write-LogEntry -Value "Checking for cache subfolder '$($CacheSubfolder)' in profile '$($EdgeProfile.Name)': $($EdgeCacheTargetPath)" -Severity 1

                            if (Test-Path $EdgeCacheTargetPath) {
                                Write-LogEntry -Value "Found Edge cache directory, adding to directory list: $($EdgeCacheTargetPath)" -Severity 1
                                $DirectoryPathsList.Add($EdgeCacheTargetPath)
                            }
                            else {
                                Write-LogEntry -Value "Cache subfolder not found: $($EdgeCacheTargetPath)" -Severity 2
                            }
                        }
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to process Edge profiles. Error message: $($_.Exception.Message)" -Severity 3
                }
            }
            else {
                Write-LogEntry -Value "Edge base directory not found" -Severity 2
            }

            # Microsoft Office caches
            $OfficeLocalAppDataPath = Join-Path -Path $UserProfile.ProfileImagePath -ChildPath "AppData\Local\Microsoft\Office"
            Write-LogEntry -Value "Checking Office base directory: $($OfficeLocalAppDataPath)" -Severity 1
            if (Test-Path $OfficeLocalAppDataPath) {
                try {
                    $OfficeVersionFolders = Get-ChildItem $OfficeLocalAppDataPath -Directory -ErrorAction Stop | Where-Object { $_.Name -match '^\d+\.\d+$' }
                    Write-LogEntry -Value "Found $($OfficeVersionFolders.Count) Office version folders" -Severity 1

                    foreach ($OfficeVersionFolder in $OfficeVersionFolders) {
                        Write-LogEntry -Value "Processing Office version: $($OfficeVersionFolder.Name)" -Severity 1
                        $OfficeCacheTargets = @(
                            Join-Path -Path $OfficeVersionFolder.FullName -ChildPath 'OfficeFileCache'
                            Join-Path -Path $OfficeVersionFolder.FullName -ChildPath 'Wef'
                        )
                        foreach ($OfficeCacheTarget in $OfficeCacheTargets) {
                            if (Test-Path $OfficeCacheTarget) {
                                Write-LogEntry -Value "Found Office cache directory, adding to directory list: $($OfficeCacheTarget)" -Severity 1
                                $DirectoryPathsList.Add($OfficeCacheTarget)
                            }
                        }
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to process Office versions. Error message: $($_.Exception.Message)" -Severity 3
                }
            }
            else {
                Write-LogEntry -Value "Office base directory not found" -Severity 2
            }

            # Microsoft Teams cache
            $TeamsLocalCachePath = Join-Path -Path $UserProfile.ProfileImagePath -ChildPath "AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams"
            Write-LogEntry -Value "Checking Teams cache directory: $($TeamsLocalCachePath)" -Severity 1
            if (Test-Path $TeamsLocalCachePath) {
                try {
                    # Enumerate all subdirectories in Teams cache, excluding Backgrounds to preserve user uploads
                    $TeamsCacheSubfolders = Get-ChildItem -Path $TeamsLocalCachePath -Directory -ErrorAction Stop
                    Write-LogEntry -Value "Found $($TeamsCacheSubfolders.Count) Teams cache subdirectories" -Severity 1
                    
                    foreach ($TeamsCacheSubfolder in $TeamsCacheSubfolders) {
                        if ($TeamsCacheSubfolder.Name -eq "Backgrounds") {
                            Write-LogEntry -Value "Skipping Teams Backgrounds folder to preserve user uploads: $($TeamsCacheSubfolder.FullName)" -Severity 1
                        }
                        else {
                            Write-LogEntry -Value "Found Teams cache directory, adding to directory list: $($TeamsCacheSubfolder.FullName)" -Severity 1
                            $DirectoryPathsList.Add($TeamsCacheSubfolder.FullName)
                        }
                    }
                }
                catch [System.Exception] {
                    Write-LogEntry -Value "Failed to process Teams cache subdirectories. Error message: $($_.Exception.Message)" -Severity 3
                }
            }
            else {
                Write-LogEntry -Value "Teams cache directory not found" -Severity 2
            }

            # Adobe caches
            $AdobeCachePaths = @(
                Join-Path -Path $UserProfile.ProfileImagePath -ChildPath "AppData\Local\Adobe\CameraRaw\Cache"
                Join-Path -Path $UserProfile.ProfileImagePath -ChildPath "AppData\Local\Adobe\UXP\Cache"
            )
            foreach ($AdobeCachePath in $AdobeCachePaths) {
                Write-LogEntry -Value "Checking Adobe cache directory: $($AdobeCachePath)" -Severity 1
                if (Test-Path $AdobeCachePath) {
                    Write-LogEntry -Value "Found Adobe cache directory, adding to directory list" -Severity 1
                    $DirectoryPathsList.Add($AdobeCachePath)
                }
            }

            # Additional common directories
            $AdditionalCommonDirectories = @(
                Join-Path -Path $UserProfile.ProfileImagePath -ChildPath "AppData\Local\CrashDumps"
                Join-Path -Path $UserProfile.ProfileImagePath -ChildPath "AppData\Local\Microsoft\OneDrive\Cache"
                Join-Path -Path $UserProfile.ProfileImagePath -ChildPath "AppData\Local\pip\cache"
                Join-Path -Path $UserProfile.ProfileImagePath -ChildPath "AppData\Local\Microsoft\OneDrive\logs"
            )
            foreach ($AdditionalDirectory in $AdditionalCommonDirectories) {
                Write-LogEntry -Value "Checking extra directory: $($AdditionalDirectory)" -Severity 1
                if (Test-Path $AdditionalDirectory) {
                    Write-LogEntry -Value "Found extra directory, adding to directory list" -Severity 1
                    $DirectoryPathsList.Add($AdditionalDirectory)
                }
            }

            # NuGet caches
            $NuGetGlobalPackagesPath = Join-Path -Path $UserProfile.ProfileImagePath -ChildPath ".nuget\packages"
            Write-LogEntry -Value "Checking NuGet global packages directory: $($NuGetGlobalPackagesPath)" -Severity 1
            if (Test-Path $NuGetGlobalPackagesPath) {
                Write-LogEntry -Value "Found NuGet global packages directory, adding to directory list" -Severity 1
                $DirectoryPathsList.Add($NuGetGlobalPackagesPath)
            }

            $NuGetLocalAppDataPath = Join-Path -Path $UserProfile.ProfileImagePath -ChildPath "AppData\Local\NuGet"
            Write-LogEntry -Value "Checking NuGet local base directory: $($NuGetLocalAppDataPath)" -Severity 1
            if (Test-Path $NuGetLocalAppDataPath) {
                $NuGetLocalCacheSubfolders = @('Cache', 'v3-cache', 'plugins-cache')
                foreach ($NuGetLocalSubfolder in $NuGetLocalCacheSubfolders) {
                    $NuGetLocalCachePath = Join-Path -Path $NuGetLocalAppDataPath -ChildPath $NuGetLocalSubfolder
                    if (Test-Path $NuGetLocalCachePath) {
                        Write-LogEntry -Value "Found NuGet local cache directory, adding to directory list: $($NuGetLocalCachePath)" -Severity 1
                        $DirectoryPathsList.Add($NuGetLocalCachePath)
                    }
                }
            }
        }

        # GlobalProtect logs (system-wide, not per-user)
        $GlobalProtectInstallPath = Join-Path -Path $env:ProgramFiles -ChildPath "Palo Alto Networks\GlobalProtect"
        Write-LogEntry -Value "Checking GlobalProtect base directory: $($GlobalProtectInstallPath)" -Severity 1

        if (Test-Path $GlobalProtectInstallPath) {
            $GlobalProtectLogFileNames = @(
                "PanGPS.log"
                "pan_gp_event.log"
            )

            foreach ($GlobalProtectLogFileName in $GlobalProtectLogFileNames) {
                $GlobalProtectLogFilePath = Join-Path -Path $GlobalProtectInstallPath -ChildPath $GlobalProtectLogFileName

                if (Test-Path $GlobalProtectLogFilePath) {
                    Write-LogEntry -Value "Found GlobalProtect log file, adding to specific files list: $($GlobalProtectLogFilePath)" -Severity 1
                    $SpecificFilesList.Add($GlobalProtectLogFilePath)
                }
            }

            if ($SpecificFilesList.Count -gt 0) {
                Write-LogEntry -Value "GlobalProtect log files detected. Administrator privileges may be required for removal." -Severity 2
            }
        }
        else {
            Write-LogEntry -Value "GlobalProtect base directory not found" -Severity 2
        }

        # Log completion of path collection
        Write-LogEntry -Value "Path collection phase completed" -Severity 1
        Write-LogEntry -Value "Total directories collected: $($DirectoryPathsList.Count)" -Severity 1
        Write-LogEntry -Value "Total specific files collected: $($SpecificFilesList.Count)" -Severity 1

        # Process directories if any were found
        if ($DirectoryPathsList.Count -ge 1) {
            Write-LogEntry -Value "Total count of '$($DirectoryPathsList.Count)' directories to be processed" -Severity 1
            Clear-DirectoryContents -DirectoryPaths $DirectoryPathsList.ToArray()
        }
        else {
            Write-LogEntry -Value "No directories found for processing" -Severity 2
        }

        # Process specific files if any were found
        if ($SpecificFilesList.Count -ge 1) {
            Write-LogEntry -Value "Total count of '$($SpecificFilesList.Count)' specific files to be processed" -Severity 1
            Remove-SpecificFiles -FilePaths $SpecificFilesList.ToArray()
        }
        else {
            Write-LogEntry -Value "No specific files found for processing" -Severity 2
        }

        # Log completion of overall cleanup
        Write-LogEntry -Value "LocalAppData caches cleanup process completed" -Severity 1
    }
    catch [System.Exception] {
        Write-LogEntry -Value "Failed to process LocalAppData caches cleanup. Error message: $($_.Exception.Message)" -Severity 3
    }

    # Clean up duplicate SID registry entries for WsiAccount user profile
    try {
        Write-LogEntry -Value "Initiating cleanup of duplicate SID registry entries for WsiAccount" -Severity 1
        
        # Parameters for WsiAccount cleanup
        $ProfilePath = Join-Path -Path $env:SystemDrive -ChildPath "Users\WsiAccount"
        $Username = "WsiAccount"

        Write-LogEntry -Value "Targeting profile: $($ProfilePath)" -Severity 1

        # Backup the ProfileList registry key
        $BackupPath = Join-Path -Path $env:Windir -ChildPath "Temp\ProfileList_Backup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
        $null = reg export "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" $BackupPath
        Write-LogEntry -Value "Registry backup created: $($BackupPath)" -Severity 1

        try {    
            # Get the correct SID for the username
            try {
                $CorrectSID = $null
                
                # Detect if the account exists
                $LocalAccount = Get-WmiObject -Class "Win32_UserAccount" -Filter "Name='$($Username)' AND LocalAccount=True" -ErrorAction "SilentlyContinue"
                if ($LocalAccount -ne $null) {
                    $CorrectSID = $LocalAccount.SID
                    Write-LogEntry -Value "Found SID via WMI (Local Account): $($CorrectSID)" -Severity 1
                    Write-LogEntry -Value "Correct SID for '$($Username)': $($CorrectSID)" -Severity 1

                    # Find ProfileList subkeys pointing to the target profile
                    $ProfileListRegPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
                    $SubKeys = Get-ChildItem -Path $ProfileListRegPath -ErrorAction SilentlyContinue
                    $DuplicateKeys = New-Object -TypeName System.Collections.Generic.List[PSObject]

                    # Check each subkey for matching ProfileImagePath
                    foreach ($SubKey in $SubKeys) {
                        $ImagePath = Get-ItemProperty -Path $SubKey.PSPath -Name "ProfileImagePath" -ErrorAction "SilentlyContinue"
                        if ($ImagePath -ne $null) {
                            if ($ImagePath.ProfileImagePath -eq $ProfilePath) {
                                $DuplicateKeys.Add(@{
                                    FullPath = $SubKey.PSPath
                                    SID = $SubKey.PSChildName
                                    IsCorrect = ($SubKey.PSChildName -eq $CorrectSID)
                                })
                            }
                        }
                    }

                    # Analyze found entries
                    if ($DuplicateKeys.Count -eq 0) {
                        Write-LogEntry -Value "No duplicate entries found for '$($ProfilePath)'" -Severity 1
                    } 
                    else {
                        if ($DuplicateKeys.Count -eq 1 -and $DuplicateKeys[0].IsCorrect) {
                            Write-LogEntry -Value "Only the correct entry found, no action needed" -Severity 1
                        }
                        else {
                            Write-LogEntry -Value "Found $($DuplicateKeys.Count) registry entries for: $($ProfilePath)" -Severity 1
                            
                            # Display all found entries for review
                            foreach ($DuplicateKey in $DuplicateKeys) {
                                $Status = if ($DuplicateKey.IsCorrect) { "CORRECT" } else { "DUPLICATE" }
                                Write-LogEntry -Value " - SID: $($DuplicateKey.SID) [$Status]" -Severity 1
                            }

                            # Delete duplicate keys (non-correct ones)
                            $DeletedCount = 0
                            foreach ($DuplicateKey in $DuplicateKeys) {
                                if (-not $DuplicateKey.IsCorrect) {
                                    try {
                                        Remove-Item -Path $DuplicateKey.FullPath -Recurse -Force
                                        Write-LogEntry -Value "Deleted duplicate SID: $($DuplicateKey.SID)" -Severity 1
                                        $DeletedCount++
                                    }
                                    catch [System.Exception] {
                                        Write-LogEntry -Value "Failed to delete SID $($DuplicateKey.SID): $($_.Exception.Message)" -Severity 3
                                    }
                                }
                            }

                            # Summary of deletions
                            Write-LogEntry -Value "Deleted '$($DeletedCount)' duplicate SID(s) for user profile: '$($ProfilePath)'" -Severity 1
                        }
                    }
                }
                else {
                    Write-LogEntry -Value "WsiAccount not found via WMI query - account may not exist or may not be a local account" -Severity 2
                }
            }
            catch [System.Exception] {
                Write-LogEntry -Value "Error retrieving SID: '$($_.Exception.Message)'" -Severity 3
            }
        }
        catch [System.Exception] {
            Write-LogEntry -Value "Failed to create registry backup for SID cleanup. Skipping further steps." -Severity 3
        }
        
        # Handle SID cleanup completion log output
        Write-LogEntry -Value "Cleanup of duplicate SID registry entries completed" -Severity 1
    }
    catch [System.Exception] {
        Write-LogEntry -Value "Failed to process duplicate SID registry entries cleanup. Error message: $($_.Exception.Message)" -Severity 3
    }

    # Retrieve free disk space on system drive after cleanup
    $FreeDiskSpaceAfter = [math]::Round((Get-WmiObject -Class Win32_LogicalDisk -Filter "DeviceID='$($env:SystemDrive)'" -ErrorAction "Stop" | Select-Object -ExpandProperty FreeSpace) / 1GB, 2)
    $CleanedUpDiskSpace = [math]::Round($FreeDiskSpaceAfter - $FreeDiskSpaceBefore, 2)
    Write-LogEntry -Value "Cleanup activities cleaned up a total of: $($CleanedUpDiskSpace) GB" -Severity 1

    # Handle output of free disk space after cleanup captured by Intune
    Write-Output -Value "Reclaimed space: $($CleanedUpDiskSpace) GB"

    # Final logging details for enforcement script
    Write-LogEntry -Value "[$($ProactiveRemediationName)-Enforcement] - Completed" -Severity 1
}