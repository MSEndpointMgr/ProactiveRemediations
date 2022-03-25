<#
.SYNOPSIS
Proactive Remeditiations Remediation Script to detect outdated versions of Chrome for cleanup 

.DESCRIPTION
Remediate outdated versions of Chrome for cleanup 
Remediate all user and machine based Chrome installs
Must be run as system

.NOTES
FileName:    detect.ps1
Author:      Jan Ketil Skanke / Sandy Zeng
Contact: @JankeSkanke @sandytsang
Contributor: 
Created:     2022-03-23
Updated:     2022-03-23

Version history:
1.0.0 - (2023-23-03) Script Created
#>

function Get-UserInstalledApplications() {
    param(
        [string]$UserSid
    )
    
    New-PSDrive -PSProvider Registry -Name "HKU" -Root HKEY_USERS | Out-Null
    $regpath = "HKU:\$UserSid\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    if (-not ([IntPtr]::Size -eq 4)) {
        $regpath += "HKU:\$UserSid\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    }
    $propertyNames = 'DisplayName', 'DisplayVersion', 'Publisher', 'UninstallString'
    $Apps = Get-ItemProperty $regpath -Name $propertyNames -ErrorAction SilentlyContinue | . { process { if ($_.DisplayName) { $_ } } } | Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, PSPath | Sort-Object DisplayName   
    Remove-PSDrive -Name "HKU" | Out-Null
    Return $Apps
}#end function
function Get-MachineInstalledApplications() {
       
    $regpath = @("HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*")
    if (-not ([IntPtr]::Size -eq 4)) {
        $regpath += "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    }
    $propertyNames = 'DisplayName', 'DisplayVersion', 'Publisher', 'UninstallString'
    $Apps = Get-ItemProperty $regpath -Name $propertyNames -ErrorAction SilentlyContinue | . { process { if ($_.DisplayName) { $_ } } } | Select-Object DisplayName, DisplayVersion, Publisher, UninstallString, PSPath | Sort-Object DisplayName   
    Return $Apps
}#end function

# UserHives - Find all the user profiles in the registry
$UserHives = Get-ChildItem Registry::HKEY_USERS\ | Where-Object {$_.Name -match "S-1-12-1-" -and $_.Name -notmatch "Classes"}
$SIDs = $UserHives.PSChildName

# Cleanup Chrome for user based installs
foreach ($sid in $SIDs){
    $ChromeUserInstalls = Get-UserInstalledApplications -UserSid $Sid | Where-Object {$_.DisplayName -match "Google Chrome"}
    foreach($install in $ChromeUserInstalls){
        $UninstallString = $install.UninstallString
        Write-Output $UninstallString
        if ($UninstallString -match "setup.exe"){
            #Construct the setup.exe uninstall parameters 
            $Proc = ($UninstallString.Split(" --"))[0]
            $arguments = "--uninstall --channel=stable --system-level --verbose-logging --force-uninstall"
            Start-Process -FilePath $Proc -ArgumentList $arguments -Wait
        }
        else {
            #Construct the msiexec.exe uninstall parameters 
            $UninstallString -match "{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$" | Out-Null
            $arguments =  "/X$($Matches[0]) /qn"
            Start-Process "msiexec.exe" -ArgumentList $arguments
        }   
    }
}

# Get Chrome for machine based installs
$ChromeInstalls = Get-MachineInstalledApplications | Where-Object {$_.DisplayName -match "Google Chrome"}
# Cleanup machine based installs
foreach($install in $ChromeInstalls){
    $UninstallString = $install.UninstallString
    if ($UninstallString -match "setup.exe"){
        #Construct the setup.exe uninstall parameters 
        $Proc = ($UninstallString.Split(" --"))[0]
        $arguments = "--uninstall --channel=stable --system-level --verbose-logging --force-uninstall"
        Start-Process -FilePath $Proc -ArgumentList $arguments -Wait
    }
    else {
        #Construct the msiexec.exe uninstall parameters 
        $UninstallString -match "{[A-Z0-9]{8}-([A-Z0-9]{4}-){3}[A-Z0-9]{12}}$" | Out-Null
        $arguments =  "/X$($Matches[0]) /qn"
        Start-Process "msiexec.exe" -ArgumentList $arguments
    }
}






