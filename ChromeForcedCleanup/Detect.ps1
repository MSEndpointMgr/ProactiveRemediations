<#
.SYNOPSIS
Proactive Remeditiations Detection Script to detect outdated versions of Chrome for cleanup 

.DESCRIPTION
Detect outdated versions of Chrome for cleanup 
Detects all user and machine based Chrome installs
If you want to have a more dynamic control of the version number you can either 

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

# Option 1 - Hardcode a "minimum version"
[VERSION]$ApprovedVersion = "98.0.4758.102"

# Option 2 - Use a Azure Blob to be able update the version manually outside of script 
<#
#Input the URL to the approved version (Azure Blob)
$ApprovedAppVersionURL = "https://<YourBlob>.blob.core.windows.net/<Container>/chrome_approved_version.txt"
#Get approved version from Azure blob
[VERSION]$ApprovedVersion = (Invoke-WebRequest -Uri $ApprovedAppVersionURL -UseBasicParsing).Content
#>

# Option 3 - Use Google release API to dynamicly get X months old version as minimum 
<#
$Months = 3
$Date = ((Get-Date).AddMonths(-$Months)).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssK")
$ChromeReleases = Invoke-RestMethod -Method Get -Uri "https://versionhistory.googleapis.com/v1/chrome/platforms/win64/channels/stable/versions/all/releases?filter=starttime>$Date&order_by=starttime%20asc"
[version]$ApprovedVersion =  $ChromeReleases.releases.version | Select-Object -First 1
#>

#UserHives - Find all the user profiles in the registry
$UserHives = Get-ChildItem Registry::HKEY_USERS\ | Where-Object {$_.Name -match "S-1-12-1-" -and $_.Name -notmatch "Classes"}
$SIDs = $UserHives.PSChildName

#Detect Chrome for machine based installs
$ChromeInstalls = Get-MachineInstalledApplications | Where-Object {$_.DisplayName -match "Google Chrome"}
if ($ChromeInstalls){
    if ([VERSION]$ChromeInstalls.DisplayVersion  -lt $ApprovedVersion){
        Write-Output "Fail: Unapproved Chrome version found"
        Exit 1
    }
}

#Detect Chrome for user based installs
foreach ($sid in $SIDs){
    $ChromeUserInstalls = Get-UserInstalledApplications -UserSid $Sid | Where-Object {$_.DisplayName -match "Google Chrome"}
    if ($ChromeUserInstalls){
        if ([VERSION]$ChromeUserInstalls.DisplayVersion  -lt $ApprovedVersion){
            Write-Output "Fail: Unapproved Chrome version found"
            Exit 1
        }
    }
}
# If no unnaproved versions is found, exit 0 with a OK message. 
Write-Output "OK: Unapproved Chrome version not found"
Exit 0 



