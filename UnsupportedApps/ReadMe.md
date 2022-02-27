# Unsupported Apps Detection Script
  
**Scripts**  
   
Invoke-UnsupportedAppToast.ps1  
 
**SYNOPSIS** 
  
Pop a toast notification if unsupported applications are detected  
  
**DESCRIPTION**  
  
This script is designed to be run as a Proactive Remediation. 
The BadApps array contains application names that are considered unsupported by the company. The user is prompted to remove the application(s).
If no BadApps are found, the output of the script is "No Bad Apps Found" and no Toast is displayed. If BadApps are found, along with the Toast notification, the BadApps are written to the script output as a JSON which is viewable in Proactive Remediation Device Results.  
  
Each App in the $BadApps Array is compared using the -like *$BadApps* operator against each App found on the device. If a match is found, the app is added to another Array called $BadAppArray.  
  
*Note: The script is suitable for environments where users have the correct permissions to remove the application(s) listed.*
  
There is no Remediation Script. The user is alerted, by a Toast Notification via the Detection script. If unsupported apps are found, the list of Apps, version and publisher are output as a compressed JSON and viewable in the Results column in Endpoint Analaytics.  
  
**Variables**  
  
Several Variables are configurable to customise the toast notification:-  
  
**$BadApps** = an Array that contains the list of unsupported apps.  
**$GoodMorning** = "Good Morning" - Use Regional Language alternative if English is not the first language  e.g. "God Morgen"  
**$GoodAfternoon** = "Good Afternoon" - Use Regional Language alternative if English is not the first language e.g. "God Ettermiddag"     
**$GoodEvening** = "Good Evening" - Use Regional Language alternative if English is not the first language e.g. "God Kveld"   
  
*IMPORTANT: The URI used below is reference only, it wont work in the PR. Upload this hero image to your own, accesible location, perhaps Azure Blob storage, and modify the $ToastImageSource variable in the script to reflect that location.*  
  
**$ToastImageSource** = Specify the location of the Toast Hero Image "https://github.com/MSEndpointMgr/ProactiveRemediations/raw/master/UnsupportedApps/heroimage.jpg" #ToastImage should be  364px x 180px 
  
*Example Hero Image*  
  
![Alt text](https://github.com/MSEndpointMgr/ProactiveRemediations/raw/master/UnsupportedApps/heroimage.jpg)
  
**$ToastImage** = ToastImageSource is downloaded to this location. Defaul location is User %temp% folder  
**$ToastDuration** = How long should the Toast notification be displayed before it is moved to the Notification Panel? Short = 7s, Long = 25s  
**$ToastScenario** = Default Toast scenario is "reminder". Choose from "Default", "Reminder" or "Alarm"  
**$ToastTitle** = Toast Title. Default is "Unsupported App(s) Found"  
**$ToastText** = Toast Text. Default is "Please uninstall the following Adobe applications at your earliest convenience as they pose a security risk to your computer:-"  
**$SnoozeTitle** = Reminder button title. Default is "Set Reminder"  
**$SnoozeMessage** = Reminder option list title. Default is "Remind me again in"  
**$LogFile** = Location of LogFile. Default is User %Temp% folder\UnsupportAppsFound-x.log
  
**Proactive Remediation**  
  
The Proactive Remediation should be run in:-  
-The User Context  
-As a 64bit Application  
  
Output Example if Bad Apps are found for a device  
  

  
**Toast Example**  
  
  $BadApps = @(  
    "JavaFX"  
    "Java 6"  
    "Java SE Development Kit 6"  
    "Java(TM) SE Development Kit 6"  
    "Java(TM) 6"  
    "Java 7"  
    "Java SE Development Kit 7"  
    "Java(TM) SE Development Kit 7"  
    "Java(TM) 7"  
)  
