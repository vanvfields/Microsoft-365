##
## This script leverages Microsoft Graph scripts in order to import the JSON files which deploy the baseline policies
## Before running the script, ensure all scripts and JSON files are present in the same working directory
## 
## Enter your admin username (e.g. intuneadmin@itpromentor.com); if the variable is not specified the script will prompt
## E.g. .\Setup-Intune.ps1 -User intuneadmin@itpromentor.com
##
## NOTE: No assignments will be made (policies will be imported but not deployed)
## To deploy the polices simply assign them to groups
##

Param (
    $User   
)
if($User -eq $null -or $User -eq ""){

    $User = Read-Host -Prompt "Please specify your user principal name for Intune administration"
    Write-Host
}


## Import enrollment restrictions - currently this just blocks Windows mobile platform
.\Import-EnrollmentRestrictions.ps1 -User $User

## Import the iOS MDM policies
.\Import-Compliance.ps1 -ImportPath .\Compliance-iOS.json -User $User
.\Import-DeviceConfig.ps1 -ImportPath .\Config-iOS.json -User $User

## Import the Android MDM policies
.\Import-Compliance.ps1 -ImportPath .\Compliance-Android.json -User $User
.\Import-DeviceConfig.ps1 -ImportPath .\Config-Android.json -User $User

## Import the macOS MDM policies
.\Import-Compliance.ps1 -ImportPath .\Compliance-macOS.json -User $User
.\Import-DeviceConfig.ps1 -ImportPath .\Config-macOS.json -User $User
.\Import-DeviceConfig.ps1 -ImportPath .\Endpoint-macOS.json -User $User

## Import the Windows 10 MDM policies
.\Import-Compliance.ps1 -ImportPath .\Compliance-Win10.json -User $User
.\Import-DeviceConfig.ps1 -ImportPath .\Win10-Antivirus.json -User $User
.\Import-DeviceConfig.ps1 -ImportPath .\Win10-AppGuard.json -User $User
.\Import-DeviceConfig.ps1 -ImportPath .\Win10-Bitlocker.json -User $User
.\Import-DeviceConfig.ps1 -ImportPath .\Win10-CredGuard.json -User $User
.\Import-DeviceConfig.ps1 -ImportPath .\Win10-ExploitBasic.json -User $User
.\Import-DeviceConfig.ps1 -ImportPath .\Win10-ExploitEnterprise.json -User $User
.\Import-DeviceConfig.ps1 -ImportPath .\Win10-Firewall.json -User $User
.\Import-DeviceConfig.ps1 -ImportPath .\Win10-SmartScreen.json -User $User
.\Import-DeviceConfig.ps1 -ImportPath .\Win10-UAC.json -User $User

## Import the Windows 10 Update policies
.\Import-DeviceConfig.ps1 -ImportPath .\Update-PilotRing.json -User $User
.\Import-DeviceConfig.ps1 -ImportPath .\Update-BroadRing.json -User $User

## Import the Office 365 application deployment policies
.\Import-Applications.ps1 -ImportPath .\Apps64-SAC.json -User $User
.\Import-Applications.ps1 -ImportPath .\Apps64-Monthly.json -User $User
.\Import-Applications.ps1 -ImportPath .\Apps32-SAC.json -User $User
.\Import-Applications.ps1 -ImportPath .\Apps32-Monthly.json -User $User

## Import the MAM policies for iOS and Android
.\Import-MAMPolicy.ps1 -ImportPath .\APP-AndroidBaseline.json -User $User
.\Import-MAMPolicy.ps1 -ImportPath .\APP-AndroidSensitive.json -User $User
.\Import-MAMPolicy.ps1 -ImportPath .\APP-iosBaseline.json -User $User
.\Import-MAMPolicy.ps1 -ImportPath .\APP-iosSensitive.json -User $User
