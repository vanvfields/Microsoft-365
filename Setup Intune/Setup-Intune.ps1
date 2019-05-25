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
.\Import-DeviceConfig.ps1 -ImportPath .\Config-Win10Defender.json -User $User
.\Import-DeviceConfig.ps1 -ImportPath .\Endpoint-Win10Pro.json -User $User
.\Import-DeviceConfig.ps1 -ImportPath .\Endpoint-Win10Enterprise.json -User $User
.\Import-DeviceConfig.ps1 -ImportPath .\Update-Win10.json -User $User

## Import the MAM policies for iOS and Android
.\Import-MAMPolicy.ps1 -ImportPath .\AppProtection-iOS.json -User $User
.\Import-MAMPolicy.ps1 -ImportPath .\AppProtection-Android.json -User $User
