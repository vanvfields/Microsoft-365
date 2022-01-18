<##################################################################################################
#
.SYNOPSIS
This script imports BYOD policies for macOS, iOS, and Android, including:
 1. App protection policies (MAM) for iOS and Android
 2. Compliance policies (MDM) for macOS, iOS, and Android
 
The functions contained in this script are taken from the Graph samples published by Microsoft on GitHub:
https://github.com/microsoftgraph/powershell-intune-samples


.NOTES
    FileName:    Install-BYODMobileDeviceProfiles.ps1
    Author:      Alex Fields 
	Based on:    Per Larsen / Frank Simorjay
    Created:     February 2021
	Revised:     February 2021
    Version:     1.0 
    
#>
###################################################################################################
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

####################################################

function Get-AuthToken {

<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>

[cmdletbinding()]

param
(
    [Parameter(Mandatory=$true)]
    $User
)

$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

$tenant = $userUpn.Host

Write-Host "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($AadModule -eq $null) {

        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    }

    if ($AadModule -eq $null) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        exit
    }

# Getting path to ActiveDirectory Assemblies
# If the module count is greater than 1 find the latest version

    if($AadModule.count -gt 1){

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

            # Checking if there are multiple versions of the same module found

            if($AadModule.count -gt 1){

            $aadModule = $AadModule | select -Unique

            }

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"

$redirectUri = "urn:ietf:wg:oauth:2.0:oob"

$resourceAppIdURI = "https://graph.microsoft.com"

$authority = "https://login.microsoftonline.com/$Tenant"

    try {

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

        # If the accesstoken is valid then create the authentication header

        if($authResult.AccessToken){

        # Creating header for Authorization token

        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }

        return $authHeader

        }

        else {

        Write-Host
        Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
        Write-Host
        break

        }

    }

    catch {

    write-host $_.Exception.Message -f Red
    write-host $_.Exception.ItemName -f Red
    write-host
    break

    }

}

####################################################

Function Test-JSON(){

<#
.SYNOPSIS
This function is used to test if the JSON passed to a REST Post request is valid
.DESCRIPTION
The function tests if the JSON passed to the REST Post is valid
.EXAMPLE
Test-JSON -JSON $JSON
Test if the JSON is valid before calling the Graph REST interface
.NOTES
NAME: Test-AuthHeader
#>

param (

$JSON

)

    try {

    $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
    $validJson = $true

    }

    catch {

    $validJson = $false
    $_.Exception

    }

    if (!$validJson){

    Write-Host "Provided JSON isn't in valid JSON format" -f Red
    break

    }

}

####################################################

Function Add-DeviceCompliancePolicybaseline(){

    <#
    .SYNOPSIS
    This function is used to add a device compliance policy using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a device compliance policy
    .EXAMPLE
    Add-DeviceCompliancePolicy -JSON $JSON
    Adds an iOS device compliance policy in Intune
    .NOTES
    NAME: Add-DeviceCompliancePolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $JSON
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicies"
        
        try {
    
            if($JSON -eq "" -or $JSON -eq $null){
    
            write-host "No JSON specified, please specify valid JSON for the iOS Policy..." -f Red
    
            }
    
            else {
    
            Test-JSON -JSON $JSON
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
            Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
    
            }
    
        }
        
        catch {
    
        $ex = $_.Exception
        $errorResponse = $ex.Response.GetResponseStream()
        $reader = New-Object System.IO.StreamReader($errorResponse)
        $reader.BaseStream.Position = 0
        $reader.DiscardBufferedData()
        $responseBody = $reader.ReadToEnd();
        Write-Host "Response content:`n$responseBody" -f Red
        Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
        write-host
        break
    
        }
    
    }

####################################################

Function Add-ManagedAppPolicy(){

<#
.SYNOPSIS
This function is used to add an Managed App policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a Managed App policy
.EXAMPLE
Add-ManagedAppPolicy -JSON $JSON
Adds a Managed App policy in Intune
.NOTES
NAME: Add-ManagedAppPolicy
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/managedAppPolicies"

    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for a Managed App Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

        }

    }

    catch {

    Write-Host
    $ex = $_.Exception
    $errorResponse = $ex.Response.GetResponseStream()
    $reader = New-Object System.IO.StreamReader($errorResponse)
    $reader.BaseStream.Position = 0
    $reader.DiscardBufferedData()
    $responseBody = $reader.ReadToEnd();
    Write-Host "Response content:`n$responseBody" -f Red
    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
    write-host
    break

    }

}

####################################################

Function Get-EnterpriseDomain(){



<#

.SYNOPSIS

This function is used to get the initial domain created using the Graph API REST interface

.DESCRIPTION

The function connects to the Graph API Interface and gets the initial domain created

.EXAMPLE

Get-EnterpriseDomain

Gets the initial domain created in Azure - Format domain.onmicrosoft.com

.NOTES

NAME: Get-EnterpriseDomain

#>



    try {



    $uri = "https://graph.microsoft.com/v1.0/domains"



    $domains = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value



    $EnterpriseDomain = ($domains | ? { $_.isInitial -eq $true } | select id).id



    return $EnterpriseDomain



    }



    catch {



    $ex = $_.Exception

    $errorResponse = $ex.Response.GetResponseStream()

    $reader = New-Object System.IO.StreamReader($errorResponse)

    $reader.BaseStream.Position = 0

    $reader.DiscardBufferedData()

    $responseBody = $reader.ReadToEnd();

    Write-Host "Response content:`n$responseBody" -f Red

    Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"

    write-host

    break





    }



}

####################################################

#region Authentication

write-host

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

            # Defining User Principal Name if not present

            if($User -eq $null -or $User -eq ""){
           $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq ""){
    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}

#endregion

####################################################

$EnterpriseDomain = Get-EnterpriseDomain

$Sharepoint = $EnterpriseDomain.Split(".")[0]


####################################################
#JSON Components
####################################################



####################################################
#App Protection policies
####################################################

$MAM_AndroidBase = @"

{
    "@odata.context":  "https://graph.microsoft.com/beta/$metadata#deviceAppManagement/androidManagedAppProtections(apps())/$entity",
    "displayName":  "[ITPM Baseline] Android MAM",
    "description":  "This policy will encrypt app data and require a PIN on unmanaged devices. However, it does not restrict copy/paste/save to unmanaged applications.",
    "periodOfflineBeforeAccessCheck":  "PT12H",
    "periodOnlineBeforeAccessCheck":  "PT5M",
    "allowedInboundDataTransferSources":  "allApps",
    "allowedOutboundDataTransferDestinations":  "allApps",
    "organizationalCredentialsRequired":  false,
    "allowedOutboundClipboardSharingLevel":  "allApps",
    "dataBackupBlocked":  true,
    "deviceComplianceRequired":  true,
    "managedBrowserToOpenLinksRequired":  false,
    "saveAsBlocked":  true,
    "periodOfflineBeforeWipeIsEnforced":  "P60D",
    "pinRequired":  true,
    "maximumPinRetries":  10,
    "simplePinBlocked":  false,
    "minimumPinLength":  4,
    "pinCharacterSet":  "numeric",
    "periodBeforePinReset":  "PT0S",
    "allowedDataStorageLocations":  [
                                        "oneDriveForBusiness",
                                        "sharePoint"
                                    ],
    "contactSyncBlocked":  false,
    "printBlocked":  false,
    "fingerprintBlocked":  false,
    "disableAppPinIfDevicePinIsSet":  true,
    "maximumRequiredOsVersion":  null,
    "maximumWarningOsVersion":  null,
    "maximumWipeOsVersion":  null,
    "minimumRequiredOsVersion":  "8.0",
    "minimumWarningOsVersion":  null,
    "minimumRequiredAppVersion":  null,
    "minimumWarningAppVersion":  null,
    "minimumWipeOsVersion":  null,
    "minimumWipeAppVersion":  null,
    "appActionIfDeviceComplianceRequired":  "block",
    "appActionIfMaximumPinRetriesExceeded":  "block",
    "pinRequiredInsteadOfBiometricTimeout":  "PT30M",
    "allowedOutboundClipboardSharingExceptionLength":  0,
    "notificationRestriction":  "allow",
    "previousPinBlockCount":  0,
    "managedBrowser":  "notConfigured",
    "maximumAllowedDeviceThreatLevel":  "notConfigured",
    "mobileThreatDefenseRemediationAction":  "block",
    "blockDataIngestionIntoOrganizationDocuments":  false,
    "allowedDataIngestionLocations":  [
                                          "oneDriveForBusiness",
                                          "sharePoint",
                                          "camera"
                                      ],
    "appActionIfUnableToAuthenticateUser":  "wipe",
    "dialerRestrictionLevel":  "allApps",
    "isAssigned":  true,
    "targetedAppManagementLevels":  "unspecified",
    "screenCaptureBlocked":  false,
    "disableAppEncryptionIfDeviceEncryptionIsEnabled":  false,
    "encryptAppData":  true,
    "deployedAppCount":  18,
    "minimumRequiredPatchVersion":  null,
    "minimumWarningPatchVersion":  null,
    "minimumWipePatchVersion":  null,
    "allowedAndroidDeviceManufacturers":  null,
    "appActionIfAndroidDeviceManufacturerNotAllowed":  "block",
    "requiredAndroidSafetyNetDeviceAttestationType":  "none",
    "appActionIfAndroidSafetyNetDeviceAttestationFailed":  "block",
    "requiredAndroidSafetyNetAppsVerificationType":  "none",
    "appActionIfAndroidSafetyNetAppsVerificationFailed":  "block",
    "customBrowserPackageId":  "",
    "customBrowserDisplayName":  "",
    "minimumRequiredCompanyPortalVersion":  null,
    "minimumWarningCompanyPortalVersion":  null,
    "minimumWipeCompanyPortalVersion":  null,
    "keyboardsRestricted":  false,
    "allowedAndroidDeviceModels":  [

                                   ],
    "appActionIfAndroidDeviceModelNotAllowed":  "block",
    "customDialerAppPackageId":  "",
    "customDialerAppDisplayName":  "",
    "biometricAuthenticationBlocked":  false,
    "requiredAndroidSafetyNetEvaluationType":  "basic",
    "blockAfterCompanyPortalUpdateDeferralInDays":  0,
    "warnAfterCompanyPortalUpdateDeferralInDays":  0,
    "wipeAfterCompanyPortalUpdateDeferralInDays":  0,
    "deviceLockRequired":  false,
    "appActionIfDeviceLockNotSet":  "block",
    "exemptedAppPackages":  [
                                {
                                    "name":  "Google Maps ",
                                    "value":  "com.google.maps"
                                },
                                {
                                    "name":  "Google Play Music",
                                    "value":  "com.google.android.music"
                                },
                                {
                                    "name":  "Android SMS",
                                    "value":  "com.google.android.apps.messaging"
                                },
                                {
                                    "name":  "Android MMS",
                                    "value":  "com.android.mms"
                                },
                                {
                                    "name":  "Samsung SMS",
                                    "value":  "com.samsung.android.messaging"
                                },
                                {
                                    "name":  "Certificate Installer",
                                    "value":  "com.android.certinstaller"
                                }
                            ],
    "approvedKeyboards":  [

                          ],
    "apps@odata.context":  "https://graph.microsoft.com/beta/$metadata#deviceAppManagement/androidManagedAppProtections(\u0027T_effd51e4-c6d8-4e38-b298-405d88bf4387\u0027)/apps",
    "apps":  [
                 {
                     "id":  "com.microsoft.emmx.android",
                     "version":  "-725393251",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.emmx"
                                             }
                 },
                 {
                     "id":  "com.microsoft.launcher.android",
                     "version":  "-1429615568",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.launcher"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.excel.android",
                     "version":  "-1789826587",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.office.excel"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.officehub.android",
                     "version":  "-1091809935",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.office.officehub"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.officehubhl.android",
                     "version":  "-1175805259",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.office.officehubhl"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.officehubrow.android",
                     "version":  "-1861979965",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.office.officehubrow"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.onenote.android",
                     "version":  "186482170",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.office.onenote"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.outlook.android",
                     "version":  "1146701235",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.office.outlook"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.powerpoint.android",
                     "version":  "1411665537",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.office.powerpoint"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.word.android",
                     "version":  "2122351424",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.office.word"
                                             }
                 },
                 {
                     "id":  "com.microsoft.planner.android",
                     "version":  "-1658524342",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.planner"
                                             }
                 },
                 {
                     "id":  "com.microsoft.powerbim.android",
                     "version":  "1564653697",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.powerbim"
                                             }
                 },
                 {
                     "id":  "com.microsoft.sharepoint.android",
                     "version":  "84773357",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.sharepoint"
                                             }
                 },
                 {
                     "id":  "com.microsoft.skydrive.android",
                     "version":  "1887770705",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.skydrive"
                                             }
                 },
                 {
                     "id":  "com.microsoft.stream.android",
                     "version":  "648128536",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.stream"
                                             }
                 },
                 {
                     "id":  "com.microsoft.teams.android",
                     "version":  "1900143244",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.teams"
                                             }
                 },
                 {
                     "id":  "com.microsoft.todos.android",
                     "version":  "1697858135",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.todos"
                                             }
                 },
                 {
                     "id":  "com.yammer.v1.android",
                     "version":  "-1248070370",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.yammer.v1"
                                             }
                 }
             ],
    "@odata.type":  "#microsoft.graph.androidManagedAppProtection"
}


"@

####################################################

$MAM_iosBase = @"
{
    "@odata.context":  "https://graph.microsoft.com/beta/$metadata#deviceAppManagement/iosManagedAppProtections(apps())/$entity",
    "displayName":  "[ITPM Baseline] iOS MAM",
    "description":  "This policy will encrypt app data and require a PIN on unmanaged devices. However, it does not restrict copy/paste/save to unmanaged applications.",
    "periodOfflineBeforeAccessCheck":  "PT12H",
    "periodOnlineBeforeAccessCheck":  "PT5M",
    "allowedInboundDataTransferSources":  "allApps",
    "allowedOutboundDataTransferDestinations":  "allApps",
    "organizationalCredentialsRequired":  false,
    "allowedOutboundClipboardSharingLevel":  "allApps",
    "dataBackupBlocked":  true,
    "deviceComplianceRequired":  true,
    "managedBrowserToOpenLinksRequired":  false,
    "saveAsBlocked":  true,
    "periodOfflineBeforeWipeIsEnforced":  "P60D",
    "pinRequired":  true,
    "maximumPinRetries":  10,
    "simplePinBlocked":  false,
    "minimumPinLength":  4,
    "pinCharacterSet":  "numeric",
    "periodBeforePinReset":  "PT0S",
    "allowedDataStorageLocations":  [
                                        "oneDriveForBusiness",
                                        "sharePoint"
                                    ],
    "contactSyncBlocked":  false,
    "printBlocked":  false,
    "fingerprintBlocked":  false,
    "disableAppPinIfDevicePinIsSet":  true,
    "maximumRequiredOsVersion":  null,
    "maximumWarningOsVersion":  null,
    "maximumWipeOsVersion":  null,
    "minimumRequiredOsVersion":  "13.1",
    "minimumWarningOsVersion":  null,
    "minimumRequiredAppVersion":  null,
    "minimumWarningAppVersion":  null,
    "minimumWipeOsVersion":  null,
    "minimumWipeAppVersion":  null,
    "appActionIfDeviceComplianceRequired":  "block",
    "appActionIfMaximumPinRetriesExceeded":  "wipe",
    "pinRequiredInsteadOfBiometricTimeout":  "PT30M",
    "allowedOutboundClipboardSharingExceptionLength":  0,
    "notificationRestriction":  "allow",
    "previousPinBlockCount":  0,
    "managedBrowser":  "notConfigured",
    "maximumAllowedDeviceThreatLevel":  "notConfigured",
    "mobileThreatDefenseRemediationAction":  "block",
    "blockDataIngestionIntoOrganizationDocuments":  false,
    "allowedDataIngestionLocations":  [
                                          "oneDriveForBusiness",
                                          "sharePoint",
                                          "camera"
                                      ],
    "appActionIfUnableToAuthenticateUser":  "wipe",
    "dialerRestrictionLevel":  "allApps",
    "isAssigned":  true,
    "targetedAppManagementLevels":  "unspecified",
    "appDataEncryptionType":  "whenDeviceLocked",
    "minimumRequiredSdkVersion":  null,
    "deployedAppCount":  15,
    "faceIdBlocked":  false,
    "minimumWipeSdkVersion":  null,
    "allowedIosDeviceModels":  null,
    "appActionIfIosDeviceModelNotAllowed":  "block",
    "thirdPartyKeyboardsBlocked":  false,
    "filterOpenInToOnlyManagedApps":  false,
    "disableProtectionOfManagedOutboundOpenInData":  false,
    "protectInboundDataFromUnknownSources":  false,
    "customBrowserProtocol":  "",
    "customDialerAppProtocol":  "",
    "exemptedAppProtocols":  [
                                 {
                                     "name":  "Default",
                                     "value":  "tel;telprompt;skype;app-settings;calshow;itms;itmss;itms-apps;itms-appss;itms-services;"
                                 },
                                 {
                                     "name":  "Apple Maps",
                                     "value":  "maps"
                                 },
                                 {
                                     "name":  "Apple Messages",
                                     "value":  "sms"
                                 }
                             ],
    "apps@odata.context":  "https://graph.microsoft.com/beta/$metadata#deviceAppManagement/iosManagedAppProtections(\u0027T_fc3f7a8f-55a5-4d8f-b80b-7ae2d15afeff\u0027)/apps",
    "apps":  [
                 {
                     "id":  "com.microsoft.msedge.ios",
                     "version":  "-2135752869",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.msedge"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.excel.ios",
                     "version":  "-1255026913",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.office.excel"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.outlook.ios",
                     "version":  "-518090279",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.office.outlook"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.powerpoint.ios",
                     "version":  "-740777841",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.office.powerpoint"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.word.ios",
                     "version":  "922692278",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.office.word"
                                             }
                 },
                 {
                     "id":  "com.microsoft.officemobile.ios",
                     "version":  "-803819540",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.officemobile"
                                             }
                 },
                 {
                     "id":  "com.microsoft.onenote.ios",
                     "version":  "107156768",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.onenote"
                                             }
                 },
                 {
                     "id":  "com.microsoft.plannermobile.ios",
                     "version":  "-175532278",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.plannermobile"
                                             }
                 },
                 {
                     "id":  "com.microsoft.powerbimobile.ios",
                     "version":  "-91595494",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.powerbimobile"
                                             }
                 },
                 {
                     "id":  "com.microsoft.sharepoint.ios",
                     "version":  "-585639021",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.sharepoint"
                                             }
                 },
                 {
                     "id":  "com.microsoft.skydrive.ios",
                     "version":  "-108719121",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.skydrive"
                                             }
                 },
                 {
                     "id":  "com.microsoft.skype.teams.ios",
                     "version":  "-1040529574",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.skype.teams"
                                             }
                 },
                 {
                     "id":  "com.microsoft.stream.ios",
                     "version":  "126860698",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.stream"
                                             }
                 },
                 {
                     "id":  "com.microsoft.to-do.ios",
                     "version":  "-292160221",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.to-do"
                                             }
                 },
                 {
                     "id":  "wefwef.ios",
                     "version":  "207428455",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "wefwef"
                                             }
                 }
             ],
    "@odata.type":  "#microsoft.graph.iosManagedAppProtection"
}

"@

####################################################

$MAM_AndroidStrict = @"

{
    "@odata.context":  "https://graph.microsoft.com/beta/$metadata#deviceAppManagement/androidManagedAppProtections(apps())/$entity",
    "displayName":  "[ITPM Strict] Android MAM",
    "description":  "This policy will encrypt app data and require a PIN on unmanaged devices. The policy also restricts copy/paste/export to unmanaged applications.",
    "periodOfflineBeforeAccessCheck":  "PT12H",
    "periodOnlineBeforeAccessCheck":  "PT5M",
    "allowedInboundDataTransferSources":  "allApps",
    "allowedOutboundDataTransferDestinations":  "managedApps",
    "organizationalCredentialsRequired":  false,
    "allowedOutboundClipboardSharingLevel":  "managedAppsWithPasteIn",
    "dataBackupBlocked":  true,
    "deviceComplianceRequired":  true,
    "managedBrowserToOpenLinksRequired":  true,
    "saveAsBlocked":  true,
    "periodOfflineBeforeWipeIsEnforced":  "P60D",
    "pinRequired":  true,
    "maximumPinRetries":  10,
    "simplePinBlocked":  false,
    "minimumPinLength":  4,
    "pinCharacterSet":  "numeric",
    "periodBeforePinReset":  "PT0S",
    "allowedDataStorageLocations":  [
                                        "oneDriveForBusiness",
                                        "sharePoint"
                                    ],
    "contactSyncBlocked":  false,
    "printBlocked":  false,
    "fingerprintBlocked":  false,
    "disableAppPinIfDevicePinIsSet":  true,
    "maximumRequiredOsVersion":  null,
    "maximumWarningOsVersion":  null,
    "maximumWipeOsVersion":  null,
    "minimumRequiredOsVersion":  "8.0",
    "minimumWarningOsVersion":  null,
    "minimumRequiredAppVersion":  null,
    "minimumWarningAppVersion":  null,
    "minimumWipeOsVersion":  null,
    "minimumWipeAppVersion":  null,
    "appActionIfDeviceComplianceRequired":  "block",
    "appActionIfMaximumPinRetriesExceeded":  "block",
    "pinRequiredInsteadOfBiometricTimeout":  "PT30M",
    "allowedOutboundClipboardSharingExceptionLength":  0,
    "notificationRestriction":  "allow",
    "previousPinBlockCount":  0,
    "managedBrowser":  "microsoftEdge",
    "maximumAllowedDeviceThreatLevel":  "notConfigured",
    "mobileThreatDefenseRemediationAction":  "block",
    "blockDataIngestionIntoOrganizationDocuments":  false,
    "allowedDataIngestionLocations":  [
                                          "oneDriveForBusiness",
                                          "sharePoint",
                                          "camera"
                                      ],
    "appActionIfUnableToAuthenticateUser":  "wipe",
    "dialerRestrictionLevel":  "allApps",
    "isAssigned":  true,
    "targetedAppManagementLevels":  "unspecified",
    "screenCaptureBlocked":  false,
    "disableAppEncryptionIfDeviceEncryptionIsEnabled":  false,
    "encryptAppData":  true,
    "deployedAppCount":  18,
    "minimumRequiredPatchVersion":  null,
    "minimumWarningPatchVersion":  null,
    "minimumWipePatchVersion":  null,
    "allowedAndroidDeviceManufacturers":  null,
    "appActionIfAndroidDeviceManufacturerNotAllowed":  "block",
    "requiredAndroidSafetyNetDeviceAttestationType":  "none",
    "appActionIfAndroidSafetyNetDeviceAttestationFailed":  "block",
    "requiredAndroidSafetyNetAppsVerificationType":  "none",
    "appActionIfAndroidSafetyNetAppsVerificationFailed":  "block",
    "customBrowserPackageId":  "",
    "customBrowserDisplayName":  "",
    "minimumRequiredCompanyPortalVersion":  null,
    "minimumWarningCompanyPortalVersion":  null,
    "minimumWipeCompanyPortalVersion":  null,
    "keyboardsRestricted":  false,
    "allowedAndroidDeviceModels":  [

                                   ],
    "appActionIfAndroidDeviceModelNotAllowed":  "block",
    "customDialerAppPackageId":  "",
    "customDialerAppDisplayName":  "",
    "biometricAuthenticationBlocked":  false,
    "requiredAndroidSafetyNetEvaluationType":  "basic",
    "blockAfterCompanyPortalUpdateDeferralInDays":  0,
    "warnAfterCompanyPortalUpdateDeferralInDays":  0,
    "wipeAfterCompanyPortalUpdateDeferralInDays":  0,
    "deviceLockRequired":  false,
    "appActionIfDeviceLockNotSet":  "block",
    "exemptedAppPackages":  [
                                {
                                    "name":  "Google Maps ",
                                    "value":  "com.google.maps"
                                },
                                {
                                    "name":  "Google Play Music",
                                    "value":  "com.google.android.music"
                                },
                                {
                                    "name":  "Android SMS",
                                    "value":  "com.google.android.apps.messaging"
                                },
                                {
                                    "name":  "Android MMS",
                                    "value":  "com.android.mms"
                                },
                                {
                                    "name":  "Samsung SMS",
                                    "value":  "com.samsung.android.messaging"
                                },
                                {
                                    "name":  "Certificate Installer",
                                    "value":  "com.android.certinstaller"
                                }
                            ],
    "approvedKeyboards":  [

                          ],
    "apps@odata.context":  "https://graph.microsoft.com/beta/$metadata#deviceAppManagement/androidManagedAppProtections(\u0027T_effd51e4-c6d8-4e38-b298-405d88bf4387\u0027)/apps",
    "apps":  [
                 {
                     "id":  "com.microsoft.emmx.android",
                     "version":  "-725393251",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.emmx"
                                             }
                 },
                 {
                     "id":  "com.microsoft.launcher.android",
                     "version":  "-1429615568",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.launcher"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.excel.android",
                     "version":  "-1789826587",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.office.excel"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.officehub.android",
                     "version":  "-1091809935",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.office.officehub"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.officehubhl.android",
                     "version":  "-1175805259",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.office.officehubhl"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.officehubrow.android",
                     "version":  "-1861979965",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.office.officehubrow"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.onenote.android",
                     "version":  "186482170",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.office.onenote"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.outlook.android",
                     "version":  "1146701235",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.office.outlook"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.powerpoint.android",
                     "version":  "1411665537",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.office.powerpoint"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.word.android",
                     "version":  "2122351424",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.office.word"
                                             }
                 },
                 {
                     "id":  "com.microsoft.planner.android",
                     "version":  "-1658524342",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.planner"
                                             }
                 },
                 {
                     "id":  "com.microsoft.powerbim.android",
                     "version":  "1564653697",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.powerbim"
                                             }
                 },
                 {
                     "id":  "com.microsoft.sharepoint.android",
                     "version":  "84773357",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.sharepoint"
                                             }
                 },
                 {
                     "id":  "com.microsoft.skydrive.android",
                     "version":  "1887770705",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.skydrive"
                                             }
                 },
                 {
                     "id":  "com.microsoft.stream.android",
                     "version":  "648128536",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.stream"
                                             }
                 },
                 {
                     "id":  "com.microsoft.teams.android",
                     "version":  "1900143244",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.teams"
                                             }
                 },
                 {
                     "id":  "com.microsoft.todos.android",
                     "version":  "1697858135",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.microsoft.todos"
                                             }
                 },
                 {
                     "id":  "com.yammer.v1.android",
                     "version":  "-1248070370",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.androidMobileAppIdentifier",
                                                 "packageId":  "com.yammer.v1"
                                             }
                 }
             ],
    "@odata.type":  "#microsoft.graph.androidManagedAppProtection"
}

"@

####################################################

$MAM_iosStrict = @"
{
    "@odata.context":  "https://graph.microsoft.com/beta/$metadata#deviceAppManagement/iosManagedAppProtections(apps())/$entity",
    "displayName":  "[ITPM Strict] iOS MAM",
    "description":  "This policy will encrypt app data and require a PIN on unmanaged devices. The policy also restricts copy/paste/export to unmanaged applications.",
    "periodOfflineBeforeAccessCheck":  "PT12H",
    "periodOnlineBeforeAccessCheck":  "PT5M",
    "allowedInboundDataTransferSources":  "allApps",
    "allowedOutboundDataTransferDestinations":  "managedApps",
    "organizationalCredentialsRequired":  false,
    "allowedOutboundClipboardSharingLevel":  "managedAppsWithPasteIn",
    "dataBackupBlocked":  true,
    "deviceComplianceRequired":  true,
    "managedBrowserToOpenLinksRequired":  true,
    "saveAsBlocked":  true,
    "periodOfflineBeforeWipeIsEnforced":  "P60D",
    "pinRequired":  true,
    "maximumPinRetries":  10,
    "simplePinBlocked":  false,
    "minimumPinLength":  4,
    "pinCharacterSet":  "numeric",
    "periodBeforePinReset":  "PT0S",
    "allowedDataStorageLocations":  [
                                        "oneDriveForBusiness",
                                        "sharePoint"
                                    ],
    "contactSyncBlocked":  false,
    "printBlocked":  false,
    "fingerprintBlocked":  false,
    "disableAppPinIfDevicePinIsSet":  true,
    "maximumRequiredOsVersion":  null,
    "maximumWarningOsVersion":  null,
    "maximumWipeOsVersion":  null,
    "minimumRequiredOsVersion":  "13.1",
    "minimumWarningOsVersion":  null,
    "minimumRequiredAppVersion":  null,
    "minimumWarningAppVersion":  null,
    "minimumWipeOsVersion":  null,
    "minimumWipeAppVersion":  null,
    "appActionIfDeviceComplianceRequired":  "block",
    "appActionIfMaximumPinRetriesExceeded":  "wipe",
    "pinRequiredInsteadOfBiometricTimeout":  "PT30M",
    "allowedOutboundClipboardSharingExceptionLength":  0,
    "notificationRestriction":  "allow",
    "previousPinBlockCount":  0,
    "managedBrowser":  "microsoftEdge",
    "maximumAllowedDeviceThreatLevel":  "notConfigured",
    "mobileThreatDefenseRemediationAction":  "block",
    "blockDataIngestionIntoOrganizationDocuments":  false,
    "allowedDataIngestionLocations":  [
                                          "oneDriveForBusiness",
                                          "sharePoint",
                                          "camera"
                                      ],
    "appActionIfUnableToAuthenticateUser":  "wipe",
    "dialerRestrictionLevel":  "allApps",
    "isAssigned":  true,
    "targetedAppManagementLevels":  "unspecified",
    "appDataEncryptionType":  "whenDeviceLocked",
    "minimumRequiredSdkVersion":  null,
    "deployedAppCount":  15,
    "faceIdBlocked":  false,
    "minimumWipeSdkVersion":  null,
    "allowedIosDeviceModels":  null,
    "appActionIfIosDeviceModelNotAllowed":  "block",
    "thirdPartyKeyboardsBlocked":  false,
    "filterOpenInToOnlyManagedApps":  false,
    "disableProtectionOfManagedOutboundOpenInData":  false,
    "protectInboundDataFromUnknownSources":  false,
    "customBrowserProtocol":  "",
    "customDialerAppProtocol":  "",
    "exemptedAppProtocols":  [
                                 {
                                     "name":  "Default",
                                     "value":  "tel;telprompt;skype;app-settings;calshow;itms;itmss;itms-apps;itms-appss;itms-services;"
                                 },
                                 {
                                     "name":  "Apple Maps",
                                     "value":  "maps"
                                 },
                                 {
                                     "name":  "Apple Messages",
                                     "value":  "sms"
                                 }
                             ],
    "apps@odata.context":  "https://graph.microsoft.com/beta/$metadata#deviceAppManagement/iosManagedAppProtections(\u0027T_fc3f7a8f-55a5-4d8f-b80b-7ae2d15afeff\u0027)/apps",
    "apps":  [
                 {
                     "id":  "com.microsoft.msedge.ios",
                     "version":  "-2135752869",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.msedge"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.excel.ios",
                     "version":  "-1255026913",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.office.excel"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.outlook.ios",
                     "version":  "-518090279",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.office.outlook"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.powerpoint.ios",
                     "version":  "-740777841",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.office.powerpoint"
                                             }
                 },
                 {
                     "id":  "com.microsoft.office.word.ios",
                     "version":  "922692278",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.office.word"
                                             }
                 },
                 {
                     "id":  "com.microsoft.officemobile.ios",
                     "version":  "-803819540",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.officemobile"
                                             }
                 },
                 {
                     "id":  "com.microsoft.onenote.ios",
                     "version":  "107156768",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.onenote"
                                             }
                 },
                 {
                     "id":  "com.microsoft.plannermobile.ios",
                     "version":  "-175532278",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.plannermobile"
                                             }
                 },
                 {
                     "id":  "com.microsoft.powerbimobile.ios",
                     "version":  "-91595494",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.powerbimobile"
                                             }
                 },
                 {
                     "id":  "com.microsoft.sharepoint.ios",
                     "version":  "-585639021",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.sharepoint"
                                             }
                 },
                 {
                     "id":  "com.microsoft.skydrive.ios",
                     "version":  "-108719121",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.skydrive"
                                             }
                 },
                 {
                     "id":  "com.microsoft.skype.teams.ios",
                     "version":  "-1040529574",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.skype.teams"
                                             }
                 },
                 {
                     "id":  "com.microsoft.stream.ios",
                     "version":  "126860698",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.stream"
                                             }
                 },
                 {
                     "id":  "com.microsoft.to-do.ios",
                     "version":  "-292160221",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.to-do"
                                             }
                 },
                 {
                     "id":  "wefwef.ios",
                     "version":  "207428455",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "wefwef"
                                             }
                 }
             ],
    "@odata.type":  "#microsoft.graph.iosManagedAppProtection"
}

"@

####################################################




####################################################
#Compliance policies
####################################################

$BaselineiOS = @"

{
    "@odata.type":  "#microsoft.graph.iosCompliancePolicy",
    "description":  "This policy measures compliance for both personally-owned and company-owned iOS/iPadOS devices.",
    "displayName":  "[ITPM Baseline] iOS/iPadOS",
    "passcodeBlockSimple":  true,
    "passcodeExpirationDays":  null,
    "passcodeMinimumLength":  6,
    "passcodeMinutesOfInactivityBeforeLock":  0,
    "passcodeMinutesOfInactivityBeforeScreenTimeout":  5,
    "passcodePreviousPasscodeBlockCount":  null,
    "passcodeMinimumCharacterSetCount":  null,
    "passcodeRequiredType":  "numeric",
    "passcodeRequired":  true,
    "osMinimumVersion":  "13.1",
    "osMaximumVersion":  null,
    "osMinimumBuildVersion":  null,
    "osMaximumBuildVersion":  null,
    "securityBlockJailbrokenDevices":  true,
    "deviceThreatProtectionEnabled":  false,
    "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
    "advancedThreatProtectionRequiredSecurityLevel":  "unavailable",
    "managedEmailProfileRequired":  false,
    "restrictedApps":  [

                       ],
    "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":"","notificationMessageCCList":[]}]}]

}



"@

####################################################

$BLOCKAndroidLegacy = @"
{
    "@odata.type":  "#microsoft.graph.androidCompliancePolicy",
    "description":  "Use this policy to migrate from legacy device administrator enrollment; devices must unenroll and re-enroll with Work profile. Otherwise you can just block device administrator using device enrollment restrictions.",
    "displayName":  "[ITPM Baseline] Block Android Device Administrator (Legacy)",
    "passwordRequired":  false,
    "passwordMinimumLength":  null,
    "passwordRequiredType":  "deviceDefault",
    "requiredPasswordComplexity":  "none",
    "passwordMinutesOfInactivityBeforeLock":  null,
    "passwordExpirationDays":  null,
    "passwordPreviousPasswordBlockCount":  null,
    "passwordSignInFailureCountBeforeFactoryReset":  null,
    "securityPreventInstallAppsFromUnknownSources":  false,
    "securityDisableUsbDebugging":  false,
    "securityRequireVerifyApps":  false,
    "deviceThreatProtectionEnabled":  false,
    "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
    "advancedThreatProtectionRequiredSecurityLevel":  "unavailable",
    "securityBlockJailbrokenDevices":  false,
    "securityBlockDeviceAdministratorManagedDevices":  true,
    "osMinimumVersion":  null,
    "osMaximumVersion":  null,
    "minAndroidSecurityPatchLevel":  null,
    "storageRequireEncryption":  false,
    "securityRequireSafetyNetAttestationBasicIntegrity":  false,
    "securityRequireSafetyNetAttestationCertifiedDevice":  false,
    "securityRequireGooglePlayServices":  false,
    "securityRequireUpToDateSecurityProviders":  false,
    "securityRequireCompanyPortalAppIntegrity":  false,
    "conditionStatementId":  null,
    "restrictedApps":  [

                       ],
    "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":72,"notificationTemplateId":"","notificationMessageCCList":[]}]}]

}

"@

####################################################

$BaselineAndroidCompany = @"

{
    "@odata.type":  "#microsoft.graph.androidDeviceOwnerCompliancePolicy",
    "description":  "Use this policy for company-owned Android Enterprise devices",
    "displayName":  "[ITPM Baseline] Company-Owned Android Enterprise",
    "deviceThreatProtectionEnabled":  false,
    "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
    "advancedThreatProtectionRequiredSecurityLevel":  null,
    "securityRequireSafetyNetAttestationBasicIntegrity":  true,
    "securityRequireSafetyNetAttestationCertifiedDevice":  false,
    "osMinimumVersion":  "8.0",
    "osMaximumVersion":  null,
    "minAndroidSecurityPatchLevel":  null,
    "passwordRequired":  true,
    "passwordMinimumLength":  6,
    "passwordMinimumLetterCharacters":  null,
    "passwordMinimumLowerCaseCharacters":  null,
    "passwordMinimumNonLetterCharacters":  null,
    "passwordMinimumNumericCharacters":  null,
    "passwordMinimumSymbolCharacters":  null,
    "passwordMinimumUpperCaseCharacters":  null,
    "passwordRequiredType":  "numeric",
    "passwordMinutesOfInactivityBeforeLock":  5,
    "passwordExpirationDays":  null,
    "passwordPreviousPasswordCountToBlock":  null,
    "storageRequireEncryption":  true,
    "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":"","notificationMessageCCList":[]}]}]

}

"@

####################################################

$BaselineAndroidBYOD = @"

{
    "@odata.type":  "#microsoft.graph.androidWorkProfileCompliancePolicy",
    "description":  "Use this policy for personally-owned Android devices",
    "displayName":  "[ITPM Baseline] BYOD Android Work Profile",
    "passwordRequired":  true,
    "passwordMinimumLength":  6,
    "passwordRequiredType":  "numericComplex",
    "passwordMinutesOfInactivityBeforeLock":  5,
    "passwordExpirationDays":  null,
    "passwordPreviousPasswordBlockCount":  null,
    "passwordSignInFailureCountBeforeFactoryReset":  null,
    "securityPreventInstallAppsFromUnknownSources":  true,
    "securityDisableUsbDebugging":  false,
    "securityRequireVerifyApps":  false,
    "deviceThreatProtectionEnabled":  false,
    "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
    "advancedThreatProtectionRequiredSecurityLevel":  "unavailable",
    "securityBlockJailbrokenDevices":  true,
    "osMinimumVersion":  "8.0",
    "osMaximumVersion":  null,
    "minAndroidSecurityPatchLevel":  null,
    "storageRequireEncryption":  true,
    "securityRequireSafetyNetAttestationBasicIntegrity":  true,
    "securityRequireSafetyNetAttestationCertifiedDevice":  false,
    "securityRequireGooglePlayServices":  true,
    "securityRequireUpToDateSecurityProviders":  true,
    "securityRequireCompanyPortalAppIntegrity":  true,
    "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":"","notificationMessageCCList":[]}]}]

}

"@

####################################################

$BaselineMacOS = @"

{
    "@odata.type":  "#microsoft.graph.macOSCompliancePolicy",
    "description":  "This policy measures compliance for personally-owned or corporate-owned MacOS devices.",
    "displayName":  "[ITPM Baseline] MacOS",
    "passwordRequired":  true,
    "passwordBlockSimple":  true,
    "passwordExpirationDays":  null,
    "passwordMinimumLength":  9,
    "passwordMinutesOfInactivityBeforeLock":  5,
    "passwordPreviousPasswordBlockCount":  null,
    "passwordMinimumCharacterSetCount":  null,
    "passwordRequiredType":  "deviceDefault",
    "osMinimumVersion":  "10.13",
    "osMaximumVersion":  null,
    "osMinimumBuildVersion":  null,
    "osMaximumBuildVersion":  null,
    "systemIntegrityProtectionEnabled":  true,
    "deviceThreatProtectionEnabled":  false,
    "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
    "storageRequireEncryption":  true,
    "gatekeeperAllowedAppSource":  "macAppStoreAndIdentifiedDevelopers",
    "firewallEnabled":  true,
    "firewallBlockAllIncoming":  false,
    "firewallEnableStealthMode":  true,
    "scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":"","notificationMessageCCList":[]}]}]

}

"@

####################################################



####################################################
#Import JSON to create policies
####################################################

$Answer = Read-Host "Do you want to import the Baseline MAM policies for iOS and Android (Recommended)? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {

Write-Host "Adding baseline MAM policies for mobile devices..." -ForegroundColor Green

Add-ManagedAppPolicy -JSON $MAM_AndroidBase #OK
Add-ManagedAppPolicy -JSON $MAM_iosBase #OK

Write-Host 
} else 

{ Write-Host "Baseline MAM policies will not be imported" -ForegroundColor Yellow
Write-Host
}


<#
$Answer = Read-Host "Do you want to import the Strict MAM policies for iOS and Android (block unmanaged app sharing)? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {

Write-Host "Adding baseline MAM policies for mobile devices..." -ForegroundColor Green

Add-ManagedAppPolicy -JSON $MAM_AndroidStrict #OK
Add-ManagedAppPolicy -JSON $MAM_iosStrict #OK


Write-Host 
} else 



{ Write-Host "Strict MAM policies will not be imported" -ForegroundColor Yellow
Write-Host
}
#>

####################################################

$Answer = Read-Host "Do you want to import the baseline MDM policies for iOS and Android? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
Write-Host "Adding MDM compliance policies for mobile devices..." -ForegroundColor Green

#Add-DeviceCompliancePolicybaseline -JSON $BaselineAndroidCompany 
Add-DeviceCompliancePolicybaseline -JSON $BLOCKAndroidLegacy
Add-DeviceCompliancePolicybaseline -JSON $BaselineAndroidBYOD 
Add-DeviceCompliancePolicybaseline -JSON $BaselineiOS 

Write-Host } else 

{Write-Host "MDM policies for iOS and Android will not be imported" -ForegroundColor Yellow
Write-Host
}
####################################################

$Answer = Read-Host "Do you want to import the baseline MDM policy for MacOS? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
Write-Host "Adding MDM compliance policies for MacOS..." -ForegroundColor Green

Add-DeviceCompliancePolicybaseline -Json $BaselineMacOS 
Write-Host 

} else {Write-Host "MDM policies for MacOS will not be imported" -ForegroundColor Yellow
Write-Host
}
####################################################
