<##################################################################################################
#
.SYNOPSIS
This script installs app protection policies from JSON:
1. [SMB] Android - App protection baseline
2. [SMB] iOS - App protection baseline

.NOTES
    FileName:    Install-SmbAppProtectionPolicies.ps1
    Author:      Alex Fields 
	Based on:    https://github.com/microsoft/mggraph-intune-samples & https://github.com/Azure/securedworkstation
    Created:     May 2024
	Revised:     May 2024
    Version:     1.0 
    
#>
###################################################################################################

#region connect

# Function to connect to Microsoft Graph
function Connect-ToGraph {
    param (
        [string[]]$RequiredScopes,
        [string[]]$RequiredModules
    )

    # Import required modules
    foreach ($module in $RequiredModules) {
        try {
            #Import the module
            Import-Module -Name $module -ErrorAction Stop
        }
        catch {
            Write-Host "Failed to import $module module. Please install the module first."
            return
        }

    }

    try {
        # Connect to Microsoft Graph using Connect-MgGraph
        Connect-MgGraph -Scopes $RequiredScopes -ErrorAction Stop

        Write-Host "Successfully connected to Microsoft Graph with scopes: $($RequiredScopes -join ', ')"
    }
    catch {
        Write-Host "Failed to connect to Microsoft Graph. Please check your credentials and try again."
        Write-Host "Error: $($_.Exception.Message)"
    }
}

#Define the required scopes
$RequiredScopes = @("DeviceManagementApps.ReadWrite.All")

#Define the required modules
$RequiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Devices.CorporateManagement")

Connect-ToGraph -RequiredScopes $RequiredScopes -RequiredModules $RequiredModules

#endregion

#region functions

# Function to create an App Protection Policy
function New-AppProtectionPolicy {
    param (
        [Parameter(Mandatory = $true)]
        [string]$RawJsonData,
        [Parameter(Mandatory = $true)]
        [ValidateSet("iOS", "Android")]
        [string]$Platform
    )

    try {
        # Convert raw JSON data
        $JSON_Convert = $RawJsonData | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version, deployedAppCount
        $JSON_Apps = $JSON_Convert.apps | Select-Object * -ExcludeProperty id, version
        $JSON_Convert | Add-Member -MemberType NoteProperty -Name 'apps' -Value @($JSON_Apps) -Force
        
        $DisplayName = $JSON_Convert.displayName
        $JSON_Output = $JSON_Convert | ConvertTo-Json -Depth 5

        Write-Host
        Write-Host "App Protection Policy '$DisplayName' Found..." -ForegroundColor Cyan
        Write-Host
        $JSON_Output
        Write-Host

        Write-Host "Adding App Protection Policy '$DisplayName'" -ForegroundColor Yellow
        Write-Host "Creating Policy..."
        Write-Host

        # Create the policy based on the platform
        if ($Platform -eq "iOS") {
            $CreateResult = New-MgDeviceAppMgtiOSManagedAppProtection -BodyParameter $JSON_Output
        } elseif ($Platform -eq "Android") {
            $CreateResult = New-MgDeviceAppMgtAndroidManagedAppProtection -BodyParameter $JSON_Output
        }

        if ($null -ne $CreateResult -and $null -ne $CreateResult.id) {
            Write-Host "Policy created successfully with id: $($CreateResult.id)" -ForegroundColor Green
        } else {
            Write-Host "Policy creation failed: No ID returned" -ForegroundColor Red
        }
    } catch {
        Write-Host "Error creating the app protection policy: $_" -ForegroundColor Red
    }
}

#endregion

#region json

# JSON Data - Sample Android APP policy 
$json_Android = @"

{
    "@odata.context":  "https://graph.microsoft.com/beta/$metadata#deviceAppManagement/androidManagedAppProtections(apps())/$entity",
    "displayName":  "[SMB] Android - App protection",
    "description":  "Protects company data on Android devices. This policy is appropriate for Company and personally owned devices.",
    "periodOfflineBeforeAccessCheck":  "PT12H",
    "periodOnlineBeforeAccessCheck":  "PT5M",
    "allowedInboundDataTransferSources":  "allApps",
    "allowedOutboundDataTransferDestinations":  "managedApps",
    "organizationalCredentialsRequired":  false,
    "allowedOutboundClipboardSharingLevel":  "managedAppsWithPasteIn",
    "dataBackupBlocked":  true,
    "deviceComplianceRequired":  true,
    "managedBrowserToOpenLinksRequired":  false,
    "saveAsBlocked":  true,
    "periodOfflineBeforeWipeIsEnforced":  "P90D",
    "pinRequired":  true,
    "maximumPinRetries":  5,
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
    "minimumRequiredOsVersion":  null,
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
    "mobileThreatDefensePartnerPriority":  null,
    "blockDataIngestionIntoOrganizationDocuments":  false,
    "allowedDataIngestionLocations":  [
                                          "oneDriveForBusiness",
                                          "sharePoint",
                                          "camera",
                                          "photoLibrary"
                                      ],
    "appActionIfUnableToAuthenticateUser":  null,
    "dialerRestrictionLevel":  "allApps",
    "gracePeriodToBlockAppsDuringOffClockHours":  null,
    "isAssigned":  false,
    "targetedAppManagementLevels":  "unspecified",
    "appGroupType":  "allCoreMicrosoftApps",
    "screenCaptureBlocked":  false,
    "disableAppEncryptionIfDeviceEncryptionIsEnabled":  false,
    "encryptAppData":  true,
    "deployedAppCount":  13,
    "minimumRequiredPatchVersion":  "0000-00-00",
    "minimumWarningPatchVersion":  "0000-00-00",
    "minimumWipePatchVersion":  "0000-00-00",
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
    "connectToVpnOnLaunch":  false,
    "appActionIfDevicePasscodeComplexityLessThanLow":  null,
    "appActionIfDevicePasscodeComplexityLessThanMedium":  null,
    "appActionIfDevicePasscodeComplexityLessThanHigh":  null,
    "requireClass3Biometrics":  false,
    "requirePinAfterBiometricChange":  false,
    "fingerprintAndBiometricEnabled":  true,
    "exemptedAppPackages":  [

                            ],
    "approvedKeyboards":  [

                          ],
    "apps@odata.context":  "https://graph.microsoft.com/beta/$metadata#deviceAppManagement/androidManagedAppProtections(\u0027T_5f1787bb-2637-4d35-a75b-838e330f7b3c\u0027)/apps",
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
                 }
             ],
    "@odata.type":  "#microsoft.graph.androidManagedAppProtection"
}
"@

# JSON Data - Sample iOS APP policy 
$json_iOS = @"
{
    "@odata.context":  "https://graph.microsoft.com/beta/$metadata#deviceAppManagement/iosManagedAppProtections(apps())/$entity",
    "displayName":  "[SMB] iOS - App protection",
    "description":  "This policy protects company data on iOS devices",
    "periodOfflineBeforeAccessCheck":  "PT12H",
    "periodOnlineBeforeAccessCheck":  "PT5M",
    "allowedInboundDataTransferSources":  "allApps",
    "allowedOutboundDataTransferDestinations":  "managedApps",
    "organizationalCredentialsRequired":  false,
    "allowedOutboundClipboardSharingLevel":  "managedAppsWithPasteIn",
    "dataBackupBlocked":  true,
    "deviceComplianceRequired":  true,
    "managedBrowserToOpenLinksRequired":  false,
    "saveAsBlocked":  true,
    "periodOfflineBeforeWipeIsEnforced":  "P90D",
    "pinRequired":  true,
    "maximumPinRetries":  5,
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
    "minimumRequiredOsVersion":  null,
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
    "mobileThreatDefensePartnerPriority":  null,
    "blockDataIngestionIntoOrganizationDocuments":  false,
    "allowedDataIngestionLocations":  [
                                          "oneDriveForBusiness",
                                          "sharePoint",
                                          "camera",
                                          "photoLibrary"
                                      ],
    "appActionIfUnableToAuthenticateUser":  null,
    "dialerRestrictionLevel":  "allApps",
    "gracePeriodToBlockAppsDuringOffClockHours":  null,
    "isAssigned":  false,
    "targetedAppManagementLevels":  "unspecified",
    "appGroupType":  "allCoreMicrosoftApps",
    "appDataEncryptionType":  "whenDeviceLocked",
    "minimumRequiredSdkVersion":  null,
    "deployedAppCount":  11,
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
    "managedUniversalLinks":  [
                                  "http://*.appsplatform.us/*",
                                  "http://*.onedrive.com/*",
                                  "http://*.powerapps.cn/*",
                                  "http://*.powerapps.com/*",
                                  "http://*.powerapps.us/*",
                                  "http://*.powerbi.com/*",
                                  "http://*.service-now.com/*",
                                  "http://*.sharepoint-df.com/*",
                                  "http://*.sharepoint.com/*",
                                  "http://*.yammer.com/*",
                                  "http://*.zoom.us/*",
                                  "http://*collab.apps.mil/l/*",
                                  "http://*devspaces.skype.com/l/*",
                                  "http://*teams-fl.microsoft.com/l/*",
                                  "http://*teams.live.com/l/*",
                                  "http://*teams.microsoft.com/l/*",
                                  "http://*teams.microsoft.us/l/*",
                                  "http://app.powerbi.cn/*",
                                  "http://app.powerbi.de/*",
                                  "http://app.powerbigov.us/*",
                                  "http://msit.microsoftstream.com/video/*",
                                  "http://tasks.office.com/*",
                                  "http://to-do.microsoft.com/sharing*",
                                  "http://web.microsoftstream.com/video/*",
                                  "http://zoom.us/*",
                                  "https://*.appsplatform.us/*",
                                  "https://*.onedrive.com/*",
                                  "https://*.powerapps.cn/*",
                                  "https://*.powerapps.com/*",
                                  "https://*.powerapps.us/*",
                                  "https://*.powerbi.com/*",
                                  "https://*.service-now.com/*",
                                  "https://*.sharepoint-df.com/*",
                                  "https://*.sharepoint.com/*",
                                  "https://*.yammer.com/*",
                                  "https://*.zoom.us/*",
                                  "https://*collab.apps.mil/l/*",
                                  "https://*devspaces.skype.com/l/*",
                                  "https://*teams-fl.microsoft.com/l/*",
                                  "https://*teams.live.com/l/*",
                                  "https://*teams.microsoft.com/l/*",
                                  "https://*teams.microsoft.us/l/*",
                                  "https://app.powerbi.cn/*",
                                  "https://app.powerbi.de/*",
                                  "https://app.powerbigov.us/*",
                                  "https://msit.microsoftstream.com/video/*",
                                  "https://tasks.office.com/*",
                                  "https://to-do.microsoft.com/sharing*",
                                  "https://web.microsoftstream.com/video/*",
                                  "https://zoom.us/*"
                              ],
    "exemptedUniversalLinks":  [
                                   "http://facetime.apple.com",
                                   "http://maps.apple.com",
                                   "https://facetime.apple.com",
                                   "https://maps.apple.com"
                               ],
    "minimumWarningSdkVersion":  null,
    "exemptedAppProtocols":  [
                                 {
                                     "name":  "Default",
                                     "value":  "skype;app-settings;calshow;itms;itmss;itms-apps;itms-appss;itms-services;"
                                 }
                             ],
    "apps@odata.context":  "https://graph.microsoft.com/beta/$metadata#deviceAppManagement/iosManagedAppProtections(\u0027T_df1e5af3-b581-4eb5-a1f2-9dd1c2cd5135\u0027)/apps",
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
                     "id":  "com.microsoft.to-do.ios",
                     "version":  "-292160221",
                     "mobileAppIdentifier":  {
                                                 "@odata.type":  "#microsoft.graph.iosMobileAppIdentifier",
                                                 "bundleId":  "com.microsoft.to-do"
                                             }
                 }
             ],
    "@odata.type":  "#microsoft.graph.iosManagedAppProtection"
}
"@

#endregion

#region create policies
# Call the function to create the Android policy
New-AppProtectionPolicy -RawJsonData $json_Android -Platform "Android"

# Call the function to create the iOS policy
New-AppProtectionPolicy -RawJsonData $json_iOS -Platform "iOS"

#endregion

# Disconnect from Microsoft Graph
Disconnect-MgGraph