<##################################################################################################
#
.SYNOPSIS
This script installs the following:

App protection policies:
01. [SMB] Android - App protection 
02. [SMB] iOS - App protection 

Device compliance policies:
01. [SMB] Windows - Immediate compliance
02. [SMB] Windows - Delayed compliance 
03. [SMB] Windows - Microsoft Defender for Business compliance

Device configuration profiles:
01. [SMB] Windows - Endpoint protection
02. [SMB] Windows - Device restrictions
03. [SMB] Windows - Custom CSP
04. [SMB] Windows - Enable Hello
05. [SMB] Windows - Health monitoring
06. [SMB] Windows - Default Update Ring
07. [SMB] Windows - Delayed Updated Ring 

Device configuration profiles (ADMX templates):
08. [SMB] Windows - Edge browser 
09. [SMB] Windows - OneDrive client settings

Conditional Access policies:
01. [SMB] 0.01 - Block legacy authentication
02. [SMB] 0.02 - Require MFA for management
03. [SMB] 0.03 - Require MFA to register or join devices
04. [SMB] 0.04 - Block unknown or unsupported device platforms
05. [SMB] 0.05 - No persistent browser on unmanaged devices
06. [SMB] 1.01 - Require MFA for admins
07. [SMB] 2.01 - Require MFA for internals
08. [SMB] 2.02 - Securing MFA registration for internals
09. [SMB] 2.03 - Require app protection for Office 365 mobile access
10. [SMB] 2.04 - Require compliant device for Office 365 desktop access
11. [SMB] 3.01 - Require MFA for externals

.NOTES
    FileName:    Install-SmbSecurityProfile.ps1
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
$RequiredScopes = @("Policy.ReadWrite.ConditionalAccess", "DeviceManagementApps.ReadWrite.All", "DeviceManagementConfiguration.ReadWrite.All", "Directory.Read.All")

#Define the required modules
$RequiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.SignIns", "Microsoft.Graph.Devices.CorporateManagement", "Microsoft.Graph.DeviceManagement")

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

#Function to create a Compliance Policy
function New-CompliancePolicy {
    param (
        [Parameter(Mandatory = $true)]
        [string]$JsonData
    )

    try {
        # Define the Graph API URI for creating compliance policies
        $graphUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"

        # Create the compliance policy in Microsoft Graph using Invoke-MgGraphRequest
        $response = Invoke-MgGraphRequest -Method POST -Uri $graphUri -Body $JsonData -ContentType "application/json"
        
        Write-Output "Compliance policy created successfully."
    }
    catch {
        Write-Error "Failed to create compliance policy: $($_.Exception.Message)"
    }
}

#Function to create a new Device Configuration Profile
function New-DeviceConfigurationProfile {
    param (
        [Parameter(Mandatory = $true)]
        [string]$jsonData
    )

    try {
        # Define the Graph API URI for creating device configuration profiles
        $graphUri = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations"

        # Create the device configuration profile using the provided JSON 
        $response = Invoke-MgGraphRequest -Method POST -Uri $graphUri -Body $jsonData -ErrorAction Stop

        Write-Output "Device configuration profile created successfully."
    }
    catch {
        Write-Error "Error creating device configuration profile: $($_.Exception.Message)"
    }
}

#Function to create a Group Policy Configuration
function New-GroupPolicyConfiguration {
    param (
        [string]$DisplayName,
        [string]$Description
    )

    try {
        # Create the device configuration profile (Group Policy Configuration)
        $profile = New-Object -TypeName PSCustomObject -Property @{
            "@odata.type" = "#microsoft.graph.groupPolicyConfiguration"
            "displayName" = $DisplayName
            "description" = $Description
        }

        # Convert the profile to JSON
        $profileJson = $profile | ConvertTo-Json -Depth 10

        # Define the Graph API URI for creating group policy config profiles
        $graphUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations"
        
        # Create the configuration profile using the provided JSON
        $response = Invoke-MgGraphRequest -Method POST -Uri $graphUri -Body $profileJson -ContentType "application/json"

        # Return the ID of the created profile
        return $response.id
    }
    catch {
        Write-Error "An error occurred while creating the group policy configuration: $($_.Exception.Message)"
    }
}

#Function to install Group Policy Definition values
function Set-GroupPolicyDefinitionValues {
    param (
        [string]$ProfileId,
        [string]$JsonData
    )

    try {
        # Convert the JSON data to a PowerShell object
        $policyData = $JsonData | ConvertFrom-Json

        # Add the definition values to the created profile
        foreach ($definition in $policyData) {
            $definitionJson = $definition | ConvertTo-Json -Depth 10
            $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$ProfileId/definitionValues"
            Invoke-MgGraphRequest -Method POST -Uri $uri -Body $definitionJson -ContentType "application/json"
        }
    }
    catch {
        Write-Error "An error occurred while setting group policy definition values: $($_.Exception.Message)"
    }
}

#Function to retrieve the tenant ID
function Get-TenantID {
    try {
        # Retrieve and store tenant ID in a variable
        $tenantID = Get-MgOrganization | Select-Object -ExpandProperty Id

        # Check if tenantID was successfully retrieved
        if ($null -eq $tenantID) {
            throw "Failed to retrieve the tenant ID."
        }

        # Output tenant ID
        Write-Output $tenantID
    }
    catch {
        # Handle errors and output the error message
        Write-Error "An error occurred while retrieving the tenant ID: $_"
    }
}

#Retrieve the tenant ID
$myTenantID = Get-TenantID

# Function to create a Conditional Access Policy
function New-ConditionalAccessPolicy {
    param (
        [string]$JsonData
    )

    try {
        # Create the conditional access policy
        New-MgIdentityConditionalAccessPolicy -BodyParameter $JsonData -ErrorAction Stop
        Write-Output "Conditional access policy created successfully."
    } catch {
        Write-Error "Error creating conditional access policy: $($_.Exception.Message)" 
        
    }
}

#endregion

#region json

#App protection policies 
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


#Compliance policies
$smbImmediate = @'
{
    "@odata.type":  "#microsoft.graph.windows10CompliancePolicy",
    "description":  "Intune compliance settings to apply immediately\n",
    "displayName":  "[SMB] Windows - Immediate compliance",
    "osMinimumVersion":  "10.0.19045.0",
    "bitLockerEnabled":  false,
    "secureBootEnabled":  false,
    "codeIntegrityEnabled":  false,
    "storageRequireEncryption":  false,
    "activeFirewallRequired":  false,
    "defenderEnabled":  true,
    "defenderVersion":  null,
    "signatureOutOfDate":  false,
    "rtpEnabled":  true,
    "antivirusRequired":  false,
    "antiSpywareRequired":  false,
    "deviceThreatProtectionEnabled":  false,
    "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
    "tpmRequired":  false,
    "scheduledActionsForRule":  [
        {
            "ruleName":  null,
            "@odata.type":  "#microsoft.graph.deviceComplianceScheduledActionForRule",
            "scheduledActionConfigurations":  [
                {
                    "gracePeriodHours":  0,
                    "actionType":  "block",
                    "notificationTemplateId":  ""
                }
            ]
        }
    ]
}
'@

$smbDelayed = @'
{
    "@odata.type":  "#microsoft.graph.windows10CompliancePolicy",
    "description":  "Intune compliance settings to apply after a 24 hour grace period\n",
    "displayName":  "[SMB] Windows - Delayed compliance",
    "osMinimumVersion":  "10.0.19045.0",
    "bitLockerEnabled":  true,
    "secureBootEnabled":  true,
    "codeIntegrityEnabled":  true,
    "storageRequireEncryption":  false,
    "activeFirewallRequired":  true,
    "defenderEnabled":  true,
    "defenderVersion":  null,
    "signatureOutOfDate":  true,
    "rtpEnabled":  true,
    "antivirusRequired":  true,
    "antiSpywareRequired":  true,
    "deviceThreatProtectionEnabled":  false,
    "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
    "tpmRequired":  true,
    "scheduledActionsForRule":  [
        {
            "ruleName":  null,
            "@odata.type":  "#microsoft.graph.deviceComplianceScheduledActionForRule",
            "scheduledActionConfigurations":  [
                {
                    "gracePeriodHours":  24,
                    "actionType":  "block",
                    "notificationTemplateId":  ""
                }
            ]
        }
    ]
}
'@

$smbDefender = @'
{
    "@odata.type":  "#microsoft.graph.windows10CompliancePolicy",
    "description":  "Defender for Business compliance settings to apply after 24 hour grace period\n",
    "displayName":  "[SMB] Windows - Defender for Business compliance",
    "deviceThreatProtectionEnabled":  true,
    "deviceThreatProtectionRequiredSecurityLevel":  "low",
    "scheduledActionsForRule":  [
        {
            "ruleName":  null,
            "@odata.type":  "#microsoft.graph.deviceComplianceScheduledActionForRule",
            "scheduledActionConfigurations":  [
                {
                    "gracePeriodHours":  24,
                    "actionType":  "block",
                    "notificationTemplateId":  ""
                }
            ]
        }
    ]
}
'@


#Device config profiles
$smbEndpointProtection = @"
{
    "@odata.type": "#microsoft.graph.windows10EndpointProtectionConfiguration",
    "description": "This profile enables a number of critical security features such as the Windows Firewall, BitLocker, Attack Surface Reduction rules, User Account Control, automatic screen lock, and more. This policy is appropriate for Company-owned devices.",
    "displayName": "[SMB] Windows - Endpoint protection",
    "dmaGuardDeviceEnumerationPolicy": "deviceDefault",
    "xboxServicesEnableXboxGameSaveTask": false,
    "xboxServicesAccessoryManagementServiceStartupMode": "disabled",
    "xboxServicesLiveAuthManagerServiceStartupMode": "disabled",
    "xboxServicesLiveGameSaveServiceStartupMode": "disabled",
    "xboxServicesLiveNetworkingServiceStartupMode": "disabled",
    "localSecurityOptionsBlockMicrosoftAccounts": true,
    "localSecurityOptionsBlockRemoteLogonWithBlankPassword": true,
    "localSecurityOptionsDisableAdministratorAccount": true,
    "localSecurityOptionsDisableGuestAccount": true,
    "localSecurityOptionsAllowUndockWithoutHavingToLogon": true,
    "localSecurityOptionsBlockRemoteOpticalDriveAccess": true,
    "localSecurityOptionsMachineInactivityLimit": 5,
    "localSecurityOptionsMachineInactivityLimitInMinutes": 5,
    "localSecurityOptionsDoNotRequireCtrlAltDel": false,
    "localSecurityOptionsHideLastSignedInUser": false,
    "localSecurityOptionsHideUsernameAtSignIn": false,
    "localSecurityOptionsAllowPKU2UAuthenticationRequests": true,
    "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManagerHelperBool": false,
    "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedClients": "ntlmV2And128BitEncryption",
    "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedServers": "ntlmV2And128BitEncryption",
    "lanManagerAuthenticationLevel": "lmNtlmV2AndNotLmOrNtm",
    "lanManagerWorkstationDisableInsecureGuestLogons": true,
    "localSecurityOptionsClearVirtualMemoryPageFile": false,
    "localSecurityOptionsAllowSystemToBeShutDownWithoutHavingToLogOn": false,
    "localSecurityOptionsAllowUIAccessApplicationElevation": true,
    "localSecurityOptionsVirtualizeFileAndRegistryWriteFailuresToPerUserLocations": true,
    "localSecurityOptionsOnlyElevateSignedExecutables": true,
    "localSecurityOptionsAdministratorElevationPromptBehavior": "promptForConsentOnTheSecureDesktop",
    "localSecurityOptionsStandardUserElevationPromptBehavior": "promptForCredentialsOnTheSecureDesktop",
    "localSecurityOptionsSwitchToSecureDesktopWhenPromptingForElevation": false,
    "localSecurityOptionsDetectApplicationInstallationsAndPromptForElevation": true,
    "localSecurityOptionsAllowUIAccessApplicationsForSecureLocations": false,
    "localSecurityOptionsUseAdminApprovalMode": false,
    "localSecurityOptionsUseAdminApprovalModeForAdministrators": false,
    "localSecurityOptionsInformationShownOnLockScreen": "notConfigured",
    "localSecurityOptionsInformationDisplayedOnLockScreen": "notConfigured",
    "localSecurityOptionsDisableClientDigitallySignCommunicationsIfServerAgrees": false,
    "localSecurityOptionsClientDigitallySignCommunicationsAlways": true,
    "localSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers": true,
    "localSecurityOptionsDisableServerDigitallySignCommunicationsAlways": false,
    "localSecurityOptionsDisableServerDigitallySignCommunicationsIfClientAgrees": false,
    "localSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares": true,
    "localSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts": true,
    "localSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares": true,
    "localSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange": true,
    "localSecurityOptionsSmartCardRemovalBehavior": "noAction",
    "defenderSecurityCenterDisableAppBrowserUI": false,
    "defenderSecurityCenterDisableFamilyUI": true,
    "defenderSecurityCenterDisableHealthUI": false,
    "defenderSecurityCenterDisableNetworkUI": false,
    "defenderSecurityCenterDisableVirusUI": false,
    "defenderSecurityCenterDisableAccountUI": false,
    "defenderSecurityCenterDisableClearTpmUI": true,
    "defenderSecurityCenterDisableRansomwareUI": false,
    "defenderSecurityCenterDisableVulnerableTpmFirmwareUpdateUI": true,
    "defenderSecurityCenterNotificationsFromApp": "blockNoncriticalNotifications",
    "defenderSecurityCenterITContactDisplay": "notConfigured",
    "windowsDefenderTamperProtection": "enable",
    "firewallBlockStatefulFTP": true,
    "defenderAdobeReaderLaunchChildProcess": "enable",
    "defenderAttackSurfaceReductionExcludedPaths": [],
    "defenderOfficeAppsOtherProcessInjectionType": "block",
    "defenderOfficeAppsOtherProcessInjection": "enable",
    "defenderOfficeCommunicationAppsLaunchChildProcess": "enable",
    "defenderOfficeAppsExecutableContentCreationOrLaunchType": "block",
    "defenderOfficeAppsExecutableContentCreationOrLaunch": "enable",
    "defenderOfficeAppsLaunchChildProcessType": "block",
    "defenderOfficeAppsLaunchChildProcess": "enable",
    "defenderOfficeMacroCodeAllowWin32ImportsType": "block",
    "defenderOfficeMacroCodeAllowWin32Imports": "enable",
    "defenderScriptObfuscatedMacroCodeType": "block",
    "defenderScriptObfuscatedMacroCode": "enable",
    "defenderScriptDownloadedPayloadExecutionType": "block",
    "defenderScriptDownloadedPayloadExecution": "enable",
    "defenderPreventCredentialStealingType": "enable",
    "defenderProcessCreationType": "block",
    "defenderProcessCreation": "enable",
    "defenderUntrustedUSBProcessType": "block",
    "defenderUntrustedUSBProcess": "enable",
    "defenderUntrustedExecutableType": "block",
    "defenderUntrustedExecutable": "enable",
    "defenderEmailContentExecutionType": "block",
    "defenderEmailContentExecution": "enable",
    "defenderAdvancedRansomewareProtectionType": "enable",
    "defenderGuardMyFoldersType": "userDefined",
    "defenderGuardedFoldersAllowedAppPaths": [],
    "defenderAdditionalGuardedFolders": [],
    "defenderNetworkProtectionType": "enable",
    "defenderSecurityCenterBlockExploitProtectionOverride": true,
    "defenderBlockPersistenceThroughWmiType": "userDefined",
    "smartScreenEnableInShell": true,
    "smartScreenBlockOverrideForFiles": true,
    "bitLockerAllowStandardUserEncryption": true,
    "bitLockerDisableWarningForOtherDiskEncryption": true,
    "bitLockerEnableStorageCardEncryptionOnMobile": false,
    "bitLockerEncryptDevice": true,
    "bitLockerRecoveryPasswordRotation": "enabledForAzureAd",
    "firewallRules": [],
    "firewallProfileDomain": {
        "firewallEnabled": "allowed",
        "inboundNotificationsBlocked": true,
        "outboundConnectionsRequired": true,
        "inboundConnectionsBlocked": true,
        "policyRulesFromGroupPolicyNotMerged": false
    },
    "firewallProfilePublic": {
        "firewallEnabled": "allowed",
        "inboundNotificationsBlocked": true,
        "outboundConnectionsRequired": true,
        "inboundConnectionsBlocked": true,
        "policyRulesFromGroupPolicyNotMerged": false
    },
    "firewallProfilePrivate": {
        "firewallEnabled": "allowed",
        "inboundNotificationsBlocked": true,
        "outboundConnectionsRequired": true,
        "inboundConnectionsBlocked": true,
        "policyRulesFromGroupPolicyNotMerged": false
    },
    "bitLockerSystemDrivePolicy": {
        "encryptionMethod": "xtsAes128",
        "startupAuthenticationRequired": true,
        "startupAuthenticationBlockWithoutTpmChip": true,
        "startupAuthenticationTpmUsage": "allowed",
        "startupAuthenticationTpmPinUsage": "allowed",
        "startupAuthenticationTpmKeyUsage": "allowed",
        "startupAuthenticationTpmPinAndKeyUsage": "allowed",
        "recoveryOptions": {
            "blockDataRecoveryAgent": true,
            "recoveryPasswordUsage": "allowed",
            "recoveryKeyUsage": "allowed",
            "hideRecoveryOptions": true,
            "enableRecoveryInformationSaveToStore": true,
            "recoveryInformationToStore": "passwordAndKey",
            "enableBitLockerAfterRecoveryInformationToStore": true
        }
    },
    "bitLockerFixedDrivePolicy": {
        "encryptionMethod": "xtsAes128",
        "requireEncryptionForWriteAccess": true,
        "recoveryOptions": {
            "blockDataRecoveryAgent": true,
            "recoveryPasswordUsage": "allowed",
            "recoveryKeyUsage": "allowed",
            "hideRecoveryOptions": true,
            "enableRecoveryInformationSaveToStore": true,
            "recoveryInformationToStore": "passwordAndKey",
            "enableBitLockerAfterRecoveryInformationToStore": true
        }
    },
    "bitLockerRemovableDrivePolicy": {
        "encryptionMethod": "aesCbc128",
        "requireEncryptionForWriteAccess": false,
        "blockCrossOrganizationWriteAccess": false
    }
}
"@

$smbDeviceRestrictions = @"
{
    "@odata.type": "#microsoft.graph.windows10GeneralConfiguration",
    "description":  "",
    "displayName":  "[SMB] Windows - Device restrictions",
    "taskManagerBlockEndTask":  false,
    "powerHybridSleepOnBattery":  "enabled",
    "powerHybridSleepPluggedIn":  "enabled",
    "enableAutomaticRedeployment":  true,
    "authenticationAllowSecondaryDevice":  true,
    "experienceDoNotSyncBrowserSettings":  "blocked",
    "messagingBlockSync":  false,
    "messagingBlockMMS":  false,
    "messagingBlockRichCommunicationServices":  false,
    "printerBlockAddition":  false,
    "searchBlockDiacritics":  false,
    "searchDisableAutoLanguageDetection":  false,
    "searchDisableIndexingEncryptedItems":  false,
    "searchEnableRemoteQueries":  false,
    "searchDisableUseLocation":  false,
    "searchDisableLocation":  false,
    "searchDisableIndexerBackoff":  false,
    "searchDisableIndexingRemovableDrive":  false,
    "searchEnableAutomaticIndexSizeManangement":  false,
    "searchBlockWebResults":  false,
    "securityBlockAzureADJoinedDevicesAutoEncryption":  false,
    "diagnosticsDataSubmissionMode":  "enhanced",
    "oneDriveDisableFileSync":  false,
    "systemTelemetryProxyServer":  null,
    "inkWorkspaceAccess":  "disabled",
    "inkWorkspaceAccessState":  "blocked",
    "inkWorkspaceBlockSuggestedApps":  false,
    "smartScreenEnableAppInstallControl":  false,
    "bluetoothBlockAdvertising":  false,
    "bluetoothBlockPromptedProximalConnections":  false,
    "bluetoothBlockDiscoverableMode":  false,
    "bluetoothBlockPrePairing":  false,
    "edgeBlockAutofill":  false,
    "edgeBlocked":  false,
    "edgeCookiePolicy":  "userDefined",
    "edgeBlockDeveloperTools":  true,
    "edgeBlockSendingDoNotTrackHeader":  true,
    "edgeBlockExtensions":  false,
    "edgeBlockInPrivateBrowsing":  true,
    "edgeBlockJavaScript":  false,
    "edgeBlockPasswordManager":  false,
    "edgeBlockAddressBarDropdown":  false,
    "edgeBlockCompatibilityList":  false,
    "edgeClearBrowsingDataOnExit":  true,
    "edgeAllowStartPagesModification":  false,
    "edgeDisableFirstRunPage":  false,
    "edgeBlockLiveTileDataCollection":  true,
    "edgeSyncFavoritesWithInternetExplorer":  false,
    "edgeBlockEditFavorites":  false,
    "edgeHomeButtonConfigurationEnabled":  false,
    "edgeBlockSideloadingExtensions":  false,
    "edgeBlockPrinting":  false,
    "edgeBlockSavingHistory":  true,
    "edgeBlockFullScreenMode":  false,
    "edgeBlockWebContentOnNewTabPage":  false,
    "edgeBlockTabPreloading":  false,
    "edgeBlockPrelaunch":  false,
    "edgePreventCertificateErrorOverride":  true,
    "cellularBlockDataWhenRoaming":  false,
    "cellularBlockVpn":  false,
    "cellularBlockVpnWhenRoaming":  false,
    "cellularData":  "allowed",
    "defenderRequireRealTimeMonitoring":  true,
    "defenderRequireBehaviorMonitoring":  true,
    "defenderRequireNetworkInspectionSystem":  true,
    "defenderScanDownloads":  true,
    "defenderScheduleScanEnableLowCpuPriority":  false,
    "defenderDisableCatchupQuickScan":  false,
    "defenderDisableCatchupFullScan":  false,
    "defenderScanScriptsLoadedInInternetExplorer":  true,
    "defenderBlockEndUserAccess":  false,
    "defenderSignatureUpdateIntervalInHours":  1,
    "defenderMonitorFileActivity":  "userDefined",
    "defenderScanArchiveFiles":  true,
    "defenderScanIncomingMail":  true,
    "defenderScanRemovableDrivesDuringFullScan":  true,
    "defenderScanMappedNetworkDrivesDuringFullScan":  false,
    "defenderScanNetworkFiles":  true,
    "defenderRequireCloudProtection":  true,
    "defenderCloudBlockLevel":  "high",
    "defenderCloudExtendedTimeout":  50,
    "defenderCloudExtendedTimeoutInSeconds":  50,
    "defenderPromptForSampleSubmission":  "sendAllDataWithoutPrompting",
    "defenderScheduledQuickScanTime":  "18:00:00.0000000",
    "defenderScanType":  "full",
    "defenderSystemScanSchedule":  "saturday",
    "defenderScheduledScanTime":  "18:00:00.0000000",
    "defenderPotentiallyUnwantedAppAction":  "block",
    "defenderPotentiallyUnwantedAppActionSetting":  "userDefined",
    "defenderSubmitSamplesConsentType":  "sendSafeSamplesAutomatically",
    "defenderBlockOnAccessProtection":  false,
    "lockScreenAllowTimeoutConfiguration":  false,
    "lockScreenBlockActionCenterNotifications":  false,
    "lockScreenBlockCortana":  true,
    "lockScreenBlockToastNotifications":  true,
    "lockScreenTimeoutInSeconds":  null,
    "passwordBlockSimple":  true,
    "passwordExpirationDays":  null,
    "passwordMinimumLength":  9,
    "passwordMinutesOfInactivityBeforeScreenTimeout":  15,
    "passwordMinimumCharacterSetCount":  2,
    "passwordPreviousPasswordBlockCount":  null,
    "passwordRequired":  true,
    "passwordRequireWhenResumeFromIdleState":  true,
    "passwordRequiredType":  "alphanumeric",
    "passwordSignInFailureCountBeforeFactoryReset":  9,
    "passwordMinimumAgeInDays":  null,
    "privacyAutoAcceptPairingAndConsentPrompts":  false,
    "privacyDisableLaunchExperience":  false,
    "privacyBlockInputPersonalization":  false,
    "privacyBlockPublishUserActivities":  true,
    "privacyBlockActivityFeed":  true,
    "startBlockUnpinningAppsFromTaskbar":  false,
    "startMenuAppListVisibility":  "userDefined",
    "startMenuHideChangeAccountSettings":  false,
    "startMenuHideFrequentlyUsedApps":  false,
    "startMenuHideHibernate":  false,
    "startMenuHideLock":  false,
    "startMenuHidePowerButton":  false,
    "startMenuHideRecentJumpLists":  false,
    "startMenuHideRecentlyAddedApps":  false,
    "startMenuHideRestartOptions":  false,
    "startMenuHideShutDown":  false,
    "startMenuHideSignOut":  false,
    "startMenuHideSleep":  true,
    "startMenuHideSwitchAccount":  true,
    "startMenuHideUserTile":  false,
    "startMenuLayoutXml":  "",
    "startMenuMode":  "userDefined",
    "startMenuPinnedFolderHomeGroup":  "hide",
    "startMenuPinnedFolderMusic":  "hide",
    "startMenuPinnedFolderNetwork":  "hide",
    "settingsBlockSettingsApp":  false,
    "settingsBlockSystemPage":  false,
    "settingsBlockDevicesPage":  false,
    "settingsBlockNetworkInternetPage":  false,
    "settingsBlockPersonalizationPage":  false,
    "settingsBlockAccountsPage":  false,
    "settingsBlockTimeLanguagePage":  false,
    "settingsBlockEaseOfAccessPage":  false,
    "settingsBlockPrivacyPage":  true,
    "settingsBlockUpdateSecurityPage":  false,
    "settingsBlockAppsPage":  false,
    "settingsBlockGamingPage":  true,
    "windowsSpotlightBlockConsumerSpecificFeatures":  false,
    "windowsSpotlightBlocked":  false,
    "windowsSpotlightBlockOnActionCenter":  false,
    "windowsSpotlightBlockTailoredExperiences":  false,
    "windowsSpotlightBlockThirdPartyNotifications":  false,
    "windowsSpotlightBlockWelcomeExperience":  false,
    "windowsSpotlightBlockWindowsTips":  false,
    "networkProxyApplySettingsDeviceWide":  false,
    "networkProxyDisableAutoDetect":  false,
    "networkProxyAutomaticConfigurationUrl":  null,
    "networkProxyServer":  null,
    "accountsBlockAddingNonMicrosoftAccountEmail":  true,
    "antiTheftModeBlocked":  false,
    "bluetoothBlocked":  false,
    "cameraBlocked":  false,
    "connectedDevicesServiceBlocked":  true,
    "certificatesBlockManualRootCertificateInstallation":  false,
    "copyPasteBlocked":  false,
    "cortanaBlocked":  false,
    "deviceManagementBlockFactoryResetOnMobile":  false,
    "deviceManagementBlockManualUnenroll":  true,
    "safeSearchFilter":  "userDefined",
    "edgeBlockPopups":  false,
    "edgeBlockSearchSuggestions":  false,
    "edgeBlockSearchEngineCustomization":  false,
    "edgeBlockSendingIntranetTrafficToInternetExplorer":  false,
    "edgeSendIntranetTrafficToInternetExplorer":  false,
    "edgeRequireSmartScreen":  true,
    "edgeBlockAccessToAboutFlags":  false,
    "smartScreenBlockPromptOverride":  true,
    "smartScreenBlockPromptOverrideForFiles":  true,
    "webRtcBlockLocalhostIpAddress":  true,
    "internetSharingBlocked":  true,
    "settingsBlockAddProvisioningPackage":  true,
    "settingsBlockRemoveProvisioningPackage":  true,
    "settingsBlockChangeSystemTime":  true,
    "settingsBlockEditDeviceName":  false,
    "settingsBlockChangeRegion":  false,
    "settingsBlockChangeLanguage":  false,
    "settingsBlockChangePowerSleep":  false,
    "locationServicesBlocked":  false,
    "microsoftAccountBlocked":  false,
    "microsoftAccountBlockSettingsSync":  true,
    "nfcBlocked":  false,
    "resetProtectionModeBlocked":  false,
    "screenCaptureBlocked":  false,
    "storageBlockRemovableStorage":  false,
    "storageRequireMobileDeviceEncryption":  false,
    "usbBlocked":  false,
    "voiceRecordingBlocked":  false,
    "wiFiBlockAutomaticConnectHotspots":  false,
    "wiFiBlocked":  false,
    "wiFiBlockManualConfiguration":  false,
    "wiFiScanInterval":  null,
    "wirelessDisplayBlockProjectionToThisDevice":  false,
    "wirelessDisplayBlockUserInputFromReceiver":  false,
    "wirelessDisplayRequirePinForPairing":  true,
    "windowsStoreBlocked":  false,
    "appsAllowTrustedAppsSideloading":  "allowed",
    "windowsStoreBlockAutoUpdate":  false,
    "developerUnlockSetting":  "blocked",
    "sharedUserAppDataAllowed":  true,
    "appsBlockWindowsStoreOriginatedApps":  false,
    "windowsStoreEnablePrivateStoreOnly":  true,
    "storageRestrictAppDataToSystemVolume":  false,
    "storageRestrictAppInstallToSystemVolume":  false,
    "gameDvrBlocked":  true,
    "experienceBlockDeviceDiscovery":  false,
    "experienceBlockErrorDialogWhenNoSIM":  false,
    "experienceBlockTaskSwitcher":  false,
    "logonBlockFastUserSwitching":  true,
    "tenantLockdownRequireNetworkDuringOutOfBoxExperience":  true,
    "appManagementMSIAllowUserControlOverInstall":  false,
    "appManagementMSIAlwaysInstallWithElevatedPrivileges":  false,
    "dataProtectionBlockDirectMemoryAccess":  true,
    "uninstallBuiltInApps":  false,
    "defenderDetectedMalwareActions":  {
                                           "lowSeverity":  "quarantine",
                                           "moderateSeverity":  "quarantine",
                                           "highSeverity":  "quarantine",
                                           "severeSeverity":  "quarantine"
                                       },
    "edgeSearchEngine":  {
                             "@odata.type":  "#microsoft.graph.edgeSearchEngine",
                             "edgeSearchEngineType":  "default"
                         }
}
"@

$smbCustomCSP = @"
{
    "@odata.type":  "#microsoft.graph.windows10CustomConfiguration",
    "description":  "",
    "displayName":  "[SMB] Windows - Custom CSP",
    "omaSettings":  [
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "NetworkIsolation/EnterpriseProxyServersAreAuthoritative",
                            "description":  "EnterpriseProxyServersAreAuthoritative",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/NetworkIsolation/EnterpriseProxyServersAreAuthoritative",
                            "isEncrypted":  false,
                            "value":  1,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "NetworkIsolation/EnterpriseIPRangesAreAuthoritative",
                            "description":  "EnterpriseIPRangesAreAuthoritative",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/NetworkIsolation/EnterpriseIPRangesAreAuthoritative",
                            "isEncrypted":  false,
                            "value":  1,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "Search/AllowIndexingEncryptedStoresOrItems",
                            "description":  "AllowIndexingEncryptedStoresOrItems",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Search/AllowIndexingEncryptedStoresOrItems",
                            "isEncrypted":  false,
                            "value":  0,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "LanmanWorkstation/EnableInsecureGuestLogons",
                            "description":  "EnableInsecureGuestLogons",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/LanmanWorkstation/EnableInsecureGuestLogons",
                            "isEncrypted":  false,
                            "value":  0,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "Games/AllowAdvancedGamingServices",
                            "description":  "AllowAdvancedGamingServices",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Games/AllowAdvancedGamingServices",
                            "isEncrypted":  false,
                            "value":  0,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "ControlPolicyConflict/MDMWinsOverGP",
                            "description":  "MDMWinsOverGP",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/ControlPolicyConflict/MDMWinsOverGP",
                            "isEncrypted":  false,
                            "value":  1,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "SystemServices/ConfigureHomeGroupListenerServiceStartupMode",
                            "description":  "ConfigureHomeGroupListenerServiceStartupMode",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/SystemServices/ConfigureHomeGroupListenerServiceStartupMode",
                            "isEncrypted":  false,
                            "value":  4,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "SystemServices/ConfigureHomeGroupProviderServiceStartupMode",
                            "description":  "ConfigureHomeGroupProviderServiceStartupMode",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/SystemServices/ConfigureHomeGroupProviderServiceStartupMode",
                            "isEncrypted":  false,
                            "value":  4,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "ErrorReporting/DisableWindowsErrorReporting",
                            "description":  "DisableWindowsErrorReporting",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/ErrorReporting/DisableWindowsErrorReporting",
                            "isEncrypted":  false,
                            "value":  " \u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Power/AllowStandbyWhenSleepingPluggedIn",
                            "description":  "AllowStandbyWhenSleepingPluggedIn",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Power/AllowStandbyWhenSleepingPluggedIn",
                            "isEncrypted":  false,
                            "value":  "\u003cdisabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Power/RequirePasswordWhenComputerWakesOnBattery",
                            "description":  "RequirePasswordWhenComputerWakesOnBattery",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Power/RequirePasswordWhenComputerWakesOnBattery",
                            "isEncrypted":  false,
                            "value":  " \u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Power/RequirePasswordWhenComputerWakesPluggedIn",
                            "description":  "RequirePasswordWhenComputerWakesPluggedIn",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Power/RequirePasswordWhenComputerWakesPluggedIn",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "RemoteAssistance/SolicitedRemoteAssistance",
                            "description":  "SolicitedRemoteAssistance",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/RemoteAssistance/SolicitedRemoteAssistance",
                            "isEncrypted":  false,
                            "value":  "\u003cdisabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "AutoPlay/DisallowAutoplayForNonVolumeDevices",
                            "description":  "DisallowAutoplayForNonVolumeDevices",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/AutoPlay/DisallowAutoplayForNonVolumeDevices",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "RemoteDesktopServices/DoNotAllowDriveRedirection",
                            "description":  "DoNotAllowDriveRedirection",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/DoNotAllowDriveRedirection",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "RemoteDesktopServices/PromptForPasswordUponConnection",
                            "description":  "PromptForPasswordUponConnection",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/PromptForPasswordUponConnection",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "RemoteDesktopServices/RequireSecureRPCCommunication",
                            "description":  "RequireSecureRPCCommunication",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/RemoteDesktopServices/RequireSecureRPCCommunication",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "DeviceLock/PreventLockScreenSlideShow",
                            "description":  "PreventLockScreenSlideShow",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventLockScreenSlideShow",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "MSSecurityGuide/EnableStructuredExceptionHandlingOverwriteProtection",
                            "description":  "EnableStructuredExceptionHandlingOverwriteProtection",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/EnableStructuredExceptionHandlingOverwriteProtection",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "MSSLegacy/AllowICMPRedirectsToOverrideOSPFGeneratedRoutes",
                            "description":  "AllowICMPRedirectsToOverrideOSPFGeneratedRoutes",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/AllowICMPRedirectsToOverrideOSPFGeneratedRoutes",
                            "isEncrypted":  false,
                            "value":  "\u003cdisabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "MSSLegacy/AllowTheComputerToIgnoreNetBIOSNameReleaseRequestsExceptFromWINSServers",
                            "description":  "AllowTheComputerToIgnoreNetBIOSNameReleaseRequestsExceptFromWINSServers",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/AllowTheComputerToIgnoreNetBIOSNameReleaseRequestsExceptFromWINSServers",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "WindowsDefenderApplicationGuard/Audit/AuditApplicationGuard",
                            "description":  "AuditApplicationGuard",
                            "omaUri":  "./Device/Vendor/MSFT/WindowsDefenderApplicationGuard/Audit/AuditApplicationGuard",
                            "isEncrypted":  false,
                            "value":  1,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "DeviceLock/MaxDevicePasswordFailedAttempts",
                            "description":  "MaxDevicePasswordFailedAttempts",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/DeviceLock/MaxDevicePasswordFailedAttempts",
                            "isEncrypted":  false,
                            "value":  9,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "Start/HidePeopleBar",
                            "description":  "HidePeopleBar ",
                            "omaUri":  "./User/Vendor/MSFT/Policy/Config/Start/HidePeopleBar",
                            "isEncrypted":  false,
                            "value":  1,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "Browser/AllowFlash",
                            "description":  "AllowFlash",
                            "omaUri":  "./Vendor/MSFT/Policy/Config/Browser/AllowFlash",
                            "isEncrypted":  false,
                            "value":  0,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "Privacy/AllowCrossDeviceClipboard",
                            "description":  "AllowCrossDeviceClipboard",
                            "omaUri":  "./Vendor/MSFT/Policy/Config/Privacy/AllowCrossDeviceClipboard",
                            "isEncrypted":  false,
                            "value":  0,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "Experience/DoNotShowFeedbackNotifications",
                            "description":  "HideFeedbackNotifications",
                            "omaUri":  "./Vendor/MSFT/Policy/Config/Experience/DoNotShowFeedbackNotifications",
                            "isEncrypted":  false,
                            "value":  1,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "MSSecurityGuide/ApplyUACRestrictionsToLocalAccountsOnNetworkLogon",
                            "description":  "ApplyUACRestrictionsToLocalAccountsOnNetworkLogon",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ApplyUACRestrictionsToLocalAccountsOnNetworkLogon",
                            "isEncrypted":  false,
                            "value":  "\u003cEnabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Connectivity/ProhibitInstallationAndConfigurationOfNetworkBridge",
                            "description":  "ProhibitInstallationAndConfigurationOfNetworkBridge",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Connectivity/ProhibitInstallationAndConfigurationOfNetworkBridge",
                            "isEncrypted":  false,
                            "value":  "\u003cEnabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "RemoteAssistance/UnsolicitedRemoteAssistance",
                            "description":  "UnsolicitedRemoteAssistance",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/RemoteAssistance/UnsolicitedRemoteAssistance",
                            "isEncrypted":  false,
                            "value":  "\u003cDisabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "ApplicationManagement/MSIAlwaysInstallWithElevatedPrivileges",
                            "description":  "MSIAlwaysInstallWithElevatedPrivileges",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/ApplicationManagement/MSIAlwaysInstallWithElevatedPrivileges",
                            "isEncrypted":  false,
                            "value":  0,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "RemoteManagement/AllowBasicAuthentication_Client",
                            "description":  "AllowBasicAuthentication_Client",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/RemoteManagement/AllowBasicAuthentication_Client",
                            "isEncrypted":  false,
                            "value":  "\u003cDisabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "RemoteManagement/AllowBasicAuthentication_Service",
                            "description":  "AllowBasicAuthentication_Service",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/RemoteManagement/AllowBasicAuthentication_Service",
                            "isEncrypted":  false,
                            "value":  "\u003cDisabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "MSSLegacy/IPv6SourceRoutingProtectionLevel",
                            "description":  "IPv6SourceRoutingProtectionLevel",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPv6SourceRoutingProtectionLevel",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e\u003cdata id=\"DisableIPSourceRoutingIPv6\" value=\"2\"/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "CredentialsUI/EnumerateAdministrators",
                            "description":  "EnumerateAdministrators",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/CredentialsUI/EnumerateAdministrators",
                            "isEncrypted":  false,
                            "value":  "\u003cdisabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Autoplay/TurnOffAutoPlay",
                            "description":  "TurnOffAutoPlay",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Autoplay/TurnOffAutoPlay",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e\u003cdata id=\"Autorun_Box\" value=\"255\"/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Autoplay/SetDefaultAutoRunBehavior",
                            "description":  "SetDefaultAutoRunBehavior",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Autoplay/SetDefaultAutoRunBehavior",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e\u003cdata id=\"NoAutorun_Dropdown\" value=\"1\"/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "MSSecurityGuide/ConfigureSMBV1ClientDriver",
                            "description":  "ConfigureSMBV1ClientDriver",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/MSSecurityGuide/ConfigureSMBV1ClientDriver",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e \n\u003cdata id=\"Pol_SecGuide_SMB1ClientDriver\" value=\"4\"/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "MSSLegacy/IPSourceRoutingProtectionLevel",
                            "description":  "IPSourceRoutingProtectionLevel",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/MSSLegacy/IPSourceRoutingProtectionLevel",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e\u003cdata id=\"DisableIPSourceRouting\" value=\"2\"/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "Start/HideSleep",
                            "description":  "HideSleep",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Start/HideSleep",
                            "isEncrypted":  false,
                            "value":  1,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "Start/HideHibernate",
                            "description":  "HideHibernate",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Start/HideHibernate",
                            "isEncrypted":  false,
                            "value":  0,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Power/StandbyTimeoutPluggedIn",
                            "description":  "StandbyTimeoutPluggedIn",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Power/StandbyTimeoutPluggedIn",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e\u003cdata id=\"EnterACStandbyTimeOut\" value=\"1800\"/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Power/HibernateTimeoutPluggedIn",
                            "description":  "HibernateTimeoutPluggedIn",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Power/HibernateTimeoutPluggedIn",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e\u003cdata id=\"EnterACHibernateTimeOut\" value=\"3600\"/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "Power/HibernateTimeoutOnBattery",
                            "description":  "HibernateTimeoutOnBattery",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/Power/HibernateTimeoutOnBattery",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e\u003cdata id=\"EnterDCHibernateTimeOut\" value=\"3600\"/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "RemovableStroageDevices/CDDenyWrite",
                            "description":  "CDDenyWrite",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/RemovableStorageDevices\\{53f56308-b6bf-11d0-94f2-00a0c91efb8b}/CDandDVD_DenyWrite_Access_2",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "CredentialsUI/DisablePasswordReveal",
                            "description":  "DisablePasswordReveal",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/CredentialsUI/DisablePasswordReveal",
                            "isEncrypted":  false,
                            "value":  "\u003cenabled/\u003e"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingString",
                            "displayName":  "MS DM Server/CommercialID",
                            "description":  "CommercialID",
                            "omaUri":  "./Vendor/MSFT/DMClient/Provider/MS DM Server/CommercialID",
                            "isEncrypted":  false,
                            "value":  "11111111-1111-1111-1111-111111111111"
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "System/AllowDeviceNameInDiagnosticData",
                            "description":  "AllowDeviceNameInDiagnosticData",
                            "omaUri":  "./Vendor/MSFT/Policy/Config/System/AllowDeviceNameInDiagnosticData",
                            "isEncrypted":  false,
                            "value":  1,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "System/ConfigureTelemetryOptInSettingsUx",
                            "description":  "ConfigureTelemetryOptInSettingsUx",
                            "omaUri":  "./Vendor/MSFT/Policy/Config/System/ConfigureTelemetryOptInSettingsUx",
                            "isEncrypted":  false,
                            "value":  1,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "System/LimitEnhancedDiagnosticDataWindowsAnalytics",
                            "description":  "LimitEnhancedDiagnosticDataWindowsAnalytics",
                            "omaUri":  "./Vendor/MSFT/Policy/Config/System/LimitEnhancedDiagnosticDataWindowsAnalytics",
                            "isEncrypted":  false,
                            "value":  1,
                            "isReadOnly":  false
                        },
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "System/ConfigureTelemetryOptInChangeNotification",
                            "description":  "ConfigureTelemetryOptInChangeNotification",
                            "omaUri":  "./Vendor/MSFT/Policy/Config/System/ConfigureTelemetryOptInChangeNotification",
                            "isEncrypted":  false,
                            "value":  1,
                            "isReadOnly":  false
                        }
                    ]
}
"@

$smbWindowsHello = @"
{
    "@odata.type":  "#microsoft.graph.windowsIdentityProtectionConfiguration",
    "description":  "",
    "displayName":  "[SMB] Windows - Enable Hello",
    "useSecurityKeyForSignin":  true,
    "enhancedAntiSpoofingForFacialFeaturesEnabled":  true,
    "pinMinimumLength":  8,
    "pinMaximumLength":  100,
    "pinUppercaseCharactersUsage":  "blocked",
    "pinLowercaseCharactersUsage":  "blocked",
    "pinSpecialCharactersUsage":  "blocked",
    "pinExpirationInDays":  null,
    "pinPreviousBlockCount":  null,
    "pinRecoveryEnabled":  true,
    "securityDeviceRequired":  true,
    "unlockWithBiometricsEnabled":  true,
    "useCertificatesForOnPremisesAuthEnabled":  false,
    "windowsHelloForBusinessBlocked":  false
}
"@

$smbHealthMonitoring = @"
{
    "@odata.type": "#microsoft.graph.windowsHealthMonitoringConfiguration",
    "description":  "",
    "displayName": "[SMB] Windows - Health monitoring",
    "deviceManagementApplicabilityRuleOsEdition": null,
    "deviceManagementApplicabilityRuleOsVersion": null,
    "deviceManagementApplicabilityRuleDeviceMode": null,
    "allowDeviceHealthMonitoring": "enabled",
    "configDeviceHealthMonitoringScope": "bootPerformance,windowsUpdates",
    "configDeviceHealthMonitoringCustomScope": null
}
"@

$smbUpdateDefault = @"
{
    "@odata.type":  "#microsoft.graph.windowsUpdateForBusinessConfiguration",
    "deviceManagementApplicabilityRuleOsEdition":  null,
    "deviceManagementApplicabilityRuleOsVersion":  null,
    "deviceManagementApplicabilityRuleDeviceMode":  null,
    "description":  "Applies General availability channel updates without delay.",
    "displayName":  "[SMB] Windows - Default Update Ring",
    "deliveryOptimizationMode":  "userDefined",
    "prereleaseFeatures":  "userDefined",
    "automaticUpdateMode":  "autoInstallAtMaintenanceTime",
    "microsoftUpdateServiceAllowed":  true,
    "driversExcluded":  false,
    "qualityUpdatesDeferralPeriodInDays":  0,
    "featureUpdatesDeferralPeriodInDays":  0,
    "qualityUpdatesPaused":  false,
    "featureUpdatesPaused":  false,
    "qualityUpdatesPauseExpiryDateTime":  "0001-01-01T00:00:00Z",
    "featureUpdatesPauseExpiryDateTime":  "0001-01-01T00:00:00Z",
    "businessReadyUpdatesOnly":  "businessReadyOnly",
    "skipChecksBeforeRestart":  false,
    "updateWeeks":  null,
    "qualityUpdatesPauseStartDate":  null,
    "featureUpdatesPauseStartDate":  null,
    "featureUpdatesRollbackWindowInDays":  21,
    "qualityUpdatesWillBeRolledBack":  false,
    "featureUpdatesWillBeRolledBack":  false,
    "qualityUpdatesRollbackStartDateTime":  "0001-01-01T00:00:00Z",
    "featureUpdatesRollbackStartDateTime":  "0001-01-01T00:00:00Z",
    "engagedRestartDeadlineInDays":  null,
    "engagedRestartSnoozeScheduleInDays":  null,
    "engagedRestartTransitionScheduleInDays":  null,
    "deadlineForFeatureUpdatesInDays":  null,
    "deadlineForQualityUpdatesInDays":  null,
    "deadlineGracePeriodInDays":  null,
    "postponeRebootUntilAfterDeadline":  null,
    "autoRestartNotificationDismissal":  "notConfigured",
    "scheduleRestartWarningInHours":  4,
    "scheduleImminentRestartWarningInMinutes":  15,
    "userPauseAccess":  "enabled",
    "userWindowsUpdateScanAccess":  "enabled",
    "updateNotificationLevel":  "restartWarningsOnly",
    "installationSchedule":  {
                                 "@odata.type":  "#microsoft.graph.windowsUpdateActiveHoursInstall",
                                 "activeHoursStart":  "08:00:00.0000000",
                                 "activeHoursEnd":  "18:00:00.0000000"
                             }
}


"@

$smbUpdateDelayed = @"

{
    "@odata.type":  "#microsoft.graph.windowsUpdateForBusinessConfiguration",
    "deviceManagementApplicabilityRuleOsEdition":  null,
    "deviceManagementApplicabilityRuleOsVersion":  null,
    "deviceManagementApplicabilityRuleDeviceMode":  null,
    "description":  "This update ring delays quality updates by one week and feature updates by two weeks.",
    "displayName":  "[SMB] Windows - Delayed Update Ring",
    "deliveryOptimizationMode":  "userDefined",
    "prereleaseFeatures":  "userDefined",
    "automaticUpdateMode":  "autoInstallAtMaintenanceTime",
    "microsoftUpdateServiceAllowed":  true,
    "driversExcluded":  false,
    "qualityUpdatesDeferralPeriodInDays":  7,
    "featureUpdatesDeferralPeriodInDays":  14,
    "qualityUpdatesPaused":  false,
    "featureUpdatesPaused":  false,
    "qualityUpdatesPauseExpiryDateTime":  "0001-01-01T00:00:00Z",
    "featureUpdatesPauseExpiryDateTime":  "0001-01-01T00:00:00Z",
    "businessReadyUpdatesOnly":  "businessReadyOnly",
    "skipChecksBeforeRestart":  false,
    "updateWeeks":  null,
    "qualityUpdatesPauseStartDate":  null,
    "featureUpdatesPauseStartDate":  null,
    "featureUpdatesRollbackWindowInDays":  21,
    "qualityUpdatesWillBeRolledBack":  false,
    "featureUpdatesWillBeRolledBack":  false,
    "qualityUpdatesRollbackStartDateTime":  "0001-01-01T00:00:00Z",
    "featureUpdatesRollbackStartDateTime":  "0001-01-01T00:00:00Z",
    "engagedRestartDeadlineInDays":  null,
    "engagedRestartSnoozeScheduleInDays":  null,
    "engagedRestartTransitionScheduleInDays":  null,
    "deadlineForFeatureUpdatesInDays":  null,
    "deadlineForQualityUpdatesInDays":  null,
    "deadlineGracePeriodInDays":  null,
    "postponeRebootUntilAfterDeadline":  null,
    "autoRestartNotificationDismissal":  "notConfigured",
    "scheduleRestartWarningInHours":  4,
    "scheduleImminentRestartWarningInMinutes":  15,
    "userPauseAccess":  "enabled",
    "userWindowsUpdateScanAccess":  "enabled",
    "updateNotificationLevel":  "restartWarningsOnly",
    "installationSchedule":  {
                                 "@odata.type":  "#microsoft.graph.windowsUpdateActiveHoursInstall",
                                 "activeHoursStart":  "08:00:00.0000000",
                                 "activeHoursEnd":  "18:00:00.0000000"
                             }
}


"@


#Device config profiles (ADMX)
$smbEdgeBrowser = @"
[
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('06b9c400-f1ed-4046-b8cb-02af3ae8e38d')",
        "enabled":  "true"
    },
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('59922037-5107-4eaf-a72f-249a73c08d16')",
        "enabled":  "true"
    },
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('6189eace-13bd-435e-b438-2f38495bf9cc')",
        "enabled":  "false"
    },
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('270e643f-a1dd-49eb-8365-8292e9d6c7f7')",
        "enabled":  "true"
    },
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('fdfedea9-c9d1-4109-9b59-883cfe2d861a')",
        "enabled":  "true",
        "presentationValues":  [
                                   {
                                       "@odata.type":  "#microsoft.graph.groupPolicyPresentationValueText",
                                       "value":  "ntlm,negotiate",
                                       "presentation@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('fdfedea9-c9d1-4109-9b59-883cfe2d861a')/presentations('e6b8ffac-8e06-4a30-95c6-cec2dfc1a08f')"
                                   }
                               ]
    },
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('bc6a79f3-77d4-462c-9924-8ea74dc34386')",
        "enabled":  "false"
    },
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('ccfd2123-ff05-4680-a4eb-ab2790b6d6ed')",
        "enabled":  "false"
    },
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('6f317cd9-3683-476b-adea-b93eb74e07c1')",
        "enabled":  "true"
    },
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('f9de5937-2ff5-4c34-a5ec-d0d997787b68')",
        "enabled":  "true"
    }
]
"@

$smbOdfbClient = @"
[
{
    "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('81c07ba0-7512-402d-b1f6-00856975cfab')",
    "enabled":  "true"
},
{
    "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('61b07a01-7e60-4127-b086-f6b32458a5c5')",
    "enabled":  "true"
},
{
    "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('2ce2f507-aae8-49a1-98ce-dc3faafcd331')",
    "enabled":  "true"
},
{
    "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('24bec81e-a596-4fc1-867b-0256114a19a4')",
    "enabled":  "true",
    "presentationValues":  [
                               {
                                   "@odata.type":  "#microsoft.graph.groupPolicyPresentationValueText",
                                   "value":  "$myTenantID",
                                   "presentation@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('24bec81e-a596-4fc1-867b-0256114a19a4')/presentations('4640c3f7-b89a-41be-948b-e86a2a97cae4')"
                               }
                           ]
},
{
    "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('39147fa2-6c5e-437b-8264-19b50b891709')",
    "enabled":  "true",
    "presentationValues":  [
                               {
                                   "@odata.type":  "#microsoft.graph.groupPolicyPresentationValueText",
                                   "value":  "$myTenantID",
                                   "presentation@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('39147fa2-6c5e-437b-8264-19b50b891709')/presentations('fbefbbdf-5382-477c-8b6c-71f4a06e2805')"
                               }
                           ]
}
]
"@


#Conditional Access policies
$smbCa001 = @"
{
    "displayName": "[SMB] 0.01 - Block legacy authentication",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": [
            "exchangeActiveSync",
			"other"
        ],
        "platforms": null,
        "locations": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [
                "All"
            ],
            "excludeApplications": [],
            "includeUserActions": []
        },
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": []
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa002 = @" 
{
    "displayName": "[SMB] 0.02 - Require MFA for management",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": null,
        "platforms": null,
        "locations": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [
                "797f4846-ba00-4fd7-ba43-dac1f8f63013",
                "MicrosoftAdminPortals"
            ],
            "excludeApplications": [],
            "includeUserActions": []
        },
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": []
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "mfa"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa003 = @" 
{
    "displayName": "[SMB] 0.03 - Require MFA to register or join devices",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": null,
        "platforms": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [],
            "excludeApplications": [],
            "includeUserActions": [
                "urn:user:registerdevice"
            ]
        },
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [
                "GuestsOrExternalUsers"
            ],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": []
        },
        "locations": {
            "includeLocations": [
                "All"
            ],
            "excludeLocations": [
                "AllTrusted"
            ]
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "mfa"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa004 = @" 
{
    "displayName": "[SMB] 0.04 - Block unknown or unsupported device platforms",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": [
            "All"
        ],
        "platforms": {
			"includePlatforms":[
				"all"
			],
			"excludePlatforms":[
				"android",
				"iOS",
				"windows",
				"macOS"
			]
		},
        "locations": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [
                "All"
            ],
            "excludeApplications": [],
            "includeUserActions": []
        },
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [
				"GuestsOrExternalUsers"
			],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": []
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa005 = @" 
{"grantControls":null,"conditions":{"userRiskLevels":[],"signInRiskLevels":[],"clientAppTypes":["all"],"servicePrincipalRiskLevels":[],"insiderRiskLevels":null,"clients":null,"platforms":null,"locations":null,"times":null,"deviceStates":null,"clientApplications":null,"authenticationFlows":null,"applications":{"includeApplications":["All"],"excludeApplications":[],"includeUserActions":[],"includeAuthenticationContextClassReferences":[],"applicationFilter":null,"networkAccess":null,"globalSecureAccess":null},"users":{"includeUsers":["All"],"excludeUsers":[],"includeGroups":[],"excludeGroups":[],"includeRoles":[],"excludeRoles":[],"includeGuestsOrExternalUsers":null,"excludeGuestsOrExternalUsers":null},"devices":{"includeDeviceStates":[],"excludeDeviceStates":[],"includeDevices":[],"excludeDevices":[],"deviceFilter":{"mode":"include","rule":"device.trustType -ne \"ServerAD\" -or device.isCompliant -ne True"}}},"sessionControls":{"disableResilienceDefaults":null,"applicationEnforcedRestrictions":null,"cloudAppSecurity":null,"continuousAccessEvaluation":null,"secureSignInSession":null,"networkAccessSecurity":null,"globalSecureAccessFilteringProfile":null,"signInFrequency":{"value":1,"type":"hours","authenticationType":"primaryAndSecondaryAuthentication","frequencyInterval":"timeBased","isEnabled":true},"persistentBrowser":{"mode":"never","isEnabled":true}},"displayName":"[SMB] 0.05 - No persistent browser on unmanaged devices"}
"@

$smbCa101 = @" 
{
    "displayName": "[SMB] 1.01 - Require MFA for admins",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": null,
        "platforms": null,
        "locations": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [
                "All"
            ],
            "excludeApplications": [],
            "includeUserActions": []
        },
        "users": {
            "includeUsers": [],
            "excludeUsers": [],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [ 
                "62e90394-69f5-4237-9190-012177145e10",
                "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
                "29232cdf-9323-42fd-ade2-1d097af3e4de",
                "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
                "194ae4cb-b126-40b2-bd5b-6091b380977d",
                "729827e3-9c14-49f7-bb1b-9608f156bbb8",
                "966707d0-3269-4727-9be2-8c3a10f19b9d",
                "b0f54661-2d74-4c50-afa3-1ec803f12efe",
                "fe930be7-5e62-47db-91af-98c3a49a38b1",
				"c4e39bd9-1100-46d3-8c65-fb160da0071f",
				"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
				"158c047a-c907-4556-b7ef-446551a6b5f7",
				"7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
				"e8611ab8-c189-46e8-94e1-60213ab1f814"
            ],
            "excludeRoles": []
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "mfa"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa201 = @" 
{
    "displayName": "[SMB] 2.01 - Require MFA for internals",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": null,
        "platforms": null,
        "locations": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [
                "All"
            ],
            "excludeApplications": [],
            "includeUserActions": []
        },
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeUsers": ["GuestsOrExternalUsers"],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": []
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "mfa"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa202 = @" 
{
    "displayName": "[SMB] 2.02 - Securing MFA registration for internals",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": null,
        "platforms": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [],
            "excludeApplications": [],
            "includeUserActions": [
                "urn:user:registersecurityinfo"
            ]
        },
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [
                "GuestsOrExternalUsers"
            ],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": [
				"62e90394-69f5-4237-9190-012177145e10"
			]
        },
        "locations": {
            "includeLocations": [
                "All"
            ],
            "excludeLocations": [
                "AllTrusted"
            ]
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "mfa"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa203 = @" 
{
    "displayName": "[SMB] 2.03 - Require app protection for Office 365 mobile access",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": null,
        "platforms": {
			"includePlatforms": [
				"android",
				"iOS"
			],
			"excludePlatforms": []
		},		
        "locations": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [
                "Office365"
            ],
            "excludeApplications": [],
            "includeUserActions": []
        },
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeUsers": ["GuestsOrExternalUsers"],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": []
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
			"compliantApplication"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa204 = @" 
{
    "displayName": "[SMB] 2.04 - Require compliant device for Office 365 desktop access",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": null,
        "platforms": {
			"includePlatforms": [
				"windows",
				"macOS"
			],
			"excludePlatforms": []
		},		
        "locations": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [
                "Office365"
            ],
            "excludeApplications": [],
            "includeUserActions": []
        },
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [
				"GuestsOrExternalUsers"
			],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": []
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "compliantDevice"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa301 = @" 

{
    "displayName": "[SMB] 3.01 - Require MFA for externals",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": null,
        "platforms": null,
        "locations": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [
                "All"
            ],
            "excludeApplications": [],
            "includeUserActions": []
        },
        "users": {
            "includeUsers": [
                "GuestsOrExternalUsers"
            ],
            "excludeUsers": [],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": []
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "mfa"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}

"@

#endregion

#region create policies

#Create app protection policies
New-AppProtectionPolicy -RawJsonData $json_Android -Platform "Android"
New-AppProtectionPolicy -RawJsonData $json_iOS -Platform "iOS"


#Create compliance policies
New-CompliancePolicy -JsonData $smbImmediate
New-CompliancePolicy -JsonData $smbDelayed
New-CompliancePolicy -JsonData $smbDefender


#Create Device config profiles
New-DeviceConfigurationProfile -jsonData $smbEndpointProtection
New-DeviceConfigurationProfile -jsonData $smbDeviceRestrictions
New-DeviceConfigurationProfile -jsonData $smbCustomCSP
New-DeviceConfigurationProfile -jsonData $smbWindowsHello
New-DeviceConfigurationProfile -jsonData $smbHealthMonitoring
New-DeviceConfigurationProfile -jsonData $smbUpdateDefault
New-DeviceConfigurationProfile -jsonData $smbUpdateDelayed


#Create Device config profiles (ADMX templates)
#Create the OneDrive profile
$profileId = New-GroupPolicyConfiguration -DisplayName "[SMB] Windows - OneDrive client" -Description "Settings for the OneDrive client."
#Populate the definition values
Set-GroupPolicyDefinitionValues -ProfileId $profileId -JsonData $smbOdfbClient
# Create the Edge profile
$profileId = New-GroupPolicyConfiguration -DisplayName "[SMB] Windows - Edge browser" -Description "Security baseline for the Microsoft Edge browser."
# Populate the definition values
Set-GroupPolicyDefinitionValues -ProfileId $profileId -JsonData $smbEdgeBrowser


#Create Conditional Access policies
New-ConditionalAccessPolicy -JsonData $smbCa001
New-ConditionalAccessPolicy -JsonData $smbCa002
New-ConditionalAccessPolicy -JsonData $smbCa003
New-ConditionalAccessPolicy -JsonData $smbCa004
New-ConditionalAccessPolicy -JsonData $smbCa005
New-ConditionalAccessPolicy -JsonData $smbCa101
New-ConditionalAccessPolicy -JsonData $smbCa201
New-ConditionalAccessPolicy -JsonData $smbCa202
New-ConditionalAccessPolicy -JsonData $smbCa203
New-ConditionalAccessPolicy -JsonData $smbCa204
New-ConditionalAccessPolicy -JsonData $smbCa301


#endregion

#Disconnect from Microsoft Graph
Disconnect-MgGraph
