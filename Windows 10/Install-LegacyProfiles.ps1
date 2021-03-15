<##################################################################################################
#
.SYNOPSIS
This script imports my legacy Device configuration profiles for Windows 10.

In newer scripts these functions have moved over to Endpoint security profiles.

Please read about and test the impacts of each policy before assigning to users/devices: 

https://gum.co/FvuOd

All scripts offered without warranty of any kind.

The functions contained in this script are from the Graph samples published by Microsoft on GitHub:
https://github.com/microsoftgraph/powershell-intune-samples

.NOTES
    FileName:    Install-LegacyProfiles.ps1
    Author:      Alex Fields (ITProMentor.com)
    Created:     March 2021
	Revised:     March 2021
    
#>
###################################################################################################

###################################################################################################
## Functions used in the script
###################################################################################################

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

Function Add-DeviceConfigurationPolicy(){

<#
.SYNOPSIS
This function is used to add an device configuration policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device configuration policy
.EXAMPLE
Add-DeviceConfigurationPolicy -JSON $JSON
Adds a device configuration policy in Intune
.NOTES
NAME: Add-DeviceConfigurationPolicy
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/deviceConfigurations"
Write-Verbose "Resource: $DCP_resource"

    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for the Android Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
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


###################################################################################################
## JSON describing the policies to be imported
###################################################################################################

$Config_Win10LegacyDR = @"

{
    "@odata.type":  "#microsoft.graph.windows10GeneralConfiguration",
    "deviceManagementApplicabilityRuleOsEdition":  null,
    "deviceManagementApplicabilityRuleOsVersion":  null,
    "deviceManagementApplicabilityRuleDeviceMode":  null,
    "description":  "Basic security profile for Windows 10 that is also BYOD friendly.",
    "displayName":  "[ITPM Legacy] Windows 10: Baseline Device Restrictions",
    "taskManagerBlockEndTask":  false,
    "energySaverOnBatteryThresholdPercentage":  0,
    "energySaverPluggedInThresholdPercentage":  0,
    "powerLidCloseActionOnBattery":  "notConfigured",
    "powerLidCloseActionPluggedIn":  "notConfigured",
    "powerButtonActionOnBattery":  "notConfigured",
    "powerButtonActionPluggedIn":  "notConfigured",
    "powerSleepButtonActionOnBattery":  "notConfigured",
    "powerSleepButtonActionPluggedIn":  "notConfigured",
    "powerHybridSleepOnBattery":  "enabled",
    "powerHybridSleepPluggedIn":  "enabled",
    "windows10AppsForceUpdateSchedule":  null,
    "enableAutomaticRedeployment":  false,
    "microsoftAccountSignInAssistantSettings":  "notConfigured",
    "authenticationAllowSecondaryDevice":  true,
    "authenticationWebSignIn":  "notConfigured",
    "authenticationPreferredAzureADTenantDomainName":  null,
    "cryptographyAllowFipsAlgorithmPolicy":  false,
    "displayAppListWithGdiDPIScalingTurnedOn":  [

                                                ],
    "displayAppListWithGdiDPIScalingTurnedOff":  [

                                                 ],
    "enterpriseCloudPrintDiscoveryEndPoint":  null,
    "enterpriseCloudPrintOAuthAuthority":  null,
    "enterpriseCloudPrintOAuthClientIdentifier":  null,
    "enterpriseCloudPrintResourceIdentifier":  null,
    "enterpriseCloudPrintDiscoveryMaxLimit":  null,
    "enterpriseCloudPrintMopriaDiscoveryResourceIdentifier":  null,
    "experienceDoNotSyncBrowserSettings":  "notConfigured",
    "messagingBlockSync":  false,
    "messagingBlockMMS":  false,
    "messagingBlockRichCommunicationServices":  false,
    "printerNames":  [

                     ],
    "printerDefaultName":  null,
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
    "findMyFiles":  "notConfigured",
    "securityBlockAzureADJoinedDevicesAutoEncryption":  false,
    "diagnosticsDataSubmissionMode":  "none",
    "oneDriveDisableFileSync":  false,
    "systemTelemetryProxyServer":  null,
    "edgeTelemetryForMicrosoft365Analytics":  "notConfigured",
    "inkWorkspaceAccess":  "notConfigured",
    "inkWorkspaceAccessState":  "notConfigured",
    "inkWorkspaceBlockSuggestedApps":  false,
    "smartScreenEnableAppInstallControl":  false,
    "smartScreenAppInstallControl":  "notConfigured",
    "personalizationDesktopImageUrl":  null,
    "personalizationLockScreenImageUrl":  null,
    "bluetoothAllowedServices":  [

                                 ],
    "bluetoothBlockAdvertising":  false,
    "bluetoothBlockPromptedProximalConnections":  false,
    "bluetoothBlockDiscoverableMode":  false,
    "bluetoothBlockPrePairing":  false,
    "edgeBlockAutofill":  false,
    "edgeBlocked":  false,
    "edgeCookiePolicy":  "userDefined",
    "edgeBlockDeveloperTools":  false,
    "edgeBlockSendingDoNotTrackHeader":  false,
    "edgeBlockExtensions":  false,
    "edgeBlockInPrivateBrowsing":  false,
    "edgeBlockJavaScript":  false,
    "edgeBlockPasswordManager":  false,
    "edgeBlockAddressBarDropdown":  false,
    "edgeBlockCompatibilityList":  false,
    "edgeClearBrowsingDataOnExit":  false,
    "edgeAllowStartPagesModification":  false,
    "edgeDisableFirstRunPage":  false,
    "edgeBlockLiveTileDataCollection":  false,
    "edgeSyncFavoritesWithInternetExplorer":  false,
    "edgeFavoritesListLocation":  null,
    "edgeBlockEditFavorites":  false,
    "edgeNewTabPageURL":  null,
    "edgeHomeButtonConfiguration":  null,
    "edgeHomeButtonConfigurationEnabled":  false,
    "edgeOpensWith":  "notConfigured",
    "edgeBlockSideloadingExtensions":  false,
    "edgeRequiredExtensionPackageFamilyNames":  [

                                                ],
    "edgeBlockPrinting":  false,
    "edgeFavoritesBarVisibility":  "notConfigured",
    "edgeBlockSavingHistory":  false,
    "edgeBlockFullScreenMode":  false,
    "edgeBlockWebContentOnNewTabPage":  false,
    "edgeBlockTabPreloading":  false,
    "edgeBlockPrelaunch":  false,
    "edgeShowMessageWhenOpeningInternetExplorerSites":  "notConfigured",
    "edgePreventCertificateErrorOverride":  false,
    "edgeKioskModeRestriction":  "notConfigured",
    "edgeKioskResetAfterIdleTimeInMinutes":  null,
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
    "defenderMonitorFileActivity":  "monitorAllFiles",
    "defenderDaysBeforeDeletingQuarantinedMalware":  10,
    "defenderScanMaxCpu":  50,
    "defenderScanArchiveFiles":  true,
    "defenderScanIncomingMail":  true,
    "defenderScanRemovableDrivesDuringFullScan":  true,
    "defenderScanMappedNetworkDrivesDuringFullScan":  false,
    "defenderScanNetworkFiles":  true,
    "defenderRequireCloudProtection":  true,
    "defenderCloudBlockLevel":  "high",
    "defenderCloudExtendedTimeout":  null,
    "defenderCloudExtendedTimeoutInSeconds":  null,
    "defenderPromptForSampleSubmission":  "promptBeforeSendingPersonalData",
    "defenderScheduledQuickScanTime":  null,
    "defenderScanType":  "userDefined",
    "defenderSystemScanSchedule":  "userDefined",
    "defenderScheduledScanTime":  null,
    "defenderPotentiallyUnwantedAppAction":  "block",
    "defenderPotentiallyUnwantedAppActionSetting":  "userDefined",
    "defenderSubmitSamplesConsentType":  "sendSafeSamplesAutomatically",
    "defenderBlockOnAccessProtection":  false,
    "defenderFileExtensionsToExclude":  [

                                        ],
    "defenderFilesAndFoldersToExclude":  [

                                         ],
    "defenderProcessesToExclude":  [

                                   ],
    "lockScreenAllowTimeoutConfiguration":  false,
    "lockScreenBlockActionCenterNotifications":  false,
    "lockScreenBlockCortana":  false,
    "lockScreenBlockToastNotifications":  false,
    "lockScreenTimeoutInSeconds":  null,
    "lockScreenActivateAppsWithVoice":  "notConfigured",
    "passwordBlockSimple":  true,
    "passwordExpirationDays":  null,
    "passwordMinimumLength":  9,
    "passwordMinutesOfInactivityBeforeScreenTimeout":  5,
    "passwordMinimumCharacterSetCount":  3,
    "passwordPreviousPasswordBlockCount":  null,
    "passwordRequired":  true,
    "passwordRequireWhenResumeFromIdleState":  false,
    "passwordRequiredType":  "alphanumeric",
    "passwordSignInFailureCountBeforeFactoryReset":  10,
    "passwordMinimumAgeInDays":  null,
    "privacyAdvertisingId":  "notConfigured",
    "privacyAutoAcceptPairingAndConsentPrompts":  false,
    "privacyDisableLaunchExperience":  false,
    "privacyBlockInputPersonalization":  false,
    "privacyBlockPublishUserActivities":  false,
    "privacyBlockActivityFeed":  false,
    "activateAppsWithVoice":  "notConfigured",
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
    "startMenuHideSleep":  false,
    "startMenuHideSwitchAccount":  false,
    "startMenuHideUserTile":  false,
    "startMenuLayoutEdgeAssetsXml":  null,
    "startMenuLayoutXml":  null,
    "startMenuMode":  "userDefined",
    "startMenuPinnedFolderDocuments":  "notConfigured",
    "startMenuPinnedFolderDownloads":  "notConfigured",
    "startMenuPinnedFolderFileExplorer":  "notConfigured",
    "startMenuPinnedFolderHomeGroup":  "notConfigured",
    "startMenuPinnedFolderMusic":  "notConfigured",
    "startMenuPinnedFolderNetwork":  "notConfigured",
    "startMenuPinnedFolderPersonalFolder":  "notConfigured",
    "startMenuPinnedFolderPictures":  "notConfigured",
    "startMenuPinnedFolderSettings":  "notConfigured",
    "startMenuPinnedFolderVideos":  "notConfigured",
    "settingsBlockSettingsApp":  false,
    "settingsBlockSystemPage":  false,
    "settingsBlockDevicesPage":  false,
    "settingsBlockNetworkInternetPage":  false,
    "settingsBlockPersonalizationPage":  false,
    "settingsBlockAccountsPage":  false,
    "settingsBlockTimeLanguagePage":  false,
    "settingsBlockEaseOfAccessPage":  false,
    "settingsBlockPrivacyPage":  false,
    "settingsBlockUpdateSecurityPage":  false,
    "settingsBlockAppsPage":  false,
    "settingsBlockGamingPage":  false,
    "windowsSpotlightBlockConsumerSpecificFeatures":  false,
    "windowsSpotlightBlocked":  false,
    "windowsSpotlightBlockOnActionCenter":  false,
    "windowsSpotlightBlockTailoredExperiences":  false,
    "windowsSpotlightBlockThirdPartyNotifications":  false,
    "windowsSpotlightBlockWelcomeExperience":  false,
    "windowsSpotlightBlockWindowsTips":  false,
    "windowsSpotlightConfigureOnLockScreen":  "notConfigured",
    "networkProxyApplySettingsDeviceWide":  false,
    "networkProxyDisableAutoDetect":  false,
    "networkProxyAutomaticConfigurationUrl":  null,
    "networkProxyServer":  null,
    "accountsBlockAddingNonMicrosoftAccountEmail":  false,
    "antiTheftModeBlocked":  false,
    "bluetoothBlocked":  false,
    "cameraBlocked":  false,
    "connectedDevicesServiceBlocked":  false,
    "certificatesBlockManualRootCertificateInstallation":  false,
    "copyPasteBlocked":  false,
    "cortanaBlocked":  false,
    "deviceManagementBlockFactoryResetOnMobile":  false,
    "deviceManagementBlockManualUnenroll":  false,
    "safeSearchFilter":  "userDefined",
    "edgeBlockPopups":  false,
    "edgeBlockSearchSuggestions":  false,
    "edgeBlockSearchEngineCustomization":  false,
    "edgeBlockSendingIntranetTrafficToInternetExplorer":  false,
    "edgeSendIntranetTrafficToInternetExplorer":  false,
    "edgeRequireSmartScreen":  true,
    "edgeEnterpriseModeSiteListLocation":  null,
    "edgeFirstRunUrl":  null,
    "edgeSearchEngine":  null,
    "edgeHomepageUrls":  [

                         ],
    "edgeBlockAccessToAboutFlags":  false,
    "smartScreenBlockPromptOverride":  false,
    "smartScreenBlockPromptOverrideForFiles":  false,
    "webRtcBlockLocalhostIpAddress":  false,
    "internetSharingBlocked":  false,
    "settingsBlockAddProvisioningPackage":  false,
    "settingsBlockRemoveProvisioningPackage":  false,
    "settingsBlockChangeSystemTime":  false,
    "settingsBlockEditDeviceName":  false,
    "settingsBlockChangeRegion":  false,
    "settingsBlockChangeLanguage":  false,
    "settingsBlockChangePowerSleep":  false,
    "locationServicesBlocked":  false,
    "microsoftAccountBlocked":  false,
    "microsoftAccountBlockSettingsSync":  false,
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
    "wirelessDisplayRequirePinForPairing":  false,
    "windowsStoreBlocked":  false,
    "appsAllowTrustedAppsSideloading":  "notConfigured",
    "windowsStoreBlockAutoUpdate":  false,
    "developerUnlockSetting":  "blocked",
    "sharedUserAppDataAllowed":  false,
    "appsBlockWindowsStoreOriginatedApps":  false,
    "windowsStoreEnablePrivateStoreOnly":  false,
    "storageRestrictAppDataToSystemVolume":  false,
    "storageRestrictAppInstallToSystemVolume":  false,
    "gameDvrBlocked":  false,
    "experienceBlockDeviceDiscovery":  false,
    "experienceBlockErrorDialogWhenNoSIM":  false,
    "experienceBlockTaskSwitcher":  false,
    "logonBlockFastUserSwitching":  false,
    "tenantLockdownRequireNetworkDuringOutOfBoxExperience":  false,
    "appManagementMSIAllowUserControlOverInstall":  false,
    "appManagementMSIAlwaysInstallWithElevatedPrivileges":  false,
    "dataProtectionBlockDirectMemoryAccess":  true,
    "appManagementPackageFamilyNamesToLaunchAfterLogOn":  [

                                                          ],
    "uninstallBuiltInApps":  false,
    "configureTimeZone":  null,
    "defenderDetectedMalwareActions":  {
                                           "lowSeverity":  "quarantine",
                                           "moderateSeverity":  "quarantine",
                                           "highSeverity":  "quarantine",
                                           "severeSeverity":  "quarantine"
                                       }
}


"@

####################################################

$Config_Win10LegacyEP = @"

{
    "@odata.type":  "#microsoft.graph.windows10EndpointProtectionConfiguration",
    "deviceManagementApplicabilityRuleOsEdition":  null,
    "deviceManagementApplicabilityRuleOsVersion":  null,
    "deviceManagementApplicabilityRuleDeviceMode":  null,
    "description":  "Basic security profile for Windows 10 that is also BYOD friendly.",
    "displayName":  "[ITPM Legacy] Windows 10: Baseline Endpoint Protection",
    "dmaGuardDeviceEnumerationPolicy":  "deviceDefault",
    "xboxServicesEnableXboxGameSaveTask":  false,
    "xboxServicesAccessoryManagementServiceStartupMode":  "manual",
    "xboxServicesLiveAuthManagerServiceStartupMode":  "manual",
    "xboxServicesLiveGameSaveServiceStartupMode":  "manual",
    "xboxServicesLiveNetworkingServiceStartupMode":  "manual",
    "localSecurityOptionsBlockMicrosoftAccounts":  false,
    "localSecurityOptionsBlockRemoteLogonWithBlankPassword":  false,
    "localSecurityOptionsDisableAdministratorAccount":  false,
    "localSecurityOptionsAdministratorAccountName":  null,
    "localSecurityOptionsDisableGuestAccount":  true,
    "localSecurityOptionsGuestAccountName":  null,
    "localSecurityOptionsAllowUndockWithoutHavingToLogon":  true,
    "localSecurityOptionsBlockUsersInstallingPrinterDrivers":  false,
    "localSecurityOptionsBlockRemoteOpticalDriveAccess":  false,
    "localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUser":  "notConfigured",
    "localSecurityOptionsMachineInactivityLimit":  5,
    "localSecurityOptionsMachineInactivityLimitInMinutes":  5,
    "localSecurityOptionsDoNotRequireCtrlAltDel":  false,
    "localSecurityOptionsHideLastSignedInUser":  false,
    "localSecurityOptionsHideUsernameAtSignIn":  false,
    "localSecurityOptionsLogOnMessageTitle":  null,
    "localSecurityOptionsLogOnMessageText":  null,
    "localSecurityOptionsAllowPKU2UAuthenticationRequests":  false,
    "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManagerHelperBool":  false,
    "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManager":  null,
    "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedClients":  "ntlmV2And128BitEncryption",
    "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedServers":  "ntlmV2And128BitEncryption",
    "lanManagerAuthenticationLevel":  "lmNtlmV2AndNotLmOrNtm",
    "lanManagerWorkstationDisableInsecureGuestLogons":  true,
    "localSecurityOptionsClearVirtualMemoryPageFile":  false,
    "localSecurityOptionsAllowSystemToBeShutDownWithoutHavingToLogOn":  false,
    "localSecurityOptionsAllowUIAccessApplicationElevation":  false,
    "localSecurityOptionsVirtualizeFileAndRegistryWriteFailuresToPerUserLocations":  false,
    "localSecurityOptionsOnlyElevateSignedExecutables":  false,
    "localSecurityOptionsAdministratorElevationPromptBehavior":  "promptForCredentialsOnTheSecureDesktop",
    "localSecurityOptionsStandardUserElevationPromptBehavior":  "promptForCredentialsOnTheSecureDesktop",
    "localSecurityOptionsSwitchToSecureDesktopWhenPromptingForElevation":  false,
    "localSecurityOptionsDetectApplicationInstallationsAndPromptForElevation":  true,
    "localSecurityOptionsAllowUIAccessApplicationsForSecureLocations":  false,
    "localSecurityOptionsUseAdminApprovalMode":  true,
    "localSecurityOptionsUseAdminApprovalModeForAdministrators":  true,
    "localSecurityOptionsInformationShownOnLockScreen":  "notConfigured",
    "localSecurityOptionsInformationDisplayedOnLockScreen":  "notConfigured",
    "localSecurityOptionsDisableClientDigitallySignCommunicationsIfServerAgrees":  false,
    "localSecurityOptionsClientDigitallySignCommunicationsAlways":  false,
    "localSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers":  false,
    "localSecurityOptionsDisableServerDigitallySignCommunicationsAlways":  false,
    "localSecurityOptionsDisableServerDigitallySignCommunicationsIfClientAgrees":  false,
    "localSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares":  true,
    "localSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts":  true,
    "localSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares":  true,
    "localSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange":  true,
    "localSecurityOptionsSmartCardRemovalBehavior":  "lockWorkstation",
    "defenderSecurityCenterDisableAppBrowserUI":  null,
    "defenderSecurityCenterDisableFamilyUI":  null,
    "defenderSecurityCenterDisableHealthUI":  null,
    "defenderSecurityCenterDisableNetworkUI":  null,
    "defenderSecurityCenterDisableVirusUI":  null,
    "defenderSecurityCenterDisableAccountUI":  null,
    "defenderSecurityCenterDisableClearTpmUI":  null,
    "defenderSecurityCenterDisableHardwareUI":  null,
    "defenderSecurityCenterDisableNotificationAreaUI":  null,
    "defenderSecurityCenterDisableRansomwareUI":  null,
    "defenderSecurityCenterDisableSecureBootUI":  null,
    "defenderSecurityCenterDisableTroubleshootingUI":  null,
    "defenderSecurityCenterDisableVulnerableTpmFirmwareUpdateUI":  null,
    "defenderSecurityCenterOrganizationDisplayName":  null,
    "defenderSecurityCenterHelpEmail":  null,
    "defenderSecurityCenterHelpPhone":  null,
    "defenderSecurityCenterHelpURL":  null,
    "defenderSecurityCenterNotificationsFromApp":  "notConfigured",
    "defenderSecurityCenterITContactDisplay":  "notConfigured",
    "windowsDefenderTamperProtection":  "notConfigured",
    "firewallBlockStatefulFTP":  null,
    "firewallIdleTimeoutForSecurityAssociationInSeconds":  null,
    "firewallPreSharedKeyEncodingMethod":  "deviceDefault",
    "firewallIPSecExemptionsNone":  false,
    "firewallIPSecExemptionsAllowNeighborDiscovery":  false,
    "firewallIPSecExemptionsAllowICMP":  false,
    "firewallIPSecExemptionsAllowRouterDiscovery":  false,
    "firewallIPSecExemptionsAllowDHCP":  false,
    "firewallCertificateRevocationListCheckMethod":  "deviceDefault",
    "firewallMergeKeyingModuleSettings":  null,
    "firewallPacketQueueingMethod":  "deviceDefault",
    "defenderAdobeReaderLaunchChildProcess":  "enable",
    "defenderAttackSurfaceReductionExcludedPaths":  [

                                                    ],
    "defenderOfficeAppsOtherProcessInjectionType":  "block",
    "defenderOfficeAppsOtherProcessInjection":  "enable",
    "defenderOfficeCommunicationAppsLaunchChildProcess":  "enable",
    "defenderOfficeAppsExecutableContentCreationOrLaunchType":  "block",
    "defenderOfficeAppsExecutableContentCreationOrLaunch":  "enable",
    "defenderOfficeAppsLaunchChildProcessType":  "block",
    "defenderOfficeAppsLaunchChildProcess":  "enable",
    "defenderOfficeMacroCodeAllowWin32ImportsType":  "block",
    "defenderOfficeMacroCodeAllowWin32Imports":  "enable",
    "defenderScriptObfuscatedMacroCodeType":  "block",
    "defenderScriptObfuscatedMacroCode":  "enable",
    "defenderScriptDownloadedPayloadExecutionType":  "block",
    "defenderScriptDownloadedPayloadExecution":  "enable",
    "defenderPreventCredentialStealingType":  "enable",
    "defenderProcessCreationType":  "block",
    "defenderProcessCreation":  "enable",
    "defenderUntrustedUSBProcessType":  "block",
    "defenderUntrustedUSBProcess":  "enable",
    "defenderUntrustedExecutableType":  "auditMode",
    "defenderUntrustedExecutable":  "auditMode",
    "defenderEmailContentExecutionType":  "block",
    "defenderEmailContentExecution":  "enable",
    "defenderAdvancedRansomewareProtectionType":  "enable",
    "defenderGuardMyFoldersType":  "auditMode",
    "defenderGuardedFoldersAllowedAppPaths":  [

                                              ],
    "defenderAdditionalGuardedFolders":  [

                                         ],
    "defenderNetworkProtectionType":  "enable",
    "defenderExploitProtectionXml":  null,
    "defenderExploitProtectionXmlFileName":  null,
    "defenderSecurityCenterBlockExploitProtectionOverride":  false,
    "defenderBlockPersistenceThroughWmiType":  "userDefined",
    "appLockerApplicationControl":  "notConfigured",
    "deviceGuardLocalSystemAuthorityCredentialGuardSettings":  "notConfigured",
    "deviceGuardEnableVirtualizationBasedSecurity":  false,
    "deviceGuardEnableSecureBootWithDMA":  false,
    "deviceGuardSecureBootWithDMA":  "notConfigured",
    "deviceGuardLaunchSystemGuard":  "notConfigured",
    "smartScreenEnableInShell":  true,
    "smartScreenBlockOverrideForFiles":  true,
    "applicationGuardEnabled":  false,
    "applicationGuardEnabledOptions":  "notConfigured",
    "applicationGuardBlockFileTransfer":  "notConfigured",
    "applicationGuardBlockNonEnterpriseContent":  false,
    "applicationGuardAllowPersistence":  false,
    "applicationGuardForceAuditing":  false,
    "applicationGuardBlockClipboardSharing":  "notConfigured",
    "applicationGuardAllowPrintToPDF":  false,
    "applicationGuardAllowPrintToXPS":  false,
    "applicationGuardAllowPrintToLocalPrinters":  false,
    "applicationGuardAllowPrintToNetworkPrinters":  false,
    "applicationGuardAllowVirtualGPU":  false,
    "applicationGuardAllowFileSaveOnHost":  false,
    "applicationGuardAllowCameraMicrophoneRedirection":  null,
    "applicationGuardCertificateThumbprints":  [

                                               ],
    "bitLockerAllowStandardUserEncryption":  true,
    "bitLockerDisableWarningForOtherDiskEncryption":  true,
    "bitLockerEnableStorageCardEncryptionOnMobile":  false,
    "bitLockerEncryptDevice":  true,
    "bitLockerRecoveryPasswordRotation":  "enabledForAzureAd",
    "defenderDisableScanArchiveFiles":  null,
    "defenderAllowScanArchiveFiles":  null,
    "defenderDisableBehaviorMonitoring":  null,
    "defenderAllowBehaviorMonitoring":  null,
    "defenderDisableCloudProtection":  null,
    "defenderAllowCloudProtection":  null,
    "defenderEnableScanIncomingMail":  null,
    "defenderEnableScanMappedNetworkDrivesDuringFullScan":  null,
    "defenderDisableScanRemovableDrivesDuringFullScan":  null,
    "defenderAllowScanRemovableDrivesDuringFullScan":  null,
    "defenderDisableScanDownloads":  null,
    "defenderAllowScanDownloads":  null,
    "defenderDisableIntrusionPreventionSystem":  null,
    "defenderAllowIntrusionPreventionSystem":  null,
    "defenderDisableOnAccessProtection":  null,
    "defenderAllowOnAccessProtection":  null,
    "defenderDisableRealTimeMonitoring":  null,
    "defenderAllowRealTimeMonitoring":  null,
    "defenderDisableScanNetworkFiles":  null,
    "defenderAllowScanNetworkFiles":  null,
    "defenderDisableScanScriptsLoadedInInternetExplorer":  null,
    "defenderAllowScanScriptsLoadedInInternetExplorer":  null,
    "defenderBlockEndUserAccess":  null,
    "defenderAllowEndUserAccess":  null,
    "defenderScanMaxCpuPercentage":  null,
    "defenderCheckForSignaturesBeforeRunningScan":  null,
    "defenderCloudBlockLevel":  null,
    "defenderCloudExtendedTimeoutInSeconds":  null,
    "defenderDaysBeforeDeletingQuarantinedMalware":  null,
    "defenderDisableCatchupFullScan":  null,
    "defenderDisableCatchupQuickScan":  null,
    "defenderEnableLowCpuPriority":  null,
    "defenderFileExtensionsToExclude":  [

                                        ],
    "defenderFilesAndFoldersToExclude":  [

                                         ],
    "defenderProcessesToExclude":  [

                                   ],
    "defenderPotentiallyUnwantedAppAction":  null,
    "defenderScanDirection":  null,
    "defenderScanType":  null,
    "defenderScheduledQuickScanTime":  null,
    "defenderScheduledScanDay":  null,
    "defenderScheduledScanTime":  null,
    "defenderSignatureUpdateIntervalInHours":  null,
    "defenderSubmitSamplesConsentType":  null,
    "defenderDetectedMalwareActions":  null,
    "firewallRules":  [

                      ],
    "userRightsAccessCredentialManagerAsTrustedCaller":  {
                                                             "state":  "notConfigured",
                                                             "localUsersOrGroups":  [

                                                                                    ]
                                                         },
    "userRightsAllowAccessFromNetwork":  {
                                             "state":  "notConfigured",
                                             "localUsersOrGroups":  [

                                                                    ]
                                         },
    "userRightsBlockAccessFromNetwork":  {
                                             "state":  "notConfigured",
                                             "localUsersOrGroups":  [

                                                                    ]
                                         },
    "userRightsActAsPartOfTheOperatingSystem":  {
                                                    "state":  "notConfigured",
                                                    "localUsersOrGroups":  [

                                                                           ]
                                                },
    "userRightsLocalLogOn":  {
                                 "state":  "notConfigured",
                                 "localUsersOrGroups":  [

                                                        ]
                             },
    "userRightsDenyLocalLogOn":  {
                                     "state":  "notConfigured",
                                     "localUsersOrGroups":  [

                                                            ]
                                 },
    "userRightsBackupData":  {
                                 "state":  "notConfigured",
                                 "localUsersOrGroups":  [

                                                        ]
                             },
    "userRightsChangeSystemTime":  {
                                       "state":  "notConfigured",
                                       "localUsersOrGroups":  [

                                                              ]
                                   },
    "userRightsCreateGlobalObjects":  {
                                          "state":  "notConfigured",
                                          "localUsersOrGroups":  [

                                                                 ]
                                      },
    "userRightsCreatePageFile":  {
                                     "state":  "notConfigured",
                                     "localUsersOrGroups":  [

                                                            ]
                                 },
    "userRightsCreatePermanentSharedObjects":  {
                                                   "state":  "notConfigured",
                                                   "localUsersOrGroups":  [

                                                                          ]
                                               },
    "userRightsCreateSymbolicLinks":  {
                                          "state":  "notConfigured",
                                          "localUsersOrGroups":  [

                                                                 ]
                                      },
    "userRightsCreateToken":  {
                                  "state":  "notConfigured",
                                  "localUsersOrGroups":  [

                                                         ]
                              },
    "userRightsDebugPrograms":  {
                                    "state":  "notConfigured",
                                    "localUsersOrGroups":  [

                                                           ]
                                },
    "userRightsRemoteDesktopServicesLogOn":  {
                                                 "state":  "notConfigured",
                                                 "localUsersOrGroups":  [

                                                                        ]
                                             },
    "userRightsDelegation":  {
                                 "state":  "notConfigured",
                                 "localUsersOrGroups":  [

                                                        ]
                             },
    "userRightsGenerateSecurityAudits":  {
                                             "state":  "notConfigured",
                                             "localUsersOrGroups":  [

                                                                    ]
                                         },
    "userRightsImpersonateClient":  {
                                        "state":  "notConfigured",
                                        "localUsersOrGroups":  [

                                                               ]
                                    },
    "userRightsIncreaseSchedulingPriority":  {
                                                 "state":  "notConfigured",
                                                 "localUsersOrGroups":  [

                                                                        ]
                                             },
    "userRightsLoadUnloadDrivers":  {
                                        "state":  "notConfigured",
                                        "localUsersOrGroups":  [

                                                               ]
                                    },
    "userRightsLockMemory":  {
                                 "state":  "notConfigured",
                                 "localUsersOrGroups":  [

                                                        ]
                             },
    "userRightsManageAuditingAndSecurityLogs":  {
                                                    "state":  "notConfigured",
                                                    "localUsersOrGroups":  [

                                                                           ]
                                                },
    "userRightsManageVolumes":  {
                                    "state":  "notConfigured",
                                    "localUsersOrGroups":  [

                                                           ]
                                },
    "userRightsModifyFirmwareEnvironment":  {
                                                "state":  "notConfigured",
                                                "localUsersOrGroups":  [

                                                                       ]
                                            },
    "userRightsModifyObjectLabels":  {
                                         "state":  "notConfigured",
                                         "localUsersOrGroups":  [

                                                                ]
                                     },
    "userRightsProfileSingleProcess":  {
                                           "state":  "notConfigured",
                                           "localUsersOrGroups":  [

                                                                  ]
                                       },
    "userRightsRemoteShutdown":  {
                                     "state":  "notConfigured",
                                     "localUsersOrGroups":  [

                                                            ]
                                 },
    "userRightsRestoreData":  {
                                  "state":  "notConfigured",
                                  "localUsersOrGroups":  [

                                                         ]
                              },
    "userRightsTakeOwnership":  {
                                    "state":  "notConfigured",
                                    "localUsersOrGroups":  [

                                                           ]
                                },
    "firewallProfileDomain":  {
                                  "firewallEnabled":  "allowed",
                                  "stealthModeRequired":  false,
                                  "stealthModeBlocked":  false,
                                  "incomingTrafficRequired":  false,
                                  "incomingTrafficBlocked":  false,
                                  "unicastResponsesToMulticastBroadcastsRequired":  false,
                                  "unicastResponsesToMulticastBroadcastsBlocked":  false,
                                  "inboundNotificationsRequired":  false,
                                  "inboundNotificationsBlocked":  false,
                                  "authorizedApplicationRulesFromGroupPolicyMerged":  false,
                                  "authorizedApplicationRulesFromGroupPolicyNotMerged":  false,
                                  "globalPortRulesFromGroupPolicyMerged":  false,
                                  "globalPortRulesFromGroupPolicyNotMerged":  false,
                                  "connectionSecurityRulesFromGroupPolicyMerged":  false,
                                  "connectionSecurityRulesFromGroupPolicyNotMerged":  false,
                                  "outboundConnectionsRequired":  true,
                                  "outboundConnectionsBlocked":  false,
                                  "inboundConnectionsRequired":  false,
                                  "inboundConnectionsBlocked":  true,
                                  "securedPacketExemptionAllowed":  false,
                                  "securedPacketExemptionBlocked":  false,
                                  "policyRulesFromGroupPolicyMerged":  false,
                                  "policyRulesFromGroupPolicyNotMerged":  false
                              },
    "firewallProfilePublic":  {
                                  "firewallEnabled":  "allowed",
                                  "stealthModeRequired":  false,
                                  "stealthModeBlocked":  false,
                                  "incomingTrafficRequired":  false,
                                  "incomingTrafficBlocked":  false,
                                  "unicastResponsesToMulticastBroadcastsRequired":  false,
                                  "unicastResponsesToMulticastBroadcastsBlocked":  false,
                                  "inboundNotificationsRequired":  false,
                                  "inboundNotificationsBlocked":  false,
                                  "authorizedApplicationRulesFromGroupPolicyMerged":  false,
                                  "authorizedApplicationRulesFromGroupPolicyNotMerged":  false,
                                  "globalPortRulesFromGroupPolicyMerged":  false,
                                  "globalPortRulesFromGroupPolicyNotMerged":  false,
                                  "connectionSecurityRulesFromGroupPolicyMerged":  false,
                                  "connectionSecurityRulesFromGroupPolicyNotMerged":  false,
                                  "outboundConnectionsRequired":  true,
                                  "outboundConnectionsBlocked":  false,
                                  "inboundConnectionsRequired":  false,
                                  "inboundConnectionsBlocked":  true,
                                  "securedPacketExemptionAllowed":  false,
                                  "securedPacketExemptionBlocked":  false,
                                  "policyRulesFromGroupPolicyMerged":  false,
                                  "policyRulesFromGroupPolicyNotMerged":  false
                              },
    "firewallProfilePrivate":  {
                                   "firewallEnabled":  "allowed",
                                   "stealthModeRequired":  false,
                                   "stealthModeBlocked":  false,
                                   "incomingTrafficRequired":  false,
                                   "incomingTrafficBlocked":  false,
                                   "unicastResponsesToMulticastBroadcastsRequired":  false,
                                   "unicastResponsesToMulticastBroadcastsBlocked":  false,
                                   "inboundNotificationsRequired":  false,
                                   "inboundNotificationsBlocked":  false,
                                   "authorizedApplicationRulesFromGroupPolicyMerged":  false,
                                   "authorizedApplicationRulesFromGroupPolicyNotMerged":  false,
                                   "globalPortRulesFromGroupPolicyMerged":  false,
                                   "globalPortRulesFromGroupPolicyNotMerged":  false,
                                   "connectionSecurityRulesFromGroupPolicyMerged":  false,
                                   "connectionSecurityRulesFromGroupPolicyNotMerged":  false,
                                   "outboundConnectionsRequired":  true,
                                   "outboundConnectionsBlocked":  false,
                                   "inboundConnectionsRequired":  false,
                                   "inboundConnectionsBlocked":  true,
                                   "securedPacketExemptionAllowed":  false,
                                   "securedPacketExemptionBlocked":  false,
                                   "policyRulesFromGroupPolicyMerged":  false,
                                   "policyRulesFromGroupPolicyNotMerged":  false
                               },
    "bitLockerSystemDrivePolicy":  {
                                       "encryptionMethod":  null,
                                       "startupAuthenticationRequired":  true,
                                       "startupAuthenticationBlockWithoutTpmChip":  false,
                                       "startupAuthenticationTpmUsage":  "required",
                                       "startupAuthenticationTpmPinUsage":  "blocked",
                                       "startupAuthenticationTpmKeyUsage":  "blocked",
                                       "startupAuthenticationTpmPinAndKeyUsage":  "blocked",
                                       "minimumPinLength":  null,
                                       "prebootRecoveryEnableMessageAndUrl":  false,
                                       "prebootRecoveryMessage":  null,
                                       "prebootRecoveryUrl":  null,
                                       "recoveryOptions":  {
                                                               "blockDataRecoveryAgent":  false,
                                                               "recoveryPasswordUsage":  "allowed",
                                                               "recoveryKeyUsage":  "allowed",
                                                               "hideRecoveryOptions":  true,
                                                               "enableRecoveryInformationSaveToStore":  true,
                                                               "recoveryInformationToStore":  "passwordAndKey",
                                                               "enableBitLockerAfterRecoveryInformationToStore":  true
                                                           }
                                   },
    "bitLockerFixedDrivePolicy":  {
                                      "encryptionMethod":  null,
                                      "requireEncryptionForWriteAccess":  false,
                                      "recoveryOptions":  {
                                                              "blockDataRecoveryAgent":  false,
                                                              "recoveryPasswordUsage":  "allowed",
                                                              "recoveryKeyUsage":  "allowed",
                                                              "hideRecoveryOptions":  true,
                                                              "enableRecoveryInformationSaveToStore":  true,
                                                              "recoveryInformationToStore":  "passwordAndKey",
                                                              "enableBitLockerAfterRecoveryInformationToStore":  true
                                                          }
                                  },
    "bitLockerRemovableDrivePolicy":  {
                                          "encryptionMethod":  null,
                                          "requireEncryptionForWriteAccess":  false,
                                          "blockCrossOrganizationWriteAccess":  false
                                      }
}


"@

####################################################


###################################################################################################
## Import policies from JSON
###################################################################################################
Write-Host
Write-Host "My legacy configuration profiles offer a simple security baseline that is also BYOD friendly."
Write-Host
$Answer = Read-Host "Do you want to import legacy configuration profiles for Windows 10 (Optional)? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
Write-Host "Adding Legacy Baseline Device configuration profiles..." -ForegroundColor Cyan
Write-Host
Write-Host "Adding Legacy Device restrictions baseline..." -ForegroundColor Yellow
Add-DeviceConfigurationPolicy -JSON $Config_Win10LegacyDR
Write-Host
Write-Host "Adding Legacy Endpoint protection baseline..." -ForegroundColor Yellow
Add-DeviceConfigurationPolicy -JSON $Config_Win10LegacyEP
Write-Host
} else

{
Write-Host
Write-Host "Legacy baseline profiles will not be imported" -ForegroundColor Red
Write-Host 
}

Write-Host "Script completed" -ForegroundColor Cyan
