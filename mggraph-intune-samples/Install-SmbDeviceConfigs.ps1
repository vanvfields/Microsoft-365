<##################################################################################################
#
.SYNOPSIS
This script installs device configuration profiles from JSON:
1. [SMB] Windows - Endpoint protection
2. [SMB] Windows - Device restrictions
3. [SMB] Windows - Custom CSP
4. [SMB] Windows - Enable Hello

.NOTES
    FileName:    Install-SmbDeviceConfigs.ps1
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
$RequiredScopes = @("DeviceManagementConfiguration.ReadWrite.All")

#Define the required modules
$RequiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.DeviceManagement")

#Connect to the graph with required modules and scopes
Connect-ToGraph -RequiredScopes $RequiredScopes -RequiredModules $RequiredModules

#endregion

#region functions

#Function to create a new device configuration profile
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

#endregion

#region json

$smbEndpointProtection = @"
{
    "@odata.type": "#microsoft.graph.windows10EndpointProtectionConfiguration",
    "description": "This profile enables a number of critical security features such as the Windows Firewall, BitLocker, Attack Surface Reduction rules, User Account Control, automatic screen lock, and more. This policy is appropriate for Company-owned devices.",
    "displayName": "[SMB] Windows - Endpoint protection baseline",
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
    "displayName":  "[SMB] Windows - Device restrictions baseline",
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
    "displayName":  "[SMB] Default Update Ring",
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
    "displayName":  "[SMB] Delayed Update Ring",
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

#endregion

#region create policies

New-DeviceConfigurationProfile -jsonData $smbEndpointProtection
New-DeviceConfigurationProfile -jsonData $smbDeviceRestrictions
New-DeviceConfigurationProfile -jsonData $smbCustomCSP
New-DeviceConfigurationProfile -jsonData $smbWindowsHello
New-DeviceConfigurationProfile -jsonData $smbHealthMonitoring
New-DeviceConfigurationProfile -jsonData $smbUpdateDefault
New-DeviceConfigurationProfile -jsonData $smbUpdateDelayed

#endregion

# Disconnect from Microsoft Graph
Disconnect-MgGraph