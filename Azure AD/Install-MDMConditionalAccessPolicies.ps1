<##################################################################################################
#
.SYNOPSIS
    This script can create the following Device-based Conditional Access policies in your tenant:
    1. [ITPM Mobile] Require managed apps for Office 365 access (MAM)
    2. [ITPM Mobile] Require compliant device for Office 365 client app access (MDM)
    3. [ITPM MacOS] Require compliant device for Office 365 client app access
    4. [ITPM Windows] Require compliant device or hybrid join for Office 365 client app access
    5. [ITPM Browsers] Prevent web downloads from Office 365 on unmanaged devices
    6. [ITPM Strict] Block all access on unmanaged devices for supported platforms

.NOTES
    1. You may need to disable the 'Security defaults' first. See https://aka.ms/securitydefaults
    2. None of the policies created by this script will be enabled by default.
    3. Before enabling policies, you should notify end users about the expected impacts
    4. Be sure to populate the 'Exclude from CA' security group with at least one admin account for emergency access

.HOW-TO
    1. To install the Azure AD PowerShell module use: Install-Module AzureAD
    2. Connect to Azure AD via PowerShell to run this script: Connect-AzureAD 
    3. Run .\Baseline-ConditionalAccessPolicies.ps1
    4. Reference: https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0#installing-the-azure-ad-module

.DETAILS
    FileName:    Install-MDMConditionalAccessPolicies.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     September 2020
	Updated:     February 2021

#>
###################################################################################################

Connect-AzureAD

########################################################

## This policy enforces MAM for browser and client app access on iOS and Android devices
## MAM NOTES: 
##     1. End-users will not be able to access company data from built-in browser or mail apps for iOS or Android; they must use approved apps (e.g. Outlook, Edge)
##     2. Android and iOS users must have the Authenticator app configured, and Android users must also download the Company Portal app
##     3. You must also deploy App protection policies for iOS and Android

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "Office365"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.Platforms = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessPlatformCondition
$conditions.Platforms.IncludePlatforms = @('Android', 'IOS')
$conditions.ClientAppTypes = @('Browser', 'MobileAppsAndDesktopClients')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = @('ApprovedApplication', 'CompliantApplication')

New-AzureADMSConditionalAccessPolicy -DisplayName "[ITPM Baseline] Office 365 Mobile access: Require managed apps (MAM)" -State "Disabled" -Conditions $conditions -GrantControls $controls 


########################################################

## This policy requires MDM for client app access on iOS and Android devices (i.e. Company-owned devices)
## MDM NOTES:
##     1. For iOS: Configure Apple enrollment certificate, and optionally connect Apple Business Manager (Company-owned)
##     2. For Android: Link your Managed Google Play account, and optionally configure corporate-owned dedicated or fully managed devices
##     3. Personal devices: Both iOS and Android users should download the Authenticator app, and the Company Portal app to sign-in

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "Office365"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.Platforms = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessPlatformCondition
$conditions.Platforms.IncludePlatforms = @('Android', 'IOS')
$conditions.ClientAppTypes = @('MobileAppsAndDesktopClients')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = @('CompliantDevice')

New-AzureADMSConditionalAccessPolicy -DisplayName "[ITPM Mobile] Require compliant device for Office 365 client app access (MDM)" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

## This policy requires MDM for client app access on macOS devices 
## MDM NOTES:
##     1. For macOS: Configure Apple enrollment certificate, and optionally connect Apple Business Manager (Company-owned)
##     2. Personal devices: Users need the Company Portal app to enroll

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "Office365"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.Platforms = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessPlatformCondition
$conditions.Platforms.IncludePlatforms = @('macOS')
$conditions.ClientAppTypes = @('Browser', 'MobileAppsAndDesktopClients')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = @('CompliantDevice')

New-AzureADMSConditionalAccessPolicy -DisplayName "[ITPM MacOS] Require compliant device for Office 365 client app access" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

## This policy requires compliant device or Hybrid Azure AD join for client app access on Windows devices 
## MDM NOTES:
##     1. For Windows: Configure Microsoft Store (Intune) or Hybrid Azure AD Join (On-premises/Azure AD Connect)
##     2. Personal devices: Users need the Company Portal app to enroll

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "Office365"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.Platforms = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessPlatformCondition
$conditions.Platforms.IncludePlatforms = @('Windows')
$conditions.ClientAppTypes = @('MobileAppsAndDesktopClients')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = @('DomainJoinedDevice', 'CompliantDevice')

New-AzureADMSConditionalAccessPolicy -DisplayName "[ITPM Windows] Require compliant device for Office 365 client app access" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

## This policy prevents web downloads from unmanaged devices and unmanaged web browsers 
## Policy NOTES:
##     1. You must take additional action in Exchange Online and SharePoint Online to complete the set up for this policy to take effect
##     2. See my Conditional Access Best Practices guide for more details on those additional steps 
##     3. Unmanaged browsers (e.g. Firefox) will also be impacted by this policy, even on managed devices
##     4. End users should be advised to use Edge (Chromium version) with Office 365

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "Office365"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.ClientAppTypes = @('Browser')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessSessionControls
$controls.ApplicationEnforcedRestrictions = $true

New-AzureADMSConditionalAccessPolicy -DisplayName "[ITPM Browsers] Prevent web downloads from Office 365 on unmanaged devices" -State "Disabled" -Conditions $conditions -SessionControls $controls 

########################################################

## This policy enforces device compliance (or Hybrid Azure AD join) for all supported platforms: Windows, macOS, Android, and iOS
## NOTES: 
##    1. End-users must enroll their devices with Intune before enabling this policy
##    2. Azure AD joined or Hybrid Joined devices will be managed without taking additional action
##    3. Users with personal devices should use the Company Portal app to enroll
##    4. This policy blocks unmanaged device access from browsers (Edge, Firefox, etc.) and client apps (Outlook, OneDrive, etc.)

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "Office365"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.Platforms = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessPlatformCondition
$conditions.Platforms.IncludePlatforms = @('Android', 'IOS', 'Windows', 'macOS')
$conditions.ClientAppTypes = @('Browser', 'MobileAppsAndDesktopClients')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = @('DomainJoinedDevice', 'CompliantDevice')

New-AzureADMSConditionalAccessPolicy -DisplayName "[ITPM Strict] Block all access on unmanaged devices for supported platforms" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################
