<##################################################################################################
#
.SYNOPSIS
    This script will create the following recommended Baseline Conditional Access policies in your tenant:
    1. [All cloud apps] BLOCK: Legacy authentication clients
    2. [All cloud apps] GRANT: Require MFA for Admin users
    3. [All cloud apps] GRANT: Require MFA for All users
    4. [All cloud apps] BLOCK: Unsupported device platforms
    5. [Office 365] GRANT: Require approved app for mobile access (MAM)
    6. [Office 365] GRANT: Require compliant device for supported platforms
    7. [Office 365] SESSION: Prevent downloads from unmanaged devices and browsers


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
    FileName:    Baseline-ConditionalAccessPolicies.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     September 2020
	Updated:     October 2020

#>
###################################################################################################


## Check for the existence of the "Exclude from CA" security group, and create the group if it does not exist

$ExcludeCAGroup = Get-AzureADGroup | Where-Object DisplayName -EQ "Exclude From CA"

if ($ExcludeCAGroup -eq $null -or $ExcludeCAGroup -eq "") {
New-AzureADGroup -DisplayName "Exclude From CA" -SecurityEnabled $true -MailEnabled $false -MailNickName ExludeFromCA
$ExcludeCAGroup = Get-AzureADGroup | Where-Object DisplayName -EQ "Exclude From CA"

}
else {write-host "Exclude from CA group already exists"}


########################################################

## This policy blocks legacy authentication for all users

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.ClientAppTypes = @('ExchangeActiveSync', 'Other')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "Block"

New-AzureADMSConditionalAccessPolicy -DisplayName "[All cloud apps] BLOCK: Legacy authentication clients" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

## This policy requires Multi-factor authentication for Admin users

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeRoles = @('62e90394-69f5-4237-9190-012177145e10', 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', '29232cdf-9323-42fd-ade2-1d097af3e4de', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', '194ae4cb-b126-40b2-bd5b-6091b380977d', '729827e3-9c14-49f7-bb1b-9608f156bbb8', '966707d0-3269-4727-9be2-8c3a10f19b9d', 'b0f54661-2d74-4c50-afa3-1ec803f12efe', 'fe930be7-5e62-47db-91af-98c3a49a38b1')
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.ClientAppTypes = @('Browser', 'MobileAppsAndDesktopClients')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "MFA"

New-AzureADMSConditionalAccessPolicy -DisplayName "[All cloud apps] GRANT: Require MFA for Admin users" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

## This policy requires Multi-factor authentication for All users

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.ClientAppTypes = @('Browser', 'MobileAppsAndDesktopClients')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "MFA"

New-AzureADMSConditionalAccessPolicy -DisplayName "[All cloud apps] GRANT: Require MFA for All users" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

## This policy blocks unsupported device platforms such as Linux and ChromeOS

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.Platforms = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessPlatformCondition
$conditions.Platforms.IncludePlatforms = "All"
$conditions.Platforms.ExcludePlatforms = @('Android', 'IOS', 'Windows', 'macOS')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "Block"

New-AzureADMSConditionalAccessPolicy -DisplayName "[All cloud apps] BLOCK: Unsupported device platforms" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

## This policy enables MAM enforcement for iOS and Android devices
## MAM NOTES: 
##     1. End-users will not be able to access company data from built-in browser or mail apps for iOS or Android; they must use approved apps (e.g. Outlook, Edge)
##     2. Android and iOS users must have the Authenticator app configured, and Android users must also download the Company Portal app

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

New-AzureADMSConditionalAccessPolicy -DisplayName "[Office 365] GRANT: Require approved app for mobile access (MAM)" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################
<#
## This policy is optional, and enables MDM enforcement for iOS and Android devices (i.e. company-owned devices)
## MDM NOTES:
##     1. For iOS: Configure Apple enrollment certificate, and optionally connect Apple Business Manager (company-owned)
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
$conditions.ClientAppTypes = @('Browser', 'MobileAppsAndDesktopClients')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = @('CompliantDevice')

New-AzureADMSConditionalAccessPolicy -DisplayName "[Office 365] GRANT: Require compliant device for mobile access (MDM)" -State "Disabled" -Conditions $conditions -GrantControls $controls 
#>
########################################################

## This policy enforces device compliance (or Hybrid Azure AD join) for supported platforms: Windows, macOS, Android, and iOS
## NOTES: 
##    1. End-users must enroll their devices with Intune before enabling this policy
##    2. Azure AD joined or Hybrid Joined devices will be managed without taking additional action
##    3. Users with personal devices should use the Company Portal app to enroll
##    4. This policy blocks access from Mobile and desktop client apps (e.g. Outlook, OneDrive, etc.)
##    5. Optionally, you may remove Android and IOS from the IncludePlatforms condition (some choose to enforce MAM only)
##    6. Optionally, you may add 'Browser' to the ClientAppTypes condition in lieu of the next policy (SESSION policy)

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "Office365"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.Platforms = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessPlatformCondition
$conditions.Platforms.IncludePlatforms = @('Android', 'IOS', 'Windows', 'macOS')
$conditions.ClientAppTypes = @('MobileAppsAndDesktopClients')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = @('DomainJoinedDevice', 'CompliantDevice')

New-AzureADMSConditionalAccessPolicy -DisplayName "[Office 365] GRANT: Require compliant device for supported platforms" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

## This policy prevents web downloads from unmanaged devices and unmanaged web browsers 
## Policy NOTES:
##     1. You must take additional action in Exchange Online and SharePoint Online to complete the set up for this policy to take effect
##     2. See my Conditional Access Best Practices guide for more details 
##     3. Unmanaged browsers (e.g. Firefox) will also be impacted by this policy, even on managed devices
##     4. End users should be advised to Edge (Chromium version) with Office 365

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

New-AzureADMSConditionalAccessPolicy -DisplayName "[Office 365] SESSION: Prevent web downloads from unmanaged devices" -State "Disabled" -Conditions $conditions -SessionControls $controls 

########################################################
