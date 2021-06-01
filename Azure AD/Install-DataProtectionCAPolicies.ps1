<##################################################################################################
#
.SYNOPSIS
    This script will create the following recommended Data Protection Conditional Access policies in your tenant:

    1. AllUsers | Office365 | DataProtection: Require approved apps and browsers on iOS & Android (MAM)
    2. AllUsers | Office365 | DataProtection: Require compliant device for mobile apps on iOS & Android (MDM)
    3. AllUsers | Office365 | DataProtection: Require managed devices for desktop apps on Windows & macOS
    4. AllUsers | Office365 | DataProtection: Prevent web downloads on unmanaged browsers & devices 
    5. Admins | AllCloudApps | DataProtection: Always require managed devices for access to cloud apps

.NOTES
    1. You may need to disable the 'Security defaults' first. See https://aka.ms/securitydefaults
    2. None of the policies created by this script will be enabled by default.
    3. Before enabling policies, you should notify end users about the expected impacts
    4. Be sure to populate the security group 'sg-Exclude from CA' with at least one admin account for emergency access
    5. To install the Azure AD Preview PowerShell module use: Install-Module AzureADPreview -AllowClobber

.DETAILS
    FileName:    Install-DataProtectionCAPolicies.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     June 2021
	Updated:     June 2021

#>
###################################################################################################

Import-Module AzureADPreview
Connect-AzureAD

## Check for the existence of the "Exclude from CA" security group, and create the group if it does not exist

$ExcludeCAGroupName = "sg-Exclude From CA"
$ExcludeCAGroup = Get-AzureADGroup -All $true | Where-Object DisplayName -eq $ExcludeCAGroupName

if ($ExcludeCAGroup -eq $null -or $ExcludeCAGroup -eq "") {
    New-AzureADGroup -DisplayName $ExcludeCAGroupName -SecurityEnabled $true -MailEnabled $false -MailNickName sg-ExcludeFromCA
    $ExcludeCAGroup = Get-AzureADGroup -All $true | Where-Object DisplayName -eq $ExcludeCAGroupName
}
else {
    Write-Host "Exclude from CA group already exists"
}


########################################################
## 1.
## AllUsers | Office365 | DataProtection: Require approved browsers and mobile apps on iOS & Android (MAM)

## This policy enables MAM enforcement for iOS and Android devices
## MAM NOTES: 
##     1. End-users will not be able to access company data from built-in browser or mail apps for iOS or Android; they must use approved apps (e.g. Outlook, Edge)
##     2. You must also deploy App protection policies in Microsoft Endpoint Manager for this policy to be most effective
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

New-AzureADMSConditionalAccessPolicy -DisplayName "AllUsers | Office365 | DataProtection: Require approved browsers and mobile apps on iOS & Android (MAM)" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################
## 2. 
## AllUsers | Office365 | DataProtection: Require compliant device for mobile apps on iOS & Android (MDM)


## [OPTIONAL POLICY] Enforces MDM compliance for client app access on iOS and Android devices (i.e. Company-owned devices)
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
$conditions.ClientAppTypes = @('MobileAppsAndDesktopClients')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = @('CompliantDevice')

New-AzureADMSConditionalAccessPolicy -DisplayName "AllUsers | Office365 | DataProtection: Require compliant device for mobile apps on iOS & Android (MDM)" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################
## 3.
## AllUsers | Office365 | DataProtection: Require managed devices for desktop apps on Windows & macOS
 
## This policy enforces device compliance (or Hybrid Azure AD join) for these platforms: Windows, macOS
## NOTES: 
##    1. End-users must enroll their devices with Intune before enabling this policy
##    2. Azure AD joined or Hybrid Joined devices will be managed without taking additional action
##    3. Users with personal devices should use the Company Portal app to enroll
##    4. This policy blocks unmanaged device access from desktop client apps (e.g. Outlook, OneDrive, etc.)
##    5. Optionally, you may add 'Browser' to the ClientAppTypes condition in lieu of the block web downloads policy (SESSION policy)

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "Office365"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.Platforms = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessPlatformCondition
$conditions.Platforms.IncludePlatforms = @('Windows', 'macOS')
$conditions.ClientAppTypes = @('MobileAppsAndDesktopClients')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = @('DomainJoinedDevice', 'CompliantDevice')

New-AzureADMSConditionalAccessPolicy -DisplayName "AllUsers | Office365 | DataProtection: Require managed devices for desktop apps on Windows & macOS" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################
## 4.
## AllUsers | Office365 | DataProtection: Prevent web downloads on unmanaged browsers & devices

## [OPTIONAL POLICY] This policy prevents web downloads from unmanaged devices and unmanaged web browsers 
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

New-AzureADMSConditionalAccessPolicy -DisplayName "AllUsers | Office365 | DataProtection: Prevent web downloads on unmanaged browsers & devices" -State "Disabled" -Conditions $conditions -SessionControls $controls 

########################################################
## 5. 
## Admins | AllCloudApps | DataProtection: Always require managed devices for access to cloud apps

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Applications.ExcludeApplications = "d4ebce55-015a-49b5-a083-c84d1797ae8c"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeRoles = @('62e90394-69f5-4237-9190-012177145e10', 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', '29232cdf-9323-42fd-ade2-1d097af3e4de', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', '194ae4cb-b126-40b2-bd5b-6091b380977d', '729827e3-9c14-49f7-bb1b-9608f156bbb8', '966707d0-3269-4727-9be2-8c3a10f19b9d', 'b0f54661-2d74-4c50-afa3-1ec803f12efe', 'fe930be7-5e62-47db-91af-98c3a49a38b1')
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.ClientAppTypes = @('Browser', 'MobileAppsAndDesktopClients')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = @('DomainJoinedDevice', 'CompliantDevice')

New-AzureADMSConditionalAccessPolicy -DisplayName "Admins | AllCloudApps | DataProtection: Always require managed devices for access to cloud apps" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

Write-Host "Script completed" -ForegroundColor Cyan

