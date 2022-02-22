<##################################################################################################
#
.SYNOPSIS
    This script contains a baseline for SMB orgs to create the following recommended Conditional Access policies:
    
    01. CA001: Block legacy authentication
    02. CA002: Block access from unsupported device platforms
    03. CA003: Require MFA for Azure management 
    04. CA004: Require MFA to register or join devices 
    05. CA101: Require MFA for admin users
    06. CA201: Require MFA for internal users
    07. CA202: Securing security info registration
    08. CA203: Require MAM or MDM for mobile device access (Office 365)
    09. CA204: Require managed devices for desktop client access (Office 365)
    10. CA301: Block guest access to unsupported apps
    11: CA302: Require MFA for guests & external users
  
    
.NOTES
    1. You may need to disable the 'Security defaults' first. See https://aka.ms/securitydefaults
    2. None of the policies created by this script will be enabled by default.
    3. Before enabling policies, you should notify end users about the expected impacts
    4. Be sure to populate the security group 'sgu-Exclude from CA' with at least one admin account for emergency access

.HOW-TO
    1. To install the Azure AD Preview PowerShell module use: Install-Module AzureADPreview -AllowClobber
    2. Run .\Install-ITPMBaselineCAPolicies.ps1

.DETAILS
    FileName:    Install-ITPMBaselineCAPolicies.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     February 2022
    Updated:     February 2022
    VERSION:     1.0

#>
###################################################################################################


Import-Module AzureADPreview
Connect-AzureAD

## Check for the existence of the "Exclude from CA" security group, and create the group if it does not exist

$ExcludeCAGroupName = "sgu-Exclude From CA"
$ExcludeCAGroup = Get-AzureADGroup -All $true | Where-Object DisplayName -eq $ExcludeCAGroupName

if ($ExcludeCAGroup -eq $null -or $ExcludeCAGroup -eq "") {
    New-AzureADGroup -DisplayName $ExcludeCAGroupName -SecurityEnabled $true -MailEnabled $false -MailNickName sgu-ExcludeFromCA
    $ExcludeCAGroup = Get-AzureADGroup -All $true | Where-Object DisplayName -eq $ExcludeCAGroupName
}
else {
    Write-Host "Exclude from CA group already exists"
}


# GLOBAL POLICIES:

########################################################
## CA001: Block legacy authentication
## This policy blocks legacy authentication for all users; check sign-in logs for legacy auth before enabling this policy.

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

New-AzureADMSConditionalAccessPolicy -DisplayName "CA001: Block legacy authentication" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################
## CA002: Block access from unsupported device platforms
## This policy prevents access from unsupported devices platforms such as Linux and ChromeOS

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.Platforms = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessPlatformCondition
$conditions.Platforms.IncludePlatforms = "All"
$conditions.Platforms.ExcludePlatforms = @('Android', 'IOS', 'Windows', 'macOS')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "Block"

New-AzureADMSConditionalAccessPolicy -DisplayName "CA002: Block access from unsupported device platforms" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################
## CA003: Require MFA for Azure management
## This policy requires Multi-factor Authentication for Azure Management for all users

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "MFA"

New-AzureADMSConditionalAccessPolicy -DisplayName "CA003: Require MFA for Azure management" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################
## CA004: Require MFA to register or join devices
## This policy requires Multi-factor Authentication when registering or joining a new device

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeUserActions = "urn:user:registerdevice"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "MFA"

New-AzureADMSConditionalAccessPolicy -DisplayName "CA004: Require MFA to register or join devices" -State "Disabled" -Conditions $conditions -GrantControls $controls 



########################################################
# ADMIN PERSONA POLICIES:
# These policies target admin roles specifically

########################################################
## CA101: Require MFA for admins
## This policy requires Multi-factor Authentication for Admin users

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeRoles = @('62e90394-69f5-4237-9190-012177145e10', 'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', '29232cdf-9323-42fd-ade2-1d097af3e4de', 'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', '194ae4cb-b126-40b2-bd5b-6091b380977d', '729827e3-9c14-49f7-bb1b-9608f156bbb8', '966707d0-3269-4727-9be2-8c3a10f19b9d', 'b0f54661-2d74-4c50-afa3-1ec803f12efe', 'fe930be7-5e62-47db-91af-98c3a49a38b1')
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "MFA"

New-AzureADMSConditionalAccessPolicy -DisplayName "CA101: Require MFA for admin users" -State "Disabled" -Conditions $conditions -GrantControls $controls 


########################################################
# INTERNAL PERSONA POLICIES:
# These policies target internal users, and always exclude guests and external users

########################################################
## CA201: Require MFA or compliant device for internal users 
## This policy requires Multi-factor Authentication for all users 

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
$controls.BuiltInControls = @('MFA', 'CompliantDevice')

New-AzureADMSConditionalAccessPolicy -DisplayName "CA201: Require MFA or compliant device for internal users" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################
## CA202: Securing security info registration
## This policy requires Multi-factor Authentication (e.g. TAP) when registering security information @ https://aka.ms/mysecurityinfo

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeUserActions = "urn:user:registersecurityinfo"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.Users.ExcludeRoles = "62e90394-69f5-4237-9190-012177145e10"
$conditions.Locations = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessLocationCondition
$conditions.Locations.IncludeLocations = "All"
$conditions.Locations.ExcludeLocations = "AllTrusted"
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "MFA"

New-AzureADMSConditionalAccessPolicy -DisplayName "CA202: Securing security info registration" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################
## CA203: Require MAM or MDM for mobile device access (Office 365)
## This policy enforces either MAM or MDM for iOS and Android devices
## NOTES: 
##     1. End-user must either use approved Microsoft apps (e.g. Outlook, Edge) OR enroll their device using Company Portal (in order to use other apps)
##     2. You must also deploy App protection policies and Compliance policies in Microsoft Endpoint Manager to complete this setup
##     2. Android and iOS users must have the Authenticator app as well as the Company Portal app

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "Office365"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.Platforms = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessPlatformCondition
$conditions.Platforms.IncludePlatforms = @('Android', 'IOS')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = @('CompliantDevice', 'ApprovedApplication', 'CompliantApplication')

New-AzureADMSConditionalAccessPolicy -DisplayName "CA203: Require MAM or MDM for mobile device access (Office 365)" -State "Disabled" -Conditions $conditions -GrantControls $controls 


########################################################
## CA204: Require managed devices for desktop client access (Office 365)
## This policy enforces device compliance (or Hybrid Azure AD join) for these platforms: Windows, macOS
## NOTES: 
##    1. Azure AD joined or Hybrid Joined devices will be auto-enrolled if configured properly
##    2. Users with personal devices should use the Company Portal app to enroll
##    3. This policy blocks unmanaged device access from desktop client apps (e.g. Outlook, OneDrive, etc.)
##    4. Optionally, you may add 'Browser' to the ClientAppTypes condition if you also want to block web access on unmanaged devices

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

New-AzureADMSConditionalAccessPolicy -DisplayName "CA204: Require managed devices for desktop client access (Office 365)" -State "Disabled" -Conditions $conditions -GrantControls $controls 


########################################################
# EXTERNAL/GUEST PERSONA POLICIES:
# Note: Some orgs prefer to separate personas for External (longer-term) and Guest (shorter-term) access

########################################################
## CA301: Block guest access to unsupported apps
## This policy blocks guest access to all cloud apps except Office 365 

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Applications.ExcludeApplications = "Office365"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "Block"

New-AzureADMSConditionalAccessPolicy -DisplayName "CA301: Block guest access to unsupported apps" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################
## CA302: Require MFA for guests and external users
## This policy requires Multi-factor Authentication for guests 
## Note: You should also plan to enable trust for MFA claims coming from outside Azure AD tenants
## Find trust settings under External identities > Cross-tenant access settings > Default settings > Edit inbound defaults > Trust settings

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "MFA"

New-AzureADMSConditionalAccessPolicy -DisplayName "CA302: Require MFA for guests and external users" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

Write-Host "Script completed" -ForegroundColor Cyan
