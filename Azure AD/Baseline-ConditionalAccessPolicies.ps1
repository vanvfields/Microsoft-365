<##################################################################################################
#
.SYNOPSIS
    This script will create the recommended baseline Conditional Access policies in your tenant:
    1. BLOCK - Legacy authentication
    2. GRANT - Require MFA for admins
    3. GRANT - Require MFA for all users
    4. GRANT - Require MAM or MDM for mobile device access
    5. GRANT - Require compliant device for Windows and Mac access
    6. BLOCK - Unsupported device platforms

.NOTES
    1. You may need to disable the 'Security defaults' first. See https://aka.ms/securitydefaults
    2. None of the policies created by this script will be enabled by default.
    3. Before enabling policies, you should notify end users about the expected impacts
    4. Be sure to populate the 'Exclude from CA' security group with at least one admin account for emergency access

.HOW-TO
    1. Connect to Azure AD via PowerShell to run this script using Connect-AzureAD, and then run .\Baseline-ConditionalAccessPolicies.ps1
    2. To install the Azure AD PowerShell module use Install-Module AzureAD
    3. Reference: https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0#installing-the-azure-ad-module

.DETAILS
    FileName:    Baseline-ConditionalAccessPolicies.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     September 2020
	Updated:     September 2020
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

New-AzureADMSConditionalAccessPolicy -DisplayName "BLOCK - Legacy authentication" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

## This policy requires Multi-factor authentication for global admins (SMB's do not typically delegate other roles)

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeRoles = "62e90394-69f5-4237-9190-012177145e10"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.ClientAppTypes = @('Browser', 'MobileAppsAndDesktopClients')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "MFA"

New-AzureADMSConditionalAccessPolicy -DisplayName "GRANT - Require MFA for admins" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

## This policy requires Multi-factor authentication for all users

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

New-AzureADMSConditionalAccessPolicy -DisplayName "GRANT - Require MFA for all users" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

## This policy enables MAM or MDM enforcement for iOS and Android devices (end-user choice)
## MAM NOTES: 
##     1. End-users will not be able to access company data from built-in browser or mail apps for iOS or Android; they must use approved apps (e.g. Outlook, Edge)
##     2. Android and iOS users must have the Authenticator app configured, and Android users must also download the Company Portal app
## MDM NOTES:
##     1. With MDM, both iOS and Android users should download the Authenticator app, and the Company Portal app
##     2. It is possible to use built-in web and mail clients, unless you change the $controls._Operator to 'AND'

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
$controls.BuiltInControls = @('CompliantDevice', 'ApprovedApplication', 'CompliantApplication')

New-AzureADMSConditionalAccessPolicy -DisplayName "GRANT - Require MAM or MDM for mobile device access" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

## This policy enforces device compliance for Windows and MacOS
## NOTES: 
##    1. End-users must enroll their devices for full management with Intune before enabling this policy
##    2. Azure AD joined or Hybrid Joined devices will be managed without taking additional action
##    3. Personal devices (Windows or Mac) should use the Company Portal to enroll
##    4. This policy blocks access from both client apps (e.g. Outlook, OneDrive, etc.) as well as web browsers
##    5. To allow Browser access from unmanaged devices, remove the 'Browser' condition under $conditions.ClientAppTypes

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "Office365"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.Platforms = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessPlatformCondition
$conditions.Platforms.IncludePlatforms = @('Windows', 'macOS')
$conditions.ClientAppTypes = @('Browser', 'MobileAppsAndDesktopClients')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = @('DomainJoinedDevice', 'CompliantDevice')

New-AzureADMSConditionalAccessPolicy -DisplayName "GRANT - Require compliant device for Windows or Mac access" -State "Disabled" -Conditions $conditions -GrantControls $controls 

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

New-AzureADMSConditionalAccessPolicy -DisplayName "BLOCK - Unsupported device platforms" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################
