<##################################################################################################
#
.SYNOPSIS
    This script will create the following optional Conditional Access policies in your tenant:

    1. Guests | AllCloudApps | IdentityProtection: Require MFA for guests
    2. Guests | AllCloudApps | AttackSurfaceReduction: Block guest access to non-Office 365 apps
    3. Guests | AllCloudApps | DataProtection: Prevent persistent browser sessions for guests
    4. Guests | Office365 | DataProtection: Prevent web downloads for guests
    5. Guests | AllCloudApps | DataProtection: Block guest access from mobile and desktop apps

.NOTES
    1. You may need to disable the 'Security defaults' first. See https://aka.ms/securitydefaults
    2. None of the policies created by this script will be enabled by default.
    3. Before enabling policies, you should notify end users about the expected impacts
    4. Be sure to populate the security group 'sg-Exclude from CA' with at least one admin account for emergency access

.HOW-TO
    1. To install the Azure AD Preview PowerShell module use: Install-Module AzureADPreview -AllowClobber
    2. Run .\Install-GuestCAPolicies.ps1

.DETAILS
    FileName:    Install-GuestCAPolicies.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     June 2021
	Updated:     June 2021

#>
###################################################################################################



########################################################
## 1.
## Guests | AllCloudApps | IdentityProtection: Require MFA for guests 
## This policy requires Multi-factor Authentication for guests 

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.ClientAppTypes = @('Browser', 'MobileAppsAndDesktopClients')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "MFA"

New-AzureADMSConditionalAccessPolicy -DisplayName "Guests | AllCloudApps | IdentityProtection: Require MFA for guests" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################
## 2.
## Guests | AllCloudApps | AttackSurfaceReduction: Block guest access to non-Office 365 apps
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

New-AzureADMSConditionalAccessPolicy -DisplayName "Guests | AllCloudApps | AttackSurfaceReduction: Block guest access to non-Office 365 apps" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################
## 3. 
## Guests | AllCloudApps | DataProtection: Prevent persistent browser sessions for guests

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.ClientAppTypes = @('Browser')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessSessionControls
$PersistentBrowser= @"
{
  "isEnabled": true,
  "mode": "never"
}
"@
$convertedString = ConvertFrom-Json $PersistentBrowser
$controls.PersistentBrowser = $convertedString

New-AzureADMSConditionalAccessPolicy -DisplayName "Guests | AllCloudApps | DataProtection: Prevent persistent browser sessions for guests" -State "Disabled" -Conditions $conditions -SessionControls $controls 

########################################################
## 4.
## Guests | Office365 | DataProtection: Prevent web downloads for guests
## Policy NOTES:
##     1. You must take additional action in Exchange Online and SharePoint Online to complete the set up for this policy to take effect
##     2. See my Conditional Access Best Practices guide for more details on those additional steps 

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "Office365"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.ClientAppTypes = @('Browser')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessSessionControls
$controls.ApplicationEnforcedRestrictions = $true

New-AzureADMSConditionalAccessPolicy -DisplayName "Guests | Office365 | DataProtection: Prevent web downloads for guests" -State "Disabled" -Conditions $conditions -SessionControls $controls 

########################################################
## 5.
## Guests | AllCloudApps | DataProtection: Block guest access from mobile and desktop apps
## This policy will block access to any guest attempting to open content shared with them in a desktop application such as Word, Excel, PowerPoint, etc.

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "All"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.ClientAppTypes = @('MobileAppsAndDesktopClients')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "Block"

New-AzureADMSConditionalAccessPolicy -DisplayName "Guests | AllCloudApps | DataProtection: Block guest access from mobile and desktop apps" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

Write-Host "Script completed" -ForegroundColor Cyan