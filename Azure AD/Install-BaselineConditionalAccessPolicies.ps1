<##################################################################################################
#
.SYNOPSIS
    This script will create the following recommended Baseline Conditional Access policies in your tenant:
    1. [ITPM Baseline] Block legacy authentication clients
    2. [ITPM Baseline] Block unsupported device platforms
    3. [ITPM Baseline] Require MFA for Admin users
    4. [ITPM Baseline] Require MFA for Azure Management
    4. [ITPM Baseline] Require MFA for unmanaged devices 
    5. [ITPM Baseline] Require MFA to join or register a device


.NOTES
    1. You may need to disable the 'Security defaults' first. See https://aka.ms/securitydefaults
    2. None of the policies created by this script will be enabled by default.
    3. Before enabling policies, you should notify end users about the expected impacts
    4. Be sure to populate the security group 'sg-Exclude from CA' with at least one admin account for emergency access

.HOW-TO
    1. To install the Azure AD Preview PowerShell module use: Install-Module AzureADPreview -AllowClobber
    2. Run .\Install-BaselineConditionalAccessPolicies.ps1
    3. Reference: https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0#installing-the-azure-ad-module

.DETAILS
    FileName:    Install-BaselineConditionalAccessPolicies.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     September 2020
	Updated:     April 2021

#>
###################################################################################################

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

New-AzureADMSConditionalAccessPolicy -DisplayName "[ITPM Baseline] Block legacy authentication clients" -State "Disabled" -Conditions $conditions -GrantControls $controls 

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

New-AzureADMSConditionalAccessPolicy -DisplayName "[ITPM Baseline] Block unsupported device platforms" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

## This policy requires Multi-factor Authentication for Admin users

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

New-AzureADMSConditionalAccessPolicy -DisplayName "[ITPM Baseline] Require MFA for Admin users" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

## This policy requires Multi-factor Authentication for Azure Management

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeApplications = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$conditions.ClientAppTypes = @('Browser', 'MobileAppsAndDesktopClients')
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "MFA"

New-AzureADMSConditionalAccessPolicy -DisplayName "[ITPM Baseline] Require MFA for Azure Management" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

## This policy requires Multi-factor Authentication for all users on unmanaged devices

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
$controls.BuiltInControls = @('MFA', 'CompliantDevice', 'DomainJoinedDevice')

New-AzureADMSConditionalAccessPolicy -DisplayName "[ITPM Baseline] Require MFA for unmanaged devices" -State "Disabled" -Conditions $conditions -GrantControls $controls 

########################################################

## This policy requires Multi-factor Authentication when registering or joining a new device

$conditions = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessConditionSet
$conditions.Applications = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessApplicationCondition
$conditions.Applications.IncludeUserActions = "urn:user:registerdevice"
$conditions.Users = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessUserCondition
$conditions.Users.IncludeUsers = "All"
$conditions.Users.ExcludeUsers = "GuestsOrExternalUsers"
$conditions.Users.ExcludeGroups = $ExcludeCAGroup.ObjectId
$controls = New-Object -TypeName Microsoft.Open.MSGraph.Model.ConditionalAccessGrantControls
$controls._Operator = "OR"
$controls.BuiltInControls = "MFA"

New-AzureADMSConditionalAccessPolicy -DisplayName "[ITPM Baseline] Require MFA to register or join devices" -State "Disabled" -Conditions $conditions -GrantControls $controls 


########################################################
