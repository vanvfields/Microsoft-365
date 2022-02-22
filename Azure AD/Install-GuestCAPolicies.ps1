<##################################################################################################
#NOTE: This script is legacy, the latest complete baseline is Install-ITPMBaselineCAPolicies.ps1
.SYNOPSIS
    This script will create the following optional Conditional Access policies in your tenant:

    1. CA301: Block guest access to unsupported apps
    2. CA302: Require MFA for guests and external users

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
	Updated:     January 2022

#>
###################################################################################################



## Check for the existence of the "Exclude from CA" security group, and create the group if it does not exist

$ExcludeCAGroupName = "sgu-Exclude From CA"
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
## 2.
## CA302: Require MFA for guests and external users
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

New-AzureADMSConditionalAccessPolicy -DisplayName "CA302: Require MFA for guests and external users" -State "Disabled" -Conditions $conditions -GrantControls $controls 


########################################################

Write-Host "Script completed" -ForegroundColor Cyan
