
<##################################################################################################
#
.SYNOPSIS
Define a security group using the variable $GroupName
This will limit the privilege for creating Office 365 Groups to the specified security group


You have to connect to Azure AD using Connect-AzureAD before running this script:
https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0

Source of script:
https://docs.microsoft.com/en-us/microsoft-365/admin/create-groups/manage-creation-of-groups?view=o365-worldwide

.NOTES
    FileName:    Limit-GroupsCreation.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     February 2020
    Revised:     April 2021
    Version:     1.1
    
#>
###################################################################################################


$GroupName = "sg-Group Creators"
$AllowGroupCreation = "False"


$CheckForGroup = Get-AzureADGroup -All $true | Where-Object DisplayName -eq $GroupName

if ($CheckForGroup -eq $null -or $CheckForGroup -eq "") {
    New-AzureADGroup -DisplayName $GroupName -SecurityEnabled $true -MailEnabled $false -MailNickName $GroupName
    $CheckForGroup = Get-AzureADGroup -All $true | Where-Object DisplayName -eq $GroupName
}
else {
    Write-Host "Security group for Group Creators already exists"
}


$settingsObjectID = (Get-AzureADDirectorySetting | Where-object -Property Displayname -Value "Group.Unified" -EQ).id
if(!$settingsObjectID)
{
	  $template = Get-AzureADDirectorySettingTemplate | Where-object {$_.displayname -eq "group.unified"}
    $settingsCopy = $template.CreateDirectorySetting()
    New-AzureADDirectorySetting -DirectorySetting $settingsCopy
    $settingsObjectID = (Get-AzureADDirectorySetting | Where-object -Property Displayname -Value "Group.Unified" -EQ).id
}

$settingsCopy = Get-AzureADDirectorySetting -Id $settingsObjectID
$settingsCopy["EnableGroupCreation"] = $AllowGroupCreation

if($GroupName)
{
	$settingsCopy["GroupCreationAllowedGroupId"] = (Get-AzureADGroup -SearchString $GroupName).objectid
} else {
$settingsCopy["GroupCreationAllowedGroupId"] = $GroupName
}
Set-AzureADDirectorySetting -Id $settingsObjectID -DirectorySetting $settingsCopy

(Get-AzureADDirectorySetting -Id $settingsObjectID).Values


