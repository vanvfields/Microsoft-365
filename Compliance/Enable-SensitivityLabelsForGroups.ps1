<##################################################################################################
#
.SYNOPSIS
    This script will enable Sensitivity labels for Groups and Sites:

.PREREQUISITES
    1. You must install the AzureADPreview PowerShell module (Install-AzureADPreview)
    2. You will also require the Exchange Online V2 module (Install-Module -Name ExchangeOnlineManagement) 

.DETAILS
    FileName:    Enable-SensitivityLabelsForGroups.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     November 2020
	Updated:     April 2021

.NOTES
    You will be prompted twice since you must authenticate against both Azure AD and Exchange Online

#>
###################################################################################################


## Import the AzureADPreview module
Import-Module AzureADPreview

## Connect to Azure AD
Connect-AzureAD

## Import the Exchange Online V2 module
Import-Module ExchangeOnlineManagement

## Connect to the Security & Compliance center with the EXO V2 module
Connect-IPPSSession

## Get the Template ID for Group.Unified
$TemplateId = (Get-AzureADDirectorySettingTemplate | where { $_.DisplayName -eq "Group.Unified" }).Id
$Template = Get-AzureADDirectorySettingTemplate | where -Property Id -Value $TemplateId -EQ


## Create a new settings object based on the template
$Setting = $Template.CreateDirectorySetting()

## Enable the unified lables feature for groups
$Setting["EnableMIPLabels"] = "True"

## Apply the setting 
New-AzureADDirectorySetting -DirectorySetting $Setting

## Note: Read the settings for this new object out with the following:
$Setting.Values

## Run the following to allow Sensitivity labels to be used with Groups:
Execute-AzureAdLabelSync


## End of script