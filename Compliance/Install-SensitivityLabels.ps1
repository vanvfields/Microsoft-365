<# 
.SYNOPSIS
    Use this script to deploy Sensitivity Labels from the Data Protection Starter Kit:
    - Non-Business: Use to identify personal data
    - Public: Use to identify data explicitly approved for public consumption
    - General: Use to identify data that can be shared as needed for business purposes.
    - Confidential: Category of labels to identify sensitive data
        -Anyone (Not Protected): Use to identify sensitive data which can be shared with approved external parties 
        -External (Protected): Use to identify and protect sensitive data which can be shared with approved external parties
        -Internal (Protected): Use to identify and protect sensitive data which can only be shared internally 
        -Recipients Only (Protected): Use to encrypt email messges in Outlook with Do Not Forward permissions (recipients cannot forward, copy, or print)

.NOTES
    1. You must have the AzureADPreview PowerShell module installed in order to run this script.
    2. You must have the ExchangeOnlineManagement PowerShell module installed in order to run this script.
    3. You must enable Sensitivity labels for Groups and Sites in order to run this script.
    4. Reference: https://docs.microsoft.com/en-us/microsoft-365/compliance/sensitivity-labels-teams-groups-sites

.DETAILS
    FileName:    Install-SensitivityLabels.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     May 2021
	Updated:     May 2021

#>


Import-Module AzureADPreview
Connect-AzureAD

Import-Module ExchangeOnlineManagement
Connect-IPPSSession


$CheckLabels = Get-LabelPolicy

if (!$CheckLabels) {

## Install the Non-Business label
$NonBusinessParam=@{
   'Name' = 'Non-Business';
   'DisplayName' = 'Non-Business';
   'Tooltip' = 'Use this classification to identify personal, non-corporate data. This label does not imply privacy.'
}

New-Label @NonBusinessParam 

## Install the Public label
$PublicParam=@{
   'Name' = 'Public';
   'DisplayName' = 'Public';
   'Tooltip' = 'Use this classification to identify data that is explicitly approved for general public consumption.';
   'SiteAndGroupProtectionEnabled' = $true;
   'SiteAndGroupProtectionPrivacy' = 'Public';
   'SiteAndGroupProtectionAllowAccessToGuestUsers' = $true;
   'SiteAndGroupProtectionAllowEmailFromGuestUsers' = $true;
   #'SiteExternalSharingControlType' = "ExternalUserAndGuestSharing";
   'Comment' = ' '
}

 New-Label @PublicParam 

 ## Install the General label
$GeneralParam=@{
   'Name' = 'General';
   'DisplayName' = 'General';
   'Tooltip' = 'Use this label to identify data that belongs to the Organization, but which may be shared as needed.';
   'SiteAndGroupProtectionEnabled' = $true;
   'SiteAndGroupProtectionAllowAccessToGuestUsers' = $true;
   'SiteAndGroupProtectionAllowEmailFromGuestUsers' = $true;
   #'SiteExternalSharingControlType' = "ExternalUserSharingOnly";
   'Comment' = ' '
}

 New-Label @GeneralParam 

  ## Install the Confidential label
$ConfidentialParam=@{
   'Name' = 'Confidential';
   'DisplayName' = 'Confidential';
   'Tooltip' = 'Use this classification to identify and protect data which is sensitive, and which should be shared more carefully.';
   'SiteAndGroupProtectionEnabled' = $true;
   'SiteAndGroupProtectionPrivacy' = 'Private';
   'SiteAndGroupProtectionAllowAccessToGuestUsers' = $false;
   'SiteAndGroupProtectionAllowEmailFromGuestUsers' = $false;
   #'SiteExternalSharingControlType' = "Disabled";
   'Comment' = ' '
}

 New-Label @ConfidentialParam 

## Install sub-labels for Confidential

## Install the Anyone (Not Protected) label (No encryption is applied)

$AnyoneParam=@{
   'Name' = 'Anyone';
   'DisplayName' = 'Anyone (Not Protected)';
   'Tooltip' = 'Use this classification to identify Confidential data that can be shared with approved parties outside the Organization; no encryption is applied.';
   'ParentID' = 'Confidential';
   'EncryptionEnabled' = $false;
   'EncryptionProtectionType' = 'RemoveProtection';
   'ApplyContentMarkingHeaderEnabled' = $true;
   'ApplyContentMarkingHeaderAlignment' = 'Left';
   'ApplyContentMarkingHeaderText' = 'Confidential (Not Protected)'
}

New-Label @AnyoneParam 


## Install the External (Protected) label 

$RightsDefinition = "VIEW,VIEWRIGHTSDATA,DOCEDIT,EDIT,PRINT,EXTRACT,REPLY,REPLYALL,FORWARD,OBJMODEL"

$ExternalParam=@{
   'Name' = 'External';
   'DisplayName' = 'External (Protected)';
   'Tooltip' = 'Use this classification to identify and protect Confidential data that can be shared with approved parties outside the Organization.';
   'ParentID' = 'Confidential';
   'EncryptionEnabled' = $true;
   'EncryptionProtectionType' = 'Template';
   'EncryptionRightsDefinitions' = "AuthenticatedUsers"+":"+$RightsDefinition;
   'EncryptionContentExpiredOnDateInDaysOrNever' = 'Never';
   'EncryptionOfflineAccessDays' = '30';
   'ApplyContentMarkingHeaderEnabled' = $true;
   'ApplyContentMarkingHeaderAlignment' = 'Left';
   'ApplyContentMarkingHeaderText' = 'Confidential (External)'
}

New-Label @ExternalParam 

## Install the Internal label (Encryption with Co-author permissions for all users in the domain)

$TenantDomain = (Get-AzureADDomain | Where-Object {$_.isInitial}).name
$RightsDefinition = "VIEW,VIEWRIGHTSDATA,DOCEDIT,EDIT,PRINT,EXTRACT,REPLY,REPLYALL,FORWARD,OBJMODEL"

$InternalParam=@{
   'Name' = 'Internal';
   'DisplayName' = 'Internal (Protected)';
   'Tooltip' = 'Use this classification to identify and protect Confidential data that should not be shared outside the Organization.';
   'ParentID' = 'Confidential';
   'EncryptionEnabled' = $true;
   'EncryptionProtectionType' = 'Template';
   'EncryptionRightsDefinitions' = $TenantDomain+":"+$RightsDefinition;
   'EncryptionContentExpiredOnDateInDaysOrNever' = 'Never';
   'EncryptionOfflineAccessDays' = '30';
   'ApplyContentMarkingHeaderEnabled' = $true;
   'ApplyContentMarkingHeaderAlignment' = 'Left';
   'ApplyContentMarkingHeaderText' = 'Confidential (Internal)'

}

New-Label @InternalParam 


## Install the Recipients Only label (Applies Do Not Forward template in Outlook)
$DNFParam=@{
   'Name' = 'Recipients Only';
   'DisplayName' = 'Recipients Only (Protected)';
   'Tooltip' = 'Use this classification to protect Confidential messages in Outlook. Recipients cannot forward, copy, or print the message.';
   'ParentID' = 'Confidential';
   'EncryptionEnabled' = $true;
   'EncryptionProtectionType' = 'UserDefined';
   'EncryptionDoNotForward' = $true
}

New-Label @DNFParam 


Write-Host 
Write-Host "The default labels have been installed."  -ForegroundColor Cyan
Write-Host
$Publish = Read-Host "Do you want to publish the labels to all users? Type Y or N and press Enter"

if ($Publish = 'y') { 


## Install a label policy to publish the labels 


$PolicyJSON = @"

{
    "requiredowngradejustification": true,
    "mandatory": false,
    "siteandgroupmandatory": false,
    "siteandgroupdefaultlabelid": ""
}

"@


New-LabelPolicy -Name "Default classification labels" -Labels "Non-Business","Public","General","Confidential","Anyone","External","Internal","Recipients Only" -ExchangeLocation All -Settings $PolicyJSON
Write-Host
Write-Host 'Default labels have been added and published to all users in the tenant.' -ForegroundColor Cyan
Write-Host 
Write-Host 'Script completed' -ForegroundColor Cyan
Write-Host
}

else {

Write-Host 
Write-Host "Labels will not be published at this time. You must publish labels before they can be applied to content." -ForegroundColor Yellow

}

}

else {
Write-Host
Write-Host 'Labels are already deployed in this organization. No changes have been made.' -ForegroundColor Yellow
Write-Host
Write-Host 'Script completed' -ForegroundColor Cyan
Write-Host
}


<# 
.NOTES 
    At the time of writing this script, the external sharing settings for sites are not functioning correctly when deployed via PowerShell.

    Therefore I have commented out the parameters for now, until Microsoft fixes it.

    It should be as follows:
   
    SiteExternalSharingControlType: 
        Anonymous/Anyone links = ExternalUserAndGuestSharing
        New and existing guests = ExternalUserSharingOnly
        Existing guests only = ExistingExternalUserSharingOnly 
        Only in the organization =  Disabled


#>