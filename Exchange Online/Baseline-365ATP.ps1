<##################################################################################################
#
.SYNOPSIS
This script configures a new tenant with Office 365 Advanced Threat Protection Plan 1.
In the future you can simply use the protection templates which will be available in the Security & Compliance center.
Until then, use this to get a good baseline configuration in place.

Connect to Exchange Online via PowerShell using MFA:
https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps

.NOTES
    FileName:    Baseline-365ATP.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     November 2019
	Revised:     August 2020
    Version:     3.1
    
#>
###################################################################################################

#################################################
## CONFIGURE OFFICE 365 ATP SETTINGS
#################################################
Write-Host
$Answer = Read-Host "Do you want to configure Office 365 ATP with the recommended baseline settings? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {


$AcceptedDomains = Get-AcceptedDomain
$RecipientDomains = $AcceptedDomains.DomainName

Write-Host 
Write-Host -foregroundcolor green "Creating the Anti-Phish Baseline Policy..."

## Create the Anti-Phish policy 
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-antiphishpolicy?view=exchange-ps
## You can edit the below to enable TargetedDomainsToProtect as well as TargetedUsersToProtect, as needed (optional).

$PhishPolicyParam=@{
   ##'Name' = "AntiPhish Baseline Policy";
   ##'AdminDisplayName' = "AntiPhish Baseline Policy";
   'EnableTargetedUserProtection' = $false;
   ##'TargetedUsersToProtect' = $TargetedUsersToProtect
   'EnableOrganizationDomainsProtection' = $true;
   'EnableTargetedDomainsProtection' = $false;
   ##'TargetedDomainsToProtect' = $RecipientDomains;
   'TargetedUserProtectionAction' =  'Quarantine';
   'TargetedDomainProtectionAction' =  'Quarantine';
   'EnableSimilarUsersSafetyTips' = $true;
   'EnableSimilarDomainsSafetyTips' = $true;
   'EnableUnusualCharactersSafetyTips' = $true;
   'EnableMailboxIntelligence' = $true;
   'EnableMailboxIntelligenceProtection' = $true;
   'MailboxIntelligenceProtectionAction' = 'MoveToJmf';
   'EnableAntispoofEnforcement' = $true;
   'EnableUnauthenticatedSender' = $true;
   'AuthenticationFailAction' =  'MoveToJmf';
   'PhishThresholdLevel' = 2;
   'Enabled' = $true
   
}

Set-AntiPhishPolicy -Identity "Office365 AntiPhish Default" @PhishPolicyParam


<# Ignore this section unless you are attempting to create custom rules
## Get-AntiPhishRule | Remove-AntiPhishRule
## Get-AntiPhishPolicy | Where-Object IsDefault -eq $false | Set-AntiPhishPolicy -Enabled $false 
## Create the AntiPhish rule
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-antiphishrule?view=exchange-ps
	
$PhishRuleParam = @{
    'Name' = "AntiPhish Baseline";
	'AntiPhishPolicy' = "AntiPhish Baseline Policy"; 
	'RecipientDomainis' = $RecipientDomains;
	'Enabled' = $true;
	'Priority' = 0
}

New-AntiPhishRule @PhishRuleParam
#>

Write-Host -foregroundcolor green "The AntiPhish Baseline Policy is deployed."
Write-Host 

write-host -foregroundcolor green "Configuring the default ATP links policy for Office 365..."

## Configures the default ATP links policy for Office 365
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/set-atppolicyforo365?view=exchange-ps
$AtpPolicyForO365Param=@{
   'EnableATPForSPOTeamsODB' =  $true;
   'EnableSafeLinksForO365Clients' = $true;
   #'EnableSafeLinksForWebAccessCompanion' = $true;
   'EnableSafeDocs' = $false
   'TrackClicks' = $true;
   'AllowClickThrough' = $false
}

Set-AtpPolicyForO365 @AtpPolicyForO365Param

write-host -foregroundcolor green "Default ATP policy for Office 365 has been set."

Write-Host -foregroundcolor green "Creating the Safe Links Baseline Policy..."
	
## Create the Safe Links policy for users
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-safelinkspolicy?view=exchange-ps

$SafeLinksPolicyParam=@{
   'IsEnabled' = $true;
   'Name' = "Safe Links Baseline Policy";
   'AdminDisplayName' = "Safe Links Baseline Policy";
   'EnableSafeLinksForTeams' = $true;
   'ScanUrls' = $true;
   'DeliverMessageAfterScan' = $true;
   'EnableForInternalSenders' = $true;
   'DoNotTrackUserClicks' = $false;
   'DoNotAllowClickThrough' =  $true
}

New-SafeLinksPolicy @SafeLinksPolicyParam 

## Create the Safe Links Rule
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-safelinksrule?view=exchange-ps

$SafeLinksRuleParam = @{
    'Name' = "Safe Links Baseline";
	'SafeLinksPolicy' = "Safe Links Baseline Policy";
	'RecipientDomainIs' = $RecipientDomains;
	'Enabled' = $true;
	'Priority' = 0
}

New-SafeLinksRule @SafeLinksRuleParam

Write-Host -foregroundcolor green "The Safe Links Baseline Policy is deployed."

Write-Host -foregroundcolor green "Creating the Safe Attachments Baseline Policy..."

## Create the SafeAttachments policy
## Action options = Block | Replace | Allow | DynamicDelivery (Block is the recommended action)
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-safeattachmentpolicy?view=exchange-ps
## Note: Optionally you can edit the below to enable Redirect, and specify a RedirectAddress--in that case set ActionOnError to $true

$SafeAttachmentPolicyParam=@{
   'Name' = "Safe Attachments Baseline Policy";
   'AdminDisplayName' = "Safe Attachments Baseline Policy";
   'Action' =  "Block";
   'Redirect' = $false;
   ##'RedirectAddress' = $RedirectAddress;
   'ActionOnError' = $false;
   'Enable' = $true
}

New-SafeAttachmentPolicy @SafeAttachmentPolicyParam

## Create the SafeAttachments Rule 
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-safeattachmentrule?view=exchange-ps

$SafeAttachRuleParam=@{
    'Name' = "Safe Attachments Baseline";
	'SafeAttachmentPolicy' = "Safe Attachments Baseline Policy";
	'RecipientDomainIs' = $RecipientDomains;
	'Enabled' = $true;
	'Priority' = 0
}

New-SafeAttachmentRule @SafeAttachRuleParam

Write-Host -foregroundcolor green "The Safe Attachment Baseline Policy is deployed."


write-host -foregroundcolor green "Office 365 ATP baseline configuration has completed."

} else {

    Write-Host
    Write-Host -ForegroundColor $AssessmentColor "Office 365 ATP features have not been modified."

}


###################################################################################################
## THIS CONCLUDES THE SCRIPT

