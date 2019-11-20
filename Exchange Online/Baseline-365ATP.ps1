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
    Created:     11-18-2019
	Revised:     11-18-2019
    Version:     2.0
    
#>
###################################################################################################


Clear-Host
$AcceptedDomains = Get-AcceptedDomain
$RecipientDomains = $AcceptedDomains.DomainName


write-host -foregroundcolor green "Configuring the Default ATP policy for Office 365..."

## Configures the default ATP policy for Office 365
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/set-atppolicyforo365?view=exchange-ps
Set-AtpPolicyForO365 -EnableSafeLinksForClients $true -EnableATPForSPOTeamsODB $true -AllowClickThrough $false -TrackClicks $true

write-host -foregroundcolor green "Default ATP policy for Office 365 has been set."

Write-Host -foregroundcolor green "Creating the Safe Links Baseline Policy..."
	
## Create the SafeLinks policy
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-safelinkspolicy?view=exchange-ps

$SafeLinksPolicyParam=@{
   'Name' = "Safe Links Baseline Policy";
   'AdminDisplayName' = "Safe Links Baseline Policy";
   'DoNotAllowClickThrough' =  $true;
   'DoNotTrackUserClicks' = $false;
   'DeliverMessageAfterScan' = $true;
   'EnableForInternalSender' = $true;
   'ScanUrls' = $true;
   'TrackClicks' = $true;
   'IsEnabled' = $true
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

$SafeAttachmentPolicyParam=@{
   'Name' = "Safe Attachments Baseline Policy";
   'AdminDisplayName' = "Safe Attachments Baseline Policy";
   'Action' =  "Block";
   'ActionOnError' = $true;
   'Enable' = $true;
   'Redirect' = $false
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

Write-Host -foregroundcolor green "Creating the Anti-Phish Baseline Policy..."

## Create the Anti-Phish policy 
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-antiphishpolicy?view=exchange-ps

$PhishPolicyParam=@{
   ##'Name' = "AntiPhish Baseline Policy";
   ##'AdminDisplayName' = "AntiPhish Baseline Policy";
   'AuthenticationFailAction' =  'Quarantine';
   'EnableAntispoofEnforcement' = $true;
   'EnableAuthenticationSafetyTip' = $true;
   'EnableAuthenticationSoftPassSafetyTip' = $true;
   'Enabled' = $true;
   'EnableMailboxIntelligence' = $true;
   'EnableMailboxIntelligenceProtection' = $true;
   'MailboxIntelligenceProtectionAction' = 'Quarantine';
   'EnableOrganizationDomainsProtection' = $true;
   'EnableSimilarDomainsSafetyTips' = $true;
   'EnableSimilarUsersSafetyTips' = $true;
   'EnableTargetedDomainsProtection' = $false;
   ##'TargetedDomainsToProtect' = $RecipientDomains;
   'EnableTargetedUserProtection' = $false;
   ##'TargetedUsersToProtect' = $TargetedUsersToProtect;
   'EnableUnusualCharactersSafetyTips' = $true;
   'PhishThresholdLevel' = 3;
   'TargetedDomainProtectionAction' =  'Quarantine';
   'TargetedUserProtectionAction' =  'Quarantine';
   'TreatSoftPassAsAuthenticated' = $true
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

write-host -foregroundcolor green "Office 365 ATP baseline configuration has completed."
