##########################################################################################################################################################################################
## Description:
## This script configures Office 365 Advanced Threat Protection Plan 1
## Prerequisites:
## The tenant will need to include licensing for Office 365 ATP Plan 1 
## Connect to Exchange Online via PowerShell using MFA:
## https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps
##
## WARNING: Script provided as-is. Author is not responsible for its use and application. Use at your own risk.
##########################################################################################################################################################################################
## Fill in all of the following variables:
##
## $AlertAddress = Required only if you enable this option within the Safe Attachments policy. Who will recieve notifications/redirected emails?
$AlertAddress = "alert@providerdomain.com"
##
## $RecipientDomains = Fill in the domain names that will be protected by domain impersonation:
## e.g. $RecipientDomains = "tenantname.onmicrosoft.com", "domain1.com", "domain2.com", "domain3.com"
##
$RecipientDomains = "tenant.onmicrosoft.com", "firstdomain.com", "seconddomain.com", "n-domain.com"
##
## $TargetedUsersToProtect = Fill in the users who will be protected by user impersonation:
## e.g. $TargetedUsersToProtect = "Display Name 1;user1@domain.com", "Display Name 2;user2@domain.com", "Display Name 3;user3@domain.com"
##
$TargetedUsersToProtect="John Doe;JDoe@firstdomain.com", "Jane Smith;JSmith@n-domain.com"
##
## Note: you may need to set your execution policy for the script to run successfully
##########################################################################################################################################################################################

Clear-Host

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
   'Redirect' = $false;
   #'RedirectAddress' = $AlertAddress
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
   'Name' = "Anti-Phish Baseline Policy";
   'AdminDisplayName' = "Anti-Phish Baseline Policy";
   'AuthenticationFailAction' =  'Quarantine';
   'EnableAntispoofEnforcement' = $true;
   'EnableAuthenticationSafetyTip' = $true;
   'EnableAuthenticationSoftPassSafetyTip' = $true;
   'Enabled' = $true;
   'EnableMailboxIntelligence' = $true;
   'EnableOrganizationDomainsProtection' = $true;
   'EnableSimilarDomainsSafetyTips' = $true;
   'EnableSimilarUsersSafetyTips' = $true;
   'EnableTargetedDomainsProtection' = $false;
   'EnableTargetedUserProtection' = $true;
   'TargetedUsersToProtect' = $TargetedUsersToProtect;
   'EnableUnusualCharactersSafetyTips' = $true;
   'PhishThresholdLevel' = 1;
   'TargetedDomainProtectionAction' =  'Quarantine';
   'TargetedUserProtectionAction' =  'Quarantine';
   'TreatSoftPassAsAuthenticated' = $true
}

New-AntiPhishPolicy @PhishPolicyParam

## Create the Anti-Phish rule
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-antiphishrule?view=exchange-ps
	
$PhishRuleParam = @{
    'Name' = "Anti-Phish Baseline";
	'AntiPhishPolicy' = "Anti-Phish Baseline Policy"; 
	'RecipientDomainis' = $RecipientDomains;
	'Enabled' = $true;
	'Priority' = 0
}

New-AntiPhishRule @PhishRuleParam

Write-Host -foregroundcolor green "The Anti-Phish Baseline Policy is deployed."

write-host -foregroundcolor green "ATP baseline configuration has completed."
