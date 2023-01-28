<##################################################################################################
#
.SYNOPSIS 
This script deploys custom EOP and MDO policies for new tenants following the Standard Protection settings with 1/day quarantine notifications.

See this article for more details:
https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365?view=o365-worldwide


Connect to Exchange Online via PowerShell:
https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps


.NOTES
    FileName:    Install-EXOStandardProtection.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     March 2020
	Revised:     January 2023
    Version:     4.0
    
#>
###################################################################################################
## NOTE: If the script errors out, you may need to set your execution policy.
## You may also need to run: Enable-OrganizationCustomization
## Please define these variables before running this script: 
$MessageColor = "Green"
$AssessmentColor = "Yellow"

$AcceptedDomains = Get-AcceptedDomain
$RecipientDomains = $AcceptedDomains.DomainName


#############################################################################################
## INBOUND FILTER POLICY SETTINGS
## IT IS RECOMMENDED TO USE PRESET SECURITY POLICIES OR EQUIVALENT CUSTOM POLICIES
#############################################################################################

Write-Host 
$Answer = Read-Host "Do you want to reset the default inbound filter policy with the Standard Protection settings? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
    $HostedContentPolicyParam = @{
        'SpamAction' = 'MoveToJMF';
        'HighConfidenceSpamAction' =  'quarantine';
        'PhishSpamAction' = 'quarantine';
        'HighConfidencePhishAction' =  'quarantine';
        'BulkSpamAction' =  'MoveToJMF';
        'BulkThreshold' =  '6';
        'QuarantineRetentionPeriod' = 30;
        'InlineSafetyTipsEnabled' = $true;
        'EnableEndUserSpamNotifications' = $true;
        'EndUserSpamNotificationFrequency' = 1;
        'SpamZapEnabled'= $true;
        'PhishZapEnabled' = $true;
        'MarkAsSpamBulkMail' = 'On';
        'IncreaseScoreWithImageLinks' = 'off'
        'IncreaseScoreWithNumericIps' = 'off'
        'IncreaseScoreWithRedirectToOtherPort' = 'off'
        'IncreaseScoreWithBizOrInfoUrls' = 'off';
        'MarkAsSpamEmptyMessages' ='off';
        'MarkAsSpamJavaScriptInHtml' = 'off';
        'MarkAsSpamFramesInHtml' = 'off';
        'MarkAsSpamObjectTagsInHtml' = 'off';
        'MarkAsSpamEmbedTagsInHtml' ='off';
        'MarkAsSpamFormTagsInHtml' = 'off';
        'MarkAsSpamWebBugsInHtml' = 'off';
        'MarkAsSpamSensitiveWordList' = 'off';
        'MarkAsSpamSpfRecordHardFail' = 'off';
        'MarkAsSpamFromAddressAuthFail' = 'off';
        'MarkAsSpamNdrBackscatter' = 'off'
    }
    Set-HostedContentFilterPolicy Default @HostedContentPolicyParam -MakeDefault
    Write-Host
    Write-Host -ForegroundColor $MessageColor "The default inbound filter policy has been reset according to best practices"
        Write-Host 
        $Answer2 = Read-Host "Do you also want to disable custom anti-spam rules, so that only the default policy applies? Type Y or N and press Enter to continue"
            if ($Answer2 -eq 'y' -or $Answer2 -eq 'yes') {
            Get-HostedContentFilterRule | Disable-HostedContentFilterRule
            Write-Host
            Write-Host -ForegroundColor $MessageColor "All custom anti-spam rules were disabled; they have not been deleted"
            } else {
                Write-Host 
                Write-Host -ForegroundColor $AssessmentColor "No custom rules were disabled"
        }
    
    } else {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "The default inbound policy has not been modified"
    }


#############################################################################################
## RESET OUTBOUND SPAM FILTER
## ANY SUBSCRIPTION
## IT IS RECOMMENDED TO USE PRESET SECURITY POLICIES OR EQUIVALENT CUSTOM POLICIES
#############################################################################################
Write-Host 
$Answer = Read-Host "Do you want to reset the outbound spam filter policy with the Standard Protection settings? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {

                $OutboundPolicyParam = @{
                "Identity" = 'Default';
                'RecipientLimitExternalPerHour' = 500;
                'RecipientLimitInternalPerHour' = 1000;
                'RecipientLimitPerDay' = 1000;
                'ActionWhenThresholdReached' = 'BlockUser';
                'AutoForwardingMode' = 'Off';
                ##'BccSuspiciousOutboundMail' = $false;
                ##'BccSuspiciousOutboundAdditionalRecipients' = '';
                ##'NotifyOutboundSpamRecipients' = ''
                'NotifyOutboundSpam' = $false                
            }
            Set-HostedOutboundSpamFilterPolicy @OutboundPolicyParam 
            Write-Host
            Write-Host -ForegroundColor $MessageColor "The default outbound spam filter has been reset according to best practices"
            }
 else {
    Write-Host
    Write-Host -ForegroundColor $AssessmentColor "The outbound spam filter policy has not been modified"
}


############################################################################################
## RESET DEFAULT ANTIMALWARE SETTINGS
## ANY SUBSCRIPTION
## IT IS RECOMMENDED TO USE PRESET SECURITY POLICIES OR EQUIVALENT CUSTOM POLICIES
############################################################################################
Write-Host 

$Answer = Read-Host "Do you want to reset the default malware filter policy with the Standard Protection settings? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
    Write-Host 
    #$AlertAddress= Read-Host "Enter the email address where you would like to recieve alerts about malware"
    ## Modify the default malware filter policy
    $MalwarePolicyParam = @{
        'EnableFileFilter' =  $true;
        'FileTypeAction' = "Reject";
        'ZapEnabled' = $true
        
    }
    Set-MalwareFilterPolicy Default @MalwarePolicyParam -MakeDefault
    Write-Host 
    Write-Host -ForegroundColor $MessageColor "The default malware filter policy has been reset according to best practices"
        Write-Host 
        $Answer2 = Read-Host "Do you also want to disable custom malware filter rules, so that only the default policy applies? Type Y or N and press Enter to continue"
            if ($Answer2 -eq 'y' -or $Answer2 -eq 'yes') {
            Get-MalwareFilterRule | Disable-MalwareFilterRule
            Write-Host
            Write-Host -ForegroundColor $MessageColor "All custom malware filter rules were disabled; they have not been deleted"
            } else {
            Write-Host 
            Write-Host -ForegroundColor $AssessmentColor "No custom rules were disabled"
    }
    
    } else {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "The default malware filter policy has not been modified"
    }



#############################################################################################
## CONFIGURE DEFENDER FOR OFFICE 365
## IT IS RECOMMENDED TO USE PRESET SECURITY POLICIES OR EQUIVALENT CUSTOM POLICIES
#############################################################################################
Write-Host
$Answer = Read-Host "Do you want to configure default Defender for Office 365 policies with the Standard Protection settings? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {


Write-Host 
Write-Host -foregroundcolor green "Setting the Anti-Phish Baseline Policy..."

## Create the Anti-Phish policy 
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-antiphishpolicy?view=exchange-ps
## You can edit the below to enable TargetedDomainsToProtect as well as TargetedUsersToProtect, as needed (optional).

$PhishPolicyParam=@{
   ##'Name' = "AntiPhish Standard Policy";
   ##'AdminDisplayName' = "AntiPhish Standard Policy";
   'EnableSpoofIntelligence' = $true;
   'AuthenticationFailAction' = "MoveToJmf";
   'EnableFirstContactSafetyTips' = $false;
   'EnableUnauthenticatedSender' = $true;
   'EnableViaTag' = $true;
   'PhishThresholdLevel' = 3;
   'EnableOrganizationDomainsProtection' = $true;
   'EnableMailboxIntelligence' = $true;
   'EnableMailboxIntelligenceProtection' = $true;
   'MailboxIntelligenceProtectionAction' = 'MoveToJmf';
   'EnableSimilarUsersSafetyTips' = $true;
   'EnableSimilarDomainsSafetyTips' = $true;
   'EnableUnusualCharactersSafetyTips' = $true;

   ## It is recommended to customize and configure the targeted user and domain options below
   ##'EnableTargetedUserProtection' = $true;
   ##'TargetedUsersToProtect' = <list of users>
   ##'EnableTargetedDomainsProtection' = $true;
   ##'TargetedDomainsToProtect' = <list of domains>;
   'TargetedUserProtectionAction' =  'Quarantine';
   'TargetedDomainProtectionAction' =  'Quarantine';
   

   
   ## The parameter below is deprecated
   ##'EnableAntispoofEnforcement' = $true;
   
   
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

Write-Host -foregroundcolor green "The AntiPhish Standard Policy is deployed."
Write-Host 

## Create the SafeAttachments policy
## Action options = Block | Replace | Allow | DynamicDelivery (Block is the recommended action)
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-safeattachmentpolicy?view=exchange-ps
## Note: Optionally you can edit the below to enable Redirect, and specify a RedirectAddress--in that case set ActionOnError to $true

Write-Host -foregroundcolor green "Creating the Safe Attachments Standard Policy..."


$SafeAttachmentPolicyParam=@{
   'Name' = "Safe Attachments Standard Policy";
   'AdminDisplayName' = "Safe Attachments Standard Policy";
   'Enable' = $true;
   'Action' =  "Block"
   

   ## It is recommended to customize and configure the redirect settings below
   ##'Redirect' = $false;
   ##'RedirectAddress' = $RedirectAddress;
   ##'ActionOnError' = $true
     
}

New-SafeAttachmentPolicy @SafeAttachmentPolicyParam

## Create the SafeAttachments Rule 
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-safeattachmentrule?view=exchange-ps

$SafeAttachRuleParam=@{
    'Name' = "Safe Attachments Standard Rule";
	'SafeAttachmentPolicy' = "Safe Attachments Standard Policy";
	'RecipientDomainIs' = $RecipientDomains;
	'Enabled' = $true;
	'Priority' = 0
}

New-SafeAttachmentRule @SafeAttachRuleParam

Write-Host -foregroundcolor green "The Safe Attachment Baseline Policy is deployed."





write-host -foregroundcolor green "Configuring the Default Safe Links policy for Office 365..."

## Configures the default safe links policy for Office 365
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/set-atppolicyforo365?view=exchange-ps
$AtpPolicyForO365Param=@{
   'EnableATPForSPOTeamsODB' =  $true
   # SafeDocs is for E5 subscriptions only
   #'EnableSafeDocs' = $true;
   #'AllowSafeDocsOpen' = $false
}

Set-AtpPolicyForO365 @AtpPolicyForO365Param

write-host -foregroundcolor green "Default safe links policy for Office 365 has been set."

Write-Host -foregroundcolor green "Creating the Safe Links Standard Policy..."
	
## Create the Safe Links policy for users
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-safelinkspolicy?view=exchange-ps

$SafeLinksPolicyParam=@{
   'Name' = "Safe Links Standard Policy";
   'AdminDisplayName' = "Safe Links Standard Policy";
   'EnableSafeLinksForEmail' = $true;
   'EnableSafeLinksForTeams' = $true;
   'EnableSafeLinksForOffice' = $true;
   'ScanUrls' = $true;
   'DeliverMessageAfterScan' = $true;
   'EnableForInternalSenders' = $true;
   'TrackClicks' = $true;
   'AllowClickThrough' =  $false
}

New-SafeLinksPolicy @SafeLinksPolicyParam 

## Create the Safe Links Rule
## https://docs.microsoft.com/en-us/powershell/module/exchange/advanced-threat-protection/new-safelinksrule?view=exchange-ps

$SafeLinksRuleParam = @{
    'Name' = "Safe Links Standard Rule";
	'SafeLinksPolicy' = "Safe Links Standard Policy";
	'RecipientDomainIs' = $RecipientDomains;
	'Enabled' = $true;
	'Priority' = 0
}

New-SafeLinksRule @SafeLinksRuleParam

Write-Host -foregroundcolor green "The Safe Links Standard Policy is deployed."



write-host -foregroundcolor green "Defender for Office 365 baseline configuration has completed."

} else {

    Write-Host
    Write-Host -ForegroundColor $AssessmentColor "Defender for Office 365 features have not been modified."

}


###################################################################################################
## THIS CONCLUDES THE SCRIPT
