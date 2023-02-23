<##################################################################################################
#
.SYNOPSIS 
This script deploys custom EOP and MDO policies including quarantine settings, mostly in line with the Strict protection template.

You will be given a prompt regarding quarantine settings:
    - Answer in the affirmative to deploy full access policy (end users get to release their own messages)
    - Answer in the negative to deploy limited access policy (admins must release messages) 

See this article for more details:
https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/recommended-settings-for-eop-and-office365?view=o365-worldwide


Connect to Exchange Online via PowerShell:
https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps


.NOTES
    FileName:    Install-EXOCustomProtection.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     February 2023
	Revised:     February 2023
    Version:     1.0
    
#>
###################################################################################################


#region variables

$MessageColor = "Green"
$AcceptedDomains = Get-AcceptedDomain
$RecipientDomains = $AcceptedDomains.DomainName

#endregion variables


###################################################################################################
#region quarantine policy

Write-Host 
$Answer = Read-Host "Should end users have full access to quarantine items? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y' -or $Answer -eq 'yes') {

    Write-Host
    Write-Host -ForegroundColor $MessageColor "Creating full access quarantine policy with notifications enabled..."
    $QuarantinePolicyParams = @{
        'Name' = 'FullAccessNotificationPolicy';
        'EndUserQuarantinePermissionsValue' = '23';
        'QuarantineRetentionDays' = '30';
        'ESNEnabled' = $true
    }

    $QuarantinePolicy = New-QuarantinePolicy @QuarantinePolicyParams
    } else {

    Write-Host
    Write-Host -ForegroundColor $MessageColor "Creating limited access quarantine policy with notifications enabled..."
    $QuarantinePolicyParams = @{
        'Name' = 'LimitedAccessNotificationPolicy';
        'EndUserQuarantinePermissionsValue' = '27';
        'QuarantineRetentionDays' = '30';
        'ESNEnabled' = $true
    }

    $QuarantinePolicy = New-QuarantinePolicy @QuarantinePolicyParams
}


#endregion quarantine policy


###################################################################################################
#region anti-spam inbound policy

    Write-Host
    Write-Host -ForegroundColor $MessageColor "Creating custom anti-spam inbound baseline policy..."

    $HostedContentPolicyParam = @{
        'Name' = 'BaselineInboundPolicy';
        'SpamAction' = 'MoveToJMF';
        'HighConfidenceSpamAction' =  'quarantine';
        'HighConfidenceSpamQuarantineTag' = $QuarantinePolicy;
        'PhishSpamAction' = 'quarantine';
        'PhishQuarantineTag' = $QuarantinePolicy;
        'HighConfidencePhishAction' =  'quarantine';
        'HighConfidencePhishQuarantineTag' = $QuarantinePolicy;
        'BulkSpamAction' =  'MoveToJMF';
        'BulkThreshold' =  '5';
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
   
    New-HostedContentFilterPolicy @HostedContentPolicyParam 
    
    $HostedContentRuleParam = @{
        'Name' = 'Custom Anti-spam inbound baseline';
        'HostedContentFilterPolicy' = 'BaselineInboundPolicy';
        'RecipientDomainIs' = $RecipientDomains;
        'Enabled' = $true;
        'Priority' = '0'
    }
     
    New-HostedContentFilterRule @HostedContentRuleParam



#endregion anti-spam inbound policy


###################################################################################################
#region anti-spam outbound policy
    Write-Host
    Write-Host -ForegroundColor $MessageColor "Creating custom anti-spam outbound baseline policy..."

    $OutboundPolicyParam = @{
        'Name' = 'BaselineOutboundPolicy';
        'RecipientLimitExternalPerHour' = 400;
        'RecipientLimitInternalPerHour' = 800;
        'RecipientLimitPerDay' = 800;
        'ActionWhenThresholdReached' = 'BlockUser';
        'AutoForwardingMode' = 'Off';
        'NotifyOutboundSpam' = $false                
        }
    New-HostedOutboundSpamFilterPolicy @OutboundPolicyParam

    $OutboundRuleParam = @{
        'Name' = 'Custom Anti-spam outbound baseline';
        'HostedOutboundSpamFilterPolicy' = 'BaselineOutboundPolicy';
        'SenderDomainIs' = $RecipientDomains;
        'Enabled' = $true;
        'Priority' = 0
    }
    
    New-HostedOutboundSpamFilterRule @OutboundRuleParam    


#endregion anti-spam outbound policy


###################################################################################################
#region anti-malware policy

    Write-Host 
    Write-Host -ForegroundColor $MessageColor "Creating custom anti-malware baseline policy"

    $MalwarePolicyParam = @{
        'Name' = 'BaselineAntiMalwarePolicy';
        'EnableFileFilter' =  $true;
        'FileTypeAction' = "Reject";
        'ZapEnabled' = $true
        
    }

    New-MalwareFilterPolicy @MalwarePolicyParam

    $MalwareRuleParam = @{
        'Name' = 'Custom Anti-malware baseline';
        'MalwareFilterPolicy' = 'BaselineAntiMalwarePolicy';
        'RecipientDomainIs' = $RecipientDomains;
        'Enabled' = $true;
        'Priority' = 0

    }

    New-MalwareFilterRule @MalwareRuleParam



#endregion anti-malware policy


###################################################################################################
#region anti-phish policy

Write-Host 
Write-Host -foregroundcolor $MessageColor "Creating custom Anti-phish baseline policy..."

    $PhishPolicyParam=@{
       'Name' = "BaselineAntiPhishPolicy";
       'EnableSpoofIntelligence' = $true;
       'AuthenticationFailAction' = "quarantine";
       'SpoofQuarantineTag' = $QuarantinePolicy;
       'EnableFirstContactSafetyTips' = $true;
       'EnableUnauthenticatedSender' = $true;
       'EnableViaTag' = $true;
       'PhishThresholdLevel' = 4;
       'EnableOrganizationDomainsProtection' = $true;
       'EnableMailboxIntelligence' = $true;
       'EnableMailboxIntelligenceProtection' = $true;
       'MailboxIntelligenceProtectionAction' = 'quarantine';
       'MailboxIntelligenceQuarantineTag' = $QuarantinePolicy;
       'EnableSimilarUsersSafetyTips' = $true;
       'EnableSimilarDomainsSafetyTips' = $true;
       'EnableUnusualCharactersSafetyTips' = $true;

       ## It is recommended to customize and configure the targeted user and domain options below
       ##'EnableTargetedUserProtection' = $true;
       ##'TargetedUsersToProtect' = <list of users>
       ##'EnableTargetedDomainsProtection' = $true;
       ##'TargetedDomainsToProtect' = <list of domains>;
       'TargetedUserProtectionAction' =  'Quarantine';
       'TargetedUserQuarantineTag' = $QuarantinePolicy;
       'TargetedDomainProtectionAction' =  'Quarantine';
       'TargetedDomainQuarantineTag' = $QuarantinePolicy;
      
       'Enabled' = $true
   
    }
    New-AntiPhishPolicy @PhishPolicyParam 
	
    $PhishRuleParam = @{
        'Name' = "Custom Anti-phish baseline";
	    'AntiPhishPolicy' = "BaselineAntiPhishPolicy"; 
	    'RecipientDomainis' = $RecipientDomains;
	    'Enabled' = $true;
	    'Priority' = 0
    }

    New-AntiPhishRule @PhishRuleParam

#    Get-AntiPhishPolicy -Identity BaselineAntiPhishPolicy | Set-AntiPhishPolicy -MakeDefault

#endregion anti-phish policy


###################################################################################################
#region safe attachments policy

Write-Host
Write-host -foregroundcolor $MessageColor "Configuring the Safe Attachments Global settings..."

    $AtpPolicyForO365Param=@{
       'EnableATPForSPOTeamsODB' =  $true
       # SafeDocs settings below for E5 subscriptions only:
       #'EnableSafeDocs' = $true;
       #'AllowSafeDocsOpen' = $false
    }

    Set-AtpPolicyForO365 @AtpPolicyForO365Param


Write-Host 
Write-Host -foregroundcolor $MessageColor "Creating Custom Safe Attachments baseline..."

    $SafeAttachmentPolicyParam=@{
       'Name' = "BaselineSafeAttachmentsPolicy";
       'Enable' = $true;
       'Action' =  "Block";
       'ActionOnError' = $true
     
    }

    New-SafeAttachmentPolicy @SafeAttachmentPolicyParam


    $SafeAttachRuleParam=@{
        'Name' = "Custom Safe Attachments baseline";
	    'SafeAttachmentPolicy' = "BaselineSafeAttachmentsPolicy";
	    'RecipientDomainIs' = $RecipientDomains;
	    'Enabled' = $true;
	    'Priority' = 0
    }

    New-SafeAttachmentRule @SafeAttachRuleParam


#endregion safe attachments policy


###################################################################################################
#region safe links policy

Write-Host -foregroundcolor $MessageColor "Creating Custom Safe Links baseline..."
	
    $SafeLinksPolicyParam=@{
       'Name' = "BaselineSafeLinksPolicy";
       'EnableSafeLinksForEmail' = $true;
       'EnableSafeLinksForTeams' = $true;
       'EnableSafeLinksForOffice' = $true;
       'ScanUrls' = $true;
       'DeliverMessageAfterScan' = $true;
       'DisableURLRewrite' = $false;
       'EnableForInternalSenders' = $true;
       'TrackClicks' = $true;
       'AllowClickThrough' =  $false
    }
    New-SafeLinksPolicy @SafeLinksPolicyParam 

    $SafeLinksRuleParam = @{
        'Name' = "Custom Safe Links baseline";
	    'SafeLinksPolicy' = "BaselineSafeLinksPolicy";
	    'RecipientDomainIs' = $RecipientDomains;
	    'Enabled' = $true;
	    'Priority' = 0
    }
    New-SafeLinksRule @SafeLinksRuleParam



write-host -foregroundcolor $MessageColor "EOP and MDO baseline configuration completed."

#endregion safe links policy

###################################################################################################
## THIS CONCLUDES THE SCRIPT
