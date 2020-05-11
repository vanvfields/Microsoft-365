<##################################################################################################
#
.SYNOPSIS
This script configures a new Office 365 tenant with Basline Exchange Online settings.
This script does not include Office 365 ATP settings, see Baseline-365ATP.ps1
Baseline-M365BTenant.ps1 includes everything from this script and the ATP script

See Advanced-TenantConfig.ps1 for other customizations  

Connect to Exchange Online via PowerShell using MFA:
https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps

.NOTES
    FileName:    Baseline-ExchangeOnline.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     11-18-2019
	Revised:     03-01-2020
    Version:     3.0
    
#>
###################################################################################################
## NOTE: If the script errors out, you may need to set your execution policy.
## You may also need to run: Enable-OrganizationCustomization
## Please define these variables before running this script: 
$MessageColor = "Green"
$AssessmentColor = "Yellow"
###################################################################################################

#################################################
## ENABLE UNIFIED AUDIT LOG SEARCH
#################################################
$AuditLogConfig = Get-AdminAuditLogConfig
if ($AuditLogConfig.UnifiedAuditLogIngestionEnabled) {
    Write-Host 
    Write-Host -ForegroundColor $MessageColor "Unified Audit Log Search is already enabled"
} else {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "Unified Audit Log is not enabled"
    Write-Host 
    $Answer = Read-Host "Do you want to enable mailbox auditing to the Unified Audit Log now? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
        Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Unified Audit Log Search is now enabled with mailbox auditing enabled" 
    } else {
        Write-Host 
        Write-Host -ForegroundColor $AssessmentColor "Unified Audit Log will not be enabled"
    }
 }



 
#################################################
## CHECK TO ENSURE MODERN AUTH IS ENABLED
#################################################
$OrgConfig = Get-OrganizationConfig 
 if ($OrgConfig.OAuth2ClientProfileEnabled) {
     Write-Host 
     Write-Host -ForegroundColor $MessageColor "Modern Authentication for Exchange Online is already enabled"
 } else {
    Write-Host
    Write-Host -ForegroundColor $AssessmentColor "Modern Authentication for Exchange online is not enabled, enabling"
    Write-Host 
    Set-OrganizationConfig -OAuth2ClientProfileEnabled $true
    Write-Host 
    Write-Host -ForegroundColor $MessageColor "Modern Authentication is now enabled"

 }


#################################################
## BLOCK BASIC AUTH
#################################################
if ($OrgConfig.DefaultAuthenticationPolicy -eq $null -or $OrgConfig.DefaultAuthenticationPolicy -eq "") {
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "There is no default authentication policy in place"
        Write-Host -ForegroundColor $MessageColor "NOTE: You don't need one if you are using Security Defaults or Conditional Access"
        $AuthAnswer = Read-Host "Would you like to block legacy authentication using an authentication policy? Type Y or N and press Enter to continue"
        if ($AuthAnswer -eq "y" -or $AuthAnswer -eq "yes") {
                $PolicyName = "Block Basic Auth"
                $CheckPolicy = Get-AuthenticationPolicy | Where-Object {$_.Name -contains $PolicyName}
                if (!$CheckPolicy) {
                    New-AuthenticationPolicy -Name $PolicyName
                    Write-Host
                    Write-Host -ForegroundColor $MessageColor "Block Basic Auth policy has been created"
                    } else {
                    Write-Host
                    Write-Host  -ForegroundColor $MessageColor "Block Basic Auth policy already exists"
                    }
                Set-OrganizationConfig -DefaultAuthenticationPolicy $PolicyName
                Write-Host
                Write-Host -ForegroundColor $MessageColor "Block Basic Auth has been set as the default authentication policy for the organization; to create exceptions to this policy, please see the comments included at the end of this script."
                Write-Host
        } else {
                Write-Host
                Write-Host -ForegroundColor $AssessmentColor "Block Basic Auth will not be set as the default authentication policy."
                Write-Host
                }
    } else {
    Write-Host
    Write-Host -ForegroundColor $AssessmentColor "There is already a default policy in place. No changes will be made. Your default authentication policy is:"
    Write-Host
    $OrgConfig.DefaultAuthenticationPolicy
    Write-Host 
    }



## OPTIONAL: 
## Create and assign the 'Block Basic Auth' policy explicitly to all users:
## New-AuthenticationPolicy "Block Basic Auth"
## Get-User -ResultSize unlimited | Set-User -AuthenticationPolicy "Block Basic Auth"

## OPTIONAL: 
## Create additional authentication policies for allowing exceptions for basic authentication (e.g. for service accounts)

## EXAMPLE:
## New-AuthenticationPolicy "Allow Basic Auth for <ServiceName>"

## Then use Set-AuthenticationPolicy to allow basic auth for one or more of these protocols:
## AllowBasicAuthActiveSync           
## AllowBasicAuthAutodiscover        
## AllowBasicAuthImap                 
## AllowBasicAuthMapi                 
## AllowBasicAuthOfflineAddressBook   
## AllowBasicAuthOutlookService       
## AllowBasicAuthPop                  
## AllowBasicAuthReportingWebServices 
## AllowBasicAuthRest                 
## AllowBasicAuthRpc                  
## AllowBasicAuthSmtp                 
## AllowBasicAuthWebServices          
## AllowBasicAuthPowershell           

## Example below enables basic auth for IMAP: 
## Set-AuthenticationPolicy "Allow Basic Auth for IMAP"  -AllowBasicAuthImap

## To assign the exception policy to an account use:
## $ExceptionUser = username@domain.com
## Set-User -Identity $ExceptionUser -AuthenticationPolicy "Allow Basic Auth Exceptions"


     
#################################################
## DISABLE AUTOMATIC FORWARDING 
#################################################
$RemoteDomainDefault = Get-RemoteDomain Default 
if ($RemoteDomainDefault.AutoForwardEnabled) {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "Auto-forwarding to remote domains is currently allowed."
    Write-Host 
    $Answer = Read-Host "Do you want to block auto-forwarding to remote domains? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        ## DENY AUTOFORWARD ON THE DEFAULT REMOTE DOMAIN (*) 
        Set-RemoteDomain Default -AutoForwardEnabled $false
        ## ALSO DENY AUTO-FORWARDING FROM MAILBOX RULES VIA TRANSPORT RULE WITH REJECTION MESSAGE
        $TransportRuleName = "External Forward Block"
        $rejectMessageText = "Mail forwarding to external domains is not permitted. If you have questions, please contact support."
        $ExternalForwardRule = Get-TransportRule | Where-Object {$_.Identity -contains $TransportRuleName}
        if (!$ExternalForwardRule) {
        Write-Output "External Forward Block rule not found, creating rule..."
        New-TransportRule -name $TransportRuleName -Priority 1 -SentToScope NotInOrganization -MessageTypeMatches AutoForward -RejectMessageEnhancedStatusCode 5.7.1 -RejectMessageReasonText $rejectMessageText
        } else {Write-Output "External forward block rule already exists."} 
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Auto-forwarding to remote domains is now disabled"        
        } else {
        Write-Host
        Write-Host -ForegroundColor $AssessmentColor "Auto-forwarding to remote domains will not be disabled"
        }
  
    ## EXPORT LIST OF FORWARDERS TO CSV
    Write-Host    
    $Answer2 = Read-Host "Do you want to export to CSV a list of mailboxes that might be impacted by disabling auto-forward to remote domains? Type Y or N and press Enter to continue"
    if ($Answer2 -eq 'y' -or $Answer2 -eq 'yes') {
        ## Collect existing mailbox forwarding into CSV files at C:\temp\DomainName-MailboxForwarding.csv and DomainName-InboxRules.csv
        Write-Host 
        Write-Host -ForegroundColor $AssessmentColor "Exporting known mailbox forwarders and inbox rules that auto-forward"
        $DefaultDomainName = Get-AcceptedDomain | Where-Object Default -EQ True
        Get-Mailbox -ResultSize Unlimited -Filter {(RecipientTypeDetails -ne "DiscoveryMailbox") -and ((ForwardingSmtpAddress -ne $null) -or (ForwardingAddress -ne $null))} | Select Identity,ForwardingSmtpAddress,ForwardingAddress | Export-Csv c:\temp\$DefaultDomainName-MailboxForwarding.csv -append
        foreach ($a in (Get-Mailbox -ResultSize Unlimited |select PrimarySMTPAddress)) {Get-InboxRule -Mailbox $a.PrimarySMTPAddress | ?{($_.ForwardTo -ne $null) -or ($_.ForwardAsAttachmentTo -ne $null) -or ($_.DeleteMessage -eq $true) -or ($_.RedirectTo -ne $null)} |select Name,Identity,ForwardTo,ForwardAsAttachmentTo, RedirectTo, DeleteMessage | Export-Csv c:\temp\$DefaultDomainName-InboxRules.csv -append }
        Write-Host 
        Write-Host -ForegroundColor $AssessmentColor "After running this script, check the CSV files under C:\temp for a list of mail users who may be affected by disabling the ability to auto-forward messages to external domains"
        } else {
        Write-Host 
        Write-Host  -ForegroundColor $MessageColor "Run the script again if you wish to export auto-forwarding mailboxes and inbox rules"
        }
} else {
    Write-Host 
    Write-Host -ForegroundColor $MessageColor "Auto-forwarding to remote domains is already disabled"
 }
 

#################################################
## RESET THE DEFAULT ANTISPAM SETTINGS
#################################################
Write-Host 
$Answer = Read-Host "Do you want to reset the default spam filter policy with the recommended baseline settings? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
    $HostedContentPolicyParam = @{
        'bulkspamaction' =  'MoveToJMF';
        'bulkthreshold' =  '6';
        'highconfidencespamaction' =  'quarantine';
        'inlinesafetytipsenabled' = $true;
        'markasspambulkmail' = 'on';
        'enablelanguageblocklist' = $false;
        'enableregionblocklist' = $false;
        'increasescorewithimagelinks' = 'off'
        'increasescorewithnumericips' = 'off'
        'increasescorewithredirecttootherport' = 'off'
        'increasescorewithbizorinfourls' = 'off';
        'markasspamemptymessages' ='off';
        'markasspamjavascriptinhtml' = 'off';
        'markasspamframesinhtml' = 'off';
        'markasspamobjecttagsinhtml' = 'off';
        'markasspamembedtagsinhtml' ='off';
        'markasspamformtagsinhtml' = 'off';
        'markasspamwebbugsinhtml' = 'off';
        'markasspamsensitivewordlist' = 'off';
        'markasspamspfrecordhardfail' = 'off';
        'markasspamfromaddressauthfail' = 'off';
        'markasspamndrbackscatter' = 'off';
        'phishspamaction' = 'quarantine';
        'spamaction' = 'MoveToJMF';
        'zapenabled' = $true;
        'EnableEndUserSpamNotifications' = $true;
        'EndUserSpamNotificationFrequency' = 1;
        'QuarantineRetentionPeriod' = 30
    }
    Set-HostedContentFilterPolicy Default @HostedContentPolicyParam -MakeDefault
    Write-Host
    Write-Host -ForegroundColor $MessageColor "The default spam filter policy has been reset according to best practices"
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
    Write-Host -ForegroundColor $AssessmentColor "The default anti-spam policy has not been modified"
    }


#################################################
## RESET DEFAULT ANTIMALWARE SETTINGS
#################################################
Write-Host 
$Answer = Read-Host "Do you want to reset the default malware filter policy with the recommended baseline settings? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
    Write-Host 
    $AlertAddress= Read-Host "Enter the email address where you would like to recieve alerts about malware and outbound spam"
    ## Modify the default malware filter policy
    $MalwarePolicyParam = @{
        'Action' =  'DeleteMessage';
        'EnableFileFilter' =  $true;
        'EnableInternalSenderAdminNotifications' = $true;
        'InternalSenderAdminAddress' =  $AlertAddress;
        'EnableInternalSenderNotifications' =  $false;
        'EnableExternalSenderNotifications' = $false;
        'Zap' = $true
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


#################################################
## RESET OUTBOUND SPAM FILTER
#################################################
Write-Host 
$Answer = Read-Host "Do you want to reset the outbound spam filter policy with the recommended baseline settings? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        if ($AlertAddress -eq $null -or $AlertAddress -eq "") {
        $AlertAddress = Read-Host "Enter the email address where you would like to recieve alerts about outbound spam"
        $OutboundPolicyParam = @{
                "Identity" = 'Default';
                'RecipientLimitExternalPerHour' = 500;
                'RecipientLimitInternalPerHour' = 1000;
                'RecipientLimitPerDay' = 1000;
                'ActionWhenThresholdReached' = BlockUser;
                'notifyoutboundspam' = $true;
                'NotifyOutboundSpamRecipients' = $AlertAddress
            }
            Set-HostedOutboundSpamFilterPolicy @OutboundPolicyParam
            Write-Host
            Write-Host -ForegroundColor $MessageColor "The default outbound spam filter has been reset according to best practices"
        } else {
            $OutboundPolicyParam = @{
                "identity" = 'Default';
                'notifyoutboundspam' = $true;
                'NotifyOutboundSpamRecipients' = $AlertAddress
            }
            Set-HostedOutboundSpamFilterPolicy @OutboundPolicyParam
            Write-Host
            Write-Host -ForegroundColor $MessageColor "The default outbound spam filter has been reset according to best practices"
            }
} else {
    Write-Host
    Write-Host -ForegroundColor $AssessmentColor "The outbound spam filter policy has not been modified"
}


###################################################################################################
## THIS CONCLUDES THE SCRIPT



