<##################################################################################################
#
.SYNOPSIS
Run this script instead of Baseline-ExchangeOnline.ps1 or Baseline-M365BTenant.ps1 for further customization of your subscription

Connect to Exchange Online via PowerShell using MFA:
https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps

.NOTES
    FileName:    Advanced-TenantConfig.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     March 2020
	Revised:     August 2020
    Version:     1.1
    
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
## ANY SUBSCRIPTION
#################################################
$AuditLogConfig = Get-AdminAuditLogConfig
if ($AuditLogConfig.UnifiedAuditLogIngestionEnabled) {
    Write-Host 
    Write-Host -ForegroundColor $MessageColor "Unified Audit Log Search is already enabled"
} else {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "Unified Audit Log is not enabled"
    Write-Host 
    $Answer = Read-Host "Do you want to enable the Unified Audit Log now? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Unified Audit Log Search is now enabled" 
    } else {
        Write-Host 
        Write-Host -ForegroundColor $AssessmentColor "Unified Audit Log will not be enabled"
    }
 }

 

#################################################
## EDIT THE PER-MAILBOX AUDIT LOG AGE LIMIT 
## E5 or E5 Compliance SKU
#################################################
Write-Host 
$CurrentAge = (get-mailbox -resultsize unlimited).auditlogagelimit
Write-Host -ForegroundColor $AssessmentColor "Current audit log age limit (age and number of mailboxes):"
$CurrentAge | group | select name, count | ft
$Answer = Read-Host "Do you want to set the audit log age limit and enable all auditing actions on all mailboxes? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        Write-Host 
        $AuditLogAgeLimit = Read-Host "Enter the new audit log age limit in days; recommended value 365 or greater (or press Enter to continue without making changes)"
        if ($AuditLogAgeLimit -eq $null -or $AuditLogAgeLimit -eq "" -or $AuditLogAgeLimit -eq 'n' -or $AuditLogAgeLimit -eq 'no'){
            Write-Host
            Write-Host -ForegroundColor $AssessmentColor "The audit log age limit and audit actions will not be modified"
        } else {
            Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit $AuditLogAgeLimit
            Write-Host 
            Write-Host -ForegroundColor $MessageColor "The new audit log age limit has been set for all mailboxes"
            ## Enable all mailbox auditing actions
            Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditAdmin @{Add="Copy","Create","FolderBind","HardDelete","Move","MoveToDeletedItems","SendAs","SendOnBehalf","SoftDelete","Update","UpdateFolderPermissions","UpdateInboxRules","UpdateCalendarDelegation"}
            Get-Mailbox -ResultSize Unlimited | Set-Mailbox –AuditDelegate @{Add="Create","FolderBind","HardDelete","Move","MoveToDeletedItems","SendAs","SendOnBehalf","SoftDelete","Update","UpdateFolderPermissions","UpdateInboxRules"}
            Get-Mailbox -ResultSize Unlimited | Set-Mailbox –AuditOwner @{Add="Create","HardDelete","Move","Mailboxlogin","MoveToDeletedItems","SoftDelete","Update","UpdateFolderPermissions","UpdateInboxRules","UpdateCalendarDelegation"}
            Write-Host 
            Write-host -ForegroundColor $MessageColor "All auditing actions are now enabled on all mailboxes"
            } 

} else {
        Write-Host
        Write-Host -ForegroundColor $AssessmentColor "The audit log age limit and audit actions will not be modified"
        }



#################################################
## CHECK TO ENSURE MODERN AUTH IS ENABLED
## ANY SUBSCRIPTION
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
## BLOCK SMTP AUTHENTICATION
## ANY SUBSCRIPTION
#################################################

Write-Host 
$Answer = Read-Host "Do you want to disable SMTP client authentication on all mailboxes? Type Y or N and press Enter to continue"
if ($Answer -eq 'y'-or $Answer -eq 'yes') {
    Get-Mailbox -ResultSize Unlimited |Set-CASMailbox -SmtpClientAuthenticationDisabled $true
    Write-Host 
    Write-Host -ForegroundColor $MessageColor "SMTP client authentication has been disabled for all existing mailboxes"
} Else {
    Write Host 
    Write-Host -ForegroundColor $AssessmentColor "SMTP client authentication status has not been changed for any mailboxes"
}


#################################################
## BLOCK POP & IMAP
## ANY SUBSCRIPTION
#################################################
Write-Host 
$Answer = Read-Host "Do you want to disable POP and IMAP on all mailboxes? Type Y or N and press Enter to continue"
if ($Answer -eq 'y'-or $Answer -eq 'yes') {
    Get-CASMailbox -ResultSize Unlimited -Filter {ImapEnabled -eq $True} | Set-CASMailbox -ImapEnabled $False 
    Get-CASMailbox -ResultSize Unlimited -Filter {PopEnabled -eq $True} | Set-CASMailbox -PopEnabled $False 
    Get-CASMailboxPlan -Filter {ImapEnabled -eq $True}| Set-CASMailboxPlan -ImapEnabled $False
    Get-CASMailboxPlan -Filter {PopEnabled -eq $True}| Set-CASMailboxPlan -PopEnabled $False
    Write-Host 
    Write-Host -ForegroundColor $MessageColor "POP and IMAP have been disabled for all existing mailboxes and all future mailboxes"
} Else {
    Write Host 
    Write-Host -ForegroundColor $AssessmentColor "POP and IMAP settings have not been changed"
}



#################################################
## BLOCK BASIC AUTH
## ANY SUBSCRIPTION
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
## ANY SUBSCRIPTION
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
## SET RETAIN DELETED ITEMS TO 30 DAYS
## ANY SUBSCRIPTION
#################################################
Write-Host 
$CurrentRetention = (Get-Mailbox -ResultSize Unlimited).RetainDeletedItemsFor
Write-Host -ForegroundColor $AssessmentColor "Current retention limit (in days and number of mailboxes):"
$CurrentRetention | group | select name, count | ft
$Answer = Read-Host "Would you like to enforce the maximum allowed value of 30 days retention of deleted items for all mailboxes? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
    Get-Mailbox -ResultSize Unlimited | Set-Mailbox -RetainDeletedItemsFor 30
    Get-MailboxPlan | Set-MailboxPlan -RetainDeletedItemsFor 30
    Write-Host 
    Write-Host -ForegroundColor $MessageColor "Deleted items will be retained for the maximum of 30 days for all mailboxes"
    } else {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "The deleted items retention value has not been modified on any mailboxes"
    }



#################################################
## PREVENT CONSUMER STORAGE LOCATIONS
## ANY SUBSCRIPTION
#################################################
Write-Host
$OwaPolicy = Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default
if ($OwaPolicy.AdditionalStorageProvidersAvailable) {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "Outside storage locations like GoogleDrive and consumer OneDrive are currently enabled"
    Write-Host 
    $Answer = Read-Host "Do you want to disable outside storage locations like GoogleDrive or consumer OneDrive? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y'-or $Answer -eq 'yes') {
        Get-OwaMailboxPolicy | Set-OwaMailboxPolicy -AdditionalStorageProvidersAvailable $False
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Outside storage locations like GoogleDrive and consumer OneDrive are now disabled"
    } Else {
        Write-Host
        Write-Host -ForegroundColor $AssessmentColor "Outside storage locations like GoogleDrive and consumer OneDrive have not been disabled"
        }
} Else {
Write-Host
Write-Host -ForegroundColor $MessageColor "Outside storage locations like GoogleDrive and consumer OneDrive are already disabled"
}



#################################################
## ENABLE ENCRYPT IN OWA 
## SUBSCRIPTIONS: O365E3/E5, M365B/E3/E5, EM+SE3/E5
#################################################

$IRMConfig = Get-IRMConfiguration
if (!$IRMConfig.SimplifiedClientAccessEnabled) {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "The 'Encrypt' option is not available in OWA"
    Write-Host 
    $Answer = Read-Host "Enable the 'Encrypt' option in Outlook Web Access now? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        Set-IRMConfiguration -SimplifiedClientAccessEnabled $true
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "The 'Encrypt' option for Outlook on the web has been enabled"
        } else {
        Write-Host 
        Write-Host -ForegroundColor $AssessmentColor "The 'Encrypt' option for Outlook on the Web will not be enabled"
        }
    } else {
    Write-Host
    Write-Host -ForegroundColor $MessageColor "The 'Encrypt' option for Outlook on the web is already enabled"
}


#################################################
## ENCRYPT PDF ATTACHMENTS 
## SUBSCRIPTIONS: O365E3/E5, M365B/E3/E5, EM+SE3/E5
#################################################
if (!$IRMConfig.EnablePdfEncryption) {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "PDF attachments are not encrypted by OME"
    Write-Host 
    $Answer = Read-Host "Do you want to enable encryption of PDF attachments in OME protected messages? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        Set-IRMConfiguration -EnablePdfEncryption $true
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "PDF attachments will now be encrypted by OME"
        } else {
        Write-Host 
        Write-Host -ForegroundColor $AssessmentColor "PDF attachments will not be encrypted by OME"
        }
    } else {
    Write-Host
    Write-Host -ForegroundColor $MessageColor "PDF attachments are already being encrypted by OME"
}


#################################################
## AUTO-DECRYPT ENCRYPTED ATTACHMENTS 
## SUBSCRIPTIONS: O365E3/E5, M365B/E3/E5, EM+SE3/E5
#################################################
Write-Host
if (!$IRMConfig.DecryptAttachmentForEncryptOnly) {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "Attachments are encrypted by default upon download"
    Write-Host 
    $Answer = Read-Host "Do you want to enable attachments to be decrypted on download? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        Set-IRMConfiguration -DecryptAttachmentForEncryptOnly $true
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Attachments will now be automatically decrypted on download"
        } else {
        Write-Host 
        Write-Host -ForegroundColor $AssessmentColor "Attachments will remain encrypted on download"
        }
    } else {
    Write-Host
    Write-Host -ForegroundColor $MessageColor "Attachments are automatically decrypted on download"
}


#################################################
## JOURNAL REPORT DECRYPTION
## SUBSCRIPTIONS: O365E3/E5, M365B/E3/E5, EM+SE3/E5
#################################################
Write-Host
if (!$IRMConfig.JournalReportDecryptionEnabled) {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "Journal reports of OME protected messages are currently not decrypted"
    Write-Host 
    $Answer = Read-Host "Do you want to enable decrypted journal reports for OME protected messages? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        Set-IRMConfiguration -JournalReportDecryptionEnabled $true
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Journal reports will now be decrypted"
        } else {
        Write-Host 
        Write-Host -ForegroundColor $AssessmentColor "Journal reports will remain encrypted"
        }
    } else {
    Write-Host
    Write-Host -ForegroundColor $MessageColor "Journal reports of OME messages are already being decrypted, no changes have been made"
}




#################################################
## CONDITIONAL ACCESS - LIMITED WEB ACCESS
## SUBSCRIPTIONS: EM+S E3/E5 or M365B/E3/E5
#################################################

$OwaPolicy = Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default
if ($OwaPolicy.ConditionalAccessPolicy -eq 'Off') {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "Attachment download is currently enabled for unmanaged devices by the default OWA policy"
    Write-Host 
    $Answer = Read-Host "Do you want to disable attachment download on unmanaged devices? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y'-or $Answer -eq 'yes') {
        Get-OwaMailboxPolicy | Set-OwaMailboxPolicy -ConditionalAccessPolicy ReadOnly
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Attachment download on unmanaged devices is now disabled; please be sure to create a corresponding Conditional Access policy in Azure AD"
    } Else {
        Write-Host
        Write-Host -ForegroundColor $AssessmentColor "Attachment download on unamanged devices has not been disabled"
        }
} Else {
Write-Host
Write-Host -ForegroundColor $MessageColor "Attachment download on unmanaged devices is already disabled; please be sure there is a corresponding Conditional Access policy present in Azure AD"
}


## NOTE: You must implement this policy in conjunction with a corresponding Conditional Access policy in Azure AD
## To create the policy from Azure AD > Security > Conditional Access:
## Name the policy "Block web downloads on unmanaged devices"
## Target the appropriate user groups (or All users)
## Target Exchange Online
## Use the Session Control called "Enforce app restricitons"
## Save and enable the policy



#################################################
## ARCHIVE AND LEGAL HOLD
## SUBSCRIPTIONS: O365E3/E5, M365B/E3/E5
#################################################


## Use the following to modify the Default move to archive retention policy; example shown is for 3 years instead of 2 years
## Set-RetentionPolicyTag "Default 2 year move to archive" -Name "Default 3 year move to archive" -AgeLimitForRetention 1095


Write-Host
$Answer = Read-Host "Do you want to configure Archiving and Litigation Hold features? type Y or N and press Enter to Continue"
if($Answer -eq 'y' -or $Answer -eq 'yes') {

    ## Check whether the auto-expanding archive feature is enabled, and if not, enable it
    $OrgConfig = Get-OrganizationConfig 
     if ($OrgConfig.AutoExpandingArchiveEnabled) {
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "The Auto Expanding Archive feature is already enabled"
     } else {
        Set-OrganizationConfig -AutoExpandingArchive
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "The Auto Expanding Archive feature is now enabled"
     }

    ## Prompt whether or not to enable the Archive mailbox for all users
    Write-Host 
    $ArchiveAnswer = Read-Host "Do you want to enable the Archive mailbox for all user mailboxes? NOTE: Works against cloud-only accounts; does not work against AD synchronized accounts. Type Y or N and press Enter to continue"
    if ($ArchiveAnswer -eq 'y'-or $ArchiveAnswer -eq 'yes') {
        Get-Mailbox -ResultSize Unlimited -Filter {ArchiveStatus -Eq "None" -AND RecipientTypeDetails -eq "UserMailbox"} | Enable-Mailbox -Archive
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "The Archive mailbox has been enabled for all user mailboxes"
    } Else {
        Write-Host 
        Write-Host -ForegroundColor $AssessmentColor "The Archive mailbox will not be enabled for all user mailboxes"
    }

     ## Prompt whether or not to enable Litigation Hold for all mailboxes
    Write-Host 
    $LegalHoldAnswer = Read-Host "Do you want to enable Litigation Hold indefinitely for all mailboxes? Type Y or N and press Enter to continue"
    if ($LegalHoldAnswer -eq 'y' -or $LegalHoldAnswer -eq 'yes') {
        Get-Mailbox -ResultSize Unlimited -Filter {LitigationHoldEnabled -Eq "False" -AND RecipientTypeDetails -ne "DiscoveryMailbox"} | Set-Mailbox -LitigationHoldEnabled $True
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Litigation Hold has been enabled for all mailboxes"
    } Else {
        Write-Host 
        Write-Host -ForegroundColor $AssessmentColor "Litigation Hold will not be enabled for all mailboxes"
}

} Else {
Write-Host
Write-Host -ForegroundColor $AssessmentColor "Archiving and Litigation Hold will not be configured"
}


#################################################
## RESET THE DEFAULT ANTISPAM SETTINGS
## ANY SUBSCRIPTION
#################################################
Write-Host 
$Answer = Read-Host "Do you want to reset the default spam filter policy with the recommended baseline settings? Type Y or N and press Enter to continue"
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
## RESET OUTBOUND SPAM FILTER
## ANY SUBSCRIPTION
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
                'ActionWhenThresholdReached' = 'BlockUser';
                'NotifyOutboundSpam' = $true;
                'NotifyOutboundSpamRecipients' = $AlertAddress
            }
            Set-HostedOutboundSpamFilterPolicy @OutboundPolicyParam
            Write-Host
            Write-Host -ForegroundColor $MessageColor "The default outbound spam filter has been reset according to best practices"
        } else {
            $OutboundPolicyParam = @{
                "Identity" = 'Default';
                'RecipientLimitExternalPerHour' = 500;
                'RecipientLimitInternalPerHour' = 1000;
                'RecipientLimitPerDay' = 1000;
                'ActionWhenThresholdReached' = 'BlockUser';
                'NotifyOutboundSpam' = $true;
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


#################################################
## RESET DEFAULT ANTIMALWARE SETTINGS
## ANY SUBSCRIPTION
#################################################
Write-Host 

## Note: you can optionally EnableInternalSenderAdminNotifications by modifying the script block below.

$Answer = Read-Host "Do you want to reset the default malware filter policy with the recommended baseline settings? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
    Write-Host 
    #$AlertAddress= Read-Host "Enter the email address where you would like to recieve alerts about malware"
    ## Modify the default malware filter policy
    $MalwarePolicyParam = @{
        'Action' =  'DeleteMessage';
        'EnableFileFilter' =  $true;
        'ZapEnabled' = $true;
        #'EnableInternalSenderAdminNotifications' = $true;
        #'InternalSenderAdminAddress' =  $AlertAddress;
        'EnableInternalSenderNotifications' =  $false;
        'EnableExternalSenderNotifications' = $false
        
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
## CONFIGURE OFFICE 365 ATP SETTINGS
## SUBSCRIPTIONS: O365E5, M365B/E5 or O365ATP P1/P2
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
