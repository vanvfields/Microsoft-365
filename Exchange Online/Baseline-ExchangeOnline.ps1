## Script by Alex Fields, ITProMentor.com
## Description:
## This script configures Exchange Online according to best practices as described in The Office 365 Email Security Checklist:
## https://www.itpromentor.com/email-security-checklist/
## Prerequisites:
## The tenant will need any Exchange Online plan
## To enable Archive or Litigation Hold requires Exchange Online Archiving or Exchange Online Plan 2
## Connect to Exchange Online via PowerShell using MFA:
## https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps
## WARNING: Script provided as-is. Author is not responsible for its use and application. Use at your own risk.
###################################################################################################################################################################################
## DEFINE THE VARIABLES FIRST:
$MessageColor = "Cyan"
$AssessmentColor = "Yellow"
################################################################################################################################################################################### 
## NOTE: If the script errors out, you may need to set your execution policy.
## You may also need to run: Enable-OrganizationCustomization
###################################################################################################################################################################################
## This section of the script enables the unified audit log, presents the option to modify the default audit log age limit, and enables all of the audit actions for all mailboxes

## Enable Unified Audit Log Search:
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

## Prompt for the audit log age limit on all mailboxes:
Write-Host 
$Answer = Read-Host "Do you want to set the audit log age limit and enable all auditing actions on all mailboxes? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        Write-Host 
        $AuditLogAgeLimit = Read-Host "Enter the new audit log age limit in days; recommended value 180 or greater (or press Enter to continue without making changes)"
        if ($AuditLogAgeLimit -eq $null -or $AuditLogAgeLimit -eq "" -or $AuditLogAgeLimit -eq 'n' -or $AuditLogAgeLimit -eq 'no'){
            Write-Host
            Write-Host -ForegroundColor $AssessmentColor "The audit log age limit and audit actions will not be modified"
        } else {
            Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit $AuditLogAgeLimit
            Write-Host 
            Write-Host -ForegroundColor $MessageColor "The new audit log age limit has been set for all mailboxes"
            ## Enable all mailbox auditing actions
            Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditAdmin @{Add="Copy","Create","FolderBind","HardDelete","MessageBind","Move","MoveToDeletedItems","SendAs","SendOnBehalf","SoftDelete","Update","UpdateFolderPermissions","UpdateInboxRules","UpdateCalendarDelegation"}
            Get-Mailbox -ResultSize Unlimited | Set-Mailbox –AuditDelegate @{Add="Create","FolderBind","HardDelete","Move","MoveToDeletedItems","SendAs","SendOnBehalf","SoftDelete","Update","UpdateFolderPermissions","UpdateInboxRules"}
            Get-Mailbox -ResultSize Unlimited | Set-Mailbox –AuditOwner @{Add="Create","HardDelete","Move","Mailboxlogin","MoveToDeletedItems","SoftDelete","Update","UpdateFolderPermissions","UpdateInboxRules","UpdateCalendarDelegation"}
            Write-Host 
            Write-host -ForegroundColor $MessageColor "All auditing actions are now enabled on all mailboxes"
            } 

} else {
        Write-Host
        Write-Host -ForegroundColor $AssessmentColor "The audit log age limit and audit actions will not be modified"
        }


###################################################################################################################################################################################
## This section of the script will set all mailboxes to keep deleted items for the maximum of 30 days:
Write-Host 
$Answer = Read-Host "By default Exchange Online retains deleted items for 14 days; would you like to enforce the maximum allowed value of 30 days for all mailboxes? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
    Get-Mailbox -ResultSize Unlimited | Set-Mailbox -RetainDeletedItemsFor 30
    Write-Host 
    Write-Host -ForegroundColor $MessageColor "Deleted items will be retained for the maximum of 30 days for all mailboxes"
    } else {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "The deleted items retention value has not been modified on any mailboxes"
    }

###################################################################################################################################################################################
## This section of the script will prevent winmail.dat attachments:
$DefaultRemoteDomain = Get-RemoteDomain Default
if ($DefaultRemoteDomain.TNEFEnabled) {
    Write-Host 
    $Answer = Read-Host "At present, some attachments may appear as winmail.dat and be unreadable in certain mail clients for example Apple mail; would you like to prevent this behavior? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        Set-RemoteDomain Default -TNEFEnabled $false 
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Attachments are now prevented from appearing as 'winmail.dat'"
        } else {
        Write-Host 
        Write-Host -ForegroundColor $AssessmentColor "Attachments will not be prevented from appearing as 'winmail.dat'"
        }
    } else {
    Write-Host
    Write-Host -ForegroundColor $MessageColor "Attachments are already prevented from appearing as 'winmail.dat'"
}

###################################################################################################################################################################################
## This section of the script will check whether the "Encrypt" button in Outlook on the Web is enabled, and enable it if not
## NOTE: Requires Azure Information Protection Plan 1

$IRMConfig = Get-IRMConfiguration
if (!$IRMConfig.SimplifiedClientAccessEnabled) {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "The 'Encrypt' button in Outlook Web Access is not enabled; NOTE: this feature requires Azure Info Protection Plan 1"
    Write-Host 
    $Answer = Read-Host "Do you want to enable the 'Encrypt' button in Outlook Web Access now? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        Set-IRMConfiguration -SimplifiedClientAccessEnabled $true
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "The 'Encrypt' button for Outlook on the web has been enabled"
        } else {
        Write-Host 
        Write-Host -ForegroundColor $AssessmentColor "The 'Encrypt' button for Outlook on the Web will not be enabled"
        }
    } else {
    Write-Host
    Write-Host -ForegroundColor $MessageColor "The 'Encrypt' button for Outlook on the web is already enabled"
}

###################################################################################################################################################################################
## This section of the script will present the option to disable saving to outside storage locations like GoogleDrive or consumer OneDrive
$OwaPolicy = Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default
if ($OwaPolicy.AdditionalStorageProvidersAvailable) {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "Connecting outside storage locations like GoogleDrive and consumer OneDrive are currently enabled by the default OWA policy"
    Write-Host 
    $Answer = Read-Host "Do you want to disable outside storage locations like GoogleDrive or consumer OneDrive in the default OWA policy? Type Y or N and press Enter to continue"
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

###################################################################################################################################################################################
## This section of the script will present the option to disable auto-forwarding to remote domains

$RemoteDomainDefault = Get-RemoteDomain Default 

if ($RemoteDomainDefault.AutoForwardEnabled) {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "Auto-forwarding to remote domains is currently allowed."
    Write-Host 
    $Answer = Read-Host "Do you want to block auto-forwarding to remote domains? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        Set-RemoteDomain Default -AutoForwardEnabled $false
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Auto-forwarding to remote domains is now disabled"
        } else {
        Write-Host
        Write-Host -ForegroundColor $AssessmentColor "Auto-forwarding to remote domains will not be disabled"}
} else {
    Write-Host 
    Write-Host -ForegroundColor $MessageColor "Auto-forwarding to remote domains is already disabled"
 }

 Write-Host 
 $Answer = Read-Host "Do you want to export to CSV a list of mailboxes that might be impacted by disabling auto-forward to remote domains? Type Y or N and press Enter to continue"
 if ($Answer -eq 'y' -or $Answer -eq 'yes') {
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


###################################################################################################################################################################################
## This section will reset the default spam filter policy with the recommended baseline settings

Write-Host 
$Answer = Read-Host "Do you want to reset the default spam filter policy with the recommended baseline settings? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
    $HostedContentPolicyParam = @{
        'bulkspamaction' =  'quarantine';
        'bulkthreshold' =  '7';
        'highconfidencespamaction' =  'quarantine';
        'inlinesafetytipsenabled' = $true;
        'markasspambulkmail' = 'on';
        'enablelanguageblocklist' = $false;
        'enableregionblocklist' = $false;
        'increasescorewithimagelinks' = 'off'
        'increasescorewithnumericips' = 'on'
        'increasescorewithredirecttootherport' = 'on'
        'increasescorewithbizorinfourls' = 'on';
        'markasspamemptymessages' ='on';
        'markasspamjavascriptinhtml' = 'on';
        'markasspamframesinhtml' = 'on';
        'markasspamobjecttagsinhtml' = 'on';
        'markasspamembedtagsinhtml' ='on';
        'markasspamformtagsinhtml' = 'on';
        'markasspamwebbugsinhtml' = 'off';
        'markasspamsensitivewordlist' = 'on';
        'markasspamspfrecordhardfail' = 'on';
        'markasspamfromaddressauthfail' = 'on';
        'markasspamndrbackscatter' = 'off';
        'phishspamaction' = 'quarantine';
        'spamaction' = 'quarantine';
        'zapenabled' = $true;
        'EnableEndUserSpamNotifications' = $true;
        'EndUserSpamNotificationFrequency' = 1;
        'QuarantineRetentionPeriod' = 15
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

###################################################################################################################################################################################
## This section will reset the default malware filter policy with the recommended baseline settings

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
        'EnableInternalSenderNotifications' =  $true;
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


###################################################################################################################################################################################
## This section will reset the default outbound spam filter policy with the recommended baseline settings

Write-Host 
$Answer = Read-Host "Do you want to reset the outbound spam filter policy with the recommended baseline settings? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        if ($AlertAddress -eq $null -or $AlertAddress -eq "") {
        $AlertAddress = Read-Host "Enter the email address where you would like to recieve alerts about outbound spam"
        $OutboundPolicyParam = @{
                "identity" = 'Default';
                'bccsuspiciousoutboundadditionalrecipients' =  $AlertAddress;
                'bccsuspiciousoutboundmail' = $true;
                'notifyoutboundspam' = $true;
                'NotifyOutboundSpamRecipients' = $AlertAddress
            }
            Set-HostedOutboundSpamFilterPolicy @OutboundPolicyParam
            Write-Host
            Write-Host -ForegroundColor $MessageColor "The default outbound spam filter has been reset according to best practices"
        } else {
            $OutboundPolicyParam = @{
                "identity" = 'Default';
                'bccsuspiciousoutboundadditionalrecipients' =  $AlertAddress;
                'bccsuspiciousoutboundmail' = $true;
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


###################################################################################################################################################################################
## This section of the script will present the option to deploy the baseline mobile device mailbox policy (OPTIONAL)

## Prompt whether to deploy the baseline mobile device mailbox policy (OPTIONAL):
Write-Host 
$Answer = Read-Host "Do you want to modify the default mobile device mailbox policy to require 4-digit passcode with encryption? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        $MobileDeviceParam= @{
           'PasswordEnabled' = $true;
           'AllowSimplePassword' =  $false;
           'PasswordRecoveryEnabled' = $true;
           'MinPasswordLength' = "4";
           'MaxPasswordFailedAttempts' = "15";
           'AllowExternalDeviceManagement' = $true;
           'AllowNonProvisionableDevices' = $false;
           'RequireDeviceEncryption' = $true;
           'MaxInactivityTimeLock' = "00:05:00";
           'IsDefault' = $true
        }
        Set-MobileDeviceMailboxPolicy -Identity Default @MobileDeviceParam
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "The default mobile device mailbox policy has been modified"
} else {
Write-Host 
Write-Host -ForegroundColor $AssessmentColor "Default mobile device mailbox policy will not be modified; consider using Intune to setup MDM or MAM instead"
}

###################################################################################################################################################################################
## This section will check whether the auto-expanding archive feature is enabled, and if not, enable it; requires Exchange Online Plan 2 or the Exchange Online Archiving add-on

Write-Host
$Answer = Read-Host "Do you want to configure Archiving and Litigation Hold features? NOTE: Requires Exchange Online Plan 2 or Exchange Online Archiving add-on; type Y or N and press Enter to Continue"
if($Answer -eq 'y' -or $Answer -eq 'yes') {

    ## Enable the auto expanding archive feature
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
    $LegalHoldAnswer = Read-Host "Do you want to enable Litigation Hold for all mailboxes? Type Y or N and press Enter to continue"
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


###################################################################################################################################################################################
## This section of the script will present the option to disable IMAP and POP on all existing mailboxes

## Prompt whether or not to disable POP and IMAP on all mailboxes
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


###################################################################################################################################################################################
## This section of the script enables modern authentication and provides the option to disable basic authentication

## Check whether modern authentication is enabled for Exchange Online, and if not, enable it:
$OrgConfig = Get-OrganizationConfig 
 if ($OrgConfig.OAuth2ClientProfileEnabled) {
     Write-Host 
     Write-Host -ForegroundColor $MessageColor "Modern Authentication for Exchange Online is already enabled"
 } else {
     Write-Host
     Write-Host -ForegroundColor $AssessmentColor "Modern Authentication for Exchange online is not enabled"
     Write-Host 
     $Answer = Read-Host "Do you want to enable Modern Authentication for Exchange Online now? Type Y or N and press Enter to continue"
     if ($Answer -eq 'y' -or $Answer -eq 'yes') {
         Set-OrganizationConfig -OAuth2ClientProfileEnabled $true
         Write-Host 
         Write-Host -ForegroundColor $MessageColor "Modern Authentication is now enabled"
         } Else {
         Write-Host
         Write-Host -ForegroundColor $AssessmentColor "Modern Authentication will not be enabled"
         }
 }

## Create an authentication policy to block basic authentication
$PolicyName = "Block Basic Auth"
$CheckPolicy = Get-AuthenticationPolicy | Where-Object {$_.Name -contains $PolicyName}
if (!$CheckPolicy) {
    New-AuthenticationPolicy -Name $PolicyName
    Write-Host 
    Write-Host -ForegroundColor $MessageColor "Block Basic Auth policy has been created"
    } else {
    Write-Host 
    Write-Host -ForegroundColor $MessageColor "Block Basic Auth policy already exists"
}

## Prompt whether or not to make Block Basic Auth the default policy for the organization
Write-Host 
$AuthAnswer = Read-Host "Do you want to make 'Block Basic Auth' the default authentication policy for the organization? WARNING: This action will prevent older clients from connecting to Exchange Online. Type Y or N and press Enter to continue"
 if ($AuthAnswer -eq 'y'-or $AuthAnswer -eq 'yes') {
    Set-OrganizationConfig -DefaultAuthenticationPolicy "Block Basic Auth"
    Write-Host 
    Write-Host -ForegroundColor $MessageColor "Block Basic Auth has been set as the default authentication policy for the organization; to create exceptions to this policy, please see the comments included at the end of this script"
    } else {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "Block Basic Auth will not be set as the default policy. Please assign this policy to users individually using: Set-User -Identity <username> -AuthenticationPolicy 'Block Basic Auth' "
    Write-Host 
}

## OPTIONAL: Assign the 'Block Basic Auth' policy explicitly to all users
## Get-User -ResultSize unlimited | Set-User -AuthenticationPolicy "Block Basic Auth"

## OPTIONAL: 
## Create additional authentication policies for allowing exceptions for basic authentication (e.g. for service accounts)

## EXAMPLE:
## New-AuthenticationPolicy "Allow Basic Auth Exception"

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
## Set-AuthenticationPolicy "Allow Basic Auth Exceptions"  -AllowBasicAuthImap

## To assign the exception policy to an account use:
## $ExceptionUser = username@domain.com
## Set-User -Identity $ExceptionUser -AuthenticationPolicy "Allow Basic Auth Exceptions"

###################################################################################################################################################################################
## This concludes the script
