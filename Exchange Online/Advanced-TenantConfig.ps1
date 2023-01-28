<##################################################################################################
#
.SYNOPSIS
Please run Install-EXOStandardProtection.ps1 before this script. Run this script for further customization of your tenant.

Connect to Exchange Online via PowerShell using MFA:
https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps

.NOTES
    FileName:    Advanced-TenantConfig.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     March 2020
	Revised:     October 2020
    Version:     2.0
    
#>
###################################################################################################
## NOTE: If the script errors out, you may need to set your execution policy.
## You may also need to run: Enable-OrganizationCustomization
## Please define these variables before running this script: 
$MessageColor = "Green"
$AssessmentColor = "Yellow"
###################################################################################################



#################################################
## ENABLE DEFAULT AUDITING AND UNIFIED AUDIT LOG SEARCH
## ANY SUBSCRIPTION
#################################################
$OrgConfig = Get-OrganizationConfig
if ($OrgConfig.AuditDisabled) {
 Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "Default mailbox auditing is not enabled"
    Write-Host 
    $Answer = Read-Host "Do you want to enable the default mailbox auditing now? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        Set-OrganizationConfig -AuditDisabled $false
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Default mailbox auditing is now enabled" 
    } else {
        Write-Host 
        Write-Host -ForegroundColor $AssessmentColor "Default mailbox auditing will not be enabled"
    }

} else {

    Write-Host 
    Write-Host -ForegroundColor $MessageColor "Default mailbox auditing is already enabled"
   
 }

$AuditLogConfig = Get-AdminAuditLogConfig
if ($AuditLogConfig.UnifiedAuditLogIngestionEnabled) {
    Write-Host 
    Write-Host -ForegroundColor $MessageColor "Unified Audit Log Search is already enabled"
} else {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "Unified Audit Log Search is not enabled"
    Write-Host 
    $Answer = Read-Host "Do you want to enable the Unified Audit Log Search now? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Unified Audit Log Search is now enabled" 
    } else {
        Write-Host 
        Write-Host -ForegroundColor $AssessmentColor "Unified Audit Log Search will not be enabled"
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
$Answer = Read-Host "Do you want to set the audit log age limit on all mailboxes? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        Write-Host 
        $AuditLogAgeLimit = Read-Host "Enter the new audit log age limit in days (or press Enter to continue without making changes)"
        if ($AuditLogAgeLimit -eq $null -or $AuditLogAgeLimit -eq "" -or $AuditLogAgeLimit -eq 'n' -or $AuditLogAgeLimit -eq 'no'){
            Write-Host
            Write-Host -ForegroundColor $AssessmentColor "The audit log age limit will not be modified"
        } else {
            Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit $AuditLogAgeLimit
            Write-Host 
            Write-Host -ForegroundColor $MessageColor "The new audit log age limit has been set for all mailboxes"
            } 

} else {
        Write-Host
        Write-Host -ForegroundColor $AssessmentColor "The audit log age limit will not be modified"
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
## SET RETAIN DELETED ITEMS TO 30 DAYS
## ANY SUBSCRIPTION
#################################################
Write-Host 
$CurrentRetention = (Get-Mailbox -ResultSize Unlimited).RetainDeletedItemsFor
Write-Host -ForegroundColor $AssessmentColor "Current retention limit (in days and number of mailboxes):"
$CurrentRetention | group | select name, count | ft
$Answer = Read-Host "Would you like to enforce the maximum allowed value of 30 days retention of deleted items for all mailboxes? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
    Get-Mailbox -ResultSize Unlimited | Set-Mailbox -RetainDeletedItemsFor 30 ## Existing mailboxes
    Get-MailboxPlan | Set-MailboxPlan -RetainDeletedItemsFor 30 ## All future mailboxes
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
## SUBSCRIPTIONS: EM+S E3/E5 or M365BP/E3/E5
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


## NOTE: You must implement this policy in conjunction with corresponding Conditional Access policies in Azure AD
## To create the policy from Entra > Azure AD > Protect & secure > Conditional Access
## Find the policy in templates called Use application enforced restrictions



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


###################################################################################################
## THIS CONCLUDES THE SCRIPT
