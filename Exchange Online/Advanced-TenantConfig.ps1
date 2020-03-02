<##################################################################################################
#
.SYNOPSIS
Run this script after Baseline-ExchangeOnline.ps1 or Baseline-M365BTenant.ps1 for further customization of your subscription

Connect to Exchange Online via PowerShell using MFA:
https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps

.NOTES
    FileName:    Advanced-TenantConfig.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     03-01.2020
	Revised:     03-01-2020
    Version:     1.0
    
#>
###################################################################################################
## NOTE: If the script errors out, you may need to set your execution policy.
## You may also need to run: Enable-OrganizationCustomization
## Please define these variables before running this script: 
$MessageColor = "Green"
$AssessmentColor = "Yellow"
###################################################################################################

#################################################
## EDIT THE AUDIT LOG AGE LIMIT
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
## SET RETAIN DELETED ITEMS TO 30 DAYS
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
## ENABLE ENCRYPT IN OWA 
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
## PREVENT CONSUMER STORAGE LOCATIONS
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
## BLOCK POP & IMAP
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

Write-Host


#################################################
## BLOCK SMTP
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

Write-Host



#################################################
## BLOCK BASIC AUTH
#################################################
if ($OrgConfig.DefaultAuthenticationPolicy -eq $null -or $OrgConfig.DefaultAuthenticationPolicy -eq "") {
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "There is no default authentication policy in place; you do not have to set an authentication policy if you block legacy authentication using Conditional access or Security defaults instead"
        $AuthAnswer = Read-Host "Would you like to block basic authentication using an authentication policy? Type Y or N and press Enter to continue"
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
    Write-Host -ForegroundColor $AssessmentColor "There is already a default authentication policy in place. No changes will be made. To change the authentication policy for individual users, please see the comments at the end of this script. Your default authentication policy is:"
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
## CONDITIONAL ACCESS - LIMITED WEB ACCESS
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
