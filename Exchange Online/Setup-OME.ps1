<##################################################################################################
#
.SYNOPSIS
Customize aspects of the OME encryption experience.

Connect to Exchange Online via PowerShell using MFA:
https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps

.NOTES
    FileName:    Setup-OME.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     April 2021
	Revised:     April 2021

    
#>
###################################################################################################
## NOTE: If the script errors out, you may need to set your execution policy.
## You may also need to run: Enable-OrganizationCustomization
## Please define these variables before running this script: 
$MessageColor = "Green"
$AssessmentColor = "Yellow"
###################################################################################################


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


