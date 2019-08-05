## Script by Alex Fields, ITProMentor.com
## Description:
## This script can be used to enable the archive mailbox, and/or litigation hold
## Prerequisites:
## Exchange Online plan 2 or the Exchange Online Archiving add-on 
## Connect to Exchange Online via PowerShell using MFA:
## https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps
## WARNING: Script provided as-is. Author is not responsible for its use and application. Use at your own risk.

$MessageColor = "cyan"
$AssessmentColor = "magenta"


Write-Host
$Answer = Read-Host "Do you want to configure Archiving and Litigation Hold features? NOTE: Requires Exchange Online Plan 2 or Exchange Online Archiving add-on; type Y or N and press Enter to Continue"
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

