## Script by Alex Fields, ITProMentor.com
## Description:
## This script can be used to disable POP and IMAP organization-wide
## Prerequisites:
## The tenant will require any Exchange Online plan
## Connect to Exchange Online via PowerShell using MFA:
## https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps
## WARNING: Script provided as-is. Author is not responsible for its use and application. Use at your own risk.

$MessageColor = "cyan"
$AssessmentColor = "magenta"

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

Write-Host

## End of script