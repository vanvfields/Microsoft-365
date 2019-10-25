## Script by Alex Fields, ITProMentor.com
## Use this script to block sign-in for shared mailboxes
## You must connect to Exchange Online and Azure AD using Connect-EXOPSSession and Connect-MsolService before running this script
## https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps
## https://docs.microsoft.com/en-us/powershell/module/msonline/connect-msolservice?view=azureadps-1.0
## WARNING: Script provided as-is. Author is not responsible for its use and application. Use at your own risk.


$SharedMailboxes = Get-Mailbox -ResultSize Unlimited -Filter {RecipientTypeDetails -Eq "SharedMailbox"}

Foreach ($user in $SharedMailboxes) {

Set-MsolUser -UserPrincipalName $user.UserPrincipalName -BlockCredential $true 

}


## End of script



