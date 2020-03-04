
<##################################################################################################
#
.SYNOPSIS
Enable MFA on all licensed user accounts (per-user MFA)
This method works on all versions of Azure AD / Office 365
If you want to switch from per-user MFA to Conditional Access, see: Disable-MfaForLicensedUsers.ps1

You have to connect to Azure AD using Connect-MsolService before running this script:
https://docs.microsoft.com/en-us/powershell/module/msonline/connect-msolservice?view=azureadps-1.0

Source of script: https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates

.NOTES
    FileName:    Enable-MfaForLicensedUsers.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     02-01-2020
	Revised:     02-01-2020
    Version:     1.0
    
#>
###################################################################################################



$st = New-Object -TypeName Microsoft.Online.Administration.StrongAuthenticationRequirement
$st.RelyingParty = "*"
$st.State = "Enabled"
$sta = @($st)

Get-Msoluser -all | Where-Object {$_.IsLicensed -eq $true} | Set-MsolUser -StrongAuthenticationRequirements $sta

## To disable for a specific user:
## Set-MsolUser -UserPrincipalName user@domain.com -StrongAuthenticationRequirements @()
## To disable for all users:
## Get-Msoluser -all | Where-Object {$_.IsLicensed -eq $true} |  Set-MsolUser -StrongAuthenticationRequirements @()

## Find out who is registered for MFA:
## Get-Msoluser -all | Where-Object {$_.StrongAuthenticationMethods -like "*"} 