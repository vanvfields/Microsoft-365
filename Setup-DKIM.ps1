##########################################################################################################################################################################################
## Description:
## This script can be used to help configure DKIM for Office 365
##
## Use: .\Setup-DKIM.ps1 -DomainName "yourdomainhere.com"
##
## Prerequisites:
## The tenant will require any Exchange Online plan
## Connect to Exchange Online via PowerShell using MFA:
## https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps
## 
## WARNING: Script provided as-is. Author is not responsible for its use and application. Use at your own risk.
##########################################################################################################################################################################################



Param(
$DomainName
)

## This line will return the CNAME record values for the specified domain name (Points to):
Write-Host "Enter the (Points to) CNAME values in DNS for selector1._domainkey and selector2._domainkey"

Get-DkimSigningConfig $DomainName | fl *cname 

## Pause the script to allow time for entering DKIM records 
Read-Host -Prompt "Enter the DKIM records, wait and then press Enter to continue..."

## This line will attempt to activate the DKIM service (CNAME records must be already be populated in DNS)

New-DkimSigningConfig -DomainName $DomainName -Enabled $true

