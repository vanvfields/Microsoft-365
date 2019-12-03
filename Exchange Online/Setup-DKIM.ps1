## Script by Alex Fields, ITProMentor.com
## Description:
## This script can be used to help configure DKIM for Office 365
## Use: .\Setup-DKIM.ps1 -DomainName "yourdomainhere.com"
## If you do not specify the DomainName variable, the script will prompt you for it
## Prerequisites:
## The tenant will require any Exchange Online plan
## Connect to Exchange Online via PowerShell using MFA:
## https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps
## WARNING: Script provided as-is. Author is not responsible for its use and application. Use at your own risk.


$MessageColor = "cyan"
$AssessmentColor = "magenta"

Param(
$DomainName
)

if($DomainName -eq $null -or $DomainName -eq ""){
    Write-Host 
    $DomainName = Read-Host -Prompt "Please specify the domain name"
    Write-Host
}


## This line will return the CNAME record values for the specified domain name (Points to):
Write-Host -ForegroundColor $MessageColor "Enter the (Points to) CNAME values in DNS for selector1._domainkey and selector2._domainkey:"
Write-Host 

Get-DkimSigningConfig $DomainName | fl Domain,*cname 

## Pause the script to allow time for entering DKIM records
Write-Host  
Read-Host -Prompt "Enter the DKIM records, have a coffee and wait for several minutes while DNS propogates, and then press Enter to continue..."
Write-Host 
## This line will attempt to activate the DKIM service (CNAME records must be already be populated in DNS)

##If DKIM exists but not already enabled, enable it
if (((get-dkimsigningconfig -identity $domainname -ErrorAction silent).enabled) -eq $False) {set-dkimsigningconfig -identity $domainname -enabled $true}
##If it doesn't exist - create new config
if (!(get-dkimsigningconfig -identity $domainname -erroraction silent)) {New-DkimSigningConfig -DomainName $DomainName -Enabled $true}
Write-Host 

## End of script

