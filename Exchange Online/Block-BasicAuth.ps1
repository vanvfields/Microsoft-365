## Description:
## This script can be used to enable modern auth and also block basic authentication in Exchange Online
## WARNING: This script will block older clients from connecting to Exchange Online
## Prerequisites:
## The tenant will require any Exchange Online plan
## Connect to Exchange Online via PowerShell using MFA:
## https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps
## WARNING: Script provided as-is. Author is not responsible for its use and application. Use at your own risk.

$MessageColor = "cyan"
$AssessmentColor = "magenta"

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

## End of script