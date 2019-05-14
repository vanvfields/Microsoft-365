## This script will create two authentication policies which allow you to limit your attack surface:
## "Block basic auth" = will be set as the default policy and disables basic authentication
## "Allow basic auth" = another policy which can be used to enable IMAP, POP, SMTP, EWS, etc.

## Create an authentication policy to block basic authentication

New-AuthenticationPolicy -Name "Block Basic Auth"

## Set this policy as the organization default (any accounts not already assigned a policy):

Set-OrganizationConfig -DefaultAuthenticationPolicy "Block Basic Auth"

## Optional: Assign the policy to all users
## Get-User -ResultSize unlimited | Set-User -AuthenticationPolicy "Block Basic Auth"

## Create another authentication policy for allowing basic authentication (e.g. for service accounts)

New-AuthenticationPolicy "Allow Basic Auth Exceptions"  

## Use Set-AuthenticationPolicy to allow basic auth for one or more of these protocols:
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

## Example below enables basic auth for IMAP and EWS: 
## Set-AuthenticationPolicy "Allow Basic Auth Exceptions"  -AllowBasicAuthImap -AllowBasicAuthWebServices

## To assign the exception authentication policy on an account use:
## $ExceptionUser = username@domain.com
## Set-User -Identity $ExceptionUser -AuthenticationPolicy "Allow Basic Auth Exceptions"




