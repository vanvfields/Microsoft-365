
<##################################################################################################
#
.SYNOPSIS
Disable MFA on all licensed user accounts (per-user MFA)
Use this when you want to switch from per-user MFA to Conditional Access for MFA
Conditional Access requires Azure AD Premium P1/P2, EM+S E3/E5 or M365B/E3/35

You have to connect to Azure AD using Connect-MsolService before running this script:
https://docs.microsoft.com/en-us/powershell/module/msonline/connect-msolservice?view=azureadps-1.0

Source of script: https://docs.microsoft.com/en-us/azure/active-directory/authentication/howto-mfa-userstates

.NOTES
    FileName:    Disable-MfaForLicensedUsers.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     02-01-2020
	Revised:     02-01-2020
    Version:     1.0
    
#>
###################################################################################################



## To disable only for a specific user:
## Set-MsolUser -UserPrincipalName user@domain.com -StrongAuthenticationRequirements @()
## To disable for all users:
## Get-Msoluser -all | Where-Object {$_.IsLicensed -eq $true} |  Set-MsolUser -StrongAuthenticationRequirements @()

## Find out who is registered for MFA:
## Get-Msoluser -all | Where-Object {$_.StrongAuthenticationMethods -like "*"} # Sets the MFA requirement state
function Set-MfaState {

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        $ObjectId,
        [Parameter(ValueFromPipelineByPropertyName=$True)]
        $UserPrincipalName,
        [ValidateSet("Disabled","Enabled","Enforced")]
        $State
    )

    Process {
        Write-Verbose ("Setting MFA state for user '{0}' to '{1}'." -f $ObjectId, $State)
        $Requirements = @()
        if ($State -ne "Disabled") {
            $Requirement =
                [Microsoft.Online.Administration.StrongAuthenticationRequirement]::new()
            $Requirement.RelyingParty = "*"
            $Requirement.State = $State
            $Requirements += $Requirement
        }

        Set-MsolUser -ObjectId $ObjectId -UserPrincipalName $UserPrincipalName `
                     -StrongAuthenticationRequirements $Requirements
    }
}

# Disable MFA for all users
Get-MsolUser -All | Set-MfaState -State Disabled# After this has been run, create a Conditional Access policy to replace per-user MFA:# Azure AD > Security > Conditional Access > New policy# Name it GRANT - MFA for users# Select Users and groups > All users (and Exclude any emergency access accounts, other exceptions)# Select Cloud apps and actions > All cloud apps# Do NOT select any Conditions (e.g. unless you want to exclude trusted locations)# Select Access Controls > Grant > Require Multi-factor authentication# Save and enable the policy