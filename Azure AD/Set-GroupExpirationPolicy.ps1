
<##################################################################################################
#
.SYNOPSIS
This script checks for and sets the Microsoft 365 Groups expiration policy.
If the policy already exists the script will exit without making changes.

You have to connect to Azure AD using Connect-AzureAD before running this script:
https://docs.microsoft.com/en-us/powershell/azure/active-directory/install-adv2?view=azureadps-2.0

Source of script:
https://docs.microsoft.com/en-us/azure/active-directory/enterprise-users/groups-lifecycle#powershell-examples

.NOTES
    FileName:    Set-GroupExpirationPolicy.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     April 2021
    Revised:     April 2021
    
#>
###################################################################################################


## Check for Group expiration policy
$CheckPolicy = Get-AzureADMSGroupLifecyclePolicy

if ($CheckPolicy -eq $null -or $CheckPolicy -eq "") {

Write-Host
Write-Host "No expiration policy found." -ForegroundColor Yellow
Write-Host
$EmailNotification = Read-Host "Enter the email address for orphaned Group notifications"
Write-Host
$GroupLifetime = Read-Host "Enter the desired lifetime for inactive Groups (in days)"
Write-Host
New-AzureADMSGroupLifecyclePolicy -GroupLifetimeInDays $GroupLifetime -ManagedGroupTypes All -AlternateNotificationEmails $EmailNotification
Write-Host
Write-Host "Script complete" -ForegroundColor Green
Write-Host
} 

else {

Write-Host
Write-Host "Group expiration policy already exists; no changes will be made." -ForegroundColor Red
Write-Host
$CheckPolicy
Write-Host
Write-Host "Script complete" -ForegroundColor Green
}

