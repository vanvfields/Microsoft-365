<##################################################################################################
#
.SYNOPSIS

    WARNING: Make sure you understand what you're doing before running this script!

    1. This script will disable and revoke all refresh tokens for the specified user account
    2. You will also reset the password and optionally re-enable the account
    3. There is also an option to reset all admin passwords to random complex GUIDs (this requires the AzureADIncidentResponse module)
    4. You must connect to Azure AD before running this script, i.e.:
    
        Connect-AzureAD

.NOTES
    FileName:    Remediate-CompromisedUser.ps1
    Author:      Alex Fields 
    Created:     June 2021
	Revised:     June 2021
    
#>
###################################################################################################

Import-Module AzureAD

Write-Host "Do you want to disable an account or reset and re-enable an account?" -ForegroundColor Cyan
Write-Host "   1. Disable an account" -ForegroundColor Cyan
Write-Host "   2. Reset password and re-enable an account" -ForegroundColor Cyan
Write-Host "   3. Panic button: Reset all my admin accounts NOW!" -ForegroundColor Cyan

$Choice = Read-Host "Type your selection: 1, 2, or 3 and press Enter" 

if ($Choice -eq "1") {
    #Get the Username and ObjectID
    $UserEmail = Read-Host "Enter the user's primary email address (UPN)"
    $User = Get-AzureADUser -ObjectId $UserEmail

    #Disable the user's account and revoke all refresh tokens
    Write-Host 
    Write-Host "Disabling the user's account and revoking all refresh tokens..." -ForegroundColor Yellow
    Set-AzureADUser -ObjectId $UserEmail -AccountEnabled $false
    Revoke-AzureADUserAllRefreshToken -ObjectId $UserEmail

    #Disable the user's registered devices
    Write-Host
    Write-Host "Optional: Do you want to disable the user's registered devices?" -ForegroundColor Cyan
    Write-Host 
    $Answer = Read-Host "Type Y or N and press Enter."

    if ($Answer -eq "y") {
    Write-Host 
    Write-Host "Disabling the user's registered devices..." -ForegroundColor Yellow
    Get-AzureADUserRegisteredDevice -ObjectId $UserEmail | Set-AzureADDevice -AccountEnabled $false
    } else {
    Write-Host
    Write-Host "The user's registered devices will not be disabled." -ForegroundColor Cyan
    }
    }

if ($Choice -eq "2") {
    #Get the Username and ObjectID
    $UserEmail = Read-Host "Enter the user's primary email address (UPN)"
    $User = Get-AzureADUser -ObjectId $UserEmail

    #Change the password quickly to a random string (guid)
    Write-Host 
    Write-Host "Changing the user's password to a random string..." -ForegroundColor Yellow
    Write-Host
    Set-AzureADUserPassword -ObjectId $User.ObjectId -Password (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force)

    #Change the password a second time to a string of your choosing:
    Write-Host "You may now change the user's password to a value of your choosing." -ForegroundColor Yellow
    Write-Host 
    $GetPassword = Read-Host "Enter the new password"
    $Password = ConvertTo-SecureString $GetPassword -AsPlainText -Force
    Set-AzureADUserPassword -ObjectId $User.ObjectId -Password $Password -ForceChangePasswordNextLogin $true
    Write-Host

    $Answer = Read-Host "Do you want to re-enable the user's account now? Type Y or N and press ENTER"
    Write-Host

    if ($Answer -eq "y") {
    Set-AzureADUser -ObjectId $UserEmail -AccountEnabled $true
    Write-Host "User's account has been re-enabled. User must change password on next login." -ForegroundColor Yellow
    Write-Host
    } else
    {
    Write-Host "No further action will be taken. Account is still disabled." -ForegroundColor Yellow
    Write-Host
    }

    #Enable the user's registered devices
    Write-Host "Optional: Do you want to re-enable the user's registered devices?" -ForegroundColor Cyan
    Write-Host 
    $Answer = Read-Host "Type Y or N and press Enter."

    if ($Answer -eq "y") {
    Write-Host 
    Write-Host "Re-enabling the user's registered devices..." -ForegroundColor Yellow
    Get-AzureADUserRegisteredDevice -ObjectId $UserEmail | Set-AzureADDevice -AccountEnabled $true
    } else {
    Write-Host
    Write-Host "The user's registered devices will not be re-enabled." -ForegroundColor Cyan
    }


}

if ($Choice -eq "3") {
## Credit for this section goes to Daniel Chronlund's DCToolBox PowerShell module.
Write-Host
Write-Host "You must have the Azure AD Incident Response module installed to use this option." -ForegroundColor Cyan
Import-Module AzureADIncidentResponse -ErrorAction Stop 
Write-Host
Write-Host "Warning: You are about to reset all of your admin passwords to randomly generated GUIDs." -ForegroundColor Yellow
Write-Host "You may specify one other 'breakglass' account besides the current account to exclude from this process." -ForegroundColor Yellow
Write-Host "Are you sure you want to continue?" -ForegroundColor Yellow
$Answer = Read-Host "Type Y or N and press Enter to continue" 

if ($Answer -eq "y") {
#############################################################
## Get the tenant ID and connect to Azure AD
$Domain = Get-AzureADDomain | where-object IsDefault -eq $true
$TenantID = Get-AzureADIRTenantId -DomainName $Domain.Name
Connect-AzureADIR -TenantId $TenantID 
#############################################################

## Get the current user running PowerShell against Azure AD.
Write-Host 
Write-Host "Getting the current Azure AD user to exclude from the reset process." -ForegroundColor Cyan
$CurrentUser = (Get-AzureADCurrentSessionInfo).Account.Id

## Get the additional breakglass user:
Write-Host "Specify one additional Azure AD breakglass account below." -ForegroundColor Cyan
$BreakGlassUser = Read-Host "Enter the UPN of your breakglass account and press Enter to continue"

Write-Host 
Write-Host "Getting Azure AD privileged users" -ForegroundColor Cyan
$PrivUsers = Get-AzureADIRPrivilegedRoleAssignment -TenantId $TenantID | Where-Object RoleMemberObjectType -EQ User

## Loop through admins and set new complex passwords (using generated GUIDs).
foreach ($User in $PrivUsers) {
    if ($User.RoleMemberUPN -notin $BreakGlassUser -and $User.RoleMemberUPN -ne $CurrentUser) {
        Write-Host "Setting new password and revoking current tokens for $($User.RoleMemberUPN)..." -ForegroundColor Yellow
        Revoke-AzureADUserAllRefreshToken -ObjectId $User.RoleMemberUPN
        Set-AzureADUserPassword -ObjectId $User.RoleMemberUPN -Password (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force)
        Set-AzureADUserPassword -ObjectId $User.RoleMemberUPN -Password (ConvertTo-SecureString (New-Guid).Guid -AsPlainText -Force)
    } else {
        Write-Host "Skipping $($User.RoleMemberUPN)!" -ForegroundColor Cyan
    }
}
Write-Host
Write-Host "Admin passwords have been changed." -ForegroundColor Cyan
Write-Host "Note: You must manually reset the passwords again and help the users get back into their accounts." -ForegroundColor Yellow
Write-Host "All admin users are advised to check their MFA methods at https://aka.ms/mysecurityinfo after regaining access." -ForegroundColor Yellow
} else {
Write-Host 
Write-Host "Exiting script. No changes have been made." -ForegroundColor Cyan
}
}

Write-Host
Write-Host "Script complete" -ForegroundColor Cyan
Write-Host