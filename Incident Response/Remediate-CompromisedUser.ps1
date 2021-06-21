<##################################################################################################
#
.SYNOPSIS
    1. This script will disable and revoke all refresh tokens for the specified user account
    2. You will also reset the password and optionally re-enable the account
    3. You must connect to Azure AD before running this script, i.e.:
    
        Connect-AzureAD

.NOTES
    FileName:    Remediate-CompromisedUser.ps1
    Author:      Alex Fields 
    Created:     June 2021
	Revised:     June 2021
    
#>
###################################################################################################

Import-Module AzureAD

#Get the Username and ObjectID
$UserEmail = Read-Host "Enter the user's primary email address (UPN)"
$User = Get-AzureADUser -ObjectId $UserEmail

Write-Host "Do you want to disable an account or reset and re-enable an account?" -ForegroundColor Cyan
Write-Host "   1. Disable an account" -ForegroundColor Cyan
Write-Host "   2. Reset password and re-enable an account" -ForegroundColor Cyan
$Choice = Read-Host "Type 1 or 2 and press Enter" 

if ($Choice -eq "1") {
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

Write-Host