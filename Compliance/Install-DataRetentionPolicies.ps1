<# 
.SYNOPSIS
    Use this script to deploy a blanket retention policy from the Data Protection Starter Kit

.NOTES
    1. You must have the ExchangeOnlineManagement PowerShell module installed in order to run this script.
    2. Connect to the Security & Compliance center using Connect-IPPSSession

.DETAILS
    FileName:    Install-DataRetentionPolicies.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     September 2021
    Updated:     September 2021

#>


#Connect-IPPSSession

Write-Host
$AskDate = Read-Host "Should the retention policies be based on (1) Date created or (2) Date last modified? Type 1 or 2 and press Enter"

if ($AskDate -eq "1") {
$ExpirationDateOption = "CreationAgeInDays"
Write-Host
Write-Host "Warning: Retention policies created by this script will be based on date created!" -ForegroundColor Yellow
} elseif ($AskDate -eq "2") {
$ExpirationDateOption = "ModificationAgeInDays"
Write-Host
Write-Host "Warning: Retention policies created by this script will be based on date last modified!" -ForegroundColor Yellow
} else {
Write-Host
Write-Host "Input not recognized. Defaulting to date last modified." -ForegroundColor Yellow
$ExpirationDateOption = "ModificationAgeInDays"
Write-Host
Write-Host "Warning: Retention policies created by this script will be based on date last modified!" -ForegroundColor Yellow
}


Write-Host
$Answer = Read-Host "Do you want to deploy the default User retention policy for Email and OneDrive data? Type Y or N and press Enter"

if ($Answer -eq "y") {
Write-Host
$Years = Read-Host "Retain Email and OneDrive data for how many years? Enter a value between 1 and 10 and press Enter"
$Duration = 365*$Years

Write-Host
$AskAction = Read-Host "Do you want to (1) Keep, (2) Keep and Delete, or (3) just Delete? Enter 1, 2, or 3 and press Enter"
if ($AskAction -eq "1") {

New-RetentionCompliancePolicy -Name "User data retention policy" -ExchangeLocation All -OneDriveLocation All -Enabled $false
New-RetentionComplianceRule -Name "User data retention rule" -RetentionDuration $Duration -RetentionDurationDisplayHint Years -ExpirationDateOption $ExpirationDateOption -RetentionComplianceAction Keep -Policy "User data retention policy"

} elseif ($AskAction -eq "2") {

New-RetentionCompliancePolicy -Name "User data retention policy" -ExchangeLocation All -OneDriveLocation All -Enabled $false
New-RetentionComplianceRule -Name "User data retention rule" -RetentionDuration $Duration -RetentionDurationDisplayHint Years -ExpirationDateOption $ExpirationDateOption -RetentionComplianceAction KeepAndDelete -Policy "User data retention policy"

} elseif ($AskAction -eq "3") {

New-RetentionCompliancePolicy -Name "User data deletion policy" -ExchangeLocation All -OneDriveLocation All -Enabled $false
New-RetentionComplianceRule -Name "User data deletion rule" -RetentionDuration $Duration -RetentionDurationDisplayHint Years -ExpirationDateOption $ExpirationDateOption -RetentionComplianceAction Delete -Policy "User data deletion policy"

} else {
Write-Host
Write-Host "Invalid input, no policy will be created." -ForegroundColor Yellow

}


} else {
Write-Host
Write-Host "The default User data retention policy will not be deployed." -ForegroundColor Yellow

}

Write-Host
$Answer = Read-Host "Do you want to deploy the default Company data retention policy? Type Y or N and press Enter"

if ($Answer -eq "y") {
Write-Host
$Years = Read-Host "Retain SharePoint and Groups data for how many years? Enter a value between 1 and 10 and press Enter"

$Duration = 365*$Years

Write-Host
$AskAction = Read-Host "Do you want to (1) Keep, (2) Keep and Delete, or (3) just Delete? Enter 1, 2, or 3 and press Enter"

if ($AskAction -eq "1") {

New-RetentionCompliancePolicy -Name "Company data retention policy" -SharePointLocation All -ModernGroupLocation All -Enabled $false
New-RetentionComplianceRule -Name "Company data retention rule" -RetentionDuration $Duration -RetentionDurationDisplayHint Years -ExpirationDateOption $ExpirationDateOption -RetentionComplianceAction Keep -Policy "Company data retention policy"

} elseif ($AskAction -eq "2") {

New-RetentionCompliancePolicy -Name "Company data retention policy" -SharePointLocation All -ModernGroupLocation All -Enabled $false
New-RetentionComplianceRule -Name "Company data retention rule" -RetentionDuration $Duration -RetentionDurationDisplayHint Years -ExpirationDateOption $ExpirationDateOption -RetentionComplianceAction KeepAndDelete -Policy "Company data retention policy"

} elseif ($AskAction -eq "3") {

New-RetentionCompliancePolicy -Name "Company data deletion policy" -SharePointLocation All -ModernGroupLocation All -Enabled $false
New-RetentionComplianceRule -Name "Company data deletion rule" -RetentionDuration $Duration -RetentionDurationDisplayHint Years -ExpirationDateOption $ExpirationDateOption -RetentionComplianceAction Delete -Policy "Company data deletion policy"

} else {
Write-Host
Write-Host "Invalid input, no policy will be created." -ForegroundColor Yellow

}


} else {
Write-Host
Write-Host "The default Company data retention policy will not be deployed." -ForegroundColor Yellow

}

Write-Host
Write-Host "Script completed" -ForegroundColor Cyan
