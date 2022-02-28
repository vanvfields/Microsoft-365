<# 
.SYNOPSIS
    Use this script to deploy a blanket retention policy as described in the Data Protection Starter Kit.
    You should be familiar with the regulations and policies applicable to your organization before running this script.
    Script provided as-is, use at your own risk.

.NOTES
    1. You must have the ExchangeOnlineManagement PowerShell module installed in order to run this script.
    2. Connect to the Security & Compliance center using Connect-IPPSSession

.DETAILS
    FileName:    Install-EmailRetentionPolicy.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     September 2021
	Updated:     February 2022

#>

#Import-Module ExchangeOnlineManagement
#Connect-IPPSSession

Write-Host
$AskDate = Read-Host "Will your retention policy be based on (1) Date created or (2) Date last modified? Type 1 or 2 and press Enter"

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
$AskEnable = Read-Host "Do you want the policy to be enabled upon creation? Type Y or N and press Enter"

if ($AskEnable -eq "y") {
    $Enabled = $true
    Write-Host
    Write-Host "Warning: The policy you create next will be enabled and enforced." -ForegroundColor Yellow
} else {
    $Enabled = $false
    Write-Host
    Write-Host "Warning: The policy you create next will be disabled and will not take effect until you enable them." -ForegroundColor Yellow
}


Write-Host
$Years = Read-Host "Retain Email data for how many years? Enter a value between 1 and 10 and press Enter"
$Duration = 365*$Years

Write-Host
$AskAction = Read-Host "Do you want to (1) Keep, (2) Keep and Delete, or (3) just Delete? Enter 1, 2, or 3 and press Enter"
if ($AskAction -eq "1") {

    New-RetentionCompliancePolicy -Name "Email retention policy" -ExchangeLocation All -Enabled $Enabled
    New-RetentionComplianceRule -Name "Email retention rule" -RetentionDuration $Duration -RetentionDurationDisplayHint Years -ExpirationDateOption $ExpirationDateOption -RetentionComplianceAction Keep -Policy "Email retention policy"
    Write-Host 
    Write-Host "The policy has been created. Once enabled, it can take up to 24 hours to take effect." -ForegroundColor Green

} elseif ($AskAction -eq "2") {

    New-RetentionCompliancePolicy -Name "Email retention policy" -ExchangeLocation All -Enabled $Enabled
    New-RetentionComplianceRule -Name "Email retention rule" -RetentionDuration $Duration -RetentionDurationDisplayHint Years -ExpirationDateOption $ExpirationDateOption -RetentionComplianceAction KeepAndDelete -Policy "Email retention policy"
    Write-Host
    Write-Host "The policy has been created. Once enabled, it can take up to 24 hours to take effect." -ForegroundColor Green

} elseif ($AskAction -eq "3") {

    New-RetentionCompliancePolicy -Name "Email deletion policy" -ExchangeLocation All -Enabled $Enabled
    New-RetentionComplianceRule -Name "Email deletion rule" -RetentionDuration $Duration -RetentionDurationDisplayHint Years -ExpirationDateOption $ExpirationDateOption -RetentionComplianceAction Delete -Policy "Email deletion policy"
    Write-Host
    Write-Host "The policy has been created. Once enabled, it can take up to 24 hours to take effect." -ForegroundColor Green

} 