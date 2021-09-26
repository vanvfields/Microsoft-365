<# 
.SYNOPSIS
    Use this script to deploy a blanket retention policy as described in the Data Protection Starter Kit.
    You should be familiar with the regulations and policies applicable to your organization before running this script.
    Script provided as-is, use at your own risk.

.NOTES
    1. You must have the ExchangeOnlineManagement PowerShell module installed in order to run this script.
    2. Connect to the Security & Compliance center using Connect-IPPSSession

.DETAILS
    FileName:    Install-TeamsRetentionPolicies.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     September 2021
	Updated:     September 2021

#>


#Connect-IPPSSession

Write-Host 
$AskEnable = Read-Host "Do you want the policies to be enabled upon creation? Type Y or N and press Enter"

if ($AskEnable -eq "y") {
    $Enabled = $true
    Write-Host
    Write-Host "Warning: The policies you create next will be enabled and enforced." -ForegroundColor Yellow
} else {
    $Enabled = $false
    Write-Host
    Write-Host "Warning: The policies you create next will be disabled and will not take effect until you enable them." -ForegroundColor Yellow
}

Write-Host
$Answer = Read-Host "Do you want to deploy the default retention policy for Teams chats? Type Y or N and press Enter"

if ($Answer -eq "y") {
Write-Host
$Days = Read-Host "Retain Teams chat messages for how many days? Enter a value up to 3650 and press Enter"

Write-Host
$AskAction = Read-Host "Do you want to (1) Keep, (2) Keep and Delete, or (3) just Delete? Enter 1, 2, or 3 and press Enter"
if ($AskAction -eq "1") {

    New-RetentionCompliancePolicy -Name "Teams chats retention policy" -TeamsChatLocation All -Enabled $Enabled
    New-RetentionComplianceRule -Name "Teams chats retention rule" -RetentionDuration $Days -RetentionComplianceAction Keep -Policy "Teams chats retention policy"
    Write-Host 
    Write-Host "The policy has been created. Once enabled, it can take up to 24 hours to take effect." -ForegroundColor Green

} elseif ($AskAction -eq "2") {

    New-RetentionCompliancePolicy -Name "Teams chats retention policy" -TeamsChatLocation All -Enabled $Enabled
    New-RetentionComplianceRule -Name "Teams chats retention rule" -RetentionDuration $Days -RetentionComplianceAction KeepAndDelete -Policy "Teams chats retention policy"
    Write-Host 
    Write-Host "The policy has been created. Once enabled, it can take up to 24 hours to take effect." -ForegroundColor Green

} elseif ($AskAction -eq "3") {

    New-RetentionCompliancePolicy -Name "Teams chats deletion policy" -TeamsChatLocation All -Enabled $Enabled
    New-RetentionComplianceRule -Name "Teams chats deletion rule" -RetentionDuration $Days -RetentionComplianceAction Delete -Policy "Teams chats deletion policy"
    Write-Host 
    Write-Host "The policy has been created. Once enabled, it can take up to 24 hours to take effect." -ForegroundColor Green

} else {
    Write-Host
    Write-Host "Invalid input, no policy will be created." -ForegroundColor Yellow
}


} else {
Write-Host
Write-Host "The default Teams chats policy will not be deployed." -ForegroundColor Yellow

}

Write-Host
$Answer = Read-Host "Do you want to deploy the default Teams channels retention policy? Type Y or N and press Enter"

if ($Answer -eq "y") {
Write-Host
$Days = Read-Host "Retain Teams channel messages for how many days? Enter a value up to 3650 and press Enter"

Write-Host
$AskAction = Read-Host "Do you want to (1) Keep, (2) Keep and Delete, or (3) just Delete? Enter 1, 2, or 3 and press Enter"

if ($AskAction -eq "1") {

    New-RetentionCompliancePolicy -Name "Teams channels retention policy" -TeamsChannelLocation All -Enabled $Enabled
    New-RetentionComplianceRule -Name "Teams channels retention rule" -RetentionDuration $Days -RetentionComplianceAction Keep -Policy "Teams channels retention policy"
    Write-Host 
    Write-Host "The policy has been created. Once enabled, it can take up to 24 hours to take effect." -ForegroundColor Green

} elseif ($AskAction -eq "2") {

    New-RetentionCompliancePolicy -Name "Teams channels retention policy" -TeamsChannelLocation All -Enabled $Enabled
    New-RetentionComplianceRule -Name "Teams channels retention rule" -RetentionDuration $Days -RetentionComplianceAction KeepAndDelete -Policy "Teams channels retention policy"
    Write-Host 
    Write-Host "The policy has been created. Once enabled, it can take up to 24 hours to take effect." -ForegroundColor Green

} elseif ($AskAction -eq "3") {

    New-RetentionCompliancePolicy -Name "Teams channels deletion policy" -TeamsChannelLocation All -Enabled $Enabled
    New-RetentionComplianceRule -Name "Teams channels deletion rule" -RetentionDuration $Days -RetentionComplianceAction Delete -Policy "Teams channels deletion policy"
    Write-Host 
    Write-Host "The policy has been created. Once enabled, it can take up to 24 hours to take effect." -ForegroundColor Green

} else {
    Write-Host
    Write-Host "Invalid input, no policy will be created." -ForegroundColor Yellow

}


} else {
Write-Host
Write-Host "The default Teams channels policy will not be deployed." -ForegroundColor Yellow

}

Write-Host
Write-Host "Script completed" -ForegroundColor Cyan