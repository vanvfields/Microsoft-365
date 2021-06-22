<##################################################################################################
#
.SYNOPSIS
    1. This script exports data from the Unified Audit Log for a specified user
    2. You can set the Output Path using the variable $OutputPath, or just run the script and it will prompt
    3. You must have the ExchangeOnlineManagement PowerShell module installed in order to use this script, i.e.:

        Install-Module ExchangeOnlineManagement
        Connect-ExchangeOnline

.NOTES
    FileName:    Export-ActivityByUser.ps1
    Author:      Alex Fields 
    Created:     June 2021
	Revised:     June 2021
    
#>
###################################################################################################
<#
## Import module and Connect to Exchange Online
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline
#>
#############################################################
## Gather the parameters 
## You may set the parameters in the script or enter by prompt

## Define variables
$OutputPath = ""
$DaysAgo = "90"

$CheckLog= (Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled

if (!$CheckLog) {
    Write-Host "The Unified Audit Log is not enabled in this tenant. You cannot export activities." -ForegroundColor Cyan
    Write-Host 
    } else {


## If OutputPath variable is not defined, prompt for it
if (!$OutputPath) {
    Write-Host
    $OutputPath = Read-Host 'Enter the output path, e.g. C:\IROutput'
    }

## If OutputPath does not exist, create it
$CheckOutputPath = Get-Item $OutputPath -ErrorAction SilentlyContinue
if (!$CheckOutputPath) {
    Write-Host
    Write-Host "Output path does not exist, so the directory will be created." -ForegroundColor Yellow
    mkdir $OutputPath
    }

## Set Start and End Dates
$StartDate = (Get-Date).AddDays(-$DaysAgo)
$EndDate = Get-Date

## Get Primary Domain Name (used in naming output files)
$PrimaryDomain = Get-AcceptedDomain | Where-Object Default -eq $true
$DomainName = $PrimaryDomain.DomainName

$CheckSubDir = Get-Item $OutputPath\$DomainName -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
Write-Host
Write-Host "Domain sub-directory does not exist, so the sub-directory will be created." -ForegroundColor Yellow
mkdir $OutputPath\$DomainName
}

$User = Read-Host "Enter the user's primary email address (UPN)"
$History = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -UserIds $User -SessionCommand ReturnLargeSet 

if (!$History) {
    Write-Host
    Write-Host "There are no activities in the audit log for the time period specified" -ForegroundColor Cyan
    Write-Host
    } else {

    ## Output the events to CSV
    $History | Out-GridView
    $History | Export-Csv -Path $OutputPath\$DomainName\$User-AuditLogActivities.csv
    Write-Host
    Write-Host "See user activities in the OutputPath" -ForegroundColor Yellow
    Write-Host
    }

}