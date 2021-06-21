<##################################################################################################
#
.SYNOPSIS
    1. This script exports data from the Unified Audit Log for a specified IP address
    2. You can set the Output Path using the variable $OutputPath, or just run the script and it will prompt
    3. You must have the ExchangeOnlineManagement PowerShell module installed in order to use this script, i.e.:

        Install-Module ExchangeOnlineManagement
        Connect-ExchangeOnline

.NOTES
    FileName:    Export-ActivitybyIPAddress.ps1
    Author:      Alex Fields 
    Created:     June 2021
	Revised:     June 2021
    
#>
###################################################################################################


## Import module and Connect to Exchange Online
Import-Module ExchangeOnlineManagement

## Define variables
$OutputPath = ""
$DaysAgo = "90"

$CheckLog= (Get-AdminAuditLogConfig).UnifiedAuditLogIngestionEnabled

if (!$CheckLog) {
    Write-Host "The Unified Audit Log is not enabled in this tenant. You cannot export activities." -ForegroundColor Cyan

    } else {

    ## If OutputPath variable is not defined, prompt for it
    if (!$OutputPath) {
        Write-Host
        $OutputPath = Read-Host 'Enter the output path, e.g. C:\IROutput'
        }

    ## If OutputPath does not exist, create it
    $CheckOutputPath = Get-Item $OutputPath
    if (!$CheckOutputPath) {
        mkdir $OutputPath
        }

    ## Set Start and End Dates
    $StartDate = (Get-Date).AddDays(-$DaysAgo)
    $EndDate = Get-Date

    $IPAddress = Read-Host "Enter the IP address of interest"
    $History = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -IPAddresses $IPAddress -SessionCommand ReturnLargeSet 

    if (!$History) {
        Write-Host
        Write-Host "There are no activities in the audit log for the time period specified" -ForegroundColor Cyan
        Write-Host
        } else {

        ## Output the events to CSV
        $History | Out-GridView
        $History | Export-Csv -Path $OutputPath\$IPAddress-AuditLogActivities.csv
        Write-Host
        Write-Host "See IP address activities in the OutputPath" -ForegroundColor Yellow
        Write-Host
        }

    }