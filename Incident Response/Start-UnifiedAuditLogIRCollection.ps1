<##################################################################################################
#
.SYNOPSIS
    1. This script exports events from the Unified Audit Log that are particularly relevant for Incident Response.
    2. You can set the Output Path using the variable $OutputPath, or just run the script and it will prompt
    3. By default the script is configured to collect the last 90 days of audit data; you may adjust this using $DaysAgo variable
    4. You must have the ExchangeOnline PowerShell module installed in order to use this script, i.e.:

        Install-Module ExchangeOnlineManagement

.NOTES
    FileName:    Start-UnifiedAuditLogIRCollection.ps1
    Author:      Alex Fields 
    Created:     June 2021
	Revised:     June 2021
    
#>
###################################################################################################


## Define variables
$OutputPath = ""
$DaysAgo = "90"

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

## Import module and Connect to Exchange Online
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline

## Get Primary Domain Name (used in naming output files)
$PrimaryDomain = Get-AcceptedDomain | Where-Object Default -eq $true
$DomainName = $PrimaryDomain.DomainName

## Get changes to membership in Azure AD roles (could indicate escalation of privilege)
$AzureADRoles = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add member to role.","Remove member from role.") -SessionCommand ReturnLargeSet 

    ## Check to see if the variable is null
    if (!$AzureADRoles) {
    Write-Host
    Write-Host "There are no Azure AD Role events for the time period specified" -ForegroundColor Cyan
    Write-Host
    } else {

    ## Output the events to CSV
    $AzureADRoles | Export-Csv -Path $OutputPath\$DomainName-AuditLog_AzureADRolesChanges.csv
    Write-Host
    Write-Host "See Azure AD Roles Changes events in the OutputPath" -ForegroundColor Yellow
    Write-Host
    }

## Get changes to applications, client app credentials, permissions, and new consents (could indicate app abuse)
$AppEvents = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add application.","Update application – Certificates and secrets","Add app role assignment to service principal.","Add app role assignment grant to user.","Add delegated permission grant.","Consent to application.") -SessionCommand ReturnLargeSet 

    ## Check to see if the variable is null
    if (!$AppEvents) { 
    Write-Host "There are no Azure AD App events for the time period specified" -ForegroundColor Cyan
    Write-Host
    } else {

    ## Output the events to CSV
    $AppEvents | Export-Csv -Path $OutputPath\$DomainName-AuditLog_ApplicationChanges.csv
    Write-Host "See Application Changes events in the OutputPath" -ForegroundColor Yellow
    Write-Host
    }


## Get Conditional Access policy changes 
$CAEvents = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add policy.","Update policy.","Delete policy.") -SessionCommand ReturnLargeSet 

    ## Check to see if the variable is null
    if (!$CAEvents) {
    Write-Host "There are no Conditional Access events for the time period specified" -ForegroundColor Cyan
    Write-Host
    } else {

    ## Output the events to CSV
    $CAEvents | Export-Csv -Path $OutputPath\$DomainName-AuditLog_ConditionalAccessPolicyChanges.csv
    Write-Host "See Conditional Access Policy Changes events in the OutputPath" -ForegroundColor Yellow
    Write-Host
    }


## Get Domain changes 
$DomainEvents = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add domain to company.","Remove domain from company.","Set domain authentication.","Set federation settings on domain.","Set DirSyncEnabled flag.","Update domain.","Verify domain.","Verify email verified domain.") -SessionCommand ReturnLargeSet 

    ## Check to see if the variable is null
    if (!$DomainEvents) {
    Write-Host "There are no Domain Management events for the time period specified" -ForegroundColor Cyan
    Write-Host
    } else {

    ## Output the events to CSV
    $DomainEvents | Export-Csv -Path $OutputPath\$DomainName-AuditLog_DomainChanges.csv
    Write-Host "See Domain Management events in the OutputPath" -ForegroundColor Yellow
    Write-Host
    }


## Get Partner changes 
$PartnerEvents = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add partner to company.","Remove partner from company.") -SessionCommand ReturnLargeSet 
    
    ## Check to see if the variable is null
    if (!$PartnerEvents) {
    Write-Host "There are no Partner management events for the time period specified" -ForegroundColor Cyan
    Write-Host
    } else {

    ## Output the events to CSV
    $PartnerEvents | Export-Csv -Path $OutputPath\$DomainName-AuditLog_PartnerManagementChanges.csv
    Write-Host "See Partner Management events in the OutputPath" -ForegroundColor Yellow
    Write-Host
    }
    

## Get user add events 
$UserAddEvents = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add user.") -SessionCommand ReturnLargeSet 

    ## Check to see if the variable is null
    if (!$UserAddEvents) { 
    Write-Host "There are no Users Added events for the time period specified" -ForegroundColor Cyan
    Write-Host
    } else {

    ## Output the events to CSV
    $UserAddEvents | Export-Csv -Path $OutputPath\$DomainName-AuditLog_UsersAdded.csv
    Write-Host "See Users Added events in the OutputPath" -ForegroundColor Yellow
    Write-Host
    }


## Get password changes
$PasswordEvents = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Change user password.","Reset user password.","Set force change user password.") -SessionCommand ReturnLargeSet 

    ## Check to see if the variable is null
    if (!$PasswordEvents) {
    Write-Host "There are no Password events for the time period specified" -ForegroundColor Cyan
    Write-Host
    } else {

    ## Output the events to CSV
    $PasswordEvents | Export-Csv -Path $OutputPath\$DomainName-AuditLog_UsersPasswords.csv
    Write-Host "See Users Passwords events in the OutputPath" -ForegroundColor Yellow
    Write-Host
    }

## Get Azure AD Device add events
$DeviceAddEvents = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add device.") -SessionCommand ReturnLargeSet 

    ## Check to see if the variable is null
    if (!$DeviceAddEvents) {
    Write-Host "There are no Device Added events for the time period specified" -ForegroundColor Cyan
    Write-Host
    } else {

    ## Output the events to CSV
    $DeviceAddEvents | Export-Csv -Path $OutputPath\$DomainName-AuditLog_DevicesAdded.csv
    Write-Host "See Devices Added events in the OutputPath" -ForegroundColor Yellow
    Write-Host
    }



## Get high-impact Exchange admin events such as New-InboxRule, Set-Mailbox, and Add-MailboxPermission
$MbxRuleEvents = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType ExchangeAdmin -Operations ("New-InboxRule","Set-Mailbox","Add-MailboxPermission") -SessionCommand ReturnLargeSet 

    ## Check to see if the variable is null
    if (!$MbxRuleEvents) {
    Write-Host "There are no new inbox rules, redirects, or mailbox permission events for the time period specified" -ForegroundColor Cyan
    Write-Host
    } else {

    ## Output the events to CSV
    $MbxRuleEvents | Export-Csv -Path $OutputPath\$DomainName-AuditLog_ExchangeAdminEvents.csv
    Write-Host "See Exchage Admin events in the OutputPath" -ForegroundColor Yellow
    Write-Host
    }
