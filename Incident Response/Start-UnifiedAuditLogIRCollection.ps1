<##################################################################################################
#
.SYNOPSIS
    1. This script exports events from the Unified Audit Log that are particularly relevant for Incident Response.
    2. You can set the Output Path using the variable $OutputPath, or just run the script and it will prompt
    3. By default the script is configured to collect the last 90 days of audit data; you may adjust this using $DaysAgo variable
    4. You must have the ExchangeOnlineManagement PowerShell module installed in order to use this script, i.e.:

        Install-Module ExchangeOnlineManagement
        Connect-ExchangeOnline

.NOTES
    FileName:    Start-UnifiedAuditLogIRCollection.ps1
    Author:      Alex Fields 
    Created:     June 2021
	Revised:     June 2021
    
#>
###################################################################################################
## Import the module and connect to Exchange Online
Import-Module ExchangeOnlineManagement
Connect-ExchangeOnline
#############################################################

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

    ## Get changes to membership in Azure AD roles (new adds could indicate escalation of privilege)
    $SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add member to role.","Remove member from role.") -SessionCommand ReturnLargeSet 

        ## Check to see if the variable is null
        if (!$SearchResults) {
        Write-Host
        Write-Host "There are no events matching Azure AD role changes for the time period specified" -ForegroundColor Cyan
        Write-Host
        } else {

        ## Output the events to CSV
        $SearchResults | Export-Csv -Path $OutputPath\$DomainName\AuditLog_AzureADRoleChanges.csv
        Write-Host
        Write-Host "See Azure AD Roles Changes events in the output path" -ForegroundColor Yellow
        Write-Host
        }

    ## Get changes to applications, client app credentials, permissions, and new consents (could indicate app abuse)
    $SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add application.","Add service principal.","Add service principal credentials.","Update application – Certificates and secrets","Add app role assignment to service principal.","Add app role assignment grant to user.","Add delegated permission grant.","Consent to application.") -SessionCommand ReturnLargeSet 

        ## Check to see if the variable is null
        if (!$SearchResults) { 
        Write-Host "There are no events matching Azure AD app changes for the time period specified" -ForegroundColor Cyan
        Write-Host
        } else {

        ## Output the events to CSV
        $SearchResults | Export-Csv -Path $OutputPath\$DomainName\AuditLog_AzureADAppChanges.csv
        Write-Host "See Azure AD application events in the output path" -ForegroundColor Yellow
        Write-Host
        }


    ## Get Conditional Access policy changes 
    $SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add policy.","Update policy.","Delete policy.") -SessionCommand ReturnLargeSet 

        ## Check to see if the variable is null
        if (!$SearchResults) {
        Write-Host "There are no Conditional Access events for the time period specified" -ForegroundColor Cyan
        Write-Host
        } else {

        ## Output the events to CSV
        $SearchResults | Export-Csv -Path $OutputPath\$DomainName\AuditLog_ConditionalAccessPolicyChanges.csv
        Write-Host "See Conditional Access Policy events in the output path" -ForegroundColor Yellow
        Write-Host
        }


    ## Get Domain changes 
    $SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add domain to company.","Remove domain from company.","Set domain authentication.","Set federation settings on domain.","Set DirSyncEnabled flag.","Update domain.","Verify domain.","Verify email verified domain.") -SessionCommand ReturnLargeSet 

        ## Check to see if the variable is null
        if (!$SearchResults) {
        Write-Host "There are no Domain Management events for the time period specified" -ForegroundColor Cyan
        Write-Host
        } else {

        ## Output the events to CSV
        $SearchResults | Export-Csv -Path $OutputPath\$DomainName\AuditLog_AzureADDomainChanges.csv
        Write-Host "See Domain Management events in the output path" -ForegroundColor Yellow
        Write-Host
        }


    ## Get Partner changes 
    $SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add partner to company.","Remove partner from company.") -SessionCommand ReturnLargeSet 
    
        ## Check to see if the variable is null
        if (!$SearchResults) {
        Write-Host "There are no Partner management events for the time period specified" -ForegroundColor Cyan
        Write-Host
        } else {

        ## Output the events to CSV
        $SearchResults | Export-Csv -Path $OutputPath\$DomainName\AuditLog_PartnerManagementChanges.csv
        Write-Host "See Partner Management events in the output path" -ForegroundColor Yellow
        Write-Host
        }
    

    ## Get user add and delete events 
    $SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add user.", "Delete user.") -SessionCommand ReturnLargeSet 

        ## Check to see if the variable is null
        if (!$SearchResults) { 
        Write-Host "There are no Users Added events for the time period specified" -ForegroundColor Cyan
        Write-Host
        } else {

        ## Output the events to CSV
        $SearchResults | Export-Csv -Path $OutputPath\$DomainName\AuditLog_UsersAddedOrDeleted.csv
        Write-Host "See events matching 'Add user' and 'Delete user' in the output path" -ForegroundColor Yellow
        Write-Host
        }


    ## Get password changes
    $SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Change user password.","Reset user password.","Set force change user password.") -SessionCommand ReturnLargeSet 

        ## Check to see if the variable is null
        if (!$SearchResults) {
        Write-Host "There are no Password events for the time period specified" -ForegroundColor Cyan
        Write-Host
        } else {

        ## Output the events to CSV
        $SearchResults | Export-Csv -Path $OutputPath\$DomainName\AuditLog_PasswordResetsAndChanges.csv
        Write-Host "See password events in the output path" -ForegroundColor Yellow
        Write-Host
        }

    ## Get user update events (this includes MFA registration / security info changes)
    $SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Update user.") -SessionCommand ReturnLargeSet 

        ## Check to see if the variable is null
        if (!$SearchResults) { 
        Write-Host "There are no events matching 'Update user' for the time period specified" -ForegroundColor Cyan
        Write-Host
        } else {

        ## Output the events to CSV
        $SearchResults | Export-Csv $OutputPath\$DomainName\AuditLog_UpdateUser.csv
        Write-Host "See events matching 'Update user' in the output path (this includes MFA method updates)" -ForegroundColor Yellow
        Write-Host

    }
    
    ## Get Azure AD Device add and delete events
    $SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType AzureActiveDirectory -Operations ("Add device.", "Delete device.") -SessionCommand ReturnLargeSet 

        ## Check to see if the variable is null
        if (!$SearchResults) {
        Write-Host "There are no events matching 'Add device' or 'Delete device' for the time period specified" -ForegroundColor Cyan
        Write-Host
        } else {

        ## Output the events to CSV
        $SearchResults | Export-Csv -Path $OutputPath\$DomainName\AuditLog_DevicesAddedOrDeleted.csv
        Write-Host "See events matching 'Add device' or 'Delete device' in the output path" -ForegroundColor Yellow
        Write-Host
        }



    ## Get the Exchange admin log events (this includes stuff like new inbox rules, mailbox forwarding, mailbox permissions and delegations, etc.)
    $SearchResults = Search-UnifiedAuditLog -StartDate $StartDate -EndDate $EndDate -RecordType ExchangeAdmin -SessionCommand ReturnLargeSet 

        ## Check to see if the variable is null
        if (!$SearchResults) {
        Write-Host "There are no Exchange admin events for the time period specified" -ForegroundColor Cyan
        Write-Host
        } else {

        ## Output the events to CSV
        $SearchResults | Export-Csv -Path $OutputPath\$DomainName\AuditLog_ExchangeAdminEvents.csv
        Write-Host "See Exchage Admin events in the output path" -ForegroundColor Yellow
        Write-Host
        }

}
