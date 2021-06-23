<##################################################################################################
#
.SYNOPSIS
    1. This script exports several data points from the Azure AD Incident Response PowerShell module
    2. You can set the Output Path using the variable $OutputPath, or just run the script and it will prompt
    3. Specify the primary $DomainName associated with the tenant in order to run the script, or it will prompt
    4. See additional examples of the AzureADIR functions in the comments at the end of the script
    5. You must have the AzureADIncidentResponse PowerShell module installed in order to use this script, i.e.:

        Install-Module AzureADIncidentResponse


.NOTES
    FileName:    Start-AzureADIRCollection.ps1
    Author:      Alex Fields 
    Created:     June 2021
	Revised:     June 2021
    
#>
###################################################################################################

Import-Module AzureAD
Import-Module AzureADIncidentResponse

#############################################################
## Gather the parameters 
## You may set the parameters in the script or enter by prompt

$DomainName = ""
$OutputPath = ""


## If the OutputPath variable is undefined, prompt for input
if (!$OutputPath) {
Write-Host
$OutputPath = Read-Host 'Enter the output path, e.g. C:\IROutput'
}

## If the output path does not exist, then create it
$CheckOutputPath = Get-Item $OutputPath -ErrorAction SilentlyContinue
if (!$CheckOutputPath) {
Write-Host
Write-Host "Output path does not exist, so the directory will be created." -ForegroundColor Yellow
mkdir $OutputPath
}

## If the DomainName variable is undefined, prompt for input
if ($DomainName -eq "") {
Write-Host
$DomainName = Read-Host 'Enter the primary domain name associated with the tenant'
}

$CheckSubDir = Get-Item $OutputPath\$DomainName -ErrorAction SilentlyContinue
if (!$CheckSubDir) {
Write-Host
Write-Host "Domain sub-directory does not exist, so the sub-directory will be created." -ForegroundColor Yellow
mkdir $OutputPath\$DomainName
}

## Change directory to the OutputPath 
cd $OutputPath\$DomainName

#############################################################
## Get the tenant ID and connect to Azure AD
$TenantID = Get-AzureADIRTenantId -DomainName $DomainName
Connect-AzureADIR -TenantId $TenantID 
#############################################################

## Get a current list of Azure AD Privileged role assignments 
Get-AzureADIRPrivilegedRoleAssignment -TenantId $TenantID -CsvOutput

## Gets two lists of applications with assigned permissions: delegated (user) permissions and application permissions
Get-AzureADIRPermission -TenantId $TenantID -CsvOutput

## Get a current list of Azure AD users and make recommendations on how to improve their MFA stance 
Get-AzureADIRMfaAuthMethodAnalysis -TenantId $TenantID -LocationInfo -CsvOutput

## Gets the last interactive sign-in activity for all users in the tenant
Get-AzureADIRUserLastSignInActivity -TenantId $TenantID -All -GuestInfo -CsvOutput


## Get a list of Azure AD users with MFA usage location and phone number
$PhoneToLocationCheck = Get-AzureADIRMfaPhoneToLocationCheck -TenantId $TenantID
if (!$PhoneToLocationCheck) {
Write-Host "There is no data returned for the function Get-AzureADIRMfaPhoneToLocationCheck" -ForegroundColor Cyan
} else {
Get-AzureADIRMfaPhoneToLocationCheck -TenantId $TenantID -CsvOutput
}

## Gets user risk dismissals for the target tenant 
$UserRiskDismissCheck = Get-AzureADIRDismissedUserRisk -TenantId $TenantID
if (!$UserRiskDismissCheck) {
Write-Host "There is no data returned for the function Get-AzureADIRDismissedUserRisk" -ForegroundColor Cyan
} else {
Get-AzureADIRDismissedUserRisk -TenantId $TenantID -CsvOutput
}

## Gets Self-service password reset usage history for the target tenant
$SsprHistoryCheck = Get-AzureADIRSsprUsageHistory -TenantId $TenantID
if (!$SsprHistoryCheck) {
Write-Host "There is no data returned for the function Get-AzureADIRSsprUsageHistory" -ForegroundColor Cyan
} else {
Get-AzureADIRSsprUsageHistory -TenantId $TenantID -CsvOutput
}

## Get Azure AD Conditional Access policies 
$CAPolicy = Get-AzureADIRConditionalAccessPolicy -TenantId $TenantID
if (!$CAPolicy) {
Write-Host "There is no data returned for the function Get-AzureADIRConditionalAccessPolicy" -ForegroundColor Cyan
} else {
Get-AzureADIRConditionalAccessPolicy -TenantId $TenantID -All -XmlOutput
}

######################################################################
Write-Host "Please review the files in your output directory" -ForegroundColor Cyan
Write-Host 
Write-Host "Script completed." -ForegroundColor Cyan
Write-Host 

<#
#############################################################
## More Examples; I encourage you to use and explore the various AzureADIR functions  

#############################################################
## Collect Azure AD Audit logs by category

Get-AzureADIRAuditActivity -TenantId $TenantID -Category "DirectoryManagement" | Out-GridView 

Get-AzureADIRAuditActivity -TenantId $TenantID -Category "UserManagement" | Out-GridView 

Get-AzureADIRAuditActivity -TenantId $TenantID -Category "RoleManagement" | Out-GridView

Get-AzureADIRAuditActivity -TenantId $TenantID -Category "ApplicationManagement" | Out-GridView


#############################################################
## Collect Azure AD Audit logs for specific activities

## Gets new MFA method registrations
Get-AzureADIRAuditActivity -TenantId $TenantID -ActivityDisplayName "User registered security info" | Out-GridView

## Gets newly added applications
Get-AzureADIRAuditActivity -TenantId $TenantID -ActivityDisplayName ("Add application") | Out-GridView

## Gets a list of newly added application permissions
Get-AzureADIRAuditActivity -TenantId $TenantID -ActivityDisplayName ("Add app role assignment to service principal") | Out-GridView

## Gets a list of newly added delegated user permissions
Get-AzureADIRAuditActivity -TenantId $TenantID -ActivityDisplayName ("Add delegated permission grant") | Out-GridView

## Gets a list of newly consented application permissions
Get-AzureADIRAuditActivity -TenantId $TenantID -ActivityDisplayName ("Consent to application") | Out-GridView

#############################################################
## Gets stale user accounts not signed in within last 30 days (including guests)
Get-AzureADIRUserLastSignInActivity -TenantId $TenantID -StaleThreshold 30 -GuestInfo | Export-Csv -Path $OutputPath\$DomainName\AADLog_StaleAccountsLastSignIn.csv

#############################################################



#>