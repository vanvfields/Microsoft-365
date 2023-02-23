<##################################################################################################
#
.SYNOPSIS
    1. This script creates alert policies that monitor events which could indicate compromised users or applications in Azure AD.
    2. You must have the ExchangeOnline PowerShell module installed in order to use this script, i.e.:

        Install-Module ExchangeOnlineManagement

.NOTES
    FileName:    Install-AzureADProtectionAlerts.ps1
    Author:      Alex Fields 
    Created:     June 2021
	Revised:     June 2021
    

.EXAMPLE 
    .\Install-AzureADProtectionAlerts.ps1 -AlertingEmail "alerts@contoso.com" 


#>
###################################################################################################


#region parameters
Param(
    [Parameter(Mandatory=$True)]
    [System.String]$AlertingEmail
)

if (!$AlertingEmail) {
$AlertingEmail = Read-Host "Enter the email address at which you will recieve alerts."
Write-Host
}

#endregion

<#region connect to the security & compliance center

Import-Module ExchangeOnlineManagement
Connect-IPPSSession

#endregion
#>

#region add alerts

        ## Alert when new members are added to Azure AD roles 
            $RawName = "New member added to a role"
            $NewName = if ($RawName.Length -gt 30) { "$($RawName.substring(0,30)) - $($AlertingEmail)" } else { "$($RawName) - $($AlertingEmail)" }
            $splat = @{
                name                = $NewName
                NotifyUser          = $AlertingEmail
                Operation           = "Add member to role."
                NotificationEnabled = $true
                Severity            = "Informational"
                Category            = "AccessGovernance"
                Comment             = "A new member has been added to a role in Azure AD."
                threattype          = "Activity"
                AggregationType     = "None"
                Disabled            = $false
            }
            try {
              $null = New-ProtectionAlert @splat -ErrorAction Stop
            }
            catch {
                write-host "Could not create rule. Error: $($_.Exception.Message)"
            }
            
        ## Alert when new applications are added to the directory 
            $RawName = "New application added"
            $NewName = if ($RawName.Length -gt 30) { "$($RawName.substring(0,30)) - $($AlertingEmail)" } else { "$($RawName) - $($AlertingEmail)" }
            $splat = @{
                name                = $NewName
                NotifyUser          = $AlertingEmail
                Operation           = "Add application."
                NotificationEnabled = $true
                Severity            = "Informational"
                Category            = "AccessGovernance"
                Comment             = "An application was added to Azure AD."
                threattype          = "Activity"
                AggregationType     = "None"
                Disabled            = $false
            }
            try {
              $null = New-ProtectionAlert @splat -ErrorAction Stop
            }
            catch {
                write-host "Could not create rule. Error: $($_.Exception.Message)"
            }


        ## Alert when new client credentials are added to an application or service principal 
            $RawName = "Credentials added to an application"
            $NewName = if ($RawName.Length -gt 30) { "$($RawName.substring(0,30)) - $($AlertingEmail)" } else { "$($RawName) - $($AlertingEmail)" }
            $splat = @{
                name                = $NewName
                NotifyUser          = $AlertingEmail
                Operation           = "Update application – Certificates and secrets"
                NotificationEnabled = $true
                Severity            = "Informational"
                Category            = "AccessGovernance"
                Comment             = "Certificate or secret was added to an application."
                threattype          = "Activity"
                AggregationType     = "None"
                Disabled            = $false
            }
            try {
              $null = New-ProtectionAlert @splat -ErrorAction Stop
            }
            catch {
                write-host "Could not create rule. Error: $($_.Exception.Message)"
            }

        ## Alert when new application consent is granted 
            $RawName = "Application consent granted"
            $NewName = if ($RawName.Length -gt 30) { "$($RawName.substring(0,30)) - $($AlertingEmail)" } else { "$($RawName) - $($AlertingEmail)" }
            $splat = @{
                name                = $NewName
                NotifyUser          = $AlertingEmail
                Operation           = "Consent to application."
                NotificationEnabled = $true
                Severity            = "Informational"
                Category            = "AccessGovernance"
                Comment             = "New permissions consent granted for an application."
                threattype          = "Activity"
                AggregationType     = "None"
                Disabled            = $false
            }
            try {
              $null = New-ProtectionAlert @splat -ErrorAction Stop
            }
            catch {
                write-host "Could not create rule. Error: $($_.Exception.Message)"
            }


        ## Alert when federation settings are modified 
            $RawName = "New federation settings"
            $NewName = if ($RawName.Length -gt 30) { "$($RawName.substring(0,30)) - $($AlertingEmail)" } else { "$($RawName) - $($AlertingEmail)" }
            $splat = @{
                name                = $NewName
                NotifyUser          = $AlertingEmail
                Operation           = "Set federation settings on domain."
                NotificationEnabled = $true
                Severity            = "Informational"
                Category            = "AccessGovernance"
                Comment             = "Domain federation settings have been modified."
                threattype          = "Activity"
                AggregationType     = "None"
                Disabled            = $false
            }
            try {
              $null = New-ProtectionAlert @splat -ErrorAction Stop
            }
            catch {
                write-host "Could not create rule. Error: $($_.Exception.Message)"
            }


        ## Alert when partner settings are modified 
            $RawName = "Partner relationship added"
            $NewName = if ($RawName.Length -gt 30) { "$($RawName.substring(0,30)) - $($AlertingEmail)" } else { "$($RawName) - $($AlertingEmail)" }
            $splat = @{
                name                = $NewName
                NotifyUser          = $AlertingEmail
                Operation           = "Add partner to company."
                NotificationEnabled = $true
                Severity            = "Informational"
                Category            = "AccessGovernance"
                Comment             = "Partner relationship has been added to the tenant."
                threattype          = "Activity"
                AggregationType     = "None"
                Disabled            = $false
            }
            try {
              $null = New-ProtectionAlert @splat -ErrorAction Stop
            }
            catch {
                write-host "Could not create rule. Error: $($_.Exception.Message)"
            }


        ## Alert when CA policy is modified 
            $RawName = "CA Policy has been updated"
            $NewName = if ($RawName.Length -gt 30) { "$($RawName.substring(0,30)) - $($AlertingEmail)" } else { "$($RawName) - $($AlertingEmail)" }
            $splat = @{
                name                = $NewName
                NotifyUser          = $AlertingEmail
                Operation           = "Update policy."
                NotificationEnabled = $true
                Severity            = "Informational"
                Category            = "AccessGovernance"
                Comment             = "A Conditional Access policy has been updated."
                threattype          = "Activity"
                AggregationType     = "None"
                Disabled            = $false
            }
            try {
              $null = New-ProtectionAlert @splat -ErrorAction Stop
            }
            catch {
                write-host "Could not create rule. Error: $($_.Exception.Message)"
            }

        ## Alert when CA policy is added 
            $RawName = "CA Policy has been added"
            $NewName = if ($RawName.Length -gt 30) { "$($RawName.substring(0,30)) - $($AlertingEmail)" } else { "$($RawName) - $($AlertingEmail)" }
            $splat = @{
                name                = $NewName
                NotifyUser          = $AlertingEmail
                Operation           = "Add policy."
                NotificationEnabled = $true
                Severity            = "Informational"
                Category            = "AccessGovernance"
                Comment             = "A new Conditional Access policy has been added."
                threattype          = "Activity"
                AggregationType     = "None"
                Disabled            = $false
            }
            try {
              $null = New-ProtectionAlert @splat -ErrorAction Stop
            }
            catch {
                write-host "Could not create rule. Error: $($_.Exception.Message)"
            }

        ## Alert when CA policy is deleted 
            $RawName = "CA Policy has been deleted"
            $NewName = if ($RawName.Length -gt 30) { "$($RawName.substring(0,30)) - $($AlertingEmail)" } else { "$($RawName) - $($AlertingEmail)" }
            $splat = @{
                name                = $NewName
                NotifyUser          = $AlertingEmail
                Operation           = "Delete policy."
                NotificationEnabled = $true
                Severity            = "Informational"
                Category            = "AccessGovernance"
                Comment             = "A Conditional Access policy has been deleted."
                threattype          = "Activity"
                AggregationType     = "None"
                Disabled            = $false
            }
            try {
              $null = New-ProtectionAlert @splat -ErrorAction Stop
            }
            catch {
                write-host "Could not create rule. Error: $($_.Exception.Message)"
            }



Write-Host
Write-Host "Script completed." -ForegroundColor Cyan
Write-Host

#endregion