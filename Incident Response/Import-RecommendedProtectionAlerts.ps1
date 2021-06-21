<##################################################################################################
#
.SYNOPSIS
    1. This script creates alert policies that monitor events which could indicate compromised users or applications in Azure AD.
    2. You must have the ExchangeOnline PowerShell module installed in order to use this script, i.e.:

        Install-Module ExchangeOnlineManagement

.NOTES
    FileName:    Import-RecommendedProtectionAlerts.ps1
    Author:      Alex Fields 
    Created:     June 2021
	Revised:     June 2021
    
#>
###################################################################################################

## Import EXO management module and connect to Security & Compliance Center
Import-Module ExchangeOnlineManagement
Connect-IPPSSession

$notifyUser = ""

if ($notifyUser = "") {
$notifyUser = Read-Host "Enter the email address at which you will recieve alerts."
Write-Host
}

## Administrative roles are modified
New-ProtectionAlert -Name "New member added to an Azure AD Role" -Category Others -NotifyUser $notifyUser -ThreatType Activity -Operation "Add member to role." -Description "Custom alert policy to track when members are added to Azure AD Roles" -AggregationType None

## New applications are added to the directory (always investigate unknown or unexpected apps)
New-ProtectionAlert -Name "New application added to the directory" -Category Others -NotifyUser $notifyUser -ThreatType Activity -Operation "Add application." -Description "Custom alert policy to track when applications are added to the environment" -AggregationType None

## New client credentials added to an application or service principal (could indicate app abuse if otherwise unexpected)
New-ProtectionAlert -Name "New client credentials added to an application" -Category Others -NotifyUser $notifyUser -ThreatType Activity -Operation "Update application – Certificates and secrets" -Description "Custom alert policy to track when certificates or secrets are added to an application" -AggregationType None

## Adding either delegated permissions or application permissions, and new consent grants (could indicate app abuse if otherwise unexpected)
New-ProtectionAlert -Name "Add app role assignment to service principal" -Category Others -NotifyUser $notifyUser -ThreatType Activity -Operation "Add app role assignment to service principal." -Description "Custom alert policy to track when new application permissions are added" -AggregationType None
New-ProtectionAlert -Name "Add delegated permission grant" -Category Others -NotifyUser $notifyUser -ThreatType Activity -Operation "Add delegated permission grant." -Description "Custom alert policy to track when new delegated permissions are added" -AggregationType None
New-ProtectionAlert -Name "Consent to application" -Category Others -NotifyUser $notifyUser -ThreatType Activity -Operation "Consent to application." -Description "Custom alert policy to track when application consent is granted for new permissions." -AggregationType None

## Federation settings are modified or partners are added to the organization (if these events are unexpected, it could mean access is being granted to outside domains or partners)
New-ProtectionAlert -Name "Set federation settings on domain" -Category Others -NotifyUser $notifyUser -ThreatType Activity -Operation "Set federation settings on domain." -Description "Custom alert policy to track when domain federation settings have been modified" -AggregationType None
New-ProtectionAlert -Name "Partner relationship added to the organization" -Category Others -NotifyUser $notifyUser -ThreatType Activity -Operation "Add partner to company." -Description "Custom alert policy to track when partner relationships have been added to the tenant" -AggregationType None

## Conditional Access policy modifications (attackers may want to bypass CA policies, always investigate unexpected changes)
New-ProtectionAlert -Name "Conditional Access policy added" -Category Others -NotifyUser $notifyUser -ThreatType Activity -Operation "Add policy." -Description "Custom alert policy to track when Conditional Access policies are created in Azure AD" -AggregationType None
New-ProtectionAlert -Name "Conditional Access policy updated" -Category Others -NotifyUser $notifyUser -ThreatType Activity -Operation "Update policy." -Description "Custom alert policy to track when Conditional Access policies are updated in Azure AD" -AggregationType None
New-ProtectionAlert -Name "Conditional Access policy deleted" -Category Others -NotifyUser $notifyUser -ThreatType Activity -Operation "Delete policy." -Description "Custom alert policy to track when Conditional Access policies are deleted in Azure AD" -AggregationType None

Write-Host
Write-Host "Script completed." -ForegroundColor Cyan
Write-Host 
Write-Host "You should also add your alerts email address the default protection alerts at: https://protection.office.com/alertpolicies" -ForegroundColor Cyan
Write-Host