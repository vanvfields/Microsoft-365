<##################################################################################################
#
.SYNOPSIS
This script installs device compliance policies from JSON:
1. [SMB] Windows - Immediate compliance
2. [SMB] Windows - Delayed compliance
3. [SMB] Windows - Defender compliance

.NOTES
    FileName:    Install-SmbCompliancePolicies.ps1
    Author:      Alex Fields 
	Based on:    https://github.com/microsoft/mggraph-intune-samples & https://github.com/Azure/securedworkstation
    Created:     May 2024
	Revised:     May 2024
    Version:     1.0 
    
#>
###################################################################################################

#region connect

# Function to connect to Microsoft Graph
function Connect-ToGraph {
    param (
        [string[]]$RequiredScopes,
        [string[]]$RequiredModules
    )

    # Import required modules
    foreach ($module in $RequiredModules) {
        try {
            #Import the module
            Import-Module -Name $module -ErrorAction Stop
        }
        catch {
            Write-Host "Failed to import $module module. Please install the module first."
            return
        }

    }

    try {
        # Connect to Microsoft Graph using Connect-MgGraph
        Connect-MgGraph -Scopes $RequiredScopes -ErrorAction Stop
        Write-Host "Successfully connected to Microsoft Graph with scopes: $($RequiredScopes -join ', ')"
    }
    catch {
        Write-Host "Failed to connect to Microsoft Graph. Please check your credentials and try again."
        Write-Host "Error: $($_.Exception.Message)"
    }
}

#Define the required scopes
$RequiredScopes = @("DeviceManagementConfiguration.ReadWrite.All")

#Define the required modules
$RequiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.DeviceManagement")

#Connect to the graph with required modules and scopes
Connect-ToGraph -RequiredScopes $RequiredScopes -RequiredModules $RequiredModules

#endregion

#region functions

#Function to create a compliance policy
function New-CompliancePolicy {
    param (
        [Parameter(Mandatory = $true)]
        [string]$JsonData
    )

    try {
        # Define the Graph API URI for creating compliance policies
        $graphUri = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies"

        # Create the compliance policy in Microsoft Graph using Invoke-MgGraphRequest
        $response = Invoke-MgGraphRequest -Method POST -Uri $graphUri -Body $JsonData -ContentType "application/json"
        
        Write-Output "Compliance policy created successfully."
    }
    catch {
        Write-Error "Failed to create compliance policy: $($_.Exception.Message)"
    }
}

#endregion

#region json

$smbImmediate = @'
{
    "@odata.type":  "#microsoft.graph.windows10CompliancePolicy",
    "description":  "Intune compliance settings to apply immediately\n",
    "displayName":  "[SMB] Windows - Immediate compliance",
    "osMinimumVersion":  "10.0.19045.0",
    "bitLockerEnabled":  false,
    "secureBootEnabled":  false,
    "codeIntegrityEnabled":  false,
    "storageRequireEncryption":  false,
    "activeFirewallRequired":  false,
    "defenderEnabled":  true,
    "defenderVersion":  null,
    "signatureOutOfDate":  false,
    "rtpEnabled":  true,
    "antivirusRequired":  false,
    "antiSpywareRequired":  false,
    "deviceThreatProtectionEnabled":  false,
    "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
    "tpmRequired":  false,
    "scheduledActionsForRule":  [
        {
            "ruleName":  null,
            "@odata.type":  "#microsoft.graph.deviceComplianceScheduledActionForRule",
            "scheduledActionConfigurations":  [
                {
                    "gracePeriodHours":  0,
                    "actionType":  "block",
                    "notificationTemplateId":  ""
                }
            ]
        }
    ]
}
'@

$smbDelayed = @'
{
    "@odata.type":  "#microsoft.graph.windows10CompliancePolicy",
    "description":  "Intune compliance settings to apply after a 24 hour grace period\n",
    "displayName":  "[SMB] Windows - Delayed compliance",
    "osMinimumVersion":  "10.0.19045.0",
    "bitLockerEnabled":  true,
    "secureBootEnabled":  true,
    "codeIntegrityEnabled":  true,
    "storageRequireEncryption":  false,
    "activeFirewallRequired":  true,
    "defenderEnabled":  true,
    "defenderVersion":  null,
    "signatureOutOfDate":  true,
    "rtpEnabled":  true,
    "antivirusRequired":  true,
    "antiSpywareRequired":  true,
    "deviceThreatProtectionEnabled":  false,
    "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
    "tpmRequired":  true,
    "scheduledActionsForRule":  [
        {
            "ruleName":  null,
            "@odata.type":  "#microsoft.graph.deviceComplianceScheduledActionForRule",
            "scheduledActionConfigurations":  [
                {
                    "gracePeriodHours":  24,
                    "actionType":  "block",
                    "notificationTemplateId":  ""
                }
            ]
        }
    ]
}
'@

$smbDefender = @'
{
    "@odata.type":  "#microsoft.graph.windows10CompliancePolicy",
    "description":  "Defender for Business compliance settings to apply after 24 hour grace period\n",
    "displayName":  "[SMB] Windows - Defender compliance",
    "deviceThreatProtectionEnabled":  true,
    "deviceThreatProtectionRequiredSecurityLevel":  "low",
    "scheduledActionsForRule":  [
        {
            "ruleName":  null,
            "@odata.type":  "#microsoft.graph.deviceComplianceScheduledActionForRule",
            "scheduledActionConfigurations":  [
                {
                    "gracePeriodHours":  24,
                    "actionType":  "block",
                    "notificationTemplateId":  ""
                }
            ]
        }
    ]
}
'@

#endregion

#region create policies

New-CompliancePolicy -JsonData $smbImmediate
New-CompliancePolicy -JsonData $smbDelayed
New-CompliancePolicy -JsonData $smbDefender

#endregion

#Disconnect from Microsoft Graph
Disconnect-MgGraph
