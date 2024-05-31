<##################################################################################################
#
.SYNOPSIS
This script installs device filters:
1. Windows-Corporate-Joined
2. Windows-Personal-Registered
3. Windows-Unknown

.NOTES
    FileName:    Install-SmbAdmxConfigs.ps1
    Author:      Alex Fields 
	Based on:    https://github.com/microsoft/mggraph-intune-samples & https://github.com/Azure/securedworkstation
    Created:     May 2024
	Revised:     May 2024
    Version:     1.0 
    
#>
###################################################################################################

#region connect

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

$RequiredScopes = @("DeviceManagementConfiguration.ReadWrite.All")
$RequiredModules = @("Microsoft.Graph.Authentication")

Connect-ToGraph -RequiredScopes $RequiredScopes -RequiredModules $RequiredModules

#endregion

#region functions

function New-DeviceFilter {
    param (
        [string]$jsonData
    )
    
    $url = "https://graph.microsoft.com/beta/deviceManagement/assignmentFilters"

    try {
        $response = Invoke-MgGraphRequest -Method POST -Uri $url -Body $jsonData -ContentType "application/json"
        return $response
    }
    catch {
        Write-Error "An error occurred: $_"
    }
}

#endregion

#region json

$WinCorporate = @"
{
    "displayName": "Windows-Corporate-Joined",
    "platform": "windows10AndLater",
    "assignmentFilterManagementType": "devices",
    "rule": "(device.deviceOwnership -eq \"Corporate\") or (device.deviceTrustType -eq \"Azure AD joined\") or (device.deviceTrustType -eq \"Hybrid Azure AD joined\")"
}
"@

$WinPersonal = @"
{
    "displayName": "Windows-Personal-Registered",
    "platform": "windows10AndLater",
    "assignmentFilterManagementType": "devices",
    "rule": "(device.deviceOwnership -eq \"Personal\") or (device.deviceTrustType -eq \"Azure AD registered\")"
}
"@

$WinUnknown = @"
{
    "displayName": "Windows-Unknown",
    "platform": "windows10AndLater",
    "assignmentFilterManagementType": "devices",
    "rule": "(device.deviceOwnership -eq \"Unknown\") or (device.deviceTrustType -eq \"Unknown\")"
}
"@

#endregion 

#region create filters

New-DeviceFilter -jsonData $WinCorporate

New-DeviceFilter -jsonData $WinPersonal

New-DeviceFilter -jsonData $WinUnknown

#endregion

# Disconnect from Microsoft Graph
Disconnect-MgGraph 