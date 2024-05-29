<##################################################################################################
#
.SYNOPSIS
This script installs ADMX configuration profiles from JSON:
1. [SMB] Windows - OneDrive for Business client
2. [SMB] Windows - Edge browser baseline

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
$RequiredScopes = @("Directory.Read.All", "DeviceManagementConfiguration.ReadWrite.All")

#Define the required modules
$RequiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.DeviceManagement")

#Connect to the graph with required modules and scopes
Connect-ToGraph -RequiredScopes $RequiredScopes -RequiredModules $RequiredModules

#endregion

#region functions

#Function to create a group policy configuration
function New-GroupPolicyConfiguration {
    param (
        [string]$DisplayName,
        [string]$Description
    )

    try {
        # Create the device configuration profile (Group Policy Configuration)
        $profile = New-Object -TypeName PSCustomObject -Property @{
            "@odata.type" = "#microsoft.graph.groupPolicyConfiguration"
            "displayName" = $DisplayName
            "description" = $Description
        }

        # Convert the profile to JSON
        $profileJson = $profile | ConvertTo-Json -Depth 10

        # Define the Graph API URI for creating group policy config profiles
        $graphUri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations"
        
        # Create the configuration profile using the provided JSON
        $response = Invoke-MgGraphRequest -Method POST -Uri $graphUri -Body $profileJson -ContentType "application/json"

        # Return the ID of the created profile
        return $response.id
    }
    catch {
        Write-Error "An error occurred while creating the group policy configuration: $($_.Exception.Message)"
    }
}

#Function to install group policy definition values
function Set-GroupPolicyDefinitionValues {
    param (
        [string]$ProfileId,
        [string]$JsonData
    )

    try {
        # Convert the JSON data to a PowerShell object
        $policyData = $JsonData | ConvertFrom-Json

        # Add the definition values to the created profile
        foreach ($definition in $policyData) {
            $definitionJson = $definition | ConvertTo-Json -Depth 10
            $uri = "https://graph.microsoft.com/beta/deviceManagement/groupPolicyConfigurations/$ProfileId/definitionValues"
            Invoke-MgGraphRequest -Method POST -Uri $uri -Body $definitionJson -ContentType "application/json"
        }
    }
    catch {
        Write-Error "An error occurred while setting group policy definition values: $($_.Exception.Message)"
    }
}

#Function to retrieve the tenant ID
function Get-TenantID {
    try {
        # Retrieve and store tenant ID in a variable
        $tenantID = Get-MgOrganization | Select-Object -ExpandProperty Id

        # Check if tenantID was successfully retrieved
        if ($null -eq $tenantID) {
            throw "Failed to retrieve the tenant ID."
        }

        # Output tenant ID
        Write-Output $tenantID
    }
    catch {
        # Handle errors and output the error message
        Write-Error "An error occurred while retrieving the tenant ID: $_"
    }
}

#endregion

#region json

# Define the JSON data
$smbEdgeBrowser = @"
[
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('06b9c400-f1ed-4046-b8cb-02af3ae8e38d')",
        "enabled":  "true"
    },
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('59922037-5107-4eaf-a72f-249a73c08d16')",
        "enabled":  "true"
    },
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('6189eace-13bd-435e-b438-2f38495bf9cc')",
        "enabled":  "false"
    },
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('270e643f-a1dd-49eb-8365-8292e9d6c7f7')",
        "enabled":  "true"
    },
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('fdfedea9-c9d1-4109-9b59-883cfe2d861a')",
        "enabled":  "true",
        "presentationValues":  [
                                   {
                                       "@odata.type":  "#microsoft.graph.groupPolicyPresentationValueText",
                                       "value":  "ntlm,negotiate",
                                       "presentation@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('fdfedea9-c9d1-4109-9b59-883cfe2d861a')/presentations('e6b8ffac-8e06-4a30-95c6-cec2dfc1a08f')"
                                   }
                               ]
    },
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('bc6a79f3-77d4-462c-9924-8ea74dc34386')",
        "enabled":  "false"
    },
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('ccfd2123-ff05-4680-a4eb-ab2790b6d6ed')",
        "enabled":  "false"
    },
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('6f317cd9-3683-476b-adea-b93eb74e07c1')",
        "enabled":  "true"
    },
    {
        "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('f9de5937-2ff5-4c34-a5ec-d0d997787b68')",
        "enabled":  "true"
    }
]
"@

$smbOdfbClient = @"
[
{
    "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('81c07ba0-7512-402d-b1f6-00856975cfab')",
    "enabled":  "true"
},
{
    "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('61b07a01-7e60-4127-b086-f6b32458a5c5')",
    "enabled":  "true"
},
{
    "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('2ce2f507-aae8-49a1-98ce-dc3faafcd331')",
    "enabled":  "true"
},
{
    "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('24bec81e-a596-4fc1-867b-0256114a19a4')",
    "enabled":  "true",
    "presentationValues":  [
                               {
                                   "@odata.type":  "#microsoft.graph.groupPolicyPresentationValueText",
                                   "value":  "$myTenantID",
                                   "presentation@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('24bec81e-a596-4fc1-867b-0256114a19a4')/presentations('4640c3f7-b89a-41be-948b-e86a2a97cae4')"
                               }
                           ]
},
{
    "definition@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('39147fa2-6c5e-437b-8264-19b50b891709')",
    "enabled":  "true",
    "presentationValues":  [
                               {
                                   "@odata.type":  "#microsoft.graph.groupPolicyPresentationValueText",
                                   "value":  "$myTenantID",
                                   "presentation@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('39147fa2-6c5e-437b-8264-19b50b891709')/presentations('fbefbbdf-5382-477c-8b6c-71f4a06e2805')"
                               }
                           ]
}
]
"@

#endregion

#region create policies

#Retrieve the tenant ID
$myTenantID = Get-TenantID

#Create the OneDrive profile
$profileId = New-GroupPolicyConfiguration -DisplayName "[SMB] Windows - OneDrive client" -Description "Settings for the OneDrive client."

#Populate the definition values
Set-GroupPolicyDefinitionValues -ProfileId $profileId -JsonData $smbOdfbClient

# Create the Edge profile
$profileId = New-GroupPolicyConfiguration -DisplayName "[SMB] Windows - Edge browser" -Description "Security baseline for the Microsoft Edge browser."

# Populate the definition values
Set-GroupPolicyDefinitionValues -ProfileId $profileId -JsonData $smbEdgeBrowser

#endregion

# Disconnect from Microsoft Graph
Disconnect-MgGraph