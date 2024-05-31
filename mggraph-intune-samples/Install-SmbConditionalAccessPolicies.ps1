<##################################################################################################
#
.SYNOPSIS
This script installs Conditional Access policies:
01. [SMB] 0.01 - Block legacy authentication
02. [SMB] 0.02 - Require MFA for management
03. [SMB] 0.03 - Require MFA to register or join devices
04. [SMB] 0.04 - Block unknown or unsupported device platforms
05. [SMB] 0.05 - No persistent browser on unmanaged devices
06. [SMB] 1.01 - Require MFA for admins
07. [SMB] 2.01 - Require MFA for internals
08. [SMB] 2.02 - Securing MFA registration for internals
09. [SMB] 2.03 - Require app protection for Office 365 mobile access
10. [SMB] 2.04 - Require compliant device for Office 365 desktop access
11. [SMB] 3.01 - Require MFA for externals

.NOTES
    FileName:    Install-SmbConditionalAccessPolicies.ps1
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
$RequiredScopes = @("Policy.ReadWrite.ConditionalAccess", "Directory.ReadWrite.All")

#Define the required modules
$RequiredModules = @("Microsoft.Graph.Authentication", "Microsoft.Graph.Identity.SignIns")

Connect-ToGraph -RequiredScopes $RequiredScopes -RequiredModules $RequiredModules

#endregion

#region functions

# Function to create a conditional access policy
function New-ConditionalAccessPolicy {
    param (
        [string]$JsonData
    )

    try {
        # Create the conditional access policy
        New-MgIdentityConditionalAccessPolicy -BodyParameter $JsonData -ErrorAction Stop
        Write-Output "Conditional access policy created successfully."
    } catch {
        Write-Error "Error creating conditional access policy: $($_.Exception.Message)" 
        
    }
}

#endregion

#region json 

$smbCa001 = @"
{
    "displayName": "[SMB] 0.01 - Block legacy authentication",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": [
            "exchangeActiveSync",
			"other"
        ],
        "platforms": null,
        "locations": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [
                "All"
            ],
            "excludeApplications": [],
            "includeUserActions": []
        },
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": []
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa002 = @" 
{
    "displayName": "[SMB] 0.02 - Require MFA for management",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": null,
        "platforms": null,
        "locations": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [
                "797f4846-ba00-4fd7-ba43-dac1f8f63013",
                "MicrosoftAdminPortals"
            ],
            "excludeApplications": [],
            "includeUserActions": []
        },
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": []
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "mfa"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa003 = @" 
{
    "displayName": "[SMB] 0.03 - Require MFA to register or join devices",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": null,
        "platforms": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [],
            "excludeApplications": [],
            "includeUserActions": [
                "urn:user:registerdevice"
            ]
        },
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [
                "GuestsOrExternalUsers"
            ],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": []
        },
        "locations": {
            "includeLocations": [
                "All"
            ],
            "excludeLocations": [
                "AllTrusted"
            ]
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "mfa"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa004 = @" 
{
    "displayName": "[SMB] 0.04 - Block unknown or unsupported device platforms",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": [
            "All"
        ],
        "platforms": {
			"includePlatforms":[
				"all"
			],
			"excludePlatforms":[
				"android",
				"iOS",
				"windows",
				"macOS"
			]
		},
        "locations": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [
                "All"
            ],
            "excludeApplications": [],
            "includeUserActions": []
        },
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [
				"GuestsOrExternalUsers"
			],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": []
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "block"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa005 = @" 
{"grantControls":null,"conditions":{"userRiskLevels":[],"signInRiskLevels":[],"clientAppTypes":["all"],"servicePrincipalRiskLevels":[],"insiderRiskLevels":null,"clients":null,"platforms":null,"locations":null,"times":null,"deviceStates":null,"clientApplications":null,"authenticationFlows":null,"applications":{"includeApplications":["All"],"excludeApplications":[],"includeUserActions":[],"includeAuthenticationContextClassReferences":[],"applicationFilter":null,"networkAccess":null,"globalSecureAccess":null},"users":{"includeUsers":["All"],"excludeUsers":[],"includeGroups":[],"excludeGroups":[],"includeRoles":[],"excludeRoles":[],"includeGuestsOrExternalUsers":null,"excludeGuestsOrExternalUsers":null},"devices":{"includeDeviceStates":[],"excludeDeviceStates":[],"includeDevices":[],"excludeDevices":[],"deviceFilter":{"mode":"include","rule":"device.trustType -ne \"ServerAD\" -or device.isCompliant -ne True"}}},"sessionControls":{"disableResilienceDefaults":null,"applicationEnforcedRestrictions":null,"cloudAppSecurity":null,"continuousAccessEvaluation":null,"secureSignInSession":null,"networkAccessSecurity":null,"globalSecureAccessFilteringProfile":null,"signInFrequency":{"value":1,"type":"hours","authenticationType":"primaryAndSecondaryAuthentication","frequencyInterval":"timeBased","isEnabled":true},"persistentBrowser":{"mode":"never","isEnabled":true}},"displayName":"[SMB] 0.05 - No persistent browser on unmanaged devices"}
"@

$smbCa101 = @" 
{
    "displayName": "[SMB] 1.01 - Require MFA for admins",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": null,
        "platforms": null,
        "locations": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [
                "All"
            ],
            "excludeApplications": [],
            "includeUserActions": []
        },
        "users": {
            "includeUsers": [],
            "excludeUsers": [],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [ 
                "62e90394-69f5-4237-9190-012177145e10",
                "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",
                "29232cdf-9323-42fd-ade2-1d097af3e4de",
                "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",
                "194ae4cb-b126-40b2-bd5b-6091b380977d",
                "729827e3-9c14-49f7-bb1b-9608f156bbb8",
                "966707d0-3269-4727-9be2-8c3a10f19b9d",
                "b0f54661-2d74-4c50-afa3-1ec803f12efe",
                "fe930be7-5e62-47db-91af-98c3a49a38b1",
				"c4e39bd9-1100-46d3-8c65-fb160da0071f",
				"9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",
				"158c047a-c907-4556-b7ef-446551a6b5f7",
				"7be44c8a-adaf-4e2a-84d6-ab2649e08a13",
				"e8611ab8-c189-46e8-94e1-60213ab1f814"
            ],
            "excludeRoles": []
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "mfa"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa201 = @" 
{
    "displayName": "[SMB] 2.01 - Require MFA for internals",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": null,
        "platforms": null,
        "locations": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [
                "All"
            ],
            "excludeApplications": [],
            "includeUserActions": []
        },
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeUsers": ["GuestsOrExternalUsers"],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": []
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "mfa"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa202 = @" 
{
    "displayName": "[SMB] 2.02 - Securing MFA registration for internals",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": null,
        "platforms": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [],
            "excludeApplications": [],
            "includeUserActions": [
                "urn:user:registersecurityinfo"
            ]
        },
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [
                "GuestsOrExternalUsers"
            ],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": [
				"62e90394-69f5-4237-9190-012177145e10"
			]
        },
        "locations": {
            "includeLocations": [
                "All"
            ],
            "excludeLocations": [
                "AllTrusted"
            ]
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "mfa"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa203 = @" 
{
    "displayName": "[SMB] 2.03 - Require app protection for Office 365 mobile access",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": null,
        "platforms": {
			"includePlatforms": [
				"android",
				"iOS"
			],
			"excludePlatforms": []
		},		
        "locations": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [
                "Office365"
            ],
            "excludeApplications": [],
            "includeUserActions": []
        },
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeUsers": ["GuestsOrExternalUsers"],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": []
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
			"compliantApplication"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa204 = @" 
{
    "displayName": "[SMB] 2.04 - Require compliant device for Office 365 desktop access",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": null,
        "platforms": {
			"includePlatforms": [
				"windows",
				"macOS"
			],
			"excludePlatforms": []
		},		
        "locations": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [
                "Office365"
            ],
            "excludeApplications": [],
            "includeUserActions": []
        },
        "users": {
            "includeUsers": [
                "All"
            ],
            "excludeUsers": [
				"GuestsOrExternalUsers"
			],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": []
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "compliantDevice"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}
"@

$smbCa301 = @" 

{
    "displayName": "[SMB] 3.01 - Require MFA for externals",
    "createdDateTime": null,
    "modifiedDateTime": null,
    "state": "disabled",
    "sessionControls": null,
    "conditions": {
        "signInRiskLevels": [],
        "clientAppTypes": null,
        "platforms": null,
        "locations": null,
        "deviceStates": null,
        "applications": {
            "includeApplications": [
                "All"
            ],
            "excludeApplications": [],
            "includeUserActions": []
        },
        "users": {
            "includeUsers": [
                "GuestsOrExternalUsers"
            ],
            "excludeUsers": [],
            "includeGroups": [],
            "excludeGroups": [],
            "includeRoles": [],
            "excludeRoles": []
        }
    },
    "grantControls": {
        "operator": "OR",
        "builtInControls": [
            "mfa"
        ],
        "customAuthenticationFactors": [],
        "termsOfUse": []
    }
}

"@

#endregion

#region create policies

New-ConditionalAccessPolicy -JsonData $smbCa001
New-ConditionalAccessPolicy -JsonData $smbCa002
New-ConditionalAccessPolicy -JsonData $smbCa003
New-ConditionalAccessPolicy -JsonData $smbCa004
New-ConditionalAccessPolicy -JsonData $smbCa005
New-ConditionalAccessPolicy -JsonData $smbCa101
New-ConditionalAccessPolicy -JsonData $smbCa201
New-ConditionalAccessPolicy -JsonData $smbCa202
New-ConditionalAccessPolicy -JsonData $smbCa203
New-ConditionalAccessPolicy -JsonData $smbCa204
New-ConditionalAccessPolicy -JsonData $smbCa301

#endregion

# Disconnect from Microsoft Graph
Disconnect-MgGraph