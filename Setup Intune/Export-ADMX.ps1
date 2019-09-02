
<#
http://www.scconfigmgr.com/2019/01/17/use-intune-graph-api-export-and-import-intune-admx-templates/
Version 1.0			 2019 Jan.17 First version
Version 1.0.1		 2019 Jan.21 Fixed bug enable value was wrong
#>

####################################################

function Get-AuthToken
{
	
<#
.SYNOPSIS
This function is used to authenticate with the Graph API REST interface
.DESCRIPTION
The function authenticate with the Graph API Interface with the tenant name
.EXAMPLE
Get-AuthToken
Authenticates you with the Graph API interface
.NOTES
NAME: Get-AuthToken
#>
	
	[cmdletbinding()]
	param
	(
		[Parameter(Mandatory = $true)]
		$User
	)
	
	$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User
	
	$tenant = $userUpn.Host
	
	Write-Host "Checking for AzureAD module..."
	
	$AadModule = Get-Module -Name "AzureAD" -ListAvailable
	
	if ($AadModule -eq $null)
	{
		
		Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
		$AadModule = Get-Module -Name "AzureADPreview" -ListAvailable
		
	}
	
	if ($AadModule -eq $null)
	{
		write-host
		write-host "AzureAD Powershell module not installed..." -f Red
		write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
		write-host "Script can't continue..." -f Red
		write-host
		exit
	}
	
	# Getting path to ActiveDirectory Assemblies
	# If the module count is greater than 1 find the latest version
	
	if ($AadModule.count -gt 1)
	{
		
		$Latest_Version = ($AadModule | select version | Sort-Object)[-1]
		
		$aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }
		
		# Checking if there are multiple versions of the same module found
		
		if ($AadModule.count -gt 1)
		{
			
			$aadModule = $AadModule | select -Unique
			
		}
		
		$adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
		$adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
		
	}
	else
	{
		
		$adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
		$adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"
		
	}
	
	[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null
	
	[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null
	
	$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"
	
	$redirectUri = "urn:ietf:wg:oauth:2.0:oob"
	
	$resourceAppIdURI = "https://graph.microsoft.com"
	
	$authority = "https://login.microsoftonline.com/$Tenant"
	
	try
	{
		
		$authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority
		
		# https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
		# Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession
		
		$platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"
		
		$userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")
		
		$authResult = $authContext.AcquireTokenAsync($resourceAppIdURI, $clientId, $redirectUri, $platformParameters, $userId).Result
		
		# If the accesstoken is valid then create the authentication header
		
		if ($authResult.AccessToken)
		{
			
			# Creating header for Authorization token
			
			$authHeader = @{
				'Content-Type'  = 'application/json'
				'Authorization' = "Bearer " + $authResult.AccessToken
				'ExpiresOn'	    = $authResult.ExpiresOn
			}
			
			return $authHeader
			
		}
		
		else
		{
			
			Write-Host
			Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
			Write-Host
			break
			
		}
		
	}
	
	catch
	{
		
		write-host $_.Exception.Message -f Red
		write-host $_.Exception.ItemName -f Red
		write-host
		break
		
	}
	
}

####################################################

Function Get-GroupPolicyConfigurations()
{
	
<#
.SYNOPSIS
This function is used to get device configuration policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any device configuration policies
.EXAMPLE
Get-DeviceConfigurationPolicy
Returns any device configuration policies configured in Intune
.NOTES
NAME: Get-GroupPolicyConfigurations
#>
	
	[cmdletbinding()]
	
	$graphApiVersion = "Beta"
	$DCP_resource = "deviceManagement/groupPolicyConfigurations"
	
	try
	{
		
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		(Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
		
	}
	
	catch
	{
		
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$responseBody = $reader.ReadToEnd();
		Write-Host "Response content:`n$responseBody" -f Red
		Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		write-host
		break
		
	}
	
}

####################################################
Function Get-GroupPolicyConfigurationsDefinitionValues()
{
	
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-GroupPolicyConfigurations
    #>
	
	[cmdletbinding()]
	Param (
		
		[Parameter(Mandatory = $true)]
		[string]$GroupPolicyConfigurationID
		
	)
	
	$graphApiVersion = "Beta"
	#$DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues?`$filter=enabled eq true"
	$DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues"
	
	
	try
	{
		
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		(Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
		
	}
	
	catch
	{
		
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$responseBody = $reader.ReadToEnd();
		Write-Host "Response content:`n$responseBody" -f Red
		Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		write-host
		break
		
	}
	
}

####################################################
Function Get-GroupPolicyConfigurationsDefinitionValuesPresentationValues()
{
	
    <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-GroupPolicyConfigurations
    #>
	
	[cmdletbinding()]
	Param (
		
		[Parameter(Mandatory = $true)]
		[string]$GroupPolicyConfigurationID,
		[string]$GroupPolicyConfigurationsDefinitionValueID
		
	)
	$graphApiVersion = "Beta"
	
	$DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues/$GroupPolicyConfigurationsDefinitionValueID/presentationValues"
	
	try
	{
		
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		(Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
		
	}
	
	catch
	{
		
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$responseBody = $reader.ReadToEnd();
		Write-Host "Response content:`n$responseBody" -f Red
		Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		write-host
		break
		
	}
	
}

Function Get-GroupPolicyConfigurationsDefinitionValuesdefinition ()
{
   <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-GroupPolicyConfigurations
    #>
	
	[cmdletbinding()]
	Param (
		
		[Parameter(Mandatory = $true)]
		[string]$GroupPolicyConfigurationID,
		[Parameter(Mandatory = $true)]
		[string]$GroupPolicyConfigurationsDefinitionValueID
		
	)
	$graphApiVersion = "Beta"
	$DCP_resource = "deviceManagement/groupPolicyConfigurations/$GroupPolicyConfigurationID/definitionValues/$GroupPolicyConfigurationsDefinitionValueID/definition"
	
	try
	{
		
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		
		$responseBody = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
		
		
	}
	
	catch
	{
		
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$responseBody = $reader.ReadToEnd();
		Write-Host "Response content:`n$responseBody" -f Red
		Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		write-host
		break
		
	}
	$responseBody
}


Function Get-GroupPolicyDefinitionsPresentations ()
{
   <#
    .SYNOPSIS
    This function is used to get device configuration policies from the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and gets any device configuration policies
    .EXAMPLE
    Get-DeviceConfigurationPolicy
    Returns any device configuration policies configured in Intune
    .NOTES
    NAME: Get-GroupPolicyConfigurations
    #>
	
	[cmdletbinding()]
	Param (
		
		
		[Parameter(Mandatory = $true)]
		[string]$groupPolicyDefinitionsID,
		[Parameter(Mandatory = $true)]
		[string]$GroupPolicyConfigurationsDefinitionValueID
		
	)
	$graphApiVersion = "Beta"
	$DCP_resource = "deviceManagement/groupPolicyConfigurations/$groupPolicyDefinitionsID/definitionValues/$GroupPolicyConfigurationsDefinitionValueID/presentationValues?`$expand=presentation"
	try
	{
		
		$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
		
		(Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value.presentation
		
		
	}
	
	catch
	{
		
		$ex = $_.Exception
		$errorResponse = $ex.Response.GetResponseStream()
		$reader = New-Object System.IO.StreamReader($errorResponse)
		$reader.BaseStream.Position = 0
		$reader.DiscardBufferedData()
		$responseBody = $reader.ReadToEnd();
		Write-Host "Response content:`n$responseBody" -f Red
		Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
		write-host
		break
		
	}
	
}


####################################################

####################################################

#region Authentication

write-host

# Checking if authToken exists before running authentication
if ($global:authToken)
{
	
	# Setting DateTime to Universal time to work in all timezones
	$DateTime = (Get-Date).ToUniversalTime()
	
	# If the authToken exists checking when it expires
	$TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes
	
	if ($TokenExpires -le 0)
	{
		
		write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
		write-host
		
		# Defining User Principal Name if not present
		
		if ($User -eq $null -or $User -eq "")
		{
			
			$User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
			Write-Host
			
		}
		
		$global:authToken = Get-AuthToken -User $User
		
	}
}

# Authentication doesn't exist, calling Get-AuthToken function

else
{
	
	if ($User -eq $null -or $User -eq "")
	{
		
		$User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
		Write-Host
		
	}
	
	# Getting the authorization token
	$global:authToken = Get-AuthToken -User $User
	
}

#endregion

####################################################

$ExportPath = Read-Host -Prompt "Please specify a path to export the policy data to e.g. C:\IntuneOutput"

# If the directory path doesn't exist prompt user to create the directory
$ExportPath = $ExportPath.replace('"', '')

if (!(Test-Path "$ExportPath"))
{
	
	Write-Host
	Write-Host "Path '$ExportPath' doesn't exist, do you want to create this directory? Y or N?" -ForegroundColor Yellow
	
	$Confirm = read-host
	
	if ($Confirm -eq "y" -or $Confirm -eq "Y")
	{
		
		new-item -ItemType Directory -Path "$ExportPath" | Out-Null
		Write-Host
		
	}
	
	else
	{
		
		Write-Host "Creation of directory path was cancelled..." -ForegroundColor Red
		Write-Host
		break
		
	}
	
}

####################################################

Write-Host

$DCPs = Get-GroupPolicyConfigurations

foreach ($DCP in $DCPs)
{
	$FolderName = $($DCP.displayName) -replace '\<|\>|:|"|/|\\|\||\?|\*', "_"
	New-Item "$ExportPath\$($FolderName)" -ItemType Directory -Force
	
	$GroupPolicyConfigurationsDefinitionValues = Get-GroupPolicyConfigurationsDefinitionValues -GroupPolicyConfigurationID $DCP.id
	$i = 0
	foreach ($GroupPolicyConfigurationsDefinitionValue in $GroupPolicyConfigurationsDefinitionValues)
	{
		$GroupPolicyConfigurationsDefinitionValue
		$i += 1
		$DefinitionValuePresentationValues = Get-GroupPolicyConfigurationsDefinitionValuesPresentationValues -GroupPolicyConfigurationID $DCP.id -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
		$DefinitionValuedefinition = Get-GroupPolicyConfigurationsDefinitionValuesdefinition -GroupPolicyConfigurationID $DCP.id -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
		
		$DefinitionValuedefinitionID = $($DefinitionValuedefinition.id)
		
		$DefinitionValuedefinitionDisplayName = $($DefinitionValuedefinition.displayName)
		$FileName = $DefinitionValuedefinitionDisplayName + [string]$i
		$FileName = $($fileName) -replace '\<|\>|:|"|/|\\|\||\?|\*', "_"

		$GroupPolicyDefinitionsPresentations = Get-GroupPolicyDefinitionsPresentations -groupPolicyDefinitionsID $DCP.id -GroupPolicyConfigurationsDefinitionValueID $GroupPolicyConfigurationsDefinitionValue.id
		
		if ($GroupPolicyConfigurationsDefinitionValue.enabled -match $true -and $DefinitionValuePresentationValues)
		{
			$JSON_Convert = ConvertTo-Json $DefinitionValuePresentationValues -Depth 5 | ConvertFrom-Json | Select-Object -Property * -ExcludeProperty id, createdDateTime, lastModifiedDateTime, version
			$JSON_Output = $JSON_Convert | ConvertTo-Json
			
			#If settings is set as Enabled
			if ($DefinitionValuePresentationValues.value -match "True")
			{
				$jsonCode = @"
{
   "enabled":$($GroupPolicyConfigurationsDefinitionValue.enabled.tostring().Replace("True", "true")),
   "presentationValues":[  
      {  
         <!PLACEHOLDER!>,
         "presentation@odata.bind":"https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($DefinitionValuedefinitionID)')/presentations('$($GroupPolicyDefinitionsPresentations.id)')"
      }
   ],
   "definition@odata.bind":"https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($DefinitionValuedefinitionID)')"
}
"@
				
				$jsonCodePLACEHOLDER = $JSON_Output.Substring(1)
				$jsonCodePLACEHOLDER = $jsonCodePLACEHOLDER.Replace("<!PLACEHOLDER!>", $_).Substring(0, $jsonCodePLACEHOLDER.Length - 1)
				$jsonCode = $jsonCode.Replace("<!PLACEHOLDER!>", $jsonCodePLACEHOLDER).Replace("True", "true")
				write-host "Exporting setting $($DefinitionValuedefinitionDisplayName) to folder $ExportPath\$($FolderName)\$FileName.json" -ForegroundColor Yellow
				New-Item "$ExportPath\$($FolderName)\$FileName.json" -ItemType File -Force
				$jsonCode | Set-Content -LiteralPath "$ExportPath\$($FolderName)\$FileName.json" -Force
			}
			else
			{
				$jsonCode = @"
{
   "enabled":$($GroupPolicyConfigurationsDefinitionValue.enabled.tostring().Replace("True", "true")),
   "presentationValues":[  
      {  
         <!PLACEHOLDER!>,
         "presentation@odata.bind":"https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($DefinitionValuedefinitionID)')/presentations('$($GroupPolicyDefinitionsPresentations.id)')"
      }
   ],
   "definition@odata.bind":"https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($DefinitionValuedefinitionID)')"
}
"@
				
				$jsonCodePLACEHOLDER = $JSON_Output.Substring(1)
				$jsonCodePLACEHOLDER = $jsonCodePLACEHOLDER.Replace("<!PLACEHOLDER!>", $_).Substring(0, $jsonCodePLACEHOLDER.Length - 1)
				$jsonCode = $jsonCode.Replace("<!PLACEHOLDER!>", $jsonCodePLACEHOLDER)
				write-host "Exporting setting $($DefinitionValuedefinitionDisplayName) to folder $ExportPath\$($FolderName)\$FileName.json" -ForegroundColor Yellow
				New-Item "$ExportPath\$($FolderName)\$FileName.json" -ItemType File -Force
				$jsonCode | Set-Content -LiteralPath "$ExportPath\$($FolderName)\$FileName.json" -Force
			}
		}
		else
		{
			
			$jsonCode = @"
{
   "enabled":$($GroupPolicyConfigurationsDefinitionValue.enabled.tostring().Replace("True", "true").Replace("False", "false")),
    "definition@odata.bind":"https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('$($DefinitionValuedefinitionID)')"
}
"@
			write-host "Exporting setting $($DefinitionValuedefinitionDisplayName) to folder $ExportPath\$($FolderName)\$FileName.json" -ForegroundColor Yellow
			New-Item "$ExportPath\$($FolderName)\$FileName.json" -ItemType File -Force
			$jsonCode | Out-File "$ExportPath\$($FolderName)\$FileName.json" -Encoding ascii -Force
		}
		
	}
}

Write-Host
#