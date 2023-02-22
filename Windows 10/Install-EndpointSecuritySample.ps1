<##################################################################################################
#
.SYNOPSIS
This script imports some samples of Endpoint security policies as well as Device configuraiton profiles

Please read about and test the impacts of each policy before assigning to users/devices.

.SOURCE
https://github.com/vanvfields/Microsoft-365/

All scripts offered without warranty of any kind.

The functions contained in this script are from the Graph samples published by Microsoft on GitHub:
https://github.com/microsoftgraph/powershell-intune-samples

.NOTES
    FileName:    Install-EndpointSecuritySample.ps1
    Author:      Alex Fields (ITProMentor.com)
    Created:     October 2019
	Revised:     February 2023
    
#>
###################################################################################################

#region Functions

function Get-AuthToken {

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
    [Parameter(Mandatory=$true)]
    $User
)

$userUpn = New-Object "System.Net.Mail.MailAddress" -ArgumentList $User

$tenant = $userUpn.Host

Write-Host "Checking for AzureAD module..."

    $AadModule = Get-Module -Name "AzureAD" -ListAvailable

    if ($AadModule -eq $null) {

        Write-Host "AzureAD PowerShell module not found, looking for AzureADPreview"
        $AadModule = Get-Module -Name "AzureADPreview" -ListAvailable

    }

    if ($AadModule -eq $null) {
        write-host
        write-host "AzureAD Powershell module not installed..." -f Red
        write-host "Install by running 'Install-Module AzureAD' or 'Install-Module AzureADPreview' from an elevated PowerShell prompt" -f Yellow
        write-host "Script can't continue..." -f Red
        write-host
        exit
    }

# Getting path to ActiveDirectory Assemblies
# If the module count is greater than 1 find the latest version

    if($AadModule.count -gt 1){

        $Latest_Version = ($AadModule | select version | Sort-Object)[-1]

        $aadModule = $AadModule | ? { $_.version -eq $Latest_Version.version }

            # Checking if there are multiple versions of the same module found

            if($AadModule.count -gt 1){

            $aadModule = $AadModule | select -Unique

            }

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

    else {

        $adal = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.dll"
        $adalforms = Join-Path $AadModule.ModuleBase "Microsoft.IdentityModel.Clients.ActiveDirectory.Platform.dll"

    }

[System.Reflection.Assembly]::LoadFrom($adal) | Out-Null

[System.Reflection.Assembly]::LoadFrom($adalforms) | Out-Null

$clientId = "d1ddf0e4-d672-4dae-b554-9d5bdfd93547"

$redirectUri = "urn:ietf:wg:oauth:2.0:oob"

$resourceAppIdURI = "https://graph.microsoft.com"

$authority = "https://login.microsoftonline.com/$Tenant"

    try {

    $authContext = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext" -ArgumentList $authority

    # https://msdn.microsoft.com/en-us/library/azure/microsoft.identitymodel.clients.activedirectory.promptbehavior.aspx
    # Change the prompt behaviour to force credentials each time: Auto, Always, Never, RefreshSession

    $platformParameters = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.PlatformParameters" -ArgumentList "Auto"

    $userId = New-Object "Microsoft.IdentityModel.Clients.ActiveDirectory.UserIdentifier" -ArgumentList ($User, "OptionalDisplayableId")

    $authResult = $authContext.AcquireTokenAsync($resourceAppIdURI,$clientId,$redirectUri,$platformParameters,$userId).Result

        # If the accesstoken is valid then create the authentication header

        if($authResult.AccessToken){

        # Creating header for Authorization token

        $authHeader = @{
            'Content-Type'='application/json'
            'Authorization'="Bearer " + $authResult.AccessToken
            'ExpiresOn'=$authResult.ExpiresOn
            }

        return $authHeader

        }

        else {

        Write-Host
        Write-Host "Authorization Access Token is null, please re-run authentication..." -ForegroundColor Red
        Write-Host
        break

        }

    }

    catch {

    write-host $_.Exception.Message -f Red
    write-host $_.Exception.ItemName -f Red
    write-host
    break

    }

}

####################################################

Function Test-JSON(){

<#
.SYNOPSIS
This function is used to test if the JSON passed to a REST Post request is valid
.DESCRIPTION
The function tests if the JSON passed to the REST Post is valid
.EXAMPLE
Test-JSON -JSON $JSON
Test if the JSON is valid before calling the Graph REST interface
.NOTES
NAME: Test-AuthHeader
#>

param (

$JSON

)

    try {

    $TestJSON = ConvertFrom-Json $JSON -ErrorAction Stop
    $validJson = $true

    }

    catch {

    $validJson = $false
    $_.Exception

    }

    if (!$validJson){

    Write-Host "Provided JSON isn't in valid JSON format" -f Red
    break

    }

}

####################################################

Function Add-DeviceConfigurationPolicy(){

<#
.SYNOPSIS
This function is used to add an device configuration policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device configuration policy
.EXAMPLE
Add-DeviceConfigurationPolicy -JSON $JSON
Adds a device configuration policy in Intune
.NOTES
NAME: Add-DeviceConfigurationPolicy
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$DCP_resource = "deviceManagement/deviceConfigurations"
Write-Verbose "Resource: $DCP_resource"

    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for the Android Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

        }

    }

    catch {

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

Function Create-GroupPolicyConfigurations(){
		
<#
.SYNOPSIS
This function is used to add an device configuration policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a device configuration policy
.EXAMPLE
Add-DeviceConfigurationPolicy -JSON $JSON
Adds a device configuration policy in Intune
.NOTES
NAME: Add-DeviceConfigurationPolicy
#>
		
		[cmdletbinding()]
		param
		(
			$DisplayName,
            $PolicyDescription
		)
		
		$jsonCode = @"
{
    "description":"$($PolicyDescription)",
    "displayName":"$($DisplayName)"
}
"@
		
		$graphApiVersion = "Beta"
		$DCP_resource = "deviceManagement/groupPolicyConfigurations"
		Write-Verbose "Resource: $DCP_resource"
		
		try
		{
			
			$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
			$responseBody = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $jsonCode -ContentType "application/json"
			
			
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
		$responseBody.id
}
	
####################################################
	
Function Create-GroupPolicyConfigurationsDefinitionValues(){
		
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
			
			[string]$GroupPolicyConfigurationID,
			$JSON
			
		)
		
		$graphApiVersion = "Beta"
		
		$DCP_resource = "deviceManagement/groupPolicyConfigurations/$($GroupPolicyConfigurationID)/definitionValues"
		write-host $DCP_resource
		try
		{
			if ($JSON -eq "" -or $JSON -eq $null)
			{
				
				write-host "No JSON specified, please specify valid JSON for the Device Configuration Policy..." -f Red
				
			}
			
			else
			{
				
				Test-JSON -JSON $JSON
				
				$uri = "https://graph.microsoft.com/$graphApiVersion/$($DCP_resource)"
				Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"
			}
			
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

Function Add-EndpointSecurityPolicy(){

<#
.SYNOPSIS
This function is used to add an Endpoint Security policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds an Endpoint Security  policy
.EXAMPLE
Add-EndpointSecurityDiskEncryptionPolicy -JSON $JSON -TemplateId $templateId
Adds an Endpoint Security Policy in Endpoint Manager
.NOTES
NAME: Add-EndpointSecurityPolicy
#>

[cmdletbinding()]

param
(
    $TemplateId,
    $JSON
)

$graphApiVersion = "Beta"
$ESP_resource = "deviceManagement/templates/$TemplateId/createInstance"
Write-Verbose "Resource: $ESP_resource"

    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for the Endpoint Security Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

        }

    }
    
    catch {

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

Function Get-EndpointSecurityTemplate(){

<#
.SYNOPSIS
This function is used to get all Endpoint Security templates using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets all Endpoint Security templates
.EXAMPLE
Get-EndpointSecurityTemplate 
Gets all Endpoint Security Templates in Endpoint Manager
.NOTES
NAME: Get-EndpointSecurityTemplate
#>


$graphApiVersion = "Beta"
$ESP_resource = "deviceManagement/templates?`$filter=(isof(%27microsoft.graph.securityBaselineTemplate%27))"

    try {

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($ESP_resource)"
        (Invoke-RestMethod -Method Get -Uri $uri -Headers $authToken).value

    }
    
    catch {

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

Function Get-EnterpriseDomain(){



<#

.SYNOPSIS

This function is used to get the initial domain created using the Graph API REST interface

.DESCRIPTION

The function connects to the Graph API Interface and gets the initial domain created

.EXAMPLE

Get-EnterpriseDomain

Gets the initial domain created in Azure - Format domain.onmicrosoft.com

.NOTES

NAME: Get-EnterpriseDomain

#>



    try {



    $uri = "https://graph.microsoft.com/v1.0/domains"



    $domains = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value



    $EnterpriseDomain = ($domains | ? { $_.isInitial -eq $true } | select id).id



    return $EnterpriseDomain



    }



    catch {



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

Function Get-TenantID(){



<#

.SYNOPSIS

This function is used to get the tenant ID using the Graph API REST interface

.DESCRIPTION

The function connects to the Graph API Interface and gets the tenant ID

.EXAMPLE

Get-TenantID

Gets the unique ID of this tenant in Azure - Format xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

.NOTES

NAME: Get-TenantID

#>



    try {



    $uri = "https://graph.microsoft.com/v1.0/organization"
    
    $organziation = (Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get).Value
    
    $TenantID = ($organziation | select id).id
    
    return $TenantID
    
    }



    catch {
    
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

#endregion

#region Authentication

write-host

# Checking if authToken exists before running authentication
if($global:authToken){

    # Setting DateTime to Universal time to work in all timezones
    $DateTime = (Get-Date).ToUniversalTime()

    # If the authToken exists checking when it expires
    $TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes

        if($TokenExpires -le 0){

        write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
        write-host

            # Defining User Principal Name if not present

            if($User -eq $null -or $User -eq ""){

            $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
            Write-Host

            }

        $global:authToken = Get-AuthToken -User $User

        }
}

# Authentication doesn't exist, calling Get-AuthToken function

else {

    if($User -eq $null -or $User -eq ""){

    $User = Read-Host -Prompt "Please specify your user principal name for Azure Authentication"
    Write-Host

    }

# Getting the authorization token
$global:authToken = Get-AuthToken -User $User

}

#endregion

#region Variables

$TenantID = Get-TenantID
$EnterpriseDomain = Get-EnterpriseDomain
$Sharepoint = $EnterpriseDomain.Split(".")[0]

$Templates = Get-EndpointSecurityTemplate 

#$IDASR = "0e237410-1367-4844-bd7f-15fb0f08943b"
$TempASR = $Templates |Where-Object displayName -eq "Attack surface reduction rules"
$IDASR = $TempASR.id

#$IDDC = "4648b50e-d3ef-4ba0-848e-b0ef561b3aa5"
$TempDC = $Templates |Where-Object displayName -eq "Device control"
$IDDC = $TempDC.id

#$IDBL = "d1174162-1dd2-4976-affc-6667049ab0ae"
$TempBL = $Templates |Where-Object displayName -eq "BitLocker"
$IDBL = $TempBL.id

#$IDAC = "0f2b5d70-d4e9-4156-8c16-1397eb6c54a5"
$TempAC = $Templates |Where-Object displayName -eq "Account protection (Preview)"
$IDAC = $TempAC.id

#endregion

#region JSON representations

####################################################

$Config_WinDefaultUpdate = @"
{
    "@odata.type":  "#microsoft.graph.windowsUpdateForBusinessConfiguration",
    "deviceManagementApplicabilityRuleOsEdition":  null,
    "deviceManagementApplicabilityRuleOsVersion":  null,
    "deviceManagementApplicabilityRuleDeviceMode":  null,
    "description":  "Applies updates via the Semi-annual channel without delay.",
    "displayName":  "[ITPM Standard] Default Update Ring",
    "deliveryOptimizationMode":  "userDefined",
    "prereleaseFeatures":  "userDefined",
    "automaticUpdateMode":  "autoInstallAtMaintenanceTime",
    "microsoftUpdateServiceAllowed":  true,
    "driversExcluded":  false,
    "qualityUpdatesDeferralPeriodInDays":  0,
    "featureUpdatesDeferralPeriodInDays":  0,
    "qualityUpdatesPaused":  false,
    "featureUpdatesPaused":  false,
    "qualityUpdatesPauseExpiryDateTime":  "0001-01-01T00:00:00Z",
    "featureUpdatesPauseExpiryDateTime":  "0001-01-01T00:00:00Z",
    "businessReadyUpdatesOnly":  "businessReadyOnly",
    "skipChecksBeforeRestart":  false,
    "updateWeeks":  null,
    "qualityUpdatesPauseStartDate":  null,
    "featureUpdatesPauseStartDate":  null,
    "featureUpdatesRollbackWindowInDays":  21,
    "qualityUpdatesWillBeRolledBack":  false,
    "featureUpdatesWillBeRolledBack":  false,
    "qualityUpdatesRollbackStartDateTime":  "0001-01-01T00:00:00Z",
    "featureUpdatesRollbackStartDateTime":  "0001-01-01T00:00:00Z",
    "engagedRestartDeadlineInDays":  null,
    "engagedRestartSnoozeScheduleInDays":  null,
    "engagedRestartTransitionScheduleInDays":  null,
    "deadlineForFeatureUpdatesInDays":  null,
    "deadlineForQualityUpdatesInDays":  null,
    "deadlineGracePeriodInDays":  null,
    "postponeRebootUntilAfterDeadline":  null,
    "autoRestartNotificationDismissal":  "notConfigured",
    "scheduleRestartWarningInHours":  4,
    "scheduleImminentRestartWarningInMinutes":  15,
    "userPauseAccess":  "enabled",
    "userWindowsUpdateScanAccess":  "enabled",
    "updateNotificationLevel":  "restartWarningsOnly",
    "installationSchedule":  {
                                 "@odata.type":  "#microsoft.graph.windowsUpdateActiveHoursInstall",
                                 "activeHoursStart":  "08:00:00.0000000",
                                 "activeHoursEnd":  "18:00:00.0000000"
                             }
}


"@

####################################################

$Config_WinDelayedUpdate = @"

{
    "@odata.type":  "#microsoft.graph.windowsUpdateForBusinessConfiguration",
    "deviceManagementApplicabilityRuleOsEdition":  null,
    "deviceManagementApplicabilityRuleOsVersion":  null,
    "deviceManagementApplicabilityRuleDeviceMode":  null,
    "description":  "This update ring delays quality updates by one week and feature updates by two weeks.",
    "displayName":  "[ITPM Standard] Delayed Update Ring",
    "deliveryOptimizationMode":  "userDefined",
    "prereleaseFeatures":  "userDefined",
    "automaticUpdateMode":  "autoInstallAtMaintenanceTime",
    "microsoftUpdateServiceAllowed":  true,
    "driversExcluded":  false,
    "qualityUpdatesDeferralPeriodInDays":  7,
    "featureUpdatesDeferralPeriodInDays":  14,
    "qualityUpdatesPaused":  false,
    "featureUpdatesPaused":  false,
    "qualityUpdatesPauseExpiryDateTime":  "0001-01-01T00:00:00Z",
    "featureUpdatesPauseExpiryDateTime":  "0001-01-01T00:00:00Z",
    "businessReadyUpdatesOnly":  "businessReadyOnly",
    "skipChecksBeforeRestart":  false,
    "updateWeeks":  null,
    "qualityUpdatesPauseStartDate":  null,
    "featureUpdatesPauseStartDate":  null,
    "featureUpdatesRollbackWindowInDays":  21,
    "qualityUpdatesWillBeRolledBack":  false,
    "featureUpdatesWillBeRolledBack":  false,
    "qualityUpdatesRollbackStartDateTime":  "0001-01-01T00:00:00Z",
    "featureUpdatesRollbackStartDateTime":  "0001-01-01T00:00:00Z",
    "engagedRestartDeadlineInDays":  null,
    "engagedRestartSnoozeScheduleInDays":  null,
    "engagedRestartTransitionScheduleInDays":  null,
    "deadlineForFeatureUpdatesInDays":  null,
    "deadlineForQualityUpdatesInDays":  null,
    "deadlineGracePeriodInDays":  null,
    "postponeRebootUntilAfterDeadline":  null,
    "autoRestartNotificationDismissal":  "notConfigured",
    "scheduleRestartWarningInHours":  4,
    "scheduleImminentRestartWarningInMinutes":  15,
    "userPauseAccess":  "enabled",
    "userWindowsUpdateScanAccess":  "enabled",
    "updateNotificationLevel":  "restartWarningsOnly",
    "installationSchedule":  {
                                 "@odata.type":  "#microsoft.graph.windowsUpdateActiveHoursInstall",
                                 "activeHoursStart":  "08:00:00.0000000",
                                 "activeHoursEnd":  "18:00:00.0000000"
                             }
}


"@

####################################################

$GPO_ODfBClient = @"
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
                                   "value":  "$TenantID",
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
                                   "value":  "$TenantID",
                                   "presentation@odata.bind":  "https://graph.microsoft.com/beta/deviceManagement/groupPolicyDefinitions('39147fa2-6c5e-437b-8264-19b50b891709')/presentations('fbefbbdf-5382-477c-8b6c-71f4a06e2805')"
                               }
                           ]
}
]
"@

####################################################

$ES_BitLockerRD = @"

{
    "displayName":  "[ITPM Standard] BitLocker silent deployment with removable drive protection",
    "description":  "This policy enables BitLocker in Silent mode, and also requires encryption of removable media.",
    "settingsDelta":  [
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "62e544ef-e23d-4814-af1e-7bcb9d5f2549",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerEncryptDevice",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "4ae32cce-8c0e-4266-bb8c-3847386f22e0",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerEnableStorageCardEncryptionOnMobile",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "f2c484d5-92d2-4b01-b40f-8e12b67795df",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerDisableWarningForOtherDiskEncryption",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "10dced42-008b-4c91-b408-a5da962d1ac7",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerAllowStandardUserEncryption",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "667526b5-e5c0-4d43-9ef8-8307e961dfa4",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerRecoveryPasswordRotation",
                              "valueJson":  "\"enabledForAzureAd\"",
                              "value":  "enabledForAzureAd"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementComplexSettingInstance",
                              "id":  "f8f09a56-42ae-4f92-8b15-4794d1b87305",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerSystemDrivePolicy",
                              "valueJson":  "{\"startupAuthenticationRequired\":true,\"startupAuthenticationTpmUsage\":\"required\",\"startupAuthenticationTpmPinUsage\":null,\"startupAuthenticationTpmKeyUsage\":\"blocked\",\"startupAuthenticationTpmPinAndKeyUsage\":null,\"startupAuthenticationBlockWithoutTpmChip\":true,\"prebootRecoveryEnableMessageAndUrl\":false,\"prebootRecoveryMessage\":null,\"prebootRecoveryUrl\":null,\"recoveryOptions\":{\"recoveryKeyUsage\":\"allowed\",\"recoveryInformationToStore\":null,\"enableRecoveryInformationSaveToStore\":true,\"recoveryPasswordUsage\":\"allowed\",\"hideRecoveryOptions\":true,\"enableBitLockerAfterRecoveryInformationToStore\":false,\"blockDataRecoveryAgent\":true},\"encryptionMethod\":\"xtsAes256\",\"minimumPinLength\":null}",
                              "value":  [
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "3fba96d1-732c-4c66-80a9-82d506a9d5ad",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_startupAuthenticationRequired",
                                                "valueJson":  "true",
                                                "value":  true
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "e84817a4-7345-4712-8d36-9329199f84e1",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_startupAuthenticationTpmUsage",
                                                "valueJson":  "\"required\"",
                                                "value":  "required"
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "2f9c7745-ef64-4648-a6bb-82f33b2baf5e",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_startupAuthenticationTpmPinUsage",
                                                "valueJson":  "null",
                                                "value":  null
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "6bb1be19-67ec-4dd7-a50b-47c9edb75f95",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_startupAuthenticationTpmKeyUsage",
                                                "valueJson":  "\"blocked\"",
                                                "value":  "blocked"
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "0a30b73d-6cfc-43c0-a314-bdbcfb469490",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_startupAuthenticationTpmPinAndKeyUsage",
                                                "valueJson":  "null",
                                                "value":  null
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "186fa0de-f344-4dbf-931e-6af7279ab20b",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_startupAuthenticationBlockWithoutTpmChip",
                                                "valueJson":  "true",
                                                "value":  true
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "99b39542-57a1-48e1-9f07-32826025647c",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_prebootRecoveryEnableMessageAndUrl",
                                                "valueJson":  "false",
                                                "value":  false
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "c77d7efd-a616-49a1-9e35-d02e2467cfa6",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_prebootRecoveryMessage",
                                                "valueJson":  "null",
                                                "value":  null
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "e2ab6052-3e26-4fee-afad-b5cf9b9481f3",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_prebootRecoveryUrl",
                                                "valueJson":  "null",
                                                "value":  null
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementComplexSettingInstance",
                                                "id":  "73b96571-7eba-4a02-980e-27452f8d05d7",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_recoveryOptions",
                                                "valueJson":  "{\"recoveryKeyUsage\":\"allowed\",\"recoveryInformationToStore\":null,\"enableRecoveryInformationSaveToStore\":true,\"recoveryPasswordUsage\":\"allowed\",\"hideRecoveryOptions\":true,\"enableBitLockerAfterRecoveryInformationToStore\":false,\"blockDataRecoveryAgent\":true}"
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "60ffa522-330c-49ac-a787-ff2faf474362",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_encryptionMethod",
                                                "valueJson":  "\"xtsAes256\"",
                                                "value":  "xtsAes256"
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                                                "id":  "ed03699f-3622-4b7e-8bd2-61b58fdd2463",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_minimumPinLength",
                                                "valueJson":  "null",
                                                "value":  null
                                            }
                                        ]
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementComplexSettingInstance",
                              "id":  "32ef62b8-d993-4f07-a2b0-4be2ed1327a6",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerFixedDrivePolicy",
                              "valueJson":  "{\"recoveryOptions\":{\"recoveryKeyUsage\":\"allowed\",\"recoveryInformationToStore\":null,\"enableRecoveryInformationSaveToStore\":true,\"recoveryPasswordUsage\":\"allowed\",\"hideRecoveryOptions\":true,\"enableBitLockerAfterRecoveryInformationToStore\":false,\"blockDataRecoveryAgent\":true},\"requireEncryptionForWriteAccess\":true,\"encryptionMethod\":\"xtsAes256\"}",
                              "value":  [
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementComplexSettingInstance",
                                                "id":  "e66287ac-447c-4c92-927a-4c6516ec9ff5",
                                                "definitionId":  "deviceConfiguration--bitLockerFixedDrivePolicy_recoveryOptions",
                                                "valueJson":  "{\"recoveryKeyUsage\":\"allowed\",\"recoveryInformationToStore\":null,\"enableRecoveryInformationSaveToStore\":true,\"recoveryPasswordUsage\":\"allowed\",\"hideRecoveryOptions\":true,\"enableBitLockerAfterRecoveryInformationToStore\":false,\"blockDataRecoveryAgent\":true}"
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "df9496d8-294b-4055-a637-0c42283c8bfa",
                                                "definitionId":  "deviceConfiguration--bitLockerFixedDrivePolicy_requireEncryptionForWriteAccess",
                                                "valueJson":  "true",
                                                "value":  true
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "64cc575b-57a8-4b65-8aa3-243804db8631",
                                                "definitionId":  "deviceConfiguration--bitLockerFixedDrivePolicy_encryptionMethod",
                                                "valueJson":  "\"xtsAes256\"",
                                                "value":  "xtsAes256"
                                            }
                                        ]
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementComplexSettingInstance",
                              "id":  "8b452d30-f0af-4387-87c0-fde889ba8445",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerRemovableDrivePolicy",
                              "valueJson":  "{\"encryptionMethod\":\"aesCbc128\",\"requireEncryptionForWriteAccess\":true,\"blockCrossOrganizationWriteAccess\":false}",
                              "value":  [
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "70cd01b2-7bc9-4936-8635-e4359fb9478c",
                                                "definitionId":  "deviceConfiguration--bitLockerRemovableDrivePolicy_encryptionMethod",
                                                "valueJson":  "\"aesCbc128\"",
                                                "value":  "aesCbc128"
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "b9787475-76a0-4561-a74b-d8029fb3f6e3",
                                                "definitionId":  "deviceConfiguration--bitLockerRemovableDrivePolicy_requireEncryptionForWriteAccess",
                                                "valueJson":  "true",
                                                "value":  true
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "bb955726-2584-41af-88d0-1613ac20595d",
                                                "definitionId":  "deviceConfiguration--bitLockerRemovableDrivePolicy_blockCrossOrganizationWriteAccess",
                                                "valueJson":  "false",
                                                "value":  false
                                            }
                                        ]
                          }
                      ]
}


"@

####################################################

$ES_ASRAudit = @"

{
    "displayName":  "[ITPM Standard] Audit ASR Rules",
    "description":  "Assign this policy to Company owned Windows devices. You must have proper licensing to use this profile: Microsoft 365 Business Premium, E3, or E5. Use either the Audit policy or the Enable policy, but not both at the same time. ",
    "settingsDelta":  [
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "d419d780-275a-4e06-8185-e1b4c406ba3c",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderBlockPersistenceThroughWmiType",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "eb9e4c92-602f-41d7-8091-59ab6d9ae892",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderPreventCredentialStealingType",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "dc5e6c65-2fdd-4ebb-aef2-514488bdda4e",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAdobeReaderLaunchChildProcess",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "439c8d6c-c5de-4d5e-8fe1-21853f33577d",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderOfficeAppsOtherProcessInjectionType",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "3f689fee-a494-4510-bbbc-b3e3242cef36",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderOfficeAppsExecutableContentCreationOrLaunchType",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "886ec98d-e588-44fb-ac52-84a71c66e513",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderOfficeAppsLaunchChildProcessType",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "e4a0388a-fb19-4327-90ae-f06e2de2f1cb",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderOfficeMacroCodeAllowWin32ImportsType",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "138fa97d-00c5-4fa0-a35c-09a0dad3ab71",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderOfficeCommunicationAppsLaunchChildProcess",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "962a6db7-d878-4635-aa83-c498805bf5f8",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderScriptObfuscatedMacroCodeType",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "df666c57-a8a8-46c2-bb70-9567e6ef807c",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderScriptDownloadedPayloadExecutionType",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "f00be9e1-f455-4528-a656-297b455b06d9",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderProcessCreationType",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "0e1d70ef-0be0-48b2-bede-644d08914d2d",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderUntrustedUSBProcessType",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "f0a0167f-c2ab-4e13-9ecb-0a4dcbd320c2",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderUntrustedExecutableType",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "6efadb92-9442-4d76-933f-4e3cb8fb3b34",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderEmailContentExecutionType",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "25c80268-a9ce-49af-9619-cf94d214821f",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAdvancedRansomewareProtectionType",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "e4f29265-c737-42ca-b37c-1d86dd097d68",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderGuardMyFoldersType",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementCollectionSettingInstance",
                              "id":  "eabd14a0-207f-4b26-a6b3-feb305a95e27",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAdditionalGuardedFolders",
                              "valueJson":  "null"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementCollectionSettingInstance",
                              "id":  "4313fa19-fae9-41a2-843e-d0d017c344c9",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderGuardedFoldersAllowedAppPaths",
                              "valueJson":  "null"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementCollectionSettingInstance",
                              "id":  "2187bb24-8bb5-4157-b176-75437c1e7709",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAttackSurfaceReductionExcludedPaths",
                              "valueJson":  "null"
                          }
                      ]
}



"@

####################################################

$ES_DeviceControl = @"

{
    "displayName":  "[ITPM Standard] Block USB removable storage",
    "description":  "This policy will block removable storage devices.",
    "settingsDelta":  [
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementAbstractComplexSettingInstance",
                              "id":  "d6b80913-f6d6-4ed5-8e10-4d39350d3162",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_allowHardwareDeviceInstallationByDeviceIdentifiers",
                              "valueJson":  "null",
                              "implementationId":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementAbstractComplexSettingInstance",
                              "id":  "8aaf2cf8-991d-44b2-bb65-df3188da0aff",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_hardwareDeviceInstallationByDeviceIdentifiers",
                              "valueJson":  "null",
                              "implementationId":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementAbstractComplexSettingInstance",
                              "id":  "952670b6-88ed-4e67-9e74-65c1c24a7549",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_allowHardwareDeviceInstallationBySetupClasses",
                              "valueJson":  "null",
                              "implementationId":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementAbstractComplexSettingInstance",
                              "id":  "c49f9c88-d94c-4425-b58e-36e95e1131a7",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_hardwareDeviceInstallationBySetupClasses",
                              "valueJson":  "null",
                              "implementationId":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementAbstractComplexSettingInstance",
                              "id":  "ee6d8ed7-942a-4ba3-a204-51078064371d",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_allowHardwareDeviceInstallationByDeviceInstanceIdentifiers",
                              "valueJson":  "null",
                              "implementationId":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementAbstractComplexSettingInstance",
                              "id":  "6aa7a8f8-c62d-4225-8727-ab30498ca609",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_preventHardwareDeviceInstallationByDeviceInstanceIdentifiers",
                              "valueJson":  "null",
                              "implementationId":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "f8f41cd7-43a4-4b67-a8a8-aa9a302c1a36",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_defenderScanRemovableDrivesDuringFullScan",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "384ca184-09d7-4f4d-a848-2464545f8339",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_dataProtectionBlockDirectMemoryAccess",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "676c1472-b18e-4f57-ba60-461735f5611a",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_dmaGuardDeviceEnumerationPolicy",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "55fcf7fc-b959-442c-9e20-101635129443",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_storageBlockRemovableStorage",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "8ebd96c0-6d7b-400c-a0f1-ae4d82b2ede0",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_usbBlocked",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "877a254e-a5b4-4d86-b4a3-ee9cdc07c6dc",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_storageBlockRemovableStorageWrite",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "9c2d0165-5029-4e52-8acd-d32378bcd72a",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_bluetoothBlocked",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "d051bb57-2f4a-4aa1-b7db-417c3ec0adcd",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_bluetoothBlockDiscoverableMode",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "aa8ca4c8-ff45-4f66-bc07-d24db4957989",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_bluetoothBlockPrePairing",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "ea2f58a7-88f4-462d-81ce-9fa53f2bd3f2",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_bluetoothBlockAdvertising",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "3950efa9-b504-4fb9-9f3a-04890af6abd6",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_bluetoothBlockPromptedProximalConnections",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementCollectionSettingInstance",
                              "id":  "6b1c8efd-e000-4355-bcb0-c7a00bcb9ae2",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_bluetoothAllowedServices",
                              "valueJson":  "null"
                          }
                      ]
}
"@

####################################################

$ES_WindowsHello = @"

{
    "displayName":  "[ITPM Standard] Windows Hello for Business",
    "description":  "Assign this profile to Company owned Windows devices that are Azure AD Joined. Do not assign this profile to Hybrid Azure AD Joined devices.",
    "settingsDelta":  [
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "cd95785f-6ff4-4f4e-a24e-d109213074ae",
                              "definitionId":  "deviceConfiguration--windowsIdentityProtectionConfiguration_windowsHelloForBusinessBlocked",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "3ed2b206-e91d-4689-a932-1d018cd47b42",
                              "definitionId":  "deviceConfiguration--windowsIdentityProtectionConfiguration_pinMinimumLength",
                              "valueJson":  "6",
                              "value":  6
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "38083c1c-cef8-4b83-95a0-de16602f5bfa",
                              "definitionId":  "deviceConfiguration--windowsIdentityProtectionConfiguration_pinMaximumLength",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "4480fd2e-fca3-47db-a5dd-eeea2d139df6",
                              "definitionId":  "deviceConfiguration--windowsIdentityProtectionConfiguration_pinLowercaseCharactersUsage",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "ee78ed01-1324-4a8e-acdd-9643e617e083",
                              "definitionId":  "deviceConfiguration--windowsIdentityProtectionConfiguration_pinUppercaseCharactersUsage",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "60ebb8d8-7307-4620-9241-f629631a3162",
                              "definitionId":  "deviceConfiguration--windowsIdentityProtectionConfiguration_pinSpecialCharactersUsage",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "e95e446e-2f6e-4608-a5bf-21a5fa144092",
                              "definitionId":  "deviceConfiguration--windowsIdentityProtectionConfiguration_pinExpirationInDays",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "12d7704e-7321-4954-9bde-43ed396b3ef7",
                              "definitionId":  "deviceConfiguration--windowsIdentityProtectionConfiguration_pinPreviousBlockCount",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "49acd01f-162e-4b7c-ac0a-7c624a25f3f2",
                              "definitionId":  "deviceConfiguration--windowsIdentityProtectionConfiguration_pinRecoveryEnabled",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "0446ee25-ace2-4ec7-8aa6-2e9c2348208e",
                              "definitionId":  "deviceConfiguration--windowsIdentityProtectionConfiguration_securityDeviceRequired",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "52edebb1-69f9-4bfa-9d62-6a86f6ece2ac",
                              "definitionId":  "deviceConfiguration--windowsIdentityProtectionConfiguration_unlockWithBiometricsEnabled",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "e943ec65-d992-4f0f-88e6-4b528eee4956",
                              "definitionId":  "deviceConfiguration--windowsIdentityProtectionConfiguration_enhancedAntiSpoofingForFacialFeaturesEnabled",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "ad0fa863-5fbc-4def-af64-792319b54c57",
                              "definitionId":  "deviceConfiguration--windowsIdentityProtectionConfiguration_useCertificatesForOnPremisesAuthEnabled",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "b90734da-6b11-409e-a322-6e1d6ffb2b50",
                              "definitionId":  "deviceConfiguration--windowsIdentityProtectionConfiguration_useSecurityKeyForSignin",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "53a4c135-6e3b-46ba-bd0e-ac5500e4c66b",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_deviceGuardLocalSystemAuthorityCredentialGuardSettings",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          }
                      ]
}


"@

####################################################


#endregion

#region Import policies

Write-Host
Write-Host "Adding Default update ring for Windows..." -ForegroundColor Yellow
Add-DeviceConfigurationPolicy -JSON $Config_WinDefaultUpdate
Write-Host
Write-Host "Adding Delayed update ring for Windows..." -ForegroundColor Yellow
Add-DeviceConfigurationPolicy -JSON $Config_WinDelayedUpdate
Write-Host
Write-Host "Adding OneDrive client config profile..." -ForegroundColor Yellow
Write-Host
$Policy_Name = "[ITPM Standard] Windows: OneDrive client config"
$Policy_Description = "Configures the OneDrive client. Assign this profile to Company owned Windows devices."
$GroupPolicyConfigurationID = Create-GroupPolicyConfigurations -DisplayName $Policy_Name -PolicyDescription $Policy_Description
## Populate the policy with settings
$JSON_Convert = $GPO_ODfBClient | ConvertFrom-Json
$JSON_Convert | ForEach-Object { $_
    
            	$JSON_Output = ConvertTo-Json -Depth 5 $_
                
                Write-Host $JSON_Output

            	Create-GroupPolicyConfigurationsDefinitionValues -JSON $JSON_Output -GroupPolicyConfigurationID $GroupPolicyConfigurationID 
        	 }

Write-Host "Policy: " $Policy_Name "created" -ForegroundColor Yellow
Write-Host 
Write-Host "Adding BitLocker Silent deployment policy..." -ForegroundColor Yellow
Add-EndpointSecurityPolicy -TemplateId $IDBL -JSON $ES_BitLockerRD
Write-Host
Write-Host "Adding Device Control Block removable storage policy..." -ForegroundColor Yellow
Add-EndpointSecurityPolicy -TemplateId $IDDC -JSON $ES_DeviceControl
Write-Host
Write-Host "Adding Attack surface reduction rules audit policy..." -ForegroundColor Yellow
Add-EndpointSecurityPolicy -TemplateId $IDASR -JSON $ES_ASRAudit
Write-Host
Write-Host "Adding Account Protection Windows Hello policy..." -ForegroundColor Yellow
Add-EndpointSecurityPolicy -TemplateId $IDAC -JSON $ES_WindowsHello
Write-Host

#endregion

Write-Host "Script completed" -ForegroundColor Cyan
Write-Host
