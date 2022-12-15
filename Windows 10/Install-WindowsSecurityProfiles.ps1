<##################################################################################################
#
.SYNOPSIS
This script imports recommended Windows 10 Security Profiles described in this resource: 

https://gum.co/FvuOd.

Please read about and test the impacts of each policy before assigning to users/devices.

.SOURCE
https://github.com/vanvfields/Microsoft-365/

All scripts offered without warranty of any kind.

The functions contained in this script are from the Graph samples published by Microsoft on GitHub:
https://github.com/microsoftgraph/powershell-intune-samples

.NOTES
    FileName:    Install-WindowsSecurityProfiles.ps1
    Author:      Alex Fields (ITProMentor.com)
    Created:     October 2019
	Revised:     January 2022
    
#>
###################################################################################################

###################################################################################################
## Functions used in the script
###################################################################################################

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

Function Add-DeviceCompliancePolicybaseline(){

    <#
    .SYNOPSIS
    This function is used to add a device compliance policy using the Graph API REST interface
    .DESCRIPTION
    The function connects to the Graph API Interface and adds a device compliance policy
    .EXAMPLE
    Add-DeviceCompliancePolicy -JSON $JSON
    Adds an iOS device compliance policy in Intune
    .NOTES
    NAME: Add-DeviceCompliancePolicy
    #>
    
    [cmdletbinding()]
    
    param
    (
        $JSON
    )
    
    $graphApiVersion = "Beta"
    $Resource = "deviceManagement/deviceCompliancePolicies"
        
        try {
    
            if($JSON -eq "" -or $JSON -eq $null){
    
            write-host "No JSON specified, please specify valid JSON for the iOS Policy..." -f Red
    
            }
    
            else {
    
            Test-JSON -JSON $JSON
    
            $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
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

Function Add-MDMApplication(){



<#

.SYNOPSIS

This function is used to add an MDM application using the Graph API REST interface

.DESCRIPTION

The function connects to the Graph API Interface and adds an MDM application from the itunes store

.EXAMPLE

Add-MDMApplication -JSON $JSON

Adds an application into Intune

.NOTES

NAME: Add-MDMApplication

#>



[cmdletbinding()]



param

(

    $JSON

)



$graphApiVersion = "Beta"

$App_resource = "deviceAppManagement/mobileApps"



    try {



        if(!$JSON){



        write-host "No JSON was passed to the function, provide a JSON variable" -f Red

        break



        }



        Test-JSON -JSON $JSON



        $uri = "https://graph.microsoft.com/$graphApiVersion/$($App_resource)"

        Invoke-RestMethod -Uri $uri -Method Post -ContentType "application/json" -Body $JSON -Headers $authToken



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

Function Add-WindowsInformationProtectionPolicy(){



<#

.SYNOPSIS

This function is used to add a Windows Information Protection policy using the Graph API REST interface

.DESCRIPTION

The function connects to the Graph API Interface and adds a Windows Information Protection policy

.EXAMPLE

Add-WindowsInformationProtectionPolicy -JSON $JSON

Adds a Windows Information Protection policy in Intune

.NOTES

NAME: Add-WindowsInformationProtectionPolicy

#>



[cmdletbinding()]



param

(

    $JSON

)



$graphApiVersion = "Beta"

$Resource = "deviceAppManagement/windowsInformationProtectionPolicies"

    

    try {

        

        if($JSON -eq "" -or $JSON -eq $null){



        write-host "No JSON specified, please specify valid JSON for the iOS Policy..." -f Red



        }



        else {



        Test-JSON -JSON $JSON



        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

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

Function Add-MDMWindowsInformationProtectionPolicy(){



<#

.SYNOPSIS

This function is used to add a Windows Information Protection policy using the Graph API REST interface

.DESCRIPTION

The function connects to the Graph API Interface and adds a Windows Information Protection policy

.EXAMPLE

Add-MDMWindowsInformationProtectionPolicy -JSON $JSON

Adds a Windows Information Protection policy in Intune

.NOTES

NAME: Add-MDMWindowsInformationProtectionPolicy

#>



[cmdletbinding()]



param

(

    $JSON

)



$graphApiVersion = "Beta"

$Resource = "deviceAppManagement/mdmWindowsInformationProtectionPolicies"

    

    try {

        

        if($JSON -eq "" -or $JSON -eq $null){



        write-host "No JSON specified, please specify valid JSON for the iOS Policy..." -f Red



        }



        else {



        Test-JSON -JSON $JSON



        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"

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


###################################################################################################
## Get your authentication token
###################################################################################################

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

####################################################


###################################################################################################
## Get Tenant ID and Enterprise Domain for use in certain policies
###################################################################################################
$TenantID = Get-TenantID
$EnterpriseDomain = Get-EnterpriseDomain
$Sharepoint = $EnterpriseDomain.Split(".")[0]


###################################################################################################
## Get Current Template IDs for use with the Endpoint Security Profiles
###################################################################################################
$Templates = Get-EndpointSecurityTemplate ## Gets the most current templates

#$IDAV = "ccef13ea-d0a2-49b5-9a8a-5e397faeb9e4"
$TempAV = $Templates |Where-Object displayName -eq "Microsoft Defender Antivirus"
$IDAV = $TempAV.id

#$IDWinExp = "8227e75a-da4d-4f8f-8566-9a080cb43961"
$TempWinExp = $Templates |Where-Object displayName -eq "Windows Security experience"
$IDWinExp = $TempWinExp.id

#$IDBL = "d1174162-1dd2-4976-affc-6667049ab0ae"
$TempBL = $Templates |Where-Object displayName -eq "BitLocker"
$IDBL = $TempBL.id

#$IDFW = "c53e5a9f-2eec-4175-98a1-2b3d38084b91"
$TempFW = $Templates |Where-Object displayName -eq "Microsoft Defender Firewall"
$IDFW = $TempFW.id

#$IDASR = "0e237410-1367-4844-bd7f-15fb0f08943b"
$TempASR = $Templates |Where-Object displayName -eq "Attack surface reduction rules"
$IDASR = $TempASR.id

#$IDDC = "4648b50e-d3ef-4ba0-848e-b0ef561b3aa5"
$TempDC = $Templates |Where-Object displayName -eq "Device control"
$IDDC = $TempDC.id

#$IDAC = "0f2b5d70-d4e9-4156-8c16-1397eb6c54a5"
$TempAC = $Templates |Where-Object displayName -eq "Account protection (Preview)"
$IDAC = $TempAC.id


#$IDWin = "c04a010a-e7c5-44b1-a814-88df6f053f16"
$TempWin = $Templates |Where-Object displayName -eq "MDM Security Baseline for Windows 10 and later for Decemeber 2020"
$IDWin = $TempWin.id

#$IDEdge = "a8d6fa0e-1e66-455b-bb51-8ce0dde1559e"
$TempEdge = $Templates |Where-Object displayName -eq "Microsoft Edge baseline"
$IDEdge = $TempEdge.id

###################################################################################################
## JSON describing the policies to be imported
###################################################################################################

$Comp_WinImmediate = @"

{
    "@odata.type":  "#microsoft.graph.windows10CompliancePolicy",
    "description":  "Assign this policy to all users, including BYOD users. Windows compliance settings to apply immediately. \n",
    "displayName":  "[ITPM Baseline] Windows: Immediate",
    "passwordRequired":  false,
    "passwordBlockSimple":  false,
    "passwordRequiredToUnlockFromIdle":  false,
    "passwordMinutesOfInactivityBeforeLock":  null,
    "passwordExpirationDays":  null,
    "passwordMinimumLength":  null,
    "passwordMinimumCharacterSetCount":  null,
    "passwordRequiredType":  "deviceDefault",
    "passwordPreviousPasswordBlockCount":  null,
    "requireHealthyDeviceReport":  false,
    "osMinimumVersion":  "10.0.18363",
    "osMaximumVersion":  null,
    "mobileOsMinimumVersion":  null,
    "mobileOsMaximumVersion":  null,
    "earlyLaunchAntiMalwareDriverEnabled":  false,
    "bitLockerEnabled":  false,
    "secureBootEnabled":  false,
    "codeIntegrityEnabled":  false,
    "storageRequireEncryption":  false,
    "activeFirewallRequired":  false,
    "defenderEnabled":  true,
    "defenderVersion":  null,
    "signatureOutOfDate":  false,
    "rtpEnabled":  true,
    "antivirusRequired":  true,
    "antiSpywareRequired":  false,
    "deviceThreatProtectionEnabled":  false,
    "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
    "configurationManagerComplianceRequired":  false,
    "tpmRequired":  false,
    "deviceCompliancePolicyScript":  null,
    "validOperatingSystemBuildRanges":  [

                                        ],
	"scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":0,"notificationTemplateId":"","notificationMessageCCList":[]}]}]
}



"@

####################################################

$Comp_WinDelayed = @"
{
    "@odata.type":  "#microsoft.graph.windows10CompliancePolicy",
    "description":  "Assign this policy to all users including BYOD users. Windows compliance settings to apply with 24 hour grace period.",
    "displayName":  "[ITPM Baseline] Windows: Delayed",
    "passwordRequired":  false,
    "passwordBlockSimple":  false,
    "passwordRequiredToUnlockFromIdle":  false,
    "passwordMinutesOfInactivityBeforeLock":  null,
    "passwordExpirationDays":  null,
    "passwordMinimumLength":  null,
    "passwordMinimumCharacterSetCount":  null,
    "passwordRequiredType":  "deviceDefault",
    "passwordPreviousPasswordBlockCount":  null,
    "requireHealthyDeviceReport":  false,
    "osMinimumVersion":  "10.0.18363.476",
    "osMaximumVersion":  null,
    "mobileOsMinimumVersion":  null,
    "mobileOsMaximumVersion":  null,
    "earlyLaunchAntiMalwareDriverEnabled":  false,
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
    "configurationManagerComplianceRequired":  false,
    "tpmRequired":  true,
    "deviceCompliancePolicyScript":  null,
    "validOperatingSystemBuildRanges":  [

                                        ],
	"scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":24,"notificationTemplateId":"","notificationMessageCCList":[]}]}]
}

"@

####################################################

$WIPMAM = @"
{
    "displayName":  "[ITPM Baseline] Windows MAM/without enrollment",
    "description":  "Use this policy only if you plan to allow unmanaged Windows devices to connect to your corporate data using Microsoft 365 desktop applications. Do not assign this policy until you have added your approved apps and network locations.",
    "enforcementLevel":  "noProtection",
    "enterpriseDomain":  "$EnterpriseDomain",
    "protectionUnderLockConfigRequired":  false,
    "dataRecoveryCertificate":  null,
    "revokeOnUnenrollDisabled":  false,
    "rightsManagementServicesTemplateId":  null,
    "azureRightsManagementServicesAllowed":  false,
    "iconsVisible":  true,
    "enterpriseIPRangesAreAuthoritative":  false,
    "enterpriseProxyServersAreAuthoritative":  false,
    "indexingEncryptedStoresOrItemsBlocked":  false,
    "isAssigned":  false,
    "revokeOnMdmHandoffDisabled":  true,
    "mdmEnrollmentUrl":  "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc",
    "windowsHelloForBusinessBlocked":  false,
    "pinMinimumLength":  6,
    "pinUppercaseLetters":  "notAllow",
    "pinLowercaseLetters":  "notAllow",
    "pinSpecialCharacters":  "notAllow",
    "pinExpirationDays":  0,
    "numberOfPastPinsRemembered":  0,
    "passwordMaximumAttemptCount":  0,
    "minutesOfInactivityBeforeDeviceLock":  0,
    "daysWithoutContactBeforeUnenroll":  90,
    "enterpriseProtectedDomainNames":  [

                                       ],
    "protectedApps":  [

                      ],
    "exemptApps":  [

                   ],
    "enterpriseNetworkDomainNames":  [

                                     ],
    "enterpriseProxiedDomains":  [
                                     {
                                         "displayName":  "Microsoft 365",
                                         "proxiedDomains":  [
                                                                {
                                                                    "ipAddressOrFQDN":  "$Sharepoint.sharepoint.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "$Sharepoint-my.sharepoint.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "$Sharepoint-files.sharepoint.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "outlook.office.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "outlook.office365.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "attachments.office.net",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "protection.office.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "tasks.office.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "teams.microsoft.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "project.microsoft.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "$Sharepoint.powerbi.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "$Sharepoint.crm.dynamics.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "/*AppCompat*/",
                                                                    "proxy":  null
                                                                }
                                                            ]
                                     }
                                 ],
    "enterpriseIPRanges":  [

                           ],
    "enterpriseProxyServers":  [

                               ],
    "enterpriseInternalProxyServers":  [

                                       ],
    "neutralDomainResources":  [
                                   {
                                       "displayName":  "Microsoft login",
                                       "resources":  [
                                                         "login.microsoftonline.com",
                                                         "login.windows.net"
                                                     ]
                                   }
                               ],
    "smbAutoEncryptedFileExtensions":  [

                                       ],
    "protectedAppLockerFiles":  [

                                ],
    "exemptAppLockerFiles":  [

                             ],
    "assignments":  [

                    ],
    "@odata.type":  "#microsoft.graph.windowsInformationProtectionPolicy"
}


"@

####################################################

$WIPMDM = @"

{
    "displayName":  "[ITPM Baseline] Windows MDM/with enrollment",
    "description":  "Use this policy to protect corporate data on MDM enrolled devices. Do not assign this policy until you have added your approved apps and network locations.",
    "enforcementLevel":  "noProtection",
    "enterpriseDomain":  "$EnterpriseDomain",
    "protectionUnderLockConfigRequired":  false,
    "dataRecoveryCertificate":  null,
    "revokeOnUnenrollDisabled":  false,
    "rightsManagementServicesTemplateId":  null,
    "azureRightsManagementServicesAllowed":  false,
    "iconsVisible":  true,
    "enterpriseIPRangesAreAuthoritative":  false,
    "enterpriseProxyServersAreAuthoritative":  false,
    "indexingEncryptedStoresOrItemsBlocked":  false,
    "isAssigned":  false,
    "enterpriseProtectedDomainNames":  [

                                       ],
    "protectedApps":  [

                      ],
    "exemptApps":  [

                   ],
    "enterpriseNetworkDomainNames":  [

                                     ],
    "enterpriseProxiedDomains":  [
                                     {
                                         "displayName":  "Microsoft 365",
                                         "proxiedDomains":  [
                                                                {
                                                                    "ipAddressOrFQDN":  "$Sharepoint.sharepoint.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "$Sharepoint-my.sharepoint.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "$Sharepoint-files.sharepoint.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "outlook.office.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "outlook.office365.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "attachments.office.net",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "protection.office.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "tasks.office.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "teams.microsoft.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "project.microsoft.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "$Sharepoint.powerbi.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "$Sharepoint.crm.dynamics.com",
                                                                    "proxy":  null
                                                                },
                                                                {
                                                                    "ipAddressOrFQDN":  "/*AppCompat*/",
                                                                    "proxy":  null
                                                                }
                                                            ]
                                     }
                                 ],
    "enterpriseIPRanges":  [

                           ],
    "enterpriseProxyServers":  [

                               ],
    "enterpriseInternalProxyServers":  [

                                       ],
    "neutralDomainResources":  [
                                   {
                                       "displayName":  "Microsoft login",
                                       "resources":  [
                                                         "login.microsoftonline.com",
                                                         "login.windows.net"
                                                     ]
                                   }
                               ],
    "smbAutoEncryptedFileExtensions":  [

                                       ],
    "protectedAppLockerFiles":  [

                                ],
    "exemptAppLockerFiles":  [

                             ],
    "assignments":  [

                    ],
    "@odata.type":  "#microsoft.graph.mdmWindowsInformationProtectionPolicy"
}



"@

####################################################

$Config_WinAllowReset = @"

{
    "@odata.type":  "#microsoft.graph.windows10GeneralConfiguration",
    "deviceManagementApplicabilityRuleOsEdition":  null,
    "deviceManagementApplicabilityRuleOsVersion":  null,
    "deviceManagementApplicabilityRuleDeviceMode":  null,
    "description":  "Assign this policy to Company owned Windows devices. Allows the user to perform a self-service Autopilot reset.",
    "displayName":  "[ITPM Corporate] Windows: Allow Autopilot Reset",
    "taskManagerBlockEndTask":  false,
    "energySaverOnBatteryThresholdPercentage":  null,
    "energySaverPluggedInThresholdPercentage":  null,
    "powerLidCloseActionOnBattery":  "notConfigured",
    "powerLidCloseActionPluggedIn":  "notConfigured",
    "powerButtonActionOnBattery":  "notConfigured",
    "powerButtonActionPluggedIn":  "notConfigured",
    "powerSleepButtonActionOnBattery":  "notConfigured",
    "powerSleepButtonActionPluggedIn":  "notConfigured",
    "powerHybridSleepOnBattery":  "notConfigured",
    "powerHybridSleepPluggedIn":  "notConfigured",
    "windows10AppsForceUpdateSchedule":  null,
    "enableAutomaticRedeployment":  true,
    "microsoftAccountSignInAssistantSettings":  "notConfigured",
    "authenticationAllowSecondaryDevice":  false,
    "authenticationWebSignIn":  "notConfigured",
    "authenticationPreferredAzureADTenantDomainName":  null,
    "cryptographyAllowFipsAlgorithmPolicy":  false,
    "displayAppListWithGdiDPIScalingTurnedOn":  [

                                                ],
    "displayAppListWithGdiDPIScalingTurnedOff":  [

                                                 ],
    "enterpriseCloudPrintDiscoveryEndPoint":  null,
    "enterpriseCloudPrintOAuthAuthority":  null,
    "enterpriseCloudPrintOAuthClientIdentifier":  null,
    "enterpriseCloudPrintResourceIdentifier":  null,
    "enterpriseCloudPrintDiscoveryMaxLimit":  null,
    "enterpriseCloudPrintMopriaDiscoveryResourceIdentifier":  null,
    "experienceDoNotSyncBrowserSettings":  "notConfigured",
    "messagingBlockSync":  false,
    "messagingBlockMMS":  false,
    "messagingBlockRichCommunicationServices":  false,
    "printerNames":  [

                     ],
    "printerDefaultName":  null,
    "printerBlockAddition":  false,
    "searchBlockDiacritics":  false,
    "searchDisableAutoLanguageDetection":  false,
    "searchDisableIndexingEncryptedItems":  false,
    "searchEnableRemoteQueries":  false,
    "searchDisableUseLocation":  false,
    "searchDisableLocation":  false,
    "searchDisableIndexerBackoff":  false,
    "searchDisableIndexingRemovableDrive":  false,
    "searchEnableAutomaticIndexSizeManangement":  false,
    "searchBlockWebResults":  false,
    "findMyFiles":  "notConfigured",
    "securityBlockAzureADJoinedDevicesAutoEncryption":  false,
    "diagnosticsDataSubmissionMode":  "userDefined",
    "oneDriveDisableFileSync":  false,
    "systemTelemetryProxyServer":  null,
    "edgeTelemetryForMicrosoft365Analytics":  "notConfigured",
    "inkWorkspaceAccess":  "notConfigured",
    "inkWorkspaceAccessState":  "notConfigured",
    "inkWorkspaceBlockSuggestedApps":  false,
    "smartScreenEnableAppInstallControl":  false,
    "smartScreenAppInstallControl":  "notConfigured",
    "personalizationDesktopImageUrl":  null,
    "personalizationLockScreenImageUrl":  null,
    "bluetoothAllowedServices":  [

                                 ],
    "bluetoothBlockAdvertising":  false,
    "bluetoothBlockPromptedProximalConnections":  false,
    "bluetoothBlockDiscoverableMode":  false,
    "bluetoothBlockPrePairing":  false,
    "edgeBlockAutofill":  false,
    "edgeBlocked":  false,
    "edgeCookiePolicy":  "userDefined",
    "edgeBlockDeveloperTools":  false,
    "edgeBlockSendingDoNotTrackHeader":  false,
    "edgeBlockExtensions":  false,
    "edgeBlockInPrivateBrowsing":  false,
    "edgeBlockJavaScript":  false,
    "edgeBlockPasswordManager":  false,
    "edgeBlockAddressBarDropdown":  false,
    "edgeBlockCompatibilityList":  false,
    "edgeClearBrowsingDataOnExit":  false,
    "edgeAllowStartPagesModification":  false,
    "edgeDisableFirstRunPage":  false,
    "edgeBlockLiveTileDataCollection":  false,
    "edgeSyncFavoritesWithInternetExplorer":  false,
    "edgeFavoritesListLocation":  null,
    "edgeBlockEditFavorites":  false,
    "edgeNewTabPageURL":  null,
    "edgeHomeButtonConfiguration":  null,
    "edgeHomeButtonConfigurationEnabled":  false,
    "edgeOpensWith":  "notConfigured",
    "edgeBlockSideloadingExtensions":  false,
    "edgeRequiredExtensionPackageFamilyNames":  [

                                                ],
    "edgeBlockPrinting":  false,
    "edgeFavoritesBarVisibility":  "notConfigured",
    "edgeBlockSavingHistory":  false,
    "edgeBlockFullScreenMode":  false,
    "edgeBlockWebContentOnNewTabPage":  false,
    "edgeBlockTabPreloading":  false,
    "edgeBlockPrelaunch":  false,
    "edgeShowMessageWhenOpeningInternetExplorerSites":  "notConfigured",
    "edgePreventCertificateErrorOverride":  false,
    "edgeKioskModeRestriction":  "notConfigured",
    "edgeKioskResetAfterIdleTimeInMinutes":  null,
    "cellularBlockDataWhenRoaming":  false,
    "cellularBlockVpn":  false,
    "cellularBlockVpnWhenRoaming":  false,
    "cellularData":  "allowed",
    "defenderRequireRealTimeMonitoring":  false,
    "defenderRequireBehaviorMonitoring":  false,
    "defenderRequireNetworkInspectionSystem":  false,
    "defenderScanDownloads":  false,
    "defenderScheduleScanEnableLowCpuPriority":  false,
    "defenderDisableCatchupQuickScan":  false,
    "defenderDisableCatchupFullScan":  false,
    "defenderScanScriptsLoadedInInternetExplorer":  false,
    "defenderBlockEndUserAccess":  false,
    "defenderSignatureUpdateIntervalInHours":  null,
    "defenderMonitorFileActivity":  "userDefined",
    "defenderDaysBeforeDeletingQuarantinedMalware":  null,
    "defenderScanMaxCpu":  null,
    "defenderScanArchiveFiles":  false,
    "defenderScanIncomingMail":  false,
    "defenderScanRemovableDrivesDuringFullScan":  false,
    "defenderScanMappedNetworkDrivesDuringFullScan":  false,
    "defenderScanNetworkFiles":  false,
    "defenderRequireCloudProtection":  false,
    "defenderCloudBlockLevel":  "notConfigured",
    "defenderCloudExtendedTimeout":  null,
    "defenderCloudExtendedTimeoutInSeconds":  null,
    "defenderPromptForSampleSubmission":  "userDefined",
    "defenderScheduledQuickScanTime":  null,
    "defenderScanType":  "userDefined",
    "defenderSystemScanSchedule":  "userDefined",
    "defenderScheduledScanTime":  null,
    "defenderPotentiallyUnwantedAppAction":  null,
    "defenderPotentiallyUnwantedAppActionSetting":  "userDefined",
    "defenderSubmitSamplesConsentType":  "sendSafeSamplesAutomatically",
    "defenderBlockOnAccessProtection":  false,
    "defenderDetectedMalwareActions":  null,
    "defenderFileExtensionsToExclude":  [

                                        ],
    "defenderFilesAndFoldersToExclude":  [

                                         ],
    "defenderProcessesToExclude":  [

                                   ],
    "lockScreenAllowTimeoutConfiguration":  false,
    "lockScreenBlockActionCenterNotifications":  false,
    "lockScreenBlockCortana":  false,
    "lockScreenBlockToastNotifications":  false,
    "lockScreenTimeoutInSeconds":  null,
    "lockScreenActivateAppsWithVoice":  "notConfigured",
    "passwordBlockSimple":  false,
    "passwordExpirationDays":  null,
    "passwordMinimumLength":  null,
    "passwordMinutesOfInactivityBeforeScreenTimeout":  null,
    "passwordMinimumCharacterSetCount":  null,
    "passwordPreviousPasswordBlockCount":  null,
    "passwordRequired":  false,
    "passwordRequireWhenResumeFromIdleState":  false,
    "passwordRequiredType":  "deviceDefault",
    "passwordSignInFailureCountBeforeFactoryReset":  null,
    "passwordMinimumAgeInDays":  null,
    "privacyAdvertisingId":  "notConfigured",
    "privacyAutoAcceptPairingAndConsentPrompts":  false,
    "privacyDisableLaunchExperience":  false,
    "privacyBlockInputPersonalization":  false,
    "privacyBlockPublishUserActivities":  false,
    "privacyBlockActivityFeed":  false,
    "activateAppsWithVoice":  "notConfigured",
    "startBlockUnpinningAppsFromTaskbar":  false,
    "startMenuAppListVisibility":  "userDefined",
    "startMenuHideChangeAccountSettings":  false,
    "startMenuHideFrequentlyUsedApps":  false,
    "startMenuHideHibernate":  false,
    "startMenuHideLock":  false,
    "startMenuHidePowerButton":  false,
    "startMenuHideRecentJumpLists":  false,
    "startMenuHideRecentlyAddedApps":  false,
    "startMenuHideRestartOptions":  false,
    "startMenuHideShutDown":  false,
    "startMenuHideSignOut":  false,
    "startMenuHideSleep":  false,
    "startMenuHideSwitchAccount":  false,
    "startMenuHideUserTile":  false,
    "startMenuLayoutEdgeAssetsXml":  null,
    "startMenuLayoutXml":  null,
    "startMenuMode":  "userDefined",
    "startMenuPinnedFolderDocuments":  "notConfigured",
    "startMenuPinnedFolderDownloads":  "notConfigured",
    "startMenuPinnedFolderFileExplorer":  "notConfigured",
    "startMenuPinnedFolderHomeGroup":  "notConfigured",
    "startMenuPinnedFolderMusic":  "notConfigured",
    "startMenuPinnedFolderNetwork":  "notConfigured",
    "startMenuPinnedFolderPersonalFolder":  "notConfigured",
    "startMenuPinnedFolderPictures":  "notConfigured",
    "startMenuPinnedFolderSettings":  "notConfigured",
    "startMenuPinnedFolderVideos":  "notConfigured",
    "settingsBlockSettingsApp":  false,
    "settingsBlockSystemPage":  false,
    "settingsBlockDevicesPage":  false,
    "settingsBlockNetworkInternetPage":  false,
    "settingsBlockPersonalizationPage":  false,
    "settingsBlockAccountsPage":  false,
    "settingsBlockTimeLanguagePage":  false,
    "settingsBlockEaseOfAccessPage":  false,
    "settingsBlockPrivacyPage":  false,
    "settingsBlockUpdateSecurityPage":  false,
    "settingsBlockAppsPage":  false,
    "settingsBlockGamingPage":  false,
    "windowsSpotlightBlockConsumerSpecificFeatures":  false,
    "windowsSpotlightBlocked":  false,
    "windowsSpotlightBlockOnActionCenter":  false,
    "windowsSpotlightBlockTailoredExperiences":  false,
    "windowsSpotlightBlockThirdPartyNotifications":  false,
    "windowsSpotlightBlockWelcomeExperience":  false,
    "windowsSpotlightBlockWindowsTips":  false,
    "windowsSpotlightConfigureOnLockScreen":  "notConfigured",
    "networkProxyApplySettingsDeviceWide":  false,
    "networkProxyDisableAutoDetect":  false,
    "networkProxyAutomaticConfigurationUrl":  null,
    "networkProxyServer":  null,
    "accountsBlockAddingNonMicrosoftAccountEmail":  true,
    "antiTheftModeBlocked":  false,
    "bluetoothBlocked":  false,
    "cameraBlocked":  false,
    "connectedDevicesServiceBlocked":  false,
    "certificatesBlockManualRootCertificateInstallation":  false,
    "copyPasteBlocked":  false,
    "cortanaBlocked":  false,
    "deviceManagementBlockFactoryResetOnMobile":  false,
    "deviceManagementBlockManualUnenroll":  false,
    "safeSearchFilter":  "userDefined",
    "edgeBlockPopups":  false,
    "edgeBlockSearchSuggestions":  false,
    "edgeBlockSearchEngineCustomization":  false,
    "edgeBlockSendingIntranetTrafficToInternetExplorer":  false,
    "edgeSendIntranetTrafficToInternetExplorer":  false,
    "edgeRequireSmartScreen":  false,
    "edgeEnterpriseModeSiteListLocation":  null,
    "edgeFirstRunUrl":  null,
    "edgeSearchEngine":  null,
    "edgeHomepageUrls":  [

                         ],
    "edgeBlockAccessToAboutFlags":  false,
    "smartScreenBlockPromptOverride":  false,
    "smartScreenBlockPromptOverrideForFiles":  false,
    "webRtcBlockLocalhostIpAddress":  false,
    "internetSharingBlocked":  false,
    "settingsBlockAddProvisioningPackage":  false,
    "settingsBlockRemoveProvisioningPackage":  false,
    "settingsBlockChangeSystemTime":  false,
    "settingsBlockEditDeviceName":  false,
    "settingsBlockChangeRegion":  false,
    "settingsBlockChangeLanguage":  false,
    "settingsBlockChangePowerSleep":  false,
    "locationServicesBlocked":  false,
    "microsoftAccountBlocked":  false,
    "microsoftAccountBlockSettingsSync":  false,
    "nfcBlocked":  false,
    "resetProtectionModeBlocked":  false,
    "screenCaptureBlocked":  false,
    "storageBlockRemovableStorage":  false,
    "storageRequireMobileDeviceEncryption":  false,
    "usbBlocked":  false,
    "voiceRecordingBlocked":  false,
    "wiFiBlockAutomaticConnectHotspots":  false,
    "wiFiBlocked":  false,
    "wiFiBlockManualConfiguration":  false,
    "wiFiScanInterval":  null,
    "wirelessDisplayBlockProjectionToThisDevice":  false,
    "wirelessDisplayBlockUserInputFromReceiver":  false,
    "wirelessDisplayRequirePinForPairing":  false,
    "windowsStoreBlocked":  false,
    "appsAllowTrustedAppsSideloading":  "notConfigured",
    "windowsStoreBlockAutoUpdate":  false,
    "developerUnlockSetting":  "blocked",
    "sharedUserAppDataAllowed":  true,
    "appsBlockWindowsStoreOriginatedApps":  false,
    "windowsStoreEnablePrivateStoreOnly":  false,
    "storageRestrictAppDataToSystemVolume":  false,
    "storageRestrictAppInstallToSystemVolume":  false,
    "gameDvrBlocked":  false,
    "experienceBlockDeviceDiscovery":  false,
    "experienceBlockErrorDialogWhenNoSIM":  false,
    "experienceBlockTaskSwitcher":  false,
    "logonBlockFastUserSwitching":  false,
    "tenantLockdownRequireNetworkDuringOutOfBoxExperience":  true,
    "appManagementMSIAllowUserControlOverInstall":  false,
    "appManagementMSIAlwaysInstallWithElevatedPrivileges":  false,
    "dataProtectionBlockDirectMemoryAccess":  true,
    "appManagementPackageFamilyNamesToLaunchAfterLogOn":  [

                                                          ],
    "uninstallBuiltInApps":  false,
    "configureTimeZone":  null
}


"@

####################################################

$Config_WinDisableAnimation = @"

{
    "@odata.type":  "#microsoft.graph.windows10CustomConfiguration",
    "deviceManagementApplicabilityRuleOsEdition":  null,
    "deviceManagementApplicabilityRuleOsVersion":  null,
    "deviceManagementApplicabilityRuleDeviceMode":  null,
    "description":  "Assign this profile to Company owned Windows devices. Prevents the sign-in animation sequence for users signing into the device for the first time.",
    "displayName":  "[ITPM Corporate] Windows: Disable first sign-in animation",
    "omaSettings":  [
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "EnableFirstLogonAnimation",
                            "description":  "Disable first sign-in animation",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/WindowsLogon/EnableFirstLogonAnimation",
                            "isEncrypted":  false,
                            "value":  0,
                            "isReadOnly":  false
                        }
                    ]
}


"@

####################################################

$Config_WinMDMWins = @"

{
    "@odata.type":  "#microsoft.graph.windows10CustomConfiguration",
    "deviceManagementApplicabilityRuleOsEdition":  null,
    "deviceManagementApplicabilityRuleOsVersion":  null,
    "deviceManagementApplicabilityRuleDeviceMode":  null,
    "description":  "Assign this profile to Hybrid Azure AD Joined Windows devices. Allows MDM settings to override conflicts with Group Policy.",
    "displayName":  "[ITPM Corporate] Windows: MDM wins over Group Policy",
    "omaSettings":  [
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "ControlPolicyConflict/MDMWinsOverGP",
                            "description":  "MDMWinsOverGP",
                            "omaUri":  "./Device/Vendor/MSFT/Policy/Config/ControlPolicyConflict/MDMWinsOverGP",
                            "isEncrypted":  false,
                            "value":  1,
                            "isReadOnly":  false
                        }
                    ]
}

"@

####################################################

$Config_WinDefaultUpdate = @"
{
    "@odata.type":  "#microsoft.graph.windowsUpdateForBusinessConfiguration",
    "deviceManagementApplicabilityRuleOsEdition":  null,
    "deviceManagementApplicabilityRuleOsVersion":  null,
    "deviceManagementApplicabilityRuleDeviceMode":  null,
    "description":  "Applies updates via the Semi-annual channel without delay.",
    "displayName":  "[ITPM Corporate] Default Update Ring",
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
    "displayName":  "[ITPM Corporate] Delayed Update Ring",
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

$Office32 = @"

{

  "@odata.type": "#microsoft.graph.officeSuiteApp",

  "autoAcceptEula": true,

  "description": "[ITPM Corporate] 32-bit Microsoft 365 Desktop apps",

  "developer": "Microsoft",

  "displayName": "[ITPM Corporate] 32-bit Microsoft 365 Desktop apps",

  "excludedApps": {

    "groove": true,

    "infoPath": true,

    "sharePointDesigner": true,

    "lync":  true

  },

  "informationUrl": "",

  "isFeatured": false,

  "largeIcon": {

    "type": "image/png",

    "value": "iVBORw0KGgoAAAANSUhEUgAAAF0AAAAeCAMAAAEOZNKlAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAJhUExURf////7z7/i9qfF1S/KCW/i+qv3q5P/9/PrQwfOMae1RG+s8AOxGDfBtQPWhhPvUx/759/zg1vWgg+9fLu5WIvKFX/rSxP728/nCr/FyR+tBBvOMaO1UH+1RHOs+AvSScP3u6f/+/v3s5vzg1+xFDO9kNPOOa/i7pvzj2/vWyes9Af76+Pzh2PrTxf/6+f7y7vOGYexHDv3t5+1SHfi8qPOIZPvb0O1NFuxDCe9hMPSVdPnFs/3q4/vaz/STcu5VIe5YJPWcfv718v/9/e1MFfF4T/F4TvF2TP3o4exECvF0SexIEPONavzn3/vZze1QGvF3Te5dK+5cKvrPwPrQwvKAWe1OGPexmexKEveulfezm/BxRfamiuxLE/apj/zf1e5YJfSXd/OHYv3r5feznPakiPze1P7x7f739f3w6+xJEfnEsvWdf/Wfge1LFPe1nu9iMvnDsfBqPOs/BPOIY/WZevJ/V/zl3fnIt/vTxuxHD+xEC+9mN+5ZJv749vBpO/KBWvBwRP/8+/SUc/etlPjArP/7+vOLZ/F7UvWae/708e1OF/aihvSWdvi8p+tABfSZefvVyPWihfSVde9lNvami+9jM/zi2fKEXvBuQvOKZvalifF5UPJ/WPSPbe9eLfrKuvvd0uxBB/7w7Pzj2vrRw/rOv+1PGfi/q/eymu5bKf3n4PnJuPBrPf3t6PWfgvWegOxCCO9nOO9oOfaskvSYePi5pPi2oPnGtO5eLPevlvKDXfrNvv739Pzd0/708O9gL+9lNfJ9VfrLu/OPbPnDsPBrPus+A/nArfarkQAAAGr5HKgAAADLdFJOU/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8AvuakogAAAAlwSFlzAAAOwwAADsMBx2+oZAAAAz5JREFUOE+tVTtu4zAQHQjppmWzwIJbEVCzpTpjbxD3grQHSOXKRXgCAT6EC7UBVAmp3KwBnmvfzNCyZTmxgeTZJsXx43B+HBHRE34ZkXgkerXFTheeiCkRrbB4UXmp4wSWz5raaQEMTM5TZwuiXoaKgV+6FsmkZQcSy0kA71yMTMGHanX+AzMMGLAQCxU1F/ZwjULPugazl82GM0NEKm/U8EqFwEkO3/EAT4grgl0nucwlk9pcpTTJ4VPA4g/Rb3yIRhhp507e9nTQmZ1OS5RO4sS7nIRPEeHXCHdkw9ZEW2yVE5oIS7peD58Avs7CN+PVCmHh21oOqBdjDzIs+FldPJ74TFESUSJEfVzy9U/dhu+AuOT6eBp6gGKyXEx8euO450ZE4CMfstMFT44broWw/itkYErWXRx+fFArt9Ca9os78TFed0LVIUsmIHrwbwaw3BEOnOk94qVpQ6Ka2HjxewJnfyd6jUtGDQLdWlzmYNYLeKbbGOucJsNabCq1Yub0o92rtR+i30V2dapxYVEePXcOjeCKPnYyit7BtKeNlZqHbr+gt7i+AChWA9RsRs03pxTQc67ouWpxyESvjK5Vs3DVSy3IpkxPm5X+wZoBi+MFHWW69/w8FRhc7VBe6HAhMB2b8Q0XqDzTNZtXUMnKMjwKVaCrB/CSUL7WSx/HsdJC86lFGXwnioTeOMPjV+szlFvrZLA5VMVK4y+41l4e1xfx7Z88o4hkilRUH/qKqwNVlgDgpvYCpH3XwAy5eMCRnezIUxffVXoDql2rTHFDO+pjWnTWzAfrYXn6BFECblUpWGrvPZvBipETjS5ydM7tdXpH41ZCEbBNy/+wFZu71QO2t9pgT+iZEf657Q1vpN94PQNDxUHeKR103LV9nPVOtDikcNKO+2naCw7yKBhOe9Hm79pe8C4/CfC2wDjXnqC94kEeBU3WwN7dt/2UScXas7zDl5GpkY+M8WKv2J7fd4Ib2rGTk+jsC2cleEM7jI9veF7B0MBJrsZqfKd/81q9pR2NZfwJK2JzsmIT1Ns8jUH0UusQBpU8d2JzsHiXg1zXGLqxfitUNTDT/nUUeqDBp2HZVr+Ocqi/Ty3Rf4Jn82xxfSNtAAAAAElFTkSuQmCC"

  },

  "localesToInstall": [

    "en-us"

  ],

  "notes": "",

  "officePlatformArchitecture": "x86",

  "owner": "Microsoft",

  "privacyInformationUrl": "",

  "productIds": [

    "o365ProPlusRetail"

  ],

  "publisher": "Microsoft",

  "updateChannel": "current",

  "useSharedComputerActivation": true

}



"@

####################################################

$Office64 = @"



{

  "@odata.type": "#microsoft.graph.officeSuiteApp",

  "autoAcceptEula": true,

  "description": "[ITPM Corporate] 64-bit Microsoft 365 Desktop apps",

  "developer": "Microsoft",

  "displayName": "[ITPM Corporate] 64-bit Microsoft 365 Desktop apps",

  "excludedApps": {

    "groove": true,

    "infoPath": true,

    "lync":  true,

    "sharePointDesigner": true

  },

  "informationUrl": "",

  "isFeatured": false,

  "largeIcon": {

    "type": "image/png",

    "value": "iVBORw0KGgoAAAANSUhEUgAAAF0AAAAeCAMAAAEOZNKlAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAJhUExURf////7z7/i9qfF1S/KCW/i+qv3q5P/9/PrQwfOMae1RG+s8AOxGDfBtQPWhhPvUx/759/zg1vWgg+9fLu5WIvKFX/rSxP728/nCr/FyR+tBBvOMaO1UH+1RHOs+AvSScP3u6f/+/v3s5vzg1+xFDO9kNPOOa/i7pvzj2/vWyes9Af76+Pzh2PrTxf/6+f7y7vOGYexHDv3t5+1SHfi8qPOIZPvb0O1NFuxDCe9hMPSVdPnFs/3q4/vaz/STcu5VIe5YJPWcfv718v/9/e1MFfF4T/F4TvF2TP3o4exECvF0SexIEPONavzn3/vZze1QGvF3Te5dK+5cKvrPwPrQwvKAWe1OGPexmexKEveulfezm/BxRfamiuxLE/apj/zf1e5YJfSXd/OHYv3r5feznPakiPze1P7x7f739f3w6+xJEfnEsvWdf/Wfge1LFPe1nu9iMvnDsfBqPOs/BPOIY/WZevJ/V/zl3fnIt/vTxuxHD+xEC+9mN+5ZJv749vBpO/KBWvBwRP/8+/SUc/etlPjArP/7+vOLZ/F7UvWae/708e1OF/aihvSWdvi8p+tABfSZefvVyPWihfSVde9lNvami+9jM/zi2fKEXvBuQvOKZvalifF5UPJ/WPSPbe9eLfrKuvvd0uxBB/7w7Pzj2vrRw/rOv+1PGfi/q/eymu5bKf3n4PnJuPBrPf3t6PWfgvWegOxCCO9nOO9oOfaskvSYePi5pPi2oPnGtO5eLPevlvKDXfrNvv739Pzd0/708O9gL+9lNfJ9VfrLu/OPbPnDsPBrPus+A/nArfarkQAAAGr5HKgAAADLdFJOU/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////8AvuakogAAAAlwSFlzAAAOwwAADsMBx2+oZAAAAz5JREFUOE+tVTtu4zAQHQjppmWzwIJbEVCzpTpjbxD3grQHSOXKRXgCAT6EC7UBVAmp3KwBnmvfzNCyZTmxgeTZJsXx43B+HBHRE34ZkXgkerXFTheeiCkRrbB4UXmp4wSWz5raaQEMTM5TZwuiXoaKgV+6FsmkZQcSy0kA71yMTMGHanX+AzMMGLAQCxU1F/ZwjULPugazl82GM0NEKm/U8EqFwEkO3/EAT4grgl0nucwlk9pcpTTJ4VPA4g/Rb3yIRhhp507e9nTQmZ1OS5RO4sS7nIRPEeHXCHdkw9ZEW2yVE5oIS7peD58Avs7CN+PVCmHh21oOqBdjDzIs+FldPJ74TFESUSJEfVzy9U/dhu+AuOT6eBp6gGKyXEx8euO450ZE4CMfstMFT44broWw/itkYErWXRx+fFArt9Ca9os78TFed0LVIUsmIHrwbwaw3BEOnOk94qVpQ6Ka2HjxewJnfyd6jUtGDQLdWlzmYNYLeKbbGOucJsNabCq1Yub0o92rtR+i30V2dapxYVEePXcOjeCKPnYyit7BtKeNlZqHbr+gt7i+AChWA9RsRs03pxTQc67ouWpxyESvjK5Vs3DVSy3IpkxPm5X+wZoBi+MFHWW69/w8FRhc7VBe6HAhMB2b8Q0XqDzTNZtXUMnKMjwKVaCrB/CSUL7WSx/HsdJC86lFGXwnioTeOMPjV+szlFvrZLA5VMVK4y+41l4e1xfx7Z88o4hkilRUH/qKqwNVlgDgpvYCpH3XwAy5eMCRnezIUxffVXoDql2rTHFDO+pjWnTWzAfrYXn6BFECblUpWGrvPZvBipETjS5ydM7tdXpH41ZCEbBNy/+wFZu71QO2t9pgT+iZEf657Q1vpN94PQNDxUHeKR103LV9nPVOtDikcNKO+2naCw7yKBhOe9Hm79pe8C4/CfC2wDjXnqC94kEeBU3WwN7dt/2UScXas7zDl5GpkY+M8WKv2J7fd4Ib2rGTk+jsC2cleEM7jI9veF7B0MBJrsZqfKd/81q9pR2NZfwJK2JzsmIT1Ns8jUH0UusQBpU8d2JzsHiXg1zXGLqxfitUNTDT/nUUeqDBp2HZVr+Ocqi/Ty3Rf4Jn82xxfSNtAAAAAElFTkSuQmCC"

  },

  "localesToInstall": [

    "en-us"

  ],

  "notes": "",

  "officePlatformArchitecture": "x64",

  "owner": "Microsoft",

  "privacyInformationUrl": "",

  "productIds": [

    "o365ProPlusRetail"

  ],

  "publisher": "Microsoft",

  "updateChannel": "current",

  "useSharedComputerActivation": true

}



"@

####################################################

$ChrEdge = @"

{
    "@odata.context":  "https://graph.microsoft.com/Beta/$metadata#deviceAppManagement/mobileApps/$entity",
    "@odata.type":  "#microsoft.graph.windowsMicrosoftEdgeApp",
    "displayName":  "[ITPM Corporate] Chromium Edge for Windows",
    "description":  "Microsoft Edge is the browser for business with modern and legacy web compatibility, new privacy features such as Tracking prevention, and built-in productivity tools such as enterprise-grade PDF support and access to Office and corporate search right from a new tab.",
    "publisher":  "Microsoft",
    "isFeatured":  false,
    "privacyInformationUrl":  "https://privacy.microsoft.com/en-US/privacystatement",
    "informationUrl":  "https://www.microsoft.com/en-us/windows/microsoft-edge",
    "developer":  "Microsoft",
    "isAssigned":  false,
    "dependentAppCount":  0,
    "channel":  "stable",
    "displayLanguageLocale":  null
}

"@

####################################################

$SB_WinBase = @"

{
    "displayName":  "[ITPM Corporate] Modified Baseline for Windows OS",
    "description":  "Assign this profile to Company owned Windows devices. This baseline has been modified to remove overlap with other Endpoint Security profiles; for example BitLocker, Firewall, Microsoft Defender settings and more.",
    "settingsDelta":  [
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "2f6d9cd8-3581-44a2-9840-714ca091f5a1",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_lockScreenActivateAppsWithVoice",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "c3ecf669-f176-4fea-bdfa-c55d9f6b40d4",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_lockScreenBlockToastNotifications",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "f6948045-fc3f-433a-b7ef-555b5040ff28",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_accountLogonAuditCredentialValidation",
                              "valueJson":  "\"successAndFailure\"",
                              "value":  "successAndFailure"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "dda5a20c-49be-430a-ac8f-dcc34c5701dd",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_accountLogonAuditKerberosAuthenticationService",
                              "valueJson":  "\"none\"",
                              "value":  "none"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "4e1703da-09a7-41a0-a40f-c653581ce99d",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_accountLogonLogoffAuditAccountLockout",
                              "valueJson":  "\"failure\"",
                              "value":  "failure"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "08874a58-96b7-45a7-8694-667e6003a125",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_accountLogonLogoffAuditGroupMembership",
                              "valueJson":  "\"success\"",
                              "value":  "success"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b0593c58-5e56-4465-aa5b-a5f36a7cacf1",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_accountLogonLogoffAuditLogon",
                              "valueJson":  "\"successAndFailure\"",
                              "value":  "successAndFailure"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "d0b168f9-cb5d-4ba5-b7d9-d72ad983458b",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_accountLogonLogoffAuditOtherLogonLogoffEvents",
                              "valueJson":  "\"successAndFailure\"",
                              "value":  "successAndFailure"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "d17197db-39ba-49f9-b529-318816d315b5",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_accountLogonLogoffAuditSpecialLogon",
                              "valueJson":  "\"success\"",
                              "value":  "success"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b9c89a6e-4313-4f1b-b575-90274d606a39",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_accountManagementAuditSecurityGroupManagement",
                              "valueJson":  "\"success\"",
                              "value":  "success"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "936aa843-ae0a-45e9-8488-e3f097851b13",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_accountManagementAuditUserAccountManagement",
                              "valueJson":  "\"successAndFailure\"",
                              "value":  "successAndFailure"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b5077cca-0fba-4c86-bc9b-6cc43849a200",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_detailedTrackingAuditPNPActivity",
                              "valueJson":  "\"success\"",
                              "value":  "success"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "d7864c55-ecbb-43bd-acc5-22b091cfaca8",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_detailedTrackingAuditProcessCreation",
                              "valueJson":  "\"success\"",
                              "value":  "success"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "3334b5db-46d7-4de4-bb1a-7cc1a63313e1",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_objectAccessAuditDetailedFileShare",
                              "valueJson":  "\"failure\"",
                              "value":  "failure"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "5cdd9803-739f-486d-80ad-d4d9df2d21c3",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_objectAccessAuditFileShare",
                              "valueJson":  "\"successAndFailure\"",
                              "value":  "successAndFailure"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "d6b396df-0cfe-4a66-82ba-e507cfda158b",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_objectAccessAuditOtherObjectAccessEvents",
                              "valueJson":  "\"successAndFailure\"",
                              "value":  "successAndFailure"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "c2ac7686-39ae-48e5-aa16-f5d315e6c5de",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_objectAccessAuditRemovableStorage",
                              "valueJson":  "\"successAndFailure\"",
                              "value":  "successAndFailure"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "387aa34b-0cc2-483b-9bca-0f829c5143b1",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_policyChangeAuditAuthenticationPolicyChange",
                              "valueJson":  "\"success\"",
                              "value":  "success"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "fc9c6b6d-6b7d-4654-a959-5bd55bbc7e16",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_policyChangeAuditMPSSVCRuleLevelPolicyChange",
                              "valueJson":  "\"successAndFailure\"",
                              "value":  "successAndFailure"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "1d20b945-52d2-4f86-b4cc-b7ff440b1d4f",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_policyChangeAuditOtherPolicyChangeEvents",
                              "valueJson":  "\"failure\"",
                              "value":  "failure"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "0727ff50-ce13-4b0b-adb8-7f84d3f3c6e3",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_policyChangeAuditPolicyChange",
                              "valueJson":  "\"success\"",
                              "value":  "success"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "57f4c7fd-16b6-4f8e-b4e7-c5c45d39eaec",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_privilegeUseAuditSensitivePrivilegeUse",
                              "valueJson":  "\"successAndFailure\"",
                              "value":  "successAndFailure"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "dc72fbde-d4ba-4b0f-813c-98cf0b861fce",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_systemAuditOtherSystemEvents",
                              "valueJson":  "\"successAndFailure\"",
                              "value":  "successAndFailure"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "61ef4a8f-7e01-43f6-9c8f-07194356d325",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_systemAuditSecurityStateChange",
                              "valueJson":  "\"success\"",
                              "value":  "success"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "5ed55428-a14b-4674-86d0-e327a2ce58aa",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_systemAuditSecuritySystemExtension",
                              "valueJson":  "\"success\"",
                              "value":  "success"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "1c730044-a2eb-47d2-9ccf-89212207123b",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_systemAuditSystemIntegrity",
                              "valueJson":  "\"successAndFailure\"",
                              "value":  "successAndFailure"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "64c74d0a-21cc-4601-ac75-a2139993a63e",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_deviceGuardSecureBootWithDMA",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "d3b985b0-86b0-492d-a1f9-bdbf01075350",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_deviceGuardEnableVirtualizationBasedSecurity",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "44ee73c4-2c7f-4fcd-a6c4-e4453b112158",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_deviceGuardLaunchSystemGuard",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "2bdc1d56-d8d7-4040-a47b-c066f9366685",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_deviceGuardLocalSystemAuthorityCredentialGuardSettings",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "f31d6124-943d-4a65-bab6-4804355aaee7",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_appManagementMSIAlwaysInstallWithElevatedPrivileges",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "6ac96999-b567-4891-9197-1f4999e081ef",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_appManagementMSIAllowUserControlOverInstall",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "47cb7f9a-b5fc-43d5-8af1-0e641d59f9c1",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_gameDvrBlocked",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "8b862416-1590-4f7f-a70e-d71291005b75",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAdobeReaderLaunchChildProcess",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "8fd3e1b9-dd39-4f44-8fda-035cbcc2f895",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderOfficeCommunicationAppsLaunchChildProcess",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "4cc5758e-7984-4516-8830-2c6683d83d6f",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_defenderSignatureUpdateIntervalInHours",
                              "valueJson":  "1",
                              "value":  1
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "4524e179-3570-40e9-82a2-3492a3f31f31",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_defenderScanType",
                              "valueJson":  "\"userDefined\"",
                              "value":  "userDefined"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "59adb26b-9e8b-49fc-a8bc-0696002b817f",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_defenderScheduleScanDay",
                              "valueJson":  "\"everyday\"",
                              "value":  "everyday"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "07fd9428-c831-4738-867e-2a8819ac3781",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_defenderScheduledScanTime",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "f8a40e22-977a-4b8a-9a49-3679041e230f",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_defenderCloudBlockLevel",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "bf97bb5a-5962-4095-9a61-ba1adb8b86e1",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_defenderScanNetworkFiles",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "a25c7b38-9bfc-42b7-843d-d7093ec3cc62",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_defenderRequireRealTimeMonitoring",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "c73d6449-d7a7-4b5a-aeb0-732784ff9af3",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_defenderScanArchiveFiles",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "dd17c6b0-39ff-4124-9093-9e563f40d3d0",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_defenderRequireBehaviorMonitoring",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "2324793a-789c-4f3c-a3a0-13533da6a6b8",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_defenderRequireCloudProtection",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "2ac1a4b6-16e5-4ff3-9e4d-503c1c9deff1",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_defenderScanIncomingMail",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "bda1eed3-e1c4-473b-99a4-585b3c6e2068",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_defenderScanRemovableDrivesDuringFullScan",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "97244ea8-4bcd-49f5-b0dd-5beb4d808181",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderOfficeAppsOtherProcessInjectionType",
                              "valueJson":  "\"userDefined\"",
                              "value":  "userDefined"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "29cf2cd6-fa48-4c1c-a9fe-73479100583b",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderOfficeAppsExecutableContentCreationOrLaunchType",
                              "valueJson":  "\"userDefined\"",
                              "value":  "userDefined"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "35d80002-842c-404d-9ec0-e6b45a7dcfa4",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderOfficeAppsLaunchChildProcessType",
                              "valueJson":  "\"userDefined\"",
                              "value":  "userDefined"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "c3de920b-796f-43a4-bb68-4a2b371894ce",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderOfficeMacroCodeAllowWin32ImportsType",
                              "valueJson":  "\"userDefined\"",
                              "value":  "userDefined"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "404a2be3-9bd6-4f7b-acd0-a6786cbc272c",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderScriptObfuscatedMacroCodeType",
                              "valueJson":  "\"userDefined\"",
                              "value":  "userDefined"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "d28baf9f-3195-49c0-ae9e-5d0e3b487803",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderScriptDownloadedPayloadExecutionType",
                              "valueJson":  "\"userDefined\"",
                              "value":  "userDefined"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "f794d471-b48c-47f5-b628-50286caad642",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderEmailContentExecutionType",
                              "valueJson":  "\"userDefined\"",
                              "value":  "userDefined"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "f62c57a0-3dfc-4395-9372-08e62670a1ee",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderPreventCredentialStealingType",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "99be2a6e-f676-4560-8dbe-95838b2d8615",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_defenderPotentiallyUnwantedAppAction",
                              "valueJson":  "\"deviceDefault\"",
                              "value":  "deviceDefault"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "9b0e2395-9671-4983-8647-ebc1859c0881",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderUntrustedUSBProcessType",
                              "valueJson":  "\"userDefined\"",
                              "value":  "userDefined"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "6da7691e-2f50-40b3-bedb-2bda6df13a63",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderNetworkProtectionType",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "172755ba-0341-48bf-9300-a1dfef8f71d1",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_defenderSubmitSamplesConsentType",
                              "valueJson":  "\"sendSafeSamplesAutomatically\"",
                              "value":  "sendSafeSamplesAutomatically"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "96ba863d-ba6c-4460-a41d-14de46638cbe",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_smartScreenEnableInShell",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "d877ad0e-22de-423d-a1bd-5f83255d3939",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_smartScreenBlockOverrideForFiles",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "63514eca-5e32-474d-9b2e-3d8b11085d96",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_connectivityDownloadingOfPrintDriversOverHttp",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b918369b-2fac-4a14-9226-26750bde419e",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_connectivityInternetDownloadForWebPublishingAndOnlineOrderingWizards",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementCollectionSettingInstance",
                              "id":  "89db2afc-0345-4b20-8801-5453777e8518",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerEncryptionSupport",
                              "valueJson":  "[\"tls11\",\"tls12\"]"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b9345ad8-e3fb-4767-a57b-26ab14f6253b",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerPreventManagingSmartScreenFilter",
                              "valueJson":  "\"enable\"",
                              "value":  "enable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "58c95ce8-b10a-48c6-ab32-91562eee1a03",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneScriptActiveXControlsMarkedSafeForScripting",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "ea70745a-3313-4086-bc7d-6a04298de503",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneFileDownloads",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "91c39732-b276-4743-86fe-0aa7bedcf4d9",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerCertificateAddressMismatchWarning",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "f59eb2c7-a9a3-49ef-9936-b96d265a2745",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerEnhancedProtectedMode",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "37340ced-88fd-41ad-8bcb-671a07ca2967",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerFallbackToSsl3",
                              "valueJson":  "\"noSites\"",
                              "value":  "noSites"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "4427cca3-0784-42a3-84c2-83f8510317a9",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerSoftwareWhenSignatureIsInvalid",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "0f335143-6f12-4d8e-aa29-6a58d3ba9857",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerCheckServerCertificateRevocation",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "018e231e-26f3-4ba2-adf7-9564a3c3b6bd",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerCheckSignaturesOnDownloadedPrograms",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "a027a06d-150c-4387-b704-cbf84f20b447",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerProcessesConsistentMimeHandling",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b57802dc-044d-4d0d-82f9-ec42c327bc3c",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerBypassSmartScreenWarnings",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "85652a68-85d7-4969-ae4d-5cf9fc33277c",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerBypassSmartScreenWarningsAboutUncommonFiles",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "4fe5e682-fddf-4551-8be2-570d8971a430",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerCrashDetection",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "06a954b7-17e5-4a23-a247-d97d9d8e5875",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerDownloadEnclosures",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "5f972965-e082-4b69-bcd3-26cd38b041ce",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerIgnoreCertificateErrors",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "3a003e22-a58a-4b87-9eac-a7f4724eb858",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerDisableProcessesInEnhancedProtectedMode",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "6f0e7965-10f9-4147-90c2-10c227f7bf6c",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerSecuritySettingsCheck",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "464900f2-ca45-4058-b4b0-1a09bec5ca0b",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerActiveXControlsInProtectedMode",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "5b76e0ab-552b-4203-9f14-378d4330e60e",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerUsersAddingSites",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "35d6e4a2-2514-4513-9179-c15ae088d1b1",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerUsersChangingPolicies",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "2ad90a3a-d07c-47be-8058-b1184d89a8bf",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerBlockOutdatedActiveXControls",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "a886af20-8c02-4f97-b4f9-f1b2e20df7ca",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerIncludeAllNetworkPaths",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "5e48ddc0-6c32-4dfc-97fb-d834aa930e19",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneAccessToDataSources",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "ba70186e-aed3-4125-b994-67989b73c9d4",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneAutomaticPromptForFileDownloads",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "87dbd921-dd3a-4209-baf6-1b4508544ac5",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneCopyAndPasteViaScript",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "f28d3bda-1ac9-4aa5-83ef-24ebf16b8c4e",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneDragAndDropOrCopyAndPasteFiles",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "05937628-fb65-4df8-ab90-e9f2e428b6c1",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneLessPrivilegedSites",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "c2714d00-c800-4c5a-ad71-40b6c4fb54e0",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneLoadingOfXamlFiles",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "9d294dbc-387a-441e-807f-1cb999a295b3",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneDotNetFrameworkReliantComponents",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "9249655f-39b4-4d12-a57b-c5c694646bb7",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneAllowOnlyApprovedDomainsToUseActiveXControls",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "adbda295-65af-4a65-98ef-3641831307e8",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneAllowOnlyApprovedDomainsToUseTdcActiveXControls",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "a1dffa71-8597-42c2-b54a-2604d46f7fef",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneScriptingOfWebBrowserControls",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "bbab6211-916a-4669-95a5-17d412d108e5",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneScriptInitiatedWindows",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "af104e64-3e30-48f9-aa4c-28676b9568a7",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneScriptlets",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "909e44d2-c7c6-4f07-91a5-c577561d7660",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneSmartScreen",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "69a23429-a118-426e-a3b2-42a31491c880",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneUpdatesToStatusBarViaScript",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "622702c8-4ba0-41e5-a1bc-22418d10c395",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneUserDataPersistence",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "109e0919-c8e1-4e2f-b0b9-85906685aa04",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneAllowVBScriptToRun",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "2cac2dab-9cac-42cc-a12d-9499e5b0b7fd",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneDoNotRunAntimalwareAgainstActiveXControls",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "cfcc154d-0c89-4e84-9e30-69f0be11b093",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneDownloadSignedActiveXControls",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "35010960-646e-4b73-ba40-27f29d178759",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneDownloadUnsignedActiveXControls",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "c29270b6-d6f6-4019-ad1d-04fe5430f9eb",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneCrossSiteScriptingFilter",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "f73288fd-7fba-4355-96bd-b8f01e462c12",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneDragContentFromDifferentDomainsAcrossWindows",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "69171533-dc82-4108-97ab-62a525c9cba9",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneDragContentFromDifferentDomainsWithinWindows",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b5edb88c-5e77-4147-a67e-b685759eda4a",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneProtectedMode",
                              "valueJson":  "\"enable\"",
                              "value":  "enable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "63886b7f-a372-48c0-acfd-907da7ccb2aa",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneIncludeLocalPathWhenUploadingFilesToServer",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "9cc6f37f-5d97-4521-a1e2-96a41325129b",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneInitializeAndScriptActiveXControlsNotMarkedAsSafe",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "6268cba1-fa78-490e-bc36-1e2cecf6f84d",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneJavaPermissions",
                              "valueJson":  "\"disableJava\"",
                              "value":  "disableJava"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "9a1acdce-a511-4db8-8448-8efc9485a114",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneLaunchApplicationsAndFilesInAnIFrame",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "247612e1-e66d-4993-908c-504895b3875a",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneLogonOptions",
                              "valueJson":  "\"prompt\"",
                              "value":  "prompt"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b07def3f-15fe-48e0-9e2a-01c696e6c674",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneNavigateWindowsAndFramesAcrossDifferentDomains",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "c0531a23-f495-4cb7-9eb8-eee617cb8f0a",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneRunDotNetFrameworkReliantComponentsSignedWithAuthenticode",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "597aa534-a960-422e-b7a1-88cb171878ed",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZoneSecurityWarningForPotentiallyUnsafeFiles",
                              "valueJson":  "\"prompt\"",
                              "value":  "prompt"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "85993b64-7288-48f9-ae14-8fcfd3b6b523",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerInternetZonePopupBlocker",
                              "valueJson":  "\"enable\"",
                              "value":  "enable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "4a181255-a192-4c75-b4fc-da81380547c5",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerIntranetZoneDoNotRunAntimalwareAgainstActiveXControls",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "ea49c33c-9106-4b73-af65-c922f2e57426",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerIntranetZoneInitializeAndScriptActiveXControlsNotMarkedAsSafe",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b6c50009-667b-42c5-8d89-66a872c17081",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerIntranetZoneJavaPermissions",
                              "valueJson":  "\"highSafety\"",
                              "value":  "highSafety"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "2fe87f3e-1b55-4503-96d2-d7e925d3b65d",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerLocalMachineZoneDoNotRunAntimalwareAgainstActiveXControls",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "2f932890-e803-4037-9094-061883380df8",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerLocalMachineZoneJavaPermissions",
                              "valueJson":  "\"disableJava\"",
                              "value":  "disableJava"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "c0cd1dd6-8677-4fca-9ee5-5c7b2d0df7e8",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerLockedDownInternetZoneSmartScreen",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b248c155-ce0c-4fb3-9aff-d1f9abbc7d92",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerLockedDownIntranetZoneJavaPermissions",
                              "valueJson":  "\"disableJava\"",
                              "value":  "disableJava"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "dca2fa69-c678-4347-985f-c0614564c056",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerLockedDownLocalMachineZoneJavaPermissions",
                              "valueJson":  "\"disableJava\"",
                              "value":  "disableJava"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "d8a3443e-9e81-44c5-a8c4-7d6c87bb3c8b",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerLockedDownRestrictedZoneSmartScreen",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "0d10bd54-2c4e-4866-8426-99a7486886c2",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerLockedDownRestrictedZoneJavaPermissions",
                              "valueJson":  "\"disableJava\"",
                              "value":  "disableJava"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "a5fc6f57-abce-4569-9af2-f83481e11902",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerLockedDownTrustedZoneJavaPermissions",
                              "valueJson":  "\"disableJava\"",
                              "value":  "disableJava"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "95f7241f-23f1-4d14-b313-ff4ada3b7151",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerProcessesMimeSniffingSafetyFeature",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "0578351d-83a3-4ef9-b0ec-704316849a01",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerProcessesMKProtocolSecurityRestriction",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "638a0f3a-13b4-4ddd-84a6-952d66912af5",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerProcessesNotificationBar",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "8816a920-28a6-47d8-95bf-c910a88d75ac",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerPreventPerUserInstallationOfActiveXControls",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "ae34b151-4e87-4a50-b9da-9b408e8cff0c",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerProcessesProtectionFromZoneElevation",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "e30d933f-004e-444e-a9a2-a8c13c4ecd3f",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRemoveRunThisTimeButtonForOutdatedActiveXControls",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "6a0af8dc-1e5a-44f3-ac39-1e77c89d50b9",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerProcessesRestrictActiveXInstall",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "19d52128-23e2-42d2-8118-aea8ab0ad22a",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneAccessToDataSources",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "019f9b47-5d72-4c48-acc8-d0f0cb4cf922",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneActiveScripting",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "7d7af09d-9e75-43da-a81e-f34ed1545237",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneAutomaticPromptForFileDownloads",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "fffd5ac8-554c-4f94-a41c-200abed726ea",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneBinaryAndScriptBehaviors",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "9e60a3b6-b6c3-4043-8fbc-ce0287ad5099",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneCopyAndPasteViaScript",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "a742b148-00fa-46b2-9595-576dff309f1f",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneDragAndDropOrCopyAndPasteFiles",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "8d56c8cf-9980-4fba-b685-dabf098f2d38",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneLessPrivilegedSites",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "dd6aca3b-8f97-48a6-919e-4510de1178ee",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneLoadingOfXamlFiles",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "a9ea7a10-ccf4-415e-acd4-359d22e2c85a",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneMetaRefresh",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "059d0f04-64e4-467b-a03e-fbfd97417e75",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneDotNetFrameworkReliantComponents",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "d2744856-ade1-4f3d-a5b9-e17d9b8daf23",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneAllowOnlyApprovedDomainsToUseActiveXControls",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "50c9aaa6-5ae3-401b-8e5f-7e60bbb5f99b",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneAllowOnlyApprovedDomainsToUseTdcActiveXControls",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "3ce2e07a-0edc-4545-a1c3-48b7af8b8d85",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneScriptingOfWebBrowserControls",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "2800bbb1-4b82-4732-be01-bce74083f7a1",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneScriptInitiatedWindows",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "51351de8-453a-47af-bc3c-57c9ea96b6d5",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneScriptlets",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b3b8af6e-94dc-43d0-ac9b-e177e07feb18",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneSmartScreen",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "a1038c65-61b7-4722-b379-1f2e0a2d2f81",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneUpdatesToStatusBarViaScript",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "7ea30c71-8427-4806-be54-797e349d3ce5",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneUserDataPersistence",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "6f88c7e7-6fe5-4eb2-870f-d8e347aa92bc",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneAllowVBScriptToRun",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "1dec5595-be60-45b3-b563-2f8d21423c69",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneDoNotRunAntimalwareAgainstActiveXControls",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "6d325400-38ce-42bd-9184-87ff31902f6c",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneDownloadSignedActiveXControls",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "ed32ec98-deec-43ca-91d5-3480f068a442",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneDownloadUnsignedActiveXControls",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "d851c4d3-d19e-4513-a300-c773eccb0bdb",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneCrossSiteScriptingFilter",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "871eefa4-b65a-4be5-9348-49bfe60dca10",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneDragContentFromDifferentDomainsAcrossWindows",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "6b537cae-543c-4ea7-9018-17bb386d3d19",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneDragContentFromDifferentDomainsWithinWindows",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "93ed0238-9a9a-4e97-bbab-d96e28a5b2fb",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneIncludeLocalPathWhenUploadingFilesToServer",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "800c35dc-bd44-471e-b62d-2befee36c1fc",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneInitializeAndScriptActiveXControlsNotMarkedAsSafe",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "fffd3ea1-03ed-4864-9548-565f130f9072",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneJavaPermissions",
                              "valueJson":  "\"disableJava\"",
                              "value":  "disableJava"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "cd3111f3-ee8d-48aa-bf05-b336f26a2ef2",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneLaunchApplicationsAndFilesInAnIFrame",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b2f63520-0e54-4259-b197-ab27262a9c9e",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneLogonOptions",
                              "valueJson":  "\"anonymous\"",
                              "value":  "anonymous"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "ac8e1637-01af-4b76-bb71-0504c8e4d131",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneNavigateWindowsAndFramesAcrossDifferentDomains",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "feb738f0-cabc-411f-8e1a-7ebe99386f71",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneRunActiveXControlsAndPlugins",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "4c757a0e-a0d8-4079-aa31-e9de821d7fd0",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneRunDotNetFrameworkReliantComponentsSignedWithAuthenticode",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "4d9f56dc-d82b-44cf-9537-8b8bdfdc4e5b",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneScriptingOfJavaApplets",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "6b70c0b5-647b-4398-a82a-7bc5b08556c6",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneSecurityWarningForPotentiallyUnsafeFiles",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "3579352f-baa5-4d75-b85f-aa2d160e68cf",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZoneProtectedMode",
                              "valueJson":  "\"enable\"",
                              "value":  "enable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "436f7f18-3798-4752-8e1f-fa6c29ae5225",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerRestrictedZonePopupBlocker",
                              "valueJson":  "\"enable\"",
                              "value":  "enable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "f0b345ea-6399-4a3a-8119-3a0493e2a0bb",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerProcessesRestrictFileDownload",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "87a45585-ed33-42f8-bdaa-f0919b2ece92",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerProcessesScriptedWindowSecurityRestrictions",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "f14dfe4f-cd0c-492e-a40b-be2fa9fa9b6a",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerSecurityZonesUseOnlyMachineSettings",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "a5f7fec5-cb0c-49a7-8765-8312baa10925",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerUseActiveXInstallerService",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b9cce8be-85fd-4842-a31d-72358ffa2565",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerTrustedZoneDoNotRunAntimalwareAgainstActiveXControls",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "51dcacac-b986-4baa-a595-6e46c802df00",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerTrustedZoneInitializeAndScriptActiveXControlsNotMarkedAsSafe",
                              "valueJson":  "\"disable\"",
                              "value":  "disable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "d5a9536b-ea85-473c-9984-6fd7ba409d4e",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerTrustedZoneJavaPermissions",
                              "valueJson":  "\"highSafety\"",
                              "value":  "highSafety"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "3b923cc2-b58d-4258-a8fd-826f818b0b75",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetExplorerAutoComplete",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "cff64c48-ad11-4a43-8233-860331279c88",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_dmaGuardDeviceEnumerationPolicy",
                              "valueJson":  "\"blockAll\"",
                              "value":  "blockAll"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementComplexSettingInstance",
                              "id":  "16d0d1d8-19d0-43e6-94ed-bac1197cd99e",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfileDomain",
                              "valueJson":  "{\"inboundConnectionsBlocked\":false,\"outboundConnectionsRequired\":false,\"inboundNotificationsBlocked\":false,\"firewallEnabled\":\"notConfigured\"}",
                              "value":  [
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "51d4c2b0-a4a5-41ca-b1c0-7913c475c0a1",
                                                "definitionId":  "deviceConfiguration--windowsFirewallNetworkProfile_inboundConnectionsBlocked",
                                                "valueJson":  "false",
                                                "value":  false
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "6a78e291-019a-499b-813c-96b5d569b73c",
                                                "definitionId":  "deviceConfiguration--windowsFirewallNetworkProfile_outboundConnectionsRequired",
                                                "valueJson":  "false",
                                                "value":  false
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "e89b5765-0737-477e-8474-b8991607833e",
                                                "definitionId":  "deviceConfiguration--windowsFirewallNetworkProfile_inboundNotificationsBlocked",
                                                "valueJson":  "false",
                                                "value":  false
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "dbcab8de-fa2a-4a10-bd2b-f760c260a078",
                                                "definitionId":  "deviceConfiguration--windowsFirewallNetworkProfile_firewallEnabled",
                                                "valueJson":  "\"notConfigured\"",
                                                "value":  "notConfigured"
                                            }
                                        ]
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementComplexSettingInstance",
                              "id":  "7d6b9a27-0317-4180-93a4-89f7431032b7",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePrivate",
                              "valueJson":  "{\"inboundConnectionsBlocked\":false,\"outboundConnectionsRequired\":false,\"inboundNotificationsBlocked\":false,\"firewallEnabled\":\"notConfigured\"}",
                              "value":  [
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "d17e710a-80a1-42e1-a806-e582d1a27f89",
                                                "definitionId":  "deviceConfiguration--windowsFirewallNetworkProfile_inboundConnectionsBlocked",
                                                "valueJson":  "false",
                                                "value":  false
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "979cc9c0-c5a7-4be6-afe0-333a28049306",
                                                "definitionId":  "deviceConfiguration--windowsFirewallNetworkProfile_outboundConnectionsRequired",
                                                "valueJson":  "false",
                                                "value":  false
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "dd62121a-5ef8-48c5-ac76-a9d262007bf2",
                                                "definitionId":  "deviceConfiguration--windowsFirewallNetworkProfile_inboundNotificationsBlocked",
                                                "valueJson":  "false",
                                                "value":  false
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "28bdb616-3627-4de5-8289-299036cf5df8",
                                                "definitionId":  "deviceConfiguration--windowsFirewallNetworkProfile_firewallEnabled",
                                                "valueJson":  "\"notConfigured\"",
                                                "value":  "notConfigured"
                                            }
                                        ]
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementComplexSettingInstance",
                              "id":  "9e697338-48ca-4d72-89f1-60c7d1bc2fa1",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePublic",
                              "valueJson":  "{\"inboundConnectionsBlocked\":false,\"outboundConnectionsRequired\":false,\"inboundNotificationsBlocked\":false,\"firewallEnabled\":\"notConfigured\",\"connectionSecurityRulesFromGroupPolicyNotMerged\":false,\"policyRulesFromGroupPolicyNotMerged\":false}",
                              "value":  [
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "06534e2d-871e-4753-a89d-b789c480e221",
                                                "definitionId":  "deviceConfiguration--windowsFirewallNetworkProfile_inboundConnectionsBlocked",
                                                "valueJson":  "false",
                                                "value":  false
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "09e68423-c549-45b1-9c9e-950aeac848ba",
                                                "definitionId":  "deviceConfiguration--windowsFirewallNetworkProfile_outboundConnectionsRequired",
                                                "valueJson":  "false",
                                                "value":  false
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "bc40ce1e-c385-413c-92c0-887302347dc6",
                                                "definitionId":  "deviceConfiguration--windowsFirewallNetworkProfile_inboundNotificationsBlocked",
                                                "valueJson":  "false",
                                                "value":  false
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "04a262e3-98c1-44f3-a0f4-d5d6c6e2af15",
                                                "definitionId":  "deviceConfiguration--windowsFirewallNetworkProfile_firewallEnabled",
                                                "valueJson":  "\"notConfigured\"",
                                                "value":  "notConfigured"
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "a3fb7e0b-6ed7-4429-a860-294a9f881066",
                                                "definitionId":  "deviceConfiguration--windowsFirewallNetworkProfile_connectionSecurityRulesFromGroupPolicyNotMerged",
                                                "valueJson":  "false",
                                                "value":  false
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "1f3e9678-927a-4e73-b81d-00bb04b02e91",
                                                "definitionId":  "deviceConfiguration--windowsFirewallNetworkProfile_policyRulesFromGroupPolicyNotMerged",
                                                "valueJson":  "false",
                                                "value":  false
                                            }
                                        ]
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementComplexSettingInstance",
                              "id":  "006b2c2b-613b-45ad-83f4-b49dd13d455b",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerRemovableDrivePolicy",
                              "valueJson":  "{\"requireEncryptionForWriteAccess\":false}",
                              "value":  [
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "f86b41d2-fe52-4b94-99bd-8139fdb0c2d4",
                                                "definitionId":  "deviceConfiguration--bitLockerRemovableDrivePolicy_requireEncryptionForWriteAccess",
                                                "valueJson":  "false",
                                                "value":  false
                                            }
                                        ]
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "643d7fad-b37e-4b05-9b9a-9dcec5a948dd",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_searchDisableIndexingEncryptedItems",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "17c174fa-600d-4986-a06b-e4cb6ba279d3",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_passwordRequired",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "a951e76b-b1b3-4031-8478-53f904c80801",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_passwordRequiredType",
                              "valueJson":  "\"alphanumeric\"",
                              "value":  "alphanumeric"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "42240913-d402-4a57-bb21-abbecf213670",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_passwordExpirationDays",
                              "valueJson":  "60",
                              "value":  60
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "36b35626-6a9a-4839-91e9-9798ee22dcf5",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_passwordMinimumCharacterSetCount",
                              "valueJson":  "3",
                              "value":  3
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "6d491e19-022b-4c45-a4f9-ac23ba43e8e7",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_passwordPreviousPasswordBlockCount",
                              "valueJson":  "24",
                              "value":  24
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "0fc26671-924c-4a5d-9a96-e8289128b7e6",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_passwordMinimumLength",
                              "valueJson":  "8",
                              "value":  8
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "9000c987-0c1c-434a-9c81-cb077540f50e",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_passwordSignInFailureCountBeforeFactoryReset",
                              "valueJson":  "10",
                              "value":  10
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "fce3429d-7892-4807-b784-6de15e569fa5",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_passwordMinimumAgeInDays",
                              "valueJson":  "1",
                              "value":  1
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "d547df92-5ae2-4d60-8e0a-11ed8353a84c",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_passwordBlockSimple",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "c98778cd-baef-498c-9593-c02504f35bdb",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_lockScreenCamera",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "230ab294-e3f6-4800-9a75-520b5633370e",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_lockScreenSlideShow",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "e1a89050-02e9-4b30-a2a3-a2959ddd4259",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_inkWorkspaceAccess",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "f8ab54fe-d43f-45c5-b71b-53372c9e46df",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_powerShellShellScriptBlockLogging",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "39097346-5c9c-481d-a9d1-cfbe56154bbb",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_appsMicrosoftAccountsOptional",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "6776dba3-64b5-4699-9c8a-f45197eec7e8",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_autoPlayDefaultAutoRunBehavior",
                              "valueJson":  "\"doNotExecute\"",
                              "value":  "doNotExecute"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "4f78f838-b2e6-47a1-b990-d864c36ea258",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_autoPlayMode",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "183a673f-1fc5-444f-a6ca-c8fef0e969e2",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_autoPlayForNonVolumeDevices",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "92dbad44-938a-4e88-be8b-d500f27adab0",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_edgeBlockPasswordManager",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "c4076845-ac93-4cc9-a9f8-374881a2cd51",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_edgeRequireSmartScreen",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "409f42cb-aaee-4ee4-92ee-f2fbe038dbb0",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_smartScreenBlockPromptOverride",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "be414d81-6a67-46a3-aa4c-b685040f5ce8",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_smartScreenBlockPromptOverrideForFiles",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "275c0db3-f6cc-48df-b5d6-7cca264e9769",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_edgePreventCertificateErrorOverride",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "0dff5f52-7e39-4f9f-bdb2-5abe510c2724",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_remoteHostDelegationOfNonExportableCredentials",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "cb726601-3f28-4539-92b8-94960ee31d85",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_credentialsUIEnumerateAdministrators",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "61a3c1dd-d09f-4c17-a20a-8963f8cb1dde",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_dataProtectionBlockDirectMemoryAccess",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "879e51f4-9f87-40f1-b341-c54825e075e8",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_eventLogServiceApplicationLogMaximumFileSizeInKb",
                              "valueJson":  "32768",
                              "value":  32768
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "82e4704e-3b58-41ca-bcb8-0b4bdff976d0",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_eventLogServiceSystemLogMaximumFileSizeInKb",
                              "valueJson":  "32768",
                              "value":  32768
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "29dee634-6e1a-4a3f-bde2-29994197a97c",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_eventLogServiceSecurityLogMaximumFileSizeInKb",
                              "valueJson":  "196608",
                              "value":  196608
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "309c6273-7041-4e21-bde1-0af4898f9139",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_windowsSpotlightBlocked",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "a127ef8f-16af-45c8-9b4b-7095bb7f4fce",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_windowsSpotlightBlockThirdPartyNotifications",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "0bc5d4f6-ed42-493e-bcff-d5f72767d5ee",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_windowsSpotlightBlockConsumerSpecificFeatures",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "4ee09f5d-c9c6-41b1-b7a4-6a4d2d4d4745",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_explorerDataExecutionPrevention",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "eeaebaba-aa53-4e0a-8a62-4d65766c6517",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_explorerHeapTerminationOnCorruption",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "ccfb1c2d-5a83-4a5d-a888-5e0539be59bd",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsBlockRemoteLogonWithBlankPassword",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "918b9d37-3e9f-4505-bae3-80700bf4b26a",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsMachineInactivityLimit",
                              "valueJson":  "5",
                              "value":  5
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "56bf1852-1723-4cf1-bb3e-8e13235f7dfc",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsSmartCardRemovalBehavior",
                              "valueJson":  "\"lockWorkstation\"",
                              "value":  "lockWorkstation"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "0d558cfb-2b35-498d-9dc1-049355837009",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsClientDigitallySignCommunicationsAlways",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "bb868689-a304-4e08-8fd6-2e77c9ba534a",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "37737e5b-6127-46d2-b911-6b7693607527",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsDisableServerDigitallySignCommunicationsAlways",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "7321b5f7-7538-417b-8c53-56c87fdd22d9",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "e3ce88d9-fbfc-48e0-9454-2fd565e32b1f",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "a9f312ec-0f2b-41ed-b1bc-0f4ebe919457",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "a66cafef-dd49-45fe-b499-5ef1cce86ef3",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsAllowRemoteCallsToSecurityAccountsManager",
                              "valueJson":  "\"O:BAG:BAD:(A;;RC;;;BA)\"",
                              "value":  "O:BAG:BAD:(A;;RC;;;BA)"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "49b2997e-3580-41d1-bd03-d7ff736d4fce",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "ee5eb8f3-e31c-4390-b685-af28741450dc",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_lanManagerAuthenticationLevel",
                              "valueJson":  "\"lmNtlmV2AndNotLmOrNtm\"",
                              "value":  "lmNtlmV2AndNotLmOrNtm"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "9baee1f6-c2c7-41b5-88b0-66addd0a810f",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedClients",
                              "valueJson":  "\"ntlmV2And128BitEncryption\"",
                              "value":  "ntlmV2And128BitEncryption"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "4b9e17a4-ac70-48a5-b8c0-3861b19f9b53",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedServers",
                              "valueJson":  "\"ntlmV2And128BitEncryption\"",
                              "value":  "ntlmV2And128BitEncryption"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "a05ed6a5-9f40-4301-a458-768e27c06157",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsAdministratorElevationPromptBehavior",
                              "valueJson":  "\"promptForCredentialsOnTheSecureDesktop\"",
                              "value":  "promptForConsentOnTheSecureDesktop"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "771c44a1-1665-4e9f-af7e-c7f318cdf2c3",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsStandardUserElevationPromptBehavior",
                              "valueJson":  "\"promptForCredentialsOnTheSecureDesktop\"",
                              "value":  "promptForCredentialsOnTheSecureDesktop"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "dc470448-12da-4aee-affe-521ed585ae53",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsDetectApplicationInstallationsAndPromptForElevation",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "5ab030a3-57f5-495a-b748-9170ca68a76e",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsAllowUIAccessApplicationsForSecureLocations",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "7a94cb5a-f172-4426-926c-29372efe0f50",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsUseAdminApprovalModeForAdministrators",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "a2f0369d-eb98-435d-b136-f1fa4d9e1783",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsUseAdminApprovalMode",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "cb8f8c29-8ec1-434b-a60b-4a39ddd45cb6",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_localSecurityOptionsVirtualizeFileAndRegistryWriteFailuresToPerUserLocations",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "c37dbe61-07a0-4b28-ae62-42d695b0bfe4",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_securityGuideSmbV1ClientDriverStartConfiguration",
                              "valueJson":  "\"disableDriver\"",
                              "value":  "disableDriver"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "967ecf5c-700f-4b5d-b9f3-b10d93b9504a",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_securityGuideApplyUacRestrictionsToLocalAccountsOnNetworkLogon",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b135d4ba-7088-4987-a1bb-dcc33a01a940",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_securityGuideStructuredExceptionHandlingOverwriteProtection",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "2ba314f7-923c-401a-98ae-3550658809c0",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_securityGuideSmbV1Server",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "90a7c13b-edc4-4c51-904a-e7f6e5cd82f7",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_securityGuideWDigestAuthentication",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "8a2bb7f9-dec0-4d27-9958-425fc751fc08",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_networkIpV6SourceRoutingProtectionLevel",
                              "valueJson":  "\"highestProtection\"",
                              "value":  "highestProtection"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "26c0a09e-a06e-43d3-8637-8381d4edcf3d",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_networkIpSourceRoutingProtectionLevel",
                              "valueJson":  "\"highestProtection\"",
                              "value":  "highestProtection"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b3e06df8-7c10-42ef-9bf1-773390789e5e",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_networkIgnoreNetBiosNameReleaseRequestsExceptFromWinsServers",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "d990849e-ba45-40a0-b196-9b6b13d9c62c",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_networkIcmpRedirectsOverrideOspfGeneratedRoutes",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "51722ac5-493c-4964-adc5-24be73651675",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_powerRequirePasswordOnWakeWhileOnBattery",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "86a7553d-7d85-47b7-84b5-32235c761b23",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_powerRequirePasswordOnWakeWhilePluggedIn",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "4f5c8bda-4594-417a-acd7-20e837a1166d",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_powerStandbyStatesWhenSleepingWhileOnBattery",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "5cdd08b5-10ee-4d3b-9ee5-27229793725e",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_powerStandbyStatesWhenSleepingWhilePluggedIn",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "ae0388c2-ffdc-4fea-a249-95100d32b9ae",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_remoteDesktopServicesClientConnectionEncryptionLevel",
                              "valueJson":  "\"high\"",
                              "value":  "high"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "072b38a8-dda7-4e27-89a1-a4e8fe18084e",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_remoteDesktopServicesDriveRedirection",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b47beca4-6281-4a77-b012-4ff8b9fb145f",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_remoteDesktopServicesPasswordSaving",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b612c6a7-3593-4b1e-a6a4-15732f7d554c",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_remoteDesktopServicesPromptForPasswordUponConnection",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "5b816dda-d2f3-49fc-8add-38882e752d6d",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_remoteDesktopServicesSecureRpcCommunication",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "605cfd12-e1ef-425d-b8eb-291232d96a31",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_remoteManagementClientDigestAuthentication",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "dd5f27f9-a892-4e80-845e-635bcc152b82",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_remoteManagementServiceStoringRunAsCredentials",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "4291f5e5-90d7-4a37-9528-38a6ebc5ff9b",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_remoteManagementClientBasicAuthentication",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "6984629c-8c67-48a9-a948-abfb92f4c90a",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_remoteManagementServiceBasicAuthentication",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "8dd69c1f-cba2-4483-955f-a0c6ac091e07",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_remoteManagementClientUnencryptedTraffic",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "f73bed4a-c458-423e-9ded-977ee108803d",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_remoteManagementServiceUnencryptedTraffic",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b5f2c7f2-325e-4623-91e9-1927a5d14109",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_rpcUnauthenticatedClientOptions",
                              "valueJson":  "\"authenticated\"",
                              "value":  "authenticated"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "d0536080-64fc-4746-b1e2-589ddc6c0aa5",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_systemBootStartDriverInitialization",
                              "valueJson":  "\"goodUnknownAndBadButCritical\"",
                              "value":  "goodUnknownAndBadButCritical"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "5f916967-043d-407a-b04d-0c68b76e725f",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_wiFiBlockAutomaticConnectHotspots",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "76cf39c4-3a5b-4a87-bc17-0782f0a76268",
                              "definitionId":  "deviceConfiguration--windows10GeneralConfiguration_internetSharingBlocked",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "8a3293d0-d674-45ab-af5f-1a45b5cf546b",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_windowsConnectionManagerConnectionToNonDomainNetworks",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          }
                      ]
}


"@

####################################################

$SB_EdgeBase = @"

{
    "displayName":  "[ITPM Corporate] Edge Chromium baseline",
    "description":  "Assign this profile to Company owned Windows devices. WARNING: This policy will disable all browser extensions by default; create a Device configuration profile to allow specific extensions to be installed from the Edge add-ons store.",
    "settingsDelta":  [
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementCollectionSettingInstance",
                              "id":  "cc3e5d9b-e76e-47b7-b6ae-79f55f7e1a76",
                              "definitionId":  "admx--microsoftedgeAuthSchemes_AuthSchemes",
                              "valueJson":  "[\"ntlm\",\"negotiate\"]"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "7fa472aa-3cc9-40c9-818e-c5e914215e77",
                              "definitionId":  "admx--microsoftedge_AuthSchemes",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "cd316e16-f5f6-4253-8652-4e9ec9e3fd8d",
                              "definitionId":  "admx--microsoftedge_DefaultPluginsSetting",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "38c8b1b1-d6e7-4471-9a0a-d6c0577dfde8",
                              "definitionId":  "admx--microsoftedgeDefaultPluginsSetting_DefaultPluginsSetting",
                              "valueJson":  "\"2\"",
                              "value":  "2"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "70f60848-cb70-4fc7-99d6-92189843566a",
                              "definitionId":  "admx--microsoftedge_ExtensionInstallBlocklist",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementCollectionSettingInstance",
                              "id":  "a640b71e-8cf4-4805-88e9-eb596bbd272c",
                              "definitionId":  "admx--microsoftedgeExtensionInstallBlocklist_ExtensionInstallBlocklistDesc",
                              "valueJson":  "[\"*\"]"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "0a12320a-4702-4dfb-8b61-f4f1fcbd3efc",
                              "definitionId":  "admx--microsoftedge_NativeMessagingUserLevelHosts",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "9f63f0ae-f25e-44d8-8618-b56566fc5800",
                              "definitionId":  "admx--microsoftedge_PasswordManagerEnabled",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "5f4d089f-6bab-4e19-848f-bf10cc94af9a",
                              "definitionId":  "admx--microsoftedge_PreventSmartScreenPromptOverride",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "5999e27c-ddde-4176-95fe-0decaa2119f8",
                              "definitionId":  "admx--microsoftedge_PreventSmartScreenPromptOverrideForFiles",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "958e2890-d23c-4428-9a4b-6961fb492ffb",
                              "definitionId":  "admx--microsoftedge_SitePerProcess",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "58dce6dc-16cc-4d7d-b151-92a5d2bae90d",
                              "definitionId":  "admx--microsoftedge_SmartScreenEnabled",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "82cac80b-13f4-4272-8598-0662fb684698",
                              "definitionId":  "admx--microsoftedgev80diff_SmartScreenPuaEnabled",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "f128307a-3e2a-4a40-934e-5147f31d845b",
                              "definitionId":  "admx--microsoftedge_SSLErrorOverrideAllowed",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "fd4c09bc-d143-4688-aa2c-2edaa149d77d",
                              "definitionId":  "admx--microsoftedge_SSLVersionMin",
                              "valueJson":  "\"enabled\"",
                              "value":  "enabled"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "28bd2c9e-e5c3-4aaf-bed5-d82c7006bb92",
                              "definitionId":  "admx--microsoftedgeSSLVersionMin_SSLVersionMin",
                              "valueJson":  "\"tls1.2\"",
                              "value":  "tls1.2"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "e7941c35-cf0c-4220-ad37-872dbb65d396",
                              "definitionId":  "admx--microsoftedgev85diff_EnableSha1ForLocalAnchors",
                              "valueJson":  "\"disabled\"",
                              "value":  "disabled"
                          }
                      ]
}



"@

####################################################

$ES_Antivirus = @"

{
    "displayName":  "[ITPM Corporate] Microsoft Defender Antivirus",
    "description":  "Assign this policy to Company owned Windows devices.",
    "settingsDelta":  [
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "16478911-9d0a-43d2-b0a5-c9a8d8dc5175",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAllowCloudProtection",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "aab0da47-6f85-4dc8-8b82-01f206cee5a0",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderCloudBlockLevel",
                              "valueJson":  "\"high\"",
                              "value":  "high"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "3036f464-ba06-4376-b19f-37b1b86096fa",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderCloudExtendedTimeoutInSeconds",
                              "valueJson":  "50",
                              "value":  50
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "73381042-8f0f-4b86-b6b2-82e33062d3e2",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAllowRealTimeMonitoring",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "f74b1b95-9e92-417c-9e95-d693d024ca93",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAllowOnAccessProtection",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "a55c1387-fd66-49fa-bb3f-b93437369ae4",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderScanDirection",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "d638b2a1-663a-4e09-8448-173bea9ed0da",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAllowBehaviorMonitoring",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "1a6b8a65-184e-48ff-971c-d2b9831103a3",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAllowIntrusionPreventionSystem",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "bab94350-72f4-4213-9919-9ad8d6f318ca",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAllowScanDownloads",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "c02e47c1-b3c9-47bf-9911-546d429f7884",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAllowScanScriptsLoadedInInternetExplorer",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "6a63497b-57f5-4dfd-a660-07fda0f84078",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAllowScanNetworkFiles",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "fea85286-ea73-4f33-bc7d-02a76c6f564a",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderEnableScanIncomingMail",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "5f5f6634-4762-4454-8815-a149d3014360",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderDaysBeforeDeletingQuarantinedMalware",
                              "valueJson":  "14",
                              "value":  14
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "a6ad68f1-fe2b-492c-878c-dad20581192c",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSubmitSamplesConsentType",
                              "valueJson":  "\"sendAllSamplesAutomatically\"",
                              "value":  "sendAllSamplesAutomatically"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "83d2b347-12bc-497d-afd2-4de79668a20d",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderPotentiallyUnwantedAppAction",
                              "valueJson":  "\"enable\"",
                              "value":  "enable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementComplexSettingInstance",
                              "id":  "e254021c-8d14-406e-93c3-e6100591482f",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderDetectedMalwareActions",
                              "valueJson":  "{\"lowSeverity\":\"quarantine\",\"moderateSeverity\":\"quarantine\",\"highSeverity\":\"quarantine\",\"severeSeverity\":\"quarantine\"}",
                              "value":  [
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "cf114ae1-1a07-4da2-a64b-5c51c4d87b3f",
                                                "definitionId":  "deviceConfiguration--defenderDetectedMalwareActions_lowSeverity",
                                                "valueJson":  "\"quarantine\"",
                                                "value":  "quarantine"
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "2d456bb5-fd94-4162-84b2-9cde00922165",
                                                "definitionId":  "deviceConfiguration--defenderDetectedMalwareActions_moderateSeverity",
                                                "valueJson":  "\"quarantine\"",
                                                "value":  "quarantine"
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "01ed4dee-9a7d-49b8-aa90-25507cd1d6a8",
                                                "definitionId":  "deviceConfiguration--defenderDetectedMalwareActions_highSeverity",
                                                "valueJson":  "\"quarantine\"",
                                                "value":  "quarantine"
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "5fec3028-bc71-40e3-930e-0599111e1dbd",
                                                "definitionId":  "deviceConfiguration--defenderDetectedMalwareActions_severeSeverity",
                                                "valueJson":  "\"quarantine\"",
                                                "value":  "quarantine"
                                            }
                                        ]
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "2b92e3e1-59d8-459e-9aee-066e1bd2cc2b",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAllowScanArchiveFiles",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "fe29e983-0f0c-4ca7-bb14-4c292eec38d8",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderEnableLowCpuPriority",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "ef9453d7-66fc-4065-b842-62b10d430388",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderDisableCatchupFullScan",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "52dc06cc-bb3d-4a25-a02a-92d5bbdb3f7b",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderDisableCatchupQuickScan",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "5b724192-f37c-42e6-88f4-d85229edeb63",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderScanMaxCpuPercentage",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "49b6a0b6-6b44-40cd-b396-30d6d1f31162",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderEnableScanMappedNetworkDrivesDuringFullScan",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "4747010f-f29c-4413-b2d1-4ea624de18b4",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderScheduledQuickScanTime",
                              "valueJson":  "\"t6PM\"",
                              "value":  "t6PM"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "07fc215f-856c-4798-8a26-c51bc39a52e6",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderScanType",
                              "valueJson":  "\"full\"",
                              "value":  "full"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "4fa431bd-a5f1-4ee4-bc98-74c55d7dd11c",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderScheduledScanDay",
                              "valueJson":  "\"saturday\"",
                              "value":  "saturday"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "bffd2e94-c0bb-45cb-be15-ff0ebb8d24b1",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderScheduledScanTime",
                              "valueJson":  "\"t6PM\"",
                              "value":  "t6PM"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "36571b71-8152-4157-8b5c-9adc55170162",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderCheckForSignaturesBeforeRunningScan",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "86d95577-dd21-433c-a5de-bf3c84b8b4cb",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSignatureUpdateIntervalInHours",
                              "valueJson":  "1",
                              "value":  1
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementCollectionSettingInstance",
                              "id":  "3b7a8156-2fe8-41f0-81d0-297c059cd1d2",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSignatureUpdateFileSharesSources",
                              "valueJson":  "null"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementCollectionSettingInstance",
                              "id":  "88eb6544-c2a2-4603-b656-2fc9be63b234",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSignatureUpdateFallbackOrder",
                              "valueJson":  "null"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "36946ad9-df1e-441f-bb70-24c91b254d51",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAllowEndUserAccess",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementCollectionSettingInstance",
                              "id":  "3fe1ff38-0d96-4aba-9598-5ec33d5f9fc4",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderProcessesToExclude",
                              "valueJson":  "null"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementCollectionSettingInstance",
                              "id":  "076269ed-51aa-49c5-ac41-0342f6069867",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderFileExtensionsToExclude",
                              "valueJson":  "null"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementCollectionSettingInstance",
                              "id":  "bb861594-6524-46f5-8306-362d1b80c976",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderFilesAndFoldersToExclude",
                              "valueJson":  "null"
                          }
                      ]
}



"@

####################################################

$ES_SecurityCenter = @"

{
    "displayName":  "[ITPM Corporate] Windows Security Center",
    "description":  "Assign this profile to Company owned Windows devices.",
    "settingsDelta":  [
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "85ef1a7a-2ce3-4439-b7f4-5954ae0b3b0d",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_windowsDefenderTamperProtection",
                              "valueJson":  "\"enable\"",
                              "value":  "enable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "ea7be52a-3d0b-4e3d-8b50-dd122ed325a2",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSecurityCenterDisableVirusUI",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "daafeb10-8809-403e-b14c-ae79fec8e89c",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSecurityCenterDisableRansomwareUI",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "15bafc14-0db2-45c0-9983-f25cef35ea8d",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSecurityCenterDisableAccountUI",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "74010313-92d3-48c9-a0b9-a46cf6330f5d",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSecurityCenterDisableNetworkUI",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "4cd4fcc0-561b-4fbb-bbba-92f2e27d95fe",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSecurityCenterDisableAppBrowserUI",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "2d5b969a-f1e3-4801-bb17-e32cd05fbc9a",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSecurityCenterDisableHardwareUI",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "b32df70c-fc79-4f1b-843c-e1accaa8d341",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSecurityCenterDisableHealthUI",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "165d5c6f-8403-4a9a-9d61-712565934355",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSecurityCenterDisableFamilyUI",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "ff0ff6cf-8b9f-4eea-9d41-296b3bd30d88",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSecurityCenterNotificationsFromApp",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "6b530ec8-0246-4488-8467-f44aebf71917",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSecurityCenterDisableNotificationAreaUI",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "12df431e-85e0-4192-bc43-0be84a294992",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSecurityCenterDisableClearTpmUI",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "4aa1a91f-903c-4898-9962-da4ab604d3ee",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSecurityCenterDisableVulnerableTpmFirmwareUpdateUI",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "15270415-0a15-4650-be51-2f988b47ec63",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSecurityCenterITContactDisplay",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "c80f19dc-9ac2-4974-9cf7-f129d6a400d0",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSecurityCenterOrganizationDisplayName",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "ab685a81-53f0-4fbc-9db1-bc69012b19da",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSecurityCenterHelpPhone",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "bbc4e1b8-13fc-4df6-8b12-fededcfb6eb6",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSecurityCenterHelpEmail",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "7eec443d-5c4e-4fd1-a6ce-becde95d3803",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderSecurityCenterHelpURL",
                              "valueJson":  "null",
                              "value":  null
                          }
                      ]
}


"@

####################################################

$ES_BitLocker = @"
{
    "displayName":  "[ITPM Corporate] BitLocker silent enablement",
    "description":  "Assign this policy to Company owned Windows devices.",
    "settingsDelta":  [
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "e7f1495c-10ac-422d-aea3-a4d4cf17009c",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerEncryptDevice",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "dcdd722c-058b-442d-954f-da06cb748f15",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerEnableStorageCardEncryptionOnMobile",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "d31f8bbe-0e72-426d-b2ca-88af94d23254",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerDisableWarningForOtherDiskEncryption",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "38f67682-7c8c-4de1-a114-2bf99c1324f9",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerAllowStandardUserEncryption",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "94c50e8c-67e3-4583-ab09-41c438ac94ef",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerRecoveryPasswordRotation",
                              "valueJson":  "\"enabledForAzureAd\"",
                              "value":  "enabledForAzureAd"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementComplexSettingInstance",
                              "id":  "b79aa58c-3493-40c5-a49c-acf2c846516e",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerSystemDrivePolicy",
                              "valueJson":  "{\"startupAuthenticationRequired\":true,\"startupAuthenticationTpmUsage\":\"required\",\"startupAuthenticationTpmPinUsage\":null,\"startupAuthenticationTpmKeyUsage\":\"blocked\",\"startupAuthenticationTpmPinAndKeyUsage\":null,\"startupAuthenticationBlockWithoutTpmChip\":true,\"prebootRecoveryEnableMessageAndUrl\":false,\"prebootRecoveryMessage\":null,\"prebootRecoveryUrl\":null,\"recoveryOptions\":{\"recoveryKeyUsage\":\"allowed\",\"recoveryInformationToStore\":null,\"enableRecoveryInformationSaveToStore\":true,\"recoveryPasswordUsage\":\"allowed\",\"hideRecoveryOptions\":true,\"enableBitLockerAfterRecoveryInformationToStore\":false,\"blockDataRecoveryAgent\":true},\"encryptionMethod\":\"xtsAes256\",\"minimumPinLength\":null}",
                              "value":  [
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "f2b1f10f-d4fd-421a-85ad-1b2981361f2a",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_startupAuthenticationRequired",
                                                "valueJson":  "true",
                                                "value":  true
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "cd483f32-30ea-47c0-9d89-34fecc2628cb",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_startupAuthenticationTpmUsage",
                                                "valueJson":  "\"required\"",
                                                "value":  "required"
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "a0482565-8e1c-4d4a-853a-81a62de27077",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_startupAuthenticationTpmPinUsage",
                                                "valueJson":  "null",
                                                "value":  null
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "f54502de-761f-4e9f-b7a0-d981e6b3ae27",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_startupAuthenticationTpmKeyUsage",
                                                "valueJson":  "\"blocked\"",
                                                "value":  "blocked"
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "91d5186f-beea-44d6-a645-2cd5c727754a",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_startupAuthenticationTpmPinAndKeyUsage",
                                                "valueJson":  "null",
                                                "value":  null
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "09c1ff14-dcba-4c84-a1b7-5f7aee4c3b93",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_startupAuthenticationBlockWithoutTpmChip",
                                                "valueJson":  "true",
                                                "value":  true
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "3e525c15-0c9f-4038-a2ff-df0dc3c3390a",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_prebootRecoveryEnableMessageAndUrl",
                                                "valueJson":  "false",
                                                "value":  false
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "931fd839-8fa5-4c24-ae99-dca37c9f5955",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_prebootRecoveryMessage",
                                                "valueJson":  "null",
                                                "value":  null
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "d6f9724a-8137-414d-bffb-82e9ef83edda",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_prebootRecoveryUrl",
                                                "valueJson":  "null",
                                                "value":  null
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementComplexSettingInstance",
                                                "id":  "98d454b8-7e21-4d80-b231-ceecc9ccc1fa",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_recoveryOptions",
                                                "valueJson":  "{\"recoveryKeyUsage\":\"allowed\",\"recoveryInformationToStore\":null,\"enableRecoveryInformationSaveToStore\":true,\"recoveryPasswordUsage\":\"allowed\",\"hideRecoveryOptions\":true,\"enableBitLockerAfterRecoveryInformationToStore\":false,\"blockDataRecoveryAgent\":true}"
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "14ca1c76-a37c-4b43-a6f8-ba2c58c44d0b",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_encryptionMethod",
                                                "valueJson":  "\"xtsAes256\"",
                                                "value":  "xtsAes256"
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                                                "id":  "86659813-daed-42e0-a824-04f2ca27a2d9",
                                                "definitionId":  "deviceConfiguration--bitLockerSystemDrivePolicy_minimumPinLength",
                                                "valueJson":  "null",
                                                "value":  null
                                            }
                                        ]
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementComplexSettingInstance",
                              "id":  "b1936214-a108-4456-ad96-167a1ba6ea56",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerFixedDrivePolicy",
                              "valueJson":  "{\"recoveryOptions\":{\"recoveryKeyUsage\":\"allowed\",\"recoveryInformationToStore\":null,\"enableRecoveryInformationSaveToStore\":true,\"recoveryPasswordUsage\":\"allowed\",\"hideRecoveryOptions\":true,\"enableBitLockerAfterRecoveryInformationToStore\":false,\"blockDataRecoveryAgent\":true},\"requireEncryptionForWriteAccess\":true,\"encryptionMethod\":\"xtsAes256\"}",
                              "value":  [
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementComplexSettingInstance",
                                                "id":  "eaf04b37-38a0-4ebf-af9a-b597220bb723",
                                                "definitionId":  "deviceConfiguration--bitLockerFixedDrivePolicy_recoveryOptions",
                                                "valueJson":  "{\"recoveryKeyUsage\":\"allowed\",\"recoveryInformationToStore\":null,\"enableRecoveryInformationSaveToStore\":true,\"recoveryPasswordUsage\":\"allowed\",\"hideRecoveryOptions\":true,\"enableBitLockerAfterRecoveryInformationToStore\":false,\"blockDataRecoveryAgent\":true}"
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "ca3b87d9-19b6-4fdf-9785-a504477b9dba",
                                                "definitionId":  "deviceConfiguration--bitLockerFixedDrivePolicy_requireEncryptionForWriteAccess",
                                                "valueJson":  "true",
                                                "value":  true
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "8f1366ef-5dd6-449d-a47c-6796270495e3",
                                                "definitionId":  "deviceConfiguration--bitLockerFixedDrivePolicy_encryptionMethod",
                                                "valueJson":  "\"xtsAes256\"",
                                                "value":  "xtsAes256"
                                            }
                                        ]
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementComplexSettingInstance",
                              "id":  "c73e3ec5-2cfd-488d-8649-cfc2412a8081",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_bitLockerRemovableDrivePolicy",
                              "valueJson":  "{\"encryptionMethod\":\"aesCbc128\",\"requireEncryptionForWriteAccess\":false,\"blockCrossOrganizationWriteAccess\":false}",
                              "value":  [
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                                                "id":  "1f557bad-a2fc-436a-856e-175baabc8748",
                                                "definitionId":  "deviceConfiguration--bitLockerRemovableDrivePolicy_encryptionMethod",
                                                "valueJson":  "\"aesCbc128\"",
                                                "value":  "aesCbc128"
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "65f453ca-854b-4113-a472-2c04f7fef939",
                                                "definitionId":  "deviceConfiguration--bitLockerRemovableDrivePolicy_requireEncryptionForWriteAccess",
                                                "valueJson":  "false",
                                                "value":  false
                                            },
                                            {
                                                "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                                                "id":  "6df6ad60-cbbe-496d-86ff-df4ce8bbef75",
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

$ES_BitLockerRD = @"

{
    "displayName":  "[ITPM Corporate] BitLocker with removable drive protection",
    "description":  "This policy is the same as the silent enablement policy except that it also requires encryption of removable media.",
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

$ES_Firewall = @"

{
    "displayName":  "[ITPM Corporate] Windows Firewall",
    "description":  "Assign this policy to Company owned Windows devices.",
    "settingsDelta":  [
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "9280f807-6fd4-4c09-896c-9da48d03fe80",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallBlockStatefulFTP",
                              "valueJson":  "true",
                              "value":  true
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementIntegerSettingInstance",
                              "id":  "f362f362-3d74-4d80-8d15-f7a754d8c587",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallIdleTimeoutForSecurityAssociationInSeconds",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "1a4b9026-2f71-4faf-8ad1-5f09262f4097",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallPreSharedKeyEncodingMethod",
                              "valueJson":  "\"deviceDefault\"",
                              "value":  "deviceDefault"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "c2c2a71b-4d1c-4359-9c9d-820375f5a000",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallIPSecExemptionsNone",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "b54bb400-37b5-455a-a879-84dad818ba26",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallIPSecExemptionsAllowNeighborDiscovery",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "3e896600-8428-4d51-bedb-dd5b739f0594",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallIPSecExemptionsAllowICMP",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "e257ba35-605f-4542-b0c5-52cfda158d9c",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallIPSecExemptionsAllowRouterDiscovery",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "e27f6778-a140-4922-9b40-44104767c35e",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallIPSecExemptionsAllowDHCP",
                              "valueJson":  "false",
                              "value":  false
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "28a08dd5-b206-4c7e-90be-ff24d0b38938",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallCertificateRevocationListCheckMethod",
                              "valueJson":  "\"deviceDefault\"",
                              "value":  "deviceDefault"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementBooleanSettingInstance",
                              "id":  "bb741bf7-8166-40e2-8dd4-b8fe405df86d",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallMergeKeyingModuleSettings",
                              "valueJson":  "null",
                              "value":  null
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "88d1b2bc-3842-4672-83e5-5076f8721f33",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallPacketQueueingMethod",
                              "valueJson":  "\"deviceDefault\"",
                              "value":  "deviceDefault"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "fcc7e72f-1ea4-4243-83c6-358db78621e1",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfileDomainFirewallEnabled",
                              "valueJson":  "\"allowed\"",
                              "value":  "allowed"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "c21ce811-a94b-4766-aa65-33f6ae6529c4",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfileDomainStealthModeBlocked",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "388a2fac-789d-4761-8003-445bd426dea1",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfileDomainSecuredPacketExemptionAllowed",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "17580bf0-38f0-427f-b208-cede458c5954",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfileDomainIncomingTrafficBlocked",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "9e05bb32-2289-48c1-b7e0-5885ebdda0aa",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfileDomainUnicastResponsesToMulticastBroadcastsBlocked",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "c8dcce3a-9b77-4fb3-b279-fed198dd7a17",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfileDomainInboundNotificationsBlocked",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "f618bae8-c82c-4a09-a84a-896c6fb5f63d",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfileDomainOutboundConnectionsBlocked",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "39bd4b57-fdba-4e25-a4ce-fc2dc5778443",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfileDomainInboundConnectionsBlocked",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "7d53b1c7-f409-40e2-8a8f-0d1792228653",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfileDomainAuthorizedApplicationRulesFromGroupPolicyMerged",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "adcc0437-9bbd-46e7-b06c-395b70d28580",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfileDomainGlobalPortRulesFromGroupPolicyMerged",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "1b00023a-28f8-40f2-9d3a-62169c729138",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfileDomainPolicyRulesFromGroupPolicyMerged",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "a42e6ee9-fe9a-470d-b052-45caa6d675e3",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfileDomainConnectionSecurityRulesFromGroupPolicyMerged",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "57b5d9bd-b119-4295-a641-5a4a2cc7f2f8",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePrivateFirewallEnabled",
                              "valueJson":  "\"allowed\"",
                              "value":  "allowed"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "ccb54936-c3ed-4a9c-85ad-7942934e719b",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePrivateStealthModeBlocked",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "e71e294c-8511-4864-8c6a-9dde809bf71f",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePrivateSecuredPacketExemptionAllowed",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "2c85fd64-24a7-4856-9ce1-41351b8eeeb8",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePrivateIncomingTrafficBlocked",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "357910f6-7d9d-4b2f-a6e3-044b561e065d",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePrivateUnicastResponsesToMulticastBroadcastsBlocked",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "ca4fa8f6-0b06-44df-8800-075a6e5bbd7a",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePrivateInboundNotificationsBlocked",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "da891122-bb7a-4d0d-8393-d3aeb61160b3",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePrivateOutboundConnectionsBlocked",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "a9bdd2c2-ab87-45fb-9d4e-658e8b85b38a",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePrivateInboundConnectionsBlocked",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "ee3f55a1-8e3a-4d17-97d2-96f4777181aa",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePrivateAuthorizedApplicationRulesFromGroupPolicyMerged",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "df1b7629-872b-4730-808c-47944389a9d7",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePrivateGlobalPortRulesFromGroupPolicyMerged",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "b3ea8e90-3a41-4884-895b-1c175d8e602e",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePrivatePolicyRulesFromGroupPolicyMerged",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "00a0e179-783b-46e1-bd00-38898e5c134f",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePrivateConnectionSecurityRulesFromGroupPolicyMerged",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "96c8547b-795f-4632-9325-97a573659953",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePublicFirewallEnabled",
                              "valueJson":  "\"allowed\"",
                              "value":  "allowed"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "6bb49c35-235a-4dbf-b8bb-e3cf40b55637",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePublicStealthModeBlocked",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "db96cceb-e01f-42e1-a3b7-30ad96d16ebe",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePublicSecuredPacketExemptionAllowed",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "10a9357b-1d2a-47e8-8ab1-e78db34c3fad",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePublicIncomingTrafficBlocked",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "1880232c-3ddd-422d-8763-9cf957bb29fd",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePublicUnicastResponsesToMulticastBroadcastsBlocked",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "33f0204d-47af-478b-a9a0-b4624e7c599d",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePublicInboundNotificationsBlocked",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "07083d34-b8a5-4349-8b08-b343b5dd2504",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePublicOutboundConnectionsBlocked",
                              "valueJson":  "\"notConfigured\"",
                              "value":  "notConfigured"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "6e62cc04-1c24-41ce-ab0d-2ecea16a2b7a",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePublicInboundConnectionsBlocked",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "6ac086fe-5ef1-4e5d-b9ec-d9442f7d94ea",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePublicAuthorizedApplicationRulesFromGroupPolicyMerged",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "0f5d762f-db00-4684-8cd3-0e6bc57f6399",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePublicGlobalPortRulesFromGroupPolicyMerged",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "9d2d1f31-e7ff-48e3-965d-0e2870794244",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePublicPolicyRulesFromGroupPolicyMerged",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "c853275f-2a9d-4466-8c2c-af4cfde34200",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_firewallProfilePublicConnectionSecurityRulesFromGroupPolicyMerged",
                              "valueJson":  "\"blocked\"",
                              "value":  "blocked"
                          }
                      ]
}


"@

####################################################

$ES_ASRAudit = @"

{
    "displayName":  "[ITPM Corporate] Audit ASR Rules",
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

$ES_ASREnable = @"
{
    "displayName":  "[ITPM Corporate] Enable ASR Rules",
    "description":  "Assign this policy to Company owned Windows devices. You must have proper licensing to use this profile: Microsoft 365 Business Premium, E3, or E5. Use either the Audit policy or the Enable policy, but not both at the same time. ",
    "settingsDelta":  [
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "ce88099a-3b84-4c9b-bc9d-1c494d9abaf8",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderBlockPersistenceThroughWmiType",
                              "valueJson":  "\"block\"",
                              "value":  "block"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "f03360bf-613e-4a7a-8708-6cdf8aa78f45",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderPreventCredentialStealingType",
                              "valueJson":  "\"enable\"",
                              "value":  "enable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "67937792-0537-4a7d-b545-775df0de6bdb",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAdobeReaderLaunchChildProcess",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "32c5de23-6752-4dea-8d31-b932eda43aba",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderOfficeAppsOtherProcessInjectionType",
                              "valueJson":  "\"block\"",
                              "value":  "block"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "7ad79760-0dd5-4fc7-81d2-d4a73a93cf3b",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderOfficeAppsExecutableContentCreationOrLaunchType",
                              "valueJson":  "\"block\"",
                              "value":  "block"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "2485c49e-59e4-49b9-8f83-49638a287c1c",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderOfficeAppsLaunchChildProcessType",
                              "valueJson":  "\"block\"",
                              "value":  "block"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "1674109f-23ee-4860-b12d-ef3f3abc11b9",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderOfficeMacroCodeAllowWin32ImportsType",
                              "valueJson":  "\"block\"",
                              "value":  "block"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "200403d6-e85a-4529-80aa-b5b548e39d4d",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderOfficeCommunicationAppsLaunchChildProcess",
                              "valueJson":  "\"enable\"",
                              "value":  "enable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "52edd831-bd2a-4a00-acaf-f0dff82273ab",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderScriptObfuscatedMacroCodeType",
                              "valueJson":  "\"block\"",
                              "value":  "block"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "a9df5eb6-87a1-44d7-ad93-62c5fe27e064",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderScriptDownloadedPayloadExecutionType",
                              "valueJson":  "\"block\"",
                              "value":  "block"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "f1b0f132-7b8e-4939-8251-a0ff3c301d9c",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderProcessCreationType",
                              "valueJson":  "\"block\"",
                              "value":  "block"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "3012753a-86e4-41a6-ba9b-72999bddd979",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderUntrustedUSBProcessType",
                              "valueJson":  "\"block\"",
                              "value":  "block"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "13e092c8-53fb-4c08-923d-cb4605874b8b",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderUntrustedExecutableType",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "3e49b60b-3f02-40c2-9529-6573b0b1af18",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderEmailContentExecutionType",
                              "valueJson":  "\"block\"",
                              "value":  "block"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "919fbff3-faac-408a-ac78-a565cbfc7b82",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAdvancedRansomewareProtectionType",
                              "valueJson":  "\"enable\"",
                              "value":  "enable"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementStringSettingInstance",
                              "id":  "e11dd36f-f1b2-4a16-a318-5b1a0a5d16f7",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderGuardMyFoldersType",
                              "valueJson":  "\"auditMode\"",
                              "value":  "auditMode"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementCollectionSettingInstance",
                              "id":  "c562c267-477c-47a9-b3f0-b726721fc101",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAdditionalGuardedFolders",
                              "valueJson":  "null"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementCollectionSettingInstance",
                              "id":  "5b1ed7b7-fa13-4e20-a416-87e33833d542",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderGuardedFoldersAllowedAppPaths",
                              "valueJson":  "null"
                          },
                          {
                              "@odata.type":  "#microsoft.graph.deviceManagementCollectionSettingInstance",
                              "id":  "fb27248a-a5cd-412d-baa6-e1a768c780c6",
                              "definitionId":  "deviceConfiguration--windows10EndpointProtectionConfiguration_defenderAttackSurfaceReductionExcludedPaths",
                              "valueJson":  "null"
                          }
                      ]
}


"@

####################################################

$ES_DeviceControl = @"

{
    "displayName":  "[ITPM Corporate] Optional: Block removable storage",
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
    "displayName":  "[ITPM Corporate] Windows Hello for Business",
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


###################################################################################################
## Import policies from JSON
###################################################################################################
Write-Host
Write-Host "Compliance policies specify the minimum requirements for connecting to Company resources."
Write-Host
$Answer = Read-Host "Do you want to import the Baseline Compliance policies? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {

## RECOMMENDED: Import Baseline MDM Compliance policies 
Write-Host "Adding Baseline Compliance policies..." -ForegroundColor Cyan
Write-Host
Write-Host "Adding Windows Immediate policy..." -ForegroundColor Yellow
Add-DeviceCompliancePolicybaseline -JSON $Comp_WinImmediate 
Write-Host
Write-Host "Adding Windows Delayed policy..." -ForegroundColor Yellow
Add-DeviceCompliancePolicybaseline -JSON $Comp_WinDelayed
Write-Host
} else

{
Write-Host
Write-Host "Baseline Compliance policies will not be imported" -ForegroundColor Red
Write-Host 
}

####################################################

## OPTIONAL: Import Windows Information Protection (App protection) policies
Write-Host "App protection policies help prevent data leakage on endpoints and enable lightweight management for non-enrolled devices."
Write-Host
$Answer = Read-Host "Do you want to import App protection policies for Windows 10? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {

Write-Host "Adding Windows Information Protection policies..." -ForegroundColor Cyan
Write-Host
Write-Host "Adding WIP policy for MDM enrolled devices" -ForegroundColor Yellow
Add-MDMWindowsInformationProtectionPolicy -JSON $WIPMDM
Write-Host
Write-Host "Adding WIP policy for MAM/unmanaged devices" -ForegroundColor Yellow
Add-WindowsInformationProtectionPolicy -JSON $WIPMAM 
Write-Host
Write-Host "WARNING: Additional set up required in order to use WIP!" -ForegroundColor Yellow 
Write-Host
} else 

{ 
Write-Host
Write-Host "Windows Information Protection policies will not be imported" -ForegroundColor Red
Write-Host 
}

####################################################

## Import Software update rings
Write-Host "Software update rings control the update schedule on Company owned devices."
Write-Host
$Answer = Read-Host "Do you want to import the Software update rings? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {

Write-Host "Adding Default update ring for Windows..." -ForegroundColor Yellow
Add-DeviceConfigurationPolicy -JSON $Config_WinDefaultUpdate
Write-Host
Write-Host "Adding Delayed update ring for Windows..." -ForegroundColor Yellow
Add-DeviceConfigurationPolicy -JSON $Config_WinDelayedUpdate
Write-Host
} else

{
Write-Host
Write-Host "Software update rings will not be imported" -ForegroundColor Red
Write-Host 
}

####################################################
<#
## Import desktop apps and Edge (Chromium)
Write-Host "Corporate applications such as Outlook, Word, and Excel can be deployed automatically to enrolled devices."
Write-Host
$Answer = Read-Host "Do you want to import Chromium Edge and Office Desktop apps? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
Write-Host "Adding Windows app packages..." -ForegroundColor Cyan
Write-Host
Write-Host "Publishing" ($Office32 | ConvertFrom-Json).displayName -ForegroundColor Yellow
Add-MDMApplication -JSON $Office32
Write-Host 
Write-Host "Publishing" ($Office64 | ConvertFrom-Json).displayName -ForegroundColor Yellow
Add-MDMApplication -JSON $Office64
Write-Host
Write-Host "Publishing" ($ChrEdge | ConvertFrom-Json).displayName -ForegroundColor Yellow
Add-MDMApplication -JSON $ChrEdge
Write-Host
} else

{
Write-Host
Write-Host "Chromium Edge and Office apps will not be imported" -ForegroundColor Red
Write-Host 
}
#>

####################################################

Write-Host "Configuration profiles control certain experiences for Company owned devices."
Write-Host
$Answer = Read-Host "Do you want to import the Corporate Configuration profiles? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {

## Import Corproate Device configuration profiles
Write-Host "Adding Corporate Device configuration profiles..." -ForegroundColor Cyan
Write-Host
Write-Host "Adding MDM wins over GP profile..." -ForegroundColor Yellow
Add-DeviceConfigurationPolicy -JSON $Config_WinMDMWins
Write-Host 
Write-Host "Adding Allow Autopilot reset profile..." -ForegroundColor Yellow
Add-DeviceConfigurationPolicy -JSON $Config_WinAllowReset
Write-Host
Write-Host "Adding Disable sign-in animation profile..." -ForegroundColor Yellow
Add-DeviceConfigurationPolicy -JSON $Config_WinDisableAnimation
Write-Host

## Create the ADMX Configuration profile
Write-Host "Adding OneDrive client config profile..." -ForegroundColor Yellow
Write-Host
$Policy_Name = "[ITPM Corporate] Windows: OneDrive client config"
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
} else
{
Write-Host
Write-Host "Corporate Configuration profiles will not be imported" -ForegroundColor Red
Write-Host 
}


$Answer = Read-Host "Do you want to import the antivirus policies? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {

Write-Host "Adding Antivirus security profiles..." -ForegroundColor Cyan
Write-Host
Write-Host "Adding Microsoft Defender Antivirus policy..." -ForegroundColor Yellow
Add-EndpointSecurityPolicy -TemplateId $IDAV -JSON $ES_Antivirus #OK
Write-Host
Write-Host "Adding Windows Security Center policy..." -ForegroundColor Yellow
Add-EndpointSecurityPolicy -TemplateId $IDWinExp -JSON $ES_SecurityCenter #OK
Write-Host
} else
{
Write-Host
Write-Host "Antivirus policies will not be imported" -ForegroundColor Red
Write-Host 
}


$Answer = Read-Host "Do you want to import the BitLocker policies? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
Write-Host "Adding BitLocker silent enablement policy..." -ForegroundColor Yellow
Add-EndpointSecurityPolicy -TemplateId $IDBL -JSON $ES_BitLocker
Write-Host
Write-Host "Adding BitLocker removable drive protection policy..." -ForegroundColor Yellow
Add-EndpointSecurityPolicy -TemplateId $IDBL -JSON $ES_BitLockerRD
Write-Host
}else
{
Write-Host
Write-Host "BitLocker policies will not be imported" -ForegroundColor Red
Write-Host 
}



$Answer = Read-Host "Do you want to import the Windows firewall policies? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {

Write-Host "Adding Windows Firewall policy..." -ForegroundColor Yellow
Add-EndpointSecurityPolicy -TemplateId $IDFW -JSON $ES_Firewall
Write-Host
}else
{
Write-Host
Write-Host "Windows firewall policies will not be imported" -ForegroundColor Red
Write-Host 
}


$Answer = Read-Host "Do you want to import the Attack Surface Reduction policies? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {

Write-Host "Adding Attack surface reduction rules audit policy..." -ForegroundColor Yellow
Add-EndpointSecurityPolicy -TemplateId $IDASR -JSON $ES_ASRAudit
Write-Host
Write-Host "Adding Attack surface reduction rules enable policy..." -ForegroundColor Yellow
Add-EndpointSecurityPolicy -TemplateId $IDASR -JSON $ES_ASREnable
Write-Host
Write-Host "Adding Device Control Block removable storage policy..." -ForegroundColor Yellow
Add-EndpointSecurityPolicy -TemplateId $IDDC -JSON $ES_DeviceControl
Write-Host
}else
{
Write-Host
Write-Host "Attack Surface Reduction policies will not be imported" -ForegroundColor Red
Write-Host 
}


$Answer = Read-Host "Do you want to import the Windows Hello policy? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {

Write-Host "Adding Account Protection Windows Hello policy..." -ForegroundColor Yellow
Add-EndpointSecurityPolicy -TemplateId $IDAC -JSON $ES_WindowsHello
Write-Host
}else
{
Write-Host
Write-Host "Windows Hello policy will not be imported" -ForegroundColor Red
Write-Host 
}


<#
Write-Host "Microsoft publishes recommended Security baselines for Windows and Edge."
Write-Host
$Answer = Read-Host "Do you want to import the Microsoft Security baseline profiles? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
## RECOMMENDED: Import Endpoint Security Baseline profiles
Write-Host "Adding Microsoft Security baseline profiles..." -ForegroundColor Cyan
Write-Host
Write-Host "Adding Windows OS Baseline policy..." -ForegroundColor Yellow
Add-EndpointSecurityPolicy -TemplateId $IDWin -JSON $SB_WinBase #OK
Write-Host
Write-Host "Adding Edge Chromium Baseline policy..." -ForegroundColor Yellow
Add-EndpointSecurityPolicy -TemplateId $IDEdge -JSON $SB_EdgeBase #OK
Write-Host
} else
{
Write-Host
Write-Host "Microsoft Security baselines will not be imported" -ForegroundColor Red
Write-Host 
}
#>
####################################################

Write-Host "Script completed" -ForegroundColor Cyan
Write-Host
