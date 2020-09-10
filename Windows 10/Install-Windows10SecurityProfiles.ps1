<##################################################################################################
#
.SYNOPSIS
This script imports baseline app protection, compliance and device configuration for common platforms.
The functions contained in this script are taken from the Graph samples published by Microsoft on GitHub:
https://github.com/microsoftgraph/powershell-intune-samples


.NOTES
    FileName:    Install-Windows10SecurityProfiles.ps1
    Author:      Alex Fields 
	Based on:    Per Larsen / Frank Simorjay
    Created:     October 2019
	Revised:     July 2020
    Version:     4.0 
    
#>
###################################################################################################
<#

.COPYRIGHT
Copyright (c) Microsoft Corporation. All rights reserved. Licensed under the MIT license.
See LICENSE in the project root for license information.

#>

####################################################

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

Function Add-ManagedAppPolicy(){

<#
.SYNOPSIS
This function is used to add an Managed App policy using the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and adds a Managed App policy
.EXAMPLE
Add-ManagedAppPolicy -JSON $JSON
Adds a Managed App policy in Intune
.NOTES
NAME: Add-ManagedAppPolicy
#>

[cmdletbinding()]

param
(
    $JSON
)

$graphApiVersion = "Beta"
$Resource = "deviceAppManagement/managedAppPolicies"

    try {

        if($JSON -eq "" -or $JSON -eq $null){

        write-host "No JSON specified, please specify valid JSON for a Managed App Policy..." -f Red

        }

        else {

        Test-JSON -JSON $JSON

        $uri = "https://graph.microsoft.com/$graphApiVersion/$($Resource)"
        Invoke-RestMethod -Uri $uri -Headers $authToken -Method Post -Body $JSON -ContentType "application/json"

        }

    }

    catch {

    Write-Host
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

$EnterpriseDomain = Get-EnterpriseDomain

$Sharepoint = $EnterpriseDomain.Split(".")[0]


####################################################
#Jason Components
####################################################



####################################################
#App Protection policies
####################################################

$APP_WIP_MDM = @"



{

  "description": "This policy protects app data on MDM-enrolled Windows 10 devices",

  "displayName": "Windows 10 Managed Devices App Protection Baseline",

  "enforcementLevel": "encryptAndAuditOnly",

  "enterpriseDomain": "$EnterpriseDomain",

  "enterpriseProtectedDomainNames": [],

  "protectionUnderLockConfigRequired": false,

  "dataRecoveryCertificate": null,

  "revokeOnUnenrollDisabled": false,

  "rightsManagementServicesTemplateId": null,

  "azureRightsManagementServicesAllowed": false,

  "iconsVisible": false,

  "protectedApps": [

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionDesktopApp",

      "description": "",

      "displayName": "Microsoft Teams",

      "productName": "*",

      "publisherName": "O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false,

      "binaryName": "teams.exe",

      "binaryVersionLow": "*",

      "binaryVersionHigh": "*"

    },

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionDesktopApp",

      "description": "",

      "displayName": "Microsoft Remote Desktop",

      "productName": "*",

      "publisherName": "O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false,

      "binaryName": "mstsc.exe",

      "binaryVersionLow": "*",

      "binaryVersionHigh": "*"

    },

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionDesktopApp",

      "description": "",

      "displayName": "Microsoft Paint",

      "productName": "*",

      "publisherName": "O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false,

      "binaryName": "mspaint.exe",

      "binaryVersionLow": "*",

      "binaryVersionHigh": "*"

    },

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionDesktopApp",

      "description": "",

      "displayName": "Notepad",

      "productName": "*",

      "publisherName": "O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false,

      "binaryName": "notepad.exe",

      "binaryVersionLow": "*",

      "binaryVersionHigh": "*"

    },

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionDesktopApp",

      "description": "",

      "displayName": "Microsoft OneDrive",

      "productName": "*",

      "publisherName": "O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false,

      "binaryName": "onedrive.exe",

      "binaryVersionLow": "*",

      "binaryVersionHigh": "*"

    },

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionDesktopApp",

      "description": "",

      "displayName": "IE11",

      "productName": "*",

      "publisherName": "O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false,

      "binaryName": "iexplore.exe",

      "binaryVersionLow": "*",

      "binaryVersionHigh": "*"

    },

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",

      "description": "",

      "displayName": "Company Portal",

      "productName": "Microsoft.CompanyPortal",

      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false

    },

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",

      "description": "",

      "displayName": "Microsoft Messaging",

      "productName": "Microsoft.Messaging",

      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false

    },

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",

      "description": "",

      "displayName": "Microsoft Movies and TV",

      "productName": "Microsoft.ZuneVideo",

      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false

    },

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",

      "description": "",

      "displayName": "Groove Music",

      "productName": "Microsoft.ZuneMusic",

      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false

    },

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",

      "description": "",

      "displayName": "Microsoft Photos",

      "productName": "Microsoft.Windows.Photos",

      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false

    },

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",

      "description": "",

      "displayName": "Mail and Calendar for Windows 10",

      "productName": "microsoft.windowscommunicationsapps",

      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false

    },

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",

      "description": "",

      "displayName": "OneNote",

      "productName": "Microsoft.Office.OneNote",

      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false

    },

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",

      "description": "",

      "displayName": "PowerPoint Mobile",

      "productName": "Microsoft.Office.PowerPoint",

      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false

    },

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",

      "description": "",

      "displayName": "Excel Mobile",

      "productName": "Microsoft.Office.Excel",

      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false

    },

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",

      "description": "",

      "displayName": "Word Mobile",

      "productName": "Microsoft.Office.Word",

      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false

    },

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",

      "description": "",

      "displayName": "Microsoft People",

      "productName": "Microsoft.People",

      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false

    },

    {

      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",

      "description": "",

      "displayName": "Microsoft Edge",

      "productName": "Microsoft.MicrosoftEdge",

      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",

      "denied": false

    }

  ],

  "exemptApps": [],

  "protectedAppLockerFiles": [

    {

      "displayName": "Denied-Downlevel-Office-365-ProPlus.xml",

      "fileHash": "786d7f7d-0735-49b8-9293-7b3aaf68b68c",

      "file": "PEFwcExvY2tlclBvbGljeSBWZXJzaW9uPSIxIj4NCjxSdWxlQ29sbGVjdGlvbiBUeXBlPSJFeGUiIEVuZm9yY2VtZW50TW9kZT0iRW5hYmxlZCI+DQogIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iYjAwNWVhZGUtYTVlZS00ZjVhLWJlNDUtZDA4ZmE1NTdhNGIyIiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgPENvbmRpdGlvbnM+DQogICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIqIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICA8L0NvbmRpdGlvbnM+DQogIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iZGU5ZjM0NjEtNjg1Ni00MDVkLTk2MjQtYTgwY2E3MDFmNmNiIiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMDMsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICA8Q29uZGl0aW9ucz4NCiAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAwMyIgQmluYXJ5TmFtZT0iKiI+DQogICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgPC9Db25kaXRpb25zPg0KICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImFkZTFiODI4LTcwNTUtNDdmYy05OWJjLTQzMmNmN2QxMjA5ZSIgTmFtZT0iMjAwNyBNSUNST1NPRlQgT0ZGSUNFIFNZU1RFTSwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgIDxDb25kaXRpb25zPg0KICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iMjAwNyBNSUNST1NPRlQgT0ZGSUNFIFNZU1RFTSIgQmluYXJ5TmFtZT0iKiI+DQogICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgPC9Db25kaXRpb25zPg0KICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImY2YTA3NWI1LWE1YjUtNDY1NC1hYmQ2LTczMWRhY2I0MGQ5NSIgTmFtZT0iTUlDUk9TT0ZUIE9GRklDRSBPTkVOT1RFLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgPENvbmRpdGlvbnM+DQogICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIE9ORU5PVEUiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIxMi4wLjk5OTkuOTk5OSIgLz4NCiAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICA8L0NvbmRpdGlvbnM+DQogIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iMGVjMDNiMmYtZTlhNC00NzQzLWFlNjAtNmQyOTg4NmNmNmFlIiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFIE9VVExPT0ssIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICA8Q29uZGl0aW9ucz4NCiAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgT1VUTE9PSyIgQmluYXJ5TmFtZT0iKiI+DQogICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IjEyLjAuOTk5OS45OTk5IiAvPg0KICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgIDwvQ29uZGl0aW9ucz4NCiAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSI3YjI3MmVmZC00MTA1LTRmYjctOWQ0MC1iZmE1OTdjNjc5MmEiIE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxMywgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgIDxDb25kaXRpb25zPg0KICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDEzIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIqIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICA8L0NvbmRpdGlvbnM+DQogIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iODlkOGE0ZDMtZjllMy00MjNhLTkyYWUtODZlNzMzM2UyNjYyIiBOYW1lPSJNSUNST1NPRlQgT05FTk9URSwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgIDxDb25kaXRpb25zPg0KICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9ORU5PVEUiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8RXhjZXB0aW9ucz4NCiAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPTkVOT1RFIiBCaW5hcnlOYW1lPSJPTkVOT1RFLkVYRSI+DQogICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC43NTAwLjAwMDAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgIDwvRXhjZXB0aW9ucz4NCiAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSI1YTIxMzhiZC04MDQyLTRlYzUtOTViNC1mOTkwNjY2ZmJmNjEiIE5hbWU9Ik1JQ1JPU09GVCBPVVRMT09LLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgPENvbmRpdGlvbnM+DQogICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT1VUTE9PSyIgQmluYXJ5TmFtZT0iKiI+DQogICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgPC9Db25kaXRpb25zPg0KICAgIDxFeGNlcHRpb25zPg0KICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9VVExPT0siIEJpbmFyeU5hbWU9Ik9VVExPT0suRVhFIj4NCiAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc1MDAuMDAwMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgPC9FeGNlcHRpb25zPg0KICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9IjNmYzVmOWM1LWYxODAtNDM1Yi04MzhmLTI5NjAxMDZhMzg2MCIgTmFtZT0iTUlDUk9TT0ZUIE9ORURSSVZFLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgPENvbmRpdGlvbnM+DQogICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT05FRFJJVkUiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8RXhjZXB0aW9ucz4NCiAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPTkVEUklWRSIgQmluYXJ5TmFtZT0iT05FRFJJVkUuRVhFIj4NCiAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNy4zLjYzODYuMDQxMiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgPC9FeGNlcHRpb25zPg0KICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9IjE3ZDk4OGVmLTA3M2UtNGQ5Mi1iNGJmLWY0NzdiMmVjY2NiNSIgTmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2LCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgPENvbmRpdGlvbnM+DQogICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8RXhjZXB0aW9ucz4NCiAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iTFlOQy5FWEUiPg0KICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuNzUwMC4wMDAwIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iTFlOQzk5LkVYRSI+DQogICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC43NTAwLjAwMDAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJVQ01BUEkuRVhFIj4NCiAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc1MDAuMDAwMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9Ik9DUFVCTUdSLkVYRSI+DQogICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC43NTAwLjAwMDAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJXSU5XT1JELkVYRSI+DQogICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC43NTAwLjAwMDAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJFWENFTC5FWEUiPg0KICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuNzUwMC4wMDAwIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iUE9XRVJQTlQuRVhFIj4NCiAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc1MDAuMDAwMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9Ik1TT1NZTkMuRVhFIj4NCiAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc1MDAuMDAwMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgPC9FeGNlcHRpb25zPg0KICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KPC9SdWxlQ29sbGVjdGlvbj4NCjwvQXBwTG9ja2VyUG9saWN5Pg==",

      "id": "95a3cc79-7306-4eac-8a1a-7daef9f083b3",

      "@odata.type": "#microsoft.graph.windowsInformationProtectionAppLockerFile"

    },

    {

      "displayName": "Office-365-ProPlus-1708-Allowed.xml",

      "fileHash": "2eb106c8-234b-4253-af44-63f522bfe222",

      "file": "PEFwcExvY2tlclBvbGljeSBWZXJzaW9uPSIxIj4NCiAgPFJ1bGVDb2xsZWN0aW9uIFR5cGU9IkV4ZSIgRW5mb3JjZW1lbnRNb2RlPSJFbmFibGVkIj4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImQ2NjMyNzZjLTU0NGUtNGRlYS1iNzVjLTc1ZmMyZDRlMDI2NiIgTmFtZT0iTFlOQy5FWEUsIHZlcnNpb24gMTYuMC43ODcwLjIwMjAgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJMWU5DLkVYRSI+DQoJCSAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuNzg3MC4yMDIwIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9Db25kaXRpb25zPg0KCTwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSIyMTk1NzFiNC1hMjU3LTRiNGMtYjg1Ni1lYmYwNjgxZWUwZjAiIE5hbWU9IkxZTkM5OS5FWEUsIHZlcnNpb24gMTYuMC43ODcwLjIwMjAgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJMWU5DOTkuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuNzg3MC4yMDIwIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9Db25kaXRpb25zPg0KICAgIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSI1MzhkNDQzYS05ZmRiLTQ5MWUtOGJjMy1lNzhkYjljMzEwYzciIE5hbWU9Ik9ORU5PVEVNLkVYRSwgdmVyc2lvbiAxNi4wLjgyMDEuMjAyNSBhbmQgYWJvdmUsIGluIE1JQ1JPU09GVCBPTkVOT1RFLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPTkVOT1RFIiBCaW5hcnlOYW1lPSJPTkVOT1RFTS5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9IjZlZjA3YTkyLWYxZGItNDg4MC04YjQwLWRkMzliNzQzYTQ4NSIgTmFtZT0iV0lOV09SRC5FWEUsIHZlcnNpb24gMTYuMC44MjAxLjIwMjUgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJXSU5XT1JELkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjgyMDEuMjAyNSIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iN2Q3NGQxYWQtYTYwYi00ZWE4LWJiNjAtM2Q0MDQ4ODZkMTBiIiBOYW1lPSJPTkVOT1RFLkVYRSwgdmVyc2lvbiAxNi4wLjgyMDEuMjAyNSBhbmQgYWJvdmUsIGluIE1JQ1JPU09GVCBPTkVOT1RFLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPTkVOT1RFIiBCaW5hcnlOYW1lPSJPTkVOT1RFLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjgyMDEuMjAyNSIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iODQwOWFhNjItMWI1Mi00ODRiLTg3ODctZDU3Y2M4NTI1ZTIxIiBOYW1lPSJPQ1BVQk1HUi5FWEUsIHZlcnNpb24gMTYuMC43ODcwLjIwMjAgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJPQ1BVQk1HUi5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC43ODcwLjIwMjAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImU2Y2NjY2QxLWE2MGYtNGNiNC04YjRiLTkwM2M3MDk3NmI1MCIgTmFtZT0iUE9XRVJQTlQuRVhFLCB2ZXJzaW9uIDE2LjAuODIwMS4yMDI1IGFuZCBhYm92ZSwgaW4gTUlDUk9TT0ZUIE9GRklDRSAyMDE2LCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iUE9XRVJQTlQuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9Db25kaXRpb25zPg0KICAgIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSJlYzc5ZWJiZS0zMTY5LTRhMjYtYWY1ZS1lMDc2YzkwOTY0OTUiIE5hbWU9Ik1TT1NZTkMuRVhFLCB2ZXJzaW9uIDE2LjAuODIwMS4yMDI1IGFuZCBhYm92ZSwgaW4gTUlDUk9TT0ZUIE9GRklDRSAyMDE2LCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iTVNPU1lOQy5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImYwYjM1MjZiLTE0ZTctNDQyOC05NzAzLTRkZmYyZWE0MDAwZCIgTmFtZT0iVUNNQVBJLkVYRSwgdmVyc2lvbiAxNi4wLjc4NzAuMjAyMCBhbmQgYWJvdmUsIGluIE1JQ1JPU09GVCBPRkZJQ0UgMjAxNiwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkFsbG93Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9IlVDTUFQSS5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC43ODcwLjIwMjAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImYxYmVkY2IxLWNhMzQtNDdiNS04NmM4LTI1NjU0YjE3OGNiOSIgTmFtZT0iT1VUTE9PSy5FWEUsIHZlcnNpb24gMTYuMC44MjAxLjIwMjUgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT1VUTE9PSywgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkFsbG93Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT1VUTE9PSyIgQmluYXJ5TmFtZT0iT1VUTE9PSy5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImY5NjFlODQ2LTNmZTctNDY0Yy05NTA4LTAzNTMzN2QxZTg2OCIgTmFtZT0iRVhDRUwuRVhFLCB2ZXJzaW9uIDE2LjAuODIwMS4yMDI1IGFuZCBhYm92ZSwgaW4gTUlDUk9TT0ZUIE9GRklDRSAyMDE2LCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iRVhDRUwuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9Db25kaXRpb25zPg0KICAgIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSJkNzAzMzE5Yy0wYzllLTQ0NjctYWQwOS03MTMzMDdlMzBkZjYiIE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImRlOWYzNDYxLTY4NTYtNDA1ZC05NjI0LWE4MGNhNzAxZjZjYiIgTmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDAzLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDAzIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImFkZTFiODI4LTcwNTUtNDdmYy05OWJjLTQzMmNmN2QxMjA5ZSIgTmFtZT0iMjAwNyBNSUNST1NPRlQgT0ZGSUNFIFNZU1RFTSwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9IjIwMDcgTUlDUk9TT0ZUIE9GRklDRSBTWVNURU0iIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iYmIzODc3YjYtZjFhZC00YzgzLTk2ZTItZDZiZjc1ZTMzY2JmIiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTAsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTAiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iMjM2MzVlZWYtYjFlMy00ZGEyLTg4NTktMDYzOGVjNjA3YjM4IiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTMsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTMiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iZDJkMDUyMGEtNTdkZS00YmQ1LWJjZDktYjNkNDcyMjFmODdhIiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICAgIDxFeGNlcHRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9IkVYQ0VMLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjgyMDEuMjAyNSIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJMWU5DLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc4NzAuMjAyMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJMWU5DOTkuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuNzg3MC4yMDIwIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9Ik1TT1NZTkMuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9Ik9DUFVCTUdSLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc4NzAuMjAyMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJQT1dFUlBOVC5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iVUNNQVBJLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc4NzAuMjAyMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJXSU5XT1JELkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjgyMDEuMjAyNSIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvRXhjZXB0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iYTMzNjVkZmYtNjA1Mi00MWE4LTgyYTYtMzQ0NDRlYzI1OTUzIiBOYW1lPSJNSUNST1NPRlQgT05FTk9URSwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPTkVOT1RFIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgICA8RXhjZXB0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9ORU5PVEUiIEJpbmFyeU5hbWU9Ik9ORU5PVEUuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT05FTk9URSIgQmluYXJ5TmFtZT0iT05FTk9URU0uRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9FeGNlcHRpb25zPg0KICAgIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSIwYmE0YzE1MC0xY2IzLTRjYjktYWIwMi0yNjUyNzQ0MTk0MDkiIE5hbWU9Ik1JQ1JPU09GVCBPVVRMT09LLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9VVExPT0siIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICAgIDxFeGNlcHRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT1VUTE9PSyIgQmluYXJ5TmFtZT0iT1VUTE9PSy5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0V4Y2VwdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9IjY3MTRmODVmLWFkZGEtNGVjNy05NDdjLTc1NTJmN2Q5NDYyNSIgTmFtZT0iTUlDUk9TT0ZUIENMSVAgT1JHQU5JWkVSLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIENMSVAgT1JHQU5JWkVSIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4JDQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSI3NGFiMzY4Zi1hMTQ3LTRjZjktODBjMy01M2ZiNjY5YzQ4MzYiIE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgSU5GT1BBVEgsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIElORk9QQVRIIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9Ijk3NjlkMjA5LTg1ZjgtNDM4OS1iZGM2LWRkY2EzMGYxYzY3MSIgTmFtZT0iTUlDUk9TT0ZUIE9GRklDRSBIRUxQIFZJRVdFUiwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgSEVMUCBWSUVXRVIiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KCTwvUnVsZUNvbGxlY3Rpb24+DQo8L0FwcExvY2tlclBvbGljeT4=",

      "id": "4e49ffae-f006-46b9-b74d-785565f7efb4",

      "@odata.type": "#microsoft.graph.windowsInformationProtectionAppLockerFile"

    }

  ],

  "exemptAppLockerFiles": [],

  "enterpriseNetworkDomainNames": [],

  "enterpriseProxiedDomains": [

    {

      "displayName": "SharePoint",

      "proxiedDomains": [

        {

          "ipAddressOrFQDN": "$Sharepoint.sharepoint.com",

          "@odata.type": "#microsoft.graph.proxiedDomain"

        },

        {

          "ipAddressOrFQDN": "$Sharepoint-my.sharepoint.com",

          "@odata.type": "#microsoft.graph.proxiedDomain"

        },

        {

          "ipAddressOrFQDN": "/*AppCompat*/",

          "@odata.type": "#microsoft.graph.proxiedDomain"

        }

      ],

      "@odata.type": "#microsoft.graph.windowsInformationProtectionProxiedDomainCollection"

    }

  ],

  "enterpriseIPRanges": [],

  "enterpriseIPRangesAreAuthoritative": false,

  "enterpriseProxyServers": [],

  "enterpriseInternalProxyServers": [],

  "enterpriseProxyServersAreAuthoritative": false,

  "neutralDomainResources": [],

  "@odata.type": "#microsoft.graph.mdmWindowsInformationProtectionPolicy"

}



"@

####################################################

$APP_WIP_MAM = @"
{
  "description": "This policy protects app data on non-enrolled Windows 10 devices",
  "displayName": "Windows 10 Unmanaged Devices App Protection Baseline",
  "enforcementLevel": "encryptAndAuditOnly",
  "enterpriseDomain": "$EnterpriseDomain",
  "enterpriseProtectedDomainNames": [],
  "protectionUnderLockConfigRequired": false,
  "dataRecoveryCertificate": null,
  "revokeOnUnenrollDisabled": false,
  "revokeOnMdmHandoffDisabled": true,
  "rightsManagementServicesTemplateId": null,
  "azureRightsManagementServicesAllowed": false,
  "iconsVisible": false,
  "protectedApps": [
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionDesktopApp",
      "description": "",
      "displayName": "Microsoft Teams",
      "productName": "*",
      "publisherName": "O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false,
      "binaryName": "teams.exe",
      "binaryVersionLow": "*",
      "binaryVersionHigh": "*"
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionDesktopApp",
      "description": "",
      "displayName": "Microsoft Remote Desktop",
      "productName": "*",
      "publisherName": "O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false,
      "binaryName": "mstsc.exe",
      "binaryVersionLow": "*",
      "binaryVersionHigh": "*"
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionDesktopApp",
      "description": "",
      "displayName": "Microsoft Paint",
      "productName": "*",
      "publisherName": "O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false,
      "binaryName": "mspaint.exe",
      "binaryVersionLow": "*",
      "binaryVersionHigh": "*"
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionDesktopApp",
      "description": "",
      "displayName": "Notepad",
      "productName": "*",
      "publisherName": "O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false,
      "binaryName": "notepad.exe",
      "binaryVersionLow": "*",
      "binaryVersionHigh": "*"
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionDesktopApp",
      "description": "",
      "displayName": "Microsoft OneDrive",
      "productName": "*",
      "publisherName": "O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false,
      "binaryName": "onedrive.exe",
      "binaryVersionLow": "*",
      "binaryVersionHigh": "*"
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionDesktopApp",
      "description": "",
      "displayName": "IE11",
      "productName": "*",
      "publisherName": "O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false,
      "binaryName": "iexplore.exe",
      "binaryVersionLow": "*",
      "binaryVersionHigh": "*"
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "Company Portal",
      "productName": "Microsoft.CompanyPortal",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "Microsoft Messaging",
      "productName": "Microsoft.Messaging",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "Microsoft Movies and TV",
      "productName": "Microsoft.ZuneVideo",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "Groove Music",
      "productName": "Microsoft.ZuneMusic",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "Microsoft Photos",
      "productName": "Microsoft.Windows.Photos",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "Mail and Calendar for Windows 10",
      "productName": "microsoft.windowscommunicationsapps",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "OneNote",
      "productName": "Microsoft.Office.OneNote",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "PowerPoint Mobile",
      "productName": "Microsoft.Office.PowerPoint",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "Excel Mobile",
      "productName": "Microsoft.Office.Excel",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "Word Mobile",
      "productName": "Microsoft.Office.Word",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "Microsoft People",
      "productName": "Microsoft.People",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    },
    {
      "@odata.type": "#microsoft.graph.windowsInformationProtectionStoreApp",
      "description": "",
      "displayName": "Microsoft Edge",
      "productName": "Microsoft.MicrosoftEdge",
      "publisherName": "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US",
      "denied": false
    }
  ],
  "exemptApps": [],
  "protectedAppLockerFiles": [
    {
      "displayName": "Denied-Downlevel-Office-365-ProPlus.xml",
      "fileHash": "69f299b4-e4aa-48d1-8c6a-49600133d832",
      "file": "PEFwcExvY2tlclBvbGljeSBWZXJzaW9uPSIxIj4NCjxSdWxlQ29sbGVjdGlvbiBUeXBlPSJFeGUiIEVuZm9yY2VtZW50TW9kZT0iRW5hYmxlZCI+DQogIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iYjAwNWVhZGUtYTVlZS00ZjVhLWJlNDUtZDA4ZmE1NTdhNGIyIiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgPENvbmRpdGlvbnM+DQogICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIqIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICA8L0NvbmRpdGlvbnM+DQogIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iZGU5ZjM0NjEtNjg1Ni00MDVkLTk2MjQtYTgwY2E3MDFmNmNiIiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMDMsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICA8Q29uZGl0aW9ucz4NCiAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAwMyIgQmluYXJ5TmFtZT0iKiI+DQogICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgPC9Db25kaXRpb25zPg0KICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImFkZTFiODI4LTcwNTUtNDdmYy05OWJjLTQzMmNmN2QxMjA5ZSIgTmFtZT0iMjAwNyBNSUNST1NPRlQgT0ZGSUNFIFNZU1RFTSwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgIDxDb25kaXRpb25zPg0KICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iMjAwNyBNSUNST1NPRlQgT0ZGSUNFIFNZU1RFTSIgQmluYXJ5TmFtZT0iKiI+DQogICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgPC9Db25kaXRpb25zPg0KICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImY2YTA3NWI1LWE1YjUtNDY1NC1hYmQ2LTczMWRhY2I0MGQ5NSIgTmFtZT0iTUlDUk9TT0ZUIE9GRklDRSBPTkVOT1RFLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgPENvbmRpdGlvbnM+DQogICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIE9ORU5PVEUiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIxMi4wLjk5OTkuOTk5OSIgLz4NCiAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICA8L0NvbmRpdGlvbnM+DQogIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iMGVjMDNiMmYtZTlhNC00NzQzLWFlNjAtNmQyOTg4NmNmNmFlIiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFIE9VVExPT0ssIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICA8Q29uZGl0aW9ucz4NCiAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgT1VUTE9PSyIgQmluYXJ5TmFtZT0iKiI+DQogICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IjEyLjAuOTk5OS45OTk5IiAvPg0KICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgIDwvQ29uZGl0aW9ucz4NCiAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSI3YjI3MmVmZC00MTA1LTRmYjctOWQ0MC1iZmE1OTdjNjc5MmEiIE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxMywgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgIDxDb25kaXRpb25zPg0KICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDEzIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIqIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICA8L0NvbmRpdGlvbnM+DQogIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iODlkOGE0ZDMtZjllMy00MjNhLTkyYWUtODZlNzMzM2UyNjYyIiBOYW1lPSJNSUNST1NPRlQgT05FTk9URSwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgIDxDb25kaXRpb25zPg0KICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9ORU5PVEUiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8RXhjZXB0aW9ucz4NCiAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPTkVOT1RFIiBCaW5hcnlOYW1lPSJPTkVOT1RFLkVYRSI+DQogICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC43NTAwLjAwMDAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgIDwvRXhjZXB0aW9ucz4NCiAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSI1YTIxMzhiZC04MDQyLTRlYzUtOTViNC1mOTkwNjY2ZmJmNjEiIE5hbWU9Ik1JQ1JPU09GVCBPVVRMT09LLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgPENvbmRpdGlvbnM+DQogICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT1VUTE9PSyIgQmluYXJ5TmFtZT0iKiI+DQogICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgPC9Db25kaXRpb25zPg0KICAgIDxFeGNlcHRpb25zPg0KICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9VVExPT0siIEJpbmFyeU5hbWU9Ik9VVExPT0suRVhFIj4NCiAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc1MDAuMDAwMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgPC9FeGNlcHRpb25zPg0KICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9IjNmYzVmOWM1LWYxODAtNDM1Yi04MzhmLTI5NjAxMDZhMzg2MCIgTmFtZT0iTUlDUk9TT0ZUIE9ORURSSVZFLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgPENvbmRpdGlvbnM+DQogICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT05FRFJJVkUiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8RXhjZXB0aW9ucz4NCiAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPTkVEUklWRSIgQmluYXJ5TmFtZT0iT05FRFJJVkUuRVhFIj4NCiAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNy4zLjYzODYuMDQxMiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgPC9FeGNlcHRpb25zPg0KICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9IjE3ZDk4OGVmLTA3M2UtNGQ5Mi1iNGJmLWY0NzdiMmVjY2NiNSIgTmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2LCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgPENvbmRpdGlvbnM+DQogICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8RXhjZXB0aW9ucz4NCiAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iTFlOQy5FWEUiPg0KICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuNzUwMC4wMDAwIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iTFlOQzk5LkVYRSI+DQogICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC43NTAwLjAwMDAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJVQ01BUEkuRVhFIj4NCiAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc1MDAuMDAwMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9Ik9DUFVCTUdSLkVYRSI+DQogICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC43NTAwLjAwMDAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJXSU5XT1JELkVYRSI+DQogICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC43NTAwLjAwMDAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJFWENFTC5FWEUiPg0KICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuNzUwMC4wMDAwIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iUE9XRVJQTlQuRVhFIj4NCiAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc1MDAuMDAwMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9Ik1TT1NZTkMuRVhFIj4NCiAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc1MDAuMDAwMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgPC9FeGNlcHRpb25zPg0KICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KPC9SdWxlQ29sbGVjdGlvbj4NCjwvQXBwTG9ja2VyUG9saWN5Pg==",
      "id": "a23470d1-1fb1-445f-9282-e4a7d10ff5b8",
      "@odata.type": "#microsoft.graph.windowsInformationProtectionAppLockerFile"
    },
    {
      "displayName": "Office-365-ProPlus-1708-Allowed.xml",
      "fileHash": "4107a857-0e0b-483f-8ff5-bb3ed095b434",
      "file": "PEFwcExvY2tlclBvbGljeSBWZXJzaW9uPSIxIj4NCiAgPFJ1bGVDb2xsZWN0aW9uIFR5cGU9IkV4ZSIgRW5mb3JjZW1lbnRNb2RlPSJFbmFibGVkIj4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImQ2NjMyNzZjLTU0NGUtNGRlYS1iNzVjLTc1ZmMyZDRlMDI2NiIgTmFtZT0iTFlOQy5FWEUsIHZlcnNpb24gMTYuMC43ODcwLjIwMjAgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJMWU5DLkVYRSI+DQoJCSAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuNzg3MC4yMDIwIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9Db25kaXRpb25zPg0KCTwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSIyMTk1NzFiNC1hMjU3LTRiNGMtYjg1Ni1lYmYwNjgxZWUwZjAiIE5hbWU9IkxZTkM5OS5FWEUsIHZlcnNpb24gMTYuMC43ODcwLjIwMjAgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJMWU5DOTkuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuNzg3MC4yMDIwIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9Db25kaXRpb25zPg0KICAgIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSI1MzhkNDQzYS05ZmRiLTQ5MWUtOGJjMy1lNzhkYjljMzEwYzciIE5hbWU9Ik9ORU5PVEVNLkVYRSwgdmVyc2lvbiAxNi4wLjgyMDEuMjAyNSBhbmQgYWJvdmUsIGluIE1JQ1JPU09GVCBPTkVOT1RFLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPTkVOT1RFIiBCaW5hcnlOYW1lPSJPTkVOT1RFTS5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9IjZlZjA3YTkyLWYxZGItNDg4MC04YjQwLWRkMzliNzQzYTQ4NSIgTmFtZT0iV0lOV09SRC5FWEUsIHZlcnNpb24gMTYuMC44MjAxLjIwMjUgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJXSU5XT1JELkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjgyMDEuMjAyNSIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iN2Q3NGQxYWQtYTYwYi00ZWE4LWJiNjAtM2Q0MDQ4ODZkMTBiIiBOYW1lPSJPTkVOT1RFLkVYRSwgdmVyc2lvbiAxNi4wLjgyMDEuMjAyNSBhbmQgYWJvdmUsIGluIE1JQ1JPU09GVCBPTkVOT1RFLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPTkVOT1RFIiBCaW5hcnlOYW1lPSJPTkVOT1RFLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjgyMDEuMjAyNSIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iODQwOWFhNjItMWI1Mi00ODRiLTg3ODctZDU3Y2M4NTI1ZTIxIiBOYW1lPSJPQ1BVQk1HUi5FWEUsIHZlcnNpb24gMTYuMC43ODcwLjIwMjAgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJBbGxvdyI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJPQ1BVQk1HUi5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC43ODcwLjIwMjAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImU2Y2NjY2QxLWE2MGYtNGNiNC04YjRiLTkwM2M3MDk3NmI1MCIgTmFtZT0iUE9XRVJQTlQuRVhFLCB2ZXJzaW9uIDE2LjAuODIwMS4yMDI1IGFuZCBhYm92ZSwgaW4gTUlDUk9TT0ZUIE9GRklDRSAyMDE2LCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iUE9XRVJQTlQuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9Db25kaXRpb25zPg0KICAgIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSJlYzc5ZWJiZS0zMTY5LTRhMjYtYWY1ZS1lMDc2YzkwOTY0OTUiIE5hbWU9Ik1TT1NZTkMuRVhFLCB2ZXJzaW9uIDE2LjAuODIwMS4yMDI1IGFuZCBhYm92ZSwgaW4gTUlDUk9TT0ZUIE9GRklDRSAyMDE2LCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iTVNPU1lOQy5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImYwYjM1MjZiLTE0ZTctNDQyOC05NzAzLTRkZmYyZWE0MDAwZCIgTmFtZT0iVUNNQVBJLkVYRSwgdmVyc2lvbiAxNi4wLjc4NzAuMjAyMCBhbmQgYWJvdmUsIGluIE1JQ1JPU09GVCBPRkZJQ0UgMjAxNiwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkFsbG93Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9IlVDTUFQSS5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC43ODcwLjIwMjAiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImYxYmVkY2IxLWNhMzQtNDdiNS04NmM4LTI1NjU0YjE3OGNiOSIgTmFtZT0iT1VUTE9PSy5FWEUsIHZlcnNpb24gMTYuMC44MjAxLjIwMjUgYW5kIGFib3ZlLCBpbiBNSUNST1NPRlQgT1VUTE9PSywgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkFsbG93Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT1VUTE9PSyIgQmluYXJ5TmFtZT0iT1VUTE9PSy5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImY5NjFlODQ2LTNmZTctNDY0Yy05NTA4LTAzNTMzN2QxZTg2OCIgTmFtZT0iRVhDRUwuRVhFLCB2ZXJzaW9uIDE2LjAuODIwMS4yMDI1IGFuZCBhYm92ZSwgaW4gTUlDUk9TT0ZUIE9GRklDRSAyMDE2LCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iQWxsb3ciPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iRVhDRUwuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9Db25kaXRpb25zPg0KICAgIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSJkNzAzMzE5Yy0wYzllLTQ0NjctYWQwOS03MTMzMDdlMzBkZjYiIE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImRlOWYzNDYxLTY4NTYtNDA1ZC05NjI0LWE4MGNhNzAxZjZjYiIgTmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDAzLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDAzIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9ImFkZTFiODI4LTcwNTUtNDdmYy05OWJjLTQzMmNmN2QxMjA5ZSIgTmFtZT0iMjAwNyBNSUNST1NPRlQgT0ZGSUNFIFNZU1RFTSwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9IjIwMDcgTUlDUk9TT0ZUIE9GRklDRSBTWVNURU0iIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iYmIzODc3YjYtZjFhZC00YzgzLTk2ZTItZDZiZjc1ZTMzY2JmIiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTAsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTAiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iMjM2MzVlZWYtYjFlMy00ZGEyLTg4NTktMDYzOGVjNjA3YjM4IiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTMsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTMiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iZDJkMDUyMGEtNTdkZS00YmQ1LWJjZDktYjNkNDcyMjFmODdhIiBOYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICAgIDxFeGNlcHRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9IkVYQ0VMLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjgyMDEuMjAyNSIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJMWU5DLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc4NzAuMjAyMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJMWU5DOTkuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuNzg3MC4yMDIwIiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9Ik1TT1NZTkMuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIDIwMTYiIEJpbmFyeU5hbWU9Ik9DUFVCTUdSLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc4NzAuMjAyMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJQT1dFUlBOVC5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgMjAxNiIgQmluYXJ5TmFtZT0iVUNNQVBJLkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjc4NzAuMjAyMCIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9GRklDRSAyMDE2IiBCaW5hcnlOYW1lPSJXSU5XT1JELkVYRSI+DQogICAgICAgICAgPEJpbmFyeVZlcnNpb25SYW5nZSBMb3dTZWN0aW9uPSIxNi4wLjgyMDEuMjAyNSIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvRXhjZXB0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KICAgIDxGaWxlUHVibGlzaGVyUnVsZSBJZD0iYTMzNjVkZmYtNjA1Mi00MWE4LTgyYTYtMzQ0NDRlYzI1OTUzIiBOYW1lPSJNSUNST1NPRlQgT05FTk9URSwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPTkVOT1RFIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgICA8RXhjZXB0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9ORU5PVEUiIEJpbmFyeU5hbWU9Ik9ORU5PVEUuRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT05FTk9URSIgQmluYXJ5TmFtZT0iT05FTk9URU0uRVhFIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IjE2LjAuODIwMS4yMDI1IiBIaWdoU2VjdGlvbj0iKiIgLz4NCiAgICAgICAgPC9GaWxlUHVibGlzaGVyQ29uZGl0aW9uPg0KICAgICAgPC9FeGNlcHRpb25zPg0KICAgIDwvRmlsZVB1Ymxpc2hlclJ1bGU+DQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSIwYmE0YzE1MC0xY2IzLTRjYjktYWIwMi0yNjUyNzQ0MTk0MDkiIE5hbWU9Ik1JQ1JPU09GVCBPVVRMT09LLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIE9VVExPT0siIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICAgIDxFeGNlcHRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT1VUTE9PSyIgQmluYXJ5TmFtZT0iT1VUTE9PSy5FWEUiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iMTYuMC44MjAxLjIwMjUiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0V4Y2VwdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9IjY3MTRmODVmLWFkZGEtNGVjNy05NDdjLTc1NTJmN2Q5NDYyNSIgTmFtZT0iTUlDUk9TT0ZUIENMSVAgT1JHQU5JWkVSLCBmcm9tIE89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgRGVzY3JpcHRpb249IiIgVXNlck9yR3JvdXBTaWQ9IlMtMS0xLTAiIEFjdGlvbj0iRGVueSI+DQogICAgICA8Q29uZGl0aW9ucz4NCiAgICAgICAgPEZpbGVQdWJsaXNoZXJDb25kaXRpb24gUHVibGlzaGVyTmFtZT0iTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBQcm9kdWN0TmFtZT0iTUlDUk9TT0ZUIENMSVAgT1JHQU5JWkVSIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4JDQogICAgPEZpbGVQdWJsaXNoZXJSdWxlIElkPSI3NGFiMzY4Zi1hMTQ3LTRjZjktODBjMy01M2ZiNjY5YzQ4MzYiIE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgSU5GT1BBVEgsIGZyb20gTz1NSUNST1NPRlQgQ09SUE9SQVRJT04sIEw9UkVETU9ORCwgUz1XQVNISU5HVE9OLCBDPVVTIiBEZXNjcmlwdGlvbj0iIiBVc2VyT3JHcm91cFNpZD0iUy0xLTEtMCIgQWN0aW9uPSJEZW55Ij4NCiAgICAgIDxDb25kaXRpb25zPg0KICAgICAgICA8RmlsZVB1Ymxpc2hlckNvbmRpdGlvbiBQdWJsaXNoZXJOYW1lPSJPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIFByb2R1Y3ROYW1lPSJNSUNST1NPRlQgT0ZGSUNFIElORk9QQVRIIiBCaW5hcnlOYW1lPSIqIj4NCiAgICAgICAgICA8QmluYXJ5VmVyc2lvblJhbmdlIExvd1NlY3Rpb249IioiIEhpZ2hTZWN0aW9uPSIqIiAvPg0KICAgICAgICA8L0ZpbGVQdWJsaXNoZXJDb25kaXRpb24+DQogICAgICA8L0NvbmRpdGlvbnM+DQogICAgPC9GaWxlUHVibGlzaGVyUnVsZT4NCiAgICA8RmlsZVB1Ymxpc2hlclJ1bGUgSWQ9Ijk3NjlkMjA5LTg1ZjgtNDM4OS1iZGM2LWRkY2EzMGYxYzY3MSIgTmFtZT0iTUlDUk9TT0ZUIE9GRklDRSBIRUxQIFZJRVdFUiwgZnJvbSBPPU1JQ1JPU09GVCBDT1JQT1JBVElPTiwgTD1SRURNT05ELCBTPVdBU0hJTkdUT04sIEM9VVMiIERlc2NyaXB0aW9uPSIiIFVzZXJPckdyb3VwU2lkPSJTLTEtMS0wIiBBY3Rpb249IkRlbnkiPg0KICAgICAgPENvbmRpdGlvbnM+DQogICAgICAgIDxGaWxlUHVibGlzaGVyQ29uZGl0aW9uIFB1Ymxpc2hlck5hbWU9Ik89TUlDUk9TT0ZUIENPUlBPUkFUSU9OLCBMPVJFRE1PTkQsIFM9V0FTSElOR1RPTiwgQz1VUyIgUHJvZHVjdE5hbWU9Ik1JQ1JPU09GVCBPRkZJQ0UgSEVMUCBWSUVXRVIiIEJpbmFyeU5hbWU9IioiPg0KICAgICAgICAgIDxCaW5hcnlWZXJzaW9uUmFuZ2UgTG93U2VjdGlvbj0iKiIgSGlnaFNlY3Rpb249IioiIC8+DQogICAgICAgIDwvRmlsZVB1Ymxpc2hlckNvbmRpdGlvbj4NCiAgICAgIDwvQ29uZGl0aW9ucz4NCiAgICA8L0ZpbGVQdWJsaXNoZXJSdWxlPg0KCTwvUnVsZUNvbGxlY3Rpb24+DQo8L0FwcExvY2tlclBvbGljeT4=",
      "id": "0c5c4541-87a8-478b-b9fc-4206d0f421f9",
      "@odata.type": "#microsoft.graph.windowsInformationProtectionAppLockerFile"
    }
  ],
  "exemptAppLockerFiles": [],
  "enterpriseNetworkDomainNames": [],
  "enterpriseProxiedDomains": [
    {
      "displayName": "SharePoint",
      "proxiedDomains": [
        {
          "ipAddressOrFQDN": "$Sharepoint.sharepoint.com",
          "@odata.type": "#microsoft.graph.proxiedDomain"
        },
        {
          "ipAddressOrFQDN": "$Sharepoint-my.sharepoint.com",
          "@odata.type": "#microsoft.graph.proxiedDomain"
        },
        {
          "ipAddressOrFQDN": "/*AppCompat*/",
          "@odata.type": "#microsoft.graph.proxiedDomain"
        }
      ],
      "@odata.type": "#microsoft.graph.windowsInformationProtectionProxiedDomainCollection"
    }
  ],
  "enterpriseIPRanges": [],
  "enterpriseIPRangesAreAuthoritative": false,
  "enterpriseProxyServers": [],
  "enterpriseInternalProxyServers": [],
  "enterpriseProxyServersAreAuthoritative": false,
  "neutralDomainResources": [],
  "windowsHelloForBusinessBlocked": false,
  "pinMinimumLength": 4,
  "pinUppercaseLetters": "notAllow",
  "pinLowercaseLetters": "notAllow",
  "pinSpecialCharacters": "notAllow",
  "pinExpirationDays": 0,
  "numberOfPastPinsRemembered": 0,
  "passwordMaximumAttemptCount": 0,
  "minutesOfInactivityBeforeDeviceLock": 0,
  "mdmEnrollmentUrl": "https://enrollment.manage.microsoft.com/enrollmentserver/discovery.svc",
  "@odata.type": "#microsoft.graph.windowsInformationProtectionPolicy"
}
"@

####################################################




####################################################
#Compliance policies
####################################################

$BaselineWin10 = @"

{
    "@odata.type":  "#microsoft.graph.windows10CompliancePolicy",
    "description":  "Minimum OS: 1903",
    "displayName":  "Windows 10 Baseline",
    "passwordRequired":  true,
    "passwordBlockSimple":  true,
    "passwordRequiredToUnlockFromIdle":  false,
    "passwordMinutesOfInactivityBeforeLock":  15,
    "passwordExpirationDays":  null,
    "passwordMinimumLength":  8,
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
    "storageRequireEncryption":  true,
    "activeFirewallRequired":  true,
    "defenderEnabled":  false,
    "defenderVersion":  null,
    "signatureOutOfDate":  false,
    "rtpEnabled":  false,
    "antivirusRequired":  true,
    "antiSpywareRequired":  true,
    "deviceThreatProtectionEnabled":  false,
    "deviceThreatProtectionRequiredSecurityLevel":  "unavailable",
    "configurationManagerComplianceRequired":  false,
    "tpmRequired":  true,
    "validOperatingSystemBuildRanges":  [

                                        ],
"scheduledActionsForRule":[{"ruleName":"PasswordRequired","scheduledActionConfigurations":[{"actionType":"block","gracePeriodHours":72,"notificationTemplateId":"","notificationMessageCCList":[]}]}]
}


"@

####################################################





####################################################
#Device configuration profiles
####################################################
####################################################

$Win10BASICDR = @"

{
    "@odata.type":  "#microsoft.graph.windows10GeneralConfiguration",
    "deviceManagementApplicabilityRuleOsEdition":  null,
    "deviceManagementApplicabilityRuleOsVersion":  null,
    "deviceManagementApplicabilityRuleDeviceMode":  null,
    "description":  "Basic security profile for Windows 10 that is also BYOD friendly.",
    "displayName":  "Windows 10 - Standard Device Security",
    "taskManagerBlockEndTask":  false,
    "energySaverOnBatteryThresholdPercentage":  0,
    "energySaverPluggedInThresholdPercentage":  0,
    "powerLidCloseActionOnBattery":  "notConfigured",
    "powerLidCloseActionPluggedIn":  "notConfigured",
    "powerButtonActionOnBattery":  "notConfigured",
    "powerButtonActionPluggedIn":  "notConfigured",
    "powerSleepButtonActionOnBattery":  "notConfigured",
    "powerSleepButtonActionPluggedIn":  "notConfigured",
    "powerHybridSleepOnBattery":  "enabled",
    "powerHybridSleepPluggedIn":  "enabled",
    "windows10AppsForceUpdateSchedule":  null,
    "enableAutomaticRedeployment":  false,
    "microsoftAccountSignInAssistantSettings":  "notConfigured",
    "authenticationAllowSecondaryDevice":  true,
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
    "securityBlockAzureADJoinedDevicesAutoEncryption":  false,
    "diagnosticsDataSubmissionMode":  "none",
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
    "defenderBlockEndUserAccess":  false,
    "defenderDaysBeforeDeletingQuarantinedMalware":  5,
    "defenderSystemScanSchedule":  "userDefined",
    "defenderFilesAndFoldersToExclude":  [

                                         ],
    "defenderFileExtensionsToExclude":  [

                                        ],
    "defenderScanMaxCpu":  50,
    "defenderMonitorFileActivity":  "monitorIncomingFilesOnly",
    "defenderPotentiallyUnwantedAppAction":  "audit",
    "defenderPotentiallyUnwantedAppActionSetting":  "auditMode",
    "defenderProcessesToExclude":  [

                                   ],
    "defenderPromptForSampleSubmission":  "promptBeforeSendingPersonalData",
    "defenderRequireBehaviorMonitoring":  true,
    "defenderRequireCloudProtection":  true,
    "defenderRequireNetworkInspectionSystem":  true,
    "defenderRequireRealTimeMonitoring":  true,
    "defenderScanArchiveFiles":  true,
    "defenderScanDownloads":  true,
    "defenderScheduleScanEnableLowCpuPriority":  false,
    "defenderDisableCatchupQuickScan":  false,
    "defenderDisableCatchupFullScan":  false,
    "defenderScanNetworkFiles":  true,
    "defenderScanIncomingMail":  true,
    "defenderScanMappedNetworkDrivesDuringFullScan":  false,
    "defenderScanRemovableDrivesDuringFullScan":  true,
    "defenderScanScriptsLoadedInInternetExplorer":  true,
    "defenderSignatureUpdateIntervalInHours":  2,
    "defenderScanType":  "userDefined",
    "defenderScheduledScanTime":  null,
    "defenderScheduledQuickScanTime":  null,
    "defenderCloudBlockLevel":  "notConfigured",
    "defenderCloudExtendedTimeout":  null,
    "defenderCloudExtendedTimeoutInSeconds":  null,
    "defenderBlockOnAccessProtection":  false,
    "defenderSubmitSamplesConsentType":  "sendSafeSamplesAutomatically",
    "lockScreenAllowTimeoutConfiguration":  false,
    "lockScreenBlockActionCenterNotifications":  false,
    "lockScreenBlockCortana":  false,
    "lockScreenBlockToastNotifications":  false,
    "lockScreenTimeoutInSeconds":  null,
    "lockScreenActivateAppsWithVoice":  "notConfigured",
    "passwordBlockSimple":  true,
    "passwordExpirationDays":  null,
    "passwordMinimumLength":  8,
    "passwordMinutesOfInactivityBeforeScreenTimeout":  15,
    "passwordMinimumCharacterSetCount":  3,
    "passwordPreviousPasswordBlockCount":  null,
    "passwordRequired":  true,
    "passwordRequireWhenResumeFromIdleState":  false,
    "passwordRequiredType":  "alphanumeric",
    "passwordSignInFailureCountBeforeFactoryReset":  10,
    "passwordMinimumAgeInDays":  null,
    "privacyAdvertisingId":  "notConfigured",
    "privacyAutoAcceptPairingAndConsentPrompts":  false,
    "privacyDisableLaunchExperience":  false,
    "privacyBlockInputPersonalization":  false,
    "privacyBlockPublishUserActivities":  false,
    "privacyBlockActivityFeed":  false,
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
    "accountsBlockAddingNonMicrosoftAccountEmail":  false,
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
    "edgeRequireSmartScreen":  true,
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
    "developerUnlockSetting":  "notConfigured",
    "sharedUserAppDataAllowed":  false,
    "appsBlockWindowsStoreOriginatedApps":  false,
    "windowsStoreEnablePrivateStoreOnly":  false,
    "storageRestrictAppDataToSystemVolume":  false,
    "storageRestrictAppInstallToSystemVolume":  false,
    "gameDvrBlocked":  false,
    "experienceBlockDeviceDiscovery":  false,
    "experienceBlockErrorDialogWhenNoSIM":  false,
    "experienceBlockTaskSwitcher":  false,
    "logonBlockFastUserSwitching":  false,
    "tenantLockdownRequireNetworkDuringOutOfBoxExperience":  false,
    "appManagementMSIAllowUserControlOverInstall":  false,
    "appManagementMSIAlwaysInstallWithElevatedPrivileges":  false,
    "dataProtectionBlockDirectMemoryAccess":  false,
    "appManagementPackageFamilyNamesToLaunchAfterLogOn":  [

                                                          ],
    "uninstallBuiltInApps":  false,
    "defenderDetectedMalwareActions":  {
                                           "lowSeverity":  "clean",
                                           "moderateSeverity":  "quarantine",
                                           "highSeverity":  "remove",
                                           "severeSeverity":  "block"
                                       }
}


"@

####################################################

$Win10BASICEP = @"

{
    "@odata.type":  "#microsoft.graph.windows10EndpointProtectionConfiguration",
    "deviceManagementApplicabilityRuleOsEdition":  null,
    "deviceManagementApplicabilityRuleOsVersion":  null,
    "deviceManagementApplicabilityRuleDeviceMode":  null,
    "description":  "Basic security profile for Windows 10 that is also BYOD friendly.",
    "displayName":  "Windows 10 - Standard Endpoint Protection",
    "dmaGuardDeviceEnumerationPolicy":  "deviceDefault",
    "xboxServicesEnableXboxGameSaveTask":  false,
    "xboxServicesAccessoryManagementServiceStartupMode":  "manual",
    "xboxServicesLiveAuthManagerServiceStartupMode":  "manual",
    "xboxServicesLiveGameSaveServiceStartupMode":  "manual",
    "xboxServicesLiveNetworkingServiceStartupMode":  "manual",
    "localSecurityOptionsBlockMicrosoftAccounts":  false,
    "localSecurityOptionsBlockRemoteLogonWithBlankPassword":  false,
    "localSecurityOptionsDisableAdministratorAccount":  false,
    "localSecurityOptionsAdministratorAccountName":  null,
    "localSecurityOptionsDisableGuestAccount":  false,
    "localSecurityOptionsGuestAccountName":  null,
    "localSecurityOptionsAllowUndockWithoutHavingToLogon":  false,
    "localSecurityOptionsBlockUsersInstallingPrinterDrivers":  false,
    "localSecurityOptionsBlockRemoteOpticalDriveAccess":  false,
    "localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUser":  "notConfigured",
    "localSecurityOptionsMachineInactivityLimit":  15,
    "localSecurityOptionsMachineInactivityLimitInMinutes":  15,
    "localSecurityOptionsDoNotRequireCtrlAltDel":  false,
    "localSecurityOptionsHideLastSignedInUser":  false,
    "localSecurityOptionsHideUsernameAtSignIn":  false,
    "localSecurityOptionsLogOnMessageTitle":  null,
    "localSecurityOptionsLogOnMessageText":  null,
    "localSecurityOptionsAllowPKU2UAuthenticationRequests":  false,
    "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManagerHelperBool":  false,
    "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManager":  null,
    "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedClients":  "none",
    "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedServers":  "none",
    "lanManagerAuthenticationLevel":  "lmAndNltm",
    "lanManagerWorkstationDisableInsecureGuestLogons":  false,
    "localSecurityOptionsClearVirtualMemoryPageFile":  false,
    "localSecurityOptionsAllowSystemToBeShutDownWithoutHavingToLogOn":  false,
    "localSecurityOptionsAllowUIAccessApplicationElevation":  false,
    "localSecurityOptionsVirtualizeFileAndRegistryWriteFailuresToPerUserLocations":  false,
    "localSecurityOptionsOnlyElevateSignedExecutables":  false,
    "localSecurityOptionsAdministratorElevationPromptBehavior":  "promptForConsentOnTheSecureDesktop",
    "localSecurityOptionsStandardUserElevationPromptBehavior":  "promptForCredentialsOnTheSecureDesktop",
    "localSecurityOptionsSwitchToSecureDesktopWhenPromptingForElevation":  false,
    "localSecurityOptionsDetectApplicationInstallationsAndPromptForElevation":  true,
    "localSecurityOptionsAllowUIAccessApplicationsForSecureLocations":  false,
    "localSecurityOptionsUseAdminApprovalMode":  true,
    "localSecurityOptionsUseAdminApprovalModeForAdministrators":  true,
    "localSecurityOptionsInformationShownOnLockScreen":  "notConfigured",
    "localSecurityOptionsInformationDisplayedOnLockScreen":  "notConfigured",
    "localSecurityOptionsDisableClientDigitallySignCommunicationsIfServerAgrees":  false,
    "localSecurityOptionsClientDigitallySignCommunicationsAlways":  false,
    "localSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers":  false,
    "localSecurityOptionsDisableServerDigitallySignCommunicationsAlways":  false,
    "localSecurityOptionsDisableServerDigitallySignCommunicationsIfClientAgrees":  false,
    "localSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares":  false,
    "localSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts":  false,
    "localSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares":  false,
    "localSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange":  false,
    "localSecurityOptionsSmartCardRemovalBehavior":  "lockWorkstation",
    "defenderSecurityCenterDisableAppBrowserUI":  false,
    "defenderSecurityCenterDisableFamilyUI":  false,
    "defenderSecurityCenterDisableHealthUI":  false,
    "defenderSecurityCenterDisableNetworkUI":  false,
    "defenderSecurityCenterDisableVirusUI":  false,
    "defenderSecurityCenterDisableAccountUI":  false,
    "defenderSecurityCenterDisableClearTpmUI":  false,
    "defenderSecurityCenterDisableHardwareUI":  false,
    "defenderSecurityCenterDisableNotificationAreaUI":  false,
    "defenderSecurityCenterDisableRansomwareUI":  false,
    "defenderSecurityCenterDisableSecureBootUI":  false,
    "defenderSecurityCenterDisableTroubleshootingUI":  false,
    "defenderSecurityCenterDisableVulnerableTpmFirmwareUpdateUI":  false,
    "defenderSecurityCenterOrganizationDisplayName":  null,
    "defenderSecurityCenterHelpEmail":  null,
    "defenderSecurityCenterHelpPhone":  null,
    "defenderSecurityCenterHelpURL":  null,
    "defenderSecurityCenterNotificationsFromApp":  "notConfigured",
    "defenderSecurityCenterITContactDisplay":  "notConfigured",
    "windowsDefenderTamperProtection":  "notConfigured",
    "firewallBlockStatefulFTP":  false,
    "firewallIdleTimeoutForSecurityAssociationInSeconds":  null,
    "firewallPreSharedKeyEncodingMethod":  "deviceDefault",
    "firewallIPSecExemptionsAllowNeighborDiscovery":  false,
    "firewallIPSecExemptionsAllowICMP":  false,
    "firewallIPSecExemptionsAllowRouterDiscovery":  false,
    "firewallIPSecExemptionsAllowDHCP":  false,
    "firewallCertificateRevocationListCheckMethod":  "deviceDefault",
    "firewallMergeKeyingModuleSettings":  false,
    "firewallPacketQueueingMethod":  "deviceDefault",
    "defenderAdobeReaderLaunchChildProcess":  "auditMode",
    "defenderAttackSurfaceReductionExcludedPaths":  [

                                                    ],
    "defenderOfficeAppsOtherProcessInjectionType":  "auditMode",
    "defenderOfficeAppsOtherProcessInjection":  "auditMode",
    "defenderOfficeCommunicationAppsLaunchChildProcess":  "auditMode",
    "defenderOfficeAppsExecutableContentCreationOrLaunchType":  "auditMode",
    "defenderOfficeAppsExecutableContentCreationOrLaunch":  "auditMode",
    "defenderOfficeAppsLaunchChildProcessType":  "auditMode",
    "defenderOfficeAppsLaunchChildProcess":  "auditMode",
    "defenderOfficeMacroCodeAllowWin32ImportsType":  "auditMode",
    "defenderOfficeMacroCodeAllowWin32Imports":  "auditMode",
    "defenderScriptObfuscatedMacroCodeType":  "auditMode",
    "defenderScriptObfuscatedMacroCode":  "auditMode",
    "defenderScriptDownloadedPayloadExecutionType":  "auditMode",
    "defenderScriptDownloadedPayloadExecution":  "auditMode",
    "defenderPreventCredentialStealingType":  "auditMode",
    "defenderProcessCreationType":  "auditMode",
    "defenderProcessCreation":  "auditMode",
    "defenderUntrustedUSBProcessType":  "auditMode",
    "defenderUntrustedUSBProcess":  "auditMode",
    "defenderUntrustedExecutableType":  "auditMode",
    "defenderUntrustedExecutable":  "auditMode",
    "defenderEmailContentExecutionType":  "auditMode",
    "defenderEmailContentExecution":  "auditMode",
    "defenderAdvancedRansomewareProtectionType":  "auditMode",
    "defenderGuardMyFoldersType":  "auditMode",
    "defenderGuardedFoldersAllowedAppPaths":  [

                                              ],
    "defenderAdditionalGuardedFolders":  [

                                         ],
    "defenderNetworkProtectionType":  "enable",
    "defenderExploitProtectionXml":  null,
    "defenderExploitProtectionXmlFileName":  null,
    "defenderSecurityCenterBlockExploitProtectionOverride":  false,
    "appLockerApplicationControl":  "notConfigured",
    "deviceGuardLocalSystemAuthorityCredentialGuardSettings":  "notConfigured",
    "deviceGuardEnableVirtualizationBasedSecurity":  false,
    "deviceGuardEnableSecureBootWithDMA":  false,
    "deviceGuardSecureBootWithDMA":  "notConfigured",
    "deviceGuardLaunchSystemGuard":  "notConfigured",
    "smartScreenEnableInShell":  true,
    "smartScreenBlockOverrideForFiles":  false,
    "applicationGuardEnabled":  false,
    "applicationGuardEnabledOptions":  "notConfigured",
    "applicationGuardBlockFileTransfer":  "notConfigured",
    "applicationGuardBlockNonEnterpriseContent":  false,
    "applicationGuardAllowPersistence":  false,
    "applicationGuardForceAuditing":  false,
    "applicationGuardBlockClipboardSharing":  "notConfigured",
    "applicationGuardAllowPrintToPDF":  false,
    "applicationGuardAllowPrintToXPS":  false,
    "applicationGuardAllowPrintToLocalPrinters":  false,
    "applicationGuardAllowPrintToNetworkPrinters":  false,
    "applicationGuardAllowVirtualGPU":  false,
    "applicationGuardAllowFileSaveOnHost":  false,
    "bitLockerAllowStandardUserEncryption":  true,
    "bitLockerDisableWarningForOtherDiskEncryption":  true,
    "bitLockerEnableStorageCardEncryptionOnMobile":  false,
    "bitLockerEncryptDevice":  true,
    "bitLockerRecoveryPasswordRotation":  "notConfigured",
    "defenderDisableScanArchiveFiles":  false,
    "defenderDisableBehaviorMonitoring":  false,
    "defenderDisableCloudProtection":  false,
    "defenderEnableScanIncomingMail":  false,
    "defenderEnableScanMappedNetworkDrivesDuringFullScan":  false,
    "defenderDisableScanRemovableDrivesDuringFullScan":  false,
    "defenderDisableScanDownloads":  false,
    "defenderDisableIntrusionPreventionSystem":  false,
    "defenderDisableOnAccessProtection":  false,
    "defenderDisableRealTimeMonitoring":  false,
    "defenderDisableScanNetworkFiles":  false,
    "defenderDisableScanScriptsLoadedInInternetExplorer":  false,
    "defenderBlockEndUserAccess":  false,
    "defenderScanMaxCpuPercentage":  null,
    "defenderCheckForSignaturesBeforeRunningScan":  false,
    "defenderCloudBlockLevel":  "notConfigured",
    "defenderCloudExtendedTimeoutInSeconds":  null,
    "defenderDaysBeforeDeletingQuarantinedMalware":  null,
    "defenderDisableCatchupFullScan":  false,
    "defenderDisableCatchupQuickScan":  false,
    "defenderEnableLowCpuPriority":  false,
    "defenderFileExtensionsToExclude":  [

                                        ],
    "defenderFilesAndFoldersToExclude":  [

                                         ],
    "defenderProcessesToExclude":  [

                                   ],
    "defenderPotentiallyUnwantedAppAction":  "userDefined",
    "defenderScanDirection":  "monitorAllFiles",
    "defenderScanType":  "userDefined",
    "defenderScheduledQuickScanTime":  null,
    "defenderScheduledScanDay":  "userDefined",
    "defenderScheduledScanTime":  null,
    "defenderSubmitSamplesConsentType":  "sendSafeSamplesAutomatically",
    "defenderDetectedMalwareActions":  null,
    "firewallRules":  [

                      ],
    "userRightsAccessCredentialManagerAsTrustedCaller":  {
                                                             "state":  "notConfigured",
                                                             "localUsersOrGroups":  [

                                                                                    ]
                                                         },
    "userRightsAllowAccessFromNetwork":  {
                                             "state":  "notConfigured",
                                             "localUsersOrGroups":  [

                                                                    ]
                                         },
    "userRightsBlockAccessFromNetwork":  {
                                             "state":  "notConfigured",
                                             "localUsersOrGroups":  [

                                                                    ]
                                         },
    "userRightsActAsPartOfTheOperatingSystem":  {
                                                    "state":  "notConfigured",
                                                    "localUsersOrGroups":  [

                                                                           ]
                                                },
    "userRightsLocalLogOn":  {
                                 "state":  "notConfigured",
                                 "localUsersOrGroups":  [

                                                        ]
                             },
    "userRightsDenyLocalLogOn":  {
                                     "state":  "notConfigured",
                                     "localUsersOrGroups":  [

                                                            ]
                                 },
    "userRightsBackupData":  {
                                 "state":  "notConfigured",
                                 "localUsersOrGroups":  [

                                                        ]
                             },
    "userRightsChangeSystemTime":  {
                                       "state":  "notConfigured",
                                       "localUsersOrGroups":  [

                                                              ]
                                   },
    "userRightsCreateGlobalObjects":  {
                                          "state":  "notConfigured",
                                          "localUsersOrGroups":  [

                                                                 ]
                                      },
    "userRightsCreatePageFile":  {
                                     "state":  "notConfigured",
                                     "localUsersOrGroups":  [

                                                            ]
                                 },
    "userRightsCreatePermanentSharedObjects":  {
                                                   "state":  "notConfigured",
                                                   "localUsersOrGroups":  [

                                                                          ]
                                               },
    "userRightsCreateSymbolicLinks":  {
                                          "state":  "notConfigured",
                                          "localUsersOrGroups":  [

                                                                 ]
                                      },
    "userRightsCreateToken":  {
                                  "state":  "notConfigured",
                                  "localUsersOrGroups":  [

                                                         ]
                              },
    "userRightsDebugPrograms":  {
                                    "state":  "notConfigured",
                                    "localUsersOrGroups":  [

                                                           ]
                                },
    "userRightsRemoteDesktopServicesLogOn":  {
                                                 "state":  "notConfigured",
                                                 "localUsersOrGroups":  [

                                                                        ]
                                             },
    "userRightsDelegation":  {
                                 "state":  "notConfigured",
                                 "localUsersOrGroups":  [

                                                        ]
                             },
    "userRightsGenerateSecurityAudits":  {
                                             "state":  "notConfigured",
                                             "localUsersOrGroups":  [

                                                                    ]
                                         },
    "userRightsImpersonateClient":  {
                                        "state":  "notConfigured",
                                        "localUsersOrGroups":  [

                                                               ]
                                    },
    "userRightsIncreaseSchedulingPriority":  {
                                                 "state":  "notConfigured",
                                                 "localUsersOrGroups":  [

                                                                        ]
                                             },
    "userRightsLoadUnloadDrivers":  {
                                        "state":  "notConfigured",
                                        "localUsersOrGroups":  [

                                                               ]
                                    },
    "userRightsLockMemory":  {
                                 "state":  "notConfigured",
                                 "localUsersOrGroups":  [

                                                        ]
                             },
    "userRightsManageAuditingAndSecurityLogs":  {
                                                    "state":  "notConfigured",
                                                    "localUsersOrGroups":  [

                                                                           ]
                                                },
    "userRightsManageVolumes":  {
                                    "state":  "notConfigured",
                                    "localUsersOrGroups":  [

                                                           ]
                                },
    "userRightsModifyFirmwareEnvironment":  {
                                                "state":  "notConfigured",
                                                "localUsersOrGroups":  [

                                                                       ]
                                            },
    "userRightsModifyObjectLabels":  {
                                         "state":  "notConfigured",
                                         "localUsersOrGroups":  [

                                                                ]
                                     },
    "userRightsProfileSingleProcess":  {
                                           "state":  "notConfigured",
                                           "localUsersOrGroups":  [

                                                                  ]
                                       },
    "userRightsRemoteShutdown":  {
                                     "state":  "notConfigured",
                                     "localUsersOrGroups":  [

                                                            ]
                                 },
    "userRightsRestoreData":  {
                                  "state":  "notConfigured",
                                  "localUsersOrGroups":  [

                                                         ]
                              },
    "userRightsTakeOwnership":  {
                                    "state":  "notConfigured",
                                    "localUsersOrGroups":  [

                                                           ]
                                },
    "firewallProfileDomain":  {
                                  "firewallEnabled":  "allowed",
                                  "stealthModeRequired":  false,
                                  "stealthModeBlocked":  false,
                                  "incomingTrafficRequired":  false,
                                  "incomingTrafficBlocked":  false,
                                  "unicastResponsesToMulticastBroadcastsRequired":  false,
                                  "unicastResponsesToMulticastBroadcastsBlocked":  false,
                                  "inboundNotificationsRequired":  false,
                                  "inboundNotificationsBlocked":  false,
                                  "authorizedApplicationRulesFromGroupPolicyMerged":  false,
                                  "authorizedApplicationRulesFromGroupPolicyNotMerged":  false,
                                  "globalPortRulesFromGroupPolicyMerged":  false,
                                  "globalPortRulesFromGroupPolicyNotMerged":  false,
                                  "connectionSecurityRulesFromGroupPolicyMerged":  false,
                                  "connectionSecurityRulesFromGroupPolicyNotMerged":  false,
                                  "outboundConnectionsRequired":  false,
                                  "outboundConnectionsBlocked":  false,
                                  "inboundConnectionsRequired":  false,
                                  "inboundConnectionsBlocked":  true,
                                  "securedPacketExemptionAllowed":  false,
                                  "securedPacketExemptionBlocked":  false,
                                  "policyRulesFromGroupPolicyMerged":  false,
                                  "policyRulesFromGroupPolicyNotMerged":  false
                              },
    "firewallProfilePublic":  {
                                  "firewallEnabled":  "allowed",
                                  "stealthModeRequired":  false,
                                  "stealthModeBlocked":  false,
                                  "incomingTrafficRequired":  false,
                                  "incomingTrafficBlocked":  false,
                                  "unicastResponsesToMulticastBroadcastsRequired":  false,
                                  "unicastResponsesToMulticastBroadcastsBlocked":  false,
                                  "inboundNotificationsRequired":  false,
                                  "inboundNotificationsBlocked":  false,
                                  "authorizedApplicationRulesFromGroupPolicyMerged":  false,
                                  "authorizedApplicationRulesFromGroupPolicyNotMerged":  false,
                                  "globalPortRulesFromGroupPolicyMerged":  false,
                                  "globalPortRulesFromGroupPolicyNotMerged":  false,
                                  "connectionSecurityRulesFromGroupPolicyMerged":  false,
                                  "connectionSecurityRulesFromGroupPolicyNotMerged":  false,
                                  "outboundConnectionsRequired":  false,
                                  "outboundConnectionsBlocked":  false,
                                  "inboundConnectionsRequired":  false,
                                  "inboundConnectionsBlocked":  true,
                                  "securedPacketExemptionAllowed":  false,
                                  "securedPacketExemptionBlocked":  false,
                                  "policyRulesFromGroupPolicyMerged":  false,
                                  "policyRulesFromGroupPolicyNotMerged":  false
                              },
    "firewallProfilePrivate":  {
                                   "firewallEnabled":  "allowed",
                                   "stealthModeRequired":  false,
                                   "stealthModeBlocked":  false,
                                   "incomingTrafficRequired":  false,
                                   "incomingTrafficBlocked":  false,
                                   "unicastResponsesToMulticastBroadcastsRequired":  false,
                                   "unicastResponsesToMulticastBroadcastsBlocked":  false,
                                   "inboundNotificationsRequired":  false,
                                   "inboundNotificationsBlocked":  false,
                                   "authorizedApplicationRulesFromGroupPolicyMerged":  false,
                                   "authorizedApplicationRulesFromGroupPolicyNotMerged":  false,
                                   "globalPortRulesFromGroupPolicyMerged":  false,
                                   "globalPortRulesFromGroupPolicyNotMerged":  false,
                                   "connectionSecurityRulesFromGroupPolicyMerged":  false,
                                   "connectionSecurityRulesFromGroupPolicyNotMerged":  false,
                                   "outboundConnectionsRequired":  false,
                                   "outboundConnectionsBlocked":  false,
                                   "inboundConnectionsRequired":  false,
                                   "inboundConnectionsBlocked":  true,
                                   "securedPacketExemptionAllowed":  false,
                                   "securedPacketExemptionBlocked":  false,
                                   "policyRulesFromGroupPolicyMerged":  false,
                                   "policyRulesFromGroupPolicyNotMerged":  false
                               },
    "bitLockerSystemDrivePolicy":  {
                                       "encryptionMethod":  null,
                                       "startupAuthenticationRequired":  true,
                                       "startupAuthenticationBlockWithoutTpmChip":  false,
                                       "startupAuthenticationTpmUsage":  "allowed",
                                       "startupAuthenticationTpmPinUsage":  "allowed",
                                       "startupAuthenticationTpmKeyUsage":  "allowed",
                                       "startupAuthenticationTpmPinAndKeyUsage":  "allowed",
                                       "minimumPinLength":  null,
                                       "prebootRecoveryEnableMessageAndUrl":  false,
                                       "prebootRecoveryMessage":  null,
                                       "prebootRecoveryUrl":  null,
                                       "recoveryOptions":  {
                                                               "blockDataRecoveryAgent":  false,
                                                               "recoveryPasswordUsage":  "allowed",
                                                               "recoveryKeyUsage":  "allowed",
                                                               "hideRecoveryOptions":  true,
                                                               "enableRecoveryInformationSaveToStore":  true,
                                                               "recoveryInformationToStore":  "passwordAndKey",
                                                               "enableBitLockerAfterRecoveryInformationToStore":  true
                                                           }
                                   },
    "bitLockerFixedDrivePolicy":  {
                                      "encryptionMethod":  null,
                                      "requireEncryptionForWriteAccess":  false,
                                      "recoveryOptions":  {
                                                              "blockDataRecoveryAgent":  false,
                                                              "recoveryPasswordUsage":  "allowed",
                                                              "recoveryKeyUsage":  "allowed",
                                                              "hideRecoveryOptions":  true,
                                                              "enableRecoveryInformationSaveToStore":  true,
                                                              "recoveryInformationToStore":  "passwordAndKey",
                                                              "enableBitLockerAfterRecoveryInformationToStore":  true
                                                          }
                                  },
    "bitLockerRemovableDrivePolicy":  {
                                          "encryptionMethod":  null,
                                          "requireEncryptionForWriteAccess":  false,
                                          "blockCrossOrganizationWriteAccess":  false
                                      }
}


"@

####################################################

$Win10DR = @"
{
    "@odata.type":  "#microsoft.graph.windows10GeneralConfiguration",
    "deviceManagementApplicabilityRuleOsEdition":  null,
    "deviceManagementApplicabilityRuleOsVersion":  null,
    "deviceManagementApplicabilityRuleDeviceMode":  null,
    "description":  "Enhanced security profile for Windows 10 that is approriate for corporate environments.",
    "displayName":  "Windows 10 - Enhanced Security Device Restrictions",
    "taskManagerBlockEndTask":  false,
    "energySaverOnBatteryThresholdPercentage":  null,
    "energySaverPluggedInThresholdPercentage":  null,
    "powerLidCloseActionOnBattery":  "notConfigured",
    "powerLidCloseActionPluggedIn":  "notConfigured",
    "powerButtonActionOnBattery":  "notConfigured",
    "powerButtonActionPluggedIn":  "notConfigured",
    "powerSleepButtonActionOnBattery":  "notConfigured",
    "powerSleepButtonActionPluggedIn":  "notConfigured",
    "powerHybridSleepOnBattery":  "enabled",
    "powerHybridSleepPluggedIn":  "enabled",
    "enableAutomaticRedeployment":  true,
    "microsoftAccountSignInAssistantSettings":  "notConfigured",
    "authenticationAllowSecondaryDevice":  true,
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
    "searchDisableIndexingEncryptedItems":  true,
    "searchEnableRemoteQueries":  false,
    "searchDisableUseLocation":  false,
    "searchDisableLocation":  false,
    "searchDisableIndexerBackoff":  false,
    "searchDisableIndexingRemovableDrive":  true,
    "searchEnableAutomaticIndexSizeManangement":  false,
    "searchBlockWebResults":  false,
    "findMyFiles":  "notConfigured",
    "securityBlockAzureADJoinedDevicesAutoEncryption":  false,
    "diagnosticsDataSubmissionMode":  "none",
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
    "edgeBlockPasswordManager":  true,
    "edgeBlockAddressBarDropdown":  false,
    "edgeBlockCompatibilityList":  false,
    "edgeClearBrowsingDataOnExit":  false,
    "edgeAllowStartPagesModification":  false,
    "edgeDisableFirstRunPage":  true,
    "edgeBlockLiveTileDataCollection":  true,
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
    "edgePreventCertificateErrorOverride":  true,
    "edgeKioskModeRestriction":  "notConfigured",
    "edgeKioskResetAfterIdleTimeInMinutes":  null,
    "cellularBlockDataWhenRoaming":  false,
    "cellularBlockVpn":  false,
    "cellularBlockVpnWhenRoaming":  false,
    "cellularData":  "allowed",
    "defenderRequireRealTimeMonitoring":  true,
    "defenderRequireBehaviorMonitoring":  true,
    "defenderRequireNetworkInspectionSystem":  true,
    "defenderScanDownloads":  true,
    "defenderScheduleScanEnableLowCpuPriority":  false,
    "defenderDisableCatchupQuickScan":  false,
    "defenderDisableCatchupFullScan":  false,
    "defenderScanScriptsLoadedInInternetExplorer":  true,
    "defenderBlockEndUserAccess":  false,
    "defenderSignatureUpdateIntervalInHours":  2,
    "defenderMonitorFileActivity":  "monitorAllFiles",
    "defenderDaysBeforeDeletingQuarantinedMalware":  5,
    "defenderScanMaxCpu":  50,
    "defenderScanArchiveFiles":  true,
    "defenderScanIncomingMail":  true,
    "defenderScanRemovableDrivesDuringFullScan":  true,
    "defenderScanMappedNetworkDrivesDuringFullScan":  false,
    "defenderScanNetworkFiles":  true,
    "defenderRequireCloudProtection":  true,
    "defenderCloudBlockLevel":  "notConfigured",
    "defenderCloudExtendedTimeout":  null,
    "defenderCloudExtendedTimeoutInSeconds":  null,
    "defenderPromptForSampleSubmission":  "promptBeforeSendingPersonalData",
    "defenderScheduledQuickScanTime":  null,
    "defenderScanType":  "userDefined",
    "defenderSystemScanSchedule":  "userDefined",
    "defenderScheduledScanTime":  "10:00:00.0000000",
    "defenderPotentiallyUnwantedAppAction":  "block",
    "defenderPotentiallyUnwantedAppActionSetting":  "userDefined",
    "defenderSubmitSamplesConsentType":  "sendSafeSamplesAutomatically",
    "defenderBlockOnAccessProtection":  false,
    "defenderFileExtensionsToExclude":  [

                                        ],
    "defenderFilesAndFoldersToExclude":  [

                                         ],
    "defenderProcessesToExclude":  [

                                   ],
    "lockScreenAllowTimeoutConfiguration":  false,
    "lockScreenBlockActionCenterNotifications":  false,
    "lockScreenBlockCortana":  true,
    "lockScreenBlockToastNotifications":  true,
    "lockScreenTimeoutInSeconds":  null,
    "lockScreenActivateAppsWithVoice":  "disabled",
    "passwordBlockSimple":  true,
    "passwordExpirationDays":  60,
    "passwordMinimumLength":  8,
    "passwordMinutesOfInactivityBeforeScreenTimeout":  15,
    "passwordMinimumCharacterSetCount":  3,
    "passwordPreviousPasswordBlockCount":  24,
    "passwordRequired":  true,
    "passwordRequireWhenResumeFromIdleState":  false,
    "passwordRequiredType":  "alphanumeric",
    "passwordSignInFailureCountBeforeFactoryReset":  10,
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
    "windowsSpotlightBlockConsumerSpecificFeatures":  true,
    "windowsSpotlightBlocked":  false,
    "windowsSpotlightBlockOnActionCenter":  false,
    "windowsSpotlightBlockTailoredExperiences":  false,
    "windowsSpotlightBlockThirdPartyNotifications":  true,
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
    "cortanaBlocked":  true,
    "deviceManagementBlockFactoryResetOnMobile":  false,
    "deviceManagementBlockManualUnenroll":  true,
    "safeSearchFilter":  "userDefined",
    "edgeBlockPopups":  true,
    "edgeBlockSearchSuggestions":  false,
    "edgeBlockSearchEngineCustomization":  false,
    "edgeBlockSendingIntranetTrafficToInternetExplorer":  false,
    "edgeSendIntranetTrafficToInternetExplorer":  false,
    "edgeRequireSmartScreen":  true,
    "edgeEnterpriseModeSiteListLocation":  null,
    "edgeFirstRunUrl":  null,
    "edgeHomepageUrls":  [

                         ],
    "edgeBlockAccessToAboutFlags":  false,
    "smartScreenBlockPromptOverride":  true,
    "smartScreenBlockPromptOverrideForFiles":  true,
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
    "microsoftAccountBlocked":  true,
    "microsoftAccountBlockSettingsSync":  false,
    "nfcBlocked":  false,
    "resetProtectionModeBlocked":  false,
    "screenCaptureBlocked":  false,
    "storageBlockRemovableStorage":  false,
    "storageRequireMobileDeviceEncryption":  false,
    "usbBlocked":  false,
    "voiceRecordingBlocked":  false,
    "wiFiBlockAutomaticConnectHotspots":  true,
    "wiFiBlocked":  false,
    "wiFiBlockManualConfiguration":  false,
    "wiFiScanInterval":  null,
    "wirelessDisplayBlockProjectionToThisDevice":  false,
    "wirelessDisplayBlockUserInputFromReceiver":  false,
    "wirelessDisplayRequirePinForPairing":  false,
    "windowsStoreBlocked":  false,
    "appsAllowTrustedAppsSideloading":  "notConfigured",
    "windowsStoreBlockAutoUpdate":  false,
    "developerUnlockSetting":  "notConfigured",
    "sharedUserAppDataAllowed":  false,
    "appsBlockWindowsStoreOriginatedApps":  false,
    "windowsStoreEnablePrivateStoreOnly":  false,
    "storageRestrictAppDataToSystemVolume":  false,
    "storageRestrictAppInstallToSystemVolume":  false,
    "gameDvrBlocked":  true,
    "experienceBlockDeviceDiscovery":  false,
    "experienceBlockErrorDialogWhenNoSIM":  false,
    "experienceBlockTaskSwitcher":  false,
    "logonBlockFastUserSwitching":  false,
    "tenantLockdownRequireNetworkDuringOutOfBoxExperience":  false,
    "appManagementMSIAllowUserControlOverInstall":  true,
    "appManagementMSIAlwaysInstallWithElevatedPrivileges":  true,
    "dataProtectionBlockDirectMemoryAccess":  true,
    "appManagementPackageFamilyNamesToLaunchAfterLogOn":  [

                                                          ],
    "uninstallBuiltInApps":  false,
    "configureTimeZone":  null,
    "windows10AppsForceUpdateSchedule":  {
                                             "startDateTime":  "0001-01-01T00:00:00Z",
                                             "recurrence":  "none",
                                             "runImmediatelyIfAfterStartDateTime":  false
                                         },
    "defenderDetectedMalwareActions":  {
                                           "lowSeverity":  "clean",
                                           "moderateSeverity":  "quarantine",
                                           "highSeverity":  "remove",
                                           "severeSeverity":  "block"
                                       },
    "edgeSearchEngine":  {
                             "@odata.type":  "#microsoft.graph.edgeSearchEngine",
                             "edgeSearchEngineType":  "default"
                         }
}

"@

####################################################

$Win10EP = @"
{
    "@odata.type":  "#microsoft.graph.windows10EndpointProtectionConfiguration",
    "deviceManagementApplicabilityRuleOsEdition":  null,
    "deviceManagementApplicabilityRuleOsVersion":  null,
    "deviceManagementApplicabilityRuleDeviceMode":  null,
    "description":  "Advanced security profile for Windows 10 that is appropriate for corporate-owned workstations.",
    "displayName":  "Windows 10 - Enhanced Security Endpoint Protection baseline",
    "dmaGuardDeviceEnumerationPolicy":  "deviceDefault",
    "xboxServicesEnableXboxGameSaveTask":  false,
    "xboxServicesAccessoryManagementServiceStartupMode":  "manual",
    "xboxServicesLiveAuthManagerServiceStartupMode":  "manual",
    "xboxServicesLiveGameSaveServiceStartupMode":  "manual",
    "xboxServicesLiveNetworkingServiceStartupMode":  "manual",
    "localSecurityOptionsBlockMicrosoftAccounts":  false,
    "localSecurityOptionsBlockRemoteLogonWithBlankPassword":  true,
    "localSecurityOptionsDisableAdministratorAccount":  true,
    "localSecurityOptionsAdministratorAccountName":  null,
    "localSecurityOptionsDisableGuestAccount":  true,
    "localSecurityOptionsGuestAccountName":  null,
    "localSecurityOptionsAllowUndockWithoutHavingToLogon":  false,
    "localSecurityOptionsBlockUsersInstallingPrinterDrivers":  false,
    "localSecurityOptionsBlockRemoteOpticalDriveAccess":  false,
    "localSecurityOptionsFormatAndEjectOfRemovableMediaAllowedUser":  "notConfigured",
    "localSecurityOptionsMachineInactivityLimit":  15,
    "localSecurityOptionsMachineInactivityLimitInMinutes":  15,
    "localSecurityOptionsDoNotRequireCtrlAltDel":  false,
    "localSecurityOptionsHideLastSignedInUser":  false,
    "localSecurityOptionsHideUsernameAtSignIn":  false,
    "localSecurityOptionsLogOnMessageTitle":  null,
    "localSecurityOptionsLogOnMessageText":  null,
    "localSecurityOptionsAllowPKU2UAuthenticationRequests":  false,
    "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManagerHelperBool":  false,
    "localSecurityOptionsAllowRemoteCallsToSecurityAccountsManager":  null,
    "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedClients":  "ntlmV2And128BitEncryption",
    "localSecurityOptionsMinimumSessionSecurityForNtlmSspBasedServers":  "ntlmV2And128BitEncryption",
    "lanManagerAuthenticationLevel":  "lmNtlmV2AndNotLmOrNtm",
    "lanManagerWorkstationDisableInsecureGuestLogons":  true,
    "localSecurityOptionsClearVirtualMemoryPageFile":  true,
    "localSecurityOptionsAllowSystemToBeShutDownWithoutHavingToLogOn":  false,
    "localSecurityOptionsAllowUIAccessApplicationElevation":  true,
    "localSecurityOptionsVirtualizeFileAndRegistryWriteFailuresToPerUserLocations":  true,
    "localSecurityOptionsOnlyElevateSignedExecutables":  true,
    "localSecurityOptionsAdministratorElevationPromptBehavior":  "promptForConsentOnTheSecureDesktop",
    "localSecurityOptionsStandardUserElevationPromptBehavior":  "promptForCredentialsOnTheSecureDesktop",
    "localSecurityOptionsSwitchToSecureDesktopWhenPromptingForElevation":  false,
    "localSecurityOptionsDetectApplicationInstallationsAndPromptForElevation":  true,
    "localSecurityOptionsAllowUIAccessApplicationsForSecureLocations":  false,
    "localSecurityOptionsUseAdminApprovalMode":  true,
    "localSecurityOptionsUseAdminApprovalModeForAdministrators":  true,
    "localSecurityOptionsInformationShownOnLockScreen":  "notConfigured",
    "localSecurityOptionsInformationDisplayedOnLockScreen":  "notConfigured",
    "localSecurityOptionsDisableClientDigitallySignCommunicationsIfServerAgrees":  true,
    "localSecurityOptionsClientDigitallySignCommunicationsAlways":  true,
    "localSecurityOptionsClientSendUnencryptedPasswordToThirdPartySMBServers":  true,
    "localSecurityOptionsDisableServerDigitallySignCommunicationsAlways":  true,
    "localSecurityOptionsDisableServerDigitallySignCommunicationsIfClientAgrees":  true,
    "localSecurityOptionsRestrictAnonymousAccessToNamedPipesAndShares":  true,
    "localSecurityOptionsDoNotAllowAnonymousEnumerationOfSAMAccounts":  true,
    "localSecurityOptionsAllowAnonymousEnumerationOfSAMAccountsAndShares":  true,
    "localSecurityOptionsDoNotStoreLANManagerHashValueOnNextPasswordChange":  true,
    "localSecurityOptionsSmartCardRemovalBehavior":  "lockWorkstation",
    "defenderSecurityCenterDisableAppBrowserUI":  false,
    "defenderSecurityCenterDisableFamilyUI":  false,
    "defenderSecurityCenterDisableHealthUI":  false,
    "defenderSecurityCenterDisableNetworkUI":  false,
    "defenderSecurityCenterDisableVirusUI":  false,
    "defenderSecurityCenterDisableAccountUI":  false,
    "defenderSecurityCenterDisableClearTpmUI":  false,
    "defenderSecurityCenterDisableHardwareUI":  false,
    "defenderSecurityCenterDisableNotificationAreaUI":  false,
    "defenderSecurityCenterDisableRansomwareUI":  false,
    "defenderSecurityCenterDisableSecureBootUI":  false,
    "defenderSecurityCenterDisableTroubleshootingUI":  false,
    "defenderSecurityCenterDisableVulnerableTpmFirmwareUpdateUI":  false,
    "defenderSecurityCenterOrganizationDisplayName":  null,
    "defenderSecurityCenterHelpEmail":  null,
    "defenderSecurityCenterHelpPhone":  null,
    "defenderSecurityCenterHelpURL":  null,
    "defenderSecurityCenterNotificationsFromApp":  "notConfigured",
    "defenderSecurityCenterITContactDisplay":  "notConfigured",
    "windowsDefenderTamperProtection":  "notConfigured",
    "firewallBlockStatefulFTP":  false,
    "firewallIdleTimeoutForSecurityAssociationInSeconds":  null,
    "firewallPreSharedKeyEncodingMethod":  "deviceDefault",
    "firewallIPSecExemptionsAllowNeighborDiscovery":  false,
    "firewallIPSecExemptionsAllowICMP":  false,
    "firewallIPSecExemptionsAllowRouterDiscovery":  false,
    "firewallIPSecExemptionsAllowDHCP":  false,
    "firewallCertificateRevocationListCheckMethod":  "deviceDefault",
    "firewallMergeKeyingModuleSettings":  false,
    "firewallPacketQueueingMethod":  "deviceDefault",
    "defenderAdobeReaderLaunchChildProcess":  "enable",
    "defenderAttackSurfaceReductionExcludedPaths":  [

                                                    ],
    "defenderOfficeAppsOtherProcessInjectionType":  "block",
    "defenderOfficeAppsOtherProcessInjection":  "enable",
    "defenderOfficeCommunicationAppsLaunchChildProcess":  "enable",
    "defenderOfficeAppsExecutableContentCreationOrLaunchType":  "block",
    "defenderOfficeAppsExecutableContentCreationOrLaunch":  "enable",
    "defenderOfficeAppsLaunchChildProcessType":  "block",
    "defenderOfficeAppsLaunchChildProcess":  "enable",
    "defenderOfficeMacroCodeAllowWin32ImportsType":  "block",
    "defenderOfficeMacroCodeAllowWin32Imports":  "enable",
    "defenderScriptObfuscatedMacroCodeType":  "block",
    "defenderScriptObfuscatedMacroCode":  "enable",
    "defenderScriptDownloadedPayloadExecutionType":  "block",
    "defenderScriptDownloadedPayloadExecution":  "enable",
    "defenderPreventCredentialStealingType":  "enable",
    "defenderProcessCreationType":  "block",
    "defenderProcessCreation":  "enable",
    "defenderUntrustedUSBProcessType":  "block",
    "defenderUntrustedUSBProcess":  "enable",
    "defenderUntrustedExecutableType":  "block",
    "defenderUntrustedExecutable":  "enable",
    "defenderEmailContentExecutionType":  "block",
    "defenderEmailContentExecution":  "enable",
    "defenderAdvancedRansomewareProtectionType":  "enable",
    "defenderGuardMyFoldersType":  "auditMode",
    "defenderGuardedFoldersAllowedAppPaths":  [

                                              ],
    "defenderAdditionalGuardedFolders":  [

                                         ],
    "defenderNetworkProtectionType":  "enable",
    "defenderExploitProtectionXml":  null,
    "defenderExploitProtectionXmlFileName":  null,
    "defenderSecurityCenterBlockExploitProtectionOverride":  false,
    "appLockerApplicationControl":  "enforceComponentsStoreAppsAndSmartlocker",
    "deviceGuardLocalSystemAuthorityCredentialGuardSettings":  "notConfigured",
    "deviceGuardEnableVirtualizationBasedSecurity":  false,
    "deviceGuardEnableSecureBootWithDMA":  false,
    "deviceGuardSecureBootWithDMA":  "notConfigured",
    "deviceGuardLaunchSystemGuard":  "notConfigured",
    "smartScreenEnableInShell":  true,
    "smartScreenBlockOverrideForFiles":  true,
    "applicationGuardEnabled":  false,
    "applicationGuardEnabledOptions":  "notConfigured",
    "applicationGuardBlockFileTransfer":  "notConfigured",
    "applicationGuardBlockNonEnterpriseContent":  false,
    "applicationGuardAllowPersistence":  false,
    "applicationGuardForceAuditing":  false,
    "applicationGuardBlockClipboardSharing":  "notConfigured",
    "applicationGuardAllowPrintToPDF":  false,
    "applicationGuardAllowPrintToXPS":  false,
    "applicationGuardAllowPrintToLocalPrinters":  false,
    "applicationGuardAllowPrintToNetworkPrinters":  false,
    "applicationGuardAllowVirtualGPU":  false,
    "applicationGuardAllowFileSaveOnHost":  false,
    "bitLockerAllowStandardUserEncryption":  true,
    "bitLockerDisableWarningForOtherDiskEncryption":  true,
    "bitLockerEnableStorageCardEncryptionOnMobile":  false,
    "bitLockerEncryptDevice":  true,
    "bitLockerRecoveryPasswordRotation":  "notConfigured",
    "defenderDisableScanArchiveFiles":  null,
    "defenderAllowScanArchiveFiles":  null,
    "defenderDisableBehaviorMonitoring":  null,
    "defenderAllowBehaviorMonitoring":  null,
    "defenderDisableCloudProtection":  null,
    "defenderAllowCloudProtection":  null,
    "defenderEnableScanIncomingMail":  null,
    "defenderEnableScanMappedNetworkDrivesDuringFullScan":  null,
    "defenderDisableScanRemovableDrivesDuringFullScan":  null,
    "defenderAllowScanRemovableDrivesDuringFullScan":  null,
    "defenderDisableScanDownloads":  null,
    "defenderAllowScanDownloads":  null,
    "defenderDisableIntrusionPreventionSystem":  null,
    "defenderAllowIntrusionPreventionSystem":  null,
    "defenderDisableOnAccessProtection":  null,
    "defenderAllowOnAccessProtection":  null,
    "defenderDisableRealTimeMonitoring":  null,
    "defenderAllowRealTimeMonitoring":  null,
    "defenderDisableScanNetworkFiles":  null,
    "defenderAllowScanNetworkFiles":  null,
    "defenderDisableScanScriptsLoadedInInternetExplorer":  null,
    "defenderAllowScanScriptsLoadedInInternetExplorer":  null,
    "defenderBlockEndUserAccess":  null,
    "defenderAllowEndUserAccess":  null,
    "defenderScanMaxCpuPercentage":  null,
    "defenderCheckForSignaturesBeforeRunningScan":  null,
    "defenderCloudBlockLevel":  null,
    "defenderCloudExtendedTimeoutInSeconds":  null,
    "defenderDaysBeforeDeletingQuarantinedMalware":  null,
    "defenderDisableCatchupFullScan":  null,
    "defenderDisableCatchupQuickScan":  null,
    "defenderEnableLowCpuPriority":  null,
    "defenderFileExtensionsToExclude":  [

                                        ],
    "defenderFilesAndFoldersToExclude":  [

                                         ],
    "defenderProcessesToExclude":  [

                                   ],
    "defenderPotentiallyUnwantedAppAction":  null,
    "defenderScanDirection":  null,
    "defenderScanType":  null,
    "defenderScheduledQuickScanTime":  null,
    "defenderScheduledScanDay":  null,
    "defenderScheduledScanTime":  null,
    "defenderSignatureUpdateIntervalInHours":  null,
    "defenderSubmitSamplesConsentType":  null,
    "defenderDetectedMalwareActions":  null,
    "firewallRules":  [

                      ],
    "userRightsAccessCredentialManagerAsTrustedCaller":  {
                                                             "state":  "notConfigured",
                                                             "localUsersOrGroups":  [

                                                                                    ]
                                                         },
    "userRightsAllowAccessFromNetwork":  {
                                             "state":  "notConfigured",
                                             "localUsersOrGroups":  [

                                                                    ]
                                         },
    "userRightsBlockAccessFromNetwork":  {
                                             "state":  "notConfigured",
                                             "localUsersOrGroups":  [

                                                                    ]
                                         },
    "userRightsActAsPartOfTheOperatingSystem":  {
                                                    "state":  "notConfigured",
                                                    "localUsersOrGroups":  [

                                                                           ]
                                                },
    "userRightsLocalLogOn":  {
                                 "state":  "notConfigured",
                                 "localUsersOrGroups":  [

                                                        ]
                             },
    "userRightsDenyLocalLogOn":  {
                                     "state":  "notConfigured",
                                     "localUsersOrGroups":  [

                                                            ]
                                 },
    "userRightsBackupData":  {
                                 "state":  "notConfigured",
                                 "localUsersOrGroups":  [

                                                        ]
                             },
    "userRightsChangeSystemTime":  {
                                       "state":  "notConfigured",
                                       "localUsersOrGroups":  [

                                                              ]
                                   },
    "userRightsCreateGlobalObjects":  {
                                          "state":  "notConfigured",
                                          "localUsersOrGroups":  [

                                                                 ]
                                      },
    "userRightsCreatePageFile":  {
                                     "state":  "notConfigured",
                                     "localUsersOrGroups":  [

                                                            ]
                                 },
    "userRightsCreatePermanentSharedObjects":  {
                                                   "state":  "notConfigured",
                                                   "localUsersOrGroups":  [

                                                                          ]
                                               },
    "userRightsCreateSymbolicLinks":  {
                                          "state":  "notConfigured",
                                          "localUsersOrGroups":  [

                                                                 ]
                                      },
    "userRightsCreateToken":  {
                                  "state":  "notConfigured",
                                  "localUsersOrGroups":  [

                                                         ]
                              },
    "userRightsDebugPrograms":  {
                                    "state":  "notConfigured",
                                    "localUsersOrGroups":  [

                                                           ]
                                },
    "userRightsRemoteDesktopServicesLogOn":  {
                                                 "state":  "notConfigured",
                                                 "localUsersOrGroups":  [

                                                                        ]
                                             },
    "userRightsDelegation":  {
                                 "state":  "notConfigured",
                                 "localUsersOrGroups":  [

                                                        ]
                             },
    "userRightsGenerateSecurityAudits":  {
                                             "state":  "notConfigured",
                                             "localUsersOrGroups":  [

                                                                    ]
                                         },
    "userRightsImpersonateClient":  {
                                        "state":  "notConfigured",
                                        "localUsersOrGroups":  [

                                                               ]
                                    },
    "userRightsIncreaseSchedulingPriority":  {
                                                 "state":  "notConfigured",
                                                 "localUsersOrGroups":  [

                                                                        ]
                                             },
    "userRightsLoadUnloadDrivers":  {
                                        "state":  "notConfigured",
                                        "localUsersOrGroups":  [

                                                               ]
                                    },
    "userRightsLockMemory":  {
                                 "state":  "notConfigured",
                                 "localUsersOrGroups":  [

                                                        ]
                             },
    "userRightsManageAuditingAndSecurityLogs":  {
                                                    "state":  "notConfigured",
                                                    "localUsersOrGroups":  [

                                                                           ]
                                                },
    "userRightsManageVolumes":  {
                                    "state":  "notConfigured",
                                    "localUsersOrGroups":  [

                                                           ]
                                },
    "userRightsModifyFirmwareEnvironment":  {
                                                "state":  "notConfigured",
                                                "localUsersOrGroups":  [

                                                                       ]
                                            },
    "userRightsModifyObjectLabels":  {
                                         "state":  "notConfigured",
                                         "localUsersOrGroups":  [

                                                                ]
                                     },
    "userRightsProfileSingleProcess":  {
                                           "state":  "notConfigured",
                                           "localUsersOrGroups":  [

                                                                  ]
                                       },
    "userRightsRemoteShutdown":  {
                                     "state":  "notConfigured",
                                     "localUsersOrGroups":  [

                                                            ]
                                 },
    "userRightsRestoreData":  {
                                  "state":  "notConfigured",
                                  "localUsersOrGroups":  [

                                                         ]
                              },
    "userRightsTakeOwnership":  {
                                    "state":  "notConfigured",
                                    "localUsersOrGroups":  [

                                                           ]
                                },
    "firewallProfileDomain":  {
                                  "firewallEnabled":  "allowed",
                                  "stealthModeRequired":  false,
                                  "stealthModeBlocked":  false,
                                  "incomingTrafficRequired":  false,
                                  "incomingTrafficBlocked":  false,
                                  "unicastResponsesToMulticastBroadcastsRequired":  false,
                                  "unicastResponsesToMulticastBroadcastsBlocked":  false,
                                  "inboundNotificationsRequired":  false,
                                  "inboundNotificationsBlocked":  false,
                                  "authorizedApplicationRulesFromGroupPolicyMerged":  false,
                                  "authorizedApplicationRulesFromGroupPolicyNotMerged":  false,
                                  "globalPortRulesFromGroupPolicyMerged":  false,
                                  "globalPortRulesFromGroupPolicyNotMerged":  false,
                                  "connectionSecurityRulesFromGroupPolicyMerged":  false,
                                  "connectionSecurityRulesFromGroupPolicyNotMerged":  false,
                                  "outboundConnectionsRequired":  false,
                                  "outboundConnectionsBlocked":  false,
                                  "inboundConnectionsRequired":  false,
                                  "inboundConnectionsBlocked":  true,
                                  "securedPacketExemptionAllowed":  false,
                                  "securedPacketExemptionBlocked":  false,
                                  "policyRulesFromGroupPolicyMerged":  false,
                                  "policyRulesFromGroupPolicyNotMerged":  false
                              },
    "firewallProfilePublic":  {
                                  "firewallEnabled":  "allowed",
                                  "stealthModeRequired":  false,
                                  "stealthModeBlocked":  false,
                                  "incomingTrafficRequired":  false,
                                  "incomingTrafficBlocked":  false,
                                  "unicastResponsesToMulticastBroadcastsRequired":  false,
                                  "unicastResponsesToMulticastBroadcastsBlocked":  false,
                                  "inboundNotificationsRequired":  false,
                                  "inboundNotificationsBlocked":  false,
                                  "authorizedApplicationRulesFromGroupPolicyMerged":  false,
                                  "authorizedApplicationRulesFromGroupPolicyNotMerged":  false,
                                  "globalPortRulesFromGroupPolicyMerged":  false,
                                  "globalPortRulesFromGroupPolicyNotMerged":  false,
                                  "connectionSecurityRulesFromGroupPolicyMerged":  false,
                                  "connectionSecurityRulesFromGroupPolicyNotMerged":  false,
                                  "outboundConnectionsRequired":  false,
                                  "outboundConnectionsBlocked":  false,
                                  "inboundConnectionsRequired":  false,
                                  "inboundConnectionsBlocked":  true,
                                  "securedPacketExemptionAllowed":  false,
                                  "securedPacketExemptionBlocked":  false,
                                  "policyRulesFromGroupPolicyMerged":  false,
                                  "policyRulesFromGroupPolicyNotMerged":  false
                              },
    "firewallProfilePrivate":  {
                                   "firewallEnabled":  "allowed",
                                   "stealthModeRequired":  false,
                                   "stealthModeBlocked":  false,
                                   "incomingTrafficRequired":  false,
                                   "incomingTrafficBlocked":  false,
                                   "unicastResponsesToMulticastBroadcastsRequired":  false,
                                   "unicastResponsesToMulticastBroadcastsBlocked":  false,
                                   "inboundNotificationsRequired":  false,
                                   "inboundNotificationsBlocked":  false,
                                   "authorizedApplicationRulesFromGroupPolicyMerged":  false,
                                   "authorizedApplicationRulesFromGroupPolicyNotMerged":  false,
                                   "globalPortRulesFromGroupPolicyMerged":  false,
                                   "globalPortRulesFromGroupPolicyNotMerged":  false,
                                   "connectionSecurityRulesFromGroupPolicyMerged":  false,
                                   "connectionSecurityRulesFromGroupPolicyNotMerged":  false,
                                   "outboundConnectionsRequired":  false,
                                   "outboundConnectionsBlocked":  false,
                                   "inboundConnectionsRequired":  false,
                                   "inboundConnectionsBlocked":  true,
                                   "securedPacketExemptionAllowed":  false,
                                   "securedPacketExemptionBlocked":  false,
                                   "policyRulesFromGroupPolicyMerged":  false,
                                   "policyRulesFromGroupPolicyNotMerged":  false
                               },
    "bitLockerSystemDrivePolicy":  {
                                       "encryptionMethod":  "xtsAes256",
                                       "startupAuthenticationRequired":  true,
                                       "startupAuthenticationBlockWithoutTpmChip":  true,
                                       "startupAuthenticationTpmUsage":  "required",
                                       "startupAuthenticationTpmPinUsage":  "blocked",
                                       "startupAuthenticationTpmKeyUsage":  "blocked",
                                       "startupAuthenticationTpmPinAndKeyUsage":  "blocked",
                                       "minimumPinLength":  null,
                                       "prebootRecoveryEnableMessageAndUrl":  false,
                                       "prebootRecoveryMessage":  null,
                                       "prebootRecoveryUrl":  null,
                                       "recoveryOptions":  {
                                                               "blockDataRecoveryAgent":  true,
                                                               "recoveryPasswordUsage":  "allowed",
                                                               "recoveryKeyUsage":  "allowed",
                                                               "hideRecoveryOptions":  true,
                                                               "enableRecoveryInformationSaveToStore":  true,
                                                               "recoveryInformationToStore":  "passwordAndKey",
                                                               "enableBitLockerAfterRecoveryInformationToStore":  true
                                                           }
                                   },
    "bitLockerFixedDrivePolicy":  {
                                      "encryptionMethod":  "xtsAes256",
                                      "requireEncryptionForWriteAccess":  true,
                                      "recoveryOptions":  {
                                                              "blockDataRecoveryAgent":  true,
                                                              "recoveryPasswordUsage":  "allowed",
                                                              "recoveryKeyUsage":  "allowed",
                                                              "hideRecoveryOptions":  true,
                                                              "enableRecoveryInformationSaveToStore":  true,
                                                              "recoveryInformationToStore":  "passwordAndKey",
                                                              "enableBitLockerAfterRecoveryInformationToStore":  true
                                                          }
                                  },
    "bitLockerRemovableDrivePolicy":  {
                                          "encryptionMethod":  "aesCbc256",
                                          "requireEncryptionForWriteAccess":  true,
                                          "blockCrossOrganizationWriteAccess":  false
                                      }
}

"@

####################################################

$Win10_WHfB = @"

{
    "@odata.type":  "#microsoft.graph.windowsIdentityProtectionConfiguration",
    "description":  "Enables Windows Hello for Business settings including option to use FIDO2 security keys.",
    "displayName":  "Windows 10 - Windows Hello for Business",
    "useSecurityKeyForSignin":  true,
    "enhancedAntiSpoofingForFacialFeaturesEnabled":  true,
    "pinMinimumLength":  6,
    "pinMaximumLength":  null,
    "pinUppercaseCharactersUsage":  "blocked",
    "pinLowercaseCharactersUsage":  "blocked",
    "pinSpecialCharactersUsage":  "blocked",
    "pinExpirationInDays":  null,
    "pinPreviousBlockCount":  null,
    "pinRecoveryEnabled":  false,
    "securityDeviceRequired":  false,
    "unlockWithBiometricsEnabled":  true,
    "useCertificatesForOnPremisesAuthEnabled":  false,
    "windowsHelloForBusinessBlocked":  false
}

"@

####################################################

$Win10_F2 = @"

{
    "@odata.type":  "#microsoft.graph.windows10CustomConfiguration",
    "description":  "Enables FIDO2 security keys as a sign-in method for Windows 10",
    "displayName":  "Windows 10 - FIDO2 security keys (optional)",
    "omaSettings":  [
                        {
                            "@odata.type":  "#microsoft.graph.omaSettingInteger",
                            "displayName":  "Turn on FIDO Security Keys for Windows Sign-In",
                            "description":  null,
                            "omaUri":  "./Device/Vendor/MSFT/PassportForWork/SecurityKey/UseSecurityKeyForSignin",
                            "value":  1,
                            "isReadOnly":  false
                        }
                    ]
}

"@

####################################################

$UpdatePilot = @"

{
    "@odata.type":  "#microsoft.graph.windowsUpdateForBusinessConfiguration",
    "description":  "",
    "displayName":  "Pilot ring",
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
    "updateWeeks":  "everyWeek",
    "qualityUpdatesPauseStartDate":  "2019-06-07",
    "featureUpdatesPauseStartDate":  "2019-06-07",
    "featureUpdatesRollbackWindowInDays":  null,
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
    "scheduleRestartWarningInHours":  null,
    "scheduleImminentRestartWarningInMinutes":  null,
    "userPauseAccess":  "enabled",
    "userWindowsUpdateScanAccess":  "enabled",
    "updateNotificationLevel":  "defaultNotifications",
    "installationSchedule":  {
                                 "@odata.type":  "#microsoft.graph.windowsUpdateActiveHoursInstall",
                                 "activeHoursStart":  "08:00:00.0000000",
                                 "activeHoursEnd":  "17:00:00.0000000"
                             }
}


"@

####################################################

$UpdateBroad = @"

{
    "@odata.type":  "#microsoft.graph.windowsUpdateForBusinessConfiguration",
    "description":  "",
    "displayName":  "Broad ring",
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
    "updateWeeks":  "everyWeek",
    "qualityUpdatesPauseStartDate":  null,
    "featureUpdatesPauseStartDate":  null,
    "featureUpdatesRollbackWindowInDays":  null,
    "qualityUpdatesWillBeRolledBack":  null,
    "featureUpdatesWillBeRolledBack":  null,
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
    "scheduleRestartWarningInHours":  null,
    "scheduleImminentRestartWarningInMinutes":  null,
    "userPauseAccess":  "enabled",
    "userWindowsUpdateScanAccess":  "enabled",
    "updateNotificationLevel":  "defaultNotifications",
    "installationSchedule":  {
                                 "@odata.type":  "#microsoft.graph.windowsUpdateActiveHoursInstall",
                                 "activeHoursStart":  "08:00:00.0000000",
                                 "activeHoursEnd":  "17:00:00.0000000"
                             }
}


"@

####################################################



####################################################
#Apps
####################################################

$Office32 = @"



{

  "@odata.type": "#microsoft.graph.officeSuiteApp",

  "autoAcceptEula": true,

  "description": "Microsoft 365 Desktop apps - 32 bit",

  "developer": "Microsoft",

  "displayName": "Microsoft 365 Desktop apps - 32 bit",

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

  "description": "Microsoft 365 Desktop apps - 64 bit",

  "developer": "Microsoft",

  "displayName": "Microsoft 365 Desktop apps - 64 bit",

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
    "displayName":  "Microsoft Edge for Windows 10",
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




####################################################
#Import JSON to create policies
####################################################

#Write-Host "Adding Windows Information Protection policies..." -ForegroundColor Yellow

Add-MDMWindowsInformationProtectionPolicy -JSON $APP_WIP_MDM #OK
Add-WindowsInformationProtectionPolicy -JSON $APP_WIP_MAM #OK

Write-Host
####################################################

Write-Host "Adding Compliance policy for Windows..." -ForegroundColor Yellow

Add-DeviceCompliancePolicybaseline -Json $BaselineWin10 #OK

Write-Host 
####################################################

Write-Host "Adding Device configuration profiles..." -ForegroundColor Yellow

#Add-DeviceConfigurationPolicy -Json $Win10BASICDR
#Add-DeviceConfigurationPolicy -Json $Win10BASICEP
Add-DeviceConfigurationPolicy -Json $Win10DR
Add-DeviceConfigurationPolicy -Json $Win10EP
Add-DeviceConfigurationPolicy -Json $Win10_F2
Add-DeviceConfigurationPolicy -Json $Win10_WHfB

Write-Host 

#Write-Host "Adding Windows 10 Software Update Rings..." -ForegroundColor Yellow

Add-DeviceConfigurationPolicy -Json $UpdatePilot # OK
Add-DeviceConfigurationPolicy -Json $UpdateBroad # OK

Write-Host
####################################################

write-host "Publishing" ($Office32 | ConvertFrom-Json).displayName -ForegroundColor Yellow
Add-MDMApplication -JSON $Office32
Write-Host 

write-host "Publishing" ($Office64 | ConvertFrom-Json).displayName -ForegroundColor Yellow
Add-MDMApplication -JSON $Office64
Write-Host

write-host "Publishing" ($ChrEdge | ConvertFrom-Json).displayName -ForegroundColor Yellow
Add-MDMApplication -JSON $ChrEdge
Write-Host

####################################################


