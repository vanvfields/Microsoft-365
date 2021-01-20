<##################################################################################################
#
.SYNOPSIS
    This script will set the default MDM authority to Intune if it is not already


.HOW-TO
    1. To install the module use: Install-Module Microsoft.Graph.Intune

.DETAILS
    FileName:    Set-MDMAuthority.ps1
    Author:      Alex Fields, ITProMentor.com
    Created:     September 2019
	Updated:     January 2021

#>
###################################################################################################


#Connect to MS Graph API
Connect-MSGraph
#Check if Intune already is MDM Authority
$mdmAuth = (Invoke-MSGraphRequest -Url "https://graph.microsoft.com/beta/organization('$OrgId')?`$select=mobiledevicemanagementauthority" -HttpMethod Get -ErrorAction Stop).mobileDeviceManagementAuthority
#Sets Intune as MDM Authority if not already set
if($mdmAuth -notlike "intune"){    Write-Progress -Activity "Set Intune as the MDM Authority" -Status "..."    $OrgID = (Invoke-MSGraphRequest -Url "https://graph.microsoft.com/v1.0/organization" -HttpMethod Get -ErrorAction Stop).value.id    Invoke-MSGraphRequest -Url "https://graph.microsoft.com/v1.0/organization/$OrgID/setMobileDeviceManagementAuthority" -HttpMethod Post -ErrorAction Stop}
