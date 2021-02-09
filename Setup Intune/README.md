# Script to setup Intune:

Scripts are modified, and based on Microsoft's Intune samples: https://github.com/microsoftgraph/powershell-intune-samples/

Simply download and run <b>Setup-Intune.ps1</b>

None of the policies will be assigned when you import them.

Intune deployment scripts:

	• Install-BYODMobileDeviceProfiles.ps1 = Imports (but does not assign) baseline BYOD policies for iOS, Android, and MacOS
	• Setup-Intune.ps1 = Imports all baseline policies from JSON (but does not assign them) 
	• OLD_Setup-Intune.ps1 = Previous version of my master script to import configuration profiles

MAM scripts:

	• Export-AppProtection.ps1 = Prompts for authentication user, then exports to JSON all existing MAM policies
	• Import-AppProtection.ps1 = Prompts for authentication user, and prompts for path to JSON file for import

MDM scripts:

	• Export-Compliance.ps1 = Prompts for authentication user, then exports to JSON all existing Compliance policies
	• Import-Compliance.ps1 = Prompts for authentication user, and prompts for path to JSON file for import
	• Export-DeviceConfiguration.ps1 = Prompts for authentication user, then exports to JSON all existing Device profiles
	• Import-DeviceConfiguration.ps1 = Prompts for authentication user, and prompts for path to JSON file for import
	• Export-EndpointSecurity.ps1 = Prompts for authentication user, then exports to JSON all existing Endpoint security profiles
	• Import-EndpointSecurity.ps1 = Prompts for authentication user, and prompts for path to JSON file for import
	

The original article which corresponds with these scripts is located here: https://www.itpromentor.com/setup-intune
