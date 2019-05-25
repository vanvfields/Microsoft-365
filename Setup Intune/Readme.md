Scripts to setup Intune:

Note: the Intune scripts are (mostly) taken and modified from Microsoft: https://github.com/microsoftgraph/powershell-intune-samples/

None of the policies will be assigned when you import the JSON files; simply review, adjust and test settings before assigning them

Intune deployment script:

	• Setup-Intune.ps1 = Imports all the baseline policies from JSON (but does not assign them)

MAM scripts:

	• Export-MAMPolicy.ps1 = Prompts for authentication user, then exports to JSON all existing MAM policies
	• Import-MAMPolicy.ps1 = Prompts for authentication user, and prompts for path to JSON file for import

App Protection (MAM) policy JSON files:
 
	• AppProtection-iOS: Basic iOS MAM policy (will not restrict copy/paste)
	• AppProtection-Android: Basic Android MAM policy (will not restrict copy/paste)

MDM scripts:

	• Export-Compliance.ps1 = Prompts for authentication user, then exports to JSON all existing Compliance policies
	• Import-Compliance.ps1 = Prompts for authentication user, and prompts for path to JSON file for import
	• Export-DeviceConfig.ps1 = Prompts for authentication user, then exports to JSON all existing Device profiles
	• Import-DeviceConfig.ps1 = Prompts for authentication user, and prompts for path to JSON file for import

Compliance policy JSON files:

	• Compliance-iOS: Block jailbroken devices only
	• Compliance-Android: Block rooted devices, require Google Play services and verify app integrity
	• Compliance-Win10: Require firewall, antivirus and antispyware
	• Compliance-macOS: Require encryption and system integrity
  
  Configuration policy JSON files:
  
	• Config-iOS: Basic device restriction profile (including 4-digit PIN)
	• Config-Android: Basic device restriction profile (including 4-digit PIN)
	• Config-macOS: Basic device restriction profile
	• Config-Win10Defender: Advanced Windows Defender configuration
	• Endpoint-Win10Pro: Pro version Endpoint protection (Application Guard, UAC, firewall and more)
	• Endpoint-Win10Enterprise: Enterprise Endpoint protection (adds Credential Guard, Exploit Guard and more)
  
