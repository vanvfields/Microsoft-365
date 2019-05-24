# Microsoft-365
Scripts to help configure Microsoft 365 

Be sure to review the variables at the beginning of each script and set them to your liking.

Office 365 Email Security scripts:

	• Baseline-ExchangeOnline.ps1: Configures Exchange Online tenant with baseline settings and policies
	• Baseline-ATP-P1.ps1: Configures Office 365 Advanced Threat Protection (plan 1)
	• Block-BasicAuth.ps1: Creates an authentication policy to block basic auth (see the comments in the script for making exceptions)
	• Setup-DKIM.ps1: This script helps with configuring DKIM; use: .\Setup-DKIM.ps1 -DomainName "yourdomainhere.com"
	• Disable-Forwarding.ps1: This script will disable auto-forwarding and also output csv of existing forwarders to C:\temp

Scripts to setup Intune:

	Note: the Intune scripts are (mostly) taken and modified from Microsoft: https://github.com/microsoftgraph/powershell-intune-samples/
	None of the policies will be assigned when you import the JSON files; simply review, adjust and test settings before assigning them

MAM scripts:

	• Export-MAMPolicy.ps1 = Prompts for authentication user, then exports to JSON all existing MAM policies
	• Import-MAMPolicy.ps1 = Prompts for authentication user, and prompts for path to JSON file for import
	  
MDM scripts:

	• Export-Compliance.ps1 = Prompts for authentication user, then exports to JSON all existing Compliance policies
	• Import-Compliance.ps1 = Prompts for authentication user, and prompts for path to JSON file for import
	• Export-DeviceConfig.ps1 = Prompts for authentication user, then exports to JSON all existing Device profiles
	• Import-DeviceConfig.ps1 = Prompts for authentication user, and prompts for path to JSON file for import

Intune deployment script:

	• Setup-Intune.ps1 = Imports all the baseline policies from JSON (but does not assign them)

Compliance policy JSON files:

	• Compliance-iOS: Block jailbroken devices only
	• Compliance-Android: Block rooted devices, require Google Play services and verify app integrity
	• Compliance-Win10: Require firewall, antivirus and antispyware
	• Compliance-macOS: Require encryption and system integrity
  
  Configuration policy JSON files:
  
	• Config-iOS: Basic device restriction profile (including 4-digit PIN)
	• Config-Android: Basic device restriction profile (including 4-digit PIN)
	• Config-macOS: Basic device restriction profile
	• Config-Win10ProBasic: Basic Windows Defender config (configurable via 365 admin center)
	• Config-Win10ProAdvanced: Advanced Windows Defender config (recommended to review, test and deploy in rings)
	• Endpoint-Win10ProBasic: Basic Windows Endpoint protection config (configurable via 365 admin center)
	• Endpoint-Win10ProAdvanced: Advanced Endpoint protection config (recommended to review, test and deploy in rings)
  
 App Protection policy JSON files:
 
	• AppProtection-iOS: Basic iOS MAM policy (will not restrict copy/paste)
	• AppProtection-Android: Basic Android MAM policy (will not restrict copy/paste)
