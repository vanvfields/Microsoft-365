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
	None of the policies will be assigned when you import the JSON files; simply review, adjust and test settings before assigning them. See more details in the Intune folder's readme file.
