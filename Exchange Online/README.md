
The Office 365 Email Security Checklist scripts:

	• Baseline-ExchangeOnline.ps1: Configures Exchange Online tenant with baseline settings and policies
	• Baseline-ATP-P1.ps1: Configures Office 365 Advanced Threat Protection (plan 1)
	• Block-BasicAuth.ps1: Creates an authentication policy to block basic auth (see the comments in the script for making exceptions)
	• Setup-DKIM.ps1: This script helps with configuring DKIM; use: .\Setup-DKIM.ps1 -DomainName "yourdomainhere.com"
	• Disable-Forwarding.ps1: This script will disable auto-forwarding and also output csv of existing forwarders to C:\temp

Be sure to read the comments and variables at the beginning of each script. You are responsible for your own implementation, use at your own risk.
