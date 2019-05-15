# Microsoft-365
scripts to help configure Microsoft 365 

Be sure to review the variables at the beginning of each script and set them to your liking.

Baseline-ExchangeOnline.ps1: Configures Exchange Online tenant with baseline settings and policies. Follows The Office 365 Email Security Checklist

Baseline-ATP-P1.ps1: Configures Office 365 Advanced Threat Protection (plan 1)

Block-BasicAuth.ps1: Creates an authentication policy to block basic auth (see the comments in the script for making exceptions)

Setup-DKIM.ps1: This script helps with configuring DKIM; use: .\Setup-DKIM.ps1 -DomainName "yourdomainhere.com"

Disable-Forwarding.ps1: This script will disable auto-forwarding and also output csv of existing forwarders to C:\temp

