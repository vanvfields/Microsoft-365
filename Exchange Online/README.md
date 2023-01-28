<H1>The Office 365 Email Security Checklist scripts</H1>

<H2>Description of the scripts:</H2>

<p>• <b>Install-EXOStandardProtection.ps1</b>: This script will configure your default EOP and MDO settings to match the Standard protection template
<p>• <b>Advanced-TenantConfig.ps1</b>: For customization of Exchange Online including many of the settings featured in other scripts:
<p>• <b>Block-UnmanagedDownload.ps1 </b>: This script configures the "Read-Only" Conditonal Access policy (additional config required)
<p>• <b>Block-ConsumerStorageOWA.ps1 </b>: This script disables 3rd party consumer storage locations in OWA
<p>• <b>Configure-Auditing.ps1 </b>: This script enables and helps you configure audit log age, etc.
<p>• <b>Disable-Forwarding.ps1</b>: This script will disable auto-forwarding and also output csv of existing forwarders to C:\temp
<p>• <b>Disable-SharedMbxSignOn.ps1 </b>: This script disables sign-in for shared mailboxes
<p>• <b>Set-DeletedItemsRetention.ps1 </b>: This script sets the deleted items retention value to max = 30 days (instead of default = 14)
<p>• <b>Setup-DKIM.ps1 </b>: This script helps with configuring DKIM; use: .\Setup-DKIM.ps1 -Domain "yourdomainhere.com"


<p>Be sure to read the comments and review each script. You are responsible for your own implementation, use at your own risk.
<p>These scripts follow the guide published at: https://www.itpromentor.com/email-security-checklist/
  <p>
