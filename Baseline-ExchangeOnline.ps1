##########################################################################################################################################################################################
## Description:
## This script configures "Baseline" policies and security settings for Exchange Online
## The changes implemented in this script correspond to The Office 365 Email Security Checklist
## Prerequisites:
## The tenant will need any Exchange Online plan
## To enable Archive or Litigation Hold requires Exchange Online Archiving or Exchange Online Plan 2
## Connect to Exchange Online via PowerShell using MFA:
## https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps
## 
## WARNING: Script provided as-is. Author is not responsible for its use and application. Use at your own risk.
##########################################################################################################################################################################################
## DEFINE THE VARIABLES FIRST:
## Where should the alerts go:
$AlertAddress= "alert@itpromentor.com"
## Deploy the default Mobile Device Policy? (not needed with Intune or other MDM):                        
$MobilePolicy = $false 
## Enable archive mailbox for all users?  NOTE: Requires Exchange Online Archiving: 
$EnableArchive = $false                         
## Enable litigation hold for all users?  NOTE: Requires Exchange Online Archiving: 
$EnableLegalHold = $false                       
## List the domains that will be protected by anti-spam and anti-malware policies
$RecipientDomains = "itpromentor.onmicrosoft.com", "itpromentor.com"    
########################################################################################################################################################################################## 

## Enable Organization Customization - if it has already been enabled, it will produce an error; ignore it:
Enable-OrganizationCustomization

## Enable audit log search:
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

## Enable auditing on all mailboxes, keeping logs for 1 year:
Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit 365 -AuditAdmin Update, MoveToDeletedItems, SoftDelete, HardDelete, SendAs, SendOnBehalf, Create, UpdateFolderPermission -AuditDelegate Update, SoftDelete, HardDelete, SendAs, Create, UpdateFolderPermissions, MoveToDeletedItems, SendOnBehalf -AuditOwner UpdateFolderPermission, MailboxLogin, Create, SoftDelete, HardDelete, Update, MoveToDeletedItems 

## Disable IMAP and POP on all mailboxes:
Get-Mailbox | Set-CASMailbox -ImapEnabled $false -PopEnabled $false

## Disable IMAP and POP globally (for any future mailboxes):
Get-CASMailboxPlan | Set-CASMailboxPlan -ImapEnabled $false -PopEnabled $false

## Enable modern authentication for Exchange Online:
Set-OrganizationConfig -OAuth2ClientProfileEnabled $true

## Disable basic authentication:
New-AuthenticationPolicy -Name "Block Basic Auth"
Set-OrganizationConfig -DefaultAuthenticationPolicy "Block Basic Auth"

## Set all mailboxes to keep deleted items for the maximum of 30 days:
Get-Mailbox | Set-Mailbox -RetainDeletedItemsFor 30

## Prevent winmail.dat attachments:
Set-RemoteDomain Default -TNEFEnabled $false 

## Collect existing mailbox forwarding into CSV files at C:\temp\DomainName-MailboxForwarding.csv and DomainName-InboxRules.csv
$DefaultDomainName = Get-AcceptedDomain | Where-Object Default -EQ True    ## Finds the default accepted domain name and stores it in a variable called '$DefaultDomainName'
Get-Mailbox -ResultSize Unlimited -Filter {(RecipientTypeDetails -ne "DiscoveryMailbox") -and ((ForwardingSmtpAddress -ne $null) -or (ForwardingAddress -ne $null))} | Select Identity,ForwardingSmtpAddress,ForwardingAddress | Export-Csv c:\temp\$DefaultDomainName-MailboxForwarding.csv -append
foreach ($a in (Get-Mailbox -ResultSize Unlimited |select PrimarySMTPAddress)) {Get-InboxRule -Mailbox $a.PrimarySMTPAddress | ?{($_.ForwardTo -ne $null) -or ($_.ForwardAsAttachmentTo -ne $null) -or ($_.DeleteMessage -eq $true) -or ($_.RedirectTo -ne $null)} |select Name,Identity,ForwardTo,ForwardAsAttachmentTo, RedirectTo, DeleteMessage | Export-Csv c:\temp\$DefaultDomainName-InboxRules.csv -append }
## NOTE: After running this script, check the CSV files under C:\temp for a list of mail users who may be affected by disabling the ability to auto-forward messages to external domains

## Disable external domain forwarding (globally disable auto-forwarding on the default remote domain):
Set-RemoteDomain Default -AutoForwardEnabled $false

## Remove the ability for users to setup forwarding via the OWA portal
## Creates a new RBAC Role Assignment Policy 
$RoleName = "DenyForwarding"
$DenyForwardRole = Get-ManagementRole | Where-Object {$_.Name -contains $RoleName}
if (!$DenyForwardRole) {
    Write-Output "DenyForwarding role not found, creating role..."
    New-ManagementRole -Parent MyBaseOptions -Name $RoleName
    Set-ManagementRoleEntry DenyForwarding\Set-Mailbox -RemoveParameter -Parameters DeliverToMailboxAndForward,ForwardingAddress,ForwardingSmtpAddress
    New-RoleAssignmentPolicy -Name DenyForwardingRoleAssignmentPolicy -Roles DenyForwarding,MyContactInformation,MyRetentionPolicies,MyMailSubscriptions,MyTextMessaging,MyVoiceMail,MyDistributionGroupMembership,MyDistributionGroups,MyProfileInformation,MyTeamMailboxes,"My ReadWriteMailbox Apps","My Marketplace Apps","My Custom Apps"
    Set-RoleAssignmentPolicy -Identity DenyForwardingRoleAssignmentPolicy -IsDefault -Confirm:$false 
} else {Write-Output "DenyForwarding role already exists."}

## Create the baseline spam filter policy and rule
$HostedContentPolicyParam = @{
    "name" = "Anti-spam Baseline";
    'bulkspamaction' =  'quarantine';
    'bulkthreshold' =  '7';
    'highconfidencespamaction' =  'quarantine';
    'inlinesafetytipsenabled' = $true;
    'markasspambulkmail' = 'on';
    'enablelanguageblocklist' = $true;
    'enableregionblocklist' = $true;
    'increasescorewithimagelinks' = 'off'
    'increasescorewithnumericips' = 'on'
    'increasescorewithredirecttootherport' = 'on'
    'increasescorewithbizorinfourls' = 'on';
    'markasspamemptymessages' ='on';
    'markasspamjavascriptinhtml' = 'on';
    'markasspamframesinhtml' = 'on';
    'markasspamobjecttagsinhtml' = 'on';
    'markasspamembedtagsinhtml' ='on';
    'markasspamformtagsinhtml' = 'on';
    'markasspamwebbugsinhtml' = 'on';
    'markasspamsensitivewordlist' = 'on';
    'markasspamspfrecordhardfail' = 'on';
    'markasspamfromaddressauthfail' = 'on';
    'markasspamndrbackscatter' = 'on';
    'phishspamaction' = 'quarantine';
    'spamaction' = 'quarantine';
    'zapenabled' = $true;
    'EnableEndUserSpamNotifications' = $true;
    'EndUserSpamNotificationFrequency' = 1;
    'QuarantineRetentionPeriod' = 15
}
New-HostedContentFilterPolicy @HostedContentPolicyParam

$HostedContentRuleParam = @{
    'name' = 'Anti-spam Baseline';
    'hostedcontentfilterpolicy' = 'Anti-spam baseline'; 
    'recipientdomainis' = $RecipientDomains; 
    'Enabled' = $true
}
New-HostedContentFilterRule @HostedContentRuleParam

## Create Baseline malware filter policy and rule
$MalwarePolicyParam = @{
    "Name" = "Anti-malware Baseline";
    'Action' =  'deletemessage';
    'Enablefilefilter' =  $true;
    'EnableInternalSenderAdminNotifications' = $true;
    'InternalSenderAdminAddress' =  $AlertAddress;
    'Enableinternalsendernotifications' =  $true;
    'Zap' = $true
}
New-MalwareFilterPolicy @MalwarePolicyParam
    
### Note to self: need to scope recipient domain(s) to all accepted domains*
$MalwareRuleParam = @{
    'name' = 'Anti-malware Baseline';
    'malwarefilterpolicy' = 'Anti-malware Baseline'; ## this needs to match the above policy name
    'recipientdomainis' = $RecipientDomains; ## this needs to match the domains you wish to protect in your tenant
    'Priority' = 0;
    'Enabled' = $true
}
    
New-MalwareFilterRule @MalwareRuleParam


## Modify existing 'Default' oubound spam filter
$OutboundPolicyParam = @{
    "identity" = 'Default';
    'bccsuspiciousoutboundadditionalrecipients' =  $AlertAddress;
    'bccsuspiciousoutboundmail' = $true;
    'notifyoutboundspam' = $true;
    'NotifyOutboundSpamRecipients' = $AlertAddress
}

Set-HostedOutboundSpamFilterPolicy @OutboundPolicyParam

## Enable the default mobile device mailbox policy (optional):
if ($MobilePolicy) {
$MobileDeviceParam= @{
   'Name' = "Baseline Mobile Device Policy";
   'PasswordEnabled' = $true;
   'AllowSimplePassword' =  $false;
   'PasswordRecoveryEnabled' = $true;
   'MinPasswordLength' = "4";
   'MaxPasswordFailedAttempts' = "15";
   'AllowExternalDeviceManagement' = $true;
   'AllowNonProvisionableDevices' = $false;
   'RequireDeviceEncryption' = $true;
   'MaxInactivityTimeLock' = "00:05:00";
   'IsDefault' = $true
}

New-MobileDeviceMailboxPolicy @MobileDeviceParam
}

## Enable archive mailboxes for all users (optional):
if ($EnableArchive) {
## Enable auto-expanding archive capability 
Set-OrganizationConfig -AutoExpandingArchive

## Enable the archive mailbox for all users
Get-Mailbox -Filter {ArchiveStatus -Eq "None" -AND RecipientTypeDetails -eq "UserMailbox"} | Enable-Mailbox -Archive
}

## Enable legal hold on mailboxes for all users (optional):
if ($EnableLegalHold){
    Get-Mailbox | Set-Mailbox -LitigationHoldEnabled $true
}
