##########################################################################################################################################################################################
## Description:
## This script disables auto-forwarding
## Prerequisites:
## The tenant will need to include licensing for any Exchange Online Plan 
## Connect to Exchange Online via PowerShell using MFA:
## https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps
##
## WARNING: Script provided as-is. Author is not responsible for its use and application. Use at your own risk.
##########################################################################################################################################################################################

## Disable external domain forwarding - globally disable auto-forwarding on the default remote domain
Set-RemoteDomain Default -AutoForwardEnabled $false

## Collect existing mailbox forwarding and output the result to CSV files:
$DefaultDomainName = Get-AcceptedDomain | Where-Object Default -EQ True    ## Finds the default accepted domain name and stores it in a variable called '$DefaultDomainName'
## The next line outputs a list to C:\temp\DomainName-MailboxForwarding.csv of auto-forwarding mailboxes configured before this policy: 
Get-Mailbox -ResultSize Unlimited -Filter {(RecipientTypeDetails -ne "DiscoveryMailbox") -and ((ForwardingSmtpAddress -ne $null) -or (ForwardingAddress -ne $null))} | Select Identity,ForwardingSmtpAddress,ForwardingAddress | Export-Csv c:\temp\$DomainName-MailboxForwarding.csv -append
## The next line outputs a list to c:\temp\DomainName-InboxRules.csv of inbox rules which were configured to auto-forward messages:
foreach ($a in (Get-Mailbox -ResultSize Unlimited |select PrimarySMTPAddress)) {Get-InboxRule -Mailbox $a.PrimarySMTPAddress | ?{($_.ForwardTo -ne $null) -or ($_.ForwardAsAttachmentTo -ne $null) -or ($_.DeleteMessage -eq $true) -or ($_.RedirectTo -ne $null)} |select Name,Identity,ForwardTo,ForwardAsAttachmentTo, RedirectTo, DeleteMessage | Export-Csv c:\temp\$DomainName-InboxRules.csv -append }
## NOTE: After running this script, check the CSV files under C:\temp for a list of mail users who may be affected by disabling the ability to auto-forward messages to external domains

## The rest of this script is optional, and commented out (use if you deem appropriate)
## Remove any existing mailbox forwarding rules that are in place:
## Get-Mailbox | Set-Mailbox -ForwardingAddress $null -ForwardingSmtpAddress $null

## DENY AUTO-FORWARDING FROM MAILBOX RULES
## Creates a transport rule which will deny auto forwarding rules to external domains and reject the message with a notification to end-users
## $TransportRuleName = "External Forward Block"
## $rejectMessageText = "Mail forwarding to external domains is not permitted. If you have questions, please contact support."
## $ExternalForwardRule = Get-TransportRule | Where-Object {$_.Identity -contains $TransportRuleName}
## if (!$ExternalForwardRule) {
##    Write-Output "External Forward Block rule not found, creating rule..."
##    New-TransportRule -name $TransportRuleName -Priority 1 -SentToScope NotInOrganization -FromScope InOrganization -MessageTypeMatches AutoForward -RejectMessageEnhancedStatusCode 5.7.1 -RejectMessageReasonText $rejectMessageText
## } else {Write-Output "External forward block rule already exists."}   

## Remove the ability for users to setup forwarding via the OWA portal
## Creates a new RBAC Role Assignment Policy 
## $RoleName = "DenyForwarding"
## $DenyForwardRole = Get-ManagementRole | Where-Object {$_.Name -contains $RoleName}
## if (!$DenyForwardRole) {
##    Write-Output "DenyForwarding role not found, creating role..."
##    New-ManagementRole -Parent MyBaseOptions -Name $RoleName
##    Set-ManagementRoleEntry DenyForwarding\Set-Mailbox -RemoveParameter -Parameters DeliverToMailboxAndForward,ForwardingAddress,ForwardingSmtpAddress
##    New-RoleAssignmentPolicy -Name DenyForwardingRoleAssignmentPolicy -Roles DenyForwarding,MyContactInformation,MyRetentionPolicies,MyMailSubscriptions,MyTextMessaging,MyVoiceMail,MyDistributionGroupMembership,MyDistributionGroups,MyProfileInformation,MyTeamMailboxes,"My ReadWriteMailbox Apps","My Marketplace Apps","My Custom Apps"
##    Set-RoleAssignmentPolicy -Identity DenyForwardingRoleAssignmentPolicy -IsDefault -Confirm:$false 
## } else {Write-Output "DenyForwarding role already exists."}
