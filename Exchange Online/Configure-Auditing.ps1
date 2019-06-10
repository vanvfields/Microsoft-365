##########################################################################################################################################################################################
## Description:
## This script configures auditing for Exchange Online
## Reference: https://docs.microsoft.com/en-us/exchange/policy-and-compliance/mailbox-audit-logging/enable-or-disable?view=exchserver-2019
## The changes implemented in this script correspond to The Office 365 Email Security Checklist
## Prerequisites:
## The tenant will need any Exchange Online plan
## Connect to Exchange Online via PowerShell:
## Using MFA: https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/clconnect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps
## 
## WARNING: Script provided as-is. Author is not responsible for its use and application. Use at your own risk.
##########################################################################################################################################################################################

$AuditLogAgeLimit = "365"

## Enable audit log search:
Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true

## Enable auditing on all mailboxes:
Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit $AuditLogAgeLimit -AuditAdmin Update, MoveToDeletedItems, SoftDelete, HardDelete, SendAs, SendOnBehalf, Create, UpdateFolderPermission -AuditDelegate Update, SoftDelete, HardDelete, SendAs, Create, UpdateFolderPermissions, MoveToDeletedItems, SendOnBehalf -AuditOwner UpdateFolderPermission, MailboxLogin, Create, SoftDelete, HardDelete, Update, MoveToDeletedItems 
