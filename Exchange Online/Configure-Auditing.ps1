## Script by Alex Fields, ITProMentor.com
## Description:
## This script configures auditing for Exchange Online
## Reference: https://docs.microsoft.com/en-us/exchange/policy-and-compliance/mailbox-audit-logging/enable-or-disable?view=exchserver-2019
## Prerequisites:
## The tenant will need any Exchange Online plan
## Connect to Exchange Online via PowerShell using MFA: https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/clconnect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps
## WARNING: Script provided as-is. Author is not responsible for its use and application. Use at your own risk.

$MessageColor = "cyan"
$AssessmentColor = "magenta"

## Enable Unified Audit Log Search:
$AuditLogConfig = Get-AdminAuditLogConfig
if ($AuditLogConfig.UnifiedAuditLogIngestionEnabled) {
    Write-Host 
    Write-Host -ForegroundColor $MessageColor "Unified Audit Log Search is already enabled"
} else {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "Unified Audit Log is not enabled"
    Write-Host 
    $Answer = Read-Host "Do you want to enable the Unified Audit Log now? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Unified Audit Log Search is now enabled" 
    } else {
        Write-Host 
        Write-Host -ForegroundColor $AssessmentColor "Unified Audit Log will not be enabled"
    }
 }

## Prompt for the audit log age limit on all mailboxes:
Write-Host 
$Answer = Read-Host "Do you want to set the audit log age limit and enable all auditing actions on all mailboxes? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        Write-Host 
        $AuditLogAgeLimit = Read-Host "Enter the new audit log age limit in days (or press Enter to continue without making changes)"
        if ($AuditLogAgeLimit -eq $null -or $AuditLogAgeLimit -eq "" -or $AuditLogAgeLimit -eq 'n' -or $AuditLogAgeLimit -eq 'no'){
            Write-Host
            Write-Host -ForegroundColor $AssessmentColor "The audit log age limit and audit actions will not be modified"
        } else {
            Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditEnabled $true -AuditLogAgeLimit $AuditLogAgeLimit
            Write-Host 
            Write-Host -ForegroundColor $MessageColor "The new audit log age limit has been set for all mailboxes"
            ## Enable all mailbox auditing actions
            Get-Mailbox -ResultSize Unlimited | Set-Mailbox -AuditAdmin @{Add="Copy","Create","FolderBind","HardDelete","MessageBind","Move","MoveToDeletedItems","SendAs","SendOnBehalf","SoftDelete","Update","UpdateFolderPermissions","UpdateInboxRules","UpdateCalendarDelegation"}
            Get-Mailbox -ResultSize Unlimited | Set-Mailbox –AuditDelegate @{Add="Create","FolderBind","HardDelete","Move","MoveToDeletedItems","SendAs","SendOnBehalf","SoftDelete","Update","UpdateFolderPermissions","UpdateInboxRules"}
            Get-Mailbox -ResultSize Unlimited | Set-Mailbox –AuditOwner @{Add="Create","HardDelete","Move","Mailboxlogin","MoveToDeletedItems","SoftDelete","Update","UpdateFolderPermissions","UpdateInboxRules","UpdateCalendarDelegation"}
            Write-Host 
            Write-host -ForegroundColor $MessageColor "All auditing actions are now enabled on all mailboxes"
            } 

} else {
        Write-Host
        Write-Host -ForegroundColor $AssessmentColor "The audit log age limit and audit actions will not be modified"
        }

