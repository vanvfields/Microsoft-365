##########################################################################################################################################################################################
## Description:
## This script modifies the default mobile device mailbox policy to require minimum 4 digit passcode and enforced device encryption
## Reference: https://docs.microsoft.com/en-us/powershell/module/exchange/devices/new-mobiledevicemailboxpolicy?view=exchange-ps
## Prerequisites:
## The tenant will need any Exchange Online plan
## Connect to Exchange Online via PowerShell using MFA:
## https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps
## 
## WARNING: Script provided as-is. Author is not responsible for its use and application. Use at your own risk.
########################################################################################################################################################################################## 

$MessageColor = "cyan"
$AssessmentColor = "magenta"

## Prompt whether to deploy the baseline mobile device mailbox policy (OPTIONAL):
Write-Host 
$Answer = Read-Host "Do you want to modify the default mobile device mailbox policy to require 4-digit passcode with encryption? Type Y or N and press Enter to continue"
if ($Answer -eq 'y' -or $Answer -eq 'yes') {
        $MobileDeviceParam= @{
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
        Set-MobileDeviceMailboxPolicy -Identity Default @MobileDeviceParam
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "The default mobile device mailbox policy has been modified"
} else {
Write-Host 
Write-Host -ForegroundColor $AssessmentColor "Default mobile device mailbox policy will not be modified; consider using Intune to setup MDM or MAM instead"
}
