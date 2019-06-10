##########################################################################################################################################################################################
## Description:
## This script creates a baseline mobile device mailbox policy to require minimum 4 digit passcode and enforced device encryption
## Reference: https://docs.microsoft.com/en-us/powershell/module/exchange/devices/new-mobiledevicemailboxpolicy?view=exchange-ps
## Prerequisites:
## The tenant will need any Exchange Online plan
## Connect to Exchange Online via PowerShell using MFA:
## https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps
## 
## WARNING: Script provided as-is. Author is not responsible for its use and application. Use at your own risk.
########################################################################################################################################################################################## 


$MobileDeviceParams= @{
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

New-MobileDeviceMailboxPolicy @MobileDeviceParams



