## Script by Alex Fields, ITProMentor.com
## Description:
## This script will block the ability for users to connect to Consumer cloud storage locations via OWA
## Prerequisites:
## The tenant will require any Exchange Online plan
## Connect to Exchange Online via PowerShell using MFA:
## https://docs.microsoft.com/en-us/powershell/exchange/exchange-online/connect-to-exchange-online-powershell/mfa-connect-to-exchange-online-powershell?view=exchange-ps
## WARNING: Script provided as-is. Author is not responsible for its use and application. Use at your own risk.

$MessageColor = "cyan"
$AssessmentColor = "magenta"

$OwaPolicy = Get-OwaMailboxPolicy -Identity OwaMailboxPolicy-Default
if ($OwaPolicy.AdditionalStorageProvidersAvailable) {
    Write-Host 
    Write-Host -ForegroundColor $AssessmentColor "Connecting consumer storage locations like GoogleDrive and OneDrive (personal) are currently enabled by the default OWA policy"
    Write-Host 
    $Answer = Read-Host "Do you want to block outside storage locations like GoogleDrive or consumer OneDrive in the default OWA policy? Type Y or N and press Enter to continue"
    if ($Answer -eq 'y'-or $Answer -eq 'yes') {
        Get-OwaMailboxPolicy | Set-OwaMailboxPolicy -AdditionalStorageProvidersAvailable $False
        Write-Host 
        Write-Host -ForegroundColor $MessageColor "Consumer storage locations like GoogleDrive and OneDrive (personal) are now disabled"
    } Else {
        Write-Host
        Write-Host -ForegroundColor $AssessmentColor "Consumer storage locations like GoogleDrive and OneDrive (personal) have not been disabled"
        }
} Else {
Write-Host
Write-Host -ForegroundColor $MessageColor "Consumer storage locations like GoogleDrive and OneDrive (personal) are already disabled"
}
