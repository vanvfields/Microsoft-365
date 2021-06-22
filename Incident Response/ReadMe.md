## Incident Response Scripts

I have found these scripts to be useful during Incident Response in Microsoft 365.

<b>1) Start-AzureADIRCollection.ps1:</b> Use this script to begin a collection of data against a tenant. You must have the AzureADIncidentResponse module installed.

<b>2) Start-UnifiedAuditLogIRCollection.ps1:</b> Use this script to get interesting events exported from the Unified Audit Log. You must have the ExchangeOnlineManagement module installed.

<b>3) Export-PrivilegedUserSignIn.ps1:</b> Use this script to investigate the sign-in activities from privileged user accounts. You must have the AzureADIncidentResponse module installed.

<b>4) Export-PrivilegedUserActions.ps1:</b> Use this script to investigate the Azure AD audit log for activities performed by privileged users. You must have the AzureADIncidentResponse module installed.

<b>5) Export-SignInByUser.ps1:</b> Use this script to get available sign-in data for the specified username. You must have the AzureADIncidentResponse module installed.

<b>6) Export-SignInByIpAddress.ps1:</b> Use this script to get available sign-in data for the specified IP address. You must have the AzureADIncidentResponse module installed. 

<b>7) Export-ActivityByUser.ps1:</b> Use this script to get activities from the Unified audit log for the specified username. You must have the ExchangeOnlineManagement module installed.  
  
<b>8) Export-ActivityByIpAddress.ps1:</b> Use this script to get available sign-in data for the specified IP address. You must have the ExchangeOnlineManagement module installed. 

<b>9) Install-AzureADProtectionAlerts.ps1:</b> Use this script to import alert policies for Azure AD monitoring. You must have the ExchangeOnlineManagement module installed.

<b>10) Remediate-CompromisedUser.ps1:</b> Use this script to disable and revoke access, and/or reset a user's password and re-enable access. You must have the AzureAD module installed. There is also an option to reset all admin passwords at once, excluding breakglass and current user account (this option requires the AzureADIncidentResponse module).

