## Incident Response Scripts

I have found these scripts to be useful during Incident Response in Microsoft 365.

<b>1) Start-AzureADIRCollection.ps1:</b> Use this script to begin a collection of data against a tenant. You must have the AzureADIncidentResponse module installed.

<b>2) Start-UnifiedAuditLogIRCollection.ps1:</b> Use this script to get interesting events exported from the Unified Audit Log. You must have the ExchangeOnlineManagement module installed.

<b>3) Investigate-PrivilegedUserSignIn.ps1:</b> Use this script to investigate the sign-in activities from privileged user accounts. You must have the AzureADIncidentResponse module installed.

<b>4) Investigate-PrivilegedUserActivities.ps1:</b> Use this script to investigate the Azure AD audit log for activities performed by privileged users. You must have the AzureADIncidentResponse module installed.

<b>5) Investigate-UserSignInHistory.ps1:</b> Use this script to get available sign-in data for the specified username. You must have the AzureADIncidentResponse module installed.

<b>6) Investigate-UserActivityHistory.ps1:</b> Use this script to get activities from the Unified audit log for the specified username. You must have the ExchangeOnlineManagement module.  
  
<b>7) Investigate-SignInByIpAddress.ps1:</b> Use this script to get available sign-in data for the specified IP address. You must have the AzureADIncidentResponse module installed. 

<b>8) Remediate-CompromisedUser.ps1:</b> Use this script to disable and revoke access, and reset a user's password (and optionally re-enable access). You must have the AzureAD module installed.

