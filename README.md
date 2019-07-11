# Microsoft-365
Scripts and other resources to help configure Microsoft 365 

<b><u>Azure AD Best Practices Checklist</b></u>: Settings that I recommend reviewing for every Microsoft 365 tenant, with criticality/heat map indicating relative importance/impact of each item.

<b><u>Recommended Conditional access policies</b></u>: Adapted from Microsoft's own recommendations, I believe I have improved and simplified the design somewhat for those who just want to implement a good baseline without a lot of complexity.

<b><u>Recommended Conditional access policy design</b></u>: This describes in a single page the settings within each of the recommended Conditonal access policies from above

<b><u>Intune Best Practices Checklist</b></u>: Device management done right. In a similar format to the Azure AD checklist, this lays out all of the items that I would recommend for every single Microsoft 365 implementation; i.e. What does "good" look like? It looks like this.

<a href="https://www.itpromentor.com/email-security-checklist/"> <b><u>The Office 365 Email Security Checklist</b></u></a>: For anyone with an Exchange Online subscription for Email hosted in Office 365, start here. Scripts from this guide are located in the Exchange Online folder.

<a href="https://www.itpromentor.com/setup-intune/"><b><u>The Intune Setup scripts</b></u></a>: The Intune scripts are (mostly) taken and modified from Microsoft: https://github.com/microsoftgraph/powershell-intune-samples/ ; 
None of the policies will be assigned when you first import the JSON files; simply review, adjust and test the settings out before assigning them. See more details in the "Setup Intune" folder's readme file.
