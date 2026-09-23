# UL: Defender for Cloud Apps - Unsanctioned Apps Export Tool

PowerShell helpers for Microsoft Defender for Cloud Apps / Microsoft security portal workflows.

## Scripts

- `Get-MDCACookies.ps1` opens `security.microsoft.com`, extracts the required session cookies from that controlled browser session, and provides separate copy buttons for `sccauth` and `XSRF-TOKEN`.
- `Get-SanctionedMDCAApps.ps1` exports unsanctioned app/domain results in an Excel-friendly format.

## Before Running

1. Run `Get-MDCACookies.ps1` and sign in to the Microsoft security portal.
2. Copy the `sccauth` and `XSRF-TOKEN` values.
3. Paste those values into the configuration block at the top of `Get-SanctionedMDCAApps.ps1`.
4. Copy your tenant ID from https://security.microsoft.com/securitysettings/defender/session_details and add your tenant ID in the same configuration block in `Get-SanctionedMDCAApps.ps1`.
5. Run `Get-SanctionedMDCAApps.ps1` and wait for the export to complete. Depending on the number of unsanctioned apps, this can take several minutes.


## These are custom scripts and not an official Microsoft product; no support is provided by Microsoft.
