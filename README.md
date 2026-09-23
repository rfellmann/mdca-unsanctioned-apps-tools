# UL: Defender for Cloud Apps - Unsanctioned Apps Export Tool

PowerShell helpers for Microsoft Defender for Cloud Apps / Microsoft security portal workflows.

## Scripts

- `Get-SanctionedMDCAApps.ps1` exports unsanctioned app/domain results in an Excel-friendly format.
- `Get-MDCACookies.ps1` opens `security.microsoft.com`, extracts the required session cookies from that controlled browser session, and provides separate copy buttons for `sccauth` and `XSRF-TOKEN`.

## Before Running

1. Run `Get-MDCACookies.ps1` and sign in to the Microsoft security portal.
2. Copy the `sccauth` and `XSRF-TOKEN` values.
3. Paste those values into the configuration block at the top of `Get-SanctionedMDCAApps.ps1`.
4. Add your tenant ID in the same configuration block.
5. Run `Get-SanctionedMDCAApps.ps1` and wait for the export to complete. Depending on the number of unsanctioned apps, this can take several minutes.
