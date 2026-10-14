# UL: Defender for Cloud Apps - Unsanctioned Apps Bulk Export Script

PowerShell helpers for Microsoft Defender for Cloud Apps / Microsoft security portal workflows.

## Scripts

- `Get-MDCACookies.ps1` opens `security.microsoft.com`, extracts the required session cookies from that controlled browser session, and provides separate copy buttons for `sccauth` and `XSRF-TOKEN`.
- `Get-UnsanctionedMDCAApps.ps1` authenticates against the MCAS v1 API using the extracted session cookies and exports unsanctioned app/domain results in an Excel-friendly format.

## Before Running

1. Run `Get-MDCACookies.ps1` and sign in to the Microsoft security portal.
2. Copy the `sccauth` and `XSRF-TOKEN` values.
3. Paste those values into the configuration block at the top of `Get-UnsanctionedMDCAApps.ps1`.
4. Copy your tenant ID from https://security.microsoft.com/securitysettings/defender/session_details and add your tenant ID in the same configuration block in `Get-UnsanctionedMDCAApps.ps1`.
5. Run `Get-UnsanctionedMDCAApps.ps1` and wait for the export to complete. Depending on the number of discovered apps and unmatched blocked domains, this can take several minutes. A CSV file will be saved in the script's folder.

## Performance and Output

- Domain matching uses an index instead of scanning every blocked domain for each discovered app. Exact and parent/subdomain matching rules are preserved.
- Unmatched blocked domains are resolved against the Cloud App Catalog with up to four concurrent requests. Set `$catalogLookupConcurrency` near the top of the script to `2` or `1` if throttling is frequent; the supported range is `1` through `8`.
- Transient JSON API failures are retried up to three total attempts, honoring the service's `Retry-After` header when supplied.
- Discovered apps are still retrieved sequentially in pages of 250. Results are exported in batches of 250 to one timestamped CSV; the final partial batch is also exported.
- Failed page or catalog requests stop the run to avoid silently omitting results. CSV batches already written remain on disk and must be treated as partial if the run fails.
- The script remains read-only and supports Windows PowerShell 5.1 and PowerShell 7 on Windows.

Never commit real authentication cookies, tenant IDs, or generated customer exports. Use fresh cookies from the helper when the session expires.

## Support Statement
- These are custom scripts and not an official Microsoft product; no support is provided by Microsoft. MDCA API capabilities used by this script might change over time.
