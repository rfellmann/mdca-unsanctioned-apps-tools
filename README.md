# Defender for Cloud Apps - Sanctioned and Unsanctioned App Exports

PowerShell helpers for Microsoft Defender for Cloud Apps / Microsoft security portal workflows.

## Scripts

- `Get-MDCACookies.ps1` opens `security.microsoft.com`, extracts the required session cookies from that controlled browser session, and provides separate copy buttons for `sccauth` and `XSRF-TOKEN`.
- `Get-UnsanctionedMDCAApps.ps1` authenticates against the MCAS v1 API using the extracted session cookies and exports unsanctioned app/domain results in an Excel-friendly format.
- `Get-SanctionedMDCAApps.ps1` uses the same cookie authentication to match discovered apps against the global sanctioned-domain export, resolve remaining domains through the Cloud App Catalog, and deduplicate by app ID.

## Before Running

1. Run `Get-MDCACookies.ps1` and sign in to the Microsoft security portal.
2. Copy the `sccauth` and `XSRF-TOKEN` values.
3. Paste those values into the configuration block of the export script you want to run.
4. Copy your tenant ID from https://security.microsoft.com/securitysettings/defender/session_details and add it to the same configuration block.
5. Run `Get-UnsanctionedMDCAApps.ps1` or `Get-SanctionedMDCAApps.ps1` and wait for the Complete message. A timestamped CSV is saved in the script's folder when matching results are found.

## Unsanctioned Export: Performance and Output

- Domain matching uses an index instead of scanning every blocked domain for each discovered app. Exact and parent/subdomain matching rules are preserved.
- Unmatched blocked domains are resolved against the Cloud App Catalog with up to four concurrent requests. Set `$catalogLookupConcurrency` near the top of the script to `2` or `1` if throttling is frequent; the supported range is `1` through `8`.
- Transient JSON API failures are retried up to three total attempts, honoring the service's `Retry-After` header when supplied.
- Discovered apps are still retrieved sequentially in pages of 250. Results are exported in batches of 250 to one timestamped CSV; the final partial batch is also exported.
- Failed page or catalog requests stop the run to avoid silently omitting results. CSV batches already written remain on disk and must be treated as partial if the run fails.
- The script remains read-only and supports PowerShell 7 on Windows. Windows PowerShell 5.1 is not supported.

Never commit real authentication cookies, tenant IDs, or generated customer exports. Use fresh cookies from the helper when the session expires.

## Sanctioned Export

- Retrieves the global sanctioned-domain list using `discovery_block_scripts/?format=102&type=sanctioned`, then matches discovered-app pages against a suffix index. Missing `sanctioned`/`banned` fields no longer stop matching.
- Domain-list membership, an explicit Boolean `sanctioned: true`, or a string `SANCTIONED` tag identifies a sanctioned result. `banned: false` alone is not treated as proof of sanctioning.
- Resolves remaining sanctioned domains with up to four concurrent Cloud App Catalog workers. Set `$catalogLookupConcurrency` to `2` or `1` if throttling is frequent (supported range: `1` through `8`).
- Sanctioned domains with no catalog match are retained as `GlobalSanctionedDomain` rows with no app ID; these are domain records, not confirmed catalog apps.
- Matching results from each discovery page are immediately appended to `MDCA_SanctionedApps_<timestamp>.csv`. Remaining domain results are appended after all catalog lookups finish. The columns are `AppNameOrDomainGroup`, `AppId`, `Source`, `DomainCount`, and `Domains`; each exported set is also copied to the clipboard.
- Failed runs leave partial CSV files. Only the Complete message indicates that discovery and catalog resolution finished.
- The sanctioned-domain endpoint approach is demonstrated by this [public implementation](https://github.com/mattnovitsch/M365/blob/main/MDA/MDA-SanctionedApps-Template.ps1), but is not yet verified against the customer's live tenant. Compare the export with the portal before relying on it; unexpected nonempty domain-export formats stop the run.
- The script is read-only and supports PowerShell 7 on Windows. Windows PowerShell 5.1 is not supported.

## Support Statement
- These are custom scripts and not an official Microsoft product; no support is provided by Microsoft. MDCA API capabilities used by this script might change over time.
