# Get-SanctionedMDCAApps.ps1
# Read-only export of sanctioned apps from discovered apps and the Cloud App Catalog.
# Compatible with Windows PowerShell 5.1 and PowerShell 7 on Windows.
# Run Get-MDCACookies.ps1 first, then paste its cookie values and your tenant ID below.
# Never publish real cookies, tenant IDs, or customer exports.
#
# The portal's tri-state banned field uses false for sanctioned, true for banned,
# and null for untagged. An explicit sanctioned Boolean takes precedence if present.
# Unknown status schemas stop the export instead of guessing that apps are sanctioned.
# These portal proxy endpoints are not a stable public API; validate against your portal.
#
# Each page's matching results are saved immediately to one CSV in this script's folder.
# A failed run leaves a partial CSV; only the Complete message indicates completion.
# This is a custom script, not an official Microsoft product.

$sccauth = "INSERT_YOUR_SCCAUTH_COOKIE_HERE"
$xsrfToken = "INSERT_YOUR_XSRF_TOKEN_COOKIE_HERE"
$tenantId = "INSERT_YOUR_TENANT_ID_HERE"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $color = switch ($Level) {
        "ERROR" { "Red" }
        "WARNING" { "Yellow" }
        "SUCCESS" { "Green" }
        default { "White" }
    }
    Write-Host "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Message" -ForegroundColor $color
}

function Invoke-MDCAProxyApi {
    param(
        [string]$Endpoint,
        [object]$Body,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )

    $headers = @{
        "accept"       = "application/json, text/plain, */*"
        "origin"       = "https://security.microsoft.com"
        "referer"      = "https://security.microsoft.com/cloudapps/discovery"
        "tenant-id"    = $tenantId
        "x-tid"        = $tenantId
        "x-xsrf-token" = $xsrfToken -replace '%3A', ':'
    }
    $request = @{
        Uri             = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/$Endpoint"
        Method          = "POST"
        WebSession      = $Session
        Headers         = $headers
        ContentType     = "application/json; charset=utf-8"
        Body            = $Body | ConvertTo-Json -Depth 10 -Compress
        UseBasicParsing = $true
        TimeoutSec      = 120
        ErrorAction     = "Stop"
    }

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            return Invoke-RestMethod @request
        } catch {
            $statusCode = 0
            $response = $_.Exception.Response
            if ($response) {
                $statusCode = [int]$response.StatusCode
            }
            $transient = $statusCode -in @(408, 429, 500, 502, 503, 504) -or
                $_.Exception.Message -match '(?i)forcibly closed|transport connection|connection reset|timed? out|request was canceled|temporarily unavailable'
            if (-not $transient -or $attempt -eq 3) {
                throw "API request failed for $Endpoint (HTTP $statusCode). Export stopped; any existing CSV is partial. $($_.Exception.Message)"
            }

            $delaySeconds = 2 * $attempt
            $retryAfter = $null
            if ($response -and $response.Headers -is [System.Net.WebHeaderCollection]) {
                $retryAfter = $response.Headers['Retry-After']
            } elseif ($response -and $response.Headers.RetryAfter) {
                $retryAfter = $response.Headers.RetryAfter.ToString()
            }
            $retrySeconds = 0
            $retryDate = [DateTimeOffset]::MinValue
            if ([int]::TryParse([string]$retryAfter, [ref]$retrySeconds)) {
                $delaySeconds = [Math]::Max($delaySeconds, $retrySeconds)
            } elseif ([DateTimeOffset]::TryParse([string]$retryAfter, [ref]$retryDate)) {
                $delaySeconds = [Math]::Max($delaySeconds, [int][Math]::Ceiling(($retryDate - [DateTimeOffset]::UtcNow).TotalSeconds))
            }
            Write-Log "Transient failure for $Endpoint; retrying in $delaySeconds seconds (attempt $($attempt + 1) of 3)." -Level "WARNING"
            Start-Sleep -Seconds $delaySeconds
        }
    }
}

function Get-DomainsFromValue {
    param([object]$Value)

    if ($null -eq $Value) { return }
    if ($Value -is [string]) {
        $pattern = '(?i)(?:https?://)?\.?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)'
        foreach ($match in [regex]::Matches($Value, $pattern)) {
            $domain = $match.Groups[1].Value.ToLowerInvariant()
            if ($domain -notmatch '^\d+(\.\d+){3}$') { $domain }
        }
    } elseif ($Value -is [System.Collections.IEnumerable]) {
        foreach ($item in $Value) { Get-DomainsFromValue -Value $item }
    } else {
        foreach ($property in $Value.PSObject.Properties) {
            if ($property.Name -match '(?i)domain|url|host') {
                Get-DomainsFromValue -Value $property.Value
            }
        }
    }
}

function Get-AppDomains {
    param([object]$App)

    $domains = foreach ($name in @('domainList', 'allDomains', 'searchFieldList', 'instancesTopLevelDomain', 'domains', 'domain', 'website', 'homepage', 'url')) {
        if ($App.PSObject.Properties.Name -contains $name -and $App.$name) {
            Get-DomainsFromValue -Value $App.$name
        }
    }
    return @($domains | Sort-Object -Unique)
}

function Test-AppSanctioned {
    param([object]$App)

    $names = @($App.PSObject.Properties.Name)
    if ($names -contains 'sanctioned') {
        if ($null -ne $App.sanctioned -and $App.sanctioned -isnot [bool]) {
            throw "Unexpected sanctioned status type; stopping rather than misclassifying apps."
        }
        if ($App.sanctioned -eq $true -and $App.banned -is [bool] -and $App.banned) {
            throw "Conflicting sanctioned and banned statuses; stopping rather than misclassifying apps."
        }
        return ($App.sanctioned -is [bool] -and $App.sanctioned -eq $true)
    }
    if ($names -contains 'banned') {
        if ($null -ne $App.banned -and $App.banned -isnot [bool]) {
            throw "Unexpected banned status type; stopping rather than misclassifying apps."
        }
        return ($App.banned -is [bool] -and $App.banned -eq $false)
    }
    throw "Response lacks sanctioned/banned status fields. The portal API schema must be checked before exporting."
}

function Get-SanctionedAppsPage {
    param(
        [string]$Endpoint,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [int]$Skip,
        [int]$Limit = 250
    )

    # Scan unfiltered pages: do not depend on undocumented server-side status filters.
    $response = Invoke-MDCAProxyApi -Endpoint $Endpoint -Session $Session -Body @{
        filters = @{}
        skip    = $Skip
        limit   = $Limit
    }
    if ($null -eq $response -or $response.PSObject.Properties.Name -notcontains 'data' -or $null -eq $response.data) {
        throw "Invalid response for $Endpoint at offset $Skip; stopping to avoid an incomplete export."
    }
    return @($response.data)
}

function Get-SanctionedApps {
    param(
        [AllowEmptyCollection()]
        [object[]]$Apps,
        [hashtable]$MatchedAppIds,
        [string]$Source
    )

    foreach ($app in $Apps) {
        if (-not (Test-AppSanctioned -App $app)) { continue }
        if (-not $app.appId -and [string]::IsNullOrWhiteSpace([string]$app.name)) {
            throw "A sanctioned app has neither appId nor name; stopping to avoid losing its identity."
        }
        $key = if ($app.appId) { "appId:$($app.appId)" } else { "name:$($app.name)" }
        if ($MatchedAppIds.ContainsKey($key)) { continue }
        $MatchedAppIds[$key] = $true
        $domains = @(Get-AppDomains -App $app)
        [pscustomobject]@{
            name             = $app.name
            appId            = $app.appId
            Domains          = $domains -join ', '
            DomainCount      = $domains.Count
            sanctioned       = $true
            SanctionedSource = $Source
        }
    }
}

function Export-SanctionedAppsPage {
    param(
        [AllowEmptyCollection()]
        [object[]]$Records,
        [string]$CsvPath
    )

    if ($Records.Count -eq 0) { return }
    $rows = @(
        foreach ($record in $Records) {
            [pscustomobject][ordered]@{
                AppNameOrDomainGroup = $record.name
                AppId                = $record.appId
                Source               = $record.SanctionedSource
                DomainCount          = $record.DomainCount
                Domains              = $record.Domains
            }
        }
    )
    $append = Test-Path -LiteralPath $CsvPath
    $rows | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8 -Append:$append -ErrorAction Stop
    Write-Log "Saved $($rows.Count) sanctioned apps to $CsvPath" -Level "SUCCESS"
    try {
        $rows | ConvertTo-Csv -NoTypeInformation -Delimiter "`t" | Set-Clipboard -ErrorAction Stop
    } catch {
        Write-Log "CSV saved, but clipboard update failed: $($_.Exception.Message)" -Level "WARNING"
    }
}

# MAIN EXECUTION
$startTime = Get-Date
foreach ($entry in @{ sccauth = $sccauth; xsrfToken = $xsrfToken; tenantId = $tenantId }.GetEnumerator()) {
    if ([string]::IsNullOrWhiteSpace($entry.Value) -or $entry.Value -like 'INSERT_YOUR_*') {
        throw "Set $($entry.Key) in the configuration block before running this script."
    }
}

$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
$session.Cookies.Add([System.Net.Cookie]::new("sccauth", $sccauth, "/", "security.microsoft.com"))
$session.Cookies.Add([System.Net.Cookie]::new("XSRF-TOKEN", $xsrfToken, "/", "security.microsoft.com"))
$csvPath = Join-Path $PSScriptRoot "MDCA_SanctionedApps_$(Get-Date -Format 'yyyyMMdd_HHmmss_fff').csv"
$matchedAppIds = @{}
$allResults = [System.Collections.Generic.List[object]]::new()
$pageLimit = 250
$processed = 0

Write-Log "===== Retrieving sanctioned apps (read-only) ====="
try {
    foreach ($source in @(
        @{ Name = 'DiscoveredApps'; Endpoint = 'discovery/discovered_apps/' },
        @{ Name = 'CloudAppCatalog'; Endpoint = 'discovery/app_catalog/' }
    )) {
        $skip = 0
        while ($true) {
            Write-Progress -Id 1 -Activity "Scanning $($source.Name)" -Status "Requesting offset $skip; $($allResults.Count) sanctioned apps found"
            $apps = @(Get-SanctionedAppsPage -Endpoint $source.Endpoint -Session $session -Skip $skip -Limit $pageLimit)
            if ($apps.Count -eq 0) { break }
            $processed += $apps.Count
            $results = @(Get-SanctionedApps -Apps $apps -MatchedAppIds $matchedAppIds -Source $source.Name)
            Export-SanctionedAppsPage -Records $results -CsvPath $csvPath
            foreach ($result in $results) { $allResults.Add($result) }
            Write-Log "$($source.Name): processed $($apps.Count) apps at offset $skip; $($results.Count) new sanctioned apps."
            # Advance by actual count so server-side page caps do not truncate the scan.
            $skip += $apps.Count
        }
    }
} catch {
    Write-Log "Export failed. Any CSV already written is partial: $csvPath" -Level "ERROR"
    throw
} finally {
    Write-Progress -Id 1 -Activity "Scanning sanctioned apps" -Completed
}

Write-Log "===== Complete: $($allResults.Count) sanctioned apps; $processed source records scanned; $([Math]::Round(((Get-Date) - $startTime).TotalSeconds, 1)) seconds =====" -Level "SUCCESS"
if ($allResults.Count -gt 0) {
    Write-Log "Consolidated CSV: $csvPath" -Level "SUCCESS"
} else {
    Write-Log "No sanctioned apps found; no CSV was created." -Level "WARNING"
}
$allResults.ToArray()
