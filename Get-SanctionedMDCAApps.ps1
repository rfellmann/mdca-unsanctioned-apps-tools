# Get-SanctionedMDCAApps.ps1
# Read-only export of sanctioned apps from discovered apps and the Cloud App Catalog.
# Compatible with Windows PowerShell 5.1 and PowerShell 7 on Windows.
# Run Get-MDCACookies.ps1 first, then paste its cookie values and your tenant ID below.
# Never publish real cookies, tenant IDs, or customer exports.
#
# Membership in the global sanctioned-domain export identifies sanctioned apps.
# Explicit sanctioned flags/tags also qualify; banned:false alone does not.
# These portal proxy endpoints are not a stable public API; validate against your portal.
#
# Discovery-page matches are saved immediately; remaining domains are saved after catalog resolution.
# All results use one CSV in this script's folder.
# Domain export approach: https://github.com/mattnovitsch/M365/blob/main/MDA/MDA-SanctionedApps-Template.ps1
# A failed run leaves a partial CSV; only the Complete message indicates completion.
# This is a custom script, not an official Microsoft product.

$sccauth = "INSERT_YOUR_SCCAUTH_COOKIE_HERE"
$xsrfToken = "INSERT_YOUR_XSRF_TOKEN_COOKIE_HERE"
$tenantId = "INSERT_YOUR_TENANT_ID_HERE"

$catalogLookupConcurrency = 4

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
    if ($names -contains 'tags') {
        foreach ($tag in @($App.tags)) {
            if ($tag -is [string] -and $tag -ieq 'sanctioned') {
                return $true
            }
        }
    }
    return $false
}

function Get-SanctionedDomains {
    param([Microsoft.PowerShell.Commands.WebRequestSession]$Session)

    Write-Log "Retrieving the global sanctioned-domain list..."
    $text = Invoke-MDCAProxyTextApi -Endpoint 'discovery_block_scripts/?format=102&type=sanctioned' -Session $Session -ApiBasePaths @('api', 'api/v1')
    if ($null -eq $text) {
        throw "Unable to retrieve sanctioned domains. Export stopped rather than guessing app status."
    }
    if ($text -match '(?i)<html|<!doctype|^\s*[\{\[]') {
        throw "The sanctioned-domain endpoint returned an unexpected response instead of a domain script."
    }
    $domains = @(Convert-BlockScriptToDomains -BlockScript $text)
    if (-not [string]::IsNullOrWhiteSpace($text) -and $domains.Count -eq 0) {
        throw "The sanctioned-domain response was nonempty but contained no recognized domain rules. Check the portal export format."
    }
    Write-Log "Retrieved $($domains.Count) sanctioned domains." -Level SUCCESS
    return $domains
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
        [hashtable]$MatchedDomains,
        [hashtable]$DomainIndex,
        [string]$Source
    )

    foreach ($app in $Apps) {
        $appDomains = @(Get-AppDomains -App $app)
        $matches = @(Get-MatchingBlockDomains -AppDomains $appDomains -BlockDomainIndex $DomainIndex)
        if ($matches.Count -eq 0 -and -not (Test-AppSanctioned -App $app)) { continue }
        foreach ($domain in $matches) { $MatchedDomains[$domain] = $true }
        if (-not $app.appId -and [string]::IsNullOrWhiteSpace([string]$app.name)) {
            throw "A sanctioned app has neither appId nor name; stopping to avoid losing its identity."
        }
        $key = if ($app.appId) { "appId:$($app.appId)" } else { "name:$($app.name)" }
        if ($MatchedAppIds.ContainsKey($key)) { continue }
        $MatchedAppIds[$key] = $true
        $domains = if ($matches.Count -gt 0) { $matches } else { $appDomains }
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

function Get-RemainingSanctionedApps {
    param(
        [string[]]$Domains,
        [hashtable]$MatchedDomains,
        [hashtable]$MatchedAppIds,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [ValidateRange(1, 8)]
        [int]$Concurrency = 4
    )

    $remaining = @($Domains | Where-Object { -not $MatchedDomains.ContainsKey($_) })
    $groups = @{}
    Get-CatalogAppsByDomain -Domains $remaining -Session $Session -Concurrency $Concurrency | ForEach-Object {
        $domain = $_.Domain
        $app = $_.App
        $key = if ($app.appId) { "appId:$($app.appId)" } else { "domain:$domain" }
        if (-not $groups.ContainsKey($key)) {
            $groups[$key] = @{
                App = $app
                Domains = [System.Collections.Generic.List[string]]::new()
            }
        }
        $groups[$key].Domains.Add($domain)
        $MatchedDomains[$domain] = $true
    }
    foreach ($key in $groups.Keys) {
        if ($MatchedAppIds.ContainsKey($key)) { continue }
        $MatchedAppIds[$key] = $true
        $group = $groups[$key]
        $domainsForApp = @($group.Domains | Sort-Object -Unique)
        [pscustomobject]@{
            name = if ($group.App.appId) { $group.App.name } else { $domainsForApp[0] }
            appId = $group.App.appId
            Domains = $domainsForApp -join ', '
            DomainCount = $domainsForApp.Count
            sanctioned = $true
            SanctionedSource = if ($group.App.appId) { 'CloudAppCatalog' } else { 'GlobalSanctionedDomain' }
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

function Invoke-MDCAProxyTextApi {
    param(
        [string]$Endpoint,
        [string]$Method = "GET",
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [string[]]$ApiBasePaths = @("api/v1")
    )

    $xsrfHeader = $xsrfToken -replace '%3A', ':'

    $headers = @{
        "accept"            = "text/plain, */*"
        "accept-language"   = "en-US,en;q=0.9"
        "origin"            = "https://security.microsoft.com"
        "referer"           = "https://security.microsoft.com/cloudapps/discovery"
        "sec-fetch-dest"    = "empty"
        "sec-fetch-mode"    = "cors"
        "sec-fetch-site"    = "same-origin"
        "tenant-id"         = $tenantId
        "x-tid"             = $tenantId
        "x-xsrf-token"      = $xsrfHeader
    }

    $lastError = $null

    foreach ($apiBasePath in $ApiBasePaths) {
        $uri = "https://security.microsoft.com/apiproxy/mcas/cas/$apiBasePath/$Endpoint"

        try {
            $params = @{
                Uri              = $uri
                Method           = $Method
                WebSession       = $Session
                Headers          = $headers
                UseBasicParsing  = $true
                TimeoutSec       = 120
                ErrorAction      = "Stop"
            }

            return (Invoke-WebRequest @params).Content
        }
        catch {
            $lastError = $_
            $errorMsg = $_.Exception.Message
            if ($_.Exception.Response) {
                $errorMsg += " - $($_.Exception.Response.StatusCode)"
            }
            Write-Log "Text API call failed for $apiBasePath/$Endpoint : $errorMsg" -Level "WARNING"
        }
    }

    if ($lastError) {
        Write-Log "Text API call failed for all known proxy paths for $Endpoint" -Level "ERROR"
    }
    return $null
}

function Convert-BlockScriptToDomains {
    param([string]$BlockScript)

    if ([string]::IsNullOrWhiteSpace($BlockScript)) {
        return @()
    }

    $domainPattern = '(?i)url\.domain=([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)'
    return @([regex]::Matches($BlockScript, $domainPattern) |
        ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() } |
        Where-Object { $_ -ne 'url.domain' -and $_ -notmatch '^\d+(\.\d+){3}$' } |
        Sort-Object -Unique)
}

function Get-AppCatalogAppByDomain {
    param(
        [string]$Domain,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )

    if ([string]::IsNullOrWhiteSpace($Domain)) {
        return $null
    }

    $normalizedDomain = $Domain.ToLowerInvariant().Trim()
    $body = @{
        "filters" = @{
            "domainList" = @{
                "eq" = $normalizedDomain
            }
        }
        "skip"  = 0
        "limit" = 1
    }

    $response = Invoke-MDCAProxyApi -Endpoint "discovery/app_catalog/" -Method "POST" -Body $body -Session $Session
    if ($null -eq $response) {
        throw "Cloud App Catalog lookup failed for a blocked domain; see the API error above."
    }
    if ($response.PSObject.Properties.Name -notcontains 'data') {
        throw "The Cloud App Catalog lookup response did not contain a data field."
    }

    if ($response.data.Count -gt 0) {
        return @($response.data)[0]
    }

    return $null
}

function New-BlockDomainIndex {
    param(
        [AllowEmptyCollection()]
        [string[]]$BlockDomains
    )

    $index = @{
        Exact       = @{}
        Descendants = @{}
    }

    foreach ($domain in $BlockDomains) {
        $normalizedDomain = $domain.ToLowerInvariant()
        if ($index.Exact.ContainsKey($normalizedDomain)) {
            continue
        }
        $index.Exact[$normalizedDomain] = $true
        $suffix = $normalizedDomain

        while ($true) {
            if (-not $index.Descendants.ContainsKey($suffix)) {
                $index.Descendants[$suffix] = [System.Collections.Generic.List[string]]::new()
            }
            $index.Descendants[$suffix].Add($normalizedDomain)

            $dot = $suffix.IndexOf('.')
            if ($dot -lt 0) {
                break
            }
            $suffix = $suffix.Substring($dot + 1)
        }
    }

    return $index
}

function Get-MatchingBlockDomains {
    param(
        [AllowEmptyCollection()]
        [string[]]$AppDomains,
        [hashtable]$BlockDomainIndex
    )

    $matches = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($domain in $AppDomains) {
        $suffix = $domain.ToLowerInvariant()
        if ($BlockDomainIndex.Descendants.ContainsKey($suffix)) {
            foreach ($blockedDomain in $BlockDomainIndex.Descendants[$suffix]) {
                $null = $matches.Add($blockedDomain)
            }
        }

        while ($true) {
            if ($BlockDomainIndex.Exact.ContainsKey($suffix)) {
                $null = $matches.Add($suffix)
            }
            $dot = $suffix.IndexOf('.')
            if ($dot -lt 0) {
                break
            }
            $suffix = $suffix.Substring($dot + 1)
        }
    }

    return @($matches | Sort-Object)
}

function Get-CatalogAppsByDomain {
    param(
        [AllowEmptyCollection()]
        [string[]]$Domains,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [ValidateRange(1, 8)]
        [int]$Concurrency = 4
    )

    if ($Domains.Count -eq 0) {
        return
    }

    $state = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    foreach ($functionName in @('Invoke-MDCAProxyApi', 'Get-AppCatalogAppByDomain')) {
        $definition = (Get-Item "Function:\$functionName").Definition
        $state.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new($functionName, $definition))
    }
    $state.Commands.Add([System.Management.Automation.Runspaces.SessionStateFunctionEntry]::new('Write-Log', {
        param([string]$Message, [string]$Level = 'INFO')
        Write-Warning "[$Level] $Message"
    }.ToString()))

    $cookieDefinitions = @(
        foreach ($cookie in $Session.Cookies.GetCookies([Uri]'https://security.microsoft.com')) {
            [pscustomobject]@{
                Name   = $cookie.Name
                Value  = $cookie.Value
                Path   = $cookie.Path
                Domain = $cookie.Domain
            }
        }
    )
    foreach ($entry in @{
        tenantId          = $tenantId
        xsrfToken         = $xsrfToken
        CatalogCookies    = $cookieDefinitions
        CatalogUserAgent  = $Session.UserAgent
    }.GetEnumerator()) {
        $state.Variables.Add([System.Management.Automation.Runspaces.SessionStateVariableEntry]::new($entry.Key, $entry.Value, ''))
    }

    $worker = {
        param([string]$Domain)
        # Each runspace reuses its own session; cookie containers are not shared.
        if (-not $script:CatalogSession) {
            $script:CatalogSession = New-Object Microsoft.PowerShell.Commands.WebRequestSession
            $script:CatalogSession.UserAgent = $CatalogUserAgent
            foreach ($cookie in $CatalogCookies) {
                $script:CatalogSession.Cookies.Add([System.Net.Cookie]::new($cookie.Name, $cookie.Value, $cookie.Path, $cookie.Domain))
            }
        }
        [pscustomobject]@{
            Domain = $Domain
            App    = Get-AppCatalogAppByDomain -Domain $Domain -Session $script:CatalogSession
        }
    }

    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $Concurrency, $state, $Host)
    $jobs = [System.Collections.Generic.List[object]]::new()
    $nextDomain = 0
    $completed = 0

    try {
        $pool.Open()
        while ($nextDomain -lt $Domains.Count -or $jobs.Count -gt 0) {
            while ($nextDomain -lt $Domains.Count -and $jobs.Count -lt $Concurrency) {
                $pipeline = [System.Management.Automation.PowerShell]::Create()
                $pipeline.RunspacePool = $pool
                $null = $pipeline.AddScript($worker.ToString()).AddArgument($Domains[$nextDomain])
                try {
                    $handle = $pipeline.BeginInvoke()
                } catch {
                    $pipeline.Dispose()
                    throw
                }
                $jobs.Add([pscustomobject]@{
                    Domain   = $Domains[$nextDomain]
                    Pipeline = $pipeline
                    Handle   = $handle
                })
                $nextDomain++
            }

            $readyJobs = @($jobs | Where-Object { $_.Handle.IsCompleted })
            if ($readyJobs.Count -eq 0) {
                $handles = [System.Threading.WaitHandle[]]@($jobs | ForEach-Object { $_.Handle.AsyncWaitHandle })
                $null = [System.Threading.WaitHandle]::WaitAny($handles, 1000)
                continue
            }

            foreach ($job in $readyJobs) {
                try {
                    $result = @($job.Pipeline.EndInvoke($job.Handle))
                    if ($job.Pipeline.HadErrors -or $result.Count -ne 1) {
                        throw "Catalog worker failed or returned an unexpected result."
                    }
                    $result[0]
                } catch {
                    throw "Cloud App Catalog lookup failed for $($job.Domain); stopping to avoid an incomplete export. $($_.Exception.Message)"
                } finally {
                    $job.Pipeline.Dispose()
                    $null = $jobs.Remove($job)
                }
                $completed++
                Write-Progress -Id 2 -Activity 'Resolving blocked domains' -Status "$completed of $($Domains.Count) checked ($Concurrency workers)" -PercentComplete ([int](100 * $completed / $Domains.Count))
            }
        }
    } finally {
        foreach ($job in $jobs) {
            try {
                $job.Pipeline.Stop()
            } finally {
                $job.Pipeline.Dispose()
            }
        }
        $pool.Dispose()
        Write-Progress -Id 2 -Activity 'Resolving blocked domains' -Completed
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
$matchedDomains = @{}
$allResults = [System.Collections.Generic.List[object]]::new()
$pageLimit = 250
$processed = 0

Write-Log "===== Retrieving sanctioned apps (read-only) ====="
try {
    $sanctionedDomains = @(Get-SanctionedDomains -Session $session)
    $domainIndex = New-BlockDomainIndex -BlockDomains $sanctionedDomains
    foreach ($source in @(
        @{ Name = 'DiscoveredApps'; Endpoint = 'discovery/discovered_apps/' }
    )) {
        $skip = 0
        while ($true) {
            Write-Progress -Id 1 -Activity "Scanning $($source.Name)" -Status "Requesting offset $skip; $($allResults.Count) sanctioned apps found"
            $apps = @(Get-SanctionedAppsPage -Endpoint $source.Endpoint -Session $session -Skip $skip -Limit $pageLimit)
            if ($apps.Count -eq 0) { break }
            $processed += $apps.Count
            $results = @(Get-SanctionedApps -Apps $apps -MatchedAppIds $matchedAppIds -MatchedDomains $matchedDomains -DomainIndex $domainIndex -Source $source.Name)
            Export-SanctionedAppsPage -Records $results -CsvPath $csvPath
            foreach ($result in $results) { $allResults.Add($result) }
            Write-Log "$($source.Name): processed $($apps.Count) apps at offset $skip; $($results.Count) new sanctioned apps."
            # Advance by actual count so server-side page caps do not truncate the scan.
            $skip += $apps.Count
        }
    }
    $remaining = @(Get-RemainingSanctionedApps -Domains $sanctionedDomains -MatchedDomains $matchedDomains -MatchedAppIds $matchedAppIds -Session $session -Concurrency $catalogLookupConcurrency)
    Export-SanctionedAppsPage -Records $remaining -CsvPath $csvPath
    foreach ($result in $remaining) { $allResults.Add($result) }
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
