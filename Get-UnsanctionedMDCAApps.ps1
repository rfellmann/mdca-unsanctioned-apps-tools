# Get-UnsanctionedMDCAApps.ps1
#
# Capabilities:
# - Connects to Microsoft Defender for Cloud Apps through security.microsoft.com cookie authentication.
# - Retrieves unsanctioned/banned cloud app entries and resolves domains against the Cloud App Catalog where possible.
# - Groups domains into Excel-friendly rows and exports CSV/TSV output for review.
#
# Safety:
# - Read-only: this script does not sanction, unsanction, delete, or modify any apps.
# - This is a custom script and is not an official Microsoft product; no support is provided by Microsoft.
# - Do not commit real sccauth, XSRF-TOKEN, tenant, or customer-specific values.

# ====================================================================
# CONFIGURATION - PASTE YOUR VALUES BELOW
# ====================================================================
# Paste only the cookie values here, not the cookie names.
# Example: if the browser shows sccauth=abc123; paste only abc123.
# Get these from the same browser session where you are signed in to https://security.microsoft.com.

# security.microsoft.com sccauth cookie value
$sccauth = ""

# security.microsoft.com XSRF-TOKEN cookie value
$xsrfToken = ""

# Your Tenant ID
$tenantId = ""

# Log file 
$LogFile = "$PSScriptRoot\MDCA_UnsanctionedApps_Log_$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"

# OPTIMIZATION: Cache for app lookups
$script:AppCache = @{}
$script:AppCacheLoaded = $false
$script:AllApps = @()
$script:AllCatalogApps = @()
$script:CatalogDomainCache = @{}

# Function to write log
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $LogFile -Value $logMessage
    
    switch ($Level) {
        "ERROR"   { Write-Host $logMessage -ForegroundColor Red }
        "SUCCESS" { Write-Host $logMessage -ForegroundColor Green }
        "WARNING" { Write-Host $logMessage -ForegroundColor Yellow }
        default   { Write-Host $logMessage -ForegroundColor White }
    }
}

# Function to call MDCA API via security.microsoft.com proxy
function Invoke-MDCAProxyApi {
    param(
        [string]$Endpoint,
        [string]$Method = "POST",
        [object]$Body = $null,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    
    $xsrfHeader = $xsrfToken -replace '%3A', ':'
    
    $headers = @{
        "accept"            = "application/json, text/plain, */*"
        "accept-language"   = "en-US,en;q=0.9"
        "content-type"      = "application/json; charset=utf-8"
        "origin"            = "https://security.microsoft.com"
        "referer"           = "https://security.microsoft.com/cloudapps/discovery"
        "sec-ch-ua"         = "`"Not A(Brand`";v=`"99`", `"Microsoft Edge`";v=`"131`", `"Chromium`";v=`"131`""
        "sec-ch-ua-mobile"  = "?0"
        "sec-ch-ua-platform" = "`"Windows`""
        "sec-fetch-dest"    = "empty"
        "sec-fetch-mode"    = "cors"
        "sec-fetch-site"    = "same-origin"
        "tenant-id"         = $tenantId
        "x-tid"             = $tenantId
        "x-xsrf-token"      = $xsrfHeader
    }
    
    $uri = "https://security.microsoft.com/apiproxy/mcas/cas/api/v1/$Endpoint"
    
    $jsonBody = if ($Body) { $Body | ConvertTo-Json -Depth 10 -Compress } else { '{}' }
    $params = @{
        Uri              = $uri
        Method           = $Method
        WebSession       = $Session
        Headers          = $headers
        Body             = $jsonBody
        UseBasicParsing  = $true
        TimeoutSec       = 120
        ErrorAction      = "Stop"
    }

    for ($attempt = 1; $attempt -le 3; $attempt++) {
        try {
            return Invoke-RestMethod @params
        }
        catch {
            $errorMsg = $_.Exception.Message
            $statusCode = 0
            if ($_.Exception.Response) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                $errorMsg += " - $($_.Exception.Response.StatusCode)"
            }

            $transientStatus = $statusCode -in @(408, 429, 500, 502, 503, 504)
            $transientTransport = $errorMsg -match '(?i)forcibly closed|transport connection|connection reset|timed? out|request was canceled|temporarily unavailable'
            if (($transientStatus -or $transientTransport) -and $attempt -lt 3) {
                $delaySeconds = 2 * $attempt
                Write-Log "Transient API failure for $Endpoint; retrying in $delaySeconds seconds (attempt $($attempt + 1) of 3)." -Level "WARNING"
                Start-Sleep -Seconds $delaySeconds
                continue
            }

            Write-Log "API call failed for $Endpoint : $errorMsg" -Level "ERROR"
            return $null
        }
    }
}

# Function to call MDCA API endpoints that return plain text instead of JSON
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

function Get-DomainsFromValue {
    param([object]$Value)
    
    if ($null -eq $Value) {
        return @()
    }
    
    if ($Value -is [string]) {
        $domainPattern = '(?i)(?:https?://)?\.?([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)'
        return @([regex]::Matches($Value, $domainPattern) |
            ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() } |
            Where-Object { $_ -notmatch '^\d+(\.\d+){3}$' })
    }
    
    if ($Value -is [System.Collections.IEnumerable] -and $Value -isnot [string]) {
        $domains = @()
        foreach ($item in $Value) {
            $domains += @(Get-DomainsFromValue -Value $item)
        }
        return $domains
    }
    
    if ($Value.PSObject -and $Value.PSObject.Properties.Count -gt 0) {
        $domains = @()
        foreach ($property in $Value.PSObject.Properties) {
            if ($property.Name -match '(?i)domain|url|host') {
                $domains += @(Get-DomainsFromValue -Value $property.Value)
            }
        }
        return $domains
    }
    
    return @()
}

function Get-AppDomains {
    param([object]$App)
    
    $domains = @()
    foreach ($propertyName in @("domainList", "allDomains", "searchFieldList", "instancesTopLevelDomain", "domains", "domain", "website", "homepage", "url")) {
        if ($App.PSObject.Properties.Name -contains $propertyName -and $App.$propertyName) {
            $domains += @(Get-DomainsFromValue -Value $App.$propertyName)
        }
    }
    
    return @($domains | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique)
}

function Get-BaseDomain {
    param([string]$Domain)
    
    $normalizedDomain = ($Domain -replace '^https?://', '' -replace '/.*$', '').ToLowerInvariant().Trim()
    $parts = @($normalizedDomain.Split('.') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    
    if ($parts.Count -le 2) {
        return $normalizedDomain
    }
    
    $commonSecondLevelTlds = @('ac', 'co', 'com', 'edu', 'gov', 'net', 'org')
    $lastPart = $parts[$parts.Count - 1]
    $secondLastPart = $parts[$parts.Count - 2]
    
    if ($lastPart.Length -eq 2 -and $commonSecondLevelTlds -contains $secondLastPart) {
        return ($parts[($parts.Count - 3)..($parts.Count - 1)] -join '.')
    }
    
    return ($parts[($parts.Count - 2)..($parts.Count - 1)] -join '.')
}

function Get-DomainGroupKey {
    param([string]$Domain)
    
    $normalizedDomain = ($Domain -replace '^https?://', '' -replace '/.*$', '').ToLowerInvariant().Trim()
    $parts = @($normalizedDomain.Split('.') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    
    if ($parts.Count -eq 0) {
        return $normalizedDomain
    }
    
    if ($parts.Count -le 2) {
        return $parts[0]
    }
    
    $commonSecondLevelTlds = @('ac', 'co', 'com', 'edu', 'go', 'gov', 'ne', 'net', 'or', 'org')
    $lastPart = $parts[$parts.Count - 1]
    $secondLastPart = $parts[$parts.Count - 2]
    
    if ($lastPart.Length -eq 2 -and $commonSecondLevelTlds -contains $secondLastPart) {
        return $parts[$parts.Count - 3]
    }
    
    return $parts[$parts.Count - 2]
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

function Get-UnsanctionedBlockDomains {
    param([Microsoft.PowerShell.Commands.WebRequestSession]$Session)
    
    Write-Log "Retrieving global unsanctioned app block list..."
    $blockScript = Invoke-MDCAProxyTextApi -Endpoint "discovery_block_scripts/?format=102&type=banned" -Method "GET" -Session $Session -ApiBasePaths @("api", "api/v1")
    if ($null -eq $blockScript) {
        throw "Failed to retrieve the global unsanctioned app block list; see the API errors above."
    }

    $domains = @(Convert-BlockScriptToDomains -BlockScript $blockScript)
    Write-Log "Found $($domains.Count) domains in the global unsanctioned app block list" -Level "SUCCESS"
    return $domains
}

# Retrieve one discovered-app page so it can be processed and exported before fetching the next.
function Get-DiscoveredAppsPage {
    param(
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session,
        [int]$Skip,
        [int]$Limit = 250
    )

    $body = @{
        "filters" = @{}
        "skip"    = $Skip
        "limit"   = $Limit
    }

    $response = Invoke-MDCAProxyApi -Endpoint "discovery/discovered_apps/" -Method "POST" -Body $body -Session $Session
    if ($null -eq $response) {
        throw "Failed to retrieve discovered apps at offset $Skip; stopping to avoid an incomplete export."
    }
    if ($response.PSObject.Properties.Name -notcontains 'data') {
        throw "The discovered-app response at offset $Skip did not contain a data field."
    }

    return @($response.data)
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

# Match one discovered-app page against the global block list.
function Get-UnsanctionedApps {
    param(
        [object[]]$Apps,
        [string[]]$BlockDomains,
        [hashtable]$MatchedDomains,
        [hashtable]$MatchedAppIds
    )

    $unsanctioned = @()

    foreach ($app in $Apps) {
        $appDomains = @(Get-AppDomains -App $app | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
        $matchedAppDomains = @($BlockDomains | Where-Object {
            $blockDomain = $_
            @($appDomains | Where-Object {
                $appDomain = $_
                $blockDomain -eq $appDomain -or $blockDomain.EndsWith(".$appDomain") -or $appDomain.EndsWith(".$blockDomain")
            }).Count -gt 0
        } | Sort-Object -Unique)
        
        if ($app.banned -eq $true -or $matchedAppDomains.Count -gt 0) {
            foreach ($domain in $matchedAppDomains) {
                $MatchedDomains[$domain.ToLowerInvariant()] = $true
            }
            
            $appKey = if ($app.appId) { "appId:$($app.appId)" } else { "name:$($app.name)" }
            if ($MatchedAppIds.ContainsKey($appKey)) {
                continue
            }
            $MatchedAppIds[$appKey] = $true
            
            $displayDomains = if ($matchedAppDomains.Count -gt 0) { $matchedAppDomains } else { $appDomains }
            $unsanctioned += [pscustomobject]@{
                name                = $app.name
                appId               = $app.appId
                Domains             = ($displayDomains -join ", ")
                DomainCount         = $displayDomains.Count
                banned              = $true
                UnsanctionedSource  = "DiscoveredApps"
            }
        }
    }

    return $unsanctioned
}

# Resolve block-list domains that did not match any discovered-app page.
function Get-UnmatchedBlockDomainApps {
    param(
        [string[]]$BlockDomains,
        [hashtable]$MatchedDomains,
        [hashtable]$MatchedAppIds,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )

    $unsanctioned = @()
    $remainingDomains = @($BlockDomains | Where-Object { -not $MatchedDomains.ContainsKey($_) })
    $catalogMatchesByAppId = @{}

    if ($remainingDomains.Count -gt 0) {
        Write-Log "Resolving $($remainingDomains.Count) unmatched blocked domains against the Cloud App Catalog..."
        foreach ($domain in $remainingDomains) {
            $catalogApp = Get-AppCatalogAppByDomain -Domain $domain -Session $Session
            if (-not $catalogApp.appId) {
                continue
            }

            $catalogAppKey = "appId:$($catalogApp.appId)"
            if (-not $catalogMatchesByAppId.ContainsKey($catalogAppKey)) {
                $catalogMatchesByAppId[$catalogAppKey] = [pscustomobject]@{
                    App     = $catalogApp
                    Domains = New-Object System.Collections.Generic.List[string]
                }
            }

            $catalogMatchesByAppId[$catalogAppKey].Domains.Add($domain)
            $MatchedDomains[$domain] = $true
        }
    }
    
    foreach ($catalogAppKey in $catalogMatchesByAppId.Keys) {
        if ($MatchedAppIds.ContainsKey($catalogAppKey)) {
            continue
        }
        $MatchedAppIds[$catalogAppKey] = $true
        
        $catalogMatch = $catalogMatchesByAppId[$catalogAppKey]
        $domains = @($catalogMatch.Domains | Sort-Object -Unique)
        $unsanctioned += [pscustomobject]@{
            name                = $catalogMatch.App.name
            appId               = $catalogMatch.App.appId
            Domains             = ($domains -join ", ")
            DomainCount         = $domains.Count
            banned              = $true
            UnsanctionedSource  = "CloudAppCatalog"
        }
    }
    
    $unmatchedDomainGroups = @($BlockDomains |
        Where-Object { -not $MatchedDomains.ContainsKey($_) } |
        Group-Object { Get-DomainGroupKey -Domain $_ })
    
    foreach ($group in $unmatchedDomainGroups) {
        $domains = @($group.Group | Sort-Object -Unique)
        if ($domains.Count -gt 0) {
            $unsanctioned += [pscustomobject]@{
                name                = $group.Name
                appId               = $null
                Domains             = ($domains -join ", ")
                DomainCount         = $domains.Count
                banned              = $true
                UnsanctionedSource  = "GlobalBlockListAppKeyGroup"
            }
        }
    }
    
    return $unsanctioned
}

# Function to search for app (uses cache)
function Get-RecordFieldValue {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Record,
        [Parameter(Mandatory = $true)]
        [string[]]$Names
    )

    foreach ($name in $Names) {
        if ($null -ne $Record -and $Record.PSObject.Properties.Name -contains $name) {
            return $Record.$name
        }
    }

    return $null
}

function ConvertTo-ExcelReadyRecords {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.IEnumerable]$Records
    )

    foreach ($record in @($Records)) {
        [pscustomobject][ordered]@{
            AppNameOrDomainGroup = Get-RecordFieldValue -Record $record -Names @('AppNameOrDomainGroup','name')
            AppId                = Get-RecordFieldValue -Record $record -Names @('AppId','appId')
            Source               = Get-RecordFieldValue -Record $record -Names @('Source','UnsanctionedSource')
            DomainCount          = Get-RecordFieldValue -Record $record -Names @('DomainCount')
            Domains              = Get-RecordFieldValue -Record $record -Names @('Domains','domains')
        }
    }
}

function Format-ExcelReadyRows {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.IEnumerable]$Records,
        [string]$Delimiter = "`t"
    )

    $header = @("AppNameOrDomainGroup", "AppId", "Source", "DomainCount", "Domains") -join $Delimiter
    $excelRows = @($header)

    foreach ($record in (ConvertTo-ExcelReadyRecords -Records $Records)) {
        $excelRows += (@(
            $record.AppNameOrDomainGroup,
            $record.AppId,
            $record.Source,
            $record.DomainCount,
            $record.Domains
        ) -join $Delimiter)
    }

    return $excelRows
}

function Export-ExcelFriendlyFile {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.IEnumerable]$Records,
        [Parameter(Mandatory = $true)]
        [string]$BasePath,
        [ValidateSet('CSV','TSV')]
        [string]$Format = 'CSV'
    )

    $delimiter = if ($Format -eq 'CSV') { ',' } else { "`t" }
    $filePath = if ($Format -eq 'CSV') { "$BasePath.csv" } else { "$BasePath.tsv" }

    if ($Format -eq 'CSV') {
        $rows = @(ConvertTo-ExcelReadyRecords -Records $Records | ConvertTo-Csv -NoTypeInformation)
    } else {
        $rows = Format-ExcelReadyRows -Records $Records -Delimiter $delimiter
    }
    $rows -join "`r`n" | Set-Content -Path $filePath -Encoding UTF8
    return $filePath
}

function Export-UnsanctionedAppsBatch {
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Records,
        [Parameter(Mandatory = $true)]
        [int]$BatchNumber,
        [Parameter(Mandatory = $true)]
        [string]$RunId,
        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory
    )

    $basePath = Join-Path -Path $OutputDirectory -ChildPath ("MDCA_UnsanctionedApps_{0}_batch_{1:D3}" -f $RunId, $BatchNumber)
    $csvFile = Export-ExcelFriendlyFile -Records $Records -BasePath $basePath -Format CSV
    $tsvFile = Export-ExcelFriendlyFile -Records $Records -BasePath $basePath -Format TSV
    Write-Host "Exported $($Records.Count) unsanctioned apps." -ForegroundColor Green
    Write-Host "CSV saved to: $csvFile" -ForegroundColor Yellow
    Write-Host "TSV saved to: $tsvFile" -ForegroundColor Yellow

    $tsvText = (Format-ExcelReadyRows -Records $Records) -join "`r`n"
    try {
        $tsvText | Set-Clipboard
        Write-Host "Batch $BatchNumber copied to the clipboard." -ForegroundColor Green
    }
    catch {
        Write-Log "Unable to copy batch $BatchNumber to the clipboard: $($_.Exception.Message)" -Level "WARNING"
    }

    foreach ($app in $Records) {
        Write-Log "Unsanctioned: $($app.name) (ID: $($app.appId); DomainCount: $($app.DomainCount); Domains: $($app.Domains); Source: $($app.UnsanctionedSource))"
    }

    return $BatchNumber + 1
}

function Export-ReadyUnsanctionedBatches {
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [System.Collections.Generic.List[object]]$PendingRecords,
        [Parameter(Mandatory = $true)]
        [int]$BatchSize,
        [Parameter(Mandatory = $true)]
        [int]$NextBatchNumber,
        [Parameter(Mandatory = $true)]
        [string]$RunId,
        [Parameter(Mandatory = $true)]
        [string]$OutputDirectory,
        [switch]$IncludeRemainder
    )

    while ($PendingRecords.Count -ge $BatchSize -or ($IncludeRemainder -and $PendingRecords.Count -gt 0)) {
        $recordCount = [Math]::Min($BatchSize, $PendingRecords.Count)
        $records = $PendingRecords.GetRange(0, $recordCount).ToArray()
        $NextBatchNumber = Export-UnsanctionedAppsBatch -Records $records -BatchNumber $NextBatchNumber -RunId $RunId -OutputDirectory $OutputDirectory
        $PendingRecords.RemoveRange(0, $recordCount)
    }

    return $NextBatchNumber
}

function Get-AppIdByName {
    param(
        [string]$AppName,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    
    # Validate input
    if ([string]::IsNullOrWhiteSpace($AppName)) {
        Write-Log "Empty or null app name provided" -Level "WARNING"
        return $null
    }
    
    # Check exact match first
    if ($script:AppCache.ContainsKey($AppName)) {
        return $script:AppCache[$AppName]
    }
    
    # Check case-insensitive match
    $lowerName = $AppName.ToLower()
    if ($script:AppCache.ContainsKey($lowerName)) {
        return $script:AppCache[$lowerName]
    }
    
    Write-Log "No match found for: $AppName" -Level "WARNING"
    return $null
}

# ====================================================================
# MAIN EXECUTION
# ====================================================================

$startTime = Get-Date
Write-Log "===== Starting Retrieve Unsanctioned (Banned) Apps ====="

# Validate configuration
if ([string]::IsNullOrWhiteSpace($sccauth) -or [string]::IsNullOrWhiteSpace($xsrfToken) -or [string]::IsNullOrWhiteSpace($tenantId)) {
    Write-Log "ERROR: Missing required configuration!" -Level "ERROR"
    Write-Log "Please update the script with your sccauth, xsrfToken, and tenantId values" -Level "ERROR"
    exit 1
}

if ($sccauth -eq "INSERT_YOUR_SCCAUTH_COOKIE_HERE" -or $xsrfToken -eq "INSERT_YOUR_XSRF_TOKEN_COOKIE_HERE" -or $tenantId -eq "INSERT_YOUR_TENANT_ID_HERE") {
    Write-Log "ERROR: Please replace placeholder values with your actual credentials!" -Level "ERROR"
    Write-Log "See instructions at the top of the script on how to get cookies and tenant ID" -Level "ERROR"
    exit 1
}

# Create web session with cookies
Write-Log "Creating authenticated session..."
$session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
$session.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

$cookie1 = New-Object System.Net.Cookie("sccauth", $sccauth, "/", "security.microsoft.com")
$session.Cookies.Add($cookie1)

$cookie2 = New-Object System.Net.Cookie("XSRF-TOKEN", $xsrfToken, "/", "security.microsoft.com")
$session.Cookies.Add($cookie2)

# Test API connection
Write-Log "Testing API connection..."
$testBody = @{ "filters" = @{}; "skip" = 0; "limit" = 250 }
$testResponse = Invoke-MDCAProxyApi -Endpoint "discovery/discovered_apps/" -Method "POST" -Body $testBody -Session $session

if ($null -eq $testResponse) {
    Write-Log "API Connection Failed!" -Level "ERROR"
    Write-Log "Debugging info:" -Level "ERROR"
    Write-Log "  - Cookies in session: $($session.Cookies.Count)" -Level "ERROR"
    Write-Log "" -Level "ERROR"
    Write-Log "IMPORTANT: Make sure you:" -Level "ERROR"
    Write-Log "  1. Used the SAME BROWSER where you're logged into security.microsoft.com" -Level "ERROR"
    Write-Log "  2. Copied the ENTIRE cookie values without truncation" -Level "ERROR"
    Write-Log "  3. Didn't modify or paste them incorrectly" -Level "ERROR"
    Write-Log "  4. Your session hasn't expired (re-run the JavaScript in browser)" -Level "ERROR"
    exit 1
}
if ($testResponse.PSObject.Properties.Name -notcontains 'data') {
    Write-Log "API response did not contain discovered-app data." -Level "ERROR"
    exit 1
}
$initialDiscoveredApps = @($testResponse.data)
Write-Log "API Connection Successful!" -Level "SUCCESS"

# Fetch discovered apps in pages, but create exports in batches of 250 unsanctioned results.
$blockDomains = @(Get-UnsanctionedBlockDomains -Session $session | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
$matchedDomains = @{}
$matchedAppIds = @{}
$unsanctionedApps = @()
$pendingUnsanctionedApps = [System.Collections.Generic.List[object]]::new()
$discoveredAppsProcessed = 0
$pageLimit = 250
$exportBatchSize = 250
$exportBatchNumber = 1
$runId = Get-Date -Format 'yyyyMMdd_HHmmss'
$skip = 0
$useInitialDiscoveredPage = $true

while ($true) {
    if ($useInitialDiscoveredPage) {
        $pageApps = $initialDiscoveredApps
        $useInitialDiscoveredPage = $false
    } else {
        $pageApps = @(Get-DiscoveredAppsPage -Session $session -Skip $skip -Limit $pageLimit)
    }

    if ($pageApps.Count -eq 0) {
        break
    }

    $discoveredAppsProcessed += $pageApps.Count
    $pageUnsanctionedApps = @(Get-UnsanctionedApps -Apps $pageApps -BlockDomains $blockDomains -MatchedDomains $matchedDomains -MatchedAppIds $matchedAppIds)
    foreach ($app in $pageUnsanctionedApps) {
        $pendingUnsanctionedApps.Add($app)
        $unsanctionedApps += $app
    }

    Write-Log "Processed discovered apps $($skip + 1)-$($skip + $pageApps.Count): $($pageApps.Count) records; $($pageUnsanctionedApps.Count) unsanctioned groups." -Level "SUCCESS"

    $exportBatchNumber = Export-ReadyUnsanctionedBatches -PendingRecords $pendingUnsanctionedApps -BatchSize $exportBatchSize -NextBatchNumber $exportBatchNumber -RunId $runId -OutputDirectory $PSScriptRoot

    if ($pageApps.Count -lt $pageLimit) {
        break
    }
    $skip += $pageLimit
}

# Resolve remaining blocked domains, then flush full and final partial result batches.
$remainingBlockListApps = @(Get-UnmatchedBlockDomainApps -BlockDomains $blockDomains -MatchedDomains $matchedDomains -MatchedAppIds $matchedAppIds -Session $session)
foreach ($app in $remainingBlockListApps) {
    $pendingUnsanctionedApps.Add($app)
    $unsanctionedApps += $app
}

$exportBatchNumber = Export-ReadyUnsanctionedBatches -PendingRecords $pendingUnsanctionedApps -BatchSize $exportBatchSize -NextBatchNumber $exportBatchNumber -RunId $runId -OutputDirectory $PSScriptRoot -IncludeRemainder

$endTime = Get-Date
$duration = $endTime - $startTime
Write-Log "Discovered apps processed: $discoveredAppsProcessed" -Level "SUCCESS"
Write-Log "Unsanctioned app/domain groups found: $($unsanctionedApps.Count)" -Level "SUCCESS"
if ($unsanctionedApps.Count -eq 0) {
    Write-Log "No unsanctioned (banned) apps found in the tenant." -Level "WARNING"
}

# Summary
Write-Host "`n" -NoNewline
Write-Log "`n===== Complete ====="
Write-Log "Duration: $($duration.TotalSeconds) seconds"
Write-Log "Log file saved to: $LogFile"

# Return the apps so the caller/pipeline can use them
$unsanctionedApps

