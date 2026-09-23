# Get-SanctionedMDCAApps.ps1
#
# Capabilities:
# - Connects to Microsoft Defender for Cloud Apps through security.microsoft.com cookie authentication.
# - Retrieves unsanctioned/banned cloud app entries, including domains from discovery block scripts.
# - Resolves discovered domains against the Cloud App Catalog where possible to include app names and app IDs.
# - Groups domains into Excel-friendly app/domain rows and exports CSV/TSV output for review.
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
    
    try {
        $jsonBody = if ($Body) { $Body | ConvertTo-Json -Depth 10 -Compress } else { '{}' }
        
        $params = @{
            Uri              = $uri
            Method           = $Method
            WebSession       = $Session
            Headers          = $headers
            Body             = $jsonBody
            UseBasicParsing  = $true
            TimeoutSec       = 30
            ErrorAction      = "Stop"
        }
        
        return Invoke-RestMethod @params
    }
    catch {
        $errorMsg = $_.Exception.Message
        if ($_.Exception.Response) {
            $errorMsg += " - $($_.Exception.Response.StatusCode)"
        }
        Write-Log "API call failed for $Endpoint : $errorMsg" -Level "ERROR"
        return $null
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
                TimeoutSec       = 30
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
    $domains = @(Convert-BlockScriptToDomains -BlockScript $blockScript)
    Write-Log "Found $($domains.Count) domains in the global unsanctioned app block list" -Level "SUCCESS"
    return $domains
}

# OPTIMIZATION: Retrieve all discovered apps (with paging)
function Get-AllDiscoveredApps {
    param([Microsoft.PowerShell.Commands.WebRequestSession]$Session)
    
    $skip = 0
    $limit = 500  # Increased batch size
    $allApps = @()
    
    while ($true) {
        $body = @{
            "filters" = @{}
            "skip"    = $skip
            "limit"   = $limit
        }
        
        $response = Invoke-MDCAProxyApi -Endpoint "discovery/discovered_apps/" -Method "POST" -Body $body -Session $Session
        
        if ($response -and $response.data -and $response.data.Count -gt 0) {
            $allApps += $response.data
            
            if ($response.data.Count -lt $limit) {
                break
            }
            
            $skip += $limit
            Write-Host "." -NoNewline
        } else {
            break
        }
    }
    
    return $allApps
}

function Get-AllAppCatalogApps {
    param([Microsoft.PowerShell.Commands.WebRequestSession]$Session)
    
    $skip = 0
    $limit = 100
    $allCatalogApps = @()
    
    while ($true) {
        $body = @{
            "filters" = @{}
            "skip"    = $skip
            "limit"   = $limit
        }
        
        $response = Invoke-MDCAProxyApi -Endpoint "discovery/app_catalog/" -Method "POST" -Body $body -Session $Session
        
        if ($response -and $response.data -and $response.data.Count -gt 0) {
            $allCatalogApps += $response.data
            
            if ($response.data.Count -lt $limit) {
                break
            }
            
            $skip += $limit
            Write-Host "." -NoNewline
        } else {
            break
        }
    }
    
    return $allCatalogApps
}

function Get-AppCatalogAppByDomain {
    param(
        [string]$Domain,
        [Microsoft.PowerShell.Commands.WebRequestSession]$Session
    )
    
    if ([string]::IsNullOrWhiteSpace($Domain)) {
        return $null
    }
    
    if ($null -eq $script:CatalogDomainCache) {
        $script:CatalogDomainCache = @{}
    }
    
    $normalizedDomain = $Domain.ToLowerInvariant().Trim()
    if ($script:CatalogDomainCache.ContainsKey($normalizedDomain)) {
        return $script:CatalogDomainCache[$normalizedDomain]
    }
    
    $body = @{
        "filters" = @{
            "domainList" = @{
                "eq" = $normalizedDomain
            }
        }
        "skip"    = 0
        "limit"   = 1
    }
    
    $response = Invoke-MDCAProxyApi -Endpoint "discovery/app_catalog/" -Method "POST" -Body $body -Session $Session
    $app = if ($response -and $response.data -and $response.data.Count -gt 0) { @($response.data)[0] } else { $null }
    $script:CatalogDomainCache[$normalizedDomain] = $app
    return $app
}

# OPTIMIZATION: Pre-load all apps into memory
function Load-AllAppsToCache {
    param([Microsoft.PowerShell.Commands.WebRequestSession]$Session)
    
    Write-Log "Pre-loading app cache..."
    $allApps = Get-AllDiscoveredApps -Session $Session
    $script:AllApps = $allApps
    
    # Build lookup hashtable for fast access
    foreach ($app in $allApps) {
        if ($app.name -and -not [string]::IsNullOrWhiteSpace($app.name)) {
            # Store exact match
            if (-not $script:AppCache.ContainsKey($app.name)) {
                $script:AppCache[$app.name] = $app.appId
            }
            
            # Store lowercase match
            $lowerName = $app.name.ToLower()
            if (-not $script:AppCache.ContainsKey($lowerName)) {
                $script:AppCache[$lowerName] = $app.appId
            }
        }
    }
    
    $script:AppCacheLoaded = $true
    Write-Log "Loaded $($allApps.Count) apps into cache" -Level "SUCCESS"
    return $allApps.Count
}

# Function to return all unsanctioned (banned) apps in the tenant
function Get-UnsanctionedApps {
    param([Microsoft.PowerShell.Commands.WebRequestSession]$Session)
    
    $blockDomains = @(Get-UnsanctionedBlockDomains -Session $Session | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
    $blockDomainLookup = @{}
    foreach ($domain in $blockDomains) {
        $blockDomainLookup[$domain] = $true
    }
    
    # Reuse the cached apps if already loaded, otherwise fetch them
    if ($script:AllApps -and $script:AllApps.Count -gt 0) {
        $allApps = $script:AllApps
    } else {
        Write-Log "Retrieving all discovered apps..."
        $allApps = Get-AllDiscoveredApps -Session $Session
        $script:AllApps = $allApps
    }
    
    $unsanctioned = @()
    $matchedDomains = @{}
    $matchedAppIds = @{}
    
    foreach ($app in $allApps) {
        $appDomains = @(Get-AppDomains -App $app | ForEach-Object { $_.ToLowerInvariant() } | Sort-Object -Unique)
        $matchedAppDomains = @($blockDomains | Where-Object {
            $blockDomain = $_
            @($appDomains | Where-Object {
                $appDomain = $_
                $blockDomain -eq $appDomain -or $blockDomain.EndsWith(".$appDomain") -or $appDomain.EndsWith(".$blockDomain")
            }).Count -gt 0
        } | Sort-Object -Unique)
        
        if ($app.banned -eq $true -or $matchedAppDomains.Count -gt 0) {
            foreach ($domain in $matchedAppDomains) {
                $matchedDomains[$domain.ToLowerInvariant()] = $true
            }
            
            $appKey = if ($app.appId) { "appId:$($app.appId)" } else { "name:$($app.name)" }
            if ($matchedAppIds.ContainsKey($appKey)) {
                continue
            }
            $matchedAppIds[$appKey] = $true
            
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
    
    $catalogMatchesByAppId = @{}
    foreach ($domain in @($blockDomains | Where-Object { -not $matchedDomains.ContainsKey($_) })) {
        $catalogApp = Get-AppCatalogAppByDomain -Domain $domain -Session $Session
        if ($catalogApp -and $catalogApp.appId) {
            $catalogAppKey = "appId:$($catalogApp.appId)"
            if (-not $catalogMatchesByAppId.ContainsKey($catalogAppKey)) {
                $catalogMatchesByAppId[$catalogAppKey] = [pscustomobject]@{
                    App     = $catalogApp
                    Domains = New-Object System.Collections.Generic.List[string]
                }
            }
            
            $catalogMatchesByAppId[$catalogAppKey].Domains.Add($domain)
            $matchedDomains[$domain] = $true
        }
    }
    
    foreach ($catalogAppKey in $catalogMatchesByAppId.Keys) {
        if ($matchedAppIds.ContainsKey($catalogAppKey)) {
            continue
        }
        $matchedAppIds[$catalogAppKey] = $true
        
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
    
    $unmatchedDomainGroups = @($blockDomains |
        Where-Object { -not $matchedDomains.ContainsKey($_) } |
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
    
    Write-Log "Found $($unsanctioned.Count) unsanctioned (banned) app/domain groups in the tenant from $($blockDomains.Count) blocked domains" -Level "SUCCESS"
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

function Format-ExcelReadyRows {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Records,
        [string]$Delimiter = "`t"
    )

    $excelRows = @(
        ($(
            "AppNameOrDomainGroup",
            "AppId",
            "Source",
            "DomainCount",
            "Domains"
        ) -join $Delimiter)
    )

    foreach ($record in @($Records)) {
        $nameValue = Get-RecordFieldValue -Record $record -Names @('AppNameOrDomainGroup','name')
        $appIdValue = Get-RecordFieldValue -Record $record -Names @('AppId','appId')
        $sourceValue = Get-RecordFieldValue -Record $record -Names @('Source','UnsanctionedSource')
        $domainCountValue = Get-RecordFieldValue -Record $record -Names @('DomainCount')
        $domainsValue = Get-RecordFieldValue -Record $record -Names @('Domains','domains')

        $excelRows += @(
            $(
                $nameValue,
                $appIdValue,
                $sourceValue,
                $domainCountValue,
                $domainsValue
            ) -join $Delimiter
        )
    }

    return $excelRows
}

function Export-ExcelFriendlyFile {
    param(
        [Parameter(Mandatory = $true)]
        [System.Collections.IEnumerable]$Records,
        [Parameter(Mandatory = $true)]
        [string]$BasePath,
        [ValidateSet('CSV','TSV')]
        [string]$Format = 'CSV'
    )

    $delimiter = if ($Format -eq 'CSV') { ',' } else { "`t" }
    $filePath = if ($Format -eq 'CSV') { "$BasePath.csv" } else { "$BasePath.tsv" }

    $rows = Format-ExcelReadyRows -Records $Records -Delimiter $delimiter
    $rows -join "`r`n" | Set-Content -Path $filePath -Encoding UTF8
    return $filePath
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
$testBody = @{ "filters" = @{}; "skip" = 0; "limit" = 1 }
$testResponse = Invoke-MDCAProxyApi -Endpoint "discovery/discovered_apps/" -Method "POST" -Body $testBody -Session $session

if ($null -eq $testResponse) {
    Write-Log "API Connection Failed!" -Level "ERROR"
    Write-Log "Debugging info:" -Level "ERROR"
    Write-Log "  - Tenant ID: $tenantId" -Level "ERROR"
    Write-Log "  - XSRF Token length: $($xsrfToken.Length)" -Level "ERROR"
    Write-Log "  - XSRF Token starts with: $($xsrfToken.Substring(0, [Math]::Min(50, $xsrfToken.Length)))" -Level "ERROR"
    Write-Log "  - Cookies in session: $($session.Cookies.Count)" -Level "ERROR"
    Write-Log "" -Level "ERROR"
    Write-Log "IMPORTANT: Make sure you:" -Level "ERROR"
    Write-Log "  1. Used the SAME BROWSER where you're logged into security.microsoft.com" -Level "ERROR"
    Write-Log "  2. Copied the ENTIRE cookie values without truncation" -Level "ERROR"
    Write-Log "  3. Didn't modify or paste them incorrectly" -Level "ERROR"
    Write-Log "  4. Your session hasn't expired (re-run the JavaScript in browser)" -Level "ERROR"
    exit 1
}
Write-Log "API Connection Successful!" -Level "SUCCESS"

# Retrieve all unsanctioned (banned) apps
$unsanctionedApps = @(Get-UnsanctionedApps -Session $session)

$endTime = Get-Date
$duration = $endTime - $startTime

# Output results
if ($unsanctionedApps.Count -gt 0) {
    $excelRows = Format-ExcelReadyRows -Records ($unsanctionedApps |
        Sort-Object name |
        Select-Object @{Name='AppNameOrDomainGroup';Expression={$_.name}}, @{Name='AppId';Expression={$_.appId}}, @{Name='DomainCount';Expression={$_.DomainCount}}, @{Name='Domains';Expression={$_.Domains}}, @{Name='Source';Expression={$_.UnsanctionedSource}})

    Write-Host "`nCopy/paste the following rows into Excel (tab-separated):" -ForegroundColor Cyan
    $tsvText = $excelRows -join "`r`n"
    Write-Output $tsvText

    # Also copy to the clipboard for a one-click paste into Excel
    try {
        $tsvText | Set-Clipboard
        Write-Host "`nExcel-ready data copied to the clipboard." -ForegroundColor Green
    }
    catch {
        Write-Log "Unable to copy data to the clipboard: $($_.Exception.Message)" -Level "WARNING"
    }

    $baseName = "MDCA_UnsanctionedApps_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
    $csvFile = Join-Path -Path $PSScriptRoot -ChildPath $baseName
    $tsvFile = Export-ExcelFriendlyFile -Records ($unsanctionedApps | Sort-Object name | Select-Object @{Name='AppNameOrDomainGroup';Expression={$_.name}}, @{Name='AppId';Expression={$_.appId}}, @{Name='DomainCount';Expression={$_.DomainCount}}, @{Name='Domains';Expression={$_.Domains}}, @{Name='Source';Expression={$_.UnsanctionedSource}}) -BasePath $csvFile -Format TSV
    $csvExport = Export-ExcelFriendlyFile -Records ($unsanctionedApps | Sort-Object name | Select-Object @{Name='AppNameOrDomainGroup';Expression={$_.name}}, @{Name='AppId';Expression={$_.appId}}, @{Name='DomainCount';Expression={$_.DomainCount}}, @{Name='Domains';Expression={$_.Domains}}, @{Name='Source';Expression={$_.UnsanctionedSource}}) -BasePath $csvFile -Format CSV

    Write-Host "TSV saved to: $tsvFile" -ForegroundColor Yellow
    Write-Host "CSV saved to: $csvExport" -ForegroundColor Yellow

    foreach ($app in $unsanctionedApps) {
        Write-Log "Unsanctioned: $($app.name) (ID: $($app.appId); DomainCount: $($app.DomainCount); Domains: $($app.Domains); Source: $($app.UnsanctionedSource))"
    }
} else {
    Write-Log "No unsanctioned (banned) apps found in the tenant." -Level "WARNING"
}

# Summary
Write-Host "`n" -NoNewline
Write-Log "`n===== Complete ====="
Write-Log "Unsanctioned (banned) app/domain groups found: $($unsanctionedApps.Count)" -Level "SUCCESS"
Write-Log "Duration: $($duration.TotalSeconds) seconds"
Write-Log "Log file saved to: $LogFile"

# Return the apps so the caller/pipeline can use them
$unsanctionedApps

Write-Log "`n===== CSV saved to $($csvfile).csv  ====="

