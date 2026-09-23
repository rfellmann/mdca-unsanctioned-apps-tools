<#
Get-MDCACookies.ps1

Capabilities:
- Opens security.microsoft.com in a dedicated Microsoft Edge session with local DevTools enabled.
- Extracts the security portal sccauth and XSRF-TOKEN cookies from that signed-in browser session.
- Displays separate copy buttons for each cookie so the values can be pasted into Get-SanctionedMDCAApps.ps1.
- Avoids external SQLite dependencies by using the browser DevTools protocol.

Safety:
- Does not send cookie values anywhere except the local clipboard when a copy button is clicked.
- Close the dedicated Edge window when finished and avoid sharing copied cookie values.
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

function Get-EdgeExecutable {
    $candidates = @(
        (Get-Command msedge -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Source),
        "$env:ProgramFiles\Microsoft\Edge\Application\msedge.exe",
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
        "$env:LOCALAPPDATA\Microsoft\Edge\Application\msedge.exe"
    )

    foreach ($candidate in $candidates | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) {
        if (Test-Path $candidate) {
            return $candidate
        }
    }

    return $null
}

function Get-AvailableLocalPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    $port = $listener.LocalEndpoint.Port
    $listener.Stop()
    return $port
}

function Start-SecurityPortalBrowser {
    $edgeExe = Get-EdgeExecutable
    if (-not $edgeExe) {
        throw "Microsoft Edge was not found. Install Edge or update the script with the browser path."
    }

    if (-not $script:DevToolsPort) {
        $script:DevToolsPort = Get-AvailableLocalPort
    }

    if (-not $script:DevToolsUserDataDir) {
        $script:DevToolsUserDataDir = Join-Path $env:TEMP "MDCA-CookieHelper-EdgeProfile"
    }

    New-Item -Path $script:DevToolsUserDataDir -ItemType Directory -Force | Out-Null

    $arguments = @(
        "--remote-debugging-port=$script:DevToolsPort",
        "--user-data-dir=$script:DevToolsUserDataDir",
        "--no-first-run",
        "--new-window",
        "https://security.microsoft.com"
    )

    Start-Process -FilePath $edgeExe -ArgumentList $arguments | Out-Null
}

function Invoke-DevToolsCommand {
    param(
        [string]$WebSocketUrl,
        [string]$Method,
        [hashtable]$Params = @{}
    )

    $client = [System.Net.WebSockets.ClientWebSocket]::new()
    $client.ConnectAsync([System.Uri]$WebSocketUrl, [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()

    try {
        $id = Get-Random -Minimum 1000 -Maximum 999999
        $payload = @{
            id = $id
            method = $Method
        }

        if ($Params.Count -gt 0) {
            $payload.params = $Params
        }

        $json = $payload | ConvertTo-Json -Depth 10 -Compress
        $sendBytes = [System.Text.Encoding]::UTF8.GetBytes($json)
        $sendSegment = [System.ArraySegment[byte]]::new($sendBytes)
        $client.SendAsync($sendSegment, [System.Net.WebSockets.WebSocketMessageType]::Text, $true, [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()

        $buffer = New-Object byte[] 65536

        do {
            $builder = [System.Text.StringBuilder]::new()

            do {
                $receiveSegment = [System.ArraySegment[byte]]::new($buffer)
                $result = $client.ReceiveAsync($receiveSegment, [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()

                if ($result.MessageType -eq [System.Net.WebSockets.WebSocketMessageType]::Close) {
                    throw "DevTools closed the WebSocket connection before returning cookie data."
                }

                $null = $builder.Append([System.Text.Encoding]::UTF8.GetString($buffer, 0, $result.Count))
            } while (-not $result.EndOfMessage)

            $response = $builder.ToString() | ConvertFrom-Json
        } while ($response.id -ne $id)

        if ($response.error) {
            throw $response.error.message
        }

        return $response.result
    }
    finally {
        if ($client.State -eq [System.Net.WebSockets.WebSocketState]::Open) {
            $client.CloseAsync([System.Net.WebSockets.WebSocketCloseStatus]::NormalClosure, "done", [System.Threading.CancellationToken]::None).GetAwaiter().GetResult()
        }

        $client.Dispose()
    }
}

function Get-BrowserCookiesForSecurityPortal {
    if (-not $script:DevToolsPort) {
        throw "Click Open security.microsoft.com first, sign in, then extract the cookies."
    }

    $pages = Invoke-RestMethod -Uri "http://127.0.0.1:$script:DevToolsPort/json/list" -ErrorAction Stop
    $page = $pages | Where-Object { $_.type -eq 'page' -and $_.url -like 'https://security.microsoft.com*' } | Select-Object -First 1

    if (-not $page) {
        $page = $pages | Where-Object { $_.type -eq 'page' } | Select-Object -First 1
    }

    if (-not $page -or [string]::IsNullOrWhiteSpace($page.webSocketDebuggerUrl)) {
        throw "The DevTools browser page was not found. Reopen security.microsoft.com from this helper and try again."
    }

    $result = Invoke-DevToolsCommand -WebSocketUrl $page.webSocketDebuggerUrl -Method 'Network.getAllCookies'
    $parsed = @{}
    $requiredNames = @('sccauth', 'XSRF-TOKEN')

    foreach ($cookie in ($result.cookies | Where-Object { $requiredNames -contains $_.name -and $_.domain -like '*security.microsoft.com*' })) {
        $parsed[$cookie.name] = $cookie.value
    }

    foreach ($cookie in ($result.cookies | Where-Object { $requiredNames -contains $_.name })) {
        if (-not $parsed.ContainsKey($cookie.name)) {
            $parsed[$cookie.name] = $cookie.value
        }
    }

    return $parsed
}

function Show-CookieDialog {
    param(
        [hashtable]$CookieValues
    )

    $popup = New-Object System.Windows.Forms.Form
    $popup.Text = "MDCA Cookies"
    $popup.Size = New-Object System.Drawing.Size(780, 300)
    $popup.StartPosition = "CenterParent"
    $popup.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedDialog
    $popup.MaximizeBox = $false
    $popup.MinimizeBox = $false

    $table = New-Object System.Windows.Forms.TableLayoutPanel
    $table.Dock = [System.Windows.Forms.DockStyle]::Fill
    $table.ColumnCount = 3
    $table.RowCount = 2
    $table.Padding = [System.Windows.Forms.Padding]::new(10)
    $table.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 120))) | Out-Null
    $table.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Percent, 100))) | Out-Null
    $table.ColumnStyles.Add((New-Object System.Windows.Forms.ColumnStyle([System.Windows.Forms.SizeType]::Absolute, 150))) | Out-Null
    $table.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 50))) | Out-Null
    $table.RowStyles.Add((New-Object System.Windows.Forms.RowStyle([System.Windows.Forms.SizeType]::Percent, 50))) | Out-Null

    function Add-CookieRow {
        param(
            [string]$LabelText,
            [string]$CookieKey,
            [int]$RowIndex
        )

        $label = New-Object System.Windows.Forms.Label
        $label.Text = $LabelText
        $label.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
        $label.Anchor = [System.Windows.Forms.AnchorStyles]::Left
        $label.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
        $table.Controls.Add($label, 0, $RowIndex)

        $textBox = New-Object System.Windows.Forms.TextBox
        $textBox.Multiline = $true
        $textBox.ReadOnly = $true
        $textBox.ScrollBars = [System.Windows.Forms.ScrollBars]::Vertical
        $textBox.Font = New-Object System.Drawing.Font("Consolas", 9)
        $textBox.Anchor = [System.Windows.Forms.AnchorStyles]::Left -bor [System.Windows.Forms.AnchorStyles]::Right -bor [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Bottom
        $textBox.Height = 60
        $textBox.Text = if ($CookieValues.ContainsKey($CookieKey)) { $CookieValues[$CookieKey] } else { "" }
        $table.Controls.Add($textBox, 1, $RowIndex)

        $copyButton = New-Object System.Windows.Forms.Button
        $copyButton.Text = "Copy $LabelText"
        $copyButton.AutoSize = $true
        $copyButton.Padding = [System.Windows.Forms.Padding]::new(12, 6, 12, 6)
        $copyButton.Tag = [pscustomobject]@{
            TextBox = $textBox
            DefaultText = "Copy $LabelText"
        }
        $copyButton.Add_Click({
            $button = [System.Windows.Forms.Button]$this
            [System.Windows.Forms.Clipboard]::SetText($button.Tag.TextBox.Text)
            $button.Text = "Copied"
            Start-Sleep -Milliseconds 800
            $button.Text = $button.Tag.DefaultText
        })
        $table.Controls.Add($copyButton, 2, $RowIndex)
    }

    Add-CookieRow -LabelText "sccauth" -CookieKey "sccauth" -RowIndex 0
    Add-CookieRow -LabelText "XSRF-TOKEN" -CookieKey "XSRF-TOKEN" -RowIndex 1

    $buttonPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $buttonPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
    $buttonPanel.Height = 48
    $buttonPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::RightToLeft
    $buttonPanel.Padding = [System.Windows.Forms.Padding]::new(10, 8, 10, 8)

    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = "Close"
    $closeButton.DialogResult = [System.Windows.Forms.DialogResult]::OK
    $closeButton.AutoSize = $true
    $closeButton.Padding = [System.Windows.Forms.Padding]::new(12, 6, 12, 6)
    $buttonPanel.Controls.Add($closeButton)

    $popup.Controls.Add($table)
    $popup.Controls.Add($buttonPanel)
    $popup.AcceptButton = $closeButton

    $popup.ShowDialog() | Out-Null
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "MDCA Cookie Helper"
$form.Size = New-Object System.Drawing.Size(760, 170)
$form.StartPosition = "CenterScreen"
$form.Icon = [System.Drawing.SystemIcons]::Shield
$form.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedSingle
$form.MaximizeBox = $false
$form.MinimizeBox = $false

$script:MdcaCookieValues = @{}

$label = New-Object System.Windows.Forms.Label
$label.Text = "Open security.microsoft.com from this helper, sign in, click Extract cookies, then use the separate copy buttons for each cookie."
$label.Dock = [System.Windows.Forms.DockStyle]::Top
$label.Padding = [System.Windows.Forms.Padding]::new(12, 12, 12, 0)
$label.AutoSize = $true
$form.Controls.Add($label)

$actionPanel = New-Object System.Windows.Forms.FlowLayoutPanel
$actionPanel.Dock = [System.Windows.Forms.DockStyle]::Bottom
$actionPanel.Height = 68
$actionPanel.Padding = [System.Windows.Forms.Padding]::new(10, 10, 10, 10)
$actionPanel.FlowDirection = [System.Windows.Forms.FlowDirection]::LeftToRight
$form.Controls.Add($actionPanel)

$openButton = New-Object System.Windows.Forms.Button
$openButton.Text = "Open security.microsoft.com"
$openButton.AutoSize = $true
$openButton.Padding = [System.Windows.Forms.Padding]::new(12, 6, 12, 6)
$actionPanel.Controls.Add($openButton)

$extractButton = New-Object System.Windows.Forms.Button
$extractButton.Text = "Extract cookies"
$extractButton.AutoSize = $true
$extractButton.Padding = [System.Windows.Forms.Padding]::new(12, 6, 12, 6)
$actionPanel.Controls.Add($extractButton)

$copySccAuthButton = New-Object System.Windows.Forms.Button
$copySccAuthButton.Text = "Copy sccauth"
$copySccAuthButton.AutoSize = $true
$copySccAuthButton.Enabled = $false
$copySccAuthButton.Padding = [System.Windows.Forms.Padding]::new(12, 6, 12, 6)
$actionPanel.Controls.Add($copySccAuthButton)

$copyXsrfButton = New-Object System.Windows.Forms.Button
$copyXsrfButton.Text = "Copy XSRF-TOKEN"
$copyXsrfButton.AutoSize = $true
$copyXsrfButton.Enabled = $false
$copyXsrfButton.Padding = [System.Windows.Forms.Padding]::new(12, 6, 12, 6)
$actionPanel.Controls.Add($copyXsrfButton)

$openButton.Add_Click({
    try {
        Start-SecurityPortalBrowser
        $label.Text = "Sign in in the Edge window that just opened. After the portal loads, click Extract cookies."
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Browser launch failed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
    }
})

$copySccAuthButton.Add_Click({
    [System.Windows.Forms.Clipboard]::SetText($script:MdcaCookieValues['sccauth'])
    $copySccAuthButton.Text = "Copied sccauth"
    Start-Sleep -Milliseconds 800
    $copySccAuthButton.Text = "Copy sccauth"
})

$copyXsrfButton.Add_Click({
    [System.Windows.Forms.Clipboard]::SetText($script:MdcaCookieValues['XSRF-TOKEN'])
    $copyXsrfButton.Text = "Copied XSRF-TOKEN"
    Start-Sleep -Milliseconds 800
    $copyXsrfButton.Text = "Copy XSRF-TOKEN"
})

$extractButton.Add_Click({
    try {
        $cookieMap = Get-BrowserCookiesForSecurityPortal

        if (-not $cookieMap.ContainsKey('sccauth') -or -not $cookieMap.ContainsKey('XSRF-TOKEN')) {
            [System.Windows.Forms.MessageBox]::Show("The required cookies were not found. Use the Open security.microsoft.com button, sign in in that Edge window, and click Extract cookies again after the portal finishes loading.", "Cookies not found", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information) | Out-Null
            return
        }

        $script:MdcaCookieValues = $cookieMap
        $copySccAuthButton.Enabled = $true
        $copyXsrfButton.Enabled = $true
        $label.Text = "Cookies found. Use Copy sccauth and Copy XSRF-TOKEN below."
        Show-CookieDialog -CookieValues $cookieMap
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show("Unable to extract the cookies. $($_.Exception.Message)", "Read failed", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Warning) | Out-Null
    }
})

$form.ShowDialog() | Out-Null
