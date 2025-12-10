#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Plaster - Cross-platform clipboard service client
    A FILO (First In, Last Out) clipboard that stores multiple entries

.DESCRIPTION
    A PowerShell client for the Plaster clipboard service with automatic API key generation.

.EXAMPLES
    PS> 'my text' | plaster.ps1        # Push text to clipboard
    PS> plaster.ps1                    # Get latest entry
    PS> plaster.ps1 -List              # List all entries
    PS> plaster.ps1 -Entry 3           # Get 3rd entry
    PS> plaster.ps1 -Clear             # Clear clipboard
#>

[CmdletBinding()]
param(
    [Parameter(ValueFromPipeline = $true, Position = 0)]
    [string]$InputText,

    [switch]$List,
    [switch]$Clear,
    [switch]$Help,
    [switch]$Setup,
    [switch]$NewApi,

    [string]$NewServerUrl,
    [int]$Entry = -1,

    [string]$Config = (Join-Path $env:USERPROFILE ".plaster" "config.yaml")
)

$ErrorActionPreference = "Stop"
$script:ServerUrl = "http://localhost:9321"
$script:ApiKey = ""

function Invoke-ApiRequest {
    param(
        [string]$Method = 'Get',
        [string]$Endpoint,
        [object]$Body = $null,
        [switch]$SkipRetry = $false
    )

    $headers = @{
        'X-API-Key' = $script:ApiKey
        'Content-Type' = 'application/json'
    }

    $url = "$script:ServerUrl$Endpoint"
    $params = @{
        Uri = $url
        Method = $Method
        Headers = $headers
        UseBasicParsing = $true
    }

    if ($Body) {
        $params['Body'] = $Body | ConvertTo-Json
    }

    try {
        Invoke-WebRequest @params
    } catch {
        # Check for 401 (expired key)
        if ($_.Exception.Response.StatusCode -eq 401 -and -not $SkipRetry) {
            Regenerate-ApiKey
            # Retry with new key
            Invoke-ApiRequest -Method $Method -Endpoint $Endpoint -Body $Body -SkipRetry
        } else {
            throw $_
        }
    }
}

function New-ApiKey {
    try {
        $response = Invoke-WebRequest -Uri "$script:ServerUrl/auth/generate" `
            -Method Post `
            -ContentType "application/json" `
            -UseBasicParsing -ErrorAction Stop

        $data = $response.Content | ConvertFrom-Json
        return $data.api_key
    } catch {
        Write-Error "Failed to generate API key: $_"
        exit 1
    }
}

function Regenerate-ApiKey {
    Write-Host "API key expired. Generating new one..." -ForegroundColor Yellow
    $newKey = New-ApiKey
    $script:ApiKey = $newKey

    # Update config file
    $content = Get-Content $Config -Raw
    $newContent = $content -replace 'api_key:.*', "api_key: `"$newKey`""
    Set-Content -Path $Config -Value $newContent

    Write-Host "✓ New API key generated" -ForegroundColor Green
}

function Load-Config {
    if (-not (Test-Path $Config)) {
        Write-Host "Error: Config file not found at $Config" -ForegroundColor Red
        Write-Host "Run './plaster.ps1 -Setup' to initialize." -ForegroundColor Yellow
        exit 1
    }

    # Parse YAML
    $content = Get-Content $Config -Raw

    $match = $content -match 'server_url:\s*["\']?([^"\s]+)'
    if ($match) {
        $script:ServerUrl = $matches[1]
    }

    $match = $content -match 'api_key:\s*["\']?([^"\s]+)'
    if ($match) {
        $script:ApiKey = $matches[1]
    }

    if ([string]::IsNullOrEmpty($script:ApiKey)) {
        Write-Host "Error: No API key found in config. Run './plaster.ps1 -NewApi' to generate one." -ForegroundColor Red
        exit 1
    }
}

function Setup-Config {
    Write-Host ""
    Write-Host "╔═════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║     Plaster Initial Setup               ║" -ForegroundColor Cyan
    Write-Host "╚═════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""

    # Create config directory
    $configDir = Split-Path $Config
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }

    # Prompt for server URL
    while ($true) {
        $serverInput = Read-Host "Server URL (e.g., http://localhost:9321)"
        if ([string]::IsNullOrWhiteSpace($serverInput)) {
            Write-Host "Error: Server URL cannot be empty" -ForegroundColor Red
            continue
        }
        $script:ServerUrl = $serverInput
        break
    }

    Write-Host ""
    Write-Host "Generating API key from server..." -ForegroundColor Cyan
    $script:ApiKey = New-ApiKey

    # Create config
    $configContent = @"
# Plaster Configuration File

server_url: "$script:ServerUrl"
api_key: "$script:ApiKey"
port: 9321
max_entries: 100
persistence: true
backup_file: "~/.plaster/backup.json"
max_entry_size_mb: 10
max_total_size_mb: 500
rate_limit_requests: 100
rate_limit_window_seconds: 60
"@
    Set-Content -Path $Config -Value $configContent

    Write-Host ""
    Write-Host "✓ Configuration saved to $Config" -ForegroundColor Green
    Write-Host "✓ Server URL: $script:ServerUrl" -ForegroundColor Green
    Write-Host "✓ API Key: $script:ApiKey" -ForegroundColor Green
    Write-Host ""
    Write-Host "Setup complete! You can now use Plaster:" -ForegroundColor Green
    Write-Host "  'my text' | .\plaster.ps1    # Push text"
    Write-Host "  .\plaster.ps1                # Get latest entry"
    Write-Host "  .\plaster.ps1 -List          # List all entries"
}

function Generate-NewApiKey {
    Load-Config

    Write-Host "Generating new API key from $script:ServerUrl..." -ForegroundColor Cyan
    $newKey = New-ApiKey
    $script:ApiKey = $newKey

    # Update config file
    $content = Get-Content $Config -Raw
    $newContent = $content -replace 'api_key:.*', "api_key: `"$newKey`""
    Set-Content -Path $Config -Value $newContent

    Write-Host "✓ New API key generated: $newKey" -ForegroundColor Green
}

function Change-ServerUrl {
    param([string]$NewUrl)

    if (-not (Test-Path $Config)) {
        Write-Host "Error: Config file not found. Run './plaster.ps1 -Setup' first." -ForegroundColor Red
        exit 1
    }

    # Update config file
    $content = Get-Content $Config -Raw
    $newContent = $content -replace 'server_url:.*', "server_url: `"$NewUrl`""
    Set-Content -Path $Config -Value $newContent

    Write-Host "✓ Server URL updated to: $NewUrl" -ForegroundColor Green
}

function Get-LatestEntry {
    try {
        $response = Invoke-ApiRequest -Endpoint '/peek'
        $data = $response.Content | ConvertFrom-Json
        Write-Output $data.text
    } catch {
        Write-Error "Failed to get clipboard entry: $_"
        exit 1
    }
}

function Get-ClipboardList {
    try {
        $response = Invoke-ApiRequest -Endpoint '/list'
        $data = $response.Content | ConvertFrom-Json

        Write-Host "Clipboard entries ($($data.count) total):" -ForegroundColor Cyan
        $data.entries | ForEach-Object -Begin { $i = 0 } {
            Write-Host "$([String]::Format('{0, 3}', $i + 1)). $_"
            $i++
        }
    } catch {
        Write-Error "Failed to list entries: $_"
        exit 1
    }
}

function Get-ClipboardEntry {
    param([int]$Index)

    try {
        $response = Invoke-ApiRequest -Endpoint "/entry/$Index"
        $data = $response.Content | ConvertFrom-Json
        Write-Output $data.text
    } catch {
        Write-Error "Failed to get entry at index $Index`: $_"
        exit 1
    }
}

function Push-Text {
    param([string]$Text)

    try {
        $body = @{ text = $Text }
        $response = Invoke-ApiRequest -Method Post -Endpoint '/push' -Body $body
        Write-Host "✓ Text pushed to clipboard" -ForegroundColor Green
    } catch {
        Write-Error "Failed to push text: $_"
        exit 1
    }
}

function Clear-Clipboard {
    try {
        $response = Invoke-ApiRequest -Method Delete -Endpoint '/clear'
        Write-Host "✓ Clipboard cleared" -ForegroundColor Green
    } catch {
        Write-Error "Failed to clear clipboard: $_"
        exit 1
    }
}

# Main logic
if ($Help) {
    Get-Help $MyInvocation.MyCommand.Name
    exit 0
}

# Handle setup commands first (don't need config loaded)
if ($Setup) {
    Setup-Config
    exit 0
}

if ($NewApi) {
    Generate-NewApiKey
    exit 0
}

if (-not [string]::IsNullOrEmpty($NewServerUrl)) {
    Change-ServerUrl -NewUrl $NewServerUrl
    exit 0
}

# Load config for all other operations
Load-Config

# Check for piped input
if (-not [console]::IsInputRedirected -and -not [string]::IsNullOrWhiteSpace($InputText)) {
    Push-Text -Text $InputText
} elseif ([console]::IsInputRedirected) {
    $InputText = [Console]::In.ReadToEnd()
    if (-not [string]::IsNullOrEmpty($InputText)) {
        Push-Text -Text $InputText
    }
} else {
    # Interactive mode
    if ($List) {
        Get-ClipboardList
    } elseif ($Entry -ge 0) {
        Get-ClipboardEntry -Index $Entry
    } elseif ($Clear) {
        Clear-Clipboard
    } else {
        # Default: get latest entry
        Get-LatestEntry
    }
}
