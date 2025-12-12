#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Plaster - Cross-platform clipboard service client
    A FILO (First In, Last Out) clipboard that stores multiple entries

.DESCRIPTION
    A PowerShell client for the Plaster clipboard service with automatic API key generation.

.EXAMPLES
    PS> 'my text' | .\plaster.ps1      # Push text to clipboard
    PS> .\plaster.ps1                  # Get latest entry
    PS> .\plaster.ps1 -List            # List all entries
    PS> .\plaster.ps1 -Entry 1         # Get 1st entry
    PS> .\plaster.ps1 -Entry 3         # Get 3rd entry
    PS> .\plaster.ps1 -Clear           # Clear clipboard
    PS> .\plaster.ps1 -Setup           # Initial setup
    PS> .\plaster.ps1 -NewApi          # Generate new labeled API key
    PS> .\plaster.ps1 -SelectApi       # List and select from stored API keys
    PS> .\plaster.ps1 -QRCode          # Generate QR code for web UI link
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
    [string]$NewApiKey,
    [switch]$Install,
    [switch]$Uninstall,
    [switch]$ShowApi,
    [switch]$ShowUrl,
    [switch]$QRCode,
    [switch]$SelectApi,

    [string]$NewServerUrl,
    [int]$Entry = -1,

    [string]$Config
)

$ErrorActionPreference = "Stop"
$script:ServerUrl = "http://localhost:9321"
$script:ApiKey = ""
$script:ClientVersion = "1.0.0"

# Function to check dependencies
function Test-Dependencies {
    $missingDeps = @()

    # Check for curl
    if (-not (Get-Command curl -ErrorAction SilentlyContinue)) {
        $missingDeps += "curl"
    }

    # Check for ConvertFrom-Json (built-in, should always exist)
    # PowerShell has built-in JSON support, no external dependency needed

    if ($missingDeps.Count -gt 0) {
        Write-Host "Error: Missing required dependencies: $($missingDeps -join ', ')" -ForegroundColor Red
        Write-Host ""
        Write-Host "Please install the following tools:" -ForegroundColor Red
        foreach ($dep in $missingDeps) {
            switch ($dep) {
                "curl" {
                    Write-Host "  - curl: HTTP client (required for API communication)"
                    Write-Host "    Windows: choco install curl or scoop install curl"
                    Write-Host "    Alternative: Use 'Invoke-WebRequest' cmdlet (built-in)"
                }
            }
        }
        exit 1
    }
}

# Function to check for updates (non-blocking)
function Test-UpdateAvailable {
    # Run in background job to not block operation
    $job = Start-Job -ScriptBlock {
        param($ServerUrl, $ClientVersion)
        try {
            $response = Invoke-WebRequest -Uri "$ServerUrl/version" -Method Get -UseBasicParsing -ErrorAction SilentlyContinue
            $data = $response.Content | ConvertFrom-Json -ErrorAction SilentlyContinue
            $serverVersion = $data.version

            if ($serverVersion -and $serverVersion -ne $ClientVersion) {
                Write-Host ""
                Write-Host "ℹ️  Update available! Plaster $serverVersion is available (you have $ClientVersion)" -ForegroundColor Yellow
            }
        } catch {
            # Silently fail - don't interrupt user operations
        }
    } -ArgumentList $script:ServerUrl, $script:ClientVersion

    # Don't wait for the job
    $job | Remove-Job -Force -ErrorAction SilentlyContinue
}

# Set config path based on location
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
if ($scriptDir -like "*Program Files*") {
    # Installed version - use user home directory
    if (-not $Config) {
        $Config = Join-Path $env:USERPROFILE ".plaster" "config.yaml"
    }
} else {
    # Local version - use script directory
    if (-not $Config) {
        $Config = Join-Path $scriptDir "config.yaml"
    }
}

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
        if ($data.api_key) {
            return $data.api_key
        } else {
            Write-Error "Failed to parse API key from response"
            Write-Error "Server response: $($response.Content)"
            Write-Error "Response length: $($response.Content.Length) bytes"
            exit 1
        }
    } catch {
        try {
            $statusCode = $_.Exception.Response.StatusCode.Value
        } catch {
            $statusCode = "Unknown"
        }
        $errorMsg = $_.Exception.Message
        Write-Error "Failed to generate API key (HTTP $statusCode): $errorMsg"
        Write-Error "Server response: $($_.ErrorDetails.Message)"
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

function Set-NewApiKey {
    param([string]$ProvidedKey)

    Load-Config

    if ([string]::IsNullOrWhiteSpace($ProvidedKey)) {
        Write-Host "Generating new API key from $script:ServerUrl..." -ForegroundColor Cyan
        $newKey = New-ApiKey
        Write-Host "✓ New API key generated: $newKey" -ForegroundColor Green
    } else {
        $newKey = $ProvidedKey
        Write-Host "✓ API key set to: $newKey" -ForegroundColor Green
    }

    # Prompt for label
    $label = Read-Host "Enter a label for this key (e.g., 'work', 'testing', 'shared')"
    if ([string]::IsNullOrWhiteSpace($label)) {
        $label = "unlabeled"
    }

    # Update config file
    $content = Get-Content $Config -Raw
    $newContent = $content -replace 'api_key:.*', "api_key: `"$newKey`""
    Set-Content -Path $Config -Value $newContent

    # Save to keys file
    Save-ApiKeyWithLabel $newKey $label

    Write-Host "✓ API key saved with label: $label" -ForegroundColor Green
}

function Load-Config {
    # Check dependencies before loading config
    Test-Dependencies

    if (-not (Test-Path $Config)) {
        Write-Host "Error: Config file not found at $Config" -ForegroundColor Red
        Write-Host "Run './plaster.ps1 -Setup' to initialize." -ForegroundColor Yellow
        exit 1
    }

    # Parse YAML
    $content = Get-Content $Config -Raw

    $match = $content -match 'server_url:\s*[''"]?([^''"\s]+)[''"]?'
    if ($match) {
        $script:ServerUrl = $matches[1]
    }

    $match = $content -match 'api_key:\s*[''"]?([^''"\s]+)[''"]?'
    if ($match) {
        $script:ApiKey = $matches[1]
    }

    if ([string]::IsNullOrEmpty($script:ApiKey)) {
        Write-Host "Error: No API key found in config. Run './plaster.ps1 -NewApi' to generate one." -ForegroundColor Red
        exit 1
    }

    # Check for updates (non-blocking)
    Test-UpdateAvailable
}

function Setup-Config {
    # Check dependencies before starting setup
    Test-Dependencies

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
# Plaster Client Configuration
# Only contains client-side settings

server_url: "$script:ServerUrl"
api_key: "$script:ApiKey"
"@
    Set-Content -Path $Config -Value $configContent

    # Save initial API key with "initial" label
    Save-ApiKeyWithLabel $script:ApiKey "initial"

    Write-Host ""
    Write-Host "✓ Configuration saved to $Config" -ForegroundColor Green
    Write-Host "✓ Server URL: $script:ServerUrl" -ForegroundColor Green
    Write-Host "✓ API Key: $script:ApiKey" -ForegroundColor Green
    Write-Host "✓ Key labeled as: initial" -ForegroundColor Green
    Write-Host ""
    Write-Host "Setup complete! You can now use Plaster:" -ForegroundColor Green
    Write-Host "  'my text' | .\plaster.ps1    # Push text"
    Write-Host "  .\plaster.ps1                # Get latest entry"
    Write-Host "  .\plaster.ps1 -List          # List all entries"
    Write-Host "  .\plaster.ps1 -NewApi        # Generate new labeled API key"
    Write-Host "  .\plaster.ps1 -SelectApi     # Switch between stored API keys"
    Write-Host ""
    Write-Host "To make 'plaster' available from anywhere, install it:" -ForegroundColor Cyan
    Write-Host "  .\plaster.ps1 -Install       # Install to Program Files (requires admin)"
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

function Install-Plaster {
    $installPath = Join-Path $env:ProgramFiles "plaster" "plaster.ps1"
    $installDir = Split-Path $installPath
    $configDir = Join-Path $env:USERPROFILE ".plaster"
    $oldConfig = Join-Path (Split-Path -Parent $PSCommandPath) "config.yaml"
    $newConfig = Join-Path $configDir "config.yaml"

    Write-Host "Installing Plaster to $installDir..." -ForegroundColor Cyan

    # Check if running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
    if (-not $isAdmin) {
        Write-Host "Error: Installation requires administrator privileges" -ForegroundColor Red
        Write-Host "Please run: Start-Process powershell -ArgumentList `"'-Command', '& `"$PSCommandPath`" -Install'`" -Verb RunAs" -ForegroundColor Yellow
        exit 1
    }

    # Create directory if it doesn't exist
    if (-not (Test-Path $installDir)) {
        New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    }

    # Copy script
    Copy-Item -Path $PSCommandPath -Destination $installPath -Force

    # Create wrapper script in System32 for direct access
    $wrapperPath = Join-Path $env:SystemRoot "System32" "plaster.ps1"
    Copy-Item -Path $PSCommandPath -Destination $wrapperPath -Force

    # Create config directory for installed version
    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }

    # Migrate config from script directory to %USERPROFILE%\.plaster if it exists there
    if ((Test-Path $oldConfig) -and -not (Test-Path $newConfig)) {
        Write-Host "Migrating config from $(Split-Path -Parent $PSCommandPath) to $configDir..." -ForegroundColor Cyan
        Copy-Item -Path $oldConfig -Destination $newConfig -Force
        Write-Host "✓ Config migrated to $newConfig" -ForegroundColor Green
    }

    Write-Host "✓ Plaster installed successfully to $installDir" -ForegroundColor Green
    Write-Host "✓ Config directory: $configDir" -ForegroundColor Green
    Write-Host "You can now run 'plaster -Setup' from anywhere (or use 'plaster.ps1 -Setup' in PowerShell)" -ForegroundColor Green
}

function Uninstall-Plaster {
    $installPath = Join-Path $env:ProgramFiles "plaster" "plaster.ps1"
    $installDir = Split-Path $installPath
    $wrapperPath = Join-Path $env:SystemRoot "System32" "plaster.ps1"
    $configDir = Join-Path $env:USERPROFILE ".plaster"

    Write-Host "Uninstalling Plaster from $installDir..." -ForegroundColor Cyan

    # Check if running as admin
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
    if (-not $isAdmin) {
        Write-Host "Error: Uninstallation requires administrator privileges" -ForegroundColor Red
        Write-Host "Please run: Start-Process powershell -ArgumentList `"'-Command', '& `"$PSCommandPath`" -Uninstall'`" -Verb RunAs" -ForegroundColor Yellow
        exit 1
    }

    if (-not (Test-Path $installPath)) {
        Write-Host "Error: Plaster is not installed at $installPath" -ForegroundColor Red
        exit 1
    }

    Remove-Item -Path $installPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $wrapperPath -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $installDir -Force -ErrorAction SilentlyContinue

    # Ask to remove config directory
    if (Test-Path $configDir) {
        $response = Read-Host "Remove config directory $configDir`? (y/N)"
        if ($response -eq 'y' -or $response -eq 'Y') {
            Remove-Item -Path $configDir -Recurse -Force
            Write-Host "✓ Config directory removed" -ForegroundColor Green
        } else {
            Write-Host "Config directory preserved at $configDir" -ForegroundColor Green
        }
    }

    Write-Host "✓ Plaster uninstalled successfully" -ForegroundColor Green
}

function Show-ApiKey {
    Load-Config
    Write-Output $script:ApiKey
}

function Show-ServerUrl {
    Load-Config
    Write-Output $script:ServerUrl
}

function Show-QRCode {
    Load-Config

    # Create the web UI URL with API key
    $webUrl = "$script:ServerUrl/?api_key=$script:ApiKey"

    Write-Host "Generating QR code for: $webUrl" -ForegroundColor Cyan
    Write-Host ""

    # Try to use a QR code library or command
    try {
        # First, try using qrencode if available
        if (Get-Command qrencode -ErrorAction SilentlyContinue) {
            qrencode -t ANSI256 $webUrl
        }
        # Try using PowerShell's built-in capability to generate ASCII QR codes
        elseif (Get-Command qr -ErrorAction SilentlyContinue) {
            qr $webUrl
        }
        else {
            Write-Host "QR code generation not available." -ForegroundColor Yellow
            Write-Host "Install qrencode or use this URL directly:" -ForegroundColor Yellow
            Write-Host $webUrl -ForegroundColor Green
            Write-Host ""
            Write-Host "Installation:" -ForegroundColor Cyan
            Write-Host "  Windows (Chocolatey): choco install qrencode" -ForegroundColor Gray
            Write-Host "  Windows (Scoop): scoop install qrencode" -ForegroundColor Gray
            Write-Host "  macOS (Homebrew): brew install qrencode" -ForegroundColor Gray
        }
    }
    catch {
        Write-Host "Could not generate QR code: $_" -ForegroundColor Red
        Write-Host "Alternatively, use this URL: $webUrl" -ForegroundColor Green
    }
}

function Save-ApiKeyWithLabel {
    param([string]$Key, [string]$Label)

    $configDir = Split-Path $Config
    $keysFile = Join-Path $configDir "api_keys.conf"

    # Create keys file if it doesn't exist
    if (-not (Test-Path $keysFile)) {
        New-Item -ItemType File -Path $keysFile -Force | Out-Null
        (Get-Item $keysFile).Attributes = 'Hidden'
    }

    # Read existing keys and remove if already present
    $allLines = @()
    if (Test-Path $keysFile) {
        $allLines = @(Get-Content $keysFile | Where-Object { $_ -notmatch "^$([regex]::Escape($Key)):" })
    }

    # Add the new key and keep only last 10
    $allLines += "$Key`:$Label"
    $allLines[-10..-1] | Set-Content $keysFile
}

function Verify-ApiKey {
    param([string]$Key)

    try {
        $response = Invoke-WebRequest -Uri "$script:ServerUrl/peek" `
            -Method Get `
            -Headers @{'X-API-Key' = $Key} `
            -UseBasicParsing -ErrorAction SilentlyContinue

        if ($response.Content | ConvertFrom-Json | Select-Object -ExpandProperty status -ErrorAction SilentlyContinue) {
            return $true
        }
    } catch {
        return $false
    }
    return $false
}

function Select-ApiKey {
    Load-Config

    $configDir = Split-Path $Config
    $keysFile = Join-Path $configDir "api_keys.conf"

    if (-not (Test-Path $keysFile)) {
        Write-Host "No stored API keys found. Run '.\plaster.ps1 -NewApi' to create one." -ForegroundColor Red
        exit 1
    }

    Write-Host "Available API Keys:" -ForegroundColor Cyan
    $keys = @()
    $labels = @()
    $index = 1

    Get-Content $keysFile | ForEach-Object {
        if ($_ -match '^(.+?):(.+)$') {
            $key = $matches[1]
            $label = $matches[2]

            if (Verify-ApiKey $key) {
                $status = "✓ ACTIVE"
            } else {
                $status = "✗ INACTIVE"
            }

            Write-Host "$index) [$status] $label" -ForegroundColor Yellow
            $keys += $key
            $labels += $label
            $index++
        }
    }

    if ($keys.Count -eq 0) {
        Write-Host "No valid API keys found." -ForegroundColor Red
        exit 1
    }

    # Prompt for selection
    $choice = Read-Host "Select API key (1-$($keys.Count))"

    if (-not ($choice -match '^\d+$') -or $choice -lt 1 -or $choice -gt $keys.Count) {
        Write-Host "Invalid selection" -ForegroundColor Red
        exit 1
    }

    $selectedKey = $keys[$choice - 1]
    $selectedLabel = $labels[$choice - 1]

    # Update current API key in config
    $content = Get-Content $Config -Raw
    $newContent = $content -replace 'api_key:\s*["\']?[^"\']+["\']?', "api_key: `"$selectedKey`""
    Set-Content -Path $Config -Value $newContent

    Write-Host "✓ Switched to: $selectedLabel" -ForegroundColor Green
}

function Copy-ToSystemClipboard {
    param([string]$Text)

    # Copy to Windows clipboard if available
    try {
        $Text | Set-Clipboard -ErrorAction SilentlyContinue
    } catch {
        # Silently fail if clipboard not available (headless/remote)
    }
}

function Get-LatestEntry {
    try {
        $response = Invoke-ApiRequest -Endpoint '/peek'
        $data = $response.Content | ConvertFrom-Json
        Write-Output $data.text
        Copy-ToSystemClipboard -Text $data.text
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
            # Show only first line, truncated to 50 chars with ellipsis
            $firstLine = ($_ -split '\r?\n')[0]
            if ($firstLine.Length -gt 50) {
                $display = $firstLine.Substring(0, 50) + "..."
            } else {
                $display = $firstLine
            }
            Write-Host "$([String]::Format('{0, 3}', $i + 1)). $display"
            $i++
        }
    } catch {
        Write-Error "Failed to list entries: $_"
        exit 1
    }
}

function Get-ClipboardEntry {
    param([int]$Index)

    # Convert from 1-based (user input) to 0-based (server)
    $serverIndex = $Index - 1

    if ($serverIndex -lt 0) {
        Write-Host "Error: Entry index must be 1 or greater" -ForegroundColor Red
        exit 1
    }

    try {
        $response = Invoke-ApiRequest -Endpoint "/entry/$serverIndex"
        $data = $response.Content | ConvertFrom-Json
        Write-Output $data.text
        Copy-ToSystemClipboard -Text $data.text
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

# Handle installation commands first
if ($Install) {
    Install-Plaster
    exit 0
}

if ($Uninstall) {
    Uninstall-Plaster
    exit 0
}

# Handle setup commands (don't need config loaded)
if ($Setup) {
    Setup-Config
    exit 0
}

if ($NewApi) {
    Set-NewApiKey -ProvidedKey $NewApiKey
    exit 0
}

if (-not [string]::IsNullOrEmpty($NewServerUrl)) {
    Change-ServerUrl -NewUrl $NewServerUrl
    exit 0
}

if ($ShowApi) {
    Show-ApiKey
    exit 0
}

if ($ShowUrl) {
    Show-ServerUrl
    exit 0
}

if ($QRCode) {
    Show-QRCode
    exit 0
}

if ($SelectApi) {
    Select-ApiKey
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
    # Interactive mode - check if no arguments provided
    $hasArguments = $PSBoundParameters.Count -gt 0

    if (-not $hasArguments) {
        # No arguments - get latest entry
        Get-LatestEntry
    } elseif ($List) {
        Get-ClipboardList
    } elseif ($Entry -ge 0) {
        Get-ClipboardEntry -Index $Entry
    } elseif ($Clear) {
        Clear-Clipboard
    } else {
        # Show help if no recognized argument
        Get-Help $MyInvocation.MyCommand.Name
    }
}
