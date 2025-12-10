<#
.SYNOPSIS
    Plaster Installation Script for Windows
    Sets up Plaster configuration with user-provided API key and server URL

.DESCRIPTION
    Interactive installation script that creates the Plaster configuration file
    with user-provided API key and server URL settings.

.EXAMPLE
    PS> .\install.ps1

.NOTES
    Requires PowerShell 5.0 or higher
#>

[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

# Configuration paths
$ConfigDir = Join-Path $env:USERPROFILE ".plaster"
$ConfigFile = Join-Path $ConfigDir "config.yaml"

# Color helper function
function Write-ColorOutput {
    param(
        [string]$Message,
        [ValidateSet("Green", "Red", "Yellow", "Cyan", "Blue")]
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

# Header
Write-Host ""
Write-ColorOutput "╔═════════════════════════════════════════╗" -Color Cyan
Write-ColorOutput "║     Plaster Installation Script         ║" -Color Cyan
Write-ColorOutput "╚═════════════════════════════════════════╝" -Color Cyan
Write-Host ""

# Create config directory if needed
if (-not (Test-Path $ConfigDir)) {
    Write-ColorOutput "→ Creating config directory at $ConfigDir..." -Color Yellow
    New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
    Write-ColorOutput "✓ Config directory created" -Color Green
}

# Check if config already exists
if (Test-Path $ConfigFile) {
    Write-ColorOutput "⚠  Configuration file already exists at $ConfigFile" -Color Yellow
    $response = Read-Host "Do you want to overwrite it? (y/N)"
    if ($response -ne 'y' -and $response -ne 'Y') {
        Write-ColorOutput "→ Skipping configuration setup" -Color Yellow
        exit 0
    }
}

Write-Host ""
Write-ColorOutput "Please provide the following information:" -Color Cyan
Write-Host ""

# Prompt for Server URL
while ($true) {
    $ServerUrl = Read-Host "Server URL (e.g., http://localhost:9321)"
    if ([string]::IsNullOrWhiteSpace($ServerUrl)) {
        Write-ColorOutput "✗ Server URL cannot be empty" -Color Red
        continue
    }
    break
}

Write-Host ""

# Prompt for API Key
while ($true) {
    $ApiKeySecure = Read-Host "API Key" -AsSecureString
    $ApiKey = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUni($ApiKeySecure))

    if ([string]::IsNullOrWhiteSpace($ApiKey)) {
        Write-ColorOutput "✗ API Key cannot be empty" -Color Red
        continue
    }

    $ApiKeyConfirmSecure = Read-Host "Confirm API Key" -AsSecureString
    $ApiKeyConfirm = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUni($ApiKeyConfirmSecure))

    if ($ApiKey -ne $ApiKeyConfirm) {
        Write-ColorOutput "✗ API Keys do not match, please try again" -Color Red
        continue
    }
    break
}

Write-Host ""

# Create config file content
$ConfigContent = @"
# Plaster Configuration File
# Location: ~/.plaster/config.yaml

# Server URL - where the plaster service is running
server_url: "$ServerUrl"

# API Key for authentication
api_key: "$ApiKey"

# Port for the service to listen on
port: 9321

# Maximum number of clipboard entries to keep
max_entries: 100

# Data persistence settings
# If true: keeps entries in memory AND backs them up to disk
# If false: keeps entries in memory only (lost on restart)
persistence: true

# Path to backup file (only used if persistence is true)
backup_file: "~/.plaster/backup.json"

# Maximum size of a single entry in MB
max_entry_size_mb: 10

# Maximum total size of all entries in MB
max_total_size_mb: 500

# Rate limiting
rate_limit_requests: 100
rate_limit_window_seconds: 60
"@

# Write config file
try {
    Set-Content -Path $ConfigFile -Value $ConfigContent -Encoding UTF8
    Write-ColorOutput "✓ Configuration file created successfully" -Color Green
} catch {
    Write-ColorOutput "✗ Failed to create configuration file: $_" -Color Red
    exit 1
}

Write-Host ""
Write-ColorOutput "Configuration saved to: $ConfigFile" -Color Cyan
Write-Host ""
Write-ColorOutput "Installation complete!" -Color Green
Write-Host "You can now use Plaster with the configured settings."
Write-Host ""
