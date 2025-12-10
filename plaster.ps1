#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Plaster - Cross-platform clipboard service client
    A FILO (First In, Last Out) clipboard that stores multiple entries

.DESCRIPTION
    A PowerShell client for the Plaster clipboard service. Allows pushing text,
    retrieving entries, listing clipboard history, and clearing entries.

.PARAMETER List
    List all clipboard entries (first 50 chars each)

.PARAMETER Entry
    Get specific clipboard entry by index

.PARAMETER Clear
    Clear all clipboard entries

.PARAMETER Config
    Use custom config file path

.PARAMETER Help
    Show help message

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

    [int]$Entry = -1,

    [string]$Config = (Join-Path $env:USERPROFILE ".plaster" "config.yaml")
)

$ErrorActionPreference = "Stop"

function Show-Help {
    @"
Usage: plaster.ps1 [OPTION]

A FILO clipboard service client.

OPTIONS:
  (no args)              Get the latest clipboard entry
  -List                  List all clipboard entries (first 50 chars each)
  -Entry <index>         Get specific clipboard entry by index
  -Clear                 Clear all clipboard entries
  -Config <path>         Use custom config file path
  -Help                  Show this help message

EXAMPLES:
  'my text' | plaster.ps1        # Push text to clipboard
  plaster.ps1                    # Get latest entry
  plaster.ps1 -List              # List all entries
  plaster.ps1 -Entry 3           # Get 3rd entry
  plaster.ps1 -Clear             # Clear clipboard
"@
}

function Load-Config {
    if (-not (Test-Path $Config)) {
        Write-Error "Error: Config file not found at $Config"
        Write-Error "Make sure you've started the plaster server first."
        exit 1
    }

    # Parse YAML config file (simple regex approach)
    $content = Get-Content $Config -Raw
    $match = $content -match 'server_url:\s*["\']?([^"\s]+)'
    if ($match) {
        $script:ServerUrl = $matches[1]
    } else {
        $script:ServerUrl = "http://localhost:9321"
    }
}

function Push-Text {
    param([string]$Text)

    $body = @{
        text = $Text
    } | ConvertTo-Json

    try {
        $response = Invoke-WebRequest -Uri "$ServerUrl/push" `
            -Method Post `
            -ContentType "application/json" `
            -Body $body `
            -UseBasicParsing `
            -ErrorAction Stop

        if ($response.StatusCode -eq 200) {
            Write-Host "✓ Text pushed to clipboard" -ForegroundColor Green
        }
    } catch {
        Write-Error "Error: Failed to push text`n$_"
        exit 1
    }
}

function Get-LatestEntry {
    try {
        $response = Invoke-WebRequest -Uri "$ServerUrl/peek" `
            -Method Get `
            -UseBasicParsing `
            -ErrorAction Stop

        $data = $response.Content | ConvertFrom-Json
        if ($data.status -eq "ok") {
            Write-Output $data.text
        } else {
            Write-Error "Error: Failed to get clipboard entry"
            exit 1
        }
    } catch {
        Write-Error "Error: Failed to get clipboard entry`n$_"
        exit 1
    }
}

function Get-ClipboardList {
    try {
        $response = Invoke-WebRequest -Uri "$ServerUrl/list" `
            -Method Get `
            -UseBasicParsing `
            -ErrorAction Stop

        $data = $response.Content | ConvertFrom-Json
        if ($data.status -eq "ok") {
            Write-Host "Clipboard entries ($($data.count) total):" -ForegroundColor Cyan
            $index = 0
            foreach ($entry in $data.entries) {
                Write-Host "$($index + 1). $entry"
                $index++
            }
        } else {
            Write-Error "Error: Failed to list entries"
            exit 1
        }
    } catch {
        Write-Error "Error: Failed to list entries`n$_"
        exit 1
    }
}

function Get-ClipboardEntry {
    param([int]$Index)

    try {
        $response = Invoke-WebRequest -Uri "$ServerUrl/entry/$Index" `
            -Method Get `
            -UseBasicParsing `
            -ErrorAction Stop

        $data = $response.Content | ConvertFrom-Json
        if ($data.status -eq "ok") {
            Write-Output $data.text
        } else {
            Write-Error "Error: Failed to get entry at index $Index"
            exit 1
        }
    } catch {
        Write-Error "Error: Failed to get entry at index $Index`n$_"
        exit 1
    }
}

function Clear-Clipboard {
    try {
        $response = Invoke-WebRequest -Uri "$ServerUrl/clear" `
            -Method Delete `
            -UseBasicParsing `
            -ErrorAction Stop

        if ($response.StatusCode -eq 200) {
            Write-Host "✓ Clipboard cleared" -ForegroundColor Green
        }
    } catch {
        Write-Error "Error: Failed to clear clipboard`n$_"
        exit 1
    }
}

# Main logic
Load-Config

if ($Help) {
    Show-Help
    exit 0
}

# Check if input is being piped
if (-not [console]::IsInputRedirected) {
    # Interactive mode - process parameters
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
} else {
    # Piped input mode - read and push
    if ([string]::IsNullOrEmpty($InputText)) {
        $InputText = [Console]::In.ReadToEnd()
    }

    if (-not [string]::IsNullOrEmpty($InputText)) {
        Push-Text -Text $InputText
    }
}
