# Plaster - Multi-Platform Clipboard Service

A FILO (First In, Last Out) clipboard service with REST API backend, beautiful web UI, and cross-platform CLI clients for macOS, Linux, and Windows. Keep multiple clipboard entries and access them from anywhere.

## Features

- 📋 **FILO Stack**: Newest entries are accessed first
- 🎨 **Beautiful Web UI**: Modern, responsive interface at `http://localhost:9321`
- 🔧 **Configurable Storage**: Set max number of entries to keep
- 💾 **Persistence**: Optional disk backup of clipboard entries
- 🌐 **REST API**: Easy integration with other tools and scripts
- 🖥️ **Cross-Platform**: Works on macOS, Linux, and Windows
- 🐳 **Docker Support**: Run with Docker or Docker Compose
- ⚡ **Lightweight**: Minimal dependencies, fast and efficient

## Table of Contents

- [Quick Start with Docker](#quick-start-with-docker)
- [Server Installation (Manual)](#server-installation-manual)
- [Client Installation](#client-installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [REST API Reference](#rest-api-reference)
- [Examples](#examples)
- [Running as a Service](#running-as-a-service)
- [Troubleshooting](#troubleshooting)

---

## Quick Start with Docker

The fastest way to get Plaster running.

### Prerequisites
- Docker and Docker Compose installed

### Step 1: Start the Server with Docker Compose

```bash
# Clone or download the repository
git clone https://github.com/yourusername/plaster.git
cd plaster

# Start the server
docker-compose up -d
```

That's it! The server is now running at `http://localhost:9321`

**View logs:**
```bash
docker-compose logs -f plaster
```

**Stop the server:**
```bash
docker-compose down
```

**Data persistence:** Clipboard data is stored in a Docker volume called `plaster_data` and will persist across restarts.

### Step 2: Install CLI Client (Linux/macOS)

```bash
# Linux/macOS - Install bash client to ~/.local/bin/
curl -o ~/.local/bin/plaster https://raw.githubusercontent.com/yourusername/plaster/main/plaster
chmod +x ~/.local/bin/plaster

# Ensure ~/.local/bin is in your PATH
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### Step 3: Install CLI Client (Windows)

```powershell
# Windows - Install PowerShell client
# Create directory if it doesn't exist
New-Item -ItemType Directory -Path "$env:USERPROFILE\.plaster" -Force | Out-Null

# Download the script
(Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yourusername/plaster/main/plaster.ps1" -OutFile "$env:USERPROFILE\.plaster\plaster.ps1")

# Add to PowerShell profile for easy access
$profileDir = Split-Path $PROFILE
if (!(Test-Path $profileDir)) { New-Item -ItemType Directory -Path $profileDir -Force }
Add-Content $PROFILE "Set-Alias -Name plaster -Value '$env:USERPROFILE\.plaster\plaster.ps1' -Force"

# Reload profile
. $PROFILE
```

**Or create a batch wrapper for easier use:**

Create a file `C:\Windows\plaster.bat`:
```batch
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -Command "& '%USERPROFILE%\.plaster\plaster.ps1' %*"
```

Then you can use: `plaster` directly from any terminal.

---

## Server Installation (Manual)

If you prefer to run without Docker.

### Prerequisites

- Python 3.8+
- `curl` (for health checks and API calls)
- `jq` (for bash client - optional but recommended)

### Step 1: Clone and Install

```bash
# Clone the repository
git clone https://github.com/yourusername/plaster.git
cd plaster

# Install Python dependencies
pip install -r requirements.txt
```

### Step 2: Start the Server

```bash
# Start server in foreground
python plaster_server.py

# Or run in background (Linux/macOS)
nohup python plaster_server.py > ~/.plaster/server.log 2>&1 &
```

The server will:
- Create `~/.plaster/config.yaml` (if not exists)
- Create `~/.plaster/backup.json` (if persistence enabled)
- Listen on `http://localhost:9321`

**Test the server:**
```bash
curl http://localhost:9321/health
# Should return: {"status":"ok"}
```

### Step 3: Access the Web UI

Open your browser and go to: **http://localhost:9321**

---

## Client Installation

### Linux/macOS - Bash Client

**Option 1: System-wide installation**
```bash
sudo cp plaster /usr/local/bin/
sudo chmod +x /usr/local/bin/plaster
```

**Option 2: User installation**
```bash
mkdir -p ~/.local/bin
cp plaster ~/.local/bin/
chmod +x ~/.local/bin/plaster

# Add to PATH if not already there
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

**Option 3: Download and install**
```bash
# From anywhere, download the latest client
curl -o ~/.local/bin/plaster https://raw.githubusercontent.com/yourusername/plaster/main/plaster
chmod +x ~/.local/bin/plaster
```

**Install dependencies:**
```bash
# macOS
brew install jq curl

# Ubuntu/Debian
sudo apt-get install jq curl

# RHEL/CentOS
sudo yum install jq curl
```

### Windows - PowerShell Client

**Option 1: Create executable alias**
```powershell
# Run this once
$scriptPath = "C:\path\to\plaster.ps1"  # Update this path
$profileDir = Split-Path $PROFILE
if (!(Test-Path $profileDir)) { New-Item -ItemType Directory -Path $profileDir -Force }
Add-Content $PROFILE "Set-Alias -Name plaster -Value '$scriptPath' -Force"

# Reload PowerShell or run:
. $PROFILE
```

**Option 2: Create batch wrapper**
```batch
# Save as C:\Windows\plaster.bat or add to PATH
@echo off
powershell -NoProfile -ExecutionPolicy Bypass -Command "& 'C:\path\to\plaster.ps1' %*"
```

**Option 3: Module installation**
```powershell
# Copy plaster.ps1 to PowerShell modules
Copy-Item plaster.ps1 "$PROFILE\..\Modules\plaster\"
```

**Allow script execution:**
```powershell
# If you get execution policy errors
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

---

## Usage

### Web UI

Access the beautiful web interface at: **http://localhost:9321**

**Features:**
- Text input box to add entries
- "Push to Clipboard" button
- "Clear All" button with confirmation
- List of all entries showing:
  - Entry index (#0, #1, etc.)
  - First 50 characters of each entry
  - Copy button for each entry (copies to browser clipboard)
- Real-time updates (refreshes every 2 seconds)
- Toast notifications for feedback

### Bash/Linux/macOS CLI

```bash
# Push text to clipboard
echo "my important text" | plaster
cat file.txt | plaster
history | plaster

# Get latest entry
plaster

# Redirect to file
plaster > myfile.txt
plaster > ~/clipboard_backup.txt

# List all entries (first 50 chars preview)
plaster --list
plaster -l

# Get specific entry by index (0-indexed)
plaster -n 0    # Latest entry
plaster -n 3    # 4th entry
plaster -n 10   # 11th entry

# Clear clipboard
plaster --clear

# Use custom config
plaster --config ~/.plaster/custom.yaml

# Show help
plaster --help
```

**Examples:**
```bash
# Save command output
ls -la | plaster

# Use in scripts
python script.py | plaster

# Save multiple things and retrieve
echo "item1" | plaster
echo "item2" | plaster
echo "item3" | plaster
plaster -n 1  # Retrieves "item2"

# Process retrieved data
plaster | wc -l
plaster | head -10
```

### PowerShell/Windows CLI

```powershell
# Push text to clipboard
'my important text' | plaster
Get-Content file.txt | plaster
Get-Process | ConvertTo-Json | plaster

# Get latest entry
plaster

# List all entries
plaster -List

# Get specific entry by index
plaster -Entry 0    # Latest entry
plaster -Entry 3    # 4th entry
plaster -Entry 10   # 11th entry

# Clear clipboard
plaster -Clear

# Use custom config
plaster -Config "C:\Users\YourName\.plaster\config.yaml"

# Show help
plaster -Help
```

**Examples:**
```powershell
# Save process information
Get-Process | ConvertTo-Json | plaster

# Save service status
Get-Service | plaster

# Save command output
dir C:\Users | plaster

# Use in scripts
plaster | Write-Host
plaster | ConvertFrom-Json

# Process retrieved data
plaster | Measure-Object -Line
```

---

## Configuration

Edit `~/.plaster/config.yaml` (created automatically on first run):

```yaml
# Server URL - where the plaster service is running
server_url: "http://localhost:9321"

# Server port - what port the service listens on
port: 9321

# Maximum number of clipboard entries to keep
# When exceeded, oldest entries are removed
max_entries: 100

# Data persistence settings
# true: keeps entries in memory AND backs them up to disk
# false: keeps entries in memory only (lost on restart)
persistence: true

# Path to backup file (only used if persistence is true)
backup_file: "~/.plaster/backup.json"
```

**Docker Note:** To customize config with Docker Compose, edit the environment variables or volume mount a custom config file:

```yaml
# In docker-compose.yaml
volumes:
  - plaster_data:/root/.plaster
  - ./config.yaml:/root/.plaster/config.yaml  # Custom config
```

---

## REST API Reference

### Health Check
```
GET /health
Response: {"status": "ok"}
```

### Web UI
```
GET /
Response: HTML page with web interface
```

### Push Entry
```
POST /push
Content-Type: application/json
Body: {"text": "my text"}

Response: {"status": "ok", "message": "Added text (length: 7)"}
```

### Get Latest (Non-destructive)
```
GET /peek
Response: {"status": "ok", "text": "my text"}
```

### Get and Remove Latest
```
GET /pop
Response: {"status": "ok", "text": "my text"}
```

### List All Entries
```
GET /list
Response: {
  "status": "ok",
  "count": 5,
  "entries": ["first 50 chars...", ...]
}
```

### Get Specific Entry
```
GET /entry/{index}
Response: {"status": "ok", "index": 0, "text": "full text"}
```

### Clear All
```
DELETE /clear
Response: {"status": "ok", "message": "Clipboard cleared"}
```

**Example API calls:**
```bash
# Using curl
curl http://localhost:9321/health
curl -X POST http://localhost:9321/push -H "Content-Type: application/json" -d '{"text":"hello"}'
curl http://localhost:9321/peek
curl http://localhost:9321/list
curl http://localhost:9321/entry/0
curl -X DELETE http://localhost:9321/clear
```

---

## Examples

### Save and Retrieve Command Output

```bash
# Save command output
df -h | plaster
ps aux | plaster

# Retrieve later
plaster  # Get latest
plaster > disk_usage.txt
plaster -n 1  # Get second entry
```

### Build a Text Archive

```bash
# Save multiple important outputs
echo "Server: production" | plaster
date | plaster
whoami | plaster
pwd | plaster

# List what we've saved
plaster --list

# Export all to file
for i in {0..3}; do
  echo "=== Entry $i ===" >> archive.txt
  plaster -n $i >> archive.txt
done
```

### Backup Logs

```bash
# Daily backup
tail -100 /var/log/app.log | plaster

# Retrieve when needed
plaster > ~/log_backup_$(date +%s).txt
```

### Windows PowerShell Examples

```powershell
# Save system information
Get-ComputerInfo | ConvertTo-Json | plaster

# Save directory listing
Get-ChildItem C:\Users | ConvertTo-Json | plaster

# Retrieve and parse
plaster | ConvertFrom-Json | Format-Table
```

---

## Running as a Service

### Linux (systemd)

Create `/etc/systemd/system/plaster.service`:
```ini
[Unit]
Description=Plaster Clipboard Service
After=network.target

[Service]
Type=simple
User=your_username
WorkingDirectory=/path/to/plaster
ExecStart=/usr/bin/python3 /path/to/plaster_server.py
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable plaster
sudo systemctl start plaster

# Check status
sudo systemctl status plaster

# View logs
sudo journalctl -u plaster -f
```

### macOS (launchd)

Create `~/Library/LaunchAgents/com.plaster.service.plist`:
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.plaster.service</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/python3</string>
        <string>/path/to/plaster_server.py</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/plaster.out</string>
    <key>StandardErrorPath</key>
    <string>/tmp/plaster.err</string>
</dict>
</plist>
```

Load the service:
```bash
launchctl load ~/Library/LaunchAgents/com.plaster.service.plist

# View logs
tail -f /tmp/plaster.out
tail -f /tmp/plaster.err

# Unload
launchctl unload ~/Library/LaunchAgents/com.plaster.service.plist
```

### Windows (Task Scheduler)

**Method 1: Batch wrapper**

Create `C:\Plaster\start-plaster.bat`:
```batch
@echo off
cd /d C:\Plaster
python plaster_server.py
```

Then create a scheduled task:
1. Open Task Scheduler
2. Create Basic Task → "Plaster Server"
3. Trigger: "At startup"
4. Action: Start program → `C:\Plaster\start-plaster.bat`
5. Check "Run with highest privileges"

**Method 2: Python directly**

Create scheduled task to run:
```
python.exe C:\Plaster\plaster_server.py
```

---

## Troubleshooting

### Server Connection Issues

**Connection refused**
```bash
# Check if server is running
curl http://localhost:9321/health

# If it fails, ensure server is started
python plaster_server.py
```

**Port already in use**
```bash
# Change port in config.yaml or:
# Kill process using port 9321
lsof -i :9321
kill -9 <PID>

# Or use different port in docker-compose.yaml:
# ports:
#   - "9322:9321"
```

### Client Installation Issues

**Bash: Command not found**
```bash
# Ensure location is in PATH
echo $PATH

# Or use full path
~/.local/bin/plaster

# Add to PATH
export PATH="$HOME/.local/bin:$PATH"
```

**Bash: jq not found**
```bash
# macOS
brew install jq

# Ubuntu/Debian
sudo apt-get update && sudo apt-get install jq

# RHEL/CentOS
sudo yum install jq
```

**PowerShell: Execution policy error**
```powershell
# For current session only
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

# For current user (permanent)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### Data Issues

**Data not persisting**
- Check `persistence: true` in config.yaml
- Verify backup file path is writable: `touch ~/.plaster/backup.json`
- Check available disk space: `df -h`

**Lost data after restart**
- Enable persistence in config.yaml
- Ensure backup file is not deleted

**Reset clipboard**
```bash
# Via CLI
plaster --clear

# Via API
curl -X DELETE http://localhost:9321/clear

# Via web UI
Click "Clear All" button
```

### Docker Issues

**Docker not running**
```bash
# Start Docker daemon
sudo systemctl start docker

# On macOS
open /Applications/Docker.app
```

**Container not starting**
```bash
# Check logs
docker-compose logs plaster

# Restart
docker-compose restart plaster
```

**Port already in use**
```yaml
# Edit docker-compose.yaml
ports:
  - "9322:9321"  # Use different host port
```

**Reset Docker volume**
```bash
# Remove volume and recreate
docker-compose down -v
docker-compose up -d
```

---

## Architecture

```
┌──────────────────────────────────────────────┐
│           Your Applications                  │
├──────────────────────────────────────────────┤
│  • Bash CLI (Linux/macOS)                    │
│  • PowerShell CLI (Windows)                  │
│  • Web Browser                               │
│  • REST API Clients                          │
└──────────┬──────────────────────────────────┘
           │
           │ HTTP REST Requests
           │
┌──────────▼──────────────────────────────────┐
│     FastAPI Server (plaster_server.py)      │
├──────────────────────────────────────────────┤
│  • Web UI (http://localhost:9321)            │
│  • REST API Endpoints                        │
│  • FILO Stack Manager                        │
│  • Persistence Manager                       │
└──────────┬──────────────────────────────────┘
           │
           ▼
┌──────────────────────────────────────────────┐
│    In-Memory Clipboard + Disk Backup         │
├──────────────────────────────────────────────┤
│  • ~/.plaster/backup.json (persistent)       │
│  • In-memory cache (fast access)              │
│  • FILO stack (newest first)                  │
└──────────────────────────────────────────────┘
```

---

## Project Structure

```
plaster/
├── plaster_server.py          # FastAPI server with web UI
├── plaster                    # Bash/macOS/Linux CLI client
├── plaster.ps1                # PowerShell/Windows CLI client
├── config.yaml                # Configuration template
├── requirements.txt           # Python dependencies
├── Dockerfile                 # Docker image definition
├── docker-compose.yaml        # Docker Compose configuration
└── README.md                  # This file
```

---

## Development & Testing

### Manual Testing

```bash
# Start server
python plaster_server.py &

# Test API
curl http://localhost:9321/health
curl -X POST http://localhost:9321/push -H "Content-Type: application/json" -d '{"text":"test"}'
curl http://localhost:9321/peek

# Test bash client
echo "test1" | ./plaster
./plaster
./plaster --list
./plaster -n 0
./plaster --clear

# Test PowerShell client
'test1' | .\plaster.ps1
.\plaster.ps1
.\plaster.ps1 -List
.\plaster.ps1 -Entry 0
.\plaster.ps1 -Clear
```

### Building Docker Image

```bash
# Build image
docker build -t plaster:latest .

# Run container
docker run -d -p 9321:9321 -v plaster_data:/root/.plaster plaster:latest

# View logs
docker logs -f <container_id>
```

---

## License

MIT

## Contributing

Issues and pull requests welcome!

## Support

Having issues? Check the [Troubleshooting](#troubleshooting) section or open an issue on GitHub.
