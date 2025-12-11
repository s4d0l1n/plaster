# Plaster - FILO Clipboard Service

A simple, cross-platform clipboard service with a beautiful web UI and CLI clients. Each API key gets its own isolated clipboard with size limits and rate limiting.

## Features

- 📋 **FILO Stack**: Newest entries accessed first (Last In, First Out)
- 🎨 **Web UI**: Beautiful, responsive interface at `http://localhost:9321`
- 🔐 **API Key Auth**: Auto-generated keys, multi-tenant support
- 🏠 **Isolated**: Each key has its own separate clipboard
- 💾 **Persistent**: Survives restarts
- 🖥️ **Cross-Platform**: Works on Linux, macOS, and Windows
- 🐳 **Docker**: Easy one-command deployment

## Quick Start

### Start the Server (Docker)

```bash
git clone https://github.com/s4d0l1n/plaster.git
cd plaster
docker compose up -d
```

Server is now running at `http://localhost:9321`

### Setup Client

**Linux/macOS (Bash):**
```bash
curl -o ~/plaster https://raw.githubusercontent.com/s4d0l1n/plaster/main/plaster
chmod +x ~/plaster
~/plaster --setup
```

**Windows (PowerShell):**
```powershell
(Invoke-WebRequest -Uri "https://raw.githubusercontent.com/s4d0l1n/plaster/main/plaster.ps1" -OutFile "$env:USERPROFILE\plaster.ps1")
& "$env:USERPROFILE\plaster.ps1" -Setup
```

The setup will ask for your server URL and automatically generate an API key.

**After setup**, you can optionally install the script system-wide:

**Linux/macOS:**
```bash
~/plaster --install          # Install to /usr/local/bin
# Then use 'plaster' from anywhere
```

**Windows (PowerShell):**
```powershell
& "$env:USERPROFILE\plaster.ps1" -Install    # Requires admin
# Then use 'plaster -Setup' from PowerShell
```

---

## Usage

### Web UI

Visit `http://localhost:9321` in your browser

**Features:**
- View and copy your API key
- Add text entries
- View all entries with copy buttons
- Generate new API keys
- Clear all entries

### Bash Client (Linux/macOS)

```bash
# Push text to clipboard
echo 'my text' | plaster
cat file.txt | plaster

# Get latest entry (also copies to system clipboard)
plaster

# List all entries
plaster --list

# Get specific entry (1-indexed, also copies to system clipboard)
plaster -n 1    # First entry
plaster -n 3    # Third entry

# Clear all entries
plaster --clear

# Manage API keys
plaster --new-api                          # Generate new API key
plaster --new-api plaster_key_here         # Use specific API key
plaster --api                              # Show current API key

# Manage server
plaster --new-server-url http://example.com:9321
plaster --url                              # Show current server URL

# Help
plaster --help
```

**Note:** When you run `plaster` or `plaster -n <index>`, the output is displayed in the terminal AND automatically copied to your system clipboard (on macOS, Linux with xclip/xsel, or Windows WSL with clip.exe). On headless systems without clipboard support, the text is still displayed normally.

### PowerShell Client (Windows)

```powershell
# Push text to clipboard
'my text' | & .\plaster.ps1
Get-Content file.txt | & .\plaster.ps1

# Get latest entry (also copies to Windows clipboard)
& .\plaster.ps1

# List all entries
& .\plaster.ps1 -List

# Get specific entry (1-indexed, also copies to Windows clipboard)
& .\plaster.ps1 -Entry 1    # First entry
& .\plaster.ps1 -Entry 3    # Third entry

# Clear all entries
& .\plaster.ps1 -Clear

# Manage API keys
& .\plaster.ps1 -NewApi                                # Generate new API key
& .\plaster.ps1 -NewApi -NewApiKey "plaster_key_here" # Use specific API key
& .\plaster.ps1 -ShowApi                               # Show current API key

# Manage server
& .\plaster.ps1 -NewServerUrl http://example.com:9321
& .\plaster.ps1 -ShowUrl                               # Show current server URL

# Help
& .\plaster.ps1 -Help
```

**Note:** When you run `.\plaster.ps1` or `.\plaster.ps1 -Entry <index>`, the output is displayed in PowerShell AND automatically copied to your Windows clipboard using `Set-Clipboard`. On headless/remote systems without clipboard support, the text is still displayed normally.

---

## Command Reference

### Bash Script (`plaster`)

| Command | Description |
|---------|-------------|
| `plaster` | Get latest entry |
| `echo 'text' \| plaster` | Push text to clipboard |
| `plaster --list` / `-l` | List all entries |
| `plaster -n <index>` | Get specific entry (1-indexed) |
| `plaster --clear` / `-c` | Clear all entries |
| `plaster --new-api [KEY]` | Generate new key or set to KEY |
| `plaster --new-server-url <url>` | Change server URL |
| `plaster --api` | Show current API key |
| `plaster --url` | Show current server URL |
| `plaster --setup` | Initial setup (interactive) |
| `plaster --install` | Install to /usr/local/bin |
| `plaster --uninstall` | Uninstall from /usr/local/bin |
| `plaster --help` / `-h` | Show help |

### PowerShell Script (`plaster.ps1`)

| Command | Description |
|---------|-------------|
| `.\plaster.ps1` | Get latest entry |
| `'text' \| .\plaster.ps1` | Push text to clipboard |
| `.\plaster.ps1 -List` | List all entries |
| `.\plaster.ps1 -Entry <index>` | Get specific entry (1-indexed) |
| `.\plaster.ps1 -Clear` | Clear all entries |
| `.\plaster.ps1 -NewApi` | Generate new API key |
| `.\plaster.ps1 -NewApi -NewApiKey "KEY"` | Set API key to KEY |
| `.\plaster.ps1 -NewServerUrl <url>` | Change server URL |
| `.\plaster.ps1 -ShowApi` | Show current API key |
| `.\plaster.ps1 -ShowUrl` | Show current server URL |
| `.\plaster.ps1 -Setup` | Initial setup (interactive) |
| `.\plaster.ps1 -Install` | Install to Program Files |
| `.\plaster.ps1 -Uninstall` | Uninstall from Program Files |
| `.\plaster.ps1 -Help` | Show help |

---

## Configuration

Config files are created automatically during `--setup` and contain:
- Server URL
- API key

**Config location depends on installation status:**

### Local (Before Install)
- **Bash:** `./config.yaml` (same directory as script)
- **PowerShell:** `.\config.yaml` (same directory as script)

This allows you to keep the script and config together for easy portability.

### After Installation
- **Bash (Linux/macOS):** `~/.plaster/config.yaml`
- **PowerShell (Windows):** `$env:USERPROFILE\.plaster\config.yaml`

This follows standard practice for installed applications.

**To reconfigure:**
```bash
plaster --setup              # Bash
.\plaster.ps1 -Setup        # PowerShell
```

**To uninstall and optionally remove config:**
```bash
plaster --uninstall          # Bash (prompts to remove ~/.plaster)
.\plaster.ps1 -Uninstall    # PowerShell (prompts to remove ~/.plaster)
```

---

## REST API

All endpoints require `X-API-Key: your_api_key` header.

```bash
# Get latest entry
curl -H "X-API-Key: plaster_xxx" http://localhost:9321/peek

# Push entry
curl -X POST http://localhost:9321/push \
  -H "X-API-Key: plaster_xxx" \
  -H "Content-Type: application/json" \
  -d '{"text":"hello"}'

# List entries
curl -H "X-API-Key: plaster_xxx" http://localhost:9321/list

# Get entry by index
curl -H "X-API-Key: plaster_xxx" http://localhost:9321/entry/0

# Remove and get latest
curl -H "X-API-Key: plaster_xxx" http://localhost:9321/pop

# Clear all
curl -X DELETE http://localhost:9321/clear \
  -H "X-API-Key: plaster_xxx"

# Generate new API key
curl -X POST http://localhost:9321/auth/generate

# Rotate API key (preserves clipboard)
curl -X POST http://localhost:9321/auth/rotate \
  -H "X-API-Key: plaster_xxx"

# Health check
curl http://localhost:9321/health
```

---

## Troubleshooting

**Can't connect to server:**
```bash
curl http://localhost:9321/health
docker compose logs plaster
```

**Forgot API key:**

If running locally (uninstalled):
```bash
# Bash
cat ./config.yaml
# PowerShell
Get-Content .\config.yaml
```

If installed system-wide:
```bash
# Bash
grep api_key ~/.plaster/config.yaml
# PowerShell
Select-String "api_key" $env:USERPROFILE\.plaster\config.yaml
```

**Generate new API key:**
```bash
plaster --new-api              # Bash
.\plaster.ps1 -NewApi         # PowerShell
```

**Rate limit exceeded (429 error):**
Wait 60 seconds and try again. Default limit is 100 requests per 60 seconds.

**Config in wrong location:**
Delete the incorrect `config.yaml` and run `--setup` again:
```bash
plaster --setup       # Bash
.\plaster.ps1 -Setup # PowerShell
```

---

## Security Notes

- API keys are cryptographically random
- Each clipboard is isolated per API key
- Size limits prevent memory exhaustion (10MB per entry, 500MB total)
- Rate limiting prevents abuse
- Web UI escapes HTML to prevent XSS

---

## Installation (Manual)

Without Docker:

```bash
git clone https://github.com/s4d0l1n/plaster.git
cd plaster
pip install -r requirements.txt
python plaster_server.py
```

Server runs on port 9321 by default.

---

## Files

### Client Files

**Local (uninstalled):**
```
./
└── config.yaml          # Config with server URL and API key
```

**After installation:**
```
~/.plaster/              # User's plaster directory
└── config.yaml          # Config with server URL and API key
```

### Server Files (on server machine)

```
~/.plaster/
├── config.yaml          # Server configuration
├── keys.json            # Registered API keys
└── backups/             # Per-key clipboard backups
    ├── plaster_xxx.json
    └── plaster_yyy.json
```

---

## License

MIT

---

**Need help?** Check the logs:
```bash
docker compose logs plaster -f
```
