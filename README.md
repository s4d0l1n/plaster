# Plaster - Multi-Tenant Clipboard Service

A FILO (First In, Last Out) clipboard service with API key authentication, beautiful web UI, and cross-platform CLI clients. Each API key gets its own isolated clipboard with size limits and rate limiting.

## Features

- 📋 **FILO Stack**: Newest entries accessed first
- 🎨 **Beautiful Web UI**: Modern responsive interface with API key management
- 🔐 **API Key Authentication**: Auto-generated keys, multi-tenant support
- 🏠 **Isolated Clipboards**: Each key has separate clipboard storage
- ⏱️ **Rate Limiting**: 100 requests per 60 seconds per key (configurable)
- 📏 **Size Limits**: 10MB per entry, 500MB total per clipboard (configurable)
- 💾 **Persistence**: Per-key backup files survive restarts
- 🌐 **REST API**: Full JSON API with Swagger docs
- 🖥️ **Cross-Platform**: Linux/macOS bash + Windows PowerShell clients
- 🐳 **Docker**: Production-ready Docker Compose setup

## Quick Start (Docker)

```bash
git clone https://github.com/s4d0l1n/plaster.git
cd plaster
docker-compose up -d
```

Server running at `http://localhost:9321`

**First client use (auto-generates API key):**

```bash
# Linux/macOS
curl -o ~/.local/bin/plaster https://raw.githubusercontent.com/s4d0l1n/plaster/main/plaster
chmod +x ~/.local/bin/plaster
echo 'hello' | plaster  # Creates ~/.plaster/config.yaml with API key

# Windows PowerShell
(Invoke-WebRequest -Uri "https://raw.githubusercontent.com/s4d0l1n/plaster/main/plaster.ps1" -OutFile "$env:USERPROFILE\.plaster\plaster.ps1")
'hello' | & "$env:USERPROFILE\.plaster\plaster.ps1"
```

That's it! API key is auto-generated and saved.

## How It Works

### Multi-Tenant Architecture

```
┌─────────────────────────────────────┐
│  User A (API Key: plaster_xxx)      │
│  ├─ Clipboard A (isolated)          │
│  ├─ Rate Limit: 100 req/min         │
│  └─ Backups: ~/.plaster/backups/    │
│                                     │
│  User B (API Key: plaster_yyy)      │
│  ├─ Clipboard B (isolated)          │
│  ├─ Rate Limit: 100 req/min         │
│  └─ Backups: ~/.plaster/backups/    │
└─────────────────────────────────────┘
         ↑ All requests need X-API-Key header
         │
    FastAPI Server
```

### API Key Generation

1. **First client run**: Client calls `POST /auth/generate` → Server generates `plaster_<random>`
2. **Key stored**: Saved to `~/.plaster/config.yaml`
3. **All requests**: Include `X-API-Key: plaster_xxx` header
4. **Rate limited**: Per-key tracking (100 req/60sec default)
5. **Rotation**: Web UI "Generate New Key" copies clipboard to new key

## Usage

### Web UI

Access `http://localhost:9321` after providing API key (displayed when first accessing)

**Features:**
- View/edit API key (copy button)
- Generate new key (rotates to fresh key)
- Text input to push entries
- List all entries (50-char preview)
- Copy button for each entry
- Clear all with confirmation
- Live auto-refresh

### CLI (Bash/macOS/Linux)

```bash
# First run - generates key
echo 'text' | plaster

# Get latest entry
plaster

# List all
plaster --list

# Get specific entry (0-indexed)
plaster -n 0
plaster -n 3

# Clear all
plaster --clear
```

### CLI (PowerShell/Windows)

```powershell
# First run - generates key
'text' | & plaster.ps1

# Get latest
& plaster.ps1

# List all
& plaster.ps1 -List

# Get entry
& plaster.ps1 -Entry 0

# Clear all
& plaster.ps1 -Clear
```

## Configuration

Created automatically at `~/.plaster/config.yaml`:

```yaml
server_url: "http://localhost:9321"
api_key: "plaster_abc123..."  # Auto-generated
port: 9321
max_entries: 100
persistence: true
backup_file: "~/.plaster/backups/"
max_entry_size_mb: 10         # Per entry (10MB default)
max_total_size_mb: 500        # Total per clipboard (500MB default)
rate_limit_requests: 100      # Per minute per key
rate_limit_window_seconds: 60
idle_timeout_days: 7          # Delete unused keys after 7 days
cleanup_interval_hours: 24    # Check for expired keys every 24 hours
```

### Idle Timeout & Auto-Cleanup

**How it works:**

1. **Idle timeout**: After 7 days of inactivity (default), API keys are automatically deleted
2. **Cleanup task**: Server checks for expired keys every 24 hours (background thread)
3. **When expired**: All clipboard data and backup files for that key are deleted
4. **Client behavior**: If client tries expired key → Gets 401 → **Automatically generates new key**

**No manual action needed!** Clients seamlessly regenerate keys when needed.

**Example flow:**
- Day 1: User generates key → works normally
- Day 7: No activity → key still valid
- Day 8: Cleanup runs → deletes old key + clipboard
- User tries plaster command → 401 error → **auto-generates new key**
- User continues using Plaster with new key!

**Customize timeouts** in config.yaml:
```yaml
idle_timeout_days: 30         # Keep keys for 30 days instead
cleanup_interval_hours: 6     # Check every 6 hours instead of 24
```

**Docker Compose config:**

```yaml
services:
  plaster:
    environment:
      # Adjust limits per your needs
      MAX_ENTRY_SIZE: 10
      MAX_TOTAL_SIZE: 500
      RATE_LIMIT: 100
```

## REST API

All endpoints require `X-API-Key: plaster_xxx` header

### Core Endpoints

```
POST   /push                 # Push entry (body: {"text": "..."})
GET    /peek                 # Get latest (non-destructive)
GET    /pop                  # Get and remove latest
GET    /list                 # List all (50-char preview)
GET    /entry/{index}        # Get specific by index
DELETE /clear                # Clear all

POST   /auth/generate        # Generate new API key (first time)
POST   /auth/rotate          # Rotate to new key (preserves clipboard)
```

### Example

```bash
API_KEY="plaster_abc123..."
curl -H "X-API-Key: $API_KEY" http://localhost:9321/peek
curl -X POST http://localhost:9321/push \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"text":"hello"}'
```

## Installation

### Setup Configuration (Recommended)

Before using the client, configure your server URL and API key using the interactive installation scripts:

**Linux/macOS:**
```bash
bash install.sh
```

**Windows (PowerShell):**
```powershell
.\install.ps1
```

The scripts will:
- Prompt for your server URL (e.g., `http://localhost:9321`)
- Prompt for your API key
- Create `~/.plaster/config.yaml` with your settings
- Set secure file permissions

### Manual (No Docker)

```bash
# Clone & install
git clone https://github.com/s4d0l1n/plaster.git
cd plaster
pip install -r requirements.txt

# Start server
python plaster_server.py

# In another terminal - install client
cp plaster ~/.local/bin/
chmod +x ~/.local/bin/plaster
```

### systemd Service (Linux)

Create `/etc/systemd/system/plaster.service`:

```ini
[Unit]
Description=Plaster Clipboard Service
After=network.target

[Service]
Type=simple
User=your_user
ExecStart=/usr/bin/python3 /path/to/plaster_server.py
Restart=always

[Install]
WantedBy=multi-user.target
```

Then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now plaster
sudo journalctl -u plaster -f
```

## Security Notes

- **Size limits**: Prevent memory exhaustion (10MB per entry, 500MB total)
- **Rate limiting**: Per-key limits prevent abuse (100 req/min)
- **Multi-tenant**: API keys are cryptographically random (`secrets.token_hex(16)`)
- **Isolation**: Each clipboard is separate - no cross-key leaks
- **XSS Protection**: Web UI escapes all HTML entities
- **Persistence**: Each key gets own backup file for security

## Troubleshooting

### API Key Issues

```bash
# If key missing, regenerate
rm ~/.plaster/config.yaml
echo 'test' | plaster  # Auto-generates new key

# View current key
grep api_key ~/.plaster/config.yaml
```

### Connection Errors

```bash
# Check server running
curl http://localhost:9321/health

# Check key being sent
plaster -h  # Should show config location
```

### Rate Limit Hit

```
429 Too Many Requests
```

Wait 60 seconds, or adjust `rate_limit_requests` in config.yaml

## Architecture

**Files created:**

- `~/.plaster/config.yaml` - Config with API key
- `~/.plaster/keys.json` - Server-side key registry
- `~/.plaster/backups/*.json` - Per-key clipboard backups

**Server processes:**

1. APIKeyManager - Generates/validates/tracks keys
2. RateLimiter - Per-key request tracking
3. Clipboard - FILO stack per key
4. FastAPI handlers - HTTP endpoints
5. Middleware - Auth checking

## Development

### Testing

```bash
# Start server
python plaster_server.py &

# Test API
curl -H "X-API-Key: test" http://localhost:9321/health
# Error: Invalid API key (expected)

# Generate test key
curl -X POST http://localhost:9321/auth/generate
# {"status":"ok","api_key":"plaster_xxx"}

# Test with key
TEST_KEY="plaster_xxx"
echo "hello" | curl -X POST http://localhost:9321/push \
  -H "X-API-Key: $TEST_KEY" \
  -H "Content-Type: application/json" \
  -d '{"text":"hello"}'

curl -H "X-API-Key: $TEST_KEY" http://localhost:9321/peek
```

### Building Docker Image

```bash
docker build -t plaster:latest .
docker run -d -p 9321:9321 -v plaster_data:/root/.plaster plaster:latest
```

## Project Files

```
plaster/
├── plaster_server.py      # FastAPI server + multi-tenant logic
├── plaster                # Bash client with auto-key generation
├── plaster.ps1            # PowerShell client with auto-key generation
├── config.yaml            # Template config
├── Dockerfile             # Container definition
├── docker-compose.yaml    # Full stack
├── requirements.txt       # Python deps
├── .gitignore
└── README.md
```

## License

MIT

## Support

- Check logs: `docker-compose logs plaster` or `journalctl -u plaster -f`
- Issues: https://github.com/s4d0l1n/plaster/issues
- Docs: See code comments in `plaster_server.py`

---

**Version 2.0** - Multi-tenant API key authentication release
