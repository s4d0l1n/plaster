#!/bin/bash
#
# Plaster Installation Script for Linux/macOS
# Sets up Plaster configuration with user-provided API key and server URL
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration directory and file
CONFIG_DIR="$HOME/.plaster"
CONFIG_FILE="$CONFIG_DIR/config.yaml"

echo -e "${BLUE}╔═════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║     Plaster Installation Script         ║${NC}"
echo -e "${BLUE}╚═════════════════════════════════════════╝${NC}"
echo

# Create config directory if it doesn't exist
if [ ! -d "$CONFIG_DIR" ]; then
    echo -e "${YELLOW}→${NC} Creating config directory at $CONFIG_DIR..."
    mkdir -p "$CONFIG_DIR"
    echo -e "${GREEN}✓${NC} Config directory created"
fi

# Check if config already exists
if [ -f "$CONFIG_FILE" ]; then
    echo -e "${YELLOW}⚠${NC}  Configuration file already exists at $CONFIG_FILE"
    read -p "Do you want to overwrite it? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${YELLOW}→${NC} Skipping configuration setup"
        exit 0
    fi
fi

echo
echo -e "${BLUE}Please provide the following information:${NC}"
echo

# Prompt for Server URL
while true; do
    read -p "Server URL (e.g., http://localhost:9321): " SERVER_URL
    if [ -z "$SERVER_URL" ]; then
        echo -e "${RED}✗${NC} Server URL cannot be empty"
        continue
    fi
    break
done

echo

# Prompt for API Key
while true; do
    read -p "API Key: " -s API_KEY
    echo
    if [ -z "$API_KEY" ]; then
        echo -e "${RED}✗${NC} API Key cannot be empty"
        continue
    fi

    read -p "Confirm API Key: " -s API_KEY_CONFIRM
    echo

    if [ "$API_KEY" != "$API_KEY_CONFIRM" ]; then
        echo -e "${RED}✗${NC} API Keys do not match, please try again"
        continue
    fi
    break
done

echo

# Create config file
cat > "$CONFIG_FILE" << EOF
# Plaster Configuration File
# Location: ~/.plaster/config.yaml

# Server URL - where the plaster service is running
server_url: "$SERVER_URL"

# API Key for authentication
api_key: "$API_KEY"

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
EOF

# Set appropriate permissions
chmod 600 "$CONFIG_FILE"

echo -e "${GREEN}✓${NC} Configuration file created successfully"
echo
echo -e "${BLUE}Configuration saved to:${NC} $CONFIG_FILE"
echo
echo -e "${GREEN}Installation complete!${NC}"
echo "You can now use Plaster with the configured settings."
