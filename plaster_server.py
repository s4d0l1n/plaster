#!/usr/bin/env python3
"""
Plaster - A multi-tenant clipboard service with API key authentication
"""

import json
import os
import secrets
import time
import threading
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import yaml
from fastapi import FastAPI, HTTPException, Body, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn

# Configuration management
CONFIG_DIR = Path.home() / ".plaster"
CONFIG_FILE = CONFIG_DIR / "config.yaml"
BACKUP_DIR = CONFIG_DIR / "backups"
KEYS_FILE = CONFIG_DIR / "keys.json"

# Default configuration
DEFAULT_CONFIG = {
    "server_url": "http://localhost:9321",
    "max_entries": 100,
    "persistence": True,
    "backup_file": str(BACKUP_DIR),
    "port": 9321,
    "max_entry_size_mb": 10,
    "max_total_size_mb": 500,
    "rate_limit_requests": 100,
    "rate_limit_window_seconds": 60,
    "idle_timeout_days": 7,
    "cleanup_interval_hours": 24
}

class TextEntry(BaseModel):
    text: str

class Clipboard:
    """Manages clipboard entries with FILO (First In, Last Out) behavior"""

    def __init__(self, api_key: str, max_entries: int = 100, backup_path: str = None, persistence: bool = True):
        self.api_key = api_key
        self.stack: List[str] = []
        self.max_entries = max_entries
        self.persistence = persistence
        self.backup_path = backup_path
        self.load_from_backup()

    def push(self, text: str, max_entry_size: int, max_total_size: int) -> None:
        """Add text to clipboard (newest on top)"""
        # Validate size
        if len(text) > max_entry_size:
            raise ValueError(f"Entry exceeds max size of {max_entry_size} bytes")

        total_size = sum(len(e) for e in self.stack) + len(text)
        if total_size > max_total_size:
            raise ValueError(f"Clipboard would exceed max total size of {max_total_size} bytes")

        self.stack.insert(0, text)
        if len(self.stack) > self.max_entries:
            self.stack.pop()
        if self.persistence:
            self.save_to_backup()

    def pop(self) -> str:
        """Remove and return the most recent entry"""
        if not self.stack:
            raise ValueError("Clipboard is empty")
        entry = self.stack.pop(0)
        if self.persistence:
            self.save_to_backup()
        return entry

    def peek(self) -> str:
        """Return the most recent entry without removing it"""
        if not self.stack:
            raise ValueError("Clipboard is empty")
        return self.stack[0]

    def get_all(self) -> List[str]:
        """Return all entries"""
        return self.stack.copy()

    def get_entry(self, index: int) -> str:
        """Get entry by index"""
        if index < 0 or index >= len(self.stack):
            raise ValueError(f"Index {index} out of range")
        return self.stack[index]

    def clear(self) -> None:
        """Clear all entries"""
        self.stack.clear()
        if self.persistence:
            self.save_to_backup()

    def save_to_backup(self) -> None:
        """Save clipboard to disk"""
        try:
            backup_dir = Path(self.backup_path)
            backup_dir.mkdir(parents=True, exist_ok=True)
            backup_file = backup_dir / f"{self.api_key}.json"
            with open(backup_file, 'w') as f:
                json.dump(self.stack, f)
        except Exception as e:
            print(f"Warning: Failed to save backup for {self.api_key}: {e}")

    def load_from_backup(self) -> None:
        """Load clipboard from disk if it exists"""
        try:
            backup_dir = Path(self.backup_path)
            backup_file = backup_dir / f"{self.api_key}.json"
            if backup_file.exists():
                with open(backup_file, 'r') as f:
                    self.stack = json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load backup for {self.api_key}: {e}")
            self.stack = []

class APIKeyManager:
    """Manages API keys and their metadata"""

    def __init__(self, keys_file: str):
        self.keys_file = Path(keys_file)
        self.keys_data = self.load_keys()

    def load_keys(self) -> dict:
        """Load keys from file"""
        if self.keys_file.exists():
            with open(self.keys_file, 'r') as f:
                return json.load(f)
        return {}

    def save_keys(self) -> None:
        """Save keys to file"""
        self.keys_file.parent.mkdir(parents=True, exist_ok=True)
        with open(self.keys_file, 'w') as f:
            json.dump(self.keys_data, f, indent=2)

    def generate_key(self) -> str:
        """Generate a new API key"""
        key = f"plaster_{secrets.token_hex(16)}"
        self.keys_data[key] = {
            "created": datetime.now().isoformat(),
            "last_used": None
        }
        self.save_keys()
        return key

    def validate_key(self, key: str) -> bool:
        """Check if key exists"""
        return key in self.keys_data

    def update_last_used(self, key: str) -> None:
        """Update last used timestamp"""
        if key in self.keys_data:
            self.keys_data[key]["last_used"] = datetime.now().isoformat()
            self.save_keys()

    def delete_key(self, key: str) -> bool:
        """Delete an API key"""
        if key in self.keys_data:
            del self.keys_data[key]
            self.save_keys()
            return True
        return False

    def cleanup_expired_keys(self, idle_timeout_days: int) -> List[str]:
        """Delete keys that haven't been used for idle_timeout_days"""
        now = datetime.now()
        timeout_seconds = idle_timeout_days * 24 * 60 * 60
        expired_keys = []

        for key, data in list(self.keys_data.items()):
            last_used_str = data.get("last_used")
            if last_used_str:
                last_used = datetime.fromisoformat(last_used_str)
                age = (now - last_used).total_seconds()
                if age > timeout_seconds:
                    expired_keys.append(key)
                    self.delete_key(key)

        return expired_keys

class RateLimiter:
    """Per-key rate limiting"""

    def __init__(self, requests_per_window: int, window_seconds: int):
        self.requests_per_window = requests_per_window
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = {}

    def is_allowed(self, key: str) -> bool:
        """Check if request is allowed for this key"""
        now = time.time()

        if key not in self.requests:
            self.requests[key] = []

        # Remove old requests outside the window
        self.requests[key] = [req_time for req_time in self.requests[key]
                               if now - req_time < self.window_seconds]

        # Check if limit exceeded
        if len(self.requests[key]) >= self.requests_per_window:
            return False

        # Record this request
        self.requests[key].append(now)
        return True

def load_config() -> dict:
    """Load configuration from ~/.plaster/config.yaml"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    if CONFIG_FILE.exists():
        with open(CONFIG_FILE, 'r') as f:
            config = yaml.safe_load(f)
            return {**DEFAULT_CONFIG, **config}
    else:
        # Create default config
        with open(CONFIG_FILE, 'w') as f:
            yaml.dump(DEFAULT_CONFIG, f)
        return DEFAULT_CONFIG

# Load configuration
config = load_config()

# Initialize managers
key_manager = APIKeyManager(str(KEYS_FILE))
rate_limiter = RateLimiter(
    config.get("rate_limit_requests", 100),
    config.get("rate_limit_window_seconds", 60)
)

# Clipboards storage (per API key)
clipboards: Dict[str, Clipboard] = {}

def get_or_create_clipboard(api_key: str) -> Clipboard:
    """Get or create a clipboard for an API key"""
    if api_key not in clipboards:
        clipboards[api_key] = Clipboard(
            api_key=api_key,
            max_entries=config.get("max_entries", 100),
            backup_path=str(BACKUP_DIR),
            persistence=config.get("persistence", True)
        )
    return clipboards[api_key]

# Create FastAPI app
app = FastAPI(title="Plaster", version="2.0.0")

# Cleanup background task
def cleanup_expired_keys_task():
    """Periodically cleanup expired API keys and their clipboards"""
    idle_timeout_days = config.get("idle_timeout_days", 7)
    cleanup_interval_hours = config.get("cleanup_interval_hours", 24)
    cleanup_interval_seconds = cleanup_interval_hours * 3600

    while True:
        try:
            time.sleep(cleanup_interval_seconds)
            expired_keys = key_manager.cleanup_expired_keys(idle_timeout_days)

            # Delete clipboard data for expired keys
            for key in expired_keys:
                if key in clipboards:
                    del clipboards[key]
                # Delete backup file
                backup_file = Path(BACKUP_DIR) / f"{key}.json"
                if backup_file.exists():
                    backup_file.unlink()

            if expired_keys:
                print(f"Cleaned up {len(expired_keys)} expired API keys")
        except Exception as e:
            print(f"Error in cleanup task: {e}")

@app.on_event("startup")
async def startup_event():
    """Start cleanup task on server startup"""
    cleanup_thread = threading.Thread(target=cleanup_expired_keys_task, daemon=True)
    cleanup_thread.start()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication middleware
@app.middleware("http")
async def check_api_key(request: Request, call_next):
    """Check API key for all requests except health, key generation, and initial setup"""
    path = request.url.path

    # Skip auth for health check, static docs, key generation, and root path (initial setup)
    if path in ["/health", "/docs", "/openapi.json", "/auth/generate", "/"]:
        return await call_next(request)

    # Get API key from header
    api_key = request.headers.get("X-API-Key")

    if not api_key:
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    if not key_manager.validate_key(api_key):
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Check rate limit
    if not rate_limiter.is_allowed(api_key):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    # Update last used
    key_manager.update_last_used(api_key)

    # Store key in request state for later use
    request.state.api_key = api_key

    return await call_next(request)

def get_setup_page() -> str:
    """Generate the setup/login page"""
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Plaster - Clipboard Service</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
                display: flex;
                justify-content: center;
                align-items: center;
            }

            .container {
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                max-width: 600px;
                width: 100%;
                overflow: hidden;
            }

            .header {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 40px 30px;
                text-align: center;
            }

            .header h1 {
                font-size: 32px;
                margin-bottom: 8px;
                font-weight: 700;
            }

            .header p {
                opacity: 0.95;
                font-size: 14px;
                letter-spacing: 0.5px;
            }

            .content {
                padding: 40px 30px;
            }

            .section {
                margin-bottom: 30px;
            }

            .section h2 {
                font-size: 18px;
                color: #333;
                margin-bottom: 15px;
                font-weight: 600;
            }

            .input-group {
                display: flex;
                gap: 10px;
                margin-bottom: 15px;
            }

            #apiKeyInput {
                flex: 1;
                padding: 12px 16px;
                border: 2px solid #e0e0e0;
                border-radius: 10px;
                font-size: 14px;
                font-family: 'Menlo', monospace;
                transition: all 0.3s ease;
            }

            #apiKeyInput:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }

            button {
                padding: 12px 24px;
                border: none;
                border-radius: 10px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            .btn-primary {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                flex: 0 0 auto;
            }

            .btn-primary:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
            }

            .btn-primary:active {
                transform: translateY(0);
            }

            .instructions {
                background: #f8f9fa;
                border-left: 4px solid #667eea;
                padding: 15px;
                border-radius: 8px;
                line-height: 1.6;
            }

            .instructions h3 {
                color: #333;
                font-size: 14px;
                margin-bottom: 10px;
            }

            .instructions ol {
                margin-left: 20px;
                color: #666;
                font-size: 13px;
            }

            .instructions li {
                margin-bottom: 8px;
            }

            .code-block {
                background: #f0f0f0;
                padding: 10px;
                border-radius: 6px;
                font-family: 'Menlo', monospace;
                font-size: 12px;
                margin-top: 8px;
                overflow-x: auto;
                color: #333;
            }

            .toast {
                position: fixed;
                bottom: 20px;
                right: 20px;
                background: #51cf66;
                color: white;
                padding: 14px 20px;
                border-radius: 10px;
                box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
                opacity: 0;
                transform: translateY(20px);
                transition: all 0.3s ease;
                z-index: 1000;
            }

            .toast.show {
                opacity: 1;
                transform: translateY(0);
            }

            .toast.error {
                background: #ff6b6b;
            }

            @media (max-width: 600px) {
                .header {
                    padding: 30px 20px;
                }

                .header h1 {
                    font-size: 24px;
                }

                .content {
                    padding: 25px 20px;
                }

                .input-group {
                    flex-direction: column;
                }

                button {
                    width: 100%;
                }
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>📋 Plaster</h1>
                <p>Your FILO Clipboard Service</p>
            </div>

            <div class="content">
                <div class="section">
                    <h2>Access Clipboard</h2>
                    <div class="input-group">
                        <input type="text" id="apiKeyInput" placeholder="Enter your API key..." />
                        <button class="btn-primary" onclick="loadClipboard()">Load</button>
                    </div>
                </div>

                <div class="section">
                    <div class="instructions">
                        <h3>Getting Started:</h3>
                        <ol>
                            <li>Download the Plaster client (plaster for Linux/macOS, plaster.ps1 for Windows)</li>
                            <li>Run the setup command:
                                <div class="code-block">
                                    # Linux/macOS<br>
                                    plaster --setup<br>
                                    <br>
                                    # Windows<br>
                                    .\plaster.ps1 -Setup
                                </div>
                            </li>
                            <li>Enter your server URL and get an API key automatically</li>
                            <li>Start using Plaster from the command line:
                                <div class="code-block">
                                    echo 'my text' | plaster<br>
                                    plaster --list<br>
                                    plaster --new-api
                                </div>
                            </li>
                        </ol>
                    </div>
                </div>
            </div>
        </div>

        <div class="toast" id="toast"></div>

        <script>
            function loadClipboard() {
                const apiKey = document.getElementById('apiKeyInput').value.trim();
                if (!apiKey) {
                    showToast('Please enter an API key', 'error');
                    return;
                }
                // Redirect to the main page with the API key
                window.location.href = '/?api_key=' + encodeURIComponent(apiKey);
            }

            function showToast(message, type = 'success') {
                const toast = document.getElementById('toast');
                toast.textContent = message;
                toast.className = 'toast show';
                if (type === 'error') {
                    toast.classList.add('error');
                } else {
                    toast.classList.remove('error');
                }

                setTimeout(() => {
                    toast.classList.remove('show');
                }, 3000);
            }

            // Allow Enter key to load clipboard
            document.getElementById('apiKeyInput').addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    loadClipboard();
                }
            });
        </script>
    </body>
    </html>
    """

def get_html_page(api_key: str) -> str:
    """Generate the HTML page with embedded CSS and JavaScript"""
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Plaster - Clipboard Service</title>
        <style>
            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}

            body {{
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                padding: 20px;
                display: flex;
                justify-content: center;
                align-items: center;
            }}

            .container {{
                background: white;
                border-radius: 20px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                max-width: 600px;
                width: 100%;
                overflow: hidden;
            }}

            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 40px 30px;
                text-align: center;
            }}

            .header h1 {{
                font-size: 32px;
                margin-bottom: 8px;
                font-weight: 700;
            }}

            .header p {{
                opacity: 0.95;
                font-size: 14px;
                letter-spacing: 0.5px;
            }}

            .api-key-section {{
                background: rgba(255, 255, 255, 0.1);
                padding: 20px;
                border-radius: 10px;
                margin-top: 20px;
                backdrop-filter: blur(10px);
            }}

            .api-key-label {{
                font-size: 12px;
                text-transform: uppercase;
                opacity: 0.8;
                letter-spacing: 1px;
                margin-bottom: 8px;
                display: block;
            }}

            .api-key-container {{
                display: flex;
                gap: 10px;
                align-items: center;
                background: rgba(255, 255, 255, 0.15);
                padding: 10px 15px;
                border-radius: 8px;
                font-family: 'Menlo', monospace;
                font-size: 12px;
                word-break: break-all;
            }}

            .api-key-value {{
                flex: 1;
                color: white;
            }}

            .api-key-input {{
                flex: 1;
                padding: 10px 15px;
                border: none;
                border-radius: 8px;
                font-family: 'Menlo', monospace;
                font-size: 12px;
                background: rgba(255, 255, 255, 0.2);
                color: white;
            }}

            .api-key-input::placeholder {{
                color: rgba(255, 255, 255, 0.6);
            }}

            .btn-copy-key {{
                background: rgba(255, 255, 255, 0.2);
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 11px;
                font-weight: 600;
                white-space: nowrap;
                transition: all 0.2s;
            }}

            .btn-copy-key:hover {{
                background: rgba(255, 255, 255, 0.3);
            }}

            .btn-copy-key.copied {{
                background: #51cf66;
            }}

            .btn-switch {{
                background: rgba(255, 255, 255, 0.2);
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 11px;
                font-weight: 600;
                white-space: nowrap;
                transition: all 0.2s;
                margin-left: 5px;
            }}

            .btn-switch:hover {{
                background: rgba(255, 255, 255, 0.3);
            }}

            .btn-rotate {{
                background: #ff6b6b;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 12px;
                font-weight: 600;
                transition: all 0.2s;
                margin-top: 10px;
                width: 100%;
            }}

            .btn-rotate:hover {{
                background: #ee5a52;
            }}

            .btn-load-key {{
                background: #4c6ef5;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 12px;
                font-weight: 600;
                transition: all 0.2s;
                margin-top: 10px;
                width: 100%;
            }}

            .btn-load-key:hover {{
                background: #3d5ce5;
            }}

            .content {{
                padding: 40px 30px;
            }}

            .input-section {{
                margin-bottom: 30px;
            }}

            .input-label {{
                display: block;
                font-size: 14px;
                font-weight: 600;
                color: #333;
                margin-bottom: 10px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}

            #textInput {{
                width: 100%;
                padding: 14px 16px;
                border: 2px solid #e0e0e0;
                border-radius: 10px;
                font-size: 14px;
                font-family: inherit;
                transition: all 0.3s ease;
                resize: none;
                min-height: 80px;
            }}

            #textInput:focus {{
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }}

            .button-group {{
                display: flex;
                gap: 10px;
                margin-top: 15px;
            }}

            button {{
                padding: 12px 24px;
                border: none;
                border-radius: 10px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}

            .btn-primary {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                flex: 1;
            }}

            .btn-primary:hover {{
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
            }}

            .btn-primary:active {{
                transform: translateY(0);
            }}

            .btn-danger {{
                background: #ff6b6b;
                color: white;
            }}

            .btn-danger:hover {{
                background: #ee5a52;
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(255, 107, 107, 0.3);
            }}

            .btn-danger:active {{
                transform: translateY(0);
            }}

            .btn-copy {{
                background: #f0f0f0;
                color: #333;
                padding: 8px 12px;
                font-size: 12px;
                border-radius: 6px;
                flex-shrink: 0;
            }}

            .btn-copy:hover {{
                background: #667eea;
                color: white;
                transform: translateY(-2px);
            }}

            .btn-copy.copied {{
                background: #51cf66;
                color: white;
            }}

            .list-section {{
                margin-top: 40px;
            }}

            .list-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
            }}

            .list-title {{
                font-size: 18px;
                font-weight: 700;
                color: #333;
            }}

            .list-count {{
                background: #f0f0f0;
                color: #666;
                padding: 6px 12px;
                border-radius: 20px;
                font-size: 13px;
                font-weight: 600;
            }}

            .entries-list {{
                display: flex;
                flex-direction: column;
                gap: 12px;
                max-height: 400px;
                overflow-y: auto;
            }}

            .entry-item {{
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 14px 16px;
                background: #f8f9fa;
                border-radius: 10px;
                border-left: 4px solid #667eea;
                transition: all 0.3s ease;
            }}

            .entry-item:hover {{
                background: #f0f0f0;
                transform: translateX(4px);
            }}

            .entry-index {{
                font-weight: 700;
                color: #667eea;
                font-size: 12px;
                min-width: 24px;
                text-align: center;
            }}

            .entry-text {{
                flex: 1;
                font-size: 14px;
                color: #333;
                word-break: break-word;
                font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
                line-height: 1.4;
            }}

            .empty-state {{
                text-align: center;
                padding: 40px 20px;
                color: #999;
            }}

            .empty-state-icon {{
                font-size: 48px;
                margin-bottom: 16px;
                opacity: 0.5;
            }}

            .empty-state-text {{
                font-size: 14px;
                color: #999;
            }}

            .toast {{
                position: fixed;
                bottom: 20px;
                right: 20px;
                background: #51cf66;
                color: white;
                padding: 14px 20px;
                border-radius: 10px;
                box-shadow: 0 10px 20px rgba(0, 0, 0, 0.2);
                opacity: 0;
                transform: translateY(20px);
                transition: all 0.3s ease;
                z-index: 1000;
            }}

            .toast.show {{
                opacity: 1;
                transform: translateY(0);
            }}

            .toast.error {{
                background: #ff6b6b;
            }}

            ::-webkit-scrollbar {{
                width: 6px;
            }}

            ::-webkit-scrollbar-track {{
                background: #f1f1f1;
            }}

            ::-webkit-scrollbar-thumb {{
                background: #667eea;
                border-radius: 3px;
            }}

            ::-webkit-scrollbar-thumb:hover {{
                background: #764ba2;
            }}

            @media (max-width: 600px) {{
                .header {{
                    padding: 30px 20px;
                }}

                .header h1 {{
                    font-size: 24px;
                }}

                .content {{
                    padding: 25px 20px;
                }}

                .button-group {{
                    flex-direction: column;
                }}

                .btn-primary {{
                    flex: unset;
                }}

                .api-key-container {{
                    flex-direction: column;
                    align-items: flex-start;
                }}
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>📋 Plaster</h1>
                <p>Your FILO Clipboard Service</p>

                <div class="api-key-section">
                    <span class="api-key-label" id="keyLabel">Your API Key</span>
                    <div class="api-key-container">
                        <span class="api-key-value" id="apiKeyDisplay">{api_key}</span>
                        <button class="btn-copy-key" onclick="copyApiKey()">Copy</button>
                        <button class="btn-switch" onclick="toggleKeyInput()">Switch</button>
                    </div>
                    <div id="keyInputContainer" style="display: none;">
                        <input type="text" class="api-key-input" id="customKeyInput" placeholder="Enter API key..." />
                        <button class="btn-load-key" onclick="loadCustomKey()">Load Key</button>
                    </div>
                    <button class="btn-rotate" id="rotateBtn" onclick="rotateKey()">Generate New Key</button>
                </div>
            </div>

            <div class="content">
                <div class="input-section">
                    <label class="input-label">Add Entry</label>
                    <textarea id="textInput" placeholder="Paste or type text here..."></textarea>
                    <div class="button-group">
                        <button class="btn-primary" onclick="pushText()">Push to Clipboard</button>
                        <button class="btn-danger" onclick="clearClipboard()">Clear All</button>
                    </div>
                </div>

                <div class="list-section">
                    <div class="list-header">
                        <span class="list-title">Clipboard History</span>
                        <span class="list-count" id="entryCount">0 entries</span>
                    </div>
                    <div class="entries-list" id="entriesList"></div>
                </div>
            </div>
        </div>

        <div class="toast" id="toast"></div>

        <script>
            const API_BASE = window.location.origin;
            let currentApiKey = '{api_key}';
            let isOwnKey = true;

            function getCurrentApiKey() {{
                return currentApiKey;
            }}

            function toggleKeyInput() {{
                const container = document.getElementById('keyInputContainer');
                const display = document.getElementById('apiKeyDisplay');
                container.style.display = container.style.display === 'none' ? 'block' : 'none';
                if (container.style.display === 'block') {{
                    document.getElementById('customKeyInput').focus();
                    document.getElementById('customKeyInput').value = '';
                }}
            }}

            function loadCustomKey() {{
                const customKey = document.getElementById('customKeyInput').value.trim();
                if (!customKey) {{
                    showToast('Please enter an API key', 'error');
                    return;
                }}
                currentApiKey = customKey;
                isOwnKey = false;
                updateKeyDisplay();
                toggleKeyInput();
                loadEntries();
                showToast('Loaded custom API key');
            }}

            function updateKeyDisplay() {{
                const label = document.getElementById('keyLabel');
                const display = document.getElementById('apiKeyDisplay');
                const rotateBtn = document.getElementById('rotateBtn');

                if (isOwnKey) {{
                    label.textContent = 'Your API Key';
                    display.textContent = '{api_key}';
                    rotateBtn.style.display = 'block';
                }} else {{
                    label.textContent = 'Viewing API Key';
                    display.textContent = currentApiKey;
                    rotateBtn.style.display = 'none';
                }}
            }}

            async function loadEntries() {{
                try {{
                    const response = await fetch(API_BASE + '/list', {{
                        headers: {{'X-API-Key': getCurrentApiKey()}}
                    }});
                    const data = await response.json();

                    if (data.status === 'ok') {{
                        const entriesList = document.getElementById('entriesList');
                        const entryCount = document.getElementById('entryCount');

                        if (data.count === 0) {{
                            entriesList.innerHTML = `
                                <div class="empty-state">
                                    <div class="empty-state-icon">📭</div>
                                    <div class="empty-state-text">No clipboard entries yet</div>
                                </div>
                            `;
                            entryCount.textContent = '0 entries';
                        }} else {{
                            entriesList.innerHTML = data.entries.map((entry, index) => `
                                <div class="entry-item">
                                    <span class="entry-index">#${{index}}</span>
                                    <span class="entry-text">${{escapeHtml(entry)}}</span>
                                    <button class="btn-copy" onclick="copyToClipboard(${{index}}, this)">Copy</button>
                                </div>
                            `).join('');

                            entryCount.textContent = data.count === 1 ? '1 entry' : `${{data.count}} entries`;
                        }}
                    }}
                }} catch (error) {{
                    console.error('Error loading entries:', error);
                    showToast('Error loading entries', 'error');
                }}
            }}

            async function pushText() {{
                const text = document.getElementById('textInput').value.trim();

                if (!text) {{
                    showToast('Please enter some text', 'error');
                    return;
                }}

                try {{
                    const response = await fetch(API_BASE + '/push', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json',
                            'X-API-Key': getCurrentApiKey()
                        }},
                        body: JSON.stringify({{ text: text }})
                    }});

                    if (response.ok) {{
                        document.getElementById('textInput').value = '';
                        showToast('✓ Text pushed to clipboard');
                        loadEntries();
                    }} else {{
                        const error = await response.json();
                        showToast('Error: ' + error.detail, 'error');
                    }}
                }} catch (error) {{
                    console.error('Error:', error);
                    showToast('Error pushing text', 'error');
                }}
            }}

            async function copyToClipboard(index, button) {{
                try {{
                    const response = await fetch(API_BASE + `/entry/${{index}}`, {{
                        headers: {{'X-API-Key': getCurrentApiKey()}}
                    }});
                    const data = await response.json();

                    if (data.status === 'ok') {{
                        await navigator.clipboard.writeText(data.text);

                        button.classList.add('copied');
                        button.textContent = 'Copied!';

                        setTimeout(() => {{
                            button.classList.remove('copied');
                            button.textContent = 'Copy';
                        }}, 2000);

                        showToast('✓ Copied to clipboard');
                    }}
                }} catch (error) {{
                    console.error('Error:', error);
                    showToast('Error copying to clipboard', 'error');
                }}
            }}

            async function clearClipboard() {{
                if (!confirm('Are you sure you want to clear all clipboard entries?')) {{
                    return;
                }}

                try {{
                    const response = await fetch(API_BASE + '/clear', {{
                        method: 'DELETE',
                        headers: {{'X-API-Key': getCurrentApiKey()}}
                    }});

                    if (response.ok) {{
                        showToast('✓ Clipboard cleared');
                        loadEntries();
                    }} else {{
                        showToast('Error clearing clipboard', 'error');
                    }}
                }} catch (error) {{
                    console.error('Error:', error);
                    showToast('Error clearing clipboard', 'error');
                }}
            }}

            async function rotateKey() {{
                if (!confirm('Generate a new API key? Your old key will still work for 5 minutes.')) {{
                    return;
                }}

                try {{
                    const response = await fetch(API_BASE + '/auth/rotate', {{
                        method: 'POST',
                        headers: {{'X-API-Key': getCurrentApiKey()}}
                    }});

                    if (response.ok) {{
                        const data = await response.json();
                        window.location.reload();
                    }} else {{
                        showToast('Error rotating key', 'error');
                    }}
                }} catch (error) {{
                    console.error('Error:', error);
                    showToast('Error rotating key', 'error');
                }}
            }}

            function copyApiKey() {{
                const keyText = document.getElementById('apiKeyDisplay').textContent;
                navigator.clipboard.writeText(keyText);
                showToast('✓ API key copied');
            }}

            function showToast(message, type = 'success') {{
                const toast = document.getElementById('toast');
                toast.textContent = message;
                toast.className = 'toast show';
                if (type === 'error') {{
                    toast.classList.add('error');
                }} else {{
                    toast.classList.remove('error');
                }}

                setTimeout(() => {{
                    toast.classList.remove('show');
                }}, 3000);
            }}

            function escapeHtml(text) {{
                const map = {{
                    '&': '&amp;',
                    '<': '&lt;',
                    '>': '&gt;',
                    '"': '&quot;',
                    "'": '&#039;'
                }};
                return text.replace(/[&<>"']/g, m => map[m]);
            }}

            // Load entries on page load and set up auto-refresh
            document.addEventListener('DOMContentLoaded', loadEntries);

            // Refresh entries every 2 seconds
            setInterval(loadEntries, 2000);

            // Allow Ctrl+Enter or Cmd+Enter to push text
            document.getElementById('textInput').addEventListener('keydown', (e) => {{
                if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {{
                    pushText();
                }}
            }});

            // Allow Enter to load custom key
            document.getElementById('customKeyInput').addEventListener('keydown', (e) => {{
                if (e.key === 'Enter') {{
                    loadCustomKey();
                }}
            }});
        </script>
    </body>
    </html>
    """

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
async def serve_ui(request: Request):
    """Serve the web UI"""
    # Get API key from request state (set by middleware if authenticated)
    api_key = getattr(request.state, 'api_key', None)

    if not api_key:
        # No API key provided - show setup instructions
        return get_setup_page()

    return get_html_page(api_key)

@app.post("/auth/generate")
async def generate_key():
    """Generate a new API key (first time setup)"""
    key = key_manager.generate_key()
    get_or_create_clipboard(key)
    return {"status": "ok", "api_key": key}

@app.post("/auth/rotate")
async def rotate_key(request: Request):
    """Rotate API key (generates new key, keeps old for backwards compatibility)"""
    old_key = request.state.api_key
    new_key = key_manager.generate_key()

    # Copy clipboard from old key to new key
    if old_key in clipboards:
        old_clipboard = clipboards[old_key]
        new_clipboard = get_or_create_clipboard(new_key)
        new_clipboard.stack = old_clipboard.stack.copy()
        if config.get("persistence"):
            new_clipboard.save_to_backup()

    return {"status": "ok", "api_key": new_key}

@app.post("/push")
async def push(request: Request, entry: TextEntry):
    """Add text to clipboard"""
    api_key = request.state.api_key
    clipboard = get_or_create_clipboard(api_key)

    try:
        max_entry_size = config.get("max_entry_size_mb", 10) * 1024 * 1024
        max_total_size = config.get("max_total_size_mb", 500) * 1024 * 1024
        clipboard.push(entry.text, max_entry_size, max_total_size)
        return {"status": "ok", "message": f"Added text (length: {len(entry.text)})"}
    except ValueError as e:
        raise HTTPException(status_code=413, detail=str(e))

@app.get("/pop")
async def pop(request: Request):
    """Get and remove the most recent entry"""
    api_key = request.state.api_key
    clipboard = get_or_create_clipboard(api_key)

    try:
        entry = clipboard.pop()
        return {"status": "ok", "text": entry}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/peek")
async def peek(request: Request):
    """Get the most recent entry without removing it"""
    api_key = request.state.api_key
    clipboard = get_or_create_clipboard(api_key)

    try:
        entry = clipboard.peek()
        return {"status": "ok", "text": entry}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/list")
async def list_entries(request: Request):
    """Get all entries with first 50 characters preview"""
    api_key = request.state.api_key
    clipboard = get_or_create_clipboard(api_key)

    entries = clipboard.get_all()
    previews = [entry[:50] + ("..." if len(entry) > 50 else "") for entry in entries]
    return {
        "status": "ok",
        "count": len(entries),
        "entries": previews
    }

@app.get("/entry/{index}")
async def get_entry(request: Request, index: int):
    """Get specific entry by index"""
    api_key = request.state.api_key
    clipboard = get_or_create_clipboard(api_key)

    try:
        entry = clipboard.get_entry(index)
        return {"status": "ok", "index": index, "text": entry}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/clear")
async def clear(request: Request):
    """Clear all entries"""
    api_key = request.state.api_key
    clipboard = get_or_create_clipboard(api_key)

    clipboard.clear()
    return {"status": "ok", "message": "Clipboard cleared"}

if __name__ == "__main__":
    port = config.get("port", 9321)
    print(f"Starting Plaster server on port {port}...")
    print(f"Config file: {CONFIG_FILE}")
    print(f"Backup directory: {BACKUP_DIR}")
    print(f"API Keys file: {KEYS_FILE}")
    print(f"Max entries: {config.get('max_entries')}")
    print(f"Max entry size: {config.get('max_entry_size_mb')}MB")
    print(f"Max total size: {config.get('max_total_size_mb')}MB")
    print(f"Persistence: {config.get('persistence')}")
    print(f"Rate limit: {config.get('rate_limit_requests')} requests per {config.get('rate_limit_window_seconds')} seconds")
    uvicorn.run(app, host="0.0.0.0", port=port)
