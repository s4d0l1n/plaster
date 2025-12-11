#!/usr/bin/env python3
"""
Plaster - A multi-tenant clipboard service with API key authentication
"""

import json
import os
import secrets
import time
import threading
import logging
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime
import yaml
from fastapi import FastAPI, HTTPException, Body, Request
from fastapi.responses import HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import uvicorn
from cryptography.fernet import Fernet

# Configuration management
CONFIG_DIR = Path.home() / ".plaster"
CONFIG_FILE = CONFIG_DIR / "config.yaml"
BACKUP_DIR = CONFIG_DIR / "backups"
KEYS_FILE = CONFIG_DIR / "keys.json"
MASTER_KEY_FILE = CONFIG_DIR / "master.key"
AUDIT_LOG_FILE = CONFIG_DIR / "audit.log"

# Setup logging
def setup_logging():
    """Configure audit logging"""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    # Create logger
    logger = logging.getLogger("plaster")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # Prevent propagation to uvicorn logger

    # File handler for audit log
    try:
        file_handler = logging.FileHandler(AUDIT_LOG_FILE)
        file_handler.setLevel(logging.INFO)

        # Log format: timestamp | level | message
        formatter = logging.Formatter('%(asctime)s | %(levelname)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        file_handler.setFormatter(formatter)

        # Remove existing handlers to avoid duplicates
        logger.handlers.clear()
        logger.addHandler(file_handler)

        # Set restrictive permissions on log file
        try:
            os.chmod(AUDIT_LOG_FILE, 0o600)
        except (OSError, FileNotFoundError):
            pass  # File doesn't exist yet, will be created with restrictive perms
    except Exception as e:
        print(f"Warning: Failed to setup file logging: {e}", flush=True)

    return logger

# Setup encryption
class EncryptedStorage:
    """Handles encryption/decryption of sensitive data at rest"""

    def __init__(self, key_file: Path):
        self.key_file = key_file
        self.cipher = self._load_or_create_key()

    def _load_or_create_key(self) -> Fernet:
        """Load existing encryption key or create new one"""
        if self.key_file.exists():
            with open(self.key_file, 'rb') as f:
                key = f.read()
        else:
            # Generate new encryption key
            key = Fernet.generate_key()
            self.key_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self.key_file, 'wb') as f:
                f.write(key)
            # Protect the master key with restrictive permissions
            os.chmod(self.key_file, 0o600)

        return Fernet(key)

    def encrypt(self, data: str) -> str:
        """Encrypt data and return base64-encoded result"""
        return self.cipher.encrypt(data.encode()).decode()

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt base64-encoded data"""
        return self.cipher.decrypt(encrypted_data.encode()).decode()

# Initialize logger and encryption
logger = setup_logging()
try:
    encrypted_storage = EncryptedStorage(MASTER_KEY_FILE)
    logger.info("Encryption system initialized successfully")
except Exception as e:
    print(f"CRITICAL: Failed to initialize encryption: {e}", flush=True)
    import sys
    sys.exit(1)

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
    "max_api_keys_per_ip": 10,
    "idle_timeout_days": 7,
    "entry_lifespan_days": None,
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
        """Save encrypted clipboard to disk"""
        try:
            backup_dir = Path(self.backup_path)
            backup_dir.mkdir(parents=True, exist_ok=True)
            backup_file = backup_dir / f"{self.api_key}.json"

            # Serialize stack to JSON
            json_data = json.dumps(self.stack)

            # Encrypt the data
            encrypted_data = encrypted_storage.encrypt(json_data)

            # Write encrypted data to file
            with open(backup_file, 'w') as f:
                f.write(encrypted_data)

            # Protect with restrictive permissions
            os.chmod(backup_file, 0o600)
        except Exception as e:
            print(f"Warning: Failed to save backup for {self.api_key}: {e}")

    def load_from_backup(self) -> None:
        """Load and decrypt clipboard from disk if it exists"""
        try:
            backup_dir = Path(self.backup_path)
            backup_file = backup_dir / f"{self.api_key}.json"
            if backup_file.exists():
                with open(backup_file, 'r') as f:
                    encrypted_data = f.read()

                # Decrypt the data
                decrypted_data = encrypted_storage.decrypt(encrypted_data)
                self.stack = json.loads(decrypted_data)
        except Exception as e:
            print(f"Warning: Failed to load backup for {self.api_key}: {e}")
            self.stack = []

class APIKeyManager:
    """Manages API keys and their metadata with encryption"""

    def __init__(self, keys_file: str):
        self.keys_file = Path(keys_file)
        self.keys_data = self.load_keys()

    def load_keys(self) -> dict:
        """Load and decrypt keys from file"""
        if self.keys_file.exists():
            try:
                with open(self.keys_file, 'r') as f:
                    encrypted_data = f.read()

                # Decrypt the file content
                decrypted_data = encrypted_storage.decrypt(encrypted_data)
                return json.loads(decrypted_data)
            except Exception as e:
                logger.warning(f"Failed to load keys file: {e}. Starting with empty keys.")
                return {}
        return {}

    def save_keys(self) -> None:
        """Encrypt and save keys to file"""
        self.keys_file.parent.mkdir(parents=True, exist_ok=True)
        try:
            # Serialize keys to JSON
            json_data = json.dumps(self.keys_data, indent=2)

            # Encrypt the data
            encrypted_data = encrypted_storage.encrypt(json_data)

            # Write encrypted data to file
            with open(self.keys_file, 'w') as f:
                f.write(encrypted_data)

            # Protect with restrictive permissions
            os.chmod(self.keys_file, 0o600)
        except Exception as e:
            logger.error(f"Failed to save keys file: {e}")

    def generate_key(self) -> str:
        """Generate a new API key"""
        key = f"plaster_{secrets.token_hex(16)}"
        self.keys_data[key] = {
            "created": datetime.now().isoformat(),
            "last_used": None
        }
        self.save_keys()
        logger.info(f"Generated new API key: {key[:16]}...")
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
            logger.info(f"Deleted API key: {key[:16]}...")
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

class APIKeyGenerationLimiter:
    """Limit API key generation per IP address with FILO (oldest key deleted when limit reached)"""

    def __init__(self, max_keys_per_ip: int):
        self.max_keys_per_ip = max_keys_per_ip
        self.ips: Dict[str, List[str]] = {}  # ip -> list of api keys (oldest first)

    def get_oldest_key_if_at_limit(self, ip: str) -> str:
        """
        Check if IP is at limit and return oldest key to delete.
        Returns None if not at limit.
        """
        if ip not in self.ips:
            self.ips[ip] = []

        if len(self.ips[ip]) >= self.max_keys_per_ip:
            # Return oldest key (first in list)
            return self.ips[ip][0]
        return None

    def record_key(self, ip: str, api_key: str) -> None:
        """Record that this IP generated this key (append to end)"""
        if ip not in self.ips:
            self.ips[ip] = []
        self.ips[ip].append(api_key)

    def remove_key(self, api_key: str) -> None:
        """Remove a key from tracking when it's deleted"""
        for ip in list(self.ips.keys()):
            if api_key in self.ips[ip]:
                self.ips[ip].remove(api_key)
            if not self.ips[ip]:
                del self.ips[ip]

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
api_key_gen_limiter = APIKeyGenerationLimiter(
    config.get("max_api_keys_per_ip", 10)
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
                # Remove from API key generation limiter
                api_key_gen_limiter.remove_key(key)

            if expired_keys:
                logger.info(f"Cleanup task: Deleted {len(expired_keys)} idle API keys (idle > {idle_timeout_days} days)")
                for key in expired_keys:
                    logger.warning(f"Deleted idle key: {key[:16]}...")
        except Exception as e:
            logger.error(f"Error in cleanup task: {e}")

@app.on_event("startup")
async def startup_event():
    """Start cleanup task on server startup"""
    logger.info("="*60)
    logger.info("Plaster server starting")
    logger.info(f"Config: {CONFIG_FILE}")
    logger.info(f"Encryption key: {MASTER_KEY_FILE}")
    logger.info(f"Audit log: {AUDIT_LOG_FILE}")
    logger.info("="*60)
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
    client_ip = request.client.host if request.client else "unknown"

    # Skip auth for health check, static docs, key generation, and root path (initial setup)
    if path in ["/health", "/docs", "/openapi.json", "/auth/generate", "/"]:
        return await call_next(request)

    # Get API key from header
    api_key = request.headers.get("X-API-Key")

    if not api_key:
        logger.warning(f"Missing X-API-Key header from {client_ip} for {path}")
        raise HTTPException(status_code=401, detail="Missing X-API-Key header")

    if not key_manager.validate_key(api_key):
        logger.warning(f"Invalid API key attempt from {client_ip} for {path}")
        raise HTTPException(status_code=401, detail="Invalid API key")

    # Check rate limit
    if not rate_limiter.is_allowed(api_key):
        logger.warning(f"Rate limit exceeded for {api_key[:16]}... from {client_ip}")
        raise HTTPException(status_code=429, detail="Rate limit exceeded")

    # Update last used
    key_manager.update_last_used(api_key)

    # Log successful authentication
    logger.info(f"Authenticated {api_key[:16]}... from {client_ip} for {request.method} {path}")

    # Store key in request state for later use
    request.state.api_key = api_key

    return await call_next(request)

def get_setup_page() -> str:
    """Generate the setup/login page with retro theme"""
    return r"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PLASTER - Clipboard Service</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Courier+Prime:wght@400;700&display=swap');

            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }

            body {
                font-family: 'Courier Prime', monospace;
                background: #001a33;
                background-image:
                    repeating-linear-gradient(
                        0deg,
                        rgba(0, 255, 0, 0.03) 0px,
                        rgba(0, 255, 0, 0.03) 1px,
                        transparent 1px,
                        transparent 2px
                    );
                min-height: 100vh;
                padding: 20px;
                display: flex;
                justify-content: center;
                align-items: center;
                color: #00ff00;
                text-shadow: 0 0 10px rgba(0, 255, 0, 0.5);
            }

            .container {
                background: #0a0e27;
                border: 3px solid #00ff00;
                box-shadow:
                    0 0 20px rgba(0, 255, 0, 0.4),
                    inset 0 0 20px rgba(0, 255, 0, 0.1);
                max-width: 600px;
                width: 100%;
                overflow: hidden;
                position: relative;
            }

            .header {
                background: #002244;
                color: #00ff00;
                padding: 40px 30px;
                text-align: center;
                border-bottom: 2px solid #00ff00;
            }

            .header h1 {
                font-size: 32px;
                margin-bottom: 8px;
                font-weight: 700;
                letter-spacing: 3px;
                text-transform: uppercase;
                text-shadow: 0 0 15px rgba(0, 255, 0, 0.6);
            }

            .header p {
                opacity: 0.9;
                font-size: 12px;
                letter-spacing: 2px;
                text-transform: uppercase;
            }

            .content {
                padding: 40px 30px;
            }

            .section {
                margin-bottom: 30px;
            }

            .section h2 {
                font-size: 14px;
                color: #00ff00;
                margin-bottom: 15px;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 2px;
                text-shadow: 0 0 5px rgba(0, 255, 0, 0.3);
            }

            .input-group {
                display: flex;
                gap: 10px;
                margin-bottom: 15px;
            }

            #apiKeyInput {
                flex: 1;
                padding: 10px 12px;
                border: 1px solid #00ff00;
                border-radius: 2px;
                font-size: 12px;
                font-family: 'Courier Prime', monospace;
                background: #0d0d1f;
                color: #00ff00;
                transition: all 0.15s ease;
                text-shadow: 0 0 5px rgba(0, 255, 0, 0.1);
            }

            #apiKeyInput:focus {
                outline: none;
                border-color: #00ff00;
                box-shadow: 0 0 20px rgba(0, 255, 0, 0.4), inset 0 0 10px rgba(0, 255, 0, 0.1);
            }

            #apiKeyInput::placeholder {
                color: #00884488;
            }

            button {
                padding: 10px 16px;
                border: 1px solid #00ff00;
                border-radius: 2px;
                font-size: 11px;
                font-weight: 700;
                font-family: 'Courier Prime', monospace;
                cursor: pointer;
                transition: all 0.15s ease;
                text-transform: uppercase;
                letter-spacing: 1px;
                background: #002244;
                color: #00ff00;
                text-shadow: 0 0 5px rgba(0, 255, 0, 0.3);
            }

            .btn-primary {
                flex: 0 0 auto;
            }

            .btn-primary:hover {
                background: #00ff00;
                color: #001a33;
                box-shadow: 0 0 15px rgba(0, 255, 0, 0.6);
                text-shadow: none;
            }

            .instructions {
                background: #0d0d1f;
                border: 1px solid #00884422;
                border-left: 3px solid #00ff00;
                padding: 15px;
                border-radius: 2px;
                line-height: 1.6;
            }

            .instructions h3 {
                color: #00ff00;
                font-size: 11px;
                margin-bottom: 10px;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 2px;
                text-shadow: 0 0 5px rgba(0, 255, 0, 0.2);
            }

            .instructions ol {
                margin-left: 20px;
                color: #00ff00;
                font-size: 11px;
            }

            .instructions li {
                margin-bottom: 8px;
                opacity: 0.95;
            }

            .code-block {
                background: #050509;
                padding: 10px;
                border-radius: 2px;
                border: 1px solid #00442288;
                font-family: 'Courier Prime', monospace;
                font-size: 10px;
                margin-top: 8px;
                overflow-x: auto;
                color: #00ff00;
                text-shadow: 0 0 3px rgba(0, 255, 0, 0.2);
            }

            .toast {
                position: fixed;
                bottom: 20px;
                right: 20px;
                background: #004400;
                color: #00ff00;
                padding: 14px 20px;
                border: 1px solid #00ff00;
                border-radius: 2px;
                box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
                opacity: 0;
                transform: translateY(20px);
                transition: all 0.3s ease;
                z-index: 1000;
                font-family: 'Courier Prime', monospace;
                font-size: 12px;
                text-shadow: 0 0 5px rgba(0, 255, 0, 0.3);
            }

            .toast.show {
                opacity: 1;
                transform: translateY(0);
            }

            .toast.error {
                background: #440000;
                color: #ff6666;
                border-color: #ff6666;
                box-shadow: 0 0 20px rgba(255, 102, 102, 0.3);
                text-shadow: 0 0 5px rgba(255, 102, 102, 0.2);
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
                <h1>PLASTER</h1>
                <p>FILO Clipboard Service</p>
            </div>

            <div class="content">
                <div class="section">
                    <h2>Access Clipboard</h2>
                    <div class="input-group">
                        <input type="text" id="apiKeyInput" placeholder="Enter API key..." />
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
    """Generate the HTML page with retro/old school computer theme"""
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>PLASTER - Clipboard Service</title>
        <style>
            @import url('https://fonts.googleapis.com/css2?family=Courier+Prime:wght@400;700&display=swap');

            * {{
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }}

            body {{
                font-family: 'Courier Prime', monospace;
                background: #001a33;
                background-image:
                    repeating-linear-gradient(
                        0deg,
                        rgba(0, 255, 0, 0.03) 0px,
                        rgba(0, 255, 0, 0.03) 1px,
                        transparent 1px,
                        transparent 2px
                    );
                min-height: 100vh;
                padding: 20px;
                display: flex;
                justify-content: center;
                align-items: center;
                color: #00ff00;
                text-shadow: 0 0 10px rgba(0, 255, 0, 0.5);
            }}

            .container {{
                background: #0a0e27;
                border: 3px solid #00ff00;
                box-shadow:
                    0 0 20px rgba(0, 255, 0, 0.4),
                    inset 0 0 20px rgba(0, 255, 0, 0.1);
                max-width: 800px;
                width: 100%;
                overflow: hidden;
                position: relative;
            }}

            .container::before {{
                content: '';
                position: absolute;
                top: 0;
                left: 0;
                right: 0;
                bottom: 0;
                pointer-events: none;
                background:
                    repeating-linear-gradient(
                        0deg,
                        rgba(0, 255, 0, 0.05) 0px,
                        rgba(0, 255, 0, 0.05) 1px,
                        transparent 1px,
                        transparent 2px
                    );
            }}

            .header {{
                background: #002244;
                color: #00ff00;
                padding: 30px 30px;
                text-align: center;
                border-bottom: 2px solid #00ff00;
                position: relative;
                z-index: 1;
            }}

            .header h1 {{
                font-size: 32px;
                margin-bottom: 8px;
                font-weight: 700;
                letter-spacing: 3px;
                text-transform: uppercase;
                text-shadow: 0 0 15px rgba(0, 255, 0, 0.6);
            }}

            .header p {{
                opacity: 0.9;
                font-size: 12px;
                letter-spacing: 2px;
                text-transform: uppercase;
            }}

            .api-key-section {{
                background: #1a1f3a;
                padding: 20px;
                border: 1px solid #00ff00;
                border-radius: 2px;
                margin-top: 20px;
                box-shadow: 0 0 10px rgba(0, 255, 0, 0.2);
            }}

            .api-key-label {{
                font-size: 11px;
                text-transform: uppercase;
                color: #00ff00;
                letter-spacing: 2px;
                margin-bottom: 10px;
                display: block;
                text-shadow: 0 0 5px rgba(0, 255, 0, 0.3);
            }}

            .api-key-container {{
                display: flex;
                gap: 8px;
                align-items: center;
                background: #0d0d1f;
                padding: 10px 12px;
                border: 1px solid #00ff00;
                border-radius: 2px;
                font-family: 'Courier Prime', monospace;
                font-size: 11px;
                word-break: break-all;
            }}

            .api-key-value {{
                flex: 1;
                color: #00ff00;
                text-shadow: 0 0 5px rgba(0, 255, 0, 0.3);
            }}

            .api-key-input {{
                flex: 1;
                padding: 8px 10px;
                border: 1px solid #00ff00;
                border-radius: 2px;
                font-family: 'Courier Prime', monospace;
                font-size: 11px;
                background: #0d0d1f;
                color: #00ff00;
                text-shadow: 0 0 5px rgba(0, 255, 0, 0.3);
            }}

            .api-key-input::placeholder {{
                color: #00884422;
            }}

            .btn-copy-key,
            .btn-switch,
            .btn-rotate,
            .btn-load-key {{
                background: #002244;
                color: #00ff00;
                border: 1px solid #00ff00;
                border-radius: 2px;
                padding: 6px 10px;
                cursor: pointer;
                font-size: 10px;
                font-weight: 700;
                font-family: 'Courier Prime', monospace;
                white-space: nowrap;
                transition: all 0.15s;
                text-transform: uppercase;
                letter-spacing: 1px;
                text-shadow: 0 0 5px rgba(0, 255, 0, 0.3);
            }}

            .btn-copy-key:hover,
            .btn-switch:hover,
            .btn-rotate:hover,
            .btn-load-key:hover {{
                background: #00ff00;
                color: #001a33;
                box-shadow: 0 0 15px rgba(0, 255, 0, 0.6);
                text-shadow: none;
            }}

            .btn-copy-key.copied {{
                background: #00ff00;
                color: #001a33;
            }}

            .content {{
                padding: 30px 30px;
                position: relative;
                z-index: 1;
            }}

            .input-section {{
                margin-bottom: 25px;
            }}

            .input-label {{
                display: block;
                font-size: 11px;
                font-weight: 700;
                color: #00ff00;
                margin-bottom: 8px;
                text-transform: uppercase;
                letter-spacing: 2px;
                text-shadow: 0 0 5px rgba(0, 255, 0, 0.3);
            }}

            #textInput {{
                width: 100%;
                padding: 10px 12px;
                border: 1px solid #00ff00;
                border-radius: 2px;
                font-size: 12px;
                font-family: 'Courier Prime', monospace;
                background: #0d0d1f;
                color: #00ff00;
                transition: all 0.15s ease;
                resize: none;
                min-height: 80px;
                text-shadow: 0 0 5px rgba(0, 255, 0, 0.1);
            }}

            #textInput:focus {{
                outline: none;
                border-color: #00ff00;
                box-shadow: 0 0 20px rgba(0, 255, 0, 0.4), inset 0 0 10px rgba(0, 255, 0, 0.1);
            }}

            .button-group {{
                display: flex;
                gap: 8px;
                margin-top: 12px;
            }}

            button {{
                padding: 8px 16px;
                border: 1px solid #00ff00;
                border-radius: 2px;
                font-size: 11px;
                font-weight: 700;
                font-family: 'Courier Prime', monospace;
                cursor: pointer;
                transition: all 0.15s ease;
                text-transform: uppercase;
                letter-spacing: 1px;
                background: #002244;
                color: #00ff00;
                text-shadow: 0 0 5px rgba(0, 255, 0, 0.3);
            }}

            .btn-primary {{
                flex: 1;
            }}

            .btn-primary:hover {{
                background: #00ff00;
                color: #001a33;
                box-shadow: 0 0 15px rgba(0, 255, 0, 0.6);
                text-shadow: none;
            }}

            .btn-danger {{
                background: #440000;
                color: #ff6666;
                border-color: #ff6666;
                text-shadow: 0 0 5px rgba(255, 102, 102, 0.3);
            }}

            .btn-danger:hover {{
                background: #ff6666;
                color: #440000;
                box-shadow: 0 0 15px rgba(255, 102, 102, 0.6);
                text-shadow: none;
            }}

            .btn-copy {{
                background: #002244;
                color: #00ff00;
                padding: 6px 10px;
                font-size: 10px;
                border-radius: 2px;
                flex-shrink: 0;
                border: 1px solid #00ff00;
            }}

            .btn-copy:hover {{
                background: #00ff00;
                color: #001a33;
                box-shadow: 0 0 15px rgba(0, 255, 0, 0.6);
            }}

            .btn-copy.copied {{
                background: #00ff00;
                color: #001a33;
            }}

            .list-section {{
                margin-top: 30px;
            }}

            .list-header {{
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 15px;
                padding-bottom: 10px;
                border-bottom: 1px solid #00884422;
            }}

            .list-title {{
                font-size: 13px;
                font-weight: 700;
                color: #00ff00;
                text-transform: uppercase;
                letter-spacing: 2px;
                text-shadow: 0 0 5px rgba(0, 255, 0, 0.3);
            }}

            .list-count {{
                background: #002244;
                color: #00ff00;
                padding: 4px 10px;
                border: 1px solid #00884422;
                border-radius: 2px;
                font-size: 11px;
                font-weight: 700;
                text-shadow: 0 0 5px rgba(0, 255, 0, 0.2);
            }}

            .entries-list {{
                display: flex;
                flex-direction: column;
                gap: 8px;
                max-height: 400px;
                overflow-y: auto;
                overflow-x: hidden;
                padding-right: 5px;
            }}

            .entry-item {{
                display: flex;
                align-items: center;
                gap: 8px;
                padding: 10px 12px;
                background: #0d0d1f;
                border: 1px solid #00884422;
                border-left: 3px solid #00ff00;
                border-radius: 2px;
                transition: all 0.15s ease;
            }}

            .entry-item:hover {{
                background: #1a1f3a;
                border-left-color: #00ff00;
                box-shadow: 0 0 15px rgba(0, 255, 0, 0.2);
            }}

            .entry-index {{
                font-weight: 700;
                color: #00ff00;
                font-size: 10px;
                min-width: 28px;
                text-align: center;
                text-shadow: 0 0 5px rgba(0, 255, 0, 0.3);
                font-family: 'Courier Prime', monospace;
            }}

            .entry-text {{
                flex: 1;
                font-size: 12px;
                color: #00ff00;
                word-break: break-word;
                font-family: 'Courier Prime', monospace;
                line-height: 1.4;
                text-shadow: 0 0 3px rgba(0, 255, 0, 0.1);
                max-height: 200px;
                overflow: hidden;
            }}

            .empty-state {{
                text-align: center;
                padding: 30px 20px;
                color: #00884422;
            }}

            .empty-state-icon {{
                font-size: 48px;
                margin-bottom: 16px;
                opacity: 0.4;
            }}

            .empty-state-text {{
                font-size: 12px;
                color: #00884422;
                text-transform: uppercase;
                letter-spacing: 1px;
            }}

            .toast {{
                position: fixed;
                bottom: 20px;
                right: 20px;
                background: #002244;
                color: #00ff00;
                border: 1px solid #00ff00;
                padding: 12px 16px;
                border-radius: 2px;
                box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
                opacity: 0;
                transform: translateY(20px);
                transition: all 0.3s ease;
                z-index: 1000;
                text-shadow: 0 0 5px rgba(0, 255, 0, 0.3);
                font-family: 'Courier Prime', monospace;
                font-size: 12px;
            }}

            .toast.show {{
                opacity: 1;
                transform: translateY(0);
            }}

            .toast.error {{
                color: #ff6666;
                border-color: #ff6666;
                background: #440000;
                box-shadow: 0 0 20px rgba(255, 102, 102, 0.3);
            }}

            ::-webkit-scrollbar {{
                width: 10px;
                height: 10px;
            }}

            ::-webkit-scrollbar-track {{
                background: #0d0d1f;
                border: 1px solid #00884422;
            }}

            ::-webkit-scrollbar-thumb {{
                background: #002244;
                border: 1px solid #00ff00;
                border-radius: 2px;
            }}

            ::-webkit-scrollbar-thumb:hover {{
                background: #00ff00;
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
                <p style="opacity: 0.8; font-size: 12px; margin-top: 10px;">A FILO (First In, Last Out) clipboard - newest entries accessed first</p>

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

                <div class="list-section" style="margin-top: 50px; border-top: 1px solid #e0e0e0; padding-top: 30px;">
                    <div class="list-title" style="margin-bottom: 15px;">CLI Usage</div>
                    <div class="instructions">
                        <p style="margin-bottom: 10px; color: #666; font-size: 13px;">Use the command-line client for quick access:</p>
                        <pre style="background: #f0f0f0; padding: 10px; border-radius: 6px; overflow-x: auto; font-size: 12px; color: #333;">plaster              # Get latest entry (LIFO)
plaster --list       # List all entries
plaster -n 1         # Get 1st entry (1-indexed)
plaster -n 3         # Get 3rd entry
echo 'text' | plaster    # Push text
plaster --clear      # Clear all entries
plaster --api        # Show current API key
plaster --url        # Show current server URL
plaster --new-api    # Generate new API key</pre>
                    </div>
                </div>
            </div>
        </div>

        <div class="toast" id="toast"></div>

        <script>
            const API_BASE = window.location.origin;
            let currentApiKey = '{api_key}';
            let isOwnKey = true;

            // Check if API key was passed via query parameter
            function initializeApiKey() {{
                const params = new URLSearchParams(window.location.search);
                const queryApiKey = params.get('api_key');

                if (queryApiKey) {{
                    currentApiKey = queryApiKey;
                    isOwnKey = false;
                    updateKeyDisplay();
                    // Remove query parameter from URL
                    window.history.replaceState({{}}, document.title, window.location.pathname);
                    loadEntries();
                }}
            }}

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
                                    <span class="entry-index">#${{index + 1}}</span>
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
            document.addEventListener('DOMContentLoaded', () => {{
                initializeApiKey();
                loadEntries();
            }});

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

    # If no key in state, check query parameter
    if not api_key:
        api_key = request.query_params.get('api_key')

    if not api_key:
        # No API key provided - show setup instructions
        return get_setup_page()

    return get_html_page(api_key)

@app.post("/auth/generate")
async def generate_key(request: Request):
    """Generate a new API key (first time setup)"""
    # Get client IP
    client_ip = request.client.host if request.client else "unknown"

    logger.info(f"API key generation requested from {client_ip}")

    # Check if this IP is at limit and delete oldest key if needed
    oldest_key = api_key_gen_limiter.get_oldest_key_if_at_limit(client_ip)
    if oldest_key:
        # Delete the oldest key
        key_manager.delete_key(oldest_key)
        api_key_gen_limiter.remove_key(oldest_key)
        # Delete clipboard data for this key
        if oldest_key in clipboards:
            del clipboards[oldest_key]
        # Delete backup file
        backup_file = Path(BACKUP_DIR) / f"{oldest_key}.json"
        if backup_file.exists():
            backup_file.unlink()
        logger.warning(f"FILO deletion: Removed oldest key {oldest_key[:16]}... from {client_ip} (limit reached)")

    # Generate the new key
    key = key_manager.generate_key()

    # Record this generation
    api_key_gen_limiter.record_key(client_ip, key)

    get_or_create_clipboard(key)
    logger.info(f"Successfully generated new API key from {client_ip}")
    return {"status": "ok", "api_key": key}

@app.post("/auth/rotate")
async def rotate_key(request: Request):
    """Rotate API key (generates new key, keeps old for backwards compatibility)"""
    old_key = request.state.api_key
    new_key = key_manager.generate_key()

    logger.info(f"Rotated API key: {old_key[:16]}... -> {new_key[:16]}...")

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
        logger.info(f"Pushed text entry ({len(entry.text)} bytes) for {api_key[:16]}...")
        return {"status": "ok", "message": f"Added text (length: {len(entry.text)})"}
    except ValueError as e:
        logger.warning(f"Failed to push entry for {api_key[:16]}...: {e}")
        raise HTTPException(status_code=413, detail=str(e))

@app.get("/pop")
async def pop(request: Request):
    """Get and remove the most recent entry"""
    api_key = request.state.api_key
    clipboard = get_or_create_clipboard(api_key)

    try:
        entry = clipboard.pop()
        logger.info(f"Popped entry ({len(entry)} bytes) for {api_key[:16]}...")
        return {"status": "ok", "text": entry}
    except ValueError as e:
        logger.info(f"Pop failed for {api_key[:16]}... (clipboard empty)")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/peek")
async def peek(request: Request):
    """Get the most recent entry without removing it"""
    api_key = request.state.api_key
    clipboard = get_or_create_clipboard(api_key)

    try:
        entry = clipboard.peek()
        logger.info(f"Peeked entry ({len(entry)} bytes) for {api_key[:16]}...")
        return {"status": "ok", "text": entry}
    except ValueError as e:
        logger.info(f"Peek failed for {api_key[:16]}... (clipboard empty)")
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/list")
async def list_entries(request: Request):
    """Get all entries with first 50 characters preview"""
    api_key = request.state.api_key
    clipboard = get_or_create_clipboard(api_key)

    entries = clipboard.get_all()
    previews = [entry[:50] + ("..." if len(entry) > 50 else "") for entry in entries]
    logger.info(f"Listed {len(entries)} entries for {api_key[:16]}...")
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
        logger.info(f"Retrieved entry {index} ({len(entry)} bytes) for {api_key[:16]}...")
        return {"status": "ok", "index": index, "text": entry}
    except ValueError as e:
        logger.warning(f"Failed to get entry {index} for {api_key[:16]}...: {e}")
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/clear")
async def clear(request: Request):
    """Clear all entries"""
    api_key = request.state.api_key
    clipboard = get_or_create_clipboard(api_key)

    clipboard.clear()
    logger.warning(f"Cleared all entries for {api_key[:16]}...")
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
