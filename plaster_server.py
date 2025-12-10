#!/usr/bin/env python3
"""
Plaster - A clipboard service that stores multiple entries (FILO stack)
"""

import json
import os
from pathlib import Path
from typing import List
import yaml
from fastapi import FastAPI, HTTPException, Body
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
import uvicorn

# Configuration management
CONFIG_DIR = Path.home() / ".plaster"
CONFIG_FILE = CONFIG_DIR / "config.yaml"
BACKUP_FILE = CONFIG_DIR / "backup.json"

# Default configuration
DEFAULT_CONFIG = {
    "server_url": "http://localhost:9321",
    "max_entries": 100,
    "persistence": True,
    "backup_file": str(BACKUP_FILE),
    "port": 9321
}

class TextEntry(BaseModel):
    text: str

class Clipboard:
    """Manages clipboard entries with FILO (First In, Last Out) behavior"""

    def __init__(self, max_entries: int = 100, backup_path: str = None, persistence: bool = True):
        self.stack: List[str] = []
        self.max_entries = max_entries
        self.persistence = persistence
        self.backup_path = backup_path or str(BACKUP_FILE)
        self.load_from_backup()

    def push(self, text: str) -> None:
        """Add text to clipboard (newest on top)"""
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
            backup_path = Path(self.backup_path)
            backup_path.parent.mkdir(parents=True, exist_ok=True)
            with open(backup_path, 'w') as f:
                json.dump(self.stack, f)
        except Exception as e:
            print(f"Warning: Failed to save backup: {e}")

    def load_from_backup(self) -> None:
        """Load clipboard from disk if it exists"""
        try:
            backup_path = Path(self.backup_path)
            if backup_path.exists():
                with open(backup_path, 'r') as f:
                    self.stack = json.load(f)
        except Exception as e:
            print(f"Warning: Failed to load backup: {e}")
            self.stack = []

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

# Load configuration and initialize clipboard
config = load_config()
clipboard = Clipboard(
    max_entries=config.get("max_entries", 100),
    backup_path=config.get("backup_file", str(BACKUP_FILE)),
    persistence=config.get("persistence", True)
)

# Create FastAPI app
app = FastAPI(title="Plaster", version="1.0.0")

def get_html_page() -> str:
    """Generate the HTML page with embedded CSS and JavaScript"""
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

            .input-section {
                margin-bottom: 30px;
            }

            .input-label {
                display: block;
                font-size: 14px;
                font-weight: 600;
                color: #333;
                margin-bottom: 10px;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }

            .input-group {
                display: flex;
                gap: 10px;
            }

            #textInput {
                flex: 1;
                padding: 14px 16px;
                border: 2px solid #e0e0e0;
                border-radius: 10px;
                font-size: 14px;
                font-family: inherit;
                transition: all 0.3s ease;
                resize: none;
                min-height: 80px;
            }

            #textInput:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }

            .button-group {
                display: flex;
                gap: 10px;
                margin-top: 15px;
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
                flex: 1;
            }

            .btn-primary:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(102, 126, 234, 0.3);
            }

            .btn-primary:active {
                transform: translateY(0);
            }

            .btn-danger {
                background: #ff6b6b;
                color: white;
            }

            .btn-danger:hover {
                background: #ee5a52;
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(255, 107, 107, 0.3);
            }

            .btn-danger:active {
                transform: translateY(0);
            }

            .btn-copy {
                background: #f0f0f0;
                color: #333;
                padding: 8px 12px;
                font-size: 12px;
                border-radius: 6px;
                flex-shrink: 0;
            }

            .btn-copy:hover {
                background: #667eea;
                color: white;
                transform: translateY(-2px);
            }

            .btn-copy.copied {
                background: #51cf66;
                color: white;
            }

            .list-section {
                margin-top: 40px;
            }

            .list-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 20px;
            }

            .list-title {
                font-size: 18px;
                font-weight: 700;
                color: #333;
            }

            .list-count {
                background: #f0f0f0;
                color: #666;
                padding: 6px 12px;
                border-radius: 20px;
                font-size: 13px;
                font-weight: 600;
            }

            .entries-list {
                display: flex;
                flex-direction: column;
                gap: 12px;
                max-height: 400px;
                overflow-y: auto;
            }

            .entry-item {
                display: flex;
                align-items: center;
                gap: 12px;
                padding: 14px 16px;
                background: #f8f9fa;
                border-radius: 10px;
                border-left: 4px solid #667eea;
                transition: all 0.3s ease;
            }

            .entry-item:hover {
                background: #f0f0f0;
                transform: translateX(4px);
            }

            .entry-index {
                font-weight: 700;
                color: #667eea;
                font-size: 12px;
                min-width: 24px;
                text-align: center;
            }

            .entry-text {
                flex: 1;
                font-size: 14px;
                color: #333;
                word-break: break-word;
                font-family: 'Menlo', 'Monaco', 'Courier New', monospace;
                line-height: 1.4;
            }

            .empty-state {
                text-align: center;
                padding: 40px 20px;
                color: #999;
            }

            .empty-state-icon {
                font-size: 48px;
                margin-bottom: 16px;
                opacity: 0.5;
            }

            .empty-state-text {
                font-size: 14px;
                color: #999;
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

            ::-webkit-scrollbar {
                width: 6px;
            }

            ::-webkit-scrollbar-track {
                background: #f1f1f1;
            }

            ::-webkit-scrollbar-thumb {
                background: #667eea;
                border-radius: 3px;
            }

            ::-webkit-scrollbar-thumb:hover {
                background: #764ba2;
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

                .button-group {
                    flex-direction: column;
                }

                .btn-primary {
                    flex: unset;
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

            async function loadEntries() {
                try {
                    const response = await fetch(API_BASE + '/list');
                    const data = await response.json();

                    if (data.status === 'ok') {
                        const entriesList = document.getElementById('entriesList');
                        const entryCount = document.getElementById('entryCount');

                        if (data.count === 0) {
                            entriesList.innerHTML = `
                                <div class="empty-state">
                                    <div class="empty-state-icon">📭</div>
                                    <div class="empty-state-text">No clipboard entries yet</div>
                                </div>
                            `;
                            entryCount.textContent = '0 entries';
                        } else {
                            entriesList.innerHTML = data.entries.map((entry, index) => `
                                <div class="entry-item">
                                    <span class="entry-index">#${index}</span>
                                    <span class="entry-text">${escapeHtml(entry)}</span>
                                    <button class="btn-copy" onclick="copyToClipboard(${index}, this)">Copy</button>
                                </div>
                            `).join('');

                            entryCount.textContent = data.count === 1 ? '1 entry' : `${data.count} entries`;
                        }
                    }
                } catch (error) {
                    console.error('Error loading entries:', error);
                    showToast('Error loading entries', 'error');
                }
            }

            async function pushText() {
                const text = document.getElementById('textInput').value.trim();

                if (!text) {
                    showToast('Please enter some text', 'error');
                    return;
                }

                try {
                    const response = await fetch(API_BASE + '/push', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ text: text })
                    });

                    if (response.ok) {
                        document.getElementById('textInput').value = '';
                        showToast('✓ Text pushed to clipboard');
                        loadEntries();
                    } else {
                        showToast('Error pushing text', 'error');
                    }
                } catch (error) {
                    console.error('Error:', error);
                    showToast('Error pushing text', 'error');
                }
            }

            async function copyToClipboard(index, button) {
                try {
                    const response = await fetch(API_BASE + `/entry/${index}`);
                    const data = await response.json();

                    if (data.status === 'ok') {
                        await navigator.clipboard.writeText(data.text);

                        button.classList.add('copied');
                        button.textContent = 'Copied!';

                        setTimeout(() => {
                            button.classList.remove('copied');
                            button.textContent = 'Copy';
                        }, 2000);

                        showToast('✓ Copied to clipboard');
                    }
                } catch (error) {
                    console.error('Error:', error);
                    showToast('Error copying to clipboard', 'error');
                }
            }

            async function clearClipboard() {
                if (!confirm('Are you sure you want to clear all clipboard entries?')) {
                    return;
                }

                try {
                    const response = await fetch(API_BASE + '/clear', {
                        method: 'DELETE'
                    });

                    if (response.ok) {
                        showToast('✓ Clipboard cleared');
                        loadEntries();
                    } else {
                        showToast('Error clearing clipboard', 'error');
                    }
                } catch (error) {
                    console.error('Error:', error);
                    showToast('Error clearing clipboard', 'error');
                }
            }

            function showToast(message, type = 'success') {
                const toast = document.getElementById('toast');
                toast.textContent = message;
                toast.className = 'toast show';

                setTimeout(() => {
                    toast.classList.remove('show');
                }, 3000);
            }

            function escapeHtml(text) {
                const map = {
                    '&': '&amp;',
                    '<': '&lt;',
                    '>': '&gt;',
                    '"': '&quot;',
                    "'": '&#039;'
                };
                return text.replace(/[&<>"']/g, m => map[m]);
            }

            // Load entries on page load and set up auto-refresh
            document.addEventListener('DOMContentLoaded', loadEntries);

            // Refresh entries every 2 seconds
            setInterval(loadEntries, 2000);

            // Allow Enter key to push text
            document.getElementById('textInput').addEventListener('keydown', (e) => {
                if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                    pushText();
                }
            });
        </script>
    </body>
    </html>
    """

@app.get("/", response_class=HTMLResponse)
async def serve_ui():
    """Serve the web UI"""
    return get_html_page()

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "ok"}

@app.post("/push")
async def push(entry: TextEntry):
    """Add text to clipboard"""
    clipboard.push(entry.text)
    return {"status": "ok", "message": f"Added text (length: {len(entry.text)})"}

@app.get("/pop")
async def pop():
    """Get and remove the most recent entry"""
    try:
        entry = clipboard.pop()
        return {"status": "ok", "text": entry}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/peek")
async def peek():
    """Get the most recent entry without removing it"""
    try:
        entry = clipboard.peek()
        return {"status": "ok", "text": entry}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/list")
async def list_entries():
    """Get all entries with first 50 characters preview"""
    entries = clipboard.get_all()
    previews = [entry[:50] + ("..." if len(entry) > 50 else "") for entry in entries]
    return {
        "status": "ok",
        "count": len(entries),
        "entries": previews
    }

@app.get("/entry/{index}")
async def get_entry(index: int):
    """Get specific entry by index"""
    try:
        entry = clipboard.get_entry(index)
        return {"status": "ok", "index": index, "text": entry}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/clear")
async def clear():
    """Clear all entries"""
    clipboard.clear()
    return {"status": "ok", "message": "Clipboard cleared"}

if __name__ == "__main__":
    port = config.get("port", 9321)
    print(f"Starting Plaster server on port {port}...")
    print(f"Config file: {CONFIG_FILE}")
    print(f"Backup file: {config.get('backup_file')}")
    print(f"Max entries: {config.get('max_entries')}")
    print(f"Persistence: {config.get('persistence')}")
    uvicorn.run(app, host="0.0.0.0", port=port)
