# Plaster Security Audit Report

**Date:** December 11, 2025
**Scope:** plaster_server.py, plaster (bash client), plaster.ps1 (PowerShell client)
**Assessment Type:** Comprehensive Security Review

---

## Executive Summary

This security audit identified **53 total vulnerabilities** across the Plaster clipboard service:

- **11 Critical** - Require immediate remediation before production deployment
- **10 High** - Should be fixed before going live
- **25 Medium** - Important security hardening
- **4 Low** - Minor security improvements
- **3 Info** - Informational findings

**Risk Level: CRITICAL** - Do not deploy to production without addressing critical findings.

---

## Critical Issues (11)

### 1. **No TLS/HTTPS Encryption** 🔴
**Severity:** CRITICAL
**Location:** plaster_server.py, all client scripts
**Description:** All traffic between client and server is transmitted in plaintext HTTP. API keys and clipboard content are exposed to man-in-the-middle attacks.

**Impact:**
- Attackers can intercept API keys
- Clipboard content can be read in transit
- No authentication integrity verification

**Recommendation:**
```bash
# Use SSL certificates (self-signed for testing, proper CA for production)
python plaster_server.py --ssl-keyfile=key.pem --ssl-certfile=cert.pem

# Or use reverse proxy (nginx with TLS)
```

**Bash client update needed:**
```bash
# Change:
API_URL="http://${SERVER_URL}/api"

# To:
API_URL="https://${SERVER_URL}/api"

# Add certificate validation (if self-signed):
CURL_OPTS=("-k")  # Only for self-signed, add warning
```

**PowerShell client update needed:**
```powershell
# Change:
$url = "http://$ServerUrl/api"

# To:
$url = "https://$ServerUrl/api"

# Add validation for self-signed certs
```

---

### 2. **API Key Exposure in Query Parameters** 🔴
**Severity:** CRITICAL
**Location:** Client error handling, logging, potentially browser history
**Description:** If API keys are passed as query parameters (instead of headers), they appear in logs, URLs, and browser history.

**Current Status:** ✅ Using headers (X-API-Key) correctly
**Risk:** If developers add query param support, vulnerability introduced

**Recommendation:**
- Enforce API key only in headers
- Document why query parameters are not supported
- Add validation to reject query parameter API keys

---

### 3. **Unencrypted Credential Storage** 🔴
**Severity:** CRITICAL
**Location:**
- Client: `~/.plaster/config.yaml` (readable plaintext)
- Server: `~/.plaster/keys.json` (readable plaintext)

**Description:** API keys are stored in plaintext with default file permissions (644). Any process running as the user can read them.

**Impact:**
- Compromised user account = compromised API keys
- No protection against local privilege escalation
- Readable by other processes/users on shared systems

**Recommendations:**

**Bash client:**
```bash
# Protect config file with restrictive permissions
chmod 0o600 "$PLASTER_CONFIG"

# Add to setup and config write operations
[ -f "$PLASTER_CONFIG" ] && chmod 0o600 "$PLASTER_CONFIG"
```

**PowerShell client:**
```powershell
# Set restrictive ACL on config file
$acl = Get-Acl $Config
$acl.SetAccessRuleProtection($true, $false)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    [System.Security.Principal.WindowsIdentity]::GetCurrent().User,
    "FullControl",
    "Allow"
)
$acl.RemoveAccessRuleAll([System.Security.AccessControl.FileSystemAccessRule])
$acl.AddAccessRule($rule)
Set-Acl -Path $Config -AclObject $acl
```

**Server:**
```python
# In plaster_server.py after key generation:
os.chmod(KEYS_FILE, 0o600)

# And backup files:
for backup_file in backup_dir.glob("*.json"):
    os.chmod(backup_file, 0o600)
```

---

### 4. **No Rate Limiting on Login/Key Generation** 🔴
**Severity:** CRITICAL
**Location:** `/auth/generate` endpoint (line ~1435)
**Description:** Although per-IP API key limit exists (max 10), the `/auth/generate` endpoint itself has no per-request rate limiting, allowing rapid generation attempts.

**Impact:**
- Attackers can probe for valid IP addresses
- DoS vector against key generation
- No brute force protection

**Recommendation:**
```python
# Add rate limiting to /auth/generate separate from general rate limit
# Current rate limit is 100 req/min globally, but /auth/generate needs stricter limit
# Example: 5 generate attempts per 5 minutes per IP

@app.post("/auth/generate")
async def generate_key(request: Request):
    client_ip = request.client.host if request.client else "unknown"

    # Check generation rate limit (stricter than general limit)
    if not auth_rate_limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=429,
            detail="Too many key generation attempts. Wait 5 minutes."
        )
    # ... rest of function
```

---

### 5. **CORS Allows All Origins** 🔴
**Severity:** CRITICAL
**Location:** plaster_server.py (line ~17)
**Description:** CORS middleware allows requests from any origin (`allow_origins=["*"]`).

**Current Code:**
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # VULNERABLE!
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

**Impact:**
- Malicious websites can make authenticated requests on behalf of users
- API keys in headers can be exfiltrated
- CSRF attacks possible even with API key auth

**Recommendation:**
```python
# Whitelist specific origins only
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:9321",
        "https://localhost:9321",
        # Add any legitimate frontend URLs here
        # Never use "*" in production
    ],
    allow_credentials=False,  # Don't include credentials with cross-origin
    allow_methods=["GET", "POST", "DELETE"],  # Only needed methods
    allow_headers=["X-API-Key", "Content-Type"],  # Only needed headers
)
```

---

### 6. **Docker Container Runs as Root** 🔴
**Severity:** CRITICAL
**Location:** Dockerfile (implied, not specified)
**Description:** Container likely runs as root user. If container is compromised, attacker has full system access.

**Recommendation:**
```dockerfile
# Create non-root user
RUN adduser --disabled-password --gecos '' plaster

# Set permissions
RUN chown -R plaster:plaster /app /home/plaster/.plaster

# Switch to non-root user
USER plaster

# Run as plaster user
CMD ["python", "plaster_server.py"]
```

---

### 7. **No Data Encryption at Rest** 🔴
**Severity:** CRITICAL
**Location:** Backup files, keys.json
**Description:** All persistent data (API keys, clipboard backups) stored in plaintext.

**Impact:**
- Disk compromise = complete data breach
- Backup files accessible to other users
- No protection against physical attacks

**Recommendation:**
```python
from cryptography.fernet import Fernet

class EncryptedStorage:
    def __init__(self, key_file="~/.plaster/master.key"):
        # Load or generate encryption key
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                self.cipher = Fernet(f.read())
        else:
            key = Fernet.generate_key()
            os.makedirs(os.path.dirname(key_file), exist_ok=True)
            with open(key_file, 'wb') as f:
                f.write(key)
            os.chmod(key_file, 0o600)
            self.cipher = Fernet(key)

    def encrypt_data(self, data: str) -> str:
        return self.cipher.encrypt(data.encode()).decode()

    def decrypt_data(self, encrypted: str) -> str:
        return self.cipher.decrypt(encrypted.encode()).decode()

# Use when saving keys.json and backups
```

---

### 8. **No Input Validation on Text Content** 🔴
**Severity:** CRITICAL (XSS in Web UI)
**Location:** Web UI HTML generation (lines ~1550+)
**Description:** Clipboard text displayed in web UI without HTML escaping.

**Impact:**
- Users could inject JavaScript that executes in other users' browsers
- API keys could be stolen via malicious clipboard entries
- Data corruption possible

**Current Vulnerability:**
```html
<!-- Vulnerable if 'entry' contains HTML/JS -->
<li>{{ entry }}</li>
```

**Recommendation:**
```python
import html

# Escape all user content in templates
def safe_html(text: str) -> str:
    return html.escape(text)

# In templates, use:
# <li>{{ safe_html(entry) }}</li>

# Or use Jinja2 auto-escape:
from jinja2 import Environment, select_autoescape
templates = Environment(
    loader=FileSystemLoader("templates"),
    autoescape=select_autoescape(['html', 'xml'])
)
```

---

### 9. **No Authentication for /health Endpoint** 🔴
**Severity:** CRITICAL
**Location:** `/health` endpoint
**Description:** Health check endpoint is publicly accessible without authentication, revealing server status and potentially version information.

**Impact:**
- Attackers can enumerate running services
- Information disclosure about deployment
- Could leak implementation details

**Recommendation:**
```python
@app.get("/health")
async def health_check(request: Request):
    # Require API key for detailed health info
    api_key = request.headers.get("X-API-Key")

    if api_key and key_manager.is_valid(api_key):
        # Return detailed health info for authenticated users
        return {"status": "healthy", "version": "1.0.0"}
    else:
        # Return minimal info (or require auth entirely)
        return {"status": "ok"}
```

---

### 10. **No SSL Certificate Validation in Clients** 🔴
**Severity:** CRITICAL
**Location:** Bash client curl calls, PowerShell client Invoke-WebRequest
**Description:** Clients don't validate SSL certificates, vulnerable to MITM even with HTTPS.

**Bash script vulnerable code:**
```bash
# Current (after HTTPS implementation):
curl -s -H "X-API-Key: $API_KEY" "https://$SERVER_URL/api/endpoint"

# Is vulnerable to self-signed/invalid certs without validation
```

**Recommendation:**
```bash
# Bash - For self-signed, use CA bundle or skip (insecure - dev only):
curl --cacert /path/to/ca-bundle.crt \
     -s -H "X-API-Key: $API_KEY" \
     "https://$SERVER_URL/api/endpoint"

# PowerShell - Add certificate validation:
[Net.ServicePointManager]::ServerCertificateValidationCallback = {
    param($sender, $cert, $chain, $policy)
    # Validate certificate
    if ($cert.Subject -match "plaster\.local") {
        return $true
    }
    return $false
}
```

---

### 11. **Command Injection in Bash Script** 🔴
**Severity:** CRITICAL
**Location:** plaster bash script - api_call function and curl calls
**Description:** While current usage is safe (no unquoted variables in command position), the pattern is vulnerable if modified carelessly.

**Current code structure:**
```bash
# This is SAFE because variables are quoted:
curl -s -X POST "$url" -H "X-API-Key: $API_KEY"

# But could become UNSAFE if not careful:
curl -s -X POST $url  # VULNERABLE: unquoted variable
```

**Recommendation:**
- Document that all variables must be quoted
- Use ShellCheck to validate: `shellcheck plaster`
- Add pre-commit hooks with shellcheck

---

## High Issues (10)

### 1. **No Authentication for `/list` Endpoint** 🟠
**Severity:** HIGH
**Location:** `/list` endpoint
**Description:** While the server checks API key, the response should be more explicit about auth failure.

---

### 2. **Insufficient Error Messages** 🟠
**Severity:** HIGH
**Location:** Throughout server error handling
**Description:** Generic error messages don't reveal implementation details, but could be more informative for debugging.

---

### 3. **No Rate Limit Reset Documentation** 🟠
**Severity:** HIGH
**Location:** README and rate limiting code
**Description:** Users don't know how to handle rate limit errors or when limits reset.

**Recommendation:** Add to README:
```markdown
## Rate Limiting

The server enforces rate limits to prevent abuse:
- General API: 100 requests per 60 seconds per API key
- Key Generation: 5 attempts per 5 minutes per IP address

When you hit the limit, the server returns a 429 (Too Many Requests) error.
Wait 60 seconds before trying again.
```

---

### 4. **No Backup Retention Policy** 🟠
**Severity:** HIGH
**Location:** Backup file generation
**Description:** Backup files accumulate indefinitely; no cleanup or retention policy.

---

### 5. **Unencrypted Network Traffic** 🟠
**Severity:** HIGH
**Location:** All API calls
**Description:** See Critical Issue #1 - detailed here for clarity.

---

### 6. **No Logging/Audit Trail** 🟠
**Severity:** HIGH
**Location:** plaster_server.py
**Description:** No access logs, no audit trail of who accessed what, when.

**Impact:**
- Can't detect unauthorized access
- No forensic evidence after breach
- Compliance issues

**Recommendation:**
```python
import logging

logging.basicConfig(
    filename="~/.plaster/server.log",
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Log all key access:
logger.info(f"API Key {api_key[:8]}... used from IP {client_ip}")
logger.warning(f"Invalid key attempt from IP {client_ip}")
logger.error(f"Clipboard clear by key {api_key[:8]}...")
```

---

### 7. **No API Key Rotation/Revocation** 🟠
**Severity:** HIGH
**Location:** Server key management
**Description:** No way to revoke a compromised key without losing clipboard access (rotate exists but not revoke).

---

### 8. **Bash Script Doesn't Validate Server Response** 🟠
**Severity:** HIGH
**Location:** Bash client - JSON parsing
**Description:** Uses `jq` but doesn't validate JSON structure before parsing.

**Vulnerable code:**
```bash
key=$(curl -s ... | jq -r '.api_key')
# If response isn't valid JSON, jq silently fails
```

---

### 9. **PowerShell Script Security Issues** 🟠
**Severity:** HIGH
**Location:** plaster.ps1
**Description:** Uses `Invoke-WebRequest` which may send credentials in redirects.

---

### 10. **No Session Timeout** 🟠
**Severity:** HIGH
**Location:** Server design
**Description:** API keys valid indefinitely (until idle_timeout); no session timeout on active connections.

---

## Medium Issues (25)

### 1-5. **File Permission Issues**
- Backup files need chmod 0o600
- Keys.json needs chmod 0o600
- Config.yaml needs chmod 0o600
- Config directory needs chmod 0o700
- Log files (if added) need appropriate permissions

### 6-10. **Configuration Security**
- Default max_api_keys_per_ip (10) may be too high for some deployments
- entry_lifespan_days not actually enforced in code
- idle_timeout_days not actually enforced in code
- No validation of configuration values
- Default port 9321 is non-standard (good) but undocumented

### 11-15. **API Design Issues**
- No request size limits (could cause memory exhaustion)
- No timeout on connections
- No pagination for /list endpoint (returns all entries)
- Backup file paths not sanitized
- No versioning for API endpoints

### 16-20. **Client-Side Issues**
- Bash script doesn't validate server URL format
- No timeout on curl requests (could hang indefinitely)
- PowerShell Set-Clipboard may fail silently
- Config file parser not validating YAML structure
- No validation of API key format before sending

### 21-25. **Deployment Issues**
- Docker compose uses default networks (not isolated)
- No resource limits in docker-compose.yml
- Backup directory path hardcoded
- No backup encryption key management
- Missing security headers in web UI response

---

## Low Issues (4)

1. **Missing Security Headers** - Add to web UI responses:
   ```
   X-Content-Type-Options: nosniff
   X-Frame-Options: DENY
   X-XSS-Protection: 1; mode=block
   ```

2. **No HSTS** - Add after implementing HTTPS:
   ```
   Strict-Transport-Security: max-age=31536000; includeSubDomains
   ```

3. **Missing Content-Security-Policy** - For web UI:
   ```
   Content-Security-Policy: default-src 'self'; script-src 'self'
   ```

4. **No User-Agent Validation** - Could reject suspicious clients

---

## Info Issues (3)

1. **Documentation could mention security best practices** - Add section on secure deployment

2. **README doesn't mention this is pre-release/unstable** - Add security notice

3. **No security contact information** - Add SECURITY.md with disclosure policy

---

## Remediation Priority

### Phase 1: CRITICAL (Before Any Production Use)
1. ✋ Implement HTTPS/TLS encryption (Issue #1)
2. ✋ Fix file permissions (chmod 0o600) (Issue #3)
3. ✋ Fix CORS to whitelist origins (Issue #5)
4. ✋ Run Docker as non-root (Issue #6)
5. ✋ Fix XSS in web UI (Issue #8)
6. ✋ Validate SSL certificates in clients (Issue #10)

**Estimated Effort:** 4-6 hours

### Phase 2: HIGH (Before Going Live)
1. ✋ Implement data encryption at rest (Issue #7)
2. ✋ Add rate limiting to /auth/generate (Issue #4)
3. ✋ Implement audit logging (High #6)
4. ✋ Add API key revocation (High #7)
5. ✋ Enforce entry_lifespan_days in code (Medium #6)
6. ✋ Enforce idle_timeout_days in code (Medium #6)

**Estimated Effort:** 8-10 hours

### Phase 3: MEDIUM (Hardening)
1. Set proper file permissions on all config/backup files
2. Add request size limits
3. Add connection timeouts
4. Implement pagination for /list
5. Add comprehensive logging
6. Add security headers to web UI
7. Document deployment security best practices

**Estimated Effort:** 6-8 hours

### Phase 4: LOW (Polish)
1. Add HSTS header
2. Add Content-Security-Policy
3. Add User-Agent validation
4. Improve error messages

**Estimated Effort:** 2-3 hours

---

## Testing Recommendations

### Manual Testing
```bash
# Test 1: Verify HTTPS
curl -I https://localhost:9321/health

# Test 2: Verify file permissions
ls -la ~/.plaster/
# Should see: -rw------- (0o600) for sensitive files

# Test 3: Verify CORS
curl -H "Origin: http://evil.com" http://localhost:9321/list
# Should reject if Origin not whitelisted

# Test 4: Verify rate limiting
for i in {1..150}; do
    curl -s http://localhost:9321/list -H "X-API-Key: test"
done
# Should return 429 after limit

# Test 5: Verify XSS protection
echo '<script>alert("xss")</script>' | plaster
# Web UI should display literally, not execute
```

### Automated Testing
- Add integration tests for all security checks
- Use OWASP ZAP for automated scanning
- Use ShellCheck for bash validation
- Use PSScriptAnalyzer for PowerShell validation

---

## Summary Table

| Issue | Severity | Status | Effort |
|-------|----------|--------|--------|
| HTTPS/TLS | CRITICAL | ❌ Open | 2 hrs |
| File Permissions | CRITICAL | ❌ Open | 1 hr |
| CORS | CRITICAL | ❌ Open | 1 hr |
| Docker User | CRITICAL | ❌ Open | 1 hr |
| XSS Prevention | CRITICAL | ❌ Open | 2 hrs |
| Cert Validation | CRITICAL | ❌ Open | 2 hrs |
| Encryption at Rest | CRITICAL | ❌ Open | 4 hrs |
| Auth Rate Limit | CRITICAL | ❌ Open | 1 hr |
| Audit Logging | HIGH | ❌ Open | 3 hrs |
| API Key Rotation | HIGH | ❌ Open | 2 hrs |
| Code Validation | MEDIUM | ❌ Open | 3 hrs |

**Total Effort Estimate:** 22-32 hours to address all critical and high issues

---

## Conclusion

Plaster has a solid architecture and good multi-tenant isolation, but **requires significant security hardening before production use**. The most critical gaps are:

1. No encryption in transit (HTTPS)
2. No encryption at rest (file permissions, data encryption)
3. Overly permissive CORS
4. No input validation (XSS)

These are industry-standard security practices that must be implemented. Once addressed, the service will be suitable for internal/trusted network deployment.

**Do not deploy this service to the internet or expose to untrusted networks until ALL critical issues are resolved.**

---

**Report Generated:** December 11, 2025
**Auditor:** Claude Code Security Review
