# Vulnerable Web Application - CVE Simulation Environment

⚠️ **WARNING**: This application simulates **50 real CVEs** for security testing purposes only!

**DO NOT** deploy this in production or expose it to the internet!

## Overview

This vulnerable application simulates common Apache HTTP Server and PHP vulnerabilities:

- **Total CVEs**: 50
- **Risk Score**: 66.0/100 (Medium risk)
- **Server**: Apache/2.4.59 (Unix) PHP/7.4.33 OpenSSL/1.1.1k

## CVE Breakdown

### Critical Severity (7 CVEs)
- CVE-2024-38475 - mod_rewrite improper escaping
- CVE-2024-38473 - mod_proxy encoding bypass
- CVE-2023-25690 - HTTP Request Smuggling
- CVE-2024-27316 - HTTP/2 memory exhaustion
- CVE-2025-23048 - TLS 1.3 session resumption bypass
- CVE-2024-38472 - SSRF with NTLM hash leak
- CVE-2024-40898 - SSRF on Windows with mod_rewrite

### Medium Severity (3 CVEs)
- CVE-2024-24795 - HTTP Response Splitting
- CVE-2024-42516 - HTTP response splitting (incomplete fix)
- CVE-2023-38709 - HTTP response splitting

### Low Severity (40 CVEs)
Apache HTTP Server, PHP, and module vulnerabilities including:
- Environment variable injection
- Memory leaks
- DoS vulnerabilities
- Information disclosure
- Command injection
- Path traversal
- XSS in various modules
- SQL injection in mod_authnz_external
- And many more...

## Running the Application

The vulnerable app is automatically started with docker-compose:

```bash
# Start all services
docker-compose up -d

# Access the CVE dashboard
http://localhost:5000
```

## Available Endpoints

### Main Dashboard
- **/** - CVE dashboard with statistics and links

### CVE List
- **/cve/list** - JSON list of all 50 CVEs with details

### Apache HTTP Server CVEs
- **/cve/apache/response-split** - CVE-2024-24795 (HTTP Response Splitting)
- **/cve/apache/rewrite-bypass** - CVE-2024-38475 (mod_rewrite bypass)
- **/cve/apache/encoding-bypass** - CVE-2024-38473 (Encoding bypass)
- **/cve/apache/request-smuggling** - CVE-2023-25690 (Request smuggling)
- **/cve/apache/ssrf-ntlm** - CVE-2024-38472 (SSRF/NTLM leak)
- **/cve/apache/http2-dos** - CVE-2024-27316 (HTTP/2 DoS)

### PHP CVEs
- **/cve/php/parse-str** - CVE-2007-3205 (Variable overwrite)
- **/cve/php/command-injection** - CVE-2024-3566 (Command injection)

### Information Disclosure
- **/cve/info/server** - Server version and configuration
- **/cve/info/config** - Exposed configuration with secrets

## Testing Examples

### List All CVEs
```bash
curl http://localhost:5000/cve/list | jq
```

### Test HTTP Response Splitting
```bash
curl "http://localhost:5000/cve/apache/response-split?redirect=test%0d%0aX-Injected:header"
```

### Test Path Traversal (mod_rewrite bypass)
```bash
curl "http://localhost:5000/cve/apache/rewrite-bypass?path=../../../etc/passwd"
```

### Test SSRF
```bash
curl "http://localhost:5000/cve/apache/ssrf-ntlm?target=http://localhost:8000/api/stats"
```

### Get Server Information
```bash
curl http://localhost:5000/cve/info/server | jq
```

### Test Command Injection
```bash
curl "http://localhost:5000/cve/php/command-injection?cmd=ls%20-la"
```

## Testing with Bug Bounty Tool

### Run Vulnerability Scan
```bash
docker-compose exec app python src/main.py scan --target http://vulnerable-app:5000
```

### Full Pipeline
```bash
docker-compose exec app python src/main.py full --target vulnerable-app:5000
```

## Expected Findings

The bug bounty tool should detect:

✓ Missing security headers (CSP, HSTS, X-Frame-Options, etc.)  
✓ Server version disclosure (Apache/2.4.59, PHP/7.4.33)  
✓ Information disclosure endpoints  
✓ Exposed configuration  
✓ Multiple CVE patterns  

## CVE Categories

### Apache HTTP Server (43 CVEs)
- mod_rewrite vulnerabilities
- mod_proxy issues
- HTTP/2 protocol bugs
- Request smuggling
- Response splitting
- SSRF vulnerabilities
- Memory leaks and DoS
- Module-specific vulnerabilities

### PHP (7 CVEs)
- Command injection
- Variable overwriting
- Buffer overflows
- URL validation bypass
- PHAR RCE

## File Structure

```
vulnerable-app/
├── app.py                 # Main Flask application (CVE simulations)
├── Dockerfile             # Docker configuration
├── requirements.txt       # Python dependencies
└── README.md              # This file
```

## Security Notice

This application is intentionally vulnerable and should **ONLY** be used in isolated testing environments:

- ✗ Never expose to the internet
- ✗ Never use with real data
- ✗ Never deploy in production
- ✓ Use only in Docker containers
- ✓ Use only for security testing
- ✓ Use only in isolated networks

## License

This vulnerable application is part of the Bug Bounty Automation Tool project and is provided for educational and testing purposes only.
