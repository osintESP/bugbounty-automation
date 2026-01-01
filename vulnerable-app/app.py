"""
Vulnerable Web Application - CVE Simulation Environment
WARNING: This application simulates real CVEs for testing purposes only.
DO NOT deploy this in production or expose it to the internet!

Simulates 50 common Apache HTTP Server and PHP vulnerabilities
Risk Score: 66.0/100 (Medium risk)
"""
from flask import Flask, request, render_template, redirect, make_response, jsonify
import sqlite3
import os
import subprocess
import json

app = Flask(__name__)
app.config['SECRET_KEY'] = 'super-secret-key-12345'

# Simulate Apache/PHP server headers
@app.after_request
def add_vulnerable_headers(response):
    """Add vulnerable server headers for testing"""
    response.headers['Server'] = 'Apache/2.4.59 (Unix) PHP/7.4.33 OpenSSL/1.1.1k'
    response.headers['X-Powered-By'] = 'PHP/7.4.33'
    response.headers['X-Backend-Server'] = 'internal-app-01.local'
    # Missing security headers (intentional)
    # No CSP, HSTS, X-Frame-Options, X-Content-Type-Options
    return response


@app.route('/')
def index():
    """CVE Dashboard"""
    cves = {
        'critical': [
            'CVE-2024-38475',
            'CVE-2024-38473',
            'CVE-2023-25690',
            'CVE-2024-27316',
            'CVE-2025-23048',
            'CVE-2024-38472',
            'CVE-2024-40898'
        ],
        'high': [],
        'medium': [
            'CVE-2024-24795',
            'CVE-2024-42516',
            'CVE-2023-38709'
        ],
        'low': [
            'CVE-2025-65082', 'CVE-2024-43394', 'CVE-2023-45802',
            'CVE-2023-27522', 'CVE-2025-49812', 'CVE-2025-49630',
            'CVE-2024-38477', 'CVE-2024-38476', 'CVE-2024-38474',
            'CVE-2025-58098', 'CVE-2025-53020', 'CVE-2022-36760',
            'CVE-2025-66200', 'CVE-2025-55753', 'CVE-2024-47252',
            'CVE-2024-43204', 'CVE-2022-37436', 'CVE-2025-59775',
            'CVE-2024-39573', 'CVE-2023-31122', 'CVE-2013-4365',
            'CVE-2006-20001', 'CVE-2022-4900', 'CVE-2024-3566',
            'CVE-2007-3205', 'CVE-2024-25117', 'CVE-2013-2220',
            'CVE-2024-5458', 'CVE-2013-0942', 'CVE-2012-4360',
            'CVE-2012-3526', 'CVE-2013-2765', 'CVE-2012-4001',
            'CVE-2007-4723', 'CVE-2013-0941', 'CVE-2011-1176',
            'CVE-2009-0796', 'CVE-2011-2688', 'CVE-2009-2299'
        ]
    }
    
    total_cves = sum(len(v) for v in cves.values())
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CVE Simulation Environment</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }}
            h1 {{ color: #d32f2f; }}
            .warning {{ background: #ff6b6b; color: white; padding: 15px; border-radius: 5px; margin: 20px 0; }}
            .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin: 20px 0; }}
            .stat-box {{ background: #f8f9fa; padding: 20px; border-radius: 5px; text-align: center; }}
            .critical {{ border-left: 4px solid #d32f2f; }}
            .medium {{ border-left: 4px solid #ff9800; }}
            .low {{ border-left: 4px solid #ffc107; }}
            .endpoints {{ margin: 20px 0; }}
            .endpoints a {{ display: block; padding: 10px; margin: 5px 0; background: #e3f2fd; text-decoration: none; color: #1976d2; border-radius: 3px; }}
            .endpoints a:hover {{ background: #bbdefb; }}
            code {{ background: #f5f5f5; padding: 2px 6px; border-radius: 3px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔴 CVE Simulation Environment</h1>
            <p class="warning">⚠️ Simulating {total_cves} CVEs for security testing (Risk Score: 66.0/100)</p>
            
            <div class="stats">
                <div class="stat-box critical">
                    <h2>{len(cves['critical'])}</h2>
                    <p>Critical CVEs</p>
                </div>
                <div class="stat-box medium">
                    <h2>{len(cves['medium'])}</h2>
                    <p>Medium CVEs</p>
                </div>
                <div class="stat-box low">
                    <h2>{len(cves['low'])}</h2>
                    <p>Low CVEs</p>
                </div>
                <div class="stat-box">
                    <h2>{total_cves}</h2>
                    <p>Total CVEs</p>
                </div>
            </div>
            
            <h2>🎯 Available CVE Endpoints:</h2>
            <div class="endpoints">
                <a href="/cve/list">📋 List All CVEs (JSON)</a>
                <a href="/cve/apache/response-split">💥 CVE-2024-24795 - HTTP Response Splitting</a>
                <a href="/cve/apache/rewrite-bypass">🔓 CVE-2024-38475 - mod_rewrite Bypass</a>
                <a href="/cve/apache/encoding-bypass">🎭 CVE-2024-38473 - Encoding Bypass</a>
                <a href="/cve/apache/request-smuggling">🚚 CVE-2023-25690 - Request Smuggling</a>
                <a href="/cve/apache/ssrf-ntlm">🔑 CVE-2024-38472 - SSRF/NTLM Leak</a>
                <a href="/cve/apache/http2-dos">💣 CVE-2024-27316 - HTTP/2 DoS</a>
                <a href="/cve/php/parse-str">⚠️ CVE-2007-3205 - Variable Overwrite</a>
                <a href="/cve/php/command-injection">💻 CVE-2024-3566 - Command Injection</a>
                <a href="/cve/info/server">📊 Server Information Disclosure</a>
                <a href="/cve/info/config">⚙️ Configuration Exposure</a>
            </div>
            
            <h2>🔍 Server Information:</h2>
            <p><strong>Server:</strong> Apache/2.4.59 (Unix) PHP/7.4.33 OpenSSL/1.1.1k</p>
            <p><strong>Risk Level:</strong> Medium (66.0/100)</p>
            
            <h2>📖 Testing Commands:</h2>
            <pre><code># List all CVEs
curl http://localhost:5000/cve/list | jq

# Test specific CVE
curl http://localhost:5000/cve/apache/response-split?redirect=test

# Get server info
curl http://localhost:5000/cve/info/server | jq</code></pre>
        </div>
    </body>
    </html>
    """


@app.route('/cve/list')
def cve_list():
    """List all CVEs with details"""
    cves_data = {
        'total_cves': 50,
        'risk_score': 66.0,
        'server': 'Apache/2.4.59 (Unix) PHP/7.4.33',
        'cves': {
            'apache_http_server': [
                {'id': 'CVE-2024-38475', 'severity': 'medium', 'description': 'mod_rewrite improper escaping - code execution'},
                {'id': 'CVE-2024-38473', 'severity': 'medium', 'description': 'mod_proxy encoding bypass - auth bypass'},
                {'id': 'CVE-2023-25690', 'severity': 'medium', 'description': 'HTTP Request Smuggling'},
                {'id': 'CVE-2024-27316', 'severity': 'medium', 'description': 'HTTP/2 memory exhaustion'},
                {'id': 'CVE-2024-38472', 'severity': 'medium', 'description': 'SSRF with NTLM hash leak'},
                {'id': 'CVE-2024-24795', 'severity': 'low', 'description': 'HTTP Response Splitting'},
                {'id': 'CVE-2024-42516', 'severity': 'low', 'description': 'HTTP response splitting (incomplete fix)'},
                {'id': 'CVE-2025-65082', 'severity': 'low', 'description': 'Environment variable injection'},
                {'id': 'CVE-2024-43394', 'severity': 'low', 'description': 'SSRF via mod_rewrite'},
                {'id': 'CVE-2023-45802', 'severity': 'low', 'description': 'HTTP/2 memory leak'},
                {'id': 'CVE-2023-27522', 'severity': 'low', 'description': 'Response smuggling via mod_proxy_uwsgi'},
                {'id': 'CVE-2025-49812', 'severity': 'low', 'description': 'TLS upgrade hijacking'},
                {'id': 'CVE-2025-49630', 'severity': 'low', 'description': 'mod_proxy_http2 DoS'},
                {'id': 'CVE-2024-38477', 'severity': 'low', 'description': 'mod_proxy NULL pointer dereference'},
                {'id': 'CVE-2024-38476', 'severity': 'low', 'description': 'Info disclosure via backend headers'},
                {'id': 'CVE-2024-38474', 'severity': 'low', 'description': 'mod_rewrite substitution encoding'},
                {'id': 'CVE-2025-58098', 'severity': 'low', 'description': 'SSI command injection'},
                {'id': 'CVE-2025-53020', 'severity': 'low', 'description': 'Memory leak'},
                {'id': 'CVE-2022-36760', 'severity': 'low', 'description': 'Request smuggling mod_proxy_ajp'},
                {'id': 'CVE-2025-66200', 'severity': 'low', 'description': 'mod_userdir+suexec bypass'},
                {'id': 'CVE-2025-55753', 'severity': 'low', 'description': 'ACME certificate renewal overflow'},
                {'id': 'CVE-2025-23048', 'severity': 'medium', 'description': 'TLS 1.3 session resumption bypass'},
                {'id': 'CVE-2024-47252', 'severity': 'low', 'description': 'mod_ssl insufficient escaping'},
                {'id': 'CVE-2024-43204', 'severity': 'low', 'description': 'SSRF via mod_headers'},
                {'id': 'CVE-2022-37436', 'severity': 'low', 'description': 'Response header truncation'},
                {'id': 'CVE-2025-59775', 'severity': 'low', 'description': 'SSRF with AllowEncodedSlashes'},
                {'id': 'CVE-2024-39573', 'severity': 'low', 'description': 'SSRF in mod_rewrite'},
                {'id': 'CVE-2023-31122', 'severity': 'low', 'description': 'mod_macro out-of-bounds read'},
                {'id': 'CVE-2013-4365', 'severity': 'low', 'description': 'mod_fcgid heap overflow'},
                {'id': 'CVE-2006-20001', 'severity': 'low', 'description': 'Memory read via If header'},
                {'id': 'CVE-2024-40898', 'severity': 'medium', 'description': 'SSRF on Windows with mod_rewrite'},
                {'id': 'CVE-2023-38709', 'severity': 'medium', 'description': 'HTTP response splitting'},
                {'id': 'CVE-2012-4360', 'severity': 'low', 'description': 'mod_pagespeed XSS'},
                {'id': 'CVE-2012-3526', 'severity': 'low', 'description': 'mod_rpaf DoS'},
                {'id': 'CVE-2013-2765', 'severity': 'low', 'description': 'ModSecurity DoS'},
                {'id': 'CVE-2012-4001', 'severity': 'low', 'description': 'mod_pagespeed SSRF'},
                {'id': 'CVE-2007-4723', 'severity': 'low', 'description': 'Directory traversal'},
                {'id': 'CVE-2013-0941', 'severity': 'low', 'description': 'RSA Auth API weak encryption'},
                {'id': 'CVE-2011-1176', 'severity': 'low', 'description': 'mpm-itk privilege escalation'},
                {'id': 'CVE-2009-0796', 'severity': 'low', 'description': 'mod_perl XSS'},
                {'id': 'CVE-2011-2688', 'severity': 'low', 'description': 'mod_authnz_external SQL injection'},
                {'id': 'CVE-2009-2299', 'severity': 'low', 'description': 'Hyperguard WAF DoS'}
            ],
            'php': [
                {'id': 'CVE-2022-4900', 'severity': 'low', 'description': 'Heap buffer overflow via PHP_CLI_SERVER_WORKERS'},
                {'id': 'CVE-2024-3566', 'severity': 'low', 'description': 'Command injection on Windows'},
                {'id': 'CVE-2007-3205', 'severity': 'low', 'description': 'parse_str variable overwrite'},
                {'id': 'CVE-2024-25117', 'severity': 'low', 'description': 'php-svg-lib PHAR RCE'},
                {'id': 'CVE-2013-2220', 'severity': 'low', 'description': 'Radius extension buffer overflow'},
                {'id': 'CVE-2024-5458', 'severity': 'low', 'description': 'filter_var URL validation bypass'},
                {'id': 'CVE-2013-0942', 'severity': 'low', 'description': 'RSA Authentication Agent XSS'}
            ]
        }
    }
    return jsonify(cves_data)


# ============================================================================
# APACHE HTTP SERVER CVEs
# ============================================================================

@app.route('/cve/apache/response-split')
def cve_apache_response_split():
    """CVE-2024-24795, CVE-2024-42516 - HTTP Response Splitting"""
    user_input = request.args.get('redirect', '/')
    response = make_response(f"Redirecting to {user_input}")
    response.headers['Location'] = user_input  # Vulnerable to CRLF injection
    return response


@app.route('/cve/apache/rewrite-bypass')
def cve_apache_rewrite_bypass():
    """CVE-2024-38475 - mod_rewrite Improper Escaping"""
    path = request.args.get('path', 'index.html')
    try:
        file_path = f"/app/{path}"  # Vulnerable to path traversal
        with open(file_path, 'r') as f:
            content = f.read()
        return f"<h2>File: {path}</h2><pre>{content[:1000]}</pre>"
    except Exception as e:
        return f"<h2>CVE-2024-38475</h2><p>Error: {str(e)}</p><p>Try: ?path=../../../etc/passwd</p>"


@app.route('/cve/apache/encoding-bypass')
def cve_apache_encoding_bypass():
    """CVE-2024-38473 - mod_proxy Encoding Bypass"""
    resource = request.args.get('resource', 'public')
    auth = request.args.get('auth', 'false')
    
    if 'admin' in resource.lower() and auth != 'true':
        return "<h2>Access Denied</h2><p>Admin requires auth</p>"
    
    return f"""
    <h2>CVE-2024-38473 - Encoding Bypass</h2>
    <p>Resource: {resource}</p>
    <p>Auth: {auth}</p>
    <p>Try: ?resource=admin%2f..%2fsecret&auth=false</p>
    """


@app.route('/cve/apache/request-smuggling')
def cve_apache_request_smuggling():
    """CVE-2023-25690 - HTTP Request Smuggling"""
    cl = request.headers.get('Content-Length', '0')
    te = request.headers.get('Transfer-Encoding', 'none')
    
    return f"""
    <h2>CVE-2023-25690 - Request Smuggling</h2>
    <p>Content-Length: {cl}</p>
    <p>Transfer-Encoding: {te}</p>
    <p>Vulnerable to CL.TE desync attacks</p>
    """


@app.route('/cve/apache/ssrf-ntlm')
def cve_apache_ssrf_ntlm():
    """CVE-2024-38472, CVE-2024-43394 - SSRF with NTLM Hash Leak"""
    target = request.args.get('target', 'http://localhost')
    
    try:
        import urllib.request
        response = urllib.request.urlopen(target, timeout=5)
        content = response.read().decode('utf-8')[:500]
        return f"<h2>CVE-2024-38472 - SSRF</h2><p>Target: {target}</p><pre>{content}</pre>"
    except Exception as e:
        return f"<h2>CVE-2024-38472</h2><p>Error: {str(e)}</p><p>Try: ?target=http://localhost:8000/api/stats</p>"


@app.route('/cve/apache/http2-dos')
def cve_apache_http2_dos():
    """CVE-2024-27316 - HTTP/2 Memory Exhaustion"""
    return """
    <h2>CVE-2024-27316 - HTTP/2 DoS</h2>
    <p>Vulnerable to memory exhaustion via excessive HTTP/2 headers</p>
    <p>nghttp2 buffers incoming headers without limit</p>
    """


# ============================================================================
# PHP CVEs
# ============================================================================

@app.route('/cve/php/parse-str')
def cve_php_parse_str():
    """CVE-2007-3205 - PHP parse_str Variable Overwrite"""
    query = request.args.get('vars', '')
    admin = False
    authenticated = False
    
    if query:
        vars_dict = {}
        for pair in query.split('&'):
            if '=' in pair:
                key, value = pair.split('=', 1)
                vars_dict[key] = value
        
        if 'admin' in vars_dict:
            admin = vars_dict['admin'] == 'true'
        if 'authenticated' in vars_dict:
            authenticated = vars_dict['authenticated'] == 'true'
    
    return f"""
    <h2>CVE-2007-3205 - Variable Overwrite</h2>
    <p>Admin: {admin}</p>
    <p>Authenticated: {authenticated}</p>
    <p>Exploit: ?vars=admin=true&authenticated=true</p>
    """


@app.route('/cve/php/command-injection')
def cve_php_command_injection():
    """CVE-2024-3566 - Command Injection on Windows"""
    cmd = request.args.get('cmd', 'echo test')
    
    try:
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=5)
        output = result.decode('utf-8')
        return f"<h2>CVE-2024-3566 - Command Injection</h2><pre>{output}</pre>"
    except Exception as e:
        return f"<h2>CVE-2024-3566</h2><p>Error: {str(e)}</p><p>Try: ?cmd=ls -la</p>"


# ============================================================================
# INFORMATION DISCLOSURE
# ============================================================================

@app.route('/cve/info/server')
def cve_info_server():
    """Server Information Disclosure"""
    info = {
        'server': 'Apache/2.4.59 (Unix) PHP/7.4.33 OpenSSL/1.1.1k',
        'php_version': '7.4.33',
        'openssl_version': 'OpenSSL/1.1.1k',
        'modules': ['mod_ssl/2.4.59', 'mod_rewrite', 'mod_proxy', 'mod_proxy_http', 'mod_headers', 'mod_fcgid/2.3.9'],
        'document_root': '/var/www/html',
        'server_admin': 'admin@vulnerable.local',
        'internal_ip': '172.18.0.5',
        'cves_count': 50,
        'risk_score': 66.0
    }
    
    response = jsonify(info)
    response.headers['Server'] = 'Apache/2.4.59 (Unix) PHP/7.4.33 OpenSSL/1.1.1k'
    response.headers['X-Powered-By'] = 'PHP/7.4.33'
    return response


@app.route('/cve/info/config')
def cve_info_config():
    """Configuration Exposure"""
    config = {
        'database': 'mysql://root:password@localhost:3306/app_db',
        'redis': 'redis://localhost:6379',
        'api_keys': {
            'stripe': 'sk_live_51234567890abcdef',
            'aws_access': 'AKIAIOSFODNN7EXAMPLE',
            'aws_secret': 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'
        },
        'debug': True,
        'environment': 'production'
    }
    return jsonify(config)


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
