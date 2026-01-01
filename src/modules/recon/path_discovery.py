#!/usr/bin/env python3
"""
Path discovery module using intelligent fuzzing
Discovers endpoints, directories, and files
"""
import requests
import concurrent.futures
from typing import List, Dict, Set
from urllib.parse import urljoin
from pathlib import Path
from utils.logger import logger


class PathDiscovery:
    """Intelligent path and endpoint discovery"""
    
    # Common paths to check
    COMMON_PATHS = [
        # Admin/Management
        '/admin', '/administrator', '/admin.php', '/admin/', '/login',
        '/dashboard', '/panel', '/cpanel', '/wp-admin', '/phpmyadmin',
        
        # API endpoints
        '/api', '/api/v1', '/api/v2', '/api/config', '/api/users',
        '/api/admin', '/graphql', '/rest', '/v1', '/v2',
        
        # Configuration files
        '/.env', '/.env.local', '/.env.production', '/config.php',
        '/config.json', '/settings.php', '/configuration.php',
        '/web.config', '/app.config', '/.git/config',
        
        # Common files
        '/robots.txt', '/sitemap.xml', '/.htaccess', '/crossdomain.xml',
        '/phpinfo.php', '/info.php', '/test.php', '/debug',
        
        # Upload/Media
        '/upload', '/uploads', '/files', '/media', '/images',
        '/assets', '/static', '/public', '/storage',
        
        # Backup files
        '/backup', '/backups', '/.backup', '/db.sql', '/database.sql',
        '/backup.zip', '/backup.tar.gz', '/site.zip',
        
        # Source code
        '/.git', '/.svn', '/.gitignore', '/composer.json',
        '/package.json', '/requirements.txt', '/Gemfile',
        
        # Documentation
        '/docs', '/documentation', '/api-docs', '/swagger',
        '/readme.md', '/README.md', '/CHANGELOG.md',
    ]
    
    # Technology-specific paths
    TECH_PATHS = {
        'Apache': [
            '/cgi-bin/', '/icons/', '/manual/', '/.htaccess',
            '/server-status', '/server-info',
        ],
        'PHP': [
            '/index.php', '/admin.php', '/config.php', '/phpinfo.php',
            '/info.php', '/test.php', '/upload.php',
        ],
        'WordPress': [
            '/wp-admin/', '/wp-content/', '/wp-includes/',
            '/wp-login.php', '/xmlrpc.php', '/wp-config.php',
        ],
        'Flask': [
            '/static/', '/admin/', '/api/', '/debug',
        ],
        'Django': [
            '/admin/', '/static/', '/media/', '/api/',
        ],
        'Laravel': [
            '/public/', '/storage/', '/api/', '/admin/',
        ],
        'Node.js': [
            '/node_modules/', '/package.json', '/server.js',
        ],
    }
    
    def __init__(self, target: str, wordlist: str = None, threads: int = 10, timeout: int = 10):
        self.target = target.rstrip('/')
        self.wordlist = wordlist
        self.threads = threads
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'BugBountyTool/1.0 (Security Research)'
        })
        self.discovered = []
        
    def run(self, technologies: List[str] = None) -> List[Dict]:
        """Execute path discovery"""
        logger.info(f"Starting path discovery for {self.target}")
        
        paths_to_check = set(self.COMMON_PATHS)
        
        # Add technology-specific paths
        if technologies:
            for tech in technologies:
                if tech in self.TECH_PATHS:
                    paths_to_check.update(self.TECH_PATHS[tech])
                    logger.info(f"Added {len(self.TECH_PATHS[tech])} paths for {tech}")
        
        # Add custom wordlist if provided
        if self.wordlist and Path(self.wordlist).exists():
            with open(self.wordlist, 'r') as f:
                custom_paths = [line.strip() for line in f if line.strip()]
                paths_to_check.update(custom_paths)
                logger.info(f"Added {len(custom_paths)} paths from wordlist")
        
        # Perform discovery with threading
        logger.info(f"Checking {len(paths_to_check)} paths with {self.threads} threads")
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self._check_path, path): path for path in paths_to_check}
            
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    self.discovered.append(result)
        
        # Sort by status code and size
        self.discovered.sort(key=lambda x: (x['status'], -x['size']))
        
        logger.info(f"Path discovery complete: {len(self.discovered)} paths found")
        return self.discovered
    
    def _check_path(self, path: str) -> Dict:
        """Check if a path exists and gather information"""
        url = urljoin(self.target, path)
        
        try:
            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=False,
                verify=False  # For testing purposes
            )
            
            # Filter interesting responses
            if self._is_interesting(response):
                result = {
                    'url': url,
                    'path': path,
                    'status': response.status_code,
                    'size': len(response.content),
                    'content_type': response.headers.get('Content-Type', 'unknown'),
                    'redirect': response.headers.get('Location'),
                    'interesting': True
                }
                
                # Add additional context
                result['reason'] = self._get_interesting_reason(response, path)
                
                logger.info(f"Found: {path} [{response.status_code}] ({len(response.content)} bytes)")
                return result
                
        except requests.exceptions.Timeout:
            logger.debug(f"Timeout: {path}")
        except requests.exceptions.RequestException as e:
            logger.debug(f"Error checking {path}: {e}")
        
        return None
    
    def _is_interesting(self, response: requests.Response) -> bool:
        """Determine if a response is interesting"""
        
        # Status codes of interest
        interesting_codes = [200, 201, 204, 301, 302, 307, 308, 401, 403, 500]
        
        if response.status_code not in interesting_codes:
            return False
        
        # Filter out empty responses
        if response.status_code == 200 and len(response.content) == 0:
            return False
        
        # Filter out default error pages (common sizes)
        if response.status_code in [403, 404] and len(response.content) in [0, 162, 169, 345]:
            return False
        
        return True
    
    def _get_interesting_reason(self, response: requests.Response, path: str) -> str:
        """Get reason why this path is interesting"""
        
        reasons = []
        
        if response.status_code == 200:
            reasons.append("Accessible")
        elif response.status_code in [301, 302, 307, 308]:
            reasons.append(f"Redirects to {response.headers.get('Location', 'unknown')}")
        elif response.status_code == 401:
            reasons.append("Requires authentication")
        elif response.status_code == 403:
            reasons.append("Forbidden (exists but not accessible)")
        elif response.status_code == 500:
            reasons.append("Server error (potential vulnerability)")
        
        # Check for sensitive files
        sensitive_extensions = ['.env', '.git', '.sql', '.zip', '.tar.gz', '.backup']
        if any(path.endswith(ext) for ext in sensitive_extensions):
            reasons.append("Sensitive file")
        
        # Check for configuration endpoints
        if 'config' in path.lower() or 'settings' in path.lower():
            reasons.append("Configuration endpoint")
        
        # Check for admin panels
        if 'admin' in path.lower() or 'panel' in path.lower():
            reasons.append("Admin panel")
        
        # Check for API endpoints
        if '/api' in path.lower():
            reasons.append("API endpoint")
        
        return ', '.join(reasons) if reasons else "Unknown"
    
    def get_by_status(self, status_code: int) -> List[Dict]:
        """Get discovered paths by status code"""
        return [p for p in self.discovered if p['status'] == status_code]
    
    def get_accessible_paths(self) -> List[Dict]:
        """Get all accessible paths (200, 201, 204)"""
        return [p for p in self.discovered if p['status'] in [200, 201, 204]]
    
    def get_sensitive_files(self) -> List[Dict]:
        """Get potentially sensitive files"""
        sensitive_keywords = ['.env', '.git', '.sql', 'backup', 'config', 'database']
        return [
            p for p in self.discovered
            if any(keyword in p['path'].lower() for keyword in sensitive_keywords)
        ]
    
    def export_results(self) -> Dict:
        """Export discovery results in structured format"""
        return {
            'target': self.target,
            'total_checked': len(self.COMMON_PATHS),
            'total_found': len(self.discovered),
            'accessible': len(self.get_accessible_paths()),
            'sensitive': len(self.get_sensitive_files()),
            'paths': self.discovered
        }
