#!/usr/bin/env python3
"""
Fingerprinting module for technology detection
Detects server software, frameworks, languages, and versions
"""
import re
import requests
from typing import Dict, List, Optional
from urllib.parse import urljoin
from utils.logger import logger


class Fingerprinter:
    """Technology fingerprinting and version detection"""
    
    def __init__(self, target: str, timeout: int = 10):
        self.target = target.rstrip('/')
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'BugBountyTool/1.0 (Security Research)'
        })
        
    def run(self) -> Dict:
        """Execute complete fingerprinting"""
        logger.info(f"Starting fingerprinting for {self.target}")
        
        result = {
            'target': self.target,
            'server': None,
            'language': None,
            'framework': None,
            'cms': None,
            'technologies': [],
            'versions': {},
            'confidence': 0.0,
            'headers': {},
            'signatures': []
        }
        
        try:
            # Get initial response
            response = self.session.get(self.target, timeout=self.timeout, allow_redirects=True)
            result['headers'] = dict(response.headers)
            
            # Analyze headers
            self._analyze_headers(response.headers, result)
            
            # Analyze response body
            self._analyze_body(response.text, result)
            
            # Detect specific technologies
            self._detect_technologies(response, result)
            
            # Calculate confidence score
            result['confidence'] = self._calculate_confidence(result)
            
            logger.info(f"Fingerprinting complete: {result['server']}, {result['framework']}")
            
        except Exception as e:
            logger.error(f"Fingerprinting error: {e}")
            result['error'] = str(e)
            
        return result
    
    def _analyze_headers(self, headers: Dict, result: Dict):
        """Extract information from HTTP headers"""
        
        # Server header
        if 'Server' in headers:
            server = headers['Server']
            result['server'] = server
            
            # Extract version
            version_match = re.search(r'/([\d.]+)', server)
            if version_match:
                result['versions']['server'] = version_match.group(1)
        
        # X-Powered-By header
        if 'X-Powered-By' in headers:
            powered_by = headers['X-Powered-By']
            result['technologies'].append(powered_by)
            
            # Detect language/framework
            if 'PHP' in powered_by:
                result['language'] = 'PHP'
                version_match = re.search(r'PHP/([\d.]+)', powered_by)
                if version_match:
                    result['versions']['php'] = version_match.group(1)
            elif 'ASP.NET' in powered_by:
                result['framework'] = 'ASP.NET'
        
        # X-AspNet-Version
        if 'X-AspNet-Version' in headers:
            result['framework'] = 'ASP.NET'
            result['versions']['aspnet'] = headers['X-AspNet-Version']
        
        # X-Framework headers
        framework_headers = ['X-Powered-By', 'X-Generator', 'X-Framework']
        for header in framework_headers:
            if header in headers:
                value = headers[header]
                if 'Flask' in value:
                    result['framework'] = 'Flask'
                elif 'Django' in value:
                    result['framework'] = 'Django'
                elif 'Express' in value:
                    result['framework'] = 'Express'
                elif 'Laravel' in value:
                    result['framework'] = 'Laravel'
    
    def _analyze_body(self, body: str, result: Dict):
        """Analyze response body for technology signatures"""
        
        # Meta generator tags
        meta_generator = re.search(r'<meta name="generator" content="([^"]+)"', body, re.I)
        if meta_generator:
            generator = meta_generator.group(1)
            result['technologies'].append(generator)
            
            # Detect CMS
            if 'WordPress' in generator:
                result['cms'] = 'WordPress'
                version_match = re.search(r'WordPress ([\d.]+)', generator)
                if version_match:
                    result['versions']['wordpress'] = version_match.group(1)
            elif 'Joomla' in generator:
                result['cms'] = 'Joomla'
            elif 'Drupal' in generator:
                result['cms'] = 'Drupal'
        
        # Framework signatures in HTML comments
        if '<!-- Flask' in body or 'Werkzeug' in body:
            result['framework'] = 'Flask'
            result['language'] = 'Python'
        
        if '<!-- Django' in body or 'csrfmiddlewaretoken' in body:
            result['framework'] = 'Django'
            result['language'] = 'Python'
        
        # JavaScript framework detection
        if 'react' in body.lower() or '_react' in body:
            result['technologies'].append('React')
        if 'vue' in body.lower() or 'Vue.js' in body:
            result['technologies'].append('Vue.js')
        if 'angular' in body.lower() or 'ng-app' in body:
            result['technologies'].append('Angular')
        
        # Look for version comments
        version_comments = re.findall(r'<!-- Version: ([\d.]+) -->', body)
        if version_comments:
            result['signatures'].append(f"Version comment: {version_comments[0]}")
    
    def _detect_technologies(self, response: requests.Response, result: Dict):
        """Detect specific technologies through targeted requests"""
        
        # Check for common framework files
        checks = [
            # WordPress
            ('/wp-admin/', 'WordPress'),
            ('/wp-content/', 'WordPress'),
            ('/wp-includes/version.php', 'WordPress'),
            
            # Joomla
            ('/administrator/', 'Joomla'),
            
            # Drupal
            ('/misc/drupal.js', 'Drupal'),
            
            # Laravel
            ('/vendor/laravel/', 'Laravel'),
            
            # Flask/Python
            ('/static/', 'Flask/Python'),
            
            # PHP
            ('/index.php', 'PHP'),
            
            # Node.js/Express
            ('/node_modules/', 'Node.js'),
        ]
        
        for path, tech in checks:
            try:
                url = urljoin(self.target, path)
                resp = self.session.head(url, timeout=5, allow_redirects=False)
                
                if resp.status_code in [200, 301, 302, 403]:
                    if tech not in result['technologies']:
                        result['technologies'].append(tech)
                        result['signatures'].append(f"Found {path}")
                    
                    # Set CMS/Framework if not already set
                    if tech in ['WordPress', 'Joomla', 'Drupal'] and not result['cms']:
                        result['cms'] = tech
                    elif tech in ['Flask/Python', 'Laravel'] and not result['framework']:
                        result['framework'] = tech.split('/')[0]
                        if '/' in tech:
                            result['language'] = tech.split('/')[1]
                    elif tech == 'PHP' and not result['language']:
                        result['language'] = 'PHP'
                    elif tech == 'Node.js' and not result['language']:
                        result['language'] = 'Node.js'
                        
            except:
                continue
    
    def _calculate_confidence(self, result: Dict) -> float:
        """Calculate confidence score based on detected information"""
        score = 0.0
        
        if result['server']:
            score += 0.3
        if result['language']:
            score += 0.2
        if result['framework']:
            score += 0.2
        if result['cms']:
            score += 0.1
        if result['versions']:
            score += 0.1 * len(result['versions'])
        if result['technologies']:
            score += 0.05 * min(len(result['technologies']), 4)
        
        return min(score, 1.0)
    
    def get_version_info(self) -> Dict[str, str]:
        """Get detailed version information for all detected technologies"""
        result = self.run()
        return result.get('versions', {})
    
    def is_vulnerable_version(self, software: str, version: str, vulnerable_versions: List[str]) -> bool:
        """Check if detected version matches known vulnerable versions"""
        # Simple version comparison (can be enhanced with semantic versioning)
        return version in vulnerable_versions
