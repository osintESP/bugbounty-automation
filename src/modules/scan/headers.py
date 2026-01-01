"""
Security Headers Analyzer
"""
from typing import List, Dict
import requests
from utils.logger import get_logger
from config import Config

logger = get_logger(__name__)


class HeaderAnalyzer:
    """Analyze security headers"""
    
    # Security headers to check
    SECURITY_HEADERS = {
        'strict-transport-security': {
            'name': 'HTTP Strict Transport Security (HSTS)',
            'severity': 'medium',
            'description': 'HSTS header is missing. This header forces browsers to use HTTPS.'
        },
        'content-security-policy': {
            'name': 'Content Security Policy (CSP)',
            'severity': 'medium',
            'description': 'CSP header is missing. This header helps prevent XSS attacks.'
        },
        'x-frame-options': {
            'name': 'X-Frame-Options',
            'severity': 'medium',
            'description': 'X-Frame-Options header is missing. This header prevents clickjacking attacks.'
        },
        'x-content-type-options': {
            'name': 'X-Content-Type-Options',
            'severity': 'low',
            'description': 'X-Content-Type-Options header is missing. This header prevents MIME-sniffing.'
        },
        'x-xss-protection': {
            'name': 'X-XSS-Protection',
            'severity': 'low',
            'description': 'X-XSS-Protection header is missing (deprecated but still useful for older browsers).'
        },
        'referrer-policy': {
            'name': 'Referrer-Policy',
            'severity': 'low',
            'description': 'Referrer-Policy header is missing. This header controls referrer information.'
        },
        'permissions-policy': {
            'name': 'Permissions-Policy',
            'severity': 'low',
            'description': 'Permissions-Policy header is missing. This header controls browser features.'
        }
    }
    
    def __init__(self, target: str):
        self.target = target
        self.config = Config.get_scan_config().get('headers', {})
        self.issues: List[Dict] = []
    
    def run(self) -> List[Dict]:
        """Analyze security headers"""
        if not self.config.get('enabled', False):
            logger.warning("Header analysis is disabled in config")
            return []
        
        logger.info(f"Analyzing security headers for {self.target}")
        
        try:
            # Make request
            url = f"https://{self.target}" if not self.target.startswith('http') else self.target
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            
            headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Check for missing headers
            headers_to_check = self.config.get('check', list(self.SECURITY_HEADERS.keys()))
            
            for header in headers_to_check:
                if header not in headers:
                    header_info = self.SECURITY_HEADERS.get(header, {})
                    issue = {
                        'header': header,
                        'name': header_info.get('name', header),
                        'severity': header_info.get('severity', 'low'),
                        'description': header_info.get('description', f'{header} is missing'),
                        'status': 'missing',
                        'url': url
                    }
                    self.issues.append(issue)
                else:
                    # Header exists, check value
                    value = headers[header]
                    logger.info(f"  {header}: {value}")
                    
                    # Validate specific headers
                    if header == 'strict-transport-security':
                        if 'max-age' not in value.lower():
                            self.issues.append({
                                'header': header,
                                'name': 'HSTS max-age',
                                'severity': 'medium',
                                'description': 'HSTS header present but max-age directive is missing',
                                'status': 'misconfigured',
                                'value': value,
                                'url': url
                            })
                    
                    elif header == 'x-frame-options':
                        if value.upper() not in ['DENY', 'SAMEORIGIN']:
                            self.issues.append({
                                'header': header,
                                'name': 'X-Frame-Options',
                                'severity': 'low',
                                'description': f'X-Frame-Options has weak value: {value}',
                                'status': 'misconfigured',
                                'value': value,
                                'url': url
                            })
            
            logger.info(f"Found {len(self.issues)} header issues")
            return self.issues
            
        except requests.RequestException as e:
            logger.error(f"Error analyzing headers: {e}")
            return []
    
    def save_to_db(self, scan_id: int):
        """Save header issues to database"""
        from database import Database, Vulnerability
        
        session = Database.get_session()
        try:
            for issue in self.issues:
                vulnerability = Vulnerability(
                    scan_id=scan_id,
                    title=f"Missing/Misconfigured Header: {issue['name']}",
                    severity=issue['severity'],
                    description=issue['description'],
                    url=issue['url'],
                    tool='header_analyzer',
                    evidence={'header': issue['header'], 'value': issue.get('value', 'N/A')}
                )
                session.add(vulnerability)
            
            session.commit()
            logger.info(f"Saved {len(self.issues)} header issues to database")
            
        except Exception as e:
            logger.error(f"Error saving to database: {e}")
            session.rollback()
        finally:
            session.close()
