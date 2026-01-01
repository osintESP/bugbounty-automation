"""
Secrets Scanner Module
"""
from typing import List, Dict
from utils.executor import CommandExecutor
from utils.logger import get_logger
from config import Config
import json
import re

logger = get_logger(__name__)


class SecretScanner:
    """Scan for exposed secrets and credentials"""
    
    # Common secret patterns
    PATTERNS = {
        'api_key': r'(?i)(api[_-]?key|apikey)[\s:=]+["\']?([a-zA-Z0-9_\-]{20,})["\']?',
        'aws_key': r'(?i)(aws[_-]?access[_-]?key[_-]?id|aws[_-]?secret[_-]?access[_-]?key)[\s:=]+["\']?([A-Z0-9]{20,})["\']?',
        'github_token': r'(?i)(github[_-]?token|gh[ps]_[a-zA-Z0-9]{36,})',
        'private_key': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
        'password': r'(?i)(password|passwd|pwd)[\s:=]+["\']([^"\']{8,})["\']',
        'jwt': r'eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*',
        'slack_token': r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}',
        'stripe_key': r'(?i)(sk|pk)_(test|live)_[a-zA-Z0-9]{24,}',
    }
    
    def __init__(self, target: str):
        self.target = target
        self.executor = CommandExecutor()
        self.config = Config.get_scan_config().get('secrets', {})
        self.secrets: List[Dict] = []
    
    def run(self) -> List[Dict]:
        """Run secret scanning"""
        if not self.config.get('enabled', False):
            logger.warning("Secret scanning is disabled in config")
            return []
        
        logger.info(f"Starting secret scan for {self.target}")
        
        tools = self.config.get('tools', [])
        
        for tool in tools:
            if tool == 'trufflehog':
                self._run_trufflehog()
            elif tool == 'gitleaks':
                self._run_gitleaks()
            else:
                logger.warning(f"Unknown tool: {tool}")
        
        # Also run pattern matching
        self._pattern_scan()
        
        logger.info(f"Found {len(self.secrets)} potential secrets")
        return self.secrets
    
    def _run_trufflehog(self):
        """Run trufflehog"""
        if not self.executor.check_tool_installed('trufflehog'):
            logger.warning("trufflehog not installed, skipping")
            return
        
        logger.info("Running trufflehog...")
        command = f"trufflehog https://{self.target} --json"
        exit_code, stdout, stderr = self.executor.run(command, timeout=300)
        
        if exit_code == 0:
            try:
                for line in stdout.split('\n'):
                    if line.strip():
                        secret = json.loads(line)
                        self.secrets.append({
                            'type': secret.get('DetectorName', 'unknown'),
                            'value': secret.get('Raw', ''),
                            'file': secret.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', ''),
                            'tool': 'trufflehog',
                            'severity': 'high'
                        })
                
                logger.info(f"trufflehog found {len(self.secrets)} secrets")
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing trufflehog output: {e}")
        else:
            logger.error(f"trufflehog failed: {stderr}")
    
    def _run_gitleaks(self):
        """Run gitleaks"""
        if not self.executor.check_tool_installed('gitleaks'):
            logger.warning("gitleaks not installed, skipping")
            return
        
        logger.info("Running gitleaks...")
        # Note: gitleaks is primarily for git repos, this is a placeholder
        logger.info("gitleaks requires a git repository, skipping for web targets")
    
    def _pattern_scan(self):
        """Scan using regex patterns"""
        logger.info("Running pattern-based secret detection...")
        
        try:
            import requests
            url = f"https://{self.target}" if not self.target.startswith('http') else self.target
            response = requests.get(url, timeout=10, verify=False)
            content = response.text
            
            patterns_to_check = self.config.get('patterns', list(self.PATTERNS.keys()))
            
            for pattern_name in patterns_to_check:
                if pattern_name in self.PATTERNS:
                    pattern = self.PATTERNS[pattern_name]
                    matches = re.finditer(pattern, content)
                    
                    for match in matches:
                        self.secrets.append({
                            'type': pattern_name,
                            'value': match.group(0)[:50] + '...',  # Truncate for safety
                            'file': url,
                            'tool': 'pattern_matcher',
                            'severity': 'medium',
                            'line': content[:match.start()].count('\n') + 1
                        })
            
            logger.info(f"Pattern matching found {len(self.secrets)} potential secrets")
            
        except Exception as e:
            logger.error(f"Error in pattern scanning: {e}")
    
    def save_to_db(self, scan_id: int):
        """Save secrets to database"""
        from database import Database, Vulnerability
        
        session = Database.get_session()
        try:
            for secret in self.secrets:
                vulnerability = Vulnerability(
                    scan_id=scan_id,
                    title=f"Exposed Secret: {secret['type']}",
                    severity=secret.get('severity', 'high'),
                    description=f"Potential {secret['type']} found in {secret.get('file', 'unknown')}",
                    url=self.target,
                    tool=secret['tool'],
                    evidence={'type': secret['type'], 'location': secret.get('file', '')}
                )
                session.add(vulnerability)
            
            session.commit()
            logger.info(f"Saved {len(self.secrets)} secrets to database")
            
        except Exception as e:
            logger.error(f"Error saving to database: {e}")
            session.rollback()
        finally:
            session.close()
