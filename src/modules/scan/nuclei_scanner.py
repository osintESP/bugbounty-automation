"""
Nuclei Scanner Module
"""
from typing import List, Dict
from utils.executor import CommandExecutor
from utils.logger import get_logger
from config import Config
import json
import tempfile

logger = get_logger(__name__)


class NucleiScanner:
    """Run Nuclei vulnerability scanner"""
    
    def __init__(self, target: str):
        self.target = target
        self.executor = CommandExecutor()
        self.config = Config.get_scan_config().get('nuclei', {})
        self.vulnerabilities: List[Dict] = []
    
    def run(self, severity: str = 'medium') -> List[Dict]:
        """Run Nuclei scan"""
        if not self.config.get('enabled', False):
            logger.warning("Nuclei scanning is disabled in config")
            return []
        
        if not self.executor.check_tool_installed('nuclei'):
            logger.error("Nuclei not installed")
            return []
        
        logger.info(f"Starting Nuclei scan for {self.target}")
        
        # Get configuration
        severities = self.config.get('severity', ['critical', 'high', 'medium'])
        rate_limit = self.config.get('rate_limit', 150)
        
        # Filter severities based on minimum
        severity_levels = ['info', 'low', 'medium', 'high', 'critical']
        min_index = severity_levels.index(severity)
        filtered_severities = severity_levels[min_index:]
        
        # Build command
        severity_flags = ','.join([s for s in severities if s in filtered_severities])
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_file = f.name
        
        command = f"nuclei -u https://{self.target} -severity {severity_flags} -rate-limit {rate_limit} -json -o {output_file}"
        
        logger.info(f"Running: {command}")
        exit_code, stdout, stderr = self.executor.run(command, timeout=600)
        
        if exit_code == 0 or exit_code == 1:  # Nuclei returns 1 if vulnerabilities found
            try:
                with open(output_file, 'r') as f:
                    for line in f:
                        if line.strip():
                            vuln = json.loads(line)
                            self.vulnerabilities.append({
                                'title': vuln.get('info', {}).get('name', 'Unknown'),
                                'severity': vuln.get('info', {}).get('severity', 'unknown'),
                                'description': vuln.get('info', {}).get('description', ''),
                                'url': vuln.get('matched-at', self.target),
                                'tool': 'nuclei',
                                'template': vuln.get('template-id', ''),
                                'matcher_name': vuln.get('matcher-name', ''),
                                'evidence': {
                                    'curl_command': vuln.get('curl-command', ''),
                                    'extracted_results': vuln.get('extracted-results', [])
                                }
                            })
                
                logger.info(f"Nuclei found {len(self.vulnerabilities)} vulnerabilities")
            except Exception as e:
                logger.error(f"Error parsing Nuclei output: {e}")
        else:
            logger.error(f"Nuclei failed: {stderr}")
        
        return self.vulnerabilities
    
    def save_to_db(self, scan_id: int):
        """Save vulnerabilities to database"""
        from database import Database, Vulnerability
        
        session = Database.get_session()
        try:
            for vuln in self.vulnerabilities:
                vulnerability = Vulnerability(
                    scan_id=scan_id,
                    title=vuln['title'],
                    severity=vuln['severity'],
                    description=vuln['description'],
                    url=vuln['url'],
                    tool=vuln['tool'],
                    evidence=vuln.get('evidence', {})
                )
                session.add(vulnerability)
            
            session.commit()
            logger.info(f"Saved {len(self.vulnerabilities)} vulnerabilities to database")
            
        except Exception as e:
            logger.error(f"Error saving to database: {e}")
            session.rollback()
        finally:
            session.close()
