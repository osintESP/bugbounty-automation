"""
Technology Detection Module
"""
from typing import List, Dict
from utils.executor import CommandExecutor
from utils.logger import get_logger
from config import Config
import json

logger = get_logger(__name__)


class TechDetector:
    """Detect web technologies"""
    
    def __init__(self, target: str):
        self.target = target
        self.executor = CommandExecutor()
        self.config = Config.get_recon_config().get('tech_detect', {})
        self.technologies: List[Dict] = []
    
    def run(self) -> List[Dict]:
        """Run technology detection"""
        if not self.config.get('enabled', False):
            logger.warning("Technology detection is disabled in config")
            return []
        
        logger.info(f"Starting technology detection for {self.target}")
        
        tools = self.config.get('tools', [])
        
        for tool in tools:
            if tool == 'whatweb':
                self._run_whatweb()
            elif tool == 'wappalyzer':
                self._run_wappalyzer()
            else:
                logger.warning(f"Unknown tool: {tool}")
        
        logger.info(f"Detected {len(self.technologies)} technologies")
        return self.technologies
    
    def _run_whatweb(self):
        """Run whatweb"""
        if not self.executor.check_tool_installed('whatweb'):
            logger.warning("whatweb not installed, skipping")
            return
        
        logger.info("Running whatweb...")
        command = f"whatweb --log-json=/dev/stdout {self.target}"
        exit_code, stdout, stderr = self.executor.run(command, timeout=60)
        
        if exit_code == 0:
            try:
                for line in stdout.split('\n'):
                    if line.strip():
                        data = json.loads(line)
                        for plugin, details in data.get('plugins', {}).items():
                            tech = {
                                'name': plugin,
                                'version': details.get('version', [''])[0] if isinstance(details.get('version'), list) else '',
                                'category': details.get('category', 'unknown'),
                                'source': 'whatweb'
                            }
                            self.technologies.append(tech)
                
                logger.info(f"whatweb detected {len(self.technologies)} technologies")
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing whatweb output: {e}")
        else:
            logger.error(f"whatweb failed: {stderr}")
    
    def _run_wappalyzer(self):
        """Run wappalyzer (requires httpx)"""
        if not self.executor.check_tool_installed('httpx'):
            logger.warning("httpx not installed, skipping wappalyzer")
            return
        
        logger.info("Running httpx with tech detection...")
        command = f"echo {self.target} | httpx -silent -tech-detect -json"
        exit_code, stdout, stderr = self.executor.run(command, timeout=60, shell=True)
        
        if exit_code == 0:
            try:
                for line in stdout.split('\n'):
                    if line.strip():
                        data = json.loads(line)
                        techs = data.get('tech', [])
                        
                        for tech_name in techs:
                            tech = {
                                'name': tech_name,
                                'version': '',
                                'category': 'web',
                                'source': 'httpx'
                            }
                            self.technologies.append(tech)
                
                logger.info(f"httpx detected technologies")
            except json.JSONDecodeError as e:
                logger.error(f"Error parsing httpx output: {e}")
        else:
            logger.error(f"httpx failed: {stderr}")
    
    def save_to_db(self):
        """Save detected technologies to database"""
        from database import Database, Subdomain, Technology
        
        session = Database.get_session()
        try:
            # Find subdomain
            subdomain = session.query(Subdomain).filter_by(
                subdomain=self.target
            ).first()
            
            if subdomain:
                for tech in self.technologies:
                    # Check if technology already exists
                    existing = session.query(Technology).filter_by(
                        subdomain_id=subdomain.id,
                        name=tech['name']
                    ).first()
                    
                    if not existing:
                        technology = Technology(
                            subdomain_id=subdomain.id,
                            name=tech['name'],
                            version=tech.get('version', ''),
                            category=tech.get('category', 'unknown')
                        )
                        session.add(technology)
                
                session.commit()
                logger.info(f"Saved {len(self.technologies)} technologies to database")
            else:
                logger.warning(f"Subdomain {self.target} not found in database")
                
        except Exception as e:
            logger.error(f"Error saving to database: {e}")
            session.rollback()
        finally:
            session.close()
