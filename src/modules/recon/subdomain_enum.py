"""
Subdomain Enumeration Module
"""
from typing import List, Set
from utils.executor import CommandExecutor
from utils.logger import get_logger
from config import Config

logger = get_logger(__name__)


class SubdomainEnumerator:
    """Enumerate subdomains using multiple tools"""
    
    def __init__(self, target: str):
        self.target = target
        self.executor = CommandExecutor()
        self.config = Config.get_recon_config().get('subdomain_enum', {})
        self.subdomains: Set[str] = set()
    
    def run(self) -> List[str]:
        """Run all enabled subdomain enumeration tools"""
        if not self.config.get('enabled', False):
            logger.warning("Subdomain enumeration is disabled in config")
            return []
        
        tools = self.config.get('tools', [])
        timeout = self.config.get('timeout', 300)
        
        logger.info(f"Starting subdomain enumeration for {self.target}")
        
        for tool in tools:
            if tool == 'subfinder':
                self._run_subfinder(timeout)
            elif tool == 'amass':
                self._run_amass(timeout)
            elif tool == 'assetfinder':
                self._run_assetfinder(timeout)
            else:
                logger.warning(f"Unknown tool: {tool}")
        
        logger.info(f"Found {len(self.subdomains)} unique subdomains")
        return sorted(list(self.subdomains))
    
    def _run_subfinder(self, timeout: int):
        """Run subfinder"""
        if not self.executor.check_tool_installed('subfinder'):
            logger.warning("subfinder not installed, skipping")
            return
        
        logger.info("Running subfinder...")
        command = f"subfinder -d {self.target} -silent"
        exit_code, stdout, stderr = self.executor.run(command, timeout=timeout)
        
        if exit_code == 0:
            subdomains = [s.strip() for s in stdout.split('\n') if s.strip()]
            self.subdomains.update(subdomains)
            logger.info(f"subfinder found {len(subdomains)} subdomains")
        else:
            logger.error(f"subfinder failed: {stderr}")
    
    def _run_amass(self, timeout: int):
        """Run amass"""
        if not self.executor.check_tool_installed('amass'):
            logger.warning("amass not installed, skipping")
            return
        
        logger.info("Running amass...")
        command = f"amass enum -passive -d {self.target}"
        exit_code, stdout, stderr = self.executor.run(command, timeout=timeout)
        
        if exit_code == 0:
            subdomains = [s.strip() for s in stdout.split('\n') if s.strip()]
            self.subdomains.update(subdomains)
            logger.info(f"amass found {len(subdomains)} subdomains")
        else:
            logger.error(f"amass failed: {stderr}")
    
    def _run_assetfinder(self, timeout: int):
        """Run assetfinder"""
        if not self.executor.check_tool_installed('assetfinder'):
            logger.warning("assetfinder not installed, skipping")
            return
        
        logger.info("Running assetfinder...")
        command = f"assetfinder --subs-only {self.target}"
        exit_code, stdout, stderr = self.executor.run(command, timeout=timeout)
        
        if exit_code == 0:
            subdomains = [s.strip() for s in stdout.split('\n') if s.strip()]
            self.subdomains.update(subdomains)
            logger.info(f"assetfinder found {len(subdomains)} subdomains")
        else:
            logger.error(f"assetfinder failed: {stderr}")
    
    def save_to_db(self):
        """Save discovered subdomains to database"""
        from database import Database, Target, Subdomain
        
        session = Database.get_session()
        try:
            # Get or create target
            target = session.query(Target).filter_by(domain=self.target).first()
            if not target:
                target = Target(domain=self.target)
                session.add(target)
                session.commit()
            
            # Add subdomains
            for subdomain in self.subdomains:
                existing = session.query(Subdomain).filter_by(
                    target_id=target.id,
                    subdomain=subdomain
                ).first()
                
                if not existing:
                    sub = Subdomain(
                        target_id=target.id,
                        subdomain=subdomain,
                        discovered_by='enumeration'
                    )
                    session.add(sub)
            
            session.commit()
            logger.info(f"Saved {len(self.subdomains)} subdomains to database")
            
        except Exception as e:
            logger.error(f"Error saving to database: {e}")
            session.rollback()
        finally:
            session.close()
