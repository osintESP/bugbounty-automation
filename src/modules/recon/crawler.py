"""
Web Crawler Module
"""
from typing import List, Set
from utils.executor import CommandExecutor
from utils.logger import get_logger
from config import Config

logger = get_logger(__name__)


class WebCrawler:
    """Crawl websites to discover URLs"""
    
    def __init__(self, target: str):
        self.target = target
        self.executor = CommandExecutor()
        self.config = Config.get_recon_config().get('crawler', {})
        self.urls: Set[str] = set()
    
    def run(self) -> List[str]:
        """Run web crawling"""
        if not self.config.get('enabled', False):
            logger.warning("Web crawling is disabled in config")
            return []
        
        logger.info(f"Starting web crawling for {self.target}")
        
        tools = self.config.get('tools', [])
        depth = self.config.get('depth', 3)
        max_urls = self.config.get('max_urls', 1000)
        
        for tool in tools:
            if tool == 'gospider':
                self._run_gospider(depth)
            elif tool == 'hakrawler':
                self._run_hakrawler(depth)
            elif tool == 'katana':
                self._run_katana(depth)
            elif tool == 'gau':
                self._run_gau()
            else:
                logger.warning(f"Unknown tool: {tool}")
            
            # Stop if we've reached max URLs
            if len(self.urls) >= max_urls:
                logger.info(f"Reached maximum URL limit ({max_urls})")
                break
        
        logger.info(f"Found {len(self.urls)} unique URLs")
        return sorted(list(self.urls))[:max_urls]
    
    def _run_gospider(self, depth: int):
        """Run gospider"""
        if not self.executor.check_tool_installed('gospider'):
            logger.warning("gospider not installed, skipping")
            return
        
        logger.info("Running gospider...")
        command = f"gospider -s https://{self.target} -d {depth} -c 10 -t 20"
        exit_code, stdout, stderr = self.executor.run(command, timeout=300)
        
        if exit_code == 0:
            urls = [line.split(' - ')[1].strip() for line in stdout.split('\n') 
                   if ' - ' in line and line.strip()]
            self.urls.update(urls)
            logger.info(f"gospider found {len(urls)} URLs")
        else:
            logger.error(f"gospider failed: {stderr}")
    
    def _run_hakrawler(self, depth: int):
        """Run hakrawler"""
        if not self.executor.check_tool_installed('hakrawler'):
            logger.warning("hakrawler not installed, skipping")
            return
        
        logger.info("Running hakrawler...")
        command = f"echo https://{self.target} | hakrawler -d {depth}"
        exit_code, stdout, stderr = self.executor.run(command, timeout=300, shell=True)
        
        if exit_code == 0:
            urls = [u.strip() for u in stdout.split('\n') if u.strip()]
            self.urls.update(urls)
            logger.info(f"hakrawler found {len(urls)} URLs")
        else:
            logger.error(f"hakrawler failed: {stderr}")
    
    def _run_katana(self, depth: int):
        """Run katana"""
        if not self.executor.check_tool_installed('katana'):
            logger.warning("katana not installed, skipping")
            return
        
        logger.info("Running katana...")
        command = f"katana -u https://{self.target} -d {depth} -silent"
        exit_code, stdout, stderr = self.executor.run(command, timeout=300)
        
        if exit_code == 0:
            urls = [u.strip() for u in stdout.split('\n') if u.strip()]
            self.urls.update(urls)
            logger.info(f"katana found {len(urls)} URLs")
        else:
            logger.error(f"katana failed: {stderr}")
    
    def _run_gau(self):
        """Run gau (Get All URLs from archives)"""
        if not self.executor.check_tool_installed('gau'):
            logger.warning("gau not installed, skipping")
            return
        
        logger.info("Running gau...")
        command = f"gau {self.target} --threads 5"
        exit_code, stdout, stderr = self.executor.run(command, timeout=300)
        
        if exit_code == 0:
            urls = [u.strip() for u in stdout.split('\n') if u.strip()]
            self.urls.update(urls)
            logger.info(f"gau found {len(urls)} URLs")
        else:
            logger.error(f"gau failed: {stderr}")
    
    def save_to_db(self):
        """Save discovered URLs to database"""
        from database import Database, Subdomain, URL
        
        session = Database.get_session()
        try:
            # Find subdomain
            subdomain = session.query(Subdomain).filter_by(
                subdomain=self.target
            ).first()
            
            if subdomain:
                for url in self.urls:
                    # Check if URL already exists
                    existing = session.query(URL).filter_by(
                        subdomain_id=subdomain.id,
                        url=url
                    ).first()
                    
                    if not existing:
                        url_obj = URL(
                            subdomain_id=subdomain.id,
                            url=url,
                            discovered_by='crawler'
                        )
                        session.add(url_obj)
                
                session.commit()
                logger.info(f"Saved {len(self.urls)} URLs to database")
            else:
                logger.warning(f"Subdomain {self.target} not found in database")
                
        except Exception as e:
            logger.error(f"Error saving to database: {e}")
            session.rollback()
        finally:
            session.close()
