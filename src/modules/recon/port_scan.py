"""
Port Scanning Module
"""
import nmap
from typing import List, Dict
from utils.logger import get_logger
from config import Config

logger = get_logger(__name__)


class PortScanner:
    """Scan ports using nmap"""
    
    def __init__(self, target: str):
        self.target = target
        self.config = Config.get_recon_config().get('port_scan', {})
        self.scanner = nmap.PortScanner()
        self.results: List[Dict] = []
    
    def run(self) -> List[Dict]:
        """Run port scan"""
        if not self.config.get('enabled', False):
            logger.warning("Port scanning is disabled in config")
            return []
        
        logger.info(f"Starting port scan for {self.target}")
        
        # Get configuration
        scan_type = self.config.get('scan_type', '-sV')
        top_ports = self.config.get('top_ports', 1000)
        
        try:
            # Scan top ports
            logger.info(f"Scanning top {top_ports} ports...")
            self.scanner.scan(
                hosts=self.target,
                arguments=f'{scan_type} --top-ports {top_ports}'
            )
            
            # Parse results
            for host in self.scanner.all_hosts():
                logger.info(f"Host: {host} ({self.scanner[host].hostname()})")
                logger.info(f"State: {self.scanner[host].state()}")
                
                for proto in self.scanner[host].all_protocols():
                    ports = self.scanner[host][proto].keys()
                    
                    for port in ports:
                        port_info = self.scanner[host][proto][port]
                        
                        result = {
                            'host': host,
                            'port': port,
                            'protocol': proto,
                            'state': port_info['state'],
                            'service': port_info.get('name', 'unknown'),
                            'version': port_info.get('version', ''),
                            'product': port_info.get('product', '')
                        }
                        
                        self.results.append(result)
                        logger.info(f"  Port {port}/{proto}: {result['service']} {result['version']}")
            
            logger.info(f"Found {len(self.results)} open ports")
            return self.results
            
        except Exception as e:
            logger.error(f"Port scan failed: {e}")
            return []
    
    def save_to_db(self):
        """Save port scan results to database"""
        from database import Database, Subdomain, Port
        
        session = Database.get_session()
        try:
            for result in self.results:
                # Find subdomain
                subdomain = session.query(Subdomain).filter_by(
                    subdomain=result['host']
                ).first()
                
                if subdomain:
                    # Check if port already exists
                    existing = session.query(Port).filter_by(
                        subdomain_id=subdomain.id,
                        port=result['port'],
                        protocol=result['protocol']
                    ).first()
                    
                    if not existing:
                        port = Port(
                            subdomain_id=subdomain.id,
                            port=result['port'],
                            protocol=result['protocol'],
                            service=result['service'],
                            version=f"{result['product']} {result['version']}".strip()
                        )
                        session.add(port)
            
            session.commit()
            logger.info(f"Saved {len(self.results)} ports to database")
            
        except Exception as e:
            logger.error(f"Error saving to database: {e}")
            session.rollback()
        finally:
            session.close()
