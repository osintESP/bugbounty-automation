#!/usr/bin/env python3
"""
CVE Matcher - Matches detected technologies to known CVEs
"""
import json
from typing import List, Dict, Optional
from pathlib import Path
from utils.logger import logger


class CVEMatcher:
    """Match detected technologies and versions to known CVEs"""
    
    # Built-in CVE database for common vulnerabilities
    CVE_DATABASE = {
        'Apache': {
            '2.4.49': [
                {
                    'cve': 'CVE-2021-41773',
                    'severity': 'critical',
                    'cvss': 9.8,
                    'description': 'Path traversal and RCE in Apache HTTP Server 2.4.49',
                    'affected_versions': ['2.4.49'],
                    'exploit_available': True,
                    'exploit_type': 'path_traversal',
                    'references': [
                        'https://nvd.nist.gov/vuln/detail/CVE-2021-41773',
                        'https://github.com/blasty/CVE-2021-41773'
                    ]
                }
            ],
            '2.4.50': [
                {
                    'cve': 'CVE-2021-42013',
                    'severity': 'critical',
                    'cvss': 9.8,
                    'description': 'Path traversal and RCE in Apache HTTP Server 2.4.50',
                    'affected_versions': ['2.4.50'],
                    'exploit_available': True,
                    'exploit_type': 'path_traversal',
                    'references': [
                        'https://nvd.nist.gov/vuln/detail/CVE-2021-42013'
                    ]
                }
            ]
        },
        'PHP': {
            '7.4.0': [
                {
                    'cve': 'CVE-2019-11043',
                    'severity': 'critical',
                    'cvss': 9.8,
                    'description': 'PHP-FPM RCE vulnerability',
                    'affected_versions': ['7.4.0', '7.3.0-7.3.11', '7.2.0-7.2.24'],
                    'exploit_available': True,
                    'exploit_type': 'rce',
                    'references': [
                        'https://nvd.nist.gov/vuln/detail/CVE-2019-11043'
                    ]
                }
            ]
        },
        'Flask': {
            '2.0.1': [
                {
                    'cve': 'CVE-2023-30861',
                    'severity': 'high',
                    'cvss': 7.5,
                    'description': 'Cookie parsing vulnerability in Werkzeug',
                    'affected_versions': ['2.0.0-2.0.3'],
                    'exploit_available': False,
                    'exploit_type': 'cookie_injection',
                    'references': [
                        'https://nvd.nist.gov/vuln/detail/CVE-2023-30861'
                    ]
                }
            ]
        },
        'WordPress': {
            '5.8.0': [
                {
                    'cve': 'CVE-2021-24762',
                    'severity': 'critical',
                    'cvss': 9.8,
                    'description': 'WordPress Plugin SQL Injection',
                    'affected_versions': ['<5.8.1'],
                    'exploit_available': True,
                    'exploit_type': 'sqli',
                    'references': []
                }
            ]
        }
    }
    
    def __init__(self, custom_db_path: str = None):
        self.custom_db_path = custom_db_path
        self.cve_db = self.CVE_DATABASE.copy()
        
        # Load custom CVE database if provided
        if custom_db_path and Path(custom_db_path).exists():
            self._load_custom_db(custom_db_path)
    
    def _load_custom_db(self, db_path: str):
        """Load custom CVE database from JSON file"""
        try:
            with open(db_path, 'r') as f:
                custom_db = json.load(f)
                # Merge with built-in database
                for tech, versions in custom_db.items():
                    if tech in self.cve_db:
                        self.cve_db[tech].update(versions)
                    else:
                        self.cve_db[tech] = versions
                logger.info(f"Loaded custom CVE database from {db_path}")
        except Exception as e:
            logger.error(f"Error loading custom CVE database: {e}")
    
    def match(self, fingerprint: Dict, severity_filter: List[str] = None) -> List[Dict]:
        """
        Match fingerprint results to known CVEs
        
        Args:
            fingerprint: Result from Fingerprinter.run()
            severity_filter: List of severities to include (e.g., ['critical', 'high'])
        
        Returns:
            List of matched CVEs with exploit information
        """
        logger.info("Starting CVE matching")
        
        matched_cves = []
        
        # Extract technology and version information
        technologies = self._extract_technologies(fingerprint)
        
        logger.info(f"Detected technologies: {technologies}")
        
        # Match each technology
        for tech_name, version in technologies.items():
            if tech_name in self.cve_db:
                logger.info(f"Checking {tech_name} {version} for CVEs")
                
                # Check exact version match
                if version in self.cve_db[tech_name]:
                    cves = self.cve_db[tech_name][version]
                    for cve in cves:
                        if self._should_include(cve, severity_filter):
                            cve_copy = cve.copy()
                            cve_copy['matched_technology'] = tech_name
                            cve_copy['matched_version'] = version
                            matched_cves.append(cve_copy)
                            logger.info(f"Matched {cve['cve']} for {tech_name} {version}")
                
                # Check version ranges (for affected_versions like "<5.8.1")
                for db_version, cves in self.cve_db[tech_name].items():
                    for cve in cves:
                        if self._version_in_range(version, cve.get('affected_versions', [])):
                            if self._should_include(cve, severity_filter):
                                cve_copy = cve.copy()
                                cve_copy['matched_technology'] = tech_name
                                cve_copy['matched_version'] = version
                                if cve_copy not in matched_cves:
                                    matched_cves.append(cve_copy)
                                    logger.info(f"Matched {cve['cve']} (range) for {tech_name} {version}")
        
        # Sort by CVSS score (highest first)
        matched_cves.sort(key=lambda x: x.get('cvss', 0), reverse=True)
        
        logger.info(f"CVE matching complete: {len(matched_cves)} CVEs found")
        return matched_cves
    
    def _extract_technologies(self, fingerprint: Dict) -> Dict[str, str]:
        """Extract technology names and versions from fingerprint"""
        technologies = {}
        
        # Server
        if fingerprint.get('server'):
            server = fingerprint['server']
            if 'Apache' in server:
                tech_name = 'Apache'
                version = fingerprint.get('versions', {}).get('server')
                if version:
                    technologies[tech_name] = version
        
        # Language
        if fingerprint.get('language'):
            lang = fingerprint['language']
            if lang in self.cve_db:
                version = fingerprint.get('versions', {}).get(lang.lower())
                if version:
                    technologies[lang] = version
        
        # Framework
        if fingerprint.get('framework'):
            framework = fingerprint['framework']
            if framework in self.cve_db:
                version = fingerprint.get('versions', {}).get(framework.lower())
                if version:
                    technologies[framework] = version
        
        # CMS
        if fingerprint.get('cms'):
            cms = fingerprint['cms']
            if cms in self.cve_db:
                version = fingerprint.get('versions', {}).get(cms.lower())
                if version:
                    technologies[cms] = version
        
        return technologies
    
    def _should_include(self, cve: Dict, severity_filter: List[str]) -> bool:
        """Check if CVE should be included based on severity filter"""
        if not severity_filter:
            return True
        return cve.get('severity', '').lower() in [s.lower() for s in severity_filter]
    
    def _version_in_range(self, version: str, affected_versions: List[str]) -> bool:
        """Check if version is in affected version range"""
        # Simple implementation - can be enhanced with semantic versioning
        for affected in affected_versions:
            if affected.startswith('<'):
                # Version less than
                max_version = affected[1:].strip()
                if self._compare_versions(version, max_version) < 0:
                    return True
            elif affected.startswith('>'):
                # Version greater than
                min_version = affected[1:].strip()
                if self._compare_versions(version, min_version) > 0:
                    return True
            elif '-' in affected:
                # Version range (e.g., "7.2.0-7.2.24")
                min_v, max_v = affected.split('-')
                if (self._compare_versions(version, min_v.strip()) >= 0 and
                    self._compare_versions(version, max_v.strip()) <= 0):
                    return True
            elif version == affected:
                return True
        
        return False
    
    def _compare_versions(self, v1: str, v2: str) -> int:
        """
        Compare two version strings
        Returns: -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2
        """
        try:
            parts1 = [int(x) for x in v1.split('.')]
            parts2 = [int(x) for x in v2.split('.')]
            
            # Pad shorter version with zeros
            max_len = max(len(parts1), len(parts2))
            parts1 += [0] * (max_len - len(parts1))
            parts2 += [0] * (max_len - len(parts2))
            
            for p1, p2 in zip(parts1, parts2):
                if p1 < p2:
                    return -1
                elif p1 > p2:
                    return 1
            
            return 0
        except:
            # Fallback to string comparison
            if v1 < v2:
                return -1
            elif v1 > v2:
                return 1
            return 0
    
    def get_exploitable_cves(self, matched_cves: List[Dict]) -> List[Dict]:
        """Filter CVEs that have available exploits"""
        return [cve for cve in matched_cves if cve.get('exploit_available', False)]
    
    def export_results(self, matched_cves: List[Dict]) -> Dict:
        """Export CVE matching results"""
        return {
            'total_cves': len(matched_cves),
            'exploitable': len(self.get_exploitable_cves(matched_cves)),
            'by_severity': {
                'critical': len([c for c in matched_cves if c.get('severity') == 'critical']),
                'high': len([c for c in matched_cves if c.get('severity') == 'high']),
                'medium': len([c for c in matched_cves if c.get('severity') == 'medium']),
                'low': len([c for c in matched_cves if c.get('severity') == 'low']),
            },
            'cves': matched_cves
        }
