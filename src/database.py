"""
Database models and connection management
"""
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, ForeignKey, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os

Base = declarative_base()


class Target(Base):
    """Target domain model"""
    __tablename__ = 'targets'
    
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), unique=True, nullable=False)
    scope = Column(JSON)  # List of in-scope domains
    exclude = Column(JSON)  # List of excluded domains
    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    subdomains = relationship("Subdomain", back_populates="target", cascade="all, delete-orphan")
    scans = relationship("Scan", back_populates="target", cascade="all, delete-orphan")


class Subdomain(Base):
    """Subdomain model"""
    __tablename__ = 'subdomains'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey('targets.id'), nullable=False)
    subdomain = Column(String(255), nullable=False)
    ip_address = Column(String(45))  # IPv4 or IPv6
    status_code = Column(Integer)
    discovered_by = Column(String(50))  # Tool that discovered it
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    target = relationship("Target", back_populates="subdomains")
    ports = relationship("Port", back_populates="subdomain", cascade="all, delete-orphan")


class Port(Base):
    """Open port model"""
    __tablename__ = 'ports'
    
    id = Column(Integer, primary_key=True)
    subdomain_id = Column(Integer, ForeignKey('subdomains.id'), nullable=False)
    port = Column(Integer, nullable=False)
    protocol = Column(String(10))  # tcp, udp
    service = Column(String(100))
    version = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    subdomain = relationship("Subdomain", back_populates="ports")


class Vulnerability(Base):
    """Vulnerability finding model"""
    __tablename__ = 'vulnerabilities'
    
    id = Column(Integer, primary_key=True)
    scan_id = Column(Integer, ForeignKey('scans.id'), nullable=False)
    title = Column(String(255), nullable=False)
    severity = Column(String(20))  # critical, high, medium, low, info
    description = Column(Text)
    url = Column(String(512))
    tool = Column(String(50))  # Tool that found it
    cve = Column(String(50))
    cvss_score = Column(String(10))
    remediation = Column(Text)
    evidence = Column(JSON)  # Screenshots, request/response, etc.
    status = Column(String(20), default='open')  # open, confirmed, false_positive, fixed
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="vulnerabilities")


class Scan(Base):
    """Scan execution model"""
    __tablename__ = 'scans'
    
    id = Column(Integer, primary_key=True)
    target_id = Column(Integer, ForeignKey('targets.id'), nullable=False)
    scan_type = Column(String(50))  # recon, vuln_scan, full
    status = Column(String(20))  # running, completed, failed
    started_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime)
    duration = Column(Integer)  # Duration in seconds
    results_summary = Column(JSON)
    
    # Relationships
    target = relationship("Target", back_populates="scans")
    vulnerabilities = relationship("Vulnerability", back_populates="scan", cascade="all, delete-orphan")


class Technology(Base):
    """Detected technology model"""
    __tablename__ = 'technologies'
    
    id = Column(Integer, primary_key=True)
    subdomain_id = Column(Integer, ForeignKey('subdomains.id'), nullable=False)
    name = Column(String(100))
    version = Column(String(50))
    category = Column(String(50))  # cms, framework, server, etc.
    created_at = Column(DateTime, default=datetime.utcnow)


class URL(Base):
    """Discovered URL model"""
    __tablename__ = 'urls'
    
    id = Column(Integer, primary_key=True)
    subdomain_id = Column(Integer, ForeignKey('subdomains.id'), nullable=False)
    url = Column(String(1024), nullable=False)
    status_code = Column(Integer)
    content_type = Column(String(100))
    discovered_by = Column(String(50))
    created_at = Column(DateTime, default=datetime.utcnow)


class Database:
    """Database connection manager"""
    
    _engine = None
    _session_factory = None
    
    @classmethod
    def initialize(cls, db_url: str = None):
        """Initialize database connection"""
        if db_url is None:
            # Build from environment variables
            db_host = os.getenv('DB_HOST', 'localhost')
            db_port = os.getenv('DB_PORT', '5432')
            db_name = os.getenv('DB_NAME', 'bugbounty')
            db_user = os.getenv('DB_USER', 'bugbounty_user')
            db_password = os.getenv('DB_PASSWORD', 'changeme123')
            
            db_url = f"postgresql://{db_user}:{db_password}@{db_host}:{db_port}/{db_name}"
        
        cls._engine = create_engine(db_url, echo=False)
        cls._session_factory = sessionmaker(bind=cls._engine)
        
        # Create tables
        Base.metadata.create_all(cls._engine)
    
    @classmethod
    def get_session(cls):
        """Get database session"""
        if cls._session_factory is None:
            cls.initialize()
        return cls._session_factory()
    
    @classmethod
    def close(cls):
        """Close database connection"""
        if cls._engine:
            cls._engine.dispose()
