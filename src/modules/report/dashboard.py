"""
Dashboard API Module
"""
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from typing import List, Dict
from database import Database, Target, Scan, Vulnerability, Subdomain
from pydantic import BaseModel
from datetime import datetime

app = FastAPI(title="Bug Bounty Automation API", version="1.0.0")


class TargetModel(BaseModel):
    domain: str
    scope: List[str] = []
    exclude: List[str] = []
    enabled: bool = True


class ScanModel(BaseModel):
    target_id: int
    scan_type: str


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Main dashboard"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Bug Bounty Dashboard</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #1a1a1a; color: #fff; }
            .container { max-width: 1400px; margin: 0 auto; }
            h1 { color: #00d4ff; }
            .card { background: #2a2a2a; padding: 20px; margin: 20px 0; border-radius: 8px; border-left: 4px solid #00d4ff; }
            .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }
            .stat-box { background: #333; padding: 20px; border-radius: 8px; text-align: center; }
            .stat-number { font-size: 2em; font-weight: bold; color: #00d4ff; }
            .stat-label { color: #aaa; margin-top: 10px; }
            a { color: #00d4ff; text-decoration: none; }
            a:hover { text-decoration: underline; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔒 Bug Bounty Automation Dashboard</h1>
            
            <div class="card">
                <h2>Quick Links</h2>
                <ul>
                    <li><a href="/api/targets">View All Targets</a></li>
                    <li><a href="/api/scans">View All Scans</a></li>
                    <li><a href="/api/vulnerabilities">View All Vulnerabilities</a></li>
                    <li><a href="/docs">API Documentation</a></li>
                </ul>
            </div>
            
            <div class="card">
                <h2>API Endpoints</h2>
                <ul>
                    <li><code>GET /api/targets</code> - List all targets</li>
                    <li><code>POST /api/targets</code> - Add new target</li>
                    <li><code>GET /api/scans</code> - List all scans</li>
                    <li><code>GET /api/vulnerabilities</code> - List all vulnerabilities</li>
                    <li><code>GET /api/stats</code> - Get statistics</li>
                </ul>
            </div>
        </div>
    </body>
    </html>
    """


@app.get("/api/targets")
async def get_targets():
    """Get all targets"""
    session = Database.get_session()
    try:
        targets = session.query(Target).all()
        return [{
            'id': t.id,
            'domain': t.domain,
            'scope': t.scope,
            'exclude': t.exclude,
            'enabled': t.enabled,
            'created_at': t.created_at.isoformat()
        } for t in targets]
    finally:
        session.close()


@app.post("/api/targets")
async def create_target(target: TargetModel):
    """Create new target"""
    session = Database.get_session()
    try:
        # Check if target already exists
        existing = session.query(Target).filter_by(domain=target.domain).first()
        if existing:
            raise HTTPException(status_code=400, detail="Target already exists")
        
        new_target = Target(
            domain=target.domain,
            scope=target.scope,
            exclude=target.exclude,
            enabled=target.enabled
        )
        session.add(new_target)
        session.commit()
        
        return {"id": new_target.id, "domain": new_target.domain, "status": "created"}
    except Exception as e:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        session.close()


@app.get("/api/scans")
async def get_scans():
    """Get all scans"""
    session = Database.get_session()
    try:
        scans = session.query(Scan).order_by(Scan.started_at.desc()).limit(100).all()
        return [{
            'id': s.id,
            'target_id': s.target_id,
            'scan_type': s.scan_type,
            'status': s.status,
            'started_at': s.started_at.isoformat(),
            'completed_at': s.completed_at.isoformat() if s.completed_at else None,
            'duration': s.duration
        } for s in scans]
    finally:
        session.close()


@app.get("/api/vulnerabilities")
async def get_vulnerabilities(severity: str = None, limit: int = 100):
    """Get vulnerabilities"""
    session = Database.get_session()
    try:
        query = session.query(Vulnerability)
        
        if severity:
            query = query.filter_by(severity=severity)
        
        vulns = query.order_by(Vulnerability.created_at.desc()).limit(limit).all()
        
        return [{
            'id': v.id,
            'scan_id': v.scan_id,
            'title': v.title,
            'severity': v.severity,
            'description': v.description,
            'url': v.url,
            'tool': v.tool,
            'status': v.status,
            'created_at': v.created_at.isoformat()
        } for v in vulns]
    finally:
        session.close()


@app.get("/api/stats")
async def get_stats():
    """Get statistics"""
    session = Database.get_session()
    try:
        total_targets = session.query(Target).count()
        total_scans = session.query(Scan).count()
        total_vulns = session.query(Vulnerability).count()
        total_subdomains = session.query(Subdomain).count()
        
        # Vulnerability breakdown by severity
        vuln_breakdown = {}
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            count = session.query(Vulnerability).filter_by(severity=severity).count()
            vuln_breakdown[severity] = count
        
        return {
            'total_targets': total_targets,
            'total_scans': total_scans,
            'total_vulnerabilities': total_vulns,
            'total_subdomains': total_subdomains,
            'vulnerability_breakdown': vuln_breakdown
        }
    finally:
        session.close()


@app.on_event("startup")
async def startup_event():
    """Initialize database on startup"""
    Database.initialize()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
