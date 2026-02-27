"""Intelligent Drive Scanner v2.0 — FastAPI Dashboard Server.

Real-time analytics dashboard with WebSocket scan progress,
RESTful API for file intelligence, and Jinja2 HTML templates.

Port: 8460
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from loguru import logger
from starlette.requests import Request

from config import DASHBOARD_PORT, ScanConfig
from storage.db import IntelligenceDB
from storage.models import ScanProgress

DASHBOARD_DIR = Path(__file__).resolve().parent
TEMPLATES_DIR = DASHBOARD_DIR / "templates"
STATIC_DIR = DASHBOARD_DIR / "static"


# ── WebSocket Manager ────────────────────────────────────────────────────────


class ConnectionManager:
    """Manage WebSocket connections for real-time scan updates."""

    def __init__(self) -> None:
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.append(ws)
        logger.debug("WebSocket connected, total: {}", len(self.active))

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.active:
            self.active.remove(ws)
        logger.debug("WebSocket disconnected, total: {}", len(self.active))

    async def broadcast(self, data: dict[str, Any]) -> None:
        dead: list[WebSocket] = []
        for ws in self.active:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


ws_manager = ConnectionManager()


# ── App Factory ──────────────────────────────────────────────────────────────


def create_app(db_path: str | Path | None = None) -> FastAPI:
    """Create the FastAPI dashboard application.

    Args:
        db_path: Path to SQLite database. Uses default if None.

    Returns:
        Configured FastAPI application.
    """
    from config import DB_PATH
    db = IntelligenceDB(db_path or DB_PATH)

    app = FastAPI(
        title="Intelligent Drive Scanner",
        version="2.0.0",
        description="AI-powered file intelligence with 2,632 domain engines",
    )

    # Mount static files
    STATIC_DIR.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

    # ── HTML Routes ──────────────────────────────────────────────────────

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        """Main dashboard page."""
        return templates.TemplateResponse("index.html", {"request": request})

    # ── Scan API ─────────────────────────────────────────────────────────

    @app.post("/api/scan/start")
    async def start_scan(body: dict[str, Any]) -> JSONResponse:
        """Start a new intelligence scan."""
        paths = body.get("paths", [])
        profile = body.get("profile", "INTELLIGENCE")
        if not paths:
            raise HTTPException(400, "paths required")

        # Run scan in background
        from scanner import IntelligenceScanOrchestrator
        config = ScanConfig()
        orchestrator = IntelligenceScanOrchestrator(config)

        def progress_cb(progress: ScanProgress) -> None:
            asyncio.create_task(ws_manager.broadcast(progress.model_dump()))

        orchestrator.add_progress_callback(progress_cb)

        async def run() -> None:
            try:
                await orchestrator.run_scan(paths, profile)
            except Exception as e:
                logger.error("Background scan failed: {}", e)
                await ws_manager.broadcast({"phase": "failed", "error": str(e)})

        asyncio.create_task(run())
        return JSONResponse({"status": "started", "message": "Scan started in background"})

    @app.get("/api/scan/status")
    async def scan_status() -> JSONResponse:
        """Get current scan status."""
        scans = db.list_scans(limit=1)
        if not scans:
            return JSONResponse({"status": "no_scans"})
        scan = scans[0]
        return JSONResponse(scan.model_dump())

    @app.get("/api/scan/{scan_id}/results")
    async def scan_results(scan_id: int) -> JSONResponse:
        """Get scan results summary."""
        summary = db.get_scan_summary(scan_id)
        if not summary:
            raise HTTPException(404, "Scan not found")
        return JSONResponse(summary.model_dump())

    # ── File API ─────────────────────────────────────────────────────────

    @app.get("/api/files")
    async def list_files(
        scan_id: int | None = None,
        domain: str | None = None,
        extension: str | None = None,
        min_score: float | None = None,
        search: str | None = None,
        limit: int = Query(default=100, le=1000),
        offset: int = 0,
    ) -> JSONResponse:
        """List files with optional filters."""
        if search:
            files = db.search_files(search, scan_id=scan_id, limit=limit)
        else:
            files = db.list_files(
                scan_id=scan_id,
                extension=extension,
                limit=limit,
                offset=offset,
            )

        results = []
        for f in files:
            score = db.get_score(f.id or 0)
            results.append({
                "file": f.model_dump(),
                "score": score.model_dump() if score else None,
            })
        return JSONResponse({"files": results, "count": len(results)})

    @app.get("/api/files/{file_id}")
    async def get_file_detail(file_id: int) -> JSONResponse:
        """Get full file detail with classifications and scores."""
        file = db.get_file(file_id)
        if not file:
            raise HTTPException(404, "File not found")

        score = db.get_score(file_id)
        classifications = db.get_classifications(file_id)
        relationships = db.get_file_relationships(file_id)

        return JSONResponse({
            "file": file.model_dump(),
            "score": score.model_dump() if score else None,
            "classifications": [c.model_dump() for c in classifications],
            "relationships": [r.model_dump() for r in relationships],
        })

    # ── Domain API ───────────────────────────────────────────────────────

    @app.get("/api/domains")
    async def list_domains(scan_id: int | None = None) -> JSONResponse:
        """Get domain distribution statistics."""
        sid = scan_id
        if not sid:
            scans = db.list_scans(limit=1)
            if scans:
                sid = scans[0].id or 0
        if not sid:
            return JSONResponse({"domains": []})

        stats = db.get_domain_stats(sid)
        return JSONResponse({
            "domains": [s.model_dump() for s in stats],
            "total_domains": len(stats),
        })

    # ── Duplicate API ────────────────────────────────────────────────────

    @app.get("/api/duplicates")
    async def list_duplicates(scan_id: int | None = None) -> JSONResponse:
        """Get duplicate file clusters."""
        clusters = db.get_duplicate_clusters(scan_id)
        return JSONResponse({
            "clusters": [c.model_dump() for c in clusters],
            "total_clusters": len(clusters),
            "total_wasted_bytes": sum(c.total_wasted_bytes for c in clusters),
        })

    # ── Recommendation API ───────────────────────────────────────────────

    @app.get("/api/recommendations")
    async def list_recommendations(scan_id: int | None = None) -> JSONResponse:
        """Get all recommendations."""
        sid = scan_id
        if not sid:
            scans = db.list_scans(limit=1)
            if scans:
                sid = scans[0].id or 0
        if not sid:
            return JSONResponse({"recommendations": []})

        recs = db.get_recommendations(sid)
        return JSONResponse({
            "recommendations": [r.model_dump() for r in recs],
            "total": len(recs),
        })

    @app.post("/api/recommendations/{rec_id}/execute")
    async def execute_recommendation(rec_id: int) -> JSONResponse:
        """Execute a recommendation (placeholder for auto-exec logic)."""
        db.update_recommendation_status(rec_id, "executed")
        return JSONResponse({"status": "executed", "id": rec_id})

    # ── Score API ────────────────────────────────────────────────────────

    @app.get("/api/scores/distribution")
    async def score_distribution(
        scan_id: int | None = None,
        dimension: str = "overall_score",
    ) -> JSONResponse:
        """Get score distribution histogram."""
        sid = scan_id
        if not sid:
            scans = db.list_scans(limit=1)
            if scans:
                sid = scans[0].id or 0
        if not sid:
            return JSONResponse({"distribution": []})

        dist = db.get_score_distribution(sid, dimension)
        return JSONResponse(dist.model_dump() if dist else {"dimension": dimension, "buckets": []})

    @app.get("/api/scores/top")
    async def top_scores(
        scan_id: int | None = None,
        dimension: str = "overall_score",
        limit: int = 20,
    ) -> JSONResponse:
        """Get top-scoring files."""
        sid = scan_id
        if not sid:
            scans = db.list_scans(limit=1)
            if scans:
                sid = scans[0].id or 0
        if not sid:
            return JSONResponse({"files": []})

        top = db.get_top_scores(sid, dimension=dimension, limit=limit)
        return JSONResponse({"files": [s.model_dump() for s in top]})

    @app.get("/api/scores/risk")
    async def high_risk_files(
        scan_id: int | None = None,
        min_risk: float = 50.0,
    ) -> JSONResponse:
        """Get high-risk files."""
        sid = scan_id
        if not sid:
            scans = db.list_scans(limit=1)
            if scans:
                sid = scans[0].id or 0
        if not sid:
            return JSONResponse({"files": []})

        risk_files = db.get_high_risk_files(sid, min_risk=min_risk)
        return JSONResponse({"files": [s.model_dump() for s in risk_files]})

    # ── Export ───────────────────────────────────────────────────────────

    @app.get("/api/export/report")
    async def export_report(scan_id: int | None = None) -> JSONResponse:
        """Export full intelligence report as JSON."""
        sid = scan_id
        if not sid:
            scans = db.list_scans(limit=1)
            if scans:
                sid = scans[0].id or 0
        if not sid:
            raise HTTPException(404, "No scans found")

        summary = db.get_scan_summary(sid)
        domains = db.get_domain_stats(sid)
        recs = db.get_recommendations(sid)
        risk = db.get_high_risk_files(sid)

        return JSONResponse({
            "report_version": "2.0",
            "scan_summary": summary.model_dump() if summary else None,
            "domain_stats": [d.model_dump() for d in domains],
            "recommendations": [r.model_dump() for r in recs],
            "high_risk_files": [r.model_dump() for r in risk],
        })

    # ── Timeline ─────────────────────────────────────────────────────────

    @app.get("/api/timeline")
    async def timeline() -> JSONResponse:
        """Get scan history for timeline view."""
        scans = db.list_scans(limit=20)
        return JSONResponse({
            "scans": [s.model_dump() for s in scans],
        })

    # ── Health ───────────────────────────────────────────────────────────

    @app.get("/health")
    async def health() -> JSONResponse:
        """Health check."""
        scans = db.list_scans(limit=1)
        return JSONResponse({
            "status": "healthy",
            "version": "2.0.0",
            "db_path": str(db.db_path),
            "total_scans": len(scans),
            "latest_scan": scans[0].model_dump() if scans else None,
        })

    # ── WebSocket ────────────────────────────────────────────────────────

    @app.websocket("/api/ws/scan")
    async def ws_scan_progress(ws: WebSocket) -> None:
        """WebSocket for real-time scan progress updates."""
        await ws_manager.connect(ws)
        try:
            while True:
                # Keep connection alive, receive any client messages
                data = await ws.receive_text()
                if data == "ping":
                    await ws.send_json({"type": "pong"})
        except WebSocketDisconnect:
            ws_manager.disconnect(ws)

    return app
