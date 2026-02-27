"""Intelligent Drive Scanner v2.0 — Main Scan Orchestrator.

Coordinates the full intelligence scanning pipeline:
  1. File discovery (walk filesystem)
  2. Content sampling (extract samples, hashes, MIME types)
  3. Classification (3-tier engine pipeline)
  4. Scoring (6-dimension intelligence scores)
  5. Relationship mapping (cross-file analysis)
  6. Deduplication (exact, near, semantic)
  7. Recommendations (actionable intelligence)
  8. Cloud sync (upload results to Cloudflare Worker)
  9. Dashboard (optional live analytics)

Usage:
    python scanner.py --profile INTELLIGENCE --drives O: I: F:
    python scanner.py --intelligence --path "O:\\TAX_KNOWLEDGE" --dashboard
"""

from __future__ import annotations

import asyncio
import json
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import aiohttp
from loguru import logger

from config import (
    CLOUD_WORKER_URL,
    DB_PATH,
    LOG_DIR,
    SCAN_PROFILES,
    ScanConfig,
)
from intelligence.classifier import ClassificationPipeline
from intelligence.content_sampler import ContentSampler
from intelligence.deduplicator import Deduplicator
from intelligence.engine_client import EngineRuntimeClient
from intelligence.recommender import RecommendationEngine
from intelligence.relationship_mapper import RelationshipMapper
from intelligence.scorer import IntelligenceScorer
from storage.db import IntelligenceDB
from storage.models import (
    Classification,
    DomainStats,
    FileRecord,
    IntelligenceScore,
    ScanProgress,
    ScanStatus,
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── File Discovery ───────────────────────────────────────────────────────────


def discover_files(
    paths: list[str],
    config: ScanConfig,
) -> list[Path]:
    """Walk filesystem paths and collect file entries.

    Applies extension filtering, size limits, and skip patterns.

    Args:
        paths: List of root paths (drives, folders) to scan.
        config: Scan configuration with filters.

    Returns:
        List of discovered file paths.
    """
    discovered: list[Path] = []
    skip_dirs = {
        ".git", "__pycache__", "node_modules", ".venv", "venv",
        ".hf_cache", ".playwright-mcp", "$Recycle.Bin",
        "System Volume Information", "Windows",
    }

    for root_path_str in paths:
        root_path = Path(root_path_str)
        if not root_path.exists():
            logger.warning("Path does not exist: {}", root_path)
            continue

        logger.info("Discovering files in: {}", root_path)

        if root_path.is_file():
            discovered.append(root_path)
            continue

        for dirpath, dirnames, filenames in os.walk(root_path, topdown=True):
            # Prune skip directories
            dirnames[:] = [
                d for d in dirnames
                if d not in skip_dirs
                and not d.startswith(".")
            ]

            depth = len(Path(dirpath).parts) - len(root_path.parts)
            if config.max_depth and depth > config.max_depth:
                dirnames.clear()
                continue

            for filename in filenames:
                try:
                    filepath = Path(dirpath) / filename
                    # Quick stat to check size
                    try:
                        stat = filepath.stat()
                    except (OSError, PermissionError):
                        continue

                    if stat.st_size == 0:
                        continue
                    if config.max_file_size and stat.st_size > config.max_file_size:
                        continue

                    # Extension filter
                    ext = filepath.suffix.lower()
                    if config.include_extensions and ext not in config.include_extensions:
                        continue
                    if config.exclude_extensions and ext in config.exclude_extensions:
                        continue

                    discovered.append(filepath)
                except Exception as e:
                    logger.debug("Error checking file {}: {}", filename, e)

    logger.info("Discovered {} files across {} paths", len(discovered), len(paths))
    return discovered


def build_file_records(
    file_paths: list[Path],
    scan_id: int,
) -> list[FileRecord]:
    """Convert discovered paths to FileRecord objects with filesystem metadata.

    Args:
        file_paths: Discovered file paths.
        scan_id: Current scan ID.

    Returns:
        List of FileRecord objects.
    """
    records: list[FileRecord] = []

    for fp in file_paths:
        try:
            stat = fp.stat()
            records.append(FileRecord(
                path=str(fp),
                filename=fp.name,
                extension=fp.suffix.lower(),
                size_bytes=stat.st_size,
                created_at=datetime.fromtimestamp(stat.st_ctime, tz=timezone.utc).isoformat(),
                modified_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat(),
                accessed_at=datetime.fromtimestamp(stat.st_atime, tz=timezone.utc).isoformat(),
                drive=fp.drive or str(fp.parts[0]) if fp.parts else "",
                parent_dir=str(fp.parent),
                depth=len(fp.parts),
                scan_id=scan_id,
            ))
        except (OSError, PermissionError) as e:
            logger.debug("Cannot stat {}: {}", fp, e)

    return records


# ── Main Scanner Orchestrator ────────────────────────────────────────────────


class IntelligenceScanOrchestrator:
    """Orchestrates the full intelligence scanning pipeline.

    Coordinates discovery, sampling, classification, scoring, relationships,
    deduplication, and recommendation generation.
    """

    def __init__(self, config: ScanConfig | None = None) -> None:
        self.config = config or ScanConfig()
        self.db = IntelligenceDB(DB_PATH)
        self.sampler = ContentSampler()
        self.scorer = IntelligenceScorer()
        self.mapper = RelationshipMapper()
        self.deduplicator = Deduplicator()
        self.recommender = RecommendationEngine()
        self.progress = ScanProgress(scan_id=0)
        self._progress_callbacks: list[Any] = []

    def add_progress_callback(self, callback: Any) -> None:
        """Register a callback for progress updates (e.g., WebSocket)."""
        self._progress_callbacks.append(callback)

    def _update_progress(self, **kwargs: Any) -> None:
        """Update and broadcast scan progress."""
        for key, value in kwargs.items():
            if hasattr(self.progress, key):
                setattr(self.progress, key, value)
        for cb in self._progress_callbacks:
            try:
                cb(self.progress)
            except Exception:
                pass

    async def run_scan(
        self,
        paths: list[str],
        profile: str = "INTELLIGENCE",
    ) -> int:
        """Execute a full intelligence scan.

        Args:
            paths: Root paths to scan.
            profile: Scan profile name.

        Returns:
            Scan ID.
        """
        start_time = time.time()
        logger.info("Starting intelligence scan: paths={}, profile={}", paths, profile)

        # Initialize database
        self.db.initialize()

        # Create scan record
        scan_id = self.db.create_scan(
            drives=json.dumps(paths),
            profile=profile,
        )
        self.progress.scan_id = scan_id
        self._update_progress(phase="discovering")

        try:
            # Phase 1: Discovery
            logger.info("Phase 1: File Discovery")
            self._update_progress(phase="discovering")
            file_paths = discover_files(paths, self.config)
            self._update_progress(total_files=len(file_paths))

            if not file_paths:
                logger.warning("No files discovered. Completing scan.")
                self.db.complete_scan(scan_id, total_files=0, total_size=0)
                return scan_id

            # Phase 2: Build file records + Content sampling
            logger.info("Phase 2: Building file records & sampling content")
            self._update_progress(phase="sampling")
            file_records = build_file_records(file_paths, scan_id)
            total_size = sum(f.size_bytes for f in file_records)

            # Sample content
            sampled_records = []
            for i, record in enumerate(file_records):
                try:
                    sample = self.sampler.sample_file(Path(record.path))
                    if sample:
                        record.sha256 = sample.sha256
                        record.xxhash = sample.xxhash
                        record.mime_type = sample.mime_type
                        record.content_sample = sample.content_sample
                        record.file_signature = sample.file_signature
                        record.is_binary = 1 if sample.is_binary else 0
                    sampled_records.append(record)
                except Exception as e:
                    logger.debug("Failed to sample {}: {}", record.path, e)
                    sampled_records.append(record)

                if (i + 1) % 1000 == 0:
                    self._update_progress(
                        processed_files=i + 1,
                        current_file=record.filename,
                    )

            # Store in database
            logger.info("Storing {} file records in database", len(sampled_records))
            stored_records = self.db.upsert_files_batch(sampled_records)
            # Update IDs from database
            path_to_id: dict[str, int] = {}
            for rec in stored_records:
                path_to_id[rec.path] = rec.id or 0
            for rec in sampled_records:
                rec.id = path_to_id.get(rec.path, rec.id)

            # Phase 3: Classification
            logger.info("Phase 3: Engine Classification")
            self._update_progress(phase="classifying")

            all_classifications: dict[int, list[Classification]] = {}
            engine_client = EngineRuntimeClient()

            async with aiohttp.ClientSession() as session:
                engine_client._session = session
                pipeline = ClassificationPipeline(engine_client)

                # Build file samples for classification
                from storage.models import FileSample
                samples = []
                for rec in sampled_records:
                    if rec.content_sample or not rec.is_binary:
                        samples.append(FileSample(
                            path=rec.path,
                            filename=rec.filename,
                            extension=rec.extension,
                            size_bytes=rec.size_bytes,
                            mime_type=rec.mime_type or "",
                            file_signature=rec.file_signature or "",
                            content_sample=rec.content_sample,
                            is_binary=bool(rec.is_binary),
                            sha256=rec.sha256 or "",
                            xxhash=rec.xxhash or "",
                        ))

                # Classify in batches
                batch_size = 100
                api_calls = 0
                cache_hits = 0
                for batch_start in range(0, len(samples), batch_size):
                    batch = samples[batch_start:batch_start + batch_size]
                    results = await pipeline.classify_batch_sorted(batch, scan_id)

                    for result in results:
                        file_id = path_to_id.get(result.file_path, 0)
                        if file_id and result.classifications:
                            all_classifications[file_id] = result.classifications
                            self.db.insert_classifications_batch(result.classifications)
                            api_calls += len(result.classifications)

                    classified = batch_start + len(batch)
                    self._update_progress(
                        classified_files=classified,
                        api_calls=api_calls,
                        cache_hits=cache_hits,
                        throughput_files_per_min=(
                            classified / max(1, (time.time() - start_time) / 60)
                        ),
                    )

            # Phase 4: Intelligence Scoring
            logger.info("Phase 4: Intelligence Scoring")
            self._update_progress(phase="scoring")

            scores: dict[int, IntelligenceScore] = {}
            for rec in sampled_records:
                fid = rec.id or 0
                clss = all_classifications.get(fid, [])
                score = self.scorer.score_file(rec, clss, scan_id)
                scores[fid] = score
                self.db.upsert_score(score)

            # Phase 5: Relationship Mapping
            logger.info("Phase 5: Relationship Mapping")
            self._update_progress(phase="mapping_relationships")

            relationships = self.mapper.detect_all(
                sampled_records, all_classifications, scan_id,
            )
            if relationships:
                self.db.insert_relationships_batch(relationships)

            # Phase 6: Deduplication
            logger.info("Phase 6: Deduplication")
            self._update_progress(phase="deduplicating")

            clusters = self.deduplicator.find_duplicates(
                sampled_records, scores, all_classifications,
            )
            for cluster in clusters:
                self.db.insert_duplicate_cluster(cluster)

            # Phase 7: Recommendations
            logger.info("Phase 7: Generating Recommendations")
            self._update_progress(phase="recommending")

            recommendations = self.recommender.generate_all(
                sampled_records, scores, all_classifications,
                relationships, clusters, scan_id,
            )
            if recommendations:
                self.db.insert_recommendations_batch(recommendations)

            # Phase 8: Domain Statistics
            logger.info("Phase 8: Computing Domain Statistics")
            self._update_progress(phase="computing_stats")

            domain_file_counts: dict[str, int] = defaultdict(int)
            domain_size_totals: dict[str, int] = defaultdict(int)
            domain_score_sums: dict[str, float] = defaultdict(float)

            for fid, score in scores.items():
                domain = score.primary_domain or "UNKNOWN"
                domain_file_counts[domain] += 1
                rec = next((r for r in sampled_records if r.id == fid), None)
                if rec:
                    domain_size_totals[domain] += rec.size_bytes
                domain_score_sums[domain] += score.overall_score

            for domain in domain_file_counts:
                count = domain_file_counts[domain]
                avg = domain_score_sums[domain] / max(1, count)
                ds = DomainStats(
                    scan_id=scan_id,
                    domain=domain,
                    file_count=count,
                    total_size_bytes=domain_size_totals[domain],
                    avg_score=round(avg, 1),
                )
                self.db.upsert_domain_stats(ds)

            # Complete scan
            elapsed = time.time() - start_time
            self.db.complete_scan(
                scan_id=scan_id,
                total_files=len(sampled_records),
                total_size=total_size,
                files_classified=len(all_classifications),
                duration=elapsed,
            )

            self._update_progress(
                phase="completed",
                elapsed_seconds=elapsed,
            )

            # Log summary
            logger.info(
                "Scan {} complete: {} files, {} classified, {} relationships, "
                "{} duplicate clusters, {} recommendations, {:.1f}s",
                scan_id,
                len(sampled_records),
                len(all_classifications),
                len(relationships),
                len(clusters),
                len(recommendations),
                elapsed,
            )

            return scan_id

        except Exception as e:
            logger.error("Scan {} failed: {}", scan_id, e)
            self.db.fail_scan(scan_id, str(e))
            raise

    async def upload_to_cloud(self, scan_id: int) -> bool:
        """Upload scan results to cloud worker for cross-machine intelligence.

        Args:
            scan_id: Scan ID to upload.

        Returns:
            True if upload succeeded.
        """
        if not CLOUD_WORKER_URL:
            logger.warning("No cloud worker URL configured, skipping upload")
            return False

        summary = self.db.get_scan_summary(scan_id)
        if not summary:
            logger.error("Scan {} not found", scan_id)
            return False

        logger.info("Uploading scan {} to cloud: {}", scan_id, CLOUD_WORKER_URL)

        # Gather scan data
        files = self.db.list_files(scan_id=scan_id, limit=100000)
        scores_list = self.db.get_top_scores(scan_id, limit=100000)
        recommendations = self.db.get_recommendations(scan_id)
        domain_stats = self.db.get_domain_stats(scan_id)

        payload = {
            "scan_id": scan_id,
            "machine_id": os.environ.get("COMPUTERNAME", "ALPHA"),
            "summary": summary.model_dump(),
            "files_count": len(files),
            "scores_count": len(scores_list),
            "recommendations_count": len(recommendations),
            "domains": [ds.model_dump() for ds in domain_stats],
            "uploaded_at": _now_iso(),
        }

        try:
            async with aiohttp.ClientSession() as session:
                headers = {
                    "Content-Type": "application/json",
                    "X-Echo-API-Key": os.environ.get("ECHO_API_KEY", ""),
                }
                async with session.post(
                    f"{CLOUD_WORKER_URL}/scans",
                    json=payload,
                    headers=headers,
                    timeout=aiohttp.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 200:
                        logger.info("Upload to cloud successful")
                        return True
                    logger.error("Cloud upload failed: {} {}", resp.status, await resp.text())
                    return False
        except Exception as e:
            logger.error("Cloud upload error: {}", e)
            return False

    def get_scan_summary(self, scan_id: int) -> dict[str, Any] | None:
        """Get scan summary for display."""
        summary = self.db.get_scan_summary(scan_id)
        if summary:
            return summary.model_dump()
        return None
