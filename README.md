# Intelligent Drive Scanner v2.0

![Version](https://img.shields.io/badge/version-2.0.0-blue)
![Python](https://img.shields.io/badge/python-3.11%2B-brightgreen)
![License](https://img.shields.io/badge/license-MIT-green)
![Engines](https://img.shields.io/badge/engines-2%2C632-orange)
![Domains](https://img.shields.io/badge/domains-210-purple)

**AI-powered file intelligence scanner that classifies, scores, deduplicates, and recommends actions for every file on a drive using 2,632 domain-specific engines.**

Intelligent Drive Scanner leverages the Echo Engine Runtime API -- a fleet of 2,632 engines spanning 210 domain categories with 201,975 doctrines -- to build a deep intelligence profile of every file in your filesystem. Rather than treating files as dumb blobs with names and sizes, the scanner understands what each file *is*, how important it is, whether it is duplicated, what it relates to, and what you should do with it. The result is a queryable intelligence database with a real-time dashboard, actionable recommendations, and optional cloud sync to Cloudflare.

---

## Architecture

```
+---------------------------+       +----------------------------+
|        CLI Interface      |       |    FastAPI Dashboard        |
|   (scan, recommend, etc.) |       |  (D3.js sunburst/treemap)  |
+-------------+-------------+       +-------------+--------------+
              |                                    |
              v                                    v
+--------------------------------------------------------------+
|                   Scan Orchestrator (8 phases)                |
|  Discovery -> Sample -> Classify -> Score -> Dedup ->        |
|  Relationships -> Recommend -> Persist                       |
+------+----------+----------+---------+-----------+-----------+
       |          |          |         |           |
       v          v          v         v           v
 +---------+ +--------+ +-------+ +--------+ +----------+
 |Content  | |3-Tier  | |6-Dim  | |3-Level | |Relation  |
 |Sampler  | |Classif.| |Scorer | |Dedup   | |Mapper    |
 +---------+ +--------+ +-------+ +--------+ +----------+
                 |                                  |
                 v                                  v
+-------------------------------+   +-----------------------------+
| Echo Engine Runtime API       |   | Recommendation Engine       |
| 2,632 engines / 210 domains  |   | 10 categories / 6 strategies|
| 201,975 doctrines            |   +-----------------------------+
+-------------------------------+
                 |
                 v
+-------------------------------+   +-----------------------------+
| SQLite Intelligence DB        |   | Cloudflare Worker Companion |
| 9 tables / 17 indexes / WAL  |   | D1 + R2 + KV cloud sync    |
+-------------------------------+   +-----------------------------+
```

---

## Features

### 3-Tier Classification Pipeline

| Tier | Name    | Share | Method                                           |
|------|---------|-------|--------------------------------------------------|
| 1    | Fast    | 90%   | Extension + path heuristics, instant local match  |
| 2    | Explore | 8%    | Cross-domain engine query with content sampling    |
| 3    | Deep    | 2%    | MEMO-mode analysis via AI Orchestrator fallback    |

Files are routed through tiers based on classification confidence. Tier 1 resolves the vast majority of files in under 1ms. Tier 2 sends a content sample to the Engine Runtime API for cross-domain matching. Tier 3 engages deep analysis for ambiguous or high-value files.

### 6-Dimension Intelligence Scoring

Each file receives six independent scores on a 0--100 scale:

| Dimension   | Weight   | Description                                        |
|-------------|----------|----------------------------------------------------|
| Quality     | positive | Content richness, structure, completeness           |
| Importance  | positive | Business relevance, access frequency, location      |
| Sensitivity | positive | PII, credentials, financial data, legal exposure    |
| Staleness   | negative | Time since last access/modification, version drift  |
| Uniqueness  | positive | Inverse of duplication count across the scan        |
| Risk        | negative | Malware indicators, permission anomalies, exposure  |

The composite intelligence score is a weighted sum with configurable weights per scan profile.

### Content-Aware Deduplication

Three levels of duplicate detection, each progressively more tolerant:

- **Exact**: SHA-256 full-file hash. Byte-identical duplicates.
- **Near**: Normalized text hash (whitespace, case, encoding normalization). Catches reformatted copies.
- **Semantic**: Classification overlap + keyword intersection scoring. Detects files covering the same topic in different formats.

### Keeper Selection Strategies

When duplicates are found, the scanner recommends which copy to keep based on a configurable strategy:

- `keep_newest` -- most recently modified
- `keep_largest` -- largest file size (most complete)
- `keep_shallowest` -- shallowest directory depth (most accessible)
- `keep_most_accessed` -- highest access count
- `keep_highest_quality` -- highest quality score from the intelligence model
- `keep_in_domain_folder` -- file located in the most contextually appropriate directory

### Relationship Mapping

Five relationship types are detected across files:

| Type           | Detection Method                                 |
|----------------|--------------------------------------------------|
| duplicates     | SHA-256 or near-hash match                       |
| versioned      | Same base name with version suffix or timestamp  |
| references     | Filename or path substring match in file content |
| depends_on     | Import/include/require statement parsing         |
| co_classified  | Same engine domain classification                |

### Recommendation Engine

Ten recommendation categories, each with a severity level and human-readable rationale:

`archive` | `delete` | `secure` | `backup` | `deduplicate` | `organize` | `review` | `alert` | `encrypt` | `update`

Recommendations are generated from a rule engine that combines classification, scoring, deduplication, and relationship data. High-sensitivity files with no encryption trigger `encrypt`. Stale files with low importance trigger `archive`. Exact duplicates trigger `deduplicate` with a keeper selection.

---

## Installation

**Prerequisites**: Python 3.11+ (via `H:\Tools\PyManager\pythons\py311\python.exe` or any compatible installation).

```bash
cd O:\ECHO_OMEGA_PRIME\SYSTEMS\intelligent-drive-scanner
pip install -r requirements.txt
```

Dependencies:

- `fastapi` + `uvicorn` -- dashboard server
- `aiohttp` -- async HTTP client for Engine Runtime API
- `pydantic` -- data models and validation
- `loguru` -- structured logging
- `jinja2` -- dashboard template rendering
- `aiofiles` -- async file operations
- `xxhash` -- fast hashing for near-duplicate detection

---

## Configuration

All configuration lives in `config.py`. Three built-in scan profiles are provided:

### Scan Profiles

| Profile        | Description                                                |
|----------------|------------------------------------------------------------|
| `QUICK`        | Extension-only classification, no API calls, no dedup      |
| `STANDARD`     | Tier 1 + Tier 2 classification, exact dedup, basic scoring |
| `INTELLIGENCE` | All 3 tiers, all 3 dedup levels, full scoring, cloud sync |

### Scoring Weights (default)

```python
SCORING_WEIGHTS = {
    "quality":    0.25,
    "importance": 0.25,
    "sensitivity":0.20,
    "staleness":  -0.10,
    "uniqueness": 0.15,
    "risk":       -0.05,
}
```

### Key Thresholds

| Parameter                  | Default | Description                              |
|----------------------------|---------|------------------------------------------|
| `TIER2_CONFIDENCE_FLOOR`   | 0.60    | Minimum Tier 1 confidence to skip Tier 2 |
| `TIER3_CONFIDENCE_FLOOR`   | 0.40    | Minimum Tier 2 confidence to skip Tier 3 |
| `NEAR_HASH_THRESHOLD`      | 0.95    | Similarity ratio for near-duplicate match |
| `SEMANTIC_OVERLAP_MIN`     | 0.70    | Keyword overlap for semantic dedup        |
| `API_RATE_LIMIT`           | 500     | Max Engine Runtime API requests per minute|
| `API_CIRCUIT_BREAKER`      | 10      | Consecutive failures before circuit opens |
| `CONTENT_SAMPLE_BYTES`     | 8192    | Bytes read from each file for sampling    |
| `MAX_FILE_SIZE_MB`         | 500     | Skip files larger than this               |

### Engine Runtime API

The scanner connects to the Echo Engine Runtime API at:

```
https://echo-engine-runtime.bmcii1976.workers.dev
```

This endpoint serves 2,632 engines across 210 domain categories with 201,975 doctrines. The async client uses connection pooling (20 connections), an LRU cache (10,000 entries), and a circuit breaker pattern to handle transient failures gracefully.

---

## CLI Usage

The CLI is the primary interface. All subcommands:

### scan

Run a scan on one or more root paths.

```bash
python cli.py scan O:\ I:\ --profile INTELLIGENCE --upload
python cli.py scan C:\Users\bobmc --profile QUICK
python cli.py scan D:\Projects --profile STANDARD --exclude "node_modules,.git,__pycache__"
```

| Flag         | Description                                      |
|--------------|--------------------------------------------------|
| `--profile`  | Scan profile: QUICK, STANDARD, INTELLIGENCE      |
| `--upload`   | Sync results to Cloudflare Worker after scan      |
| `--exclude`  | Comma-separated directory names to skip           |
| `--max-files`| Cap the number of files processed                 |

### recommendations

View actionable recommendations from a completed scan.

```bash
python cli.py recommendations --scan-id 1 --severity high
python cli.py recommendations --scan-id 1 --category deduplicate
```

### summary

Print a scan summary with classification distribution and scoring statistics.

```bash
python cli.py summary --scan-id 1
```

### list-scans

List all completed scans in the intelligence database.

```bash
python cli.py list-scans
```

### dashboard

Launch the FastAPI dashboard with real-time visualizations.

```bash
python cli.py dashboard --port 8460
```

### export

Export scan results to JSON or CSV.

```bash
python cli.py export --scan-id 1 --format json --output report.json
python cli.py export --scan-id 1 --format csv --output report.csv
```

---

## Dashboard

The dashboard is a FastAPI application serving a single-page interface at `http://localhost:8460`. It uses D3.js for interactive visualizations and WebSocket connections for real-time scan progress updates.

### Visualizations

- **Sunburst Chart**: Hierarchical view of file classifications by domain and subdomain. Click to drill into any segment.
- **Treemap**: Space-proportional view of disk usage by classification category.
- **Score Distribution**: Histogram of composite intelligence scores across all scanned files.
- **Recommendation Summary**: Bar chart of recommendation counts by category and severity.
- **Scan Timeline**: Progress indicator with phase completion and throughput metrics during active scans.

### Theme

The dashboard uses the Sovereign dark theme: `#0a0a0f` background, `#00d4ff` accent, `#e2e8f0` text.

---

## Dashboard API Reference

All endpoints are served by the FastAPI instance on the configured port.

| Method | Endpoint                          | Description                              |
|--------|-----------------------------------|------------------------------------------|
| GET    | `/`                               | Dashboard HTML page                      |
| GET    | `/api/scans`                      | List all scans                           |
| GET    | `/api/scans/{scan_id}`            | Scan details and metadata                |
| GET    | `/api/scans/{scan_id}/files`      | Paginated file list with scores          |
| GET    | `/api/scans/{scan_id}/classifications` | Classification distribution         |
| GET    | `/api/scans/{scan_id}/duplicates` | Duplicate groups with keeper selections  |
| GET    | `/api/scans/{scan_id}/recommendations` | Recommendations with severity filter|
| GET    | `/api/scans/{scan_id}/relationships` | File relationship graph data          |
| GET    | `/api/scans/{scan_id}/scores`     | Score statistics and distribution        |
| GET    | `/api/scans/{scan_id}/export`     | Full export (JSON)                       |
| WS     | `/ws/scan-progress`              | Real-time scan progress updates          |
| GET    | `/health`                         | Health check                             |

---

## Cloud Integration

The `WORKERS/echo-drive-intelligence/` directory contains a Cloudflare Worker companion that receives scan results and stores them in the cloud for cross-machine access and historical analysis.

### Worker Resources

| Resource | Type | Purpose                                  |
|----------|------|------------------------------------------|
| D1       | SQL  | Scan metadata, file records, recommendations |
| R2       | Blob | Full scan exports, large file samples    |
| KV       | K/V  | Scan status cache, dashboard config      |

### Upload Flow

When `--upload` is passed to the `scan` command:

1. Scan completes locally and persists to SQLite.
2. Results are serialized and POST'd to the Worker `/ingest` endpoint.
3. The Worker writes structured data to D1 and stores the full export in R2.
4. A KV entry is updated with the latest scan timestamp and summary.

### Worker Endpoints

| Method | Endpoint         | Description                     |
|--------|------------------|---------------------------------|
| POST   | `/ingest`        | Receive and store scan results  |
| GET    | `/scans`         | List cloud-synced scans         |
| GET    | `/scans/:id`     | Retrieve a specific scan        |
| GET    | `/compare`       | Compare two scans for drift     |
| GET    | `/health`        | Worker health check             |

---

## Testing

Tests are located in the `tests/` directory and use pytest.

```bash
pytest tests/ -v
```

| Test File                    | Coverage Area                          |
|------------------------------|----------------------------------------|
| `test_models.py`             | Pydantic model validation and defaults |
| `test_scorer.py`             | 6-dimension scoring with edge cases    |
| `test_deduplicator.py`       | All 3 dedup levels and keeper logic    |
| `test_relationship_mapper.py`| Relationship type detection            |
| `test_recommender.py`        | Recommendation rule triggers           |

---

## Tech Stack

| Component              | Technology                                       |
|------------------------|--------------------------------------------------|
| Language               | Python 3.11+                                     |
| Async HTTP             | aiohttp with connection pooling                  |
| Web Framework          | FastAPI + Uvicorn                                |
| Data Models            | Pydantic v2                                      |
| Database               | SQLite (WAL mode) with 9 tables, 17 indexes      |
| Hashing                | hashlib (SHA-256) + xxhash (near-duplicate)      |
| Visualization          | D3.js (sunburst, treemap, histograms)            |
| Real-Time Updates      | WebSocket via FastAPI                            |
| Logging                | Loguru (structured, rotated)                     |
| Cloud Sync             | Cloudflare Worker (D1 + R2 + KV)                 |
| AI Backend             | Echo Engine Runtime API (2,632 engines)          |
| Templates              | Jinja2                                           |
| Testing                | pytest                                           |

---

## Performance

| Metric                     | Target            | Notes                                    |
|----------------------------|-------------------|------------------------------------------|
| File discovery             | 10,000 files/min  | Async directory walk, parallel stat calls |
| Classification throughput  | 500 files/min     | Rate-limited by Engine Runtime API        |
| Per-file scoring           | < 200ms           | Local computation, no network calls       |
| Max files per scan         | 100K+             | Tested with 500K files under 1GB memory   |
| Memory ceiling (500K files)| < 1 GB            | Streaming processing, batch persistence   |
| SQLite write throughput    | 5,000 inserts/sec | WAL mode, batch commits every 500 records |
| Dashboard load time        | < 2 seconds       | Pre-aggregated statistics, lazy D3 render |

The scanner processes files in streaming batches to maintain constant memory usage regardless of scan size. Classification results are persisted to SQLite as they arrive rather than held in memory.

---

## File Structure

```
intelligent-drive-scanner/
├── scanner.py                          # 8-phase scan orchestrator
├── cli.py                              # CLI: scan, recommendations, summary,
│                                       #       list-scans, dashboard, export
├── config.py                           # Profiles, weights, thresholds, paths
├── requirements.txt                    # Python dependencies
├── intelligence/
│   ├── classifier.py                   # 3-tier classification pipeline
│   ├── scorer.py                       # 6-dimension intelligence scoring
│   ├── content_sampler.py              # File content sampling + hashing
│   ├── engine_client.py                # Async Engine Runtime API client
│   ├── relationship_mapper.py          # Cross-file relationship detection
│   ├── recommender.py                  # 10-category recommendation engine
│   └── deduplicator.py                 # 3-level content-aware deduplication
├── storage/
│   ├── models.py                       # Pydantic data models
│   └── db.py                           # SQLite with 9 tables, 17 indexes
├── dashboard/
│   ├── server.py                       # FastAPI dashboard server
│   ├── templates/
│   │   └── index.html                  # D3.js interactive visualizations
│   └── static/
│       ├── dashboard.css               # Sovereign dark theme
│       └── dashboard.js                # D3.js charts + WebSocket client
├── tests/
│   ├── test_models.py                  # Model validation tests
│   ├── test_scorer.py                  # Scoring logic tests
│   ├── test_deduplicator.py            # Deduplication tests
│   ├── test_relationship_mapper.py     # Relationship detection tests
│   └── test_recommender.py             # Recommendation rule tests
└── WORKERS/
    └── echo-drive-intelligence/        # Cloudflare Worker companion
        ├── wrangler.toml               # Worker configuration
        └── src/
            └── index.ts                # D1/R2/KV cloud sync endpoints
```

---

## License

MIT License. Copyright (c) 2026 Echo Prime Technologies.
