"""Intelligent Drive Scanner v2.0 — Configuration & Constants."""

from __future__ import annotations

from pathlib import Path

from pydantic import BaseModel, Field

# ── Paths ────────────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent
DB_PATH = PROJECT_ROOT / "intelligence.db"
LOG_DIR = PROJECT_ROOT / "logs"
LOG_DIR.mkdir(exist_ok=True)

EXISTING_SCANNER = Path(r"O:\ECHO_OMEGA_PRIME\CORE\system_scanner.py")

# ── Cloud Endpoints ──────────────────────────────────────────────────────────

ENGINE_RUNTIME_URL = "https://echo-engine-runtime.bmcii1976.workers.dev"
SHARED_BRAIN_URL = "https://echo-shared-brain.bmcii1976.workers.dev"
GRAPH_RAG_URL = "https://echo-graph-rag.bmcii1976.workers.dev"
KNOWLEDGE_FORGE_URL = "https://echo-knowledge-forge.bmcii1976.workers.dev"
AI_ORCHESTRATOR_URL = "https://echo-ai-orchestrator.bmcii1976.workers.dev"
DRIVE_INTELLIGENCE_URL = "https://echo-drive-intelligence.bmcii1976.workers.dev"

# ── Engine Runtime API ───────────────────────────────────────────────────────

RUNTIME_ENDPOINTS = {
    "engine_query": "/engine/{engine_id}/query",
    "domain_query": "/domain/{domain}/query",
    "cross_domain": "/cross-domain/query",
    "search": "/search",
    "domains": "/domains",
    "health": "/health",
    "stats": "/stats",
}

MAX_CONCURRENT_REQUESTS = 20
MAX_REQUESTS_PER_MINUTE = 500
CACHE_TTL_SECONDS = 3600
REQUEST_TIMEOUT_SECONDS = 10
MAX_RETRIES = 3
RETRY_BACKOFF_BASE = 0.5

# ── Content Sampling ─────────────────────────────────────────────────────────

SAMPLE_SIZE = 2048
SIGNATURE_SIZE = 16
KEYWORD_LIMIT = 50

# ── Classification ───────────────────────────────────────────────────────────

BATCH_SIZE = 100
CONCURRENT_BATCHES = 5
TIER1_CONCURRENCY = 20
TIER2_CONCURRENCY = 10
TIER3_CONCURRENCY = 3
TIER2_CONFIDENCE_THRESHOLD = 0.5
TIER3_SIZE_THRESHOLD = 51200  # 50KB

# ── Scoring Weights ──────────────────────────────────────────────────────────

QUALITY_WEIGHTS = {
    "content_length": 0.15,
    "keyword_density": 0.15,
    "structure_score": 0.15,
    "engine_match_count": 0.20,
    "engine_match_score": 0.20,
    "completeness": 0.15,
}

IMPORTANCE_WEIGHTS = {
    "domain_criticality": 0.25,
    "authority_weight": 0.20,
    "access_recency": 0.15,
    "reference_count": 0.15,
    "uniqueness": 0.15,
    "path_depth": 0.10,
}

OVERALL_WEIGHTS = {
    "quality": 0.20,
    "importance": 0.25,
    "sensitivity": 0.15,
    "staleness": -0.10,
    "uniqueness": 0.15,
    "risk": -0.15,
}

DOMAIN_CRITICALITY = {
    "CYBER": 90,
    "FIN": 85,
    "LG": 80,
    "TAX": 80,
    "MED": 85,
    "CRYPTO": 70,
    "FOREN": 75,
    "LM": 70,
    "DRL": 65,
    "FRAC": 65,
    "PROD": 60,
    "OFE": 55,
    "ENV": 65,
    "NUC": 90,
    "AERO": 75,
    "MARINE": 60,
    "EE": 55,
    "MECH": 50,
    "CONST": 50,
    "AUTO": 50,
    "CHEM": 60,
    "INS": 60,
    "RE": 55,
    "ACCT": 70,
    "FOOD": 40,
    "PROG": 45,
}

DOMAIN_SENSITIVITY = {
    "MED": 40,
    "FIN": 35,
    "TAX": 35,
    "LG": 30,
    "CYBER": 25,
    "CRYPTO": 30,
    "FOREN": 25,
    "INS": 20,
}

# ── Deduplication ────────────────────────────────────────────────────────────

DEFAULT_KEEPER_STRATEGY = "keep_highest_quality"
FALLBACK_KEEPER_STRATEGIES = ["keep_newest", "keep_shallowest"]

# ── Dashboard ────────────────────────────────────────────────────────────────

DASHBOARD_HOST = "127.0.0.1"
DASHBOARD_PORT = 8460

# ── Scan Profiles ────────────────────────────────────────────────────────────

SCAN_PROFILES = {
    "INTELLIGENCE": {
        "intelligence": True,
        "tier1": True,
        "tier2": True,
        "tier3": True,
        "dedup": True,
        "relationships": True,
        "recommendations": True,
    },
    "INTEL_FAST": {
        "intelligence": True,
        "tier1": True,
        "tier2": False,
        "tier3": False,
        "dedup": True,
        "relationships": False,
        "recommendations": True,
    },
    "INTEL_SECURITY": {
        "intelligence": True,
        "tier1": True,
        "tier2": True,
        "tier3": True,
        "dedup": False,
        "relationships": False,
        "recommendations": True,
        "domains": ["CYBER", "FOREN"],
    },
    "INTEL_COMPLIANCE": {
        "intelligence": True,
        "tier1": True,
        "tier2": True,
        "tier3": True,
        "dedup": False,
        "relationships": True,
        "recommendations": True,
        "domains": ["FIN", "LG", "MED", "TAX", "ACCT", "INS"],
    },
    "INTEL_OILFIELD": {
        "intelligence": True,
        "tier1": True,
        "tier2": True,
        "tier3": True,
        "dedup": False,
        "relationships": True,
        "recommendations": True,
        "domains": ["DRL", "FRAC", "PROD", "OFE", "LM", "ENV"],
    },
    "DEDUP": {
        "intelligence": False,
        "tier1": False,
        "tier2": False,
        "tier3": False,
        "dedup": True,
        "relationships": False,
        "recommendations": True,
    },
}

# ── File Signatures (Magic Bytes) ────────────────────────────────────────────

FILE_SIGNATURES: dict[bytes, str] = {
    b"\x25\x50\x44\x46": "application/pdf",
    b"\x50\x4b\x03\x04": "application/zip",
    b"\xd0\xcf\x11\xe0": "application/msword",
    b"\x89\x50\x4e\x47": "image/png",
    b"\xff\xd8\xff": "image/jpeg",
    b"\x7f\x45\x4c\x46": "application/x-elf",
    b"\x4d\x5a": "application/x-dosexec",
    b"\x53\x51\x4c\x69": "application/x-sqlite3",
    b"\x47\x49\x46\x38": "image/gif",
    b"\x42\x4d": "image/bmp",
    b"\x52\x49\x46\x46": "audio/wav",
    b"\x49\x44\x33": "audio/mpeg",
    b"\xff\xfb": "audio/mpeg",
    b"\x1a\x45\xdf\xa3": "video/webm",
    b"\x00\x00\x00\x1c\x66\x74\x79\x70": "video/mp4",
    b"\x00\x00\x01\xba": "video/mpeg",
    b"\x00\x00\x01\xb3": "video/mpeg",
    b"\x1f\x8b": "application/gzip",
    b"\x42\x5a\x68": "application/x-bzip2",
    b"\xfd\x37\x7a\x58\x5a\x00": "application/x-xz",
    b"\x37\x7a\xbc\xaf\x27\x1c": "application/x-7z-compressed",
    b"\x52\x61\x72\x21": "application/x-rar",
    b"\x4f\x67\x67\x53": "audio/ogg",
    b"\x66\x4c\x61\x43": "audio/flac",
    b"\x7b": "application/json",
    b"\xef\xbb\xbf": "text/plain",
    b"\xff\xfe": "text/plain",
    b"\xfe\xff": "text/plain",
}

# ── MIME to Extension Mapping ────────────────────────────────────────────────

EXTENSION_MIME: dict[str, str] = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".log": "text/plain",
    ".csv": "text/csv",
    ".json": "application/json",
    ".xml": "application/xml",
    ".html": "text/html",
    ".htm": "text/html",
    ".css": "text/css",
    ".js": "application/javascript",
    ".ts": "application/typescript",
    ".py": "text/x-python",
    ".go": "text/x-go",
    ".rs": "text/x-rust",
    ".java": "text/x-java",
    ".cpp": "text/x-c++",
    ".c": "text/x-c",
    ".h": "text/x-c",
    ".cs": "text/x-csharp",
    ".rb": "text/x-ruby",
    ".php": "text/x-php",
    ".sh": "text/x-shellscript",
    ".ps1": "text/x-powershell",
    ".bat": "text/x-batch",
    ".cmd": "text/x-batch",
    ".sql": "text/x-sql",
    ".yaml": "text/yaml",
    ".yml": "text/yaml",
    ".toml": "text/toml",
    ".ini": "text/plain",
    ".cfg": "text/plain",
    ".env": "text/plain",
    ".pdf": "application/pdf",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ".ppt": "application/vnd.ms-powerpoint",
    ".pptx": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    ".zip": "application/zip",
    ".tar": "application/x-tar",
    ".gz": "application/gzip",
    ".7z": "application/x-7z-compressed",
    ".rar": "application/x-rar",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
    ".bmp": "image/bmp",
    ".svg": "image/svg+xml",
    ".webp": "image/webp",
    ".ico": "image/x-icon",
    ".mp3": "audio/mpeg",
    ".wav": "audio/wav",
    ".flac": "audio/flac",
    ".ogg": "audio/ogg",
    ".mp4": "video/mp4",
    ".avi": "video/x-msvideo",
    ".mkv": "video/x-matroska",
    ".webm": "video/webm",
    ".mov": "video/quicktime",
    ".exe": "application/x-dosexec",
    ".dll": "application/x-dosexec",
    ".so": "application/x-sharedlib",
    ".msi": "application/x-msi",
    ".db": "application/x-sqlite3",
    ".sqlite": "application/x-sqlite3",
    ".sqlite3": "application/x-sqlite3",
    ".sol": "text/x-solidity",
    ".asm": "text/x-asm",
    ".wasm": "application/wasm",
}

TEXT_EXTENSIONS = {
    ".txt", ".md", ".log", ".csv", ".json", ".xml", ".html", ".htm",
    ".css", ".js", ".ts", ".tsx", ".jsx", ".py", ".go", ".rs", ".java",
    ".cpp", ".c", ".h", ".cs", ".rb", ".php", ".sh", ".ps1", ".bat",
    ".cmd", ".sql", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".env",
    ".r", ".m", ".swift", ".kt", ".lua", ".pl", ".pm", ".tcl", ".awk",
    ".sed", ".makefile", ".cmake", ".gradle", ".sbt", ".cabal",
    ".nix", ".tf", ".hcl", ".dockerfile", ".gitignore", ".editorconfig",
    ".eslintrc", ".prettierrc", ".babelrc", ".svg", ".mdx", ".rst",
    ".tex", ".bib", ".properties", ".conf", ".reg", ".vbs",
}

EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".wsf", ".msi",
    ".com", ".scr", ".pif", ".hta", ".cpl", ".jar", ".sh",
}

BINARY_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".tiff",
    ".mp3", ".wav", ".flac", ".ogg", ".aac", ".wma", ".m4a",
    ".mp4", ".avi", ".mkv", ".webm", ".mov", ".wmv", ".flv",
    ".exe", ".dll", ".so", ".msi", ".bin", ".dat", ".iso",
    ".zip", ".tar", ".gz", ".7z", ".rar", ".bz2", ".xz",
    ".db", ".sqlite", ".sqlite3", ".mdb", ".accdb",
    ".psd", ".ai", ".sketch", ".fig",
    ".ttf", ".otf", ".woff", ".woff2", ".eot",
    ".pyc", ".pyo", ".class", ".o", ".obj", ".lib", ".a",
    ".wasm",
}

# ── Domain Auto-Detection Rules ──────────────────────────────────────────────

EXTENSION_DOMAIN: dict[str, str] = {
    ".py": "PROG",
    ".js": "PROG",
    ".ts": "PROG",
    ".tsx": "PROG",
    ".jsx": "PROG",
    ".go": "PROG",
    ".rs": "PROG",
    ".java": "PROG",
    ".cpp": "PROG",
    ".c": "PROG",
    ".cs": "PROG",
    ".rb": "PROG",
    ".php": "PROG",
    ".swift": "PROG",
    ".kt": "PROG",
    ".sol": "CRYPTO",
    ".asm": "CYBER",
}

CONTENT_DOMAIN_RULES: dict[str, dict[str, str]] = {
    ".pdf": {
        r"contract|agreement|clause|indemnif": "LG",
        r"invoice|revenue|balance|ledger|audit": "FIN",
        r"deed|mineral|royalty|lease|convey": "LM",
        r"patient|diagnosis|prescription|HIPAA": "MED",
        r"well|drilling|casing|completion|BOP": "DRL",
        r"fracture|proppant|slurry|perforat": "FRAC",
        "_default": "UNKNOWN",
    },
    ".xlsx": {
        r"revenue|expense|balance|depreciat": "ACCT",
        r"production|BOE|MCF|barrel": "PROD",
        r"premium|claim|loss|reserve|actuari": "INS",
        "_default": "FIN",
    },
    ".xls": {
        r"revenue|expense|balance|depreciat": "ACCT",
        r"production|BOE|MCF|barrel": "PROD",
        "_default": "FIN",
    },
    ".docx": {
        r"contract|agreement|term|condition": "LG",
        r"specification|tolerance|material": "MECH",
        r"recipe|ingredient|HACCP|allergen": "FOOD",
        "_default": "UNKNOWN",
    },
    ".doc": {
        r"contract|agreement|term|condition": "LG",
        r"specification|tolerance|material": "MECH",
        "_default": "UNKNOWN",
    },
}

PATH_DOMAIN_RULES: dict[str, str] = {
    r"tax|irs|1040|w2|1099": "TAX",
    r"legal|law|contract|litigation": "LG",
    r"landman|title|deed|mineral|lease": "LM",
    r"security|cyber|malware|threat|vuln": "CYBER",
    r"finance|accounting|audit|ledger": "FIN",
    r"medical|patient|clinical|pharma": "MED",
    r"drilling|wellbore|BHA|MWD": "DRL",
    r"frac|completion|stimulat|proppant": "FRAC",
    r"production|artificial.lift|ESP|rod.pump": "PROD",
    r"oilfield|equipment|BOP|separator": "OFE",
    r"crypto|blockchain|defi|wallet|token": "CRYPTO",
    r"insurance|actuari|claim|underwrit": "INS",
    r"real.estate|property|apprais|mortgage": "RE",
    r"aerospace|aviation|FAA|airframe": "AERO",
    r"automotive|vehicle|ADAS|OBD": "AUTO",
    r"chemistry|chemical|reaction|catalyst": "CHEM",
    r"nuclear|reactor|neutron|fission": "NUC",
    r"marine|offshore|subsea|vessel": "MARINE",
    r"construction|concrete|steel|ACI": "CONST",
    r"electrical|power|relay|transformer": "EE",
    r"food|HACCP|sanitation|ingredient": "FOOD",
    r"forensic|evidence|crime|investig": "FOREN",
    r"environment|emission|EPA|pollut": "ENV",
}

# ── Sensitivity Patterns ─────────────────────────────────────────────────────

SENSITIVITY_PATTERNS: dict[str, tuple[str, int]] = {
    "ssn": (r"\b\d{3}-\d{2}-\d{4}\b", 90),
    "credit_card": (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", 95),
    "email": (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", 30),
    "phone": (r"\b\d{3}[\s.-]\d{3}[\s.-]\d{4}\b", 25),
    "api_key": (r"\b(?:sk|pk|api|key|token|secret)[_-]?[A-Za-z0-9]{20,}\b", 85),
    "password": (r"(?i)(?:password|passwd|pwd)\s*[:=]\s*\S+", 90),
    "medical_record": (r"(?i)(?:patient|diagnosis|prescription|ICD-10)", 80),
    "financial": (r"(?i)(?:account\s*number|routing\s*number|bank|SWIFT)", 75),
    "legal_privileged": (r"(?i)(?:attorney.client|privileged|confidential|under\s*seal)", 70),
    "classified": (r"(?i)(?:top\s*secret|classified|restricted|FOUO)", 95),
}

# ── Recommendation Thresholds ────────────────────────────────────────────────

REC_ARCHIVE_STALENESS = 80
REC_ARCHIVE_IMPORTANCE = 30
REC_DELETE_STALENESS = 90
REC_DELETE_IMPORTANCE = 10
REC_SECURE_SENSITIVITY = 70
REC_BACKUP_IMPORTANCE = 80
REC_DEDUP_MIN_COPIES = 5
REC_REVIEW_RISK = 70
REC_UPDATE_STALENESS = 50
REC_UPDATE_IMPORTANCE = 60


class ScanConfig(BaseModel):
    """Configuration for a single scan run."""

    drives: list[str] = Field(default_factory=lambda: ["O:"])
    paths: list[str] = Field(default_factory=list)
    profile: str = "INTELLIGENCE"
    domains: list[str] | None = None
    intelligence: bool = True
    dashboard: bool = False
    upload_cloud: bool = False
    max_files: int | None = None
    skip_binary: bool = False
    skip_large_mb: int | None = None
    incremental: bool = True
    deep_analyze_paths: list[str] = Field(default_factory=list)
