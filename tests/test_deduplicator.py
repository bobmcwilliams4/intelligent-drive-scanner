"""Tests for deduplication module."""

from intelligence.deduplicator import (
    Deduplicator,
    extract_keywords,
    keyword_overlap,
    normalize_text,
    normalized_hash,
)
from storage.models import FileRecord


def test_normalize_text():
    """Text normalization should strip formatting."""
    assert normalize_text("  Hello,  WORLD!  ") == "hello world"
    assert normalize_text("No.Punctuation?Here!") == "no punctuation here"
    assert normalize_text("CAPS  and   spaces") == "caps and spaces"


def test_normalized_hash_same():
    """Same content with different formatting should have same hash."""
    h1 = normalized_hash("Hello, World!")
    h2 = normalized_hash("hello world")
    assert h1 == h2


def test_normalized_hash_different():
    """Different content should have different hashes."""
    h1 = normalized_hash("Hello World")
    h2 = normalized_hash("Goodbye World")
    assert h1 != h2


def test_extract_keywords():
    """Keyword extraction should return unique words."""
    kw = extract_keywords("the quick brown fox jumps over the lazy dog")
    assert "quick" in kw
    assert "brown" in kw
    assert "fox" in kw
    assert "the" in kw
    # Short words excluded
    assert "to" not in extract_keywords("go to the store")


def test_keyword_overlap_identical():
    """Identical keyword sets should have overlap 1.0."""
    a = {"hello", "world"}
    b = {"hello", "world"}
    assert keyword_overlap(a, b) == 1.0


def test_keyword_overlap_none():
    """Disjoint keyword sets should have overlap 0.0."""
    a = {"hello", "world"}
    b = {"foo", "bar"}
    assert keyword_overlap(a, b) == 0.0


def test_keyword_overlap_partial():
    """Partial overlap should be between 0 and 1."""
    a = {"hello", "world", "foo"}
    b = {"hello", "world", "bar"}
    overlap = keyword_overlap(a, b)
    assert 0 < overlap < 1
    assert abs(overlap - 0.5) < 0.01  # 2/4 = 0.5


def test_keyword_overlap_empty():
    """Empty sets should return 0."""
    assert keyword_overlap(set(), {"hello"}) == 0.0
    assert keyword_overlap(set(), set()) == 0.0


def _make_file(id: int, sha256: str = "", content: str = "", **kwargs) -> FileRecord:
    defaults = {
        "id": id,
        "path": f"O:\\test\\file_{id}.txt",
        "filename": f"file_{id}.txt",
        "size_bytes": 1024,
        "modified_at": "2026-02-27T00:00:00Z",
        "accessed_at": "2026-02-27T00:00:00Z",
        "depth": 3,
    }
    defaults.update(kwargs)
    return FileRecord(
        sha256=sha256 or None,
        content_sample=content or None,
        **defaults,
    )


def test_exact_duplicates():
    """Files with same SHA-256 should be detected as exact duplicates."""
    files = [
        _make_file(1, sha256="abc123", content="same content"),
        _make_file(2, sha256="abc123", content="same content"),
        _make_file(3, sha256="def456", content="different content"),
    ]
    dedup = Deduplicator(near_dup_enabled=False, semantic_dup_enabled=False)
    clusters = dedup.find_duplicates(files)
    assert len(clusters) == 1
    assert clusters[0].file_count == 2
    assert dedup.stats["exact_clusters"] == 1


def test_no_duplicates():
    """Unique files should produce no clusters."""
    files = [
        _make_file(1, sha256="abc"),
        _make_file(2, sha256="def"),
        _make_file(3, sha256="ghi"),
    ]
    dedup = Deduplicator(near_dup_enabled=False, semantic_dup_enabled=False)
    clusters = dedup.find_duplicates(files)
    assert len(clusters) == 0


def test_keeper_selection():
    """Keeper should be selected by strategy (newest by default fallback)."""
    files = [
        _make_file(1, sha256="abc", modified_at="2025-01-01T00:00:00Z"),
        _make_file(2, sha256="abc", modified_at="2026-02-27T00:00:00Z"),
    ]
    dedup = Deduplicator(strategy="keep_newest", near_dup_enabled=False, semantic_dup_enabled=False)
    clusters = dedup.find_duplicates(files)
    assert len(clusters) == 1
    assert clusters[0].best_file_id == 2  # Newer file
