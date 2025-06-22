"""
Test configuration and fixtures for OmicsOracle tests.
"""

import pytest
import os
import tempfile
from pathlib import Path


@pytest.fixture
def temp_dir():
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_data_dir():
    """Path to sample data directory."""
    return Path(__file__).parent / "data"


@pytest.fixture
def mock_geo_response():
    """Mock GEO API response."""
    return {
        "accession": "GSE12345",
        "title": "Test Dataset",
        "summary": "This is a test genomics dataset",
        "organism": "Homo sapiens",
        "samples": 24,
        "platform": "GPL1234"
    }


@pytest.fixture
def sample_fasta_content():
    """Sample FASTA content for testing."""
    return """>seq1
ATCGATCGATCGATCG
>seq2
GCTAGCTAGCTAGCTA
>seq3
TTTTAAAACCCCGGGG
"""


@pytest.fixture
def sample_metadata():
    """Sample metadata for testing."""
    return {
        "dataset_id": "TEST001",
        "title": "Sample Genomics Dataset",
        "description": "A sample dataset for testing purposes",
        "organism": "Homo sapiens",
        "tissue": "brain",
        "condition": "control",
        "replicate_count": 3,
        "platform": "Illumina HiSeq",
        "date_created": "2024-01-01"
    }
