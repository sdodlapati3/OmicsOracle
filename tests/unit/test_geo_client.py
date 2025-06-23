"""
Comprehensive tests for the GEO client.

This module contains tests for:
- GEO client initialization
- GEO ID validation
- Search functionality (mock tests)
- Metadata retrieval (mock tests)
- Batch processing
- Error handling
"""

import os
from unittest.mock import AsyncMock, Mock, patch

import pytest
from dotenv import load_dotenv

from src.omics_oracle.core.config import Config
from src.omics_oracle.core.exceptions import GEOClientError, GEOParseError
from src.omics_oracle.geo_tools.geo_client import UnifiedGEOClient


class TestUnifiedGEOClient:
    """Test cases for the UnifiedGEOClient class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = Config()
        self.client = UnifiedGEOClient(self.config)

    def test_client_initialization(self):
        """Test that the client initializes correctly."""
        assert self.client.config is not None
        assert isinstance(self.client.config, Config)

    def test_client_info(self):
        """Test that client info returns expected structure."""
        info = self.client.get_client_info()

        expected_keys = {
            "entrez_email",
            "entrez_api_key",
            "cache_directory",
            "rate_limit",
            "has_entrez",
            "has_geoparse",
            "has_pysradb",
        }

        assert set(info.keys()) == expected_keys
        assert info["has_entrez"] in ["True", "False"]
        assert info["has_geoparse"] in ["True", "False"]
        assert info["has_pysradb"] in ["True", "False"]

    @pytest.mark.parametrize(
        "geo_id,expected",
        [
            ("GSE123456", True),
            ("gse789", True),
            ("GSE1", True),
            ("GSE999999", True),
            ("ABC123", False),
            ("GSE", False),
            ("123", False),
            ("", False),
            (None, False),
            (123, False),
        ],
    )
    def test_validate_geo_id(self, geo_id, expected):
        """Test GEO ID validation with various inputs."""
        result = self.client.validate_geo_id(geo_id)
        assert result == expected

    @pytest.mark.asyncio
    async def test_search_geo_series_success(self):
        """Test successful GEO series search."""
        # Mock the NCBI client
        mock_ncbi_client = Mock()
        mock_ncbi_client.esearch = AsyncMock(return_value=["123", "456", "789"])
        self.client.ncbi_client = mock_ncbi_client

        # Mock cache to return None (no cached data)
        self.client._get_cached_data = Mock(return_value=None)
        self.client._cache_data = Mock()

        result = await self.client.search_geo_series(
            "test query", max_results=10
        )

        assert result == ["123", "456", "789"]
        mock_ncbi_client.esearch.assert_called_once_with(
            db="gds", term="test query", retmax=10
        )

    @pytest.mark.asyncio
    async def test_search_geo_series_no_ncbi_client(self):
        """Test search when NCBI client is not available."""
        self.client.ncbi_client = None

        with pytest.raises(GEOClientError, match="NCBI client not available"):
            await self.client.search_geo_series("test query")

    @pytest.mark.asyncio
    async def test_search_geo_series_no_results(self):
        """Test search when no results are found."""
        # Mock the NCBI client to return empty results
        mock_ncbi_client = Mock()
        mock_ncbi_client.esearch = AsyncMock(return_value=[])
        self.client.ncbi_client = mock_ncbi_client

        result = await self.client.search_geo_series("nonexistent query")

        assert result == []

    @patch("src.omics_oracle.geo_tools.geo_client.HAS_GEOPARSE", True)
    @patch("src.omics_oracle.geo_tools.geo_client.get_GEO")
    async def test_get_geo_metadata_success(self, mock_get_geo):
        """Test successful metadata retrieval."""
        # Mock GEO object
        mock_gse = Mock()
        mock_gse.metadata = {
            "title": ["Test Dataset"],
            "summary": ["Test summary"],
            "overall_design": ["Test design"],
            "taxon": ["Homo sapiens"],
            "submission_date": ["2023-01-01"],
            "last_update_date": ["2023-01-02"],
            "contact_name": ["Test Contact"],
            "contact_email": ["test@example.com"],
        }
        mock_gse.gpls = {"GPL123": Mock()}
        mock_gse.gsms = {"GSM123": Mock(), "GSM456": Mock()}

        mock_get_geo.return_value = mock_gse

        result = await self.client.get_geo_metadata(
            "GSE123456", include_sra=False
        )

        assert result["geo_id"] == "GSE123456"
        assert result["title"] == "Test Dataset"
        assert result["platform_count"] == 1
        assert result["sample_count"] == 2
        assert "sra_info" not in result or result["sra_info"] is None

    @patch("src.omics_oracle.geo_tools.geo_client.HAS_GEOPARSE", False)
    async def test_get_geo_metadata_no_geoparse(self):
        """Test metadata retrieval when GEOparse is not available."""
        with pytest.raises(GEOClientError, match="GEOparse not available"):
            await self.client.get_geo_metadata("GSE123456")

    async def test_batch_retrieve_metadata_success(self):
        """Test batch metadata retrieval."""
        # Mock the get_geo_metadata method
        self.client.get_geo_metadata = AsyncMock()
        self.client.get_geo_metadata.side_effect = [
            {"geo_id": "GSE1", "title": "Dataset 1"},
            {"geo_id": "GSE2", "title": "Dataset 2"},
        ]

        geo_ids = ["GSE1", "GSE2"]
        result = await self.client.batch_retrieve_metadata(
            geo_ids, max_concurrent=2
        )

        assert len(result) == 2
        assert result["GSE1"]["title"] == "Dataset 1"
        assert result["GSE2"]["title"] == "Dataset 2"

    async def test_batch_retrieve_metadata_with_errors(self):
        """Test batch retrieval handling partial failures."""
        # Mock the get_geo_metadata method with one failure
        self.client.get_geo_metadata = AsyncMock()
        self.client.get_geo_metadata.side_effect = [
            {"geo_id": "GSE1", "title": "Dataset 1"},
            GEOParseError("Failed to parse GSE2"),
        ]

        geo_ids = ["GSE1", "GSE2"]
        result = await self.client.batch_retrieve_metadata(
            geo_ids, max_concurrent=2
        )

        assert len(result) == 2
        assert result["GSE1"]["title"] == "Dataset 1"
        assert "error" in result["GSE2"]


@pytest.mark.integration
class TestGEOClientIntegration:
    """Integration tests requiring actual API access."""

    def setup_method(self):
        """Set up test fixtures."""
        # Load environment variables from .env file
        load_dotenv()

        # Create config with environment variables loaded
        self.config = Config()

        # Override config with environment variables if available
        if os.getenv("NCBI_EMAIL"):
            self.config.ncbi.email = os.getenv("NCBI_EMAIL")
        if os.getenv("NCBI_API_KEY"):
            self.config.ncbi.api_key = os.getenv("NCBI_API_KEY")

        # Only run if we have NCBI credentials
        if not self.config.ncbi.email:
            pytest.skip("NCBI email not configured")

        self.client = UnifiedGEOClient(self.config)

    @pytest.mark.asyncio
    async def test_real_geo_search(self):
        """Test actual GEO search with real API (requires NCBI config)."""
        try:
            results = await self.client.search_geo_series(
                "breast cancer[Title/Abstract] AND gse[Entry Type]",
                max_results=5,
            )

            # Should get some results for this common query
            assert isinstance(results, list)
            assert len(results) <= 5

            # Each result should be a string ID
            for result in results:
                assert isinstance(result, str)
                assert result.isdigit()

        except GEOClientError as e:
            pytest.skip(f"API test skipped due to: {e}")

    @pytest.mark.asyncio
    async def test_real_metadata_retrieval(self):
        """Test actual metadata retrieval (requires working API)."""
        try:
            # Use a well-known, stable GEO series
            metadata = await self.client.get_geo_metadata(
                "GSE2034", include_sra=False
            )

            assert metadata["geo_id"] == "GSE2034"
            assert "title" in metadata
            assert "summary" in metadata
            assert isinstance(metadata["platform_count"], int)
            assert isinstance(metadata["sample_count"], int)

        except GEOClientError as e:
            pytest.skip(f"API test skipped due to: {e}")


if __name__ == "__main__":
    # Run basic tests
    pytest.main([__file__, "-v"])
