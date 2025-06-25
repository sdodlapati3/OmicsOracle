"""
Export service for OmicsOracle modern interface
Handles data export operations in various formats
"""

import csv
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.exceptions import ExportException, ValidationException
from core.logging_config import get_service_logger
from models import ExportRequest, ExportResponse, SearchResult


class ExportService:
    """Service for handling data export operations"""

    def __init__(self, exports_dir: Path):
        """
        Initialize export service

        Args:
            exports_dir: Directory for export files
        """
        self.exports_dir = exports_dir
        self.logger = get_service_logger()
        self.exports_dir.mkdir(exist_ok=True)

        # Supported export formats
        self.supported_formats = ["csv", "json", "tsv"]

        # Default field mappings for CSV export
        self.default_csv_fields = [
            "id",
            "title",
            "abstract",
            "authors",
            "journal",
            "doi",
            "pmid",
            "url",
            "relevance_score",
        ]

    def export_search_results(
        self, results: List[SearchResult], export_request: ExportRequest
    ) -> ExportResponse:
        """
        Export search results to specified format

        Args:
            results: List of search results to export
            export_request: Export parameters

        Returns:
            ExportResponse with download information

        Raises:
            ExportException: If export operation fails
            ValidationException: If export parameters are invalid
        """
        try:
            self.logger.info(
                f"Starting export: {len(results)} results to {export_request.format}"
            )

            # Validate export request
            self._validate_export_request(export_request)

            # Generate filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = (
                f"omics_oracle_export_{timestamp}.{export_request.format}"
            )
            file_path = self.exports_dir / filename

            # Export based on format
            if export_request.format == "csv":
                self._export_csv(results, file_path, export_request)
            elif export_request.format == "tsv":
                self._export_tsv(results, file_path, export_request)
            elif export_request.format == "json":
                self._export_json(results, file_path, export_request)
            else:
                raise ExportException(
                    f"Unsupported export format: {export_request.format}"
                )

            # Create download URL (this would need to be configured based on server setup)
            download_url = f"/api/v1/exports/download/{filename}"

            # Calculate expiration (24 hours from now)
            expires_at = datetime.now() + timedelta(hours=24)

            export_response = ExportResponse(
                download_url=download_url,
                filename=filename,
                format=export_request.format,
                total_records=len(results),
                created_at=datetime.now(),
                expires_at=expires_at,
            )

            self.logger.info(
                f"Export completed: {filename} ({len(results)} records)"
            )
            return export_response

        except Exception as e:
            self.logger.error(f"Export failed: {str(e)}", exc_info=True)
            if isinstance(e, (ExportException, ValidationException)):
                raise
            raise ExportException(f"Export operation failed: {str(e)}")

    def _export_csv(
        self,
        results: List[SearchResult],
        file_path: Path,
        export_request: ExportRequest,
    ) -> None:
        """Export results to CSV format"""

        # Determine fields to include
        fields = export_request.include_fields or self.default_csv_fields

        with open(file_path, "w", newline="", encoding="utf-8") as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fields)
            writer.writeheader()

            for result in results:
                row_data = self._prepare_row_data(result, fields)
                writer.writerow(row_data)

    def _export_tsv(
        self,
        results: List[SearchResult],
        file_path: Path,
        export_request: ExportRequest,
    ) -> None:
        """Export results to TSV format"""

        # Determine fields to include
        fields = export_request.include_fields or self.default_csv_fields

        with open(file_path, "w", newline="", encoding="utf-8") as tsvfile:
            writer = csv.DictWriter(tsvfile, fieldnames=fields, delimiter="\t")
            writer.writeheader()

            for result in results:
                row_data = self._prepare_row_data(result, fields)
                writer.writerow(row_data)

    def _export_json(
        self,
        results: List[SearchResult],
        file_path: Path,
        export_request: ExportRequest,
    ) -> None:
        """Export results to JSON format"""

        export_data = {
            "metadata": {
                "export_timestamp": datetime.now().isoformat(),
                "total_records": len(results),
                "format": "json",
                "filters_applied": export_request.filters,
            },
            "results": [],
        }

        # Include specified fields or all fields
        for result in results:
            if export_request.include_fields:
                # Filter to specified fields
                result_data = {}
                result_dict = result.to_dict()
                for field in export_request.include_fields:
                    if field in result_dict:
                        result_data[field] = result_dict[field]
                    elif field in result.metadata:
                        result_data[field] = result.metadata[field]
            else:
                # Include all fields
                result_data = result.to_dict()

            export_data["results"].append(result_data)

        with open(file_path, "w", encoding="utf-8") as jsonfile:
            json.dump(export_data, jsonfile, indent=2, default=str)

    def _prepare_row_data(
        self, result: SearchResult, fields: List[str]
    ) -> Dict[str, Any]:
        """Prepare row data for CSV/TSV export"""
        row_data = {}
        result_dict = result.to_dict()

        for field in fields:
            if field in result_dict:
                value = result_dict[field]
            elif field in result.metadata:
                value = result.metadata[field]
            else:
                value = ""

            # Handle list fields (like authors)
            if isinstance(value, list):
                value = "; ".join(str(item) for item in value)

            # Handle None values
            if value is None:
                value = ""

            row_data[field] = str(value)

        return row_data

    def _validate_export_request(self, export_request: ExportRequest) -> None:
        """Validate export request parameters"""
        if export_request.format not in self.supported_formats:
            raise ValidationException(
                f"Unsupported export format: {export_request.format}. "
                f"Supported formats: {', '.join(self.supported_formats)}"
            )

        if export_request.max_results < 1:
            raise ValidationException("Max results must be positive")

        if export_request.max_results > 10000:
            raise ValidationException("Max results cannot exceed 10,000")

    def get_export_file(self, filename: str) -> Optional[Path]:
        """
        Get export file path if it exists and hasn't expired

        Args:
            filename: Export filename

        Returns:
            Path to export file or None if not found/expired
        """
        file_path = self.exports_dir / filename

        if not file_path.exists():
            return None

        # Check if file has expired (older than 24 hours)
        file_age = time.time() - file_path.stat().st_mtime
        if file_age > 24 * 3600:  # 24 hours
            self.logger.info(f"Export file expired: {filename}")
            file_path.unlink(missing_ok=True)
            return None

        return file_path

    def cleanup_expired_exports(self) -> int:
        """
        Clean up expired export files

        Returns:
            Number of files cleaned up
        """
        cleaned_count = 0
        current_time = time.time()

        try:
            for export_file in self.exports_dir.glob("omics_oracle_export_*"):
                file_age = current_time - export_file.stat().st_mtime
                if file_age > 24 * 3600:  # 24 hours
                    export_file.unlink(missing_ok=True)
                    cleaned_count += 1

            if cleaned_count > 0:
                self.logger.info(
                    f"Cleaned up {cleaned_count} expired export files"
                )

        except Exception as e:
            self.logger.error(f"Export cleanup failed: {str(e)}")

        return cleaned_count

    def get_export_stats(self) -> Dict[str, Any]:
        """Get export statistics"""
        try:
            export_files = list(self.exports_dir.glob("omics_oracle_export_*"))
            total_size = sum(f.stat().st_size for f in export_files)

            return {
                "total_exports": len(export_files),
                "total_size_bytes": total_size,
                "exports_dir": str(self.exports_dir),
            }
        except Exception as e:
            self.logger.error(f"Failed to get export stats: {str(e)}")
            return {
                "total_exports": 0,
                "total_size_bytes": 0,
                "exports_dir": str(self.exports_dir),
            }
