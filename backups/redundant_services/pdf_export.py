"""
PDF Export Service for OmicsOracle

This module provides PDF report generation with AI insights and visualizations.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY, TA_LEFT
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

logger = logging.getLogger(__name__)


class PDFExportService:
    """Service for generating PDF reports with AI insights."""

    def __init__(self):
        """Initialize PDF export service."""
        if not REPORTLAB_AVAILABLE:
            logger.warning("ReportLab not available. PDF export will use fallback mode.")

        self.styles = self._setup_styles() if REPORTLAB_AVAILABLE else None

    def _setup_styles(self) -> Dict[str, Any]:
        """Set up PDF styles."""
        if not REPORTLAB_AVAILABLE:
            return {}

        styles = getSampleStyleSheet()

        # Custom styles
        styles.add(
            ParagraphStyle(
                name="CustomTitle",
                parent=styles["Heading1"],
                fontSize=18,
                spaceAfter=30,
                textColor=colors.HexColor("#2c3e50"),
            )
        )

        styles.add(
            ParagraphStyle(
                name="AIInsight",
                parent=styles["Normal"],
                fontSize=10,
                leftIndent=20,
                rightIndent=20,
                spaceAfter=12,
                backgroundColor=colors.HexColor("#f8f9ff"),
                borderColor=colors.HexColor("#667eea"),
                borderWidth=1,
                borderPadding=10,
            )
        )

        styles.add(
            ParagraphStyle(
                name="DatasetTitle",
                parent=styles["Heading2"],
                fontSize=14,
                spaceAfter=10,
                textColor=colors.HexColor("#34495e"),
            )
        )

        return styles

    def generate_report(
        self,
        query_result: Dict[str, Any],
        output_path: Optional[Path] = None,
        include_metadata: bool = True,
        include_ai_summaries: bool = True,
    ) -> Path:
        """
        Generate a comprehensive PDF report.

        Args:
            query_result: The search results with AI summaries
            output_path: Output file path (auto-generated if None)
            include_metadata: Whether to include dataset metadata
            include_ai_summaries: Whether to include AI insights

        Returns:
            Path to the generated PDF file
        """
        if not REPORTLAB_AVAILABLE:
            return self._generate_fallback_report(query_result, output_path)

        # Generate output path if not provided
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            query_clean = "".join(
                c
                for c in query_result.get("original_query", "query")[:20]
                if c.isalnum() or c in (" ", "-", "_")
            ).replace(" ", "_")
            output_path = Path(f"omics_oracle_report_{query_clean}_{timestamp}.pdf")

        # Create PDF document
        doc = SimpleDocTemplate(
            str(output_path),
            pagesize=A4,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18,
        )

        # Build content
        story = []
        self._add_header(story, query_result)

        if include_ai_summaries and query_result.get("ai_summaries"):
            self._add_ai_insights(story, query_result["ai_summaries"])

        if include_metadata and query_result.get("metadata"):
            self._add_dataset_details(story, query_result["metadata"])

        self._add_footer(story, query_result)

        # Build PDF
        doc.build(story)
        logger.info(f"PDF report generated: {output_path}")

        return output_path

    def _add_header(self, story: List, query_result: Dict[str, Any]):
        """Add report header."""
        if not REPORTLAB_AVAILABLE:
            return

        # Title
        title = Paragraph("🧬 OmicsOracle Research Report", self.styles["CustomTitle"])
        story.append(title)
        story.append(Spacer(1, 12))

        # Query information
        query_info = f"""
        <b>Search Query:</b> {query_result.get('original_query', 'N/A')}<br/>
        <b>Results Found:</b> {len(query_result.get('metadata', []))} datasets<br/>
        <b>Processing Time:</b> {query_result.get('processing_time', 0):.2f} seconds<br/>
        <b>Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
        """

        query_para = Paragraph(query_info, self.styles["Normal"])
        story.append(query_para)
        story.append(Spacer(1, 20))

    def _add_ai_insights(self, story: List, ai_summaries: Dict[str, Any]):
        """Add AI insights section."""
        if not REPORTLAB_AVAILABLE:
            return

        # AI Insights header
        ai_header = Paragraph("🤖 AI-Generated Insights", self.styles["Heading1"])
        story.append(ai_header)
        story.append(Spacer(1, 12))

        # Batch summary
        if "batch_summary" in ai_summaries:
            batch = ai_summaries["batch_summary"]
            batch_text = f"""
            <b>Research Overview:</b><br/>
            {batch.get('overview', 'No overview available')}<br/><br/>
            <b>Key Statistics:</b><br/>
            • Total Datasets: {batch.get('total_datasets', 0)}<br/>
            • Total Samples: {batch.get('total_samples', 0)}<br/>
            • Organisms: {', '.join(batch.get('organisms', ['Not specified']))}<br/>
            """
            batch_para = Paragraph(batch_text, self.styles["AIInsight"])
            story.append(batch_para)
            story.append(Spacer(1, 15))

        # Brief overview
        if "brief_overview" in ai_summaries:
            brief = ai_summaries["brief_overview"]
            if isinstance(brief, dict):
                brief_text = "<b>Key Findings:</b><br/>"
                for key, value in brief.items():
                    if value:
                        brief_text += f"• <b>{key.replace('_', ' ').title()}:</b> {value}<br/>"
            else:
                brief_text = f"<b>Brief Analysis:</b><br/>{brief}"

            brief_para = Paragraph(brief_text, self.styles["AIInsight"])
            story.append(brief_para)
            story.append(Spacer(1, 20))

    def _add_dataset_details(self, story: List, metadata: List[Dict[str, Any]]):
        """Add dataset details section."""
        if not REPORTLAB_AVAILABLE:
            return

        # Dataset details header
        datasets_header = Paragraph("📚 Dataset Details", self.styles["Heading1"])
        story.append(datasets_header)
        story.append(Spacer(1, 12))

        for i, dataset in enumerate(metadata[:10], 1):  # Limit to first 10 datasets
            # Dataset title
            dataset_title = f"{i}. {dataset.get('title', 'Untitled Dataset')}"
            title_para = Paragraph(dataset_title, self.styles["DatasetTitle"])
            story.append(title_para)

            # Dataset information table
            data = [
                ["Accession ID", dataset.get("id", "N/A")],
                ["Organism", dataset.get("organism", "Not specified")],
                ["Platform", dataset.get("platform", "Not specified")],
                ["Sample Count", str(dataset.get("sample_count", "Unknown"))],
                [
                    "Submission Date",
                    dataset.get("submission_date", "Not available"),
                ],
            ]

            table = Table(data, colWidths=[2 * inch, 4 * inch])
            table.setStyle(
                TableStyle(
                    [
                        (
                            "BACKGROUND",
                            (0, 0),
                            (0, -1),
                            colors.HexColor("#f8f9fa"),
                        ),
                        ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        (
                            "GRID",
                            (0, 0),
                            (-1, -1),
                            1,
                            colors.HexColor("#dee2e6"),
                        ),
                    ]
                )
            )

            story.append(table)

            # Dataset summary
            if dataset.get("summary"):
                summary_text = f"<b>Summary:</b> {dataset['summary'][:500]}..."
                summary_para = Paragraph(summary_text, self.styles["Normal"])
                story.append(summary_para)

            story.append(Spacer(1, 15))

    def _add_footer(self, story: List, query_result: Dict[str, Any]):
        """Add report footer."""
        if not REPORTLAB_AVAILABLE:
            return

        story.append(Spacer(1, 30))

        footer_text = """
        <i>This report was generated by OmicsOracle, an AI-powered biomedical research platform.</i><br/>
        <i>For more information, visit our documentation or contact support.</i>
        """

        footer_para = Paragraph(footer_text, self.styles["Normal"])
        story.append(footer_para)

    def _generate_fallback_report(
        self, query_result: Dict[str, Any], output_path: Optional[Path] = None
    ) -> Path:
        """Generate a text-based report when ReportLab is not available."""
        if output_path is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            query_clean = "".join(
                c
                for c in query_result.get("original_query", "query")[:20]
                if c.isalnum() or c in (" ", "-", "_")
            ).replace(" ", "_")
            output_path = Path(f"omics_oracle_report_{query_clean}_{timestamp}.txt")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("🧬 OmicsOracle Research Report\n")
            f.write("=" * 50 + "\n\n")

            # Query information
            f.write(f"Search Query: {query_result.get('original_query', 'N/A')}\n")
            f.write(f"Results Found: {len(query_result.get('metadata', []))} datasets\n")
            f.write(f"Processing Time: {query_result.get('processing_time', 0):.2f} seconds\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            # AI insights
            if query_result.get("ai_summaries"):
                f.write("🤖 AI-Generated Insights\n")
                f.write("-" * 30 + "\n")
                f.write(json.dumps(query_result["ai_summaries"], indent=2))
                f.write("\n\n")

            # Dataset details
            if query_result.get("metadata"):
                f.write("📚 Dataset Details\n")
                f.write("-" * 20 + "\n")
                for i, dataset in enumerate(query_result["metadata"], 1):
                    f.write(f"{i}. {dataset.get('title', 'Untitled')}\n")
                    f.write(f"   ID: {dataset.get('id', 'N/A')}\n")
                    f.write(f"   Organism: {dataset.get('organism', 'Not specified')}\n")
                    f.write(f"   Summary: {dataset.get('summary', 'No summary')[:200]}...\n\n")

        logger.info(f"Text report generated: {output_path}")
        return output_path


# Global service instance
pdf_service = PDFExportService()
