"""
Citation manager integrations for OmicsOracle.

Provides functionality to export references in various formats
compatible with popular citation managers.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class CitationManagerIntegration:
    """Integration for exporting references to citation managers."""

    def __init__(self) -> None:
        """Initialize citation manager integration."""
        pass

    def format_geo_reference(
        self,
        geo_data: Dict[str, Any],
        papers: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Format GEO dataset as a reference entry.

        Args:
            geo_data: GEO dataset information
            papers: Optional related papers

        Returns:
            Formatted reference dictionary
        """
        # Extract key information
        accession = geo_data.get("accession", "Unknown")
        title = geo_data.get("title", "Untitled Dataset")
        summary = geo_data.get("summary", "")

        # Try to extract submission date
        submission_date = geo_data.get("submission_date")
        if isinstance(submission_date, str):
            try:
                date_obj = datetime.strptime(submission_date, "%Y-%m-%d")
                formatted_date = date_obj.strftime("%Y")
            except ValueError:
                formatted_date = submission_date
        else:
            formatted_date = (
                str(submission_date) if submission_date else "Unknown"
            )

        # Create reference entry
        reference = {
            "id": accession,
            "type": "dataset",
            "title": title,
            "abstract": summary,
            "URL": f"https://www.ncbi.nlm.nih.gov/geo/query/acc.cgi?acc={accession}",
            "accessed": datetime.now().strftime("%Y-%m-%d"),
            "issued": {
                "date-parts": [[formatted_date]]
                if formatted_date != "Unknown"
                else []
            },
            "publisher": "Gene Expression Omnibus (GEO)",
            "source": "NCBI GEO",
            "note": f"GEO accession: {accession}",
        }

        # Add related papers if available
        if papers:
            reference["related_papers"] = [
                {
                    "pmid": paper.get("pmid"),
                    "title": paper.get("title"),
                    "authors": paper.get("authors", []),
                    "journal": paper.get("journal"),
                    "year": paper.get("year"),
                    "url": paper.get("pubmed_url"),
                }
                for paper in papers[:5]  # Limit to top 5 related papers
            ]

        return reference

    def to_bibtex(self, reference: Dict[str, Any]) -> str:
        """
        Convert reference to BibTeX format.

        Args:
            reference: Reference dictionary

        Returns:
            BibTeX formatted string
        """
        bibtex_type = "misc"  # Use 'misc' for datasets
        cite_key = reference.get("id", "dataset")

        # Build BibTeX entry
        bibtex_lines = [f"@{bibtex_type}{{{cite_key},"]

        # Add fields
        if reference.get("title"):
            bibtex_lines.append(f'  title = {{{reference["title"]}}},')

        if reference.get("publisher"):
            bibtex_lines.append(f'  publisher = {{{reference["publisher"]}}},')

        if reference.get("URL"):
            bibtex_lines.append(f'  url = {{{reference["URL"]}}},')

        if reference.get("accessed"):
            bibtex_lines.append(f'  urldate = {{{reference["accessed"]}}},')

        if reference.get("issued") and reference["issued"].get("date-parts"):
            year = reference["issued"]["date-parts"][0][0]
            bibtex_lines.append(f"  year = {{{year}}},")

        if reference.get("note"):
            bibtex_lines.append(f'  note = {{{reference["note"]}}},')

        if reference.get("abstract"):
            # Truncate abstract if too long
            abstract = (
                reference["abstract"][:500] + "..."
                if len(reference["abstract"]) > 500
                else reference["abstract"]
            )
            bibtex_lines.append(f"  abstract = {{{abstract}}},")

        # Remove trailing comma from last line
        if bibtex_lines[-1].endswith(","):
            bibtex_lines[-1] = bibtex_lines[-1][:-1]

        bibtex_lines.append("}")

        return "\n".join(bibtex_lines)

    def to_ris(self, reference: Dict[str, Any]) -> str:
        """
        Convert reference to RIS format.

        Args:
            reference: Reference dictionary

        Returns:
            RIS formatted string
        """
        ris_lines = ["TY  - DATA"]  # Type: Database/Dataset

        if reference.get("title"):
            ris_lines.append(f'TI  - {reference["title"]}')

        if reference.get("abstract"):
            # Split long abstracts into multiple lines
            abstract = reference["abstract"]
            if len(abstract) > 200:
                # Split into chunks
                chunks = [
                    abstract[i : i + 200] for i in range(0, len(abstract), 200)
                ]
                for chunk in chunks:
                    ris_lines.append(f"AB  - {chunk}")
            else:
                ris_lines.append(f"AB  - {abstract}")

        if reference.get("URL"):
            ris_lines.append(f'UR  - {reference["URL"]}')

        if reference.get("publisher"):
            ris_lines.append(f'PB  - {reference["publisher"]}')

        if reference.get("issued") and reference["issued"].get("date-parts"):
            year = reference["issued"]["date-parts"][0][0]
            ris_lines.append(f"PY  - {year}")

        if reference.get("note"):
            ris_lines.append(f'N1  - {reference["note"]}')

        # Add related papers as notes
        if reference.get("related_papers"):
            ris_lines.append("N1  - Related Papers:")
            for paper in reference["related_papers"][:3]:  # Limit to 3
                if paper.get("title") and paper.get("pmid"):
                    ris_lines.append(
                        f'N1  - PMID:{paper["pmid"]} - {paper["title"]}'
                    )

        ris_lines.append("ER  - ")  # End of record

        return "\n".join(ris_lines)

    def to_endnote_xml(self, reference: Dict[str, Any]) -> str:
        """
        Convert reference to EndNote XML format.

        Args:
            reference: Reference dictionary

        Returns:
            EndNote XML formatted string
        """
        xml_lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        xml_lines.append("<xml>")
        xml_lines.append("<records>")
        xml_lines.append("<record>")
        xml_lines.append(
            '<ref-type name="Dataset">59</ref-type>'
        )  # Dataset type

        # Add contributors (empty for datasets)
        xml_lines.append("<contributors></contributors>")

        # Add titles
        xml_lines.append("<titles>")
        if reference.get("title"):
            xml_lines.append(
                f'<title>{self._escape_xml(reference["title"])}</title>'
            )
        xml_lines.append("</titles>")

        # Add dates
        xml_lines.append("<dates>")
        if reference.get("issued") and reference["issued"].get("date-parts"):
            year = reference["issued"]["date-parts"][0][0]
            xml_lines.append(f"<year>{year}</year>")
        xml_lines.append("</dates>")

        # Add publisher
        if reference.get("publisher"):
            xml_lines.append(
                f'<publisher>{self._escape_xml(reference["publisher"])}</publisher>'
            )

        # Add URLs
        xml_lines.append("<urls>")
        if reference.get("URL"):
            xml_lines.append(
                f'<related-urls><url>{reference["URL"]}</url></related-urls>'
            )
        xml_lines.append("</urls>")

        # Add abstract
        if reference.get("abstract"):
            xml_lines.append(
                f'<abstract><p>{self._escape_xml(reference["abstract"])}</p></abstract>'
            )

        # Add notes
        if reference.get("note"):
            xml_lines.append(
                f'<notes><note><p>{self._escape_xml(reference["note"])}</p></note></notes>'
            )

        xml_lines.append("</record>")
        xml_lines.append("</records>")
        xml_lines.append("</xml>")

        return "\n".join(xml_lines)

    def to_csl_json(self, reference: Dict[str, Any]) -> str:
        """
        Convert reference to CSL-JSON format.

        Args:
            reference: Reference dictionary

        Returns:
            CSL-JSON formatted string
        """
        csl_item = {
            "id": reference.get("id"),
            "type": "dataset",
            "title": reference.get("title"),
            "abstract": reference.get("abstract"),
            "URL": reference.get("URL"),
            "publisher": reference.get("publisher"),
            "source": reference.get("source"),
            "note": reference.get("note"),
        }

        # Add date
        if reference.get("issued"):
            csl_item["issued"] = reference["issued"]

        # Add accessed date
        if reference.get("accessed"):
            csl_item["accessed"] = {"raw": reference["accessed"]}

        # Remove None values
        csl_item = {k: v for k, v in csl_item.items() if v is not None}

        return json.dumps([csl_item], indent=2)

    def _escape_xml(self, text: str) -> str:
        """Escape XML special characters."""
        if not text:
            return ""
        return (
            text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&apos;")
        )

    def export_references(
        self,
        geo_datasets: List[Dict[str, Any]],
        format_type: str = "bibtex",
        include_papers: bool = True,
    ) -> str:
        """
        Export multiple GEO datasets as references.

        Args:
            geo_datasets: List of GEO dataset information
            format_type: Export format ('bibtex', 'ris', 'endnote', 'csl-json')
            include_papers: Whether to include related papers

        Returns:
            Formatted references string
        """
        references = []

        for dataset in geo_datasets:
            # Format dataset as reference
            papers = dataset.get("related_papers") if include_papers else None
            reference = self.format_geo_reference(dataset, papers)

            # Convert to requested format
            if format_type.lower() == "bibtex":
                references.append(self.to_bibtex(reference))
            elif format_type.lower() == "ris":
                references.append(self.to_ris(reference))
            elif format_type.lower() == "endnote":
                references.append(self.to_endnote_xml(reference))
            elif format_type.lower() == "csl-json":
                references.append(self.to_csl_json(reference))
            else:
                logger.warning(f"Unsupported format: {format_type}")
                continue

        # Join references appropriately
        if format_type.lower() == "csl-json":
            # For CSL-JSON, we need to combine into a single array
            all_items = []
            for ref_json in references:
                items = json.loads(ref_json)
                all_items.extend(items)
            return json.dumps(all_items, indent=2)
        else:
            return "\n\n".join(references)


# Convenience function
def export_geo_references(
    geo_datasets: List[Dict[str, Any]],
    format_type: str = "bibtex",
    include_papers: bool = True,
) -> str:
    """
    Convenience function to export GEO dataset references.

    Args:
        geo_datasets: List of GEO dataset information
        format_type: Export format
        include_papers: Whether to include related papers

    Returns:
        Formatted references string
    """
    citation_manager = CitationManagerIntegration()
    return citation_manager.export_references(
        geo_datasets, format_type, include_papers
    )
