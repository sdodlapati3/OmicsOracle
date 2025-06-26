#!/usr/bin/env python3
"""
GSE ID Content Mismatch Detector

This script is designed to detect content mismatches between GSE IDs and their associated data.
It focuses on identifying cases where:
1. GSE IDs are shown with unrelated content
2. Title, summary, and organism data don't match NCBI GEO database records
3. GSE IDs are invalid or non-existent

The script supports two primary modes:
1. Testing a specific GSE ID
2. Validating all GSE IDs from a search query

Features:
- Cross-references with NCBI GEO using multiple APIs for reliability
- Supports batch validation of search results
- Calculates text similarity scores using NLP techniques
- Caches NCBI GEO data to reduce API calls
- Generates detailed reports and summaries

Usage:
    python validate_gse_content.py --query "cancer" [--max-results 20]
    python validate_gse_content.py --gse-id "GSE278726"
    python validate_gse_content.py --file-path "results_file.json"
"""

import argparse
import asyncio
import json
import logging
import os
import re
import ssl
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import aiohttp
import certifi

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("gse_content_validation.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("gse_content_validator")


class GSEContentValidator:
    def __init__(
        self,
        base_url="http://localhost:8001",
        ncbi_api_key=None,
        disable_ssl_verify=False,
    ):
        self.base_url = base_url
        self.ncbi_api_key = ncbi_api_key
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir = "validation_reports"
        os.makedirs(self.output_dir, exist_ok=True)
        self.disable_ssl_verify = disable_ssl_verify

        # Initialize session and cache
        self.session = None
        self.geo_cache = {}  # Cache for NCBI GEO data

        logger.info(
            f"GSE Content Validator initialized with base URL: {self.base_url}"
        )
        if self.disable_ssl_verify:
            logger.warning(
                "SSL verification is disabled - this should only be used for testing!"
            )

    async def init_session(self):
        """Initialize aiohttp session with proper SSL configuration"""
        if self.session is None:
            # Create connector with appropriate SSL settings
            if self.disable_ssl_verify:
                # Create a connector that doesn't verify SSL certificates
                connector = aiohttp.TCPConnector(ssl=False)
                logger.warning(
                    "Using insecure SSL connection (verification disabled)"
                )
            else:
                # Create SSL context with proper certificate validation
                ssl_context = ssl.create_default_context(cafile=certifi.where())
                connector = aiohttp.TCPConnector(ssl=ssl_context)

            # Create session with timeout and configured connector
            timeout = aiohttp.ClientTimeout(total=30)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    "User-Agent": "OmicsOracle-GSE-Validator/1.0 (https://github.com/example/omicsoracle)"
                },
            )

    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None

    async def validate_by_query(
        self, query: str, max_results: int = 20
    ) -> Dict[str, Any]:
        """
        Validate GSE IDs returned from a search query
        """
        await self.init_session()

        logger.info(f"Starting validation for query: '{query}'")

        # Step 1: Get search results from our API
        search_results = await self.get_search_results(query, max_results)

        if not search_results or "results" not in search_results:
            logger.error("No results returned from API")
            return {"error": "No results returned from API"}

        # Step 2: Validate each GSE ID in the results
        validation_results = []

        for i, result in enumerate(search_results["results"]):
            gse_id = result.get("geo_id")
            if not gse_id:
                logger.warning(f"Result {i} missing GSE ID")
                continue

            logger.info(
                f"Validating GSE ID: {gse_id} ({i+1}/{len(search_results['results'])})"
            )
            validation = await self.validate_gse_id(gse_id, result)
            validation_results.append(validation)

            # Be nice to NCBI API - don't hammer it
            await asyncio.sleep(1)

        # Step 3: Generate report
        report = {
            "query": query,
            "timestamp": self.timestamp,
            "results_count": len(search_results["results"]),
            "validation_results": validation_results,
            "summary": self.generate_validation_summary(validation_results),
        }

        # Save report
        self.save_report(report)

        return report

    async def validate_from_file(self, file_path: str) -> Dict[str, Any]:
        """
        Validate GSE IDs from a results file
        """
        await self.init_session()

        logger.info(f"Starting validation from file: {file_path}")

        try:
            with open(file_path, "r") as f:
                file_data = json.load(f)

            # Extract results based on file format
            results = []
            if isinstance(file_data, dict) and "results" in file_data:
                results = file_data["results"]
                query = file_data.get("query", "unknown")
            elif isinstance(file_data, list):
                results = file_data
                query = "from_file"
            else:
                logger.error(f"Unrecognized file format in {file_path}")
                return {"error": "Unrecognized file format"}

            # Step 2: Validate each GSE ID in the results
            validation_results = []

            for i, result in enumerate(results):
                gse_id = result.get("geo_id")
                if not gse_id:
                    logger.warning(f"Result {i} missing GSE ID")
                    continue

                logger.info(
                    f"Validating GSE ID: {gse_id} ({i+1}/{len(results)})"
                )
                validation = await self.validate_gse_id(gse_id, result)
                validation_results.append(validation)

                # Be nice to NCBI API - don't hammer it
                await asyncio.sleep(1)

            # Step 3: Generate report
            report = {
                "source_file": file_path,
                "timestamp": self.timestamp,
                "results_count": len(results),
                "validation_results": validation_results,
                "summary": self.generate_validation_summary(validation_results),
            }

            # Save report
            self.save_report(report)

            return report

        except Exception as e:
            logger.error(f"Error processing file {file_path}: {str(e)}")
            return {"error": str(e)}

    async def validate_gse_id(
        self, gse_id: str, our_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Validate a specific GSE ID against NCBI GEO database
        """
        await self.init_session()

        # Standardize GSE ID format
        if not gse_id.startswith("GSE"):
            gse_id = f"GSE{gse_id}"

        validation = {
            "gse_id": gse_id,
            "exists_in_geo": False,
            "title_match": False,
            "title_similarity": 0.0,  # Similarity score from 0 to 1
            "summary_match": None,
            "summary_similarity": 0.0,
            "organism_match": None,
            "issues": [],
            "ncbi_data": None,
            "our_data": our_data,
        }

        # Check if GSE ID follows the expected pattern (GSE followed by numbers)
        if not re.match(r"^GSE\d+$", gse_id):
            validation["issues"].append(f"Invalid GSE ID format: {gse_id}")

        # Get data from NCBI GEO (or cache)
        if gse_id in self.geo_cache:
            ncbi_data = self.geo_cache[gse_id]
            logger.info(f"Using cached NCBI data for {gse_id}")
        else:
            ncbi_data = await self.fetch_geo_data(gse_id)
            if ncbi_data and "error" not in ncbi_data:
                self.geo_cache[gse_id] = ncbi_data

        if not ncbi_data or "error" in ncbi_data:
            validation["exists_in_geo"] = False
            validation["issues"].append(
                f"GSE ID {gse_id} not found in NCBI GEO"
            )
            validation["verdict"] = "NOT_FOUND"
            return validation

        validation["exists_in_geo"] = True
        validation["ncbi_data"] = ncbi_data

        # Set default verdict as MATCH if GSE exists but we don't have our data to compare
        if not our_data:
            validation["verdict"] = "FOUND_IN_GEO"

        # If we have our data, compare it
        if our_data:
            # Check title
            our_title = our_data.get("title", "").strip()
            ncbi_title = ncbi_data.get("title", "").strip()

            if our_title and ncbi_title:
                # Calculate title similarity score
                title_similarity = self.calculate_text_similarity(
                    our_title, ncbi_title
                )
                validation["title_similarity"] = title_similarity

                # Determine match level based on similarity
                if title_similarity > 0.9:  # 90% similar
                    validation["title_match"] = True
                elif title_similarity > 0.6:  # 60-90% similar
                    validation["title_match"] = "partial"
                else:
                    validation["title_match"] = False
                    validation["issues"].append(
                        f"Title mismatch (similarity: {title_similarity:.2f})"
                    )
                    validation["issues"].append(
                        f"Our title: {our_title[:100]}..."
                    )
                    validation["issues"].append(
                        f"NCBI title: {ncbi_title[:100]}..."
                    )

            # Check summary
            our_summary = our_data.get("summary", "").strip()
            ncbi_summary = ncbi_data.get("summary", "").strip()

            if our_summary and ncbi_summary:
                # Calculate summary similarity
                summary_similarity = self.calculate_text_similarity(
                    our_summary, ncbi_summary
                )
                validation["summary_similarity"] = summary_similarity

                if summary_similarity > 0.7:  # 70% similar
                    validation["summary_match"] = True
                elif summary_similarity > 0.4:  # 40-70% similar
                    validation["summary_match"] = "partial"
                else:
                    validation["summary_match"] = False
                    validation["issues"].append(
                        f"Summary mismatch (similarity: {summary_similarity:.2f})"
                    )

            # Check organism
            our_organism = our_data.get("organism", "").lower().strip()
            ncbi_organism = ncbi_data.get("organism", "").lower().strip()

            if our_organism and ncbi_organism:
                # For organisms, check for substring matches or common terms
                if our_organism == ncbi_organism:
                    validation["organism_match"] = True
                elif (
                    our_organism in ncbi_organism
                    or ncbi_organism in our_organism
                ):
                    validation["organism_match"] = True
                else:
                    # Check for common organism terms
                    our_terms = set(our_organism.split())
                    ncbi_terms = set(ncbi_organism.split())
                    common_terms = our_terms.intersection(ncbi_terms)

                    if len(common_terms) > 0:
                        validation["organism_match"] = "partial"
                    else:
                        validation["organism_match"] = False
                        validation["issues"].append(
                            f"Organism mismatch: {our_organism} vs {ncbi_organism}"
                        )

            # Additional check: detect COVID-19 content mismatch
            # Example: GSE278726 shown with unrelated COVID-19 content
            covid_keywords = ["covid", "covid-19", "sars-cov-2", "coronavirus"]

            if any(
                kw in our_title.lower() for kw in covid_keywords
            ) and not any(kw in ncbi_title.lower() for kw in covid_keywords):
                validation["issues"].append(
                    "CRITICAL: COVID-19 content mismatch detected - our data mentions COVID-19 but NCBI data does not"
                )

            # Overall validation verdict
            if validation["exists_in_geo"]:
                if (
                    validation["title_match"] is False
                    or validation["organism_match"] is False
                ):
                    validation["verdict"] = "MISMATCH"
                elif validation["issues"]:
                    validation["verdict"] = "PARTIAL_MATCH"
                else:
                    validation["verdict"] = "MATCH"
            else:
                validation["verdict"] = "NOT_FOUND"
        else:
            # If we don't have our data to compare, set default verdict based on NCBI existence
            validation["verdict"] = (
                "FOUND_IN_GEO" if validation["exists_in_geo"] else "NOT_FOUND"
            )

        return validation

    async def get_search_results(
        self, query: str, max_results: int = 20
    ) -> Dict[str, Any]:
        """
        Get search results from our API
        """
        try:
            payload = {
                "query": query,
                "max_results": max_results,
                "search_type": "comprehensive",
                "disable_cache": True,
                "timestamp": int(time.time() * 1000),
            }

            logger.info(
                f"Making API request to {self.base_url}/api/search with payload: {payload}"
            )

            async with self.session.post(
                f"{self.base_url}/api/search",
                headers={
                    "Content-Type": "application/json",
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                    "Expires": "0",
                },
                json=payload,
            ) as response:
                if response.status != 200:
                    logger.error(f"API returned status {response.status}")
                    return {"error": f"API returned status {response.status}"}

                return await response.json()

        except Exception as e:
            logger.error(f"Error getting search results: {str(e)}")
            return {"error": str(e)}

    async def fetch_geo_data(self, gse_id: str) -> Dict[str, Any]:
        """
        Fetch data for a GSE ID from NCBI GEO
        Using multiple methods for resilience
        """
        try:
            # First try the Entrez API
            entrez_data = await self.fetch_from_entrez(gse_id)
            if entrez_data and "error" not in entrez_data:
                return entrez_data

            # Fall back to direct GEO API
            geo_data = await self.fetch_geo_direct(gse_id)
            if geo_data and "error" not in geo_data:
                return geo_data

            # If both methods fail, return the error
            return {
                "error": f"Could not fetch data for {gse_id} from any source"
            }

        except Exception as e:
            logger.error(f"Error fetching GSE data: {str(e)}")
            return {"error": str(e)}

    async def fetch_from_entrez(self, gse_id: str) -> Dict[str, Any]:
        """
        Fetch data from NCBI Entrez eUtils API
        """
        try:
            # First try esearch to get the correct ID
            esearch_url = (
                "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi"
            )

            esearch_params = {
                "db": "gds",  # GEO DataSets
                "term": gse_id,
                "retmode": "json",
            }

            if self.ncbi_api_key:
                esearch_params["api_key"] = self.ncbi_api_key

            logger.info(f"Searching for GSE ID in NCBI Entrez: {gse_id}")

            async with self.session.get(
                esearch_url, params=esearch_params
            ) as response:
                if response.status != 200:
                    logger.error(
                        f"NCBI Entrez esearch API returned status {response.status}"
                    )
                    return {
                        "error": f"NCBI Entrez esearch API returned status {response.status}"
                    }

                search_data = await response.json()

                if (
                    "esearchresult" not in search_data
                    or "idlist" not in search_data["esearchresult"]
                ):
                    logger.error(
                        f"No results found for {gse_id} in Entrez esearch"
                    )
                    return {"error": f"No results found for {gse_id} in Entrez"}

                id_list = search_data["esearchresult"]["idlist"]
                if not id_list:
                    logger.error(
                        f"Empty ID list for {gse_id} in Entrez esearch"
                    )
                    return {"error": f"Empty ID list for {gse_id} in Entrez"}

                entrez_id = id_list[0]

            # Now fetch the summary with the correct ID
            entrez_url = (
                "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi"
            )

            params = {
                "db": "gds",  # GEO DataSets
                "id": entrez_id,
                "retmode": "json",
                "version": "2.0",
            }

            if self.ncbi_api_key:
                params["api_key"] = self.ncbi_api_key

            logger.info(
                f"Fetching GSE data from NCBI Entrez for {gse_id} using ID {entrez_id}"
            )

            async with self.session.get(entrez_url, params=params) as response:
                if response.status != 200:
                    logger.error(
                        f"NCBI Entrez API returned status {response.status}"
                    )
                    return {
                        "error": f"NCBI Entrez API returned status {response.status}"
                    }

                data = await response.json()

                # Process Entrez response
                if "result" in data:
                    result = data["result"]
                    if str(entrez_id) in result:
                        entry = result[str(entrez_id)]
                        return {
                            "title": entry.get("title", ""),
                            "summary": entry.get("summary", ""),
                            "organism": "; ".join(entry.get("organism", [])),
                            "entrytype": entry.get("entrytype", ""),
                            "accession": entry.get("accession", ""),
                        }

                return {"error": "Could not parse Entrez response"}

        except Exception as e:
            logger.error(f"Error fetching from Entrez: {str(e)}")
            return {"error": str(e)}

    async def fetch_geo_direct(self, gse_id: str) -> Dict[str, Any]:
        """
        Fetch data directly from GEO (text format)
        """
        try:
            geo_url = "https://www.ncbi.nlm.nih.gov/geo/query/acc.cgi"

            params = {
                "acc": gse_id,
                "targ": "self",
                "form": "text",
                "view": "brief",
            }

            logger.info(f"Fetching GSE data directly from GEO for {gse_id}")

            async with self.session.get(geo_url, params=params) as response:
                if response.status != 200:
                    logger.error(f"GEO API returned status {response.status}")
                    return {
                        "error": f"GEO API returned status {response.status}"
                    }

                text = await response.text()

                # Check if it's an error page (doesn't contain Series info)
                if "Series does not exist" in text or "^SERIES =" not in text:
                    return {"error": f"GSE ID {gse_id} not found in GEO"}

                # Parse the text format response
                data = {}

                if "!Series_title" in text:
                    title_lines = [
                        line
                        for line in text.split("\n")
                        if line.startswith("!Series_title")
                    ]
                    data["title"] = (
                        title_lines[0].split("=", 1)[1].strip()
                        if title_lines
                        else ""
                    )

                if "!Series_summary" in text:
                    summary_lines = [
                        line
                        for line in text.split("\n")
                        if line.startswith("!Series_summary")
                    ]
                    data["summary"] = " ".join(
                        [
                            line.split("=", 1)[1].strip()
                            for line in summary_lines
                        ]
                    )

                # Try multiple organism fields
                organism_fields = [
                    "!Series_organism",
                    "!Series_platform_organism",
                    "!Series_sample_organism",
                ]
                for field in organism_fields:
                    if field in text:
                        organism_lines = [
                            line
                            for line in text.split("\n")
                            if line.startswith(field)
                        ]
                        if organism_lines:
                            data["organism"] = (
                                organism_lines[0].split("=", 1)[1].strip()
                            )
                            break

                # Add accession and submission date if available
                if "!Series_geo_accession" in text:
                    acc_line = [
                        line
                        for line in text.split("\n")
                        if line.startswith("!Series_geo_accession")
                    ][0]
                    data["accession"] = acc_line.split("=", 1)[1].strip()

                if "!Series_submission_date" in text:
                    date_line = [
                        line
                        for line in text.split("\n")
                        if line.startswith("!Series_submission_date")
                    ][0]
                    data["submission_date"] = date_line.split("=", 1)[1].strip()

                # Log what we found for debugging
                logger.info(
                    f"Extracted from GEO: Title: '{data.get('title', 'None')}', Accession: '{data.get('accession', 'None')}'"
                )

                return data

        except Exception as e:
            logger.error(f"Error fetching GSE data directly from GEO: {str(e)}")
            return {"error": str(e)}

    def calculate_text_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate similarity between two text strings
        Using a simple Jaccard similarity on word sets
        """
        if not text1 or not text2:
            return 0.0

        # Normalize and tokenize texts
        def normalize(text):
            text = text.lower()
            # Remove punctuation and split into words
            words = re.findall(r"\b\w+\b", text)
            return set(words)

        set1 = normalize(text1)
        set2 = normalize(text2)

        # Calculate Jaccard similarity: |A intersect B| / |A union B|
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))

        return intersection / union if union > 0 else 0.0

    def generate_validation_summary(
        self, validation_results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Generate a summary of validation results
        """
        total = len(validation_results)
        existing_in_geo = sum(
            1 for v in validation_results if v.get("exists_in_geo", False)
        )
        title_matches = sum(
            1 for v in validation_results if v.get("title_match") is True
        )
        title_partial = sum(
            1 for v in validation_results if v.get("title_match") == "partial"
        )
        organism_matches = sum(
            1 for v in validation_results if v.get("organism_match") is True
        )
        organism_partial = sum(
            1
            for v in validation_results
            if v.get("organism_match") == "partial"
        )

        # Count verdicts
        matches = sum(
            1 for v in validation_results if v.get("verdict") == "MATCH"
        )
        partial_matches = sum(
            1 for v in validation_results if v.get("verdict") == "PARTIAL_MATCH"
        )
        mismatches = sum(
            1 for v in validation_results if v.get("verdict") == "MISMATCH"
        )
        not_found = sum(
            1 for v in validation_results if v.get("verdict") == "NOT_FOUND"
        )
        found_in_geo = sum(
            1 for v in validation_results if v.get("verdict") == "FOUND_IN_GEO"
        )

        # Calculate average similarity scores
        title_similarities = [
            v.get("title_similarity", 0)
            for v in validation_results
            if v.get("exists_in_geo", False)
        ]
        summary_similarities = [
            v.get("summary_similarity", 0)
            for v in validation_results
            if v.get("exists_in_geo", False)
        ]

        avg_title_similarity = (
            sum(title_similarities) / len(title_similarities)
            if title_similarities
            else 0
        )
        avg_summary_similarity = (
            sum(summary_similarities) / len(summary_similarities)
            if summary_similarities
            else 0
        )

        # Find most severe mismatches (lowest similarity scores)
        worst_matches = sorted(
            [v for v in validation_results if v.get("exists_in_geo", False)],
            key=lambda x: x.get("title_similarity", 1.0),
        )[
            :3
        ]  # Top 3 worst matches

        worst_match_ids = [v["gse_id"] for v in worst_matches]

        return {
            "total_validated": total,
            "existing_in_geo": existing_in_geo,
            "not_found_in_geo": total - existing_in_geo,
            "title_exact_matches": title_matches,
            "title_partial_matches": title_partial,
            "organism_exact_matches": organism_matches,
            "organism_partial_matches": organism_partial,
            "complete_matches": matches,
            "partial_matches": partial_matches,
            "mismatches": mismatches,
            "not_found": not_found,
            "found_in_geo": found_in_geo,
            "avg_title_similarity": avg_title_similarity,
            "avg_summary_similarity": avg_summary_similarity,
            "worst_match_ids": worst_match_ids,
            "accuracy": {
                "overall": matches / total if total > 0 else 0,
                "title": (title_matches + 0.5 * title_partial) / existing_in_geo
                if existing_in_geo > 0
                else 0,
                "organism": (organism_matches + 0.5 * organism_partial)
                / existing_in_geo
                if existing_in_geo > 0
                else 0,
            },
        }

    def save_report(self, report: Dict[str, Any]) -> None:
        """
        Save validation report to file
        """
        filename = f"{self.output_dir}/content_validation_{self.timestamp}.json"
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"Validation report saved to {filename}")

        # Also save a summary file
        summary_filename = f"{self.output_dir}/content_validation_summary_{self.timestamp}.json"
        summary = {
            "timestamp": report["timestamp"],
            "results_count": report["results_count"],
            "summary": report["summary"],
            "mismatches": [
                {
                    "gse_id": result["gse_id"],
                    "verdict": result["verdict"],
                    "issues": result["issues"],
                    "title_similarity": result.get("title_similarity", 0),
                    "our_title": result.get("our_data", {}).get("title", ""),
                    "ncbi_title": result.get("ncbi_data", {}).get("title", ""),
                }
                for result in report["validation_results"]
                if result["verdict"] in ["MISMATCH", "PARTIAL_MATCH"]
            ],
        }

        with open(summary_filename, "w") as f:
            json.dump(summary, f, indent=2)

        logger.info(f"Validation summary saved to {summary_filename}")

    def print_summary(self, report: Dict[str, Any]) -> None:
        """
        Print a human-readable summary of validation results
        """
        print("\n" + "=" * 80)
        print(f"GSE CONTENT VALIDATION SUMMARY")
        print("=" * 80)

        summary = report["summary"]

        print(f"\nTotal datasets validated: {summary['total_validated']}")
        print(
            f"Found in NCBI GEO: {summary['existing_in_geo']} ({summary['existing_in_geo']/summary['total_validated']*100:.1f}%)"
        )
        print(
            f"Not found in NCBI GEO: {summary['not_found_in_geo']} ({summary['not_found_in_geo']/summary['total_validated']*100:.1f}%)"
        )

        if summary["existing_in_geo"] > 0:
            print(
                f"\nAverage title similarity: {summary['avg_title_similarity']*100:.1f}%"
            )
            print(
                f"Average summary similarity: {summary['avg_summary_similarity']*100:.1f}%"
            )

            print(
                f"\nMatches: {summary['complete_matches']} ({summary['complete_matches']/summary['total_validated']*100:.1f}%)"
            )
            print(
                f"Partial matches: {summary['partial_matches']} ({summary['partial_matches']/summary['total_validated']*100:.1f}%)"
            )
            print(
                f"Mismatches: {summary['mismatches']} ({summary['mismatches']/summary['total_validated']*100:.1f}%)"
            )
            print(
                f"Not found: {summary['not_found']} ({summary['not_found']/summary['total_validated']*100:.1f}%)"
            )
            print(
                f"Found in GEO (no comparison): {summary['found_in_geo']} ({summary['found_in_geo']/summary['total_validated']*100:.1f}%)"
            )

        if summary["mismatches"] > 0:
            print(f"\nWORST MISMATCHES DETECTED:")

            # Show details of worst mismatches
            print("\nMismatch Details:")
            for i, result in enumerate(
                [
                    r
                    for r in report["validation_results"]
                    if r["verdict"] == "MISMATCH"
                ][:5]
            ):
                print(
                    f"\n{i+1}. GSE ID: {result['gse_id']} - MISMATCH (Title similarity: {result.get('title_similarity', 0)*100:.1f}%)"
                )
                print(
                    f"   Our Title: {result.get('our_data', {}).get('title', 'N/A')[:100]}..."
                )
                print(
                    f"   NCBI Title: {result.get('ncbi_data', {}).get('title', 'N/A')[:100]}..."
                )
                if result["issues"]:
                    print(f"   Issues: {', '.join(result['issues'])}")

        print("\n" + "=" * 80)


async def main():
    parser = argparse.ArgumentParser(
        description="Validate GSE ID content consistency"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--query", help="Search query to validate results for")
    group.add_argument("--gse-id", help="Specific GSE ID to validate")
    group.add_argument(
        "--file-path", help="Path to a JSON file containing search results"
    )

    parser.add_argument(
        "--max-results",
        type=int,
        default=20,
        help="Maximum number of results to validate",
    )
    parser.add_argument(
        "--api-url",
        default="http://localhost:8001",
        help="Base URL for the API",
    )
    parser.add_argument(
        "--ncbi-api-key", help="NCBI API key for higher rate limits"
    )
    parser.add_argument(
        "--disable-ssl-verify",
        action="store_true",
        help="Disable SSL verification (use with caution)",
    )

    args = parser.parse_args()

    validator = GSEContentValidator(
        base_url=args.api_url,
        ncbi_api_key=args.ncbi_api_key,
        disable_ssl_verify=args.disable_ssl_verify,
    )

    try:
        if args.query:
            logger.info(f"Validating search results for query: {args.query}")
            report = await validator.validate_by_query(
                args.query, args.max_results
            )
            validator.print_summary(report)
        elif args.gse_id:
            logger.info(f"Validating specific GSE ID: {args.gse_id}")
            validation = await validator.validate_gse_id(args.gse_id)

            print("\n" + "=" * 80)
            print(f"CONTENT VALIDATION RESULT FOR GSE ID: {args.gse_id}")
            print("=" * 80)
            print(f"\nExists in NCBI GEO: {validation['exists_in_geo']}")

            if validation["exists_in_geo"]:
                print(
                    f"NCBI Title: {validation.get('ncbi_data', {}).get('title', 'N/A')}"
                )
                print(
                    f"NCBI Organism: {validation.get('ncbi_data', {}).get('organism', 'N/A')}"
                )

                if validation.get("our_data"):
                    print(
                        f"\nTitle similarity: {validation.get('title_similarity', 0)*100:.1f}%"
                    )
                    print(
                        f"Our Title: {validation.get('our_data', {}).get('title', 'N/A')}"
                    )

            print(f"\nVerdict: {validation.get('verdict', 'UNKNOWN')}")

            if validation["issues"]:
                print(f"Issues: {', '.join(validation['issues'])}")

            print("\n" + "=" * 80)

            # Save single validation result
            filename = f"{validator.output_dir}/content_validation_single_{args.gse_id}_{validator.timestamp}.json"
            with open(filename, "w") as f:
                json.dump(validation, f, indent=2)

            logger.info(f"Single validation result saved to {filename}")
        elif args.file_path:
            logger.info(f"Validating results from file: {args.file_path}")
            report = await validator.validate_from_file(args.file_path)
            validator.print_summary(report)
    finally:
        await validator.close_session()


if __name__ == "__main__":
    asyncio.run(main())
