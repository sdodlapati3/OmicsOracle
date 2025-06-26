#!/usr/bin/env python3
"""
OmicsOracle Data Integrity Validator

This script is designed to comprehensively validate data integrity between:
1. What's in NCBI GEO (ground truth)
2. What's displayed in the OmicsOracle interface

It can validate specific GSE IDs, a batch of GSE IDs, or all results from a search query.
The script reports any mismatches, incorrect content mappings, or cases where COVID-19
or other terms appear in OmicsOracle but not in the original NCBI GEO data.

Usage:
    python validate_data_integrity.py --gse-id GSE278726
    python validate_data_integrity.py --gse-ids GSE278726,GSE123456,GSE654321
    python validate_data_integrity.py --query "cancer"
    python validate_data_integrity.py --random-sample 10
"""

import argparse
import asyncio
import json
import logging
import os
import random
import re
import ssl
import sys
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

import aiohttp

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("data_integrity_validation.log"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("data_integrity_validator")


class DataIntegrityValidator:
    def __init__(
        self,
        api_url="http://localhost:8001",
        ncbi_api_key=None,
        disable_ssl_verify=False,
    ):
        self.api_url = api_url
        self.ncbi_api_key = ncbi_api_key
        self.disable_ssl_verify = disable_ssl_verify
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = "integrity_reports"
        os.makedirs(self.report_dir, exist_ok=True)

        # Keywords to check for content mismatches
        self.content_keywords = {
            "covid": [
                "covid",
                "covid-19",
                "sars-cov-2",
                "coronavirus",
                "pandemic",
            ],
            "cancer": ["cancer", "tumor", "oncology", "malignant", "carcinoma"],
            "diabetes": ["diabetes", "insulin", "glucose", "pancreatic"],
            "alzheimer": [
                "alzheimer",
                "dementia",
                "neurodegenerative",
                "cognitive decline",
            ],
            "cardiac": ["heart", "cardiac", "cardiovascular", "myocardial"],
        }

        # Initialize session
        self.session = None
        self.ncbi_cache = {}  # Cache for NCBI data

        logger.info(
            f"Data Integrity Validator initialized with API URL: {self.api_url}"
        )
        if self.disable_ssl_verify:
            logger.warning("SSL verification is disabled - use with caution!")

    async def init_session(self):
        """Initialize aiohttp session with proper SSL configuration"""
        if self.session is None:
            # Configure SSL appropriately
            if self.disable_ssl_verify:
                connector = aiohttp.TCPConnector(ssl=False)
                logger.warning("Using insecure SSL connection")
            else:
                try:
                    import certifi

                    ssl_context = ssl.create_default_context(
                        cafile=certifi.where()
                    )
                    connector = aiohttp.TCPConnector(ssl=ssl_context)
                except ImportError:
                    logger.warning(
                        "certifi not found, using default SSL context"
                    )
                    connector = aiohttp.TCPConnector(ssl=True)

            # Create session with a reasonable timeout
            timeout = aiohttp.ClientTimeout(total=60)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    "User-Agent": "OmicsOracle-IntegrityValidator/1.0",
                    "Accept": "application/json",
                },
            )

    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None

    async def validate_gse_id(self, gse_id: str) -> Dict[str, Any]:
        """
        Validate data integrity for a specific GSE ID
        """
        await self.init_session()

        # Normalize GSE ID format
        if not gse_id.startswith("GSE"):
            gse_id = f"GSE{gse_id}"

        logger.info(f"Validating data integrity for {gse_id}")

        # Initialize result structure
        result = {
            "gse_id": gse_id,
            "timestamp": self.timestamp,
            "ncbi_data": None,
            "our_data": None,
            "exists_in_ncbi": False,
            "found_in_our_system": False,
            "title_match": False,
            "title_similarity": 0.0,
            "summary_match": False,
            "summary_similarity": 0.0,
            "organism_match": False,
            "content_keyword_mismatches": [],
            "issues": [],
            "verdict": "UNKNOWN",
        }

        # Get NCBI data (ground truth)
        ncbi_data = await self.fetch_from_ncbi(gse_id)
        result["ncbi_data"] = ncbi_data

        if not ncbi_data or "error" in ncbi_data:
            result["exists_in_ncbi"] = False
            result["issues"].append(f"GSE ID {gse_id} not found in NCBI GEO")
            result["verdict"] = "NOT_FOUND_IN_NCBI"
            return result

        result["exists_in_ncbi"] = True

        # Get data from our system
        our_data = await self.fetch_from_our_system(gse_id)
        result["our_data"] = our_data

        if not our_data or "error" in our_data:
            result["found_in_our_system"] = False
            result["issues"].append(f"GSE ID {gse_id} not found in our system")
            result["verdict"] = "NOT_FOUND_IN_OUR_SYSTEM"
            return result

        result["found_in_our_system"] = True

        # Compare title
        ncbi_title = ncbi_data.get("title", "").strip()
        our_title = our_data.get("title", "").strip()

        if ncbi_title and our_title:
            title_similarity = self.calculate_text_similarity(
                ncbi_title, our_title
            )
            result["title_similarity"] = title_similarity

            if title_similarity > 0.9:  # 90% similar
                result["title_match"] = True
            elif title_similarity < 0.5:  # Less than 50% similar
                result["issues"].append(
                    f"Title mismatch (similarity: {title_similarity:.2f})"
                )
                result["issues"].append(f"NCBI title: {ncbi_title}")
                result["issues"].append(f"Our title: {our_title}")

        # Compare summary
        ncbi_summary = ncbi_data.get("summary", "").strip()
        our_summary = our_data.get("summary", "").strip()

        if ncbi_summary and our_summary:
            summary_similarity = self.calculate_text_similarity(
                ncbi_summary, our_summary
            )
            result["summary_similarity"] = summary_similarity

            if summary_similarity > 0.7:  # 70% similar
                result["summary_match"] = True
            elif summary_similarity < 0.3:  # Less than 30% similar
                result["issues"].append(
                    f"Summary mismatch (similarity: {summary_similarity:.2f})"
                )

        # Compare organism
        ncbi_organism = ncbi_data.get("organism", "").lower().strip()
        our_organism = our_data.get("organism", "").lower().strip()

        if ncbi_organism and our_organism:
            if (
                ncbi_organism == our_organism
                or ncbi_organism in our_organism
                or our_organism in ncbi_organism
            ):
                result["organism_match"] = True
            else:
                result["issues"].append(
                    f"Organism mismatch: '{ncbi_organism}' vs '{our_organism}'"
                )

        # Check for content keyword mismatches
        for category, keywords in self.content_keywords.items():
            # Check if keywords are in our data but not in NCBI data
            in_our_data = any(
                kw in our_title.lower()
                or (our_summary and kw in our_summary.lower())
                for kw in keywords
            )
            in_ncbi_data = any(
                kw in ncbi_title.lower()
                or (ncbi_summary and kw in ncbi_summary.lower())
                for kw in keywords
            )

            if in_our_data and not in_ncbi_data:
                mismatch = {
                    "category": category,
                    "keywords_matched": [
                        kw
                        for kw in keywords
                        if kw in our_title.lower()
                        or (our_summary and kw in our_summary.lower())
                    ],
                    "severity": "CRITICAL" if category == "covid" else "HIGH",
                }
                result["content_keyword_mismatches"].append(mismatch)
                result["issues"].append(
                    f"CRITICAL: {category} content mismatch - our data mentions {category} but NCBI data does not"
                )

        # Determine overall verdict
        if (
            result["title_match"]
            and result["organism_match"]
            and not result["content_keyword_mismatches"]
        ):
            result["verdict"] = "MATCH"
        elif result["content_keyword_mismatches"]:
            result["verdict"] = "CONTENT_MISMATCH"
        elif not result["title_match"]:
            result["verdict"] = "TITLE_MISMATCH"
        else:
            result["verdict"] = "PARTIAL_MATCH"

        return result

    async def validate_multiple_gse_ids(
        self, gse_ids: List[str]
    ) -> Dict[str, Any]:
        """
        Validate data integrity for multiple GSE IDs
        """
        results = []
        for gse_id in gse_ids:
            try:
                result = await self.validate_gse_id(gse_id)
                results.append(result)
                # Be nice to the APIs - add a small delay
                await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"Error validating {gse_id}: {str(e)}")
                results.append(
                    {"gse_id": gse_id, "error": str(e), "verdict": "ERROR"}
                )

        # Generate summary
        summary = self.generate_summary(results)

        # Prepare report
        report = {
            "timestamp": self.timestamp,
            "gse_ids": gse_ids,
            "results": results,
            "summary": summary,
        }

        # Save report
        filename = (
            f"{self.report_dir}/integrity_report_multiple_{self.timestamp}.json"
        )
        with open(filename, "w") as f:
            json.dump(report, f, indent=2)

        logger.info(f"Multiple GSE validation report saved to {filename}")

        return report

    async def validate_search_query(
        self, query: str, max_results: int = 20
    ) -> Dict[str, Any]:
        """
        Validate data integrity for all results from a search query
        """
        await self.init_session()

        logger.info(f"Validating data integrity for search query: '{query}'")

        # Get search results
        search_results = await self.search_our_system(query, max_results)

        if (
            not search_results
            or "results" not in search_results
            or not search_results["results"]
        ):
            logger.error(f"No results found for query: '{query}'")
            return {
                "error": f"No results found for query: '{query}'",
                "query": query,
                "timestamp": self.timestamp,
            }

        # Extract GSE IDs
        gse_ids = []
        for result in search_results["results"]:
            gse_id = result.get("geo_id")
            if gse_id:
                gse_ids.append(gse_id)

        # Validate each GSE ID
        return await self.validate_multiple_gse_ids(gse_ids)

    async def fetch_from_ncbi(self, gse_id: str) -> Dict[str, Any]:
        """
        Fetch data from NCBI GEO for a GSE ID
        """
        # Check cache first
        if gse_id in self.ncbi_cache:
            return self.ncbi_cache[gse_id]

        try:
            # First try Entrez eUtils API
            entrez_data = await self.fetch_from_entrez(gse_id)
            if entrez_data and "error" not in entrez_data:
                self.ncbi_cache[gse_id] = entrez_data
                return entrez_data

            # Fallback to direct GEO fetch
            geo_data = await self.fetch_from_geo_direct(gse_id)
            if geo_data and "error" not in geo_data:
                self.ncbi_cache[gse_id] = geo_data
                return geo_data

            return {"error": f"Could not fetch data for {gse_id} from NCBI"}

        except Exception as e:
            logger.error(f"Error fetching from NCBI for {gse_id}: {str(e)}")
            return {"error": str(e)}

    async def fetch_from_entrez(self, gse_id: str) -> Dict[str, Any]:
        """
        Fetch data from NCBI Entrez eUtils API
        """
        try:
            # First get the numeric ID using esearch
            esearch_url = (
                "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi"
            )
            esearch_params = {"db": "gds", "term": gse_id, "retmode": "json"}

            if self.ncbi_api_key:
                esearch_params["api_key"] = self.ncbi_api_key

            logger.info(f"Searching NCBI Entrez for {gse_id}")

            async with self.session.get(
                esearch_url, params=esearch_params
            ) as response:
                if response.status != 200:
                    return {
                        "error": f"Entrez API returned status {response.status}"
                    }

                search_data = await response.json()

                if (
                    "esearchresult" not in search_data
                    or "idlist" not in search_data["esearchresult"]
                ):
                    return {"error": "Invalid response from Entrez esearch"}

                id_list = search_data["esearchresult"]["idlist"]
                if not id_list:
                    return {"error": f"GSE ID {gse_id} not found in Entrez"}

                entrez_id = id_list[0]

            # Now get the full data with esummary
            esummary_url = (
                "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi"
            )
            esummary_params = {
                "db": "gds",
                "id": entrez_id,
                "retmode": "json",
                "version": "2.0",
            }

            if self.ncbi_api_key:
                esummary_params["api_key"] = self.ncbi_api_key

            logger.info(f"Fetching summary from NCBI Entrez for {gse_id}")

            async with self.session.get(
                esummary_url, params=esummary_params
            ) as response:
                if response.status != 200:
                    return {
                        "error": f"Entrez esummary API returned status {response.status}"
                    }

                data = await response.json()

                if "result" in data and str(entrez_id) in data["result"]:
                    entry = data["result"][str(entrez_id)]
                    return {
                        "title": entry.get("title", ""),
                        "summary": entry.get("summary", ""),
                        "organism": "; ".join(entry.get("organism", [])),
                        "accession": entry.get("accession", ""),
                        "geo_accession": gse_id,
                    }
                else:
                    return {
                        "error": "Invalid response format from Entrez esummary"
                    }

        except Exception as e:
            logger.error(f"Error in fetch_from_entrez for {gse_id}: {str(e)}")
            return {"error": str(e)}

    async def fetch_from_geo_direct(self, gse_id: str) -> Dict[str, Any]:
        """
        Fetch data directly from NCBI GEO
        """
        try:
            geo_url = "https://www.ncbi.nlm.nih.gov/geo/query/acc.cgi"
            params = {
                "acc": gse_id,
                "targ": "self",
                "form": "text",
                "view": "brief",
            }

            logger.info(f"Fetching directly from GEO for {gse_id}")

            async with self.session.get(geo_url, params=params) as response:
                if response.status != 200:
                    return {
                        "error": f"GEO API returned status {response.status}"
                    }

                text = await response.text()

                # Check if it's an error page
                if "Series does not exist" in text or "^SERIES =" not in text:
                    return {"error": f"GSE ID {gse_id} not found in GEO"}

                # Parse the text format
                data = {"geo_accession": gse_id}

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

                # Try different organism fields
                organism_fields = [
                    "!Series_organism",
                    "!Series_sample_organism",
                    "!Series_platform_organism",
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

                return data

        except Exception as e:
            logger.error(
                f"Error in fetch_from_geo_direct for {gse_id}: {str(e)}"
            )
            return {"error": str(e)}

    async def fetch_from_our_system(self, gse_id: str) -> Dict[str, Any]:
        """
        Fetch data from our system for a GSE ID
        """
        try:
            # Try direct search with the GSE ID
            search_results = await self.search_our_system(gse_id, 10)

            if (
                not search_results
                or "results" not in search_results
                or not search_results["results"]
            ):
                return {"error": f"GSE ID {gse_id} not found in our system"}

            # Find the exact match
            for result in search_results["results"]:
                if result.get("geo_id") == gse_id:
                    return result

            return {"error": f"GSE ID {gse_id} not found in results"}

        except Exception as e:
            logger.error(
                f"Error fetching from our system for {gse_id}: {str(e)}"
            )
            return {"error": str(e)}

    async def search_our_system(
        self, query: str, max_results: int = 20
    ) -> Dict[str, Any]:
        """
        Search our system with a query
        """
        try:
            logger.info(f"Searching OmicsOracle for: '{query}'")

            payload = {
                "query": query,
                "max_results": max_results,
                "search_type": "comprehensive",
                "disable_cache": True,
                "timestamp": int(time.time() * 1000),
            }

            async with self.session.post(
                f"{self.api_url}/api/search",
                headers={
                    "Content-Type": "application/json",
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                },
                json=payload,
                timeout=aiohttp.ClientTimeout(total=60),
            ) as response:
                if response.status != 200:
                    logger.error(
                        f"API returned status {response.status} for query: '{query}'"
                    )
                    return {"error": f"API returned status {response.status}"}

                data = await response.json()

                logger.info(
                    f"Found {len(data.get('results', []))} results for '{query}'"
                )
                return data

        except asyncio.TimeoutError:
            logger.error(f"Request timeout for query '{query}'")
            return {"error": f"Request timeout for query '{query}'"}
        except Exception as e:
            logger.error(f"Error searching our system for '{query}': {str(e)}")
            return {"error": str(e)}

    async def get_random_gse_ids(self, count: int = 10) -> List[str]:
        """
        Get a random sample of GSE IDs from our system
        """
        try:
            # Use common search terms to get a diverse set of results
            search_terms = [
                "cancer",
                "diabetes",
                "heart",
                "brain",
                "liver",
                "covid",
                "immune",
                "gene expression",
            ]
            all_gse_ids = set()

            for term in search_terms:
                results = await self.search_our_system(term, 20)
                if results and "results" in results:
                    for result in results["results"]:
                        gse_id = result.get("geo_id")
                        if gse_id and gse_id.startswith("GSE"):
                            all_gse_ids.add(gse_id)

                if len(all_gse_ids) >= count * 2:
                    break

            # Select a random sample
            sample = random.sample(
                list(all_gse_ids), min(count, len(all_gse_ids))
            )
            return sample

        except Exception as e:
            logger.error(f"Error getting random GSE IDs: {str(e)}")
            return []

    def calculate_text_similarity(self, text1: str, text2: str) -> float:
        """
        Calculate similarity between two text strings
        Using Jaccard similarity on word sets
        """
        if not text1 or not text2:
            return 0.0

        # Normalize and tokenize
        def normalize(text):
            text = text.lower()
            words = re.findall(r"\b\w+\b", text)
            return set(words)

        set1 = normalize(text1)
        set2 = normalize(text2)

        # Jaccard similarity: |A intersect B| / |A union B|
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))

        return intersection / union if union > 0 else 0.0

    def generate_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary of validation results
        """
        total = len(results)
        matches = sum(1 for r in results if r.get("verdict") == "MATCH")
        content_mismatches = sum(
            1 for r in results if r.get("verdict") == "CONTENT_MISMATCH"
        )
        title_mismatches = sum(
            1 for r in results if r.get("verdict") == "TITLE_MISMATCH"
        )
        partial_matches = sum(
            1 for r in results if r.get("verdict") == "PARTIAL_MATCH"
        )
        not_found_ncbi = sum(
            1 for r in results if r.get("verdict") == "NOT_FOUND_IN_NCBI"
        )
        not_found_our = sum(
            1 for r in results if r.get("verdict") == "NOT_FOUND_IN_OUR_SYSTEM"
        )
        errors = sum(1 for r in results if r.get("verdict") == "ERROR")

        # Calculate average similarities
        title_similarities = [
            r.get("title_similarity", 0)
            for r in results
            if r.get("exists_in_ncbi") and r.get("found_in_our_system")
        ]
        summary_similarities = [
            r.get("summary_similarity", 0)
            for r in results
            if r.get("exists_in_ncbi") and r.get("found_in_our_system")
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

        # Collect critical issues
        critical_issues = []
        for result in results:
            if result.get("content_keyword_mismatches"):
                for mismatch in result["content_keyword_mismatches"]:
                    if mismatch.get("severity") == "CRITICAL":
                        critical_issues.append(
                            {
                                "gse_id": result["gse_id"],
                                "category": mismatch["category"],
                                "keywords": mismatch["keywords_matched"],
                            }
                        )

        return {
            "total_validated": total,
            "matches": matches,
            "content_mismatches": content_mismatches,
            "title_mismatches": title_mismatches,
            "partial_matches": partial_matches,
            "not_found_in_ncbi": not_found_ncbi,
            "not_found_in_our_system": not_found_our,
            "errors": errors,
            "avg_title_similarity": avg_title_similarity,
            "avg_summary_similarity": avg_summary_similarity,
            "critical_issues_count": len(critical_issues),
            "critical_issues": critical_issues,
            "data_integrity_score": matches / total if total > 0 else 0,
        }

    def print_result(self, result: Dict[str, Any]) -> None:
        """
        Print a human-readable summary of a single validation result
        """
        print("\n" + "=" * 80)
        print(f"DATA INTEGRITY VALIDATION FOR {result['gse_id']}")
        print("=" * 80)

        print(f"\nVerdict: {result['verdict']}")

        if result["exists_in_ncbi"]:
            print(
                f"\nNCBI Title: {result.get('ncbi_data', {}).get('title', 'N/A')}"
            )

            if result["found_in_our_system"]:
                print(
                    f"Our Title: {result.get('our_data', {}).get('title', 'N/A')}"
                )
                print(
                    f"\nTitle Similarity: {result['title_similarity'] * 100:.1f}%"
                )
                print(
                    f"Summary Similarity: {result['summary_similarity'] * 100:.1f}%"
                )

                if result["content_keyword_mismatches"]:
                    print("\nContent Keyword Mismatches:")
                    for mismatch in result["content_keyword_mismatches"]:
                        print(
                            f"  - {mismatch['severity']}: {mismatch['category']} terms in our data but not in NCBI"
                        )
                        print(
                            f"    Keywords: {', '.join(mismatch['keywords_matched'])}"
                        )

        if result["issues"]:
            print("\nIssues:")
            for issue in result["issues"]:
                print(f"  - {issue}")

        print("\n" + "=" * 80)

    def print_summary(self, summary: Dict[str, Any]) -> None:
        """
        Print a human-readable summary of validation results
        """
        print("\n" + "=" * 80)
        print("DATA INTEGRITY VALIDATION SUMMARY")
        print("=" * 80)

        print(f"\nTotal GSE IDs validated: {summary['total_validated']}")
        print(
            f"Complete matches: {summary['matches']} ({summary['matches']/summary['total_validated']*100:.1f}%)"
        )
        print(
            f"Content mismatches: {summary['content_mismatches']} ({summary['content_mismatches']/summary['total_validated']*100:.1f}%)"
        )
        print(
            f"Title mismatches: {summary['title_mismatches']} ({summary['title_mismatches']/summary['total_validated']*100:.1f}%)"
        )
        print(
            f"Partial matches: {summary['partial_matches']} ({summary['partial_matches']/summary['total_validated']*100:.1f}%)"
        )

        print(
            f"\nAverage title similarity: {summary['avg_title_similarity']*100:.1f}%"
        )
        print(
            f"Average summary similarity: {summary['avg_summary_similarity']*100:.1f}%"
        )

        print(
            f"\nOverall data integrity score: {summary['data_integrity_score']*100:.1f}%"
        )

        if summary["critical_issues_count"] > 0:
            print("\nCRITICAL ISSUES DETECTED:")
            for issue in summary["critical_issues"]:
                print(
                    f"  - GSE ID {issue['gse_id']}: {issue['category']} terms detected"
                )
                print(f"    Keywords: {', '.join(issue['keywords'])}")

        print("\n" + "=" * 80)


async def main():
    parser = argparse.ArgumentParser(
        description="Validate data integrity between NCBI GEO and OmicsOracle"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--gse-id", help="Validate a specific GSE ID")
    group.add_argument(
        "--gse-ids", help="Validate multiple GSE IDs (comma-separated)"
    )
    group.add_argument(
        "--query", help="Validate all results from a search query"
    )
    group.add_argument(
        "--random-sample", type=int, help="Validate a random sample of GSE IDs"
    )

    parser.add_argument(
        "--max-results",
        type=int,
        default=20,
        help="Maximum number of results to validate for queries",
    )
    parser.add_argument(
        "--api-url",
        default="http://localhost:8001",
        help="URL for the OmicsOracle API",
    )
    parser.add_argument(
        "--ncbi-api-key", help="NCBI API key for higher rate limits"
    )
    parser.add_argument(
        "--disable-ssl-verify",
        action="store_true",
        help="Disable SSL verification",
    )

    args = parser.parse_args()

    validator = DataIntegrityValidator(
        api_url=args.api_url,
        ncbi_api_key=args.ncbi_api_key,
        disable_ssl_verify=args.disable_ssl_verify,
    )

    try:
        if args.gse_id:
            result = await validator.validate_gse_id(args.gse_id)
            validator.print_result(result)

            # Save result
            filename = f"{validator.report_dir}/integrity_single_{args.gse_id}_{validator.timestamp}.json"
            with open(filename, "w") as f:
                json.dump(result, f, indent=2)
            logger.info(f"Single validation result saved to {filename}")

        elif args.gse_ids:
            gse_ids = [gse_id.strip() for gse_id in args.gse_ids.split(",")]
            report = await validator.validate_multiple_gse_ids(gse_ids)
            validator.print_summary(report["summary"])

        elif args.query:
            report = await validator.validate_search_query(
                args.query, args.max_results
            )
            if "summary" in report:
                validator.print_summary(report["summary"])
            else:
                print(f"Error: {report.get('error', 'Unknown error')}")

        elif args.random_sample:
            gse_ids = await validator.get_random_gse_ids(args.random_sample)
            if not gse_ids:
                print("Error: Could not get random GSE IDs")
                return

            logger.info(f"Validating random sample of {len(gse_ids)} GSE IDs")
            report = await validator.validate_multiple_gse_ids(gse_ids)
            validator.print_summary(report["summary"])

    finally:
        await validator.close_session()


if __name__ == "__main__":
    asyncio.run(main())
