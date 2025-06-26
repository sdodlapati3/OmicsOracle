#!/usr/bin/env python3
"""
Search Result Data Integrity Validator

This script validates data integrity between search results and NCBI GEO.
It focuses on detecting:
1. GSE ID content mismatches in search results
2. Title/content swaps between different GSE IDs
3. COVID-19 content appearing where it shouldn't

Usage:
    python validate_search_results.py --query "chromatin accessibility heart"
    python validate_search_results.py --gse-ids GSE278726,GSE291262,GSE291260
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
from typing import Any, Dict, List, Optional, Set

import aiohttp

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("search_validation.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("search_validator")

class SearchResultValidator:
    def __init__(self, api_url="http://localhost:8001", ncbi_api_key=None, disable_ssl_verify=False, timeout=60):
        self.api_url = api_url
        self.ncbi_api_key = ncbi_api_key
        self.disable_ssl_verify = disable_ssl_verify
        self.request_timeout = timeout
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.report_dir = "search_validation_reports"
        os.makedirs(self.report_dir, exist_ok=True)

        # Keywords to check for content mismatches
        self.content_keywords = {
            "covid": ["covid", "covid-19", "sars-cov-2", "coronavirus", "pandemic"],
            "cancer": ["cancer", "tumor", "oncology", "malignant", "carcinoma"],
            "diabetes": ["diabetes", "insulin", "glucose", "pancreatic"],
            "alzheimer": ["alzheimer", "dementia", "neurodegenerative", "cognitive decline"],
            "cardiac": ["heart", "cardiac", "cardiovascular", "myocardial"],
            "schizophrenia": ["schizophrenia", "psychosis", "psychiatric", "mental illness"]
        }

        # Initialize session
        self.session = None
        self.ncbi_cache = {}  # Cache for NCBI data

        logger.info(f"Search Result Validator initialized with API URL: {self.api_url}")
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
                    ssl_context = ssl.create_default_context(cafile=certifi.where())
                    connector = aiohttp.TCPConnector(ssl=ssl_context)
                except ImportError:
                    logger.warning("certifi not found, using default SSL context")
                    connector = aiohttp.TCPConnector(ssl=True)

            # Create session with a reasonable timeout
            timeout = aiohttp.ClientTimeout(total=self.request_timeout)
            self.session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers={
                    'User-Agent': 'OmicsOracle-SearchValidator/1.0',
                    'Accept': 'application/json'
                }
            )

    async def close_session(self):
        """Close aiohttp session"""
        if self.session:
            await self.session.close()
            self.session = None

    async def validate_search_results(self, query: str, max_results: int = 20) -> Dict[str, Any]:
        """
        Validate search results for a given query
        """
        await self.init_session()

        logger.info(f"Validating search results for query: '{query}'")

        # Get search results
        search_results = await self.search_our_system(query, max_results)

        if not search_results or "results" not in search_results:
            logger.error(f"No results returned for query: '{query}'")
            return {"error": f"No results returned for query: '{query}'"}

        # Validate each GSE ID in the results against NCBI
        validation_results = []

        for i, result in enumerate(search_results["results"]):
            gse_id = result.get("geo_id")
            if not gse_id:
                logger.warning(f"Result {i} missing GSE ID")
                continue

            logger.info(f"Validating GSE ID: {gse_id} ({i+1}/{len(search_results['results'])})")

            # Get NCBI data for this GSE ID
            ncbi_data = await self.fetch_from_ncbi(gse_id)

            # Validate the result
            validation = {
                "gse_id": gse_id,
                "position": i + 1,
                "exists_in_ncbi": bool(ncbi_data and "error" not in ncbi_data),
                "our_title": result.get("title", ""),
                "ncbi_title": ncbi_data.get("title", "") if ncbi_data else "",
                "title_match": False,
                "title_similarity": 0.0,
                "content_keyword_mismatches": [],
                "issues": []
            }

            # Check if it exists in NCBI
            if not validation["exists_in_ncbi"]:
                validation["issues"].append(f"GSE ID {gse_id} not found in NCBI GEO")
                validation["verdict"] = "NOT_FOUND_IN_NCBI"
                validation_results.append(validation)
                continue

            # Compare titles
            our_title = result.get("title", "").strip()
            ncbi_title = ncbi_data.get("title", "").strip()

            if our_title and ncbi_title:
                title_similarity = self.calculate_text_similarity(our_title, ncbi_title)
                validation["title_similarity"] = title_similarity

                if title_similarity > 0.9:  # 90% similar
                    validation["title_match"] = True
                else:
                    validation["title_match"] = False
                    validation["issues"].append(f"Title mismatch (similarity: {title_similarity:.2f})")
                    validation["issues"].append(f"Our title: {our_title}")
                    validation["issues"].append(f"NCBI title: {ncbi_title}")

            # Check for content keyword mismatches
            for category, keywords in self.content_keywords.items():
                # Check if keywords are in our data but not in NCBI data
                in_our_data = any(kw in our_title.lower() or (result.get("summary", "") and kw in result.get("summary", "").lower()) for kw in keywords)
                in_ncbi_data = any(kw in ncbi_title.lower() or (ncbi_data.get("summary", "") and kw in ncbi_data.get("summary", "").lower()) for kw in keywords)

                if in_our_data and not in_ncbi_data:
                    mismatch = {
                        "category": category,
                        "keywords_matched": [kw for kw in keywords if kw in our_title.lower() or (result.get("summary", "") and kw in result.get("summary", "").lower())],
                        "severity": "CRITICAL" if category == "covid" else "HIGH"
                    }
                    validation["content_keyword_mismatches"].append(mismatch)
                    validation["issues"].append(f"CRITICAL: {category} content mismatch - our data mentions {category} but NCBI data does not")

            # Determine verdict
            if validation["title_match"] and not validation["content_keyword_mismatches"]:
                validation["verdict"] = "MATCH"
            elif validation["content_keyword_mismatches"]:
                validation["verdict"] = "CONTENT_MISMATCH"
            else:
                validation["verdict"] = "TITLE_MISMATCH"

            validation_results.append(validation)

            # Be nice to NCBI API - don't hammer it
            await asyncio.sleep(1)

        # Check for any GSE ID swaps
        gse_swaps = self.check_for_gse_swaps(validation_results)

        # Generate report
        report = {
            "query": query,
            "timestamp": self.timestamp,
            "results_count": len(search_results["results"]),
            "validation_results": validation_results,
            "gse_swaps": gse_swaps,
            "summary": self.generate_summary(validation_results, gse_swaps)
        }

        # Save report
        filename = f"{self.report_dir}/search_validation_{self.timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"Search validation report saved to {filename}")

        return report

    async def validate_specific_gse_ids(self, gse_ids: List[str]) -> Dict[str, Any]:
        """
        Validate specific GSE IDs in search results
        """
        await self.init_session()

        logger.info(f"Validating specific GSE IDs: {', '.join(gse_ids)}")

        # For each GSE ID:
        # 1. Search for it directly
        # 2. Check if it appears with correct content

        validation_results = []

        for gse_id in gse_ids:
            logger.info(f"Validating GSE ID: {gse_id}")

            # Get NCBI data for this GSE ID (ground truth)
            ncbi_data = await self.fetch_from_ncbi(gse_id)

            # Search for this GSE ID
            search_results = await self.search_our_system(gse_id, max_results=10)

            validation = {
                "gse_id": gse_id,
                "exists_in_ncbi": bool(ncbi_data and "error" not in ncbi_data),
                "ncbi_title": ncbi_data.get("title", "") if ncbi_data else "",
                "found_in_search": False,
                "search_title": "",
                "title_match": False,
                "title_similarity": 0.0,
                "content_keyword_mismatches": [],
                "issues": []
            }

            # Check if it exists in NCBI
            if not validation["exists_in_ncbi"]:
                validation["issues"].append(f"GSE ID {gse_id} not found in NCBI GEO")
                validation["verdict"] = "NOT_FOUND_IN_NCBI"
                validation_results.append(validation)
                continue

            # Check if it's in the search results
            found_result = None
            for result in search_results.get("results", []):
                if result.get("geo_id") == gse_id:
                    found_result = result
                    break

            if not found_result:
                validation["issues"].append(f"GSE ID {gse_id} not found in search results")
                validation["verdict"] = "NOT_FOUND_IN_SEARCH"
                validation_results.append(validation)
                continue

            validation["found_in_search"] = True
            validation["search_title"] = found_result.get("title", "")

            # Compare titles
            our_title = found_result.get("title", "").strip()
            ncbi_title = ncbi_data.get("title", "").strip()

            if our_title and ncbi_title:
                title_similarity = self.calculate_text_similarity(our_title, ncbi_title)
                validation["title_similarity"] = title_similarity

                if title_similarity > 0.9:  # 90% similar
                    validation["title_match"] = True
                else:
                    validation["title_match"] = False
                    validation["issues"].append(f"Title mismatch (similarity: {title_similarity:.2f})")
                    validation["issues"].append(f"Our title: {our_title}")
                    validation["issues"].append(f"NCBI title: {ncbi_title}")

            # Check for content keyword mismatches
            for category, keywords in self.content_keywords.items():
                # Check if keywords are in our data but not in NCBI data
                in_our_data = any(kw in our_title.lower() or (found_result.get("summary", "") and kw in found_result.get("summary", "").lower()) for kw in keywords)
                in_ncbi_data = any(kw in ncbi_title.lower() or (ncbi_data.get("summary", "") and kw in ncbi_data.get("summary", "").lower()) for kw in keywords)

                if in_our_data and not in_ncbi_data:
                    mismatch = {
                        "category": category,
                        "keywords_matched": [kw for kw in keywords if kw in our_title.lower() or (found_result.get("summary", "") and kw in found_result.get("summary", "").lower())],
                        "severity": "CRITICAL" if category == "covid" else "HIGH"
                    }
                    validation["content_keyword_mismatches"].append(mismatch)
                    validation["issues"].append(f"CRITICAL: {category} content mismatch - our data mentions {category} but NCBI data does not")

            # Determine verdict
            if validation["title_match"] and not validation["content_keyword_mismatches"]:
                validation["verdict"] = "MATCH"
            elif validation["content_keyword_mismatches"]:
                validation["verdict"] = "CONTENT_MISMATCH"
            else:
                validation["verdict"] = "TITLE_MISMATCH"

            validation_results.append(validation)

            # Be nice to NCBI API - don't hammer it
            await asyncio.sleep(1)

        # Search for all GSE IDs together to check for cross-contamination
        combined_query = " OR ".join(gse_ids)
        combined_results = await self.search_our_system(combined_query, max_results=len(gse_ids) * 2)

        # Check for GSE ID swaps
        gse_swaps = []

        if combined_results and "results" in combined_results:
            # Build a mapping of GSE IDs to titles from NCBI data
            ncbi_titles = {}
            for gse_id in gse_ids:
                ncbi_data = await self.fetch_from_ncbi(gse_id)
                if ncbi_data and "error" not in ncbi_data:
                    ncbi_titles[gse_id] = ncbi_data.get("title", "")

            # Check if any GSE ID has another's title
            for result in combined_results["results"]:
                result_gse_id = result.get("geo_id")
                result_title = result.get("title", "")

                if not result_gse_id or result_gse_id not in gse_ids:
                    continue

                for gse_id, ncbi_title in ncbi_titles.items():
                    if gse_id != result_gse_id and self.calculate_text_similarity(result_title, ncbi_title) > 0.9:
                        gse_swaps.append({
                            "gse_id": result_gse_id,
                            "has_title_from": gse_id,
                            "displayed_title": result_title,
                            "correct_title": ncbi_titles.get(result_gse_id, "Unknown")
                        })

        # Generate report
        report = {
            "gse_ids": gse_ids,
            "timestamp": self.timestamp,
            "validation_results": validation_results,
            "gse_swaps": gse_swaps,
            "summary": self.generate_summary(validation_results, gse_swaps)
        }

        # Save report
        filename = f"{self.report_dir}/gse_ids_validation_{self.timestamp}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)

        logger.info(f"GSE IDs validation report saved to {filename}")

        return report

    def check_for_gse_swaps(self, validation_results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Check if any GSE IDs have swapped titles/content with others
        """
        swaps = []

        # For each GSE ID with a title mismatch, check if its title matches another GSE ID's NCBI title
        for i, result1 in enumerate(validation_results):
            if result1["verdict"] != "TITLE_MISMATCH":
                continue

            our_title = result1["our_title"]

            for j, result2 in enumerate(validation_results):
                if i == j:
                    continue

                if self.calculate_text_similarity(our_title, result2["ncbi_title"]) > 0.9:
                    swaps.append({
                        "gse_id": result1["gse_id"],
                        "has_title_from": result2["gse_id"],
                        "displayed_title": our_title,
                        "correct_title": result1["ncbi_title"]
                    })
                    break

        return swaps

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
            words = re.findall(r'\b\w+\b', text)
            return set(words)

        set1 = normalize(text1)
        set2 = normalize(text2)

        # Calculate Jaccard similarity: |A intersect B| / |A union B|
        intersection = len(set1.intersection(set2))
        union = len(set1.union(set2))

        return intersection / union if union > 0 else 0.0

    def generate_summary(self, validation_results: List[Dict[str, Any]], gse_swaps: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a summary of validation results
        """
        if not validation_results:
            return {"error": "No validation results"}

        # Count different verdicts
        matches = sum(1 for v in validation_results if v.get("verdict") == "MATCH")
        content_mismatches = sum(1 for v in validation_results if v.get("verdict") == "CONTENT_MISMATCH")
        title_mismatches = sum(1 for v in validation_results if v.get("verdict") == "TITLE_MISMATCH")
        not_found_in_ncbi = sum(1 for v in validation_results if v.get("verdict") == "NOT_FOUND_IN_NCBI")
        not_found_in_search = sum(1 for v in validation_results if v.get("verdict") == "NOT_FOUND_IN_SEARCH")

        # Count keyword categories
        keyword_categories = {}
        for v in validation_results:
            for mismatch in v.get("content_keyword_mismatches", []):
                category = mismatch.get("category")
                if category:
                    keyword_categories[category] = keyword_categories.get(category, 0) + 1

        # Calculate average title similarity
        avg_title_similarity = sum(v.get("title_similarity", 0) for v in validation_results) / len(validation_results)

        # Generate list of critical issues
        critical_issues = []
        for v in validation_results:
            for mismatch in v.get("content_keyword_mismatches", []):
                if mismatch.get("severity") == "CRITICAL":
                    critical_issues.append({
                        "gse_id": v["gse_id"],
                        "category": mismatch.get("category", "unknown"),
                        "keywords": mismatch.get("keywords_matched", [])
                    })

        # Calculate data integrity score (0-1)
        total = len(validation_results)
        data_integrity_score = matches / total if total > 0 else 0

        return {
            "total_validated": total,
            "matches": matches,
            "content_mismatches": content_mismatches,
            "title_mismatches": title_mismatches,
            "not_found_in_ncbi": not_found_in_ncbi,
            "not_found_in_search": not_found_in_search,
            "gse_swaps_count": len(gse_swaps),
            "keyword_categories": keyword_categories,
            "avg_title_similarity": avg_title_similarity,
            "critical_issues_count": len(critical_issues),
            "critical_issues": critical_issues,
            "data_integrity_score": data_integrity_score
        }

    async def search_our_system(self, query: str, max_results: int = 20) -> Dict[str, Any]:
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
                "timestamp": int(time.time() * 1000)
            }

            try:
                timeout = aiohttp.ClientTimeout(total=self.request_timeout)
            async with self.session.post(
                f"{self.api_url}/api/search",
                headers={
                    "Content-Type": "application/json",
                    "Cache-Control": "no-cache, no-store, must-revalidate"
                },
                json=payload,
                timeout=timeout
            ) as response:
                if response.status != 200:
                    logger.error(f"API returned status {response.status} for query: '{query}'")
                    return {"error": f"API returned status {response.status}"}

                data = await response.json()

                logger.info(f"Found {len(data.get('results', []))} results for '{query}'")
                return data
    except asyncio.TimeoutError:
        logger.error(f"Search timed out after {timeout.total} seconds for query: '{query}'")
        return {"error": f"Search timed out after {timeout.total} seconds", "timeout": True}

        except Exception as e:
            logger.error(f"Error searching our system for '{query}': {str(e)}")
            return {"error": str(e)}

    async def fetch_from_ncbi(self, gse_id: str) -> Dict[str, Any]:
        """
        Fetch data from NCBI GEO for a GSE ID
        """
        # Check cache first
        if gse_id in self.ncbi_cache:
            return self.ncbi_cache[gse_id]

        try:
            logger.info(f"Searching NCBI Entrez for {gse_id}")

            # First try esearch to get the correct ID
            esearch_url = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esearch.fcgi"

            esearch_params = {
                "db": "gds",  # GEO DataSets
                "term": gse_id,
                "retmode": "json"
            }

            if self.ncbi_api_key:
                esearch_params["api_key"] = self.ncbi_api_key

            async with self.session.get(esearch_url, params=esearch_params) as response:
                if response.status != 200:
                    logger.error(f"NCBI Entrez esearch API returned status {response.status}")
                    return {"error": f"NCBI Entrez esearch API returned status {response.status}"}

                search_data = await response.json()

                if "esearchresult" not in search_data or "idlist" not in search_data["esearchresult"]:
                    logger.error(f"No results found for {gse_id} in Entrez esearch")
                    return {"error": f"No results found for {gse_id} in Entrez"}

                id_list = search_data["esearchresult"]["idlist"]
                if not id_list:
                    logger.error(f"Empty ID list for {gse_id} in Entrez esearch")
                    return {"error": f"Empty ID list for {gse_id} in Entrez"}

                entrez_id = id_list[0]

            # Now fetch the summary with the correct ID
            logger.info(f"Fetching summary from NCBI Entrez for {gse_id}")
            entrez_url = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/esummary.fcgi"

            params = {
                "db": "gds",  # GEO DataSets
                "id": entrez_id,
                "retmode": "json",
                "version": "2.0"
            }

            if self.ncbi_api_key:
                params["api_key"] = self.ncbi_api_key

            async with self.session.get(entrez_url, params=params) as response:
                if response.status != 200:
                    logger.error(f"NCBI Entrez API returned status {response.status}")
                    return {"error": f"NCBI Entrez API returned status {response.status}"}

                data = await response.json()

                # Process Entrez response
                if "result" in data:
                    result = data["result"]
                    if str(entrez_id) in result:
                        entry = result[str(entrez_id)]
                        ncbi_data = {
                            "title": entry.get("title", ""),
                            "summary": entry.get("summary", ""),
                            "organism": "; ".join(entry.get("organism", [])),
                            "entrytype": entry.get("entrytype", ""),
                            "accession": entry.get("accession", ""),
                            "geo_accession": entry.get("accession", "")
                        }

                        # Cache the result
                        self.ncbi_cache[gse_id] = ncbi_data

                        return ncbi_data

                return {"error": "Could not parse Entrez response"}

        except Exception as e:
            logger.error(f"Error fetching from NCBI for {gse_id}: {str(e)}")
            return {"error": str(e)}

    def print_summary(self, summary: Dict[str, Any]) -> None:
        """
        Print a human-readable summary of validation results
        """
        print("\n" + "="*80)
        print(f"SEARCH RESULTS VALIDATION SUMMARY")
        print("="*80)

        print(f"\nTotal GSE IDs validated: {summary['total_validated']}")
        print(f"Matches: {summary['matches']} ({summary['matches']/summary['total_validated']*100:.1f}%)")
        print(f"Content mismatches: {summary['content_mismatches']} ({summary['content_mismatches']/summary['total_validated']*100:.1f}%)")
        print(f"Title mismatches: {summary['title_mismatches']} ({summary['title_mismatches']/summary['total_validated']*100:.1f}%)")

        if summary['gse_swaps_count'] > 0:
            print(f"\nGSE ID swaps detected: {summary['gse_swaps_count']}")

        if summary['critical_issues_count'] > 0:
            print("\nCRITICAL ISSUES DETECTED:")
            for issue in summary['critical_issues']:
                print(f"  - GSE ID {issue['gse_id']}: {issue['category']} terms detected")
                print(f"    Keywords: {', '.join(issue['keywords'])}")

        print(f"\nAverage title similarity: {summary['avg_title_similarity']*100:.1f}%")
        print(f"Overall data integrity score: {summary['data_integrity_score']*100:.1f}%")

        print("\n" + "="*80)


async def main():
    parser = argparse.ArgumentParser(description="Validate search results for data integrity")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--query", help="Validate search results for a query")
    group.add_argument("--gse-ids", help="Validate specific GSE IDs (comma-separated)")

    parser.add_argument("--max-results", type=int, default=20, help="Maximum number of results to validate for queries")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout in seconds for API requests")
    parser.add_argument("--api-url", default="http://localhost:8001", help="URL for the OmicsOracle API")
    parser.add_argument("--ncbi-api-key", help="NCBI API key for higher rate limits")
    parser.add_argument("--disable-ssl-verify", action="store_true", help="Disable SSL verification")

    args = parser.parse_args()

    validator = SearchResultValidator(
        api_url=args.api_url,
        ncbi_api_key=args.ncbi_api_key,
        disable_ssl_verify=args.disable_ssl_verify,
        timeout=args.timeout
    )

    try:
        if args.query:
            logger.info(f"Validating search results for query: {args.query}")
            report = await validator.validate_search_results(args.query, args.max_results)
            if "summary" in report:
                validator.print_summary(report["summary"])
            else:
                print("\n" + "="*80)
                print(f"SEARCH VALIDATION ERROR")
                print("="*80)
                print(f"\nError: {report.get('error', 'Unknown error')}")
                if report.get('timeout'):
                    print(f"The search query timed out. This could indicate:")
                    print(f" - Search server performance issues")
                    print(f" - Misconfigured search functionality")
                    print(f" - Connection problems between services")
                print("\n" + "="*80)

        elif args.gse_ids:
            gse_ids = [gse_id.strip() for gse_id in args.gse_ids.split(",")]
            logger.info(f"Validating specific GSE IDs: {', '.join(gse_ids)}")
            report = await validator.validate_specific_gse_ids(gse_ids)
            if "summary" in report:
                validator.print_summary(report["summary"])
            else:
                print("\n" + "="*80)
                print(f"GSE ID VALIDATION ERROR")
                print("="*80)
                print(f"\nError: {report.get('error', 'Unknown error')}")
                if report.get('timeout'):
                    print(f"The validation timed out. This could indicate API connectivity issues.")
                print("\n" + "="*80)

    finally:
        await validator.close_session()

if __name__ == "__main__":
    asyncio.run(main())
