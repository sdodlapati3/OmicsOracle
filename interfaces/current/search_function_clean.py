# Clean search function to replace the corrupted one

@app.post("/search")
async def search(
    query: str = Form(...),
    max_results: int = Form(10),
    page: int = Form(1),
    page_size: int = Form(10),
):
    """Handle search requests with pagination support"""
    try:
        # Calculate pagination parameters
        offset = (page - 1) * page_size

        logger.info(
            f"Search request: '{query}' (page: {page}, page_size: {page_size}, offset: {offset})"
        )

        # Update search analytics
        update_search_analytics(query)

        if OMICS_AVAILABLE and pipeline:
            # Use real OmicsOracle pipeline
            try:
                # Run the search with extended results for pagination
                all_results = await pipeline.process_query(
                    query, max_results=min(max_results * 2, 100)
                )

                logger.info(
                    f"Pipeline returned {len(all_results.metadata)} results"
                )

                # Process results
                processed_results = []
                organism_patterns = {
                    r"\b(homo sapiens|human|hsa)\b": "Homo sapiens",
                    r"\b(mus musculus|mouse|mmu)\b": "Mus musculus", 
                    r"\b(rattus norvegicus|rat|rno)\b": "Rattus norvegicus",
                    r"\b(arabidopsis thaliana|arabidopsis|ath)\b": "Arabidopsis thaliana",
                    r"\b(drosophila melanogaster|drosophila|dme)\b": "Drosophila melanogaster",
                    r"\b(saccharomyces cerevisiae|yeast|sce)\b": "Saccharomyces cerevisiae",
                    r"\b(caenorhabditis elegans|c\.?\s*elegans|cel)\b": "Caenorhabditis elegans",
                    r"\b(escherichia coli|e\.?\s*coli|eco)\b": "Escherichia coli",
                }

                total_available = len(all_results.metadata)

                # Calculate which results to show based on pagination
                start_idx = offset
                end_idx = min(offset + page_size, total_available)
                results_subset = all_results.metadata[start_idx:end_idx]

                # Calculate metadata for response
                current_page = page
                total_pages = (
                    total_available + page_size - 1
                ) // page_size  # Ceiling division
                has_more = end_idx < total_available

                for idx, result in enumerate(results_subset):
                    # Initialize variables with defaults
                    geo_id = "unknown"
                    organism = "Unknown"
                    sample_count = "Unknown"
                    platform = "Unknown"
                    ai_summary = ""

                    try:
                        # First get AI summary if available
                        ai_summaries = getattr(all_results, "ai_summaries", {})
                        individual_summaries = ai_summaries.get(
                            "individual_summaries", []
                        )

                        # Approach 1: Look for individual summary that matches this result
                        if individual_summaries:
                            for summary_item in individual_summaries:
                                # Try multiple ways to match the summary to the result
                                summary_keys = summary_item.keys()
                                result_str = str(result)

                                # Check if any key from summary matches content in result
                                for key in summary_keys:
                                    if (
                                        key != "summary"
                                        and key in result_str
                                    ):
                                        ai_summary = summary_item.get(
                                            "summary", ""
                                        )
                                        break

                                if ai_summary:
                                    break

                        # If no individual summary, try brief overview
                        if not ai_summary:
                            ai_summary = ai_summaries.get("brief_overview")

                        # Enhanced metadata extraction - use multiple approaches
                        organism = "Unknown"
                        sample_count = "Unknown"

                        # Approach 1: Try dictionary access
                        if hasattr(result, "get"):
                            try:
                                # Extract each field individually with explicit checking
                                extracted_geo_id = result.get("geo_id")
                                extracted_organism = result.get("organism")
                                extracted_sample_count = result.get("sample_count")

                                # Only use extracted values if they're valid (not None/empty)
                                if (
                                    extracted_geo_id
                                    and extracted_geo_id.strip()
                                ):
                                    geo_id = extracted_geo_id
                                if (
                                    extracted_organism
                                    and extracted_organism.strip()
                                ):
                                    organism = extracted_organism
                                if (
                                    extracted_sample_count
                                    and str(extracted_sample_count).strip()
                                ):
                                    sample_count = extracted_sample_count
                            except Exception as e:
                                logger.debug(f"Dict access failed for result: {e}")

                        # Approach 2: Try direct attribute if dict access failed
                        if not geo_id or geo_id == "unknown":
                            try:
                                geo_id = (
                                    getattr(result, "geo_id", None)
                                    or getattr(result, "id", None)
                                    or getattr(result, "accession", None)
                                )
                            except Exception as e:
                                logger.debug(f"Attribute access failed: {e}")

                        # Approach 3: Extract from text content if still not found
                        if (
                            not organism
                            or organism == "Unknown"
                            or organism == ""
                        ):
                            try:
                                organism = (
                                    getattr(result, "organism", None)
                                    or getattr(result, "species", None)
                                    or getattr(result, "taxon", None)
                                )

                                # If still not found, try to extract from text fields
                                if not organism or organism == "":
                                    # Try to extract organism from summary, title, or overall_design
                                    text_to_search = (
                                        str(getattr(result, "summary", ""))
                                        + " "
                                        + str(getattr(result, "title", ""))
                                        + " "
                                        + str(getattr(result, "overall_design", ""))
                                    ).lower()

                                    # Common organism patterns
                                    import re
                                    for (
                                        pattern,
                                        organism_name,
                                    ) in organism_patterns.items():
                                        if re.search(pattern, text_to_search):
                                            organism = organism_name
                                            logger.info(
                                                f"Extracted organism from text: {organism}"
                                            )
                                            break

                                    # If still not found, check if it's likely human based on context
                                    if not organism or organism == "":
                                        human_indicators = [
                                            "patient",
                                            "clinical",
                                            "hospital",
                                            "covid-19",
                                            "disease",
                                            "blood",
                                            "plasma",
                                            "serum",
                                            "biopsy",
                                            "tumor",
                                            "cancer",
                                        ]
                                        if any(
                                            indicator in text_to_search
                                            for indicator in human_indicators
                                        ):
                                            organism = "Homo sapiens"
                                            logger.info(
                                                "Inferred human based on clinical context"
                                            )
                            except Exception as e:
                                logger.debug(f"Text extraction failed: {e}")

                        if (
                            not sample_count
                            or sample_count == "Unknown"
                            or sample_count == ""
                        ):
                            try:
                                sample_count = (
                                    getattr(result, "sample_count", None)
                                    or getattr(result, "n_samples", None)
                                    or getattr(result, "samples", None)
                                )

                                # If it's a list, get the length
                                if isinstance(sample_count, list):
                                    sample_count = len(sample_count)
                                elif isinstance(
                                    sample_count, str
                                ) and sample_count.startswith("["):
                                    # Handle string representations of lists
                                    try:
                                        sample_list = eval(sample_count)
                                        if isinstance(sample_list, list):
                                            sample_count = len(sample_list)
                                    except Exception:
                                        # If we can't parse it, keep as is
                                        pass
                            except Exception as e:
                                logger.debug(f"Sample count extraction failed: {e}")

                        # Approach 4: Extract from AI summary if direct extraction completely failed
                        if ai_summary and (
                            not geo_id or geo_id == "unknown" or geo_id == ""
                        ):
                            import re

                            summary_text = str(ai_summary)
                            # Look for GEO accession patterns (GSE followed by digits)
                            geo_match = re.search(r"GSE\d+", summary_text)
                            if geo_match:
                                extracted_geo = geo_match.group()
                                logger.info(
                                    f"Extracted GEO ID from AI summary: {extracted_geo}"
                                )
                                # Only use it if we don't have a valid geo_id already
                                if (
                                    not geo_id
                                    or geo_id == "unknown"
                                    or geo_id == ""
                                ):
                                    geo_id = extracted_geo
                                    logger.info(f"Using extracted GEO ID: {geo_id}")

                        # Approach 4: Extract from original summary/title if still unknown
                        if not geo_id or geo_id == "unknown":
                            import re
                            all_text = str(result)
                            geo_match = re.search(r"GSE\d+", all_text)
                            if geo_match:
                                geo_id = geo_match.group()
                                logger.info(f"Extracted GEO ID from result text: {geo_id}")

                        # Ensure we have string representations
                        geo_id = str(geo_id) if geo_id else "unknown"
                        organism = str(organism) if organism else "Unknown"
                        sample_count = str(sample_count) if sample_count else "Unknown"

                        # Process AI summary for display
                        processed_ai_summary = ""

                        # Try to find the correct AI summary for this specific dataset
                        ai_summary = ""

                        # First try to match by dataset ID
                        if individual_summaries:
                            for summary_item in individual_summaries:
                                summary_accession = summary_item.get(
                                    "accession", ""
                                )
                                if summary_accession and (
                                    summary_accession == geo_id
                                    or summary_accession in str(result)
                                    or geo_id in summary_accession
                                ):
                                    ai_summary = summary_item.get("summary", "")
                                    logger.info(
                                        f"Matched AI summary for {geo_id}: {ai_summary[:100]}..."
                                    )
                                    break

                        # If no specific match found, try to use a general summary
                        if not ai_summary and ai_summaries:
                            ai_summary = (
                                ai_summaries.get("brief_overview", "")
                                or ai_summaries.get("summary", "")
                                or str(ai_summaries.get("individual_summaries", [{}])[0].get("summary", ""))
                            )
                            if ai_summary:
                                logger.info("Using general AI summary")

                        # Use the result's own summary if no AI summary
                        if not ai_summary:
                            ai_summary = getattr(result, "summary", "") or getattr(result, "description", "")

                        # Final fallback
                        if not ai_summary:
                            ai_summary = f"Dataset {geo_id} containing genomics data"

                        processed_ai_summary = str(ai_summary)[:500]  # Limit length
                    except Exception as e:
                        logger.error(f"Error processing result {idx}: {e}")
                        # Use fallback values
                        processed_ai_summary = f"Dataset {geo_id} from genomics research"

                    # Create processed result
                    processed_result = {
                        "id": geo_id,
                        "title": (
                            getattr(result, "title", f"Dataset {geo_id}")
                            or f"Dataset {geo_id}"
                        ),
                        "summary": processed_ai_summary,
                        "organism": organism,
                        "sample_count": sample_count,
                        "platform": getattr(result, "platform", "Unknown")
                        or "Unknown",
                        "ai_enhanced": bool(processed_ai_summary and processed_ai_summary != f"Dataset {geo_id} from genomics research"),
                    }

                    processed_results.append(processed_result)

                # Pagination metadata
                total_count = len(all_results.metadata)
                total_pages = (
                    total_count + page_size - 1
                ) // page_size  # Ceiling division

                return JSONResponse(
                    {
                        "results": processed_results,
                        "pagination": {
                            "current_page": current_page,
                            "page_size": page_size,
                            "total_results": total_available,
                            "total_pages": total_pages,
                            "has_next": has_more,
                            "has_previous": current_page > 1,
                            "start_index": offset + 1,
                            "end_index": min(
                                offset + page_size, total_available
                            ),
                        },
                        "total_count": total_available,
                        "displayed_count": len(processed_results),
                        "query": query,
                        "status": "success",
                        "mode": "real_data",
                    }
                )

            except Exception as e:
                logger.error(f"Pipeline search failed: {e}")
                return JSONResponse(
                    {"error": f"Search failed: {str(e)}", "status": "error"},
                    status_code=500,
                )
        else:
            # Return informative message instead of mock data
            return JSONResponse(
                {
                    "results": [],
                    "total_count": 0,
                    "query": query,
                    "status": "unavailable",
                    "message": "OmicsOracle pipeline is not available. Please ensure it's properly installed and configured.",
                    "mode": "limited",
                }
            )

    except Exception as e:
        logger.error(f"Search error: {e}")
        return JSONResponse(
            {"error": str(e), "status": "error"}, status_code=500
        )
