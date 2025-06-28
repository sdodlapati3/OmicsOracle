"""
Command Line Interface for OmicsOracle

Provides a CLI for interacting with the OmicsOracle pipeline.
"""

import asyncio
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Optional

import click

# Add src to path for CLI execution
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

# Import project modules after path setup  # noqa: E402
from omics_oracle.core.config import Config  # noqa: E402
from omics_oracle.pipeline import OmicsOracle, ResultFormat  # noqa: E402


@click.group()
@click.option(
    "--config",
    "-c",
    type=click.Path(exists=True),
    help="Path to configuration file",
)
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx, config: Optional[str], verbose: bool):
    """OmicsOracle - Biological Data Search and Analysis Pipeline"""
    ctx.ensure_object(dict)

    # Load configuration
    if config:
        ctx.obj["config"] = Config.from_file(config)
    else:
        ctx.obj["config"] = Config()

    ctx.obj["verbose"] = verbose

    if verbose:
        click.echo("OmicsOracle CLI initialized")


@cli.command()
@click.argument("query", type=str)
@click.option(
    "--max-results",
    "-m",
    default=50,
    help="Maximum number of results to return",
)
@click.option("--include-sra", is_flag=True, help="Include SRA metadata in results")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["json", "csv", "tsv", "summary"]),
    default="summary",
    help="Output format",
)
@click.option("--output", "-o", type=click.Path(), help="Output file (default: stdout)")
@click.pass_context
def search(
    ctx,
    query: str,
    max_results: int,
    include_sra: bool,
    output_format: str,
    output: Optional[str],
):
    """Search for biological data using natural language query"""

    async def run_search():
        oracle = OmicsOracle(ctx.obj["config"])

        try:
            if ctx.obj["verbose"]:
                click.echo(f"Searching for: {query}")
                click.echo(f"Max results: {max_results}")
                click.echo(f"Include SRA: {include_sra}")
                click.echo(f"Format: {output_format}")
                click.echo("Processing...")

            # Process the query
            result = await oracle.process_query(
                query=query,
                max_results=max_results,
                include_sra=include_sra,
                result_format=ResultFormat(output_format),
            )

            # Format output
            if output_format == "summary":
                output_text = format_summary(result)
            elif output_format == "json":
                output_text = format_json(result)
            else:
                output_text = f"Format {output_format} not yet implemented"

            # Write output
            if output:
                with open(output, "w") as f:
                    f.write(output_text)
                click.echo(f"Results written to: {output}")
            else:
                click.echo(output_text)

        except Exception as e:
            click.echo(f"Error: {str(e)}", err=True)
            sys.exit(1)
        finally:
            await oracle.close()

    asyncio.run(run_search())


@cli.command()
@click.argument("geo_id", type=str)
@click.option("--include-sra", is_flag=True, help="Include SRA metadata")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["json", "summary"]),
    default="summary",
    help="Output format",
)
@click.pass_context
def info(ctx, geo_id: str, include_sra: bool, output_format: str):
    """Get detailed information about a specific GEO dataset"""

    async def run_info():
        oracle = OmicsOracle(ctx.obj["config"])

        try:
            if ctx.obj["verbose"]:
                click.echo(f"Getting info for: {geo_id}")

            metadata = await oracle.geo_client.get_geo_metadata(geo_id, include_sra=include_sra)

            if output_format == "json":
                click.echo(json.dumps(metadata, indent=2))
            else:
                click.echo(format_metadata_summary(metadata))

        except Exception as e:
            click.echo(f"Error: {str(e)}", err=True)
            sys.exit(1)
        finally:
            await oracle.close()

    asyncio.run(run_info())


@cli.command()
@click.argument("geo_id", type=str)
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(),
    default="./downloads",
    help="Output directory for downloaded files",
)
@click.option(
    "--format",
    "-f",
    "download_format",
    type=click.Choice(["soft", "miniml", "txt"]),
    default="soft",
    help="Download format",
)
@click.option("--include-sra", is_flag=True, help="Include SRA data if available")
@click.pass_context
def download(ctx, geo_id: str, output_dir: str, download_format: str, include_sra: bool):
    """Download GEO dataset files directly"""

    async def run_download():
        oracle = OmicsOracle(ctx.obj["config"])

        try:
            if ctx.obj["verbose"]:
                click.echo(f"Downloading {geo_id} in {download_format} format")
                click.echo(f"Output directory: {output_dir}")

            # Create output directory
            Path(output_dir).mkdir(parents=True, exist_ok=True)

            # Get metadata first
            metadata = await oracle.geo_client.get_geo_metadata(geo_id, include_sra=include_sra)

            if not metadata:
                click.echo(f"No metadata found for {geo_id}", err=True)
                return

            # For now, save metadata as JSON
            # In a full implementation, this would download actual data files
            output_file = Path(output_dir) / f"{geo_id}_metadata.json"

            with open(output_file, "w") as f:
                json.dump(metadata, f, indent=2, default=str)

            click.echo(f"Downloaded metadata for {geo_id}")
            click.echo(f"Saved to: {output_file}")

            if ctx.obj["verbose"]:
                click.echo(f"Title: {metadata.get('title', 'N/A')}")
                click.echo(f"Type: {metadata.get('type', 'N/A')}")

        except Exception as e:
            click.echo(f"Error downloading {geo_id}: {str(e)}", err=True)
            sys.exit(1)
        finally:
            await oracle.close()

    asyncio.run(run_download())


@cli.command()
@click.argument("geo_id", type=str)
@click.option("--output", "-o", type=click.Path(), help="Output file for analysis results")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["json", "summary", "csv"]),
    default="summary",
    help="Output format",
)
@click.pass_context
def analyze(ctx, geo_id: str, output: str, output_format: str):
    """Analyze GEO dataset and provide detailed insights"""

    async def run_analyze():
        oracle = OmicsOracle(ctx.obj["config"])

        try:
            if ctx.obj["verbose"]:
                click.echo(f"Analyzing dataset: {geo_id}")

            # Get detailed metadata
            metadata = await oracle.geo_client.get_geo_metadata(geo_id, include_sra=True)

            if not metadata:
                click.echo(f"No data found for {geo_id}", err=True)
                return

            # Perform analysis using biomedical NER
            title_text = metadata.get("title", "")
            summary_text = metadata.get("summary", "")
            combined_text = f"{title_text} {summary_text}"

            # Extract entities from metadata
            entities = oracle.biomedical_ner.extract_biomedical_entities(combined_text)

            # Create analysis results
            analysis = {
                "geo_id": geo_id,
                "title": title_text,
                "summary": (summary_text[:500] + "..." if len(summary_text) > 500 else summary_text),
                "type": metadata.get("type", "Unknown"),
                "organism": metadata.get("organism", "Unknown"),
                "platform": metadata.get("platform", "Unknown"),
                "samples_count": len(metadata.get("samples", [])),
                "entities": entities,
                "analysis_timestamp": datetime.now().isoformat(),
            }

            # Format output
            if output_format == "json":
                output_text = json.dumps(analysis, indent=2, default=str)
            elif output_format == "csv":
                output_text = format_analysis_csv(analysis)
            else:
                output_text = format_analysis_summary(analysis)

            # Write output
            if output:
                with open(output, "w") as f:
                    f.write(output_text)
                click.echo(f"Analysis saved to: {output}")
            else:
                click.echo(output_text)

        except Exception as e:
            click.echo(f"Error analyzing {geo_id}: {str(e)}", err=True)
            sys.exit(1)
        finally:
            await oracle.close()

    asyncio.run(run_analyze())


@cli.command()
@click.argument("queries_file", type=click.Path(exists=True))
@click.option(
    "--output-dir",
    "-o",
    type=click.Path(),
    default="./batch_results",
    help="Output directory for batch results",
)
@click.option("--max-results", "-m", default=10, help="Maximum results per query")
@click.option(
    "--format",
    "-f",
    "output_format",
    type=click.Choice(["json", "csv", "summary"]),
    default="json",
    help="Output format",
)
@click.pass_context
def batch(
    ctx,
    queries_file: str,
    output_dir: str,
    max_results: int,
    output_format: str,
):
    """Process multiple queries from a file"""

    async def run_batch():
        oracle = OmicsOracle(ctx.obj["config"])

        try:
            # Read queries from file
            with open(queries_file, "r") as f:
                queries = [line.strip() for line in f if line.strip()]

            if not queries:
                click.echo("No queries found in file", err=True)
                return

            click.echo(f"Processing {len(queries)} queries...")

            # Create output directory
            Path(output_dir).mkdir(parents=True, exist_ok=True)

            results = []

            for i, query in enumerate(queries, 1):
                if ctx.obj["verbose"]:
                    click.echo(f"Processing query {i}/{len(queries)}: {query}")

                try:
                    result = await oracle.process_query(
                        query=query,
                        max_results=max_results,
                        result_format=ResultFormat(output_format),
                    )
                    results.append(result)

                    # Save individual result
                    filename = f"query_{i:03d}_result.{output_format}"
                    filepath = Path(output_dir) / filename

                    with open(filepath, "w") as f:
                        if output_format == "json":
                            f.write(format_json(result))
                        else:
                            f.write(format_summary(result))

                    click.echo(f"OK Query {i} completed: " f"{len(result.metadata)} results")

                except Exception as e:
                    click.echo(f"FAILED Query {i} failed: {str(e)}")
                    continue

            # Create summary report
            summary_file = Path(output_dir) / "batch_summary.json"
            summary = {
                "total_queries": len(queries),
                "successful_queries": len(results),
                "failed_queries": len(queries) - len(results),
                "total_results": sum(len(r.metadata) for r in results),
                "queries": queries,
                "timestamp": datetime.now().isoformat(),
            }

            with open(summary_file, "w") as f:
                json.dump(summary, f, indent=2, default=str)

            click.echo("\nBatch processing completed!")
            click.echo(f"Results saved to: {output_dir}")
            successful = summary["successful_queries"]
            total = summary["total_queries"]
            click.echo(f"Summary: {successful}/{total} queries successful")

        except Exception as e:
            click.echo(f"Batch processing error: {str(e)}", err=True)
            sys.exit(1)
        finally:
            await oracle.close()

    asyncio.run(run_batch())


@cli.group()
def config():
    """Configuration management commands"""
    pass


@config.command()
@click.argument("key", type=str)
@click.argument("value", type=str)
def set(key: str, value: str):
    """Set a configuration value"""
    click.echo(f"Setting {key} = {value}")
    # In a full implementation, this would update the configuration file
    click.echo("Configuration updated (placeholder)")


@config.command()
@click.argument("key", type=str, required=False)
def get(key: str):
    """Get configuration value(s)"""
    if key:
        click.echo(f"Getting value for: {key}")
        # In a full implementation, this would read from configuration
        click.echo("Value: <placeholder>")
    else:
        click.echo("Current configuration:")
        click.echo("  NCBI_EMAIL: sdodl001@odu.edu")
        click.echo("  NCBI_API_KEY: fb9ea751dc...")
        click.echo("  LOG_LEVEL: INFO")


@config.command()
def list():
    """List all configuration options"""
    click.echo("Available configuration options:")
    click.echo("  NCBI_EMAIL - Email for NCBI API access")
    click.echo("  NCBI_API_KEY - API key for NCBI services")
    click.echo("  LOG_LEVEL - Logging level (DEBUG, INFO, WARNING, ERROR)")
    click.echo("  CACHE_TTL - Cache time-to-live in seconds")
    click.echo("  CACHE_DIRECTORY - Directory for caching files")


@cli.command()
@click.pass_context
def status(ctx):
    """Show system status and configuration"""
    config = ctx.obj["config"]

    click.echo("=== OmicsOracle Status ===")
    click.echo("Configuration loaded: OK")
    click.echo(f"NCBI Email: {config.ncbi.email or 'Not configured'}")
    click.echo(f"Cache Directory: {config.cache.directory}")
    click.echo(f"Log Level: {config.logging.level}")

    # Test component initialization
    try:
        oracle = OmicsOracle(config)
        click.echo("Pipeline initialization: OK")
        asyncio.run(oracle.close())
    except Exception as e:
        click.echo(f"Pipeline initialization: FAILED ({str(e)})")


@cli.command()
@click.option("--max-results", "-m", default=10, help="Default maximum results per query")
@click.pass_context
def interactive(ctx, max_results: int):
    """Start interactive query mode"""

    async def run_interactive():
        oracle = OmicsOracle(ctx.obj["config"])

        try:
            click.echo("=== OmicsOracle Interactive Mode ===")
            click.echo("Enter biological queries (type 'quit' to exit)")
            click.echo("Commands: search <query>, status, help, quit")
            click.echo("")

            while True:
                try:
                    query = click.prompt("omics> ", type=str).strip()

                    if query.lower() in ["quit", "exit", "q"]:
                        click.echo("Goodbye!")
                        break
                    elif query.lower() == "help":
                        click.echo("Available commands:")
                        click.echo("  search <query> - Search for biological data")
                        click.echo("  status - Show system status")
                        click.echo("  help - Show this help")
                        click.echo("  quit - Exit interactive mode")
                        continue
                    elif query.lower() == "status":
                        config = ctx.obj["config"]
                        click.echo(f"NCBI Email: {config.ncbi.email}")
                        click.echo(f"Cache Dir: {config.cache.directory}")
                        continue
                    elif query.startswith("search "):
                        query = query[7:]  # Remove 'search ' prefix
                    elif not query:
                        continue

                    # Process the query
                    click.echo(f"Searching for: {query}")
                    result = await oracle.process_query(
                        query=query,
                        max_results=max_results,
                        result_format=ResultFormat.SUMMARY,
                    )

                    # Display results
                    click.echo(format_summary(result))
                    click.echo("")

                except KeyboardInterrupt:
                    click.echo("\nUse 'quit' to exit")
                    continue
                except Exception as e:
                    click.echo(f"Error: {str(e)}")
                    continue

        finally:
            await oracle.close()

    asyncio.run(run_interactive())


@cli.command()
@click.argument("query")
@click.option("--max-results", default=5, help="Maximum number of results to analyze")
@click.option(
    "--summary-type",
    type=click.Choice(["brief", "comprehensive", "technical"]),
    default="comprehensive",
    help="Type of AI summary to generate",
)
@click.option(
    "--output-format",
    type=click.Choice(["text", "json"]),
    default="text",
    help="Output format",
)
@click.pass_context
def summarize(ctx, query: str, max_results: int, summary_type: str, output_format: str):
    """Generate AI-powered summaries of genomics datasets using natural language queries.

    Example:
        omics-oracle summarize "diabetes pancreatic beta cells" --max-results 3
        omics-oracle summarize "cancer stem cells" --summary-type brief
    """
    config = ctx.obj["config"]
    verbose = ctx.obj["verbose"]

    if verbose:
        click.echo(f"Starting AI summarization for query: '{query}'")

    async def run_summarization():
        oracle = OmicsOracle(config)

        try:
            # Process the query
            if verbose:
                click.echo("🔍 Processing query through pipeline...")

            result = await oracle.process_query(
                query, max_results=max_results, result_format=ResultFormat.JSON
            )

            if result.is_failed:
                click.echo(f"❌ Query failed: {result.error}", err=True)
                sys.exit(1)

            if not result.metadata:
                click.echo("No datasets found for the given query.")
                return

            if verbose:
                click.echo(f"📊 Found {len(result.metadata)} datasets")
                click.echo("🤖 Generating AI summaries...")

            # Display results based on format
            if output_format == "json":
                output = {
                    "query": query,
                    "summary_type": summary_type,
                    "total_results": len(result.metadata),
                    "ai_summaries": result.ai_summaries,
                    "datasets": result.metadata,
                }
                click.echo(json.dumps(output, indent=2, default=str))
            else:
                # Text format
                click.echo("🌟 OmicsOracle AI-Powered Dataset Summaries")
                click.echo("=" * 60)
                click.echo(f"Query: {query}")
                click.echo(f"Summary Type: {summary_type}")
                click.echo(f"Results: {len(result.metadata)} datasets")
                click.echo()

                # Display batch summary if available
                if result.ai_summaries.get("batch_summary"):
                    batch = result.ai_summaries["batch_summary"]
                    click.echo("📋 BATCH OVERVIEW:")
                    click.echo("-" * 40)
                    click.echo(f"Total Datasets: {batch.get('total_datasets', 0)}")
                    click.echo(f"Total Samples: {batch.get('total_samples', 0)}")
                    click.echo(f"Organisms: {', '.join(batch.get('organisms', []))}")
                    click.echo(f"Platforms: {', '.join(batch.get('platforms', []))}")
                    click.echo()
                    click.echo(f"Summary: {batch.get('overview', 'N/A')}")
                    click.echo()

                # Display brief overview if available
                if result.ai_summaries.get("brief_overview"):
                    click.echo("🎯 KEY INSIGHTS:")
                    click.echo("-" * 40)
                    for summary_key, content in result.ai_summaries["brief_overview"].items():
                        if content:
                            click.echo(f"{summary_key.replace('_', ' ').title()}: {content}")
                    click.echo()

                # Display individual summaries
                if result.ai_summaries.get("individual_summaries"):
                    click.echo("📚 INDIVIDUAL DATASET SUMMARIES:")
                    click.echo("=" * 50)

                    for i, summary_data in enumerate(result.ai_summaries["individual_summaries"], 1):
                        click.echo(f"\n🔬 Dataset {i}: {summary_data.get('accession', 'Unknown')}")
                        click.echo("-" * 40)

                        dataset_summaries = summary_data.get("summary", {})
                        for summary_key, content in dataset_summaries.items():
                            if content:
                                click.echo(f"\n{summary_key.replace('_', ' ').title()}:")
                                click.echo(content)
                                click.echo()

                # Display any errors
                if result.ai_summaries.get("error"):
                    click.echo(f"⚠️  AI Summarization Error: {result.ai_summaries['error']}")

                click.echo("\n💡 Tip: Use --output-format json for machine-readable output")
                click.echo("💡 Try different --summary-type options: brief, comprehensive, technical")

        except Exception as e:
            click.echo(f"❌ Error during summarization: {e}", err=True)
            if verbose:
                import traceback

                traceback.print_exc()
            sys.exit(1)
        finally:
            await oracle.close()

    # Run the async function
    asyncio.run(run_summarization())


def format_summary(result) -> str:
    """Format query result as a human-readable summary"""
    lines = [
        "=== OmicsOracle Search Results ===",
        f"Query: {result.original_query}",
        f"Status: {result.status.value}",
        f"Intent: {result.intent or 'Unknown'}",
        (f"Processing time: {result.duration:.2f}s" if result.duration else "N/A"),
        "",
    ]

    if result.entities:
        lines.append("Detected Entities:")
        for entity_type, entities in result.entities.items():
            if entities:
                entity_texts = [e["text"] for e in entities]
                lines.append(f"  {entity_type.title()}: {', '.join(entity_texts)}")
        lines.append("")

    if result.expanded_query and result.expanded_query != result.original_query:
        lines.append(f"Expanded Query: {result.expanded_query}")
        lines.append("")

    lines.append(f"Found {len(result.geo_ids)} GEO datasets")
    lines.append(f"Retrieved metadata for {len(result.metadata)} datasets")
    lines.append("")

    if result.metadata:
        lines.append("Top Results:")
        for i, metadata in enumerate(result.metadata[:5], 1):
            geo_id = metadata.get("accession", "Unknown")
            title = metadata.get("title", "No title")[:80]
            score = metadata.get("relevance_score", 0)
            lines.append(f"  {i}. {geo_id}: {title}... (score: {score:.1f})")

    if result.error:
        lines.extend(["", f"Error: {result.error}"])

    return "\n".join(lines)


def format_json(result) -> str:
    """Format query result as JSON"""
    # Convert to JSON-serializable format
    data = {
        "query_id": result.query_id,
        "original_query": result.original_query,
        "status": result.status.value,
        "intent": result.intent,
        "entities": result.entities,
        "expanded_query": result.expanded_query,
        "geo_ids": result.geo_ids,
        "metadata": result.metadata,
        "duration": result.duration,
        "error": result.error,
    }

    return json.dumps(data, indent=2, default=str)


def format_metadata_summary(metadata) -> str:
    """Format metadata as a human-readable summary"""
    if not metadata:
        return "No metadata found"

    lines = [
        "=== GEO Dataset Information ===",
        f"Accession: {metadata.get('accession', 'Unknown')}",
        f"Title: {metadata.get('title', 'No title')}",
        f"Type: {metadata.get('type', 'Unknown')}",
        "",
        "Summary:",
        metadata.get("summary", "No summary available"),
        "",
    ]

    if "samples" in metadata:
        lines.append(f"Samples: {len(metadata['samples'])}")

    if "platform" in metadata:
        lines.append(f"Platform: {metadata['platform']}")

    if "organism" in metadata:
        lines.append(f"Organism: {metadata['organism']}")

    return "\n".join(lines)


def format_analysis_summary(analysis) -> str:
    """Format analysis results as a human-readable summary"""
    lines = [
        "=== GEO Dataset Analysis ===",
        f"Dataset: {analysis['geo_id']}",
        f"Title: {analysis['title']}",
        f"Type: {analysis['type']}",
        f"Organism: {analysis['organism']}",
        f"Platform: {analysis['platform']}",
        f"Samples: {analysis['samples_count']}",
        "",
        "Summary:",
        analysis["summary"],
        "",
    ]

    if analysis["entities"]:
        lines.append("Detected Biological Entities:")
        for entity_type, entities in analysis["entities"].items():
            if entities:
                entity_texts = [e["text"] for e in entities]
                lines.append(f"  {entity_type.title()}: {', '.join(entity_texts)}")
        lines.append("")

    lines.append(f"Analysis performed: {analysis['analysis_timestamp']}")

    return "\n".join(lines)


def format_analysis_csv(analysis) -> str:
    """Format analysis results as CSV"""
    lines = [
        "field,value",
        f"geo_id,{analysis['geo_id']}",
        f"title,\"{analysis['title']}\"",
        f"type,{analysis['type']}",
        f"organism,{analysis['organism']}",
        f"platform,{analysis['platform']}",
        f"samples_count,{analysis['samples_count']}",
        f"analysis_timestamp,{analysis['analysis_timestamp']}",
    ]

    return "\n".join(lines)
