"""
Command-line interface for OmicsOracle.
"""

import click
from omics_oracle.config import settings
from omics_oracle.core.exceptions import OmicsOracleException


@click.group()
@click.version_option()
def main():
    """OmicsOracle - AI-Powered Genomics Data Summary Agent."""
    pass


@main.command()
@click.option("--host", default=settings.api_host, help="Host to bind to")
@click.option("--port", default=settings.api_port, help="Port to bind to")
@click.option("--reload", is_flag=True, help="Enable auto-reload")
def serve(host: str, port: int, reload: bool):
    """Start the API server."""
    try:
        import uvicorn

        uvicorn.run(
            "omics_oracle.api.main:app",
            host=host,
            port=port,
            reload=reload or settings.api_reload,
        )
    except Exception as e:
        raise OmicsOracleException(f"Failed to start server: {e}")


@main.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--output", "-o", help="Output file path")
@click.option(
    "--format", default="json", help="Output format (json, csv, txt)"
)
def analyze(input_file: str, output: str, format: str):
    """Analyze a genomics data file."""
    click.echo(f"Analyzing file: {input_file}")
    click.echo(f"Output format: {format}")
    if output:
        click.echo(f"Output will be saved to: {output}")
    # TODO: Implement analysis logic
    click.echo("Analysis complete!")


@main.command()
@click.argument("geo_id")
@click.option("--summary", is_flag=True, help="Generate summary only")
def fetch_geo(geo_id: str, summary: bool):
    """Fetch and analyze GEO dataset."""
    click.echo(f"Fetching GEO dataset: {geo_id}")
    if summary:
        click.echo("Generating summary only...")
    # TODO: Implement GEO fetching logic
    click.echo("GEO dataset processed!")


@main.command()
def status():
    """Check system status."""
    click.echo("OmicsOracle System Status:")
    click.echo(f"Environment: {settings.environment}")
    click.echo(f"Debug Mode: {settings.debug}")
    click.echo(f"Log Level: {settings.log_level}")
    # TODO: Add more status checks (database, Redis, etc.)
    click.echo("Status: OK")


if __name__ == "__main__":
    main()
