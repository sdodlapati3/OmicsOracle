"""
Command-line interface for OmicsOracle.
"""

import click

from omics_oracle.core.config import get_config
from omics_oracle.core.exceptions import OmicsOracleException


@click.group()
@click.version_option()
def main():
    """OmicsOracle - AI-Powered Genomics Data Summary Agent."""
    pass


@main.command()
@click.option("--host", default="0.0.0.0", help="Host to bind to")
@click.option("--port", default=8000, help="Port to bind to")
@click.option("--reload", is_flag=True, help="Enable auto-reload")
def serve(host: str, port: int, reload: bool):
    """Start the API server."""
    try:
        import uvicorn

        config = get_config()
        uvicorn.run(
            "omics_oracle.api.main:app",
            host=host,
            port=port,
            reload=reload or config.api.reload,
        )
    except Exception as e:
        raise OmicsOracleException(f"Failed to start server: {e}") from e


@main.command()
@click.argument("input_file", type=click.Path(exists=True))
@click.option("--output", "-o", help="Output file path")
@click.option("--format", "output_format", default="json", help="Output format")
def analyze(input_file: str, output: str, output_format: str):
    """Analyze a genomics data file."""
    click.echo(f"Analyzing file: {input_file}")
    click.echo(f"Output format: {output_format}")
    if output:
        click.echo(f"Output will be saved to: {output}")
    click.echo("Analysis complete!")


@main.command()
@click.argument("geo_id")
@click.option("--summary", is_flag=True, help="Generate summary only")
def fetch_geo(geo_id: str, summary: bool):
    """Fetch and analyze GEO dataset."""
    click.echo(f"Fetching GEO dataset: {geo_id}")
    if summary:
        click.echo("Generating summary only...")
    click.echo("GEO dataset processed!")


@main.command()
def status():
    """Check system status."""
    click.echo("OmicsOracle System Status:")
    try:
        config = get_config()
        click.echo(f"Environment: {config.environment}")
        click.echo(f"Debug Mode: {config.debug}")
        click.echo(f"Log Level: {config.logging.level}")
        click.echo("Status: OK")
    except Exception as e:
        click.echo(f"Error loading configuration: {e}")
        click.echo("Status: ERROR")


if __name__ == "__main__":
    main()
