"""
Monkey patch for Bio.Entrez to force email configuration
"""

import logging
import os

logger = logging.getLogger("entrez_patch")

# Try to import Bio.Entrez
try:
    from Bio import Entrez

    # Store original email value
    original_email = getattr(Entrez, "email", None)

    # Set email from environment or use default
    ncbi_email = os.environ.get("NCBI_EMAIL", "omicsoracle@example.com")
    Entrez.email = ncbi_email

    logger.info(f"Patched Bio.Entrez.email: {original_email} -> {Entrez.email}")

except ImportError:
    logger.warning("Bio.Entrez not found, skipping patch")


# Add patch to pipeline initialization
def patch_pipeline():
    """Patch the OmicsOracle pipeline to ensure NCBI email is set."""
    try:
        from src.omics_oracle.pipeline.pipeline import OmicsOracle

        # Store original __init__
        original_init = OmicsOracle.__init__

        # Create patched init
        def patched_init(self, config=None):
            # Call original init
            original_init(self, config)

            # Ensure NCBI email is set in GEO client
            if hasattr(self, "geo_client") and hasattr(
                self.geo_client, "_client"
            ):
                try:
                    ncbi_email = os.environ.get(
                        "NCBI_EMAIL", "omicsoracle@example.com"
                    )
                    self.geo_client._client.email = ncbi_email
                    logger.info(
                        f"Patched geo_client email: {self.geo_client._client.email}"
                    )
                except AttributeError:
                    logger.warning("Could not patch geo_client email")

        # Apply patch
        OmicsOracle.__init__ = patched_init
        logger.info("Patched OmicsOracle.__init__")

    except ImportError:
        logger.warning("OmicsOracle pipeline not found, skipping patch")


# Run the patch
patch_pipeline()
