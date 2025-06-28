#!/usr/bin/env python3
"""
Generate PNG visualization from DOT file for the OmicsOracle event flow.
Requires Graphviz to be installed.
"""

import os
import subprocess
import sys
from pathlib import Path


def generate_png_from_dot(dot_file, output_file=None):
    """
    Generate a PNG visualization from a DOT file.

    Args:
        dot_file (str): Path to the DOT file
        output_file (str, optional): Path to save the PNG output. If None, uses the same name with .png extension.

    Returns:
        bool: True if successful, False otherwise
    """
    if output_file is None:
        output_file = os.path.splitext(dot_file)[0] + ".png"

    try:
        # Check if dot is available
        subprocess.run(
            ["dot", "-V"],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        print("Error: Graphviz 'dot' command not found. Please install Graphviz.")
        print("  macOS: brew install graphviz")
        print("  Linux: sudo apt-get install graphviz")
        print("  Windows: download from https://graphviz.org/download/")
        return False

    try:
        # Generate PNG from DOT file
        subprocess.run(
            ["dot", "-Tpng", dot_file, "-o", output_file],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        print(f"Successfully generated: {output_file}")
        return True
    except subprocess.SubprocessError as e:
        print(f"Error generating PNG: {e}")
        return False


def main():
    """Main function to generate PNG from DOT file."""
    # Get the project root directory
    project_root = Path(__file__).parent

    # Default DOT file path
    dot_file = project_root / "docs" / "event_flow_validation.dot"

    # Default output file path
    output_file = project_root / "docs" / "event_flow_visualization.png"

    # Check if DOT file exists
    if not dot_file.exists():
        print(f"Error: DOT file not found at {dot_file}")
        return 1

    # Create docs directory if it doesn't exist
    os.makedirs(output_file.parent, exist_ok=True)

    # Generate PNG
    success = generate_png_from_dot(str(dot_file), str(output_file))

    if success:
        print("\nVisualization generated successfully!")
        print(f"View it at: {output_file}")

        # Create also in SVG format for better quality
        svg_output = str(output_file).replace(".png", ".svg")
        subprocess.run(
            ["dot", "-Tsvg", str(dot_file), "-o", svg_output],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        print(f"SVG version also available at: {svg_output}")

        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())
