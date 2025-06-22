#!/usr/bin/env python3
"""
ASCII-Only Character Enforcement Script for OmicsOracle
Prevents non-ASCII characters in source code files to avoid CI/CD failures.
"""

import argparse
import sys
from pathlib import Path
from typing import Dict, List


class ASCIIEnforcer:
    """Comprehensive ASCII character enforcement for OmicsOracle codebase."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.violations: List[Dict[str, str]] = []
        self.processed_files = 0
        self.total_violations = 0

    def is_ascii_only(self, text: str) -> bool:
        """Check if text contains only ASCII characters."""
        try:
            text.encode("ascii")
            return True
        except UnicodeEncodeError:
            return False

    def find_non_ascii_chars(
        self, text: str, filepath: str
    ) -> List[Dict[str, str]]:
        """Find all non-ASCII characters in text with their positions."""
        violations = []
        lines = text.split("\n")

        for line_num, line in enumerate(lines, 1):
            for col_num, char in enumerate(line, 1):
                if ord(char) > 127:  # Non-ASCII character
                    severity = self.classify_character(char)
                    violations.append(
                        {
                            "file": filepath,
                            "line": line_num,
                            "column": col_num,
                            "character": char,
                            "unicode_code": f"U+{ord(char):04X}",
                            "severity": severity,
                            "context": line.strip(),
                        }
                    )

        return violations

    def classify_character(self, char: str) -> str:
        """Classify non-ASCII character by severity."""
        code = ord(char)

        # Critical: Commonly problematic characters
        if code in [0x2705, 0x274C, 0x26A0]:  # Checkmarks, crosses, warnings
            return "CRITICAL"

        # Emoji ranges
        if 0x1F000 <= code <= 0x1FFFF:
            return "EMOJI"

        # Other non-ASCII
        return "NON_ASCII"

    def check_file(self, filepath: Path) -> bool:
        """Check a single file for ASCII compliance."""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()

            if self.is_ascii_only(content):
                if self.verbose:
                    print(f"[OK][OK][OK] {filepath} - ASCII compliant")
                return True

            file_violations = self.find_non_ascii_chars(content, str(filepath))
            self.violations.extend(file_violations)
            self.total_violations += len(file_violations)

            if self.verbose:
                print(
                    f"[OK][OK][OK] {filepath} - {len(file_violations)} violations"
                )

            return False

        except Exception as e:
            print(f"Error reading {filepath}: {e}")
            return False

    def should_check_file(self, filepath: Path) -> bool:
        """Determine if file should be checked."""
        # Skip excluded directories
        excluded_dirs = {
            ".git",
            "__pycache__",
            ".pytest_cache",
            ".mypy_cache",
            "node_modules",
            "venv",
            "env",
            ".env",
            "docs",
            "extracted_docs",
        }

        if any(part in excluded_dirs for part in filepath.parts):
            return False

        # Skip excluded file types
        excluded_extensions = {
            ".md",
            ".rst",
            ".tex",
            ".pdf",
            ".png",
            ".jpg",
            ".jpeg",
        }
        if filepath.suffix.lower() in excluded_extensions:
            return False

        # Include code files
        code_extensions = {
            ".py",
            ".yml",
            ".yaml",
            ".json",
            ".sh",
            ".bash",
            ".zsh",
            ".toml",
            ".ini",
            ".cfg",
            ".conf",
            ".txt",
            ".sql",
            ".js",
            ".ts",
            ".html",
            ".css",
            ".xml",
        }

        # Check by extension or specific filenames
        if (
            filepath.suffix.lower() in code_extensions
            or filepath.name in ["Dockerfile", "Makefile"]
            or filepath.name.startswith("requirements")
        ):
            return True

        return False

    def print_violations(self):
        """Print all violations in a formatted way."""
        if not self.violations:
            print("[OK][OK][OK] All files pass ASCII enforcement checks!")
            return

        print(f"[OK][OK][OK] Found {self.total_violations} ASCII violations:")
        print("=" * 60)

        current_file = None
        for violation in self.violations:
            if violation["file"] != current_file:
                current_file = violation["file"]
                print(f"FILE: {current_file}")

            print(
                f"LINE: {violation['line']:4d} | "
                f"COL: {violation['column']:3d} | "
                f"{violation['severity']}: Non-ASCII character "
                f"'{violation['character']}' ({violation['unicode_code']})"
            )
            print("-" * 60)

        print("\nSUMMARY:")
        print(f"  Errors:   {self.total_violations}")
        print("  Warnings: 0")

        print("\n[OK][OK][OK][OK] To fix ASCII violations:")
        print("   1. Replace non-ASCII characters with ASCII equivalents")
        print("   2. Move decorative content to markdown documentation")
        print("   3. Use ASCII art instead of Unicode symbols")
        print("   4. Replace smart quotes with straight quotes")

    def run(self, paths: List[str]) -> int:
        """Run ASCII enforcement on specified paths."""
        all_files = []

        for path_str in paths:
            path = Path(path_str)
            if path.is_file():
                if self.should_check_file(path):
                    all_files.append(path)
            elif path.is_dir():
                for file_path in path.rglob("*"):
                    if file_path.is_file() and self.should_check_file(
                        file_path
                    ):
                        all_files.append(file_path)

        if not all_files:
            print("No files to check.")
            return 0

        print(f"Checking {len(all_files)} files for ASCII compliance...")

        all_passed = True
        for filepath in all_files:
            self.processed_files += 1
            if not self.check_file(filepath):
                all_passed = False

        self.print_violations()

        return 0 if all_passed else 1


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Enforce ASCII-only characters in source code files"
    )
    parser.add_argument(
        "paths",
        nargs="*",
        default=["."],
        help="Paths to check (default: current directory)",
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Verbose output"
    )

    args = parser.parse_args()

    enforcer = ASCIIEnforcer(verbose=args.verbose)
    exit_code = enforcer.run(args.paths)

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
