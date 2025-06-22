#!/usr/bin/env python3
"""
OmicsOracle ASCII Character Enforcement System

This script enforces strict ASCII-only characters in all code files, 
configurations, and scripts while allowing Unicode in markdown documentation.

Inspired by patch-hyena but enhanced for genomics research requirements.
"""

import argparse
import os
import re
import sys
from pathlib import Path
from typing import List, Tuple, Dict, Set


class ASCIIEnforcer:
    """Comprehensive ASCII character enforcement for OmicsOracle codebase."""

    # File patterns that MUST be ASCII-only
    ASCII_ONLY_PATTERNS = {
        r'\.py$',           # Python files
        r'\.yml$',          # YAML files
        r'\.yaml$',         # YAML files
        r'\.json$',         # JSON files
        r'\.sh$',           # Shell scripts
        r'\.bash$',         # Bash scripts
        r'\.zsh$',          # Zsh scripts
        r'\.toml$',         # TOML files
        r'\.ini$',          # INI files
        r'\.cfg$',          # Config files
        r'\.conf$',         # Config files
        r'\.txt$',          # Text files (except docs)
        r'\.sql$',          # SQL files
        r'\.js$',           # JavaScript files
        r'\.ts$',           # TypeScript files
        r'\.html$',         # HTML files
        r'\.css$',          # CSS files
        r'\.xml$',          # XML files
        r'Dockerfile$',     # Docker files
        r'Makefile$',       # Makefiles
        r'requirements.*\.txt$',  # Requirements files
    }

    # File patterns that CAN contain Unicode (documentation)
    UNICODE_ALLOWED_PATTERNS = {
        r'\.md$',           # Markdown files
        r'\.rst$',          # reStructuredText files
        r'\.tex$',          # LaTeX files
        r'/docs/',          # Documentation directories
        r'/README',         # README files
    }

    # Directories to exclude
    EXCLUDED_DIRS = {
        '.git', '__pycache__', '.pytest_cache', '.mypy_cache',
        'node_modules', '.venv', 'venv', 'env', '.env',
        '.tox', 'dist', 'build', '*.egg-info'
    }

    # Special characters commonly found in genomics that should be flagged
    PROBLEMATIC_CHARS = {
        # Arrows and mathematical symbols
        '→', '←', '↑', '↓', '↔', '↕',
        '⇒', '⇐', '⇑', '⇓', '⇔', '⇕',
        
        # Science and research emojis
        '🧬', '🔬', '🧪', '🎯', '🔍', '🔎',
        '📊', '📈', '📉', '💻', '🖥️', '💾',
        '🚀', '⚡', '💡', '🛠️', '⚙️',
        
        # Status and UI emojis commonly used in code
        '✅', '❌', '⚠️', '�', '�', '�',
        '✓', '✗', '⭐', '🎉', '🎊',
        
        # Mathematical and scientific symbols
        '°', '±', '×', '÷', '∞', '≤', '≥', '≠',
        '∑', '∏', '∂', '∇', '∆', '∫', '√',
        'α', 'β', 'γ', 'δ', 'ε', 'ζ', 'η', 'θ',
        'λ', 'μ', 'π', 'ρ', 'σ', 'τ', 'φ', 'χ', 'ψ', 'ω',
        
        # Typography characters
        '"', '"', ''', ''', '–', '—',
        '…', '•', '‰', '§', '¶', '†', '‡',
        
        # Currency and units
        '€', '£', '¥', '¢', '™', '®', '©',
        
        # Fractions and subscripts/superscripts
        '½', '⅓', '¼', '¾', '⅔', '⅕', '⅖', '⅗', '⅘', '⅙', '⅚', '⅛',
        '⅜', '⅝', '⅞',
        '¹', '²', '³', '⁴', '⁵', '⁶', '⁷', '⁸', '⁹', '⁰',
        '₀', '₁', '₂', '₃', '₄', '₅', '₆', '₇', '₈', '₉',
    }

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.errors: List[Dict] = []
        self.warnings: List[Dict] = []

    def check_file(self, file_path: Path) -> bool:
        """Check a single file for ASCII compliance."""
        try:
            # Skip if file should be excluded
            if self._should_exclude_file(file_path):
                return True

            # Determine if file should be ASCII-only
            is_ascii_required = self._requires_ascii_only(file_path)
            
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read()

            return self._check_content(file_path, content, is_ascii_required)

        except Exception as e:
            self._add_error(file_path, 0, 0, f"Failed to read file: {e}")
            return False

    def _should_exclude_file(self, file_path: Path) -> bool:
        """Check if file should be excluded from ASCII checking."""
        path_str = str(file_path)
        
        # Check excluded directories
        for excluded_dir in self.EXCLUDED_DIRS:
            if excluded_dir in path_str:
                return True
        
        # Check if it's a binary file
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                if b'\0' in chunk:  # Likely binary file
                    return True
        except Exception:
            return True
            
        return False

    def _requires_ascii_only(self, file_path: Path) -> bool:
        """Determine if file requires ASCII-only characters."""
        path_str = str(file_path)
        
        # Check if Unicode is explicitly allowed
        for pattern in self.UNICODE_ALLOWED_PATTERNS:
            if re.search(pattern, path_str):
                return False
        
        # Check if ASCII is required
        for pattern in self.ASCII_ONLY_PATTERNS:
            if re.search(pattern, path_str):
                return True
        
        # Default to ASCII-only for unknown file types
        return True

    def _check_content(
        self, file_path: Path, content: str, ascii_required: bool
    ) -> bool:
        """Check file content for character compliance."""
        lines = content.split('\n')
        has_errors = False

        for line_num, line in enumerate(lines, 1):
            line_errors = self._check_line(line, line_num, ascii_required)
            if line_errors:
                has_errors = True
                for col, char, error_type in line_errors:
                    error_msg = (
                        f"{error_type}: Non-ASCII character '{char}' "
                        f"(U+{ord(char):04X})"
                    )
                    self._add_error(file_path, line_num, col, error_msg)

        return not has_errors

    def _check_line(
        self, line: str, line_num: int, ascii_required: bool
    ) -> List[Tuple[int, str, str]]:
        """Check a single line for character violations."""
        errors = []
        
        for col, char in enumerate(line, 1):
            char_code = ord(char)
            
            if char_code > 127:  # Non-ASCII character
                if ascii_required:
                    error_type = self._classify_error(char)
                    errors.append((col, char, error_type))
                elif char in self.PROBLEMATIC_CHARS:
                    # Warning for problematic chars even in allowed files
                    warning_msg = (
                        f"Potentially problematic character '{char}' "
                        f"(U+{char_code:04X}) - consider ASCII alternative"
                    )
                    self._add_warning(line_num, col, warning_msg)
        
        return errors

    def _classify_error(self, char: str) -> str:
        """Classify the type of ASCII violation."""
        char_code = ord(char)
        
        if char in self.PROBLEMATIC_CHARS:
            return "CRITICAL"
        elif 0x2000 <= char_code <= 0x206F:  # General punctuation
            return "PUNCTUATION"
        elif 0x1F000 <= char_code <= 0x1FFFF:  # Emoji range
            return "EMOJI"
        else:
            return "NON_ASCII"

    def _add_error(self, file_path: Path, line: int, col: int, message: str):
        """Add an error to the error list."""
        self.errors.append({
            'file': str(file_path),
            'line': line,
            'column': col,
            'message': message,
            'severity': 'ERROR'
        })

    def _add_warning(self, line: int, col: int, message: str):
        """Add a warning to the warning list."""
        self.warnings.append({
            'line': line,
            'column': col,
            'message': message,
            'severity': 'WARNING'
        })

    def check_directory(self, directory: Path) -> bool:
        """Check all files in a directory recursively."""
        success = True
        
        for file_path in directory.rglob('*'):
            if file_path.is_file():
                if not self.check_file(file_path):
                    success = False
        
        return success

    def report_results(self) -> None:
        """Print a comprehensive report of findings."""
        if not self.errors and not self.warnings:
            print("✅ All files pass ASCII enforcement checks!")
            return

        if self.errors:
            print(f"\n❌ Found {len(self.errors)} ASCII violations:")
            print("=" * 60)
            
            for error in self.errors:
                line_num = error['line']
                col_num = error['column']
                print(f"FILE: {error['file']}")
                error_msg = error['message']
                msg = f"LINE: {line_num:4d} | COL: {col_num:3d} | {error_msg}"
                print(msg)
                print("-" * 60)

        if self.warnings:
            print(f"\n⚠️  Found {len(self.warnings)} warnings:")
            print("=" * 60)
            
            for warning in self.warnings:
                line_num = warning['line']
                col_num = warning['column']
                warning_msg = warning['message']
                line_col = f"LINE: {line_num:4d} | COL: {col_num:3d}"
                print(f"{line_col} | {warning_msg}")
                print("-" * 60)

        # Summary
        print("\nSUMMARY:")
        print(f"  Errors:   {len(self.errors)}")
        print(f"  Warnings: {len(self.warnings)}")
        
        if self.errors:
            print("\n💡 To fix ASCII violations:")
            print("   1. Replace non-ASCII characters with ASCII equivalents")
            print("   2. Move decorative content to markdown documentation")
            print("   3. Use ASCII art instead of Unicode symbols")
            print("   4. Replace smart quotes with straight quotes")


def main() -> None:
    """Main entry point for ASCII enforcement."""
    parser = argparse.ArgumentParser(
        description="Enforce ASCII-only characters in OmicsOracle codebase"
    )
    parser.add_argument(
        'paths',
        nargs='*',
        help='Files or directories to check (default: current directory)'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )
    parser.add_argument(
        '--fix',
        action='store_true',
        help='Attempt to automatically fix common issues'
    )
    
    args = parser.parse_args()
    
    if not args.paths:
        args.paths = ['.']
    
    enforcer = ASCIIEnforcer(verbose=args.verbose)
    success = True
    
    for path_str in args.paths:
        path = Path(path_str)
        if path.is_file():
            if not enforcer.check_file(path):
                success = False
        elif path.is_dir():
            if not enforcer.check_directory(path):
                success = False
        else:
            print(f"❌ Path not found: {path_str}")
            success = False
    
    enforcer.report_results()
    
    if not success:
        sys.exit(1)


if __name__ == '__main__':
    main()
