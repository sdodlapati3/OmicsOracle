#!/usr/bin/env python3
"""
Quick Local CI Check

Simple ASCII-only validation script that mirrors GitHub Actions checks.
"""

import subprocess
import sys
from typing import List, Tuple


def run_check(cmd: List[str], description: str) -> bool:
    """Run a single check and return success status."""
    print(f"\n[CHECK] {description}")
    print(f"Command: {' '.join(cmd)}")

    try:
        subprocess.run(cmd, capture_output=True, text=True, check=True)
        print(f"[PASS] {description}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"[FAIL] {description}")
        if e.stdout:
            print(f"Output: {e.stdout}")
        if e.stderr:
            print(f"Error: {e.stderr}")
        return False
    except FileNotFoundError:
        print(f"[ERROR] Command not found: {cmd[0]}")
        return False


def main() -> int:
    """Run essential CI checks."""
    print("=== Quick Local CI Validation ===")

    checks: List[Tuple[List[str], str]] = [
        (["python", "scripts/ascii_enforcer.py"], "ASCII Enforcement"),
        (
            ["black", "--check", "src/", "tests/", "scripts/", "--line-length", "88"],
            "Black Formatting",
        ),
        (
            [
                "isort",
                "--check-only",
                "src/",
                "tests/",
                "scripts/",
                "--profile",
                "black",
            ],
            "Import Sorting",
        ),
        (["ruff", "check", "src/", "tests/", "scripts/"], "Ruff Linting"),
        (
            ["bandit", "-r", "src/", "-f", "json", "-o", "bandit-report.json"],
            "Security Scan",
        ),
    ]

    failures = 0
    failed_checks = []

    for cmd, desc in checks:
        if not run_check(cmd, desc):
            failures += 1
            failed_checks.append(desc)

    print("\n=== Summary ===")
    if failures == 0:
        print("[SUCCESS] All checks passed!")
        return 0
    else:
        print(f"[FAILED] {failures} checks failed:")
        for failed_check in failed_checks:
            print(f"  - {failed_check}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
