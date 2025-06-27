#!/usr/bin/env python3
"""
Import Structure Fix Script

This script addresses the critical sys.path manipulation problem by:
1. Creating proper __init__.py files
2. Setting up PYTHONPATH correctly
3. Providing proper package imports
4. Generating a report of changes needed
"""

import os
import re
import sys
from pathlib import Path
from typing import Dict, List, Set


class ImportFixer:
    """Fix import structure and remove sys.path manipulations."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.src_dir = project_root / "src"
        self.fixes_needed = []
        self.files_with_syspath = []

    def analyze_import_issues(self):
        """Analyze the current import structure issues."""
        print("🔍 Analyzing import structure issues...")

        # Find all files with sys.path manipulations
        self._find_syspath_files()

        # Check for missing __init__.py files
        self._check_init_files()

        # Analyze import patterns
        self._analyze_import_patterns()

        return self._generate_report()

    def _find_syspath_files(self):
        """Find all files that manipulate sys.path."""
        for file_path in self.project_root.rglob("*.py"):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    if (
                        "sys.path.insert" in content
                        or "sys.path.append" in content
                    ):
                        self.files_with_syspath.append(file_path)
            except Exception as e:
                print(f"Warning: Could not read {file_path}: {e}")

    def _check_init_files(self):
        """Check for missing __init__.py files."""
        python_dirs = set()

        # Find all directories containing Python files
        for file_path in self.project_root.rglob("*.py"):
            python_dirs.add(file_path.parent)

        # Check which directories need __init__.py
        for dir_path in python_dirs:
            if dir_path.name in [
                ".git",
                "__pycache__",
                ".pytest_cache",
                "venv",
            ]:
                continue

            init_file = dir_path / "__init__.py"
            if not init_file.exists():
                self.fixes_needed.append(
                    {
                        "type": "missing_init",
                        "path": dir_path,
                        "description": f"Missing __init__.py in {dir_path.relative_to(self.project_root)}",
                    }
                )

    def _analyze_import_patterns(self):
        """Analyze problematic import patterns."""
        for file_path in self.project_root.rglob("*.py"):
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()

                # Look for relative imports that might be problematic
                relative_imports = re.findall(
                    r"from\s+(\.+\w*)\s+import", content
                )
                if relative_imports:
                    for imp in relative_imports:
                        if imp.count(".") > 3:  # Very deep relative imports
                            self.fixes_needed.append(
                                {
                                    "type": "deep_relative_import",
                                    "path": file_path,
                                    "import": imp,
                                    "description": f"Deep relative import {imp} in {file_path.relative_to(self.project_root)}",
                                }
                            )

            except Exception as e:
                print(f"Warning: Could not analyze {file_path}: {e}")

    def _generate_report(self) -> Dict:
        """Generate a comprehensive report of import issues."""
        return {
            "files_with_syspath": len(self.files_with_syspath),
            "syspath_files": [
                str(f.relative_to(self.project_root))
                for f in self.files_with_syspath
            ],
            "fixes_needed": self.fixes_needed,
            "total_issues": len(self.fixes_needed)
            + len(self.files_with_syspath),
        }

    def create_init_files(self):
        """Create missing __init__.py files."""
        print("📁 Creating missing __init__.py files...")

        created_count = 0
        for fix in self.fixes_needed:
            if fix["type"] == "missing_init":
                init_file = fix["path"] / "__init__.py"

                # Create appropriate __init__.py content based on directory
                content = self._generate_init_content(fix["path"])

                try:
                    with open(init_file, "w", encoding="utf-8") as f:
                        f.write(content)
                    print(
                        f"✅ Created {init_file.relative_to(self.project_root)}"
                    )
                    created_count += 1
                except Exception as e:
                    print(f"❌ Failed to create {init_file}: {e}")

        print(f"📊 Created {created_count} __init__.py files")
        return created_count

    def _generate_init_content(self, dir_path: Path) -> str:
        """Generate appropriate __init__.py content for a directory."""
        relative_path = dir_path.relative_to(self.project_root)

        # Different content based on directory type
        if "src/omics_oracle" in str(relative_path):
            if relative_path.name in [
                "domain",
                "application",
                "infrastructure",
                "presentation",
            ]:
                return f'"""OmicsOracle {relative_path.name} layer."""\n'
            elif relative_path.name in [
                "entities",
                "value_objects",
                "repositories",
                "services",
            ]:
                return f'"""OmicsOracle {relative_path.name} module."""\n'
            else:
                return f'"""OmicsOracle {relative_path.name} package."""\n'
        elif "tests" in str(relative_path):
            return f'"""Test package for {relative_path.name}."""\n'
        elif "interfaces" in str(relative_path):
            return f'"""Interface package for {relative_path.name}."""\n'
        else:
            return f'"""Package {relative_path.name}."""\n'

    def create_setup_py(self):
        """Create a proper setup.py file."""
        print("📦 Creating setup.py...")

        setup_content = '''#!/usr/bin/env python3
"""
OmicsOracle Setup Configuration

This setup.py file enables proper package installation and import structure.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8')

# Read requirements
requirements = []
requirements_file = this_directory / "requirements.txt"
if requirements_file.exists():
    requirements = requirements_file.read_text().strip().split('\\n')

setup(
    name="omics-oracle",
    version="0.1.0",
    description="AI-powered genomics data search and analysis platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="OmicsOracle Team",
    author_email="team@omicsoracle.com",
    url="https://github.com/omicsoracle/omicsoracle",

    packages=find_packages(where="src"),
    package_dir={"": "src"},

    python_requires=">=3.8",
    install_requires=requirements,

    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "test": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "pytest-cov>=4.0.0",
        ]
    },

    entry_points={
        "console_scripts": [
            "omics-oracle=omics_oracle.cli.main:main",
            "omics-web=omics_oracle.web.main:main",
        ],
    },

    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Science/Research",
        "Topic :: Scientific/Engineering :: Bio-Informatics",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],

    keywords="genomics bioinformatics ai machine-learning data-analysis",

    include_package_data=True,
    zip_safe=False,
)
'''

        setup_file = self.project_root / "setup.py"
        try:
            with open(setup_file, "w", encoding="utf-8") as f:
                f.write(setup_content)
            print(f"✅ Created {setup_file.relative_to(self.project_root)}")
            return True
        except Exception as e:
            print(f"❌ Failed to create setup.py: {e}")
            return False

    def create_pyproject_toml_fix(self):
        """Update pyproject.toml for proper packaging."""
        print("⚙️ Updating pyproject.toml...")

        pyproject_file = self.project_root / "pyproject.toml"

        # Read existing content
        existing_content = ""
        if pyproject_file.exists():
            with open(pyproject_file, "r", encoding="utf-8") as f:
                existing_content = f.read()

        # Add packaging configuration if not present
        if "[build-system]" not in existing_content:
            build_system = """
[build-system]
requires = ["setuptools>=45", "wheel", "setuptools_scm"]
build-backend = "setuptools.build_meta"

[project]
name = "omics-oracle"
dynamic = ["version"]
description = "AI-powered genomics data search and analysis platform"
readme = "README.md"
requires-python = ">=3.8"
license = {text = "MIT"}
authors = [
    {name = "OmicsOracle Team", email = "team@omicsoracle.com"}
]
keywords = ["genomics", "bioinformatics", "ai", "machine-learning"]
classifiers = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Science/Research",
    "Topic :: Scientific/Engineering :: Bio-Informatics",
    "Programming Language :: Python :: 3",
    "Programming Language :: Python :: 3.8",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
]

[project.scripts]
omics-oracle = "omics_oracle.cli.main:main"
omics-web = "omics_oracle.web.main:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.setuptools.package-dir]
"" = "src"

"""
            with open(pyproject_file, "a", encoding="utf-8") as f:
                f.write(build_system)
            print("✅ Updated pyproject.toml with packaging configuration")
        else:
            print("ℹ️ pyproject.toml already has build configuration")


def main():
    """Main function to fix import structure."""
    project_root = Path(__file__).parent

    print("🚀 OmicsOracle Import Structure Fix")
    print("=" * 50)

    # Initialize fixer
    fixer = ImportFixer(project_root)

    # Analyze current issues
    report = fixer.analyze_import_issues()

    print(f"📊 Analysis Results:")
    print(
        f"   Files with sys.path manipulation: {report['files_with_syspath']}"
    )
    print(f"   Total issues found: {report['total_issues']}")
    print()

    # Show some problematic files
    if report["syspath_files"]:
        print("🚨 Files using sys.path manipulation:")
        for file_path in report["syspath_files"][:10]:  # Show first 10
            print(f"   - {file_path}")
        if len(report["syspath_files"]) > 10:
            print(f"   ... and {len(report['syspath_files']) - 10} more")
        print()

    # Create fixes
    print("🔧 Applying fixes...")

    # Create __init__.py files
    created_init = fixer.create_init_files()

    # Create setup.py
    setup_created = fixer.create_setup_py()

    # Update pyproject.toml
    fixer.create_pyproject_toml_fix()

    print()
    print("✅ Import structure fix completed!")
    print(f"   Created {created_init} __init__.py files")
    print(f"   Setup.py created: {setup_created}")

    print()
    print("🎯 Next Steps:")
    print(
        "   1. Run: pip install -e . (to install package in development mode)"
    )
    print("   2. Remove sys.path manipulations from files")
    print("   3. Use proper imports: 'from omics_oracle.module import ...'")
    print("   4. Test imports with: python -c 'import omics_oracle'")

    # Save detailed report
    report_file = project_root / "import_fix_report.json"
    import json

    with open(report_file, "w") as f:
        json.dump(report, f, indent=2, default=str)
    print(f"   📄 Detailed report saved to: {report_file.name}")


if __name__ == "__main__":
    main()
