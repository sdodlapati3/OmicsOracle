# Scripts Directory

This directory contains utility scripts for the OmicsOracle project.

## quick_ci_check.py

A local CI validation script that mirrors the main quality gates enforced by GitHub Actions.

### Usage

```bash
python scripts/quick_ci_check.py
```

### What it checks

1. **ASCII Enforcement** - Ensures all source files contain only ASCII characters
2. **Black Formatting** - Validates code formatting with Black
3. **Import Sorting** - Checks imports are sorted correctly with isort
4. **Ruff Linting** - Runs comprehensive linting checks
5. **Security Scan** - Performs security analysis with Bandit

### Exit Codes

- `0` - All checks passed
- `1` - One or more checks failed

### Integration

Run this script before pushing code to catch issues locally:

```bash
# Instead of using --no-verify, run the CI checks first
python scripts/quick_ci_check.py

# If all checks pass, then commit and push
git commit -m "Your commit message"
git push
```

### Known Issues

- Bandit may report medium-severity warnings for binding to `0.0.0.0` in development configurations. These are acceptable for development but should be reviewed for production deployments.

## ascii_enforcer.py

Utility script that checks files for ASCII-only compliance.

### Usage

```bash
python scripts/ascii_enforcer.py [file_or_directory...]
```

If no arguments are provided, it checks common source directories (src/, tests/, scripts/).
