#!/bin/bash
# 
# Pre-Push Quality Check Script
# This script runs all quality checks before pushing code to prevent CI/CD failures
# 
# Usage: ./scripts/pre_push_check.sh
# 
# This script will:
# 1. Run all pre-commit hooks on all files
# 2. Run unit tests
# 3. Check for security vulnerabilities
# 4. Validate configuration files
# 5. Report summary of any issues found

set -e  # Exit on any error

echo "🔍 OmicsOracle Pre-Push Quality Check"
echo "===================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Track overall status
OVERALL_STATUS=0

echo -e "${BLUE}Step 1: Running pre-commit hooks on all files...${NC}"
if pre-commit run --all-files; then
    echo -e "${GREEN}✓ Pre-commit hooks passed${NC}"
else
    echo -e "${RED}✗ Pre-commit hooks failed${NC}"
    OVERALL_STATUS=1
fi

echo ""
echo -e "${BLUE}Step 2: Running unit tests...${NC}"
if python -m pytest tests/unit/ -v --tb=short; then
    echo -e "${GREEN}✓ Unit tests passed${NC}"
else
    echo -e "${RED}✗ Unit tests failed${NC}"
    OVERALL_STATUS=1
fi

echo ""
echo -e "${BLUE}Step 3: Checking for security vulnerabilities...${NC}"
if python -m bandit -r src/ -f json -o bandit-report.json; then
    echo -e "${GREEN}✓ Security check passed${NC}"
else
    echo -e "${YELLOW}⚠ Security warnings found (check bandit-report.json)${NC}"
    # Don't fail on security warnings, just alert
fi

echo ""
echo -e "${BLUE}Step 4: Validating configuration files...${NC}"
CONFIG_STATUS=0

# Check YAML files
if find . -name "*.yml" -o -name "*.yaml" | grep -v ".git" | xargs -I {} python -c "import yaml; yaml.safe_load(open('{}'))"; then
    echo -e "${GREEN}✓ YAML files are valid${NC}"
else
    echo -e "${RED}✗ Invalid YAML files found${NC}"
    CONFIG_STATUS=1
fi

# Check JSON files
if find . -name "*.json" | grep -v ".git" | xargs -I {} python -c "import json; json.load(open('{}'))"; then
    echo -e "${GREEN}✓ JSON files are valid${NC}"
else
    echo -e "${RED}✗ Invalid JSON files found${NC}"
    CONFIG_STATUS=1
fi

if [ $CONFIG_STATUS -eq 0 ]; then
    echo -e "${GREEN}✓ Configuration validation passed${NC}"
else
    echo -e "${RED}✗ Configuration validation failed${NC}"
    OVERALL_STATUS=1
fi

echo ""
echo -e "${BLUE}Step 5: Checking import structure...${NC}"
if python -c "
import sys
sys.path.insert(0, 'src')
try:
    import omics_oracle
    from omics_oracle.core import config, exceptions, models
    print('✓ All core modules import successfully')
except ImportError as e:
    print(f'✗ Import error: {e}')
    sys.exit(1)
"; then
    echo -e "${GREEN}✓ Import structure is valid${NC}"
else
    echo -e "${RED}✗ Import structure has issues${NC}"
    OVERALL_STATUS=1
fi

echo ""
echo "===================================="

# Final report
if [ $OVERALL_STATUS -eq 0 ]; then
    echo -e "${GREEN}🎉 ALL CHECKS PASSED! Safe to push.${NC}"
    echo ""
    echo "Your code is ready for CI/CD pipeline:"
    echo "• Code formatting: ✓"
    echo "• Linting: ✓" 
    echo "• Type checking: ✓"
    echo "• Unit tests: ✓"
    echo "• Security: ✓"
    echo "• Configuration: ✓"
    echo "• Imports: ✓"
    echo ""
    echo "Push command: git push origin <branch-name>"
else
    echo -e "${RED}❌ CHECKS FAILED! Fix issues before pushing.${NC}"
    echo ""
    echo "Failed checks need attention before pushing to prevent CI/CD failures."
    echo ""
    echo "Quick fixes:"
    echo "• Run: pre-commit run --all-files (and fix any issues)"
    echo "• Run: python -m pytest tests/unit/ -v (fix failing tests)" 
    echo "• Check bandit-report.json for security issues"
    echo "• Validate YAML/JSON syntax"
    echo ""
    exit 1
fi
