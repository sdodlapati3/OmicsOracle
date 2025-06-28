#!/bin/bash
# OmicsOracle Codebase Cleanup Script
# This script removes redundant and obsolete files to clean up the codebase
# Run from the project root directory

set -e  # Exit on any error

PROJECT_ROOT="$(pwd)"
BACKUP_DIR="archive/cleanup_$(date +%Y%m%d_%H%M%S)"

echo "🧹 OmicsOracle Codebase Cleanup Starting..."
echo "📂 Project root: $PROJECT_ROOT"
echo "💾 Backup directory: $BACKUP_DIR"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Function to safely move files to backup
backup_and_remove() {
    local file="$1"
    if [[ -f "$file" ]]; then
        echo "📦 Backing up and removing: $file"
        cp "$file" "$BACKUP_DIR/"
        rm "$file"
    elif [[ -d "$file" ]]; then
        echo "📦 Backing up and removing directory: $file"
        cp -r "$file" "$BACKUP_DIR/"
        rm -rf "$file"
    else
        echo "⚠️  File not found, skipping: $file"
    fi
}

# Function to safely remove files without backup (logs, cache, etc.)
safe_remove() {
    local file="$1"
    if [[ -f "$file" ]]; then
        echo "🗑️  Removing: $file"
        rm "$file"
    elif [[ -d "$file" ]]; then
        echo "🗑️  Removing directory: $file"
        rm -rf "$file"
    else
        echo "⚠️  File not found, skipping: $file"
    fi
}

echo ""
echo "🗂️  Phase 1: Remove Root-Level Test Files (duplicated in tests/)"
echo "=" * 60

# Root-level test files that are duplicated in tests/ directory
test_files=(
    "test_api_endpoints.py"
    "test_geo_client.py"
    "test_honest_results.py"
    "test_ncbi_config.py"
    "test_ncbi_connection.py"
    "test_progress_client.py"
    "test_progress_events.py"
    "test_search.py"
)

for file in "${test_files[@]}"; do
    backup_and_remove "$file"
done

echo ""
echo "🗂️  Phase 2: Remove Redundant Utility Files"
echo "=" * 60

# Redundant utility files
utility_files=(
    "check_env.py"
    "debug_pipeline.py"
    "debug_pipeline_init.py"
    "fix_ncbi_email.py"
    "fix_ncbi_env.py"
    "run_comprehensive_tests.py"
    "run_tests.py"
)

for file in "${utility_files[@]}"; do
    backup_and_remove "$file"
done

echo ""
echo "🗂️  Phase 3: Remove Log Files and Cache Directories"
echo "=" * 60

# Log files and cache directories (no backup needed)
temp_files=(
    "websocket_messages.log"
    "progress_events_raw.log"
    "__pycache__"
    "temp"
    ".pytest_cache"
    "*.pyc"
)

for pattern in "${temp_files[@]}"; do
    # Use find for pattern matching
    find . -name "$pattern" -type f -delete 2>/dev/null || true
    find . -name "$pattern" -type d -exec rm -rf {} + 2>/dev/null || true
done

echo ""
echo "🗂️  Phase 4: Archive Legacy Files"
echo "=" * 60

# Files to archive (keep for reference but not in main codebase)
legacy_files=(
    "entrez_patch.py"
    "omics_toolbox.py"
    "start-futuristic-fixed.sh"
    "validate_ncbi_config.py"
)

# Create legacy archive directory
mkdir -p "archive/legacy_files"

for file in "${legacy_files[@]}"; do
    if [[ -f "$file" ]]; then
        echo "📦 Moving to archive: $file"
        mv "$file" "archive/legacy_files/"
    fi
done

echo ""
echo "🗂️  Phase 5: Clean Interface Redundancies"
echo "=" * 60

# Remove redundant interface files
interface_files=(
    "interfaces/futuristic/enhanced_server.py"
    "interfaces/futuristic/test_server.py"
    "interfaces/futuristic/futuristic_demo.py"
    "interfaces/futuristic/validate_interface.py"
    "interfaces/futuristic/progress_events_raw.log"
    "interfaces/futuristic/futuristic_interface_validation_results.json"
)

for file in "${interface_files[@]}"; do
    backup_and_remove "$file"
done

echo ""
echo "🗂️  Phase 6: Clean Test Directory"
echo "=" * 60

# Remove redundant test files
test_cleanup_files=(
    "tests/run_comprehensive_tests.py"
    "tests/run_comprehensive_tests_simple.py"
)

for file in "${test_cleanup_files[@]}"; do
    backup_and_remove "$file"
done

# Move misplaced test files to appropriate directories
if [[ -f "tests/test_pagination.py" ]]; then
    echo "📁 Moving test_pagination.py to unit tests"
    mkdir -p "tests/unit"
    mv "tests/test_pagination.py" "tests/unit/"
fi

if [[ -f "tests/test_search_fix.py" ]]; then
    echo "📁 Moving test_search_fix.py to integration tests"
    mkdir -p "tests/integration"
    mv "tests/test_search_fix.py" "tests/integration/"
fi

echo ""
echo "🗂️  Phase 7: Clean Scripts Directory"
echo "=" * 60

# Remove redundant scripts
redundant_scripts=(
    "scripts/validate_integrations.py"
    "scripts/run_validation_suite.py"
    "scripts/quick_ci_check.py"
    "scripts/demo_biomedical_nlp.py"
    "scripts/web_interface_test_summary.py"
    "scripts/setup-mvp.sh"
    "scripts/monitor.sh"
    "scripts/workflow_monitor.py"
    "scripts/read_pdfs.py"
    "scripts/test_pipeline.py"
)

for file in "${redundant_scripts[@]}"; do
    backup_and_remove "$file"
done

# Clean script subdirectories that are mostly obsolete
script_dirs=(
    "scripts/demos"
    "scripts/.ruff_cache"
)

for dir in "${script_dirs[@]}"; do
    if [[ -d "$dir" ]]; then
        backup_and_remove "$dir"
    fi
done

echo ""
echo "🗂️  Phase 8: Documentation Cleanup Preparation"
echo "=" * 60

# Create consolidated documentation directory structure
mkdir -p "docs/consolidated"

echo "📝 Documentation files identified for manual consolidation:"
echo "   - docs/ARCHITECTURAL_ANALYSIS.md"
echo "   - docs/CRITICAL_ARCHITECTURE_EVALUATION.md"
echo "   - docs/COMPREHENSIVE_ARCHITECTURE_EVALUATION_SUMMARY.md"
echo "   → Should be merged into single comprehensive architecture guide"
echo ""
echo "   - docs/EVENT_FLOW_README.md"
echo "   - docs/EVENT_FLOW_CHART.md"
echo "   - docs/EVENT_FLOW_GAP_ANALYSIS.md"
echo "   → Should be merged into single event flow guide"

# Create a summary of what was cleaned up
cat > "$BACKUP_DIR/cleanup_summary.txt" << EOF
OmicsOracle Codebase Cleanup Summary
Date: $(date)
Project Root: $PROJECT_ROOT

Files Removed/Archived:
========================

Root-level test files (8 files):
$(printf '%s\n' "${test_files[@]}")

Redundant utility files (7 files):
$(printf '%s\n' "${utility_files[@]}")

Legacy files moved to archive (4 files):
$(printf '%s\n' "${legacy_files[@]}")

Interface redundancies (6 files):
$(printf '%s\n' "${interface_files[@]}")

Test cleanup (2 files):
$(printf '%s\n' "${test_cleanup_files[@]}")

Redundant scripts (10 files):
$(printf '%s\n' "${redundant_scripts[@]}")

Script directories (2 directories):
$(printf '%s\n' "${script_dirs[@]}")

Temporary/cache files: Cleaned automatically

Next Steps (Manual):
===================
1. Consolidate documentation files in docs/
2. Review and merge duplicate interface functionality
3. Verify all tests still pass after cleanup
4. Update any scripts that referenced removed files
5. Update documentation to reflect new structure

All removed files have been backed up to: $BACKUP_DIR
EOF

echo ""
echo "✅ Cleanup Phase Complete!"
echo "📊 Summary:"

# Count files in backup to show what was removed
removed_count=$(find "$BACKUP_DIR" -type f | wc -l)
echo "   📦 Files backed up and removed: $removed_count"
echo "   📁 Backup location: $BACKUP_DIR"
echo "   📄 Detailed summary: $BACKUP_DIR/cleanup_summary.txt"

echo ""
echo "🔍 Next Steps:"
echo "   1. Review the cleanup summary: cat $BACKUP_DIR/cleanup_summary.txt"
echo "   2. Run tests to ensure everything still works: python comprehensive_test_runner.py"
echo "   3. Manually consolidate documentation files as noted above"
echo "   4. Review interfaces/ directory for any remaining duplication"
echo "   5. Update any references to removed files in documentation"

echo ""
echo "⚠️  Important: If anything breaks, you can restore files from: $BACKUP_DIR"
echo "🎉 Codebase is now significantly cleaner and more organized!"
