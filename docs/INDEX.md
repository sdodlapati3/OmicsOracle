# OmicsOracle Documentation Index

## Directory Structure

### Planning Documents (`docs/planning/`)
- Phase development plans and completion summaries
- Implementation progress tracking
- Interface development and cleanup plans
- Environment consolidation plans
- Project status reports

### Reports (`docs/reports/`)
- Data integrity findings and reports
- GSE-specific investigation summaries
- Testing and monitoring summaries
- Search system enhancement reports

### Analysis (`docs/analysis/`)
- Advanced cleanup analysis
- System analysis documents

### Guides (`docs/`)
- STARTUP_GUIDE.md - Guide for starting the application
- This index file

## Scripts Directory Structure

### Debug Scripts (`scripts/debug/`)
- debug_*.py - Pipeline and route debugging
- diagnose_*.py - System diagnostics
- check_*.py - Environment and configuration checks
- fix_*.py - Repair and fix utilities
- trace_*.py - Query flow tracing
- entrez_patch.py - NCBI Entrez patching utility

### Analysis Scripts (`scripts/analysis/`)
- analyze_traces.py - Trace analysis
- search_*_analyzer.py - Search performance analysis
- architecture_quality_analyzer.py - Code quality analysis
- generate_event_flow_visualization.py - Event flow visualization
- diagnostics.py - System diagnostics
- direct_gse_check.py - Direct GSE validation
- integrate_search_enhancer.py - Search enhancement integration
- omics_toolbox.py - General utilities

### Validation Scripts (`scripts/validation/`)
- validate_*.py - Various system validation scripts

### Monitoring Scripts (`scripts/monitoring/`)
- *monitor*.py - System monitoring utilities

### Utility Scripts (`scripts/`)
- cleanup_codebase.sh - Codebase cleanup script
- start_futuristic_enhanced.sh - Enhanced startup script

## Tests Directory Structure

### Integration Tests (`tests/integration/`)
- test_*.py - All integration test files
- comprehensive_test_runner.py - Main test runner
- run_*.py - Test execution scripts
- run_all_tests.sh - Shell script for running all tests

### Unit Tests (`tests/unit/`)
- Ready for unit test files (currently empty)

## Configuration Files (Root)
- .env.* - Environment configuration files
- Dockerfile* - Container configuration
- docker-compose.yml - Multi-container setup
- pyproject.toml - Python project configuration
- requirements*.txt - Dependency specifications
- Makefile - Build and development tasks
- mkdocs.yml - Documentation generation

## Main Application
- start.sh - Primary application startup script
- src/ - Main source code
- interfaces/ - User interface modules
- data/ - Data storage and cache
- logs/ - Application logs
