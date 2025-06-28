# OmicsOracle Error Analysis

This directory contains error analysis reports for the OmicsOracle search system. These reports help identify patterns in errors and provide recommendations for improving system reliability.

## Overview

The error analysis system examines:

- **Error Categories**: Types and frequencies of different errors
- **Time Distribution**: How errors are distributed over time
- **Logger Distribution**: Which components are generating errors
- **Example Errors**: Representative examples of each error type
- **Recommendations**: Suggested actions to address common issues

## Report Types

### JSON Analysis Data

Raw error analysis data is stored in JSON format with filenames like:
```
error_analysis_20250627_140306.json
```

These files contain detailed error data that can be analyzed programmatically.

### Markdown Reports

Human-readable reports are stored in Markdown format with filenames like:
```
error_analysis_report_20250627_140306.md
```

These reports include error categorization, statistics, examples, and recommendations.

### Visualization Charts

Error analysis visualizations are stored as PNG images with filenames like:
```
error_categories_20250627_140306.png
error_timeline_20250627_140306.png
error_by_logger_20250627_140306.png
```

These charts provide visual representations of error patterns for easier analysis.

## Running Error Analysis

To generate a new error analysis report, run:

```bash
python3 ../search_error_analyzer.py --logs LOG_FILE1 [LOG_FILE2 ...]
```

Options:
- `--logs LOG_FILES`: Paths to log files to analyze (required)
- `--no-json`: Don't save raw analysis as JSON
- `--no-markdown`: Don't save formatted report as Markdown
- `--no-plots`: Don't generate visualization plots

## Common Error Categories

The error analyzer looks for these common patterns:

- **connection_timeout**: Connection timeout errors
- **api_rate_limit**: API rate limiting issues
- **parsing_error**: Data parsing errors
- **authentication_error**: Authentication failures
- **data_not_found**: Requested data not found
- **server_error**: Server-side errors (500, 502, etc.)
- **query_too_complex**: Query complexity limit exceeded
- **memory_error**: Memory-related errors
- **invalid_parameter**: Invalid parameter errors
- **geo_api_error**: GEO API-specific errors
- **ncbi_api_error**: NCBI API-specific errors

## Addressing Common Issues

Based on the error analysis, consider these general strategies:

### For Connection Timeouts
- Increase timeout values
- Implement retry mechanisms with exponential backoff
- Check network connectivity and stability

### For API Rate Limits
- Implement client-side rate limiting
- Add request throttling
- Cache frequently accessed data

### For Parsing Errors
- Improve input validation
- Add better error handling for malformed data
- Log problematic inputs for further analysis

### For Data Not Found Errors
- Improve user feedback for non-existent data
- Implement fallback search strategies
- Update database indices

## Related Documentation

For more information about the search system and error handling:

- [Advanced Search Features](../docs/ADVANCED_SEARCH_FEATURES.md)
- [Search System Technical Documentation](../docs/SEARCH_SYSTEM_TECHNICAL_DOCUMENTATION.md)
