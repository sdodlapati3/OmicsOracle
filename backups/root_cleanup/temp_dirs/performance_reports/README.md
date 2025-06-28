# OmicsOracle Performance Monitoring

This directory contains performance monitoring reports for the OmicsOracle search system. These reports track search performance metrics over time and help identify optimization opportunities.

## Overview

The performance monitoring system measures:

- **Response Times**: How long queries take to process
- **Component Timing**: Time spent in different parts of the search pipeline
- **Result Counts**: Number of results returned for different queries
- **Resource Usage**: Memory and CPU consumption during query processing

## Report Types

### JSON Performance Data

Raw performance data is stored in JSON format with filenames like:
```
search_performance_20250627_140306.json
```

These files contain detailed metrics that can be analyzed programmatically.

### Markdown Reports

Human-readable reports are stored in Markdown format with filenames like:
```
search_performance_report_20250627_140306.md
```

These reports include summary statistics, detailed query performance, and component timing analysis.

### Visualization Charts

Performance visualizations are stored as PNG images with filenames like:
```
response_times_20250627_140306.png
components_human_liver_cancer_20250627_140306.png
```

These charts provide visual representations of performance metrics for easier analysis.

## Running Performance Tests

To generate a new performance report, run:

```bash
python3 ../search_performance_monitor.py
```

Options:
- `--url URL`: Base URL of the OmicsOracle API (default: http://localhost:8000)
- `--iterations N`: Number of iterations per query (default: 3)
- `--queries-file FILE`: JSON file with custom test queries
- `--no-json`: Don't save raw metrics as JSON
- `--no-markdown`: Don't save formatted report as Markdown
- `--no-plots`: Don't generate visualization plots

## Interpreting Results

When analyzing performance reports, look for:

1. **High average response times**: May indicate general performance issues
2. **Outliers in response times**: May indicate inconsistent performance
3. **Slow components**: Components taking a disproportionate amount of time
4. **Correlation between query complexity and response time**: May indicate scaling issues

## Performance Optimization

Based on the performance reports, consider these optimization strategies:

- **Caching**: Implement or improve caching for frequent queries
- **Query Preprocessing**: Optimize the query parsing and component extraction
- **Database Indexing**: Ensure proper indexes are in place for search fields
- **Asynchronous Processing**: Use async processing for non-critical components
- **Resource Scaling**: Increase resources for bottlenecked components

## Related Documentation

For more information about the search system and performance monitoring:

- [Advanced Search Features](../docs/ADVANCED_SEARCH_FEATURES.md)
- [Search System Technical Documentation](../docs/SEARCH_SYSTEM_TECHNICAL_DOCUMENTATION.md)
