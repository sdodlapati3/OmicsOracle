# Test Suite Organization

This directory contains the comprehensive test suite for OmicsOracle.

## Structure

### Integration Tests (`integration/`)
- End-to-end integration tests
- Query refinement integration tests
- System integration tests

### System Tests (`system/`)
- Full system validation tests
- Performance and scalability tests

### Interface Tests (`interface/`)
- Web interface testing
- UI/UX validation tests
- Cross-browser compatibility tests

## Running Tests

### All Tests
```bash
pytest tests/
```

### Specific Test Categories
```bash
# Integration tests
pytest tests/integration/

# System tests  
pytest tests/system/

# Interface tests
pytest tests/interface/
```

## Test Coverage

Run coverage analysis:
```bash
pytest --cov=src tests/
```
