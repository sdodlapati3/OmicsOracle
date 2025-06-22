#!/usr/bin/env python3
"""
Test script for Phase 1.2 Core Architecture Implementation.

This script validates that our core architecture components are working correctly:
- Configuration system
- Exception handling
- Data models
- Logging infrastructure
"""

import sys
import os
from pathlib import Path

# Add src to path for testing
src_path = Path(__file__).parent / "src"
sys.path.insert(0, str(src_path))


def test_configuration():
    """Test configuration system."""
    print("Testing configuration system...")

    try:
        from omics_oracle.core.config import ConfigManager, Environment

        # Test configuration manager
        config_manager = ConfigManager()
        print("  ✓ ConfigManager instantiated successfully")

        # Test loading development config
        config = config_manager.load_config("development")
        print(f"  ✓ Development config loaded: {config.environment}")
        print(f"  ✓ Database URL: {config.database.url}")
        print(f"  ✓ Logging level: {config.logging.level}")

        return True
    except Exception as e:
        print(f"  ✗ Configuration test failed: {e}")
        return False


def test_exceptions():
    """Test exception hierarchy."""
    print("Testing exception system...")

    try:
        from omics_oracle.core.exceptions import (
            OmicsOracleException,
            ConfigurationError,
            ValidationError,
        )

        # Test base exception
        try:
            raise OmicsOracleException("Test exception", code="TEST_ERROR")
        except OmicsOracleException as e:
            print(f"  ✓ Base exception: {e.message} (code: {e.code})")

        # Test specific exception
        try:
            raise ConfigurationError("Config error")
        except ConfigurationError as e:
            print(f"  ✓ Configuration exception: {e.message}")

        return True
    except Exception as e:
        print(f"  ✗ Exception test failed: {e}")
        return False


def test_models():
    """Test data models."""
    print("Testing data models...")

    try:
        from omics_oracle.core.models import (
            AssayType,
            GEOSample,
            SearchRequest,
            ErrorResponse,
        )

        # Test enum
        assay = AssayType.RNA_SEQ
        print(f"  ✓ AssayType enum: {assay}")

        # Test dataclass
        sample = GEOSample(
            accession="GSM123456", title="Test sample", organism="Homo sapiens"
        )
        print(f"  ✓ GEOSample created: {sample.accession}")

        # Test Pydantic model
        request = SearchRequest(query="RNA-seq human")
        print(f"  ✓ SearchRequest created: {request.query}")

        return True
    except Exception as e:
        print(f"  ✗ Models test failed: {e}")
        return False


def test_logging():
    """Test logging system."""
    print("Testing logging system...")

    try:
        from omics_oracle.core.logging import setup_logging, get_logger

        # Test setup
        setup_logging(level="DEBUG")
        print("  ✓ Logging setup successful")

        # Test logger
        logger = get_logger("test")
        logger.info("Test log message")
        print("  ✓ Logger created and message logged")

        return True
    except Exception as e:
        print(f"  ✗ Logging test failed: {e}")
        return False


def test_integration():
    """Test integration between components."""
    print("Testing component integration...")

    try:
        # Test that we can load config and use it in other components
        from omics_oracle.core.config import load_config
        from omics_oracle.core.models import SearchRequest
        from omics_oracle.core.exceptions import ValidationError

        # Load config (should work)
        config = load_config("development")
        print(f"  ✓ Config loaded for environment: {config.environment}")

        # Create a request model
        request = SearchRequest(query="test query")
        print(f"  ✓ Request model created: {request.query}")

        # Test validation error
        try:
            SearchRequest(query="")  # Should fail validation
        except Exception as e:
            print(f"  ✓ Validation error caught: {e}")

        return True
    except Exception as e:
        print(f"  ✗ Integration test failed: {e}")
        return False


def main():
    """Run all tests."""
    print("🧬 OmicsOracle Phase 1.2 Architecture Test")
    print("=" * 50)

    tests = [
        test_configuration,
        test_exceptions,
        test_models,
        test_logging,
        test_integration,
    ]

    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
            print()
        except Exception as e:
            print(f"  ✗ Test failed with exception: {e}")
            results.append(False)
            print()

    # Summary
    passed = sum(results)
    total = len(results)

    print("=" * 50)
    print(f"Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests passed! Core architecture is ready.")
        return 0
    else:
        print("❌ Some tests failed. Check output above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
