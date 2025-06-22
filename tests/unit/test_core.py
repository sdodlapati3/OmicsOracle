"""
Basic unit tests for OmicsOracle core modules.

This module provides basic unit tests to ensure core functionality
and prevent workflow failures.
"""

import unittest
import sys
from pathlib import Path

# Add the src directory to the path to import our modules
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "src"))

from omics_oracle.core import config, exceptions, models


class TestCoreModules(unittest.TestCase):
    """Test basic functionality of core modules."""

    def test_config_module_imports(self):
        """Test that config module imports correctly."""
        self.assertTrue(hasattr(config, 'OmicsOracleConfig'))
        
    def test_exceptions_module_imports(self):
        """Test that exceptions module imports correctly."""
        self.assertTrue(hasattr(exceptions, 'OmicsOracleError'))
        
    def test_models_module_imports(self):
        """Test that models module imports correctly."""
        self.assertTrue(hasattr(models, 'BaseModel'))

    def test_config_creation(self):
        """Test basic configuration creation."""
        try:
            conf = config.OmicsOracleConfig()
            self.assertIsNotNone(conf)
        except Exception as e:
            self.fail(f"Config creation failed: {e}")

    def test_exception_inheritance(self):
        """Test that our custom exceptions inherit properly."""
        error = exceptions.OmicsOracleError("test error")
        self.assertIsInstance(error, Exception)
        self.assertEqual(str(error), "test error")


if __name__ == '__main__':
    unittest.main()
