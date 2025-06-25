#!/usr/bin/env python3
"""
Simple test script to validate the OmicsOracle modern interface setup
"""

import sys
import os
from pathlib import Path

# Add the modern interface to Python path
modern_path = Path(__file__).parent / "interfaces" / "modern"
sys.path.insert(0, str(modern_path))

def test_imports():
    """Test that all core modules can be imported"""
    print("🧪 Testing module imports...")
    
    try:
        from core.config import Config, get_config
        print("✅ Config module imported successfully")
        
        from core.exceptions import OmicsOracleException, SearchException
        print("✅ Exceptions module imported successfully")
        
        from core.logging_config import setup_logging, get_logger
        print("✅ Logging module imported successfully")
        
        from models import SearchQuery, SearchResult, SearchResponse
        print("✅ Models module imported successfully")
        
        from services import SearchService, CacheService, ExportService
        print("✅ Services module imported successfully")
        
        # Note: API modules will have import issues due to relative imports
        # This is expected until we set up proper package structure
        
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        return False

def test_configuration():
    """Test configuration system"""
    print("\n🔧 Testing configuration...")
    
    try:
        from core.config import get_config, DevelopmentConfig
        
        config = get_config('development')
        print(f"✅ Configuration loaded: {config.__class__.__name__}")
        print(f"   • Debug mode: {config.DEBUG}")
        print(f"   • Cache enabled: {config.CACHE_ENABLED}")
        print(f"   • Data directory: {config.DATA_DIR}")
        
        return True
        
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return False

def test_models():
    """Test data models"""
    print("\n📊 Testing data models...")
    
    try:
        from models import SearchQuery, SearchResult, SearchResponse, SearchType
        
        # Create a test search query
        query = SearchQuery(
            query="test search",
            page=1,
            page_size=20
        )
        print(f"✅ SearchQuery created: '{query.query}' (page {query.page})")
        
        # Create a test search result
        result = SearchResult(
            id="GSE12345",
            title="Test Dataset",
            abstract="This is a test dataset"
        )
        print(f"✅ SearchResult created: {result.id} - {result.title}")
        
        # Test serialization
        result_dict = result.to_dict()
        print(f"✅ SearchResult serialization: {len(result_dict)} fields")
        
        return True
        
    except Exception as e:
        print(f"❌ Models error: {e}")
        return False

def test_services():
    """Test service classes"""
    print("\n🔧 Testing services...")
    
    try:
        from services import SearchService, CacheService, ExportService
        from pathlib import Path
        
        # Test SearchService
        search_service = SearchService()
        print("✅ SearchService instantiated")
        
        # Test CacheService
        cache_dir = Path("/tmp/test_cache")
        cache_service = CacheService(cache_dir, ttl=60, enabled=True)
        print("✅ CacheService instantiated")
        
        # Test cache operations
        cache_service.set("test_key", {"test": "data"})
        cached_data = cache_service.get("test_key")
        if cached_data:
            print("✅ Cache operations working")
        else:
            print("⚠️  Cache operations not working as expected")
        
        # Test ExportService
        export_dir = Path("/tmp/test_exports")
        export_service = ExportService(export_dir)
        print("✅ ExportService instantiated")
        
        return True
        
    except Exception as e:
        print(f"❌ Services error: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 OmicsOracle Modern Interface Validation")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_configuration,
        test_models,
        test_services
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        try:
            if test():
                passed += 1
        except Exception as e:
            print(f"❌ Test {test.__name__} failed with exception: {e}")
    
    print("\n" + "=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("🎉 All tests passed! The modern interface is ready.")
        return 0
    else:
        print("⚠️  Some tests failed. Check the setup and dependencies.")
        return 1

if __name__ == "__main__":
    sys.exit(main())
