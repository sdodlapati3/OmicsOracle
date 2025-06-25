#!/usr/bin/env python3
"""
Targeted unused imports fixer for the futuristic interface
"""

import re
from pathlib import Path


def fix_unused_imports_in_file(file_path: Path) -> bool:
    """Fix unused imports in a specific file"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original_content = content
        
        # Define specific unused imports to remove based on flake8 output
        unused_imports = {
            'agents/analysis_agent.py': [
                'from datetime import datetime',
            ],
            'agents/orchestrator.py': [
                'from typing import List',
                'from ..models.futuristic_models import AgentStatus, AnalysisInsight, SearchResult, VisualizationData',
            ],
            'core/config.py': [
                'from typing import Dict, Optional',
            ],
            'core/health.py': [
                'from datetime import timedelta', 
                'from typing import Optional',
            ],
            'futuristic_demo.py': [
                'from fastapi.responses import JSONResponse',
            ],
            'main.py': [
                'from typing import Any, List',
                'from fastapi.responses import JSONResponse',
                'from pydantic import BaseModel, Field',
                'from models.futuristic_models import AgentMessage, AgentStatus, SystemMetrics',
            ],
            'models/futuristic_models.py': [
                'from typing import Union',
            ],
            'services/logging_service.py': [
                'from typing import Optional',
            ],
            'services/visualization_service.py': [
                'import json',
                'import math',
            ],
            'services/websocket_manager.py': [
                'from fastapi import WebSocketDisconnect',
            ],
            'test_server.py': [
                'import os',
            ],
            'ui/routes.py': [
                'from core.config import UI_THEME',
            ],
        }
        
        # Check if this file has unused imports to remove
        relative_path = str(file_path.relative_to(file_path.parent.parent))
        if relative_path in unused_imports:
            for import_line in unused_imports[relative_path]:
                # Remove the import line (with optional trailing comma handling)
                pattern = re.escape(import_line) + r'.*?\n'
                content = re.sub(pattern, '', content, flags=re.MULTILINE)
                
                # Also try to remove from multi-line imports
                if 'import' in import_line and ',' in import_line:
                    # Handle comma-separated imports
                    for part in import_line.split('import')[1].split(','):
                        part = part.strip()
                        if part:
                            # Remove just this part from comma-separated imports
                            content = re.sub(rf',\s*{re.escape(part)}', '', content)
                            content = re.sub(rf'{re.escape(part)}\s*,', '', content)
        
        if content != original_content:
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            return True
        return False
        
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return False


def main():
    """Main function"""
    base_path = Path(__file__).parent.parent / "interfaces" / "futuristic"
    
    fixed_files = []
    for py_file in base_path.rglob("*.py"):
        if fix_unused_imports_in_file(py_file):
            fixed_files.append(str(py_file.relative_to(base_path)))
    
    if fixed_files:
        print("Fixed unused imports in:")
        for file_path in fixed_files:
            print(f"  {file_path}")
    else:
        print("No unused imports found to fix")


if __name__ == "__main__":
    main()
